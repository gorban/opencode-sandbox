"""Multi-turn streaming pod-loopback relay for interactive provider sessions."""

import contextlib
import os
from pathlib import Path
import re
import select
import selectors
import socket
import struct
import sys
import threading
import time

if __package__:
    from .managed import relay
else:
    import relay


PROVIDER = ("127.0.0.1", 8401)
RELAY_PORT_MIN = 8401
RELAY_PORT_MAX = 8416
MAX_HEADER = 16 * 1024
MAX_BODY = 4 * 1024 * 1024
MAX_WIRE_RESPONSE = 9 * 1024 * 1024
REQUEST_TIMEOUT = 15
STREAM_TIMEOUT = 330
CHUNK = 16 * 1024
REQUEST_LENGTH = struct.Struct("!I")

_END = b"\r\n\r\n"
_REQUEST_LINE = re.compile(rb"(?:GET|POST) [!-~]+ HTTP/1\.1\Z")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_LENGTH = re.compile(rb"(?:0|[1-9]\d{0,7})\Z")


class RelayError(ValueError):
    """A bounded framing or lease refusal on the interactive relay."""


_OTHER_CLOSED = select.POLLHUP | select.POLLERR | select.POLLNVAL


def _check_poll_events(events, peer_fd: int, mask: int, other_fd: int | None,
                       lease, deadline: float) -> bool:
    for fd, flags in events:
        if other_fd is not None and fd == other_fd and (flags & _OTHER_CLOSED):
            raise RelayError("worker closed connection")
    for fd, flags in events:
        if fd == peer_fd and (flags & mask):
            if time.monotonic() < deadline and lease.active():
                return True
            raise RelayError("relay lease expired or revoked")
        if fd == peer_fd and (flags & relay.PEER_CLOSED):
            return True
    return False


def _wait(peer, mask, lease, deadline, other=None):
    poll = select.poll()
    poll.register(peer, mask | select.POLLRDHUP)
    other_fd = None
    if other is not None:
        # Watch only hard hangup/error on the client socket so standard HTTP/1.1
        # SHUT_WR half-close does not abort a streamed response.
        other_fd = other.fileno()
        poll.register(other, _OTHER_CLOSED)
    peer_fd = peer.fileno()
    while lease.active():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        events = poll.poll(max(1, int(1000 * min(remaining, relay.GRANT_POLL))))
        if _check_poll_events(events, peer_fd, mask, other_fd, lease, deadline):
            return
    raise RelayError("relay lease expired or revoked")


def _recv_some(peer, size, lease, deadline, other=None):
    while True:
        _wait(peer, select.POLLIN, lease, deadline, other)
        try:
            return peer.recv(size)
        except BlockingIOError:
            continue


def _send_all(peer, data, lease, deadline, *, other=None, deliver=None):
    view = memoryview(data)
    while view:
        _wait(peer, select.POLLOUT, lease, deadline, other)
        try:
            sent = peer.send(view) if deliver is None else deliver(lease, peer, view)
        except BlockingIOError:
            continue
        if not 0 < sent <= len(view):
            raise RelayError("relay write refused")
        view = view[sent:]


def _parse_header_line(line: bytes, length: int | None) -> int | None:
    name, sep, value = line.partition(b":")
    if not sep or not _HEADER_NAME.fullmatch(name) or not re.fullmatch(rb"[ -~]*", value):
        raise RelayError("invalid HTTP header")
    low = name.lower()
    if low == b"transfer-encoding":
        raise RelayError("chunked requests unsupported")
    if low == b"content-length":
        val = value.strip(b" \t")
        if length is not None or not _LENGTH.fullmatch(val):
            raise RelayError("invalid Content-Length")
        return int(val)
    return length


def _parse_content_length(header: bytes) -> int:
    request_line, *lines = header.split(b"\r\n")
    if not _REQUEST_LINE.fullmatch(request_line):
        raise RelayError("invalid HTTP request line")
    length = None
    for line in lines:
        length = _parse_header_line(line, length)
    if length is None:
        if request_line.startswith(b"GET "):
            return 0
        raise RelayError("POST requires Content-Length")
    if length > MAX_BODY:
        raise RelayError("request body exceeds limit")
    return length


def _read_request(worker: socket.socket, lease: relay.Lease, deadline: float) -> bytes:
    buf = bytearray()
    while (end := buf.find(_END)) < 0:
        remaining = MAX_HEADER - len(buf)
        if remaining <= 0:
            raise RelayError("request headers exceed limit")
        chunk = _recv_some(worker, min(remaining, CHUNK), lease, deadline)
        if not chunk:
            raise RelayError("worker closed before request headers finished")
        buf.extend(chunk)
    total = end + len(_END) + _parse_content_length(bytes(buf[:end]))
    if len(buf) > total:
        del buf[total:]
    while len(buf) < total:
        chunk = _recv_some(worker, min(total - len(buf), CHUNK), lease, deadline)
        if not chunk:
            raise RelayError("worker closed before request body finished")
        buf.extend(chunk)
    return bytes(buf)


def forward_stream(worker: socket.socket, broker: socket.socket, lease: relay.Lease,
                   proof: bytes, deadline: float) -> None:
    """Forward one HTTP/1.1 request and stream the broker's response under the lease fence."""
    if type(proof) is not bytes or len(proof) != relay.PROOF_SIZE:
        raise RelayError("invalid relay proof")
    worker.setblocking(False)
    broker.setblocking(False)
    req_deadline = min(deadline, time.monotonic() + REQUEST_TIMEOUT)
    raw = _read_request(worker, lease, req_deadline)
    _send_all(broker, relay.PROOF_PREFIX + proof + REQUEST_LENGTH.pack(len(raw)), lease, deadline, other=worker)
    _send_all(broker, raw, lease, deadline, other=worker)

    forwarded = 0
    while lease.active() and time.monotonic() < deadline:
        chunk = _recv_some(broker, CHUNK, lease, deadline, other=worker)
        if not chunk:
            return
        forwarded += len(chunk)
        if forwarded > MAX_WIRE_RESPONSE:
            raise RelayError("response exceeded relay wire limit")
        _send_all(worker, chunk, lease, deadline, deliver=relay.deliver)


def _handle_client(worker: socket.socket, lease: relay.Lease, proof: bytes) -> None:
    if not lease.active():
        return
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker:
        broker.settimeout(relay.GRANT_POLL)
        broker.connect(relay.PROVIDER_SOCKET)
        forward_stream(worker, broker, lease, proof, time.monotonic() + STREAM_TIMEOUT)


def _spawn_peer(listener: socket.socket, lease: relay.Lease, slots: threading.BoundedSemaphore,
                peers: set[socket.socket], peers_lock: threading.Lock, handle) -> None:
    client, _ = listener.accept()
    if not lease.active() or not slots.acquire(blocking=False):
        client.close()
        return
    with peers_lock:
        peers.add(client)
    try:
        threading.Thread(target=handle, args=(client,), daemon=True).start()
    except RuntimeError:
        slots.release()
        with peers_lock:
            peers.discard(client)
        client.close()


def serve(lease: relay.Lease, proof: bytes, port: int = 8401) -> None:
    if type(port) is not int or not RELAY_PORT_MIN <= port <= RELAY_PORT_MAX:
        raise RelayError("invalid relay port")
    os.umask(0o077)
    if lease.status() == "terminal":
        return
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((PROVIDER[0], port))
        listener.listen(8)
        slots = threading.BoundedSemaphore(8)
        peers: set[socket.socket] = set()
        peers_lock = threading.Lock()

        def handle(client: socket.socket) -> None:
            with client:
                try:
                    _handle_client(client, lease, proof)
                except (EOFError, OSError, ValueError):
                    pass
                finally:
                    with peers_lock:
                        peers.discard(client)
                    slots.release()

        try:
            with selectors.DefaultSelector() as selector:
                selector.register(listener, selectors.EVENT_READ)
                was_active = False
                while True:
                    status = lease.status()
                    if status == "terminal" or (was_active and status != "active"):
                        break
                    was_active = status == "active"
                    for _, _ in selector.select(relay.GRANT_POLL):
                        _spawn_peer(listener, lease, slots, peers, peers_lock, handle)
        finally:
            with peers_lock:
                for client in peers:
                    with contextlib.suppress(OSError):
                        client.shutdown(socket.SHUT_RDWR)


if __name__ == "__main__":
    if len(sys.argv) not in (4, 5):
        sys.exit("Invalid session relay arguments")
    bind_port = 8401
    if len(sys.argv) == 5:
        if not sys.argv[4].isdecimal():
            sys.exit("Invalid session relay port")
        bind_port = int(sys.argv[4])
        if not RELAY_PORT_MIN <= bind_port <= RELAY_PORT_MAX:
            sys.exit("Invalid session relay port")
    active = relay.grant_record(sys.argv[1], int(sys.argv[2]), True)
    with relay.PROOF.open("rb") as file:
        secret = file.read(relay.PROOF_SIZE + 1)
    if len(secret) != relay.PROOF_SIZE:
        sys.exit("Relay proof is missing or invalid")
    serve(relay.Lease(relay.GRANT, active, int(sys.argv[3])), secret, port=bind_port)
