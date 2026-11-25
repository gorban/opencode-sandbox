"""Private single-response framing for the integrated local relay proof."""

from dataclasses import replace
import re
import select
import socket
import struct
import time

if __package__:
    from . import relay
else:
    import relay


MAX_HEADER = 16 * 1024
MAX_BODY = 256 * 1024
MAX_REQUEST = MAX_HEADER + MAX_BODY
MAX_RESPONSE = 2 * 1024 * 1024

REQUEST_LENGTH = struct.Struct("!I")
RESPONSE_HEADER = struct.Struct("!16sI")
RECEIPT = struct.Struct("!16sQI")

_END = b"\r\n\r\n"
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_\x60|~0-9A-Za-z-]+\Z")
_REQUEST_LINE = re.compile(rb"[A-Z]+ [!-~]+ HTTP/1\.1\Z")
_LENGTH = re.compile(rb"(?:0|[1-9]\d{0,5})\Z")
_INVALID_FRAMING = "invalid HTTP request framing"


class ReceiptError(ValueError):
    """The private exchange did not establish a complete handoff."""


def _wait(peer, mask, lease, deadline, worker=None):
    poll = select.poll()
    poll.register(peer, mask | select.POLLRDHUP)
    if worker is not None:
        poll.register(worker, select.POLLRDHUP)
    while lease.active():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        events = poll.poll(max(1, int(1000 * min(remaining, relay.GRANT_POLL))))
        if any(flags & relay.PEER_CLOSED for _, flags in events):
            raise ReceiptError("private exchange peer closed")
        if any(fd == peer.fileno() and flags & mask for fd, flags in events):
            if time.monotonic() < deadline and lease.active():
                return
            break
    raise ReceiptError("private exchange expired or revoked")


def _read(peer, size, lease, deadline, worker=None):
    while True:
        _wait(peer, select.POLLIN, lease, deadline, worker)
        try:
            chunk = peer.recv(size)
        except BlockingIOError:
            continue
        if not chunk:
            raise ReceiptError("private exchange peer closed")
        return chunk


def _read_exact(peer, size, lease, deadline, worker=None):
    data = bytearray()
    while len(data) < size:
        data.extend(_read(peer, size - len(data), lease, deadline, worker))
    return bytes(data)


def _write(peer, data, lease, deadline, *, worker=None, deliver=None):
    view = memoryview(data)
    while view:
        _wait(peer, select.POLLOUT, lease, deadline, worker)
        try:
            sent = peer.send(view) if deliver is None else deliver(lease, peer, view)
        except BlockingIOError:
            continue
        if not 0 < sent <= len(view):
            raise ReceiptError("private exchange write refused")
        view = view[sent:]


def _content_length(header):
    request, *lines = header.split(b"\r\n")
    if not _REQUEST_LINE.fullmatch(request):
        raise ReceiptError(_INVALID_FRAMING)
    length = None
    for line in lines:
        name, separator, value = line.partition(b":")
        if not separator or not _HEADER_NAME.fullmatch(name) or not re.fullmatch(rb"[ -~]*", value):
            raise ReceiptError(_INVALID_FRAMING)
        name = name.lower()
        if name == b"transfer-encoding":
            raise ReceiptError(_INVALID_FRAMING)
        if name == b"content-length":
            value = value.strip(b" ")
            if length is not None or not _LENGTH.fullmatch(value):
                raise ReceiptError(_INVALID_FRAMING)
            length = int(value)
    if length is None or length > MAX_BODY:
        raise ReceiptError(_INVALID_FRAMING)
    return length


def _request(worker, lease, deadline):
    buffer = bytearray()
    while (end := buffer.find(_END)) < 0:
        remaining = MAX_HEADER - len(buffer)
        if not remaining:
            raise ReceiptError("HTTP request headers exceed limit")
        buffer.extend(_read(worker, min(remaining, relay.CHUNK), lease, deadline))
    size = end + len(_END) + _content_length(bytes(buffer[:end]))
    # A worker may pipeline bytes. Only this first framed request is forwarded.
    del buffer[size:]
    buffer.extend(_read_exact(worker, size - len(buffer), lease, deadline))
    return bytes(buffer)


def forward(worker, broker, lease, proof, deadline):
    """Forward one request and acknowledge exact worker socket handoff.

    Both sockets are connected and owned by the caller, which closes them on
    success or failure. The lease identifies the exact host grant. A receipt
    describes bytes the kernel accepted, before any claim of tool execution.
    """
    if type(proof) is not bytes or len(proof) != relay.PROOF_SIZE:
        raise ReceiptError("invalid relay proof length")
    active = re.fullmatch(rb"[^ \r\n]+ ([1-9]\d{0,19}) active\n", lease.active_record)
    if active is None or not 0 < (generation := int(active[1])) < 2**64:
        raise ReceiptError("invalid relay grant generation")
    # Apply the exchange deadline inside the existing fenced worker send too.
    lease = replace(lease, deadline_ns=min(lease.deadline_ns, int(deadline * 1_000_000_000)))
    try:
        worker.setblocking(False)
        broker.setblocking(False)
        request = _request(worker, lease, min(deadline, time.monotonic() + 5))
        _write(broker, relay.PROOF_PREFIX + proof + REQUEST_LENGTH.pack(len(request)), lease, deadline,
               worker=worker)
        _write(broker, request, lease, deadline, worker=worker)
        request_id, size = RESPONSE_HEADER.unpack(
            _read_exact(broker, RESPONSE_HEADER.size, lease, deadline, worker)
        )
        if request_id == bytes(16) or not 0 < size <= MAX_RESPONSE:
            raise ReceiptError("invalid private response envelope")

        remaining = size
        while remaining:
            data = _read(broker, min(remaining, relay.CHUNK), lease, deadline, worker)
            _write(worker, data, lease, deadline, deliver=relay.deliver)
            remaining -= len(data)

        # After the final worker write, only this trusted peer can receive a
        # receipt. A subsequent worker close does not undo socket handoff.
        _write(broker, RECEIPT.pack(request_id, generation, size), lease, deadline)
        broker.shutdown(socket.SHUT_WR)
    except OSError:
        raise ReceiptError("private exchange I/O failed") from None
