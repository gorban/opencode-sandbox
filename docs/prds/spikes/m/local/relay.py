"""Loopback relay for the offline PoC. Copy this file into the isolated sidecar."""

import fcntl
import os
from pathlib import Path
import select
import selectors
import socket
import struct
import sys
import threading
import time


WORKER = ("127.0.0.1", 4096)
PROVIDER = ("127.0.0.1", 8401)
REQUEST_LIMIT = 64 * 1024
WIRE_LIMIT = 2 * 1024 * 1024
FRAME_TIMEOUT = 8
STREAM_TIMEOUT = 90
FENCE_TIMEOUT = 3
CHUNK = 16 * 1024
GRANT_POLL = 0.05
PROVIDER_SOCKET = "/provider/provider.sock"
CONTROL_SOCKET = "/control/control.sock"
GRANT = Path("/grant")


def grant_record(incarnation: str, generation: int, active: bool) -> bytes:
    return f"{incarnation} {generation} {'active' if active else 'terminal'}\n".encode("ascii")


def take_fence(fd: int) -> None:
    deadline = time.monotonic() + FENCE_TIMEOUT
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise TimeoutError("Grant fence timed out") from None
            time.sleep(0.01)


def read_exact(peer: socket.socket, length: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Control frame timed out")
        peer.settimeout(remaining)
        chunk = peer.recv(length - len(data))
        if not chunk:
            raise EOFError("Incomplete control frame")
        data.extend(chunk)
    return bytes(data)


def host_owns_job(grant: Path) -> bool:
    # An abandoned grant is inert even if a terminal-state write failed before
    # the driver process exited. The relay never acquires a blocking lifetime lock.
    try:
        with (grant / "lifetime").open("rb") as lifetime:
            try:
                fcntl.flock(lifetime.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
    except OSError:
        pass
    return False


def grant_active(grant: Path, active: bytes) -> bool:
    try:
        with (grant / "state").open("rb") as state:
            return state.read(len(active) + 1) == active and host_owns_job(grant)
    except OSError:
        return False


def handoff(worker: socket.socket, request: bytes, grant: Path, active: bytes) -> bytes:
    # This fd is opened for each attempt. Sharing it between threads would defeat
    # flock exclusion because the lock belongs to the open file description.
    try:
        with (grant / "lock").open("rb") as lock:
            take_fence(lock.fileno())
            if not grant_active(grant, active):
                return b"Z"
            try:
                submitted = worker.send(request)
            except BlockingIOError:
                return b"Z"
            except OSError:
                return b"U"
            if submitted == 0:
                return b"Z"
            return b"H" if submitted == len(request) else b"U"
    except FileNotFoundError:
        return b"Z"


def copy_streams(
    peers: dict[socket.socket, socket.socket],
    eof_peer: socket.socket,
    grant: Path,
    active: bytes,
    *,
    watch_peer: socket.socket | None = None,
) -> None:
    """Copy at most one buffered chunk in each direction and exit on revoke."""
    deadline = time.monotonic() + STREAM_TIMEOUT
    for peer in set(peers) | set(peers.values()):
        peer.setblocking(False)
    totals = dict.fromkeys(peers, 0)
    sources = set(peers)
    pending: dict[socket.socket, bytes] = {}
    peer_poll = select.poll()
    closed = select.POLLRDHUP | select.POLLHUP | select.POLLERR | select.POLLNVAL
    if watch_peer is not None:
        peer_poll.register(watch_peer, select.POLLRDHUP)
    while (sources or pending) and grant_active(grant, active):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        reading, writing, _ = select.select(
            sources - pending.keys(), [peers[source] for source in pending], [], min(remaining, GRANT_POLL),
        )
        if not grant_active(grant, active) or time.monotonic() >= deadline:
            return
        if watch_peer is not None and any(flags & closed for _, flags in peer_poll.poll(0)):
            # Check hangup without considering extra input a second request.
            return
        for source, data in list(pending.items()):
            target = peers[source]
            if target not in writing:
                continue
            try:
                sent = target.send(data)
            except BlockingIOError:
                continue
            if not sent:
                return
            if sent == len(data):
                del pending[source]
            else:
                pending[source] = data[sent:]
        for source in reading:
            try:
                data = source.recv(CHUNK)
            except BlockingIOError:
                continue
            if not data:
                if source is eof_peer:
                    return
                sources.remove(source)
                peers[source].shutdown(socket.SHUT_WR)
                continue
            totals[source] += len(data)
            if totals[source] > WIRE_LIMIT:
                return
            pending[source] = data


def control(client: socket.socket, active: bytes) -> None:
    deadline = time.monotonic() + FRAME_TIMEOUT
    mode = read_exact(client, 1, deadline)
    length = struct.unpack("!I", read_exact(client, 4, deadline))[0]
    if mode not in (b"N", b"P") or not 0 < length <= REQUEST_LIMIT:
        return
    request = read_exact(client, length, deadline)
    try:
        worker = socket.create_connection(WORKER, timeout=FRAME_TIMEOUT)
    except OSError:
        client.sendall(b"Z")
        return
    with worker:
        if mode == b"P":
            client.settimeout(FRAME_TIMEOUT)
            client.sendall(b"P")
            if read_exact(client, 1, time.monotonic() + FRAME_TIMEOUT) != b"G":
                return
        worker.setblocking(False)
        status = handoff(worker, request, GRANT, active)
        client.settimeout(FRAME_TIMEOUT)
        client.sendall(status)
        if status == b"H":
            copy_streams({worker: client}, worker, GRANT, active, watch_peer=client)


def provider(worker: socket.socket, active: bytes) -> None:
    if not grant_active(GRANT, active):
        return
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker:
        broker.settimeout(GRANT_POLL)
        broker.connect(PROVIDER_SOCKET)
        copy_streams({worker: broker, broker: worker}, broker, GRANT, active)


def serve(active: bytes) -> None:
    os.umask(0o077)
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as model,
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as driver,
    ):
        model.bind(PROVIDER)
        driver.bind(CONTROL_SOCKET)
        model.listen(8)
        driver.listen(8)
        # Bound concurrent connections on each listener independently.
        listeners = {
            model: (lambda client: provider(client, active), threading.BoundedSemaphore(8)),
            driver: (lambda client: control(client, active), threading.BoundedSemaphore(8)),
        }

        def handle(client, handler, slots):
            with client:
                try:
                    handler(client)
                except (EOFError, OSError, ValueError):
                    # The driver treats a missing receipt as uncertain.
                    pass
                finally:
                    slots.release()

        with selectors.DefaultSelector() as selector:
            for listener in listeners:
                selector.register(listener, selectors.EVENT_READ)
            while True:
                for key, _ in selector.select():
                    listener = key.fileobj
                    handler, slots = listeners[listener]
                    client, _ = listener.accept()
                    if not slots.acquire(blocking=False):
                        client.close()
                        continue
                    threading.Thread(target=handle, args=(client, handler, slots), daemon=True).start()


if __name__ == "__main__":
    serve(grant_record(sys.argv[1], int(sys.argv[2]), True))
