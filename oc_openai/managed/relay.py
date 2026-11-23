"""Private loopback relay for the managed OpenCode worker."""

import contextlib
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import select
import selectors
import socket
import stat
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
PROOF = Path("/proof/relay")
PROOF_PREFIX = b"OC-MODEL\x01"
PROOF_SIZE = 32
PEER_CLOSED = select.POLLRDHUP | select.POLLHUP | select.POLLERR | select.POLLNVAL


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


def _identity(info):
    return info.st_dev, info.st_ino


@dataclass(frozen=True)
class Lease:
    directory: Path
    active_record: bytes
    deadline_ns: int
    directory_identity: tuple[int, int] | None = None
    lock_identity: tuple[int, int] | None = None
    lifetime_identity: tuple[int, int] | None = None

    def __post_init__(self):
        if self.directory_identity is None:
            info = self.directory.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("Invalid grant directory")
            object.__setattr__(self, "directory_identity", _identity(info))
        with self._directory() as directory:
            for leaf, field in (("lock", "lock_identity"), ("lifetime", "lifetime_identity")):
                info = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("Invalid grant inode")
                existing = getattr(self, field)
                if existing is None:
                    object.__setattr__(self, field, _identity(info))
                elif existing != _identity(info):
                    raise ValueError("Grant inode changed")

    @contextlib.contextmanager
    def _directory(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if _identity(os.fstat(fd)) != self.directory_identity:
                raise OSError("Grant directory changed")
            yield fd
        finally:
            os.close(fd)

    def status(self) -> str:
        if time.monotonic_ns() >= self.deadline_ns:
            return "terminal"
        try:
            with self._directory() as directory:
                lock = os.stat("lock", dir_fd=directory, follow_symlinks=False)
                if (_identity(lock) != self.lock_identity or lock.st_nlink != 1
                        or not host_owns_job(directory, self.lifetime_identity)):
                    return "terminal"
                fd = os.open("state", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                with os.fdopen(fd, "rb") as state:
                    current = state.read(len(self.active_record) + 1)
        except OSError:
            return "terminal"
        if time.monotonic_ns() >= self.deadline_ns:
            return "terminal"
        if current == self.active_record:
            return "active"
        if current == b"pending\n":
            return "pending"
        return "terminal"

    def active(self) -> bool:
        return self.status() == "active"

    @contextlib.contextmanager
    def fence(self):
        with self._directory() as directory:
            fd = os.open("lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if _identity(info) != self.lock_identity or info.st_nlink != 1:
                    raise OSError("Grant lock changed")
                take_fence(fd)
                yield
            finally:
                os.close(fd)


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


def host_owns_job(grant_fd: int, identity: tuple[int, int]) -> bool:
    # Pin the exclusive owner lock to the exact inode established at launch.
    # A missing, unlocked or replaced inode cannot extend the grant.
    try:
        fd = os.open("lifetime", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=grant_fd)
        try:
            info = os.fstat(fd)
            if _identity(info) != identity or info.st_nlink != 1:
                return False
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
        finally:
            os.close(fd)
    except OSError:
        pass
    return False


def handoff(worker: socket.socket, request: bytes, lease: Lease) -> bytes:
    try:
        with lease.fence():
            if not lease.active():
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


def deliver(lease: Lease, worker: socket.socket, data: bytes) -> int:
    """Order one nonblocking worker-facing send against the terminal fence."""
    with lease.fence():
        if not lease.active():
            return 0
        return worker.send(data)


def control_reply(worker: socket.socket, client: socket.socket, lease: Lease) -> None:
    """Forward one bounded native HTTP response and discard it on revocation."""
    deadline = time.monotonic() + STREAM_TIMEOUT
    client.setblocking(False)
    total = 0
    pending = memoryview(b"")
    peer_poll = select.poll()
    peer_poll.register(client, select.POLLRDHUP)
    while lease.active() and time.monotonic() < deadline:
        reading, writing, _ = select.select(
            [] if pending else [worker], [client] if pending else [], [], GRANT_POLL,
        )
        if any(flags & PEER_CLOSED for _, flags in peer_poll.poll(0)):
            return
        if reading:
            data = worker.recv(CHUNK)
            total += len(data)
            if not data or total > WIRE_LIMIT:
                return
            pending = memoryview(data)
        if writing:
            try:
                count = deliver(lease, client, pending)
            except BlockingIOError:
                continue
            if not count:
                return
            pending = pending[count:]


def control(client: socket.socket, lease: Lease) -> None:
    deadline = time.monotonic() + FRAME_TIMEOUT
    mode = read_exact(client, 1, deadline)
    length = struct.unpack("!I", read_exact(client, 4, deadline))[0]
    if mode != b"N" or not 0 < length <= REQUEST_LIMIT:
        return
    request = read_exact(client, length, deadline)
    client.settimeout(FRAME_TIMEOUT)
    if not lease.active():
        client.sendall(b"Z")
        return
    try:
        worker = socket.create_connection(WORKER, timeout=FRAME_TIMEOUT)
    except OSError:
        client.sendall(b"Z")
        return
    with worker:
        worker.setblocking(False)
        status = handoff(worker, request, lease)
        client.sendall(status)
        if status == b"H":
            control_reply(worker, client, lease)


def provider(worker: socket.socket, lease: Lease, proof: bytes) -> None:
    if not lease.active():
        return
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker:
        broker.settimeout(GRANT_POLL)
        broker.connect(PROVIDER_SOCKET)
        from relay_receipt import forward
        forward(worker, broker, lease, proof, time.monotonic() + STREAM_TIMEOUT)


def serve(lease: Lease, proof: bytes) -> None:
    os.umask(0o077)
    if lease.status() == "terminal":
        return
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
            model: (lambda client: provider(client, lease, proof), threading.BoundedSemaphore(8)),
            driver: (lambda client: control(client, lease), threading.BoundedSemaphore(8)),
        }

        peers = set()
        peers_lock = threading.Lock()

        def handle(client, handler, slots):
            with client:
                try:
                    handler(client)
                except (EOFError, OSError, ValueError):
                    # The driver treats a missing receipt as uncertain.
                    pass
                finally:
                    with peers_lock:
                        peers.discard(client)
                    slots.release()

        try:
            with selectors.DefaultSelector() as selector:
                for listener in listeners:
                    selector.register(listener, selectors.EVENT_READ)
                was_active = False
                while True:
                    status = lease.status()
                    if status == "terminal" or (was_active and status != "active"):
                        break
                    was_active = status == "active"
                    for key, _ in selector.select(GRANT_POLL):
                        listener = key.fileobj
                        handler, slots = listeners[listener]
                        client, _ = listener.accept()
                        if not lease.active() or not slots.acquire(blocking=False):
                            client.close()
                            continue
                        with peers_lock:
                            peers.add(client)
                        try:
                            threading.Thread(target=handle, args=(client, handler, slots), daemon=True).start()
                        except RuntimeError:
                            slots.release()
                            with peers_lock:
                                peers.discard(client)
                            client.close()
        finally:
            with peers_lock:
                for client in peers:
                    with contextlib.suppress(OSError):
                        client.shutdown(socket.SHUT_RDWR)
            # Returning exits this dedicated relay process, closing outbound
            # sockets. The host keeps the exact receipt if it cannot verify
            # removal after owner loss; this relay never sweeps other jobs.


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("Invalid relay arguments")
    active = grant_record(sys.argv[1], int(sys.argv[2]), True)
    with PROOF.open("rb") as file:
        proof = file.read(PROOF_SIZE + 1)
    if len(proof) != PROOF_SIZE:
        sys.exit("Relay proof is missing or invalid")
    serve(Lease(GRANT, active, int(sys.argv[3])), proof)
