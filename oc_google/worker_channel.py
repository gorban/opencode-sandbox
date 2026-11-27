"""Retain one locally adopted worker socket through exact offline retirement."""

from array import array
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum, auto
import fcntl
from hashlib import sha256
import hmac
import os
import re
import select
import socket
import stat
import struct
from threading import Lock
from time import monotonic

from oc_orchestrator import protocol

from .route import _send_once


_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)
_SCM_PIDFD = getattr(socket, "SCM_PIDFD", 4)
_COOKIE = getattr(socket, "SO_COOKIE", 57)
_NETNS_COOKIE = getattr(socket, "SO_NETNS_COOKIE", 71)
_CREDENTIALS = struct.Struct("=iII")
_FD = struct.Struct("=i")
_U64 = struct.Struct("=Q")
_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z", re.ASCII)
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_ADOPTION_SECONDS = 5


class WorkerChannelError(RuntimeError):
    """The exact worker connection could not be adopted, settled, or used."""


def _reject_clone(self, *_):
    raise TypeError(f"{type(self).__name__} has exclusive ownership")


def _require(condition, message):
    if not condition:
        raise WorkerChannelError(message)


def _ident(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def _pidfd_pid(fd):
    with open(f"/proc/self/fdinfo/{fd}", "rb") as file:
        fields = file.read(4097).splitlines()
    pids = [line[4:].strip() for line in fields if line.startswith(b"Pid:")]
    _require(len(pids) == 1 and re.fullmatch(rb"-?[0-9]{1,10}", pids[0]), "Invalid worker process pin")
    return int(pids[0])


def _dead(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    return any(events & select.POLLIN for _, events in poll.poll(0))


class ProcessPin:
    """Own a duplicate of a host-captured pidfd and its exact cgroup expectation."""

    __copy__ = __deepcopy__ = __reduce_ex__ = _reject_clone

    def __init__(self, *, pid, uid, pidfd, cgroup, read_cgroup):
        _require(type(pid) is int and pid > 0 and type(uid) is int and uid >= 0
                 and type(cgroup) is bytes and 1 < len(cgroup) <= 4091 and cgroup.startswith(b"/")
                 and all(33 <= byte <= 126 for byte in cgroup), "Invalid worker process authority")
        self._pid = pid
        self._uid = uid
        self._group = b"0::" + cgroup
        self._read = read_cgroup
        self._lock = Lock()
        self._inode = _ident(pidfd)
        self._fd = os.dup(pidfd)
        try:
            _require(self.active(), "Worker process authority is not current")
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _matches(self, fd):
        try:
            return fd is not None and _ident(fd) == self._inode
        except OSError:
            return False

    def close(self):
        with self._lock:
            fd, self._fd = self._fd, None
            if self._matches(fd):
                os.close(fd)

    def active(self):
        with self._lock:
            fd = self._fd
            if not self._matches(fd) or _dead(fd) or _pidfd_pid(fd) != self._pid:
                return False
        group = self._read(self._pid)
        with self._lock:
            return (type(group) is bytes and len(group) <= 4096 and group.splitlines() == [self._group]
                    and self._fd == fd and self._matches(fd) and not _dead(fd))

    def alive(self):
        """Recheck the kernel pin without calling the placement observer."""
        with self._lock:
            fd = self._fd
            return self._matches(fd) and _pidfd_pid(fd) == self._pid and not _dead(fd)

    def retired(self):
        with self._lock:
            fd = self._fd
            return self._matches(fd) and _dead(fd) and _pidfd_pid(fd) == -1

    def require_peer(self, control):
        _require(control.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_UNIX
                 and control.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
                 "Unexpected relay control socket")
        pid, uid, _ = _CREDENTIALS.unpack(control.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                            _CREDENTIALS.size))
        _require(pid == self._pid and uid == self._uid, "Relay control peer credentials differ")
        fd, = _FD.unpack(control.getsockopt(socket.SOL_SOCKET, _PEERPIDFD, _FD.size))
        try:
            _require(_ident(fd) == self._inode and _pidfd_pid(fd) == self._pid and not _dead(fd) and self.active(),
                     "Relay control peer process or cgroup differs")
        finally:
            os.close(fd)


def _cookie(connection, option):
    value, = _U64.unpack(connection.getsockopt(socket.SOL_SOCKET, option, _U64.size))
    _require(value > 0, "Kernel socket cookie is unavailable")
    return value


@dataclass(frozen=True, slots=True, init=False)
class WorkerNamespaceReference:
    """Scope the cookie from a separate host-owned probe of the verified worker."""

    worker_id: str
    run: str
    epoch: str
    probe_id: str
    cookie: int

    def __init__(self, connection, *, worker_id, run, epoch, probe_id):
        _require(connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_INET,
                 "Unexpected worker namespace reference socket")
        object.__setattr__(self, "worker_id", worker_id)
        object.__setattr__(self, "run", run)
        object.__setattr__(self, "epoch", epoch)
        object.__setattr__(self, "probe_id", probe_id)
        object.__setattr__(self, "cookie", _cookie(connection, _NETNS_COOKIE))


@dataclass(frozen=True, slots=True, eq=False)
class WorkerPlacement:
    worker_id: str
    worker_image: str
    relay_id: str
    relay_image: str
    run: str
    route: str
    epoch: str
    network_mode: str
    relay_network_mode: str
    worker: ProcessPin
    relay: ProcessPin
    reference: WorkerNamespaceReference


@dataclass(frozen=True, slots=True, eq=False)
class AdoptedWorker:
    placement: WorkerPlacement
    request_digest: str
    socket_cookie: int


@dataclass(frozen=True, slots=True, eq=False)
class RelayRetirement:
    """Evidence from the private placement observer for this exact adoption."""

    adopted: AdoptedWorker
    relay_id: str


@dataclass(frozen=True, slots=True)
class DeliveryReceipt:
    attempted: bool = False
    bytes_sent: int | None = 0
    complete: bool = False


@dataclass(frozen=True, slots=True)
class _DescriptorPin:
    fd: int
    inode: tuple[int, int]
    cookie: int

    def matches(self, connection):
        fd = connection.fileno()
        try:
            return fd == self.fd and _ident(fd) == self.inode and _cookie(connection, _COOKIE) == self.cookie
        except (OSError, WorkerChannelError, struct.error):
            return False


@dataclass(frozen=True, slots=True)
class _SocketIdentity:
    pin: _DescriptorPin
    local: tuple[str, int]
    remote: tuple[str, int]
    namespace: int


def _socket_identity(connection, port):
    fd = connection.fileno()
    info = os.fstat(fd)
    _require(stat.S_ISSOCK(info.st_mode) and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
             and connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_INET
             and connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
             and connection.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL) == socket.IPPROTO_TCP
             and connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 0
             and connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0,
             "Unexpected worker TCP socket")
    local, remote = connection.getsockname(), connection.getpeername()
    _require(local == ("127.0.0.1", port) and remote[0] == "127.0.0.1"
             and type(remote[1]) is int and 0 < remote[1] <= 65535 and local != remote,
             "Unexpected worker TCP endpoints")
    pin = _DescriptorPin(fd, (info.st_dev, info.st_ino), _cookie(connection, _COOKIE))
    return _SocketIdentity(pin, local, remote, _cookie(connection, _NETNS_COOKIE))


def _remaining(deadline):
    seconds = deadline - monotonic()
    _require(seconds > 0, "Worker handoff deadline expired")
    return seconds


def _receive_control(control, deadline, count, *, handoff=False):
    fds = array("i")
    control.settimeout(_remaining(deadline))
    data, messages, flags, _ = control.recvmsg(
        count, socket.CMSG_SPACE(fds.itemsize * 2), socket.MSG_CMSG_CLOEXEC,
    )
    try:
        valid = True
        for level, kind, ancillary in messages:
            if level != socket.SOL_SOCKET or kind not in (socket.SCM_RIGHTS, _SCM_PIDFD):
                valid = False
                continue
            # Unexpected SCM_PIDFD carries an installed descriptor as well.
            valid &= kind == socket.SCM_RIGHTS
            aligned = len(ancillary) - len(ancillary) % fds.itemsize
            fds.frombytes(ancillary[:aligned])
            valid &= aligned == len(ancillary)
        _require(valid and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC),
                 "Truncated relay handoff")
        if not handoff:
            _require(not messages, "Unexpected descriptor outside worker handoff")
            return data
        _require(data == b"F" and len(messages) == len(fds) == 1, "Expected exactly one worker descriptor")
        _require(stat.S_ISSOCK(os.fstat(fds[0]).st_mode), "Unexpected worker descriptor type")
        connection = socket.socket(fileno=fds[0])
        fds.pop()
        return connection
    finally:
        for fd in fds:
            os.close(fd)


def _receive_proof(control, deadline):
    proof = bytearray()
    while len(proof) != protocol.PROOF_SIZE:
        data = _receive_control(control, deadline, protocol.PROOF_SIZE - len(proof))
        _require(data, "Missing worker handoff proof")
        proof.extend(data)
    return proof


def _quiet_client(connection):
    connection.setblocking(False)
    try:
        connection.recv(1, socket.MSG_PEEK)
    except BlockingIOError:
        return
    raise WorkerChannelError("Worker socket already closed or contains extra request data")


class _Phase(Enum):
    OPEN = auto()
    ADOPTING = auto()
    ADOPTED = auto()
    CLOSED = auto()
    SEALED = auto()
    SPENT = auto()
    REVOKED = auto()


class RetainedWorkerChannel:
    """Leaf for one private relay handoff and one retained-socket delivery.

    The private placement owner supplies a shared reentrant fence, current owner
    and worker checks, independently observed relay retirement, and the durable
    delivery claim. Podman inspection, probe removal, and native retirement are
    upstream obligations of that owner.
    """

    __copy__ = __deepcopy__ = __reduce_ex__ = _reject_clone

    def __init__(self, placement, *, port, model, system_digest, worker_token, proof, fence,
                 owner_current, worker_current, retirement_current, claim_delivery):
        _require(type(placement) is WorkerPlacement, "Expected typed worker placement")
        ids = (placement.worker_id, placement.worker_image, placement.relay_id, placement.relay_image)
        tags = (placement.run, placement.route, placement.epoch, model)
        _require(all(type(value) is str and _CONTAINER_ID.fullmatch(value) for value in ids)
                 and all(type(value) is str and _ID.fullmatch(value) for value in tags)
                 and placement.worker_id != placement.relay_id
                 and type(placement.worker) is ProcessPin and type(placement.relay) is ProcessPin
                 and placement.worker._pid != placement.relay._pid
                 and placement.network_mode == "none"
                 and placement.relay_network_mode == f"container:{placement.worker_id}",
                 "Unexpected retained worker placement")
        reference = placement.reference
        _require(type(reference) is WorkerNamespaceReference and reference.worker_id == placement.worker_id
                 and reference.run == placement.run and reference.epoch == placement.epoch
                 and type(reference.probe_id) is str and _ID.fullmatch(reference.probe_id)
                 and type(reference.cookie) is int and 0 < reference.cookie < 2**64,
                 "Unexpected worker namespace reference")
        _require(type(port) is int and 0 < port <= 65535
                 and type(proof) is bytes and len(proof) == protocol.PROOF_SIZE
                 and type(worker_token) is bytes and re.fullmatch(rb"[A-Za-z0-9._~+/-]{1,256}={0,2}", worker_token)
                 and type(system_digest) is str and _CONTAINER_ID.fullmatch(system_digest),
                 "Unexpected fixed worker protocol")
        self._placement = placement
        self._port, self._model, self._system_digest = port, model, system_digest
        self._worker_token, self._proof = worker_token, proof
        self._fence = fence
        self._owner_current, self._worker_current = owner_current, worker_current
        self._retirement_current, self._claim_delivery = retirement_current, claim_delivery
        self._phase = _Phase.OPEN
        self._control = self._control_pin = self._client = self._identity = None
        self._adopted = self._retirement = None
        self._delivery = DeliveryReceipt()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.revoke()

    @property
    def delivery(self):
        with self._fence:
            return self._delivery

    @staticmethod
    def _close_exact(connection, pin, *, shutdown):
        if shutdown and pin.matches(connection):
            with suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
        if pin.matches(connection):
            connection.close()
        else:
            # Do not close a foreign object that reused the descriptor number.
            connection.detach()

    def _close_control_locked(self, *, shutdown):
        control, pin = self._control, self._control_pin
        self._control = self._control_pin = None
        if control is not None:
            self._close_exact(control, pin, shutdown=shutdown)

    def _revoke_locked(self):
        self._phase = _Phase.REVOKED
        client, self._client = self._client, None
        try:
            if client is not None:
                self._close_exact(client, self._identity.pin, shutdown=True)
        finally:
            self._close_control_locked(shutdown=True)

    def revoke(self):
        with self._fence:
            self._revoke_locked()

    def close_admission(self):
        """Close further acquisition while retaining a fully adopted connection."""
        with self._fence:
            if self._phase is _Phase.ADOPTED:
                self._phase = _Phase.CLOSED
            elif self._phase in (_Phase.OPEN, _Phase.ADOPTING):
                self._revoke_locked()

    def _check_worker(self, phase):
        _require(self._phase is phase and self._placement.worker.active()
                 and self._worker_current(self._placement) is True and self._placement.worker.active()
                 and self._owner_current() is True and self._phase is phase,
                 "Retained worker or owner is no longer current")

    def _check_worker_pin(self, phase):
        _require(self._phase is phase and self._placement.worker.alive(),
                 "Retained worker or owner is no longer current")

    def _check_live_adoption(self):
        _require(self._placement.relay.alive(), "Relay exited before worker socket adoption")
        self._check_worker_pin(_Phase.ADOPTING)

    def _check_client(self):
        client = self._client
        try:
            identity = _socket_identity(client, self._port) if client is not None else None
        except OSError:
            raise WorkerChannelError("Retained worker descriptor changed") from None
        _require(identity is not None and identity == self._identity, "Retained worker descriptor changed")
        _quiet_client(client)

    def _check_control(self, control):
        _require(self._phase is _Phase.ADOPTING and control is self._control and self._control_pin.matches(control),
                 "Retained relay control descriptor changed")

    def adopt(self, control):
        """Authenticate one request and consume the AF_UNIX stream once pinned."""
        deadline = monotonic() + _MAX_ADOPTION_SECONDS
        with self._fence:
            try:
                fd = control.fileno()
                pin = _DescriptorPin(fd, _ident(fd), _cookie(control, _COOKIE))
            except (OSError, WorkerChannelError, struct.error):
                raise WorkerChannelError("Relay control descriptor could not be pinned") from None
            if self._phase is not _Phase.OPEN:
                if control is not self._control:
                    self._close_exact(control, pin, shutdown=False)
                raise WorkerChannelError("Worker admission is closed")
            self._phase = _Phase.ADOPTING
            self._control, self._control_pin = control, pin
        candidate = identity = None
        try:
            self._placement.relay.require_peer(control)
            with self._fence:
                self._check_worker(_Phase.ADOPTING)
                self._check_control(control)
                self._check_live_adoption()
            proof = _receive_proof(control, deadline)
            _require(hmac.compare_digest(proof, self._proof), "Worker handoff proof differs")
            with self._fence:
                self._check_control(control)
            candidate = _receive_control(control, deadline, 1, handoff=True)
            _require(_receive_control(control, deadline, 1) == b"", "Extra relay handoff data")
            identity = _socket_identity(candidate, self._port)
            _require(identity.namespace == self._placement.reference.cookie, "Worker socket namespace differs")
            with self._fence:
                _require(self._placement.relay.active(), "Relay exited before worker socket adoption")
                self._check_worker(_Phase.ADOPTING)
                self._check_control(control)
                _require(_socket_identity(candidate, self._port) == identity, "Retained worker descriptor changed")
                self._check_live_adoption()
                self._client, self._identity = candidate, identity
                candidate = None
                client = self._client
            body = protocol.request_body(client, deadline, self._port, worker_token=self._worker_token)
            protocol.accept_text(body, model=self._model, system_digest=self._system_digest)
            with self._fence:
                _require(self._placement.relay.active(), "Relay exited before authenticating worker request")
                self._check_worker(_Phase.ADOPTING)
                self._check_client()
                self._check_control(control)
                self._check_live_adoption()
                self._adopted = AdoptedWorker(self._placement, sha256(body).hexdigest(), identity.pin.cookie)
                self._phase = _Phase.ADOPTED
                return self._adopted
        except BaseException as exc:
            self.revoke()
            if isinstance(exc, (OSError, ValueError, struct.error)):
                raise WorkerChannelError("Worker handoff or fixed request refused") from None
            raise
        finally:
            if candidate is not None:
                if identity is None:
                    candidate.close()
                else:
                    self._close_exact(candidate, identity.pin, shutdown=False)
            with self._fence:
                if self._control is control:
                    self._close_control_locked(shutdown=False)

    def _check_retirement(self, receipt, phase):
        _require(type(receipt) is RelayRetirement and receipt.adopted is self._adopted
                 and receipt.relay_id == self._placement.relay_id and self._placement.relay.retired()
                 and self._retirement_current(receipt) is True and self._placement.relay.retired(),
                 "Exact relay retirement is unconfirmed")
        self._check_worker(phase)
        self._check_client()
        _require(self._placement.relay.retired(), "Exact relay retirement is unconfirmed")
        # Both observers and socket checks precede the final kernel liveness sample.
        self._check_worker_pin(phase)

    def seal(self, receipt):
        """Bind exact observed relay retirement to the retained worker channel."""
        with self._fence:
            try:
                _require(self._phase is _Phase.CLOSED, "Worker admission is not closed for settlement")
                self._check_retirement(receipt, _Phase.CLOSED)
                self._retirement = receipt
                self._phase = _Phase.SEALED
            except BaseException:
                self._revoke_locked()
                raise

    def deliver(self):
        """Spend the private durable claim and attempt exactly one bounded syscall."""
        with self._fence:
            _require(self._phase is _Phase.SEALED, "Worker delivery is not available")
            self._phase = _Phase.SPENT
            try:
                retirement = self._retirement
                self._check_retirement(retirement, _Phase.SPENT)
                _require(self._claim_delivery(self._adopted, retirement) is True,
                         "Durable worker delivery claim is unconfirmed")
                response = protocol.text_reply_bytes(self._model)
                self._check_retirement(retirement, _Phase.SPENT)
                self._delivery = DeliveryReceipt(attempted=True, bytes_sent=None)
                sent = _send_once(self._client, response)
                if type(sent) is int and 0 <= sent <= len(response):
                    self._delivery = DeliveryReceipt(True, sent, sent == len(response))
                _require(self._delivery.complete, "Worker response write was incomplete")
                return self._delivery
            finally:
                self._revoke_locked()
