"""A workstation reference to the isolated relay's existing delivery fence."""

from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
import fcntl
import os
import re
import secrets
import stat

from .connection_state import ConnectionError, _lock
from .managed.relay import grant_record


_TEMP = "/tmp"
_LEAF = re.compile(r"oc-i4a-[a-z0-9_]{8}")
_INCARNATION = re.compile(r"inc_[0-9a-f]{32}")
_BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_RETRY = "managed_retirement_incomplete"


@dataclass(frozen=True)
class WorkerLease:
    root: str
    incarnation: str
    generation: int
    grant_dev: int
    grant_ino: int
    lock_dev: int
    lock_ino: int
    lifetime_dev: int
    lifetime_ino: int
    boot: str

    @classmethod
    def parse(cls, value):
        try:
            lease = cls(**value)
            if (not _LEAF.fullmatch(lease.root) or not _INCARNATION.fullmatch(lease.incarnation)
                    or not _BOOT_ID.fullmatch(lease.boot) or not _positive(lease.generation) or lease.generation >= 2**63
                    or not all(_positive(n) for n in (
                        lease.grant_dev, lease.grant_ino, lease.lock_dev, lease.lock_ino,
                        lease.lifetime_dev, lease.lifetime_ino,
                    ))):
                raise ValueError
            return lease
        except (TypeError, ValueError):
            raise ConnectionError(_RETRY) from None

    @classmethod
    def capture(cls, job):
        root = job.root.name
        if job.root.parent.as_posix() != _TEMP or not _LEAF.fullmatch(root):
            raise ConnectionError(_RETRY)
        with _grant(root) as (grant, lock, lifetime):
            lease = cls(root, job.incarnation, job.generation, *_identity(grant),
                        *_identity(lock), *_identity(lifetime), _boot())
        return cls.parse(lease.record())

    def record(self):
        return asdict(self)

    def terminal(self):
        """Publish terminal under the same inode fence used for each relay send."""
        try:
            if _boot() != self.boot:
                return
            with _grant(self.root) as (grant, lock, lifetime):
                self._verify(grant, lock, lifetime)
                _lock(lock)
                current = _read_state(grant)
                terminal = grant_record(self.incarnation, self.generation, False)
                if current == terminal:
                    return
                active = grant_record(self.incarnation, self.generation, True)
                if current not in (b"pending\n", active) and not _owner_gone(lifetime):
                    raise ConnectionError(_RETRY)
                _publish(grant, terminal)
                if _read_state(grant) != terminal:
                    raise ConnectionError(_RETRY)
        except (OSError, ConnectionError):
            raise ConnectionError(_RETRY) from None

    def confirm_terminal(self):
        try:
            with _grant(self.root) as (grant, lock, lifetime):
                self._verify(grant, lock, lifetime)
                _lock(lock)
                if (_read_state(grant) != grant_record(self.incarnation, self.generation, False)
                        and not _owner_gone(lifetime)):
                    raise ConnectionError(_RETRY)
        except (OSError, ConnectionError):
            raise ConnectionError(_RETRY) from None

    def _verify(self, grant, lock, lifetime):
        if (*_identity(grant), *_identity(lock), *_identity(lifetime)) != (
            self.grant_dev, self.grant_ino, self.lock_dev, self.lock_ino, self.lifetime_dev, self.lifetime_ino,
        ):
            raise ConnectionError(_RETRY)


def _identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def _owner_gone(lifetime):
    try:
        fcntl.flock(lifetime, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def _boot():
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as stream:
        value = stream.read(64).strip()
    if not _BOOT_ID.fullmatch(value):
        raise ConnectionError(_RETRY)
    return value


def _positive(value):
    return type(value) is int and value > 0


def _open(stack, name, flags, *, parent=None, exact_mode=None):
    fd = os.open(name, flags, dir_fd=parent)
    stack.callback(os.close, fd)
    if exact_mode is not None:
        info = os.fstat(fd)
        file_ok = bool(flags & os.O_DIRECTORY) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        if not file_ok or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != exact_mode:
            raise ConnectionError(_RETRY)
    return fd


@contextmanager
def _grant(root):
    with ExitStack() as stack:
        shared = _open(stack, _TEMP, _DIR_FLAGS)
        # This directory is checked against the physical host at provisioning.
        info = os.fstat(shared)
        if not info.st_mode & stat.S_ISVTX or info.st_uid not in (0, 65534):
            raise ConnectionError(_RETRY)
        job = _open(stack, root, _DIR_FLAGS, parent=shared, exact_mode=0o700)
        grant = _open(stack, "grant", _DIR_FLAGS, parent=job, exact_mode=0o700)
        lock = _open(stack, "lock", _FILE_FLAGS, parent=grant, exact_mode=0o600)
        lifetime = _open(stack, "lifetime", _FILE_FLAGS, parent=grant, exact_mode=0o600)
        yield grant, lock, lifetime


def _read_state(grant):
    try:
        with ExitStack() as stack:
            state = _open(stack, "state", _FILE_FLAGS, parent=grant, exact_mode=0o600)
            with os.fdopen(os.dup(state), "rb") as stream:
                return stream.read(192)
    except FileNotFoundError:
        return None


def _publish(grant, contents):
    filename = ".retire-" + secrets.token_hex(16)
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=grant)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, "state", src_dir_fd=grant, dst_dir_fd=grant)
        os.fsync(grant)
    finally:
        try:
            os.unlink(filename, dir_fd=grant)
        except FileNotFoundError:
            pass
