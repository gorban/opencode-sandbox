"""Durable registration state with a separately revocable enrollment attempt."""

from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass, replace
import fcntl
import json
import os
import re
import secrets
import stat


HOSTS = ("oauth2.googleapis.com:443", "www.googleapis.com:443")
RECORD_LIMIT = 1024


class EnrollmentUnavailable(RuntimeError):
    """The registration or exact attempt cannot advance."""


@dataclass(frozen=True)
class Identity:
    registration: str
    generation: str
    attempt: str


@dataclass(frozen=True)
class Enrollment:
    identity: Identity
    build: str
    state: str = "pending"
    revoked: bool = False
    attempt_retired: bool = False
    cold_check: str | None = None
    closed_slots: int = 0
    active_slot: str | None = None


def unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise EnrollmentUnavailable("duplicate enrollment record field")
    return result


def require_identifier(value, size):
    if type(value) is not str or not re.fullmatch(rf"[a-f0-9]{{{size}}}", value):
        raise EnrollmentUnavailable("invalid enrollment identifier")


def decode(raw):
    try:
        values = json.loads(raw, object_pairs_hook=unique)
        enrolled = Enrollment(**{**values, "identity": Identity(**values["identity"])})
    except (KeyError, TypeError, ValueError) as error:
        raise EnrollmentUnavailable("invalid enrollment record") from error
    for identifier in asdict(enrolled.identity).values():
        require_identifier(identifier, 32)
    require_identifier(enrolled.build, 64)
    if (set(values) != set(asdict(enrolled)) or enrolled.state not in ("pending", "ready", "abandoned")
            or type(enrolled.revoked) is not bool or type(enrolled.attempt_retired) is not bool
            or type(enrolled.closed_slots) is not int
            or not 0 <= enrolled.closed_slots <= len(HOSTS)):
        raise EnrollmentUnavailable("invalid enrollment record state")
    if enrolled.active_slot is not None and (enrolled.closed_slots >= len(HOSTS)
                                              or enrolled.active_slot != HOSTS[enrolled.closed_slots]):
        raise EnrollmentUnavailable("invalid enrollment slot")
    if enrolled.state != "pending" and not enrolled.revoked:
        raise EnrollmentUnavailable("terminal enrollment retains an active attempt")
    if enrolled.attempt_retired and (not enrolled.revoked or enrolled.active_slot is not None):
        raise EnrollmentUnavailable("invalid enrollment retirement record")
    if enrolled.state == "ready" and not enrolled.attempt_retired:
        raise EnrollmentUnavailable("published enrollment lacks retirement evidence")
    if enrolled.cold_check is not None:
        require_identifier(enrolled.cold_check, 32)
        if not enrolled.attempt_retired or enrolled.state != "pending":
            raise EnrollmentUnavailable("invalid cold readiness check")
    return enrolled


def require_private_file(fd):
    info = os.fstat(fd)
    if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1):
        raise EnrollmentUnavailable("unsafe private enrollment file")


def fetch(directory):
    try:
        fd = os.open("enrollment.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        require_private_file(fd)
        raw = stream.read(RECORD_LIMIT + 1)
    if len(raw) > RECORD_LIMIT:
        raise EnrollmentUnavailable("oversized enrollment record")
    return decode(raw)


def durable_store(directory, value):
    temporary = "enrollment-" + secrets.token_hex(16)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            json.dump(asdict(value), stream, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, "enrollment.json", src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=directory)


class EnrollmentJournal:
    def __init__(self, path):
        self.path = path

    @contextmanager
    def _locked(self):
        directory = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise EnrollmentUnavailable("unsafe private enrollment directory")
            fd = os.open("enrollment.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "rb") as lock:
                require_private_file(lock.fileno())
                fcntl.flock(lock, fcntl.LOCK_EX)
                yield directory
        finally:
            os.close(directory)

    def status(self):
        with self._locked() as directory:
            return fetch(directory)

    def begin(self, build):
        require_identifier(build, 64)
        with self._locked() as directory:
            if fetch(directory) is not None:
                raise EnrollmentUnavailable("registration already has an attempt")
            enrolled = Enrollment(Identity(*(secrets.token_hex(16) for _ in range(3))), build)
            durable_store(directory, enrolled)
            return enrolled.identity

    @contextmanager
    def _exact(self, identity, *, allow_abandoned=False):
        with self._locked() as directory:
            current = fetch(directory)
            permitted = ("pending", "abandoned") if allow_abandoned else ("pending",)
            if current is None or current.identity != identity or current.state not in permitted:
                raise EnrollmentUnavailable("the exact enrollment changed")
            yield directory, current

    def reserve(self, identity, target):
        with self._exact(identity) as (directory, current):
            index = current.closed_slots
            if current.revoked or current.active_slot is not None or index == len(HOSTS) or target != HOSTS[index]:
                raise EnrollmentUnavailable("the enrollment tunnel slot is unavailable")
            durable_store(directory, replace(current, active_slot=target))

    def retired(self, identity, target):
        with self._exact(identity) as (directory, current):
            if current.revoked or current.active_slot is None or current.active_slot != target:
                raise EnrollmentUnavailable("the enrollment tunnel did not retire in order")
            durable_store(directory, replace(current, closed_slots=current.closed_slots + 1, active_slot=None))

    def revoke(self, identity):
        with self._exact(identity) as (directory, current):
            if not current.revoked or current.cold_check is not None:
                durable_store(directory, replace(current, revoked=True, cold_check=None))

    def record_attempt_retirement(self, identity):
        """Record the supervisor's verification that the broker and unit retired."""
        with self._exact(identity, allow_abandoned=True) as (directory, current):
            if not current.revoked and current.closed_slots != len(HOSTS):
                raise EnrollmentUnavailable("the enrollment attempt is still active")
            if not current.attempt_retired:
                durable_store(directory, replace(current, revoked=True, attempt_retired=True, active_slot=None))

    def begin_cold_check(self, identity):
        with self._exact(identity) as (directory, current):
            if not current.attempt_retired or current.cold_check is not None:
                raise EnrollmentUnavailable("the cold readiness check is unavailable")
            check = secrets.token_hex(16)
            durable_store(directory, replace(current, cold_check=check))
            return check

    def mark_ready_after_cold_check(self, identity, check):
        require_identifier(check, 32)
        with self._exact(identity) as (directory, current):
            if not current.attempt_retired or current.cold_check != check:
                raise EnrollmentUnavailable("the exact cold readiness check changed")
            durable_store(directory, replace(current, state="ready", revoked=True, cold_check=None))

    def abandon(self, identity):
        with self._exact(identity) as (directory, current):
            durable_store(directory, replace(current, state="abandoned", revoked=True, cold_check=None))
