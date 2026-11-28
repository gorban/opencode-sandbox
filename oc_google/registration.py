"""Durable local Google enrollment observations and launch records."""

from collections.abc import Callable
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import asdict, dataclass, replace
import errno
from enum import StrEnum
import fcntl
from hashlib import sha256
from hmac import compare_digest
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import threading
import time

from oc_providers.config import ProviderConfigError, _account_home, _check_dir_stat, _inside_sandbox
from oc_providers.contracts import is_valid_instance_label

from .account_binding import SubjectProof, bind_subject, rebind_subject
from .metadata_destination import MetadataRoute
from .oauth_exchange import validate_refresh_form


_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_RECORD = "registration.json"
_LOCK = "registration.lock"
_CUSTODY = "cold-custody.json"
_INVOCATION = "cold-invocation.json"
_LIMIT = 4096
_CREDENTIAL_LIMIT = 65536
_LOCK_TIME = .5
_RUNTIME_PARENT = Path("/run/user")


_STORAGE_UNAVAILABLE = "Google registration storage is unavailable"


class RegistrationUnavailable(RuntimeError):
    """The local enrollment authority cannot advance or be verified."""


@contextmanager
def _metadata_storage_errors():
    try:
        yield
    except (OSError, ProviderConfigError):
        raise RegistrationUnavailable("Google metadata settlement storage is unavailable") from None


class Phase(StrEnum):
    PENDING = "pending"
    ENROLLING = "enrolling"
    ENROLLMENT_RETIRED = "enrollment-retired"
    COLD_PENDING = "cold-pending"
    COLD_CHECKING = "cold-checking"
    COLD_RETIREMENT_OBSERVED = "cold-retirement-observed"


_ENROLLMENT_ROUTES = (MetadataRoute.TOKEN, MetadataRoute.USERINFO, MetadataRoute.LOAD_CODE_ASSIST)
_COLD_ROUTES = (*_ENROLLMENT_ROUTES, MetadataRoute.FETCH_AVAILABLE_MODELS)


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int

    @classmethod
    def of(cls, info):
        return cls(info.st_dev, info.st_ino)


@dataclass(frozen=True)
class Enrollment:
    label: str
    registration_id: str
    generation: str
    attempt: str
    build_digest: str
    profile_identity: FileIdentity
    subject_key_identity: FileIdentity


@dataclass(frozen=True)
class ColdCheck:
    enrollment: Enrollment
    nonce: str
    credential_identity: FileIdentity


@dataclass(frozen=True)
class ColdObservation:
    """Caller-reported metadata and retirement for one local cold check."""

    check: ColdCheck
    authenticated_metadata: bool
    prompt_count: int
    native_retired: bool


@dataclass(frozen=True)
class RegistrationStatus:
    label: str
    registration_id: str
    generation: str
    phase: Phase


@dataclass(frozen=True)
class PinnedProfile:
    path: Path
    fd: int
    reserve_enrollment_spawn: Callable[..., None] | None
    bind_subject: Callable[..., SubjectProof]
    spend_metadata: Callable[..., None]
    refresh_form: Callable[[bytes], bytes]
    verify_cold_source: Callable[[], None]
    stage_cold_source: Callable[..., "ColdReplica"]
    bind_native_invocation: Callable[..., None]
    verify_native_invocation: Callable[..., None]
    complete_cold_custody: Callable[..., RegistrationStatus]
    complete_enrollment: Callable[..., RegistrationStatus]
    phase_scope: object
    record_native_custody: Callable[..., None]


@dataclass(frozen=True)
class _Record:
    version: int
    enrollment: Enrollment
    lock_identity: FileIdentity
    phase: Phase
    check_nonce: str | None = None
    credential_identity: FileIdentity | None = None
    subject_digest: str | None = None
    cold_subject_observed: bool = False
    enrollment_metadata_spent: int = 0
    cold_metadata_spent: int = 0
    metadata_pending: bool = False

    def status(self):
        return RegistrationStatus(self.enrollment.label, self.enrollment.registration_id,
                                  self.enrollment.generation, self.phase)

    def check(self):
        return ColdCheck(self.enrollment, self.check_nonce, self.credential_identity)


class ColdReplica:
    """An attempt-owned mount and cleanup capability, pinned until settlement."""

    def __init__(self, root, runtime_fd, root_fd, profile_fd, unit, reserve_spawn, abandon):
        self.root = root
        self.unit = unit
        self._reserve_spawn = reserve_spawn
        self._abandon = abandon
        self._runtime_fd = self._root_fd = self._profile_fd = None
        self._service = None
        self._invocation = None
        self._cleanup_confirmed = False
        self._definite_no_spawn = None
        try:
            self._runtime_fd = os.dup(runtime_fd)
            self._root_fd = os.dup(root_fd)
            self._profile_fd = os.dup(profile_fd)
        except OSError:
            self.close()
            raise RegistrationUnavailable("Google cold replica descriptors are unavailable") from None

    def _require_open(self):
        if self._runtime_fd is None or self._root_fd is None or self._profile_fd is None:
            raise RegistrationUnavailable("Google cold replica has retired")

    def mount_path(self):
        self._require_open()
        profile = self.root / "profile"
        try:
            entry = os.stat(self.root.name, dir_fd=self._runtime_fd, follow_symlinks=False)
            if (not os.path.samestat(os.fstat(self._runtime_fd), self.root.parent.lstat())
                    or not os.path.samestat(os.fstat(self._root_fd), entry)
                    or not os.path.samestat(os.fstat(self._profile_fd), profile.lstat())):
                raise RegistrationUnavailable("Google cold replica mount changed")
        except OSError:
            raise RegistrationUnavailable("Google cold replica mount changed") from None
        return profile

    def remove(self):
        if self._service is None or self._service.retired != self._invocation:
            raise RegistrationUnavailable("Google cold replica still belongs to a live or uncertain service")
        self._remove_files()

    def _remove_files(self):
        self.mount_path()
        quarantine = self._quarantine
        try:
            os.mkdir(quarantine, 0o700, dir_fd=self._runtime_fd)
            quarantine_fd = os.open(quarantine, _DIRECTORY, dir_fd=self._runtime_fd)
            try:
                os.rename(self.root.name, "replica", src_dir_fd=self._runtime_fd, dst_dir_fd=quarantine_fd)
                entry = os.stat("replica", dir_fd=quarantine_fd, follow_symlinks=False)
                if not os.path.samestat(os.fstat(self._root_fd), entry):
                    raise RegistrationUnavailable("Google cold cleanup could not identify the recovered tree")
                shutil.rmtree("replica", dir_fd=quarantine_fd)
            finally:
                os.close(quarantine_fd)
            os.rmdir(quarantine, dir_fd=self._runtime_fd)
        except OSError:
            raise RegistrationUnavailable("Google cold replica cleanup is unavailable") from None
        if not self._deletion_absent():
            raise RegistrationUnavailable("Google cold replica removal is incomplete")
        self._cleanup_confirmed = True

    def _bind(self, service, invocation):
        if self._service is not None and (self._service is not service or self._invocation != invocation):
            raise RegistrationUnavailable("Google cold replica invocation already bound")
        self._service = service
        self._invocation = invocation

    def mount_source(self):
        self.mount_path()
        info = os.fstat(self._profile_fd)
        return Path(f"/proc/{os.getpid()}/fd/{self._profile_fd}"), info.st_dev, info.st_ino

    def reserve_spawn(self, authorized):
        self._reserve_spawn(self, authorized)

    def _failed_to_spawn(self, confirmed=lambda: True):
        self._definite_no_spawn = confirmed

    def _confirmed_no_spawn(self):
        return self._definite_no_spawn is not None and self._definite_no_spawn()

    def abandon_unlaunched(self):
        self._abandon(self)

    def removed(self):
        return self._cleanup_confirmed and self._deletion_absent()

    @property
    def _quarantine(self):
        return "." + self.root.name + "-retire"

    def _deletion_absent(self):
        self._require_open()
        try:
            return (os.path.samestat(os.fstat(self._runtime_fd), self.root.parent.lstat())
                    and os.fstat(self._root_fd).st_nlink == 0 and os.fstat(self._profile_fd).st_nlink == 0
                    and _absent(self.root.name, directory=self._runtime_fd)
                    and _absent(self._quarantine, directory=self._runtime_fd))
        except OSError:
            raise RegistrationUnavailable("Google cold replica removal cannot be verified") from None

    def close(self):
        for name in ("_profile_fd", "_root_fd", "_runtime_fd"):
            fd = getattr(self, name)
            if fd is not None:
                setattr(self, name, None)
                os.close(fd)


def _hex(value, width):
    return type(value) is str and re.fullmatch(rf"[0-9a-f]{{{width}}}", value) is not None


def _unique(pairs):
    values = dict(pairs)
    if len(values) != len(pairs):
        raise ValueError("duplicate registration record entry")
    return values


def _file_identity(values):
    identity = FileIdentity(**values)
    if (type(identity.device) is not int or identity.device < 0
            or type(identity.inode) is not int or identity.inode <= 0):
        raise ValueError
    return identity


def _validate_stored_credential(values, phase, nonce, credential):
    cold = phase in (Phase.COLD_PENDING, Phase.COLD_CHECKING)
    if (cold and not _hex(nonce, 32)) or (not cold and nonce is not None):
        raise ValueError
    has_cold_profile = cold or phase == Phase.COLD_RETIREMENT_OBSERVED
    digest = values["subject_digest"]
    observed = values["cold_subject_observed"]
    has_credential = phase == Phase.ENROLLMENT_RETIRED or has_cold_profile
    if ((credential is not None) != has_credential
            or (digest is not None and not _hex(digest, 64))
            or (digest is None and has_cold_profile)
            or (digest is not None and phase == Phase.PENDING)
            or type(observed) is not bool or (observed and phase != Phase.COLD_CHECKING)):
        raise ValueError
    return digest, observed


def _validate_stored_admission(values, phase):
    enroll_spent, cold_spent = values["enrollment_metadata_spent"], values["cold_metadata_spent"]
    pending = values["metadata_pending"]
    if (type(enroll_spent) is not int or not 0 <= enroll_spent <= len(_ENROLLMENT_ROUTES)
            or type(cold_spent) is not int or not 0 <= cold_spent <= len(_COLD_ROUTES)
            or (enroll_spent and phase == Phase.PENDING)
            or (cold_spent and phase not in (Phase.COLD_CHECKING, Phase.COLD_RETIREMENT_OBSERVED))
            or type(pending) is not bool
            or (pending and not ((phase == Phase.ENROLLING and enroll_spent)
                                 or (phase == Phase.COLD_CHECKING and cold_spent)))):
        raise ValueError
    return enroll_spent, cold_spent, pending


def _decode(raw):
    try:
        values = json.loads(raw, object_pairs_hook=_unique)
        if set(values) != set(_Record.__dataclass_fields__) or type(values["version"]) is not int or values["version"] != 1:
            raise ValueError
        stored = values["enrollment"]
        enrollment = Enrollment(**(stored | {
            "profile_identity": _file_identity(stored["profile_identity"]),
            "subject_key_identity": _file_identity(stored["subject_key_identity"]),
        }))
        phase = Phase(values["phase"])
        nonce = values["check_nonce"]
        credential = values["credential_identity"]
        if (not is_valid_instance_label(enrollment.label) or not _hex(enrollment.build_digest, 64)
                or not all(_hex(field, 32) for field in (enrollment.registration_id, enrollment.generation, enrollment.attempt))):
            raise ValueError
        digest, observed = _validate_stored_credential(values, phase, nonce, credential)
        enroll_spent, cold_spent, pending = _validate_stored_admission(values, phase)
        return _Record(1, enrollment, _file_identity(values["lock_identity"]), phase, nonce,
                       None if credential is None else _file_identity(credential), digest, observed,
                       enroll_spent, cold_spent, pending)
    except (KeyError, TypeError, ValueError, RecursionError):
        raise RegistrationUnavailable("invalid Google registration receipt") from None


def _private_file(info):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)


@dataclass(frozen=True)
class _Directory:
    path: Path
    fd: int
    parent: "_Directory | None" = None
    private: bool = False
    owned: bool = False

    def verify(self):
        if self.parent is None:
            return
        self.parent.verify()
        info = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
        if not os.path.samestat(info, os.fstat(self.fd)):
            raise RegistrationUnavailable("Google registration directory changed")
        _check_dir_stat(info, current=self.path, is_target=self.owned or self.private, uid=os.geteuid())
        if self.private and stat.S_IMODE(info.st_mode) != 0o700:
            raise RegistrationUnavailable("Google registration directory is not private")


def _child(pins, parent, name, *, create=False, private=False, owned=False, exclusive=False):
    created = False
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fd)
            created = True
        except FileExistsError:
            if exclusive:
                raise
    fd = os.open(name, _DIRECTORY, dir_fd=parent.fd)
    pins.callback(os.close, fd)
    path = parent.path / name
    info = os.fstat(fd)
    _check_dir_stat(info, current=path, is_target=owned or private, uid=os.geteuid())
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise RegistrationUnavailable("Google registration directory is not private")
    if created:
        os.fsync(parent.fd)
    return _Directory(path, fd, parent, private, owned), created


def _state_root(pins, create):
    if not os.geteuid() or os.getuid() != os.geteuid():
        raise RegistrationUnavailable("Google registration requires the workstation account")
    home = _account_home()
    anchor = home / ".local" / "state" / "oc-sandbox" / "google"
    sandbox = (home / "opencode-sandbox").resolve()
    fd = os.open("/", _DIRECTORY)
    pins.callback(os.close, fd)
    directory = _Directory(Path("/"), fd)
    for name in anchor.parts[1:]:
        component = directory.path / name
        if _inside_sandbox(component, sandbox, check_contains=component == anchor):
            raise RegistrationUnavailable("Google registration state overlaps the sandbox")
        directory, _ = _child(pins, directory, name, create=create and directory.path.is_relative_to(home),
                              private=component == anchor, owned=component == home)
    directory.verify()
    return directory


@dataclass(frozen=True)
class _Slot:
    root: _Directory
    directory: _Directory
    lock: int
    new: bool

    def verify(self):
        self.directory.verify()
        info = os.fstat(self.lock)
        entry = os.stat(_LOCK, dir_fd=self.directory.fd, follow_symlinks=False)
        if not _private_file(info) or not os.path.samestat(entry, info):
            raise RegistrationUnavailable("Google registration lock changed")

    def fetch(self):
        self.verify()
        fd = os.open(_RECORD, os.O_RDONLY | _FILE, dir_fd=self.directory.fd)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            entry = os.stat(_RECORD, dir_fd=self.directory.fd, follow_symlinks=False)
            if not _private_file(info) or not os.path.samestat(info, entry):
                raise RegistrationUnavailable("unsafe Google registration receipt")
            raw = stream.read(_LIMIT + 1)
        if len(raw) > _LIMIT:
            raise RegistrationUnavailable("oversized Google registration receipt")
        record = _decode(raw)
        if (record.enrollment.label != self.directory.path.name
                or record.lock_identity != FileIdentity.of(os.fstat(self.lock))):
            raise RegistrationUnavailable("Google registration identity changed")
        return record

    def latch(self):
        if os.pwrite(self.lock, b"!", 0) != 1:
            raise RegistrationUnavailable("Google registration writes are unavailable")
        os.fsync(self.lock)

    def clear_latch(self, recheck):
        try:
            os.ftruncate(self.lock, 0)
            os.fsync(self.lock)
            if recheck is not None:
                recheck()
        except (OSError, ProviderConfigError, RegistrationUnavailable):
            # Closing the acquisition lock must not expose a failed transition.
            try:
                self.latch()
            except (OSError, RegistrationUnavailable):
                # Park the exact lock inode so the expected name remains closed
                # independently of a failed attempt to restore its contents.
                self.verify()
                parked = ".registration-held-" + secrets.token_hex(16)
                os.rename(_LOCK, parked, src_dir_fd=self.directory.fd, dst_dir_fd=self.directory.fd)
                os.fsync(self.directory.fd)
            raise

    def store(self, value, *, recheck=None):
        self.verify()
        if recheck is not None:
            recheck()
        # Preserve a blocking indicator in the stable lock file if a write
        # reaches the directory but publication sync cannot be confirmed.
        self.latch()
        temporary = ".registration-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE, 0o600, dir_fd=self.directory.fd)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as out:
                os.fchmod(fd, 0o600)
                json.dump(asdict(value), out, sort_keys=True, separators=(",", ":"))
                out.write("\n")
                out.flush()
                os.fsync(out.fileno())
            self.verify()
            if recheck is not None:
                recheck()
            os.replace(temporary, _RECORD, src_dir_fd=self.directory.fd, dst_dir_fd=self.directory.fd)
            os.fsync(self.directory.fd)
            self.verify()
            if recheck is not None:
                recheck()
            self.clear_latch(recheck)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self.directory.fd)


def _acquire(fd, *, authorized=None):
    deadline = time.monotonic() + _LOCK_TIME
    while True:
        if authorized is not None and authorized() is not True:
            raise RegistrationUnavailable("Google registration owner is unavailable")
        if time.monotonic() >= deadline:
            raise RegistrationUnavailable("Google registration is busy")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as error:
            if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RegistrationUnavailable("Google registration is busy") from None
            time.sleep(min(.025, remaining))


def _profile(pins, slot, generation, *, create=False):
    profiles, _ = _child(pins, slot.root, "profiles", create=create, private=True)
    directory, _ = _child(pins, profiles, generation, create=create, private=True, exclusive=True)
    directory.verify()
    return directory


def _open_credential(pins, profile):
    profile.verify()
    native, _ = _child(pins, profile, "antigravity-acp", private=True)
    leaf = "acp_token.json"
    fd = os.open(leaf, os.O_RDONLY | _FILE, dir_fd=native.fd)
    pins.callback(os.close, fd)
    info = os.fstat(fd)
    entry = os.stat(leaf, dir_fd=native.fd, follow_symlinks=False)
    native.verify()
    if not _private_file(info) or not os.path.samestat(info, entry) or not 0 < info.st_size <= _CREDENTIAL_LIMIT:
        raise RegistrationUnavailable("unsafe Google profile credential file")
    return fd, info


def _credential(pins, profile):
    _, info = _open_credential(pins, profile)
    return FileIdentity.of(info)


def _key_name(generation):
    return f"subject-{generation}.key"


def _create_subject_key(slot, generation):
    name = _key_name(generation)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE
    slot.verify()
    with os.fdopen(os.open(name, flags, 0o600, dir_fd=slot.directory.fd), "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(secrets.token_bytes(32))
        stream.flush()
        os.fsync(stream.fileno())
        identity = FileIdentity.of(os.fstat(stream.fileno()))
        _verify_subject_key(slot, stream.fileno(), generation, identity)
    os.fsync(slot.directory.fd)
    return identity


def _verify_subject_key(slot, fd, generation, expected):
    slot.verify()
    info = os.fstat(fd)
    entry = os.stat(_key_name(generation), dir_fd=slot.directory.fd, follow_symlinks=False)
    if (not _private_file(info) or info.st_size != 32 or FileIdentity.of(info) != expected
            or not os.path.samestat(info, entry)):
        raise RegistrationUnavailable("the exact Google subject key changed")


def _open_subject_key(pins, slot, enrollment):
    fd = os.open(_key_name(enrollment.generation), os.O_RDONLY | _FILE, dir_fd=slot.directory.fd)
    pins.callback(os.close, fd)
    _verify_subject_key(slot, fd, enrollment.generation, enrollment.subject_key_identity)
    return fd


def _check_credential(pins, profile, record):
    if _credential(pins, profile) != record.credential_identity:
        raise RegistrationUnavailable("the exact Google credential file changed")


def _credential_bytes(profile, record):
    with ExitStack() as pins:
        fd, before = _open_credential(pins, profile)
        body = os.pread(fd, _CREDENTIAL_LIMIT + 1, 0)
        after = os.fstat(fd)
        if (FileIdentity.of(before) != record.credential_identity
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (len(body), after.st_mtime_ns, after.st_ctime_ns)):
            raise RegistrationUnavailable("the exact Google profile credential changed")
        _check_credential(pins, profile, record)
        return body


def _verify_binding(slot, record, profile, key_fd):
    profile.verify()
    enrollment = record.enrollment
    _verify_subject_key(slot, key_fd, enrollment.generation, enrollment.subject_key_identity)
    if record.credential_identity is not None:
        with ExitStack() as pins:
            _check_credential(pins, profile, record)


class _HeldProfile:
    """Serialize metadata spending and subject binding under the held registration lock."""

    def __init__(self, slot, record, profile, key_fd):
        self._slot = slot
        self._record = record
        self._profile = profile
        self._key_fd = key_fd
        self._lock = threading.RLock()
        self._active = True
        self._subject_available = True
        self._spending = False
        self._replica = None
        self._native = None
        self._invocation = None
        self._phase_scope = object()
        self._spawn_consumed = False
        self._cold_digest = (sha256(_credential_bytes(profile, record)).digest()
                             if record.phase is Phase.COLD_CHECKING else None)

    def close(self):
        with self._lock:
            self._active = False
            if self._replica is not None:
                try:
                    self.abandon_cold_replica(self._replica)
                finally:
                    self._replica.close()

    def _verify(self):
        _verify_binding(self._slot, self._record, self._profile, self._key_fd)
        if self._cold_digest is not None:
            self._verify_cold_bytes()

    def _verify_cold_bytes(self):
        body = _credential_bytes(self._profile, self._record)
        if self._cold_digest is None or not compare_digest(self._cold_digest, sha256(body).digest()):
            raise RegistrationUnavailable("the exact Google profile credential content changed")
        return body

    def verify_cold_source(self):
        with self._lock:
            if not self._active or self._cold_digest is None:
                raise RegistrationUnavailable("the exact Google cold credential is unavailable")
            try:
                self._check_current()
            except (OSError, ProviderConfigError):
                raise RegistrationUnavailable("Google cold credential verification is unavailable") from None

    def stage_cold_source(self, root: Path, unit: str, *, authorized):
        """Journal a disposable profile before writing bytes into its private root."""
        if (not callable(authorized) or type(unit) is not str
                or re.fullmatch(r"oc-google-acp-[a-f0-9]{24}\.service", unit) is None):
            raise RegistrationUnavailable("Invalid Google cold replica authority")
        with self._lock, ExitStack() as pins:
            self.verify_cold_source()
            self._check_authority(authorized)
            try:
                if (root.parent != _RUNTIME_PARENT / str(os.geteuid()) or not root.name.startswith("oc-g-")
                        or not _hex(root.name[5:], 24)):
                    raise RegistrationUnavailable("Unrecognized Google cold replica root")
                runtime_fd = os.open(root.parent, _DIRECTORY)
                pins.callback(os.close, runtime_fd)
                parent = os.fstat(runtime_fd)
                if (not os.path.samestat(parent, root.parent.lstat()) or parent.st_uid != os.geteuid()
                        or stat.S_IMODE(parent.st_mode) != 0o700):
                    raise RegistrationUnavailable("Google cold runtime parent is not private")
                root_fd = os.open(root.name, _DIRECTORY, dir_fd=runtime_fd)
                pins.callback(os.close, root_fd)
                info = os.fstat(root_fd)
                if (not os.path.samestat(info, root.lstat()) or info.st_uid != os.geteuid()
                        or stat.S_IMODE(info.st_mode) != 0o700
                        or not _absent("profile", directory=root_fd)):
                    raise RegistrationUnavailable("Google cold replica root is not private and fresh")
                enrolled = self._record.enrollment
                custody = {"registration": enrolled.registration_id, "generation": enrolled.generation,
                           "check": self._record.check_nonce, "root": str(root), "device": info.st_dev,
                           "inode": info.st_ino, "uid": info.st_uid, "unit": unit}
                _write_private(self._slot.directory.fd, _CUSTODY,
                               json.dumps(custody, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")
                self._check_current()
                self._check_authority(authorized)
                body = self._verify_cold_bytes()
                os.mkdir("profile", 0o700, dir_fd=root_fd)
                profile_fd = os.open("profile", _DIRECTORY, dir_fd=root_fd)
                pins.callback(os.close, profile_fd)
                os.mkdir("antigravity-acp", 0o700, dir_fd=profile_fd)
                native = os.open("antigravity-acp", _DIRECTORY, dir_fd=profile_fd)
                pins.callback(os.close, native)
                self._replica = ColdReplica(root, runtime_fd, root_fd, profile_fd, unit,
                                            self.reserve_cold_spawn, self.abandon_cold_replica)
                try:
                    _write_private(native, "settings.json", b'{"telemetry":{"enabled":false},"auth":{"type":"oauth-personal"}}')
                    _write_private(native, "acp_token.json", body)
                    self.verify_cold_source()
                    self._check_authority(authorized)
                    self._replica.mount_path()
                except BaseException:
                    self._replica.abandon_unlaunched()
                    raise
                return self._replica
            except OSError:
                raise RegistrationUnavailable("Google cold replica could not be staged") from None

    def _reserve_spawn(self, phase, authorized):
        self._check_authority(authorized)
        self._check_current()
        if self._spawn_consumed or self._record.phase is not phase:
            raise RegistrationUnavailable("Google native launch authority is spent or unavailable")
        self._spawn_consumed = True

    def reserve_enrollment_spawn(self, authorized):
        with self._lock, _metadata_storage_errors():
            self._reserve_spawn(Phase.ENROLLING, authorized)

    def reserve_cold_spawn(self, replica, authorized):
        with self._lock, _metadata_storage_errors():
            if self._replica is not replica:
                raise RegistrationUnavailable("Google cold launch does not own its replica")
            replica.mount_path()
            self.verify_cold_source()
            self._reserve_spawn(Phase.COLD_CHECKING, authorized)

    def abandon_cold_replica(self, replica):
        with self._lock, _metadata_storage_errors():
            if (replica is self._replica and not replica._cleanup_confirmed
                    and (not self._spawn_consumed or replica._confirmed_no_spawn())):
                replica._remove_files()

    def bind_native_invocation(self, service, *, authorized):
        from .native_service import NativeService

        if type(service) is not NativeService:
            raise RegistrationUnavailable("Google native service identity is invalid")
        with self._lock, _metadata_storage_errors():
            self._check_current()
            self._check_authority(authorized)
            if self._native is not None or not self._spawn_consumed:
                raise RegistrationUnavailable("Google native invocation is already bound or was not authorized")
            identity = service.attested
            if identity is None or service.invocation() != identity:
                raise RegistrationUnavailable("Google native invocation does not match the original attestation")
            if self._record.phase is Phase.COLD_CHECKING:
                custody = _custody_record(self._slot, self._record)
                if self._replica is None or custody["unit"] != identity.unit or self._replica.unit != identity.unit:
                    raise RegistrationUnavailable("Google cold replica belongs to another unit")
                self._replica.mount_path()
                _write_private(self._slot.directory.fd, _INVOCATION, json.dumps({
                    "unit": identity.unit, "invocation": identity.invocation_id,
                }, sort_keys=True).encode("ascii") + b"\n")
                self._replica._bind(service, identity)
            elif self._record.phase is not Phase.ENROLLING or service.enrollment_scope is not self._phase_scope:
                raise RegistrationUnavailable("Google native launch phase is unavailable")
            self._check_current()
            self._check_authority(authorized)
            self._native = service
            self._invocation = identity

    def _native_current(self):
        if self._native is None or self._native.invocation() != self._invocation:
            raise RegistrationUnavailable("Google native metadata invocation is unavailable")
        if self._record.phase is Phase.COLD_CHECKING:
            if self._replica is None:
                raise RegistrationUnavailable("Google cold metadata requires its exact staged replica")
            self._replica.mount_path()
            invocation = _custody_invocation(self._slot, _custody_record(self._slot, self._record))
            if invocation["invocation"] != self._invocation.invocation_id:
                raise RegistrationUnavailable("Google cold invocation receipt changed")

    def record_native_custody(self, event, receipt):
        """Keep process evidence in the registration slot beyond runtime deletion."""
        with self._lock, _metadata_storage_errors():
            self._verify()
            if event not in ("launch", "attested", "no-spawn", "retired"):
                raise RegistrationUnavailable("Google native custody event is invalid")
            if self._record.phase not in (Phase.ENROLLING, Phase.COLD_CHECKING):
                raise RegistrationUnavailable("Google native custody phase is unavailable")
            label = "enrollment" if self._record.phase is Phase.ENROLLING else "cold"
            enrollment = self._record.enrollment
            data = {**receipt, "label": enrollment.label, "registration": enrollment.registration_id,
                    "generation": enrollment.generation}
            _write_private(self._slot.directory.fd, f"{label}-native-{event}.json",
                           json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n")

    def verify_native_invocation(self, *, authorized):
        with self._lock, _metadata_storage_errors():
            self._check_authority(authorized)
            self._native_current()
            self._check_authority(authorized)

    def _phase_retirement(self, completion, service, acp, *, cold):
        from .enrollment_session import MetadataCompletion
        from .native_enrollment_acp import NativeEnrollmentAcp
        from .native_service import NativeService

        if (type(completion) is not MetadataCompletion or completion.scope is not self._phase_scope or completion.cold is not cold
                or type(service) is not NativeService or service is not self._native or service.retired != self._invocation
                or type(acp) is not NativeEnrollmentAcp or not acp.completed_for(service.process, cold=cold)):
            raise RegistrationUnavailable("Google exact phase retirement is incomplete")
        return service.retired

    def complete_enrollment(self, service, acp, *, completion, authorized):
        with self._lock, _metadata_storage_errors(), ExitStack() as pins:
            self._check_current()
            self._check_authority(authorized)
            self._phase_retirement(completion, service, acp, cold=False)
            if (self._record.phase is not Phase.ENROLLING or self._record.subject_digest is None
                    or self._record.enrollment_metadata_spent != len(_ENROLLMENT_ROUTES)):
                raise RegistrationUnavailable("Google enrollment is not active")
            retired = replace(self._record, phase=Phase.ENROLLMENT_RETIRED,
                              credential_identity=_credential(pins, self._profile))

            def recheck():
                _verify_binding(self._slot, retired, self._profile, self._key_fd)
                self._check_authority(authorized)

            self._slot.store(retired, recheck=recheck)
            self._record = retired
            return retired.status()

    def complete_cold_custody(self, observation, *, completion, service, acp, authorized):
        """Publish the exact observation only after the owner confirms retirement."""
        with self._lock, _metadata_storage_errors():
            self.verify_cold_source()
            self._check_authority(authorized)
            _require_cold_observation(self._record, observation)
            retired = self._phase_retirement(completion, service, acp, cold=True)
            custody = _custody_record(self._slot, self._record)
            invocation = _custody_invocation(self._slot, custody)
            if (retired.unit != invocation["unit"] or retired.invocation_id != invocation["invocation"]
                    or self._replica is None or str(self._replica.root) != custody["root"] or not self._replica.removed()
                    or self._record.cold_metadata_spent != len(_COLD_ROUTES)):
                raise RegistrationUnavailable("Google cold custody retirement is incomplete")
            observed = replace(self._record, phase=Phase.COLD_RETIREMENT_OBSERVED,
                               check_nonce=None, cold_subject_observed=False)
            self._save(observed, authorized=authorized)
            return observed.status()

    def _check_current(self, *, pending=False):
        self._verify()
        if (os.pread(self._slot.lock, 1, 0) or self._slot.fetch() != self._record
                or self._record.metadata_pending is not pending):
            raise RegistrationUnavailable("the exact Google metadata phase is unavailable")

    def _save(self, record, *, authorized=None):
        def recheck():
            self._verify()
            if authorized is not None:
                self._check_authority(authorized)

        self._slot.store(record, recheck=recheck)
        self._record = record

    def bind(self, bearer, body, *, authorized):
        with self._lock:
            if not self._active or not self._subject_available:
                raise RegistrationUnavailable("the exact Google subject binding is already spent")
            if self._spending:
                raise RegistrationUnavailable("Google metadata dispatch is in progress")
            self._subject_available = False
            try:
                self._check_current()
                self._check_authority(authorized)
                key = os.pread(self._key_fd, 33, 0)
                if self._record.phase == Phase.ENROLLING:
                    proof = bind_subject(key, bearer, body)
                    updated = replace(self._record, subject_digest=proof.digest.hex())
                else:
                    proof = rebind_subject(key, bearer, body, bytes.fromhex(self._record.subject_digest))
                    updated = replace(self._record, cold_subject_observed=True)
                self._save(updated, authorized=authorized)
                return proof
            except (OSError, ProviderConfigError):
                raise RegistrationUnavailable("Google subject binding storage is unavailable") from None

    def _check_authority(self, authorized):
        try:
            valid = self._active and authorized() is True
        except Exception:
            raise RegistrationUnavailable("Google metadata dispatch authority is unavailable") from None
        if not valid:
            raise RegistrationUnavailable("Google metadata dispatch authority is unavailable")

    def refresh(self, form):
        """Match refresh fields against the exact registered credential of a cold check."""
        with self._lock:
            if (not self._active or self._spending or self._record.phase is not Phase.COLD_CHECKING
                    or self._record.cold_metadata_spent):
                raise RegistrationUnavailable("the exact Google cold refresh is unavailable")
            try:
                self._check_current()
                self._native_current()
                body = self._verify_cold_bytes()
                result = validate_refresh_form(form, pinned_credential=body)
                self._check_current()
                self._native_current()
                return result
            except (OSError, ProviderConfigError):
                raise RegistrationUnavailable("Google cold refresh credential is unavailable") from None

    def spend(self, route: MetadataRoute, send: Callable[[], None], *, authorized: Callable[[], bool]) -> None:
        """Persist an ordered spend for the controller's write, with no reply settlement."""
        if type(route) is not MetadataRoute or not callable(send) or not callable(authorized):
            raise RegistrationUnavailable("invalid Google metadata dispatch")
        with self._lock:
            if not self._active or self._spending:
                raise RegistrationUnavailable("the exact Google metadata context is unavailable")
            self._spending = True
            try:
                self._check_current()
                if self._record.phase == Phase.ENROLLING:
                    routes, counter = _ENROLLMENT_ROUTES, "enrollment_metadata_spent"
                else:
                    routes, counter = _COLD_ROUTES, "cold_metadata_spent"
                index = getattr(self._record, counter)
                if index == len(routes) or route is not routes[index]:
                    raise RegistrationUnavailable("Google metadata route is unavailable in this phase")
                self._check_authority(authorized)
                self._native_current()
                self._save(replace(self._record, metadata_pending=True, **{counter: index + 1}), authorized=authorized)
                self._check_current(pending=True)
                self._check_authority(authorized)
                self._native_current()
                self._check_authority(authorized)
                try:
                    result = send()
                except Exception:
                    raise RegistrationUnavailable("Google metadata write is unsettled") from None
                if result is not None:
                    raise RegistrationUnavailable("Google metadata write is unsettled")
                self._check_current(pending=True)
                self._save(replace(self._record, metadata_pending=False), authorized=authorized)
            except (OSError, ProviderConfigError):
                raise RegistrationUnavailable("Google metadata enrollment storage is unavailable") from None
            finally:
                self._spending = False


def _pinned_profile(pins, slot, record, profile, key_fd):
    held = _HeldProfile(slot, record, profile, key_fd)
    pins.enter_context(_held_profile_lifetime(held))
    launch = held.reserve_enrollment_spawn if record.phase is Phase.ENROLLING else None
    return PinnedProfile(profile.path, profile.fd, launch, held.bind, held.spend, held.refresh,
                         held.verify_cold_source, held.stage_cold_source,
                         held.bind_native_invocation, held.verify_native_invocation, held.complete_cold_custody,
                         held.complete_enrollment, held._phase_scope, held.record_native_custody)


@contextmanager
def _held_profile_lifetime(held):
    try:
        yield
    except BaseException as primary:
        try:
            held.close()
        except BaseException as cleanup:
            primary.add_note("Google held profile cleanup remains unresolved")
            if primary.__cause__ is None:
                raise primary from cleanup
        raise
    else:
        held.close()


def _write_private(directory, name, payload):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE, 0o600, dir_fd=directory)
    with os.fdopen(fd, "wb") as output:
        os.fchmod(fd, 0o600)
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    os.fsync(directory)


def _read_private_record(directory, leaf):
    fd = os.open(leaf, os.O_RDONLY | _FILE, dir_fd=directory)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        data = source.read(_LIMIT + 1)
        entry = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
    if not _private_file(info) or not os.path.samestat(info, entry) or len(data) != info.st_size or len(data) > _LIMIT:
        raise RegistrationUnavailable("Google custody receipt is unavailable")
    try:
        record = json.loads(data.decode("ascii"), object_pairs_hook=_unique)
        if type(record) is dict:
            return record
    except (ValueError, RecursionError):
        pass
    raise RegistrationUnavailable("Google custody receipt is unavailable")


def _custody_record(slot, current):
    record = _read_private_record(slot.directory.fd, _CUSTODY)
    expected = current.enrollment
    expected_root = _RUNTIME_PARENT / str(os.geteuid()) / "oc-g-"
    if (set(record) != {"registration", "generation", "check", "root", "device", "inode", "uid", "unit"}
            or record["registration"] != expected.registration_id or record["generation"] != expected.generation
            or record["check"] != current.check_nonce or record["uid"] != os.geteuid()
            or type(record["root"]) is not str or re.fullmatch(re.escape(str(expected_root)) + r"[0-9a-f]{24}", record["root"]) is None
            or type(record["unit"]) is not str or re.fullmatch(r"oc-google-acp-[a-f0-9]{24}\.service", record["unit"]) is None
            or type(record["device"]) is not int or record["device"] < 0 or type(record["inode"]) is not int or record["inode"] <= 0):
        raise RegistrationUnavailable("Google custody receipt does not match the exact check")
    return record


def _custody_invocation(slot, custody):
    invocation = _read_private_record(slot.directory.fd, _INVOCATION)
    if (set(invocation) != {"unit", "invocation"} or invocation["unit"] != custody["unit"]
            or not _hex(invocation["invocation"], 32)):
        raise RegistrationUnavailable("Google cold invocation receipt is unavailable")
    return invocation


def _require_cold_observation(current, observation):
    if (type(observation) is not ColdObservation or observation.check != current.check()
            or observation.authenticated_metadata is not True or observation.native_retired is not True
            or type(observation.prompt_count) is not int or observation.prompt_count != 0
            or not current.cold_subject_observed):
        raise RegistrationUnavailable("Google cold observation is incomplete")


def _absent(path, *, directory=None):
    try:
        os.stat(path, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


class RegistrationJournal:
    """Serialize one enrollment against a canonical owner-only registration."""

    def __init__(self, label):
        if not is_valid_instance_label(label):
            raise RegistrationUnavailable("invalid Google registration label")
        self.label = label

    def _registration_root(self, pins, create):
        return _state_root(pins, create)

    @contextmanager
    def _locked(self, *, create=False, authorized=None):
        with ExitStack() as pins:
            try:
                root = self._registration_root(pins, create)
                registrations, _ = _child(pins, root, "registrations", create=create, private=True)
                directory, new = _child(pins, registrations, self.label, create=create, private=True)
            except FileNotFoundError:
                if create:
                    raise RegistrationUnavailable(_STORAGE_UNAVAILABLE) from None
                yield None
                return
            except (OSError, ProviderConfigError):
                raise RegistrationUnavailable(_STORAGE_UNAVAILABLE) from None

            try:
                flags = os.O_RDWR | _FILE | (os.O_CREAT | os.O_EXCL if new else 0)
                fd = os.open(_LOCK, flags, 0o600, dir_fd=directory.fd)
                pins.callback(os.close, fd)
                if new:
                    os.fchmod(fd, 0o600)
                    os.fsync(fd)
                    os.fsync(directory.fd)
                slot = _Slot(root, directory, fd, new)
                slot.verify()
                _acquire(fd, authorized=authorized)
                slot.verify()
                if os.pread(fd, 1, 0):
                    raise RegistrationUnavailable("Google registration requires inspection after an interrupted write")
                yield slot
            except (OSError, ProviderConfigError):
                raise RegistrationUnavailable(_STORAGE_UNAVAILABLE) from None

    def status(self):
        """Return redacted enrollment metadata, or None when the registration is absent."""
        with self._locked() as slot:
            if slot is None:
                return None
            record = slot.fetch()
            with ExitStack() as pins:
                profile = self._exact_profile(pins, slot, record)
                _open_subject_key(pins, slot, record.enrollment)
                if record.credential_identity is not None:
                    _check_credential(pins, profile, record)
            return record.status()

    def begin(self, build_digest):
        """Persist the exact pending generation before a profile can be opened for launch."""
        if not _hex(build_digest, 64):
            raise RegistrationUnavailable("invalid Google enrollment artifact binding")
        with self._locked(create=True) as slot, ExitStack() as pins:
            if not slot.new:
                raise RegistrationUnavailable("Google registration already exists or requires inspection")
            registration, generation, attempt = (secrets.token_hex(16) for _ in range(3))
            profile = _profile(pins, slot, generation, create=True)
            enrolled = Enrollment(self.label, registration, generation, attempt, build_digest,
                                  FileIdentity.of(os.fstat(profile.fd)), _create_subject_key(slot, generation))
            slot.store(_Record(1, enrolled, FileIdentity.of(os.fstat(slot.lock)), Phase.PENDING))
            return enrolled

    @contextmanager
    def _exact(self, enrollment, phase, *, authorized=None):
        if type(enrollment) is not Enrollment:
            raise RegistrationUnavailable("invalid Google enrollment")
        with self._locked(authorized=authorized) as slot, ExitStack() as pins:
            if slot is None:
                raise RegistrationUnavailable("Google registration is unavailable")
            record = slot.fetch()
            if record.enrollment != enrollment or record.phase != phase or record.metadata_pending:
                raise RegistrationUnavailable("the exact Google enrollment cannot advance")
            key_fd = _open_subject_key(pins, slot, enrollment)
            yield slot, record, self._exact_profile(pins, slot, record), pins, key_fd

    @staticmethod
    def _exact_profile(pins, slot, record):
        profile = _profile(pins, slot, record.enrollment.generation)
        if record.enrollment.profile_identity != FileIdentity.of(os.fstat(profile.fd)):
            raise RegistrationUnavailable("the exact Google profile changed")
        return profile

    @contextmanager
    def enrollment_profile(self, enrollment):
        """Consume the pending launch once and pin its empty generation directory."""
        with self._exact(enrollment, Phase.PENDING) as (slot, record, profile, pins, key_fd):
            if os.listdir(profile.fd):
                raise RegistrationUnavailable("the new Google profile is not empty")
            enrolling = replace(record, phase=Phase.ENROLLING)
            view = _pinned_profile(pins, slot, enrolling, profile, key_fd)
            slot.store(enrolling, recheck=lambda: _verify_binding(slot, enrolling, profile, key_fd))
            yield view

    def begin_cold_check(self, enrollment):
        """Record one pending, zero-prompt metadata check of the exact profile and file."""
        with self._exact(enrollment, Phase.ENROLLMENT_RETIRED) as (slot, record, profile, pins, key_fd):
            if record.subject_digest is None:
                raise RegistrationUnavailable("the exact Google enrollment has no subject binding")
            _check_credential(pins, profile, record)
            pending = replace(record, phase=Phase.COLD_PENDING, check_nonce=secrets.token_hex(16))
            slot.store(pending, recheck=lambda: _verify_binding(slot, pending, profile, key_fd))
            return pending.check()

    @contextmanager
    def cold_profile(self, check):
        """Consume the exact pending cold start and pin its verified profile."""
        if type(check) is not ColdCheck:
            raise RegistrationUnavailable("invalid Google cold check")
        with self._exact(check.enrollment, Phase.COLD_PENDING) as (slot, record, profile, pins, key_fd):
            if record.check() != check:
                raise RegistrationUnavailable("the exact Google cold check changed")
            _check_credential(pins, profile, record)
            checking = replace(record, phase=Phase.COLD_CHECKING)
            view = _pinned_profile(pins, slot, checking, profile, key_fd)
            slot.store(checking, recheck=lambda: _verify_binding(slot, checking, profile, key_fd))
            yield view
