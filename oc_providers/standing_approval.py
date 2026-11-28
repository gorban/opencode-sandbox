"""Host-only compare-and-commit storage for attended named subscription approval."""

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from enum import Enum
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import NamedTuple

from .config import CONFIG_FILENAME, MAX_CONFIG_BYTES, _open_trusted_dir, hash_providers_config_bytes
from .contracts import MAX_PROVIDER_SLOTS, PROVIDERS, ProviderIntegrityError, is_valid_instance_label


_RECEIPT = "standing-approval.json"
_LOCK = "standing-approval.lock"
_LOCK_WAIT_SECONDS = 1.0
_MAX_RECEIPT_BYTES = 8 * 1024
_OPEN_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_DIGEST = re.compile(r"[a-f0-9]{64}")
_REVISION = re.compile(r"[a-f0-9]{32}")
_LINEAGE = re.compile(r"[a-zA-Z0-9_-]{16,128}")


class Foreground(Enum):
    LIVE = "live"
    CANCELLED = "cancelled"
    OWNER_LOST = "owner_lost"


class Publication(Enum):
    UNCHANGED = "unchanged"
    PUBLISHED = "published"
    UNCERTAIN = "uncertain"


class StandingApprovalError(ProviderIntegrityError):
    def __init__(self, code: str, publication: Publication = Publication.UNCHANGED):
        super().__init__(code)
        self.publication = publication


class _Identity(NamedTuple):
    device: int
    inode: int


class _FileVersion(NamedTuple):
    identity: _Identity
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _FileSnapshot:
    data: bytes = field(repr=False)
    version: _FileVersion

    @property
    def identity(self) -> _Identity:
        return self.version.identity


@dataclass(frozen=True)
class ApprovalAuthority:
    """Canonical delegation and placement digests with sorted (kind, label, opaque local ID) members."""

    delegation_digest: str
    placement_digest: str
    lineages: tuple[tuple[str, str, str], ...] = field(repr=False)

    def __post_init__(self) -> None:
        if not all(type(value) is str and _DIGEST.fullmatch(value)
                   for value in (self.delegation_digest, self.placement_digest)):
            raise StandingApprovalError("approval_invalid_authority")
        rows = self.lineages
        if type(rows) is not tuple or not 1 <= len(rows) <= MAX_PROVIDER_SLOTS:
            raise StandingApprovalError("approval_invalid_lineages")
        for row in rows:
            if (
                type(row) is not tuple or len(row) != 3
                or type(row[0]) is not str or row[0] not in PROVIDERS
                or not is_valid_instance_label(row[1])
                or type(row[2]) is not str or not _LINEAGE.fullmatch(row[2])
            ):
                raise StandingApprovalError("approval_invalid_lineages")
        members = tuple(row[:2] for row in rows)
        if members != tuple(sorted(set(members))):
            raise StandingApprovalError("approval_invalid_lineages")


@dataclass(frozen=True)
class ApprovalReceipt:
    revision: str
    config_digest: str
    authority: ApprovalAuthority

    def encode(self) -> bytes:
        return json.dumps({
            "version": 1,
            "revision": self.revision,
            "config_digest": self.config_digest,
            "delegation_digest": self.authority.delegation_digest,
            "placement_digest": self.authority.placement_digest,
            "lineages": self.authority.lineages,
        }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"

    @classmethod
    def decode(cls, raw: bytes) -> "ApprovalReceipt":
        try:
            record = json.loads(raw)
            receipt = cls(
                record["revision"],
                record["config_digest"],
                ApprovalAuthority(record["delegation_digest"], record["placement_digest"],
                                  tuple(tuple(row) for row in record["lineages"])),
            )
            if not _REVISION.fullmatch(receipt.revision) or not _DIGEST.fullmatch(receipt.config_digest):
                raise ValueError
            if raw != receipt.encode():
                raise ValueError
            return receipt
        except (KeyError, TypeError, ValueError, RecursionError, StandingApprovalError):
            raise StandingApprovalError("approval_corrupt_receipt") from None


@dataclass(frozen=True)
class ApprovalSnapshot:
    """Exact trusted config and prior receipt, including confirmed receipt absence."""

    _config: _FileSnapshot | None = field(repr=False)
    _receipt: _FileSnapshot | None = field(repr=False)
    _config_dir: _Identity
    _state_dir: _Identity
    _lock: _Identity
    receipt: ApprovalReceipt | None

    @property
    def config_bytes(self) -> bytes | None:
        return self._config.data if self._config is not None else None

    @property
    def config_digest(self) -> str | None:
        raw = self.config_bytes
        return hash_providers_config_bytes(raw) if raw is not None else None

    def covers(self, authority: ApprovalAuthority) -> bool:
        """Check whether a proposal is needed. Admission also verifies current durable state."""
        return (
            self.receipt is not None and self.receipt.config_digest == self.config_digest
            and self.receipt.authority == authority
        )


# The caller acquires existing registry fences in their established order. It computes
# fresh local authority from this config and prior receipt without network or prompting.
# Adapters surface registry integrity and availability errors as ProviderIntegrityError.
AuthorityFence = Callable[[ApprovalSnapshot], AbstractContextManager[ApprovalAuthority]]
Checkpoint = Callable[[], Foreground]


def _identity(info: os.stat_result) -> _Identity:
    return _Identity(info.st_dev, info.st_ino)


def _version(info: os.stat_result) -> _FileVersion:
    return _FileVersion(_identity(info), info.st_mtime_ns, info.st_ctime_ns)


def _regular(info: os.stat_result, *, private: bool) -> _FileVersion:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & (0o077 if private else 0o022)
    ):
        raise StandingApprovalError("approval_untrusted_file")
    return _version(info)


def _verify_name(directory: int, name: str, expected: _FileVersion | None, *, private: bool) -> None:
    try:
        actual = _regular(os.stat(name, dir_fd=directory, follow_symlinks=False), private=private)
    except FileNotFoundError:
        actual = None
    if actual != expected:
        raise StandingApprovalError("approval_snapshot_changed")


def _read(directory: int, name: str, limit: int, *, private: bool, sync: bool = False) -> _FileSnapshot | None:
    try:
        fd = os.open(name, os.O_RDONLY | _OPEN_FLAGS, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        version = _regular(os.fstat(fd), private=private)
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise StandingApprovalError("approval_file_too_large")
        if sync:
            os.fsync(fd)
        if _regular(os.fstat(fd), private=private) != version:
            raise StandingApprovalError("approval_snapshot_changed")
        _verify_name(directory, name, version, private=private)
    return _FileSnapshot(data, version)


def _checkpoint(checkpoint: Checkpoint) -> None:
    state = checkpoint()
    if state is Foreground.CANCELLED:
        raise StandingApprovalError("approval_cancelled")
    if state is not Foreground.LIVE:
        raise StandingApprovalError("approval_owner_lost")


def _compare(expected: ApprovalSnapshot, current: ApprovalSnapshot) -> None:
    if expected != current:
        raise StandingApprovalError("approval_snapshot_changed")


@contextmanager
def _prepare(directory: int, data: bytes) -> Iterator[tuple[str, _Identity]]:
    name = ".standing-" + secrets.token_hex(16) + ".tmp"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _OPEN_FLAGS, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
            yield name, _regular(os.fstat(fd), private=True).identity
    finally:
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass


class _HeldLock(NamedTuple):
    state_dir: int
    identity: _Identity


class StandingApprovalStore:
    """A single writer for standing receipts and managed provider config changes.

    Paths come from the trusted host caller. The owner-only state directory must
    already exist, and the lock is never rotated or removed by managed writers.
    Call outside any registry, connection, lease, or exposure fence. Keep prompts
    and provider discovery outside this store.
    """

    def __init__(self, *, config_dir: Path, state_dir: Path, sandbox_dir: Path):
        self._config_dir = Path(config_dir)
        self._state_dir = Path(state_dir)
        self._sandbox_dir = Path(sandbox_dir).resolve()

    @contextmanager
    def _directory(self, path: Path, *, private: bool) -> Iterator[int]:
        if not path.name:
            raise StandingApprovalError("approval_untrusted_directory")
        fd = _open_trusted_dir(path, sandbox=self._sandbox_dir)
        if fd is None:
            raise StandingApprovalError("approval_directory_missing")
        try:
            if private and stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
                raise StandingApprovalError("approval_untrusted_directory")
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def _locked(self) -> Iterator[_HeldLock]:
        with self._directory(self._state_dir, private=True) as directory:
            fd = self._open_lock(directory)
            try:
                identity = _regular(os.fstat(fd), private=True).identity
                deadline = time.monotonic() + _LOCK_WAIT_SECONDS
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise StandingApprovalError("approval_storage_busy") from None
                        time.sleep(min(0.025, remaining))
                held = _HeldLock(directory, identity)
                self._verify_lock(held)
                yield held
            finally:
                os.close(fd)

    @staticmethod
    def _open_lock(directory: int) -> int:
        flags = os.O_RDWR | _OPEN_FLAGS
        try:
            return os.open(_LOCK, flags, dir_fd=directory)
        except FileNotFoundError:
            try:
                os.stat(_RECEIPT, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                try:
                    return os.open(_LOCK, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
                except FileExistsError:
                    pass
            # A writer could have installed both names after our first open.
            try:
                return os.open(_LOCK, flags, dir_fd=directory)
            except FileNotFoundError:
                raise StandingApprovalError("approval_lock_missing") from None

    def _verify_lock(self, held: _HeldLock) -> None:
        with self._directory(self._state_dir, private=True) as directory:
            lock = os.stat(_LOCK, dir_fd=directory, follow_symlinks=False)
            if (_identity(os.fstat(directory)) != _identity(os.fstat(held.state_dir))
                    or _regular(lock, private=True).identity != held.identity):
                raise StandingApprovalError("approval_lock_changed")

    def _snapshot(self, held: _HeldLock, *, sync: bool = False) -> ApprovalSnapshot:
        with self._directory(self._config_dir, private=False) as config_dir:
            return self._snapshot_at(held, config_dir, sync=sync)

    def _snapshot_at(self, held: _HeldLock, config_dir: int, *, sync: bool) -> ApprovalSnapshot:
        self._verify_lock(held)
        config = _read(config_dir, CONFIG_FILENAME, MAX_CONFIG_BYTES, private=False)
        raw = _read(held.state_dir, _RECEIPT, _MAX_RECEIPT_BYTES, private=True, sync=sync)
        receipt = ApprovalReceipt.decode(raw.data) if raw is not None else None
        if sync:
            os.fsync(held.state_dir)
        with self._directory(self._config_dir, private=False) as current_config_dir:
            config_identity = _identity(os.fstat(config_dir))
            if config_identity != _identity(os.fstat(current_config_dir)):
                raise StandingApprovalError("approval_snapshot_changed")
        self._verify_lock(held)
        _verify_name(config_dir, CONFIG_FILENAME, config.version if config else None, private=False)
        _verify_name(held.state_dir, _RECEIPT, raw.version if raw else None, private=True)
        return ApprovalSnapshot(config, raw, config_identity, _identity(os.fstat(held.state_dir)),
                                held.identity, receipt)

    def observe(self) -> ApprovalSnapshot:
        """Capture the trusted files for proposal preparation outside the lock."""
        try:
            with self._locked() as held:
                return self._snapshot(held)
        except OSError:
            raise StandingApprovalError("approval_storage_unavailable") from None
        except ProviderIntegrityError as error:
            raise StandingApprovalError(error.code) from None

    def commit(
        self, expected: ApprovalSnapshot, approved: ApprovalAuthority,
        *, authority_fence: AuthorityFence, checkpoint: Checkpoint,
    ) -> ApprovalSnapshot:
        """Publish a new attended decision and recheck it before launch admission."""
        publication = Publication.UNCHANGED
        try:
            with self._locked() as held:
                current = self._snapshot(held)
                _compare(expected, current)
                config_digest = current.config_digest
                if config_digest is None:
                    raise StandingApprovalError("approval_config_missing")
                with authority_fence(current) as verified:
                    if verified != approved:
                        raise StandingApprovalError("approval_authority_changed")
                    receipt = ApprovalReceipt(secrets.token_hex(16), config_digest, approved)
                    with _prepare(held.state_dir, receipt.encode()) as (temporary, identity):
                        _compare(expected, self._snapshot(held))
                        _checkpoint(checkpoint)
                        _compare(expected, self._snapshot(held))
                        publication = Publication.UNCERTAIN
                        os.replace(temporary, _RECEIPT, src_dir_fd=held.state_dir, dst_dir_fd=held.state_dir)
                        os.fsync(held.state_dir)
                        publication = Publication.PUBLISHED
                        installed = self._snapshot(held)
                        if (installed.receipt != receipt or installed._receipt is None
                                or installed._receipt.identity != identity):
                            raise StandingApprovalError("approval_snapshot_changed")
                        expected_install = ApprovalSnapshot(
                            _config=expected._config,
                            _receipt=installed._receipt,
                            _config_dir=expected._config_dir,
                            _state_dir=expected._state_dir,
                            _lock=expected._lock,
                            receipt=receipt,
                        )
                        _compare(expected_install, installed)
                        _checkpoint(checkpoint)
                        _compare(installed, self._snapshot(held))
                        return installed
        except OSError:
            raise StandingApprovalError("approval_storage_unavailable", publication) from None
        except ProviderIntegrityError as error:
            raise StandingApprovalError(error.code, publication) from None

    def verify_admission(
        self, expected: ApprovalSnapshot, approved: ApprovalAuthority,
        *, authority_fence: AuthorityFence, checkpoint: Checkpoint,
    ) -> ApprovalSnapshot:
        """Durably re-read an exact existing decision under current registry fences."""
        try:
            with self._locked() as held:
                current = self._snapshot(held)
                _compare(expected, current)
                with authority_fence(current) as verified:
                    if verified != approved or not current.covers(approved):
                        raise StandingApprovalError("approval_authority_changed")
                    _compare(expected, self._snapshot(held, sync=True))
                    _checkpoint(checkpoint)
                    _compare(expected, self._snapshot(held))
                    return current
        except OSError:
            raise StandingApprovalError("approval_storage_unavailable") from None
        except ProviderIntegrityError as error:
            raise StandingApprovalError(error.code) from None

    def replace_config(
        self, expected: ApprovalSnapshot, data: bytes, *, checkpoint: Checkpoint,
    ) -> ApprovalSnapshot:
        """Publish already validated, owner-approved config using the same writer lock.

        The receipt left by this operation still covers only its original bytes.
        Any new standing decision uses commit() with a fresh observation.
        """
        if type(data) is not bytes or len(data) > MAX_CONFIG_BYTES:
            raise StandingApprovalError("approval_invalid_config")
        publication = Publication.UNCHANGED
        try:
            with self._locked() as held, self._directory(self._config_dir, private=False) as directory:
                _compare(expected, self._snapshot_at(held, directory, sync=False))
                with _prepare(directory, data) as (temporary, identity):
                    _compare(expected, self._snapshot_at(held, directory, sync=False))
                    _checkpoint(checkpoint)
                    _compare(expected, self._snapshot_at(held, directory, sync=False))
                    publication = Publication.UNCERTAIN
                    os.replace(temporary, CONFIG_FILENAME, src_dir_fd=directory, dst_dir_fd=directory)
                    os.fsync(directory)
                    publication = Publication.PUBLISHED
                    installed = self._snapshot(held)
                    if (installed._config is None or installed.config_bytes != data
                            or installed._config.identity != identity):
                        raise StandingApprovalError("approval_snapshot_changed")
                    expected_install = ApprovalSnapshot(
                        _config=installed._config,
                        _receipt=expected._receipt,
                        _config_dir=expected._config_dir,
                        _state_dir=expected._state_dir,
                        _lock=expected._lock,
                        receipt=expected.receipt,
                    )
                    _compare(expected_install, installed)
                    _checkpoint(checkpoint)
                    _compare(installed, self._snapshot(held))
                    return installed
        except OSError:
            raise StandingApprovalError("approval_storage_unavailable", publication) from None
        except ProviderIntegrityError as error:
            raise StandingApprovalError(error.code, publication) from None
