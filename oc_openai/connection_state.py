"""Protected and atomic workstation connection storage."""

import contextlib
import fcntl
import hashlib
import html
import json
import math
import os
import re
import secrets
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


class ConnectionError(RuntimeError):
    """A stable diagnostic suitable for terminal output."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


CREATE_FLAGS = os.O_CLOEXEC | os.O_NOFOLLOW
MAX_STATE = 128 * 1024
MAX_WORKER_LEASES = 16
LOCK_SECONDS = 0.6


def unique_fields(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ValueError("duplicate JSON field")
    return value


def reject_constant(_):
    raise ValueError("invalid JSON number")


def decode_json(data):
    return json.loads(data, object_pairs_hook=unique_fields, parse_constant=reject_constant)


def _timestamp(value):
    return type(value) in (int, float) and 0 < value < math.inf


_STATE_FILE = "state.json"
_HOLD_PREFIX = ".lease-hold-"
_SETTLED_PREFIX = ".lease-settled-"
_HOLD_MAX_BYTES = 1024
_HOLD_JSON_KEYS = frozenset({"version", "state", "hold_id", "root", "incarnation"})
_HOLD_ID_RE = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)


@dataclass(frozen=True)
class LeaseHoldToken:
    """Unique per-retirement hold identity binding hold and settlement markers."""

    hold_id: str
    root: str
    incarnation: str


def _valid_scalar_fields(value):
    for key in ("generation", "profile", "host_id", "client", "pending_client", "subject"):
        if key in value and (not isinstance(value[key], str) or not value[key]):
            return False
    for key in ("retiring", "refresh_retry_after"):
        if key in value and not _timestamp(value[key]):
            return False
    for key in ("revocation_unconfirmed", "scope_missing", "registration_observed"):
        if key in value and type(value[key]) is not bool:
            return False
    return True


def _valid_transactions(value):
    pending = value.get("pending", {})
    if not isinstance(pending, dict) or ("pending" in value and not _timestamp(pending.get("expires"))):
        return False
    refresh = value.get("refresh_pending", {})
    if not isinstance(refresh, dict) or ("refresh_pending" in value and (
        not _timestamp(refresh.get("until")) or not isinstance(refresh.get("ticket"), str)
    )):
        return False
    for transaction in (pending, refresh):
        if "may_have_sent" in transaction and type(transaction["may_have_sent"]) is not bool:
            return False
    return "consumed" not in pending or type(pending["consumed"]) is bool


def _valid_leases_and_tokens(value):
    if "worker_retiring" in value and value["worker_retiring"] is not True:
        return False
    if "worker_lease" in value and type(value["worker_lease"]) is not dict:
        return False
    if "worker_leases" in value:
        leases = value["worker_leases"]
        if (type(leases) is not dict or len(leases) > MAX_WORKER_LEASES
                or any(type(key) is not str or not key or type(item) is not dict for key, item in leases.items())):
            return False
    if "tokens" not in value:
        return True
    tokens = value["tokens"]
    return (
        isinstance(tokens, dict) and {"generation", "profile", "client"} <= value.keys()
        and isinstance(tokens.get("access"), str) and isinstance(tokens.get("refresh"), str)
        and _timestamp(tokens.get("expiry"))
        and (tokens.get("earliest") is None or _timestamp(tokens["earliest"]))
    )


def _valid_record(value):
    if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
        return False
    return _valid_scalar_fields(value) and _valid_transactions(value) and _valid_leases_and_tokens(value)


def _open_dir_component(fd, part, flags, *, create):
    try:
        return os.open(part, flags, dir_fd=fd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(part, 0o700, dir_fd=fd)
        except FileExistsError:
            pass
        return os.open(part, flags, dir_fd=fd)


def _directory(path: Path, *, create=False):
    if not path.is_absolute() or ".." in path.parts or not path.name:
        raise ConnectionError("untrusted_connection_path")
    flags = os.O_RDONLY | os.O_DIRECTORY | CREATE_FLAGS
    uid = os.getuid()
    fd = os.open("/", flags)
    try:
        for index, part in enumerate(path.parts[1:], 1):
            private = index == len(path.parts) - 1
            child = _open_dir_component(fd, part, flags, create=create)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            expected_owners = {uid} if private else {0, uid}
            forbidden = 0o077 if private else 0o022
            if info.st_uid not in expected_owners or info.st_mode & forbidden:
                raise ConnectionError("untrusted_connection_path")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _regular(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_nlink != 1):
        raise ConnectionError("untrusted_connection_file")


def _lock(fd):
    deadline = time.monotonic() + LOCK_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise ConnectionError("connection_storage_busy") from None
            time.sleep(0.025)


def _valid_marker_stat(fd: int) -> bool:
    info = os.fstat(fd)
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 1
    )


def _read_bounded_fd(fd: int, limit: int) -> bytes:
    chunks = bytearray()
    while len(chunks) <= limit:
        chunk = os.read(fd, (limit + 1) - len(chunks))
        if not chunk:
            break
        chunks.extend(chunk)
    return bytes(chunks)


def _write_all_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(fd, view[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _encode_marker_payload(state: str, token: LeaseHoldToken) -> bytes:
    payload = {
        "version": 1,
        "state": state,
        "hold_id": token.hold_id,
        "root": token.root,
        "incarnation": token.incarnation,
    }
    return (json.dumps(payload, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _parse_marker_payload(data: bytes, expected_state: str, expected_suffix: str) -> LeaseHoldToken | None:
    if len(data) > _HOLD_MAX_BYTES or not _HOLD_ID_RE.fullmatch(expected_suffix):
        return None
    try:
        obj = decode_json(data)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if type(obj) is not dict or set(obj) != _HOLD_JSON_KEYS:
        return None
    if type(obj["version"]) is not int or obj["version"] != 1 or obj["state"] != expected_state:
        return None
    hold_id, root, incarnation = obj["hold_id"], obj["root"], obj["incarnation"]
    if (
        type(hold_id) is not str or type(root) is not str or type(incarnation) is not str
        or not root or not incarnation or hold_id != expected_suffix
    ):
        return None
    return LeaseHoldToken(hold_id=hold_id, root=root, incarnation=incarnation)


def _assert_marker_absent(directory: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        raise ConnectionError("managed_retirement_incomplete") from None
    raise ConnectionError("managed_retirement_incomplete")


def _open_validated_marker(
    directory: int, name: str, expected_state: str, expected_suffix: str,
) -> tuple[int, LeaseHoldToken] | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | CREATE_FLAGS, dir_fd=directory)
    except OSError:
        return None
    try:
        if not _valid_marker_stat(fd):
            os.close(fd)
            return None
        data = _read_bounded_fd(fd, _HOLD_MAX_BYTES)
        token = _parse_marker_payload(data, expected_state, expected_suffix)
        if token is None:
            os.close(fd)
            return None
        return fd, token
    except OSError:
        os.close(fd)
        return None
    except BaseException:
        os.close(fd)
        raise


def _has_lockless_state_or_markers(directory: int) -> bool:
    try:
        os.stat(_STATE_FILE, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        pass
    except OSError:
        return True
    try:
        entries = os.listdir(directory)
    except OSError:
        return True
    return any(name.startswith((_HOLD_PREFIX, _SETTLED_PREFIX)) for name in entries)


def _write_hold_in_dir(directory: int, token: LeaseHoldToken, data: bytes) -> None:
    hold_name = f"{_HOLD_PREFIX}{token.hold_id}"
    settled_name = f"{_SETTLED_PREFIX}{token.hold_id}"
    _assert_marker_absent(directory, hold_name)
    _assert_marker_absent(directory, settled_name)
    try:
        fd = os.open(hold_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | CREATE_FLAGS, 0o600, dir_fd=directory)
    except FileExistsError:
        raise ConnectionError("managed_retirement_incomplete") from None
    try:
        _regular(fd)
        _write_all_fd(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory)


def _gc_settled_pair(directory: int, hold_id: str) -> None:
    hold_name = f"{_HOLD_PREFIX}{hold_id}"
    settled_name = f"{_SETTLED_PREFIX}{hold_id}"
    try:
        try:
            os.unlink(hold_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.fsync(directory)
    except OSError:
        return
    with contextlib.suppress(OSError):
        try:
            os.unlink(settled_name, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.fsync(directory)


def _publish_settled_temp(
    directory: int,
    settled_name: str,
    data: bytes,
    before_publish: Callable[[], bool] | None,
) -> bool:
    tmp_name = ".lease-settle-tmp-" + secrets.token_hex(16)
    fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | CREATE_FLAGS, 0o600, dir_fd=directory)
    tmp_unlinked = False
    try:
        try:
            _regular(fd)
            _write_all_fd(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        if before_publish is not None and before_publish() is not True:
            return False
        try:
            os.link(tmp_name, settled_name, src_dir_fd=directory, dst_dir_fd=directory)
        except FileExistsError:
            raise ConnectionError("managed_retirement_incomplete") from None
        os.unlink(tmp_name, dir_fd=directory)
        tmp_unlinked = True
        os.fsync(directory)
        return True
    finally:
        if not tmp_unlinked:
            with contextlib.suppress(FileNotFoundError, OSError):
                os.unlink(tmp_name, dir_fd=directory)


class Store:
    def __init__(self, path: Path):
        self.path = path

    @contextlib.contextmanager
    def browser_redirect(self, url):
        document = (
            '<!doctype html><meta charset="utf-8">'
            '<meta name="referrer" content="no-referrer">'
            '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'">'
            '<meta http-equiv="refresh" content="0;url=' + html.escape(url, quote=True) + '">'
            '<title>Continue with ChatGPT</title>'
        )
        name = ".browser-" + secrets.token_hex(16) + ".html"
        try:
            directory = _directory(self.path)
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | CREATE_FLAGS,
                             0o600, dir_fd=directory)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(document.encode("utf-8"))
                    yield (self.path / name).as_uri()
                finally:
                    os.unlink(name, dir_fd=directory)
            finally:
                os.close(directory)
        except OSError:
            raise ConnectionError("connection_storage_unavailable") from None

    @contextlib.contextmanager
    def locked(self, *, create=False, require_existing=False):
        try:
            directory = _directory(self.path, create=create)
        except FileNotFoundError:
            if create:
                raise ConnectionError("connection_storage_unavailable") from None
            if require_existing:
                raise ConnectionError("managed_retirement_incomplete") from None
            yield None
            return
        except OSError:
            raise ConnectionError("untrusted_connection_path") from None
        try:
            flags = os.O_RDWR | os.O_NONBLOCK | CREATE_FLAGS
            if create:
                flags |= os.O_CREAT
            try:
                mutex = os.open("state.lock", flags, 0o600, dir_fd=directory)
            except FileNotFoundError:
                # An absent lock is an empty state only if no snapshot or hold marker exists.
                if _has_lockless_state_or_markers(directory):
                    raise ConnectionError("untrusted_connection_file") from None
                if require_existing:
                    raise ConnectionError("managed_retirement_incomplete") from None
                yield None
                return
            try:
                _regular(mutex)
                _lock(mutex)
                yield directory
            finally:
                os.close(mutex)
        except OSError:
            raise ConnectionError("connection_storage_unavailable") from None
        finally:
            os.close(directory)

    def read(self, directory, *, require_existing=False):
        if directory is None:
            if require_existing:
                raise ConnectionError("managed_retirement_incomplete")
            return {}
        try:
            fd = os.open(_STATE_FILE, os.O_RDONLY | os.O_NONBLOCK | CREATE_FLAGS,
                         dir_fd=directory)
        except FileNotFoundError:
            if require_existing:
                raise ConnectionError("managed_retirement_incomplete") from None
            return {}
        with os.fdopen(fd, "rb") as stream:
            _regular(stream.fileno())
            try:
                data = stream.read(MAX_STATE + 1)
                if len(data) > MAX_STATE:
                    raise ValueError
                record = decode_json(data)
                if not _valid_record(record):
                    raise ValueError
                return record
            except (ValueError, RecursionError):
                raise ConnectionError("invalid_connection_state") from None

    def write(self, directory, record, *, before_commit=None):
        data = json.dumps({**record, "version": 1}, allow_nan=False).encode("utf-8")
        if len(data) > MAX_STATE:
            raise ConnectionError("invalid_connection_state")
        temporary = ".state-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | CREATE_FLAGS,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if before_commit is not None:
                with before_commit() as allowed:
                    if not allowed:
                        return False
                    os.replace(temporary, _STATE_FILE, src_dir_fd=directory, dst_dir_fd=directory)
            else:
                os.replace(temporary, _STATE_FILE, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
            return True
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)

    def write_lease_hold(
        self, root_name: str, incarnation: str, *, directory: int | None = None,
    ) -> LeaseHoldToken:
        """Persist a unique durable hold marker before any irreversible lease release."""
        if (
            type(root_name) is not str or not root_name
            or type(incarnation) is not str or not incarnation
        ):
            raise ConnectionError("managed_retirement_incomplete")
        hold_nonce = secrets.token_hex(16)
        hold_id = hashlib.sha256(
            f"{root_name}\0{incarnation}\0{hold_nonce}".encode("utf-8", errors="surrogateescape")
        ).hexdigest()[:32]
        token = LeaseHoldToken(hold_id=hold_id, root=root_name, incarnation=incarnation)
        data = _encode_marker_payload("hold", token)
        if len(data) > _HOLD_MAX_BYTES:
            raise ConnectionError("managed_retirement_incomplete")
        if directory is not None:
            _write_hold_in_dir(directory, token, data)
            return token
        opened = _directory(self.path, create=False)
        try:
            _write_hold_in_dir(opened, token, data)
            return token
        finally:
            os.close(opened)

    def settle_lease_hold(
        self,
        token: LeaseHoldToken,
        *,
        directory: int | None = None,
        before_publish: Callable[[], bool] | None = None,
    ) -> bool:
        """Publish an authoritative settlement receipt for one validated hold, then GC best-effort."""
        if directory is None:
            raise ConnectionError("connection_storage_unavailable")
        if not isinstance(token, LeaseHoldToken) or not _HOLD_ID_RE.fullmatch(token.hold_id):
            raise ConnectionError("managed_retirement_incomplete")
        record = self.read(directory)
        single = record.get("worker_lease")
        leases = record.get("worker_leases") or {}
        if (isinstance(single, dict) and single.get("root") == token.root) or token.root in leases:
            raise ConnectionError("managed_retirement_incomplete")
        hold_name = f"{_HOLD_PREFIX}{token.hold_id}"
        settled_name = f"{_SETTLED_PREFIX}{token.hold_id}"
        opened = _open_validated_marker(directory, hold_name, "hold", token.hold_id)
        if opened is None:
            raise ConnectionError("managed_retirement_incomplete")
        hold_fd, disk_token = opened
        os.close(hold_fd)
        if disk_token != token:
            raise ConnectionError("managed_retirement_incomplete")
        _assert_marker_absent(directory, settled_name)
        data = _encode_marker_payload("settled", token)
        if len(data) > _HOLD_MAX_BYTES:
            raise ConnectionError("managed_retirement_incomplete")
        if not _publish_settled_temp(directory, settled_name, data, before_publish):
            return False
        _gc_settled_pair(directory, token.hold_id)
        return True

    def lease_hold_names(self, directory) -> frozenset[str] | None:
        if directory is None:
            return frozenset()
        try:
            entries = os.listdir(directory)
        except OSError:
            return None
        return frozenset(name for name in entries if name.startswith(_HOLD_PREFIX))

    def _reconcile_hold_entry(self, directory: int, name: str, active_roots: frozenset[str]) -> bool:
        suffix = name[len(_HOLD_PREFIX):]
        if not _HOLD_ID_RE.fullmatch(suffix):
            return False
        opened_hold = _open_validated_marker(directory, name, "hold", suffix)
        if opened_hold is None:
            return False
        hold_fd, hold_token = opened_hold
        os.close(hold_fd)
        if hold_token.root in active_roots:
            return False
        settled_name = f"{_SETTLED_PREFIX}{suffix}"
        opened_settled = _open_validated_marker(directory, settled_name, "settled", suffix)
        if opened_settled is None:
            return False
        settled_fd, settled_token = opened_settled
        try:
            if settled_token != hold_token:
                return False
            os.fsync(settled_fd)
            os.fsync(directory)
        except OSError:
            return False
        finally:
            os.close(settled_fd)
        _gc_settled_pair(directory, suffix)
        return True

    def has_lease_holds(self, directory, active_roots=()) -> bool:
        holds = self.lease_hold_names(directory)
        if holds is None:
            return True
        if not holds:
            return False
        active = frozenset(active_roots)
        for name in sorted(holds):
            if not self._reconcile_hold_entry(directory, name, active):
                return True
        return False
