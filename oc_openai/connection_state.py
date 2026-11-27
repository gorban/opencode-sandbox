"""Protected and atomic workstation connection storage."""

import contextlib
import fcntl
import html
import json
import math
import os
import secrets
import stat
import time
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
    def locked(self, *, create=False):
        try:
            directory = _directory(self.path, create=create)
        except FileNotFoundError:
            if create:
                raise ConnectionError("connection_storage_unavailable") from None
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
                # An absent lock is an empty state only if no snapshot exists.
                try:
                    os.stat(_STATE_FILE, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    yield None
                    return
                raise ConnectionError("untrusted_connection_file") from None
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

    def read(self, directory):
        if directory is None:
            return {}
        try:
            fd = os.open(_STATE_FILE, os.O_RDONLY | os.O_NONBLOCK | CREATE_FLAGS,
                         dir_fd=directory)
        except FileNotFoundError:
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

    def write_lease_hold(self, root_name: str) -> None:
        """Persist an independent durable hold marker without waiting on state.lock."""
        safe = "".join(ch for ch in root_name if ch.isalnum() or ch in ("-", "_", "."))[:96] or "unknown"
        name = f"{_HOLD_PREFIX}{safe}"
        directory = _directory(self.path, create=False)
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | CREATE_FLAGS, 0o600, dir_fd=directory)
            try:
                _regular(fd)
                os.write(fd, b"hold\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
        finally:
            os.close(directory)

    def has_lease_holds(self, directory) -> bool:
        if directory is None:
            return False
        try:
            entries = os.listdir(directory)
        except OSError:
            return True
        return any(name.startswith(_HOLD_PREFIX) for name in entries)
