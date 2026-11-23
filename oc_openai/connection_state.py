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


def _valid_record(value):
    if not isinstance(value, dict) or value.get("version") != 1:
        return False
    for key in ("generation", "profile", "host_id", "client", "pending_client", "subject"):
        if key in value and (not isinstance(value[key], str) or not value[key]):
            return False
    for key in ("retiring", "refresh_retry_after"):
        if key in value and not _timestamp(value[key]):
            return False
    pending = value.get("pending", {})
    if not isinstance(pending, dict) or ("pending" in value and not _timestamp(pending.get("expires"))):
        return False
    refresh = value.get("refresh_pending", {})
    if not isinstance(refresh, dict) or ("refresh_pending" in value and (
        not _timestamp(refresh.get("until")) or not isinstance(refresh.get("ticket"), str)
    )):
        return False
    if "worker_retiring" in value and value["worker_retiring"] is not True:
        return False
    if "worker_lease" in value and type(value["worker_lease"]) is not dict:
        return False
    if "tokens" in value:
        tokens = value["tokens"]
        if (not isinstance(tokens, dict) or not {"generation", "profile", "client"} <= value.keys()
                or not isinstance(tokens.get("access"), str) or not isinstance(tokens.get("refresh"), str)
                or not _timestamp(tokens.get("expiry"))
                or (tokens.get("earliest") is not None and not _timestamp(tokens["earliest"]))):
            return False
    return True


def _directory(path: Path, *, create=False):
    if not path.is_absolute() or ".." in path.parts or not path.name:
        raise ConnectionError("untrusted_connection_path")
    flags = os.O_RDONLY | os.O_DIRECTORY | CREATE_FLAGS
    uid = os.getuid()
    fd = os.open("/", flags)
    try:
        for index, part in enumerate(path.parts[1:], 1):
            private = index == len(path.parts) - 1
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=fd)
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
                    os.stat("state.json", dir_fd=directory, follow_symlinks=False)
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
            fd = os.open("state.json", os.O_RDONLY | os.O_NONBLOCK | CREATE_FLAGS,
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

    def write(self, directory, record):
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
            os.replace(temporary, "state.json", src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory)
