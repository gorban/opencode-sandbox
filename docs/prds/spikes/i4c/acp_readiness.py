"""Offline readiness proof for the bundled synthetic ACP peer."""

from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import secrets
import selectors
import stat
import subprocess
import sys
import time

from oc_providers import ReadinessState

from acp_fixture import ENROLLMENT_LOCK, PROFILE, VERIFIER, credential_digest, decode_json, is_identifier


MAX_FRAME = 256 * 1024
MAX_RECORD = 1024
JOURNAL = "readiness.json"
RECEIPT = "readiness-inflight.json"
FIXTURE = Path(__file__).resolve().with_name("acp_fixture.py")
STATES = frozenset({ReadinessState.READY, ReadinessState.DISCONNECTED, ReadinessState.NEEDS_VERIFY,
                    ReadinessState.REVOCATION_UNCONFIRMED})


class ProtocolError(RuntimeError):
    """The synthetic peer did not provide a valid readiness transcript."""


class IntegrityError(RuntimeError):
    """The synthetic profile journal could not be trusted or updated."""


@dataclass(frozen=True)
class Record:
    generation: str
    readiness: ReadinessState
    check: str | None = None


def _private_file(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise IntegrityError("unsafe private journal file")


@contextmanager
def _locked(root):
    try:
        directory = os.open(root, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise IntegrityError("unsafe private journal directory")
            fd = os.open("readiness.lock", os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CREAT | os.O_RDWR,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "rb") as lock:
                _private_file(lock.fileno())
                fcntl.flock(lock, fcntl.LOCK_EX)
                yield directory
        finally:
            os.close(directory)
    except OSError:
        raise IntegrityError("synthetic journal or scratch I/O failed") from None


def _read(directory, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        _private_file(fd)
        raw = stream.read(MAX_RECORD + 1)
    try:
        if len(raw) > MAX_RECORD:
            raise ValueError("oversized record")
        fields = decode_json(raw)
        if type(fields) is not dict or fields.keys() != {"generation", "readiness", "check"}:
            raise ValueError("wrong record fields")
        readiness = ReadinessState(fields["readiness"])
        check = fields["check"]
        inflight = name == RECEIPT
        if (not is_identifier(fields["generation"]) or readiness not in STATES
                or inflight != (readiness is ReadinessState.REVOCATION_UNCONFIRMED)
                or (inflight and not is_identifier(check)) or (not inflight and check is not None)):
            raise ValueError("invalid readiness record")
        return Record(fields["generation"], readiness, check)
    except (ValueError, TypeError, RecursionError):
        raise IntegrityError("corrupt synthetic readiness journal") from None


def _status(directory):
    current = _read(directory, JOURNAL)
    pending = _read(directory, RECEIPT)
    if pending is not None:
        if current is None or current.generation != pending.generation:
            raise IntegrityError("the synthetic readiness receipt does not match its journal")
        return pending
    return current


def _store_json(directory, target, fields, *, durable_rename=True):
    name = "journal-" + secrets.token_hex(16)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            json.dump(fields, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, target, src_dir_fd=directory, dst_dir_fd=directory)
        if durable_rename:
            os.fsync(directory)
        else:
            # A lost synthetic profile after a crash is treated as signed-out.
            with suppress(OSError):
                os.fsync(directory)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(name, dir_fd=directory)


def _store(directory, target, record):
    _store_json(directory, target, {"generation": record.generation, "readiness": record.readiness.value,
                                    "check": record.check})


@contextmanager
def _enrollment_handle(directory, *, create=False):
    flags = os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= (os.O_CREAT | os.O_EXCL | os.O_RDWR) if create else os.O_RDONLY
    fd = os.open(ENROLLMENT_LOCK, flags, 0o600, dir_fd=directory)
    try:
        _private_file(fd)
        operation = fcntl.LOCK_EX if create else fcntl.LOCK_SH
        try:
            fcntl.flock(fd, operation | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
        else:
            yield True
    finally:
        os.close(fd)


@contextmanager
def enrollment_fixture(root, *, expires_at=None):
    """Model an enrollment capability with an exclusive, process-local handle."""
    if expires_at is not None and (type(expires_at) is not int or expires_at < 0):
        raise IntegrityError("invalid synthetic enrollment expiration")
    with ExitStack() as enrollment:
        with _locked(root) as directory:
            if _status(directory) is not None:
                raise IntegrityError("synthetic profile already has a journal")
            if not enrollment.enter_context(_enrollment_handle(directory, create=True)):
                raise IntegrityError("could not acquire synthetic enrollment authority")
            generation = secrets.token_hex(16)
            expected = Record(generation, ReadinessState.NEEDS_VERIFY)
            _store(directory, JOURNAL, expected)
        yield generation
        with _locked(root) as directory:
            if _status(directory) != expected:
                raise IntegrityError("the exact synthetic enrollment changed")
            credential = secrets.token_hex(16)
            digest = credential_digest(generation, credential, expires_at)
            # Persist the independent verifier before publishing the peer's profile.
            _store_json(directory, VERIFIER, {"generation": generation, "digest": digest})
            _store_json(directory, PROFILE, {"generation": generation, "credential": credential,
                                             "expires_at": expires_at}, durable_rename=False)


def enroll_fixture(root, *, expires_at=None):
    """Complete a synthetic enrollment and close its handle."""
    with enrollment_fixture(root, expires_at=expires_at) as generation:
        return generation


def read_status(root):
    with _locked(root) as directory:
        return _status(directory)


class _Channel:
    def __init__(self, process, io, deadline):
        self.process = process
        self.io = io
        self.deadline = deadline
        self.buffer = bytearray()
        io.register(process.stdout, selectors.EVENT_READ)
        os.set_blocking(process.stdin.fileno(), False)

    def _read(self):
        remaining = self.deadline - time.monotonic()
        try:
            if remaining <= 0 or not self.io.select(remaining):
                raise ProtocolError("synthetic ACP deadline expired")
            return os.read(self.process.stdout.fileno(), 8192)
        except OSError:
            raise ProtocolError("synthetic ACP response could not be read") from None

    def exchange(self, request_id, method, params):
        request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        wire = json.dumps(request).encode("ascii") + b"\n"
        try:
            if len(wire) > 4096 or os.write(self.process.stdin.fileno(), wire) != len(wire):
                raise ProtocolError("synthetic ACP request exceeded its write bound")
        except OSError:
            raise ProtocolError("synthetic ACP request could not be written") from None
        while b"\n" not in self.buffer:
            chunk = self._read()
            if not chunk or len(self.buffer) + len(chunk) > MAX_FRAME:
                raise ProtocolError("synthetic ACP response was truncated or exceeded its bound")
            self.buffer.extend(chunk)
        line, _, remainder = self.buffer.partition(b"\n")
        if remainder:
            raise ProtocolError("unexpected extra synthetic ACP output")
        self.buffer.clear()
        try:
            reply = decode_json(line)
        except (ValueError, RecursionError):
            raise ProtocolError("malformed synthetic ACP frame") from None
        if (type(reply) is not dict or reply.get("jsonrpc") != "2.0" or type(reply.get("id")) is not int
                or reply["id"] != request_id or reply.keys() not in ({"jsonrpc", "id", "result"},
                                                                      {"jsonrpc", "id", "error"})):
            raise ProtocolError("unexpected synthetic ACP envelope")
        return reply

    def finish(self):
        self.process.stdin.close()
        if self._read():
            raise ProtocolError("unexpected trailing synthetic ACP output")
        try:
            if self.process.wait(timeout=max(self.deadline - time.monotonic(), 0)):
                raise ProtocolError("synthetic ACP peer did not finish cleanly")
        except subprocess.TimeoutExpired:
            raise ProtocolError("synthetic ACP peer did not exit by its deadline") from None


def _classify(reply):
    result = reply.get("result")
    session_id = result.get("sessionId") if type(result) is dict else None
    if type(session_id) is str and session_id.strip():
        return ReadinessState.READY

    error = reply.get("error")
    if type(error) is not dict or type(error.get("code")) is not int:
        raise ProtocolError("unrecognized synthetic ACP session verdict")
    verdict = (error["code"], error.get("message"))
    if verdict == (-32000, "authentication required"):
        return ReadinessState.DISCONNECTED
    if verdict == (-32001, "synthetic credential expired"):
        return ReadinessState.NEEDS_VERIFY
    if verdict == (-32002, "synthetic profile integrity error"):
        raise IntegrityError("synthetic ACP peer rejected its private profile")
    raise ProtocolError("unrecognized synthetic ACP session verdict")


def _transcript(process, workspace, timeout):
    with selectors.DefaultSelector() as io:
        channel = _Channel(process, io, time.monotonic() + timeout)
        hello = channel.exchange(1, "initialize", {"protocolVersion": 1, "clientCapabilities": {}})
        version = hello["result"].get("protocolVersion") if type(hello.get("result")) is dict else None
        if type(version) is not int or version != 1:
            raise ProtocolError("unexpected synthetic ACP protocol version")
        reply = channel.exchange(2, "session/new", {"cwd": str(workspace), "mcpServers": []})
        channel.finish()
        return _classify(reply)


def _retire(process):
    try:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=1)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        process.stdin.close()
        process.stdout.close()


def _finish_check(directory, process, workspace, current, check, readiness):
    if not _retire(process):
        return ReadinessState.REVOCATION_UNCONFIRMED
    expected = Record(current.generation, ReadinessState.REVOCATION_UNCONFIRMED, check)
    if _read(directory, JOURNAL) != current or _read(directory, RECEIPT) != expected:
        raise IntegrityError("the exact synthetic readiness check changed")
    # Keep the receipt if final publication cannot be synced, even if the rename succeeded.
    _store(directory, JOURNAL, Record(current.generation, readiness))
    workspace.rmdir()
    os.unlink(RECEIPT, dir_fd=directory)
    # The journal is already durable. This sync only makes receipt eviction durable.
    # If a crash brings the receipt back, it blocks reuse until inspected.
    with suppress(OSError):
        os.fsync(directory)
    return readiness


def _run_fixture(directory, current, check, scene, timeout):
    workspace = Path(f"/proc/self/fd/{directory}") / check
    workspace.mkdir(mode=0o700)
    try:
        args = [sys.executable, "-IBS", str(FIXTURE), scene, str(workspace.resolve().parent), current.generation]
        process = subprocess.Popen(args, cwd=workspace,
                                   env={"HOME": "/nonexistent", "LANG": "C.UTF-8"}, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
    except OSError:
        # The process receipt is unavailable. Preserve the provisional record and scratch.
        return ReadinessState.REVOCATION_UNCONFIRMED
    try:
        # Pass the child's actual path, since /proc/self/fd is scoped to the parent.
        readiness = _transcript(process, workspace.resolve(strict=True), timeout)
    except BaseException:
        _finish_check(directory, process, workspace, current, check, ReadinessState.NEEDS_VERIFY)
        raise
    return _finish_check(directory, process, workspace, current, check, readiness)


def probe_fixture(root, generation, scene="ready", *, timeout=2):
    """Run only the bundled fake peer, with no native profile or enrollment transport."""
    with _locked(root) as directory:
        current = _status(directory)
        if current is None or current.generation != generation:
            raise IntegrityError("the exact synthetic generation changed")
        if current.readiness is ReadinessState.REVOCATION_UNCONFIRMED:
            return current.readiness
        with _enrollment_handle(directory) as closed:
            if not closed:
                return ReadinessState.NEEDS_VERIFY
            check = secrets.token_hex(16)
            _store(directory, RECEIPT, Record(generation, ReadinessState.REVOCATION_UNCONFIRMED, check))
            return _run_fixture(directory, current, check, scene, timeout)
