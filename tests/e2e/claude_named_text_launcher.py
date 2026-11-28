"""Own one inert Claude wire fixture in an exclusive offline subprocess owner."""

from contextlib import ExitStack, contextmanager, suppress
import ctypes
from dataclasses import asdict, dataclass
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import stat
import subprocess
from threading import Lock
import time

from oc_openai.connection_state import decode_json
from tools.ci.supervisor import CheckError, Children, WAIT_FLAGS, supervise

from .claude_named_text_protocol import NativeText, TextWireError, native_packet, read_native_turn, verify_ready


_PYTHON = "/usr/bin/python3"
_SOURCE = Path(__file__).with_name("claude_named_text_child.py")
_SOURCE_DIGEST = "629a67ca5b0e6f2912eb0a4bdd2adf44c16df37253bd00280474e0c94f49914d"
_BOOTSTRAP = """import os, sys
source, executable, workspace = map(int, sys.argv[1:4])
os.close(executable)
os.close(workspace)
with os.fdopen(source, 'rb') as image:
    image.seek(0)
    code = compile(image.read(), '<sealed Claude fixture>', 'exec', dont_inherit=True)
sys.argv = sys.argv[4:]
exec(code, {'__name__': '__main__'})
"""
_SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
_MODEL = "claude-fixture"
_PROFILE = "named-fixture-profile"
_ACCOUNT = "named-fixture-account"
_FRAME_LIMIT = 8192
_STDOUT_LIMIT = 32 * 1024
_TURN_SECONDS = 2
_POLL_SECONDS = 0.02
_OWNER_SECONDS = 8
_OWNER_RESULT_LIMIT = 32 * 1024
_OWNER_UNVERIFIED = 79
_OWNER_DRAIN_SECONDS = 3.5
_RETIREMENT_NOTE = "Native descendant retirement could not be verified."
_OWNER_INTERRUPTS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
_QUARANTINE_LIMIT = 16
_WORKSPACE_GATE = Lock()
_QUARANTINE = []
_UNKNOWN_RETIREMENT = ".oc-unknown-retirement"

# A single libc write refuses EINTR or any short result without retrying.
_WRITE = ctypes.CDLL(None, use_errno=True).write
_WRITE.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t]
_WRITE.restype = ctypes.c_ssize_t


class FixtureLaunchError(RuntimeError):
    """Fixed diagnostics for the exclusive test owner."""


def _require(condition, reason):
    if not condition:
        raise FixtureLaunchError(reason)


def _check(supervisor, cancelled, deadline):
    supervisor.check_interrupted()
    _require(not cancelled.is_set(), "native_cancelled")
    remaining = deadline - time.monotonic()
    _require(remaining > 0, "native_deadline")
    return min(remaining, _POLL_SECONDS)


@contextmanager
def _closing_preserving_error(resource):
    try:
        yield resource
    except BaseException as error:
        try:
            resource.close()
        except BaseException as close_error:
            raise error from close_error
        raise
    else:
        resource.close()


def _pin_source(resources, source, digest):
    source_fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with _closing_preserving_error(os.fdopen(source_fd, "rb")) as stream:
        _require(stat.S_ISREG(os.fstat(source_fd).st_mode), "native_source_unverified")
        data = stream.read(65537)
        _require(0 < len(data) <= 65536 and sha256(data).hexdigest() == digest, "native_source_unverified")
    descriptor = os.memfd_create("claude-named-fixture", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    resources.callback(os.close, descriptor)
    _require(os.write(descriptor, data) == len(data), "native_source_unverified")
    fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, _SEALS)
    _require(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == _SEALS
             and os.pread(descriptor, len(data) + 1, 0) == data, "native_source_unverified")
    return descriptor


@dataclass(frozen=True)
class _WorkspaceBinding:
    path: Path
    fd: int


def _verify_workspace(workspace, fd):
    info = os.fstat(fd)
    with os.scandir(fd) as entries:
        _require(os.path.samestat(info, workspace.lstat()) and info.st_uid == os.geteuid()
                 and stat.S_IMODE(info.st_mode) == 0o700 and next(entries, None) is None,
                 "native_workspace_unverified")


def _pin_workspace(workspace):
    _require(workspace.is_absolute() and workspace.resolve(strict=True) == workspace, "native_workspace_unverified")
    _require(all(workspace != pinned.path for pinned in _QUARANTINE), "native_workspace_quarantined")
    fd = os.open(workspace, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        _require(all(not os.path.samestat(info, os.fstat(pinned.fd)) for pinned in _QUARANTINE),
                 "native_workspace_quarantined")
        _verify_workspace(workspace, fd)
        return _WorkspaceBinding(workspace, fd)
    except BaseException as error:
        try:
            os.close(fd)
        except BaseException as close_error:
            raise error from close_error
        raise


def _quarantine_workspace(workspace):
    # Preserve the exact directory descriptor and both pathname and inode blocks in this controller.
    _QUARANTINE.append(workspace)
    # A new controller also refuses the workspace if the marker is still present.
    with suppress(OSError):
        marker = os.open(
            _UNKNOWN_RETIREMENT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=workspace.fd,
        )
        os.close(marker)


def _pin_executable(resources):
    descriptor = os.open(_PYTHON, os.O_RDONLY | os.O_CLOEXEC)
    resources.callback(os.close, descriptor)
    info = os.fstat(descriptor)
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             "native_executable_unverified")
    return descriptor


def _exact_proc_record(path, expected):
    with path.open("rb") as stream:
        return stream.read(len(expected) + 1) == expected


def _pipe_access(path):
    with path.open("rb") as stream:
        fields = stream.read(4097).splitlines()
    flags = [line.removeprefix(b"flags:\t") for line in fields if line.startswith(b"flags:\t")]
    _require(len(flags) == 1 and 1 <= len(flags[0]) <= 16, "native_stdio_unverified")
    return int(flags[0], 8) & os.O_ACCMODE


def _verify_stdio(process, proc):
    endpoints = (
        (process.stdin, os.O_WRONLY, os.O_RDONLY),
        (process.stdout, os.O_RDONLY, os.O_WRONLY),
        (process.stderr, os.O_RDONLY, os.O_WRONLY),
    )
    try:
        for index, (stream, parent_access, child_access) in enumerate(endpoints):
            fd = stream.fileno()
            own = os.fstat(fd)
            remote = (proc / "fd" / str(index)).stat()
            _require(
                stat.S_ISFIFO(own.st_mode) and stat.S_ISFIFO(remote.st_mode) and os.path.samestat(own, remote)
                and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == parent_access
                and _pipe_access(proc / "fdinfo" / str(index)) == child_access,
                "native_stdio_unverified",
            )
    except (OSError, ValueError):
        raise FixtureLaunchError("native_stdio_unverified") from None


def _verify_started(process, pidfd, cmd, env, workspace_fd, python_fd, source_fd):
    proc = Path("/proc") / str(process.pid)
    argv = b"\0".join(map(os.fsencode, cmd)) + b"\0"
    environment = b"\0".join(os.fsencode(f"{key}={value}") for key, value in env.items()) + b"\0"
    workspace = Path(env["HOME"]).lstat()
    _require(os.waitid(os.P_PIDFD, pidfd, WAIT_FLAGS) is None
             and os.path.samestat((proc / "exe").stat(), os.fstat(python_fd))
             and os.path.samestat((proc / "cwd").stat(), os.fstat(workspace_fd))
             and os.path.samestat(workspace, os.fstat(workspace_fd))
             and workspace.st_uid == os.geteuid() and stat.S_IMODE(workspace.st_mode) == 0o700
             and _exact_proc_record(proc / "cmdline", argv)
             and _exact_proc_record(proc / "environ", environment)
             and fcntl.fcntl(source_fd, fcntl.F_GET_SEALS) == _SEALS,
             "native_child_unverified")
    _verify_stdio(process, proc)
    _require({entry.name for entry in (proc / "fd").iterdir()} == {"0", "1", "2"}, "native_stdio_unverified")


class _Output:
    def __init__(self, process, checkpoint):
        self.checkpoint = checkpoint
        self.stdout = process.stdout.fileno()
        self.stderr = process.stderr.fileno()
        self.open = {self.stdout, self.stderr}
        self.poll = select.poll()
        for descriptor in self.open:
            os.set_blocking(descriptor, False)
            self.poll.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
        self.remaining = _STDOUT_LIMIT
        self.buffer = bytearray()

    def _read(self):
        for descriptor, _events in self.poll.poll(max(1, int(self.checkpoint() * 1000))):
            self.checkpoint()
            size = min(8192, self.remaining + 1) if descriptor == self.stdout else 1
            try:
                data = os.read(descriptor, size)
            except BlockingIOError:
                continue
            if not data:
                self.open.remove(descriptor)
                self.poll.unregister(descriptor)
                continue
            _require(descriptor == self.stdout, "native_stderr")
            self.remaining -= len(data)
            _require(self.remaining >= 0, "native_output_limit")
            self.buffer.extend(data)

    def verify_quiet_snapshot(self):
        # This rejects output visible at the checkpoint. It cannot prevent a later write.
        _require(not self.buffer and self.open == {self.stdout, self.stderr} and not self.poll.poll(0),
                 "native_output_before_request")

    def frames(self):
        while True:
            self.checkpoint()
            boundary = self.buffer.find(b"\n") + 1
            if boundary:
                _require(boundary <= _FRAME_LIMIT, "native_frame_limit")
                frame = bytes(self.buffer[:boundary])
                del self.buffer[:boundary]
                yield frame
            elif not self.open:
                _require(not self.buffer, "native_partial_frame")
                return
            else:
                _require(len(self.buffer) < _FRAME_LIMIT, "native_frame_limit")
                self._read()


def _finish_child(process, pidfd, supervisor, checkpoint):
    while True:
        wait = checkpoint()
        event = os.waitid(os.P_PIDFD, pidfd, WAIT_FLAGS)
        if event is not None:
            code = process.wait(timeout=wait)
            _require(event.si_pid == process.pid and event.si_code == os.CLD_EXITED
                     and event.si_status == code == 0, "native_child_failed")
            break
        time.sleep(wait)
    _require(supervisor.reap(process, set()) is Children.DRAINED, "native_descendants_live")
    checkpoint()


def _close_pipes(process):
    for stream in (process.stdin, process.stdout, process.stderr):
        with suppress(OSError):
            stream.close()


def _send_once(process, packet, checkpoint):
    descriptor = process.stdin.fileno()
    os.set_blocking(descriptor, False)
    try:
        _require(signal.getsignal(signal.SIGPIPE) is signal.SIG_IGN, "native_sigpipe_unverified")
        checkpoint()
        _require(_WRITE(descriptor, packet, len(packet)) == len(packet), "native_write_uncertain")
    except BaseException as error:
        try:
            process.stdin.close()
        except BaseException as close_error:
            # The owner's record carries the checked send error, with the close report kept local.
            raise error from close_error
        raise
    else:
        process.stdin.close()


class _OwnerCancellation:
    def __init__(self, connection):
        self.connection = connection

    def is_set(self):
        try:
            return self.connection.recv(1, socket.MSG_DONTWAIT) == b""
        except BlockingIOError:
            return False


@dataclass
class _ExchangeDisposition:
    retirement_verified: bool = True
    primary_error: BaseException | None = None


def _owner_entry(connection, turn, text, workspace):
    # Dispose of the owner's inherited descriptors and never return to the caller, even on uncertainty.
    try:
        # Install interruption handlers before unblocking signals that the caller may have masked.
        signal.pthread_sigmask(signal.SIG_BLOCK, _OWNER_INTERRUPTS)
        keep = {0, 1, 2, connection.fileno(), workspace.fd}
        for name in os.listdir("/proc/self/fd"):
            fd = int(name)
            if fd not in keep:
                with suppress(OSError):
                    os.close(fd)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        disposition = _ExchangeDisposition()
        try:
            result = turn._owned_exchange(
                text, workspace=workspace, cancelled=_OwnerCancellation(connection), disposition=disposition,
            )
            _require(disposition.retirement_verified, "native_owner_retirement_unverified")
            record = {"result": asdict(result)}
        except BaseException as error:
            if disposition.primary_error is not None:
                error = disposition.primary_error
            known = isinstance(error, (FixtureLaunchError, TextWireError, CheckError))
            record = {
                "error": type(error).__name__ if known else "FixtureLaunchError",
                "message": str(error) if known else "native_owner_failed",
            }
        status = 0 if disposition.retirement_verified else _OWNER_UNVERIFIED
        connection.settimeout(_POLL_SECONDS * 10)
        connection.sendall(json.dumps(record, ensure_ascii=True).encode("ascii"))
    except BaseException:
        os._exit(1)
    os._exit(status)


def _decode_owner_record(payload, status):
    _require(status in (0, _OWNER_UNVERIFIED), "native_owner_failed")
    try:
        record = decode_json(payload.decode("ascii"))
    except (ValueError, RecursionError):
        raise FixtureLaunchError("native_owner_failed") from None
    _require(type(record) is dict, "native_owner_failed")
    if record.keys() == {"error", "message"}:
        _require(type(record["error"]) is str and record["error"] in (
            "CheckError", "FixtureLaunchError", "TextWireError",
        ) and type(record["message"]) is str and 0 < len(record["message"]) <= 256, "native_owner_failed")
        return record
    _require(status == 0 and record.keys() == {"result"}, "native_owner_failed")
    result = record["result"]
    _require(type(result) is dict and result.keys() == {"text", "input_tokens", "output_tokens", "terminal_digest"},
             "native_owner_failed")
    text = result["text"]
    digest = result["terminal_digest"]
    try:
        _require(type(text) is str and 0 < len(text.encode("utf-8")) <= 4096 and "\0" not in text,
                 "native_owner_failed")
    except UnicodeError:
        raise FixtureLaunchError("native_owner_failed") from None
    _require(type(result["input_tokens"]) is int and 1 <= result["input_tokens"] <= 512
             and type(result["output_tokens"]) is int and 1 <= result["output_tokens"] <= 1024
             and type(digest) is str and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest),
             "native_owner_failed")
    return record


def _read_owner(connection, pidfd, pid, cancelled):
    deadline = time.monotonic() + _OWNER_SECONDS
    payload = bytearray()
    poll = select.poll()
    poll.register(connection, select.POLLIN | select.POLLHUP | select.POLLERR)
    sent_cancel = False
    while True:
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "native_owner_deadline")
        if not sent_cancel and cancelled.is_set():
            connection.shutdown(socket.SHUT_WR)
            sent_cancel = True
        if not poll.poll(max(1, int(min(remaining, _POLL_SECONDS) * 1000))):
            continue
        data = connection.recv(min(8192, _OWNER_RESULT_LIMIT + 1 - len(payload)))
        if not data:
            break
        payload.extend(data)
        _require(len(payload) <= _OWNER_RESULT_LIMIT, "native_owner_result_limit")

    while True:
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "native_owner_deadline")
        event = os.waitid(os.P_PIDFD, pidfd, WAIT_FLAGS)
        if event is not None:
            _require(event.si_pid == pid and event.si_code == os.CLD_EXITED
                     and event.si_status in (0, _OWNER_UNVERIFIED), "native_owner_failed")
            return _decode_owner_record(payload, event.si_status), event.si_status
        time.sleep(min(remaining, _POLL_SECONDS))


def _reap_owner(pid, pidfd, *, grace):
    # Without a pidfd, waitid still proves this is our unreaped direct child before signaling.
    kind, ident = (os.P_PIDFD, pidfd) if pidfd is not None else (os.P_PID, pid)
    deadline = time.monotonic() + grace
    while os.waitid(kind, ident, WAIT_FLAGS) is None:
        if time.monotonic() >= deadline:
            with suppress(ProcessLookupError):
                if pidfd is None:
                    os.kill(pid, signal.SIGKILL)
                else:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            kill_deadline = time.monotonic() + 1
            while os.waitid(kind, ident, WAIT_FLAGS) is None:
                _require(time.monotonic() < kill_deadline, "native_owner_retirement_unverified")
                time.sleep(_POLL_SECONDS)
            break
        time.sleep(_POLL_SECONDS)
    _require(os.waitpid(pid, os.WNOHANG)[0] == pid, "native_owner_retirement_unverified")


def _run_owner_process(turn, text, workspace, cancelled):
    control, owner = socket.socketpair()
    resources = ExitStack()
    release_error = None
    try:
        resources.enter_context(control)
        resources.enter_context(owner)
        pid = os.fork()
        if pid == 0:
            try:
                control.close()
                _owner_entry(owner, turn, text, workspace)
            finally:
                os._exit(1)
        pidfd = None
        try:
            owner.close()
            pidfd = os.pidfd_open(pid)
            resources.callback(os.close, pidfd)
            record, status = _read_owner(control, pidfd, pid, cancelled)
            _reap_owner(pid, pidfd, grace=0)
        except BaseException as error:
            # Release the owner lifetime so it can drain its private descendants.
            with suppress(OSError):
                control.shutdown(socket.SHUT_WR)
            try:
                _reap_owner(pid, pidfd, grace=_OWNER_DRAIN_SECONDS)
            finally:
                error.add_note(_RETIREMENT_NOTE)
                raise error from None
    finally:
        try:
            resources.close()
        except BaseException as error:
            # A close can fail after consuming the descriptor. Keep the checked
            # owner outcome and any primary error without retrying descriptor release.
            release_error = error
    return record, status, release_error


def _disposable_owner(turn, text, workspace_path, cancelled):
    _require(len(os.listdir("/proc/self/task")) == 1 and signal.getsignal(signal.SIGCHLD) is signal.SIG_DFL,
             "exclusive fixture ownership unavailable")
    _require(_WORKSPACE_GATE.acquire(blocking=False), "exclusive fixture ownership unavailable")
    workspace_release_error = None
    try:
        _require(len(_QUARANTINE) < _QUARANTINE_LIMIT, "native_workspace_quarantine_full")
        workspace = _pin_workspace(workspace_path)
        quarantine = True
        try:
            record, status, release_error = _run_owner_process(turn, text, workspace, cancelled)
            quarantine = status == _OWNER_UNVERIFIED
        finally:
            if quarantine:
                _quarantine_workspace(workspace)
            else:
                try:
                    os.close(workspace.fd)
                except BaseException as error:
                    workspace_release_error = error
    finally:
        _WORKSPACE_GATE.release()

    if "result" in record:
        _require(status == 0 and record.keys() == {"result"}, "native_owner_failed")
        if release_error is not None:
            if workspace_release_error is not None:
                raise release_error from workspace_release_error
            raise release_error
        if workspace_release_error is not None:
            raise workspace_release_error
        _require(not cancelled.is_set(), "native_cancelled")
        return NativeText(**record["result"])
    error_type = {"CheckError": CheckError, "FixtureLaunchError": FixtureLaunchError, "TextWireError": TextWireError}
    kind = error_type[record["error"]]
    error = TextWireError() if kind is TextWireError else kind(record["message"])
    if status == _OWNER_UNVERIFIED:
        error.add_note(_RETIREMENT_NOTE)
    if workspace_release_error is not None:
        raise error from workspace_release_error
    raise error


class FixtureTurn:
    """A one-use, host-created fixture turn. The production resolver never imports it."""

    def __init__(self, workspace, *, _source=_SOURCE, _source_digest=_SOURCE_DIGEST):
        self.workspace = Path(workspace)
        self.source = _source
        self.digest = _source_digest
        self._lock = Lock()
        self._spent = False

    def run(self, text, *, cancelled):
        with self._lock:
            _require(not self._spent, "native_turn_spent")
            self._spent = True
            # Capture the caller's selected path before invoking the cancellation observer.
            workspace_path = Path(self.workspace)
        _require(not cancelled.is_set(), "native_cancelled")
        return _disposable_owner(self, text, workspace_path, cancelled)

    def _owned_exchange(self, text, *, workspace, cancelled, disposition):
        deadline = time.monotonic() + _TURN_SECONDS
        with supervise() as supervisor, _closing_preserving_error(ExitStack()) as resources:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, _OWNER_INTERRUPTS)

            def checkpoint():
                return _check(supervisor, cancelled, deadline)

            checkpoint()
            source_fd = _pin_source(resources, self.source, self.digest)
            python_fd = _pin_executable(resources)
            session = secrets.token_hex(16)
            challenge = secrets.token_hex(16)
            command = (_PYTHON, "-ISB", "-c", _BOOTSTRAP, str(source_fd), str(python_fd), str(workspace.fd),
                       _SOURCE.name, session, _MODEL, _PROFILE, _ACCOUNT)
            environment = {"LC_ALL": "C", "HOME": str(workspace.path)}
            supervisor.drained = False
            disposition.retirement_verified = False
            process = None
            try:
                _verify_workspace(workspace.path, workspace.fd)
                checkpoint()
                process = subprocess.Popen(
                    command, executable=f"/proc/self/fd/{python_fd}", cwd=f"/proc/self/fd/{workspace.fd}",
                    env=environment, pass_fds=(source_fd, python_fd, workspace.fd), start_new_session=True,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                )
                pidfd = os.pidfd_open(process.pid)
                resources.callback(os.close, pidfd)
                output = _Output(process, checkpoint)
                frames = output.frames()
                ready = next(frames, None)
                _require(ready is not None, "native_ready_missing")
                verify_ready(ready, session=session, model=_MODEL, profile=_PROFILE, account=_ACCOUNT)
                pipe_buf = os.fpathconf(process.stdin.fileno(), "PC_PIPE_BUF")
                packet = native_packet(text, session=session, challenge=challenge, pipe_buf=pipe_buf)
                checkpoint()
                _verify_started(process, pidfd, command, environment, workspace.fd, python_fd, source_fd)
                output.verify_quiet_snapshot()
                _send_once(process, packet, checkpoint)
                result = read_native_turn(
                    frames, session=session, challenge=challenge, model=_MODEL, max_input=512, max_output=1024,
                )
                _finish_child(process, pidfd, supervisor, checkpoint)
                disposition.retirement_verified = True
                return result
            except BaseException as error:
                disposition.primary_error = error
                if process is not None:
                    _close_pipes(process)
                try:
                    if not supervisor.drained:
                        supervisor.drain(process)
                except BaseException:
                    # Keep retirement uncertain independently of the primary error.
                    pass
                else:
                    disposition.retirement_verified = supervisor.drained
                raise
            finally:
                if process is not None:
                    _close_pipes(process)
