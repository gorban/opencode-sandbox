"""Attest one fixed standalone ACP text turn before synthetic result transfer."""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
from io import FileIO
import math
import os
import select
import stat
from threading import RLock
import time

from .native_enrollment_acp import NativeAcpError, _SESSION_ID, _parse_frame, _usage_session
from .native_service import NativeInvocation


PROMPT_REQUEST_ID = 4
_TURN_SECONDS = 20
_FRAME_BYTES = 4096
_POLL_MS = 50
_RLOCK_TYPE = type(RLock())
_TERMINAL_USAGE_FIELDS = frozenset({
    "inputTokens", "outputTokens", "totalTokens", "thoughtTokens", "cachedReadTokens", "cachedWriteTokens",
})


class TranscriptUnavailable(RuntimeError):
    """The original standalone ACP turn cannot produce successful evidence."""


@dataclass(frozen=True, slots=True)
class NaturalExitReceipt:
    """Trusted observation of the retained unit before any forced stop."""

    invocation: NativeInvocation
    exec_main_code: int
    exec_main_status: int
    main_pid: int
    cgroup_vacant: bool


@dataclass(frozen=True, slots=True)
class UnitRetirementReceipt:
    """Trusted independent verification after retiring the exact unit."""

    invocation: NativeInvocation
    unit_retired: bool
    cgroup_vacant: bool


def _pipe(stream, access, *, nonblocking=False):
    if type(stream) is not FileIO:
        raise TranscriptUnavailable("Standalone Google ACP requires original unbuffered pipes")
    try:
        fd = stream.fileno()
    except ValueError:
        raise TranscriptUnavailable("Standalone Google ACP pipe is unavailable") from None
    return _pipe_fd(fd, access, nonblocking=nonblocking)


def _pipe_fd(fd, access, *, nonblocking=False):
    try:
        info = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError:
        raise TranscriptUnavailable("Standalone Google ACP pipe is unavailable") from None
    if (not stat.S_ISFIFO(info.st_mode) or flags & os.O_ACCMODE != access
            or (nonblocking and not flags & os.O_NONBLOCK)):
        raise TranscriptUnavailable("Standalone Google ACP pipe has unexpected direction or type")
    return fd, info.st_dev, info.st_ino


def _pin_stdout(stream, identity):
    fd = os.dup(identity[0])
    try:
        if _pipe_fd(fd, os.O_RDONLY)[1:] != identity[1:] or _pipe(stream, os.O_RDONLY) != identity:
            raise TranscriptUnavailable("Standalone Google ACP stdout changed during pinning")
        os.set_blocking(fd, False)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _poll(fd, flags):
    poll = select.poll()
    poll.register(fd, flags)
    return poll


def _pin_pidfd(fd, pid):
    if type(fd) is not int or fd < 0 or type(pid) is not int or pid <= 0:
        raise TranscriptUnavailable("Standalone Google ACP pidfd is unavailable")
    try:
        duplicate = os.dup(fd)
    except OSError:
        raise TranscriptUnavailable("Standalone Google ACP pidfd is unavailable") from None
    try:
        with open(f"/proc/self/fdinfo/{duplicate}", "rb") as info:
            data = info.read(8193)
        pids = [line.split() for line in data.splitlines() if line.startswith(b"Pid:")]
        if (len(data) > 8192 or pids != [[b"Pid:", str(pid).encode("ascii")]]
                or _poll(duplicate, select.POLLIN).poll(0)):
            raise TranscriptUnavailable("Standalone Google ACP pidfd does not pin the live invocation")
        return duplicate
    except OSError:
        os.close(duplicate)
        raise TranscriptUnavailable("Standalone Google ACP pidfd could not be verified") from None
    except BaseException:
        os.close(duplicate)
        raise


def _text(frame, session_id):
    if set(frame) != {"jsonrpc", "method", "params"} or frame["method"] != "session/update":
        raise TranscriptUnavailable("Unexpected standalone Google ACP request or notification")
    params = frame["params"]
    if type(params) is not dict or set(params) != {"sessionId", "update"} or params["sessionId"] != session_id:
        raise TranscriptUnavailable("Unexpected standalone Google ACP session")
    update = params["update"]
    if (type(update) is not dict or set(update) != {"sessionUpdate", "content"}
            or update["sessionUpdate"] != "agent_message_chunk"):
        raise TranscriptUnavailable("Unexpected standalone Google ACP update")
    content = update["content"]
    if (type(content) is not dict or set(content) != {"type", "text"} or content["type"] != "text"
            or type(content["text"]) is not str or not content["text"]):
        raise TranscriptUnavailable("Unexpected standalone Google ACP content")
    return content["text"]


def _valid_terminal_result(result):
    if type(result) is not dict or result.get("stopReason") != "end_turn":
        return False
    if result.keys() == {"stopReason"}:
        return True
    usage = result.get("usage")
    return (result.keys() == {"stopReason", "usage"} and type(usage) is dict
            and usage.keys() == _TERMINAL_USAGE_FIELDS
            and all(type(value) is int and 0 <= value <= 2**31 - 1 for value in usage.values()))


class GenerationTranscript:
    """Keep transcript, natural exit, and retirement evidence independent.

    The trusted supervisor pairs the original unbuffered Popen pipes with the
    pinned invocation. Stdin stays exclusive and is accessed under the shared
    fence once handed off after the durable prompt send. This helper reads its
    own duplicate of stdout. The supervisor observes and retires that precise
    unit independently and calls forced_stop before any fallback signal.
    """

    def __init__(self, stdin, stdout, *, invocation, pidfd, session_id, deadline, authorized, fence):
        now = time.monotonic()
        if (type(invocation) is not NativeInvocation or type(session_id) is not str
                or _SESSION_ID.fullmatch(session_id) is None or type(deadline) not in (float, int)
                or not now < deadline <= now + _TURN_SECONDS or not math.isfinite(deadline)
                or not callable(authorized) or type(fence) is not _RLOCK_TYPE):
            raise TranscriptUnavailable("Standalone Google ACP transcript scope is unavailable")
        self._stdin, self._stdout = stdin, stdout
        self._input = _pipe(stdin, os.O_WRONLY)
        self._output = _pipe(stdout, os.O_RDONLY)
        if self._input[1:] == self._output[1:]:
            raise TranscriptUnavailable("Standalone Google ACP pipes are not independent")
        self._invocation = invocation
        self._session_id = session_id
        self._deadline = deadline
        self._authorized = authorized
        self._fence = fence
        self._phase = "pending"
        self._invalid = False
        self._buffer = b""
        self._pidfd = self._stdout_fd = None
        try:
            self._stdout_fd = _pin_stdout(stdout, self._output)
            self._pidfd = _pin_pidfd(pidfd, invocation.pid)
        except OSError:
            self.close()
            raise TranscriptUnavailable("Standalone Google ACP stdout could not be bounded") from None
        except BaseException:
            self.close()
            raise

    def __copy__(self):
        raise TypeError("Standalone Google ACP transcript authority cannot be copied")

    def __deepcopy__(self, _memo):
        raise TypeError("Standalone Google ACP transcript authority cannot be copied")

    def __reduce__(self):
        raise TypeError("Standalone Google ACP transcript authority cannot be serialized")

    def __reduce_ex__(self, _protocol):
        return self.__reduce__()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        with self._fence:
            self._invalid = True
            pidfd, stdout_fd = self._pidfd, self._stdout_fd
            self._pidfd = self._stdout_fd = None
        try:
            if stdout_fd is not None:
                os.close(stdout_fd)
        finally:
            if pidfd is not None:
                os.close(pidfd)

    @contextmanager
    def _borrow(self, fd):
        # close() revokes immediately, but can only close the owner's pins.
        # An in-flight poll/read retains its own FD until it unwinds.
        with self._fence:
            self._check()
            try:
                borrowed = os.dup(fd)
            except OSError:
                raise TranscriptUnavailable("Standalone Google ACP owned descriptor is unavailable") from None
        try:
            yield borrowed
        finally:
            os.close(borrowed)

    def forced_stop(self):
        """Disqualify success before any fallback termination."""
        with self._fence:
            self._invalid = True

    def _check(self):
        with self._fence:
            if (self._invalid or self._authorized() is not True or self._invalid
                    or time.monotonic() >= self._deadline):
                raise TranscriptUnavailable("Standalone Google ACP transcript owner or deadline changed")

    @contextmanager
    def _step(self, expected, active):
        with self._fence:
            if self._invalid or self._phase != expected:
                raise TranscriptUnavailable("Standalone Google ACP transcript phase changed")
            self._phase = active
        try:
            self._check()
            yield
        except BaseException:
            self.forced_stop()
            raise

    def _wait(self, poll, ready):
        while True:
            self._check()
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TranscriptUnavailable("Standalone Google ACP transcript deadline expired")
            events = poll.poll(min(_POLL_MS, max(1, math.ceil(1000 * remaining))))
            if events:
                if len(events) != 1 or not events[0][1] & ready or events[0][1] & (select.POLLERR | select.POLLNVAL):
                    raise TranscriptUnavailable("Standalone Google ACP descriptor is unavailable")
                self._check()
                return

    def _read(self, fd, poll, size):
        while True:
            self._wait(poll, select.POLLIN | select.POLLHUP)
            if _pipe_fd(fd, os.O_RDONLY, nonblocking=True)[1:] != self._output[1:]:
                raise TranscriptUnavailable("Standalone Google ACP stdout changed")
            try:
                return os.read(fd, size)
            except BlockingIOError:
                continue
            except OSError:
                raise TranscriptUnavailable("Standalone Google ACP stdout could not be read") from None

    def _frame(self, fd, poll):
        while b"\n" not in self._buffer:
            block = self._read(fd, poll, _FRAME_BYTES + 1 - len(self._buffer))
            self._buffer += block
            if not block or len(self._buffer) > _FRAME_BYTES:
                raise TranscriptUnavailable("Standalone Google ACP output ended or exceeded its frame bound")
        frame, _, self._buffer = self._buffer.partition(b"\n")
        try:
            return _parse_frame(frame), len(frame)
        except NativeAcpError:
            raise TranscriptUnavailable("Standalone Google ACP emitted a malformed generation frame") from None

    def _terminal(self, fd, poll):
        text = ""
        usage_seen = False
        while True:
            frame, frame_size = self._frame(fd, poll)
            if "id" in frame:
                if (set(frame) != {"jsonrpc", "id", "result"} or type(frame["id"]) is not int
                        or frame["id"] != PROMPT_REQUEST_ID or not _valid_terminal_result(frame["result"])
                        or text != "ok"):
                    raise TranscriptUnavailable("Unexpected standalone Google ACP terminal result")
                return
            if usage_seen:
                raise TranscriptUnavailable("Unexpected standalone Google ACP output after usage")
            params = frame.get("params")
            update = params.get("update") if type(params) is dict else None
            if type(update) is dict and update.get("sessionUpdate") == "usage_update":
                if text != "ok":
                    raise TranscriptUnavailable("Unexpected standalone Google ACP usage notification")
                try:
                    session = _usage_session(frame, frame_size)
                except NativeAcpError:
                    raise TranscriptUnavailable("Unexpected standalone Google ACP usage notification") from None
                if session != self._session_id:
                    raise TranscriptUnavailable("Unexpected standalone Google ACP usage notification")
                usage_seen = True
                del frame, frame_size, params, update
                continue
            text += _text(frame, self._session_id)
            if not "ok".startswith(text):
                raise TranscriptUnavailable("Unexpected standalone Google ACP answer")

    def read_to_eof(self):
        """Observe the exact terminal turn, close stdin, then require strict EOF."""
        with self._step("pending", "reading"), self._borrow(self._stdout_fd) as fd:
            if _pipe(self._stdout, os.O_RDONLY, nonblocking=True) != self._output:
                raise TranscriptUnavailable("Standalone Google ACP stdout alias changed before reading")
            poll = _poll(fd, select.POLLIN)
            self._terminal(fd, poll)
            with self._fence:
                self._check()
                if _pipe(self._stdin, os.O_WRONLY) != self._input:
                    raise TranscriptUnavailable("Standalone Google ACP stdin changed")
                stdin, self._stdin = self._stdin, None
                try:
                    stdin.close()
                except OSError:
                    raise TranscriptUnavailable("Standalone Google ACP stdin did not close") from None
            if self._buffer or self._read(fd, poll, 1):
                raise TranscriptUnavailable("Standalone Google ACP emitted trailing output")
            with self._fence:
                self._check()
                self._phase = "eof"

    def attest_exit(self, observe):
        """Require pidfd death and a trusted observer honoring the supplied deadline."""
        with self._step("eof", "observing exit"), self._borrow(self._pidfd) as fd:
            self._wait(_poll(fd, select.POLLIN), select.POLLIN)
            receipt = observe(self._invocation, self._deadline)
            with self._fence:
                self._check()
                if (type(receipt) is not NaturalExitReceipt or receipt.invocation is not self._invocation
                        or type(receipt.exec_main_code) is not int or receipt.exec_main_code != os.CLD_EXITED
                        or type(receipt.exec_main_status) is not int or receipt.exec_main_status != 0
                        or type(receipt.main_pid) is not int or receipt.main_pid != 0 or receipt.cgroup_vacant is not True):
                    raise TranscriptUnavailable("Standalone Google ACP natural completion is unconfirmed")
                self._phase = "exited"

    def finish(self, retirement) -> bytes:
        """Freeze immutable answer bytes only after independent exact retirement."""
        with self._step("exited", "settling"):
            with self._fence:
                self._check()
                if (type(retirement) is not UnitRetirementReceipt or retirement.invocation is not self._invocation
                        or retirement.unit_retired is not True or retirement.cgroup_vacant is not True):
                    raise TranscriptUnavailable("Standalone Google ACP exact unit retirement is unconfirmed")
                self._phase = "settled"
                return b"ok"
