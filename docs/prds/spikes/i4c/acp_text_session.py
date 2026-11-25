"""Strict one-turn transcript for the bundled offline ACP peer."""

from contextlib import ExitStack, contextmanager, suppress
import ctypes
import hashlib
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import sys
from threading import Lock
import time

import acp_readiness as readiness
from acp_readiness import IntegrityError, ProtocolError, ReadinessState, RetirementUnconfirmed
from acp_text_peer import (EARLY_SCENES, INIT_ID, MAX_FRAMES, PROMPT_ID, SCENES, SESSION_ID, frame_body,
                           hash_chunk, prompt_request, request, wire)


MAX_LINE = 1024
MAX_BYTES = 8192
MAX_SESSION = 128
MAX_EVIDENCE = 1024
EXPECTED_TEXT = "ok"
EMPTY_DIGEST = hashlib.sha256().hexdigest()
SPIKE = Path(__file__).resolve().parent
REPO = SPIKE.parents[3]
PEER_ENTRY = (
    "import sys; sys.path[:0] = sys.argv[1:3]; "
    "from acp_text_peer import main; raise SystemExit(main(*sys.argv[3:]))"
)
# Python os.write retries EINTR. The admission write must spend its claim on that result.
_LIBC_WRITE = ctypes.CDLL(None, use_errno=True).write
_LIBC_WRITE.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t)
_LIBC_WRITE.restype = ctypes.c_ssize_t
RECEIPT_FIELDS = {
    "attempt", "session_id", "prompt_request_id", "prompt_count",
    "post_prompt_chunk_count", "post_prompt_chunks_sha256",
}


def _object(value, keys):
    return type(value) is dict and value.keys() == keys


def _decode(line):
    try:
        return frame_body(line)
    except (ValueError, RecursionError):
        raise ProtocolError("malformed synthetic ACP frame") from None


def _response(frame, request_id, field):
    if (not _object(frame, {"jsonrpc", "id", field}) or frame["jsonrpc"] != "2.0"
            or type(frame["id"]) is not int or frame["id"] != request_id):
        raise ProtocolError("unexpected synthetic ACP response")
    return frame[field]


def _chunk(frame, session_id):
    if (not _object(frame, {"jsonrpc", "method", "params"}) or frame["jsonrpc"] != "2.0"
            or frame["method"] != "session/update"):
        raise ProtocolError("unexpected synthetic ACP notification or callback")
    params = frame["params"]
    if not _object(params, {"sessionId", "update"}) or params["sessionId"] != session_id:
        raise ProtocolError("unexpected synthetic ACP session")
    update = params["update"]
    if (not _object(update, {"sessionUpdate", "content"})
            or update["sessionUpdate"] != "agent_message_chunk"):
        raise ProtocolError("unexpected synthetic ACP update")
    content = update["content"]
    if (not _object(content, {"type", "text"}) or content["type"] != "text"
            or type(content["text"]) is not str):
        raise ProtocolError("unexpected synthetic ACP content")
    return content["text"]


def _read(fd, deadline, cancelled):
    try:
        with selectors.DefaultSelector() as io:
            io.register(fd, selectors.EVENT_READ)
            while True:
                if cancelled():
                    raise ProtocolError("synthetic ACP exchange was cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProtocolError("synthetic ACP deadline expired")
                if io.select(min(remaining, .05)):
                    return os.read(fd, 4096)
    except OSError:
        raise ProtocolError("synthetic ACP input could not be read") from None


def _prompt_write(fd, packet):
    written = _LIBC_WRITE(fd, packet, len(packet))
    if written < 0:
        raise OSError(ctypes.get_errno(), "synthetic ACP prompt write failed")
    return written


def _write_once(write, fd, packet):
    try:
        written = write(fd, packet)
    except OSError:
        raise ProtocolError("synthetic ACP request write was uncertain") from None
    if written != len(packet):
        raise ProtocolError("synthetic ACP request write was incomplete")


def _read_evidence(fd, attempt, session_id):
    raw = bytearray()
    try:
        while len(raw) <= MAX_EVIDENCE:
            data = os.read(fd, MAX_EVIDENCE + 1 - len(raw))
            if not data:
                break
            raw.extend(data)
    except OSError:
        # In particular, a pipe with a surviving writer must never block retirement.
        return None
    if len(raw) > MAX_EVIDENCE or raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
        return None
    try:
        record = frame_body(bytes(raw[:-1]))
    except (ValueError, RecursionError):
        return None
    if (not _object(record, RECEIPT_FIELDS) or record["attempt"] != attempt
            or record["session_id"] != session_id or type(record["prompt_request_id"]) is not int
            or record["prompt_request_id"] != PROMPT_ID or type(record["prompt_count"]) is not int
            or record["prompt_count"] not in (0, 1) or type(record["post_prompt_chunk_count"]) is not int
            or not 0 <= record["post_prompt_chunk_count"] <= MAX_BYTES
            or type(record["post_prompt_chunks_sha256"]) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", record["post_prompt_chunks_sha256"])):
        return None
    chunks = record["post_prompt_chunk_count"]
    if (record["prompt_count"] == 0 and chunks != 0
            or chunks == 0 and record["post_prompt_chunks_sha256"] != EMPTY_DIGEST):
        return None
    return record


class PublicationUnconfirmed(RuntimeError):
    """The peer retired, but the pending journal still fences workspace settlement."""


class _TextSession:
    """Stdio has one user at a time, from owner startup to broker turn to owner fallback."""

    def __init__(self, process, pidfd, evidence, workspace_fd, directory, current, attempt,
                 timeout, cancelled):
        self.process = process
        self.pidfd = pidfd
        self.evidence = evidence
        self.workspace_fd = workspace_fd
        self.directory = directory
        self.current = current
        self.attempt = attempt
        self.timeout = timeout
        self.cancelled = cancelled
        self.session_id = None
        self.prompt_count = None
        self.prompt_packet = None
        self.prompt_attempted = False
        self.prompt_sent = False
        self.finished = False
        self.phase_failure_state = ReadinessState.NEEDS_VERIFY
        self.buffer = bytearray()
        self.received = 0
        self.frames = 0
        self._lease_lock = Lock()
        self._busy = False
        self._closing = False
        self._peer_retired = False
        self._abandoned_resources = None
        self._receipt_committed = False

    @contextmanager
    def _peer_operation(self):
        # State transitions take the lock, and every peer operation owns the resulting lease.
        # The only file operation under the lock is the final local receipt unlink.
        with self._lease_lock:
            if self._busy or self._closing:
                raise ProtocolError("synthetic ACP peer is unavailable")
            self._busy = True
        try:
            yield
        finally:
            with self._lease_lock:
                resources = self._abandoned_resources
                self._busy = False
            if resources is not None:
                with resources, suppress(RetirementUnconfirmed):
                    self.abort()

    def close_owner(self, resources):
        with self._lease_lock:
            self._closing = True
            if self._busy:
                # The active operation still owns the pidfd, pipes, workspace and journal lock.
                # Defer closing those files to it. Before commit, this also vetoes receipt eviction.
                self._abandoned_resources = resources.pop_all()
                if not self._receipt_committed:
                    if self._peer_retired:
                        raise PublicationUnconfirmed("synthetic ACP peer retired with journal settlement pending")
                    raise RetirementUnconfirmed("synthetic ACP peer still owns retirement resources")
                return
        self.abort()

    def _next_frame(self, deadline):
        while b"\n" not in self.buffer:
            if len(self.buffer) > MAX_LINE:
                raise ProtocolError("synthetic ACP frame exceeded its bound")
            raw = _read(self.process.stdout.fileno(), deadline, self.cancelled)
            self.received += len(raw)
            if self.received > MAX_BYTES:
                raise ProtocolError("synthetic ACP transcript exceeded its byte bound")
            if not raw:
                raise ProtocolError("synthetic ACP frame ended before its delimiter")
            self.buffer.extend(raw)
        line, _, self.buffer = self.buffer.partition(b"\n")
        self.frames += 1
        if len(line) > MAX_LINE or self.frames > MAX_FRAMES:
            raise ProtocolError("synthetic ACP frame or frame count exceeded its bound")
        return _decode(bytes(line))

    def _exchange(self, request_id, method, params, deadline):
        if self.cancelled() or time.monotonic() >= deadline:
            raise ProtocolError("synthetic ACP startup was cancelled or expired")
        packet = wire(request(request_id, method, params))
        if len(packet) >= self.pipe_buf:
            raise ProtocolError("synthetic ACP startup request exceeded its write bound")
        _write_once(os.write, self.process.stdin.fileno(), packet)
        frame = self._next_frame(deadline)
        if self.buffer:
            raise ProtocolError("unexpected output was already buffered across an ACP phase boundary")
        return frame

    def initialize(self, workspace, sync, deadline):
        stdin = self.process.stdin.fileno()
        os.set_blocking(stdin, False)
        os.set_blocking(self.process.stdout.fileno(), False)
        self.pipe_buf = os.fpathconf(stdin, "PC_PIPE_BUF")
        hello = self._exchange(INIT_ID, "initialize",
                               {"protocolVersion": 1, "clientCapabilities": {}}, deadline)
        version = _response(hello, INIT_ID, "result")
        if (not _object(version, {"protocolVersion"}) or type(version["protocolVersion"]) is not int
                or version["protocolVersion"] != 1):
            raise ProtocolError("unexpected synthetic ACP protocol version")
        reply = self._exchange(SESSION_ID, "session/new", {"cwd": str(workspace), "mcpServers": []},
                               deadline)
        if type(reply) is dict and "error" in reply:
            error = _response(reply, SESSION_ID, "error")
            if not _object(error, {"code", "message"}):
                raise ProtocolError("unexpected synthetic ACP session verdict")
            self.phase_failure_state = readiness._classify(reply)
            raise ProtocolError("synthetic ACP session was refused")
        result = _response(reply, SESSION_ID, "result")
        if not _object(result, {"sessionId"}):
            raise ProtocolError("unexpected synthetic ACP session result")
        session_id = result["sessionId"]
        if (type(session_id) is not str or not 1 <= len(session_id) <= MAX_SESSION
                or any(not "!" <= char <= "~" for char in session_id)):
            raise ProtocolError("invalid synthetic ACP session ID")
        self.session_id = session_id
        if sync:
            begin, queued = sync
            _write_once(os.write, begin.fileno(), b"\x01")
            begin.close()
            if _read(queued.fileno(), deadline, self.cancelled) != b"\x01":
                raise ProtocolError("synthetic ACP early-output fixture was not synchronized")
            queued.close()
        packet = wire(prompt_request(self.session_id))
        if len(packet) >= self.pipe_buf:
            raise ProtocolError("synthetic ACP prompt exceeded its write bound")
        self.prompt_packet = packet

    def send_prompt(self):
        """Make the one prompt write under the caller's admission fence."""
        with self._peer_operation():
            if self.finished or self.prompt_attempted or self.prompt_packet is None:
                raise ProtocolError("synthetic ACP prompt is unavailable or already spent")
            self.prompt_attempted = True
            self.deadline = time.monotonic() + self.timeout
            _write_once(_prompt_write, self.process.stdin.fileno(), self.prompt_packet)
            self.prompt_sent = True

    def _finish_transcript(self, deadline, cancelled):
        self.process.stdin.close()
        if self.buffer or _read(self.process.stdout.fileno(), deadline, cancelled):
            raise ProtocolError("unexpected trailing synthetic ACP output")
        try:
            while not cancelled() and time.monotonic() < deadline:
                result = readiness._observe_exit(self.pidfd)
                if result is not None:
                    if result.si_code == os.CLD_EXITED and result.si_status == 0:
                        return
                    raise ProtocolError("synthetic ACP peer did not exit cleanly")
                time.sleep(.01)
        except OSError:
            raise ProtocolError("synthetic ACP exit could not be observed") from None
        raise ProtocolError("synthetic ACP clean exit could not be confirmed")

    def _read_turn(self):
        text = ""
        chunks = 0
        digest = hashlib.sha256()
        while True:
            if self.cancelled() or time.monotonic() >= self.deadline:
                raise ProtocolError("synthetic ACP turn was cancelled or expired")
            frame = self._next_frame(self.deadline)
            if type(frame) is dict and "id" in frame:
                break
            chunk = _chunk(frame, self.session_id)
            text += chunk
            if not EXPECTED_TEXT.startswith(text):
                raise ProtocolError("unexpected synthetic ACP text prefix")
            chunks += 1
            hash_chunk(digest, chunk)

        terminal = _response(frame, PROMPT_ID, "result")
        if not _object(terminal, {"stopReason"}) or terminal["stopReason"] != "end_turn":
            raise ProtocolError("unexpected synthetic ACP terminal result")
        if text != EXPECTED_TEXT:
            raise ProtocolError("unexpected synthetic ACP turn text")
        self._finish_transcript(self.deadline, self.cancelled)
        return text, chunks, digest.hexdigest()

    def complete(self):
        """Return validated text only after receipt, verified retirement, and durable cleanup."""
        with self._peer_operation():
            if self.finished or not self.prompt_sent:
                raise ProtocolError("synthetic ACP turn is unavailable")
            try:
                text, chunks, digest = self._read_turn()
            except BaseException:
                self._finalize(ReadinessState.NEEDS_VERIFY)
                raise
            self._finalize(ReadinessState.READY, transcript=(chunks, digest))
            return text

    def retire(self):
        """Retire an idle or spent peer from the broker thread after revocation."""
        with self._peer_operation():
            self.abort()

    def abort(self):
        if self.finished:
            return
        state = self.phase_failure_state
        clean_abort = False
        if not self.prompt_sent:
            try:
                self._finish_transcript(time.monotonic() + min(self.timeout, .25), lambda: False)
            except (OSError, ProtocolError):
                pass
            else:
                clean_abort = self.prompt_packet is not None and not self.prompt_attempted
        self._finalize(state, clean_abort=clean_abort)

    def _finalize(self, state, *, transcript=None, clean_abort=False):
        self.finished = True
        retired = readiness._retire(self.process, self.pidfd)
        evidence = _read_evidence(self.evidence.fileno(), self.attempt, self.session_id)
        if evidence is not None:
            self.prompt_count = evidence["prompt_count"]
        if not retired:
            raise RetirementUnconfirmed("synthetic ACP retirement is unconfirmed")
        with self._lease_lock:
            self._peer_retired = True
            self._require_publication_rights()

        evidence_matches = evidence is not None and (
            evidence["post_prompt_chunk_count"], evidence["post_prompt_chunks_sha256"]
        )
        turn_verified = (self.prompt_count == 1 and transcript is not None and transcript[0] > 0
                         and evidence_matches == transcript)
        if transcript is not None and not turn_verified:
            state = ReadinessState.NEEDS_VERIFY
        if clean_abort and self.prompt_count == 0 and evidence_matches == (0, EMPTY_DIGEST):
            state = ReadinessState.READY

        # The pending receipt takes precedence over the staged journal state. An owner
        # abandoning during the journal sync can still veto workspace cleanup and publication.
        expected = readiness.Record(self.current.generation, ReadinessState.REVOCATION_UNCONFIRMED,
                                    self.attempt)
        if (readiness._read(self.directory, readiness.JOURNAL) != self.current
                or readiness._read(self.directory, readiness.RECEIPT) != expected):
            raise IntegrityError("the exact synthetic readiness check changed")
        readiness._check_workspace(self.directory, self.attempt, self.workspace_fd)
        readiness._store(self.directory, readiness.JOURNAL, readiness.Record(self.current.generation, state))
        with self._lease_lock:
            self._require_publication_rights()
        readiness._remove_workspace(self.directory, self.attempt, self.workspace_fd)
        try:
            os.fsync(self.directory)
        except OSError:
            raise IntegrityError("synthetic ACP workspace cleanup could not be synced") from None
        with self._lease_lock:
            self._require_publication_rights()
            os.unlink(readiness.RECEIPT, dir_fd=self.directory)
            self._receipt_committed = True
        with suppress(OSError):
            os.fsync(self.directory)

        if transcript is not None and not turn_verified:
            raise ProtocolError("synthetic ACP post-prompt evidence did not match the transcript")

    def _require_publication_rights(self):
        if self._abandoned_resources is not None:
            raise PublicationUnconfirmed("synthetic ACP journal settlement was abandoned after peer retirement")


def _pipe(stack):
    reader, writer = os.pipe()
    return stack.enter_context(os.fdopen(reader, "rb", buffering=0)), stack.enter_context(
        os.fdopen(writer, "wb", buffering=0)
    )


def _launch(resources, directory, workspace_fd, current, attempt, scene, timeout, cancelled):
    workspace_link = Path(f"/proc/self/fd/{workspace_fd}")
    workspace = workspace_link.resolve(strict=True)
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise RetirementUnconfirmed("synthetic ACP child ownership is unavailable")
    evidence_r, evidence_w = _pipe(resources)
    os.set_blocking(evidence_r.fileno(), False)
    inherited = [evidence_w]
    sync = None
    if scene in EARLY_SCENES:
        begin_r, begin_w = _pipe(resources)
        queued_r, queued_w = _pipe(resources)
        inherited.extend((begin_r, queued_w))
        sync = begin_w, queued_r
    fds = tuple(stream.fileno() for stream in inherited)
    sync_fds = fds[1:] or (-1, -1)
    args = [sys.executable, "-IBS", "-c", PEER_ENTRY, str(SPIKE), str(REPO), scene, str(workspace.parent),
            current.generation, attempt, str(fds[0]), *(str(fd) for fd in sync_fds)]
    try:
        process = subprocess.Popen(args, cwd=workspace_link, pass_fds=fds, start_new_session=True,
                                   env={"HOME": "/nonexistent", "LANG": "C.UTF-8"}, bufsize=0,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        raise RetirementUnconfirmed("synthetic ACP launch could not be verified") from None
    finally:
        for stream in inherited:
            stream.close()
    resources.callback(readiness._close_pipes, process)
    try:
        pidfd = resources.enter_context(readiness._owned_pidfd(process))
    except (AttributeError, OSError):
        raise RetirementUnconfirmed("synthetic ACP child ownership could not be verified") from None
    if not readiness._prepare_owned_peer(process, pidfd):
        raise RetirementUnconfirmed("synthetic ACP group retirement is unavailable")
    session = _TextSession(process, pidfd, evidence_r, workspace_fd, directory, current, attempt,
                           timeout, cancelled)
    return session, workspace, sync


@contextmanager
def open_text_session(root: Path, generation: str, scene="ready", *, timeout=5, cancelled=lambda: False):
    """Open the fixed peer and hand off stdio. Join its broker before leaving this context.

    `prompt_count` is the observed 0 or 1 from a verified receipt, or None when unknown.
    """
    if scene not in SCENES or type(timeout) not in (int, float) or not 0 < timeout <= 30:
        raise ValueError("invalid synthetic ACP scene or timeout")
    deadline = time.monotonic() + timeout
    with ExitStack() as resources:
        directory = resources.enter_context(readiness._locked(root, deadline=deadline, cancelled=cancelled))
        current = readiness._status(directory)
        if current is None or current.generation != generation:
            raise IntegrityError("the exact synthetic generation changed")
        if current.readiness is ReadinessState.REVOCATION_UNCONFIRMED:
            raise RetirementUnconfirmed("a previous synthetic ACP retirement is unconfirmed")
        closed = resources.enter_context(readiness._enrollment_handle(directory))
        if not closed:
            raise ProtocolError("synthetic ACP enrollment is still open")
        attempt = secrets.token_hex(16)
        readiness._store(directory, readiness.RECEIPT,
                         readiness.Record(generation, ReadinessState.REVOCATION_UNCONFIRMED, attempt))
        os.mkdir(attempt, mode=0o700, dir_fd=directory)
        workspace_fd = os.open(attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        resources.callback(os.close, workspace_fd)
        readiness._check_workspace(directory, attempt, workspace_fd)
        session, workspace, sync = _launch(resources, directory, workspace_fd, current, attempt,
                                           scene, timeout, cancelled)
        try:
            session.initialize(workspace, sync, deadline)
            if cancelled() or time.monotonic() >= deadline:
                raise ProtocolError("synthetic ACP startup was cancelled or expired")
            yield session
        finally:
            session.close_owner(resources)
