"""Attended foreground broker and CLI for the single-turn zero-tool ChatGPT canary."""

from contextlib import contextmanager, suppress
from dataclasses import dataclass
from hashlib import sha256
import hmac
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import sys
import tempfile
import threading
import time

from .canary_ledger import (
    CanaryLedger,
    CanaryLedgerError,
    HistorySnapshot,
    RecoverySnapshot,
)
from .canary_protocol import (
    IDLE_SECONDS,
    MAX_MODELS_REQUESTS,
    PORT,
    PROOF_SIZE,
    REFUSAL_RESPONSE,
    TOTAL_SECONDS,
    CanaryUnsettledError,
    Refused,
    StreamOutcome,
    consume_upstream_stream,
    models_http_response,
    ok_sse_http_response,
    parse_local_request,
    receive_client,
    validate_responses_request,
    verify_opencode_json_stdout,
)
from .canary_runtime import (
    DetachedOwnerSession,
    OwnerLost,
    RuntimeFailure,
    check_private_directory,
    scratch_parent,
)
from .cli import MODEL, Reason, RouteUnavailable, StreamTerminal, Terminal, report_failure
from .connection import ConnectionError
from .exposure import _INPUT_LIMIT, _OUTPUT_LIMIT, binding_digest
from .live import make_backend
from .profile_backend import ProfileBackend
from .responses import StreamFailure, StreamLimits


_MODEL_SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_CLOSED_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
_CLOSED_MEDIA = frozenset({"sse", "missing", "plain", "octet-stream", "other", "ambiguous"})
_CLOSED_SUPPRESS_REASONS = frozenset({
    "ok", "non_exact_output", "non_exact_text", "invalid_delta", "projected_limit",
    "invalid_output", "disallowed_item", "invalid_item", "disallowed_part",
    "invalid_queued", "unexpected_event", "safety_signal", "safety_buffering",
    "safety_scan_limit", "metadata_guardian", "metadata_envelope", "metadata_fields",
    "metadata_review", "metadata_moderation", "metadata_moderation_shape",
    "metadata_moderation_root_keys", "metadata_moderation_blocked",
})
REVIEWED_MODELS = {MODEL: (_INPUT_LIMIT, _OUTPUT_LIMIT)}
CANARY_STREAM_LIMITS = StreamLimits(
    max_json=1024 * 1024,
    max_stream=4 * 1024 * 1024,
    max_line=512 * 1024,
    max_events=1024,
    io_timeout=IDLE_SECONDS,
)


def _closed_diagnostic(exc: Exception) -> str:
    """Return a strictly content-free closed diagnostic string for an exception."""
    if isinstance(exc, StreamFailure):
        return exc.describe()
    if isinstance(exc, ConnectionError):
        code = exc.code if type(exc.code) is str and _CLOSED_CODE_RE.fullmatch(exc.code) else "provider_error"
        return f"code={code}"
    if isinstance(exc, RouteUnavailable):
        return f"code={exc.reason.value}"
    if isinstance(exc, (CanaryUnsettledError, CanaryLedgerError)):
        raw = exc.args[0] if exc.args and type(exc.args[0]) is str else ""
        code = raw if _CLOSED_CODE_RE.fullmatch(raw) else "canary_error"
        return f"code={code}"
    if isinstance(exc, OwnerLost):
        return "code=owner_lost"
    if isinstance(exc, RuntimeFailure):
        return "code=runtime_failure"
    return "code=io_error"


_UNSUPPORTED_ARGS = "unsupported canary arguments"


@dataclass(frozen=True)
class CanaryArgs:
    model: str | None
    synthetic_check: bool
    reviewed_source: str | None = None
    recover_unsettled: bool = False


def _parse_canary_flag(argv: list[str], idx: int, current: str | None, pattern: re.Pattern) -> tuple[str, int]:
    if current is not None or idx + 1 >= len(argv):
        raise ValueError(_UNSUPPORTED_ARGS)
    value = argv[idx + 1]
    if not pattern.fullmatch(value):
        raise ValueError("invalid canary argument value")
    return value, idx + 2


def _set_unique_flag(current: bool, conflict: bool) -> bool:
    if current or conflict:
        raise ValueError(_UNSUPPORTED_ARGS)
    return True


def _consume_canary_arg(argv: list[str], idx: int, state: dict) -> int:
    arg = argv[idx]
    if arg == "--synthetic-check":
        state["synthetic"] = _set_unique_flag(state["synthetic"], state["recover"])
        return idx + 1
    if arg == "--recover-unsettled":
        state["recover"] = _set_unique_flag(state["recover"], state["synthetic"])
        return idx + 1
    if arg == "--model":
        state["model"], next_idx = _parse_canary_flag(argv, idx, state["model"], _MODEL_SLUG_RE)
        return next_idx
    if arg == "--reviewed-source":
        state["reviewed_source"], next_idx = _parse_canary_flag(argv, idx, state["reviewed_source"], _SHA256_RE)
        return next_idx
    raise ValueError(_UNSUPPORTED_ARGS)


def parse_canary_argv(argv: list[str]) -> CanaryArgs:
    """Strictly parse `canary [--model SLUG] [--reviewed-source SHA256] [--synthetic-check | --recover-unsettled]`."""
    state: dict = {"model": None, "synthetic": False, "recover": False, "reviewed_source": None}
    idx = 0
    while idx < len(argv):
        idx = _consume_canary_arg(argv, idx, state)
    if state["recover"] and state["reviewed_source"] is None:
        raise ValueError("--recover-unsettled requires --reviewed-source")
    return CanaryArgs(
        model=state["model"],
        synthetic_check=state["synthetic"],
        reviewed_source=state["reviewed_source"],
        recover_unsettled=state["recover"],
    )


def _trusted_source_file(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise RuntimeFailure("untrusted canary source file") from None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or info.st_nlink != 1 or info.st_mode & 0o022):
            raise RuntimeFailure("untrusted canary source file")
        data = stream.read(1_048_577)
    if len(data) > 1_048_576:
        raise RuntimeFailure("canary source file exceeds size cap")
    return data


def _collect_dir_files(base: Path, directory: Path, out: list[Path]) -> None:
    try:
        info = directory.lstat()
    except OSError:
        raise RuntimeFailure("untrusted canary source directory") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise RuntimeFailure("untrusted canary source directory")
    for entry in sorted(directory.iterdir()):
        if not entry.is_symlink() and entry.is_dir():
            _collect_dir_files(base, entry, out)
        else:
            out.append(entry.relative_to(base))


def _collect_source_files(root: Path) -> list[Path]:
    files = [Path("oc-sandbox"), Path("oc-openai.py")]
    for pkg in ("oc_openai", "oc_providers"):
        _collect_dir_files(root, root / pkg, files)
    return sorted(files)


def canary_source_digest(root: Path | None = None) -> str:
    """Compute a deterministic SHA-256 provenance digest over the canary source tree."""
    base = Path(__file__).resolve().parents[1] if root is None else Path(root)
    hasher = sha256()
    for rel in _collect_source_files(base):
        data = _trusted_source_file(base / rel)
        hasher.update(rel.as_posix().encode("ascii") + b"\0" + sha256(data).digest())
    return hasher.hexdigest()


def _send_all_bounded(sock: socket.socket, data: bytes, *, timeout: float = IDLE_SECONDS) -> int:
    sock.settimeout(timeout)
    sock.sendall(data)
    return len(data)


def _send_nonblocking_exact(sock: socket.socket, data: bytes) -> int:
    """Single non-blocking send for use while holding global profile/store locks."""
    sock.setblocking(False)
    try:
        sent = sock.send(data)
    except OSError:
        raise OwnerLost("nonblocking client delivery failed") from None
    finally:
        with suppress(OSError):
            sock.settimeout(IDLE_SECONDS)
    if sent != len(data):
        raise OwnerLost("incomplete nonblocking client delivery")
    return sent


def _recv_exact_proof(conn: socket.socket, expected: bytes) -> bool:
    conn.settimeout(IDLE_SECONDS)
    buf = bytearray()
    while len(buf) < PROOF_SIZE:
        chunk = conn.recv(PROOF_SIZE - len(buf))
        if not chunk:
            return False
        buf.extend(chunk)
    return hmac.compare_digest(bytes(buf), expected)


@dataclass(frozen=True)
class CanaryBrokerConfig:
    """Configuration and callbacks for one zero-tool canary broker run."""

    proof: bytes
    worker_token: str
    bound_model: str
    ledger: CanaryLedger
    run_id: str
    binding_hash: str
    history_digest: str
    upstream_stream: object
    fenced_client_write: object
    check_alive: object
    port: int = PORT
    after_reserve: object = None
    recovery_prior: tuple[str, str] | None = None
    expected_prior: tuple[str, str] | None = None


@dataclass(frozen=True)
class CanaryLiveResult:
    """Strictly content-free result from an isolated live e2e canary run."""

    ok: bool
    label: str
    model: str
    upstream_calls: int
    ledger_outcome: str | None
    delivered_bytes: int
    media_fallback: str | None
    input_tokens: int | None
    output_tokens: int | None
    opencode_rc: int
    stdout_verified: bool
    cleanup_verified: bool
    details: str


class CanaryBroker:
    """Foreground UDS broker enforcing 0 tools and at most 1 upstream Responses send."""

    def __init__(self, sock_path: Path, config: CanaryBrokerConfig):
        self.sock_path = sock_path
        self.proof = config.proof
        self.worker_token = config.worker_token
        self.bound_model = config.bound_model
        self.ledger = config.ledger
        self.run_id = config.run_id
        self.binding_hash = config.binding_hash
        self.history_digest = config.history_digest
        self.upstream_stream = config.upstream_stream
        self.fenced_client_write = config.fenced_client_write
        self.check_alive = config.check_alive
        self.port = config.port
        self.after_reserve = config.after_reserve
        self.recovery_prior = config.recovery_prior
        self.expected_prior = config.expected_prior
        self._stop = threading.Event()
        self._admit_lock = threading.Lock()
        self._peer_lock = threading.Lock()
        self._active_peers: set[socket.socket] = set()
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.models_requests = 0
        self.inference_admitted = False
        self.upstream_calls = 0
        self.stream_outcome: StreamOutcome | None = None
        self.ledger_outcome: str | None = None
        self.delivered_bytes = 0
        self.media_fallback: str | None = None
        self.diagnostic: str = ""
        self.error: str | None = None

    def observe_media(self, category: str) -> None:
        if type(category) is str and category in _CLOSED_MEDIA:
            self.media_fallback = category

    @contextmanager
    def _track_peer(self, sock: socket.socket):
        with self._peer_lock:
            if self._stop.is_set():
                raise OwnerLost("canary cancelled")
            self._active_peers.add(sock)
        try:
            yield
        finally:
            with self._peer_lock:
                self._active_peers.discard(sock)

    def start(self) -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(self.sock_path))
            os.chmod(self.sock_path, 0o600)
            server.listen(4)
            server.settimeout(0.25)
        except BaseException:
            with suppress(OSError):
                server.close()
            raise
        self._server = server
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._server is not None:
            with suppress(OSError):
                self._server.close()
        with self._peer_lock:
            peers = tuple(self._active_peers)
        for peer in peers:
            with suppress(OSError):
                peer.shutdown(socket.SHUT_RDWR)
        if self._thread is not None:
            self._thread.join(timeout=5)
        with suppress(OSError):
            self.sock_path.unlink(missing_ok=True)

    def _serve(self) -> None:
        server = self._server
        if server is None:
            return
        while not self._stop.is_set():
            try:
                control, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with control, self._track_peer(control):
                    self._handle_control(control)
            except Exception as exc:
                self.error = str(exc)

    def _handle_control(self, control: socket.socket) -> None:
        try:
            if not _recv_exact_proof(control, self.proof):
                return
            client = receive_client(control, port=self.port)
        except (OSError, Refused):
            return
        with client, self._track_peer(client):
            self._handle_client(client)

    def _send_if_alive(self, client: socket.socket, payload: bytes) -> None:
        if self._stop.is_set():
            return
        try:
            self.check_alive()
        except (OwnerLost, RouteUnavailable, ConnectionError):
            return
        with suppress(OSError):
            _send_all_bounded(client, payload)

    def _handle_client(self, client: socket.socket) -> None:
        deadline = time.monotonic() + TOTAL_SECONDS
        try:
            req = parse_local_request(
                client, deadline, port=self.port, expected_token=self.worker_token,
            )
        except (OSError, Refused):
            self._send_if_alive(client, REFUSAL_RESPONSE)
            return
        if req.kind == "models":
            self._serve_models(client)
            return
        self._serve_responses(client, req.body or b"", deadline)

    def _serve_models(self, client: socket.socket) -> None:
        with self._admit_lock:
            if self.models_requests >= MAX_MODELS_REQUESTS:
                self._send_if_alive(client, REFUSAL_RESPONSE)
                return
            self.models_requests += 1
        self._send_if_alive(client, models_http_response(self.bound_model))

    def _check_dispatch_authority(self, deadline: float) -> None:
        if self._stop.is_set():
            raise OwnerLost("canary cancelled")
        if time.monotonic() >= deadline:
            raise OwnerLost("canary turn deadline expired")
        self.check_alive()

    def _reserve_before_write(self, deadline: float) -> None:
        self._check_dispatch_authority(deadline)
        alive_cb = lambda: self._check_dispatch_authority(deadline)
        if self.recovery_prior is not None:
            prior_run_id, prior_digest = self.recovery_prior
            self.ledger.reserve_recovery(
                self.run_id, self.binding_hash, self.bound_model, self.history_digest,
                prior_run_id=prior_run_id, prior_digest=prior_digest,
                expected_prior=self.expected_prior, deadline=deadline, check_alive=alive_cb,
            )
        else:
            self.ledger.reserve(
                self.run_id, self.binding_hash, self.bound_model, self.history_digest,
                deadline=deadline, check_alive=alive_cb,
            )
        self.ledger_outcome = "unsettled"
        if self.after_reserve is not None:
            self.after_reserve()
        # Re-verify TTY, owner liveness, cancellation, and deadline after blocking reservation.
        self._check_dispatch_authority(deadline)

    def _serve_responses(self, client: socket.socket, body: bytes, deadline: float) -> None:
        try:
            canonical = validate_responses_request(body, bound_model=self.bound_model)
        except Refused:
            self._send_if_alive(client, REFUSAL_RESPONSE)
            return
        with self._admit_lock:
            if self.inference_admitted:
                self._send_if_alive(client, REFUSAL_RESPONSE)
                return
            self.inference_admitted = True
        self._dispatch_single_turn(client, canonical, deadline)

    def _dispatch_single_turn(self, client: socket.socket, canonical: dict, deadline: float) -> None:
        recovery = self.recovery_prior is not None
        try:
            self._check_dispatch_authority(deadline)
            self.upstream_calls += 1
            with self.upstream_stream(
                canonical,
                before_write=lambda: self._reserve_before_write(deadline),
                deadline=deadline,
                cancelled=self._stop,
            ) as events:
                outcome = consume_upstream_stream(
                    events, bound_model=self.bound_model,
                    check_alive=lambda: self._check_dispatch_authority(deadline),
                )
            self.stream_outcome = outcome
            settled = self.ledger.settle(
                self.run_id,
                allow_delivery=outcome.allow_delivery,
                input_tokens=outcome.input_tokens,
                output_tokens=outcome.output_tokens,
                recovery=recovery,
            )
            self.ledger_outcome = settled
            if settled == "ok_settled":
                payload = ok_sse_http_response(
                    self.bound_model, outcome.input_tokens, outcome.output_tokens,
                )
                self._deliver_fenced(client, payload, deadline)
        except (CanaryLedgerError, CanaryUnsettledError, ConnectionError, OwnerLost, RouteUnavailable, OSError) as exc:
            self.diagnostic = _closed_diagnostic(exc)
            self.error = self.diagnostic

    def _deliver_fenced(self, client: socket.socket, payload: bytes, deadline: float) -> None:
        def write_action():
            self._check_dispatch_authority(deadline)
            return _send_nonblocking_exact(client, payload)

        self.delivered_bytes = self.fenced_client_write(write_action)


def _format_disclosure(
    label: str,
    model: str,
    history: HistorySnapshot,
    source_digest: str,
    *,
    recovery: RecoverySnapshot | None = None,
) -> str:
    max_in, max_out = REVIEWED_MODELS[model]
    prior_desc = (
        f"{len(history.present_files)} prior I4a record file(s) "
        f"({history.record_count} entries, {history.unsettled_count} unsettled; "
        f"verified settled usage {history.settled_input:,} in / {history.settled_output:,} out; "
        f"open unsettled reservations {history.unsettled_input:,} in / {history.unsettled_output:,} out; "
        f"cumulative prior ceilings {history.reserved_input:,} in / {history.reserved_output:,} out)"
        if history.present_files
        else "no prior I4a hold files"
    )
    prior_canary_in = recovery.prior_max_input if recovery is not None else 0
    prior_canary_out = recovery.prior_max_output if recovery is not None else 0
    total_in = history.reserved_input + prior_canary_in + max_in
    total_out = history.reserved_output + prior_canary_out + max_out
    recovery_note = (
        f"Prior unsettled canary.json (read-only, untouched): run_id={recovery.prior_run_id}, "
        f"open unsettled ceiling {prior_canary_in:,} in / {prior_canary_out:,} out. "
        "This one-shot recovery reserves canary-recovery.json without modifying canary.json; "
        "strict moderation checks remain active and may settle actual usage as refused_settled with 0 client bytes. "
        if recovery is not None
        else ""
    )
    return (
        f"Active registration: {label}. Bound model: {model}. "
        f"Canary source SHA-256: {source_digest}. "
        f"Prior workstation state (read-only, untouched): {prior_desc}. "
        f"{recovery_note}"
        f"This single-use zero-tool canary authorizes at most 1 request to OpenAI ('Reply with exactly: ok'). "
        f"OpenCode local limit.output=64 does not cap upstream because ChatGPT /v1/responses omits max_output_tokens; "
        f"published ceilings add up to {max_in:,} input and {max_out:,} output tokens "
        f"(combined reserved ceiling up to {total_in:,} input and {total_out:,} output tokens). "
        "OpenAI may use your ChatGPT plan or account credits with no verified hard spending cap. "
        "API-key fallback and all tools are disabled. Ctrl-C stops and cleans up."
    )


def _format_failure_details(broker: CanaryBroker) -> str:
    parts = []
    if broker.media_fallback in _CLOSED_MEDIA:
        parts.append(f"media_fallback={broker.media_fallback}")
    if broker.stream_outcome is not None and not broker.stream_outcome.allow_delivery:
        raw_reason = broker.stream_outcome.reason
        reason = raw_reason if raw_reason in _CLOSED_SUPPRESS_REASONS else "suppressed"
        parts.append(f"reason={reason}")
    elif broker.diagnostic:
        parts.append(broker.diagnostic)
    return ("; " + ", ".join(parts)) if parts else ""


def _resolve_model(conn, binding, requested: str | None) -> str:
    target = requested or MODEL
    if target not in REVIEWED_MODELS:
        raise RouteUnavailable(Reason.MODEL_UNAVAILABLE)
    models = conn.models(binding)
    if target not in models:
        raise RouteUnavailable(Reason.MODEL_UNAVAILABLE)
    return target


def _verify_live_identity(backend: ProfileBackend, label: str, epoch: str, binding) -> None:
    cur_label, cur_epoch, _cur_conn, cur_binding = backend.active_connection()
    if (cur_label, cur_epoch, cur_binding) != (label, epoch, binding):
        raise RouteUnavailable(Reason.CONNECTION_CHANGED)


def _check_tty_and_owner(terminal: Terminal, owner: DetachedOwnerSession) -> None:
    if not terminal.attended():
        raise OwnerLost("foreground terminal lost")
    owner.check_alive()


def _verify_and_record_completion(
    terminal: Terminal,
    ledger: CanaryLedger,
    broker: CanaryBroker,
    run_id: str,
    *,
    root: Path,
    rc: int,
    stdout_bytes: bytes,
    cleanup_verified: bool,
    cleanup_error: str,
    owner_rc: int,
    recovery: bool = False,
) -> int:
    clean_ok = cleanup_verified and owner_rc == 0 and not root.exists()
    if not clean_ok:
        terminal.error(
            f"ChatGPT canary cleanup was not verified ({cleanup_error or f'owner_rc={owner_rc}'}); "
            f"preserving ledger state ({broker.ledger_outcome or 'none'}) without retry."
        )
        return 1
    if (broker.ledger_outcome == "ok_settled" and broker.delivered_bytes > 0
            and rc == 0 and verify_opencode_json_stdout(stdout_bytes)):
        ledger.mark_delivered(run_id, recovery=recovery)
        terminal.write(
            f"ChatGPT canary succeeded: exact 'ok' delivered, verified cleanup, and settled "
            f"({broker.stream_outcome.input_tokens} in / {broker.stream_outcome.output_tokens} out)."
        )
        return 0
    details = _format_failure_details(broker)
    terminal.error(
        f"ChatGPT canary did not verify clean 'ok' delivery "
        f"(ledger={broker.ledger_outcome or 'none'}, opencode_rc={rc}{details})."
    )
    return 1


def _execute_canary_session(
    *,
    terminal: Terminal,
    backend: ProfileBackend,
    ledger: CanaryLedger,
    label: str,
    epoch: str,
    conn,
    binding,
    model: str,
    history: HistorySnapshot,
    owner_factory=DetachedOwnerSession,
    recovery_prior: tuple[str, str] | None = None,
    expected_prior: tuple[str, str] | None = None,
) -> int:
    run_id = secrets.token_hex(16)
    worker_token = secrets.token_hex(32)
    b_hash = binding_digest(binding.profile, binding.generation, epoch)
    owner = owner_factory(model, worker_token)
    broker = None
    root: Path | None = None
    try:
        root, proof = owner.prepare()

        def check_alive():
            _check_tty_and_owner(terminal, owner)

        @contextmanager
        def upstream_stream(body, *, before_write, deadline, cancelled):
            with conn.canary_responses(
                binding, body,
                authorization=lambda: backend.selected_fence(label, epoch),
                before_write=before_write,
                limits=CANARY_STREAM_LIMITS,
                deadline=deadline,
                cancelled=cancelled,
                inspect_media=True,
                observe_media=broker.observe_media,
            ) as events:
                yield events

        broker = CanaryBroker(
            root / "relay" / "provider.sock",
            CanaryBrokerConfig(
                proof=proof,
                worker_token=worker_token,
                bound_model=model,
                ledger=ledger,
                run_id=run_id,
                binding_hash=b_hash,
                history_digest=history.digest,
                upstream_stream=upstream_stream,
                fenced_client_write=lambda fn: backend.canary_fenced_write(label, epoch, conn, binding, fn),
                check_alive=check_alive,
                recovery_prior=recovery_prior,
                expected_prior=expected_prior,
            ),
        )
        broker.start()
        owner.start_containers()
        rc, stdout_bytes, _stderr_bytes, cleanup_verified, cleanup_error = owner.wait_opencode()
    finally:
        if broker is not None:
            broker.close()
        owner_rc = owner.close()
    return _verify_and_record_completion(
        terminal, ledger, broker, run_id,
        root=root, rc=rc, stdout_bytes=stdout_bytes,
        cleanup_verified=cleanup_verified, cleanup_error=cleanup_error, owner_rc=owner_rc,
        recovery=(recovery_prior is not None),
    )


def _preflight_and_resolve(backend: ProfileBackend, ledger: CanaryLedger, requested_model: str | None, *,
                           recover_unsettled: bool, expected_prior: tuple[str, str] | None):
    if not recover_unsettled:
        history = ledger.preflight()
        label, epoch, conn, binding = backend.active_connection()
        model = _resolve_model(conn, binding, requested_model)
        return label, epoch, conn, binding, model, history, None
    target = requested_model or MODEL
    if target not in REVIEWED_MODELS:
        raise RouteUnavailable(Reason.MODEL_UNAVAILABLE)
    label, epoch, conn, binding = backend.active_connection()
    b_hash = binding_digest(binding.profile, binding.generation, epoch)
    rec = ledger.preflight_recovery(b_hash, target, expected_prior=expected_prior)
    model = _resolve_model(conn, binding, target)
    return label, epoch, conn, binding, model, rec.history, rec


def run_canary(
    terminal: Terminal,
    *,
    requested_model: str | None = None,
    reviewed_source: str | None = None,
    recover_unsettled: bool = False,
    expected_prior: tuple[str, str] | None = None,
    backend_factory=None,
    owner_factory=DetachedOwnerSession,
    source_root: Path | None = None,
) -> int:
    """Run the attended single-turn zero-tool ChatGPT canary (or one-shot unsettled recovery)."""
    if not terminal.attended():
        terminal.error("ChatGPT canary requires an attended foreground workstation terminal.")
        return 2
    if recover_unsettled and reviewed_source is None:
        terminal.error("ChatGPT canary recovery requires --reviewed-source SHA256.")
        return 2
    factory = backend_factory or make_backend
    try:
        source_digest = canary_source_digest(source_root)
        if reviewed_source is not None and not hmac.compare_digest(source_digest, reviewed_source):
            terminal.error("ChatGPT canary source digest does not match --reviewed-source.")
            return 1
        backend = factory()
        ledger = CanaryLedger(backend._state)
        with ledger.exclusive_run():
            label, epoch, conn, binding, model, history, rec_snap = _preflight_and_resolve(
                backend, ledger, requested_model,
                recover_unsettled=recover_unsettled, expected_prior=expected_prior,
            )
            terminal.write(_format_disclosure(label, model, history, source_digest, recovery=rec_snap))
            prompt = (
                "Authorize this single one-shot recovery zero-tool OpenCode canary request?"
                if rec_snap is not None
                else "Authorize this single zero-tool OpenCode canary request?"
            )
            if not terminal.confirm(prompt):
                terminal.error("Cancelled.")
                return 1
            _verify_live_identity(backend, label, epoch, binding)
            return _execute_canary_session(
                terminal=terminal, backend=backend, ledger=ledger,
                label=label, epoch=epoch, conn=conn, binding=binding,
                model=model, history=history, owner_factory=owner_factory,
                recovery_prior=(rec_snap.prior_run_id, rec_snap.prior_digest) if rec_snap is not None else None,
                expected_prior=expected_prior,
            )
    except RouteUnavailable as error:
        return report_failure(terminal, error, operation="ChatGPT canary")
    except (CanaryLedgerError, ConnectionError, OwnerLost, RuntimeFailure) as error:
        terminal.error(f"ChatGPT canary refused: {_closed_diagnostic(error)}")
        return 1


def _synthetic_upstream_events(body: dict):
    resp_id = "resp_synth_1"
    return (
        {"type": "response.created", "response": {"id": resp_id, "model": body["model"], "status": "in_progress"}},
        {"type": "response.metadata", "response_id": resp_id, "sequence_number": 1,
         "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {"outputs": [{"is_blocked": False}]}}}},
        {"type": "response.output_item.added", "output_index": 0,
         "item": {"id": "rs_1", "type": "reasoning", "status": "completed", "summary": []}},
        {"type": "response.output_text.delta", "output_index": 1, "content_index": 0, "delta": "ok"},
        {"type": "response.output_text.done", "output_index": 1, "content_index": 0, "text": "ok"},
        {"type": "response.completed", "response": {
            "id": resp_id, "model": body["model"], "status": "completed",
            "output": [
                {"id": "rs_1", "type": "reasoning", "status": "completed", "summary": []},
                {"id": "msg_1", "type": "message", "role": "assistant", "status": "completed",
                 "content": [{"type": "output_text", "text": "ok"}]},
            ],
            "usage": {"input_tokens": 12, "output_tokens": 1, "total_tokens": 13},
        }},
    )


def run_synthetic_check(terminal: Terminal, *, requested_model: str | None = None) -> int:
    """Run the shipping canary placement against an in-process synthetic upstream (0 live calls)."""
    model = requested_model or MODEL
    if model not in REVIEWED_MODELS:
        terminal.error(f"Synthetic ChatGPT canary refused: model '{model}' is not reviewed.")
        return 1
    parent = scratch_parent()
    try:
        check_private_directory(parent)
    except RuntimeFailure as error:
        terminal.error(f"Synthetic ChatGPT canary check failed: {error}")
        return 1
    with tempfile.TemporaryDirectory(prefix="oc-canary-synth-", dir=parent) as scratch:
        state_dir = Path(scratch)
        os.chmod(state_dir, 0o700)
        ledger = CanaryLedger(state_dir)
        history = ledger.preflight()
        run_id = secrets.token_hex(16)
        worker_token = secrets.token_hex(32)
        b_hash = binding_digest("a" * 43, "b" * 43, "c" * 43)
        owner = DetachedOwnerSession(model, worker_token)
        broker = None
        root: Path | None = None
        try:
            root, proof = owner.prepare()

            @contextmanager
            def fake_upstream(body, *, before_write, deadline, cancelled):
                before_write()
                if cancelled.is_set() or time.monotonic() >= deadline:
                    raise OwnerLost("synthetic canary cancelled")
                yield _synthetic_upstream_events(body)

            broker = CanaryBroker(
                root / "relay" / "provider.sock",
                CanaryBrokerConfig(
                    proof=proof,
                    worker_token=worker_token,
                    bound_model=model,
                    ledger=ledger,
                    run_id=run_id,
                    binding_hash=b_hash,
                    history_digest=history.digest,
                    upstream_stream=fake_upstream,
                    fenced_client_write=lambda fn: fn(),
                    check_alive=owner.check_alive,
                ),
            )
            broker.start()
            owner.start_containers()
            rc, stdout_bytes, _stderr_bytes, cleanup_verified, cleanup_error = owner.wait_opencode()
        except (CanaryLedgerError, OwnerLost, RuntimeFailure, OSError) as error:
            terminal.error(f"Synthetic ChatGPT canary check failed: {error}")
            return 1
        finally:
            if broker is not None:
                broker.close()
            owner_rc = owner.close()
        clean_ok = cleanup_verified and owner_rc == 0 and root is not None and not root.exists()
        if (clean_ok and broker.upstream_calls == 1 and broker.ledger_outcome == "ok_settled"
                and broker.delivered_bytes > 0 and rc == 0 and verify_opencode_json_stdout(stdout_bytes)):
            ledger.mark_delivered(run_id)
            terminal.write(
                f"Synthetic ChatGPT canary check passed for model {model} "
                "(1 synthetic POST, exact 'ok', cleanup verified)."
            )
            return 0
        terminal.error(
            f"Synthetic ChatGPT canary check failed "
            f"(posts={broker.upstream_calls}, ledger={broker.ledger_outcome}, rc={rc}, "
            f"cleanup={cleanup_verified}:{cleanup_error})."
        )
        return 1


def _build_live_result(
    label: str, model: str, broker: CanaryBroker,
    wait_result: tuple[int, bytes, bool, int], root: Path | None,
) -> CanaryLiveResult:
    rc, stdout_bytes, cleanup_verified, owner_rc = wait_result
    stdout_ok = verify_opencode_json_stdout(stdout_bytes)
    clean_ok = cleanup_verified and owner_rc == 0 and root is not None and not root.exists()
    out = broker.stream_outcome
    ok = (
        clean_ok and broker.upstream_calls == 1 and broker.ledger_outcome == "ok_settled"
        and broker.delivered_bytes > 0 and rc == 0 and stdout_ok
    )
    return CanaryLiveResult(
        ok=ok,
        label=label,
        model=model,
        upstream_calls=broker.upstream_calls,
        ledger_outcome=broker.ledger_outcome,
        delivered_bytes=broker.delivered_bytes,
        media_fallback=broker.media_fallback,
        input_tokens=out.input_tokens if out is not None else None,
        output_tokens=out.output_tokens if out is not None else None,
        opencode_rc=rc,
        stdout_verified=stdout_ok,
        cleanup_verified=clean_ok,
        details=_format_failure_details(broker),
    )


def run_live_canary_e2e(
    *,
    requested_model: str | None = None,
    backend_factory=None,
    owner_factory=DetachedOwnerSession,
) -> CanaryLiveResult:
    """Run the zero-tool OpenCode + OpenAI live e2e canary using an isolated scratch ledger."""
    factory = backend_factory or make_backend
    backend = factory()
    label, epoch, conn, binding = backend.active_connection()
    model = _resolve_model(conn, binding, requested_model)
    parent = scratch_parent()
    check_private_directory(parent)
    with tempfile.TemporaryDirectory(prefix="oc-canary-e2e-", dir=parent) as scratch:
        state_dir = Path(scratch)
        os.chmod(state_dir, 0o700)
        ledger = CanaryLedger(state_dir)
        history = ledger.preflight()
        run_id = secrets.token_hex(16)
        worker_token = secrets.token_hex(32)
        b_hash = binding_digest(binding.profile, binding.generation, epoch)
        owner = owner_factory(model, worker_token)
        broker = None
        root: Path | None = None
        try:
            root, proof = owner.prepare()

            @contextmanager
            def upstream_stream(body, *, before_write, deadline, cancelled):
                with conn.canary_responses(
                    binding, body,
                    authorization=lambda: backend.selected_fence(label, epoch),
                    before_write=before_write,
                    limits=CANARY_STREAM_LIMITS,
                    deadline=deadline,
                    cancelled=cancelled,
                    inspect_media=True,
                    observe_media=broker.observe_media,
                ) as events:
                    yield events

            broker = CanaryBroker(
                root / "relay" / "provider.sock",
                CanaryBrokerConfig(
                    proof=proof,
                    worker_token=worker_token,
                    bound_model=model,
                    ledger=ledger,
                    run_id=run_id,
                    binding_hash=b_hash,
                    history_digest=history.digest,
                    upstream_stream=upstream_stream,
                    fenced_client_write=lambda fn: backend.canary_fenced_write(label, epoch, conn, binding, fn),
                    check_alive=owner.check_alive,
                ),
            )
            broker.start()
            owner.start_containers()
            rc, stdout_bytes, _stderr_bytes, cleanup_verified, _cleanup_error = owner.wait_opencode()
        finally:
            if broker is not None:
                broker.close()
            owner_rc = owner.close()
        result = _build_live_result(label, model, broker, (rc, stdout_bytes, cleanup_verified, owner_rc), root)
        if result.ok:
            ledger.mark_delivered(run_id)
        return result


@contextmanager
def _interrupt_signals():
    def _raise_interrupt(_signum, _frame):
        raise KeyboardInterrupt

    previous = {}
    for sig in (signal.SIGTERM, signal.SIGHUP):
        with suppress(OSError, ValueError):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, _raise_interrupt)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            with suppress(OSError, ValueError):
                signal.signal(sig, handler)


def main(argv: list[str], *, terminal: Terminal | None = None) -> int:
    term = terminal or StreamTerminal(sys.stdin, sys.stdout, sys.stderr)
    try:
        parsed = parse_canary_argv(argv)
    except ValueError:
        term.error(
            "usage: oc-sandbox openai canary [--model SLUG] [--reviewed-source SHA256] "
            "[--synthetic-check | --recover-unsettled]"
        )
        return 2
    try:
        with _interrupt_signals():
            if parsed.synthetic_check:
                return run_synthetic_check(term, requested_model=parsed.model)
            return run_canary(
                term,
                requested_model=parsed.model,
                reviewed_source=parsed.reviewed_source,
                recover_unsettled=parsed.recover_unsettled,
            )
    except KeyboardInterrupt:
        term.error("Interrupted.")
        return 130
