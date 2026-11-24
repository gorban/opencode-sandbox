"""Attended foreground broker and CLI for the single-turn zero-tool ChatGPT canary."""

from contextlib import contextmanager, suppress
from dataclasses import dataclass
import hmac
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import sys
import tempfile
import threading
import time

from .canary_ledger import (
    CanaryLedger,
    CanaryLedgerError,
    HistorySnapshot,
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
from .canary_runtime import DetachedOwnerSession, OwnerLost, RuntimeFailure
from .cli import MODEL, Reason, RouteUnavailable, StreamTerminal, Terminal, report_failure
from .connection import ConnectionError
from .exposure import _INPUT_LIMIT, _OUTPUT_LIMIT, binding_digest
from .live import make_backend
from .profile_backend import ProfileBackend
from .responses import StreamLimits


_MODEL_SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
CANARY_STREAM_LIMITS = StreamLimits(
    max_json=1024 * 1024,
    max_stream=4 * 1024 * 1024,
    max_line=512 * 1024,
    max_events=1024,
    io_timeout=IDLE_SECONDS,
)


@dataclass(frozen=True)
class CanaryArgs:
    model: str | None
    synthetic_check: bool


def parse_canary_argv(argv: list[str]) -> CanaryArgs:
    """Strictly parse `canary [--model SLUG] [--synthetic-check]`."""
    model = None
    synthetic = False
    idx = 0
    while idx < len(argv):
        arg = argv[idx]
        if arg == "--synthetic-check" and not synthetic:
            synthetic = True
            idx += 1
        elif arg == "--model" and model is None and idx + 1 < len(argv):
            slug = argv[idx + 1]
            if not _MODEL_SLUG_RE.fullmatch(slug):
                raise ValueError("invalid model slug")
            model = slug
            idx += 2
        else:
            raise ValueError("unsupported canary arguments")
    return CanaryArgs(model=model, synthetic_check=synthetic)


def _send_all_bounded(sock: socket.socket, data: bytes, *, timeout: float = IDLE_SECONDS) -> int:
    sock.settimeout(timeout)
    sock.sendall(data)
    return len(data)


def _recv_exact_proof(conn: socket.socket, expected: bytes) -> bool:
    conn.settimeout(IDLE_SECONDS)
    buf = bytearray()
    while len(buf) < PROOF_SIZE:
        chunk = conn.recv(PROOF_SIZE - len(buf))
        if not chunk:
            return False
        buf.extend(chunk)
    return hmac.compare_digest(bytes(buf), expected)


class CanaryBroker:
    """Foreground UDS broker enforcing 0 tools and at most 1 upstream Responses send."""

    def __init__(
        self,
        sock_path: Path,
        *,
        proof: bytes,
        worker_token: str,
        bound_model: str,
        ledger: CanaryLedger,
        run_id: str,
        binding_hash: str,
        history_digest: str,
        upstream_stream,
        fenced_client_write,
        check_alive,
        port: int = PORT,
        after_reserve=None,
    ):
        self.sock_path = sock_path
        self.proof = proof
        self.worker_token = worker_token
        self.bound_model = bound_model
        self.ledger = ledger
        self.run_id = run_id
        self.binding_hash = binding_hash
        self.history_digest = history_digest
        self.upstream_stream = upstream_stream
        self.fenced_client_write = fenced_client_write
        self.check_alive = check_alive
        self.port = port
        self.after_reserve = after_reserve
        self._stop = threading.Event()
        self._admit_lock = threading.Lock()
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.models_requests = 0
        self.inference_admitted = False
        self.upstream_calls = 0
        self.stream_outcome: StreamOutcome | None = None
        self.ledger_outcome: str | None = None
        self.delivered_bytes = 0
        self.error: str | None = None

    def start(self) -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(self.sock_path))
        os.chmod(self.sock_path, 0o600)
        server.listen(4)
        server.settimeout(0.25)
        self._server = server
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._server is not None:
            with suppress(OSError):
                self._server.close()
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
            with control:
                self._handle_control(control)

    def _handle_control(self, control: socket.socket) -> None:
        try:
            if not _recv_exact_proof(control, self.proof):
                return
            client = receive_client(control, port=self.port)
        except (OSError, Refused):
            return
        with client:
            self._handle_client(client)

    def _handle_client(self, client: socket.socket) -> None:
        deadline = time.monotonic() + TOTAL_SECONDS
        try:
            req = parse_local_request(
                client, deadline, port=self.port, expected_token=self.worker_token,
            )
        except (OSError, Refused):
            with suppress(OSError):
                _send_all_bounded(client, REFUSAL_RESPONSE)
            return
        if req.kind == "models":
            self._serve_models(client)
            return
        self._serve_responses(client, req.body or b"", deadline)

    def _serve_models(self, client: socket.socket) -> None:
        with self._admit_lock:
            if self.models_requests >= MAX_MODELS_REQUESTS:
                with suppress(OSError):
                    _send_all_bounded(client, REFUSAL_RESPONSE)
                return
            self.models_requests += 1
        with suppress(OSError):
            _send_all_bounded(client, models_http_response(self.bound_model))

    def _reserve_before_write(self) -> None:
        self.check_alive()
        self.ledger.reserve(
            self.run_id, self.binding_hash, self.bound_model, self.history_digest,
        )
        self.ledger_outcome = "unsettled"
        if self.after_reserve is not None:
            self.after_reserve()

    def _serve_responses(self, client: socket.socket, body: bytes, deadline: float) -> None:
        try:
            canonical = validate_responses_request(body, bound_model=self.bound_model)
        except Refused:
            with suppress(OSError):
                _send_all_bounded(client, REFUSAL_RESPONSE)
            return
        with self._admit_lock:
            if self.inference_admitted:
                with suppress(OSError):
                    _send_all_bounded(client, REFUSAL_RESPONSE)
                return
            self.inference_admitted = True
        self._dispatch_single_turn(client, canonical, deadline)

    def _dispatch_single_turn(self, client: socket.socket, canonical: dict, deadline: float) -> None:
        try:
            self.check_alive()
            self.upstream_calls += 1
            with self.upstream_stream(
                canonical,
                before_write=self._reserve_before_write,
                deadline=deadline,
                cancelled=self._stop,
            ) as events:
                outcome = consume_upstream_stream(
                    events, bound_model=self.bound_model, check_alive=self.check_alive,
                )
            self.stream_outcome = outcome
            settled = self.ledger.settle(
                self.run_id,
                allow_delivery=outcome.allow_delivery,
                input_tokens=outcome.input_tokens,
                output_tokens=outcome.output_tokens,
            )
            self.ledger_outcome = settled
            if settled == "ok_settled":
                payload = ok_sse_http_response(
                    self.bound_model, outcome.input_tokens, outcome.output_tokens,
                )
                self._deliver_fenced(client, payload)
        except (CanaryLedgerError, CanaryUnsettledError, ConnectionError, OwnerLost, RouteUnavailable, OSError) as exc:
            self.error = str(exc)

    def _deliver_fenced(self, client: socket.socket, payload: bytes) -> None:
        def write_action():
            self.check_alive()
            return _send_all_bounded(client, payload)

        self.delivered_bytes = self.fenced_client_write(write_action)


def _format_disclosure(label: str, model: str, history: HistorySnapshot) -> str:
    prior_desc = (
        f"{len(history.present_files)} prior I4a record file(s) "
        f"({history.record_count} entries, {history.unsettled_count} unsettled, "
        f"prior exposure {history.reserved_input:,} input / {history.reserved_output:,} output tokens)"
        if history.present_files
        else "no prior I4a hold files"
    )
    total_in = history.reserved_input + _INPUT_LIMIT
    total_out = history.reserved_output + _OUTPUT_LIMIT
    return (
        f"Active registration: {label}. Bound model: {model}. "
        f"Prior workstation state (read-only, untouched): {prior_desc}. "
        f"This single-use zero-tool canary authorizes at most 1 request to OpenAI ('Reply with exactly: ok'). "
        f"OpenCode local limit.output=64 does not cap upstream because ChatGPT /v1/responses omits max_output_tokens; "
        f"published ceilings add up to {_INPUT_LIMIT:,} input and {_OUTPUT_LIMIT:,} output tokens "
        f"(combined exposure up to {total_in:,} input and {total_out:,} output tokens). "
        "OpenAI may use your ChatGPT plan or account credits with no verified hard spending cap. "
        "API-key fallback and all tools are disabled. Ctrl-C stops and cleans up."
    )


def _resolve_model(conn, binding, requested: str | None) -> str:
    models = conn.models(binding)
    target = requested or MODEL
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
) -> int:
    run_id = secrets.token_hex(16)
    worker_token = secrets.token_hex(32)
    b_hash = binding_digest(binding.profile, binding.generation, epoch)
    owner = owner_factory(model, worker_token)
    broker = None
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
            ) as events:
                yield events

        broker = CanaryBroker(
            root / "relay" / "provider.sock",
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
        )
        broker.start()
        owner.start_containers()
        rc, stdout_bytes, _stderr_bytes = owner.wait_opencode()
        if (broker.ledger_outcome == "ok_settled" and broker.delivered_bytes > 0
                and rc == 0 and verify_opencode_json_stdout(stdout_bytes)):
            ledger.mark_delivered(run_id)
            terminal.write(
                f"ChatGPT canary succeeded: exact 'ok' delivered and settled "
                f"({broker.stream_outcome.input_tokens} in / {broker.stream_outcome.output_tokens} out)."
            )
            return 0
        terminal.error(
            f"ChatGPT canary did not verify clean 'ok' delivery "
            f"(ledger={broker.ledger_outcome or 'none'}, opencode_rc={rc})."
        )
        return 1
    finally:
        if broker is not None:
            broker.close()
        owner.close()


def run_canary(
    terminal: Terminal,
    *,
    requested_model: str | None = None,
    backend_factory=None,
    owner_factory=DetachedOwnerSession,
) -> int:
    """Run the attended single-turn zero-tool ChatGPT canary."""
    if not terminal.attended():
        terminal.error("ChatGPT canary requires an attended foreground workstation terminal.")
        return 2
    factory = backend_factory or make_backend
    try:
        backend = factory()
        ledger = CanaryLedger(backend._state)
        with ledger.exclusive_run():
            history = ledger.preflight()
            label, epoch, conn, binding = backend.active_connection()
            model = _resolve_model(conn, binding, requested_model)
            terminal.write(_format_disclosure(label, model, history))
            if not terminal.confirm("Authorize this single zero-tool OpenCode canary request?"):
                terminal.error("Cancelled.")
                return 1
            _verify_live_identity(backend, label, epoch, binding)
            return _execute_canary_session(
                terminal=terminal, backend=backend, ledger=ledger,
                label=label, epoch=epoch, conn=conn, binding=binding,
                model=model, history=history, owner_factory=owner_factory,
            )
    except RouteUnavailable as error:
        return report_failure(terminal, error, operation="ChatGPT canary")
    except (CanaryLedgerError, ConnectionError, OwnerLost, RuntimeFailure) as error:
        terminal.error(f"ChatGPT canary refused: {error}")
        return 1


def run_synthetic_check(terminal: Terminal, *, requested_model: str | None = None) -> int:
    """Run the shipping canary placement against an in-process synthetic upstream (0 live calls)."""
    model = requested_model or MODEL
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    with tempfile.TemporaryDirectory(prefix="oc-canary-synth-", dir=home) as scratch:
        state_dir = Path(scratch)
        ledger = CanaryLedger(state_dir)
        history = ledger.preflight()
        run_id = secrets.token_hex(16)
        worker_token = secrets.token_hex(32)
        b_hash = binding_digest("a" * 43, "b" * 43, "c" * 43)
        owner = DetachedOwnerSession(model, worker_token)
        broker = None
        try:
            root, proof = owner.prepare()

            @contextmanager
            def fake_upstream(body, *, before_write, deadline, cancelled):
                before_write()
                resp_id = "resp_synth_1"
                yield (
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

            broker = CanaryBroker(
                root / "relay" / "provider.sock",
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
            )
            broker.start()
            owner.start_containers()
            rc, stdout_bytes, _stderr_bytes = owner.wait_opencode()
            if (broker.upstream_calls == 1 and broker.ledger_outcome == "ok_settled"
                    and broker.delivered_bytes > 0 and rc == 0 and verify_opencode_json_stdout(stdout_bytes)):
                ledger.mark_delivered(run_id)
                terminal.write(f"Synthetic ChatGPT canary check passed for model {model} (1 synthetic POST, exact 'ok').")
                return 0
            terminal.error(
                f"Synthetic ChatGPT canary check failed "
                f"(posts={broker.upstream_calls}, ledger={broker.ledger_outcome}, rc={rc})."
            )
            return 1
        except (CanaryLedgerError, OwnerLost, RuntimeFailure, OSError) as error:
            terminal.error(f"Synthetic ChatGPT canary check failed: {error}")
            return 1
        finally:
            if broker is not None:
                broker.close()
            owner.close()


def main(argv: list[str], *, terminal: Terminal | None = None) -> int:
    term = terminal or StreamTerminal(sys.stdin, sys.stdout, sys.stderr)
    try:
        parsed = parse_canary_argv(argv)
    except ValueError:
        term.error("usage: oc-sandbox openai canary [--model SLUG] [--synthetic-check]")
        return 2
    if parsed.synthetic_check:
        return run_synthetic_check(term, requested_model=parsed.model)
    return run_canary(term, requested_model=parsed.model)
