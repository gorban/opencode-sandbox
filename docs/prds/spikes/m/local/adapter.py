"""The operator-only CoordHub transport for one disposable local OpenCode job."""

from __future__ import annotations

from contextlib import ExitStack, suppress
from dataclasses import dataclass
import hashlib
import re
import socket
import threading
import time

from oc_address import parse_local_target, validate_thread_id
from oc_coord_contract import (
    CoordError, DispatchOutcome, DispatchResult, RoutingEdge, StreamEvent, TrustClass,
    TurnDispatch, WorkerStatus, canonicalize_body_text, mint_crypto_id, sha256_canonical_body,
    validate_opaque_token,
)

from broker import Broker
from client import (
    DispatchOutcome as RelayOutcome, OpenCode, ProbeError, RelayExchange, Subscription,
    TurnEvents, TurnPins, Wire, remaining,
)
from runtime import Job, JobRuntimeError


PROMPT = "prompt"
TERMINALS = frozenset({"turn_completed", "turn_error"})
RECEIPT_TIMEOUT = 6
REPLY_TIMEOUT = 8
SUBSCRIPTION_TIMEOUT = 40
SESSION_LIMIT = 2
STREAM_UNCONFIRMED = "native_stream_unconfirmed"
INVALID_PROMPT_FRAME = "invalid_prompt_frame"


class PauseBarrier:
    """One-shot trusted fixture hook. The hub never selects the pause from a turn."""

    def __init__(self):
        self.acknowledged = threading.Event()
        self.release = threading.Event()
        self.outcome: DispatchOutcome | None = None

    def wait(self, deadline: float) -> None:
        self.acknowledged.set()
        if not self.release.wait(remaining(deadline)):
            raise ProbeError("fixture pause expired")


@dataclass
class _Stream:
    id: str
    wire: Wire
    owner: ExitStack
    reading: bool = False


@dataclass
class _Reservation:
    client: OpenCode
    events: Subscription
    owner: ExitStack
    native: TurnPins
    msg_id: str | None = None
    dispatching: bool = False
    stream: _Stream | None = None

    def close(self) -> None:
        if self.stream is not None:
            with suppress(OSError):
                self.stream.wire.sock.shutdown(socket.SHUT_RDWR)
            self.stream.owner.close()
        with suppress(OSError):
            self.events.wire.sock.shutdown(socket.SHUT_RDWR)
        self.owner.close()


class LocalOpenCodeTransport:
    external_write_fence = True

    def __init__(self, job: Job, broker: Broker, *, sandbox_addr: str, thread_id: str,
                 pause: PauseBarrier | None = None):
        self.sandbox_addr = parse_local_target(sandbox_addr).canonical
        self.thread_id = validate_thread_id(thread_id)
        self.incarnation = validate_opaque_token(job.incarnation, "incarnation")
        self.generation = job.generation
        self._job = job
        self._broker = broker
        self._pause = pause
        self._run_label = job.run_label
        self._relay_id = job.recorded_ids.get("relay")
        self._provider_socket = job.provider_socket
        self._control_socket = job.control_socket
        if (type(self.generation) is not int or self.generation < 1
                or not re.fullmatch(r"[a-f0-9]{32}", self._run_label)
                or self._relay_id is None or not re.fullmatch(r"[a-f0-9]{64}", self._relay_id)
                or not self._owns_job()):
            raise ProbeError("local relay identity is unverified")
        self._require_live_job()
        job.assert_running()
        digest = hashlib.sha256(f"{self._run_label}:{self._relay_id}".encode("ascii")).hexdigest()
        self._owner_id = "local-relay:" + digest
        self._lock = threading.Lock()
        self._abort_lock = threading.Lock()
        self._edge_id: str | None = None
        self._reservation: _Reservation | None = None
        self._preparing = False
        self._closed_admission = False
        self._confirmed = False
        self._last_error: str | None = None
        self._sessions: set[str] = set()
        self._used_messages: set[str] = set()

    def _owns_job(self) -> bool:
        job = self._job
        actual = (job.incarnation, job.generation, job.run_label, job.ids.get("relay"),
                  job.recorded_ids.get("relay"), job.provider_socket, job.control_socket)
        expected = (self.incarnation, self.generation, self._run_label, self._relay_id,
                    self._relay_id, self._provider_socket, self._control_socket)
        return actual == expected and type(job.generation) is int

    def _job_is_live(self) -> bool:
        return self._owns_job() and self._job.terminal is False

    def _require_live_job(self) -> None:
        if not self._job_is_live():
            raise ProbeError("local job is unavailable")
        if not self._broker.is_bound_to(self._provider_socket):
            raise ProbeError("local broker binding is unverified")

    def _target_matches(self, addr: str, incarnation: str) -> bool:
        return (addr, incarnation) == (self.sandbox_addr, self.incarnation) and self._owns_job()

    def transport_owner_id(self, sandbox_addr: str, incarnation_id: str) -> str:
        if not self._target_matches(sandbox_addr, incarnation_id):
            raise ProbeError("unknown local relay owner")
        return self._owner_id

    def bind_grant(self, edge: RoutingEdge) -> None:
        pins = (edge.dst_addr, edge.grant_generation, edge.src_incarnation, edge.lease_request_id)
        if (pins != (self.sandbox_addr, self.generation, None, None)
                or type(edge.grant_generation) is not int or edge.active is not True
                or not edge.src_actor.startswith("operator:")
                or edge.allowed_threads != frozenset({self.thread_id})
                or edge.allowed_msg_kinds != frozenset({PROMPT})):
            raise ProbeError("invalid local operator grant")
        edge_id = validate_opaque_token(edge.edge_id, "edge")
        with self._lock:
            if self._edge_id is not None or self._closed_admission:
                raise ProbeError("local grant cannot be rebound")
            self._edge_id = edge_id

    def reserve(self) -> None:
        """Create and subscribe a fresh native session before binding a hub message."""
        with self._lock:
            if self._closed_admission or self._edge_id is None:
                raise ProbeError("local grant is unavailable")
            if self._preparing or self._reservation is not None or len(self._sessions) >= SESSION_LIMIT:
                raise ProbeError("local session slot is unavailable")
            self._preparing = True
        try:
            self._prepare_session()
        finally:
            with self._lock:
                self._preparing = False

    def _prepare_session(self) -> None:
        self._require_live_job()
        client = OpenCode(self._control_socket, self._job.password, sandbox_addr=self.sandbox_addr,
                          incarnation_id=self.incarnation, grant_generation=self.generation)
        session = client.create_session(time.monotonic() + REPLY_TIMEOUT)
        with self._lock:
            if self._closed_admission:
                raise ProbeError("local grant is unavailable")
            if session in self._sessions:
                self._closed_admission = True
                self._last_error = "native_session_reused"
                raise ProbeError("native session ID was reused")
            self._sessions.add(session)
        pins = TurnPins(self.sandbox_addr, self.incarnation, session, mint_crypto_id("msg"), self.generation)
        self._require_live_job()
        with ExitStack() as owner:
            events = owner.enter_context(client.events(time.monotonic() + SUBSCRIPTION_TIMEOUT))
            with self._lock:
                if self._closed_admission or not self._job_is_live():
                    raise ProbeError("local grant is unavailable")
                self._reservation = _Reservation(client, events, owner.pop_all(), pins)

    def bind(self, msg_id: str) -> None:
        msg_id = validate_opaque_token(msg_id, "message")
        with self._lock:
            reservation = self._reservation
            if (self._closed_admission or reservation is None or reservation.msg_id is not None
                    or msg_id in self._used_messages):
                raise ProbeError("local session cannot bind this message")
            reservation.msg_id = msg_id

    @staticmethod
    def _refusal(reason: str, *, permanent: bool = True) -> DispatchResult:
        return DispatchResult(DispatchOutcome.ZERO_BYTES_SENT, detail=reason, permanent=permanent)

    def _valid_turn_pins(self, turn: TurnDispatch) -> bool:
        return (
            (turn.sandbox_addr, turn.incarnation_id, turn.thread_id, turn.edge_id, turn.grant_generation)
            == (self.sandbox_addr, self.incarnation, self.thread_id, self._edge_id, self.generation)
            and type(turn.grant_generation) is int
            and self._edge_id is not None
            and turn.lease_request_id is None
            and turn.trust_class is TrustClass.OPERATOR_DIRECTIVE
            and turn.msg_kind == PROMPT
            and turn.artifact_refs == ()
            and self._job_is_live()
        )

    def _claim(self, turn: TurnDispatch, *, digest_valid: bool) -> _Reservation | DispatchResult:
        with self._lock:
            reservation = self._reservation
            if not self._valid_turn_pins(turn):
                return self._refusal("invalid_turn_pins")
            if self._closed_admission:
                return self._refusal("local_grant_unavailable")
            if turn.msg_id in self._used_messages:
                return self._refusal("native_message_already_used")
            if reservation is not None and reservation.dispatching:
                if not digest_valid:
                    return self._refusal(INVALID_PROMPT_FRAME)
                return self._refusal("local_session_busy", permanent=False)
            if reservation is None or reservation.msg_id != turn.msg_id:
                return self._refusal("no_bound_native_session")
            reservation.dispatching = True
            return reservation

    def dispatch_turn(self, turn: TurnDispatch) -> DispatchResult:
        if not isinstance(turn, TurnDispatch):
            return self._refusal("invalid_turn")
        text = self._verified_text(turn)
        reservation = self._claim(turn, digest_valid=text is not None)
        if isinstance(reservation, DispatchResult):
            return reservation
        try:
            if text is None:
                raise ProbeError("prompt digest mismatch")
            encoded = reservation.client.encode_prompt(reservation.native, text)
            stream_id = mint_crypto_id("stream")
        except (CoordError, ProbeError):
            self._detach(reservation)
            return self._refusal(INVALID_PROMPT_FRAME)
        return self._handoff(reservation, encoded, stream_id)

    @staticmethod
    def _verified_text(turn: TurnDispatch) -> str | None:
        try:
            text = canonicalize_body_text(turn.wire_text)
            return text if sha256_canonical_body(text) == turn.body_sha256 else None
        except CoordError:
            return None

    def _handoff(self, reservation: _Reservation, encoded: bytes, stream_id: str) -> DispatchResult:
        try:
            self._require_live_job()
        except ProbeError:
            self._detach(reservation)
            return self._refusal("local_job_unavailable")
        with self._lock:
            if self._closed_admission:
                return self._refusal("local_grant_unavailable")
            pause, self._pause = self._pause, None
        deadline = time.monotonic() + RECEIPT_TIMEOUT
        with ExitStack() as owner:
            relay_outcome, exchange = self._read_receipt(reservation, encoded, deadline, pause, owner)
            if relay_outcome is RelayOutcome.HANDED_OFF:
                with self._lock:
                    if reservation.msg_id is not None:
                        self._used_messages.add(reservation.msg_id)
                    if self._reservation is reservation and not self._closed_admission:
                        reservation.stream = _Stream(stream_id, exchange.wire, owner.pop_all())
                return DispatchResult(DispatchOutcome.HANDED_OFF, stream_id=stream_id)
        if relay_outcome is RelayOutcome.ZERO_BYTES_SENT:
            with self._lock:
                reservation.dispatching = False
            return self._refusal("relay_zero_bytes", permanent=False)
        self._detach(reservation, failure="relay_handoff_uncertain")
        return DispatchResult(DispatchOutcome.UNCERTAIN, detail="relay_handoff_uncertain")

    @staticmethod
    def _read_receipt(reservation: _Reservation, encoded: bytes, deadline: float,
                      pause: PauseBarrier | None, owner: ExitStack) -> tuple[RelayOutcome, RelayExchange | None]:
        try:
            exchange = owner.enter_context(reservation.client.prompt_exchange(encoded, deadline, pause=pause is not None))
            if pause is not None and exchange.pause_acknowledged:
                pause.wait(deadline)
            outcome = exchange.receipt()
        except Exception:
            outcome, exchange = RelayOutcome.UNCERTAIN, None
        if pause is not None:
            pause.outcome = DispatchOutcome(outcome.value)
        return outcome, exchange

    def _take_stream(self, stream_id: str) -> _Reservation | None:
        with self._lock:
            reservation = self._reservation
            if reservation is None or self._closed_admission:
                return None
            stream = reservation.stream
            if stream is None or stream.id != stream_id or stream.reading:
                return None
            stream.reading = True
            return reservation

    def _detach(self, reservation: _Reservation, *, failure: str | None = None) -> bool:
        with self._lock:
            if self._reservation is not reservation:
                return False
            self._reservation = None
            live = not self._closed_admission
            if failure is not None and live:
                self._closed_admission = True
                self._last_error = failure
        reservation.close()
        return live

    def _event(self, reservation: _Reservation, kind: str, text: str = "") -> StreamEvent:
        return StreamEvent(kind, self.sandbox_addr, self.incarnation, self.thread_id,
                           message_id=reservation.msg_id, text=text)

    def _native_events(self, reservation: _Reservation):
        match = TurnEvents(reservation.native)
        event_ids = set()
        for native in reservation.events:
            data = native.get("data")
            if not isinstance(data, dict) or data.get("sessionID") != reservation.native.thread_id:
                continue
            event_id = validate_opaque_token(native.get("id"), "event")
            if event_id in event_ids:
                continue
            event_ids.add(event_id)
            event = match.accept(native)
            if event is not None:
                yield self._event(reservation, event.kind, event.text)

    def stream_events(self, stream_id: str):
        reservation = self._take_stream(stream_id)
        if reservation is None:
            return
        try:
            yield from self._stream(reservation)
        except Exception:
            if self._detach(reservation, failure=STREAM_UNCONFIRMED):
                yield self._event(reservation, "turn_error", STREAM_UNCONFIRMED)
        finally:
            self._detach(reservation, failure=STREAM_UNCONFIRMED)

    def _stream(self, reservation: _Reservation):
        reservation.client.read_prompt_reply(reservation.stream.wire, reservation.native,
                                             time.monotonic() + REPLY_TIMEOUT)
        for event in self._native_events(reservation):
            if event.event_type in TERMINALS:
                if self._detach(reservation):
                    yield event
                return
            with self._lock:
                if self._reservation is not reservation or self._closed_admission:
                    return
            # The hub independently checks its delivery fence before recording.
            yield event
        raise ProbeError("native stream ended before its terminal event")

    def confirm_incarnation_terminal(self, sandbox_addr: str, incarnation_id: str, *,
                                     owner_id: str, reason: str) -> bool:
        if not self._target_matches(sandbox_addr, incarnation_id) or owner_id != self._owner_id:
            return False
        try:
            self._abort()
        except ProbeError:
            return False
        return True

    def abort_incarnation(self, sandbox_addr: str, incarnation_id: str, *, reason: str) -> bool:
        self.transport_owner_id(sandbox_addr, incarnation_id)
        return self._abort()

    def _abort(self) -> bool:
        with self._abort_lock:
            with self._lock:
                if self._confirmed:
                    return False
                self._closed_admission = True
                reservation, self._reservation = self._reservation, None
            try:
                self._install_terminal_fence()
            finally:
                if reservation is not None:
                    reservation.close()
            with self._lock:
                self._confirmed = True
            return bool(reservation and reservation.dispatching)

    def _install_terminal_fence(self) -> None:
        if not self._owns_job():
            raise ProbeError("local terminal binding unconfirmed")
        broker_closed = self._revoke_broker()
        try:
            self._job.revoke()
        except (JobRuntimeError, OSError):
            # Job sets terminal after a successful readback or verified exact relay stop.
            pass
        if not broker_closed or self._job.terminal is not True:
            raise ProbeError("local terminal fence unconfirmed")

    def _revoke_broker(self) -> bool:
        try:
            if not self._broker.is_bound_to(self._provider_socket, allow_revoked=True):
                return False
            self._broker.revoke()
        except Exception:
            return False
        return True

    def status(self, sandbox_addr: str, incarnation_id: str) -> WorkerStatus:
        self.transport_owner_id(sandbox_addr, incarnation_id)
        with self._lock:
            active = int(self._reservation is not None and self._reservation.dispatching)
            if self._confirmed:
                state = "revoked"
            elif self._closed_admission:
                state = "degraded"
            else:
                state = "busy" if active else "running"
            return WorkerStatus(self.sandbox_addr, self.incarnation, state, active,
                                self._confirmed, self._last_error)
