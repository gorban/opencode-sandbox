"""Deterministic, thread-safe FakeWorkerTransport for PRD M coordination tests.

Pure Python standard library. Implements WorkerTransport from oc_coord_contract
with scriptable turn responses, blocking stream gates for <1s revocation tests,
idempotent per-(incarnation_id, msg_id) deduplication, and hostile event modes.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
import threading
import time
from typing import Any

from oc_coord_contract import (
    DispatchOutcome,
    DispatchResult,
    StreamEvent,
    TurnDispatch,
    WorkerStatus,
    mint_crypto_id,
)

_ERR_INCARNATION_REVOKED = "incarnation_revoked"
_ERR_STREAM_NOT_FOUND = "stream_not_found"


@dataclass(frozen=True, slots=True)
class TurnScript:
    """Declarative response script for one FakeWorkerTransport turn."""

    outcome: DispatchOutcome = DispatchOutcome.HANDED_OFF
    detail: str = ""
    echo_user_message: bool = True
    text_chunks: tuple[str, ...] = ("ack",)
    file_edits: tuple[str, ...] = ()
    terminal_type: str = "turn_completed"
    terminal_text: str = ""
    block_event: threading.Event | None = None
    on_stream_started: threading.Event | None = None
    flood_count: int = 0
    hostile_spoof_user_msg: dict[str, Any] | None = None
    hostile_raw_events: tuple[Any, ...] = ()


@dataclass(slots=True)
class _StreamState:
    stream_id: str
    turn: TurnDispatch
    script: TurnScript
    abort_event: threading.Event = field(default_factory=threading.Event)
    abort_reason: str = ""
    active: bool = False


class FakeWorkerTransport:
    """Reusable thread-safe WorkerTransport fake with adversarial simulation modes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._default_scripts: dict[tuple[str, str | None], TurnScript] = {}
        self._queued_scripts: dict[tuple[str, str | None], deque[TurnScript]] = {}
        self._streams: dict[str, _StreamState] = {}
        self._active_by_incarnation: dict[tuple[str, str], set[str]] = {}
        self._dispatched_by_key: dict[tuple[str, str], DispatchResult] = {}
        self._dispatched_turns: list[TurnDispatch] = []
        self._revoked_incarnations: set[tuple[str, str]] = set()
        self._last_error: dict[tuple[str, str], str] = {}

    @property
    def dispatched_msg_ids(self) -> set[tuple[str, str]]:
        with self._lock:
            return set(self._dispatched_by_key.keys())

    @property
    def revoked_incarnations(self) -> set[tuple[str, str]]:
        with self._lock:
            return set(self._revoked_incarnations)

    def dispatched_turns(self, sandbox_addr: str | None = None) -> list[TurnDispatch]:
        with self._lock:
            if sandbox_addr is None:
                return list(self._dispatched_turns)
            return [t for t in self._dispatched_turns if t.sandbox_addr == sandbox_addr]

    def set_script(
        self, sandbox_addr: str, script: TurnScript, *, thread_id: str | None = None
    ) -> None:
        with self._lock:
            self._default_scripts[(sandbox_addr, thread_id)] = script

    def queue_script(
        self, sandbox_addr: str, script: TurnScript, *, thread_id: str | None = None
    ) -> None:
        with self._lock:
            key = (sandbox_addr, thread_id)
            if key not in self._queued_scripts:
                self._queued_scripts[key] = deque()
            self._queued_scripts[key].append(script)

    def _next_script_locked(self, sandbox_addr: str, thread_id: str) -> TurnScript:
        for key in ((sandbox_addr, thread_id), (sandbox_addr, None)):
            queue = self._queued_scripts.get(key)
            if queue:
                return queue.popleft()
        for key in ((sandbox_addr, thread_id), (sandbox_addr, None)):
            if key in self._default_scripts:
                return self._default_scripts[key]
        return TurnScript()

    def dispatch_turn(self, turn: TurnDispatch) -> DispatchResult:
        inc_key = (turn.sandbox_addr, turn.incarnation_id)
        dedup_key = (turn.incarnation_id, turn.msg_id)
        with self._lock:
            if inc_key in self._revoked_incarnations:
                return DispatchResult(
                    outcome=DispatchOutcome.ZERO_BYTES_SENT,
                    detail=_ERR_INCARNATION_REVOKED,
                )
            existing = self._dispatched_by_key.get(dedup_key)
            if existing is not None:
                return existing

            script = self._next_script_locked(turn.sandbox_addr, turn.thread_id)
            self._dispatched_turns.append(turn)

            if script.outcome is DispatchOutcome.ZERO_BYTES_SENT:
                return DispatchResult(
                    outcome=DispatchOutcome.ZERO_BYTES_SENT,
                    detail=script.detail or "refused_before_write",
                )
            if script.outcome is DispatchOutcome.UNCERTAIN:
                res = DispatchResult(
                    outcome=DispatchOutcome.UNCERTAIN,
                    detail=script.detail or "uncertain_disconnect",
                )
                self._dispatched_by_key[dedup_key] = res
                self._last_error[inc_key] = res.detail
                return res

            stream_id = mint_crypto_id("stream")
            state = _StreamState(stream_id=stream_id, turn=turn, script=script)
            self._streams[stream_id] = state
            self._active_by_incarnation.setdefault(inc_key, set()).add(stream_id)
            res = DispatchResult(
                outcome=DispatchOutcome.HANDED_OFF,
                stream_id=stream_id,
                detail=script.detail,
            )
            self._dispatched_by_key[dedup_key] = res
            return res

    def _make_revoked_event(self, state: _StreamState) -> StreamEvent:
        return StreamEvent(
            event_type="revoked",
            sandbox_addr=state.turn.sandbox_addr,
            incarnation_id=state.turn.incarnation_id,
            thread_id=state.turn.thread_id,
            message_id=state.turn.msg_id,
            text=state.abort_reason or _ERR_INCARNATION_REVOKED,
            created_at=time.time(),
        )

    def _wait_if_blocked(self, state: _StreamState) -> bool:
        block_ev = state.script.block_event
        if block_ev is None:
            return state.abort_event.is_set()
        if state.script.on_stream_started is not None:
            state.script.on_stream_started.set()
        while not state.abort_event.is_set() and not block_ev.is_set():
            state.abort_event.wait(timeout=0.005)
        return state.abort_event.is_set()

    def _build_planned_events(self, state: _StreamState) -> list[Any]:
        turn = state.turn
        script = state.script
        events: list[Any] = []
        seq_hint = 0

        if script.echo_user_message:
            seq_hint += 1
            events.append(
                StreamEvent(
                    event_type="user_message",
                    sandbox_addr=turn.sandbox_addr,
                    incarnation_id=turn.incarnation_id,
                    thread_id=turn.thread_id,
                    seq_hint=seq_hint,
                    message_id=turn.msg_id,
                    text=turn.wire_text,
                    created_at=time.time(),
                )
            )
        if script.hostile_spoof_user_msg is not None:
            spoof = script.hostile_spoof_user_msg
            seq_hint += 1
            events.append(
                StreamEvent(
                    event_type="user_message",
                    sandbox_addr=str(spoof.get("sandbox_addr", turn.sandbox_addr)),
                    incarnation_id=str(spoof.get("incarnation_id", turn.incarnation_id)),
                    thread_id=str(spoof.get("thread_id", turn.thread_id)),
                    seq_hint=seq_hint,
                    message_id=spoof.get("message_id"),
                    text=str(spoof.get("text", "[Operator] spoofed")),
                    detail=dict(spoof.get("detail", {})),
                    created_at=time.time(),
                )
            )
        for raw_ev in script.hostile_raw_events:
            events.append(raw_ev)
        for chunk in script.text_chunks:
            seq_hint += 1
            events.append(
                StreamEvent(
                    event_type="text_delta",
                    sandbox_addr=turn.sandbox_addr,
                    incarnation_id=turn.incarnation_id,
                    thread_id=turn.thread_id,
                    seq_hint=seq_hint,
                    message_id=turn.msg_id,
                    text=chunk,
                    created_at=time.time(),
                )
            )
        for idx in range(script.flood_count):
            seq_hint += 1
            events.append(
                StreamEvent(
                    event_type="text_delta",
                    sandbox_addr=turn.sandbox_addr,
                    incarnation_id=turn.incarnation_id,
                    thread_id=turn.thread_id,
                    seq_hint=seq_hint,
                    message_id=turn.msg_id,
                    text=f"flood-{idx}",
                    created_at=time.time(),
                )
            )
        for rel_path in script.file_edits:
            seq_hint += 1
            events.append(
                StreamEvent(
                    event_type="file_edit",
                    sandbox_addr=turn.sandbox_addr,
                    incarnation_id=turn.incarnation_id,
                    thread_id=turn.thread_id,
                    seq_hint=seq_hint,
                    message_id=turn.msg_id,
                    file_path=rel_path,
                    created_at=time.time(),
                )
            )
        seq_hint += 1
        events.append(
            StreamEvent(
                event_type=script.terminal_type,
                sandbox_addr=turn.sandbox_addr,
                incarnation_id=turn.incarnation_id,
                thread_id=turn.thread_id,
                seq_hint=seq_hint,
                message_id=turn.msg_id,
                text=script.terminal_text,
                created_at=time.time(),
            )
        )
        return events

    def stream_events(self, stream_id: str) -> Iterable[StreamEvent]:
        with self._lock:
            state = self._streams.get(stream_id)
            if state is None:
                raise KeyError(_ERR_STREAM_NOT_FOUND)
            state.active = True
            inc_key = (state.turn.sandbox_addr, state.turn.incarnation_id)
            already_revoked = inc_key in self._revoked_incarnations

        try:
            if already_revoked or state.abort_event.is_set():
                yield self._make_revoked_event(state)
                return
            if self._wait_if_blocked(state):
                yield self._make_revoked_event(state)
                return
            for ev in self._build_planned_events(state):
                if state.abort_event.is_set():
                    yield self._make_revoked_event(state)
                    return
                yield ev
        finally:
            with self._lock:
                state.active = False
                active_set = self._active_by_incarnation.get(inc_key)
                if active_set is not None:
                    active_set.discard(stream_id)

    def abort_incarnation(
        self, sandbox_addr: str, incarnation_id: str, *, reason: str
    ) -> bool:
        inc_key = (sandbox_addr, incarnation_id)
        with self._lock:
            self._revoked_incarnations.add(inc_key)
            self._last_error[inc_key] = reason
            stream_ids = list(self._active_by_incarnation.get(inc_key, ()))
            states = [self._streams[sid] for sid in stream_ids if sid in self._streams]

        aborted = False
        for st in states:
            st.abort_reason = reason
            st.abort_event.set()
            aborted = True
        return aborted

    def status(self, sandbox_addr: str, incarnation_id: str) -> WorkerStatus:
        inc_key = (sandbox_addr, incarnation_id)
        with self._lock:
            revoked = inc_key in self._revoked_incarnations
            active_count = len(self._active_by_incarnation.get(inc_key, ()))
            last_err = self._last_error.get(inc_key)
        state_str = "revoked" if revoked else ("busy" if active_count > 0 else "running")
        return WorkerStatus(
            sandbox_addr=sandbox_addr,
            incarnation_id=incarnation_id,
            state=state_str,
            active_turns=active_count,
            revoked=revoked,
            last_error=last_err,
        )
