"""Operator-only bounded terminal replay store and reader for PRD M3.3.

Pure Python standard library plus read-only imports from docs/prds/spikes/m.
Enforces strict CoordRole.OPERATOR-only admission, pre/post session and live
authority fencing, per-sandbox incarnation and monotonic stream_epoch/frame_seq
fencing, bounded ring eviction, post-pack stream-identity recheck, and hard
UTF-8 JSON response-byte budgets.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
import sys
import threading

_TERMINAL_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _TERMINAL_DIR.parent
for _import_dir in (str(_TERMINAL_DIR), str(_SPIKE_M_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_coord_contract import (  # noqa: E402
    CoordAuthError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    IncarnationMismatchError,
    PrincipalCtx,
    RevokedError,
)
from oc_terminal_contract import (  # noqa: E402
    DEFAULT_MAX_RING_BYTES,
    DEFAULT_MAX_RING_FRAMES,
    DEFAULT_PAGE_LIMIT,
    ERR_BUDGET_ENVELOPE,
    ERR_BUDGET_ITEM,
    MAX_FEED_CHUNK_BYTES,
    MAX_FRAME_TEXT_BYTES,
    MAX_INT64,
    MAX_PAGE_LIMIT,
    MAX_RESPONSE_BYTES,
    MAX_RETIRED_INCARNATIONS,
    MAX_RING_BYTES,
    MAX_RING_FRAMES,
    MAX_TRACKED_SANDBOXES,
    MIN_RESPONSE_BYTES,
    TERMINAL_OBSERVE_SCHEMA_VERSION,
    ReadSessionEcho,
    SanitizerMode,
    SanitizerStats,
    TerminalReplayFrame,
    TerminalReplayPage,
    compute_replay_scope_hash,
    encode_replay_cursor,
    parse_replay_cursor_fields,
    parse_terminal_target,
    serialize_terminal_bytes,
    validate_finite_timestamp,
    validate_sanitizer_mode,
    validate_strict_int_range,
    validate_terminal_id,
    validate_terminal_token,
    verify_replay_cursor_scope,
)
from oc_terminal_sanitizer import (  # noqa: E402
    SGR_RESET,
    TerminalOutputSanitizer,
    back_up_mid_sgr,
    diff_sanitizer_stats,
    sgr_is_open,
    truncate_sanitized_text_utf8,
    wrap_self_contained_sgr_frame,
)

ERR_CALLER_TYPE = "caller must be PrincipalCtx"
ERR_OPERATOR_REQUIRED = "operator_role_required"
ERR_OPERATOR_UNBOUND = "operator_principal_must_not_bind_sandbox"
ERR_SESSION_PAIR_REQUIRED = "read_session_pair_required"
ERR_SESSION_VALIDATOR_UNCONFIGURED = "read_session_validator_unconfigured"
ERR_SESSION_REQUIRED = "read_session_required"
ERR_SESSION_RETIRED = "read_session_retired"
ERR_AUTHORITY_REVOKED = "read_authority_revoked"
ERR_MAX_SANDBOXES = "max_tracked_sandboxes_exceeded"
ERR_MAX_RETIRED = "max_retired_incarnations_exceeded"
ERR_RETIRED_REUSED = "retired_incarnation_reused"
ERR_STALE_INCARNATION = "stale_incarnation_id"
ERR_STREAM_NOT_REGISTERED = "terminal_stream_not_registered"
ERR_STREAM_NOT_FOUND = "terminal_stream_not_found"
ERR_STREAM_CLOSED = "terminal_stream_closed"
ERR_STALE_EPOCH = "stale_stream_epoch"
ERR_UNREGISTERED_EPOCH = "unregistered_stream_epoch"
ERR_NON_MONOTONIC_SEQ = "non_monotonic_frame_seq"
ERR_CLOSE_PAIR_REQUIRED = "close_flush_frame_pair_required"

_K_UTF8 = "utf-8"
_L_INCARNATION_ID = "incarnation_id"
_L_STREAM_EPOCH = "stream_epoch"
_L_CAPTURED_AT = "captured_at"
_L_READ_SESSION_ID = "read_session_id"
_L_SESSION_GENERATION = "session_generation"


@dataclass(slots=True)
class _StreamState:
    stream_epoch: int
    mode: SanitizerMode
    sanitizer: TerminalOutputSanitizer
    ring: deque[TerminalReplayFrame] = field(default_factory=deque)
    ring_bytes: int = 0
    last_frame_seq: int = 0
    evicted_frame_count: int = 0
    last_evicted_seq: int = 0
    closed: bool = False


@dataclass(slots=True)
class _SandboxState:
    active_incarnation_id: str
    retired_incarnations: set[str] = field(default_factory=set)
    streams: dict[str, _StreamState] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _StreamSnapshot:
    sandbox_addr: str
    incarnation_id: str
    terminal_id: str
    stream_epoch: int
    mode: SanitizerMode
    stream_closed: bool
    ring_frames_retained: int
    ring_bytes_retained: int
    evicted_frame_count: int
    frames_evicted_before_page: bool
    stream_stats: SanitizerStats
    candidates: tuple[TerminalReplayFrame, ...]


@dataclass(frozen=True, slots=True)
class _FramePayload:
    sandbox_addr: str
    incarnation_id: str
    terminal_id: str
    stream_epoch: int
    frame_seq: int
    captured_at: float
    wrapped_text: str
    raw_input_bytes: int
    frame_stats: SanitizerStats


def authorize_operator_caller(caller: object) -> PrincipalCtx:
    """Enforce strict CoordRole.OPERATOR-only admission before any stream lookup."""
    if not isinstance(caller, PrincipalCtx):
        raise CoordValidationError(ERR_CALLER_TYPE)
    if caller.role is not CoordRole.OPERATOR:
        raise CoordAuthError(ERR_OPERATOR_REQUIRED)
    if caller.sandbox_addr is not None or caller.incarnation_id is not None:
        raise CoordAuthError(ERR_OPERATOR_UNBOUND)
    return caller


def _validate_optional_callback(cb: object, label: str) -> None:
    if cb is not None and not callable(cb):
        raise CoordValidationError(f"{label} must be callable or None")


def _make_page(
    snapshot: _StreamSnapshot,
    *,
    frames: tuple[TerminalReplayFrame, ...],
    has_more: bool,
    next_cursor: str | None,
    read_session: ReadSessionEcho | None,
) -> TerminalReplayPage:
    return TerminalReplayPage(
        schema_version=TERMINAL_OBSERVE_SCHEMA_VERSION,
        read_only=True,
        untrusted_content=True,
        sandbox_addr=snapshot.sandbox_addr,
        incarnation_id=snapshot.incarnation_id,
        terminal_id=snapshot.terminal_id,
        stream_epoch=snapshot.stream_epoch,
        sanitizer_mode=snapshot.mode.value,
        stream_closed=snapshot.stream_closed,
        ring_frames_retained=snapshot.ring_frames_retained,
        ring_bytes_retained=snapshot.ring_bytes_retained,
        evicted_frame_count=snapshot.evicted_frame_count,
        frames_evicted_before_page=snapshot.frames_evicted_before_page,
        stream_stats=snapshot.stream_stats,
        frames=frames,
        has_more=has_more,
        next_cursor=next_cursor,
        read_session=read_session,
    )


def _with_truncated_text(
    frame: TerminalReplayFrame, new_text: str
) -> TerminalReplayFrame:
    return TerminalReplayFrame(
        sandbox_addr=frame.sandbox_addr,
        incarnation_id=frame.incarnation_id,
        terminal_id=frame.terminal_id,
        stream_epoch=frame.stream_epoch,
        frame_seq=frame.frame_seq,
        captured_at=frame.captured_at,
        text=new_text,
        text_bytes=len(new_text.encode(_K_UTF8)),
        text_truncated=True,
        original_sanitized_bytes=frame.original_sanitized_bytes,
        raw_input_bytes=frame.raw_input_bytes,
        frame_stats=frame.frame_stats,
        untrusted_content=True,
    )


def _fit_first_frame_in_budget(
    snapshot: _StreamSnapshot,
    *,
    first_frame: TerminalReplayFrame,
    first_has_more: bool,
    first_cursor: str | None,
    max_response_bytes: int,
    read_session: ReadSessionEcho | None,
) -> TerminalReplayPage:
    empty_frame = _with_truncated_text(first_frame, "")
    empty_page = _make_page(
        snapshot,
        frames=(empty_frame,),
        has_more=first_has_more,
        next_cursor=first_cursor,
        read_session=read_session,
    )
    if len(serialize_terminal_bytes(empty_page)) > max_response_bytes:
        raise CoordValidationError(ERR_BUDGET_ITEM)

    mode = snapshot.mode
    source = first_frame.text
    lo = 0
    hi = len(source) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        prefix = back_up_mid_sgr(source[:mid], mode)
        probe = (
            f"{prefix}{SGR_RESET}"
            if (mode is SanitizerMode.SAFE_SGR and "\x1b[" in prefix)
            else prefix
        )
        trial_page = _make_page(
            snapshot,
            frames=(_with_truncated_text(first_frame, probe),),
            has_more=first_has_more,
            next_cursor=first_cursor,
            read_session=read_session,
        )
        if len(serialize_terminal_bytes(trial_page)) <= max_response_bytes:
            lo = mid
        else:
            hi = mid - 1

    best_prefix = back_up_mid_sgr(source[:lo], mode)
    final_text = (
        f"{best_prefix}{SGR_RESET}"
        if (mode is SanitizerMode.SAFE_SGR and sgr_is_open(best_prefix))
        else best_prefix
    )
    return _make_page(
        snapshot,
        frames=(_with_truncated_text(first_frame, final_text),),
        has_more=first_has_more,
        next_cursor=first_cursor,
        read_session=read_session,
    )


def _build_bounded_replay_page(
    snapshot: _StreamSnapshot,
    *,
    scope_hash: str,
    limit: int,
    max_response_bytes: int,
    read_session: ReadSessionEcho | None,
) -> TerminalReplayPage:
    candidates = snapshot.candidates
    first_has_more = len(candidates) > 1
    first_cursor = (
        encode_replay_cursor(
            scope_hash=scope_hash,
            incarnation_id=snapshot.incarnation_id,
            stream_epoch=snapshot.stream_epoch,
            frame_seq=candidates[0].frame_seq,
        )
        if first_has_more
        else None
    )
    envelope_probe = _make_page(
        snapshot,
        frames=(),
        has_more=first_has_more,
        next_cursor=first_cursor,
        read_session=read_session,
    )
    if len(serialize_terminal_bytes(envelope_probe)) > max_response_bytes:
        raise CoordValidationError(ERR_BUDGET_ENVELOPE)
    if not candidates:
        return envelope_probe

    first_frame = candidates[0]
    first_page = _make_page(
        snapshot,
        frames=(first_frame,),
        has_more=first_has_more,
        next_cursor=first_cursor,
        read_session=read_session,
    )
    if len(serialize_terminal_bytes(first_page)) > max_response_bytes:
        return _fit_first_frame_in_budget(
            snapshot,
            first_frame=first_frame,
            first_has_more=first_has_more,
            first_cursor=first_cursor,
            max_response_bytes=max_response_bytes,
            read_session=read_session,
        )

    admitted: tuple[TerminalReplayFrame, ...] = (first_frame,)
    best_page = first_page
    max_items = min(limit, len(candidates))
    for idx in range(1, max_items):
        trial_frames = (*admitted, candidates[idx])
        trial_has_more = len(trial_frames) < len(candidates)
        trial_cursor = (
            encode_replay_cursor(
                scope_hash=scope_hash,
                incarnation_id=snapshot.incarnation_id,
                stream_epoch=snapshot.stream_epoch,
                frame_seq=trial_frames[-1].frame_seq,
            )
            if trial_has_more
            else None
        )
        trial_page = _make_page(
            snapshot,
            frames=trial_frames,
            has_more=trial_has_more,
            next_cursor=trial_cursor,
            read_session=read_session,
        )
        if len(serialize_terminal_bytes(trial_page)) > max_response_bytes:
            break
        admitted = trial_frames
        best_page = trial_page
    return best_page


class TerminalReplayStore:
    """Operator-only bounded in-memory terminal replay store and paginated reader."""

    def __init__(
        self,
        *,
        max_ring_frames: int = DEFAULT_MAX_RING_FRAMES,
        max_ring_bytes: int = DEFAULT_MAX_RING_BYTES,
        session_validator: Callable[[PrincipalCtx, str, int], bool] | None = None,
        live_authority_checker: Callable[[PrincipalCtx], bool] | None = None,
        on_after_snapshot_before_release: Callable[[], None] | None = None,
    ) -> None:
        self._max_ring_frames = validate_strict_int_range(
            max_ring_frames, "max_ring_frames", 1, MAX_RING_FRAMES
        )
        self._max_ring_bytes = validate_strict_int_range(
            max_ring_bytes, "max_ring_bytes", MAX_FRAME_TEXT_BYTES, MAX_RING_BYTES
        )
        _validate_optional_callback(session_validator, "session_validator")
        _validate_optional_callback(live_authority_checker, "live_authority_checker")
        _validate_optional_callback(
            on_after_snapshot_before_release, "on_after_snapshot_before_release"
        )
        self._session_validator = session_validator
        self._live_authority_checker = live_authority_checker
        self._on_after_snapshot_before_release = on_after_snapshot_before_release
        self._lock = threading.RLock()
        self._sandboxes: dict[str, _SandboxState] = {}

    def _new_stream_state(self, stream_epoch: int, mode: SanitizerMode) -> _StreamState:
        return _StreamState(
            stream_epoch=stream_epoch,
            mode=mode,
            sanitizer=TerminalOutputSanitizer(mode=mode),
        )

    def register_stream(
        self,
        *,
        target: str,
        incarnation_id: str,
        terminal_id: str,
        stream_epoch: int = 1,
        mode: SanitizerMode = SanitizerMode.PLAIN,
    ) -> None:
        """Register or rotate a confined read-only terminal replay stream."""
        addr = parse_terminal_target(target).canonical
        inc = validate_terminal_token(incarnation_id, _L_INCARNATION_ID)
        tid = validate_terminal_id(terminal_id)
        ep = validate_strict_int_range(stream_epoch, _L_STREAM_EPOCH, 1, MAX_INT64)
        clean_mode = validate_sanitizer_mode(mode)

        with self._lock:
            sb = self._sandboxes.get(addr)
            if sb is None:
                if len(self._sandboxes) >= MAX_TRACKED_SANDBOXES:
                    raise CoordPolicyError(ERR_MAX_SANDBOXES)
                sb = _SandboxState(active_incarnation_id=inc)
                sb.streams[tid] = self._new_stream_state(ep, clean_mode)
                self._sandboxes[addr] = sb
                return
            if inc in sb.retired_incarnations:
                raise IncarnationMismatchError(ERR_RETIRED_REUSED)
            if inc != sb.active_incarnation_id:
                if len(sb.retired_incarnations) >= MAX_RETIRED_INCARNATIONS:
                    raise CoordPolicyError(ERR_MAX_RETIRED)
                sb.retired_incarnations.add(sb.active_incarnation_id)
                sb.active_incarnation_id = inc
                sb.streams.clear()
                sb.streams[tid] = self._new_stream_state(ep, clean_mode)
                return
            existing = sb.streams.get(tid)
            if existing is not None and ep <= existing.stream_epoch:
                raise CoordPolicyError(ERR_STALE_EPOCH)
            sb.streams[tid] = self._new_stream_state(ep, clean_mode)

    def _lookup_registered_stream_locked(
        self, addr: str, inc: str, tid: str
    ) -> tuple[_SandboxState, _StreamState]:
        sb = self._sandboxes.get(addr)
        if sb is None:
            raise CoordPolicyError(ERR_STREAM_NOT_REGISTERED)
        if inc != sb.active_incarnation_id:
            raise IncarnationMismatchError(ERR_STALE_INCARNATION)
        stream = sb.streams.get(tid)
        if stream is None:
            raise CoordPolicyError(ERR_STREAM_NOT_REGISTERED)
        return sb, stream

    def rotate_stream_epoch(
        self,
        *,
        target: str,
        incarnation_id: str,
        terminal_id: str,
        new_stream_epoch: int,
        mode: SanitizerMode | None = None,
    ) -> None:
        """Advance an active (or closed) terminal stream to a strictly higher epoch."""
        addr = parse_terminal_target(target).canonical
        inc = validate_terminal_token(incarnation_id, _L_INCARNATION_ID)
        tid = validate_terminal_id(terminal_id)
        new_ep = validate_strict_int_range(new_stream_epoch, "new_stream_epoch", 1, MAX_INT64)
        clean_mode = validate_sanitizer_mode(mode) if mode is not None else None

        with self._lock:
            sb, stream = self._lookup_registered_stream_locked(addr, inc, tid)
            if new_ep <= stream.stream_epoch:
                raise CoordPolicyError(ERR_STALE_EPOCH)
            chosen_mode = stream.mode if clean_mode is None else clean_mode
            sb.streams[tid] = self._new_stream_state(new_ep, chosen_mode)

    def _store_sanitized_frame(
        self, stream: _StreamState, payload: _FramePayload
    ) -> TerminalReplayFrame:
        full_bytes = len(payload.wrapped_text.encode(_K_UTF8))
        text, text_bytes, truncated = truncate_sanitized_text_utf8(
            payload.wrapped_text, MAX_FRAME_TEXT_BYTES, mode=stream.mode
        )
        frame = TerminalReplayFrame(
            sandbox_addr=payload.sandbox_addr,
            incarnation_id=payload.incarnation_id,
            terminal_id=payload.terminal_id,
            stream_epoch=payload.stream_epoch,
            frame_seq=payload.frame_seq,
            captured_at=payload.captured_at,
            text=text,
            text_bytes=text_bytes,
            text_truncated=truncated,
            original_sanitized_bytes=full_bytes,
            raw_input_bytes=payload.raw_input_bytes,
            frame_stats=payload.frame_stats,
            untrusted_content=True,
        )
        stream.last_frame_seq = payload.frame_seq
        stream.ring.append(frame)
        stream.ring_bytes += text_bytes
        while (
            len(stream.ring) > self._max_ring_frames
            or stream.ring_bytes > self._max_ring_bytes
        ):
            evicted = stream.ring.popleft()
            stream.ring_bytes -= evicted.text_bytes
            stream.evicted_frame_count += 1
            stream.last_evicted_seq = evicted.frame_seq
        return frame

    def _check_open_epoch_locked(self, stream: _StreamState, ep: int) -> None:
        if stream.closed:
            raise RevokedError(ERR_STREAM_CLOSED)
        if ep < stream.stream_epoch:
            raise CoordPolicyError(ERR_STALE_EPOCH)
        if ep > stream.stream_epoch:
            raise CoordPolicyError(ERR_UNREGISTERED_EPOCH)

    def close_stream(
        self,
        *,
        target: str,
        incarnation_id: str,
        terminal_id: str,
        stream_epoch: int,
        flush_frame_seq: int | None = None,
        captured_at: float | None = None,
    ) -> TerminalReplayFrame | None:
        """Flush and close an open terminal stream with strict epoch and pre-flush fencing."""
        addr = parse_terminal_target(target).canonical
        inc = validate_terminal_token(incarnation_id, _L_INCARNATION_ID)
        tid = validate_terminal_id(terminal_id)
        ep = validate_strict_int_range(stream_epoch, _L_STREAM_EPOCH, 1, MAX_INT64)
        if (flush_frame_seq is None) != (captured_at is None):
            raise CoordValidationError(ERR_CLOSE_PAIR_REQUIRED)
        flush_seq = (
            validate_strict_int_range(flush_frame_seq, "flush_frame_seq", 1, MAX_INT64)
            if flush_frame_seq is not None
            else None
        )
        flush_ts = (
            validate_finite_timestamp(captured_at, _L_CAPTURED_AT)
            if captured_at is not None
            else None
        )

        with self._lock:
            _, stream = self._lookup_registered_stream_locked(addr, inc, tid)
            self._check_open_epoch_locked(stream, ep)
            if flush_seq is not None and flush_seq <= stream.last_frame_seq:
                raise CoordPolicyError(ERR_NON_MONOTONIC_SEQ)

            before = stream.sanitizer.stats
            prefix_sgr = stream.sanitizer.active_sgr_seq
            flushed = stream.sanitizer.flush()
            after = stream.sanitizer.stats
            sgr_open_end = bool(stream.sanitizer.active_sgr_seq)
            stream.closed = True
            if flush_seq is None or flush_ts is None:
                return None
            wrapped = wrap_self_contained_sgr_frame(
                flushed, prefix_sgr, sgr_open_end, mode=stream.mode
            )
            return self._store_sanitized_frame(
                stream,
                _FramePayload(
                    sandbox_addr=addr,
                    incarnation_id=inc,
                    terminal_id=tid,
                    stream_epoch=ep,
                    frame_seq=flush_seq,
                    captured_at=flush_ts,
                    wrapped_text=wrapped,
                    raw_input_bytes=0,
                    frame_stats=diff_sanitizer_stats(before, after),
                ),
            )

    def append_chunk(
        self,
        *,
        target: str,
        incarnation_id: str,
        terminal_id: str,
        stream_epoch: int,
        frame_seq: int,
        raw_bytes: bytes,
        captured_at: float,
    ) -> TerminalReplayFrame:
        """Sanitize and append one raw PTY output chunk with full provenance fencing."""
        addr = parse_terminal_target(target).canonical
        inc = validate_terminal_token(incarnation_id, _L_INCARNATION_ID)
        tid = validate_terminal_id(terminal_id)
        ep = validate_strict_int_range(stream_epoch, _L_STREAM_EPOCH, 1, MAX_INT64)
        seq = validate_strict_int_range(frame_seq, "frame_seq", 1, MAX_INT64)
        ts = validate_finite_timestamp(captured_at, _L_CAPTURED_AT)
        if not isinstance(raw_bytes, bytes) or len(raw_bytes) > MAX_FEED_CHUNK_BYTES:
            raise CoordValidationError("raw_bytes must be bounded bytes")

        with self._lock:
            _, stream = self._lookup_registered_stream_locked(addr, inc, tid)
            self._check_open_epoch_locked(stream, ep)
            if seq <= stream.last_frame_seq:
                raise CoordPolicyError(ERR_NON_MONOTONIC_SEQ)

            before = stream.sanitizer.stats
            prefix_sgr = stream.sanitizer.active_sgr_seq
            clean_full = stream.sanitizer.feed(raw_bytes)
            after = stream.sanitizer.stats
            sgr_open_end = bool(stream.sanitizer.active_sgr_seq)
            wrapped = wrap_self_contained_sgr_frame(
                clean_full, prefix_sgr, sgr_open_end, mode=stream.mode
            )
            return self._store_sanitized_frame(
                stream,
                _FramePayload(
                    sandbox_addr=addr,
                    incarnation_id=inc,
                    terminal_id=tid,
                    stream_epoch=ep,
                    frame_seq=seq,
                    captured_at=ts,
                    wrapped_text=wrapped,
                    raw_input_bytes=len(raw_bytes),
                    frame_stats=diff_sanitizer_stats(before, after),
                ),
            )

    def _validate_session_echo(
        self, read_session_id: str | None, session_generation: int | None
    ) -> ReadSessionEcho | None:
        if (read_session_id is None) != (session_generation is None):
            raise CoordValidationError(ERR_SESSION_PAIR_REQUIRED)
        if read_session_id is None or session_generation is None:
            if self._session_validator is not None:
                raise CoordAuthError(ERR_SESSION_REQUIRED)
            return None
        clean_sid = validate_terminal_token(read_session_id, _L_READ_SESSION_ID)
        clean_gen = validate_strict_int_range(
            session_generation, _L_SESSION_GENERATION, 1, MAX_INT64
        )
        if self._session_validator is None:
            raise CoordPolicyError(ERR_SESSION_VALIDATOR_UNCONFIGURED)
        return ReadSessionEcho(read_session_id=clean_sid, session_generation=clean_gen)

    def _run_authority_fences(
        self, caller: PrincipalCtx, session_echo: ReadSessionEcho | None
    ) -> None:
        if self._session_validator is not None and session_echo is not None:
            try:
                ok = self._session_validator(
                    caller, session_echo.read_session_id, session_echo.session_generation
                )
            except Exception as exc:
                raise RevokedError(ERR_SESSION_RETIRED) from exc
            if ok is not True:
                raise RevokedError(ERR_SESSION_RETIRED)
        if self._live_authority_checker is not None:
            try:
                live_ok = self._live_authority_checker(caller)
            except Exception as exc:
                raise RevokedError(ERR_AUTHORITY_REVOKED) from exc
            if live_ok is not True:
                raise RevokedError(ERR_AUTHORITY_REVOKED)

    def _snapshot_stream_locked(
        self,
        *,
        addr: str,
        tid: str,
        req_inc: str | None,
        req_ep: int | None,
        parsed_cursor: tuple[str, str, str, int, int] | None,
    ) -> tuple[_StreamSnapshot, str, bool]:
        sb = self._sandboxes.get(addr)
        if sb is None:
            raise CoordPolicyError(ERR_STREAM_NOT_FOUND)
        if req_inc is not None and req_inc != sb.active_incarnation_id:
            raise IncarnationMismatchError(ERR_STALE_INCARNATION)
        stream = sb.streams.get(tid)
        if stream is None:
            raise CoordPolicyError(ERR_STREAM_NOT_FOUND)
        if req_ep is not None and req_ep != stream.stream_epoch:
            raise CoordPolicyError(ERR_STALE_EPOCH)

        applied_inc = sb.active_incarnation_id
        applied_ep = stream.stream_epoch
        scope_hash = compute_replay_scope_hash(
            target=addr,
            terminal_id=tid,
            incarnation_id=applied_inc,
            stream_epoch=applied_ep,
        )
        after_seq = verify_replay_cursor_scope(
            parsed_cursor,
            expected_scope_hash=scope_hash,
            expected_incarnation_id=applied_inc,
            expected_stream_epoch=applied_ep,
        )
        evicted_before = (
            (stream.last_evicted_seq > 0)
            if after_seq is None
            else (stream.last_evicted_seq > after_seq)
        )
        candidates = tuple(
            f for f in stream.ring if after_seq is None or f.frame_seq > after_seq
        )
        snapshot = _StreamSnapshot(
            sandbox_addr=addr,
            incarnation_id=applied_inc,
            terminal_id=tid,
            stream_epoch=applied_ep,
            mode=stream.mode,
            stream_closed=stream.closed,
            ring_frames_retained=len(stream.ring),
            ring_bytes_retained=stream.ring_bytes,
            evicted_frame_count=stream.evicted_frame_count,
            frames_evicted_before_page=evicted_before,
            stream_stats=stream.sanitizer.stats,
            candidates=candidates,
        )
        return snapshot, scope_hash, stream.closed

    def _verify_post_pack_stream_locked(
        self,
        *,
        addr: str,
        tid: str,
        applied_inc: str,
        applied_ep: int,
        captured_closed: bool,
    ) -> None:
        sb = self._sandboxes.get(addr)
        if sb is None:
            raise CoordPolicyError(ERR_STREAM_NOT_FOUND)
        if sb.active_incarnation_id != applied_inc:
            raise IncarnationMismatchError(ERR_STALE_INCARNATION)
        stream = sb.streams.get(tid)
        if stream is None:
            raise CoordPolicyError(ERR_STREAM_NOT_FOUND)
        if stream.stream_epoch != applied_ep:
            raise CoordPolicyError(ERR_STALE_EPOCH)
        if not captured_closed and stream.closed:
            raise RevokedError(ERR_STREAM_CLOSED)

    def read_replay_frames(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        terminal_id: str,
        incarnation_id: str | None = None,
        stream_epoch: int | None = None,
        after_cursor: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> TerminalReplayPage:
        """Read a bounded, operator-only, pre/post-fenced page of sanitized replay frames."""
        operator = authorize_operator_caller(caller)
        addr = parse_terminal_target(target).canonical
        tid = validate_terminal_id(terminal_id)
        req_inc = (
            validate_terminal_token(incarnation_id, _L_INCARNATION_ID)
            if incarnation_id is not None
            else None
        )
        req_ep = (
            validate_strict_int_range(stream_epoch, _L_STREAM_EPOCH, 1, MAX_INT64)
            if stream_epoch is not None
            else None
        )
        page_limit = validate_strict_int_range(limit, "limit", 1, MAX_PAGE_LIMIT)
        budget = validate_strict_int_range(
            max_response_bytes,
            "max_response_bytes",
            MIN_RESPONSE_BYTES,
            MAX_RESPONSE_BYTES,
        )
        parsed_cursor = parse_replay_cursor_fields(after_cursor)
        session_echo = self._validate_session_echo(read_session_id, session_generation)
        self._run_authority_fences(operator, session_echo)

        with self._lock:
            snapshot, scope_hash, captured_closed = self._snapshot_stream_locked(
                addr=addr,
                tid=tid,
                req_inc=req_inc,
                req_ep=req_ep,
                parsed_cursor=parsed_cursor,
            )

        if self._on_after_snapshot_before_release is not None:
            self._on_after_snapshot_before_release()
        page = _build_bounded_replay_page(
            snapshot,
            scope_hash=scope_hash,
            limit=page_limit,
            max_response_bytes=budget,
            read_session=session_echo,
        )
        self._run_authority_fences(operator, session_echo)
        with self._lock:
            self._verify_post_pack_stream_locked(
                addr=addr,
                tid=tid,
                applied_inc=snapshot.incarnation_id,
                applied_ep=snapshot.stream_epoch,
                captured_closed=captured_closed,
            )
        return page
