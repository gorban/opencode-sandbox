"""Thread-safe in-memory browser provenance store and operator-only read APIs for PRD M3.4.

Pure Python standard library plus read-only imports from docs/prds/spikes/m.
Zero live Chromium, zero CDP input/navigation writes, zero InputLease writes,
zero network or filesystem access.
"""

from __future__ import annotations

import base64
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
import math
import threading
import time
from typing import Any, cast

from oc_coord_contract import (
    CoordAuthError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    IncarnationMismatchError,
    PrincipalCtx,
    RevokedError,
)

from oc_browser_contract import (
    BROWSER_OBSERVE_SCHEMA_VERSION,
    BrowserFrameMeta,
    BrowserNavState,
    BrowserSurfaceAudit,
    BrowserSurfaceSnapshot,
    BrowserWallPage,
    BrowserWallTile,
    DEFAULT_MAX_FRAME_AGE_MS,
    DEFAULT_WALL_LIMIT,
    FrameAdmissionResult,
    FrameFreshness,
    MAX_FRAME_AGE_MS,
    MAX_QUARANTINE_HISTORY_PER_SURFACE,
    MAX_ROTATIONS_PER_SANDBOX,
    MAX_SNAPSHOT_RESPONSE_BYTES,
    MAX_SQLITE_INT64,
    MAX_SURFACES_PER_SANDBOX,
    MAX_TRACKED_SANDBOXES,
    MAX_WALL_LIMIT,
    MAX_WALL_RESPONSE_BYTES,
    MIN_FRAME_AGE_MS,
    MIN_RESPONSE_BYTES,
    NavClassification,
    OMIT_BUDGET_EXCEEDED,
    PairedBrowserFrame,
    ReadSessionEcho,
    STALE_AWAITING_FRAME,
    STALE_AWAITING_NAV,
    STALE_CAPTURE_GENERATION,
    STALE_CLOCK_REGRESSION,
    STALE_DISCONNECTED,
    STALE_FRAME_SUPERSEDED,
    STALE_NAV_GENERATION,
    STALE_NON_MONOTONIC_SEQ,
    STALE_SANDBOX_NOT_RUNNING,
    STALE_SUPERSEDED_INCARNATION,
    STALE_TTL_EXPIRED,
    STALE_UNKNOWN_NAV,
    SandboxViewMeta,
    SurfaceKey,
    VALID_SANDBOX_STATUSES,
    compute_wall_scope_hash,
    decode_wall_cursor,
    encode_wall_cursor,
    parse_sandbox_target,
    require_bool,
    serialize_json_bytes,
    validate_finite_nonneg_float,
    validate_positive_int,
    validate_token_strict,
)
from oc_browser_validate import (
    parse_and_classify_url,
    scrub_page_title,
    validate_frame_bytes,
)

_MAX_SAFE_AGE_SECONDS = 9_000_000_000_000_000.0
_STATUS_RUNNING = "running"
_STATUS_REVOKED = "revoked"

_ERR_CALLER_TYPE = "caller must be PrincipalCtx"
_ERR_OPERATOR_ROLE = "operator_role_required"
_ERR_OPERATOR_BOUND = "operator_principal_must_not_bind_sandbox"
_ERR_SESSION_PAIR = "read_session_pair_required"
_ERR_SESSION_REQUIRED = "read_session_required"
_ERR_SESSION_UNCONFIGURED = "read_session_validator_unconfigured"
_ERR_SESSION_RETIRED = "read_session_retired"
_ERR_AUTHORITY_REVOKED = "read_authority_revoked"
_ERR_SANDBOX_NOT_FOUND = "sandbox_not_found"
_ERR_BROWSER_DISABLED = "browser_service_not_enabled"
_ERR_SURFACE_NOT_FOUND = "surface_not_found"
_ERR_INCARNATION_REVOKED = "incarnation_revoked"
_ERR_CAP_GEN_EXHAUSTED = "capture_generation_exhausted"
_ERR_MAX_SANDBOXES = "max_sandboxes_exceeded"
_ERR_MAX_SURFACES = "max_surfaces_exceeded"
_ERR_MAX_ROTATIONS = "max_incarnation_rotations_exceeded"
_ERR_INVALID_CLOCK = "invalid_monotonic_clock"
_ERR_BUDGET_ENVELOPE = "response_budget_too_small_for_envelope"
_ERR_BUDGET_ITEM = "response_budget_too_small_for_item"
_ERR_WALL_CHANGED_AT_RELEASE = "wall_state_changed_during_release"
_ERR_NON_MONOTONIC_NAV = "non_monotonic_nav_generation"
_ERR_COMMITTED_FUTURE = "committed_at_in_future"
_ERR_COMMITTED_NON_MONO = "committed_at_non_monotonic"
_ERR_CAPTURED_FUTURE = "frame_captured_at_in_future"
_ERR_CAPTURED_NON_MONO = "frame_captured_at_non_monotonic"
_ERR_INVALID_BOUNDS = "invalid_bound_parameter"
_LABEL_INCARNATION_ID = "incarnation_id"
_LABEL_SURFACE_ID = "surface_id"
_LABEL_CAPTURE_GEN = "capture_generation"
_LABEL_NAV_GEN = "nav_generation"


@dataclass(frozen=True, slots=True)
class _QuarantinedFrameEvent:
    frame_seq: int
    nav_generation: int
    stale_reason: str
    observed_at: float


@dataclass(slots=True)
class _SurfaceRecord:
    surface_id: str
    current_nav: BrowserNavState | None = None
    last_nav_generation: int = 0
    last_frame_seq: int = 0
    last_nav_committed_at: float | None = None
    last_frame_captured_at: float | None = None
    paired_frame: PairedBrowserFrame | None = None
    paired_frame_bytes: bytes | None = None
    dropped_frame_counts: dict[str, int] = field(default_factory=dict)
    quarantine_recent: deque[_QuarantinedFrameEvent] = field(
        default_factory=lambda: deque(maxlen=MAX_QUARANTINE_HISTORY_PER_SURFACE)
    )


@dataclass(slots=True)
class _SandboxBrowserRecord:
    sandbox_addr: str
    worker_ref: str
    instance_name: str
    current_incarnation_id: str
    browser_enabled: bool
    status: str
    capture_generation: int = 1
    capture_generation_exhausted: bool = False
    superseded_incarnations: set[str] = field(default_factory=set)
    superseded_frame_drops: int = 0
    surfaces: dict[str, _SurfaceRecord] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _CapturedSurfaceState:
    sandbox_meta: SandboxViewMeta
    surface_key: SurfaceKey
    nav: BrowserNavState | None
    paired_frame: PairedBrowserFrame | None
    paired_frame_bytes: bytes | None
    freshness: FrameFreshness
    dropped_frame_counts: dict[str, int]
    observed_at: float
    capture_generation_exhausted: bool


def _bounded_display_age_ms(
    elapsed_s: float, *, max_frame_age_ms: int, expired: bool
) -> int:
    """Convert elapsed seconds to display milliseconds, clamped and saturated cleanly."""
    if not math.isfinite(elapsed_s) or elapsed_s >= _MAX_SAFE_AGE_SECONDS:
        return MAX_SQLITE_INT64
    elapsed_ms = elapsed_s * 1000.0
    if expired:
        return min(MAX_SQLITE_INT64, max(max_frame_age_ms + 1, math.ceil(elapsed_ms)))
    return min(max_frame_age_ms, max(0, math.floor(elapsed_ms)))


def _is_elapsed_expired(elapsed_s: float, max_frame_age_ms: int) -> bool:
    """Compare exact unrounded elapsed seconds against max_frame_age_ms / 1000.0."""
    if not math.isfinite(elapsed_s) or elapsed_s >= _MAX_SAFE_AGE_SECONDS:
        return True
    return elapsed_s > (max_frame_age_ms / 1000.0)


def _evaluate_freshness(
    sb: _SandboxBrowserRecord,
    surf: _SurfaceRecord,
    now: float,
    max_frame_age_ms: int,
) -> FrameFreshness:
    if sb.status != _STATUS_RUNNING:
        return FrameFreshness(True, STALE_DISCONNECTED, None)
    if surf.current_nav is None:
        return FrameFreshness(True, STALE_AWAITING_NAV, None)
    if surf.paired_frame is None or surf.paired_frame_bytes is None:
        return FrameFreshness(True, STALE_AWAITING_FRAME, None)
    elapsed_s = now - surf.paired_frame.frame.captured_at
    if elapsed_s < 0.0:
        return FrameFreshness(True, STALE_CLOCK_REGRESSION, None)
    if _is_elapsed_expired(elapsed_s, max_frame_age_ms):
        age_ms = _bounded_display_age_ms(
            elapsed_s, max_frame_age_ms=max_frame_age_ms, expired=True
        )
        return FrameFreshness(True, STALE_TTL_EXPIRED, age_ms)
    age_ms = _bounded_display_age_ms(
        elapsed_s, max_frame_age_ms=max_frame_age_ms, expired=False
    )
    return FrameFreshness(False, None, age_ms)


def _clear_surface_state(sb: _SandboxBrowserRecord) -> None:
    for surf in sb.surfaces.values():
        surf.current_nav = None
        surf.paired_frame = None
        surf.paired_frame_bytes = None


def _retire_capture_generation(sb: _SandboxBrowserRecord) -> None:
    """Clear all surfaces and bump capture_generation; never raises on exhaustion."""
    _clear_surface_state(sb)
    if sb.capture_generation >= MAX_SQLITE_INT64:
        sb.capture_generation_exhausted = True
    else:
        sb.capture_generation += 1


def _record_quarantine(
    surf: _SurfaceRecord,
    frame_seq: int,
    nav_generation: int,
    stale_reason: str,
    observed_at: float,
) -> None:
    surf.dropped_frame_counts[stale_reason] = (
        surf.dropped_frame_counts.get(stale_reason, 0) + 1
    )
    surf.quarantine_recent.append(
        _QuarantinedFrameEvent(
            frame_seq=frame_seq,
            nav_generation=nav_generation,
            stale_reason=stale_reason,
            observed_at=observed_at,
        )
    )


def _authorize_operator_caller(caller: object) -> PrincipalCtx:
    if not isinstance(caller, PrincipalCtx):
        raise CoordValidationError(_ERR_CALLER_TYPE)
    if caller.role is not CoordRole.OPERATOR:
        raise CoordAuthError(_ERR_OPERATOR_ROLE)
    if caller.sandbox_addr is not None or caller.incarnation_id is not None:
        raise CoordAuthError(_ERR_OPERATOR_BOUND)
    return caller


def _validate_int_range(value: object, min_v: int, max_v: int) -> int:
    if type(value) is not int:
        raise CoordValidationError(_ERR_INVALID_BOUNDS)
    ival = cast(int, value)
    if not (min_v <= ival <= max_v):
        raise CoordValidationError(_ERR_INVALID_BOUNDS)
    return ival


def _max_optional_float(a: float | None, b: float | None) -> float | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if a >= b else b


def _clone_nav_with_text(
    nav: BrowserNavState,
    *,
    title: str,
    title_truncated: bool,
    path: str,
    path_truncated: bool,
) -> BrowserNavState:
    cls = NavClassification(
        origin_trust=nav.origin_trust,
        tls_state=nav.tls_state,
        userinfo_redacted=nav.userinfo_redacted,
        query_redacted=nav.query_redacted,
        fragment_redacted=nav.fragment_redacted,
        path_truncated=nav.path_truncated or path_truncated,
        title_scrubbed=nav.title_scrubbed,
        title_truncated=nav.title_truncated or title_truncated,
    )
    return BrowserNavState(
        surface_key=nav.surface_key,
        nav_generation=nav.nav_generation,
        origin=nav.origin,
        path_redacted=path,
        scheme=nav.scheme,
        tls_verified=nav.tls_verified,
        page_title_clean=title,
        committed_at=nav.committed_at,
        classification=cls,
    )


def _binary_search_prefix(
    text: str, *, min_len: int, fits: Callable[[str], bool]
) -> str | None:
    if not fits(text[:min_len]):
        return None
    lo = min_len
    hi = len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if fits(text[:mid]):
            lo = mid
        else:
            hi = mid - 1
    return text[:lo]


def _shrink_nav_to_fit(
    nav: BrowserNavState, *, builder: Callable[[BrowserNavState], bytes], budget: int
) -> BrowserNavState | None:
    if len(builder(nav)) <= budget:
        return nav
    empty_title_nav = _clone_nav_with_text(
        nav, title="", title_truncated=bool(nav.page_title_clean),
        path=nav.path_redacted, path_truncated=False,
    )
    if len(builder(empty_title_nav)) <= budget:
        shrunk_title = _binary_search_prefix(
            nav.page_title_clean,
            min_len=0,
            fits=lambda s: len(
                builder(
                    _clone_nav_with_text(
                        nav, title=s, title_truncated=(len(s) < len(nav.page_title_clean)),
                        path=nav.path_redacted, path_truncated=False,
                    )
                )
            )
            <= budget,
        )
        if shrunk_title is None:
            return None
        return _clone_nav_with_text(
            nav, title=shrunk_title,
            title_truncated=(len(shrunk_title) < len(nav.page_title_clean)),
            path=nav.path_redacted, path_truncated=False,
        )
    shrunk_path = _binary_search_prefix(
        nav.path_redacted,
        min_len=1,
        fits=lambda p: len(
            builder(
                _clone_nav_with_text(
                    nav, title="", title_truncated=bool(nav.page_title_clean),
                    path=p, path_truncated=(len(p) < len(nav.path_redacted)),
                )
            )
        )
        <= budget,
    )
    if shrunk_path is None:
        return None
    return _clone_nav_with_text(
        nav, title="", title_truncated=bool(nav.page_title_clean),
        path=shrunk_path, path_truncated=(len(shrunk_path) < len(nav.path_redacted)),
    )


def _rebuild_snapshot_nav(
    snapshot: BrowserSurfaceSnapshot, new_nav: BrowserNavState
) -> BrowserSurfaceSnapshot:
    new_paired = (
        None
        if snapshot.paired_frame is None
        else PairedBrowserFrame(
            nav=new_nav, frame=snapshot.paired_frame.frame, untrusted_content=True
        )
    )
    return BrowserSurfaceSnapshot(
        schema_version=snapshot.schema_version,
        sandbox_meta=snapshot.sandbox_meta,
        surface_key=snapshot.surface_key,
        nav=new_nav,
        paired_frame=new_paired,
        freshness=snapshot.freshness,
        frame_b64=snapshot.frame_b64,
        frame_b64_omitted_reason=snapshot.frame_b64_omitted_reason,
        audit=snapshot.audit,
        untrusted_content=True,
    )


def _pack_surface_snapshot(
    captured: _CapturedSurfaceState,
    *,
    include_frame_b64: bool,
    max_response_bytes: int,
    read_session: ReadSessionEcho | None,
) -> BrowserSurfaceSnapshot:
    audit = BrowserSurfaceAudit(
        dropped_frame_counts=captured.dropped_frame_counts,
        observed_at=captured.observed_at,
        read_session=read_session,
    )
    frame_b64: str | None = None
    omitted_reason: str | None = None
    if include_frame_b64:
        if captured.freshness.frame_stale:
            omitted_reason = captured.freshness.stale_reason
        elif captured.paired_frame_bytes is not None:
            frame_b64 = base64.b64encode(captured.paired_frame_bytes).decode("ascii")

    candidate = BrowserSurfaceSnapshot(
        schema_version=BROWSER_OBSERVE_SCHEMA_VERSION,
        sandbox_meta=captured.sandbox_meta,
        surface_key=captured.surface_key,
        nav=captured.nav,
        paired_frame=captured.paired_frame,
        freshness=captured.freshness,
        frame_b64=frame_b64,
        frame_b64_omitted_reason=omitted_reason,
        audit=audit,
        untrusted_content=True,
    )
    if len(serialize_json_bytes(candidate)) <= max_response_bytes:
        return candidate
    if frame_b64 is not None:
        candidate = BrowserSurfaceSnapshot(
            schema_version=BROWSER_OBSERVE_SCHEMA_VERSION,
            sandbox_meta=captured.sandbox_meta,
            surface_key=captured.surface_key,
            nav=captured.nav,
            paired_frame=captured.paired_frame,
            freshness=captured.freshness,
            frame_b64=None,
            frame_b64_omitted_reason=OMIT_BUDGET_EXCEEDED,
            audit=audit,
            untrusted_content=True,
        )
        if len(serialize_json_bytes(candidate)) <= max_response_bytes:
            return candidate
    if candidate.nav is None:
        raise CoordValidationError(_ERR_BUDGET_ENVELOPE)
    shrunk_nav = _shrink_nav_to_fit(
        candidate.nav,
        builder=lambda n: serialize_json_bytes(_rebuild_snapshot_nav(candidate, n)),
        budget=max_response_bytes,
    )
    if shrunk_nav is None:
        raise CoordValidationError(_ERR_BUDGET_ENVELOPE)
    return _rebuild_snapshot_nav(candidate, shrunk_nav)


def _check_frame_identity_and_ttl(
    surf: _SurfaceRecord,
    captured: _CapturedSurfaceState,
    now_release: float,
    max_frame_age_ms: int,
) -> str | None:
    if surf.paired_frame is None or surf.paired_frame_bytes is None:
        return STALE_AWAITING_FRAME
    if captured.paired_frame is None:
        return STALE_AWAITING_FRAME
    cur_frame = surf.paired_frame.frame
    cap_frame = captured.paired_frame.frame
    if (
        cur_frame.frame_seq != cap_frame.frame_seq
        or cur_frame.frame_sha256 != cap_frame.frame_sha256
    ):
        return STALE_FRAME_SUPERSEDED
    elapsed_s = now_release - cur_frame.captured_at
    if elapsed_s < 0.0:
        return STALE_CLOCK_REGRESSION
    if _is_elapsed_expired(elapsed_s, max_frame_age_ms):
        return STALE_TTL_EXPIRED
    return None


def _check_fresh_release_invariant(
    sb: _SandboxBrowserRecord,
    surf: _SurfaceRecord | None,
    captured: _CapturedSurfaceState,
    now_release: float,
    max_frame_age_ms: int,
) -> str | None:
    if sb.status != _STATUS_RUNNING:
        return STALE_DISCONNECTED
    if sb.capture_generation != captured.surface_key.capture_generation:
        return STALE_CAPTURE_GENERATION
    if surf is None or surf.current_nav is None:
        return STALE_AWAITING_NAV
    if captured.nav is None or surf.current_nav.nav_generation != captured.nav.nav_generation:
        return STALE_NAV_GENERATION
    return _check_frame_identity_and_ttl(surf, captured, now_release, max_frame_age_ms)


def _check_stale_metadata_release_invariant(
    sb: _SandboxBrowserRecord,
    surf: _SurfaceRecord | None,
    captured: _CapturedSurfaceState,
) -> str | None:
    if sb.capture_generation != captured.surface_key.capture_generation:
        return STALE_CAPTURE_GENERATION
    if surf is None:
        return STALE_AWAITING_NAV
    cur_nav_gen = None if surf.current_nav is None else surf.current_nav.nav_generation
    cap_nav_gen = None if captured.nav is None else captured.nav.nav_generation
    if cur_nav_gen != cap_nav_gen:
        return STALE_AWAITING_NAV if cur_nav_gen is None else STALE_NAV_GENERATION
    if captured.paired_frame is None:
        return None
    if surf.paired_frame is None:
        return STALE_AWAITING_FRAME
    cur_f = surf.paired_frame.frame
    cap_f = captured.paired_frame.frame
    if cur_f.frame_seq != cap_f.frame_seq or cur_f.frame_sha256 != cap_f.frame_sha256:
        return STALE_FRAME_SUPERSEDED
    return None


def _resolve_rebuilt_pair_and_age(
    surf: _SurfaceRecord | None,
    cur_key: SurfaceKey,
    now_release: float,
    release_failure: str,
    max_frame_age_ms: int,
) -> tuple[PairedBrowserFrame | None, int | None]:
    if (
        release_failure not in (STALE_TTL_EXPIRED, STALE_CLOCK_REGRESSION)
        or surf is None
        or surf.current_nav is None
        or surf.paired_frame is None
        or surf.current_nav.surface_key != cur_key
    ):
        return None, None
    cur_paired = surf.paired_frame
    age_ms: int | None = None
    if release_failure == STALE_TTL_EXPIRED:
        elapsed_s = now_release - cur_paired.frame.captured_at
        if elapsed_s >= 0.0:
            age_ms = _bounded_display_age_ms(
                elapsed_s, max_frame_age_ms=max_frame_age_ms, expired=True
            )
    return cur_paired, age_ms


def _build_zero_pixel_rebuilt_state(
    sb: _SandboxBrowserRecord,
    surf: _SurfaceRecord | None,
    surface_id: str,
    now_release: float,
    release_failure: str,
    max_frame_age_ms: int,
) -> _CapturedSurfaceState:
    cur_meta = SandboxViewMeta(
        worker_ref=sb.worker_ref,
        instance_name=sb.instance_name,
        sandbox_status=sb.status,
        capture_generation=sb.capture_generation,
    )
    cur_key = SurfaceKey(
        sandbox_addr=sb.sandbox_addr,
        incarnation_id=sb.current_incarnation_id,
        surface_id=surface_id,
        capture_generation=sb.capture_generation,
    )
    cur_paired, age_ms = _resolve_rebuilt_pair_and_age(
        surf, cur_key, now_release, release_failure, max_frame_age_ms
    )
    stale_reason = STALE_DISCONNECTED if sb.status != _STATUS_RUNNING else release_failure
    return _CapturedSurfaceState(
        sandbox_meta=cur_meta,
        surface_key=cur_key,
        nav=None if surf is None else surf.current_nav,
        paired_frame=cur_paired,
        paired_frame_bytes=None,
        freshness=FrameFreshness(True, stale_reason, age_ms),
        dropped_frame_counts={} if surf is None else dict(surf.dropped_frame_counts),
        observed_at=now_release,
        capture_generation_exhausted=sb.capture_generation_exhausted,
    )


def _rebuild_wall_tile_nav(
    tile: BrowserWallTile, new_nav: BrowserNavState
) -> BrowserWallTile:
    return BrowserWallTile(
        sandbox_meta=tile.sandbox_meta,
        surface_key=tile.surface_key,
        nav=new_nav,
        frame_meta=tile.frame_meta,
        freshness=tile.freshness,
        untrusted_content=True,
    )


def _shrink_first_wall_tile(
    tile: BrowserWallTile,
    *,
    has_more_after: bool,
    cursor_after: str | None,
    max_response_bytes: int,
    observed_at: float,
    read_session: ReadSessionEcho | None,
) -> BrowserWallTile:
    if tile.nav is None:
        raise CoordValidationError(_ERR_BUDGET_ITEM)
    shrunk_nav = _shrink_nav_to_fit(
        tile.nav,
        builder=lambda n: serialize_json_bytes(
            BrowserWallPage(
                schema_version=BROWSER_OBSERVE_SCHEMA_VERSION,
                tiles=(_rebuild_wall_tile_nav(tile, n),),
                has_more=has_more_after,
                next_cursor=cursor_after,
                observed_at=observed_at,
                read_session=read_session,
            )
        ),
        budget=max_response_bytes,
    )
    if shrunk_nav is None:
        raise CoordValidationError(_ERR_BUDGET_ITEM)
    return _rebuild_wall_tile_nav(tile, shrunk_nav)


def _pack_wall_page(
    candidates: list[BrowserWallTile],
    *,
    scope_hash: str,
    limit: int,
    max_response_bytes: int,
    observed_at: float,
    read_session: ReadSessionEcho | None,
) -> BrowserWallPage:
    empty_page = BrowserWallPage(
        schema_version=BROWSER_OBSERVE_SCHEMA_VERSION,
        tiles=(),
        has_more=False,
        next_cursor=None,
        observed_at=observed_at,
        read_session=read_session,
    )
    if len(serialize_json_bytes(empty_page)) > max_response_bytes:
        raise CoordValidationError(_ERR_BUDGET_ENVELOPE)
    if not candidates:
        return empty_page

    admitted: list[BrowserWallTile] = []
    for idx, tile in enumerate(candidates[:limit]):
        has_more_after = idx + 1 < len(candidates)
        cursor_after = (
            encode_wall_cursor(
                scope_hash=scope_hash,
                sandbox_addr=tile.sandbox_addr,
                surface_id=tile.surface_id,
            )
            if has_more_after
            else None
        )
        trial_page = BrowserWallPage(
            schema_version=BROWSER_OBSERVE_SCHEMA_VERSION,
            tiles=(*admitted, tile),
            has_more=has_more_after,
            next_cursor=cursor_after,
            observed_at=observed_at,
            read_session=read_session,
        )
        if len(serialize_json_bytes(trial_page)) <= max_response_bytes:
            admitted.append(tile)
            continue
        if not admitted:
            admitted.append(
                _shrink_first_wall_tile(
                    tile,
                    has_more_after=has_more_after,
                    cursor_after=cursor_after,
                    max_response_bytes=max_response_bytes,
                    observed_at=observed_at,
                    read_session=read_session,
                )
            )
        break

    final_has_more = len(admitted) < len(candidates)
    final_cursor = (
        encode_wall_cursor(
            scope_hash=scope_hash,
            sandbox_addr=admitted[-1].sandbox_addr,
            surface_id=admitted[-1].surface_id,
        )
        if final_has_more
        else None
    )
    return BrowserWallPage(
        schema_version=BROWSER_OBSERVE_SCHEMA_VERSION,
        tiles=tuple(admitted),
        has_more=final_has_more,
        next_cursor=final_cursor,
        observed_at=observed_at,
        read_session=read_session,
    )


class BrowserProvenanceStore:
    """In-memory navigation <-> frame provenance pairing store & operator-only read service."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_frame_age_ms: int = DEFAULT_MAX_FRAME_AGE_MS,
        session_validator: Callable[[PrincipalCtx, str, int], bool] | None = None,
        live_authority_checker: Callable[[PrincipalCtx], bool] | None = None,
        on_after_pack_before_release: Callable[[], None] | None = None,
    ) -> None:
        if not callable(clock):
            raise CoordValidationError("clock_must_be_callable")
        self._max_frame_age_ms = _validate_int_range(
            max_frame_age_ms, MIN_FRAME_AGE_MS, MAX_FRAME_AGE_MS
        )
        if session_validator is not None and not callable(session_validator):
            raise CoordValidationError("session_validator_must_be_callable")
        if live_authority_checker is not None and not callable(live_authority_checker):
            raise CoordValidationError("live_authority_checker_must_be_callable")
        if on_after_pack_before_release is not None and not callable(
            on_after_pack_before_release
        ):
            raise CoordValidationError("release_hook_must_be_callable")
        self._clock = clock
        self._session_validator = session_validator
        self._live_authority_checker = live_authority_checker
        self._on_after_pack_before_release = on_after_pack_before_release
        self._lock = threading.RLock()
        self._sandboxes: dict[str, _SandboxBrowserRecord] = {}

    def _read_monotonic_clock(self) -> float:
        try:
            raw = self._clock()
        except Exception as exc:
            raise CoordPolicyError(_ERR_INVALID_CLOCK) from exc
        if type(raw) is bool or not isinstance(raw, (int, float)):
            raise CoordPolicyError(_ERR_INVALID_CLOCK)
        try:
            fval = float(raw)
        except OverflowError as exc:
            raise CoordPolicyError(_ERR_INVALID_CLOCK) from exc
        if not math.isfinite(fval) or fval < 0.0:
            raise CoordPolicyError(_ERR_INVALID_CLOCK)
        return fval + 0.0

    def _validate_session_args(
        self, read_session_id: object, session_generation: object
    ) -> ReadSessionEcho | None:
        if (read_session_id is None) != (session_generation is None):
            raise CoordValidationError(_ERR_SESSION_PAIR)
        if read_session_id is None:
            if self._session_validator is not None:
                raise CoordAuthError(_ERR_SESSION_REQUIRED)
            return None
        echo = ReadSessionEcho(
            read_session_id=validate_token_strict(read_session_id, "read_session_id"),
            session_generation=validate_positive_int(
                session_generation, "session_generation"
            ),
        )
        if self._session_validator is None:
            raise CoordPolicyError(_ERR_SESSION_UNCONFIGURED)
        return echo

    def _check_authority_and_session(
        self, caller: PrincipalCtx, session_echo: ReadSessionEcho | None
    ) -> None:
        if self._session_validator is not None:
            if session_echo is None:
                raise CoordAuthError(_ERR_SESSION_REQUIRED)
            try:
                ok = self._session_validator(
                    caller, session_echo.read_session_id, session_echo.session_generation
                )
            except Exception as exc:
                raise RevokedError(_ERR_SESSION_RETIRED) from exc
            if ok is not True:
                raise RevokedError(_ERR_SESSION_RETIRED)
        if self._live_authority_checker is not None:
            try:
                live_ok = self._live_authority_checker(caller)
            except Exception as exc:
                raise RevokedError(_ERR_AUTHORITY_REVOKED) from exc
            if live_ok is not True:
                raise RevokedError(_ERR_AUTHORITY_REVOKED)

    def _require_enabled_sandbox_locked(self, addr: str) -> _SandboxBrowserRecord:
        sb = self._sandboxes.get(addr)
        if sb is None:
            raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
        if not sb.browser_enabled:
            raise CoordPolicyError(_ERR_BROWSER_DISABLED)
        return sb

    def register_sandbox(
        self,
        sandbox_addr: str,
        *,
        incarnation_id: str,
        browser_enabled: bool = True,
        status: str = _STATUS_RUNNING,
    ) -> None:
        """Register a sandbox or rotate it to a fresh incarnation."""
        target = parse_sandbox_target(sandbox_addr)
        inc = validate_token_strict(incarnation_id, _LABEL_INCARNATION_ID)
        require_bool(browser_enabled, "browser_enabled")
        if status not in VALID_SANDBOX_STATUSES:
            raise CoordValidationError("invalid_sandbox_status")
        with self._lock:
            existing = self._sandboxes.get(target.canonical)
            if existing is not None:
                self._update_or_rotate_sandbox_locked(
                    existing, inc=inc, browser_enabled=browser_enabled, status=status
                )
                return
            if len(self._sandboxes) >= MAX_TRACKED_SANDBOXES:
                raise CoordPolicyError(_ERR_MAX_SANDBOXES)
            self._sandboxes[target.canonical] = _SandboxBrowserRecord(
                sandbox_addr=target.canonical,
                worker_ref=target.worker_ref,
                instance_name=target.name,
                current_incarnation_id=inc,
                browser_enabled=browser_enabled,
                status=status,
            )

    def _update_same_incarnation_locked(
        self,
        existing: _SandboxBrowserRecord,
        *,
        browser_enabled: bool,
        status: str,
    ) -> None:
        if existing.status == _STATUS_REVOKED:
            if status != _STATUS_REVOKED or browser_enabled != existing.browser_enabled:
                raise RevokedError(_ERR_INCARNATION_REVOKED)
            return
        was_active = existing.status == _STATUS_RUNNING and existing.browser_enabled
        is_active = status == _STATUS_RUNNING and browser_enabled
        if existing.capture_generation_exhausted and is_active:
            raise RevokedError(_ERR_CAP_GEN_EXHAUSTED)
        existing.browser_enabled = browser_enabled
        existing.status = status
        if was_active and not is_active:
            _retire_capture_generation(existing)
        elif not is_active:
            _clear_surface_state(existing)

    def _update_or_rotate_sandbox_locked(
        self,
        existing: _SandboxBrowserRecord,
        *,
        inc: str,
        browser_enabled: bool,
        status: str,
    ) -> None:
        if inc == existing.current_incarnation_id:
            self._update_same_incarnation_locked(
                existing, browser_enabled=browser_enabled, status=status
            )
            return
        if inc in existing.superseded_incarnations:
            raise IncarnationMismatchError(STALE_SUPERSEDED_INCARNATION)
        if len(existing.superseded_incarnations) >= MAX_ROTATIONS_PER_SANDBOX:
            raise CoordPolicyError(_ERR_MAX_ROTATIONS)
        existing.superseded_incarnations.add(existing.current_incarnation_id)
        existing.current_incarnation_id = inc
        existing.capture_generation = 1
        existing.capture_generation_exhausted = False
        existing.browser_enabled = browser_enabled
        existing.status = status
        existing.surfaces.clear()

    def _apply_status_transition_locked(
        self, sb: _SandboxBrowserRecord, status: str
    ) -> None:
        if sb.status == _STATUS_REVOKED:
            if status != _STATUS_REVOKED:
                raise RevokedError(_ERR_INCARNATION_REVOKED)
            return
        if sb.capture_generation_exhausted and status == _STATUS_RUNNING:
            raise RevokedError(_ERR_CAP_GEN_EXHAUSTED)
        was_active = sb.status == _STATUS_RUNNING and sb.browser_enabled
        is_active = status == _STATUS_RUNNING and sb.browser_enabled
        sb.status = status
        if was_active and not is_active:
            _retire_capture_generation(sb)
        elif not is_active:
            _clear_surface_state(sb)

    def set_sandbox_status(
        self, sandbox_addr: str, *, incarnation_id: str, status: str
    ) -> None:
        """Transition sandbox lifecycle status with incarnation & terminal-revocation fencing."""
        target = parse_sandbox_target(sandbox_addr)
        inc = validate_token_strict(incarnation_id, _LABEL_INCARNATION_ID)
        if status not in VALID_SANDBOX_STATUSES:
            raise CoordValidationError("invalid_sandbox_status")
        with self._lock:
            sb = self._sandboxes.get(target.canonical)
            if sb is None:
                raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
            if inc != sb.current_incarnation_id:
                raise IncarnationMismatchError(STALE_SUPERSEDED_INCARNATION)
            self._apply_status_transition_locked(sb, status)

    def record_navigation(
        self,
        sandbox_addr: str,
        *,
        incarnation_id: str,
        surface_id: str,
        capture_generation: int,
        nav_generation: int,
        raw_url: str,
        tls_verified: bool,
        tls_state_evidence: str | None = None,
        page_title: str = "",
        committed_at: float | None = None,
    ) -> BrowserNavState:
        """Record a host-observed committed navigation and clear any prior paired frame."""
        target = parse_sandbox_target(sandbox_addr)
        inc = validate_token_strict(incarnation_id, _LABEL_INCARNATION_ID)
        sid = validate_token_strict(surface_id, _LABEL_SURFACE_ID)
        validate_positive_int(capture_generation, _LABEL_CAPTURE_GEN)
        validate_positive_int(nav_generation, _LABEL_NAV_GEN)
        require_bool(tls_verified, "tls_verified")
        explicit_ts = (
            None
            if committed_at is None
            else validate_finite_nonneg_float(committed_at, "committed_at")
        )
        parsed = parse_and_classify_url(
            raw_url,
            sandbox_instance_name=target.name,
            tls_verified=tls_verified,
            tls_state_evidence=tls_state_evidence,
        )
        scrubbed = scrub_page_title(page_title)
        with self._lock:
            now = self._read_monotonic_clock()
            ts = now if explicit_ts is None else explicit_ts
            if ts > now:
                raise CoordValidationError(_ERR_COMMITTED_FUTURE)
            sb = self._require_enabled_sandbox_locked(target.canonical)
            if inc != sb.current_incarnation_id:
                raise IncarnationMismatchError(STALE_SUPERSEDED_INCARNATION)
            if sb.capture_generation_exhausted:
                raise RevokedError(_ERR_CAP_GEN_EXHAUSTED)
            if sb.status != _STATUS_RUNNING:
                raise CoordPolicyError(STALE_SANDBOX_NOT_RUNNING)
            if capture_generation != sb.capture_generation:
                raise CoordPolicyError(STALE_CAPTURE_GENERATION)
            surf = self._prepare_surface_for_nav_locked(sb, sid, nav_generation, ts)
            skey = SurfaceKey(target.canonical, inc, sid, capture_generation)
            classification = NavClassification(
                origin_trust=parsed.origin_trust,
                tls_state=parsed.tls_state,
                userinfo_redacted=parsed.userinfo_redacted,
                query_redacted=parsed.query_redacted,
                fragment_redacted=parsed.fragment_redacted,
                path_truncated=parsed.path_truncated,
                title_scrubbed=scrubbed.scrubbed,
                title_truncated=scrubbed.truncated,
            )
            nav = BrowserNavState(
                surface_key=skey,
                nav_generation=nav_generation,
                origin=parsed.origin,
                path_redacted=parsed.path_redacted,
                scheme=parsed.scheme,
                tls_verified=parsed.effective_tls_verified,
                page_title_clean=scrubbed.text,
                committed_at=ts,
                classification=classification,
            )
            surf.current_nav = nav
            surf.last_nav_generation = nav_generation
            surf.last_nav_committed_at = ts
            surf.paired_frame = None
            surf.paired_frame_bytes = None
            return nav

    def _prepare_surface_for_nav_locked(
        self,
        sb: _SandboxBrowserRecord,
        sid: str,
        nav_generation: int,
        committed_ts: float,
    ) -> _SurfaceRecord:
        surf = sb.surfaces.get(sid)
        if surf is not None:
            if nav_generation <= surf.last_nav_generation:
                raise CoordValidationError(_ERR_NON_MONOTONIC_NAV)
            min_ts = _max_optional_float(
                surf.last_nav_committed_at, surf.last_frame_captured_at
            )
            if min_ts is not None and committed_ts < min_ts:
                raise CoordValidationError(_ERR_COMMITTED_NON_MONO)
            return surf
        if len(sb.surfaces) >= MAX_SURFACES_PER_SANDBOX:
            raise CoordPolicyError(_ERR_MAX_SURFACES)
        surf = _SurfaceRecord(surface_id=sid)
        sb.surfaces[sid] = surf
        return surf

    def ingest_frame(
        self,
        sandbox_addr: str,
        *,
        incarnation_id: str,
        surface_id: str,
        capture_generation: int,
        nav_generation: int,
        frame_seq: int,
        media_type: str,
        frame_bytes: bytes,
        captured_at: float | None = None,
    ) -> FrameAdmissionResult:
        """Inspect PNG/JPEG headers and admit frame iff all provenance fences pass."""
        target = parse_sandbox_target(sandbox_addr)
        inc = validate_token_strict(incarnation_id, _LABEL_INCARNATION_ID)
        sid = validate_token_strict(surface_id, _LABEL_SURFACE_ID)
        validate_positive_int(capture_generation, _LABEL_CAPTURE_GEN)
        validate_positive_int(nav_generation, _LABEL_NAV_GEN)
        validate_positive_int(frame_seq, "frame_seq")
        explicit_ts = (
            None
            if captured_at is None
            else validate_finite_nonneg_float(captured_at, "captured_at")
        )
        header = validate_frame_bytes(media_type, frame_bytes)
        with self._lock:
            now = self._read_monotonic_clock()
            ts = now if explicit_ts is None else explicit_ts
            if ts > now:
                raise CoordValidationError(_ERR_CAPTURED_FUTURE)
            sb = self._require_enabled_sandbox_locked(target.canonical)
            if inc != sb.current_incarnation_id:
                sb.superseded_frame_drops += 1
                return FrameAdmissionResult(
                    accepted=False, stale_reason=STALE_SUPERSEDED_INCARNATION
                )
            if sb.capture_generation_exhausted:
                raise RevokedError(_ERR_CAP_GEN_EXHAUSTED)
            if sb.status != _STATUS_RUNNING:
                return FrameAdmissionResult(
                    accepted=False, stale_reason=STALE_SANDBOX_NOT_RUNNING
                )
            if capture_generation != sb.capture_generation:
                existing_surf = sb.surfaces.get(sid)
                if existing_surf is not None:
                    _record_quarantine(
                        existing_surf, frame_seq, nav_generation, STALE_CAPTURE_GENERATION, now
                    )
                raise CoordPolicyError(STALE_CAPTURE_GENERATION)
            return self._admit_frame_for_surface_locked(
                sb, sid=sid, nav_generation=nav_generation,
                frame_seq=frame_seq, header=header,
                frame_bytes=frame_bytes, ts=ts, now=now,
            )

    def _admit_frame_for_surface_locked(
        self,
        sb: _SandboxBrowserRecord,
        *,
        sid: str,
        nav_generation: int,
        frame_seq: int,
        header: Any,
        frame_bytes: bytes,
        ts: float,
        now: float,
    ) -> FrameAdmissionResult:
        surf = sb.surfaces.get(sid)
        if surf is None or surf.current_nav is None:
            return FrameAdmissionResult(accepted=False, stale_reason=STALE_UNKNOWN_NAV)
        cur_gen = surf.current_nav.nav_generation
        if nav_generation < cur_gen:
            _record_quarantine(surf, frame_seq, nav_generation, STALE_NAV_GENERATION, now)
            return FrameAdmissionResult(accepted=False, stale_reason=STALE_NAV_GENERATION)
        if nav_generation > cur_gen:
            _record_quarantine(surf, frame_seq, nav_generation, STALE_UNKNOWN_NAV, now)
            return FrameAdmissionResult(accepted=False, stale_reason=STALE_UNKNOWN_NAV)
        if frame_seq <= surf.last_frame_seq:
            _record_quarantine(surf, frame_seq, nav_generation, STALE_NON_MONOTONIC_SEQ, now)
            return FrameAdmissionResult(
                accepted=False, stale_reason=STALE_NON_MONOTONIC_SEQ
            )
        if ts < surf.current_nav.committed_at:
            _record_quarantine(surf, frame_seq, nav_generation, STALE_NAV_GENERATION, now)
            return FrameAdmissionResult(accepted=False, stale_reason=STALE_NAV_GENERATION)
        if surf.last_frame_captured_at is not None and ts < surf.last_frame_captured_at:
            raise CoordValidationError(_ERR_CAPTURED_NON_MONO)
        meta = BrowserFrameMeta(
            surface_key=surf.current_nav.surface_key,
            nav_generation=nav_generation,
            frame_seq=frame_seq,
            media_type=header.media_type,
            width=header.width,
            height=header.height,
            size_bytes=header.size_bytes,
            frame_sha256=header.frame_sha256,
            captured_at=ts,
        )
        paired = PairedBrowserFrame(nav=surf.current_nav, frame=meta, untrusted_content=True)
        surf.last_frame_seq = frame_seq
        surf.last_frame_captured_at = ts
        surf.paired_frame = paired
        surf.paired_frame_bytes = frame_bytes
        return FrameAdmissionResult(
            accepted=True, stale_reason=None, frame_meta=meta, paired_frame=paired
        )

    def _capture_surface_state_locked(
        self, addr: str, sid: str, explicit_inc: str | None
    ) -> _CapturedSurfaceState:
        now = self._read_monotonic_clock()
        sb = self._sandboxes.get(addr)
        if sb is None:
            raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
        if explicit_inc is not None and explicit_inc != sb.current_incarnation_id:
            raise IncarnationMismatchError(STALE_SUPERSEDED_INCARNATION)
        if sb.status == _STATUS_REVOKED:
            raise RevokedError(_ERR_INCARNATION_REVOKED)
        if sb.capture_generation_exhausted:
            raise RevokedError(_ERR_CAP_GEN_EXHAUSTED)
        if not sb.browser_enabled:
            raise CoordPolicyError(_ERR_BROWSER_DISABLED)
        surf = sb.surfaces.get(sid)
        if surf is None:
            raise CoordPolicyError(_ERR_SURFACE_NOT_FOUND)
        freshness = _evaluate_freshness(sb, surf, now, self._max_frame_age_ms)
        return _CapturedSurfaceState(
            sandbox_meta=SandboxViewMeta(
                worker_ref=sb.worker_ref,
                instance_name=sb.instance_name,
                sandbox_status=sb.status,
                capture_generation=sb.capture_generation,
            ),
            surface_key=SurfaceKey(
                sandbox_addr=sb.sandbox_addr,
                incarnation_id=sb.current_incarnation_id,
                surface_id=sid,
                capture_generation=sb.capture_generation,
            ),
            nav=surf.current_nav,
            paired_frame=surf.paired_frame,
            paired_frame_bytes=surf.paired_frame_bytes,
            freshness=freshness,
            dropped_frame_counts=dict(surf.dropped_frame_counts),
            observed_at=now,
            capture_generation_exhausted=sb.capture_generation_exhausted,
        )

    def _verify_release_sandbox_locked(
        self, captured: _CapturedSurfaceState
    ) -> _SandboxBrowserRecord:
        sb = self._sandboxes.get(captured.surface_key.sandbox_addr)
        if sb is None:
            raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
        if sb.current_incarnation_id != captured.surface_key.incarnation_id:
            raise IncarnationMismatchError(STALE_SUPERSEDED_INCARNATION)
        if sb.status == _STATUS_REVOKED:
            raise RevokedError(_ERR_INCARNATION_REVOKED)
        if sb.capture_generation_exhausted:
            raise RevokedError(_ERR_CAP_GEN_EXHAUSTED)
        if not sb.browser_enabled:
            raise CoordPolicyError(_ERR_BROWSER_DISABLED)
        return sb

    def _enforce_snapshot_release_fence(
        self,
        packed: BrowserSurfaceSnapshot,
        captured: _CapturedSurfaceState,
        *,
        include_frame_b64: bool,
        max_response_bytes: int,
        session_echo: ReadSessionEcho | None,
    ) -> BrowserSurfaceSnapshot:
        with self._lock:
            now_release = self._read_monotonic_clock()
            sb = self._verify_release_sandbox_locked(captured)
            needs_check = (
                (not packed.frame_stale)
                or (packed.nav is not None)
                or (packed.paired_frame is not None)
            )
            if not needs_check:
                return packed
            surf = sb.surfaces.get(captured.surface_key.surface_id)
            failure = (
                _check_fresh_release_invariant(
                    sb, surf, captured, now_release, self._max_frame_age_ms
                )
                if not packed.frame_stale
                else _check_stale_metadata_release_invariant(sb, surf, captured)
            )
            if failure is None:
                return packed
            rebuilt_state = _build_zero_pixel_rebuilt_state(
                sb,
                surf,
                captured.surface_key.surface_id,
                now_release,
                failure,
                self._max_frame_age_ms,
            )
            return _pack_surface_snapshot(
                rebuilt_state,
                include_frame_b64=include_frame_b64,
                max_response_bytes=max_response_bytes,
                read_session=session_echo,
            )

    def get_surface_snapshot(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        surface_id: str = "main",
        incarnation_id: str | None = None,
        include_frame_b64: bool = False,
        max_response_bytes: int = MAX_SNAPSHOT_RESPONSE_BYTES,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> BrowserSurfaceSnapshot:
        """Return an operator-only, session-fenced, byte-bounded surface snapshot."""
        op_caller = _authorize_operator_caller(caller)
        parsed_target = parse_sandbox_target(target)
        sid = validate_token_strict(surface_id, _LABEL_SURFACE_ID)
        explicit_inc = (
            None
            if incarnation_id is None
            else validate_token_strict(incarnation_id, _LABEL_INCARNATION_ID)
        )
        require_bool(include_frame_b64, "include_frame_b64")
        budget = _validate_int_range(
            max_response_bytes, MIN_RESPONSE_BYTES, MAX_SNAPSHOT_RESPONSE_BYTES
        )
        session_echo = self._validate_session_args(read_session_id, session_generation)
        self._check_authority_and_session(op_caller, session_echo)

        with self._lock:
            captured = self._capture_surface_state_locked(
                parsed_target.canonical, sid, explicit_inc
            )

        packed = _pack_surface_snapshot(
            captured,
            include_frame_b64=include_frame_b64,
            max_response_bytes=budget,
            read_session=session_echo,
        )
        if self._on_after_pack_before_release is not None:
            self._on_after_pack_before_release()
        self._check_authority_and_session(op_caller, session_echo)
        return self._enforce_snapshot_release_fence(
            packed,
            captured,
            include_frame_b64=include_frame_b64,
            max_response_bytes=budget,
            session_echo=session_echo,
        )

    def _collect_sandbox_wall_tiles_locked(
        self,
        sb: _SandboxBrowserRecord,
        *,
        now: float,
        after_key: tuple[str, str] | None,
    ) -> list[BrowserWallTile]:
        sb_meta = SandboxViewMeta(
            worker_ref=sb.worker_ref,
            instance_name=sb.instance_name,
            sandbox_status=sb.status,
            capture_generation=sb.capture_generation,
        )
        out: list[BrowserWallTile] = []
        for sid in sorted(sb.surfaces.keys()):
            if after_key is not None and (sb.sandbox_addr, sid) <= after_key:
                continue
            surf = sb.surfaces[sid]
            freshness = _evaluate_freshness(sb, surf, now, self._max_frame_age_ms)
            skey = SurfaceKey(
                sandbox_addr=sb.sandbox_addr,
                incarnation_id=sb.current_incarnation_id,
                surface_id=sid,
                capture_generation=sb.capture_generation,
            )
            frame_meta = None if surf.paired_frame is None else surf.paired_frame.frame
            out.append(
                BrowserWallTile(
                    sandbox_meta=sb_meta,
                    surface_key=skey,
                    nav=surf.current_nav,
                    frame_meta=frame_meta,
                    freshness=freshness,
                    untrusted_content=True,
                )
            )
        return out

    def _collect_wall_candidates_locked(
        self,
        *,
        include_disconnected: bool,
        after_key: tuple[str, str] | None,
        now: float | None = None,
    ) -> tuple[list[BrowserWallTile], float]:
        cur_now = self._read_monotonic_clock() if now is None else now
        tiles: list[BrowserWallTile] = []
        for addr in sorted(self._sandboxes.keys()):
            sb = self._sandboxes[addr]
            if not sb.browser_enabled:
                continue
            if not include_disconnected and sb.status != _STATUS_RUNNING:
                continue
            tiles.extend(
                self._collect_sandbox_wall_tiles_locked(
                    sb, now=cur_now, after_key=after_key
                )
            )
        return tiles, cur_now

    def _wall_tile_frame_matches(
        self, tile: BrowserWallTile, surf: _SurfaceRecord
    ) -> bool:
        cur_frame = None if surf.paired_frame is None else surf.paired_frame.frame
        if tile.frame_meta is None:
            return cur_frame is None
        return (
            cur_frame is not None
            and cur_frame.frame_seq == tile.frame_meta.frame_seq
            and cur_frame.frame_sha256 == tile.frame_meta.frame_sha256
        )

    def _wall_sandbox_matches_tile_locked(
        self, tile: BrowserWallTile, *, include_disconnected: bool
    ) -> _SandboxBrowserRecord | None:
        sb = self._sandboxes.get(tile.sandbox_addr)
        if sb is None or not sb.browser_enabled:
            return None
        if not include_disconnected and sb.status != _STATUS_RUNNING:
            return None
        if (
            sb.current_incarnation_id != tile.incarnation_id
            or sb.capture_generation != tile.capture_generation
            or sb.status != tile.sandbox_meta.sandbox_status
        ):
            return None
        return sb

    def _wall_tile_matches_locked(
        self,
        tile: BrowserWallTile,
        *,
        include_disconnected: bool,
        now_release: float,
    ) -> bool:
        sb = self._wall_sandbox_matches_tile_locked(
            tile, include_disconnected=include_disconnected
        )
        if sb is None:
            return False
        surf = sb.surfaces.get(tile.surface_id)
        if surf is None:
            return False
        cur_nav_gen = None if surf.current_nav is None else surf.current_nav.nav_generation
        tile_nav_gen = None if tile.nav is None else tile.nav.nav_generation
        if cur_nav_gen != tile_nav_gen or not self._wall_tile_frame_matches(tile, surf):
            return False
        cur_fresh = _evaluate_freshness(sb, surf, now_release, self._max_frame_age_ms)
        return (
            cur_fresh.frame_stale == tile.frame_stale
            and cur_fresh.stale_reason == tile.stale_reason
        )

    def _all_wall_tiles_valid_locked(
        self, page: BrowserWallPage, *, include_disconnected: bool, now_release: float
    ) -> bool:
        return all(
            self._wall_tile_matches_locked(
                tile,
                include_disconnected=include_disconnected,
                now_release=now_release,
            )
            for tile in page.tiles
        )

    def _run_wall_pack_and_release_fence(
        self,
        op_caller: PrincipalCtx,
        *,
        include_disconnected: bool,
        after_key: tuple[str, str] | None,
        scope_hash: str,
        limit: int,
        budget: int,
        session_echo: ReadSessionEcho | None,
    ) -> BrowserWallPage:
        with self._lock:
            candidates, observed_at = self._collect_wall_candidates_locked(
                include_disconnected=include_disconnected, after_key=after_key
            )
        for attempt in range(2):
            page = _pack_wall_page(
                candidates,
                scope_hash=scope_hash,
                limit=limit,
                max_response_bytes=budget,
                observed_at=observed_at,
                read_session=session_echo,
            )
            if self._on_after_pack_before_release is not None:
                self._on_after_pack_before_release()
            self._check_authority_and_session(op_caller, session_echo)
            with self._lock:
                now_release = self._read_monotonic_clock()
                if self._all_wall_tiles_valid_locked(
                    page,
                    include_disconnected=include_disconnected,
                    now_release=now_release,
                ):
                    return page
                if attempt == 1:
                    raise CoordPolicyError(_ERR_WALL_CHANGED_AT_RELEASE)
                candidates, observed_at = self._collect_wall_candidates_locked(
                    include_disconnected=include_disconnected,
                    after_key=after_key,
                    now=now_release,
                )
        raise CoordPolicyError(_ERR_WALL_CHANGED_AT_RELEASE)

    def list_browser_wall(
        self,
        caller: PrincipalCtx,
        *,
        include_disconnected: bool = False,
        after_cursor: str | None = None,
        limit: int = DEFAULT_WALL_LIMIT,
        max_response_bytes: int = MAX_WALL_RESPONSE_BYTES,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> BrowserWallPage:
        """Return a paginated, metadata-only PiP Browser Wall snapshot (zero raw pixels)."""
        op_caller = _authorize_operator_caller(caller)
        require_bool(include_disconnected, "include_disconnected")
        clean_limit = _validate_int_range(limit, 1, MAX_WALL_LIMIT)
        budget = _validate_int_range(
            max_response_bytes, MIN_RESPONSE_BYTES, MAX_WALL_RESPONSE_BYTES
        )
        scope_hash = compute_wall_scope_hash(include_disconnected=include_disconnected)
        after_key = decode_wall_cursor(after_cursor, expected_scope_hash=scope_hash)
        session_echo = self._validate_session_args(read_session_id, session_generation)
        self._check_authority_and_session(op_caller, session_echo)
        return self._run_wall_pack_and_release_fence(
            op_caller,
            include_disconnected=include_disconnected,
            after_key=after_key,
            scope_hash=scope_hash,
            limit=clean_limit,
            budget=budget,
            session_echo=session_echo,
        )


BrowserObserveService = BrowserProvenanceStore
