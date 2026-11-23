"""Standalone, operator-only read-only projection service for PRD M3.1.

Public entry points:
- ``ReadOnlyProjectionService.get_workspace_tree``
- ``ReadOnlyProjectionService.get_sandbox_status``
- ``ReadOnlyProjectionService.get_thread_events``
- ``ReadOnlyProjectionService.get_sandbox_mailbox``
- ``open_readonly_snapshot`` (re-exported from ``oc_projection_db``)
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from functools import partial
import hashlib
from pathlib import Path
import sqlite3
import sys
import time
from typing import Any

_PROJECTION_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _PROJECTION_DIR.parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
for _import_dir in (str(_PROJECTION_DIR), str(_SPIKE_M_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_address import AddressError, parse_local_target, validate_thread_id  # noqa: E402
from oc_coord_contract import (  # noqa: E402
    SANDBOX_LIFECYCLE_STATES,
    STREAM_EVENT_TYPES,
    CoordAuthError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    PrincipalCtx,
    RevokedError,
    TrustClass,
    validate_opaque_token,
)
from oc_projection_contract import (  # noqa: E402
    DEFAULT_MAX_READ_MS,
    DEFAULT_PAGE_LIMIT,
    HEALTH_DEGRADED,
    HEALTH_HEALTHY,
    HEALTH_UNKNOWN,
    MAX_EDGES_PER_SANDBOX,
    MAX_HASH_TEXT_BYTES,
    MAX_ITEM_TEXT_BYTES,
    MAX_METADATA_TEXT_BYTES,
    MAX_PAGE_LIMIT,
    MAX_READ_MS,
    MAX_RESPONSE_BYTES,
    MAX_SANDBOXES_PER_PAGE,
    MAX_THREADS_PER_SANDBOX,
    MAX_UNCONFIRMED_BINDINGS_SUMMARY,
    MIN_READ_MS,
    MIN_RESPONSE_BYTES,
    OP_EVENTS,
    OP_MAILBOX,
    OP_TREE,
    PROJECTION_SCHEMA_VERSION,
    SOURCE_EVENT_LOG,
    SOURCE_STREAM_EVENT,
    MailboxPage,
    ProjectedMailboxEntry,
    ProjectedProjectGroup,
    ProjectedRoutingEdge,
    ProjectedSandboxNode,
    ProjectedSubtreeBudget,
    ProjectedThreadEvent,
    ProjectedThreadSummary,
    ReadSessionEcho,
    SandboxStatusSnapshot,
    ThreadEventsPage,
    UnconfirmedBindingSummary,
    WorkspaceHealth,
    WorkspaceHealthSummary,
    WorkspaceTreeSnapshot,
    compute_scope_hash,
    decode_events_cursor,
    decode_mailbox_cursor,
    decode_tree_cursor,
    encode_events_cursor,
    encode_mailbox_cursor,
    encode_tree_cursor,
    serialize_projection_bytes,
)
from oc_projection_db import (  # noqa: E402
    ERR_REGISTRY_UNREADABLE,
    check_deadline_ms,
    execute_bounded,
    open_readonly_snapshot,
    read_marker_health,
    read_seq_counter,
    verify_state_dir_and_db_readonly,
)
from oc_projection_decode import (  # noqa: E402
    decode_bounded_blob,
    decode_single_line_cell,
    evaluate_stream_provenance,
    has_multiline_control_or_bidi,
    parse_artifact_refs_json,
    parse_budget_json,
    parse_detail_json,
    parse_string_list_json,
    require_clean_primary_id,
    safe_bool_flag,
    safe_finite_float,
    safe_int,
    sanitize_enum_str,
    sanitize_optional_ref,
    scrub_single_line_str,
)
from oc_registry import _TRUST_CLASS_TO_BADGE, _VALID_OUTBOX_STATUSES  # noqa: E402

__all__ = ["ReadOnlyProjectionService", "open_readonly_snapshot"]

_ORCH_PREFIX = "orchestrator:"
_COL_INCARNATION_ID = "incarnation_id"
_COL_SANDBOX_ADDR = "sandbox_addr"
_COL_SANDBOX_TYPE = "sandbox_type"
_COL_UPDATED_AT = "updated_at"
_COL_UPDATED_AT_MALFORMED = "updated_at_malformed"
_COL_CREATED_AT = "created_at"
_COL_CREATED_AT_MALFORMED = "created_at_malformed"
_COL_ORIGINAL_TEXT_BYTES = "original_text_bytes"
_COL_ABORT_REQUESTED = "abort_requested"
_KEY_DEGRADED_MARKER_PRESENT = "degraded_marker_present"
_KEY_MARKER_UNREADABLE = "marker_unreadable"
_KEY_LIVE_STATUS_AVAILABLE = "live_status_available"
_PARAM_MAX_RESPONSE_BYTES = "max_response_bytes"
_PARAM_MAX_READ_MS = "max_read_ms"

_ERR_SANDBOX_NOT_FOUND = "sandbox_not_found"
_ERR_BUDGET_ENVELOPE = "response_budget_too_small_for_envelope"
_ERR_BUDGET_ITEM = "response_budget_too_small_for_item"

_EMPTY_EDGES: tuple[ProjectedRoutingEdge, ...] = ()
_EMPTY_BINDINGS: tuple[UnconfirmedBindingSummary, ...] = ()
_EMPTY_PROJECTS: tuple[ProjectedProjectGroup, ...] = ()
_EMPTY_EVENTS: tuple[ProjectedThreadEvent, ...] = ()
_EMPTY_ENTRIES: tuple[ProjectedMailboxEntry, ...] = ()

_TRUSTED_TRUST_CLASSES = frozenset(
    {TrustClass.OPERATOR_DIRECTIVE.value, TrustClass.PARENT_TASK.value}
)
_TRUST_AUTHORITY_RANK = {
    TrustClass.OPERATOR_DIRECTIVE.value: 3,
    TrustClass.PARENT_TASK.value: 2,
    TrustClass.UNTRUSTED_PEER_DATA.value: 1,
    TrustClass.SYSTEM_ALERT.value: 0,
}

_CLOSED_OUTBOX_SQL_LIST = ",".join(f"'{s}'" for s in sorted(_VALID_OUTBOX_STATUSES))

_BINDING_SELECT_COLUMNS = """
    CASE WHEN typeof(b.sandbox_addr) = 'text' AND LENGTH(CAST(b.sandbox_addr AS BLOB)) <= 256
         THEN b.sandbox_addr ELSE NULL END AS sandbox_addr,
    CASE WHEN typeof(b.incarnation_id) = 'text' AND LENGTH(CAST(b.incarnation_id AS BLOB)) <= 256
         THEN b.incarnation_id ELSE NULL END AS incarnation_id,
    CASE WHEN typeof(b.abort_requested) = 'integer' AND b.abort_requested IN (0, 1)
         THEN b.abort_requested ELSE NULL END AS abort_requested,
    (typeof(b.abort_requested) != 'integer' OR b.abort_requested NOT IN (0, 1)) AS abort_requested_malformed,
    CASE WHEN typeof(b.terminal_confirmed) = 'integer' AND b.terminal_confirmed IN (0, 1)
         THEN b.terminal_confirmed ELSE NULL END AS terminal_confirmed,
    (typeof(b.terminal_confirmed) != 'integer' OR b.terminal_confirmed NOT IN (0, 1)) AS terminal_confirmed_malformed,
    SUBSTR(CAST(b.reason AS BLOB), 1, 1024) AS reason_blob,
    LENGTH(CAST(b.reason AS BLOB)) AS reason_bytes,
    (typeof(b.reason) != 'text') AS reason_non_text,
    CASE WHEN typeof(b.updated_at) IN ('integer', 'real') THEN b.updated_at ELSE NULL END AS updated_at,
    (typeof(b.updated_at) NOT IN ('integer', 'real')) AS updated_at_malformed,
    CASE WHEN typeof(s.status) = 'text' AND LENGTH(CAST(s.status AS BLOB)) <= 64
         THEN s.status ELSE NULL END AS sandbox_status,
    CASE WHEN typeof(s.incarnation_id) = 'text' AND LENGTH(CAST(s.incarnation_id AS BLOB)) <= 256
         THEN s.incarnation_id ELSE NULL END AS current_incarnation,
    (s.sandbox_addr IS NULL) AS sandbox_missing
"""

_BINDING_FROM_WHERE_SQL = """
FROM external_transport_bindings b
LEFT JOIN sandboxes s ON s.sandbox_addr = b.sandbox_addr
WHERE (typeof(b.terminal_confirmed) != 'integer' OR b.terminal_confirmed NOT IN (0, 1))
   OR (typeof(b.abort_requested) != 'integer' OR b.abort_requested NOT IN (0, 1))
   OR (b.terminal_confirmed = 0
       AND (b.abort_requested = 1
            OR s.sandbox_addr IS NULL
            OR s.status = 'revoked'
            OR s.incarnation_id IS NOT b.incarnation_id))
"""

_SQL_UNCONFIRMED_BINDINGS_COUNT = f"SELECT COUNT(*) AS cnt {_BINDING_FROM_WHERE_SQL}"
_SQL_UNCONFIRMED_BINDINGS_SUMMARY = (
    f"SELECT {_BINDING_SELECT_COLUMNS} {_BINDING_FROM_WHERE_SQL} "
    "ORDER BY b.sandbox_addr ASC, b.incarnation_id ASC LIMIT ?"
)

_SQL_SANDBOX_COLUMNS = """
    CASE WHEN typeof(sandbox_addr) = 'text' AND LENGTH(CAST(sandbox_addr AS BLOB)) <= 256
         THEN sandbox_addr ELSE NULL END AS sandbox_addr,
    CASE WHEN typeof(worker_ref) = 'text' AND LENGTH(CAST(worker_ref AS BLOB)) <= 256
         THEN worker_ref ELSE NULL END AS worker_ref,
    CASE WHEN typeof(instance_name) = 'text' AND LENGTH(CAST(instance_name AS BLOB)) <= 256
         THEN instance_name ELSE NULL END AS instance_name,
    CASE WHEN typeof(incarnation_id) = 'text' AND LENGTH(CAST(incarnation_id AS BLOB)) <= 256
         THEN incarnation_id ELSE NULL END AS incarnation_id,
    CASE WHEN typeof(job_id) = 'text' AND LENGTH(CAST(job_id AS BLOB)) <= 256
         THEN job_id ELSE NULL END AS job_id,
    CASE WHEN typeof(project_id) = 'text' AND LENGTH(CAST(project_id AS BLOB)) <= 4096
         THEN project_id ELSE NULL END AS project_id_raw,
    SUBSTR(CAST(project_id AS BLOB), 1, 1024) AS project_id_preview_blob,
    LENGTH(CAST(project_id AS BLOB)) AS project_id_bytes,
    (typeof(project_id) != 'text') AS project_id_non_text,
    SUBSTR(CAST(project_name AS BLOB), 1, 1024) AS project_name_blob,
    LENGTH(CAST(project_name AS BLOB)) AS project_name_bytes,
    (typeof(project_name) != 'text') AS project_name_non_text,
    SUBSTR(CAST(branch AS BLOB), 1, 1024) AS branch_blob,
    LENGTH(CAST(branch AS BLOB)) AS branch_bytes,
    (typeof(branch) != 'text') AS branch_non_text,
    CASE WHEN typeof(sandbox_type) = 'text' AND LENGTH(CAST(sandbox_type AS BLOB)) <= 64
         THEN sandbox_type ELSE NULL END AS sandbox_type,
    SUBSTR(CAST(task_brief AS BLOB), 1, 1024) AS task_brief_blob,
    LENGTH(CAST(task_brief AS BLOB)) AS task_brief_bytes,
    (typeof(task_brief) != 'text') AS task_brief_non_text,
    CASE WHEN typeof(status) = 'text' AND LENGTH(CAST(status AS BLOB)) <= 64
         THEN status ELSE NULL END AS status,
    CASE WHEN parent_addr IS NULL THEN NULL
         WHEN typeof(parent_addr) = 'text' AND LENGTH(CAST(parent_addr AS BLOB)) <= 256
         THEN parent_addr ELSE NULL END AS parent_addr,
    (parent_addr IS NOT NULL AND (typeof(parent_addr) != 'text' OR LENGTH(CAST(parent_addr AS BLOB)) > 256)) AS parent_addr_malformed,
    CASE WHEN typeof(depth) = 'integer' THEN depth ELSE NULL END AS depth,
    (typeof(depth) != 'integer') AS depth_malformed,
    CASE WHEN typeof(created_at) IN ('integer', 'real') THEN created_at ELSE NULL END AS created_at,
    (typeof(created_at) NOT IN ('integer', 'real')) AS created_at_malformed,
    CASE WHEN typeof(updated_at) IN ('integer', 'real') THEN updated_at ELSE NULL END AS updated_at,
    (typeof(updated_at) NOT IN ('integer', 'real')) AS updated_at_malformed
"""


@dataclass(frozen=True, slots=True)
class _EventsPackCtx:
    snapshot_seq: int
    health: WorkspaceHealthSummary
    sandbox_addr: str
    target_inc: str
    is_current: bool
    stale_reason: str | None
    thread_id: str
    thread_exists: bool
    page_limit: int
    scope_hash: str
    max_bytes: int
    session_echo: ReadSessionEcho | None
    deadline: float


@dataclass(frozen=True, slots=True)
class _TreePackCtx:
    snapshot_seq: int
    sb_limit: int
    include_historical: bool
    max_threads: int
    scope_hash: str
    max_bytes: int
    session_echo: ReadSessionEcho | None
    deadline: float


@dataclass(frozen=True, slots=True)
class _MailboxPackCtx:
    snapshot_seq: int
    health: WorkspaceHealthSummary
    sandbox_addr: str
    current_inc: str
    page_limit: int
    scope_hash: str
    max_bytes: int
    session_echo: ReadSessionEcho | None
    deadline: float


@dataclass(frozen=True, slots=True)
class _StatusPackCtx:
    snapshot_seq: int
    binding: UnconfirmedBindingSummary | None
    budget: ProjectedSubtreeBudget | None
    budget_malformed: bool
    max_bytes: int
    session_echo: ReadSessionEcho | None
    deadline: float


def _validate_int_range(value: object, label: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CoordValidationError(f"{label} must be an int in {lo}..{hi}")
    if value < lo or value > hi:
        raise CoordValidationError(f"{label} must be an int in {lo}..{hi}")
    return value


def _validate_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise CoordValidationError(f"{label} must be a bool")
    return value


def _validate_outbox_statuses(statuses: Iterable[str] | None) -> tuple[str, ...] | None:
    if statuses is None:
        return None
    if isinstance(statuses, (str, bytes)):
        raise CoordValidationError("statuses must be an iterable of status strings")
    cleaned: set[str] = set()
    for item in statuses:
        if not isinstance(item, str) or item not in _VALID_OUTBOX_STATUSES:
            raise CoordValidationError(f"Unsupported outbox status filter: {item!r}")
        cleaned.add(item)
    if not cleaned:
        raise CoordValidationError("statuses filter must not be empty")
    return tuple(sorted(cleaned))


def _authorize_operator_caller(caller: object) -> PrincipalCtx:
    if not isinstance(caller, PrincipalCtx):
        raise CoordValidationError("caller must be PrincipalCtx")
    if caller.role is not CoordRole.OPERATOR:
        raise CoordAuthError("operator_role_required")
    if caller.sandbox_addr is not None or caller.incarnation_id is not None:
        raise CoordAuthError("operator_principal_must_not_bind_sandbox")
    return caller


def _validate_session_args(
    read_session_id: object, session_generation: object, *, has_validator: bool
) -> ReadSessionEcho | None:
    if (read_session_id is None) != (session_generation is None):
        raise CoordValidationError("read_session_pair_required")
    if read_session_id is None:
        if has_validator:
            raise CoordAuthError("read_session_required")
        return None
    try:
        clean_id = validate_opaque_token(read_session_id, "read_session_id")
    except AddressError as exc:
        raise CoordValidationError(str(exc)) from exc
    if isinstance(session_generation, bool) or not isinstance(session_generation, int):
        raise CoordValidationError("session_generation must be an int >= 1")
    if session_generation < 1:
        raise CoordValidationError("session_generation must be an int >= 1")
    if not has_validator:
        raise CoordPolicyError("read_session_validator_unconfigured")
    return ReadSessionEcho(read_session_id=clean_id, session_generation=session_generation)


def _enforce_authority_fences(
    caller: PrincipalCtx,
    session_echo: ReadSessionEcho | None,
    session_validator: Callable[[PrincipalCtx, str, int], bool] | None,
    live_authority_checker: Callable[[PrincipalCtx], bool] | None,
) -> None:
    if session_validator is not None and session_echo is not None:
        try:
            ok = session_validator(
                caller, session_echo.read_session_id, session_echo.session_generation
            )
        except Exception as exc:
            raise RevokedError("read_session_retired") from exc
        if ok is not True:
            raise RevokedError("read_session_retired")
    if live_authority_checker is not None:
        try:
            ok = live_authority_checker(caller)
        except Exception as exc:
            raise RevokedError("read_authority_revoked") from exc
        if ok is not True:
            raise RevokedError("read_authority_revoked")


def _row_to_binding_summary(row: Mapping[str, Any]) -> UnconfirmedBindingSummary:
    sb_addr, bad_sb = sanitize_optional_ref(row[_COL_SANDBOX_ADDR])
    inc_id, bad_inc = sanitize_optional_ref(row[_COL_INCARNATION_ID])
    sb_status, bad_st = sanitize_optional_ref(row["sandbox_status"])
    cur_inc, bad_cinc = sanitize_optional_ref(row["current_incarnation"])
    abort_req, bad_abort = safe_bool_flag(
        row[_COL_ABORT_REQUESTED], row["abort_requested_malformed"]
    )
    term_conf, bad_term = safe_bool_flag(
        row["terminal_confirmed"], row["terminal_confirmed_malformed"]
    )
    reason, reason_trunc, bad_reason = decode_single_line_cell(
        row["reason_blob"], row["reason_bytes"], row["reason_non_text"]
    )
    updated_at, bad_upd = safe_finite_float(
        row[_COL_UPDATED_AT], row[_COL_UPDATED_AT_MALFORMED]
    )
    malformed_id = (sb_addr is None) or (inc_id is None) or bad_sb or bad_inc
    malformed_meta = (
        bad_abort or bad_term or bad_reason or bad_upd or bad_st or bad_cinc
    )
    return UnconfirmedBindingSummary(
        sandbox_addr=sb_addr,
        incarnation_id=inc_id,
        abort_requested=abort_req,
        terminal_confirmed=term_conf,
        reason=reason,
        reason_truncated=reason_trunc,
        updated_at=updated_at,
        sandbox_status=sb_status,
        current_incarnation=cur_inc,
        sandbox_missing=bool(row["sandbox_missing"]),
        malformed_identity=malformed_id,
        malformed_metadata=malformed_meta,
    )


def _compute_health_status(
    marker: Mapping[str, Any], has_unconfirmed: bool
) -> tuple[str, bool, tuple[str, ...]]:
    reasons: list[str] = []
    if marker[_KEY_DEGRADED_MARKER_PRESENT]:
        reasons.append(_KEY_DEGRADED_MARKER_PRESENT)
    if marker[_KEY_MARKER_UNREADABLE]:
        reasons.append(_KEY_MARKER_UNREADABLE)
    if marker["live_degraded"]:
        reasons.append("live_hub_degraded")
    if has_unconfirmed:
        reasons.append("unconfirmed_transport_bindings")
    if reasons:
        return HEALTH_DEGRADED, True, tuple(reasons)
    if marker[_KEY_LIVE_STATUS_AVAILABLE]:
        return HEALTH_HEALTHY, False, ()
    return HEALTH_UNKNOWN, False, ()


def _build_compact_health(
    conn: sqlite3.Connection, marker: Mapping[str, Any], deadline: float
) -> WorkspaceHealthSummary:
    cnt_row = execute_bounded(
        conn, _SQL_UNCONFIRMED_BINDINGS_COUNT, (), deadline
    ).fetchone()
    count = int(cnt_row["cnt"]) if cnt_row is not None else 0
    has_unconfirmed = count > 0
    status, degraded, _ = _compute_health_status(marker, has_unconfirmed)
    return WorkspaceHealthSummary(
        health_status=status,
        degraded=degraded,
        session_active_marker_present=bool(marker["session_active_marker_present"]),
        live_status_available=bool(marker[_KEY_LIVE_STATUS_AVAILABLE]),
        has_unconfirmed_bindings=has_unconfirmed,
        unconfirmed_bindings_count=count,
    )


def _build_full_health(
    conn: sqlite3.Connection, marker: Mapping[str, Any], deadline: float
) -> WorkspaceHealth:
    cnt_row = execute_bounded(
        conn, _SQL_UNCONFIRMED_BINDINGS_COUNT, (), deadline
    ).fetchone()
    count = int(cnt_row["cnt"]) if cnt_row is not None else 0
    rows = execute_bounded(
        conn,
        _SQL_UNCONFIRMED_BINDINGS_SUMMARY,
        (MAX_UNCONFIRMED_BINDINGS_SUMMARY,),
        deadline,
    ).fetchall()
    summaries = tuple(_row_to_binding_summary(r) for r in rows)
    has_unconfirmed = count > 0
    status, degraded, reasons = _compute_health_status(marker, has_unconfirmed)
    return WorkspaceHealth(
        health_status=status,
        degraded=degraded,
        degraded_reasons=reasons,
        degraded_marker_present=bool(marker[_KEY_DEGRADED_MARKER_PRESENT]),
        degraded_marker_reason=marker["degraded_marker_reason"],
        marker_unreadable=bool(marker[_KEY_MARKER_UNREADABLE]),
        session_active_marker_present=bool(marker["session_active_marker_present"]),
        live_status_available=bool(marker[_KEY_LIVE_STATUS_AVAILABLE]),
        has_unconfirmed_bindings=has_unconfirmed,
        unconfirmed_bindings_count=count,
        unconfirmed_bindings=summaries,
        unconfirmed_bindings_truncated=(count > len(summaries)),
    )


def _select_sandboxes_page(
    conn: sqlite3.Connection,
    *,
    include_revoked: bool,
    after_addr: str | None,
    limit: int,
    deadline: float,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if not include_revoked:
        clauses.append("status != 'revoked'")
    if after_addr is not None:
        clauses.append("sandbox_addr > ?")
        params.append(after_addr)
    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        f"SELECT {_SQL_SANDBOX_COLUMNS} FROM sandboxes {where_sql} "
        "ORDER BY sandbox_addr ASC LIMIT ?"
    )
    params.append(limit)
    return execute_bounded(conn, sql, tuple(params), deadline).fetchall()


def _select_single_sandbox(
    conn: sqlite3.Connection, addr: str, deadline: float
) -> dict[str, Any] | None:
    sql = f"SELECT {_SQL_SANDBOX_COLUMNS} FROM sandboxes WHERE sandbox_addr = ?"
    return execute_bounded(conn, sql, (addr,), deadline).fetchone()


def _select_threads_for_sandbox(
    conn: sqlite3.Connection,
    *,
    sandbox_addr: str,
    current_inc: str,
    include_historical: bool,
    max_threads: int,
    deadline: float,
) -> tuple[tuple[ProjectedThreadSummary, ...], bool, int]:
    hist_row = execute_bounded(
        conn,
        "SELECT COUNT(*) AS cnt FROM threads WHERE sandbox_addr = ? AND incarnation_id != ?",
        (sandbox_addr, current_inc),
        deadline,
    ).fetchone()
    historical_count = int(hist_row["cnt"]) if hist_row is not None else 0

    inc_filter = "" if include_historical else "AND incarnation_id = ?"
    params: tuple[Any, ...] = (
        (sandbox_addr, max_threads + 1)
        if include_historical
        else (sandbox_addr, current_inc, max_threads + 1)
    )
    sql = f"""
        SELECT
            CASE WHEN typeof(thread_id) = 'text' AND LENGTH(CAST(thread_id AS BLOB)) <= 256
                 THEN thread_id ELSE NULL END AS thread_id,
            CASE WHEN typeof(incarnation_id) = 'text' AND LENGTH(CAST(incarnation_id AS BLOB)) <= 256
                 THEN incarnation_id ELSE NULL END AS incarnation_id,
            SUBSTR(CAST(title AS BLOB), 1, 1024) AS title_blob,
            LENGTH(CAST(title AS BLOB)) AS title_bytes,
            (typeof(title) != 'text') AS title_non_text,
            CASE WHEN typeof(status) = 'text' AND LENGTH(CAST(status AS BLOB)) <= 64
                 THEN status ELSE NULL END AS status,
            CASE WHEN typeof(last_seq) = 'integer' THEN last_seq ELSE NULL END AS last_seq,
            (typeof(last_seq) != 'integer') AS last_seq_malformed,
            CASE WHEN typeof(updated_at) IN ('integer', 'real') THEN updated_at ELSE NULL END AS updated_at,
            (typeof(updated_at) NOT IN ('integer', 'real')) AS updated_at_malformed
        FROM threads
        WHERE sandbox_addr = ? {inc_filter}
        ORDER BY updated_at DESC, thread_id ASC, incarnation_id ASC
        LIMIT ?
    """
    rows = execute_bounded(conn, sql, params, deadline).fetchall()
    items = tuple(_row_to_thread_summary(r, current_inc) for r in rows[:max_threads])
    return items, len(rows) > max_threads, historical_count


def _row_to_thread_summary(
    row: Mapping[str, Any], current_inc: str
) -> ProjectedThreadSummary:
    th_id = require_clean_primary_id(row["thread_id"])
    inc_id = require_clean_primary_id(row[_COL_INCARNATION_ID])
    title, title_trunc, bad_title = decode_single_line_cell(
        row["title_blob"], row["title_bytes"], row["title_non_text"]
    )
    last_seq, bad_seq = safe_int(row["last_seq"], row["last_seq_malformed"])
    updated_at, bad_upd = safe_finite_float(
        row[_COL_UPDATED_AT], row[_COL_UPDATED_AT_MALFORMED]
    )
    status_val, bad_status = sanitize_enum_str(row["status"])
    return ProjectedThreadSummary(
        thread_id=th_id,
        incarnation_id=inc_id,
        is_current_incarnation=(inc_id == current_inc),
        title=title,
        title_truncated=title_trunc,
        status=status_val,
        last_seq=last_seq,
        updated_at=updated_at,
        malformed_metadata=(bad_title or bad_seq or bad_upd or bad_status),
    )


def _select_grant_counts(
    conn: sqlite3.Connection, sandbox_addr: str, deadline: float
) -> tuple[int, int]:
    orch_actor = f"{_ORCH_PREFIX}{sandbox_addr}"
    row = execute_bounded(
        conn,
        """
        SELECT
            COALESCE(SUM(CASE WHEN typeof(r.active) = 'integer' AND r.active = 1
                                   AND t.edge_id IS NULL THEN 1 ELSE 0 END), 0) AS active_cnt,
            COALESCE(SUM(CASE WHEN typeof(r.active) = 'integer' AND r.active = 1
                                   AND t.edge_id IS NULL THEN 0 ELSE 1 END), 0) AS revoked_cnt
        FROM routing_edges r
        LEFT JOIN grant_tombstones t
          ON t.edge_id = r.edge_id AND t.grant_generation = r.grant_generation
        WHERE r.dst_addr = ? OR r.src_actor = ? OR r.src_actor = ?
        """,
        (sandbox_addr, sandbox_addr, orch_actor),
        deadline,
    ).fetchone()
    if row is None:
        return 0, 0
    return int(row["active_cnt"]), int(row["revoked_cnt"])


def _select_outbox_counts(
    conn: sqlite3.Connection, sandbox_addr: str, deadline: float
) -> dict[str, int]:
    rows = execute_bounded(
        conn,
        f"""
        SELECT
            CASE WHEN typeof(o.status) = 'text' AND o.status IN ({_CLOSED_OUTBOX_SQL_LIST})
                 THEN o.status ELSE 'malformed' END AS status,
            COUNT(*) AS cnt
        FROM outbox o
        JOIN event_log e ON e.msg_id = o.msg_id
        WHERE e.dst_addr = ?
        GROUP BY 1
        """,
        (sandbox_addr,),
        deadline,
    ).fetchall()
    return {str(r["status"]): int(r["cnt"]) for r in rows}


def _select_binding_state_and_summary(
    conn: sqlite3.Connection, sandbox_addr: str, incarnation_id: str, deadline: float
) -> tuple[str, UnconfirmedBindingSummary | None]:
    sql = (
        f"SELECT {_BINDING_SELECT_COLUMNS} "
        "FROM external_transport_bindings b "
        "LEFT JOIN sandboxes s ON s.sandbox_addr = b.sandbox_addr "
        "WHERE b.sandbox_addr = ? AND b.incarnation_id = ?"
    )
    row = execute_bounded(conn, sql, (sandbox_addr, incarnation_id), deadline).fetchone()
    if row is None:
        return "none", None
    summary = _row_to_binding_summary(row)
    if summary.malformed_metadata or summary.malformed_identity:
        return _COL_ABORT_REQUESTED, summary
    if summary.terminal_confirmed:
        return "terminal_confirmed", summary
    if summary.abort_requested:
        return _COL_ABORT_REQUESTED, summary
    return "active", summary


def _extract_sandbox_primary_ids(row: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    addr = require_clean_primary_id(row[_COL_SANDBOX_ADDR])
    inc = require_clean_primary_id(row[_COL_INCARNATION_ID])
    worker_ref = require_clean_primary_id(row["worker_ref"])
    inst_name = require_clean_primary_id(row["instance_name"])
    job_id = require_clean_primary_id(row["job_id"])
    try:
        if parse_local_target(addr).canonical != addr:
            raise CoordPolicyError(ERR_REGISTRY_UNREADABLE)
        validate_opaque_token(inc, _COL_INCARNATION_ID)
    except (AddressError, CoordValidationError) as exc:
        raise CoordPolicyError(ERR_REGISTRY_UNREADABLE) from exc
    return addr, inc, worker_ref, inst_name, job_id


def _decode_sandbox_project_id(
    row: Mapping[str, Any], addr: str
) -> tuple[str, str | None, bool, bool, tuple[str, str]]:
    proj_raw = row["project_id_raw"]
    proj_bytes = row["project_id_bytes"] if type(row["project_id_bytes"]) is int else 0
    if proj_raw is not None:
        proj_sha = hashlib.sha256(proj_raw.encode("utf-8")).hexdigest()
        proj_display, proj_trunc = scrub_single_line_str(proj_raw)
        return proj_display, proj_sha, proj_trunc, False, ("exact", proj_raw)
    proj_display, proj_trunc_cell, _ = decode_single_line_cell(
        row["project_id_preview_blob"], proj_bytes, row["project_id_non_text"]
    )
    proj_trunc = proj_trunc_cell or (proj_bytes > MAX_METADATA_TEXT_BYTES)
    return proj_display, None, proj_trunc, True, ("oversize", addr)


def _build_sandbox_node(
    conn: sqlite3.Connection,
    row: Mapping[str, Any],
    *,
    include_historical: bool,
    max_threads: int,
    deadline: float,
) -> tuple[ProjectedSandboxNode, tuple[str, str], UnconfirmedBindingSummary | None]:
    check_deadline_ms(deadline)
    addr, inc, worker_ref, inst_name, job_id = _extract_sandbox_primary_ids(row)
    proj_display, proj_sha, proj_trunc, proj_malformed, group_key = (
        _decode_sandbox_project_id(row, addr)
    )
    proj_name, proj_name_trunc, bad_pname = decode_single_line_cell(
        row["project_name_blob"], row["project_name_bytes"], row["project_name_non_text"]
    )
    branch, branch_trunc, bad_branch = decode_single_line_cell(
        row["branch_blob"], row["branch_bytes"], row["branch_non_text"]
    )
    brief, brief_trunc, bad_brief = decode_single_line_cell(
        row["task_brief_blob"], row["task_brief_bytes"], row["task_brief_non_text"]
    )
    sb_type, bad_type = sanitize_enum_str(row[_COL_SANDBOX_TYPE])
    status_val, bad_status = sanitize_enum_str(row["status"], SANDBOX_LIFECYCLE_STATES)
    parent_addr, bad_parent = sanitize_optional_ref(
        row["parent_addr"], row["parent_addr_malformed"]
    )
    depth, bad_depth = safe_int(row["depth"], row["depth_malformed"])
    created_at, bad_created = safe_finite_float(
        row[_COL_CREATED_AT], row[_COL_CREATED_AT_MALFORMED]
    )
    updated_at, bad_updated = safe_finite_float(
        row[_COL_UPDATED_AT], row[_COL_UPDATED_AT_MALFORMED]
    )
    threads, threads_trunc, hist_cnt = _select_threads_for_sandbox(
        conn,
        sandbox_addr=addr,
        current_inc=inc,
        include_historical=include_historical,
        max_threads=max_threads,
        deadline=deadline,
    )
    active_grants, revoked_grants = _select_grant_counts(conn, addr, deadline)
    outbox_counts = _select_outbox_counts(conn, addr, deadline)
    binding_state, binding_summary = _select_binding_state_and_summary(
        conn, addr, inc, deadline
    )
    malformed = any(
        (
            proj_malformed,
            bad_pname,
            bad_branch,
            bad_brief,
            bad_type,
            bad_status,
            bad_parent,
            bad_depth,
            bad_created,
            bad_updated,
        )
    )
    node = ProjectedSandboxNode(
        sandbox_addr=addr,
        worker_ref=worker_ref,
        instance_name=inst_name,
        incarnation_id=inc,
        job_id=job_id,
        project_id=proj_display,
        project_id_sha256=proj_sha,
        project_id_truncated=proj_trunc,
        project_name=proj_name,
        project_name_truncated=proj_name_trunc,
        branch=branch,
        branch_truncated=branch_trunc,
        sandbox_type=sb_type,
        task_brief=brief,
        task_brief_truncated=brief_trunc,
        status=status_val,
        parent_addr=parent_addr,
        depth=depth,
        created_at=created_at,
        updated_at=updated_at,
        threads=threads,
        threads_truncated=threads_trunc,
        historical_thread_count=hist_cnt,
        active_grant_count=active_grants,
        revoked_grant_count=revoked_grants,
        outbox_counts=outbox_counts,
        binding_state=binding_state,
        malformed_metadata=malformed,
    )
    return node, group_key, binding_summary


def _group_sandboxes_by_project(
    admitted: list[tuple[ProjectedSandboxNode, tuple[str, str]]]
) -> tuple[ProjectedProjectGroup, ...]:
    buckets: dict[tuple[str, str], list[ProjectedSandboxNode]] = {}
    for node, key in admitted:
        buckets.setdefault(key, []).append(node)
    groups: list[ProjectedProjectGroup] = []
    for key in sorted(buckets.keys()):
        nodes = tuple(sorted(buckets[key], key=lambda s: s.sandbox_addr))
        first = nodes[0]
        groups.append(
            ProjectedProjectGroup(
                project_id=first.project_id,
                project_id_sha256=first.project_id_sha256,
                project_id_truncated=first.project_id_truncated,
                project_name=first.project_name,
                sandboxes=nodes,
                malformed_metadata=any(n.malformed_metadata for n in nodes),
            )
        )
    return tuple(groups)


def _binary_search_prefix(
    count: int,
    make_candidate: Callable[[int], Any],
    max_response_bytes: int,
    deadline: float,
) -> Any | None:
    lo = 0
    hi = count
    best: Any | None = None
    while lo <= hi:
        check_deadline_ms(deadline)
        mid = (lo + hi) // 2
        candidate = make_candidate(mid)
        if len(serialize_projection_bytes(candidate)) <= max_response_bytes:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1
    check_deadline_ms(deadline)
    return best


def _fit_health_in_budget(
    health: WorkspaceHealth,
    make_snapshot: Callable[[WorkspaceHealth], Any],
    max_response_bytes: int,
    deadline: float,
) -> WorkspaceHealth | None:
    check_deadline_ms(deadline)
    if len(serialize_projection_bytes(make_snapshot(health))) <= max_response_bytes:
        check_deadline_ms(deadline)
        return health
    total = len(health.unconfirmed_bindings)
    lo = 0
    hi = total
    best: WorkspaceHealth | None = None
    while lo <= hi:
        check_deadline_ms(deadline)
        mid = (lo + hi) // 2
        candidate = replace(
            health,
            unconfirmed_bindings=health.unconfirmed_bindings[:mid],
            unconfirmed_bindings_truncated=(
                health.unconfirmed_bindings_truncated or mid < total
            ),
        )
        if len(serialize_projection_bytes(make_snapshot(candidate))) <= max_response_bytes:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1
    check_deadline_ms(deadline)
    return best


def _shrink_first_sandbox_threads(
    node: ProjectedSandboxNode,
    group_key: tuple[str, str],
    make_snapshot: Callable[[tuple[ProjectedProjectGroup, ...]], Any],
    max_response_bytes: int,
    deadline: float,
) -> ProjectedSandboxNode | None:
    lo = 0
    hi = len(node.threads)
    best: ProjectedSandboxNode | None = None
    while lo <= hi:
        check_deadline_ms(deadline)
        mid = (lo + hi) // 2
        trimmed = replace(
            node,
            threads=node.threads[:mid],
            threads_truncated=(node.threads_truncated or mid < len(node.threads)),
        )
        groups = _group_sandboxes_by_project([(trimmed, group_key)])
        if len(serialize_projection_bytes(make_snapshot(groups))) <= max_response_bytes:
            best = trimmed
            lo = mid + 1
        else:
            hi = mid - 1
    check_deadline_ms(deadline)
    return best


def _shrink_text_item_to_fit(
    item: Any,
    text_field: str,
    trunc_field: str,
    make_page: Callable[[Any], Any],
    max_response_bytes: int,
    deadline: float,
) -> Any | None:
    full_text: str = getattr(item, text_field)
    lo = 0
    hi = len(full_text)
    best: Any | None = None
    while lo <= hi:
        check_deadline_ms(deadline)
        mid = (lo + hi) // 2
        candidate = replace(
            item,
            **{
                text_field: full_text[:mid],
                trunc_field: getattr(item, trunc_field) or (mid < len(full_text)),
            },
        )
        if len(serialize_projection_bytes(make_page(candidate))) <= max_response_bytes:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1
    check_deadline_ms(deadline)
    return best


def _select_edges_for_sandbox(
    conn: sqlite3.Connection, sandbox_addr: str, deadline: float
) -> tuple[tuple[ProjectedRoutingEdge, ...], bool]:
    orch_actor = f"{_ORCH_PREFIX}{sandbox_addr}"
    rows = execute_bounded(
        conn,
        """
        SELECT
            CASE WHEN typeof(r.edge_id) = 'text' AND LENGTH(CAST(r.edge_id AS BLOB)) <= 256
                 THEN r.edge_id ELSE NULL END AS edge_id,
            CASE WHEN typeof(r.src_actor) = 'text' AND LENGTH(CAST(r.src_actor AS BLOB)) <= 256
                 THEN r.src_actor ELSE NULL END AS src_actor,
            CASE WHEN r.src_incarnation IS NULL THEN NULL
                 WHEN typeof(r.src_incarnation) = 'text' AND LENGTH(CAST(r.src_incarnation AS BLOB)) <= 256
                 THEN r.src_incarnation ELSE NULL END AS src_incarnation,
            (r.src_incarnation IS NOT NULL AND (typeof(r.src_incarnation) != 'text' OR LENGTH(CAST(r.src_incarnation AS BLOB)) > 256)) AS src_inc_malformed,
            CASE WHEN typeof(r.dst_addr) = 'text' AND LENGTH(CAST(r.dst_addr AS BLOB)) <= 256
                 THEN r.dst_addr ELSE NULL END AS dst_addr,
            CASE WHEN typeof(r.allowed_threads_json) = 'text' AND LENGTH(CAST(r.allowed_threads_json AS BLOB)) <= 65536
                 THEN CAST(r.allowed_threads_json AS BLOB) ELSE NULL END AS allowed_threads_blob,
            LENGTH(CAST(r.allowed_threads_json AS BLOB)) AS allowed_threads_bytes,
            CASE WHEN typeof(r.allowed_msg_kinds_json) = 'text' AND LENGTH(CAST(r.allowed_msg_kinds_json AS BLOB)) <= 65536
                 THEN CAST(r.allowed_msg_kinds_json AS BLOB) ELSE NULL END AS allowed_msg_kinds_blob,
            LENGTH(CAST(r.allowed_msg_kinds_json AS BLOB)) AS allowed_msg_kinds_bytes,
            CASE WHEN typeof(r.max_rounds) = 'integer' THEN r.max_rounds ELSE NULL END AS max_rounds,
            (typeof(r.max_rounds) != 'integer') AS max_rounds_malformed,
            CASE WHEN typeof(r.turns_used) = 'integer' THEN r.turns_used ELSE NULL END AS turns_used,
            (typeof(r.turns_used) != 'integer') AS turns_used_malformed,
            CASE WHEN typeof(r.rate_limit_rpm) = 'integer' THEN r.rate_limit_rpm ELSE NULL END AS rate_limit_rpm,
            (typeof(r.rate_limit_rpm) != 'integer') AS rate_limit_rpm_malformed,
            CASE WHEN typeof(r.active) = 'integer' AND r.active IN (0, 1) THEN r.active ELSE NULL END AS active,
            (typeof(r.active) != 'integer' OR r.active NOT IN (0, 1)) AS active_malformed,
            CASE WHEN typeof(r.grant_generation) = 'integer' THEN r.grant_generation ELSE NULL END AS grant_generation,
            (typeof(r.grant_generation) != 'integer') AS grant_gen_malformed,
            CASE WHEN typeof(r.created_at) IN ('integer', 'real') THEN r.created_at ELSE NULL END AS created_at,
            (typeof(r.created_at) NOT IN ('integer', 'real')) AS created_at_malformed,
            (t.edge_id IS NOT NULL) AS tombstoned,
            SUBSTR(CAST(t.reason AS BLOB), 1, 1024) AS tomb_reason_blob,
            LENGTH(CAST(t.reason AS BLOB)) AS tomb_reason_bytes,
            (t.edge_id IS NOT NULL AND typeof(t.reason) != 'text') AS tomb_reason_non_text,
            CASE WHEN t.edge_id IS NULL THEN NULL
                 WHEN typeof(t.revoked_at) IN ('integer', 'real') THEN t.revoked_at ELSE NULL END AS tomb_revoked_at,
            (t.edge_id IS NOT NULL AND typeof(t.revoked_at) NOT IN ('integer', 'real')) AS tomb_revoked_malformed
        FROM routing_edges r
        LEFT JOIN grant_tombstones t
          ON t.edge_id = r.edge_id AND t.grant_generation = r.grant_generation
        WHERE r.dst_addr = ? OR r.src_actor = ? OR r.src_actor = ?
        ORDER BY r.edge_id ASC
        LIMIT ?
        """,
        (sandbox_addr, sandbox_addr, orch_actor, MAX_EDGES_PER_SANDBOX + 1),
        deadline,
    ).fetchall()
    return tuple(_row_to_routing_edge(r) for r in rows[:MAX_EDGES_PER_SANDBOX]), (
        len(rows) > MAX_EDGES_PER_SANDBOX
    )


def _row_to_routing_edge(row: Mapping[str, Any]) -> ProjectedRoutingEdge:
    edge_id = require_clean_primary_id(row["edge_id"])
    src_actor = require_clean_primary_id(row["src_actor"])
    dst_addr = require_clean_primary_id(row["dst_addr"])
    src_inc, bad_sinc = sanitize_optional_ref(
        row["src_incarnation"], row["src_inc_malformed"]
    )
    threads, bad_threads = parse_string_list_json(
        row["allowed_threads_blob"], row["allowed_threads_bytes"]
    )
    kinds, bad_kinds = parse_string_list_json(
        row["allowed_msg_kinds_blob"], row["allowed_msg_kinds_bytes"]
    )
    max_rounds, bad_mr = safe_int(row["max_rounds"], row["max_rounds_malformed"])
    turns_used, bad_tu = safe_int(row["turns_used"], row["turns_used_malformed"])
    rpm, bad_rpm = safe_int(row["rate_limit_rpm"], row["rate_limit_rpm_malformed"])
    active, bad_act = safe_bool_flag(row["active"], row["active_malformed"])
    grant_gen, bad_gen = safe_int(
        row["grant_generation"], row["grant_gen_malformed"], default=1
    )
    created_at, bad_cr = safe_finite_float(
        row[_COL_CREATED_AT], row[_COL_CREATED_AT_MALFORMED]
    )
    tombstoned = bool(row["tombstoned"])
    tomb_reason: str | None = None
    tomb_revoked: float | None = None
    bad_tomb = False
    if tombstoned:
        tomb_reason, _, bad_tr = decode_single_line_cell(
            row["tomb_reason_blob"], row["tomb_reason_bytes"], row["tomb_reason_non_text"]
        )
        tomb_revoked, bad_ta = safe_finite_float(
            row["tomb_revoked_at"], row["tomb_revoked_malformed"]
        )
        bad_tomb = bad_tr or bad_ta
    malformed = any(
        (
            bad_threads,
            bad_kinds,
            bad_mr,
            bad_tu,
            bad_rpm,
            bad_act,
            bad_gen,
            bad_cr,
            bad_tomb,
            bad_sinc,
        )
    )
    return ProjectedRoutingEdge(
        edge_id=edge_id,
        src_actor=src_actor,
        src_incarnation=src_inc,
        dst_addr=dst_addr,
        allowed_threads=threads,
        allowed_msg_kinds=kinds,
        max_rounds=max_rounds,
        turns_used=turns_used,
        rate_limit_rpm=rpm,
        active=active,
        grant_generation=grant_gen,
        tombstoned=tombstoned,
        tombstone_reason=tomb_reason,
        tombstone_revoked_at=tomb_revoked,
        created_at=created_at,
        malformed_metadata=malformed,
    )


def _select_budget_safe(
    conn: sqlite3.Connection, sandbox_addr: str, incarnation_id: str, deadline: float
) -> tuple[ProjectedSubtreeBudget | None, bool]:
    row = execute_bounded(
        conn,
        """
        SELECT
            CASE WHEN typeof(budget_json) = 'text' AND LENGTH(CAST(budget_json AS BLOB)) <= 65536
                 THEN CAST(budget_json AS BLOB) ELSE NULL END AS budget_blob,
            LENGTH(CAST(budget_json AS BLOB)) AS budget_bytes
        FROM sandbox_budgets
        WHERE sandbox_addr = ? AND incarnation_id = ?
        """,
        (sandbox_addr, incarnation_id),
        deadline,
    ).fetchone()
    if row is None:
        return None, False
    return parse_budget_json(row["budget_blob"], row["budget_bytes"])


def _select_thread_event_log_rows(
    conn: sqlite3.Connection,
    *,
    sandbox_addr: str,
    incarnation_id: str,
    thread_id: str,
    parsed_cursor: tuple[int, int] | None,
    limit: int,
    deadline: float,
) -> list[dict[str, Any]]:
    seq_clause = "AND seq > ?" if parsed_cursor is not None else ""
    params: tuple[Any, ...] = (
        (sandbox_addr, incarnation_id, thread_id, parsed_cursor[0], limit)
        if parsed_cursor is not None
        else (sandbox_addr, incarnation_id, thread_id, limit)
    )
    sql = f"""
        SELECT
            seq,
            CASE WHEN typeof(msg_id) = 'text' AND LENGTH(CAST(msg_id AS BLOB)) <= 256
                 THEN msg_id ELSE NULL END AS msg_id,
            CASE WHEN typeof(src_role) = 'text' AND LENGTH(CAST(src_role AS BLOB)) <= 64
                 THEN src_role ELSE NULL END AS src_role,
            CASE WHEN typeof(src_actor) = 'text' AND LENGTH(CAST(src_actor AS BLOB)) <= 256
                 THEN src_actor ELSE NULL END AS src_actor,
            CASE WHEN typeof(trust_class) = 'text' AND LENGTH(CAST(trust_class AS BLOB)) <= 64
                 THEN trust_class ELSE NULL END AS trust_class,
            CASE WHEN typeof(msg_kind) = 'text' AND LENGTH(CAST(msg_kind AS BLOB)) <= 64
                 THEN msg_kind ELSE NULL END AS msg_kind,
            SUBSTR(CAST(body_text AS BLOB), 1, {MAX_ITEM_TEXT_BYTES}) AS text_blob,
            LENGTH(CAST(body_text AS BLOB)) AS original_text_bytes,
            (typeof(body_text) != 'text') AS text_non_text,
            CASE WHEN typeof(edge_id) = 'text' AND LENGTH(CAST(edge_id AS BLOB)) <= 256
                 THEN edge_id ELSE NULL END AS edge_id,
            CASE WHEN typeof(edge_turn_seq) = 'integer' THEN edge_turn_seq ELSE NULL END AS edge_turn_seq,
            (typeof(edge_turn_seq) != 'integer') AS edge_turn_seq_malformed,
            CASE WHEN in_reply_to IS NULL THEN NULL
                 WHEN typeof(in_reply_to) = 'text' AND LENGTH(CAST(in_reply_to AS BLOB)) <= 256
                 THEN in_reply_to ELSE NULL END AS in_reply_to,
            (in_reply_to IS NOT NULL AND (typeof(in_reply_to) != 'text' OR LENGTH(CAST(in_reply_to AS BLOB)) > 256)) AS in_reply_to_malformed,
            CASE WHEN typeof(artifact_refs_json) = 'text' AND LENGTH(CAST(artifact_refs_json AS BLOB)) <= 65536
                 THEN CAST(artifact_refs_json AS BLOB) ELSE NULL END AS artifact_refs_blob,
            LENGTH(CAST(artifact_refs_json AS BLOB)) AS artifact_refs_bytes,
            CASE WHEN typeof(created_at) IN ('integer', 'real') THEN created_at ELSE NULL END AS created_at,
            (typeof(created_at) NOT IN ('integer', 'real')) AS created_at_malformed
        FROM event_log
        WHERE dst_addr = ? AND dst_incarnation = ? AND dst_thread_id = ? {seq_clause}
        ORDER BY seq ASC
        LIMIT ?
    """
    return execute_bounded(conn, sql, params, deadline).fetchall()


def _select_thread_stream_rows(
    conn: sqlite3.Connection,
    *,
    sandbox_addr: str,
    incarnation_id: str,
    thread_id: str,
    parsed_cursor: tuple[int, int] | None,
    limit: int,
    deadline: float,
) -> list[dict[str, Any]]:
    if parsed_cursor is None:
        seq_clause = ""
        params: tuple[Any, ...] = (sandbox_addr, incarnation_id, thread_id, limit)
    else:
        op = ">=" if parsed_cursor[1] == 0 else ">"
        seq_clause = f"AND seq {op} ?"
        params = (sandbox_addr, incarnation_id, thread_id, parsed_cursor[0], limit)
    sql = f"""
        SELECT
            seq,
            CASE WHEN typeof(event_type) = 'text' AND LENGTH(CAST(event_type AS BLOB)) <= 64
                 THEN event_type ELSE NULL END AS event_type,
            CASE WHEN typeof(seq_hint) = 'integer' THEN seq_hint ELSE NULL END AS seq_hint,
            (typeof(seq_hint) != 'integer') AS seq_hint_malformed,
            CASE WHEN message_id IS NULL THEN NULL
                 WHEN typeof(message_id) = 'text' AND LENGTH(CAST(message_id AS BLOB)) <= 256
                 THEN message_id ELSE NULL END AS message_id,
            (message_id IS NOT NULL AND (typeof(message_id) != 'text' OR LENGTH(CAST(message_id AS BLOB)) > 256)) AS message_id_malformed,
            CASE WHEN dispatch_msg_id IS NULL THEN NULL
                 WHEN typeof(dispatch_msg_id) = 'text' AND LENGTH(CAST(dispatch_msg_id AS BLOB)) <= 256
                 THEN dispatch_msg_id ELSE NULL END AS dispatch_msg_id,
            (dispatch_msg_id IS NOT NULL AND (typeof(dispatch_msg_id) != 'text' OR LENGTH(CAST(dispatch_msg_id AS BLOB)) > 256)) AS dispatch_msg_id_malformed,
            SUBSTR(CAST(text AS BLOB), 1, {MAX_ITEM_TEXT_BYTES}) AS text_blob,
            LENGTH(CAST(text AS BLOB)) AS original_text_bytes,
            (typeof(text) != 'text') AS text_non_text,
            CASE WHEN typeof(text) = 'text' AND LENGTH(CAST(text AS BLOB)) <= {MAX_HASH_TEXT_BYTES}
                 THEN CAST(text AS BLOB) ELSE NULL END AS text_for_hash_blob,
            CASE WHEN file_path IS NULL THEN NULL
                 WHEN typeof(file_path) = 'text' AND LENGTH(CAST(file_path AS BLOB)) <= 512
                 THEN file_path ELSE NULL END AS file_path,
            (file_path IS NOT NULL AND (typeof(file_path) != 'text' OR LENGTH(CAST(file_path AS BLOB)) > 512)) AS file_path_malformed,
            CASE WHEN typeof(detail_json) = 'text' AND LENGTH(CAST(detail_json AS BLOB)) <= 65536
                 THEN CAST(detail_json AS BLOB) ELSE NULL END AS detail_blob,
            LENGTH(CAST(detail_json AS BLOB)) AS detail_bytes,
            CASE WHEN badge IS NULL THEN NULL
                 WHEN typeof(badge) = 'text' AND LENGTH(CAST(badge AS BLOB)) <= 64
                 THEN badge ELSE NULL END AS badge,
            (badge IS NOT NULL AND (typeof(badge) != 'text' OR LENGTH(CAST(badge AS BLOB)) > 64)) AS badge_malformed,
            CASE WHEN typeof(created_at) IN ('integer', 'real') THEN created_at ELSE NULL END AS created_at,
            (typeof(created_at) NOT IN ('integer', 'real')) AS created_at_malformed
        FROM stream_events
        WHERE sandbox_addr = ? AND incarnation_id = ? AND thread_id = ? {seq_clause}
        ORDER BY seq ASC
        LIMIT ?
    """
    return execute_bounded(conn, sql, params, deadline).fetchall()


def _require_nonneg_seq(val: Any) -> int:
    if type(val) is not int or val < 0:
        raise CoordPolicyError(ERR_REGISTRY_UNREADABLE)
    return val


def _project_event_log_row(
    row: Mapping[str, Any], *, sandbox_addr: str, incarnation_id: str, thread_id: str
) -> ProjectedThreadEvent:
    seq = _require_nonneg_seq(row["seq"])
    msg_id = require_clean_primary_id(row["msg_id"])
    src_role, bad_role = sanitize_optional_ref(row["src_role"])
    src_actor, bad_actor = sanitize_optional_ref(row["src_actor"])
    msg_kind, bad_kind = sanitize_optional_ref(row["msg_kind"])
    edge_id, bad_edge = sanitize_optional_ref(row["edge_id"])
    in_reply_to, bad_reply = sanitize_optional_ref(
        row["in_reply_to"], row["in_reply_to_malformed"]
    )
    raw_orig = row[_COL_ORIGINAL_TEXT_BYTES]
    orig_bytes = raw_orig if type(raw_orig) is int and raw_orig >= 0 else 0
    decoded, inspected_len, bad_utf8 = decode_bounded_blob(row["text_blob"], orig_bytes)
    suffix_uninspected = orig_bytes > inspected_len
    artifacts, bad_arts = parse_artifact_refs_json(
        row["artifact_refs_blob"], row["artifact_refs_bytes"]
    )
    edge_turn_seq, bad_ets = safe_int(
        row["edge_turn_seq"], row["edge_turn_seq_malformed"]
    )
    created_at, bad_cr = safe_finite_float(
        row[_COL_CREATED_AT], row[_COL_CREATED_AT_MALFORMED]
    )
    tc_val, bad_tc_chars = sanitize_optional_ref(row["trust_class"])
    tc_valid = tc_val in _TRUST_AUTHORITY_RANK
    eff_badge = (
        _TRUST_CLASS_TO_BADGE[TrustClass(tc_val)].value if tc_valid and tc_val else None
    )
    actor_verified = src_actor if (tc_valid and src_actor is not None) else None
    auth_rank = _TRUST_AUTHORITY_RANK.get(tc_val or "", 0) if actor_verified else 0
    untrusted = (not actor_verified) or (tc_val not in _TRUSTED_TRUST_CLASSES)
    malformed = any(
        (
            bad_utf8,
            bool(row["text_non_text"]),
            bad_arts,
            bad_ets,
            bad_cr,
            bad_role,
            bad_actor,
            bad_kind,
            bad_edge,
            bad_reply,
            bad_tc_chars,
            not tc_valid,
            src_actor is None,
        )
    )
    return ProjectedThreadEvent(
        source=SOURCE_EVENT_LOG,
        source_rank=0,
        seq=seq,
        event_type="envelope",
        sandbox_addr=sandbox_addr,
        incarnation_id=incarnation_id,
        thread_id=thread_id,
        msg_id=msg_id,
        message_id=msg_id,
        dispatch_msg_id=None,
        src_role=src_role,
        src_actor=src_actor,
        verified_actor=actor_verified,
        trust_class=tc_val if tc_valid else None,
        msg_kind=msg_kind,
        raw_badge=eff_badge,
        effective_badge=eff_badge,
        authority_rank=auth_rank,
        untrusted_content=untrusted,
        provenance_anomaly=False,
        anomaly_reason=None,
        text=decoded,
        text_truncated=suffix_uninspected,
        text_suffix_uninspected=suffix_uninspected,
        original_text_bytes=orig_bytes,
        has_control_or_bidi=(bad_utf8 or has_multiline_control_or_bidi(decoded)),
        file_path=None,
        in_reply_to=in_reply_to,
        edge_id=edge_id,
        edge_turn_seq=edge_turn_seq,
        seq_hint=None,
        artifact_refs=artifacts,
        detail={},
        created_at=created_at,
        malformed_metadata=malformed,
    )


def _project_stream_row(
    conn: sqlite3.Connection,
    row: Mapping[str, Any],
    *,
    sandbox_addr: str,
    incarnation_id: str,
    thread_id: str,
    deadline: float,
) -> ProjectedThreadEvent:
    seq = _require_nonneg_seq(row["seq"])
    ev_type, bad_ev_type = sanitize_enum_str(row["event_type"], STREAM_EVENT_TYPES)
    if bad_ev_type:
        raise CoordPolicyError(ERR_REGISTRY_UNREADABLE)
    raw_orig = row[_COL_ORIGINAL_TEXT_BYTES]
    orig_bytes = raw_orig if type(raw_orig) is int and raw_orig >= 0 else 0
    decoded, inspected_len, bad_utf8 = decode_bounded_blob(row["text_blob"], orig_bytes)
    suffix_uninspected = orig_bytes > inspected_len
    detail, bad_detail = parse_detail_json(row["detail_blob"], row["detail_bytes"])
    seq_hint, bad_hint = safe_int(row["seq_hint"], row["seq_hint_malformed"])
    created_at, bad_cr = safe_finite_float(
        row[_COL_CREATED_AT], row[_COL_CREATED_AT_MALFORMED]
    )
    msg_id, bad_mid = sanitize_optional_ref(row["message_id"], row["message_id_malformed"])
    disp_id, bad_disp = sanitize_optional_ref(
        row["dispatch_msg_id"], row["dispatch_msg_id_malformed"]
    )
    file_path, bad_fp = sanitize_optional_ref(row["file_path"], row["file_path_malformed"])
    clean_raw_badge, bad_badge = sanitize_optional_ref(row["badge"], row["badge_malformed"])
    eff_badge, verified_actor, auth_rank, untrusted, anomaly, anomaly_reason = (
        evaluate_stream_provenance(
            conn,
            row,
            execute_fn=execute_bounded,
            check_deadline_fn=check_deadline_ms,
            event_type=ev_type,
            sandbox_addr=sandbox_addr,
            incarnation_id=incarnation_id,
            thread_id=thread_id,
            deadline=deadline,
        )
    )
    malformed = any(
        (
            bad_utf8,
            bool(row["text_non_text"]),
            bad_detail,
            bad_hint,
            bad_cr,
            bad_mid,
            bad_disp,
            bad_fp,
            bad_badge,
        )
    )
    return ProjectedThreadEvent(
        source=SOURCE_STREAM_EVENT,
        source_rank=1,
        seq=seq,
        event_type=ev_type,
        sandbox_addr=sandbox_addr,
        incarnation_id=incarnation_id,
        thread_id=thread_id,
        msg_id=None,
        message_id=msg_id,
        dispatch_msg_id=disp_id,
        src_role=None,
        src_actor=None,
        verified_actor=verified_actor,
        trust_class=None,
        msg_kind=None,
        raw_badge=clean_raw_badge,
        effective_badge=eff_badge,
        authority_rank=auth_rank,
        untrusted_content=untrusted,
        provenance_anomaly=anomaly,
        anomaly_reason=anomaly_reason,
        text=decoded,
        text_truncated=suffix_uninspected,
        text_suffix_uninspected=suffix_uninspected,
        original_text_bytes=orig_bytes,
        has_control_or_bidi=(bad_utf8 or has_multiline_control_or_bidi(decoded)),
        file_path=file_path,
        in_reply_to=None,
        edge_id=None,
        edge_turn_seq=None,
        seq_hint=seq_hint,
        artifact_refs=(),
        detail=detail,
        created_at=created_at,
        malformed_metadata=malformed,
    )


def _merge_sorted_events(
    ev_rows: list[dict[str, Any]], st_rows: list[dict[str, Any]]
) -> list[tuple[int, int, dict[str, Any]]]:
    tagged: list[tuple[int, int, dict[str, Any]]] = []
    for rank, bucket in ((0, ev_rows), (1, st_rows)):
        for row in bucket:
            seq = _require_nonneg_seq(row["seq"])
            tagged.append((seq, rank, row))
    tagged.sort(key=lambda item: (item[0], item[1]))
    return tagged


def _select_mailbox_rows(
    conn: sqlite3.Connection,
    *,
    sandbox_addr: str,
    statuses: tuple[str, ...] | None,
    parsed_cursor: tuple[int, str] | None,
    limit: int,
    deadline: float,
) -> list[dict[str, Any]]:
    clauses = ["e.dst_addr = ?"]
    params: list[Any] = [sandbox_addr]
    if statuses is not None:
        placeholders = ",".join("?" for _ in statuses)
        clauses.append(f"o.status IN ({placeholders})")
        params.extend(statuses)
    if parsed_cursor is not None:
        clauses.append("(o.seq > ? OR (o.seq = ? AND o.msg_id > ?))")
        params.extend([parsed_cursor[0], parsed_cursor[0], parsed_cursor[1]])
    where_sql = " AND ".join(clauses)
    sql = f"""
        SELECT
            CASE WHEN typeof(o.seq) = 'integer' THEN o.seq ELSE NULL END AS seq,
            (typeof(o.seq) != 'integer') AS seq_malformed,
            CASE WHEN typeof(o.msg_id) = 'text' AND LENGTH(CAST(o.msg_id AS BLOB)) <= 256
                 THEN o.msg_id ELSE NULL END AS msg_id,
            CASE WHEN typeof(o.edge_id) = 'text' AND LENGTH(CAST(o.edge_id AS BLOB)) <= 256
                 THEN o.edge_id ELSE NULL END AS edge_id,
            CASE WHEN typeof(o.grant_generation) = 'integer' THEN o.grant_generation ELSE NULL END AS grant_generation,
            (typeof(o.grant_generation) != 'integer') AS grant_gen_malformed,
            CASE WHEN typeof(e.src_actor) = 'text' AND LENGTH(CAST(e.src_actor AS BLOB)) <= 256
                 THEN e.src_actor ELSE NULL END AS src_actor,
            CASE WHEN typeof(e.src_role) = 'text' AND LENGTH(CAST(e.src_role AS BLOB)) <= 64
                 THEN e.src_role ELSE NULL END AS src_role,
            CASE WHEN o.src_incarnation IS NULL THEN NULL
                 WHEN typeof(o.src_incarnation) = 'text' AND LENGTH(CAST(o.src_incarnation AS BLOB)) <= 256
                 THEN o.src_incarnation ELSE NULL END AS src_incarnation,
            (o.src_incarnation IS NOT NULL AND (typeof(o.src_incarnation) != 'text' OR LENGTH(CAST(o.src_incarnation AS BLOB)) > 256)) AS src_inc_malformed,
            CASE WHEN typeof(src_sb.status) = 'text' AND LENGTH(CAST(src_sb.status AS BLOB)) <= 64
                 THEN src_sb.status ELSE NULL END AS src_sandbox_status,
            CASE WHEN typeof(src_sb.incarnation_id) = 'text' AND LENGTH(CAST(src_sb.incarnation_id AS BLOB)) <= 256
                 THEN src_sb.incarnation_id ELSE NULL END AS src_current_incarnation,
            CASE WHEN typeof(o.dst_incarnation) = 'text' AND LENGTH(CAST(o.dst_incarnation AS BLOB)) <= 256
                 THEN o.dst_incarnation ELSE NULL END AS dst_incarnation,
            CASE WHEN typeof(o.thread_id) = 'text' AND LENGTH(CAST(o.thread_id AS BLOB)) <= 256
                 THEN o.thread_id ELSE NULL END AS thread_id,
            CASE WHEN typeof(e.trust_class) = 'text' AND LENGTH(CAST(e.trust_class AS BLOB)) <= 64
                 THEN e.trust_class ELSE NULL END AS trust_class,
            CASE WHEN typeof(e.msg_kind) = 'text' AND LENGTH(CAST(e.msg_kind AS BLOB)) <= 64
                 THEN e.msg_kind ELSE NULL END AS msg_kind,
            CASE WHEN typeof(o.priority) = 'integer' THEN o.priority ELSE NULL END AS priority,
            (typeof(o.priority) != 'integer') AS priority_malformed,
            CASE WHEN typeof(o.status) = 'text' AND LENGTH(CAST(o.status AS BLOB)) <= 64
                 THEN o.status ELSE NULL END AS status,
            CASE WHEN typeof(o.body_bytes) = 'integer' THEN o.body_bytes ELSE NULL END AS body_bytes,
            (typeof(o.body_bytes) != 'integer') AS body_bytes_malformed,
            CASE WHEN typeof(o.attempts) = 'integer' THEN o.attempts ELSE NULL END AS attempts,
            (typeof(o.attempts) != 'integer') AS attempts_malformed,
            CASE WHEN o.stream_id IS NULL THEN NULL
                 WHEN typeof(o.stream_id) = 'text' AND LENGTH(CAST(o.stream_id AS BLOB)) <= 256
                 THEN o.stream_id ELSE NULL END AS stream_id,
            (o.stream_id IS NOT NULL AND (typeof(o.stream_id) != 'text' OR LENGTH(CAST(o.stream_id AS BLOB)) > 256)) AS stream_id_malformed,
            SUBSTR(CAST(o.detail AS BLOB), 1, 1024) AS detail_blob,
            LENGTH(CAST(o.detail AS BLOB)) AS detail_bytes,
            (typeof(o.detail) != 'text') AS detail_non_text,
            CASE WHEN r.edge_id IS NULL THEN NULL
                 WHEN typeof(r.active) = 'integer' AND r.active IN (0, 1) THEN r.active ELSE NULL END AS grant_active,
            (r.edge_id IS NOT NULL AND (typeof(r.active) != 'integer' OR r.active NOT IN (0, 1))) AS grant_active_malformed,
            (t_out.edge_id IS NOT NULL OR t_cur.edge_id IS NOT NULL) AS grant_tombstoned,
            CASE WHEN typeof(o.updated_at) IN ('integer', 'real') THEN o.updated_at ELSE NULL END AS updated_at,
            (typeof(o.updated_at) NOT IN ('integer', 'real')) AS updated_at_malformed
        FROM outbox o
        JOIN event_log e ON e.msg_id = o.msg_id
        LEFT JOIN routing_edges r ON r.edge_id = o.edge_id
        LEFT JOIN grant_tombstones t_out
          ON t_out.edge_id = o.edge_id AND t_out.grant_generation = o.grant_generation
        LEFT JOIN grant_tombstones t_cur
          ON t_cur.edge_id = o.edge_id AND r.edge_id IS NOT NULL AND t_cur.grant_generation = r.grant_generation
        LEFT JOIN sandboxes src_sb
          ON src_sb.sandbox_addr = CASE
              WHEN typeof(e.src_actor) = 'text' AND SUBSTR(e.src_actor, 1, 13) = 'orchestrator:'
                   THEN SUBSTR(e.src_actor, 14)
              ELSE e.src_actor END
        WHERE {where_sql}
        ORDER BY o.seq ASC, o.msg_id ASC
        LIMIT ?
    """
    params.append(limit)
    return execute_bounded(conn, sql, tuple(params), deadline).fetchall()


def _extract_mailbox_primary_keys(row: Mapping[str, Any]) -> tuple[int, str, str, str, str]:
    if bool(row["seq_malformed"]):
        raise CoordPolicyError(ERR_REGISTRY_UNREADABLE)
    seq = _require_nonneg_seq(row["seq"])
    msg_id = require_clean_primary_id(row["msg_id"])
    edge_id = require_clean_primary_id(row["edge_id"])
    dst_inc = require_clean_primary_id(row["dst_incarnation"])
    thread_id = require_clean_primary_id(row["thread_id"])
    try:
        validate_opaque_token(msg_id, "msg_id")
    except (AddressError, CoordValidationError) as exc:
        raise CoordPolicyError(ERR_REGISTRY_UNREADABLE) from exc
    return seq, msg_id, edge_id, dst_inc, thread_id


def _row_to_mailbox_entry(row: Mapping[str, Any]) -> ProjectedMailboxEntry:
    seq, msg_id, edge_id, dst_inc, thread_id = _extract_mailbox_primary_keys(row)
    src_actor, bad_sa = sanitize_optional_ref(row["src_actor"])
    src_role, bad_sr = sanitize_optional_ref(row["src_role"])
    src_inc, bad_si = sanitize_optional_ref(row["src_incarnation"], row["src_inc_malformed"])
    src_sb_status, bad_sbs = sanitize_optional_ref(row["src_sandbox_status"])
    src_cur_inc, bad_sci = sanitize_optional_ref(row["src_current_incarnation"])
    trust_class, bad_tc = sanitize_optional_ref(row["trust_class"])
    msg_kind, bad_mk = sanitize_optional_ref(row["msg_kind"])
    stream_id, bad_sid = sanitize_optional_ref(row["stream_id"], row["stream_id_malformed"])
    status_val, bad_status = sanitize_enum_str(row["status"], _VALID_OUTBOX_STATUSES)

    grant_gen, bad_gen = safe_int(
        row["grant_generation"], row["grant_gen_malformed"], default=1
    )
    priority, bad_pri = safe_int(row["priority"], row["priority_malformed"])
    body_bytes, bad_bb = safe_int(row["body_bytes"], row["body_bytes_malformed"])
    attempts, bad_att = safe_int(row["attempts"], row["attempts_malformed"])
    detail, detail_trunc, bad_det = decode_single_line_cell(
        row["detail_blob"], row["detail_bytes"], row["detail_non_text"]
    )
    updated_at, bad_upd = safe_finite_float(
        row[_COL_UPDATED_AT], row[_COL_UPDATED_AT_MALFORMED]
    )
    grant_active = None if row["grant_active"] is None else (row["grant_active"] == 1)
    malformed = any(
        (
            bad_gen,
            bad_pri,
            bad_bb,
            bad_att,
            bad_det,
            bad_upd,
            bad_sa,
            bad_sr,
            bad_si,
            bad_sbs,
            bad_sci,
            bad_tc,
            bad_mk,
            bad_sid,
            bad_status,
            bool(row["grant_active_malformed"]),
        )
    )
    return ProjectedMailboxEntry(
        seq=seq,
        msg_id=msg_id,
        edge_id=edge_id,
        grant_generation=grant_gen,
        src_actor=src_actor,
        src_role=src_role,
        src_incarnation=src_inc,
        src_sandbox_status=src_sb_status,
        src_current_incarnation=src_cur_inc,
        dst_incarnation=dst_inc,
        thread_id=thread_id,
        trust_class=trust_class,
        msg_kind=msg_kind,
        priority=priority,
        status=status_val,
        body_bytes=body_bytes,
        attempts=attempts,
        stream_id=stream_id,
        detail=detail,
        detail_truncated=detail_trunc,
        grant_active=grant_active,
        grant_tombstoned=bool(row["grant_tombstoned"]),
        updated_at=updated_at,
        malformed_metadata=malformed,
    )


def _validate_sandbox_incarnation(sb_row: Mapping[str, Any]) -> str:
    inc = require_clean_primary_id(sb_row[_COL_INCARNATION_ID])
    try:
        validate_opaque_token(inc, _COL_INCARNATION_ID)
    except (AddressError, CoordValidationError) as exc:
        raise CoordPolicyError(ERR_REGISTRY_UNREADABLE) from exc
    return inc


class ReadOnlyProjectionService:
    """Operator-only read-only snapshot projection over $STATE/registry.sqlite."""

    def __init__(
        self,
        state_dir: Path | str,
        *,
        sandbox_root: Path | str | None = None,
        session_validator: Callable[[PrincipalCtx, str, int], bool] | None = None,
        live_authority_checker: Callable[[PrincipalCtx], bool] | None = None,
        live_degraded_checker: Callable[[], bool] | None = None,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._sandbox_root = Path(sandbox_root) if sandbox_root is not None else None
        self._session_validator = session_validator
        self._live_authority_checker = live_authority_checker
        self._live_degraded_checker = live_degraded_checker

    def _preflight(
        self, caller: object, read_session_id: object, session_generation: object
    ) -> tuple[PrincipalCtx, ReadSessionEcho | None, Path, dict[str, Any]]:
        principal = _authorize_operator_caller(caller)
        session_echo = _validate_session_args(
            read_session_id,
            session_generation,
            has_validator=(self._session_validator is not None),
        )
        _enforce_authority_fences(
            principal,
            session_echo,
            self._session_validator,
            self._live_authority_checker,
        )
        trusted_dir, db_path = verify_state_dir_and_db_readonly(
            self._state_dir, self._sandbox_root
        )
        marker_health = read_marker_health(trusted_dir, self._live_degraded_checker)
        return principal, session_echo, db_path, marker_health

    def _postflight(
        self, principal: PrincipalCtx, session_echo: ReadSessionEcho | None
    ) -> None:
        _enforce_authority_fences(
            principal,
            session_echo,
            self._session_validator,
            self._live_authority_checker,
        )

    def get_workspace_tree(
        self,
        caller: PrincipalCtx,
        *,
        include_revoked: bool = True,
        include_historical_incarnations: bool = False,
        after_cursor: str | None = None,
        sandbox_limit: int = MAX_SANDBOXES_PER_PAGE,
        max_threads_per_sandbox: int = MAX_THREADS_PER_SANDBOX,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_read_ms: int = DEFAULT_MAX_READ_MS,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> WorkspaceTreeSnapshot:
        """Return a bounded Project -> Sandbox -> Thread snapshot page."""
        _authorize_operator_caller(caller)
        inc_rev = _validate_bool(include_revoked, "include_revoked")
        inc_hist = _validate_bool(
            include_historical_incarnations, "include_historical_incarnations"
        )
        sb_limit = _validate_int_range(
            sandbox_limit, "sandbox_limit", 1, MAX_SANDBOXES_PER_PAGE
        )
        th_limit = _validate_int_range(
            max_threads_per_sandbox,
            "max_threads_per_sandbox",
            0,
            MAX_THREADS_PER_SANDBOX,
        )
        max_bytes = _validate_int_range(
            max_response_bytes,
            _PARAM_MAX_RESPONSE_BYTES,
            MIN_RESPONSE_BYTES,
            MAX_RESPONSE_BYTES,
        )
        read_ms = _validate_int_range(
            max_read_ms, _PARAM_MAX_READ_MS, MIN_READ_MS, MAX_READ_MS
        )
        scope_hash = compute_scope_hash(
            OP_TREE,
            include_revoked=inc_rev,
            include_historical_incarnations=inc_hist,
        )
        after_addr = decode_tree_cursor(after_cursor, expected_scope_hash=scope_hash)
        principal, session_echo, db_path, marker = self._preflight(
            caller, read_session_id, session_generation
        )

        deadline = time.monotonic() + (read_ms / 1000.0)
        with open_readonly_snapshot(db_path, deadline=deadline) as conn:
            snapshot_seq = read_seq_counter(conn, deadline)
            raw_health = _build_full_health(conn, marker, deadline)
            sb_rows = _select_sandboxes_page(
                conn,
                include_revoked=inc_rev,
                after_addr=after_addr,
                limit=sb_limit + 1,
                deadline=deadline,
            )
            ctx = _TreePackCtx(
                snapshot_seq=snapshot_seq,
                sb_limit=sb_limit,
                include_historical=inc_hist,
                max_threads=th_limit,
                scope_hash=scope_hash,
                max_bytes=max_bytes,
                session_echo=session_echo,
                deadline=deadline,
            )
            snapshot = self._pack_workspace_tree(conn, raw_health, sb_rows, ctx)
            check_deadline_ms(deadline)

        self._postflight(principal, session_echo)
        return snapshot

    def _fit_first_tree_sandbox(
        self,
        node: ProjectedSandboxNode,
        group_key: tuple[str, str],
        health: WorkspaceHealth,
        make_tree: Callable[
            [WorkspaceHealth, tuple[ProjectedProjectGroup, ...], bool, str | None],
            WorkspaceTreeSnapshot,
        ],
        more_after: bool,
        cursor_after: str | None,
        ctx: _TreePackCtx,
    ) -> WorkspaceTreeSnapshot:
        shrunk = _shrink_first_sandbox_threads(
            node,
            group_key,
            partial(make_tree, health, more=more_after, cursor=cursor_after),
            ctx.max_bytes,
            ctx.deadline,
        )
        cur_health = health
        if shrunk is None and cur_health.unconfirmed_bindings:
            cur_health = replace(
                cur_health,
                unconfirmed_bindings=_EMPTY_BINDINGS,
                unconfirmed_bindings_truncated=True,
            )
            shrunk = _shrink_first_sandbox_threads(
                node,
                group_key,
                partial(make_tree, cur_health, more=more_after, cursor=cursor_after),
                ctx.max_bytes,
                ctx.deadline,
            )
        if shrunk is None:
            raise CoordValidationError(_ERR_BUDGET_ITEM)
        return make_tree(
            cur_health,
            _group_sandboxes_by_project([(shrunk, group_key)]),
            more_after,
            cursor_after,
        )

    def _pack_workspace_tree(
        self,
        conn: sqlite3.Connection,
        raw_health: WorkspaceHealth,
        sb_rows: list[dict[str, Any]],
        ctx: _TreePackCtx,
    ) -> WorkspaceTreeSnapshot:
        def _make_tree(
            cur_health: WorkspaceHealth,
            groups: tuple[ProjectedProjectGroup, ...],
            more: bool,
            cursor: str | None,
        ) -> WorkspaceTreeSnapshot:
            return WorkspaceTreeSnapshot(
                schema_version=PROJECTION_SCHEMA_VERSION,
                snapshot_seq=ctx.snapshot_seq,
                health=cur_health,
                projects=groups,
                has_more=more,
                next_cursor=cursor,
                read_session=ctx.session_echo,
            )

        health = _fit_health_in_budget(
            raw_health,
            lambda h: _make_tree(h, _EMPTY_PROJECTS, False, None),
            ctx.max_bytes,
            ctx.deadline,
        )
        if health is None:
            raise CoordValidationError(_ERR_BUDGET_ENVELOPE)

        total_rows = len(sb_rows)
        admitted: list[tuple[ProjectedSandboxNode, tuple[str, str]]] = []
        last_page = _make_tree(health, _EMPTY_PROJECTS, False, None)

        for idx, row in enumerate(sb_rows[: ctx.sb_limit]):
            check_deadline_ms(ctx.deadline)
            node, group_key, _ = _build_sandbox_node(
                conn,
                row,
                include_historical=ctx.include_historical,
                max_threads=ctx.max_threads,
                deadline=ctx.deadline,
            )
            more_after = (idx + 1) < total_rows
            cursor_after = (
                encode_tree_cursor(scope_hash=ctx.scope_hash, sandbox_addr=node.sandbox_addr)
                if more_after
                else None
            )
            candidate = _make_tree(
                health,
                _group_sandboxes_by_project([*admitted, (node, group_key)]),
                more_after,
                cursor_after,
            )
            if len(serialize_projection_bytes(candidate)) <= ctx.max_bytes:
                admitted.append((node, group_key))
                last_page = candidate
                continue

            if not admitted:
                return self._fit_first_tree_sandbox(
                    node, group_key, health, _make_tree, more_after, cursor_after, ctx
                )

            stop_cursor = encode_tree_cursor(
                scope_hash=ctx.scope_hash, sandbox_addr=admitted[-1][0].sandbox_addr
            )
            return _make_tree(
                last_page.health, last_page.projects, True, stop_cursor
            )

        return last_page

    def get_sandbox_status(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_read_ms: int = DEFAULT_MAX_READ_MS,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> SandboxStatusSnapshot:
        """Return a bounded detailed status snapshot for one sandbox."""
        _authorize_operator_caller(caller)
        try:
            addr = parse_local_target(target).canonical
        except AddressError as exc:
            raise CoordValidationError(str(exc)) from exc
        max_bytes = _validate_int_range(
            max_response_bytes,
            _PARAM_MAX_RESPONSE_BYTES,
            MIN_RESPONSE_BYTES,
            MAX_RESPONSE_BYTES,
        )
        read_ms = _validate_int_range(
            max_read_ms, _PARAM_MAX_READ_MS, MIN_READ_MS, MAX_READ_MS
        )
        principal, session_echo, db_path, marker = self._preflight(
            caller, read_session_id, session_generation
        )

        deadline = time.monotonic() + (read_ms / 1000.0)
        with open_readonly_snapshot(db_path, deadline=deadline) as conn:
            snapshot_seq = read_seq_counter(conn, deadline)
            raw_health = _build_full_health(conn, marker, deadline)
            sb_row = _select_single_sandbox(conn, addr, deadline)
            if sb_row is None:
                raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
            node, _, binding = _build_sandbox_node(
                conn,
                sb_row,
                include_historical=False,
                max_threads=MAX_THREADS_PER_SANDBOX,
                deadline=deadline,
            )
            edges, edges_trunc = _select_edges_for_sandbox(conn, addr, deadline)
            budget, budget_malformed = _select_budget_safe(
                conn, addr, node.incarnation_id, deadline
            )
            ctx = _StatusPackCtx(
                snapshot_seq=snapshot_seq,
                binding=binding,
                budget=budget,
                budget_malformed=budget_malformed,
                max_bytes=max_bytes,
                session_echo=session_echo,
                deadline=deadline,
            )
            snapshot = self._pack_sandbox_status(raw_health, node, edges, edges_trunc, ctx)
            check_deadline_ms(deadline)

        self._postflight(principal, session_echo)
        return snapshot

    def _pack_sandbox_status(
        self,
        raw_health: WorkspaceHealth,
        node: ProjectedSandboxNode,
        edges: tuple[ProjectedRoutingEdge, ...],
        edges_trunc: bool,
        ctx: _StatusPackCtx,
    ) -> SandboxStatusSnapshot:
        def _make(
            cur_edges: tuple[ProjectedRoutingEdge, ...],
            cur_edges_trunc: bool,
            cur_health: WorkspaceHealth,
            cur_node: ProjectedSandboxNode,
        ) -> SandboxStatusSnapshot:
            return SandboxStatusSnapshot(
                schema_version=PROJECTION_SCHEMA_VERSION,
                snapshot_seq=ctx.snapshot_seq,
                health=cur_health,
                sandbox=cur_node,
                edges=cur_edges,
                edges_truncated=cur_edges_trunc,
                binding=ctx.binding,
                budget=ctx.budget,
                budget_malformed=ctx.budget_malformed,
                read_session=ctx.session_echo,
            )

        check_deadline_ms(ctx.deadline)
        full = _make(edges, edges_trunc, raw_health, node)
        if len(serialize_projection_bytes(full)) <= ctx.max_bytes:
            return full

        best_edges = _binary_search_prefix(
            len(edges),
            lambda mid: _make(
                edges[:mid], edges_trunc or (mid < len(edges)), raw_health, node
            ),
            ctx.max_bytes,
            ctx.deadline,
        )
        if best_edges is not None:
            return best_edges

        zero_edges_trunc = edges_trunc or bool(edges)
        fitted_health = _fit_health_in_budget(
            raw_health,
            lambda h: _make(_EMPTY_EDGES, zero_edges_trunc, h, node),
            ctx.max_bytes,
            ctx.deadline,
        )
        if fitted_health is not None:
            return _make(_EMPTY_EDGES, zero_edges_trunc, fitted_health, node)

        min_health = replace(
            raw_health,
            unconfirmed_bindings=_EMPTY_BINDINGS,
            unconfirmed_bindings_truncated=(
                raw_health.unconfirmed_bindings_truncated
                or bool(raw_health.unconfirmed_bindings)
            ),
        )
        best_th = _binary_search_prefix(
            len(node.threads),
            lambda mid_t: _make(
                _EMPTY_EDGES,
                zero_edges_trunc,
                min_health,
                replace(
                    node,
                    threads=node.threads[:mid_t],
                    threads_truncated=(node.threads_truncated or mid_t < len(node.threads)),
                ),
            ),
            ctx.max_bytes,
            ctx.deadline,
        )
        if best_th is None:
            raise CoordValidationError(_ERR_BUDGET_ENVELOPE)
        return best_th

    def get_thread_events(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        thread_id: str,
        incarnation_id: str | None = None,
        after_cursor: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_read_ms: int = DEFAULT_MAX_READ_MS,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> ThreadEventsPage:
        """Return a bounded, provenance-verified event page for a sandbox thread."""
        _authorize_operator_caller(caller)
        try:
            addr = parse_local_target(target).canonical
            clean_thread = validate_thread_id(thread_id)
            explicit_inc = (
                validate_opaque_token(incarnation_id, _COL_INCARNATION_ID)
                if incarnation_id is not None
                else None
            )
        except AddressError as exc:
            raise CoordValidationError(str(exc)) from exc
        page_limit = _validate_int_range(limit, "limit", 1, MAX_PAGE_LIMIT)
        max_bytes = _validate_int_range(
            max_response_bytes,
            _PARAM_MAX_RESPONSE_BYTES,
            MIN_RESPONSE_BYTES,
            MAX_RESPONSE_BYTES,
        )
        read_ms = _validate_int_range(
            max_read_ms, _PARAM_MAX_READ_MS, MIN_READ_MS, MAX_READ_MS
        )
        principal, session_echo, db_path, marker = self._preflight(
            caller, read_session_id, session_generation
        )

        deadline = time.monotonic() + (read_ms / 1000.0)
        with open_readonly_snapshot(db_path, deadline=deadline) as conn:
            snapshot_seq = read_seq_counter(conn, deadline)
            health_summary = _build_compact_health(conn, marker, deadline)
            sb_row = _select_single_sandbox(conn, addr, deadline)
            if sb_row is None:
                raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
            current_inc = _validate_sandbox_incarnation(sb_row)
            target_inc = explicit_inc if explicit_inc is not None else current_inc
            is_current = target_inc == current_inc

            scope_hash = compute_scope_hash(
                OP_EVENTS,
                target=addr,
                thread_id=clean_thread,
                incarnation_id=target_inc,
            )
            parsed_cursor = decode_events_cursor(
                after_cursor,
                expected_scope_hash=scope_hash,
                expected_incarnation_id=target_inc,
            )
            th_row = execute_bounded(
                conn,
                "SELECT 1 FROM threads WHERE sandbox_addr = ? AND incarnation_id = ? AND thread_id = ?",
                (addr, target_inc, clean_thread),
                deadline,
            ).fetchone()
            ev_rows = _select_thread_event_log_rows(
                conn,
                sandbox_addr=addr,
                incarnation_id=target_inc,
                thread_id=clean_thread,
                parsed_cursor=parsed_cursor,
                limit=page_limit + 1,
                deadline=deadline,
            )
            st_rows = _select_thread_stream_rows(
                conn,
                sandbox_addr=addr,
                incarnation_id=target_inc,
                thread_id=clean_thread,
                parsed_cursor=parsed_cursor,
                limit=page_limit + 1,
                deadline=deadline,
            )
            ctx = _EventsPackCtx(
                snapshot_seq=snapshot_seq,
                health=health_summary,
                sandbox_addr=addr,
                target_inc=target_inc,
                is_current=is_current,
                stale_reason=None if is_current else "superseded_incarnation",
                thread_id=clean_thread,
                thread_exists=(th_row is not None),
                page_limit=page_limit,
                scope_hash=scope_hash,
                max_bytes=max_bytes,
                session_echo=session_echo,
                deadline=deadline,
            )
            page = self._pack_thread_events(
                conn, _merge_sorted_events(ev_rows, st_rows), ctx
            )
            check_deadline_ms(deadline)

        self._postflight(principal, session_echo)
        return page

    def _project_merged_event(
        self, conn: sqlite3.Connection, rank: int, row: Mapping[str, Any], ctx: _EventsPackCtx
    ) -> ProjectedThreadEvent:
        if rank == 0:
            return _project_event_log_row(
                row,
                sandbox_addr=ctx.sandbox_addr,
                incarnation_id=ctx.target_inc,
                thread_id=ctx.thread_id,
            )
        return _project_stream_row(
            conn,
            row,
            sandbox_addr=ctx.sandbox_addr,
            incarnation_id=ctx.target_inc,
            thread_id=ctx.thread_id,
            deadline=ctx.deadline,
        )

    def _pack_thread_events(
        self,
        conn: sqlite3.Connection,
        merged: list[tuple[int, int, dict[str, Any]]],
        ctx: _EventsPackCtx,
    ) -> ThreadEventsPage:
        def _make_page(
            events: tuple[ProjectedThreadEvent, ...],
            has_more: bool,
            next_cursor: str | None,
        ) -> ThreadEventsPage:
            return ThreadEventsPage(
                schema_version=PROJECTION_SCHEMA_VERSION,
                snapshot_seq=ctx.snapshot_seq,
                health=ctx.health,
                sandbox_addr=ctx.sandbox_addr,
                applied_incarnation_id=ctx.target_inc,
                is_current_incarnation=ctx.is_current,
                stale_reason=ctx.stale_reason,
                thread_id=ctx.thread_id,
                thread_exists=ctx.thread_exists,
                events=events,
                has_more=has_more,
                next_cursor=next_cursor,
                read_session=ctx.session_echo,
            )

        def _make_single(
            more: bool, cursor: str | None, item: ProjectedThreadEvent
        ) -> ThreadEventsPage:
            return _make_page((item,), more, cursor)

        empty = _make_page(_EMPTY_EVENTS, False, None)
        if len(serialize_projection_bytes(empty)) > ctx.max_bytes:
            raise CoordValidationError(_ERR_BUDGET_ENVELOPE)

        total = len(merged)
        admitted: list[ProjectedThreadEvent] = []
        last_page = empty

        for idx, (_seq, rank, row) in enumerate(merged[: ctx.page_limit]):
            check_deadline_ms(ctx.deadline)
            projected = self._project_merged_event(conn, rank, row, ctx)
            more_after = (idx + 1) < total
            cursor_after = (
                encode_events_cursor(
                    scope_hash=ctx.scope_hash,
                    seq=projected.seq,
                    rank=projected.source_rank,
                    incarnation_id=ctx.target_inc,
                )
                if more_after
                else None
            )
            candidate = _make_page((*admitted, projected), more_after, cursor_after)
            if len(serialize_projection_bytes(candidate)) <= ctx.max_bytes:
                admitted.append(projected)
                last_page = candidate
                continue

            if not admitted:
                shrunk = _shrink_text_item_to_fit(
                    projected,
                    "text",
                    "text_truncated",
                    partial(_make_single, more_after, cursor_after),
                    ctx.max_bytes,
                    ctx.deadline,
                )
                if shrunk is None:
                    raise CoordValidationError(_ERR_BUDGET_ITEM)
                return _make_page((shrunk,), more_after, cursor_after)

            prev = admitted[-1]
            stop_cursor = encode_events_cursor(
                scope_hash=ctx.scope_hash,
                seq=prev.seq,
                rank=prev.source_rank,
                incarnation_id=ctx.target_inc,
            )
            return _make_page(last_page.events, True, stop_cursor)

        return last_page

    def get_sandbox_mailbox(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        statuses: Iterable[str] | None = None,
        after_cursor: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        max_read_ms: int = DEFAULT_MAX_READ_MS,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> MailboxPage:
        """Return a bounded paginated mailbox snapshot for one sandbox."""
        _authorize_operator_caller(caller)
        try:
            addr = parse_local_target(target).canonical
        except AddressError as exc:
            raise CoordValidationError(str(exc)) from exc
        clean_statuses = _validate_outbox_statuses(statuses)
        page_limit = _validate_int_range(limit, "limit", 1, MAX_PAGE_LIMIT)
        max_bytes = _validate_int_range(
            max_response_bytes,
            _PARAM_MAX_RESPONSE_BYTES,
            MIN_RESPONSE_BYTES,
            MAX_RESPONSE_BYTES,
        )
        read_ms = _validate_int_range(
            max_read_ms, _PARAM_MAX_READ_MS, MIN_READ_MS, MAX_READ_MS
        )
        scope_hash = compute_scope_hash(
            OP_MAILBOX, target=addr, statuses=clean_statuses
        )
        parsed_cursor = decode_mailbox_cursor(
            after_cursor, expected_scope_hash=scope_hash
        )
        principal, session_echo, db_path, marker = self._preflight(
            caller, read_session_id, session_generation
        )

        deadline = time.monotonic() + (read_ms / 1000.0)
        with open_readonly_snapshot(db_path, deadline=deadline) as conn:
            snapshot_seq = read_seq_counter(conn, deadline)
            health_summary = _build_compact_health(conn, marker, deadline)
            sb_row = _select_single_sandbox(conn, addr, deadline)
            if sb_row is None:
                raise CoordPolicyError(_ERR_SANDBOX_NOT_FOUND)
            current_inc = _validate_sandbox_incarnation(sb_row)
            rows = _select_mailbox_rows(
                conn,
                sandbox_addr=addr,
                statuses=clean_statuses,
                parsed_cursor=parsed_cursor,
                limit=page_limit + 1,
                deadline=deadline,
            )
            ctx = _MailboxPackCtx(
                snapshot_seq=snapshot_seq,
                health=health_summary,
                sandbox_addr=addr,
                current_inc=current_inc,
                page_limit=page_limit,
                scope_hash=scope_hash,
                max_bytes=max_bytes,
                session_echo=session_echo,
                deadline=deadline,
            )
            page = self._pack_mailbox_page(rows, ctx)
            check_deadline_ms(deadline)

        self._postflight(principal, session_echo)
        return page

    def _pack_mailbox_page(
        self, rows: list[dict[str, Any]], ctx: _MailboxPackCtx
    ) -> MailboxPage:
        def _make_page(
            entries: tuple[ProjectedMailboxEntry, ...],
            has_more: bool,
            next_cursor: str | None,
        ) -> MailboxPage:
            return MailboxPage(
                schema_version=PROJECTION_SCHEMA_VERSION,
                snapshot_seq=ctx.snapshot_seq,
                health=ctx.health,
                sandbox_addr=ctx.sandbox_addr,
                current_incarnation_id=ctx.current_inc,
                entries=entries,
                has_more=has_more,
                next_cursor=next_cursor,
                read_session=ctx.session_echo,
            )

        def _make_single(
            more: bool, cursor: str | None, item: ProjectedMailboxEntry
        ) -> MailboxPage:
            return _make_page((item,), more, cursor)

        empty = _make_page(_EMPTY_ENTRIES, False, None)
        if len(serialize_projection_bytes(empty)) > ctx.max_bytes:
            raise CoordValidationError(_ERR_BUDGET_ENVELOPE)

        total = len(rows)
        admitted: list[ProjectedMailboxEntry] = []
        last_page = empty

        for idx, row in enumerate(rows[: ctx.page_limit]):
            check_deadline_ms(ctx.deadline)
            entry = _row_to_mailbox_entry(row)
            more_after = (idx + 1) < total
            cursor_after = (
                encode_mailbox_cursor(
                    scope_hash=ctx.scope_hash, seq=entry.seq, msg_id=entry.msg_id
                )
                if more_after
                else None
            )
            candidate = _make_page((*admitted, entry), more_after, cursor_after)
            if len(serialize_projection_bytes(candidate)) <= ctx.max_bytes:
                admitted.append(entry)
                last_page = candidate
                continue

            if not admitted:
                shrunk = _shrink_text_item_to_fit(
                    entry,
                    "detail",
                    "detail_truncated",
                    partial(_make_single, more_after, cursor_after),
                    ctx.max_bytes,
                    ctx.deadline,
                )
                if shrunk is None:
                    raise CoordValidationError(_ERR_BUDGET_ITEM)
                return _make_page((shrunk,), more_after, cursor_after)

            prev = admitted[-1]
            stop_cursor = encode_mailbox_cursor(
                scope_hash=ctx.scope_hash, seq=prev.seq, msg_id=prev.msg_id
            )
            return _make_page(last_page.entries, True, stop_cursor)

        return last_page
