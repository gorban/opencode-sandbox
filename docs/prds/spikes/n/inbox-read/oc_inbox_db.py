"""Verification-only filesystem admission, live-WAL snapshot opener, and bounded SQL.

Internal database module supporting ``oc_inbox_projection.py``. Never creates
directories or files, never repairs permissions via chmod/fchmod, never writes
to SQLite, and guards against hostile views, triggers, virtual tables, and
``pragma_table_list`` name collisions before reading ``inbox_seq_counter``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
from typing import Any, cast
from urllib.parse import quote

_INBOX_DIR = Path(__file__).resolve().parent
_SPIKE_N_DIR = _INBOX_DIR.parent
_SPIKE_M_DIR = _SPIKE_N_DIR.parent / "m"
_SPIKE_M_PROJ_DIR = _SPIKE_M_DIR / "projection"
_SPIKE_L_DIR = _SPIKE_N_DIR.parent / "l"
for _import_dir in (
    str(_INBOX_DIR),
    str(_SPIKE_N_DIR),
    str(_SPIKE_M_PROJ_DIR),
    str(_SPIKE_M_DIR),
    str(_SPIKE_L_DIR),
):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_broker_common import _UMASK_LOCK  # noqa: E402
from oc_coord_contract import CoordPolicyError  # noqa: E402
from oc_inbox_contract import (  # noqa: E402
    BUCKET_MALFORMED,
    MAX_ITEM_TEXT_BYTES,
    MAX_PRIORITY_RANK,
    MAX_SQLITE_INT64,
    SOURCE_HOST_WORKFLOW_ENGINE,
    SQL_MAX_CELL_BYTES,
    STATUS_PENDING,
    VALID_SEVERITIES,
    VALID_SOURCE_KINDS,
    VALID_STATUSES,
    ParsedInboxCursor,
)
from oc_projection_db import (  # noqa: E402
    apply_remaining_busy_timeout,
    check_deadline_ms,
    check_deadline_s,
    dict_row_factory,
    execute_bounded,
    verify_regular_private_file_nofollow as _proj_verify_regular_private_file_nofollow,
)
from oc_schema import (  # noqa: E402
    PolicyError,
    assert_trusted_dir,
    check_not_host_production_dir,
    check_not_in_sandbox,
)

DB_FILENAME = "inbox.sqlite"
DB_ALL_FILES = ("", "-wal", "-shm", "-journal")

ERR_READ_DEADLINE = "read_deadline_exceeded"
ERR_INBOX_BUSY = "inbox_db_busy"
ERR_INBOX_UNREADABLE = "inbox_db_unreadable"
ERR_STATE_DIR_UNREADABLE = "state_dir_unreadable"
_SFX_UNREADABLE = "_unreadable"
_K_TOTAL_ITEMS = "total_items"
_K_PAUSED_LANES_COUNT = "paused_lanes_count"
_K_REQ_HUMAN_REVIEW_COUNT = "requires_human_review_count"
_K_MALFORMED_ROWS_COUNT = "malformed_rows_count"

_CLOSED_STATUS_SQL = ", ".join(f"'{s}'" for s in sorted(VALID_STATUSES))
_CLOSED_SEVERITY_SQL = ", ".join(f"'{s}'" for s in sorted(VALID_SEVERITIES))
_CLOSED_SOURCE_SQL = ", ".join(f"'{s}'" for s in sorted(VALID_SOURCE_KINDS))

MAX_SCHEMA_OBJECTS = 32
MAX_SCHEMA_COLUMNS = 64
MAX_INDEX_COLS = 16
MAX_SCHEMA_NAME_BYTES = 128
MAX_SCHEMA_SQL_BYTES = 16 * 1024

_TBL_SEQ = "inbox_seq_counter"
_TBL_ITEMS = "review_items"
_TBL_RUNS = "workflow_runs"
_TBL_ARTS = "review_artifacts"
_CORE_TABLES: frozenset[str] = frozenset(
    {_TBL_SEQ, _TBL_ITEMS, _TBL_RUNS, _TBL_ARTS}
)
_AUTOINDEX_NAME_RE = re.compile(
    r"^sqlite_autoindex_(?:inbox_seq_counter|workflow_runs|review_items|review_artifacts)_\d+$",
    re.ASCII,
)
_SQL_SCHEMA_SAFETY_PRECHECK = (
    "SELECT 1 FROM main.sqlite_schema "
    "WHERE type IN ('trigger', 'view') "
    "OR (type = 'table' AND (typeof(rootpage) != 'integer' OR rootpage <= 0)) "
    f"OR (name IS NOT NULL AND LENGTH(CAST(name AS BLOB)) > {MAX_SCHEMA_NAME_BYTES}) "
    f"OR (tbl_name IS NOT NULL AND LENGTH(CAST(tbl_name AS BLOB)) > {MAX_SCHEMA_NAME_BYTES}) "
    f"OR (sql IS NOT NULL AND LENGTH(CAST(sql AS BLOB)) > {MAX_SCHEMA_SQL_BYTES}) "
    "LIMIT 1"
)
_SQL_SCHEMA_OBJECT_COUNT = (
    f"SELECT COUNT(*) AS cnt FROM (SELECT 1 FROM main.sqlite_schema LIMIT {MAX_SCHEMA_OBJECTS + 1})"
)
_SQL_LIST_INDEXES = (
    "SELECT name, tbl_name, (sql IS NULL) AS sql_is_null "
    f"FROM main.sqlite_schema WHERE type = 'index' LIMIT {MAX_SCHEMA_OBJECTS + 1}"
)
_PRAGMA_TABLE_LIST_CHECKS: tuple[tuple[str, str], ...] = (
    (_TBL_SEQ, "PRAGMA main.table_list('inbox_seq_counter')"),
    (_TBL_ITEMS, "PRAGMA main.table_list('review_items')"),
    (_TBL_RUNS, "PRAGMA main.table_list('workflow_runs')"),
    (_TBL_ARTS, "PRAGMA main.table_list('review_artifacts')"),
)
_COL_ARTIFACT_ID = "artifact_id"
_SQL_FROM_REVIEW_ITEMS = "FROM review_items r "
_PRAGMA_TABLE_PK_CHECKS: tuple[tuple[str, str, tuple[tuple[str, ...], ...]], ...] = (
    (_TBL_SEQ, "PRAGMA main.table_info('inbox_seq_counter')", (("id",),)),
    (_TBL_RUNS, "PRAGMA main.table_info('workflow_runs')", (("run_id",),)),
    (_TBL_ITEMS, "PRAGMA main.table_info('review_items')", (("review_id",),)),
    (
        _TBL_ARTS,
        "PRAGMA main.table_info('review_artifacts')",
        ((_COL_ARTIFACT_ID,), ("review_id", _COL_ARTIFACT_ID)),
    ),
)
_PRAGMA_INDEX_LIST_SQL: dict[str, str] = {
    _TBL_SEQ: "PRAGMA main.index_list('inbox_seq_counter')",
    _TBL_RUNS: "PRAGMA main.index_list('workflow_runs')",
    _TBL_ITEMS: "PRAGMA main.index_list('review_items')",
    _TBL_ARTS: "PRAGMA main.index_list('review_artifacts')",
}
_EXPECTED_USER_INDEXES: dict[tuple[str, str], tuple[str, ...]] = {
    ("idx_review_items_order", _TBL_ITEMS): (
        "priority_rank",
        "checkpoint_seq",
        "review_id",
    ),
    ("idx_review_items_run_status", _TBL_ITEMS): ("run_id", "status"),
    ("idx_review_artifacts_review", _TBL_ARTS): (
        "review_id",
        "is_primary",
        _COL_ARTIFACT_ID,
    ),
}
_SQL_READ_SEQ_COUNTER = (
    "SELECT CASE WHEN typeof(last_seq) = 'integer' THEN last_seq ELSE NULL END AS last_seq, "
    "(typeof(last_seq) != 'integer') AS last_seq_malformed "
    "FROM inbox_seq_counter WHERE typeof(id) = 'integer' AND id = 1 LIMIT 2"
)

_SQL_ITEM_GATED_COLUMNS = f"""
    CASE WHEN typeof(r.review_id) = 'text' AND LENGTH(CAST(r.review_id AS BLOB)) <= 96
         THEN r.review_id ELSE NULL END AS review_id,
    CASE WHEN typeof(r.run_id) = 'text' AND LENGTH(CAST(r.run_id AS BLOB)) <= 96
         THEN r.run_id ELSE NULL END AS run_id,
    (typeof(r.run_id) != 'text' OR LENGTH(CAST(r.run_id AS BLOB)) > 96) AS run_id_malformed,
    CASE WHEN typeof(r.step_id) = 'text' AND LENGTH(CAST(r.step_id AS BLOB)) <= 96
         THEN r.step_id ELSE NULL END AS step_id,
    (typeof(r.step_id) != 'text' OR LENGTH(CAST(r.step_id AS BLOB)) > 96) AS step_id_malformed,
    CASE WHEN typeof(r.checkpoint_seq) = 'integer' AND r.checkpoint_seq >= 0
         THEN r.checkpoint_seq ELSE NULL END AS checkpoint_seq,
    (typeof(r.checkpoint_seq) != 'integer' OR r.checkpoint_seq < 0) AS checkpoint_seq_malformed,
    CASE WHEN typeof(r.checkpoint_seq) = 'integer' AND r.checkpoint_seq >= 0
         THEN r.checkpoint_seq ELSE {MAX_SQLITE_INT64} END AS effective_seq,
    CASE WHEN typeof(r.item_revision) = 'integer' AND r.item_revision >= 1
         THEN r.item_revision ELSE NULL END AS item_revision,
    (typeof(r.item_revision) != 'integer' OR r.item_revision < 1) AS item_revision_malformed,
    CASE WHEN typeof(r.status) = 'text' AND LENGTH(CAST(r.status AS BLOB)) <= 64
         THEN r.status ELSE NULL END AS status,
    (typeof(r.status) != 'text' OR LENGTH(CAST(r.status AS BLOB)) > 64) AS status_malformed,
    CASE WHEN typeof(r.severity) = 'text' AND LENGTH(CAST(r.severity AS BLOB)) <= 64
         THEN r.severity ELSE NULL END AS severity,
    (typeof(r.severity) != 'text' OR LENGTH(CAST(r.severity AS BLOB)) > 64) AS severity_malformed,
    CASE WHEN typeof(r.priority_rank) = 'integer' AND r.priority_rank BETWEEN 0 AND {MAX_PRIORITY_RANK}
         THEN r.priority_rank ELSE NULL END AS priority_rank,
    (typeof(r.priority_rank) != 'integer' OR r.priority_rank NOT BETWEEN 0 AND {MAX_PRIORITY_RANK}) AS priority_rank_malformed,
    CASE WHEN typeof(r.priority_rank) = 'integer' AND r.priority_rank BETWEEN 0 AND {MAX_PRIORITY_RANK}
         THEN r.priority_rank ELSE 0 END AS effective_priority,
    CASE WHEN typeof(r.lane_paused) = 'integer' AND r.lane_paused IN (0, 1)
         THEN r.lane_paused ELSE NULL END AS lane_paused,
    (typeof(r.lane_paused) != 'integer' OR r.lane_paused NOT IN (0, 1)) AS lane_paused_malformed,
    CASE WHEN typeof(r.requires_human_review) = 'integer' AND r.requires_human_review IN (0, 1)
         THEN r.requires_human_review ELSE NULL END AS requires_human_review,
    (typeof(r.requires_human_review) != 'integer' OR r.requires_human_review NOT IN (0, 1)) AS requires_human_review_malformed,
    CASE WHEN typeof(r.source_kind) = 'text' AND LENGTH(CAST(r.source_kind AS BLOB)) <= 64
         THEN r.source_kind ELSE NULL END AS source_kind,
    (typeof(r.source_kind) != 'text' OR LENGTH(CAST(r.source_kind AS BLOB)) > 64) AS source_kind_malformed,
    CASE WHEN r.target_addr IS NULL THEN NULL
         WHEN typeof(r.target_addr) = 'text' AND LENGTH(CAST(r.target_addr AS BLOB)) <= 256
         THEN r.target_addr ELSE NULL END AS target_addr,
    (r.target_addr IS NOT NULL AND (typeof(r.target_addr) != 'text' OR LENGTH(CAST(r.target_addr AS BLOB)) > 256)) AS target_addr_malformed,
    CASE WHEN r.target_incarnation_id IS NULL THEN NULL
         WHEN typeof(r.target_incarnation_id) = 'text' AND LENGTH(CAST(r.target_incarnation_id AS BLOB)) <= 96
         THEN r.target_incarnation_id ELSE NULL END AS target_incarnation_id,
    (r.target_incarnation_id IS NOT NULL AND (typeof(r.target_incarnation_id) != 'text' OR LENGTH(CAST(r.target_incarnation_id AS BLOB)) > 96)) AS target_incarnation_id_malformed,
    SUBSTR(CAST(r.title AS BLOB), 1, 1024) AS title_blob,
    LENGTH(CAST(r.title AS BLOB)) AS title_bytes,
    (typeof(r.title) != 'text') AS title_non_text,
    SUBSTR(CAST(r.summary_text AS BLOB), 1, {MAX_ITEM_TEXT_BYTES}) AS summary_blob,
    LENGTH(CAST(r.summary_text AS BLOB)) AS original_summary_bytes,
    (typeof(r.summary_text) != 'text') AS summary_non_text,
    CASE WHEN typeof(r.artifact_sha256) = 'text' AND LENGTH(CAST(r.artifact_sha256 AS BLOB)) = 64
         THEN r.artifact_sha256 ELSE NULL END AS artifact_sha256,
    (typeof(r.artifact_sha256) != 'text' OR LENGTH(CAST(r.artifact_sha256 AS BLOB)) != 64) AS artifact_sha256_malformed,
    CASE WHEN typeof(r.policy_digest) = 'text' AND LENGTH(CAST(r.policy_digest AS BLOB)) = 64
         THEN r.policy_digest ELSE NULL END AS policy_digest,
    (typeof(r.policy_digest) != 'text' OR LENGTH(CAST(r.policy_digest AS BLOB)) != 64) AS policy_digest_malformed,
    CASE WHEN typeof(r.review_pin_sha256) = 'text' AND LENGTH(CAST(r.review_pin_sha256 AS BLOB)) = 64
         THEN r.review_pin_sha256 ELSE NULL END AS review_pin_sha256,
    (typeof(r.review_pin_sha256) != 'text' OR LENGTH(CAST(r.review_pin_sha256 AS BLOB)) != 64) AS review_pin_sha256_malformed,
    CASE WHEN typeof(r.metadata_json) = 'text' AND LENGTH(CAST(r.metadata_json AS BLOB)) <= {SQL_MAX_CELL_BYTES}
         THEN CAST(r.metadata_json AS BLOB) ELSE NULL END AS metadata_blob,
    LENGTH(CAST(r.metadata_json AS BLOB)) AS metadata_bytes,
    (typeof(r.metadata_json) != 'text' OR LENGTH(CAST(r.metadata_json AS BLOB)) > {SQL_MAX_CELL_BYTES}) AS metadata_malformed,
    CASE WHEN typeof(r.created_at) IN ('integer', 'real') THEN r.created_at ELSE NULL END AS created_at,
    (typeof(r.created_at) NOT IN ('integer', 'real')) AS created_at_malformed,
    CASE WHEN typeof(r.updated_at) IN ('integer', 'real') THEN r.updated_at ELSE NULL END AS updated_at,
    (typeof(r.updated_at) NOT IN ('integer', 'real')) AS updated_at_malformed,
    CASE WHEN r.expires_at IS NULL THEN NULL
         WHEN typeof(r.expires_at) IN ('integer', 'real') THEN r.expires_at ELSE NULL END AS expires_at,
    (r.expires_at IS NOT NULL AND typeof(r.expires_at) NOT IN ('integer', 'real')) AS expires_at_malformed,
    (w.run_id IS NOT NULL) AS workflow_run_present,
    CASE WHEN w.run_id IS NULL THEN NULL
         WHEN typeof(w.run_id) = 'text' AND LENGTH(CAST(w.run_id AS BLOB)) <= 96
         THEN w.run_id ELSE NULL END AS joined_run_id,
    (SELECT COUNT(*) FROM (
        SELECT 1 FROM workflow_runs w2
        WHERE typeof(r.run_id) = 'text'
          AND typeof(w2.run_id) = 'text'
          AND w2.run_id COLLATE BINARY = r.run_id COLLATE BINARY
        LIMIT 2
    )) AS workflow_run_match_count,
    CASE WHEN w.run_id IS NULL THEN NULL
         WHEN typeof(w.workflow_id) = 'text' AND LENGTH(CAST(w.workflow_id AS BLOB)) <= 128
         THEN w.workflow_id ELSE NULL END AS workflow_id,
    (w.run_id IS NOT NULL AND (typeof(w.workflow_id) != 'text' OR LENGTH(CAST(w.workflow_id AS BLOB)) > 128)) AS workflow_id_malformed,
    CASE WHEN w.run_id IS NULL THEN NULL
         WHEN typeof(w.policy_digest) = 'text' AND LENGTH(CAST(w.policy_digest AS BLOB)) = 64
         THEN w.policy_digest ELSE NULL END AS run_policy_digest,
    (w.run_id IS NOT NULL AND (typeof(w.policy_digest) != 'text' OR LENGTH(CAST(w.policy_digest AS BLOB)) != 64)) AS run_policy_digest_malformed
"""

_SQL_WORKFLOW_RUN_JOIN = (
    "LEFT JOIN workflow_runs w "
    "ON typeof(r.run_id) = 'text' "
    "AND typeof(w.run_id) = 'text' "
    "AND w.run_id COLLATE BINARY = r.run_id COLLATE BINARY"
)

_SQL_OUTER_ITEM_COLUMNS = """
    review_id, run_id, run_id_malformed, step_id, step_id_malformed,
    checkpoint_seq, checkpoint_seq_malformed, effective_seq,
    item_revision, item_revision_malformed, status, status_malformed,
    severity, severity_malformed, priority_rank, priority_rank_malformed, effective_priority,
    lane_paused, lane_paused_malformed, requires_human_review, requires_human_review_malformed,
    source_kind, source_kind_malformed, target_addr, target_addr_malformed,
    target_incarnation_id, target_incarnation_id_malformed,
    title_blob, title_bytes, title_non_text,
    summary_blob, original_summary_bytes, summary_non_text,
    artifact_sha256, artifact_sha256_malformed,
    policy_digest, policy_digest_malformed,
    review_pin_sha256, review_pin_sha256_malformed,
    metadata_blob, metadata_bytes, metadata_malformed,
    created_at, created_at_malformed, updated_at, updated_at_malformed,
    expires_at, expires_at_malformed,
    workflow_run_present, joined_run_id, workflow_run_match_count,
    workflow_id, workflow_id_malformed,
    run_policy_digest, run_policy_digest_malformed
"""

_SQL_ARTIFACT_GATED_COLUMNS = """
    CASE WHEN typeof(review_id) = 'text' AND LENGTH(CAST(review_id AS BLOB)) <= 96
         THEN review_id ELSE NULL END AS owner_review_id,
    CASE WHEN typeof(artifact_id) = 'text' AND LENGTH(CAST(artifact_id AS BLOB)) <= 96
         THEN artifact_id ELSE NULL END AS artifact_id,
    (typeof(artifact_id) != 'text' OR LENGTH(CAST(artifact_id AS BLOB)) > 96) AS artifact_id_malformed,
    CASE WHEN typeof(blob_sha256) = 'text' AND LENGTH(CAST(blob_sha256 AS BLOB)) = 64
         THEN blob_sha256 ELSE NULL END AS blob_sha256,
    (typeof(blob_sha256) != 'text' OR LENGTH(CAST(blob_sha256 AS BLOB)) != 64) AS blob_sha256_malformed,
    CASE WHEN typeof(size_bytes) = 'integer' AND size_bytes >= 0
         THEN size_bytes ELSE NULL END AS size_bytes,
    (typeof(size_bytes) != 'integer' OR size_bytes < 0) AS size_bytes_malformed,
    CASE WHEN typeof(media_type) = 'text' AND LENGTH(CAST(media_type AS BLOB)) <= 128
         THEN media_type ELSE NULL END AS media_type,
    (typeof(media_type) != 'text' OR LENGTH(CAST(media_type AS BLOB)) > 128) AS media_type_malformed,
    SUBSTR(CAST(label AS BLOB), 1, 1024) AS label_blob,
    LENGTH(CAST(label AS BLOB)) AS label_bytes,
    (typeof(label) != 'text') AS label_non_text,
    CASE WHEN typeof(is_primary) = 'integer' AND is_primary IN (0, 1)
         THEN is_primary ELSE NULL END AS is_primary,
    (typeof(is_primary) != 'integer' OR is_primary NOT IN (0, 1)) AS is_primary_malformed,
    CASE WHEN typeof(created_at) IN ('integer', 'real') THEN created_at ELSE NULL END AS created_at,
    (typeof(created_at) NOT IN ('integer', 'real')) AS created_at_malformed
"""

_SQL_STATUS_AGG = f"""
    SELECT
        CASE WHEN typeof(status) = 'text' AND status COLLATE BINARY IN ({_CLOSED_STATUS_SQL})
             THEN status ELSE '{BUCKET_MALFORMED}' END AS bucket,
        COUNT(*) AS cnt
    FROM review_items
    GROUP BY 1
"""

_SQL_SEVERITY_AGG = f"""
    SELECT
        CASE WHEN typeof(severity) = 'text' AND severity COLLATE BINARY IN ({_CLOSED_SEVERITY_SQL})
             THEN severity ELSE '{BUCKET_MALFORMED}' END AS bucket,
        COUNT(*) AS cnt,
        COALESCE(SUM(CASE WHEN typeof(status) = 'text' AND status COLLATE BINARY = '{STATUS_PENDING}'
                          THEN 1 ELSE 0 END), 0) AS pending_cnt
    FROM review_items
    GROUP BY 1
"""

_SQL_STRUCTURAL_TOTALS = f"""
    SELECT
        COUNT(*) AS total_items,
        COALESCE(SUM(CASE WHEN typeof(source_kind) = 'text'
                           AND source_kind COLLATE BINARY = '{SOURCE_HOST_WORKFLOW_ENGINE}'
                           AND typeof(lane_paused) = 'integer'
                           AND lane_paused = 1
                          THEN 1 ELSE 0 END), 0) AS paused_lanes_count,
        COALESCE(SUM(CASE WHEN typeof(requires_human_review) = 'integer'
                           AND requires_human_review = 1
                          THEN 1 ELSE 0 END), 0) AS requires_human_review_count,
        COALESCE(SUM(CASE WHEN
              typeof(review_id) != 'text' OR LENGTH(CAST(review_id AS BLOB)) NOT BETWEEN 1 AND 96
           OR typeof(run_id) != 'text' OR LENGTH(CAST(run_id AS BLOB)) NOT BETWEEN 1 AND 96
           OR typeof(step_id) != 'text' OR LENGTH(CAST(step_id AS BLOB)) NOT BETWEEN 1 AND 96
           OR typeof(checkpoint_seq) != 'integer' OR checkpoint_seq < 0
           OR typeof(item_revision) != 'integer' OR item_revision < 1
           OR typeof(status) != 'text' OR status COLLATE BINARY NOT IN ({_CLOSED_STATUS_SQL})
           OR typeof(severity) != 'text' OR severity COLLATE BINARY NOT IN ({_CLOSED_SEVERITY_SQL})
           OR typeof(priority_rank) != 'integer' OR priority_rank NOT BETWEEN 0 AND {MAX_PRIORITY_RANK}
           OR typeof(lane_paused) != 'integer' OR lane_paused NOT IN (0, 1)
           OR typeof(requires_human_review) != 'integer' OR requires_human_review NOT IN (0, 1)
           OR typeof(source_kind) != 'text' OR source_kind COLLATE BINARY NOT IN ({_CLOSED_SOURCE_SQL})
           OR (typeof(lane_paused) = 'integer' AND lane_paused = 1
               AND (typeof(source_kind) != 'text' OR source_kind COLLATE BINARY != '{SOURCE_HOST_WORKFLOW_ENGINE}'))
           OR (target_addr IS NOT NULL AND (typeof(target_addr) != 'text'
               OR LENGTH(CAST(target_addr AS BLOB)) NOT BETWEEN 1 AND 256))
           OR (target_incarnation_id IS NOT NULL AND (typeof(target_incarnation_id) != 'text'
               OR LENGTH(CAST(target_incarnation_id AS BLOB)) NOT BETWEEN 1 AND 96))
           OR typeof(title) != 'text'
           OR typeof(summary_text) != 'text'
           OR typeof(artifact_sha256) != 'text' OR LENGTH(CAST(artifact_sha256 AS BLOB)) != 64
           OR typeof(policy_digest) != 'text' OR LENGTH(CAST(policy_digest AS BLOB)) != 64
           OR typeof(review_pin_sha256) != 'text' OR LENGTH(CAST(review_pin_sha256 AS BLOB)) != 64
           OR typeof(metadata_json) != 'text' OR LENGTH(CAST(metadata_json AS BLOB)) > {SQL_MAX_CELL_BYTES}
           OR typeof(created_at) NOT IN ('integer', 'real')
              OR NOT (-9e999 < created_at AND created_at < 9e999)
           OR typeof(updated_at) NOT IN ('integer', 'real')
              OR NOT (-9e999 < updated_at AND updated_at < 9e999)
           OR (expires_at IS NOT NULL AND (typeof(expires_at) NOT IN ('integer', 'real')
              OR NOT (-9e999 < expires_at AND expires_at < 9e999)))
        THEN 1 ELSE 0 END), 0) AS malformed_rows_count
    FROM review_items
"""


def map_sqlite_operational_error(
    exc: sqlite3.OperationalError, deadline: float
) -> CoordPolicyError:
    msg = str(exc).lower()
    if "interrupted" in msg or time.monotonic() >= deadline:
        return CoordPolicyError(ERR_READ_DEADLINE)
    if "locked" in msg or "busy" in msg:
        return CoordPolicyError(ERR_INBOX_BUSY)
    return CoordPolicyError(ERR_INBOX_UNREADABLE)


def _clear_progress_handler(conn: sqlite3.Connection) -> None:
    try:
        conn.set_progress_handler(None, 0)
    except sqlite3.Error:
        return


def _safe_close(conn: sqlite3.Connection | None) -> None:
    if conn is None:
        return
    _clear_progress_handler(conn)
    try:
        conn.close()
    except sqlite3.Error:
        return


def _lstat_reject_user_symlink(acc: Path) -> None:
    try:
        st = os.lstat(acc)
    except FileNotFoundError:
        return
    except (OSError, ValueError) as exc:
        raise CoordPolicyError(ERR_STATE_DIR_UNREADABLE) from exc
    if stat.S_ISLNK(st.st_mode) and st.st_uid != 0:
        raise CoordPolicyError(f"state_dir_symlink_ancestor_rejected: {acc}")


def assert_raw_no_user_symlink_ancestors(raw: Path) -> None:
    """Inspect every raw ancestor prefix left-to-right without collapsing '..'."""
    try:
        anchored = raw if raw.is_absolute() else (Path.cwd() / raw)
    except (OSError, ValueError) as exc:
        raise CoordPolicyError(ERR_STATE_DIR_UNREADABLE) from exc
    parts = anchored.parts
    if not parts:
        return
    acc = Path(parts[0])
    _lstat_reject_user_symlink(acc)
    for part in parts[1:]:
        acc = acc / part
        _lstat_reject_user_symlink(acc)


def verify_regular_private_file_nofollow(
    path: Path, *, required: bool, label: str
) -> None:
    """Verify a regular, single-link, euid-owned, private-mode file without blocking on FIFOs."""
    try:
        _proj_verify_regular_private_file_nofollow(
            path, required=required, label=label
        )
    except ValueError as exc:
        raise CoordPolicyError(f"{label}{_SFX_UNREADABLE}") from exc
    except OSError as exc:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE) from exc


def verify_state_dir_and_db_readonly(
    state_dir: Path, sandbox_root: Path | None
) -> tuple[Path, Path]:
    """Verification-only state directory and inbox.sqlite + sidecar admission."""
    try:
        raw = Path(state_dir)
        is_raw_symlink = raw.is_symlink()
    except (OSError, ValueError) as exc:
        raise CoordPolicyError(ERR_STATE_DIR_UNREADABLE) from exc
    if is_raw_symlink:
        raise CoordPolicyError("state_dir_symlink_rejected")
    assert_raw_no_user_symlink_ancestors(raw)
    try:
        phys = check_not_in_sandbox(raw, sandbox_root)
        check_not_host_production_dir(raw)
        check_not_host_production_dir(phys)
    except PolicyError as exc:
        raise CoordPolicyError(str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise CoordPolicyError(ERR_STATE_DIR_UNREADABLE) from exc
    try:
        if phys.is_symlink() or not phys.exists():
            raise CoordPolicyError("state_dir_missing_or_symlink")
        trusted_dir = assert_trusted_dir(phys, sandbox_root=sandbox_root)
    except PolicyError as exc:
        raise CoordPolicyError(str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise CoordPolicyError(ERR_STATE_DIR_UNREADABLE) from exc
    db_path = trusted_dir / DB_FILENAME
    for idx, suffix in enumerate(DB_ALL_FILES):
        label = "inbox_db" if idx == 0 else f"inbox_db_sidecar_{suffix.lstrip('-')}"
        verify_regular_private_file_nofollow(
            Path(f"{db_path}{suffix}"), required=(idx == 0), label=label
        )
    return trusted_dir, db_path


def _fetch_bounded_pragma_rows(
    conn: sqlite3.Connection, sql: str, max_rows: int, deadline: float
) -> list[dict[str, Any]]:
    cur = execute_bounded(conn, sql, (), deadline)
    rows = cur.fetchmany(max_rows + 1)
    cur.close()
    if len(rows) > max_rows:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    return rows


def _index_columns_strict(
    conn: sqlite3.Connection, idx_name: str, deadline: float
) -> tuple[str, ...] | None:
    rows = _fetch_bounded_pragma_rows(
        conn, f"PRAGMA main.index_info('{idx_name}')", MAX_INDEX_COLS, deadline
    )
    if not rows:
        return None
    cols: list[tuple[int, str]] = []
    for row in rows:
        cid = row.get("cid")
        seqno = row.get("seqno")
        col_name = row.get("name")
        if (
            type(cid) is not int
            or cast(int, cid) < 0
            or type(seqno) is not int
            or not isinstance(col_name, str)
        ):
            return None
        cols.append((cast(int, seqno), col_name))
    cols.sort(key=lambda pair: pair[0])
    return tuple(name for _, name in cols)


def _has_matching_pk_index(
    conn: sqlite3.Connection,
    table_name: str,
    pk_cols: tuple[str, ...],
    idx_by_name: dict[str, dict[str, Any]],
    deadline: float,
) -> bool:
    for idx_name, idx_row in idx_by_name.items():
        if idx_row.get("unique") != 1 or idx_row.get("partial") != 0:
            continue
        is_allowed_name = (
            _AUTOINDEX_NAME_RE.fullmatch(idx_name) is not None
            or (idx_name, table_name) in _EXPECTED_USER_INDEXES
        )
        if is_allowed_name and _index_columns_strict(conn, idx_name, deadline) == pk_cols:
            return True
    return False


def _verify_table_pk_and_unique(
    conn: sqlite3.Connection,
    table_name: str,
    info_sql: str,
    allowed_pks: tuple[tuple[str, ...], ...],
    deadline: float,
) -> dict[str, dict[str, Any]]:
    info_rows = _fetch_bounded_pragma_rows(
        conn, info_sql, MAX_SCHEMA_COLUMNS, deadline
    )
    pk_entries = sorted(
        (
            (cast(int, col["pk"]), str(col["name"]), str(col.get("type", "")))
            for col in info_rows
            if type(col.get("pk")) is int
            and cast(int, col["pk"]) > 0
            and isinstance(col.get("name"), str)
        ),
        key=lambda item: item[0],
    )
    pk_cols = tuple(item[1] for item in pk_entries)
    if pk_cols not in allowed_pks:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)

    idx_rows = _fetch_bounded_pragma_rows(
        conn, _PRAGMA_INDEX_LIST_SQL[table_name], MAX_SCHEMA_OBJECTS, deadline
    )
    idx_by_name = {
        str(row["name"]): row for row in idx_rows if isinstance(row.get("name"), str)
    }
    if table_name == _TBL_SEQ:
        if pk_entries[0][2].upper() != "INTEGER":
            raise CoordPolicyError(ERR_INBOX_UNREADABLE)
        return idx_by_name
    if not _has_matching_pk_index(conn, table_name, pk_cols, idx_by_name, deadline):
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    return idx_by_name


def _verify_indexes_allowlisted(
    conn: sqlite3.Connection,
    table_indexes: dict[str, dict[str, dict[str, Any]]],
    deadline: float,
) -> None:
    schema_indexes = _fetch_bounded_pragma_rows(
        conn, _SQL_LIST_INDEXES, MAX_SCHEMA_OBJECTS, deadline
    )
    for row in schema_indexes:
        name = row.get("name")
        tbl_name = row.get("tbl_name")
        sql_is_null = bool(row.get("sql_is_null"))
        if not isinstance(name, str) or not isinstance(tbl_name, str):
            raise CoordPolicyError(ERR_INBOX_UNREADABLE)
        if (
            sql_is_null
            and tbl_name in _CORE_TABLES
            and _AUTOINDEX_NAME_RE.fullmatch(name) is not None
        ):
            continue
        expected_cols = _EXPECTED_USER_INDEXES.get((name, tbl_name))
        if expected_cols is None:
            raise CoordPolicyError(ERR_INBOX_UNREADABLE)
        idx_meta = table_indexes.get(tbl_name, {}).get(name)
        if (
            idx_meta is None
            or idx_meta.get("partial") != 0
            or _index_columns_strict(conn, name, deadline) != expected_cols
        ):
            raise CoordPolicyError(ERR_INBOX_UNREADABLE)


def _verify_schema_and_anchor_snapshot(
    conn: sqlite3.Connection, deadline: float
) -> None:
    """Anchor snapshot on main.sqlite_schema, verify bounded tables/PKs/indexes, then read counter."""
    unsafe_obj = execute_bounded(
        conn, _SQL_SCHEMA_SAFETY_PRECHECK, (), deadline
    ).fetchone()
    if unsafe_obj is not None:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    obj_count_row = execute_bounded(
        conn, _SQL_SCHEMA_OBJECT_COUNT, (), deadline
    ).fetchone()
    if (
        obj_count_row is None
        or type(obj_count_row.get("cnt")) is not int
        or cast(int, obj_count_row["cnt"]) > MAX_SCHEMA_OBJECTS
    ):
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    for table_name, pragma_sql in _PRAGMA_TABLE_LIST_CHECKS:
        rows = _fetch_bounded_pragma_rows(conn, pragma_sql, 1, deadline)
        if (
            len(rows) != 1
            or rows[0].get("schema") != "main"
            or rows[0].get("name") != table_name
            or rows[0].get("type") != "table"
        ):
            raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    table_indexes: dict[str, dict[str, dict[str, Any]]] = {}
    for table_name, info_sql, allowed_pks in _PRAGMA_TABLE_PK_CHECKS:
        table_indexes[table_name] = _verify_table_pk_and_unique(
            conn, table_name, info_sql, allowed_pks, deadline
        )
    _verify_indexes_allowlisted(conn, table_indexes, deadline)
    execute_bounded(conn, _SQL_READ_SEQ_COUNTER, (), deadline).fetchone()


@contextmanager
def open_readonly_inbox_snapshot(
    db_path: Path, *, deadline: float
) -> Iterator[sqlite3.Connection]:
    """Open a live-WAL mode=ro SQLite snapshot and guarantee ROLLBACK + close."""
    try:
        uri = f"file:{quote(str(db_path), safe='/')}?mode=ro"
    except UnicodeEncodeError as exc:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE) from exc
    remaining_s = check_deadline_s(deadline)
    if not _UMASK_LOCK.acquire(timeout=min(remaining_s, 60.0)):
        raise CoordPolicyError(ERR_READ_DEADLINE)
    try:
        conn: sqlite3.Connection | None = None
        remaining_ms = check_deadline_ms(deadline)
        old_umask = os.umask(0o077)
        try:
            conn = sqlite3.connect(
                uri,
                uri=True,
                isolation_level=None,
                timeout=max(0.001, remaining_ms / 1000.0),
                check_same_thread=False,
            )
            conn.row_factory = dict_row_factory
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA temp_store = MEMORY")
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("PRAGMA cell_size_check = ON")
            apply_remaining_busy_timeout(conn, deadline)
            conn.set_progress_handler(
                lambda: 1 if time.monotonic() >= deadline else 0, 1000
            )
            conn.execute("BEGIN DEFERRED")
            _verify_schema_and_anchor_snapshot(conn, deadline)
        except sqlite3.OperationalError as exc:
            _safe_close(conn)
            raise map_sqlite_operational_error(exc, deadline) from exc
        except sqlite3.DatabaseError as exc:
            _safe_close(conn)
            raise CoordPolicyError(ERR_INBOX_UNREADABLE) from exc
        except BaseException:
            _safe_close(conn)
            raise
        finally:
            os.umask(old_umask)
    finally:
        _UMASK_LOCK.release()

    try:
        yield conn
    except sqlite3.OperationalError as exc:
        raise map_sqlite_operational_error(exc, deadline) from exc
    except sqlite3.DatabaseError as exc:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE) from exc
    finally:
        _clear_progress_handler(conn)
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        finally:
            conn.close()


def read_inbox_seq_counter(conn: sqlite3.Connection, deadline: float) -> int:
    rows = execute_bounded(conn, _SQL_READ_SEQ_COUNTER, (), deadline).fetchall()
    if len(rows) != 1:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    row = rows[0]
    raw_seq = row["last_seq"]
    if bool(row["last_seq_malformed"]) or type(raw_seq) is not int:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    seq_val = cast(int, raw_seq)
    if seq_val < 0 or seq_val > MAX_SQLITE_INT64:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    return seq_val


_COL_OWNER_REVIEW_ID = "owner_review_id"
_SQL_ART_WHERE_REVIEW_ID = (
    "FROM review_artifacts "
    "WHERE typeof(review_id) = 'text' AND review_id COLLATE BINARY = ? "
)


def _assert_artifact_owner_exact(
    rows: list[dict[str, Any]], review_id: str
) -> list[dict[str, Any]]:
    if any(row.get(_COL_OWNER_REVIEW_ID) != review_id for row in rows):
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    return rows


def select_review_items_page(
    conn: sqlite3.Connection,
    *,
    statuses: tuple[str, ...] | None,
    run_id: str | None,
    cursor: ParsedInboxCursor | None,
    limit: int,
    deadline: float,
) -> list[dict[str, Any]]:
    inner_clauses: list[str] = ["1 = 1"]
    params: list[Any] = []
    if statuses is not None:
        placeholders = ", ".join("?" for _ in statuses)
        inner_clauses.append(
            f"typeof(r.status) = 'text' AND r.status COLLATE BINARY IN ({placeholders})"
        )
        params.extend(statuses)
    if run_id is not None:
        inner_clauses.append("typeof(r.run_id) = 'text' AND r.run_id COLLATE BINARY = ?")
        params.append(run_id)

    outer_where = ""
    if cursor is not None:
        outer_where = (
            "WHERE (effective_priority < ?) "
            "OR (effective_priority = ? AND effective_seq > ?) "
            "OR (effective_priority = ? AND effective_seq = ? AND _ord_rid COLLATE BINARY > ?) "
        )
        params.extend(
            (
                cursor.priority_rank,
                cursor.priority_rank,
                cursor.checkpoint_seq,
                cursor.priority_rank,
                cursor.checkpoint_seq,
                cursor.review_id,
            )
        )
    params.append(limit)
    sql = (
        f"WITH ranked AS ("
        f"SELECT r.review_id AS _ord_rid, {_SQL_ITEM_GATED_COLUMNS} "
        f"{_SQL_FROM_REVIEW_ITEMS}"
        f"{_SQL_WORKFLOW_RUN_JOIN} "
        f"WHERE {' AND '.join(inner_clauses)}"
        f") "
        f"SELECT {_SQL_OUTER_ITEM_COLUMNS} "
        f"FROM ranked "
        f"{outer_where}"
        f"ORDER BY effective_priority DESC, effective_seq ASC, _ord_rid COLLATE BINARY ASC "
        f"LIMIT ?"
    )
    rows = execute_bounded(conn, sql, tuple(params), deadline).fetchall()
    if run_id is not None and any(row["run_id"] != run_id for row in rows):
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    return rows


def select_single_review_item(
    conn: sqlite3.Connection, review_id: str, deadline: float
) -> dict[str, Any] | None:
    sql = (
        f"SELECT {_SQL_ITEM_GATED_COLUMNS} "
        f"{_SQL_FROM_REVIEW_ITEMS}"
        f"{_SQL_WORKFLOW_RUN_JOIN} "
        f"WHERE typeof(r.review_id) = 'text' AND r.review_id COLLATE BINARY = ? "
        f"LIMIT 2"
    )
    rows = execute_bounded(conn, sql, (review_id,), deadline).fetchall()
    if not rows:
        return None
    if len(rows) > 1 or rows[0]["review_id"] != review_id:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    return rows[0]


def select_primary_artifacts_for_pin(
    conn: sqlite3.Connection, review_id: str, deadline: float
) -> list[dict[str, Any]]:
    sql = (
        f"SELECT {_SQL_ARTIFACT_GATED_COLUMNS} "
        f"{_SQL_ART_WHERE_REVIEW_ID}"
        f"AND ((typeof(is_primary) != 'integer' OR is_primary NOT IN (0, 1)) OR is_primary = 1) "
        f"ORDER BY artifact_id COLLATE BINARY ASC "
        f"LIMIT 2"
    )
    rows = execute_bounded(conn, sql, (review_id,), deadline).fetchall()
    return _assert_artifact_owner_exact(rows, review_id)


def select_item_artifacts(
    conn: sqlite3.Connection, review_id: str, *, limit: int, deadline: float
) -> list[dict[str, Any]]:
    sql = (
        f"SELECT {_SQL_ARTIFACT_GATED_COLUMNS} "
        f"{_SQL_ART_WHERE_REVIEW_ID}"
        f"ORDER BY (CASE WHEN typeof(is_primary) = 'integer' AND is_primary = 1 "
        f"THEN 1 ELSE 0 END) DESC, artifact_id COLLATE BINARY ASC "
        f"LIMIT ?"
    )
    rows = execute_bounded(conn, sql, (review_id, limit), deadline).fetchall()
    return _assert_artifact_owner_exact(rows, review_id)


def select_status_aggregate_counts(
    conn: sqlite3.Connection, deadline: float
) -> dict[str, int]:
    counts: dict[str, int] = dict.fromkeys(sorted(VALID_STATUSES), 0)
    counts[BUCKET_MALFORMED] = 0
    rows = execute_bounded(conn, _SQL_STATUS_AGG, (), deadline).fetchall()
    for row in rows:
        bucket = str(row["bucket"])
        if bucket in counts:
            counts[bucket] = int(row["cnt"])
        else:
            counts[BUCKET_MALFORMED] += int(row["cnt"])
    return counts


def select_severity_aggregate_counts(
    conn: sqlite3.Connection, deadline: float
) -> tuple[dict[str, int], dict[str, int]]:
    total: dict[str, int] = dict.fromkeys(sorted(VALID_SEVERITIES), 0)
    total[BUCKET_MALFORMED] = 0
    pending: dict[str, int] = dict.fromkeys(sorted(VALID_SEVERITIES), 0)
    pending[BUCKET_MALFORMED] = 0
    rows = execute_bounded(conn, _SQL_SEVERITY_AGG, (), deadline).fetchall()
    for row in rows:
        bucket = str(row["bucket"])
        target = bucket if bucket in total else BUCKET_MALFORMED
        total[target] += int(row["cnt"])
        pending[target] += int(row["pending_cnt"])
    return total, pending


def select_structural_summary_totals(
    conn: sqlite3.Connection, deadline: float
) -> dict[str, int]:
    row = execute_bounded(conn, _SQL_STRUCTURAL_TOTALS, (), deadline).fetchone()
    if row is None:
        return {
            _K_TOTAL_ITEMS: 0,
            _K_PAUSED_LANES_COUNT: 0,
            _K_REQ_HUMAN_REVIEW_COUNT: 0,
            _K_MALFORMED_ROWS_COUNT: 0,
        }
    return {
        _K_TOTAL_ITEMS: int(row[_K_TOTAL_ITEMS]),
        _K_PAUSED_LANES_COUNT: int(row[_K_PAUSED_LANES_COUNT]),
        _K_REQ_HUMAN_REVIEW_COUNT: int(row[_K_REQ_HUMAN_REVIEW_COUNT]),
        _K_MALFORMED_ROWS_COUNT: int(row[_K_MALFORMED_ROWS_COUNT]),
    }
