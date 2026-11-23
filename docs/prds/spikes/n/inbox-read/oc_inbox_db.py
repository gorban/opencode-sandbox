"""Verification-only filesystem admission, live-WAL snapshot opener, and bounded SQL.

Internal database module supporting ``oc_inbox_projection.py``. Never creates
directories or files, never repairs permissions via chmod/fchmod, never writes
to SQLite, and guards against hostile views, triggers, virtual tables, and
``pragma_table_list`` name collisions before reading ``inbox_seq_counter``.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
from typing import Any, cast
from urllib.parse import quote

_INBOX_DIR = Path(__file__).resolve().parent
_SPIKE_N_DIR = _INBOX_DIR.parent
_SPIKE_M_DIR = _SPIKE_N_DIR.parent / "m"
_SPIKE_L_DIR = _SPIKE_N_DIR.parent / "l"
for _import_dir in (
    str(_INBOX_DIR),
    str(_SPIKE_N_DIR),
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

_SQL_SCHEMA_SAFETY_PRECHECK = (
    "SELECT 1 FROM main.sqlite_schema "
    "WHERE type IN ('trigger', 'view') "
    "OR (type = 'table' AND (typeof(rootpage) != 'integer' OR rootpage <= 0)) "
    "LIMIT 1"
)
_PRAGMA_TABLE_LIST_CHECKS: tuple[tuple[str, str], ...] = (
    ("inbox_seq_counter", "PRAGMA main.table_list('inbox_seq_counter')"),
    ("review_items", "PRAGMA main.table_list('review_items')"),
    ("workflow_runs", "PRAGMA main.table_list('workflow_runs')"),
    ("review_artifacts", "PRAGMA main.table_list('review_artifacts')"),
)
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
         WHEN typeof(w.workflow_id) = 'text' AND LENGTH(CAST(w.workflow_id AS BLOB)) <= 128
         THEN w.workflow_id ELSE NULL END AS workflow_id,
    (w.run_id IS NOT NULL AND (typeof(w.workflow_id) != 'text' OR LENGTH(CAST(w.workflow_id AS BLOB)) > 128)) AS workflow_id_malformed,
    CASE WHEN w.run_id IS NULL THEN NULL
         WHEN typeof(w.policy_digest) = 'text' AND LENGTH(CAST(w.policy_digest AS BLOB)) = 64
         THEN w.policy_digest ELSE NULL END AS run_policy_digest,
    (w.run_id IS NOT NULL AND (typeof(w.policy_digest) != 'text' OR LENGTH(CAST(w.policy_digest AS BLOB)) != 64)) AS run_policy_digest_malformed
"""

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
    workflow_run_present, workflow_id, workflow_id_malformed,
    run_policy_digest, run_policy_digest_malformed
"""

_SQL_ARTIFACT_GATED_COLUMNS = """
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
        CASE WHEN typeof(status) = 'text' AND status IN ({_CLOSED_STATUS_SQL})
             THEN status ELSE '{BUCKET_MALFORMED}' END AS bucket,
        COUNT(*) AS cnt
    FROM review_items
    GROUP BY 1
"""

_SQL_SEVERITY_AGG = f"""
    SELECT
        CASE WHEN typeof(severity) = 'text' AND severity IN ({_CLOSED_SEVERITY_SQL})
             THEN severity ELSE '{BUCKET_MALFORMED}' END AS bucket,
        COUNT(*) AS cnt,
        COALESCE(SUM(CASE WHEN typeof(status) = 'text' AND status = '{STATUS_PENDING}'
                          THEN 1 ELSE 0 END), 0) AS pending_cnt
    FROM review_items
    GROUP BY 1
"""

_SQL_STRUCTURAL_TOTALS = f"""
    SELECT
        COUNT(*) AS total_items,
        COALESCE(SUM(CASE WHEN typeof(source_kind) = 'text'
                           AND source_kind = '{SOURCE_HOST_WORKFLOW_ENGINE}'
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
           OR typeof(status) != 'text' OR status NOT IN ({_CLOSED_STATUS_SQL})
           OR typeof(severity) != 'text' OR severity NOT IN ({_CLOSED_SEVERITY_SQL})
           OR typeof(priority_rank) != 'integer' OR priority_rank NOT BETWEEN 0 AND {MAX_PRIORITY_RANK}
           OR typeof(lane_paused) != 'integer' OR lane_paused NOT IN (0, 1)
           OR typeof(requires_human_review) != 'integer' OR requires_human_review NOT IN (0, 1)
           OR typeof(source_kind) != 'text' OR source_kind NOT IN ({_CLOSED_SOURCE_SQL})
           OR (typeof(lane_paused) = 'integer' AND lane_paused = 1
               AND (typeof(source_kind) != 'text' OR source_kind != '{SOURCE_HOST_WORKFLOW_ENGINE}'))
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


def dict_row_factory(cursor: sqlite3.Cursor, row: tuple[Any, ...]) -> dict[str, Any]:
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description or ())}


def check_deadline_s(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        raise CoordPolicyError(ERR_READ_DEADLINE)
    return remaining


def check_deadline_ms(deadline: float) -> int:
    return max(1, int(check_deadline_s(deadline) * 1000.0))


def apply_remaining_busy_timeout(conn: sqlite3.Connection, deadline: float) -> None:
    remaining_ms = check_deadline_ms(deadline)
    conn.execute(f"PRAGMA busy_timeout = {remaining_ms}")


def _is_busy_error(exc: sqlite3.OperationalError) -> bool:
    msg = str(exc).lower()
    return "locked" in msg or "busy" in msg


def execute_bounded(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
    deadline: float,
) -> sqlite3.Cursor:
    while True:
        apply_remaining_busy_timeout(conn, deadline)
        try:
            return conn.execute(sql, params)
        except sqlite3.OperationalError as exc:
            if not _is_busy_error(exc):
                raise
            remaining_s = deadline - time.monotonic()
            if remaining_s <= 0.0:
                raise CoordPolicyError(ERR_READ_DEADLINE) from exc
            time.sleep(min(0.005, remaining_s))


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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        if required:
            raise CoordPolicyError(f"{label}_missing") from exc
        return
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise CoordPolicyError(f"{label}_symlink_rejected") from exc
        raise CoordPolicyError(f"{label}{_SFX_UNREADABLE}") from exc
    except ValueError as exc:
        raise CoordPolicyError(f"{label}{_SFX_UNREADABLE}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CoordPolicyError(f"{label}_not_regular")
        if st.st_nlink != 1:
            raise CoordPolicyError(f"{label}_hardlink_rejected")
        if st.st_uid != os.geteuid():
            raise CoordPolicyError(f"{label}_wrong_owner")
        if (st.st_mode & 0o077) != 0:
            raise CoordPolicyError(f"{label}_unsafe_mode")
    finally:
        os.close(fd)


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


def _verify_schema_and_anchor_snapshot(
    conn: sqlite3.Connection, deadline: float
) -> None:
    """Anchor snapshot on main.sqlite_schema, check ordinary tables, then read counter."""
    unsafe_obj = execute_bounded(
        conn, _SQL_SCHEMA_SAFETY_PRECHECK, (), deadline
    ).fetchone()
    if unsafe_obj is not None:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    for table_name, pragma_sql in _PRAGMA_TABLE_LIST_CHECKS:
        rows = execute_bounded(conn, pragma_sql, (), deadline).fetchall()
        if (
            len(rows) != 1
            or rows[0].get("schema") != "main"
            or rows[0].get("name") != table_name
            or rows[0].get("type") != "table"
        ):
            raise CoordPolicyError(ERR_INBOX_UNREADABLE)
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
            f"typeof(r.status) = 'text' AND r.status IN ({placeholders})"
        )
        params.extend(statuses)
    if run_id is not None:
        inner_clauses.append("typeof(r.run_id) = 'text' AND r.run_id = ?")
        params.append(run_id)

    outer_where = ""
    if cursor is not None:
        outer_where = (
            "WHERE (effective_priority < ?) "
            "OR (effective_priority = ? AND effective_seq > ?) "
            "OR (effective_priority = ? AND effective_seq = ? AND _ord_rid > ?) "
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
        f"FROM review_items r "
        f"LEFT JOIN workflow_runs w ON typeof(r.run_id) = 'text' AND w.run_id = r.run_id "
        f"WHERE {' AND '.join(inner_clauses)}"
        f") "
        f"SELECT {_SQL_OUTER_ITEM_COLUMNS} "
        f"FROM ranked "
        f"{outer_where}"
        f"ORDER BY effective_priority DESC, effective_seq ASC, _ord_rid ASC "
        f"LIMIT ?"
    )
    return execute_bounded(conn, sql, tuple(params), deadline).fetchall()


def select_single_review_item(
    conn: sqlite3.Connection, review_id: str, deadline: float
) -> dict[str, Any] | None:
    sql = (
        f"SELECT {_SQL_ITEM_GATED_COLUMNS} "
        f"FROM review_items r "
        f"LEFT JOIN workflow_runs w ON typeof(r.run_id) = 'text' AND w.run_id = r.run_id "
        f"WHERE typeof(r.review_id) = 'text' AND r.review_id = ?"
    )
    return execute_bounded(conn, sql, (review_id,), deadline).fetchone()


def select_primary_artifacts_for_pin(
    conn: sqlite3.Connection, review_id: str, deadline: float
) -> list[dict[str, Any]]:
    sql = (
        f"SELECT {_SQL_ARTIFACT_GATED_COLUMNS} "
        f"FROM review_artifacts "
        f"WHERE typeof(review_id) = 'text' AND review_id = ? "
        f"AND ((typeof(is_primary) != 'integer' OR is_primary NOT IN (0, 1)) OR is_primary = 1) "
        f"ORDER BY artifact_id ASC "
        f"LIMIT 2"
    )
    return execute_bounded(conn, sql, (review_id,), deadline).fetchall()


def select_item_artifacts(
    conn: sqlite3.Connection, review_id: str, *, limit: int, deadline: float
) -> list[dict[str, Any]]:
    sql = (
        f"SELECT {_SQL_ARTIFACT_GATED_COLUMNS} "
        f"FROM review_artifacts "
        f"WHERE typeof(review_id) = 'text' AND review_id = ? "
        f"ORDER BY (CASE WHEN typeof(is_primary) = 'integer' AND is_primary = 1 "
        f"THEN 1 ELSE 0 END) DESC, artifact_id ASC "
        f"LIMIT ?"
    )
    return execute_bounded(conn, sql, (review_id, limit), deadline).fetchall()


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
