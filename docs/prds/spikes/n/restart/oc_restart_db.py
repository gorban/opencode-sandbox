"""Filesystem admission, exclusive locking, bounded WAL SQLite helpers, and storage-class gated reads."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import errno
import fcntl
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
from typing import Any, TypeVar
from urllib.parse import quote

_RESTART_DIR = Path(__file__).resolve().parent
_SPIKE_N_DIR = _RESTART_DIR.parent
_SPIKE_L_DIR = _SPIKE_N_DIR.parent / "l"
for _import_dir in (str(_RESTART_DIR), str(_SPIKE_N_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_broker_common import _UMASK_LOCK  # noqa: E402
from oc_restart_contract import (  # noqa: E402
    ALLOWED_EFFECTS,
    CORE_TABLE_NAMES,
    ERR_DUP_MATERIALIZED_KEY,
    ERR_EXTRA_ROWS,
    ERR_INVALID_META_SEQ,
    ERR_JOURNAL_CORRUPT,
    ERR_JOURNAL_UNREADABLE,
    ERR_LOCK_HELD,
    ERR_MALFORMED_STORAGE,
    ERR_META_MISSING,
    ERR_META_MISSING_NONEMPTY,
    ERR_META_MULTIPLE,
    ERR_OP_DEADLINE,
    ERR_UNEXPECTED_SCHEMA,
    KEY_ATTEMPT_NO,
    KEY_CANCEL_REQUESTED,
    KEY_CREATED_AT_US,
    KEY_CREATED_EPOCH,
    KEY_CURRENT_EPOCH,
    KEY_DEPENDS_ON,
    KEY_EFFECT_KIND,
    KEY_ENTRY_HASH,
    KEY_EVIDENCE_DIGEST,
    KEY_FAILURE_REASON,
    KEY_GRANT_GENERATION,
    KEY_IDEM_KEY,
    KEY_LAST_EVENT_SEQ,
    KEY_LEASE_EPOCH,
    KEY_MAX_ATTEMPTS,
    KEY_OUTPUT_DIGEST,
    KEY_RECON_EPOCH,
    KEY_RECON_KEY,
    KEY_RECORDED_SEQ,
    KEY_REQUIRES_AUTHORITY,
    KEY_RESOLUTION,
    KEY_SIDE_EFFECTING,
    KEY_SPEC_DIGEST,
    KEY_STATE_NAME,
    KEY_STEP_ORDER,
    KEY_SUPERVISOR_EPOCH,
    KEY_UPDATED_AT_US,
    KEY_WORKFLOW_ID,
    KEY_WORKFLOW_PLAN_DIGEST,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_ID_BYTES,
    MAX_REASON_BYTES,
    MAX_STEP_ATTEMPTS,
    PURE_IDEMPOTENT_EFFECTS,
    EventType,
    IdempotencyOutcome,
    JournalEvent,
    JournalIntegrityError,
    ReconcileResolution,
    ReplayMismatchError,
    RestartStorageError,
    RestartValidationError,
    RunStatus,
    StepDefinition,
    StepIdempotencyRecord,
    StepReconciliationRecord,
    StepStatus,
    SupervisorMetaRecord,
    WorkflowRunRecord,
    WorkflowStepRecord,
    parse_canonical_json_blob,
    validate_int64,
    validate_opaque_id,
    validate_reason,
    validate_sha256_hex,
    validate_step_id,
)
from oc_schema import (  # noqa: E402
    PolicyError,
    assert_trusted_dir,
    check_not_host_production_dir,
    check_not_in_sandbox,
)

DB_FILENAME = "workflow_restart.sqlite"
DB_ALL_FILES: tuple[str, ...] = ("", "-wal", "-shm", "-journal")
LOCK_FILENAME = ".workflow_restart.lock"

_COL_DIRTY_SHUTDOWN = "dirty_shutdown"
_COL_OUTCOME_STATUS = "outcome_status"
_COL_EVENT_TYPE = "event_type"

_TBL_META = "supervisor_meta"
_TBL_RUNS = "workflow_runs"
_TBL_STEPS = "workflow_steps"
_TBL_IDEM = "step_idempotency_keys"
_TBL_RECON = "step_reconciliations"
_TBL_EVENTS = "workflow_event_log"

_NON_META_TABLES: tuple[str, ...] = (
    _TBL_RUNS,
    _TBL_STEPS,
    _TBL_IDEM,
    _TBL_RECON,
    _TBL_EVENTS,
)

_AUTOINDEX_NAME_RE = re.compile(r"^sqlite_autoindex_[a-zA-Z\d_]+_\d+$", re.ASCII)
_COLLATE_CLAUSE_RE = re.compile(r"\bcollate\b", re.IGNORECASE)
_SQL_BIN_EQ = "COLLATE BINARY = ?"
_SQL_BIN_EQ_LIMIT_2 = "COLLATE BINARY = ? LIMIT 2"

_DEADLINE_CHECK_STRIDE = 128

_SCHEMA_SQL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS supervisor_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        current_epoch INTEGER NOT NULL CHECK (current_epoch >= 1),
        last_event_seq INTEGER NOT NULL CHECK (last_event_seq >= 0),
        head_hash TEXT NOT NULL,
        dirty_shutdown INTEGER NOT NULL CHECK (dirty_shutdown IN (0, 1)),
        updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= 0)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS workflow_runs (
        run_id TEXT PRIMARY KEY,
        workflow_id TEXT NOT NULL,
        spec_digest TEXT NOT NULL,
        workflow_plan_digest TEXT NOT NULL,
        grant_generation INTEGER NOT NULL CHECK (grant_generation >= 1),
        requires_authority INTEGER NOT NULL DEFAULT 0 CHECK (requires_authority IN (0, 1)),
        status TEXT NOT NULL,
        cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
        created_epoch INTEGER NOT NULL CHECK (created_epoch >= 1),
        created_at_us INTEGER NOT NULL CHECK (created_at_us >= 0),
        updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= 0)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS workflow_steps (
        run_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        step_order INTEGER NOT NULL CHECK (step_order >= 0),
        state_name TEXT NOT NULL,
        effect_kind TEXT NOT NULL,
        side_effecting INTEGER NOT NULL CHECK (side_effecting IN (0, 1)),
        depends_on_json TEXT NOT NULL,
        max_attempts INTEGER NOT NULL CHECK (max_attempts >= 1),
        status TEXT NOT NULL,
        attempt_no INTEGER NOT NULL CHECK (attempt_no >= 0),
        lease_epoch INTEGER NOT NULL CHECK (lease_epoch >= 0),
        idempotency_key TEXT,
        output_digest TEXT,
        failure_reason TEXT,
        updated_at_us INTEGER NOT NULL CHECK (updated_at_us >= 0),
        PRIMARY KEY (run_id, step_id),
        FOREIGN KEY (run_id) REFERENCES workflow_runs(run_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS step_idempotency_keys (
        run_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        step_id TEXT NOT NULL,
        attempt_no INTEGER NOT NULL CHECK (attempt_no >= 1),
        lease_epoch INTEGER NOT NULL CHECK (lease_epoch >= 1),
        outcome_status TEXT NOT NULL,
        output_digest TEXT,
        failure_reason TEXT,
        recorded_seq INTEGER NOT NULL CHECK (recorded_seq >= 1),
        PRIMARY KEY (run_id, idempotency_key),
        UNIQUE (run_id, step_id, attempt_no),
        FOREIGN KEY (run_id, step_id) REFERENCES workflow_steps(run_id, step_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS step_reconciliations (
        run_id TEXT NOT NULL,
        reconciliation_key TEXT NOT NULL,
        step_id TEXT NOT NULL,
        attempt_no INTEGER NOT NULL CHECK (attempt_no >= 1),
        reconciled_epoch INTEGER NOT NULL CHECK (reconciled_epoch >= 1),
        resolution TEXT NOT NULL,
        output_digest TEXT,
        evidence_digest TEXT NOT NULL,
        reason TEXT NOT NULL,
        recorded_seq INTEGER NOT NULL CHECK (recorded_seq >= 1),
        PRIMARY KEY (run_id, reconciliation_key),
        FOREIGN KEY (run_id, step_id) REFERENCES workflow_steps(run_id, step_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS workflow_event_log (
        seq INTEGER PRIMARY KEY,
        supervisor_epoch INTEGER NOT NULL CHECK (supervisor_epoch >= 1),
        event_type TEXT NOT NULL,
        run_id TEXT,
        step_id TEXT,
        payload_json TEXT NOT NULL,
        created_at_us INTEGER NOT NULL CHECK (created_at_us >= 0),
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
    )
    """,
)


# --- Deadlines & SQLite connection hygiene ---


def dict_row_factory(cursor: sqlite3.Cursor, row: tuple[Any, ...]) -> dict[str, Any]:
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description or ())}


def check_deadline_s(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        raise RestartStorageError(ERR_OP_DEADLINE)
    return remaining


def check_deadline_ms(deadline: float) -> int:
    return max(1, int(check_deadline_s(deadline) * 1000.0))


def apply_remaining_busy_timeout(conn: sqlite3.Connection, deadline: float) -> None:
    remaining_ms = check_deadline_ms(deadline)
    conn.execute(f"PRAGMA busy_timeout = {remaining_ms}")


def install_progress_deadline(conn: sqlite3.Connection, deadline: float) -> None:
    def _progress() -> int:
        return 1 if time.monotonic() >= deadline else 0

    conn.set_progress_handler(_progress, 1000)


def _is_busy_error(exc: sqlite3.OperationalError) -> bool:
    msg = str(exc).lower()
    return "locked" in msg or "busy" in msg


def map_sqlite_error(exc: sqlite3.OperationalError, deadline: float) -> RestartStorageError:
    msg = str(exc).lower()
    if "interrupted" in msg or time.monotonic() >= deadline:
        return RestartStorageError(ERR_OP_DEADLINE)
    if "locked" in msg or "busy" in msg:
        return RestartStorageError("journal_busy")
    return RestartStorageError(ERR_JOURNAL_UNREADABLE)


def safe_close(conn: sqlite3.Connection | None) -> None:
    if conn is None:
        return
    try:
        conn.set_progress_handler(None, 0)
    except sqlite3.Error:
        pass
    try:
        conn.close()
    except sqlite3.Error:
        pass


def safe_rollback_and_close(conn: sqlite3.Connection | None) -> None:
    if conn is None:
        return
    try:
        conn.set_progress_handler(None, 0)
    except sqlite3.Error:
        pass
    try:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass
    safe_close(conn)


@contextmanager
def scoped_op_deadline(conn: sqlite3.Connection, deadline: float) -> Iterator[None]:
    """Scope busy_timeout + VM progress handler to one operation, always clearing in finally."""
    apply_remaining_busy_timeout(conn, deadline)
    install_progress_deadline(conn, deadline)
    try:
        yield
    except sqlite3.OperationalError as exc:
        raise map_sqlite_error(exc, deadline) from exc
    except sqlite3.DatabaseError as exc:
        raise RestartStorageError(ERR_JOURNAL_CORRUPT) from exc
    finally:
        try:
            conn.set_progress_handler(None, 0)
        except sqlite3.Error:
            pass


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
                raise RestartStorageError(ERR_OP_DEADLINE) from exc
            time.sleep(min(0.005, remaining_s))


# --- Filesystem admission & exclusive supervisor lock ---


def assert_raw_no_user_symlink_ancestors(raw: Path) -> None:
    """Reject non-root symlinks along raw lexical path preserving '..' components."""
    anchored = raw if raw.is_absolute() else (Path.cwd() / raw)
    parts = anchored.parts
    if not parts:
        return
    acc = Path(parts[0])
    for idx, part in enumerate(parts):
        if idx > 0:
            acc = acc / part
        try:
            st = os.lstat(acc)
            if stat.S_ISLNK(st.st_mode) and st.st_uid != 0:
                raise RestartStorageError(f"state_dir_symlink_ancestor_rejected: {acc}")
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RestartStorageError(f"state_dir_ancestor_unreadable: {acc}") from exc


def _verify_ancestor_stat(cur: Path, uid: int) -> None:
    try:
        st = os.lstat(cur)
    except OSError as exc:
        raise RestartStorageError(f"state_dir_ancestor_unreadable: {cur}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RestartStorageError(f"state_dir_ancestor_not_dir: {cur}")
    if st.st_uid not in (uid, 0):
        raise RestartStorageError(f"state_dir_ancestor_wrong_owner: {cur}")
    is_root_sticky = st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
    if (st.st_mode & 0o022) != 0 and not is_root_sticky:
        raise RestartStorageError(f"state_dir_ancestor_writable: {cur}")


def assert_existing_ancestors_trusted(phys: Path) -> None:
    """Verify every existing ancestor directory up to '/' is owned by euid/root and non-writable."""
    uid = os.geteuid()
    cur = phys
    while not cur.exists() and cur.parent != cur:
        cur = cur.parent
    while True:
        _verify_ancestor_stat(cur, uid)
        if cur.parent == cur:
            break
        cur = cur.parent


def create_private_dir_locked(phys: Path, *, deadline: float) -> None:
    """Create missing leaf state_dir with 0o700 under _UMASK_LOCK without repairing existing dirs."""
    if not phys.parent.exists():
        raise RestartStorageError("state_dir_parent_missing")
    remaining_s = check_deadline_s(deadline)
    if not _UMASK_LOCK.acquire(timeout=remaining_s):
        raise RestartStorageError(ERR_OP_DEADLINE)
    try:
        check_deadline_ms(deadline)
        old_umask = os.umask(0o077)
        try:
            os.mkdir(phys, 0o700)
        except FileExistsError:
            return
        except OSError as exc:
            raise RestartStorageError("state_dir_create_failed") from exc
        finally:
            os.umask(old_umask)
    finally:
        _UMASK_LOCK.release()


def _check_private_regular_stat(st: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(st.st_mode):
        raise RestartStorageError(f"{label}_not_regular")
    if st.st_nlink != 1:
        raise RestartStorageError(f"{label}_hardlink_rejected")
    if st.st_uid != os.geteuid():
        raise RestartStorageError(f"{label}_wrong_owner")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise RestartStorageError(f"{label}_unsafe_mode")


def verify_regular_private_file_nofollow(
    path: Path, *, required: bool, label: str
) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        if required:
            raise RestartStorageError(f"{label}_missing") from exc
        return
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise RestartStorageError(f"{label}_symlink_rejected") from exc
        raise RestartStorageError(f"{label}_unreadable") from exc
    try:
        _check_private_regular_stat(os.fstat(fd), label)
    finally:
        os.close(fd)


def verify_all_db_files(db_path: Path, *, required_main: bool) -> None:
    for idx, suffix in enumerate(DB_ALL_FILES):
        label = "journal_db" if idx == 0 else f"journal_sidecar_{suffix.lstrip('-')}"
        verify_regular_private_file_nofollow(
            Path(f"{db_path}{suffix}"),
            required=(idx == 0 and required_main),
            label=label,
        )


def admit_state_dir(
    state_dir: Path,
    *,
    sandbox_root: Path | None,
    create_if_missing: bool,
    deadline: float,
) -> tuple[Path, Path]:
    raw = Path(state_dir)
    if raw.is_symlink():
        raise RestartStorageError("state_dir_symlink_rejected")
    assert_raw_no_user_symlink_ancestors(raw)
    try:
        phys = check_not_in_sandbox(raw, sandbox_root)
        check_not_host_production_dir(raw)
        check_not_host_production_dir(phys)
    except PolicyError as exc:
        raise RestartStorageError(str(exc)) from exc
    if phys.is_symlink():
        raise RestartStorageError("state_dir_symlink_rejected")
    if not phys.exists():
        if not create_if_missing:
            raise RestartStorageError("state_dir_missing")
        assert_existing_ancestors_trusted(phys)
        create_private_dir_locked(phys, deadline=deadline)
    try:
        trusted_dir = assert_trusted_dir(phys, sandbox_root=sandbox_root)
    except PolicyError as exc:
        raise RestartStorageError(str(exc)) from exc
    dir_st = os.lstat(trusted_dir)
    if stat.S_IMODE(dir_st.st_mode) != 0o700:
        raise RestartStorageError("state_dir_unsafe_mode")
    db_path = trusted_dir / DB_FILENAME
    verify_all_db_files(db_path, required_main=(not create_if_missing))
    return trusted_dir, db_path


def _open_lock_fd_locked(lock_path: Path, deadline: float) -> int:
    remaining_s = check_deadline_s(deadline)
    if not _UMASK_LOCK.acquire(timeout=remaining_s):
        raise RestartStorageError(ERR_OP_DEADLINE)
    flags = (
        os.O_CREAT
        | os.O_RDWR
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        check_deadline_ms(deadline)
        old_umask = os.umask(0o077)
        try:
            return os.open(lock_path, flags, 0o600)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise RestartStorageError("supervisor_lock_symlink_rejected") from exc
            raise RestartStorageError("supervisor_lock_open_failed") from exc
        finally:
            os.umask(old_umask)
    finally:
        _UMASK_LOCK.release()


def acquire_exclusive_supervisor_lock(trusted_dir: Path, *, deadline: float) -> int:
    lock_path = trusted_dir / LOCK_FILENAME
    fd = _open_lock_fd_locked(lock_path, deadline)
    try:
        fst = os.fstat(fd)
        _check_private_regular_stat(fst, "supervisor_lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RestartStorageError(ERR_LOCK_HELD) from exc
        try:
            lst = os.lstat(lock_path)
        except OSError as exc:
            raise RestartStorageError("supervisor_lock_unlinked") from exc
        if (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
            raise RestartStorageError("supervisor_lock_inode_mismatch")
        return fd
    except BaseException:
        os.close(fd)
        raise


def release_lock_fd(lock_fd: int | None) -> None:
    if lock_fd is None or lock_fd < 0:
        return
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(lock_fd)
    except OSError:
        pass


def open_sqlite_bounded(
    db_path: Path, *, readonly: bool, deadline: float
) -> sqlite3.Connection:
    """Open SQLite WAL DB under _UMASK_LOCK with URI validation pre-lock and safe pragma order."""
    try:
        mode = "ro" if readonly else "rwc"
        uri = f"file:{quote(str(db_path), safe='/')}?mode={mode}"
    except UnicodeEncodeError as exc:
        raise RestartStorageError("journal_uri_unencodable") from exc

    remaining_s = check_deadline_s(deadline)
    if not _UMASK_LOCK.acquire(timeout=remaining_s):
        raise RestartStorageError(ERR_OP_DEADLINE)
    conn: sqlite3.Connection | None = None
    try:
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
            conn.execute("PRAGMA temp_store = MEMORY")
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("PRAGMA cell_size_check = ON")
            conn.execute("PRAGMA foreign_keys = ON")
            with scoped_op_deadline(conn, deadline):
                if readonly:
                    execute_bounded(conn, "PRAGMA query_only = ON", (), deadline)
                    execute_bounded(conn, "BEGIN DEFERRED", (), deadline)
                    execute_bounded(
                        conn, "SELECT 1 FROM main.sqlite_schema LIMIT 1", (), deadline
                    ).fetchone()
                else:
                    execute_bounded(conn, "PRAGMA journal_mode = WAL", (), deadline)
                    execute_bounded(conn, "PRAGMA synchronous = FULL", (), deadline)
            return conn
        except BaseException:
            safe_close(conn)
            raise
        finally:
            os.umask(old_umask)
    finally:
        _UMASK_LOCK.release()


# --- Schema integrity & DDL ---

_MAX_SCHEMA_ROWS = 128
_SQL_INSPECT_SCHEMA = (
    "SELECT "
    "CASE WHEN typeof(type) = 'text' AND LENGTH(CAST(type AS BLOB)) <= 32 THEN type ELSE NULL END AS type, "
    "CASE WHEN typeof(name) = 'text' AND LENGTH(CAST(name AS BLOB)) <= 128 THEN name ELSE NULL END AS name, "
    "CASE WHEN typeof(tbl_name) = 'text' AND LENGTH(CAST(tbl_name AS BLOB)) <= 128 THEN tbl_name ELSE NULL END AS tbl_name, "
    "CASE WHEN typeof(rootpage) = 'integer' THEN rootpage ELSE NULL END AS rootpage, "
    "(sql IS NULL) AS sql_is_null, "
    "CASE WHEN typeof(sql) = 'text' AND LENGTH(CAST(sql AS BLOB)) <= 8192 THEN sql ELSE NULL END AS sql_text, "
    "(type = 'table' AND name NOT LIKE 'sqlite_%' "
    "AND (typeof(sql) != 'text' OR LENGTH(CAST(sql AS BLOB)) > 8192)) AS sql_malformed, "
    "(typeof(type) != 'text' OR typeof(name) != 'text' OR typeof(tbl_name) != 'text' "
    "OR typeof(rootpage) != 'integer') AS meta_malformed "
    "FROM main.sqlite_schema LIMIT ?"
)


def _check_schema_table_row(row: dict[str, Any], found_core: set[str]) -> None:
    name = row.get("name")
    rootpage = row.get("rootpage")
    if isinstance(name, str) and name.startswith("sqlite_"):
        return
    if name not in CORE_TABLE_NAMES or type(rootpage) is not int or rootpage <= 0:
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
    sql_text = row.get("sql_text")
    if (
        row.get("sql_malformed") != 0
        or not isinstance(sql_text, str)
        or _COLLATE_CLAUSE_RE.search(sql_text) is not None
    ):
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
    found_core.add(name)


def _check_schema_index_row(row: dict[str, Any], name: Any, tbl_name: Any) -> None:
    valid_autoindex = (
        tbl_name in CORE_TABLE_NAMES
        and isinstance(name, str)
        and _AUTOINDEX_NAME_RE.fullmatch(name) is not None
        and row.get("sql_is_null") == 1
    )
    if not valid_autoindex:
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)


def _check_schema_row(row: dict[str, Any], found_core: set[str]) -> None:
    if row.get("meta_malformed") != 0:
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
    obj_type = row.get("type")
    if obj_type == "table":
        _check_schema_table_row(row, found_core)
        return
    if obj_type == "index":
        _check_schema_index_row(row, row.get("name"), row.get("tbl_name"))
        return
    raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)


_CORE_TABLE_PKS: dict[str, tuple[str, ...]] = {
    _TBL_META: ("id",),
    _TBL_RUNS: ("run_id",),
    _TBL_STEPS: ("run_id", "step_id"),
    _TBL_IDEM: ("run_id", KEY_IDEM_KEY),
    _TBL_RECON: ("run_id", KEY_RECON_KEY),
    _TBL_EVENTS: ("seq",),
}

_CORE_TABLE_COLS: dict[str, frozenset[str]] = {
    _TBL_META: frozenset(
        {
            "id",
            KEY_CURRENT_EPOCH,
            KEY_LAST_EVENT_SEQ,
            "head_hash",
            _COL_DIRTY_SHUTDOWN,
            KEY_UPDATED_AT_US,
        }
    ),
    _TBL_RUNS: frozenset(
        {
            "run_id",
            KEY_WORKFLOW_ID,
            KEY_SPEC_DIGEST,
            KEY_WORKFLOW_PLAN_DIGEST,
            KEY_GRANT_GENERATION,
            KEY_REQUIRES_AUTHORITY,
            "status",
            KEY_CANCEL_REQUESTED,
            KEY_CREATED_EPOCH,
            KEY_CREATED_AT_US,
            KEY_UPDATED_AT_US,
        }
    ),
    _TBL_STEPS: frozenset(
        {
            "run_id",
            "step_id",
            KEY_STEP_ORDER,
            KEY_STATE_NAME,
            KEY_EFFECT_KIND,
            KEY_SIDE_EFFECTING,
            "depends_on_json",
            KEY_MAX_ATTEMPTS,
            "status",
            KEY_ATTEMPT_NO,
            KEY_LEASE_EPOCH,
            KEY_IDEM_KEY,
            KEY_OUTPUT_DIGEST,
            KEY_FAILURE_REASON,
            KEY_UPDATED_AT_US,
        }
    ),
    _TBL_IDEM: frozenset(
        {
            "run_id",
            KEY_IDEM_KEY,
            "step_id",
            KEY_ATTEMPT_NO,
            KEY_LEASE_EPOCH,
            _COL_OUTCOME_STATUS,
            KEY_OUTPUT_DIGEST,
            KEY_FAILURE_REASON,
            KEY_RECORDED_SEQ,
        }
    ),
    _TBL_RECON: frozenset(
        {
            "run_id",
            KEY_RECON_KEY,
            "step_id",
            KEY_ATTEMPT_NO,
            KEY_RECON_EPOCH,
            KEY_RESOLUTION,
            KEY_OUTPUT_DIGEST,
            KEY_EVIDENCE_DIGEST,
            "reason",
            KEY_RECORDED_SEQ,
        }
    ),
    _TBL_EVENTS: frozenset(
        {
            "seq",
            KEY_SUPERVISOR_EPOCH,
            _COL_EVENT_TYPE,
            "run_id",
            "step_id",
            "payload_json",
            KEY_CREATED_AT_US,
            "prev_hash",
            KEY_ENTRY_HASH,
        }
    ),
}

_CORE_TABLE_REQUIRED_INDEXES: dict[str, frozenset[tuple[str, ...]]] = {
    _TBL_RUNS: frozenset({("run_id",)}),
    _TBL_STEPS: frozenset({("run_id", "step_id")}),
    _TBL_IDEM: frozenset({("run_id", KEY_IDEM_KEY), ("run_id", "step_id", KEY_ATTEMPT_NO)}),
    _TBL_RECON: frozenset({("run_id", KEY_RECON_KEY)}),
}


def _verify_core_table_columns_and_pk(
    conn: sqlite3.Connection, table_name: str, deadline: float
) -> None:
    cols = execute_bounded(
        conn, f"PRAGMA main.table_info('{table_name}')", (), deadline
    ).fetchall()
    col_names: set[str] = set()
    pk_pairs: list[tuple[int, str]] = []
    for col in cols:
        col_name = col.get("name")
        if not isinstance(col_name, str):
            raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
        col_names.add(col_name)
        pk_ord = col.get("pk")
        if type(pk_ord) is int and pk_ord > 0:
            pk_pairs.append((pk_ord, col_name))
    pk_pairs.sort(key=lambda pair: pair[0])
    if col_names != _CORE_TABLE_COLS[table_name]:
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
    if tuple(name for _, name in pk_pairs) != _CORE_TABLE_PKS[table_name]:
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)


def _read_binary_index_cols(
    conn: sqlite3.Connection, idx_name: str, deadline: float
) -> tuple[str, ...]:
    if _AUTOINDEX_NAME_RE.fullmatch(idx_name) is None:
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
    info_rows = execute_bounded(
        conn, f"PRAGMA main.index_xinfo('{idx_name}')", (), deadline
    ).fetchall()
    pairs: list[tuple[int, str]] = []
    for item in info_rows:
        if item.get("key") != 1:
            continue
        seqno = item.get("seqno")
        cname = item.get("name")
        if type(seqno) is not int or not isinstance(cname, str) or item.get("coll") != "BINARY":
            raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
        pairs.append((seqno, cname))
    pairs.sort(key=lambda pair: pair[0])
    return tuple(cname for _, cname in pairs)


def _verify_core_table_indexes(
    conn: sqlite3.Connection, table_name: str, deadline: float
) -> None:
    idx_rows = execute_bounded(
        conn, f"PRAGMA main.index_list('{table_name}')", (), deadline
    ).fetchall()
    found: set[tuple[str, ...]] = set()
    for idx in idx_rows:
        idx_name = idx.get("name")
        if idx.get("unique") != 1 or idx.get("partial") != 0 or not isinstance(idx_name, str):
            raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
        found.add(_read_binary_index_cols(conn, idx_name, deadline))
    required = _CORE_TABLE_REQUIRED_INDEXES.get(table_name, frozenset())
    if not required.issubset(found):
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)


def _verify_core_table_pragma(
    conn: sqlite3.Connection, table_name: str, deadline: float
) -> None:
    rows = execute_bounded(
        conn, f"PRAGMA main.table_list('{table_name}')", (), deadline
    ).fetchall()
    if len(rows) != 1:
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
    info = rows[0]
    if (
        info.get("schema") != "main"
        or info.get("name") != table_name
        or info.get("type") != "table"
    ):
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
    _verify_core_table_columns_and_pk(conn, table_name, deadline)
    _verify_core_table_indexes(conn, table_name, deadline)


def verify_no_unexpected_schema_objects(
    conn: sqlite3.Connection, *, require_core_tables: bool, deadline: float
) -> None:
    schema_rows = execute_bounded(
        conn, _SQL_INSPECT_SCHEMA, (_MAX_SCHEMA_ROWS,), deadline
    ).fetchall()
    if len(schema_rows) >= _MAX_SCHEMA_ROWS:
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
    found_core: set[str] = set()
    for row in schema_rows:
        _check_schema_row(row, found_core)
    if require_core_tables and found_core != CORE_TABLE_NAMES:
        raise JournalIntegrityError(ERR_UNEXPECTED_SCHEMA)
    for table_name in sorted(found_core):
        _verify_core_table_pragma(conn, table_name, deadline)


def ensure_schema(conn: sqlite3.Connection, deadline: float) -> None:
    for stmt in _SCHEMA_SQL:
        execute_bounded(conn, stmt, (), deadline)


def assert_all_other_tables_empty(conn: sqlite3.Connection, deadline: float) -> None:
    for tbl in _NON_META_TABLES:
        row = execute_bounded(conn, f"SELECT 1 FROM {tbl} LIMIT 1", (), deadline).fetchone()
        if row is not None:
            raise JournalIntegrityError(ERR_META_MISSING_NONEMPTY)


# --- SQL storage-class gating helpers & row decoders ---

_MALFORMED_SUFFIX = "_malformed"
_SQL_CASE_WHEN = "CASE WHEN "
_SQL_ELSE_NULL_AS = " ELSE NULL END AS "
_SQL_TEXT_LEN = ") = 'text' AND LENGTH(CAST("
_SQL_NOT_TEXT_LEN = ") != 'text' OR LENGTH(CAST("
_SQL_BLOB_LE = " AS BLOB)) <= "
_SQL_BLOB_GT = " AS BLOB)) > "


def _sql_gated(expr_valid: str, expr_invalid: str, value_expr: str, alias: str) -> str:
    return (
        f"{_SQL_CASE_WHEN}{expr_valid} THEN {value_expr}{_SQL_ELSE_NULL_AS}{alias}, "
        f"({expr_invalid}) AS {alias}{_MALFORMED_SUFFIX}"
    )


def _sql_nullable_gated(col: str, valid: str, invalid: str) -> str:
    return (
        f"{_SQL_CASE_WHEN}{col} IS NULL THEN NULL WHEN {valid} THEN {col}"
        f"{_SQL_ELSE_NULL_AS}{col}, "
        f"({col} IS NOT NULL AND ({invalid})) AS {col}{_MALFORMED_SUFFIX}"
    )


def _sql_int(col: str, alias: str | None = None) -> str:
    a = alias or col
    return _sql_gated(f"typeof({col}) = 'integer'", f"typeof({col}) != 'integer'", col, a)


def _sql_bool(col: str, alias: str | None = None) -> str:
    a = alias or col
    return _sql_gated(
        f"typeof({col}) = 'integer' AND {col} IN (0, 1)",
        f"typeof({col}) != 'integer' OR {col} NOT IN (0, 1)",
        col,
        a,
    )


def _sql_text_predicate(col: str, op_ok: str, op_bad: str, cap: int) -> tuple[str, str]:
    valid = f"typeof({col}{_SQL_TEXT_LEN}{col}{op_ok}{cap}"
    invalid = f"typeof({col}{_SQL_NOT_TEXT_LEN}{col}{op_bad}{cap}"
    return valid, invalid


def _sql_sha256(col: str, *, nullable: bool = False) -> str:
    valid, invalid = _sql_text_predicate(col, " AS BLOB)) = ", " AS BLOB)) != ", 64)
    if nullable:
        return _sql_nullable_gated(col, valid, invalid)
    return _sql_gated(valid, invalid, col, col)


def _sql_text(col: str, cap: int, *, nullable: bool = False) -> str:
    valid, invalid = _sql_text_predicate(col, _SQL_BLOB_LE, _SQL_BLOB_GT, cap)
    if nullable:
        return _sql_nullable_gated(col, valid, invalid)
    return _sql_gated(valid, invalid, col, col)


def _sql_json_blob(col: str, alias: str) -> str:
    valid, invalid = _sql_text_predicate(
        col, _SQL_BLOB_LE, _SQL_BLOB_GT, MAX_EVENT_PAYLOAD_BYTES
    )
    return _sql_gated(valid, invalid, f"CAST({col} AS BLOB)", alias)


_SQL_META_ID = _sql_gated(
    "typeof(id) = 'integer' AND id = 1",
    "typeof(id) != 'integer' OR id != 1",
    "id",
    "id",
)

_SQL_SELECT_META = (
    f"SELECT {_SQL_META_ID}, "
    f"{_sql_int(KEY_CURRENT_EPOCH)}, "
    f"{_sql_int(KEY_LAST_EVENT_SEQ)}, "
    f"{_sql_sha256('head_hash')}, "
    f"{_sql_bool(_COL_DIRTY_SHUTDOWN)}, "
    f"{_sql_int(KEY_UPDATED_AT_US)} "
    "FROM supervisor_meta LIMIT 2"
)

_SQL_SELECT_RUNS_COLS = (
    f"{_sql_text('run_id', MAX_ID_BYTES)}, "
    f"{_sql_text(KEY_WORKFLOW_ID, MAX_ID_BYTES)}, "
    f"{_sql_sha256(KEY_SPEC_DIGEST)}, "
    f"{_sql_sha256(KEY_WORKFLOW_PLAN_DIGEST)}, "
    f"{_sql_int(KEY_GRANT_GENERATION)}, "
    f"{_sql_bool(KEY_REQUIRES_AUTHORITY)}, "
    f"{_sql_text('status', 64)}, "
    f"{_sql_bool(KEY_CANCEL_REQUESTED)}, "
    f"{_sql_int(KEY_CREATED_EPOCH)}, "
    f"{_sql_int(KEY_CREATED_AT_US)}, "
    f"{_sql_int(KEY_UPDATED_AT_US)}"
)

_SQL_SELECT_STEPS_COLS = (
    f"{_sql_text('run_id', MAX_ID_BYTES)}, "
    f"{_sql_text('step_id', 64)}, "
    f"{_sql_int(KEY_STEP_ORDER)}, "
    f"{_sql_text(KEY_STATE_NAME, 64)}, "
    f"{_sql_text(KEY_EFFECT_KIND, 64)}, "
    f"{_sql_bool(KEY_SIDE_EFFECTING)}, "
    f"{_sql_json_blob('depends_on_json', 'depends_on_blob')}, "
    f"{_sql_int(KEY_MAX_ATTEMPTS)}, "
    f"{_sql_text('status', 64)}, "
    f"{_sql_int(KEY_ATTEMPT_NO)}, "
    f"{_sql_int(KEY_LEASE_EPOCH)}, "
    f"{_sql_text(KEY_IDEM_KEY, MAX_ID_BYTES, nullable=True)}, "
    f"{_sql_sha256(KEY_OUTPUT_DIGEST, nullable=True)}, "
    f"{_sql_text(KEY_FAILURE_REASON, MAX_REASON_BYTES, nullable=True)}, "
    f"{_sql_int(KEY_UPDATED_AT_US)}"
)

_SQL_SELECT_IDEM_COLS = (
    f"{_sql_text('run_id', MAX_ID_BYTES)}, "
    f"{_sql_text(KEY_IDEM_KEY, MAX_ID_BYTES)}, "
    f"{_sql_text('step_id', 64)}, "
    f"{_sql_int(KEY_ATTEMPT_NO)}, "
    f"{_sql_int(KEY_LEASE_EPOCH)}, "
    f"{_sql_text(_COL_OUTCOME_STATUS, 64)}, "
    f"{_sql_sha256(KEY_OUTPUT_DIGEST, nullable=True)}, "
    f"{_sql_text(KEY_FAILURE_REASON, MAX_REASON_BYTES, nullable=True)}, "
    f"{_sql_int(KEY_RECORDED_SEQ)}"
)

_SQL_SELECT_RECON_COLS = (
    f"{_sql_text('run_id', MAX_ID_BYTES)}, "
    f"{_sql_text(KEY_RECON_KEY, MAX_ID_BYTES)}, "
    f"{_sql_text('step_id', 64)}, "
    f"{_sql_int(KEY_ATTEMPT_NO)}, "
    f"{_sql_int(KEY_RECON_EPOCH)}, "
    f"{_sql_text('resolution', 64)}, "
    f"{_sql_sha256(KEY_OUTPUT_DIGEST, nullable=True)}, "
    f"{_sql_sha256(KEY_EVIDENCE_DIGEST)}, "
    f"{_sql_text('reason', MAX_REASON_BYTES)}, "
    f"{_sql_int(KEY_RECORDED_SEQ)}"
)

_SQL_SELECT_EVENTS_COLS = (
    f"{_sql_int('seq')}, "
    f"{_sql_int(KEY_SUPERVISOR_EPOCH)}, "
    f"{_sql_text(_COL_EVENT_TYPE, 64)}, "
    f"{_sql_text('run_id', MAX_ID_BYTES, nullable=True)}, "
    f"{_sql_text('step_id', 64, nullable=True)}, "
    f"{_sql_json_blob('payload_json', 'payload_blob')}, "
    f"{_sql_int(KEY_CREATED_AT_US)}, "
    f"{_sql_sha256('prev_hash')}, "
    f"{_sql_sha256(KEY_ENTRY_HASH)}"
)


def _assert_no_malformed(row: dict[str, Any]) -> None:
    for key, val in row.items():
        if key.endswith(_MALFORMED_SUFFIX) and val != 0:
            raise JournalIntegrityError(ERR_MALFORMED_STORAGE)


def _as_integrity_error(exc: Exception) -> JournalIntegrityError:
    return JournalIntegrityError(str(exc))


def _decode_run_row(row: dict[str, Any]) -> WorkflowRunRecord:
    _assert_no_malformed(row)
    try:
        return WorkflowRunRecord(
            run_id=validate_opaque_id(row["run_id"], "run_id"),
            workflow_id=validate_opaque_id(row[KEY_WORKFLOW_ID], KEY_WORKFLOW_ID),
            spec_digest=validate_sha256_hex(row[KEY_SPEC_DIGEST], KEY_SPEC_DIGEST),
            workflow_plan_digest=validate_sha256_hex(
                row[KEY_WORKFLOW_PLAN_DIGEST], KEY_WORKFLOW_PLAN_DIGEST
            ),
            grant_generation=validate_int64(
                row[KEY_GRANT_GENERATION], KEY_GRANT_GENERATION, min_val=1
            ),
            requires_authority=bool(row[KEY_REQUIRES_AUTHORITY]),
            status=RunStatus(row["status"]),
            cancel_requested=bool(row[KEY_CANCEL_REQUESTED]),
            created_epoch=validate_int64(
                row[KEY_CREATED_EPOCH], KEY_CREATED_EPOCH, min_val=1
            ),
            created_at_us=validate_int64(
                row[KEY_CREATED_AT_US], KEY_CREATED_AT_US, min_val=0
            ),
            updated_at_us=validate_int64(
                row[KEY_UPDATED_AT_US], KEY_UPDATED_AT_US, min_val=0
            ),
        )
    except (RestartValidationError, ValueError) as exc:
        raise _as_integrity_error(exc) from exc


def _decode_step_row(row: dict[str, Any]) -> WorkflowStepRecord:
    _assert_no_malformed(row)
    deps_raw = parse_canonical_json_blob(row["depends_on_blob"], expect_list=True)
    try:
        deps = tuple(validate_step_id(item, KEY_DEPENDS_ON) for item in deps_raw)
        effect = row[KEY_EFFECT_KIND]
        if effect not in ALLOWED_EFFECTS:
            raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
        side_effecting = bool(row[KEY_SIDE_EFFECTING])
        if effect not in PURE_IDEMPOTENT_EFFECTS and not side_effecting:
            raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
        max_att = validate_int64(row[KEY_MAX_ATTEMPTS], KEY_MAX_ATTEMPTS, min_val=1)
        if max_att > MAX_STEP_ATTEMPTS:
            raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
        defn = StepDefinition(
            step_id=validate_step_id(row["step_id"], "step_id"),
            step_order=validate_int64(row[KEY_STEP_ORDER], KEY_STEP_ORDER, min_val=0),
            state_name=validate_step_id(row[KEY_STATE_NAME], KEY_STATE_NAME),
            effect_kind=effect,
            side_effecting=side_effecting,
            depends_on=deps,
            max_attempts=max_att,
        )
        idem = (
            validate_opaque_id(row[KEY_IDEM_KEY], KEY_IDEM_KEY)
            if row[KEY_IDEM_KEY] is not None
            else None
        )
        out_d = (
            validate_sha256_hex(row[KEY_OUTPUT_DIGEST], KEY_OUTPUT_DIGEST)
            if row[KEY_OUTPUT_DIGEST] is not None
            else None
        )
        fail_r = (
            validate_reason(row[KEY_FAILURE_REASON], KEY_FAILURE_REASON)
            if row[KEY_FAILURE_REASON] is not None
            else None
        )
        return WorkflowStepRecord(
            run_id=validate_opaque_id(row["run_id"], "run_id"),
            definition=defn,
            status=StepStatus(row["status"]),
            attempt_no=validate_int64(row[KEY_ATTEMPT_NO], KEY_ATTEMPT_NO, min_val=0),
            lease_epoch=validate_int64(row[KEY_LEASE_EPOCH], KEY_LEASE_EPOCH, min_val=0),
            idempotency_key=idem,
            output_digest=out_d,
            failure_reason=fail_r,
            updated_at_us=validate_int64(
                row[KEY_UPDATED_AT_US], KEY_UPDATED_AT_US, min_val=0
            ),
        )
    except (RestartValidationError, ValueError) as exc:
        raise _as_integrity_error(exc) from exc


def _decode_idem_row(row: dict[str, Any]) -> StepIdempotencyRecord:
    _assert_no_malformed(row)
    try:
        out_d = (
            validate_sha256_hex(row[KEY_OUTPUT_DIGEST], KEY_OUTPUT_DIGEST)
            if row[KEY_OUTPUT_DIGEST] is not None
            else None
        )
        fail_r = (
            validate_reason(row[KEY_FAILURE_REASON], KEY_FAILURE_REASON)
            if row[KEY_FAILURE_REASON] is not None
            else None
        )
        return StepIdempotencyRecord(
            run_id=validate_opaque_id(row["run_id"], "run_id"),
            idempotency_key=validate_opaque_id(row[KEY_IDEM_KEY], KEY_IDEM_KEY),
            step_id=validate_step_id(row["step_id"], "step_id"),
            attempt_no=validate_int64(row[KEY_ATTEMPT_NO], KEY_ATTEMPT_NO, min_val=1),
            lease_epoch=validate_int64(row[KEY_LEASE_EPOCH], KEY_LEASE_EPOCH, min_val=1),
            outcome_status=IdempotencyOutcome(row["outcome_status"]),
            output_digest=out_d,
            failure_reason=fail_r,
            recorded_seq=validate_int64(
                row[KEY_RECORDED_SEQ], KEY_RECORDED_SEQ, min_val=1
            ),
        )
    except (RestartValidationError, ValueError) as exc:
        raise _as_integrity_error(exc) from exc


def _decode_recon_row(row: dict[str, Any]) -> StepReconciliationRecord:
    _assert_no_malformed(row)
    try:
        out_d = (
            validate_sha256_hex(row[KEY_OUTPUT_DIGEST], KEY_OUTPUT_DIGEST)
            if row[KEY_OUTPUT_DIGEST] is not None
            else None
        )
        return StepReconciliationRecord(
            run_id=validate_opaque_id(row["run_id"], "run_id"),
            reconciliation_key=validate_opaque_id(row[KEY_RECON_KEY], KEY_RECON_KEY),
            step_id=validate_step_id(row["step_id"], "step_id"),
            attempt_no=validate_int64(row[KEY_ATTEMPT_NO], KEY_ATTEMPT_NO, min_val=1),
            reconciled_epoch=validate_int64(
                row[KEY_RECON_EPOCH], KEY_RECON_EPOCH, min_val=1
            ),
            resolution=ReconcileResolution(row["resolution"]),
            output_digest=out_d,
            evidence_digest=validate_sha256_hex(
                row[KEY_EVIDENCE_DIGEST], KEY_EVIDENCE_DIGEST
            ),
            reason=validate_reason(row["reason"], "reason"),
            recorded_seq=validate_int64(
                row[KEY_RECORDED_SEQ], KEY_RECORDED_SEQ, min_val=1
            ),
        )
    except (RestartValidationError, ValueError) as exc:
        raise _as_integrity_error(exc) from exc


def _decode_event_row(row: dict[str, Any]) -> JournalEvent:
    _assert_no_malformed(row)
    payload = parse_canonical_json_blob(row["payload_blob"], expect_list=False)
    try:
        run_id = (
            validate_opaque_id(row["run_id"], "run_id")
            if row["run_id"] is not None
            else None
        )
        step_id = (
            validate_step_id(row["step_id"], "step_id")
            if row["step_id"] is not None
            else None
        )
        return JournalEvent(
            seq=validate_int64(row["seq"], "seq", min_val=1),
            supervisor_epoch=validate_int64(
                row[KEY_SUPERVISOR_EPOCH], KEY_SUPERVISOR_EPOCH, min_val=1
            ),
            event_type=EventType(row["event_type"]),
            run_id=run_id,
            step_id=step_id,
            payload=payload,
            created_at_us=validate_int64(
                row[KEY_CREATED_AT_US], KEY_CREATED_AT_US, min_val=0
            ),
            prev_hash=validate_sha256_hex(row["prev_hash"], "prev_hash"),
            entry_hash=validate_sha256_hex(row[KEY_ENTRY_HASH], KEY_ENTRY_HASH),
        )
    except (RestartValidationError, ValueError) as exc:
        raise _as_integrity_error(exc) from exc


def read_meta_strict(
    conn: sqlite3.Connection, *, allow_missing: bool, deadline: float
) -> SupervisorMetaRecord | None:
    rows = execute_bounded(conn, _SQL_SELECT_META, (), deadline).fetchall()
    if len(rows) > 1:
        raise JournalIntegrityError(ERR_META_MULTIPLE)
    if not rows:
        if allow_missing:
            return None
        raise JournalIntegrityError(ERR_META_MISSING)
    row = rows[0]
    _assert_no_malformed(row)
    try:
        last_seq = validate_int64(
            row[KEY_LAST_EVENT_SEQ], KEY_LAST_EVENT_SEQ, min_val=0
        )
        if last_seq < 1:
            raise JournalIntegrityError(ERR_INVALID_META_SEQ)
        return SupervisorMetaRecord(
            current_epoch=validate_int64(
                row[KEY_CURRENT_EPOCH], KEY_CURRENT_EPOCH, min_val=1
            ),
            last_event_seq=last_seq,
            head_hash=validate_sha256_hex(row["head_hash"], "head_hash"),
            dirty_shutdown=int(row["dirty_shutdown"]),
            updated_at_us=validate_int64(
                row[KEY_UPDATED_AT_US], KEY_UPDATED_AT_US, min_val=0
            ),
        )
    except (RestartValidationError, ValueError) as exc:
        raise _as_integrity_error(exc) from exc


def stream_event_log_strict(
    conn: sqlite3.Connection, *, max_events: int, deadline: float
) -> list[JournalEvent]:
    cur = execute_bounded(
        conn,
        f"SELECT {_SQL_SELECT_EVENTS_COLS} FROM workflow_event_log ORDER BY seq ASC LIMIT ?",
        (max_events + 1,),
        deadline,
    )
    events: list[JournalEvent] = []
    for idx, row in enumerate(cur):
        if idx % _DEADLINE_CHECK_STRIDE == 0:
            check_deadline_ms(deadline)
        if len(events) >= max_events:
            raise JournalIntegrityError("replay_event_limit_exceeded")
        events.append(_decode_event_row(row))
    return events


_K = TypeVar("_K")
_V = TypeVar("_V")


def _read_table_strict(
    conn: sqlite3.Connection,
    sql: str,
    *,
    max_rows: int,
    deadline: float,
    decoder: Callable[[dict[str, Any]], _V],
    key_fn: Callable[[_V], _K],
) -> dict[_K, _V]:
    cur = execute_bounded(conn, sql, (max_rows + 1,), deadline)
    out: dict[_K, _V] = {}
    for idx, row in enumerate(cur):
        if idx % _DEADLINE_CHECK_STRIDE == 0:
            check_deadline_ms(deadline)
        if idx >= max_rows:
            raise ReplayMismatchError(ERR_EXTRA_ROWS)
        rec = decoder(row)
        pk = key_fn(rec)
        if pk in out:
            raise ReplayMismatchError(ERR_DUP_MATERIALIZED_KEY)
        out[pk] = rec
    return out


def _fetch_single_row_strict(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple[Any, ...],
    deadline: float,
    decoder: Callable[[dict[str, Any]], _V],
) -> _V | None:
    rows = execute_bounded(conn, sql, params, deadline).fetchall()
    if len(rows) > 1:
        raise JournalIntegrityError(ERR_DUP_MATERIALIZED_KEY)
    return None if not rows else decoder(rows[0])


def read_runs_strict(
    conn: sqlite3.Connection, *, max_rows: int, deadline: float
) -> dict[str, WorkflowRunRecord]:
    return _read_table_strict(
        conn,
        f"SELECT {_SQL_SELECT_RUNS_COLS} FROM workflow_runs LIMIT ?",
        max_rows=max_rows,
        deadline=deadline,
        decoder=_decode_run_row,
        key_fn=lambda rec: rec.run_id,
    )


def read_steps_strict(
    conn: sqlite3.Connection, *, max_rows: int, deadline: float
) -> dict[tuple[str, str], WorkflowStepRecord]:
    return _read_table_strict(
        conn,
        f"SELECT {_SQL_SELECT_STEPS_COLS} FROM workflow_steps LIMIT ?",
        max_rows=max_rows,
        deadline=deadline,
        decoder=_decode_step_row,
        key_fn=lambda rec: (rec.run_id, rec.step_id),
    )


def read_idempotency_strict(
    conn: sqlite3.Connection, *, max_rows: int, deadline: float
) -> dict[tuple[str, str], StepIdempotencyRecord]:
    return _read_table_strict(
        conn,
        f"SELECT {_SQL_SELECT_IDEM_COLS} FROM step_idempotency_keys LIMIT ?",
        max_rows=max_rows,
        deadline=deadline,
        decoder=_decode_idem_row,
        key_fn=lambda rec: (rec.run_id, rec.idempotency_key),
    )


def read_reconciliations_strict(
    conn: sqlite3.Connection, *, max_rows: int, deadline: float
) -> dict[tuple[str, str], StepReconciliationRecord]:
    return _read_table_strict(
        conn,
        f"SELECT {_SQL_SELECT_RECON_COLS} FROM step_reconciliations LIMIT ?",
        max_rows=max_rows,
        deadline=deadline,
        decoder=_decode_recon_row,
        key_fn=lambda rec: (rec.run_id, rec.reconciliation_key),
    )


def read_run_by_id_strict(
    conn: sqlite3.Connection, run_id: str, deadline: float
) -> WorkflowRunRecord | None:
    rec = _fetch_single_row_strict(
        conn,
        f"SELECT {_SQL_SELECT_RUNS_COLS} FROM workflow_runs "
        f"WHERE run_id {_SQL_BIN_EQ_LIMIT_2}",
        (run_id,),
        deadline,
        _decode_run_row,
    )
    if rec is not None and rec.run_id != run_id:
        raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
    return rec


def read_step_by_pk_strict(
    conn: sqlite3.Connection, run_id: str, step_id: str, deadline: float
) -> WorkflowStepRecord | None:
    rec = _fetch_single_row_strict(
        conn,
        f"SELECT {_SQL_SELECT_STEPS_COLS} FROM workflow_steps "
        f"WHERE run_id {_SQL_BIN_EQ} AND step_id {_SQL_BIN_EQ_LIMIT_2}",
        (run_id, step_id),
        deadline,
        _decode_step_row,
    )
    if rec is not None and (rec.run_id, rec.step_id) != (run_id, step_id):
        raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
    return rec


def read_run_steps_strict(
    conn: sqlite3.Connection, run_id: str, deadline: float
) -> dict[str, WorkflowStepRecord]:
    rows = execute_bounded(
        conn,
        f"SELECT {_SQL_SELECT_STEPS_COLS} FROM workflow_steps "
        f"WHERE run_id {_SQL_BIN_EQ} ORDER BY step_order ASC, step_id ASC",
        (run_id,),
        deadline,
    ).fetchall()
    out: dict[str, WorkflowStepRecord] = {}
    for row in rows:
        rec = _decode_step_row(row)
        if rec.run_id != run_id:
            raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
        if rec.step_id in out:
            raise JournalIntegrityError(ERR_DUP_MATERIALIZED_KEY)
        out[rec.step_id] = rec
    return out


def read_idem_by_pk_strict(
    conn: sqlite3.Connection, run_id: str, idempotency_key: str, deadline: float
) -> StepIdempotencyRecord | None:
    rec = _fetch_single_row_strict(
        conn,
        f"SELECT {_SQL_SELECT_IDEM_COLS} FROM step_idempotency_keys "
        f"WHERE run_id {_SQL_BIN_EQ} AND idempotency_key {_SQL_BIN_EQ_LIMIT_2}",
        (run_id, idempotency_key),
        deadline,
        _decode_idem_row,
    )
    if rec is not None and (rec.run_id, rec.idempotency_key) != (run_id, idempotency_key):
        raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
    return rec


def read_recon_by_pk_strict(
    conn: sqlite3.Connection, run_id: str, reconciliation_key: str, deadline: float
) -> StepReconciliationRecord | None:
    rec = _fetch_single_row_strict(
        conn,
        f"SELECT {_SQL_SELECT_RECON_COLS} FROM step_reconciliations "
        f"WHERE run_id {_SQL_BIN_EQ} AND reconciliation_key {_SQL_BIN_EQ_LIMIT_2}",
        (run_id, reconciliation_key),
        deadline,
        _decode_recon_row,
    )
    if rec is not None and (rec.run_id, rec.reconciliation_key) != (
        run_id,
        reconciliation_key,
    ):
        raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
    return rec


def count_obligations_strict(conn: sqlite3.Connection, deadline: float) -> tuple[int, int]:
    """Return (leased_count, uncertain_count) across all runs inside the active transaction."""
    row = execute_bounded(
        conn,
        "SELECT "
        "SUM(CASE WHEN status = 'leased' THEN 1 ELSE 0 END) AS leased_cnt, "
        "SUM(CASE WHEN status = 'uncertain_needs_reconcile' THEN 1 ELSE 0 END) AS uncertain_cnt "
        "FROM workflow_steps",
        (),
        deadline,
    ).fetchone()
    if row is None:
        return 0, 0
    return int(row["leased_cnt"] or 0), int(row["uncertain_cnt"] or 0)


def count_runs_strict(conn: sqlite3.Connection, deadline: float) -> int:
    row = execute_bounded(
        conn, "SELECT COUNT(*) AS cnt FROM workflow_runs", (), deadline
    ).fetchone()
    return 0 if row is None else int(row["cnt"] or 0)
