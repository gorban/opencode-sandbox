"""Verification-only filesystem admission and live-WAL SQLite snapshot helpers.

Internal module supporting ``oc_projection.py``. Never creates directories or
files, never repairs permissions via chmod/fchmod, and never acquires
``.coord_hub.lock``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time
from typing import Any
from urllib.parse import quote

_PROJECTION_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _PROJECTION_DIR.parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
for _import_dir in (str(_PROJECTION_DIR), str(_SPIKE_M_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_broker_common import _UMASK_LOCK  # noqa: E402
from oc_coord_contract import CoordPolicyError  # noqa: E402
from oc_projection_contract import MAX_MARKER_BYTES  # noqa: E402
from oc_projection_decode import decode_bounded_blob, scrub_single_line_str  # noqa: E402
from oc_schema import (  # noqa: E402
    PolicyError,
    assert_trusted_dir,
    check_not_host_production_dir,
    check_not_in_sandbox,
)

DB_FILENAME = "registry.sqlite"
DB_ALL_FILES = ("", "-wal", "-shm", "-journal")
DEGRADED_MARKER_NAME = ".coord_degraded"
SESSION_ACTIVE_MARKER_NAME = ".coord_session_active"

ERR_READ_DEADLINE = "read_deadline_exceeded"
ERR_REGISTRY_BUSY = "registry_busy"
ERR_REGISTRY_UNREADABLE = "registry_unreadable"


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
        return CoordPolicyError(ERR_REGISTRY_BUSY)
    return CoordPolicyError(ERR_REGISTRY_UNREADABLE)


def _safe_close(conn: sqlite3.Connection | None) -> None:
    if conn is None:
        return
    try:
        conn.close()
    except sqlite3.Error:
        pass


def _assert_raw_no_user_symlink_ancestors(raw: Path) -> None:
    cur = Path(os.path.abspath(str(raw)))
    while True:
        try:
            st = os.lstat(cur)
            if stat.S_ISLNK(st.st_mode) and st.st_uid != 0:
                raise CoordPolicyError(f"state_dir_symlink_ancestor_rejected: {cur}")
        except FileNotFoundError:
            pass
        if cur.parent == cur:
            break
        cur = cur.parent


def verify_regular_private_file_nofollow(
    path: Path, *, required: bool, label: str
) -> None:
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
        raise CoordPolicyError(f"{label}_unreadable") from exc
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
    raw = Path(state_dir)
    if raw.is_symlink():
        raise CoordPolicyError("state_dir_symlink_rejected")
    _assert_raw_no_user_symlink_ancestors(raw)
    try:
        phys = check_not_in_sandbox(raw, sandbox_root)
        check_not_host_production_dir(raw)
        check_not_host_production_dir(phys)
    except PolicyError as exc:
        raise CoordPolicyError(str(exc)) from exc
    if phys.is_symlink() or not phys.exists():
        raise CoordPolicyError("state_dir_missing_or_symlink")
    try:
        trusted_dir = assert_trusted_dir(phys, sandbox_root=sandbox_root)
    except PolicyError as exc:
        raise CoordPolicyError(str(exc)) from exc
    db_path = trusted_dir / DB_FILENAME
    for idx, suffix in enumerate(DB_ALL_FILES):
        label = "registry" if idx == 0 else f"registry_sidecar_{suffix.lstrip('-')}"
        verify_regular_private_file_nofollow(
            Path(f"{db_path}{suffix}"), required=(idx == 0), label=label
        )
    return trusted_dir, db_path


def _read_private_marker_nofollow(path: Path) -> tuple[bool, bytes | None, bool]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return False, None, False
    except OSError:
        return False, None, True
    try:
        st = os.fstat(fd)
        invalid = (
            not stat.S_ISREG(st.st_mode)
            or st.st_nlink != 1
            or st.st_uid != os.geteuid()
            or (st.st_mode & 0o077) != 0
        )
        if invalid:
            return False, None, True
        return True, os.read(fd, MAX_MARKER_BYTES), False
    except OSError:
        return False, None, True
    finally:
        os.close(fd)


def read_marker_health(
    trusted_dir: Path,
    live_degraded_checker: Callable[[], bool] | None,
) -> dict[str, Any]:
    deg_present, deg_raw, deg_unreadable = _read_private_marker_nofollow(
        trusted_dir / DEGRADED_MARKER_NAME
    )
    sess_present, _sess_raw, sess_unreadable = _read_private_marker_nofollow(
        trusted_dir / SESSION_ACTIVE_MARKER_NAME
    )
    marker_unreadable = deg_unreadable or sess_unreadable
    deg_reason: str | None = None
    if deg_present and deg_raw is not None:
        decoded, _, _ = decode_bounded_blob(deg_raw, len(deg_raw))
        deg_reason, _ = scrub_single_line_str(decoded, max_bytes=MAX_MARKER_BYTES)

    live_available = live_degraded_checker is not None
    live_degraded = False
    if live_degraded_checker is not None:
        try:
            live_degraded = live_degraded_checker() is not False
        except Exception:
            live_degraded = True

    return {
        "degraded_marker_present": deg_present,
        "degraded_marker_reason": deg_reason,
        "marker_unreadable": marker_unreadable,
        "session_active_marker_present": sess_present,
        "live_status_available": live_available,
        "live_degraded": live_degraded,
    }


@contextmanager
def open_readonly_snapshot(
    db_path: Path, *, deadline: float
) -> Iterator[sqlite3.Connection]:
    """Open a live-WAL mode=ro SQLite snapshot and guarantee ROLLBACK + close."""
    try:
        uri = f"file:{quote(str(db_path), safe='/')}?mode=ro"
    except UnicodeEncodeError as exc:
        raise CoordPolicyError(ERR_REGISTRY_UNREADABLE) from exc
    remaining_s = check_deadline_s(deadline)
    if not _UMASK_LOCK.acquire(timeout=remaining_s):
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
            apply_remaining_busy_timeout(conn, deadline)
            conn.set_progress_handler(
                lambda: 1 if time.monotonic() >= deadline else 0, 1000
            )
            conn.execute("BEGIN DEFERRED")
            execute_bounded(
                conn,
                "SELECT CASE WHEN typeof(last_seq) = 'integer' THEN last_seq ELSE NULL END "
                "AS last_seq FROM seq_counter WHERE id = 1",
                (),
                deadline,
            ).fetchone()
        except sqlite3.OperationalError as exc:
            _safe_close(conn)
            raise map_sqlite_operational_error(exc, deadline) from exc
        except sqlite3.DatabaseError as exc:
            _safe_close(conn)
            raise CoordPolicyError(ERR_REGISTRY_UNREADABLE) from exc
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
        raise CoordPolicyError(ERR_REGISTRY_UNREADABLE) from exc
    finally:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        finally:
            conn.close()


def read_seq_counter(conn: sqlite3.Connection, deadline: float) -> int:
    row = execute_bounded(
        conn,
        "SELECT CASE WHEN typeof(last_seq) = 'integer' THEN last_seq ELSE NULL END AS last_seq, "
        "(typeof(last_seq) != 'integer') AS last_seq_malformed "
        "FROM seq_counter WHERE id = 1",
        (),
        deadline,
    ).fetchone()
    if (
        row is None
        or bool(row["last_seq_malformed"])
        or type(row["last_seq"]) is not int
        or row["last_seq"] < 0
    ):
        raise CoordPolicyError(ERR_REGISTRY_UNREADABLE)
    return row["last_seq"]
