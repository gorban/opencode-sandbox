"""Hardened SQLite WAL registry for PRD M multi-sandbox coordination (M2.1, M2.3, M3.1).

Pure Python standard library plus read-only imports from docs/prds/spikes/l and
docs/prds/spikes/m. Enforces host-trusted $STATE boundaries, 0o600 SQLite WAL
permissions, atomic send admission and turn budgets, fenced outbox transitions,
persistent grant tombstones, single-use 5-tuple provenance receipts, one-shot
TUI Enter tokens, host-trusted worktree auto-discovery, and a hash-chained
audit log.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import sys
import threading
import time
from typing import Any

_SPIKE_M_DIR = Path(__file__).resolve().parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
for _import_dir in (str(_SPIKE_M_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_address import (  # noqa: E402
    AddressError,
    check_no_control_or_bidi,
    parse_local_target,
    validate_msg_kind,
    validate_thread_id,
)
from oc_broker_common import _UMASK_LOCK  # noqa: E402
from oc_coord_contract import (  # noqa: E402
    MAX_ARTIFACTS_PER_MSG,
    MAX_FRAMED_BODY_BYTES,
    MAX_INLINE_BODY_BYTES,
    MAX_STREAM_EVENT_BYTES,
    ROLE_TO_TRUST_CLASS,
    SANDBOX_LIFECYCLE_STATES,
    STREAM_EVENT_TYPES,
    ArtifactRef,
    CoordAuthError,
    CoordBackpressureError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    Envelope,
    IncarnationMismatchError,
    ProvenanceBadge,
    RevokedError,
    RoutingEdge,
    SandboxRecord,
    StreamEvent,
    ThreadRecord,
    TrustClass,
    canonicalize_body_text,
    is_control_priority,
    sha256_canonical_body,
    validate_opaque_token,
    validate_reason_text,
    validate_sandbox_rel_path,
    validate_stream_text,
    validate_task_brief,
)
from oc_schema import (  # noqa: E402
    PolicyError,
    SchemaError,
    assert_trusted_dir,
    canonical_json,
    check_not_host_production_dir,
    check_not_in_sandbox,
    read_regular_no_follow,
)

_DB_FILENAME = "registry.sqlite"
_DB_SIDECAR_SUFFIXES = ("", "-wal", "-shm", "-journal")
_DEFAULT_THREAD_ID = "main"
_TUI_SURFACE_KIND = "opencode-tui"
_MAX_TUI_TOKEN_TTL_S = 5.0
_MAX_WORKTREE_FILE_BYTES = 4096
_MAX_DETAIL_DEPTH = 16
_AUDIT_GENESIS_HASH = "0" * 64

_STATUS_PENDING = "pending"
_STATUS_DISPATCH_STARTED = "dispatch_started"
_STATUS_HANDED_OFF = "handed_off"
_STATUS_UNCERTAIN = "uncertain"
_STATUS_COMPLETED = "completed"
_STATUS_ABORTED = "aborted"
_STATUS_CANCELLED = "cancelled"
_STATUS_REVOKED = "revoked"
_REPLYABLE_OUTBOX_STATUSES = (_STATUS_HANDED_OFF, _STATUS_COMPLETED, _STATUS_UNCERTAIN)
_ORCH_ACTOR_PREFIX = "orchestrator:"


def _sandbox_addr_from_actor(actor: str) -> str | None:
    """Resolve a canonical sender actor string to its underlying local sandbox address, if any."""
    if not isinstance(actor, str) or not actor:
        return None
    candidate = actor[len(_ORCH_ACTOR_PREFIX) :] if actor.startswith(_ORCH_ACTOR_PREFIX) else actor
    try:
        return parse_local_target(candidate).canonical
    except AddressError:
        return None
_STATUS_IDLE = "idle"

_VALID_OUTBOX_STATUSES: frozenset[str] = frozenset(
    {
        _STATUS_PENDING,
        _STATUS_DISPATCH_STARTED,
        _STATUS_HANDED_OFF,
        _STATUS_UNCERTAIN,
        _STATUS_COMPLETED,
        _STATUS_ABORTED,
        _STATUS_CANCELLED,
    }
)

_TRUST_CLASS_TO_BADGE: dict[TrustClass, ProvenanceBadge] = {
    TrustClass.OPERATOR_DIRECTIVE: ProvenanceBadge.OPERATOR,
    TrustClass.PARENT_TASK: ProvenanceBadge.ORCHESTRATOR,
    TrustClass.UNTRUSTED_PEER_DATA: ProvenanceBadge.PEER,
    TrustClass.SYSTEM_ALERT: ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED,
}

_TRUST_RANK: dict[TrustClass, int] = {
    TrustClass.UNTRUSTED_PEER_DATA: 0,
    TrustClass.SYSTEM_ALERT: 0,
    TrustClass.PARENT_TASK: 1,
    TrustClass.OPERATOR_DIRECTIVE: 2,
}

_UNTRUSTED_DETAIL_KEYS: frozenset[str] = frozenset(
    {
        "src",
        "principal",
        "sender",
        "src_actor",
        "src_role",
        "role",
        "trust",
        "trust_class",
        "badge",
        "provenance",
        "provenance_badge",
        "verified_sender",
    }
)

_ERR_INVALID_IN_REPLY_TO = "invalid_in_reply_to"
_ERR_INVALID_OUTBOX_TRANSITION = "invalid_outbox_transition"

_SCHEMA_SQL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS seq_counter (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        last_seq INTEGER NOT NULL
    )
    """,
    "INSERT OR IGNORE INTO seq_counter (id, last_seq) VALUES (1, 0)",
    """
    CREATE TABLE IF NOT EXISTS sandboxes (
        sandbox_addr TEXT PRIMARY KEY,
        worker_ref TEXT NOT NULL,
        instance_name TEXT NOT NULL,
        incarnation_id TEXT NOT NULL,
        job_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        project_name TEXT NOT NULL,
        branch TEXT NOT NULL,
        sandbox_type TEXT NOT NULL,
        task_brief TEXT NOT NULL,
        status TEXT NOT NULL,
        controller_request_id TEXT,
        parent_addr TEXT,
        depth INTEGER NOT NULL DEFAULT 0,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS threads (
        sandbox_addr TEXT NOT NULL,
        incarnation_id TEXT NOT NULL,
        thread_id TEXT NOT NULL,
        title TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'idle',
        last_seq INTEGER NOT NULL DEFAULT 0,
        updated_at REAL NOT NULL,
        PRIMARY KEY (sandbox_addr, incarnation_id, thread_id),
        FOREIGN KEY (sandbox_addr) REFERENCES sandboxes(sandbox_addr)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS routing_edges (
        edge_id TEXT PRIMARY KEY,
        src_actor TEXT NOT NULL,
        src_incarnation TEXT,
        dst_addr TEXT NOT NULL,
        allowed_threads_json TEXT NOT NULL,
        allowed_msg_kinds_json TEXT NOT NULL,
        max_rounds INTEGER NOT NULL,
        turns_used INTEGER NOT NULL DEFAULT 0,
        rate_limit_rpm INTEGER NOT NULL DEFAULT 60,
        active INTEGER NOT NULL DEFAULT 1,
        lease_request_id TEXT,
        grant_generation INTEGER NOT NULL DEFAULT 1,
        created_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS grant_tombstones (
        edge_id TEXT NOT NULL,
        grant_generation INTEGER NOT NULL,
        reason TEXT NOT NULL,
        revoked_at REAL NOT NULL,
        PRIMARY KEY (edge_id, grant_generation)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS event_log (
        seq INTEGER PRIMARY KEY,
        msg_id TEXT NOT NULL UNIQUE,
        src_role TEXT NOT NULL,
        src_actor TEXT NOT NULL,
        src_incarnation TEXT,
        dst_addr TEXT NOT NULL,
        dst_thread_id TEXT NOT NULL,
        dst_incarnation TEXT NOT NULL,
        trust_class TEXT NOT NULL,
        msg_kind TEXT NOT NULL,
        body_text TEXT NOT NULL,
        body_sha256 TEXT NOT NULL,
        edge_id TEXT NOT NULL,
        edge_turn_seq INTEGER NOT NULL,
        in_reply_to TEXT,
        artifact_refs_json TEXT NOT NULL,
        created_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS dispatch_receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sandbox_addr TEXT NOT NULL,
        incarnation_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        message_id TEXT NOT NULL,
        body_sha256 TEXT NOT NULL,
        badge TEXT NOT NULL,
        src_actor TEXT NOT NULL,
        trust_class TEXT NOT NULL,
        consumed_at REAL,
        UNIQUE(sandbox_addr, incarnation_id, session_id, message_id, body_sha256)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS outbox (
        seq INTEGER NOT NULL,
        msg_id TEXT PRIMARY KEY,
        edge_id TEXT NOT NULL,
        lease_request_id TEXT,
        grant_generation INTEGER NOT NULL,
        src_incarnation TEXT,
        dst_incarnation TEXT NOT NULL,
        thread_id TEXT NOT NULL,
        priority INTEGER NOT NULL,
        status TEXT NOT NULL,
        body_bytes INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        stream_id TEXT,
        detail TEXT NOT NULL DEFAULT '',
        updated_at REAL NOT NULL,
        FOREIGN KEY (msg_id) REFERENCES event_log(msg_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tui_enter_tokens (
        token_sha256 TEXT PRIMARY KEY,
        sandbox_addr TEXT NOT NULL,
        incarnation_id TEXT NOT NULL,
        surface_kind TEXT NOT NULL,
        expires_at REAL NOT NULL,
        consumed_at REAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS stream_events (
        seq INTEGER PRIMARY KEY,
        event_type TEXT NOT NULL,
        sandbox_addr TEXT NOT NULL,
        incarnation_id TEXT NOT NULL,
        thread_id TEXT NOT NULL,
        seq_hint INTEGER NOT NULL DEFAULT 0,
        message_id TEXT,
        text TEXT NOT NULL DEFAULT '',
        file_path TEXT,
        detail_json TEXT NOT NULL DEFAULT '{}',
        badge TEXT,
        created_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        outcome TEXT NOT NULL,
        detail_json TEXT NOT NULL,
        created_at REAL NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
    )
    """,
)


def _assert_existing_ancestors_trusted(target_dir: Path) -> None:
    """Verify every existing ancestor directory is owned by current user/root and safe."""
    uid = os.geteuid()
    cur = target_dir
    while not cur.exists() and cur.parent != cur:
        cur = cur.parent
    while True:
        ast = os.lstat(cur)
        if not stat.S_ISDIR(ast.st_mode) or stat.S_ISLNK(ast.st_mode):
            raise CoordPolicyError(f"Expected non-symlink ancestor directory: {cur}")
        if ast.st_uid not in (uid, 0):
            raise CoordPolicyError(f"Untrusted ancestor owner for {target_dir}: {cur}")
        if (ast.st_mode & 0o022) and not (ast.st_uid == 0 and (ast.st_mode & stat.S_ISVTX)):
            raise CoordPolicyError(f"Writable ancestor directory for {target_dir}: {cur}")
        if cur.parent == cur:
            break
        cur = cur.parent


def _prepare_trusted_state_dir(state_dir: Path, sandbox_root: Path | None) -> Path:
    """Validate and prepare a host-trusted 0o700 state directory outside $SB and prod."""
    raw = Path(state_dir)
    if raw.is_symlink():
        raise CoordPolicyError(f"Symlink state directory rejected: {raw}")
    try:
        phys = check_not_in_sandbox(raw, sandbox_root)
        check_not_host_production_dir(raw)
        if phys.is_symlink():
            raise CoordPolicyError(f"Symlink state directory rejected: {phys}")
        if phys.exists():
            return assert_trusted_dir(phys, sandbox_root=sandbox_root)
        _assert_existing_ancestors_trusted(phys)
        with _UMASK_LOCK:
            old_umask = os.umask(0o077)
            try:
                phys.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(phys, 0o700)
            finally:
                os.umask(old_umask)
        return assert_trusted_dir(phys, sandbox_root=sandbox_root)
    except PolicyError as exc:
        raise CoordPolicyError(str(exc)) from exc


def _check_regular_file_stat(st: os.stat_result, path: Path) -> None:
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise CoordPolicyError(f"Non-regular database file rejected: {path}")
    if st.st_nlink != 1:
        raise CoordPolicyError(f"Hardlinked database file rejected: {path}")
    if st.st_uid != os.geteuid():
        raise CoordPolicyError(f"Database file not owned by current user: {path}")


def _verify_db_file(path: Path, *, enforce_0600: bool) -> None:
    """Reject symlinks/hardlinks/foreign owners and optionally enforce 0o600 via O_NOFOLLOW."""
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return
    _check_regular_file_stat(lst, path)
    if not enforce_0600:
        return
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise CoordPolicyError(f"Symlink database file rejected: {path}") from exc
        raise
    try:
        fst = os.fstat(fd)
        _check_regular_file_stat(fst, path)
        if stat.S_IMODE(fst.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _verify_all_db_files(db_path: Path, *, enforce_0600: bool) -> None:
    for suffix in _DB_SIDECAR_SUFFIXES:
        _verify_db_file(Path(f"{db_path}{suffix}"), enforce_0600=enforce_0600)


def _compute_audit_hash(
    prev_hash: str,
    actor: str,
    action: str,
    target: str,
    outcome: str,
    detail_json: str,
    created_at: float,
) -> str:
    payload = canonical_json(
        {
            "actor": actor,
            "action": action,
            "target": target,
            "outcome": outcome,
            "detail_json": detail_json,
            "created_at": created_at,
        }
    )
    return hashlib.sha256(f"{prev_hash}{payload}".encode("utf-8")).hexdigest()


_MIN_SAFE_INT = -(1 << 63)
_MAX_SAFE_INT = (1 << 63) - 1


def _has_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _safe_timestamp(raw: Any) -> float:
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        try:
            val = float(raw)
        except OverflowError:
            return time.time()
        if math.isfinite(val) and val > 0.0:
            return val
    return time.time()


def _sanitize_detail_scalar(val: Any) -> tuple[bool, Any]:
    if val is None or isinstance(val, bool):
        return True, val
    if isinstance(val, int):
        return (True, val) if _MIN_SAFE_INT <= val <= _MAX_SAFE_INT else (False, None)
    if isinstance(val, float):
        return (True, val) if math.isfinite(val) else (False, None)
    if isinstance(val, str):
        return (False, None) if _has_surrogate(val) else (True, val)
    return False, None


def _sanitize_detail_value(val: Any, depth: int) -> tuple[bool, Any]:
    if depth > _MAX_DETAIL_DEPTH:
        return False, None
    if isinstance(val, Mapping):
        return True, _sanitize_detail_mapping(val, depth + 1)
    if isinstance(val, (list, tuple)):
        items = [
            cleaned
            for elem in val
            for ok, cleaned in (_sanitize_detail_value(elem, depth + 1),)
            if ok
        ]
        return True, items
    return _sanitize_detail_scalar(val)


def _sanitize_detail_mapping(mapping: Mapping[str, Any], depth: int) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, val in mapping.items():
        if not isinstance(key, str) or _has_surrogate(key) or key.strip().lower() in _UNTRUSTED_DETAIL_KEYS:
            continue
        ok, cleaned = _sanitize_detail_value(val, depth)
        if ok:
            clean[key] = cleaned
    return clean


def _sanitize_stream_detail(detail: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    clean = _sanitize_detail_mapping(detail, 0) if isinstance(detail, Mapping) else {}
    encoded = canonical_json(clean)
    if len(encoded.encode("utf-8")) > MAX_STREAM_EVENT_BYTES:
        raise CoordValidationError("StreamEvent detail exceeds maximum bounded size")
    return clean, encoded


def _sanitize_stream_message_id(raw: str | None) -> str | None:
    if raw is None:
        return None
    try:
        return validate_opaque_token(raw, "message_id")
    except (AddressError, CoordValidationError):
        return None


def _row_to_sandbox(row: sqlite3.Row) -> SandboxRecord:
    return SandboxRecord(
        sandbox_addr=row["sandbox_addr"],
        worker_ref=row["worker_ref"],
        instance_name=row["instance_name"],
        incarnation_id=row["incarnation_id"],
        job_id=row["job_id"],
        project_id=row["project_id"],
        project_name=row["project_name"],
        branch=row["branch"],
        sandbox_type=row["sandbox_type"],
        task_brief=row["task_brief"],
        status=row["status"],
        controller_request_id=row["controller_request_id"],
        parent_addr=row["parent_addr"],
        depth=int(row["depth"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )


def _row_to_thread(row: sqlite3.Row) -> ThreadRecord:
    return ThreadRecord(
        sandbox_addr=row["sandbox_addr"],
        incarnation_id=row["incarnation_id"],
        thread_id=row["thread_id"],
        title=row["title"],
        status=row["status"],
        last_seq=int(row["last_seq"]),
        updated_at=float(row["updated_at"]),
    )


def _row_to_edge(row: sqlite3.Row) -> RoutingEdge:
    return RoutingEdge(
        edge_id=row["edge_id"],
        src_actor=row["src_actor"],
        src_incarnation=row["src_incarnation"],
        dst_addr=row["dst_addr"],
        allowed_threads=frozenset(json.loads(row["allowed_threads_json"])),
        allowed_msg_kinds=frozenset(json.loads(row["allowed_msg_kinds_json"])),
        max_rounds=int(row["max_rounds"]),
        turns_used=int(row["turns_used"]),
        rate_limit_rpm=int(row["rate_limit_rpm"]),
        active=bool(row["active"]),
        lease_request_id=row["lease_request_id"],
        grant_generation=int(row["grant_generation"]),
        created_at=float(row["created_at"]),
    )


def _row_to_envelope(row: sqlite3.Row) -> Envelope:
    raw_arts = json.loads(row["artifact_refs_json"])
    arts = tuple(
        ArtifactRef(
            blob_sha256=item["blob_sha256"],
            size_bytes=int(item["size_bytes"]),
            media_type=item["media_type"],
        )
        for item in raw_arts
    )
    return Envelope(
        msg_id=row["msg_id"],
        seq=int(row["seq"]),
        src_role=CoordRole(row["src_role"]),
        src_actor=row["src_actor"],
        src_incarnation=row["src_incarnation"],
        dst_addr=row["dst_addr"],
        dst_thread_id=row["dst_thread_id"],
        dst_incarnation=row["dst_incarnation"],
        trust_class=TrustClass(row["trust_class"]),
        msg_kind=row["msg_kind"],
        body_text=row["body_text"],
        body_sha256=row["body_sha256"],
        edge_id=row["edge_id"],
        edge_turn_seq=int(row["edge_turn_seq"]),
        in_reply_to=row["in_reply_to"],
        artifact_refs=arts,
        created_at=float(row["created_at"]),
    )


def _row_to_outbox_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "seq": int(row["seq"]),
        "msg_id": row["msg_id"],
        "edge_id": row["edge_id"],
        "lease_request_id": row["lease_request_id"],
        "grant_generation": int(row["grant_generation"]),
        "src_incarnation": row["src_incarnation"],
        "dst_incarnation": row["dst_incarnation"],
        "thread_id": row["thread_id"],
        "priority": int(row["priority"]),
        "status": row["status"],
        "body_bytes": int(row["body_bytes"]),
        "attempts": int(row["attempts"]),
        "stream_id": row["stream_id"],
        "detail": row["detail"],
        "updated_at": float(row["updated_at"]),
    }


def _row_to_stream_event_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "source": "stream_event",
        "seq": int(row["seq"]),
        "event_type": row["event_type"],
        "sandbox_addr": row["sandbox_addr"],
        "incarnation_id": row["incarnation_id"],
        "thread_id": row["thread_id"],
        "seq_hint": int(row["seq_hint"]),
        "message_id": row["message_id"],
        "text": row["text"],
        "file_path": row["file_path"],
        "detail": json.loads(row["detail_json"]),
        "badge": row["badge"],
        "created_at": float(row["created_at"]),
    }


def _row_to_event_log_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "source": "event_log",
        "seq": int(row["seq"]),
        "msg_id": row["msg_id"],
        "src_role": row["src_role"],
        "src_actor": row["src_actor"],
        "src_incarnation": row["src_incarnation"],
        "sandbox_addr": row["dst_addr"],
        "dst_addr": row["dst_addr"],
        "thread_id": row["dst_thread_id"],
        "incarnation_id": row["dst_incarnation"],
        "trust_class": row["trust_class"],
        "msg_kind": row["msg_kind"],
        "body_text": row["body_text"],
        "body_sha256": row["body_sha256"],
        "edge_id": row["edge_id"],
        "edge_turn_seq": int(row["edge_turn_seq"]),
        "in_reply_to": row["in_reply_to"],
        "created_at": float(row["created_at"]),
    }


def _validate_sandbox_record(record: SandboxRecord) -> str:
    parse_local_target(record.sandbox_addr)
    brief = validate_task_brief(record.task_brief)
    validate_opaque_token(record.incarnation_id, "incarnation_id")
    validate_opaque_token(record.job_id, "job_id")
    if record.status not in SANDBOX_LIFECYCLE_STATES:
        raise CoordValidationError(f"Invalid sandbox status: {record.status!r}")
    if record.parent_addr is not None:
        parse_local_target(record.parent_addr)
    if record.controller_request_id is not None:
        validate_opaque_token(record.controller_request_id, "controller_request_id")
    if type(record.depth) is not int or record.depth < 0:
        raise CoordValidationError("sandbox depth must be a non-negative integer")
    for field_val, label in (
        (record.worker_ref, "worker_ref"),
        (record.instance_name, "instance_name"),
        (record.project_id, "project_id"),
        (record.project_name, "project_name"),
        (record.branch, "branch"),
        (record.sandbox_type, "sandbox_type"),
    ):
        check_no_control_or_bidi(field_val, label)
    return brief


def _validate_routing_edge(edge: RoutingEdge) -> tuple[list[str], list[str]]:
    validate_opaque_token(edge.edge_id, "edge_id")
    check_no_control_or_bidi(edge.src_actor, "src_actor")
    if edge.src_incarnation is not None:
        validate_opaque_token(edge.src_incarnation, "src_incarnation")
    parse_local_target(edge.dst_addr)
    threads = sorted(validate_thread_id(t) for t in edge.allowed_threads)
    kinds = sorted(validate_msg_kind(k) for k in edge.allowed_msg_kinds)
    if type(edge.max_rounds) is not int or edge.max_rounds < 0:
        raise CoordValidationError("edge.max_rounds must be a non-negative integer")
    if type(edge.turns_used) is not int or edge.turns_used < 0:
        raise CoordValidationError("edge.turns_used must be a non-negative integer")
    if type(edge.rate_limit_rpm) is not int or edge.rate_limit_rpm < 1:
        raise CoordValidationError("edge.rate_limit_rpm must be >= 1")
    if type(edge.grant_generation) is not int or edge.grant_generation < 1:
        raise CoordValidationError("edge.grant_generation must be >= 1")
    return threads, kinds


def _parse_worktree_entry(
    entry: Path, wt_dir: Path, sandbox_root: Path | None
) -> dict[str, Any] | None:
    try:
        addr = parse_local_target(entry.name)
    except AddressError:
        return None
    try:
        raw = read_regular_no_follow(
            entry,
            max_bytes=_MAX_WORKTREE_FILE_BYTES,
            confined_root=wt_dir,
            sandbox_root=sandbox_root,
        )
        text = raw.decode("utf-8")
    except (OSError, PolicyError, SchemaError, UnicodeDecodeError):
        return None
    lines = text.splitlines()
    if len(lines) < 3:
        return None
    cwd, repo, branch = lines[0].strip(), lines[1].strip(), lines[2].strip()
    if not cwd or not repo or not branch:
        return None
    try:
        check_no_control_or_bidi(cwd, "worktree cwd")
        check_no_control_or_bidi(repo, "worktree repo")
        check_no_control_or_bidi(branch, "worktree branch")
    except AddressError:
        return None
    return {
        "sandbox_addr": addr.canonical,
        "instance_name": addr.name,
        "cwd": cwd,
        "repo": repo,
        "branch": branch,
    }


class CoordRegistry:
    """Thread-safe, host-trusted SQLite WAL coordination registry."""

    def __init__(self, state_dir: Path, *, sandbox_root: Path | None = None) -> None:
        self._sandbox_root = sandbox_root
        self._state_dir = _prepare_trusted_state_dir(state_dir, sandbox_root)
        self._db_path = self._state_dir / _DB_FILENAME
        self._lock = threading.RLock()
        self._in_tx = False
        self._closed = False
        self._conn = self._open_hardened_db()

    def _open_hardened_db(self) -> sqlite3.Connection:
        _verify_all_db_files(self._db_path, enforce_0600=True)
        with _UMASK_LOCK:
            old_umask = os.umask(0o177)
            try:
                conn = sqlite3.connect(
                    str(self._db_path),
                    isolation_level=None,
                    check_same_thread=False,
                )
                try:
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA journal_mode = WAL")
                    conn.execute("PRAGMA foreign_keys = ON")
                    conn.execute("PRAGMA synchronous = FULL")
                    conn.execute("PRAGMA busy_timeout = 5000")
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        for stmt in _SCHEMA_SQL:
                            conn.execute(stmt)
                        conn.execute("COMMIT")
                    except BaseException:
                        conn.execute("ROLLBACK")
                        raise
                except BaseException:
                    conn.close()
                    raise
            finally:
                os.umask(old_umask)
        _verify_all_db_files(self._db_path, enforce_0600=True)
        return conn

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._conn.close()

    def __enter__(self) -> CoordRegistry:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise CoordPolicyError("CoordRegistry is closed")
            if self._in_tx:
                yield self._conn
                return
            self._conn.execute("BEGIN IMMEDIATE")
            self._in_tx = True
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            finally:
                self._in_tx = False

    def _next_seq(self, conn: sqlite3.Connection) -> int:
        conn.execute("UPDATE seq_counter SET last_seq = last_seq + 1 WHERE id = 1")
        row = conn.execute("SELECT last_seq FROM seq_counter WHERE id = 1").fetchone()
        return int(row["last_seq"])

    def _is_tombstoned_conn(
        self, conn: sqlite3.Connection, edge_id: str, grant_generation: int
    ) -> bool:
        row = conn.execute(
            "SELECT 1 FROM grant_tombstones WHERE edge_id = ? AND grant_generation = ?",
            (edge_id, grant_generation),
        ).fetchone()
        return row is not None

    def _ensure_thread_conn(
        self,
        conn: sqlite3.Connection,
        sandbox_addr: str,
        incarnation_id: str,
        thread_id: str,
        *,
        title: str = "",
        now: float | None = None,
    ) -> ThreadRecord:
        ts = time.time() if now is None else now
        conn.execute(
            """
            INSERT OR IGNORE INTO threads
                (sandbox_addr, incarnation_id, thread_id, title, status, last_seq, updated_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (sandbox_addr, incarnation_id, thread_id, title, _STATUS_IDLE, ts),
        )
        if title:
            conn.execute(
                """
                UPDATE threads SET title = ?, updated_at = ?
                WHERE sandbox_addr = ? AND incarnation_id = ? AND thread_id = ? AND title = ''
                """,
                (title, ts, sandbox_addr, incarnation_id, thread_id),
            )
        row = conn.execute(
            """
            SELECT * FROM threads
            WHERE sandbox_addr = ? AND incarnation_id = ? AND thread_id = ?
            """,
            (sandbox_addr, incarnation_id, thread_id),
        ).fetchone()
        return _row_to_thread(row)

    def _append_audit_conn(
        self,
        conn: sqlite3.Connection,
        actor: str,
        action: str,
        target: str,
        outcome: str,
        detail: Mapping[str, Any] | None,
    ) -> int:
        last_row = conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last_row["entry_hash"] if last_row is not None else _AUDIT_GENESIS_HASH
        now = time.time()
        detail_json = canonical_json(dict(detail) if detail is not None else {})
        entry_hash = _compute_audit_hash(
            prev_hash, actor, action, target, outcome, detail_json, now
        )
        cur = conn.execute(
            """
            INSERT INTO audit_log
                (actor, action, target, outcome, detail_json, created_at, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (actor, action, target, outcome, detail_json, now, prev_hash, entry_hash),
        )
        return int(cur.lastrowid)

    # ------------------------------------------------------------------
    # Sandbox & Thread Operations
    # ------------------------------------------------------------------

    def register_sandbox(self, record: SandboxRecord) -> SandboxRecord:
        brief = _validate_sandbox_record(record)
        now = time.time()
        created_at = record.created_at if record.created_at > 0 else now
        updated_at = record.updated_at if record.updated_at > 0 else now
        stored = replace(record, task_brief=brief, created_at=created_at, updated_at=updated_at)
        with self._tx() as conn:
            conn.execute(
                """
                INSERT INTO sandboxes (
                    sandbox_addr, worker_ref, instance_name, incarnation_id, job_id,
                    project_id, project_name, branch, sandbox_type, task_brief,
                    status, controller_request_id, parent_addr, depth, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sandbox_addr) DO UPDATE SET
                    worker_ref = excluded.worker_ref,
                    instance_name = excluded.instance_name,
                    incarnation_id = excluded.incarnation_id,
                    job_id = excluded.job_id,
                    project_id = excluded.project_id,
                    project_name = excluded.project_name,
                    branch = excluded.branch,
                    sandbox_type = excluded.sandbox_type,
                    task_brief = excluded.task_brief,
                    status = excluded.status,
                    controller_request_id = excluded.controller_request_id,
                    parent_addr = excluded.parent_addr,
                    depth = excluded.depth,
                    updated_at = excluded.updated_at
                """,
                (
                    stored.sandbox_addr,
                    stored.worker_ref,
                    stored.instance_name,
                    stored.incarnation_id,
                    stored.job_id,
                    stored.project_id,
                    stored.project_name,
                    stored.branch,
                    stored.sandbox_type,
                    stored.task_brief,
                    stored.status,
                    stored.controller_request_id,
                    stored.parent_addr,
                    stored.depth,
                    stored.created_at,
                    stored.updated_at,
                ),
            )
            self._ensure_thread_conn(
                conn, stored.sandbox_addr, stored.incarnation_id, _DEFAULT_THREAD_ID, now=updated_at
            )
            row = conn.execute(
                "SELECT * FROM sandboxes WHERE sandbox_addr = ?", (stored.sandbox_addr,)
            ).fetchone()
            return _row_to_sandbox(row)

    def get_sandbox(self, sandbox_addr: str) -> SandboxRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM sandboxes WHERE sandbox_addr = ?", (sandbox_addr,)
            ).fetchone()
            return _row_to_sandbox(row) if row is not None else None

    def list_sandboxes(self) -> list[SandboxRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM sandboxes ORDER BY project_id ASC, sandbox_addr ASC"
            ).fetchall()
            return [_row_to_sandbox(r) for r in rows]

    def update_sandbox_status(
        self, sandbox_addr: str, status: str, *, incarnation_id: str | None = None
    ) -> None:
        if status not in SANDBOX_LIFECYCLE_STATES:
            raise CoordValidationError(f"Invalid sandbox status: {status!r}")
        if incarnation_id is not None:
            validate_opaque_token(incarnation_id, "incarnation_id")
        now = time.time()
        with self._tx() as conn:
            if incarnation_id is None:
                cur = conn.execute(
                    "UPDATE sandboxes SET status = ?, updated_at = ? WHERE sandbox_addr = ?",
                    (status, now, sandbox_addr),
                )
            else:
                cur = conn.execute(
                    """
                    UPDATE sandboxes SET status = ?, incarnation_id = ?, updated_at = ?
                    WHERE sandbox_addr = ?
                    """,
                    (status, incarnation_id, now, sandbox_addr),
                )
            if cur.rowcount != 1:
                raise CoordValidationError(f"Unknown sandbox: {sandbox_addr!r}")
            if incarnation_id is not None:
                self._ensure_thread_conn(
                    conn, sandbox_addr, incarnation_id, _DEFAULT_THREAD_ID, now=now
                )

    def ensure_thread(
        self, sandbox_addr: str, incarnation_id: str, thread_id: str, *, title: str = ""
    ) -> ThreadRecord:
        parse_local_target(sandbox_addr)
        validate_opaque_token(incarnation_id, "incarnation_id")
        validate_thread_id(thread_id)
        check_no_control_or_bidi(title, "thread title")
        with self._tx() as conn:
            return self._ensure_thread_conn(
                conn, sandbox_addr, incarnation_id, thread_id, title=title
            )

    # ------------------------------------------------------------------
    # Routing Edge Operations
    # ------------------------------------------------------------------

    def grant_edge(self, edge: RoutingEdge) -> RoutingEdge:
        threads, kinds = _validate_routing_edge(edge)
        created_at = _safe_timestamp(edge.created_at)
        with self._tx() as conn:
            tomb = conn.execute(
                "SELECT MAX(grant_generation) AS max_gen FROM grant_tombstones WHERE edge_id = ?",
                (edge.edge_id,),
            ).fetchone()
            if tomb is not None and tomb["max_gen"] is not None and edge.grant_generation <= int(tomb["max_gen"]):
                raise RevokedError(
                    f"Grant ({edge.edge_id}, gen={edge.grant_generation}) is at or below tombstoned generation"
                )
            existing = conn.execute(
                "SELECT grant_generation, turns_used FROM routing_edges WHERE edge_id = ?",
                (edge.edge_id,),
            ).fetchone()
            turns_used = edge.turns_used
            if existing is not None:
                prev_gen = int(existing["grant_generation"])
                if edge.grant_generation < prev_gen:
                    raise RevokedError(
                        f"Grant ({edge.edge_id}, gen={edge.grant_generation}) cannot downgrade from gen={prev_gen}"
                    )
                if edge.grant_generation == prev_gen:
                    turns_used = max(turns_used, int(existing["turns_used"]))
            conn.execute(
                """
                INSERT INTO routing_edges (
                    edge_id, src_actor, src_incarnation, dst_addr,
                    allowed_threads_json, allowed_msg_kinds_json,
                    max_rounds, turns_used, rate_limit_rpm, active,
                    lease_request_id, grant_generation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(edge_id) DO UPDATE SET
                    src_actor = excluded.src_actor,
                    src_incarnation = excluded.src_incarnation,
                    dst_addr = excluded.dst_addr,
                    allowed_threads_json = excluded.allowed_threads_json,
                    allowed_msg_kinds_json = excluded.allowed_msg_kinds_json,
                    max_rounds = excluded.max_rounds,
                    turns_used = excluded.turns_used,
                    rate_limit_rpm = excluded.rate_limit_rpm,
                    active = excluded.active,
                    lease_request_id = excluded.lease_request_id,
                    grant_generation = excluded.grant_generation,
                    created_at = excluded.created_at
                """,
                (
                    edge.edge_id,
                    edge.src_actor,
                    edge.src_incarnation,
                    edge.dst_addr,
                    canonical_json(threads),
                    canonical_json(kinds),
                    edge.max_rounds,
                    turns_used,
                    edge.rate_limit_rpm,
                    1 if edge.active else 0,
                    edge.lease_request_id,
                    edge.grant_generation,
                    created_at,
                ),
            )
            row = conn.execute(
                "SELECT * FROM routing_edges WHERE edge_id = ?", (edge.edge_id,)
            ).fetchone()
            return _row_to_edge(row)

    def get_edge(self, edge_id: str) -> RoutingEdge | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM routing_edges WHERE edge_id = ?", (edge_id,)
            ).fetchone()
            return _row_to_edge(row) if row is not None else None

    def find_active_edge(
        self, src_actor: str, dst_addr: str, thread_id: str, msg_kind: str
    ) -> RoutingEdge | None:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM routing_edges
                WHERE src_actor = ? AND dst_addr = ? AND active = 1
                ORDER BY created_at ASC, edge_id ASC
                """,
                (src_actor, dst_addr),
            ).fetchall()
            for row in rows:
                if self._is_tombstoned_conn(self._conn, row["edge_id"], int(row["grant_generation"])):
                    continue
                edge = _row_to_edge(row)
                if thread_id in edge.allowed_threads and msg_kind in edge.allowed_msg_kinds:
                    return edge
            return None

    def list_edges(
        self,
        *,
        dst_addr: str | None = None,
        src_actor: str | None = None,
        active_only: bool = True,
    ) -> list[RoutingEdge]:
        clauses: list[str] = []
        params: list[Any] = []
        if dst_addr is not None:
            clauses.append("dst_addr = ?")
            params.append(dst_addr)
        if src_actor is not None:
            clauses.append("src_actor = ?")
            params.append(src_actor)
        if active_only:
            clauses.append("active = 1")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM routing_edges {where} ORDER BY created_at ASC, edge_id ASC",
                params,
            ).fetchall()
            edges: list[RoutingEdge] = []
            for row in rows:
                if active_only and self._is_tombstoned_conn(
                    self._conn, row["edge_id"], int(row["grant_generation"])
                ):
                    continue
                edges.append(_row_to_edge(row))
            return edges

    def reset_edge_turns(self, edge_id: str) -> None:
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE routing_edges SET turns_used = 0 WHERE edge_id = ?", (edge_id,)
            )
            if cur.rowcount != 1:
                raise CoordValidationError(f"Unknown edge_id: {edge_id!r}")
            self._append_audit_conn(
                conn, "operator", "reset_edge_turns", edge_id, "ok", {"turns_used": 0}
            )

    # ------------------------------------------------------------------
    # Atomic Send Admission, Turn Budget, Backpressure, Write-Ahead Receipts
    # ------------------------------------------------------------------

    def _verify_edge_for_send(
        self,
        conn: sqlite3.Connection,
        edge_id: str,
        expected_grant_generation: int,
        expected_src_incarnation: str | None,
        envelope: Envelope,
    ) -> sqlite3.Row:
        edge_row = conn.execute(
            "SELECT * FROM routing_edges WHERE edge_id = ?", (edge_id,)
        ).fetchone()
        if edge_row is None:
            raise CoordAuthError("edge_not_found")
        actual_gen = int(edge_row["grant_generation"])
        if self._is_tombstoned_conn(conn, edge_id, expected_grant_generation) or self._is_tombstoned_conn(
            conn, edge_id, actual_gen
        ):
            raise RevokedError("grant_tombstoned")
        if int(edge_row["active"]) != 1:
            raise RevokedError("edge_inactive")
        if actual_gen != expected_grant_generation:
            raise RevokedError("grant_generation_mismatch")
        pinned_src = edge_row["src_incarnation"]
        if pinned_src is not None and pinned_src != expected_src_incarnation:
            raise IncarnationMismatchError("src_incarnation_mismatch")
        allowed_threads = set(json.loads(edge_row["allowed_threads_json"]))
        allowed_kinds = set(json.loads(edge_row["allowed_msg_kinds_json"]))
        if (
            edge_row["src_actor"] != envelope.src_actor
            or edge_row["dst_addr"] != envelope.dst_addr
            or envelope.dst_thread_id not in allowed_threads
            or envelope.msg_kind not in allowed_kinds
        ):
            raise CoordAuthError("edge_scope_denied")
        return edge_row

    def _verify_target_sandbox_for_send(
        self, conn: sqlite3.Connection, dst_addr: str, expected_dst_incarnation: str
    ) -> None:
        sb = conn.execute(
            "SELECT incarnation_id, status FROM sandboxes WHERE sandbox_addr = ?", (dst_addr,)
        ).fetchone()
        if sb is None:
            raise CoordValidationError(f"Target sandbox not found: {dst_addr!r}")
        if sb["status"] == _STATUS_REVOKED:
            raise RevokedError("target_sandbox_revoked")
        if sb["incarnation_id"] != expected_dst_incarnation:
            raise IncarnationMismatchError("dst_incarnation_mismatch")

    def _verify_source_sandbox_for_send(
        self,
        conn: sqlite3.Connection,
        src_actor: str,
        expected_src_incarnation: str | None,
    ) -> None:
        sb_addr = _sandbox_addr_from_actor(src_actor)
        sb = (
            conn.execute(
                "SELECT incarnation_id, status FROM sandboxes WHERE sandbox_addr = ?", (sb_addr,)
            ).fetchone()
            if sb_addr is not None
            else None
        )
        if sb is None:
            if expected_src_incarnation is not None:
                raise IncarnationMismatchError("src_sandbox_not_found")
            return
        if sb["status"] == _STATUS_REVOKED:
            raise RevokedError("src_sandbox_revoked")
        if expected_src_incarnation is not None and sb["incarnation_id"] != expected_src_incarnation:
            raise IncarnationMismatchError("src_incarnation_mismatch")

    def _verify_in_reply_to(
        self,
        conn: sqlite3.Connection,
        edge_row: sqlite3.Row,
        envelope: Envelope,
        check_in_reply_to: tuple[str, str, str],
        expected_src_incarnation: str | None = None,
    ) -> None:
        ref_msg_id, caller_dst_addr, thread_id = check_in_reply_to
        if (
            (envelope.in_reply_to is not None and ref_msg_id != envelope.in_reply_to)
            or thread_id != envelope.dst_thread_id
        ):
            raise CoordValidationError(_ERR_INVALID_IN_REPLY_TO)
        ref_row = conn.execute(
            """
            SELECT e.src_actor, e.dst_addr, e.dst_thread_id, e.dst_incarnation, o.status AS outbox_status
            FROM event_log e
            LEFT JOIN outbox o ON o.msg_id = e.msg_id
            WHERE e.msg_id = ? AND e.dst_addr = ? AND e.dst_thread_id = ?
            """,
            (ref_msg_id, caller_dst_addr, thread_id),
        ).fetchone()
        if ref_row is None or ref_row["outbox_status"] not in _REPLYABLE_OUTBOX_STATUSES:
            raise CoordValidationError(_ERR_INVALID_IN_REPLY_TO)
        if expected_src_incarnation is not None and ref_row["dst_incarnation"] != expected_src_incarnation:
            raise CoordValidationError(_ERR_INVALID_IN_REPLY_TO)
        if edge_row["src_actor"] != caller_dst_addr or edge_row["dst_addr"] != ref_row["src_actor"]:
            raise CoordValidationError(_ERR_INVALID_IN_REPLY_TO)

    def _check_outbox_backpressure(
        self,
        conn: sqlite3.Connection,
        edge_id: str,
        body_bytes: int,
        max_queued_msgs: int,
        max_queued_bytes: int,
    ) -> None:
        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt, COALESCE(SUM(body_bytes), 0) AS total_bytes
            FROM outbox WHERE edge_id = ? AND status = ?
            """,
            (edge_id, _STATUS_PENDING),
        ).fetchone()
        if int(row["cnt"]) >= max_queued_msgs or int(row["total_bytes"]) + body_bytes > max_queued_bytes:
            raise CoordBackpressureError("edge_outbox_backpressure_exceeded")

    def _consume_edge_turn(
        self,
        conn: sqlite3.Connection,
        edge_row: sqlite3.Row,
        edge_id: str,
        expected_grant_generation: int,
        count_turn: bool,
    ) -> int:
        if not count_turn:
            return int(edge_row["turns_used"])
        cur = conn.execute(
            """
            UPDATE routing_edges
            SET turns_used = turns_used + 1
            WHERE edge_id = ? AND active = 1 AND grant_generation = ? AND turns_used < max_rounds
            """,
            (edge_id, expected_grant_generation),
        )
        if cur.rowcount != 1:
            raise CoordPolicyError("edge_turn_budget_exhausted")
        row = conn.execute(
            "SELECT turns_used FROM routing_edges WHERE edge_id = ?", (edge_id,)
        ).fetchone()
        return int(row["turns_used"])

    def _persist_admitted_send(
        self,
        conn: sqlite3.Connection,
        edge_row: sqlite3.Row,
        updated_env: Envelope,
        priority: int,
        body_bytes: int,
    ) -> None:
        arts_json = canonical_json(
            [
                {
                    "blob_sha256": a.blob_sha256,
                    "size_bytes": a.size_bytes,
                    "media_type": a.media_type,
                }
                for a in updated_env.artifact_refs
            ]
        )
        conn.execute(
            """
            INSERT INTO event_log (
                seq, msg_id, src_role, src_actor, src_incarnation,
                dst_addr, dst_thread_id, dst_incarnation, trust_class,
                msg_kind, body_text, body_sha256, edge_id, edge_turn_seq,
                in_reply_to, artifact_refs_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                updated_env.seq,
                updated_env.msg_id,
                updated_env.src_role.value,
                updated_env.src_actor,
                updated_env.src_incarnation,
                updated_env.dst_addr,
                updated_env.dst_thread_id,
                updated_env.dst_incarnation,
                updated_env.trust_class.value,
                updated_env.msg_kind,
                updated_env.body_text,
                updated_env.body_sha256,
                updated_env.edge_id,
                updated_env.edge_turn_seq,
                updated_env.in_reply_to,
                arts_json,
                updated_env.created_at,
            ),
        )
        badge = _TRUST_CLASS_TO_BADGE[updated_env.trust_class]
        conn.execute(
            """
            INSERT INTO dispatch_receipts (
                sandbox_addr, incarnation_id, session_id, message_id,
                body_sha256, badge, src_actor, trust_class, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                updated_env.dst_addr,
                updated_env.dst_incarnation,
                updated_env.dst_thread_id,
                updated_env.msg_id,
                updated_env.body_sha256,
                badge.value,
                updated_env.src_actor,
                updated_env.trust_class.value,
            ),
        )
        conn.execute(
            """
            INSERT INTO outbox (
                seq, msg_id, edge_id, lease_request_id, grant_generation,
                src_incarnation, dst_incarnation, thread_id, priority,
                status, body_bytes, attempts, stream_id, detail, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, '', ?)
            """,
            (
                updated_env.seq,
                updated_env.msg_id,
                updated_env.edge_id,
                edge_row["lease_request_id"],
                int(edge_row["grant_generation"]),
                updated_env.src_incarnation,
                updated_env.dst_incarnation,
                updated_env.dst_thread_id,
                priority,
                _STATUS_PENDING,
                body_bytes,
                updated_env.created_at,
            ),
        )
        self._ensure_thread_conn(
            conn,
            updated_env.dst_addr,
            updated_env.dst_incarnation,
            updated_env.dst_thread_id,
            now=updated_env.created_at,
        )
        conn.execute(
            """
            UPDATE threads
            SET last_seq = CASE WHEN last_seq < ? THEN ? ELSE last_seq END,
                updated_at = ?
            WHERE sandbox_addr = ? AND incarnation_id = ? AND thread_id = ?
            """,
            (
                updated_env.seq,
                updated_env.seq,
                updated_env.created_at,
                updated_env.dst_addr,
                updated_env.dst_incarnation,
                updated_env.dst_thread_id,
            ),
        )
        self._append_audit_conn(
            conn,
            updated_env.src_actor,
            "admit_and_enqueue_send",
            updated_env.dst_addr,
            "admitted",
            {
                "msg_id": updated_env.msg_id,
                "seq": updated_env.seq,
                "edge_id": updated_env.edge_id,
                "grant_generation": int(edge_row["grant_generation"]),
                "priority": priority,
            },
        )

    def _validate_envelope_for_send(
        self, envelope: Envelope, expected_src_incarnation: str | None
    ) -> tuple[str, str, int]:
        if not isinstance(envelope.src_role, CoordRole) or not isinstance(envelope.trust_class, TrustClass):
            raise CoordValidationError("Invalid src_role or trust_class")
        max_trust = ROLE_TO_TRUST_CLASS[envelope.src_role]
        if _TRUST_RANK[envelope.trust_class] > _TRUST_RANK[max_trust]:
            raise CoordPolicyError("trust_class_exceeds_role")
        parse_local_target(envelope.dst_addr)
        validate_thread_id(envelope.dst_thread_id)
        validate_msg_kind(envelope.msg_kind)
        validate_opaque_token(envelope.msg_id, "msg_id")
        if envelope.in_reply_to is not None:
            validate_opaque_token(envelope.in_reply_to, "in_reply_to")
        if expected_src_incarnation is not None:
            validate_opaque_token(expected_src_incarnation, "expected_src_incarnation")
        if len(envelope.artifact_refs) > MAX_ARTIFACTS_PER_MSG or any(
            not isinstance(a, ArtifactRef) for a in envelope.artifact_refs
        ):
            raise CoordValidationError("Invalid or excessive artifact_refs")
        max_body = (
            MAX_FRAMED_BODY_BYTES
            if envelope.trust_class is TrustClass.UNTRUSTED_PEER_DATA
            else MAX_INLINE_BODY_BYTES
        )
        canon_body = canonicalize_body_text(envelope.body_text, max_bytes=max_body)
        canon_sha = sha256_canonical_body(canon_body, max_bytes=max_body)
        return canon_body, canon_sha, len(canon_body.encode("utf-8"))

    def admit_and_enqueue_send(
        self,
        *,
        edge_id: str,
        expected_grant_generation: int,
        expected_src_incarnation: str | None,
        expected_dst_incarnation: str,
        envelope: Envelope,
        count_turn: bool,
        max_queued_msgs: int,
        max_queued_bytes: int,
        check_in_reply_to: tuple[str, str, str] | None = None,
    ) -> tuple[int, Envelope]:
        canon_body, canon_sha, body_bytes = self._validate_envelope_for_send(
            envelope, expected_src_incarnation
        )
        priority = 1 if is_control_priority(envelope.trust_class, envelope.msg_kind) else 0
        now = _safe_timestamp(envelope.created_at)

        with self._tx() as conn:
            edge_row = self._verify_edge_for_send(
                conn, edge_id, expected_grant_generation, expected_src_incarnation, envelope
            )
            self._verify_source_sandbox_for_send(conn, envelope.src_actor, expected_src_incarnation)
            self._verify_target_sandbox_for_send(conn, envelope.dst_addr, expected_dst_incarnation)
            effective_src_inc = (
                expected_src_incarnation
                if expected_src_incarnation is not None
                else edge_row["src_incarnation"]
            )
            effective_reply = check_in_reply_to
            if effective_reply is None and envelope.in_reply_to is not None:
                effective_reply = (
                    envelope.in_reply_to,
                    envelope.src_actor,
                    envelope.dst_thread_id,
                )
            if effective_reply is not None:
                self._verify_in_reply_to(
                    conn, edge_row, envelope, effective_reply, effective_src_inc
                )
            if priority == 0:
                self._check_outbox_backpressure(
                    conn, edge_id, body_bytes, max_queued_msgs, max_queued_bytes
                )
            turn_seq = self._consume_edge_turn(
                conn, edge_row, edge_id, expected_grant_generation, count_turn
            )
            seq = self._next_seq(conn)
            updated_env = replace(
                envelope,
                seq=seq,
                src_incarnation=effective_src_inc,
                dst_incarnation=expected_dst_incarnation,
                body_text=canon_body,
                body_sha256=canon_sha,
                edge_id=edge_id,
                edge_turn_seq=turn_seq,
                created_at=now,
            )
            self._persist_admitted_send(conn, edge_row, updated_env, priority, body_bytes)
            return seq, updated_env

    # ------------------------------------------------------------------
    # Fenced Outbox State Machine & Persistent Grant Tombstones
    # ------------------------------------------------------------------

    def _cancel_pending_outbox_msgs(
        self, conn: sqlite3.Connection, msg_ids: list[str], reason: str, now: float
    ) -> None:
        if not msg_ids:
            return
        placeholders = ",".join("?" for _ in msg_ids)
        conn.execute(
            f"""
            UPDATE outbox SET status = ?, detail = ?, updated_at = ?
            WHERE status = ? AND msg_id IN ({placeholders})
            """,
            (_STATUS_CANCELLED, reason, now, _STATUS_PENDING, *msg_ids),
        )
        conn.execute(
            f"""
            DELETE FROM dispatch_receipts
            WHERE consumed_at IS NULL AND message_id IN ({placeholders})
            """,
            tuple(msg_ids),
        )

    def _revoke_whole_sandbox_conn(
        self, conn: sqlite3.Connection, target_addr: str, reason: str, now: float
    ) -> None:
        orch_actor = f"{_ORCH_ACTOR_PREFIX}{target_addr}"
        conn.execute(
            "UPDATE sandboxes SET status = ?, updated_at = ? WHERE sandbox_addr = ?",
            (_STATUS_REVOKED, now, target_addr),
        )
        conn.execute(
            """
            UPDATE tui_enter_tokens SET consumed_at = ?
            WHERE sandbox_addr = ? AND consumed_at IS NULL
            """,
            (now, target_addr),
        )
        conn.execute(
            "DELETE FROM dispatch_receipts WHERE consumed_at IS NULL AND sandbox_addr = ?",
            (target_addr,),
        )
        rows = conn.execute(
            """
            SELECT o.msg_id FROM outbox o
            JOIN event_log e ON e.msg_id = o.msg_id
            WHERE o.status = ? AND (e.dst_addr = ? OR e.src_actor = ? OR e.src_actor = ?)
            """,
            (_STATUS_PENDING, target_addr, target_addr, orch_actor),
        ).fetchall()
        self._cancel_pending_outbox_msgs(conn, [r["msg_id"] for r in rows], reason, now)

    def invalidate_prior_incarnation(
        self, sandbox_addr: str, new_incarnation_id: str, *, reason: str = "incarnation_rotated"
    ) -> list[str]:
        """Invalidate prior-incarnation edges, pending outbox rows, receipts, and TUI tokens."""
        clean_addr = parse_local_target(sandbox_addr).canonical
        validate_opaque_token(new_incarnation_id, "new_incarnation_id")
        clean_reason = validate_reason_text(reason, "reason")
        orch_actor = f"{_ORCH_ACTOR_PREFIX}{clean_addr}"
        now = time.time()
        with self._tx() as conn:
            conn.execute(
                """
                UPDATE tui_enter_tokens SET consumed_at = ?
                WHERE sandbox_addr = ? AND incarnation_id != ? AND consumed_at IS NULL
                """,
                (now, clean_addr, new_incarnation_id),
            )
            conn.execute(
                """
                DELETE FROM dispatch_receipts
                WHERE consumed_at IS NULL AND sandbox_addr = ? AND incarnation_id != ?
                """,
                (clean_addr, new_incarnation_id),
            )
            stale_outbox = conn.execute(
                """
                SELECT o.msg_id FROM outbox o
                JOIN event_log e ON e.msg_id = o.msg_id
                WHERE o.status = ? AND (
                    (e.dst_addr = ? AND o.dst_incarnation != ?)
                    OR ((e.src_actor = ? OR e.src_actor = ?) AND o.src_incarnation IS NOT NULL AND o.src_incarnation != ?)
                )
                """,
                (_STATUS_PENDING, clean_addr, new_incarnation_id, clean_addr, orch_actor, new_incarnation_id),
            ).fetchall()
            self._cancel_pending_outbox_msgs(
                conn, [r["msg_id"] for r in stale_outbox], clean_reason, now
            )
            edge_rows = conn.execute(
                """
                SELECT edge_id, grant_generation FROM routing_edges
                WHERE active = 1 AND (
                    dst_addr = ?
                    OR ((src_actor = ? OR src_actor = ?) AND src_incarnation IS NOT NULL AND src_incarnation != ?)
                )
                ORDER BY edge_id ASC
                """,
                (clean_addr, clean_addr, orch_actor, new_incarnation_id),
            ).fetchall()
            return self._revoke_matching_edges_conn(conn, edge_rows, clean_reason, now)

    def _build_revoke_where(
        self,
        target_addr: str | None,
        edge_id: str | None,
        lease_request_id: str | None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if target_addr is not None:
            orch_actor = f"{_ORCH_ACTOR_PREFIX}{target_addr}"
            clauses.append("(dst_addr = ? OR src_actor = ? OR src_actor = ?)")
            params.extend((target_addr, target_addr, orch_actor))
        if edge_id is not None:
            clauses.append("edge_id = ?")
            params.append(edge_id)
        if lease_request_id is not None:
            clauses.append("lease_request_id = ?")
            params.append(lease_request_id)
        if not clauses:
            raise CoordValidationError("At least one revocation selector is required")
        return " AND ".join(clauses), params

    def _revoke_matching_edges_conn(
        self, conn: sqlite3.Connection, rows: list[sqlite3.Row], reason: str, now: float
    ) -> list[str]:
        revoked_ids: list[str] = []
        for row in rows:
            eid = row["edge_id"]
            gen = int(row["grant_generation"])
            revoked_ids.append(eid)
            conn.execute(
                """
                INSERT OR IGNORE INTO grant_tombstones
                    (edge_id, grant_generation, reason, revoked_at)
                VALUES (?, ?, ?, ?)
                """,
                (eid, gen, reason, now),
            )
            conn.execute("UPDATE routing_edges SET active = 0 WHERE edge_id = ?", (eid,))
            all_edge_msgs = conn.execute(
                "SELECT msg_id, status FROM outbox WHERE edge_id = ? AND grant_generation = ?",
                (eid, gen),
            ).fetchall()
            pending_ids = [r["msg_id"] for r in all_edge_msgs if r["status"] == _STATUS_PENDING]
            self._cancel_pending_outbox_msgs(conn, pending_ids, reason, now)
            all_ids = [r["msg_id"] for r in all_edge_msgs]
            if all_ids:
                placeholders = ",".join("?" for _ in all_ids)
                conn.execute(
                    f"DELETE FROM dispatch_receipts WHERE consumed_at IS NULL AND message_id IN ({placeholders})",
                    tuple(all_ids),
                )
        return revoked_ids

    def _revoke_lease_only_outbox_conn(
        self, conn: sqlite3.Connection, lease_request_id: str, reason: str, now: float
    ) -> None:
        lease_rows = conn.execute(
            "SELECT msg_id, status FROM outbox WHERE lease_request_id = ?",
            (lease_request_id,),
        ).fetchall()
        pending_ids = [r["msg_id"] for r in lease_rows if r["status"] == _STATUS_PENDING]
        self._cancel_pending_outbox_msgs(conn, pending_ids, reason, now)
        all_lease_ids = [r["msg_id"] for r in lease_rows]
        if all_lease_ids:
            placeholders = ",".join("?" for _ in all_lease_ids)
            conn.execute(
                f"DELETE FROM dispatch_receipts WHERE consumed_at IS NULL AND message_id IN ({placeholders})",
                tuple(all_lease_ids),
            )

    def revoke_grant_and_cancel_outbox(
        self,
        *,
        target_addr: str | None = None,
        edge_id: str | None = None,
        lease_request_id: str | None = None,
        reason: str = "revoked",
    ) -> list[str]:
        clean_reason = validate_reason_text(reason, "reason")
        where, params = self._build_revoke_where(target_addr, edge_id, lease_request_id)
        whole_sandbox = target_addr is not None and edge_id is None and lease_request_id is None
        lease_only = lease_request_id is not None and edge_id is None and target_addr is None
        now = time.time()

        with self._tx() as conn:
            if whole_sandbox and target_addr is not None:
                self._revoke_whole_sandbox_conn(conn, target_addr, clean_reason, now)
            rows = conn.execute(
                f"SELECT edge_id, grant_generation FROM routing_edges WHERE {where} ORDER BY edge_id ASC",
                params,
            ).fetchall()
            revoked_ids = self._revoke_matching_edges_conn(conn, rows, clean_reason, now)
            if lease_only and lease_request_id is not None:
                self._revoke_lease_only_outbox_conn(conn, lease_request_id, clean_reason, now)
            self._append_audit_conn(
                conn,
                "host",
                "revoke_grant_and_cancel_outbox",
                target_addr or edge_id or lease_request_id or "",
                _STATUS_REVOKED,
                {"revoked_edges": revoked_ids, "reason": clean_reason},
            )
            return revoked_ids

    def is_grant_tombstoned(self, edge_id: str, grant_generation: int) -> bool:
        with self._lock:
            return self._is_tombstoned_conn(self._conn, edge_id, grant_generation)

    def list_outbox(self, *, statuses: tuple[str, ...] = (_STATUS_PENDING,)) -> list[dict[str, Any]]:
        if not statuses:
            return []
        for st in statuses:
            if st not in _VALID_OUTBOX_STATUSES:
                raise CoordValidationError(f"Invalid outbox status: {st!r}")
        placeholders = ",".join("?" for _ in statuses)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM outbox WHERE status IN ({placeholders}) ORDER BY priority DESC, seq ASC",
                statuses,
            ).fetchall()
            return [_row_to_outbox_dict(r) for r in rows]

    def get_envelope(self, msg_id: str) -> Envelope | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM event_log WHERE msg_id = ?", (msg_id,)
            ).fetchone()
            return _row_to_envelope(row) if row is not None else None

    def _outbox_fence_allows(
        self,
        conn: sqlite3.Connection,
        edge_id: str,
        grant_generation: int,
        src_incarnation: str | None,
        dst_incarnation: str,
    ) -> bool:
        edge = conn.execute(
            "SELECT src_actor, dst_addr, active, grant_generation FROM routing_edges WHERE edge_id = ?",
            (edge_id,),
        ).fetchone()
        if (
            edge is None
            or int(edge["active"]) != 1
            or int(edge["grant_generation"]) != grant_generation
            or self._is_tombstoned_conn(conn, edge_id, grant_generation)
        ):
            return False
        dst_sb = conn.execute(
            "SELECT incarnation_id, status FROM sandboxes WHERE sandbox_addr = ?",
            (edge["dst_addr"],),
        ).fetchone()
        if dst_sb is None or dst_sb["status"] == _STATUS_REVOKED or dst_sb["incarnation_id"] != dst_incarnation:
            return False
        src_sb_addr = _sandbox_addr_from_actor(edge["src_actor"])
        src_sb = (
            conn.execute(
                "SELECT incarnation_id, status FROM sandboxes WHERE sandbox_addr = ?",
                (src_sb_addr,),
            ).fetchone()
            if src_sb_addr is not None
            else None
        )
        if src_sb is None:
            return src_incarnation is None
        if src_sb["status"] == _STATUS_REVOKED:
            return False
        if src_incarnation is not None and src_sb["incarnation_id"] != src_incarnation:
            return False
        return True

    def mark_outbox_dispatch_started(
        self,
        msg_id: str,
        *,
        edge_id: str,
        grant_generation: int,
        dst_incarnation: str,
    ) -> bool:
        now = time.time()
        with self._tx() as conn:
            row = conn.execute(
                """
                SELECT src_incarnation FROM outbox
                WHERE msg_id = ? AND status = ? AND edge_id = ?
                  AND grant_generation = ? AND dst_incarnation = ?
                """,
                (msg_id, _STATUS_PENDING, edge_id, grant_generation, dst_incarnation),
            ).fetchone()
            if row is None:
                return False
            if not self._outbox_fence_allows(
                conn, edge_id, grant_generation, row["src_incarnation"], dst_incarnation
            ):
                return False
            cur = conn.execute(
                """
                UPDATE outbox
                SET status = ?, attempts = attempts + 1, updated_at = ?
                WHERE msg_id = ? AND status = ? AND edge_id = ?
                  AND grant_generation = ? AND dst_incarnation = ?
                """,
                (
                    _STATUS_DISPATCH_STARTED,
                    now,
                    msg_id,
                    _STATUS_PENDING,
                    edge_id,
                    grant_generation,
                    dst_incarnation,
                ),
            )
            return cur.rowcount == 1

    def return_outbox_to_pending(self, msg_id: str, *, detail: str = "") -> bool:
        now = time.time()
        with self._tx() as conn:
            row = conn.execute(
                """
                SELECT edge_id, grant_generation, src_incarnation, dst_incarnation
                FROM outbox WHERE msg_id = ? AND status = ?
                """,
                (msg_id, _STATUS_DISPATCH_STARTED),
            ).fetchone()
            if row is None:
                return False
            if not self._outbox_fence_allows(
                conn,
                row["edge_id"],
                int(row["grant_generation"]),
                row["src_incarnation"],
                row["dst_incarnation"],
            ):
                return False
            cur = conn.execute(
                """
                UPDATE outbox SET status = ?, detail = ?, updated_at = ?
                WHERE msg_id = ? AND status = ?
                """,
                (_STATUS_PENDING, detail, now, msg_id, _STATUS_DISPATCH_STARTED),
            )
            return cur.rowcount == 1

    def mark_outbox_handed_off(self, msg_id: str, *, stream_id: str) -> None:
        validate_opaque_token(stream_id, "stream_id")
        now = time.time()
        with self._tx() as conn:
            cur = conn.execute(
                """
                UPDATE outbox SET status = ?, stream_id = ?, updated_at = ?
                WHERE msg_id = ? AND status = ?
                """,
                (_STATUS_HANDED_OFF, stream_id, now, msg_id, _STATUS_DISPATCH_STARTED),
            )
            if cur.rowcount != 1:
                raise CoordValidationError(_ERR_INVALID_OUTBOX_TRANSITION)

    def mark_outbox_uncertain(self, msg_id: str, *, detail: str) -> None:
        now = time.time()
        with self._tx() as conn:
            cur = conn.execute(
                """
                UPDATE outbox SET status = ?, detail = ?, updated_at = ?
                WHERE msg_id = ? AND status = ?
                """,
                (_STATUS_UNCERTAIN, detail, now, msg_id, _STATUS_DISPATCH_STARTED),
            )
            if cur.rowcount != 1:
                raise CoordValidationError(_ERR_INVALID_OUTBOX_TRANSITION)
            self._append_audit_conn(
                conn, "host", "mark_outbox_uncertain", msg_id, _STATUS_UNCERTAIN, {"detail": detail}
            )

    def mark_outbox_completed(self, msg_id: str) -> None:
        now = time.time()
        with self._tx() as conn:
            cur = conn.execute(
                """
                UPDATE outbox SET status = ?, updated_at = ?
                WHERE msg_id = ? AND status = ?
                """,
                (_STATUS_COMPLETED, now, msg_id, _STATUS_HANDED_OFF),
            )
            if cur.rowcount != 1:
                raise CoordValidationError(_ERR_INVALID_OUTBOX_TRANSITION)

    def mark_outbox_aborted(self, msg_id: str, *, reason: str = "stream_aborted") -> None:
        clean_reason = validate_reason_text(reason, "reason")
        now = time.time()
        with self._tx() as conn:
            cur = conn.execute(
                """
                UPDATE outbox SET status = ?, detail = ?, updated_at = ?
                WHERE msg_id = ? AND status = ?
                """,
                (_STATUS_ABORTED, clean_reason, now, msg_id, _STATUS_HANDED_OFF),
            )
            if cur.rowcount != 1:
                raise CoordValidationError(_ERR_INVALID_OUTBOX_TRANSITION)
            conn.execute(
                "DELETE FROM dispatch_receipts WHERE consumed_at IS NULL AND message_id = ?",
                (msg_id,),
            )

    def cancel_outbox_row(self, msg_id: str, *, reason: str) -> None:
        clean_reason = validate_reason_text(reason, "reason")
        now = time.time()
        with self._tx() as conn:
            cur = conn.execute(
                """
                UPDATE outbox SET status = ?, detail = ?, updated_at = ?
                WHERE msg_id = ? AND status IN (?, ?)
                """,
                (_STATUS_CANCELLED, clean_reason, now, msg_id, _STATUS_PENDING, _STATUS_DISPATCH_STARTED),
            )
            if cur.rowcount != 1:
                raise CoordValidationError(_ERR_INVALID_OUTBOX_TRANSITION)
            conn.execute(
                "DELETE FROM dispatch_receipts WHERE consumed_at IS NULL AND message_id = ?",
                (msg_id,),
            )

    # ------------------------------------------------------------------
    # Provenance Receipts, TUI Enter Tokens, & Hostile Stream Events
    # ------------------------------------------------------------------

    def _sandbox_is_live_conn(
        self, conn: sqlite3.Connection, sandbox_addr: str, incarnation_id: str
    ) -> bool:
        sb = conn.execute(
            "SELECT incarnation_id, status FROM sandboxes WHERE sandbox_addr = ?",
            (sandbox_addr,),
        ).fetchone()
        if sb is None:
            return False
        return sb["status"] != _STATUS_REVOKED and sb["incarnation_id"] == incarnation_id

    def consume_dispatch_receipt(
        self,
        sandbox_addr: str,
        incarnation_id: str,
        thread_id: str,
        message_id: str,
        body_text: str,
    ) -> ProvenanceBadge | None:
        try:
            canon_sha = sha256_canonical_body(body_text, max_bytes=MAX_FRAMED_BODY_BYTES)
        except CoordValidationError:
            return None
        now = time.time()
        with self._tx() as conn:
            if not self._sandbox_is_live_conn(conn, sandbox_addr, incarnation_id):
                return None
            row = conn.execute(
                """
                SELECT badge FROM dispatch_receipts
                WHERE sandbox_addr = ? AND incarnation_id = ? AND session_id = ?
                  AND message_id = ? AND body_sha256 = ? AND consumed_at IS NULL
                """,
                (sandbox_addr, incarnation_id, thread_id, message_id, canon_sha),
            ).fetchone()
            if row is None:
                return None
            cur = conn.execute(
                """
                UPDATE dispatch_receipts SET consumed_at = ?
                WHERE sandbox_addr = ? AND incarnation_id = ? AND session_id = ?
                  AND message_id = ? AND body_sha256 = ? AND consumed_at IS NULL
                """,
                (now, sandbox_addr, incarnation_id, thread_id, message_id, canon_sha),
            )
            if cur.rowcount != 1:
                return None
            return ProvenanceBadge(row["badge"])

    def mint_tui_enter_token(
        self,
        sandbox_addr: str,
        incarnation_id: str,
        surface_kind: str,
        *,
        ttl_s: float = _MAX_TUI_TOKEN_TTL_S,
    ) -> str:
        parse_local_target(sandbox_addr)
        validate_opaque_token(incarnation_id, "incarnation_id")
        if surface_kind != _TUI_SURFACE_KIND:
            raise CoordPolicyError(f"Unsupported TUI enter token surface: {surface_kind!r}")
        if (
            isinstance(ttl_s, bool)
            or not isinstance(ttl_s, (int, float))
            or not (0.0 < float(ttl_s) <= _MAX_TUI_TOKEN_TTL_S)
        ):
            raise CoordPolicyError(f"TUI enter token ttl_s must be in (0, {_MAX_TUI_TOKEN_TTL_S}]")
        token = f"tui_{secrets.token_hex(24)}"
        token_sha = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = time.time() + float(ttl_s)
        with self._tx() as conn:
            sb = conn.execute(
                "SELECT incarnation_id, status FROM sandboxes WHERE sandbox_addr = ?",
                (sandbox_addr,),
            ).fetchone()
            if sb is not None and (
                sb["status"] == _STATUS_REVOKED or sb["incarnation_id"] != incarnation_id
            ):
                raise RevokedError("sandbox_revoked_or_rotated")
            conn.execute(
                """
                INSERT INTO tui_enter_tokens
                    (token_sha256, sandbox_addr, incarnation_id, surface_kind, expires_at, consumed_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (token_sha, sandbox_addr, incarnation_id, _TUI_SURFACE_KIND, expires_at),
            )
        return token

    def consume_tui_enter_token(
        self, token: str, sandbox_addr: str, incarnation_id: str, surface_kind: str
    ) -> bool:
        if surface_kind != _TUI_SURFACE_KIND or not isinstance(token, str) or not token:
            return False
        token_sha = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = time.time()
        with self._tx() as conn:
            cur = conn.execute(
                """
                UPDATE tui_enter_tokens SET consumed_at = ?
                WHERE token_sha256 = ? AND sandbox_addr = ? AND incarnation_id = ?
                  AND surface_kind = ? AND consumed_at IS NULL AND expires_at >= ?
                """,
                (now, token_sha, sandbox_addr, incarnation_id, _TUI_SURFACE_KIND, now),
            )
            return cur.rowcount == 1

    def _resolve_user_message_badge(
        self, event: StreamEvent, safe_message_id: str | None, tui_enter_token: str | None
    ) -> ProvenanceBadge:
        if safe_message_id is not None:
            receipt_badge = self.consume_dispatch_receipt(
                event.sandbox_addr,
                event.incarnation_id,
                event.thread_id,
                safe_message_id,
                event.text,
            )
            if receipt_badge is not None:
                return receipt_badge
        if tui_enter_token is not None and self.consume_tui_enter_token(
            tui_enter_token, event.sandbox_addr, event.incarnation_id, _TUI_SURFACE_KIND
        ):
            return ProvenanceBadge.TUI_INPUT
        return ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED

    @staticmethod
    def _validate_stream_event_fields(event: StreamEvent) -> None:
        if not isinstance(event, StreamEvent):
            raise CoordValidationError("event must be a StreamEvent")
        if event.event_type not in STREAM_EVENT_TYPES:
            raise CoordValidationError(f"Unsupported StreamEvent type: {event.event_type!r}")
        parse_local_target(event.sandbox_addr)
        validate_opaque_token(event.incarnation_id, "incarnation_id")
        validate_thread_id(event.thread_id)
        validate_stream_text(event.text)
        if event.file_path is not None:
            validate_sandbox_rel_path(event.file_path)

    def record_stream_event(
        self, event: StreamEvent, *, tui_enter_token: str | None = None
    ) -> dict[str, Any]:
        self._validate_stream_event_fields(event)
        clean_detail, detail_json = _sanitize_stream_detail(event.detail)
        safe_message_id = _sanitize_stream_message_id(event.message_id)
        now = _safe_timestamp(event.created_at)
        with self._tx() as conn:
            badge: ProvenanceBadge | None = None
            if event.event_type == "user_message":
                badge = self._resolve_user_message_badge(event, safe_message_id, tui_enter_token)
            seq = self._next_seq(conn)
            badge_val = badge.value if badge is not None else None
            conn.execute(
                """
                INSERT INTO stream_events (
                    seq, event_type, sandbox_addr, incarnation_id, thread_id,
                    seq_hint, message_id, text, file_path, detail_json, badge, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    seq,
                    event.event_type,
                    event.sandbox_addr,
                    event.incarnation_id,
                    event.thread_id,
                    event.seq_hint,
                    safe_message_id,
                    event.text,
                    event.file_path,
                    detail_json,
                    badge_val,
                    now,
                ),
            )
            sb_exists = conn.execute(
                "SELECT 1 FROM sandboxes WHERE sandbox_addr = ?", (event.sandbox_addr,)
            ).fetchone()
            if sb_exists is not None:
                self._ensure_thread_conn(
                    conn, event.sandbox_addr, event.incarnation_id, event.thread_id, now=now
                )
                conn.execute(
                    """
                    UPDATE threads
                    SET last_seq = CASE WHEN last_seq < ? THEN ? ELSE last_seq END,
                        updated_at = ?
                    WHERE sandbox_addr = ? AND incarnation_id = ? AND thread_id = ?
                    """,
                    (seq, seq, now, event.sandbox_addr, event.incarnation_id, event.thread_id),
                )
            return {
                "source": "stream_event",
                "seq": seq,
                "event_type": event.event_type,
                "sandbox_addr": event.sandbox_addr,
                "incarnation_id": event.incarnation_id,
                "thread_id": event.thread_id,
                "seq_hint": event.seq_hint,
                "message_id": safe_message_id,
                "text": event.text,
                "file_path": event.file_path,
                "detail": clean_detail,
                "badge": badge_val,
                "created_at": now,
            }

    @staticmethod
    def _event_trust_excluded(item: dict[str, Any], exclude_trust_classes: frozenset[str]) -> bool:
        if not exclude_trust_classes:
            return False
        trust = item.get("trust_class")
        if trust is not None and str(trust) in exclude_trust_classes:
            return True
        return (
            item.get("badge") == ProvenanceBadge.OPERATOR.value
            and TrustClass.OPERATOR_DIRECTIVE.value in exclude_trust_classes
        )

    @staticmethod
    def _event_allowed_by_scope(
        item: dict[str, Any],
        *,
        allowed_threads_by_sandbox: Mapping[str, frozenset[str]] | None,
        required_incarnations: Mapping[str, str] | None,
        exclude_trust_classes: frozenset[str],
    ) -> bool:
        addr = str(item.get("dst_addr") or item.get("sandbox_addr") or "")
        inc = str(item.get("dst_incarnation") or item.get("incarnation_id") or "")
        thread_id = str(item.get("dst_thread_id") or item.get("thread_id") or "")
        if required_incarnations is not None and required_incarnations.get(addr) != inc:
            return False
        if allowed_threads_by_sandbox is not None:
            allowed_threads = allowed_threads_by_sandbox.get(addr)
            if allowed_threads is None or thread_id not in allowed_threads:
                return False
        return not CoordRegistry._event_trust_excluded(item, exclude_trust_classes)

    def has_committed_artifact(
        self, sandbox_addr: str, incarnation_id: str, blob_sha256: str
    ) -> bool:
        """Return True iff blob_sha256 was committed to (sandbox_addr, incarnation_id) on a non-cancelled envelope."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT e.artifact_refs_json FROM event_log e
                LEFT JOIN outbox o ON o.msg_id = e.msg_id
                WHERE e.dst_addr = ? AND e.dst_incarnation = ?
                  AND (o.status IS NULL OR o.status != ?)
                """,
                (sandbox_addr, incarnation_id, _STATUS_CANCELLED),
            ).fetchall()
        for row in rows:
            try:
                refs = json.loads(row["artifact_refs_json"] or "[]")
            except ValueError:
                continue
            if any(isinstance(r, dict) and r.get("blob_sha256") == blob_sha256 for r in refs):
                return True
        return False

    def list_events_since(
        self,
        sandbox_addrs: Iterable[str],
        since_seq: int,
        *,
        limit: int = 200,
        allowed_threads_by_sandbox: Mapping[str, frozenset[str]] | None = None,
        required_incarnations: Mapping[str, str] | None = None,
        exclude_trust_classes: frozenset[str] = frozenset(),
    ) -> list[dict[str, Any]]:
        if type(limit) is not int or limit < 1:
            raise CoordValidationError("limit must be a positive integer")
        addrs = sorted({str(a) for a in sandbox_addrs})
        if not addrs:
            return []
        placeholders = ",".join("?" for _ in addrs)
        fetch_limit = limit * 4 if (allowed_threads_by_sandbox or required_incarnations or exclude_trust_classes) else limit
        with self._lock:
            ev_rows = self._conn.execute(
                f"""
                SELECT * FROM event_log
                WHERE dst_addr IN ({placeholders}) AND seq > ?
                ORDER BY seq ASC LIMIT ?
                """,
                (*addrs, since_seq, fetch_limit),
            ).fetchall()
            st_rows = self._conn.execute(
                f"""
                SELECT * FROM stream_events
                WHERE sandbox_addr IN ({placeholders}) AND seq > ?
                ORDER BY seq ASC LIMIT ?
                """,
                (*addrs, since_seq, fetch_limit),
            ).fetchall()
        merged = [_row_to_event_log_dict(r) for r in ev_rows] + [
            _row_to_stream_event_dict(r) for r in st_rows
        ]
        if allowed_threads_by_sandbox is not None or required_incarnations is not None or exclude_trust_classes:
            merged = [
                item
                for item in merged
                if self._event_allowed_by_scope(
                    item,
                    allowed_threads_by_sandbox=allowed_threads_by_sandbox,
                    required_incarnations=required_incarnations,
                    exclude_trust_classes=exclude_trust_classes,
                )
            ]
        merged.sort(key=lambda item: int(item["seq"]))
        return merged[:limit]

    # ------------------------------------------------------------------
    # Projection, Worktree Auto-Discovery, & Hash-Chained Audit Log
    # ------------------------------------------------------------------

    def get_projection(self) -> dict[str, Any]:
        with self._lock:
            sb_rows = self._conn.execute(
                "SELECT * FROM sandboxes ORDER BY project_id ASC, sandbox_addr ASC"
            ).fetchall()
            th_rows = self._conn.execute(
                "SELECT * FROM threads ORDER BY sandbox_addr ASC, incarnation_id ASC, thread_id ASC"
            ).fetchall()
            st_rows = self._conn.execute(
                "SELECT * FROM stream_events ORDER BY seq ASC"
            ).fetchall()

        msgs_by_thread: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        for row in st_rows:
            key = (row["sandbox_addr"], row["incarnation_id"], row["thread_id"])
            msgs_by_thread.setdefault(key, []).append(_row_to_stream_event_dict(row))

        threads_by_sb: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in th_rows:
            tkey = (row["sandbox_addr"], row["incarnation_id"], row["thread_id"])
            threads_by_sb.setdefault((row["sandbox_addr"], row["incarnation_id"]), []).append(
                {
                    "thread_id": row["thread_id"],
                    "title": row["title"],
                    "status": row["status"],
                    "last_seq": int(row["last_seq"]),
                    "messages": msgs_by_thread.get(tkey, []),
                }
            )

        projects_map: dict[str, dict[str, Any]] = {}
        for row in sb_rows:
            pid = row["project_id"]
            proj = projects_map.setdefault(
                pid,
                {"project_id": pid, "project_name": row["project_name"], "sandboxes": []},
            )
            proj["sandboxes"].append(
                {
                    "sandbox_addr": row["sandbox_addr"],
                    "worker_ref": row["worker_ref"],
                    "instance_name": row["instance_name"],
                    "incarnation_id": row["incarnation_id"],
                    "branch": row["branch"],
                    "status": row["status"],
                    "threads": threads_by_sb.get((row["sandbox_addr"], row["incarnation_id"]), []),
                }
            )
        return {"projects": list(projects_map.values())}

    def discover_worktrees(self) -> list[dict[str, Any]]:
        wt_dir = self._state_dir / "worktrees"
        if not wt_dir.exists() and not wt_dir.is_symlink():
            return []
        try:
            trusted_wt = assert_trusted_dir(wt_dir, sandbox_root=self._sandbox_root)
        except PolicyError as exc:
            raise CoordPolicyError(str(exc)) from exc
        found: list[dict[str, Any]] = []
        for entry in sorted(trusted_wt.iterdir(), key=lambda p: p.name):
            parsed = _parse_worktree_entry(entry, trusted_wt, self._sandbox_root)
            if parsed is not None:
                found.append(parsed)
        return found

    def append_audit(
        self,
        actor: str,
        action: str,
        target: str,
        outcome: str,
        detail: Mapping[str, Any] | None = None,
    ) -> int:
        with self._tx() as conn:
            return self._append_audit_conn(conn, actor, action, target, outcome, detail)

    def verify_audit_chain(self) -> tuple[bool, int]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, actor, action, target, outcome, detail_json,
                       created_at, prev_hash, entry_hash
                FROM audit_log ORDER BY id ASC
                """
            ).fetchall()
        expected_prev = _AUDIT_GENESIS_HASH
        for row in rows:
            row_id = int(row["id"])
            if row["prev_hash"] != expected_prev:
                return False, row_id
            expected_hash = _compute_audit_hash(
                expected_prev,
                row["actor"],
                row["action"],
                row["target"],
                row["outcome"],
                row["detail_json"],
                float(row["created_at"]),
            )
            if row["entry_hash"] != expected_hash:
                return False, row_id
            expected_prev = expected_hash
        return True, len(rows)
