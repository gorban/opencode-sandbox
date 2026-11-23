"""Exhaustive offline qualification & adversarial test suite for PRD N3 Human Inbox read projection.

Runs 100% offline with zero Podman, zero network, and zero writes to host
production directories:
    python3 -B -m unittest discover -s docs/prds/spikes/n/inbox-read -p 'test_*.py' -v
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import itertools
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import threading
import time
from typing import Any
import unittest
from unittest import mock

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
from oc_coord_contract import (  # noqa: E402
    CoordAuthError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    PrincipalCtx,
    RevokedError,
)
from oc_inbox_contract import (  # noqa: E402
    ANOMALY_ARTIFACT_AMBIGUOUS,
    ANOMALY_ARTIFACT_MISMATCH,
    ANOMALY_ARTIFACT_MISSING,
    ANOMALY_MALFORMED_METADATA,
    ANOMALY_PIN_MISMATCH,
    ANOMALY_POLICY_MISMATCH,
    ANOMALY_RUN_MISSING,
    ANOMALY_TAMPERED_STORAGE,
    BUCKET_MALFORMED,
    CURSOR_PREFIX,
    ERR_CURSOR_MALFORMED,
    ERR_CURSOR_SCOPE_MISMATCH,
    ERR_CURSOR_SNAPSHOT_CHANGED,
    MAX_ITEM_TEXT_BYTES,
    MAX_SQLITE_INT64,
    MIN_RESPONSE_BYTES,
    OP_INBOX_LIST,
    PIN_VERIFICATION_SCOPE_ITEM_ONLY,
    REDACTED_MARKER,
    SOURCE_HOST_WORKFLOW_ENGINE,
    SOURCE_ORCHESTRATOR_ADVISORY,
    STATUS_EXPIRED,
    STATUS_PENDING,
    STATUS_RESOLVED,
    STATUS_SUPERSEDED,
    compute_review_pin_sha256,
    compute_scope_hash,
    encode_inbox_list_cursor,
    serialize_inbox_bytes,
    serialize_inbox_json,
)
from oc_inbox_db import (  # noqa: E402
    DB_FILENAME,
    ERR_INBOX_UNREADABLE,
    ERR_READ_DEADLINE,
    ERR_STATE_DIR_UNREADABLE,
    open_readonly_inbox_snapshot,
)
from oc_inbox_projection import (  # noqa: E402
    HumanInboxReadProjection,
    ReadOnlyInboxService,
    _safe_finite_float,
    _safe_nullable_finite_float,
)

_SCHEMA_SQL = """
CREATE TABLE inbox_seq_counter (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    last_seq INTEGER NOT NULL
);

CREATE TABLE workflow_runs (
    run_id        TEXT PRIMARY KEY,
    workflow_id   TEXT NOT NULL,
    spec_digest   TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    status        TEXT NOT NULL,
    owner_role    TEXT NOT NULL,
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);

CREATE TABLE review_items (
    review_id             TEXT PRIMARY KEY,
    run_id                TEXT NOT NULL,
    step_id               TEXT NOT NULL,
    checkpoint_seq        INTEGER NOT NULL,
    item_revision         INTEGER NOT NULL,
    status                TEXT NOT NULL,
    severity              TEXT NOT NULL,
    priority_rank         INTEGER NOT NULL,
    lane_paused           INTEGER NOT NULL,
    requires_human_review INTEGER NOT NULL,
    source_kind           TEXT NOT NULL,
    target_addr           TEXT,
    target_incarnation_id TEXT,
    title                 TEXT NOT NULL,
    summary_text          TEXT NOT NULL,
    artifact_sha256       TEXT NOT NULL,
    policy_digest         TEXT NOT NULL,
    review_pin_sha256     TEXT NOT NULL,
    metadata_json         TEXT NOT NULL,
    created_at            REAL NOT NULL,
    updated_at            REAL NOT NULL,
    expires_at            REAL
);

CREATE TABLE review_artifacts (
    artifact_id TEXT PRIMARY KEY,
    review_id   TEXT NOT NULL,
    blob_sha256 TEXT NOT NULL,
    size_bytes  INTEGER NOT NULL,
    media_type  TEXT NOT NULL,
    label       TEXT NOT NULL,
    is_primary  INTEGER NOT NULL,
    created_at  REAL NOT NULL
);

CREATE INDEX idx_review_items_order
    ON review_items (priority_rank DESC, checkpoint_seq ASC, review_id ASC);
CREATE INDEX idx_review_items_run_status
    ON review_items (run_id, status);
CREATE INDEX idx_review_artifacts_review
    ON review_artifacts (review_id, is_primary DESC, artifact_id ASC);
"""

_OP = PrincipalCtx(role=CoordRole.OPERATOR, actor_id="operator:local")
_RUN_ID = "run-inbox-0001"
_WORKFLOW_ID = "builtin/prd-delivery"
_SPEC_DIGEST = "1" * 64
_POLICY_DIGEST = "2" * 64
_ART_SHA = "3" * 64
_ART_SHA_ALT = "4" * 64
_STEP_ID = "step-human-gate"
_REV_ID = "rev-0001"
_ART_ID = "art-0001"
_SESS_ID = "sess-inbox-001"
_MEDIA_PATCH = "text/x-patch"

# Synthetic fixture tokens constructed dynamically to avoid static-scanner false positives.
_CANARY_KEY_SECRET = "".join(("sk-ant-", "canarykey", "98765432"))
_CANARY_REVIEW_ID = "".join(("sk-ant-", "synthetic-", "12345678"))
_CANARY_RUN_ID = "".join(("ghp_", "syntheticRun", "Token9999"))
_CANARY_ART_ID = "".join(("ocjob_", "syntheticArt", "Secret1"))
_CANARY_INC_ID = "".join(("ocpeer_", "syntheticInc", "Secret1"))

_SQL_INSERT_ART = "INSERT INTO review_artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
_SQL_INSERT_RUN = "INSERT INTO workflow_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
_ERR_ITEM_NOT_FOUND = "review_item_not_found"
_ERR_UNSUPPORTED_STATUS = "unsupported_inbox_status_filter"
_SQL_BUMP_SEQ = "UPDATE inbox_seq_counter SET last_seq = last_seq + 1 WHERE id = 1"
_SQL_CLEAR_SEQ = "DELETE FROM inbox_seq_counter"
_REV_REMOTE = "rev-remote"
_REV_BADPIN = "rev-badpin"
_REV_BADPOL = "rev-badpol"
_REV_DUP_ART = "rev-dup-art"
_REV_ART_MIS = "rev-art-mis"
_REV_BLOBSEQ = "rev-blobseq"
_REV_ADV_PAUSED = "rev-adv-paused"
_REV_CLEAN_ML = "rev-clean-ml"
_REV_SPLIT_UTF8 = "rev-split-utf8"
_REV_SPLIT_ESC = "rev-split-esc"
_REV_SEC_RED = "rev-sec-red"
_REV_HIGH_0 = "rev:high:0"
_REV_HIGH_MAX = "rev:high:max"
_REV_TIE_TEXT = "rev-tie-text"
_ADDR_REMOTE = "macmini / dev-1"
_VAL_FIRST_WINS = "first_wins"
_CREATE_ITEMS_PREFIX = "CREATE TABLE review_items ("
_COL_REVIEW_ID = "review_id"
_COL_CHECKPOINT_SEQ = "checkpoint_seq"
_COL_PRIORITY_RANK = "priority_rank"
_COL_SUMMARY_TEXT = "summary_text"
_COL_METADATA_JSON = "metadata_json"
_COL_TARGET_ADDR = "target_addr"
_COL_TARGET_INC_ID = "target_incarnation_id"
_COL_ARTIFACT_SHA256 = "artifact_sha256"
_COL_POLICY_DIGEST = "policy_digest"
_COL_REVIEW_PIN = "review_pin_sha256"
_COL_LANE_PAUSED = "lane_paused"
_COL_SOURCE_KIND = "source_kind"
_COL_EXPIRES_AT = "expires_at"

_DEFAULT_ITEM_ROW: dict[str, Any] = {
    _COL_REVIEW_ID: _REV_ID,
    "run_id": _RUN_ID,
    "step_id": _STEP_ID,
    _COL_CHECKPOINT_SEQ: 10,
    "item_revision": 1,
    "status": STATUS_PENDING,
    "severity": "high",
    _COL_PRIORITY_RANK: 80,
    _COL_LANE_PAUSED: 1,
    "requires_human_review": 1,
    _COL_SOURCE_KIND: SOURCE_HOST_WORKFLOW_ENGINE,
    _COL_TARGET_ADDR: None,
    _COL_TARGET_INC_ID: None,
    "title": "PRD Human Review Gate",
    _COL_SUMMARY_TEXT: "Review ready for operator inspection.",
    _COL_ARTIFACT_SHA256: _ART_SHA,
    _COL_POLICY_DIGEST: _POLICY_DIGEST,
    _COL_METADATA_JSON: '{"stage":"review"}',
    "created_at": 1700000000.0,
    "updated_at": 1700000001.0,
    _COL_EXPIRES_AT: None,
}

_ITEM_INSERT_COLS: tuple[str, ...] = (*_DEFAULT_ITEM_ROW.keys(), _COL_REVIEW_PIN)


def _make_private_dir(parent: Path, name: str) -> Path:
    path = parent / name
    path.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _init_inbox_db(
    state_dir: Path, *, initial_seq: int = 1, schema_sql: str = _SCHEMA_SQL
) -> Path:
    db_path = state_dir / DB_FILENAME
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(schema_sql)
        conn.execute(
            "INSERT INTO inbox_seq_counter (id, last_seq) VALUES (1, ?)",
            (initial_seq,),
        )
        conn.execute(
            _SQL_INSERT_RUN,
            (
                _RUN_ID,
                _WORKFLOW_ID,
                _SPEC_DIGEST,
                _POLICY_DIGEST,
                "active",
                "operator",
                1700000000.0,
                1700000001.0,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{db_path}{suffix}")
        if candidate.exists():
            os.chmod(candidate, 0o600)
    return db_path


def _insert_item(
    db_path: Path,
    overrides: Mapping[str, Any] | None = None,
    *,
    override_pin: str | None = None,
    with_primary_artifact: bool = True,
    artifact_id: str = _ART_ID,
    advance_seq: bool = True,
) -> str:
    row = dict(_DEFAULT_ITEM_ROW)
    if overrides:
        row.update(overrides)
    pin = override_pin or compute_review_pin_sha256(
        run_id=row["run_id"],
        step_id=row["step_id"],
        review_id=row[_COL_REVIEW_ID],
        checkpoint_seq=row[_COL_CHECKPOINT_SEQ],
        artifact_sha256=row[_COL_ARTIFACT_SHA256],
        policy_digest=row[_COL_POLICY_DIGEST],
    )
    row[_COL_REVIEW_PIN] = pin
    cols_sql = ", ".join(_ITEM_INSERT_COLS)
    qs_sql = ", ".join("?" for _ in _ITEM_INSERT_COLS)
    vals = tuple(row[col] for col in _ITEM_INSERT_COLS)

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(f"INSERT INTO review_items ({cols_sql}) VALUES ({qs_sql})", vals)
        if with_primary_artifact:
            conn.execute(
                _SQL_INSERT_ART,
                (
                    artifact_id,
                    row[_COL_REVIEW_ID],
                    row[_COL_ARTIFACT_SHA256],
                    256,
                    _MEDIA_PATCH,
                    "Primary patch diff",
                    1,
                    1700000000.0,
                ),
            )
        if advance_seq:
            conn.execute(_SQL_BUMP_SEQ)
        conn.commit()
    finally:
        conn.close()
    return pin


def _exec_write(db_path: Path, sql: str, params: tuple[object, ...] = ()) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


def _snapshot_db_digest(db_path: Path) -> str:
    conn = sqlite3.connect(str(db_path))
    try:
        dump = "\n".join(conn.iterdump())
    finally:
        conn.close()
    return hashlib.sha256(dump.encode("utf-8")).hexdigest()


def _chmod_best_effort(path: Path, mode: int) -> None:
    if path.is_symlink():
        return
    try:
        os.chmod(path, mode)
    except OSError:
        return


def _encode_raw_cursor(raw_json: str) -> str:
    enc = base64.urlsafe_b64encode(raw_json.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{CURSOR_PREFIX}{enc}"


def _cursor_json(fh: str, **fields: Any) -> str:
    payload: dict[str, Any] = {
        "fh": fh,
        "op": OP_INBOX_LIST,
        "pr": 10,
        "rid": "rev-1",
        "seq": 1,
        "ss": 1,
    }
    payload.update(fields)
    return _encode_raw_cursor(json.dumps(payload, separators=(",", ":"), sort_keys=True))


class InboxReadTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.state_dir = _make_private_dir(self.root, "state")
        self.sandbox_root = _make_private_dir(self.root, "sandbox")
        self.db_path = _init_inbox_db(self.state_dir)
        self.svc = HumanInboxReadProjection(
            self.state_dir, sandbox_root=self.sandbox_root
        )

    def tearDown(self) -> None:
        for dirpath, dirnames, filenames in os.walk(self.root):
            _chmod_best_effort(Path(dirpath), 0o700)
            for name in dirnames:
                _chmod_best_effort(Path(dirpath) / name, 0o700)
            for name in filenames:
                _chmod_best_effort(Path(dirpath) / name, 0o600)
        self._tmp.cleanup()


class TestAdmissionAndFencing(InboxReadTestBase):
    """Section 9.1: Operator-only admission, AddressError mapping, and pre/post fencing."""

    def test_non_operator_and_invalid_callers_rejected_before_fs(self) -> None:
        missing_svc = ReadOnlyInboxService(self.root / "does-not-exist")
        bad_principals = (
            PrincipalCtx(role=CoordRole.JOB, actor_id="job:dev", sandbox_addr="dev", incarnation_id="inc-1"),
            PrincipalCtx(role=CoordRole.ORCHESTRATOR, actor_id="orch:root"),
            PrincipalCtx(role=CoordRole.ORCHESTRATOR, actor_id="orch:dev", sandbox_addr="dev", incarnation_id="inc-1"),
            PrincipalCtx(role=CoordRole.EXTERNAL_PEER, actor_id="peer:ext"),
            PrincipalCtx(role=CoordRole.OPERATOR, actor_id="op:bound", sandbox_addr="dev"),
            PrincipalCtx(role=CoordRole.OPERATOR, actor_id="op:inc", incarnation_id="inc-1"),
        )
        for principal in bad_principals:
            with self.assertRaises(CoordAuthError):
                missing_svc.list_inbox_items(principal)
            with self.assertRaises(CoordAuthError):
                missing_svc.get_inbox_item(principal, review_id=_REV_ID)
            with self.assertRaises(CoordAuthError):
                missing_svc.get_inbox_summary(principal)

        with self.assertRaises(CoordValidationError):
            missing_svc.list_inbox_items("not-a-principal")
        with self.assertRaises(CoordValidationError):
            self.svc.list_inbox_items(_OP, statuses=123)  # type: ignore[arg-type]

    def test_address_error_inputs_mapped_to_coord_validation_error(self) -> None:
        bad_tokens: tuple[object, ...] = (123, "bad\x00tok", "bad\u202etok", "bad\x1btok")
        for bad in bad_tokens:
            with self.assertRaises(CoordValidationError):
                self.svc.list_inbox_items(_OP, run_id=bad)  # type: ignore[arg-type]
            with self.assertRaises(CoordValidationError):
                self.svc.get_inbox_item(_OP, review_id=bad)  # type: ignore[arg-type]
            with self.assertRaises(CoordValidationError):
                self.svc.get_inbox_summary(
                    _OP, read_session_id=bad, session_generation=1  # type: ignore[arg-type]
                )

    def test_session_validator_rules_and_echo(self) -> None:
        _insert_item(self.db_path)
        with self.assertRaises(CoordPolicyError):
            self.svc.list_inbox_items(_OP, read_session_id=_SESS_ID, session_generation=1)
        with self.assertRaises(CoordValidationError):
            self.svc.list_inbox_items(_OP, read_session_id=_SESS_ID)
        with self.assertRaises(CoordValidationError):
            self.svc.list_inbox_items(_OP, session_generation=1)

        for bad_gen in (True, 0, -1, MAX_SQLITE_INT64 + 1, "1"):
            with self.assertRaises(CoordValidationError):
                self.svc.list_inbox_items(
                    _OP, read_session_id=_SESS_ID, session_generation=bad_gen  # type: ignore[arg-type]
                )

        gated = ReadOnlyInboxService(
            self.state_dir,
            sandbox_root=self.sandbox_root,
            session_validator=lambda _c, sid, gen: sid == _SESS_ID and gen == 2,
        )
        with self.assertRaises(CoordAuthError):
            gated.list_inbox_items(_OP)

        page = gated.list_inbox_items(_OP, read_session_id=_SESS_ID, session_generation=2)
        detail = gated.get_inbox_item(
            _OP, review_id=_REV_ID, read_session_id=_SESS_ID, session_generation=2
        )
        summary = gated.get_inbox_summary(
            _OP, read_session_id=_SESS_ID, session_generation=2
        )
        for snap in (page, detail, summary):
            self.assertIsNotNone(snap.read_session)
            assert snap.read_session is not None
            self.assertEqual(snap.read_session.read_session_id, _SESS_ID)
            self.assertEqual(snap.read_session.session_generation, 2)

        truthy_svc = ReadOnlyInboxService(
            self.state_dir,
            sandbox_root=self.sandbox_root,
            session_validator=lambda _c, _s, _g: 1,  # type: ignore[return-value]
        )
        with self.assertRaises(RevokedError):
            truthy_svc.list_inbox_items(_OP, read_session_id=_SESS_ID, session_generation=1)

        def _raising_validator(_c: PrincipalCtx, _s: str, _g: int) -> bool:
            raise RuntimeError("boom")

        err_svc = ReadOnlyInboxService(
            self.state_dir,
            sandbox_root=self.sandbox_root,
            session_validator=_raising_validator,
        )
        with self.assertRaises(RevokedError):
            err_svc.get_inbox_summary(_OP, read_session_id=_SESS_ID, session_generation=1)

    def test_mid_read_revocation_returns_zero_data(self) -> None:
        _insert_item(self.db_path)
        sess_calls = [0]

        def _flip_session(_c: PrincipalCtx, _s: str, _g: int) -> bool:
            sess_calls[0] += 1
            return sess_calls[0] == 1

        sess_svc = ReadOnlyInboxService(
            self.state_dir,
            sandbox_root=self.sandbox_root,
            session_validator=_flip_session,
        )
        with self.assertRaises(RevokedError):
            sess_svc.list_inbox_items(_OP, read_session_id=_SESS_ID, session_generation=1)
        self.assertEqual(sess_calls[0], 2)

        auth_calls = [0]

        def _flip_auth(_c: PrincipalCtx) -> bool:
            auth_calls[0] += 1
            return auth_calls[0] == 1

        auth_svc = ReadOnlyInboxService(
            self.state_dir,
            sandbox_root=self.sandbox_root,
            live_authority_checker=_flip_auth,
        )
        with self.assertRaises(RevokedError):
            auth_svc.get_inbox_item(_OP, review_id=_REV_ID)
        self.assertEqual(auth_calls[0], 2)


class TestFilesystemAndSchemaAdmission(InboxReadTestBase):
    """Section 9.2: Verification-only FS admission, trigger/view/vtable/pragma_table_list defense."""

    def test_missing_db_not_created_and_symlink_dotdot_rejected(self) -> None:
        empty_dir = _make_private_dir(self.root, "empty_state")
        empty_svc = ReadOnlyInboxService(empty_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx:
            empty_svc.get_inbox_summary(_OP)
        self.assertIn("inbox_db_missing", str(ctx.exception))
        self.assertFalse((empty_dir / DB_FILENAME).exists())

        sym_rel = self.root / "sym_rel"
        sym_rel.symlink_to(self.state_dir)
        dotdot_path = Path("sym_rel") / ".." / "state"
        orig_cwd = Path.cwd()
        try:
            os.chdir(self.root)
            dotdot_svc = ReadOnlyInboxService(dotdot_path, sandbox_root=self.sandbox_root)
            with self.assertRaises(CoordPolicyError) as ctx2:
                dotdot_svc.get_inbox_summary(_OP)
            self.assertIn("state_dir_symlink_ancestor_rejected", str(ctx2.exception))
        finally:
            os.chdir(orig_cwd)

    def test_unmapped_fs_exceptions_mapped_to_coord_policy_error(self) -> None:
        nul_svc = ReadOnlyInboxService("bad\x00path", sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx:
            nul_svc.get_inbox_summary(_OP)
        self.assertIn(ERR_STATE_DIR_UNREADABLE, str(ctx.exception))

        reg_file = self.root / "not_a_dir"
        reg_file.write_text("x", encoding="utf-8")
        os.chmod(reg_file, 0o600)
        enotdir_svc = ReadOnlyInboxService(reg_file / "child", sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError):
            enotdir_svc.get_inbox_summary(_OP)

        if os.geteuid() != 0:
            locked = _make_private_dir(self.root, "locked_parent")
            child = _make_private_dir(locked, "child")
            os.chmod(locked, 0o000)
            perm_svc = ReadOnlyInboxService(child, sandbox_root=self.sandbox_root)
            with self.assertRaises(CoordPolicyError):
                perm_svc.get_inbox_summary(_OP)

    def test_fifo_hardlink_unsafe_mode_sandbox_and_readonly_dir(self) -> None:
        in_sb = _make_private_dir(self.sandbox_root, "inner_state")
        _init_inbox_db(in_sb)
        sb_svc = ReadOnlyInboxService(in_sb, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError):
            sb_svc.get_inbox_summary(_OP)

        os.chmod(self.db_path, 0o640)
        with self.assertRaises(CoordPolicyError) as ctx:
            self.svc.get_inbox_summary(_OP)
        self.assertIn("unsafe_mode", str(ctx.exception))
        self.assertEqual(stat.S_IMODE(os.stat(self.db_path).st_mode), 0o640)
        os.chmod(self.db_path, 0o600)

        hl = self.state_dir / "db_hardlink"
        os.link(self.db_path, hl)
        with self.assertRaises(CoordPolicyError) as ctx2:
            self.svc.get_inbox_summary(_OP)
        self.assertIn("hardlink_rejected", str(ctx2.exception))
        hl.unlink()

        journal_fifo = Path(f"{self.db_path}-journal")
        os.mkfifo(journal_fifo, 0o600)
        with self.assertRaises(CoordPolicyError) as ctx3:
            self.svc.get_inbox_summary(_OP)
        self.assertIn("not_regular", str(ctx3.exception))
        journal_fifo.unlink()

        if os.geteuid() != 0:
            ro_dir = _make_private_dir(self.root, "ro_state")
            ro_db = _init_inbox_db(ro_dir)
            for sfx in ("-shm", "-wal"):
                p = Path(f"{ro_db}{sfx}")
                if p.exists():
                    p.unlink()
            os.chmod(ro_dir, 0o500)
            ro_svc = ReadOnlyInboxService(ro_dir, sandbox_root=self.sandbox_root)
            with self.assertRaises(CoordPolicyError):
                ro_svc.get_inbox_summary(_OP)

    def test_hostile_view_trigger_virtual_table_and_pragma_table_list_collision(self) -> None:
        _insert_item(self.db_path)
        _exec_write(self.db_path, "CREATE TABLE pragma_table_list (x INTEGER)")
        summary = self.svc.get_inbox_summary(_OP)
        self.assertEqual(summary.total_items, 1)

        with open_readonly_inbox_snapshot(
            self.db_path, deadline=time.monotonic() + 5.0
        ) as conn:
            ts = conn.execute("PRAGMA trusted_schema").fetchone()
            csc = conn.execute("PRAGMA cell_size_check").fetchone()
            self.assertEqual(next(iter(ts.values())), 0)
            self.assertEqual(next(iter(csc.values())), 1)

        v_dir = _make_private_dir(self.root, "view_state")
        v_db = _init_inbox_db(v_dir)
        _exec_write(v_db, "DROP TABLE inbox_seq_counter")
        _exec_write(
            v_db,
            "CREATE VIEW inbox_seq_counter AS SELECT 1 AS id, 99 AS last_seq",
        )
        v_svc = ReadOnlyInboxService(v_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_v:
            v_svc.get_inbox_summary(_OP)
        self.assertIn(ERR_INBOX_UNREADABLE, str(ctx_v.exception))

        t_dir = _make_private_dir(self.root, "trig_state")
        t_db = _init_inbox_db(t_dir)
        _exec_write(
            t_db,
            "CREATE TRIGGER evil_trig AFTER INSERT ON review_items BEGIN SELECT 1; END",
        )
        t_svc = ReadOnlyInboxService(t_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_t:
            t_svc.get_inbox_summary(_OP)
        self.assertIn(ERR_INBOX_UNREADABLE, str(ctx_t.exception))

        vt_dir = _make_private_dir(self.root, "vtab_state")
        vt_db = _init_inbox_db(vt_dir)
        _exec_write(vt_db, "CREATE VIRTUAL TABLE evil_vt USING fts5(content)")
        vt_svc = ReadOnlyInboxService(vt_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_vt:
            vt_svc.get_inbox_summary(_OP)
        self.assertIn(ERR_INBOX_UNREADABLE, str(ctx_vt.exception))

        mt_dir = _make_private_dir(self.root, "missing_tbl_state")
        mt_db = _init_inbox_db(mt_dir)
        _exec_write(mt_db, "DROP TABLE workflow_runs")
        mt_svc = ReadOnlyInboxService(mt_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_mt:
            mt_svc.get_inbox_summary(_OP)
        self.assertIn(ERR_INBOX_UNREADABLE, str(ctx_mt.exception))

        # Missing integer id=1 row in inbox_seq_counter fails closed
        nc_dir = _make_private_dir(self.root, "no_counter_state")
        nc_db = _init_inbox_db(nc_dir)
        _exec_write(nc_db, _SQL_CLEAR_SEQ)
        nc_svc = ReadOnlyInboxService(nc_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_nc:
            nc_svc.get_inbox_summary(_OP)
        self.assertIn(ERR_INBOX_UNREADABLE, str(ctx_nc.exception))


class TestPinsArtifactsAndExclusivity(InboxReadTestBase):
    """Section 9.3: Review pins, orchestrator_advisory vs lane_paused, artifacts, IDs."""

    def test_valid_pending_and_non_pending_statuses_and_canonical_targets(self) -> None:
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-nulls", _COL_TARGET_ADDR: None, _COL_TARGET_INC_ID: None, _COL_EXPIRES_AT: None},
            artifact_id="art-nulls",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_REMOTE, _COL_TARGET_ADDR: _ADDR_REMOTE, _COL_TARGET_INC_ID: "inc-01"},
            artifact_id="art-remote",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-peer", _COL_TARGET_ADDR: "@peer-1", "status": STATUS_RESOLVED},
            artifact_id="art-peer",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-exp", "status": STATUS_EXPIRED},
            artifact_id="art-exp",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-sup", "status": STATUS_SUPERSEDED},
            artifact_id="art-sup",
        )

        page = self.svc.list_inbox_items(_OP)
        by_id = {it.review_id: it for it in page.items}
        self.assertTrue(by_id["rev-nulls"].pin_verified)
        self.assertFalse(by_id["rev-nulls"].malformed_metadata)
        self.assertTrue(by_id["rev-nulls"].review_ready)
        self.assertEqual(by_id[_REV_REMOTE].identity.target_addr, _ADDR_REMOTE)
        self.assertEqual(by_id[_REV_REMOTE].workflow_id, _WORKFLOW_ID)
        for non_pending in ("rev-peer", "rev-exp", "rev-sup"):
            self.assertTrue(by_id[non_pending].pin_verified)
            self.assertFalse(by_id[non_pending].review_ready)

        filtered = self.svc.list_inbox_items(
            _OP, statuses=(STATUS_RESOLVED,), run_id=_RUN_ID
        )
        self.assertEqual([it.review_id for it in filtered.items], ["rev-peer"])
        with self.assertRaises(CoordPolicyError) as ctx_nf:
            self.svc.get_inbox_item(_OP, review_id="rev-does-not-exist")
        self.assertIn(_ERR_ITEM_NOT_FOUND, str(ctx_nf.exception))

    def test_orchestrator_advisory_with_lane_paused_contradiction_all_3_apis(self) -> None:
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_ADV_PAUSED, _COL_SOURCE_KIND: SOURCE_ORCHESTRATOR_ADVISORY, _COL_LANE_PAUSED: 1},
            artifact_id="art-adv-paused",
        )
        page = self.svc.list_inbox_items(_OP)
        self.assertEqual(len(page.items), 1)
        item_list = page.items[0]
        detail = self.svc.get_inbox_item(_OP, review_id=_REV_ADV_PAUSED)
        summary = self.svc.get_inbox_summary(_OP)

        for it in (item_list, detail.item):
            self.assertFalse(it.lane_paused)
            self.assertTrue(it.malformed_metadata)
            self.assertFalse(it.pin_verified)
            self.assertTrue(it.pin_anomaly)
            self.assertEqual(it.anomaly_reason, ANOMALY_MALFORMED_METADATA)
            self.assertFalse(it.review_ready)

        self.assertEqual(summary.paused_lanes_count, 0)
        self.assertEqual(summary.malformed_rows_count, 1)

    def test_pin_and_cross_table_tampering_modes(self) -> None:
        good_pin = compute_review_pin_sha256(
            run_id=_RUN_ID,
            step_id=_STEP_ID,
            review_id=_REV_BADPIN,
            checkpoint_seq=1,
            artifact_sha256=_ART_SHA,
            policy_digest=_POLICY_DIGEST,
        )
        flipped = ("0" if good_pin[0] != "0" else "1") + good_pin[1:]
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_BADPIN, _COL_CHECKPOINT_SEQ: 1},
            override_pin=flipped,
            artifact_id="art-badpin",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-norun", "run_id": "run-missing", _COL_CHECKPOINT_SEQ: 2},
            artifact_id="art-norun",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_BADPOL, _COL_CHECKPOINT_SEQ: 3, _COL_POLICY_DIGEST: "9" * 64},
            artifact_id="art-badpol",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-noart", _COL_CHECKPOINT_SEQ: 4},
            with_primary_artifact=False,
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_DUP_ART, _COL_CHECKPOINT_SEQ: 5},
            artifact_id="art-dup-1",
        )
        _exec_write(
            self.db_path,
            _SQL_INSERT_ART,
            ("art-dup-2", _REV_DUP_ART, _ART_SHA, 128, _MEDIA_PATCH, "Dup", 1, 1700000000.0),
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_ART_MIS, _COL_CHECKPOINT_SEQ: 6},
            with_primary_artifact=False,
        )
        _exec_write(
            self.db_path,
            _SQL_INSERT_ART,
            ("art-mis-1", _REV_ART_MIS, _ART_SHA_ALT, 128, _MEDIA_PATCH, "Wrong", 1, 1700000000.0),
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_BLOBSEQ, _COL_CHECKPOINT_SEQ: 7},
            artifact_id="art-blobseq",
        )
        _exec_write(
            self.db_path,
            "UPDATE review_items SET checkpoint_seq = ? WHERE review_id = ?",
            (b"X" * 64, _REV_BLOBSEQ),
        )

        expected = {
            _REV_BADPIN: ANOMALY_PIN_MISMATCH,
            "rev-norun": ANOMALY_RUN_MISSING,
            _REV_BADPOL: ANOMALY_POLICY_MISMATCH,
            "rev-noart": ANOMALY_ARTIFACT_MISSING,
            _REV_DUP_ART: ANOMALY_ARTIFACT_AMBIGUOUS,
            _REV_ART_MIS: ANOMALY_ARTIFACT_MISMATCH,
            _REV_BLOBSEQ: ANOMALY_TAMPERED_STORAGE,
        }
        page = self.svc.list_inbox_items(_OP)
        by_id = {it.review_id: it for it in page.items}
        for rid, reason in expected.items():
            it = by_id[rid]
            self.assertFalse(it.pin_verified, rid)
            self.assertTrue(it.pin_anomaly, rid)
            self.assertEqual(it.anomaly_reason, reason, rid)
            self.assertFalse(it.review_ready, rid)
        # P2-2: pin-column storage-class tampering folds into state.malformed_metadata
        self.assertTrue(by_id[_REV_BLOBSEQ].malformed_metadata)

    def test_secondary_artifact_degradation_and_malformed_primary_artifact_flag(self) -> None:
        _insert_item(self.db_path, {_COL_REVIEW_ID: "rev-sec"}, artifact_id="art-sec-prim")
        _exec_write(
            self.db_path,
            _SQL_INSERT_ART,
            ("bad id!", "rev-sec", "not-hex", -5, "bad media", b"\xff\xfe", 0, float("inf")),
        )
        detail = self.svc.get_inbox_item(_OP, review_id="rev-sec")
        self.assertTrue(detail.item.pin_verified)
        self.assertTrue(detail.artifacts_malformed)
        sec = [a for a in detail.artifact_refs if not a.is_primary][0]
        self.assertTrue(sec.malformed_metadata)
        self.assertIsNone(sec.artifact_id)
        self.assertIsNone(sec.blob_sha256)
        self.assertEqual(sec.size_bytes, 0)
        self.assertAlmostEqual(sec.created_at, 0.0)
        self.assertIn("artifacts_malformed", serialize_inbox_json(detail))

        _exec_write(
            self.db_path,
            "UPDATE review_artifacts SET is_primary = 2 WHERE artifact_id = 'bad id!'",
        )
        detail2 = self.svc.get_inbox_item(_OP, review_id="rev-sec")
        page2 = self.svc.list_inbox_items(_OP)
        self.assertEqual(detail2.item.anomaly_reason, ANOMALY_TAMPERED_STORAGE)
        self.assertEqual(page2.items[0].anomaly_reason, ANOMALY_TAMPERED_STORAGE)


class TestStorageClassesSummaryAndJsonSafety(InboxReadTestBase):
    """Section 9.4: Empty summary COALESCE, REAL 1.0 flags, 2 MiB BLOBs, Inf/1e400, OverflowError."""

    def test_empty_summary_and_real_flag_and_null_nullable_columns(self) -> None:
        empty_sum = self.svc.get_inbox_summary(_OP)
        self.assertEqual(empty_sum.total_items, 0)
        self.assertEqual(empty_sum.paused_lanes_count, 0)
        self.assertEqual(empty_sum.requires_human_review_count, 0)
        self.assertEqual(empty_sum.malformed_rows_count, 0)
        self.assertEqual(empty_sum.pin_verification_scope, PIN_VERIFICATION_SCOPE_ITEM_ONLY)

        _insert_item(self.db_path, {_COL_REVIEW_ID: "rev-clean"}, artifact_id="art-clean")
        clean_sum = self.svc.get_inbox_summary(_OP)
        self.assertEqual(clean_sum.paused_lanes_count, 1)
        self.assertEqual(clean_sum.malformed_rows_count, 0)

        r_dir = _make_private_dir(self.root, "real_flag_state")
        r_db = _init_inbox_db(r_dir)
        _exec_write(r_db, "DROP TABLE review_items")
        _exec_write(
            r_db,
            _SCHEMA_SQL.split(_CREATE_ITEMS_PREFIX)[1]
            .split(");")[0]
            .replace("lane_paused           INTEGER NOT NULL,", "lane_paused           REAL NOT NULL,")
            .replace("requires_human_review INTEGER NOT NULL,", "requires_human_review REAL NOT NULL,")
            .join((_CREATE_ITEMS_PREFIX, ");")),
        )
        _insert_item(r_db, {_COL_REVIEW_ID: "rev-realflag"}, artifact_id="art-realflag")
        r_svc = ReadOnlyInboxService(r_dir, sandbox_root=self.sandbox_root)
        real_sum = r_svc.get_inbox_summary(_OP)
        self.assertEqual(real_sum.paused_lanes_count, 0)
        self.assertEqual(real_sum.requires_human_review_count, 0)
        self.assertEqual(real_sum.malformed_rows_count, 1)

        # P3-1: OverflowError defense on giant Python int -> float conversion
        f_val, f_bad = _safe_finite_float(10**400, False)
        self.assertAlmostEqual(f_val, 0.0)
        self.assertTrue(f_bad)
        nf_val, nf_bad = _safe_nullable_finite_float(10**400, False)
        self.assertIsNone(nf_val)
        self.assertTrue(nf_bad)

    def test_oversize_blobs_inf_1e400_and_deep_json_recursion(self) -> None:
        big_blob = b"B" * (2 * 1024 * 1024)
        _insert_item(self.db_path, {_COL_REVIEW_ID: "rev-blob"}, artifact_id="art-blob")
        _exec_write(
            self.db_path,
            "UPDATE review_items SET created_at = ?, lane_paused = ?, metadata_json = ? "
            "WHERE review_id = 'rev-blob'",
            (big_blob, big_blob, big_blob),
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-1e400", _COL_METADATA_JSON: '{"overflow": 1e400}'},
            artifact_id="art-1e400",
        )
        deep_json = "[" * 2000 + "1" + "]" * 2000
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-deep", _COL_METADATA_JSON: deep_json},
            artifact_id="art-deep",
        )
        _insert_item(self.db_path, {_COL_REVIEW_ID: "rev-inf"}, artifact_id="art-inf")
        _exec_write(
            self.db_path,
            "UPDATE review_items SET updated_at = 9e999, status = 'bogus', severity = 'mega' "
            "WHERE review_id = 'rev-inf'",
        )

        page = self.svc.list_inbox_items(_OP)
        by_id = {it.review_id: it for it in page.items}
        for rid in ("rev-blob", "rev-1e400", "rev-deep", "rev-inf"):
            self.assertTrue(by_id[rid].malformed_metadata, rid)
            self.assertFalse(by_id[rid].pin_verified, rid)
            self.assertFalse(by_id[rid].review_ready, rid)
        self.assertEqual(dict(by_id["rev-1e400"].metadata), {})
        detail_1e400 = self.svc.get_inbox_item(_OP, review_id="rev-1e400")
        self.assertEqual(dict(detail_1e400.item.metadata), {})
        self.assertTrue(detail_1e400.item.malformed_metadata)
        self.assertFalse(detail_1e400.item.pin_verified)
        self.assertEqual(by_id["rev-inf"].status, BUCKET_MALFORMED)
        self.assertEqual(by_id["rev-inf"].severity, BUCKET_MALFORMED)

        raw_json = serialize_inbox_json(page)
        self.assertNotIn("NaN", raw_json)
        self.assertNotIn("Infinity", raw_json)
        summary = self.svc.get_inbox_summary(_OP)
        self.assertEqual(summary.counts_by_status[BUCKET_MALFORMED], 1)
        self.assertEqual(summary.counts_by_severity[BUCKET_MALFORMED], 1)
        self.assertEqual(summary.malformed_rows_count, 2)


class TestScrubbingRedactionAndCredentialIds(InboxReadTestBase):
    """Section 9.5: Stage-1 ANSI/C1/BiDi/NUL/split scrubbing & Stage-2 redaction + credential IDs."""

    def test_stage1_escapes_c1_bidi_nul_and_split_boundaries(self) -> None:
        hostile_summary = (
            "line1\n\tindented\x1b[31mRED\x1b]0;title\x9csafe1"
            "\x1bPdata\x9csafe2\x1b(B\x1b7\x1b8\x1bc"
            "\x9b31mC1\x9d0;t\x9c\x90dcs\x9c\x9fapc\x9c"
            "a\x00b\u202erev\u2066iso\rEND"
        )
        _insert_item(
            self.db_path,
            {
                _COL_REVIEW_ID: "rev-esc",
                "title": "Title\x1b[31m\u202e\x00Clean",
                _COL_SUMMARY_TEXT: hostile_summary,
            },
            artifact_id="art-esc",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_CLEAN_ML, _COL_SUMMARY_TEXT: "line1\r\n\tline2\nline3"},
            artifact_id="art-clean-ml",
        )
        prefix_pad = "a" * (MAX_ITEM_TEXT_BYTES - 2)
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_SPLIT_UTF8, _COL_SUMMARY_TEXT: prefix_pad + "\U0001f680tail"},
            artifact_id="art-split-utf8",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: _REV_SPLIT_ESC, _COL_SUMMARY_TEXT: prefix_pad + "\x1b[31mRED"},
            artifact_id="art-split-esc",
        )

        page = self.svc.list_inbox_items(_OP)
        by_id = {it.review_id: it for it in page.items}
        esc_item = by_id["rev-esc"]
        self.assertTrue(esc_item.has_control_or_bidi)
        self.assertIn("safe1", esc_item.summary_text)
        self.assertIn("safe2", esc_item.summary_text)
        self.assertIn("line1\n\tindented", esc_item.summary_text)
        for forbidden in ("\x1b", "\x9b", "\x9d", "\x90", "\x9f", "\x00", "\u202e", "\u2066", "\r"):
            self.assertNotIn(forbidden, esc_item.summary_text)
            self.assertNotIn(forbidden, esc_item.title)

        self.assertFalse(by_id[_REV_CLEAN_ML].has_control_or_bidi)
        self.assertTrue(by_id[_REV_SPLIT_UTF8].text_suffix_uninspected)
        self.assertFalse(by_id[_REV_SPLIT_UTF8].malformed_metadata)
        self.assertTrue(by_id[_REV_SPLIT_ESC].text_suffix_uninspected)
        self.assertTrue(by_id[_REV_SPLIT_ESC].has_control_or_bidi)
        self.assertNotIn("\x1b", by_id[_REV_SPLIT_ESC].summary_text)

    def test_stage2_secret_redaction_bypasses_metadata_keys_and_collisions(self) -> None:
        _exec_write(self.db_path, "ALTER TABLE review_items ADD COLUMN env_vars TEXT")
        _exec_write(self.db_path, "ALTER TABLE review_items ADD COLUMN auth_header TEXT")

        # Dynamically assemble synthetic test secrets so static scanners do not false-positive
        db_sec = "".join(("myDb", "Secret", "123"))
        aws_sec = "".join(("awsKey", "Secret", "456"))
        gh_sec = "".join(("ghp_", "abc12345", "67890"))
        json_sec = "".join(("json", "Secret", "Value"))
        url_sec = "".join(("url", "Secret", "99"))
        url_auth_line = "".join(("https://", "alice", ":", url_sec, "@example.com/path"))
        digest_sec = "".join(("deadbeef", "DigestHash", "999"))
        cookie_sec = "".join(("MySecret", "Session", "99999"))
        setcookie_sec = "".join(("MySecret", "Cookie", "99999"))
        cred_sec = "".join(("cred", "Secret", "3"))
        awk_sec = "".join(("awkHash", "Secret", "4"))
        pem_sec = "".join(("MIIE_", "PRIV_", "SECRET"))
        bear_sec = "".join(("bear", "Secret", "777"))

        summary_with_secrets = (
            f"DB_PASSWORD={db_sec} "
            f"AWS_ACCESS_KEY={aws_sec} "
            f"GITHUB_TOKEN={gh_sec} "
            f'{{"password": "{json_sec}", "Authorization": "CustomScheme {bear_sec}", "keep": "visible"}} '
            f"{url_auth_line} "
            f'Authorization: Digest username="alice", realm="prod", response="{digest_sec}"\n'
            f'Cookie: theme="dark"; sid={cookie_sec}\n'
            f'Set-Cookie: pref="x"; auth={setcookie_sec}; HttpOnly\n'
            f"credential={cred_sec} awakeable_token_hash={awk_sec} "
            f"-----BEGIN RSA PRIVATE KEY-----\n{pem_sec}\n-----END RSA PRIVATE KEY-----"
        )
        padded_sensitive_key = ("p" * 280) + "_password"
        collide_a = ("k" * 64) + "_1"
        collide_b = ("k" * 64) + "_2"
        meta = {
            "safe_note": "ok",
            "private-key": "drop1",
            "accessKey": "drop2",
            "nested": {"auth-header": "drop3", "inner": f"Bearer {bear_sec}"},
            padded_sensitive_key: "drop4",
            _CANARY_KEY_SECRET: "drop5",
            collide_a: _VAL_FIRST_WINS,
            collide_b: "second_dropped",
        }
        _insert_item(
            self.db_path,
            {
                _COL_REVIEW_ID: _REV_SEC_RED,
                _COL_SUMMARY_TEXT: summary_with_secrets,
                _COL_METADATA_JSON: json.dumps(meta),
            },
            artifact_id="art-sec-red",
        )
        _exec_write(
            self.db_path,
            "UPDATE review_items SET env_vars = 'ENV_SECRET_UNSELECTED', "
            "auth_header = 'AUTH_HDR_UNSELECTED' WHERE review_id = ?",
            (_REV_SEC_RED,),
        )
        eof_q_sec = "".join(("EofQuoted", "Secret", "Value"))
        _insert_item(
            self.db_path,
            {
                _COL_REVIEW_ID: "rev-eof-q",
                _COL_SUMMARY_TEXT: (
                    "x" * (MAX_ITEM_TEXT_BYTES - 30)
                    + f'password="{eof_q_sec}999999999999999'
                ),
            },
            artifact_id="art-eof-q",
        )
        jwt_hdr = "eyJhbGciOiJIUzI1NiJ9"
        _insert_item(
            self.db_path,
            {
                _COL_REVIEW_ID: "rev-eof-jwt",
                _COL_SUMMARY_TEXT: (
                    "y" * (MAX_ITEM_TEXT_BYTES - 48)
                    + f"{jwt_hdr}.eyJzdWIiOiIxMjM0NTY3OCJ9.TruncSig9999999"
                ),
            },
            artifact_id="art-eof-jwt",
        )

        page = self.svc.list_inbox_items(_OP)
        serialized = serialize_inbox_json(page)
        leaked_tokens = (
            db_sec,
            aws_sec,
            gh_sec,
            json_sec,
            url_sec,
            digest_sec,
            cookie_sec,
            setcookie_sec,
            cred_sec,
            awk_sec,
            pem_sec,
            bear_sec,
            _CANARY_KEY_SECRET,
            "ENV_SECRET_UNSELECTED",
            "AUTH_HDR_UNSELECTED",
            eof_q_sec,
            jwt_hdr,
            "drop1",
            "drop2",
            "drop3",
            "drop4",
            "drop5",
        )
        for secret in leaked_tokens:
            self.assertNotIn(secret, serialized)

        by_id = {it.review_id: it for it in page.items}
        item = by_id[_REV_SEC_RED]
        self.assertTrue(item.redaction_applied)
        self.assertTrue(item.untrusted_content)
        self.assertTrue(item.malformed_metadata)
        self.assertEqual(item.metadata["k" * 64], _VAL_FIRST_WINS)
        self.assertIn("visible", item.summary_text)

    def test_credential_shaped_identifiers_rejected_with_zero_echo(self) -> None:
        d1 = _make_private_dir(self.root, "cred_rid")
        db1 = _init_inbox_db(d1)
        _insert_item(db1, {_COL_REVIEW_ID: _CANARY_REVIEW_ID}, artifact_id="art-c1")
        svc1 = ReadOnlyInboxService(d1, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx1:
            svc1.list_inbox_items(_OP)
        self.assertEqual(str(ctx1.exception), ERR_INBOX_UNREADABLE)
        self.assertNotIn(_CANARY_REVIEW_ID, str(ctx1.exception))

        d2 = _make_private_dir(self.root, "cred_run")
        db2 = _init_inbox_db(d2)
        _insert_item(db2, {_COL_REVIEW_ID: "rev-c2", "run_id": _CANARY_RUN_ID}, artifact_id="art-c2")
        svc2 = ReadOnlyInboxService(d2, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx2:
            svc2.list_inbox_items(_OP)
        self.assertEqual(str(ctx2.exception), ERR_INBOX_UNREADABLE)
        self.assertNotIn(_CANARY_RUN_ID, str(ctx2.exception))

        d3 = _make_private_dir(self.root, "cred_art")
        db3 = _init_inbox_db(d3)
        _insert_item(db3, {_COL_REVIEW_ID: "rev-c3"}, artifact_id=_CANARY_ART_ID)
        svc3 = ReadOnlyInboxService(d3, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx3:
            svc3.get_inbox_item(_OP, review_id="rev-c3")
        self.assertEqual(str(ctx3.exception), ERR_INBOX_UNREADABLE)
        self.assertNotIn(_CANARY_ART_ID, str(ctx3.exception))

        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-c4", _COL_TARGET_INC_ID: _CANARY_INC_ID},
            artifact_id="art-c4",
        )
        detail = self.svc.get_inbox_item(_OP, review_id="rev-c4")
        self.assertIsNone(detail.item.identity.target_incarnation_id)
        self.assertTrue(detail.item.redaction_applied)
        self.assertTrue(detail.item.malformed_metadata)
        self.assertFalse(detail.item.pin_verified)
        self.assertFalse(detail.item.review_ready)
        self.assertNotIn(_CANARY_INC_ID, serialize_inbox_json(detail))


class TestBudgetsCursorsAndDeadlines(InboxReadTestBase):
    """Section 9.6 & 9.7: 2048 B budgets, metadata-drop retry, cursors, BLOB-PK continuation, deadlines."""

    def test_2048_byte_budget_next_cursor_accounting_and_metadata_drop_retry(self) -> None:
        escape_heavy = '"\\\n\U0001f680' * 300
        large_meta = json.dumps({f"field_{i:02d}": "v" * 48 for i in range(16)})
        _insert_item(
            self.db_path,
            {
                _COL_REVIEW_ID: "rev-b1",
                _COL_PRIORITY_RANK: 90,
                _COL_SUMMARY_TEXT: escape_heavy,
                _COL_METADATA_JSON: large_meta,
            },
            artifact_id="art-b1",
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-b2", _COL_PRIORITY_RANK: 80, _COL_SUMMARY_TEXT: "second item"},
            artifact_id="art-b2",
        )

        page = self.svc.list_inbox_items(_OP, max_response_bytes=MIN_RESPONSE_BYTES)
        self.assertEqual(len(page.items), 1)
        self.assertTrue(page.has_more)
        self.assertIsNotNone(page.next_cursor)
        self.assertTrue(page.items[0].metadata_truncated)
        self.assertEqual(dict(page.items[0].metadata), {})
        self.assertTrue(page.items[0].summary_text)
        self.assertTrue(page.items[0].text_truncated)
        self.assertLessEqual(len(serialize_inbox_bytes(page)), MIN_RESPONSE_BYTES)

        for a_idx in range(6):
            _exec_write(
                self.db_path,
                _SQL_INSERT_ART,
                (
                    f"art-extra-{a_idx}",
                    "rev-b1",
                    _ART_SHA_ALT,
                    512,
                    _MEDIA_PATCH,
                    f"Secondary diff {a_idx}",
                    0,
                    1700000000.0,
                ),
            )
        detail = self.svc.get_inbox_item(
            _OP, review_id="rev-b1", max_response_bytes=MIN_RESPONSE_BYTES
        )
        self.assertTrue(detail.artifact_refs_truncated)
        self.assertLessEqual(len(serialize_inbox_bytes(detail)), MIN_RESPONSE_BYTES)
        summary = self.svc.get_inbox_summary(_OP, max_response_bytes=MIN_RESPONSE_BYTES)
        self.assertLessEqual(len(serialize_inbox_bytes(summary)), MIN_RESPONSE_BYTES)

        with self.assertRaises(CoordValidationError):
            self.svc.list_inbox_items(_OP, max_response_bytes=MIN_RESPONSE_BYTES - 1)
        with self.assertRaises(CoordValidationError):
            self.svc.get_inbox_summary(_OP, max_response_bytes=MIN_RESPONSE_BYTES - 1)

    def test_int64_pagination_snapshot_change_rollback_and_blob_pk_continuation(self) -> None:
        seeds = (
            {_COL_REVIEW_ID: _REV_HIGH_0, _COL_PRIORITY_RANK: 90, _COL_CHECKPOINT_SEQ: 0},
            {_COL_REVIEW_ID: _REV_HIGH_MAX, _COL_PRIORITY_RANK: 90, _COL_CHECKPOINT_SEQ: MAX_SQLITE_INT64},
            {_COL_REVIEW_ID: "rev:low:1", _COL_PRIORITY_RANK: 10, _COL_CHECKPOINT_SEQ: 1},
        )
        for idx, seed in enumerate(seeds):
            _insert_item(self.db_path, seed, artifact_id=f"art-p-{idx}")

        seen: list[str] = []
        cursor: str | None = None
        while True:
            page = self.svc.list_inbox_items(_OP, limit=1, after_cursor=cursor)
            seen.extend(it.review_id for it in page.items)
            if not page.has_more:
                break
            cursor = page.next_cursor
        self.assertEqual(seen, [_REV_HIGH_0, _REV_HIGH_MAX, "rev:low:1"])

        p1 = self.svc.list_inbox_items(_OP, limit=1)
        assert p1.next_cursor is not None
        rb_conn = sqlite3.connect(str(self.db_path))
        try:
            rb_conn.execute("BEGIN")
            rb_conn.execute("UPDATE review_items SET priority_rank = 5 WHERE review_id = 'rev:low:1'")
            rb_conn.execute(_SQL_BUMP_SEQ)
            rb_conn.execute("ROLLBACK")
        finally:
            rb_conn.close()
        p2_ok = self.svc.list_inbox_items(_OP, limit=1, after_cursor=p1.next_cursor)
        self.assertEqual(p2_ok.items[0].review_id, _REV_HIGH_MAX)

        w_conn = sqlite3.connect(str(self.db_path))
        try:
            w_conn.execute("BEGIN")
            w_conn.execute("UPDATE workflow_runs SET updated_at = updated_at + 1 WHERE run_id = ?", (_RUN_ID,))
            w_conn.execute(_SQL_BUMP_SEQ)
            w_conn.commit()
        finally:
            w_conn.close()
        with self.assertRaises(CoordValidationError) as ctx_snap:
            self.svc.list_inbox_items(_OP, limit=1, after_cursor=p1.next_cursor)
        self.assertIn(ERR_CURSOR_SNAPSHOT_CHANGED, str(ctx_snap.exception))

        b_dir = _make_private_dir(self.root, "blob_pk_state")
        b_db = _init_inbox_db(b_dir)
        _insert_item(
            b_db,
            {_COL_REVIEW_ID: _REV_TIE_TEXT, _COL_PRIORITY_RANK: 0, _COL_CHECKPOINT_SEQ: MAX_SQLITE_INT64},
            artifact_id="art-tie-1",
        )
        _insert_item(
            b_db,
            {_COL_REVIEW_ID: "rev-tie-placeholder", _COL_PRIORITY_RANK: 0, _COL_CHECKPOINT_SEQ: MAX_SQLITE_INT64},
            artifact_id="art-tie-2",
        )
        _exec_write(
            b_db,
            "UPDATE review_items SET review_id = ? WHERE review_id = 'rev-tie-placeholder'",
            (b"\xde\xad\xbe\xef",),
        )
        b_svc = ReadOnlyInboxService(b_dir, sandbox_root=self.sandbox_root)
        bp1 = b_svc.list_inbox_items(_OP, limit=1)
        self.assertEqual(bp1.items[0].review_id, _REV_TIE_TEXT)
        self.assertTrue(bp1.has_more)
        assert bp1.next_cursor is not None
        with self.assertRaises(CoordPolicyError) as ctx_bp2:
            b_svc.list_inbox_items(_OP, limit=1, after_cursor=bp1.next_cursor)
        self.assertIn(ERR_INBOX_UNREADABLE, str(ctx_bp2.exception))

    def test_forged_and_cross_scope_cursors_rejected(self) -> None:
        fh = compute_scope_hash(OP_INBOX_LIST, statuses=None, run_id=None)
        good_cur = encode_inbox_list_cursor(
            scope_hash=fh,
            snapshot_seq=1,
            priority_rank=50,
            checkpoint_seq=1,
            review_id=_REV_ID,
        )
        with self.assertRaises(CoordValidationError) as ctx_sc:
            self.svc.list_inbox_items(_OP, statuses=(STATUS_PENDING,), after_cursor=good_cur)
        self.assertIn(ERR_CURSOR_SCOPE_MISMATCH, str(ctx_sc.exception))

        bad_cursors = (
            good_cur + "=",
            "v2.abc",
            _cursor_json(fh, seq=MAX_SQLITE_INT64 + 1),
            _cursor_json(fh, ss=MAX_SQLITE_INT64 + 1),
            _cursor_json(fh, pr=101),
            _cursor_json(fh, seq=True),
            _cursor_json(fh, rid=_CANARY_REVIEW_ID),
            _encode_raw_cursor('{"x":1e400}'),
            _encode_raw_cursor('{"x":NaN}'),
            _encode_raw_cursor("[" * 300 + "1" + "]" * 300),
        )
        for bad in bad_cursors:
            with self.assertRaises(CoordValidationError) as ctx_m:
                self.svc.list_inbox_items(_OP, after_cursor=bad)
            self.assertIn(ERR_CURSOR_MALFORMED, str(ctx_m.exception))

    def test_deadlines_umask_lock_uri_error_and_zero_mutation_authority(self) -> None:
        _insert_item(self.db_path)
        before_digest = _snapshot_db_digest(self.db_path)

        lk_dir = _make_private_dir(self.root, "lock_state")
        lk_db = _init_inbox_db(lk_dir)
        _insert_item(lk_db)
        _exec_write(lk_db, "PRAGMA journal_mode = DELETE")
        os.chmod(lk_db, 0o600)
        lk_svc = ReadOnlyInboxService(lk_dir, sandbox_root=self.sandbox_root)
        lock_conn = sqlite3.connect(str(lk_db), isolation_level=None)
        try:
            lock_conn.execute("BEGIN EXCLUSIVE")
            with self.assertRaises(CoordPolicyError) as ctx_lk:
                lk_svc.list_inbox_items(_OP, max_read_ms=50)
            self.assertIn(ERR_READ_DEADLINE, str(ctx_lk.exception))
        finally:
            lock_conn.execute("ROLLBACK")
            lock_conn.close()

        acquired = threading.Event()
        release = threading.Event()

        def _hold_lock() -> None:
            _UMASK_LOCK.acquire()
            acquired.set()
            release.wait(timeout=2.0)
            _UMASK_LOCK.release()

        holder = threading.Thread(target=_hold_lock)
        holder.start()
        acquired.wait(timeout=1.0)
        try:
            with (
                mock.patch("oc_inbox_db.sqlite3.connect") as mock_conn,
                self.assertRaises(CoordPolicyError) as ctx_ul,
            ):
                self.svc.get_inbox_summary(_OP, max_read_ms=50)
            self.assertIn(ERR_READ_DEADLINE, str(ctx_ul.exception))
            self.assertEqual(mock_conn.call_count, 0)
        finally:
            release.set()
            holder.join(timeout=2.0)

        def _bad_quote(*_args: object, **_kwargs: object) -> str:
            raise UnicodeEncodeError("utf-8", "\udcc0", 0, 1, "surrogate")

        with (
            mock.patch("oc_inbox_db.quote", side_effect=_bad_quote),
            self.assertRaises(CoordPolicyError) as ctx_uri,
        ):
            self.svc.get_inbox_summary(_OP)
        self.assertIn(ERR_INBOX_UNREADABLE, str(ctx_uri.exception))
        self.assertTrue(_UMASK_LOCK.acquire(timeout=0.1))
        _UMASK_LOCK.release()

        with (
            open_readonly_inbox_snapshot(
                self.db_path, deadline=time.monotonic() + 5.0
            ) as ro_conn,
            self.assertRaises(sqlite3.OperationalError),
        ):
            ro_conn.execute("DELETE FROM review_items")
        with self.assertRaises(sqlite3.ProgrammingError):
            ro_conn.execute("SELECT 1")

        ticks = iter(
            (100.0, 100.01, 100.01, 100.01, 100.01, 100.01, 100.01, 100.01,
             100.01, 100.01, 100.01, 100.01, 200.0, 200.0, 200.0)
        )

        def _advancing_monotonic() -> float:
            return next(ticks, 200.0)

        with (
            mock.patch("oc_inbox_projection.time.monotonic", side_effect=_advancing_monotonic),
            mock.patch("oc_inbox_db.time.monotonic", side_effect=_advancing_monotonic),
            mock.patch("oc_projection_db.time.monotonic", side_effect=_advancing_monotonic),
            self.assertRaises(CoordPolicyError) as ctx_pack,
        ):
            self.svc.get_inbox_summary(_OP, max_read_ms=50)
        self.assertIn(ERR_READ_DEADLINE, str(ctx_pack.exception))

        public_methods = {
            name for name in dir(ReadOnlyInboxService) if not name.startswith("_")
        }
        self.assertEqual(
            public_methods,
            {"list_inbox_items", "get_inbox_item", "get_inbox_summary"},
        )
        self.svc.list_inbox_items(_OP)
        self.svc.get_inbox_item(_OP, review_id=_REV_ID)
        self.svc.get_inbox_summary(_OP)
        self.assertEqual(_snapshot_db_digest(self.db_path), before_digest)


class _NoEncodeStr(str):
    """Test string failing immediately if .encode() is invoked."""

    def encode(self, *_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("encode_must_not_be_called")


class _NoHashStr(str):
    """Test string failing immediately if __hash__() is invoked."""

    def __hash__(self) -> int:
        raise AssertionError("hash_must_not_be_called")


class TestExternalReviewRegressions(InboxReadTestBase):
    """Adversarial regressions verified red on c48ee250 and green on patched code."""

    def test_collate_nocase_cross_identity_and_schema_pk_index_guards(self) -> None:
        rev_pk_def = "review_id             TEXT PRIMARY KEY"
        nc_dir = _make_private_dir(self.root, "nocase_state")
        nc_schema = (
            _SCHEMA_SQL.replace(
                "run_id        TEXT PRIMARY KEY",
                "run_id        TEXT PRIMARY KEY COLLATE NOCASE",
            )
            .replace(rev_pk_def, f"{rev_pk_def} COLLATE NOCASE")
            .replace(
                "review_id   TEXT NOT NULL",
                "review_id   TEXT NOT NULL COLLATE NOCASE",
            )
        )
        nc_db = _init_inbox_db(nc_dir, schema_sql=nc_schema)
        _exec_write(
            nc_db,
            _SQL_INSERT_RUN,
            ("run-a", _WORKFLOW_ID, _SPEC_DIGEST, _POLICY_DIGEST, "running", "orchestrator", 1700000000.0, 1700000001.0),
        )
        pin = compute_review_pin_sha256(
            run_id="Run-A",
            step_id=_STEP_ID,
            review_id="Rev-1",
            checkpoint_seq=10,
            artifact_sha256=_ART_SHA,
            policy_digest=_POLICY_DIGEST,
        )
        _insert_item(
            nc_db,
            {_COL_REVIEW_ID: "Rev-1", "run_id": "Run-A"},
            override_pin=pin,
            with_primary_artifact=False,
        )
        _exec_write(
            nc_db,
            _SQL_INSERT_ART,
            ("art-lower", "rev-1", _ART_SHA, 128, _MEDIA_PATCH, "Lower", 1, 1700000000.0),
        )

        nc_svc = ReadOnlyInboxService(nc_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_miss:
            nc_svc.get_inbox_item(_OP, review_id="rev-1")
        self.assertIn(_ERR_ITEM_NOT_FOUND, str(ctx_miss.exception))
        self.assertEqual(nc_svc.list_inbox_items(_OP, run_id="run-a").items, ())

        detail = nc_svc.get_inbox_item(_OP, review_id="Rev-1")
        self.assertFalse(detail.item.pin_verified)
        self.assertFalse(detail.item.review_ready)
        self.assertEqual(detail.item.anomaly_reason, ANOMALY_RUN_MISSING)
        self.assertIsNone(detail.item.identity.workflow_id)
        self.assertEqual(detail.artifact_refs, ())

        nopk_dir = _make_private_dir(self.root, "nopk_state")
        nopk_schema = _SCHEMA_SQL.replace(
            rev_pk_def,
            "review_id             TEXT NOT NULL",
        )
        _init_inbox_db(nopk_dir, schema_sql=nopk_schema)
        nopk_svc = ReadOnlyInboxService(nopk_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_nopk:
            nopk_svc.list_inbox_items(_OP)
        self.assertEqual(str(ctx_nopk.exception), ERR_INBOX_UNREADABLE)

        idx_dir = _make_private_dir(self.root, "extra_idx_state")
        idx_db = _init_inbox_db(idx_dir)
        _exec_write(idx_db, "CREATE INDEX idx_evil_expr ON review_items(lower(review_id))")
        idx_svc = ReadOnlyInboxService(idx_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_idx:
            idx_svc.list_inbox_items(_OP)
        self.assertEqual(str(ctx_idx.exception), ERR_INBOX_UNREADABLE)

    def test_sql_truncation_withholds_split_credential_prefix(self) -> None:
        url_tok = "".join(("TopSec", "Url", "998877"))
        sk_tok = "".join(("9988", "7766", "5544"))
        url_cred = "".join(("https://", "alice:", url_tok, "@example.com/db"))
        sk_cred = "".join(("sk-ant-", sk_tok))
        ansi_pad = "\x1b[31m" * 202
        rev_cut_url = "rev-cut-url"
        rev_cut_sk = "rev-cut-sk"

        _insert_item(
            self.db_path,
            {
                _COL_REVIEW_ID: rev_cut_url,
                "title": "t " + ansi_pad + " " + url_cred,
                _COL_SUMMARY_TEXT: "s " + ("a" * (MAX_ITEM_TEXT_BYTES - 21)) + " " + url_cred,
            },
            artifact_id="art-cut-url",
        )
        _insert_item(
            self.db_path,
            {
                _COL_REVIEW_ID: rev_cut_sk,
                "title": "t " + ("b" * 245) + " " + sk_cred,
                _COL_SUMMARY_TEXT: "s " + ("b" * (MAX_ITEM_TEXT_BYTES - 12)) + " " + sk_cred,
            },
            artifact_id="art-cut-sk",
        )
        _exec_write(
            self.db_path,
            "UPDATE review_artifacts SET label = ? WHERE artifact_id = 'art-cut-url'",
            ("l " + ansi_pad + " " + sk_cred,),
        )
        _exec_write(
            self.db_path,
            "UPDATE review_artifacts SET label = ? WHERE artifact_id = 'art-cut-sk'",
            ("l " + ("c" * 245) + " " + url_cred,),
        )

        page_json = serialize_inbox_json(self.svc.list_inbox_items(_OP))
        d1_json = serialize_inbox_json(self.svc.get_inbox_item(_OP, review_id=rev_cut_url))
        d2_json = serialize_inbox_json(self.svc.get_inbox_item(_OP, review_id=rev_cut_sk))
        combined = page_json + d1_json + d2_json
        for leaked in ("alice:", url_tok[:4], "sk-ant-", sk_tok[:2]):
            self.assertNotIn(leaked, combined)

    def test_stage2_header_redaction_ordering_and_quoted_braces(self) -> None:
        s1 = "".join(("SUPER_", "SEC_", "COLON1"))
        s2 = "".join(("SUPER_", "SEC_", "DOLLAR2"))
        s3 = "".join(("PROXY_", "SEC_", "DOLLAR3"))
        s4 = "".join(("extra_", "secret_", "tail4"))
        s5 = "".join(("EXTRA_", "BASIC_", "SEC5"))
        s6 = "".join(("SECRET_", "AFTER_", "BRACE6"))
        s7 = "".join(("SECRET_", "COOKIE_", "BRACE7"))
        payload = "\n".join(
            (
                f"Authorization: Bearer abc123:{s1}",
                f"Authorization: Bearer fooo${s2}",
                f"Proxy-Authorization: Bearer fooo${s3}",
                f"Authorization: Bearer tok1234 {s4}",
                f"Authorization: Basic dXNlcjpwYXNz {s5}",
                f'Authorization: "part1}}{s6}"',
                f'Cookie: "sid=abc}}{s7}"',
            )
        )
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-hdr-ord", _COL_SUMMARY_TEXT: payload},
            artifact_id="art-hdr-ord",
        )
        page = self.svc.list_inbox_items(_OP)
        serialized = serialize_inbox_json(page)
        for secret in (s1, s2, s3, s4, s5, s6, s7):
            self.assertNotIn(secret, serialized)
        self.assertTrue(page.items[0].redaction_applied)

    def test_stage1_nested_spliced_padded_escapes_and_dot_metadata_keys(self) -> None:
        cases = (
            ("rev-fsm-1", "A\x1b[\x1b]0;x\x0731mB"),
            ("rev-fsm-2", "A\x9b\x1b]0;x\x0731mB"),
            ("rev-fsm-3", "A\x1b\x1b]0;x\x07]0;PWNED\x07B"),
            ("rev-fsm-4", "A\x1b\x1bPfoo\x1b\\]0;HIDDEN_OSC\x07B"),
            ("rev-fsm-5", "A\x1b\x00]0;HIDDEN_NUL\x07B"),
            ("rev-fsm-6", "A\x1b\x7fPHIDDEN_DCS\x1b\\B"),
        )
        dot_meta = json.dumps(
            {
                "api.key": "dot1",
                "private.key": "dot2",
                "env.vars": "dot3",
                "auth/header": "dot4",
                "safe_ok": "kept",
            }
        )
        for rid, text in cases:
            _insert_item(
                self.db_path,
                {
                    _COL_REVIEW_ID: rid,
                    _COL_SUMMARY_TEXT: text,
                    _COL_METADATA_JSON: dot_meta,
                },
                artifact_id=f"art-{rid}",
            )
        page = self.svc.list_inbox_items(_OP)
        serialized = serialize_inbox_json(page)
        for item in page.items:
            self.assertEqual(item.summary_text, "AB")
            self.assertTrue(item.has_control_or_bidi)
            self.assertTrue(item.redaction_applied)
            self.assertEqual(dict(item.metadata), {"safe_ok": "kept"})
        for leaked in ("31m", "PWNED", "HIDDEN_OSC", "HIDDEN_NUL", "HIDDEN_DCS", "dot1", "dot2", "dot3", "dot4"):
            self.assertNotIn(leaked, serialized)

    def test_credential_shaped_media_type_and_read_session_id_blocked(self) -> None:
        cred_tok = "".join(("sk-ant-", "mediaSec", "123456"))
        _insert_item(
            self.db_path,
            {_COL_REVIEW_ID: "rev-mt-p"},
            with_primary_artifact=False,
        )
        _exec_write(
            self.db_path,
            _SQL_INSERT_ART,
            ("art-mt-p", "rev-mt-p", _ART_SHA, 64, f"application/vnd.{cred_tok}", "Prim", 1, 1700000000.0),
        )
        _exec_write(
            self.db_path,
            _SQL_INSERT_ART,
            ("art-mt-s", "rev-mt-p", _ART_SHA_ALT, 64, f"text/{cred_tok}", "Sec", 0, 1700000000.0),
        )
        detail = self.svc.get_inbox_item(_OP, review_id="rev-mt-p")
        self.assertFalse(detail.item.pin_verified)
        self.assertFalse(detail.item.review_ready)
        self.assertEqual(detail.item.anomaly_reason, ANOMALY_ARTIFACT_MISMATCH)
        self.assertTrue(detail.item.malformed_metadata)
        self.assertTrue(detail.artifacts_malformed)
        for art in detail.artifact_refs:
            self.assertEqual(art.media_type, "application/octet-stream")
            self.assertTrue(art.redaction_applied)
            self.assertTrue(art.malformed_metadata)
        self.assertNotIn(cred_tok, serialize_inbox_json(detail))

        cred_sess = "".join(("sk-ant-", "sessTok", "123456"))
        sess_svc = ReadOnlyInboxService(
            self.state_dir,
            sandbox_root=self.sandbox_root,
            session_validator=lambda _c, _sid, _gen: True,
        )
        for call in (
            lambda: sess_svc.list_inbox_items(_OP, read_session_id=cred_sess, session_generation=1),
            lambda: sess_svc.get_inbox_item(_OP, review_id="rev-mt-p", read_session_id=cred_sess, session_generation=1),
            lambda: sess_svc.get_inbox_summary(_OP, read_session_id=cred_sess, session_generation=1),
        ):
            with self.assertRaises(CoordValidationError) as ctx_s:
                call()
            self.assertEqual(str(ctx_s.exception), "invalid_read_session_id")
            self.assertNotIn(cred_sess, str(ctx_s.exception))

    def test_mid_read_revocation_precedes_storage_errors(self) -> None:
        _insert_item(self.db_path, {_COL_REVIEW_ID: "rev-keep-1"}, artifact_id="art-k1")
        _insert_item(self.db_path, {_COL_REVIEW_ID: "rev-keep-2"}, artifact_id="art-k2")
        page1 = self.svc.list_inbox_items(_OP, limit=1)
        stale_cursor = page1.next_cursor
        self.assertIsNotNone(stale_cursor)
        _exec_write(self.db_path, _SQL_BUMP_SEQ)

        calls = 0

        def _retire_on_second(_c: PrincipalCtx, _sid: str, _gen: int) -> bool:
            nonlocal calls
            calls += 1
            return calls % 2 == 1

        rev_svc = ReadOnlyInboxService(
            self.state_dir,
            sandbox_root=self.sandbox_root,
            session_validator=_retire_on_second,
        )
        with self.assertRaises(RevokedError):
            rev_svc.get_inbox_item(
                _OP, review_id="rev-missing-999", read_session_id=_SESS_ID, session_generation=1
            )
        with self.assertRaises(RevokedError):
            rev_svc.list_inbox_items(
                _OP, after_cursor=stale_cursor, read_session_id=_SESS_ID, session_generation=1
            )

    def test_o1_cursor_no_encode_and_bounded_statuses_and_token_precheck(self) -> None:
        oversize_cur = _NoEncodeStr("v1." + ("A" * 600))
        with self.assertRaises(CoordValidationError) as ctx_cur:
            self.svc.list_inbox_items(_OP, after_cursor=oversize_cur)
        self.assertIn(ERR_CURSOR_MALFORMED, str(ctx_cur.exception))

        oversize_tok = _NoEncodeStr("a" * 200)
        with self.assertRaises(CoordValidationError):
            self.svc.get_inbox_item(_OP, review_id=oversize_tok)
        with self.assertRaises(CoordValidationError):
            self.svc.list_inbox_items(_OP, run_id=oversize_tok)

        for many in (itertools.repeat(STATUS_PENDING), [STATUS_PENDING] * 1000):
            with self.assertRaises(CoordValidationError) as ctx_many:
                self.svc.list_inbox_items(_OP, statuses=many)
            self.assertEqual(str(ctx_many.exception), "status_filter_too_many_entries")

        bad_sec = "".join(("sk-ant-", "badStat", "123456"))
        with self.assertRaises(CoordValidationError) as ctx_bad:
            self.svc.list_inbox_items(_OP, statuses=[bad_sec])
        self.assertEqual(str(ctx_bad.exception), _ERR_UNSUPPORTED_STATUS)
        self.assertNotIn(bad_sec, str(ctx_bad.exception))

    def test_truncated_backslash_quoted_secret_and_raw_cookie_with_brace(self) -> None:
        w1 = "".join(("Multi", "Word", "One"))
        w2 = "".join(("Multi", "Word", "Two"))
        w3 = "".join(("Short", "Slash", "One"))
        w4 = "".join(("Short", "Slash", "Two"))
        c_tail = "".join(("COOKIE_", "BRACE_", "TAIL99"))
        c_json = "".join(("JSON_", "COOKIE_", "SEC88"))
        x_tail = "".join(("XAPI_", "BRACE_", "TAIL77"))
        rev_trunc = "rev-bs-trunc"
        rev_raw = "rev-bs-raw"
        pwd_prefix = "".join(("pass", 'word="'))

        tail_quote = f" {pwd_prefix}{w1} {w2}\\"
        pad_len = MAX_ITEM_TEXT_BYTES - len(tail_quote)
        _insert_item(
            self.db_path,
            {
                _COL_REVIEW_ID: rev_trunc,
                _COL_SUMMARY_TEXT: ("p" * pad_len) + tail_quote + "extra_cut",
            },
            artifact_id="art-bs-trunc",
        )
        _insert_item(
            self.db_path,
            {
                _COL_REVIEW_ID: rev_raw,
                _COL_SUMMARY_TEXT: "\n".join(
                    (
                        f"Cookie: sid=abc}}{c_tail}",
                        f'Cookie: prefs={{"k":"v"}}; sid={c_json}',
                        f"X-Api-Key: k}}{x_tail}",
                        f"{pwd_prefix}{w3} {w4}\\",
                    )
                ),
            },
            artifact_id="art-bs-raw",
        )
        page = self.svc.list_inbox_items(_OP)
        serialized = serialize_inbox_json(page)
        for secret in (w1, w2, w3, w4, c_tail, c_json, x_tail):
            self.assertNotIn(secret, serialized)
        by_id = {it.review_id: it for it in page.items}
        self.assertEqual(by_id[rev_trunc].summary_text, REDACTED_MARKER)
        self.assertTrue(by_id[rev_trunc].redaction_applied)
        self.assertTrue(by_id[rev_raw].redaction_applied)

    def test_mid_fs_admission_revocation_precedes_missing_db_and_bad_sidecar(self) -> None:
        calls = 0

        def _retire_after_precheck(_c: PrincipalCtx, _sid: str, _gen: int) -> bool:
            nonlocal calls
            calls += 1
            return calls % 2 == 1

        empty_dir = _make_private_dir(self.root, "empty_rev_state")
        miss_svc = ReadOnlyInboxService(
            empty_dir,
            sandbox_root=self.sandbox_root,
            session_validator=_retire_after_precheck,
        )
        with self.assertRaises(RevokedError):
            miss_svc.list_inbox_items(_OP, read_session_id=_SESS_ID, session_generation=1)

        bad_dir = _make_private_dir(self.root, "sidecar_rev_state")
        bad_db = _init_inbox_db(bad_dir)
        wal_path = Path(f"{bad_db}-wal")
        wal_path.write_bytes(b"")
        os.chmod(wal_path, 0o600 | 0o044)
        bad_svc = ReadOnlyInboxService(
            bad_dir,
            sandbox_root=self.sandbox_root,
            session_validator=_retire_after_precheck,
        )
        with self.assertRaises(RevokedError):
            bad_svc.get_inbox_summary(_OP, read_session_id=_SESS_ID, session_generation=1)

    def test_oversized_schema_ddl_columns_and_objects_rejected_before_seq_read(self) -> None:
        import oc_inbox_db  # noqa: PLC0415

        self.assertIn("sql_is_null", oc_inbox_db._SQL_LIST_INDEXES)
        self.assertNotIn(", sql ", oc_inbox_db._SQL_LIST_INDEXES)

        big_def_dir = _make_private_dir(self.root, "big_ddl_state")
        huge_default = "D" * (200 * 1024)
        big_schema = _SCHEMA_SQL.replace(
            "title                 TEXT NOT NULL,",
            f"title                 TEXT NOT NULL DEFAULT '{huge_default}',",
        )
        big_db = _init_inbox_db(big_def_dir, schema_sql=big_schema)
        _exec_write(big_db, _SQL_CLEAR_SEQ)
        big_svc = ReadOnlyInboxService(big_def_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_ddl:
            big_svc.list_inbox_items(_OP)
        self.assertEqual(str(ctx_ddl.exception), ERR_INBOX_UNREADABLE)

        col_dir = _make_private_dir(self.root, "many_col_state")
        col_db = _init_inbox_db(col_dir)
        for idx in range(70):
            _exec_write(col_db, f"ALTER TABLE review_items ADD COLUMN extra_c{idx} INTEGER")
        col_svc = ReadOnlyInboxService(col_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_col:
            col_svc.list_inbox_items(_OP)
        self.assertEqual(str(ctx_col.exception), ERR_INBOX_UNREADABLE)

        obj_dir = _make_private_dir(self.root, "many_obj_state")
        obj_db = _init_inbox_db(obj_dir)
        for idx in range(35):
            _exec_write(obj_db, f"CREATE TABLE extra_t{idx} (id INTEGER PRIMARY KEY)")
        obj_svc = ReadOnlyInboxService(obj_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError) as ctx_obj:
            obj_svc.list_inbox_items(_OP)
        self.assertEqual(str(ctx_obj.exception), ERR_INBOX_UNREADABLE)

    def test_oversized_status_filter_short_circuits_before_hash(self) -> None:
        oversize_status = _NoHashStr("x" * 1000)
        with self.assertRaises(CoordValidationError) as ctx:
            self.svc.list_inbox_items(_OP, statuses=[oversize_status])
        self.assertEqual(str(ctx.exception), _ERR_UNSUPPORTED_STATUS)


if __name__ == "__main__":
    unittest.main()
