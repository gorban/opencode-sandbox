"""Deterministic offline qualification suite for PRD M3.1 Read-Only Projection.

Runs under both default $HOME and TMPDIR=/tmp using private owner-only synthetic
CoordRegistry + CoordHub fixtures (zero Podman, zero network, zero live
credentials, zero writes to host production directories).
"""

from __future__ import annotations

import base64
from collections.abc import Iterable
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

_PROJECTION_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _PROJECTION_DIR.parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
for _import_dir in (str(_PROJECTION_DIR), str(_SPIKE_M_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_broker_common import _UMASK_LOCK  # noqa: E402
from oc_coord_contract import (  # noqa: E402
    ArtifactRef,
    CoordAuthError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    DispatchOutcome,
    DispatchResult,
    Envelope,
    PrincipalCtx,
    ProvenanceBadge,
    RevokedError,
    RoutingEdge,
    SandboxRecord,
    StreamEvent,
    SubtreeBudget,
    TrustClass,
    TurnDispatch,
    WorkerStatus,
    sha256_canonical_body,
)
from oc_fake_worker import FakeWorkerTransport  # noqa: E402
from oc_hub import CoordHub  # noqa: E402
import oc_projection  # noqa: E402
from oc_projection import ReadOnlyProjectionService, open_readonly_snapshot  # noqa: E402
from oc_projection_contract import (  # noqa: E402
    HEALTH_DEGRADED,
    HEALTH_HEALTHY,
    HEALTH_UNKNOWN,
    MAX_ITEM_TEXT_BYTES,
    PROJECTION_SCHEMA_VERSION,
    SOURCE_EVENT_LOG,
    SOURCE_STREAM_EVENT,
    encode_cursor,
    serialize_projection_bytes,
    serialize_projection_json,
)
from oc_registry import CoordRegistry  # noqa: E402

_OP_CALLER = PrincipalCtx(role=CoordRole.OPERATOR, actor_id="op-main")
_DEFAULT_THREAD = "main"
_DEFAULT_WORKER = "local"
_DEFAULT_PROJECT_ID = "proj-alpha"
_DEFAULT_PROJECT_NAME = "Alpha Project"
_DEFAULT_BRANCH = "main"
_DEFAULT_TYPE = "default"
_DEFAULT_BRIEF = "Implement projection tests"
_DEFAULT_INC = "inc:1"
_DB_NAME = "registry.sqlite"
_ERR_DEADLINE = "read_deadline_exceeded"
_ERR_UNREADABLE = "registry_unreadable"
_ERR_BODY_HASH = "receipt_body_hash_mismatch"
_SQL_LAST_SEQ = "SELECT last_seq FROM seq_counter WHERE id = 1"
_MSG_OVERSIZE = "msg-oversize"
_SB_FLAG_MAL_ABORT = "flag-mal-abort"
_ERR_CURSOR_MALFORMED = "cursor_malformed"
_PATCH_DB_CONNECT = "oc_projection_db.sqlite3.connect"


def _make_private_tempdir() -> Path:
    root = Path(tempfile.mkdtemp(prefix="oc-proj-test-"))
    os.chmod(root, 0o700)
    return root


def _make_state_and_sandbox(root: Path) -> tuple[Path, Path]:
    state_dir = root / "state"
    sandbox_root = root / "sandbox_home"
    state_dir.mkdir(mode=0o700)
    os.chmod(state_dir, 0o700)
    sandbox_root.mkdir(mode=0o700)
    os.chmod(sandbox_root, 0o700)
    return state_dir, sandbox_root


def _register_sample_sandbox(
    reg: CoordRegistry,
    *,
    name: str = "worker-a",
    incarnation_id: str = _DEFAULT_INC,
    job_id: str = "job-1",
    project_id: str = _DEFAULT_PROJECT_ID,
    project_name: str = _DEFAULT_PROJECT_NAME,
    branch: str = _DEFAULT_BRANCH,
    parent_addr: str | None = None,
    depth: int = 0,
):
    now = time.time()
    rec = SandboxRecord(
        sandbox_addr=name,
        worker_ref=_DEFAULT_WORKER,
        instance_name=name,
        incarnation_id=incarnation_id,
        job_id=job_id,
        project_id=project_id,
        project_name=project_name,
        branch=branch,
        sandbox_type=_DEFAULT_TYPE,
        task_brief=_DEFAULT_BRIEF,
        status="running",
        parent_addr=parent_addr,
        depth=depth,
        created_at=now,
        updated_at=now,
    )
    out = reg.register_sandbox(rec)
    reg.ensure_thread(name, incarnation_id, _DEFAULT_THREAD, title="Main thread")
    return out


def _open_raw_rw(state_dir: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(state_dir / _DB_NAME), isolation_level=None)
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _read_raw_seq(state_dir: Path) -> int:
    conn = _open_raw_rw(state_dir)
    try:
        row = conn.execute(_SQL_LAST_SEQ).fetchone()
        return int(row[0]) if row is not None else 0
    finally:
        conn.close()


def _insert_verified_operator_message(
    reg: CoordRegistry,
    *,
    sandbox_addr: str,
    incarnation_id: str,
    thread_id: str,
    msg_id: str,
    body_text: str,
    artifact_refs: tuple[ArtifactRef, ...] = (),
) -> str:
    edge_id = f"edge:{sandbox_addr}:{msg_id}"
    edge = reg.grant_edge(
        RoutingEdge(
            edge_id=edge_id,
            src_actor=_OP_CALLER.canonical_sender,
            src_incarnation=None,
            dst_addr=sandbox_addr,
            allowed_threads=frozenset({thread_id}),
            allowed_msg_kinds=frozenset({"prompt"}),
            created_at=time.time(),
        )
    )
    env_in = Envelope(
        msg_id=msg_id,
        seq=0,
        src_role=CoordRole.OPERATOR,
        src_actor=_OP_CALLER.canonical_sender,
        src_incarnation=None,
        dst_addr=sandbox_addr,
        dst_thread_id=thread_id,
        dst_incarnation=incarnation_id,
        trust_class=TrustClass.OPERATOR_DIRECTIVE,
        msg_kind="prompt",
        body_text=body_text,
        body_sha256=sha256_canonical_body(body_text),
        edge_id=edge.edge_id,
        edge_turn_seq=1,
        artifact_refs=artifact_refs,
        created_at=time.time(),
    )
    _, env = reg.admit_and_enqueue_send(
        edge_id=edge.edge_id,
        expected_grant_generation=edge.grant_generation,
        expected_src_incarnation=None,
        expected_dst_incarnation=incarnation_id,
        envelope=env_in,
        count_turn=False,
        max_queued_msgs=32,
        max_queued_bytes=1_048_576,
    )
    reg.record_stream_event(
        StreamEvent(
            event_type="user_message",
            sandbox_addr=sandbox_addr,
            incarnation_id=incarnation_id,
            thread_id=thread_id,
            seq_hint=1,
            message_id=env.msg_id,
            text=body_text,
        ),
        dispatch_msg_id=env.msg_id,
    )
    return env.msg_id


class _ExternallyFencedFakeTransport:
    """Minimal ExternallyFencedTransport stub for end-to-end hub integration tests."""

    def __init__(self) -> None:
        self._streams: dict[str, list[StreamEvent]] = {}
        self._aborted: set[tuple[str, str]] = set()
        self._counter = 0

    @property
    def external_write_fence(self) -> bool:
        return True

    def transport_owner_id(self, sandbox_addr: str, incarnation_id: str) -> str:
        return f"ext-owner:{sandbox_addr}:{incarnation_id}"

    def dispatch_turn(self, turn: TurnDispatch) -> DispatchResult:
        if (turn.sandbox_addr, turn.incarnation_id) in self._aborted:
            return DispatchResult(
                outcome=DispatchOutcome.ZERO_BYTES_SENT,
                detail="aborted",
                permanent=True,
            )
        self._counter += 1
        sid = f"stream_{self._counter}"
        self._streams[sid] = [
            StreamEvent(
                event_type="user_message",
                sandbox_addr=turn.sandbox_addr,
                incarnation_id=turn.incarnation_id,
                thread_id=turn.thread_id,
                seq_hint=1,
                message_id=turn.msg_id,
                text=turn.wire_text,
            ),
            StreamEvent(
                event_type="text_delta",
                sandbox_addr=turn.sandbox_addr,
                incarnation_id=turn.incarnation_id,
                thread_id=turn.thread_id,
                seq_hint=2,
                text="Ack from fenced transport",
            ),
            StreamEvent(
                event_type="turn_completed",
                sandbox_addr=turn.sandbox_addr,
                incarnation_id=turn.incarnation_id,
                thread_id=turn.thread_id,
                seq_hint=3,
                text="done",
            ),
        ]
        return DispatchResult(outcome=DispatchOutcome.HANDED_OFF, stream_id=sid)

    def stream_events(self, stream_id: str) -> Iterable[StreamEvent]:
        return list(self._streams.get(stream_id, ()))

    def abort_incarnation(
        self, sandbox_addr: str, incarnation_id: str, *, reason: str
    ) -> bool:
        _ = reason
        self._aborted.add((sandbox_addr, incarnation_id))
        return True

    def status(self, sandbox_addr: str, incarnation_id: str) -> WorkerStatus:
        aborted = (sandbox_addr, incarnation_id) in self._aborted
        return WorkerStatus(
            sandbox_addr=sandbox_addr,
            incarnation_id=incarnation_id,
            state="revoked" if aborted else "running",
            revoked=aborted,
        )


class ProjectionBaseTest(unittest.TestCase):
    """Shared isolated fixture root cleanup."""

    def setUp(self) -> None:
        self.root = _make_private_tempdir()
        self.state_dir, self.sandbox_root = _make_state_and_sandbox(self.root)

    def tearDown(self) -> None:
        for path in sorted(self.root.rglob("*"), reverse=True):
            try:
                if not path.is_symlink() and path.is_dir():
                    os.chmod(path, 0o700)
            except OSError:
                pass
        shutil.rmtree(self.root, ignore_errors=True)

    def _new_registry(self) -> CoordRegistry:
        return CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)

    def _new_service(self, **kwargs) -> ReadOnlyProjectionService:
        return ReadOnlyProjectionService(
            self.state_dir, sandbox_root=self.sandbox_root, **kwargs
        )


class TestFilesystemAdmissionAndLiveWal(ProjectionBaseTest):
    """Section 9.1: verification-only filesystem checks, sidecars, FIFO/hardlink, live WAL."""

    def test_missing_registry_fails_without_creating_file(self) -> None:
        svc = self._new_service()
        with self.assertRaisesRegex(CoordPolicyError, "registry_missing"):
            svc.get_workspace_tree(_OP_CALLER)
        self.assertFalse((self.state_dir / _DB_NAME).exists())

    def test_symlink_state_dir_and_user_symlink_ancestor_rejected(self) -> None:
        reg = self._new_registry()
        reg.close()
        sym_dir = self.root / "sym_state"
        os.symlink(self.state_dir, sym_dir)
        svc_sym = ReadOnlyProjectionService(sym_dir, sandbox_root=self.sandbox_root)
        with self.assertRaisesRegex(CoordPolicyError, "state_dir_symlink_rejected"):
            svc_sym.get_workspace_tree(_OP_CALLER)

        anc_sym = self.root / "anc_link"
        os.symlink(self.root / "state", anc_sym)
        sub_state = anc_sym / "nested"
        svc_anc = ReadOnlyProjectionService(sub_state, sandbox_root=self.sandbox_root)
        with self.assertRaisesRegex(CoordPolicyError, "symlink_ancestor_rejected"):
            svc_anc.get_workspace_tree(_OP_CALLER)

    def test_production_host_dir_and_sandbox_dir_rejected(self) -> None:
        prod_dir = Path.home() / ".local" / "share" / "oc-sandbox"
        svc_prod = ReadOnlyProjectionService(prod_dir, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError):
            svc_prod.get_workspace_tree(_OP_CALLER)

        in_sb = self.sandbox_root / "state"
        in_sb.mkdir(mode=0o700)
        svc_sb = ReadOnlyProjectionService(in_sb, sandbox_root=self.sandbox_root)
        with self.assertRaises(CoordPolicyError):
            svc_sb.get_workspace_tree(_OP_CALLER)

    def test_unsafe_mode_db_not_repaired_and_rejected(self) -> None:
        reg = self._new_registry()
        reg.close()
        db_path = self.state_dir / _DB_NAME
        os.chmod(db_path, 0o640)
        svc = self._new_service()
        with self.assertRaisesRegex(CoordPolicyError, "registry_unsafe_mode"):
            svc.get_workspace_tree(_OP_CALLER)
        self.assertEqual(stat.S_IMODE(os.lstat(db_path).st_mode), 0o640)

    def test_symlink_hardlink_and_fifo_db_and_sidecars_fail_immediately(self) -> None:
        reg = self._new_registry()
        reg.close()
        db_path = self.state_dir / _DB_NAME
        svc = self._new_service()

        # Hardlinked DB
        hl_path = self.root / "db_hardlink"
        os.link(db_path, hl_path)
        try:
            with self.assertRaisesRegex(CoordPolicyError, "registry_hardlink_rejected"):
                svc.get_workspace_tree(_OP_CALLER)
        finally:
            hl_path.unlink()

        # Hardlinked -wal sidecar
        wal_path = Path(f"{db_path}-wal")
        wal_path.write_bytes(b"")
        os.chmod(wal_path, 0o600)
        wal_hl = self.root / "wal_hardlink"
        os.link(wal_path, wal_hl)
        try:
            with self.assertRaisesRegex(CoordPolicyError, "registry_sidecar_wal_hardlink"):
                svc.get_workspace_tree(_OP_CALLER)
        finally:
            wal_hl.unlink()
            wal_path.unlink()

        # Symlinked -shm sidecar
        shm_path = Path(f"{db_path}-shm")
        os.symlink(db_path, shm_path)
        try:
            with self.assertRaisesRegex(CoordPolicyError, "registry_sidecar_shm_symlink"):
                svc.get_workspace_tree(_OP_CALLER)
        finally:
            shm_path.unlink()

        # FIFO at -journal sidecar must not block!
        journal_path = Path(f"{db_path}-journal")
        os.mkfifo(journal_path, 0o600)
        try:
            t0 = time.monotonic()
            with self.assertRaisesRegex(CoordPolicyError, "registry_sidecar_journal_not_regular"):
                svc.get_workspace_tree(_OP_CALLER)
            self.assertLess(time.monotonic() - t0, 1.0)
        finally:
            journal_path.unlink()

        # FIFO replacing DB itself must not block!
        db_path.unlink()
        os.mkfifo(db_path, 0o600)
        t0 = time.monotonic()
        with self.assertRaisesRegex(CoordPolicyError, "registry_not_regular"):
            svc.get_workspace_tree(_OP_CALLER)
        self.assertLess(time.monotonic() - t0, 1.0)

    def test_direct_write_rejected_and_logical_immutability_preserved(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="imm-a")
        before_audit = reg.verify_audit_chain()
        reg.close()
        before_seq = _read_raw_seq(self.state_dir)

        db_path = self.state_dir / _DB_NAME
        with (
            open_readonly_snapshot(db_path, deadline=time.monotonic() + 2.0) as conn,
            self.assertRaises(sqlite3.OperationalError),
        ):
            conn.execute("UPDATE seq_counter SET last_seq = 999999 WHERE id = 1")

        svc = self._new_service()
        tree = svc.get_workspace_tree(_OP_CALLER)
        self.assertEqual(tree.snapshot_seq, before_seq)

        reg2 = self._new_registry()
        try:
            self.assertEqual(_read_raw_seq(self.state_dir), before_seq)
            self.assertEqual(reg2.verify_audit_chain(), before_audit)
        finally:
            reg2.close()

    def test_readonly_dir_without_shm_maps_to_registry_unreadable(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="ro-a")
        reg.close()
        for suffix in ("-shm", "-wal"):
            sidecar = self.state_dir / f"registry.sqlite{suffix}"
            if sidecar.exists():
                sidecar.unlink()
        os.chmod(self.state_dir, 0o500)
        svc = self._new_service()
        try:
            with self.assertRaisesRegex(CoordPolicyError, _ERR_UNREADABLE):
                svc.get_workspace_tree(_OP_CALLER)
        finally:
            os.chmod(self.state_dir, 0o700)


class TestCallerAuthorityAndFencing(ProjectionBaseTest):
    """Section 9.2: operator-only admission and pre/post session & authority fencing."""

    def test_non_operator_and_malformed_callers_denied_before_filesystem(self) -> None:
        missing_svc = ReadOnlyProjectionService(
            self.root / "does_not_exist", sandbox_root=self.sandbox_root
        )
        non_op_callers = [
            PrincipalCtx(
                role=CoordRole.JOB,
                actor_id="job-a",
                sandbox_addr="worker-a",
                incarnation_id="inc-1",
            ),
            PrincipalCtx(role=CoordRole.ORCHESTRATOR, actor_id="orch-root"),
            PrincipalCtx(
                role=CoordRole.ORCHESTRATOR,
                actor_id="orch-sub",
                sandbox_addr="worker-a",
                incarnation_id="inc-1",
            ),
            PrincipalCtx(role=CoordRole.EXTERNAL_PEER, actor_id="peer-a"),
            PrincipalCtx(
                role=CoordRole.OPERATOR,
                actor_id="op-bound",
                sandbox_addr="worker-a",
            ),
        ]
        for caller in non_op_callers:
            with self.assertRaises(CoordAuthError):
                missing_svc.get_workspace_tree(caller)
        with self.assertRaisesRegex(CoordValidationError, "PrincipalCtx"):
            missing_svc.get_workspace_tree("not-a-principal")  # type: ignore[arg-type]

    def test_session_validator_pairing_unconfigured_and_pre_post_revocation(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="fence-a")
        reg.close()

        # Session args without validator -> CoordPolicyError
        unconfigured = self._new_service()
        with self.assertRaisesRegex(CoordPolicyError, "read_session_validator_unconfigured"):
            unconfigured.get_workspace_tree(
                _OP_CALLER, read_session_id="sess_1", session_generation=1
            )

        # Partial pair -> CoordValidationError
        with self.assertRaisesRegex(CoordValidationError, "read_session_pair_required"):
            unconfigured.get_workspace_tree(_OP_CALLER, read_session_id="sess_1")

        # Bool / <=0 session_generation -> CoordValidationError
        with self.assertRaises(CoordValidationError):
            unconfigured.get_workspace_tree(
                _OP_CALLER, read_session_id="sess_1", session_generation=True
            )
        with self.assertRaises(CoordValidationError):
            unconfigured.get_workspace_tree(
                _OP_CALLER, read_session_id="sess_1", session_generation=0
            )

        # Configured validator: omitted args -> CoordAuthError
        calls = {"n": 0}
        svc_sess = self._new_service(
            session_validator=lambda _c, _sid, _gen: calls.__setitem__("n", calls["n"] + 1)
            or True
        )
        with self.assertRaisesRegex(CoordAuthError, "read_session_required"):
            svc_sess.get_workspace_tree(_OP_CALLER)

        # Valid session echoes coordinates and invokes validator pre + post
        snap = svc_sess.get_workspace_tree(
            _OP_CALLER, read_session_id="sess_ok", session_generation=7
        )
        self.assertEqual(calls["n"], 2)
        self.assertIsNotNone(snap.read_session)
        assert snap.read_session is not None
        self.assertEqual(snap.read_session.read_session_id, "sess_ok")
        self.assertEqual(snap.read_session.session_generation, 7)

        # Truthy non-True return fails closed
        svc_truthy = self._new_service(session_validator=lambda _c, _s, _g: 1)  # type: ignore[arg-type,return-value]
        with self.assertRaisesRegex(RevokedError, "read_session_retired"):
            svc_truthy.get_workspace_tree(
                _OP_CALLER, read_session_id="sess_ok", session_generation=1
            )

        # Revoked DURING snapshot (1st call True, 2nd call False) -> RevokedError, zero data
        state = {"count": 0}

        def _retire_mid_read(_c: PrincipalCtx, _sid: str, _gen: int) -> bool:
            state["count"] += 1
            return state["count"] == 1

        svc_mid = self._new_service(session_validator=_retire_mid_read)
        with self.assertRaisesRegex(RevokedError, "read_session_retired"):
            svc_mid.get_workspace_tree(
                _OP_CALLER, read_session_id="sess_mid", session_generation=2
            )
        self.assertEqual(state["count"], 2)

        # live_authority_checker revoked DURING snapshot -> RevokedError
        auth_state = {"count": 0}

        def _revoke_auth_mid(_c: PrincipalCtx) -> bool:
            auth_state["count"] += 1
            return auth_state["count"] == 1

        svc_auth = self._new_service(live_authority_checker=_revoke_auth_mid)
        with self.assertRaisesRegex(RevokedError, "read_authority_revoked"):
            svc_auth.get_workspace_tree(_OP_CALLER)
        self.assertEqual(auth_state["count"], 2)


class TestHealthMarkersAndBindingDomains(ProjectionBaseTest):
    """Section 9.3: lock-free 3-state health, markers, orphaned & malformed bindings."""

    def test_lock_free_observed_status_and_concurrent_hub_startup(self) -> None:
        reg = self._new_registry()
        hub = CoordHub(
            reg,
            FakeWorkerTransport(),
            self.state_dir,
            sandbox_root=self.sandbox_root,
        )
        try:
            # Standalone reader (no live_degraded_checker) observes .coord_session_active -> unknown
            svc_standalone = self._new_service()
            tree_unknown = svc_standalone.get_workspace_tree(_OP_CALLER)
            self.assertEqual(tree_unknown.health.health_status, HEALTH_UNKNOWN)
            self.assertFalse(tree_unknown.health.degraded)
            self.assertTrue(tree_unknown.health.session_active_marker_present)
            self.assertFalse(tree_unknown.health.live_status_available)

            # With live_degraded_checker returning False -> healthy
            svc_live = self._new_service(live_degraded_checker=lambda: False)
            tree_healthy = svc_live.get_workspace_tree(_OP_CALLER)
            self.assertEqual(tree_healthy.health.health_status, HEALTH_HEALTHY)
            self.assertFalse(tree_healthy.health.degraded)
            self.assertTrue(tree_healthy.health.live_status_available)

            # With live_degraded_checker returning True -> degraded
            svc_deg = self._new_service(live_degraded_checker=lambda: True)
            tree_deg = svc_deg.get_workspace_tree(_OP_CALLER)
            self.assertEqual(tree_deg.health.health_status, HEALTH_DEGRADED)
            self.assertTrue(tree_deg.health.degraded)
            self.assertIn("live_hub_degraded", tree_deg.health.degraded_reasons)
        finally:
            hub.close()
            reg.close()

        # Verify standalone reader NEVER blocks a fresh CoordHub acquiring .coord_hub.lock
        db_path = self.state_dir / _DB_NAME
        with open_readonly_snapshot(db_path, deadline=time.monotonic() + 2.0):
            reg2 = self._new_registry()
            hub2 = CoordHub(
                reg2,
                FakeWorkerTransport(),
                self.state_dir,
                sandbox_root=self.sandbox_root,
            )
            hub2.close()
            reg2.close()

    def test_unreadable_fifo_and_unsafe_mode_health_markers_degrade_without_blocking(
        self,
    ) -> None:
        reg = self._new_registry()
        reg.close()
        svc = self._new_service(live_degraded_checker=lambda: False)

        deg_marker = self.state_dir / ".coord_degraded"
        os.mkfifo(deg_marker, 0o600)
        try:
            t0 = time.monotonic()
            tree = svc.get_workspace_tree(_OP_CALLER)
            self.assertLess(time.monotonic() - t0, 1.0)
            self.assertEqual(tree.health.health_status, HEALTH_DEGRADED)
            self.assertTrue(tree.health.marker_unreadable)
            self.assertIn("marker_unreadable", tree.health.degraded_reasons)
        finally:
            deg_marker.unlink()

        sess_marker = self.state_dir / ".coord_session_active"
        sess_marker.write_text("active", encoding="utf-8")
        os.chmod(sess_marker, 0o640)
        try:
            tree = svc.get_workspace_tree(_OP_CALLER)
            self.assertEqual(tree.health.health_status, HEALTH_DEGRADED)
            self.assertTrue(tree.health.marker_unreadable)
        finally:
            sess_marker.unlink()

    def test_orphaned_binding_and_no_owner_id_leak(self) -> None:
        reg = self._new_registry()
        reg.close()
        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                """
                INSERT INTO external_transport_bindings
                (sandbox_addr, incarnation_id, owner_id, abort_requested, terminal_confirmed,
                 reason, created_at, updated_at)
                VALUES (?, ?, ?, 0, 0, 'orphaned-row', 100.0, 200.0)
                """,
                ("ghost-sb", "inc-orphan", "SECRET_OWNER_TOKEN_XYZ"),
            )
        finally:
            raw.close()

        svc = self._new_service(live_degraded_checker=lambda: False)
        tree = svc.get_workspace_tree(_OP_CALLER)
        self.assertEqual(tree.health.health_status, HEALTH_DEGRADED)
        self.assertEqual(tree.health.unconfirmed_bindings_count, 1)
        self.assertEqual(len(tree.health.unconfirmed_bindings), 1)
        b = tree.health.unconfirmed_bindings[0]
        self.assertEqual(b.sandbox_addr, "ghost-sb")
        self.assertTrue(b.sandbox_missing)
        serialized = serialize_projection_json(tree)
        self.assertNotIn("SECRET_OWNER_TOKEN_XYZ", serialized)

    def test_oversized_blob_in_binding_updated_at_gated_in_sql(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="blob-sb")
        reg.close()
        giant_blob = b"X" * (2 * 1024 * 1024)
        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                """
                INSERT INTO external_transport_bindings
                (sandbox_addr, incarnation_id, owner_id, abort_requested, terminal_confirmed,
                 reason, created_at, updated_at)
                VALUES (?, ?, 'own-1', 1, 0, 'aborting', 1.0, ?)
                """,
                ("blob-sb", _DEFAULT_INC, sqlite3.Binary(giant_blob)),
            )
        finally:
            raw.close()

        # Verify SQL itself returns NULL (not the 2 MiB BLOB!) to Python
        with open_readonly_snapshot(
            self.state_dir / _DB_NAME, deadline=time.monotonic() + 2.0
        ) as conn:
            sql_row = conn.execute(
                oc_projection._SQL_UNCONFIRMED_BINDINGS_SUMMARY, (10,)
            ).fetchone()
            self.assertIsNotNone(sql_row)
            self.assertIsNone(sql_row["updated_at"])
            self.assertEqual(sql_row["updated_at_malformed"], 1)

        svc = self._new_service(live_degraded_checker=lambda: False)
        tree = svc.get_workspace_tree(_OP_CALLER)
        self.assertEqual(tree.health.unconfirmed_bindings_count, 1)
        item = tree.health.unconfirmed_bindings[0]
        self.assertEqual(item.updated_at, 0.0)
        self.assertTrue(item.malformed_metadata)
        self.assertLess(len(serialize_projection_bytes(tree)), 4096)

    def test_binding_flag_domain_confirmed_malformed_out_of_domain_and_valid(
        self,
    ) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="flag-valid")
        _register_sample_sandbox(reg, name=_SB_FLAG_MAL_ABORT)
        _register_sample_sandbox(reg, name="flag-ood-term")
        reg.close()

        # 1. Valid confirmed row alone -> healthy, excluded from summary and count
        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                """
                INSERT INTO external_transport_bindings
                (sandbox_addr, incarnation_id, owner_id, abort_requested, terminal_confirmed,
                 reason, created_at, updated_at)
                VALUES ('flag-valid', ?, 'own-v', 1, 1, 'cleanly-done', 10.0, 20.0)
                """,
                (_DEFAULT_INC,),
            )
        finally:
            raw.close()

        svc = self._new_service(live_degraded_checker=lambda: False)
        tree_clean = svc.get_workspace_tree(_OP_CALLER)
        self.assertEqual(tree_clean.health.health_status, HEALTH_HEALTHY)
        self.assertEqual(tree_clean.health.unconfirmed_bindings_count, 0)
        self.assertEqual(tree_clean.health.unconfirmed_bindings, ())

        # 2. Confirmed row with malformed abort_requested (2 MiB BLOB) -> independently qualifies!
        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                """
                INSERT INTO external_transport_bindings
                (sandbox_addr, incarnation_id, owner_id, abort_requested, terminal_confirmed,
                 reason, created_at, updated_at)
                VALUES ('flag-mal-abort', ?, 'own-m', ?, 1, 'bad-abort', 10.0, 20.0)
                """,
                (_DEFAULT_INC, sqlite3.Binary(b"B" * (2 * 1024 * 1024))),
            )
        finally:
            raw.close()

        tree_mal = svc.get_workspace_tree(_OP_CALLER)
        self.assertEqual(tree_mal.health.health_status, HEALTH_DEGRADED)
        self.assertEqual(tree_mal.health.unconfirmed_bindings_count, 1)
        self.assertEqual(len(tree_mal.health.unconfirmed_bindings), 1)
        self.assertEqual(tree_mal.health.unconfirmed_bindings[0].sandbox_addr, _SB_FLAG_MAL_ABORT)
        self.assertTrue(tree_mal.health.unconfirmed_bindings[0].malformed_metadata)
        self.assertLess(len(serialize_projection_bytes(tree_mal)), 4096)

        # 3. Row with out-of-domain terminal_confirmed = 2 -> independently qualifies!
        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                """
                INSERT INTO external_transport_bindings
                (sandbox_addr, incarnation_id, owner_id, abort_requested, terminal_confirmed,
                 reason, created_at, updated_at)
                VALUES ('flag-ood-term', ?, 'own-o', 0, 2, 'ood-term', 10.0, 20.0)
                """,
                (_DEFAULT_INC,),
            )
        finally:
            raw.close()

        tree_both = svc.get_workspace_tree(_OP_CALLER)
        self.assertEqual(tree_both.health.health_status, HEALTH_DEGRADED)
        self.assertEqual(tree_both.health.unconfirmed_bindings_count, 2)
        addrs = [b.sandbox_addr for b in tree_both.health.unconfirmed_bindings]
        self.assertEqual(addrs, [_SB_FLAG_MAL_ABORT, "flag-ood-term"])
        self.assertTrue(all(b.malformed_metadata for b in tree_both.health.unconfirmed_bindings))
        # Valid confirmed row remains excluded
        self.assertNotIn("flag-valid", addrs)


class TestBoundsCursorsDeadlinesAndConcurrency(ProjectionBaseTest):
    """Section 9.4: hard byte bounds, SQL cell caps, cursors, deadlines, close, WAL."""

    def test_1kib_response_budget_escape_heavy_and_utf8_truncation(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="esc-a")
        payload = ('"\\"\n\u2603' * 400)
        _insert_verified_operator_message(
            reg,
            sandbox_addr="esc-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg:esc:1",
            body_text=payload,
        )
        reg.close()

        svc = self._new_service()
        page = svc.get_thread_events(
            _OP_CALLER,
            target="esc-a",
            thread_id=_DEFAULT_THREAD,
            limit=50,
            max_response_bytes=1024,
        )
        raw_bytes = serialize_projection_bytes(page)
        self.assertLessEqual(len(raw_bytes), 1024)
        self.assertEqual(len(page.events), 1)
        self.assertTrue(page.events[0].text_truncated)
        # Verify valid UTF-8 and valid strict JSON
        parsed = json.loads(raw_bytes.decode("utf-8"))
        self.assertEqual(parsed["schema_version"], PROJECTION_SCHEMA_VERSION)

    def test_budget_too_small_for_first_item_raises_validation_error(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="tiny-a")
        reg.close()
        svc = self._new_service()
        # With long read_session_id, 1024 B can fit empty page or fail cleanly on sandbox item
        with self.assertRaises(CoordValidationError):
            svc.get_workspace_tree(_OP_CALLER, max_response_bytes=512)

    def test_long_project_ids_oversize_isolation_colons_and_same_seq_pagination(
        self,
    ) -> None:
        reg = self._new_registry()
        prefix_260 = "p" * 260
        proj_a = f"{prefix_260}:alpha:" + ("x" * 1800)  # ~2 KiB with ':'
        proj_b = f"{prefix_260}:beta:" + ("y" * 1800)   # distinct >256B sharing 260B prefix!
        _register_sample_sandbox(reg, name="sb-1", incarnation_id="inc:1:a", project_id=proj_a)
        _register_sample_sandbox(reg, name="sb-2", incarnation_id="inc:2:b", project_id=proj_b)
        _register_sample_sandbox(reg, name="sb-3", incarnation_id="inc:3:c", project_id="short")
        reg.close()

        # Inject > 4 KiB project_id directly on sb-3 to test SQL oversize isolation
        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                "UPDATE sandboxes SET project_id = ? WHERE sandbox_addr = 'sb-3'",
                ("Z" * 10_000,),
            )
            # Also craft identical seq=500 in BOTH event_log and stream_events on sb-1!
            raw.execute(
                """
                INSERT INTO event_log
                (seq, msg_id, src_role, src_actor, src_incarnation, dst_addr, dst_thread_id,
                 dst_incarnation, trust_class, msg_kind, body_text, body_sha256, edge_id,
                 edge_turn_seq, in_reply_to, artifact_refs_json, created_at)
                VALUES (500, 'msg:colon:500', 'operator', 'operator:op-main', NULL,
                        'sb-1', 'main', 'inc:1:a', 'OPERATOR_DIRECTIVE', 'prompt',
                        'hello-500', ?, 'edge:1', 1, NULL, '[]', 10.0)
                """,
                (sha256_canonical_body("hello-500"),),
            )
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (500, 'text_delta', 'sb-1', 'inc:1:a', 'main', 1,
                        NULL, 'msg:colon:500', 'stream-500', NULL, '{}', NULL, 11.0)
                """
            )
        finally:
            raw.close()

        svc = self._new_service()
        # Full tree: proj_a and proj_b MUST remain separate groups; sb-3 isolated oversize!
        full = svc.get_workspace_tree(_OP_CALLER, sandbox_limit=50)
        self.assertEqual(len(full.projects), 3)
        by_sb = {g.sandboxes[0].sandbox_addr: g for g in full.projects}
        self.assertNotEqual(by_sb["sb-1"].project_id_sha256, by_sb["sb-2"].project_id_sha256)
        self.assertTrue(by_sb["sb-1"].project_id_truncated)
        self.assertTrue(by_sb["sb-2"].project_id_truncated)
        self.assertIsNone(by_sb["sb-3"].project_id_sha256)
        self.assertTrue(by_sb["sb-3"].malformed_metadata)

        # Paginate tree with sandbox_limit=1 -> all 3 sandboxes with zero skips/dupes
        seen_sbs: list[str] = []
        cursor: str | None = None
        while True:
            page = svc.get_workspace_tree(_OP_CALLER, sandbox_limit=1, after_cursor=cursor)
            for grp in page.projects:
                for node in grp.sandboxes:
                    seen_sbs.append(node.sandbox_addr)
            if not page.has_more:
                self.assertIsNone(page.next_cursor)
                break
            cursor = page.next_cursor
        self.assertEqual(seen_sbs, ["sb-1", "sb-2", "sb-3"])

        # Paginate events with limit=1 across same-seq (500, rank=0) and (500, rank=1)!
        seen_ev: list[tuple[int, int]] = []
        ev_cursor: str | None = None
        while True:
            ev_page = svc.get_thread_events(
                _OP_CALLER,
                target="sb-1",
                thread_id=_DEFAULT_THREAD,
                limit=1,
                after_cursor=ev_cursor,
            )
            for ev in ev_page.events:
                seen_ev.append((ev.seq, ev.source_rank))
            if not ev_page.has_more:
                self.assertIsNone(ev_page.next_cursor)
                break
            ev_cursor = ev_page.next_cursor
        self.assertEqual(seen_ev, [(500, 0), (500, 1)])

    def test_oversized_cells_and_binding_identities_sql_gated(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="big-a")
        reg.close()
        big_text = "A" * (2 * 1024 * 1024)
        big_json = '{"k":"' + ("J" * (2 * 1024 * 1024)) + '"}'
        big_id = "id-" + ("9" * 400)
        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (10, 'text_delta', 'big-a', ?, 'main', 1, NULL, NULL, ?, NULL, ?, NULL, 10.0)
                """,
                (_DEFAULT_INC, big_text, big_json),
            )
            raw.execute(
                """
                INSERT INTO external_transport_bindings
                (sandbox_addr, incarnation_id, owner_id, abort_requested, terminal_confirmed,
                 reason, created_at, updated_at)
                VALUES (?, ?, 'own', 1, 0, 'huge-id', 10.0, 20.0)
                """,
                (big_id, big_id),
            )
        finally:
            raw.close()

        svc = self._new_service()
        tree = svc.get_workspace_tree(_OP_CALLER)
        self.assertEqual(tree.health.unconfirmed_bindings_count, 1)
        b = tree.health.unconfirmed_bindings[0]
        self.assertIsNone(b.sandbox_addr)
        self.assertIsNone(b.incarnation_id)
        self.assertTrue(b.malformed_identity)

        ev_page = svc.get_thread_events(_OP_CALLER, target="big-a", thread_id=_DEFAULT_THREAD)
        self.assertEqual(len(ev_page.events), 1)
        ev = ev_page.events[0]
        self.assertEqual(ev.detail, {})
        self.assertTrue(ev.malformed_metadata)
        self.assertTrue(ev.text_truncated)
        self.assertTrue(ev.text_suffix_uninspected)
        self.assertLessEqual(len(ev.text.encode("utf-8")), MAX_ITEM_TEXT_BYTES)

    def test_cursor_scope_mismatch_and_non_canonical_rejected(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="cur-a")
        _register_sample_sandbox(reg, name="cur-b")
        reg.close()

        svc = self._new_service()
        p1 = svc.get_workspace_tree(_OP_CALLER, include_revoked=True, sandbox_limit=1)
        self.assertIsNotNone(p1.next_cursor)

        # Different filter on same op -> cursor_scope_mismatch
        with self.assertRaisesRegex(CoordValidationError, "cursor_scope_mismatch"):
            svc.get_workspace_tree(
                _OP_CALLER, include_revoked=False, after_cursor=p1.next_cursor
            )

        # Cross-operation reuse (tree cursor on mailbox) -> cursor_scope_mismatch
        with self.assertRaisesRegex(CoordValidationError, "cursor_scope_mismatch"):
            svc.get_sandbox_mailbox(_OP_CALLER, target="cur-a", after_cursor=p1.next_cursor)

        # Non-canonical base64 padding -> cursor_malformed
        bad_padded = f"{p1.next_cursor}=="
        with self.assertRaisesRegex(CoordValidationError, _ERR_CURSOR_MALFORMED):
            svc.get_workspace_tree(_OP_CALLER, after_cursor=bad_padded)

        # NaN inside cursor JSON -> cursor_malformed
        nan_b64 = base64.urlsafe_b64encode(b'{"fh":"0123456789abcdef","op":"tree","x":NaN}').decode(
            "ascii"
        ).rstrip("=")
        with self.assertRaisesRegex(CoordValidationError, _ERR_CURSOR_MALFORMED):
            svc.get_workspace_tree(_OP_CALLER, after_cursor=f"v1.{nan_b64}")

        # Unknown field -> cursor_malformed
        extra = encode_cursor({"op": "tree", "fh": "0123456789abcdef", "addr": "cur-a", "z": 1})
        with self.assertRaises(CoordValidationError):
            svc.get_workspace_tree(_OP_CALLER, after_cursor=extra)

    def test_write_lock_contention_and_umask_lock_and_uri_failure_and_progress_deadline(
        self,
    ) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="dl-a")
        reg.close()
        svc = self._new_service()
        db_path = self.state_dir / _DB_NAME

        # 1. Held EXCLUSIVE lock aborts within deadline (<< 500 ms)
        locker = _open_raw_rw(self.state_dir)
        locker.execute("PRAGMA locking_mode = EXCLUSIVE")
        locker.execute("BEGIN EXCLUSIVE")
        locker.execute("UPDATE seq_counter SET last_seq = last_seq WHERE id = 1")
        try:
            t0 = time.monotonic()
            with self.assertRaisesRegex(CoordPolicyError, _ERR_DEADLINE):
                svc.get_workspace_tree(_OP_CALLER, max_read_ms=50)
            self.assertLess(time.monotonic() - t0, 0.5)
        finally:
            locker.execute("ROLLBACK")
            locker.execute("PRAGMA locking_mode = NORMAL")
            locker.close()

        # 2. Held _UMASK_LOCK past max_read_ms=50 -> zero calls to sqlite3.connect!
        held = threading.Event()
        release = threading.Event()

        def _hold_umask() -> None:
            _UMASK_LOCK.acquire()
            try:
                held.set()
                release.wait(timeout=2.0)
            finally:
                _UMASK_LOCK.release()

        holder = threading.Thread(target=_hold_umask)
        holder.start()
        held.wait(timeout=1.0)
        try:
            with mock.patch(_PATCH_DB_CONNECT) as mock_connect:
                with self.assertRaisesRegex(CoordPolicyError, _ERR_DEADLINE):
                    svc.get_workspace_tree(_OP_CALLER, max_read_ms=50)
                mock_connect.assert_not_called()
        finally:
            release.set()
            holder.join(timeout=2.0)

        # 3. URI construction failure (surrogate-escaped path) NEVER strands _UMASK_LOCK!
        surrogate_raw = os.fsencode(str(self.root / "bad")) + b"\xffpath/" + _DB_NAME.encode("ascii")
        surrogate_path = Path(os.fsdecode(surrogate_raw))
        dl_surrogate = time.monotonic() + 2.0

        def _open_surrogate() -> None:
            with open_readonly_snapshot(surrogate_path, deadline=dl_surrogate):
                self.fail("expected surrogate path URI failure")

        with self.assertRaisesRegex(CoordPolicyError, _ERR_UNREADABLE):
            _open_surrogate()
        acquired = {"ok": False}

        def _probe_lock() -> None:
            if _UMASK_LOCK.acquire(timeout=0.5):
                acquired["ok"] = True
                _UMASK_LOCK.release()

        probe = threading.Thread(target=_probe_lock)
        probe.start()
        probe.join(timeout=1.0)
        self.assertTrue(acquired["ok"])

        # 4. Large slow query aborts promptly via SQLite VM progress handler
        t0 = time.monotonic()
        dl_slow = t0 + 0.05

        def _run_slow_query() -> None:
            with open_readonly_snapshot(db_path, deadline=dl_slow) as conn:
                conn.execute(
                    "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < 50000000) "
                    "SELECT SUM(x) FROM cnt"
                ).fetchone()

        with self.assertRaisesRegex(CoordPolicyError, _ERR_DEADLINE):
            _run_slow_query()
        self.assertLess(time.monotonic() - t0, 1.0)

    def test_connection_closed_on_success_anchor_failure_and_timeout(self) -> None:
        reg = self._new_registry()
        reg.close()
        db_path = self.state_dir / _DB_NAME

        # Normal return closes connection immediately
        leaked: list[sqlite3.Connection] = []
        with open_readonly_snapshot(db_path, deadline=time.monotonic() + 2.0) as conn:
            leaked.append(conn)
        with self.assertRaises(sqlite3.ProgrammingError):
            leaked[0].execute("SELECT 1")

        # Anchor failure (missing seq_counter table) closes connection cleanly
        broken_dir = self.root / "broken_state"
        broken_dir.mkdir(mode=0o700)
        os.chmod(broken_dir, 0o700)
        broken_db = broken_dir / _DB_NAME
        bconn = sqlite3.connect(str(broken_db))
        bconn.execute("CREATE TABLE other (id INTEGER)")
        bconn.commit()
        bconn.close()
        os.chmod(broken_db, 0o600)

        opened: list[sqlite3.Connection] = []
        real_connect = sqlite3.connect

        def _spy_connect(*args, **kwargs):
            c = real_connect(*args, **kwargs)
            opened.append(c)
            return c

        dl_broken = time.monotonic() + 2.0

        def _open_broken() -> None:
            with open_readonly_snapshot(broken_db, deadline=dl_broken):
                self.fail("expected missing seq_counter anchor failure")

        with (
            mock.patch(_PATCH_DB_CONNECT, side_effect=_spy_connect),
            self.assertRaisesRegex(CoordPolicyError, _ERR_UNREADABLE),
        ):
            _open_broken()
        self.assertEqual(len(opened), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1")

    def test_concurrent_wal_writer_does_not_tear_snapshot(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="wal-a")
        reg.close()
        db_path = self.state_dir / _DB_NAME

        with open_readonly_snapshot(db_path, deadline=time.monotonic() + 2.0) as conn:
            seq_before = conn.execute(_SQL_LAST_SEQ).fetchone()[
                "last_seq"
            ]
            # Concurrent writer mutates sandboxes + routing_edges + outbox
            reg2 = self._new_registry()
            try:
                _register_sample_sandbox(reg2, name="wal-b")
            finally:
                reg2.close()
            # Snapshot inside open transaction MUST still see pre-mutation state!
            addrs = [
                r["sandbox_addr"]
                for r in conn.execute("SELECT sandbox_addr FROM sandboxes ORDER BY sandbox_addr")
            ]
            seq_after = conn.execute(_SQL_LAST_SEQ).fetchone()[
                "last_seq"
            ]
            self.assertEqual(addrs, ["wal-a"])
            self.assertEqual(seq_after, seq_before)


class TestProvenanceAndHostileDatabaseDefense(ProjectionBaseTest):
    """Section 9.5: strict per-event provenance, TEXT vs BLOB, swapped badges, TUI, JSON."""

    def test_multiline_normal_text_nul_blob_and_beyond_preview_suffix(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="txt-a")
        _insert_verified_operator_message(
            reg,
            sandbox_addr="txt-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-multi",
            body_text="line1\n\tline2\r\nline3",
        )
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            # Embedded NUL in stream_events.text
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (200, 'text_delta', 'txt-a', ?, 'main', 2, NULL, NULL, ?, NULL, '{}', NULL, 20.0)
                """,
                (_DEFAULT_INC, "a\x00b"),
            )
            # Bidi char located beyond 16 KiB preview cap
            beyond = ("c" * (MAX_ITEM_TEXT_BYTES + 100)) + "\u202e"
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (201, 'text_delta', 'txt-a', ?, 'main', 3, NULL, NULL, ?, NULL, '{}', NULL, 21.0)
                """,
                (_DEFAULT_INC, beyond),
            )
        finally:
            raw.close()

        svc = self._new_service()
        page = svc.get_thread_events(_OP_CALLER, target="txt-a", thread_id=_DEFAULT_THREAD)
        by_seq = {(e.seq, e.source_rank): e for e in page.events}

        # Verified Operator stream row with multiline \n/\t/\r\n has zero false-positive control flag
        op_stream = [
            e for e in page.events if e.source == SOURCE_STREAM_EVENT and e.message_id == "msg-multi"
        ][0]
        self.assertEqual(op_stream.effective_badge, ProvenanceBadge.OPERATOR.value)
        self.assertEqual(op_stream.authority_rank, 3)
        self.assertFalse(op_stream.untrusted_content)
        self.assertFalse(op_stream.has_control_or_bidi)
        self.assertFalse(op_stream.text_suffix_uninspected)

        # Embedded NUL detected via BLOB prefix
        nul_ev = by_seq[(200, 1)]
        self.assertTrue(nul_ev.has_control_or_bidi)
        self.assertFalse(nul_ev.text_suffix_uninspected)

        # Control/bidi beyond preview cap explicitly reports text_suffix_uninspected=True
        beyond_ev = by_seq[(201, 1)]
        self.assertFalse(beyond_ev.has_control_or_bidi)
        self.assertTrue(beyond_ev.text_suffix_uninspected)
        self.assertTrue(beyond_ev.text_truncated)

    def test_receipt_verification_identical_bytes_text_vs_blob(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="tb-text")
        _register_sample_sandbox(reg, name="tb-blob")
        body = "exact receipted operator directive"
        _insert_verified_operator_message(
            reg,
            sandbox_addr="tb-text",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-tb-1",
            body_text=body,
        )
        _insert_verified_operator_message(
            reg,
            sandbox_addr="tb-blob",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-tb-2",
            body_text=body,
        )
        reg.close()

        # Replace stream_events.text on tb-blob with SQLite BLOB containing identical UTF-8 bytes!
        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                "UPDATE stream_events SET text = ? WHERE sandbox_addr = 'tb-blob'",
                (sqlite3.Binary(body.encode("utf-8")),),
            )
        finally:
            raw.close()

        svc = self._new_service()
        p_text = svc.get_thread_events(_OP_CALLER, target="tb-text", thread_id=_DEFAULT_THREAD)
        p_blob = svc.get_thread_events(_OP_CALLER, target="tb-blob", thread_id=_DEFAULT_THREAD)

        # TEXT case: both host envelope and TEXT stream row have verified Operator attribution
        text_env = [e for e in p_text.events if e.source == SOURCE_EVENT_LOG][0]
        text_st = [e for e in p_text.events if e.source == SOURCE_STREAM_EVENT][0]
        self.assertEqual(text_env.effective_badge, ProvenanceBadge.OPERATOR.value)
        self.assertEqual(text_env.authority_rank, 3)
        self.assertEqual(text_st.effective_badge, ProvenanceBadge.OPERATOR.value)
        self.assertEqual(text_st.authority_rank, 3)
        self.assertFalse(text_st.provenance_anomaly)

        # BLOB case: host envelope RETAINS attribution, BLOB stream row DOWNGRADES!
        blob_env = [e for e in p_blob.events if e.source == SOURCE_EVENT_LOG][0]
        blob_st = [e for e in p_blob.events if e.source == SOURCE_STREAM_EVENT][0]
        self.assertEqual(blob_env.effective_badge, ProvenanceBadge.OPERATOR.value)
        self.assertEqual(blob_env.authority_rank, 3)
        self.assertEqual(blob_st.effective_badge, ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)
        self.assertEqual(blob_st.authority_rank, 0)
        self.assertTrue(blob_st.provenance_anomaly)
        self.assertEqual(blob_st.anomaly_reason, _ERR_BODY_HASH)
        self.assertTrue(blob_st.malformed_metadata)

    def test_swapped_badge_full_tuple_ambiguity_vs_spoofed_body_replay(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="amb-a")
        _register_sample_sandbox(reg, name="spoof-a")
        body = "run security audit"
        _insert_verified_operator_message(
            reg,
            sandbox_addr="amb-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-amb-1",
            body_text=body,
        )
        _insert_verified_operator_message(
            reg,
            sandbox_addr="spoof-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-spoof-1",
            body_text=body,
        )
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            # amb-a: swap badge off original row and insert second full-5-tuple match with Operator badge
            raw.execute(
                "UPDATE stream_events SET badge = ? WHERE sandbox_addr = 'amb-a'",
                (ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value,),
            )
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (900, 'user_message', 'amb-a', ?, 'main', 9,
                        'msg-amb-1', 'msg-amb-1', ?, NULL, '{}', ?, 99.0)
                """,
                (_DEFAULT_INC, body, ProvenanceBadge.OPERATOR.value),
            )
            # spoof-a: insert replay of message_id with DIFFERENT spoofed body
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (901, 'user_message', 'spoof-a', ?, 'main', 9,
                        'msg-spoof-1', 'msg-spoof-1', 'spoofed body', NULL, '{}', ?, 99.0)
                """,
                (_DEFAULT_INC, ProvenanceBadge.OPERATOR.value),
            )
        finally:
            raw.close()

        svc = self._new_service()
        # amb-a paginated with limit=1 across page boundaries: BOTH stream rows unverified, envelope stays Operator!
        amb_events = []
        cur = None
        while True:
            pg = svc.get_thread_events(
                _OP_CALLER, target="amb-a", thread_id=_DEFAULT_THREAD, limit=1, after_cursor=cur
            )
            amb_events.extend(pg.events)
            if not pg.has_more:
                break
            cur = pg.next_cursor

        amb_env = [e for e in amb_events if e.source == SOURCE_EVENT_LOG][0]
        amb_streams = [e for e in amb_events if e.source == SOURCE_STREAM_EVENT]
        self.assertEqual(amb_env.effective_badge, ProvenanceBadge.OPERATOR.value)
        self.assertEqual(amb_env.authority_rank, 3)
        self.assertEqual(len(amb_streams), 2)
        for st in amb_streams:
            self.assertEqual(st.effective_badge, ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)
            self.assertEqual(st.authority_rank, 0)
        self.assertEqual(amb_streams[1].anomaly_reason, "ambiguous_receipt_match")

        # spoof-a: genuine row KEEPS Operator, spoofed row downgrades!
        sp_page = svc.get_thread_events(_OP_CALLER, target="spoof-a", thread_id=_DEFAULT_THREAD)
        sp_streams = [e for e in sp_page.events if e.source == SOURCE_STREAM_EVENT]
        self.assertEqual(len(sp_streams), 2)
        self.assertEqual(sp_streams[0].effective_badge, ProvenanceBadge.OPERATOR.value)
        self.assertEqual(sp_streams[0].authority_rank, 3)
        self.assertEqual(
            sp_streams[1].effective_badge, ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value
        )
        self.assertEqual(sp_streams[1].anomaly_reason, _ERR_BODY_HASH)

    def test_conflicting_receipts_missing_message_id_oversize_tui_and_non_user_badge(
        self,
    ) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="prov-a")
        _insert_verified_operator_message(
            reg,
            sandbox_addr="prov-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-conf",
            body_text="original",
        )
        # Mint and consume a real TUI token on live incarnation -> TUI_INPUT still ALWAYS downgrades!
        tui_tok = reg.mint_tui_enter_token("prov-a", _DEFAULT_INC, "opencode-tui")
        reg.consume_tui_enter_token(tui_tok, "prov-a", _DEFAULT_INC, "opencode-tui")
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            # Conflicting second consumed receipt on same 4-tuple
            raw.execute(
                """
                INSERT INTO dispatch_receipts
                (sandbox_addr, incarnation_id, session_id, message_id, body_sha256,
                 badge, src_actor, trust_class, consumed_at)
                VALUES ('prov-a', ?, 'main', 'msg-conf', ?, 'Operator',
                        'operator:op-main', 'OPERATOR_DIRECTIVE', 50.0)
                """,
                (_DEFAULT_INC, sha256_canonical_body("different")),
            )
            # message_id=None with valid dispatch_msg_id -> unbacked_host_badge
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (300, 'user_message', 'prov-a', ?, 'main', 2,
                        NULL, 'msg-conf', 'original', NULL, '{}', 'Operator', 30.0)
                """,
                (_DEFAULT_INC,),
            )
            # TUI_INPUT row (1 token, 1 event on live incarnation) -> ALWAYS downgraded!
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (301, 'user_message', 'prov-a', ?, 'main', 3,
                        NULL, NULL, 'typed in tui', NULL, '{}', ?, 31.0)
                """,
                (_DEFAULT_INC, ProvenanceBadge.TUI_INPUT.value),
            )
            # Non-user event carrying a badge -> cleared + non_user_event_has_badge
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (302, 'text_delta', 'prov-a', ?, 'main', 4,
                        NULL, NULL, 'delta', NULL, '{}', 'Operator', 32.0)
                """,
                (_DEFAULT_INC,),
            )
        finally:
            raw.close()

        svc = self._new_service()
        page = svc.get_thread_events(_OP_CALLER, target="prov-a", thread_id=_DEFAULT_THREAD)
        st_by_seq = {e.seq: e for e in page.events if e.source == SOURCE_STREAM_EVENT}

        conf_ev = [e for e in st_by_seq.values() if e.message_id == "msg-conf"][0]
        self.assertEqual(conf_ev.anomaly_reason, "ambiguous_receipt_match")
        self.assertEqual(st_by_seq[300].anomaly_reason, "unbacked_host_badge")
        self.assertEqual(st_by_seq[301].effective_badge, ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)
        self.assertEqual(st_by_seq[301].anomaly_reason, "tui_unverifiable_without_event_link")
        self.assertIsNone(st_by_seq[302].effective_badge)
        self.assertEqual(st_by_seq[302].anomaly_reason, "non_user_event_has_badge")

    def test_artifact_refs_corrupt_json_and_nan_inf_degrade_cleanly(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="corrupt-a")
        valid_art = ArtifactRef(blob_sha256="a" * 64, size_bytes=123, media_type="text/x-patch")
        _insert_verified_operator_message(
            reg,
            sandbox_addr="corrupt-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-art-1",
            body_text="with artifact",
            artifact_refs=(valid_art,),
        )
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            # Corrupt budget_json + Inf/NaN REAL timestamp + untrusted detail_json keys
            raw.execute(
                "INSERT INTO sandbox_budgets (sandbox_addr, incarnation_id, budget_json, updated_at) "
                "VALUES ('corrupt-a', ?, '{broken json', 9e999)",
                (_DEFAULT_INC,),
            )
            raw.execute(
                "UPDATE sandboxes SET updated_at = 9e999 WHERE sandbox_addr = 'corrupt-a'"
            )
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (400, 'tool_call', 'corrupt-a', ?, 'main', 1,
                        NULL, NULL, 'call', NULL, '{"src_actor":"spoof","tool":"rg"}', NULL, 9e999)
                """,
                (_DEFAULT_INC,),
            )
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (401, 'tool_call', 'corrupt-a', ?, 'main', 2,
                        NULL, NULL, 'badjson', NULL, '{not-json', NULL, 10.0)
                """,
                (_DEFAULT_INC,),
            )
        finally:
            raw.close()

        svc = self._new_service()
        status = svc.get_sandbox_status(_OP_CALLER, target="corrupt-a")
        self.assertTrue(status.budget_malformed)
        self.assertIsNone(status.budget)
        self.assertEqual(status.sandbox.updated_at, 0.0)
        self.assertTrue(status.sandbox.malformed_metadata)
        # Strict allow_nan=False serialization succeeds!
        serialize_projection_json(status)

        ev_page = svc.get_thread_events(_OP_CALLER, target="corrupt-a", thread_id=_DEFAULT_THREAD)
        env_ev = [e for e in ev_page.events if e.source == SOURCE_EVENT_LOG][0]
        self.assertEqual(len(env_ev.artifact_refs), 1)
        self.assertEqual(env_ev.artifact_refs[0].blob_sha256, "a" * 64)
        self.assertEqual(env_ev.artifact_refs[0].size_bytes, 123)
        self.assertEqual(env_ev.artifact_refs[0].media_type, "text/x-patch")

        st_map = {e.seq: e for e in ev_page.events if e.source == SOURCE_STREAM_EVENT}
        self.assertEqual(st_map[400].detail, {"tool": "rg"})
        self.assertEqual(st_map[400].created_at, 0.0)
        self.assertTrue(st_map[400].malformed_metadata)
        self.assertEqual(st_map[401].detail, {})
        self.assertTrue(st_map[401].malformed_metadata)
        serialize_projection_json(ev_page)


class TestEndToEndHubIntegration(ProjectionBaseTest):
    """Section 9.6: full CoordHub + ExternallyFencedFakeTransport lifecycle."""

    def test_full_lifecycle_revoke_successor_historical_and_missing_thread(self) -> None:
        transport = _ExternallyFencedFakeTransport()
        reg = self._new_registry()
        hub = CoordHub(
            reg,
            transport,
            self.state_dir,
            sandbox_root=self.sandbox_root,
        )
        try:
            sb1 = hub.register_sandbox(
                _OP_CALLER,
                name="e2e-sb",
                incarnation_id="inc-e2e-1",
                project_id="proj-e2e",
                project_name="E2E Project",
                branch="feat/m3",
                sandbox_type=_DEFAULT_TYPE,
                task_brief="Run end-to-end projection test",
                child_budget=SubtreeBudget(max_depth_remaining=1),
            )
            hub.grant_edge(
                _OP_CALLER,
                src_actor=_OP_CALLER.canonical_sender,
                dst_addr=sb1.sandbox_addr,
                allowed_threads=(_DEFAULT_THREAD,),
                allowed_msg_kinds=("prompt",),
            )
            hub.send(
                _OP_CALLER,
                target=sb1.sandbox_addr,
                thread_id=_DEFAULT_THREAD,
                msg_kind="prompt",
                body_text="hello e2e",
            )
            hub.dispatch_once(async_stream=False)

            svc = self._new_service(live_degraded_checker=lambda: False)
            tree = svc.get_workspace_tree(_OP_CALLER)
            self.assertEqual(tree.health.health_status, HEALTH_HEALTHY)
            self.assertEqual(len(tree.projects), 1)
            node = tree.projects[0].sandboxes[0]
            self.assertEqual(node.sandbox_addr, "e2e-sb")
            self.assertEqual(node.active_grant_count, 1)

            status = svc.get_sandbox_status(_OP_CALLER, target="e2e-sb")
            self.assertIsNotNone(status.budget)
            assert status.budget is not None
            self.assertEqual(status.budget.max_depth_remaining, 1)
            self.assertEqual(len(status.edges), 1)

            mb = svc.get_sandbox_mailbox(_OP_CALLER, target="e2e-sb", statuses=["completed"])
            self.assertEqual(len(mb.entries), 1)
            self.assertEqual(mb.entries[0].status, "completed")

            # Non-existent thread on existing sandbox returns empty page with thread_exists=False
            missing_th = svc.get_thread_events(
                _OP_CALLER, target="e2e-sb", thread_id="no-such-thread"
            )
            self.assertFalse(missing_th.thread_exists)
            self.assertEqual(missing_th.events, ())

            # Non-existent sandbox raises CoordPolicyError("sandbox_not_found")
            with self.assertRaisesRegex(CoordPolicyError, "sandbox_not_found"):
                svc.get_sandbox_status(_OP_CALLER, target="ghost-sb")

            # Revoke sb1, restart hub, then register fresh same-address successor sb2
            hub.revoke(_OP_CALLER, target="e2e-sb", reason="rotate")
            hub.close()
            hub = CoordHub(
                reg,
                transport,
                self.state_dir,
                sandbox_root=self.sandbox_root,
            )
            sb2 = hub.register_sandbox(
                _OP_CALLER,
                name="e2e-sb",
                incarnation_id="inc-e2e-2",
                project_id="proj-e2e",
                project_name="E2E Project",
                branch="feat/m3",
                sandbox_type=_DEFAULT_TYPE,
                task_brief="Fresh successor",
            )
            self.assertNotEqual(sb1.incarnation_id, sb2.incarnation_id)

            # Historical incarnation query returns sb1 events with stale_reason="superseded_incarnation"
            hist = svc.get_thread_events(
                _OP_CALLER,
                target="e2e-sb",
                thread_id=_DEFAULT_THREAD,
                incarnation_id=sb1.incarnation_id,
            )
            self.assertFalse(hist.is_current_incarnation)
            self.assertEqual(hist.stale_reason, "superseded_incarnation")
            self.assertGreaterEqual(len(hist.events), 2)

            # Audit chain remains completely intact after all projection reads!
            ok, count = reg.verify_audit_chain()
            self.assertTrue(ok)
            self.assertGreater(count, 0)
        finally:
            hub.close()
            reg.close()

    def test_oversize_and_nul_host_badged_stream_text_downgrade_cleanly(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="tamper-a")
        _insert_verified_operator_message(
            reg,
            sandbox_addr="tamper-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id=_MSG_OVERSIZE,
            body_text="short-ok",
        )
        _insert_verified_operator_message(
            reg,
            sandbox_addr="tamper-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-nul",
            body_text="clean-ok",
        )
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                "UPDATE stream_events SET text = ? WHERE message_id = 'msg-oversize'",
                ("X" * 80_000,),
            )
            raw.execute(
                "UPDATE stream_events SET text = ? WHERE message_id = 'msg-nul'",
                ("clean\x00ok",),
            )
        finally:
            raw.close()

        svc = self._new_service()
        page = svc.get_thread_events(_OP_CALLER, target="tamper-a", thread_id=_DEFAULT_THREAD)
        st_by_msg = {
            e.message_id: e for e in page.events if e.source == SOURCE_STREAM_EVENT
        }
        self.assertEqual(
            st_by_msg[_MSG_OVERSIZE].effective_badge,
            ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value,
        )
        self.assertEqual(
            st_by_msg[_MSG_OVERSIZE].anomaly_reason, _ERR_BODY_HASH
        )
        self.assertEqual(
            st_by_msg["msg-nul"].effective_badge,
            ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value,
        )
        self.assertEqual(
            st_by_msg["msg-nul"].anomaly_reason, _ERR_BODY_HASH
        )
        self.assertTrue(st_by_msg["msg-nul"].has_control_or_bidi)

    def test_mailbox_pagination_tombstones_and_1kib_detail_truncation(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="mb-a")
        _insert_verified_operator_message(
            reg,
            sandbox_addr="mb-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg:mb:1",
            body_text="first",
        )
        _insert_verified_operator_message(
            reg,
            sandbox_addr="mb-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg:mb:2",
            body_text="second",
        )
        reg.revoke_grant_and_cancel_outbox(
            edge_id="edge:mb-a:msg:mb:1", reason="revoked-for-test"
        )
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                "UPDATE outbox SET detail = ? WHERE msg_id = 'msg:mb:1'",
                ("D" * 900,),
            )
        finally:
            raw.close()

        svc = self._new_service()
        seen: list[str] = []
        cursor: str | None = None
        while True:
            pg = svc.get_sandbox_mailbox(
                _OP_CALLER,
                target="mb-a",
                limit=1,
                max_response_bytes=1024,
                after_cursor=cursor,
            )
            self.assertLessEqual(len(serialize_projection_bytes(pg)), 1024)
            for item in pg.entries:
                seen.append(item.msg_id)
                if item.msg_id == "msg:mb:1":
                    self.assertTrue(item.grant_tombstoned)
                    self.assertTrue(item.detail_truncated)
            if not pg.has_more:
                self.assertIsNone(pg.next_cursor)
                break
            cursor = pg.next_cursor
        self.assertEqual(seen, ["msg:mb:1", "msg:mb:2"])

    def test_sandbox_status_progressive_capping_and_envelope_overflow(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="cap-a")
        for idx in range(25):
            reg.grant_edge(
                RoutingEdge(
                    edge_id=f"edge-cap-{idx:02d}",
                    src_actor=_OP_CALLER.canonical_sender,
                    src_incarnation=None,
                    dst_addr="cap-a",
                    allowed_threads=frozenset({_DEFAULT_THREAD}),
                    allowed_msg_kinds=frozenset({"prompt"}),
                    created_at=time.time(),
                )
            )
        reg.close()

        svc = self._new_service()
        capped = svc.get_sandbox_status(
            _OP_CALLER, target="cap-a", max_response_bytes=1536
        )
        self.assertLessEqual(len(serialize_projection_bytes(capped)), 1536)
        self.assertTrue(capped.edges_truncated)
        self.assertLess(len(capped.edges), 25)

        # Valid >=1024 budget that cannot even fit the status envelope raises CoordValidationError
        svc_sess = self._new_service(session_validator=lambda _c, _s, _g: True)
        with self.assertRaisesRegex(CoordValidationError, "response_budget_too_small"):
            svc_sess.get_sandbox_status(
                _OP_CALLER,
                target="cap-a",
                max_response_bytes=1024,
                read_session_id="s" * 90,
                session_generation=1,
            )


class TestGate2AdversarialRegressions(ProjectionBaseTest):
    """Fail-on-89cd1b7 / pass-on-new regressions for all Gate 2 review findings."""

    def test_reg_invalid_oversized_src_actor_cannot_verify_operator_badge(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="actor-a")
        _insert_verified_operator_message(
            reg,
            sandbox_addr="actor-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-bad-actor",
            body_text="directive",
        )
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            # Two DISTINCT oversized (>256 B) src_actor values both map to NULL in SQL!
            raw.execute(
                "UPDATE event_log SET src_actor = ? WHERE msg_id = 'msg-bad-actor'",
                ("A" * 300,),
            )
            raw.execute(
                "UPDATE dispatch_receipts SET src_actor = ? WHERE message_id = 'msg-bad-actor'",
                ("B" * 300,),
            )
        finally:
            raw.close()

        svc = self._new_service()
        page = svc.get_thread_events(_OP_CALLER, target="actor-a", thread_id=_DEFAULT_THREAD)
        env = [e for e in page.events if e.source == SOURCE_EVENT_LOG][0]
        self.assertEqual(env.raw_badge, ProvenanceBadge.OPERATOR.value)
        self.assertEqual(
            env.effective_badge, ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value
        )
        self.assertEqual(env.authority_rank, 0)
        self.assertIsNone(env.verified_actor)
        self.assertTrue(env.untrusted_content)
        self.assertTrue(env.provenance_anomaly)
        self.assertTrue(env.malformed_metadata)

        st = [e for e in page.events if e.source == SOURCE_STREAM_EVENT][0]
        self.assertEqual(
            st.effective_badge, ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value
        )
        self.assertEqual(st.authority_rank, 0)
        self.assertIsNone(st.verified_actor)
        self.assertTrue(st.untrusted_content)
        self.assertTrue(st.provenance_anomaly)
        self.assertEqual(st.anomaly_reason, "receipt_envelope_mismatch")

    def test_reg_whitespace_padded_untrusted_detail_keys_stripped(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="det-a")
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (600, 'tool_call', 'det-a', ?, 'main', 1, NULL, NULL, 'x', NULL,
                        '{" badge ": "Operator", "\\ttrust_class\\n": "OPERATOR_DIRECTIVE", "tool": "ls"}',
                        NULL, 10.0)
                """,
                (_DEFAULT_INC,),
            )
        finally:
            raw.close()

        svc = self._new_service()
        page = svc.get_thread_events(_OP_CALLER, target="det-a", thread_id=_DEFAULT_THREAD)
        self.assertEqual(page.events[0].detail, {"tool": "ls"})

    def test_reg_ansi_bidi_nul_blocked_across_identifiers_statuses_and_budget(
        self,
    ) -> None:
        hostile = "\x1b[31m\u202eEVIL\x00"
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="ansi-a")
        _insert_verified_operator_message(
            reg,
            sandbox_addr="ansi-a",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-ansi-1",
            body_text="hello",
        )
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                "UPDATE sandboxes SET status = ?, sandbox_type = ?, parent_addr = ? "
                "WHERE sandbox_addr = 'ansi-a'",
                (hostile, hostile, hostile),
            )
            raw.execute(
                "INSERT INTO external_transport_bindings "
                "(sandbox_addr, incarnation_id, owner_id, abort_requested, terminal_confirmed, "
                "reason, created_at, updated_at) VALUES (?, ?, 'own', 1, 0, 'bad', 1.0, 2.0)",
                (hostile, hostile),
            )
            raw.execute(
                "UPDATE stream_events SET badge = ?, file_path = ? WHERE sandbox_addr = 'ansi-a'",
                (hostile, hostile),
            )
            raw.execute(
                "UPDATE event_log SET src_role = ?, src_actor = ?, msg_kind = ?, in_reply_to = ? "
                "WHERE msg_id = 'msg-ansi-1'",
                (hostile, hostile, hostile, hostile),
            )
            bad_budget = json.dumps(
                {
                    "max_depth_remaining": 1,
                    "max_children": 1,
                    "max_total_sandboxes": 2,
                    "allowed_workers": [hostile],
                    "allowed_sandbox_types": ["default"],
                    "allowed_models": None,
                    "allowed_variants": None,
                    "allowed_broker_routes": [],
                    "max_security_profile": "standard",
                }
            )
            raw.execute(
                "INSERT INTO sandbox_budgets (sandbox_addr, incarnation_id, budget_json, updated_at) "
                "VALUES ('ansi-a', ?, ?, 1.0)",
                (_DEFAULT_INC, bad_budget),
            )
        finally:
            raw.close()

        svc = self._new_service()
        status = svc.get_sandbox_status(_OP_CALLER, target="ansi-a")
        self.assertTrue(status.budget_malformed)
        self.assertIsNone(status.budget)
        self.assertEqual(status.sandbox.status, "unknown")
        self.assertIsNone(status.sandbox.parent_addr)
        self.assertTrue(status.health.unconfirmed_bindings[0].malformed_identity)
        self.assertIsNone(status.health.unconfirmed_bindings[0].sandbox_addr)

        ev_page = svc.get_thread_events(_OP_CALLER, target="ansi-a", thread_id=_DEFAULT_THREAD)
        mb_page = svc.get_sandbox_mailbox(_OP_CALLER, target="ansi-a")
        for snap in (status, ev_page, mb_page):
            wire = serialize_projection_json(snap)
            self.assertNotIn("\\u001b", wire)
            self.assertNotIn("\x1b", wire)
            self.assertNotIn("\u202e", wire)
            self.assertNotIn("\\u0000", wire)

    def test_reg_negative_seq_and_last_seq_fail_closed(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="neg-a")
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (-5, 'text_delta', 'neg-a', ?, 'main', 1, NULL, NULL, 'neg', NULL, '{}', NULL, 1.0)
                """,
                (_DEFAULT_INC,),
            )
        finally:
            raw.close()

        svc = self._new_service()
        with self.assertRaisesRegex(CoordPolicyError, _ERR_UNREADABLE):
            svc.get_thread_events(_OP_CALLER, target="neg-a", thread_id=_DEFAULT_THREAD, limit=1)

        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute("DELETE FROM stream_events WHERE seq < 0")
            raw.execute("UPDATE seq_counter SET last_seq = -1 WHERE id = 1")
        finally:
            raw.close()

        with self.assertRaisesRegex(CoordPolicyError, _ERR_UNREADABLE):
            svc.get_workspace_tree(_OP_CALLER)

    def test_reg_grant_and_outbox_counts_bounded_sql_aggregates(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="agg-a")
        edge_ok = reg.grant_edge(
            RoutingEdge(
                edge_id="edge-agg-ok",
                src_actor=_OP_CALLER.canonical_sender,
                src_incarnation=None,
                dst_addr="agg-a",
                allowed_threads=frozenset({_DEFAULT_THREAD}),
                allowed_msg_kinds=frozenset({"prompt"}),
                created_at=time.time(),
            )
        )
        edge_rev = reg.grant_edge(
            RoutingEdge(
                edge_id="edge-agg-rev",
                src_actor=_OP_CALLER.canonical_sender,
                src_incarnation=None,
                dst_addr="agg-a",
                allowed_threads=frozenset({_DEFAULT_THREAD}),
                allowed_msg_kinds=frozenset({"prompt"}),
                created_at=time.time(),
            )
        )
        reg.revoke_grant_and_cancel_outbox(edge_id=edge_rev.edge_id, reason="done")
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            for idx in range(50):
                mid = f"msg-bogus-{idx}"
                raw.execute(
                    """
                    INSERT INTO event_log
                    (seq, msg_id, src_role, src_actor, src_incarnation, dst_addr, dst_thread_id,
                     dst_incarnation, trust_class, msg_kind, body_text, body_sha256, edge_id,
                     edge_turn_seq, in_reply_to, artifact_refs_json, created_at)
                    VALUES (?, ?, 'operator', 'operator:op-main', NULL, 'agg-a', 'main', ?,
                            'OPERATOR_DIRECTIVE', 'prompt', 'x', ?, ?, 1, NULL, '[]', 1.0)
                    """,
                    (700 + idx, mid, _DEFAULT_INC, sha256_canonical_body("x"), edge_ok.edge_id),
                )
                raw.execute(
                    """
                    INSERT INTO outbox
                    (seq, msg_id, edge_id, lease_request_id, grant_generation, src_incarnation,
                     dst_incarnation, thread_id, priority, status, body_bytes, attempts,
                     stream_id, detail, updated_at)
                    VALUES (?, ?, ?, NULL, 1, NULL, ?, 'main', 0, ?, 1, 0, NULL, '', 1.0)
                    """,
                    (700 + idx, mid, edge_ok.edge_id, _DEFAULT_INC, f"bogus_status_{idx}"),
                )
        finally:
            raw.close()

        svc = self._new_service()
        status = svc.get_sandbox_status(_OP_CALLER, target="agg-a")
        self.assertEqual(status.sandbox.active_grant_count, 1)
        self.assertEqual(status.sandbox.revoked_grant_count, 1)
        self.assertEqual(status.sandbox.outbox_counts, {"malformed": 50})
        self.assertLessEqual(len(status.sandbox.outbox_counts), 8)

    def test_reg_deadline_expiry_during_final_serialization_aborts_and_closes_conn(
        self,
    ) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="clk-a")
        reg.close()

        opened: list[sqlite3.Connection] = []
        real_connect = sqlite3.connect
        real_serialize = oc_projection.serialize_projection_bytes
        clock = {"now": 1000.0}

        def _spy_connect(*args, **kwargs):
            c = real_connect(*args, **kwargs)
            opened.append(c)
            return c

        def _expiring_serialize(obj):
            res = real_serialize(obj)
            # Advance fake clock past the 200 ms budget during the final serialization!
            clock["now"] += 10.0
            return res

        svc = self._new_service()
        with (
            mock.patch(_PATCH_DB_CONNECT, side_effect=_spy_connect),
            mock.patch("oc_projection.time.monotonic", side_effect=lambda: clock["now"]),
            mock.patch("oc_projection_db.time.monotonic", side_effect=lambda: clock["now"]),
            mock.patch("oc_projection.serialize_projection_bytes", side_effect=_expiring_serialize),
            self.assertRaisesRegex(CoordPolicyError, _ERR_DEADLINE),
        ):
            svc.get_sandbox_status(_OP_CALLER, target="clk-a", max_read_ms=200)

        self.assertEqual(len(opened), 1)
        with self.assertRaises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1")

    def test_reg_json_recursion_error_and_budget_lone_surrogate_fallback(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="rec-a")
        reg.close()

        deep_json = ("[" * 2000) + ("]" * 2000)
        surrogate_budget = (
            '{"max_depth_remaining":1,"max_children":1,"max_total_sandboxes":2,'
            '"allowed_workers":["local\\ud800"],"allowed_sandbox_types":["default"],'
            '"allowed_models":null,"allowed_variants":null,"allowed_broker_routes":[],'
            '"max_security_profile":"standard"}'
        )
        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (800, 'tool_call', 'rec-a', ?, 'main', 1, NULL, NULL, 'deep', NULL, ?, NULL, 1.0)
                """,
                (_DEFAULT_INC, deep_json),
            )
            raw.execute(
                "INSERT INTO sandbox_budgets (sandbox_addr, incarnation_id, budget_json, updated_at) "
                "VALUES ('rec-a', ?, ?, 1.0)",
                (_DEFAULT_INC, surrogate_budget),
            )
        finally:
            raw.close()

        svc = self._new_service()
        status = svc.get_sandbox_status(_OP_CALLER, target="rec-a")
        self.assertTrue(status.budget_malformed)
        self.assertIsNone(status.budget)
        serialize_projection_bytes(status)

        ev_page = svc.get_thread_events(_OP_CALLER, target="rec-a", thread_id=_DEFAULT_THREAD)
        self.assertEqual(ev_page.events[0].detail, {})
        self.assertTrue(ev_page.events[0].malformed_metadata)
        serialize_projection_bytes(ev_page)

    def test_reg_cursor_sqlite_int64_boundary(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="i64-a")
        reg.close()

        svc = self._new_service()
        max_i64 = (1 << 63) - 1
        over_i64 = 1 << 63

        ev_scope = oc_projection.compute_scope_hash(
            "events", target="i64-a", thread_id=_DEFAULT_THREAD, incarnation_id=_DEFAULT_INC
        )
        ev_max = encode_cursor(
            {"op": "events", "fh": ev_scope, "seq": max_i64, "rank": 1, "inc": _DEFAULT_INC}
        )
        ev_over = encode_cursor(
            {"op": "events", "fh": ev_scope, "seq": over_i64, "rank": 1, "inc": _DEFAULT_INC}
        )
        pg_ok = svc.get_thread_events(
            _OP_CALLER, target="i64-a", thread_id=_DEFAULT_THREAD, after_cursor=ev_max
        )
        self.assertEqual(pg_ok.events, ())
        with self.assertRaisesRegex(CoordValidationError, _ERR_CURSOR_MALFORMED):
            svc.get_thread_events(
                _OP_CALLER, target="i64-a", thread_id=_DEFAULT_THREAD, after_cursor=ev_over
            )

        mb_scope = oc_projection.compute_scope_hash("mailbox", target="i64-a", statuses=None)
        mb_max = encode_cursor({"op": "mailbox", "fh": mb_scope, "seq": max_i64, "mid": "m1"})
        mb_over = encode_cursor({"op": "mailbox", "fh": mb_scope, "seq": over_i64, "mid": "m1"})
        mb_ok = svc.get_sandbox_mailbox(_OP_CALLER, target="i64-a", after_cursor=mb_max)
        self.assertEqual(mb_ok.entries, ())
        with self.assertRaisesRegex(CoordValidationError, _ERR_CURSOR_MALFORMED):
            svc.get_sandbox_mailbox(_OP_CALLER, target="i64-a", after_cursor=mb_over)

    def test_reg_case_sensitive_orchestrator_prefix_and_relative_state_dir(self) -> None:
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="src-sb")
        _register_sample_sandbox(reg, name="dst-sb")
        _insert_verified_operator_message(
            reg,
            sandbox_addr="dst-sb",
            incarnation_id=_DEFAULT_INC,
            thread_id=_DEFAULT_THREAD,
            msg_id="msg-case-1",
            body_text="hi",
        )
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            raw.execute(
                "UPDATE event_log SET src_actor = 'ORCHESTRATOR:src-sb' WHERE msg_id = 'msg-case-1'"
            )
        finally:
            raw.close()

        svc = self._new_service()
        mb = svc.get_sandbox_mailbox(_OP_CALLER, target="dst-sb")
        self.assertEqual(len(mb.entries), 1)
        self.assertIsNone(mb.entries[0].src_sandbox_status)

        # Relative state_dir traversing a user symlink followed by '..' must fail BEFORE SQLite opens!
        sym_rel = self.root / "sym_rel"
        os.symlink(self.state_dir, sym_rel)
        orig_cwd = os.getcwd()
        try:
            os.chdir(self.root)
            rel_svc = ReadOnlyProjectionService(
                Path("sym_rel/../state"), sandbox_root=self.sandbox_root
            )
            with mock.patch(_PATCH_DB_CONNECT) as mock_connect:
                with self.assertRaisesRegex(CoordPolicyError, "symlink_ancestor_rejected"):
                    rel_svc.get_workspace_tree(_OP_CALLER)
                mock_connect.assert_not_called()
        finally:
            os.chdir(orig_cwd)

    def test_reg_rejected_hostile_message_id_cannot_verify_stream_badge(self) -> None:
        hostile_mid = "msg\x1b[31m"
        reg = self._new_registry()
        _register_sample_sandbox(reg, name="mid-a")
        body = "matching directive"
        reg.close()

        raw = _open_raw_rw(self.state_dir)
        try:
            sha = sha256_canonical_body(body)
            raw.execute(
                """
                INSERT INTO event_log
                (seq, msg_id, src_role, src_actor, src_incarnation, dst_addr, dst_thread_id,
                 dst_incarnation, trust_class, msg_kind, body_text, body_sha256, edge_id,
                 edge_turn_seq, in_reply_to, artifact_refs_json, created_at)
                VALUES (950, ?, 'operator', 'operator:op-main', NULL, 'mid-a', 'main', ?,
                        'OPERATOR_DIRECTIVE', 'prompt', ?, ?, 'edge-mid', 1, NULL, '[]', 1.0)
                """,
                (hostile_mid, _DEFAULT_INC, body, sha),
            )
            raw.execute(
                """
                INSERT INTO dispatch_receipts
                (sandbox_addr, incarnation_id, session_id, message_id, body_sha256,
                 badge, src_actor, trust_class, consumed_at)
                VALUES ('mid-a', ?, 'main', ?, ?, 'Operator',
                        'operator:op-main', 'OPERATOR_DIRECTIVE', 2.0)
                """,
                (_DEFAULT_INC, hostile_mid, sha),
            )
            raw.execute(
                """
                INSERT INTO stream_events
                (seq, event_type, sandbox_addr, incarnation_id, thread_id, seq_hint,
                 message_id, dispatch_msg_id, text, file_path, detail_json, badge, created_at)
                VALUES (951, 'user_message', 'mid-a', ?, 'main', 1, ?, ?, ?, NULL, '{}', 'Operator', 3.0)
                """,
                (_DEFAULT_INC, hostile_mid, hostile_mid, body),
            )
        finally:
            raw.close()

        # Query stream row directly (event_log seq=950 has invalid primary msg_id, so cursor past 950)
        scope = oc_projection.compute_scope_hash(
            "events", target="mid-a", thread_id=_DEFAULT_THREAD, incarnation_id=_DEFAULT_INC
        )
        after_env = encode_cursor(
            {"op": "events", "fh": scope, "seq": 950, "rank": 1, "inc": _DEFAULT_INC}
        )
        svc = self._new_service()
        page = svc.get_thread_events(
            _OP_CALLER, target="mid-a", thread_id=_DEFAULT_THREAD, after_cursor=after_env
        )
        self.assertEqual(len(page.events), 1)
        st = page.events[0]
        self.assertIsNone(st.message_id)
        self.assertEqual(
            st.effective_badge, ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value
        )
        self.assertEqual(st.authority_rank, 0)
        self.assertIsNone(st.verified_actor)
        self.assertTrue(st.untrusted_content)
        self.assertTrue(st.provenance_anomaly)
        self.assertEqual(st.anomaly_reason, "unbacked_host_badge")


if __name__ == "__main__":
    unittest.main()
