"""Unit and adversarial security tests for oc_registry.py (PRD M Lane 1)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import time
import unittest

_SPIKE_M_DIR = Path(__file__).resolve().parent
if str(_SPIKE_M_DIR) not in sys.path:
    sys.path.insert(0, str(_SPIKE_M_DIR))

from oc_address import AddressError  # noqa: E402
from oc_coord_contract import (  # noqa: E402
    MAX_ARTIFACTS_PER_MSG,
    MAX_INLINE_BODY_BYTES,
    MAX_STREAM_EVENT_BYTES,
    ArtifactRef,
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
    TrustClass,
    mint_crypto_id,
    sha256_canonical_body,
)
from oc_registry import CoordRegistry  # noqa: E402

_SB_A = "feat-a"
_SB_B = "feat-b"
_OP_ACTOR = "operator:op1"
_TUI_SURFACE = "opencode-tui"
_INC_1 = "inc_alpha1"
_INC_2 = "inc_beta2"
_THREAD_MAIN = "main"
_THREAD_REV = "review-1"
_EDGE_1 = "edge_1"
_KIND_PROMPT = "prompt"


def _make_sandbox(
    addr: str = _SB_A,
    inc: str = _INC_1,
    project_id: str = "proj-1",
    project_name: str = "Demo Project",
    *,
    parent_addr: str | None = None,
    controller_request_id: str | None = None,
    depth: int = 0,
) -> SandboxRecord:
    return SandboxRecord(
        sandbox_addr=addr,
        worker_ref="local",
        instance_name=addr,
        incarnation_id=inc,
        job_id=f"job_{addr}",
        project_id=project_id,
        project_name=project_name,
        branch=f"feat/{addr}",
        sandbox_type="default",
        task_brief=f"Work on {addr}",
        parent_addr=parent_addr,
        controller_request_id=controller_request_id,
        depth=depth,
    )


def _make_edge(
    edge_id: str = _EDGE_1,
    src_actor: str = _OP_ACTOR,
    dst_addr: str = _SB_A,
    *,
    src_incarnation: str | None = None,
    max_rounds: int = 16,
    turns_used: int = 0,
    grant_generation: int = 1,
    lease_request_id: str | None = "req_1",
    threads: frozenset[str] = frozenset({_THREAD_MAIN, _THREAD_REV}),
    kinds: frozenset[str] = frozenset({_KIND_PROMPT, "question", "answer", "cancel"}),
) -> RoutingEdge:
    return RoutingEdge(
        edge_id=edge_id,
        src_actor=src_actor,
        src_incarnation=src_incarnation,
        dst_addr=dst_addr,
        allowed_threads=threads,
        allowed_msg_kinds=kinds,
        max_rounds=max_rounds,
        turns_used=turns_used,
        grant_generation=grant_generation,
        lease_request_id=lease_request_id,
    )


def _make_envelope(
    dst_addr: str = _SB_A,
    dst_inc: str = _INC_1,
    *,
    msg_id: str | None = None,
    src_role: CoordRole = CoordRole.OPERATOR,
    src_actor: str = _OP_ACTOR,
    src_inc: str | None = None,
    thread_id: str = _THREAD_MAIN,
    trust_class: TrustClass = TrustClass.OPERATOR_DIRECTIVE,
    msg_kind: str = _KIND_PROMPT,
    body_text: str = "hello world",
    edge_id: str = _EDGE_1,
    in_reply_to: str | None = None,
    artifacts: tuple[ArtifactRef, ...] = (),
) -> Envelope:
    mid = msg_id or mint_crypto_id("msg")
    return Envelope(
        msg_id=mid,
        seq=0,
        src_role=src_role,
        src_actor=src_actor,
        src_incarnation=src_inc,
        dst_addr=dst_addr,
        dst_thread_id=thread_id,
        dst_incarnation=dst_inc,
        trust_class=trust_class,
        msg_kind=msg_kind,
        body_text=body_text,
        body_sha256=sha256_canonical_body(body_text),
        edge_id=edge_id,
        edge_turn_seq=0,
        in_reply_to=in_reply_to,
        artifact_refs=artifacts,
    )


class TestRegistrySecurityAndBoundaries(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="oc-reg-test-")
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.sandbox_root = self.root / "opencode-sandbox"
        self.sandbox_root.mkdir(mode=0o700)
        self.state_dir = self.root / "state"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_rejects_state_dir_in_sandbox_or_symlink_or_open_perms(self) -> None:
        inside_sb = self.sandbox_root / "nested-state"
        with self.assertRaises(CoordPolicyError):
            CoordRegistry(inside_sb, sandbox_root=self.sandbox_root)

        sym_to_sb = self.root / "sym-state"
        sym_to_sb.symlink_to(self.sandbox_root)
        with self.assertRaises(CoordPolicyError):
            CoordRegistry(sym_to_sb, sandbox_root=self.sandbox_root)

        open_dir = self.root / "open-state"
        open_dir.mkdir(mode=0o750)
        os.chmod(open_dir, 0o750)
        with self.assertRaises(CoordPolicyError):
            CoordRegistry(open_dir, sandbox_root=self.sandbox_root)

    def test_rejects_host_production_dirs(self) -> None:
        prod_cfg = Path.home() / ".config" / "oc-sandbox" / "poc-test"
        with self.assertRaises(CoordPolicyError):
            CoordRegistry(prod_cfg, sandbox_root=self.sandbox_root)

        prod_data = Path.home() / ".local" / "share" / "oc-sandbox" / "poc-test"
        with self.assertRaises(CoordPolicyError):
            CoordRegistry(prod_data, sandbox_root=self.sandbox_root)

    def test_rejects_symlink_and_hardlink_db_files_and_enforces_0600_wal(self) -> None:
        self.state_dir.mkdir(mode=0o700)
        decoy = self.root / "decoy.sqlite"
        decoy.write_bytes(b"")
        db_path = self.state_dir / "registry.sqlite"

        db_path.symlink_to(decoy)
        with self.assertRaises(CoordPolicyError):
            CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        db_path.unlink()

        os.link(decoy, db_path)
        with self.assertRaises(CoordPolicyError):
            CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        db_path.unlink()

        reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        try:
            reg.register_sandbox(_make_sandbox())
            for suffix in ("", "-wal", "-shm"):
                fpath = Path(f"{db_path}{suffix}")
                if fpath.exists():
                    self.assertEqual(stat.S_IMODE(os.lstat(fpath).st_mode), 0o600)
            journal = reg._conn.execute("PRAGMA journal_mode").fetchone()["journal_mode"]
            self.assertEqual(str(journal).lower(), "wal")
            self.assertEqual(
                int(reg._conn.execute("PRAGMA foreign_keys").fetchone()["foreign_keys"]), 1
            )
        finally:
            reg.close()

        # Pre-existing 0o640 DB file is tightened to 0o600 on reopen
        os.chmod(db_path, 0o640)
        reg2 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        reg2.close()
        self.assertEqual(stat.S_IMODE(os.lstat(db_path).st_mode), 0o600)

    def test_rejects_sidecar_wal_and_shm_symlinks_and_hardlinks(self) -> None:
        reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        reg.register_sandbox(_make_sandbox())
        reg.close()

        decoy = self.root / "sidecar-decoy"
        decoy.write_bytes(b"")
        db_path = self.state_dir / "registry.sqlite"

        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{db_path}{suffix}")
            if sidecar.exists() or sidecar.is_symlink():
                sidecar.unlink()
            sidecar.symlink_to(decoy)
            with self.assertRaises(CoordPolicyError):
                CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
            sidecar.unlink()

            os.link(decoy, sidecar)
            with self.assertRaises(CoordPolicyError):
                CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
            sidecar.unlink()


class TestRegistryCoreAndConcurrency(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="oc-reg-core-")
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.sandbox_root = self.root / "opencode-sandbox"
        self.sandbox_root.mkdir(mode=0o700)
        self.state_dir = self.root / "state"
        self.reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)

    def tearDown(self) -> None:
        self.reg.close()
        self._tmp.cleanup()

    def test_sandbox_registration_validation_and_status_rotation(self) -> None:
        sb = self.reg.register_sandbox(_make_sandbox(_SB_A, _INC_1))
        self.assertEqual(sb.sandbox_addr, _SB_A)
        self.assertEqual(self.reg.get_sandbox(_SB_A), sb)
        self.assertEqual(len(self.reg.list_sandboxes()), 1)

        bad_remote = _make_sandbox("mac / feat-a", _INC_1)
        with self.assertRaises(AddressError):
            self.reg.register_sandbox(bad_remote)
        bad_parent = _make_sandbox(_SB_B, _INC_1, parent_addr="mac / root")
        with self.assertRaises(AddressError):
            self.reg.register_sandbox(bad_parent)
        bad_req = _make_sandbox(_SB_B, _INC_1, controller_request_id="bad id!")
        with self.assertRaises(CoordValidationError):
            self.reg.register_sandbox(bad_req)
        bad_depth = _make_sandbox(_SB_B, _INC_1, depth=-1)
        with self.assertRaises(CoordValidationError):
            self.reg.register_sandbox(bad_depth)
        with self.assertRaises(CoordValidationError):
            self.reg.update_sandbox_status(_SB_A, "invalid-state")

        self.reg.update_sandbox_status(_SB_A, "degraded", incarnation_id=_INC_2)
        updated = self.reg.get_sandbox(_SB_A)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, "degraded")
        self.assertEqual(updated.incarnation_id, _INC_2)

    def test_concurrent_turn_budget_contention_allows_exact_final_turn(self) -> None:
        self.reg.register_sandbox(_make_sandbox(_SB_A, _INC_1))
        self.reg.grant_edge(_make_edge("edge_race", src_actor=_SB_B, dst_addr=_SB_A, max_rounds=3))

        for idx in range(2):
            env = _make_envelope(
                _SB_A,
                _INC_1,
                src_role=CoordRole.JOB,
                src_actor=_SB_B,
                trust_class=TrustClass.UNTRUSTED_PEER_DATA,
                edge_id="edge_race",
                body_text=f"turn-{idx}",
            )
            self.reg.admit_and_enqueue_send(
                edge_id="edge_race",
                expected_grant_generation=1,
                expected_src_incarnation=None,
                expected_dst_incarnation=_INC_1,
                envelope=env,
                count_turn=True,
                max_queued_msgs=32,
                max_queued_bytes=1_048_576,
            )

        def _try_send(idx: int) -> bool:
            env = _make_envelope(
                _SB_A,
                _INC_1,
                src_role=CoordRole.JOB,
                src_actor=_SB_B,
                trust_class=TrustClass.UNTRUSTED_PEER_DATA,
                edge_id="edge_race",
                body_text=f"contest-{idx}",
            )
            try:
                self.reg.admit_and_enqueue_send(
                    edge_id="edge_race",
                    expected_grant_generation=1,
                    expected_src_incarnation=None,
                    expected_dst_incarnation=_INC_1,
                    envelope=env,
                    count_turn=True,
                    max_queued_msgs=32,
                    max_queued_bytes=1_048_576,
                )
                return True
            except CoordPolicyError:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(_try_send, range(8)))

        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 7)
        self.assertEqual(self.reg.get_edge("edge_race").turns_used, 3)

        # grant_edge must NOT silently lower turns_used for same generation
        same_gen = self.reg.grant_edge(
            _make_edge("edge_race", src_actor=_SB_B, dst_addr=_SB_A, max_rounds=3, turns_used=0)
        )
        self.assertEqual(same_gen.turns_used, 3)

        self.reg.reset_edge_turns("edge_race")
        self.assertEqual(self.reg.get_edge("edge_race").turns_used, 0)

    def test_send_admission_rejects_trust_escalation_artifacts_and_src_incarnation_drift(self) -> None:
        self.reg.register_sandbox(_make_sandbox(_SB_A, _INC_1))
        self.reg.register_sandbox(_make_sandbox(_SB_B, _INC_2))
        self.reg.grant_edge(_make_edge("edge_ba", src_actor=_SB_B, dst_addr=_SB_A))

        # JOB role cannot escalate to OPERATOR_DIRECTIVE or PARENT_TASK
        escalated = _make_envelope(
            _SB_A,
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor=_SB_B,
            trust_class=TrustClass.OPERATOR_DIRECTIVE,
            edge_id="edge_ba",
        )
        with self.assertRaises(CoordPolicyError):
            self.reg.admit_and_enqueue_send(
                edge_id="edge_ba",
                expected_grant_generation=1,
                expected_src_incarnation=_INC_2,
                expected_dst_incarnation=_INC_1,
                envelope=escalated,
                count_turn=False,
                max_queued_msgs=32,
                max_queued_bytes=1_048_576,
            )

        # Excessive artifact_refs rejected
        too_many_arts = tuple(
            ArtifactRef(blob_sha256="a" * 64, size_bytes=16) for _ in range(MAX_ARTIFACTS_PER_MSG + 1)
        )
        art_env = _make_envelope(
            _SB_A,
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor=_SB_B,
            trust_class=TrustClass.UNTRUSTED_PEER_DATA,
            edge_id="edge_ba",
            artifacts=too_many_arts,
        )
        with self.assertRaises(CoordValidationError):
            self.reg.admit_and_enqueue_send(
                edge_id="edge_ba",
                expected_grant_generation=1,
                expected_src_incarnation=_INC_2,
                expected_dst_incarnation=_INC_1,
                envelope=art_env,
                count_turn=False,
                max_queued_msgs=32,
                max_queued_bytes=1_048_576,
            )

        # Stale expected_src_incarnation rejected with IncarnationMismatchError
        peer_env = _make_envelope(
            _SB_A,
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor=_SB_B,
            trust_class=TrustClass.UNTRUSTED_PEER_DATA,
            edge_id="edge_ba",
        )
        with self.assertRaises(IncarnationMismatchError):
            self.reg.admit_and_enqueue_send(
                edge_id="edge_ba",
                expected_grant_generation=1,
                expected_src_incarnation="inc_stale",
                expected_dst_incarnation=_INC_1,
                envelope=peer_env,
                count_turn=False,
                max_queued_msgs=32,
                max_queued_bytes=1_048_576,
            )

    def test_in_reply_to_validation_and_opaque_rejection(self) -> None:
        self.reg.register_sandbox(_make_sandbox(_SB_A, _INC_1))
        self.reg.register_sandbox(_make_sandbox(_SB_B, _INC_2))
        self.reg.grant_edge(_make_edge("edge_ab", src_actor=_SB_A, dst_addr=_SB_B))
        self.reg.grant_edge(_make_edge("edge_ba", src_actor=_SB_B, dst_addr=_SB_A))

        q_env = _make_envelope(
            _SB_B,
            _INC_2,
            src_role=CoordRole.JOB,
            src_actor=_SB_A,
            trust_class=TrustClass.UNTRUSTED_PEER_DATA,
            msg_kind="question",
            edge_id="edge_ab",
            body_text="please check",
        )
        _, sent_q = self.reg.admit_and_enqueue_send(
            edge_id="edge_ab",
            expected_grant_generation=1,
            expected_src_incarnation=None,
            expected_dst_incarnation=_INC_2,
            envelope=q_env,
            count_turn=True,
            max_queued_msgs=32,
            max_queued_bytes=1_048_576,
        )

        self.assertTrue(
            self.reg.mark_outbox_dispatch_started(
                sent_q.msg_id,
                edge_id="edge_ab",
                grant_generation=1,
                dst_incarnation=_INC_2,
            )
        )
        self.reg.mark_outbox_handed_off(sent_q.msg_id, stream_id="stream_q1")

        a_env = _make_envelope(
            _SB_A,
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor=_SB_B,
            trust_class=TrustClass.UNTRUSTED_PEER_DATA,
            msg_kind="answer",
            edge_id="edge_ba",
            in_reply_to=sent_q.msg_id,
            body_text="looks good",
        )
        seq, _ = self.reg.admit_and_enqueue_send(
            edge_id="edge_ba",
            expected_grant_generation=1,
            expected_src_incarnation=None,
            expected_dst_incarnation=_INC_1,
            envelope=a_env,
            count_turn=True,
            max_queued_msgs=32,
            max_queued_bytes=1_048_576,
            check_in_reply_to=(sent_q.msg_id, _SB_B, _THREAD_MAIN),
        )
        self.assertGreater(seq, 0)

        bad_refs = [
            ("msg_nonexistent", _SB_B, _THREAD_MAIN, None),
            (sent_q.msg_id, _SB_B, _THREAD_REV, None),
            (sent_q.msg_id, _SB_A, _THREAD_MAIN, None),
            (sent_q.msg_id, _SB_B, _THREAD_MAIN, "msg_other"),
        ]
        for ref_id, caller_dst, tid, env_reply_to in bad_refs:
            bad_env = _make_envelope(
                _SB_A,
                _INC_1,
                src_role=CoordRole.JOB,
                src_actor=_SB_B,
                trust_class=TrustClass.UNTRUSTED_PEER_DATA,
                msg_kind="answer",
                edge_id="edge_ba",
                in_reply_to=env_reply_to,
            )
            with self.assertRaises(CoordValidationError) as ctx:
                self.reg.admit_and_enqueue_send(
                    edge_id="edge_ba",
                    expected_grant_generation=1,
                    expected_src_incarnation=None,
                    expected_dst_incarnation=_INC_1,
                    envelope=bad_env,
                    count_turn=True,
                    max_queued_msgs=32,
                    max_queued_bytes=1_048_576,
                    check_in_reply_to=(ref_id, caller_dst, tid),
                )
            self.assertEqual(str(ctx.exception), "invalid_in_reply_to")

    def test_dual_cap_backpressure_and_unstarvable_control_priority(self) -> None:
        self.reg.register_sandbox(_make_sandbox(_SB_A, _INC_1))
        self.reg.grant_edge(_make_edge("edge_bp", src_actor=_SB_B, dst_addr=_SB_A))

        for i in range(2):
            env = _make_envelope(
                _SB_A,
                _INC_1,
                src_role=CoordRole.JOB,
                src_actor=_SB_B,
                trust_class=TrustClass.UNTRUSTED_PEER_DATA,
                edge_id="edge_bp",
                body_text=f"msg-{i}",
            )
            self.reg.admit_and_enqueue_send(
                edge_id="edge_bp",
                expected_grant_generation=1,
                expected_src_incarnation=None,
                expected_dst_incarnation=_INC_1,
                envelope=env,
                count_turn=False,
                max_queued_msgs=2,
                max_queued_bytes=100,
            )

        over_count = _make_envelope(
            _SB_A,
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor=_SB_B,
            trust_class=TrustClass.UNTRUSTED_PEER_DATA,
            edge_id="edge_bp",
            body_text="overflow",
        )
        with self.assertRaises(CoordBackpressureError):
            self.reg.admit_and_enqueue_send(
                edge_id="edge_bp",
                expected_grant_generation=1,
                expected_src_incarnation=None,
                expected_dst_incarnation=_INC_1,
                envelope=over_count,
                count_turn=False,
                max_queued_msgs=2,
                max_queued_bytes=100,
            )

        over_bytes = _make_envelope(
            _SB_A,
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor=_SB_B,
            trust_class=TrustClass.UNTRUSTED_PEER_DATA,
            edge_id="edge_bp",
            body_text="x" * 20,
        )
        with self.assertRaises(CoordBackpressureError):
            self.reg.admit_and_enqueue_send(
                edge_id="edge_bp",
                expected_grant_generation=1,
                expected_src_incarnation=None,
                expected_dst_incarnation=_INC_1,
                envelope=over_bytes,
                count_turn=False,
                max_queued_msgs=10,
                max_queued_bytes=15,
            )

        cancel_env = _make_envelope(
            _SB_A,
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor=_SB_B,
            trust_class=TrustClass.UNTRUSTED_PEER_DATA,
            msg_kind="cancel",
            edge_id="edge_bp",
            body_text="stop now",
        )
        _, admitted_cancel = self.reg.admit_and_enqueue_send(
            edge_id="edge_bp",
            expected_grant_generation=1,
            expected_src_incarnation=None,
            expected_dst_incarnation=_INC_1,
            envelope=cancel_env,
            count_turn=False,
            max_queued_msgs=2,
            max_queued_bytes=10,
        )
        queued = self.reg.list_outbox()
        self.assertEqual(queued[0]["msg_id"], admitted_cancel.msg_id)
        self.assertEqual(queued[0]["priority"], 1)

    def test_fenced_outbox_state_machine_tombstones_and_generation_monotonicity(self) -> None:
        self.reg.register_sandbox(_make_sandbox(_SB_A, _INC_1))
        self.reg.grant_edge(_make_edge(_EDGE_1, dst_addr=_SB_A, grant_generation=2))

        mids: list[str] = []
        for idx in range(3):
            env = _make_envelope(_SB_A, _INC_1, edge_id=_EDGE_1, body_text=f"m{idx}")
            _, stored = self.reg.admit_and_enqueue_send(
                edge_id=_EDGE_1,
                expected_grant_generation=2,
                expected_src_incarnation=None,
                expected_dst_incarnation=_INC_1,
                envelope=env,
                count_turn=False,
                max_queued_msgs=32,
                max_queued_bytes=1_048_576,
            )
            mids.append(stored.msg_id)

        self.assertFalse(
            self.reg.mark_outbox_dispatch_started(
                mids[0], edge_id=_EDGE_1, grant_generation=2, dst_incarnation=_INC_2
            )
        )
        self.assertTrue(
            self.reg.mark_outbox_dispatch_started(
                mids[0], edge_id=_EDGE_1, grant_generation=2, dst_incarnation=_INC_1
            )
        )
        self.assertTrue(self.reg.return_outbox_to_pending(mids[0], detail="zero_bytes_sent"))
        self.assertTrue(
            self.reg.mark_outbox_dispatch_started(
                mids[0], edge_id=_EDGE_1, grant_generation=2, dst_incarnation=_INC_1
            )
        )
        self.reg.mark_outbox_handed_off(mids[0], stream_id="stream_1")
        self.reg.mark_outbox_completed(mids[0])
        self.assertEqual(len(self.reg.list_outbox(statuses=("completed",))), 1)

        self.assertTrue(
            self.reg.mark_outbox_dispatch_started(
                mids[1], edge_id=_EDGE_1, grant_generation=2, dst_incarnation=_INC_1
            )
        )
        self.reg.mark_outbox_uncertain(mids[1], detail="transport_reset")
        self.assertFalse(self.reg.return_outbox_to_pending(mids[1], detail="illegal"))

        # Revoke edge_1 gen 2: cancels pending m2, deletes m2's unconsumed receipt, tombstones gen 2
        revoked = self.reg.revoke_grant_and_cancel_outbox(edge_id=_EDGE_1, reason="operator_revoke")
        self.assertEqual(revoked, [_EDGE_1])
        self.assertTrue(self.reg.is_grant_tombstoned(_EDGE_1, 2))
        self.assertFalse(
            self.reg.mark_outbox_dispatch_started(
                mids[2], edge_id=_EDGE_1, grant_generation=2, dst_incarnation=_INC_1
            )
        )
        # Cancelled m2 cannot later claim Operator badge via receipt
        self.assertIsNone(
            self.reg.consume_dispatch_receipt(_SB_A, _INC_1, _THREAD_MAIN, mids[2], "m2")
        )

        # Close and reopen: tombstone and uncertain status MUST persist
        self.reg.close()
        self.reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        self.assertTrue(self.reg.is_grant_tombstoned(_EDGE_1, 2))
        self.assertEqual([r["msg_id"] for r in self.reg.list_outbox(statuses=("uncertain",))], [mids[1]])

        # Re-granting gen 2 OR downgrading to gen 1 is refused; gen 3 succeeds
        edge_gen2 = _make_edge(_EDGE_1, dst_addr=_SB_A, grant_generation=2)
        with self.assertRaises(RevokedError):
            self.reg.grant_edge(edge_gen2)
        edge_gen1 = _make_edge(_EDGE_1, dst_addr=_SB_A, grant_generation=1)
        with self.assertRaises(RevokedError):
            self.reg.grant_edge(edge_gen1)
        regranted = self.reg.grant_edge(_make_edge(_EDGE_1, dst_addr=_SB_A, grant_generation=3))
        self.assertEqual(regranted.grant_generation, 3)

    def test_outbox_fence_rejects_return_and_dispatch_after_src_or_dst_rotation(self) -> None:
        self.reg.register_sandbox(_make_sandbox(_SB_A, _INC_1))
        self.reg.register_sandbox(_make_sandbox(_SB_B, _INC_2))
        self.reg.grant_edge(
            _make_edge("edge_ba", src_actor=_SB_B, dst_addr=_SB_A, src_incarnation=_INC_2)
        )

        env1 = _make_envelope(
            _SB_A,
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor=_SB_B,
            trust_class=TrustClass.UNTRUSTED_PEER_DATA,
            edge_id="edge_ba",
            body_text="p1",
        )
        _, sent1 = self.reg.admit_and_enqueue_send(
            edge_id="edge_ba",
            expected_grant_generation=1,
            expected_src_incarnation=_INC_2,
            expected_dst_incarnation=_INC_1,
            envelope=env1,
            count_turn=False,
            max_queued_msgs=32,
            max_queued_bytes=1_048_576,
        )
        env2 = _make_envelope(
            _SB_A,
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor=_SB_B,
            trust_class=TrustClass.UNTRUSTED_PEER_DATA,
            edge_id="edge_ba",
            body_text="p2",
        )
        _, sent2 = self.reg.admit_and_enqueue_send(
            edge_id="edge_ba",
            expected_grant_generation=1,
            expected_src_incarnation=_INC_2,
            expected_dst_incarnation=_INC_1,
            envelope=env2,
            count_turn=False,
            max_queued_msgs=32,
            max_queued_bytes=1_048_576,
        )

        self.assertTrue(
            self.reg.mark_outbox_dispatch_started(
                sent1.msg_id, edge_id="edge_ba", grant_generation=1, dst_incarnation=_INC_1
            )
        )
        # Rotate source sandbox incarnation -> both return_to_pending and new dispatch_started refused
        self.reg.update_sandbox_status(_SB_B, "running", incarnation_id="inc_rotated")
        self.assertFalse(self.reg.return_outbox_to_pending(sent1.msg_id, detail="zero_bytes_sent"))
        self.assertFalse(
            self.reg.mark_outbox_dispatch_started(
                sent2.msg_id, edge_id="edge_ba", grant_generation=1, dst_incarnation=_INC_1
            )
        )

    def test_combined_selector_revocation_does_not_over_revoke_sandbox(self) -> None:
        self.reg.register_sandbox(_make_sandbox(_SB_A, _INC_1))
        self.reg.grant_edge(_make_edge("edge_a1", dst_addr=_SB_A))
        self.reg.grant_edge(_make_edge("edge_a2", dst_addr=_SB_A))
        tok = self.reg.mint_tui_enter_token(_SB_A, _INC_1, _TUI_SURFACE)

        env2 = _make_envelope(_SB_A, _INC_1, edge_id="edge_a2", body_text="keep me")
        _, sent2 = self.reg.admit_and_enqueue_send(
            edge_id="edge_a2",
            expected_grant_generation=1,
            expected_src_incarnation=None,
            expected_dst_incarnation=_INC_1,
            envelope=env2,
            count_turn=False,
            max_queued_msgs=32,
            max_queued_bytes=1_048_576,
        )

        # Combined target_addr + edge_id revokes ONLY edge_a1, leaving sandbox and edge_a2 intact
        revoked = self.reg.revoke_grant_and_cancel_outbox(target_addr=_SB_A, edge_id="edge_a1")
        self.assertEqual(revoked, ["edge_a1"])
        self.assertEqual(self.reg.get_sandbox(_SB_A).status, "running")
        self.assertEqual([r["msg_id"] for r in self.reg.list_outbox()], [sent2.msg_id])

        # Whole-sandbox revocation revokes sandbox, cancels edge_a2, and invalidates TUI token
        revoked_all = self.reg.revoke_grant_and_cancel_outbox(target_addr=_SB_A)
        self.assertEqual(revoked_all, ["edge_a1", "edge_a2"])
        self.assertEqual(self.reg.get_sandbox(_SB_A).status, "revoked")
        self.assertEqual(self.reg.list_outbox(), [])
        self.assertFalse(self.reg.consume_tui_enter_token(tok, _SB_A, _INC_1, _TUI_SURFACE))


class TestProvenanceTuiWorktreesAndAudit(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="oc-reg-prov-")
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.sandbox_root = self.root / "opencode-sandbox"
        self.sandbox_root.mkdir(mode=0o700)
        self.state_dir = self.root / "state"
        self.reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        self.reg.register_sandbox(_make_sandbox(_SB_A, _INC_1))
        self.reg.register_sandbox(_make_sandbox(_SB_B, _INC_2))

    def tearDown(self) -> None:
        self.reg.close()
        self._tmp.cleanup()

    def test_5_tuple_receipt_consumption_theft_replay_tamper_and_nested_detail(self) -> None:
        self.reg.grant_edge(_make_edge("edge_op", src_actor=_OP_ACTOR, dst_addr=_SB_A))
        env = _make_envelope(
            _SB_A,
            _INC_1,
            edge_id="edge_op",
            body_text="line1\r\nline2",
            trust_class=TrustClass.OPERATOR_DIRECTIVE,
        )
        _, sent = self.reg.admit_and_enqueue_send(
            edge_id="edge_op",
            expected_grant_generation=1,
            expected_src_incarnation=None,
            expected_dst_incarnation=_INC_1,
            envelope=env,
            count_turn=False,
            max_queued_msgs=32,
            max_queued_bytes=1_048_576,
        )

        # Nested smuggling, non-finite float, huge int, unpaired surrogate, malformed message_id, huge created_at
        hostile = StreamEvent(
            event_type="user_message",
            sandbox_addr=_SB_A,
            incarnation_id=_INC_1,
            thread_id=_THREAD_MAIN,
            message_id="bad\u202eid",
            text="line1\nline2!",
            detail={
                "badge": "Operator",
                "nested": {"src": "operator:root", "principal": "op", "keep": True},
                "arr": [{"sender": "spoof", "ok": 1}, float("nan")],
                "inf": float("inf"),
                "huge_int": 10**5000,
                "surrogate": "\ud800",
            },
            created_at=10**400,  # type: ignore[arg-type]
        )
        proj_h = self.reg.record_stream_event(hostile)
        self.assertEqual(proj_h["badge"], ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)
        self.assertIsNone(proj_h["message_id"])
        self.assertEqual(proj_h["detail"], {"nested": {"keep": True}, "arr": [{"ok": 1}]})
        self.assertGreater(proj_h["created_at"], 0.0)

        # Cross-sandbox, cross-incarnation, and cross-thread theft all fail
        for sb_addr, inc, tid in (
            (_SB_B, _INC_2, _THREAD_MAIN),
            (_SB_A, _INC_2, _THREAD_MAIN),
            (_SB_A, _INC_1, _THREAD_REV),
        ):
            theft = StreamEvent("user_message", sb_addr, inc, tid, message_id=sent.msg_id, text="line1\nline2")
            self.assertEqual(
                self.reg.record_stream_event(theft)["badge"],
                ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value,
            )

        # Exact 5-tuple match consumes receipt -> Operator; replay -> SANDBOX_LOCAL_UNVERIFIED
        valid_ev = StreamEvent(
            "user_message", _SB_A, _INC_1, _THREAD_MAIN, message_id=sent.msg_id, text="line1\nline2"
        )
        self.assertEqual(self.reg.record_stream_event(valid_ev)["badge"], ProvenanceBadge.OPERATOR.value)
        self.assertEqual(
            self.reg.record_stream_event(valid_ev)["badge"],
            ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value,
        )

    def test_hostile_user_message_oversized_or_nul_text_and_oversized_detail(self) -> None:
        oversized_ev = StreamEvent(
            "user_message",
            _SB_A,
            _INC_1,
            _THREAD_MAIN,
            message_id="msg_1",
            text="a" * (MAX_INLINE_BODY_BYTES + 100),
        )
        self.assertEqual(
            self.reg.record_stream_event(oversized_ev)["badge"],
            ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value,
        )

        with self.assertRaises(CoordValidationError):
            StreamEvent(
                "user_message", _SB_A, _INC_1, _THREAD_MAIN, message_id="msg_2", text="bad\x00nul"
            )

        huge_detail_ev = StreamEvent(
            "text_delta", _SB_A, _INC_1, _THREAD_MAIN, detail={"blob": "x" * (MAX_STREAM_EVENT_BYTES + 64)}
        )
        with self.assertRaises(CoordValidationError):
            self.reg.record_stream_event(huge_detail_ev)

    def test_one_shot_tui_enter_token_policy_scoping_and_expiry(self) -> None:
        for bad_surface in ("shell", "browser", "terminal"):
            with self.assertRaises(CoordPolicyError):
                self.reg.mint_tui_enter_token(_SB_A, _INC_1, bad_surface)

        for bad_ttl in (0.0, -1.0, 5.1, True):
            with self.assertRaises(CoordPolicyError):
                self.reg.mint_tui_enter_token(_SB_A, _INC_1, _TUI_SURFACE, ttl_s=bad_ttl)

        tok = self.reg.mint_tui_enter_token(_SB_A, _INC_1, _TUI_SURFACE, ttl_s=5.0)
        # Direct wrong surface, cross-sandbox, and cross-incarnation theft fail without consuming token
        self.assertFalse(self.reg.consume_tui_enter_token(tok, _SB_A, _INC_1, "shell"))
        self.assertFalse(self.reg.consume_tui_enter_token(tok, _SB_B, _INC_1, _TUI_SURFACE))
        self.assertFalse(self.reg.consume_tui_enter_token(tok, _SB_A, _INC_2, _TUI_SURFACE))

        ev = StreamEvent("user_message", _SB_A, _INC_1, _THREAD_MAIN, text="typed in tui")
        proj1 = self.reg.record_stream_event(ev, tui_enter_token=tok)
        self.assertEqual(proj1["badge"], ProvenanceBadge.TUI_INPUT.value)
        self.assertNotEqual(proj1["badge"], ProvenanceBadge.OPERATOR.value)

        # Single-use: second use falls back to SANDBOX_LOCAL_UNVERIFIED
        proj2 = self.reg.record_stream_event(ev, tui_enter_token=tok)
        self.assertEqual(proj2["badge"], ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)

        short_tok = self.reg.mint_tui_enter_token(_SB_A, _INC_1, _TUI_SURFACE, ttl_s=0.04)
        time.sleep(0.08)
        proj_exp = self.reg.record_stream_event(ev, tui_enter_token=short_tok)
        self.assertEqual(proj_exp["badge"], ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)

    def test_projection_and_events_persist_across_close_reopen(self) -> None:
        self.reg.grant_edge(_make_edge("edge_p", dst_addr=_SB_A))
        art = ArtifactRef(blob_sha256="a" * 64, size_bytes=64)
        env = _make_envelope(_SB_A, _INC_1, edge_id="edge_p", artifacts=(art,))
        seq1, sent = self.reg.admit_and_enqueue_send(
            edge_id="edge_p",
            expected_grant_generation=1,
            expected_src_incarnation=None,
            expected_dst_incarnation=_INC_1,
            envelope=env,
            count_turn=True,
            max_queued_msgs=32,
            max_queued_bytes=1_048_576,
        )
        ev = StreamEvent(
            "user_message", _SB_A, _INC_1, _THREAD_MAIN, message_id=sent.msg_id, text=sent.body_text
        )
        self.reg.record_stream_event(ev)

        before = self.reg.get_projection()
        self.reg.close()
        self.reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        after = self.reg.get_projection()
        self.assertEqual(before, after)
        self.assertEqual(self.reg.get_envelope(sent.msg_id).artifact_refs, (art,))

        events = self.reg.list_events_since([_SB_A], since_seq=0, limit=50)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["seq"], seq1)
        self.assertGreater(events[1]["seq"], seq1)

    def test_discover_worktrees_skips_symlinks_and_malformed_entries(self) -> None:
        wt_dir = self.state_dir / "worktrees"
        wt_dir.mkdir(mode=0o700)

        (wt_dir / _SB_A).write_text("/home/user/repo\nmy-repo\nfeat/a\n", encoding="utf-8")
        (wt_dir / "agent").write_text("/home/user/repo\nmy-repo\nmain\n", encoding="utf-8")
        (wt_dir / "BadName").write_text("/home/user/repo\nmy-repo\nmain\n", encoding="utf-8")
        (wt_dir / "feat-short").write_text("/only-two\nlines\n", encoding="utf-8")
        (wt_dir / "feat-bidi").write_text("/cwd\nrepo\nmain\u202e\n", encoding="utf-8")
        target = self.root / "outside.txt"
        target.write_text("/outside\nrepo\nmain\n", encoding="utf-8")
        (wt_dir / "feat-sym").symlink_to(target)

        discovered = self.reg.discover_worktrees()
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["sandbox_addr"], _SB_A)
        self.assertEqual(discovered[0]["branch"], "feat/a")

        sym_state = self.root / "state-sym-wt"
        sym_reg = CoordRegistry(sym_state, sandbox_root=self.sandbox_root)
        try:
            (sym_state / "worktrees").symlink_to(wt_dir)
            with self.assertRaises(CoordPolicyError):
                sym_reg.discover_worktrees()
        finally:
            sym_reg.close()

    def test_cancel_outbox_row_deletes_unconsumed_receipt_and_edge_lookup(self) -> None:
        self.reg.grant_edge(_make_edge("edge_l1", src_actor=_OP_ACTOR, dst_addr=_SB_A))
        found = self.reg.find_active_edge(_OP_ACTOR, _SB_A, _THREAD_MAIN, _KIND_PROMPT)
        self.assertIsNotNone(found)
        self.assertEqual(found.edge_id, "edge_l1")
        self.assertEqual(len(self.reg.list_edges(dst_addr=_SB_A, active_only=True)), 1)

        env = _make_envelope(_SB_A, _INC_1, edge_id="edge_l1", body_text="cancel-me")
        _, sent = self.reg.admit_and_enqueue_send(
            edge_id="edge_l1",
            expected_grant_generation=1,
            expected_src_incarnation=None,
            expected_dst_incarnation=_INC_1,
            envelope=env,
            count_turn=False,
            max_queued_msgs=32,
            max_queued_bytes=1_048_576,
        )
        self.reg.cancel_outbox_row(sent.msg_id, reason="operator_cancel")
        self.assertEqual(len(self.reg.list_outbox(statuses=("cancelled",))), 1)
        self.assertIsNone(
            self.reg.consume_dispatch_receipt(_SB_A, _INC_1, _THREAD_MAIN, sent.msg_id, "cancel-me")
        )

    def test_audit_hash_chain_detects_tampering(self) -> None:
        self.reg.append_audit(_OP_ACTOR, "test_1", _SB_A, "ok", {"step": 1})
        row2_id = self.reg.append_audit(_OP_ACTOR, "test_2", _SB_A, "ok", {"step": 2})
        self.reg.append_audit(_OP_ACTOR, "test_3", _SB_A, "ok", {"step": 3})

        ok, count = self.reg.verify_audit_chain()
        self.assertTrue(ok)
        self.assertEqual(count, 3)

        conn = sqlite3.connect(str(self.state_dir / "registry.sqlite"))
        try:
            conn.execute("UPDATE audit_log SET outcome = 'forged' WHERE id = ?", (row2_id,))
            conn.commit()
        finally:
            conn.close()

        ok_after, failing_id = self.reg.verify_audit_chain()
        self.assertFalse(ok_after)
        self.assertEqual(failing_id, row2_id)


if __name__ == "__main__":
    unittest.main()
