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

_INC_1 = "inc_alpha1"
_INC_2 = "inc_beta2"
_THREAD_MAIN = "main"
_THREAD_REV = "review-1"


def _make_sandbox(
    addr: str = "feat-a",
    inc: str = _INC_1,
    project_id: str = "proj-1",
    project_name: str = "Demo Project",
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
    )


def _make_edge(
    edge_id: str = "edge_1",
    src_actor: str = "operator:op1",
    dst_addr: str = "feat-a",
    *,
    src_incarnation: str | None = None,
    max_rounds: int = 16,
    grant_generation: int = 1,
    lease_request_id: str | None = "req_1",
    threads: frozenset[str] = frozenset({_THREAD_MAIN, _THREAD_REV}),
    kinds: frozenset[str] = frozenset({"prompt", "question", "answer", "cancel"}),
) -> RoutingEdge:
    return RoutingEdge(
        edge_id=edge_id,
        src_actor=src_actor,
        src_incarnation=src_incarnation,
        dst_addr=dst_addr,
        allowed_threads=threads,
        allowed_msg_kinds=kinds,
        max_rounds=max_rounds,
        grant_generation=grant_generation,
        lease_request_id=lease_request_id,
    )


def _make_envelope(
    dst_addr: str = "feat-a",
    dst_inc: str = _INC_1,
    *,
    msg_id: str | None = None,
    src_role: CoordRole = CoordRole.OPERATOR,
    src_actor: str = "operator:op1",
    src_inc: str | None = None,
    thread_id: str = _THREAD_MAIN,
    trust_class: TrustClass = TrustClass.OPERATOR_DIRECTIVE,
    msg_kind: str = "prompt",
    body_text: str = "hello world",
    edge_id: str = "edge_1",
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
                    mode = stat.S_IMODE(os.lstat(fpath).st_mode)
                    self.assertEqual(mode, 0o600, msg=f"{fpath.name} mode was {oct(mode)}")
            journal = reg._conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual(str(journal).lower(), "wal")
            fk = reg._conn.execute("PRAGMA foreign_keys").fetchone()[0]
            self.assertEqual(int(fk), 1)
        finally:
            reg.close()

        # Verify symlinked -wal is rejected on reopen
        wal_path = Path(f"{db_path}-wal")
        if wal_path.exists():
            wal_path.unlink()
        wal_path.symlink_to(decoy)
        with self.assertRaises(CoordPolicyError):
            CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)


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
        sb = self.reg.register_sandbox(_make_sandbox("feat-a", _INC_1))
        self.assertEqual(sb.sandbox_addr, "feat-a")
        self.assertEqual(self.reg.get_sandbox("feat-a"), sb)
        self.assertEqual(len(self.reg.list_sandboxes()), 1)

        bad_remote = _make_sandbox("mac / feat-a", _INC_1)
        with self.assertRaises(AddressError):
            self.reg.register_sandbox(bad_remote)

        bad_brief = SandboxRecord(
            sandbox_addr="feat-b",
            worker_ref="local",
            instance_name="feat-b",
            incarnation_id=_INC_1,
            job_id="job_b",
            project_id="p1",
            project_name="P1",
            branch="main",
            sandbox_type="default",
            task_brief="   ",
        )
        with self.assertRaises(CoordValidationError):
            self.reg.register_sandbox(bad_brief)

        with self.assertRaises(CoordValidationError):
            self.reg.update_sandbox_status("feat-a", "invalid-state")

        self.reg.update_sandbox_status("feat-a", "degraded", incarnation_id=_INC_2)
        updated = self.reg.get_sandbox("feat-a")
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, "degraded")
        self.assertEqual(updated.incarnation_id, _INC_2)

    def test_concurrent_turn_budget_contention_allows_exact_final_turn(self) -> None:
        self.reg.register_sandbox(_make_sandbox("feat-a", _INC_1))
        self.reg.grant_edge(_make_edge("edge_race", src_actor="feat-b", dst_addr="feat-a", max_rounds=3))

        for idx in range(2):
            env = _make_envelope(
                "feat-a",
                _INC_1,
                src_role=CoordRole.JOB,
                src_actor="feat-b",
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
                "feat-a",
                _INC_1,
                src_role=CoordRole.JOB,
                src_actor="feat-b",
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
        edge = self.reg.get_edge("edge_race")
        self.assertIsNotNone(edge)
        self.assertEqual(edge.turns_used, 3)

        self.reg.reset_edge_turns("edge_race")
        self.assertEqual(self.reg.get_edge("edge_race").turns_used, 0)

    def test_in_reply_to_validation_and_opaque_rejection(self) -> None:
        self.reg.register_sandbox(_make_sandbox("feat-a", _INC_1))
        self.reg.register_sandbox(_make_sandbox("feat-b", _INC_2))
        self.reg.grant_edge(_make_edge("edge_ab", src_actor="feat-a", dst_addr="feat-b"))
        self.reg.grant_edge(_make_edge("edge_ba", src_actor="feat-b", dst_addr="feat-a"))

        q_env = _make_envelope(
            "feat-b",
            _INC_2,
            src_role=CoordRole.JOB,
            src_actor="feat-a",
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

        # Valid reply from feat-b -> feat-a referencing sent_q.msg_id
        a_env = _make_envelope(
            "feat-a",
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor="feat-b",
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
            check_in_reply_to=(sent_q.msg_id, "feat-b", _THREAD_MAIN),
        )
        self.assertGreater(seq, 0)

        # Bad ref_msg_id, wrong thread, wrong caller_dst_addr all fail opaquely
        bad_refs = [
            ("msg_nonexistent", "feat-b", _THREAD_MAIN),
            (sent_q.msg_id, "feat-b", _THREAD_REV),
            (sent_q.msg_id, "feat-a", _THREAD_MAIN),
        ]
        for ref in bad_refs:
            bad_env = _make_envelope(
                "feat-a",
                _INC_1,
                src_role=CoordRole.JOB,
                src_actor="feat-b",
                trust_class=TrustClass.UNTRUSTED_PEER_DATA,
                msg_kind="answer",
                edge_id="edge_ba",
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
                    check_in_reply_to=ref,
                )
            self.assertEqual(str(ctx.exception), "invalid_in_reply_to")

    def test_dual_cap_backpressure_and_unstarvable_control_priority(self) -> None:
        self.reg.register_sandbox(_make_sandbox("feat-a", _INC_1))
        self.reg.grant_edge(_make_edge("edge_bp", src_actor="feat-b", dst_addr="feat-a"))

        # Fill count cap (max_queued_msgs=2)
        for i in range(2):
            env = _make_envelope(
                "feat-a",
                _INC_1,
                src_role=CoordRole.JOB,
                src_actor="feat-b",
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

        # 3rd peer message hits count cap
        over_count = _make_envelope(
            "feat-a",
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor="feat-b",
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

        # Byte cap check (max_queued_msgs=10, max_queued_bytes=15)
        over_bytes = _make_envelope(
            "feat-a",
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor="feat-b",
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

        # Control Priority (cancel) MUST bypass saturated peer backlog and sort FIRST
        cancel_env = _make_envelope(
            "feat-a",
            _INC_1,
            src_role=CoordRole.JOB,
            src_actor="feat-b",
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

    def test_fenced_outbox_state_machine_and_persistent_tombstones(self) -> None:
        self.reg.register_sandbox(_make_sandbox("feat-a", _INC_1))
        self.reg.grant_edge(_make_edge("edge_1", dst_addr="feat-a", grant_generation=1))

        # Admit 3 messages
        mids: list[str] = []
        for idx in range(3):
            env = _make_envelope("feat-a", _INC_1, edge_id="edge_1", body_text=f"m{idx}")
            _, stored = self.reg.admit_and_enqueue_send(
                edge_id="edge_1",
                expected_grant_generation=1,
                expected_src_incarnation=None,
                expected_dst_incarnation=_INC_1,
                envelope=env,
                count_turn=False,
                max_queued_msgs=32,
                max_queued_bytes=1_048_576,
            )
            mids.append(stored.msg_id)

        # Wrong incarnation refused
        self.assertFalse(
            self.reg.mark_outbox_dispatch_started(
                mids[0], edge_id="edge_1", grant_generation=1, dst_incarnation=_INC_2
            )
        )

        # m0: dispatch_started -> return_to_pending (zero_bytes_sent) -> dispatch_started -> handed_off -> completed
        self.assertTrue(
            self.reg.mark_outbox_dispatch_started(
                mids[0], edge_id="edge_1", grant_generation=1, dst_incarnation=_INC_1
            )
        )
        self.assertTrue(self.reg.return_outbox_to_pending(mids[0], detail="zero_bytes_sent"))
        self.assertTrue(
            self.reg.mark_outbox_dispatch_started(
                mids[0], edge_id="edge_1", grant_generation=1, dst_incarnation=_INC_1
            )
        )
        self.reg.mark_outbox_handed_off(mids[0], stream_id="stream_1")
        self.reg.mark_outbox_completed(mids[0])
        self.assertEqual(len(self.reg.list_outbox(statuses=("completed",))), 1)

        # m1: dispatch_started -> uncertain (must survive reopen and never auto-return)
        self.assertTrue(
            self.reg.mark_outbox_dispatch_started(
                mids[1], edge_id="edge_1", grant_generation=1, dst_incarnation=_INC_1
            )
        )
        self.reg.mark_outbox_uncertain(mids[1], detail="transport_reset")
        self.assertFalse(self.reg.return_outbox_to_pending(mids[1], detail="illegal"))

        # Revoke edge_1: cancels pending m2 and writes persistent tombstone
        revoked = self.reg.revoke_grant_and_cancel_outbox(edge_id="edge_1", reason="operator_revoke")
        self.assertEqual(revoked, ["edge_1"])
        self.assertTrue(self.reg.is_grant_tombstoned("edge_1", 1))
        self.assertEqual(self.reg.list_outbox(statuses=("pending",)), [])
        cancelled = self.reg.list_outbox(statuses=("cancelled",))
        self.assertEqual([r["msg_id"] for r in cancelled], [mids[2]])

        # Close and reopen: tombstone and uncertain status MUST persist
        self.reg.close()
        self.reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        self.assertTrue(self.reg.is_grant_tombstoned("edge_1", 1))
        uncertain = self.reg.list_outbox(statuses=("uncertain",))
        self.assertEqual([r["msg_id"] for r in uncertain], [mids[1]])

        # Re-granting tombstoned generation is refused; next generation succeeds
        with self.assertRaises(RevokedError):
            self.reg.grant_edge(_make_edge("edge_1", dst_addr="feat-a", grant_generation=1))
        regranted = self.reg.grant_edge(_make_edge("edge_1", dst_addr="feat-a", grant_generation=2))
        self.assertEqual(regranted.grant_generation, 2)


class TestProvenanceTuiWorktreesAndAudit(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="oc-reg-prov-")
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.sandbox_root = self.root / "opencode-sandbox"
        self.sandbox_root.mkdir(mode=0o700)
        self.state_dir = self.root / "state"
        self.reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        self.reg.register_sandbox(_make_sandbox("feat-a", _INC_1))

    def tearDown(self) -> None:
        self.reg.close()
        self._tmp.cleanup()

    def test_5_tuple_receipt_consumption_replay_tamper_and_detail_stripping(self) -> None:
        self.reg.grant_edge(_make_edge("edge_op", src_actor="operator:op1", dst_addr="feat-a"))
        env = _make_envelope(
            "feat-a",
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

        # Wrong body tamper fails receipt match -> SANDBOX_LOCAL_UNVERIFIED
        tampered = StreamEvent(
            event_type="user_message",
            sandbox_addr="feat-a",
            incarnation_id=_INC_1,
            thread_id=_THREAD_MAIN,
            message_id=sent.msg_id,
            text="line1\nline2!",
            detail={"badge": "Operator", "sender": "operator:root", "safe": 1},
        )
        proj_tampered = self.reg.record_stream_event(tampered)
        self.assertEqual(proj_tampered["badge"], ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)
        self.assertEqual(proj_tampered["detail"], {"safe": 1})

        # Cross-thread mismatch fails receipt match
        wrong_thread = StreamEvent(
            event_type="user_message",
            sandbox_addr="feat-a",
            incarnation_id=_INC_1,
            thread_id=_THREAD_REV,
            message_id=sent.msg_id,
            text="line1\nline2",
        )
        proj_wt = self.reg.record_stream_event(wrong_thread)
        self.assertEqual(proj_wt["badge"], ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)

        # Exact 5-tuple match (CRLF normalized to LF) consumes receipt -> Operator
        valid_ev = StreamEvent(
            event_type="user_message",
            sandbox_addr="feat-a",
            incarnation_id=_INC_1,
            thread_id=_THREAD_MAIN,
            message_id=sent.msg_id,
            text="line1\nline2",
        )
        proj_ok = self.reg.record_stream_event(valid_ev)
        self.assertEqual(proj_ok["badge"], ProvenanceBadge.OPERATOR.value)

        # Replay of same 5-tuple MUST NOT match again -> SANDBOX_LOCAL_UNVERIFIED
        proj_replay = self.reg.record_stream_event(valid_ev)
        self.assertEqual(proj_replay["badge"], ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)

        # Non-user_message event has badge=None
        delta = StreamEvent("text_delta", "feat-a", _INC_1, _THREAD_MAIN, text="hi")
        proj_delta = self.reg.record_stream_event(delta)
        self.assertIsNone(proj_delta["badge"])

    def test_one_shot_tui_enter_token_policy_expiry_and_never_operator(self) -> None:
        for bad_surface in ("shell", "browser", "terminal"):
            with self.assertRaises(CoordPolicyError):
                self.reg.mint_tui_enter_token("feat-a", _INC_1, bad_surface)

        for bad_ttl in (0.0, -1.0, 5.1, True):
            with self.assertRaises(CoordPolicyError):
                self.reg.mint_tui_enter_token("feat-a", _INC_1, "opencode-tui", ttl_s=bad_ttl)

        tok = self.reg.mint_tui_enter_token("feat-a", _INC_1, "opencode-tui", ttl_s=5.0)
        ev = StreamEvent("user_message", "feat-a", _INC_1, _THREAD_MAIN, text="typed in tui")
        proj1 = self.reg.record_stream_event(ev, tui_enter_token=tok)
        self.assertEqual(proj1["badge"], ProvenanceBadge.TUI_INPUT.value)
        self.assertNotEqual(proj1["badge"], ProvenanceBadge.OPERATOR.value)

        # Single-use: second use falls back to SANDBOX_LOCAL_UNVERIFIED
        proj2 = self.reg.record_stream_event(ev, tui_enter_token=tok)
        self.assertEqual(proj2["badge"], ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)

        # Expired token falls back to SANDBOX_LOCAL_UNVERIFIED
        short_tok = self.reg.mint_tui_enter_token("feat-a", _INC_1, "opencode-tui", ttl_s=0.04)
        time.sleep(0.08)
        proj_exp = self.reg.record_stream_event(ev, tui_enter_token=short_tok)
        self.assertEqual(proj_exp["badge"], ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value)

    def test_projection_and_events_persist_across_close_reopen(self) -> None:
        self.reg.grant_edge(_make_edge("edge_p", dst_addr="feat-a"))
        art = ArtifactRef(blob_sha256="a" * 64, size_bytes=64)
        env = _make_envelope("feat-a", _INC_1, edge_id="edge_p", artifacts=(art,))
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
            "user_message", "feat-a", _INC_1, _THREAD_MAIN, message_id=sent.msg_id, text=sent.body_text
        )
        self.reg.record_stream_event(ev)

        before = self.reg.get_projection()
        self.reg.close()
        self.reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        after = self.reg.get_projection()
        self.assertEqual(before, after)
        self.assertEqual(len(after["projects"]), 1)
        sb_proj = after["projects"][0]["sandboxes"][0]
        self.assertEqual(sb_proj["sandbox_addr"], "feat-a")
        self.assertEqual(len(sb_proj["threads"][0]["messages"]), 1)

        loaded_env = self.reg.get_envelope(sent.msg_id)
        self.assertIsNotNone(loaded_env)
        self.assertEqual(loaded_env.artifact_refs, (art,))

        events = self.reg.list_events_since(["feat-a"], since_seq=0, limit=50)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["seq"], seq1)
        self.assertGreater(events[1]["seq"], seq1)

    def test_discover_worktrees_skips_symlinks_and_malformed_entries(self) -> None:
        wt_dir = self.state_dir / "worktrees"
        wt_dir.mkdir(mode=0o700)

        (wt_dir / "feat-a").write_text("/home/user/repo\nmy-repo\nfeat/a\n", encoding="utf-8")
        (wt_dir / "agent").write_text("/home/user/repo\nmy-repo\nmain\n", encoding="utf-8")
        (wt_dir / "BadName").write_text("/home/user/repo\nmy-repo\nmain\n", encoding="utf-8")
        (wt_dir / "feat-short").write_text("/only-two\nlines\n", encoding="utf-8")
        (wt_dir / "feat-bidi").write_text("/cwd\nrepo\nmain\u202e\n", encoding="utf-8")
        target = self.root / "outside.txt"
        target.write_text("/outside\nrepo\nmain\n", encoding="utf-8")
        (wt_dir / "feat-sym").symlink_to(target)

        discovered = self.reg.discover_worktrees()
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["sandbox_addr"], "feat-a")
        self.assertEqual(discovered[0]["branch"], "feat/a")

        # Symlinked worktrees directory itself must be rejected
        sym_state = self.root / "state-sym-wt"
        sym_reg = CoordRegistry(sym_state, sandbox_root=self.sandbox_root)
        try:
            (sym_state / "worktrees").symlink_to(wt_dir)
            with self.assertRaises(CoordPolicyError):
                sym_reg.discover_worktrees()
        finally:
            sym_reg.close()

    def test_edge_lookup_listing_and_target_addr_revocation(self) -> None:
        self.reg.grant_edge(_make_edge("edge_l1", src_actor="operator:op1", dst_addr="feat-a"))
        found = self.reg.find_active_edge("operator:op1", "feat-a", _THREAD_MAIN, "prompt")
        self.assertIsNotNone(found)
        self.assertEqual(found.edge_id, "edge_l1")
        self.assertIsNone(self.reg.find_active_edge("operator:op1", "feat-a", "other", "prompt"))
        self.assertEqual(len(self.reg.list_edges(dst_addr="feat-a", active_only=True)), 1)

        env = _make_envelope("feat-a", _INC_1, edge_id="edge_l1")
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

        revoked = self.reg.revoke_grant_and_cancel_outbox(target_addr="feat-a", reason="kill")
        self.assertEqual(revoked, ["edge_l1"])
        self.assertEqual(self.reg.get_sandbox("feat-a").status, "revoked")
        self.assertIsNone(self.reg.find_active_edge("operator:op1", "feat-a", _THREAD_MAIN, "prompt"))
        self.assertEqual(self.reg.list_edges(dst_addr="feat-a", active_only=True), [])

    def test_audit_hash_chain_detects_tampering(self) -> None:
        self.reg.append_audit("operator:op1", "test_1", "feat-a", "ok", {"step": 1})
        row2_id = self.reg.append_audit("operator:op1", "test_2", "feat-a", "ok", {"step": 2})
        self.reg.append_audit("operator:op1", "test_3", "feat-a", "ok", {"step": 3})

        ok, count = self.reg.verify_audit_chain()
        self.assertTrue(ok)
        self.assertEqual(count, 3)

        # Tamper directly in SQLite
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
