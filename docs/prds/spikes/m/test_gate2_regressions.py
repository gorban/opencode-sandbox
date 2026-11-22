"""Dedicated Gate 2 Round 1 adversarial regression tests for PRD M coordination.

Every test in this module reproduces a specific P1, P2, or P3 finding from
Gate 2 Round 1 against commit f4cc88e9 and verifies the root-cause fix.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from typing import Any

_SPIKE_M_DIR = Path(__file__).resolve().parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
_REPO_ROOT = _SPIKE_M_DIR.parents[3]
for _p in (str(_SPIKE_M_DIR), str(_SPIKE_L_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from oc_broker_common import BrokerLease  # noqa: E402
from oc_controller import (  # noqa: E402
    Capability,
    Controller,
    Decision,
    Intent,
    Job,
    Operation,
    Outcome,
    Principal,
    ProbeResult,
    Proposal,
    Reference,
    Role,
    Subject,
    Worker,
)
from oc_coord_contract import (  # noqa: E402
    ArtifactRef,
    CoordAuthError,
    CoordBackpressureError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    DispatchOutcome,
    IncarnationMismatchError,
    PrincipalCtx,
    ProvenanceBadge,
    RevokedError,
    StreamEvent,
    SubtreeBudget,
    TrustClass,
)
from oc_coord_rpc import CoordUdsRpcServer, uds_rpc_call  # noqa: E402
from oc_fake_worker import FakeWorkerTransport, TurnScript  # noqa: E402
from oc_hub import ArtifactSpool, CoordHub  # noqa: E402
from oc_registry import CoordRegistry  # noqa: E402
from oc_ui_auth import UiAuthDeniedError, UiAuthManager  # noqa: E402

_OP = PrincipalCtx(CoordRole.OPERATOR, "host_op")
_HOST = "127.0.0.1:47110"
_ORIGIN = "http://127.0.0.1:47110"
_THREAD_MAIN = "main"
_THREAD_REVIEW = "review"
_KIND_PROMPT = "prompt"


class _RegFixtureAdapter:
    def target_revision(self, target: str) -> str:
        return "rev-1"

    def set_target_revision(self, target: str, revision: str) -> None:
        return None

    def dispatch(self, *_args: Any, **_kwargs: Any) -> ProbeResult:
        return ProbeResult(Outcome.SUCCEEDED, "ok")

    def reconcile(self, *_args: Any, **_kwargs: Any) -> ProbeResult:
        return ProbeResult(Outcome.SUCCEEDED, "ok")


def _make_controller_lease(
    sandbox_name: str, incarnation_id: str
) -> tuple[Controller, Principal, BrokerLease, str]:
    operator = Principal(Role.OPERATOR, "op-reg")
    orchestrator = Principal(Role.ORCHESTRATOR, "orch-reg")
    job_actor = Principal(Role.JOB, f"chan-{sandbox_name}")
    subject = Subject("worker-local", incarnation_id, f"chan-{sandbox_name}")
    controller = Controller(
        incarnation="b" * 32,
        clock=lambda: 100,
        lifetime=3600,
        workers=[Worker("worker-local", operator)],
        jobs=[Job(subject, orchestrator, proposal_budget=4)],
        capabilities=[Capability("cap-probe", Operation.PROBE, "tgt-reg")],
        references=[Reference("ref-probe", "cap-probe")],
        adapter=_RegFixtureAdapter(),
    )
    controller._set_alias("alias-reg", "tgt-reg")
    st = controller.propose(job_actor, Proposal(Intent.PROBE_GRANT, "alias-reg", "ref-probe"))
    view = controller.view(operator, st.request_id)
    controller.decide(operator, st.request_id, view.payload.revision, view.digest, Decision.APPROVE)
    lease = BrokerLease(
        f"job-{sandbox_name}",
        controller=controller,
        controller_actor=operator,
        controller_request_id=st.request_id,
    )
    return controller, operator, lease, st.request_id


class TestGate2Round1Regressions(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.state_dir = self.root / "state"
        self.state_dir.mkdir(mode=0o700)
        self.sandbox_root = self.root / "sandbox-home"
        self.sandbox_root.mkdir(mode=0o700)
        self.sock_dir = self.root / "run"
        self.sock_dir.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _new_stack(
        self,
        *,
        controller: Controller | None = None,
        controller_actor: Principal | None = None,
    ) -> tuple[CoordRegistry, FakeWorkerTransport, CoordHub]:
        reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        transport = FakeWorkerTransport()
        kwargs: dict[str, Any] = {
            "controller": controller,
            "sandbox_root": self.sandbox_root,
            "watchdog_interval_s": 0.02,
        }
        if controller_actor is not None:
            kwargs["controller_actor"] = controller_actor
        hub = CoordHub(reg, transport, self.state_dir, **kwargs)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        return reg, transport, hub

    def test_p1_1_subtree_budget_blocks_escalation_laundering_and_depth0(self) -> None:
        default_parent = SubtreeBudget()
        escalated_routes = SubtreeBudget(
            max_depth_remaining=1,
            allowed_broker_routes=frozenset({"pg:prod-rw", "http:admin"}),
        )
        self.assertFalse(default_parent.attenuates(escalated_routes))

        # Two-hop capability laundering must fail
        restricted_root = SubtreeBudget(
            max_depth_remaining=2,
            allowed_models=frozenset({"model-a"}),
            allowed_broker_routes=frozenset({"http:readonly"}),
        )
        empty_child = SubtreeBudget(
            max_depth_remaining=1,
            allowed_models=frozenset(),
            allowed_broker_routes=frozenset(),
        )
        laundered_grandchild = SubtreeBudget(
            max_depth_remaining=0,
            allowed_models=frozenset({"model-expensive"}),
            allowed_broker_routes=frozenset({"http:admin"}),
        )
        self.assertTrue(restricted_root.attenuates(empty_child))
        self.assertFalse(empty_child.attenuates(laundered_grandchild))

        # Depth-0 leaf cannot delegate any child budget
        leaf = SubtreeBudget(max_depth_remaining=0)
        self.assertFalse(leaf.attenuates(SubtreeBudget(max_depth_remaining=0)))

        # Ranked security profile attenuation: elevated-nested -> desktop-wayland -> standard
        elevated = SubtreeBudget(max_depth_remaining=2, max_security_profile="elevated-nested")
        wayland = SubtreeBudget(max_depth_remaining=1, max_security_profile="desktop-wayland")
        standard = SubtreeBudget(max_depth_remaining=0, max_security_profile="standard")
        self.assertTrue(elevated.attenuates(wayland))
        self.assertTrue(wayland.attenuates(standard))
        self.assertFalse(wayland.attenuates(SubtreeBudget(max_depth_remaining=0, max_security_profile="elevated-nested")))

    def test_p1_2_revoked_sub_orchestrator_blocked_and_orchestrator_subtree_scoped(self) -> None:
        reg, transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="orch-1",
            incarnation_id="inc_o1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Sub orchestrator",
        )
        hub.register_sandbox(
            _OP,
            name="other-sb",
            incarnation_id="inc_other",
            project_id="p2",
            project_name="P2",
            branch="main",
            task_brief="Unrelated sandbox",
        )
        orch_ctx = PrincipalCtx(
            CoordRole.ORCHESTRATOR, "orch-1", sandbox_addr="orch-1", incarnation_id="inc_o1"
        )
        # Sub-orchestrator must bind parent_addr to itself and cannot overwrite existing sandboxes
        with self.assertRaises(CoordAuthError):
            hub.register_sandbox(
                orch_ctx,
                name="rogue-root",
                incarnation_id="inc_r",
                project_id="p1",
                project_name="P1",
                branch="main",
                task_brief="Escape parent",
                parent_addr=None,
            )
        with self.assertRaises(CoordPolicyError):
            hub.register_sandbox(
                orch_ctx,
                name="other-sb",
                incarnation_id="inc_hijack",
                project_id="p2",
                project_name="P2",
                branch="main",
                task_brief="Overwrite sibling",
                parent_addr="orch-1",
            )
        hub.register_sandbox(
            orch_ctx,
            name="child-a",
            incarnation_id="inc_c1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Legit child",
            parent_addr="orch-1",
        )
        # Sub-orchestrator cannot grant operator edges or revoke/view outside subtree
        with self.assertRaises(CoordAuthError):
            hub.grant_edge(orch_ctx, src_actor="operator:host_op", dst_addr="child-a")
        with self.assertRaises(CoordAuthError):
            hub.revoke(orch_ctx, target="other-sb")
        proj = hub.projection(orch_ctx)
        visible_addrs = {
            sb["sandbox_addr"] for p in proj["projects"] for sb in p["sandboxes"]
        }
        self.assertEqual(visible_addrs, {"orch-1", "child-a"})

        hub.grant_edge(orch_ctx, src_actor=orch_ctx.canonical_sender, dst_addr="child-a")
        rev = hub.revoke(_OP, target="orch-1", reason="revoke-sub-orch")
        self.assertEqual(rev.revoked_edges, 1)
        with self.assertRaises(RevokedError):
            hub.send(orch_ctx, target="child-a", body_text="Post-revoke parent task")
        with self.assertRaises(RevokedError):
            hub.register_sandbox(
                orch_ctx,
                name="orch-1",
                incarnation_id="inc_o2",
                project_id="p1",
                project_name="P1",
                branch="main",
                task_brief="Attempt resurrection",
                parent_addr="orch-1",
            )
        self.assertEqual(hub.dispatch_once(), 0)
        self.assertEqual(transport.dispatched_turns("child-a"), [])

    def test_p1_3_wait_read_artifact_stale_incarnation_and_unverified_refs_blocked(self) -> None:
        reg, _transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="peer-a",
            incarnation_id="inc_a1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Peer A",
        )
        hub.register_sandbox(
            _OP,
            name="target-b",
            incarnation_id="inc_b1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Target B",
        )
        hub.grant_edge(
            _OP,
            src_actor=_OP.canonical_sender,
            dst_addr="target-b",
            allowed_threads=(_THREAD_MAIN, _THREAD_REVIEW),
            allowed_msg_kinds=(_KIND_PROMPT,),
        )
        hub.grant_edge(
            _OP,
            src_actor="peer-a",
            src_incarnation="inc_a1",
            dst_addr="target-b",
            allowed_threads=(_THREAD_REVIEW,),
            allowed_msg_kinds=("review_request",),
        )
        secret_patch = b"--- a/secret.py\n+++ b/secret.py\n+TOP_SECRET\n"
        op_send = hub.send(
            _OP,
            target="target-b",
            thread_id=_THREAD_MAIN,
            body_text="Operator private directive",
            artifact_blobs=(secret_patch,),
        )
        op_env = reg.get_envelope(op_send["msg_id"])
        self.assertIsNotNone(op_env)
        op_ref = op_env.artifact_refs[0]
        hub.dispatch_once()

        peer_a = PrincipalCtx(CoordRole.JOB, "job-a", sandbox_addr="peer-a", incarnation_id="inc_a1")
        # 1. wait() must NOT leak target-b's OPERATOR_DIRECTIVE or unauthorized 'main' thread
        wait_res = hub.wait(peer_a, targets=["target-b"], since_seq=0, timeout_s=0.05)
        self.assertEqual(wait_res["events"], [])
        self.assertTrue(wait_res["timed_out"])

        # 2. Outgoing peer-a must NOT steal operator's patch delivered to target-b
        with self.assertRaises(CoordAuthError):
            hub.read_artifact(peer_a, sandbox_addr="target-b", ref=op_ref)

        # 3. Unverified caller-supplied artifact_refs must be rejected on send()
        bogus_ref = ArtifactRef(blob_sha256="a" * 64, size_bytes=10)
        with self.assertRaises(CoordPolicyError):
            hub.send(
                peer_a,
                target="target-b",
                thread_id=_THREAD_REVIEW,
                msg_kind="review_request",
                body_text="Inject ref",
                artifact_refs=(bogus_ref,),
            )

        # 4. Stale target-b incarnation cannot read v2 status or artifacts after rotation
        hub.register_sandbox(
            _OP,
            name="target-b",
            incarnation_id="inc_b2",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Target B rotated",
        )
        stale_b = PrincipalCtx(
            CoordRole.JOB, "job-b", sandbox_addr="target-b", incarnation_id="inc_b1"
        )
        with self.assertRaises(IncarnationMismatchError):
            hub.status(stale_b, target="target-b")
        with self.assertRaises(IncarnationMismatchError):
            hub.read_artifact(stale_b, sandbox_addr="target-b", ref=op_ref)

    def test_p1_4_hub_restart_enforces_controller_revoke_and_durable_degraded_marker(self) -> None:
        controller, ctrl_op, lease, req_id = _make_controller_lease("sb1", "inc_ctrl_1")
        reg1 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        transport = FakeWorkerTransport()
        hub1 = CoordHub(
            reg1,
            transport,
            self.state_dir,
            controller=controller,
            sandbox_root=self.sandbox_root,
        )
        try:
            hub1.register_sandbox(
                _OP,
                name="sb1",
                incarnation_id="inc_ctrl_1",
                project_id="p1",
                project_name="P1",
                branch="main",
                task_brief="Controller lease sandbox",
                lease=lease,
                controller_request_id=req_id,
            )
            hub1.grant_edge(
                _OP,
                src_actor=_OP.canonical_sender,
                dst_addr="sb1",
                lease_request_id=req_id,
            )
            hub1.send(_OP, target="sb1", body_text="Queued before hub down")
        finally:
            hub1.close()
            reg1.close()

        # Revoke in oc_controller while hub is stopped
        controller.revoke(ctrl_op, req_id)

        # Restarted hub must fail closed on dispatch AND new sends
        reg2 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        hub2 = CoordHub(
            reg2,
            transport,
            self.state_dir,
            controller=controller,
            sandbox_root=self.sandbox_root,
        )
        try:
            self.assertEqual(hub2.dispatch_once(), 0)
            self.assertEqual(transport.dispatched_turns("sb1"), [])
            with self.assertRaises(RevokedError):
                hub2.send(_OP, target="sb1", body_text="Must deny after controller revoke")
        finally:
            hub2.close()
            reg2.close()

        # Durable degraded marker survives restart
        reg3 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        hub3 = CoordHub(reg3, transport, self.state_dir, sandbox_root=self.sandbox_root)
        try:
            hub3._mark_degraded("simulated_tombstone_write_failure")
            self.assertTrue(hub3.is_degraded)
        finally:
            hub3.close()
            reg3.close()

        reg4 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        hub4 = CoordHub(reg4, transport, self.state_dir, sandbox_root=self.sandbox_root)
        try:
            self.assertTrue(hub4.is_degraded)
            self.assertEqual(hub4.dispatch_once(), 0)
        finally:
            hub4.close()
            reg4.close()

    def test_p1_5_outbox_zero_bytes_revoke_post_revoke_receipt_and_aborted_stream(self) -> None:
        reg, transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="sb-a",
            incarnation_id="inc_a1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="SB A",
        )
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-a")

        # 1. ZERO_BYTES_SENT coinciding with revocation cancels dispatch_started and deletes receipt
        send1 = hub.send(_OP, target="sb-a", body_text="Turn 1")
        msg1 = send1["msg_id"]
        orig_dispatch = transport.dispatch_turn

        def _zero_and_revoke(turn: Any) -> Any:
            hub.revoke(_OP, target="sb-a", reason="mid-zero-revoke")
            return TurnScript(outcome=DispatchOutcome.ZERO_BYTES_SENT, detail="revoked").outcome

        transport.queue_script(
            "sb-a", TurnScript(outcome=DispatchOutcome.ZERO_BYTES_SENT, detail="pre-write-refused")
        )
        # Revoke after mark_outbox_dispatch_started by wrapping transport.dispatch_turn
        def _dispatch_zero_then_revoke(turn: Any) -> Any:
            res = orig_dispatch(turn)
            reg.revoke_grant_and_cancel_outbox(target_addr="sb-a", reason="raced-revoke")
            return res

        transport.dispatch_turn = _dispatch_zero_then_revoke  # type: ignore[method-assign]
        hub.dispatch_once()
        transport.dispatch_turn = orig_dispatch  # type: ignore[method-assign]
        cancelled_rows = reg.list_outbox(statuses=("cancelled",))
        self.assertTrue(any(r["msg_id"] == msg1 for r in cancelled_rows))
        self.assertIsNone(reg.consume_dispatch_receipt("sb-a", "inc_a1", _THREAD_MAIN, msg1, "Turn 1"))
        with self.assertRaises(RevokedError):
            reg.mint_tui_enter_token("sb-a", "inc_a1", "opencode-tui")

        # 2. Aborted/errored stream must NOT be marked 'completed'
        hub.register_sandbox(
            _OP,
            name="sb-b",
            incarnation_id="inc_b1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="SB B",
        )
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-b")
        transport.queue_script(
            "sb-b", TurnScript(echo_user_message=False, terminal_type="turn_error", terminal_text="boom")
        )
        send2 = hub.send(_OP, target="sb-b", body_text="Turn error test")
        hub.dispatch_once()
        aborted_rows = reg.list_outbox(statuses=("aborted",))
        self.assertTrue(any(r["msg_id"] == send2["msg_id"] for r in aborted_rows))
        completed_rows = reg.list_outbox(statuses=("completed",))
        self.assertFalse(any(r["msg_id"] == send2["msg_id"] for r in completed_rows))

    def test_p1_6_wait_registers_before_revoke_check_no_missed_wakeup(self) -> None:
        reg, _transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="sb-wait",
            incarnation_id="inc_w1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Wait race test",
        )
        # Trigger revoke on the first list_events_since() call (the exact TOCTOU window
        # between _assert_targets_not_revoked and _waiters.add in f4cc88e9)
        orig_list = reg.list_events_since
        triggered = [False]
        rev_threads: list[threading.Thread] = []

        def _racy_list(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            if not triggered[0]:
                triggered[0] = True
                t = threading.Thread(
                    target=lambda: hub.revoke(_OP, target="sb-wait", reason="raced-during-wait"),
                    daemon=True,
                )
                rev_threads.append(t)
                t.start()
                time.sleep(0.05)
            return orig_list(*args, **kwargs)

        reg.list_events_since = _racy_list  # type: ignore[method-assign]
        t0 = time.monotonic()
        with self.assertRaises(RevokedError):
            hub.wait(_OP, targets=["sb-wait"], since_seq=999_999, timeout_s=0.4)
        self.assertLess(time.monotonic() - t0, 0.35)
        for t in rev_threads:
            t.join(timeout=1.0)

    def test_p1_7_hostile_surrogate_cross_thread_and_bypassed_stream_event(self) -> None:
        reg, transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="sb-hostile",
            incarnation_id="inc_h1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Hostile worker test",
        )
        hub.grant_edge(
            _OP,
            src_actor=_OP.canonical_sender,
            dst_addr="sb-hostile",
            allowed_threads=(_THREAD_REVIEW,),
        )
        # Unpaired surrogate rejected cleanly in StreamEvent constructor
        with self.assertRaises(CoordValidationError):
            StreamEvent("text_delta", "sb-hostile", "inc_h1", _THREAD_REVIEW, text="bad\ud800surrogate")

        # Cross-thread injection from hostile worker on 'review' targeting 'main' must be dropped
        cross_thread_ev = StreamEvent(
            "turn_completed", "sb-hostile", "inc_h1", _THREAD_MAIN, text="forged main complete"
        )
        transport.queue_script(
            "sb-hostile",
            TurnScript(hostile_raw_events=(cross_thread_ev,)),
            thread_id=_THREAD_REVIEW,
        )
        hub.send(_OP, target="sb-hostile", thread_id=_THREAD_REVIEW, body_text="review task")
        hub.dispatch_once()
        main_events = [
            e for e in reg.list_events_since(["sb-hostile"], 0) if e.get("thread_id") == _THREAD_MAIN
        ]
        self.assertEqual(main_events, [])

        # Bypassed __post_init__ StreamEvent must still be rejected by record_stream_event()
        forged_ev = object.__new__(StreamEvent)
        object.__setattr__(forged_ev, "event_type", "forged_admin_event")
        object.__setattr__(forged_ev, "sandbox_addr", "../escape")
        object.__setattr__(forged_ev, "incarnation_id", "inc_h1")
        object.__setattr__(forged_ev, "thread_id", "../bad")
        object.__setattr__(forged_ev, "seq_hint", 0)
        object.__setattr__(forged_ev, "message_id", None)
        object.__setattr__(forged_ev, "text", "ok")
        object.__setattr__(forged_ev, "file_path", "../../../etc/passwd")
        object.__setattr__(forged_ev, "detail", {})
        object.__setattr__(forged_ev, "created_at", 0.0)
        with self.assertRaises(CoordValidationError):
            reg.record_stream_event(forged_ev)

    def test_p2_1_near_64k_peer_message_frames_and_consumes_receipt_cleanly(self) -> None:
        reg, transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="peer-src",
            incarnation_id="inc_s1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Src",
        )
        hub.register_sandbox(
            _OP,
            name="peer-dst",
            incarnation_id="inc_d1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Dst",
        )
        hub.grant_edge(
            _OP,
            src_actor="peer-src",
            src_incarnation="inc_s1",
            dst_addr="peer-dst",
            allowed_msg_kinds=("review_request",),
        )
        caller = PrincipalCtx(
            CoordRole.JOB, "job-src", sandbox_addr="peer-src", incarnation_id="inc_s1"
        )
        near_64k = "x" * 65_500
        res = hub.send(
            caller, target="peer-dst", msg_kind="review_request", body_text=near_64k
        )
        self.assertEqual(hub.dispatch_once(), 1)
        events = reg.list_events_since(["peer-dst"], 0)
        user_msgs = [
            e for e in events if e.get("event_type") == "user_message" and e.get("message_id") == res["msg_id"]
        ]
        self.assertEqual(len(user_msgs), 1)
        self.assertEqual(user_msgs[0]["badge"], ProvenanceBadge.PEER.value)

    def test_p2_2_artifact_spool_auto_reconciles_and_recovers_quotas_on_restart(self) -> None:
        spool1 = ArtifactSpool(
            self.state_dir,
            sandbox_root=self.sandbox_root,
            max_global_count=1,
            max_global_bytes=128,
        )
        abandoned = spool1.staging_root / "adm_abandoned"
        abandoned.mkdir(mode=0o700)
        (abandoned / "stale.patch").write_bytes(b"stale")
        resv = spool1.reserve("edge-1", [b"0123456789"])
        spool1.stage_blobs(resv, [b"0123456789"])
        spool1.publish(resv, "inc_pub1")

        # Restarted ArtifactSpool must auto-reclaim .staging and count existing published blobs
        spool2 = ArtifactSpool(
            self.state_dir,
            sandbox_root=self.sandbox_root,
            max_global_count=1,
            max_global_bytes=128,
        )
        self.assertEqual(list(spool2.staging_root.iterdir()), [])
        self.assertEqual(spool2.usage_snapshot()["published_count"], 1)
        with self.assertRaises(CoordBackpressureError):
            spool2.reserve("edge-2", [b"another"])

    def test_p2_3_in_reply_to_rejects_cancelled_and_prior_incarnation_messages(self) -> None:
        reg, _transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="sb-x",
            incarnation_id="inc_x1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="SB X",
        )
        hub.register_sandbox(
            _OP,
            name="sb-y",
            incarnation_id="inc_y1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="SB Y",
        )
        hub.grant_edge(
            _OP,
            src_actor="sb-x",
            src_incarnation="inc_x1",
            dst_addr="sb-y",
            allowed_msg_kinds=("question",),
        )
        hub.grant_edge(
            _OP,
            src_actor="sb-y",
            dst_addr="sb-x",
            allowed_msg_kinds=("answer",),
        )
        ctx_x = PrincipalCtx(CoordRole.JOB, "jx", sandbox_addr="sb-x", incarnation_id="inc_x1")
        ctx_y1 = PrincipalCtx(CoordRole.JOB, "jy1", sandbox_addr="sb-y", incarnation_id="inc_y1")

        # 1. Cancelled message cannot be replied to
        q1 = hub.send(ctx_x, target="sb-y", msg_kind="question", body_text="q1")
        reg.cancel_outbox_row(q1["msg_id"], reason="never_delivered")
        with self.assertRaises(CoordValidationError):
            hub.send(
                ctx_y1,
                target="sb-x",
                msg_kind="answer",
                body_text="reply to cancelled",
                in_reply_to=q1["msg_id"],
            )

        # 2. Message delivered to inc_y1 cannot be replied to by rotated inc_y2
        q2 = hub.send(ctx_x, target="sb-y", msg_kind="question", body_text="q2")
        hub.dispatch_once()
        hub.register_sandbox(
            _OP,
            name="sb-y",
            incarnation_id="inc_y2",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="SB Y rotated",
        )
        hub.grant_edge(
            _OP,
            src_actor="sb-y",
            src_incarnation="inc_y2",
            dst_addr="sb-x",
            allowed_msg_kinds=("answer",),
        )
        ctx_y2 = PrincipalCtx(CoordRole.JOB, "jy2", sandbox_addr="sb-y", incarnation_id="inc_y2")
        with self.assertRaises(CoordValidationError):
            hub.send(
                ctx_y2,
                target="sb-x",
                msg_kind="answer",
                body_text="reply from rotated inc",
                in_reply_to=q2["msg_id"],
            )

    def test_p2_4_ui_auth_requires_origin_on_exchange_and_session_on_ws_consume(self) -> None:
        now = [100.0]
        mgr = UiAuthManager(
            allowed_hosts={_HOST}, allowed_origins={_ORIGIN}, clock=lambda: now[0]
        )
        code = mgr.mint_bootstrap_code()
        with self.assertRaises(UiAuthDeniedError):
            mgr.exchange_bootstrap_code(code, host_header=_HOST, origin_header=None)

        code2 = mgr.mint_bootstrap_code()
        _rec, csrf, cookie = mgr.exchange_bootstrap_code(
            code2, host_header=_HOST, origin_header=_ORIGIN
        )
        sid = cookie.split(";", 1)[0].split("=", 1)[1]
        tk = mgr.mint_ws_ticket(
            sid,
            host_header=_HOST,
            origin_header=_ORIGIN,
            csrf_token=csrf,
            target_addr="feat-a",
            incarnation_id="inc_1",
            surface_kind="opencode-tui",
            mode="observe",
        )
        with self.assertRaises(UiAuthDeniedError):
            mgr.consume_ws_ticket(
                tk,
                host_header=_HOST,
                origin_header=_ORIGIN,
                expected_target_addr="feat-a",
                expected_incarnation_id="inc_1",
                expected_surface_kind="opencode-tui",
                expected_mode="observe",
                expected_session_id=None,
            )

    def test_p2_5_rpc_wait_target_cap_reason_bounds_and_role_config_guard(self) -> None:
        _reg, _transport, hub = self._new_stack()
        bad_sock = self.sock_dir / "bad_job.sock"
        with self.assertRaises(ValueError):
            CoordUdsRpcServer(hub, bad_sock, sandbox_root=self.sandbox_root, role=CoordRole.JOB)

        sock_path = self.sock_dir / "op.sock"
        rpc = CoordUdsRpcServer(hub, sock_path, sandbox_root=self.sandbox_root)
        rpc.start()
        self.addCleanup(rpc.stop)

        too_many_targets = [f"sb-{i}" for i in range(65)]
        wait_resp = uds_rpc_call(
            sock_path, "coord.wait", {"targets": too_many_targets, "timeout_s": 0.1}
        )
        self.assertEqual(wait_resp["error"]["code"], -32602)

        bad_reason_resp = uds_rpc_call(
            sock_path, "coord.revoke", {"target": "sb-a", "reason": "x" * 300}
        )
        self.assertEqual(bad_reason_resp["error"]["code"], -32602)

    def test_p3_1_p3_2_p3_3_publish_rollback_symlink_ancestor_and_job_ctx(self) -> None:
        # P3-3: JOB principal requires sandbox_addr and incarnation_id
        with self.assertRaises(CoordValidationError):
            PrincipalCtx(CoordRole.JOB, "job-no-sb")

        # P3-2: ArtifactSpool rejects symlinked ancestor before mkdir
        real_dir = self.root / "real_target"
        real_dir.mkdir(mode=0o700)
        sym_parent = self.root / "sym_parent"
        os.symlink(real_dir, sym_parent)
        with self.assertRaises(CoordPolicyError):
            ArtifactSpool(sym_parent / "nested_state", sandbox_root=self.sandbox_root)

        # P3-1: publish() failure cancels the newly committed outbox row
        reg, _transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="sb-pub",
            incarnation_id="inc_pub",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Publish rollback test",
        )
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-pub")

        def _boom(_resv: Any, _inc: str) -> None:
            raise OSError("disk_full")

        hub.spool.publish = _boom  # type: ignore[method-assign]
        with self.assertRaises(OSError):
            hub.send(_OP, target="sb-pub", body_text="fail publish", artifact_blobs=(b"patch",))
        self.assertEqual(reg.list_outbox(statuses=("pending",)), [])
        self.assertEqual(len(reg.list_outbox(statuses=("cancelled",))), 1)


if __name__ == "__main__":
    unittest.main()
