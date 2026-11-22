"""Dedicated Gate 2 adversarial regression tests for PRD M coordination.

Every test reproduces a specific Round 1 or Round 2 finding and verifies its fix.
"""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
from unittest import mock
from typing import Any

_SPIKE_M_DIR = Path(__file__).resolve().parent
if str(_SPIKE_M_DIR) not in sys.path:
    sys.path.insert(0, str(_SPIKE_M_DIR))

from test_prd_m_coord_e2e import (  # noqa: E402
    CoordTestBase,
    _E2eFixtureAdapter,
    _create_controller_lease,
)
from oc_broker_common import BrokerError, BrokerLease, UdsStartupError  # noqa: E402
from oc_controller import (  # noqa: E402
    Capability,
    Controller,
    Decision,
    Intent,
    Job,
    Operation,
    Principal,
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


def _make_controller_lease(
    sandbox_name: str, incarnation_id: str
) -> tuple[Controller, Principal, BrokerLease, str]:
    return _create_controller_lease(sandbox_name=sandbox_name, incarnation_id=incarnation_id)


class TestGate2Round1Regressions(CoordTestBase):
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
        _, transport, hub = self._new_stack()
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
        controller, ctrl_op, _lease, req_id = _make_controller_lease("sb1", "inc_ctrl_1")
        reg1 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        transport = FakeWorkerTransport()
        hub1 = CoordHub(
            reg1,
            transport,
            self.state_dir,
            controller=controller,
            controller_actor=ctrl_op,
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
            controller_actor=ctrl_op,
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
        reg, _, hub = self._new_stack()
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


def _make_dual_request_controller() -> tuple[Controller, Principal, BrokerLease, str, str]:
    operator = Principal(Role.OPERATOR, "op-r2")
    orchestrator = Principal(Role.ORCHESTRATOR, "orch-r2")
    job_actor = Principal(Role.JOB, "chan-r2")
    subject = Subject("worker-local", "inc_dual_1", "chan-r2")
    controller = Controller(
        incarnation="c" * 32,
        clock=lambda: 100,
        lifetime=3600,
        workers=[Worker("worker-local", operator)],
        jobs=[Job(subject, orchestrator, proposal_budget=8)],
        capabilities=[
            Capability("cap-sb", Operation.PROBE, "tgt-sb"),
            Capability("cap-edge", Operation.PROBE, "tgt-edge"),
        ],
        references=[
            Reference("ref-sb", "cap-sb"),
            Reference("ref-edge", "cap-edge"),
        ],
        adapter=_E2eFixtureAdapter(),
    )
    controller._set_alias("alias-sb", "tgt-sb")
    controller._set_alias("alias-edge", "tgt-edge")
    st_sb = controller.propose(job_actor, Proposal(Intent.PROBE_GRANT, "alias-sb", "ref-sb"))
    v_sb = controller.view(operator, st_sb.request_id)
    controller.decide(operator, st_sb.request_id, v_sb.payload.revision, v_sb.digest, Decision.APPROVE)
    st_edge = controller.propose(job_actor, Proposal(Intent.PROBE_GRANT, "alias-edge", "ref-edge"))
    v_edge = controller.view(operator, st_edge.request_id)
    controller.decide(
        operator, st_edge.request_id, v_edge.payload.revision, v_edge.digest, Decision.APPROVE
    )
    lease_sb = BrokerLease(
        "job-dual",
        controller=controller,
        controller_actor=operator,
        controller_request_id=st_sb.request_id,
    )
    return controller, operator, lease_sb, st_sb.request_id, st_edge.request_id


class TestGate2Round2Regressions(CoordTestBase):
    def _new_stack(self) -> tuple[CoordRegistry, FakeWorkerTransport, CoordHub]:
        reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        transport = FakeWorkerTransport()
        hub = CoordHub(reg, transport, self.state_dir, sandbox_root=self.sandbox_root)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        return reg, transport, hub

    def test_r2_p1_1_shared_thread_wait_hides_operator_stream_and_catches_mid_wait_edge_revoke(
        self,
    ) -> None:
        reg, transport, hub = self._new_stack()
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
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="target-b")
        peer_edge = hub.grant_edge(
            _OP,
            src_actor="peer-a",
            src_incarnation="inc_a1",
            dst_addr="target-b",
            allowed_threads=(_THREAD_MAIN,),
            allowed_msg_kinds=("review_request",),
        )
        transport.queue_script(
            "target-b",
            TurnScript(
                text_chunks=("TOP_SECRET_OPERATOR_ANSWER",),
                file_edits=("secrets.env",),
            ),
            thread_id=_THREAD_MAIN,
        )
        hub.send(_OP, target="target-b", thread_id=_THREAD_MAIN, body_text="Operator secret")
        hub.dispatch_once()

        peer_a = PrincipalCtx(
            CoordRole.JOB, "job-a", sandbox_addr="peer-a", incarnation_id="inc_a1"
        )
        # 1. Peer on shared 'main' thread MUST NOT see Operator's assistant text_delta/file_edit/turn_completed
        wait_res = hub.wait(peer_a, targets=["target-b"], since_seq=0, timeout_s=0.05)
        self.assertEqual(wait_res["events"], [])
        self.assertTrue(wait_res["timed_out"])

        # 2. Mid-wait single-edge revocation must raise RevokedError on wakeup (not return post-revoke events)
        wait_exc: list[Exception] = []
        started = threading.Event()

        def _waiter() -> None:
            started.set()
            try:
                hub.wait(peer_a, targets=["target-b"], since_seq=0, timeout_s=2.0)
            except Exception as exc:
                wait_exc.append(exc)

        wt = threading.Thread(target=_waiter, daemon=True)
        wt.start()
        self.assertTrue(started.wait(timeout=1.0))
        time.sleep(0.05)
        reg.revoke_grant_and_cancel_outbox(edge_id=peer_edge.edge_id, reason="single_edge_revoked")
        hub._notify_waiters()
        wt.join(timeout=1.0)
        self.assertEqual(len(wait_exc), 1)
        self.assertIsInstance(wait_exc[0], RevokedError)

    def test_r2_p1_2_restarted_hub_rejects_revoked_sandbox_request_with_distinct_edge_lease(
        self,
    ) -> None:
        controller, ctrl_op, _lease_sb, req_sb, req_edge = _make_dual_request_controller()
        reg1 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        transport = FakeWorkerTransport()
        hub1 = CoordHub(
            reg1,
            transport,
            self.state_dir,
            controller=controller,
            controller_actor=ctrl_op,
            sandbox_root=self.sandbox_root,
        )
        try:
            hub1.register_sandbox(
                _OP,
                name="sb-dual",
                incarnation_id="inc_dual_1",
                project_id="p1",
                project_name="P1",
                branch="main",
                task_brief="Dual lease sandbox",
                controller_request_id=req_sb,
            )
            hub1.grant_edge(
                _OP,
                src_actor=_OP.canonical_sender,
                dst_addr="sb-dual",
                lease_request_id=req_edge,
            )
            hub1.send(_OP, target="sb-dual", body_text="Queued turn")
        finally:
            hub1.close()
            reg1.close()

        # Revoke ONLY sandbox controller_request_id (leaving distinct edge lease_request_id active!)
        controller.revoke(ctrl_op, req_sb)

        reg2 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        hub2 = CoordHub(
            reg2,
            transport,
            self.state_dir,
            controller=controller,
            controller_actor=ctrl_op,
            sandbox_root=self.sandbox_root,
        )
        try:
            self.assertEqual(hub2.dispatch_once(), 0)
            self.assertEqual(transport.dispatched_turns("sb-dual"), [])
            with self.assertRaises(RevokedError):
                hub2.send(_OP, target="sb-dual", body_text="Should fail closed")
        finally:
            hub2.close()
            reg2.close()

    def test_r2_p2_1_sql_where_pushdown_prevents_operator_flood_starving_peer_wait(self) -> None:
        _, transport, hub = self._new_stack()
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
            allowed_threads=(_THREAD_MAIN,),
        )
        hub.grant_edge(
            _OP,
            src_actor="peer-a",
            src_incarnation="inc_a1",
            dst_addr="target-b",
            allowed_threads=(_THREAD_REVIEW,),
            allowed_msg_kinds=("review_request",),
        )
        # Emit 850 operator stream events on 'main' (> 4 * 200)
        transport.queue_script(
            "target-b",
            TurnScript(text_chunks=tuple(f"op-{i}" for i in range(850))),
            thread_id=_THREAD_MAIN,
        )
        hub.send(_OP, target="target-b", thread_id=_THREAD_MAIN, body_text="Long op turn")
        hub.dispatch_once()

        peer_a = PrincipalCtx(
            CoordRole.JOB, "job-a", sandbox_addr="peer-a", incarnation_id="inc_a1"
        )
        transport.queue_script(
            "target-b",
            TurnScript(text_chunks=("LGTM",)),
            thread_id=_THREAD_REVIEW,
        )
        hub.send(
            peer_a,
            target="target-b",
            thread_id=_THREAD_REVIEW,
            msg_kind="review_request",
            body_text="Check diff",
        )
        hub.dispatch_once()

        wait_res = hub.wait(peer_a, targets=["target-b"], since_seq=0, timeout_s=0.1)
        texts = [ev.get("text") for ev in wait_res["events"]]
        self.assertIn("LGTM", texts)

    def test_r2_p2_2_multi_principal_rpc_rate_limiter_isolates_noisy_job_from_operator(
        self,
    ) -> None:
        _reg, _transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="sb-rl",
            incarnation_id="inc_rl1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Rate limit isolation",
        )
        job_a = PrincipalCtx(CoordRole.JOB, "job-rl", sandbox_addr="sb-rl", incarnation_id="inc_rl1")
        sock_path = self.sock_dir / "multi.sock"
        rpc = CoordUdsRpcServer(
            hub,
            sock_path,
            sandbox_root=self.sandbox_root,
            token_principals={"tok_job_a": job_a, "tok_op": _OP},
            rate_limit_max=2,
            rate_limit_window=60.0,
        )
        rpc.start()
        self.addCleanup(rpc.stop)

        # Noisy job exhausts its own per-principal limit (2 allowed, 3rd denied)
        r1 = uds_rpc_call(sock_path, "coord.status", {"target": "sb-rl"}, auth_token="tok_job_a")
        r2 = uds_rpc_call(sock_path, "coord.status", {"target": "sb-rl"}, auth_token="tok_job_a")
        r3 = uds_rpc_call(sock_path, "coord.status", {"target": "sb-rl"}, auth_token="tok_job_a")
        self.assertIn("result", r1)
        self.assertIn("result", r2)
        self.assertEqual(r3["error"]["message"], "principal_rate_limited")

        # Operator on the same multi-principal socket must NOT be starved by job_a
        op_resp = uds_rpc_call(sock_path, "coord.status", {"target": "sb-rl"}, auth_token="tok_op")
        self.assertIn("result", op_resp)

    def test_r2_p2_3_reregister_revoked_incarnation_denied_and_rotation_cleans_unpinned_edges(
        self,
    ) -> None:
        reg, _transport, hub = self._new_stack()
        hub.register_sandbox(
            _OP,
            name="sb-r",
            incarnation_id="inc_same",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Revoked inc test",
        )
        hub.register_sandbox(
            _OP,
            name="sb-dst",
            incarnation_id="inc_dst",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Dest",
        )
        # Revoke sb-r at inc_same, then attempt to re-register with the SAME inc_same -> MUST FAIL
        hub.revoke(_OP, target="sb-r", reason="kill")
        with self.assertRaises(RevokedError):
            hub.register_sandbox(
                _OP,
                name="sb-r",
                incarnation_id="inc_same",
                project_id="p1",
                project_name="P1",
                branch="main",
                task_brief="Attempt same-inc revival",
            )

        # Legitimate rotation on sb-rot: unpinned outgoing edge (src_incarnation=None) must be revoked
        hub.register_sandbox(
            _OP,
            name="sb-rot",
            incarnation_id="inc_rot_1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Rotatable",
        )
        unpinned = hub.grant_edge(
            _OP,
            src_actor="sb-rot",
            src_incarnation=None,
            dst_addr="sb-dst",
        )
        hub.register_sandbox(
            _OP,
            name="sb-rot",
            incarnation_id="inc_rot_2",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Rotated to v2",
        )
        edge_after = reg.get_edge(unpinned.edge_id)
        self.assertIsNotNone(edge_after)
        self.assertFalse(edge_after.active)
        self.assertTrue(hub._is_target_fenced("sb-rot", "inc_rot_1"))

    def test_r2_p3_1_and_p3_2_seq_hint_bounds_and_sub_orchestrator_child_edge_pinning(
        self,
    ) -> None:
        reg, _transport, hub = self._new_stack()
        # R2-P3-1: Invalid seq_hint (negative or > 64-bit int or bool) rejected in record_stream_event
        bad_ev = StreamEvent("text_delta", "sb-a", "inc_1", _THREAD_MAIN, seq_hint=-1, text="x")
        with self.assertRaises(CoordValidationError):
            reg.record_stream_event(bad_ev)

        # R2-P3-2: Sub-orchestrator granting child-to-child edge checks live source & pins incarnation
        hub.register_sandbox(
            _OP,
            name="orch-sub",
            incarnation_id="inc_os1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Sub orch",
        )
        orch_ctx = PrincipalCtx(
            CoordRole.ORCHESTRATOR, "orch-sub", sandbox_addr="orch-sub", incarnation_id="inc_os1"
        )
        hub.register_sandbox(
            orch_ctx,
            name="child-1",
            incarnation_id="inc_c1",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Child 1",
            parent_addr="orch-sub",
        )
        hub.register_sandbox(
            orch_ctx,
            name="child-2",
            incarnation_id="inc_c2",
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief="Child 2",
            parent_addr="orch-sub",
        )
        edge = hub.grant_edge(orch_ctx, src_actor="child-1", dst_addr="child-2")
        self.assertEqual(edge.src_incarnation, "inc_c1")

        hub.revoke(orch_ctx, target="child-1", reason="stop-child-1")
        with self.assertRaises(RevokedError):
            hub.grant_edge(orch_ctx, src_actor="child-1", dst_addr="child-2")


class TestReciprocalReviewRegressions(CoordTestBase):
    """Regressions for every finding from the PR #50 reciprocal security review."""

    def _open_pair(
        self,
        *,
        controller: Controller | None = None,
        controller_actor: Principal | None = None,
        root_budget: SubtreeBudget | None = None,
    ) -> tuple[CoordRegistry, FakeWorkerTransport, CoordHub]:
        reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        transport = FakeWorkerTransport()
        hub = CoordHub(
            reg,
            transport,
            self.state_dir,
            controller=controller,
            controller_actor=controller_actor,
            root_budget=root_budget,
            sandbox_root=self.sandbox_root,
            watchdog_interval_s=0.02,
        )
        return reg, transport, hub

    @staticmethod
    def _reg_sb(
        hub: CoordHub,
        caller: PrincipalCtx,
        name: str,
        inc: str,
        **kwargs: Any,
    ) -> Any:
        return hub.register_sandbox(
            caller,
            name=name,
            incarnation_id=inc,
            project_id="p1",
            project_name="P1",
            branch="main",
            task_brief=f"Task {name}",
            **kwargs,
        )

    def test_rec_p1_1_narrowed_parent_budget_persists_and_missing_budget_fails_closed(
        self,
    ) -> None:
        root_b = SubtreeBudget(allowed_sandbox_types=frozenset({"default", "reviewer"}))
        narrow = SubtreeBudget(
            max_depth_remaining=1,
            max_children=1,
            max_total_sandboxes=4,
            allowed_sandbox_types=frozenset({"reviewer"}),
        )
        reg1, transport, hub1 = self._open_pair(root_budget=root_b)
        try:
            self._reg_sb(hub1, _OP, "sub-orch", "inc_so1", child_budget=narrow)
        finally:
            hub1.close()
            reg1.close()

        orch_ctx = PrincipalCtx(
            CoordRole.ORCHESTRATOR, "sub-orch", sandbox_addr="sub-orch", incarnation_id="inc_so1"
        )
        reg2, _t2, hub2 = self._open_pair(root_budget=root_b)
        try:
            # Must NOT fall back to root_budget (which permits "default" and max_children=8)
            with self.assertRaises(CoordPolicyError):
                self._reg_sb(hub2, orch_ctx, "c-default", "inc_c0", parent_addr="sub-orch")
            self._reg_sb(
                hub2,
                orch_ctx,
                "c-rev1",
                "inc_c1",
                sandbox_type="reviewer",
                parent_addr="sub-orch",
            )
            with self.assertRaises(CoordPolicyError):
                self._reg_sb(
                    hub2,
                    orch_ctx,
                    "c-rev2",
                    "inc_c2",
                    sandbox_type="reviewer",
                    parent_addr="sub-orch",
                )
            # Delete persisted budget row to simulate missing budget -> fail closed
            with reg2._tx() as conn:
                conn.execute("DELETE FROM sandbox_budgets WHERE sandbox_addr = ?", ("sub-orch",))
        finally:
            hub2.close()
            reg2.close()

        reg3, _t3, hub3 = self._open_pair(root_budget=root_b)
        try:
            with self.assertRaises(CoordPolicyError):
                self._reg_sb(
                    hub3,
                    orch_ctx,
                    "c-after-del",
                    "inc_c3",
                    sandbox_type="reviewer",
                    parent_addr="sub-orch",
                )
        finally:
            hub3.close()
            reg3.close()
        _ = transport

    def test_rec_p1_2_peer_wait_uses_host_dispatch_attribution_for_unmatched_events(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "peer-a", "inc_a1")
        self._reg_sb(hub, _OP, "target-b", "inc_b1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="target-b")
        hub.grant_edge(_OP, src_actor="peer-a", dst_addr="target-b")
        peer_a = PrincipalCtx(
            CoordRole.JOB, "peer-a", sandbox_addr="peer-a", incarnation_id="inc_a1"
        )

        # Malicious worker emits null and spoofed message_id during an OPERATOR turn
        transport.queue_script(
            "target-b",
            TurnScript(
                hostile_raw_events=(
                    StreamEvent("text_delta", "target-b", "inc_b1", _THREAD_MAIN, message_id=None, text="OP_SECRET_NULL"),
                    StreamEvent(
                        "text_delta",
                        "target-b",
                        "inc_b1",
                        _THREAD_MAIN,
                        message_id="msg_unmatched_spoof",
                        text="OP_SECRET_UNMATCHED",
                    ),
                )
            ),
        )
        hub.send(_OP, target="target-b", body_text="Secret operator directive")
        hub.dispatch_once()

        peer_wait_op = hub.wait(peer_a, targets=["target-b"], since_seq=0, timeout_s=0.05)
        leaked_texts = [ev.get("text", "") for ev in peer_wait_op["events"]]
        self.assertNotIn("OP_SECRET_NULL", leaked_texts)
        self.assertNotIn("OP_SECRET_UNMATCHED", leaked_texts)

        # Peer-dispatched turn with worker message_id=None IS visible via host dispatch_msg_id
        transport.queue_script(
            "target-b",
            TurnScript(
                hostile_raw_events=(
                    StreamEvent("text_delta", "target-b", "inc_b1", _THREAD_MAIN, message_id=None, text="PEER_OK_NULL"),
                )
            ),
        )
        hub.send(peer_a, target="target-b", body_text="Peer prompt")
        hub.dispatch_once()

        peer_wait_ok = hub.wait(peer_a, targets=["target-b"], since_seq=0, timeout_s=0.05)
        visible_texts = [ev.get("text", "") for ev in peer_wait_ok["events"]]
        self.assertIn("PEER_OK_NULL", visible_texts)

    def test_rec_p1_3_read_and_wait_reauthorization_enforce_live_edge_and_controller_grants(
        self,
    ) -> None:
        controller, ctrl_op, lease_sb, req_sb, req_edge = _make_dual_request_controller()
        reg, _transport, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "peer-a", "inc_a1")
        self._reg_sb(
            hub,
            _OP,
            "target-b",
            "inc_b1",
            lease=lease_sb,
            controller_request_id=req_sb,
        )
        hub.grant_edge(_OP, src_actor="peer-a", dst_addr="target-b", lease_request_id=req_edge)
        peer_a = PrincipalCtx(
            CoordRole.JOB, "peer-a", sandbox_addr="peer-a", incarnation_id="inc_a1"
        )
        self.assertIn("sandbox", hub.status(peer_a, target="target-b"))

        # Revoke ONLY the edge's controller grant -> peer status() and wait() must fail closed
        controller.revoke(ctrl_op, req_edge)
        with self.assertRaises(RevokedError):
            hub.status(peer_a, target="target-b")
        with self.assertRaises(RevokedError):
            hub.wait(peer_a, targets=["target-b"], since_seq=0, timeout_s=0.05)

        # Revoke the target sandbox's controller grant -> operator wait() must also fail closed
        controller.revoke(ctrl_op, req_sb)
        with self.assertRaises(RevokedError):
            hub.wait(_OP, targets=["target-b"], since_seq=0, timeout_s=0.05)

    def test_rec_p1_4_direct_hub_revoke_terminates_lease_and_stale_watchdog_skips_replacement(
        self,
    ) -> None:
        controller, ctrl_op, lease1, req1 = _make_controller_lease("sb-lease", "inc_1")
        reg, _transport, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-lease", "inc_1", lease=lease1, controller_request_id=req1)
        self.assertTrue(lease1.is_active())

        hub.revoke(_OP, target="sb-lease", reason="direct_hub_kill")
        self.assertFalse(lease1.is_active())

        # Register replacement with fresh lease; stale callback for old incarnation must not revoke it
        lease_old = BrokerLease("job_old_inc")
        lease_new = BrokerLease("job_new_inc")
        self._reg_sb(hub, _OP, "sb-rot", "inc_old", lease=lease_old)
        self._reg_sb(hub, _OP, "sb-rot", "inc_new", lease=lease_new)
        self.assertFalse(lease_old.is_active())
        self.assertTrue(lease_new.is_active())

        hub._on_lease_revoked("sb-rot", "inc_old", lease_old)
        time.sleep(0.05)
        st = hub.status(_OP, target="sb-rot")
        self.assertEqual(st["sandbox"]["status"], "running")
        self.assertEqual(st["sandbox"]["incarnation_id"], "inc_new")
        self.assertTrue(lease_new.is_active())

    def test_rec_p1_5_lease_authority_derived_verified_and_ephemeral_fails_closed_after_restart(
        self,
    ) -> None:
        controller, ctrl_op, lease_ctrl, req_ctrl = _make_controller_lease("sb-ctrl", "inc_c1")
        lease_eph = BrokerLease("job_ephemeral_only")
        reg1, _t1, hub1 = self._open_pair(controller=controller, controller_actor=ctrl_op)
        try:
            # Mismatched controller_request_id vs lease._controller_request_id rejected
            with self.assertRaises(CoordPolicyError):
                self._reg_sb(
                    hub1,
                    _OP,
                    "sb-bad",
                    "inc_bad",
                    lease=lease_ctrl,
                    controller_request_id="req_different_id",
                )
            # Omit controller_request_id -> derived automatically from lease
            rec_ctrl = self._reg_sb(hub1, _OP, "sb-ctrl", "inc_c1", lease=lease_ctrl)
            self.assertEqual(rec_ctrl.controller_request_id, req_ctrl)
            hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-ctrl")

            # Controller-only registration survives clean close and checks controller after restart
            self._reg_sb(hub1, _OP, "sb-ctrl-only", "inc_co1", controller_request_id=req_ctrl)
            hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-ctrl-only")

            # Ephemeral lease works before restart
            rec_eph = self._reg_sb(hub1, _OP, "sb-eph", "inc_e1", lease=lease_eph)
            self.assertIsNotNone(rec_eph.controller_request_id)
            hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-eph")
            hub1.send(_OP, target="sb-eph", body_text="Before restart ok")
        finally:
            hub1.close()
            reg1.close()

        controller.revoke(ctrl_op, req_ctrl)

        reg2, _t2, hub2 = self._open_pair(controller=controller, controller_actor=ctrl_op)
        try:
            # Lease-backed incarnations are durably retired at clean close
            self.assertEqual(reg2.get_sandbox("sb-ctrl").status, "revoked")  # type: ignore[union-attr]
            self.assertEqual(reg2.get_sandbox("sb-eph").status, "revoked")  # type: ignore[union-attr]
            with self.assertRaises(CoordAuthError):
                hub2.send(_OP, target="sb-ctrl", body_text="Must deny retired lease")
            with self.assertRaises(CoordAuthError):
                hub2.send(_OP, target="sb-eph", body_text="Must deny ephemeral after restart")
            # Controller-only registration detects out-of-band revoke after restart
            with self.assertRaises(RevokedError):
                hub2.send(_OP, target="sb-ctrl-only", body_text="Must deny after controller revoke")
        finally:
            hub2.close()
            reg2.close()

    @staticmethod
    def _simulate_crash(hub: CoordHub, reg: CoordRegistry) -> None:
        """Simulate SIGKILL: kernel releases flock fd without running hub.close()."""
        lock_fd = getattr(hub, "_state_lock_fd", -1)
        if lock_fd >= 0:
            os.close(lock_fd)
            hub._state_lock_fd = -1
        reg.close()

    def test_rec_p1_6_unclean_shutdown_fails_closed_until_operator_recovery(self) -> None:
        reg1, _t1, hub1 = self._open_pair()
        self._reg_sb(hub1, _OP, "sb-crash", "inc_1")
        # Simulate crash / double-persistence failure: kernel releases lock, .coord_session_active remains
        self._simulate_crash(hub1, reg1)

        reg2, _t2, hub2 = self._open_pair()
        try:
            self.assertTrue(hub2.is_degraded)
            with self.assertRaises(CoordPolicyError):
                self._reg_sb(hub2, _OP, "sb-after-crash", "inc_2")
            orch_caller = PrincipalCtx(CoordRole.ORCHESTRATOR, "orch-1")
            with self.assertRaises(CoordAuthError):
                hub2.confirm_recovery(orch_caller, reason="unauthorized")
            hub2.confirm_recovery(_OP, reason="operator_verified")
            self.assertFalse(hub2.is_degraded)
        finally:
            hub2.close()
            reg2.close()

        # After clean close(), next boot is healthy (not degraded)
        reg3, _t3, hub3 = self._open_pair()
        try:
            self.assertFalse(hub3.is_degraded)
        finally:
            hub3.close()
            reg3.close()

    def test_rec_p2_7_startup_reconciles_missing_artifact_and_restores_edge_charges(self) -> None:
        reg1, transport1, hub1 = self._open_pair()
        blob_ok = b"diff --git a/a.py b/a.py\n+ok\n"
        blob_lost = b"diff --git a/b.py b/b.py\n+lost\n"
        try:
            self._reg_sb(hub1, _OP, "sb-art", "inc_art1")
            edge = hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-art")
            hub1.send(_OP, target="sb-art", body_text="Good artifact", artifact_blobs=[blob_ok])
            hub1.dispatch_once()
            res_lost = hub1.send(
                _OP, target="sb-art", body_text="Lost artifact", artifact_blobs=[blob_lost]
            )
            lost_msg_id = res_lost["msg_id"]
            lost_env = reg1.get_envelope(lost_msg_id)
            self.assertIsNotNone(lost_env)
            lost_digest = lost_env.artifact_refs[0].blob_sha256
            # Simulate crash leaving committed outbox row without published spool file
            os.unlink(hub1.spool.spool_root / "inc_art1" / f"{lost_digest}.patch")
        finally:
            hub1.close()
            reg1.close()
        _ = transport1

        reg2, transport2, hub2 = self._open_pair()
        try:
            # Missing-blob pending row must be cancelled during startup reconciliation before dispatch
            self.assertEqual(hub2.dispatch_once(), 0)
            self.assertEqual(transport2.dispatched_turns("sb-art"), [])
            cancelled = reg2.list_outbox(statuses=("cancelled",))
            self.assertTrue(any(r["msg_id"] == lost_msg_id for r in cancelled))
            # Per-edge charges for the verified published blob must be restored on restart
            self.assertEqual(hub2.spool._edge_published_count.get(edge.edge_id), 1)
            self.assertEqual(hub2.spool._edge_published_bytes.get(edge.edge_id), len(blob_ok))
        finally:
            hub2.close()
            reg2.close()

    def test_rec_p2_8_split_rpc_operator_available_while_job_slots_held_and_saturated(
        self,
    ) -> None:
        from oc_coord_rpc import CoordSplitUdsRpcServer

        reg, _transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-sat", "inc_sat1")
        job_a = PrincipalCtx(
            CoordRole.JOB, "job-sat", sandbox_addr="sb-sat", incarnation_id="inc_sat1"
        )
        op_dir = self.sock_dir / "op"
        job_dir = self.sock_dir / "job"
        op_dir.mkdir(mode=0o700)
        job_dir.mkdir(mode=0o700)
        op_sock = op_dir / "operator.sock"
        job_sock = job_dir / "job.sock"
        # Reject wrong role, empty credentials, overlapping tokens, and shared socket directory
        with self.assertRaises(ValueError):
            CoordSplitUdsRpcServer(
                hub,
                operator_socket_path=op_sock,
                job_socket_path=job_sock,
                operator_token_principals={"tok_op": _OP},
                job_token_principals={"tok_op_bad": _OP},
            )
        with self.assertRaises(ValueError):
            CoordSplitUdsRpcServer(
                hub,
                operator_socket_path=op_sock,
                job_socket_path=job_sock,
                operator_token_principals={},
                job_token_principals={"tok_job": job_a},
            )
        with self.assertRaises(ValueError):
            CoordSplitUdsRpcServer(
                hub,
                operator_socket_path=op_sock,
                job_socket_path=job_sock,
                operator_token_principals={"shared_tok": _OP},
                job_token_principals={"shared_tok": job_a},
            )
        with self.assertRaises(ValueError):
            CoordSplitUdsRpcServer(
                hub,
                operator_socket_path=self.sock_dir / "op_same.sock",
                job_socket_path=self.sock_dir / "job_same.sock",
                operator_token_principals={"tok_op": _OP},
                job_token_principals={"tok_job": job_a},
            )
        rpc = CoordSplitUdsRpcServer(
            hub,
            operator_socket_path=op_sock,
            job_socket_path=job_sock,
            operator_token_principals={"tok_op": _OP},
            job_token_principals={"tok_job": job_a},
            sandbox_root=self.sandbox_root,
            operator_max_concurrent_conns=2,
            job_max_concurrent_conns=2,
            rate_limit_max=2,
            rate_limit_window=60.0,
            io_timeout=1.5,
        )
        rpc.start()
        self.addCleanup(rpc.stop)

        # Hold ALL job listener worker slots open simultaneously (slowloris/occupied slots)
        held_conns: list[socket.socket] = []
        try:
            for _ in range(2):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(str(job_sock))
                held_conns.append(s)
            time.sleep(0.05)

            # While job worker slots are 100% occupied, operator control succeeds immediately
            op1 = uds_rpc_call(op_sock, "coord.status", {"target": "sb-sat"}, auth_token="tok_op")
            op2 = uds_rpc_call(op_sock, "coord.status", {"target": "sb-sat"}, auth_token="tok_op")
            op3 = uds_rpc_call(op_sock, "coord.status", {"target": "sb-sat"}, auth_token="tok_op")
            self.assertIn("result", op1)
            self.assertIn("result", op2)
            self.assertEqual(op3["error"]["message"], "rate_limited")
        finally:
            for s in held_conns:
                s.close()

        # Wait briefly for held job handlers to unwind; next job call hits pre-parse rate_limited
        time.sleep(0.05)
        job_over = uds_rpc_call(
            job_sock, "coord.status", {"target": "sb-sat"}, auth_token="tok_job"
        )
        self.assertEqual(job_over["error"]["message"], "rate_limited")

    def test_rec_p2_9_rpc_server_retains_listener_ownership_through_incomplete_stop(self) -> None:
        reg, _transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        sock_path = self.sock_dir / "retry_stop.sock"
        rpc = CoordUdsRpcServer(hub, sock_path, sandbox_root=self.sandbox_root)
        rpc.start()

        real_stop = rpc._workers.stop
        attempts = {"count": 0}

        def _flaky_stop(listener: Any, bound: Any = None) -> None:
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise BrokerError("Broker stop incomplete; workers are still running")
            real_stop(listener, bound)

        rpc._workers.stop = _flaky_stop  # type: ignore[method-assign]
        with self.assertRaises(BrokerError):
            rpc.stop()
        # Ownership retained after failed stop; restart refused until stop succeeds
        self.assertIsNotNone(rpc._listener)
        self.assertIsNotNone(rpc._bound)
        with self.assertRaises(BrokerError):
            rpc.start()

        # Retry stop succeeds and cleans up socket
        rpc.stop()
        self.assertIsNone(rpc._listener)
        self.assertIsNone(rpc._bound)
        self.assertFalse(sock_path.exists())

    def test_rec_ui_auth_ws_ticket_pins_minting_origin_across_multi_origin_config(self) -> None:
        host_b = "localhost:47110"
        origin_b = f"https://{host_b}"
        mgr = UiAuthManager(allowed_hosts=[_HOST, host_b], allowed_origins=[_ORIGIN, origin_b])
        code = mgr.mint_bootstrap_code(actor_id="op1")
        _rec, csrf, set_cookie = mgr.exchange_bootstrap_code(
            code, host_header=_HOST, origin_header=_ORIGIN
        )
        session_id = set_cookie.split("=", 1)[1].split(";", 1)[0]

        ticket_cross = mgr.mint_ws_ticket(
            session_id,
            host_header=_HOST,
            origin_header=_ORIGIN,
            csrf_token=csrf,
            target_addr="sb-1",
            incarnation_id="inc_1",
            surface_kind="events",
            mode="observe",
        )
        with self.assertRaises(UiAuthDeniedError):
            mgr.consume_ws_ticket(
                ticket_cross,
                host_header=host_b,
                origin_header=origin_b,
                expected_target_addr="sb-1",
                expected_incarnation_id="inc_1",
                expected_surface_kind="events",
                expected_mode="observe",
                expected_session_id=session_id,
            )

        ticket_same = mgr.mint_ws_ticket(
            session_id,
            host_header=_HOST,
            origin_header=_ORIGIN,
            csrf_token=csrf,
            target_addr="sb-1",
            incarnation_id="inc_1",
            surface_kind="events",
            mode="observe",
        )
        scope = mgr.consume_ws_ticket(
            ticket_same,
            host_header=_HOST,
            origin_header=_ORIGIN,
            expected_target_addr="sb-1",
            expected_incarnation_id="inc_1",
            expected_surface_kind="events",
            expected_mode="observe",
            expected_session_id=session_id,
        )
        self.assertEqual(scope.minting_origin, _ORIGIN)

    def test_delta_p1_1_duplicate_close_and_failed_recovery_preserve_degraded_protection(
        self,
    ) -> None:
        # 1. Duplicate hub1.close() must NOT unlink hub2's active session seal
        reg1, _t1, hub1 = self._open_pair()
        hub1.close()
        reg1.close()

        reg2, _t2, hub2 = self._open_pair()
        self.assertFalse(hub2.is_degraded)
        # Duplicate close on old hub1 must be a no-op and leave hub2's seal intact
        hub1.close()
        self._simulate_crash(hub2, reg2)

        reg3, _t3, hub3 = self._open_pair()
        try:
            self.assertTrue(hub3.is_degraded)
            # 2. If writing session seal fails during confirm_recovery, .coord_degraded stays intact
            hub3._mark_degraded("simulated_persist_err")
            orig_marker = hub3._session_active_marker
            hub3._session_active_marker = self.state_dir / "nonexistent_dir" / "seal"
            with self.assertRaises(OSError):
                hub3.confirm_recovery(_OP, reason="will_fail")
            hub3._session_active_marker = orig_marker
            self.assertTrue(hub3.is_degraded)
            self.assertTrue(hub3._degraded_marker.exists())
        finally:
            hub3.close()
            reg3.close()

        reg4, _t4, hub4 = self._open_pair()
        try:
            self.assertTrue(hub4.is_degraded)
        finally:
            hub4.close()
            reg4.close()

    def test_delta_p1_2_failed_or_sub_orchestrator_register_cannot_mutate_hub_controller(
        self,
    ) -> None:
        reg, _t, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sub-o", "inc_so1")
        sub_ctx = PrincipalCtx(
            CoordRole.ORCHESTRATOR, "sub-o", sandbox_addr="sub-o", incarnation_id="inc_so1"
        )
        rogue_ctrl, _rogue_op, rogue_lease, _rogue_req = _make_controller_lease("c1", "inc_c1")
        # Unauthorized parent_addr=None fails BEFORE touching hub._controller
        with self.assertRaises(CoordAuthError):
            self._reg_sb(hub, sub_ctx, "c1", "inc_c1", parent_addr=None, lease=rogue_lease)
        self.assertIsNone(hub._controller)
        self.assertIsNone(hub._controller_actor)
        # Even with valid parent_addr, sub-orchestrator cannot bind hub._controller
        with self.assertRaises(CoordAuthError):
            self._reg_sb(hub, sub_ctx, "c1", "inc_c1", parent_addr="sub-o", lease=rogue_lease)
        self.assertIsNone(hub._controller)
        self.assertIsNone(hub._controller_actor)
        _ = rogue_ctrl

    def test_delta_p2_1_startup_reconciles_missing_artifact_in_dispatch_started_status(
        self,
    ) -> None:
        reg1, _t1, hub1 = self._open_pair()
        blob = b"diff --git a/c.py b/c.py\n+lost\n"
        try:
            self._reg_sb(hub1, _OP, "sb-ds", "inc_ds1")
            edge = hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-ds")
            res = hub1.send(_OP, target="sb-ds", body_text="Started", artifact_blobs=[blob])
            msg_id = res["msg_id"]
            env = reg1.get_envelope(msg_id)
            self.assertIsNotNone(env)
            digest = env.artifact_refs[0].blob_sha256
            started = reg1.mark_outbox_dispatch_started(
                msg_id,
                edge_id=edge.edge_id,
                grant_generation=edge.grant_generation,
                dst_incarnation="inc_ds1",
            )
            self.assertTrue(started)
            os.unlink(hub1.spool.spool_root / "inc_ds1" / f"{digest}.patch")
        finally:
            hub1.close()
            reg1.close()

        reg2, _t2, hub2 = self._open_pair()
        try:
            # Missing blob after dispatch_started preserves uncertainty with original msg_id
            uncertain = reg2.list_outbox(statuses=("uncertain",))
            self.assertTrue(any(r["msg_id"] == msg_id for r in uncertain))
            cancelled = reg2.list_outbox(statuses=("cancelled",))
            self.assertFalse(any(r["msg_id"] == msg_id for r in cancelled))
            still_started = reg2.list_outbox(statuses=("dispatch_started",))
            self.assertEqual(still_started, [])
            self.assertEqual(hub2.dispatch_once(), 0)
        finally:
            hub2.close()
            reg2.close()

    def test_delta_p2_2_grant_edge_rejects_ephemeral_prefix_and_invalid_lease_request_id(
        self,
    ) -> None:
        reg, _t, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-g", "inc_g1", lease=BrokerLease("job_fake"))
        with self.assertRaises(CoordValidationError):
            hub.grant_edge(
                _OP,
                src_actor=_OP.canonical_sender,
                dst_addr="sb-g",
                lease_request_id="ephemeral-lease:job_fake",
            )
        with self.assertRaises(CoordValidationError):
            hub.grant_edge(
                _OP,
                src_actor=_OP.canonical_sender,
                dst_addr="sb-g",
                lease_request_id="bad id with spaces",
            )

    def test_delta_close_drains_watchdog_threads_without_spurious_degraded(self) -> None:
        controller, ctrl_op, lease, req_id = _make_controller_lease("sb-wd", "inc_wd1")
        reg, _t, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self._reg_sb(hub, _OP, "sb-wd", "inc_wd1", lease=lease, controller_request_id=req_id)
        controller.revoke(ctrl_op, req_id)
        # Immediately close hub + registry while watchdog callback may be racing
        hub.close()
        reg.close()
        self.assertFalse(hub._watchdog_threads)
        self.assertFalse(hub._degraded_marker.exists())
        self.assertFalse(hub._session_active_marker.exists())

    def test_r3_p1_1_degraded_restart_blocks_peer_reads_and_wait_wakeups(self) -> None:
        reg1, _t1, hub1 = self._open_pair()
        self._reg_sb(hub1, _OP, "peer-a", "inc_a1")
        self._reg_sb(hub1, _OP, "target-b", "inc_b1")
        hub1.grant_edge(_OP, src_actor="peer-a", dst_addr="target-b")
        peer_a = PrincipalCtx(
            CoordRole.JOB, "peer-a", sandbox_addr="peer-a", incarnation_id="inc_a1"
        )
        hub1.send(peer_a, target="target-b", body_text="Historical turn")
        hub1.dispatch_once()
        # Simulate unpersisted revocation + crash leaving active SQLite edge intact
        hub1._mark_degraded("unpersisted_revoke")
        self._simulate_crash(hub1, reg1)

        reg2, _t2, hub2 = self._open_pair()
        try:
            self.assertTrue(hub2.is_degraded)
            with self.assertRaises(CoordPolicyError):
                hub2.status(peer_a, target="target-b")
            with self.assertRaises(CoordPolicyError):
                hub2.wait(peer_a, targets=["target-b"], since_seq=0, timeout_s=0.05)
            # Operator diagnostic path remains available while degraded
            diag = hub2.status(_OP, target="target-b")
            self.assertTrue(diag["degraded"])
            self.assertIn("projects", hub2.projection(_OP))
            # Recover: ALL pre-recovery grants AND incarnations are retired until fresh registration
            hub2.confirm_recovery(_OP, reason="diag_ok")
            with self.assertRaises(RevokedError):
                hub2.status(peer_a, target="peer-a")
            with self.assertRaises(RevokedError):
                hub2.status(peer_a, target="target-b")
            # Fresh incarnations + fresh edge restore service; mid-wait degrade wakes & denies
            self._reg_sb(hub2, _OP, "peer-a", "inc_a2")
            self._reg_sb(hub2, _OP, "target-b", "inc_b2")
            hub2.grant_edge(_OP, src_actor="peer-a", dst_addr="target-b")
            peer_a2 = PrincipalCtx(
                CoordRole.JOB, "peer-a", sandbox_addr="peer-a", incarnation_id="inc_a2"
            )
            wait_err: list[Exception] = []

            def _sleep_wait() -> None:
                try:
                    hub2.wait(peer_a2, targets=["target-b"], since_seq=9999, timeout_s=2.0)
                except Exception as exc:
                    wait_err.append(exc)

            wt = threading.Thread(target=_sleep_wait, daemon=True)
            wt.start()
            time.sleep(0.05)
            hub2._mark_degraded("mid_wait_degrade")
            wt.join(timeout=1.0)
            self.assertEqual(len(wait_err), 1)
            self.assertIsInstance(wait_err[0], CoordPolicyError)
        finally:
            hub2.close()
            reg2.close()

    def test_r3_p1_2_confirm_recovery_keeps_dispatch_closed_and_propagates_failure(self) -> None:
        reg1, _t1, hub1 = self._open_pair()
        blob = b"diff --git a/r.py b/r.py\n+rec\n"
        self._reg_sb(hub1, _OP, "sb-rec", "inc_rec1")
        hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-rec")
        res = hub1.send(_OP, target="sb-rec", body_text="Pending blob", artifact_blobs=[blob])
        env = reg1.get_envelope(res["msg_id"])
        self.assertIsNotNone(env)
        os.unlink(hub1.spool.spool_root / "inc_rec1" / f"{env.artifact_refs[0].blob_sha256}.patch")
        self._simulate_crash(hub1, reg1)

        # Part A: Pause inside reconciliation; dispatch and admission must remain closed
        reg2, transport2, hub2 = self._open_pair()
        try:
            self.assertTrue(hub2.is_degraded)
            entered = threading.Event()
            release = threading.Event()
            orig_rec = hub2._reconcile_artifacts_on_startup

            def _paused_rec(*, raise_on_error: bool = False) -> None:
                entered.set()
                release.wait(timeout=2.0)
                orig_rec(raise_on_error=raise_on_error)

            hub2._reconcile_artifacts_on_startup = _paused_rec  # type: ignore[method-assign]
            t = threading.Thread(
                target=lambda: hub2.confirm_recovery(_OP, reason="paused_ok"), daemon=True
            )
            t.start()
            self.assertTrue(entered.wait(timeout=1.0))
            self.assertTrue(hub2.is_degraded)
            self.assertEqual(hub2.dispatch_once(), 0)
            self.assertEqual(transport2.dispatched_turns("sb-rec"), [])
            with self.assertRaises(CoordPolicyError):
                hub2.send(_OP, target="sb-rec", body_text="Must fail while reconciling")
            release.set()
            t.join(timeout=2.0)
            self.assertFalse(hub2.is_degraded)

            # Part B: Failing reconciliation must propagate, keep degraded, and not audit ok
            hub2._mark_degraded("need_rec_2")

            def _boom() -> list[dict[str, Any]]:
                raise OSError("db_reconcile_io_error")

            hub2._reconcile_artifacts_on_startup = orig_rec  # type: ignore[method-assign]
            orig_list = reg2.list_committed_artifact_manifests
            reg2.list_committed_artifact_manifests = _boom  # type: ignore[method-assign]
            try:
                with self.assertRaises(CoordPolicyError):
                    hub2.confirm_recovery(_OP, reason="will_fail_rec")
            finally:
                reg2.list_committed_artifact_manifests = orig_list  # type: ignore[method-assign]
            self.assertTrue(hub2.is_degraded)
            with reg2._lock:
                audits = reg2._conn.execute(
                    "SELECT action, detail_json FROM audit_log WHERE action = 'confirm_recovery'"
                ).fetchall()
            self.assertFalse(
                any("will_fail_rec" in str(a["detail_json"]) for a in audits)
            )
        finally:
            hub2.close()
            reg2.close()

    def test_r3_p1_3_exclusive_state_lock_blocks_second_hub_and_preserves_live_staging(
        self,
    ) -> None:
        reg1, _t1, hub1 = self._open_pair()
        try:
            self._reg_sb(hub1, _OP, "sb-lock", "inc_l1")
            edge = hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-lock")
            # Stage an active in-flight reservation in .staging/
            resv = hub1.spool.reserve(edge.edge_id, [b"diff --git a/x b/x\n+live\n"])
            hub1.spool.stage_blobs(resv, [b"diff --git a/x b/x\n+live\n"])
            staged_files = list(resv.staging_dir.iterdir())
            self.assertEqual(len(staged_files), 1)
            # Second opener must fail immediately before touching ArtifactSpool or markers
            reg2 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
            transport2 = FakeWorkerTransport()
            try:
                with self.assertRaises(CoordPolicyError):
                    CoordHub(
                        reg2,
                        transport2,
                        self.state_dir,
                        sandbox_root=self.sandbox_root,
                    )
            finally:
                reg2.close()
            # Live hub1 staging files and session seal remain completely untouched
            self.assertTrue(staged_files[0].exists())
            self.assertEqual(
                hub1._session_active_marker.read_text(encoding="utf-8").strip(),
                hub1._session_id,
            )
            hub1.spool.abort_reservation(resv)
        finally:
            hub1.close()
            reg1.close()

    def test_r3_p1_4_close_fences_calls_retains_seal_on_held_worker_and_settles_revoke(
        self,
    ) -> None:
        # Part A: Held worker prevents clean seal removal & lock release; calls fail closed
        reg1, transport1, hub1 = self._open_pair()
        self._reg_sb(hub1, _OP, "sb-held", "inc_h1")
        hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-held")
        started = threading.Event()
        release = threading.Event()
        transport1.queue_script(
            "sb-held",
            TurnScript(on_stream_started=started, block_event=release),
        )
        hub1.send(_OP, target="sb-held", body_text="Hold worker")
        hub1.dispatch_once(async_stream=True)
        self.assertTrue(started.wait(timeout=1.0))

        with self.assertRaises(CoordPolicyError):
            hub1.close(timeout_s=0.05)
        self.assertTrue(hub1._session_active_marker.exists())
        with self.assertRaises(CoordPolicyError):
            hub1.send(_OP, target="sb-held", body_text="Must deny after close")
        with self.assertRaises(CoordPolicyError):
            hub1.status(_OP, target="sb-held")
        with self.assertRaises(CoordPolicyError):
            hub1.revoke(_OP, target="sb-held", reason="after_close")

        release.set()
        hub1.close(timeout_s=1.0)
        self.assertFalse(hub1._session_active_marker.exists())
        reg1.close()

        # Part B: Lease-local revoke pending at close() is settled to SQLite before close returns
        reg2, _t2, hub2 = self._open_pair()
        lease_local = BrokerLease("job_local_pending_close")
        self._reg_sb(hub2, _OP, "sb-lr", "inc_lr1", lease=lease_local)
        edge_lr = hub2.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-lr")
        lease_local.revoke()
        hub2.close(timeout_s=1.0)
        sb_after = reg2.get_sandbox("sb-lr")
        edge_after = reg2.get_edge(edge_lr.edge_id)
        reg2.close()
        self.assertIsNotNone(sb_after)
        self.assertEqual(sb_after.status, "revoked")
        self.assertIsNotNone(edge_after)
        self.assertFalse(edge_after.active)

    def test_r3_p1_5_partially_bound_lease_rejected_and_bound_lease_aborts_held_stream(
        self,
    ) -> None:
        controller, ctrl_op, full_lease, req_id = _make_controller_lease("sb-pb", "inc_pb1")
        # 1. Partially bound lease (request ID set, no controller) rejected at registration
        partial_lease = BrokerLease(
            "job_partial_bound",
            controller=None,
            controller_actor=None,
            controller_request_id=req_id,
        )
        ephemeral_lease = BrokerLease("job_no_ctrl_arg")
        reg, transport, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        with self.assertRaises(CoordPolicyError):
            self._reg_sb(hub, _OP, "sb-pb", "inc_pb1", lease=partial_lease)
        with self.assertRaises(CoordPolicyError):
            self._reg_sb(
                hub, _OP, "sb-pb2", "inc_pb2", lease=ephemeral_lease, controller_request_id=req_id
            )

        # 2. Properly bound lease tears down an actively held stream on controller revoke
        self._reg_sb(hub, _OP, "sb-pb", "inc_pb1", lease=full_lease)
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-pb")
        started = threading.Event()
        never_release = threading.Event()
        transport.queue_script(
            "sb-pb",
            TurnScript(on_stream_started=started, block_event=never_release),
        )
        hub.send(_OP, target="sb-pb", body_text="Held turn before controller revoke")
        hub.dispatch_once(async_stream=True)
        self.assertTrue(started.wait(timeout=1.0))

        controller.revoke(ctrl_op, req_id)
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            sb = reg.get_sandbox("sb-pb")
            if sb is not None and sb.status == "revoked" and ("sb-pb", "inc_pb1") in transport.revoked_incarnations:
                break
            time.sleep(0.02)
        self.assertIn(("sb-pb", "inc_pb1"), transport.revoked_incarnations)
        sb_after = reg.get_sandbox("sb-pb")
        self.assertIsNotNone(sb_after)
        self.assertEqual(sb_after.status, "revoked")
        with self.assertRaises(CoordAuthError):
            hub.send(_OP, target="sb-pb", body_text="Must deny after controller revoke")

    def test_r3_p2_2_rpc_start_captures_uds_startup_error_endpoint_for_retry_stop(self) -> None:
        reg, _t, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        sock_path = self.sock_dir / "partial_bind.sock"
        rpc = CoordUdsRpcServer(hub, sock_path, sandbox_root=self.sandbox_root)
        cleaned: list[bool] = []

        class _FakeEndpoint:
            def cleanup(self, deadline: float | None = None) -> None:
                _ = deadline
                cleaned.append(True)

        fake_ep = _FakeEndpoint()
        with (
            mock.patch("oc_coord_rpc.bind_trusted_uds", side_effect=UdsStartupError(fake_ep)),  # type: ignore[arg-type]
            self.assertRaises(UdsStartupError),
        ):
            rpc.start()
        self.assertIs(rpc._bound, fake_ep)
        with self.assertRaises(BrokerError):
            rpc.start()
        rpc.stop()
        self.assertEqual(cleaned, [True])
        self.assertIsNone(rpc._bound)

    def test_r4_p1_1_sync_dispatch_held_stream_retains_state_lock_until_close_settles(
        self,
    ) -> None:
        reg1, transport1, hub1 = self._open_pair()
        self._reg_sb(hub1, _OP, "sb-sync", "inc_s1")
        hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-sync")
        started = threading.Event()
        release = threading.Event()
        transport1.queue_script(
            "sb-sync",
            TurnScript(on_stream_started=started, block_event=release),
        )
        hub1.send(_OP, target="sb-sync", body_text="Sync held stream")
        sync_thread = threading.Thread(
            target=lambda: hub1.dispatch_once(async_stream=False), daemon=True
        )
        sync_thread.start()
        self.assertTrue(started.wait(timeout=1.0))

        # close() MUST retain session seal and flock while synchronous dispatch is held
        with self.assertRaises(CoordPolicyError):
            hub1.close(timeout_s=0.05)
        self.assertTrue(hub1._session_active_marker.exists())
        reg2 = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        transport2 = FakeWorkerTransport()
        try:
            with self.assertRaises(CoordPolicyError):
                CoordHub(reg2, transport2, self.state_dir, sandbox_root=self.sandbox_root)
        finally:
            reg2.close()

        release.set()
        sync_thread.join(timeout=1.0)
        hub1.close(timeout_s=1.0)
        self.assertFalse(hub1._session_active_marker.exists())
        reg1.close()

    def test_r4_p1_2_confirm_recovery_keeps_closed_on_audit_failure_and_concurrent_close(
        self,
    ) -> None:
        # 1. Failing recovery audit must keep degraded=True and .coord_degraded on disk
        reg1, _t1, hub1 = self._open_pair()
        hub1._mark_degraded("need_recovery_audit_test")
        orig_audit = reg1.append_audit

        def _fail_audit(*_args: Any, **_kwargs: Any) -> int:
            raise OSError("audit_disk_full")

        reg1.append_audit = _fail_audit  # type: ignore[method-assign]
        try:
            with self.assertRaises(OSError):
                hub1.confirm_recovery(_OP, reason="audit_will_fail")
        finally:
            reg1.append_audit = orig_audit  # type: ignore[method-assign]
        self.assertTrue(hub1.is_degraded)
        self.assertTrue(hub1._degraded_marker.exists())

        # 2. Concurrent close() while confirm_recovery() is paused prevents post-close reopen
        entered = threading.Event()
        release = threading.Event()
        orig_rec = hub1._reconcile_artifacts_on_startup

        def _paused_rec(*, raise_on_error: bool = False) -> None:
            entered.set()
            release.wait(timeout=2.0)
            orig_rec(raise_on_error=raise_on_error)

        hub1._reconcile_artifacts_on_startup = _paused_rec  # type: ignore[method-assign]
        rec_excs: list[Exception] = []

        def _do_recover() -> None:
            try:
                hub1.confirm_recovery(_OP, reason="race_with_close")
            except Exception as exc:
                rec_excs.append(exc)

        rt = threading.Thread(target=_do_recover, daemon=True)
        rt.start()
        self.assertTrue(entered.wait(timeout=1.0))
        with self.assertRaises(CoordPolicyError):
            hub1.close(timeout_s=0.05)
        release.set()
        rt.join(timeout=1.0)
        self.assertEqual(len(rec_excs), 1)
        self.assertIsInstance(rec_excs[0], CoordPolicyError)
        self.assertTrue(hub1.is_degraded)
        self.assertTrue(hub1._degraded_marker.exists())
        hub1.close(timeout_s=1.0)
        reg1.close()

    def test_r4_p1_3_close_cutoff_persists_late_lease_revoke_without_orphan_watchdog(
        self,
    ) -> None:
        reg, _t, hub = self._open_pair()
        lease = BrokerLease("job_late_close_revoke")
        self._reg_sb(hub, _OP, "sb-late", "inc_late1", lease=lease)
        edge = hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-late")

        late_callbacks: list[bool] = []
        orig_cb = hub._on_lease_revoked

        def _spy_cb(*args: Any, **kwargs: Any) -> None:
            late_callbacks.append(True)
            orig_cb(*args, **kwargs)

        hub._on_lease_revoked = _spy_cb  # type: ignore[method-assign]
        orig_join = hub._join_watchdog_threads

        def _revoke_during_close(*, timeout_s: float = 2.0) -> bool:
            ok = orig_join(timeout_s=timeout_s)
            # Simulate lease-local revoke firing right at close cutoff
            lease.revoke()
            return ok

        hub._join_watchdog_threads = _revoke_during_close  # type: ignore[method-assign]
        hub.close(timeout_s=1.0)
        sb_after = reg.get_sandbox("sb-late")
        edge_after = reg.get_edge(edge.edge_id)
        reg.close()
        self.assertEqual(late_callbacks, [])
        self.assertIsNotNone(sb_after)
        self.assertEqual(sb_after.status, "revoked")
        self.assertIsNotNone(edge_after)
        self.assertFalse(edge_after.active)
        self.assertFalse(hub._watchdog_threads)

    def test_r4_p2_1_mid_dispatch_close_or_degrade_leaves_valid_pending_row_uncancelled(
        self,
    ) -> None:
        reg, _t, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-pend", "inc_p1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-pend")
        res = hub.send(_OP, target="sb-pend", body_text="Keep pending on shutdown")
        msg_id = res["msg_id"]
        rows = reg.list_outbox(statuses=("pending",))
        self.assertEqual(len(rows), 1)

        # Simulate degrade/close happening AFTER list_outbox() and BEFORE _dispatch_single_row()
        hub._mark_degraded("transient_shutdown")
        self.assertFalse(hub._dispatch_single_row(rows[0], async_stream=False))
        pending_after = reg.list_outbox(statuses=("pending",))
        cancelled_after = reg.list_outbox(statuses=("cancelled",))
        self.assertTrue(any(r["msg_id"] == msg_id for r in pending_after))
        self.assertEqual(cancelled_after, [])

    def test_r5_c1_lease_retirement_durable_on_close_and_retry_after_settlement_error(
        self,
    ) -> None:
        # 1. Controller stays eligible; lease revoked locally after detachment -> fresh hub refuses old inc
        controller, ctrl_op, lease_ok, _ = _make_controller_lease("sb-ret", "inc_ret1")
        reg1, _t1, hub1 = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self._reg_sb(hub1, _OP, "sb-ret", "inc_ret1", lease=lease_ok)
        edge1 = hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-ret")
        hub1.close(timeout_s=1.0)
        lease_ok.revoke()
        reg1.close()

        reg2, _t2, hub2 = self._open_pair(controller=controller, controller_actor=ctrl_op)
        try:
            self.assertFalse(hub2.is_degraded)
            sb_after = reg2.get_sandbox("sb-ret")
            edge_after = reg2.get_edge(edge1.edge_id)
            self.assertIsNotNone(sb_after)
            self.assertEqual(sb_after.status, "revoked")
            self.assertIsNotNone(edge_after)
            self.assertFalse(edge_after.active)
            # 2. Inject settlement failure on close() -> seal & retry state preserved; retry finishes it
            c2, op2, lease2, _r2 = _make_controller_lease("sb-err", "inc_err1")
            hub2._controller = c2
            hub2._controller_actor = op2
            self._reg_sb(hub2, _OP, "sb-err", "inc_err1", lease=lease2)
            edge2 = hub2.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-err")
            orig_get_sb = reg2.get_sandbox

            def _fail_get(addr: str) -> Any:
                raise OSError("db_settlement_io_error")

            reg2.get_sandbox = _fail_get  # type: ignore[method-assign]
            try:
                with self.assertRaises(OSError):
                    hub2.close(timeout_s=1.0)
            finally:
                reg2.get_sandbox = orig_get_sb  # type: ignore[method-assign]
            self.assertTrue(hub2.is_degraded)
            self.assertTrue(hub2._session_active_marker.exists())
            self.assertTrue(hub2._degraded_marker.exists())
            self.assertFalse(hub2._shutdown_settled)
            # Retry close() finishes retirement of sb-err and releases lock (keeping degraded markers)
            hub2.close(timeout_s=1.0)
            self.assertTrue(hub2._shutdown_settled)
            self.assertEqual(reg2.get_sandbox("sb-err").status, "revoked")  # type: ignore[union-attr]
            self.assertFalse(reg2.get_edge(edge2.edge_id).active)  # type: ignore[union-attr]
            self.assertTrue(hub2._session_active_marker.exists())
            self.assertTrue(hub2._degraded_marker.exists())
        finally:
            reg2.close()

    def test_r5_c2_degraded_recovery_retires_all_incarnations_and_healthy_duplicate_noop(
        self,
    ) -> None:
        reg1, _t1, hub1 = self._open_pair()
        self._reg_sb(hub1, _OP, "orch-r", "inc_o1")
        orch_old = PrincipalCtx(
            CoordRole.ORCHESTRATOR, "orch-r", sandbox_addr="orch-r", incarnation_id="inc_o1"
        )
        self._reg_sb(hub1, orch_old, "leaf-r", "inc_l1", parent_addr="orch-r")
        leaf_old = PrincipalCtx(
            CoordRole.JOB, "leaf-r", sandbox_addr="leaf-r", incarnation_id="inc_l1"
        )
        self._simulate_crash(hub1, reg1)

        reg2, _t2, hub2 = self._open_pair()
        try:
            self.assertTrue(hub2.is_degraded)
            hub2.confirm_recovery(_OP, reason="retire_all_old")
            self.assertFalse(hub2.is_degraded)
            # Old principals lose self-read and orchestrator authority
            with self.assertRaises(RevokedError):
                hub2.status(leaf_old, target="leaf-r")
            with self.assertRaises(RevokedError):
                hub2.projection(orch_old)
            # Fresh registration restores ONLY new incarnations
            self._reg_sb(hub2, _OP, "orch-r", "inc_o2")
            orch_new = PrincipalCtx(
                CoordRole.ORCHESTRATOR, "orch-r", sandbox_addr="orch-r", incarnation_id="inc_o2"
            )
            self._reg_sb(hub2, orch_new, "leaf-r2", "inc_l2", parent_addr="orch-r")
            fresh_edge = hub2.grant_edge(orch_new, src_actor=orch_new.canonical_sender, dst_addr="leaf-r2")
            # Duplicate confirm_recovery() on healthy hub is a no-op and preserves fresh grants
            hub2.confirm_recovery(_OP, reason="duplicate_noop")
            self.assertTrue(reg2.get_edge(fresh_edge.edge_id).active)  # type: ignore[union-attr]
            self.assertIn("projects", hub2.projection(orch_new))
        finally:
            hub2.close()
            reg2.close()

    def test_r5_c3_unavailable_controller_aborts_held_stream_preserves_pending_then_revoke_cancels(
        self,
    ) -> None:
        controller, ctrl_op, lease, req_id = _make_controller_lease("sb-u", "inc_u1")
        reg, transport, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-u", "inc_u1", lease=lease)
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-u")

        started = threading.Event()
        never_done = threading.Event()
        transport.queue_script("sb-u", TurnScript(on_stream_started=started, block_event=never_done))
        res1 = hub.send(_OP, target="sb-u", body_text="Held turn 1")
        msg1 = res1["msg_id"]
        hub.dispatch_once(async_stream=True)
        self.assertTrue(started.wait(timeout=1.0))

        # Queue Turn 2 while Turn 1 is actively held
        res2 = hub.send(_OP, target="sb-u", body_text="Queued turn 2")
        msg2 = res2["msg_id"]

        # Make controller lookup transiently unavailable -> held stream aborts, queued stays pending
        orig_status = controller.status

        def _outage(_actor: Any, _req: str) -> Any:
            raise OSError("controller_temporarily_unreachable")

        controller.status = _outage  # type: ignore[method-assign]
        try:
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                aborted_rows = reg.list_outbox(statuses=("aborted",))
                if any(r["msg_id"] == msg1 for r in aborted_rows):
                    break
                time.sleep(0.02)
            aborted_ids = {r["msg_id"] for r in reg.list_outbox(statuses=("aborted",))}
            self.assertIn(msg1, aborted_ids)
            # Pending Turn 2 must NOT be cancelled during transient unavailability
            self.assertEqual(hub.dispatch_once(), 0)
            pending_ids = {r["msg_id"] for r in reg.list_outbox(statuses=("pending",))}
            self.assertIn(msg2, pending_ids)
        finally:
            controller.status = orig_status  # type: ignore[method-assign]

        # Authority restored: ONLY Turn 2 dispatches (Turn 1 stays aborted, never retried!)
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)
        dispatched_ids = [t.msg_id for t in transport.dispatched_turns("sb-u")]
        self.assertEqual(dispatched_ids.count(msg1), 1)
        self.assertEqual(dispatched_ids.count(msg2), 1)
        self.assertIn(msg1, {r["msg_id"] for r in reg.list_outbox(statuses=("aborted",))})

        # Queue Turn 3, then issue confirmed controller revoke -> cancels Turn 3 & revokes sandbox
        res3 = hub.send(_OP, target="sb-u", body_text="Queued turn 3")
        msg3 = res3["msg_id"]
        controller.revoke(ctrl_op, req_id)
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            if any(r["msg_id"] == msg3 for r in reg.list_outbox(statuses=("cancelled",))):
                break
            time.sleep(0.02)
        self.assertIn(msg3, {r["msg_id"] for r in reg.list_outbox(statuses=("cancelled",))})

    def test_r5_c4_restored_controller_only_target_installs_monitor_and_aborts_held_stream(
        self,
    ) -> None:
        controller, ctrl_op, _lease, req_id = _make_controller_lease("sb-rmon", "inc_rm1")
        reg1, _t1, hub1 = self._open_pair(controller=controller, controller_actor=ctrl_op)
        try:
            self._reg_sb(hub1, _OP, "sb-rmon", "inc_rm1", controller_request_id=req_id)
            hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-rmon")
            hub1.send(_OP, target="sb-rmon", body_text="Queued for restored hub")
        finally:
            hub1.close()
            reg1.close()

        reg2, transport2, hub2 = self._open_pair(controller=controller, controller_actor=ctrl_op)
        try:
            started = threading.Event()
            never_done = threading.Event()
            transport2.queue_script(
                "sb-rmon", TurnScript(on_stream_started=started, block_event=never_done)
            )
            self.assertEqual(hub2.dispatch_once(async_stream=True), 1)
            self.assertTrue(started.wait(timeout=1.0))

            # Controller revokes AFTER the recovered stream has started -> monitor aborts it!
            controller.revoke(ctrl_op, req_id)
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                if ("sb-rmon", "inc_rm1") in transport2.revoked_incarnations:
                    break
                time.sleep(0.02)
            self.assertIn(("sb-rmon", "inc_rm1"), transport2.revoked_incarnations)
            self.assertEqual(reg2.get_sandbox("sb-rmon").status, "revoked")  # type: ignore[union-attr]
        finally:
            hub2.close()
            reg2.close()

    def test_r5_c5_close_deadline_bounded_and_drains_async_producers_and_register_audit(
        self,
    ) -> None:
        # 1. close(timeout_s=0.05) while register_sandbox trailing audit is blocked stays within budget
        reg, transport, hub = self._open_pair()
        audit_entered = threading.Event()
        audit_release = threading.Event()
        orig_audit = reg.append_audit

        def _slow_audit(actor: str, action: str, target: str, outcome: str, detail: Any = None) -> int:
            if action == "register_sandbox":
                audit_entered.set()
                audit_release.wait(timeout=2.0)
            return orig_audit(actor, action, target, outcome, detail)

        reg.append_audit = _slow_audit  # type: ignore[method-assign]
        rt = threading.Thread(
            target=lambda: self._reg_sb(hub, _OP, "sb-aud", "inc_aud1"), daemon=True
        )
        rt.start()
        self.assertTrue(audit_entered.wait(timeout=1.0))

        t0 = time.monotonic()
        with self.assertRaises(CoordPolicyError):
            hub.close(timeout_s=0.05)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.35)
        self.assertTrue(hub._session_active_marker.exists())
        # Second hub stays excluded while trailing audit is still running
        reg_other = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        t_other = FakeWorkerTransport()
        try:
            with self.assertRaises(CoordPolicyError):
                CoordHub(reg_other, t_other, self.state_dir, sandbox_root=self.sandbox_root)
        finally:
            reg_other.close()

        audit_release.set()
        rt.join(timeout=1.0)
        hub.close(timeout_s=1.0)
        self.assertFalse(hub._session_active_marker.exists())
        reg.close()
        _ = transport


class _NoAbortStreamTransport:
    """Minimal WorkerTransport proxy implementing only abort_incarnation (no abort_stream)."""

    def __init__(self, inner: FakeWorkerTransport) -> None:
        self._inner = inner

    def dispatch_turn(self, turn: Any) -> Any:
        return self._inner.dispatch_turn(turn)

    def stream_events(self, stream_id: str) -> Any:
        return self._inner.stream_events(stream_id)

    def abort_incarnation(self, sandbox_addr: str, incarnation_id: str, *, reason: str) -> bool:
        return self._inner.abort_incarnation(sandbox_addr, incarnation_id, reason=reason)

    def status(self, sandbox_addr: str, incarnation_id: str) -> Any:
        return self._inner.status(sandbox_addr, incarnation_id)


def _approve_extra_request(controller: Controller, ctrl_op: Principal, job_name: str) -> str:
    job_actor = Principal(Role.JOB, f"chan-{job_name}")
    st = controller.propose(job_actor, Proposal(Intent.PROBE_GRANT, "alias-e2e", "ref-probe"))
    view = controller.view(ctrl_op, st.request_id)
    controller.decide(ctrl_op, st.request_id, view.payload.revision, view.digest, Decision.APPROVE)
    return st.request_id


class TestReciprocalRound6Fixes(CoordTestBase):
    """Red/green regressions for all six reciprocal review findings on fd761776."""

    def _open_pair(
        self,
        *,
        controller: Controller | None = None,
        controller_actor: Principal | None = None,
        transport: Any | None = None,
    ) -> tuple[CoordRegistry, Any, CoordHub]:
        reg = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        actual_transport = transport if transport is not None else FakeWorkerTransport()
        hub = CoordHub(
            reg,
            actual_transport,
            self.state_dir,
            controller=controller,
            controller_actor=controller_actor,
            sandbox_root=self.sandbox_root,
            watchdog_interval_s=0.02,
        )
        return reg, actual_transport, hub

    @staticmethod
    def _reg_sb(
        hub: CoordHub,
        caller: PrincipalCtx,
        name: str,
        inc: str,
        *,
        parent_addr: str | None = None,
        lease: BrokerLease | None = None,
        controller_request_id: str | None = None,
    ) -> Any:
        return hub.register_sandbox(
            caller,
            name=name,
            incarnation_id=inc,
            project_id="p_r6",
            project_name="PR6",
            branch="main",
            task_brief=f"Task {name}",
            parent_addr=parent_addr,
            lease=lease,
            controller_request_id=controller_request_id,
        )

    @staticmethod
    def _wait_until(predicate: Any, timeout_s: float = 1.5) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return bool(predicate())

    def test_r6_p1_1_in_process_recovery_fences_inflight_handoff_and_aborts_held_stream(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-rec1", "inc_rec1")
        self._reg_sb(hub, _OP, "sb-rec2", "inc_rec2")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-rec1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-rec2")

        # 1. Start a held stream on sb-rec2 that would emit ordinary events after unblock
        held_started = threading.Event()
        held_release = threading.Event()
        transport.queue_script(
            "sb-rec2",
            TurnScript(
                on_stream_started=held_started,
                block_event=held_release,
                text_chunks=("STALE_ORDINARY_DELTA_MUST_DROP",),
            ),
        )
        msg_held = hub.send(_OP, target="sb-rec2", body_text="Held before recovery")["msg_id"]
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(held_started.wait(timeout=1.0))

        # 2. Pause an in-flight handoff on sb-rec1 inside dispatch_turn()
        in_handoff = threading.Event()
        release_handoff = threading.Event()
        orig_dispatch = transport.dispatch_turn

        def _blocked_dispatch(turn: Any) -> Any:
            if turn.sandbox_addr == "sb-rec1":
                in_handoff.set()
                release_handoff.wait(timeout=2.0)
            return orig_dispatch(turn)

        transport.dispatch_turn = _blocked_dispatch  # type: ignore[method-assign]
        transport.queue_script("sb-rec1", TurnScript(text_chunks=("LATE_HANDOFF_MUST_ABORT",)))
        msg_inf = hub.send(_OP, target="sb-rec1", body_text="Inflight handoff")["msg_id"]

        disp_thread = threading.Thread(
            target=lambda: hub.dispatch_once(async_stream=True), daemon=True
        )
        disp_thread.start()
        self.assertTrue(in_handoff.wait(timeout=1.0))

        # 3. Degrade hub and start in-process confirm_recovery(): MUST wait for in-flight handoff!
        hub._mark_degraded("in_process_recovery_test")
        rec_done = threading.Event()
        rec_err: list[Exception] = []

        def _do_recover() -> None:
            try:
                hub.confirm_recovery(_OP, reason="in_process_verified")
            except Exception as exc:  # pragma: no cover
                rec_err.append(exc)
            finally:
                rec_done.set()

        rec_thread = threading.Thread(target=_do_recover, daemon=True)
        rec_thread.start()
        # Must NOT reopen while dispatch_turn() is still executing under the fence!
        self.assertFalse(rec_done.wait(timeout=0.08))
        self.assertTrue(hub.is_degraded)

        release_handoff.set()
        self.assertTrue(rec_done.wait(timeout=1.5))
        self.assertEqual(rec_err, [])
        self.assertFalse(hub.is_degraded)
        held_release.set()
        disp_thread.join(timeout=1.5)

        # Both retired incarnations must be aborted and ZERO ordinary deltas recorded
        self.assertIn(("sb-rec1", "inc_rec1"), transport.revoked_incarnations)
        self.assertIn(("sb-rec2", "inc_rec2"), transport.revoked_incarnations)
        self.assertTrue(
            self._wait_until(
                lambda: {msg_held, msg_inf}.issubset(
                    {r["msg_id"] for r in reg.list_outbox(statuses=("aborted",))}
                )
            )
        )
        events = reg.list_events_since(("sb-rec1", "sb-rec2"), 0)
        texts = [str(ev.get("text", "")) for ev in events]
        self.assertFalse(any("STALE_ORDINARY_DELTA_MUST_DROP" in t for t in texts))
        self.assertFalse(any("LATE_HANDOFF_MUST_ABORT" in t for t in texts))

    def test_r6_p1_2_stale_caller_blocked_under_register_lock_on_register_and_grant(
        self,
    ) -> None:
        reg, _transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        orig_orch = self._reg_sb(hub, _OP, "orch-r6", "inc_o1")
        orig_src = self._reg_sb(hub, _OP, "sb-gsrc", "inc_gs1")
        self._reg_sb(hub, _OP, "sb-gdst", "inc_gd1")
        stale_orch = PrincipalCtx(
            CoordRole.ORCHESTRATOR, "o1", sandbox_addr="orch-r6", incarnation_id="inc_o1"
        )

        # Part A: waiting register_sandbox must fail after orch-r6 rotates under _register_lock
        reg_err: list[Exception] = []

        def _wait_register() -> None:
            try:
                self._reg_sb(hub, stale_orch, "child-stale", "inc_c1", parent_addr="orch-r6")
            except Exception as exc:
                reg_err.append(exc)

        hub._register_lock.acquire()
        try:
            t_reg = threading.Thread(target=_wait_register, daemon=True)
            t_reg.start()
            time.sleep(0.05)
            reg.register_sandbox(replace(orig_orch, incarnation_id="inc_o2"))
            hub._budgets[("orch-r6", "inc_o2")] = SubtreeBudget()
        finally:
            hub._register_lock.release()
        t_reg.join(timeout=1.5)
        self.assertEqual(len(reg_err), 1)
        self.assertIsInstance(reg_err[0], (IncarnationMismatchError, RevokedError))
        self.assertIsNone(reg.get_sandbox("child-stale"))

        # Part B: waiting grant_edge must fail after source incarnation rotates under _register_lock
        grant_err: list[Exception] = []

        def _wait_grant() -> None:
            try:
                hub.grant_edge(
                    _OP,
                    src_actor="sb-gsrc",
                    src_incarnation="inc_gs1",
                    dst_addr="sb-gdst",
                )
            except Exception as exc:
                grant_err.append(exc)

        hub._register_lock.acquire()
        try:
            t_grant = threading.Thread(target=_wait_grant, daemon=True)
            t_grant.start()
            time.sleep(0.05)
            reg.register_sandbox(replace(orig_src, incarnation_id="inc_gs2"))
        finally:
            hub._register_lock.release()
        t_grant.join(timeout=1.5)
        self.assertEqual(len(grant_err), 1)
        self.assertIsInstance(grant_err[0], (IncarnationMismatchError, RevokedError))
        self.assertEqual(reg.list_edges(src_actor="sb-gsrc", active_only=True), [])

    def test_r6_p1_3_distinct_edge_revoke_preserves_destination_and_source_outage_aborts_outbound(
        self,
    ) -> None:
        controller, ctrl_op, _lease, req_src = _make_controller_lease("sb-src", "inc_s1")
        req_dst = _approve_extra_request(controller, ctrl_op, "sb-src")
        req_edge1 = _approve_extra_request(controller, ctrl_op, "sb-src")

        reg, transport, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-src", "inc_s1", controller_request_id=req_src)
        self._reg_sb(hub, _OP, "sb-dst", "inc_d1", controller_request_id=req_dst)
        edge1 = hub.grant_edge(
            _OP,
            src_actor="sb-src",
            src_incarnation="inc_s1",
            dst_addr="sb-dst",
            lease_request_id=req_edge1,
        )
        edge2 = hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-dst")

        src_ctx = PrincipalCtx(CoordRole.JOB, "js1", sandbox_addr="sb-src", incarnation_id="inc_s1")
        s1_started = threading.Event()
        s1_release = threading.Event()
        s2_started = threading.Event()
        s2_release = threading.Event()
        self.addCleanup(s1_release.set)
        self.addCleanup(s2_release.set)
        transport.queue_script(
            "sb-dst", TurnScript(on_stream_started=s1_started, block_event=s1_release)
        )
        transport.queue_script(
            "sb-dst", TurnScript(on_stream_started=s2_started, block_event=s2_release)
        )
        msg_e1 = hub.send(src_ctx, target="sb-dst", body_text="Edge1 outbound")["msg_id"]
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(s1_started.wait(timeout=1.0))

        msg_e2 = hub.send(_OP, target="sb-dst", body_text="Edge2 independent")["msg_id"]
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(s2_started.wait(timeout=1.0))

        # 1. Source request outage aborts ONLY edge1 outbound stream; edge2 stays handed_off
        orig_status = controller.status

        def _src_outage(actor: Any, req: str) -> Any:
            if req == req_src:
                raise OSError("source_controller_outage")
            return orig_status(actor, req)

        controller.status = _src_outage  # type: ignore[method-assign]
        try:
            self.assertTrue(
                self._wait_until(
                    lambda: any(r["msg_id"] == msg_e1 for r in reg.list_outbox(statuses=("aborted",)))
                )
            )
            self.assertIn(msg_e2, {r["msg_id"] for r in reg.list_outbox(statuses=("handed_off",))})
            self.assertEqual(reg.get_sandbox("sb-dst").status, "running")  # type: ignore[union-attr]
        finally:
            controller.status = orig_status  # type: ignore[method-assign]

        # 2. Revoking distinct edge1 lease revokes ONLY edge1; sb-dst & edge2 survive intact!
        s1b_started = threading.Event()
        s1b_release = threading.Event()
        self.addCleanup(s1b_release.set)
        transport.queue_script(
            "sb-dst", TurnScript(on_stream_started=s1b_started, block_event=s1b_release)
        )
        msg_e1b = hub.send(src_ctx, target="sb-dst", body_text="Edge1 active before revoke")["msg_id"]
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(s1b_started.wait(timeout=1.0))
        msg_e1b_q = hub.send(src_ctx, target="sb-dst", body_text="Edge1 queued")["msg_id"]
        msg_e2_q = hub.send(_OP, target="sb-dst", body_text="Edge2 queued")["msg_id"]

        controller.revoke(ctrl_op, req_edge1)
        self.assertTrue(
            self._wait_until(
                lambda: (
                    not reg.get_edge(edge1.edge_id).active  # type: ignore[union-attr]
                    and any(r["msg_id"] == msg_e1b for r in reg.list_outbox(statuses=("aborted",)))
                    and any(r["msg_id"] == msg_e1b_q for r in reg.list_outbox(statuses=("cancelled",)))
                )
            )
        )
        self.assertEqual(reg.get_sandbox("sb-dst").status, "running")  # type: ignore[union-attr]
        self.assertNotIn(("sb-dst", "inc_d1"), transport.revoked_incarnations)
        self.assertTrue(reg.get_edge(edge2.edge_id).active)  # type: ignore[union-attr]
        s2_release.set()
        self.assertTrue(
            self._wait_until(
                lambda: any(r["msg_id"] == msg_e2 for r in reg.list_outbox(statuses=("completed",)))
            )
        )
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)
        self.assertIn(msg_e2_q, {r["msg_id"] for r in reg.list_outbox(statuses=("completed",))})

    def test_r6_p1_4_outage_across_handoff_retryable_abort_stream_and_require_stream_abort_cap(
        self,
    ) -> None:
        # Part A: Transport lacking abort_stream is rejected BEFORE admitting monitored turn
        ctrl_a, op_a, _lease_a, req_a = _make_controller_lease("sb-cap", "inc_cap1")
        inner_t = FakeWorkerTransport()
        proxy_t = _NoAbortStreamTransport(inner_t)
        reg_a, _ta, hub_a = self._open_pair(
            controller=ctrl_a, controller_actor=op_a, transport=proxy_t
        )
        try:
            self._reg_sb(hub_a, _OP, "sb-cap", "inc_cap1", controller_request_id=req_a)
            hub_a.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-cap")
            with self.assertRaises(CoordPolicyError):
                hub_a.send(_OP, target="sb-cap", body_text="Need abort_stream")
            self.assertEqual(inner_t.dispatched_turns("sb-cap"), [])
            self.assertEqual(reg_a.list_outbox(statuses=("pending",)), [])
            self.assertNotIn(("sb-cap", "inc_cap1"), inner_t.revoked_incarnations)
        finally:
            hub_a.close()
            reg_a.close()

        # Part B: Outage during handoff + failed first abort_stream retried until stream exits
        ctrl_b, op_b, _lease_b, req_b = _make_controller_lease("sb-ho", "inc_ho1")
        reg_b, transport_b, hub_b = self._open_pair(controller=ctrl_b, controller_actor=op_b)
        self.addCleanup(reg_b.close)
        self.addCleanup(hub_b.close)
        self._reg_sb(hub_b, _OP, "sb-ho", "inc_ho1", controller_request_id=req_b)
        hub_b.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-ho")

        in_handoff = threading.Event()
        release_handoff = threading.Event()
        orig_dispatch = transport_b.dispatch_turn
        orig_abort_stream = transport_b.abort_stream
        abort_calls: list[str] = []

        def _paused_dispatch(turn: Any) -> Any:
            in_handoff.set()
            release_handoff.wait(timeout=2.0)
            return orig_dispatch(turn)

        def _flaky_abort_stream(stream_id: str, *, reason: str) -> bool:
            abort_calls.append(stream_id)
            if len(abort_calls) == 1:
                raise RuntimeError("transient_abort_stream_failure")
            return orig_abort_stream(stream_id, reason=reason)

        transport_b.dispatch_turn = _paused_dispatch  # type: ignore[method-assign]
        transport_b.abort_stream = _flaky_abort_stream  # type: ignore[method-assign]
        transport_b.queue_script("sb-ho", TurnScript(block_event=threading.Event()))
        msg_ho = hub_b.send(_OP, target="sb-ho", body_text="Outage across handoff")["msg_id"]

        t_disp = threading.Thread(
            target=lambda: hub_b.dispatch_once(async_stream=True), daemon=True
        )
        t_disp.start()
        self.assertTrue(in_handoff.wait(timeout=1.0))

        # Trigger controller outage WHILE dispatch_turn() is paused (before stream registration)
        orig_status = ctrl_b.status

        def _outage_b(_actor: Any, _req: str) -> Any:
            raise OSError("outage_during_handoff")

        ctrl_b.status = _outage_b  # type: ignore[method-assign]
        try:
            time.sleep(0.08)
            release_handoff.set()
            t_disp.join(timeout=1.5)
            self.assertTrue(
                self._wait_until(
                    lambda: any(r["msg_id"] == msg_ho for r in reg_b.list_outbox(statuses=("aborted",)))
                )
            )
            self.assertGreaterEqual(len(abort_calls), 2)
            self.assertNotIn(("sb-ho", "inc_ho1"), transport_b.revoked_incarnations)
        finally:
            ctrl_b.status = orig_status  # type: ignore[method-assign]

    def test_r6_p1_5_concurrent_monitor_install_reserves_single_owner_and_rolls_back_failed_start(
        self,
    ) -> None:
        controller, ctrl_op, _lease, req_id = _make_controller_lease("sb-mon", "inc_m1")
        req_fail = _approve_extra_request(controller, ctrl_op, "sb-mon")
        reg1, _t1, hub1 = self._open_pair(controller=controller, controller_actor=ctrl_op)
        try:
            self._reg_sb(hub1, _OP, "sb-mon", "inc_m1", controller_request_id=req_id)
            self._reg_sb(hub1, _OP, "sb-mon-s1", "inc_ms1")
            self._reg_sb(hub1, _OP, "sb-mon-s2", "inc_ms2")
            hub1.grant_edge(_OP, src_actor="sb-mon-s1", dst_addr="sb-mon")
            hub1.grant_edge(_OP, src_actor="sb-mon-s2", dst_addr="sb-mon")
            s1_ctx = PrincipalCtx(
                CoordRole.JOB, "jm1", sandbox_addr="sb-mon-s1", incarnation_id="inc_ms1"
            )
            s2_ctx = PrincipalCtx(
                CoordRole.JOB, "jm2", sandbox_addr="sb-mon-s2", incarnation_id="inc_ms2"
            )
            hub1.send(s1_ctx, target="sb-mon", body_text="Concurrent monitor trigger 1")
            hub1.send(s2_ctx, target="sb-mon", body_text="Concurrent monitor trigger 2")
        finally:
            hub1.close()
            reg1.close()

        reg, _transport, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        rows = reg.list_outbox(statuses=("pending",))
        self.assertEqual(len(rows), 2)

        # Part A: Two concurrent dispatches for the same key start ONLY ONE monitor thread
        start_entered = threading.Event()
        release_start = threading.Event()
        orig_start = threading.Thread.start
        monitor_starts = 0
        start_lock = threading.Lock()

        def _intercept_start(thr: threading.Thread) -> None:
            nonlocal monitor_starts
            target = getattr(thr, "_target", None)
            if target == hub._run_controller_monitor:
                with start_lock:
                    monitor_starts += 1
                    first = monitor_starts == 1
                if first:
                    start_entered.set()
                    release_start.wait(timeout=2.0)
            orig_start(thr)

        with mock.patch.object(threading.Thread, "start", _intercept_start):
            t1 = threading.Thread(
                target=lambda: hub._dispatch_single_row(rows[0], async_stream=False), daemon=True
            )
            t2 = threading.Thread(
                target=lambda: hub._dispatch_single_row(rows[1], async_stream=False), daemon=True
            )
            t1.start()
            self.assertTrue(start_entered.wait(timeout=1.0))
            t2.start()
            time.sleep(0.05)
            release_start.set()
            t1.join(timeout=1.5)
            t2.join(timeout=1.5)

        self.assertEqual(monitor_starts, 1)

        # Part B: Failed monitor start() rolls back reservation cleanly so retry succeeds
        failed_once = False

        def _fail_once_start(thr: threading.Thread) -> None:
            nonlocal failed_once
            target = getattr(thr, "_target", None)
            if target == hub._run_controller_monitor and not failed_once:
                failed_once = True
                raise RuntimeError("simulated_thread_start_failure")
            orig_start(thr)

        with mock.patch.object(threading.Thread, "start", _fail_once_start):
            with self.assertRaises(RuntimeError):
                self._reg_sb(hub, _OP, "sb-mon-f", "inc_mf1", controller_request_id=req_fail)
            self._reg_sb(hub, _OP, "sb-mon-f", "inc_mf2", controller_request_id=req_fail)
            self.assertIn(req_fail, hub._request_monitors)

    def test_r6_p2_6_close_settlement_respects_deadline_and_retry_completes_missing_audit(
        self,
    ) -> None:
        reg, _transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        lease = BrokerLease("job_settle_r6")
        self._reg_sb(hub, _OP, "sb-settle", "inc_st1", lease=lease)

        in_settlement = threading.Event()
        release_settlement = threading.Event()
        orig_update = reg.update_sandbox_status
        orig_audit = reg.append_audit
        fail_revoke_audit = {"enabled": True}

        def _slow_update(
            sandbox_addr: str, status: str, *, incarnation_id: str | None = None
        ) -> None:
            if sandbox_addr == "sb-settle" and not release_settlement.is_set():
                in_settlement.set()
                release_settlement.wait(timeout=2.0)
            orig_update(sandbox_addr, status, incarnation_id=incarnation_id)

        def _flaky_audit(
            actor: str, action: str, target: str, outcome: str, detail: Any = None
        ) -> int:
            if action == "revoke" and target == "sb-settle" and fail_revoke_audit["enabled"]:
                fail_revoke_audit["enabled"] = False
                raise OSError("simulated_audit_write_failure")
            return orig_audit(actor, action, target, outcome, detail)

        reg.update_sandbox_status = _slow_update  # type: ignore[method-assign]
        reg.append_audit = _flaky_audit  # type: ignore[method-assign]

        # 1. close(timeout_s=0.05) blocked INSIDE settlement must return within deadline
        t0 = time.monotonic()
        with self.assertRaises(CoordPolicyError):
            hub.close(timeout_s=0.05)
        elapsed = time.monotonic() - t0
        self.assertTrue(in_settlement.is_set())
        self.assertLess(elapsed, 0.35)
        self.assertTrue(hub._session_active_marker.exists())
        self.assertGreaterEqual(hub._state_lock_fd, 0)

        # Second hub stays locked out while settlement worker is still active
        reg_other = CoordRegistry(self.state_dir, sandbox_root=self.sandbox_root)
        t_other = FakeWorkerTransport()
        try:
            with self.assertRaises(CoordPolicyError):
                CoordHub(reg_other, t_other, self.state_dir, sandbox_root=self.sandbox_root)
        finally:
            reg_other.close()

        # 2. Unblock settlement -> status writes 'revoked', then audit fails -> close fails & retains state
        release_settlement.set()
        with self.assertRaises(CoordPolicyError):
            hub.close(timeout_s=1.0)
        self.assertEqual(reg.get_sandbox("sb-settle").status, "revoked")  # type: ignore[union-attr]
        self.assertTrue(hub._session_active_marker.exists())
        self.assertGreaterEqual(hub._state_lock_fd, 0)
        def _count_revoke_audits() -> int:
            with reg._lock:
                row = reg._conn.execute(
                    "SELECT COUNT(*) AS cnt FROM audit_log WHERE action = 'revoke' AND target = ?",
                    ("sb-settle",),
                ).fetchone()
                return int(row["cnt"]) if row is not None else 0

        self.assertEqual(_count_revoke_audits(), 0)

        # 3. Retry close() completes the missing revoke audit even though status is already 'revoked'!
        hub.close(timeout_s=1.0)
        self.assertEqual(_count_revoke_audits(), 1)
        self.assertTrue(reg.verify_audit_chain()[0])
        self.assertTrue(hub._degraded_marker.exists())
        self.assertTrue(hub._session_active_marker.exists())


class TestReciprocalRound7Fixes(CoordTestBase):
    """Red/green regressions for all five failure-path findings on 0a6b6b40."""

    _open_pair = TestReciprocalRound6Fixes._open_pair
    _reg_sb = staticmethod(TestReciprocalRound6Fixes._reg_sb)
    _wait_until = staticmethod(TestReciprocalRound6Fixes._wait_until)

    def test_r7_p1_1_recovery_cancels_lease_and_held_stream_before_failing_db_write(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        lease = BrokerLease("job_rec_fail_r7")
        self._reg_sb(hub, _OP, "sb-rl", "inc_rl1", lease=lease)
        edge = hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-rl")

        held_started = threading.Event()
        held_release = threading.Event()
        self.addCleanup(held_release.set)
        transport.queue_script(
            "sb-rl", TurnScript(on_stream_started=held_started, block_event=held_release)
        )
        hub.send(_OP, target="sb-rl", body_text="Held stream during failing recovery")
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(held_started.wait(timeout=1.0))

        hub._mark_degraded("simulated_r7_recovery_db_failure")
        orig_revoke_grant = reg.revoke_grant_and_cancel_outbox
        fail_once = {"enabled": True}

        def _failing_revoke_grant(**kwargs: Any) -> list[str]:
            if fail_once["enabled"]:
                fail_once["enabled"] = False
                raise OSError("simulated_db_write_failure_during_recovery")
            return orig_revoke_grant(**kwargs)

        reg.revoke_grant_and_cancel_outbox = _failing_revoke_grant  # type: ignore[method-assign]
        with self.assertRaises(OSError):
            hub.confirm_recovery(_OP, reason="first_attempt_db_fails")

        # BEFORE retry: lease MUST already be locally revoked and held transport aborted!
        self.assertTrue(hub._is_lease_locally_revoked(lease))
        self.assertIn(("sb-rl", "inc_rl1"), transport.revoked_incarnations)
        self.assertTrue(hub.is_degraded)

        # Retry completes durable retirement and reopens cleanly
        hub.confirm_recovery(_OP, reason="retry_after_db_recovers")
        self.assertFalse(hub.is_degraded)
        self.assertEqual(reg.get_sandbox("sb-rl").status, "revoked")  # type: ignore[union-attr]
        self.assertFalse(reg.get_edge(edge.edge_id).active)  # type: ignore[union-attr]

    def test_r7_p1_2_known_controller_outage_before_handoff_blocks_dispatch_and_keeps_pending(
        self,
    ) -> None:
        controller, ctrl_op, _lease, req_ko = _make_controller_lease("sb-ko", "inc_ko1")
        reg, transport, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-ko", "inc_ko1", controller_request_id=req_ko)
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-ko")
        msg_ko = hub.send(_OP, target="sb-ko", body_text="Do not handoff during known outage")[
            "msg_id"
        ]

        orig_status = controller.status
        orig_mark_started = reg.mark_outbox_dispatch_started
        triggered = {"done": False}

        def _outage(_actor: Any, _req: str) -> Any:
            raise OSError("known_outage_before_handoff")

        def _mark_started_with_outage(msg_id: str, **kwargs: Any) -> bool:
            ok = orig_mark_started(msg_id, **kwargs)
            if ok and not triggered["done"]:
                triggered["done"] = True
                controller.status = _outage  # type: ignore[method-assign]
                self._wait_until(lambda: req_ko in hub._unavailable_requests)
            return ok

        reg.mark_outbox_dispatch_started = _mark_started_with_outage  # type: ignore[method-assign]
        try:
            self.assertEqual(hub.dispatch_once(async_stream=False), 0)
            self.assertEqual(transport.dispatched_turns("sb-ko"), [])
            self.assertIn(msg_ko, {r["msg_id"] for r in reg.list_outbox(statuses=("pending",))})
        finally:
            controller.status = orig_status  # type: ignore[method-assign]
            reg.mark_outbox_dispatch_started = orig_mark_started  # type: ignore[method-assign]

        # Once controller recovers, the untouched pending row dispatches cleanly once
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)
        self.assertEqual([t.msg_id for t in transport.dispatched_turns("sb-ko")], [msg_ko])
        self.assertIn(msg_ko, {r["msg_id"] for r in reg.list_outbox(statuses=("completed",))})

    def test_r7_p1_3_failed_handoff_receipt_write_retains_stream_handle_cancels_and_marks_uncertain(
        self,
    ) -> None:
        controller, ctrl_op, _lease, req_hf = _make_controller_lease("sb-hf", "inc_hf1")
        reg, transport, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-hf", "inc_hf1", controller_request_id=req_hf)
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-hf")
        transport.queue_script("sb-hf", TurnScript(block_event=threading.Event()))
        msg_hf = hub.send(_OP, target="sb-hf", body_text="Handoff receipt write fails")["msg_id"]

        orig_abort_stream = transport.abort_stream
        abort_calls: list[str] = []

        def _flaky_abort(stream_id: str, *, reason: str) -> bool:
            abort_calls.append(stream_id)
            if len(abort_calls) == 1:
                raise RuntimeError("transient_abort_failure_after_handoff_persist_err")
            return orig_abort_stream(stream_id, reason=reason)

        def _fail_handed_off(_msg_id: str, *, stream_id: str) -> None:
            _ = stream_id
            raise OSError("sqlite_write_failed_after_transport_handoff")

        transport.abort_stream = _flaky_abort  # type: ignore[method-assign]
        reg.mark_outbox_handed_off = _fail_handed_off  # type: ignore[method-assign]

        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        # Original msg_id MUST be marked uncertain (no replay!) and stream_id immediately targeted
        self.assertIn(msg_hf, {r["msg_id"] for r in reg.list_outbox(statuses=("uncertain",))})
        self.assertEqual(len(abort_calls), 1)
        returned_sid = abort_calls[0]
        # Handle retained after first abort_stream failure -> monitor retries and clears it
        self.assertTrue(
            self._wait_until(
                lambda: len(abort_calls) >= 2 and returned_sid not in hub._stream_authorities
            )
        )
        # No replay on subsequent dispatch_once
        self.assertEqual(hub.dispatch_once(async_stream=False), 0)
        self.assertEqual(len(transport.dispatched_turns("sb-hf")), 1)

    def test_r7_p2_4_failed_monitor_start_leaves_no_durable_registration_or_grant(
        self,
    ) -> None:
        controller, ctrl_op, _lease, req_reg_fail = _make_controller_lease("sb-mfail", "inc_mf1")
        req_edge_fail = _approve_extra_request(controller, ctrl_op, "sb-mfail")
        reg, _transport, hub = self._open_pair(controller=controller, controller_actor=ctrl_op)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)

        orig_start = threading.Thread.start
        fail_flag = {"enabled": True}

        def _fail_once(thr: threading.Thread) -> None:
            if getattr(thr, "_target", None) == hub._run_controller_monitor and fail_flag["enabled"]:
                fail_flag["enabled"] = False
                raise RuntimeError("simulated_monitor_start_err")
            orig_start(thr)

        # Part A: Failed monitor startup on register_sandbox must NOT persist the sandbox
        with mock.patch.object(threading.Thread, "start", _fail_once):
            with self.assertRaises(RuntimeError):
                self._reg_sb(hub, _OP, "sb-mfail", "inc_mf1", controller_request_id=req_reg_fail)
            self.assertIsNone(reg.get_sandbox("sb-mfail"))
            self._reg_sb(hub, _OP, "sb-mfail", "inc_mf1", controller_request_id=req_reg_fail)
            self.assertIsNotNone(reg.get_sandbox("sb-mfail"))

        # Part B: Failed monitor startup on grant_edge must NOT persist the edge
        fail_flag["enabled"] = True
        with mock.patch.object(threading.Thread, "start", _fail_once):
            with self.assertRaises(RuntimeError):
                hub.grant_edge(
                    _OP,
                    src_actor=_OP.canonical_sender,
                    dst_addr="sb-mfail",
                    lease_request_id=req_edge_fail,
                )
            self.assertEqual(reg.list_edges(dst_addr="sb-mfail", active_only=False), [])
            edge = hub.grant_edge(
                _OP,
                src_actor=_OP.canonical_sender,
                dst_addr="sb-mfail",
                lease_request_id=req_edge_fail,
            )
            self.assertTrue(reg.get_edge(edge.edge_id).active)  # type: ignore[union-attr]

    def test_r7_p2_5_blocked_waiter_does_not_defeat_close_deadline(self) -> None:
        reg, _transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self._reg_sb(hub, _OP, "sb-wt", "inc_wt1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-wt")

        in_wait_read = threading.Event()
        release_wait_read = threading.Event()
        self.addCleanup(release_wait_read.set)
        orig_list_events = reg.list_events_since

        def _slow_list_events(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            if not release_wait_read.is_set():
                in_wait_read.set()
                release_wait_read.wait(timeout=2.0)
            return orig_list_events(*args, **kwargs)

        reg.list_events_since = _slow_list_events  # type: ignore[method-assign]
        wait_errs: list[Exception] = []

        def _run_wait() -> None:
            try:
                hub.wait(_OP, targets=("sb-wt",), since_seq=0, timeout_s=5.0)
            except Exception as exc:
                wait_errs.append(exc)

        wait_thread = threading.Thread(target=_run_wait, daemon=True)
        wait_thread.start()
        self.assertTrue(in_wait_read.wait(timeout=1.0))

        t0 = time.monotonic()
        with self.assertRaises(CoordPolicyError):
            hub.close(timeout_s=0.05)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.35)
        self.assertTrue(hub._session_active_marker.exists())
        self.assertGreaterEqual(hub._state_lock_fd, 0)

        release_wait_read.set()
        wait_thread.join(timeout=1.5)
        self.assertEqual(len(wait_errs), 1)
        self.assertIsInstance(wait_errs[0], CoordPolicyError)
        hub.close(timeout_s=1.0)
        self.assertFalse(hub._session_active_marker.exists())


class TestReciprocalRound8Fixes(CoordTestBase):
    """Red/green regressions for all four cleanup/waiter findings on b0b26deb."""

    _open_pair = TestReciprocalRound6Fixes._open_pair
    _reg_sb = staticmethod(TestReciprocalRound6Fixes._reg_sb)
    _wait_until = staticmethod(TestReciprocalRound6Fixes._wait_until)

    def test_r8_p1_1_recovery_cancels_lease_and_held_stream_before_failing_artifact_reconcile(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        lease = BrokerLease("job_rec_art_r8")
        self._reg_sb(hub, _OP, "sb-ar", "inc_ar1", lease=lease)
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-ar")

        held_started = threading.Event()
        held_release = threading.Event()
        self.addCleanup(held_release.set)
        transport.queue_script(
            "sb-ar", TurnScript(on_stream_started=held_started, block_event=held_release)
        )
        hub.send(_OP, target="sb-ar", body_text="Held turn during failing artifact repair")
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(held_started.wait(timeout=1.0))

        # Queue a second turn with a staged artifact blob, then remove the blob so artifact repair writes
        hub.send(
            _OP,
            target="sb-ar",
            body_text="Pending with artifact",
            artifact_blobs=[b"patch-bytes-r8"],
        )
        for p in (self.state_dir / "inbox-spool" / "inc_ar1").glob("*.patch"):
            p.unlink()

        hub._mark_degraded("simulated_art_repair_degrade")
        orig_cancel = reg.cancel_outbox_row
        fail_once = {"enabled": True}

        def _failing_cancel(msg_id: str, *, reason: str) -> None:
            if fail_once["enabled"]:
                fail_once["enabled"] = False
                raise OSError("artifact_repair_cancel_write_failed")
            orig_cancel(msg_id, reason=reason)

        reg.cancel_outbox_row = _failing_cancel  # type: ignore[method-assign]
        with self.assertRaises(CoordPolicyError):
            hub.confirm_recovery(_OP, reason="art_repair_fails_first")

        # BEFORE retry: lease MUST already be locally revoked and held transport already aborted!
        self.assertTrue(hub._is_lease_locally_revoked(lease))
        self.assertIn(("sb-ar", "inc_ar1"), transport.revoked_incarnations)
        self.assertTrue(hub.is_degraded)

        # Retry succeeds once DB write recovers
        hub.confirm_recovery(_OP, reason="art_repair_retry_ok")
        self.assertFalse(hub.is_degraded)

    def test_r8_p1_2_recovery_and_close_refuse_completion_while_local_cleanup_unresolved(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        lease1 = BrokerLease("job_uc1_r8")
        self._reg_sb(hub, _OP, "sb-uc1", "inc_uc1", lease=lease1)
        hub._mark_degraded("degraded_before_cleanup_fault")

        orig_revoke1 = lease1.revoke
        orig_abort = transport.abort_incarnation
        fail_state = {"lease": True, "abort": True}

        def _flaky_revoke1() -> None:
            if fail_state["lease"]:
                raise RuntimeError("lease_revoke_failed")
            orig_revoke1()

        def _flaky_abort(sb_addr: str, inc_id: str, *, reason: str) -> bool:
            if fail_state["abort"]:
                raise RuntimeError("abort_incarnation_failed")
            return orig_abort(sb_addr, inc_id, reason=reason)

        lease1.revoke = _flaky_revoke1  # type: ignore[method-assign]
        transport.abort_incarnation = _flaky_abort  # type: ignore[method-assign]

        # Part A: confirm_recovery MUST NOT reopen while lease revoke or transport abort fails
        with self.assertRaises(CoordPolicyError):
            hub.confirm_recovery(_OP, reason="cleanup_fails_first")
        self.assertTrue(hub.is_degraded)
        self.assertTrue(hub._degraded_marker.exists())
        self.assertFalse(hub._is_lease_locally_revoked(lease1))

        # Clear faults -> recovery retry settles both handles and reopens cleanly
        fail_state["lease"] = False
        fail_state["abort"] = False
        hub.confirm_recovery(_OP, reason="cleanup_retry_ok")
        self.assertFalse(hub.is_degraded)
        self.assertTrue(hub._is_lease_locally_revoked(lease1))
        self.assertIn(("sb-uc1", "inc_uc1"), transport.revoked_incarnations)

        # Part B: close() MUST NOT release lock or settle while lease revoke fails
        lease2 = BrokerLease("job_uc2_r8")
        self._reg_sb(hub, _OP, "sb-uc2", "inc_uc2", lease=lease2)
        orig_revoke2 = lease2.revoke
        fail_close_lease = {"enabled": True}

        def _flaky_revoke2() -> None:
            if fail_close_lease["enabled"]:
                raise RuntimeError("close_lease_revoke_failed")
            orig_revoke2()

        lease2.revoke = _flaky_revoke2  # type: ignore[method-assign]
        with self.assertRaises(RuntimeError):
            hub.close(timeout_s=1.0)
        self.assertTrue(hub._session_active_marker.exists())
        self.assertGreaterEqual(hub._state_lock_fd, 0)
        self.assertFalse(hub._shutdown_settled)

        # Clear fault -> close retry revokes lease and settles cleanly
        fail_close_lease["enabled"] = False
        hub.close(timeout_s=1.0)
        self.assertTrue(hub._is_lease_locally_revoked(lease2))
        self.assertTrue(hub._shutdown_settled)

    def test_r8_p1_3_unmonitored_failed_receipt_stream_has_retry_owner_and_blocks_close_until_settled(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        # No controller_request_id and no lease -> zero controller monitors
        self._reg_sb(hub, _OP, "sb-um", "inc_um1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-um")
        transport.queue_script("sb-um", TurnScript(block_event=threading.Event()))
        msg_um = hub.send(_OP, target="sb-um", body_text="Unmonitored failed receipt")["msg_id"]

        orig_abort_stream = transport.abort_stream
        allow_abort = {"ok": False}
        abort_calls: list[str] = []

        def _gated_abort(stream_id: str, *, reason: str) -> bool:
            abort_calls.append(stream_id)
            if not allow_abort["ok"]:
                return False
            return orig_abort_stream(stream_id, reason=reason)

        def _fail_handed_off(_msg_id: str, *, stream_id: str) -> None:
            _ = stream_id
            raise OSError("unmonitored_handoff_write_failed")

        transport.abort_stream = _gated_abort  # type: ignore[method-assign]
        reg.mark_outbox_handed_off = _fail_handed_off  # type: ignore[method-assign]

        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertEqual(hub._request_monitors, {})
        self.assertIn(msg_um, {r["msg_id"] for r in reg.list_outbox(statuses=("uncertain",))})

        # Part A: Background cleanup retry worker retries abort_stream without any controller monitor
        self.assertTrue(self._wait_until(lambda: len(abort_calls) >= 2))
        returned_sid = abort_calls[0]
        self.assertIn(returned_sid, hub._pending_cleanup_streams)

        # Part B: close() refuses to settle while failed-receipt stream remains uncancelled
        with self.assertRaises(CoordPolicyError):
            hub.close(timeout_s=1.0)
        self.assertTrue(hub._session_active_marker.exists())
        self.assertGreaterEqual(hub._state_lock_fd, 0)
        self.assertIn(returned_sid, hub._pending_cleanup_streams)

        # Allow abort_stream to succeed -> close retry settles cleanly and clears handle
        allow_abort["ok"] = True
        hub.close(timeout_s=1.0)
        self.assertNotIn(returned_sid, hub._pending_cleanup_streams)
        self.assertNotIn(returned_sid, hub._stream_authorities)
        self.assertTrue(hub._shutdown_settled)

    def test_r8_p1_4_waiter_rejects_nonempty_batch_when_revoked_during_read(
        self,
    ) -> None:
        reg, _transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-wr", "inc_wr1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-wr")
        hub.send(_OP, target="sb-wr", body_text="Produce nonempty batch")
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)

        in_read = threading.Event()
        release_read = threading.Event()
        self.addCleanup(release_read.set)
        orig_list_events = reg.list_events_since

        def _paused_list_events(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            events = orig_list_events(*args, **kwargs)
            if events and not release_read.is_set():
                in_read.set()
                release_read.wait(timeout=2.0)
            return events

        reg.list_events_since = _paused_list_events  # type: ignore[method-assign]
        wait_res: list[dict[str, Any]] = []
        wait_err: list[Exception] = []

        def _run_waiter() -> None:
            try:
                wait_res.append(hub.wait(_OP, targets=("sb-wr",), since_seq=0, timeout_s=5.0))
            except Exception as exc:
                wait_err.append(exc)

        t_wait = threading.Thread(target=_run_waiter, daemon=True)
        t_wait.start()
        self.assertTrue(in_read.wait(timeout=1.0))

        # Revoke target WHILE waiter is paused with a nonempty batch ready to return
        hub.revoke(_OP, target="sb-wr", reason="revoked_mid_read")
        release_read.set()
        t_wait.join(timeout=1.5)

        self.assertEqual(wait_res, [])
        self.assertEqual(len(wait_err), 1)
        self.assertIsInstance(wait_err[0], RevokedError)


class TestReciprocalRound9Fixes(CoordTestBase):
    """Red/green regressions for cleanup worker, minimal transport, and wait deadline on 8d1f8ab2."""

    _open_pair = TestReciprocalRound6Fixes._open_pair
    _reg_sb = staticmethod(TestReciprocalRound6Fixes._reg_sb)
    _wait_until = staticmethod(TestReciprocalRound6Fixes._wait_until)

    def _assert_concurrent_cleanup_single_owner(
        self, hub: CoordHub, allow_s2: dict[str, bool]
    ) -> None:
        start_entered = threading.Event()
        release_start = threading.Event()
        orig_start = threading.Thread.start
        worker_starts = 0
        start_lock = threading.Lock()

        def _intercept_start(thr: threading.Thread) -> None:
            nonlocal worker_starts
            if getattr(thr, "_target", None) == hub._run_cleanup_retry_loop:
                with start_lock:
                    worker_starts += 1
                    first = worker_starts == 1
                if first:
                    start_entered.set()
                    release_start.wait(timeout=2.0)
            orig_start(thr)

        allow_s2["ok"] = False
        hub._record_pending_cleanup_stream("sid_r9_2", "sb-cw", "inc_cw1", "handoff_persist_failed")
        with mock.patch.object(threading.Thread, "start", _intercept_start):
            t1 = threading.Thread(target=hub._ensure_cleanup_retry_worker, daemon=True)
            t2 = threading.Thread(target=hub._ensure_cleanup_retry_worker, daemon=True)
            t1.start()
            self.assertTrue(start_entered.wait(timeout=1.0))
            t2.start()
            time.sleep(0.05)
            release_start.set()
            t1.join(timeout=1.5)
            t2.join(timeout=1.5)
        self.assertEqual(worker_starts, 1)
        allow_s2["ok"] = True
        self.assertTrue(self._wait_until(lambda: not hub._has_pending_cleanups()))
        self.assertTrue(self._wait_until(lambda: hub._cleanup_state is None))

    def _assert_cleanup_start_error_surfaced(
        self, hub: CoordHub, allow_s2: dict[str, bool]
    ) -> None:
        orig_start = threading.Thread.start
        allow_s2["ok"] = False
        hub._record_pending_cleanup_stream("sid_r9_2", "sb-cw", "inc_cw1", "handoff_persist_failed")

        def _fail_start(thr: threading.Thread) -> None:
            if getattr(thr, "_target", None) == hub._run_cleanup_retry_loop:
                raise RuntimeError("cleanup_worker_start_failed")
            orig_start(thr)

        with (
            mock.patch.object(threading.Thread, "start", _fail_start),
            self.assertRaises(RuntimeError),
        ):
            hub._ensure_cleanup_retry_worker()
        self.assertTrue(hub.is_degraded)
        self.assertIn("sid_r9_2", hub._pending_cleanup_streams)
        allow_s2["ok"] = True

    def test_r9_p1_1_cleanup_worker_atomic_retirement_single_owner_and_start_error_surfaced(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-cw", "inc_cw1")

        # Part A: Enqueue a second stream while first worker is retiring -> MUST NOT strand!
        allow_s1 = {"ok": False}
        allow_s2 = {"ok": False}
        s2_aborted = threading.Event()
        orig_abort_stream = transport.abort_stream

        def _custom_abort(stream_id: str, *, reason: str) -> bool:
            if stream_id == "sid_r9_1":
                return allow_s1["ok"]
            if stream_id == "sid_r9_2":
                if allow_s2["ok"]:
                    s2_aborted.set()
                    return True
                return False
            return orig_abort_stream(stream_id, reason=reason)

        transport.abort_stream = _custom_abort  # type: ignore[method-assign]
        injected_s2 = {"done": False}
        orig_drain = hub._drain_pending_cleanups

        def _drain_and_enqueue_s2() -> bool:
            res = orig_drain()
            if res and not injected_s2["done"]:
                injected_s2["done"] = True
                # Enqueue second stream AFTER worker observed empty queue, BEFORE worker retires!
                hub._record_pending_cleanup_stream("sid_r9_2", "sb-cw", "inc_cw1", "handoff_persist_failed")
                allow_s2["ok"] = True
            return res

        hub._drain_pending_cleanups = _drain_and_enqueue_s2  # type: ignore[method-assign]
        hub._record_pending_cleanup_stream("sid_r9_1", "sb-cw", "inc_cw1", "handoff_persist_failed")
        hub._ensure_cleanup_retry_worker()
        allow_s1["ok"] = True
        self.assertTrue(s2_aborted.wait(timeout=1.5))
        self.assertTrue(self._wait_until(lambda: not hub._has_pending_cleanups()))
        hub._drain_pending_cleanups = orig_drain  # type: ignore[method-assign]

        # Part B & C: Single-owner concurrent startup and surfaced startup failure
        self._assert_concurrent_cleanup_single_owner(hub, allow_s2)
        self._assert_cleanup_start_error_surfaced(hub, allow_s2)

    def test_r9_p1_2_failed_inbound_revoke_abort_retries_automatically_and_unblocks_close(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self._reg_sb(hub, _OP, "sb-ir", "inc_ir1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-ir")

        started = threading.Event()
        never_done = threading.Event()
        self.addCleanup(never_done.set)
        transport.queue_script(
            "sb-ir", TurnScript(on_stream_started=started, block_event=never_done)
        )
        hub.send(_OP, target="sb-ir", body_text="Held inbound stream")
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(started.wait(timeout=1.0))

        orig_abort = transport.abort_incarnation
        fail_abort = {"on": True}

        def _flaky_abort(sb_addr: str, inc_id: str, *, reason: str) -> bool:
            if fail_abort["on"]:
                raise RuntimeError("transient_inbound_abort_failure")
            return orig_abort(sb_addr, inc_id, reason=reason)

        transport.abort_incarnation = _flaky_abort  # type: ignore[method-assign]
        hub.revoke(_OP, target="sb-ir", reason="inbound_revoke_with_transient_err")
        self.assertNotIn(("sb-ir", "inc_ir1"), transport.revoked_incarnations)

        # Clear transport fault -> cleanup retry worker (and close pre-join drain) aborts held stream!
        fail_abort["on"] = False
        self.assertTrue(
            self._wait_until(lambda: ("sb-ir", "inc_ir1") in transport.revoked_incarnations)
        )
        hub.close(timeout_s=1.0)
        self.assertFalse(hub._session_active_marker.exists())

    def test_r9_p2_3_minimal_transport_without_abort_stream_recovers_and_closes_cleanly(
        self,
    ) -> None:
        inner = FakeWorkerTransport()
        proxy = _NoAbortStreamTransport(inner)
        reg, _transport, hub = self._open_pair(transport=proxy)
        self.addCleanup(reg.close)
        self._reg_sb(hub, _OP, "sb-min", "inc_min1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-min")

        started = threading.Event()
        never_done = threading.Event()
        self.addCleanup(never_done.set)
        inner.queue_script(
            "sb-min", TurnScript(on_stream_started=started, block_event=never_done)
        )
        hub.send(_OP, target="sb-min", body_text="Held turn on minimal transport")
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(started.wait(timeout=1.0))

        hub._mark_degraded("minimal_transport_degrade")
        hub.confirm_recovery(_OP, reason="minimal_transport_recovered")
        self.assertFalse(hub.is_degraded)
        self.assertIn(("sb-min", "inc_min1"), inner.revoked_incarnations)
        self.assertEqual(hub._pending_cleanup_streams, {})
        hub.close(timeout_s=1.0)
        self.assertFalse(hub._session_active_marker.exists())

    def test_r9_p2_4_nonempty_wait_honors_deadline_under_sustained_generation_churn(
        self,
    ) -> None:
        reg, _transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-wc", "inc_wc1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-wc")
        hub.send(_OP, target="sb-wc", body_text="Produce nonempty batch for churn test")
        self.assertEqual(hub.dispatch_once(async_stream=False), 1)

        orig_list = reg.list_events_since

        def _churning_list(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            events = orig_list(*args, **kwargs)
            time.sleep(0.015)
            hub._notify_waiters()
            return events

        reg.list_events_since = _churning_list  # type: ignore[method-assign]
        t0 = time.monotonic()
        res = hub.wait(_OP, targets=("sb-wc",), since_seq=0, timeout_s=0.06)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.5)
        self.assertTrue(res["timed_out"])
        self.assertEqual(res["events"], [])


class TestReciprocalRound10Fixes(CoordTestBase):
    """Red/green regressions for the four boundary findings on b01543f9."""

    _open_pair = TestReciprocalRound6Fixes._open_pair
    _reg_sb = staticmethod(TestReciprocalRound6Fixes._reg_sb)
    _wait_until = staticmethod(TestReciprocalRound6Fixes._wait_until)

    def test_r10_p1_1_revoke_retry_worker_start_failure_does_not_strand_detached_lease(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        lease = BrokerLease("job_strand_r10")
        self._reg_sb(hub, _OP, "sb-r10s", "inc_s1", lease=lease)
        self._reg_sb(hub, _OP, "sb-r10d", "inc_d1")
        hub.grant_edge(_OP, src_actor="sb-r10s", src_incarnation="inc_s1", dst_addr="sb-r10d")

        started = threading.Event()
        never_done = threading.Event()
        self.addCleanup(never_done.set)
        transport.queue_script(
            "sb-r10d", TurnScript(on_stream_started=started, block_event=never_done)
        )
        src_ctx = PrincipalCtx(
            CoordRole.JOB, "jr10", sandbox_addr="sb-r10s", incarnation_id="inc_s1"
        )
        hub.send(src_ctx, target="sb-r10d", body_text="Held outbound turn")
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(started.wait(timeout=1.0))

        orig_abort_stream = transport.abort_stream
        fail_abort_stream = {"on": True}

        def _flaky_abort_stream(stream_id: str, *, reason: str) -> bool:
            if fail_abort_stream["on"]:
                return False
            return orig_abort_stream(stream_id, reason=reason)

        orig_start = threading.Thread.start

        def _fail_worker_start(thr: threading.Thread) -> None:
            if getattr(thr, "_target", None) == hub._run_cleanup_retry_loop:
                raise RuntimeError("retry_worker_start_failed")
            orig_start(thr)

        transport.abort_stream = _flaky_abort_stream  # type: ignore[method-assign]
        with (
            mock.patch.object(threading.Thread, "start", _fail_worker_start),
            self.assertRaises(RuntimeError),
        ):
            hub.revoke(_OP, target="sb-r10s", reason="revoke_with_worker_start_err")

        # Detached lease MUST already be revoked (not stranded active!), hub degraded, stream retained
        self.assertTrue(hub._is_lease_locally_revoked(lease))
        self.assertTrue(hub.is_degraded)
        self.assertTrue(bool(hub._pending_cleanup_streams))

        fail_abort_stream["on"] = False
        hub.confirm_recovery(_OP, reason="recovered_after_worker_start_err")
        self.assertFalse(hub.is_degraded)
        self.assertEqual(hub._pending_cleanup_streams, {})

    def test_r10_p1_2_peer_turn_on_minimal_transport_rejected_without_abort_stream(
        self,
    ) -> None:
        inner = FakeWorkerTransport()
        proxy = _NoAbortStreamTransport(inner)
        reg, _transport, hub = self._open_pair(transport=proxy)
        self.addCleanup(reg.close)
        self.addCleanup(hub.close)
        self._reg_sb(hub, _OP, "sb-p1", "inc_p1")
        self._reg_sb(hub, _OP, "sb-p2", "inc_p2")
        hub.grant_edge(_OP, src_actor="sb-p1", src_incarnation="inc_p1", dst_addr="sb-p2")
        p1_ctx = PrincipalCtx(CoordRole.JOB, "jp1", sandbox_addr="sb-p1", incarnation_id="inc_p1")
        with self.assertRaises(CoordPolicyError):
            hub.send(p1_ctx, target="sb-p2", body_text="Peer turn needs abort_stream")
        self.assertEqual(inner.dispatched_turns("sb-p2"), [])
        self.assertEqual(reg.list_outbox(statuses=("pending",)), [])

    def test_r10_p2_3_stalled_pre_join_cleanup_drain_respects_close_deadline(
        self,
    ) -> None:
        reg, _transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        lease = BrokerLease("job_prejoin_r10")
        self._reg_sb(hub, _OP, "sb-pj", "inc_pj1", lease=lease)

        in_drain = threading.Event()
        release_drain = threading.Event()
        self.addCleanup(release_drain.set)
        orig_revoke = lease.revoke

        def _stalled_revoke() -> None:
            if not release_drain.is_set():
                in_drain.set()
                release_drain.wait(timeout=2.0)
            orig_revoke()

        lease.revoke = _stalled_revoke  # type: ignore[method-assign]
        # Enqueue lease directly in pending cleanups (e.g. from prior failed revoke)
        hub._record_pending_cleanup_lease(lease)

        t0 = time.monotonic()
        with self.assertRaises(CoordPolicyError):
            hub.close(timeout_s=0.05)
        elapsed = time.monotonic() - t0
        self.assertTrue(in_drain.is_set())
        self.assertLess(elapsed, 0.35)
        self.assertTrue(hub._session_active_marker.exists())
        self.assertGreaterEqual(hub._state_lock_fd, 0)
        self.assertIn(lease, hub._pending_cleanup_leases)

        release_drain.set()
        hub.close(timeout_s=1.0)
        self.assertTrue(hub._is_lease_locally_revoked(lease))
        self.assertFalse(hub._session_active_marker.exists())

    def test_r10_p2_4_recovery_settles_streams_when_abort_incarnation_purges_stream_handles(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self._reg_sb(hub, _OP, "sb-pg", "inc_pg1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-pg")

        started = threading.Event()
        never_done = threading.Event()
        self.addCleanup(never_done.set)
        transport.queue_script(
            "sb-pg", TurnScript(on_stream_started=started, block_event=never_done)
        )
        hub.send(_OP, target="sb-pg", body_text="Held turn before purging abort_incarnation")
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertTrue(started.wait(timeout=1.0))

        orig_abort_inc = transport.abort_incarnation

        def _purging_abort_incarnation(
            sandbox_addr: str, incarnation_id: str, *, reason: str
        ) -> bool:
            res = orig_abort_inc(sandbox_addr, incarnation_id, reason=reason)
            # Simulate a transport that removes stream handles during abort_incarnation so abort_stream returns False
            with transport._lock:
                for sid in tuple(transport._streams):
                    st = transport._streams[sid]
                    if (
                        st.turn.sandbox_addr == sandbox_addr
                        and st.turn.incarnation_id == incarnation_id
                    ):
                        transport._streams.pop(sid, None)
            return res

        transport.abort_incarnation = _purging_abort_incarnation  # type: ignore[method-assign]
        hub._mark_degraded("purging_transport_degrade")
        hub.confirm_recovery(_OP, reason="purging_transport_recovered")
        self.assertFalse(hub.is_degraded)
        self.assertEqual(hub._pending_cleanup_streams, {})
        hub.close(timeout_s=1.0)
        self.assertFalse(hub._session_active_marker.exists())


class TestReciprocalRound11Fixes(CoordTestBase):
    """Red/green regressions for the two P2 findings on a4421111."""

    _open_pair = TestReciprocalRound6Fixes._open_pair
    _reg_sb = staticmethod(TestReciprocalRound6Fixes._reg_sb)

    def test_r11_p2_1_unsupported_pending_peer_turn_does_not_block_eligible_turn_and_new_send_rejected(
        self,
    ) -> None:
        # Phase 1: Enqueue an unsupported peer turn AND an eligible operator turn while full transport is attached
        reg1, _t1, hub1 = self._open_pair()
        try:
            self._reg_sb(hub1, _OP, "sb-psrc", "inc_ps1")
            self._reg_sb(hub1, _OP, "sb-pdst", "inc_pd1")
            self._reg_sb(hub1, _OP, "sb-elig", "inc_el1")
            self._reg_sb(hub1, _OP, "sb-elig0", "inc_el0")
            hub1.grant_edge(_OP, src_actor="sb-psrc", src_incarnation="inc_ps1", dst_addr="sb-pdst")
            hub1.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-elig")
            hub1.grant_edge(_OP, src_actor="sb-elig0", src_incarnation="inc_el0", dst_addr="sb-elig0")
            p_ctx = PrincipalCtx(
                CoordRole.JOB, "jp11", sandbox_addr="sb-psrc", incarnation_id="inc_ps1"
            )
            self_ctx = PrincipalCtx(
                CoordRole.JOB, "js11", sandbox_addr="sb-elig0", incarnation_id="inc_el0"
            )
            # Peer row (priority=0) sits ahead of equal-priority eligible self-send (priority=0) in seq order
            msg_peer = hub1.send(p_ctx, target="sb-pdst", body_text="Unsupported peer row")[
                "msg_id"
            ]
            msg_elig0 = hub1.send(self_ctx, target="sb-elig0", body_text="Eligible prio-0 row")[
                "msg_id"
            ]
            msg_elig = hub1.send(_OP, target="sb-elig", body_text="Eligible operator row")[
                "msg_id"
            ]
            by_id = {r["msg_id"]: r for r in reg1.list_outbox(statuses=("pending",))}
            self.assertEqual(by_id[msg_peer]["priority"], 0)
            self.assertEqual(by_id[msg_elig0]["priority"], 0)
            self.assertLess(by_id[msg_peer]["seq"], by_id[msg_elig0]["seq"])
        finally:
            hub1.close()
            reg1.close()

        # Phase 2: Reopen on minimal transport (no abort_stream)
        inner = FakeWorkerTransport()
        proxy = _NoAbortStreamTransport(inner)
        reg2, _t2, hub2 = self._open_pair(transport=proxy)
        self.addCleanup(reg2.close)
        self.addCleanup(hub2.close)

        # New unsupported peer send is rejected upfront before enqueue
        with self.assertRaises(CoordPolicyError):
            hub2.send(p_ctx, target="sb-pdst", body_text="Rejected upfront")

        # Already-pending unsupported peer row sends nothing, yet both eligible rows STILL dispatch!
        self.assertEqual(hub2.dispatch_once(async_stream=False), 2)
        self.assertEqual(inner.dispatched_turns("sb-pdst"), [])
        self.assertEqual([t.msg_id for t in inner.dispatched_turns("sb-elig0")], [msg_elig0])
        self.assertEqual([t.msg_id for t in inner.dispatched_turns("sb-elig")], [msg_elig])
        self.assertIn(msg_peer, {r["msg_id"] for r in reg2.list_outbox(statuses=("pending",))})
        completed = {r["msg_id"] for r in reg2.list_outbox(statuses=("completed",))}
        self.assertTrue({msg_elig, msg_elig0}.issubset(completed))

    def test_r11_p2_2_recovery_terminal_abort_settles_failed_receipt_stream_on_purging_transport(
        self,
    ) -> None:
        reg, transport, hub = self._open_pair()
        self.addCleanup(reg.close)
        self._reg_sb(hub, _OP, "sb-frp", "inc_frp1")
        hub.grant_edge(_OP, src_actor=_OP.canonical_sender, dst_addr="sb-frp")
        transport.queue_script("sb-frp", TurnScript(block_event=threading.Event()))
        msg_frp = hub.send(_OP, target="sb-frp", body_text="Failed receipt before purging recovery")[
            "msg_id"
        ]

        orig_abort_stream = transport.abort_stream
        orig_abort_inc = transport.abort_incarnation
        fail_abort_stream = {"on": True}

        def _gated_abort_stream(stream_id: str, *, reason: str) -> bool:
            if fail_abort_stream["on"]:
                return False
            return orig_abort_stream(stream_id, reason=reason)

        def _purging_abort_incarnation(
            sandbox_addr: str, incarnation_id: str, *, reason: str
        ) -> bool:
            res = orig_abort_inc(sandbox_addr, incarnation_id, reason=reason)
            with transport._lock:
                for sid in tuple(transport._streams):
                    st = transport._streams[sid]
                    if (
                        st.turn.sandbox_addr == sandbox_addr
                        and st.turn.incarnation_id == incarnation_id
                    ):
                        transport._streams.pop(sid, None)
            fail_abort_stream["on"] = False
            return res

        def _fail_handed_off(_msg_id: str, *, stream_id: str) -> None:
            _ = stream_id
            raise OSError("receipt_write_failed_before_recovery")

        transport.abort_stream = _gated_abort_stream  # type: ignore[method-assign]
        transport.abort_incarnation = _purging_abort_incarnation  # type: ignore[method-assign]
        reg.mark_outbox_handed_off = _fail_handed_off  # type: ignore[method-assign]

        # Dispatch creates a retained failed-receipt stream (reason=handoff_persist_failed)
        self.assertEqual(hub.dispatch_once(async_stream=True), 1)
        self.assertIn(msg_frp, {r["msg_id"] for r in reg.list_outbox(statuses=("uncertain",))})
        self.assertTrue(bool(hub._pending_cleanup_streams))

        # Now degrade & recover: abort_incarnation purges stream handles so abort_stream returns False
        hub._mark_degraded("degraded_with_failed_receipt_on_purging_transport")
        hub.confirm_recovery(_OP, reason="terminal_abort_settles_failed_receipt")

        self.assertFalse(hub.is_degraded)
        self.assertEqual(hub._pending_cleanup_streams, {})
        self.assertEqual(hub._stream_authorities, {})
        self.assertEqual(hub._stream_abort_reasons, {})
        self.assertIn(msg_frp, {r["msg_id"] for r in reg.list_outbox(statuses=("uncertain",))})
        hub.close(timeout_s=1.0)
        self.assertFalse(hub._session_active_marker.exists())


if __name__ == "__main__":
    unittest.main()
