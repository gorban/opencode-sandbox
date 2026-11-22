"""Unit and adversarial regression tests for offline PRD N supervision and calibration replay."""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from oc_workflow_plan import (
    AuthorityError,
    ClockSnapshot,
    LaneLeaseRegistry,
    RunAuthorityStore,
    TargetIncarnation,
    compile_workflow_plan,
    evaluate_admission,
)
from oc_workflow_schema import ExcerptDisclosureSpec
from oc_workflow_supervision import (
    BlindCheckResponse,
    BlindCheckRunBudget,
    BlindToolCall,
    CalibrationLedger,
    CalibrationRecord,
    CalibrationReplayGrant,
    CanaryLeakError,
    CorrelatedFaultCoalescer,
    DecisionsAdapterResponse,
    DecisionsRunBudget,
    DisclosureBlockedError,
    FleetCheckBudget,
    HostSleepDetector,
    LaneSupervisionState,
    LocalRulesDecisionsAdapter,
    MetricSnapshot,
    NudgeRunBudget,
    OverlapCanaryScanner,
    ProgressFingerprint,
    ReplayAuthorizationError,
    ReplayGrantBudget,
    ScriptedBlindVerifier,
    SupervisionBrokerGate,
    TrustedMetrics,
    UntrustedClaims,
    frame_untrusted_excerpt,
    process_supervision_tick,
    query_calibration_examples,
    run_calibration_replay,
    run_scheduled_audit,
)
from test_workflow_schema_and_plan import _make_skill_tree, _sample_catalog, _supervisor_toml


def _fp(commit: str = "aaa111", tree: str = "ttt111", test_seq: int = 1) -> ProgressFingerprint:
    return ProgressFingerprint(
        commit_sha=commit,
        tree_oid=tree,
        diff_stat_hash="ddd111",
        verified_test_exit_seq=test_seq,
        workflow_state_seq=1,
    )


def _snapshot(
    target: TargetIncarnation,
    *,
    stall_s: int = 700,
    errors: int = 4,
    transport_at: float = 100.0,
    human_lease: bool = False,
    fp: ProgressFingerprint | None = None,
    excerpt: str | None = None,
    self_report: str = "",
    provider_route: str = "",
    remote_worker: str = "local",
    error_class: str = "",
) -> MetricSnapshot:
    return MetricSnapshot(
        snapshot_id=f"snap_{target.sandbox_addr}_{stall_s}_{int(transport_at)}",
        trusted=TrustedMetrics(
            target=target,
            stall_seconds=stall_s,
            consecutive_errors=errors,
            http_429_count=0,
            http_5xx_count=0,
            quota_5h_remaining_pct=80,
            last_transport_frame_at=transport_at,
            human_input_lease_active=human_lease,
            progress_fingerprint=fp or _fp(),
            provider_route=provider_route,
            remote_worker=remote_worker,
            error_class=error_class,
        ),
        untrusted=UntrustedClaims(
            self_reported_status=self_report,
            sanitized_last_error_excerpt=excerpt,
        ),
    )


class TestSupervisionCore(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.skill_root = _make_skill_tree(self.root, "builtin", "firstmate-guide", b"# Guide\n")
        self.catalog = _sample_catalog()
        self.target = TargetIncarnation("local/lane-a", "inc-1")
        self.now = [ClockSnapshot(monotonic_s=100.0, wall_s=1000.0)]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _clock(self) -> ClockSnapshot:
        return self.now[0]

    def _setup_run(
        self,
        *,
        extra_supervision: str = "",
        lease_ttl_s: float = 3600.0,
        decisions_adapter: LocalRulesDecisionsAdapter | None = None,
        blind_verifier: ScriptedBlindVerifier | None = None,
        corpus: tuple[str, ...] = (),
        blind_budget_microusd: int = 2_000_000,
        decisions_budget_microusd: int = 500_000,
        decisions_calls_hr: int = 120,
        fleet_max_concurrent: int = 2,
        fleet_max_hr: int = 30,
        fleet_audit_hr: int = 8,
    ) -> dict[str, object]:
        plan = compile_workflow_plan(
            _supervisor_toml(extra_supervision=extra_supervision),
            is_builtin=True,
            skill_root=self.skill_root,
            model_catalog=self.catalog,
        )
        store = RunAuthorityStore()
        receipt = evaluate_admission(
            plan, store, principal_id="op-1", caller_role="operator",
            caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4,
            clock=self._clock(), operator_lease_ttl_s=lease_ttl_s,
        )
        lanes = LaneLeaseRegistry()
        lanes.attach(self.target, receipt=receipt, authority_store=store, clock=self._clock())
        d_adapter = decisions_adapter or LocalRulesDecisionsAdapter()
        b_verifier = blind_verifier or ScriptedBlindVerifier()
        gate = SupervisionBrokerGate(
            decisions_adapter=d_adapter,
            blind_verifier=b_verifier,
            canary_scanner=OverlapCanaryScanner(corpus),
        )
        return {
            "plan": plan,
            "store": store,
            "receipt": receipt,
            "lanes": lanes,
            "d_adapter": d_adapter,
            "b_verifier": b_verifier,
            "gate": gate,
            "sleep": HostSleepDetector(),
            "d_budget": DecisionsRunBudget(max_calls_per_hour=decisions_calls_hr, max_spend_microusd=decisions_budget_microusd),
            "b_budget": BlindCheckRunBudget(max_spend_microusd=blind_budget_microusd),
            "fleet_budget": FleetCheckBudget(
                max_concurrent=fleet_max_concurrent,
                max_checks_per_hour=fleet_max_hr,
                reserved_audit_checks_per_hour=fleet_audit_hr,
            ),
            "n_budget": NudgeRunBudget(min_nudge_interval_s=300, max_per_target_per_hour=2, max_total_per_run=40),
            "ledger": CalibrationLedger(),
            "lane_state": LaneSupervisionState(target=self.target),
        }

    def test_broker_gate_precall_authority_blind_budget_and_canary_in_payload(self) -> None:
        # Exhausted per-run blind budget with spare FleetCheckBudget yields ZERO blind-adapter calls
        ctx = self._setup_run(blind_budget_microusd=0)
        snap = _snapshot(self.target, excerpt="secret_excerpt_not_disclosed")
        res = process_supervision_tick(
            ctx["lane_state"], lambda _t: snap, self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
            authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(res.status, "blind_budget_exhausted_tier0_only")
        self.assertEqual(ctx["b_verifier"].invocation_count, 0)  # type: ignore[union-attr]
        # Verify canary_question was inside exact serialized System-1 payload
        sys1_payload = json.loads(ctx["d_adapter"].payload_history[0].decode("utf-8"))  # type: ignore[union-attr]
        self.assertEqual(sys1_payload["canary_question"], "noul(classifier_injection_suspected)")
        self.assertNotIn("sanitized_last_error_excerpt", sys1_payload)

        # Revoked run yields ZERO System-1 and ZERO blind-adapter invocations
        ctx2 = self._setup_run()
        ctx2["store"].revoke_run(ctx2["receipt"].run_id)  # type: ignore[union-attr]
        with self.assertRaises(AuthorityError):
            process_supervision_tick(
                ctx2["lane_state"], lambda _t: snap, self._clock,  # type: ignore[arg-type]
                receipt=ctx2["receipt"], plan=ctx2["plan"], sleep_detector=ctx2["sleep"],  # type: ignore[arg-type]
                authority_store=ctx2["store"], broker_gate=ctx2["gate"],  # type: ignore[arg-type]
                decisions_budget=ctx2["d_budget"], blind_budget=ctx2["b_budget"],  # type: ignore[arg-type]
                fleet_budget=ctx2["fleet_budget"], nudge_budget=ctx2["n_budget"],  # type: ignore[arg-type]
                lease_registry=ctx2["lanes"], ledger=ctx2["ledger"],  # type: ignore[arg-type]
            )
        self.assertEqual(ctx2["d_adapter"].invocation_count, 0)  # type: ignore[union-attr]
        self.assertEqual(ctx2["b_verifier"].invocation_count, 0)  # type: ignore[union-attr]

    def test_throttler_before_system1_trailing_bypass_and_cap_delayed(self) -> None:
        nudge_resp = BlindCheckResponse(tool_calls=(BlindToolCall("health_nudge_lane", {"template_id": "nudge_stalled"}),))
        verifier = ScriptedBlindVerifier([nudge_resp, nudge_resp, nudge_resp])
        ctx = self._setup_run(blind_verifier=verifier)
        snap = _snapshot(self.target, stall_s=700, errors=4)

        # Alert #1 at t=100 -> immediate triggered_leading, enters THROTTLED until t=400
        r1 = process_supervision_tick(
            ctx["lane_state"], lambda _t: snap, self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
            authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(r1.status, "action_executed")
        self.assertEqual(ctx["d_adapter"].invocation_count, 1)  # type: ignore[union-attr]
        self.assertEqual(verifier.invocation_count, 1)

        # Alerts #2..#5 during Period 1 -> suppressed, trailing_queued=True, zero additional blind calls
        for dt in (60.0, 120.0, 180.0, 240.0):
            self.now[0] = ClockSnapshot(monotonic_s=100.0 + dt, wall_s=1000.0 + dt)
            rt = process_supervision_tick(
                ctx["lane_state"], lambda _t: snap, self._clock,  # type: ignore[arg-type]
                receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
                authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
                decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
                fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
                lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
            )
            self.assertEqual(rt.status, "throttled_trailing_queued")
        self.assertEqual(verifier.invocation_count, 1)
        sys1_before_boundary = ctx["d_adapter"].invocation_count  # type: ignore[union-attr]

        # At Period-1 boundary (t=400): MUST bypass System-1 (0 new System-1 calls) and dispatch 1 trailing blind check!
        self.now[0] = ClockSnapshot(monotonic_s=400.0, wall_s=1300.0)
        r_trail = process_supervision_tick(
            ctx["lane_state"], lambda _t: snap, self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
            authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(ctx["d_adapter"].invocation_count, sys1_before_boundary)  # type: ignore[union-attr]
        self.assertEqual(verifier.invocation_count, 2)
        self.assertEqual(r_trail.confusion_outcome, "excluded")
        # Quiet Period 2 -> at t=700 returns to IDLE and runs healthy System-1
        healthy_snap = _snapshot(self.target, stall_s=0, errors=0)
        self.now[0] = ClockSnapshot(monotonic_s=700.0, wall_s=1600.0)
        r_idle = process_supervision_tick(
            ctx["lane_state"], lambda _t: healthy_snap, self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
            authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(r_idle.status, "healthy_no_action")
        self.assertEqual(ctx["lane_state"].mode, "IDLE")  # type: ignore[union-attr]

        # cap_delayed leading check must NOT enter THROTTLED prematurely
        ctx_del = self._setup_run(fleet_max_concurrent=0)
        r_del = process_supervision_tick(
            ctx_del["lane_state"], lambda _t: snap, self._clock,  # type: ignore[arg-type]
            receipt=ctx_del["receipt"], plan=ctx_del["plan"], sleep_detector=ctx_del["sleep"],  # type: ignore[arg-type]
            authority_store=ctx_del["store"], broker_gate=ctx_del["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx_del["d_budget"], blind_budget=ctx_del["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx_del["fleet_budget"], nudge_budget=ctx_del["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx_del["lanes"], ledger=ctx_del["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(r_del.status, "triggered_leading_cap_delayed")
        self.assertEqual(ctx_del["lane_state"].mode, "IDLE")  # type: ignore[union-attr]

    def test_post_verdict_freshness_mid_call_expiry_and_turn_completed_immunity(self) -> None:
        # Case A: Host-verified ProgressFingerprint advances DURING blind call -> TP recorded, nudge suppressed
        live_snap = [_snapshot(self.target, stall_s=700, errors=4, fp=_fp("c1", "t1", 1))]

        def advance_real_progress(_payload: bytes) -> None:
            live_snap[0] = _snapshot(self.target, stall_s=0, errors=0, fp=_fp("c2", "t2", 2))

        nudge_resp = BlindCheckResponse(tool_calls=(BlindToolCall("health_nudge_lane", {"template_id": "nudge_stalled"}),))
        ctx = self._setup_run(blind_verifier=ScriptedBlindVerifier([nudge_resp], on_call=advance_real_progress))
        res_prog = process_supervision_tick(
            ctx["lane_state"], lambda _t: live_snap[0], self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
            authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(res_prog.status, "suppressed_by_freshness_progress")
        self.assertIsNone(res_prog.action_taken)
        self.assertEqual(ctx["ledger"].stats_for("triggered_leading").tp, 1)  # type: ignore[union-attr]
        self.assertEqual(ctx["n_budget"].total_nudges, 0)  # type: ignore[union-attr]

        # Case B: Worker emits ONLY turn_completed / "Got it, continuing!" during blind call -> nudge proceeds!
        live_snap_b = [_snapshot(self.target, stall_s=700, errors=4, transport_at=100.0, fp=_fp("c1", "t1", 1))]

        def emit_worker_only(_payload: bytes) -> None:
            live_snap_b[0] = _snapshot(
                self.target, stall_s=700, errors=4, transport_at=105.0,
                self_report="Got it, continuing!", fp=_fp("c1", "t1", 1),
            )

        ctx_b = self._setup_run(blind_verifier=ScriptedBlindVerifier([nudge_resp], on_call=emit_worker_only))
        res_worker = process_supervision_tick(
            ctx_b["lane_state"], lambda _t: live_snap_b[0], self._clock,  # type: ignore[arg-type]
            receipt=ctx_b["receipt"], plan=ctx_b["plan"], sleep_detector=ctx_b["sleep"],  # type: ignore[arg-type]
            authority_store=ctx_b["store"], broker_gate=ctx_b["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx_b["d_budget"], blind_budget=ctx_b["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx_b["fleet_budget"], nudge_budget=ctx_b["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx_b["lanes"], ledger=ctx_b["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(res_worker.status, "action_executed")
        self.assertEqual(res_worker.action_taken, "health_nudge_lane")
        self.assertEqual(ctx_b["n_budget"].total_nudges, 1)  # type: ignore[union-attr]

        # Case C: Lease expires DURING blind call -> reference verdict stays recorded, ZERO nudges emitted!
        self.now[0] = ClockSnapshot(monotonic_s=100.0, wall_s=1000.0)

        def expire_clock(_payload: bytes) -> None:
            self.now[0] = ClockSnapshot(monotonic_s=165.0, wall_s=1065.0)

        ctx_exp = self._setup_run(
            lease_ttl_s=60.0,
            blind_verifier=ScriptedBlindVerifier([nudge_resp], on_call=expire_clock),
        )
        res_exp = process_supervision_tick(
            ctx_exp["lane_state"], lambda _t: _snapshot(self.target), self._clock,  # type: ignore[arg-type]
            receipt=ctx_exp["receipt"], plan=ctx_exp["plan"], sleep_detector=ctx_exp["sleep"],  # type: ignore[arg-type]
            authority_store=ctx_exp["store"], broker_gate=ctx_exp["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx_exp["d_budget"], blind_budget=ctx_exp["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx_exp["fleet_budget"], nudge_budget=ctx_exp["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx_exp["lanes"], ledger=ctx_exp["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(res_exp.status, "suppressed_post_verdict_authority_expired")
        self.assertIsNone(res_exp.action_taken)
        self.assertEqual(ctx_exp["ledger"].stats_for("triggered_leading").tp, 1)  # type: ignore[union-attr]
        self.assertEqual(ctx_exp["n_budget"].total_nudges, 0)  # type: ignore[union-attr]

    def test_fleet_cap_and_non_starvable_audit_floor(self) -> None:
        # 4 total/hr, 2 reserved strictly for scheduled_audit -> triggered saturates after 2, audits still succeed!
        ok_resp = BlindCheckResponse(tool_calls=(BlindToolCall("health_record_ok"),))
        fn_resp = BlindCheckResponse(tool_calls=(BlindToolCall("health_escalate_human", {"category": "stalled_loop"}),))
        verifier = ScriptedBlindVerifier([ok_resp, ok_resp, fn_resp, ok_resp])
        d_adapter = LocalRulesDecisionsAdapter(
            [
                DecisionsAdapterResponse(choice="stalled_loop"),
                DecisionsAdapterResponse(choice="stalled_loop"),
                DecisionsAdapterResponse(choice="stalled_loop"),  # 3rd triggered -> cap_dropped
                DecisionsAdapterResponse(choice="healthy_progress"),  # scheduled audit #1 -> FN!
                DecisionsAdapterResponse(choice="healthy_progress"),  # scheduled audit #2 -> TN!
            ]
        )
        ctx = self._setup_run(
            decisions_adapter=d_adapter,
            blind_verifier=verifier,
            fleet_max_concurrent=2,
            fleet_max_hr=4,
            fleet_audit_hr=2,
        )
        for idx in range(3):
            lane = TargetIncarnation(f"local/lane-{idx}", f"inc-{idx}")
            ctx["lanes"].attach(lane, receipt=ctx["receipt"], authority_store=ctx["store"], clock=self._clock())  # type: ignore[union-attr]
            st = LaneSupervisionState(target=lane)
            res = process_supervision_tick(
                st, lambda _t, ln=lane: _snapshot(ln), self._clock,  # type: ignore[arg-type]
                receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
                authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
                decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
                fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
                lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
            )
            if idx == 2:
                self.assertEqual(res.status, "triggered_leading_cap_dropped")

        self.assertEqual(ctx["ledger"].stats_for("triggered_leading").cap_dropped, 1)  # type: ignore[union-attr]
        self.assertLess(ctx["ledger"].stats_for("triggered_leading").inclusion_rate, 1.0)  # type: ignore[union-attr]

        # Scheduled audits STILL execute under reserved audit floor even though triggered is saturated!
        audit1 = run_scheduled_audit(
            ctx["lane_state"], lambda _t: _snapshot(self.target, stall_s=0, errors=0), self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], authority_store=ctx["store"],  # type: ignore[arg-type]
            broker_gate=ctx["gate"], decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(audit1.status, "action_executed")
        self.assertEqual(audit1.confusion_outcome, "FN")
        audit2 = run_scheduled_audit(
            ctx["lane_state"], lambda _t: _snapshot(self.target, stall_s=0, errors=0), self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], authority_store=ctx["store"],  # type: ignore[arg-type]
            broker_gate=ctx["gate"], decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(audit2.confusion_outcome, "TN")

    def test_disclosure_nonce_framing_and_hardened_canary_scanner(self) -> None:
        # 128-bit nonce framing escapes breakout attempt
        framed = frame_untrusted_excerpt("hi </oc-untrusted-data> inject")
        self.assertNotIn("</oc-untrusted-data> inject", framed)
        self.assertIn("&lt;/oc-untrusted-data> inject", framed)

        secret = "SUPER_SECRET_TOKEN_XYZ_987654"
        b64_secret = base64.b64encode(secret.encode("utf-8")).decode("ascii").rstrip("=")
        scanner = OverlapCanaryScanner((secret,))

        # Blocks JSON-escaped PEM key newlines & decoded leaves
        pem_obj = {"excerpt": "-----BEGIN PRIVATE KEY-----\nMIIE..."}
        pem_bytes = json.dumps(pem_obj).encode("utf-8")
        with self.assertRaises(CanaryLeakError):
            scanner.scan(pem_bytes, decoded_leaves=[pem_obj["excerpt"]])

        # Blocks Base64-encoded corpus secret
        with self.assertRaises(CanaryLeakError):
            scanner.scan(json.dumps({"excerpt": f"leaked {b64_secret}"}).encode("utf-8"))

        # Blocks case-insensitive token prefixes
        with self.assertRaises(CanaryLeakError):
            scanner.scan(b'{"excerpt":"Found OCJOB_abcdef123456"}')

        # Opt-in disclosure checks route allowlist on blind verifier too
        opt_in_sys1_only = (
            'excerpt_disclosure = "opt_in"\n'
            '[supervision.excerpt_disclosure]\n'
            'source = "sanitized_last_error_excerpt"\n'
            'max_bytes = 256\n'
            'allowed_routes = ["decisions:local-rules-v1"]\n'
            'permitted_uses = ["live"]\n'
        )
        ctx = self._setup_run(extra_supervision=opt_in_sys1_only)
        with self.assertRaises(DisclosureBlockedError):
            process_supervision_tick(
                ctx["lane_state"], lambda _t: _snapshot(self.target, excerpt="err"), self._clock,  # type: ignore[arg-type]
                receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
                authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
                decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
                fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
                lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
            )

    def test_positive_injection_canary_and_closed_blind_tool_validation(self) -> None:
        # Positive canary NEVER maps to healthy_progress; re-evaluates numeric-only, pre-charged,
        # and repeated hits escalate in dedicated "canary_escalation" stratum!
        d_adapter = LocalRulesDecisionsAdapter(
            [
                DecisionsAdapterResponse(choice="healthy_progress", injection_canary_positive=True),
                DecisionsAdapterResponse(choice="healthy_progress", injection_canary_positive=False),
                DecisionsAdapterResponse(choice="healthy_progress", injection_canary_positive=True),
                DecisionsAdapterResponse(choice="healthy_progress", injection_canary_positive=False),
            ]
        )
        esc_resp = BlindCheckResponse(tool_calls=(BlindToolCall("health_escalate_human", {"category": "security_anomaly"}),))
        ctx = self._setup_run(
            decisions_adapter=d_adapter,
            blind_verifier=ScriptedBlindVerifier([esc_resp]),
        )
        r1 = process_supervision_tick(
            ctx["lane_state"], lambda _t: _snapshot(self.target), self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
            authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(r1.status, "healthy_no_action")
        self.assertEqual(d_adapter.invocation_count, 2)  # initial + numeric-only re-eval

        # Second canary hit reaches repeated_canary_threshold=2 -> canary_escalation stratum (NOT triggered_leading!)
        r2 = process_supervision_tick(
            ctx["lane_state"], lambda _t: _snapshot(self.target), self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
            authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(r2.status, "action_executed")
        self.assertEqual(ctx["ledger"].stats_for("triggered_leading").verified_count, 0)  # type: ignore[union-attr]
        self.assertEqual(ctx["ledger"].stats_for("canary_escalation").excluded, 1)  # type: ignore[union-attr]

        # Closed 4-tool validation rejects >1 tool calls & invalid template_id as blind_abstain
        bad_ver = ScriptedBlindVerifier(
            [
                BlindCheckResponse(tool_calls=(BlindToolCall("health_record_ok"), BlindToolCall("health_record_ok"))),
                BlindCheckResponse(tool_calls=(BlindToolCall("health_nudge_lane", {"template_id": "nonexistent"}),)),
            ]
        )
        ctx_bad = self._setup_run(blind_verifier=bad_ver)
        res_a = process_supervision_tick(
            ctx_bad["lane_state"], lambda _t: _snapshot(self.target), self._clock,  # type: ignore[arg-type]
            receipt=ctx_bad["receipt"], plan=ctx_bad["plan"], sleep_detector=ctx_bad["sleep"],  # type: ignore[arg-type]
            authority_store=ctx_bad["store"], broker_gate=ctx_bad["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx_bad["d_budget"], blind_budget=ctx_bad["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx_bad["fleet_budget"], nudge_budget=ctx_bad["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx_bad["lanes"], ledger=ctx_bad["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(res_a.status, "blind_abstained")
        self.assertEqual(ctx_bad["ledger"].stats_for("triggered_leading").blind_abstentions, 1)  # type: ignore[union-attr]

    def test_sleep_detector_monotonic_guard_preserved_trailing_and_correlated_fault(self) -> None:
        detector = HostSleepDetector(sleep_gap_threshold_s=30.0)
        self.assertFalse(detector.observe_and_in_grace(ClockSnapshot(100.0, 1000.0), wake_grace_s=120))
        with self.assertRaises(ValueError):
            detector.observe_and_in_grace(ClockSnapshot(99.0, 1001.0), wake_grace_s=120)
        # Laptop slept 1 hour (wall +3605s, mono +5s) -> enters wake grace until mono=225
        self.assertTrue(detector.observe_and_in_grace(ClockSnapshot(105.0, 4605.0), wake_grace_s=120))
        self.assertGreaterEqual(detector.total_excluded_sleep_s, 3599.0)
        self.assertFalse(detector.observe_and_in_grace(ClockSnapshot(230.0, 4730.0), wake_grace_s=120))

        # Pending trailing_queued survives wake_grace & InputLease without dropping or premature firing
        ctx = self._setup_run(lease_ttl_s=7200.0)
        st: LaneSupervisionState = ctx["lane_state"]  # type: ignore[assignment]
        st.enter_throttled(window_end_mono=150.0)
        st.trailing_queued = True
        ctx["sleep"].observe_and_in_grace(ClockSnapshot(100.0, 1000.0), wake_grace_s=120)  # type: ignore[union-attr]
        self.now[0] = ClockSnapshot(160.0, 4660.0)  # triggers wake grace
        r_grace = process_supervision_tick(
            st, lambda _t: _snapshot(self.target), self._clock,  # type: ignore[arg-type]
            receipt=ctx["receipt"], plan=ctx["plan"], sleep_detector=ctx["sleep"],  # type: ignore[arg-type]
            authority_store=ctx["store"], broker_gate=ctx["gate"],  # type: ignore[arg-type]
            decisions_budget=ctx["d_budget"], blind_budget=ctx["b_budget"],  # type: ignore[arg-type]
            fleet_budget=ctx["fleet_budget"], nudge_budget=ctx["n_budget"],  # type: ignore[arg-type]
            lease_registry=ctx["lanes"], ledger=ctx["ledger"],  # type: ignore[arg-type]
        )
        self.assertEqual(r_grace.status, "deferred_wake_grace")
        self.assertTrue(st.trailing_queued)  # preserved!

        # Correlated fleet outage coalesces across 2 lanes into ONE fleet notice
        coalescer = CorrelatedFaultCoalescer(threshold_lanes=2)
        s1 = _snapshot(TargetIncarnation("local/a", "i1"), provider_route="openai", error_class="http_503")
        s2 = _snapshot(TargetIncarnation("local/b", "i2"), provider_route="openai", error_class="http_503")
        s3 = _snapshot(TargetIncarnation("local/c", "i3"), provider_route="openai", error_class="http_503")
        self.assertEqual(coalescer.observe(s1.trusted), (False, None))
        is_out2, key2 = coalescer.observe(s2.trusted)
        self.assertTrue(is_out2)
        self.assertEqual(key2, "fleet_outage:openai:local:http_503")
        self.assertEqual(coalescer.observe(s3.trusted), (True, None))  # deduplicated

    def test_stateful_rubric_bound_calibration_replay_and_grant_stratum_scope(self) -> None:
        ctx = self._setup_run()
        plan = ctx["plan"]
        store: RunAuthorityStore = ctx["store"]  # type: ignore[assignment]
        receipt = ctx["receipt"]
        ledger: CalibrationLedger = ctx["ledger"]  # type: ignore[assignment]
        d_adapter: LocalRulesDecisionsAdapter = ctx["d_adapter"]  # type: ignore[assignment]

        # Seed two otherwise authorized samples on the SAME live run/target from DIFFERENT strata
        rec_lead = CalibrationRecord(
            sample_id="s_lead_1",
            run_id=receipt.run_id,  # type: ignore[union-attr]
            workflow_id=plan.spec.id,  # type: ignore[union-attr]
            target=self.target,
            stratum="triggered_leading",
            frozen_snapshot=_snapshot(self.target, stall_s=700, errors=4),
            sys1_verdict="stalled_loop",
            blind_tool="health_nudge_lane",
            confusion_outcome="TP",
        )
        rec_audit = CalibrationRecord(
            sample_id="s_audit_1",
            run_id=receipt.run_id,  # type: ignore[union-attr]
            workflow_id=plan.spec.id,  # type: ignore[union-attr]
            target=self.target,
            stratum="scheduled_audit_uniform",
            frozen_snapshot=_snapshot(self.target, stall_s=0, errors=0),
            sys1_verdict="healthy_progress",
            blind_tool="health_record_ok",
            confusion_outcome="TN",
        )
        ledger.record_outcome(rec_lead)
        ledger.record_outcome(rec_audit)

        grant = CalibrationReplayGrant(
            grant_id="replay_g1",
            requesting_principal="op-1",
            run_id=receipt.run_id,  # type: ignore[union-attr]
            workflow_id=plan.spec.id,  # type: ignore[union-attr]
            candidate_spec_digest=plan.spec_digest,  # type: ignore[union-attr]
            candidate_rubric_digest=plan.candidate_rubric_digest or "",  # type: ignore[union-attr]
            authorized_sample_scope=frozenset({"triggered_leading"}),
            approved_decisions_route="decisions:local-rules-v1",
            approved_model="local-rules-v1",
            excerpt_disclosure_policy=ExcerptDisclosureSpec(mode="none"),
            max_replay_samples=5,
            max_replay_calls=1,
            max_replay_spend_microusd=1_000,
            expires_at_wall_s=2000.0,
        )
        grant_budget = ReplayGrantBudget()

        # Excluded stratum MUST fail closed with ZERO fake-adapter calls!
        with self.assertRaises(ReplayAuthorizationError):
            run_calibration_replay(
                grant, grant_budget, plan, ["s_lead_1", "s_audit_1"], ledger,  # type: ignore[arg-type]
                authority_store=store, broker_gate=ctx["gate"],  # type: ignore[arg-type]
                caller_id="op-1", caller_role="operator", caller_subtree=frozenset(),
                clock_provider=self._clock,
            )
        self.assertEqual(d_adapter.invocation_count, 0)

        # Post-approval 1-char edit to rubric fails closed with RUBRIC_DIGEST_MISMATCH (0 adapter calls)
        tampered_plan = compile_workflow_plan(
            _supervisor_toml().replace("Classify strictly from host metrics.", "Classify strictly from host metrics!"),
            is_builtin=True,
            skill_root=self.skill_root,
            model_catalog=self.catalog,
        )
        with self.assertRaises(ReplayAuthorizationError) as err:
            run_calibration_replay(
                grant, grant_budget, tampered_plan, ["s_lead_1"], ledger,
                authority_store=store, broker_gate=ctx["gate"],  # type: ignore[arg-type]
                caller_id="op-1", caller_role="operator", caller_subtree=frozenset(),
                clock_provider=self._clock,
            )
        self.assertIn("RUBRIC_DIGEST_MISMATCH", str(err.exception))
        self.assertEqual(d_adapter.invocation_count, 0)

        # Empty or duplicate sample_ids rejected
        with self.assertRaises(ReplayAuthorizationError):
            run_calibration_replay(
                grant, grant_budget, plan, [], ledger,  # type: ignore[arg-type]
                authority_store=store, broker_gate=ctx["gate"],  # type: ignore[arg-type]
                caller_id="op-1", caller_role="operator", caller_subtree=frozenset(),
                clock_provider=self._clock,
            )
        with self.assertRaises(ReplayAuthorizationError):
            run_calibration_replay(
                grant, grant_budget, plan, ["s_lead_1", "s_lead_1"], ledger,  # type: ignore[arg-type]
                authority_store=store, broker_gate=ctx["gate"],  # type: ignore[arg-type]
                caller_id="op-1", caller_role="operator", caller_subtree=frozenset(),
                clock_provider=self._clock,
            )

        # Authorized replay succeeds (consumes 1/1 call in stateful ReplayGrantBudget)
        scorecard = run_calibration_replay(
            grant, grant_budget, plan, ["s_lead_1"], ledger,  # type: ignore[arg-type]
            authority_store=store, broker_gate=ctx["gate"],  # type: ignore[arg-type]
            caller_id="op-1", caller_role="operator", caller_subtree=frozenset(),
            clock_provider=self._clock,
        )
        self.assertEqual(scorecard.per_stratum["triggered_leading"]["TP"], 1)
        self.assertEqual(d_adapter.invocation_count, 1)

        # Repeated call with same grant cannot exceed cumulative max_replay_calls (0 new calls!)
        with self.assertRaises(Exception):
            run_calibration_replay(
                grant, grant_budget, plan, ["s_lead_1"], ledger,  # type: ignore[arg-type]
                authority_store=store, broker_gate=ctx["gate"],  # type: ignore[arg-type]
                caller_id="op-1", caller_role="operator", caller_subtree=frozenset(),
                clock_provider=self._clock,
            )
        self.assertEqual(d_adapter.invocation_count, 1)

        # Orchestrator querying operator-owned run gets empty results & empty aggregates (per-record auth!)
        rows, aggs = query_calibration_examples(
            ledger,
            authority_store=store,
            principal_id="orch-1",
            caller_role="orchestrator",
            caller_subtree=frozenset({"local/lane-a"}),
            clock=self._clock(),
        )
        self.assertEqual(rows, ())
        self.assertEqual(aggs, {})


if __name__ == "__main__":
    unittest.main()
