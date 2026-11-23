"""Offline qualification and adversarial test suite for PRD N durable workflow restart kernel."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
import unittest
from unittest import mock

_RESTART_DIR = Path(__file__).resolve().parent
_SPIKE_N_DIR = _RESTART_DIR.parent
_SPIKE_L_DIR = _SPIKE_N_DIR.parent / "l"
for _import_dir in (str(_RESTART_DIR), str(_SPIKE_N_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_broker_common import _UMASK_LOCK  # noqa: E402
from oc_restart_contract import (  # noqa: E402
    ERR_AUTH_REVOKED_PRE_ENTRY,
    ERR_LOCK_HELD,
    ERR_MALFORMED_STORAGE,
    ERR_MAX_EVENTS,
    ERR_META_MISSING_NONEMPTY,
    ERR_OP_DEADLINE,
    ERR_PLAN_GRAPH_UNSUPPORTED,
    ERR_PROPOSED_STEPS_MISMATCH,
    ERR_UNEXPECTED_SCHEMA,
    EVENT_GENESIS_HASH,
    MAX_INT64,
    CompleteStepRequest,
    CrashPoint,
    CreateRunRequest,
    EffectTrackerReceipt,
    EventType,
    FailStepRequest,
    IdempotencyConflictError,
    InvalidStepTransitionError,
    JournalIntegrityError,
    JournalEvent,
    ReconcileResolution,
    ReconcileStepRequest,
    ReconciliationEvidenceError,
    ReplayMismatchError,
    RestartPolicyError,
    RestartStorageError,
    RestartValidationError,
    RunStatus,
    SimulatedSupervisorCrash,
    StaleEpochError,
    StepLeaseToken,
    StepSpec,
    StepStatus,
    SyntheticEffectTracker,
    WorkerStepResult,
    compute_event_hash,
    compute_reconciliation_evidence_digest,
    compute_tracker_receipt_digest,
    derive_steps_from_plan,
    reduce_event_log,
)
from oc_restart_db import (  # noqa: E402
    DB_FILENAME,
    LOCK_FILENAME,
    open_sqlite_bounded,
)
from oc_restart_store import (  # noqa: E402
    DurableWorkflowSupervisor,
    WorkflowRestartJournal,
    verify_journal_replay_readonly,
)
from oc_workflow_plan import (  # noqa: E402
    AdmissionDeniedError,
    AdmissionReceipt,
    AuthorityError,
    ClockSnapshot,
    CompiledWorkflowPlan,
    ModelCatalog,
    RunAuthorityStore,
    compile_workflow_plan,
    evaluate_admission,
)
from oc_workflow_supervision import ProgressFingerprint  # noqa: E402

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64
_DIGEST_E = "e" * 64
_DIGEST_1 = "1" * 64
_DIGEST_2 = "2" * 64

_OBSERVE_ONLY_TOML = """
schema_version = 1
kind = "workflow@1"
id = "user/observe-restart-test"
mode = "statechart"
description = "Observe-only restart qualification workflow."
autonomy = "observe_only"
orchestrator_skill = "user/restart-guide"
survives_restart = true

[scope]
target_selector = "bound_targets"
bound_targets = ["local/alpha"]
allow_remote_workers = false

[limits]
tick_interval_s = 60
throttle_period_s = 300
fleet_max_concurrent_checks = 1
fleet_max_checks_per_hour = 4
fleet_audit_checks_per_hour = 1
max_nudges_per_target_per_hour = 0
min_nudge_interval_s = 300
max_total_nudges_per_run = 0
max_decisions_calls_per_hour = 0
max_decisions_spend_usd = 0.0
max_blind_check_spend_usd = 0.0
max_open_inbox_items = 4
defer_nudge_during_human_lease = true
wake_grace_after_host_sleep_s = 120

[[states]]
name = "collect"
shape = "observe"
effects = ["read_metrics"]

[[states]]
name = "project"
shape = "observe"
effects = ["update_health_projection"]

[[transitions]]
src = "collect"
dst = "project"
"""

_ACTIVE_STATECHART_TOML = """
schema_version = 1
kind = "workflow@1"
id = "user/active-restart-test"
mode = "statechart"
description = "Active restart qualification workflow with pure and side-effecting steps."
autonomy = "nudge_bounded"
orchestrator_skill = "user/restart-guide"
survives_restart = true

[scope]
target_selector = "bound_targets"
bound_targets = ["local/alpha"]
allow_remote_workers = false

[limits]
tick_interval_s = 60
throttle_period_s = 300
fleet_max_concurrent_checks = 1
fleet_max_checks_per_hour = 4
fleet_audit_checks_per_hour = 1
max_nudges_per_target_per_hour = 2
min_nudge_interval_s = 60
max_total_nudges_per_run = 10
max_decisions_calls_per_hour = 0
max_decisions_spend_usd = 0.0
max_blind_check_spend_usd = 0.0
max_open_inbox_items = 4
defer_nudge_during_human_lease = true
wake_grace_after_host_sleep_s = 120

[[states]]
name = "scan"
shape = "observe"
effects = ["read_metrics"]

[[states]]
name = "apply_patch"
shape = "deterministic"
effects = ["stage_patch"]

[[states]]
name = "verify"
shape = "observe"
effects = ["update_health_projection"]

[[transitions]]
src = "scan"
dst = "apply_patch"

[[transitions]]
src = "apply_patch"
dst = "verify"
"""

_CYCLIC_STATECHART_TOML = """
schema_version = 1
kind = "workflow@1"
id = "user/cyclic-restart-test"
mode = "statechart"
description = "Cyclic workflow rejected by acyclic restart fixture."
autonomy = "observe_only"
orchestrator_skill = "user/restart-guide"
survives_restart = true

[scope]
target_selector = "bound_targets"
bound_targets = ["local/alpha"]
allow_remote_workers = false

[limits]
tick_interval_s = 60
throttle_period_s = 300
fleet_max_concurrent_checks = 1
fleet_max_checks_per_hour = 4
fleet_audit_checks_per_hour = 1
max_nudges_per_target_per_hour = 0
min_nudge_interval_s = 300
max_total_nudges_per_run = 0
max_decisions_calls_per_hour = 0
max_decisions_spend_usd = 0.0
max_blind_check_spend_usd = 0.0
max_open_inbox_items = 4
defer_nudge_during_human_lease = true
wake_grace_after_host_sleep_s = 120

[[states]]
name = "step_a"
shape = "observe"
effects = ["read_metrics"]

[[states]]
name = "step_b"
shape = "observe"
effects = ["update_health_projection"]

[[transitions]]
src = "step_a"
dst = "step_b"

[[transitions]]
src = "step_b"
dst = "step_a"
"""


class _ManualClock:
    def __init__(self, wall_s: float = 1_700_000_000.0, mono_s: float = 100.0) -> None:
        self.wall_s = wall_s
        self.mono_s = mono_s

    def now(self) -> ClockSnapshot:
        return ClockSnapshot(monotonic_s=self.mono_s, wall_s=self.wall_s)

    def advance(self, delta_s: float = 1.0) -> ClockSnapshot:
        self.wall_s += delta_s
        self.mono_s += delta_s
        return self.now()


class _RestartFixtureBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="oc_wf_restart_")
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.state_dir = self.root / "state"
        self.state_dir.mkdir(mode=0o700)
        os.chmod(self.state_dir, 0o700)
        self.sandbox_root = self.root / "sandbox_home"
        self.sandbox_root.mkdir(mode=0o700)
        self.skill_root = self.root / "skills"
        self._setup_skill_source()
        self.clock = _ManualClock()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _setup_skill_source(self) -> None:
        user_dir = self.skill_root / "user" / "restart-guide"
        user_dir.mkdir(parents=True, mode=0o700)
        for p in (self.skill_root, self.skill_root / "user", user_dir):
            os.chmod(p, 0o700)
        skill_file = user_dir / "SKILL.md"
        skill_file.write_text("# Restart Qualification Guide\n", encoding="utf-8")
        os.chmod(skill_file, 0o600)

    def _compile_and_admit(
        self,
        raw_toml: str,
        *,
        authority_store: RunAuthorityStore,
        caller_role: str = "operator",
        ttl_s: float = 3600.0,
    ) -> tuple[CompiledWorkflowPlan, AdmissionReceipt]:
        plan = compile_workflow_plan(
            raw_toml,
            is_builtin=False,
            skill_root=self.skill_root,
            model_catalog=ModelCatalog(),
            forbidden_sandbox_roots=(self.sandbox_root,),
        )
        receipt = evaluate_admission(
            plan,
            authority_store,
            principal_id="op_1" if caller_role == "operator" else "orch_1",
            caller_role="operator" if caller_role == "operator" else "orchestrator",
            caller_subtree=frozenset({"local/alpha"}),
            active_orchestrator_runs=0,
            max_active_orchestrator_runs=4,
            clock=self.clock.now(),
            operator_lease_ttl_s=ttl_s,
            auto_observer_ttl_s=ttl_s,
        )
        return plan, receipt

    def _make_run_request(
        self,
        run_id: str,
        steps: tuple[StepSpec, ...],
        *,
        clock: ClockSnapshot | None = None,
    ) -> CreateRunRequest:
        return CreateRunRequest(
            run_id=run_id,
            workflow_id="user/synthetic-wf",
            spec_digest=_DIGEST_1,
            workflow_plan_digest=_DIGEST_2,
            grant_generation=1,
            steps=steps,
            clock=clock or self.clock.advance(),
        )

    def _tamper_db(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        conn = sqlite3.connect(str(self.state_dir / DB_FILENAME))
        try:
            conn.execute("PRAGMA ignore_check_constraints = ON")
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()


class TestPlanBindingAndContractValidation(_RestartFixtureBase):
    def test_canonical_plan_derivation_and_tampered_or_modified_steps_rejected(self) -> None:
        auth = RunAuthorityStore()
        tracker = SyntheticEffectTracker()
        sup, report = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            authority_store=auth,
            sandbox_root=self.sandbox_root,
        )
        try:
            self.assertEqual(report.supervisor_epoch, 1)
            obs_plan, obs_receipt = self._compile_and_admit(
                _OBSERVE_ONLY_TOML, authority_store=auth, caller_role="orchestrator"
            )
            head_before = sup.journal.get_meta()

            # 1. Tampered CompiledWorkflowPlan digest fails closed with zero writes.
            tampered_plan = CompiledWorkflowPlan(
                spec=obs_plan.spec,
                reachable_effects=obs_plan.reachable_effects,
                skill_namespace=obs_plan.skill_namespace,
                skill_slug=obs_plan.skill_slug,
                skill_bytes=obs_plan.skill_bytes,
                skill_sha256=obs_plan.skill_sha256,
                blind_route=obs_plan.blind_route,
                decisions_call_cost_microusd=obs_plan.decisions_call_cost_microusd,
                blind_call_cost_microusd=obs_plan.blind_call_cost_microusd,
                workflow_plan_digest=_DIGEST_E,
            )
            now_1 = self.clock.advance()
            with self.assertRaises(AuthorityError):
                sup.create_run_from_plan(
                    plan=tampered_plan, receipt=obs_receipt, clock=now_1
                )
            self.assertEqual(sup.journal.get_meta().last_event_seq, head_before.last_event_seq)

            # 2. Unauthorized effect against observe_only plan fails with zero journal writes.
            bad_effect_steps = (
                StepSpec(
                    step_id="collect",
                    state_name="collect",
                    effect_kind="launch_sandbox",
                    side_effecting=True,
                ),
            )
            now_2 = self.clock.advance()
            with self.assertRaises(RestartPolicyError) as ctx:
                sup.create_run_from_plan(
                    plan=obs_plan,
                    receipt=obs_receipt,
                    clock=now_2,
                    proposed_steps=bad_effect_steps,
                )
            self.assertIn(ERR_PROPOSED_STEPS_MISMATCH, str(ctx.exception))
            self.assertEqual(sup.journal.get_meta().head_hash, head_before.head_hash)

            # 3. Altered dependency, altered max_attempts, or duplicated step rejected (zero writes).
            canonical = derive_steps_from_plan(obs_plan)
            changed_dep = (
                canonical[0],
                StepSpec(
                    step_id=canonical[1].step_id,
                    state_name=canonical[1].state_name,
                    effect_kind=canonical[1].effect_kind,
                    side_effecting=canonical[1].side_effecting,
                    depends_on=(),
                    max_attempts=canonical[1].max_attempts,
                ),
            )
            now_3 = self.clock.advance()
            with self.assertRaises(RestartPolicyError):
                sup.create_run_from_plan(
                    plan=obs_plan,
                    receipt=obs_receipt,
                    clock=now_3,
                    proposed_steps=changed_dep,
                )
            dup_step = (
                *canonical,
                StepSpec(
                    step_id="collect_copy",
                    state_name="collect",
                    effect_kind="read_metrics",
                    side_effecting=False,
                ),
            )
            now_4 = self.clock.advance()
            with self.assertRaises(RestartPolicyError):
                sup.create_run_from_plan(
                    plan=obs_plan,
                    receipt=obs_receipt,
                    clock=now_4,
                    proposed_steps=dup_step,
                )
            self.assertEqual(sup.journal.get_meta().last_event_seq, head_before.last_event_seq)

            # 4. Exact canonical graph succeeds and binds digests durably.
            run = sup.create_run_from_plan(
                plan=obs_plan,
                receipt=obs_receipt,
                clock=self.clock.advance(),
                proposed_steps=canonical,
            )
            self.assertEqual(run.workflow_plan_digest, obs_plan.workflow_plan_digest)
            self.assertEqual(run.spec_digest, obs_plan.spec_digest)

            # 5. Cyclic plan graph fails closed with ERR_PLAN_GRAPH_UNSUPPORTED.
            cyc_plan, cyc_receipt = self._compile_and_admit(
                _CYCLIC_STATECHART_TOML, authority_store=auth
            )
            now_5 = self.clock.advance()
            with self.assertRaises(RestartPolicyError) as cyc_ctx:
                sup.create_run_from_plan(
                    plan=cyc_plan, receipt=cyc_receipt, clock=now_5
                )
            self.assertIn(ERR_PLAN_GRAPH_UNSUPPORTED, str(cyc_ctx.exception))
        finally:
            sup.close_clean(clock=self.clock.advance())

        replayed = verify_journal_replay_readonly(
            self.state_dir, sandbox_root=self.sandbox_root
        )
        self.assertEqual(replayed.dirty_shutdown, 0)

    def test_contract_validation_rejects_hostile_inputs(self) -> None:
        with self.assertRaises(RestartValidationError):
            StepSpec("s1", "s1", "launch_sandbox", side_effecting=False)
        with self.assertRaises(RestartValidationError):
            StepSpec("s1\x00", "s1", "read_metrics", side_effecting=False)
        with self.assertRaises(RestartValidationError):
            StepSpec("s1\u202e", "s1", "read_metrics", side_effecting=False)
        with self.assertRaises(RestartValidationError):
            StepSpec("s1", "s1", "read_metrics", side_effecting=False, max_attempts=True)  # type: ignore[arg-type]

        cyclic_steps = (
            StepSpec("a", "a", "read_metrics", False, depends_on=("b",)),
            StepSpec("b", "b", "read_metrics", False, depends_on=("a",)),
        )
        with self.assertRaises(RestartValidationError):
            self._make_run_request("run_cyc", cyclic_steps)

        dup_steps = (
            StepSpec("a", "a", "read_metrics", False),
            StepSpec("a", "a", "read_metrics", False),
        )
        with self.assertRaises(RestartValidationError):
            self._make_run_request("run_dup", dup_steps)

        neg_clock = ClockSnapshot(monotonic_s=-1.0, wall_s=10.0)
        valid_steps = (StepSpec("a", "a", "read_metrics", False),)
        with self.assertRaises(RestartValidationError):
            self._make_run_request("run_neg_clk", valid_steps, clock=neg_clock)

        overflow_clock = ClockSnapshot(monotonic_s=1.0, wall_s=float(MAX_INT64))
        with self.assertRaises(RestartValidationError):
            self._make_run_request("run_ovf_clk", valid_steps, clock=overflow_clock)

        huge_float_clock = ClockSnapshot(monotonic_s=1.0, wall_s=1e305)
        with self.assertRaises(RestartValidationError):
            self._make_run_request("run_huge_flt", valid_steps, clock=huge_float_clock)

        # ClockSnapshot rejects 10**400 (OverflowError on float conversion inside ClockSnapshot or clock_to_wall_us).
        huge_int_clock = ClockSnapshot.__new__(ClockSnapshot)
        object.__setattr__(huge_int_clock, "monotonic_s", 1.0)
        object.__setattr__(huge_int_clock, "wall_s", 10**400)
        with self.assertRaises(RestartValidationError):
            self._make_run_request("run_huge_int", valid_steps, clock=huge_int_clock)

        clk_now = self.clock.now()
        with self.assertRaises(RestartValidationError):
            CreateRunRequest(
                run_id="run_ovf_gen",
                workflow_id="user/w",
                spec_digest=_DIGEST_1,
                workflow_plan_digest=_DIGEST_2,
                grant_generation=MAX_INT64 + 1,
                steps=valid_steps,
                clock=clk_now,
            )


class TestLifecycleGateAndMidStepAuthority(_RestartFixtureBase):
    def _boot_active_plan(
        self, *, ttl_s: float = 3600.0
    ) -> tuple[
        RunAuthorityStore,
        SyntheticEffectTracker,
        DurableWorkflowSupervisor,
        CompiledWorkflowPlan,
        AdmissionReceipt,
    ]:
        auth = RunAuthorityStore()
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            authority_store=auth,
            sandbox_root=self.sandbox_root,
        )
        plan, receipt = self._compile_and_admit(
            _ACTIVE_STATECHART_TOML, authority_store=auth, ttl_s=ttl_s
        )
        sup.create_run_from_plan(plan=plan, receipt=receipt, clock=self.clock.advance())
        return auth, tracker, sup, plan, receipt

    def test_pre_entry_revocation_zero_worker_entries_and_settled_terminal(self) -> None:
        _, tracker, sup, _, receipt = self._boot_active_plan()
        try:
            def _worker(_tok: StepLeaseToken) -> WorkerStepResult:
                return WorkerStepResult(outcome="completed", output_digest=_DIGEST_A)

            def _revoke_before_entry(_tok: StepLeaseToken) -> None:
                sup.revoke_run_authority(receipt.run_id)

            with self.assertRaises(AuthorityError):
                sup.run_step_once(
                    receipt.run_id,
                    "scan",
                    worker_fn=_worker,
                    clock_provider=self.clock.advance,
                    on_after_lease_before_entry=_revoke_before_entry,
                )
            self.assertEqual(tracker.count(receipt.run_id, "scan"), 0)
            step = sup.journal.get_step(receipt.run_id, "scan")
            self.assertEqual(step.status, StepStatus.FAILED_TERMINAL)
            self.assertEqual(step.failure_reason, ERR_AUTH_REVOKED_PRE_ENTRY)
            self.assertEqual(sup.journal.get_run(receipt.run_id).status, RunStatus.FAILED)
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_pre_entry_cancel_pure_and_side_effecting_steps(self) -> None:
        # Part A: pure step cancelled pre-entry -> direct CANCELLED, 0 worker entries.
        _, tracker, sup, _, receipt = self._boot_active_plan()
        try:
            def _worker(_tok: StepLeaseToken) -> WorkerStepResult:
                return WorkerStepResult(outcome="completed", output_digest=_DIGEST_A)

            def _cancel_pure(_tok: StepLeaseToken) -> None:
                sup.cancel_run(
                    receipt.run_id, reason="operator_cancel_pure", clock=self.clock.advance()
                )

            with self.assertRaises(InvalidStepTransitionError):
                sup.run_step_once(
                    receipt.run_id,
                    "scan",
                    worker_fn=_worker,
                    clock_provider=self.clock.advance,
                    on_after_lease_before_entry=_cancel_pure,
                )
            self.assertEqual(tracker.count(receipt.run_id, "scan"), 0)
            self.assertEqual(sup.journal.get_step(receipt.run_id, "scan").status, StepStatus.CANCELLED)
            self.assertEqual(sup.journal.get_run(receipt.run_id).status, RunStatus.CANCELLED)
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

        # Part B: side-effecting step cancelled pre-entry -> preserved UNCERTAIN, then reconciled.
        auth2 = RunAuthorityStore()
        tracker2 = SyntheticEffectTracker()
        dir2 = self.root / "state_se_cancel"
        dir2.mkdir(mode=0o700)
        os.chmod(dir2, 0o700)
        sup2, _ = DurableWorkflowSupervisor.start_or_recover(
            dir2,
            clock=self.clock.now(),
            tracker=tracker2,
            authority_store=auth2,
            sandbox_root=self.sandbox_root,
        )
        try:
            plan2, rec2 = self._compile_and_admit(_ACTIVE_STATECHART_TOML, authority_store=auth2)
            sup2.create_run_from_plan(plan=plan2, receipt=rec2, clock=self.clock.advance())
            sup2.run_step_once(
                rec2.run_id,
                "scan",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                clock_provider=self.clock.advance,
            )

            def _cancel_se(_tok: StepLeaseToken) -> None:
                sup2.cancel_run(
                    rec2.run_id, reason="operator_cancel_se", clock=self.clock.advance()
                )

            def _worker_b(_t: StepLeaseToken) -> WorkerStepResult:
                return WorkerStepResult("completed", _DIGEST_B)

            with self.assertRaises(InvalidStepTransitionError):
                sup2.run_step_once(
                    rec2.run_id,
                    "apply_patch",
                    worker_fn=_worker_b,
                    clock_provider=self.clock.advance,
                    on_after_lease_before_entry=_cancel_se,
                )
            self.assertEqual(tracker2.count(rec2.run_id, "apply_patch"), 0)
            se_step = sup2.journal.get_step(rec2.run_id, "apply_patch")
            self.assertEqual(se_step.status, StepStatus.UNCERTAIN_NEEDS_RECONCILE)
            self.assertEqual(
                sup2.journal.get_run(rec2.run_id).status, RunStatus.PAUSED_NEEDS_RECONCILE
            )
            sup2.reconcile_step(
                ReconcileStepRequest(
                    run_id=rec2.run_id,
                    step_id="apply_patch",
                    expected_attempt_no=se_step.attempt_no,
                    expected_epoch=sup2.journal.current_epoch,
                    reconciliation_key="recon_cancel_se_1",
                    resolution=ReconcileResolution.CANCELLED,
                    output_digest=None,
                    evidence_digest=_DIGEST_E,
                    reason="confirmed_cancelled",
                    clock=self.clock.advance(),
                )
            )
            self.assertEqual(sup2.journal.get_run(rec2.run_id).status, RunStatus.CANCELLED)
        finally:
            sup2.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(dir2, sandbox_root=self.sandbox_root)

    def test_worker_wins_gate_mid_step_revocation_settles_without_stranding(self) -> None:
        _, tracker, sup, _, receipt = self._boot_active_plan()
        try:
            def _worker_revoke_mid_exec(_tok: StepLeaseToken) -> WorkerStepResult:
                sup.revoke_run_authority(receipt.run_id)
                return WorkerStepResult(outcome="completed", output_digest=_DIGEST_A)

            outcome = sup.run_step_once(
                receipt.run_id,
                "scan",
                worker_fn=_worker_revoke_mid_exec,
                clock_provider=self.clock.advance,
            )
            self.assertEqual(tracker.count(receipt.run_id, "scan"), 1)
            self.assertEqual(outcome.ack.status, StepStatus.COMPLETED.value)
            step = sup.journal.get_step(receipt.run_id, "scan")
            self.assertEqual(step.status, StepStatus.COMPLETED)
            self.assertEqual(step.output_digest, _DIGEST_A)

            # Subsequent dispatch on revoked run fails closed with AuthorityError.
            def _worker_next(_t: StepLeaseToken) -> WorkerStepResult:
                return WorkerStepResult("completed", _DIGEST_B)

            with self.assertRaises(AuthorityError):
                sup.run_step_once(
                    receipt.run_id,
                    "apply_patch",
                    worker_fn=_worker_next,
                    clock_provider=self.clock.advance,
                )
            self.assertEqual(tracker.count(receipt.run_id, "apply_patch"), 0)
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_lock_wait_expiry_on_both_requeue_paths_and_cross_restart_authority(self) -> None:
        # Path 1: pure retryable failure expires AFTER _lifecycle_gate during journal lock wait.
        _, _, sup, _, receipt = self._boot_active_plan(ttl_s=10.0)
        try:
            calls = {"n": 0}

            def _clock_expiring_on_commit() -> ClockSnapshot:
                calls["n"] += 1
                if calls["n"] >= 3:
                    return self.clock.advance(20.0)
                return self.clock.advance(1.0)

            outcome = sup.run_step_once(
                receipt.run_id,
                "scan",
                worker_fn=lambda _t: WorkerStepResult(
                    outcome="failed_retryable", reason="transient_io"
                ),
                clock_provider=_clock_expiring_on_commit,
            )
            self.assertEqual(outcome.ack.status, StepStatus.FAILED_TERMINAL.value)
            self.assertEqual(
                sup.journal.get_step(receipt.run_id, "scan").status,
                StepStatus.FAILED_TERMINAL,
            )
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

        # Path 2: reconcile_step(requeue_pending) expires during journal lock wait -> AuthorityError,
        # zero DB writes; terminal settlement succeeds even after cross-restart authority expiry!
        auth2 = RunAuthorityStore()
        tracker2 = SyntheticEffectTracker()
        dir2 = self.root / "state_requeue_exp"
        dir2.mkdir(mode=0o700)
        os.chmod(dir2, 0o700)
        sup2, _ = DurableWorkflowSupervisor.start_or_recover(
            dir2,
            clock=self.clock.now(),
            tracker=tracker2,
            authority_store=auth2,
            sandbox_root=self.sandbox_root,
        )
        plan2, rec2 = self._compile_and_admit(
            _ACTIVE_STATECHART_TOML, authority_store=auth2, ttl_s=10.0
        )
        sup2.create_run_from_plan(plan=plan2, receipt=rec2, clock=self.clock.advance(1.0))
        sup2.run_step_once(
            rec2.run_id,
            "scan",
            worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
            clock_provider=lambda: self.clock.advance(1.0),
        )
        captured: list[StepLeaseToken] = []

        def _worker_b2(_t: StepLeaseToken) -> WorkerStepResult:
            return WorkerStepResult("completed", _DIGEST_B)

        def _adv_1s() -> ClockSnapshot:
            return self.clock.advance(1.0)

        with self.assertRaises(SimulatedSupervisorCrash):
            sup2.run_step_once(
                rec2.run_id,
                "apply_patch",
                worker_fn=_worker_b2,
                clock_provider=_adv_1s,
                crash_point=CrashPoint.AFTER_LEASE_COMMIT_BEFORE_WORKER,
                captured_tokens=captured,
            )

        # Restart into epoch 2; authority is still active at boot, then expires on fresh clock inside BEGIN IMMEDIATE!
        sup3, _ = DurableWorkflowSupervisor.start_or_recover(
            dir2,
            clock=self.clock.advance(1.0),
            tracker=tracker2,
            authority_store=auth2,
            sandbox_root=self.sandbox_root,
        )
        try:
            no_eff = tracker2.issue_receipt(
                token=captured[0], current_epoch=sup3.journal.current_epoch
            )
            seq_before = sup3.journal.get_meta().last_event_seq
            requeue_req = ReconcileStepRequest(
                run_id=rec2.run_id,
                step_id="apply_patch",
                expected_attempt_no=1,
                expected_epoch=sup3.journal.current_epoch,
                reconciliation_key="recon_requeue_exp",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=no_eff.receipt_digest,
                reason="confirmed_not_executed",
                clock=self.clock.now(),
            )
            def _adv_50s() -> ClockSnapshot:
                return self.clock.advance(50.0)

            with self.assertRaises(AuthorityError):
                sup3.reconcile_step(
                    requeue_req,
                    tracker_receipt=no_eff,
                    clock_provider=_adv_50s,
                )
            self.assertEqual(sup3.journal.get_meta().last_event_seq, seq_before)
            self.assertEqual(
                sup3.journal.get_step(rec2.run_id, "apply_patch").status,
                StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            )

            # Terminal settlement still succeeds on expired/revoked run!
            settled = sup3.reconcile_step(
                ReconcileStepRequest(
                    run_id=rec2.run_id,
                    step_id="apply_patch",
                    expected_attempt_no=1,
                    expected_epoch=sup3.journal.current_epoch,
                    reconciliation_key="recon_term_after_exp",
                    resolution=ReconcileResolution.CANCELLED,
                    output_digest=None,
                    evidence_digest=no_eff.receipt_digest,
                    reason="settle_after_expiry",
                    clock=self.clock.advance(1.0),
                ),
                tracker_receipt=no_eff,
            )
            self.assertFalse(settled.duplicate)
            self.assertEqual(sup3.journal.get_run(rec2.run_id).status, RunStatus.CANCELLED)
        finally:
            sup3.close_clean(clock=self.clock.advance(1.0))
        verify_journal_replay_readonly(dir2, sandbox_root=self.sandbox_root)


class TestCrashRecoveryFencingAndIdempotency(_RestartFixtureBase):
    def test_crash_before_worker_pure_and_side_effecting_with_receipt_gating(self) -> None:
        tracker = SyntheticEffectTracker()
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.now(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        steps = (
            StepSpec("pure_step", "pure_step", "read_metrics", side_effecting=False),
            StepSpec(
                "se_step",
                "se_step",
                "nudge_sandbox",
                side_effecting=True,
                depends_on=("pure_step",),
            ),
        )
        sup1.journal.create_run(self._make_run_request("run_pre", steps))
        def _worker_a(_t: StepLeaseToken) -> WorkerStepResult:
            return WorkerStepResult("completed", _DIGEST_A)

        def _worker_b(_t: StepLeaseToken) -> WorkerStepResult:
            return WorkerStepResult("completed", _DIGEST_B)

        pure_tokens: list[StepLeaseToken] = []
        with self.assertRaises(SimulatedSupervisorCrash):
            sup1.run_step_once(
                "run_pre",
                "pure_step",
                worker_fn=_worker_a,
                clock_provider=self.clock.advance,
                crash_point=CrashPoint.AFTER_LEASE_COMMIT_BEFORE_WORKER,
                captured_tokens=pure_tokens,
            )
        self.assertEqual(tracker.count("run_pre", "pure_step"), 0)

        # Restart into epoch 2 -> pure_step auto-requeued, executes once, completes!
        sup2, rep2 = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.advance(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        self.assertEqual(rep2.supervisor_epoch, 2)
        self.assertEqual(rep2.fenced_requeued, (("run_pre", "pure_step", 1),))
        out_pure = sup2.run_step_once(
            "run_pre",
            "pure_step",
            worker_fn=_worker_a,
            clock_provider=self.clock.advance,
        )
        self.assertEqual(out_pure.token.attempt_no, 2)
        self.assertEqual(out_pure.token.lease_epoch, 2)
        self.assertEqual(tracker.count("run_pre", "pure_step"), 1)

        # Crash before worker on side-effecting step!
        se_tokens: list[StepLeaseToken] = []
        with self.assertRaises(SimulatedSupervisorCrash):
            sup2.run_step_once(
                "run_pre",
                "se_step",
                worker_fn=_worker_b,
                clock_provider=self.clock.advance,
                crash_point=CrashPoint.AFTER_LEASE_COMMIT_BEFORE_WORKER,
                captured_tokens=se_tokens,
            )
        self.assertEqual(tracker.count("run_pre", "se_step"), 0)

        sup3, rep3 = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.advance(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        try:
            self.assertEqual(rep3.supervisor_epoch, 3)
            self.assertEqual(rep3.fenced_uncertain, (("run_pre", "se_step", 1),))
            self.assertEqual(sup3.journal.list_eligible_steps("run_pre"), ())

            # Negative tracker receipt checks ALL fail closed leaving step UNCERTAIN:
            no_eff = tracker.issue_receipt(token=se_tokens[0], current_epoch=3)
            base_req = ReconcileStepRequest(
                run_id="run_pre",
                step_id="se_step",
                expected_attempt_no=1,
                expected_epoch=3,
                reconciliation_key="recon_se_req",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=no_eff.receipt_digest,
                reason="no_effect_proof",
                clock=self.clock.advance(),
            )
            # (a) Missing receipt
            with self.assertRaises(ReconciliationEvidenceError):
                sup3.reconcile_step(base_req, tracker_receipt=None)
            # (b) Mismatched attempt_no / coordinates
            wrong_coord_digest = compute_tracker_receipt_digest(
                run_id="run_pre",
                step_id="se_step",
                attempt_no=2,
                lease_epoch=se_tokens[0].lease_epoch,
                idempotency_key=se_tokens[0].idempotency_key,
                tracker_outcome="no_effect",
                attempt_fenced=True,
                output_digest=None,
            )
            wrong_coord = EffectTrackerReceipt(
                run_id="run_pre",
                step_id="se_step",
                attempt_no=2,
                lease_epoch=se_tokens[0].lease_epoch,
                idempotency_key=se_tokens[0].idempotency_key,
                tracker_outcome="no_effect",
                attempt_fenced=True,
                output_digest=None,
                receipt_digest=wrong_coord_digest,
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup3.reconcile_step(base_req, tracker_receipt=wrong_coord)
            # (c) Tampered digest
            tampered_rcpt = EffectTrackerReceipt(
                run_id=no_eff.run_id,
                step_id=no_eff.step_id,
                attempt_no=no_eff.attempt_no,
                lease_epoch=no_eff.lease_epoch,
                idempotency_key=no_eff.idempotency_key,
                tracker_outcome="no_effect",
                attempt_fenced=True,
                output_digest=None,
                receipt_digest=_DIGEST_E,
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup3.reconcile_step(base_req, tracker_receipt=tampered_rcpt)
            # (d) still_pending / unfenced receipt
            pending_digest = compute_tracker_receipt_digest(
                run_id=no_eff.run_id,
                step_id=no_eff.step_id,
                attempt_no=no_eff.attempt_no,
                lease_epoch=no_eff.lease_epoch,
                idempotency_key=no_eff.idempotency_key,
                tracker_outcome="still_pending",
                attempt_fenced=False,
                output_digest=None,
            )
            pending_rcpt = EffectTrackerReceipt(
                run_id=no_eff.run_id,
                step_id=no_eff.step_id,
                attempt_no=no_eff.attempt_no,
                lease_epoch=no_eff.lease_epoch,
                idempotency_key=no_eff.idempotency_key,
                tracker_outcome="still_pending",
                attempt_fenced=False,
                output_digest=None,
                receipt_digest=pending_digest,
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup3.reconcile_step(base_req, tracker_receipt=pending_rcpt)
            self.assertEqual(
                sup3.journal.get_step("run_pre", "se_step").status,
                StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            )

            # Conclusive fenced no_effect receipt permits requeue -> executes once & completes!
            sup3.reconcile_step(base_req, tracker_receipt=no_eff)
            out_se = sup3.run_step_once(
                "run_pre",
                "se_step",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                clock_provider=self.clock.advance,
            )
            self.assertEqual(out_se.token.attempt_no, 2)
            self.assertEqual(tracker.count("run_pre", "se_step"), 1)
            self.assertEqual(sup3.journal.get_run("run_pre").status, RunStatus.COMPLETED)
        finally:
            sup3.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_crash_after_side_effect_zero_double_execution_and_stale_epoch_fencing(self) -> None:
        tracker = SyntheticEffectTracker()
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.now(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        steps = (
            StepSpec("se_exec", "se_exec", "stage_patch", side_effecting=True),
            StepSpec(
                "after_se",
                "after_se",
                "read_metrics",
                side_effecting=False,
                depends_on=("se_exec",),
            ),
        )
        sup1.journal.create_run(self._make_run_request("run_se", steps))
        def _worker_se(_t: StepLeaseToken) -> WorkerStepResult:
            return WorkerStepResult("completed", _DIGEST_A)

        stale_tokens: list[StepLeaseToken] = []
        with self.assertRaises(SimulatedSupervisorCrash):
            sup1.run_step_once(
                "run_se",
                "se_exec",
                worker_fn=_worker_se,
                clock_provider=self.clock.advance,
                crash_point=CrashPoint.AFTER_WORKER_EXEC_BEFORE_COMPLETE_COMMIT,
                captured_tokens=stale_tokens,
            )
        self.assertEqual(tracker.count("run_se", "se_exec"), 1)

        sup2, rep2 = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.advance(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        try:
            self.assertEqual(rep2.supervisor_epoch, 2)
            self.assertEqual(sup2.journal.get_run("run_se").status, RunStatus.PAUSED_NEEDS_RECONCILE)
            self.assertEqual(sup2.journal.list_eligible_steps("run_se"), ())
            meta_before = sup2.journal.get_meta()

            # Pre-crash epoch-1 worker callbacks ALL fail closed with StaleEpochError & ZERO writes!
            stale = stale_tokens[0]
            t_hb1 = self.clock.advance()
            with self.assertRaises(StaleEpochError):
                sup2.journal.heartbeat_step(stale, clock=t_hb1)
            comp_stale = CompleteStepRequest(stale, _DIGEST_A, self.clock.advance())
            with self.assertRaises(StaleEpochError):
                sup2.journal.complete_step(comp_stale)
            fail_stale = FailStepRequest(stale, "late_fail", False, False, self.clock.advance())
            with self.assertRaises(StaleEpochError):
                sup2.journal.fail_step(fail_stale)
            future_tok = StepLeaseToken("run_se", "se_exec", 1, 99, stale.idempotency_key)
            t_hb2 = self.clock.advance()
            with self.assertRaises(StaleEpochError):
                sup2.journal.heartbeat_step(future_tok, clock=t_hb2)
            self.assertEqual(sup2.journal.get_meta(), meta_before)

            # Attempting requeue_pending when tracker knows effect_applied fails closed!
            applied_rcpt = tracker.issue_receipt(token=stale, current_epoch=2)
            self.assertEqual(applied_rcpt.tracker_outcome, "effect_applied")
            bad_requeue = ReconcileStepRequest(
                run_id="run_se",
                step_id="se_exec",
                expected_attempt_no=1,
                expected_epoch=2,
                reconciliation_key="recon_bad_req",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=applied_rcpt.receipt_digest,
                reason="try_requeue_applied",
                clock=self.clock.advance(),
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup2.reconcile_step(bad_requeue, tracker_receipt=applied_rcpt)

            # Reconcile completed with ProgressFingerprint evidence -> downstream runs -> count == 1!
            fp = ProgressFingerprint(
                commit_sha=_DIGEST_1,
                tree_oid=_DIGEST_2,
                diff_stat_hash=_DIGEST_C,
                verified_test_exit_seq=1,
                workflow_state_seq=2,
            )
            ev_digest = compute_reconciliation_evidence_digest(applied_rcpt, fingerprint=fp)
            recon_req = ReconcileStepRequest(
                run_id="run_se",
                step_id="se_exec",
                expected_attempt_no=1,
                expected_epoch=2,
                reconciliation_key="recon_se_done",
                resolution=ReconcileResolution.COMPLETED,
                output_digest=_DIGEST_A,
                evidence_digest=ev_digest,
                reason="verified_external_side_effect",
                clock=self.clock.advance(),
            )
            rcpt1 = sup2.reconcile_step(recon_req, tracker_receipt=applied_rcpt)
            self.assertFalse(rcpt1.duplicate)
            # Active-epoch duplicate reconciliation deduplicates cleanly.
            rcpt_dup = sup2.reconcile_step(recon_req, tracker_receipt=applied_rcpt)
            self.assertTrue(rcpt_dup.duplicate)
            # Conflicting reason raises IdempotencyConflictError.
            conflict_req = ReconcileStepRequest(
                run_id="run_se",
                step_id="se_exec",
                expected_attempt_no=1,
                expected_epoch=2,
                reconciliation_key="recon_se_done",
                resolution=ReconcileResolution.COMPLETED,
                output_digest=_DIGEST_A,
                evidence_digest=ev_digest,
                reason="different_reason",
                clock=self.clock.advance(),
            )
            with self.assertRaises(IdempotencyConflictError):
                sup2.reconcile_step(conflict_req, tracker_receipt=applied_rcpt)

            sup2.run_step_once(
                "run_se",
                "after_se",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                clock_provider=self.clock.advance,
            )
            self.assertEqual(tracker.count("run_se", "se_exec"), 1)
            self.assertEqual(sup2.journal.get_run("run_se").status, RunStatus.COMPLETED)
        finally:
            sup2.close_clean(clock=self.clock.advance())

        # Cross-restart duplicate reconciliation deduplicates with new expected_epoch == 3!
        sup3, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.advance(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        try:
            cross_req = ReconcileStepRequest(
                run_id="run_se",
                step_id="se_exec",
                expected_attempt_no=1,
                expected_epoch=3,
                reconciliation_key="recon_se_done",
                resolution=ReconcileResolution.COMPLETED,
                output_digest=_DIGEST_A,
                evidence_digest=ev_digest,
                reason="verified_external_side_effect",
                clock=self.clock.advance(),
            )
            rcpt_cross = sup3.reconcile_step(cross_req)
            self.assertTrue(rcpt_cross.duplicate)
            self.assertEqual(rcpt_cross.reconciled_epoch, 2)
        finally:
            sup3.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_idempotency_key_non_reuse_heartbeat_fail_boundaries_and_cancel(self) -> None:
        journal, _ = WorkflowRestartJournal.open_and_recover(
            self.state_dir, clock=self.clock.now(), sandbox_root=self.sandbox_root
        )
        try:
            steps = (
                StepSpec("p1", "p1", "read_metrics", False, max_attempts=2),
                StepSpec("se1", "se1", "nudge_sandbox", True, max_attempts=2),
            )
            journal.create_run(self._make_run_request("run_idem", steps))
            tok1 = journal.lease_step(
                run_id="run_idem", step_id="p1", clock=self.clock.advance(), idempotency_key="k_used"
            )
            # Active-epoch heartbeat succeeds with zero event-log writes.
            seq_before_hb = journal.get_meta().last_event_seq
            hb = journal.heartbeat_step(tok1, clock=self.clock.advance())
            self.assertEqual(hb.supervisor_epoch, 1)
            self.assertEqual(journal.get_meta().last_event_seq, seq_before_hb)

            # Retryable failure on pure step requeues p1, keeping k_used permanently reserved!
            journal.fail_step(FailStepRequest(tok1, "retry_once", True, False, self.clock.advance()))
            t_reuse = self.clock.advance()
            with self.assertRaises(IdempotencyConflictError):
                journal.lease_step(
                    run_id="run_idem",
                    step_id="p1",
                    clock=t_reuse,
                    idempotency_key="k_used",
                )
            # Re-lease with fresh key, complete, then test exact dedup & conflict!
            tok2 = journal.lease_step(
                run_id="run_idem", step_id="p1", clock=self.clock.advance(), idempotency_key="k_p1_2"
            )
            ack1 = journal.complete_step(CompleteStepRequest(tok2, _DIGEST_A, self.clock.advance()))
            self.assertFalse(ack1.duplicate)
            seq_after_comp = journal.get_meta().last_event_seq
            ack_dup = journal.complete_step(
                CompleteStepRequest(tok2, _DIGEST_A, self.clock.advance())
            )
            self.assertTrue(ack_dup.duplicate)
            self.assertEqual(journal.get_meta().last_event_seq, seq_after_comp)
            bad_comp = CompleteStepRequest(tok2, _DIGEST_B, self.clock.advance())
            with self.assertRaises(IdempotencyConflictError):
                journal.complete_step(bad_comp)

            # Side-effecting step refuses retryable=True auto-retry!
            se_tok = journal.lease_step(
                run_id="run_idem", step_id="se1", clock=self.clock.advance(), idempotency_key="k_se1"
            )
            bad_retry = FailStepRequest(se_tok, "no_auto", True, False, self.clock.advance())
            with self.assertRaises(InvalidStepTransitionError):
                journal.fail_step(bad_retry)

            # cancel_run moves leased SE step to uncertain and forbids requeue_pending!
            st_after_cancel = journal.cancel_run(
                "run_idem", reason="stop_now", clock=self.clock.advance()
            )
            self.assertEqual(st_after_cancel, RunStatus.PAUSED_NEEDS_RECONCILE)
            tracker = SyntheticEffectTracker()
            tracker.fence_attempt(se_tok)
            no_eff = tracker.issue_receipt(token=se_tok, current_epoch=1)
            requeue_after_cancel = ReconcileStepRequest(
                run_id="run_idem",
                step_id="se1",
                expected_attempt_no=1,
                expected_epoch=1,
                reconciliation_key="recon_after_cancel",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=no_eff.receipt_digest,
                reason="try_resurrect",
                clock=self.clock.advance(),
            )
            with self.assertRaises(InvalidStepTransitionError):
                journal.reconcile_step(
                    requeue_after_cancel, tracker=tracker, tracker_receipt=no_eff
                )
            # Non-completed resolution with non-None output_digest rejected at validation.
            t_bad_dig = self.clock.advance()
            with self.assertRaises(RestartValidationError):
                ReconcileStepRequest(
                    run_id="run_idem",
                    step_id="se1",
                    expected_attempt_no=1,
                    expected_epoch=1,
                    reconciliation_key="recon_bad_dig",
                    resolution=ReconcileResolution.CANCELLED,
                    output_digest=_DIGEST_A,
                    evidence_digest=_DIGEST_E,
                    reason="bad",
                    clock=t_bad_dig,
                )
            journal.reconcile_step(
                ReconcileStepRequest(
                    run_id="run_idem",
                    step_id="se1",
                    expected_attempt_no=1,
                    expected_epoch=1,
                    reconciliation_key="recon_cancel_ok",
                    resolution=ReconcileResolution.CANCELLED,
                    output_digest=None,
                    evidence_digest=_DIGEST_E,
                    reason="cancelled_ok",
                    clock=self.clock.advance(),
                )
            )
            self.assertEqual(journal.get_run("run_idem").status, RunStatus.CANCELLED)
        finally:
            journal.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_dag_deadlock_prevention_parallel_branch_and_worker_exception(self) -> None:
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.now(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        try:
            # 1. step_a -> step_b plus independent step_c: step_a fails terminally -> run stays RUNNING
            #    while step_c is runnable, then transitions to FAILED once step_c completes (never deadlocked!).
            steps1 = (
                StepSpec("step_a", "step_a", "read_metrics", False, max_attempts=1),
                StepSpec("step_b", "step_b", "read_metrics", False, depends_on=("step_a",)),
                StepSpec("step_c", "step_c", "read_metrics", False),
            )
            sup.journal.create_run(self._make_run_request("run_dag_fail", steps1))
            # Retryable failure at max_attempts=1 transitions step_a -> FAILED_TERMINAL.
            out_a = sup.run_step_once(
                "run_dag_fail",
                "step_a",
                worker_fn=lambda _t: WorkerStepResult("failed_retryable", reason="exhausted"),
                clock_provider=self.clock.advance,
            )
            self.assertEqual(out_a.ack.status, StepStatus.FAILED_TERMINAL.value)
            self.assertEqual(sup.journal.get_run("run_dag_fail").status, RunStatus.RUNNING)
            sup.run_step_once(
                "run_dag_fail",
                "step_c",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                clock_provider=self.clock.advance,
            )
            self.assertEqual(sup.journal.get_run("run_dag_fail").status, RunStatus.FAILED)

            # 2. step_x (SE) -> step_y: worker raises exception -> uncertain -> reconciled CANCELLED
            #    with cancel_requested=False -> run transitions cleanly to CANCELLED (not deadlocked!).
            steps2 = (
                StepSpec("step_x", "step_x", "stage_patch", True),
                StepSpec("step_y", "step_y", "read_metrics", False, depends_on=("step_x",)),
            )
            sup.journal.create_run(self._make_run_request("run_dag_cancel", steps2))

            def _exploding_worker(_tok: StepLeaseToken) -> WorkerStepResult:
                raise RuntimeError("boom")

            out_x = sup.run_step_once(
                "run_dag_cancel",
                "step_x",
                worker_fn=_exploding_worker,
                clock_provider=self.clock.advance,
            )
            self.assertEqual(out_x.ack.status, StepStatus.UNCERTAIN_NEEDS_RECONCILE.value)
            sup.reconcile_step(
                ReconcileStepRequest(
                    run_id="run_dag_cancel",
                    step_id="step_x",
                    expected_attempt_no=1,
                    expected_epoch=1,
                    reconciliation_key="recon_dag_cancel",
                    resolution=ReconcileResolution.CANCELLED,
                    output_digest=None,
                    evidence_digest=_DIGEST_E,
                    reason="aborted_upstream",
                    clock=self.clock.advance(),
                )
            )
            self.assertEqual(sup.journal.get_run("run_dag_cancel").status, RunStatus.CANCELLED)
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_worker_failed_uncertain_refuses_requeue_pending(self) -> None:
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.now(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        try:
            steps = (StepSpec("se_unc", "se_unc", "stage_patch", True),)
            sup.journal.create_run(self._make_run_request("run_worker_unc", steps))
            unc_tokens: list[StepLeaseToken] = []
            out_u = sup.run_step_once(
                "run_worker_unc",
                "se_unc",
                worker_fn=lambda _t: WorkerStepResult("failed_uncertain", reason="socket_drop"),
                clock_provider=self.clock.advance,
                captured_tokens=unc_tokens,
            )
            self.assertEqual(out_u.ack.status, StepStatus.UNCERTAIN_NEEDS_RECONCILE.value)
            unc_rcpt = tracker.issue_receipt(
                token=unc_tokens[0], current_epoch=1, force_fence=True
            )
            self.assertEqual(unc_rcpt.tracker_outcome, "still_pending")
            bad_req_unc = ReconcileStepRequest(
                run_id="run_worker_unc",
                step_id="se_unc",
                expected_attempt_no=1,
                expected_epoch=1,
                reconciliation_key="recon_unc_requeue",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=unc_rcpt.receipt_digest,
                reason="try_requeue_uncertain_worker",
                clock=self.clock.advance(),
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup.reconcile_step(bad_req_unc, tracker_receipt=unc_rcpt)
            self.assertEqual(
                sup.journal.get_step("run_worker_unc", "se_unc").status,
                StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            )
            sup.reconcile_step(
                ReconcileStepRequest(
                    run_id="run_worker_unc",
                    step_id="se_unc",
                    expected_attempt_no=1,
                    expected_epoch=1,
                    reconciliation_key="recon_unc_cancel",
                    resolution=ReconcileResolution.CANCELLED,
                    output_digest=None,
                    evidence_digest=unc_rcpt.receipt_digest,
                    reason="settle_uncertain_cancelled",
                    clock=self.clock.advance(),
                )
            )
            self.assertEqual(sup.journal.get_run("run_worker_unc").status, RunStatus.CANCELLED)
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_crash_during_recovery_and_four_epoch_chain_with_max_attempts(self) -> None:
        tracker = SyntheticEffectTracker()
        # Epoch 1: lease a pure step (max_attempts=2) and crash before worker.
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.now(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        sup1.journal.create_run(
            self._make_run_request(
                "run_4ep", (StepSpec("loop_step", "loop_step", "read_metrics", False, max_attempts=2),)
            )
        )
        def _worker_loop(_t: StepLeaseToken) -> WorkerStepResult:
            return WorkerStepResult("completed", _DIGEST_A)

        with self.assertRaises(SimulatedSupervisorCrash):
            sup1.run_step_once(
                "run_4ep",
                "loop_step",
                worker_fn=_worker_loop,
                clock_provider=self.clock.advance,
                crash_point=CrashPoint.AFTER_LEASE_COMMIT_BEFORE_WORKER,
            )

        # Crash DURING recovery BEFORE commit -> rollback cleanly leaves epoch 1 intact!
        t_rec_rb = self.clock.advance()
        with self.assertRaises(SimulatedSupervisorCrash):
            DurableWorkflowSupervisor.start_or_recover(
                self.state_dir,
                clock=t_rec_rb,
                tracker=tracker,
                sandbox_root=self.sandbox_root,
                crash_point=CrashPoint.DURING_RECOVERY_BEFORE_COMMIT,
            )
        snap_after_rb = verify_journal_replay_readonly(
            self.state_dir, sandbox_root=self.sandbox_root
        )
        self.assertEqual(snap_after_rb.supervisor_epoch, 1)

        # Epoch 2: crash AFTER recovery commit BEFORE dispatch!
        t_rec_after = self.clock.advance()
        with self.assertRaises(SimulatedSupervisorCrash):
            DurableWorkflowSupervisor.start_or_recover(
                self.state_dir,
                clock=t_rec_after,
                tracker=tracker,
                sandbox_root=self.sandbox_root,
                crash_point=CrashPoint.AFTER_RECOVERY_COMMIT_BEFORE_DISPATCH,
            )

        # Epoch 3: re-lease attempt 2 (max_attempts=2) and crash again!
        sup3, rep3 = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.advance(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        self.assertEqual(rep3.supervisor_epoch, 3)
        with self.assertRaises(SimulatedSupervisorCrash):
            sup3.run_step_once(
                "run_4ep",
                "loop_step",
                worker_fn=_worker_loop,
                clock_provider=self.clock.advance,
                crash_point=CrashPoint.AFTER_LEASE_COMMIT_BEFORE_WORKER,
            )

        # Epoch 4: recovery sees attempt_no == max_attempts -> fails terminally (no infinite loop)!
        sup4, rep4 = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir, clock=self.clock.advance(), tracker=tracker, sandbox_root=self.sandbox_root
        )
        try:
            self.assertEqual(rep4.supervisor_epoch, 4)
            self.assertEqual(rep4.fenced_failed, (("run_4ep", "loop_step", 2),))
            self.assertEqual(sup4.journal.get_run("run_4ep").status, RunStatus.FAILED)
        finally:
            sup4.close_clean(clock=self.clock.advance())

        final_snap = verify_journal_replay_readonly(
            self.state_dir, sandbox_root=self.sandbox_root
        )
        self.assertEqual(final_snap.supervisor_epoch, 4)
        self.assertEqual(final_snap.dirty_shutdown, 0)


class TestCapacityHeadroomAndTamperDefense(_RestartFixtureBase):
    def test_headroom_crash_clean_close_and_exact_two_slot_refusal(self) -> None:
        # Cap = 8:
        # seq 1: started(e1), seq 2: run_created, seq 3: lease(SE) -> L=1, U=0 -> 3 + 3 + 2*1 = 8!
        # Next write (create_run or lease) fails closed leaving seq=3 intact!
        cap = 8
        steps = (
            StepSpec("se1", "se1", "stage_patch", True),
            StepSpec("p2", "p2", "read_metrics", False),
        )
        # Case (a): lease -> refusal -> crash -> recovery (seq 4,5) -> reconcile (seq 6) -> close (seq 7)
        dir_a = self.root / "cap_a"
        dir_a.mkdir(mode=0o700)
        os.chmod(dir_a, 0o700)
        ja, _ = WorkflowRestartJournal.open_and_recover(
            dir_a, clock=self.clock.now(), sandbox_root=self.sandbox_root, max_replay_events=cap
        )
        ja.create_run(self._make_run_request("r_a", steps))
        ja.lease_step(run_id="r_a", step_id="se1", clock=self.clock.advance())
        t_over_a = self.clock.advance()
        with self.assertRaises(RestartPolicyError) as exc_a:
            ja.lease_step(run_id="r_a", step_id="p2", clock=t_over_a)
        self.assertIn(ERR_MAX_EVENTS, str(exc_a.exception))
        self.assertEqual(ja.get_meta().last_event_seq, 3)
        ja.simulate_crash()

        ja2, _ = WorkflowRestartJournal.open_and_recover(
            dir_a, clock=self.clock.advance(), sandbox_root=self.sandbox_root, max_replay_events=cap
        )
        ja2.reconcile_step(
            ReconcileStepRequest(
                "r_a", "se1", 1, 2, "rec_a", ReconcileResolution.CANCELLED, None, _DIGEST_E, "done", self.clock.advance()
            )
        )
        ja2.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(dir_a, sandbox_root=self.sandbox_root, max_replay_events=cap)

        # Case (b) + (c): lease -> close_clean (seq 4) -> open_and_recover (seq 5, 6 -> U=1, 2 slots left!)
        # Premature close_clean() refuses while preserving open writer for reconcile (seq 7) + close (seq 8)!
        # Then writable reopen fails closed (seq 8 == cap) while read-only replay succeeds!
        dir_b = self.root / "cap_b"
        dir_b.mkdir(mode=0o700)
        os.chmod(dir_b, 0o700)
        jb, _ = WorkflowRestartJournal.open_and_recover(
            dir_b, clock=self.clock.now(), sandbox_root=self.sandbox_root, max_replay_events=cap
        )
        jb.create_run(self._make_run_request("r_b", (StepSpec("se1", "se1", "stage_patch", True),)))
        jb.lease_step(run_id="r_b", step_id="se1", clock=self.clock.advance())
        jb.close_clean(clock=self.clock.advance())

        jb2, _ = WorkflowRestartJournal.open_and_recover(
            dir_b, clock=self.clock.advance(), sandbox_root=self.sandbox_root, max_replay_events=cap
        )
        self.assertEqual(jb2.get_meta().last_event_seq, 6)
        # Exactly 2 slots left (7, 8) with U=1 -> premature close_clean refuses & keeps jb2 open!
        t_premature = self.clock.advance()
        with self.assertRaises(RestartPolicyError):
            jb2.close_clean(clock=t_premature)
        verify_journal_replay_readonly(dir_b, sandbox_root=self.sandbox_root, max_replay_events=cap)
        jb2.reconcile_step(
            ReconcileStepRequest(
                "r_b", "se1", 1, 2, "rec_b", ReconcileResolution.CANCELLED, None, _DIGEST_E, "done", self.clock.advance()
            )
        )
        final_seq = jb2.close_clean(clock=self.clock.advance())
        self.assertEqual(final_seq, cap)

        # Exhausted writable reopen fails closed leaving head intact; read-only replay succeeds!
        t_reopen = self.clock.advance()
        with self.assertRaises(RestartPolicyError):
            WorkflowRestartJournal.open_and_recover(
                dir_b, clock=t_reopen, sandbox_root=self.sandbox_root, max_replay_events=cap
            )
        snap_b = verify_journal_replay_readonly(
            dir_b, sandbox_root=self.sandbox_root, max_replay_events=cap
        )
        self.assertEqual(snap_b.last_event_seq, cap)

    def _create_base_closed_journal(self) -> None:
        j, _ = WorkflowRestartJournal.open_and_recover(
            self.state_dir, clock=self.clock.now(), sandbox_root=self.sandbox_root
        )
        j.create_run(
            self._make_run_request("run_t", (StepSpec("s1", "s1", "stage_patch", True),))
        )
        tok = j.lease_step(run_id="run_t", step_id="s1", clock=self.clock.advance())
        j.fail_step(FailStepRequest(tok, "uncertain_io", False, True, self.clock.advance()))
        j.reconcile_step(
            ReconcileStepRequest(
                "run_t", "s1", 1, 1, "rk1", ReconcileResolution.COMPLETED, _DIGEST_A, _DIGEST_E, "ok", self.clock.advance()
            )
        )
        j.close_clean(clock=self.clock.advance())

    def test_deleted_meta_zero_seq_and_json_dos_tampering(self) -> None:
        self._create_base_closed_journal()
        # 1. Deleted supervisor_meta with non-empty journal refuses epoch reset!
        self._tamper_db("DELETE FROM supervisor_meta")
        t_del = self.clock.advance()
        with self.assertRaises(JournalIntegrityError) as ctx_del:
            WorkflowRestartJournal.open_and_recover(
                self.state_dir, clock=t_del, sandbox_root=self.sandbox_root
            )
        self.assertIn(ERR_META_MISSING_NONEMPTY, str(ctx_del.exception))
        with self.assertRaises(JournalIntegrityError):
            verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

        # 2. last_event_seq == 0 on existing DB rejected.
        self._tamper_db(
            "INSERT INTO supervisor_meta VALUES (1, 1, 0, ?, 0, 1)", (EVENT_GENESIS_HASH,)
        )
        with self.assertRaises(JournalIntegrityError):
            verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

        # 3. 16 KiB deeply nested JSON DoS -> JournalIntegrityError (zero RecursionError!).
        self._tamper_db("UPDATE supervisor_meta SET last_event_seq = 6")
        nested = ("[" * 8000) + ("]" * 8000)
        self._tamper_db("UPDATE workflow_event_log SET payload_json = ? WHERE seq = 1", (nested,))
        with self.assertRaises(JournalIntegrityError):
            verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

        # 4. Duplicate JSON keys & non-canonical whitespace & floats all fail closed.
        for bad_json in (
            '{"dirty_recovery":false,"dirty_recovery":false,"prior_epoch":0}',
            '{ "dirty_recovery": false, "prior_epoch": 0 }',
            '{"dirty_recovery":false,"prior_epoch":0.0}',
        ):
            self._tamper_db(
                "UPDATE workflow_event_log SET payload_json = ? WHERE seq = 1", (bad_json,)
            )
            with self.assertRaises(JournalIntegrityError):
                verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_hash_hex_seq_lifecycle_timestamp_extra_row_and_trigger_tamper(self) -> None:
        cases = (
            ("UPDATE workflow_event_log SET entry_hash = ? WHERE seq = 1", ("z" * 64,)),
            ("UPDATE workflow_event_log SET prev_hash = ? WHERE seq = 2", (_DIGEST_B,)),
            ("UPDATE workflow_event_log SET seq = -1 WHERE seq = 1", ()),
            ("UPDATE workflow_runs SET status = 'running' WHERE run_id = 'run_t'", ()),
            ("UPDATE supervisor_meta SET updated_at_us = 1", ()),
            ("UPDATE workflow_steps SET updated_at_us = 1 WHERE run_id = 'run_t'", ()),
            (
                "INSERT INTO workflow_runs VALUES "
                "('extra_r', 'user/x', ?, ?, 1, 'running', 0, 1, 1, 1)",
                (_DIGEST_1, _DIGEST_2),
            ),
            (
                "CREATE TRIGGER evil_trig AFTER INSERT ON workflow_runs BEGIN SELECT 1; END",
                (),
            ),
            ("CREATE VIEW evil_view AS SELECT 1 AS x", ()),
            (
                "CREATE TABLE pragma_table_list(schema TEXT, name TEXT, type TEXT)",
                (),
            ),
            (
                "DROP TABLE step_reconciliations",
                (),
            ),
        )
        for idx, (sql, params) in enumerate(cases):
            sub_dir = self.root / f"tamper_{idx}"
            sub_dir.mkdir(mode=0o700)
            os.chmod(sub_dir, 0o700)
            saved = self.state_dir
            self.state_dir = sub_dir
            try:
                self._create_base_closed_journal()
                self._tamper_db(sql, params)
                with self.assertRaises(JournalIntegrityError):
                    verify_journal_replay_readonly(sub_dir, sandbox_root=self.sandbox_root)
            finally:
                self.state_dir = saved

        # Virtual table impersonating a core table (rootpage = 0) rejected before pragma!
        vdir = self.root / "tamper_virtual"
        vdir.mkdir(mode=0o700)
        os.chmod(vdir, 0o700)
        saved = self.state_dir
        self.state_dir = vdir
        try:
            self._create_base_closed_journal()
            self._tamper_db("DROP TABLE step_reconciliations")
            self._tamper_db("CREATE VIRTUAL TABLE step_reconciliations USING fts5(run_id)")
            with self.assertRaises(JournalIntegrityError) as vctx:
                verify_journal_replay_readonly(vdir, sandbox_root=self.sandbox_root)
            self.assertIn(ERR_UNEXPECTED_SCHEMA, str(vctx.exception))
        finally:
            self.state_dir = saved

    @staticmethod
    def _make_chained_event(
        *,
        seq: int,
        epoch: int,
        event_type: EventType,
        prev_hash: str,
        payload: dict[str, Any],
        run_id: str | None = None,
        step_id: str | None = None,
    ) -> JournalEvent:
        ts = 1_700_000_000_000_000 + seq
        eh = compute_event_hash(
            seq=seq,
            supervisor_epoch=epoch,
            event_type=event_type.value,
            run_id=run_id,
            step_id=step_id,
            payload=payload,
            created_at_us=ts,
            prev_hash=prev_hash,
        )
        return JournalEvent(
            seq=seq,
            supervisor_epoch=epoch,
            event_type=event_type,
            run_id=run_id,
            step_id=step_id,
            payload=payload,
            created_at_us=ts,
            prev_hash=prev_hash,
            entry_hash=eh,
        )

    def test_valid_hash_chain_replay_lifecycle_violations_rejected(self) -> None:
        # 1. Non-supervisor_started at seq == 1
        e_bad_first = self._make_chained_event(
            seq=1,
            epoch=1,
            event_type=EventType.SUPERVISOR_STOPPED,
            prev_hash=EVENT_GENESIS_HASH,
            payload={},
        )
        with self.assertRaises(ReplayMismatchError):
            reduce_event_log([e_bad_first])

        e1 = self._make_chained_event(
            seq=1,
            epoch=1,
            event_type=EventType.SUPERVISOR_STARTED,
            prev_hash=EVENT_GENESIS_HASH,
            payload={"dirty_recovery": False, "prior_epoch": 0},
        )
        e2_stop = self._make_chained_event(
            seq=2,
            epoch=1,
            event_type=EventType.SUPERVISOR_STOPPED,
            prev_hash=e1.entry_hash,
            payload={},
        )
        # 2. Post-supervisor_stopped work event in same epoch
        e3_after_stop = self._make_chained_event(
            seq=3,
            epoch=1,
            event_type=EventType.RUN_CREATED,
            prev_hash=e2_stop.entry_hash,
            run_id="r1",
            payload={
                "grant_generation": 1,
                "spec_digest": _DIGEST_1,
                "steps": [
                    StepSpec("s1", "s1", "read_metrics", False).to_payload_dict()
                ],
                "workflow_id": "user/w",
                "workflow_plan_digest": _DIGEST_2,
            },
        )
        with self.assertRaises(ReplayMismatchError):
            reduce_event_log([e1, e2_stop, e3_after_stop])

        # 3. Skipped epoch 1 -> 3
        e3_skip = self._make_chained_event(
            seq=3,
            epoch=3,
            event_type=EventType.SUPERVISOR_STARTED,
            prev_hash=e2_stop.entry_hash,
            payload={"dirty_recovery": False, "prior_epoch": 1},
        )
        with self.assertRaises(ReplayMismatchError):
            reduce_event_log([e1, e2_stop, e3_skip])

        # 4. Unfenced prior-epoch lease followed directly by supervisor_stopped (skipping fence!)
        e2_run = self._make_chained_event(
            seq=2,
            epoch=1,
            event_type=EventType.RUN_CREATED,
            prev_hash=e1.entry_hash,
            run_id="r1",
            payload={
                "grant_generation": 1,
                "spec_digest": _DIGEST_1,
                "steps": [
                    StepSpec("s1", "s1", "stage_patch", True).to_payload_dict()
                ],
                "workflow_id": "user/w",
                "workflow_plan_digest": _DIGEST_2,
            },
        )
        e3_lease = self._make_chained_event(
            seq=3,
            epoch=1,
            event_type=EventType.STEP_LEASED,
            prev_hash=e2_run.entry_hash,
            run_id="r1",
            step_id="s1",
            payload={
                "attempt_no": 1,
                "idempotency_key": "k_unfenced",
                "lease_epoch": 1,
                "side_effecting": True,
            },
        )
        e4_start2 = self._make_chained_event(
            seq=4,
            epoch=2,
            event_type=EventType.SUPERVISOR_STARTED,
            prev_hash=e3_lease.entry_hash,
            payload={"dirty_recovery": True, "prior_epoch": 1},
        )
        e5_bad_stop = self._make_chained_event(
            seq=5,
            epoch=2,
            event_type=EventType.SUPERVISOR_STOPPED,
            prev_hash=e4_start2.entry_hash,
            payload={},
        )
        with self.assertRaises(ReplayMismatchError):
            reduce_event_log([e1, e2_run, e3_lease, e4_start2, e5_bad_stop])

    def test_non_strict_sqlite_storage_class_attacks(self) -> None:
        blob = b"\x01\x02" * 512
        attacks = (
            ("UPDATE supervisor_meta SET current_epoch = ?", (blob,)),
            ("UPDATE workflow_event_log SET supervisor_epoch = ? WHERE seq = 1", (blob,)),
            ("UPDATE workflow_steps SET attempt_no = ? WHERE run_id = 'run_t'", (blob,)),
            ("UPDATE workflow_steps SET side_effecting = 2 WHERE run_id = 'run_t'", ()),
            ("UPDATE workflow_runs SET cancel_requested = ? WHERE run_id = 'run_t'", (blob,)),
            ("UPDATE step_reconciliations SET reconciled_epoch = ? WHERE run_id = 'run_t'", (blob,)),
            ("UPDATE step_idempotency_keys SET outcome_status = ? WHERE run_id = 'run_t'", (blob,)),
        )
        for idx, (sql, params) in enumerate(attacks):
            sub_dir = self.root / f"blob_{idx}"
            sub_dir.mkdir(mode=0o700)
            os.chmod(sub_dir, 0o700)
            saved = self.state_dir
            self.state_dir = sub_dir
            try:
                self._create_base_closed_journal()
                self._tamper_db(sql, params)
                with self.assertRaises(JournalIntegrityError) as ctx:
                    verify_journal_replay_readonly(sub_dir, sandbox_root=self.sandbox_root)
                self.assertIn(ERR_MALFORMED_STORAGE, str(ctx.exception))
            finally:
                self.state_dir = saved


class TestFilesystemLockConcurrencyAndChildProcessCrashes(_RestartFixtureBase):
    def test_filesystem_dir_and_boundary_refusals(self) -> None:
        clk = self.clock.now()
        sym_dir = self.root / "sym_state"
        sym_dir.symlink_to(self.state_dir)
        with self.assertRaises(RestartStorageError):
            WorkflowRestartJournal.open_and_recover(
                sym_dir, clock=clk, sandbox_root=self.sandbox_root
            )
        dotdot_via_sym = sym_dir / ".." / "state"
        with self.assertRaises(RestartStorageError):
            WorkflowRestartJournal.open_and_recover(
                dotdot_via_sym, clock=clk, sandbox_root=self.sandbox_root
            )
        in_sb = self.sandbox_root / "nested"
        in_sb.mkdir(mode=0o700)
        with self.assertRaises(RestartStorageError):
            WorkflowRestartJournal.open_and_recover(
                in_sb, clock=clk, sandbox_root=self.sandbox_root
            )
        fake_xdg = self.root / "xdg_data"
        prod_dir = fake_xdg / "oc-sandbox"
        prod_dir.mkdir(parents=True, mode=0o700)
        os.chmod(fake_xdg, 0o700)
        os.chmod(prod_dir, 0o700)
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(fake_xdg)}), self.assertRaises(
            RestartStorageError
        ):
            WorkflowRestartJournal.open_and_recover(
                prod_dir, clock=clk, sandbox_root=self.sandbox_root
            )
        open_dir = self.root / "open_dir"
        open_dir.mkdir(mode=0o750)
        os.chmod(open_dir, 0o750)
        with self.assertRaises(RestartStorageError):
            WorkflowRestartJournal.open_and_recover(
                open_dir, clock=clk, sandbox_root=self.sandbox_root
            )
        self.assertEqual(stat.S_IMODE(os.lstat(open_dir).st_mode), 0o750)

    def _prepare_hostile_file_case(self, cdir: Path, case: str) -> None:
        db_p = cdir / DB_FILENAME
        if case == "bad_db_mode":
            db_p.write_bytes(b"")
            os.chmod(db_p, 0o640)
        elif case == "bad_lock_mode":
            lp = cdir / LOCK_FILENAME
            lp.write_bytes(b"")
            os.chmod(lp, 0o640)
        elif case == "hardlink_db":
            other = self.root / "other_hl.db"
            other.write_bytes(b"")
            os.chmod(other, 0o600)
            os.link(other, db_p)
        elif case == "sym_wal":
            Path(f"{db_p}-wal").symlink_to(self.root / "nowhere")
        else:
            os.mkfifo(db_p, 0o600)

    def test_filesystem_file_mode_hardlink_symlink_fifo_refusals(self) -> None:
        clk = self.clock.now()
        for case in ("bad_db_mode", "bad_lock_mode", "hardlink_db", "sym_wal", "fifo_db"):
            cdir = self.root / f"fs_{case}"
            cdir.mkdir(mode=0o700)
            os.chmod(cdir, 0o700)
            self._prepare_hostile_file_case(cdir, case)
            with self.assertRaises(RestartStorageError):
                WorkflowRestartJournal.open_and_recover(
                    cdir, clock=clk, sandbox_root=self.sandbox_root
                )
            if case == "bad_db_mode":
                self.assertEqual(stat.S_IMODE(os.lstat(cdir / DB_FILENAME).st_mode), 0o640)
            if case == "bad_lock_mode":
                self.assertEqual(stat.S_IMODE(os.lstat(cdir / LOCK_FILENAME).st_mode), 0o640)

    def test_exclusive_lock_live_wal_and_checkpointed_readonly_replay(self) -> None:
        j, _ = WorkflowRestartJournal.open_and_recover(
            self.state_dir, clock=self.clock.now(), sandbox_root=self.sandbox_root
        )
        try:
            j.create_run(
                self._make_run_request("run_ro", (StepSpec("s1", "s1", "read_metrics", False),))
            )
            # Second concurrent live supervisor fails immediately with ERR_LOCK_HELD.
            t_lock = self.clock.advance()
            with self.assertRaises(RestartStorageError) as lock_ctx:
                WorkflowRestartJournal.open_and_recover(
                    self.state_dir, clock=t_lock, sandbox_root=self.sandbox_root
                )
            self.assertIn(ERR_LOCK_HELD, str(lock_ctx.exception))

            # Lock-free read-only replay succeeds against LIVE WAL DB!
            live_snap = verify_journal_replay_readonly(
                self.state_dir, sandbox_root=self.sandbox_root
            )
            self.assertEqual(live_snap.supervisor_epoch, 1)

            # Opened RO SQLite connection refuses SQL writes.
            ro_conn = open_sqlite_bounded(
                self.state_dir / DB_FILENAME,
                readonly=True,
                deadline=time.monotonic() + 2.0,
            )
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    ro_conn.execute("DELETE FROM supervisor_meta")
            finally:
                ro_conn.close()
        finally:
            j.close_clean(clock=self.clock.advance())

        # Checkpoint cleanly closed DB and ensure -wal/-shm are absent, then verify RO replay!
        chk = sqlite3.connect(str(self.state_dir / DB_FILENAME))
        try:
            chk.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            chk.close()
        for suf in ("-wal", "-shm"):
            sp = Path(f"{self.state_dir / DB_FILENAME}{suf}")
            if sp.exists():
                sp.unlink()
        ckpt_snap = verify_journal_replay_readonly(
            self.state_dir, sandbox_root=self.sandbox_root
        )
        self.assertEqual(ckpt_snap.dirty_shutdown, 0)
        for suf in ("-wal", "-shm"):
            sp = Path(f"{self.state_dir / DB_FILENAME}{suf}")
            if sp.exists():
                self.assertEqual(stat.S_IMODE(os.lstat(sp).st_mode), 0o600)

        # Read-only 0o500 directory fails admission cleanly.
        os.chmod(self.state_dir, 0o500)
        try:
            with self.assertRaises(RestartStorageError):
                verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)
        finally:
            os.chmod(self.state_dir, 0o700)

    def test_overlapping_concurrent_callbacks_serialize_cleanly(self) -> None:
        j, _ = WorkflowRestartJournal.open_and_recover(
            self.state_dir, clock=self.clock.now(), sandbox_root=self.sandbox_root
        )
        errors: list[Exception] = []
        try:
            def _worker(idx: int) -> None:
                try:
                    rid = f"run_conc_{idx}"
                    clk = ClockSnapshot(monotonic_s=100.0 + idx, wall_s=1_700_000_000.0 + idx)
                    j.create_run(
                        self._make_run_request(
                            rid, (StepSpec("s1", "s1", "read_metrics", False),), clock=clk
                        )
                    )
                    tok = j.lease_step(run_id=rid, step_id="s1", clock=clk)
                    j.heartbeat_step(tok, clock=clk)
                    j.complete_step(CompleteStepRequest(tok, _DIGEST_A, clk))
                except Exception as exc:  # pragma: no cover
                    errors.append(exc)

            threads = [threading.Thread(target=_worker, args=(i,)) for i in range(6)]
            for th in threads:
                th.start()
            for th in threads:
                th.join(timeout=10.0)
            self.assertEqual(errors, [])
        finally:
            j.close_clean(clock=self.clock.advance())
        snap = verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)
        self.assertEqual(len(snap.runs), 6)

    def test_deadlines_umask_lock_uri_failure_and_post_boot_progress_cleanup(self) -> None:
        # 1. Boot with tight max_op_ms=50, wait > 65ms, then run normal op -> proves
        #    progress handler was unconditionally cleared in finally!
        j, _ = WorkflowRestartJournal.open_and_recover(
            self.state_dir, clock=self.clock.now(), sandbox_root=self.sandbox_root, max_op_ms=50
        )
        try:
            time.sleep(0.07)
            j.create_run(
                self._make_run_request("run_post_boot", (StepSpec("s1", "s1", "read_metrics", False),)),
                max_op_ms=2000,
            )
            self.assertEqual(j.get_run("run_post_boot").status, RunStatus.RUNNING)
        finally:
            j.close_clean(clock=self.clock.advance())

        # 2. Held SQLite write lock past max_op_ms=50 -> RestartStorageError(ERR_OP_DEADLINE).
        holder = sqlite3.connect(str(self.state_dir / DB_FILENAME), isolation_level=None)
        try:
            holder.execute("BEGIN EXCLUSIVE")
            t_busy = self.clock.advance()
            t0 = time.monotonic()
            with self.assertRaises(RestartStorageError) as busy_ctx:
                WorkflowRestartJournal.open_and_recover(
                    self.state_dir,
                    clock=t_busy,
                    sandbox_root=self.sandbox_root,
                    max_op_ms=50,
                )
            self.assertIn(ERR_OP_DEADLINE, str(busy_ctx.exception))
            self.assertLess(time.monotonic() - t0, 1.0)
        finally:
            holder.execute("ROLLBACK")
            holder.close()

        # 3. Held _UMASK_LOCK past max_op_ms=50 -> zero sqlite3.connect calls!
        acquired = threading.Event()
        release = threading.Event()

        def _hold_umask() -> None:
            with _UMASK_LOCK:
                acquired.set()
                release.wait(timeout=2.0)

        holder_th = threading.Thread(target=_hold_umask)
        holder_th.start()
        acquired.wait(timeout=1.0)
        try:
            dl_umask = time.monotonic() + 0.05
            with mock.patch("oc_restart_db.sqlite3.connect") as mock_connect:
                with self.assertRaises(RestartStorageError) as um_ctx:
                    open_sqlite_bounded(
                        self.state_dir / DB_FILENAME,
                        readonly=True,
                        deadline=dl_umask,
                    )
                self.assertIn(ERR_OP_DEADLINE, str(um_ctx.exception))
                mock_connect.assert_not_called()
        finally:
            release.set()
            holder_th.join(timeout=2.0)

        # 4. Surrogate-escaped URI failure never strands _UMASK_LOCK!
        bad_path = self.state_dir / "bad_\udcff.sqlite"
        dl_bad = time.monotonic() + 1.0
        with self.assertRaises(RestartStorageError):
            open_sqlite_bounded(bad_path, readonly=True, deadline=dl_bad)
        got_lock = _UMASK_LOCK.acquire(timeout=0.5)
        self.assertTrue(got_lock)
        _UMASK_LOCK.release()

    def test_child_process_os_exit_137_before_and_after_commit(self) -> None:
        # Fixture A: real process death (os._exit(137)) BEFORE commit -> WAL rollback cleanly!
        dir_pre = self.root / "proc_pre"
        dir_pre.mkdir(mode=0o700)
        os.chmod(dir_pre, 0o700)
        script_pre = (
            f"import os, sys; sys.path.insert(0, {str(_RESTART_DIR)!r}); "
            "from pathlib import Path; "
            "from oc_restart_contract import CreateRunRequest, StepSpec; "
            "from oc_restart_store import WorkflowRestartJournal; "
            "from oc_workflow_plan import ClockSnapshot; "
            f"j, _ = WorkflowRestartJournal.open_and_recover(Path({str(dir_pre)!r}), "
            f"clock=ClockSnapshot(1.0, 1700000000.0), sandbox_root=Path({str(self.sandbox_root)!r})); "
            f"j.create_run(CreateRunRequest('r_pre', 'user/w', {_DIGEST_1!r}, {_DIGEST_2!r}, 1, "
            "(StepSpec('s1', 's1', 'stage_patch', True),), ClockSnapshot(2.0, 1700000001.0))); "
            "j._conn.execute('BEGIN IMMEDIATE'); "
            "j._conn.execute(\"UPDATE workflow_steps SET status='leased', attempt_no=1, lease_epoch=1 "
            "WHERE run_id='r_pre' AND step_id='s1'\"); "
            "os._exit(137)"
        )
        res_pre = subprocess.run(
            [sys.executable, "-B", "-c", script_pre], check=False, capture_output=True
        )
        self.assertEqual(res_pre.returncode, 137, msg=res_pre.stderr.decode("utf-8", "replace"))
        j_pre, rep_pre = WorkflowRestartJournal.open_and_recover(
            dir_pre, clock=self.clock.advance(), sandbox_root=self.sandbox_root
        )
        try:
            self.assertEqual(rep_pre.supervisor_epoch, 2)
            step_pre = j_pre.get_step("r_pre", "s1")
            self.assertEqual(step_pre.status, StepStatus.PENDING)
            self.assertEqual(step_pre.attempt_no, 0)
        finally:
            j_pre.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(dir_pre, sandbox_root=self.sandbox_root)

        # Fixture B: real process death (os._exit(137)) AFTER durable lease commit + external side-effect
        # marker BEFORE complete_step commit -> parent fences to uncertain, zero auto-re-execution!
        dir_post = self.root / "proc_post"
        dir_post.mkdir(mode=0o700)
        os.chmod(dir_post, 0o700)
        effect_marker = self.root / "external_effect_log.json"
        script_post = (
            f"import json, os, sys; sys.path.insert(0, {str(_RESTART_DIR)!r}); "
            "from pathlib import Path; "
            "from oc_restart_contract import CreateRunRequest, StepSpec; "
            "from oc_restart_store import WorkflowRestartJournal; "
            "from oc_workflow_plan import ClockSnapshot; "
            f"j, _ = WorkflowRestartJournal.open_and_recover(Path({str(dir_post)!r}), "
            f"clock=ClockSnapshot(1.0, 1700000000.0), sandbox_root=Path({str(self.sandbox_root)!r})); "
            f"j.create_run(CreateRunRequest('r_post', 'user/w', {_DIGEST_1!r}, {_DIGEST_2!r}, 1, "
            "(StepSpec('s1', 's1', 'stage_patch', True),), ClockSnapshot(2.0, 1700000001.0))); "
            "tok = j.lease_step(run_id='r_post', step_id='s1', clock=ClockSnapshot(3.0, 1700000002.0)); "
            f"Path({str(effect_marker)!r}).write_text(json.dumps({{'count': 1, 'output_digest': {_DIGEST_A!r}, "
            "'idem': tok.idempotency_key}), encoding='utf-8'); "
            "os._exit(137)"
        )
        res_post = subprocess.run(
            [sys.executable, "-B", "-c", script_post], check=False, capture_output=True
        )
        self.assertEqual(res_post.returncode, 137, msg=res_post.stderr.decode("utf-8", "replace"))
        marker_data = json.loads(effect_marker.read_text(encoding="utf-8"))
        self.assertEqual(marker_data["count"], 1)

        j_post, rep_post = WorkflowRestartJournal.open_and_recover(
            dir_post, clock=self.clock.advance(), sandbox_root=self.sandbox_root
        )
        try:
            self.assertEqual(rep_post.supervisor_epoch, 2)
            self.assertEqual(rep_post.fenced_uncertain, (("r_post", "s1", 1),))
            self.assertEqual(j_post.list_eligible_steps("r_post"), ())
            j_post.reconcile_step(
                ReconcileStepRequest(
                    run_id="r_post",
                    step_id="s1",
                    expected_attempt_no=1,
                    expected_epoch=2,
                    reconciliation_key="recon_proc_post",
                    resolution=ReconcileResolution.COMPLETED,
                    output_digest=marker_data["output_digest"],
                    evidence_digest=hashlib.sha256(
                        effect_marker.read_bytes()
                    ).hexdigest(),
                    reason="reconciled_external_marker",
                    clock=self.clock.advance(),
                )
            )
            self.assertEqual(j_post.get_run("r_post").status, RunStatus.COMPLETED)
            self.assertEqual(json.loads(effect_marker.read_text(encoding="utf-8"))["count"], 1)
        finally:
            j_post.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(dir_post, sandbox_root=self.sandbox_root)


if __name__ == "__main__":
    unittest.main()
