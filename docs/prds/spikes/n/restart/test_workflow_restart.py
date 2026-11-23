"""Offline qualification and adversarial test suite for PRD N durable workflow restart kernel."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
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
    SupervisorMetaRecord,
    SyntheticEffectTracker,
    WorkerStepResult,
    compute_event_hash,
    compute_reconciliation_evidence_digest,
    compute_tracker_receipt_digest,
    derive_steps_from_plan,
    reduce_event_log,
    verify_materialized_parity,
)
from oc_restart_db import (  # noqa: E402
    DB_FILENAME,
    LOCK_FILENAME,
    open_sqlite_bounded,
    read_run_by_id_strict,
    read_step_by_pk_strict,
    read_steps_strict,
    safe_rollback_and_close,
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
_TEST_JOURNAL_ID = "jnl_00000000000000000000000000000000"

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
effects = ["launch_sandbox"]

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
            no_eff = sup3.issue_tracker_receipt(captured[0])
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
            no_eff = sup3.issue_tracker_receipt(se_tokens[0])
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
            applied_rcpt = sup2.issue_tracker_receipt(stale)
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
            unc_rcpt = sup.issue_tracker_receipt(unc_tokens[0], force_fence=True)
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
            "INSERT INTO supervisor_meta VALUES "
            "(1, 'jnl_tamper000000000000000000000000', 1, 0, ?, 0, 1)",
            (EVENT_GENESIS_HASH,),
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
                "('extra_r', 'user/x', ?, ?, 1, 0, 'running', 0, 1, 1, 1)",
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
            payload={
                "dirty_recovery": False,
                "journal_id": _TEST_JOURNAL_ID,
                "prior_epoch": 0,
            },
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
                "requires_authority": False,
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
            payload={
                "dirty_recovery": False,
                "journal_id": _TEST_JOURNAL_ID,
                "prior_epoch": 1,
            },
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
                "requires_authority": False,
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
            payload={
                "dirty_recovery": True,
                "journal_id": _TEST_JOURNAL_ID,
                "prior_epoch": 1,
            },
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


_CONDITIONAL_TRANSITION_TOML = _OBSERVE_ONLY_TOML.replace(
    'dst = "project"\n',
    'dst = "project"\npredicate = "metric.stall_seconds > 10"\n',
)

_TRANSITION_EFFECT_TOML = _OBSERVE_ONLY_TOML.replace(
    'dst = "project"\n',
    'dst = "project"\neffects = ["read_metrics"]\n',
)

_MIXED_EFFECT_STATE_TOML = _ACTIVE_STATECHART_TOML.replace(
    'effects = ["launch_sandbox"]',
    'effects = ["read_metrics", "launch_sandbox"]',
)

_PURE_ON_MUTATING_SHAPE_TOML = _ACTIVE_STATECHART_TOML.replace(
    'effects = ["launch_sandbox"]',
    'effects = ["read_metrics"]',
)


class TestAdversarialRegressionsRound2(_RestartFixtureBase):
    def test_recovered_plan_run_denies_dispatch_and_requeue_without_authority_store(
        self,
    ) -> None:
        auth = RunAuthorityStore()
        plan_act, rec_act = self._compile_and_admit(
            _ACTIVE_STATECHART_TOML, authority_store=auth, ttl_s=120.0
        )
        plan_obs, rec_obs = self._compile_and_admit(
            _OBSERVE_ONLY_TOML, authority_store=auth, ttl_s=120.0
        )
        tracker = SyntheticEffectTracker()
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            authority_store=auth,
            sandbox_root=self.sandbox_root,
        )
        captured: list[StepLeaseToken] = []
        try:
            sup1.create_run_from_plan(
                plan=plan_act, receipt=rec_act, clock=self.clock.advance()
            )
            sup1.create_run_from_plan(
                plan=plan_obs, receipt=rec_obs, clock=self.clock.advance()
            )
            sup1.run_step_once(
                rec_act.run_id,
                "scan",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                clock_provider=self.clock.advance,
            )
            with self.assertRaises(SimulatedSupervisorCrash):
                sup1.run_step_once(
                    rec_act.run_id,
                    "apply_patch",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                    clock_provider=self.clock.advance,
                    crash_point=CrashPoint.AFTER_LEASE_COMMIT_BEFORE_WORKER,
                    captured_tokens=captured,
                )
        finally:
            sup1.simulate_crash()

        sup2, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.advance(),
            tracker=tracker,
            authority_store=None,
            sandbox_root=self.sandbox_root,
        )
        try:
            # Read-only inspection works without authority_store.
            run_act = sup2.journal.get_run(rec_act.run_id)
            self.assertTrue(run_act.requires_authority)
            self.assertEqual(run_act.status, RunStatus.PAUSED_NEEDS_RECONCILE)

            # New dispatch on recovered plan-bound run DENIED without authority_store!
            with self.assertRaises(AuthorityError):
                sup2.run_step_once(
                    rec_obs.run_id,
                    "collect",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                    clock_provider=self.clock.advance,
                )
            self.assertEqual(tracker.count(rec_obs.run_id, "collect"), 0)
            self.assertEqual(
                sup2.journal.get_step(rec_obs.run_id, "collect").status,
                StepStatus.PENDING,
            )

            # Requeue on recovered plan-bound run DENIED without authority_store!
            no_eff = sup2.issue_tracker_receipt(captured[0])
            req_requeue = ReconcileStepRequest(
                run_id=rec_act.run_id,
                step_id="apply_patch",
                expected_attempt_no=1,
                expected_epoch=2,
                reconciliation_key="recon_no_auth_requeue",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=no_eff.receipt_digest,
                reason="try_requeue_no_auth_store",
                clock=self.clock.advance(),
            )
            with self.assertRaises(AuthorityError):
                sup2.reconcile_step(
                    req_requeue,
                    tracker_receipt=no_eff,
                    clock_provider=self.clock.advance,
                )
            self.assertEqual(tracker.count(rec_act.run_id, "apply_patch"), 0)

            # Terminal settlement still succeeds without authority_store.
            settled = sup2.reconcile_step(
                ReconcileStepRequest(
                    run_id=rec_act.run_id,
                    step_id="apply_patch",
                    expected_attempt_no=1,
                    expected_epoch=2,
                    reconciliation_key="recon_no_auth_cancel",
                    resolution=ReconcileResolution.CANCELLED,
                    output_digest=None,
                    evidence_digest=no_eff.receipt_digest,
                    reason="settle_without_auth_store",
                    clock=self.clock.advance(),
                ),
                tracker_receipt=no_eff,
            )
            self.assertFalse(settled.duplicate)
            self.assertEqual(
                sup2.journal.get_run(rec_act.run_id).status, RunStatus.CANCELLED
            )
        finally:
            sup2.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_requeue_pending_omitted_clock_provider_rejected_for_authority_bound_run(
        self,
    ) -> None:
        auth = RunAuthorityStore()
        plan, rec = self._compile_and_admit(
            _ACTIVE_STATECHART_TOML, authority_store=auth, ttl_s=20.0
        )
        tracker = SyntheticEffectTracker()
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            authority_store=auth,
            sandbox_root=self.sandbox_root,
        )
        captured: list[StepLeaseToken] = []
        try:
            sup1.create_run_from_plan(
                plan=plan, receipt=rec, clock=self.clock.advance(1.0)
            )
            sup1.run_step_once(
                rec.run_id,
                "scan",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                clock_provider=self.clock.advance,
            )
            with self.assertRaises(SimulatedSupervisorCrash):
                sup1.run_step_once(
                    rec.run_id,
                    "apply_patch",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                    clock_provider=self.clock.advance,
                    crash_point=CrashPoint.AFTER_LEASE_COMMIT_BEFORE_WORKER,
                    captured_tokens=captured,
                )
        finally:
            sup1.simulate_crash()

        sup2, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.advance(1.0),
            tracker=tracker,
            authority_store=auth,
            sandbox_root=self.sandbox_root,
        )
        try:
            no_eff = sup2.issue_tracker_receipt(captured[0])
            seq_before = sup2.journal.get_meta().last_event_seq
            stale_snap = self.clock.now()
            req = ReconcileStepRequest(
                run_id=rec.run_id,
                step_id="apply_patch",
                expected_attempt_no=1,
                expected_epoch=2,
                reconciliation_key="recon_omit_clock_provider",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=no_eff.receipt_digest,
                reason="omitted_clock_provider",
                clock=stale_snap,
            )
            with self.assertRaises(RestartValidationError):
                sup2.reconcile_step(req, tracker_receipt=no_eff)
            self.assertEqual(sup2.journal.get_meta().last_event_seq, seq_before)
            self.assertEqual(
                sup2.journal.get_step(rec.run_id, "apply_patch").status,
                StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            )

            def _expire_in_tx() -> ClockSnapshot:
                return self.clock.advance(50.0)

            with self.assertRaises(AuthorityError):
                sup2.reconcile_step(
                    req, tracker_receipt=no_eff, clock_provider=_expire_in_tx
                )
            self.assertEqual(sup2.journal.get_meta().last_event_seq, seq_before)
        finally:
            sup2.close_clean(clock=self.clock.advance(1.0))
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_derive_steps_rejects_conditional_transition_and_mixed_state_effects(
        self,
    ) -> None:
        auth = RunAuthorityStore()
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            authority_store=auth,
            sandbox_root=self.sandbox_root,
        )
        try:
            bad_tomls = (
                _CONDITIONAL_TRANSITION_TOML,
                _TRANSITION_EFFECT_TOML,
                _MIXED_EFFECT_STATE_TOML,
                _PURE_ON_MUTATING_SHAPE_TOML,
            )
            for toml_text in bad_tomls:
                plan, rec = self._compile_and_admit(
                    toml_text, authority_store=auth, ttl_s=120.0
                )
                seq_before = sup.journal.get_meta().last_event_seq
                t_now = self.clock.advance()
                with self.assertRaises(RestartPolicyError) as ctx:
                    sup.create_run_from_plan(plan=plan, receipt=rec, clock=t_now)
                self.assertIn(ERR_PLAN_GRAPH_UNSUPPORTED, str(ctx.exception))
                self.assertEqual(sup.journal.get_meta().last_event_seq, seq_before)
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_tracker_run_admitted_concurrent_double_entry_rejected(self) -> None:
        tracker = SyntheticEffectTracker()
        tok = StepLeaseToken("run_conc", "se1", 1, 1, "idem_conc_1")
        tracker.admit_attempt(tok)
        entered = threading.Event()
        release = threading.Event()
        t1_res: list[WorkerStepResult] = []
        t1_err: list[Exception] = []

        def _worker(_t: StepLeaseToken) -> WorkerStepResult:
            entered.set()
            release.wait(timeout=5.0)
            return WorkerStepResult("completed", _DIGEST_A)

        def _run_t1() -> None:
            try:
                t1_res.append(tracker.run_admitted(tok, worker_fn=_worker))
            except Exception as exc:  # pragma: no cover
                t1_err.append(exc)

        th = threading.Thread(target=_run_t1)
        th.start()
        try:
            self.assertTrue(entered.wait(timeout=5.0))
            # While Thread 1 is inside worker_fn, a 2nd run_admitted MUST fail!
            with self.assertRaises(InvalidStepTransitionError):
                tracker.run_admitted(tok, worker_fn=_worker)
            # And a receipt issued while running MUST report still_pending!
            mid_rcpt = tracker.issue_receipt(
                token=tok, current_epoch=1, force_fence=True
            )
            self.assertEqual(mid_rcpt.tracker_outcome, "still_pending")
        finally:
            release.set()
            th.join(timeout=5.0)

        self.assertEqual(t1_err, [])
        self.assertEqual(len(t1_res), 1)
        self.assertEqual(tracker.count("run_conc", "se1"), 1)

    def test_fresh_tracker_missing_prior_history_refuses_requeue_pending(self) -> None:
        tracker1 = SyntheticEffectTracker()
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker1,
            sandbox_root=self.sandbox_root,
        )
        captured: list[StepLeaseToken] = []
        try:
            steps = (StepSpec("se1", "se1", "stage_patch", True),)
            sup1.journal.create_run(self._make_run_request("run_hist", steps))
            with self.assertRaises(SimulatedSupervisorCrash):
                sup1.run_step_once(
                    "run_hist",
                    "se1",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                    clock_provider=self.clock.advance,
                    crash_point=CrashPoint.AFTER_WORKER_EXEC_BEFORE_COMPLETE_COMMIT,
                    captured_tokens=captured,
                )
            self.assertEqual(tracker1.count("run_hist", "se1"), 1)
        finally:
            sup1.simulate_crash()

        # Reopen with a brand-new tracker that has no history before epoch 2!
        tracker2 = SyntheticEffectTracker(history_start_epoch=2)
        sup2, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.advance(),
            tracker=tracker2,
            sandbox_root=self.sandbox_root,
        )
        try:
            rcpt = sup2.issue_tracker_receipt(captured[0])
            self.assertEqual(rcpt.tracker_outcome, "still_pending")
            req_requeue = ReconcileStepRequest(
                run_id="run_hist",
                step_id="se1",
                expected_attempt_no=1,
                expected_epoch=2,
                reconciliation_key="recon_missing_hist",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=rcpt.receipt_digest,
                reason="try_requeue_with_fresh_tracker",
                clock=self.clock.advance(),
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup2.reconcile_step(
                    req_requeue,
                    tracker_receipt=rcpt,
                    clock_provider=self.clock.advance,
                )
            self.assertEqual(tracker2.count("run_hist", "se1"), 0)
            self.assertEqual(
                sup2.journal.get_step("run_hist", "se1").status,
                StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            )
        finally:
            sup2.close_clean(clock=self.clock.advance())

        # Even if a caller omits history_start_epoch on recovery, attach_epoch advances it!
        tracker3 = SyntheticEffectTracker()
        sup3, rep3 = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.advance(),
            tracker=tracker3,
            sandbox_root=self.sandbox_root,
        )
        try:
            self.assertEqual(rep3.supervisor_epoch, 3)
            self.assertEqual(tracker3.history_start_epoch, 3)
            rcpt3 = sup3.issue_tracker_receipt(captured[0])
            self.assertEqual(rcpt3.tracker_outcome, "still_pending")
        finally:
            sup3.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_supervisor_reconcile_completed_requires_verified_tracker_receipt(
        self,
    ) -> None:
        tracker = SyntheticEffectTracker()
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            sandbox_root=self.sandbox_root,
        )
        captured: list[StepLeaseToken] = []
        try:
            steps = (StepSpec("se1", "se1", "stage_patch", True),)
            sup1.journal.create_run(self._make_run_request("run_comp_req", steps))
            with self.assertRaises(SimulatedSupervisorCrash):
                sup1.run_step_once(
                    "run_comp_req",
                    "se1",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                    clock_provider=self.clock.advance,
                    crash_point=CrashPoint.AFTER_WORKER_EXEC_BEFORE_COMPLETE_COMMIT,
                    captured_tokens=captured,
                )
        finally:
            sup1.simulate_crash()

        sup2, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.advance(),
            tracker=tracker,
            sandbox_root=self.sandbox_root,
        )
        try:
            meta_before = sup2.journal.get_meta()
            applied_rcpt = sup2.issue_tracker_receipt(captured[0])
            req = ReconcileStepRequest(
                run_id="run_comp_req",
                step_id="se1",
                expected_attempt_no=1,
                expected_epoch=2,
                reconciliation_key="recon_comp_missing_rcpt",
                resolution=ReconcileResolution.COMPLETED,
                output_digest=_DIGEST_A,
                evidence_digest=applied_rcpt.receipt_digest,
                reason="claim_completed_without_receipt",
                clock=self.clock.advance(),
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup2.reconcile_step(req, tracker_receipt=None)
            meta_after = sup2.journal.get_meta()
            self.assertEqual(meta_after.last_event_seq, meta_before.last_event_seq)
            self.assertEqual(meta_after.head_hash, meta_before.head_hash)
            self.assertEqual(
                sup2.journal.get_step("run_comp_req", "se1").status,
                StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            )

            # With verified receipt, COMPLETED succeeds cleanly!
            ok = sup2.reconcile_step(req, tracker_receipt=applied_rcpt)
            self.assertFalse(ok.duplicate)
            self.assertEqual(
                sup2.journal.get_run("run_comp_req").status, RunStatus.COMPLETED
            )
        finally:
            sup2.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_uncertain_sibling_does_not_strand_leased_sibling_settlement(self) -> None:
        journal, _ = WorkflowRestartJournal.open_and_recover(
            self.state_dir, clock=self.clock.now(), sandbox_root=self.sandbox_root
        )
        try:
            steps = (
                StepSpec("step_a", "step_a", "stage_patch", True),
                StepSpec("step_b", "step_b", "read_metrics", False),
                StepSpec("step_c", "step_c", "read_metrics", False),
            )
            journal.create_run(self._make_run_request("run_sib", steps))
            tok_a = journal.lease_step(
                run_id="run_sib", step_id="step_a", clock=self.clock.advance()
            )
            tok_b = journal.lease_step(
                run_id="run_sib", step_id="step_b", clock=self.clock.advance()
            )
            journal.fail_step(
                FailStepRequest(tok_a, "net_drop", False, True, self.clock.advance())
            )
            self.assertEqual(
                journal.get_run("run_sib").status, RunStatus.PAUSED_NEEDS_RECONCILE
            )

            # New admission remains blocked while paused_needs_reconcile.
            t_blocked = self.clock.advance()
            with self.assertRaises(InvalidStepTransitionError):
                journal.lease_step(
                    run_id="run_sib", step_id="step_c", clock=t_blocked
                )

            # Already-leased sibling settles cleanly with its exact owned token!
            ack_b = journal.complete_step(
                CompleteStepRequest(tok_b, _DIGEST_B, self.clock.advance())
            )
            self.assertEqual(ack_b.status, StepStatus.COMPLETED.value)
            self.assertEqual(
                journal.get_step("run_sib", "step_b").status, StepStatus.COMPLETED
            )
            self.assertEqual(
                journal.get_run("run_sib").status, RunStatus.PAUSED_NEEDS_RECONCILE
            )

            # Reconcile step_a -> run returns to RUNNING for step_c!
            journal.reconcile_step(
                ReconcileStepRequest(
                    run_id="run_sib",
                    step_id="step_a",
                    expected_attempt_no=1,
                    expected_epoch=1,
                    reconciliation_key="recon_sib_a",
                    resolution=ReconcileResolution.COMPLETED,
                    output_digest=_DIGEST_A,
                    evidence_digest=_DIGEST_E,
                    reason="sib_a_confirmed",
                    clock=self.clock.advance(),
                )
            )
            self.assertEqual(journal.get_run("run_sib").status, RunStatus.RUNNING)
        finally:
            journal.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_tampered_missing_pk_and_duplicate_materialized_rows_rejected(self) -> None:
        j, _ = WorkflowRestartJournal.open_and_recover(
            self.state_dir, clock=self.clock.now(), sandbox_root=self.sandbox_root
        )
        try:
            j.create_run(
                self._make_run_request(
                    "run_pk_dup", (StepSpec("s1", "s1", "read_metrics", False),)
                )
            )
        finally:
            j.close_clean(clock=self.clock.advance())
        db_path = self.state_dir / DB_FILENAME
        conn = sqlite3.connect(str(db_path), isolation_level=None)
        try:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute(
                "CREATE TABLE workflow_steps_dup AS SELECT * FROM workflow_steps"
            )
            conn.execute("DROP TABLE workflow_steps")
            conn.execute("ALTER TABLE workflow_steps_dup RENAME TO workflow_steps")
            conn.execute(
                "INSERT INTO workflow_steps SELECT * FROM workflow_steps LIMIT 1"
            )
        finally:
            conn.close()

        # 1. Read-only replay fails closed on missing PRIMARY KEY via PRAGMA table_info.
        with self.assertRaises(JournalIntegrityError):
            verify_journal_replay_readonly(
                self.state_dir, sandbox_root=self.sandbox_root
            )

        # 2. Direct parity reader also rejects duplicate keys even with generous max_rows!
        ro_conn = open_sqlite_bounded(
            db_path, readonly=True, deadline=time.monotonic() + 2.0
        )
        try:
            dl = time.monotonic() + 2.0
            with self.assertRaises(JournalIntegrityError):
                read_steps_strict(ro_conn, max_rows=10, deadline=dl)
        finally:
            safe_rollback_and_close(ro_conn)

    def test_reduce_event_log_enforces_monotonic_deadline(self) -> None:
        p1 = {
            "dirty_recovery": False,
            "journal_id": _TEST_JOURNAL_ID,
            "prior_epoch": 0,
        }
        h1 = compute_event_hash(
            seq=1,
            supervisor_epoch=1,
            event_type=EventType.SUPERVISOR_STARTED.value,
            run_id=None,
            step_id=None,
            payload=p1,
            created_at_us=1_000,
            prev_hash=EVENT_GENESIS_HASH,
        )
        e1 = JournalEvent(
            seq=1,
            supervisor_epoch=1,
            event_type=EventType.SUPERVISOR_STARTED,
            run_id=None,
            step_id=None,
            payload=p1,
            created_at_us=1_000,
            prev_hash=EVENT_GENESIS_HASH,
            entry_hash=h1,
        )
        h2 = compute_event_hash(
            seq=2,
            supervisor_epoch=1,
            event_type=EventType.SUPERVISOR_STOPPED.value,
            run_id=None,
            step_id=None,
            payload={},
            created_at_us=2_000,
            prev_hash=h1,
        )
        e2 = JournalEvent(
            seq=2,
            supervisor_epoch=1,
            event_type=EventType.SUPERVISOR_STOPPED,
            run_id=None,
            step_id=None,
            payload={},
            created_at_us=2_000,
            prev_hash=h1,
            entry_hash=h2,
        )
        expired = time.monotonic() - 1.0
        with self.assertRaises(RestartStorageError) as ctx:
            reduce_event_log([e1, e2], deadline=expired)
        self.assertIn(ERR_OP_DEADLINE, str(ctx.exception))

        snap = reduce_event_log([e1, e2])
        meta = SupervisorMetaRecord(
            current_epoch=snap.supervisor_epoch,
            last_event_seq=snap.last_event_seq,
            head_hash=snap.head_hash,
            dirty_shutdown=snap.dirty_shutdown,
            updated_at_us=snap.meta_updated_at_us,
        )
        with self.assertRaises(RestartStorageError) as ctx2:
            verify_materialized_parity(
                meta=meta,
                replayed=snap,
                actual_runs=snap.runs,
                actual_steps=snap.steps,
                actual_idems=snap.idempotency_records,
                actual_recons=snap.reconciliation_records,
                deadline=expired,
            )
        self.assertIn(ERR_OP_DEADLINE, str(ctx2.exception))

    def test_tampered_indexes_dropped_unique_and_mutating_non_side_effecting_rejected(
        self,
    ) -> None:
        tamper_sqls = (
            "CREATE INDEX evil_bomb ON workflow_event_log(zeroblob(1000000))",
            "CREATE UNIQUE INDEX evil_lockout ON workflow_event_log(1) WHERE seq > 10",
            (
                "PRAGMA foreign_keys = OFF; "
                "CREATE TABLE idem_no_uniq ("
                "run_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, "
                "step_id TEXT NOT NULL, attempt_no INTEGER NOT NULL, "
                "lease_epoch INTEGER NOT NULL, outcome_status TEXT NOT NULL, "
                "output_digest TEXT, failure_reason TEXT, recorded_seq INTEGER NOT NULL, "
                "PRIMARY KEY (run_id, idempotency_key)); "
                "INSERT INTO idem_no_uniq SELECT * FROM step_idempotency_keys; "
                "DROP TABLE step_idempotency_keys; "
                "ALTER TABLE idem_no_uniq RENAME TO step_idempotency_keys;"
            ),
        )
        for idx, sql in enumerate(tamper_sqls):
            sub_dir = self.root / f"idx_tamper_{idx}"
            sub_dir.mkdir(mode=0o700)
            os.chmod(sub_dir, 0o700)
            j, _ = WorkflowRestartJournal.open_and_recover(
                sub_dir, clock=self.clock.advance(), sandbox_root=self.sandbox_root
            )
            j.close_clean(clock=self.clock.advance())
            conn = sqlite3.connect(str(sub_dir / DB_FILENAME), isolation_level=None)
            try:
                conn.executescript(sql)
            finally:
                conn.close()
            with self.assertRaises(JournalIntegrityError):
                verify_journal_replay_readonly(sub_dir, sandbox_root=self.sandbox_root)

        # Single-row lookup rejects duplicate PKs AND _decode_step_row rejects mutating side_effecting=0!
        dup_dir = self.root / "single_row_and_se_tamper"
        dup_dir.mkdir(mode=0o700)
        os.chmod(dup_dir, 0o700)
        j2, _ = WorkflowRestartJournal.open_and_recover(
            dup_dir, clock=self.clock.advance(), sandbox_root=self.sandbox_root
        )
        try:
            j2.create_run(
                self._make_run_request(
                    "run_se_chk", (StepSpec("s1", "s1", "stage_patch", True),)
                )
            )
        finally:
            j2.close_clean(clock=self.clock.advance())
        db_path = dup_dir / DB_FILENAME
        conn2 = sqlite3.connect(str(db_path), isolation_level=None)
        try:
            conn2.execute("UPDATE workflow_steps SET side_effecting = 0 WHERE step_id = 's1'")
        finally:
            conn2.close()
        ro1 = open_sqlite_bounded(db_path, readonly=True, deadline=time.monotonic() + 2.0)
        try:
            dl = time.monotonic() + 2.0
            with self.assertRaises(JournalIntegrityError):
                read_step_by_pk_strict(ro1, "run_se_chk", "s1", dl)
        finally:
            safe_rollback_and_close(ro1)

        conn3 = sqlite3.connect(str(db_path), isolation_level=None)
        try:
            conn3.execute("PRAGMA foreign_keys = OFF")
            conn3.execute("UPDATE workflow_steps SET side_effecting = 1 WHERE step_id = 's1'")
            conn3.execute("CREATE TABLE ws_dup AS SELECT * FROM workflow_steps")
            conn3.execute("DROP TABLE workflow_steps")
            conn3.execute("ALTER TABLE ws_dup RENAME TO workflow_steps")
            conn3.execute("INSERT INTO workflow_steps SELECT * FROM workflow_steps LIMIT 1")
        finally:
            conn3.close()
        ro2 = open_sqlite_bounded(db_path, readonly=True, deadline=time.monotonic() + 2.0)
        try:
            dl = time.monotonic() + 2.0
            with self.assertRaises(JournalIntegrityError):
                read_step_by_pk_strict(ro2, "run_se_chk", "s1", dl)
        finally:
            safe_rollback_and_close(ro2)

    @staticmethod
    def _build_event(
        *,
        seq: int,
        epoch: int,
        event_type: EventType,
        prev_hash: str,
        payload: dict[str, Any],
        run_id: str | None = None,
        step_id: str | None = None,
    ) -> JournalEvent:
        ehash = compute_event_hash(
            seq=seq,
            supervisor_epoch=epoch,
            event_type=event_type.value,
            run_id=run_id,
            step_id=step_id,
            payload=payload,
            created_at_us=seq * 1_000,
            prev_hash=prev_hash,
        )
        return JournalEvent(
            seq=seq,
            supervisor_epoch=epoch,
            event_type=event_type,
            run_id=run_id,
            step_id=step_id,
            payload=payload,
            created_at_us=seq * 1_000,
            prev_hash=prev_hash,
            entry_hash=ehash,
        )

    def test_replay_strict_payload_keys_bool_int_confusion_and_malformed_steps_rejected(
        self,
    ) -> None:
        # 1. Bool-for-int confusion (prior_epoch: False == 0) & extra key on genesis started.
        bad_genesis_payloads: tuple[dict[str, Any], ...] = (
            {
                "dirty_recovery": False,
                "journal_id": _TEST_JOURNAL_ID,
                "prior_epoch": False,
            },
            {
                "dirty_recovery": False,
                "journal_id": _TEST_JOURNAL_ID,
                "prior_epoch": 0,
                "extra": 1,
            },
        )
        for bad_p in bad_genesis_payloads:
            ev = self._build_event(
                seq=1,
                epoch=1,
                event_type=EventType.SUPERVISOR_STARTED,
                prev_hash=EVENT_GENESIS_HASH,
                payload=bad_p,
            )
            with self.assertRaises(ReplayMismatchError):
                reduce_event_log([ev])

        e1 = self._build_event(
            seq=1,
            epoch=1,
            event_type=EventType.SUPERVISOR_STARTED,
            prev_hash=EVENT_GENESIS_HASH,
            payload={
                "dirty_recovery": False,
                "journal_id": _TEST_JOURNAL_ID,
                "prior_epoch": 0,
            },
        )
        good_step = StepSpec("s1", "s1", "read_metrics", False).to_payload_dict()

        # 2. Malformed RUN_CREATED payloads (non-dict step, missing key, bad depends_on, extra key).
        bad_run_payloads: tuple[dict[str, Any], ...] = (
            {
                "grant_generation": 1,
                "requires_authority": False,
                "spec_digest": _DIGEST_1,
                "steps": ["not_a_dict"],
                "workflow_id": "user/w",
                "workflow_plan_digest": _DIGEST_2,
            },
            {
                "grant_generation": 1,
                "requires_authority": False,
                "spec_digest": _DIGEST_1,
                "steps": [{"step_id": "s1"}],
                "workflow_id": "user/w",
                "workflow_plan_digest": _DIGEST_2,
            },
            {
                "grant_generation": 1,
                "requires_authority": False,
                "spec_digest": _DIGEST_1,
                "steps": [{**good_step, "depends_on": "not_a_list"}],
                "workflow_id": "user/w",
                "workflow_plan_digest": _DIGEST_2,
            },
            {
                "grant_generation": 1,
                "requires_authority": False,
                "spec_digest": _DIGEST_1,
                "steps": [good_step],
                "workflow_id": "user/w",
                "workflow_plan_digest": _DIGEST_2,
                "unexpected": 99,
            },
        )
        for bad_rp in bad_run_payloads:
            e2 = self._build_event(
                seq=2,
                epoch=1,
                event_type=EventType.RUN_CREATED,
                prev_hash=e1.entry_hash,
                run_id="r1",
                payload=bad_rp,
            )
            with self.assertRaises(ReplayMismatchError):
                reduce_event_log([e1, e2])

        # 3. Bool-for-int confusion (attempt_no: True == 1) & extra key on STEP_COMPLETED.
        e2_ok = self._build_event(
            seq=2,
            epoch=1,
            event_type=EventType.RUN_CREATED,
            prev_hash=e1.entry_hash,
            run_id="r1",
            payload={
                "grant_generation": 1,
                "requires_authority": False,
                "spec_digest": _DIGEST_1,
                "steps": [good_step],
                "workflow_id": "user/w",
                "workflow_plan_digest": _DIGEST_2,
            },
        )
        e3_lease = self._build_event(
            seq=3,
            epoch=1,
            event_type=EventType.STEP_LEASED,
            prev_hash=e2_ok.entry_hash,
            run_id="r1",
            step_id="s1",
            payload={
                "attempt_no": 1,
                "idempotency_key": "k_bool_test",
                "lease_epoch": 1,
                "side_effecting": False,
            },
        )
        bad_comp_payloads: tuple[dict[str, Any], ...] = (
            {
                "attempt_no": True,
                "idempotency_key": "k_bool_test",
                "lease_epoch": 1,
                "output_digest": _DIGEST_A,
            },
            {
                "attempt_no": 1,
                "idempotency_key": "k_bool_test",
                "lease_epoch": True,
                "output_digest": _DIGEST_A,
            },
            {
                "attempt_no": 1,
                "idempotency_key": "k_bool_test",
                "lease_epoch": 1,
                "output_digest": _DIGEST_A,
                "extra_field": 1,
            },
        )
        for bad_cp in bad_comp_payloads:
            e4 = self._build_event(
                seq=4,
                epoch=1,
                event_type=EventType.STEP_COMPLETED,
                prev_hash=e3_lease.entry_hash,
                run_id="r1",
                step_id="s1",
                payload=bad_cp,
            )
            with self.assertRaises(ReplayMismatchError):
                reduce_event_log([e1, e2_ok, e3_lease, e4])

    def test_supervisor_reconcile_step_invalid_request_type_raises_validation_error(
        self,
    ) -> None:
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            sandbox_root=self.sandbox_root,
        )
        try:
            bad_req: Any = "not_a_reconcile_request"
            with self.assertRaises(RestartValidationError):
                sup.reconcile_step(bad_req)
        finally:
            sup.close_clean(clock=self.clock.advance())


_WAIT_SIGNAL_TOML = _OBSERVE_ONLY_TOML.replace(
    'name = "project"\nshape = "observe"\neffects = ["update_health_projection"]',
    'name = "await_sig"\nshape = "wait_signal"\neffects = []',
).replace('dst = "project"', 'dst = "await_sig"')


class _ClockAdvancingMapping(Mapping[Any, Any]):
    """Mapping proxy that advances a fake monotonic clock when compared for equality."""

    def __init__(self, inner: Mapping[Any, Any], on_eq: Callable[[], None]) -> None:
        self._inner = dict(inner)
        self._on_eq = on_eq

    def __getitem__(self, key: Any) -> Any:
        return self._inner[key]

    def __iter__(self) -> Iterator[Any]:
        return iter(self._inner)

    def __len__(self) -> int:
        return len(self._inner)

    def __eq__(self, other: object) -> bool:
        self._on_eq()
        return self._inner == other


class TestAdversarialRegressionsRound3(_RestartFixtureBase):
    def test_discontinuous_tracker_epoch_history_refuses_requeue_pending(self) -> None:
        # Epoch 1: tracker_a observes epoch 1 and closes cleanly.
        tracker_a = SyntheticEffectTracker()
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker_a,
            sandbox_root=self.sandbox_root,
        )
        try:
            sup1.journal.create_run(
                self._make_run_request(
                    "run_gap", (StepSpec("se1", "se1", "stage_patch", True),)
                )
            )
            self.assertEqual(tracker_a.observed_epochs, frozenset({1}))
        finally:
            sup1.close_clean(clock=self.clock.advance())

        # Epoch 2: tracker_b handles epoch 2, executes side effect, crashes before commit!
        tracker_b = SyntheticEffectTracker()
        sup2, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.advance(),
            tracker=tracker_b,
            sandbox_root=self.sandbox_root,
        )
        captured: list[StepLeaseToken] = []
        try:
            with self.assertRaises(SimulatedSupervisorCrash):
                sup2.run_step_once(
                    "run_gap",
                    "se1",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                    clock_provider=self.clock.advance,
                    crash_point=CrashPoint.AFTER_WORKER_EXEC_BEFORE_COMPLETE_COMMIT,
                    captured_tokens=captured,
                )
            self.assertEqual(tracker_b.count("run_gap", "se1"), 1)
        finally:
            sup2.simulate_crash()

        # Epoch 3: tracker_a re-attaches at epoch 3 (observed {1, 3}, NEVER observed 2!).
        sup3, rep3 = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.advance(),
            tracker=tracker_a,
            sandbox_root=self.sandbox_root,
        )
        try:
            self.assertEqual(rep3.supervisor_epoch, 3)
            self.assertEqual(tracker_a.observed_epochs, frozenset({1, 3}))
            rcpt = sup3.issue_tracker_receipt(captured[0])
            self.assertEqual(rcpt.tracker_outcome, "still_pending")
            req_requeue = ReconcileStepRequest(
                run_id="run_gap",
                step_id="se1",
                expected_attempt_no=1,
                expected_epoch=3,
                reconciliation_key="recon_gap_requeue",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=rcpt.receipt_digest,
                reason="try_requeue_across_epoch_gap",
                clock=self.clock.advance(),
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup3.reconcile_step(
                    req_requeue,
                    tracker_receipt=rcpt,
                    clock_provider=self.clock.advance,
                )
            self.assertEqual(tracker_a.count("run_gap", "se1"), 0)
        finally:
            sup3.close_clean(clock=self.clock.advance())

        # Direct supervisor construction also records observed_epochs in __init__.
        j4, _ = WorkflowRestartJournal.open_and_recover(
            self.state_dir, clock=self.clock.advance(), sandbox_root=self.sandbox_root
        )
        tracker_direct = SyntheticEffectTracker()
        sup4 = DurableWorkflowSupervisor(j4, tracker=tracker_direct)
        try:
            self.assertEqual(tracker_direct.observed_epochs, frozenset({4}))
            self.assertEqual(
                sup4.issue_tracker_receipt(captured[0]).tracker_outcome,
                "still_pending",
            )
        finally:
            sup4.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_derive_steps_rejects_wait_signal_state_before_journal_write(self) -> None:
        auth = RunAuthorityStore()
        plan, rec = self._compile_and_admit(
            _WAIT_SIGNAL_TOML, authority_store=auth, ttl_s=120.0
        )
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            authority_store=auth,
            sandbox_root=self.sandbox_root,
        )
        try:
            seq_before = sup.journal.get_meta().last_event_seq
            t_now = self.clock.advance()
            with self.assertRaises(RestartPolicyError) as ctx:
                sup.create_run_from_plan(plan=plan, receipt=rec, clock=t_now)
            self.assertIn(ERR_PLAN_GRAPH_UNSUPPORTED, str(ctx.exception))
            self.assertEqual(sup.journal.get_meta().last_event_seq, seq_before)
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_nocase_collation_tamper_rejected_at_admission_and_binary_lookup_enforced(
        self,
    ) -> None:
        j, _ = WorkflowRestartJournal.open_and_recover(
            self.state_dir, clock=self.clock.now(), sandbox_root=self.sandbox_root
        )
        try:
            j.create_run(
                self._make_run_request(
                    "RunMixedCase", (StepSpec("s1", "s1", "read_metrics", False),)
                )
            )
        finally:
            seq_before = j.close_clean(clock=self.clock.advance())

        db_path = self.state_dir / DB_FILENAME
        conn = sqlite3.connect(str(db_path), isolation_level=None)
        try:
            conn.executescript(
                "PRAGMA foreign_keys = OFF; "
                "CREATE TABLE wr_nocase ("
                "run_id TEXT PRIMARY KEY COLLATE NOCASE, "
                "workflow_id TEXT NOT NULL, spec_digest TEXT NOT NULL, "
                "workflow_plan_digest TEXT NOT NULL, "
                "grant_generation INTEGER NOT NULL, "
                "requires_authority INTEGER NOT NULL DEFAULT 0, "
                "status TEXT NOT NULL, cancel_requested INTEGER NOT NULL DEFAULT 0, "
                "created_epoch INTEGER NOT NULL, created_at_us INTEGER NOT NULL, "
                "updated_at_us INTEGER NOT NULL); "
                "INSERT INTO wr_nocase SELECT * FROM workflow_runs; "
                "DROP TABLE workflow_runs; "
                "ALTER TABLE wr_nocase RENAME TO workflow_runs;"
            )
        finally:
            conn.close()

        # 1. Read-only replay & recovery BOTH reject COLLATE NOCASE with JournalIntegrityError!
        with self.assertRaises(JournalIntegrityError):
            verify_journal_replay_readonly(
                self.state_dir, sandbox_root=self.sandbox_root
            )
        t_rec = self.clock.advance()
        with self.assertRaises(JournalIntegrityError):
            WorkflowRestartJournal.open_and_recover(
                self.state_dir, clock=t_rec, sandbox_root=self.sandbox_root
            )

        # 2. Event log remained untouched AND direct COLLATE BINARY lookup rejects wrong case!
        ro = open_sqlite_bounded(
            db_path, readonly=True, deadline=time.monotonic() + 2.0
        )
        try:
            dl = time.monotonic() + 2.0
            ev_count = ro.execute("SELECT COUNT(*) AS c FROM workflow_event_log").fetchone()["c"]
            self.assertEqual(ev_count, seq_before)
            self.assertIsNone(read_run_by_id_strict(ro, "runmixedcase", dl))
            exact = read_run_by_id_strict(ro, "RunMixedCase", dl)
            self.assertIsNotNone(exact)
            assert exact is not None
            self.assertEqual(exact.run_id, "RunMixedCase")
        finally:
            safe_rollback_and_close(ro)

    def test_paused_sibling_settles_pre_entry_and_pure_retryable_without_stranding(
        self,
    ) -> None:
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            sandbox_root=self.sandbox_root,
        )
        try:
            # (a) Sibling becomes uncertain between step_b lease and pre-entry gate.
            steps_a = (
                StepSpec("step_a", "step_a", "stage_patch", True),
                StepSpec("step_b", "step_b", "stage_patch", True),
            )
            sup.journal.create_run(self._make_run_request("run_pause_pre", steps_a))
            tok_a1 = sup.journal.lease_step(
                run_id="run_pause_pre", step_id="step_a", clock=self.clock.advance()
            )

            def _pause_before_entry(_tok: StepLeaseToken) -> None:
                sup.journal.fail_step(
                    FailStepRequest(
                        tok_a1, "sibling_uncertain", False, True, self.clock.advance()
                    )
                )

            with self.assertRaises(InvalidStepTransitionError) as ctx:
                sup.run_step_once(
                    "run_pause_pre",
                    "step_b",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                    clock_provider=self.clock.advance,
                    on_after_lease_before_entry=_pause_before_entry,
                )
            self.assertIn("run_paused_before_worker_entry", str(ctx.exception))
            self.assertEqual(tracker.count("run_pause_pre", "step_b"), 0)
            step_b_rec = sup.journal.get_step("run_pause_pre", "step_b")
            self.assertEqual(step_b_rec.status, StepStatus.FAILED_TERMINAL)
            self.assertEqual(step_b_rec.failure_reason, "run_paused_before_worker_entry")

            # (b) Pure worker returns retryable failure after sibling transitioned run to paused.
            steps_b = (
                StepSpec("step_a", "step_a", "stage_patch", True),
                StepSpec("step_pure", "step_pure", "read_metrics", False),
            )
            sup.journal.create_run(self._make_run_request("run_pause_mid", steps_b))
            tok_a2 = sup.journal.lease_step(
                run_id="run_pause_mid", step_id="step_a", clock=self.clock.advance()
            )

            def _pure_worker_mid_pause(_tok: StepLeaseToken) -> WorkerStepResult:
                sup.journal.fail_step(
                    FailStepRequest(
                        tok_a2, "sibling_mid_uncertain", False, True, self.clock.advance()
                    )
                )
                return WorkerStepResult("failed_retryable", reason="transient_net")

            outcome = sup.run_step_once(
                "run_pause_mid",
                "step_pure",
                worker_fn=_pure_worker_mid_pause,
                clock_provider=self.clock.advance,
            )
            self.assertEqual(outcome.ack.status, StepStatus.FAILED_TERMINAL.value)
            pure_rec = sup.journal.get_step("run_pause_mid", "step_pure")
            self.assertEqual(pure_rec.status, StepStatus.FAILED_TERMINAL)
            self.assertIn("run_paused_mid_step", str(pure_rec.failure_reason))
            self.assertEqual(
                sup.journal.get_run("run_pause_mid").status,
                RunStatus.PAUSED_NEEDS_RECONCILE,
            )
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_no_intervening_get_step_between_admit_attempt_and_worker_entry(
        self,
    ) -> None:
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            sandbox_root=self.sandbox_root,
        )
        try:
            sup.journal.create_run(
                self._make_run_request(
                    "run_no_get", (StepSpec("se1", "se1", "stage_patch", True),)
                )
            )
            admitted = False
            orig_admit = tracker.admit_attempt
            orig_get_step = sup.journal.get_step

            def _tracked_admit(tok: StepLeaseToken, **kwargs: Any) -> None:
                nonlocal admitted
                orig_admit(tok, **kwargs)
                admitted = True

            def _forbid_get_step_after_admit(
                run_id: str, step_id: str, *, max_op_ms: int = 2_000
            ) -> Any:
                if admitted:
                    raise RuntimeError("intervening_get_step_forbidden")
                return orig_get_step(run_id, step_id, max_op_ms=max_op_ms)

            with (
                mock.patch.object(tracker, "admit_attempt", side_effect=_tracked_admit),
                mock.patch.object(
                    sup.journal, "get_step", side_effect=_forbid_get_step_after_admit
                ),
            ):
                out = sup.run_step_once(
                    "run_no_get",
                    "se1",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                    clock_provider=self.clock.advance,
                )
            self.assertTrue(admitted)
            self.assertEqual(out.ack.status, StepStatus.COMPLETED.value)
            self.assertEqual(tracker.count("run_no_get", "se1"), 1)
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_final_deadline_check_after_reconciliation_parity_comparison(self) -> None:
        e1 = TestAdversarialRegressionsRound2._build_event(
            seq=1,
            epoch=1,
            event_type=EventType.SUPERVISOR_STARTED,
            prev_hash=EVENT_GENESIS_HASH,
            payload={
                "dirty_recovery": False,
                "journal_id": _TEST_JOURNAL_ID,
                "prior_epoch": 0,
            },
        )
        e2 = TestAdversarialRegressionsRound2._build_event(
            seq=2,
            epoch=1,
            event_type=EventType.SUPERVISOR_STOPPED,
            prev_hash=e1.entry_hash,
            payload={},
        )
        snap = reduce_event_log([e1, e2])
        meta = SupervisorMetaRecord(
            current_epoch=snap.supervisor_epoch,
            last_event_seq=snap.last_event_seq,
            head_hash=snap.head_hash,
            dirty_shutdown=snap.dirty_shutdown,
            updated_at_us=snap.meta_updated_at_us,
        )
        fake_now = [5.0]

        def _cross_deadline() -> None:
            fake_now[0] = 15.0

        slow_recons = _ClockAdvancingMapping(snap.reconciliation_records, _cross_deadline)
        with (
            mock.patch("oc_restart_contract.time.monotonic", side_effect=lambda: fake_now[0]),
            self.assertRaises(RestartStorageError) as ctx,
        ):
            verify_materialized_parity(
                meta=meta,
                replayed=snap,
                actual_runs=snap.runs,
                actual_steps=snap.steps,
                actual_idems=snap.idempotency_records,
                actual_recons=slow_recons,
                deadline=10.0,
            )
        self.assertIn(ERR_OP_DEADLINE, str(ctx.exception))


class TestAdversarialRegressionsRound4(_RestartFixtureBase):
    def test_uncertain_pause_and_worker_admission_serialized_under_lifecycle_gate(
        self,
    ) -> None:
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            sandbox_root=self.sandbox_root,
        )
        try:
            # Ordering 1: step_b wins _lifecycle_gate; sibling step_a tries to commit
            # WORKER_FAILED_UNCERTAIN in the gap AFTER verify_lease_for_entry and
            # BEFORE tracker.admit_attempt -> MUST block until step_b finishes admission!
            steps1 = (
                StepSpec("step_a", "step_a", "stage_patch", True),
                StepSpec("step_b", "step_b", "stage_patch", True),
                StepSpec("step_c", "step_c", "stage_patch", True),
            )
            sup.journal.create_run(self._make_run_request("run_ser_1", steps1))
            a_entered = threading.Event()
            release_a = threading.Event()
            a_settled = threading.Event()
            a_errors: list[Exception] = []

            def _worker_a(_tok: StepLeaseToken) -> WorkerStepResult:
                a_entered.set()
                release_a.wait(timeout=5.0)
                return WorkerStepResult("failed_uncertain", reason="sibling_drop")

            def _run_a() -> None:
                try:
                    sup.run_step_once(
                        "run_ser_1",
                        "step_a",
                        worker_fn=_worker_a,
                        clock_provider=self.clock.advance,
                    )
                except Exception as exc:  # pragma: no cover
                    a_errors.append(exc)
                finally:
                    a_settled.set()

            th_a = threading.Thread(target=_run_a)
            th_a.start()
            self.assertTrue(a_entered.wait(timeout=5.0))

            orig_verify = sup.journal.verify_lease_for_entry
            a_settled_before_admit: list[bool] = []

            def _verify_with_pause_race(
                tok: StepLeaseToken, *, max_op_ms: int = 2_000
            ) -> Any:
                res = orig_verify(tok, max_op_ms=max_op_ms)
                if tok.run_id == "run_ser_1" and tok.step_id == "step_b":
                    release_a.set()
                    a_settled_before_admit.append(a_settled.wait(timeout=0.15))
                return res

            with mock.patch.object(
                sup.journal, "verify_lease_for_entry", side_effect=_verify_with_pause_race
            ):
                out_b = sup.run_step_once(
                    "run_ser_1",
                    "step_b",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                    clock_provider=self.clock.advance,
                )
            th_a.join(timeout=5.0)
            self.assertEqual(a_errors, [])
            self.assertEqual(a_settled_before_admit, [False])
            self.assertEqual(out_b.ack.status, StepStatus.COMPLETED.value)
            self.assertEqual(tracker.count("run_ser_1", "step_b"), 1)
            self.assertEqual(
                sup.journal.get_step("run_ser_1", "step_a").status,
                StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            )
            self.assertEqual(
                sup.journal.get_run("run_ser_1").status,
                RunStatus.PAUSED_NEEDS_RECONCILE,
            )
            t_c = self.clock.advance()
            with self.assertRaises(InvalidStepTransitionError):
                sup.journal.lease_step(
                    run_id="run_ser_1", step_id="step_c", clock=t_c
                )

            # Ordering 2: step_a commits WORKER_FAILED_UNCERTAIN BEFORE step_b enters
            # _enter_worker_under_gate -> step_b settles FAILED_TERMINAL with 0 worker calls!
            steps2 = (
                StepSpec("step_a", "step_a", "stage_patch", True),
                StepSpec("step_b", "step_b", "stage_patch", True),
            )
            sup.journal.create_run(self._make_run_request("run_ser_2", steps2))
            a2_entered = threading.Event()
            release_a2 = threading.Event()
            a2_errors: list[Exception] = []

            def _worker_a2(_tok: StepLeaseToken) -> WorkerStepResult:
                a2_entered.set()
                release_a2.wait(timeout=5.0)
                return WorkerStepResult("failed_uncertain", reason="sibling_drop_2")

            def _run_a2() -> None:
                try:
                    sup.run_step_once(
                        "run_ser_2",
                        "step_a",
                        worker_fn=_worker_a2,
                        clock_provider=self.clock.advance,
                    )
                except Exception as exc:  # pragma: no cover
                    a2_errors.append(exc)

            th_a2 = threading.Thread(target=_run_a2)
            th_a2.start()
            self.assertTrue(a2_entered.wait(timeout=5.0))

            def _let_pause_win(_tok: StepLeaseToken) -> None:
                release_a2.set()
                th_a2.join(timeout=5.0)

            with self.assertRaises(InvalidStepTransitionError) as ctx:
                sup.run_step_once(
                    "run_ser_2",
                    "step_b",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                    clock_provider=self.clock.advance,
                    on_after_lease_before_entry=_let_pause_win,
                )
            self.assertEqual(a2_errors, [])
            self.assertIn("run_paused_before_worker_entry", str(ctx.exception))
            self.assertEqual(tracker.count("run_ser_2", "step_b"), 0)
            self.assertEqual(
                sup.journal.get_step("run_ser_2", "step_b").status,
                StepStatus.FAILED_TERMINAL,
            )
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)

    def test_tracker_sticky_journal_lineage_refuses_foreign_journal_requeue(
        self,
    ) -> None:
        dir_a = self.root / "journal_a"
        dir_b = self.root / "journal_b"
        for d in (dir_a, dir_b):
            d.mkdir(mode=0o700)
            os.chmod(d, 0o700)

        # Journal A: tracker_a observes epoch 1 and binds stickily to Journal A.
        tracker_a = SyntheticEffectTracker()
        sup_a, _ = DurableWorkflowSupervisor.start_or_recover(
            dir_a,
            clock=self.clock.now(),
            tracker=tracker_a,
            sandbox_root=self.sandbox_root,
        )
        try:
            sup_a.journal.create_run(
                self._make_run_request(
                    "run_a", (StepSpec("se1", "se1", "stage_patch", True),)
                )
            )
        finally:
            sup_a.close_clean(clock=self.clock.advance())

        # Journal B: tracker_b executes epoch-1 side-effecting step and crashes before commit!
        tracker_b = SyntheticEffectTracker()
        sup_b1, _ = DurableWorkflowSupervisor.start_or_recover(
            dir_b,
            clock=self.clock.advance(),
            tracker=tracker_b,
            sandbox_root=self.sandbox_root,
        )
        captured_b: list[StepLeaseToken] = []
        try:
            sup_b1.journal.create_run(
                self._make_run_request(
                    "run_b", (StepSpec("se1", "se1", "stage_patch", True),)
                )
            )
            with self.assertRaises(SimulatedSupervisorCrash):
                sup_b1.run_step_once(
                    "run_b",
                    "se1",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                    clock_provider=self.clock.advance,
                    crash_point=CrashPoint.AFTER_WORKER_EXEC_BEFORE_COMPLETE_COMMIT,
                    captured_tokens=captured_b,
                )
            self.assertEqual(tracker_b.count("run_b", "se1"), 1)
        finally:
            sup_b1.simulate_crash()

        # Recover Journal B at epoch 2 injecting foreign tracker_a (which observed epoch 1 for A)!
        sup_b2, rep_b2 = DurableWorkflowSupervisor.start_or_recover(
            dir_b,
            clock=self.clock.advance(),
            tracker=tracker_a,
            sandbox_root=self.sandbox_root,
        )
        try:
            self.assertEqual(rep_b2.supervisor_epoch, 2)
            rcpt_foreign = tracker_a.issue_receipt(
                token=captured_b[0],
                current_epoch=2,
                journal_id=sup_b2.journal.journal_id,
            )
            self.assertEqual(rcpt_foreign.tracker_outcome, "still_pending")
            req_requeue = ReconcileStepRequest(
                run_id="run_b",
                step_id="se1",
                expected_attempt_no=1,
                expected_epoch=2,
                reconciliation_key="recon_foreign_tracker",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=rcpt_foreign.receipt_digest,
                reason="try_requeue_with_foreign_tracker",
                clock=self.clock.advance(),
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup_b2.reconcile_step(
                    req_requeue,
                    tracker_receipt=rcpt_foreign,
                    clock_provider=self.clock.advance,
                )
            self.assertEqual(
                sup_b2.journal.get_step("run_b", "se1").status,
                StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            )
            self.assertEqual(tracker_a.count("run_b", "se1"), 0)
        finally:
            sup_b2.close_clean(clock=self.clock.advance())

        verify_journal_replay_readonly(dir_a, sandbox_root=self.sandbox_root)
        verify_journal_replay_readonly(dir_b, sandbox_root=self.sandbox_root)


class TestAdversarialRegressionsRound5(_RestartFixtureBase):
    def test_foreign_journal_refused_before_stored_attempt_or_epoch_mutation(
        self,
    ) -> None:
        dir_a = self.root / "lineage_a"
        dir_b = self.root / "lineage_b"
        for d in (dir_a, dir_b):
            d.mkdir(mode=0o700)
            os.chmod(d, 0o700)

        # Journal A (owner): executes shared_run/se1 with exact idem key -> effect_applied.
        tracker_a = SyntheticEffectTracker()
        sup_a, _ = DurableWorkflowSupervisor.start_or_recover(
            dir_a,
            clock=self.clock.now(),
            tracker=tracker_a,
            sandbox_root=self.sandbox_root,
        )
        jid_a = sup_a.journal.journal_id
        captured_a: list[StepLeaseToken] = []
        try:
            steps = (
                StepSpec("se1", "se1", "stage_patch", True),
                StepSpec("se2", "se2", "stage_patch", True),
            )
            sup_a.journal.create_run(self._make_run_request("shared_run", steps))
            sup_a.run_step_once(
                "shared_run",
                "se1",
                idempotency_key="shared_idem_1",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                clock_provider=self.clock.advance,
                captured_tokens=captured_a,
            )

            # Journal B (foreign): identical coordinates (run_id, step_id, attempt, epoch, idem)!
            tracker_b = SyntheticEffectTracker()
            sup_b1, _ = DurableWorkflowSupervisor.start_or_recover(
                dir_b,
                clock=self.clock.advance(),
                tracker=tracker_b,
                sandbox_root=self.sandbox_root,
            )
            jid_b = sup_b1.journal.journal_id
            self.assertNotEqual(jid_a, jid_b)
            captured_b: list[StepLeaseToken] = []
            try:
                sup_b1.journal.create_run(self._make_run_request("shared_run", steps))
                with self.assertRaises(SimulatedSupervisorCrash):
                    sup_b1.run_step_once(
                        "shared_run",
                        "se1",
                        idempotency_key="shared_idem_1",
                        worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                        clock_provider=self.clock.advance,
                        crash_point=CrashPoint.AFTER_LEASE_COMMIT_BEFORE_WORKER,
                        captured_tokens=captured_b,
                    )
            finally:
                sup_b1.simulate_crash()

            self.assertEqual(captured_a[0], captured_b[0])

            # Foreign calls MUST NOT read owner's stored effect_applied OR advance owner epoch!
            tracker_a.attach_epoch(99, journal_id=jid_b)
            rcpt_foreign = tracker_a.issue_receipt(
                token=captured_b[0],
                current_epoch=99,
                force_fence=True,
                journal_id=jid_b,
            )
            self.assertEqual(rcpt_foreign.tracker_outcome, "still_pending")
            self.assertIsNone(rcpt_foreign.output_digest)
            tracker_a.fence_epoch(99, journal_id=jid_b)

            # Reopen Journal B injecting tracker_a: reconciling COMPLETED using A's stored
            # receipt MUST fail closed with ReconciliationEvidenceError!
            owner_applied = tracker_a.issue_receipt(
                token=captured_a[0], current_epoch=1, journal_id=jid_a
            )
            self.assertEqual(owner_applied.tracker_outcome, "effect_applied")
            sup_b2, _ = DurableWorkflowSupervisor.start_or_recover(
                dir_b,
                clock=self.clock.advance(),
                tracker=tracker_a,
                sandbox_root=self.sandbox_root,
            )
            try:
                bad_comp = ReconcileStepRequest(
                    run_id="shared_run",
                    step_id="se1",
                    expected_attempt_no=1,
                    expected_epoch=2,
                    reconciliation_key="recon_steal_owner_receipt",
                    resolution=ReconcileResolution.COMPLETED,
                    output_digest=_DIGEST_A,
                    evidence_digest=owner_applied.receipt_digest,
                    reason="try_steal_owner_effect_applied",
                    clock=self.clock.advance(),
                )
                with self.assertRaises(ReconciliationEvidenceError):
                    sup_b2.reconcile_step(bad_comp, tracker_receipt=owner_applied)
            finally:
                sup_b2.close_clean(clock=self.clock.advance())

            # Owner Journal A is completely unharmed: can still execute epoch-1 se2!
            out_a2 = sup_a.run_step_once(
                "shared_run",
                "se2",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                clock_provider=self.clock.advance,
            )
            self.assertEqual(out_a2.ack.status, StepStatus.COMPLETED.value)
        finally:
            sup_a.close_clean(clock=self.clock.advance())

        verify_journal_replay_readonly(dir_a, sandbox_root=self.sandbox_root)
        verify_journal_replay_readonly(dir_b, sandbox_root=self.sandbox_root)

    def test_recreated_db_at_same_path_has_fresh_journal_id_and_refuses_old_tracker(
        self,
    ) -> None:
        # 1. Create Journal 1 at self.state_dir with tracker_1 -> binds to jid_1, epoch 1.
        tracker_1 = SyntheticEffectTracker()
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker_1,
            sandbox_root=self.sandbox_root,
        )
        jid_1 = sup1.journal.journal_id
        try:
            sup1.journal.create_run(
                self._make_run_request(
                    "run_orig", (StepSpec("se1", "se1", "stage_patch", True),)
                )
            )
        finally:
            sup1.close_clean(clock=self.clock.advance())

        # 2. Delete Journal 1's DB & sidecar files and create a brand-new Journal 2 at
        #    the EXACT SAME self.state_dir path!
        for suffix in ("", "-wal", "-shm", "-journal"):
            p = Path(f"{self.state_dir / DB_FILENAME}{suffix}")
            if p.exists():
                p.unlink()

        tracker_2 = SyntheticEffectTracker()
        sup2, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.advance(),
            tracker=tracker_2,
            sandbox_root=self.sandbox_root,
        )
        jid_2 = sup2.journal.journal_id
        self.assertNotEqual(jid_1, jid_2)
        captured_2: list[StepLeaseToken] = []
        try:
            sup2.journal.create_run(
                self._make_run_request(
                    "run_fresh", (StepSpec("se1", "se1", "stage_patch", True),)
                )
            )
            with self.assertRaises(SimulatedSupervisorCrash):
                sup2.run_step_once(
                    "run_fresh",
                    "se1",
                    worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                    clock_provider=self.clock.advance,
                    crash_point=CrashPoint.AFTER_WORKER_EXEC_BEFORE_COMPLETE_COMMIT,
                    captured_tokens=captured_2,
                )
            self.assertEqual(tracker_2.count("run_fresh", "se1"), 1)
        finally:
            sup2.simulate_crash()

        # 3. Recover Journal 2 (same path, epoch 2) with old tracker_1 -> MUST refuse!
        sup2_rec, rep2 = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.advance(),
            tracker=tracker_1,
            sandbox_root=self.sandbox_root,
        )
        try:
            self.assertEqual(rep2.supervisor_epoch, 2)
            self.assertEqual(sup2_rec.journal.journal_id, jid_2)
            rcpt = sup2_rec.issue_tracker_receipt(captured_2[0])
            self.assertEqual(rcpt.tracker_outcome, "still_pending")
            req_requeue = ReconcileStepRequest(
                run_id="run_fresh",
                step_id="se1",
                expected_attempt_no=1,
                expected_epoch=2,
                reconciliation_key="recon_recreated_same_path",
                resolution=ReconcileResolution.REQUEUE_PENDING,
                output_digest=None,
                evidence_digest=rcpt.receipt_digest,
                reason="try_requeue_old_tracker_same_path",
                clock=self.clock.advance(),
            )
            with self.assertRaises(ReconciliationEvidenceError):
                sup2_rec.reconcile_step(
                    req_requeue,
                    tracker_receipt=rcpt,
                    clock_provider=self.clock.advance,
                )
            self.assertEqual(
                sup2_rec.journal.get_step("run_fresh", "se1").status,
                StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            )
            self.assertEqual(tracker_1.count("run_fresh", "se1"), 0)
        finally:
            sup2_rec.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)


class TestAdversarialRegressionsRound6(_RestartFixtureBase):
    def test_tampered_meta_journal_id_rejected_before_tracker_attachment(self) -> None:
        tracker1 = SyntheticEffectTracker()
        sup1, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker1,
            sandbox_root=self.sandbox_root,
        )
        try:
            sup1.journal.create_run(
                self._make_run_request(
                    "run_jid_tamper", (StepSpec("s1", "s1", "read_metrics", False),)
                )
            )
        finally:
            sup1.close_clean(clock=self.clock.advance())

        # Tamper ONLY supervisor_meta.journal_id to another valid jnl_... ID!
        self._tamper_db(
            "UPDATE supervisor_meta SET journal_id = ?",
            ("jnl_tampered0000000000000000000000",),
        )

        # 1. Read-only verification fails closed with ReplayMismatchError.
        with self.assertRaises(ReplayMismatchError):
            verify_journal_replay_readonly(
                self.state_dir, sandbox_root=self.sandbox_root
            )

        # 2. Direct writable recovery fails closed with ReplayMismatchError.
        t_rec1 = self.clock.advance()
        with self.assertRaises(ReplayMismatchError):
            WorkflowRestartJournal.open_and_recover(
                self.state_dir, clock=t_rec1, sandbox_root=self.sandbox_root
            )

        # 3. Supervisor recovery fails BEFORE attaching tracker (tracker stays unbound!).
        fresh_tracker = SyntheticEffectTracker()
        t_rec2 = self.clock.advance()
        with self.assertRaises(ReplayMismatchError):
            DurableWorkflowSupervisor.start_or_recover(
                self.state_dir,
                clock=t_rec2,
                tracker=fresh_tracker,
                sandbox_root=self.sandbox_root,
            )
        self.assertIsNone(fresh_tracker.bound_journal_id)
        self.assertEqual(fresh_tracker.observed_epochs, frozenset())

    def test_bound_tracker_refuses_omitted_journal_id_without_mutating_owner(
        self,
    ) -> None:
        tracker = SyntheticEffectTracker()
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=tracker,
            sandbox_root=self.sandbox_root,
        )
        jid = sup.journal.journal_id
        captured: list[StepLeaseToken] = []
        try:
            steps = (
                StepSpec("se1", "se1", "stage_patch", True),
                StepSpec("se2", "se2", "stage_patch", True),
            )
            sup.journal.create_run(self._make_run_request("run_omit_jid", steps))
            sup.run_step_once(
                "run_omit_jid",
                "se1",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
                clock_provider=self.clock.advance,
                captured_tokens=captured,
            )
            tok = captured[0]
            step_rec = sup.journal.get_step("run_omit_jid", "se1")
            owner_rcpt = sup.issue_tracker_receipt(tok)
            self.assertEqual(owner_rcpt.tracker_outcome, "effect_applied")

            # Omitting journal_id=None on a bound tracker MUST refuse / no-op without
            # reading stored attempts or mutating owner fence/observed_epochs!
            tracker.attach_epoch(99)
            tracker.fence_epoch(99)
            tracker.fence_attempt(tok)
            self.assertEqual(tracker.observed_epochs, frozenset({1}))

            extra_tok = StepLeaseToken("run_omit_jid", "se2", 1, 1, "idem_omit_jid")
            with self.assertRaises(StaleEpochError):
                tracker.admit_attempt(extra_tok)

            rcpt_none = tracker.issue_receipt(
                token=tok, current_epoch=99, force_fence=True
            )
            self.assertEqual(rcpt_none.tracker_outcome, "still_pending")
            self.assertFalse(rcpt_none.attempt_fenced)
            self.assertIsNone(rcpt_none.output_digest)

            with self.assertRaises(ReconciliationEvidenceError):
                tracker.verify_receipt_for_step(
                    owner_rcpt,
                    step=step_rec,
                    current_epoch=1,
                    expected_outcome="effect_applied",
                    expected_evidence_digest=owner_rcpt.receipt_digest,
                    expected_output_digest=_DIGEST_A,
                )

            # Owner state is completely untouched: can still read owner receipt AND
            # execute epoch-1 se2 cleanly!
            owner_rcpt_after = tracker.issue_receipt(
                token=tok, current_epoch=1, journal_id=jid
            )
            self.assertEqual(owner_rcpt_after.tracker_outcome, "effect_applied")
            self.assertEqual(owner_rcpt_after.output_digest, _DIGEST_A)
            out2 = sup.run_step_once(
                "run_omit_jid",
                "se2",
                worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_B),
                clock_provider=self.clock.advance,
            )
            self.assertEqual(out2.ack.status, StepStatus.COMPLETED.value)
        finally:
            sup.close_clean(clock=self.clock.advance())
        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)


class TestAdversarialRegressionsRound7(_RestartFixtureBase):
    """Regressions for Round 6 review: run_admitted bound lineage & pristine first-binding."""

    def test_run_admitted_requires_exact_bound_journal_id_before_consuming_attempt(
        self,
    ) -> None:
        owner_jid = "jnl_owner_run_admitted_01"
        foreign_jid = "jnl_foreign_run_admitted_02"
        tracker = SyntheticEffectTracker()
        tracker.attach_epoch(1, journal_id=owner_jid)
        tok = StepLeaseToken(
            run_id="run_ra_1",
            step_id="se1",
            attempt_no=1,
            lease_epoch=1,
            idempotency_key="idem_ra_1",
        )
        tracker.admit_attempt(tok, journal_id=owner_jid)

        worker_calls = 0

        def _worker(_t: StepLeaseToken) -> WorkerStepResult:
            nonlocal worker_calls
            worker_calls += 1
            return WorkerStepResult("completed", _DIGEST_A)

        # Omitted journal_id MUST fail closed before consuming attempt or calling worker.
        with self.assertRaises(StaleEpochError):
            tracker.run_admitted(tok, worker_fn=_worker)
        self.assertEqual(worker_calls, 0)

        # Foreign journal_id MUST fail closed before consuming attempt or calling worker.
        with self.assertRaises(StaleEpochError):
            tracker.run_admitted(tok, worker_fn=_worker, journal_id=foreign_jid)
        self.assertEqual(worker_calls, 0)

        # Exact owner journal_id succeeds ONCE and consumes the admitted attempt.
        res = tracker.run_admitted(tok, worker_fn=_worker, journal_id=owner_jid)
        self.assertEqual(res.outcome, "completed")
        self.assertEqual(res.output_digest, _DIGEST_A)
        self.assertEqual(worker_calls, 1)
        self.assertEqual(tracker.count("run_ra_1", "se1"), 1)

        with self.assertRaises(InvalidStepTransitionError):
            tracker.run_admitted(tok, worker_fn=_worker, journal_id=owner_jid)
        self.assertEqual(worker_calls, 1)

    def test_used_standalone_tracker_cannot_be_adopted_by_journal_binding(
        self,
    ) -> None:
        # 1. Pre-populate a standalone tracker with identical coordinates to a future journal step.
        run_id = "run_adopt_1"
        idem_1 = "idem_adopt_shared_1"
        shared_tok = StepLeaseToken(
            run_id=run_id,
            step_id="se1",
            attempt_no=1,
            lease_epoch=1,
            idempotency_key=idem_1,
        )
        standalone_applied = SyntheticEffectTracker()
        standalone_applied.admit_attempt(shared_tok)
        standalone_applied.run_admitted(
            shared_tok,
            worker_fn=lambda _t: WorkerStepResult("completed", _DIGEST_A),
        )
        standalone_rcpt = standalone_applied.issue_receipt(
            token=shared_tok, current_epoch=1
        )
        self.assertEqual(standalone_rcpt.tracker_outcome, "effect_applied")

        # 2. Inject that already-used standalone tracker into a journal supervisor.
        sup, _ = DurableWorkflowSupervisor.start_or_recover(
            self.state_dir,
            clock=self.clock.now(),
            tracker=standalone_applied,
            sandbox_root=self.sandbox_root,
        )
        try:
            self.assertIsNone(standalone_applied.bound_journal_id)
            sup.journal.create_run(
                self._make_run_request(
                    run_id, (StepSpec("se1", "se1", "stage_patch", True),)
                )
            )
            leased = sup.journal.lease_step(
                run_id=run_id,
                step_id="se1",
                clock=self.clock.advance(),
                idempotency_key=idem_1,
            )
            self.assertEqual(leased, shared_tok)
            sup.journal.fail_step(
                FailStepRequest(
                    token=leased,
                    reason="worker_crash_uncertain",
                    retryable=False,
                    uncertain=True,
                    clock=self.clock.advance(),
                )
            )
            # Journal receipt MUST stay still_pending (never adopting standalone effect_applied).
            journal_rcpt = sup.issue_tracker_receipt(token=leased, force_fence=True)
            self.assertEqual(journal_rcpt.tracker_outcome, "still_pending")
            self.assertFalse(journal_rcpt.attempt_fenced)
            self.assertIsNone(journal_rcpt.output_digest)

            # Reconciling COMPLETED using the standalone receipt MUST fail closed.
            with self.assertRaises(ReconciliationEvidenceError):
                sup.reconcile_step(
                    ReconcileStepRequest(
                        run_id=run_id,
                        step_id="se1",
                        expected_attempt_no=1,
                        expected_epoch=1,
                        reconciliation_key="rec_adopt_1",
                        resolution=ReconcileResolution.COMPLETED,
                        output_digest=_DIGEST_A,
                        evidence_digest=standalone_rcpt.receipt_digest,
                        reason="attempt_adopt_standalone_applied",
                        clock=self.clock.advance(),
                    ),
                    tracker_receipt=standalone_rcpt,
                )
            # Standalone history remains intact for standalone queries.
            standalone_after = standalone_applied.issue_receipt(
                token=shared_tok, current_epoch=1
            )
            self.assertEqual(standalone_after.tracker_outcome, "effect_applied")
        finally:
            sup.close_clean(clock=self.clock.advance())

        # 3. Also verify a standalone tracker with only epoch-1 attachment cannot certify no_effect.
        dir_noeff = self.root / "adopt_no_effect"
        dir_noeff.mkdir(mode=0o700)
        standalone_obs = SyntheticEffectTracker()
        standalone_obs.attach_epoch(1)
        sup2, _ = DurableWorkflowSupervisor.start_or_recover(
            dir_noeff,
            clock=self.clock.advance(),
            tracker=standalone_obs,
            sandbox_root=self.sandbox_root,
        )
        try:
            self.assertIsNone(standalone_obs.bound_journal_id)
            sup2.journal.create_run(
                self._make_run_request(
                    "run_adopt_2", (StepSpec("se1", "se1", "stage_patch", True),)
                )
            )
            tok2 = sup2.journal.lease_step(
                run_id="run_adopt_2", step_id="se1", clock=self.clock.advance()
            )
            sup2.journal.fail_step(
                FailStepRequest(
                    token=tok2,
                    reason="uncertain_no_adopt",
                    retryable=False,
                    uncertain=True,
                    clock=self.clock.advance(),
                )
            )
            rcpt2 = sup2.issue_tracker_receipt(token=tok2, force_fence=True)
            self.assertEqual(rcpt2.tracker_outcome, "still_pending")
            self.assertFalse(rcpt2.attempt_fenced)
        finally:
            sup2.close_clean(clock=self.clock.advance())

        verify_journal_replay_readonly(self.state_dir, sandbox_root=self.sandbox_root)
        verify_journal_replay_readonly(dir_noeff, sandbox_root=self.sandbox_root)


if __name__ == "__main__":
    unittest.main()
