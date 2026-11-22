"""Unit and adversarial regression tests for workflow@1 schema, compilation, authority, and lanes."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from oc_workflow_plan import (
    AdmissionDeniedError,
    AuthorityError,
    ClockSnapshot,
    CompiledWorkflowPlan,
    LaneAuthorityError,
    LaneLeaseRegistry,
    LaneOwnershipConflictError,
    MaterializationError,
    MixedLaneRoleError,
    ModelCatalog,
    ModelCatalogEntry,
    RunAuthorityStore,
    TargetIncarnation,
    WorkflowRunLease,
    compile_workflow_plan,
    evaluate_admission,
    materialize_workflow_plan,
)
from oc_workflow_schema import (
    PredicateValidationError,
    TemplateValidationError,
    WorkflowSchemaError,
    compile_predicate,
    compute_security_delta,
    evaluate_predicate,
    parse_and_validate_workflow_toml,
    render_template,
    validate_template,
)


def _sample_catalog() -> ModelCatalog:
    return ModelCatalog(
        (
            ModelCatalogEntry(
                route="decisions:local-rules-v1",
                model="local-rules-v1",
                capability="decisions",
                max_call_cost_microusd=1_000,
            ),
            ModelCatalogEntry(
                route="decisions:openai-luna",
                model="gpt-6-luna",
                capability="decisions",
                max_call_cost_microusd=5_000,
            ),
            ModelCatalogEntry(
                route="blind:fast-verifier",
                model="fast-verifier",
                capability="blind_check",
                max_call_cost_microusd=20_000,
            ),
        )
    )


def _make_skill_tree(base: Path, ns: str, slug: str, content: bytes = b"# Skill\n") -> Path:
    skill_root = base / "skills_src"
    skill_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(skill_root, 0o700)
    ns_dir = skill_root / ns
    ns_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(ns_dir, 0o700)
    slug_dir = ns_dir / slug
    slug_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(slug_dir, 0o700)
    skill_file = slug_dir / "SKILL.md"
    skill_file.write_bytes(content)
    os.chmod(skill_file, 0o600)
    return skill_root


def _supervisor_toml(
    *,
    wf_id: str = "builtin/firstmate-supervisor",
    autonomy: str = "nudge_bounded",
    skill: str = "builtin/firstmate-guide",
    fp_threshold: str = "0.25",
    selector: str = "all_running_sandboxes",
    bound_targets: str = "[]",
    extra_supervision: str = "",
    description: str = "Fleet supervisor",
) -> str:
    return f"""
schema_version = 1
kind = "workflow@1"
id = "{wf_id}"
mode = "fleet_supervisor"
description = "{description}"
autonomy = "{autonomy}"
orchestrator_skill = "{skill}"
survives_restart = true

[scope]
target_selector = "{selector}"
bound_targets = {bound_targets}
allow_remote_workers = true

[limits]
tick_interval_s = 60
throttle_period_s = 300
fleet_max_concurrent_checks = 2
fleet_max_checks_per_hour = 30
fleet_audit_checks_per_hour = 8
max_nudges_per_target_per_hour = 2
min_nudge_interval_s = 300
max_total_nudges_per_run = 40
max_decisions_calls_per_hour = 120
max_decisions_spend_usd = 0.50
max_blind_check_spend_usd = 2.00
max_open_inbox_items = 16
defer_nudge_during_human_lease = true
wake_grace_after_host_sleep_s = 120

[supervision.system1]
route = "decisions:local-rules-v1"
model = "local-rules-v1"
authority = "trigger_only"
decision_type = "choice"
rubric = "Classify strictly from host metrics."
choices = ["healthy_progress", "stalled_loop", "machine_degraded", "escalate_human"]
abstain_default = "healthy_progress"
canary_injection_question = true
{extra_supervision}

[supervision.blind_check]
model_profile = "fast-verifier"
scheduled_audit_interval_s = 900
min_calibration_samples = 10
fp_drift_warn_threshold = {fp_threshold}
fn_drift_warn_count_24h = 2

[templates]
nudge_stalled = "Check lane {{target_addr}} stalled {{stall_seconds}}s ({{workflow_id}})."

[dashboard.default_surface]
title = "Fleet Supervisor"
priority = 10
[[dashboard.default_surface.widgets]]
id = "summary"
type = "status_card"
metrics = ["fleet.running_sandboxes"]
"""


def _observe_only_toml(
    *,
    wf_id: str = "user/lane-observer",
    skill: str = "user/observer-guide",
    selector: str = "bound_targets",
    bound_targets: str = '["local/lane-a"]',
    extra_states: str = "",
    extra_timers: str = "",
    extra_signals: str = "",
    decisions_calls: int = 0,
    nudges: int = 0,
) -> str:
    return f"""
schema_version = 1
kind = "workflow@1"
id = "{wf_id}"
mode = "statechart"
description = "Read-only observer"
autonomy = "observe_only"
orchestrator_skill = "{skill}"
survives_restart = false

[scope]
target_selector = "{selector}"
bound_targets = {bound_targets}
allow_remote_workers = false

[limits]
tick_interval_s = 30
throttle_period_s = 300
fleet_max_concurrent_checks = 0
fleet_max_checks_per_hour = 0
fleet_audit_checks_per_hour = 0
max_nudges_per_target_per_hour = {nudges}
min_nudge_interval_s = 300
max_total_nudges_per_run = {nudges}
max_decisions_calls_per_hour = {decisions_calls}
max_decisions_spend_usd = 0
max_blind_check_spend_usd = 0
max_open_inbox_items = 8
defer_nudge_during_human_lease = true
wake_grace_after_host_sleep_s = 120

[[states]]
name = "watch"
shape = "observe"
effects = ["read_metrics", "update_health_projection"]
{extra_states}
{extra_timers}
{extra_signals}
"""


class TestWorkflowSchemaAndAst(unittest.TestCase):
    def test_valid_parsing_and_canonical_numeric_normalization(self) -> None:
        s1 = parse_and_validate_workflow_toml(_supervisor_toml(fp_threshold="0.25"), is_builtin=True)
        s2 = parse_and_validate_workflow_toml(_supervisor_toml(fp_threshold="0.250"), is_builtin=True)
        self.assertEqual(s1.spec_digest, s2.spec_digest)
        self.assertEqual(s1.blind_check.fp_drift_warn_threshold_bps, 2500)  # type: ignore[union-attr]
        self.assertEqual(s1.limits.max_decisions_spend_microusd, 500_000)
        self.assertEqual(s1.limits.max_blind_check_spend_microusd, 2_000_000)

        s_one = parse_and_validate_workflow_toml(_supervisor_toml(fp_threshold="1"), is_builtin=True)
        s_one_f = parse_and_validate_workflow_toml(_supervisor_toml(fp_threshold="1.0"), is_builtin=True)
        self.assertEqual(s_one.spec_digest, s_one_f.spec_digest)
        self.assertEqual(s_one.blind_check.fp_drift_warn_threshold_bps, 10_000)  # type: ignore[union-attr]

    def test_schema_limit_and_sanitization_rejections(self) -> None:
        # Unknown top-level key
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(_supervisor_toml() + "\nextra_key = 1\n", is_builtin=True)

        # Mutable workflow impersonating builtin
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(_supervisor_toml(wf_id="builtin/spoof"), is_builtin=False)

        # Empty bound_targets when selector == bound_targets
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(
                _observe_only_toml(selector="bound_targets", bound_targets="[]"),
                is_builtin=False,
            )

        # tick_interval_s < 10
        bad_tick = _supervisor_toml().replace("tick_interval_s = 60", "tick_interval_s = 5")
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(bad_tick, is_builtin=True)

        # Sub-microdollar USD spend
        bad_usd = _supervisor_toml().replace("max_decisions_spend_usd = 0.50", "max_decisions_spend_usd = 0.0000001")
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(bad_usd, is_builtin=True)

        # BiDi control character rejected
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(_supervisor_toml(description="Bad \u202e text"), is_builtin=True)

        # Mutable workflow referencing non-allowlisted factory_id rejected
        factory_state = '\n[[states]]\nname = "fan"\nshape = "observe"\nfactory_id = "host_fanout"\n'
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(_observe_only_toml(extra_states=factory_state), is_builtin=False)
        # Allowlisted factory passes
        ok_spec = parse_and_validate_workflow_toml(
            _observe_only_toml(extra_states=factory_state),
            is_builtin=False,
            allowlisted_factories=frozenset({"host_fanout"}),
        )
        self.assertEqual(len(ok_spec.states), 2)

        # >32 states rejected
        many_states = "\n".join(
            f'[[states]]\nname = "s{i}"\nshape = "observe"\neffects = ["read_metrics"]'
            for i in range(33)
        )
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(_observe_only_toml(extra_states="\n" + many_states), is_builtin=False)

        # Invalid oc-ui@1 widget rejected
        bad_widget = _supervisor_toml().replace('type = "status_card"', 'type = "raw_html_iframe"')
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(bad_widget, is_builtin=True)

    def test_bounded_predicate_ast_security(self) -> None:
        pred = compile_predicate("metric.stall_seconds >= 300 and not lane.paused and metric.delta > -5")
        ok, err = evaluate_predicate(
            pred,
            {"metric": {"stall_seconds": 400, "delta": -2}, "lane": {"paused": False}},
        )
        self.assertTrue(ok)
        self.assertIsNone(err)

        # bool vs int trap: True == 1 and True in [1, 2] must NOT evaluate True
        p_eq = compile_predicate("metric.flag == 1")
        val_eq, _ = evaluate_predicate(p_eq, {"metric": {"flag": True}})
        self.assertFalse(val_eq)

        p_in = compile_predicate("metric.flag in [1, 2]")
        val_in, _ = evaluate_predicate(p_in, {"metric": {"flag": True}})
        self.assertFalse(val_in)

        # Disallowed constructs fail compile_predicate
        for bad in (
            "1 < metric.x < 10",  # chained comparison
            '"a" in "abc"',  # str in str
            "metric.s in 'abcdef'",  # RHS of in not list/tuple
            "metric.x in [True, 1]",  # mixed bool/int in list
            "metric.x in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]",  # >16 items
            "os.system('id') == 0",  # call + disallowed namespace
            "metric.a.b == 1",  # nested attribute
            "untrusted.text == 'ok'",  # disallowed namespace
            "not (not (not (not (not (not (not (not metric.a)))))))",  # depth > 8
            "-True == -1",  # unary minus on bool
            "+metric.x == 1",  # unary plus disallowed
            "metric.a == 'bad\x00nul'",  # NUL in literal
        ):
            with self.assertRaises(PredicateValidationError, msg=f"should reject: {bad}"):
                compile_predicate(bad)

    def test_literal_single_pass_templates(self) -> None:
        validate_template("ok_tpl", "Lane {target_addr} stalled {stall_seconds}s in {workflow_id}")
        # Substituted value containing {workflow_id} is NEVER re-expanded
        rendered = render_template(
            "Lane {target_addr} ({workflow_id})",
            {"target_addr": "{workflow_id}", "workflow_id": "builtin/sup"},
        )
        self.assertEqual(rendered, "Lane {workflow_id} (builtin/sup)")

        for bad in (
            "Bad {target_addr.__class__}",
            "Bad {target_addr[0]}",
            "Bad {unknown_var}",
            "Bad {stall_seconds:100s}",
            "Unmatched { brace",
            "Unmatched } brace",
        ):
            with self.assertRaises(TemplateValidationError, msg=f"should reject: {bad}"):
                validate_template("bad", bad)

    def test_directional_security_delta_all_10_triggers(self) -> None:
        base = parse_and_validate_workflow_toml(_supervisor_toml(), is_builtin=True)
        # Creation emits workflow_added + enabled capability triggers
        create_delta = compute_security_delta(None, base)
        self.assertIn("workflow_added", create_delta)
        self.assertIn("workflow_autonomy_widened", create_delta)
        self.assertIn("workflow_decisions_route_added", create_delta)

        # Benign description edit -> zero triggers
        desc_only = parse_and_validate_workflow_toml(_supervisor_toml(description="Updated docs"), is_builtin=True)
        self.assertEqual(compute_security_delta(base, desc_only), ())

        # Interval decrease triggers workflow_autonomy_widened
        faster_nudge = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("min_nudge_interval_s = 300", "min_nudge_interval_s = 60"),
            is_builtin=True,
        )
        self.assertIn("workflow_autonomy_widened", compute_security_delta(base, faster_nudge))

        # Disabling human-lease deferral triggers workflow_autonomy_widened
        no_defer = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("defer_nudge_during_human_lease = true", "defer_nudge_during_human_lease = false"),
            is_builtin=True,
        )
        self.assertIn("workflow_autonomy_widened", compute_security_delta(base, no_defer))

        # Increasing scheduled_audit_interval_s weakens FN detection -> workflow_decisions_route_added
        slower_audit = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("scheduled_audit_interval_s = 900", "scheduled_audit_interval_s = 3600"),
            is_builtin=True,
        )
        self.assertIn("workflow_decisions_route_added", compute_security_delta(base, slower_audit))

        # Decreasing fleet_audit_checks_per_hour -> workflow_decisions_route_added
        less_audit = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("fleet_audit_checks_per_hour = 8", "fleet_audit_checks_per_hour = 2"),
            is_builtin=True,
        )
        self.assertIn("workflow_decisions_route_added", compute_security_delta(base, less_audit))

        # Excerpt disclosure opt-in -> workflow_excerpt_disclosure_changed
        opt_in = (
            'excerpt_disclosure = "opt_in"\n'
            '[supervision.excerpt_disclosure]\n'
            'source = "sanitized_last_error_excerpt"\n'
            'max_bytes = 256\n'
            'allowed_routes = ["decisions:local-rules-v1"]\n'
            'permitted_uses = ["live"]\n'
        )
        with_disc = parse_and_validate_workflow_toml(_supervisor_toml(extra_supervision=opt_in), is_builtin=True)
        self.assertIn("workflow_excerpt_disclosure_changed", compute_security_delta(base, with_disc))

        # Rubric edit, template edit, skill sha change, surface change
        rubric_mod = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("Classify strictly from host metrics.", "Classify loosely."),
            is_builtin=True,
        )
        self.assertIn("workflow_rubric_or_predicate_changed", compute_security_delta(base, rubric_mod))

        tpl_mod = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("Check lane", "Ping lane"),
            is_builtin=True,
        )
        self.assertIn("workflow_template_changed", compute_security_delta(base, tpl_mod))

        self.assertIn(
            "workflow_skill_changed",
            compute_security_delta(base, base, old_skill_sha256="aaa", new_skill_sha256="bbb"),
        )


class TestCompileMaterializeAndLaneAuthority(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.staging = self.root / "staging"
        self.staging.mkdir(mode=0o700)
        os.chmod(self.staging, 0o700)
        self.catalog = _sample_catalog()
        self.clock = ClockSnapshot(monotonic_s=100.0, wall_s=1000.0)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_pure_compile_zero_writes_strict_modes_fifo_and_toctou(self) -> None:
        skill_root = _make_skill_tree(self.root, "builtin", "firstmate-guide", b"# Original Skill\n")
        plan = compile_workflow_plan(
            _supervisor_toml(),
            is_builtin=True,
            skill_root=skill_root,
            model_catalog=self.catalog,
        )
        # Pure compile writes ZERO files into staging
        self.assertEqual(list(self.staging.iterdir()), [])

        # Modify disk skill source AFTER compile; materialize must write pinned bytes, NOT disk edits!
        disk_skill = skill_root / "builtin" / "firstmate-guide" / "SKILL.md"
        disk_skill.write_bytes(b"# Tampered On Disk\n")
        os.chmod(disk_skill, 0o600)

        store = RunAuthorityStore()
        receipt = evaluate_admission(
            plan,
            store,
            principal_id="op-1",
            caller_role="operator",
            caller_subtree=frozenset(),
            active_orchestrator_runs=0,
            max_active_orchestrator_runs=4,
            clock=self.clock,
        )
        artifacts = materialize_workflow_plan(
            plan,
            receipt,
            authority_store=store,
            clock=self.clock,
            staging_root=self.staging,
        )
        self.assertEqual(artifacts.skill_path.read_bytes(), b"# Original Skill\n")
        self.assertEqual(stat.S_IMODE(artifacts.skill_path.stat().st_mode), 0o400)
        self.assertEqual(artifacts.skill_path.parent.name, "wf-builtin-firstmate-guide")

        # Tampered pinned bytes fail digest re-verification
        corrupted = CompiledWorkflowPlan(**{**plan.__dict__, "skill_bytes": b"# Corrupted\n"})
        receipt2 = evaluate_admission(
            plan,
            store,
            principal_id="op-1",
            caller_role="operator",
            caller_subtree=frozenset(),
            active_orchestrator_runs=0,
            max_active_orchestrator_runs=4,
            clock=self.clock,
        )
        with self.assertRaises(MaterializationError):
            materialize_workflow_plan(
                corrupted,
                receipt2,
                authority_store=store,
                clock=self.clock,
                staging_root=self.staging,
            )

        # Reject 0o644 skill file
        os.chmod(disk_skill, 0o644)
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(_supervisor_toml(), is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)
        os.chmod(disk_skill, 0o600)

        # Reject 0o755 skill dir
        os.chmod(disk_skill.parent, 0o755)
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(_supervisor_toml(), is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)
        os.chmod(disk_skill.parent, 0o700)

        # Reject named FIFO immediately without stalling (O_NONBLOCK + S_ISREG)
        disk_skill.unlink()
        os.mkfifo(disk_skill, 0o600)
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(_supervisor_toml(), is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)

    def test_slug_namespacing_prevents_builtin_user_collision(self) -> None:
        skill_root = _make_skill_tree(self.root, "builtin", "shared", b"# Builtin\n")
        _make_skill_tree(self.root, "user", "shared", b"# User\n")
        p_builtin = compile_workflow_plan(
            _supervisor_toml(wf_id="builtin/shared", skill="builtin/shared"),
            is_builtin=True,
            skill_root=skill_root,
            model_catalog=self.catalog,
        )
        p_user = compile_workflow_plan(
            _observe_only_toml(wf_id="user/shared", skill="user/shared"),
            is_builtin=False,
            skill_root=skill_root,
            model_catalog=self.catalog,
        )
        store = RunAuthorityStore()
        r1 = evaluate_admission(
            p_builtin, store, principal_id="op", caller_role="operator",
            caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        r2 = evaluate_admission(
            p_user, store, principal_id="orch-1", caller_role="orchestrator",
            caller_subtree=frozenset({"local/lane-a"}), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        a1 = materialize_workflow_plan(p_builtin, r1, authority_store=store, clock=self.clock, staging_root=self.staging)
        a2 = materialize_workflow_plan(p_user, r2, authority_store=store, clock=self.clock, staging_root=self.staging)
        self.assertNotEqual(a1.skill_path, a2.skill_path)
        self.assertEqual(a1.skill_path.read_bytes(), b"# Builtin\n")
        self.assertEqual(a2.skill_path.read_bytes(), b"# User\n")

    def test_live_authority_receipt_reuse_revocation_and_silverblue_alias(self) -> None:
        skill_root = _make_skill_tree(self.root, "builtin", "firstmate-guide", b"# Skill\n")
        plan = compile_workflow_plan(_supervisor_toml(), is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)
        store = RunAuthorityStore()

        # operator_direct mints finite lease that expires cleanly
        receipt = evaluate_admission(
            plan, store, principal_id="op-1", caller_role="operator",
            caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4,
            clock=self.clock, operator_lease_ttl_s=60.0,
        )
        expired_clock = ClockSnapshot(monotonic_s=200.0, wall_s=1061.0)
        with self.assertRaises(AuthorityError):
            materialize_workflow_plan(plan, receipt, authority_store=store, clock=expired_clock, staging_root=self.staging)

        # Revocation between admission and materialization yields ZERO files written
        receipt_rev = evaluate_admission(
            plan, store, principal_id="op-1", caller_role="operator",
            caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        store.revoke_run(receipt_rev.run_id)
        with self.assertRaises(AuthorityError):
            materialize_workflow_plan(plan, receipt_rev, authority_store=store, clock=self.clock, staging_root=self.staging)
        self.assertEqual(list(self.staging.iterdir()), [])

        # Receipt reuse for second materialization fails closed
        receipt_ok = evaluate_admission(
            plan, store, principal_id="op-1", caller_role="operator",
            caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        materialize_workflow_plan(plan, receipt_ok, authority_store=store, clock=self.clock, staging_root=self.staging)
        with self.assertRaises(MaterializationError):
            materialize_workflow_plan(plan, receipt_ok, authority_store=store, clock=self.clock, staging_root=self.staging)

        # Forbidden sandbox root rejected
        sandbox_home = self.root / "sandbox_home"
        sandbox_home.mkdir(mode=0o700)
        os.chmod(sandbox_home, 0o700)
        r_sb = evaluate_admission(
            plan, store, principal_id="op-1", caller_role="operator",
            caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        with self.assertRaises(MaterializationError):
            materialize_workflow_plan(
                plan, r_sb, authority_store=store, clock=self.clock,
                staging_root=sandbox_home, forbidden_sandbox_roots=(sandbox_home,),
            )

        # User-owned symlink ancestor rejected; root-owned OS alias (Silverblue pattern) accepted
        real_var = self.root / "var_home"
        real_var.mkdir(mode=0o700)
        os.chmod(real_var, 0o700)
        inner_stage = real_var / "stage"
        inner_stage.mkdir(mode=0o700)
        os.chmod(inner_stage, 0o700)
        home_alias = self.root / "home_alias"
        os.symlink(real_var, home_alias)
        aliased_stage = home_alias / "stage"

        with self.assertRaises(MaterializationError):
            materialize_workflow_plan(
                plan, r_sb, authority_store=store, clock=self.clock, staging_root=aliased_stage,
            )
        artifacts = materialize_workflow_plan(
            plan, r_sb, authority_store=store, clock=self.clock,
            staging_root=aliased_stage,
            root_alias_checker=lambda p: p == home_alias,
        )
        self.assertTrue(artifacts.skill_path.exists())

    def test_observe_only_effect_allowlist_scope_narrowing_and_nonexclusive_lane(self) -> None:
        skill_root = _make_skill_tree(self.root, "user", "observer-guide", b"# Obs\n")
        _make_skill_tree(self.root, "builtin", "firstmate-guide", b"# Sup\n")
        store = RunAuthorityStore()
        lanes = LaneLeaseRegistry()

        # Hidden disallowed effect in signal handler fails observe_only auto-admission even at $0 spend
        bad_sig = '\n[[signal_handlers]]\nsignal = "go"\neffects = ["nudge_sandbox"]\n'
        p_bad = compile_workflow_plan(
            _observe_only_toml(extra_signals=bad_sig),
            is_builtin=False,
            skill_root=skill_root,
            model_catalog=self.catalog,
        )
        with self.assertRaises(AdmissionDeniedError):
            evaluate_admission(
                p_bad, store, principal_id="orch-1", caller_role="orchestrator",
                caller_subtree=frozenset({"local/lane-a"}), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
            )

        # Non-zero decisions call cap fails observe_only auto-admission even at $0 spend
        p_bad_calls = compile_workflow_plan(
            _observe_only_toml(decisions_calls=5),
            is_builtin=False,
            skill_root=skill_root,
            model_catalog=self.catalog,
        )
        with self.assertRaises(AdmissionDeniedError):
            evaluate_admission(
                p_bad_calls, store, principal_id="orch-1", caller_role="orchestrator",
                caller_subtree=frozenset({"local/lane-a"}), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
            )

        # Clean observe_only auto-admits with nonexclusive_observer; scope narrowed to plan.bound_targets!
        p_obs = compile_workflow_plan(
            _observe_only_toml(bound_targets='["local/lane-a"]'),
            is_builtin=False,
            skill_root=skill_root,
            model_catalog=self.catalog,
        )
        # Caller subtree is wider (includes lane-b), but plan only binds lane-a!
        r_obs = evaluate_admission(
            p_obs, store, principal_id="orch-1", caller_role="orchestrator",
            caller_subtree=frozenset({"local/lane-a", "local/lane-b"}),
            active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        lane_a = TargetIncarnation("local/lane-a", "inc-1")
        lane_b = TargetIncarnation("local/lane-b", "inc-2")

        # Target inside caller_subtree but OUTSIDE plan.bound_targets MUST FAIL!
        with self.assertRaises(AuthorityError):
            lanes.attach(lane_b, receipt=r_obs, authority_store=store, clock=self.clock)

        # Attach observer first (even paused!), then operator starts owning workflow on SAME incarnation!
        lanes.attach(lane_a, receipt=r_obs, authority_store=store, clock=self.clock)
        lanes.pause(r_obs.run_id)
        self.assertIsNone(lanes.exclusive_owner(lane_a))
        self.assertIn(r_obs.run_id, lanes.observers(lane_a))
        with self.assertRaises(LaneAuthorityError):
            lanes.assert_can_nudge(r_obs, lane_a, authority_store=store, clock=self.clock)
        lanes.assert_can_observe(r_obs, lane_a, authority_store=store, clock=self.clock)

        p_owner = compile_workflow_plan(
            _supervisor_toml(), is_builtin=True, skill_root=skill_root, model_catalog=self.catalog,
        )
        r_owner = evaluate_admission(
            p_owner, store, principal_id="op-1", caller_role="operator",
            caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        lanes.attach(lane_a, receipt=r_owner, authority_store=store, clock=self.clock)
        self.assertEqual(lanes.exclusive_owner(lane_a), r_owner.run_id)
        lanes.assert_can_nudge(r_owner, lane_a, authority_store=store, clock=self.clock)

        # Second exclusive owner on same incarnation fails
        r_owner2 = evaluate_admission(
            p_owner, store, principal_id="op-2", caller_role="operator",
            caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        with self.assertRaises(LaneOwnershipConflictError):
            lanes.attach(lane_a, receipt=r_owner2, authority_store=store, clock=self.clock)

        # Operator launching observe_only STILL gets nonexclusive_observer!
        r_op_obs = evaluate_admission(
            p_obs, store, principal_id="op-1", caller_role="operator",
            caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        lanes.attach(lane_a, receipt=r_op_obs, authority_store=store, clock=self.clock)
        self.assertEqual(lanes.exclusive_owner(lane_a), r_owner.run_id)
        self.assertIn(r_op_obs.run_id, lanes.observers(lane_a))

        # Tier-A leased duplicate run_id reuse rejected
        lease = WorkflowRunLease(
            run_id=r_owner.run_id,
            grant_generation=2,
            principal_id="op-1",
            owner_role="operator",
            workflow_id=p_owner.spec.id,
            workflow_plan_digest=p_owner.workflow_plan_digest,
            expires_at_wall_s=2000.0,
        )
        with self.assertRaises(AdmissionDeniedError):
            evaluate_admission(
                p_owner, store, principal_id="op-1", caller_role="operator",
                caller_subtree=frozenset(), active_orchestrator_runs=0, max_active_orchestrator_runs=4,
                clock=self.clock, tier_a_lease=lease,
            )

        # Revoking target incarnation clears both maps
        lanes.revoke_target_incarnation(lane_a)
        self.assertIsNone(lanes.exclusive_owner(lane_a))
        self.assertEqual(lanes.observers(lane_a), frozenset())

        # Mixed-role guard rejects attaching the same run_id with a conflicting lane_access role
        lanes.attach(lane_a, receipt=r_obs, authority_store=store, clock=self.clock)
        rec_obs = store.verify_active(r_obs, clock=self.clock)
        rec_obs.lane_access = "exclusive_owner"
        with self.assertRaises(MixedLaneRoleError):
            lanes.attach(lane_a, receipt=r_obs, authority_store=store, clock=self.clock)


if __name__ == "__main__":
    unittest.main()
