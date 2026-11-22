"""Unit and adversarial regression tests for workflow@1 schema, compilation, authority, and lanes."""

from __future__ import annotations

import math
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
    allow_remote: bool = True,
    decisions_spend: str = "0.50",
    blind_spend: str = "2.00",
    decisions_calls: int = 120,
    extra_supervision: str = "",
    description: str = "Fleet supervisor",
) -> str:
    remote_str = "true" if allow_remote else "false"
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
allow_remote_workers = {remote_str}

[limits]
tick_interval_s = 60
throttle_period_s = 300
fleet_max_concurrent_checks = 2
fleet_max_checks_per_hour = 30
fleet_audit_checks_per_hour = 8
max_nudges_per_target_per_hour = 2
min_nudge_interval_s = 300
max_total_nudges_per_run = 40
max_decisions_calls_per_hour = {decisions_calls}
max_decisions_spend_usd = {decisions_spend}
max_blind_check_spend_usd = {blind_spend}
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
    allow_remote: bool = False,
    extra_states: str = "",
    extra_timers: str = "",
    extra_signals: str = "",
    decisions_calls: int = 0,
    nudges: int = 0,
) -> str:
    remote_str = "true" if allow_remote else "false"
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
allow_remote_workers = {remote_str}

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
    def test_valid_parsing_and_exact_decimal_precision_boundaries(self) -> None:
        s1 = parse_and_validate_workflow_toml(_supervisor_toml(fp_threshold="0.25"), is_builtin=True)
        s2 = parse_and_validate_workflow_toml(_supervisor_toml(fp_threshold="0.250"), is_builtin=True)
        self.assertEqual(s1.spec_digest, s2.spec_digest)
        self.assertEqual(s1.blind_check.fp_drift_warn_threshold_bps, 2500)  # type: ignore[union-attr]
        self.assertEqual(s1.limits.max_decisions_spend_microusd, 500_000)

        # Exact representable boundary values: 0.000001 USD (1 microdollar), 1000.00 USD, 0.0001 bps
        ok_min = parse_and_validate_workflow_toml(
            _supervisor_toml(decisions_spend="0.000001", fp_threshold="0.0001"),
            is_builtin=True,
        )
        self.assertEqual(ok_min.limits.max_decisions_spend_microusd, 1)
        self.assertEqual(ok_min.blind_check.fp_drift_warn_threshold_bps, 1)  # type: ignore[union-attr]

        ok_max = parse_and_validate_workflow_toml(
            _supervisor_toml(decisions_spend="1000.000000", fp_threshold="1.0000"),
            is_builtin=True,
        )
        self.assertEqual(ok_max.limits.max_decisions_spend_microusd, 1_000_000_000)
        self.assertEqual(ok_max.blind_check.fp_drift_warn_threshold_bps, 10_000)  # type: ignore[union-attr]

        # Values immediately past precision or magnitude boundaries MUST fail (parse_float=Decimal!)
        for bad_toml in (
            _supervisor_toml(decisions_spend="0.0000009"),
            _supervisor_toml(decisions_spend="0.0000011"),
            _supervisor_toml(decisions_spend="1000.000001"),
            _supervisor_toml(decisions_spend="1e20"),
            _supervisor_toml(fp_threshold="0.00001"),
            _supervisor_toml(fp_threshold="0.25001"),
            _supervisor_toml(fp_threshold="1.0001"),
        ):
            with self.assertRaises(WorkflowSchemaError):
                parse_and_validate_workflow_toml(bad_toml, is_builtin=True)

    def test_schema_limit_and_sanitization_rejections(self) -> None:
        bad_extra = _supervisor_toml() + "\nextra_key = 1\n"
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(bad_extra, is_builtin=True)

        bad_spoof = _supervisor_toml(wf_id="builtin/spoof")
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(bad_spoof, is_builtin=False)

        bad_empty_targets = _observe_only_toml(selector="bound_targets", bound_targets="[]")
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(bad_empty_targets, is_builtin=False)

        bad_tick = _supervisor_toml().replace("tick_interval_s = 60", "tick_interval_s = 5")
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(bad_tick, is_builtin=True)

        bad_bidi = _supervisor_toml(description="Bad \u202e text")
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(bad_bidi, is_builtin=True)

        factory_state = '\n[[states]]\nname = "fan"\nshape = "observe"\nfactory_id = "host_fanout"\n'
        factory_toml = _observe_only_toml(extra_states=factory_state)
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(factory_toml, is_builtin=False)
        ok_spec = parse_and_validate_workflow_toml(
            factory_toml,
            is_builtin=False,
            allowlisted_factories=frozenset({"host_fanout"}),
        )
        self.assertEqual(len(ok_spec.states), 2)

        many_states = "\n".join(
            f'[[states]]\nname = "s{i}"\nshape = "observe"\neffects = ["read_metrics"]'
            for i in range(33)
        )
        too_many_toml = _observe_only_toml(extra_states="\n" + many_states)
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(too_many_toml, is_builtin=False)

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

        p_eq = compile_predicate("metric.flag == 1")
        val_eq, _ = evaluate_predicate(p_eq, {"metric": {"flag": True}})
        self.assertFalse(val_eq)

        p_in = compile_predicate("metric.flag in [1, 2]")
        val_in, _ = evaluate_predicate(p_in, {"metric": {"flag": True}})
        self.assertFalse(val_in)

        # Runtime type mismatch fails closed EVEN UNDER `not`!
        p_not_mismatch = compile_predicate('not (metric.x < "abc")')
        val_not, fault_not = evaluate_predicate(p_not_mismatch, {"metric": {"x": 5}})
        self.assertFalse(val_not)
        self.assertIsNotNone(fault_not)

        # Unpaired surrogate raises WorkflowSchemaError (never raw UnicodeEncodeError)
        bad_surrogate = _supervisor_toml(description="Bad \ud800 text")
        with self.assertRaises(WorkflowSchemaError):
            parse_and_validate_workflow_toml(bad_surrogate, is_builtin=True)

        for bad in (
            "1 < metric.x < 10",
            '"a" in "abc"',
            "metric.s in 'abcdef'",
            "metric.x in [True, 1]",
            "metric.x in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]",
            "os.system('id') == 0",
            "metric.a.b == 1",
            "untrusted.text == 'ok'",
            "not (not (not (not (not (not (not (not metric.a)))))))",
            "metric.x == " + "- " * 20 + "1",
            "-True == -1",
            "+metric.x == 1",
            "metric.a == 'bad\x00nul'",
        ):
            with self.assertRaises(PredicateValidationError, msg=f"should reject: {bad}"):
                compile_predicate(bad)

    def test_literal_single_pass_templates(self) -> None:
        validate_template("ok_tpl", "Lane {target_addr} stalled {stall_seconds}s in {workflow_id}")
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
        create_delta = compute_security_delta(None, base)
        self.assertIn("workflow_added", create_delta)
        self.assertIn("workflow_autonomy_widened", create_delta)
        self.assertIn("workflow_decisions_route_added", create_delta)

        desc_only = parse_and_validate_workflow_toml(_supervisor_toml(description="Updated docs"), is_builtin=True)
        self.assertEqual(compute_security_delta(base, desc_only), ())

        faster_nudge = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("min_nudge_interval_s = 300", "min_nudge_interval_s = 60"),
            is_builtin=True,
        )
        self.assertIn("workflow_autonomy_widened", compute_security_delta(base, faster_nudge))

        no_defer = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("defer_nudge_during_human_lease = true", "defer_nudge_during_human_lease = false"),
            is_builtin=True,
        )
        self.assertIn("workflow_autonomy_widened", compute_security_delta(base, no_defer))

        shorter_wake = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("wake_grace_after_host_sleep_s = 120", "wake_grace_after_host_sleep_s = 0"),
            is_builtin=True,
        )
        self.assertIn("workflow_autonomy_widened", compute_security_delta(base, shorter_wake))

        slower_audit = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("scheduled_audit_interval_s = 900", "scheduled_audit_interval_s = 3600"),
            is_builtin=True,
        )
        self.assertIn("workflow_decisions_route_added", compute_security_delta(base, slower_audit))

        less_audit = parse_and_validate_workflow_toml(
            _supervisor_toml().replace("fleet_audit_checks_per_hour = 8", "fleet_audit_checks_per_hour = 2"),
            is_builtin=True,
        )
        self.assertIn("workflow_decisions_route_added", compute_security_delta(base, less_audit))

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


def _trusted_temp_dir() -> tempfile.TemporaryDirectory[str]:
    """Create a disposable tempdir under a root- or owner-owned parent (safe inside distrobox)."""
    env_tmp = os.environ.get("TMPDIR")
    if env_tmp:
        try:
            st = os.stat(env_tmp)
            if st.st_uid in (0, os.getuid()):
                return tempfile.TemporaryDirectory(dir=env_tmp)
        except OSError:
            pass
    base = Path.home().resolve() / ".cache" / "oc-sandbox-spike-n-tests"
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    return tempfile.TemporaryDirectory(dir=str(base))


class TestCompileMaterializeAndLaneAuthority(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = _trusted_temp_dir()
        self.root = Path(self._tmp.name)
        os.chmod(self.root, 0o700)
        self.staging = self.root / "staging"
        self.staging.mkdir(mode=0o700)
        os.chmod(self.staging, 0o700)
        self.catalog = _sample_catalog()
        self.clock = ClockSnapshot(monotonic_s=100.0, wall_s=1000.0)
        self.empty_sub: frozenset[str] = frozenset()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_pure_compile_zero_writes_strict_modes_fifo_forged_plan_and_digest_scoped_paths(self) -> None:
        skill_root = _make_skill_tree(self.root, "builtin", "firstmate-guide", b"# Revision 1\n")
        sup_toml = _supervisor_toml()
        plan_v1 = compile_workflow_plan(
            sup_toml,
            is_builtin=True,
            skill_root=skill_root,
            model_catalog=self.catalog,
        )
        self.assertEqual(list(self.staging.iterdir()), [])

        # Modify disk skill source AFTER compile; materialize must write Revision 1 pinned bytes!
        disk_skill = skill_root / "builtin" / "firstmate-guide" / "SKILL.md"
        disk_skill.write_bytes(b"# Revision 2\n")
        os.chmod(disk_skill, 0o600)

        store = RunAuthorityStore()
        r_v1 = evaluate_admission(
            plan_v1, store, principal_id="op-1", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        art_v1 = materialize_workflow_plan(
            plan_v1, r_v1, authority_store=store, clock=self.clock, staging_root=self.staging,
        )
        self.assertEqual(art_v1.skill_path.read_bytes(), b"# Revision 1\n")
        self.assertEqual(stat.S_IMODE(art_v1.skill_path.stat().st_mode), 0o400)

        # Two valid revisions sharing the SAME skill slug MUST publish to distinct digest-scoped paths!
        plan_v2 = compile_workflow_plan(
            sup_toml, is_builtin=True, skill_root=skill_root, model_catalog=self.catalog,
        )
        r_v2 = evaluate_admission(
            plan_v2, store, principal_id="op-1", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        art_v2 = materialize_workflow_plan(
            plan_v2, r_v2, authority_store=store, clock=self.clock, staging_root=self.staging,
        )
        self.assertNotEqual(art_v1.skill_path, art_v2.skill_path)
        self.assertEqual(art_v1.skill_path.read_bytes(), b"# Revision 1\n")
        self.assertEqual(art_v2.skill_path.read_bytes(), b"# Revision 2\n")

        # Forged plan whose cached workflow_plan_digest matches receipt while actual spec differs fails closed!
        modified_spec = parse_and_validate_workflow_toml(
            _supervisor_toml(description="Tampered spec"), is_builtin=True,
        )
        forged_plan = CompiledWorkflowPlan(
            **{**plan_v1.__dict__, "spec": modified_spec}
        )
        r_forged = evaluate_admission(
            plan_v1, store, principal_id="op-1", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        with self.assertRaises(MaterializationError):
            materialize_workflow_plan(
                forged_plan, r_forged, authority_store=store, clock=self.clock, staging_root=self.staging,
            )

        # Reject 0o640 and 0o644 skill file
        os.chmod(disk_skill, 0o640)
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(sup_toml, is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)
        disk_skill.chmod(0o644)  # NOSONAR(S2612) intentional negative permission test inside 0700 tempdir
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(sup_toml, is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)
        os.chmod(disk_skill, 0o600)

        # Reject 0o750 and 0o755 skill dir
        os.chmod(disk_skill.parent, 0o750)
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(sup_toml, is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)
        disk_skill.parent.chmod(0o755)  # NOSONAR(S2612) intentional negative permission test inside 0700 tempdir
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(sup_toml, is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)
        os.chmod(disk_skill.parent, 0o700)

        # Reject named FIFO immediately without stalling (O_NONBLOCK + S_ISREG)
        disk_skill.unlink()
        os.mkfifo(disk_skill, 0o600)
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(sup_toml, is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)

    def test_project_scope_non_wildcard_and_remote_worker_eligibility(self) -> None:
        skill_root = _make_skill_tree(self.root, "builtin", "firstmate-guide", b"# Guide\n")
        store = RunAuthorityStore()
        lanes = LaneLeaseRegistry()

        # Operator project_scope with EMPTY project_members MUST fail closed (never wildcard!)
        p_proj = compile_workflow_plan(
            _supervisor_toml(selector="project_scope", allow_remote=False),
            is_builtin=True,
            skill_root=skill_root,
            model_catalog=self.catalog,
        )
        with self.assertRaises(AdmissionDeniedError):
            evaluate_admission(
                p_proj, store, principal_id="op-1", caller_role="operator",
                caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4,
                clock=self.clock, project_members=self.empty_sub,
            )

        # Operator project_scope with fixture-owned project_members containing local + remote target:
        # allow_remote=False excludes remote target and rejects targets in another project!
        members = frozenset({"local/proj-a-1", "remote-1/proj-a-r"})
        r_proj = evaluate_admission(
            p_proj, store, principal_id="op-1", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4,
            clock=self.clock, project_members=members,
        )
        lanes.attach(TargetIncarnation("local/proj-a-1", "inc-1"), receipt=r_proj, authority_store=store, clock=self.clock)
        # Different project target rejected
        other_proj_target = TargetIncarnation("local/proj-b-1", "inc-2")
        with self.assertRaises(AuthorityError):
            lanes.attach(other_proj_target, receipt=r_proj, authority_store=store, clock=self.clock)
        # Remote target excluded when allow_remote_workers=False
        remote_target = TargetIncarnation("remote-1/proj-a-r", "inc-3")
        with self.assertRaises(AuthorityError):
            lanes.attach(remote_target, receipt=r_proj, authority_store=store, clock=self.clock)

        # bound_targets containing remote address rejected when allow_remote_workers=False
        p_bound_remote = compile_workflow_plan(
            _supervisor_toml(selector="bound_targets", bound_targets='["remote-1/lane-r"]', allow_remote=False),
            is_builtin=True,
            skill_root=skill_root,
            model_catalog=self.catalog,
        )
        with self.assertRaises(AdmissionDeniedError):
            evaluate_admission(
                p_bound_remote, store, principal_id="op-1", caller_role="operator",
                caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4,
                clock=self.clock,
            )

    def test_descriptor_anchored_ancestors_revocation_and_silverblue_alias(self) -> None:
        skill_root = _make_skill_tree(self.root, "builtin", "firstmate-guide", b"# Skill\n")
        plan = compile_workflow_plan(_supervisor_toml(), is_builtin=True, skill_root=skill_root, model_catalog=self.catalog)
        store = RunAuthorityStore()

        # Writable non-sticky ancestor directory causes refusal BEFORE publication
        anc = self.root / "anc_writable"
        anc.mkdir(mode=0o700)
        child_stage = anc / "stage"
        child_stage.mkdir(mode=0o700)
        os.chmod(child_stage, 0o700)
        os.chmod(anc, 0o770)  # group-writable non-sticky ancestor!
        r_anc = evaluate_admission(
            plan, store, principal_id="op-1", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        with self.assertRaises(MaterializationError):
            materialize_workflow_plan(plan, r_anc, authority_store=store, clock=self.clock, staging_root=child_stage)
        self.assertEqual(list(child_stage.iterdir()), [])
        os.chmod(anc, 0o700)

        # Swapping ancestor to user-owned symlink causes refusal; root-owned OS alias succeeds
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
            materialize_workflow_plan(plan, r_anc, authority_store=store, clock=self.clock, staging_root=aliased_stage)
        artifacts = materialize_workflow_plan(
            plan, r_anc, authority_store=store, clock=self.clock,
            staging_root=aliased_stage, root_alias_checker=lambda p: p == home_alias,
        )
        self.assertTrue(artifacts.skill_path.exists())

        # Revocation between admission and materialization yields ZERO files written
        r_rev = evaluate_admission(
            plan, store, principal_id="op-1", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        store.revoke_run(r_rev.run_id)
        with self.assertRaises(AuthorityError):
            materialize_workflow_plan(plan, r_rev, authority_store=store, clock=self.clock, staging_root=self.staging)
        self.assertEqual(list(self.staging.iterdir()), [])

        # compile_workflow_plan rejects skill_root inside forbidden_sandbox_roots and '..' paths
        sup_toml = _supervisor_toml()
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(
                sup_toml, is_builtin=True, skill_root=skill_root, model_catalog=self.catalog,
                forbidden_sandbox_roots=(skill_root,),
            )
        dotdot_skill = skill_root / "builtin" / ".." / "builtin"
        with self.assertRaises(MaterializationError):
            compile_workflow_plan(sup_toml, is_builtin=True, skill_root=dotdot_skill, model_catalog=self.catalog)

        # Approved root alias pointing to a user-owned 2nd-hop symlink MUST fail closed!
        hop2_link = self.root / "user_hop2"
        os.symlink(real_var, hop2_link)
        hop1_alias = self.root / "root_hop1"
        os.symlink(hop2_link, hop1_alias)
        r_hop = evaluate_admission(
            plan, store, principal_id="op-1", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        hop_stage = hop1_alias / "stage"
        with self.assertRaises(MaterializationError):
            materialize_workflow_plan(
                plan, r_hop, authority_store=store, clock=self.clock,
                staging_root=hop_stage, root_alias_checker=lambda p: p == hop1_alias,
            )

        # Boolean TTL and NaN lease expiry rejected
        with self.assertRaises(AdmissionDeniedError):
            evaluate_admission(
                plan, store, principal_id="op-1", caller_role="operator",
                caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4,
                clock=self.clock, operator_lease_ttl_s=True,  # type: ignore[arg-type]
            )
        with self.assertRaises(AdmissionDeniedError):
            WorkflowRunLease(
                run_id="r_nan", grant_generation=1, principal_id="op-1", owner_role="operator",
                workflow_id=plan.spec.id, workflow_plan_digest=plan.workflow_plan_digest,
                expires_at_wall_s=math.nan,
            )

        # Forbidden sandbox root rejected
        sandbox_home = self.root / "sandbox_home"
        sandbox_home.mkdir(mode=0o700)
        os.chmod(sandbox_home, 0o700)
        r_sb = evaluate_admission(
            plan, store, principal_id="op-1", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        with self.assertRaises(MaterializationError):
            materialize_workflow_plan(
                plan, r_sb, authority_store=store, clock=self.clock,
                staging_root=sandbox_home, forbidden_sandbox_roots=(sandbox_home,),
            )

    def test_observe_only_nonexclusive_lane_incarnation_revocation_and_pause(self) -> None:
        skill_root = _make_skill_tree(self.root, "user", "observer-guide", b"# Obs\n")
        _make_skill_tree(self.root, "builtin", "firstmate-guide", b"# Sup\n")
        store = RunAuthorityStore()
        lanes = LaneLeaseRegistry()
        subtree_a = frozenset({"local/lane-a"})

        bad_sig = '\n[[signal_handlers]]\nsignal = "go"\neffects = ["nudge_sandbox"]\n'
        p_bad = compile_workflow_plan(
            _observe_only_toml(extra_signals=bad_sig), is_builtin=False, skill_root=skill_root, model_catalog=self.catalog,
        )
        with self.assertRaises(AdmissionDeniedError):
            evaluate_admission(
                p_bad, store, principal_id="orch-1", caller_role="orchestrator",
                caller_subtree=subtree_a, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
            )

        p_obs = compile_workflow_plan(
            _observe_only_toml(bound_targets='["local/lane-a"]'),
            is_builtin=False, skill_root=skill_root, model_catalog=self.catalog,
        )
        r_obs = evaluate_admission(
            p_obs, store, principal_id="orch-1", caller_role="orchestrator",
            caller_subtree=frozenset({"local/lane-a", "local/lane-b"}),
            active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        lane_a = TargetIncarnation("local/lane-a", "inc-1")
        lane_b = TargetIncarnation("local/lane-b", "inc-2")

        # Target inside caller_subtree but outside plan.bound_targets fails closed
        with self.assertRaises(AuthorityError):
            lanes.attach(lane_b, receipt=r_obs, authority_store=store, clock=self.clock)

        # Observer attaches first (even paused); operator still acquires exclusive lease on SAME incarnation!
        lanes.attach(lane_a, receipt=r_obs, authority_store=store, clock=self.clock)
        lanes.pause(r_obs.run_id)
        self.assertIsNone(lanes.exclusive_owner(lane_a))
        self.assertIn(r_obs.run_id, lanes.observers(lane_a))

        p_owner = compile_workflow_plan(
            _supervisor_toml(), is_builtin=True, skill_root=skill_root, model_catalog=self.catalog,
        )
        r_owner = evaluate_admission(
            p_owner, store, principal_id="op-1", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        lanes.attach(lane_a, receipt=r_owner, authority_store=store, clock=self.clock)
        lanes.assert_can_nudge(r_owner, lane_a, authority_store=store, clock=self.clock)

        # Pausing owner blocks assert_can_nudge and assert_can_act!
        lanes.pause(r_owner.run_id)
        with self.assertRaises(LaneAuthorityError):
            lanes.assert_can_nudge(r_owner, lane_a, authority_store=store, clock=self.clock)
        with self.assertRaises(LaneAuthorityError):
            lanes.assert_can_act(r_owner, lane_a, action="health_escalate_human", authority_store=store, clock=self.clock)
        lanes.resume(r_owner.run_id)

        # Second exclusive owner rejected
        r_owner2 = evaluate_admission(
            p_owner, store, principal_id="op-2", caller_role="operator",
            caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4, clock=self.clock,
        )
        with self.assertRaises(LaneOwnershipConflictError):
            lanes.attach(lane_a, receipt=r_owner2, authority_store=store, clock=self.clock)

        # Duplicate Tier-A run_id reuse rejected
        dup_lease = WorkflowRunLease(
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
                caller_subtree=self.empty_sub, active_orchestrator_runs=0, max_active_orchestrator_runs=4,
                clock=self.clock, tier_a_lease=dup_lease,
            )

        # Revoking target incarnation permanently blocks reattachment of that revoked incarnation!
        lanes.revoke_target_incarnation(lane_a, authority_store=store)
        self.assertIsNone(lanes.exclusive_owner(lane_a))
        with self.assertRaises(AuthorityError):
            lanes.attach(lane_a, receipt=r_owner, authority_store=store, clock=self.clock)

        # Mixed-role guard tested on a fresh unrevoked incarnation
        lane_a_fresh = TargetIncarnation("local/lane-a", "inc-fresh")
        lanes.attach(lane_a_fresh, receipt=r_obs, authority_store=store, clock=self.clock)
        rec_obs = store.verify_active(r_obs, clock=self.clock)
        rec_obs.lane_access = "exclusive_owner"
        with self.assertRaises(MixedLaneRoleError):
            lanes.attach(lane_a_fresh, receipt=r_obs, authority_store=store, clock=self.clock)


if __name__ == "__main__":
    unittest.main()
