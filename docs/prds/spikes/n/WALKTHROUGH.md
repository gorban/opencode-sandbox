# PRD N offline core & supervision feasibility walkthrough (Gate 1)

Parent plans: [prd_n](../../prd_n.md) · [prd_n1](../../prd_n1.md) · [prd_n2](../../prd_n2.md) ·
[prd_n3](../../prd_n3.md) · Review gates: [implementation review gates](../../README.md#implementation-review-gates)

## 1. Scope, non-overlap, and explicit non-decisions

This spike implements and verifies the **pure offline core** of PRD N (`N0–N2` reserved) under
`docs/prds/spikes/n/` only:

- **Files in scope (all new, strictly under `docs/prds/spikes/n/`):**
  1. `docs/prds/spikes/n/WALKTHROUGH.md` — this Gate 1 walkthrough (reviewed before code).
  2. `docs/prds/spikes/n/oc_workflow_schema.py` — `workflow@1` TOML parser/validator, bounded
     predicate AST, literal single-pass template validator/renderer, canonical digests
     (`spec_digest`, `candidate_rubric_digest`), and directional `compute_security_delta()` (all 10
     closed `SECURITY_DELTA_TRIGGERS`).
  3. `docs/prds/spikes/n/oc_workflow_plan.py` — pure side-effect-free `compile_workflow_plan()`,
     `evaluate_admission()` (`AdmissionReceipt`), post-approval fixture-owned
     `materialize_workflow_plan()`, and `LaneLeaseRegistry` enforcing exclusive
     `workflow_lane_leases` vs. nonexclusive `workflow_observer_subscriptions`.
  4. `docs/prds/spikes/n/oc_workflow_supervision.py` — offline supervision primitives:
     `HostSleepDetector`, `DecisionsRunBudget`, `FleetCheckBudget`, `OverlapCanaryScanner`,
     `LocalRulesDecisionsAdapter` (`decisions:local-rules-v1`), per-lane leading+single-trailing
     coalesced throttler, correlated-fault coalescer, stateless 4-tool scripted fake blind verifier
     with outbound disclosure/nonce/canary gate, independent-progress freshness guard, stratified
     reference-verdict confusion/calibration ledger, and stateful `ReplayGrantBudget` +
     rubric-digest-bound `run_calibration_replay()`.
  5. `docs/prds/spikes/n/test_workflow_schema_and_plan.py` &
     `docs/prds/spikes/n/test_workflow_supervision.py` — stdlib `unittest` unit and adversarial
     regression suites.
- **Strictly out of scope (zero edits):**
  - `oc_controller.py`, `oc_sandbox`, `docs/prds/spikes/m/*`, and all PRD I/L files remain untouched
    while PRD M's local adapter and hub/registry restart lanes proceed in parallel.
  - Shared controller/registry/hub wiring (`CoordRole.WORKFLOW`, `TrustClass.SYSTEM_ALERT`, SQLite
    tables, `WorkflowRunLease` controller integration, live HTTP brokers) is deferred to follow-up
    slices **N1b/N2b** after PRD M settles.
  - **N3** (three-tier Human Inbox UI, `oc-ui@1` React catalog, `-o` MCP RPC wiring) remains open
    and untouched.
  - **Zero external side effects:** all examples are disposable and local inside test-owned
    temporary directories; all model calls use deterministic in-process fakes (`local-rules-v1` and
    scripted blind-check fixtures); zero network, Podman, systemd, or host-state mutations.
- **Zero open product decisions resolved here:** All five open `(decision needed)` items in PRD N
  remain completely open:
  1. Initial rollout slice scope (`prd_n.md`) — this offline spike is shared foundation to both
     options and selects neither.
  2. Daemon restart UX (`prd_n1.md`) — no daemon/registry persistence in this slice.
  3. Blind real-model tier (`prd_n2.md`) — offline deterministic fake verifier only.
  4. Default scheduled audit sampling strategy (`prd_n2.md`) — stratified ledger accepts arbitrary
     named strata without fixing a default policy.
  5. Project-scoped `[Orchestrator Overlay]` (`prd_n3.md`) — open in N3.

---

## 2. Implementation-time choices submitted for Gate 1 review

These concrete engineering choices are not pinned to exact constants in PRD N1/N2 and are surfaced
here for security and general review before implementation:

1. **Canonical digest domain separation, numeric normalization & string hygiene:**
   - Every canonical digest uses SHA-256 over `domain_prefix + canonical_json_bytes` where
     `canonical_json_bytes` is UTF-8 `json.dumps(obj, sort_keys=True, separators=(",", ":"),
     ensure_ascii=False, allow_nan=False)`.
   - Domain prefixes: `"oc-wf-spec-v1:"` (`spec_digest`), `"oc-wf-plan-v1:"`
     (`workflow_plan_digest`), and `"oc-wf-rubric-v1:"` (`candidate_rubric_digest` over
     `{"decision_type", "rubric", "choices", "abstain_default", "canary_injection_question"}`).
   - Non-finite floats (`NaN`, `Inf`, `-Inf`) are rejected at parse and serialization boundaries.
   - **Exact integer/decimal normalization:**
     - All USD ceilings (`max_decisions_spend_usd`, `max_blind_check_spend_usd`,
       `max_replay_spend_usd`) are parsed via `decimal.Decimal` (non-negative, `<= 6` decimal
       places) and normalized to integer **microdollars** (`1 USD == 1_000_000` microdollars) so
       `$0` `observe_only` checks and cumulative spend caps are exact.
     - Ratio/threshold fields (e.g., `fp_drift_warn_threshold` in `[0, 1]`) are parsed via
       `decimal.Decimal` (`<= 4` decimal places) and normalized to exact integer **basis points**
       (`0..10_000`) in the canonical model so `0.25` vs. `0.250` and `1` vs. `1.0` produce
       identical `spec_digest` values.
   - **String sanitization:** Reject NUL (`\x00`) and Unicode BiDi override/isolate controls
     (`U+202A..U+202E`, `U+2066..U+2069`, `U+200E`, `U+200F`, `U+061C`) in **all** schema strings.
     Reject all ASCII C0/DEL control characters (`< 0x20` or `0x7f`) in identifiers, routes, models,
     keys, choices, and predicate literals; allow only `\n` and `\t` (never other C0/DEL controls)
     in multi-line prose fields (`description`, `rubric`, `[templates]`).
2. **Bounded predicate AST grammar & `bool`-vs-`int` separation:**
   - Closed grammar: boolean ops (`and`, `or`, `not`), single non-chained comparisons
     (`len(node.ops) == 1`: `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`), identifiers strictly matching
     `^(metric|event|lane|state|limits)\.[a-z][a-z0-9_]*$`, unary `-` permitted **only** on numeric
     literals (`int`/`Decimal`, never `bool`/`str`; unary `+` and `~` rejected), and scalar
     literals (`bool`, `int`, finite `Decimal`, short clean `str <= 128` bytes, or literal
     tuple/list of `<= 16` homogeneous same-type scalars for `in`).
   - Hard caps: `MAX_PREDICATE_BYTES = 512`, `MAX_AST_NODES = 64`, `MAX_AST_DEPTH = 8`.
   - **Strict type separation:** Enforce `type(x) is bool` distinct from `int`/`Decimal` at both
     compile and evaluation time (`True == 1` and `True in [1, 2]` are rejected/false). Forbid
     `str in str` substring matching—the RHS of `in` MUST be a literal container of `<= 16`
     same-type scalars. Zero `eval`, zero function calls, zero attribute chaining beyond
     `<namespace>.<field>`, zero indexing, zero loops, zero regexes.
3. **Literal single-pass template engine (`[templates]`):**
   - Closed placeholder allowlist: `ALLOWED_TEMPLATE_VARS = frozenset({"target_addr",
     "stall_seconds", "workflow_id"})`.
   - Templates are bounded (`<= 1024` bytes, `<= 32` templates per workflow) and validated in a
     single pass: only `{name}` where `name in ALLOWED_TEMPLATE_VARS` is permitted. Any stray `{`
     or `}`, format spec (`:`), conversion (`!`), dot (`.`), or bracket (`[`) fails validation.
     Rendering substitutes in a single pass so a substituted value containing `{...}` is never
     re-expanded.
4. **Directional `compute_security_delta(old_spec, new_spec)` rules (all 10 closed triggers):**
   - Creation (`old_spec is None`): emits `workflow_added` **plus** any enabled high-risk capability
     triggers (`workflow_autonomy_widened` if `autonomy != "observe_only"` or `allow_remote_workers`
     or `not defer_nudge_during_human_lease`, `workflow_decisions_route_added` if any decisions or
     blind-check route/spend is configured, `workflow_blocking_gate_changed` if any lane-pausing or
     blocking gate exists, `workflow_factory_changed` if any `factory_id` is bound,
     `workflow_excerpt_disclosure_changed` if `excerpt_disclosure != "none"`).
   - Diff (`old_spec` -> `new_spec`):
     1. `workflow_added`: creation only.
     2. `workflow_autonomy_widened`: autonomy escalated (`observe_only < nudge_bounded <
        orchestrator_signal`), target scope widened, `allow_remote_workers` `False -> True`,
        `defer_nudge_during_human_lease` `True -> False`, nudge/check/inbox caps increased, OR
        rate-limiting intervals *decreased* (`min_nudge_interval_s`, `throttle_period_s`,
        `tick_interval_s`).
     3. `workflow_decisions_route_added`: decisions/blind route or model/profile changed,
        decisions/blind call or microdollar spend caps increased, `scheduled_audit_interval_s`
        *increased* (weakening `FN` detection), OR `fleet_audit_checks_per_hour` *decreased*.
     4. `workflow_blocking_gate_changed`: any `human_gate_async` / `human_gate_blocking` stage
        added, removed, or modified.
     5. `workflow_skill_changed`: `orchestrator_skill` identifier or pinned `skill_sha256` changed.
     6. `workflow_template_changed`: any `[templates]` entry added, removed, or modified.
     7. `workflow_rubric_or_predicate_changed`: `candidate_rubric_digest` changed or any statechart
        transition predicate modified.
     8. `workflow_default_surface_changed`: `[dashboard.default_surface]` widgets, metrics, columns,
        or host chips changed.
     9. `workflow_factory_changed`: any `factory_id` reference added or changed.
     10. `workflow_excerpt_disclosure_changed`: `excerpt_disclosure` enabled or any of `(source,
         max_bytes, allowed_routes, permitted_uses)` widened.
5. **Skill slug namespacing, `dir_fd` `O_NOFOLLOW` materialization & root-owned OS symlink aliases:**
   - Skill `<slug>` validated strictly against `^[a-z0-9][a-z0-9_-]{0,63}$` and namespaced by
     origin (`wf-builtin-<slug>` vs. `wf-user-<slug>`) so `builtin/foo` and `user/foo` cannot
     collide on disk.
   - **Trusted directory ancestry (`assert_trusted_dir` parity):** Walk ancestors from `/` to the
     root (`skill_root` or `staging_root`), allowing **root-owned OS directory symlink aliases**
     above the trusted root (e.g., Fedora Silverblue/Atomic Linux `/home -> /var/home`), while
     rejecting any non-root/user-owned symlink ancestor, rejecting any symlink **at or below**
     `skill_root` / `staging_root`, verifying owner UID + `0o700` on `staging_root`, and verifying
     the resolved real path is not inside any caller-supplied `forbidden_sandbox_roots`.
   - `compile_workflow_plan()` opens `skill_root` via `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` and
     reads the skill via `os.open(..., O_RDONLY | O_NOFOLLOW, dir_fd=...)`, rejecting non-regular
     files, `st_nlink != 1`, wrong UID, or group/world-writable modes (`mode & 0o022 != 0`), and
     pins `(skill_bytes, skill_sha256)` in memory with **zero** disk writes.
   - `materialize_workflow_plan()` opens/creates every intermediate directory (`staging_root`,
     `skills`, `wf-<ns>-<slug>`, `plans`) via `dir_fd` + `O_NOFOLLOW` + `0o700` checks, re-verifies
     `sha256(plan.skill_bytes) == plan.skill_sha256` (never re-reading the mutable source), writes
     temp files with `O_CREAT | O_EXCL | O_NOFOLLOW`, `fsync`s file + directory FD, sets `0o400`,
     and atomically `os.replace(..., src_dir_fd=..., dst_dir_fd=...)`s into place.
6. **Explicit injected clocks (`ClockSnapshot`) & fleet-level `HostSleepDetector`:**
   - Every admission, budget, throttle, sleep, and replay method accepts explicit
     `ClockSnapshot(monotonic_s: float, wall_s: float)` (no hidden `time.time()` calls; non-finite
     values rejected).
   - A shared fleet-level `HostSleepDetector` rejects backward `monotonic_s < last_monotonic_s`
     (`ValueError`) and applies a uniform `wake_grace_until_mono` across all lanes whenever
     `wall_dt - mono_dt > sleep_gap_threshold_s` (`30s`). During `wake_grace` or an active human
     `InputLease`, a pending `trailing_queued` boundary is **preserved** (never dropped and never
     fired prematurely) and fires on the first eligible tick after grace/lease clears.
7. **Hardened offline `OverlapCanaryScanner`:**
   - Scans **both** the exact canonical UTF-8 serialized outbound payload bytes **and** every
     decoded string leaf value recursively (preventing `\n` or `\uXXXX` JSON-escape splits).
   - Matches configured corpus secrets via raw substring, whitespace-normalized substring, 16-byte
     sliding windows, **and** standard/URL-safe Base64 encodings (padding-stripped), plus
     case-insensitive credential/key prefixes (`sk-`, `ghp_`, `gho_`, `github_pat_`, `AKIA`,
     `AIza`, `xoxb-`, `ocjob_`, `ocpeer_`, `Bearer `, and `BEGIN ... PRIVATE KEY`).

---

## 3. Trust boundaries

| Boundary | Untrusted Input | Trusted Enforcement |
|---|---|---|
| **TOML & Candidate Parsing (`oc_workflow_schema.py`)** | User or `-o`-proposed `workflow@1` TOML, `candidate_toml`, predicates, `[templates]`, `oc-ui@1` widgets | Strict schema allowlist (`schema_version == 1`, `kind == "workflow@1"`), reject unknown keys, enforce state/transition/cadence/rubric/template bounds, reject NUL/control/BiDi chars, exact microdollar/basis-point normalization, reject mutable `factory_id` outside immutable `builtin/*`, compute deterministic `spec_digest` & `candidate_rubric_digest` |
| **Pure Compilation, Admission & Materialization (`oc_workflow_plan.py`)** | Unapproved preview call, plan swap against stale receipt, mutable skill source path, symlinked staging root | `compile_workflow_plan()` performs zero writes and pins skill bytes + SHA-256; `AdmissionReceipt` binds exact `(workflow_plan_digest, workflow_id, lane_access, allowed_subtree, expires_at_wall_s)`; `materialize_workflow_plan()` verifies receipt digest + expiry via injected `clock`, never re-reads disk source, uses `dir_fd` + `O_NOFOLLOW` + root-only OS ancestor alias check + non-sandbox guard |
| **Observe-Only Admission & Lane Ownership (`oc_workflow_plan.py`)** | `-o`-launched `observe_only` plan attempting hidden effects, vacuous scope, or exclusive lane squatting | Compiler computes complete reachable effect set; `observe_only` auto-admission requires `$0` spend, `0` call/nudge caps, `excerpt_disclosure == "none"`, non-vacuous subtree enforcement, and `observe_only` allowed effects only; `lane_access` is **always** `"nonexclusive_observer"` whenever `autonomy == "observe_only"` (even for operator or Tier-A lease); `LaneLeaseRegistry` forbids mixed-role attachment and enforces `assert_can_nudge` / `assert_can_observe` |
| **Supervision Telemetry (`oc_workflow_supervision.py`)** | Worker `stream_events` / `turn_completed`, self-reported chat claims (`"Got it, continuing!"`), raw error excerpts | Hard split between `trusted_metrics` and `untrusted_claims`; `last_transport_frame_at` is transport activity only; freshness guard & stall resets require independent host-verified `ProgressFingerprint` delta; `excerpt_disclosure = "none"` default + explicit `(source, max_bytes, allowed_routes, permitted_uses)` + dual-pass `OverlapCanaryScanner` on both System-1 and blind-check outbound payloads |
| **System-1 & Blind Verifier (`oc_workflow_supervision.py`)** | Prompt-injected excerpt trying to flood alerts, overrun spend via canary spam, force `"healthy_progress"`, or emit rogue tool calls | Throttler window boundary evaluated *before* System-1 so `triggered_trailing` genuinely bypasses System-1; System-1 calls (including positive-canary numeric-only re-eval) pre-charged against `DecisionsRunBudget` and re-validated; repeated canary escalations tagged in dedicated `"canary_escalation"` stratum; blind check enforces disclosure + 128-bit nonce `<oc-untrusted-data>` framing + canary scan + at most 1 closed tool call with validated args + nudge caps & `dedupe_key` |
| **Calibration Replay (`oc_workflow_supervision.py`)** | `-o` modifying rubric after approval, replaying repeatedly under one grant, or passing cross-run / duplicate / out-of-subtree `sample_ids` | Candidate compiled offline first; `CalibrationReplayGrant` binds `(workflow_id, candidate_spec_digest, candidate_rubric_digest, route, model, disclosure_policy, sample_scope, caps, expires_at)`; stateful `ReplayGrantBudget` tracks cumulative calls/microdollars/revocation across invocations; rejects empty/duplicate `sample_ids`; per-record authorization on every sample and aggregate; strips excerpts when `"none"` and enforces `"replay" in permitted_uses` when opt-in |

---

## 4. Pseudocode walkthrough

### 4.1 Pure compilation, `AdmissionReceipt`, and `dir_fd` materialization (`oc_workflow_schema.py`, `oc_workflow_plan.py`)

```python
# --- Pure side-effect-free compilation (workflow_plan_preview) ---
def compile_workflow_plan(
    raw_toml: str,
    *,
    is_builtin: bool,
    skill_root: Path,
    model_catalog: ModelCatalog,
    allowlisted_factories: frozenset[str] = frozenset(),
) -> CompiledWorkflowPlan:
    spec = parse_and_validate_workflow_toml(
        raw_toml,
        is_builtin=is_builtin,
        allowlisted_factories=allowlisted_factories,
    )
    # 1. Validate closed bounds, bounded predicate AST (bool != int, no chained cmp,
    #    no str-in-str), literal single-pass [templates], closed oc-ui@1 widgets.
    # 2. Compute complete reachable effect set across states, transitions,
    #    signal handlers, timers, and factory_id bindings:
    reachable_effects = compute_reachable_effects(spec)
    # 3. Validate model_catalog entries, excerpt_disclosure bindings, and exact
    #    microdollar tariff upper bounds.
    # 4. Verify skill_root ancestry (root-owned OS aliases above root allowed;
    #    zero symlinks at/below root), open skill via dir_fd + O_RDONLY | O_NOFOLLOW
    #    (regular file, st_nlink == 1, same UID, mode & 0o022 == 0).
    #    Pin (skill_slug, skill_namespace, skill_bytes, skill_sha256) in memory.
    #    ZERO disk writes here.
    # 5. Compute immutable spec_digest, candidate_rubric_digest, workflow_plan_digest.
    return CompiledWorkflowPlan(...)


def evaluate_admission(
    plan: CompiledWorkflowPlan,
    *,
    caller_role: Literal["operator", "orchestrator"],
    caller_subtree: frozenset[str],
    active_orchestrator_runs: int,
    max_active_orchestrator_runs: int,
    clock: ClockSnapshot,
    tier_a_lease: WorkflowRunLease | None = None,
) -> AdmissionReceipt:
    # Hard invariant: observe_only NEVER receives exclusive_owner lane access,
    # regardless of caller_role or Tier-A lease.
    lane_access: LaneAccess = (
        "nonexclusive_observer"
        if plan.spec.autonomy == "observe_only"
        else "exclusive_owner"
    )
    allowed_subtree = None if caller_role == "operator" else caller_subtree

    if tier_a_lease is not None:
        verify_tier_a_lease_matches(
            plan,
            tier_a_lease,
            caller_role=caller_role,
            caller_subtree=caller_subtree,
            clock=clock,
        )
        # Checks: not lease.revoked, lease.workflow_plan_digest == plan.workflow_plan_digest,
        # lease.workflow_id == plan.spec.id, lease.owner_role == caller_role,
        # clock.wall_s < lease.expires_at_wall_s, and for orchestrator callers:
        # target_selector != "all_running_sandboxes" and bound_targets <= caller_subtree.
        return AdmissionReceipt(
            admitted=True,
            mode="tier_a_leased",
            lane_access=lane_access,
            workflow_plan_digest=plan.workflow_plan_digest,
            workflow_id=plan.spec.id,
            caller_role=caller_role,
            allowed_subtree=allowed_subtree,
            expires_at_wall_s=tier_a_lease.expires_at_wall_s,
        )

    if caller_role == "operator":
        return AdmissionReceipt(
            admitted=True,
            mode="operator_direct",
            lane_access=lane_access,
            workflow_plan_digest=plan.workflow_plan_digest,
            workflow_id=plan.spec.id,
            caller_role="operator",
            allowed_subtree=None,
            expires_at_wall_s=None,
        )

    # Orchestrator auto-admission path: strict observe_only gate
    has_non_vacuous_scope = (
        (plan.spec.scope.target_selector == "bound_targets" and len(plan.bound_targets) > 0 and plan.bound_targets.issubset(caller_subtree))
        or (plan.spec.scope.target_selector == "project_scope" and len(caller_subtree) > 0)
    )
    if (
        plan.spec.autonomy == "observe_only"
        and plan.spec.limits.max_decisions_spend_microusd == 0
        and plan.spec.limits.max_blind_check_spend_microusd == 0
        and plan.spec.limits.max_decisions_calls_per_hour == 0
        and plan.spec.limits.max_nudges_per_target_per_hour == 0
        and plan.spec.limits.max_total_nudges_per_run == 0
        and plan.spec.excerpt_disclosure_mode == "none"
        and has_non_vacuous_scope
        and active_orchestrator_runs < max_active_orchestrator_runs
        and plan.reachable_effects.issubset(OBSERVE_ONLY_ALLOWED_EFFECTS)
    ):
        return AdmissionReceipt(
            admitted=True,
            mode="observe_only_auto",
            lane_access="nonexclusive_observer",
            workflow_plan_digest=plan.workflow_plan_digest,
            workflow_id=plan.spec.id,
            caller_role="orchestrator",
            allowed_subtree=caller_subtree,  # enforced dynamically on every attach()
            expires_at_wall_s=None,
        )
    return AdmissionReceipt(
        admitted=False,
        mode="denied",
        lane_access="nonexclusive_observer",
        workflow_plan_digest=plan.workflow_plan_digest,
        workflow_id=plan.spec.id,
        caller_role=caller_role,
        allowed_subtree=allowed_subtree,
        expires_at_wall_s=None,
        reason="TIER_A_APPROVAL_REQUIRED",
    )


# --- Approved materialization (fixture-owned staging root) ---
def materialize_workflow_plan(
    plan: CompiledWorkflowPlan,
    receipt: AdmissionReceipt,
    *,
    clock: ClockSnapshot,
    staging_root: Path,
    forbidden_sandbox_roots: tuple[Path, ...] = (),
) -> MaterializedArtifacts:
    require(receipt.admitted)
    require(receipt.workflow_plan_digest == plan.workflow_plan_digest)
    require(receipt.workflow_id == plan.spec.id)
    if receipt.expires_at_wall_s is not None:
        require(clock.wall_s < receipt.expires_at_wall_s)
    # 1. Verify staging_root ancestry (root-owned OS aliases above root allowed;
    #    no symlinks at/below root; 0o700; same UID; not inside forbidden_sandbox_roots).
    # 2. Re-verify sha256(plan.skill_bytes) == plan.skill_sha256 (never re-read disk source).
    # 3. Use dir_fd + O_DIRECTORY | O_NOFOLLOW for staging_root -> skills -> wf-<ns>-<slug>
    #    and staging_root -> plans; create temp files with O_CREAT | O_EXCL | O_NOFOLLOW,
    #    fsync file + dir_fd, chmod 0o400, atomically os.replace(..., dir_fd).
    return MaterializedArtifacts(skill_path=..., lockfile_path=..., digest=plan.workflow_plan_digest)
```

### 4.2 Exclusive `workflow_lane_leases` vs. nonexclusive `workflow_observer_subscriptions` (`oc_workflow_plan.py`)

```python
class LaneLeaseRegistry:
    # exclusive_leases: dict[TargetIncarnation, str]       # (sandbox_addr, incarnation_id) -> run_id
    # observer_subs:    dict[TargetIncarnation, set[str]]  # (sandbox_addr, incarnation_id) -> {run_id, ...}
    # run_roles:        dict[str, LaneAccess]              # single fixed role per run_id

    def attach(
        self,
        run_id: str,
        target: TargetIncarnation,
        *,
        receipt: AdmissionReceipt,
    ) -> None:
        require(receipt.admitted)
        if receipt.allowed_subtree is not None and target.sandbox_addr not in receipt.allowed_subtree:
            raise SubtreeScopeViolationError(run_id, target)
        # Forbid mixed-role attachment for the same run_id
        if run_id in self.run_roles and self.run_roles[run_id] != receipt.lane_access:
            raise MixedLaneRoleError(run_id)
        self.run_roles[run_id] = receipt.lane_access

        if receipt.lane_access == "nonexclusive_observer":
            if self.exclusive_leases.get(target) == run_id:
                raise MixedLaneRoleError(run_id)
            self.observer_subs.setdefault(target, set()).add(run_id)
            return

        if run_id in self.observer_subs.get(target, ()):
            raise MixedLaneRoleError(run_id)
        if target in self.exclusive_leases and self.exclusive_leases[target] != run_id:
            raise LaneOwnershipConflictError(target, owner=self.exclusive_leases[target])
        self.exclusive_leases[target] = run_id

    def assert_can_nudge(self, run_id: str, target: TargetIncarnation) -> None:
        if self.exclusive_leases.get(target) != run_id:
            raise LaneAuthorityError(run_id, target)

    def assert_can_observe(self, run_id: str, target: TargetIncarnation) -> None:
        if self.exclusive_leases.get(target) != run_id and run_id not in self.observer_subs.get(target, ()):
            raise LaneAuthorityError(run_id, target)

    def pause(self, run_id: str) -> None:
        # Exclusive owner retains lease while paused; nonexclusive observer never held one.
        ...

    def release(self, run_id: str) -> None:
        # Atomic cleanup on completed | failed | revoked for both maps and run_roles.
        ...

    def revoke_target_incarnation(self, target: TargetIncarnation) -> None:
        # Clears both exclusive_leases[target] and observer_subs[target] on incarnation rotation/revocation.
        ...
```

### 4.3 Supervision pipeline: sleep detector, throttler-before-System-1, canary re-eval, blind gate & freshness guard (`oc_workflow_supervision.py`)

```python
def process_supervision_tick(
    lane_state: LaneSupervisionState,
    snapshot: MetricSnapshot,       # trusted_metrics + optional untrusted_claims
    clock: ClockSnapshot,
    policy: SupervisionPolicy,
    sleep_detector: HostSleepDetector,
    decisions_budget: DecisionsRunBudget,
    fleet_budget: FleetCheckBudget,
    nudge_budget: NudgeRunBudget,
    lease_registry: LaneLeaseRegistry,
    canary_scanner: OverlapCanaryScanner,
    decisions_adapter: LocalRulesDecisionsAdapter,
    blind_verifier: ScriptedBlindVerifier,
    ledger: CalibrationLedger,
) -> SupervisionTickResult:
    # 1. Fleet-level sleep/suspend detection & monotonic guard (Trap T6):
    #    Rejects clock.monotonic_s < sleep_detector.last_monotonic_s (ValueError).
    #    If wall_dt - mono_dt > sleep_gap_threshold_s (30s): sets uniform fleet
    #    wake_grace_until_mono = clock.monotonic_s + policy.wake_grace_s and adds
    #    excluded sleep time. Preserves any pending lane_state.trailing_queued.
    if sleep_detector.observe_and_in_grace(clock, wake_grace_s=policy.wake_grace_s):
        return SupervisionTickResult(status="deferred_wake_grace")

    # 2. Human InputLease freeze (Trap T9): preserves trailing_queued without firing.
    if snapshot.trusted.human_input_lease_active:
        return SupervisionTickResult(status="deferred_human_lease")

    # 3. Correlated fleet-outage coalescing (Trap T8):
    #    Shared (provider_route, remote_worker, error_class) threshold -> emit ONE
    #    deduplicated fleet-scoped notice instead of N per-lane escalations.

    # 4. Check THROTTLED window boundary BEFORE calling System-1 (ensures trailing bypass):
    if lane_state.mode == "THROTTLED" and clock.monotonic_s >= lane_state.window_end_mono:
        if lane_state.trailing_queued:
            # Bypass System-1 completely; evaluate fresh S_now under fleet budget
            slot = fleet_budget.acquire(kind="triggered", clock=clock)
            if slot == "cap_delayed":
                ledger.record_cap_event(stratum="triggered_trailing", outcome="cap_delayed")
                return SupervisionTickResult(status="trailing_cap_delayed")  # keeps trailing_queued=True
            if slot == "cap_dropped":
                ledger.record_cap_event(stratum="triggered_trailing", outcome="cap_dropped")
                lane_state.roll_throttled_window(clock.monotonic_s + policy.throttle_period_s)
                return SupervisionTickResult(status="trailing_cap_dropped")
            result = run_blind_check_and_act(
                snapshot_for_model=snapshot,
                current_snapshot=snapshot,
                stratum="triggered_trailing",
                sys1_verdict=None,  # excluded from System-1 TP/FP
                ...,
            )
            lane_state.roll_throttled_window(clock.monotonic_s + policy.throttle_period_s)
            return result
        else:
            lane_state.mode = "IDLE"

    # 5. System-1 evaluation (pre-charged against DecisionsRunBudget):
    payload_bytes, leaves = build_decisions_payload(snapshot, policy.excerpt_disclosure, route=policy.decisions_route, use="live")
    canary_scanner.scan(payload_bytes, decoded_leaves=leaves)
    if not decisions_budget.reserve(calls=1, cost_microusd=policy.decisions_call_cost_microusd, clock=clock):
        return SupervisionTickResult(status="decisions_budget_exhausted_tier0_only")
    sys1_resp = decisions_adapter.evaluate(payload_bytes, canary_question=policy.canary_question)
    if not is_valid_sys1_response(sys1_resp, policy.choices):
        ledger.record_abstention(stratum="triggered_leading")
        return SupervisionTickResult(status="sys1_abstained_fail_closed")

    # 6. Positive classifier_injection_suspected canary: NEVER default to healthy_progress
    if sys1_resp.injection_canary_positive:
        lane_state.canary_hits += 1
        num_bytes, num_leaves = build_metrics_only_payload(snapshot.trusted)
        canary_scanner.scan(num_bytes, decoded_leaves=num_leaves)
        if not decisions_budget.reserve(calls=1, cost_microusd=policy.decisions_call_cost_microusd, clock=clock):
            return SupervisionTickResult(status="canary_reeval_budget_exhausted_security_notice")
        sys1_resp = decisions_adapter.evaluate(num_bytes, canary_question=False)
        if not is_valid_sys1_response(sys1_resp, policy.choices):
            ledger.record_abstention(stratum="canary_escalation")
            return SupervisionTickResult(status="canary_reeval_abstained")
        if lane_state.canary_hits >= policy.repeated_canary_threshold:
            # Escalate in dedicated "canary_escalation" stratum (never pollutes System-1 TP/FP)
            ...

    # 7. Non-alert vs. alert throttler handling:
    if sys1_resp.choice == policy.healthy_choice:  # e.g. "healthy_progress"
        return SupervisionTickResult(status="healthy_no_action")

    if lane_state.mode == "THROTTLED":
        lane_state.trailing_queued = True
        lane_state.suppressed_count += 1
        return SupervisionTickResult(status="throttled_trailing_queued")

    # IDLE + Alert #1 -> immediate leading check on frozen S1
    slot = fleet_budget.acquire(kind="triggered", clock=clock)
    if slot in ("cap_delayed", "cap_dropped"):
        ledger.record_cap_event(stratum="triggered_leading", outcome=slot)
        return SupervisionTickResult(status=f"leading_{slot}")
    lane_state.enter_throttled(window_end_mono=clock.monotonic_s + policy.throttle_period_s)
    return run_blind_check_and_act(
        snapshot_for_model=snapshot,
        current_snapshot=snapshot,
        stratum="triggered_leading",
        sys1_verdict=sys1_resp.choice,
        ...,
    )


def run_blind_check_and_act(...) -> SupervisionTickResult:
    # 1. Enforce excerpt_disclosure for blind_route ("live" in permitted_uses; strip if "none").
    # 2. Wrap any permitted excerpt in 128-bit random-nonce <oc-untrusted-data nonce="...">
    #    with breakout escaping; run canary_scanner.scan(exact_payload_bytes, decoded_leaves).
    # 3. Call blind_verifier.check(...) (stateless, receives zero System-1 hint).
    # 4. Validate response: strictly 1 tool call in closed 4-tool enum with closed args
    #    (template_id in plan.spec.templates, closed category / reason_code).
    #    Malformed / >1 calls / invalid args -> record blind_abstain (never TP/FP/TN/FN).
    # 5. Record TP/FP/TN/FN/class_mismatch in explicit stratum against frozen S1 (or S_audit).
    # 6. Freshness guard (Trap T4 & T5): compare current_snapshot.trusted.progress_fingerprint
    #    vs. snapshot_for_model.trusted.progress_fingerprint ONLY (commit_sha, tree_oid,
    #    diff_stat_hash, verified_test_exit_seq, workflow_state_seq — NEVER last_transport_frame_at,
    #    stream_events, turn_completed, or chat text).
    # 7. Before executing side effect: re-verify lease active, target incarnation, absence of
    #    human InputLease, lease_registry.assert_can_nudge(run_id, target), autonomy,
    #    nudge_budget (min_nudge_interval_s, per-target/hr, total/run), and dedupe_key.
    ...
```

### 4.4 Stateful rubric-bound calibration replay (`oc_workflow_supervision.py`)

```python
def run_calibration_replay(
    grant: CalibrationReplayGrant,
    grant_budget: ReplayGrantBudget,  # stateful per grant_id: calls_used, spend_microusd_used, revoked
    candidate_plan: CompiledWorkflowPlan,
    sample_ids: Sequence[str],
    ledger: CalibrationLedger,
    *,
    caller_id: str,
    caller_role: Literal["operator", "orchestrator"],
    caller_subtree: frozenset[str],
    clock: ClockSnapshot,
    canary_scanner: OverlapCanaryScanner,
    decisions_adapter: LocalRulesDecisionsAdapter,
) -> ReplayScorecard:
    # 1. Grant validity, revocation, workflow/rubric/spec/route/model/disclosure binding:
    require(not grant_budget.is_revoked(grant.grant_id))
    require(clock.wall_s < grant.expires_at_wall_s)
    require(grant.requesting_principal == caller_id)
    require(grant.workflow_id == candidate_plan.spec.id)
    require(candidate_plan.spec_digest == grant.candidate_spec_digest)
    require(candidate_plan.candidate_rubric_digest == grant.candidate_rubric_digest)
    require(candidate_plan.spec.system1.route == grant.approved_decisions_route)
    require(candidate_plan.spec.system1.model == grant.approved_model)
    require(candidate_plan.spec.excerpt_disclosure == grant.excerpt_disclosure_policy)
    require(len(sample_ids) > 0 and len(sample_ids) == len(set(sample_ids)))
    require(len(sample_ids) <= grant.max_replay_samples)

    # 2. Per-record authorization on every sample_id (NEVER workflow_id alone):
    #    Verify sample exists, sample.run_id == grant.run_id, sample.stratum in
    #    grant.authorized_sample_scope, and target authorized for (caller_role, caller_subtree).
    # 3. For each authorized sample:
    #    - Strip stored excerpt when policy == "none"; if opt-in, enforce (source, max_bytes,
    #      grant.approved_decisions_route in allowed_routes, "replay" in permitted_uses).
    #    - Run canary_scanner.scan(exact_payload_bytes, decoded_leaves).
    #    - Reserve (calls=1, cost_microusd) in stateful grant_budget BEFORE adapter call
    #      (enforcing cumulative max_replay_calls & max_replay_spend_microusd across invocations).
    # 4. Return stratified before vs. after reference-verdict scorecard (including abstentions
    #    and cap-drop notes).
```

---

## 5. Failure, recovery, and adversarial verification matrix

### `docs/prds/spikes/n/test_workflow_schema_and_plan.py`
1. **Valid builtin & user TOML parsing & canonical normalization:** Parses `firstmate-supervisor`
   and `statechart` TOML; confirms `0.25` vs. `0.250` and `1` vs. `1.0` produce identical
   `spec_digest`; confirms exact integer microdollar and basis-point conversion.
2. **Schema, limit & string-sanitization rejections:** Rejects unknown keys, `schema_version != 1`,
   `states > 32`, `transitions > 64`, `tick_interval_s < 10`, `rubric > 2048` bytes, non-finite
   floats, negative or sub-microdollar spend, NUL/control/BiDi characters, `factory_id` in
   non-builtin TOML without allowlist, and invalid `oc-ui@1` widgets.
3. **Bounded predicate AST security:** Accepts valid bounded expressions (including unary `-` on
   numeric literals); rejects `True == 1` and `True in [1, 2]` (`bool`-vs-`int` trap), `str in str`
   substring matching, chained comparisons (`1 < metric.x < 10`), depth > 8, nodes > 64, > 512
   bytes, calls, attribute chaining, disallowed namespaces, regexes, and `in` list > 16.
4. **Literal single-pass template security:** Accepts `{target_addr}`, `{stall_seconds}`,
   `{workflow_id}`; rejects `{target_addr.__class__}`, `{target_addr[0]}`, `{unknown}`, format
   specs, stray braces, and verifies single-pass non-re-expansion.
5. **Directional `compute_security_delta()` (all 10 triggers):** Verifies creation (`old_spec is
   None`) emits `workflow_added` plus enabled capability triggers; verifies interval *decreases*
   (`min_nudge_interval_s`, `throttle_period_s`, `tick_interval_s`), `allow_remote_workers`
   `False -> True`, `defer_nudge_during_human_lease` `True -> False`, `scheduled_audit_interval_s`
   *increases*, `fleet_audit_checks_per_hour` *decreases*, and `workflow_excerpt_disclosure_changed`
   all fire; verifies benign description-only edits emit zero triggers.
6. **Pure compile zero-write, slug namespacing & skill TOCTOU defense:** Confirms
   `compile_workflow_plan()` creates zero files, namespaces `builtin/foo` (`wf-builtin-foo`) vs.
   `user/foo` (`wf-user-foo`), rejects symlink/hardlink/world-writable skill files via `O_NOFOLLOW`,
   and proves post-compile source edits never alter materialized bytes (and tampered pinned bytes
   fail digest re-verification).
7. **Admission receipt binding, `dir_fd` staging & Silverblue symlink-ancestor tests:**
   - Rejects swapping a different plan into `materialize_workflow_plan()` with another plan's
     `AdmissionReceipt` or an expired lease receipt (verified via injected `ClockSnapshot`).
   - Rejects symlinked intermediate dirs under `staging_root`, wrong modes, user-owned symlink
     ancestors, and staging paths inside a forbidden sandbox root.
   - Verifies `materialize_workflow_plan()` succeeds when a root-owned OS directory alias sits above
     `staging_root` (Fedora Silverblue `/home -> /var/home` pattern, mocked/verified via ownership
     check) while still rejecting any user-owned symlink ancestor.
8. **`observe_only` effect allowlist, non-vacuous scope & nonexclusive lane ownership:**
   - Rejects `observe_only` auto-admission even at `$0` spend when any reachable disallowed effect
     exists, when call/nudge caps > 0, or when `bound_targets` is empty / out-of-subtree.
   - Proves `observe_only` gets `"nonexclusive_observer"` even when launched by operator or Tier-A
     lease, attaches strictly to `workflow_observer_subscriptions`, and leaves an operator/owning
     workflow free to claim `workflow_lane_leases` on the same `(sandbox_addr, incarnation_id)`.
   - Verifies `LaneLeaseRegistry` rejects mixed-role attachment for one `run_id`, enforces
     `assert_can_nudge` / `assert_can_observe` and dynamic `allowed_subtree`, and clears both maps
     on `revoke_target_incarnation()`.

### `docs/prds/spikes/n/test_workflow_supervision.py`
1. **Throttler-before-System-1 & trailing bypass:** Burst of 5 alerts in Period 1 -> Alert #1
   dispatches `triggered_leading` on frozen `S1`, Alerts #2–#5 set `trailing_queued = True`,
   Period-1 boundary **bypasses System-1** (0 System-1 calls at boundary!) and dispatches one
   `triggered_trailing` blind check on `S_now`, Period-2 burst requeues for Period 3, quiet
   Period 3 returns to `IDLE`; verifies `healthy_progress` leaves `IDLE`/`THROTTLED` cleanly.
2. **Fleet outer cap & non-starvable audit floor (Trap T3):** Synchronized 10-lane burst saturating
   `fleet_max_checks_per_hour` records `cap_dropped`/`cap_delayed` (including on trailing boundary)
   while scheduled unalerted audits still execute under reserved `fleet_audit_checks_per_hour`.
3. **Outbound disclosure & hardened `OverlapCanaryScanner` on BOTH System-1 and blind verifier:**
   - Default `excerpt_disclosure = "none"` strips excerpts from both System-1 and blind-check
     payloads.
   - Opted-in disclosure enforces `(source, max_bytes, allowed_routes, permitted_uses)`, wraps
     blind-check excerpts in 128-bit random-nonce `<oc-untrusted-data nonce="...">` with breakout
     escaping, and blocks JSON-escaped PEM newlines (`\n`), `\uXXXX`-split secrets, Base64-encoded
     corpus secrets, and case-insensitive credential prefixes (`sk-`, `ghp_`, `ocjob_`, etc.).
4. **Positive `classifier_injection_suspected` canary:** Never maps to `"healthy_progress"`;
   pre-charges the numeric-only re-evaluation against `DecisionsRunBudget`, re-validates the second
   response for malformed/unknown choices, and tags repeated canary escalations in the dedicated
   `"canary_escalation"` stratum (isolated from System-1 `TP/FP`).
5. **Closed 4-tool blind-check validation & nudge caps:** Rejects 0 tools, >1 tools, unknown tool
   names, unknown `template_id`/`category`/`reason_code` as `blind_abstain` (never `TP/FP/TN/FN`),
   and enforces `assert_can_nudge`, `min_nudge_interval_s`, per-target/hr, total/run caps, and
   `dedupe_key`.
6. **Transport-only `turn_completed` & self-report immunity (Trap T5):** Synthetic `turn_completed`,
   `stream_events`, and `"Got it, continuing!"` update `last_transport_frame_at` only and never
   suppress the freshness guard or reset stall/nudge counters; genuine `ProgressFingerprint` delta
   does.
7. **Point-in-time `TP/FP/TN/FN/class_mismatch` & stratified accounting (Trap T4 & T11):**
   Verifies `S1` scoring vs. freshness suppression, `triggered_trailing` isolation, scheduled-audit
   `FN` direct execution, and accurate per-stratum inclusion rates, cap drops/delays, and
   abstentions.
8. **Fleet-level `HostSleepDetector` (Trap T6) & correlated fleet outage (Trap T8):**
   - Rejects backward `monotonic_s` (`ValueError`); applies uniform wake-grace window across all
     lanes on `wall_dt - mono_dt > 30s`; preserves pending `trailing_queued` across `wake_grace`
     and `InputLease` without dropping or premature firing.
   - Coalesces correlated `(provider_route, remote_worker, error_class)` failures into one
     fleet-scoped notice.
9. **Stateful rubric-digest-bound calibration replay & per-record authorization:**
   - Offline-compiled candidate matching grant's `(workflow_id, candidate_spec_digest,
     candidate_rubric_digest, route, model, disclosure_policy)` succeeds.
   - Post-approval edit to `rubric` or `choices` fails closed (`RUBRIC_DIGEST_MISMATCH`).
   - Calling `run_calibration_replay()` repeatedly with the same `grant` cannot exceed cumulative
     `max_replay_calls` or `max_replay_spend_microusd` in stateful `ReplayGrantBudget` (and revoked
     grants fail closed).
   - Empty/duplicate `sample_ids`, cross-run or out-of-subtree `sample_ids`, missing `"replay"` in
     `permitted_uses`, or canary-leaking excerpts fail closed; aggregate queries exclude
     unauthorized records.

---

## 6. Verification commands planned after Gate 1 clearance

1. `python3 -B -m unittest discover -s docs/prds/spikes/n -p 'test_*.py'`
2. `git diff --check` and verification that `git diff --name-only origin/main` touches only
   `docs/prds/spikes/n/*`
3. `tests/security.sh` (with real Podman) and hosted PR checks before Gate 2 review
