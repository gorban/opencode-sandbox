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
     fixture-owned in-memory `RunAuthorityStore` & `AdmissionReceipt` (`evaluate_admission()`),
     post-approval fixture-owned `materialize_workflow_plan()`, and `LaneLeaseRegistry` enforcing
     exclusive `workflow_lane_leases` vs. nonexclusive `workflow_observer_subscriptions`.
  4. `docs/prds/spikes/n/oc_workflow_supervision.py` — offline supervision primitives:
     `HostSleepDetector`, `DecisionsRunBudget`, `BlindCheckRunBudget`, `FleetCheckBudget`,
     `NudgeRunBudget`, `OverlapCanaryScanner`, unified `SupervisionBrokerGate` choke point wrapping
     both `LocalRulesDecisionsAdapter` (`decisions:local-rules-v1`) and `ScriptedBlindVerifier`,
     per-lane leading+single-trailing coalesced throttler, correlated-fault coalescer,
     post-verdict fresh-snapshot `ProgressFingerprint` freshness guard, stratified
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
5. **Skill source modes (`0o700` dir / `0o600` file, `O_NONBLOCK`), slug namespacing & `dir_fd` materialization:**
   - Skill `<slug>` validated strictly against `^[a-z0-9][a-z0-9_-]{0,63}$` and namespaced by
     origin (`wf-builtin-<slug>` vs. `wf-user-<slug>`) so `builtin/foo` and `user/foo` cannot
     collide on disk.
   - **Trusted directory ancestry (`assert_trusted_dir` parity):** Walk ancestors from `/` to the
     root (`skill_root` or `staging_root`), allowing **root-owned OS directory symlink aliases**
     above the trusted root (e.g., Fedora Silverblue/Atomic Linux `/home -> /var/home`), while
     rejecting any non-root/user-owned symlink ancestor, rejecting any symlink **at or below**
     `skill_root` / `staging_root`, verifying owner UID + exact `0o700` mode (`stat.S_IMODE(mode) ==
     0o700`) on `skill_root`, intermediate skill dirs, and `staging_root`, and verifying the
     resolved real path is not inside any caller-supplied `forbidden_sandbox_roots`.
   - `compile_workflow_plan()` opens `skill_root` via `O_RDONLY | O_DIRECTORY | O_NOFOLLOW`
     (verifying exact `0o700` and expected UID) and opens the skill source via `os.open(...,
     O_RDONLY | O_NOFOLLOW | O_NONBLOCK, dir_fd=...)`, immediately `fstat`s the FD, and enforces:
     `stat.S_ISREG(st.st_mode)` (so a FIFO or non-regular entry can never stall preview),
     `st.st_uid == expected_uid`, exact **`stat.S_IMODE(st.st_mode) == 0o600`** (rejecting `0o644`
     and any group/world bits per [prd_n1](../../prd_n1.md)), `st.st_nlink == 1`, and size
     `<= 64 KiB`. It pins `(skill_bytes, skill_sha256)` in memory with **zero** disk writes.
   - `materialize_workflow_plan()` rechecks live run authority in `RunAuthorityStore` (catching any
     intervening revocation, expiry, or reuse across runs), opens/creates every intermediate
     directory (`staging_root`, `skills`, `wf-<ns>-<slug>`, `plans`) via `dir_fd` + `O_NOFOLLOW` +
     `0o700` checks, re-verifies `sha256(plan.skill_bytes) == plan.skill_sha256` (never re-reading
     the mutable source), writes temp files with `O_CREAT | O_EXCL | O_NOFOLLOW`, `fsync`s file +
     directory FD, sets `0o400`, and atomically `os.replace(..., src_dir_fd=..., dst_dir_fd=...)`s
     into place.
6. **Fixture-owned `RunAuthorityStore` (single live authority source across admission, materialization, attachment, supervision & replay):**
   - Every admitted run—including `operator_direct` (which mints a bounded `operator_leased` run
     lease per [prd_n1](../../prd_n1.md)), `tier_a_leased`, and `observe_only_auto`—registers an
     authoritative `RunAuthorityRecord` in `RunAuthorityStore` binding `(run_id, grant_generation,
     principal_id, owner_role, workflow_id, workflow_plan_digest, admission_mode, lane_access,
     effective_target_scope, expires_at_wall_s, revoked, materialized)`.
   - `AdmissionReceipt` is a non-self-authorizing handle `(run_id, grant_generation,
     workflow_plan_digest, workflow_id)`. Every materialization, lane attachment, fake-adapter
     supervision call, post-verdict action, and calibration query/replay rechecks live state in
     `RunAuthorityStore`.
   - `effective_target_scope` narrows strictly to the plan's declared targets intersected with caller
     authority: for `target_selector == "bound_targets"`, `effective_target_scope` is **strictly
     `plan.bound_targets`** (verified non-empty and `<= caller_subtree` for orchestrator callers)—a
     target inside `caller_subtree` but outside `plan.bound_targets` is always rejected!
7. **Unified `SupervisionBrokerGate` choke point & per-run blind-check spend budget:**
   - Every fake model invocation—System-1 (`LocalRulesDecisionsAdapter`), blind check
     (`ScriptedBlindVerifier`), and calibration replay—passes through a single `SupervisionBrokerGate`
     that checks (in strict order, **before** invoking any fake adapter):
     1. Live run authority (`RunAuthorityStore.verify_active`) or active unrevoked
        `CalibrationReplayGrant` + live run/target authorization;
     2. Effective route/model match against the authorized plan/grant;
     3. `excerpt_disclosure` policy (`"none"` strips all excerpts; opt-in checks `source`,
        `max_bytes`, `effective_route in allowed_routes`, `use in permitted_uses`, and 128-bit
        random-nonce `<oc-untrusted-data nonce="...">` breakout-escaped framing for blind checks);
     4. Canonical outbound payload construction **including `canary_question` (when enabled) inside
        the serialized payload** + dual-pass `OverlapCanaryScanner` (exact UTF-8 serialized bytes
        **and** all decoded string leaf values, raw/normalized/16-byte sliding windows/Base64
        corpus encodings + case-insensitive credential/PEM prefixes);
     5. Applicable per-run call and integer-microdollar spend reservation (`DecisionsRunBudget`,
        `BlindCheckRunBudget`, or stateful `ReplayGrantBudget`).
   - Any failed check or exhausted budget yields **zero fake-adapter invocations** (even if
     `FleetCheckBudget` still has spare scheduling capacity).
8. **Explicit injected clocks (`ClockSnapshot`) & fleet-level `HostSleepDetector`:**
   - Every authority, budget, throttle, sleep, and replay method accepts explicit
     `ClockSnapshot(monotonic_s: float, wall_s: float)` (no hidden `time.time()` calls; non-finite
     values rejected).
   - Shared fleet-level `HostSleepDetector` rejects backward `monotonic_s < last_monotonic_s`
     (`ValueError`) and applies a uniform `wake_grace_until_mono` across all lanes whenever
     `wall_dt - mono_dt > sleep_gap_threshold_s` (`30s`). During `wake_grace` or an active human
     `InputLease`, a pending `trailing_queued` boundary is preserved and fires on the first eligible
     tick after grace/lease clears.

---

## 3. Trust boundaries

| Boundary | Untrusted Input | Trusted Enforcement |
|---|---|---|
| **TOML & Candidate Parsing (`oc_workflow_schema.py`)** | User or `-o`-proposed `workflow@1` TOML, `candidate_toml`, predicates, `[templates]`, `oc-ui@1` widgets | Strict schema allowlist (`schema_version == 1`, `kind == "workflow@1"`), reject unknown keys, enforce state/transition/cadence/rubric/template bounds, reject NUL/control/BiDi chars, exact microdollar/basis-point normalization, reject mutable `factory_id` outside immutable `builtin/*`, compute deterministic `spec_digest` & `candidate_rubric_digest` |
| **Pure Compilation, Live Authority & Materialization (`oc_workflow_plan.py`)** | Unapproved preview call, FIFO/symlink/`0o644` skill source, receipt reuse for a 2nd run, revocation between preview and materialization, symlinked staging root | `compile_workflow_plan()` opens skill source with `O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK`, enforces `S_ISREG`, exact `0o700` dir & `0o600` file, `st_nlink == 1`, zero disk writes; `RunAuthorityStore` binds `(principal, run_id, grant_generation, workflow_plan_digest, effective_target_scope, finite expires_at, revoked)` for every admitted run (including `operator_direct`); `materialize_workflow_plan()` rechecks live authority, prevents receipt reuse across runs, never re-reads disk source, uses `dir_fd` + `O_NOFOLLOW` + root-only OS ancestor alias check + non-sandbox guard |
| **Observe-Only Admission & Lane Ownership (`oc_workflow_plan.py`)** | `-o`-launched `observe_only` plan attempting hidden effects, vacuous scope, target inside caller subtree but outside plan, or exclusive lane squatting | Compiler computes complete reachable effect set; `observe_only` auto-admission requires `$0` spend, `0` call/nudge caps, `excerpt_disclosure == "none"`, non-vacuous scope, and `observe_only` allowed effects only; `lane_access` is **always** `"nonexclusive_observer"` whenever `autonomy == "observe_only"`; `LaneLeaseRegistry.attach()` takes `receipt` + `RunAuthorityStore` (never a separate `run_id`), enforces `effective_target_scope` (`plan.bound_targets`), forbids mixed-role attachment, and enforces `assert_can_nudge` / `assert_can_observe` |
| **Unified Fake-Adapter Gate & Supervision Telemetry (`oc_workflow_supervision.py`)** | Expired/revoked run, exhausted blind-check spend with spare fleet slots, worker `stream_events` / `turn_completed`, self-reported chat claims, prompt-injected excerpts | `SupervisionBrokerGate` checks live run authority, route/model, disclosure policy, exact serialized payload (including `canary_question`) via dual-pass `OverlapCanaryScanner`, and per-run `DecisionsRunBudget` / `BlindCheckRunBudget` **before** any fake-adapter call; throttler window boundary evaluated before System-1; post-verdict fresh snapshot obtained *after* blind check for independent `ProgressFingerprint` freshness guard |
| **Calibration Queries & Replay (`oc_workflow_supervision.py`)** | `-o` modifying rubric after approval, replaying repeatedly under one grant, passing cross-run/duplicate/revoked/out-of-scope `sample_ids` | Candidate compiled offline first; `CalibrationReplayGrant` binds `(workflow_id, run_id, candidate_spec_digest, candidate_rubric_digest, route, model, disclosure_policy, sample_scope, caps, expires_at)`; stateful `ReplayGrantBudget` tracks cumulative calls/microdollars/revocation; every replay record and aggregate input rechecks current `(caller, run_id, target_incarnation)` authority in `RunAuthorityStore`; passes through `SupervisionBrokerGate` |

---

## 4. Pseudocode walkthrough

### 4.1 Pure compilation, `RunAuthorityStore`, and `dir_fd` materialization (`oc_workflow_schema.py`, `oc_workflow_plan.py`)

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
    #    signal handlers, timers, and factory_id bindings.
    # 3. Validate model_catalog entries, excerpt_disclosure bindings, and exact
    #    microdollar tariff upper bounds.
    # 4. Verify skill_root ancestry (root-owned OS aliases above root allowed;
    #    zero symlinks at/below root; exact 0o700 dir mode & expected UID).
    #    Open skill via os.open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, dir_fd=...),
    #    fstat immediately: require S_ISREG, expected UID, exact 0o600 mode, st_nlink == 1,
    #    size <= 64 KiB. Pin (skill_slug, skill_namespace, skill_bytes, skill_sha256).
    #    ZERO disk writes here.
    # 5. Compute immutable spec_digest, candidate_rubric_digest, workflow_plan_digest.
    return CompiledWorkflowPlan(...)


def evaluate_admission(
    plan: CompiledWorkflowPlan,
    authority_store: RunAuthorityStore,
    *,
    principal_id: str,
    caller_role: Literal["operator", "orchestrator"],
    caller_subtree: frozenset[str],
    active_orchestrator_runs: int,
    max_active_orchestrator_runs: int,
    clock: ClockSnapshot,
    operator_lease_ttl_s: float = 3600.0,
    auto_observer_ttl_s: float = 3600.0,
    tier_a_lease: WorkflowRunLease | None = None,
) -> AdmissionReceipt:
    # Hard invariant: observe_only NEVER receives exclusive_owner lane access.
    lane_access: LaneAccess = (
        "nonexclusive_observer"
        if plan.spec.autonomy == "observe_only"
        else "exclusive_owner"
    )
    # Effective target scope is ALWAYS narrowed to the plan's declared targets
    # intersected with caller scope (never wider than plan.bound_targets!).
    # target_selector == "bound_targets" with empty bound_targets is rejected at
    # schema/compile validation even for operator or Tier-A leased runs.
    effective_scope = compute_effective_target_scope(
        plan, caller_role=caller_role, caller_subtree=caller_subtree
    )

    if tier_a_lease is not None:
        verify_tier_a_lease_matches(
            plan, tier_a_lease,
            principal_id=principal_id,
            caller_role=caller_role,
            caller_subtree=caller_subtree,
            clock=clock,
        )
        # Registers exact (run_id, grant_generation, workflow_plan_digest, effective_scope,
        # expires_at_wall_s) in authority_store; rejects duplicate run_id reuse.
        return authority_store.mint_record(
            run_id=tier_a_lease.run_id,
            grant_generation=tier_a_lease.grant_generation,
            principal_id=principal_id,
            owner_role=caller_role,
            plan=plan,
            admission_mode="tier_a_leased",
            lane_access=lane_access,
            effective_target_scope=effective_scope,
            expires_at_wall_s=tier_a_lease.expires_at_wall_s,
        )

    if caller_role == "operator":
        # Per N1: operator-launched runs STILL mint a bounded run lease with run_id,
        # grant_generation, effective_target_scope, and finite expires_at_wall_s.
        return authority_store.mint_fresh_run(
            principal_id=principal_id,
            owner_role="operator",
            plan=plan,
            admission_mode="operator_leased",
            lane_access=lane_access,
            effective_target_scope=effective_scope,
            expires_at_wall_s=clock.wall_s + operator_lease_ttl_s,
        )

    # Orchestrator auto-admission path: strict observe_only gate
    if (
        plan.spec.autonomy == "observe_only"
        and plan.spec.limits.max_decisions_spend_microusd == 0
        and plan.spec.limits.max_blind_check_spend_microusd == 0
        and plan.spec.limits.max_decisions_calls_per_hour == 0
        and plan.spec.limits.max_nudges_per_target_per_hour == 0
        and plan.spec.limits.max_total_nudges_per_run == 0
        and plan.spec.excerpt_disclosure_mode == "none"
        and effective_scope.is_non_vacuous()
        and active_orchestrator_runs < max_active_orchestrator_runs
        and plan.reachable_effects.issubset(OBSERVE_ONLY_ALLOWED_EFFECTS)
    ):
        return authority_store.mint_fresh_run(
            principal_id=principal_id,
            owner_role="orchestrator",
            plan=plan,
            admission_mode="observe_only_auto",
            lane_access="nonexclusive_observer",
            effective_target_scope=effective_scope,
            expires_at_wall_s=clock.wall_s + auto_observer_ttl_s,
        )
    raise AdmissionDeniedError("TIER_A_APPROVAL_REQUIRED")


# --- Approved materialization (fixture-owned staging root) ---
def materialize_workflow_plan(
    plan: CompiledWorkflowPlan,
    receipt: AdmissionReceipt,
    *,
    authority_store: RunAuthorityStore,
    clock: ClockSnapshot,
    staging_root: Path,
    forbidden_sandbox_roots: tuple[Path, ...] = (),
) -> MaterializedArtifacts:
    # 1. Recheck LIVE authority record: catches intervening revocation, expiry,
    #    generation mismatch, plan swap, or reuse of a receipt already materialized.
    record = authority_store.verify_active(
        receipt, clock=clock, expected_plan_digest=plan.workflow_plan_digest
    )
    require(not record.materialized, "RECEIPT_ALREADY_MATERIALIZED")
    # 2. Verify staging_root ancestry (root-owned OS aliases above root allowed;
    #    no symlinks at/below root; exact 0o700; same UID; not inside forbidden_sandbox_roots).
    # 3. Re-verify sha256(plan.skill_bytes) == plan.skill_sha256 (never re-read disk source).
    # 4. Use dir_fd + O_DIRECTORY | O_NOFOLLOW for staging_root -> skills -> wf-<ns>-<slug>
    #    and staging_root -> plans; create temp files with O_CREAT | O_EXCL | O_NOFOLLOW,
    #    fsync file + dir_fd, chmod 0o400, atomically os.replace(..., dir_fd).
    authority_store.mark_materialized(record.run_id, record.grant_generation)
    return MaterializedArtifacts(skill_path=..., lockfile_path=..., digest=plan.workflow_plan_digest)
```

### 4.2 Exclusive `workflow_lane_leases` vs. nonexclusive `workflow_observer_subscriptions` (`oc_workflow_plan.py`)

```python
class LaneLeaseRegistry:
    # exclusive_leases: dict[TargetIncarnation, str]       # (sandbox_addr, incarnation_id) -> run_id
    # observer_subs:    dict[TargetIncarnation, set[str]]  # (sandbox_addr, incarnation_id) -> {run_id, ...}
    # run_roles:        dict[str, LaneAccess]

    def attach(
        self,
        target: TargetIncarnation,
        *,
        receipt: AdmissionReceipt,
        authority_store: RunAuthorityStore,
        clock: ClockSnapshot,
    ) -> None:
        # Derives run_id, lane_access, and effective_target_scope strictly from LIVE authority!
        # Rejects revoked/expired runs, wrong generation, and targets inside caller_subtree
        # that fall outside plan.bound_targets.
        record = authority_store.verify_active(receipt, clock=clock, target=target)
        run_id = record.run_id

        if run_id in self.run_roles and self.run_roles[run_id] != record.lane_access:
            raise MixedLaneRoleError(run_id)
        self.run_roles[run_id] = record.lane_access

        if record.lane_access == "nonexclusive_observer":
            if self.exclusive_leases.get(target) == run_id:
                raise MixedLaneRoleError(run_id)
            self.observer_subs.setdefault(target, set()).add(run_id)
            return

        if run_id in self.observer_subs.get(target, ()):
            raise MixedLaneRoleError(run_id)
        if target in self.exclusive_leases and self.exclusive_leases[target] != run_id:
            raise LaneOwnershipConflictError(target, owner=self.exclusive_leases[target])
        self.exclusive_leases[target] = run_id

    def assert_can_nudge(self, receipt: AdmissionReceipt, target: TargetIncarnation, *, authority_store: RunAuthorityStore, clock: ClockSnapshot) -> None:
        record = authority_store.verify_active(receipt, clock=clock, target=target)
        if self.exclusive_leases.get(target) != record.run_id:
            raise LaneAuthorityError(record.run_id, target)

    def assert_can_observe(self, receipt: AdmissionReceipt, target: TargetIncarnation, *, authority_store: RunAuthorityStore, clock: ClockSnapshot) -> None:
        record = authority_store.verify_active(receipt, clock=clock, target=target)
        if self.exclusive_leases.get(target) != record.run_id and record.run_id not in self.observer_subs.get(target, ()):
            raise LaneAuthorityError(record.run_id, target)

    def revoke_run(self, run_id: str, authority_store: RunAuthorityStore) -> None:
        # Marks RunAuthorityRecord revoked AND releases both exclusive leases and observer subs.
        ...

    def revoke_target_incarnation(self, target: TargetIncarnation) -> None:
        # Clears both exclusive_leases[target] and observer_subs[target] on incarnation rotation.
        ...
```

### 4.3 Unified `SupervisionBrokerGate`, throttler-before-System-1, & post-verdict fresh snapshot (`oc_workflow_supervision.py`)

```python
class SupervisionBrokerGate:
    """Single mandatory boundary for ALL fake model calls (System-1, blind check, replay)."""

    def invoke_decisions_live(
        self,
        *,
        receipt: AdmissionReceipt,
        plan: CompiledWorkflowPlan,
        target: TargetIncarnation,
        snapshot: MetricSnapshot,
        include_canary_question: bool,
        metrics_only_override: bool,
        authority_store: RunAuthorityStore,
        decisions_budget: DecisionsRunBudget,
        clock: ClockSnapshot,
    ) -> DecisionsAdapterResponse:
        # 1. Recheck LIVE run authority & effective target scope BEFORE payload build or call.
        authority_store.verify_active(
            receipt, clock=clock, expected_plan_digest=plan.workflow_plan_digest, target=target
        )
        # 2. Enforce route/model + excerpt_disclosure ("none" or metrics_only_override strips
        #    excerpts; opt-in verifies source, max_bytes, route in allowed_routes, "live" in uses).
        # 3. Construct exact canonical payload INCLUDING canary_question when enabled;
        #    scan serialized bytes AND decoded string leaves via OverlapCanaryScanner.
        # 4. Reserve (calls=1, cost_microusd) in DecisionsRunBudget BEFORE adapter call.
        #    On exhaustion -> raise BudgetExhaustedError (0 adapter invocations!).
        return self._decisions_adapter.evaluate(checked_payload_bytes)

    def invoke_blind_check_live(
        self,
        *,
        receipt: AdmissionReceipt,
        plan: CompiledWorkflowPlan,
        target: TargetIncarnation,
        snapshot_for_model: MetricSnapshot,
        stratum: str,
        authority_store: RunAuthorityStore,
        blind_budget: BlindCheckRunBudget,
        clock: ClockSnapshot,
    ) -> BlindCheckResponse:
        # 1. Recheck LIVE run authority & target scope BEFORE payload build or adapter call!
        authority_store.verify_active(
            receipt, clock=clock, expected_plan_digest=plan.workflow_plan_digest, target=target
        )
        # 2. Enforce blind route/model + excerpt_disclosure ("none" strips excerpts; opt-in checks
        #    source, max_bytes, blind_route in allowed_routes, "live" in permitted_uses, and wraps
        #    permitted excerpt in 128-bit random-nonce <oc-untrusted-data nonce="..."> breakout-escaped).
        # 3. Run OverlapCanaryScanner on exact serialized payload bytes AND decoded leaves.
        # 4. Reserve (calls=1, cost_microusd) in per-run BlindCheckRunBudget BEFORE adapter call!
        #    An exhausted blind budget or revoked/expired lease yields ZERO fake-adapter calls
        #    even when FleetCheckBudget has spare capacity.
        return self._blind_verifier.check(checked_payload_bytes)


def process_supervision_tick(
    lane_state: LaneSupervisionState,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    *,
    receipt: AdmissionReceipt,
    plan: CompiledWorkflowPlan,
    clock: ClockSnapshot,
    sleep_detector: HostSleepDetector,
    authority_store: RunAuthorityStore,
    broker_gate: SupervisionBrokerGate,
    decisions_budget: DecisionsRunBudget,
    blind_budget: BlindCheckRunBudget,
    fleet_budget: FleetCheckBudget,
    nudge_budget: NudgeRunBudget,
    lease_registry: LaneLeaseRegistry,
    ledger: CalibrationLedger,
) -> SupervisionTickResult:
    # 0. Verify run is still active before doing work (revoked/expired -> 0 adapter calls).
    authority_store.verify_active(
        receipt, clock=clock, expected_plan_digest=plan.workflow_plan_digest, target=lane_state.target
    )
    # 1. Fleet-level HostSleepDetector (rejects backward monotonic_s; uniform wake_grace;
    #    preserves any pending trailing_queued).
    if sleep_detector.observe_and_in_grace(clock, wake_grace_s=plan.spec.limits.wake_grace_s):
        return SupervisionTickResult(status="deferred_wake_grace")

    # Capture frozen point-in-time snapshot S1 (or S_now at trailing boundary) BEFORE model call:
    frozen_snapshot = snapshot_provider(lane_state.target)

    # 2. Human InputLease freeze (preserves trailing_queued without firing).
    if frozen_snapshot.trusted.human_input_lease_active:
        return SupervisionTickResult(status="deferred_human_lease")

    # 3. Correlated fleet-outage coalescing (Trap T8).

    # 4. Check THROTTLED window boundary BEFORE calling System-1 (trailing bypasses System-1):
    if lane_state.mode == "THROTTLED" and clock.monotonic_s >= lane_state.window_end_mono:
        if lane_state.trailing_queued:
            return dispatch_blind_with_post_verdict_freshness(
                frozen_snapshot=frozen_snapshot,
                snapshot_provider=snapshot_provider,
                stratum="triggered_trailing",
                sys1_verdict=None,
                roll_window_after=True,
                ...,
            )
        lane_state.mode = "IDLE"

    # 5. System-1 evaluation strictly through SupervisionBrokerGate:
    sys1_resp = broker_gate.invoke_decisions_live(
        receipt=receipt, plan=plan, target=lane_state.target, snapshot=frozen_snapshot,
        include_canary_question=plan.spec.system1.canary_injection_question,
        metrics_only_override=False, authority_store=authority_store,
        decisions_budget=decisions_budget, clock=clock,
    )
    if not is_valid_sys1_response(sys1_resp, plan.spec.system1.choices):
        ledger.record_abstention(stratum="triggered_leading")
        return SupervisionTickResult(status="sys1_abstained_fail_closed")

    # 6. Positive classifier_injection_suspected canary: NEVER default to healthy_progress.
    #    Re-evaluate numeric-only strictly through broker_gate (pre-charged & re-validated);
    #    repeated hits route through dispatch_blind_with_post_verdict_freshness (enforcing
    #    FleetCheckBudget + BlindCheckRunBudget + SupervisionBrokerGate) tagged in dedicated
    #    "canary_escalation" stratum.
    ...

    # 7. Non-alert vs. alert throttler handling:
    if sys1_resp.choice == plan.spec.system1.healthy_choice:
        return SupervisionTickResult(status="healthy_no_action")
    if lane_state.mode == "THROTTLED":
        lane_state.trailing_queued = True
        lane_state.suppressed_count += 1
        return SupervisionTickResult(status="throttled_trailing_queued")

    lane_state.enter_throttled(window_end_mono=clock.monotonic_s + plan.spec.limits.throttle_period_s)
    return dispatch_blind_with_post_verdict_freshness(
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        stratum="triggered_leading",
        sys1_verdict=sys1_resp.choice,
        ...,
    )


def dispatch_blind_with_post_verdict_freshness(
    *,
    frozen_snapshot: MetricSnapshot,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    stratum: str,
    sys1_verdict: str | None,
    ...,
) -> SupervisionTickResult:
    # 1. Pre-check live authority & per-run BlindCheckRunBudget BEFORE consuming fleet slot
    #    or calling fake blind adapter (0 adapter calls on revoked run or exhausted blind budget!).
    # 2. Acquire FleetCheckBudget slot (record cap_delayed / cap_dropped if capped).
    # 3. Call broker_gate.invoke_blind_check_live(snapshot_for_model=frozen_snapshot, ...).
    #    (During this call, host-verified progress or worker-only events may occur in real/test world.)
    # 4. Validate closed 4-tool response (strictly 1 tool, closed args; else blind_abstain).
    # 5. Record TP/FP/TN/FN/class_mismatch in ledger against FROZEN frozen_snapshot!
    # 6. Obtain FRESH host-trusted snapshot AFTER verdict & IMMEDIATELY before simulated action:
    fresh_snapshot = snapshot_provider(lane_state.target)
    # 7. Freshness guard (Trap T4 & T5):
    #    Compare fresh_snapshot.trusted.progress_fingerprint != frozen_snapshot.trusted.progress_fingerprint
    #    (commit_sha, tree_oid, diff_stat_hash, verified_test_exit_seq, workflow_state_seq ONLY —
    #    NEVER last_transport_frame_at, worker stream_events, synthetic turn_completed, or chat text).
    #    If host-verified progress advanced during the blind call: reference verdict stays recorded
    #    in ledger, and the live nudge is SUPPRESSED.
    #    If only worker-supplied turn_completed/stream_events arrived: ProgressFingerprint is unchanged,
    #    and the nudge decision proceeds unchanged.
    # 8. Re-verify live authority (authority_store.verify_active), absence of human InputLease on
    #    fresh_snapshot, lease_registry.assert_can_nudge, autonomy, nudge_budget, and dedupe_key.
    ...
```

### 4.4 Stateful rubric-bound calibration replay (`oc_workflow_supervision.py`)

```python
def run_calibration_replay(
    grant: CalibrationReplayGrant,
    grant_budget: ReplayGrantBudget,
    candidate_plan: CompiledWorkflowPlan,
    sample_ids: Sequence[str],
    ledger: CalibrationLedger,
    *,
    authority_store: RunAuthorityStore,
    broker_gate: SupervisionBrokerGate,
    caller_id: str,
    caller_role: Literal["operator", "orchestrator"],
    caller_subtree: frozenset[str],
    clock: ClockSnapshot,
) -> ReplayScorecard:
    # 1. Verify grant active/unrevoked/unexpired, principal, workflow_id, candidate_spec_digest,
    #    candidate_rubric_digest, route, model, disclosure policy, non-empty unique sample_ids,
    #    and len(sample_ids) <= grant.max_replay_samples.
    # 2. Recheck current run & target-incarnation authority in authority_store (and caller_subtree)
    #    for EVERY individual sample_id (and in query_calibration_examples for every aggregate input!).
    # 3. Dispatch each replay call through broker_gate.invoke_decisions_replay(...), which checks
    #    complete disclosure policy (strip on "none"; enforce source, max_bytes, route in
    #    allowed_routes, "replay" in permitted_uses on opt-in), includes canary_question in the
    #    checked canonical payload, runs dual-pass OverlapCanaryScanner, and reserves cumulative
    #    (calls=1, cost_microusd) in stateful ReplayGrantBudget BEFORE adapter invocation.
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
6. **Pure compile zero-write, strict `0o700`/`0o600` + `O_NONBLOCK` FIFO check & skill TOCTOU:**
   - Confirms `compile_workflow_plan()` creates zero files and namespaces `builtin/foo`
     (`wf-builtin-foo`) vs. `user/foo` (`wf-user-foo`).
   - Rejects `0o644` skill source file, rejects `0o755` skill directory, rejects symlink/hardlink
     skill sources, and rejects a named FIFO (`os.mkfifo`) placed at the skill path immediately
     without stalling (`O_NONBLOCK` + `S_ISREG`).
   - Proves post-compile source edits never alter materialized bytes (and tampered pinned bytes fail
     digest re-verification).
7. **Live `RunAuthorityStore` binding, receipt reuse, revocation-before-materialization & Silverblue aliases:**
   - Confirms `operator_direct` mints a finite `RunAuthorityRecord` (`run_id`, `grant_generation`,
     `expires_at_wall_s`) that expires and revokes cleanly.
   - Rejects reusing an `AdmissionReceipt` for a second run or second materialization.
   - Rejects materialization when the run is **revoked between preview/admission and
     `materialize_workflow_plan()`** (zero files written) or when the receipt is swapped for a
     different plan or expired.
   - Rejects symlinked intermediate dirs under `staging_root`, wrong modes, user-owned symlink
     ancestors, and staging paths inside a forbidden sandbox root; confirms root-owned OS directory
     alias above `staging_root` (Silverblue `/home -> /var/home` pattern) succeeds while user
     symlinks fail.
8. **`observe_only` effect allowlist, `effective_target_scope` narrowing & nonexclusive lane ownership:**
   - Rejects `observe_only` auto-admission even at `$0` spend when any reachable disallowed effect
     exists, when call/nudge caps > 0, or when `bound_targets` is empty / out-of-subtree.
   - Rejects `LaneLeaseRegistry.attach()` for a target **inside `caller_subtree` but outside
     `plan.bound_targets`**!
   - Proves `observe_only` gets `"nonexclusive_observer"` even when launched by operator or Tier-A
     lease, attaches strictly to `workflow_observer_subscriptions`, and leaves an operator/owning
     workflow free to claim `workflow_lane_leases` on the same `(sandbox_addr, incarnation_id)`.
   - Verifies `LaneLeaseRegistry` rejects mixed-role attachment, enforces live-authority
     `assert_can_nudge` / `assert_can_observe`, and clears both maps on `revoke_run()` and
     `revoke_target_incarnation()`.

### `docs/prds/spikes/n/test_workflow_supervision.py`
1. **Unified `SupervisionBrokerGate` pre-call authority & blind-check spend enforcement:**
   - Exhausted per-run `BlindCheckRunBudget` with spare `FleetCheckBudget` capacity yields **zero**
     fake blind-adapter invocations and zero excerpt disclosure (falls back to Tier-0 + notice).
   - Revoked or expired run lease yields **zero** System-1 and **zero** blind-adapter invocations
     even with spare fleet capacity.
   - Confirms `canary_question` is embedded inside the exact canonical serialized payload scanned by
     `OverlapCanaryScanner`.
2. **Throttler-before-System-1 & trailing bypass:** Burst of 5 alerts in Period 1 -> Alert #1
   dispatches `triggered_leading` on frozen `S1`, Alerts #2–#5 set `trailing_queued = True`,
   Period-1 boundary **bypasses System-1** (0 System-1 calls at boundary!) and dispatches one
   `triggered_trailing` blind check on `S_now`, Period-2 burst requeues for Period 3, quiet
   Period 3 returns to `IDLE`; verifies `healthy_progress` leaves `IDLE`/`THROTTLED` cleanly.
3. **Post-verdict fresh-snapshot freshness guard & `turn_completed` immunity (Trap T4 & T5):**
   - Scripted blind verifier advances host-verified `ProgressFingerprint` (`commit_sha`/`tree_oid`)
     **during** the blind call -> reference verdict (`TP`) stays recorded in the ledger against
     frozen `S1`, while the post-verdict fresh snapshot suppresses the live nudge.
   - Scripted blind verifier emits only worker-supplied `turn_completed`, `stream_events`, or
     `"Got it, continuing!"` during the blind call -> `last_transport_frame_at` advances,
     post-verdict `ProgressFingerprint` is unchanged, and the nudge decision proceeds unchanged.
4. **Fleet outer cap & non-starvable audit floor (Trap T3):** Synchronized 10-lane burst saturating
   `fleet_max_checks_per_hour` records `cap_dropped`/`cap_delayed` (including on trailing boundary)
   while scheduled unalerted audits still execute under reserved `fleet_audit_checks_per_hour`.
5. **Outbound disclosure & hardened `OverlapCanaryScanner` on BOTH System-1 and blind verifier:**
   - Default `excerpt_disclosure = "none"` strips excerpts from both System-1 and blind-check
     payloads.
   - Opted-in disclosure enforces `(source, max_bytes, allowed_routes, permitted_uses)`, wraps
     blind-check excerpts in 128-bit random-nonce `<oc-untrusted-data nonce="...">` with breakout
     escaping, and blocks JSON-escaped PEM newlines (`\n`), `\uXXXX`-split secrets, Base64-encoded
     corpus secrets, and case-insensitive credential prefixes (`sk-`, `ghp_`, `ocjob_`, etc.).
6. **Positive `classifier_injection_suspected` canary:** Never maps to `"healthy_progress"`;
   pre-charges the numeric-only re-evaluation through `SupervisionBrokerGate`, re-validates the
   second response for malformed/unknown choices, and tags repeated canary escalations in the
   dedicated `"canary_escalation"` stratum (isolated from System-1 `TP/FP`).
7. **Closed 4-tool blind-check validation & nudge caps:** Rejects 0 tools, >1 tools, unknown tool
   names, unknown `template_id`/`category`/`reason_code` as `blind_abstain` (never `TP/FP/TN/FN`),
   and enforces live-authority `assert_can_nudge`, `min_nudge_interval_s`, per-target/hr, total/run
   caps, and `dedupe_key`.
8. **Fleet-level `HostSleepDetector` (Trap T6) & correlated fleet outage (Trap T8):**
   - Rejects backward `monotonic_s` (`ValueError`); applies uniform wake-grace window across all
     lanes on `wall_dt - mono_dt > 30s`; preserves pending `trailing_queued` across `wake_grace`
     and `InputLease` without dropping or premature firing.
   - Coalesces correlated `(provider_route, remote_worker, error_class)` failures into one
     fleet-scoped notice.
9. **Stateful rubric-digest-bound calibration replay & live per-record authorization:**
   - Offline-compiled candidate matching grant's `(workflow_id, run_id, candidate_spec_digest,
     candidate_rubric_digest, route, model, disclosure_policy)` succeeds through
     `SupervisionBrokerGate`.
   - Post-approval edit to `rubric` or `choices` fails closed (`RUBRIC_DIGEST_MISMATCH`).
   - Calling `run_calibration_replay()` repeatedly with the same `grant` cannot exceed cumulative
     `max_replay_calls` or `max_replay_spend_microusd` in stateful `ReplayGrantBudget` (and revoked
     grants fail closed).
   - Empty/duplicate `sample_ids`, cross-run / revoked-run / out-of-scope `sample_ids`, missing
     `"replay"` in `permitted_uses`, or canary-leaking excerpts fail closed; aggregate queries
     recheck live `(caller, run_id, target_incarnation)` authority and exclude unauthorized records.

---

## 6. Verification commands planned after Gate 1 clearance

1. `python3 -B -m unittest discover -s docs/prds/spikes/n -p 'test_*.py'`
2. `git diff --check` and verification that `git diff --name-only origin/main` touches only
   `docs/prds/spikes/n/*`
3. `tests/security.sh` (with real Podman) and hosted PR checks before Gate 2 review
