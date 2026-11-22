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
     (`spec_digest`, `candidate_rubric_digest`), and `compute_security_delta()` (all 10 closed
     `SECURITY_DELTA_TRIGGERS`).
  3. `docs/prds/spikes/n/oc_workflow_plan.py` — pure side-effect-free `compile_workflow_plan()`,
     post-approval fixture-owned `materialize_workflow_plan()`, and `LaneLeaseRegistry` enforcing
     exclusive `workflow_lane_leases` vs. nonexclusive `workflow_observer_subscriptions`.
  4. `docs/prds/spikes/n/oc_workflow_supervision.py` — offline supervision primitives
     (`decisions:local-rules-v1` deterministic classifier, final-payload `excerpt_disclosure` +
     `OverlapCanaryScanner` gate, rubric-digest-bound `CalibrationReplayGrant` verifier/runner,
     per-lane leading+single-trailing coalesced throttler, fleet outer cap + non-starvable audit
     floor, sleep/wake gap detector, correlated-fault coalescer, stateless 4-tool scripted fake
     blind verifier, independent-progress freshness guard, and stratified reference-verdict
     confusion/calibration ledger).
  5. `docs/prds/spikes/n/test_workflow_schema_and_plan.py` &
     `docs/prds/spikes/n/test_workflow_supervision.py` — unit and adversarial regression tests.
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

1. **Canonical digest domain separation & strict float policy:**
   - Every canonical digest uses SHA-256 over `domain_prefix + canonical_json_bytes` where
     `canonical_json_bytes` is UTF-8 `json.dumps(obj, sort_keys=True, separators=(",", ":"),
     ensure_ascii=False, allow_nan=False)`.
   - Domain prefixes: `"oc-wf-spec-v1:"` (`spec_digest`), `"oc-wf-plan-v1:"`
     (`workflow_plan_digest`), and `"oc-wf-rubric-v1:"` (`candidate_rubric_digest` over
     `{"decision_type", "rubric", "choices", "abstain_default", "canary_injection_question"}`).
   - Non-finite floats (`NaN`, `Inf`, `-Inf`) are rejected at parse and serialization boundaries.
2. **Integer microdollars for spend ceilings:**
   - Parsed USD fields (`max_decisions_spend_usd`, `max_blind_check_spend_usd`,
     `max_replay_spend_usd`) are validated as non-negative finite decimals (up to 6 decimal places,
     parsed via `decimal.Decimal`—never binary `float` arithmetic) and stored internally as integer
     microdollars (`1 USD == 1_000_000` microdollars) so `$0` `observe_only` checks and spend-cap
     comparisons are exact.
3. **Bounded predicate AST grammar & limits:**
   - Closed grammar: boolean ops (`and`, `or`, `not`), comparisons (`==`, `!=`, `<`, `<=`, `>`,
     `>=`, `in`), identifiers strictly matching `^(metric|event|lane|state|limits)\.[a-z][a-z0-9_]*$`,
     and scalar literals (`bool`, `int`, finite `Decimal`/`float`, short `str <= 128` bytes, or
     literal tuple/list of `<= 16` scalars for `in`).
   - Hard caps: `MAX_PREDICATE_BYTES = 512`, `MAX_AST_NODES = 64`, `MAX_AST_DEPTH = 8`.
   - Zero `eval`, zero function calls, zero attribute chaining beyond `<namespace>.<field>`, zero
     indexing, zero loops, zero regexes. Unknown fields or mismatched operand types fail closed
     (`PredicateValidationError` at compile time; `False` + logged fault at evaluation time).
4. **Literal single-pass template engine (`[templates]`):**
   - Closed placeholder allowlist: `ALLOWED_TEMPLATE_VARS = frozenset({"target_addr",
     "stall_seconds", "workflow_id"})`.
   - Templates are bounded (`<= 1024` bytes, max `<= 32` templates per workflow) and scanned in a
     single pass with a strict tokenizer: only `{name}` where `name in ALLOWED_TEMPLATE_VARS` is
     permitted. Any unescaped `{` or `}`, format spec (`:`), conversion (`!`), dot (`.`), or
     bracket (`[`) fails validation. Rendering performs single-pass substitution so a substituted
     value containing `{...}` is never re-expanded.
5. **Fixture-owned `O_NOFOLLOW` skill reading & atomic materialization:**
   - `compile_workflow_plan()` reads `orchestrator_skill` source via `os.open(..., O_RDONLY |
     O_NOFOLLOW)` inside an explicit trusted skill root directory verified with `O_RDONLY |
     O_DIRECTORY | O_NOFOLLOW`, rejecting symlinks, non-regular files, `st_nlink != 1`, wrong UID,
     or group/world-writable modes (`mode & 0o022 != 0`), and pins `(skill_bytes, skill_sha256)` in
     memory without writing anything to disk.
   - `materialize_workflow_plan()` accepts a verified `AdmissionReceipt` (either `observe_only`
     auto-admission or approved `WorkflowRunLease` matching exact `workflow_plan_digest`) and a
     fixture-owned `staging_root` (`0o700`, same UID, non-symlink ancestry verified component by
     component, rejecting any path under a caller-supplied forbidden sandbox root). It re-verifies
     `sha256(plan.skill_bytes) == plan.skill_sha256`, never re-reads the mutable source file, writes
     the pinned bytes and `workflow_plan.lock.json` via `O_CREAT | O_EXCL | O_NOFOLLOW` temp files
     (`0o400` inside `0o700` dirs), `fsync`s file + parent dir, and atomically `os.replace`s into
     place.
6. **Explicit injected clocks (`ClockSnapshot`) & pure data contracts:**
   - Supervision components accept explicit `ClockSnapshot(monotonic_s: float, wall_s: float)` (no
     hidden `time.time()` calls) so throttle boundaries, sleep/wake gaps, and grant expiry tests are
     100% deterministic.
   - Target identities use frozen value tuples `(sandbox_addr: str, incarnation_id: str)` matching
     PRD M's address/incarnation contract without importing mutable PRD M modules.
7. **Offline `OverlapCanaryScanner` boundary:**
   - Scans the **exact canonical UTF-8 serialized outbound payload bytes** immediately before passing
     a request to the offline `decisions:local-rules-v1` or blind-check fake adapter. Rejects any
     match against a configured canary/secret corpus (exact or whitespace-normalized substring of
     length `>= 8` bytes, plus overlapping sliding-window chunks of length `16` bytes for multi-token
     secrets) and common credential token prefixes (`sk-`, `ghp_`, `ocjob_`, `BEGIN PRIVATE KEY`).

---

## 3. Trust boundaries

| Boundary | Untrusted Input | Trusted Enforcement |
|---|---|---|
| **TOML & Candidate Parsing (`oc_workflow_schema.py`)** | User or `-o`-proposed `workflow@1` TOML, `candidate_toml`, predicates, `[templates]`, `oc-ui@1` widgets | Strict schema allowlist (`schema_version == 1`, `kind == "workflow@1"`), reject unknown keys, enforce state/transition/cadence/rubric/template bounds, reject mutable `factory_id` outside immutable `builtin/*`, compute deterministic `spec_digest` & `candidate_rubric_digest` |
| **Pure Compilation vs. Materialization (`oc_workflow_plan.py`)** | Unapproved preview call (`workflow_plan_preview`), mutable skill source path on disk, symlinked staging root | `compile_workflow_plan()` performs zero writes and pins skill bytes + SHA-256 in memory; `materialize_workflow_plan()` requires matching `AdmissionReceipt`, never re-reads disk source, verifies `O_NOFOLLOW` + `0o700` + non-sandbox ancestry, and writes `0o400` staged artifacts atomically |
| **Observe-Only Admission & Lane Ownership (`oc_workflow_plan.py`)** | `-o`-launched `observe_only` plan attempting hidden effects or exclusive lane squatting | Compiler computes complete reachable effect set across states, transitions, signals, timers, and factories; `observe_only` auto-admission fails closed if any disallowed effect is reachable or spend > 0 or `excerpt_disclosure != "none"`; `LaneLeaseRegistry` forbids `observe_only` runs from acquiring/retaining `workflow_lane_leases` (nonexclusive `workflow_observer_subscriptions` only) |
| **Supervision Telemetry (`oc_workflow_supervision.py`)** | Worker-emitted `stream_events` / `turn_completed`, agent self-reported chat claims (`"Got it, continuing!"`), raw error excerpts | Hard split between `trusted_metrics` and `untrusted_claims`; `last_transport_frame_at` is transport activity only; freshness guard & stall resets require independent host-verified `ProgressFingerprint` delta; `excerpt_disclosure = "none"` default + explicit `(source, allowed_routes, permitted_uses)` + final-payload `OverlapCanaryScanner` |
| **System-1 & Blind Verifier (`oc_workflow_supervision.py`)** | Prompt-injected excerpt trying to flood alerts or force `"healthy_progress"` suppression | System-1 (`decisions:local-rules-v1`) returns only typed verdict + optional injection canary and holds zero execution authority; positive canary strips excerpt & re-evaluates on numeric metrics only; throttler bounds per-lane + fleet rate while preserving non-starvable audit floor; blind verifier is stateless with closed 4-tool enum only |
| **Calibration Replay (`oc_workflow_supervision.py`)** | `-o` requesting replay with modified rubric or cross-run / out-of-subtree `sample_ids` | Candidate compiled offline first; `CalibrationReplayGrant` binds exact `(candidate_spec_digest, candidate_rubric_digest, route, model, disclosure_policy, sample_scope, caps, expires_at)`; per-record `(caller, run_id, subtree, target_incarnation)` check on every sample and aggregate input; post-approval rubric edit fails closed |

---

## 4. Pseudocode walkthrough

### 4.1 Pure compilation vs. approved materialization & security delta (`oc_workflow_schema.py`, `oc_workflow_plan.py`)

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
    # 1. Validate closed statechart / fleet_supervisor bounds:
    #    states <= 32, transitions <= 64, tick_interval_s >= 10,
    #    rubric <= 2048 bytes, all predicates pass bounded AST validation,
    #    all [templates] pass single-pass placeholder allowlist,
    #    all [dashboard.default_surface] widgets in closed oc-ui@1 catalog.
    # 2. Compute complete reachable effect set across states, transitions,
    #    signal handlers, timers, and factory_id bindings:
    reachable_effects = compute_reachable_effects(spec)
    #    Effect tags include:
    #      OBSERVE_ONLY_ALLOWED = {
    #          "read_metrics", "update_health_projection", "post_advisory_inbox"
    #      }
    #      DISALLOWED_FOR_OBSERVE_ONLY = {
    #          "launch_sandbox", "stage_patch", "spawn_lane", "nudge_sandbox",
    #          "pause_lane_gate", "blocking_gate", "call_decisions_model",
    #          "call_blind_check_model", "invoke_factory", "acquire_lane_lease"
    #      }
    # 3. Validate model_catalog entries (capability == "decisions" / "blind_check"),
    #    excerpt_disclosure policy bindings (default "none"), and tariff upper bounds
    #    against microdollar spend ceilings.
    # 4. Read orchestrator_skill via O_RDONLY | O_NOFOLLOW from verified skill_root
    #    (regular file, st_nlink == 1, same UID, mode & 0o022 == 0).
    #    Pin (skill_bytes, skill_sha256) in memory. ZERO disk writes here.
    # 5. Compute immutable spec_digest, candidate_rubric_digest, workflow_plan_digest.
    return CompiledWorkflowPlan(...)


def evaluate_admission(
    plan: CompiledWorkflowPlan,
    *,
    caller_role: Literal["operator", "orchestrator"],
    caller_subtree: frozenset[str],
    active_orchestrator_runs: int,
    max_active_orchestrator_runs: int,
    tier_a_lease: WorkflowRunLease | None = None,
) -> AdmissionDecision:
    if tier_a_lease is not None:
        verify_tier_a_lease_matches(plan, tier_a_lease)  # exact workflow_plan_digest & expiry
        return AdmissionDecision(admitted=True, mode="tier_a_leased", lane_access="exclusive_owner")

    if caller_role == "operator":
        return AdmissionDecision(admitted=True, mode="operator_direct", lane_access="exclusive_owner")

    # Orchestrator auto-admission path: strict observe_only gate
    if (
        plan.spec.autonomy == "observe_only"
        and plan.spec.limits.max_decisions_spend_microusd == 0
        and plan.spec.limits.max_blind_check_spend_microusd == 0
        and plan.spec.excerpt_disclosure_mode == "none"
        and plan.spec.scope.target_selector != "all_running_sandboxes"
        and plan.bound_targets.issubset(caller_subtree)
        and active_orchestrator_runs < max_active_orchestrator_runs
        and plan.reachable_effects.issubset(OBSERVE_ONLY_ALLOWED_EFFECTS)
    ):
        return AdmissionDecision(
            admitted=True,
            mode="observe_only_auto",
            lane_access="nonexclusive_observer",  # NEVER exclusive_owner
        )
    return AdmissionDecision(admitted=False, reason="TIER_A_APPROVAL_REQUIRED")


# --- Approved materialization (fixture-owned staging root) ---
def materialize_workflow_plan(
    plan: CompiledWorkflowPlan,
    admission: AdmissionDecision,
    *,
    staging_root: Path,
    forbidden_sandbox_roots: tuple[Path, ...] = (),
) -> MaterializedArtifacts:
    require(admission.admitted)
    # 1. Verify staging_root ancestry: no symlinks, 0o700, same UID, not inside forbidden_sandbox_roots.
    # 2. Re-verify sha256(plan.skill_bytes) == plan.skill_sha256 (never re-read mutable source).
    # 3. Atomically write verified skill_bytes -> staging_root/skills/wf-<slug>/SKILL.md (0o400, O_NOFOLLOW)
    #    and canonical lockfile -> staging_root/plans/<workflow_plan_digest>.lock.json (0o400, O_NOFOLLOW).
    return MaterializedArtifacts(skill_path=..., lockfile_path=..., digest=plan.workflow_plan_digest)
```

### 4.2 Exclusive `workflow_lane_leases` vs. nonexclusive `workflow_observer_subscriptions` (`oc_workflow_plan.py`)

```python
class LaneLeaseRegistry:
    # exclusive_leases: dict[(sandbox_addr, incarnation_id), run_id]
    # observer_subs:    dict[(sandbox_addr, incarnation_id), set[run_id]]

    def attach(self, run_id: str, target: TargetIncarnation, *, lane_access: LaneAccess) -> None:
        if lane_access == "nonexclusive_observer":
            # Hard invariant: observe_only NEVER touches exclusive_leases
            self.observer_subs[target].add(run_id)
            return
        if target in self.exclusive_leases and self.exclusive_leases[target] != run_id:
            raise LaneOwnershipConflictError(target, owner=self.exclusive_leases[target])
        self.exclusive_leases[target] = run_id

    def pause(self, run_id: str) -> None:
        # Exclusive owner retains lease while paused; nonexclusive observer never held one.
        ...

    def release(self, run_id: str) -> None:
        # Atomic cleanup on completed | failed | revoked for BOTH exclusive leases & observer subs.
        ...
```

**Acceptance case verified directly in tests:** starting an auto-admitted `observe_only` observer on
`(sandbox_addr, incarnation_id)` (even while it stays `running` or transitions to `paused`) leaves an
operator or authorized owning workflow completely free to acquire the exclusive `workflow_lane_leases`
entry on that same `(sandbox_addr, incarnation_id)`.

### 4.3 Supervision pipeline: disclosure gate, zero-authority System-1, coalesced throttler, blind verifier & freshness guard (`oc_workflow_supervision.py`)

```python
def process_supervision_tick(
    lane_state: LaneSupervisionState,
    snapshot: MetricSnapshot,  # trusted_metrics + optional untrusted_claims
    clock: ClockSnapshot,
    policy: SupervisionPolicy,
    fleet_budget: FleetCheckBudget,
    canary_scanner: OverlapCanaryScanner,
    decisions_adapter: LocalRulesDecisionsAdapter,
    blind_verifier: ScriptedBlindVerifier,
) -> SupervisionTickResult:
    # 1. Host sleep/suspend gap detection (Trap T6):
    if lane_state.last_clock is not None:
        wall_dt = clock.wall_s - lane_state.last_clock.wall_s
        mono_dt = clock.monotonic_s - lane_state.last_clock.monotonic_s
        if wall_dt - mono_dt > policy.sleep_gap_threshold_s:  # 30s
            lane_state.wake_grace_until_mono = clock.monotonic_s + policy.wake_grace_s
            lane_state.excluded_sleep_s += max(0.0, wall_dt - mono_dt)
    lane_state.last_clock = clock
    if clock.monotonic_s < lane_state.wake_grace_until_mono:
        return SupervisionTickResult(status="deferred_wake_grace")

    # 2. Human InputLease freeze (Trap T9):
    if snapshot.trusted.human_input_lease_active:
        return SupervisionTickResult(status="deferred_human_lease")

    # 3. Correlated fleet-outage coalescing (Trap T8):
    #    Check fleet-wide shared (provider_route, remote_worker, error_class) threshold ->
    #    emit ONE fleet-scoped notice instead of N per-lane checks/escalations.

    # 4. Build outbound System-1 payload under strict disclosure policy:
    #    - Default excerpt_disclosure == "none": metrics-only payload (excerpts stripped/forbidden).
    #    - Opted-in excerpt_disclosure: verify (source, route in allowed_routes, use in permitted_uses),
    #      truncate <= max_bytes, sanitize control chars.
    #    - Run canary_scanner.scan(exact_serialized_payload_bytes) immediately before adapter call;
    #      on hit -> abort transmission (DisclosureBlockedError), log security event.
    sys1_resp = decisions_adapter.evaluate(payload_bytes, canary_question=policy.canary_question)

    # 5. Fail-closed / positive injection-canary handling:
    if sys1_resp.malformed or sys1_resp.unknown_choice:
        record_abstention(stratum="triggered_leading")
        return SupervisionTickResult(status="abstained_fail_closed")
    if sys1_resp.injection_canary_positive:
        # NEVER default to healthy_progress!
        log_security_event("classifier_injection_suspected", lane_state.target)
        numeric_only_payload = build_metrics_only_payload(snapshot.trusted)
        canary_scanner.scan(numeric_only_payload)
        sys1_resp = decisions_adapter.evaluate(numeric_only_payload, canary_question=False)
        # On repeated canary hits, enqueue throttled blind check + deduplicated security notice.

    # 6. Zero-authority System-1 -> per-lane leading + single-trailing coalesced throttler:
    #    - IDLE + alert #1 -> record prediction on frozen S1, attempt fleet_budget.acquire(kind="triggered")
    #      -> if cap blocks/delays: record cap_dropped / cap_delayed in ledger (never assume 100% inclusion!)
    #      -> else dispatch blind_verifier.check(S1, origin="triggered_leading") (no System-1 hint!)
    #      -> enter THROTTLED(window_end = clock.monotonic_s + T, trailing_queued=False)
    #    - THROTTLED + alerts #2..#N before window_end -> set trailing_queued=True, suppressed_count += 1
    #    - At clock.monotonic_s >= window_end:
    #      if trailing_queued -> capture fresh S_now, bypass System-1, dispatch ONE
    #        blind_verifier.check(S_now, origin="triggered_trailing") (own stratum, excluded from Sys1 TP/FP),
    #        re-enter THROTTLED(window_end = clock.monotonic_s + T, trailing_queued=False)
    #      else -> return to IDLE
    #
    #    Scheduled unalerted active-lane audits draw from fleet_budget.acquire(kind="scheduled_audit")
    #    which guarantees a non-starvable reserved slice (fleet_audit_checks_per_hour) even when
    #    triggered checks saturate the rest of fleet_max_checks_per_hour.

    # 7. Blind check scoring & independent-progress freshness guard (Trap T4 & T5):
    #    - Score TP/FP/TN/FN/class_mismatch against frozen snapshot S1 (or S_audit) in its explicit stratum.
    #    - Before executing any returned tool (health_nudge_lane / health_escalate_human /
    #      health_wake_orchestrator): re-verify active lease, target incarnation, absence of human
    #      InputLease, and run freshness guard:
    #        has_independent_progress = (
    #            current_trusted.progress_fingerprint != s1_trusted.progress_fingerprint
    #        )
    #      where ProgressFingerprint includes ONLY independent host-verified fields:
    #        (commit_sha, tree_oid, diff_stat_hash, verified_test_exit_seq, workflow_state_seq)
    #      NEVER last_transport_frame_at, worker stream_events, synthetic turn_completed, or chat text!
    #    - Only if has_independent_progress is True may freshness guard suppress the action or reset
    #      stall/nudge counters.
```

### 4.4 Offline rubric-bound calibration replay (`oc_workflow_supervision.py`)

```python
def run_calibration_replay(
    grant: CalibrationReplayGrant,
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
    # 1. Grant validity & exact candidate rubric/spec digest binding:
    require(clock.wall_s < grant.expires_at_wall_s)
    require(grant.requesting_principal == caller_id)
    require(candidate_plan.spec_digest == grant.candidate_spec_digest)
    require(candidate_plan.candidate_rubric_digest == grant.candidate_rubric_digest)
    require(candidate_plan.spec.system1.route == grant.approved_decisions_route)
    require(candidate_plan.spec.system1.model == grant.approved_model)
    require(candidate_plan.spec.excerpt_disclosure == grant.excerpt_disclosure_policy)
    require(len(sample_ids) <= grant.max_replay_samples)

    # 2. Per-record authorization (NEVER workflow_id alone):
    #    Every sample_id MUST exist, belong to grant.run_id and grant.authorized_sample_scope,
    #    and its target (sandbox_addr, incarnation_id) MUST be authorized for
    #    (caller_role, caller_subtree); any unauthorized or cross-run sample_id fails closed.
    # 3. Enforce max_replay_calls and max_replay_spend_microusd (integer microdollars) before each call.
    # 4. Enforce grant.excerpt_disclosure_policy ("replay" in permitted_uses if excerpt != "none")
    #    and run canary_scanner.scan(exact_serialized_payload_bytes) on every replay request.
    # 5. Return stratified before vs. after reference-verdict scorecard (including abstentions
    #    and cap-drop notes).
```

---

## 5. Failure, recovery, and adversarial verification matrix

### `docs/prds/spikes/n/test_workflow_schema_and_plan.py`
1. **Valid builtin & user TOML parsing:** Parses `firstmate-supervisor`-shaped and `statechart`-shaped
   `workflow@1` TOML; produces deterministic `spec_digest`, `candidate_rubric_digest`, and
   `workflow_plan_digest` across key reorderings.
2. **Schema & limit rejections:** Rejects unknown keys, `schema_version != 1`, `states > 32`,
   `transitions > 64`, `tick_interval_s < 10`, `rubric > 2048` bytes, non-finite floats, negative or
   sub-microdollar spend, `factory_id` in non-builtin TOML without allowlist, and invalid `oc-ui@1`
   widget types.
3. **Bounded predicate AST security:** Accepts valid bounded expressions; rejects AST depth > 8,
   node count > 64, > 512 bytes, `eval`/call syntax, attribute traversal beyond `<ns>.<field>`,
   disallowed namespaces (`os.*`, `untrusted.*`), regexes, and list size > 16.
4. **Literal single-pass template security:** Accepts `{target_addr}`, `{stall_seconds}`,
   `{workflow_id}`; rejects `{target_addr.__class__}`, `{target_addr[0]}`, `{unknown}`, format
   specs `{stall_seconds:100000s}`, stray braces, and verifies substituted values containing
   `{workflow_id}` are never re-expanded.
5. **All 10 `SECURITY_DELTA_TRIGGERS`:** Verifies each trigger fires accurately on its exact diff
   (including `workflow_excerpt_disclosure_changed` and `workflow_rubric_or_predicate_changed`) and
   that benign description-only edits emit zero security triggers.
6. **Pure compile zero-write & skill TOCTOU defense:** Confirms `compile_workflow_plan()` creates
   zero files in staging/temp directories, rejects symlink/hardlink/world-writable skill files via
   `O_NOFOLLOW`, and proves modifying the disk source *after* compile never alters the bytes written
   by `materialize_workflow_plan()` (and corrupting pinned bytes fails closed on digest check).
7. **Materialization staging-root defense:** Rejects un-admitted plans, mismatched `WorkflowRunLease`
   digests, symlinked staging dirs, group/world-writable staging dirs, and staging paths inside a
   forbidden sandbox root.
8. **`observe_only` compiled effect allowlist & nonexclusive lane ownership (P2 acceptance case):**
   - Rejects `observe_only` auto-admission even with `$0` spend when any state, transition, signal,
     timer, or factory can reach a launch, patch, nudge, lane-pausing gate, or model call.
   - Proves starting an auto-admitted `observe_only` observer first on `(sandbox_addr,
     incarnation_id)` (both `running` and `paused`) acquires only a nonexclusive
     `workflow_observer_subscriptions` entry and leaves an operator/owning workflow free to claim
     `workflow_lane_leases` on that exact incarnation; attempting to request an exclusive lane lease
     from `observe_only` fails closed.

### `docs/prds/spikes/n/test_workflow_supervision.py`
1. **Leading + single-trailing coalesced throttler:** Burst of 5 alerts in Period 1 -> Alert #1
   dispatches immediately on frozen `S1` (`triggered_leading`), Alerts #2–#5 are suppressed with
   `trailing_queued = True`, Period-1 boundary captures fresh `S_now` and dispatches **one** blind
   check (`triggered_trailing`, bypassing System-1 and entering Period 2 throttled), Period-2 burst
   requeues for Period 3, quiet Period 3 transitions back to `IDLE`.
2. **Fleet outer cap & non-starvable audit floor (Trap T3):** Synchronized alerts across 10 lanes
   saturating `fleet_max_checks_per_hour` are bounded and recorded as `cap_dropped`/`cap_delayed`,
   while scheduled unalerted active-lane audits continue executing within their reserved
   `fleet_audit_checks_per_hour` slice with zero starvation.
3. **Default `excerpt_disclosure = "none"` & final-payload `OverlapCanaryScanner`:**
   - Default config strips/refuses any workspace or error excerpt from outbound System-1 and
     blind-check payloads.
   - Opted-in disclosure enforces `(source, allowed_routes, permitted_uses)` and blocks transmission
     if a canary secret or credential prefix appears anywhere in the exact serialized final payload.
4. **Positive `classifier_injection_suspected` canary:** Never maps to `"healthy_progress"`; logs
   security event, strips excerpt, re-evaluates strictly on numeric metrics, and escalates on
   repeated canary hits.
5. **Transport-only `turn_completed` & self-report immunity (Trap T5):**
   - Worker emitting synthetic `turn_completed`, `stream_events`, or `"Got it, continuing!"` updates
     `last_transport_frame_at` only and **cannot** suppress the freshness guard, reset stall/nudge
     counters, or auto-resolve an incident.
   - Only a genuine `ProgressFingerprint` delta (e.g., new `commit_sha`/`tree_oid` or verified test
     exit transition) suppresses a stale nudge and resets incident counters.
6. **Point-in-time `TP/FP/TN/FN/class_mismatch` & stratified accounting (Trap T4 & T11):**
   - `TP/FP` is scored on frozen `S1` even when a real progress delta later triggers the freshness
     guard to suppress live action.
   - `triggered_trailing` stays in its own stratum (excluded from System-1 `TP/FP` unless
     shadow-scored); scheduled audits record `TN`/`FN` and execute live action directly from
     blind-check `FN`; ledger accurately reports actual inclusion rates, cap drops/delays, and
     abstentions per stratum.
7. **Host sleep/suspend gap (Trap T6) & correlated fleet outage (Trap T8):**
   - `wall_delta - monotonic_delta > 30s` triggers wake grace window and excludes sleep time from
     stall dwell.
   - Multiple lanes failing on the same `(provider_route, remote_worker, error_class)` coalesce into
     one fleet-scoped notice.
8. **Rubric-digest-bound calibration replay & per-record authorization:**
   - Offline-compiled candidate matching grant's exact `(candidate_spec_digest,
     candidate_rubric_digest, route, model, disclosure_policy)` produces a stratified before/after
     scorecard.
   - Editing a single character of `rubric` or `choices` after grant issuance fails closed with
     `RUBRIC_DIGEST_MISMATCH`.
   - Passing a cross-run or out-of-subtree `sample_id` fails closed; aggregate queries exclude
     unauthorized records; expired grant or exceeded call/microdollar cap fails closed.

---

## 6. Verification commands planned after Gate 1 clearance

1. `pytest -q docs/prds/spikes/n/test_workflow_schema_and_plan.py docs/prds/spikes/n/test_workflow_supervision.py`
2. `git diff --check` and verification that `git diff --name-only origin/main` touches only
   `docs/prds/spikes/n/*`
3. `tests/security.sh` (with real Podman) and hosted PR checks before Gate 2 review
