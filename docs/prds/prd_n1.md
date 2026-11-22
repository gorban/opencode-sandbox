# prd_n1: First-class `workflow@1` schema, durable statechart kernel, and `WorkflowRunLease`

Parent: [prd_n](prd_n.md) · siblings:
[host metrics, System-1 Decisions API & blind verification](prd_n2.md),
[three-tier Human Inbox, oc-ui@1 surfaces & MCP/skills](prd_n3.md) ·
related:
[composable config & plans](prd_l.md),
[credential broker](prd_i3.md),
[cross-model orchestration](prd_m2.md)

## Problem statement

Multi-sandbox workflows—such as a long-running fleet supervisor (`firstmate`-style) or a multi-lane
PRD delivery pipeline (implementor + adversarial reviewer + async human review gate)—need to be
stored on the workstation, invoked by name by either the operator or the Root Orchestrator (`-o`),
compiled into reviewable digests before execution, and resumed durably across daemon restarts
without ever executing untrusted scripts on the host.

## Design specification

### 1. Storage, mutability, and `oc_config_mcp` authoring (`prd_l` parity)

`workflow@1` mirrors `sandbox-type@1`, `bundle@1`, and `service@1` in `oc_schema.py` and
`oc_store.py`:

| Location | Trust / Mutability | Enforcement |
|---|---|---|
| `cfg/builtin/workflows/*.toml` | Host-installed, **strictly immutable** (`builtin/*`) | `is_builtin_id()`, `assert_trusted_dir()`, `read_regular_no_follow()` |
| `$CONF_DIR/workflows/<name>.toml` | User-authored or `-o`-proposed (human-gated publish) | `0o700` dir, `0o600` file, `st_nlink == 1`, `check_not_in_sandbox()`, persistent-inode `flock` + append-only monotonic revision journal |
| `$CONF_DIR/factories.toml` | Host-only Python factory registry (**outside** `-o` MCP reach) | Optional opaque `factory_id` indirection for complex built-in evaluators; mutable `workflow@1` TOML **never** embeds Python/shell or `file.py:fn` paths |

**`oc_schema.py` / `oc_store.py` additions:**
- `KIND_DIRS["workflow"] = "workflows"`; add `"workflow"` to `READABLE_ORCHESTRATOR_KINDS` and
  `MUTABLE_ORCHESTRATOR_KINDS`.
- Extend `SECURITY_DELTA_TRIGGERS` with 5 closed triggers surfaced in `Approval Inbox`:
  1. `workflow_added`
  2. `workflow_autonomy_widened` (adding nudge/orchestrator-wake actions, widening target scope, or
     raising nudge/check caps)
  3. `workflow_decisions_route_added` (binding/changing `/decisions/*` or blind-check routes or
     raising call/USD caps)
  4. `workflow_blocking_gate_changed` (adding/removing an explicit blocking workflow gate)
  5. `workflow_skill_changed`
- `-o` authors or tunes workflows strictly through existing `oc_config_mcp.py` (`config_list`,
  `config_get`, `config_schema`, `config_diff`, `config_history`, `config_propose_revision`) ->
  `oc_controller` `Approval Inbox` (never direct disk writes).

### 2. Declarative `workflow@1` TOML schema (hierarchical statechart)

Pure declarative TOML (`schema_version = 1`), zero arbitrary shell/Python, bounded states (`<= 32`),
bounded transitions (`<= 64`), minimum periodic cadence (`>= 10s`). Supports both **macro-lifecycle
statecharts** (e.g., `builtin/prd-delivery-pipeline` with Ship/Scout stages and parallel lanes) and
**orthogonal fleet supervisors** (e.g., `builtin/firstmate-supervisor`):

```toml
schema_version = 1
kind = "workflow@1"
id = "builtin/firstmate-supervisor"
mode = "fleet_supervisor"            # closed enum: statechart | fleet_supervisor
description = "Long-running fleet supervisor using host metrics, zero-authority System-1 triage, coalesced throttling, blind real-model verification, and non-blocking Human Inbox escalation."
autonomy = "nudge_bounded"           # closed enum: observe_only | nudge_bounded | orchestrator_signal
orchestrator_skill = "builtin/firstmate-supervisor-guide"
survives_restart = true

[scope]
target_selector = "all_running_sandboxes"   # all_running_sandboxes | bound_targets | project_scope
allow_remote_workers = true

[limits]
tick_interval_s = 60                        # >= 10s; jittered
throttle_period_s = 300                     # per-lane leading + single-trailing window
fleet_max_concurrent_checks = 2
fleet_max_checks_per_hour = 30
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
route = "decisions:openai-luna"             # or "decisions:gemini-decision-1" / "decisions:local-rules-v1"
model = "gpt-6-luna"
authority = "trigger_only"                  # hard invariant: System-1 NEVER executes side effects
decision_type = "choice"                    # noul | choice | score
choices = [
  "healthy_progress",
  "slow_build_or_test",
  "stalled_loop",
  "waiting_on_dependency",
  "machine_degraded",
  "escalate_human"
]
abstain_default = "healthy_progress"
canary_injection_question = true            # adds noul("classifier_injection_suspected") in same pass
evidence_max_excerpt_bytes = 512

[supervision.blind_check]
model_profile = "fast-verifier"             # host ModelCatalog profile (separate from heavy -o)
scheduled_audit_interval_s = 900            # unalerted active-lane audit cadence (FN measurement)
min_calibration_samples = 10
fp_drift_warn_threshold = 0.25
fn_drift_warn_count_24h = 2

[templates]
nudge_stalled_loop = "Supervisor health check: host telemetry indicates stalled progress or repeated tool errors. Summarize your current blocker, verify tool outputs, or report status to the orchestrator."
nudge_verify_tests = "Supervisor health check: edits appear idle without recent verified test/check activity. Run the scoped verification check or report what is blocking completion."

[dashboard.default_surface]
title = "Firstmate Fleet Supervisor"
priority = 10
[[dashboard.default_surface.widgets]]
id = "summary"
type = "status_card"
metrics = [
  "fleet.running_sandboxes",
  "workflow.nudges_last_hour",
  "workflow.open_escalations",
  "workflow.classifier_precision",
  "workflow.classifier_fn_24h"
]
[[dashboard.default_surface.widgets]]
id = "lane_matrix"
type = "lane_health_matrix"
columns = ["target_addr", "status", "stall_seconds", "consecutive_errors", "quota_5h_remaining", "last_check_outcome"]
```

**Macro-statechart stage shapes (for `mode = "statechart"`, e.g. `builtin/prd-delivery-pipeline`):**
- `deterministic`: pure host action (compile/launch sandbox via profile, run containerized
  `safe_run` verification probe, stage `:ro` patch into `/run/oc-inbox/`).
- `ship_lane` / `scout_lane`: clean-room adoption of `firstmate`'s task shapes—`ship_lane` pairs an
  implementor sandbox with a scoped cross-model reviewer (`RoutingEdge` + `safe_run` verification
  gate), while `scout_lane` runs a read-only research sandbox producing a bounded `:ro` artifact.
- `parallel_lanes`: orthogonal sub-regions with explicit join policy (`all`, `quorum`,
  `independent_stream`).
- `wait_signal`: durable wait on a cryptographically random `workflow_awakeables` token.
- `human_gate_async`: posts a **non-blocking** Tier-B Human Inbox item bound to
  `(expected_commit_sha, workflow_seq)`; only the gated lane pauses while sibling lanes continue.
- `human_gate_blocking`: routes privilege/spend escalation strictly to `oc_controller` Tier-A
  Approval Inbox.

### 3. Plan compilation, immutable snapshots & safe-point live versioning (`oc_plan.py`)

`compile_workflow_plan(store, workflow_id, bindings, model_catalog)` performs pure, side-effect-free
compilation:
1. Validates closed statechart reachability, bounded predicate AST (comparisons and boolean ops over
   host-verified `metric.*`, `event.*`, `lane.*`, `state.*`, `limits.*` only—no loops, calls, or
   unbounded regex), closed action enum, static template placeholders (`{target_addr}`,
   `{stall_seconds}`, `{workflow_id}`), and closed `oc-ui@1` widget schema.
2. Verifies referenced `/decisions/*` and `blind_check` model profiles against host `ModelCatalog`
   and checks tariff upper bounds fit within `max_decisions_spend_usd` / `max_blind_check_spend_usd`.
3. Stages the workflow's `orchestrator_skill` read-only under `/run/oc-config/skills/wf-<slug>/SKILL.md`
   for progressive disclosure to `-o`.
4. Emits immutable `workflow_plan.lock.json` and **`workflow_plan_digest = sha256_canonical_json(plan)`**.
5. **Pinned snapshots & live migration (Trap T10):** Starting a workflow persists its compiled plan
   in `workflow_spec_snapshots(spec_digest, plan_json)`. Editing a `workflow@1` TOML on disk affects
   only *new* instances; in-flight 12h+ runs stay pinned to their starting snapshot. Explicit
   `workflow migrate <run_id> --to <spec_digest>` is permitted only at quiescent safe-points (zero
   in-flight outbox dispatches) after schema compatibility verification and (if autonomy/routes
   widened) a fresh `WorkflowRunLease` approval.

### 4. Durable event-sourced SQLite kernel & single-owner lane leases (`oc_registry.py`)

Shares `$STATE/registry.sqlite` (same `0o600` WAL, `O_NOFOLLOW`, hash-chained `audit_log`, and
single-writer ACID transactions as `oc_hub` outbox & revocation tombstones):

- **`workflow_spec_snapshots`**: `(spec_digest PRIMARY KEY, workflow_id, workflow_rev, plan_json, created_at)`
- **`workflow_runs`**: `(run_id PRIMARY KEY, workflow_id, spec_digest, instance_name UNIQUE, mode, status, autonomy, state_json, bindings_json, lease_request_id, grant_generation, last_event_seq, last_tick_at, started_by, created_at, updated_at)`
- **`workflow_step_log`**: append-only transition/action/decision journal for crash idempotency and audit.
- **`workflow_timers`**: durable `(timer_id, run_id, lane_key, fire_at_monotonic_offset, fire_at_wall, kind, payload_json, status)` supporting clean sleep/wake adjustment.
- **`workflow_awakeables`**: single-use 128-bit cryptographic correlation tokens bound to
  `(token_hash, run_id, expected_seq, expected_artifact_digest, expires_at)` to resume waiting
  states on Human Inbox resolution, `agent_wait` completion, or external signals without polling.
- **`workflow_lane_leases`** *(Trap T9)*: enforces **at most one `owner_workflow_id` per
  `sandbox_addr`**. A `fleet_supervisor` workflow respects active lane ownership: for lanes owned by
  a macro-workflow, the supervisor sends advisory signals to the owning workflow rather than
  competing to nudge the sandbox directly.

### 5. `WorkflowRunLease`, `CoordRole.WORKFLOW`, and `<1s` revocation cascade (`oc_controller.py`)

- **`WorkflowRunLease`** (parallel to `PaidFallbackGrant` and `InputLease` in [prd_m](prd_m.md)):
  bound to `(run_id, workflow_id, workflow_plan_digest, grant_generation, autonomy, target_scope,
  nudge_caps, decisions_caps, blind_check_caps, expires_at)`.
  - Operator-launched runs mint the lease directly.
  - `-o`-launched runs auto-admit **only** if `autonomy == "observe_only"`, spend caps are `0`, and
    `target_scope` is within `-o`'s `SubtreeBudget`; otherwise they route to **Approval Inbox
    (Tier A)**.
- **`CoordRole.WORKFLOW` -> `TrustClass.SYSTEM_ALERT`:** Every workflow-originated nudge flows
  through `oc_hub.send()` via a fenced `RoutingEdge` (`src_actor = "workflow:<run_id>"`,
  `allowed_msg_kinds = ["nudge"]`, durable `turns_used`/`max_rounds`), stamped with an unforgeable
  host write-ahead provenance badge `[Workflow: <workflow_id>]`.
- **Human `InputLease` auto-suspend (Trap T9):** Whenever `oc_controller` holds an active
  `InputLease` on a sandbox (`opencode-tui`, `shell`, or `browser`), supervision for that lane
  freezes stall timers and defers nudges until lease release + grace window.
- **Unified `<1s` revocation cascade:** Revoking a `WorkflowRunLease` fences the runner, aborts
  in-flight `/decisions/*` and blind-check upstream sockets on `BrokerLease`, revokes
  `workflow:<run_id>` `RoutingEdge`s, cancels pending outbox rows, and marks the run `revoked`.

---

## Concrete checkboxes and open decisions

- [ ] Extend `oc_schema.py`, `oc_store.py`, and `oc_config_mcp.py` for `workflow@1` storage,
      `SECURITY_DELTA_TRIGGERS`, and human-gated authoring.
- [ ] Implement `compile_workflow_plan()` in `oc_plan.py` with bounded predicate AST validation,
      immutable `workflow_plan_digest`, `:ro` skill staging, and `workflow_spec_snapshots`.
- [ ] Add `WorkflowRunLease` and `CoordRole.WORKFLOW` (`TrustClass.SYSTEM_ALERT`) to
      `oc_controller.py` / `oc_coord_contract.py` with `<1s` revocation cascade and `InputLease`
      auto-suspend.
- [ ] Implement the event-sourced `WorkflowEngine` in `oc_daemon` (`workflow_runs`,
      `workflow_step_log`, `workflow_timers`, `workflow_awakeables`, `workflow_lane_leases`) with
      quiescent safe-point migration.
- [ ] **(decision needed)** Restart behavior for active `nudge_bounded` / metered workflows after
      `oc_daemon` restart (Trap T13):
  - **Option A (Recommended):** `observe_only` runs auto-resume; active/metered runs boot into
    `paused (lease_reconfirm_required)` and present a **single batched "Resume N paused workflows"
    card** in `Approval Inbox (Tier A)`.
    - *Pros:* Preserves `prd_m2`'s strict invariant that controller restarts invalidate prior grant
      generations; one click resumes the whole fleet cleanly.
    - *Cons:* Overnight host reboot requires one morning click before auto-nudges resume.
    - *Effort:* ~0.5 days.
  - **Option B:** Allow an explicit opt-in `durable_auto_resume = true` flag on `WorkflowRunLease`
    (operator-signed, bounded by `expires_at` and hard spend/nudge ceilings) for unattended
    overnight runs.
    - *Pros:* Survives unattended daemon restarts overnight without manual resume.
    - *Cons:* Weakens restart-invalidates-grants unless bounded by short TTL and immutable plan
      digest verification on boot.
    - *Effort:* ~1 day (requires signed durable lease verification & extra Gate 1 review).
