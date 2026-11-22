# prd_n2: Host metrics, zero-authority System-1 Decisions API, coalesced throttler, and blind verification

Parent: [prd_n](prd_n.md) · siblings:
[workflow@1 schema & statechart kernel](prd_n1.md),
[three-tier Human Inbox, oc-ui@1 surfaces & MCP/skills](prd_n3.md) ·
related:
[orchestrator health](prd_i1.md),
[host credential brokering](prd_l1.md),
[model telemetry & quotas](prd_m1.md),
[cross-model orchestration](prd_m2.md)

## Problem statement

Supervising a fleet of parallel coding sandboxes with a frontier LLM polling loop burns excessive
tokens and invites prompt-injection attacks if untrusted sandbox logs directly steer supervisory
actions. Conversely, pure static timeouts misclassify long builds (`cargo test`, `pytest`) as
stalls while missing subtle failure loops. We need **unspoofable host-observed metrics**, a
**zero-authority System-1 Decisions API pre-filter** (`gpt-6-luna` / `gemini-decision-1`), a
**leading+trailing coalesced throttler**, **blind real-model verification** on both triggered and
scheduled unalerted snapshots (`TP / FP / TN / FN`), and a **human-triggered calibration loop**.

## Design specification

### 1. Host-authoritative metrics plane (`trusted_metrics` vs. `untrusted_claims`)

Maintain a hard namespace boundary inside `oc_daemon` and `$STATE/registry.sqlite`:

1. **`trusted_metrics` (host-observed, feeds deterministic guards, classifiers, and `-o` MCP):**
   - **Broker & LLM Gateway (`oc_broker_http` + `QuotaLedger`):** exact HTTP statuses (`200`, `429`,
     `5xx`), TTFT, SSE byte/token rate, stream stall duration, rolling `5h` / `7d` account quota %,
     `PaidFallbackGrant` burn, `/mcp/*` per-tool latency/error counts, and normalized
     `(tool_name, args_sha256)` repetition counts (detects repeating the same failing tool call
     deterministically).
   - **Coordination Hub (`oc_hub`):** turn latency (`handed_off` -> `turn_completed`), live
     `stall_seconds` (`now - last_stream_event_at` while working), outbox queue depth, active
     `agent_wait` edges, inter-sandbox ping-pong round count.
   - **Runtime / Cgroup / Worker Probes (`HostProvider.probe()`):** container CPU time delta, RSS,
     block I/O, worker RTT, available host RAM/disk (distinguishes active local compilation from a
     wedged idle container).
   - **Host-Verified Workspace Velocity (via throwaway containerized `safe_run`):** git diff-stat
     delta, commit SHA advances, verified test exit transitions (never running host `git` or
     walking worktrees inside `~/opencode-sandbox`).
   - **Supervision & Calibration Metrics:** System-1 call count/latency/spend, throttled/coalesced
     trigger count, blind-check call count/spend, `TP`, `FP`, `TN`, `FN`, `class_mismatch`,
     precision, sampling-adjusted miss rate, and nudge outcomes.
2. **`untrusted_claims` (agent self-reported progress/notes):** rendered only with untrusted
   provenance badges; **never** allowed in deterministic guards or stall-timer resets.

**Storage (`metrics_rollups`, Trap T14):** High-frequency events aggregate in memory inside
`oc_daemon` and flush every `5–10s` into ring-bounded SQLite buckets (`1m` resolution for 24h,
`5m` / `1h` rollups for 30d) to avoid SQLite WAL write amplification.

### 2. `/decisions/*` broker route (`oc_broker_http.py`, `"decisions-typed"` policy)

Mount `/decisions/<provider>/v1/evaluate` onto `HostHttpBrokerServer`, reusing `HostVaultMemory`,
`BrokerLease`, DNS-pinned IP validation, `follow_redirects=False`, `OverlapCanaryScanner`, error
scrubbing, and `QuotaLedger` durable pre-flight spend reservations ([prd_m1](prd_m1.md)):

- **Internal-only default:** Accessible only to `oc_daemon`'s host `WorkflowEngine` (zero
  `/decisions/*` routes exposed to untrusted leaf sandboxes).
- **Provider adapters:**
  - `decisions:openai-luna` — OpenAI Decisions API (`gpt-6-luna`)
  - `decisions:gemini-decision-1` — Google Gemini Decisions API (`gemini-decision-1`)
  - `decisions:local-rules-v1` — deterministic offline fixture for CI and air-gapped hosts
- **Closed request construction (`"decisions-typed"`):**
  - `model` must exist in host `ModelCatalog` with `capability == "decisions"`.
  - `rubric` comes strictly from immutable compiled `workflow_plan.lock.json` (never from untrusted
    sandbox text).
  - `evidence` is a flat JSON object (`<= 8 KiB`) containing host-verified numeric metrics plus an
    optional `sanitized_last_error_excerpt` (truncated `<= 512` bytes, control/bidi/ANSI stripped,
    explicitly tagged as untrusted data).
  - Enforces zero-output-token single-pass evaluation (`noul` / `choice` / `score`), `store: false`,
    and zero provider-side tools.
  - Batches a **`noul("classifier_injection_suspected")`** self-defense canary into every call.
- **Fail-closed output:** Any malformed payload, unknown enum label, timeout, HTTP error, or
  positive injection canary logs a security/degraded metric and fails closed to `abstain_default`
  (triggering fallback to Tier-0 deterministic backstops).

### 3. Zero-authority System-1 + leading/single-trailing coalesced throttler

**Hard security axiom:** System-1 models have **no direct execution authority**. They can only
record a prediction and submit a trigger to the per-lane throttler.

#### Per-lane coalesced throttler state machine (window `T = throttle_period_s`, e.g., `300s`)

```text
State: IDLE
  On System-1 alert #1 at t0 (frozen MetricSnapshot S1):
    -> Record System-1 prediction (snapshot_id=S1)
    -> Immediately dispatch Blind Real-Model Check(S1, origin="triggered_leading")
    -> Transition to THROTTLED(window_end = t0 + T, trailing_queued = false, suppressed_count = 0)

State: THROTTLED(window_end, trailing_queued, suppressed_count)
  On System-1 alerts #2..#N arriving before window_end:
    -> Do NOT dispatch immediately; do NOT queue additional System-1 runs for the boundary
    -> Set trailing_queued = true, suppressed_count += 1
    -> Record (S_suppressed_first, S_suppressed_last) in workflow_step_log for analytics

  At t == window_end:
    If trailing_queued == true:
      -> Capture fresh point-in-time snapshot S_now
      -> Dispatch ONE Blind Real-Model Check(S_now, origin="triggered_trailing")
         (bypasses System-1 classifier; represents coalesced alerts #2..#N)
      -> Transition to THROTTLED(window_end = t + T, trailing_queued = false, suppressed_count = 0)
         (alerts during Period 2 stay blocked but may set trailing_queued = true for Period 3)
    Else:
      -> Transition to IDLE
```

- **Fleet-wide outer cap (Trap T3):** Pair per-lane throttlers with a fleet-wide concurrency and
  hourly rate cap (`fleet_max_concurrent_checks`, `fleet_max_checks_per_hour`, round-robin across
  lanes) so synchronized spam across N compromised sandboxes cannot burst N simultaneous System-2
  checks.

### 4. Blind real-model verification, freshness guard & `TP / FP / TN / FN` confusion matrix

To eliminate confirmation bias / LLM sycophancy *and* defeat System-1 suppression prompt-injection
attacks:

- **Stateless, tool-restricted, blind context (Trap T2):** The real-model health check runs in a
  dedicated single-turn host-brokered context (never full `-o` with spawn/config tools). It
  receives **only** a generic *"Routine Lane Health Check"* prompt + the frozen `MetricSnapshot`—**no
  indication** whether System-1 alerted or a routine schedule fired.
- **Closed 4-tool surface:**
  1. `health_record_ok()`
  2. `health_nudge_lane(template_id)` *(closed enum of host-static templates only)*
  3. `health_escalate_human(category)` *(creates/updates deduplicated Tier-B Inbox item using static
     host summary + host metrics)*
  4. `health_wake_orchestrator(reason_code)` *(delivers compact Host-Verified Incident Dossier to `-o`)*
- **Dual execution paths:**
  1. **Triggered checks** (leading `S1` or trailing `S_now` from throttler).
  2. **Scheduled unalerted active-lane audits** (periodic timer on active lanes where System-1 did
     not alert; System-1 scores `S_audit` right before the blind check so every audit yields an
     exact paired `(system1_verdict, real_model_action)` record).

| Run Origin | System-1 Verdict | Blind Real-Model Tool Call | Confusion Outcome | Live Side Effect |
|---|---|---|---|---|
| Triggered (`S1`) | Alert (`class X`) | Matching tool (`class X`) | `TP` | Execute *(if freshness guard passes)* |
| Triggered (`S1`) | Alert (`class X`) | Different action tool (`class Y`) | `class_mismatch` (Action-Verified) | Execute `Y` *(if freshness guard passes)* |
| Triggered (`S1`) | Alert (`class X`) | `health_record_ok` | `FP` (False Alert) | None |
| Scheduled Audit (`S_audit`) | No Alert | `health_record_ok` | `TN` | None |
| Scheduled Audit (`S_audit`) | No Alert | Any action tool (`class Y`) | `FN` (Missed Alert) | **Execute `Y` directly from real-model alert** *(if freshness guard passes)* |

- **Point-in-time scoring vs. freshness-gated execution (Trap T4):**
  - `TP / FP` is always scored against the **exact frozen snapshot `S1`** System-1 evaluated so a
    fast self-recovery does not falsely mark System-1 as an FP.
  - Before dispatching any nudge or Human Inbox escalation, `oc_daemon` runs a deterministic
    **freshness check** (did `turn_completed`, a new commit SHA, or an active human `InputLease`
    occur since `S1`?). If self-recovered, log `action_suppressed_self_recovered` and skip the stale
    nudge while keeping the `TP` credit.
- **Host-verified progress-hash reset (Trap T5):** Stall timers and per-incident nudge counts reset
  **only** on host-verified progress (new commit SHA, diff hash delta, verified test transition, or
  workflow state advance)—never on agent chat text (`"Got it, continuing!"`).
- **Sleep/suspend detection (Trap T6):** `oc_daemon` compares wall-clock vs. monotonic elapsed time
  (`wall_delta - monotonic_delta > 30s`). On host wake, supervision pauses for
  `wake_grace_after_host_sleep_s` (`120s`), re-probes worker/SSH liveness first, and excludes host
  sleep from stall/dwell metrics.
- **Correlated fleet-outage coalescing (Trap T8):** Tier 0 detects correlated failures across lanes
  sharing `(provider_route, remote_worker, error_class)` and emits **one** fleet-scoped Tier-B
  Human Inbox card instead of N per-lane escalations.

### 5. Human-triggered calibration and replay loop (Trap T12)

Paired verification records persist in `$STATE/registry.sqlite` (`supervision_calibration_log`,
bounded ring buffer, e.g., 30 days):

1. **Dashboard telemetry:** The workflow's `[Deterministic Workflow]` card shows live raw counts
   (`TP`, `FP`, `TN`, `FN`, `class_mismatch`), precision (`TP / (TP + FP)`), **sampling-adjusted
   miss rate** (accounting for triggered 100% sampling vs. audit fraction `p`), throttle coalesce
   rate, and System-1 vs. blind-check spend.
2. **Non-blocking drift alert:** Once `N >= min_calibration_samples` (default `10`), if
   `FP_rate > fp_drift_warn_threshold` (`0.25`) or `FN_24h >= fn_drift_warn_count_24h` (`2`),
   `oc_daemon` posts a deduplicated **Tier-B Human Inbox** item: *"Classifier drift on
   `builtin/firstmate-supervisor` — [Ask Orchestrator to Propose Tuning]"*.
3. **Human-triggered tuning (default):** Workflows never self-modify. When the operator triggers
   `-o` (via the Inbox button or chat):
   - `-o` inspects disagreements via read-only `calibration_examples_query(workflow_id, outcomes, limit)`
     (excerpts strictly bounded and fenced).
   - `-o` evaluates candidate rubric/threshold edits via bounded host-side
     `workflow_calibration_replay(workflow_id, candidate_toml, sample_ids)` generating a **before vs.
     after confusion-matrix scorecard**.
   - `-o` submits `config_propose_revision(kind="workflow" | "sandbox-type", ...)` -> **`Approval
     Inbox (Tier A)`**, displaying both `security_delta` and the replay scorecard for explicit human
     approval.

### 6. Clean-room `firstmate` pattern extraction matrix

| `kunchenguid/firstmate` Primitive | Disposition | Native `oc-sandbox` Realization |
|---|---|---|
| `fm-classify-lib.sh` (incremental cursor folds, `absorb_class`, presentation-marker dedup) | **Port pattern (clean-room)** | Tier-0 SQLite `seq` cursor classifier fed strictly by host-observed broker/hub/cgroup/`safe_run` signals |
| `fm-inbox.sh` (`note --request-id`, `reply`, `receipts`, `ready`, `status`, `ask`) + `fm-captain-hold.sh` | **Port pattern (clean-room)** | Tier-B `human_inbox_items` SQLite store + MCP tools ([prd_n3](prd_n3.md)) |
| `fm-supervise-daemon.sh` + `fm-secondmate-nudge-lib.sh` (presence-gated cooldown escalation ladder) | **Port pattern (clean-room)** | Zero-authority System-1 + coalesced throttler + blind real-model verifier + `InputLease` deferral |
| `fm-bearings-snapshot.sh` (compact TOON fleet snapshot) & `fm-lane-vitals-lib.sh` | **Port pattern (clean-room)** | `fleet_bearings_snapshot(format="toon")` MCP tool for `-o` + `lane_health_matrix` widget |
| Ship vs. Scout task shapes & `AGENTS.md` triage playbooks | **Port pattern (curated skills)** | `ship_lane` / `scout_lane` workflow stages + `:ro` compiled `orchestrator_skill` |
| `bin/backends/*.sh`, `treehouse`, `crew_worktree_written_since`, worker-written `status.log`, `secondmate` remote homes, `no-mistakes` host git proxy | **Explicitly rejected** | Violate `AGENTS.md` host-git/worktree ban, `prd_i1` shell-less `-o`, `prd_l1` zero-secrets-in-sandbox, and `prd_i2a` remote worker isolation |

---

## Concrete checkboxes and open decisions

- [ ] Implement in-memory host metrics aggregator + `metrics_rollups` SQLite ring buffer (`oc_broker_http`
      `/llm/*` & `/mcp/*` tap, `oc_hub`, `QuotaLedger`, cgroup/SSH probes, `safe_run` diff velocity).
- [ ] Add `"decisions-typed"` body policy and `/decisions/<provider>/v1/evaluate` (`gpt-6-luna`,
      `gemini-decision-1`, offline `local-rules-v1`) to `oc_broker_http.py` with `QuotaLedger`
      pre-flight reservations and injection canary support.
- [ ] Implement per-lane leading+single-trailing coalesced throttler + fleet-wide outer cap +
      sleep/wake gap detector + correlated-fault coalescer.
- [ ] Implement stateless, 4-tool blind real-model verifier, freshness guard, scheduled active-lane
      audits, `supervision_calibration_log`, and `workflow_calibration_replay`.
- [ ] Author `builtin/firstmate-supervisor.toml` and its `:ro` `orchestrator_skill`.
- [ ] **(decision needed)** Dedicated model tier for the blind real-model health check (Trap T2):
  - **Option A (Recommended):** Allow `workflow@1` (`[supervision.blind_check].model_profile`) to
    pin a dedicated lightweight reasoning model/profile in `ModelCatalog` (e.g., fast Sonnet /
    Codex-mini tier), separate from the heavy `-o` orchestrator model, while reserving full `-o`
    wakes strictly for escalations.
    - *Pros:* Keeps frequent scheduled unalerted audits (e.g., every 10–15 min per active lane)
      inexpensive and fast while maintaining strong tool-calling and prompt-injection resistance.
    - *Cons:* One extra `ModelCatalog` profile to configure/validate.
    - *Effort:* ~0.5 days.
  - **Option B:** Always run blind checks on the same frontier model configured for `-o`.
    - *Pros:* Zero extra profile configuration; highest possible judgment accuracy.
    - *Cons:* Higher token/quota burn on scheduled unalerted audits, forcing sparser audit intervals
      and slower `FN` detection.
    - *Effort:* ~0 days extra.
- [ ] **(decision needed)** Scheduled unalerted audit sampling strategy (Trap T11):
  - **Option A (Recommended):** Periodic active-lane audit (`scheduled_audit_interval_s = 900`,
    uniform across active lanes for unbiased `FN` estimation) plus optional tagged `near_threshold`
    audits (kept in a separate stratum so they do not bias the headline miss-rate metric).
    - *Pros:* Statistically unbiased miss-rate estimate AND faster discovery of borderline FNs.
    - *Cons:* Slightly more SQLite schema fields (`audit_stratum`).
    - *Effort:* ~0.5 days.
  - **Option B:** Fixed periodic active-lane audit only (no near-threshold stratum).
    - *Pros:* Simplest possible math and implementation.
    - *Cons:* Takes longer to collect borderline `FN` calibration examples.
    - *Effort:* ~0.25 days.
