# prd_n3: Three-tier Human Inbox, declarative `oc-ui@1` dashboard surfaces, and orchestrator MCP/skills

Parent: [prd_n](prd_n.md) · siblings:
[workflow@1 schema & statechart kernel](prd_n1.md),
[host metrics, System-1 Decisions API & blind verification](prd_n2.md) ·
related:
[orchestrator & dashboard](prd_i1.md),
[unified control plane & UI](prd_m3.md)

## Problem statement

Long-running workflows and autonomous supervision need two things in the workstation dashboard
([prd_m3](prd_m3.md)) without compromising Trusted Host Chrome:

1. A **non-blocking Human Inbox** for asynchronous human decisions—such as our PRD `Human review`
   gate, product questions (`captain_hold`), persistent stuck-lane escalations, and classifier drift
   notices—where agents keep working on independent lanes without blocking and without diluting
   cryptographic security approvals.
2. A safe way for **workflows** (deterministically) and the **Root Orchestrator (`-o`)** (via skills
   and MCP tools) to register and update dashboard status/health widgets without executing untrusted
   JavaScript, HTML, or iframe code inside Trusted Host Chrome.

## Design specification

### 1. Three-tier Human Inbox (strict separation from `oc_controller` Approvals)

Extend the `Workspace Header` from [prd_m3](prd_m3.md):

```text
Workspace Header (Trusted Host Chrome)
 ├── Root Orchestrator ('-o')
 ├── Tier A: Approval Inbox   [RED / LOCK   · Blocking cryptographic oc_controller grants ONLY]
 ├── Tier B: Human Inbox      [AMBER / BLUE · Non-blocking PRD gates, holds, escalations, drift]
 ├── Workflows                [Active/available workflow@1 runs · oc-ui@1 surfaces]
 ├── Tier C: Health Ribbon    [Inline auto-clearing telemetry & auto-nudge status pills]
 ├── Browser Wall (PiP, Optional)
 └── Global Quota Bar         [5h + 7d multi-window meters + Paid-Fallback lock]
```

| Tier | Backing Store & Authority | Blocks Agents? | Typical Items |
|---|---|---|---|
| **Tier A — `Approval Inbox`** | `oc_controller.view(operator, request_id)` (cryptographic `(request_id, revision, digest)` + `security_delta`) | **Yes** (requesting action waits) | Sandbox launch plans, `PaidFallbackGrant`, `WorkflowRunLease`, `CalibrationReplayGrant`, `config_propose_revision`, `InputLease` |
| **Tier B — `Human Inbox`** | `$STATE/registry.sqlite` (`human_inbox_items`); **strictly zero** grant-minting or approval authority (action buttons like `[Request Calibration Replay]` may at most submit a Tier-A `oc_controller` proposal) | **No** (siblings always keep running; host `WorkflowEngine` may set `lane_paused = 1` on a declared `human_gate_async` to pause *only* that single lane until its `OPERATOR_ONLY` awakeable is resolved) | PRD `Human review` gates, `captain_hold` design questions, persistent post-nudge stuck-lane escalations, classifier FP/FN drift alerts |
| **Tier C — Health Ribbon** | Live projection / ephemeral badges | **No** | Transient telemetry (`5h quota 88%`, `rev-1 auto-nudged 1/2`); auto-clears on recovery, never creates Inbox noise |

#### Human Inbox lifecycle, `firstmate` verb parity, & display-bound TOCTOU protection (Trap T7)
- **Durable SQLite schema (`human_inbox_items`) & partitioned deduplication:**
  `(item_id, item_revision, content_digest, kind, severity, owner_scope, lane_paused,
  awakeable_token_hash, status, source_kind, source_id, workflow_run_id, target_addr,
  target_incarnation_id, thread_id, title, summary_md, evidence_json, actions_json, dedupe_key,
  expected_commit_sha, expected_tree_oid, expected_artifact_digest, expected_workflow_seq,
  snooze_until, resolution_decision, resolution_note, resolved_by, created_at, updated_at)`
  with a **partitioned partial unique index**
  `UNIQUE(owner_scope, source_kind, source_id, lane_paused, dedupe_key) WHERE status = 'open' AND dedupe_key IS NOT NULL`.
  Partitioning deduplication by ownership and scope (`owner_scope` binding run/project + target and
  separating host-owned `lane_paused = 1` operator gates from `-o` advisory `lane_paused = 0`
  posts) ensures an advisory post can **never** collide with, shadow, or suppress an operator gate.
  Only the host `WorkflowEngine` may set `lane_paused = 1` and attach an `OPERATOR_ONLY`
  `awakeable_token_hash`; `-o`'s `inbox_post` creates advisory (`lane_paused = 0`) items only.
- **Idempotent inbox verbs (ported cleanly from `fm-inbox.sh` + `fm-captain-hold.sh`):**
  - `note` (idempotent `request_id`, coalesced single wake), `reply` (sequence-stamped),
    `receipts` (bounded cursor view), `ready` (read-only readiness projection), `status`
    (zero-wake read), `ask` (isolated side question without derailing the active workflow),
    `captain_hold` (pauses only the specified lane while sibling lanes continue), `snooze(until)`.
- **Self-healing auto-resolve (corroborated progress only):** Items carrying an
  `auto_resolve_guard` (e.g., stuck-lane escalation) transition to `auto_resolved` **only** on
  independent host-verified task progress (never a worker-supplied `turn_completed` frame alone)—
  archived with full audit history so stale items never pile up.
- **Display-bound TOCTOU pinning & live `safe_run` verification (Trap T7):**
  Every `human_inbox_items` update increments `item_revision` and recomputes `content_digest`
  (SHA-256 over canonical title, summary, evidence, and actions). Actionable review gates (e.g.,
  PRD `Human review` at commit `abc123`) additionally store `(expected_commit_sha,
  expected_tree_oid, expected_artifact_digest, expected_workflow_seq)`. When the operator clicks
  **Approve / Resolve** in Trusted Host Chrome, the UI MUST submit **what the operator actually
  saw**: `(item_id, displayed_item_revision, action_id, expected_workflow_seq,
  displayed_content_digest, expected_commit_sha, expected_tree_oid, expected_artifact_digest)`.
  `oc_daemon` then:
  1. Executes an immediate containerized `safe_run` `git rev-parse HEAD` + `git rev-parse HEAD^{tree}`
     check (and/or verifies the immutable staged `:ro` artifact digest in `$STATE/inbox-spool/`)
     without ever running host `git` inside `~/opencode-sandbox`.
  2. Atomically verifies ALL of the following inside the **single SQLite transaction** before
     consuming the `OPERATOR_ONLY` awakeable, committing `HumanDecisionReceipt`, or enqueueing any
     forwarded `inbox_resolution` directive:
     - The displayed card pins (`displayed_item_revision`, `displayed_content_digest`,
       `expected_workflow_seq`) match the live `human_inbox_items` row;
     - The selected `action_id` belongs to the exact action list declared in that
       `displayed_item_revision`;
     - For workflow-gated items, the live `workflow_runs` / lane state is **still positioned on the
       exact awaiting `(lane_key, step_id, expected_workflow_seq)`** and **still owns the exact
       same live, unconsumed, unexpired (`consumed_at IS NULL AND now < expires_at`) `OPERATOR_ONLY`
       awakeable** bound to that inbox item (never satisfied by matching a stale inbox row after the
       lane has advanced, timed out, migrated, completed, or been revoked);
     - The live containerized `safe_run` workspace/spool hashes match `(expected_commit_sha,
       expected_tree_oid, expected_artifact_digest)`.
     If **any** check fails (`STALE_ITEM_REVISION`, `INVALID_ACTION_FOR_REVISION`,
     `STEP_SUPERSEDED`, `AWAKEABLE_EXPIRED`, or `TARGET_CHANGED`), the transaction rolls back and
     fails closed: **an unchanged card for a superseded or expired step MUST produce zero awakeable
     consumption, zero `HumanDecisionReceipt`, and zero forwarded `inbox_resolution` directive.**
  3. Binds the exact verified `(commit_sha, tree_oid, artifact_digest)` into the resumed workflow
     bindings so downstream steps operate exclusively on that pinned SHA/digest (never floating
     `HEAD`).
- **Auditable decision receipts & strict provenance preservation on forwarding:** Resolving a
  Tier-B item writes an append-only `HumanDecisionReceipt(operator_session, item_id,
  verified_item_revision, verified_content_digest, workflow_run_id, spec_digest, verified_sha,
  verified_tree_oid, action_id, ts)` into `audit_log`, records a `human_inbox_resolved` projection
  event on `oc_daemon`, atomically consumes any bound `OPERATOR_ONLY` `workflow_awakeables` token,
  and—when `-o` is subscribed—forwards the resolution via `oc_hub` (`msg_kind = "inbox_resolution"`,
  coordinated `oc_coord_contract.py` extension). On forwarding, **only the authenticated
  `action_id` and operator-authored `resolution_note` carry `OPERATOR_DIRECTIVE` provenance**; any
  referenced advisory `summary_md` or `evidence_json` from the original item MUST stay quarantined
  inside 128-bit random-nonce `<oc-untrusted-data nonce="...">` blocks so untrusted text is never
  promoted to operator provenance.

### 2. Declarative dashboard surfaces (`oc-ui@1`) — zero untrusted JS in Trusted Host Chrome

Instead of loading untrusted HTML/JS or per-card MCP App `ui://` iframes inside the operator chrome
(null-origin iframes stay strictly reserved for PTY and Browser Canvas per [prd_m3](prd_m3.md)),
`oc-ui@1` uses a constrained **A2UI-style declarative JSON projection** mapped onto a fixed
host-owned Svelte component catalog:

- **SQLite table (`dashboard_surfaces`):**
  `(workflow_run_id, surface_id, owner_kind, title, priority, spec_json, state_json, updated_at)`
  where `owner_kind IN ('workflow_default', 'orchestrator_overlay')` and `state_json <= 32 KiB`.
- **Closed Svelte component allowlist:**
  `status_card | metric_kpi | kv_table | lane_health_matrix | timeline_log | checklist_progress | sparkline_series | action_chips`
- **Strict `action_chips` split (prevents overlay clickjacking):**
  - On `owner_kind = "orchestrator_overlay"` surfaces: **strictly read-only navigation chips**
    (`open_thread`, `open_pty_observe`, `open_diff`, `open_inbox_item`)—zero state-mutating actions.
  - On immutable host-compiled `owner_kind = "workflow_default"` surfaces only: read-only navigation
    chips **plus** host-declared `workflow_signal` and `trigger_calibration_review` (which submits a
    Tier-A `oc_controller` proposal for a `CalibrationReplayGrant` and never mints grants directly)
    chips, always rendered with canonical host-derived action labels (never arbitrary `-o` text) and
    **never** `approve_controller_request` or `take_input_lease`.
- **Unforgeable provenance & strict Markdown AST:**
  - **`[Deterministic Workflow]`** surfaces compile directly from `workflow@1`, update from
    host-authoritative metrics with zero LLM tokens, and are **immutable** to `-o`.
  - **`[Orchestrator Overlay]`** surfaces (max 8 per workflow run) are authored by `-o` via
    `dashboard_surface_upsert/patch`, rendered strictly via an inert Markdown AST with raw HTML
    disabled, `javascript:` / `data:` URLs rejected, and external `https:` image/media loads
    blocked (`img-src 'none'` / host-bundled local assets only) under Trusted Chrome's
    `default-src 'none'; script-src 'self'` CSP, and visually badged so `-o` can never spoof host
    telemetry or security approvals.

### 3. Orchestrator (`-o`) MCP tool surface & workflow skills

Exposed exclusively over `-o`'s private `0o700` UDS MCP socket (`SO_PEERCRED` + 256-bit incarnation
token + strict JSON + closed param allowlists; leaf sandboxes receive zero access):

| Namespace | MCP Tools | Guardrails |
|---|---|---|
| **Config (existing `prd_l`)** | `config_list/get/schema/diff/history/propose_revision(kind="workflow", ...)` | Human-gated via Tier-A `Approval Inbox` with 10 `SECURITY_DELTA_TRIGGERS`; `builtin/*` immutable. |
| **Workflow** | `workflow_plan_preview`, `workflow_start`, `workflow_status`, `workflow_signal`, `workflow_pause`, `workflow_resume`, `workflow_stop` | `observe_only` + `$0` spend auto-admits **only** when compiled reachable effects pass the observe-only allowlist (zero launches/patches/nudges/lane-pausing/factories), attaches strictly via a **nonexclusive observer subscription** (never acquiring or retaining `workflow_lane_leases`), and stays within `SubtreeBudget` and `max_active_workflow_runs` / rate limits; all other runs and **every** live migration to a new digest require a Tier-A `WorkflowRunLease`. `-o` may `pause`/`resume`/`stop`/`signal` **only** `-o`-owned runs (or allowlisted signals in `WorkflowRunLease`), never operator-owned supervisors. |
| **Metrics & Bearings** | `metrics_query`, `metrics_anomalies`, `fleet_bearings_snapshot(format="toon")` | Strictly read-only, enforcing per-record `(caller, run_id, SubtreeBudget, target_incarnation)` authorization on every row and aggregate input. TOON table emits **only** host-authoritative numeric/enum/validated-identifier fields (preventing TOON row spoofing); any opted-in untrusted snippets are emitted separately inside 128-bit random-nonce `<oc-untrusted-data nonce="...">` blocks. |
| **Human Inbox** | `inbox_post`, `inbox_list`, `inbox_get`, `inbox_note`, `inbox_receipts` | Per-record `(caller, run_id, SubtreeBudget, target_incarnation)` authorization on every read/write/note/receipt; rate-limited; partitioned `dedupe_key` prevents collision with operator gates; `<= 16 KiB`; `-o`'s `inbox_post` creates advisory (`lane_paused = 0`) items only. |
| **Dashboard** | `dashboard_surface_upsert`, `dashboard_surface_patch`, `dashboard_surface_delete` | Per-record `(caller, run_id, SubtreeBudget, target_incarnation)` authorization; restricted to `owner_kind="orchestrator_overlay"`, closed `oc-ui@1` catalog, read-only navigation `action_chips` only, max 8 overlays/run, `<= 32 KiB`; cannot modify `workflow_default` surfaces. |
| **Calibration** | `calibration_examples_query`, `workflow_calibration_propose_replay`, `workflow_calibration_replay` | Per-record `(caller, run_id, SubtreeBudget, target_incarnation)` authorization on every record, `sample_id`, and aggregate input (never `workflow_id` alone). Candidate preparation happens locally offline first via pure `compile_workflow_plan()`; `workflow_calibration_propose_replay` submits the exact outbound `rubric`/`choices` and `candidate_rubric_digest` to Tier A; `workflow_calibration_replay` requires that prior Tier-A `CalibrationReplayGrant`, verifies exact `candidate_rubric_digest` / `candidate_spec_digest`, route, model, and disclosure pinning (any candidate edit requires fresh Tier-A authority), and runs `OverlapCanaryScanner` on the final payload; tuning edits require a separate Tier-A `config_propose_revision` approval. |

**Compiled workflow `SKILL.md` (progressive disclosure):**
Each `workflow@1` references an `orchestrator_skill` staged `:ro` under `prd_l`'s existing
`orchestrator_skills` discovery tree at `/run/oc-config/skills/wf-<slug>/SKILL.md` (`O_NOFOLLOW`,
host-owned `0o700`/`0o600` source, 0 base tokens until invoked). The skill teaches `-o`:
1. Required `bindings` and how to invoke `workflow_plan_preview` / `workflow_start`.
2. How to read `fleet_bearings_snapshot(format="toon")` and `metrics_query` instead of polling raw
   threads.
3. Which `[Orchestrator Overlay]` surface schema to maintain (e.g., milestone checklist or PR matrix)
   alongside the baked-in `[Deterministic Workflow]` health card.
4. How to post non-blocking `inbox_post` gates (e.g., PRD `Human review` pinned to exact commit SHA)
   and continue driving sibling lanes while checking `inbox_list` asynchronously.
5. How to run the human-triggered calibration/replay workflow when asked to tune classifier drift.

### 4. Workflow views and change review

Added on 2026-11-28, after the Gate 1 clearance recorded in [prd_n](prd_n.md). It needs design
and security review before implementation. The `oc-ui@1` surfaces in §2 show a run's status and
health. They do not show what a workflow is, where a run stands in it, or what a proposed change
would do. The locked dashboard design has only a specimen sheet of the eight surfaces
([prd_m3a1](prd_m3a1.md#design-supplement)).

All of these views are host-rendered Trusted Host Chrome. Host rendering establishes who drew a
view. It does not establish who wrote each string in it. A workflow can be proposed by `-o`, and
a run's log can carry sandbox output, so text an agent wrote reaches these views. Compiling or
approving a workflow does not turn its text into host text.

- **Host-derived, in the host's voice:** stage kind, effect names, security triggers, limits,
  digests, lease and approval state, and action labels. These come from closed enumerations and
  the compiled effect manifest, never from an authored field.
- **Authored or agent-originated, always inert and labelled:** workflow and stage names and
  descriptions, surface titles, rubric and template text, skill names, step-log text, and every
  field of a proposed revision. Render these as escaped plain text in the bounded untrusted
  container, with a label naming the source: built-in, operator-authored, proposed by `-o`, or
  sandbox output. They follow the anti-spoofing rules in
  [prd_m3a1](prd_m3a1.md#trusted-chrome-visual-language-anti-spoofing).
- **Kept distinct.** An authored label never stands in for an effect or approval label, and
  never takes the reserved glyphs, shapes or colours. In a diagram, the host draws each node's
  kind marker and the authored name sits beside it as labelled text.
- Add workflow names, templates and log lines to the hostile fixtures, and check they cannot
  imitate a host label in the list, the diagram, the run view or the change review.

- **Workflow list.** Available workflows and active runs, with owner (operator or `-o`), mode,
  autonomy level, status and lease state.
- **Workflow definition.** A diagram the host generates from the compiled plan
  ([prd_n1](prd_n1.md#authoring-surface-and-authored-deterministic-steps)): stages, lanes, gates
  and transitions. Each stage is marked as an LLM lane, a deterministic host action or a human
  gate. Beside it sit the reachable effects, the limits and the plan digest.
- **Workflow run.** The same diagram with the run's current position, per-lane state and the
  step log. Each lane links to its sandbox thread, each gate to its Human Inbox item or
  approval. `oc-ui@1` surfaces for the run appear here with their provenance pills.
- **Change review.** A proposed workflow revision arrives as a Tier A approval from
  `config_propose_revision`. Show what changed in the workflow's own terms: stages, transitions,
  effects, limits and templates added, removed or altered. Show the security triggers it raises
  ([prd_n1 §1](prd_n1.md#1-storage-mutability-and-oc_config_mcp-authoring-prd_l-parity)) and the
  diagram before and after, with changed elements marked by shape and label as well as colour.
  The approval binds to the exact revision and digest shown. The shared flow for other
  configuration kinds is in
  [M3 §7](prd_m3.md#7-settings-proposed-changes-and-operator-only-secret-entry).

---

## Concrete checkboxes and open decisions

The order these are delivered in is in [prd_n](prd_n.md#delivery-order). The Human Inbox and the
minimal crew pipeline come first.

- [ ] Build the [workflow list, definition and run views](#4-workflow-views-and-change-review)
      (Wave 1) and the change review (Wave 2), from the
      [design supplement](prd_m3a1.md#design-supplement).

- [ ] Add `human_inbox_items` and `dashboard_surfaces` tables + TOCTOU fingerprint verification +
      `HumanDecisionReceipt` audit trail in `oc_registry.py` / `oc_daemon.py`.
- [ ] Expose `workflow_*`, `metrics_*`, `fleet_bearings_snapshot`, `inbox_*`, `dashboard_*`, and
      `calibration_*` MCP tools on `-o`'s private UDS RPC server (`oc_coord_rpc.py` /
      `oc_config_mcp.py`).
- [ ] Build Trusted Host Chrome views in the shell the
      [control-plane decision](prd_m.md#control-plane-decision) selects: the
      [M3b Tauri](prd_m3b.md) app if the tech-stack spike passes, the
      [M3a loopback](prd_m3a.md) dashboard first if it fails. The views are:
      `Tier B Human Inbox` drawer (strictly separate from `Tier A Approval Inbox`), `Tier C Health
      Ribbon`, `Workflows` panel, and closed `oc-ui@1` Svelte component catalog with provenance pills.
- [ ] Author `builtin/prd-delivery-pipeline.toml` + `SKILL.md` demonstrating parallel implementor /
      adversarial-reviewer lanes with non-blocking PRD human-review gates.
- [ ] **(decision needed)** Should `-o` be allowed to register `[Orchestrator Overlay]` dashboard
      surfaces *outside* an active workflow run (e.g., an ad-hoc project status card), or only bound
      to a `workflow_run_id`?
  - **Option A (Recommended):** Allow both workflow-bound overlays and a small bounded set (max 4)
    of project-scoped `-o` overlays under the exact same closed `oc-ui@1` catalog and
    `[Orchestrator Overlay]` provenance badge.
    - *Pros:* Lets `-o` surface ad-hoc fleet/project trackers even when no formal `workflow@1` run
      is active.
    - *Cons:* Requires a project-level cleanup rule when all sandboxes in a project stop.
    - *Effort:* ~0.5 days extra.
  - **Option B:** Restrict `dashboard_surface_upsert` strictly to active `workflow_run_id`s.
    - *Pros:* Tighter lifecycle coupling (surfaces clean up automatically when workflow completes).
    - *Cons:* Less flexible for ad-hoc orchestrator sessions.
    - *Effort:* ~0 days extra.
