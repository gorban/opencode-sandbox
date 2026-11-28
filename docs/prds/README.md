# PRD index

How this tree works (progressive discovery, checkboxes, the human review gate): see
[`AGENTS.md`](../../AGENTS.md#prds-progressive-discovery-in-docsprds).

`[*]` means reserved by a named workstream. Leave reserved scope to its owner.
Use `[ ]` for open work and `[x]` for completed work. Transfer or release a
reservation explicitly in this index.

## Workstream reservations

- [*] Real subscription connections and sign-in lifecycle
  ([I4](prd_i4.md), [I3](prd_i3.md)) — **Outside-in integrations**.
  - [*] OpenAI sign-in and the ChatGPT orchestrator and sandbox path ([I4](prd_i4.md#gateway)) —
    **AGY**.
  - [ ] Claude subscription route and native sign-in qualification ([I4b](prd_i4b.md)) — **Codex**.
  - [ ] Antigravity subscription route and native sign-in qualification ([I4c](prd_i4c.md)) — **Codex**.
  - [ ] Shared provider settings, model selection and staged live acceptance
    ([I4d](prd_i4d.md), [I4f](prd_i4f.md)) — **Codex**, coordinated with **AGY** on shared
    launcher and relay changes.
  - [*] Amazon Bedrock planning and qualification ([I4e](prd_i4e.md)) — **AGY**. Plan when
    ChatGPT review leaves capacity. Live Bedrock follows ChatGPT text in both placements.
- [*] SSH remote host onboarding and first remote sandbox run
  ([I2](prd_i2.md#workers-and-connectivity)) — **Outside-in integrations**.
- [*] Maintainer setup and end-to-end acceptance for these integrations
  ([I](prd_i.md#recommended-first-slice), [I2](prd_i2.md), [I4](prd_i4.md)) — **Outside-in integrations**.
- [*] Managed worker credential isolation, sign-in enforcement, and shared-home migration
  ([I3a](prd_i3a.md)) — **Worker credential isolation**. Provider onboarding and live acceptance
  stay with **Outside-in integrations**.
- [*] [I4a local OpenAI acceptance](prd_i4a.md) — **Codex**, within the Outside-in and
  worker isolation reservations. Qualify the workstation orchestrator first, then the managed
  worker through `oc-sandbox`. The Chromium and Postgres app proof follows provider acceptance.

- [*] PRD M first PoC — local worker addressing, orchestration, and thread projection
  ([M first PoC split](prd_m.md#first-poc-split)) — **PRD M coordination**.
- [*] Local compiled-profile proof ([L](prd_l.md#local-compiled-profile-proof)) — **Codex**.
- [*] Read-only thread projection ([M3](prd_m3.md#concrete-gaps-and-checkboxes)) —
  **PRD M coordination**.
- [*] PRD N planning & initial workflow/supervision slices (**N0–N2** only; **N3** three-tier
  Human Inbox UI & declarative `oc-ui@1` surfaces remain open `[ ]`) — `workflow@1` schema/kernel,
  host-authoritative metrics, and zero-authority System-1 + blind verification supervision
  ([N milestones](prd_n.md#phased-milestones-and-ownership)) — **PRD N workflows & supervision**
  *(builds on `[*] PRD M coordination` and open PRD I/L/M prerequisites; re-coordinate ownership
  at the start of the next phase)*.
- [*] Dashboard product design and requirements for the shared SvelteKit static SPA (for both
  shells; the order is set by the [control-plane decision](prd_m.md#control-plane-decision)):
  [M3a](prd_m3a.md), [M3a1](prd_m3a1.md) design system and
  accessibility, [M3a2](prd_m3a2.md) UI SDK bridge and markup, and the visual design of the
  [N3](prd_n3.md) Trusted Chrome views — **Dashboard design** (`codex/m3a-dashboard-design`).
  Excludes moving Chromium launches into the app ([Gap M3.4](prd_m3.md#concrete-gaps-and-checkboxes)),
  the M3.1 projection and N3 backend work.

- [*] Delivery order for the dashboard and workflows: the wave plan in
  [prd_m](prd_m.md#delivery-order) and [prd_n](prd_n.md#delivery-order), the new
  [M3a3](prd_m3a3.md) frontend foundation, and the sections and notes it added to M3, M3a,
  M3a1, M3a2, M3b, N1, N3, J and K and to the
  [dashboard design README](spikes/m/dashboard-design/README.md) — **Delivery planning**
  (`spike-prd-n3-workflow-poc`, then `plan-wave0-code-home`).
  This reserves the plan text only. A `[ ]` in a wave list tracks delivery order. It does not
  open or release a reservation. Scope already reserved above keeps its owner when a wave list
  repeats it as an unchecked task, including N0–N2, the M first PoC and M3 projection, the
  dashboard design, and the Outside-in integrations. Epics that no entry above reserves stay
  open `[ ]` until a workstream reserves them here. The additions to PRDs reserved above were
  made at the operator's direction and wait for those owners' reciprocal review.
  Acknowledgments still open: **Dashboard design**, **PRD M coordination**, **PRD N workflows &
  supervision**.
- [ ] Frontend foundation: Wave 0 steps 1 to 5
  ([prd_m](prd_m.md#wave-0-prove-and-decide), [M3a3](prd_m3a3.md)) — open. The workstream that
  takes it marks this line `[*]` and adds its name and branch. It alone edits the shared files
  of `apps/dashboard/` listed under the [code home](prd_m3a3.md#code-home), and it owns the
  typed client in `apps/dashboard/src/lib/client/`.
- [ ] Shared UI contract and fixture set
  ([Gap M3.6](prd_m3.md#concrete-gaps-and-checkboxes)) — open. The workstream that takes it
  marks this line `[*]` and adds its name and branch. It owns
  `apps/dashboard/src/lib/contract/` and `apps/dashboard/src/lib/fixtures/`. It drafts in its
  own branch from the start and merges into `apps/dashboard/` only after the base is seeded
  (step 2). The client is built on its work in step 5.

Coordinate SSH fixtures and remote acceptance with **Warm worker seeding**
(`codex/warm-worker-seeding`). That workstream owns [I5](prd_i5.md) warm-start
seeding and cache qualification. The initial SSH onboarding and first run are
reserved above.

## Implementation review gates

These gates apply to work from any PRD, including a PRD that has already passed design review.

1. **Before implementation**, write a short pseudocode walkthrough of the proposed behavior.
   Cover the normal flow, failure and recovery paths, trust boundaries, and how tests will verify
   them. Include the proposed resolution of every open choice being made during implementation
   whose selected option did not receive explicit security review in the PRD. Get both a security
   review and a general PR-style review of the walkthrough and those choices. Address actionable
   findings and get the revised design re-reviewed before coding.
2. **After implementation and before merge**, get both reviews on the actual PR diff and test
   evidence for the exact commit under review. Check that the implementation and the choices it
   made match the reviewed design. Explain deviations and return material design changes to the
   first gate. Verify findings, fix them, add regression coverage where required, and get the
   updated commit re-reviewed until actionable findings are resolved.

Record the reviewed design revision, implementation commit and outcomes in the PRD or PR.
These gates are in addition to the [Human review gate](../../AGENTS.md#human-review-gate).

| PRD | Grouping | Status |
|---|---|---|
| [prd_a](prd_a.md) | Postgres reachable from the host (`-P 5432`, `-P 5433:5432`) | implemented; reopened for a host Python isolation fix (external and human review pending) |
| [prd_b](prd_b.md) | OpenCode upgrades ready before launch; no drop to the host shell | pre-launch slice human-approved; in-app restart and final review open |
| [prd_c](prd_c.md) | Worktree defaults: current repo, `wt/<repo>/NAME`, relaunch | implemented; external static review complete; human review passed |
| [prd_d](prd_d.md) | Per-instance address and DNS name (no port mapping needed) | forwarding feasibility measured; implementation open |
| [prd_e](prd_e.md) | Local HTTPS / TLS per instance (same URL in pod and on host) | CA feasibility measured, including host-browser subset; implementation open; depends on prd_d |
| [prd_f](prd_f.md) | Host tool dependencies, pinned and organised (mise) | dependency feasibility measured; implementation open |
| [prd_g](prd_g.md) | Carry-over from the parallel-instances plan | backlog |
| [prd_h](prd_h.md) | Warm start: shared setup (images, OpenCode install) done once under a lock | implemented; real acceptance passed; external static review complete; human review passed |
| [prd_i](prd_i.md) | OpenCode orchestrator and sandbox fleet | proposed; host-only Claude routing spike open |
| [prd_j](prd_j.md) | Host configuration and bridge merge tool preferences | proposed; TOML and editor design deferred |
| [prd_k](prd_k.md) | Contributor checks and repository layout | local CI and documentation PoCs human-approved; hosted qualification and final review open |
| [prd_l](prd_l.md) | Composable sandbox config, host providers, comm adapters, and orchestrator config MCP | offline spike PoC slice human-approved; external secret isolation ([prd_l1](prd_l1.md)), production port, and final review open |
| [prd_m](prd_m.md) | Model telemetry, cross-model orchestration, and a shared SvelteKit control plane | local hub and worker proof merged; [delivery order](prd_m.md#delivery-order) proposed; [Tauri desktop](prd_m3b.md) only if its Tauri qualification passes, otherwise [loopback UI first](prd_m3a.md), and either only after the shared frontend qualification; final review open |
| [prd_n](prd_n.md) | First-class long-running workflows (`workflow@1`), host metrics, zero-authority System-1 + blind-check supervision, non-blocking Human Inbox, and declarative `oc-ui@1` dashboard surfaces | proposed; Rank #1 direction selected; initial Gate 1 external security & PR-style review cleared (`e155caf2`); [delivery order](prd_n.md#delivery-order) proposed with a minimal crew pipeline first; reciprocal review, open decisions & human review pending |
| [prd_o](prd_o.md) | CI build & test duration trends, test-scope expansion (spikes, integration, secret-gated live inference smoke), and deterministic content-hashed GitHub Actions caching | proposed; empirical CI baseline measured (`9b608f43`); open decisions & human review pending |

The imported findings are evidence, not production implementation:

- [D1](prd_d1.md): `spike-d1` at `41f58da`; user-observed main 31, matrix 12, restart 8, atomic 12
  and dynamic 2 checks passed. The production teardown fix is separate work.
- [F](prd_f.md): `spike-f` at `d1027f6`; 123 checks, or 128 with the newer-mise option, passed on
  both host and devbox.
- [E1](prd_e1.md): `spike-e1` at `7c16f4d`; 2,268 matrix results and a separately observed six-case
  E/X subset in each host browser. Those host observations do not cover the full browser matrix.

Already answered and needing no PRD (from the 2026-11-15 issue list):

- **Relaunch after OpenCode exits:** `oc-sandbox -i feat-a` alone is enough. The working directory defaults
  to `wt/feat-a`, which is already the worktree, so `-W` isn't needed again. Port mappings are stored on
  the pod and kept until a new `-P` is given. `-P` can be repeated (`-P 3001:3000 -P 8081:80`) or
  comma-separated. A remaining gap is tracked in [prd_c](prd_c.md): a different `-W` is silently ignored
  once the worktree exists.
