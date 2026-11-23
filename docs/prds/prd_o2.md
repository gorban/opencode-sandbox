# prd_o2 · CI test-scope expansion, integration tiers & secret-gated inference smoke tests

Parent: [prd_o](prd_o.md) · [Index](README.md) · related:
[prd_i3](prd_i3.md), [prd_i4](prd_i4.md), [prd_k](prd_k.md), [prd_m](prd_m.md),
[prd_n](prd_n.md), [prd_o1](prd_o1.md), [prd_o3](prd_o3.md)

## Audit: what runs in CI today vs what exists on `origin/main`

Inventory at `origin/main` (`9b608f431eedf7e55137c6dfe1abead9ffd2cba8`):

| Test Group | Location on `origin/main` | Runs in Hosted CI Today? | Current Gap |
|---|---|---|---|
| Core portable unit & stubbed security suites (15 suites) | `tests/` via `tools/ci/run.py tests` | **Yes** (`oc-sandbox PR`) | Runs only on `pull_request` (not `push` to `main`); `tests/security.sh` runs stubbed (`132` checks, `OC_TEST_NO_PODMAN=1`) |
| Core Python coverage (2 modules: `oc_bridge_merge.py`, `oc_controller.py`) | `tools/ci/core_coverage.py` | **Yes** (`oc-sandbox baselines`) | Does not cover newer modules (`oc-bridge.py`, `oc-opencode-*.py`, or promoted spike kernels) |
| Offline Python spike test suites (**30 test files** across 13 dirs) | `docs/prds/spikes/{l,l_m_profile,m,n}/**/test_*.py` | **No** | Zero regression guard in hosted CI after merge; cross-spike edits can silently break merged proofs (`l/`, `m/`, `n/restart/`, `n/inbox-read/`, etc.) |
| SvelteKit / TypeScript Web UI (`oc-sandbox-m3a-dashboard`) | `docs/prds/spikes/m/web-ui/` (`package-lock.json`, `npm run check`, `npm run build`, `npm test` — 3 unit files + 1 Playwright spec) | **No** | Zero TypeScript/Svelte typecheck, build, CSP check, or UI unit test coverage in hosted CI |
| Real Podman security suite (`246` checks) & container builds | `tests/security.sh` (without `OC_TEST_NO_PODMAN=1`), `tests/postgres-host-real.py`, `tests/parallel.sh` | **No** (`SKIP`ped in portable profile) | Container/mount/secret/network regressions are only caught locally by the maintainer before commit (`AGENTS.md`) |
| SELinux / Wayland / host browser & SSH remote acceptance | `tests/parallel.sh` (host Chrome/SELinux), [prd_k](prd_k.md#remote-acceptance) | **No** | Requires host Wayland/SELinux or disposable SSH worker; explicitly remains local or separately approved trusted workflow |
| Basic live LLM provider inference smoke tests | Not yet implemented (synthetic upstreams exist in `docs/prds/spikes/m/local/`) | **No** | Upstream provider API wire-format/model-ID/auth-header drift is undetected until manual local testing |

## Four-tier CI trust and execution matrix

Expanding test scope must **never** weaken the fork-PR security boundary established in
[prd_k](prd_k.md). PRD O separates all checks into four explicit trust tiers:

| Tier | Scope | Triggers | External Secrets | GHA Cache Policy ([prd_o3](prd_o3.md)) | Required to Merge PR? |
|---|---|---|---|---|---|
| **Tier 0A** | Core portable suites (15), `quality`, coverage, CodeQL, DepReview, SonarQube Cloud | `pull_request` (incl. forks) + `push` to `main` | **None** | Verified read-only restore on PR; seeded on `main` | **Yes** (`oc-sandbox / required`) |
| **Tier 0B** | Offline Python spike suites (30 files) + Web UI (`check`, `build`, `node --test`, optional headless Playwright) | `pull_request` (incl. forks) + `push` to `main` | **None** | Verified read-only restore on PR; seeded on `main` | **Yes** (once qualified; separate job or under `required`) |
| **Tier 1** | Real rootless Podman `tests/security.sh` (`246` checks), Containerfile build smoke, bounded Postgres sidecar smoke | `push` to `main`, nightly `schedule`, `workflow_dispatch` (optional PR opt-in after spike) | **None** | Optional bounded container-layer cache (verified digest-keyed, `main`-seeded) | Advisory initially; promote only after hosted stability proof |
| **Tier 2** | Basic live LLM provider inference smoke (tiny deterministic wire-contract probe) | **`main`-only** nightly `schedule` + manual `workflow_dispatch` via protected Environment `ci-inference-smoke` | **Dedicated low-budget CI API keys ONLY** | **Strictly NONE** (no cache read or write) | **No** (never blocks PR merges on upstream provider outages) |
| **Tier 3** | Full `tests/parallel.sh` (Chrome/SELinux/Wayland), local host subscription acceptance (`prd_i3`/`prd_i4`) | Local maintainer workstation (`AGENTS.md`) | Local host credentials only | N/A | Maintainer local gate |

## Tier 0B: Offline spike suites and SvelteKit Web UI

All 30 Python spike test files under `docs/prds/spikes/` are **100% offline** (zero Podman, zero
network, zero host production writes), and `docs/prds/spikes/m/web-ui/` carries a committed
`package-lock.json` pinning Node `24.18.0` / npm `11.16.0` devDependencies (`svelte`, `vite`,
`typescript`, `svelte-check`, `@playwright/test`).

Operational notes discovered during PRs #57–#64:
- SQLite-backed spike suites (`m/projection`, `n/restart`, `n/inbox-read`) require a private,
  user-owned canonical `TMPDIR` (matching `tools/ci/run.py`'s `suite_scratch` behavior) so SQLite
  temporary files never resolve through world-writable or `nobody`-owned `/tmp` mounts.
- Web UI installs in CI must run `npm ci --ignore-scripts --offline` (against the lockfile-hashed
  cache from [prd_o3](prd_o3.md)) or `--ignore-scripts` on cache miss so untrusted postinstall
  lifecycle scripts cannot execute during dependency installation.

### Options for Tier 0B

- **Option O2-A (Recommended):** Add two dedicated zero-secret jobs to `.github/workflows/pr.yml`
  (or a companion `spikes-ci.yml` workflow) with path-aware triggers on `pull_request` AND full
  unconditional runs on `push` to `main` (and whenever `tools/ci/**` or shared spike contracts
  change):
  1. `spike-python`: runs all 30 offline Python spike test files in parallel workers under private
     `HOME`/`TMPDIR` scratch (`~10–15 s` wall clock with 4 workers).
  2. `spike-web-ui`: runs `npm ci --ignore-scripts`, `npm run check`, `npm run build`, and
     `npm test` (`node --test tests/*.test.mjs`) on `docs/prds/spikes/m/web-ui/` (`~15–25 s` warm
     cache), keeping `npm run test:browser` (Playwright Chromium) opt-in / Tier 1 to avoid
     multi-hundred-MB browser download churn on every docs PR.
  - **Pros:** Protects all 30 merged spike test suites and the SvelteKit dashboard from silent
    regressions with zero secrets and minimal wall-clock cost when parallelized and cached.
  - **Cons:** Spike directories are explicitly prototypes (`AGENTS.md`), so CI must distinguish
    promoted/active spike suites from archived throwaway probes via an explicit manifest list (just
    like `SUITES` in `tools/ci/run.py`) rather than blind recursive globbing.
  - **Effort:** ~1 day (with Gate 1/2 review).
- **Option O2-B:** Run all 30 spike Python suites + Web UI unconditionally on every PR (no path
  filtering).
  - **Pros:** Simplest workflow logic; zero risk of missing a cross-cutting dependency.
  - **Cons:** Adds Node/npm setup overhead even to pure shell or docs-only PRs.
  - **Effort:** ~0.5–1 day.
- **Option O2-C:** Keep spike suites out of hosted CI until each spike is promoted to production
  code under `src/` or `tests/`.
  - **Pros:** Zero CI maintenance for prototype directories.
  - **Cons:** Leaves 30 existing test suites and the SvelteKit UI completely unguarded on `main`
    until production ports land.
  - **Effort:** 0 days.

## Tier 1: Real container integration tests

`tests/security.sh` runs **246 real Podman tests** locally vs **132 stubbed tests** in portable CI.
`tests/parallel.sh` and `tests/postgres-host-real.py` exercise live pods, Postgres, Chromium, and
nested container flows.

Important `ubuntu-24.04` hosted-runner constraint: Ubuntu 24.04 enables
`kernel.apparmor_restrict_unprivileged_userns=1` by default, which can restrict rootless Podman
user-namespace creation unless the runner image provides an explicit AppArmor profile for `podman` /
`newuidmap` (or `podman` runs with verified runner support). Therefore, **a throwaway feasibility
spike is required before committing to hosted Tier 1 gating**.

### Options for Tier 1

- **Option O2-D (Recommended):** Run a bounded `ubuntu-24.04` hosted-runner feasibility spike
  (`workflow_dispatch` only, zero secrets) testing whether preinstalled/apt `podman` can execute
  `bash tests/security.sh` (real Podman mode) and a minimal Postgres container smoke test cleanly
  within `<= 5 min`. If feasible, enable Tier 1 on `push` to `main`, nightly `schedule`, and
  `workflow_dispatch` (advisory first, zero external API secrets). Keep full `tests/parallel.sh`
  (Chromium/SELinux/Wayland) in Tier 3 local host gates.
  - **Pros:** Closes the largest real-runtime gap (246 real Podman security assertions) without
    operating self-hosted runner infrastructure or exposing secrets to PRs.
  - **Cons:** GitHub-hosted Ubuntu runners lack Fedora SELinux enforcement and host Wayland, so
    SELinux/Wayland regressions still require Tier 3 local checks; container image pulls add
    `~30–90 s` unless paired with bounded caching ([prd_o3](prd_o3.md)).
  - **Effort:** ~1–2 days (including feasibility probe).
- **Option O2-E:** Provision an ephemeral self-hosted Fedora runner (e.g., disposable VM) for full
  `tests/security.sh` + `tests/parallel.sh` including SELinux.
  - **Pros:** Matches maintainer Fedora/SELinux environment closely.
  - **Cons:** High operational and security overhead (must NEVER run untrusted fork PRs on
    self-hosted runners; VM image patching, lifecycle teardown, host isolation).
  - **Effort:** ~3–5 days + ongoing maintenance.
- **Option O2-F:** Keep all real Podman/Postgres tests strictly local (`AGENTS.md` pre-commit gate).
  - **Pros:** Zero hosted complexity.
  - **Cons:** Container regressions on `main` are only caught when a developer runs real Podman
    locally.
  - **Effort:** 0 days.

## Tier 2: Secret-gated basic live inference smoke tests

The maintainer asked whether we will need API keys as GitHub Actions secrets for basic inference
tests.

### Direct answer

- **For Tier 0 PR checks and Tier 1 container integration:** **No.** All unit, contract, broker,
  proxy, quota-math, and offline end-to-end tests MUST continue using deterministic synthetic
  upstreams (`docs/prds/spikes/m/local/`, `oc-bridge.py` stubs) with **zero secrets**.
- **For Tier 2 live provider wire-contract smoke tests** (verifying that real OpenAI / Anthropic /
  Google Gemini endpoints still accept our request framing, auth header injection, streaming/JSON
  response parsing, and error handling): **Yes — dedicated, low-spend CI API keys stored as
  GitHub Environment secrets are required** if we want automated live inference smoke in GitHub
  Actions.
- **Hard boundary with subscription lanes ([prd_i3](prd_i3.md)/[prd_i4](prd_i4.md)):** Personal
  OAuth/subscription sessions (Codex/ChatGPT, Claude Pro/Max, Google AI Pro) MUST **never** be
  exported into GitHub Actions secrets. Tier 2 covers only revocable, pay-as-you-go API keys with
  hard monthly spend caps (`<= \$5–\$10/month`), strictly separate from local attended subscription
  acceptance.

### Security architecture for Tier 2 (if enabled)

1. **Protected GitHub Environment (`ci-inference-smoke`):**
   - Deployment branch policy restricted strictly to `main` (never PR branches, never tags from
     untrusted actors).
   - Optional required maintainer reviewer approval for `workflow_dispatch`.
   - Workflow triggers restricted strictly to `schedule` (e.g., once nightly) and `workflow_dispatch`
     — **NEVER** `pull_request` or `pull_request_target`.
2. **Zero cache & minimal permissions:**
   - `permissions: { contents: read }` only; `persist-credentials: false`.
   - **Zero** `actions/cache` read or write (no cache-to-secret pivot surface).
3. **Deterministic, injection-proof, budget-capped probe:**
   - One hardcoded static prompt per configured provider (e.g., `"Reply with the single token PONG"`),
     with `max_tokens <= 32`, `temperature = 0`, `timeout <= 20 s`, `retries = 0`, and at most `2`
     requests per provider per run (normal completion + expected error-code / invalid-model handling).
   - Never interpolate repository contents, commit messages, PR titles, or workflow inputs into the
     prompt or headers.
   - Skip a provider cleanly with an explicit warning if its secret is unset, fail loudly on auth
     (`401`/`403`) or wire-schema mismatch when set, and mask/strip all auth headers and raw tokens
     from logs.
4. **Non-blocking merge posture:**
   - Tier 2 is **never** added to `oc-sandbox / required` so upstream provider outages or billing
     glitches never block code merges.

### Options for Tier 2

- **Option O2-G (Recommended):** Implement Tier 2 as an isolated `ci-inference-smoke.yml` workflow
  bound to protected GitHub Environment `ci-inference-smoke` (`main`-only `schedule` +
  `workflow_dispatch`, zero cache, hardcoded `PONG` probe, hard `<= 32`-token cap, dedicated
  low-budget API keys). Keep all PR checks 100% synthetic/zero-secret.
  - **Pros:** Catches real provider SDK/wire/auth regressions nightly with negligible cost
    (`< \$1/month`), zero fork/PR secret exposure, and zero impact on PR velocity.
  - **Cons:** Requires maintainer to provision and rotate low-budget API keys per provider in the
    GitHub Environment and set upstream provider spend caps; does not exercise OAuth subscription
    flows (which stay in local Tier 3 acceptance).
  - **Effort:** ~1 day (once live provider adapter code lands on `main`).
- **Option O2-H:** Keep GitHub Actions 100% free of API secrets; run live inference smoke only via
  a local maintainer CLI command (`tools/ci/inference_smoke.py --local`).
  - **Pros:** Zero secrets stored in GitHub; zero cloud secret-rotation burden.
  - **Cons:** Live wire drift is discovered only when the maintainer remembers to run the local
    command.
  - **Effort:** ~0.5 day.
- **Option O2-I:** Run live inference smoke on maintainer-labeled same-repo PRs via Environment
  approval.
  - **Pros:** Pre-merge live verification on provider-adapter PRs.
  - **Cons:** Higher operational risk (approver must verify exact commit SHA before every approval
    to prevent exfiltration via modified test code); unnecessary when `workflow_dispatch` on `main`
    (or local runs pre-merge) achieves the same coverage safely.
  - **Effort:** ~1.5 days.

## Checkboxes

- [x] Audited existing CI test inventory (`15` portable suites) against full `origin/main` test
  inventory (`30` offline Python spike test files, `docs/prds/spikes/m/web-ui/`, real Podman/parallel
  suites, and live inference gap).
- [ ] `(decision needed)` Select Option O2-A, O2-B, or O2-C for Tier 0B (offline spike Python
  suites + SvelteKit Web UI in CI).
- [ ] `(decision needed)` Select Option O2-D, O2-E, or O2-F for Tier 1 (real Podman / container
  integration in hosted CI vs local-only).
- [ ] `(decision needed)` Select Option O2-G, O2-H, or O2-I for Tier 2 (secret-gated basic live
  inference smoke tests in protected GitHub Environment `ci-inference-smoke` vs local-only).
- [ ] `(decision needed)` Decide whether `tools/ci/core_coverage.py` should expand beyond
  `oc_bridge_merge.py` and `oc_controller.py` as additional Python modules stabilize.
- [ ] Run Gate 1 walkthrough review before implementing each selected tier.
