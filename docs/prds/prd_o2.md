# prd_o2 · CI test-scope expansion, integration tiers & secret-gated inference smoke tests

Parent: [prd_o](prd_o.md) · [Index](README.md) · related:
[prd_i3](prd_i3.md), [prd_i4](prd_i4.md), [prd_k](prd_k.md), [prd_m](prd_m.md),
[prd_n](prd_n.md), [prd_o1](prd_o1.md), [prd_o3](prd_o3.md)

## Audit: what runs in CI today vs what exists on `origin/main`

Inventory at `origin/main` (`9b608f431eedf7e55137c6dfe1abead9ffd2cba8`):

| Test Group | Location on `origin/main` | Runs in Hosted CI Today? | Current Gap |
|---|---|---|---|
| Core portable unit & stubbed security suites (15 suites) | `tests/` via `tools/ci/run.py tests` | **Yes** (`oc-sandbox PR`) | Runs only on `pull_request` (not `push` to `main`); `tests/security.sh` runs `224` stubbed checks (`OC_TEST_NO_PODMAN=1`) and skips `22` real-Podman checks |
| Core Python coverage (2 modules: `oc_bridge_merge.py`, `oc_controller.py`) | `tools/ci/core_coverage.py` | **Yes** (`oc-sandbox baselines`) | Does not cover newer modules (`oc-bridge.py`, `oc-opencode-*.py`, or promoted spike kernels) |
| Offline Python spike test suites (**30 test files** across 13 dirs) | `docs/prds/spikes/{l,l_m_profile,m,n}/**/test_*.py` | **No** | Zero regression guard in hosted CI after merge; cross-spike edits can silently break merged proofs (`l/`, `m/`, `n/restart/`, `n/inbox-read/`, etc.) |
| SvelteKit / TypeScript Web UI (`oc-sandbox-m3a-dashboard`) | `docs/prds/spikes/m/web-ui/` (`package-lock.json`, `npm run check`, `npm run build`, `npm test` — 3 unit files + 1 Playwright spec) | **No** | Zero TypeScript/Svelte typecheck, build, CSP check, or UI unit test coverage in hosted CI |
| Real Podman security suite (`246` checks) & container builds | `tests/security.sh` (without `OC_TEST_NO_PODMAN=1`), `tests/postgres-host-real.py`, `tests/parallel.sh` | **No** (`SKIP`ped in portable profile) | Container/mount/secret/network regressions are only caught locally by the maintainer before commit (`AGENTS.md`) |
| SELinux / Wayland / host browser & SSH remote acceptance | `tests/parallel.sh` (host Chrome/SELinux), [prd_k](prd_k.md#remote-acceptance) | **No** | Requires host Wayland/SELinux or disposable SSH worker; explicitly remains local or separately approved trusted workflow |
| Basic live LLM provider inference smoke tests | Not yet implemented (synthetic upstreams exist in `docs/prds/spikes/m/local/`) | **No** | Upstream provider API wire-format/model-ID/auth-header drift is undetected until manual local testing |

## Four-tier CI trust and execution matrix

Expanding test scope must **never** weaken the fork-PR security boundary established in
[prd_k](prd_k.md). PRD O separates all checks into four explicit trust tiers:

| Tier | Scope | Triggers & Permissions | External API Secrets | GHA Cache Policy ([prd_o3](prd_o3.md)) | Required-Check / Promotion Status |
|---|---|---|---|---|---|
| **Tier 0A-gate** (`oc-sandbox PR`) | Core portable suites (15) + `quality`, aggregated by `oc-sandbox / required` | `pull_request` (incl. forks) + proposed `push` to `main` (O1-D); `contents: read` (`{}` on aggregator) | **None** | Verified read-only restore on PR; seeded on `main` | **Required gate** (`oc-sandbox / required` aggregates `tests` and `quality` only; promotion tracked in [prd_k](prd_k.md)) |
| **Tier 0A-baselines** (`oc-sandbox baselines` workflow) | `Python coverage baseline`, `Dependency Review baseline`, and `CodeQL baseline (python, actions)` | `pull_request` (GitHub Actions workflow); `contents: read` on coverage/DepReview, **`security-events: write` strictly isolated to the `build-mode: none` CodeQL job** | **None** | Verified read-only restore on PR (`py-wheels`); seeded on `main` | **Separate from `oc-sandbox / required`**; default-branch qualification & promotion owned by [prd_k](prd_k.md) |
| **Tier 0A-sonar** (SonarQube Cloud GitHub App) | Automatic SonarQube Cloud analysis & quality gate on new code | Independent GitHub App triggered on **both `pull_request` and `main`** (not a GitHub Actions workflow; zero Actions secrets) | **None** | N/A (external GitHub App) | **Separate from `oc-sandbox / required`**; qualification & merge-gate rollout tracked in [prd_k](prd_k.md) |
| **Tier 0B** | Offline Python spike suites (30 files) + Web UI (`check`, `build`, `node --test`, optional headless Playwright) | `pull_request` (incl. forks) + `push` to `main`; `contents: read` only | **None** | Verified read-only restore on PR; seeded on `main` | Unconditional `spike-python` promotable to `oc-sandbox / required` after qualification; `spike-web-ui` advisory if path-filtered or promotable if unconditional |
| **Tier 1** | Real rootless Podman `tests/security.sh` (`22` skipped checks; `19` non-SELinux on Ubuntu), Containerfile build smoke, bounded Postgres sidecar smoke | `push` to `main`, nightly `schedule`, `workflow_dispatch`; `contents: read` only | **None** | Optional bounded container cache only after independent output-digest verification ([prd_o3](prd_o3.md)) | Advisory initially; promote only after hosted stability proof |
| **Tier 2** | Basic live LLM provider inference smoke (tiny deterministic wire-contract probe) | **`main`-only** nightly `schedule` + manual `workflow_dispatch` via protected Environment `ci-inference-smoke`; `contents: read` only | **Dedicated low-budget CI API keys ONLY** | **Strictly NONE** (no cache read or write) | **Never required** (never blocks PR merges on upstream provider outages) |
| **Tier 3** | Full `tests/parallel.sh` (Chrome/SELinux/Wayland), SELinux MCS xattr checks, local host subscription acceptance (`prd_i3`/`prd_i4`) | Local maintainer workstation (`AGENTS.md`) | Local host credentials only | N/A | Maintainer local gate |

## Tier 0B: Offline spike suites and SvelteKit Web UI

All 30 Python spike test files under `docs/prds/spikes/` are **100% offline** (zero Podman, zero
network, zero host production writes), and `docs/prds/spikes/m/web-ui/` carries a committed
`package-lock.json` pinning Node `24.18.0` / npm `11.16.0` devDependencies (`svelte`, `vite`,
`typescript`, `svelte-check`, `@playwright/test`).

Operational notes discovered during PRs #57–#64:
- SQLite-backed spike suites (`m/projection`, `n/restart`, `n/inbox-read`) require a private,
  user-owned canonical `TMPDIR` (matching `tools/ci/run.py`'s `suite_scratch` behavior) so SQLite
  temporary files never resolve through world-writable or `nobody`-owned `/tmp` mounts.
- Web UI installs in CI must first run a lockfile admission validator on **both cold and warm
  paths** (verifying every installable dependency in `package-lock.json` comes from the allowed
  registry origin and carries a strong SRI `integrity` digest — see [prd_o3](prd_o3.md)), and then
  run `npm ci --ignore-scripts --offline` on cache hit (or `npm ci --ignore-scripts --prefer-offline`
  on cold miss) so untrusted postinstall lifecycle scripts cannot execute.

### Options for Tier 0B

Required-check constraint (from [prd_k](prd_k.md) and `.github/workflows/pr.yml`): a companion
workflow using `on.pull_request.paths` creates **no** check run when paths are untouched (leaving
a GitHub ruleset required check permanently pending), and skipping a job inside `pr.yml` either
fails `oc-sandbox / required` (`[[ "$RESULT" == success ]]`) or re-introduces a skipped-job bypass
if the PR checkout itself can edit path filters. Therefore, any check promoted to a **required**
merge gate must run **unconditionally** (or be gated by a trusted target-branch classifier per
[prd_k](prd_k.md)).

- **Option O2-A (Recommended):** Add two dedicated zero-secret jobs running in parallel with
  `tests` and `quality`:
  1. `spike-python` (**unconditional on every `pull_request` and `push` to `main`**, promotable to
     `oc-sandbox / required`): runs an explicit tracked manifest of the 30 offline Python spike test
     files in process-isolated parallel workers under private `HOME`/`TMPDIR` scratch (`~10–15 s`
     wall clock with 4 workers — completely overlapped underneath `tests`, adding **`0 s`** to
     critical-path wall clock and eliminating path-filter bypass risk!).
  2. `spike-web-ui`: runs `npm ci --ignore-scripts` (with `--offline` on cache hit, else
     `--prefer-offline`), `npm run check`, `npm run build`, and `npm test`
     (`node --test tests/*.test.mjs`) on `docs/prds/spikes/m/web-ui/` (`~15–25 s` warm cache). Start
     unconditional (still overlapped underneath `tests` once warm-cached) if required, or keep
     path-filtered as **advisory-only** until a trusted classifier exists; keep
     `npm run test:browser` (Playwright Chromium) opt-in / Tier 1 to avoid multi-hundred-MB browser
     download churn on every docs PR.
  - **Pros:** Protects all 30 merged spike test suites and the SvelteKit dashboard from silent
    regressions with zero secrets, zero path-filter bypass risk on required checks, and ~`0 s`
    critical-path latency increase when overlapped with `tests`.
  - **Cons:** Spike directories are explicitly prototypes (`AGENTS.md`), so CI must maintain an
    explicit manifest list (just like `SUITES` in `tools/ci/run.py`) rather than blind recursive
    globbing, and remove entries as spikes are retired or promoted.
  - **Effort:** ~1 day (with Gate 1/2 review).
- **Option O2-B:** Run both `spike-python` and `spike-web-ui` unconditionally on every PR inside
  `oc-sandbox / required` from day one (no advisory phase).
  - **Pros:** Simplest workflow logic; uniform required-check semantics across Python and Web UI.
  - **Cons:** Adds Node/npm setup overhead even to pure shell or docs-only PRs (though overlapped
    with `tests` when warm-cached).
  - **Effort:** ~0.5–1 day.
- **Option O2-C:** Keep spike suites out of hosted CI until each spike is promoted to production
  code under `src/` or `tests/`.
  - **Pros:** Zero CI maintenance for prototype directories.
  - **Cons:** Leaves 30 existing test suites and the SvelteKit UI completely unguarded on `main`
    until production ports land.
  - **Effort:** 0 days.

## Tier 1: Real container integration tests

`tests/security.sh` runs **246 total checks** locally: **`224` stubbed checks** already run in
portable CI under `OC_TEST_NO_PODMAN=1`, while **`22` real-Podman checks** (`14` in lines
`1129–1235` + `8` `FROM scratch` checks in lines `1254–1296`) are skipped. `tests/parallel.sh` and
`tests/postgres-host-real.py` additionally exercise live pods, Postgres, Chromium, and nested
container flows.

Three concrete `ubuntu-24.04` hosted-runner constraints require a **throwaway feasibility spike**
before committing to hosted Tier 1 gating:
1. Ubuntu 24.04 enables `kernel.apparmor_restrict_unprivileged_userns=1` by default, which can
   restrict rootless Podman user-namespace creation unless the runner image provides an AppArmor
   profile for `podman`/`newuidmap` (or verified runner support).
2. `tests/security.sh:1131` silently skips the entire 14-check block unless `TEST_AGENT_IMG`
   (`oc-agent` or `OC_TEST_AGENT_IMAGE`) is prebuilt/supplied on the runner (otherwise only the 8
   `FROM scratch` checks at lines `1254–1296` execute).
3. `tests/security.sh:1175–1178` and `1228–1234` unconditionally assert SELinux MCS xattrs
   (`os.getxattr(..., "security.selinux")` and `stat -c %C`), which will **fail on Ubuntu 24.04**
   (no SELinux). On non-SELinux runners, those 3 SELinux MCS assertions must be explicitly scoped
   out (reporting a clear skip) while staying strictly fail-closed on SELinux hosts.

### Options for Tier 1

- **Option O2-D (Recommended):** Run a bounded `ubuntu-24.04` hosted-runner feasibility spike
  (`workflow_dispatch` only, zero secrets) testing whether preinstalled/apt `podman` can build or
  supply `TEST_AGENT_IMG`, execute the non-SELinux subset of the 22 real-Podman checks in
  `bash tests/security.sh` (explicitly scoping the 3 SELinux MCS xattr assertions only on
  non-SELinux hosts), and run a minimal Postgres container smoke test cleanly within `<= 5 min`.
  If feasible, enable Tier 1 on `push` to `main`, nightly `schedule`, and `workflow_dispatch`
  (advisory first, zero external API secrets). Keep SELinux MCS enforcement and full
  `tests/parallel.sh` (Chromium/SELinux/Wayland) in Tier 3 local host gates.
  - **Pros:** Closes the non-SELinux real-Podman gap (`19` of the `22` skipped real-Podman checks
    on Ubuntu, out of `246` total `tests/security.sh` assertions) without operating self-hosted
    runner infrastructure or exposing secrets to PRs.
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

Use the lowest-cost model verified to support the behavior the smoke test exercises. Pin that
model in the test so the requested route and usage scope can be reviewed. A model-picker,
capability, or compatibility test can pin a different model when the distinction is under test.

Approve real-resource tests once for the selected pytest cases before execution. The approval
lists the resource, authentication type and maximum test actions. The cases then run without
operator input. Default runs skip live tests. Workstation subscriptions use local consent.
Dedicated API keys and disposable remote SSH fixtures may use a separately authorized GitHub
Environment. Keep remote fixtures outside the PR execution boundary and verify teardown.

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

1. **Protected GitHub Environment (`ci-inference-smoke`) & `workflow_dispatch` lockdown:**
   - Deployment branch policy restricted strictly to `main` (never PR branches, never tags from
     untrusted actors), reinforced in-workflow with `if: github.ref == 'refs/heads/main'` and
     `actions/checkout` pinned to `ref: ${{ github.sha }}` (zero custom checkout ref inputs).
   - Forbid free-form `workflow_dispatch` inputs (at most a fixed-enum `choice` selecting a
     provider subset); optional required maintainer reviewer approval for manual dispatch.
   - Workflow triggers restricted strictly to `schedule` (e.g., once nightly) and `workflow_dispatch`
     — **NEVER** `pull_request` or `pull_request_target`.
   - Enforce `timeout-minutes: 5` and serialized `concurrency` (`cancel-in-progress: false`) so
     overlapping dispatches cannot multiply spend.
2. **Zero cache, minimal permissions, & step-scoped secrets:**
   - `permissions: { contents: read }` only; `persist-credentials: false`.
   - **Zero** `actions/cache` read or write (no cache-to-secret pivot surface).
   - Inject each provider API key strictly into its own isolated step (or matrix leg), never at
     workflow-level or job-level `env:`.
3. **Hardcoded HTTPS endpoints, redirect refusal, & deterministic probe:**
   - Pin provider HTTPS endpoints in code and refuse all `3xx` HTTP redirects (matching
     `tools/ci/sonar_http.py`), preventing `Authorization` / `x-api-key` redirection to another
     host; scrub `*_BASE_URL`, `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` environment variables.
   - Pass Gemini API keys strictly via the `x-goog-api-key` header (never `?key=` query strings
     that leak into URLs or tracebacks).
   - Send one hardcoded static prompt per configured provider (e.g.,
     `"Reply with the single token PONG"`), with `max_tokens <= 32`, `temperature = 0`,
     `timeout <= 20 s`, `retries = 0`, and at most `2` requests per provider per run (normal
     completion + expected error-code / invalid-model handling).
   - Never interpolate repository contents, commit messages, PR titles, or workflow inputs into the
     prompt or headers.
4. **Log hygiene, no raw HTTP artifacts, & non-blocking merge posture:**
   - Skip a provider cleanly with an explicit warning if its secret is unset, fail loudly on auth
     (`401`/`403`) or wire-schema mismatch when set, **forbid `actions/upload-artifact`** of raw
     HTTP dumps or responses, and drop/redact **both** raw response headers and raw error bodies
     before logging (emit parsed structured JSON error codes/types only).
   - Tier 2 is **never** added to `oc-sandbox / required` so upstream provider outages or billing
     glitches never block code merges.

### Options for Tier 2

- **Option O2-G (Recommended):** Implement Tier 2 as an isolated `ci-inference-smoke.yml` workflow
  bound to protected GitHub Environment `ci-inference-smoke` (`main`-only `schedule` +
  `workflow_dispatch`, zero cache, step-scoped dedicated low-budget API keys, hardcoded HTTPS
  endpoints with `3xx` refusal, static `PONG` probe, hard `<= 32`-token cap). Keep all PR checks
  100% synthetic/zero-secret.
  - **Pros:** Catches real provider SDK/wire/auth regressions nightly with negligible cost
    (`< \$1/month`), zero fork/PR secret exposure, and zero impact on PR velocity.
  - **Cons:** Requires maintainer to provision and rotate low-budget API keys per provider in the
    GitHub Environment and set upstream provider spend caps; does not exercise OAuth subscription
    flows (which stay in local Tier 3 acceptance).
  - **Effort:** ~1 day (once live provider adapter code lands on `main`).
- **Option O2-H:** Keep GitHub Actions 100% free of API secrets; run live inference smoke only via
  a local maintainer CLI command (`tools/ci/inference_smoke.py --local`).
  - **Mandatory credentialed-code boundary for Option O2-H:** The credentialed probe script and
    **every module it imports** must execute strictly from a **separately verified, reviewed
    revision** (e.g., clean `main` checkout) in a clean Python environment (`python3 -I`, isolated
    `PYTHONPATH` excluding any unreviewed candidate checkout). Candidate adapter changes under
    review are exercised strictly against **synthetic credentials and synthetic upstreams** until
    they reach that trusted reviewed revision.
  - **Pros:** Zero secrets stored in GitHub; zero cloud secret-rotation burden.
  - **Cons:** Live wire drift is discovered only when the maintainer runs the trusted-revision
    local smoke command.
  - **Effort:** ~0.5 day.
- **Rejected — PR-triggered secret smoke (formerly Option O2-I, disqualified by Non-Negotiable
  Invariants #1 & #4):** Running live inference smoke on maintainer-labeled PRs via Environment
  approval would require weakening `ci-inference-smoke`'s `main`-only deployment branch policy to
  allow PR branches and introduces label/push-to-approval TOCTOU secret-exfiltration risk via
  modified test code. It is explicitly disallowed; candidate PRs run strictly with synthetic
  upstreams, while live provider checks run only from reviewed `main` code (automated under
  `O2-G`, or locally from a verified clean `main` revision under `O2-H`).

## Checkboxes

- [x] Audited existing CI test inventory (`15` portable suites) against full `origin/main` test
  inventory (`30` offline Python spike test files, `docs/prds/spikes/m/web-ui/`, `22` skipped real
  Podman checks + `tests/parallel.sh`, and live inference gap).
- [ ] `(decision needed)` Select Option O2-A, O2-B, or O2-C for Tier 0B (offline spike Python
  suites + SvelteKit Web UI in CI).
- [ ] `(decision needed)` Select Option O2-D, O2-E, or O2-F for Tier 1 (real Podman / container
  integration in hosted CI vs local-only).
- [ ] `(decision needed)` Select Option O2-G or O2-H for Tier 2 (protected-Environment `main`-only
  live inference smoke vs local-only; PR-triggered secrets remain disallowed).
- [ ] `(decision needed)` Decide whether `tools/ci/core_coverage.py` should expand beyond
  `oc_bridge_merge.py` and `oc_controller.py` as additional Python modules stabilize.
- [ ] Run Gate 1 walkthrough review before implementing each selected tier.
