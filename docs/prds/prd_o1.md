# prd_o1 · CI build & test duration trends and bottleneck analysis

Parent: [prd_o](prd_o.md) · [Index](README.md) · related:
[prd_k](prd_k.md), [prd_o2](prd_o2.md), [prd_o3](prd_o3.md)

## Empirical baseline (`origin/main` at `9b608f43`)

All measurements below were collected from `gorban/opencode-sandbox` GitHub Actions runs spanning
`2026-11-21T13:22:31Z` through `2026-11-23T13:15:11Z` (**257 total workflow runs** across
`oc-sandbox PR` and `oc-sandbox baselines`), plus SonarQube Cloud `main` metrics (`85,286` NCLOC,
`0.2%` duplication, quality gate `OK`).

### Workflow duration trend by day

| Workflow | Total Runs | Outcomes | `2026-11-21` p50 (min–max) | `2026-11-22` p50 (min–max) | `2026-11-23` p50 (min–max) | Observed Trend |
|---|---|---|---|---|---|---|
| `oc-sandbox PR` | 131 | 110 success, **21 failure (16.0%)** | `129 s` (`114–275 s`, `n=12`) | `100 s` (`90–312 s`, `n=62`) | `99 s` (`91–286 s`, `n=36`) | Flat ~`99 s` on green runs; `p90 137 s` and `max 286–312 s` driven by retries and runner queue spikes |
| `oc-sandbox baselines` | 126 | 123 success, 3 cancelled, 0 failure | `56 s` (`43–165 s`, `n=7`) | `62 s` (`40–96 s`, `n=72`) | `72 s` (`60–268 s`, `n=44`) | **+29% upward trend in 48 h**, tracking Python codebase growth in `CodeQL baseline (python)` |

### Job and step breakdown (15 most recent runs per workflow)

| Workflow / Job | Median (`p50`) | Min–Max | Recent Failures | Dominant Step(s) |
|---|---|---|---|---|
| `oc-sandbox PR / tests` | `72 s` | `68–78 s` | 0 / 15 | `Run portable tests on the merge commit` (`p50 62.0 s`, `max 72.0 s`); `checkout` (`4 s`); setup (`2 s`) |
| `oc-sandbox PR / quality` | `14 s` | `10–18 s` | **2 / 15** | `Check source quality on the merge commit` (`p50 7.0 s`, `max 10.0 s`); `checkout` (`3 s`); runs **serially after `tests`** (`needs: tests`) |
| `oc-sandbox PR / required` | `4 s` | `3–6 s` | 2 / 15 (cascade) | Aggregator check (`needs: [tests, quality]`) |
| `oc-sandbox baselines / CodeQL (python)` | `70 s` | `57–89 s` | 0 / 15 | `codeql-action/analyze` (`p50 45.0 s`, `max 69.0 s`) + `init` (`p50 13.0 s`) + `checkout` (`4 s`) |
| `oc-sandbox baselines / CodeQL (actions)` | `40 s` | `32–44 s` | 0 / 15 | `codeql-action/analyze` (`p50 17.0 s`) + `init` (`p50 13.0 s`) + `checkout` (`4 s`) |
| `oc-sandbox baselines / Python coverage` | `11 s` | `7–14 s` | 0 / 15 | `tools/ci/core_coverage.py` (`p50 5.0 s`): fresh `venv` + uncached PyPI download of `coverage-7.11.0-py3-none-any.whl` |
| `oc-sandbox baselines / Dependency Review` | `5 s` | `3–10 s` | 0 / 15 | `actions/dependency-review-action` (`p50 2.0 s`) |

### Suite-level profile inside `oc-sandbox PR / tests` (sample run `45182071109`)

`tools/ci/run.py tests` executes all **15 suites strictly serially**, taking **`~62 s`** total:

| Suite (`tools/ci/run.py`) | Observed Time | Share of `tests` Step | Notes |
|---|---:|---:|---|
| `Security stubs` (`tests/security.sh`, `OC_TEST_NO_PODMAN=1`) | `~35.8 s` | **58%** | Spawns `224` stubbed `oc-sandbox` checks serially (`22` real-Podman checks skipped) |
| `CI supervisor contract` (`tests/test_ci_supervisor.py`) | `~11.9 s` | **19%** | Process-group timeout/signal-drain waits |
| `Launcher and setup lifecycle` (`tests/setup-lifecycle.py`) | `~8.6 s` | **14%** | 41 lifecycle subprocess tests |
| Remaining 12 suites combined | `~5.7 s` | **9%** | Each `< 1.0 s` (`Controller core` `0.008 s`, `Bridge merge core` `0.006 s`, etc.) |

## Root cause of the 16% `oc-sandbox PR` failure rate

Inspection of failed runs in the last 100 runs (`45127421466`, `45123845457`, `45120842525`,
`45120672925`, `45120478991`, `45114120123`) confirms **6 out of 6 (`100%`)** failed on the exact
same infrastructure error inside `quality`:

```text
mise ✗ github:koalaman/shellcheck@0.9.0 · failed: GitHub artifact attestations verification error:
API error: GitHub API returned 403 Forbidden: API rate limit exceeded for <runner-egress-ip>
```

Why this happens:

1. `tools/ci/toolchain.py` creates a fresh `/tmp/oc-ci-*` scratch directory on every run,
   re-downloads `mise-v2026.10.21-linux-x64.tar.xz` (`<= 64 MiB` `ARCHIVE_LIMIT` cap / `175 MB`
   extracted binary), and runs `mise install --locked` for `github:koalaman/shellcheck@0.9.0`.
2. `mise` (under `MISE_PARANOID=1` with `url_api` in `tools/ci/mise.lock`) contacts
   `api.github.com` unauthenticated to probe for GitHub artifact attestations, even though
   `koalaman/shellcheck@0.9.0` (Dec 2022) predates GitHub Artifact Attestations and is already
   pinned by exact SHA-256 in `tools/ci/mise.lock` and `tools/ci/toolchain.py`. Because
   GitHub-hosted `ubuntu-24.04` runners share NAT egress IPs, unauthenticated calls (`60 req/hr/IP`)
   frequently collide with other jobs and return `403 Forbidden`.
3. Even when `quality` succeeds, chaining `needs: tests` adds a second full runner allocation,
   checkout, and `mise` download (~`14–22 s`) onto the end of the `72 s` `tests` critical path.
4. Unlike `oc-sandbox baselines`, `oc-sandbox PR` has **no `concurrency` group**, so pushing two
   commits 10 seconds apart runs both full pipelines concurrently and doubles API-rate-limit exposure.

## Latency-reduction and reliability options

### Option O1-A: Parallelize `quality` with `tests` and add PR `concurrency` cancellation

- **Option A1 (Recommended):** Remove `needs: tests` from `quality` in `.github/workflows/pr.yml`
  (keeping `oc-sandbox / required` gated on `needs: [tests, quality]`) and add PR-scoped
  `concurrency` that never collides on or cancels non-PR runs:
  `group: ci-pr-${{ github.event.pull_request.number || github.run_id }}` with
  `cancel-in-progress: ${{ github.event_name == 'pull_request' }}`.
  - **Pros:** Immediate **~16–22 s** wall-clock drop (`99 s -> ~78 s`) with zero security regression
    (both jobs still verify `GITHUB_SHA` independently and both are required by
    `oc-sandbox / required`); eliminates wasted duplicate PR runs during rapid push bursts without
    cancelling `push` to `main` verification or `main` cache-seeding saves.
  - **Cons:** `quality` still runs even when `tests` fails (~`14 s` of runner time on red PRs, which
    is also useful feedback to contributors).
  - **Effort:** ~1 hour (plus Gate 1/2 review).
- **Option A2:** Keep `quality` serialized after `tests`; add only the non-colliding PR
  `concurrency` rule above.
  - **Pros:** Saves `quality` runner minutes on failing-test PRs.
  - **Cons:** Preserves the `16–22 s` serial wall-clock penalty on every green PR.
  - **Effort:** ~30 minutes.

### Option O1-B: Eliminate `mise` 403 rate-limit failures

- **Option B1 (Recommended — pair with [prd_o3](prd_o3.md)):** Cache the verified `mise` archive +
  pinned `shellcheck` archive (keyed by exact manifest/lockfile/checksum hash, SHA-256 re-verified on
  every hit before extraction/execution) AND keep `GITHUB_TOKEN`/`GH_TOKEN` **completely stripped**
  from `mise`'s environment (preserving `tests/test_ci_toolchain.py`'s token-isolation invariant).
  Disable `mise`'s network attestation lookup when the exact pinned SHA-256 checksum in
  `tools/ci/mise.lock` is verified offline (or extract/verify the pinned archive offline inside
  `toolchain.py`, keeping lockfile parity checks), and verify zero outbound `api.github.com`
  requests occur on cache hit.
  - **Pros:** Cuts the `16%` flaky failure rate to **~0%**, cuts `quality` step time from `7–10 s`
    to `~2–3 s`, preserves strict SHA-256 integrity (`MISE_ARCHIVE_SHA`, `MISE_BINARY_SHA`,
    `SHELLCHECK_CHECKSUM`), and never exposes `GITHUB_TOKEN` to `mise` or untrusted PR checkouts.
  - **Cons:** Requires updating `tools/ci/toolchain.py` and its unit tests (`tests/test_ci_toolchain.py`)
    to accept a read-only verified cache directory without trusting cached bytes before hashing.
  - **Effort:** ~0.5 day.
- **Option B2:** Pass `GITHUB_TOKEN` to `mise install --locked` with no caching.
  - **Pros:** Raises API rate limit from `60/hr/IP` to `1,000/hr/repo`; minimal code change.
  - **Cons:** Regresses `tests/test_ci_toolchain.py`'s explicit token-stripping invariant by
    exposing a repo-scoped `GITHUB_TOKEN` to PR-checked-out `toolchain.py`/`mise` execution; still
    downloads `mise` (`<= 64 MiB`) + `shellcheck` on every PR run; does not scale as additional
    tools (`ruff`, `actionlint`, `shfmt`) are added under [prd_k](prd_k.md).
  - **Effort:** ~2 hours.

### Option O1-C: Intra-job parallelism inside `tools/ci/run.py tests`

Because `tools/ci/supervisor.py` intentionally fails closed on multi-threaded processes
(`PR_SET_CHILD_SUBREAPER`, Linux per-thread `/proc/thread-self/children`, process-global
`os.waitid(os.P_ALL, 0, ...)`, and per-suite `supervisor.drained` gating `shutil.rmtree` against
live-child symlink races in `suite_scratch`), suite parallelism **must use process-per-worker
isolation** — never `ThreadPoolExecutor` inside one supervised process.

- **Option C1 (Recommended):** Use a single-threaded coordinator in `tools/ci/run.py tests` that
  spawns up to `min(4, os.cpu_count() or 2)` single-threaded worker subprocesses (e.g.,
  `tools/ci/run.py --suite <id>`). Each worker independently acquires its own
  `PR_SET_CHILD_SUBREAPER`, isolates its own `/tmp/oc-ci-*` scratch directory, traps and drains
  100% of its own suite's descendants, proves per-suite `drained` before deleting its scratch, and
  returns buffered logs to the coordinator for deterministic ordered printing.
  - **Pros:** Immediately overlaps `CI supervisor contract` (`11.9 s`), `Launcher and setup lifecycle`
    (`8.6 s`), and the 12 fast suites (`5.7 s`) underneath `Security stubs` (`35.8 s`), cutting
    `tests` from **`62 s -> ~37–40 s`** without extra GitHub runner startup overhead while keeping
    `tools/ci/supervisor.py`'s single-threaded subreaper and child-drain guarantees intact.
  - **Cons:** Adds a small `--suite` worker dispatch mode and coordinator-level timeout/SIGINT
    forwarding to `tools/ci/run.py`; `tests/security.sh` (`35.8 s`) remains the single longest
    critical-path suite unless sharded.
  - **Effort:** ~0.5–1 day.
- **Option C2:** Option C1 **plus** sharding `tests/security.sh` stubbed test groups into 2–3
  disjoint process-isolated shards.
  - **Pros:** Cuts `tests` step from **`62 s -> ~18–22 s`**, bringing end-to-end `oc-sandbox PR`
    wall clock under `~40 s` even after adding offline spike tests!
  - **Cons:** Slightly larger diff to `tests/security.sh` (must preserve exact pass/fail total
    reporting and `bash tests/security.sh` single-command local ergonomics).
  - **Effort:** ~1–1.5 days.
- **Option C3:** Keep `tools/ci/run.py tests` strictly serial.
  - **Pros:** Zero changes to `run.py` or `security.sh`.
  - **Cons:** Adding 30 spike suites + Web UI tests serially would push `oc-sandbox PR` past `2–3 min`.
  - **Effort:** 0 days.

### Option O1-D: CI duration trend observability

- **Option D1 (Recommended):** Run `oc-sandbox PR` on `push` to `main` (verifying the `main` commit
  `GITHUB_SHA`, alongside synthetic merge-SHA checks on `pull_request`, with non-cancelling `main`
  concurrency from Option A1) and append a concise per-suite timing summary table to
  `$GITHUB_STEP_SUMMARY` (zero secrets, zero external services, queryable via `gh api` for
  longitudinal trend checks).
  - **Pros:** Gives immediate visibility into which suite regressed latency without adding a third-party
    metrics service, and confirms `main` post-merge health continuously.
  - **Cons:** Adds one ~`40–75 s` run per merge to `main`.
  - **Effort:** ~2 hours.

## Checkboxes

- [x] Measured historical CI build/test duration trends and failure breakdown across 257 runs
  (`2026-11-21..2026-11-23`, `origin/main` `9b608f43`).
- [ ] `(decision needed)` Select Option O1-A1 vs O1-A2 (decouple `quality` + add PR `concurrency`).
- [ ] `(decision needed)` Select Option O1-B1 vs O1-B2 (`mise` 403 rate-limit elimination).
- [ ] `(decision needed)` Select Option O1-C1, O1-C2, or O1-C3 (`tools/ci/run.py` parallelism /
  `security.sh` sharding).
- [ ] `(decision needed)` Decide whether to adopt Option O1-D (`push` to `main` +
  `$GITHUB_STEP_SUMMARY` suite timings).
- [ ] Implement selected O1 optimizations after Gate 1 walkthrough review and record before/after
  hosted p50/p90 durations and 0% `mise` 403 rate across >=20 consecutive runs.
