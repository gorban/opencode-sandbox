# prd_o3 · Deterministic content-hashed GitHub Actions caching

Parent: [prd_o](prd_o.md) · [Index](README.md) · related:
[prd_f](prd_f.md), [prd_k](prd_k.md), [prd_o1](prd_o1.md), [prd_o2](prd_o2.md)

## Current baseline and burst economics

`gh api repos/gorban/opencode-sandbox/actions/caches` reports **`total_count: 0`, `total_bytes: 0`**
on `origin/main` (`9b608f43`). Every workflow run currently fetches all external dependencies cold:

| Dependency / Artifact | Where Pulled Today | Approx. Size | Current Pain |
|---|---|---:|---|
| `mise-v2026.10.21-linux-x64.tar.xz` | `tools/ci/toolchain.py` (every `oc-sandbox PR / quality` run) | `<= 64 MiB` cap (`175 MB` extracted) | Repeated download + extraction every PR push |
| `shellcheck-v0.9.0.linux.x86_64.tar.xz` | `mise install --locked` in `quality` | `~2 MiB` | Triggers unauthenticated GitHub API `403` attestation failure on **`~16%`** of runs ([prd_o1](prd_o1.md)) |
| `coverage-7.11.0-py3-none-any.whl` | `tools/ci/core_coverage.py` (every `oc-sandbox baselines` run) | `< 1 MiB` | Repeated PyPI network call + fresh `venv` creation |
| Upcoming: Web UI `npm` tarballs (`docs/prds/spikes/m/web-ui/package-lock.json`) | Tier 0B Web UI job ([prd_o2](prd_o2.md)) | `~60–120 MiB` (`npm` cache) | Uncached `npm ci` adds `~25–60 s` per PR push |
| Upcoming: Additional pinned linters/tools (`actionlint`, `ruff`, `shfmt`, `syft`, `grype`) | [prd_k](prd_k.md) toolchain expansion | `~50–150 MiB` | Compounds download time & rate-limit exposure if uncached |
| Upcoming: Tier 1 OCI base layers / Podman images | Tier 1 container integration ([prd_o2](prd_o2.md)) | `~200–800 MiB` | Largest potential time sink (`30–120 s+` cold) and largest quota consumer |

### GitHub Actions cache platform constraints

- **Repository quota:** **`10 GB`** total active cache storage per repository (entries beyond 10 GB
  are evicted LRU).
- **Idle timeout (TTL):** Unused cache entries expire after **7 days**; every cache hit refreshes
  last-accessed time.
- **Burst benefit:** During rapid multi-PR / multi-commit review bursts (e.g., **50+ runs within
  14 hours** observed during PRs #57–#64), a warm cache stays continuously hot well inside the
  7-day TTL and converts repeated network pulls into local Azure-blob restores (`~1–3 s`) with zero
  upstream rate-limit hits.
- **Branch-scoping isolation:** GitHub Actions scopes caches by branch ref:
  - A workflow on `main` writes to `main`'s scope.
  - A PR branch can **read** from its own branch, its base branch, and the default branch (`main`),
    and can write **only** to its own branch scope (never overwriting `main` or sibling PRs).
  - Fork PRs can read `main`'s cache but cannot write to the base repository's cache.

## Content-hashed cache key design

To satisfy the maintainer's goal—*keying caches strictly by the exact list of packages/dependencies
being pulled*—every cache entry uses an immutable, content-addressed key derived from the canonical
pinned dependency list (name + exact version + cryptographic hash):

```text
oc-cache-v1-<runner.os>-<arch>-<scope>-<sha256-of-exact-dependency-manifest>
```

| Scope | Manifest / Exact Dependency List Hashed | Cached Payload | Post-Restore Verification Before Use | Est. Size |
|---|---|---|---|---:|
| `ci-toolchain` | `hashFiles('tools/ci/mise.toml', 'tools/ci/mise.lock', 'tools/ci/toolchain.py')` *(note: `toolchain.py` imports `SHELLCHECK_VERSION` from `run.py`, while `mise.toml`/`mise.lock` also pin `0.9.0`, so omitting `run.py` busts on version bumps without busting on unrelated `run.py` edits)* | Downloaded verified archives (`mise` tarball + locked tool tarballs) in read-only cache dir | Pre-validate exact filenames (`O_NOFOLLOW`, regular file, size cap), re-verify `MISE_ARCHIVE_SHA`, `MISE_BINARY_SHA`, and every `mise.lock` `sha256:` before extracting or executing | `~70–180 MiB` |
| `py-wheels` | `py<minor>` + `hashFiles('tools/ci/wheels.lock.txt')` *(new tracked canonical sorted `pkg==ver --hash=sha256:...` lockfile replacing/mirroring `WHEEL`/`WHEEL_HASH` in `tools/ci/core_coverage.py`; include Python minor/ABI tag before adding any C-extension wheel)* | Raw `.whl` files only (never pre-built `venv`s with absolute paths) | Pre-validate exact allowlisted filenames with `O_NOFOLLOW`, regular-file, size-cap, and SHA-256 checks (`bounded_regular`), copy only verified wheels into private `0o700` scratch, then run `pip install --isolated --no-index --find-links <private-verified-dir> --no-deps --require-hashes --only-binary=:all:` | `~5–40 MiB` |
| `web-ui-npm` | `node24.18.0-` + `hashFiles('docs/prds/spikes/m/web-ui/package-lock.json')` *(at `9b608f43`, all 223 locked packages carry SRI `integrity` digests and the only `hasInstallScript` package is optional macOS `fsevents`)* | Isolated npm tarball cache (`--cache <private-dir>`, **never** `~/.npm` alongside `.npmrc` and **never** mutable `node_modules`) | With `NPM_CONFIG_USERCONFIG=/dev/null` and `NPM_CONFIG_GLOBALCONFIG=/dev/null`, run `npm ci --ignore-scripts --cache <private-dir> --offline` on `cache-hit == 'true'` (or `--prefer-offline` on cold miss), verifying every package SRI digest against `package-lock.json` | `~60–120 MiB` |
| `tier1-oci` *(optional, Tier 1 only)* | Canonical manifest hash of pinned base image digest + Containerfile + explicit sorted package list (`tools/ci/container-deps.manifest`) | OCI image/layer tarballs or Buildx cache | Verify exact raw archive/blob `sha256:` digest **before** `podman load` parses any untrusted tar stream (never relying on post-load `podman image inspect`) | `<= 1.5 GiB` |

### Why caching raw verified archives/wheels beats caching extracted trees

1. **Deterministic hash verification:** Verifying `sha256` over a single `.tar.xz` or `.whl` file
   takes milliseconds and detects single-bit tampering, whereas verifying thousands of extracted
   files in `node_modules/` or a Python `venv/` is slow and fragile.
2. **Smaller cache footprint & faster transfer:** Compressed tarballs and wheels are 2–4x smaller
   than extracted binaries (`mise` binary is `175 MB` extracted vs `<= 64 MiB` `ARCHIVE_LIMIT`
   compressed), keeping cache restores fast (`1–2 s`) and total storage far below the `10 GB` quota.
3. **Zero path-relocation bugs:** Extracted Python `venv` shebangs embed `/tmp/oc-ci-XXXXXX`
   scratch paths that break across runs; cached raw `.whl` files install cleanly into any fresh
   private scratch `venv` in `~1 s` with `--no-index --require-hashes`.

## Zero-trust cache security model

GitHub Actions caches are **untrusted acceleration storage**, never a security boundary:

1. **Exact-key match only (no `restore-keys` prefix fallback):**
   - For `ci-toolchain`, `py-wheels`, and `web-ui-npm`, **omit `restore-keys`** completely.
   - If the exact dependency list changes (even by one package or version), the key misses cleanly,
     fetches the exact new pinned artifact set, verifies its checksums, and populates the new key.
   - This eliminates cross-version stale-cache pollution and prevents loose-prefix cache poisoning.
2. **Mandatory fail-closed SHA-256 verification on every cache hit:**
   - Every consumer script (`tools/ci/toolchain.py`, `tools/ci/core_coverage.py`, `npm ci`) verifies
     the restored artifact's SHA-256/SRI digest (plus `O_NOFOLLOW`, regular-file, and size-cap
     checks) against the repository's tracked lockfile before executing a single instruction.
   - On any digest mismatch, symlink, non-regular file, or oversized cache entry on a cache hit:
     **fail closed by default** (especially on `main` and in regression tests) with a clear
     tamper/corruption error rather than silently falling back to network and masking cache
     poisoning or corruption.
3. **Zero cache in Tier 2 (secret-bearing) workflows:**
   - Tier 2 live inference jobs ([prd_o2](prd_o2.md)) must never call `actions/cache`,
     `actions/cache/restore`, or `actions/cache/save`.
4. **Pinned action commit SHAs & minimal permissions:**
   - Pin `actions/cache/restore@<40-hex-sha>` and `actions/cache/save@<40-hex-sha>` (exact commit
     SHAs, never floating `@v4` tags), running under `permissions: { contents: read }`.
5. **Quota budget & anti-eviction discipline (`<= 3 GB` target of `10 GB` limit):**
   - Keep `ci-toolchain + py-wheels + web-ui-npm` under `~350 MiB` total per active manifest version
     so hot Tier 0 caches are never evicted by large Tier 1 container caches.
   - Enforce a hard size budget on optional Tier 1 OCI caches (`<= 1.5 GiB` total). Note that
     deleting PR caches via GitHub API on `pull_request: [closed]` requires
     `permissions: { actions: write }`, which must **never** be granted to any workflow checking
     out PR code (requiring a separate zero-checkout cleanup workflow) — reinforcing Option O3-A's
     read-only PR restore model where PRs create no persistent caches to clean up.

## Cache scoping and seeding options

### Option O3-A (Recommended): `main`-seeded warm cache + read-only verified restore on PRs

- **`push` to `main` (and `workflow_dispatch` on `main` only):** Runs `actions/cache/restore` ->
  verifies or fetches pinned artifacts into a clean staging directory -> runs `actions/cache/save`
  **strictly gated on**
  `(github.event_name == 'push' || github.event_name == 'workflow_dispatch') && github.ref == 'refs/heads/main' && steps.restore.outputs.cache-hit != 'true'`,
  with `actions/checkout` pinned to `ref: ${{ github.sha }}` (zero custom ref inputs) and saving
  only from a clean staging directory populated solely by SHA-256-verified downloads.
- **`pull_request` (same-repo and forks):** Runs **`actions/cache/restore` ONLY** (read-only against
  `main`'s warm cache), verifies SHA-256 on hit, and performs a verified cold fetch if the PR
  modifies a dependency manifest.
- **Pros:**
  - Near-100% cache hit rate across rapid multi-PR bursts (like PRs #57–#64, which all shared the
    exact same `mise.lock` and `coverage` wheel!).
  - **Zero PR cache-eviction / LRU-flooding risk** (10 concurrent PRs cannot churn the `10 GB` quota
    with 10 duplicate copies of the same cache!).
  - Cleanest security posture: only reviewed code merged to `main` writes persistent caches.
- **Cons:** A PR that *modifies* `mise.lock` or `package-lock.json` fetches cold on each push to
  that PR until merged to `main` (rare, and acceptable for dependency-bump PRs).
- **Effort:** ~0.5–1 day (paired with [prd_o1](prd_o1.md) Option O1-B1).

### Option O3-B: Standard read+write `actions/cache` on every PR branch and `main`

- Every PR branch restores from `main` (or itself) and saves a branch-scoped cache on miss.
- **Pros:** Dependency-bump PRs also get cache hits on their 2nd+ push before merge; single action
  step instead of `restore`/`save` split.
- **Cons:** Rapidly opened dependency-bump PRs can duplicate caches across branch scopes, consuming
  more of the `10 GB` quota until PR branches are deleted or 7-day idle TTL expires.
- **Effort:** ~0.5 day.

### Option O3-C: Pre-built pinned CI toolchain container image in GHCR (digest-pinned)

- Build a minimal CI tools container image on `main` (containing pinned `mise`, `shellcheck`,
  `coverage`, future `ruff`/`actionlint`) and publish to GHCR by immutable `sha256:` digest.
- **Pros:** Zero `actions/cache` dependency and zero per-run archive extraction; completely immune to
  upstream release-asset outages and 7-day cache TTL expiration.
- **Cons:** Requires GHCR package write permissions on `main`, a container build/publish workflow,
  SBOM/attestation maintenance ([prd_k](prd_k.md)), and Docker pull time (`~5–15 s`) on runners.
- **Effort:** ~2–3 days.

## Checkboxes

- [x] Verified current repository GitHub Actions cache usage (`0` entries, `0` bytes) and mapped all
  current and upcoming CI dependency pulls.
- [ ] `(decision needed)` Select Option O3-A (`main`-seeded warm cache + read-only PR restore),
  Option O3-B (read+write per PR branch), or Option O3-C (digest-pinned GHCR CI toolchain image).
- [ ] `(decision needed)` Confirm the canonical manifest-hashed key format
  (`oc-cache-v1-<os>-<arch>-<scope>-<manifest-sha256>`) with exact-key-only restore (no
  `restore-keys` fallback) and mandatory post-restore SHA-256 verification.
- [ ] `(decision needed)` Decide whether to include optional Tier 1 OCI layer caching (with hard
  `<= 1.5 GiB` cap) after the Tier 1 Podman feasibility spike ([prd_o2](prd_o2.md)).
- [ ] Implement selected caching slice after Gate 1 walkthrough review, verifying (1) exact hit on
  unchanged manifest, (2) clean miss + rebuild when a single package/version changes, (3) fail-closed
  rejection on a corrupted cached archive, and (4) `0%` `mise` 403 rate across burst runs.
