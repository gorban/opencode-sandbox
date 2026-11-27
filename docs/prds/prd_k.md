# prd_k · Contributor checks and repository layout

[Index](README.md) · [Development](../development.md) · [Repository layout](../architecture.md)

## Initial proofs of concept

- [ ] Verify the PR-only workflow and shared local checks on the first hosted pull request.
  Portable tests run the explicit suite inventory with private scratch state and restricted Git
  configuration. Quality runs after tests on the same synthetic merge SHA. The stable
  `oc-sandbox / required` check requires both jobs to succeed. Record the observed check identity,
  checked SHA, tool versions and outcome before making that check required.
  Keep the real Podman and parallel host gates in [AGENTS.md](../../AGENTS.md#gates-before-a-commit-and-before-asking-for-review).
- [x] **Human approval of the local CI and documentation PoCs** (`start-ci` at `48b03a4`).
  This covers the portable suite, local quality checks, progressive README, task guides and
  repository map. Hosted qualification is tracked above.

### Review and evidence

- Design base `676dc65`. The README and layout PoC was cleared at design revision 1
  (SHA-256 `84877672af553aae60a4657b6d50b0754b61d1981755a4c9e936f3f2b148a807`).
  The portable CI PoC was cleared at revision 2
  (SHA-256 `892521349c33a0ae22aa0ed861f373ee01fff3463797165f654b346fa99ee289`).
  Revision 2 made Git fixture environment isolation explicit and left the hook consent and
  startup trigger for a later review.
- The reviewer also cleared the process-lifetime addendum at SHA-256
  `9ad82d51253d03731656249a8c367e872b197b5547826e97cdefe241d7f1ac10`. The runner verifies
  child exit before cleaning scratch, including after a timeout or interruption.
- The local portable run completed 13 suites. The stubbed security suite reported 132 passed
  and zero failed. The portable profile reports absent real host fixtures and unavailable remote
  acceptance as skips. The local quality run used ShellCheck 0.9.0 and checked five shell files
  and 20 Python files. Actionlint 1.7.12 passed on the workflow. Hosted qualification and ruleset
  setup are open. Record exact implementation review and hosted evidence in the pull request.

## Developer tool installation

- [x] **Human approval of the local mise toolchain slice** (`start-ci` at
  `66c8f837401cf402f42a8d29f71e132a57a77723`). The local runner installs from the mise
  lock and verifies ShellCheck `0.9.0`. All 11 toolchain tests passed, and a cold local
  install passed the quality checks. The Ubuntu runner version check passed in a local
  fixture. Verification on GitHub Actions remains open.

- [ ] Qualify the shared mise toolchain on the first hosted quality job. The local and hosted
  quality commands use the same development-scoped `mise.toml` and `mise.lock`, following
  [PRD F](prd_f.md). The initial pin is ShellCheck 0.9.0 on Linux x86-64. The command verifies a
  pinned mise release in isolated scratch, uses `mise install --locked`, then runs the same
  quality command through `mise exec`. The hosted job fails before setup if its system ShellCheck
  is missing or has a different version. Keep the Linux kernel, Bash, system Git, and system
  Python as platform prerequisites for portable fixtures. Provision developer tools only through
  the explicit quality command.

A Linux x86-64 scratch check used mise 2026.10.21 and `github:koalaman/shellcheck` 0.9.0.
The locked install kept the lockfile byte-identical and produced the same binary as the earlier
quality run. A deliberately changed checksum was rejected. The shared command passed a cold
local install and quality checks for five shell and 22 Python files. The hosted-mode probe failed
before downloading on a machine without `/usr/bin/shellcheck`. The reviewed toolchain design is
SHA-256 `7438fd62d8ccfdb25f80f2d70a82c95f039a68b60523d141472bd921698b25c9`.
The first hosted run should record its actual ShellCheck version and required check identity.

## First merge gate · SonarQube Cloud

- [ ] Qualify the existing SonarQube Cloud OSS project on a pull request to `main`. Use the
  installed GitHub App's automatic analysis and quality gate on new code. Keep this integration
  free of GitHub Actions secrets. Record the actual check name, publishing app, checked revision,
  project, PR, analyzed files and quality-gate result. Test relevant source that passes and fails,
  documentation-only and fork PRs, renamed and new extensionless source, and a newer PR revision.
  Verify handling of the base revision and a result superseded by a new analysis.
- [ ] Establish a trusted classifier before relying on the gate. Compare the complete tracked base
  and head trees, including both paths of renames and file deletions, under policy owned by the
  target branch or a separately trusted app. Treat Python, Shell, Actions, and analysis-policy
  changes as relevant, including extensionless source identified by mode, shebang or inventory.
  Unknown executable or shebang files, unclassified changes and incomplete inventory fail the
  classifier. Positively classify documentation-only changes through an explicit allowlist.
  Review any change to scanner scope or quality gate. Retained spike fixtures have their own scope.
- [ ] Require a computed passing result for the exact PR head from GitHub App ID `12526` and
  evidence that the scan covers the relevant changes. Neutral is acceptable only for a positively
  classified documentation-only change. GitHub itself accepts neutral and skipped required checks,
  so a missing, skipped, stale or uncomputed result on relevant changes is a qualification failure.
  If the native check cannot enforce the distinction, design and review a trusted companion
  verifier before activating the requirement. The verifier reads source metadata and analysis
  results as data and never runs the PR checkout with secrets or privileged credentials.
  Explicitly qualify the extensionless `oc-sandbox` launcher, which current Sonar results omit.
  Record existing ShellCheck coverage while Sonar scope is being qualified. Measure coverage
  locally and in CI because Sonar automatic analysis cannot import test coverage reports.
- [ ] After qualification, activate a GitHub branch ruleset targeting `main`. Require a pull
  request and the qualified check from its expected publishing app. Confirm failed and pending
  checks block merging. Qualify `oc-sandbox / required` separately before adding it to the rule.
  Keep other scanner jobs separate and advisory during their baselines.

The public GitHub check on `676dc65` is `SonarCloud Code Analysis`, published by
`sonarqubecloud` (GitHub App ID `12526`). It is neutral with “Quality Gate not computed.”
Sonar's public API reports `NONE` for the gate and indexes `oc_controller.py`; it has no
entry for `oc-sandbox`. No open PR targeting `main` or active branch rules were present
when inspected. This establishes the check identity and a scope gap. PR qualification is open.

- [x] Verify SonarCloud imports Python coverage and reports the native 100% new-code
  condition on a disposable PR. [PR #36](https://github.com/gorban/opencode-sandbox/pull/36)
  [failed at 96.6%](https://github.com/gorban/opencode-sandbox/runs/136951953225) and
  [passed at 100%](https://github.com/gorban/opencode-sandbox/runs/136953956343)
  over the same 29 lines. Coverage was the only failing condition. Tests ran without
  credentials, then a separate scanner published the report.
- [ ] Qualify the [maintainer-run coverage publisher](../sonar-publisher.md) on current
  `main` and a real PR to `main` during the attended analysis-mode switch. Record
  the exact analysis, App 12526 check and imported counters. Include a fork PR.
  Keep Automatic Analysis enabled until the publisher passes external and human review.

[Sonar GitHub analysis](https://docs.sonarsource.com/sonarqube-cloud/getting-started/github) ·
[Sonar coverage import](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/test-coverage/overview) ·
[GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets) ·
[Required-check behavior](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)

## Quality ratchet

[Coverage and scanner baselines](../ci-baselines.md) describes the first advisory jobs.

- [ ] Establish reproducible coverage for the two Python policy cores before enforcing per-core
  line or branch floors. Report subprocess and separate-interpreter exclusions. Measure shell
  behavior separately.
- [ ] Stage the local-first checks next. Baseline Ruff lint, formatting, selected security rules
  and C901 diagnostics, shfmt, fuller ShellCheck, actionlint, zizmor, and redacted Gitleaks CLI.
  Use the same pinned, checksum-verified tools and explicit source scopes locally and in CI.
  Run CI checks after the portable tests. Report findings during the baseline and surface
  scanner failures explicitly. Scope secret exceptions to the synthetic fixtures that need them.
  Track individual diagnostics and complex functions by file so removing one finding cannot
  mask a new one. Exercise behavior when extracting complex code. Add fast checks to hooks
  after exact Git snapshot qualification.
- [ ] Trial CodeQL advanced setup for Python on PRs to `main` to match the initial CI trigger.
  Confirm the pinned release supports workflow analysis and qualify it separately. Retain
  actionlint and zizmor for Actions coverage. Verify least-privilege permissions and completed
  SARIF upload for same-repo, fork and Dependabot PRs. A missing upload is an error or an
  explicitly unavailable result. Keep secrets out of contributor checkouts and do not use
  `pull_request_target` to run contributor code. Before declaring the baseline complete or
  requiring CodeQL, separately review and enable a default-branch analysis on trusted `main`
  and periodic refresh. The initial PR trial stays advisory.
- [ ] Enable the dependency graph and Dependabot alerts for supported dependencies. Assess Dependency Review
  when the graph has useful coverage, and add Dependabot update PRs for Actions and supported
  manifests. Consider Renovate for mise and image pins after checking for duplicate update
  PRs and reviewing lockfile updates. The offline Python cores use the standard library.
  Use focused local Semgrep rules if they add coverage for repository-specific trust boundaries.
  Add OSV-Scanner when resolved language lockfiles become part of a build or bootstrap.
  - [x] Dependabot alerts and security updates are enabled in the repository settings
        (2026-11-27). `.github/dependabot.yml` adds weekly version updates for the pinned
        Actions with a seven-day cooldown (`fix/launcher-isolated-host-python`).
  - [x] Qualify the first Dependabot update PR: the required checks run, the CodeQL upload
        completes, and the pinned commit and its version comment are both updated. PR #91
        (`actions/checkout` 6.0.2 to 7.0.1) passed all ten checks, including both CodeQL
        uploads, and changed the commit and the comment at all four uses.
  - [x] Scope Mend Renovate to what Dependabot cannot read: image references pinned by digest
        in the launcher, and the mise tools under `tools/ci`. `.github/renovate.json` turns off
        automerge, the dashboard issue and vulnerability pull requests, opens at most three
        pull requests in a weekly window, and waits seven days after a release. Registries that
        report no release date get a `no-release-age-check` label instead of the wait. A
        contract test in `tests/test_ci.py` holds those settings and checks that every
        digest-pinned launcher image is matched (`chore/renovate-gaps`).
  - [ ] Install the Mend Renovate app on this repository only, after the config is on `main`,
        and qualify its first pull request the same way as the Dependabot one.
  - [ ] Still refreshed by hand: the two digest-only Sonar images in
        `tools/ci/sonar_sandbox.py`, which have no tag for a bot to follow; the file hashes for
        the mise bootstrap, the coverage wheel and ShellCheck; and the web UI spike lockfile.
- [ ] Keep baseline scanners in jobs outside the merge requirement. A completed scan reports
  findings without blocking. A tool, config, input, inventory, database or upload failure fails
  its job. An expected scan that cannot run is an explicit error. Preserve raw finding counts
  and redacted diagnostics without using `continue-on-error` to hide scan failures.
  Review the baselines and agree on which new findings should block merging. Prioritize
  high-confidence secrets and unsafe workflow changes. Record scope and exceptions.

A local measurement at `676dc65` using its two existing offline suites, CPython 3.14 and Coverage.py
7.11.0 counted 320/323 bridge statements and 93/94 bridge branches, and 411/425 controller statements
and 121/136 controller branches. It covers those two modules in the test interpreter. A hosted
baseline and a required floor remain open.

## Image and runtime dependency inventory

- [ ] Render the agent and Chromium Containerfiles in an isolated build-only path. Evaluate
  Hadolint or Trivy config on that output. Exercise the existing host regressions for live Podman,
  SELinux, mounts, secrets and networking. A recipe check covers only the recipe inputs.
- [ ] Generate a Syft SBOM and run Grype against the exact image or OCI archive by digest.
  Cover the built agent and Chromium images, selected Podman and Postgres sidecars, and later
  warm image layers. Record target, platform, digest, scanner and database versions, and
  whether packages were inventoried. Verify representative Alpine and Fedora package coverage.
  Start with findings advisory. Review fix availability and each exception before gating
  publication. Surface stale databases, incomplete inventories and scanner errors distinctly.
  Package results do not certify the kernel, runtime configuration, mounts, secrets, networking
  or downloads after build.
- [ ] Inventory what is downloaded after image build, including the OpenCode updater and
  `chrome-devtools-mcp@latest`. Track the resolved version and artifact identity, and use
  supported lockfiles or artifact SBOMs where available. Document limits for user-selected
  tools or images and review proposed pin or update-policy changes before implementation.
- [ ] For releases and warm images, attach the SBOM and provenance to the exact published artifact.
  Plan a separately approved re-scan of published digests for new advisories. Keep publication,
  registry credentials and SSH credentials in trusted jobs that run reviewed code. The initial
  public PR checks accept fork contributions without those credentials. Any later fork-PR image
  trial keeps OCI archives, SBOMs and detailed reports in job-local scratch with no cache or upload.
  Review publication separately. Require bounded, sanitized contents, binding to the exact digest,
  explicit permissions and short retention for any future CI report artifact.

[Syft targets](https://oss.anchore.com/docs/guides/sbom/scan-targets/) ·
[Grype database](https://oss.anchore.com/docs/guides/vulnerability/database/) ·
[GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

## Exact Git snapshots and hook proof

- [ ] Qualify exact staged and committed snapshot selection before enabling a hook. Resolve Git's
  selected index, including partial commits and alternate indexes. Use a private index and object
  writes to establish the exact tree, then stream its bounded raw blobs for validation. Explicit
  commit mode must produce the same bytes for the same tree. Verify the selected index still
  identifies that tree on success. Test staged and working-file divergence in both directions,
  staged checker/config changes, additions, modes, deletion/rename, intent-to-add, path-limited
  commits, `-a`, unborn HEAD, conflicts and unusual names. Reject unsupported modes, untrusted Git
  indirection and implicit fetching. Qualify read-only input and a private scratch area for tools
  isolated from network and host repository access, keys and sockets.
- [ ] Qualify the installation and write boundary separately. Prove launcher source and Git admin
  paths, ownership and mount origin before invoking Git. Discover only the direct `.git` of the
  verified source and test linked worktree backlinks and shared hooks. Include ZIP files extracted
  within another repo and launches from untrusted working directories. Test atomic publication
  and updates without clobbering existing or edited hooks and preserve custom or disabled
  `core.hooksPath`. Agree on consent and the installation trigger before enabling launcher-side
  writes. Keep ordinary startup free of checks and tool installation.

## Remote acceptance

- [ ] Establish an independently approved SSH test in a trusted workflow with pinned host keys,
  scoped short-lived credentials and disposable workers. Require positive evidence that an optional
  fixture is unconfigured before reporting a skip. Once enabled, unexpected absence, malformed
  config, authentication or engine errors, assertion failures, timeouts and incomplete cleanup
  fail the check. Keep remote credentials and jobs outside the PR workflow.
- [ ] Reserve the local-only remote SSH target configuration file at
  `~/.config/oc-sandbox/remote-ssh.env` (and optional named profiles at
  `~/.config/oc-sandbox/remote-ssh.<NAME>.env`, with `<NAME>` restricted to
  `[a-z0-9][a-z0-9._-]*`). Keep it mode `0600`, user-owned, outside Git repositories and outside
  `~/opencode-sandbox`. Parse plain `KEY=VALUE` lines without shell `eval` or command substitution,
  and never export its values into agent containers.
- [ ] Support automated single-process SSH agent management (`OC_SSH_AGENT_MODE=keeper` in addition
  to `env`) so local acceptance runs do not require manually juggling two terminals. Spawn
  `keeper --config <OC_SSH_KEEPER_CONFIG> ssh-agent start` under a private PTY with `umask 077`,
  capture `SSH_AUTH_SOCK` without logging Keeper output or SSH key identities, verify a loaded key
  with `ssh-add -l >/dev/null`, run SSH with hardened flags, and shut down Keeper cleanly (`q\n`
  with verified exit) on completion or error. Detect expired/logged-out Keeper sessions within a
  bounded timeout and report actionable re-authentication steps instead of hanging.
- [ ] Add an OS-aware preflight and setup helper to remote and parallel host acceptance runners
  (including `tests/parallel-isolated.py --run` and future SSH/Tailcat e2e tests). When a run is
  attempted without valid configuration or prerequisites, report exactly what is missing and print
  copy-paste remediation for the detected target OS (creating `remote-ssh.env`, pinning host keys,
  re-authenticating Keeper, layering missing packages on Fedora CoreOS vs `dnf` on Fedora,
  installing `oc_chromium.cil`, or pointing to a clean account/VM when the local workstation holds
  managed provider config).

### Reserved `remote-ssh.env` variables and hardened SSH contract

| Variable | Purpose | Example placeholder |
|---|---|---|
| `OC_SSH_TARGET` | SSH `user@host` endpoint | `worker@build-host.example` |
| `OC_SSH_PORT` | SSH TCP port (default `22`) | `22` |
| `OC_SSH_KNOWN_HOSTS` | Pinned host-keys file (default `~/.ssh/known_hosts`) | `/home/alice/.ssh/known_hosts` |
| `OC_SSH_PODMAN_BIN` | Absolute path to `podman` on the SSH target | `/opt/podman/bin/podman` |
| `OC_SSH_PODMAN_MACHINE` | Optional Podman Machine VM name (omit on direct Linux hosts) | `podman-machine-default` |
| `OC_SSH_AGENT_MODE` | `env` (existing `SSH_AUTH_SOCK`) or `keeper` (managed PTY) | `keeper` |
| `OC_SSH_KEEPER_BIN` | Absolute path to `keeper` CLI (`OC_SSH_AGENT_MODE=keeper`) | `/path/to/keeper-env/bin/keeper` |
| `OC_SSH_KEEPER_CONFIG` | Absolute path to Keeper config JSON (`OC_SSH_AGENT_MODE=keeper`) | `/home/alice/.keeper/config.json` |

All automated SSH invocations must pass `-F /dev/null`, `-o IdentityAgent=SSH_AUTH_SOCK`,
`-o IdentityFile=none`, `-o BatchMode=yes`, `-o PreferredAuthentications=publickey`,
`-o ForwardAgent=no`, `-o ClearAllForwardings=yes`, `-o StrictHostKeyChecking=yes`,
`-o UserKnownHostsFile=<OC_SSH_KNOWN_HOSTS>`, and `-p <OC_SSH_PORT>`. Missing or changed host keys
fail closed without `accept-new`.

### SELinux-enforcing remote test host prerequisites

Full host acceptance (`tests/security.sh`, `tests/parallel.sh`, and legacy
`tests/parallel-isolated.py --run`) requires a Linux target running **rootless Podman** with
**SELinux enforcing**, plus:

- `python3` (with `libselinux.so.1` accessible and `os.pidfd_open`), `script` (`util-linux-script`),
  `bash`, `git`, `curl`, and `sha256sum`
- `semodule` and `/usr/share/udica/templates` (`base_container.cil`, etc.)
- The `oc_chromium.cil` policy module loaded once via `sudo semodule -i`
- A clean account home (no `~/.config/oc-sandbox/{providers.toml,openai}`) when exercising legacy
  `tests/parallel-isolated.py --run`

On macOS remote hosts, **Podman Machine** provides a Fedora CoreOS VM with rootless Podman,
SELinux enforcing, `semodule`, and `/usr/share/udica/templates` already present (unlike Colima or
OrbStack, which run non-SELinux Linux VMs). On Fedora CoreOS, layer missing tools with
`sudo rpm-ostree install python3 util-linux-script` (followed by a VM restart or `--apply-live`)
and install `oc_chromium.cil` once. Preflight diagnostics should detect the remote OS
(`/etc/os-release`), `getenforce`, Podman rootless/SELinux status, missing tools, and missing
policy modules, and print the exact commands needed to bring the target up to spec.

## Later runtime layout

- [ ] Qualify separate moves to `runtime/host/` for deployed host helpers,
  `runtime/container/` for agent image helpers and `src/oc_sandbox/` for offline policy.
  Preserve root launch and symlink behavior, source markers, helper and image lookup, and test
  fixture behavior on each move. Run rootless host acceptance for affected runtime pieces.
  Group tests by fixture type when it makes them easier to find.

- [ ] **Human review**: checked only when the user says so
