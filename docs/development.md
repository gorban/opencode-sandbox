# Development

## Tests

From the repository root, run the portable tests before the quality checks.

```bash
python3 -B tools/ci/run.py tests
python3 -B tools/ci/toolchain.py
```

These commands read the working files, including unstaged edits. The runner uses system Python
3.11 or later, Bash, Git and standard Linux utilities. Its child cleanup requires Linux
subreaper and pidfd support. The system Git must support
`git worktree add --relative-paths`. The [suite inventory](../tools/ci/run.py) includes the
offline policy cores, launcher and host-state regressions, worktree fixtures, Postgres
stubs, parallel-runner mocks and source audit, security stubs, and the CI runner's own tests. Each
suite gets private temporary home, XDG and scratch directories and a restricted environment.
Missing required tools or files, a missing or empty required unittest result, timeouts and test
failures all fail the suite. The runner stops on interruption and retains scratch if it cannot
verify that the suite's children exited.

Quality uses Bash syntax checks, in-memory Python compilation, and ShellCheck at error severity.
The toolchain command requires Linux x86-64, `curl`, and internet access. It verifies a pinned mise
release and installs **ShellCheck 0.9.0** from the [shared lockfile](../tools/ci/mise.lock) in
private scratch. It then runs the shared checks through mise. The command uses a fresh toolchain
for each run. The launcher and the portable test command have their existing platform prerequisites.
The quality checker covers active runtime, tests and CI tool sources. Retained probes and source
text embedded in test fixtures are outside the top-level lint scope.

The portable run reports real Podman security, real Postgres, and SELinux/Wayland acceptance as
skipped because it has no configured isolated fixtures. Remote acceptance is unavailable in this
profile. Missing tools in the required portable suite fail the check.

### Real host gates

[AGENTS.md](../AGENTS.md#gates-before-a-commit-and-before-asking-for-review) requires changed-shell
syntax checks, `git diff --check`, and the real Podman security suite before a feature commit or
review. Run `bash tests/security.sh` with `OC_TEST_NO_PODMAN` unset. Record its pass/fail count and
confirm the **sandbox tree, worktrees and relabelling** and **image ownership** sections both ran
without skips. A missing or unavailable Podman engine or test agent image leaves the gate
incomplete even if the script exits zero. Changes to instances, pods, ports, Postgres or sidecars
also require the real parallel test via its isolated runner. For a review finding, verify the
regression test against the previous launcher in a scratch copy using the prescribed stubs before
testing the fix.

- `tests/security.sh` runs adversarial regression tests for the host-side code in a temporary directory:
  symlinked and concurrently swapped directories against the bridge, the sandbox-tree container, worktree
  creation and relabelling; FIFO requests; planted git hooks; `postgres.env` parsing; password exposure in
  output, argv and child environments; and argument validation (ports, instance names, paths). The
  container tests need Podman and the `oc-agent` image; `OC_TEST_NO_PODMAN=1` skips them.
  `OC_TEST_AGENT_IMAGE=FULL_IMAGE_ID` can select a test-owned image containing Python and Git instead.
- `tests/postgres-host.sh` checks publication, secret handling and legacy failure paths with Podman
  stubbed. `tests/postgres-host-real.py` uses isolated, test-owned Podman resources and locally available
  Postgres 17 and Python Alpine images to check SCRAM, existing volumes and host authentication; run it
  only when no other test is using the shared Podman host.
- `python3 tests/parallel-isolated.py --run` runs the full real-host acceptance suite with headless
  Chromium. It verifies two concurrent agents and worktrees, per-instance DevTools navigation,
  loopback port mapping and isolation, Postgres, docker-in-docker, and instance removal. The suite
  uses the installed SELinux policy, a private Podman store and sandbox home, and synthetic
  credentials. It stubs user systemd and runs without the desktop display or physical security keys.
- `python3 tests/parallel-isolated.py --run --wayland` opens one visible Chromium window to verify
  the desktop Wayland connection and the named DevTools tab. Use this hand-run smoke test when
  changing desktop integration. The runner cleans up its private browser and store.

Direct execution of `tests/parallel.sh` is refused. Without `--run`, the runner only audits its sources.
An interrupted distrobox run retains both private directories if remote processes cannot be verified stopped.

## GitHub pull-request checks

[The workflow](../.github/workflows/pr.yml) runs on pull requests targeting `main`. It checks the exact
synthetic merge SHA from the event. The stable `oc-sandbox / required` job succeeds only if both
portable tests and quality succeed. The maintainer verifies the tested SHA and exact observed
GitHub Actions check identity on an actual PR before selecting it in the ruleset. Enable the
up-to-date branch requirement when the ruleset must enforce validation against the latest base
commit. The hosted quality job checks `/usr/bin/shellcheck` before provisioning the locked
toolchain. If the runner copy is missing or has a different version, the job reports the expected
and observed version and fails. Review the tool version, lockfile and policy together when
updating the pin. Verify the observed versions and check identity on the first hosted run.

[Set up SonarQube Cloud and Codex MCP, find PR issues, and qualify the required check.](sonarqube.md)
[Run local Python coverage and understand the advisory security scans.](ci-baselines.md)

CI workflow, runner and policy changes require human review. Changes that install or update tools,
write hooks or Git state, or enable remote acceptance need separate approval. The
[future hook plan](prds/prd_k.md#exact-git-snapshots-and-hook-proof) would check the exact content
selected for the commit by Git. The local commands above check working files when explicitly run.
