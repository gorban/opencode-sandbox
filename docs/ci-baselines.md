# Coverage and security baselines

The [baseline workflow](../.github/workflows/ci-baselines.yml) runs on pull requests to `main`.
Its CodeQL job also runs on every push to `main` and once a week. The coverage and Dependency
Review jobs are advisory, and their failures stay visible for triage. CodeQL results are
[required to merge](#codeql-merge-requirement).

## Python coverage

Run `python3 -IB tools/ci/core_coverage.py` from the repository with Python 3, venv support,
and network access to the pinned Coverage.py wheel. The command runs both offline unittest
suites and reports covered and total statements and branches for `oc_bridge_merge.py` and
`oc_controller.py`. It verifies repository-relative paths in the XML before discarding
the private scratch reports. Shell scripts, subprocesses, and separately launched
interpreters are outside this measurement.
Compare counts from the same Python version because the set of traced statements can vary.

SonarQube Cloud automatic analysis continues to report the required zero-new-issues gate.
It cannot import [coverage reports](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/test-coverage/overview).
This baseline gives CI and local coverage counts. A required floor and a safe way to
publish coverage have separate qualification. See [the trusted publisher](sonar-publisher.md)
for the attended import and its scope.

## CodeQL merge requirement

Since 2026-11-27 the `main` ruleset requires code scanning results from CodeQL. A pull request
cannot merge while its CodeQL analysis is running or missing, or when it adds a security alert
rated high or critical or any other alert at error level. Warnings, notes, and medium or low
security alerts do not block. The thresholds live in the ruleset, not in this repository.

GitHub finds the alerts a pull request adds by comparing its analysis with the one for `main`.
The same job therefore scans three things:

| Event | Commit scanned | Purpose |
|---|---|---|
| Pull request to `main` | synthetic merge commit | results for the ruleset |
| Push to `main` | the pushed commit | the trusted result pull requests are compared with |
| Weekly schedule | tip of `main` | unchanged code against the queries in the pinned CodeQL release |

Keep the three in one workflow file and job, with the same categories. Code scanning matches a
pull request's results to `main`'s by workflow path, job and category, so a separate workflow
would leave pull requests without a matching result. Runs on `main` are never cancelled.
Do not add `paths` filters: a skipped scan gives the rule no result to evaluate.

Open items:

- SARIF upload is unqualified for fork pull requests. Their token is read-only, and a failed
  upload now blocks the merge. Dependabot's pull request upload completed for both categories
  on [PR 91](https://github.com/gorban/opencode-sandbox/pull/91).
- Merge Dependabot pull requests with a merge commit. GitHub
  [documents](https://docs.github.com/en/code-security/code-scanning/troubleshooting-code-scanning/resource-not-accessible)
  that a squash-merge commit is authored by Dependabot, so its push run on `main` gets a
  read-only token and cannot upload. The repository settings allow merge commits only; keep
  squash merging off. Re-running such a run keeps the read-only token. The next merge or the
  weekly run restores the `main` result.
- The first push and scheduled runs on `main` have not been observed yet. Confirm both
  categories appear for `refs/heads/main` under the repository's code scanning tool status.
- A failed run on `main` leaves the previous analysis in place. Re-run the failed job.
- GitHub disables scheduled workflows in a public repository after 60 days without activity.
  The next push to `main` still scans; re-enable the workflow to restore the weekly refresh.

## CodeQL and dependency review

- **CodeQL** scans Python and GitHub Actions without building the project. Check the two job
  logs and GitHub code scanning results.
- **Dependency Review** compares the GitHub dependency graph for the PR's base and head.
  The job fails if GitHub reports a new high or critical dependency advisory. Check the job
  summary even when the graph has no changes. Mise tools, direct runtime downloads, and packages
  installed in images need separate inventory and scanning.
- **Dependabot version updates** propose new commits for the pinned Actions each week, once a
  release is seven days old. Review the upstream changes between the two commits before merging.
  Dependabot security updates are a repository setting and are not delayed.
- **Renovate** (`.github/renovate.json`) proposes updates only for image references pinned by
  digest in the launcher and for the mise tools under `tools/ci`. It opens no dashboard issue
  or vulnerability pull requests and never merges. The seven-day cooldown on Docker Hub uses
  the tag's last-pushed timestamp. A pull request labelled `no-release-age-check` can lack a
  release timestamp. Check its age yourself, or leave it open for a week before merging.
  For a `needs-checksum-update` PR, update the checksums in `tools/ci/mise.lock` and
  `tools/ci/toolchain.py` manually. Renovate skips mise artifact updates.
