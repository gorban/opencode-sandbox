# Coverage and security baselines

The [baseline workflow](../.github/workflows/ci-baselines.yml) runs on pull requests to `main`.
Its jobs are advisory. Job failures stay visible for triage.

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

## CodeQL and dependency review

- **CodeQL** scans Python and GitHub Actions on the synthetic PR merge commit without building
  the project. Check the two job logs and GitHub code scanning results. Qualify SARIF processing
  for fork and Dependabot PRs and establish a trusted `main` baseline before requiring it.
- **Dependency Review** compares the GitHub dependency graph for the PR's base and head.
  The job fails if GitHub reports a new high or critical dependency advisory. Check the job
  summary even when the graph has no changes. Mise tools, direct runtime downloads, and packages
  installed in images need separate inventory and scanning.
- **Dependabot version updates** propose new commits for the pinned Actions each week, once a
  release is seven days old. Review the upstream changes between the two commits before merging.
  Dependabot security updates are a repository setting and are not delayed.
- **Renovate** (`.github/renovate.json`) proposes updates only for image references pinned by
  digest in the launcher and for the mise tools under `tools/ci`. It is configured never to merge, and opens no
  dashboard issue and no vulnerability pull requests. A pull request labelled
  `no-release-age-check` comes from a registry that reports no release date, so leave it open for
  a week before merging. One labelled `needs-checksum-update` also needs new checksums in
  `tools/ci/mise.lock` and `tools/ci/toolchain.py` before its checks can pass.
