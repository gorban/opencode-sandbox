# Publish SonarCloud coverage from a trusted host

[SonarQube Cloud](sonarqube.md) · [PRD K](prds/prd_k.md#first-merge-gate--sonarqube-cloud)

The maintainer reviews an exact main or PR revision, then publishes from an
owner-controlled Linux checkout using rootless Podman. The first publisher
measures the bridge and controller Python cores. Sonar keeps its existing source
scope and quality gate. GitHub Actions continues running the advisory coverage
job without a Sonar token.

## Prepare and approve a revision

Use a logged-in Linux host terminal with Git, Python 3.11+, Podman, pasta and prlimit. Keep the
publisher checkout outside the sandbox home. Make sure it is clean and at the
reviewed publisher commit. For a PR, review its exact head, current main as
target, and any test changes that can influence coverage. Use the full SHAs in
the command. The PR can come from a fork.

Set the variables below to the reviewed values. The Bash function executes the
publisher directly from that Git commit. The publisher loads its other code and
config from the same commit.

```bash
trusted="$HOME/code/opencode-sandbox"
publisher_sha=FULL_REVIEWED_PUBLISHER_SHA
main_sha=FULL_CURRENT_MAIN_SHA

publish_coverage() (
  set -o pipefail
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
    /usr/bin/git --no-pager -C "$trusted" show "${publisher_sha}:tools/ci/sonar_publish.py" |
    /usr/bin/python3 -IB - --checkout "$trusted" --publisher "$publisher_sha" "$@"
)

publish_coverage --head "$main_sha" --prepare-only
```

To prepare an approved PR, use `--pr NUMBER --head FULL_PR_HEAD_SHA --base "$main_sha" --prepare-only`.
Preparation runs the two suites without network access or credentials and prints a
diagnostic report digest and counts. Publication measures again and accepts only its own
report. Maintainer review is part of admission because PR code and tests can influence
in-process coverage.

## Switch modes and publish

After external and human review, choose a quiet window with no other Sonar
publications or merges. Use a short-lived token for a Sonar analysis account with
only project Browse and Execute Analysis access. Keep it out of GitHub secrets,
shell variables, and files. Enter it at the hidden local prompt.

1. Switch off **Automatic Analysis** under **Administration → Analysis Method**.
2. Run `publish_coverage --head "$main_sha"`. Verify the published receipt has
   both measured files and the current main SHA. A computed failing main gate
   still records the imported baseline and returns exit 1. The publisher requires
   a fresh main receipt after a merge or change to the publisher or gate policy.
3. Run `publish_coverage --pr NUMBER --head FULL_PR_HEAD_SHA --base "$main_sha"`.
   Verify the published receipt and the SonarCloud Code Analysis check for that
   head. Only a computed 100% coverage result with a passing gate qualifies.
   If Sonar omits or waives coverage, the publisher refuses qualification. GitHub's
   native check may still report success for other conditions. The maintainer must
   check the publisher result before merging.
4. Confirm main and a real PR are covered during cutover. If either qualification
   fails, turn Automatic Analysis back on and revoke the temporary token. For
   later operations, rerun main after every merge and publish each reviewed PR
   head before merging. Revoke tokens after use.

[Analysis Method](https://sonarcloud.io/project/analysis_method?id=gorban_opencode-sandbox) ·
[SonarCloud analysis modes](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/ci-based-analysis/overview-of-integrated-cis)

The coverage container has a read-only snapshot and no writable host mount.
After it is removed, the publisher validates and rewrites its report. A separate
scanner receives a read-only source snapshot, trusted settings and the canonical
report. It receives the token through standard input. The publisher confirms the
scanner's exact Sonar task, revision and gate. It verifies imported counters on
main and on changed measured files Sonar indexes for a PR. The private main
receipt lives under `~/.local/state/oc-sandbox/sonar-publisher/`.
