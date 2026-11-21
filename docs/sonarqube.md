# SonarQube Cloud

[Development](development.md) · [PRD K](prds/prd_k.md#first-merge-gate--sonarqube-cloud)

## Project setup

The [SonarQube Cloud project](https://sonarcloud.io/dashboard?id=gorban_opencode-sandbox)
uses the OSS plan, organization key `gorban`, and project key `gorban_opencode-sandbox`.
For a new project, import the GitHub repository into the Sonar organization, install the
SonarQube Cloud GitHub App for the repository, and verify **Administration → Analysis Method**
shows automatic analysis. The app uses its GitHub installation to analyze the repository.
[Sonar GitHub setup](https://docs.sonarsource.com/sonarqube-cloud/getting-started/github)

Verify **Administration → New Code** and inspect the first analyses of `main`. Record
the analyzed commit, computed quality gate, and file scope. Sonar may need a second
analysis to compute the gate. Its PR gate evaluates new code relative to the target branch.
[Sonar quality gates](https://docs.sonarsource.com/sonarqube-cloud/standards/quality-gates)

## Local access with Codex MCP

Register the hosted MCP endpoint once in your local Codex configuration. Sign in with
read access to list projects, search findings, and read the quality gate.

```bash
codex mcp add sonarqube --url https://api.sonarcloud.io/mcp
codex mcp login sonarqube --scopes mcp:tools:read
```

Start a fresh Codex session and check `/mcp`. Ask for the quality gate or open issues
on `main` for `gorban_opencode-sandbox`. For a PR, give Codex the PR number so it can
read the PR analysis. If MCP reports **Insufficient scope**, repeat the login with
`mcp:tools:read` and start a fresh session. With OAuth, provide `gorban` as the
organization in tool calls that take it and leave the `SONARQUBE_ORG` header unset.
[Codex MCP setup](https://developers.openai.com/codex/mcp/) ·
[Sonar hosted MCP and OAuth scopes](https://docs.sonarsource.com/sonarqube-mcp-server/setup/sonarqube-cloud-hosted)

## PR findings and merge requirement

On a GitHub PR to `main`, open **Checks → SonarCloud Code Analysis → Details** to
reach the Sonar quality gate and issue list for that PR. Use the Sonar project's
**Issues** view with `main` selected for existing findings. The Sonar app publishes its
own check. The [GitHub Actions workflow](../.github/workflows/pr.yml) reports portable
tests and the mise-managed ShellCheck quality checks separately.
[Sonar PR analysis](https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/pull-request-analysis)

PRs to `main` will require a passing Sonar quality gate. Enforcement is pending
qualification. Verify the expected app reports on the current PR head and covers the
changed code, including the extensionless `oc-sandbox` launcher. GitHub can accept
neutral or skipped checks as satisfying a requirement. Follow [PRD K](prds/prd_k.md#first-merge-gate--sonarqube-cloud)
to qualify fail-closed behavior before enabling the required check in the `main` ruleset.
[GitHub required checks](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
