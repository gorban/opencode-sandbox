# AGENTS.md: how work is organised in this repository

Read this before changing anything here. `README.md` covers how to use the tool. This file covers how
work is planned, gated, reviewed and merged.

## Where things live

| Path | What |
|---|---|
| `~/oc-sandbox` | This checkout: planning and feature work. |
| `~/code/opencode-sandbox` | The checkout the installed `oc-sandbox` runs from (`~/.local/bin/oc-sandbox` links to it). Keep it on `main`. |
| `~/opencode-sandbox` | The **sandbox home** mounted into every agent (`/sandbox`). Agent-writable, so treat it as hostile. Never keep this repository or any host state in it. |
| `docs/prds/` | Plans, issues, ideas and retained spike findings. See below. |

## Branches

- `main` is what has been reviewed and merged. Never commit or push to it directly.
- Planning and spike findings go through reviewed documentation PRs to `main`. The `ideas` branch may
  be used for optional drafts when useful; it is not a required staging branch, and work need not be
  merged through it. Update PRD checkboxes in the PR that records the work.
- **Spike branches** answer feasibility questions with throwaway probes. Start from current `main`, or
  use an optional planning branch when appropriate. Their lasting output is findings in the PRD
  (results, decision and checkboxes) and useful probes under `docs/prds/spikes/`. A spike does not
  change `oc-sandbox`, `oc-bridge.py` or production tests. Submit findings and probes in a reviewed
  documentation PR to `main`. Probes clean up every pod, container and image they create. Production
  code based on a spike starts fresh from current `main` in a separate feature PR.
- **Feature branches** are made from the latest `main`, one reviewable change each:
  ```bash
  git fetch --prune origin && git switch main && git merge --ff-only origin/main
  git switch -c <short-topic>
  ```
- After a feature branch is merged upstream: fast-forward `main`, delete the local branch (`git branch -d`,
  which refuses unmerged work), and start the next change from `main` again. Do not keep stacking on a
  merged branch.

## Gates before a commit, and before asking for review

Commit and push only when the user has asked for that work. Pushing a feature branch for review is
part of "implement X and get it reviewed". Every commit on a feature branch must pass:

1. `bash -n` on the changed scripts, and `git diff --check`.
2. `tests/security.sh` with real Podman (not only `OC_TEST_NO_PODMAN=1`); report the pass/fail count.
3. `tests/parallel.sh` (real host: pods, Chromium, Postgres, docker-in-docker) when instance, pod, port,
   Postgres or sidecar code changes.
4. For every review finding, a regression test that **fails on the previous commit and passes on the new
   one**. Check the old commit by running the new tests against `git show HEAD:oc-sandbox` in a scratch
   copy, with Podman stubbed.

Commit messages say what was wrong and why the fix is right, not only what changed. Fix review findings
as new commits on the same branch. Don't rewrite history that a reviewer has already seen.

## External adversarial review

Every feature branch waits for an external, security-focused adversarial review before it is merged,
ideally at the level of the user's Daybreak Blue reviewer (Mythos / Cyber-level). The loop:

1. Push the branch. Tell the user the branch and commit, and that it is ready for review.
2. The user pastes findings (P1/P2…). Treat them as claims to verify, not orders: reproduce each one,
   fix it at the root (look for the same bug class elsewhere, not just the cited line), and add a
   regression test.
3. Push, and tell the user which commit to have reviewed again.
4. The user merges. Never merge or approve on the user's behalf.

## Safety rules learned the hard way

- **Tests never touch real resources unless they are designed to.** Any test that runs the real script
  with arguments that could reach `-d`/`-a`, Podman or systemd goes through the stubs in
  `tests/security.sh` (`stubbed`, `del`, `pathrun`), with a scratch `HOME`. Running a regression test against
  old code is exactly when a stub-less run deletes real data, which has happened once.
- Never run git (or anything that reads repository config or hooks) on the host inside `~/opencode-sandbox`.
  Use a throwaway container (`safe_run`).
- Host-trusted state (`~/.local/share/oc-sandbox`, `~/.config/oc-sandbox`, `~/.local/bin`, systemd units)
  must never resolve through the sandbox. The script enforces this. Don't weaken it.
- Never print or log the Postgres password (`~/.config/oc-sandbox/postgres.env`).
- Never send the user's personal details to external services.
- `pkill -f PATTERN` from a shell whose own command line contains PATTERN kills that shell. Use
  `ps -eo pid,args | grep '[p]attern'`.
- The script runs from the `devbox` distrobox and calls Podman and systemd on the host through
  `distrobox-host-exec`. Run `curl` against published ports on the host, not in the distrobox.

## PRDs: progressive discovery in `docs/prds/`

- `docs/prds/README.md` is the index: one line per top-level PRD with its status.
- Follow the [implementation review gates](docs/prds/README.md#implementation-review-gates)
  before coding from a PRD and again before merging the implementation.
- **Top-level PRDs** are `prd_a.md`, `prd_b.md`, …, one per main grouping (a feature area or an issue).
- **Children** add detail where a grouping grows: `prd_a.md` → `prd_a1.md`, `prd_a2.md` →
  `prd_a2a.md`, `prd_a2b.md` → … Nest only as deep as the grouping needs. Each parent links its
  children, and each child links its parent at the top.
- Write issues and ideas as checkboxes:
  - `- [ ]` open, `- [x]` done (with the branch/commit or PR that did it).
  - Mark a checkbox `(decision needed)` until the user has chosen between options.
  - When presenting options, give each one a short list of pros and cons and an estimated time to
    implement. Recommend the best and most secure user experience; the user may pick a smaller option
    for scope.
- Questions to the user: ask **one at a time**, and let each answer shape the next question.

### Human review gate

- Every **top-level** PRD ends with exactly one final checkbox:
  `- [ ] **Human review**: checked only when the user says so`
- **Only the user can check it.** An agent checks it only after the user explicitly says that grouping
  passed their review, in this conversation. Finishing the work, a green test run or an approved
  external review is not enough.
- If an agent worked ahead, the grouping is **available for human review** when every other checkbox
  in it and its children is checked (or explicitly deferred) and Human review is still open. When the
  user asks *"what's available for human review?"*, list those groupings with a one-line summary each,
  and links to the branch/commits.
- Reopening: if the user finds a problem in a grouping that was already reviewed, uncheck Human review
  and add the problem as a new open item.
