# prd_c: Worktree defaults (current repo, hidden worktree folder, relaunch)

[Index](README.md)

## Problem

`oc-sandbox -i feat-a` without `-W` makes a plain, empty `~/opencode-sandbox/wt/feat-a`, next to
`construct/`. A user running it from inside a git repository in the sandbox (e.g.
`~/opencode-sandbox/construct/myapp`) expects a worktree of *that* repository on branch `feat-a`.

## Current behaviour

- The script ignores the host's current directory. The working directory is `construct` (default
  instance), `wt/NAME` (other instances), or `-C DIR`.
- `-W REPO[:BRANCH]` makes `wt/NAME` a git worktree of `REPO` (branch defaults to the instance name).
  It runs only when `wt/NAME/.git` doesn't exist yet. Later runs with a **different** `-W` are silently
  ignored.
- Relaunching with `-i feat-a` alone works: it reuses the worktree and the stored ports (see
  [index](README.md)).

## Proposal

- [x] **Current-repo detection** (codex/foundations-batch): when `-i NAME` is given without `-W`/`-C` and the host's working
      directory is inside `~/opencode-sandbox`, use the git repository containing it as `REPO`. Do the
      detection in the throwaway container (`git rev-parse --show-toplevel` with hooks and fsmonitor
      off), never with host git: the repository is agent-writable.
      **Decision (2026-11-15): `wt/<repo>/NAME`**, where `<repo>` is the repo's path relative to
      `~/opencode-sandbox` (e.g. `construct/myapp` → `wt/construct/myapp/feat-a`). That avoids
      collisions between repos with the same name. Without a detected repo, it stays `wt/NAME` as
      today. Refuse to detect a repo that is itself under `wt/` (a worktree of a worktree).
- [x] (codex/foundations-batch) Print what was chosen ("worktree of construct/myapp on branch feat-a at …") and how to override it.
- [x] (codex/foundations-batch) Refuse, with a message, when an existing worktree belongs to a different repo or branch than the
      `-W` given, instead of silently ignoring it.
- [x] (codex/foundations-batch) `oc-sandbox -l` shows the repo/branch of each instance's worktree.
- [x] (codex/foundations-batch) Tests: detection from a nested directory, a symlinked repo (refused, as `-W` already does), a
      mismatch refused, and relaunch without `-W`.

### Options: where a detected repo's worktrees go

| Option | Pros | Cons | Time |
|---|---|---|---|
| **`<repo>/.worktrees/NAME`**, hidden, with `/.worktrees/` added to the repo's `.git/info/exclude` (recommended) | stays with its repo; hidden; nothing committed; a common pattern | nested inside the repo, so recursive tools (ripgrep, IDE indexers) see it unless they honour excludes | 1 day |
| **`~/opencode-sandbox/wt/<repo>/NAME`** (today's top-level, grouped by repo; chosen) | never nested inside a repo; one place for all worktrees | not next to the repo; two repos with the same name collide unless the path is encoded | 1 day |
| Sibling `<repo>.worktrees/NAME` | not nested; next to the repo | clutters the parent folder; unusual | 1 day |

- [ ] **Human review**: checked only when the user says so
