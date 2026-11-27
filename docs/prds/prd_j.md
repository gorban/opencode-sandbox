# prd_j: Host configuration and editor preferences

[Index](README.md) · related: [worktree defaults](prd_c.md), [host tools](prd_f.md),
[fleet profiles](prd_i1.md)

## Goal

Move operator preferences into a small host-trusted configuration with clear defaults and a way to
edit and validate them. Use `api-agent`'s TOML and terminal editor workflow as a reference. Review
the configuration schema and editor options before selecting or adding dependencies.

## First consumer: bridge merge tool selection

- [ ] Give the bridge a small typed selection interface for merge mode and tool. Start with a
      stub that returns `three-way` and `git-preference`. Keep selector, tool adapter, merge
      session and apply/recovery logic separate. Add no configuration file, TUI or new dependency
      for this stub.
- [ ] For a file in a verified Git worktree, prefer the repository's `merge.tool` setting, then
      the operator's host global `merge.tool` setting. Resolve the worktree based on the original
      sandbox file, including linked worktrees, instead of the host editor's staging directory.
      Outside a repo, use the host global setting. When neither scope sets a preference, offer a
      supported installed three-way adapter, with `vimdiff` as a candidate when an interactive
      host terminal is available. Do not substitute an unsupported configured tool silently.
- [ ] Treat Git config as a source of a tool **name** only. Read the local scalar through the
      existing confined Git boundary, without includes, hooks or ambient Git overrides. Read
      global config through a bounded path outside the agent-writable roots. Accept only known
      adapter names. Use fixed argument vectors and validated host executables. Do not honor
      custom `mergetool.*.cmd`, executable paths or control settings from Git config, and never
      run host Git against the sandbox repo. Explain missing or unsupported tools and keep the
      private recovery copy accessible. Show the chosen adapter and preference source in the
      operator prompt. Start from a trusted working directory and disable project startup files
      and file-embedded editor directives when the adapter supports them. Qualify adapters only
      when sandbox file contents cannot choose code that runs on the host.
- [ ] Keep `.BASE`, `.HOST`, `.AGENT` and `.MERGED` as private host session files. For three-way
      mode, require operator merge review whenever the sandbox version diverges from the base.
      Saving merge output completes the editor step. Apply it only after explicit confirmation,
      verification of the exact eligible sandbox revision and proven writer exclusion. Retain
      the result privately if apply is unsafe or uncertain. Clean up the session only after
      verified apply or explicit discard. Follow the bridge provenance and recovery reviews before
      enabling a merge or apply path.
- [ ] Reserve `two-way` for an explicit operator choice in the later configuration. A two-way
      adapter presents the host and sandbox copies and requires a manually edited, reviewed
      output. It cannot infer which side changed a line from the base. Preserve the private base
      for recovery when available. Never downgrade to two-way implicitly because a tool is missing.
- [ ] Review adapter support and completion semantics with the exact installed versions. Qualify
      at least one GUI or one interactive terminal adapter before enabling it. Test repo and
      global preference precedence, non-repo files, agent-writable config, missing or unsupported
      tools, stale merge inputs, cancellation and safe cleanup. Validate the terminal adapter
      through an attended host terminal instead of a background bridge service.

Git documents [merge tool selection](https://git-scm.com/docs/git-mergetool) and
[configuration scopes](https://git-scm.com/docs/git-config). Beyond Compare documents its
[Git integration](https://www.scootersoftware.com/kb/vcs), including three-way merge in Pro.

## Review record

- [x] Isolate selections in the existing host bridge's private stage and exclude repository and
      editor metadata before giving paths to a desktop tool. Ordinary file saves still go back
      to their recorded sandbox paths. Recover legacy staged files manually. Design review
      cleared walkthrough `efbe9485bdd3f47a90f448d66eef15724c93d3a093831bd2b765bdbfc00d815c`
      for `codex/audit-bridge-staging`. The editor operand grammar follow-up cleared
      `6e989f377b6b9f10232c066b01848795020828f7ce06911ccca51fca79aab93e`.
- [x] Make the existing bridge poll its request spool without following sandbox paths from systemd.
      Keep uncertain sessions and closed recovery files private, bound staging traffic and quote
      save diagnostics. Quiesce the bridge and hold global teardown or legacy migration when
      a retained session needs attention. Design review cleared
      `5dc97f63f8dec1b85367cb4efb3484f9197773f183376d2515ff278bb84713a2`
      for `codex/audit-bridge-lifecycle`.
- [x] Confirm the bridge triggers and drain are quiescent before replacing the runner and units.
      Keep started editor sessions recoverable until an operator confirms closure.
      The cutover and recovery walkthrough cleared both design reviews at
      `5f413a34a5ceeeb53971e27b4bae3f637faa2710befd1defb19cc40bf35aea4e`.
- [x] Verify the effective bridge unit identity and timer disarm before replacement or teardown.
      Check fresh enablement and activation links, including runtime and global links. Recheck
      the replacement units before enabling the timer.
- `oc-sandbox reviewer` cleared the three-way design and tool selector at SHA-256
  `f302a6ba7f6db3845aaac1ccf9f74637885cd3108693f267577676788fa25c8b`.
- Independent and external reviewers cleared the offline core at `98b86bf` and the
  late-receipt repair at `f260b9a` on `codex/bridge-merge-core`.
- [x] **Human approval of the offline bridge merge core** (`codex/bridge-merge-core`),
      including the typed selector, merge and finish confirmations, recovery after
      uncertain receipts, and create-only export with synthetic receipts. Live Git
      readers, editor behavior, persistent recovery and filesystem publication have
      separate qualification requirements.

## Later configuration and editor

- [ ] Propose a versioned TOML schema with safe defaults, typed values, validation, and a clear
      precedence rule for host preferences, explicit CLI options and legacy environment variables.
      Document which settings can be overridden per project and which require host authority.
      Store credential references only. Do not accept command strings or secrets in project config.
- [ ] Make config reads and writes safe across concurrent edits and failures. Use the existing
      trusted-state rules, validate complete proposed changes before publishing, preserve a valid
      prior version on failure and show the effective source of each setting. Plan migration from
      existing environment settings without weakening the launcher or merge tool boundary.
- [ ] (decision needed) **Editing interface**. Compare a plain TOML editor plus a validation command
      (smallest runtime and easiest to audit, less guided, roughly 1–2 days) with a small TUI
      inspired by `api-agent` (field help and live validation, more UI and dependency review,
      roughly 3–5 days). Recommend TOML and validation as the shared core. Review terminal
      libraries, licensing, transitive dependencies and packaging before choosing a TUI.

- [ ] **Human review**: checked only when the user says so
