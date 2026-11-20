# prd_k · Contributor checks and repository layout

[Index](README.md) · [Development](../development.md) · [Repository layout](../architecture.md)

## Initial proofs of concept

- [ ] Verify the PR-only workflow and shared local checks on the first hosted pull request.
  Portable tests run the explicit suite inventory with private scratch state and restricted Git
  configuration. Quality runs after tests on the same synthetic merge SHA. The stable
  `oc-sandbox / required` check requires both jobs to succeed. Record the observed check identity,
  checked SHA, tool versions and outcome before the maintainer configures a ruleset.
  Keep the real Podman and parallel host gates in [AGENTS.md](../../AGENTS.md#gates-before-a-commit-and-before-asking-for-review).
- [ ] Review the shorter README, task guides and responsibility map on the implementation diff.
  Preserve the installed launcher, operator behavior, Postgres README heading, existing
  README fragment links and relative examples.

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

## Quality ratchet

- [ ] Establish reproducible coverage for the two Python policy cores before enforcing per-core
  line or branch floors. Report subprocess and separate-interpreter exclusions. Measure shell
  behavior separately.
- [ ] Baseline scoped Ruff lint, formatting and C901 diagnostics, shfmt, fuller ShellCheck and
  actionlint before introducing stricter gates. Pin new tools with a reviewed version and checksum.
  Track individual diagnostics and complex functions by scope so removing one finding cannot mask
  a new one. Exercise behavior when extracting complex code.
- [ ] Review the versioned dependencies, OCI images and Actions the project uses. The offline
  Python cores use the standard library.

A local measurement at `676dc65` using its two existing offline suites, CPython 3.14 and Coverage.py
7.11.0 counted 320/323 bridge statements and 93/94 bridge branches, and 411/425 controller statements
and 121/136 controller branches. It covers those two modules in the test interpreter. A hosted
baseline and a required floor remain open.

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

## Later runtime layout

- [ ] Qualify separate moves to `runtime/host/` for deployed host helpers,
  `runtime/container/` for agent image helpers and `src/oc_sandbox/` for offline policy.
  Preserve root launch and symlink behavior, source markers, helper and image lookup, and test
  fixture behavior on each move. Run rootless host acceptance for affected runtime pieces.
  Group tests by fixture type when it makes them easier to find.

- [ ] **Human review**: checked only when the user says so
