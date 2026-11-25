# L2: Grouped CLI and test entry points

Parent: [L configuration and providers](prd_l.md) · related:
[I4a OpenAI acceptance](prd_i4a.md), [M3a loopback web](prd_m3a.md),
[M3b Tauri dashboard](prd_m3b.md), [K contributor checks](prd_k.md)

The maintainer chose grouped commands. Keep frequent provider actions short
with `oc-sandbox openai connect LABEL`. Group lifecycle verbs by their target,
with separate entry points for one instance, the installation, and workers.
Arguments identify targets. Long options describe how an action runs.

## Desired command tree

This is the target interface. Add a command to live help when its handler is
qualified. The first slice covers the local OpenAI proof and test entry point.

```text
oc-sandbox
├── help [COMMAND ...]
├── openai
│   ├── connect LABEL [--no-browser]
│   ├── status [--json]
│   ├── select LABEL
│   └── disconnect
├── instance
│   ├── run [NAME] [INSTANCE OPTIONS]
│   ├── prepare [NAME] [INSTANCE OPTIONS]
│   ├── plan [NAME] [INSTANCE OPTIONS]
│   ├── list [--json]
│   ├── shell [NAME]
│   ├── attach NAME
│   ├── remove NAME [--purge [--yes]]
│   └── rollback NAME
├── installation
│   └── teardown [--purge [--yes]]
├── build [--type TYPE] [--host WORKER]
├── keys
│   └── list
├── orchestrate
├── worker
│   ├── list [--json]
│   ├── enroll
│   ├── probe WORKER
│   ├── bootstrap WORKER
│   └── reconcile WORKER
├── config
│   ├── list
│   ├── show
│   ├── validate
│   ├── diff
│   ├── history
│   ├── approve
│   ├── reject
│   ├── reconcile
│   ├── restore
│   └── lock
└── dashboard
    └── open
```

The shared instance inputs are `--type TYPE`, `--host WORKER`,
`--with MOD`, `--without MOD`, `--port SPEC`, `--workdir DIR`,
`--worktree REPO[:REF]`, and `--no-security-keys`. Preserve the repeatable
module and port inputs. `--rebuild` applies to run and prepare.
`--allow-remote-write MCP=URL` requests an explicit elevation in the compiled
plan and requires separate operator approval before any live grant. Omitted
names on run, prepare and shell select the existing default instance.

- `instance run` reconciles the requested instance and starts OpenCode when
  needed. `instance prepare` does the existing setup and can start Chromium and
  selected services. `instance plan` is a read-only preview of the compiled
  configuration, drift, exposure and requested elevations. `build` prepares
  pinned images, toolchain layers and warm seeds. `instance rollback` restores
  a prior applied plan under the normal approval and drift checks.
- `instance shell` opens a shell in the running container. `instance attach`
  is for reconnecting to the OpenCode session once that capability lands.
- `openai` manages workstation-held connections. `disconnect` retires the
  active registration and reports unresolved revocation. Add other provider
  groups when their own connection semantics are qualified.
- `worker` manages runtime backends and their enrollment. Qualify remote
  addressing and mutation separately with [I2](prd_i2.md). Show the exact
  worker and instance before remote mutations.
- `orchestrate` launches the restricted orchestration session. Config
  approval and provider sign-in require the workstation operator. Handle
  approval against the exact proposal as specified by [L](prd_l.md).
- `dashboard open` opens the read-only loopback web dashboard first, with
  Tauri following its own PRD. The CLI and desktop reuse typed workstation
  operations and redacted results. The authority stays in the workstation
  services, and OpenCode workers receive only scoped job capabilities.

## Help and automation

Use the same static command tree for parsing and help. Root, group and leaf
accept `-h`, `--help`, and positional `help`. For example, users can enter
`oc-sandbox help openai connect`, `oc-sandbox openai help`, or
`oc-sandbox openai connect help`. A literal operand named `help` follows
`--`, as in `oc-sandbox openai connect -- help`. Help succeeds before any
config or credential reads and before browser, network or Podman calls.
Reject unknown, ambiguous and mixed legacy/canonical invocations before
effects. Invalid usage exits 2 with the nearest usage on stderr.

Reserve `-h` as the only short flag in the canonical grammar. Use structured,
redacted `--json` output for inspection and keep diagnostics on stderr. A
non-interactive flag grants only the action it explicitly names. Inference
and provider sign-in continue to require their own operator approval.

## Legacy migration

Keep the old parser during a documented transition. Test equivalent operations
under scratch HOME and stubbed host commands before migrating examples or
automation. Spell new action names in full. Retire the legacy parser in a
separately reviewed release after users have a migration path.

| Existing form | Canonical form and scope |
|---|---|
| Bare invocation | `instance run`. Switch bare invocation to help when the legacy parser is retired. |
| `-i NAME` | Positional `NAME` on the selected instance action. |
| `-n` | `instance prepare [NAME]`, which can start services and skips OpenCode. |
| `-r` | `--rebuild` on `instance run` or `instance prepare`. |
| `-p`, `-D` | `--with postgres`, `--with dind`. Preserve each service's configuration and isolation requirements. |
| `-P SPEC` | `--port SPEC`. Preserve loopback publication, exact policy checks and `none` to clear ports. |
| `-C DIR` | `--workdir DIR`, relative to the sandbox root. |
| `-W REPO[:BRANCH]` | `--worktree REPO[:BRANCH]`. Preserve relative worktrees and saved selection. |
| `-x`, `-l` | `instance shell [NAME]`, `instance list`. |
| `-k`, `-K` | `keys list`, `--no-security-keys` on setup or launch. |
| `-i NAME -d` | `instance remove NAME`. Require an explicit target, including `default` when intended. |
| `-d` without `-i` | `installation teardown`, including the host bridge and all local instances. |
| `-d -a [-y]` | Add `--purge` and optional `--yes` to the correct removal scope. |
| `-h` | `-h`, `--help`, or positional `help` at each command level. |
| Proposed `-o` | `orchestrate`. Omit the planned short alias from production. |
| Preview `openai accept` | Attended pytest scenario, outside the product grammar. |

For canonical teardown, show the complete removal scope and obtain approval
before the first destructive effect. Named removal targets only the selected
instance. Installation teardown targets all local instances and the bridge.
Purge adds owned persistent resources according to that scope. Worktree data
and workstation OpenAI registrations and usage accounting have independent
lifecycles. Preserve the legacy parser's behavior while it remains available.

## Test suites and rollout

```text
tests/
├── unit/             # Parsing, policy, transitions and accounting
├── integration/      # Real process and state boundaries, synthetic services
└── e2e/
    ├── synthetic/    # Pinned real Podman/OpenCode, fake upstream
    └── live/         # Attended workstation and managed-worker proof
```

Use pytest as the test entry point. Reuse existing unittest cases and shared
scratch fixtures where useful. Ordinary tests and PR CI use synthetic
credentials. The live case is explicitly targeted and opts in from the
foreground workstation terminal. It invokes a trusted proof driver with
the genuine saved profile and durable exposure ledger. Preserve both
independent approvals, bounded inference, redacted outcomes, and exact
worker cleanup. Keep the repository's real-host shell gates. Update CI
discovery and Sonar coverage together when moving existing suites.

- [ ] Move the attended proof out of the product CLI and qualify the pytest
  entry point under [I4a](prd_i4a.md).
- [ ] Review the grouped grammar and add effect-free help with parity tests
  for every supported legacy invocation and rejection of mixed syntax.
- [ ] Port and qualify grouped handlers in stages. Review remote placements,
  destructive operations and desktop authority before enabling them.
- [ ] Migrate the remaining Python tests to the directory convention and
  update the portable runner, coverage and development guide.
- [ ] Retire the legacy parser after the migration is qualified.
