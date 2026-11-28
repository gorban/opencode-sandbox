# I4f: Live provider rollout and staged acceptance

Parent: [I4](prd_i4.md) · related: [I3a worker credential isolation](prd_i3a.md),
[I4d provider settings](prd_i4d.md), [M1 provider-side tools and fallback](prd_m1.md)

The first outcome is a maintainer selecting a model from a connected subscription and getting a
real text response, first in the orchestrator and then in a managed OpenCode sandbox. Keep the
provider login on the workstation. Apply the same boundary when OpenCode has full file and shell
tools inside its sandbox.

## Ownership and order

- [*] **AGY** — OpenAI/ChatGPT connection, model selection and first live text through both
  placements. Plan [Bedrock](prd_i4e.md) when ChatGPT review leaves capacity. Qualify live
  Bedrock after ChatGPT text in both placements.
- [ ] **Codex** — [Antigravity](prd_i4c.md) rootless sign-in and first text. Qualify native
  Claude Code sign-in and pursue the exact [Claude subscription authorization](prd_i4.md#feasibility-spike--host-only-claude-subscription-routing)
  in parallel. A Claude API-key route has separate policy and billing.
- [ ] **Codex with AGY** — model discovery, selection and broker handoff on one shared integration
  branch when both lanes need the same change. Keep AGY's initial ChatGPT PR independent. Start
  follow-ups from the reviewed merged base or stack them explicitly on their prerequisites.

## Common interface

See the [parallel lane walkthrough](prd_i4fa.md) for the common interface and review gates.

Reuse I4d's provider instance and connection state across CLI, orchestrator and sandbox launch.
Host-only discovery associates each model with the exact enabled instance, qualified placement,
auth mode and billing policy. At selection, check the instance, model, placement and policy. Before
each broker-controlled send, retry or continuation, recheck that binding, credential generation,
selection epoch, applicable exposure authority and the job incarnation once it exists. Show the
operator a fixed recovery action if the preferred route is unavailable. Workers get only the
admitted model alias and a scoped local broker route. Keep native provider processes, keyrings,
provider tokens and connection actions on the workstation.

Review shared isolation and lifecycle code before extracting it. Keep provider-specific protocol,
tool and safety rules in their adapters. A change that affects credential reachability, renewal,
routing, exposure or revocation goes through both reviews before use by another provider.

## Testable PR milestones

1. **Connect and list.** On the normal CLI or workstation flow, connect the selected instance and
   verify readiness from a fresh process. Use inference-free discovery. Enable the available
   instances in trusted provider configuration, then launch with `oc-sandbox orchestrate` or
   `oc-sandbox`. Select a model through the
   [trusted route confirmation](prd_i4fa.md#first-inference-and-model-switches). The
   [model-first picker](prd_i4d.md#model-first-picker) shows the model name, the configured
   instance label and billing mode. Discovery leaves account identity and invocation entitlement
   open until independently verified.
2. **Live text.** Qualify and separately authorize a bounded `Reply with exactly: ok` canary on
   the actual orchestrator launch path first, then the same canary on the managed sandbox launch
   path. They may be separate PRs. For each request, review the exact instance, model, placement
   and exposure scope. A native prompt may cause an unknown number of upstream requests. Verify
   local, native and provider-side tool restrictions, terminal success, streaming where supported,
   selected instance attribution, denial of paid fallback and worker credential isolation. Each
   placement passes when the visible response is exactly `ok` and the tool invocation count is zero.
   Live qualification requires real evidence and its own authorization.
3. **Tools and continuation.** In a separately reviewed and authorized follow-up, use one permitted tool to write exact
   synthetic bytes inside the sandbox and send one continuation through the same binding. Test
   revocation, wrong incarnation and provider failure. Prove the model cannot use host tools or
   read the workstation login. Keep that provider text-only until this gate clears.

## Opt-in live e2e pytest milestones

Keep temporary canary and smoke harnesses out of the public `oc-sandbox` CLI. Automate each
provider's live `"Reply with exactly: ok"` check as an opt-in pytest under `tests/e2e/live/`
(skipped by default in CI unless its explicit opt-in flag is passed directly in pytest's CLI
invocation arguments — never via `PYTEST_ADDOPTS` or ambient environment variables). Every live e2e
harness runs in an isolated verified interpreter and disposable sandbox pod/workspace, leaves
historical exposure receipts in `~/.config/oc-sandbox/` byte-for-byte untouched without bypassing
corrupt-receipt/untrusted-store fail-closed checks or broker credential isolation, enforces
source-trust and graceful `SIGINT` teardown, and asserts exact `ok` delivery, `0` unintended tool
calls, and verified container/scratch cleanup.

- [ ] **OpenAI zero-tool canary e2e** (`tests/e2e/live/test_openai_canary_e2e.py`,
  `--run-openai-canary-live`) — opt-in zero-tool OpenCode 2.3.0 turn against the active OpenAI
  subscription (`Reply with exactly: ok`). Candidate verified live on PR #71; pending Gate 2
  re-review, serialized merge after PR #69, and final human review.
- [ ] **OpenAI interactive shell e2e** (`tests/e2e/live/test_openai_shell_e2e.py`,
  `--run-openai-shell-live`, bootstrapped via `tests/e2e/live/run_openai_shell_live.py`) — opt-in
  broker-and-pinned-TUI integration milestone exercising `run_interactive_session` (real
  `OpenAISessionAdapter`, `SessionBroker`, two-phase discovery-to-turn `session_relay.py` cutover,
  pinned `oc-agent` Full and Mini TUIs, and read-only session export corroboration) inside a
  disposable owner-managed pod with mandatory role-bound reviewed image IDs, single verified
  foreground owner retaining attended `/dev/tty` approval and foreground/drift rechecks through the
  first-write fence, `file + dir fsync` durability, and `SIGKILL`-surviving lifecycle-locked cleanup
  with pod-membership verification. Separate offline configuration-first public CLI (`oc-sandbox` /
  `oc-sandbox --mini`) spec-value parity and ambient-FD immunity checks run in CI. The I4fa
  public-launch live milestone and live qualification/human review remain open.
- [ ] **Claude live e2e** (`tests/e2e/live/test_claude_shell_e2e.py`, `--run-claude-shell-live`) —
  opt-in automated test replacing ad-hoc `/var/tmp/...` probe commands once the exact host-isolated
  Claude launch topology clears qualification and security review (remains open while PR #72's
  project launcher is synthetic), verifying exact `ok` delivery, `0` unintended tool calls, intact
  fail-closed checks, and clean teardown.
  - [x] Exercise the bounded Claude text protocol and synthetic subprocess in CI. The
    fixture pins the workspace, passes one request to the inert child, verifies exact
    retirement, and protects uncertain workspace bindings for the controller lifetime.
    See `codex/claude-bounded-text-fixture`.
  - [ ] Verify credential and process custody through the stock public launcher, then
    qualify the real subscription route and its usage evidence.
- [ ] **Combined multi-provider default + `--mini` e2e** — once OpenAI and Claude qualify in the
  sandbox, test both `oc-sandbox` and `oc-sandbox --mini` using the same trusted provider
  configuration. Pick a model from each instance through trusted confirmation and send
  `Reply with exactly: ok` in a fresh conversation. Require exact `ok`, zero tool calls,
  zero upstream requests through the other instances, zero cross-instance credential, token or
  vault visibility, and verified teardown. Start a new launch for each route until trusted
  same-launch switching qualifies. Add Antigravity to the same matrix as its sandbox route
  qualifies. Exercise overlap in an inference-free fixture with the same model across provider
  kinds and across two instances of one kind. Include live overlap cases when the connected
  subscriptions actually offer a common model.

- [ ] For each candidate, publish the exact branch/commit, provider and placement, the scope
  proven, and an attended test step using the normal public launch command and model picker.
  Use configuration to choose which instances are available for review. Keep model use opt-in
  and human review open until the maintainer explicitly records it.
- [ ] Cross-review the walkthroughs and diffs with **oc-sandbox reviewer** and
  **Security-Focused PR Reviewer Setup**. Require green CI and a passing SonarCloud quality gate
  on the exact PR head. Re-review and recheck a changed head. Serialize merges and require a fresh
  passing SonarCloud quality gate for the resulting `main` SHA before the next merge. Share the
  verified `main` SHA over the coordination channel for the next branches.
