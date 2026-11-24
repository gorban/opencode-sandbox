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
   verify readiness from a fresh process. Use inference-free discovery. The picker shows available
   model names, the operator-assigned registration label and billing mode. Discovery leaves
   account identity and invocation entitlement open until independently verified.
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

- [ ] For each candidate, publish the exact branch/commit, provider and placement, the scope
  proven, and an attended test step when ready. Keep model use opt-in and human review open
  until the maintainer explicitly records it.
- [ ] Cross-review the walkthroughs and diffs with **oc-sandbox reviewer** and
  **Security-Focused PR Reviewer Setup**. Require green CI and a passing SonarCloud quality gate
  on the exact PR head. Re-review and recheck a changed head. Serialize merges and require a fresh
  passing SonarCloud quality gate for the resulting `main` SHA before the next merge. Share the
  verified `main` SHA over the coordination channel for the next branches.
