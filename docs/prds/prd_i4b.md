# prd_i4b: Sandbox security documentation and Meridian qualification

Parent [I4 model gateway](prd_i4.md) · Related [I3 credential broker](prd_i3.md),
[I4a outside-in design](prd_i4a.md), and [current security guide](../security.md).

## README and linked guides

- [ ] Add **Security boundaries** after **What you get** and before **Requirements** in
      [README.md](../../README.md). Move the overview's security caveats into this section and
      point the existing security link in **Guides** there. Use the current-launcher copy below.
- [ ] Keep [docs/security.md](../security.md) as the security overview. Compare **Local interactive**
      and **Managed job** by readable files, visible credentials, network reach, and external
      actions. Label each profile with its availability. Keep Chromium sign-in, shared state,
      and sidecar caveats in this guide. Link to **Runtime and trust boundaries** in
      [docs/architecture.md](../architecture.md) for the stack and to `docs/threat-model.md` for
      abuse cases, residual risks, and verification. Put setup commands in the operations guide.
- [ ] In the architecture guide, show which processes run where and what each layer enforces.
      Cover the Linux host launcher, rootless Podman and namespaces, SELinux confinement and
      exceptions, the shared host kernel, mounted workspace and sidecars, and the trusted host
      controller and model broker for managed jobs. Show each verified gateway behind the
      broker. Label optional components and the policy changes they introduce.
- [ ] Publish the managed-job copy only after the release passes its isolation and revocation
      checks. Publish the Meridian claim only after provider authorization and technical
      qualification below. Until then, describe the route as a proposal in this PRD.

### README copy for the current launcher

> ## Security boundaries
>
> OpenCode runs in a rootless Podman pod. The launcher mounts `~/opencode-sandbox`, sandbox
> volumes, and configured display, device, and sidecar resources. The rest of your home directory
> stays outside those mounts. Keep host SSH keys and password-manager state outside the workspace.
> The agent can read and change the shared workspace, use accounts you sign into in its browser,
> and read API keys you forward. A prompt injection can cause it to send data it can read over
> an available network connection.
>
> See the [security model](docs/security.md#security-model) for what the sandbox exposes and
> how the [runtime is isolated](docs/architecture.md#runtime-and-trust-boundaries).

### README copy to add after managed-job qualification

> **Managed jobs** give OpenCode shell and file access inside a per-job workspace. Upstream API
> keys, subscription sign-ins, and host SSH and password-manager credentials stay outside the
> job. OpenCode calls the model through a revocable, job-scoped broker grant. The agent can
> still disclose source code it can read and misuse actions or model access granted to the job.
> See the [threat model](docs/threat-model.md) for the assumptions and limits.

After Meridian qualification, add this sentence to the managed-job paragraph after the broker
sentence. “For Antigravity through Meridian, the `agy` sign-in stays in a private runtime on
the broker host.”

## Threat model

- [ ] Write `docs/threat-model.md` using the four questions below. Use a data-flow diagram with
      labeled boundaries, an asset and access inventory, and a threat register. Use STRIDE
      (spoofing, tampering, repudiation, information disclosure, denial of service, elevation
      of privilege) to check the flows. Include prompt injection and abuse of approved actions.
      [OWASP threat-modeling guide](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)

1. **What are we building?** Show the operator and trusted host runtime, OpenCode and sidecars,
   broker, private gateways, model providers, and external destinations. Label who holds the
   worktree, job grant, SSH and vault access, upstream keys, and subscription state. Show the
   `pasta` per-job forward for local rootless Podman, the SSH reverse forward to a host socket
   for remote jobs, and where prompts and tool output travel. Assume an injected agent can run
   arbitrary code within the job. Document trust in the operator, host kernel and runtime, and
   any remote host that holds project files.
2. **What can go wrong?** Cover agent-led disclosure, host credential theft, cross-job reads and
   model calls, token replay, quota abuse, external mutations, and container escape. Treat model
   output, web pages, repository content, and tool results as untrusted inputs.
3. **What do we do about it?** For each threat, name the affected profile, enforcement point,
   and residual risk. Document open versus restricted egress and any exceptions in effect.
   Allowed model providers and services can receive readable job data. Revocation cannot recall
   data already delivered or effects already accepted upstream.
4. **How do we verify it?** Link claims to evidence for the advertised release and host profile.
   Recheck when mounts, credentials, network policy, worker backends, or providers change.

| Threat | Intended managed-job control | Residual risk and verification |
|---|---|---|
| Reads host secrets or another job's files | Isolate mounts, processes, networks and homes. Keep upstream credentials, SSH agent and host control sockets outside the job. | Depends on the kernel and runtime. Probe synthetic canaries in files, environment and sockets, including a second job. |
| Sends code or browser data out | Limit mounted data and browser profiles. Apply the job's documented egress policy. | Data can leave through allowed channels. Verify the actual routes and document what each allows. |
| Copies its grant or burns model quota | Scope the broker grant to the job, transport, model, expiry and limits. Revoke live usage. | An agent can relay permitted calls during its lease. Test cross-job and external replay, limits, expiry and revocation on open connections. |
| Abuses an approved external action | Scope sensitive actions at the trusted adapter using the [I3 approval rules](prd_i3.md#approval-and-retry). | An action within scope can still cause harm. Test target mismatches, retries and revocation. |

## Proposed Antigravity backend via Meridian

See the [Gate 1 walkthrough for the synthetic prototype](prd_i4c.md).

The [I4a plan](prd_i4a.md#resolved-open-choices-and-cross-prd-alignment) has a standalone host
`agy acp` lifecycle and leaves the Antigravity broker route disabled. Evaluate Meridian as a new
backend of the same broker. Use LiteLLM for API-key routes during the first prototype.

```text
OpenCode in managed Podman job -> per-job endpoint on trusted host broker
  -> private LiteLLM -> API-key providers
  -> private Meridian with agy -> Antigravity subscription
```

- [ ] **Stage 0 — provider authorization.** Keep I4a's `antigravity-oauth` route and its aliases
      policy-blocked. Use a distinct candidate route, `agy-meridian`, disabled by default.
      Google's current guidance rules out wrapping the CLI in third-party agents on consumer
      plans. Before any live sign-in, model call, or README availability claim for this route,
      record current provider documentation or explicit confirmation covering the exact broker
      topology, account entitlement, cross-job usage, and billing. The official CLI by itself
      supplies no such authorization. Proceed with synthetic fixtures while permission is
      absent or unclear. Passing technical tests never overrides this decision.
      [Antigravity CLI FAQ](https://antigravity.google/docs/faq/#can-i-use-antigravity-cli-headless-mode-in-third-party-coding-agents-or-automate-account-switching)
- [ ] **Lease-scoped runtime.** At Gate 1, review dispatch, failure, and cancellation using one
      separate rootless Podman container and Meridian process per lease on the broker host. Give
      each lease its own `agy` sign-in profile, scratch directory, state, private endpoint, and
      broker-to-Meridian key. Do not share writable homes, caches, or provider conversation stores
      across leases, including after restart. Verify how the operator signs in and how refresh
      works within one lease if Stage 0 clears. Keep workstation home, vault, SSH agent, host
      control sockets, and job worktree outside the runtime. Qualify text first and the tool
      bridge separately. OS isolation protects other host assets. The Meridian and `agy`
      processes themselves hold the lease's provider state, so compromise of those processes
      remains a threat to that state.
      [Meridian tool permissions](https://github.com/rynfar/meridian/blob/main/docs/antigravity.md#tool-permissions)
- [ ] **Private connection and restricted egress.** Connect the broker to the lease's backend
      over a private channel. Publish no Meridian or internal MCP listener to the host or job
      networks. Disable host gateway mapping. Enforce a default-deny egress policy outside the
      credentialed container, via a trusted resolver and an allowlist of required authentication
      and provider destinations. Leave host, LAN, link-local, and metadata destinations denied
      across IPv4 and IPv6. Review DNS resolution, proxy and redirect behavior and test blocked
      destinations with canaries. Require an explicit review of any egress policy change before
      attaching real credentials. Document how approved destinations can still receive job data.
- [ ] **Broker route.** Allow model discovery, inference, and job-bound tool continuations.
      Keep Meridian's listener, shared key, and admin endpoints private to the trusted runtime.
      Choose the backend from the broker's lease record. Drop client-supplied upstream profile,
      affinity, and session selectors. Bind tool-result continuations in broker state to the
      lease, conversation, and pending call. Reject stale, mismatched, and replayed continuations.
      Disable native browser and subagents and verify model calls cannot use local host tools.
      Enforce model, request, concurrency, and time limits. On expiry or revocation, stop
      admissions, close streams, invalidate pending calls, then stop and reap the lease runtime
      and retire its state before reuse of resources. Document advisory limits and upstream
      cancellations or effects the broker cannot confirm or recall.
      [Meridian authentication](https://github.com/rynfar/meridian/blob/main/docs/configuration.md#api-key-authentication)
- [ ] **Qualification.** Start with a hostile synthetic job. Test direct backend access,
      secret and admin endpoint access, forged session/profile selectors, colliding tool-call
      IDs, simultaneous jobs, replay after restart, and revocation while streaming or awaiting
      a tool result. Probe workstation and network canaries from the provider runtime. Verify
      that model-visible responses and tools cannot read the synthetic sign-in state. If Stage 0
      clears, verify sign-in, refresh, model discovery, streaming, a file edit executed by
      OpenCode inside its sandbox, a denied host-tool call, and cancellation on supported Linux.
      Meridian's published OpenCode setup targets V1. Qualify the V2 client we ship and record
      the implementation review and test evidence before publishing the feature.
      [Meridian client support](https://github.com/rynfar/meridian/blob/main/docs/antigravity.md#configure-installed-clients)

### License and distribution

Meridian's own code is MIT and can be used alongside this project's [BSD 2-Clause license](../../LICENSE).
The `1.93.0` tag and npm package declare MIT, but the published tarball and tagged source lack
the full license file. Upstream added the full MIT text and copyright notice after that tag.
[Tagged README](https://github.com/rynfar/meridian/blob/meridian-v1.93.0/README.md#contributing) ·
[License addition](https://github.com/rynfar/meridian/commit/8a5ba029881e2abdade0c84194351588a1df4e9e) ·
[Upstream license text](https://github.com/rynfar/meridian/blob/8a5ba029881e2abdade0c84194351588a1df4e9e/LICENSE)

- [ ] **Installed dependency.** The operator provisions the runtime in a private build container
      with no workstation mounts, sockets, or credentials. Pin the source revision, package
      version and integrity hash, and the resolved dependency versions and hashes. Inventory
      every executable and download used in provisioning. Meridian 1.93.0 runs the Claude Code
      installer from its `postinstall` script. Disable package lifecycle scripts by default and
      qualify that build. If a required build step needs one, review and pin that step and any
      inputs before running it in the credential-free build container. Avoid global host installs
      and automatic updates. Rebuild through the same process for a version change. Link to the
      source and license in the setup guide and verify the full copyright and MIT notice in any
      artifact we publish.
- [ ] **Copied or adapted code.** Record the upstream revision and paths, preserve applicable
      file notices, and include the full upstream MIT license and copyright in third-party
      notices shipped with source and binary or image releases. Keep the root BSD license for
      our code. Link to the notices from the setup guide. Review the files for any separate terms.
      [MIT license requirements](https://opensource.org/license/mit)
- [ ] **Redistributed runtime.** Inventory the packages and assets in the final artifact,
      including base-image and transitive components, then verify their redistribution terms
      and notices. The full Meridian npm package declares Claude Code and the Claude Agent SDK
      as direct dependencies even when we only select Antigravity. Both carry separate
      Anthropic terms. Meridian also includes provider icons under separate rights. Keep
      Google's `agy` CLI operator-installed and omit those icons and Anthropic components from
      any artifact we publish unless their separate redistribution rights are confirmed.
      Use an external runtime or a small MIT-only extraction if the full distribution is
      unsuitable. An extraction or pruned build needs reproducible artifact and dependency
      evidence and the same functional and isolation qualification as the full package.
      [Meridian manifest](https://github.com/rynfar/meridian/blob/meridian-v1.93.0/package.json) ·
      [Claude Code license](https://github.com/anthropics/claude-code/blob/main/LICENSE.md) ·
      [Agent SDK license](https://github.com/anthropics/claude-agent-sdk-typescript/blob/main/LICENSE.md) ·
      [Provider asset credits](https://github.com/rynfar/meridian/blob/main/assets/providers/README.md) ·
      [Official `agy` distribution](https://antigravity.google/download)
