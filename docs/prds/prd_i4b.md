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
      checks. Describe Meridian as a proposal until its route passes the qualification below.

### README copy for the current launcher

> ## Security boundaries
>
> OpenCode runs in a rootless Podman pod. The host home stays outside its mounts when you use
> the dedicated workspace. Keep host SSH keys and password-manager state outside that workspace.
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

The [I4a plan](prd_i4a.md#resolved-open-choices-and-cross-prd-alignment) has a standalone host
`agy acp` lifecycle and leaves the Antigravity broker route disabled. Evaluate Meridian as a new
backend of the same broker. Use LiteLLM for API-key routes during the first prototype.

```text
OpenCode in managed Podman job -> per-job endpoint on trusted host broker
  -> private LiteLLM -> API-key providers
  -> private Meridian with agy -> Antigravity subscription
```

- [ ] **Runtime and review.** Review the dispatch, failure, and cancellation walkthrough at
      Gate 1. Try a separate rootless Podman container on the broker host for Meridian and `agy`,
      with a private profile, scratch directory, and provider egress. Give it no workstation
      home, vault, SSH agent, host control sockets, or job worktree. Verify how Meridian's CLI
      mode signs in and refreshes with a dedicated profile. Start with text, then qualify the
      tool bridge separately. Its CLI permission hook does not provide OS isolation.
      [Meridian tool permissions](https://github.com/rynfar/meridian/blob/main/docs/antigravity.md#tool-permissions)
- [ ] **Broker route.** Allow model discovery, inference, and job-bound tool continuations.
      Keep Meridian's listener, shared key, and admin endpoints private to the trusted runtime.
      Fix the backend destination in host config. Disable native browser and subagent features,
      and verify model calls cannot use local host tools. Enforce model, request, concurrency,
      and time limits. Expiry and revocation must close streams and end pending tool turns.
      Record any advisory limits and how upstream cancellations are confirmed.
      [Meridian authentication](https://github.com/rynfar/meridian/blob/main/docs/configuration.md#api-key-authentication)
- [ ] **Qualification.** Start with a hostile synthetic job. Test direct backend access,
      secret and admin endpoint access, cross-job session reuse, and revocation during streaming
      and while awaiting a tool result. Probe workstation canaries from the provider runtime.
      Then verify sign-in, refresh, model discovery, streaming, a file edit executed by OpenCode
      inside its own sandbox, and cancellation on the supported Linux versions. Meridian's
      published OpenCode setup targets V1. Qualify the V2 client we ship before publishing the
      feature and record the implementation review and test evidence.
      [Meridian client support](https://github.com/rynfar/meridian/blob/main/docs/antigravity.md#configure-installed-clients)

### License and distribution

Meridian's own code is MIT and can be used alongside this project's [BSD 2-Clause license](../../LICENSE).
The `1.93.0` tag and npm package declare MIT, but the published tarball and tagged source lack
the full license file. Upstream added the full MIT text and copyright notice after that tag.
[Tagged README](https://github.com/rynfar/meridian/blob/meridian-v1.93.0/README.md#contributing) ·
[License addition](https://github.com/rynfar/meridian/commit/8a5ba029881e2abdade0c84194351588a1df4e9e) ·
[Upstream license text](https://github.com/rynfar/meridian/blob/8a5ba029881e2abdade0c84194351588a1df4e9e/LICENSE)

- [ ] **Installed dependency.** Start with an operator-installed Meridian release. Pin the
      version used for qualification. Link to its source and license in the setup guide. If a
      package or image we distribute contains Meridian, verify the full upstream copyright and
      MIT notice in the shipped artifact. Prefer a release that includes the license and check the
      exact artifact rather than relying on the `license` field alone.
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
      Use an external runtime or a small MIT-only extraction if the full distribution is unsuitable.
      [Meridian manifest](https://github.com/rynfar/meridian/blob/meridian-v1.93.0/package.json) ·
      [Claude Code license](https://github.com/anthropics/claude-code/blob/main/LICENSE.md) ·
      [Agent SDK license](https://github.com/anthropics/claude-agent-sdk-typescript/blob/main/LICENSE.md) ·
      [Provider asset credits](https://github.com/rynfar/meridian/blob/main/assets/providers/README.md) ·
      [Official `agy` distribution](https://antigravity.google/download)
