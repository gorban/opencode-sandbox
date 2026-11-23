# prd_i3a: Managed worker credential isolation

Parent: [I3 credential broker](prd_i3.md) · related: [I4 model gateway](prd_i4.md),
[L1 broker transports](prd_l1.md), [M1 model routes](prd_m1.md), [I5 warm starts](prd_i5.md)

## Boundary and status

A managed worker can run arbitrary commands with its normal in-sandbox permissions. Assume
prompt injection can make it read every file and use every reachable service. Treat the workspace,
Git history, downloaded packages, logs, and data returned to the worker as exportable. The goal is
to keep reusable workstation and upstream credentials outside that boundary and to limit the
model and service access a compromised job can exercise. The operator controls which data a job
receives and which operations it may request. A secret pasted in chat or embedded in an admitted
file is already inside the worker boundary.

[I3](prd_i3.md#credential-access) already calls for isolated homes, an environment allowlist, and
job-scoped broker grants. [I4](prd_i4.md#gateway) places upstream sign-in and credentials on the
host. L1 and M1 specify protocol adapters and request policy. The [offline approval core](prd_i3.md#offline-approval-core),
[L1 broker spikes](prd_l1.md), and [local OpenCode proof](spikes/m/local/README.md#joint-coordhub-proof)
provide component evidence, including synthetic inference and revocation. The regular launcher
still shares `oc-home`, forwards selected model API keys, and permits normal OpenCode sign-in.
The requirements below govern a future managed launch. The live provider adapters, subscription
sign-in lifecycle, and SSH onboarding remain with the [Outside-in integrations](README.md#workstream-reservations) owner.

## Requirements

- [ ] **Start with a clean, private worker home.** Enforce a host-controlled allowlist for
      mounts, environment, sockets, images, and initial files. Exclude shared `oc-home`, host
      login and keyring state, SSH and password-manager agents, host browser profiles, container
      engine sockets with host authority, upstream credentials in environment variables, and
      credential-bearing Git or package-manager configuration. Apply the same boundary to
      sidecars and processes they can launch. Seed from approved inputs. Never copy the legacy
      home or import its auth database, session history, browser state, or plugins into a managed
      job. Preserve the old volume separately and tell the operator how to revoke previously
      exposed provider sessions. Use a separate managed resource identity and a host-owned launch
      record. Before reporting readiness or granting access at launch or reuse, verify the
      effective pod, worker and sidecar identities, mounts, environment, and network and egress
      settings against the approved job incarnation. Refuse an already-running legacy or
      manual instance, and refuse missing or mismatched records. A managed worker restart
      may recover its own job state only.
- [ ] **Put account connection in a trusted workstation surface.** An operator may initiate
      `/connect` from the host orchestrator UI if the credential exchange, storage, refresh, and
      upstream calls run under a host identity isolated from workers and any untrusted
      orchestrator tools. Require a direct operator action in that trusted surface. Bind each
      short-lived, single-use sign-in transaction to the initiating operator session and chosen
      provider and broker route. Verify the callback or device-flow completion against that
      transaction and the provider's documented flow. Reject unsolicited, expired, mismatched,
      or replayed completions. Worker events may report a missing connection. Only the
      operator can authorize sign-in. Connecting an account issues zero worker grants. The UI
      exposes connection state and provider choice. Login redirects, auth databases, refresh
      tokens, and any browser automation for sign-in stay on the trusted side. The sandbox
      receives only the gateway endpoint and its job access. Signing in through
      a host browser on behalf of an in-worker OpenCode server still delivers credentials to the
      worker and is outside this flow.
- [ ] **Block native provider connection in managed mode.** Where OpenCode supports it, make
      `/connect` and `opencode auth login` return instructions to use the workstation. Enforce
      the boundary outside OpenCode as well. Worker-writable settings, plugins, alternate clients,
      shell commands, and the sandbox Chromium must not be able to reach provider sign-in, token
      exchange, or inference routes directly. Use L1's default-deny managed egress with approved
      relays and explicit exceptions reviewed for their effect on the guarantee, including
      any general-purpose proxy that could restore direct reachability. Treat a worker
      with unrestricted outbound internet and a browser as capable of direct sign-in. Report
      platforms that cannot enforce this as ineligible for managed use. Full tool access inside
      the job remains supported.
- [ ] **Bind model and service access to the actual job connection.** The trusted gateway
      validates the authenticated worker and job incarnation before applying the permitted route,
      models, request and usage limits, and expiry. Reject a copied job identifier or bearer
      on an independently established channel, including channels from a sibling job, an
      external client, or a later incarnation.
      Use a private local channel or a remote equivalent authorized outside the worker, and
      revalidate grants and close in-flight streams on revocation under I3. A compromised job
      can still exercise its authorized operations and spend its quota on the original channel
      while active, including by relaying another party's instructions. Return bounded results
      and redacted failures without exposing upstream credentials or sign-in artifacts.
- [ ] **Broker Git and private package access without exporting credentials.** Prefer host-side
      fetch or a typed, read-only route. Apply [I5's fetch and handoff rules](prd_i5.md#repo-and-parent-handoff)
      to one-off, cached, and warmed inputs. Pin the approved Git commit and authorized reachable
      objects or the exact package digest. Use host-owned fetch configuration with pinned origins
      and separately authorized secondary origins, including redirect targets, submodules, and
      Git LFS. Keep authentication in the fetch adapter and filter credential-bearing metadata.
      Process the result in a credential-free environment. Source hooks, filters, and package
      install scripts never run in the credentialed fetch step. Unsupported raw-credential-only
      clients stay unavailable in managed mode until there is a suitable adapter. A caller can
      export private artifacts it has permission to read, so grant the smallest useful source scope.

## Operator choice

- [ ] (decision needed) **Keep legacy direct login available?**
  - **Managed hard block with separate manual opt-in (recommended).** Put any direct provider
    login in an explicit host-side launch mode for a disposable review or trusted project. Show
    which credential becomes accessible to the worker, why, and how the host connection works.
    Require operator confirmation outside the worker and clear the approval at job end. Keep this
    mode's auth state separate from managed jobs. The applicable I4 authorization requirement
    also precedes any live manual subscription smoke test. Pros include a clear boundary and a
    way to run a manual compatibility test. The separate state and UI add roughly 1–2 days after
    managed launch enforcement exists.
  - **Managed-only mode.** Refuse direct provider login with no override in the launcher. This
    has fewer states to test and gives up the manual subscription smoke test in `oc-sandbox`.
    Budget roughly half a day for guidance and acceptance after managed launch enforcement exists.

## Isolation qualification and live-route gates

The isolation checks below use synthetic credentials. Before testing with live credentials, the
route owner records the applicable [I4 provider authorization](prd_i4.md#gateway) for the exact
provider, client, topology, authentication flow, endpoint, entitlement, and billing. Apply the
[Claude Stage 0 requirement](prd_i4.md#feasibility-spike--host-only-claude-subscription-routing)
when relevant. Before enabling a live route, the owner records adapter and placement qualification
and maintainer acceptance. For model routes, include [M1 verification](prd_m1.md#failure-recovery-and-verification-tests)
of provider-side tool restrictions and paid-fallback controls. Keep a route disabled while any
applicable gate is open.

- [ ] With synthetic upstream credentials, inventory worker-visible mounts, image layers,
      environment, process arguments, files, browser state, and diagnostics. Include another
      job and a new incarnation. Verify inherited credentials and legacy data are excluded.
      Request a managed launch while a legacy instance of the same display name is running.
      Verify that the legacy instance is neither reused nor granted access. Repeat with an
      unverifiable managed launch record and require refusal before granting access.
- [ ] Exercise workstation connection and one brokered streamed turn. Verify native sign-in is
      unavailable in the worker and that host-enforced network policy covers alternate clients.
      Verify who holds the upstream credential using a test provider and synthetic markers.
      Exercise unsolicited, expired, mismatched, and duplicate callbacks or device completions.
      Verify worker events cannot authorize sign-in or replace the provider or broker route, and
      a successful login makes no worker grant active.
- [ ] Verify an authorized in-job call succeeds. Submit the same job credential on a sibling
      or external channel and require rejection. Verify the original channel is rejected upon
      job retirement or revocation and a new incarnation cannot reuse its grant. Check that
      usage limits and revocation apply even while streaming. Repeat on each supported placement.
- [ ] Verify a worker can receive an authorized private artifact while credentials stay on the
      host. Require denial for an out-of-scope artifact on an approved origin and for an
      unapproved secondary origin. Verify credentialed fetch executes no project or package
      code. Check the manual mode warning and separation if that mode ships.

Review implementation choices and the walkthrough under the [PRD gates](README.md#implementation-review-gates).
The final human review stays with [PRD I](prd_i.md).
