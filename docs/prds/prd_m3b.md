# prd_m3b: Tauri desktop dashboard

Parent: [prd_m3](prd_m3.md) · shares the SPA with: [prd_m3a loopback dashboard](prd_m3a.md) ·
order: [control-plane decision](prd_m.md#control-plane-decision)

Package the qualified SvelteKit static SPA in Tauri v2. Reuse the same views and typed data
contract. The desktop client uses a narrow native transport to the daemon's host-only socket,
with peer identity enforced on the daemon side. If Tauri becomes the only shell, loopback
serves fixtures for tests and nothing else. It is a usable dashboard in its own right only where
the [control-plane decision](prd_m.md#control-plane-decision) selects loopback first.

On 2026-11-28 the operator chose Tauri as the only shipping shell. It takes effect if the
[Tauri qualification](#tauri-qualification) below passes, after the shared frontend
qualification has passed ([control-plane decision](prd_m.md#control-plane-decision)). Loopback
then serves fixtures for tests and carries no real authority. Delivery order:
[prd_m](prd_m.md#delivery-order).

## Tech-stack spike

A throwaway probe under `docs/prds/spikes/`, following the spike rules in
[`AGENTS.md`](../../AGENTS.md#branches). It uses synthetic data and a fixture daemon only.

It runs as step 3 of [Wave 0](prd_m.md#wave-0-prove-and-decide), after the code home and pins
are decided and the skeleton is seeded. It has two sets of checks with different consequences.

- [ ] Rerun the pinned generation commands recorded when the base was seeded
      ([prd_m3a3](prd_m3a3.md#skeleton)) and check the result against the seed's generator
      manifest. Then work on a copy of the base as committed, installed frozen from the base
      lockfile. The OpenCode client is not selected. The probe never edits the seeded base. Its
      findings are applied there afterwards, in step 4.
- [ ] Build the scratch variants on that copy, each with its own frozen lockfile: one for each
      Storybook framework and one with `devtools`
      ([prd_m3a3](prd_m3a3.md#order-of-work)). They stay in the spike.
- [ ] Run the [shared frontend qualification](prd_m3a3.md#shared-frontend-qualification) first.
      It does not depend on the shell, and both shells need it. If one of its must-pass checks
      fails, stop UI work and return to the operator. Do not run the Tauri checks, and do not
      fall back to loopback.

### Tauri qualification

Run only after the shared frontend qualification passes. The checks are in two groups.

#### Must pass

A failure of any of these, and only of these, selects loopback first, subject to its sign-in
qualification ([control-plane decision](prd_m.md#control-plane-decision)).

- [ ] The SvelteKit static build packages in Tauri v2 on Linux WebKitGTK, and starts and
      changes routes under the strict desktop CSP with no violation reported.
- [ ] A fixture daemon is called through a typed Rust bridge over a host-only socket with the
      peer check. The WebView has no filesystem, shell, HTTP or clipboard access.
- [ ] One observe-only sandbox browser frame paints on a canvas inside a null-origin confined
      iframe, and the iframe's script pinning works in this engine
      ([Gate 2 reminder 3](prd_m.md#review-record)).
- [ ] Async Svelte works in the client-rendered static build inside the packaged WebView.
- [ ] The automation build can be driven from an agent through WebDriver against the fixture
      daemon, and it refuses a real `$STATE` and the real daemon socket.
- [ ] **Release-build remote-control isolation.** On a release build of the probe, no WebDriver
      server, no inspector endpoint and no other remote-control endpoint is reachable. That
      holds with `WEBKIT_INSPECTOR_SERVER` and `WEBKIT_INSPECTOR_HTTP_SERVER` set and with
      debugging settings present in configuration. Developer extras are off. Input sent through
      such an endpoint counts as genuine user input, so a reachable one could press Approve in
      the Tier A inbox. Tauri only is not chosen until this passes. The same check is repeated
      on every release artifact under [packaging](#packaging-and-qualification).
- [ ] The Tauri release artifacts contain no fixture data and no fixture transport, and a
      release configuration cannot select that transport
      ([prd_m3a3](prd_m3a3.md#code-home)).

#### Recorded, not decisive

These are written down and feed later work. None of them selects the shell.

- [ ] Which CSS the [locked design](spikes/m/dashboard-design/DESIGN.md#engine-notes) relies on
      that this engine lacks. This feeds the design.
- [ ] Mount one [UI SDK](prd_m3a2.md) primitive and check its styles load without
      `unsafe-inline` or style attributes. This is the
      [M3a2 qualification](prd_m3a2.md#qualification) question for WebKitGTK. Its Chromium half
      is in the [shared frontend qualification](prd_m3a3.md#feeds-the-ui-sdk-decision-only). A
      failure selects another option in the [UI SDK decision](prd_m3a2.md#open-decision).
- [ ] What an agent can and cannot observe through WebDriver on the packaged app, compared with
      a DevTools client on the same static bundle in Chromium on a loopback fixture server.
- [ ] Every remote-control endpoint the pinned WebView build can expose. Tauri documents
      WebDriver on Linux. WebKitGTK has its own remote inspector, started by the two
      environment variables above when the application enables developer extras. Whether that
      build offers any Chrome DevTools Protocol endpoint is an open question until it is checked
      on the pinned version. Do not carry an assumption either way into the design. Whatever is
      found here is added to the release-build isolation check.
- [ ] Cold launch to the first populated sandbox list.

Record the result of each set of checks separately, and the resulting decisions: the shell
order in [prd_m](prd_m.md#control-plane-decision) and the UI SDK choice in
[prd_m3a2](prd_m3a2.md#open-decision).

## Packaging and qualification

- [ ] Package bundled UI assets and pin build toolchains. Grant the Rust bridge only to the
      named dashboard WebView and bundled app origin. Verify that subframes and other
      WebViews cannot invoke it. Keep the daemon credential in Rust. Peers must prove both
      the expected OS identity and the scoped daemon principal. The daemon authorizes each
      operation and target. Initially allow only typed projection reads and bounded event
      subscriptions. Gate privileged operations separately. Give the WebView no generic
      filesystem, shell, HTTP, clipboard or raw socket access.
- [ ] Run identical read-only fixtures in the loopback browser and the packaged app. Verify a
      production desktop deep link starts with CSP restricted to bundled assets and required
      platform IPC, and rejects unapproved connections. Exercise hostile event text, denied
      bridge calls from an unprivileged WebView or frame, and an invalid daemon credential.
      Apply the [M3a session-generation fence](prd_m3a.md) on desktop reconnect, logout and
      expiry. Test that late replies and queued events from a retired session cannot repaint
      the view after a fresh session starts. On Linux WebKitGTK, measure cold launch to the
      first populated sandbox list and usable keyboard navigation. Check macOS WKWebView
      when qualifying desktop support there.
- [ ] Qualify native PTY and managed browser views when their [M3 confinement gates](prd_m3.md#concrete-gaps-and-checkboxes)
      are ready. Keep agent-controlled pixels and terminal data outside the privileged
      dashboard surface and require the daemon's approved input leases.
- [ ] Qualify the shared [UI SDK / `data-agent-confirm` bridge](prd_m3.md#3-shared-sveltekit-frontend-loopback-web-auth-and-tauri-v2-uds-bridge)
      inside the packaged Tauri WebView (Linux WebKitGTK and macOS WKWebView). Route authorized
      agent UI commands strictly through the daemon's typed native bridge (zero generic WebView
      eval or unprivileged frame access), verify that agent triggers on `data-agent-confirm`
      controls pop up Trusted Chrome human confirmation even when direct human clicks skip
      confirmation. Verify that agent projection and typed IPC exclude operator-only chrome,
      including self-confirmation and Approval Inbox access. Treat `data-agent-hidden` as defense
      in depth. Retire prompts and bridge transport on desktop session retirement, and enforce
      actor-bound authorization independently in the Rust IPC layer and host daemon according
      to [M3a2](prd_m3a2.md).
- [ ] Agent-driven debugging and testing use a separate test build. Enable remote control
      (WebDriver or an inspector) only through a build-time feature that is absent from release
      builds, and bind that build to a fixture daemon so it refuses a real `$STATE`. Input sent
      through WebDriver or a DevTools client counts as genuine user input, so a control port on
      the live app could press Approve in the Tier A inbox. There is no runtime flag for this.
      For full DevTools tooling, run the same static bundle in Chromium against fixtures.
- [ ] Qualify release isolation on the release build itself. This check stands whatever the
      spike finds about Chrome DevTools Protocol support.
  - No WebDriver server and no inspector endpoint is reachable, including when the inspector
    environment variables are set and when debugging settings are present in configuration.
    Developer extras are off and the `devtools` feature is absent.
  - Repeat the check on every release artifact and after each Tauri or WebView upgrade.
  - Check every release artifact for fixture data and the fixture transport as well, and that
    a release configuration cannot select that transport ([prd_m3a3](prd_m3a3.md#code-home)).
- [ ] Qualify the automation build's confinement. It connects only to the fixture daemon: it
      refuses a real `$STATE` and the real daemon socket, and it carries no real daemon
      credential. Add a negative test that points it at each and expects a refusal.

[Tauri WebView engines](https://v2.tauri.app/reference/webview-versions/) ·
[UI SDK](https://ui-sdk.dev)
