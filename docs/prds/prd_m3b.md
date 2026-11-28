# prd_m3b: Tauri desktop dashboard

Parent: [prd_m3](prd_m3.md) · follows: [prd_m3a loopback dashboard](prd_m3a.md)

Package the qualified SvelteKit static SPA in Tauri v2. Reuse the same views and typed data
contract. The desktop client uses a narrow native transport to the daemon's host-only socket,
with peer identity enforced on the daemon side. The loopback build remains independently usable.

On 2026-11-28 the operator chose Tauri as the only shipping shell, taking effect if the spike
below passes ([control-plane decision](prd_m.md#control-plane-decision)). Loopback then serves
fixtures for tests and carries no real authority. Delivery order:
[prd_m](prd_m.md#delivery-order).

## Tech-stack spike

A throwaway probe under `docs/prds/spikes/`, following the spike rules in
[`AGENTS.md`](../../AGENTS.md#branches). It uses synthetic data and a fixture daemon only.

- [ ] Package the SvelteKit static build in Tauri v2 on Linux WebKitGTK under the strict
      desktop CSP. Record which CSS the [locked design](spikes/m/dashboard-design/DESIGN.md#engine-notes)
      relies on that this engine lacks.
- [ ] Mount one [UI SDK](prd_m3a2.md) primitive and check its styles load without
      `unsafe-inline` or style attributes. This is the
      [M3a2 qualification](prd_m3a2.md#qualification) question, answered for WebKitGTK.
- [ ] Call a fixture daemon through a typed Rust bridge over a host-only socket with the peer
      check. Confirm the WebView has no filesystem, shell, HTTP or clipboard access.
- [ ] Paint one observe-only sandbox browser frame on a canvas inside a null-origin confined
      iframe, and check the iframe's script pinning works in this engine
      ([Gate 2 reminder 3](prd_m.md#review-record)).
- [ ] Drive the packaged app from an agent through WebDriver, and drive the same static bundle
      in Chromium on a loopback fixture server with a DevTools client. Record what each can and
      cannot observe.
- [ ] Record every remote-control endpoint the pinned WebView build can expose. Tauri documents
      WebDriver on Linux. WebKitGTK has its own remote inspector, started by
      `WEBKIT_INSPECTOR_SERVER` or `WEBKIT_INSPECTOR_HTTP_SERVER` when the application enables
      developer extras. Whether that build offers any Chrome DevTools Protocol endpoint is an
      open question until it is checked on the pinned version. Do not carry an assumption either
      way into the design.
- [ ] Measure cold launch to the first populated sandbox list.
- [ ] Record the result and the resulting decisions: the shell order in
      [prd_m](prd_m.md#control-plane-decision) and the UI SDK choice in
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
- [ ] Qualify the automation build's confinement. It connects only to the fixture daemon: it
      refuses a real `$STATE` and the real daemon socket, and it carries no real daemon
      credential. Add a negative test that points it at each and expects a refusal.

[Tauri WebView engines](https://v2.tauri.app/reference/webview-versions/) ·
[UI SDK](https://ui-sdk.dev)
