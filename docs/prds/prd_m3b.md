# prd_m3b: Tauri desktop dashboard

Parent: [prd_m3](prd_m3.md) · follows: [prd_m3a loopback dashboard](prd_m3a.md)

Package the qualified SvelteKit static SPA in Tauri v2. Reuse the same views and typed data
contract. The desktop client uses a narrow native transport to the daemon's host-only socket,
with peer identity enforced on the daemon side. The loopback build remains independently usable.

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

[Tauri WebView engines](https://v2.tauri.app/reference/webview-versions/)
