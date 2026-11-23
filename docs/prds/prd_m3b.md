# prd_m3b: Tauri desktop dashboard

Parent: [prd_m3](prd_m3.md) · follows: [prd_m3a loopback dashboard](prd_m3a.md)

Package the qualified SvelteKit static SPA in Tauri v2. Reuse the same views and typed data
contract. The desktop client uses a narrow native transport to the daemon's host-only socket,
with peer identity enforced on the daemon side. The loopback build remains independently usable.

- [ ] Package bundled UI assets and pin build toolchains. Scope the Rust bridge to explicit,
      typed daemon operations and bounded events. Verify daemon peer identity and use
      host-authorized approvals for any privileged operations. Give the WebView no generic
      filesystem, shell, HTTP, clipboard or raw socket access.
- [ ] Run identical read-only fixtures in the loopback browser and the packaged app. Test
      hostile event text, reconnect, expiry, and strict CSP in the production builds. On Linux
      WebKitGTK, measure cold launch to the first populated sandbox list and usable keyboard
      navigation. Check macOS WKWebView when qualifying desktop support there.
- [ ] Qualify native PTY and managed browser views when their [M3 confinement gates](prd_m3.md#concrete-gaps-and-checkboxes)
      are ready. Keep agent-controlled pixels and terminal data outside the privileged
      dashboard surface and require the daemon's approved input leases.

[Tauri WebView engines](https://v2.tauri.app/reference/webview-versions/)
