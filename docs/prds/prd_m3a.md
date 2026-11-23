# prd_m3a: SvelteKit loopback dashboard

Parent: [prd_m3](prd_m3.md) · follows: [M3.1 read-only projection](prd_m3.md#concrete-gaps-and-checkboxes) ·
next: [prd_m3b Tauri desktop](prd_m3b.md)

Ship the first dashboard as a SvelteKit static single-page application. Use the static adapter for
build output and client-side rendering for live routes. The host daemon serves static assets and
the authenticated API on one loopback origin. Node is build tooling. The packaged app has no
SvelteKit server, server routes, server actions or runtime SSR. Load live state through a typed
client whose web implementation uses the daemon's existing authority boundaries. Route fallbacks
serve the dashboard only for UI paths. API and event paths have explicit handlers.

- [ ] Build the read-only `Project → Sandbox → Thread` view against synthetic projection data
      first. Show bounded status, mailbox and provenance entries. Render agent-supplied text as
      text. All API state and authorization come from the host daemon. Keep private state out of
      the static bundle and URLs. Disable storage or caching of private responses and clear
      in-memory state on logout or session expiry.
- [ ] Qualify actual loopback serving with the [M3 web auth and CSP](prd_m3.md#3-shared-sveltekit-frontend-loopback-web-auth-and-tauri-v2-uds-bridge).
      Bind to loopback, enforce exact Host and Origin checks where specified, exchange a one-use
      bootstrap code for the strict session cookie, and require CSRF and scoped WebSocket tickets
      where applicable. The daemon supplies the authoritative CSP response header. Account for
      generated SvelteKit bootstrapping with an exact build hash or reviewed external script.
      Verify that deep links preserve CSP and authentication, with no wildcard or unsafe-inline
      allowance. Privileged actions, PTY and browser streams have separate review gates.
- [ ] Run Lighthouse on a representative authenticated loopback fixture. Measure cold navigation
      to the first populated sandbox list and usable keyboard navigation. Defer terminal and
      browser modules until their views are opened. Consider build-time prerendering of public,
      static content only if measurement shows a useful improvement.

[SvelteKit page options](https://svelte.dev/docs/kit/page-options) ·
[Tauri's SvelteKit integration](https://v2.tauri.app/start/frontend/sveltekit/)
