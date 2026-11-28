# prd_m3a: SvelteKit loopback dashboard

Parent: [prd_m3](prd_m3.md) · follows: [M3.1 read-only projection](prd_m3.md#concrete-gaps-and-checkboxes) ·
next: [prd_m3b Tauri desktop](prd_m3b.md) · children:
[prd_m3a1 product design, design system and accessibility](prd_m3a1.md),
[prd_m3a2 UI SDK agent bridge and markup](prd_m3a2.md),
[prd_m3a3 frontend foundation, style guide and test pyramid](prd_m3a3.md)

The skeleton, conventions and tests every view follows are in [prd_m3a3](prd_m3a3.md). Views
start from that foundation, not from the hand-built [web-ui spike](spikes/m/web-ui/README.md).

Design work for this SPA runs ahead of implementation in [prd_m3a1](prd_m3a1.md). Moving
Chromium launches into the app (embedded browser views and the Browser Wall) is not part of
this phase.

On 2026-11-28 the operator chose Tauri as the only shipping shell, taking effect if the
[tech-stack spike](prd_m3b.md#tech-stack-spike) passes
([control-plane decision](prd_m.md#control-plane-decision)). In that case this phase keeps the
static SPA, its view rules and a loopback fixture server for tests. The loopback sign-in
qualification and the cookie port-sharing item below wait until loopback is asked to carry real
authority again. Delivery order: [prd_m](prd_m.md#delivery-order).

Ship the first dashboard as a SvelteKit static single-page application. Use the static adapter for
build output and client-side rendering for live routes. The host daemon serves static assets and
the authenticated API on one loopback origin. Node is build tooling. The packaged app has no
SvelteKit server, server routes, server actions or runtime SSR. Load live state through a typed
client whose web implementation uses the daemon's existing authority boundaries. Route fallbacks
serve the dashboard only for UI paths. API and event paths have explicit handlers.

- [ ] Build the read-only `Project → Sandbox → Thread` view against synthetic projection data
      first. Show bounded status, mailbox and provenance entries. Render agent-supplied text as
      text with uniform escape-by-default rendering for every dynamic and fixture field. Restrict
      in-page navigation strictly to declared SPA routes (never fetch or adopt arbitrary
      same-origin `.html` bodies or untrusted paths). Namespace all data-derived DOM element IDs
      so entity identifiers can never collide with host-chrome control IDs (such as Confirm or
      Approve controls). All API state and authorization come from the host daemon. Keep private
      state (including sandbox, project and branch names) out of the static bundle, URLs and
      `document.title`. Disable storage or caching of private responses. Implement sign-out as an
      authenticated `POST` mutation with CSRF verification (never a plain link). Retire the
      session generation on logout or expiry, cancel in-flight requests, close subscriptions,
      and clear all displayed and in-memory state (including drafts, pending confirmations and
      approval UI state). Discard every completion or queued event belonging to a retired
      generation, including after a new login.
- [ ] Qualify actual loopback serving with the [M3 web auth and CSP](prd_m3.md#3-shared-sveltekit-frontend-loopback-web-auth-and-tauri-v2-uds-bridge).
      Bind to loopback, enforce exact Host and Origin checks where specified, exchange a one-use
      bootstrap code for session auth, and require CSRF and scoped WebSocket tickets where
      applicable. Address loopback cookie port-sharing explicitly before shipping web auth:
      host-scoped cookies on `127.0.0.1` ignore ports, and Host/Origin/CSRF checks protect what
      the dashboard accepts but cannot stop the browser sending a cookie to another listener on
      that host (such as an agent-published `-P` app). Either require verified listener and
      addressing isolation that prevents any agent-reachable listener from ever receiving the
      auth cookie, or choose a transport that does not attach credentials across ports, and add
      a synthetic second-listener regression with no real credentials. The daemon supplies the
      authoritative CSP response header (`img-src 'self'` with no `data:` images, explicit
      `font-src 'none'` unless self-hosted fonts are separately reviewed) and aligns its route
      grammar with closed-enum SPA query parameters. Account for generated SvelteKit
      bootstrapping in the actual header with an exact SHA-256 build hash, or load a reviewed
      external bootstrap from the same origin. Any CSP report or fixture test server must reject
      negative or oversized `Content-Length` reads and escape all logged report fields. Verify
      that a production deep link starts under CSP and authentication and rejects unapproved
      connections. Exercise a held reply and queued event delivered after logout or expiry and a
      fresh login. Privileged actions, PTY and browser streams have separate review gates.
- [ ] Prepare the shared SvelteKit components upfront for
      [M3 agent-assisted dashboard control](prd_m3.md#3-shared-sveltekit-frontend-loopback-web-auth-and-tauri-v2-uds-bridge)
      (evaluating [UI SDK](https://ui-sdk.dev) `@ui-sdk/svelte/agent`, Apache-2.0). Mark every
      protected dashboard action with `data-agent-confirm="<impact summary>"`. The daemon
      independently classifies the typed action and initiating actor and requires Trusted
      Chrome human confirmation on the agent path even when the ordinary human path can
      execute directly. Mark the confirmation modal itself, Approval
      Inbox actions, and auth/sign-in controls `data-agent-hidden`, mark sensitive fields
      `data-agent-secret`, cancel open confirmation dialogs on session-generation retirement, and
      keep authoritative enforcement in `oc_daemon` and `oc_controller`. The current UI SDK
      release, its limits and the resulting markup rules are in [prd_m3a2](prd_m3a2.md).
- [ ] Run Lighthouse on a representative authenticated loopback fixture. Measure cold navigation
      to the first populated sandbox list and usable keyboard navigation. Defer terminal and
      browser modules until their views are opened. Consider build-time prerendering of public,
      static content only if measurement shows a useful improvement.

[SvelteKit page options](https://svelte.dev/docs/kit/page-options) ·
[Tauri's SvelteKit integration](https://v2.tauri.app/start/frontend/sveltekit/) ·
[UI SDK](https://ui-sdk.dev)
