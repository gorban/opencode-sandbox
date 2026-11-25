# prd_m3a2: UI SDK agent bridge and agent-readable dashboard markup

Parent: [prd_m3a](prd_m3a.md) · sibling: [prd_m3a1 dashboard design](prd_m3a1.md) ·
detail for: [Gap M3.5](prd_m3.md#concrete-gaps-and-checkboxes) ·
packaged by: [prd_m3b](prd_m3b.md)

[M3 §3](prd_m3.md#3-shared-sveltekit-frontend-loopback-web-auth-and-tauri-v2-uds-bridge)
specifies the agent-assisted dashboard control and asymmetric `data-agent-confirm`
confirmation. This child records what the current UI SDK release actually provides, and what
that means for design, markup and the security review. Authority stays in `oc_daemon`,
`oc_controller` and the Tauri Rust IPC layer. Nothing here grants new authority.

## What UI SDK provides today (checked 2026-11-25)

Sources: [UI SDK docs](https://ui-sdk.dev), [agent reference](https://ui-sdk.dev/docs/agents/connect-an-agent/reference),
`@ui-sdk/core` and `@ui-sdk/svelte` `0.1.0-beta.17` tarballs. Re-verify at Gate 1.

- **Maturity:** first npm release on 2026-11-12, published almost daily since. Apache-2.0.
  Expect API changes. Svelte adapter peer is `svelte >=5.33`.
- **Shape:** headless, unstyled primitives (about 70 Svelte subpath entries such as `select`,
  `tabs`, `dialog`, `button`, `field`) plus an agent layer. `@ui-sdk/svelte/agent` re-exports
  the core `createAgent`, `registerTools` and `agentTools`. There is no Svelte-specific
  agent component.
- **Agent API:** `createAgent({ allow, timeout })` returns `snapshot`, `query`, `act`,
  `subscribe` and `tools`, with no `destroy`. `act` runs steps in order and stops at the first
  failure, but earlier steps stay applied, so it is **not transactional**. `allow(step)` runs
  before each resolved action, including tabs or sections the bridge opens to search.
  Change callbacks receive `details.source` (`agent`, `keyboard`, `mouse`, …) and can cancel.
- **Visibility:** only UI SDK components (or primitives registered with an `agent` key) appear
  in `snapshot()`. Plain elements are invisible. Names come from ARIA labels, `section` from
  labelled regions, tabs, accordions and fieldsets, `row` from row text. The snapshot is capped
  at 100 components and `query` lists at most 50 items.
- **Markup:** exactly three attributes exist: `data-agent-confirm="<sentence>"` (covers the
  element and its subtree), `data-agent-hidden` (removes the subtree from snapshot and query)
  and `data-agent-secret` (shows `[redacted]`, but the agent can still type into it).
  There is no `data-agent-label` or `data-agent-description`.
- **Default is permissive:** without `allow`, every supported action except
  `data-agent-confirm` targets is accepted. An `allow` that returns `true` without checking
  `step.confirm` approves on the operator's behalf.
- **Transport:** the bridge runs in the page only. Options are our own tool loop,
  WebMCP via `registerTools` (`document.modelContext`), or `window.agent`. There is no
  postMessage, WebSocket or MCP server in the package.
- **CSP:** no `eval` or `new Function` found. It injects component CSS at mount. Without
  `style-src 'unsafe-inline'` it uses constructed stylesheets when a nonce-less
  `<meta property="csp-nonce">` is present. The `Preferences` component renders an inline
  script on the server. Snapshot `source` locations exist only in development builds.

## Requirements

### Markup rules for every dashboard view (needed even before the bridge ships)

- [ ] Give every interactive control a unique, stable accessible name, and label every
      region (`aria-labelledby` headings, fieldsets with legends). Repeated per-row controls
      carry row context (for example, "Revoke grants for `build-a`").
- [ ] Mark protected controls with `data-agent-confirm="<impact summary>"`, using the list in
      [M3 §3](prd_m3.md#3-shared-sveltekit-frontend-loopback-web-auth-and-tauri-v2-uds-bridge).
      Wrap whole danger zones where a section contains several protected controls.
- [ ] Mark the confirmation modal, Tier A Approval Inbox, sign-in and bootstrap chrome, and
      provider credential flows `data-agent-hidden`. Mark displayed secrets
      `data-agent-secret` and keep secret inputs out of agent-reachable views entirely,
      because a secret-marked field can still be typed into.
- [ ] Make each protected action a single, idempotent step whose effect is confirmed by the
      daemon, because `act` cannot roll back earlier steps.
- [ ] Keep each view under the snapshot cap by sectioning and paging long lists, and give
      `Select` controls their `items` so choices are readable while closed.

### Bridge security

- [ ] Run the bridge only for a host-authorized orchestrator session brokered by `oc_daemon`.
      Implement our own tool transport over the daemon channel. Never call `registerTools`
      (WebMCP would expose the dashboard to any browser-level agent), and never assign the
      agent to `window` or any global.
- [ ] Always supply `allow`. It denies by default, sends every `step.confirm` action to the
      Trusted Chrome confirmation modal, accepts only trusted human input there, binds the
      decision to the exact action, target, parameters and session generation, and fails
      closed on cancel, timeout, drift or session retirement.
- [ ] Validate changes in component callbacks using `details.source`, because agent actions
      call component APIs directly and bypass keyboard and click handlers.
- [ ] Treat `snapshot()` and `query()` output as untrusted data when returning it to `-o`.
      It contains page text, including agent-authored text. Wrap it in the nonce-framed
      untrusted-data blocks used elsewhere in M and N.
- [ ] Verify that production builds omit development `source` locations and
      `data-review-loc`, and that no `Preferences` inline script is emitted.
- [ ] Pin exact package versions in the lockfile, verify the licence and integrity, and
      review the resolved dependency tree at each upgrade ([prd_f](prd_f.md)).

### Qualification

- [ ] Prove constructed-stylesheet injection works under the enforcing `style-src 'self'` CSP
      in Chromium and WebKitGTK without adding `unsafe-inline` or `style-src-attr`. If it
      cannot, return the CSP change to security review before adopting the primitives.
- [ ] Measure the added bundle size on the loopback fixture and keep the agent module lazily
      loaded only for orchestrator-enabled sessions.
- [ ] Test hostile cases: an agent pressing a `data-agent-confirm` control, attempting to
      inspect or click the confirmation modal, typing into a secret field, a multi-step `act`
      that fails halfway, a confirmation left open across logout, and tampered DOM attributes
      that the daemon still rejects.

## Open decision

- [ ] (decision needed) **How much of the dashboard is built on UI SDK primitives.**
  - **UI SDK primitives for interactive controls, behind a thin local adapter (recommended,
    if the CSP qualification passes).** Agent visibility and accessible keyboard behaviour come
    from one source, and the adapter isolates us from beta API churn. Adds a young dependency
    with frequent releases. ~3–5 days, including the adapter and CSP qualification.
  - **Our own Svelte primitives, registering only selected controls with the agent layer.**
    Full control over markup, styling and size. More accessibility work, and the agent sees
    only what we register. ~5–8 days.
  - **Defer the bridge; ship only the markup rules above.** No dependency now, and the design
    stays compatible with either option. No agent-assisted control until later. ~0.5 day.
