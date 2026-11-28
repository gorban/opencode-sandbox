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
  and `data-agent-secret` (redacts the marked component value, but the agent can still type
  into it). The SDK can collect secret-marked sibling text in another control's `row` field.
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
      because a secret-marked field can still be typed into. Keep sensitive displayed text
      outside browsable SDK subtrees, including row, label, and section context.
- [ ] Render operator-only chrome as first-party, unregistered components outside the SDK
      registry and agent projection. Cover confirmation, both inboxes, bootstrap/sign-in
      and credential flows, the operator composer and target picker, the Input Lease Bar,
      the bridge Pause/Resume control, host-compiled workflow action chips, and logout/session
      controls. Mark the roots `data-agent-hidden` for defense in depth. Apply hidden or
      confirmation markup directly to any portaled root, or disable portal behavior for that
      subtree.
- [ ] Make each protected action a single, idempotent step whose effect is confirmed by the
      daemon, because `act` cannot roll back earlier steps.
- [ ] Keep each view under the snapshot cap by sectioning and paging long lists, and give
      `Select` controls their `items` so choices are readable while closed.

### Bridge security

- [ ] Run the bridge only for a host-authorized orchestrator session brokered by `oc_daemon`.
      Require explicit operator opt-in, off by default, for a single visible tab or
      packaged window. Each opt-in gets a new daemon-owned activation ID. For loopback,
      bind a CSRF-minted single-use WS ticket to
      `agent_ui_bridge`, the activation ID, exact session generation, orchestrator identity, tab and
      target scope. Check exact Host and Origin. For Tauri, use only the native typed
      IPC channel with the registered window and exact WebView origin. Use one step per
      request, at most 16 KiB per bridge message and at most four calls per second per
      active bridge. Paginate projection data within the bound. Reconfirm these choices
      at the M3.5 implementation review. Never call `registerTools` (WebMCP would expose
      the dashboard to browser-level agents), or assign the agent to `window` or any global.
- [ ] Publish a host-owned allowlisted projection scoped to the authenticated actor, session
      generation, bridge activation and permitted targets. Build names, rows, sections and values from typed,
      authorized projection fields. Keep raw SDK DOM-derived snapshots, queries, action
      results, errors and events inside the adapter. Apply the same scope to every result
      and subscription delivery; default subscriptions off and discard retired-generation
      entries. Nonce-frame any agent-authored text the projection explicitly permits.
- [ ] Preserve the initiating actor end to end. The daemon classifies the typed action and
      target independently of markup and browser-supplied source fields. Route agent
      mutations through their restricted actor channel; the bridge cannot borrow the
      ordinary operator session's mutation authority. Missing or out-of-scope actions,
      Tier A approvals, Tier B `OPERATOR_ONLY` resolutions and operator-authored notes
      are denied on the agent channel. Agent input cannot create a `HumanDecisionReceipt`
      or operator provenance ([N3](prd_n3.md)).
- [ ] Always supply a deny-by-default `allow`. For a permitted protected action, the daemon
      initiates Trusted Chrome confirmation. The independent human path accepts trusted
      input and issues a short-lived one-use decision bound to the initiating actor, exact
      typed action, target identity and revision, canonical parameters, bridge activation
      and session generation.
      Consume the decision atomically with authorization of the effect. Fail closed on
      cancel, reuse, timeout, drift or retirement. Use `step.confirm` and `details.source`
      as presentation and defense-in-depth signals.
- [ ] SDK execution is limited to allowlisted local view selection, tabs, view filter/sort,
      and expand/collapse with no mutating API or IPC effects. Block SDK writes to shared
      form state and any callback that can initiate a mutation. Intercept a proposed
      mutation before SDK execution and submit a typed agent-channel intent. The operator
      API client rejects mutating HTTP and IPC calls from agent-originated dispatch
      or continuations and withholds its CSRF token there. The daemon still verifies the
      initiating principal and authorizes the typed intent on its restricted channel.
- [ ] Use single-flight confirmation with no pending queue, at most three requests
      per minute and a five-second cooldown after cancel that stays enforced independently of
      bridge Pause/Resume state (pausing and resuming must not clear or shorten the cooldown).
      Offer an operator-only pause control (outside the SDK registry and marked
      `data-agent-hidden`) that retires the bridge session.
      Suppress unsolicited confirmation when the view is hidden, a text field is active,
      or an operator input lease is in use. Never arm a confirmation modal while the tab or view
      is hidden; cancel an open confirmation when the view loses visibility and require fresh
      input after return. Render text from canonical daemon fields using the direction-isolated
      address component ([prd_m3a1](prd_m3a1.md)).
      Define the 750 ms post-first-paint arming delay as an immutable constant in code (never
      read from a CSS token that can silently fall back on unit changes). Focus placement,
      visible-after-paint arming, fresh trusted activation (`event.isTrusted === true`), and
      post-cancel cooldown complement the daemon's authoritative one-use authorization rather
      than replacing it. Initially focus Cancel or the dialog container and keep Confirm
      disabled until the post-first-paint arming interval has elapsed and initiating input has
      been released. Require a fresh deliberate activation; reject synthetic/script-dispatched
      events, held keys and pointer events predating the dialog, while preserving accessible
      keyboard and assistive-technology activation.
- [ ] Bind intents, decisions, and subscriptions to the exact bridge activation. Recheck
      it with the operator generation and orchestrator identity at every entry and
      continuation, including decision consumption and result publication. Invalidate
      it on pause, transport loss, logout, expiry, or page exit. Retire pending decisions,
      disconnect subscriptions, and discard late callbacks. Require a fresh document if
      the pinned SDK cannot fully detach its listeners or observers.
- [ ] Verify that production builds omit development `source` locations and
      `data-review-loc`, and that no `Preferences` inline script is emitted.
- [ ] Pin exact package versions in the lockfile, verify the licence and integrity, and
      review the resolved dependency tree at each upgrade ([prd_f](prd_f.md)).

### Qualification

- [ ] Prove constructed-stylesheet injection works under the enforcing `style-src 'self'` CSP
      in Chromium and WebKitGTK without adding `unsafe-inline` or `style-src-attr`. If it
      cannot, return the CSP change to security review before adopting the primitives.
- [ ] If adopted, security-review the exact nonce-less `<meta property="csp-nonce">`
      allowance in the strict [static shell manifest](spikes/m/web-ui/scripts/csp.mjs).
      Require the fixed tag with no content or extra attributes. Exercise each adopted
      primitive in both engines under the emitted CSP, including opening and transitions,
      and check for inline style attributes and violations. Repeat on SDK upgrades.
- [ ] Measure the added bundle size on the loopback fixture and keep the agent module lazily
      loaded only for orchestrator-enabled sessions.
- [ ] Test hostile cases: an agent pressing a `data-agent-confirm` control, attempting to
      inspect or click the confirmation modal, typing into a secret field, a multi-step `act`
      that fails halfway, a confirmation left open across logout, and tampered DOM attributes
      that the daemon still rejects.
- [ ] Seed a secret beside an allowed row button and use an out-of-scope sandbox in the
      same fixture. Check that neither appears in projected snapshots, queries, action
      results, errors or any enabled subscription. Check that an action permitted on the
      ordinary operator route still requires confirmation on the agent route, and that
      forged source fields, stale or replayed decisions, and attempts to use Tier A or
      Tier B human paths yield zero mutation, receipts or operator provenance.
- [ ] Add fixture controls for a portaled protected/hidden subtree, delayed SDK continuation
      trying the operator API, shared-form poisoning, synthetic/untrusted pointer and click
      dispatch on Confirm and Approve controls, held Enter/Space across modal opening,
      opening a modal in a hidden tab, Pause/Resume during the five-second cooldown, unknown
      approval scope keys, prompt floods, hidden or busy views, ticket replay or wrong tab, and
      stale actions or subscription deliveries after logout and fresh login. Verify zero
      operator mutations and no stale disclosures, and confirm legitimate keyboard and
      assistive-technology activation still succeeds.
- [ ] Hold an approved decision and a queued subscription result across pause and re-enable
      in the same tab without logout. Reject both old items and prove a fresh request on
      the new activation works. Repeat for transport loss and reconnect. Hide the view with
      a confirmation open and verify returning cannot consume that confirmation.

## Open decision

The [tech-stack spike](prd_m3b.md#tech-stack-spike) answers the CSP question for WebKitGTK and
feeds this decision. It is a Wave 0 blocker in the [delivery order](prd_m.md#delivery-order),
because every view builds on the chosen primitive layer. The primitives tier and the selector
rule it must satisfy are in the [style guide requirements](prd_m3a3.md#style-guide).

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
