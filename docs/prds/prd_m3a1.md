# prd_m3a1: Dashboard product design, design system, and accessibility

Parent: [prd_m3a](prd_m3a.md) · siblings: [prd_m3a2 UI SDK agent bridge](prd_m3a2.md),
[prd_m3a3 frontend foundation and style guide](prd_m3a3.md) ·
related: [M3 control plane](prd_m3.md), [M3b Tauri desktop](prd_m3b.md),
[N3 Human Inbox and `oc-ui@1` surfaces](prd_n3.md), [I1 operator dashboard](prd_i1.md)

Design the shared SvelteKit static SPA once, for both the loopback dashboard and the Tauri
WebView. Which shell ships first is set by the
[control-plane decision](prd_m.md#control-plane-decision). This PRD owns screens, interaction patterns, the visual language, design tokens,
accessibility and the design selection process. It does not change protocols, authority or
the M3 security design. Where a design need appears to conflict with a security requirement,
the security requirement wins and the conflict is recorded here as an open item.

## Scope

In scope:

- The functional-first main screen and shell, the `Project → Sandbox → Thread` hierarchy and the
  pinned Root Orchestrator (`-o`) view ([M3 §1](prd_m3.md#1-unified-state-hierarchy-oc_daemonpy--stateregistrysqlite)).
- Trusted Host Chrome: the Tier A Approval Inbox, Tier B Human Inbox drawer, Tier C Health
  Ribbon, Global Quota Bar, Revoke Grants and Input Lease Bar
  ([M3 §3](prd_m3.md#3-shared-sveltekit-frontend-loopback-web-auth-and-tauri-v2-uds-bridge),
  [N3 §1](prd_n3.md#1-three-tier-human-inbox-strict-separation-from-oc_controller-approvals)).
- The thread view, provenance badges, target picker and composer, and the diff drawer
  ([M3 §2](prd_m3.md#2-symmetric-human--root-orchestrator-messaging--full-key-write-ahead-provenance)).
- The visual design of the closed `oc-ui@1` component catalog and its provenance pills
  ([N3 §2](prd_n3.md#2-declarative-dashboard-surfaces-oc-ui1--zero-untrusted-js-in-trusted-host-chrome)).
- Sign-in with the bootstrap code, session expiry, logout and reconnect.
- The agent-triggered confirmation modal from [prd_m3a2](prd_m3a2.md).
- Frame chrome for the confined terminal tab (title, Input Lease state, detach). The emulator
  itself stays with [Gap M3.3](prd_m3.md#concrete-gaps-and-checkboxes).

Out of scope at this phase:

- Moving existing Chromium launches into the app: the embedded `Browser` tab, the PiP Browser
  Wall and the CDP arbiter ([Gap M3.4](prd_m3.md#concrete-gaps-and-checkboxes)). The shell keeps
  a labelled, hidden-by-default slot for them so adding them later does not reflow the
  information architecture.
- M3.1 projection, daemon authentication and Tauri bridge implementation (other reservations).

## Users and primary jobs

The primary user is one operator on a workstation, running several local and remote sandboxes
and a root orchestrator, often for hours, while switching between other tools. Design for
these jobs in priority order:

1. **Triage at a glance.** Within five seconds of opening the dashboard, see which sandboxes need
   me (pending approvals, Human Inbox items, stalls, errors, quota pressure), and which are
   healthy.
2. **Act on a decision safely.** Open an approval or Human Inbox item, see exactly what will
   happen, and approve, deny or defer it without leaving context.
3. **Follow work.** Read a sandbox's thread with clear provenance, expand tool calls and
   subagent threads, and see diffs.
4. **Direct work.** Send a message to an unambiguous target (`NAME`, `REMOTE / NAME`, `@PEER`).
5. **Watch long runs.** Monitor workflow surfaces and health without notification noise.

## Product design requirements

### Shell and information architecture

- [ ] Use a persistent left sidebar tree (`Project → Sandbox → Thread`, Scratch / Ad-hoc group,
      pinned `-o`) with keyboard tree navigation (WAI-ARIA tree pattern, type-ahead) and a
      collapsible narrow mode. Show per-sandbox status and attention counts in the tree.
- [ ] Give the workspace header a fixed, host-owned layout for the Approval Inbox count, Human
      Inbox count, Health Ribbon and Quota Bar. Layout changes, orchestrator overlays and
      `oc-ui@1` surfaces can never move, cover or restyle it ([I1](prd_i1.md#dashboard)).
- [ ] Make the default landing screen a dense **Fleet overview**: a sortable table of sandboxes
      with status, attention, model and variant, last meaningful activity, health signal and
      active grants. Prefer tables and lists over card grids. Filters, sort and selected tab
      live in the URL only as closed-enum generic view parameters. Keep free text and
      project, sandbox, branch and other private identifiers out of URLs and history.
- [ ] Open the sandbox detail as tabs: Threads, Diff & Checkpoints, Terminals, and later
      Browser. Keep tab state above the panels so switching tabs cannot discard typed input.
- [ ] Use a right-hand drawer for diffs and Human Inbox items, so the thread stays visible.

### Trusted Chrome visual language (anti-spoofing)

Agent-supplied text, orchestrator overlays and sandbox output must not be able to look like
host chrome.

- [ ] Reserve a visual vocabulary for host-owned components only: the lock glyph, approval
      colour roles, provenance badge shapes, the Input Lease Bar and the confirmation modal
      frame. Never render agent-supplied text inside those components without a label naming
      its source.
- [ ] Render provenance badges (`[Operator]`, `[Orchestrator -o]`, `[Peer: <addr>]`,
      `[TUI Input · In-Sandbox]` amber, `[Sandbox-Local / Unverified]` warning) and the
      `[Deterministic Workflow]` / `[Orchestrator Overlay]` pills as distinct, host-rendered
      components with text, not colour alone.
- [ ] Bound every untrusted content region (thread bodies, overlay Markdown, tool output) in a
      visibly distinct container that cannot extend over chrome, use the reserved glyphs, or
      draw full-width banners. Inert Markdown rendering rules stay as specified in M3.
- [ ] Visually distinguish Tier A (blocking, cryptographic, red/lock), Tier B (non-blocking,
      amber/blue) and Tier C (transient pills) so they cannot be confused at a glance.

### States, content and resilience

- [ ] Design loading, empty, error, stale, offline, revoked and permission-denied states for
      every data region, plus session expired, logged out and reconnecting for the whole app.
      Show staleness explicitly (for example, "updated 2 min ago") rather than freezing silently.
- [ ] Handle long and hostile text and prevent target identity collisions:
      key the composer target picker, per-target drafts, Send label, same-name twin detection
      and protected-action summaries strictly on host-minted opaque identifiers (never on cleaned
      or stripped display text), and derive local vs. remote and peer vs. sandbox kind solely from
      typed projection fields (never by parsing display prefixes). Sanitize C0, DEL, C1,
      bidi-control and invisible zero-width formatting characters across the full PRD codepoint
      set before direction isolation with `<bdi>`, preferring to preserve joiners needed by
      display languages while keeping identity and disambiguation trusted and separate. Reject
      disallowed control characters at the host grammar or replace removed characters visibly,
      compute same-name twin warnings on the normalized display form, and always surface an
      explicit trusted host discriminator whenever two targets share or collide on normalized
      display text (even when normalization operates as designed). Never silently default a
      missing or unknown target to the first item in the list; fail closed with submission
      disabled until the operator selects a live target. Construct every host sentence embedding
      a target, project or sandbox name (confirmation target, impact line, same-name warning,
      Send label) from a dedicated direction-isolated address component (`<bdi>`). Keep sandbox,
      project and branch names out of `document.title`. Use hostile synthetic fixtures and follow
      the existing [rendering walkthrough](spikes/m/web-ui/WALKTHROUGH.md) for thread bodies.
- [ ] Apply fresh-press deliberate-activation checks (`event.isTrusted === true`) to Tier A
      Approval Inbox Approve controls as defense in depth alongside daemon authorization; never
      auto-advance the next pending approval item under the operator's pointer after an Approve
      or Deny click; fail closed (refuse to render Approve and display an explicit invalid-scope
      error) when an approval carries an unknown or unmapped scope key rather than rendering an
      undefined label. Keep keyboard and assistive-technology activation working in acceptance
      criteria alongside negative synthetic-input tests.
- [ ] Never invent data in prototypes. Use synthetic fixture data shaped like the
      [M3a web-ui fixtures](spikes/m/web-ui/fixtures/workspace.mjs) and the M3 hierarchy.
- [ ] Use tabular numerals for counts, quota and timings. Do not show trend arrows or
      deltas that the host does not compute.
- [ ] Motion only communicates state change, and respects `prefers-reduced-motion`.
      Streaming thread updates must not cause layout shift above the reader's position.

### Platform and security constraints on the design

- [ ] The enforcing CSP is `style-src 'self'` with no inline styles in generated HTML
      ([M3a web-ui walkthrough](spikes/m/web-ui/WALKTHROUGH.md)). Design for external
      stylesheets and Svelte scoped styles only. Keep `form-action 'none'`, `img-src 'self'`
      (no `data:` images) and explicit `font-src 'none'` unless self-hosted fonts are separately
      reviewed. Use no CDN fonts, remote images, icon fonts or third-party embeds. Icons are
      bundled SVG components with text labels. Keep unverified or non-reproducible third-party
      design-skill trees, hook installers and network clients out of the product repository;
      pin and verify every retained build dependency per [prd_f](prd_f.md).
- [ ] Fonts: the production CSP sets `font-src 'none'` by default, so bundled web fonts stay
      blocked unless `font-src 'self'` is separately reviewed. See the font decision below.
- [ ] Render correctly in Chromium (loopback) and WebKitGTK (Linux Tauri), and later
      WKWebView. Avoid CSS features that WebKitGTK does not ship without a fallback, and
      check prototypes in a WebKit engine (for example, Playwright WebKit or GNOME Web).
- [ ] Primary viewports are 1440×900 and 1280×800. Content must reflow without loss at 320
      CSS px wide (WCAG 1.4.10), where the sidebar becomes a drawer.
- [ ] Follow [prd_m3a2](prd_m3a2.md) markup rules so the agent bridge can see controls: every
      control has an accessible name, regions are labelled, and repeated row controls carry
      row context.

### Accessibility (WCAG 2.2 AA)

- [ ] Meet WCAG 2.2 AA in Chromium and WebKitGTK. Pay particular attention to:
      focus visible and not obscured by sticky chrome or drawers (2.4.7, 2.4.11); target size
      at least 24×24 CSS px, aiming for 32–40 px controls (2.5.8); colour never the only status
      cue, with 4.5:1 text and 3:1 non-text contrast in both themes (1.4.1, 1.4.3, 1.4.11);
      single-key shortcuts that can be turned off or remapped (2.1.4); no drag-only
      interactions (2.5.7); and status messages announced without moving focus (4.1.3).
- [ ] Accessible authentication (3.3.8): allow pasting the short-lived bootstrap code
      into the JS-only field with `autocomplete="off"` and no native form submission.
      Show static expiry guidance on the unauthenticated page. Only the CLI may display
      a live bootstrap-code countdown.
- [ ] Throttle live-region announcements for streaming threads and the Health Ribbon so
      screen readers are not flooded. Give the operator a "pause announcements" control.
- [ ] Run an automated and manual WCAG 2.2 AA audit on each finalist design and on the
      implemented build. Record the report and fixes here.
      - Two earlier audits found 7 failures. The full audit of `763cbac` recorded zero
        failures with 2.2.1 still open. The scoped re-audit of `f1902bc` reported the same
        totals. The selected `26d81cf` realigns the shared fleet table footer. The operator
        waived its re-audit. Findings and follow-ups are in the
        [reference design](spikes/m/dashboard-design/README.md). Open: confirm 2.2.1 (backend time
        limits), and audit the implemented build.

## Design system deliverables

- [x] `tokens.css`: colour roles (including reserved Trusted Chrome roles), type scale
      (ratio 1.125–1.2), spacing, radius, elevation, focus ring and motion durations, with
      light and dark values. Every colour and font in components goes through a token.
      `claude/m3a-design-selection`: `out/tokens.css` in the
      [reference design](spikes/m/dashboard-design/README.md), with a 1.125 type scale.
- [ ] Component inventory mapping each dashboard component to its UI SDK primitive or our own
      primitive ([prd_m3a2](prd_m3a2.md)), with states and keyboard behaviour.
- [x] Static prototypes of the screens in scope, using synthetic fixtures and the
      [reference CSP](spikes/m/dashboard-design/README.md#view-and-rebuild).
      `claude/m3a-design-selection` records the generator and checksums for the selected screens.
- [ ] A states sheet, a hostile-content sheet, and the WCAG 2.2 AA report.
      - The generated states sheet (`out/states.html`) and the audit findings (`audit/`) are in the
        [reference design](spikes/m/dashboard-design/README.md). There's no separate hostile-content
        sheet. The states sheet includes an escape and containment specimen for all five
        hostile fixture strings.
- [x] A locked `DESIGN.md` describing the chosen system and the reasons for it, which
      implementation agents read before building M3a views.
      `claude/m3a-design-selection`: [`DESIGN.md`](spikes/m/dashboard-design/DESIGN.md).

## Design supplement

Added on 2026-11-28. The [locked design](spikes/m/dashboard-design/DESIGN.md) covers 16 screens.
The operator treats that design as a UX mockup: the target for look and feel, not an
implementation guide. The build matches it and follows the
[style guide](prd_m3a3.md#style-guide) for how.
The screens below are missing. They extend the locked system: its tokens, trust vocabulary, tiers
and components stay as they are. This is a Wave 0 item in the
[delivery order](prd_m.md#delivery-order).

- [ ] **Workflow list.** Available workflows and active runs, with owner, status and the run
      lease state. The locked "Workflows" page is a specimen sheet of the eight `oc-ui@1`
      surfaces. It stays as the catalog and does not stand in for this.
- [ ] **Workflow definition.** The host-generated diagram of stages, lanes and gates, with the
      effect summary and limits beside it. Mark which stages are LLM lanes, which are
      deterministic host actions and which are human gates
      ([prd_n3](prd_n3.md#4-workflow-views-and-change-review)).
- [ ] **Workflow run.** Where a run is now on that diagram, per-lane state, the step log, and
      links to the lanes' threads, inbox items and approvals.
- [ ] **Change review.** A proposed configuration or workflow revision as a Tier A approval:
      field-level differences, security triggers, and for workflows the diagram before and after
      ([M3 §7](prd_m3.md#7-settings-proposed-changes-and-operator-only-secret-entry)).
- [ ] **Settings.** Effective values with their source, provider instances and their state, and
      the form editor for non-secret settings.
- [ ] **Secret entry.** The operator-only surface for entering a secret, with the slot it fills,
      who asked, and the set or not-set state afterwards. It uses the security frame and is
      hidden from the agent bridge.
- [ ] In the workflow and change-review screens, show authored and agent-originated text
      (names, descriptions, templates, log lines, proposed values) in the untrusted container
      with a source label, and keep host-derived effect and approval labels visibly distinct
      from it ([prd_n3](prd_n3.md#4-workflow-views-and-change-review)).
- [ ] Add each new screen to the states sheet and the hostile-content specimen, and run the
      WCAG 2.2 AA audit on it.
- [x] **Process for the supplement.** Decided by the operator on 2026-11-28: a council round
      for the workflow screens, and one design for the rest. Time estimates are rough.
  - **Workflow list, workflow definition and workflow run: a full council round.** Independent
    attempts where the design is least settled. Every attempt extends the locked system and may
    not change its tokens, trust vocabulary, tiers or components, which guards against drift.
    These three screens are the ones Wave 1 needs, so this round runs first. ~4–6 days.
  - **Change review, settings and secret entry: one design extending the locked system**, with
    operator review and an audit. Their layout mostly follows from existing components. They
    are needed in Waves 2 and 3. ~2–3 days.
  - Considered and not chosen: one design for every screen, a council round for every screen,
    and designing the screens directly as Storybook stories.

## Design selection process

Run with [design-starter-kit](https://github.com/gorban/design-starter-kit) (task
`oc-dashboard`). The result and its provenance are in the
[reference design](spikes/m/dashboard-design/README.md).

- [x] Produce at least three independent design attempts. Isolate their context: each
      attempt gets the same brief and fixtures, but its own design skill, and no access to
      other attempts, prior rounds' rationale or this repository's other agents' notes.
      `claude/m3a-design-selection` records three distinct skill-based attempts and a
      skill-free baseline.
- [ ] Review the attempts blind (neutral labels, shuffled order, authoring metadata
      stripped) by a cross-provider council (OpenAI, Google and Anthropic models). Each
      reviewer scores the same rubric, names the best facet of each attempt, and does not
      vote for an attempt produced by its own model. Aggregate with Borda count.
      - Partly met. Two rounds used neutral labels and a shared rubric. Some raw ballots
        ranked candidates from the reviewer's own model. The tally removed those entries
        before computing the recorded Borda scores.
- [ ] Share only synthetic fixtures with external design providers, including in prompts
      and screenshots. Strip workstation paths, account and host names, and real repo
      or sandbox identifiers before sharing any artifact.
      - Partly met. The fixtures were synthetic and contained no workstation paths, but they
        kept this repository's name as a project label and in mock branch paths. The
        operator-requested ownership note names the owner and the GitHub repository.
- [ ] Give the operator a review point every round: rubric scores, per-facet
      keep / kill / merge tags and element-level comments. Record the reasons for every kill
      as constraints for the next round.
      - Partly met. Both council rounds recorded operator scores and facet decisions. The
        single-design refinement and polish used fix lists and audits without another scored
        operator round.
- [ ] Hill-climb: the next round builds on the winner and merges named facets from others.
      Re-judge the new version against the previous winner in both orders. Stop when the
      challenger stops winning or after the round cap (about three divergent and two
      convergent rounds).
      - Partly met. After two blinded rounds the operator chose the champion. Polish passes
        followed, driven by operator fix lists and audit findings. There was no pairwise
        re-judge in both orders.
- [ ] Record each round's slate, scores, decisions and the selected commit or artifact here.
      - The [reference design](spikes/m/dashboard-design/README.md#how-it-was-chosen)
        records both scored slates and the selected commit
        `26d81cf58435e6660023b993c7f45891ebdc1bb3`. The third round had a
        single refinement and no council score.
- [ ] Before locking `DESIGN.md`, run the finalist against a synthetic local/remote fleet
      with simulated actions only. Start the triage clock when the operator opens the
      authenticated dashboard. Require identification of the seeded attention items and
      healthy control within five seconds, and record the loading time separately.
      Require correct distinction between Tier A authorization and Tier B
      workflow decisions, and correct local and remote message routing when two sandboxes
      have the same name. Verify zero wrong-tier or wrong-target simulated effects. Record
      observed outcomes, the fixture revision, and the operator's explicit selection of
      the exact passing finalist artifact.
      - The operator reported a pass on 2026-11-26 for `26d81cf`, with fixture
        `brief/fixtures/workspace.json` (sha256 `6a191ce7a8d1fcb1…`). The observed outcomes
        (load time, triage time, items found, tiers, routing, wrong-target count) aren't
        recorded yet. Tick this once they're added.

## Open decisions

- [x] **Fonts.** Decided: the system font stack, as the selected design uses.
  `claude/m3a-design-selection`.
  - **System font stack (recommended).** No CSP change, no font payload, native rendering in
    WebKitGTK and Chromium. Less distinctive, and metrics vary slightly by OS. ~0 days.
  - **Bundled self-hosted fonts** (for example, a grotesque plus a hyperlegible mono for
    values). More consistent and polished. Needs `font-src 'self'` added to the reviewed CSP,
    licence checks and pinned assets, and adds payload. ~0.5–1 day plus a security review.
- [x] **Styling approach.** Use the selected design's plain CSS custom-property tokens
  with scoped Svelte styles in the implementation. `claude/m3a-design-selection`.
  - **Plain CSS custom-property tokens with Svelte scoped styles (recommended).** Matches the
    current spike and the `style-src 'self'` CSP, adds no dependency, and design skills emit it
    directly. More hand-written CSS. ~0 days.
  - **Tailwind CSS v4.** Fast iteration and familiar to agents. Adds a build dependency and
    supply-chain review, and some design skills lint against its patterns. ~1 day.
  - **UI SDK `web.css` base with token overrides.** Consistent with headless primitives. Ties
    the visual layer to a beta package. ~0.5 day, depends on [prd_m3a2](prd_m3a2.md).
- [x] **Themes.** Decided: light and dark, following the system, with a manual override held
  in memory, as the selected design uses. `claude/m3a-design-selection`.
  - **Light and dark, following the system with a manual override (recommended).** Keep the
    override in memory or in a non-secret host preference. Avoid SDK inline preference scripts
    and persistent browser session state. Works for
    long sessions and accessibility. Every token and contrast check runs twice. ~1–2 days extra.
  - **Dark only at first.** Faster. Fails some users and daylight use. ~0 days.
- [x] **Density.** Decided: the compact and comfortable toggle, as the selected design uses
  (its "Comfortable" control scales the root size to 112.5%). This is the non-recommended
  option, chosen by the operator. `claude/m3a-design-selection`.
  - **One compact-but-comfortable density with 32–40 px controls (recommended).** Simpler to
    test and keeps 2.5.8 margins. Power users may want tighter tables. ~0 days.
  - **Compact and comfortable toggle.** More flexible. Doubles visual QA. ~1–2 days.
