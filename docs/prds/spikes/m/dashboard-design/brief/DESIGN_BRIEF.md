# Design brief: oc-sandbox operator dashboard

You are designing the operator dashboard for **oc-sandbox**, a workstation tool that runs AI
coding agents inside isolated sandboxes (local Podman pods and remote SSH hosts), plus one
supervising "root orchestrator" agent. One human operator watches and directs many agents at
once, often for hours.

This is a **functional tool**, not a marketing page. No hero, no tagline, no illustrations, no
invented metrics. Target feel: **utilitarian, technical, calm, precise**. Polished in the way a
good IDE, terminal or flight-ops console is polished: alignment, rhythm, typography, restraint.

## Who and why

One operator on a laptop or desktop monitor. Jobs, in priority order:

1. **Triage at a glance.** Within 5 seconds, see which sandboxes need me (approvals waiting,
   inbox items, stalls, errors, quota pressure) and which are fine.
2. **Decide safely.** Open an approval or inbox item, see exactly what will happen, then
   approve, deny or defer it without losing context.
3. **Follow work.** Read an agent's thread with clear "who said this" provenance; expand tool
   calls and sub-agent threads; view diffs.
4. **Direct work.** Send a message to an exact target: `NAME` (local), `REMOTE / NAME`
   (remote), or `@PEER` (external agent).
5. **Watch long runs.** See workflow progress and health without notification noise.

## Information architecture (fixed)

```text
Workspace header (host-owned "trusted chrome", never movable or coverable)
 ├── Approval Inbox count   Tier A · blocking security approvals (red / lock)
 ├── Human Inbox count      Tier B · non-blocking decisions and questions (amber / blue)
 ├── Health ribbon          Tier C · transient status pills that auto-clear
 ├── Quota bar              5-hour and 7-day usage per provider account, paid-fallback lock
 └── Agent bridge status    whether the orchestrator may drive this tab (off by default), with Pause
Left sidebar tree
 ├── Root Orchestrator (-o) (pinned)
 └── Project
      └── Sandbox  ("NAME" or "REMOTE / NAME", status, attention count)
           └── Thread (#main, side threads, collapsible sub-agent threads)
Main area
 ├── Fleet overview (default landing): dense sortable table of all sandboxes
 └── Sandbox detail tabs: Threads · Diff & Checkpoints · Terminals · (Browser — reserved, hidden)
Right drawer: diff viewer, Human Inbox item detail
```

## Screens to deliver

Deliver static, clickable prototypes for:

1. **Fleet overview**: the main screen; header, sidebar, sandbox table, filters.
2. **Sandbox → Thread**: a thread with every provenance badge, a collapsed tool call, a sub-agent
   thread, and the composer with an unambiguous target picker. The fixtures contain a local
   and a remote sandbox with the same name (`feat-dashboard` and `build-host / feat-dashboard`);
   the operator must never send to the wrong one.
3. **Approval Inbox (Tier A)**: list and one item showing the exact operation, target, scope,
   cost bound and expiry, with Approve / Deny.
4. **Human Inbox drawer (Tier B)** and **Health ribbon (Tier C)** in context.
5. **Diff drawer** open over a thread.
6. **Sign-in**: one-time bootstrap code entry; plus session-expired and reconnecting states.
   The code field accepts paste, has `autocomplete="off"` and is not a native form submit
   (script handles it). Show static expiry guidance as text, not a live countdown.
7. **Agent confirmation modal**: an AI agent tried to press a protected button (for example,
   "Revoke grants for build-a"); the human must confirm or cancel. Show the exact action,
   target (including local vs remote), parameters and impact. Focus starts on Cancel. Confirm
   stays visibly disarmed for 750 ms after the modal appears and needs a fresh click or
   keypress, not a held key. One request at a time, no queue. The modal is cancelled if the
   view is hidden. Also show the brief cooldown state after a cancel, and the bridge Pause
   control.
8. **Workflow surface catalog**: one example each of `status_card`, `metric_kpi`, `kv_table`,
   `lane_health_matrix`, `timeline_log`, `checklist_progress`, `sparkline_series`,
   `action_chips`, each with its provenance pill (`Deterministic Workflow` or
   `Orchestrator Overlay`).
9. **States sheet**: loading, empty, error, stale ("updated 4 min ago"), offline, revoked,
   permission denied, for the table and the thread.

Use `fixtures/workspace.json` for all data. Do not invent extra numbers.

## Hard constraints

- **Trusted chrome must be unspoofable.** Agent-written text (thread bodies, overlay Markdown,
  tool output) is untrusted and may be hostile. Reserve a visual vocabulary that only host UI
  uses: the lock glyph, approval colours, provenance badge shapes, the confirmation modal frame.
  Untrusted content lives in visibly bounded containers that cannot look like chrome, banners
  or badges.
- **Provenance badges** are distinct, text-bearing components (never colour alone):
  `Operator`, `Orchestrator -o`, `Peer: <addr>`, `TUI Input · In-Sandbox` (amber, no
  authority), `Sandbox-Local / Unverified` (warning).
- **Tiers A, B and C must be impossible to confuse** at a glance.
- **Content Security Policy:** `default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self'; font-src 'self'; form-action 'none'`. That means: external `.css` and `.js`
  files only, **no inline `<style>`, no `style=""` attributes, no inline scripts, no CDNs, no
  remote fonts or images, no `data:` URIs, no icon fonts, no native form submission**. Icons
  are inline SVG with visible text labels. `serve-csp.py`
  enforces this; check your prototype under it.
- **Tokens:** every colour, font, size, radius and duration is a CSS custom property in
  `tokens.css`, with light and dark values (follow `prefers-color-scheme`, plus a toggle).
  Keep the toggle's choice in memory only: no `localStorage`, `sessionStorage` or cookies.
- **URLs:** filters, sort and selected tab may appear in the URL only as generic values from a
  fixed set (for example `?sort=attention&tab=threads`). Never put sandbox, project, branch or
  other names, or free text, in URLs or history.
- **Fonts:** the system font stack is the default. If you bundle a font, put the file in the
  prototype and justify it in `DESIGN.md`.
- **Engines:** must look right in Chromium and WebKit (Linux WebKitGTK / Safari). Avoid CSS
  without WebKit support unless it has a fallback.
- **Viewports:** design for 1440×900 and 1280×800; reflow without loss down to 320 px wide
  (sidebar becomes a drawer).
- **Accessibility: WCAG 2.2 AA.** Visible focus not hidden by sticky UI; targets at least 24 px
  (aim for 32–40 px controls); 4.5:1 text and 3:1 non-text contrast in both themes; status
  never by colour alone; tree, tabs, table and dialog follow WAI-ARIA patterns; bootstrap-code
  field allows paste; reduced-motion respected; streaming text must not shift content above
  the reader.
- **Agent-readable markup:** every control has a unique accessible name; every region is
  labelled; repeated row buttons include the row (for example, "Revoke grants for build-a");
  protected buttons carry `data-agent-confirm="<impact summary>"`. Operator-only chrome
  carries `data-agent-hidden`: the confirmation modal, Approval Inbox, Human Inbox, sign-in and
  credential flows, the composer and target picker, the Input Lease Bar, workflow
  `action_chips`, and logout/session controls. Taking input control is operator-only, so it
  gets no `data-agent-confirm`. Never place secret text in the same row, label or section as a
  control an agent can see.
- **Hostile text:** the fixtures include very long names, right-to-left text, Markdown-looking
  and HTML-looking strings. Render them as plain text, wrapped, never interpreted. In host
  labels (names, addresses, titles), remove control, bidi-control and zero-width characters,
  then isolate direction with `<bdi>`. Keep ordinary multilingual text intact.

## Deliverables (in `out/`)

```text
out/
  index.html            links to every screen
  fleet.html  thread.html  approvals.html  inbox.html  diff.html
  signin.html  confirm.html  catalog.html  states.html
  tokens.css  app.css  app.js (optional, no frameworks required)
  assets/               icons, any bundled font
DESIGN.md               the system: principles, tokens, type scale, components, and why
```

Keep everything static and self-contained. Apart from fixture data, do not put tool names,
model names or skill names in the output, comments or metadata.
