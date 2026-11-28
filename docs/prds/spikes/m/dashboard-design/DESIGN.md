# Design: oc-sandbox operator dashboard

## Direction

Round 3. The banded fleet, the fixed host shell, the tier shapes and the trust vocabulary stay. What changed is how attention is drawn, how a decision is remembered, and how much room the composer and the confirmation take.

1. **Idea.** Colour is attention, and shape is severity. Surfaces are neutral graphite or paper; hue appears only on tier counts, status glyphs, diff lines and a quota bar past its threshold. Every hue repeats something a glyph or a word already says.
2. **Layout.** Three fixed host bands around one stage. Top: a two-band header (brand, both inboxes, bridge, Pause, Comfortable, theme; then a thin Health ribbon). Bottom: an Account usage strip with the paid-fallback lock. Between them the stage holds the sidebar, the main area and any drawer as columns, so nothing can cover the header or the footer.
3. **Triage.** The fleet table is banded by need: Needs you, Degraded with no action needed, On track or idle. Status, attention and health are three separate fields. Branch, model, grants and revoke open under a row on demand.
4. **Attention indicator.** A glyph beside a numeral, with no box. An octagon cross is an error, an hourglass a stall, a speech mark unread work, so a collapsed project still tells an error from a caution in greyscale. The pair is centred in one fixed slot in the tree and in the fleet column, so numerals line up. In the fleet a short reason sits beneath it: "1 approval · 1 inbox item", "4 unread in #main".
5. **One memory.** Screens are swapped in place, so the tab keeps one in-memory state and nothing is stored. A decision is keyed by request id and revision; the approval card, the Tier A count, fleet reasons and tree totals are all derived from it. Drafts are kept per destination. Theme and density now survive a change of screen for the same reason.
6. **Type.** The system sans carries everything the host says, in two weights (400 and 600) on a 1.125 scale from 12 to 28 px. The system mono is reserved for text an agent wrote or proposed, and for request parameters.
7. **Colour roles.** Red is a blocking approval (Tier A), blue a non-blocking decision (Tier B), amber caution or no authority, green on track. Primary actions and focus are ink. In both modes the security frame is red in the same places only: border, stripe, band, arming bar and the armed button. Its body is ordinary paper, light or dark. Every colour ships as an sRGB value with its OKLCH source behind a feature query.
8. **Protected actions.** One compact dialog inside the stage: a lock-led heading, who asks, the action as a heading, two rows (target, parameters), one impact line. The facts scroll; the heading and the footer do not. The footer holds Pause bridge, a focused Cancel and a button that reads "Arming…" for 750 ms before it becomes Confirm, and then needs a press that began after arming.
9. **Composer.** The editor starts at one line and grows to eight. The lease notice is one row with a single Take or Release button. The last row keeps the key hint, its checkbox, the qualified recipient and Send (paper plane, then the word) centred on one line; when it breaks, each label stays with its control and each row is centred.
10. **Untrusted text and addresses.** Anything an agent wrote sits in a dashed, mono, colourless well as plain text; the host answers a false claim outside it. A sandbox is always written `location / name`, a remote host strong and underlined, and a same-name twin is called out wherever a target is chosen or confirmed.

### Polish 1

- **Security frame, dark mode.** The crimson body is gone. The confirmation dialog and approval cards now swap like every other surface: dark paper body, with red kept to the border, stripe, band, arming bar, impact line and armed button, as in light. The `--color-approval-surface` token is removed.
- **Sign-in, session expired.** Code entry and Session expired are one card under one page title, "Sign in to oc-sandbox". Expired adds the amber banner above the card and renames the button "Sign in with new code".
- **Composer hint.** "Enter adds a line." is set at the size and line height of the "Ctrl + Enter sends" label, so the two share one box and one baseline.
- **Sandbox page head.** Every fact after the status is set at the status's size and line height; only its colour is quieter.
- **Sandbox page width.** From 80 rem up, the tab bar and panels are as wide as the room left beside an open drawer, or the 48 rem reading measure if that is wider. On a wide window the content therefore fills to where the drawer's edge would be and does not move when the drawer opens or closes.

### Polish 2

Six WCAG 2.2 AA fixes from the accessibility audit. Nothing else changed.

- **Focus not obscured, Workspace menu (2.4.11).** Below 60 rem the open menu makes the main area and any drawer inert, so Tab stays in the header, the menu and the footer. Escape reaches the menu before anything beneath it, closes it and returns focus to the menu button. Closing, or widening past 60 rem, releases exactly what the menu made inert; a waiting confirmation keeps its own hold, and the menu does not open over one.
- **Focus not obscured, short windows (2.4.11).** Under 30 rem of height, while a request waits, only the header row that holds Pause follows the scroll; the Health ribbon scrolls away. `--hdr-clear` reserves that row's height when focus scrolls into view, so Cancel, Confirm and Pause bridge are never under it.
- **Focus order (2.4.3).** Clear filters moves focus to the first restored row's link (or the status button if no row returns) before its own message hides.
- **Label in name (2.5.3).** Accessible names start with the visible text: "Open in drawer: changed files", "Open diff for this call: edit_file at 15:04", "Sub-agent task: write tests, thread details".
- **Target size (2.5.8).** A tree chevron keeps its 16 px glyph inside a `--target-min` (24 px) hit area; negative margins give the room back, so row height and name alignment are unchanged.
- **Page titled (2.4.2).** Each sandbox page is titled with its cleaned address, as in "local / feat-dashboard, sandbox thread, oc-sandbox". In-place navigation carries the title across.
- **Name, role, value (4.1.2).** The status filter button is a plain disclosure: `aria-expanded` and `aria-controls`, no `aria-haspopup`.

### Polish 3

One WCAG 2.2 AA fix from the second audit. Nothing else changed.

- **Reflow (1.4.10).** On the states sheet, the paired specimens stack into one column when the main area is 40 rem or narrower. The container query now follows the base two-column rule, so it wins. A button in a notice's action row may wrap onto a second line and never grows wider than its card, with or without WCAG text spacing.

### Polish 4

- **Ownership note** (`.owner`). Two quiet lines, "Copyright © David Bruck" and "github.com/gorban/opencode-sandbox", sit under the profile row in the sidebar foot and under the card on sign-in, in all three sign-in states. Both come from one helper in the generator and one style; the sign-in variant only centres it. By the operator's later instruction the second line is a link rather than plain text: it shows the address as written, goes to the full HTTPS address in a new tab, says so to assistive technology, is underlined, has a 24 px target and is the last tab stop in its container. It is hidden from the agent bridge.

### Polish 5

- **Fleet table footer.** The footer is one cell across every column, laid out as a flex row: the count at the start, "Times in CST" at the table's end. It no longer depends on how many columns are showing, so it lines up with five columns, with four when Health folds under Status, and in the stacked layout, without script. `#fleet-count` keeps `role="status"`.

## System

- Kind: app screens for one operator. Genre: minimal, technical. Posture: restrained; hue marks attention only.
- Source of truth: `out/tokens.css`, generated from `build/tokens.mjs`. `out/app.css` contains no literal colour, font, size, radius or duration; only breakpoints are written as numbers, because media and container queries cannot read custom properties.
- Modes: light is the `:root` default, dark follows `prefers-color-scheme`, and the sun or moon button sets `data-mode` on the root element. Density: the Comfortable button sets `data-density`. Both are held in memory only: they last while the tab keeps its document, across screens, and are gone on reload.
- Pages are generated from the fixture by `build/build.mjs` (run `node build/build.mjs`). Every string from the fixture is escaped there, once. `build/contrast.mjs` checks 56 token pairings in each mode against WCAG 2.2 AA.
- Every sandbox in the fixture has its own thread page (`thread.html` for the example, `thread-2.html` to `thread-7.html` for the rest), so every fleet row, tree row and inbox item opens the sandbox it names. File names are generic; no name reaches a URL.

## Principles

1. **Colour is attention.** Neutral chrome, ink primary buttons, ink focus rings. A screen with no hue on it is a screen that does not need you.
2. **Rank, then colour.** The table is grouped into three bands and ordered inside each. A count, a glyph shape and a status word carry the meaning; colour only confirms it.
3. **The host has a voice an agent cannot borrow.** Sans type, solid edges, glyphs and hue belong to the host. Mono type inside a dashed, colourless container belongs to agents. Nothing crosses.
4. **One target, always in view.** The composer names its target on the Send to line, beside the Send button and in the button's accessible name.
5. **Five columns, the rest on demand.** What ranks a sandbox is in the row. What you need once you have chosen it is one press away.
6. **Fixed bands, one stage.** Header and footer never move and are never covered. Drawers and the modal are columns and layers of the stage.
7. **Nothing moves unless state changed.** Two short durations for hover and disclosure, one 750 ms arming bar, a loader. No entrance animation.

## Colour roles

| Role | Token | Light | Dark | Used for |
| --- | --- | --- | --- | --- |
| Ground | `--color-paper` | `oklch(98.5% 0.003 250)` | `oklch(17% 0.008 250)` | Main area, controls |
| Panel | `--color-paper-2` | `oklch(96% 0.004 250)` | `oklch(21% 0.009 250)` | Header, sidebar, footer, band rows |
| Well | `--color-paper-3` | `oklch(93% 0.006 250)` | `oklch(13.5% 0.007 250)` | Untrusted text, hover |
| Ink | `--color-ink`, `-ink-2`, `--color-muted` | 21%, 33%, 44% | 95%, 84%, 72% | Text in three steps; primary buttons; focus |
| Rule | `--color-rule`, `--color-rule-2` | 86%, 58% | 31%, 55% | Hairlines; control and well edges (3:1) |
| Tier A | `--color-approval`, `-ink`, `-soft` | `oklch(47% 0.19 27)` | `oklch(72% 0.16 25)` | Blocking approvals and the security frame |
| Tier B | `--color-inbox`, `-ink`, `-soft` | `oklch(45% 0.15 255)` | `oklch(77% 0.11 250)` | Human Inbox only |
| Caution | `--color-caution`, `-edge`, `-soft` | `oklch(44% 0.1 70)` | `oklch(82% 0.13 82)` | Warnings, a quota bar at 80% or more, input with no authority |
| On track | `--color-ok`, `-soft` | `oklch(43% 0.11 150)` | `oklch(78% 0.13 150)` | Running glyph, added diff lines |
| Fault | `--color-bad`, `-soft` | `oklch(47% 0.19 27)` | `oklch(72% 0.16 25)` | Error glyph, removed diff lines, the host notice |

Neutrals share hue 250 at a chroma no higher than 0.012 in both modes; no neutral surface carries a green or blue wash. Tier buttons, drawer heads and list rows stay on neutral surfaces and take their tier hue on the edge, glyph and count only. Soft tints are reserved for content that is itself a signal: diff lines, the host notice, the Input Lease Bar, attention cards on the states sheet.

In `tokens.css` each colour is declared first as an sRGB hex value and then, inside `@supports (color: oklch(…))`, as its OKLCH source, so an engine without `oklch()` paints the same palette.

## Type

System faces only, so nothing is bundled and nothing is fetched.

- `--font-ui`: `ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Liberation Sans", sans-serif`. Everything the host says.
- `--font-mono`: `ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, "DejaVu Sans Mono", "Liberation Mono", monospace`. Wells, the diff, and overlay-proposed action chips. Never a host label, heading or button.
- Weights: 400 and 600. System faces do not reliably ship 500.
- Figures that compare use `tabular-nums` (`.num`).

| Token | Size | Role |
| --- | --- | --- |
| `--text-2xs` | 12 px | Meta, table heads, badges, the ribbon and the usage strip |
| `--text-xs` | 13 px | Table cells, tree, buttons, wells |
| `--text-sm` | 14 px | Body default, operator messages, row names |
| `--text-md` | 16 px | Section headings, the wordmark, the code field |
| `--text-lg` | 18 px | Page titles |
| `--text-xl` | 22 px | The index title |
| `--text-2xl` | 28 px | The one KPI figure |

All sizes are in rem. Comfortable density sets the root size to 112.5%, so type, spacing and targets grow together.

## Space, size, radius, motion

- Space: `--sp-2` to `--sp-64` on a 4 px rhythm (2, 4, 6, 8, 12, 16, 24, 32, 40, 64).
- Controls: 32 px default, 28 px small, 40 px large. Minimum target 24 px (`--target-min`); radio and checkbox inputs are 24 px inside 36 px rows (`--target-radio`).
- Layout: header row 48 px, ribbon 36 px, usage strip 56 px, sidebar 264 px, drawer 440 px (544 px for the diff), reading measure 46 rem.
- Radii carry meaning: 0 for blocking things and untrusted wells, 3 px for tags and badges, 6 px for controls, 8 px for panels, a full capsule for Tier C pills, the Tier B count and overlay chips.
- Motion: `--dur-micro` 120 ms, `--dur-short` 220 ms, `--dur-tip` 400 ms (tooltip hover delay), `--dur-arm` 750 ms (the lock on Approve and Confirm; the script reads this token), `--dur-cooldown` 3000 ms (prototype stand-in for the brief cooldown), `--dur-loop` 1200 ms. Anything that moves uses `transform` or `opacity`. Under reduced motion everything is instant and loaders hold still.

## Shell

- **Header, band one.** Cube mark and wordmark; Approval Inbox and Human Inbox with their counts; then Bridge with its state chip (Off, On, Request, Cooling, Paused), Pause, Comfortable and the theme button. Sign-out is not here.
- **Header, band two.** The Tier C Health ribbon. Each pill has a triangle or a circled i and a hidden severity word; nothing is colour alone.
- **Footer.** Account usage: a title with "Paid fallback locked" beneath it, then one column per account with aligned 5h and 7d bars and right-aligned percentages. No warning glyphs; a bar at 80% or more turns amber and its figure goes bold. Under 60 rem it collapses to one bar that expands upward.
- **Stage.** A grid: sidebar, main, drawer. The main area is a query container, so the table and the grids respond to the room they have, not to the window.
- **Short viewports.** Under 30 rem of height (heavy zoom) the shell lets go and the page scrolls as one document; while an agent request is waiting the header sticks, so Pause is still in view.
- At 320 px the header is two rows plus the ribbon and the first sandbox is on screen without scrolling.

## Trust vocabulary

| Signal | Host | Agent-written |
| --- | --- | --- |
| Typeface | Sans | Mono |
| Edge | Solid | Dashed |
| Colour | Roles above | None; ink on the well neutral |
| Glyphs | Yes, always with a word | Never |
| Markup | Components | Escaped plain text, `white-space: pre-wrap`, `overflow-wrap: anywhere` |

- **Well** (`.well`): the only container for thread bodies, tool summaries, overlay text, request wording and inbox summaries. It clips its content and isolates bidi (`dir="auto"`, `unicode-bidi: plaintext`). Markdown, HTML and tables arrive as characters and stay characters.
- **Invisible characters** (`.ctl`): inside a well, control, bidi-control and zero-width characters are replaced by a small solid-edged sans marker such as `U+202E`. The marker is the host speaking inside the well, which is why it is not mono.
- **Host notice** (`.hostnote`): a crimson, solid-edged line placed after a well, outside it, when the message's badge is `Sandbox-Local / Unverified`.
- **Operator's own words** (`.said`): sans, a solid ink bar on the leading edge. The only message body that is not a well.
- **Host labels**: names, addresses and titles pass through `clean()` (control, bidi-control and zero-width characters removed) and are wrapped in `<bdi>`. Long names wrap; nothing is truncated.
- **Lock glyph**: Tier A, the paid-fallback lock, revoke, the security frame and permission states. Nowhere else.
- **Tooltips** (`.tip`): ink on paper inverse, sans, shown on hover and on keyboard focus, dismissed with Escape, tied to their control with `aria-describedby`. Only host chrome has them.
- **Host line**: the header ends and the footer begins with a 2 px ink rule.

## Tiers

| Tier | Shape | Hue | Glyph | Where |
| --- | --- | --- | --- | --- |
| A, blocking | Square, 2 px edge, solid square count | Red | Lock | Header button, approval rows, the security frame, Approve and Confirm |
| B, decisions | Rounded outline, round count | Blue | Tray | Header button, drawer head, selected item |
| C, transient | Capsule, no fill | Neutral | Triangle or circled i | Health ribbon only |

**Security frame** (`.secframe`): a 2 px red border, a diagonal red stripe along the top, a solid band with the lock and title (`--color-approval-band`), a body on ordinary paper in both modes, a field list, then a full-width arming bar above the actions. Approval cards and the confirmation modal are the same component; the modal adds a second hairline outside the border.

## Provenance badges

All are 22 px tags with a glyph and text. Shape differs as well as colour.

| Badge | Form |
| --- | --- |
| `Operator` | Solid ink fill, person glyph |
| `Orchestrator` | 2 px ink outline, hub glyph. The short address is never shown |
| `Peer: <addr>` | Capsule leading end, address in a second segment |
| `Agent`, `Sub-agent` | Plain hairline outline |
| `Tool call` | Dotted outline |
| `TUI Input · In-Sandbox` | Amber soft fill, solid amber edge, followed by "No operator authority" |
| `Sandbox-Local / Unverified` | 2 px dashed crimson edge, no fill, warning glyph, followed by the host notice under the message |

Workflow pills follow the same rule: `Deterministic Workflow` is solid with a gear, `Orchestrator Overlay` is dashed with layers, and neither wraps.

## Components

- **Address** (`.addr`): glyph, location, slash, name, as text. Used in the page head, composer, approvals, inbox and modal. In the fleet table a remote row is titled `host / name` and every row has `project / Local` or `project / host` beneath it.
- **Status** (`.st`): a distinct glyph per state (play, hourglass, cycle, dash, octagon, slashed circle) plus the word.
- **Fleet table** (`.fleet`): four sortable heads with `aria-sort`, an idle two-arrow glyph, and an ink underline plus a single arrow on the active one. Attention descending is the default and the only order that shows bands. Status sorts Error, Stalled, Idle, Reconnecting, Running, Offline. A chevron per row opens branch, model, grants and Revoke grants. The foot reads "Showing n of 7 sandboxes" on the left and "Times in CST" under Last change. In a narrow container each row restacks as labelled lines, the header row leaves the page and the tab order, and a labelled Sort picker above the rows takes over; its options name field and direction ("Attention, most first") and it stays in step with the header sort and the URL. Between 40 and 54 rem of main width (a drawer open beside the table) the Health column folds beneath Status. The Attention cell is the indicator over its reason line.
- **Filters**: All sandboxes and Needs attention as a pair; a status menu of checkboxes that filters as you tick and closes only on an outside press or Escape; a worker select.
- **Tree** (`role="tree"`): roving tabindex, arrow keys, Home and End, type-ahead. Folder glyphs and bold names for projects, quiet inline location and status for sandboxes, attention indicators (`.attn`) whose glyph is the sandbox's status, unread counts as a plain numeral in the same slot. A project shows the sum of its sandboxes with the glyph of the most urgent one. Only the selected sandbox starts with its threads open. Assistive technology hears "Severity: stalled." and "3 need you" as separate phrases. Under it, fixed: six page links and the Operator row, whose menu holds Sign in and Sign out.
- **Thread**: underline tabs with "Times in CST" at the end of the bar; each message is a badge row with its time right-aligned and its body beneath. A collapsed tool call shows the tool name and its summary inline. The sub-agent row sits last, with its link.
- **Composer**: pinned under the transcript on tall, wide viewports. A one-row Input Lease Bar whose button takes input and hands it back, a Send to line with Change target, a message box that starts at one line and grows, a "Ctrl + Enter sends" checkbox, then the target again and Send. Changing target saves the draft for the old destination and restores the new one's; Send is off until the editor, the recipient and the button's name agree. The transcript is a labelled `log`. Change target opens a radio grid in place; a pointer choice or an outside press closes it, arrow keys do not. A same-name twin raises an amber note.
- **File box** (`.filebox`): one box per changed file, with path, added and removed counters and a numbered patch. Collapsed by default in Diff & Checkpoints, open in the drawer. Its chevron points down while closed and turns to the side when open.
- **Drawer** (`.drawer`): a stage column beside the main area when there is room (64 rem for the inbox, 80 rem for the diff); otherwise it takes the main area's place until closed. It opens and closes in place, so the active tab never changes.
- **Approval** (`.apr`): rows stacked; the chosen row's security frame opens directly beneath it and scrolls to the top. Approve is locked for 750 ms after a card opens. Approve and Deny are terminal for that request id and revision: the buttons are replaced by the recorded decision, the header count, fleet reason and tree totals drop, and focus moves to the next pending row. The record is shared in-memory state, so the card reads the same after visiting another screen. Defer records nothing and the revision stays pending.
- **Confirmation modal** (`.confirm`): `alertdialog` inside the stage, three parts in a column (band, scrolling facts, footer). Focus starts on Cancel, the confirm button reads "Arming…" while the bar fills, then "Confirm", and needs a press that began after arming; a held key cannot confirm. The footer also carries Pause bridge. At 320 by 568 the action, the target and all three controls are in view on opening. Cancel, Escape, Pause, turning the bridge off, or hiding the view cancels it. The stage behind it is inert; the header and footer are not.
- **Notice** (`.notice`): the state component. On the states sheet each state is a card; Error, Stale, Revoked and Permission denied tint the card and leave the glyphs inside neutral. Both stale cards show "Updated 4 min ago" above the cached content. On sign-in, static text tied to the code field with `aria-describedby` says the code works once, expires, and where to issue a fresh one.

## Agent-readable markup

- `data-agent-hidden`: both tier buttons, the Approval Inbox, the Human Inbox drawer, sign-in, the session menu, the composer and Input Lease Bar, workflow action chips, the confirmation modal, the bridge toggle.
- `data-agent-confirm="<impact>"`: every Revoke grants button.
- Repeated row controls carry the row in their name ("Details for build-host / feat-dashboard", "Revoke grants for …").
- URL state is limited to `show`, `worker`, `status`, `sort`, `dir`, `tab` and `state`, each checked against a fixed list before it is read or written. `status` may hold several values from its list. No name ever reaches the URL or history.

## Accessibility

Focus is a 2 px ink ring with a 2 px gap and appears instantly. Status is never colour alone. Contrast passes for all checked pairings in both modes (4.5:1 text, 3:1 edges and glyphs). Every disclosure has `aria-expanded` and `aria-controls`; sortable heads have `aria-sort`; icon-only controls have `aria-label`; tooltips are `role="tooltip"` and referenced by `aria-describedby`. The layout holds at 320 px with no horizontal scroll and no clipped tab. Under 60 rem the sidebar is a drawer inside the stage, and with scripting off it renders in the flow instead. Timestamps use one 24-hour format with the date when not today, and each screen that shows them states the zone.

## Engine notes

Verified in a Chromium engine under the strict policy with zero violations. Not yet run in WebKit. Colours no longer depend on `oklch()`. The CSS that still needs a recent WebKit is size container queries, `:has()` (the tooltip on keyboard focus and the ring on the chosen target row; both degrade to the control's own focus ring and the radio itself), `overflow: clip`, `inert`, and `100dvh` (with a `100vh` line before it). `text-wrap: balance` is an enhancement.

## Exports

`out/tokens.css` is portable as it stands. `out/assets/icons.svg` holds the glyphs as symbols for reference; pages inline them, because the policy and WebKit both favour inline SVG.
