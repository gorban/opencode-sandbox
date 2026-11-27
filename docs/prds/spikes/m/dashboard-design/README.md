# M3a dashboard reference design

The locked product design for the M3a operator dashboard ([prd_m3a1](../../../prd_m3a1.md)). It's
a static, clickable prototype with synthetic data, and the reference that the SvelteKit
implementation in [`../web-ui`](../web-ui) follows. It isn't production code. Port its
tokens, components and behaviour; don't ship these files.

## What's here

| Path | What |
|---|---|
| [`DESIGN.md`](DESIGN.md) | The locked design system: direction, tokens, type, components, states and the reasons for each choice. Read it before building M3a views. |
| `out/` | The prototype: one page per screen in the brief, plus `tokens.css`, `app.css`, `app.js` and `assets/`. Open [`out/index.html`](out/index.html) for the list. |
| `build/` | The generator. `node build/build.mjs` writes `out/*.html`, `out/tokens.css` and the icons from the fixture. `build/tokens.mjs` is the token source of truth, and `build/contrast.mjs` checks token contrast. `out/app.css` and `out/app.js` are written by hand. |
| `brief/` | The design input: `DESIGN_BRIEF.md` and the synthetic `fixtures/workspace.json`. |
| `audit/` | Machine-readable WCAG 2.2 AA findings from the final audits. |

To view it under the production CSP (`style-src 'self'`, no inline styles or scripts), serve
`out/` with a server that sends that policy, for example `tools/serve-csp.py out 8765` from
design-starter-kit, and open `/fleet.html`.

To rebuild after a change: run `node build/build.mjs`, and commit `build/`, `out/` and
`DESIGN.md` together.

## How it was chosen

It was designed and selected with
[design-starter-kit](https://github.com/gorban/design-starter-kit), task `oc-dashboard`:

- Four isolated attempts worked from the same brief and fixtures, each with its own design
  skill.
- A cross-provider council reviewed them blind, with no reviewer voting for its own model.
- The operator decided each round.
- The champion was then refined in polish passes, followed by WCAG audits and the operator's
  acceptance check.

The brief was synced to this repository at `3d3f408`.

The selected artifact is attempt `a1-hallmark` at commit
`26d81cf58435e6660023b993c7f45891ebdc1bb3`, tagged `design-final` in the design lab's attempt
repository, which isn't published. `DESIGN.md`, `out/` and `build/` here are byte-identical
to that commit, and rebuilding from `build/` reproduces `out/`.

## Accessibility (WCAG 2.2 AA)

| Audit | Design commit | Fail | Needs review | Pass | N/A |
|---|---|---|---|---|---|
| Full ([`audit/final-763cbac.wcag-issues.json`](audit/final-763cbac.wcag-issues.json)) | 763cbac | 0 | 1 | 43 | 11 |
| Scoped re-audit of the ownership note ([`audit/final-f1902bc-scoped.wcag-issues.json`](audit/final-f1902bc-scoped.wcag-issues.json)) | f1902bc | 0 | 1 | 43 | 11 |
| None: operator waiver for the fleet footer fix | 26d81cf (selected) | | | | |

- **Earlier failures:** the first full audit, on an earlier commit, found 6 failures, and a
  second found 1 more. All were fixed in the design's source before the passing audit.
- **The selected commit:** `26d81cf` changes only the fleet table footer since `f1902bc`. It
  now has one `colspan="5"` cell, so the footer lines up when the Health column is hidden at
  medium widths. The operator waived its re-audit. Re-audit the footer in the
  implementation.
- **Open: 2.2.1 Timing Adjustable.** Approval expiry and session lifetime are backend
  behaviour. Confirm they're adjustable or exempt before claiming conformance. The audits
  weren't verified with assistive technology.

## Follow-ups for the implementation

- **A7:** the ownership note shrinks the scrolling sidebar tree in the drawer layout at 320 px,
  to below one row with WCAG text spacing. Let the note scroll with the tree below 60rem.
- **A8:** on sign-in at 320 px, the ownership link's focus ring sits 4 px below the fold. Add
  `scroll-margin-block` to `.owner__link`.
- **External link:** the ownership link opens github.com in a new tab. The Tauri build needs an
  external-link handler for it, and the agent bridge must keep it hidden
  (`data-agent-hidden`).
- **Implementation audit:** run the full WCAG 2.2 AA audit again on the implemented build
  ([prd_m3a1](../../../prd_m3a1.md#accessibility-wcag-22-aa)).
