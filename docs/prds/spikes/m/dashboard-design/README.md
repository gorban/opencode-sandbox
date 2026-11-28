# M3a dashboard reference design

The locked product design for the M3a operator dashboard ([prd_m3a1](../../../prd_m3a1.md)). It's
a static, clickable prototype with synthetic data, and the reference that the SvelteKit
implementation in [`../web-ui`](../web-ui) follows. It isn't production code. Port its
tokens, components and behaviour; don't ship these files.

## What's here

| Path | What |
|---|---|
| [`DESIGN.md`](DESIGN.md) | The locked design system: direction, tokens, type, components, states and the reasons for each choice. Read it before building M3a views. |
| `out/` | The prototype assets and, after rebuilding, one HTML page per screen. Open `out/index.html` for the list. |
| `build/` | The generator. `node build/build.mjs` writes `out/*.html`, `out/tokens.css` and the icons from the fixture. `build/tokens.mjs` is the token source of truth, and `build/contrast.mjs` checks token contrast. `out/app.css` and `out/app.js` are written by hand. |
| [`html.sha256`](html.sha256) | Checksums for the 16 generated screens in the locked reference. |
| `brief/` | The design input: `DESIGN_BRIEF.md` and the synthetic `fixtures/workspace.json`. |
| `audit/` | Machine-readable WCAG 2.2 AA findings from the final audits. |

## View and rebuild

From this directory, build and verify the locked screens.

```sh
node build/build.mjs
sha256sum -c html.sha256
```

Serve `out/` over loopback with the reference CSP below, for example with
`tools/serve-csp.py out 8765` from design-starter-kit, and open `/fleet.html`.

```text
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

Direct page loads work with `connect-src` omitted. In-place navigation fetches HTML from
the same origin and needs `connect-src 'self'` to keep theme, density and drafts in memory.
The reference uses external stylesheets and scripts throughout.

Keep generated HTML local. The generator and tracked assets remain available for source
analysis. If the reference design changes intentionally, regenerate the pages and update
the checksums with `LC_ALL=C sha256sum out/*.html > html.sha256` in the same commit.

## How it was chosen

It was designed and selected with
[design-starter-kit](https://github.com/gorban/design-starter-kit), task `oc-dashboard`:

Four isolated attempts used the same brief and fixtures. Three used different design skills
and one ran without a design skill. The cross-provider council used neutral labels in both
scored rounds. Raw ballots could include a same-model candidate. The Borda tally excluded
those entries. The operator recorded scores and facet decisions in both rounds.

| Round | Candidate | Borda | Council rubric | Operator rubric |
| --- | --- | ---: | ---: | ---: |
| 1 | a4-claude-design | 0.75 | 83.0 | 72.0 |
| 1 | a1-hallmark | 0.75 | 84.5 | 66.0 |
| 1 | a3-frontend-design | 0.50 | 65.5 | 77.0 |
| 1 | a2-impeccable | 0.00 | 52.5 | 97.0 |
| 2 | a1-hallmark | 1.00 | 85.0 | 93.0 |
| 2 | a4-claude-design | 0.25 | 81.0 | 87.0 |
| 2 | a2-impeccable | 0.00 | 69.5 | 95.0 |

The first round narrowed the slate to three candidates. The operator selected a1-hallmark
after round two and kept the attention indicators and confirmation pattern from
a2-impeccable for the single-design refinement. Polish passes, WCAG audits and the
operator's acceptance check followed without a third scored council round.

The brief was synced to this repository at `3d3f408`.

The selected artifact is attempt `a1-hallmark` at commit
`26d81cf58435e6660023b993c7f45891ebdc1bb3`, tagged `design-final` in the design lab's attempt
repository, which isn't published. `DESIGN.md`, the tracked assets in `out/` and the
rebuilt pages are byte-identical to that commit. The generator and fixture include source
cleanup after selection.

## Accessibility (WCAG 2.2 AA)

| Audit | Design commit | Fail | Needs review | Pass | N/A |
|---|---|---|---|---|---|
| Full ([`audit/final-763cbac.wcag-issues.json`](audit/final-763cbac.wcag-issues.json)) | 763cbac | 0 | 1 | 43 | 11 |
| Scoped re-audit of the ownership note ([`audit/final-f1902bc-scoped.wcag-issues.json`](audit/final-f1902bc-scoped.wcag-issues.json)) | f1902bc | 0 | 1 | 43 | 11 |
| None: operator waiver for the fleet footer fix | 26d81cf (selected) | | | | |

- **Earlier failures:** the first full audit, on an earlier commit, found 6 failures, and a
  second found 1 more. All were fixed in the design's source before the passing audit.
- **The selected commit:** `26d81cf` updates the shared fleet table footer in Fleet, Inbox and
  Confirm, with the corresponding stylesheet and design note. A single `colspan="5"` cell
  aligns the footer when the Health column is hidden at medium widths. The operator waived
  its re-audit. Re-audit the footer in the implementation.
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
