# prd_m3a3: Frontend foundation, style guide, and test pyramid

Parent: [prd_m3a](prd_m3a.md) · siblings: [prd_m3a1 dashboard design](prd_m3a1.md),
[prd_m3a2 UI SDK agent bridge](prd_m3a2.md) · packaged by: [prd_m3b](prd_m3b.md) ·
delivery order: [prd_m](prd_m.md#delivery-order)

Added on 2026-11-28 from the operator's planning session. Lock the frontend's conventions before
any UI stream starts, so that parallel streams produce components that look consistent, compose,
and can be tested, and so that reviewers have a prescriptive foundation to cite. This is a Wave 0
blocker for every UI stream. Host streams do not wait for it.

Implementing the skeleton and harness is code, so the
[implementation review gates](README.md#implementation-review-gates) apply to it.

## Direction recorded

- **Stock skeleton.** Start from the official `sv create` skeleton and follow its conventions, so
  the project inherits the integration that the Svelte team tests. Every departure from stock is
  listed with its reason.
- **Add-ons.** Take `eslint`, `prettier`, `vitest` (unit and component usage), `playwright`,
  `storybook` and `sveltekit-adapter` with the `static` adapter. Leave out `tailwindcss`
  (styling is already decided in [prd_m3a1](prd_m3a1.md#open-decisions)), `drizzle` and
  `better-auth` (server-side), `mdsvex` (it compiles Markdown into components, against the inert
  Markdown rule), `paraglide` (translation is not planned) and `enhanced-img`.
- **Development add-ons.** Take `ai-tools` and `devtools` as well, set up as the
  [decision below](#open-decisions) records.
- **Async Svelte, now.** Enable it for its architectural benefits. The style guide says it is
  experimental. Watch for Svelte 6 and remove the flag then. Reconsider only if a critical issue
  appears. If it fails for one specific case, convert that case to conventional code, record the
  exception, and open a PRD item to revisit it once the feature has stabilised.
- **No remote functions.** They need a server, which the Tauri app does not have. Take their
  shape, not the feature.
- **Styling.** Plain CSS tokens with Svelte scoped styles, as already decided in
  [prd_m3a1](prd_m3a1.md#open-decisions).
- **The locked design is a UX mockup.** It is the target for look and feel, not an
  implementation guide. Copy its code only where that is the sensible way to match it.
- **Content Security Policy mechanics are out of scope here.** They are an implementation detail
  solved as issues arise, and are not expected to limit the architecture. If the mechanism ends
  up differing from the policy recorded in [prd_m3a](prd_m3a.md) and
  [prd_m3a1](prd_m3a1.md#platform-and-security-constraints-on-the-design), for example by using
  nonces, record that change and have it security-reviewed then.
- **Selectors.** One strategy, role and accessible name, shared by tests, accessibility and the
  [agent bridge markup rules](prd_m3a2.md#markup-rules-for-every-dashboard-view-needed-even-before-the-bridge-ships).
- **Tests.** A pyramid: full unit coverage on logic, component tests for every state, end-to-end
  tests for real operator scenarios, in two browser engines.
- **Storybook, committed.** Storybook is where components are designed, reviewed and
  component-tested. This is decided, not left to the spike. What is designed and tested there
  must be what is integrated, so the [consistency rules](#stories-match-the-app) below apply.
  The spike settles which Storybook setup to use, not whether to use it.
- **Review.** Every Storybook story is reviewed against the style guide.

## What the stack offers today (checked 2026-11-28)

Re-verify at Gate 1.

- **Async Svelte.** `await` in components has been available since Svelte 5.36 behind
  `experimental.async`. The documentation calls it experimental, "subject to breaking changes
  outside of a semver major release", and says the flag is removed in Svelte 6. With the flag on,
  block effects such as `{#if}` and `{#each}` run before `$effect.pre`.
  [Await expressions](https://svelte.dev/docs/svelte/await-expressions)
- **SvelteKit 3.** `svelte.config.js` is no longer supported. Configuration, including the async
  flag, goes to the `sveltekit` plugin in `vite.config.js`. Minimums are Node 22.17, TypeScript 6,
  Svelte 5.57.1 and Vite 8.0.12.
  [Migrating to SvelteKit 3](https://svelte.dev/docs/kit/migrating-to-sveltekit-3)
- **Remote functions.** They "always run on the server" through a generated HTTP endpoint, and
  queries cannot be used on a fully prerendered static site. No way to replace the transport is
  documented. [Remote functions](https://svelte.dev/docs/kit/remote-functions)
- **`sv create`.** Templates are `minimal`, `demo`, `library` and `addon`. Official add-ons are
  `ai-tools`, `better-auth`, `devtools`, `drizzle`, `enhanced-img`, `eslint`, `mdsvex`,
  `paraglide`, `playwright`, `prettier`, `storybook`, `sveltekit-adapter`, `tailwindcss` and
  `vitest`. [sv create](https://svelte.dev/docs/cli/sv-create)
- **What `sv create` generates.** Read from the CLI's source and its own snapshots at `sv`
  1.7.1, without running it. The `minimal` template with TypeScript gives `package.json`,
  `tsconfig.json`, `vite.config.ts`, `src/app.html`, `src/app.d.ts`, `src/lib/index.ts`,
  `src/routes/+layout.svelte`, `src/routes/+page.svelte` and `static/robots.txt`, with a `#lib`
  import alias declared in `package.json`. `eslint` adds `eslint.config.js`. `prettier` adds
  `prettier.config.js` and `.prettierignore`. `vitest` adds two test projects to
  `vite.config.ts`: `*.svelte.spec.ts` in a real browser, Chromium only, and other `*.spec.ts`
  in Node. `playwright` adds `playwright.config.ts`, which matches `*.e2e.ts` anywhere and runs
  against the built preview. `sveltekit-adapter` sets the adapter in `vite.config.ts`.
  `storybook` runs `create-storybook@latest`, and what that writes is not in the CLI's
  snapshots. [sveltejs/cli](https://github.com/sveltejs/cli)
- **Tauri.** Its SvelteKit guide requires `adapter-static`, recommends SPA mode with server
  rendering off, and says "Tauri doesn't support server-based solutions". The guide was written
  for SvelteKit 2 and its older config file.
  [Tauri and SvelteKit](https://v2.tauri.app/start/frontend/sveltekit/)
- **Storybook.** The SvelteKit framework docs are at version 10.6 and do not mention SvelteKit 3.
  Mocks for `$app/state`, `$app/navigation` and `$app/forms` are marked experimental. The Svelte
  story format is community-maintained. Its Vitest integration runs stories as tests in a real
  browser, with accessibility checks and coverage, and lists SvelteKit as supported. The
  `storybook` add-on sets up either "Storybook for SvelteKit or Storybook for Svelte & Vite".
  [Storybook for SvelteKit](https://storybook.js.org/docs/get-started/frameworks/sveltekit) ·
  [Vitest addon](https://storybook.js.org/docs/writing-tests/integrations/vitest-addon) ·
  [storybook add-on](https://svelte.dev/docs/cli/storybook)
- **`ai-tools` add-on.** It writes agent configuration into the project: the Svelte MCP server,
  skills, sub-agents and instruction files, including an `AGENTS.md` and Claude settings. Its
  recommended mode is a plugin that "keeps itself up to date". The MCP server offers
  documentation lookup, a static "autofixer" and a playground link, either from a hosted
  endpoint or from a local package run with `npx -y`. The Svelte team says it does not "log,
  store, or inspect code sent to the remote server". Supported clients include Claude Code and
  OpenCode. [ai-tools add-on](https://svelte.dev/docs/cli/ai-tools) ·
  [MCP tools](https://svelte.dev/docs/ai/tools)
- **`devtools` add-on.** It installs `@vitejs/devtools` and `@sveltejs/vite-devtools-svelte` as
  development dependencies and adds their plugins to the Vite config. It gives an in-page dock
  with component, reactivity, routing and performance inspection, and "an MCP endpoint for
  development-time Svelte diagnostics". The page does not say where that endpoint listens or
  what it exposes. [devtools add-on](https://svelte.dev/docs/cli/devtools)
- **Svelte's testing guidance.** Vitest for unit tests, Storybook with Vitest browser mode for
  component tests, and Playwright for end-to-end tests.
  [Testing](https://svelte.dev/docs/svelte/testing)
- **Actions lost before hydration.** Neither Svelte nor SvelteKit replays events, and the
  official pages read do not address the problem. It needs server-rendered controls. With server
  rendering off, the server sends an empty shell and each control is created by client code with
  its handler attached. [Page options](https://svelte.dev/docs/kit/page-options)
- **The existing [web-ui spike](spikes/m/web-ui/README.md)** was built by hand on SvelteKit
  3.4.0, Svelte 5.59.1, Vite 8.3.8 and TypeScript 6.0.3. It has no Vitest, ESLint, Prettier or
  Storybook, and it patches SvelteKit's root component, pinned by hash. It stays as evidence for
  the typed transport and the session-generation fence. It is not the starting point.

## Requirements

### Code home

Decided by the operator on 2026-11-28.

- The frontend lives in `apps/dashboard/`. That directory holds the project exactly as
  `sv create` generates it. The Tauri shell goes in `src-tauri/` beside `src/`, which is Tauri's
  own layout.
- The shared UI contract lives in `apps/dashboard/src/lib/contract/` and the shared fixture set
  in `apps/dashboard/src/lib/fixtures/` ([Gap M3.6](prd_m3.md#concrete-gaps-and-checkboxes)).
  Both are plain data, a JSON Schema and JSON fixtures, so the host side reads the same files.
- Fixtures are imported only by stories and tests. A lint rule enforces this, so a production
  route cannot ship a fixture.
- Tests sit beside the code they test, under the file names the add-ons generate: `*.spec.ts`
  for unit tests, `*.svelte.spec.ts` for component tests and `*.e2e.ts` for end-to-end tests.
  There is no separate test directory.
- A lane owns whole sub-directories under `src/routes/` and `src/lib/`, tests included. Files
  every lane shares are edited only by the lane that owns the foundation: `package.json`, the
  lockfile, `vite.config.ts`, `eslint.config.js`, `prettier.config.js`, `playwright.config.ts`,
  `tsconfig.json`, `src/app.html`, `src/app.d.ts`, the root layout and the Storybook
  configuration. Another lane that needs a change there asks for it.
- [prd_k](prd_k.md#later-runtime-layout) plans a root `src/` for the existing Python code. The
  frontend stays out of it.

### Order of work

The foundation is built in two parts, with the tech-stack spike between them. This is steps 2
to 4 of [Wave 0](prd_m.md#wave-0-prove-and-decide).

1. **Seed.** After the toolchain pins are set, generate the skeleton in the
   [code home](#code-home) and record the command. This covers the [skeleton](#skeleton) items
   up to the static adapter, and turning the async flag on.
2. **Spike.** The [tech-stack spike](prd_m3b.md#tech-stack-spike) generates the same skeleton
   from the recorded command under `docs/prds/spikes/` and runs the
   [shared frontend qualification](#shared-frontend-qualification). It does not edit the seeded
   skeleton.
3. **Finish.** Apply the spike's findings to the seeded skeleton: the chosen Storybook setup,
   the two-engine harness, the rebuilt client and the style guide. The style guide can be
   drafted during the first two parts. It is finished here.

No UI implementation stream, including the [conversion lane](#conversion-lane), starts before
the third part is done.

### Skeleton

- [ ] Generate the project with `sv create` (the `minimal` template, TypeScript) and the add-ons
      listed above, in the [code home](#code-home). Record the exact command and the resolved
      versions. The `storybook` add-on runs `create-storybook@latest`, so the command alone does
      not reproduce the result. Record what it resolved to as well.
- [ ] Keep a deviation register beside the project: every change to a generated file or default,
      with its reason. A reviewer can ask for any unlisted departure to be removed. Two entries
      are known in advance: the async flag, and a WebKit instance beside the generated
      Chromium-only component test project.
- [ ] Turn server rendering off at the root and use the static adapter with a fallback page, as
      Tauri's guide describes. Check that guide's steps against SvelteKit 3's config location.
- [ ] Rebuild on the skeleton what the web-ui spike proved: the typed, transport-neutral client
      and the session-generation fence ([prd_m3a](prd_m3a.md)).
- [ ] Pin exact versions and review the dependency tree under [prd_f](prd_f.md). Storybook brings
      the largest addition.

### Async Svelte

- [ ] Enable `experimental.async` in the Vite plugin. The style guide states that it is
      experimental and names the Svelte version it was qualified on.
- [ ] Pin Svelte exactly. Upgrade it deliberately, with the component suite as the gate, because
      the feature can change outside a major release.
- [ ] When Svelte 6 is released, remove the flag and re-run the suites.
- [ ] Reconsider async Svelte only for a critical issue. For a failure limited to one case,
      convert that case to conventional code, record it as an exception to the rule with its
      reason, and add an item here to revisit it.
- [ ] Do not adopt remote functions. Shape the typed client
      ([Gap M3.6](prd_m3.md#concrete-gaps-and-checkboxes)) the way they are shaped, so components
      read the same and a later move stays small:
  - **queries** that can be awaited, are deduplicated while in use, and can be refreshed;
  - **commands** for writes;
  - a **live query**, as an asynchronous stream, for daemon events.

### Style guide

- [ ] Write the style guide as one document in the [code home](#code-home). Its structure and
      tooling areas carry the rules recorded there: fixture imports, where tests sit, and who
      edits the shared files. Give every rule an ID, so a
      reviewer cites the rule and an exception names the rule it departs from.
- [ ] State for each rule how it is enforced: by lint, by the type checker, by a test, or by
      review. Prefer a machine check wherever one exists.
- [ ] Cover these areas. The rules named here are the minimum.
  1. **Structure.** Tiers are tokens, primitives, composites, views and routes. Imports go
     downward only. Components are pure: data in through props, events out through callbacks.
     Only views and routes use the client, and a view receives it by injection. Nothing below a
     route imports a SvelteKit module such as `$app/*`.
  2. **Async and data.** Every `await` sits under a boundary with a pending state and a failed
     state. No fetching inside components. This area holds the async rules above.
  3. **State.** Runes only. Shared state lives in modules tied to the session generation.
     Nothing private outlives sign-out. URL state is limited to the closed parameters in
     [prd_m3a1](prd_m3a1.md#shell-and-information-architecture).
  4. **Component interface.** Typed props, snippets, callback props, and variants as closed sets.
  5. **Styling.** Tokens are the only place a literal colour, size, radius or duration appears.
     Styles are scoped to their component. One small base layer holds the reset, type and focus
     ring. No global selectors outside it. Variants are set through attributes. Theme and
     density are set on the root.
  6. **Interactivity.** Enabled means it works: a control is enabled only when its handler is
     attached and what it depends on is ready, such as data, the bridge and a live session. A
     disabled control shows why, in visible text. An action in flight blocks a second
     submission. No interactive control is server-rendered or prerendered. If a page is ever
     prerendered, its controls stay disabled until they are mounted. A user cannot see an
     invisible readiness signal, so a lost action is a user-facing defect.
  7. **Accessibility and selectors.** Every control has a unique, stable role and accessible
     name, and the name starts with the visible label. Repeated controls carry their row in the
     name. Tests select by role and name only: no test IDs and no CSS selectors.
  8. **Trust and content.** Untrusted text is shown only through the designated primitives. No
     raw HTML. Addresses use the address component. The reserved vocabulary in
     [prd_m3a1](prd_m3a1.md#trusted-chrome-visual-language-anti-spoofing) belongs to host
     components.
  9. **Stories.** Every component has a story for each of its states, in both themes and both
     densities, and a hostile-content story. Stories use the shared fixtures, make no network
     calls and assert behaviour, not only appearance. They follow the
     [consistency rules](#stories-match-the-app).
  10. **Testing.** The pyramid and the banned waits below.
  11. **Tooling.** The stock skeleton, the deviation register, exact pins and the upgrade
      procedure.
  12. **Review.** How a reviewer applies the guide, and how an exception is recorded: inline,
      with the rule ID and the reason.
- [ ] Derive a story review checklist from areas 4 to 9. Each new or changed story is reviewed
      against it, including by the external adversarial reviewer.

### Stories match the app

What is designed and tested in Storybook must be what is integrated. Storybook renders a
component in its own preview and replaces SvelteKit's modules with mocks, so this does not hold
by default. These rules make it hold.

- [ ] **Same files.** A story imports the component file the app imports. No story-only
      wrapper, variant or stylesheet changes how a component looks or behaves.
- [ ] **Same compiler settings.** Storybook and the app build from one Vite configuration, with
      async Svelte on in both. A story that uses `await` proves it.
- [ ] **Same global styles.** The tokens and the base layer load from the same files in both.
- [ ] **Same fixtures.** Stories, component tests and end-to-end tests use the one shared set.
- [ ] **No SvelteKit modules below routes.** Because of the structure rule, a story never needs
      Storybook's SvelteKit mocks, which are marked experimental. A view runs with the fixture
      client in a story and the real client in the app, and is otherwise the same code.
- [ ] **Screens are stories too.** Each screen has a story composed from the same views. The
      end-to-end suite compares each screen in the built app with its screen story.
- [ ] Routes, navigation and the live client are outside Storybook. The end-to-end tests cover
      them on the built app.

### Test pyramid

- [ ] **Unit.** 100% line and branch coverage on logic modules (`.ts` and `.svelte.ts`), held by
      a threshold in the checks.
- [ ] **Component.** Stories run as tests in a real browser through Storybook's Vitest
      integration, with accessibility checks. Every state on the states sheet is covered.
- [ ] **End to end.** Playwright tests for the operator's
      [primary jobs](prd_m3a1.md#users-and-primary-jobs), against the built app on fixtures.
- [ ] **Two engines.** Run the component and end-to-end suites in Chromium and in WebKit. The
      packaged app's own WebView gets a smoke run under [prd_m3b](prd_m3b.md).
- [ ] **Waiting.** A test acts on a control and relies on the runner's own wait for that control
      to be visible and enabled. Fixed timeouts, waiting for the network to be idle, waiting on a
      hydration or readiness marker, and forced clicks are banned, by lint where a rule exists.
- [ ] **A test that passes only with an added wait is a product defect** under the interactivity
      rule. The fix goes in the component. A reviewer can cite that rule for a flaky end-to-end
      test.
- [ ] **Early action.** Include tests that act the moment a control becomes enabled, under a
      slowed processor, and check that no action is lost.
- [ ] **Fixtures.** Every tier uses the one shared fixture set
      ([Gap M3.6](prd_m3.md#concrete-gaps-and-checkboxes)), including its hostile strings.
      Clocks are controlled. Retries are not used to hide a flaky test.
- [ ] **Look and feel.** Compare each rebuilt component and screen with the mockup by
      screenshot, in both themes.

### Conversion lane

A parallel lane that can start as soon as the foundation is finished
([order of work](#order-of-work)). It does not wait for the daemon or the Tauri bridge.

- [ ] Rebuild the mockup's components as stories, in tier order: tokens, then primitives, then
      composites, then screens. Reuse the mockup's token values, since they define the look.
- [ ] Start with presentational pieces such as badges, wells, status, notices and the address.
      Interactive primitives wait for the
      [UI SDK decision](prd_m3a2.md#open-decision).
- [ ] The design keeps changing while this runs, through the
      [design supplement](prd_m3a1.md#design-supplement). Apply each change to the rebuilt
      components as a delta, and record which mockup revision each component matches.
- [ ] A component is accepted when it matches the mockup by the comparison above, passes the
      story review checklist and has its component tests.

## Shared frontend qualification

The first set of checks in the [tech-stack spike](prd_m3b.md#tech-stack-spike). None of them
depends on the shell, and both shells need all of them, so they are a prerequisite for either
one. They run in Chromium and WebKit as browser engines, not in the packaged app.

If any of these fails, stop and return to the operator. The Tauri checks are not run and no UI
stream starts. Loopback-first is not a remedy, because a failure here affects loopback as much
as Tauri ([control-plane decision](prd_m.md#control-plane-decision)).

- [ ] The seeded skeleton builds as a static, client-rendered app.
- [ ] Choose the Storybook setup. Storybook's documentation does not mention SvelteKit 3, which
      dropped the config file, so check both setups the add-on offers on the pinned SvelteKit 3
      and Svelte 5 with the async flag on: "Storybook for SvelteKit" and "Storybook for Svelte &
      Vite". The rule against SvelteKit modules below routes means the second is enough. Prefer
      whichever shares the app's Vite configuration with the fewest departures from stock.
- [ ] Run the stories as tests in Chromium and in WebKit under the chosen setup.
- [ ] If neither setup works, this qualification has failed. There is no standing fallback.
- [ ] Async Svelte works in a client-rendered static build in both engines. Whether it works
      inside the packaged WebView is a
      [Tauri qualification](prd_m3b.md#tauri-qualification) check.
- [ ] Coverage can be measured on logic modules at the 100% threshold, and reported for
      components.
- [ ] Lint rules exist for the banned waits and the selector rule. Record their exact names, or
      write the rule if none exists.
- [ ] The dependency tree the add-ons bring passes the [prd_f](prd_f.md) review.
- [ ] The production build contains no `devtools` code and opens no development endpoint. Record
      where the `devtools` endpoint listens on the development server and what it exposes.
- [ ] The pinned local MCP server starts from the committed configuration without fetching
      anything at run time.

## Open decisions

- [x] **`ai-tools` and `devtools` add-ons.** Decided by the operator on 2026-11-28: both go
      in the repository. Both are development aids and do not ship in the product. What each
      does is recorded [above](#what-the-stack-offers-today-checked-2026-11-28). The options
      considered were neither, documentation lookup kept outside the repository, `devtools`
      added later, and both. The setup below was read from the add-ons' source at `sv` 1.7.1.
  - **`ai-tools` for Claude Code, as committed files.** Answer "Individual tools", not the
    Svelte plugin, so the skills, the sub-agent and the MCP configuration are files a reviewer
    can read and nothing updates itself. Skip the opt-in feedback skill, which reports
    corrections to an outside repository.
  - **MCP server, local.** Choose the local setup, which runs over stdio, so no code goes to the
    hosted endpoint. The generated configuration fetches an unpinned package each time. Replace
    that with an exact pinned version reviewed under [prd_f](prd_f.md), and list the change in
    the deviation register.
  - **Instruction file.** The add-on writes `apps/dashboard/AGENTS.md`. It covers the frontend
    only. The root [`AGENTS.md`](../../AGENTS.md) stays as it is and wins where the two differ.
    Add a line to the generated file saying so, and pointing to the style guide.
  - **`ai-tools` for OpenCode.** OpenCode has no committed-files mode. The add-on writes a
    project configuration that loads the `@sveltejs/opencode` plugin. A sandboxed OpenCode agent
    working in this repository would then load an npm plugin that the repository names. Pin it
    to an exact version, and get it reviewed by the owners of the sandbox configuration and
    OpenCode runtime ([prd_l](prd_l.md), [prd_b](prd_b.md)) before it is committed. Seeding
    does not wait for that review. The OpenCode part lands as its own change after it.
  - **`devtools`.** Take the add-on's default plugins. It configures itself for the development
    server only, with client authentication on. Before relying on it, record where its endpoint
    listens and what it exposes, and confirm that the production build contains none of it
    ([shared frontend qualification](#shared-frontend-qualification)).
  - **The style guide wins.** One of the bundled best-practice notes is already wrong for
    SvelteKit 3: it places the async flag in a config file SvelteKit 3 rejects. Where a bundled
    note and the style guide differ, the style guide applies. Record each such difference in
    the style guide's tooling area.

Rough estimates for the foundation itself: the skeleton and two-engine harness, 2 to 3 days;
the first style guide, 1 to 2 days. The conversion lane's size depends on the mockup and is not
estimated here.
