# M3a web dashboard walkthrough

Parent [M3a](../../../prd_m3a.md) · Related [M3.1 projection](../projection/PROJECTION_WALKTHROUGH.md)

This Gate 1 design covers a read-only synthetic dashboard in this directory. The loopback
host owns HTTP authentication, authorization, cookie and CSRF handling, and the enforcing CSP.
The fixture represents a local and an offline sandbox under two projects with enough threads
to exercise selection, empty states, and bounded updates. The standalone UI test injects the
fixture through the transport below. The production bundle reads the same shape through the UI-owned
same-origin browser adapter. Provider credentials, live workers, privileged commands, PTY, embedded browser,
production launcher and Tauri are outside this slice.

## Static build and host boundary

- Use Svelte 5 and SvelteKit 2 with `adapter-static`, fallback `200.html`, root-layout
  `ssr = false`, `inlineStyleThreshold = 0`, and `paths.relative = false` for
  root-relative `/_app/` URLs. Ship just static assets. Link to the
  explicit UI paths `/dashboard/projects`, `/dashboard/sandboxes` and `/dashboard/threads`.
  The host redirects `/` to Projects. Keep selection in memory and choose the first available
  authorized item on direct navigation. Put only the generic view in history state and URLs.
  [Static adapter](https://svelte.dev/docs/kit/adapter-static) · [SPA fallback](https://svelte.dev/docs/kit/single-page-apps)
- Proposed exact pins are Node 24.18.0 (lane-local mise), npm 11.16.0, Svelte 5.59.1,
  SvelteKit 2.70.4, adapter-static 3.0.11, vite-plugin-svelte 7.3.1, Vite 8.3.8,
  TypeScript 6.0.3 and svelte-check 4.7.8. Use Playwright 1.65.1 with its pinned Chromium
  and Lighthouse 13.6.0 for qualification. Commit the npm lockfile, use `npm ci`,
  and review the resolved dependency tree and applicable advisories at Gate 2. Build tools have no runtime role. Generated output, browser installations and
  measurement reports stay out of Git.
- Decode the single generated HTML fallback as strict UTF-8. Require exactly one
  executable inline bootstrap and reject inline styles, event handlers,
  `<meta http-equiv>`, `<base>`, CR and NUL.
  Use LF line endings and hash the raw UTF-8 byte span of the bootstrap body, excluding
  its tags. Emit `build/csp-manifest.json` with `version: 1`, `html_sha256` as hex
  over the complete HTML, and `inline_script_sha256` as base64 over the byte span.
  The host verifies both digests under the same rules, keeps the manifest private, and
  serves the exact HTML bytes with the authoritative CSP header. A changed byte sequence, unsupported bootstrap structure or a
  production deep link that fails under CSP blocks qualification. Review a same-origin
  external bootstrap separately if the hash approach proves incompatible. The read-only
  transport needs only same-origin fetch in `connect-src`.
  [M3 CSP](../../../prd_m3.md#3-shared-sveltekit-frontend-loopback-web-auth-and-tauri-v2-uds-bridge)

## Projection and transport

The shared endpoint `GET /api/v1/workspace` returns one bounded, authorized snapshot.
This lane owns the browser transport. Set `X-OC-UI: 1` on private reads and expose
current session identity, expiry and logout to the view. Call `POST /api/auth/exchange`,
`GET /api/auth/session` and `POST /api/auth/logout` on the same origin. Use the read marker on `GET /api/auth/session` as well as the workspace read. The browser
handles the HttpOnly cookie. The adapter holds CSRF in memory and supplies
`X-OC-CSRF` for logout. Bootstrap input uses a password field with autocomplete off, no name or native form,
and JS-only submission, with `form-action 'none'` on the host. Clear the field on
submission or hide.
The fixture implements the same interface with synthetic promises and an in-process
expiry or refresh signal. Visible event rows are part of the snapshot.

Qualify in one fresh, single-tab browser profile with one auth controller. Serialize
exchange and logout through the complete response, including validation of its status
and body. Keep a dispatched mutation in flight for the life of the intact page and
disable further auth mutations until it settles. On logout, clear the view immediately.
The host revokes the session and sends no `Set-Cookie` for logout. After confirmed logout,
the next confirmed exchange overwrites the inert stale cookie. If a mutation's outcome
is unconfirmed, keep the view signed out and require a fresh trusted browser profile
and a host reset before another exchange.

```text
Session = { read_session_id, session_generation }
Snapshot = Session + { version: "oc.m3a.web@1", projects: Project[] }
Project = { id, label, sandboxes: Sandbox[] }
Sandbox = { id, label, status: running | stopped | offline | unknown, threads: Thread[] }
Thread = { id, label, mailbox: {text}[], provenance: Entry[], events: Entry[] }
Entry = { label, text }

load(signal) -> Snapshot
subscribe(signal, callback) -> unsubscribe    # in-process refresh or session-ended
```

The read session ID is an opaque correlation alias with no authority, and the generation is
a safe positive integer. IDs use only `[A-Za-z0-9_-]`, up to 64 characters and unique
per sibling list. The read-session alias uses the same alphabet and exactly 32 characters.
DTO decoders require exact, closed sets of own keys and reject extra keys. The shared caps are 32 KiB per JSON response, 8 projects, 16 sandboxes and
32 threads in total, 8 rows per kind per thread, 120 Unicode scalar values per label
and 256 UTF-8 bytes per text field. The host enforces caps. The UI bounds reading before
UTF-8 and JSON decoding and checks shape, size, status and identity before storing it. Use Svelte text interpolation for all display strings. Replace C0, DEL, C1 and bidi
control characters in labels, including newlines and tabs. In bodies, normalize CRLF to
LF, preserve LF and tab, and replace other control and bidi characters. Wrap long words
and isolate text direction. Provenance labels
are host-derived display data. The viewer derives no authority from body text or labels.

## View flow

```text
exchange or session check:
  record monotonic and wall-clock start times immediately before dispatch
  validate identity and finite positive remaining TTL from the complete response
  deadline = monotonic start + reported remaining TTL
  expire on deadline, on wall elapsed >= remaining TTL, or on backwards wall reading
  discard stale or expired completions before installing any session state

mount or renewed session:
  retire old generation and clear selection
  record fresh client generation and host read-session identity
  subscribe with captured generation and load one no-store snapshot
  after each await or queued callback, require captured generation to still be current
  apply the same expiry checks before publishing and retire on expiry
  use Svelte flushSync to clear private rows on hide and before restore-time revalidation
  revalidate with the host and require a current session before publishing again
  on load completion, require the latest request and matching response identity
  select authorized item by in-memory ID, or first listed item, and render
  show empty, loading, or a generic retryable failure as appropriate

choose project, sandbox, or thread:
  resolve within snapshot hierarchy, reset dependent selections, render
  navigate to the generic view and expose the active item and section heading

refresh:
  cancel superseded load, start one request in current generation
  replace snapshot atomically, clear invalid selections and reselect within the new hierarchy
  on error clear displayed snapshot and offer retry
  on 401 or 403 retire the generation and clear adapter and view state

logout, expiry, authenticated identity change, pagehide, or component teardown:
  invalidate the generation before any await
  abort reads, unsubscribe, cancel timers and clear DOM, snapshot, selections and errors
  on logout request host revocation through the serialized auth controller
  use Svelte flushSync on pagehide before any page cache snapshot
  on page restore revalidate the host session before rendering private rows
```

Use native buttons for selections, links for generic views, headings and lists for content,
visible focus and status text, and a polite announcement for load, empty and session changes.
Keep the interface functional at narrow widths and with the keyboard. The bundle and HTML
contain public shell assets only. All auth and workspace fetches use same-origin
credentials, `redirect: 'error'` and `cache: 'no-store'`. Require JSON Content-Type on
successful responses with a body, and enforce a 4 KiB cap for auth and a 32 KiB cap for
workspace while streaming, before UTF-8 or JSON decoding. Logout expects an exact 204.
The host sends `Cache-Control: no-store` for private responses.
Keep snapshots and authorization-adapter state in memory. Avoid persistent storage,
service workers, route prefetch and diagnostic output containing payloads or auth data.

## Qualification

1. Check types, a clean locked production build, and absence of fixture payloads in built
   assets. Use one shared HTML fixture and expected hash pair to check both manifest
   generation and host verification, including rejected invalid UTF-8, CR, NUL, changed
   HTML and multiple bootstraps. Load each deep link in pinned Chromium through the
   actual host with the generated CSP. Verify the bootstrap runs and the host's CSP
   checks reject unapproved connections. Review WebSocket qualification with streaming.
2. Drive keyboard selection through the full hierarchy, including fresh deep links, empty
   snapshots and offline status. Verify mailbox, provenance and event text is literal,
   long rows wrap, and fixture body text produces no interactive elements or requests.
   Verify malformed, oversized and unsupported payloads clear the view and allow retry.
3. Hold a response and schedule a captured refresh callback. Retire via logout or expiry,
   authenticate a fresh generation, then deliver the old response and callback. Check the
   view, transport call count and state after delivery. Use the injected transport to
   simulate work that escaped cancellation, then exercise a held HTTP reply through the
   loopback host. Hold exchange and session-check replies past their request-anchored
   deadlines, including suspend and restore with a paused monotonic clock. Check that
   delayed or backwards wall-clock readings cannot leave private rows visible. Hold logout and verify the next exchange stays blocked until the full
   response. After confirmed logout, exchange again and reload the exact authenticated
   deep link. Verify an unconfirmed mutation leaves further exchange blocked. Inspect
   storage, URLs, and the initial HTML for private fixture data. After retirement, use
   Back and Forward and verify private rows stay cleared.
4. Run Lighthouse against a cold loopback navigation with the synthetic session cookie
   established in the same isolated Chromium session. Set Lighthouse
   `disableStorageReset` to retain that cookie across the audit and record browser, throttling, bytes and initial requests. Measure navigation to
   the first populated sandbox list with an app mark and confirm keyboard navigation in
   Playwright. Keep the report local and record concise measurements and limitations.

Implementation starts after general and security reviews clear this walkthrough revision.
Review the exact implementation commit and qualification results at Gate 2.
