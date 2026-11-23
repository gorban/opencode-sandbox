# M3a loopback host fixture

Gate 1 draft for [M3a](../../../prd_m3a.md). This lane owns `web-host/`. The
companion `web-ui/` lane owns the SvelteKit build and browser session state.
The fixture serves a bounded synthetic operator dashboard on one ephemeral
`127.0.0.1` port. Data stays in memory. The server takes no registry, home,
sandbox, or runtime path. The HTTP surface comprises static UI, auth, and one
workspace read. Event delivery, PTY, WebSockets, and workspace mutations need
their own slices.

## Request and session flow

1. Bind IPv4 loopback and derive the exact `Host` and `http` origin from the
   actual bound port. For every request, require one exact Host header. If
   Origin is supplied, require one exact Origin header. Reject ambiguous
   headers, forwarding metadata, and non-origin-form targets. Both auth POSTs
   require Origin. A same-origin browser GET may omit it. Private GETs require
   `X-OC-UI: 1`, and the server grants no CORS or preflight permissions.
2. Mint one operator bootstrap code through the trusted launcher or private
   harness control, using [UiAuthManager](../oc_ui_auth.py). The operator
   enters it into the unauthenticated UI shell. Exchange a single bounded JSON
   `{code}` body at `POST /api/auth/exchange` within 60 seconds. Missing,
   expired, and used codes fail with a generic denial. The manager consumes
   the code atomically. The host pins the operator principal and creates a
   freshly minted noncredential `read_session_id` and monotonically
   increasing `session_generation`. A successful exchange replaces any
   active fixture session. An unsuccessful exchange leaves it alone.
3. Exchange and `GET /api/auth/session` return
   `{read_session_id,session_generation,csrf_token,expires_in_ms}`. The raw
   session ID is carried only in the manager's host-only
   `HttpOnly; SameSite=Strict; Path=/` cookie. Accept one session cookie value and reject ambiguous duplicates. Keep the
   CSRF token in the active host record and browser memory so a same-origin reload can recover
   it. Verify the `X-OC-CSRF` header through the manager on
   `POST /api/auth/logout`. On success retire the generation and expire the
   cookie with a `204` response. A validated expiry or revocation discards the
   record. Compute the remaining lesser of idle and absolute TTL from the
   same monotonic clock. In this short read-only fixture auth/session
   inspection and workspace reads do not extend the deadline.
4. Missing or retired sessions return `401`, policy denials `403`, and
   unknown routes `404`, and unsupported methods `405`, with fixed bodies
   and no private data. Keep codes,
   cookies, CSRF, internal session hashes, and fixture rows out of request
   logs, URLs, and browser storage. Suppress raw access and error logging.
   Use a fresh trusted browser profile constrained to the fixture origin for
   qualification. Cookies are host-scoped, so an ephemeral port alone does
   not isolate them from other services on `127.0.0.1`.

## Read contract and release fence

`GET /api/v1/workspace` is a same-origin, credentialed, no-store read with
no query parameters. Suggested response structure for joint qualification:

```text
{
  version: "oc.m3a.web@1", read_session_id, session_generation,
  projects: [{ id, label, sandboxes: [{
    id, label, status: "running" | "stopped" | "offline" | "unknown",
    threads: [{
      id, label, mailbox: [{ text }],
      events: [{ label, text }], provenance: [{ label, text }]
    }]
  }] }]
}
```

Use sibling-unique synthetic ASCII IDs up to 64 bytes and positive safe
integer generations. Cap the fixture at eight projects, 16 sandboxes in
total, 32 threads in total, eight entries per thread list, 120 Unicode
scalars per label, 256 UTF-8 bytes per text field, and 32 KiB serialized.
Enforce the full byte cap before release. Use fixed fixture labels for status
and provenance and include hostile-looking text as inert display input.
Publish only the fields above and echo the read alias and generation.
The grouped DTO represents the tree, status, events, and mailbox concepts in
the [operator projection](../projection/PROJECTION_WALKTHROUGH.md). The fake
reader follows its session/authority contract without opening SQLite.

```text
admit(cookie, request):
  under host lock verify exact request policy, pinned operator authority,
    active cookie, expiry and active generation
  capture the server-owned (principal, read alias, generation)

prepare():
  pass only the captured context to the bounded fake reader
  reader checks that authority and session are still active before reading
  build and validate the complete JSON body off the wire

commit():
  under the same host lock as logout, replacement and revocation,
    verify the captured context, operator authority and expiry again
  commit either the prepared private response or a fixed denial
```

The commit is the HTTP release decision. A retirement that wins this decision
returns only the denial. The client still fences delivery already committed to
the socket. It retires its generation and clears state on logout or expiry,
cancels in-flight work, and discards completions from retired generations
after a fresh login. A queued in-memory UI invalidation exercises that rule
alongside the integrated HTTP held-reply case.

## Static assets and CSP

Serve `/dashboard/projects`, `/dashboard/sandboxes`, and
`/dashboard/threads` from the trusted production static fallback
(`build/200.html`). Redirect `/` to projects. User selections stay in memory.
Resolve assets from an exact in-memory URL-to-bytes map admitted once from
the packaged artifact. Require regular files from the trusted artifact tree,
reject symlinks, use canonical paths and fixed MIME types, and reject
unlisted, encoded alias, dot-segment, and directory targets. Route misses
under API, event, and asset namespaces return fixed errors.

At startup privately read `build/csp-manifest.json` from the trusted UI
build and exclude it from HTTP. Require
`{version:1,html_sha256:<hex>,inline_script_sha256:<base64>}`. Verify the
whole HTML digest and the exact bytes inside its single executable inline
bootstrap. Refuse to start on a missing manifest, mismatch, or unexpected
executable inline block. Serve the verified HTML bytes and put the exact
`'sha256-<base64>'` value in the enforcing header on every HTML response.

```text
default-src 'none'; script-src 'self' 'sha256-<base64>'; style-src 'self';
img-src 'self' data:; connect-src 'self'; frame-src 'self';
frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```

Send `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and
`X-Content-Type-Options: nosniff`. Ship the entire fixture without a
service worker. Use a clean browser profile to exclude prior service
workers and local state.

## Offline qualification

- Standard-library host runner and deterministic fake clock. Use a private
  temporary directory, trusted tiny assets, local test client, and
  shutdown/join cleanup. Exercise missing, wrong and duplicate headers,
  foreign and null Origin, bootstrap reuse and deadline, invalid session and
  CSRF, unknown API and asset paths, and denied role/authority. Assert the
  reader count stays zero on admission denials and fixed denials contain no
  fixture text. Exercise expired idle and absolute lifetime independently.
- Hold one request before read and one after body preparation but before
  release. Retire by logout, expiry, or authority revocation and release
  each barrier. Assert no read in the first case and no private response in
  the second. Open a fresh operator generation during the hold and assert
  the old response cannot supply new-session data. Assert the fresh read
  succeeds with a new pair.
- Joint smoke runs the packaged static build with a local browser and the
  same loopback fixture. Deep-link from a fresh profile, exchange, render
  private synthetic rows, and assert CSP allows the generated bootstrap
  while blocking a connection to a second disposable loopback origin.
  Check unchanged bytes, correct MIME, no-store, inert text, cookie
  attributes, absence of private state in offline assets and browser
  storage, no service worker, and an authorized page after reload.
  Hold browser delivery across logout or expiry and fresh login, then
  release it and verify the UI ignores the retired generation. The UI
  harness also releases its retired queued invalidation. Use preinstalled
  tooling and the supplied build artifact so the exercise does not require
  package downloads or external traffic.
