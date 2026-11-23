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
   `{read_session_id,session_generation,csrf_token,expires_in_ms}`. Only a
   successful exchange sends `Set-Cookie`. The manager issues a host-only
   `HttpOnly; SameSite=Strict; Path=/` cookie. Accept one session cookie value
   and reject ambiguous duplicates. Keep the CSRF token in host and browser
   memory so a same-origin reload can recover it. Compute `expires_in_ms`
   from the remaining lesser of idle and absolute TTL at the final auth
   release check immediately before the first successful socket send. If
   that first send would block, discard the unsent frame and recompute on
   retry. Once any bytes are sent, preserve the frame. The client anchors its
   deadline to the monotonic time captured before making the request. Auth
   inspection and workspace reads do not extend the deadline.
4. Verify `X-OC-CSRF` through the manager on `POST /api/auth/logout`.
   Retire the generation and return `204` without `Set-Cookie`. The old
   cookie has no authority. The next confirmed exchange overwrites it.
   Expiry or authority revocation also retires the record.
5. Use one auth controller in a fresh single-tab qualification profile. It
   serializes exchange and logout through full response confirmation and
   leaves these requests running while the page is intact. Only a complete,
   validated outcome lets the controller start the next operation. An
   interrupted or unconfirmed operation blocks further auth in the profile.
   The trusted harness resets by discarding the profile, stopping that
   fixture server, and starting a fresh server and profile. An exchange
   response can change the cookie before its body is confirmed. This
   qualification therefore applies to one controlled tab and controller,
   with reload exercised only between confirmed operations.
6. Use fixed bodies for auth failures, policy denials, unknown routes, and
   unsupported methods (`401`, `403`, `404`, `405` respectively). Keep
   codes, cookies, CSRF, internal session hashes, and fixture rows out of
   request logs, URLs, and browser storage. Suppress raw access and error
   logging. Constrain the trusted browser profile to the fixture origin.
   Cookies are host-scoped. Qualify the fixture in a profile isolated from
   other services on `127.0.0.1`.

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
  validate the full JSON body and preframe status, headers and body
  retain a bounded private frame and an unsent-byte offset in the handler

release(frame, context):
  use a short monotonic deadline for the whole response
  at each send attempt, take the same guard as retirement and check
    deadline, captured generation, active cookie, operator authority and expiry
    if retired before any bytes are sent, select a fixed denial
    if retired after any bytes are sent, close without sending the suffix
    otherwise call the socket directly with a bounded MSG_DONTWAIT send
  advance the offset only by the number of bytes accepted by that call
  release the guard before waiting for writability or retrying
  close on deadline or transport failure
```

The guarded socket call is the release boundary. Every successful send
releases exactly the bytes accepted by the socket. All unsent bytes stay
handler-owned and must pass the guard again. Use explicit Content-Length and
close the connection after this single response. Bypass buffered HTTP
writers for the private frame. Retirement remains available while a peer
stalls because the guard covers only the authorization check and the
nonblocking syscall. Socket-accepted bytes may reach the browser after
retirement. The client clears state and cancels outstanding reads on logout
or expiry, then rejects late completions after a fresh login. A queued
in-memory UI invalidation exercises that rule alongside the HTTP held reply.

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
whole HTML digest over the original artifact bytes, then decode strictly as
UTF-8 and admit exactly one executable inline bootstrap. Reject CR, NUL and
invalid UTF-8. Hash the raw UTF-8 byte span inside the bootstrap tags, including
all LF whitespace. Use the same byte contract in the UI manifest builder, host
verifier and shared fixture. Refuse startup on a missing manifest, a mismatch
or extra executable inline content. Serve the verified bytes as
`text/html; charset=utf-8` and insert the exact `'sha256-<base64>'` value in
the enforcing header on every HTML response.

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
- Hold one request before read and another immediately before its first
  guarded socket send. Retire by logout, expiry, or authority revocation and
  release each barrier. Assert zero reads in the first case and zero private
  bytes in the second. Use a stalled peer and an intentionally partial send
  to prove retirement completes during backpressure, and assert that no
  unsent private suffix reaches the socket after retirement. Open a fresh
  generation while the old request is held and verify the fresh read.
- Delay the auth response across the first socket-send barrier and check
  that the issued TTL reflects current host time and that the browser's
  pre-request anchor is conservative. Confirm exchange overwrites a revoked
  cookie and logout emits no `Set-Cookie`. Interrupt an exchange after its
  cookie header can arrive and verify that the controller blocks further auth
  until the harness resets the server and profile. Check the same recovery
  path when logout completion is unconfirmed.
- Share a bootstrap byte fixture with the UI lane. Accept LF and multibyte
  UTF-8 with matching digests. Refuse changed HTML and script hashes,
  additional inline executable content, CR, NUL, and invalid UTF-8, including
  when the supplied hashes otherwise match.
- Joint smoke runs the packaged static build with real Chromium and the
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
