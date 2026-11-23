# M3a loopback host fixture

Gate 1 draft for [M3a](../../../prd_m3a.md). This lane owns `web-host/`. The
companion `web-ui/` lane owns the SvelteKit build and browser session state.
The fixture serves a bounded synthetic operator dashboard on one ephemeral
`127.0.0.1` port. Data stays in memory. The server takes no registry, home,
sandbox, or runtime path. The HTTP surface comprises static UI, auth, and one
workspace read. Event delivery, PTY, WebSockets, and workspace mutations need
their own slices.

## Request and session flow

1. Bind IPv4 loopback and derive the exact `Host` and `http` origin from
   the actual bound port. For every request, require one exact Host header.
   If Origin is supplied, require one exact Origin header. Both auth POSTs
   require Origin. The private GETs `/api/auth/session` and
   `/api/v1/workspace` require `X-OC-UI: 1`. Same-origin browser GETs may
   omit Origin. Grant no CORS or preflight permissions.
2. Read a bounded HTTP/1.1 request with a 16 KiB header cap. Preserve
   the original target and match only canonical origin-form paths. Refuse
   query strings, fragments, encoded aliases and traversal. Refuse
   forwarding or upgrade headers, duplicate headers, Transfer-Encoding,
   and malformed Content-Length. Reject duplicate cookie values for the
   fixture session. Use a single request per connection. At socket acceptance,
   set one two-second deadline from the real monotonic clock. Carry that
   deadline into the worker and complete all request parsing, including
   any body read, within it. Before each socket receive, set its timeout to
   the time remaining against that same deadline. A trickle of bytes cannot
   renew it. Check the deadline again before dispatch, then close on timeout
   without admission or projection work. Bound the number of active workers.
   On shutdown, retire authority and stop accepting connections. Interrupt
   outstanding reads with socket shutdown so handlers can close their own
   sockets and join without waiting for the peer.
3. Mint one operator bootstrap code through the trusted launcher or private
   harness control using [UiAuthManager](../oc_ui_auth.py). The operator
   enters it into the unauthenticated UI shell. Exchange the code at
   `POST /api/auth/exchange` within 60 seconds. Require a body of at most
   256 bytes, `Content-Type: application/json`, strict UTF-8, and the closed
   JSON object `{code: string}` with unique keys. Cap request bodies for all
   routes and reject any body on GET or logout. An invalid, expired, or used
   code receives a generic denial.
4. Under the retirement guard, require the pinned operator principal and
   active authority before mint, exchange, auth/session, logout, or read.
   For exchange, configure the manager with `max_sessions=2`. It consumes
   the code and creates the candidate session before the host revokes the
   previous session by hash. On successful manager exchange, swap in the
   candidate with a freshly minted noncredential `read_session_id` of
   exactly 32 characters from `[A-Za-z0-9_-]` and a
   monotonically increasing generation. Failed manager exchanges preserve
   the existing session. The client may still have an unconfirmed result
   after a successful host exchange.
5. Exchange and `GET /api/auth/session` return
   `{read_session_id,session_generation,csrf_token,expires_in_ms}` in JSON
   with a 4 KiB maximum body. Only a successful exchange sends
   `Set-Cookie`. The manager issues a host-only
   `HttpOnly; SameSite=Strict; Path=/` cookie. Keep the CSRF token in host
   and browser memory so a same-origin reload can recover it. Compute
   `expires_in_ms` from the remaining lesser of idle and absolute TTL at
   the final auth release check immediately before the first successful
   socket send. If remaining time rounds down to zero, return `401`.
   If the first send would block, discard the unsent frame and recompute
   on retry. Once any bytes are sent, preserve the frame. The client
   anchors its deadline to monotonic and wall time sampled before sending
   the request. Auth inspection and workspace reads use `touch=False`.
   The fixture deadline therefore stays fixed at login. With the manager's
   `idle <= absolute` constraint the idle deadline is reached first or
   both are equal. Independently reachable idle and absolute expiry
   requires a later activity policy and corresponding browser deadlines.
6. Verify `X-OC-CSRF` through the manager on `POST /api/auth/logout`.
   Retire the generation and return `204` without `Set-Cookie`. The old
   cookie has no authority. The next confirmed exchange overwrites it.
   Expiry or authority revocation also retires the record.
7. Use one auth controller in a fresh single-tab qualification profile. It
   serializes exchange and logout through full response confirmation and
   leaves these requests running while the page is intact. Only a complete,
   validated outcome lets the controller start the next operation. An
   interrupted or unconfirmed operation blocks further auth in the profile.
   The trusted harness resets by discarding the profile, stopping that
   fixture server, and starting a fresh server and profile. An exchange
   response can change the cookie before its body is confirmed. This
   qualification applies to one controlled tab and controller, with reload
   exercised only between confirmed operations.
8. Return fixed JSON denials. Use `400` for malformed request framing,
   malformed JSON, and unexpected request bodies, `401` for missing,
   invalid, or expired credentials, `403` for authority, Host, Origin,
   marker, CSRF, forwarding, or upgrade denials, `404` for unlisted target
   paths or path aliases, `405` for methods outside the route contract,
   `413` for a body over 256 bytes, and `415` for the wrong exchange media
   type. Keep codes, cookies, CSRF, internal session hashes, and fixture rows
   out of request logs, URLs, and browser storage. Suppress raw access and
   error logging. Cookies are host-scoped. Qualify the fixture in a fresh
   browser profile constrained to the fixture origin and isolated from
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

Use sibling-unique synthetic IDs of 1–64 characters from
`[A-Za-z0-9_-]` and positive safe integer generations. Cap the fixture at eight projects, 16 sandboxes in
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
      (403 for denied authority, 401 for retired session)
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
(`build/200.html`). Redirect `/` with a no-store `303` and relative
`Location: /dashboard/projects`. User selections stay in memory. Load
the prepackaged operator-trusted tree before listening. Open the build
root and its ancestors without following symlinks, then open descendants
relative to their parent directory descriptors with the same nofollow
requirement. Verify that opened file descriptors are regular single-link
files. Enforce per-file (4 MiB), aggregate (16 MiB), tree-depth (8), and
entry-count (256) caps. This protects path admission for the trusted
package. The harness keeps the source package private during startup.
Serve admitted bytes from an exact in-memory URL-to-bytes map. Exclude
the fallback, the manifest, unexpected types, service workers, and source
maps from the asset map. Use canonical paths and fixed MIME types and
return fixed errors for unlisted targets, including API and event paths.

At startup privately read `build/csp-manifest.json` from the trusted UI
build and exclude it from HTTP. Require
`{version:1,html_sha256:<hex>,inline_script_sha256:<base64>}`. Verify the
whole HTML digest over the original artifact bytes, then decode strictly as
UTF-8 and admit exactly one executable inline bootstrap. Reject CR, NUL,
invalid UTF-8, inline styles and handlers, `<style>`, `<base>`, and
`<meta http-equiv>`. Require the declared script hash to be 43 standard
base64 characters followed by one `=`, then compare the actual digest. Hash the raw UTF-8 byte span inside the bootstrap tags, including
all LF whitespace. Use the same byte contract in the UI manifest builder, host
verifier and shared fixture. Refuse startup on a missing manifest, a mismatch
or extra executable inline content. Serve the verified bytes as
`text/html; charset=utf-8` and insert the exact `'sha256-<base64>'` value in
the enforcing header on every HTML response.

```text
default-src 'none'; script-src 'self' 'sha256-<base64>'; style-src 'self';
img-src 'self' data:; connect-src 'self'; frame-src 'self';
frame-ancestors 'none'; base-uri 'none'; form-action 'none'
```

Send `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and
`X-Content-Type-Options: nosniff` on every response. Include
`Content-Security-Policy: frame-ancestors 'none'` on API, error, and
redirect responses. Ship the entire fixture without a service worker. Use a clean browser profile to exclude prior service
workers and local state.

## Offline qualification

- Standard-library host runner and deterministic fake clock. Use a private
  temporary directory, trusted tiny assets, local test client, and
  shutdown/join cleanup. Exercise missing, wrong and duplicate headers,
  foreign and null Origin, bootstrap reuse and deadline, invalid session and
  CSRF, unknown API and asset paths, and denied role/authority. Assert the
  reader count stays zero on admission denials and fixed denials contain no
  fixture text. Exercise the exact fixed deadline, including an idle/absolute
  tie and an auth TTL that floors to zero. Test replacement while the old
  session occupies a slot and check that a rejected exchange preserves it.
  Cover body limits, wrong media type, and duplicate Content-Length.
  Keep TCP peers connected with incomplete headers and an incomplete
  exchange body, and send bytes slowly enough to exceed the fixed request
  deadline. Assert incomplete requests close within the deadline, never
  reach the projection reader, and cannot change the current session.
  Separately start shutdown with incomplete requests outstanding and assert
  it interrupts reads and joins all workers within a bounded wait.
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
  UTF-8 with matching digests. Refuse changed HTML, malformed or mismatched
  script hashes, additional script content, forbidden markup, CR, NUL, and
  invalid UTF-8. Exercise nofollow ancestor and leaf handling, hard links,
  and reserved static paths.
- Joint smoke runs the packaged static build with real Chromium and the
  same loopback fixture. Deep-link from a fresh profile, exchange, reload
  to recover the session, and render private synthetic rows. Exercise the
  actual UI decoders against host responses for exchange, session recovery,
  and workspace so opaque token alphabets and lengths agree at the wire.
  Assert CSP allows the generated bootstrap
  while blocking a connection to a second disposable loopback origin.
  Check unchanged bytes, correct MIME, no-store, inert text, cookie
  attributes, absence of private state in offline assets and browser
  storage, no service worker, and an authorized page after reload.
  Hold browser delivery across logout or expiry and fresh login, then
  release it and verify the UI ignores the retired generation. The UI
  harness also releases its retired queued invalidation. Use preinstalled
  tooling and the supplied build artifact so the exercise does not require
  package downloads or external traffic.
