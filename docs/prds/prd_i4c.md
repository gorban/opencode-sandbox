# PRD I4c · Gate 1 walkthrough for the synthetic Meridian prototype

Parent [I4b security and Meridian design](prd_i4b.md) · [Implementation review gates](README.md#implementation-review-gates)

## Scope and choices for review

- [ ] Prove the first text-only broker path with synthetic credentials and an in-repo upstream
      fixture. Put the probe and its checks in `docs/prds/spikes/meridian/` on the outside-in
      spike branch. Use the Python standard library and an already-present Python image by
      immutable image ID. Do not add an install, launch, or configuration entry point to the
      product. Both Antigravity subscription routes retain their current disabled status.
- [ ] Test the host-side boundary using hostile test clients and one real rootless Podman
      container per lease. The job client is a host-side test driver using a private Unix
      socket per lease. This checks HTTP admission and routing on a pre-bound channel. A later
      test must cover the managed-job `pasta` or SSH transport and isolation from inside a real
      OpenCode pod. Keep this probe independent of the production approval controller.
- [ ] Model the text-only subset of Meridian's Anthropic Messages API. Serve `GET /v1/models`
      and `POST /v1/messages` on the job socket. Return an Anthropic-style text event stream
      from known fixture events. Defer tools, tool continuations, images, arbitrary provider
      inputs, native plugins, and persistent sessions. Reject them before dispatch. The PoC
      tests the broker design. Meridian's actual Linux client compatibility remains open.
      [Meridian 1.93.0 surface](https://github.com/rynfar/meridian/blob/meridian-v1.93.0/docs/antigravity.md#supported-surface-and-limits)
- [ ] Review a separate artifact and transport amendment before using the actual Meridian
      package with a fake `agy` process. That checkpoint needs a pinned dependency and
      executable inventory, a credential-free install, a private broker-to-Meridian HTTP
      transport, and a test of its real event shapes and cancellation. The current fixture
      requires no third-party package install or code copy. Live provider access stays subject
      to [Stage 0](prd_i4b.md#proposed-antigravity-backend-via-meridian).

## Trust and resource boundaries

| Component | Holds | Reach |
|---|---|---|
| Trusted harness and broker | Lease records, deadlines, random job tokens, backend handles | Private per-lease Unix listeners and private Podman stdio pipes |
| Synthetic job client | Its assigned socket path and job token | Sends arbitrary HTTP bytes within that channel. Can present stolen values in negative tests. |
| Upstream fixture container | Different synthetic credential and private scratch state per lease | Rootless Podman with `--network=none`. No listening port or shared pod. Private stdin and stdout only. |

Treat the client as hostile and fixture responses as potentially malformed. Use an owner-only
temporary directory outside the workspace for control sockets. Only the harness creates,
expires, or revokes leases. Lease identity comes from which listener accepted the connection.
The caller cannot select a downstream container or channel through the request. The backend
fixture runs as a non-root container user with a read-only root filesystem, private tmpfs,
dropped capabilities, no new privileges, bounded resources, and no injected proxy environment.
Mount only the fixture source file read-only. Keep the host home, other lease directories,
sockets, and source repository outside the container's mounts. Run with `--pull=never`, a
fixed executable and arguments, and container logging disabled. Use no real provider binary,
provider credentials, credential stores, host agent sockets, or provider network calls.

Use one generation per lease for this first probe. This lets the fixture close stdout on
completion and makes unexpected output after its terminal frame observable. A successful request
settles the lease, releases its slot and retires its resources. Future multi-turn reuse has a
separate protocol and cancellation design.

The broker accepts strict UTF-8 JSON with no duplicate keys, non-finite numbers, unpaired
surrogates, or nesting deeper than eight levels. Cap the request body at 16 KiB, each text field
at 4 KiB, and the message array at eight entries. Bound fixture lines and event count as well as
total output. Fixture stdout uses newline-delimited JSON in the order `ready`, one to sixteen
`text` frames, one `done`, then EOF with a clean exit. Each frame has an exact schema. Any extra
bytes, duplicate terminal frame, out-of-order event, nonzero exit, or missing EOF fail the request.

## Pseudocode walkthrough

```text
open_lease(image_id, deadline):
    validate a full local Python image ID and require rootless Podman
    generate independent tokens and a run-specific owner label
    create the networkless fixture. Capture its complete immutable container ID
    record ID in a private cidfile at creation and verify the ID and owner label
    start and attach only by that ID
    send fake provider credential down the private pipe for fixture initialization
    wait for a bounded ready event, then bind the owner-only job socket
    on failure use the same receipt-based cleanup as retirement

admit(http_request, listener_lease):
    put byte and time limits on HTTP headers and body, one request per connection
    require exact supported method and path, one Content-Length for POST, and one token
    reject transfer encoding, duplicate headers, obs-fold, control characters, and noncanonical routes
    reject trailing or pipelined bytes already received before dispatch
    match the token to the listener lease using a constant-time comparison
    allow only typed text request fields and the fixed synthetic model
    reject tools and unsupported fields. Forward no caller headers or identity selectors
    check lease expiry, revocation, request budget, and one-in-flight limit under the lease lock
    transition READY to DISPATCHED before dispatch. GET returns the catalogue without reserving
    dispatch the validated text request only to that lease's private pipe

stream(active_request):
    enforce bounded, deadline-aware fixture event grammar, EOF, and clean exit
    build fresh text SSE frames. Never forward raw stdout, stderr, or upstream errors
    bound output and write time. Cancel if the peer disconnects or sends more bytes
    after validated completion, attempt DISPATCHED to SUCCEEDED and enqueue the terminal event
      in the same serialized operation used for revocation, without waiting on socket I/O
    release the in-flight slot on success and reclaim the lease resources
    on any post-dispatch error, retire. Never retry a dispatched request

retire(lease):
    serialize READY or DISPATCHED to RETIRING and invalidate the token before cleanup
    preserve an already committed SUCCEEDED outcome
    close client stream and backend pipes to wake a stalled read
    inspect the complete container ID and owner label before stopping or removing by ID
    confirm the ID no longer exists, then remove socket and scratch state and settle RETIRED
    if identity or cleanup is uncertain, fail the run and retain the private recovery receipt
    on client disconnect during generation retire the lease as well
    repeat retirement safely from timeout, exception, and harness shutdown
    require a new lease and fresh runtime for recovery. Old tokens and state stay retired
```

On a single broker event loop, terminal enqueue with the success transition and revocation
marking run without an `await`. If expiry or revocation wins, no success terminal is enqueued.
Bytes enqueued by an earlier success can arrive later. A downstream write failure after success
was committed still triggers cleanup and cannot cause replay. Socket handling uses short
per-operation and monotonic overall deadlines. A peer that pipelines after dispatch can abort the
one generation, and the broker never admits a second request on that connection. Keep at most two
simultaneous leases and bound the test duration. Cleanup uses full IDs from private receipts and
never targets names or tags. A partial create without a confirmed ID fails with the owner label
and available receipt retained for investigation.

## Verification and limits

- [ ] Show model discovery and a streamed text response through the real Podman fixture.
      Require one terminal event for success. Reject hostile requests with the other lease's
      token, forged selectors, mismatched routes/models, tool inputs, duplicate keys, non-finite
      numbers, obs-fold, control characters, and pipelining. Check concurrent job identity and
      output. Use bad fixture modes for wrong order, duplicate terminal, trailing data, and EOF.
- [ ] Verify inspect settings and probe filesystem/network canaries inside the fixture. Verify
      that synthetic credentials and private state are absent from job responses, command-line
      arguments, container configuration, and routine diagnostics. Malformed fixture output is
      discarded and unexpected failures return generic errors. A compromised runtime could
      still encode its own readable state in a valid text response. This test verifies the
      designed channels and does not claim arbitrary secret detection in model output.
- [ ] Test stalled upstream output, early failure, disconnect, explicit revocation and expiry.
      Use test barriers to run both orderings of terminal commit and revocation. Assert no
      success after revocation wins, old-token denial, bounded teardown, sibling independence,
      and absence of test-owned containers and sockets after completion or error. Test partial
      startup and ensure a replacement using the same name cannot be removed by cleanup.
- [ ] Record exact evidence and remaining open work. A passing probe establishes host broker
      lease behavior and synthetic fixture container isolation. The credentialed provider
      boundary, actual Meridian and OpenCode V2, managed-job transport, tool continuations,
      authentication, provider egress policy, and distributed runtime licensing stay open.
