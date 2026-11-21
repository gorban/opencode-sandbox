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

## Pseudocode walkthrough

```text
open_lease(image_id, deadline):
    validate a full local Python image ID and require rootless Podman
    generate independent client token, fake provider credential, and fixture identity
    start one networkless fixture with its own writable tmpfs and attached pipes
    send fake provider credential down the private pipe for fixture initialization
    wait for a bounded ready event, then bind the owner-only job socket
    on failure stop and reap everything created for this lease

admit(http_request, listener_lease):
    put byte and time limits on HTTP headers and body, one request per connection
    require exact supported method and path, one Content-Length for POST, and one token
    reject transfer encoding, duplicate auth or lengths, and noncanonical routes
    match the token to the listener lease using a constant-time comparison
    allow only typed text request fields and the fixed synthetic model
    reject tools and unsupported fields. Forward no caller headers or identity selectors
    check lease expiry, revocation, request budget, and one-in-flight limit under the lease lock
    reserve generation before dispatch. Return the fixed catalogue for GET
    dispatch the validated text request only to that lease's private pipe

stream(active_request):
    read bounded, deadline-aware fixture frames and parse only known event types
    build fresh text SSE frames. Never forward raw stdout, stderr, or upstream errors
    bound output and write time and recheck lease state before delivering events
    finish only on an explicit upstream completion event
    on bad data, timeout, or early exit end the stream without a successful terminal event
    if dispatch already occurred, do not retry or reuse uncertain backend state

retire(lease):
    mark inactive and invalidate token before releasing admission lock
    close client stream and backend pipes to wake a stalled read
    stop and reap only this test-owned container, then remove its socket and scratch state
    on client disconnect during generation retire the lease as well
    repeat retirement safely from timeout, exception, and harness shutdown
    require a new lease and fresh runtime for recovery. Old tokens and state stay retired
```

Socket handling uses short per-operation deadlines plus a monotonic overall deadline, so a silent
or slow peer cannot defeat lease expiry. Expiry and explicit revocation use the same retirement
path and do not wait for upstream output. The test owns explicit random container identities
and verifies ownership before cleanup. No global prune or removal by image tag. Start with no
more than two simultaneous leases and a bounded test deadline.

## Verification and limits

- [ ] Show model discovery and a streamed text response through the real Podman fixture.
      Require one terminal event for success. Reject a hostile request with the other lease's
      token, forged selectors, mismatched routes/models, malformed HTTP, and tool inputs.
      Check two concurrent jobs against the correct fixture identity and output.
- [ ] Verify inspect settings and probe filesystem/network canaries inside the fixture. Verify
      that synthetic credentials and private state are absent from job responses, command-line
      arguments, container configuration, and routine diagnostics. Malformed fixture output is
      discarded and unexpected failures return generic errors. A compromised runtime could
      still encode its own readable state in a valid text response. This test verifies the
      designed channels and does not claim arbitrary secret detection in model output.
- [ ] Test stalled upstream output, early failure, disconnect, explicit revocation and expiry.
      Assert old-token denial, no successful terminal event after cancellation, bounded teardown,
      independent sibling lease operation, and absence of test-owned containers and socket
      directories on completion or error. Exercise separate teardown triggers with synthetic data.
- [ ] Record exact evidence and remaining open work. A passing probe establishes offline text
      lease behavior and the provider container boundary only. Actual Meridian and OpenCode V2,
      managed-job transport, tool continuations, authentication, provider egress policy, and
      licensing of a distributed runtime all require separate evidence.
