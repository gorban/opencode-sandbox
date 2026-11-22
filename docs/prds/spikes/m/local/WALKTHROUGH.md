# Local OpenCode PoC walkthrough

This spike covers the [local integration lane](../../../prd_m.md#first-poc-split) using
one real OpenCode 2.3.0 worker, a host broker, and a scripted synthetic model. The
host owns the job incarnation, the grant generation, the model endpoint, and the
run. No provider account, production launcher, or existing sandbox home is needed.

## Start

1. Run the harness and synthetic broker in the trusted devbox from a trusted
   checkout. Use installed, noninteractive host execution for fixed, bounded
   Podman and preflight commands. Confirm the expected process contexts, the
   same UID, the same owner-only scratch directory by device and inode, rootless
   Podman, and SELinux enforcing on the workstation. Validate full, locally
   available OpenCode and Python image IDs before creating resources. Keep
   explicit receipts for both containers using a random run label and immutable
   IDs. A broker started directly on the tested Fedora workstation received
   SELinux `EACCES` on the relay's connection. The devbox path uses the existing
   policy and labels.
2. Create the OpenCode container without external networking. Give it temporary
   home and workspace state and one synthetic provider on its loopback. Install
   a fixed configuration and distinct synthetic OpenCode and broker credentials.
   Disable inherited credentials, host proxy settings, capabilities and privilege
   escalation. Leave host ports and personal paths out of the mounts.
3. Start a Python relay in the same isolated network namespace. Give it only a
   read-only source copy, the read-only model socket and grant directories, and
   its private writable control socket directory. Verify the expected images,
   network, explicit mounts, port settings, and hard memory limits before
   starting the containers. Disable configured Podman subscription mounts for
   this run and require the host FIPS setting to be off. Confirm the namespace
   join and check both effective cgroup memory and swap limits before the first
   prompt. Keep SELinux enabled. The worker sees neither host socket.
4. The host grants exactly one incarnation and generation before dispatch. The
   broker authenticates eligible requests against that grant and registers their
   response sockets in the same critical section as revoke. Bearer possession
   cannot create or reactivate the grant. The broker accepts one bounded model
   route and invokes only the in-process scripted fake. Its response produces
   streamed text and a native OpenCode write to a fixed scratch path.

## Dispatch and revoke

1. Prepare and pin an OpenCode session, and subscribe to events before starting
   the turn. The absence of the proof file is checked independently inside the
   job. Bound the request, response framing, and event sizes. Accept no redirects
   or compressed responses. Treat worker output as untrusted and bind each
   accepted event to the pinned session and host-assigned identifiers. Compare
   each dispatch's target, incarnation, grant generation, and selected session
   with the adapter's pins before opening the socket.
2. The host and relay use the same fixed file-lock inode. State binds incarnation
   and generation. The relay receives a bounded, single control request and
   prepares its worker connection. Under the shared fence, it rechecks the
   current grant and attempts one nonblocking write to the worker. ZERO requires
   positive evidence that the worker received no bytes. A partial write is UNCERTAIN.
   A fully submitted request reports HANDED_OFF for transport progress only.
   The relay discards partial remainders. Missing receipts are UNCERTAIN. Retry
   neither an uncertain request nor a completed command. Release the fence before
   waiting for HTTP or SSE replies.
3. Verify a session text delta before its terminal event and the exact new
   scratch-file bytes through the isolated container. Start a second turn with a
   scripted response held open. Host revoke fences the broker and marks the shared
   grant terminal. Close registered streams. Verify the exact control stream is
   open immediately before revoke and closes afterward. If terminal state cannot
   be confirmed, invalidate the relay's lifetime lease, stop the relay, and
   report failure. Verify refusal of a new request with
   the correct stale bearer while the containers remain running. Record whether
   the held response shut down before teardown.
4. Exercise the final write boundary separately. Pause a relay request just
   before taking the fence, revoke and confirm terminal state, then release the
   pause. Require a zero-write receipt and no new fake-upstream admission.
5. Mark a create pending in the private receipt before calling Podman. Close
   sockets and remove resources by verified label and immutable ID. Check the
   complete run-label inventory before reporting cleanup. An unacknowledged
   create keeps cleanup unconfirmed even if the inventory is empty. A failed or
   uncertain operation keeps the private receipt and returns an error.

The cross-lane contract uses host-assigned target, incarnation, thread, message,
and grant pins, bounded events, and conservative handoff outcomes. The harness
may wait for the relay's bounded outcome outside the coordination hub. The
coordination workstream owns the hub and durable outbox restart verification.
Production wiring, live provider access, and human acceptance remain open.
