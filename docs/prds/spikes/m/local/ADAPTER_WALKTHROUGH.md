# Local OpenCode hub adapter walkthrough

This extends the [standalone proof](WALKTHROUGH.md) with the real `CoordHub`
outbox and restart path from the [PRD M split](../../../prd_m.md#first-poc-split).
The fixture uses the same rootless Podman, SELinux, private relay and synthetic
model broker. The local lane owns this directory. The coordination lane owns
the shared contract, hub, registry and restart assertions.

## Admission and first write

- One fresh job, one logical thread, one host-created native OpenCode session,
  and at most one live turn. A trusted fixture operator registers the exact
  target, incarnation, edge and grant generation. The hub admits only direct
  operator prompts on that incarnation's sole unmonitored grant. Independent
  senders, additional edges or grants, scoped abort, controller dependencies
  and other worker routes are out of scope. Check eligibility when accepting
  and again when dispatching persisted work.
- Keep existing transports on their existing fence path. Opt the local relay
  into a bounded split-phase handoff only for the above authority. The hub
  records `dispatch_started` and retains a settlement owner before releasing
  its fence. The relay's existing lock and grant/lifetime checks serialize its
  actual write with full-incarnation revoke. Hub bookkeeping and enqueueing a
  control frame are neither a terminal fence nor evidence of worker delivery.

```text
prepare: pin session, then open bounded SSE before accepting the first turn
dispatch(turn):
  verify host assignment, pins, kind, digest, and absence of artifact references
  map the logical thread to the pinned native session
  assign a native message ID and encode the entire HTTP request before dialing
  refuse invalid or oversized input with a permanent zero-write result
  reserve the single stream slot before starting the relay exchange
  transfer the request and read only the bounded first-write receipt
  H -> publish a unique host stream ID with its pinned reader and prompt reply
  Z -> release the attempt and report proven zero bytes
  partial write, missing receipt, or unproved exception -> report uncertain
stream(stream_id):
  validate the matching prompt reply outside the handoff and hub fences
  match native events to the input ID, session, and tracked assistant steps
  map safe deltas and terminal events to host pins, mark output worker-derived
  close owned readers on terminal result, revoke, or bounded failure
```

The full encoded HTTP request cap stays 65,536 bytes. Preserve the shared text
and event budgets and the existing parser bounds. Emit bounded local error
reasons, never raw exceptions, credentials, worker paths, or raw worker
metadata. Missing or malformed events after handoff may end the stream as a
protocol error. They cannot turn a submitted request into a retry. An uncertain
attempt blocks further use of that incarnation until terminal cleanup. Reserve
the stream slot before initiating worker I/O so a second caller cannot attach to
a previous request's response. Use separate bounded prompt and SSE readers so
payload consumption stays outside the first-write deadline.

## Terminal revoke and recovery

On revoke, close broker admission and revoke its held response. Publish the
exact terminal job record under the existing relay write fence. End the
adapter's stream readers, keeping any paused fixture exchange available only
long enough to verify its terminal zero-write receipt. Confirm terminal state
or verified stop of the matching relay. If neither is confirmed, report failed
cleanup and keep replacement and admission fenced. A worker socket write
ordered before the terminal publication remains handed off or uncertain. A
fenced stream cannot publish ordinary deltas afterward.

The hub retains its in-flight owner through durable outcome recording or an
explicit tracked cleanup transfer. Recovery refuses to activate on an unsettled
handoff and must verify terminal authority for the previous relay before
opening replacement work if a revoke or handoff was unresolved. The fixture
keeps the trusted job owner alive across hub restart. It can attest to the exact
relay identity and terminal state. Reopening the database cannot start a new
grant, rearm the old relay, or recreate its job. Host owner loss is separately
covered by the existing lifetime lock and relay stop verification. Same-live
active-grant resume after owner loss is outside this fixture.

## Qualification

- Run socket and parser fixtures for mismatched identities, digest failure,
  unsupported artifacts, encoded oversize, duplicate or foreign events,
  partial writes, missing receipts, and stream failure after a proven handoff.
  Deterministic rejection must reach no worker socket and settle once. Never
  replay uncertain handoff. Retain the standalone isolation and teardown tests.
- Through the real hub, run a complete operator turn. Observe a streamed delta
  before terminal and independently verify the exact scratch-file contents
  through the worker container. Arm the broker hold, observe the next turn's
  stream, and queue another turn without dispatching it.
- Revoke through the hub. Confirm that the held stream closes, the valid old
  bearer is refused, and the queued turn has no handoff, worker event or new
  upstream admission. Reopen the persisted hub/outbox while the same terminal
  worker and relay remain running. Check that the old message stays cancelled
  and undispatched. Run the paused-first-write race separately and require the
  relay's own zero-write receipt after terminal fencing.
- Verify an authorized next turn on a fresh incarnation with a fresh broker and
  run identity, then confirm cleanup for each run label and immutable container
  ID. No account credentials, host ports, personal configuration, production
  launcher changes, or actual upstream traffic are needed.
