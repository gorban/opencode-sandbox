# Sealed-guest OpenAI authority custody walkthrough

The implementation base is main `fa6d7f4f807ddda140eadb2e98a285a4133753b8`.
The separate staged receipt overlay is tree
`0f196987923eefe25d7dc9b971b990d7e0ed8f6d`. The R3 design reviewed at
Gate 1 has SHA-256
`9515ddce274fd95f67723fd6c835361ef7f74b950d3927c95200673a73d02fcc`.
This walkthrough requests security and general review of the concrete
appliance, descriptor bootstrap, and fixture choices below.

## Guest and source custody

The guest operator prepares a disposable Linux image with the network adapter
detached, no host shared mounts or credential environment, and a dedicated
root-owned system service for this one test. Package installation, account
creation, disk mounting and VM orchestration happen outside the runner. The
runner has no fallback to the workstation, a same-UID role, a user namespace,
or a currently installed OpenAI service. Offline preparation can test bundle
measurement, fixtures and command construction as a normal user. Running the
actual custody path needs the disposable guest service context, and the
offline status must distinguish these outcomes.

The appliance supplies a read-only, root-owned source mount containing the
frozen spike, the custody runner, and a separate archive of the exact legacy
tree. Prepare deterministic per-file SHA-256 manifests from explicit Git tree
objects. Reject a noncanonical or writable source directory, symlinks, host
paths, extra files, an unsafe mode, or a manifest mismatch before starting a
role. Use fixed absolute system interpreter and privilege-drop tooling.
Interpret trusted source under an empty environment with isolated Python and
explicit source paths. Do not import a Python module from a role's working
directory, scratch home, repository config, or environment. Reject unexpected
network interfaces or inherited Internet sockets. Legacy and holder upstreams
are in-process functions associated with distinct test counters. Canary's
ordinary local relay may use its scratch-only Unix socket.

The service provisions fresh empty run directories under operator-prepared
mounts. There is one holder filesystem and an independently retained
controller volume that is excluded from restoration of the holder. The
service checks fixed expected mount roots, explains and records their kernel
device and mount identities, and refuses aliases or a shared filesystem.
These checks cannot establish which snapshots the operator controls. Record
the hypervisor/controller custody evidence separately and suspend the
independent rollback result if that evidence is absent. Exercise restoring an
earlier exact holder pair without restoring the controller volume. A copied
peer directory on the same device, a second pathname, or restoring both
volumes together cannot satisfy this qualification.

Use one root controller and distinct non-root UIDs/GIDs reserved in the
disposable image for holder, measured foreground owner, legacy workstation
and worker. A sibling legacy process deliberately shares the legacy UID.
Set a private scratch HOME per role. The fixed privilege drop sets real,
effective and saved credentials to that role, clears supplementary groups
and inheritable/ambient/bounding capabilities, sets no-new-privileges and
starts an isolated process session. Verify those values in each measured
role before reading code-specific inputs or serving its channel. Use a fixed
system `setpriv` binary rather than Python pre-exec callbacks once service
threads exist. Any unexpected ID, retained capability, inherited descriptor
or missing kernel feature aborts the qualification.

## Original channels and exact process lifetime

The controller pre-creates separate anonymous `SOCK_SEQPACKET` pairs for
controller/holder and owner/holder. Inheritance passes the original designated
ends at role exec. Only the holder gets the holder scope directory FD and lock
identity. Keep the registration under a private holder-owned directory, the
continuity data under the root-only external volume, and the projected worker
job in a separate worker-accessible location. No named authorization socket or
bearer file exists. No legacy or worker role inherits an administrative
socket, pidfd, holder directory, bootstrap descriptor, or receipt.

One additional, single-use anonymous bootstrap pair per measured role solves
the timing problem of pinning the two exact peer processes after both have
been spawned. The controller opens pidfds while it owns the unreaped
children. It builds the expected PID/UID/GID for each purpose from its
measured process launch records. The receiver first pins this closed
role-to-peer mapping in a bounded metadata frame without descriptors. The
fixed second frame carries descriptors in its declared purpose slots. Neither
the ancillary order nor the supplied descriptor's own information can
establish an expected role identity.

The controller and measured roles share the guest PID namespace. The
receiver must verify that its procfs is genuine through the Linux kernel
filesystem type and that its own bounded procfs `self` and `status` PID
views agree with `getpid()` and the expected single visible namespace. A
mismatched, unavailable, or unverifiable view aborts the test. Each packet
must have kernel per-message credentials from the exact controller. The
controller's already-inherited pidfd is verified first against the
independently expected controller PID from role launch and its lifetime
polled before accepting either frame.

For every received pidfd, read the bounded kernel-provided
`/proc/self/fdinfo/<fd>` record in the receiver's procfs. Require exactly
one positive `Pid` value equal to the expected PID for that descriptor
purpose. Require its visible namespace identity to agree with that same
PID using the kernel's `NSpid` field. Reject an invisible, exited,
ambiguous, malformed or unsupported descriptor. Poll the pidfd for process
exit before using it and preserve the per-channel liveness checks
immediately before the first fixture write. Correct ordering and a readable
pidfd alone cannot satisfy this identity check.

Accept only these two bounded frames, validate descriptor counts and types,
mark received descriptors close-on-exec, close all unexpected or truncated
ancillary descriptors, and close the bootstrap endpoint before authority
traffic. Authority sockets and scope dirfds are inherited directly. Exercise
swapped genuine controller/owner or holder pidfds, a genuine pidfd for an
unrelated live process, and a genuine pidfd whose expected process has
exited. Each case must abort bootstrap, close all descriptors delivered in
the failed packet, and leave authorization and fixture counters at zero.

Create the worker projection from fixed test data after measuring its
allowlisted shape. Include only an opaque job identifier, required relay
stub fields and bounded noncredential input. It carries no profile,
registration, source root, original controller FD or upstream authority.
The test demonstrates availability of allowed readable job data separately
from denial of holder authority.

## Legacy positive and negative controls

Load the unmodified `fa6d7f4` legacy modules under the legacy UID only. Keep
imports, real on-disk legacy registration, selection, legacy ledgers and
dispatch/persistence paths intact. Seed independent inert legacy profile
registrations through the old fixture constructors. Provider strings are
synthetic values generated only for this run and never printed. Any request
for browser sign-in, DNS, Internet/TLS, systemd, Podman or an actual provider
transport aborts the test.

Use explicit constructor or call seams for attended terminal, worker
placement and deterministic Responses transport. The transport invokes the
legacy first-write callback before incrementing the legacy-only counter.
Do not stub registration resolution, authorization, ledger verification,
the dispatch callback, or settlement. Exercise these measured paths in
fresh disjoint legacy state snapshots so a positive control cannot poison
another path.

- Invoke `run_live_canary_e2e` once with its default ledger and once with a
  second legacy-owned scratch ledger. Preserve `backend.active_connection`,
  the real end-to-end ledger, canary broker and bounded local relay; always
  supply the inert owner and provider transport. Count a legacy response
  only after the real write fence.
- Invoke `run_canary` and `acceptance.run_attended` with fake attended
  approvals and fake process/transport boundaries. Require the old canary and
  proof receipts and exact legacy counts. This isolates the boundary under
  test from a real TTY, worker container and web login. It does not qualify
  any of those production behaviors.
- Drive the old ordinary `SessionBroker` request through its established
  local relay and legacy registration/exposure fence with a bounded
  synthetic text response. Public shell launch and stock OpenCode UX remain
  separate qualifications.
- Attempt the old helper with the protected fresh ledger root or registration
  as designated synthetic inputs from the legacy process. Require a bounded
  fail-closed result and zero holder authorizations. Check designated access
  probes from legacy, its sibling and worker to the fixture-owned fresh
  registration and protected process FD directory; this fixture uses known
  measured PIDs and exists solely on the sealed guest. No inspection of
  unrelated processes, memory, or files. Require all denial cases to leave
  holder state and the holder counter untouched.

Snapshot the old registrations and historical ledger payloads after their
own positive controls. Digest the bounded expected file set before and after
the holder runs. Require byte-for-byte equality, excluding any explicitly
separate legacy run receipts created during their own positive controls.
Count legacy and holder dispatches independently, without logging message
content, tokens, account identifiers, protected paths or raw diagnostics.

## Holder acceptance and evidence

1. Start the measured owner and holder. Record only positive verification of
   their identities, measurement and allowlisted descriptors. Submit the
   exact one-shot operator intent, then require claim and verified settlement
   against one holder scope and the separate external receipt.
2. Exercise owner exit and explicit lifecycle revocation, wrong or unrelated
   peer, wrong slot, mismatched registration/generation, replay, and invalid
   grant data. Route mismatches are checked before local publication.
   Repeat holder-only start against the original verified controller, and
   verify that restarting the controller cannot reconstruct authority from
   the readable bytes.
3. Use two eligible synthetic profiles with distinct holder-only bindings
   contending under the same canonical scope lock. Count each authorized
   send once, and require matching settlement. Run stale exact pair,
   interrupted local publication and loss/refusal checks with fresh
   installation state, preserving the observed evidence on failure.
4. Require zero fresh-holder frames that reach authorization, sends, or
   counter increments from legacy, same-UID legacy sibling and worker.
   Require the worker's allowlisted projection to remain readable and all
   protected reads to fail. Check no old history changed across the holder
   cases. Redact full identifiers even in negative results.
5. Deadline every role and close private endpoints on failure. Reap only
   exact children started by this controller. Remove only the run's
   verified, disposable scratch when all roles are gone and the result is
   confirmed. Retain separate evidence for an uncertain transition.
   Return a distinct result for unavailable guest preconditions, failed
   qualification, and full synthetic custody success.

The review must approve the bootstrap fd transfer, privilege-drop mechanism,
mount evidence contract and exact legacy seams. Offline checks will exercise
closed input shape, measurement mutation, bounds, credential-free fixtures
and legacy positive controls in scratch. Only actual isolated guest execution
can qualify kernel role exclusion and independent storage custody.
