# Synthetic isolated OpenAI authority receipt

This spike exercises the first offline slice of the R3 walkthrough with SHA-256
`9515ddce274fd95f67723fd6c835361ef7f74b950d3927c95200673a73d02fcc`.
Run it from the repository root on Linux with `pidfd_open` available.

```sh
python3 -B -m unittest discover -s docs/prds/spikes/i4/isolated-authority-r3 -v
```

The controller and holder use separate scratch directories and the holder is
executed afresh in the crash cases. All processes in this slice run under the
test user's UID. The directories model independently restorable domains. They
may be on the same physical disk. The tests qualify the protocol and its
restart rules. Actual custody, independent rollback protection, billing-account
exclusion, public launch and the worker projection still require separate
acceptance.

## Transition

1. The installer pins the new scope, canonical journal identity and initial
   pair digest. An explicit installer-only invocation creates the private
   receipt and permanent controller lock. Only the controller generation
   that observes successful provisioning can serve the receipt. Starting
   another controller or holder never provisions either file.
2. The measured launcher passes anonymous `SOCK_SEQPACKET` endpoints for the
   controller and owner. Controllers and holders pin their peers' exact
   PID, UID and GID before accepting messages. The launcher pins each
   exact process with a pidfd before delivering the channel. Linux
   `SCM_CREDENTIALS` verifies the sender on each packet, and the pidfd
   establishes whether that process still exists. Each channel owns and
   closes its pidfd. Only exact, bounded messages are accepted. The scoped
   launch grant is admitted once on its own endpoint. The holder rechecks
   both sockets and their independent process lifetimes before dispatch.
   A fork retaining the socket cannot keep the original peer alive.
3. Under the canonical holder lock, read and validate both local files and
   obtain a fresh exact witnessed receipt. Verify the pinned owner grant.
   Durably publish the successor local journal and anchor and verify their
   canonical digest. Send the prior and successor commitments to the
   controller. The scratch launcher pins the private holder directory with
   a descriptor and retains the originally created lock inode. The holder
   opens the lock relative to that directory, with no symlink following or
   blocking open. It verifies the private single-link inode before and
   after flock. Pair files are also accessed relative to the pinned
   directory. They must be regular and the read size is capped at 1 KiB
   per file. Lock acquisition has a 250 ms deadline.
4. The controller compares the whole prior commitment under its permanent
   lock, rejects a stale or cross-identity prior and durably writes the
   successor as `pending`. Its acknowledgment contains the exact
   successor and a fresh challenge. The holder echoes the challenge only
   after verifying the acknowledgment. Only the same controller channel,
   on its next frame after acknowledging that commit, can witness it.
5. The controller persists `witnessed` on receiving that frame. The
   witness has no success reply. The holder requires a fresh exact
   readback after it, rereads both local files and checks the original
   endpoints before dispatch. Settlement uses the same path before
   enabling use of the settled head. The scratch pair captures synthetic
   phases solely to test publication. Spend accounting remains a separate
   journal concern.

## Failure and reconciliation

A failure before the external commit may leave a new local pair alongside an
old external receipt. Either mismatch or a partial pair blocks the holder,
including on a fresh process. A storage failure during a controller publication
puts the entire generation in a sticky reconciliation state. In particular,
a witness rename can leave apparently complete bytes visible after directory
sync fails. Reads never sync or adopt these bytes. A new controller generation
has no verified publication state and refuses all use of the retained store
pending separately trusted recovery. A new holder can still use a healthy,
verified controller. A controller commit followed by a lost or
incorrect acknowledgment leaves the exact successor pending on disk. A lost
exchange during transition is `receipt_transition_uncertain`. A restarted
holder attempting to read a pending head gets
`receipt_reconciliation_required`, even when the pair digest and revision
match. The first observation of a missing receipt or permanent lock is
`missing_receipt`. A stale or partial local pair is `pair_mismatch`.
Contention that times out yields `continuity_lock_busy`. An invalid local
lock or holder directory yields `invalid_scope_lock`. Receipt
reconfiguration, repair,
automatic acknowledgment retries and fallback to a prior head are outside
the protocol. Preserve both files and the controller receipt for separate
reconciliation.

If the holder has already verified the exact commit acknowledgment and the
controller has durably received its witness, a final read failure still
blocks the current call. A later operation with the same verified controller
generation may use a complete witnessed head after a fresh matching read
under the lock. A durable witnessed claim still
represents a possible send. A future holder must retain the claim and settle it
only with independently verified terminal evidence. This spike provides no
settlement, repair or replay policy for real spend.

Fresh, equal old copies in both domains are indistinguishable from the
original state. Joint rollback, reprovisioning an erased domain under a reused
identity, and replacement of the appliance's trusted source or installer are
outside this qualification. A deployment needs independent custody of the
receipt and an installation identity with verifiable continuity.

## Next isolated acceptance

Build the sealed-guest fixture offline first. Give the appliance controller,
measured foreground owner, holder service and legacy workstation/worker
distinct custody as R3 specifies. Place immutable measured source and the
fresh synthetic registration under appliance/holder ownership. Put controller
continuity on a separately retained domain. The controller passes the two
anonymous holder sockets and the corresponding owner and controller pidfds
into the holder. It passes the owner endpoint and holder pidfd to the measured
owner. It closes unused ends. The worker receives only a projected job
grant. Keep public bootstrap and provider paths disabled until placement is
qualified.

Archive the exact legacy tree at
`fa6d7f4f807ddda140eadb2e98a285a4133753b8`. Use its unmodified
`oc_openai/canary.py` `run_live_canary_e2e`, with both canonical and
alternate legacy ledgers, and its public proof, canary and ordinary dispatch
routes. Seed a separate, inert legacy store that the legacy client recognizes.
Use disjoint legacy and fresh-holder fixture counters, no upstream reachability
and no actual credentials. A positive control must show that the old client
can exercise the relevant legacy fixture path with its own state. Require zero
fresh-holder authorizations, bytes or counter increments from that client, a
sibling with the same workstation UID, and a worker holding a valid job grant.
Verify that they cannot read the fresh registration or obtain the owner or
holder descriptors through process or filesystem access. Then prove one
authorized bounded fixture send via the measured owner and assert that all
legacy artifacts remain byte-identical across the holder tests. Validate
revocation, two eligible synthetic profiles contending on one scope, denial
for route identity mismatches, and no source/profile identity on the worker
before proposing a separate public-route acceptance.
