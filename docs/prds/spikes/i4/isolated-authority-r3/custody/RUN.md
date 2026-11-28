# Reproduce the synthetic custody fixture

[Reviewed custody walkthrough](WALKTHROUGH.md) is the contract. This runner is
separate from the OpenAI launch path. The reviewed pre-import, role and
controller-restart delta has SHA-256
`1ff2f8a78fa8bd8c40e04b78c775b220b5e678b358556eb4baca06843f09fb29`.

## Offline

Run the two focused suites from the repository root.

```sh
python3 -B -m unittest discover -s docs/prds/spikes/i4/isolated-authority-r3
python3 -B -m unittest discover -s docs/prds/spikes/i4/isolated-authority-r3/custody
```

Prepare the measured bundle from the exact staged custody tree or a reviewed
commit's tree hash. Choose a new path in a private scratch directory.

```sh
fixture=docs/prds/spikes/i4/isolated-authority-r3/custody/run.py
candidate=$(git write-tree)
python3 -I -S -B "$fixture" bundle "$scratch/appliance" "$candidate"
python3 -I -S -B "$fixture" verify "$scratch/appliance" "$manifest_sha256"
```

Set `manifest_sha256` to the digest printed when the bundle was prepared.
The legacy tree is always `fa6d7f4f807ddda140eadb2e98a285a4133753b8`. The
default receipt overlay is the reviewed plan's
`0f196987923eefe25d7dc9b971b990d7e0ed8f6d`, for offline preparation.
The bootstrap tests use real pidfds and Unix descriptor passing with scratch
children of the same UID. They cover correct identity, swapped genuine pidfds,
an unrelated live pidfd, an exited expected process, non-pidfds, bad kernel
credentials and excess ancillary descriptors. Each role checks an exact
inherited descriptor-purpose map independent of its configuration. The
foreground owner receives its bootstrap, controller pidfd and owner socket.
The holder also receives its receipt socket and pinned scope directory.
Legacy, sibling and worker roles have no inherited control descriptor.
The role launcher opens separate read-only stdin and write-only stderr
descriptions of the fixed `/dev/null` device. Its stdout is the writer of
the exact anonymous report pipe allocated and pinned by the controller.
A role checks these three endpoints before reading role configuration and
cannot reuse them as authority descriptors. Stdio failures are silent so a
refusal cannot write to a substituted descriptor. The controller service
keeps its separate standard-descriptor policy.

The legacy adapter runs the exact archived connector and its registration
store. It counts sends inside the real connection dispatch callback and uses
the exact proof and ledger code. Its canary placement seam substitutes the
accepted client TCP FD with one connected Unix socketpair end. It keeps the
archived Unix handoff, request parser, broker, write fence and settlement.
The original TCP address check, real worker placement and an attended TTY
need their own acceptance. No provider endpoint is exercised.

## Later isolated guest acceptance

The operator must independently approve the corrected receipt overlay
`6f8b05686e38730c8245ee41afc3e14ba9ad8873` combined with the custody
candidate. After review, regenerate the bundle with that tree as the optional
final argument to `bundle`. The runner refuses the original overlay in its
sealed entry point.

The isolated operator must supply a known clean, disconnected guest with no
workspace or credential mounts and preserve the bundle digest outside the
guest. Mount the verified root-owned bundle read-only at
`/opt/oc-r3/appliance`. Provision reserved accounts `r3holder`, `r3owner`,
`r3legacy` and `r3worker` with distinct numeric UIDs and GIDs. The legacy
sibling deliberately shares the legacy account. Give the two operator-mounted
fixture filesystems mountpoints `/mnt/r3h` and `/mnt/r3c` and set those
mount roots and `/run/oc-r3` to root-owned mode 0711. The appliance allocates
fresh private run roots under them. Use a filesystem with working Unix socket
and flock support. There is no user-namespace or same-UID fallback.

For later activation, the operator independently compares the reviewed
`preflight.py` digest and installs that single file as root-owned
`/usr/libexec/oc-r3-preflight.py` outside the appliance. The dedicated root
guest service pins its digest and the measured corrected-bundle manifest
digest in the canonical root-owned `/etc/oc-r3/service.json` record. Its array
fields in order are `"r3-service-v1"`, the bootstrap SHA-256, and the manifest
SHA-256. The installer must write the compact JSON bytes with no trailing
newline. The bootstrap uses only the fixed system interpreter and standard
library. It opens the candidate through no-follow descriptors, checks the
kernel mount and superblock read-only flags and rejects any nested or aliased
mount before measuring and executing candidate code.

The root service uses a cleared environment, standard descriptors, fixed
working directory and the independently pinned bundle digest. Preserve the
storage evidence outside the holder's rollback domain. The two service
executions use the same evidence that restoring the holder leaves the
external controller volume intact. The runner checks different kernel
devices and mount identities. The operator's external evidence establishes
which snapshots the controller and holder can restore.

```sh
/usr/bin/python3 -I -S -B /usr/libexec/oc-r3-preflight.py sealed "$manifest_sha256" "$storage_evidence_sha256"
# After service exit and verified original process retirement, use the returned handle.
/usr/bin/python3 -I -S -B /usr/libexec/oc-r3-preflight.py restart "$manifest_sha256" "$storage_evidence_sha256" "$restart_handle"
```

The first process returns `sealed_synthetic_retained` with an opaque handle.
The fresh controller reruns the complete bootstrap before reading the
retained pair and receipt. It verifies the original controller's retirement
and refuses receipt use with zero new owner authorizations or holder sends.
It reports `sealed_restart_refused` with separate lifetime fingerprints
after matching the holder, receipt and historical file evidence. Successful
retirement and refusal allow cleanup of identity-verified caller-owned
scratch. Unconfirmed status leaves the scratch and receipt in place for
inspection.

Exit 2 indicates unavailable preconditions, exit 3 indicates refusal or
failed acceptance, and exit 0 emits the sanitized result for that completed
phase. The runner does not install packages, create accounts, mount disks,
attach a network adapter, start a VM or start a provider route.
