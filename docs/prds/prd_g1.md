# G1: Decide managed launch admission before starting Chromium

Parent: [G](prd_g.md)

## Evidence and first slice

On main `4a22c63`, the launcher starts Chromium before running provider
admission in Python. When the operator declines the last ready provider,
the supervisor exits without creating a worker and Chromium stays running.
The scratch regression reproduced this for a new or restarted browser, including
with the Gemini continuation removed.

Make provider refusal, cancellation and initial config failure stop before
instance setup. Keep the accepted plan inside the trusted supervisor until
worker start. This slice preserves existing browser and sidecar lifetime once a
launch has passed admission. It leaves the Chromium command block, its config
digest, and the behavior of legacy launches, setup-only `-n`, and teardown
unchanged. It therefore has no upgrade replacement for a matching browser.

Startup may still fail after admission. In the independent rollback follow-up,
track the exact invocation, pod, container and start identity. In the scratch
tests, Chromium readiness and Postgres or DinD setup failure left the browser
running. A failed legacy attach also left a worker in the `created` state.
Ordinary managed worker creation needs an intent written before its possible
create, as it currently acquires the new ID only from the response. A missing
response does not prove no worker exists. These cases belong in the follow-up,
which must also preserve running or adopted resources and pending receipts
across cancellation, late host completion and teardown.

## Walkthrough

Keep the existing Bash launcher as the setup owner. Before it takes any
installation or lifecycle lock, start one trusted Python supervisor with the
same sanitized environment as the current managed entry point. Bash retains
its original setup inputs, physical working directory and terminal. Python
gets only the existing `HOME`, `TERM`, fixed `PATH`, typed intent and dedicated
control descriptors. No Postgres secrets or caller environment reach it.

```text
Bash validates the public request and source, then starts the isolated supervisor
    copy the foreground terminal separately from the private control pipes
    pass bounded intent and wait for one admission outcome
    on refusal, error or cancellation: wait for the supervisor and exit
    on acceptance: continue the current setup with original Bash inputs

Supervisor validates intent and performs host qualification before credential use
    permit existing authenticated refresh and model discovery
    run the current provider choices once and keep the accepted plan in memory
    send the authenticated parent one accepted or refused result
    wait for the prepared placement or owner loss; do not open a lease yet

Bash finishes setup under the existing shared lifecycle guard
    send a single verified placement record, including full pod ID and the
    resolved workspace, only after successful setup
    keep the guard until the supervisor signals that guarded creation has ended
    otherwise close the channel on error, cancellation or owner loss

Supervisor verifies the complete placement and original admission
    acquire its own shared lifecycle guard on the validated lock inode
    require both guards to overlap before any session container mutation
    on failure or cancellation: send no inference and clean up its own resources
    on success: create relays and worker using the prepared full pod ID
    release its guard after creation or verified cleanup and acknowledge before attach by worker ID
    supervise the TTY and per-request fences as before

Bash releases the guard once acknowledged and waits for the supervised session
    propagate signal cancellation and retain the primary error
```

The intent binds the validated instance, provider filter, UI mode, original
physical caller directory and requested workspace selector. Initial consent
identifies the explicit path or the automatic selector for the original caller.
Before accepting preparation, report the resolved path and verify it against
the same request and existing trusted worktree rules. Preserve the original
Bash context for host dispatch, Wayland, headless mode and optional setup
inputs. Existing setup prompts operate on the same terminal after Python has
finished admission and stopped reading input.

Use dedicated anonymous pipes and accept one bounded, typed message per phase.
Verify the owned child and exact acknowledgement before taking any continuation.
Reject malformed frames, additional data already available on the response pipe
before either continuation, and a final acknowledgement without end of stream.
Use the guard pipe and control pipe pattern already exercised by the launcher. Explicitly close
control and terminal descriptors in subprocesses other than the one intended
receiver. Test descriptor inheritance through both sides before allowing
invocation. The child retains all provider handles in its own memory. No public
flag, inherited environment setting or replay of argv can mint approval or
enter a private continuation.

Bash already owns the shared lifecycle guard after setup. The supervisor checks
the owner channel and acquires its own shared lock on the same validated inode
before the first session mutation. A Bash-only death must not release the
supervisor's exclusion during guarded effects or bounded cleanup. Verify the
full pod ID and trusted workspace selection under the guard. Use that full pod ID
for every create. Require the inspected pod and ownership to match before
starting or removing a worker or relay. Use the verified full worker ID for attach.
Refuse a workspace replacement observed at preparation, creation or attach
checkpoints. Podman still resolves the workspace mount by pathname. Exact inode
binding at mount time remains a separate runtime change. Reuse the managed instance
lock for managed workers. The shared lifecycle guard does not serialize other
same-instance setup. General startup adoption and legacy races remain in G.

Before a lease opens, revalidate the accepted routes against current config,
credential identity and generation, auth and billing policy, their full model
catalogs, and each acknowledged or previously absent usage hold. Treat drift as
a fresh-launch requirement. Keep the original plan and handles and allow no
extra providers or models. The existing per-request exposure, registration and
lease fences remain authoritative.

Both processes treat cancellation as sticky, including while a terminal
choice is idle or once a valid result is buffered. The original launcher owns
signal forwarding and child reaping. The supervisor treats owner pipe loss as
cancellation. Bound the entire guarded continuation, including lock acquisition, post-setup
provider revalidation, creation and acknowledgement. Reserve a separate bounded
cleanup window. No guard is held during an idle admission. Require a
verified successful setup result before worker creation. Setup can still leave
residue after admission, especially if the host may finish a timed-out mutation
or all owners die before quiescence can be observed.
Report that error and preserve evidence for the rollback follow-up.

## Container identity during the prepared session

Keep the verified create receipt through retirement. Podman's positional
namespace can resolve a name before a full ID. For a prepared session, select
the worker or relay by an anchored full-ID filter and the receipt's immutable
create label for start, attached start, stop and force removal. Supply no
positional name or ID. For a verified stopped predecessor, use its anchored
ID and checked ownership labels with non-force removal. Verify removal with
filtered full-ID inventory. An error, unexpected result or surviving ID
keeps the cleanup outcome unresolved. Qualify the native Podman selector and
attached start in the isolated guest, and test a mismatched identity with
inert stubs.

Because an empty filtered attached start can return zero, the invocation
gets a private, initially empty Podman file event log through its own minimal
configuration override. Pin the file and verify the devbox and physical host
see the same trusted inode. Require a bounded exact-ID attach record on
success and preserve the transport status and independently verified
cleanup. The clean Podman 6.1.3 guest emitted the exact attach record for a
short-lived worker and no record for the zero-match command.

Bind relay readiness to the verified relay. After listening while the grant
is pending, the relay writes one fixed record to its bounded private
container log. SELinux denied the isolated socket variants in the clean
guest and permitted the private conmon log without a policy change.
The record's MAC binds the grant incarnation, generation, port and
effective SELinux process label to the slot proof. Verify the configured
log path and pinned inode, exact live relay, and independently measured
bind-mount labels. An invalid, oversized, repeated or stale record aborts
before activation. The log remains outside the worker and relay mounts.

## Verification before review and merge

Security and general walkthrough reviews cleared the pre-admission scope. The
original launcher failed the refusal regression by creating a pod and starting
Chromium. The revised launcher stops before setup. Separate tests cover terminal
cancellation, phase acknowledgements, pod replacement, credential selection drift,
and recovery of a created container ID returned after cancellation. Local review
covered the Bash and Python changes. The clean-host runs and external review of
the exact implementation remain open.

- [ ] Show the old launcher starting a new or stopped browser on refused
  admission in a scratch copy with stubbed Podman. Verify zero browser,
  pod, relay and worker starts, no session lease, and zero inference or forwarded requests.
  Check read-only host qualification and existing credential refresh or model discovery separately.
- [ ] Recheck declined and accepted holds, no ready provider, invalid config,
  cancellation, and hung terminal input. Verify one prompt sequence and that
  teardown does not wait on a provider decision.
- [ ] Prove an approved start reaches the same setup and placement, reuses a
  matching prior Chromium container, and opens the existing UI mode. Cover explicit
  `-C` and `-W`, recorded and inferred worktrees, host dispatch, and headless setup.
- [ ] Test channel and spec bounds, inherited descriptor closure, wrong
  instance/workspace, changed binding/config/hold, partial preparation, and
  child or owner loss. Test parent-only death during a guarded create, with teardown
  waiting, and replacement under the same pod name. Every failed prepared start
  sends zero inference or forwarded requests.
- [ ] Run shell syntax, diff, portable CI and real Podman security checks.
  Use the clean SELinux test host for isolated parallel acceptance, including
  headless refusal and an attended Wayland no-window refusal.
- [ ] Record security and general walkthrough verdicts, then review the exact
  implementation and test evidence. Leave the parent Human review open.
