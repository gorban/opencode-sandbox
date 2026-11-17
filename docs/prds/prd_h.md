# prd_h: Warm start for additional instances (shared setup once, under a lock)

[Index](README.md) · related: [prd_b](prd_b.md)

## Problem (user report, 2026-11-15)

Starting `-i feat-a` and `-i feat-b` for the first time together did the OS package installs (image
builds) and the OpenCode install twice.

## Cause

Each run checks the shared pieces independently and finds them missing or outdated at the same time.
Nothing serializes:

- `ensure_image` for `oc-agent` and `oc-chromium`: both runs build, so Alpine/Fedora package installs
  happen twice. Both compete for the tag, and the loser's build is left over (the image ledger removes it
  later).
- The OpenCode install into the shared `oc-home` volume: both download it and write the same files.
- The bridge install, the SELinux module check and the `$SB` relabel: done twice, harmless but slow.

## Proposal

- [x] One **setup lock** (`flock` on `$STATE/setup.lock`) around the shared phase: images, OpenCode
      install/upgrade ([prd_b](prd_b.md)), bridge, SELinux module, relabel. The first run builds; the
      others print "waiting for instance X to finish shared setup…" and then find everything up to date.
- [x] The per-instance phase (pod, Chromium, Postgres, docker-in-docker, worktree) stays parallel,
      outside the lock.
- [x] Hold the lock for shared setup only, not while OpenCode runs. Waiting has no timeout, and the message
      says which PID holds the lock.
- [x] Tests: two first-time setups started together build each image once (count `podman build` in a
      stubbed run, then real `tests/parallel.sh` concurrent-start acceptance); a killed holder releases the lock (flock
      does this automatically).

Estimated time: 0.5 day.

Implementation: `codex/foundations-batch`; real parallel acceptance passes 45 checks, with external
integration review pending. A separate shared/exclusive lifecycle barrier coordinates startup with teardown;
per-instance worktree locks protect selection records. Lock files are retained to preserve one
locking domain across teardown and restart.

- [ ] **Human review**: checked only when the user says so
