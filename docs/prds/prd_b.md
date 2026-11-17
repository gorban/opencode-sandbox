# prd_b: OpenCode upgrades ready before launch

[Index](README.md)

## Problem

On first start OpenCode offers to upgrade (to 2.x). Upgrading ends the OpenCode process, and because
OpenCode is the container's main process (`podman run --rm … oc-agent`, with the image entrypoint
`opencode`), the container goes away and the user is back in the host shell. They then have to start
it again.

## Findings (2026-11-15)

- The image is built `FROM ghcr.io/anomalyco/opencode:latest`, but its baked copy is **1.19.5**. The
  self-updating copy in the `oc-home` volume (`/root/.opencode/bin`, first on `PATH`) is **2.3.0**: the
  user upgraded it.
- On setup, the script installs OpenCode into the volume with the official install script, but only
  when no copy exists (`test -x … || install`). It never updates an existing copy.
- The upgrade can be done non-interactively: `opencode upgrade --method curl [version]`.

## Decision (2026-11-15)

**Auto-upgrade before launch plus a restart guard** (user's choice): upgrade on every online setup
(with `OC_OPENCODE_VERSION` to pin or `keep`), and restart in place if OpenCode upgrades itself
mid-session. Related: [prd_h](prd_h.md) (warm start: shared setup done once under a lock).

## Proposal

- [ ] On every setup (while online), run `opencode upgrade --method curl` in the existing throwaway
      container that writes to `oc-home` (no Chromium/pod access, same SELinux level). Do it before
      launch, with a short timeout, and keep the current copy if offline. All instances share one
      binary, so upgrade under a lock (`flock` in `$STATE`) so two instances starting together don't
      both write it.
- [ ] Opt-out and pinning: `OC_OPENCODE_VERSION=2.3.0` pins a version, and `=keep` skips the upgrade.
- [ ] Make the agent survive an in-app upgrade: run OpenCode under a tiny wrapper inside the container
      that restarts it once if it exits right after updating its own binary (binary mtime changed),
      instead of ending the container. Ordinary quits still end the session.
- [ ] Rebuild check: bake a newer base. `ghcr.io/anomalyco/opencode:latest` appears stale (1.19.5), so
      look for the 2.x image name/tag. This is lower priority: the volume copy wins anyway.
- [ ] Tests: an upgrade step with a stubbed installer; the wrapper restarts after a binary change and
      exits on a normal quit; the pinned version is honoured.

Estimated time: 0.5–1 day.

- [ ] **Human review**: checked only when the user says so
