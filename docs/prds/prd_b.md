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

- [x] Pre-launch upgrade implemented in `codex/foundations-batch` (automated gates passed; external review pending).
      An offline reader snapshots only the binary; the networked installer sees no shared home or
      sandbox. An offline writer promotes a complete candidate after the preceding container is
      verified stopped. Timeouts/offline failures retain the working copy. Shared setup is locked;
      unpinned 1.x upgrades request `--major`, and 1.x to a pinned 2.x uses the versioned V2 installer.
- [x] Opt-out and pinning: `OC_OPENCODE_VERSION=2.3.0` pins a version, and `=keep` skips the upgrade.
- [ ] Make the agent survive an in-app upgrade: run OpenCode under a tiny wrapper inside the container
      that restarts it once if it exits right after updating its own binary (binary mtime changed),
      instead of ending the container. Ordinary quits still end the session.
      OpenCode v2.3.0's [Restart action](https://raw.githubusercontent.com/anomalyco/opencode/v2.3.0/packages/tui/src/context/update-notification.tsx)
      exits normally, like an ordinary quit. A binary change alone cannot distinguish another
      instance's update, so this remains open pending a reliable upstream restart protocol.
- [x] Bake the official Alpine-based `ghcr.io/anomalyco/opencode:2.3.0` base; the shared volume copy
      still takes precedence. The original 1.19.5 observation was from the earlier image.
- [x] Tests: staged install/upgrade, pinning, offline fallback, concurrent changes and ordinary exits
      pass the 35-check lifecycle/update suite. Real fresh and warm updates pass; real parallel
      acceptance passes 45 checks. The in-app restart requirement remains open as above.

Estimated time: 0.5–1 day.

- [ ] **Human review**: checked only when the user says so
