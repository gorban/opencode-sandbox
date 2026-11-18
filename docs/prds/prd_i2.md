# prd_i2: Worker fleet, browser wall and terminals

Parent: [prd_i](prd_i.md) · related: [orchestrator](prd_i1.md), [broker](prd_i3.md),
[per-instance networking](prd_d.md), [local HTTPS](prd_e.md)

## Workers and connectivity

- [ ] Register local, remote and temporary cloud workers by friendly name. Keep addresses,
      host keys, connection state and engine authority in the host helper. Give orchestrator
      tools names, health, available capacity and connection status. Use worker-scoped identity
      and limits for CPU, RAM and concurrent jobs.
- [ ] Launch with pinned profile/repo revision, select the worker manually at first, and retain
      enough state to reconnect, resume and scope cleanup after controller restarts. Add
      capacity-aware placement, drain and expiring cloud leases when useful. Keep worktrees and
      sidecars on the worker, with explicit transfer of patches, logs and artifacts.
- [ ] Use SSH for reachable workers. Consider a restricted reverse SSH tunnel through a
      reachable bastion where a relay is acceptable. Consider Tailcat for machines behind
      separate NATs and Tailscale/Headscale for a standing fleet that needs centralized
      enrollment and policy.
- [ ] Carry commands, results, preview streams and scoped agent messages over authenticated
      connections. Use a resumable SSE stream for status and messages to the dashboard, with
      separate authenticated requests for actions. Show direct/relayed status where available.
- [ ] Spike Tailcat across two NATs, with restricted UDP and after a network change. Check
      direct upgrade, fallback, reconnect, bootstrap and access revocation, plus PTY and video
      responsiveness. Authenticate the peers and restrict exposed services to the worker API
      or SSH. Keep enrollment material in trusted host state.

Tailcat uses DERP for rendezvous and initial communication. Both endpoints attempt UDP hole
punching. After a successful upgrade, the WireGuard-encrypted session travels peer to peer.
DERP relays the encrypted tunnel if the network prevents a direct path. Tailcat can forward
selected services without changing OS routes, so unrelated traffic stays on each machine's
normal path. SSH needs a reachable endpoint or a tunnel/bastion and does not perform this direct
upgrade on its own. The proposed dashboard browser talks to the trusted host, which handles the
native peer connection. See [Tailcat](https://github.com/tailscale/tailcat),
[Tailscale connection types](https://tailscale.com/docs/reference/connection-types) and
[OpenSSH](https://man.openbsd.org/ssh.1).

```mermaid
flowchart LR
    A["Controller behind NAT"] -.->|Bootstrap| R["DERP rendezvous or relay"]
    B["Worker behind NAT"] -.->|Bootstrap| R
    A <-->|Direct encrypted tunnel when available| B
```

## Browser wall and terminals

- [ ] Keep the current manual launch workflow with visible local Wayland Chromium. For managed
      workers, provide an optional headed Chromium profile on a worker display or virtual display.
      Show PiP-style dashboard tiles with low-rate previews. Expand a selected browser to a live
      view. Limit preview bandwidth and show disconnect/staleness.
- [ ] Provide a trusted **Take control** / **Return to agent** action. Grant one expiring input lease
      for the selected browser, suspend agent input while it is held, and show the current owner.
      Mediate both agent and operator input through the same boundary so switching ownership is
      enforced. Revoke input on expiry, disconnect or explicit release. Keep the raw CDP endpoint
      private and separate browser streaming from dashboard approvals.
- [ ] Evaluate [CDP screencast](https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-startScreencast)
      and [input](https://chromedevtools.github.io/devtools-protocol/tot/Input/) for page views.
      Evaluate a nested display with [noVNC](https://github.com/novnc/noVNC) for the full browser
      window, tabs and dialogs. Treat worker pixels as untrusted display content in a clearly
      labeled region, isolated from host app controls.
- [ ] Put the original OpenCode session in a controller-owned tmux session if the terminal
      spike succeeds. Allow manually launched local instances to opt in as well. Offer named
      windows for the orchestrator, worker OpenCode TUIs and worker
      shells. Use remote tmux or a PTY host so worker sessions survive a dropped connection.
      Preserve separate OpenCode and shell targets. Add **Open OpenCode** and **Open terminal**
      actions to trusted dashboard chrome, resolving registered session IDs on the host.
      Support read-only attach and explicit input handoff when attaching to an active agent TUI.
      Keep tmux sockets and terminal launch authority in the trusted helper. See
      [tmux control mode](https://github.com/tmux/tmux/wiki/Control-Mode).

## CI and cloud

- [ ] Watch GitHub Actions or Concourse jobs. Display status and audit history. Route dispatch,
      cancellation and deployment through canonical approval requests with workflow, ref and inputs.
      Keep provider credentials and renewal on the host. Consider scoped GitHub App installation
      tokens for read and dispatch adapters.
- [ ] Preview Render deployment or temporary job requests with service, plan, estimated cost,
      runtime limit and cleanup. Require approval for new spend. Verify the worker runtime before
      treating a Render deployment as a full sandbox host. Render one-off jobs inherit the base
      service environment and lack its persistent disk. Use a service with scoped configuration.
      See [Render one-off jobs](https://render.com/docs/one-off-jobs) and
      [GitHub Actions workflows](https://docs.github.com/en/rest/actions/workflows).

## Open choices

- [ ] (decision needed) **Transport** — SSH first (recommended, mature, reachable endpoint
      required, 3–5 days). Tailcat (direct across compatible NAT, adds pairing and fallback
      operations, 3–5 day spike). Tailscale/Headscale (fleet enrollment and ACLs, another
      service or account to operate, 1–2 weeks).
- [ ] (decision needed) **Browser view** — page previews via CDP (recommended first, efficient
      tiles, limited browser chrome and dialog visibility, 3–5 day spike) or virtual display
      with noVNC (full window, higher resource cost, 1–2 weeks).
- [ ] (decision needed) **Terminal UX** — tmux plus a scoped attach command (recommended,
      familiar and resumable, terminal rather than browser UI, 2–4 days) or an embedded web PTY
      (easier from the dashboard, more session authorization and isolation work, 1–2 weeks).

Companions include [Tailcat](https://github.com/tailscale/tailcat/blob/main/LICENSE) and
[Headscale](https://github.com/juanfont/headscale/blob/main/LICENSE) (BSD-3-Clause),
[tmux](https://github.com/tmux/tmux/wiki/Contributing#licensing) (ISC),
[Concourse](https://github.com/concourse/concourse/blob/master/LICENSE.md) (Apache-2.0), and
[noVNC](https://github.com/novnc/noVNC/blob/master/LICENSE.txt) (primarily MPL-2.0, separate
component terms). Treat noVNC as an optional companion and preserve its file-level terms if bundled.
