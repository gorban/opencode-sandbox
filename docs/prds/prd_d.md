# prd_d: Per-instance address and DNS name

[Index](README.md) · children: [prd_d1](prd_d1.md) (address + forwarding), [prd_d2](prd_d2.md) (DNS and cleanup)

## Goal

Every running instance gets its own host address and a name, e.g. `feat-a.<suffix>`, so the host can
reach **any** port an app opens with no `-P` mapping. The same URL works inside the pod (its Chromium)
and on the host. Names disappear when an instance stops, and stale entries left by crashes are cleaned
up on the next start.

## Constraints

- Rootless Podman with pasta: pods have no host-routable IP. Container addresses on a rootless bridge
  network live inside Podman's rootless network namespace, which the host can't reach.
- Everything stays on loopback, never the LAN.
- Host ports below 1024 (e.g. 443 for `https://feat-a…` without a port) need a one-time privileged
  setup; see [prd_d1](prd_d1.md).
- Never expose DevTools (9222) on the host. Postgres only as in [prd_a](prd_a.md).

## Items

- [x] Spike: per-instance loopback address with automatic forwarding of listening ports, including apps
      bound to `127.0.0.1` ([prd_d1](prd_d1.md); `spike-d1` at `41f58da`). Implementation remains open.
- [ ] Name resolution on the host for `*.<suffix>`, driven by the live pod list ([prd_d2](prd_d2.md)):
      systemd-resolved routing domain + user DNS responder, `NAME.oc-sandbox.internal`.
- [ ] The same name inside the pod: `--add-host feat-a.<suffix>:127.0.0.1` on pod creation, so the pod
      and the host use an identical URL.
- [ ] `-l` shows each instance's address and name; `-P` stays for explicit host ports.
- [ ] Tests in `tests/parallel.sh`: two instances on the same internal port, reached by name from the
      host and from each pod's Chromium; the name is gone after `-d`, and a stale entry is removed after
      a killed pod.

Estimated time: 3–5 days (after the 0.5-day spike).

- [ ] **Human review**: checked only when the user says so
