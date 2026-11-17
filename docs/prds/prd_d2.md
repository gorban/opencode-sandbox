# prd_d2: Host DNS for instance names, and cleanup

Parent: [prd_d](prd_d.md)

## Host facts (2026-11-15)

Bazzite (Fedora Atomic), systemd-resolved in stub mode, mDNS off, LLMNR on. `/etc/systemd/resolved.conf.d/`
doesn't exist yet. No `mkcert`/`certutil` on the host; `openssl` and `trust` are present.

## Suffix

- `.local` is reserved for mDNS (Avahi). Unicast answers for it confuse resolvers, and mDNS would
  advertise the names to the LAN. Avoid it.
- `.internal` is reserved by ICANN (2024) for private use and never delegated; for example
  `feat-a.oc-sandbox.internal`.
- `.test` is reserved for testing; it also works.
- `.localhost` resolves to `127.0.0.1` automatically (browsers and resolved). That needs no setup, but
  every name gets the **same** address, which defeats per-instance ports.

## Decision (2026-11-15)

- Resolver: **systemd-resolved routing domain + a small user-level DNS responder** (user's choice).
- Suffix: **`NAME.oc-sandbox.internal`** (default instance: `oc-sandbox.internal`; can be confirmed or
  changed during human review).

## Resolver options considered

| Option | Pros | Cons | Time |
|---|---|---|---|
| **systemd-resolved routing domain** `~oc-sandbox.internal`, pointing at a tiny user-level DNS responder (in the bridge service, on `127.0.0.1:<high port>`) that answers from the live pod list (recommended) | one-time root setup (a resolved drop-in, like the SELinux module today); names follow pods automatically; stale entries impossible (answers come from the pods that are actually running) | a small DNS server to write and harden (answers only that suffix, loopback only) | 2–3 days |
| `/etc/hosts` entries written by a root helper on start/stop | simple, no daemon | root on every start/stop (a prompt each time, or a sudoers rule); crashes leave stale lines, so they need sweeping | 1–2 days |
| mDNS via Avahi | standard for `.local` | names leak to the LAN; mDNS is off on this host; slow | not recommended |
| `*.localhost` only | no setup | one address for all instances, so it doesn't meet the goal | 0.5 day |

## Items

- [x] Choose the suffix and resolver (see Decision).
- [ ] Inside pods: `--add-host` for the instance's own name (see [prd_d](prd_d.md)).
- [ ] Cleanup: with the responder, nothing persists. With `/etc/hosts`, mark lines and sweep the ones
      not matching a live pod on every start and on `-d`.
- [ ] `-d -a` removes the resolved drop-in (with an admin prompt, like the SELinux module).
