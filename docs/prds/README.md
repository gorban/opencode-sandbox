# PRD index

How this tree works (progressive discovery, checkboxes, the human review gate): see
[`AGENTS.md`](../../AGENTS.md#prds-progressive-discovery-in-docsprds).

| PRD | Grouping | Status |
|---|---|---|
| [prd_a](prd_a.md) | Postgres reachable from the host (`-P 5432`, `-P 5433:5432`) | implemented; external static review complete; human review open |
| [prd_b](prd_b.md) | OpenCode upgrades ready before launch; no drop to the host shell | pre-launch updates implemented; in-app restart open; external static review complete; human review open |
| [prd_c](prd_c.md) | Worktree defaults: current repo, `wt/<repo>/NAME`, relaunch | implemented; external static review complete; human review open |
| [prd_d](prd_d.md) | Per-instance address and DNS name (no port mapping needed) | forwarding feasibility measured; implementation open |
| [prd_e](prd_e.md) | Local HTTPS / TLS per instance (same URL in pod and on host) | CA feasibility measured, including host-browser subset; implementation open; depends on prd_d |
| [prd_f](prd_f.md) | Host tool dependencies, pinned and organised (mise) | dependency feasibility measured; implementation open |
| [prd_g](prd_g.md) | Carry-over from the parallel-instances plan | backlog |
| [prd_h](prd_h.md) | Warm start: shared setup (images, OpenCode install) done once under a lock | implemented; real acceptance passed; external static review complete; human review open |
| [prd_i](prd_i.md) | OpenCode orchestrator and sandbox fleet | proposed; host-only Claude routing spike open |

The imported findings are evidence, not production implementation:

- [D1](prd_d1.md): `spike-d1` at `41f58da`; user-observed main 31, matrix 12, restart 8, atomic 12
  and dynamic 2 checks passed. The production teardown fix is separate work.
- [F](prd_f.md): `spike-f` at `d1027f6`; 123 checks, or 128 with the newer-mise option, passed on
  both host and devbox.
- [E1](prd_e1.md): `spike-e1` at `7c16f4d`; 2,268 matrix results and a separately observed six-case
  E/X subset in each host browser. Those host observations do not cover the full browser matrix.

Already answered and needing no PRD (from the 2026-11-15 issue list):

- **Relaunch after OpenCode exits:** `oc-sandbox -i feat-a` alone is enough. The working directory defaults
  to `wt/feat-a`, which is already the worktree, so `-W` isn't needed again. Port mappings are stored on
  the pod and kept until a new `-P` is given. `-P` can be repeated (`-P 3001:3000 -P 8081:80`) or
  comma-separated. A remaining gap is tracked in [prd_c](prd_c.md): a different `-W` is silently ignored
  once the worktree exists.
