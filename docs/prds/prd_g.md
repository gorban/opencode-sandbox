# prd_g: Carry-over from the parallel-instances plan

[Index](README.md)

Open items from `~/opencode-sandbox-prds.md` (the original plan for parallel instances, host ports and
docker-in-docker, implemented in PR #2).

- [ ] Confine the docker-in-docker sidecar with a dedicated SELinux type `oc_dind` instead of
      `label=disable`. This needs the AVC denials of `label=nested`, read from the audit log as root
      (`sudo ausearch -m avc -ts recent`). Fallback: a libkrun microVM runtime (`--runtime=krun`).
- [ ] Concurrent use of the shared `oc-home` by many OpenCode processes (worked with two). If it
      breaks, use a per-instance home seeded with a copy of `auth.json`.
- [ ] Per-instance `-p` publishing inside the sidecar's default network (today use `--network host`).
- [ ] Resource overrides per instance (`OC_*_MEMORY` exist; document how N instances multiply them).

- [ ] **Human review**: checked only when the user says so
