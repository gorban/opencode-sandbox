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
- [ ] Serialize overlapping starts of the **same instance name** through resource creation and a safe
      immutable-ID start handoff, while keeping different instances parallel. External static review
      of `d4782b6` found launch failures and resource churn from this race, without an established
      sandbox escape, authentication bypass, credential disclosure or data loss; it was non-blocking
      at P1/P2 severity. Add a deterministic two-launch stub regression and real same-instance check;
      cover owner death and the create-to-start gap without holding a shared lock for the session.

- [ ] **Human review**: checked only when the user says so
