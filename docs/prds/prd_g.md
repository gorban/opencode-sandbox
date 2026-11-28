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
- [x] Global `-d -a` confirms that each volume and secret is gone. If one may remain, or the
      inventory cannot be listed, it still finishes the other steps, keeps the state and the
      installation binding so the same command can be retried, and exits with an error. Stubbed
      regressions cover a failed removal, a resource that survives its removal, and failed listings
      (`fix/global-teardown-status`).
- [x] Global storage purge verifies ownership before removal, never forces volume removal, and
      retains the installation binding when legacy storage or an incomplete inventory needs manual
      attention. New Postgres secrets carry ownership labels (`fix/global-teardown-status`).

- [ ] Run managed provider admission before Chromium or instance setup.
      See [G1](prd_g1.md) for the walkthrough and observed failure.
- [ ] Roll back resources owned by a launch that fails after admission.
      Stop only the verified startup incarnation if no worker has adopted it.
      Preserve existing resources, profiles and unresolved cleanup receipts.

- [ ] **Human review**: checked only when the user says so
