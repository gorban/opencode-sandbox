---
name: oc-config-architecture
description: Explains the opencode-sandbox 3-axis compiler architecture, plan.lock.json IR, trust boundaries, and clean-slate CLI surface for the restricted orchestrator.
---

# opencode-sandbox Configuration Architecture

## 3-Axis Separation

`opencode-sandbox` separates every sandbox launch into three orthogonal axes:

1. **Workload (`sandbox-type@1`, `bundle@1`, `service@1`)** — WHAT runs inside the box: base image digests, nested bundles, recursive services, OpenCode v2 role contracts (persona, instructions, skills, MCPs), and pinned `mise` tools.
2. **Runtime Engine (`host-provider@1`)** — HOW containers execute: `builtin/podman-linux` (`pasta --no-map-gw,-T`), `builtin/podman-macos-vm` (`host.containers.internal` + `GatewayPorts` guard), `builtin/cloud-render` (one-off jobs, no sidecars, spend/TTL cap).
3. **Communication Adapter (`transport@1`)** — HOW the workstation reaches the worker: `builtin/local`, `builtin/ssh-pinned`, `builtin/tailcat`, `builtin/cloud-https`.

## Compilation & Immutable Plan IR

Before anything launches, the pure host compiler resolves all declarative `schema_version = 1` TOML into an immutable **`plan.lock.json`** with a canonical **`plan_digest`** (computed before instance-specific `drift` classification). Operators inspect plans with `oc-sandbox plan`, and `oc_controller` binds approvals to `plan_digest`.

## Trust Boundaries (Critical for Orchestrator)

- You have **no** generic host filesystem, shell, Podman, SSH, or raw secret access.
- Use ONLY the typed Config MCP tools (`config_list`, `config_get`, `config_schema`, `config_diff`, `config_history`, `plan_preview`, `config_propose_revision`).
- **Mutable kinds:** `sandbox-type`, `bundle`, `service` only. Never attempt to mutate `worker`, `host-provider`, `transport`, `factory`, `known_hosts`, `manager`, or `builtin/*`.
- Every `config_propose_revision` queues an immutable approval request (`proposal_digest` + closed `security_delta`) that only the human operator can approve with `oc-sandbox config approve <id> --digest <sha256>`.
- Never put plaintext API keys, passwords, raw `file.py:factory` paths, host bind mounts, or unpinned container tags (`:latest`) in TOML. Use typed `secret_slots`, `{file:/run/secrets/<slot>}`, opaque `factory_id`, and `@sha256:...` digests.
