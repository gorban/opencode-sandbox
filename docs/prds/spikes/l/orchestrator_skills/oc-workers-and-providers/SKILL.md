---
name: oc-workers-and-providers
description: Explains targeting local Podman, remote SSH macOS/Linux workers, Tailcat, and Render cloud providers, handling capability mismatches, and safely proposing config changes.
---

# Targeting Workers, Host Providers, and Safe Config Proposals

## Choosing a Worker

Use `config_list(kind="worker")` and `config_get(kind="worker", id=...)` to inspect registered workers' `arch` (`x86_64` vs. `arm64`), `host_provider`, and capabilities (private hostnames/IPs remain redacted).

- **`builtin/podman-linux`**: Local/remote Linux rootless Podman (`supports_pods`, `supports_pasta`, `supports_image_mounts`, `supports_wayland` on desktop, `supports_dind`).
- **`builtin/podman-macos-vm`**: Remote Apple Silicon macOS Podman Machine over pinned SSH (`arm64`, `supports_pods=true`, `supports_wayland=false`, `supports_dind=false`). Services declaring a non-escalating `fallback_service` (e.g., `builtin/chromium-wayland` -> `builtin/chromium-managed`) substitute automatically during DAG resolution.
- **`builtin/cloud-render`**: One-off cloud jobs (`supports_pods=false`, mandatory `spend_cap_usd` and `max_ttl_seconds`). Workloads requiring sidecar pods fail closed at plan time instead of launching broken jobs.

## Safe Proposal Workflow

1. Inspect current specs with `config_list` / `config_get` / `config_schema`.
2. Test your proposed TOML via `plan_preview(sandbox_type=..., worker=..., draft=[...])` to verify zero DAG cycles, port collisions, capability mismatches, or policy denials.
3. Submit via `config_propose_revision(kind=..., id=..., action="upsert"|"archive"|"unarchive", proposed_toml=...)`.
4. Report the returned `proposal_id`, `proposal_digest`, and `security_delta` triggers clearly to the operator so they can review and run:
   ```bash
   oc-sandbox config approve <proposal_id> --digest <proposal_digest>
   ```
5. Remember: `worker`, `host-provider`, `transport`, `known_hosts`, `managers.toml`, and `builtin/*` are host-operator-only and cannot be modified via orchestrator proposals.
