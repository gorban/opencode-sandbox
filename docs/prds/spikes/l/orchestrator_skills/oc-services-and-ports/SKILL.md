---
name: oc-services-and-ports
description: Explains capability-scoped service endpoints, exposure ceilings, authentication verifiers, constrained mise executables, and 2-tier zero-poisoning package caching.
---

# Services, Ports, Mise Toolchains, and Caching

## Universal Endpoint Exposure Policy

Every `service@1` declares its `[[endpoints]]` explicitly. Hardcoded port rules are gone:

- **`default_exposure` / `max_exposure`**: `"pod-only"` < `"host-loopback"` < `"instance-dns"`.
- **Pod-only ceiling (`max_exposure = "pod-only"`):** Example: Chromium DevTools (`9222`). Any attempt to expose it via `[[ports]]` or `--port` fails closed at plan time.
- **Auth-gated endpoints (`requires_auth = true`):** Example: `builtin/postgres` (`5432`) with `auth_enforcer = "pg-scram-ro-hba"` and `tls_policy = "required-when-ca-ready"`. Host or DNS exposure is refused unless a verified `auth_enforcer` is attached.
- **Named instances:** When running multiple copies of a service (e.g., `pg-primary` and `pg-analytics`), set `cardinality = "named-instance"` with distinct `instance_port` values so pod ports never collide.
- **`host_url_template`:** Only closed schemes (`http`, `https`, `postgresql`, `redis`, `tcp`) and closed placeholders (`{host}`, `{port}`, `{user}`, `{db}`, `{path}`) are permitted — never password placeholders.

## Constrained Workload `mise` Toolchains

- Declare ONLY exact three-part qualified tool pins in `[mise_tools]` (e.g., `"core:node" = "24.22.2"`, `"aqua:astral-sh/uv" = "0.13.6"`).
- Never use `latest`, version ranges, `[hooks]`, `[env]`, or `[tasks]`.
- Conflicting tool versions across bundles fail closed unless resolved in the Sandbox Type's `[mise_overrides]`.
- Compiled toolchains mount read-only at `/opt/oc-tools` (zero container startup downloads).

## 2-Tier Zero-Poisoning Package Cache

- Never propose shared writable cache volumes across sandboxes (cross-sandbox poisoning risk).
- Tier 1 uses a host/worker read-through reverse-proxy registry mirror (zero TLS MITM, `GET`-only from sandboxes).
- Tier 2 (`prd_i5`) uses immutable content-addressed RO/CoW seed layers keyed by `(auth_scope, arch, toolchain, lockfile_hash)`.
