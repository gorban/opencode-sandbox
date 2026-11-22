# prd_l1: External secret isolation for unrestricted sandboxes

Parent: [prd_l](prd_l.md) · [Index](README.md) · related: [credential broker](prd_i3.md),
[outside-in broker and subscriptions](prd_i4a.md), [Postgres host access](prd_a.md),
[per-instance networking](prd_d.md), [local HTTPS](prd_e.md)

## Problem Statement

The offline spike PoC approved in [prd_l](prd_l.md) validates configuration compilation, remote MCP
read-only defaults, explicit canonical-URL write grants, and schema-level secret-slot separation,
but still models remote MCP credentials as container-side `{file:/run/secrets/...}` file mounts.

Because our sandboxes intentionally give the LLM full environment, file read, shell access, and
network egress inside the container, **any real external credential mounted into the container
filesystem or environment is exfiltratable**:
- Local ephemeral sidecar passwords (such as per-instance `builtin/postgres` or `builtin/api-demo`)
  are acceptable as `local-ephemeral` mounts because they are randomly generated per disposable pod
  and valid only against `127.0.0.1` inside that pod.
- Real external, accessible targets (staging/production HTTPS MCP servers, third-party APIs, or
  external Postgres/RDS connection strings) **must not** expose raw long-lived or external
  credentials inside the sandbox container. This directly aligns [prd_l](prd_l.md) with
  [prd_i3](prd_i3.md).

## Open Design & Implementation Items

- [ ] **(decision needed) Choose the holistic external-credential brokering architecture** —
      evaluate host-side typed reverse proxies & protocol adapters (zero TLS MITM), OpenShell
      adoption vs. mirroring OpenShell's credential-injection/L7 policy patterns, and industry
      workload-identity / short-lived dynamic credential patterns (SPIFFE/OIDC, Vault/Keeper
      dynamic DB creds, Boundary/Teleport-style DB proxies) via best-of-N + adversarial security
      review.
- [ ] **Plan IR host-vs-container split (`broker_routes` vs. `/run/oc-config/opencode.json`)** —
      compile external MCP and service credentials into a host-only `broker_routes` section of the
      Plan IR (upstream canonical URL, vault `secret_ref`, enforced wire-level tool/method policy,
      grant expiry/revocation), while staging only pod-local broker endpoints and disposable
      per-job broker tokens into container-visible `/run/oc-config/`.
- [ ] **Host-side MCP / HTTP credential-injecting reverse proxy** — inject upstream `Authorization`
      / API-key headers strictly on the host over verified TLS (never trusting container-supplied
      destination overrides, refusing cross-origin redirects with credentials, stripping sensitive
      headers from responses), and enforce `read_only_tools` vs. `write_tools` at the JSON-RPC
      protocol layer on the wire (not only as an OpenCode client hint).
- [ ] **Host-side Postgres protocol proxy for external databases** — terminate sandbox Postgres
      connections on a pod-local proxy authenticated with a disposable per-job credential while the
      host proxy connects to the real external Postgres over verified TLS using host-held
      credentials (supporting `default_transaction_read_only=on` for read-only grants and blocking
      server-side escape primitives where applicable).
- [ ] **Explicit credential-delivery posture & break-glass policy** — distinguish
      `credential_delivery = "local-ephemeral"` (disposable local sidecars only), `"host-brokered"`
      (default for all external targets), and `"raw-container-mount"` (opt-in break-glass only,
      refused by default, permanently forbidden in `managed` tier, and surfaced as a
      `raw_remote_secret_mounted` trigger in `security_delta`).
- [ ] **Adversarial & live qualification tests** — verify with synthetic marker secrets that an
      unrestricted container shell (`env`, `/run/secrets/*`, `/proc`, outbound `curl`, redirect
      traps, host-header spoofing, and raw JSON-RPC calls) cannot extract any upstream external
      credential or invoke ungranted write tools.
