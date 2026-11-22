# prd_l: Composable sandbox configuration, host providers, communication adapters, and orchestrator config management

[Index](README.md) · related: [Postgres host access](prd_a.md), [per-instance networking](prd_d.md),
[local HTTPS](prd_e.md), [host tools](prd_f.md), [orchestrator](prd_i.md),
[orchestrator UI and profiles](prd_i1.md), [SSH onboarding](prd_i2a.md),
[credential broker](prd_i3.md), [host LLM broker](prd_i4a.md),
[warm worker starts](prd_i5.md), [host config](prd_j.md)

## Goal

Replace hardcoded top-level sandbox flags and imperative Bash special cases (such as `-p` Postgres,
`-D` DinD, and hardcoded Chromium) with a **holistic, host-trusted configuration and compilation
architecture** that cleanly separates:

1. **What runs inside a sandbox** (composable named Sandbox Types, Bundles, Services, MCPs, Skills,
   compiled `mise` toolchains, and standing Personas),
2. **How containers execute** (pluggable Runtime Engines / Host Providers), and
3. **How the controller communicates with the worker** (pluggable Communication Adapters).

At the same time, give the restricted **`oc-sandbox orchestrate` (`-o`)** agent safe, human-gated
configuration-management capabilities via typed MCP tools and curated base Skills — **without**
granting generic host filesystem, shell, Podman, or SSH access.

## Architecture: 3-Axis Compiler Model

```mermaid
flowchart LR
    subgraph SPEC["Host-Trusted Specs (~/.config/oc-sandbox/ + cfg/builtin/)"]
        ST["Sandbox Types (sandbox-type@1)"]
        BN["Nested Bundles (bundle@1: MCPs, Services, Skills, Mise, Role)"]
        SV["Services (service@1: postgres, api, chromium, dind, ...)"]
        HP["Host Providers (host-provider@1) + Comm Adapters (transport@1)"]
    end

    subgraph COMP["Trusted Host Compiler (Pure Python, Inert, Zero Side Effects)"]
        DAG["Capability & [local] DAG Resolver + Conflict/Port Checker"]
        POL["Endpoint Policy Engine + Role Contract Compiler"]
        IR["Immutable Resolved Plan IR (plan.lock.json + plan_digest)"]
        ST --> DAG
        BN --> DAG
        SV --> DAG
        HP --> POL
        DAG --> POL --> IR
    end

    subgraph EXEC["Pluggable Backends (Execute Frozen Plan IR Only)"]
        ENG["Runtime Engine: podman-linux | podman-macos-vm | cloud-render"]
        TR["Comm Adapter: local | ssh-pinned | tailcat | cloud-https"]
        CTL["oc_controller.py Approval & Lease Binding (plan_digest)"]
        IR --> CTL --> ENG --> TR
    end
```

### Axis 1: Workload (Named Sandbox Types, Bundles, Services)

- **Inert `schema_version = 1` TOML by default**, with an optional **host-trusted lazy Python
  `file.py:factory`** (`version = 1`) for complex services, custom sandbox types, or custom host
  providers.
- Discovery, `--help`, `plan`, and validation read **only** declarative TOML; zero Python executes
  until runtime activation. Python factories are loaded exclusively from host-trusted directories
  (`<repo>/cfg/builtin/` or `~/.config/oc-sandbox/`, verified by `trusted_path` + ancestor walk +
  `O_NOFOLLOW` fd-only byte capture + size cap per [prd_i4a](prd_i4a.md), zero TOCTOU).
- **Recursive Capability DAG with `api-agent`-style `[local]` Conditional Acquisition:**
  - Services (`service@1`) declare `provides` (e.g., `cap:db.postgres@17.4`), `requires` (e.g.,
    `cap:db.postgres@^17`), `cardinality` (`singleton` | `named-instance`), `readiness_probe`,
    `endpoints[]`, `volumes[]`, `secret_slots[]`, `resources` (`memory`, `pids_limit`), and
    `security_profile` (`standard` | `elevated-nested` | `desktop-wayland`).
  - A tool or bundle declaring a `[local]` service branch (e.g., `myapp/api` requiring
    `cap:db.postgres@^17`) pulls in the local API and its transitive Postgres **only** when no
    remote `API_ENDPOINT` is supplied.
  - A bundle with **0 MCP tools** can unconditionally declare `requires_services = ["builtin/postgres"]`
    so the sandbox has Postgres running with `PGPASSFILE`/`DATABASE_URL` ready for app development.
  - Cycles, unsatisfied capabilities, incompatible version constraints, duplicate pod ports, and
    silent overwrites fail closed at compile time unless resolved explicitly via
    `[composition] replace = [...]` or named service aliases (e.g., `pg-primary` vs. `pg-analytics`).
- **Built-in Service Modules replace hardcoded flags:** `builtin/postgres` (preserving 100% of
  [prd_a](prd_a.md) SCRAM `hba_file`, `PGPASSFILE` `mode=0600` secret, HMAC-keyed `oc.pgcfg` volume
  signature, and `5432` auth gate), `builtin/dind` (`security_profile = "elevated-nested"`),
  `builtin/chromium-wayland` (local desktop), and `builtin/chromium-managed-cdp` (managed/remote).
  Legacy CLI flags (`-p`, `-D`, etc.) are dropped cleanly in the reworked CLI (single-user clean
  slate; existing volume naming compatibility is preserved where configured).

### Axis 2: Runtime Engine (`host-provider@1`)

- Lowers a frozen Target-Bound Plan IR onto a target runtime:
  - `podman-linux`: rootless Podman, `pasta:--no-map-gw,-T,<port>` (managed), Podman secrets,
    native `--mount type=image` + `:O` overlay, SELinux confinement.
  - `podman-macos-vm`: Podman Machine VM, `host.containers.internal:<port>`, `GatewayPorts` guard
    ([prd_i2a](prd_i2a.md)), `arm64` target binding.
  - `cloud-render`: signed OCI digest deployment, external managed service bindings, mandatory
    `max_ttl` / `idle_timeout` / `spend_cap_usd` lease contract, `supports_sidecars = false`.
- Every Runtime Engine advertises a **Capability Manifest** (`arch`, `os`, `supports_pods`,
  `supports_pasta`, `supports_image_mounts`, `supports_reflink`, `supports_wayland`,
  `supports_dind`, `multi_tenant_loopback`). The compiler fails closed at plan time if a Sandbox
  Type demands an unsupported capability (unless an explicit fallback module is declared).

### Axis 3: Communication Adapter (`transport@1`)

- Exposes four narrow typed primitives:
  1. `exec_bounded(argv, stdin_stream, max_stdout, timeout)` — zero remote shell interpolation.
  2. `open_reverse_channel(local_host_uds) -> remote_endpoint` — bridges host-only
     `oc_llm_broker.py` or Tier-1 caching proxy UDS into the worker.
  3. `transfer_blob(digest, stream, direction)` — bounded, digest-verified transfers for Git
     bundles/artifacts ([prd_i5](prd_i5.md)).
  4. `attach_session(target_id, mode)` — PTY/tmux or browser arbiter stream ([prd_i2](prd_i2.md)).
- Implementations: `local`, `ssh-pinned` ([prd_i2a](prd_i2a.md)), future `tailcat` (reusing 100% of
  the Podman Runtime Engines), and `cloud-https`.

## Structured Role Contracts (Personas, Groupings, Skills, MCPs)

Raw depth-first system-prompt concatenation is **not** used (replacing OpenCode's `agent.prompt`
breaks core tool-calling/compaction behavior, causes persona contradictions across nested bundles,
and busts prompt caching). Instead, nested bundles (`bundle@1`) compile into **idiomatic OpenCode
v2 primitives** staged read-only under `/run/oc-config/`:

| Artifact | Merge Rule | Compiled Target in `/run/oc-config/` |
|---|---|---|
| **Primary Persona** | **Singular (non-merging).** One standing mission, authority posture, and completion rubric per sandbox. Conflicting primary personas fail compile unless `[composition] replace = ["persona"]`. | `agents/<name>.md` (`default_agent` in `opencode.json`) + concise `MISSION.md`. Additional bundle personas register as callable `subagent`s. |
| **Standing Invariants** | Topological post-order deduplicated list, byte-capped (e.g., 16 KiB total), optional symlink-confined `{{slot}}` templates (`api-agent` `[prompt_slots]`). | `instructions/<nn>-<bundle>.md` referenced in `opencode.json` `instructions` array (appends without replacing OpenCode's core prompt). |
| **Services Inventory** | Auto-synthesized fact table from resolved Plan IR (never drifts). | `SERVICES.md` (included in `instructions`). |
| **Skills (0..N)** | Set union (conflict on identical skill ID fails closed). | `skills/<name>/SKILL.md` (progressive disclosure; 0 tokens until invoked). |
| **MCPs (0..N)** | Strict map merge + **Role-Filtered Tool Surface** (persona can narrow allowed tools, e.g., read-only DB queries for a reviewer). | `opencode.json` `mcp` map; secrets strictly via `{file:/run/secrets/<name>}`. |

In `managed` tier, workspace `./opencode.json` and `.opencode/` plugins are locked out so untrusted
repos in `~/opencode-sandbox` cannot override broker routing, MCP permissions, or persona rules.

## Compiled Workload `mise`, Base Images, and Minimal Worker Bootstrap

- **Strict two-domain `mise` split:**
  - Host `mise` (`tools/mise.toml` + `tools/mise.lock`, [prd_f](prd_f.md)) stays strictly on the
    workstation (`MISE_PARANOID=1`, scrubbed inherited `MISE_*`).
  - Workload `mise` comes strictly from constrained data-only `executables.toml` manifests inside
    host-trusted bundles (exact pinned `[tools]` only; max 64 manifests / 64 tools; no `[hooks]`,
    `[env]`, or `[tasks]`; version conflicts fail closed unless overridden in the leaf Sandbox Type).
- **Compile-time lock merging -> Immutable RO OCI Toolchain Image:**
  - `oc-sandbox config lock` merges `executables.toml` pins into a multi-platform `mise.lock`
    (`linux-x64`, `linux-arm64`), verified with `lockcmp.py`, and builds a content-addressed
    read-only OCI Toolchain Image (`localhost/oc-toolchain:<key>`) in a split-phase offline builder.
  - Delivered via Podman `--mount type=image,src=localhost/oc-toolchain:<key>,dst=/opt/oc-tools,ro`
    (0ms startup, zero base-image rebuilds across tool combinations, unpoisonable), with automatic
    `COPY --from=` fallback for engines without image mounts.
- **Base Containerfile & post-install hooks:** Base images are digest-pinned (`@sha256:...`).
  Optional `mise` post-install hooks are allowed **only** from host-trusted profiles/bundles and run
  **strictly inside an offline, networkless, credential-free Phase-2 builder container**
  ([prd_i5](prd_i5.md)), hashed into the image cache key — never on the host.
- **Minimal zero-trust remote worker TCB:** Remote SSH/Tailcat workers do **not** require host
  `mise` — only rootless `podman` (or `podman machine`) and hardened `sshd` (`GatewayPorts no`) /
  `tailcat`. Startup runs read-only `HostProvider.probe()`; `oc-sandbox worker bootstrap <name>`
  provides an explicit, previewed, opt-in bootstrap script (never silent `curl | sh`).

## 2-Tier Zero-Poisoning Application Package Caching

Shared writable package caches across sandboxes are prohibited (cross-sandbox poisoning and private
package disclosure). Self-hosted Artifactory/Nexus is out of scope as a managed component (pointing
at an *existing external* Artifactory URL via config is supported).

1. **Tier 1 (Default, Universal):** A lightweight host/worker **read-through caching and
   auth-injecting HTTP forward proxy** (reachable only over `pasta -T` / internal socket; `GET`-only
   from sandboxes; caches immutable `.tgz`/`.whl`/`.crate`/`.nupkg` blobs from allowlisted upstreams
   verified by client lockfiles; holds private registry credentials strictly on the host side;
   partitioned by job grant scope). Accelerates partial lockfile diffs across all ecosystems.
2. **Tier 2 (Hot-Path Acceleration, coordinated with [prd_i5](prd_i5.md)):** Content-addressed
   immutable materialized dependency layers built offline via Tier 1, mounted locally via Podman
   `:O` overlay or Btrfs reflink and promoted to signed OCI Image Volumes for remote/cloud workers.

## Universal Capability-Scoped Endpoint Policy Engine

Every `service@1` declares its `endpoints[]` (`name`, `port`, `protocol`, `default_exposure`,
`max_exposure`, `requires_auth`, `auth_enforcer`, `tls_policy`, `readiness_probe`,
`host_url_template`). Hardcoded port numbers are removed from core code:

- `default_exposure = "pod-only"` by default; undeclared ports are never published.
- `max_exposure = "pod-only"` (e.g., Chromium DevTools `9222`) is unconditionally refused by CLI
  `--port`, [prd_d](prd_d.md) loopback forwarding, and remote `ssh -L`.
- `requires_auth = true` (e.g., Postgres `5432` with `auth_enforcer = "pg-scram-ro-hba"`) cannot be
  exposed to host loopback, [prd_d](prd_d.md) instance DNS, or remote `ssh -L` unless its auth
  enforcer is attached and its authenticated `readiness_probe` passes.
- `tls_policy = "required-when-ca-ready"` automatically wires [prd_e](prd_e.md)/[prd_e3](prd_e3.md)
  instance leaf certificates when the constrained host CA is active.

## Reworked Clean-Slate CLI Interface

| Command | Purpose |
|---|---|
| `oc-sandbox run [NAME] [--type TYPE] [--host WORKER] [--with MOD]... [--without MOD]... [--port SPEC]... [--worktree REPO[:REF]]` | Compile plan, verify grants/drift, start services and OpenCode sandbox. |
| `oc-sandbox plan [NAME] [...]` | Pure, inert dry-run emitting `plan.lock.json`, `plan_digest`, security elevations, port/auth summary, and drift diff against `applied_plan.json`. |
| `oc-sandbox build [--type TYPE] [--host WORKER]` | Build/verify pinned images, compiled `mise` OCI toolchain layer, and warm seeds without launching OpenCode. |
| `oc-sandbox orchestrate` (alias `oc-sandbox -o`) | Launch restricted host orchestrator with typed Config/Orchestration MCP tools and curated base Skills (no generic host file/shell/Podman/SSH access). |
| `oc-sandbox config {list,show,validate,diff,history,approve,reject,restore,lock}` | Host-operator config inspection, revision approval (`--digest`), rollback, and `mise.lock` compilation. |
| `oc-sandbox worker {list,enroll,probe,bootstrap,reconcile}` | Enroll pinned SSH/Tailcat/cloud workers, probe capabilities, run opt-in previewed bootstrap, reap verified orphans. |
| `oc-sandbox ps` / `attach NAME` / `down NAME [--purge]` / `rollback NAME` | Inspect running sandboxes/services, attach, tear down via ownership labels/receipts, or restore prior `applied_plan.json`. |

## Restricted Orchestrator (`-o`) Config Management & Base Skills

Aligned with [prd_i1](prd_i1.md), the orchestrator runs in a restricted OS sandbox with **zero**
generic host file reads/writes, shell, Podman socket, SSH agent, or raw secret access.

### Typed Host Config MCP Surface (Over Private `0o700` UDS)

- Connected via a helper-owned `0o700` Unix domain socket verifying kernel `SO_PEERCRED` against the
  orchestrator sandbox identity, with strict per-message byte caps (256 KiB), rate limits, and
  closed method allowlist.
- **Read-only MCP tools (opaque registered IDs only — never raw filesystem paths):**
  - `config_list(kind, include_archived=false, cursor, limit)` — lists sandbox types, bundles,
    services, workers, and host providers (returns secret **presence/ref metadata only**, never
    secret values).
  - `config_get(kind, id)` — returns the validated TOML/Markdown document and current revision hash.
  - `config_schema(kind)` — returns `schema_version = 1` schema, built-in capabilities, and valid
    enum values.
  - `plan_preview(spec_or_draft)` — compiles an existing or proposed draft config through the pure
    Plan Compiler and returns `plan_digest`, resolved DAG, security elevations, exposed endpoints,
    and drift classification (zero side effects).
  - `config_diff(kind, id, from_rev, to_rev)` and `config_history(kind, id)`.
- **Human-gated mutation MCP tool (`config_propose_revision`):**
  - Validates the complete proposed TOML/Markdown against `schema_version = 1`, rejects unknown keys
    and raw secrets, rejects host-path escapes, runs the pure Plan Compiler dry-run, computes a
    canonical unified diff + security delta summary (e.g., new elevated profiles, new exposed ports,
    new `mise` pins, new external endpoints), and creates an immutable **pending proposal** bound to
    `base_revision` and `proposal_digest` inside [oc_controller.py](../../oc_controller.py).
  - **Operator-only publish:** Only the human operator (via `oc-sandbox config approve <proposal_id>
    --digest <proposal_digest>` or trusted host dashboard) can apply a proposal. At publish time,
    the host helper re-verifies `proposal_digest`, re-checks `current_revision == base_revision`
    (rejecting stale/replayed approvals), writes atomically (`O_CREAT|O_EXCL` + `fsync` +
    `os.replace`), and appends an immutable revision record.
- **Hard non-writable boundary (permanently refused to orchestrator MCP):**
  - Python `file.py:factory` adapter code, `known_hosts` host-key pins, password-manager
    `managers.toml` and vault credentials, and `oc_controller` policy envelopes. The orchestrator
    may only *reference* already host-registered factory/secret/worker IDs.

### Curated Orchestrator Base Skills (`/run/oc-config/skills/`, mounted `:ro`)

1. **`oc-config-architecture`** — explains the 3-axis model (`Workload` × `Runtime Engine` ×
   `Comm Adapter`), `plan.lock.json` IR, trust boundaries (host-trusted vs. hostile workspace,
   `O_NOFOLLOW` factories, zero raw secrets), and the clean-slate CLI.
2. **`oc-sandbox-authoring`** — step-by-step authoring guide and complete examples:
   - Full-stack app sandbox with `builtin/postgres` and **0 MCP tools** (app dev against local DB).
   - API sandbox using `[local]` conditional acquisition (auto-spins local API + transitive
     Postgres when `API_ENDPOINT` is blank; prunes both when pointed at staging).
   - Security-reviewer standing persona (`default_agent` + role-filtered read-only MCPs +
     progressive-disclosure skills) vs. implementer persona, and `[composition] replace`.
3. **`oc-services-and-ports`** — endpoint exposure classes (`pod-only` / `host-loopback` /
   `instance-dns`), auth verifiers (Postgres SCRAM, `prd_e3` TLS), constrained `executables.toml`
   `mise` locking, and 2-tier zero-poisoning package caching.
4. **`oc-workers-and-providers`** — enrolling and targeting Local Podman, SSH Linux/macOS Podman
   Machine (Keeper SSH agent + pinned `known_hosts`), Tailcat, and Render cloud providers, handling
   capability mismatches, and using `plan_preview` + `config_propose_revision` safely.

## Additional Hardening Invariants (M1–M8)

- **M1 (Host-trusted vs. hostile workspace):** Never parse or load factories, Containerfiles, `mise`
  hooks, or MCP commands from `~/opencode-sandbox`; any future repo `.oc-sandbox.toml` is parsed
  inside `safe_run --network=none` as non-authoritative capability hints only.
- **M2 (Retire shared `oc-home` & `npx -y ...@latest`):** Managed sandboxes use isolated per-job
  homes, read-only OpenCode binary mounts, and digest-pinned RO MCP layers.
- **M3 (Cross-arch determinism):** Logical Plans stay arch-agnostic; multi-arch OCI digests and
  `mise.lock` platform entries bind against `HostProvider.probe().arch` (`x86_64` vs. `arm64`).
- **M4 (Drift detection & rollback):** Persist `applied_plan.json` per instance under `$CONF_DIR`;
  classify relaunch deltas as `hot-safe`, `recreate-stateless`, or `stateful-migration-required`
  (fail closed); support `oc-sandbox rollback NAME`.
- **M5 (Diamond & port conflicts):** Fail closed on incompatible SemVer/pin diamonds or duplicate
  pod ports unless resolved by named service instances or `[composition] replace`.
- **M6 (Universal ownership & cloud leases):** Standardize ownership labels (`oc.sandbox=1`,
  `oc.instance`, `oc.service`, `oc.volume.durable`, `oc.incarnation`), write-before-create receipts
  (`$CONF_DIR/remote-state/`), and mandatory `max_ttl`/`idle_timeout`/`spend_cap_usd` cloud leases.
- **M7 (Intra-pod topology & resource baselines):** Support explicit `pod-shared` vs.
  `isolated-sidecars` topology modes; enforce mandatory `memory`/`pids_limit`/`--cap-drop=ALL`/
  `--security-opt=no-new-privileges` on every service.
- **M8 (Universal Secret Materializer):** Generalize HMAC `pg_sig()` + stdin `podman secret`
  (`mode=0400`) + [prd_i4a](prd_i4a.md) `managers.toml` vault refs to all services and MCPs.

## Gate 1: Pseudocode Walkthrough (PoC Scope)

### 1. Pure Plan Compiler (`compile_plan`)

```text
function compile_plan(store, sandbox_type_id, worker_spec, overrides, applied_plan=None):
    st = store.load_trusted_sandbox_type(sandbox_type_id)       # schema_version == 1; no Python imported
    bundles = resolve_bundle_dag_topological(store, st.bundles, overrides.with_mods, overrides.without_mods)
        # Fails closed on cycle, missing bundle, or unacknowledged [composition] replace collision

    # 1. Resolve service DAG with [local] conditional pruning & capability matching
    active_service_reqs = collect_service_requests(bundles, overrides.env_bindings)
        # If a tool's [local] slot has an external remote endpoint bound, prune its local service branch
    services = resolve_service_dag(store, active_service_reqs)
        # Topological sort (Kahn); rejects cycles, unsatisfied capabilities, incompatible diamonds,
        # and duplicate pod ports across services

    # 2. Validate against target HostProvider Capability Manifest & arch
    caps = worker_spec.capabilities
    for svc in services:
        if not caps.satisfies(svc.required_capabilities):
            if svc.fallback_service and caps.satisfies(svc.fallback_service.required_capabilities):
                svc = substitute_explicit_fallback(svc)
            else:
                raise CapabilityMismatch(f"{svc.id} requires {svc.required_capabilities}; worker lacks them")

    # 3. Compile Endpoint Exposure Policy (zero hardcoded port numbers)
    endpoints = compile_endpoints(services, st.ports, overrides.cli_ports)
        # Rejects any requested exposure exceeding endpoint.max_exposure (e.g., 9222 -> pod-only)
        # Rejects any host/DNS exposure of requires_auth=true without verified auth_enforcer

    # 4. Compile Structured Role Contract (singular persona + instructions + skills + filtered MCPs)
    role = compile_role_contract(bundles, st.default_agent, services)
        # Rejects >1 primary persona without [composition] replace = ["persona"]
        # Generates SERVICES.md from resolved services; enforces byte cap on instructions
        # Validates symlink-confined {{slot}} files; filters MCP tools by persona allowlist
        # Rejects any raw secret literals in MCP env/headers (must be {file:/run/secrets/...})

    # 5. Merge constrained mise executables.toml (data-only [tools], <= 64 manifests / 64 tools)
    mise_tools = merge_executable_pins(bundles, services, st.mise_overrides)
        # Fails closed on version conflict, moving channel ('latest'), or hooks/env/tasks keys

    # 6. Target-bind digests for worker_spec.arch and compute immutable plan_digest
    plan = build_canonical_plan_ir(st, worker_spec, services, endpoints, role, mise_tools)
    plan.drift = classify_drift(applied_plan, plan)             # hot-safe | recreate-stateless | stateful-migration-required
    plan.plan_digest = sha256_canonical_json(plan)
    return plan
```

### 2. Restricted Orchestrator Config MCP Server & Human-Gated Publish

```text
function handle_orchestrator_mcp_request(peer_cred, raw_frame):
    assert_peer_matches_orchestrator_uid_pid(peer_cred)
    assert len(raw_frame) <= 262_144 and rate_limiter.allow(peer_cred)
    req = parse_strict_json_rpc(raw_frame)                      # closed method allowlist only
    if req.method not in ALLOWED_MCP_METHODS:
        return json_rpc_error(-32601, "method_not_allowed")

    if req.method in ("config_list", "config_get", "config_schema", "config_diff", "config_history"):
        validate_opaque_id(req.params)                          # ^[a-z0-9][a-z0-9/_-]{0,63}$; no '..' or '/'
        return execute_read_only_store_query(req.method, req.params)   # strips secret values; metadata only

    if req.method == "plan_preview":
        draft_store = overlay_validated_in_memory_draft(host_store, req.params.draft)
        plan = compile_plan(draft_store, req.params.sandbox_type, req.params.worker, req.params.overrides)
        return redacted_plan_summary(plan)

    if req.method == "config_propose_revision":
        kind, obj_id, proposed_toml, base_rev = validate_proposal_inputs(req.params)
        if kind in FORBIDDEN_ORCHESTRATOR_KINDS:                # factories, known_hosts, managers, policy
            return json_rpc_error(-32003, "host_only_resource_forbidden")
        reject_unknown_keys_raw_secrets_and_path_escapes(proposed_toml)
        # Dry-run compile every affected sandbox type to guarantee validity before queuing approval
        draft_store = host_store.with_in_memory_overlay(kind, obj_id, proposed_toml)
        security_delta = compute_security_delta(host_store, draft_store, kind, obj_id)
        proposal = create_immutable_proposal(kind, obj_id, base_rev, proposed_toml, security_delta)
        controller_req_id = controller.propose_config_change(proposal.digest, proposal.summary)
        return {"proposal_id": proposal.id, "controller_request_id": controller_req_id,
                "proposal_digest": proposal.digest, "security_delta": security_delta, "status": "pending_approval"}

function operator_approve_config_proposal(operator_principal, proposal_id, expected_digest):
    with host_store.write_lock():
        proposal = host_store.load_proposal(proposal_id)
        if not hmac.compare_digest(proposal.digest, expected_digest):
            raise DigestMismatch("Approval digest does not match canonical proposal")
        current_rev = host_store.current_revision(proposal.kind, proposal.obj_id)
        if current_rev != proposal.base_revision:
            raise StaleProposal("Target config changed since proposal; re-propose against latest revision")
        controller.approve_and_consume_once(operator_principal, proposal.controller_request_id, expected_digest)
        # Atomic host-trusted write (O_CREAT|O_EXCL temp + 0o600 + fsync + os.replace) + immutable journal entry
        new_rev = host_store.publish_atomic(proposal.kind, proposal.obj_id, proposal.proposed_toml)
        return new_rev
```

## PoC Scope (Spike Branch `spike-outside-in-poc`)

Per [AGENTS.md](../../AGENTS.md#branches), the spike PoC lives cleanly under
`docs/prds/spikes/l/` (leaving `oc-sandbox`, `oc-bridge.py`, and production tests untouched until a
dedicated feature PR branches from `main`):

- [ ] **Pure-Python Plan Compiler & Schema (`docs/prds/spikes/l/oc_plan.py`)** — `schema_version = 1`
      TOML loader (trusted-path + unknown-key + raw-secret rejection), recursive capability &
      `[local]` service DAG resolver, diamond/cycle/port-collision checks, HostProvider Capability
      Manifest matching, Universal Endpoint Policy Engine, Structured Role Contract -> OpenCode v2
      config/instructions/skills/MCP emitter, constrained `executables.toml` merger, `applied_plan`
      drift classifier, and deterministic `plan_digest`.
- [ ] **Built-in Reference Catalog (`docs/prds/spikes/l/builtin/`)** — `service/postgres` (full
      SCRAM + `PGPASSFILE` + `5432` policy), `service/api-demo` (requiring `cap:db.postgres@^17`
      with `[local]` conditional pruning), `service/chromium-wayland`, `service/chromium-managed`,
      `service/dind`, `host-provider/{podman-linux,podman-macos-vm,cloud-render}`,
      `transport/{local,ssh-pinned,tailcat,cloud-https}`, and example `sandbox-type` / `bundle`
      definitions (including 0-MCP Postgres app-dev and read-only security-reviewer persona).
- [ ] **Restricted Orchestrator Config MCP Server + Curated Base Skills (`docs/prds/spikes/l/oc_config_mcp.py`, `docs/prds/spikes/l/orchestrator_skills/`)** —
      typed JSON-RPC MCP server over private `0o700` UDS (with `SO_PEERCRED`, byte/rate caps,
      opaque IDs, forbidden-kind rejection, `plan_preview`, `config_propose_revision`, and
      operator-only stale-safe `approve`/`rollback`), plus the 4 curated orchestrator base Skills.
- [ ] **Reworked CLI PoC (`docs/prds/spikes/l/oc_sandbox_cli.py`)** — implements `plan`, `config`,
      and `worker` subcommands against the compiler & store.
- [ ] **Comprehensive Offline Adversarial & Unit Test Suite (`docs/prds/spikes/l/test_poc.py`)** —
      verifies DAG cycles, diamond conflicts, `[local]` pruning, 0-MCP Postgres wiring, endpoint
      exposure denial (`9222`, unauthenticated `5432`), persona conflict & `[composition] replace`,
      MCP role filtering, raw-secret rejection, `executables.toml` hook/latest rejection, drift
      classification, orchestrator MCP path-traversal/forbidden-kind/stale-approval/digest-mismatch
      rejection, and `SO_PEERCRED`/byte-cap enforcement.

## Review record

- Gate 1 design review (`Security-Focused PR Reviewer Setup`): pending.
- Gate 2 PoC implementation review (`Security-Focused PR Reviewer Setup`): pending.

- [ ] **Human review**: checked only when the user says so
