# prd_m2: Cross-model, cross-sandbox orchestration and unambiguous addressing

Parent: [prd_m](prd_m.md) · related: [orchestrator](prd_i1.md), [worker fleet](prd_i2.md),
[credential broker](prd_i3.md), [model telemetry](prd_m1.md), [control plane](prd_m3.md)

## Problem statement

Real engineering workflows frequently require an **"orchestrator of orchestrators"** topology:

- A root orchestrator (running on one model family) launches parallel feature lanes across local
  Podman pods and remote SSH/Tailcat Podman workers — for example, multiple implementors (e.g.,
  Codex) each paired with an independent adversarial security reviewer (e.g., Claude) on a
  different model family.
- Individual leaf sandboxes also benefit from lightweight **intra-sandbox subagents** (e.g., code
  explorer, test runner) without spinning up a full extra pod.
- Cross-harness collaboration sometimes requires messaging an **external top-level peer stream**
  (such as a standalone Antigravity, Codex, or Claude reviewer session running outside `oc-sandbox`).
- Every target must be addressed unambiguously — `"NAME"` if local, `"REMOTE / NAME"` if remote —
  without slash collisions, spoofing, or lateral prompt-injection worming across unrelated
  sandboxes.

## Design specification

### 1. Canonical addressing grammar and bijection invariants (`oc_address.py`)

Every addressable endpoint in `oc-sandbox` belongs to one of three mutually disjoint classes,
dispatched bijectively on byte 0 and the exact `" / "` separator:

```ebnf
TargetAddr   ::= LocalSandbox | RemoteSandbox | ExternalPeer
LocalSandbox ::= Name                           (* worker_ref == "local" *)
RemoteSandbox::= Remote " / " Name              (* exact ASCII 0x20 0x2F 0x20 *)
ExternalPeer ::= "@" PeerName                   (* host-enrolled non-sandbox stream *)

Name         ::= [a-z0-9] ([a-z0-9-]{0,22} [a-z0-9])?   (* matches oc-sandbox valid_instance, 1..24 chars *)
Remote       ::= [a-z0-9] ([a-z0-9-]{0,30} [a-z0-9])?   (* RFC-1123 label, 1..32 chars; excludes {"local", "peer"} *)
PeerName     ::= [a-z0-9] ([a-z0-9-]{0,22} [a-z0-9])?   (* 1..24 chars *)
ThreadId     ::= [a-z0-9] ([a-z0-9-]{0,30} [a-z0-9])?   (* separate typed wire field; default "main" *)
```

**Non-negotiable addressing invariants:**
1. **No slashes, dots, underscores, uppercase, whitespace, or control/bidi chars:** Forbids `/`,
   `.`, `_`, `#`, `@`, `:`, `\`, whitespace, ASCII controls (`0x00..0x1F`, `0x7F..0x9F`), and
   Unicode bidi overrides (`U+202A..U+202E`, `U+2066..U+2069`) in `Name`, `Remote`, `PeerName`, and
   `ThreadId`. Preserves 1:1 compatibility with Podman container names and `prd_d`/`prd_e`
   `<NAME>.oc.local` DNS/TLS labels.
2. **Reserved worker names (`{"local", "peer"}`):** Neither `"local"` nor `"peer"` can be enrolled
   as a remote worker name. `"local / foo"`, `"remote/foo"`, and `"remote  /  foo"` are **rejected**
   on wire/MCP APIs (`SchemaError`).
3. **Separate typed `thread_id` on wire APIs:** All MCP/RPC payloads pass
   `{ "target": "NAME" | "REMOTE / NAME" | "@PEER", "thread_id": "main" }`. Optional `#thread`
   syntax is accepted **solely** as UI/CLI composer shorthand lowered before wire submission.
4. **Incarnation binding:** Internally, `oc_hub` binds every live address to
   `(worker_ref, instance, incarnation_id)`. Recreating sandbox `"feat-a"` rotates `incarnation_id`,
   invalidating stale edges and in-flight replies from the previous incarnation.
5. **Migration of existing `prd_l` worker IDs:** `oc_schema.py` currently validates `worker@1` IDs
   with `OPAQUE_ID_RE` (which allows `/`, e.g. `builtin/local-workstation`). PRD M migrates
   `worker.id` to slash-free `WORKER_NAME_RE` (`"local"` for the local workstation).

### 2. Three-tier topology: intra-sandbox subagents vs. inter-sandbox peers vs. `@PEER`

| Tier | Scope & Isolation | Runtime Mechanism | Appropriate Use |
|---|---|---|---|
| **1. Intra-Sandbox Subagents** | Single sandbox (`"NAME"` or `"REMOTE / NAME"`): shares container UID, `/sandbox` worktree, and `ocjob_...` lease. | Native OpenCode `task` tool compiled into `/run/oc-config/opencode.json` (`agent.<subagent>` with explicit `model:` + `variant:`, [prd_m1](prd_m1.md)); can call a *different* model family if both models are in `lease.allowed_models`. | Fast read-only codebase exploration, test runs, and context compaction with zero IPC overhead. **Never** use for adversarial security review or concurrent writers. |
| **2. Inter-Sandbox Peers & Sub-Orchestrators** | Disjoint Podman pods across `local` and `REMOTE` workers, distinct worktrees, distinct model families, distinct `oc_controller` leases. | Host `oc_hub` over per-job reverse channel (`127.0.0.1:<http_port>/mcp/oc-swarm` on `oc_broker_http.py`); each sandbox runs `opencode serve` (authenticated pod-local server) + `tmux` (`opencode attach`). | **Orchestrator of orchestrators** (`depth 0 -> 1 -> 2`), parallel feature shards, and **Cross-Model Adversarial Pairing** (e.g., Codex `"feat-a-impl"` <-> Claude `"mac-studio / feat-a-rev"` with RO reviewer creds). |
| **3. External Top-Level Peer Streams (`@PEER`)** | Standalone non-sandbox host/IDE harness (e.g., `@antigravity`, `@codex-rev`). | Enrolled via `oc-sandbox peer create <peer> [--allow-target <addr>]` -> dedicated host UDS (`$XDG_RUNTIME_DIR/oc-sandbox/peers/<peer>.sock`, `0o600`, `SO_PEERCRED` UID check) + revocable 256-bit `ocpeer_...` token (`Principal(Role.EXTERNAL_PEER, peer)`). | Cross-model adversarial review or advisory streams outside `oc-sandbox`, with zero Podman/filesystem authority. |

### 3. Container `opencode serve` + `tmux` runtime and `isolated-sidecars` binding

To allow both structured messaging (`oc_hub` / Thread UI) and live TUI attach without fragile ANSI
scraping:
- Upgrade `oc-opencode-run.py` to launch a supervised `opencode serve --hostname 127.0.0.1 --port 4096`
  protected by a per-instance 256-bit `OPENCODE_SERVER_PASSWORD` (`/run/secrets/oc_server_pw`,
  `0400`), alongside a pod-local `tmux` server with window `0` running
  `opencode attach http://127.0.0.1:4096` and window `1` running the login shell.
- **Host-to-sandbox control binding:**
  - `interactive` (`pod-shared`): `127.0.0.1:4096` (`max_exposure = "pod-only"`, password blocks
    pod-mate SSRF from Chromium); remote SSH workers add `-L <local_uds>:127.0.0.1:4096` on the
    existing `ControlMaster` (`GatewayPorts no`).
  - `managed` (`isolated-sidecars`, [prd_l1](prd_l1.md)): under `--network=none` + UDS, a
    container-side UDS shim exposes `4096` at `$XDG_RUNTIME_DIR/oc-sandbox/jobs/<id>/opencode.sock`
    (SELinux-labeled via `oc_broker.cil`, bridged over `ssh -L` on remotes); under `pasta` +
    egress-drop `nftables`, `pasta -t <host_ephem>:4096` exposes inbound host loopback only.
- **Untrusted `opencode serve` security note:** Because the sandbox LLM shares the container UID,
  `OPENCODE_SERVER_PASSWORD` protects *pod/VM neighbors*, NOT the host against the sandbox itself.
  Therefore `oc_daemon` NEVER trusts `opencode serve`'s self-reported message roles or provenance
  metadata (see [prd_m3](prd_m3.md) host write-ahead attribution).

### 4. Capability-scoped `oc_hub` message bus and security invariants

Mirrors T3Code's **SQLite Command -> Event -> Projection + Outbox** pattern inside trusted host
`oc_daemon` (`registry.sqlite`, `0o600` WAL), combined with A2A-style task states
(`submitted -> working -> input-required -> completed | failed | canceled`) and strict capability
routing:

1. **Default-Deny `RoutingEdge` Table (Blocks Lateral Prompt Injection):**
   - Leaf sandboxes have **zero** ambient ability to enumerate or message other sandboxes.
   - Spawning child $C$ from orchestrator $P$ creates directed edges $P \leftrightarrow C$ only.
   - Peer edges (e.g., `peer_pair("feat-a-impl", "mac-studio / feat-a-rev", kinds=["review_request", "review_findings", "question", "answer"], max_rounds=6)`) must be explicitly declared in the launch topology or granted live by the operator in Trusted Chrome.
   - Sub-orchestrators (`depth >= 1`) operate strictly inside a parent-delegated `SubtreeBudget`
     (`max_depth <= 2`, `max_children <= 8`, allowed workers, allowed sandbox types, quota ceiling).
2. **Unforgeable Envelope & Nonce-Framed `UNTRUSTED_PEER_DATA`:**
   ```json
   {
     "msg_id": "msg_01J...",
     "seq": 412,
     "src": { "kind": "operator | orchestrator | sandbox | external_peer", "addr": "mac-studio / feat-a-rev", "incarnation": "inc_9f2a" },
     "dst": { "addr": "feat-a-impl", "thread_id": "main", "incarnation": "inc_3b10" },
     "trust_class": "OPERATOR_DIRECTIVE | PARENT_TASK | UNTRUSTED_PEER_DATA | SYSTEM_ALERT",
     "msg_kind": "prompt | review_request | review_findings | question | answer | status_report | cancel",
     "in_reply_to": "msg_01H...",
     "hop_depth": 2,
     "body_text": "...",
     "artifact_refs": [{ "blob_sha256": "...", "size": 14200, "media_type": "text/x-patch" }],
     "created_at": 1795370160
   }
   ```
   - `src`, `trust_class`, and `hop_depth` are stamped **exclusively by `oc_hub`** from kernel/token
     identity (`SO_PEERCRED` / `ocjob_...` / `ocpeer_...`); any client-supplied sender field is
     rejected (`InvalidRequest`).
   - Only `OPERATOR_DIRECTIVE` enters as a privileged operator turn. Any `UNTRUSTED_PEER_DATA`
     (including `@PEER` and child-to-parent replies) is wrapped in a per-message random-nonce
     data envelope (`<oc-peer-message nonce="<128-bit-hex>" from="..." trust="untrusted-peer">...</oc-peer-message>`, neutralizing any colliding closing tag inside `body_text`).
3. **Bounded Depth, Anti-Ping-Pong, Deadlock Freedom, and Backpressure:**
   - Hard caps: `max_depth = 2` (Root `0` -> Sub-Orch `1` -> Leaf `2`), `max_hop_count = 16` per
     reply chain, `max_inline_bytes = 64 KiB`.
   - **Safe Artifact / Patch Handoff (`safe_run`):** Larger diffs/patches transfer via containerized
     `safe_run` `git format-patch` / unified diff (`<= 4 MiB`, `O_NOFOLLOW`, SHA-256 verified,
     never running host `git` inside `~/opencode-sandbox` per `AGENTS.md`) staged read-only into
     `/sandbox/.inbox/<msg_id>.patch` on the recipient.
   - **Deadlock freedom:** All sends are asynchronous mailbox appends; `agent_wait(targets, since_seq,
     timeout_s)` maintains an in-memory `WaitForGraph` and immediately rejects any wait closing a
     cycle (`DeadlockCycleRejected`).
   - **Priority backpressure:** Reserved **Control Priority Queue** (`OPERATOR_DIRECTIVE`, `cancel`,
     `revoke`) is never starved by per-edge bounded mailboxes (`32` msgs / `1 MiB` per `edge_id`,
     returning `429 BackpressureRetryAfter`).
4. **Mid-Thread Cross-Model Handoff (Mirrored from T3Code):**
   - When a model bucket exhausts its `5h` window or an operator requests a model-family handoff
     (e.g., Claude -> Codex), `oc_hub` pauses the active thread, captures a containerized `safe_run`
     diff checkpoint + compacted turn summary, and resumes on the new provider/model route under
     an explicit `model_handoff` audit event.
5. **Tamper-Evident Audit Log:** Every `Envelope` appends `(seq, prev_hash, entry_digest, edge_id,
   actor, target, body_sha256, decision)` to a hash-chained SQLite WAL table.

## Gate 1 pseudocode walkthrough

```text
function handle_bus_send(caller_principal, req):
    target_addr = parse_canonical_addr(req.target)       # rejects '/', 'local / x', control/bidi chars
    thread_id   = validate_thread_id(req.thread_id or "main")
    if len(req.body_text.encode("utf-8")) > 65536:
        return error(413, "inline_body_too_large_use_artifact")

    # 1. Verify capability edge (default-deny lateral movement)
    edge = routing_table.find_active_edge(caller_principal, target_addr, thread_id, req.msg_kind)
    if edge is None or not controller.check_lease_active(edge.lease_id):
        audit_log.append_denied(caller_principal, target_addr, "no_capability_edge")
        return error(403, "target_not_authorized")

    # 2. Enforce hop bound and per-edge backpressure (never starving operator Control Queue)
    hop_depth = compute_chain_hop_depth(req.in_reply_to) + 1
    if hop_depth > MAX_HOP_COUNT:
        return error(409, "max_hop_count_exceeded")
    if not edge.rate_limiter.allow() or mailbox.edge_queued(edge.edge_id) >= EDGE_MAX_MSGS:
        return error(429, "backpressure_retry_after")

    # 3. Host stamps unforgeable provenance & records write-ahead receipt in registry.sqlite
    trust_class = derive_trust_class(caller_principal)   # OPERATOR -> OPERATOR_DIRECTIVE; JOB/PEER -> UNTRUSTED_PEER_DATA
    env = Envelope(msg_id=new_id(), src=caller_principal.canonical_src(),
                   dst=(target_addr, thread_id, resolve_incarnation(target_addr)),
                   trust_class=trust_class, msg_kind=req.msg_kind, hop_depth=hop_depth,
                   body_text=req.body_text, artifact_refs=verify_staged_blobs(req.artifact_refs))
    with registry_db.transaction():
        seq = event_log.append(env)
        dispatch_receipts.insert(env.msg_id, env.dst, sha256(env.body_text), caller_principal)
        outbox.enqueue_delivery(seq, env.msg_id)
    wake_waiters(target_addr, seq)
    return { "msg_id": env.msg_id, "seq": seq }
```

### Failure, recovery, and verification tests

- **Failure / recovery:**
  - Outbox worker retries transient delivery failures (e.g., remote SSH reconnect) idempotently using
    `msg_id` deduplication; if target `incarnation_id` changed, fails closed (`incarnation_mismatch`)
    instead of delivering stale instructions to a newly recreated sandbox.
  - Revoking a sandbox or `@PEER` in `oc_controller` removes all incident `RoutingEdge`s and wakes
    blocked `agent_wait` callers with `edge_revoked` in `<1s`.
- **Verification tests:**
  1. Fuzz/property tests on `parse_canonical_addr` / `format_canonical_addr` proving bijection,
     rejection of `/`, `local / foo`, `peer / foo`, `..`, bidi overrides, and non-canonical spacing.
  2. Adversarial lateral-movement tests proving a leaf sandbox cannot enumerate or message sibling
     sandboxes without an explicit `RoutingEdge`, and cannot spoof `src` or break out of the
     random-nonce `<oc-peer-message>` delimiter.
  3. Cycle-detection test proving mutually waiting peers ($A \to B \to A$) trigger immediate
     `DeadlockCycleRejected`; backpressure test proving a flooded peer edge never blocks
     `OPERATOR_DIRECTIVE` or `cancel`.
  4. Cross-model integration test pairing a Codex implementor sandbox with a Claude adversarial
     reviewer sandbox (and an `@PEER` stream) exchanging `safe_run` patch artifacts across mock
     local + remote SSH workers.

## Concrete gaps and checkboxes

- [ ] **Gap M2.1 — Slash-free `worker.id` migration (`oc_schema.py`, `oc_address.py`):** migrate
      `worker@1` IDs from `OPAQUE_ID_RE` (`builtin/local-workstation`) to `WORKER_NAME_RE`
      (`"local"` & `"peer"` reserved) and share `oc_address.py` across CLI, planner, daemon, and UI.
- [ ] **Gap M2.2 — `opencode serve` + `tmux` entrypoint (`oc-opencode-run.py`):** supervise
      pod-local authenticated `opencode serve` + `tmux` (`opencode attach` + shell), with
      `isolated-sidecars` UDS shim (`oc_broker.cil`) and SSH `ControlMaster` `-L` UDS forwarding.
- [ ] **Gap M2.3 — Capability-scoped `oc_hub` & MCP tools (`oc_hub.py`):** implement SQLite
      Command/Event/Projection + Outbox, `RoutingEdge` ACLs, `SubtreeBudget`, nonce-framed
      `UNTRUSTED_PEER_DATA`, `WaitForGraph` cycle check, `safe_run` patch staging, `@PEER`
      enrollment, and mid-thread cross-model handoff.
