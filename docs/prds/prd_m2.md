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
2. **Reserved names aligned with `oc-sandbox`:**
   - `Name` enforces `oc-sandbox`'s `RESERVED_NAMES` (`{"agent", "chromium", "chrome", "postgres",
     "pg", "dind", "home"}`) while explicitly permitting `"default"` for the default local instance.
   - `Remote` permanently reserves `{"local", "peer"}` — neither can be enrolled as a remote worker
     name. `"local / foo"`, `"peer / foo"`, `"remote/foo"`, and `"remote  /  foo"` are **rejected**
     on wire/MCP APIs (`SchemaError`).
3. **Separate typed `thread_id` on wire APIs:** All MCP/RPC payloads pass
   `{ "target": "NAME" | "REMOTE / NAME" | "@PEER", "thread_id": "main" }`. Optional `#thread`
   syntax is accepted **solely** as UI/CLI composer shorthand lowered before wire submission.
4. **Incarnation binding:** Internally, `oc_hub` binds every live address to
   `(worker_ref, instance, incarnation_id)`. Recreating sandbox `"feat-a"` rotates `incarnation_id`,
   invalidating stale edges and in-flight replies from the previous incarnation.
5. **Tracking `worker@1` ID migration ([prd_m](prd_m.md) open decision):** `oc_schema.py` currently
   validates `worker@1` IDs with `OPAQUE_ID_RE` (which allows `/`, e.g.,
   `builtin/local-workstation`) and enforces built-in immutability via
   `is_builtin_id(obj_id) -> obj_id.startswith("builtin/")`. Under the recommended slash-free
   `WORKER_NAME_RE` migration (`"local"` for the local workstation), `is_builtin_id()` / store
   immutability MUST be updated to protect built-in origin records (including `"local"`) explicitly
   so orchestrator proposals can never mutate or archive `"local"`.

### 2. Three-tier topology: intra-sandbox subagents vs. inter-sandbox peers vs. `@PEER`

| Tier | Scope & Isolation | Runtime Mechanism | Appropriate Use |
|---|---|---|---|
| **1. Intra-Sandbox Subagents** | Single sandbox (`"NAME"` or `"REMOTE / NAME"`): shares container UID, `/sandbox` worktree, and `ocjob_...` lease. | Native OpenCode `task` tool compiled into `/run/oc-config/opencode.json` (`agent.<subagent>` with explicit `model:` + `variant:`, [prd_m1](prd_m1.md)); can call a *different* model family if both models are in `lease.allowed_models`. | Fast read-only codebase exploration, test runs, and context compaction with zero IPC overhead. **Never** use for adversarial security review or concurrent writers. |
| **2. Inter-Sandbox Peers & Sub-Orchestrators** | Disjoint Podman pods across `local` and `REMOTE` workers, distinct worktrees, distinct model families, distinct `oc_controller` leases. | Host `oc_hub` over per-job reverse channel (`127.0.0.1:<http_port>/mcp/oc-swarm` on `oc_broker_http.py`); each sandbox runs `opencode serve` (per-job UDS/ephemeral control channel) + `tmux` (`opencode attach`). | **Orchestrator of orchestrators** (`depth 0 -> 1 -> 2`), parallel feature shards, and **Cross-Model Adversarial Pairing** (e.g., Codex `"feat-a-impl"` <-> Claude `"mac-studio / feat-a-rev"` with RO reviewer creds). |
| **3. External Top-Level Peer Streams (`@PEER`)** | Standalone non-sandbox host/IDE harness (e.g., `@antigravity`, `@codex-rev`). | Enrolled via `oc-sandbox peer create <peer> [--allow-target <addr>]` -> dedicated host UDS (`$XDG_RUNTIME_DIR/oc-sandbox/peers/<peer>.sock`, `0o600`, `SO_PEERCRED` UID check) + revocable 256-bit `ocpeer_...` token (`Principal(Role.EXTERNAL_PEER, peer)`). | Cross-model adversarial review or advisory streams outside `oc-sandbox`, with zero Podman/filesystem authority. |

### 3. Container `opencode serve` + `tmux` runtime and hardened host client

To allow both structured messaging (`oc_hub` / Thread UI) and live TUI attach without fragile ANSI
scraping or port collisions across parallel sandboxes:
- Upgrade `oc-opencode-run.py` to launch a supervised `opencode serve` protected by a per-instance
  256-bit `OPENCODE_SERVER_PASSWORD` mounted **exclusively** into the agent container
  (`/run/secrets/oc_server_pw`, `0400`; **never** mounted into Chromium, `dind`, or Postgres
  sidecars), alongside a pod-local `tmux` server (`tmux -f /dev/null`) with window `0` running
  `opencode attach` and window `1` running the login shell.
- **Collision-free per-job control transport (no fixed host port `4096`):**
  - **Local `managed` (`isolated-sidecars`, `--network=none` + UDS):** A container-side UDS shim
    exposes the agent's `opencode serve` on a per-job `0o600` UDS
    (`$XDG_RUNTIME_DIR/oc-sandbox/jobs/<job_id>/opencode.sock`, SELinux-labeled via `oc_broker.cil`).
  - **Local `interactive` (`pod-shared`) / `pasta`:** Expose per-job `0o600` UDS (preferred) or a
    per-instance host ephemeral loopback port (`127.0.0.1:<ephem>`) forwarded exclusively to the
    agent container's loopback (`pasta -t <host_ephem>:4096`) — never publishing a fixed host port
    that collides across parallel sandboxes (`prd_d`) and never exposing to LAN.
  - **Remote SSH workers:** Forward over the existing pinned-hostkey `ControlMaster` via
    `ssh -L <local_job_uds>:<remote_job_uds>` (`GatewayPorts no`, zero remote TCP listeners).
- **Hardened host `oc_daemon` HTTP/SSE client (treats `opencode serve` as hostile):**
  - Because the sandbox LLM shares the container UID and can replace or tamper with `opencode serve`,
    `oc_daemon`'s client talking to any sandbox MUST enforce `follow_redirects=False` (preventing
    host SSRF via `302 Location: http://127.0.0.1:...`), `Accept-Encoding: identity` (blocking gzip
    bombs), strict HTTP/1.1 framing, bounded response headers (`<= 16 KiB`), bounded SSE event size
    (`<= 256 KiB`), and per-sandbox SSE event rate limits.
  - `oc_daemon` NEVER trusts `opencode serve`'s self-reported message roles or provenance metadata
    (see [prd_m3](prd_m3.md) full-key write-ahead attribution).

### 4. Capability-scoped `oc_hub` message bus and security invariants

Mirrors T3Code's **SQLite Command -> Event -> Projection + Outbox** pattern inside trusted host
`oc_daemon` (`$STATE/registry.sqlite`, `0o600` WAL), combined with A2A-style task states
(`submitted -> working -> input-required -> completed | failed | canceled`) and strict capability
routing:

1. **Default-Deny `RoutingEdge` Table & Monotonic `SubtreeBudget` Attenuation:**
   - Leaf sandboxes have **zero** ambient ability to enumerate or message other sandboxes.
   - Spawning child $C$ from orchestrator $P$ requires a **nonblank task brief** ([prd_i1](prd_i1.md))
     and creates directed edges $P \leftrightarrow C$ only.
   - Peer edges (e.g., `peer_pair("feat-a-impl", "mac-studio / feat-a-rev", kinds=["review_request",
     "review_findings", "question", "answer"], max_rounds=6)`) must be explicitly declared in the
     launch topology or granted live by the operator in Trusted Chrome.
   - **Monotonic privilege attenuation (`child_caps ⊆ parent_budget ⊆ operator_approved_envelope`):**
     `SubtreeBudget` explicitly bounds `max_depth <= 2` (Root `0` -> Sub-Orch `1` -> Leaf `2`),
     `max_children_per_parent <= 8`, a **global root-level `max_total_sandboxes` cap** (default
     `16`, preventing `8×8` fan-out explosions), `allowed_workers`, `allowed_sandbox_types`,
     `allowed_models`, `allowed_variants`, `allowed_broker_routes`, `max_security_profile`, and
     `quota_ceiling`. Sub-orchestrators (`depth >= 1`) are **forbidden** from granting
     `remote_write_grants`, `raw_remote_mounts`, `elevated-nested`, or cross-tier/cross-credential
     `RoutingEdge`s without explicit `oc_controller` operator approval.
2. **Unforgeable Envelope, Strict 4-Role `trust_class`, and Nonce-Framed `UNTRUSTED_PEER_DATA`:**
   ```json
   {
     "msg_id": "msg_01J...",
     "seq": 412,
     "src": { "kind": "operator | orchestrator | sandbox | external_peer", "addr": "mac-studio / feat-a-rev", "incarnation": "inc_9f2a" },
     "dst": { "addr": "feat-a-impl", "thread_id": "main", "incarnation": "inc_3b10" },
     "trust_class": "OPERATOR_DIRECTIVE | PARENT_TASK | UNTRUSTED_PEER_DATA | SYSTEM_ALERT",
     "msg_kind": "prompt | review_request | review_findings | question | answer | status_report | cancel",
     "in_reply_to": "msg_01H...",
     "edge_turn_seq": 3,
     "body_text": "...",
     "artifact_refs": [{ "blob_sha256": "...", "size": 14200, "media_type": "text/x-patch" }],
     "created_at": 1795370160
   }
   ```
   - `src`, `trust_class`, and `edge_turn_seq` are stamped **exclusively by `oc_hub`** from
     kernel/token identity (`SO_PEERCRED` / `ocjob_...` / `ocpeer_...`); any client-supplied sender
     field is rejected (`InvalidRequest`), and all metadata strings (`from`, `msg_kind`) are
     strictly validated to contain zero control or bidi characters.
   - **Closed 4-role `trust_class` mapping:**
     - `Role.OPERATOR` (human in Trusted Chrome / `operator.sock`) -> `OPERATOR_DIRECTIVE`
     - `Role.ORCHESTRATOR` (`-o`, LLM reading untrusted worker output) -> `PARENT_TASK` (**never**
       `OPERATOR_DIRECTIVE`; zero approval authority)
     - `Role.JOB` (leaf sandbox or sub-orchestrator child) -> `UNTRUSTED_PEER_DATA`
     - `Role.EXTERNAL_PEER` (`@PEER`) -> `UNTRUSTED_PEER_DATA`
   - Any `UNTRUSTED_PEER_DATA` is delivered inside a **128-bit random-nonce envelope bound into
     both opening and closing tags** (`<oc-peer-message nonce="<hex>" from="..." kind="..."
     trust="untrusted-peer">...</oc-peer-message nonce="<hex>">`), verifying the nonce does not
     appear in `body_text` and escaping any literal `</oc-peer-message` substring prior to delivery.
3. **Anti-Ping-Pong Per-Edge Turn Caps, Verified `in_reply_to`, Deadlock Freedom, and Backpressure:**
   - **Durable monotonic per-edge turn budget (cannot be bypassed by omitting `in_reply_to`):**
     Every `RoutingEdge` persists `turns_used` against `edge.max_rounds` (default `16`) in
     `$STATE/registry.sqlite`. Every admitted non-operator send consumes a turn, regardless of
     `in_reply_to` or its eventual delivery outcome. Only an explicit operator action can reset
     the budget. Admission checks the live edge, its grant generation, and both incarnations,
     consumes the available turn conditionally, and writes the outbox row in one transaction.
   - **Fenced delivery:** Each row pins the edge, lease, grant generation, sender and recipient
     incarnations, and thread. The host controller orders enqueue, dispatch handoff, and revocation
     through the same per-grant fence. Dispatch revalidates all pins immediately before its
     bounded, nonblocking first write to the trusted transport. A buffered adapter must enforce
     the fence at its actual send boundary. Revocation that wins this ordering invalidates queued
     deliveries, including same-incarnation rows and rows recovered after restart. If handoff
     wins, bytes already sent can take effect. Revocation stops further dispatch and closes the
     active stream. The controller holds no network wait under the fence.
   - **Strict `in_reply_to` binding:** If `in_reply_to` is provided, `oc_hub` verifies that the
     referenced envelope exists, was delivered to `caller_principal` on the same `(edge, thread_id)`,
     and returns an opaque error otherwise (preventing cross-sandbox `msg_id` probing).
   - **Host-Owned Read-Only Artifact / Patch Spool (zero host writes into `~/opencode-sandbox`):**
     Inline bodies cap at `64 KiB`. Larger diffs/patches are produced via containerized `safe_run`
     `git format-patch` / unified diff (`<= 4 MiB`, bounded file count, `O_NOFOLLOW`, SHA-256
     verified, no auto-apply per [prd_i2](prd_i2.md)) and stored strictly in a host-owned `0o700`
     spool under `$STATE/inbox-spool/<job_id>/` outside `~/opencode-sandbox`, exposed to the
     recipient **either** as a `:ro` bind mount at `/run/oc-inbox/<msg_id>.patch` or via an
     authenticated `/mcp/oc-swarm` `artifact_read(blob_sha256)` tool.
   - **Deadlock freedom:** All sends are asynchronous mailbox appends; `agent_wait(targets, since_seq,
     timeout_s)` maintains an in-memory `WaitForGraph` and immediately rejects any wait closing a
     cycle (`DeadlockCycleRejected`).
   - **Priority backpressure:** Reserved **Control Priority Queue** (`OPERATOR_DIRECTIVE`, `cancel`,
     `revoke`) is never starved by per-edge bounded mailboxes (`32` msgs / `1 MiB` per `edge_id`,
     returning `429 BackpressureRetryAfter`).
4. **Mid-Thread Cross-Model Handoff (Mirrored from T3Code, Quota-Gated):**
   - When a model bucket exhausts its `5h` window or an operator requests a model-family handoff
     (e.g., Claude -> Codex), `oc_hub` pauses the active thread, **re-runs `admit_lane` on the target
     model/route and enforces the `PaidFallbackGrant` boundary** ([prd_m1](prd_m1.md), zero silent
     billing escalation), captures a containerized `safe_run` diff checkpoint + compacted turn
     summary, and resumes on the new provider/model route under an explicit `model_handoff` audit
     event.
5. **Tamper-Evident Audit Log:** Every `Envelope` appends `(seq, prev_hash, entry_digest, edge_id,
   actor, target, body_sha256, decision)` to a hash-chained SQLite WAL table in
   `$STATE/registry.sqlite`.

## Gate 1 pseudocode walkthrough

```text
function handle_bus_send(caller_principal, req):
    if req.has_client_sender_fields():
        return error(400, "client_sender_fields_forbidden")
    target_addr = parse_canonical_addr(req.target)       # rejects '/', 'local / x', 'peer / x', RESERVED_NAMES, bidi
    thread_id   = validate_thread_id(req.thread_id or "main")
    msg_kind    = validate_msg_kind(req.msg_kind)        # closed enum, zero control/bidi chars
    if len(req.body_text.encode("utf-8")) > 65536:
        return error(413, "inline_body_too_large_use_artifact")

    # Stage bounded artifacts privately. Publish them only through the same delivery fence.
    staged_blobs = stage_verified_blobs_to_host_ro_spool(req.artifact_refs, target_addr)
    host_msg_id = mint_crypto_msg_id_128bit()
    with controller.routing_fence(caller_principal, target_addr, thread_id), registry_db.transaction():
        edge = routing_table.find_active_edge(caller_principal, target_addr, thread_id, msg_kind)
        if edge is None or not controller.check_current_grant(edge.lease_id, edge.generation):
            return error(403, "target_not_authorized")
        src_inc, dst_inc = require_current_edge_incarnations(edge, caller_principal, target_addr)
        if req.in_reply_to is not None:
            require_replyable(req.in_reply_to, caller_principal, edge.edge_id, thread_id)
        enforce_rate_and_mailbox_limits(edge)
        turn = routing_table.consume_turn_if_available(edge, caller_principal.role)
        env = stamp_host_envelope(host_msg_id, caller_principal, src_inc, target_addr, dst_inc,
                                  thread_id, msg_kind, req, turn, staged_blobs)
        seq = event_log.append(env)
        dispatch_receipts.insert(target_addr, dst_inc, thread_id, host_msg_id,
                                 sha256(env.body_text), caller_principal)
        outbox.enqueue_delivery(seq, host_msg_id, edge.id, edge.lease_id, edge.generation,
                                src_inc, dst_inc, thread_id)
    wake_waiters(target_addr, seq)
    return {"msg_id": host_msg_id, "seq": seq}

function dispatch_pending(row):
    with controller.routing_fence_for_row(row):
        if not controller.current_edge_and_grant_match(row.pins):
            outbox.cancel(row, "revoked_or_stale")
            return
        # Persist before attempting the first transport write. Recovery trusts this boundary.
        if not outbox.mark_pending_as_dispatch_started_durable(row):
            return
        result = transport.first_write_nonblocking(row)
        if result.proves_zero_bytes_sent:
            outbox.return_to_pending_under_same_pins(row)
        else:
            outbox.record_handoff_or_uncertainty(row, result)
    # Any continuation also checks the grant at its send boundary.

function revoke_edge(edge):
    with controller.routing_fence_for_edge(edge):
        controller.fence_dispatch_immediately(edge)
        registry_db.persist_revocation_and_cancel_pending_rows(edge)
    close_issued_streams_and_wake_waiters(edge)
```

### Failure, recovery, and verification tests

- **Failure / recovery:**
  - On recovery, keep dispatch closed until the authoritative grants and incarnations are loaded.
    A controller restart invalidates the old grant generations and requires fresh grants.
    Recovered rows may not silently rebind to a new grant. A pending row can retry only when
    all its original pins remain current. A durable dispatch-start record
    without proof that zero bytes were sent leaves the outcome uncertain. Keep the original
    `msg_id` for reconciliation and require trusted terminal evidence before retry. A worker's
    status alone cannot prove non-delivery.
  - Revocation persists a tombstone for the old grant generation. If writing it fails, remain
    fenced and fail closed through recovery until the grant state can be confirmed. Revoking a
    sandbox, worker, or `@PEER` removes all incident edges, closes dispatched streams, and wakes
    blocked `agent_wait` callers with `edge_revoked`. Qualify the `<1s` cascade separately.
- **Verification tests:**
  1. Fuzz/property tests on `parse_canonical_addr` / `format_canonical_addr` proving bijection,
     rejection of `/`, `local / foo`, `peer / foo`, `RESERVED_NAMES`, `..`, bidi overrides, and
     non-canonical spacing; store test proving `"local"` remains immutable to orchestrator
     proposals after `worker@1` ID migration.
  2. Adversarial lateral-movement, spoofing, and ping-pong tests proving: a leaf sandbox cannot
     message siblings without a `RoutingEdge`; omitting `in_reply_to` still exhausts
     `edge.max_rounds`; cross-sandbox `in_reply_to` probing fails closed; `-o` maps strictly to
     `PARENT_TASK`; and body text containing `</oc-peer-message` cannot escape the 128-bit
     nonce-tagged envelope.
  3. Sub-orchestrator attenuation tests proving a depth-1 sub-orchestrator cannot widen
     `allowed_models`/`broker_routes`/`security_profile`, cannot exceed `max_total_sandboxes`, and
     cannot spawn without a nonblank task brief.
  4. Host-client hardening test pointing `oc_daemon` at a malicious mock `opencode serve` emitting
     `302 Location: http://127.0.0.1:...`, gzip bombs, and oversized SSE events (all rejected);
     patch-spool test verifying zero host writes into `~/opencode-sandbox` (`:ro` `/run/oc-inbox/`
     only).
  5. Cycle-detection test ($A \to B \to A \implies$ `DeadlockCycleRejected`), priority backpressure
     test, and mid-thread cross-model handoff test proving `admit_lane` + `PaidFallbackGrant`
     enforcement across a Codex implementor + Claude reviewer + `@PEER` fixture.
  6. The shared local PoC fixture queues a turn, revokes its grant before transport handoff, and
     restarts the outbox with the worker incarnation unchanged. Verify zero worker deliveries.
     Also cover handoff winning the race, uncertain delivery after a crash, and two concurrent
     sends contesting the final available turn.

## Concrete gaps and checkboxes

- [ ] **Gap M2.1 — Slash-free `worker.id` migration & immutability (`oc_schema.py`,
      `oc_address.py`):** resolve the open decision in [prd_m](prd_m.md) (recommended: migrate
      `worker@1` IDs to `WORKER_NAME_RE` with `{"local", "peer"}` reserved, update `is_builtin_id()`
      so `"local"` remains immutable, and enforce `RESERVED_NAMES` + `oc_address.py` everywhere).
- [ ] **Gap M2.2 — Per-job UDS `opencode serve` + `tmux` entrypoint (`oc-opencode-run.py`):**
      supervise agent-only `/run/secrets/oc_server_pw` `opencode serve` on per-job `0o600` UDS (or
      per-instance ephemeral loopback / SSH `-L` remote job UDS), plus hardened `oc_daemon`
      HTTP/SSE client (`follow_redirects=False`, `Accept-Encoding: identity`, bounded frames).
- [ ] **Gap M2.3 — Capability-scoped `oc_hub` & MCP tools (`oc_hub.py`):** implement `$STATE`
      SQLite Command/Event/Projection + Outbox, `RoutingEdge` ACLs + durable per-edge turn budgets,
      monotonic `SubtreeBudget` attenuation + global sandbox cap, strict 4-role `trust_class`,
      dual-tag 128-bit nonce framing, `WaitForGraph` cycle check, host-owned `:ro` `/run/oc-inbox/`
      patch staging, `@PEER` enrollment, and quota-gated mid-thread cross-model handoff.
