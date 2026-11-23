# PRD M3.1 Read-Only Projection Walkthrough (`docs/prds/spikes/m/projection/`)

Parent: [prd_m3.md](../../prd_m3.md) · [prd_m3a.md](../../prd_m3a.md) · [prd_m3b.md](../../prd_m3b.md) ·
[prd_m.md](../../prd_m.md) · builds on [oc_coord_contract.py](../oc_coord_contract.py),
[oc_registry.py](../oc_registry.py), and [oc_hub.py](../oc_hub.py)

## 1. Scope, Boundaries, and Non-Goals

This Gate 1 walkthrough specifies the **read-only M3.1 projection slice** for the unified
`Project -> Sandbox -> Thread` control plane, producing strictly typed, bounded, inert JSON-safe
snapshots from `$STATE/registry.sqlite` and `$STATE` health markers without mutating any state.

### Owned File Boundary (Strictly Disjoint)

All code and tests for this slice live exclusively under `docs/prds/spikes/m/projection/`:

- `PROJECTION_WALKTHROUGH.md` — this Gate 1 design walkthrough.
- `oc_projection_contract.py` — frozen dataclasses, schema version constants, bounds constants,
  validated cursor grammar, and strict JSON-safe serializer (`to_dict()`).
- `oc_projection.py` — `ReadOnlyProjectionService` (engine-enforced read-only SQLite snapshot
  reader, `O_NOFOLLOW` state/marker validation, caller authorization, provenance verification, and
  bounded pagination).
- `test_projection.py` — deterministic offline qualification suite built on synthetic
  `CoordRegistry` + `CoordHub` fixtures (zero Podman, zero network, zero live credentials, zero
  writes to host production directories).

**Zero edits to shared files:** This slice reuses `oc_coord_contract.py`, `oc_registry.py`,
`oc_hub.py`, and `docs/prds/spikes/m/local/*` as currently merged on `main` (`e176712` / shared
plan `f1dcc79`). No shared contract change is required. If any shared helper becomes necessary
later, it will be proposed and cleared at Gate 1 before modifying any file outside
`docs/prds/spikes/m/projection/`.

### Explicit Non-Goals (Deferred to Later Slices / Other Owners)

- No SvelteKit frontend, HTTP/WebSocket daemon routes, or Tauri v2 bridge (`prd_m3a.md`, `prd_m3b.md`).
- No mutations, message sending, grant creation/revocation, or `InputLease` writes.
- No embedded PTY streaming, browser CDP screencasts, or containerized `safe_run` turn diffs.
- No live provider credentials, real subscriptions (`I3`/`I4`), SSH/Mac Mini onboarding (`I2`),
  warm worker seeding (`I5`), or local compiled profile proof (`docs/prds/spikes/l_m_profile/`).
- No changes to production `oc-sandbox`, `oc-bridge.py`, or any PRD `Human review` checkbox.

---

## 2. Trust Boundaries & Engine-Enforced Read-Only Access

### 2.1 Filesystem & SQLite Read-Only Confinement

`ReadOnlyProjectionService` treats `$STATE` path hygiene identically to `oc_registry.py` and
`oc_hub.py`, and enforces read-only access at both the OS and SQLite engine layers:

```python
function open_readonly_snapshot(state_dir, sandbox_root):
    # 1. Path trust validation (never follow symlinks; never resolve inside sandbox_root)
    trusted_dir = assert_trusted_dir(state_dir, sandbox_root=sandbox_root)
    assert_not_in_sandbox(trusted_dir, sandbox_root)
    assert_existing_ancestors_safe(trusted_dir)

    db_path = trusted_dir / "registry.sqlite"
    # 2. Verify registry.sqlite itself via O_RDONLY | O_NOFOLLOW + fstat
    #    - Missing -> CoordPolicyError("registry_missing") (NEVER auto-create!)
    #    - Symlink (ELOOP), non-regular file, wrong UID (not euid/0), or group/world writable (mode & 0o022)
    #      -> CoordPolicyError("registry_untrusted")
    verify_regular_file_nofollow(db_path, require_owner=True, reject_group_world_writable=True)

    # 3. Open dedicated SQLite connection strictly read-only (URI mode=ro, no creation)
    #    Note: immutable=0 so live WAL snapshots from concurrent CoordHub writers are visible!
    conn = sqlite3.connect(
        f"file:{quote(str(db_path))}?mode=ro",
        uri=True,
        isolation_level=None,   # explicit transaction control
        timeout=2.0,
        check_same_thread=False,
    )
    conn.row_factory = dict_row_factory
    conn.execute("PRAGMA query_only = ON")
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA busy_timeout = 2000")
    return conn
```

- **Why `mode=ro` + `PRAGMA query_only = ON` + `immutable=0`?**
  - SQLite refuses to create missing files (`mode=ro`) and refuses any `INSERT`/`UPDATE`/`DELETE`/DDL
    (`PRAGMA query_only = ON`).
  - Leaving `immutable=0` allows SQLite WAL mode to serve consistent concurrent snapshots while
    `CoordHub` writes on its own connection without racing or corrupting reads.
  - Because `registry.sqlite` is opened in WAL mode by `CoordRegistry`, if `-wal`/`-shm` exist
    alongside `registry.sqlite`, `verify_optional_sidecar_nofollow()` verifies any present
    `registry.sqlite-wal` and `registry.sqlite-shm` files are also regular, non-symlink,
    owner-trusted, non-group/world-writable files before opening SQLite.
- **Single-Snapshot Transaction Discipline:** Every public read API executes inside a single
  `BEGIN DEFERRED` transaction (immediately executing a first `SELECT` on `seq_counter` to anchor
  the WAL read snapshot!) and unconditionally executes `ROLLBACK` in `finally:` before closing
  (or releasing) the connection. Readers therefore:
  1. Never see torn cross-table state (e.g., a rotated `sandboxes.incarnation_id` mixed with old
     `routing_edges` or `outbox` rows from a different commit).
  2. Never hold long-lived read marks that block WAL checkpointing.

### 2.2 State-Dir Health Marker Reads (`O_NOFOLLOW`)

Inside each snapshot operation (immediately before opening the `BEGIN DEFERRED` read transaction,
and re-checked inside if an optional live fence oracle is provided):

- Read `.coord_degraded` and `.coord_session_active` via `O_RDONLY | O_NOFOLLOW`, verifying regular
  file, owner UID, and bounded read (`<= 256` bytes), mirroring `oc_hub.py._read_marker_text_nofollow()`.
- **Fail-closed on marker error:** If either marker is a symlink (`ELOOP`), non-regular file,
  wrong owner, group/world-writable, or unreadable (`OSError`), do **not** treat the hub as healthy:
  force `health.degraded = True` and append `"marker_unreadable"` to `degraded_reasons`.
- **Unconfirmed external bindings check (from the same SQLite snapshot):** Query
  `external_transport_bindings WHERE terminal_confirmed = 0` joined with `sandboxes`:
  - Count bindings where `abort_requested != 0`, OR where the corresponding sandbox is `revoked`,
    OR where the binding's `incarnation_id` differs from the current `sandboxes.incarnation_id`
    (superseded unconfirmed external owner).
  - Expose `unconfirmed_bindings_count` and (for `OPERATOR` only) bounded summary entries
    (omitting raw host secrets; exposing sanitized `sandbox_addr`, `incarnation_id`,
    `abort_requested`, `terminal_confirmed`, sanitized `reason`, `updated_at`).
  - If `unconfirmed_bindings_count > 0`, set `health.has_unconfirmed_bindings = True`.
  - **Fail-closed operational gate:** When `health.degraded` is `True` OR
    `health.has_unconfirmed_bindings` is `True`, non-`OPERATOR` callers are refused with
    `CoordPolicyError("hub_degraded")`, while `OPERATOR` retains read-only diagnostic visibility
    with explicit health warnings!

### 2.3 Session-Generation Fence Readiness (`prd_m3a.md` / `prd_m3b.md`)

To support the M3a/M3b session-generation retirement invariant specified in `f1dcc79`:

- `ReadOnlyProjectionService` accepts an optional host-side `session_validator` callback:
  `validate_read_session(caller: PrincipalCtx, read_session_id: str, session_generation: int) -> bool`
  (and optional `live_fence_checker(sandbox_addr: str, incarnation_id: str) -> bool` when wired
  into an in-process `CoordHub`).
- When `read_session_id` / `session_generation` are supplied on a read call:
  1. Validate both before reading SQLite (`session_validator` must return `True`; falsy or raising
     raises `RevokedError("read_session_retired")`).
  2. Re-validate **after** reading SQLite and **before** returning the snapshot object (fencing
     late replies that raced a logout, expiry, or session rotation during the query!).
  3. Echo validated `(read_session_id, session_generation)` on the returned snapshot envelope so
     M3a/M3b clients can also discard any response whose generation no longer matches the active
     UI session.
- If a caller supplies `read_session_id` or `session_generation` when **no** `session_validator`
  is configured, fail closed with `CoordPolicyError("read_session_validator_unconfigured")` rather
  than echoing unverified session metadata.

---

## 3. Caller Read Authority Matrix (`PrincipalCtx`)

Every read API requires a host-authenticated `PrincipalCtx` (never constructed from untrusted
payloads) and performs role + liveness authorization **inside the same SQLite read snapshot**:

| `CoordRole` | `get_workspace_tree` | `get_sandbox_status` | `get_thread_events` | `get_sandbox_mailbox` |
|---|---|---|---|---|
| `OPERATOR` (`sandbox_addr is None`, `incarnation_id is None`) | Full fleet (active + revoked; optional historical incarnations); full health diagnostics | Any sandbox (active or revoked); full binding status & grants | Any sandbox/thread (current or historical incarnation with explicit stale flag) | Any sandbox outbox + stale grant/incarnation flags |
| `ORCHESTRATOR` (root `sandbox_addr is None`) | Full fleet when operational (no raw host marker reasons / `owner_id`) | Any sandbox when operational (no raw `owner_id`) | Any sandbox/thread (current or historical within operational gate) | Any sandbox outbox when operational |
| `ORCHESTRATOR` (sandbox-bound `sandbox_addr != None`) | Strictly own live subtree (`parent_addr` closure rooted at `caller.sandbox_addr`) | Strictly own live subtree | Strictly own live subtree; excludes `OPERATOR_DIRECTIVE` outside self | Strictly own live subtree |
| `JOB` (`sandbox_addr` + `incarnation_id` required) | Own current live sandbox + peer sandboxes with an **active, non-tombstoned** `routing_edge` from `caller.sandbox_addr` (matching `src_incarnation` if pinned) | Own live sandbox only (active edges to/from self; zero other-sandbox internals) | Own current incarnation threads + peer current incarnation threads explicitly in `allowed_threads` of an active non-tombstoned edge; **strictly excludes `OPERATOR_DIRECTIVE`** on peer reads; **refuses historical incarnations** | **DENIED (`CoordAuthError`)** |
| `EXTERNAL_PEER` | **DENIED (`CoordAuthError`)** | **DENIED (`CoordAuthError`)** | **DENIED (`CoordAuthError`)** | **DENIED (`CoordAuthError`)** |

### Strict Caller Liveness Rules (Inside Snapshot)

1. `OPERATOR` must have `sandbox_addr is None` and `incarnation_id is None`; otherwise reject with
   `CoordAuthError("operator_principal_must_not_bind_sandbox")`.
2. Any principal with `sandbox_addr is not None` (`JOB` or sandbox-bound `ORCHESTRATOR`):
   - `sandboxes` row for `caller.sandbox_addr` must exist and have `status != "revoked"`.
   - `sandboxes.incarnation_id` must equal `caller.incarnation_id` (else `IncarnationMismatchError`).
   - `external_transport_bindings` for `(caller.sandbox_addr, caller.incarnation_id)` must NOT have
     `abort_requested != 0` or `terminal_confirmed != 0` (else `RevokedError`).
   - If `live_fence_checker` is attached and returns fenced for `(caller.sandbox_addr,
     caller.incarnation_id)` -> `RevokedError`.
3. Active edge validation for `JOB` peer reads:
   - Edge must have `active == 1`, `src_actor == caller.sandbox_addr`,
     `(src_incarnation IS NULL OR src_incarnation == caller.incarnation_id)`, AND **no** matching
     row in `grant_tombstones` for `(edge_id, grant_generation)`!
   - Destination sandbox must exist and have `status != "revoked"` (revoked peers are never
     readable by `JOB` callers; `OPERATOR` can still inspect revoked sandboxes!).
   - Corrupt/non-list `allowed_threads_json` on an edge fails closed (grants zero threads).

---

## 4. Pseudocode Walkthrough of Read-Only Operations

### 4.1 Core Bounds Constants (`oc_projection_contract.py`)

```python
PROJECTION_SCHEMA_VERSION = "oc.m3.readonly_projection@1"
MAX_PROJECTS_PER_PAGE = 50
MAX_SANDBOXES_PER_PAGE = 100
MAX_THREADS_PER_SANDBOX = 50
MAX_EDGES_PER_SANDBOX = 100
MAX_PAGE_LIMIT = 200
DEFAULT_PAGE_LIMIT = 50
MAX_RESPONSE_BYTES = 256 * 1024        # 256 KiB serialized JSON payload cap per page
MAX_ITEM_TEXT_BYTES = 16 * 1024        # 16 KiB per-item text cap (UTF-8 safe truncation)
MAX_METADATA_TEXT_BYTES = 256          # Titles, reasons, sanitized detail fields
MAX_CURSOR_BYTES = 256
MAX_UNCONFIRMED_BINDINGS_SUMMARY = 100
```

All `limit`, `max_*`, and `max_response_bytes` arguments reject `bool`, non-`int`, `< 1`, or
values exceeding their hard upper bound with `CoordValidationError`.

### 4.2 Operation 1: `get_workspace_tree`

```python
function get_workspace_tree(
    caller,
    *,
    include_revoked=True,
    include_historical_incarnations=False,
    after_sandbox_cursor=None,
    sandbox_limit=100,
    max_threads_per_sandbox=50,
    read_session_id=None,
    session_generation=None,
) -> WorkspaceTreeSnapshot:
    validate_bounds(sandbox_limit <= MAX_SANDBOXES_PER_PAGE, max_threads_per_sandbox <= MAX_THREADS_PER_SANDBOX)
    cursor_tuple = parse_sandbox_cursor(after_sandbox_cursor)  # "v1:<project_id>:<sandbox_addr>"
    check_session_pre(caller, read_session_id, session_generation)
    health_markers = read_state_dir_markers_nofollow(state_dir)

    with readonly_snapshot_tx() as conn:
        snapshot_seq = read_seq_counter(conn)
        unconfirmed = query_unconfirmed_bindings(conn)
        health = build_workspace_health(health_markers, unconfirmed, is_operator=(caller.role == OPERATOR))
        enforce_caller_authority_and_health(conn, caller, health, require_admin=False)

        if include_historical_incarnations and caller.role not in (OPERATOR, ORCHESTRATOR):
            raise CoordAuthError("historical_incarnations_admin_only")

        # Determine exact visible sandbox set & allowed threads per sandbox
        visible_addrs, allowed_threads_map = resolve_visible_sandboxes(conn, caller, include_revoked)

        # Fetch bounded sandboxes ordered deterministically by (project_id ASC, sandbox_addr ASC)
        # applying cursor_tuple > (last_project_id, last_sandbox_addr), fetching sandbox_limit + 1
        sb_rows = select_visible_sandboxes(conn, visible_addrs, cursor_tuple, limit=sandbox_limit + 1)
        has_more = len(sb_rows) > sandbox_limit
        page_sbs = sb_rows[:sandbox_limit]

        # For page_sbs ONLY (bounded, zero full-table scans):
        #   - Fetch threads (current incarnation by default; historical only if requested by admin)
        #   - Fetch historical_thread_count per sandbox
        #   - Fetch active vs revoked/tombstoned grant counts
        #   - Fetch outbox status counts (OPERATOR/ORCHESTRATOR only; empty dict for JOB)
        #   - Fetch external_transport_bindings state ("none"|"active"|"abort_requested"|"terminal_confirmed")
        #   - Group page_sbs into deterministic ProjectSummary -> SandboxSummary -> ThreadSummary tree
        #   - Sanitize display metadata (project_name, branch, task_brief, title) for control/bidi chars
        snapshot = assemble_workspace_tree(snapshot_seq, health, page_sbs, has_more, ...)

    check_session_post(caller, read_session_id, session_generation)
    return snapshot
```

### 4.3 Operation 2: `get_sandbox_status`

```python
function get_sandbox_status(
    caller,
    *,
    target,
    read_session_id=None,
    session_generation=None,
) -> SandboxStatusSnapshot:
    addr = parse_local_target(target).canonical
    check_session_pre(caller, read_session_id, session_generation)
    health_markers = read_state_dir_markers_nofollow(state_dir)

    with readonly_snapshot_tx() as conn:
        snapshot_seq = read_seq_counter(conn)
        unconfirmed = query_unconfirmed_bindings(conn)
        health = build_workspace_health(health_markers, unconfirmed, is_operator=(caller.role == OPERATOR))
        enforce_caller_authority_and_health(conn, caller, health, require_admin=False)
        enforce_sandbox_status_access(conn, caller, addr)  # JOB: self only; ORCHESTRATOR: subtree

        sb = select_sandbox(conn, addr)
        if sb is None:
            raise CoordPolicyError("sandbox_not_found")
        edges = select_edges_for_sandbox(conn, addr, limit=MAX_EDGES_PER_SANDBOX + 1)
        tombstones = select_tombstones_for_edges(conn, edges)
        outbox_counts = select_outbox_counts(conn, addr) if caller.role in (OPERATOR, ORCHESTRATOR) else {}
        binding_summary = select_binding_summary(conn, addr, sb.incarnation_id, include_reason=(caller.role == OPERATOR))
        budget = select_sandbox_budget_safe(conn, addr, sb.incarnation_id)
        snapshot = assemble_sandbox_status(snapshot_seq, health, sb, edges, tombstones, outbox_counts, binding_summary, budget)

    check_session_post(caller, read_session_id, session_generation)
    return snapshot
```

### 4.4 Operation 3: `get_thread_events` (Bounded, Provenance-Verified Pagination)

```python
function get_thread_events(
    caller,
    *,
    target,
    thread_id,
    incarnation_id=None,
    after_cursor=None,
    limit=DEFAULT_PAGE_LIMIT,
    max_response_bytes=MAX_RESPONSE_BYTES,
    read_session_id=None,
    session_generation=None,
) -> ThreadEventsPage:
    addr = parse_local_target(target).canonical
    clean_thread = validate_thread_id(thread_id)
    validate_bounds(1 <= limit <= MAX_PAGE_LIMIT, 1024 <= max_response_bytes <= MAX_RESPONSE_BYTES)
    parsed_cursor = parse_event_cursor(after_cursor)  # "v1:<seq>:<source_rank>:<incarnation_id>"
    check_session_pre(caller, read_session_id, session_generation)
    health_markers = read_state_dir_markers_nofollow(state_dir)

    with readonly_snapshot_tx() as conn:
        snapshot_seq = read_seq_counter(conn)
        unconfirmed = query_unconfirmed_bindings(conn)
        health = build_workspace_health(health_markers, unconfirmed, is_operator=(caller.role == OPERATOR))
        enforce_caller_authority_and_health(conn, caller, health, require_admin=False)

        sb = select_sandbox(conn, addr)
        if sb is None:
            raise CoordPolicyError("sandbox_not_found")

        # Resolve target incarnation & enforce stale/historical access rules
        target_inc = validate_opaque_token(incarnation_id, "incarnation_id") if incarnation_id is not None else sb.incarnation_id
        is_current_inc = (target_inc == sb.incarnation_id)
        if parsed_cursor is not None and parsed_cursor.incarnation_id != target_inc:
            raise CoordValidationError("cursor_incarnation_mismatch")

        # Authorize thread read & determine whether OPERATOR_DIRECTIVE must be excluded
        exclude_operator_directives = authorize_thread_read(
            conn, caller, sb, clean_thread, target_inc=target_inc, is_current_inc=is_current_inc
        )

        # Query event_log (source_rank=0) and stream_events (source_rank=1) strictly scoped to
        # (addr, target_inc, clean_thread) and (seq, source_rank) > (cursor_seq, cursor_rank).
        # Fetch limit + 1 from each table so merged sort guarantees exact pagination without gaps!
        ev_rows = select_thread_event_log_rows(conn, addr, target_inc, clean_thread, parsed_cursor, exclude_operator_directives, limit=limit + 1)
        st_rows = select_thread_stream_rows(conn, addr, target_inc, clean_thread, parsed_cursor, exclude_operator_directives, limit=limit + 1)

        # Merge by (seq ASC, source_rank ASC, row_key ASC)
        merged = merge_sorted(ev_rows, st_rows)

        # Project items sequentially under BOTH row count cap (limit) AND byte cap (max_response_bytes):
        #   - Every stream_events row is provenance-verified inside this snapshot (Section 5)
        #   - Individual item text is safely UTF-8 truncated to <= MAX_ITEM_TEXT_BYTES with
        #     text_truncated + original_text_bytes + has_control_or_bidi
        #   - Always admit at least 1 bounded item if merged is non-empty; stop before exceeding
        #     max_response_bytes for subsequent items, setting has_more=True and exact next_cursor
        page = build_bounded_event_page(merged, limit=limit, max_response_bytes=max_response_bytes, ...)

    check_session_post(caller, read_session_id, session_generation)
    return page
```

### 4.5 Operation 4: `get_sandbox_mailbox`

```python
function get_sandbox_mailbox(
    caller,
    *,
    target,
    statuses=None,
    after_cursor=None,
    limit=DEFAULT_PAGE_LIMIT,
    max_response_bytes=MAX_RESPONSE_BYTES,
    read_session_id=None,
    session_generation=None,
) -> MailboxPage:
    # Strictly admin-only (OPERATOR or subtree ORCHESTRATOR); JOB & EXTERNAL_PEER denied!
    if caller.role not in (CoordRole.OPERATOR, CoordRole.ORCHESTRATOR):
        raise CoordAuthError("mailbox_projection_admin_only")
    addr = parse_local_target(target).canonical
    clean_statuses = validate_outbox_statuses(statuses)
    parsed_cursor = parse_mailbox_cursor(after_cursor)  # "v1:<seq>:<msg_id>"
    validate_bounds(1 <= limit <= MAX_PAGE_LIMIT, 1024 <= max_response_bytes <= MAX_RESPONSE_BYTES)
    check_session_pre(caller, read_session_id, session_generation)
    health_markers = read_state_dir_markers_nofollow(state_dir)

    with readonly_snapshot_tx() as conn:
        snapshot_seq = read_seq_counter(conn)
        unconfirmed = query_unconfirmed_bindings(conn)
        health = build_workspace_health(health_markers, unconfirmed, is_operator=(caller.role == OPERATOR))
        enforce_caller_authority_and_health(conn, caller, health, require_admin=True)
        enforce_subtree_if_sandbox_orchestrator(conn, caller, addr)

        sb = select_sandbox(conn, addr)
        if sb is None:
            raise CoordPolicyError("sandbox_not_found")

        # Join outbox + event_log + routing_edges + grant_tombstones for dst_addr = addr,
        # ordered by (o.seq ASC, o.msg_id ASC), computing:
        #   - is_stale_incarnation = (o.dst_incarnation != sb.incarnation_id)
        #   - is_stale_grant = (edge missing OR edge.active == 0 OR tombstone exists OR edge.grant_generation != o.grant_generation)
        #   - sanitized detail (control/bidi scrubbed, <= MAX_METADATA_TEXT_BYTES)
        #   - exclude OPERATOR_DIRECTIVE rows if sandbox-bound ORCHESTRATOR reads another sandbox
        rows = select_mailbox_rows(conn, addr, clean_statuses, parsed_cursor, exclude_op_dir, limit=limit + 1)
        page = build_bounded_mailbox_page(rows, sb, limit=limit, max_response_bytes=max_response_bytes, ...)

    check_session_post(caller, read_session_id, session_generation)
    return page
```

---

## 5. Provenance Re-Verification & Inert Content Boundary

The projection layer **never trusts raw `stream_events.badge` strings** stored in SQLite (defending
against database corruption, legacy bugs, or hostile writes). Inside the same read snapshot, every
projected `stream_events` row runs through `_verify_and_project_provenance(conn, row)`:

1. **Non-`user_message` events** (`text_delta`, `reasoning_delta`, `tool_call`, `file_edit`,
   `turn_completed`, `turn_error`, `revoked`):
   - `effective_badge` MUST be `None`, `authority_rank = 0`.
   - If `row["badge"] is not None`: set `provenance_anomaly = True`, `anomaly_reason = "non_user_event_has_badge"`,
     and force `effective_badge = None`.
2. **`user_message` events:**
   - Parse `raw_badge = row["badge"]`. If missing or not a valid `ProvenanceBadge` member:
     downgrade to `ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED`, `authority_rank = 0`,
     `provenance_anomaly = True`, `anomaly_reason = "invalid_or_missing_badge"`.
   - If `raw_badge` is `SANDBOX_LOCAL_UNVERIFIED` or `TUI_INPUT`:
     - Keep `effective_badge = raw_badge`, `authority_rank = 0` (zero directive/approval authority).
     - Note: for `TUI_INPUT`, check that a consumed `tui_enter_tokens` row exists for
       `(sandbox_addr, incarnation_id)` with `surface_kind = "opencode-tui"` and
       `consumed_at IS NOT NULL`; if none exists, downgrade to `SANDBOX_LOCAL_UNVERIFIED` with
       `provenance_anomaly = True`, `anomaly_reason = "unbacked_tui_badge"`.
   - If `raw_badge` claims a **verified host-originated badge** (`OPERATOR`, `ORCHESTRATOR`, or `PEER`):
     - Require a matching `event_log` row (by `message_id` or `dispatch_msg_id`) on the **exact**
       `(sandbox_addr, incarnation_id, thread_id)` AND a matching **consumed** `dispatch_receipts`
       row (`consumed_at IS NOT NULL`) for `(sandbox_addr, incarnation_id, session_id=thread_id,
       message_id)` whose:
       1. `receipt.trust_class` maps via `_TRUST_CLASS_TO_BADGE` to the exact `raw_badge` (and
          matches `event_log.trust_class`), AND
       2. `receipt.body_sha256 == sha256_canonical_body(row["text"])` (catches post-write body
          tampering!).
     - If ANY check fails: **fail closed** by downgrading `effective_badge` to
       `ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED`, `authority_rank = 0`,
       `provenance_anomaly = True`, and recording a closed-enum `anomaly_reason`
       (`"unbacked_host_badge"`, `"trust_class_mismatch"`, or `"receipt_body_hash_mismatch"`).
     - If all checks pass: preserve `effective_badge`, set `verified_actor = receipt.src_actor`,
       and set `authority_rank` (`3` for `OPERATOR`, `2` for `ORCHESTRATOR`, `1` for `PEER`).
3. **Inert display & hostile Unicode guarantees:**
   - Every projected event includes `render_policy = "inert_text"` and `untrusted_content` (`True`
     for all worker stream events except verified host-originated `OPERATOR`/`ORCHESTRATOR` user
     messages, and `True` for `UNTRUSTED_PEER_DATA` envelopes).
   - Display metadata (`project_name`, `branch`, `task_brief`, `title`, `detail`, `reason`) is
     scrubbed of forbidden control and Unicode bidi override characters and capped to
     `MAX_METADATA_TEXT_BYTES`.
   - Event `text` / `body_text` is UTF-8 byte-capped to `MAX_ITEM_TEXT_BYTES` without splitting
     multibyte codepoints, sets `text_truncated` + `original_text_bytes`, and sets
     `has_control_or_bidi = has_forbidden_control_or_bidi(raw_text)` so downstream SvelteKit UIs
     can render strictly as inert text with a visible warning chip.
   - `artifact_refs_json` is parsed safely and projects ONLY `(name, kind, blob_sha256, size_bytes)`
     — never host spool paths.

---

## 6. Failure & Recovery Matrix

| Failure / Edge Condition | Behavior (Fail-Closed) |
|---|---|
| Missing `registry.sqlite` | Raise `CoordPolicyError("registry_missing")` (never create file). |
| Symlinked / untrusted / group- or world-writable `state_dir`, DB, or `-wal`/`-shm` | Raise `CoordPolicyError` before opening SQLite. |
| Corrupt SQLite DB or missing schema table | Raise `CoordPolicyError("registry_unreadable")`. |
| SQLite lock contention beyond `busy_timeout` | Raise `CoordPolicyError("registry_busy")`. |
| Any SQL write attempted on projection connection | Engine error (`PRAGMA query_only = ON` + `mode=ro`). |
| Symlinked / non-regular / unreadable `.coord_degraded` or `.coord_session_active` | Set `health.degraded = True` (`"marker_unreadable"`); refuse non-operators with `CoordPolicyError("hub_degraded")`; surface degraded banner to `OPERATOR`. |
| Unconfirmed `external_transport_bindings` (`abort_requested=1` or revoked/superseded with `terminal_confirmed=0`) | Surface `has_unconfirmed_bindings = True` + count to `OPERATOR`; refuse non-operators with `CoordPolicyError("hub_degraded")`. |
| Caller sandbox revoked, rotated, or abort-requested | Raise `RevokedError` or `IncarnationMismatchError` before returning any rows. |
| Caller `EXTERNAL_PEER` on any endpoint | Raise `CoordAuthError` immediately. |
| Caller `JOB` on `get_sandbox_mailbox` or ungranted peer or historical incarnation | Raise `CoordAuthError` / `RevokedError` / `IncarnationMismatchError`. |
| `read_session` retired before or during query | Raise `RevokedError("read_session_retired")` before returning snapshot. |
| Malformed `allowed_threads_json` in DB | Treat edge as granting zero threads (fail closed). |
| Malformed `detail_json` or `budget_json` in DB | Mark `malformed_metadata = True` with safe empty dict fallback so operator diagnostics remain usable. |
| Tampered / unbacked `stream_events.badge` or altered `text` hash | Downgrade `effective_badge` to `SANDBOX_LOCAL_UNVERIFIED`, `authority_rank = 0`, `provenance_anomaly = True`, set `has_provenance_anomalies = True` on page. |
| Oversize single event (> `MAX_ITEM_TEXT_BYTES`) or page (> `MAX_RESPONSE_BYTES`) | Truncate single item cleanly at UTF-8 boundary (`text_truncated = True`); stop page cleanly with `has_more = True` and exact `next_cursor` (always making forward progress). |
| Malformed / oversized / incarnation-mismatched cursor | Raise `CoordValidationError`. |

---

## 7. Open Choices Resolved in This Walkthrough (For Gate 1 Review)

1. **Dedicated `mode=ro` + `PRAGMA query_only = ON` connection per snapshot vs. sharing `CoordRegistry._conn`:**
   - **Chosen:** Dedicated `mode=ro` + `PRAGMA query_only = ON` connection verified via `O_NOFOLLOW` +
     explicit `BEGIN DEFERRED` / `ROLLBACK` per read.
   - **Rationale:** Guarantees engine-enforced immutability, zero cross-table tearing under
     concurrent WAL writes, and zero edits to `oc_registry.py`.
2. **Tampered/unbacked provenance badge handling on read:**
   - **Chosen:** Fail-closed downgrade to `SANDBOX_LOCAL_UNVERIFIED` (`authority_rank = 0`) with
     explicit `provenance_anomaly = True` and closed-enum `anomaly_reason` rather than raising an
     exception that blocks the whole thread page.
   - **Rationale:** Prevents both badge spoofing and denial-of-service against operator incident
     inspection.
3. **Least-privilege role scoping on mailbox & host health internals:**
   - **Chosen:** `get_sandbox_mailbox` is restricted to `OPERATOR` and subtree `ORCHESTRATOR`
     (`JOB` and `EXTERNAL_PEER` denied); raw `owner_id`, `token_sha256`, and host-side marker
     reason strings are omitted from non-`OPERATOR` responses (and raw secrets / host paths are
     never returned even to `OPERATOR`).
4. **Historical incarnation reads:**
   - **Chosen:** Default all tree/thread reads to the current `sandboxes.incarnation_id`, surfacing
     `historical_thread_count` and permitting explicit `incarnation_id=<old>` lookup only for
     `OPERATOR` and subtree `ORCHESTRATOR` with explicit `is_current_incarnation = False` and
     `stale_reason = "superseded_incarnation"`.
5. **Session-generation fencing hook on M3.1 read calls:**
   - **Chosen:** Optional `session_validator` checked both before and after the SQLite read
     transaction (fail-closed if session arguments are passed without a validator), echoing the
     validated generation in the snapshot envelope for M3a/M3b late-response fencing.

---

## 8. Offline Qualification & Verification Plan (`test_projection.py`)

All tests run offline via `python3 -B -m unittest discover -s docs/prds/spikes/m/projection -p 'test_*.py'`
under both default `$HOME` and `TMPDIR=/tmp` using synthetic `CoordRegistry` + `CoordHub` fixtures:

1. **Read-only & filesystem confinement:**
   - Missing DB refuses without creating `registry.sqlite`.
   - Symlinked `state_dir`, symlinked `registry.sqlite`, symlinked `-wal`, and group/world-writable
     DB files are refused (`CoordPolicyError`).
   - Direct write attempt on opened projection connection fails with `sqlite3.OperationalError`.
   - State dir inside `sandbox_root` is refused.
2. **Consistent snapshot & bounded pagination:**
   - Multi-project, multi-sandbox, multi-thread `get_workspace_tree` produces deterministic order,
     exact `snapshot_seq`, accurate active/revoked grant counts, outbox counts, and cursor paging.
   - `get_thread_events` paginates seamlessly across merged `event_log` + `stream_events` with
     `limit=1`, `limit=2`, and tight `max_response_bytes` caps, guaranteeing zero duplicates, zero
     skips, and exact forward progress even when a single event exceeds `MAX_ITEM_TEXT_BYTES`.
   - Multibyte UTF-8 text truncation never splits characters; `text_truncated`, `original_text_bytes`,
     and `has_control_or_bidi` are exact.
   - Concurrent WAL writer mutating `sandboxes` + `routing_edges` + `outbox` while a read snapshot
     is held inside `BEGIN DEFERRED` never produces torn cross-table state.
   - Malformed, negative, oversized, or incarnation-mismatched cursors raise `CoordValidationError`.
3. **Stale, degraded, revoked, and unconfirmed state surfacing:**
   - Revoked sandboxes, tombstoned grants, superseded incarnations, `uncertain`/`aborted`/`cancelled`/
     `handed_off` outbox rows, and unconfirmed `external_transport_bindings` are surfaced accurately
     to `OPERATOR` with explicit stale/revoked flags.
   - Degraded marker (`.coord_degraded`), unreadable/symlinked marker, or unconfirmed external
     binding blocks non-`OPERATOR` callers (`CoordPolicyError("hub_degraded")`) while preserving
     `OPERATOR` diagnostic access.
   - Explicit historical incarnation lookup succeeds for `OPERATOR` with
     `is_current_incarnation=False, stale_reason="superseded_incarnation"`, and is refused for `JOB`.
4. **Provenance verification & hostile input defense:**
   - Legitimate `[Operator]`, `[Orchestrator -o]`, `[Peer]`, `[TUI Input · In-Sandbox]`, and
     `[Sandbox-Local / Unverified]` stream events project with exact expected badges & authority ranks.
   - Tampered SQLite rows — forged `[Operator]` on unlinked `user_message`, `[Operator]` badge on a
     `UNTRUSTED_PEER_DATA` envelope, post-write altered `stream_events.text` breaking receipt
     `body_sha256`, unbacked `TUI_INPUT` without consumed token, and non-null badge on `text_delta` —
     all fail closed (downgraded to `SANDBOX_LOCAL_UNVERIFIED` or `None`, `authority_rank=0`,
     `provenance_anomaly=True`).
   - Hostile control/bidi characters in `project_name`, `branch`, `title`, and `detail` are scrubbed;
     artifact projections omit host spool paths.
5. **Caller authorization & session-generation fence matrix:**
   - `EXTERNAL_PEER` rejected on all 4 operations.
   - `JOB` denied on `get_sandbox_mailbox`, denied on ungranted peer, denied on tombstoned edge,
     denied on non-allowed thread, excluded from `OPERATOR_DIRECTIVE` events on peer reads, denied
     when self is revoked or incarnation-rotated.
   - Sandbox-bound `ORCHESTRATOR` restricted strictly to its own `parent_addr` subtree; denied
     outside subtree.
   - `read_session` retired *before* read OR *during* the snapshot (between pre-check and
     post-check) raises `RevokedError("read_session_retired")` and returns zero data; session params
     without a configured validator fail closed.
   - Corrupt `allowed_threads_json` fails closed (zero threads granted); corrupt `detail_json` sets
     `malformed_metadata=True` without crashing operator diagnostics.
6. **End-to-end synthetic hub integration:**
   - Run a real `CoordHub` + `ExternallyFencedFakeTransport` lifecycle (register, grant, send,
     stream, revoke, restart, register fresh same-address successor) and verify `ReadOnlyProjectionService`
     projects exact tree, status, mailbox, provenance, and historical vs current incarnation views
     with zero mutations to SQLite (`PRAGMA data_version` / audit chain intact).
