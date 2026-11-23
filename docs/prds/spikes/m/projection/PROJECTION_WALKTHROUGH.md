# PRD M3.1 Read-Only Projection Walkthrough (`docs/prds/spikes/m/projection/`)

Parent: [prd_m3.md](../../prd_m3.md) · [prd_m3a.md](../../prd_m3a.md) · [prd_m3b.md](../../prd_m3b.md) ·
[prd_m.md](../../prd_m.md) · builds on [oc_coord_contract.py](../oc_coord_contract.py),
[oc_registry.py](../oc_registry.py), and [oc_hub.py](../oc_hub.py)

## 1. Scope, Boundaries, and Non-Goals

This Gate 1 walkthrough specifies the **standalone, operator-only read-only M3.1 projection slice**
for the unified `Project -> Sandbox -> Thread` control plane, producing strictly typed, bounded,
inert JSON-safe snapshots from `$STATE/registry.sqlite` and `$STATE` health markers.

### Owned File Boundary (Strictly Disjoint)

All code and tests for this slice live exclusively under `docs/prds/spikes/m/projection/`:

- `PROJECTION_WALKTHROUGH.md` — this Gate 1 design walkthrough.
- `oc_projection_contract.py` — frozen dataclasses, schema version constants, bounds constants,
  canonical base64url JSON cursor codec, and strict `allow_nan=False` JSON serializer.
- `oc_projection.py` — `ReadOnlyProjectionService` (operator-only standalone read-only SQLite
  snapshot reader, non-blocking `O_NOFOLLOW` state/DB/sidecar/marker validation, pre/post
  authority & session-generation fencing, per-event provenance verification, and hard-bounded
  response pagination).
- `test_projection.py` — deterministic offline qualification suite built on synthetic
  `CoordRegistry` + `CoordHub` fixtures (zero Podman, zero network, zero live credentials, zero
  writes to host production directories).

**Zero edits to shared files:** This slice reuses `oc_coord_contract.py`, `oc_registry.py`,
`oc_hub.py`, and `docs/prds/spikes/m/local/*` as merged on `main` (`e176712` / shared plan
`f1dcc79`). No shared contract change is required. If any shared helper becomes necessary later,
it will be proposed and cleared at Gate 1 before modifying any file outside
`docs/prds/spikes/m/projection/`.

### Explicit Non-Goals (Deferred to Later Slices / Other Owners)

- **Non-operator (`JOB` / `ORCHESTRATOR` / `EXTERNAL_PEER`) scoped reads:** Standalone SQLite
  cannot establish live in-memory `CoordHub` leases, target fences, grant-generation fences, or
  historical subtree ownership across reused addresses. Standalone `ReadOnlyProjectionService` is
  therefore **strictly `CoordRole.OPERATOR`-only** (`sandbox_addr is None, incarnation_id is None`).
  Any future sandbox-scoped or orchestrator-scoped read API requires a separate hub-owned Gate 1
  walkthrough that enforces live `CoordHub` lease, target-incarnation, and grant-generation
  authority at both admission and release.
- No SvelteKit frontend, HTTP/WebSocket daemon routes, or Tauri v2 bridge (`prd_m3a.md`, `prd_m3b.md`).
- No mutations, message sending, grant creation/revocation, or `InputLease` writes.
- No embedded PTY streaming, browser CDP screencasts, or containerized `safe_run` turn diffs.
- No live provider credentials, real subscriptions (`I3`/`I4`), SSH/Mac Mini onboarding (`I2`),
  warm worker seeding (`I5`), or local compiled profile proof (`docs/prds/spikes/l_m_profile/`).
- No changes to production `oc-sandbox`, `oc-bridge.py`, or any PRD `Human review` checkbox.

---

## 2. Trust Boundaries, Filesystem Admission, & Live-WAL Semantics

### 2.1 Verification-Only State Directory, Database, & Sidecar Admission

`ReadOnlyProjectionService` enforces verification-only filesystem checks **at least as strict as
`oc_registry.py`** — it **never creates directories or files, and never repairs modes via `chmod`
or `fchmod`**:

```python
_DB_ALL_FILES = ("", "-wal", "-shm", "-journal")

function verify_regular_private_file_nofollow(path, *, required: bool, label: str) -> None:
    # Always open non-blocking + no-follow so a pre-placed FIFO cannot hang before fstat()!
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if required:
            raise CoordPolicyError(f"{label}_missing")
        return
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise CoordPolicyError(f"{label}_symlink_rejected") from exc
        raise CoordPolicyError(f"{label}_unreadable") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CoordPolicyError(f"{label}_not_regular")
        if st.st_nlink != 1:
            raise CoordPolicyError(f"{label}_hardlink_rejected")
        if st.st_uid != os.geteuid():
            raise CoordPolicyError(f"{label}_wrong_owner")
        if (st.st_mode & 0o077) != 0:
            raise CoordPolicyError(f"{label}_unsafe_mode")
    finally:
        os.close(fd)

function verify_state_dir_and_db_readonly(state_dir, sandbox_root) -> tuple[Path, Path]:
    raw = Path(state_dir)
    if raw.is_symlink():
        raise CoordPolicyError("state_dir_symlink_rejected")
    assert_raw_no_user_symlink_ancestors(raw)          # mirrors oc_hub.py:375-388
    phys = check_not_in_sandbox(raw, sandbox_root)
    check_not_host_production_dir(raw)                 # mirrors oc_registry.py:398
    check_not_host_production_dir(phys)
    if phys.is_symlink() or not phys.exists():
        raise CoordPolicyError("state_dir_missing_or_symlink")
    trusted_dir = assert_trusted_dir(phys, sandbox_root=sandbox_root)  # requires 0o700, euid owner, no symlinks
    db_path = trusted_dir / "registry.sqlite"
    for idx, suffix in enumerate(_DB_ALL_FILES):
        verify_regular_private_file_nofollow(
            Path(f"{db_path}{suffix}"),
            required=(idx == 0),
            label="registry" if idx == 0 else f"registry_sidecar_{suffix.lstrip('-')}",
        )
    return trusted_dir, db_path
```

- **Strict parity with `oc_registry.py`:** Rejects raw symlinks, user-symlink ancestors,
  production host directories, missing state directories, non-`0o700` state directories, missing
  `registry.sqlite`, symlinks, FIFOs/sockets/devices, hardlinks (`st_nlink != 1`), non-effective-UID
  owners (`st_uid != os.geteuid()` — never accepts UID `0` unless running as UID `0`), any
  group/other permission bits (`(st_mode & 0o077) != 0`, rejecting `0o644`/`0o640` without
  repairing them), and verifies all 4 database files (`registry.sqlite`, `-wal`, `-shm`,
  `-journal`).

### 2.2 Live-WAL SQLite Opening, Unified Deadline, & Connection Ownership

`open_readonly_snapshot()` is a `@contextlib.contextmanager` that **owns the `sqlite3.Connection`
from creation through unconditional `ROLLBACK` + `conn.close()` in `finally:`** (including when
`PRAGMA`, `BEGIN DEFERRED`, or the initial anchor `SELECT` fails — zero FD leaks!). Every read
call computes a single monotonic deadline `deadline = time.monotonic() + (max_read_ms / 1000.0)`
and passes it to the connection, lock waits, VM progress handler, inter-query checks, and result
assembly:

```python
@contextlib.contextmanager
function open_readonly_snapshot(db_path, *, deadline: float) -> Iterator[sqlite3.Connection]:
    remaining_ms = check_deadline_ms(deadline)  # raises CoordPolicyError("read_deadline_exceeded") if <= 0
    uri = f"file:{quote(str(db_path), safe='/')}?mode=ro"
    conn = None
    with _UMASK_LOCK:
        old_umask = os.umask(0o077)
        try:
            conn = sqlite3.connect(
                uri,
                uri=True,
                isolation_level=None,
                timeout=max(0.001, remaining_ms / 1000.0),
                check_same_thread=False,
            )
            conn.row_factory = dict_row_factory
            conn.execute("PRAGMA query_only = ON")
            conn.execute("PRAGMA temp_store = MEMORY")
            apply_remaining_busy_timeout(conn, deadline)   # PRAGMA busy_timeout = max(1, remaining_ms)
            install_progress_deadline(conn, deadline)      # aborts VM when time.monotonic() >= deadline
            conn.execute("BEGIN DEFERRED")
            # Immediately anchor the WAL read snapshot on seq_counter inside this transaction!
            conn.execute("SELECT last_seq FROM seq_counter WHERE id = 1").fetchone()
        except sqlite3.OperationalError as exc:
            if conn is not None:
                safe_close(conn)
            raise map_sqlite_operational_error(exc, deadline) from exc
        except sqlite3.DatabaseError as exc:
            if conn is not None:
                safe_close(conn)
            raise CoordPolicyError("registry_unreadable") from exc
        except BaseException:
            if conn is not None:
                safe_close(conn)
            raise
        finally:
            os.umask(old_umask)

    try:
        yield conn
    except sqlite3.OperationalError as exc:
        raise map_sqlite_operational_error(exc, deadline) from exc
    except sqlite3.DatabaseError as exc:
        raise CoordPolicyError("registry_unreadable") from exc
    finally:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        finally:
            conn.close()
```

- **Explicit Live-WAL Guarantee (No Overclaimed Zero-Sidecar Filesystem Immutability):**
  - `mode=ro` + `PRAGMA query_only = ON` guarantees **strict logical immutability**: SQLite
    refuses to create a missing `registry.sqlite` and rejects every SQL write (`INSERT`, `UPDATE`,
    `DELETE`, DDL, `VACUUM`, `PRAGMA` mutations). All logical tables, `seq_counter`, and the
    hash-chained `audit_log` remain completely unchanged by projection reads.
  - Because `immutable=0` is used to read live WAL snapshots from a concurrent `CoordHub` writer,
    SQLite may create or update WAL shared-memory coordination sidecars (`registry.sqlite-shm`,
    `registry.sqlite-wal`) in a writable `0o700` `$STATE` directory (confined to `0o600` via
    `_UMASK_LOCK` + `umask(0o077)`). If `$STATE` is read-only (`0o500`) without a pre-existing
    `-shm` file, SQLite raises `OperationalError`, which is mapped fail-closed to
    `CoordPolicyError("registry_unreadable")`.
  - Post-`O_NOFOLLOW` URI opening relies on `$STATE`'s verified owner-only `0o700` confinement.
  - If strict zero-sidecar filesystem immutability is ever required (e.g., against an immutable
    archive), that belongs to a separate host-produced sealed snapshot copy opened with
    `immutable=1`.
- **Single Monotonic Deadline & Error Mapping:**
  - `deadline = time.monotonic() + (max_read_ms / 1000.0)` (`50 <= max_read_ms <= 10_000`, default
    `2000`) governs the entire read operation: before every SQL query, `apply_remaining_busy_timeout()`
    updates `PRAGMA busy_timeout = max(1, remaining_ms)` so a 50 ms caller budget never waits
    2,000 ms on a locked database; `conn.set_progress_handler(deadline_cb, 1000)` interrupts
    long SQLite VM executions; and `check_deadline_ms(deadline)` runs between queries and during
    Python result assembly.
  - Error mapping: `sqlite3.OperationalError` with `"interrupted"` or `time.monotonic() >= deadline`
    -> `CoordPolicyError("read_deadline_exceeded")`; `"locked"`/`"busy"` before deadline ->
    `CoordPolicyError("registry_busy")`; other `sqlite3.OperationalError` or corrupt
    `sqlite3.DatabaseError` -> `CoordPolicyError("registry_unreadable")`.
  - Because exact unconfirmed-binding counts and per-sandbox grant/outbox aggregates query tables
    without secondary indexes in the current schema, the guarantee is **bounded output and bounded
    work enforced by the single monotonic `max_read_ms` deadline** (not an unsupported zero-scan
    claim).

### 2.3 State-Dir Health Markers, Observed-Only Standalone Status, & Orphaned Bindings

The standalone reader **never acquires `flock` on `.coord_hub.lock`** (so a diagnostic reader can
never interfere with a concurrently starting `CoordHub`'s non-blocking `LOCK_EX`, nor misread a
restarted degraded hub holding the lock as healthy). Instead, `WorkspaceHealth` reports observed
markers explicitly alongside a 3-state `health_status`: `"healthy" | "degraded" | "unknown"`:

1. **Non-blocking `O_NOFOLLOW` marker reads (`.coord_degraded`, `.coord_session_active`):**
   - Both files are read via `os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)`, verifying
     `S_ISREG`, `st_nlink == 1`, `st_uid == os.geteuid()`, `(st_mode & 0o077) == 0`, reading at most
     `256` bytes.
   - Any open/stat failure other than `FileNotFoundError` (including FIFO, symlink `ELOOP`,
     hardlink, wrong owner, unsafe mode `0o644`) sets `marker_unreadable = True`,
     `health_status = "degraded"`, `degraded = True`, and adds `"marker_unreadable"`.
   - Record `degraded_marker_present: bool` (with sanitized reason capped to `256` bytes) and
     `session_active_marker_present: bool` as observed filesystem evidence.
2. **Optional trusted live hub callback (`live_degraded_checker: Callable[[], bool] | None`):**
   - When configured (e.g., in-process `CoordHub` wiring):
     - If `live_degraded_checker()` returns `False` AND no degraded/unreadable marker AND zero
       unconfirmed bindings -> `health_status = "healthy"`, `degraded = False`,
       `live_status_available = True`.
     - If `live_degraded_checker()` returns anything other than `False` (including `True`) or
       raises -> `health_status = "degraded"`, `degraded = True`, add `"live_hub_degraded"`.
   - When **not** configured (standalone offline reader):
     - `live_status_available = False`.
     - If `degraded_marker_present` OR `marker_unreadable` OR `has_unconfirmed_bindings` ->
       `health_status = "degraded"`, `degraded = True`.
     - Otherwise -> `health_status = "unknown"`, `degraded = False` (reporting
       `session_active_marker_present` explicitly without overstating `"healthy"` when a crashed
       or restarted hub's in-memory state is unknown!).
3. **Orphaned & unconfirmed `external_transport_bindings` (`LEFT JOIN`, inside SQLite snapshot):**
   ```sql
   SELECT b.sandbox_addr, b.incarnation_id, b.abort_requested, b.terminal_confirmed,
          SUBSTR(CAST(b.reason AS TEXT), 1, 1024) AS reason_preview,
          LENGTH(CAST(b.reason AS BLOB)) AS reason_bytes,
          b.updated_at, s.status AS sandbox_status, s.incarnation_id AS current_incarnation
   FROM external_transport_bindings b
   LEFT JOIN sandboxes s ON s.sandbox_addr = b.sandbox_addr
   WHERE b.terminal_confirmed = 0
     AND (b.abort_requested != 0
          OR s.sandbox_addr IS NULL
          OR s.status = 'revoked'
          OR s.incarnation_id != b.incarnation_id)
   ORDER BY b.sandbox_addr ASC, b.incarnation_id ASC
   LIMIT ?
   ```
   - Using `LEFT JOIN` ensures orphaned bindings whose `sandboxes` row is missing are **never**
     dropped (matching `oc_hub.py:1336-1338`).
   - Also execute `SELECT COUNT(*) ...` with the exact same `WHERE` clause so
     `unconfirmed_bindings_count` is exact even when the summary list is capped at
     `MAX_UNCONFIRMED_BINDINGS_SUMMARY = 50`.
   - Raw `owner_id` and `token_sha256` are **never** exposed in any projection response.

---

## 3. Caller Read Authority & Session-Generation Fencing

### 3.1 Strict Operator-Only Admission

Every public read method checks `caller` **before touching the filesystem or SQLite**:

```python
function authorize_operator_caller(caller) -> PrincipalCtx:
    if not isinstance(caller, PrincipalCtx):
        raise CoordValidationError("caller must be PrincipalCtx")
    if caller.role is not CoordRole.OPERATOR:
        raise CoordAuthError("operator_role_required")
    if caller.sandbox_addr is not None or caller.incarnation_id is not None:
        raise CoordAuthError("operator_principal_must_not_bind_sandbox")
    return caller
```

- `CoordRole.JOB`, `CoordRole.ORCHESTRATOR` (both root and sandbox-bound), and
  `CoordRole.EXTERNAL_PEER` are unconditionally denied (`CoordAuthError("operator_role_required")`)
  before any DB open or sandbox lookup, eliminating any sandbox-existence oracle, stale-grant race,
  or address-reuse history leak in the standalone reader.

### 3.2 Mandatory Pre-Read and Post-Read Session & Live-Authority Fencing

`ReadOnlyProjectionService` supports two optional host-side authority callbacks:

- `session_validator: Callable[[PrincipalCtx, str, int], bool] | None = None`
- `live_authority_checker: Callable[[PrincipalCtx], bool] | None = None`

Exact fail-closed rules:

1. **Session argument pairing & mandatory enforcement:**
   - Passing only one of `(read_session_id, session_generation)` raises
     `CoordValidationError("read_session_pair_required")`.
   - When `read_session_id` and `session_generation` are supplied:
     - Validate `read_session_id` via `validate_opaque_token(read_session_id, "read_session_id")`.
     - Validate `type(session_generation) is int and session_generation >= 1` (rejects `bool`,
       `<= 0`, floats).
     - If `session_validator is None`: raise `CoordPolicyError("read_session_validator_unconfigured")`.
   - When `session_validator is not None`:
     - Omitting `(read_session_id, session_generation)` raises
       `CoordAuthError("read_session_required")` (no silent bypass!).
     - Call `session_validator(caller, read_session_id, session_generation)` **both before** opening
       SQLite **and after** completing the snapshot **before returning** the response.
     - Require strict `result is True` (not truthy objects); any non-`True` return or raised
       exception raises `RevokedError("read_session_retired")` and returns zero data!
2. **Live authority check (`live_authority_checker`):**
   - When configured, call `live_authority_checker(caller)` **both before** opening SQLite **and
     after** completing the snapshot **before returning**. Require strict `result is True`; any
     non-`True` return or raised exception raises `RevokedError("read_authority_revoked")` (fencing
     a paused read if the host daemon shuts down or operator authority is revoked while a UI
     session token is still valid!).
3. **Echo validated session coordinates:** When a read session is validated, echo
   `(read_session_id, session_generation)` on the returned snapshot envelope so M3a/M3b UI clients
   can discard late responses belonging to a retired session generation.

---

## 4. Collision-Free, Context-Bound Cursors & Hard Response-Byte Caps

### 4.1 Hard Bounds (`oc_projection_contract.py`)

```python
PROJECTION_SCHEMA_VERSION = "oc.m3.readonly_projection@1"
MAX_SANDBOXES_PER_PAGE = 50
MAX_PROJECTS_PER_PAGE = 50             # bounded by MAX_SANDBOXES_PER_PAGE (<= 1 project per sandbox)
MAX_THREADS_PER_SANDBOX = 50
MAX_EDGES_PER_SANDBOX = 100
MAX_PAGE_LIMIT = 200
DEFAULT_PAGE_LIMIT = 50
MIN_RESPONSE_BYTES = 1024
MAX_RESPONSE_BYTES = 256 * 1024        # 256 KiB hard ceiling on complete UTF-8 JSON serialization
MAX_ITEM_TEXT_BYTES = 16 * 1024        # 16 KiB per-item text cap before further budget shrinking
MAX_METADATA_TEXT_BYTES = 256
SQL_MAX_CELL_BYTES = 65_536            # Max JSON/metadata cell bytes decoded; larger cells -> malformed_metadata
MAX_JSON_DEPTH = 8
MAX_CURSOR_BYTES = 512
MAX_UNCONFIRMED_BINDINGS_SUMMARY = 50
DEFAULT_MAX_READ_MS = 2000
MAX_READ_MS = 10_000
```

All `limit`, `max_*`, `max_response_bytes`, and `max_read_ms` inputs reject `bool`, non-`int`,
out-of-range values with `CoordValidationError`.

### 4.2 Collision-Free Canonical Cursor Codec

Because `_ID_TOKEN_RE` permits `:` in `incarnation_id` and `msg_id`, and `project_id` accepts
arbitrary non-control Unicode strings of unbounded length, **`:`-delimited cursors are NOT used**.

Every cursor uses canonical base64url-encoded JSON:

```text
cursor = "v1." + base64url_nopad(json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True).encode("utf-8"))
```

- **Strict validation on decode:**
  - Must be `str`, `len(cursor.encode("utf-8")) <= MAX_CURSOR_BYTES`, ASCII-only, starting with `"v1."`.
  - Decode base64url (strict alphabet, no padding), parse JSON object, verify exact expected keys
    and value types, and verify **canonical re-encoding equals the exact input string** (rejecting
    malleable base64 padding, extra whitespace, or unknown fields) -> else `CoordValidationError`.
- **Operation & filter scope binding (`"op"` + `"fh"`):**
  - Every cursor embeds `"op"` (`"tree" | "events" | "mailbox"`) and `"fh"` (16-hex-char SHA-256
    prefix of the canonicalized query parameters: operation, target, thread_id, incarnation_id,
    `include_revoked`, `include_historical_incarnations`, `statuses`).
  - Reusing a cursor under a different operation, target, thread, incarnation, or filter raises
    `CoordValidationError("cursor_scope_mismatch")`.
- **Exact keyset shapes (every key strictly bounded so a valid row NEVER emits an unparseable cursor!):**
  1. **`get_workspace_tree`:** Paginates sandboxes deterministically by **`sandbox_addr ASC`**
     (`PRIMARY KEY`, strictly `<= 63` ASCII chars via `parse_local_target`), grouping each page's
     sandboxes by **raw `project_id`** BEFORE truncating the emitted `project_id` display field
     (preventing accidental merge of two distinct >256-byte `project_id`s sharing a prefix;
     within-page groups sorted by `(project_id_sort_key ASC, sandbox_addr ASC)`, with clients
     merging multi-page projects by `project_id_sha256` / `project_id`).
     - Cursor payload: `{"op": "tree", "fh": "<16-hex>", "addr": "<sandbox_addr>"}` — always
       `< 160` bytes regardless of how long `project_id` is!
     - **SQL-bounded `project_id` fetch (`MAX_PROJECT_ID_HASH_BYTES = 4096`):** Fetch
       `LENGTH(CAST(project_id AS BLOB)) AS project_id_bytes` and
       `CASE WHEN LENGTH(CAST(project_id AS BLOB)) <= 4096 THEN project_id ELSE SUBSTR(CAST(project_id AS TEXT), 1, 256) END AS project_id_raw`.
       - When `project_id_bytes <= 4096` (covers every normal and 2 KiB long `project_id`): group
         by exact `project_id_raw`, emit exact `project_id_sha256`, and truncate displayed
         `project_id` to `MAX_METADATA_TEXT_BYTES` (`project_id_truncated = True` if shortened).
       - When `project_id_bytes > 4096`: SQL never materializes the multi-MB cell into Python;
         mark `malformed_metadata = True`, `project_id_truncated = True`, `project_id_sha256 = None`,
         and isolate that sandbox in its own group keyed by `("oversize", sandbox_addr)` so
         oversized `project_id`s can never merge with another project!
  2. **`get_thread_events`:** Total order `(seq ASC, source_rank ASC)` where `source_rank = 0` for
     `event_log` and `1` for `stream_events` (`seq` is unique per table via `INTEGER PRIMARY KEY`).
     - Cursor payload: `{"op": "events", "fh": "<16-hex>", "seq": int, "rank": 0|1, "inc": "<incarnation_id>"}`.
     - **Exact SQL boundary (zero skipped same-`seq` stream rows):**
       - When `cursor.rank == 0`: `event_log` queries `seq > cursor.seq`; `stream_events` queries
         **`seq >= cursor.seq`**!
       - When `cursor.rank == 1`: BOTH `event_log` and `stream_events` query `seq > cursor.seq`.
  3. **`get_sandbox_mailbox`:** Total order `(o.seq ASC, o.msg_id ASC)`.
     - Cursor payload: `{"op": "mailbox", "fh": "<16-hex>", "seq": int, "mid": "<msg_id>"}`.
     - SQL boundary: `(o.seq > ?) OR (o.seq = ? AND o.msg_id > ?)`.
- **Concurrent-change cursor semantics:** Each page runs inside its own single-transaction
  `BEGIN DEFERRED` read snapshot (`snapshot_seq`). Within a page, all counts, bindings, edges,
  and rows are strictly consistent. Across pages, concurrent writers produce a forward-moving
  keyset view (`snapshot_seq` may advance; callers wanting a fresh point-in-time resync when
  `snapshot_seq` or `applied_incarnation_id` rotates restart from `cursor=None`).

### 4.3 Hard End-to-End Serialized Response-Byte Enforcement (All 4 APIs)

All 4 APIs serialize strictly via `json.dumps(obj.to_dict(), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")` and **guarantee `len(serialized_utf8) <= max_response_bytes`** (including all JSON escaping such as `\"`, `\\`, `\n`, `\u0000` and full envelope overhead!):

1. **Paginated responses (`get_thread_events`, `get_sandbox_mailbox`, `get_workspace_tree`):**
   - `get_thread_events` and `get_sandbox_mailbox` carry a compact `WorkspaceHealthSummary`
     (`health_status`, `degraded`, `session_active_marker_present`, `live_status_available`,
     `has_unconfirmed_bindings`, `unconfirmed_bindings_count` — fixed compact footprint) so a
     50-item unconfirmed binding list never crowds out 1 KiB pages.
   - `get_workspace_tree` and `get_sandbox_status` carry `WorkspaceHealth` with bounded
     `unconfirmed_bindings` (shrunk / truncated with `unconfirmed_bindings_truncated = True` if
     needed to fit `max_response_bytes`).
   - Measure the exact serialized envelope size with empty item list + worst-case `next_cursor`
     length first; if the empty envelope alone exceeds `max_response_bytes`, raise
     `CoordValidationError("response_budget_too_small_for_envelope")`.
   - Add projected items one by one, checking the **actual serialized JSON UTF-8 byte length** of
     the assembled response (or incremental exact serialized item bytes + separator + updated
     `next_cursor`):
     - **First-item rule (`get_thread_events`, `get_sandbox_mailbox`):** If the first item alone
       exceeds the remaining byte budget (e.g., 1 KiB budget with escape-heavy text), shrink its
       `text` / `detail` via binary search on character length (UTF-8 & JSON-escape exact!) so the
       **complete serialized response** fits `<= max_response_bytes` with `text_truncated = True`.
       If even an empty-text first item cannot fit, raise
       `CoordValidationError("response_budget_too_small_for_item")` rather than violating the cap!
     - **First-item rule (`get_workspace_tree`):** If the first sandbox with its threads exceeds
       remaining budget, reduce its inline `threads[]` (setting `threads_truncated = True`, down to
       `0` threads if needed); if even a zero-thread sandbox cannot fit, raise
       `CoordValidationError("response_budget_too_small_for_item")`.
     - **Subsequent items:** Stop before exceeding `max_response_bytes`, set `has_more = True`,
       and emit `next_cursor` for the last admitted item.
2. **Non-paginated status (`get_sandbox_status`):**
   - Enforces `max_response_bytes` (default `MAX_RESPONSE_BYTES`), progressively capping `edges[]`
     (`edges_truncated = True`) and `health.unconfirmed_bindings[]`
     (`unconfirmed_bindings_truncated = True`) if needed, and raising
     `CoordValidationError("response_budget_too_small_for_envelope")` if even the minimal status
     envelope cannot fit.
3. **SQL-level byte-length gates on EVERY variable-width column BEFORE materializing into Python:**
   - Every variable-width SQLite column is byte-gated **inside SQL** using
     `LENGTH(CAST(col AS BLOB))` before returning values to Python (preventing multi-MB allocation
     from tampered or oversized cells!):
     - **JSON columns (`detail_json`, `artifact_refs_json`, `allowed_threads_json`,
       `allowed_msg_kinds_json`, `budget_json`):**
       `CASE WHEN LENGTH(CAST(col AS BLOB)) <= 65536 THEN col ELSE NULL END AS col, LENGTH(CAST(col AS BLOB)) AS col_bytes`.
       Cells `> SQL_MAX_CELL_BYTES (65,536)` are never returned to Python and immediately produce
       `malformed_metadata = True` with safe empty fallback (`{}` / `()`).
     - **Single-line display metadata (`project_name`, `branch`, `task_brief`, `title`, `detail`,
       `reason`):** Fetch `SUBSTR(CAST(col AS TEXT), 1, 1024)` + `LENGTH(CAST(col AS BLOB)) AS col_bytes`
       (never allocating more than ~4 KiB per metadata cell in Python) before control/bidi
       scrubbing and `MAX_METADATA_TEXT_BYTES` UTF-8 truncation.
     - **Event `body_text` / `text`:**
       - For `event_log.body_text` and non-host-badged `stream_events.text`: fetch
         `SUBSTR(CAST(col AS TEXT), 1, 16384) AS text_preview` +
         `LENGTH(CAST(col AS BLOB)) AS original_text_bytes` (so Python never allocates beyond
         `MAX_ITEM_TEXT_BYTES` characters!).
       - For `stream_events.text` on candidate host-badged `user_message` rows
         (`badge IN ('Operator', 'Orchestrator -o', 'Peer')`): fetch
         `CASE WHEN LENGTH(CAST(text AS BLOB)) <= 69632 THEN text ELSE NULL END AS text_for_hash`,
         `SUBSTR(CAST(text AS TEXT), 1, 16384) AS text_preview`, and
         `LENGTH(CAST(text AS BLOB)) AS original_text_bytes`. Any cell `> 69,632` bytes
         (`MAX_FRAMED_BODY_BYTES`) cannot match a valid `dispatch_receipts` hash, so SQL returns
         `text_for_hash = NULL` and provenance downgrades immediately with
         `"receipt_body_hash_mismatch"` without allocating megabytes!

---

## 5. Pseudocode Walkthrough of the Four Operator Read APIs

### 5.1 `get_workspace_tree`

```python
function get_workspace_tree(
    caller,
    *,
    include_revoked=True,
    include_historical_incarnations=False,
    after_cursor=None,
    sandbox_limit=MAX_SANDBOXES_PER_PAGE,
    max_threads_per_sandbox=MAX_THREADS_PER_SANDBOX,
    max_response_bytes=MAX_RESPONSE_BYTES,
    max_read_ms=DEFAULT_MAX_READ_MS,
    read_session_id=None,
    session_generation=None,
) -> WorkspaceTreeSnapshot:
    authorize_operator_caller(caller)
    validate_bounds(sandbox_limit, max_threads_per_sandbox, max_response_bytes, max_read_ms)
    scope_hash = compute_scope_hash("tree", include_revoked=include_revoked, include_historical=include_historical_incarnations)
    parsed_cursor = decode_tree_cursor(after_cursor, expected_scope_hash=scope_hash)
    check_authority_and_session_pre(caller, read_session_id, session_generation)
    trusted_dir, db_path = verify_state_dir_and_db_readonly(state_dir, sandbox_root)
    marker_health = read_state_dir_health_nofollow(trusted_dir, live_degraded_checker)

    deadline = time.monotonic() + (max_read_ms / 1000.0)
    with open_readonly_snapshot(db_path, deadline=deadline) as conn:
        snapshot_seq = read_seq_counter(conn)
        health = build_full_workspace_health(conn, marker_health)
        # Fetch sandbox_limit + 1 ordered by sandbox_addr ASC after parsed_cursor.addr
        # (filtering status != 'revoked' when include_revoked is False)
        sb_rows = select_sandboxes_page(conn, include_revoked=include_revoked, after_addr=parsed_cursor, limit=sandbox_limit + 1)
        # For ONLY those fetched sandboxes (<= 51 rows, checking deadline between queries):
        #   - Fetch bounded threads (current incarnation only unless include_historical_incarnations=True)
        #   - Compute historical_thread_count per sandbox
        #   - Compute active vs revoked/tombstoned grant counts (checking both dst_addr and src_actor/orchestrator:<addr>)
        #   - Compute outbox status counts grouped by status
        #   - Compute external_transport_bindings state ("none"|"active"|"abort_requested"|"terminal_confirmed")
        #   - Enforce max_response_bytes and deadline, grouping admitted sandboxes by raw project_id before display truncation
        snapshot = build_bounded_workspace_tree(snapshot_seq, health, sb_rows, ...)

    check_authority_and_session_post(caller, read_session_id, session_generation)
    return snapshot
```

### 5.2 `get_sandbox_status`

```python
function get_sandbox_status(
    caller,
    *,
    target,
    max_response_bytes=MAX_RESPONSE_BYTES,
    max_read_ms=DEFAULT_MAX_READ_MS,
    read_session_id=None,
    session_generation=None,
) -> SandboxStatusSnapshot:
    authorize_operator_caller(caller)
    addr = parse_local_target(target).canonical
    validate_bounds(max_response_bytes=max_response_bytes, max_read_ms=max_read_ms)
    check_authority_and_session_pre(caller, read_session_id, session_generation)
    trusted_dir, db_path = verify_state_dir_and_db_readonly(state_dir, sandbox_root)
    marker_health = read_state_dir_health_nofollow(trusted_dir, live_degraded_checker)

    deadline = time.monotonic() + (max_read_ms / 1000.0)
    with open_readonly_snapshot(db_path, deadline=deadline) as conn:
        snapshot_seq = read_seq_counter(conn)
        health = build_full_workspace_health(conn, marker_health)
        sb = select_sandbox(conn, addr)
        if sb is None:
            raise CoordPolicyError("sandbox_not_found")
        # Edges matching dst_addr = addr OR src_actor = addr OR src_actor = 'orchestrator:' || addr
        edges = select_edges_for_sandbox(conn, addr, limit=MAX_EDGES_PER_SANDBOX + 1)
        tombstones = select_tombstones_for_edges(conn, edges)
        outbox_counts = select_outbox_counts(conn, addr)
        binding_summary = select_binding_summary(conn, addr, sb["incarnation_id"])  # omits owner_id
        budget, budget_malformed = select_sandbox_budget_safe(conn, addr, sb["incarnation_id"])
        snapshot = build_bounded_sandbox_status(snapshot_seq, health, sb, edges, tombstones, outbox_counts, binding_summary, budget, ...)

    check_authority_and_session_post(caller, read_session_id, session_generation)
    return snapshot
```

### 5.3 `get_thread_events`

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
    max_read_ms=DEFAULT_MAX_READ_MS,
    read_session_id=None,
    session_generation=None,
) -> ThreadEventsPage:
    authorize_operator_caller(caller)
    addr = parse_local_target(target).canonical
    clean_thread = validate_thread_id(thread_id)
    explicit_inc = validate_opaque_token(incarnation_id, "incarnation_id") if incarnation_id is not None else None
    validate_bounds(limit=limit, max_response_bytes=max_response_bytes, max_read_ms=max_read_ms)
    check_authority_and_session_pre(caller, read_session_id, session_generation)
    trusted_dir, db_path = verify_state_dir_and_db_readonly(state_dir, sandbox_root)
    marker_health = read_state_dir_health_nofollow(trusted_dir, live_degraded_checker)

    deadline = time.monotonic() + (max_read_ms / 1000.0)
    with open_readonly_snapshot(db_path, deadline=deadline) as conn:
        snapshot_seq = read_seq_counter(conn)
        health_summary = build_compact_workspace_health(conn, marker_health)
        sb = select_sandbox(conn, addr)
        if sb is None:
            raise CoordPolicyError("sandbox_not_found")
        target_inc = explicit_inc if explicit_inc is not None else sb["incarnation_id"]
        is_current_inc = (target_inc == sb["incarnation_id"])
        stale_reason = None if is_current_inc else "superseded_incarnation"
        scope_hash = compute_scope_hash("events", target=addr, thread_id=clean_thread, incarnation_id=target_inc)
        parsed_cursor = decode_events_cursor(after_cursor, expected_scope_hash=scope_hash, expected_inc=target_inc)

        thread_exists = check_thread_row_exists(conn, addr, target_inc, clean_thread)
        # Cursor-aware fetch (limit + 1 from each table; when cursor.rank == 0, stream_events uses seq >= cursor.seq!)
        ev_rows = select_thread_event_log_rows(conn, addr, target_inc, clean_thread, parsed_cursor, limit=limit + 1)
        st_rows = select_thread_stream_rows(conn, addr, target_inc, clean_thread, parsed_cursor, limit=limit + 1)
        merged = merge_sorted_by_seq_and_rank(ev_rows, st_rows)

        # Provenance-verify every stream_events row (Section 6) and pack strictly within limit & max_response_bytes!
        # Authorized query on a non-existent thread_id of an existing sandbox returns empty page (thread_exists=False).
        page = build_bounded_events_page(conn, sb, target_inc, is_current_inc, stale_reason, thread_exists, merged, ...)

    check_authority_and_session_post(caller, read_session_id, session_generation)
    return page
```

### 5.4 `get_sandbox_mailbox`

```python
function get_sandbox_mailbox(
    caller,
    *,
    target,
    statuses=None,
    after_cursor=None,
    limit=DEFAULT_PAGE_LIMIT,
    max_response_bytes=MAX_RESPONSE_BYTES,
    max_read_ms=DEFAULT_MAX_READ_MS,
    read_session_id=None,
    session_generation=None,
) -> MailboxPage:
    authorize_operator_caller(caller)
    addr = parse_local_target(target).canonical
    clean_statuses = validate_outbox_statuses(statuses)
    validate_bounds(limit=limit, max_response_bytes=max_response_bytes, max_read_ms=max_read_ms)
    scope_hash = compute_scope_hash("mailbox", target=addr, statuses=clean_statuses)
    parsed_cursor = decode_mailbox_cursor(after_cursor, expected_scope_hash=scope_hash)
    check_authority_and_session_pre(caller, read_session_id, session_generation)
    trusted_dir, db_path = verify_state_dir_and_db_readonly(state_dir, sandbox_root)
    marker_health = read_state_dir_health_nofollow(trusted_dir, live_degraded_checker)

    deadline = time.monotonic() + (max_read_ms / 1000.0)
    with open_readonly_snapshot(db_path, deadline=deadline) as conn:
        snapshot_seq = read_seq_counter(conn)
        health_summary = build_compact_workspace_health(conn, marker_health)
        sb = select_sandbox(conn, addr)
        if sb is None:
            raise CoordPolicyError("sandbox_not_found")
        # Join outbox o + event_log e + routing_edges r + grant_tombstones (checking BOTH (o.edge_id, o.grant_generation)
        # and (o.edge_id, r.grant_generation)) + source sandbox status/incarnation!
        rows = select_mailbox_rows(conn, addr, clean_statuses, parsed_cursor, limit=limit + 1)
        page = build_bounded_mailbox_page(sb, rows, limit=limit, max_response_bytes=max_response_bytes, ...)

    check_authority_and_session_post(caller, read_session_id, session_generation)
    return page
```

---

## 6. Strict Per-Event Provenance Re-Verification & Inert Content Boundary

Inside the same read-only SQLite snapshot, every `stream_events` row is re-verified against
`event_log`, `dispatch_receipts`, and `tui_enter_tokens` — never trusting raw `stream_events.badge`:

1. **Non-`user_message` events** (`text_delta`, `reasoning_delta`, `tool_call`, `file_edit`,
   `turn_completed`, `turn_error`, `revoked`):
   - `effective_badge = None`, `authority_rank = 0`, `untrusted_content = True`.
   - If `row["badge"] is not None`: set `provenance_anomaly = True`,
     `anomaly_reason = "non_user_event_has_badge"`, and force `effective_badge = None`.
2. **`user_message` events:**
   - If `row["badge"]` is missing or not a valid `ProvenanceBadge` value: downgrade to
     `ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED`, `authority_rank = 0`, `untrusted_content = True`,
     `provenance_anomaly = True`, `anomaly_reason = "invalid_or_missing_badge"`.
   - **`SANDBOX_LOCAL_UNVERIFIED`:** keep as `SANDBOX_LOCAL_UNVERIFIED`, `authority_rank = 0`,
     `untrusted_content = True`.
   - **`TUI_INPUT` (unconditionally downgraded on today's schema):**
     - `tui_enter_tokens` records `(sandbox_addr, incarnation_id, surface_kind, expires_at,
       consumed_at)` with **no** `thread_id`, `message_id`, or `stream_events.seq`, and
       `oc_registry.py` stamps `consumed_at = now` on unused tokens during revocation/rotation.
     - Therefore, even equal token/event counts cannot establish which specific event consumed a
       token (an unrelated event could fill the count).
     - On today's schema, **every** `user_message` row carrying `TUI_INPUT` is **always downgraded**
       to `effective_badge = ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED`, `authority_rank = 0`,
       `untrusted_content = True`, `provenance_anomaly = True`,
       `anomaly_reason = "tui_unverifiable_without_event_link"`. Per-event verified `TUI_INPUT`
       attribution is deferred to a later coordinated writer/schema slice.
   - **Verified host-originated badges (`OPERATOR`, `ORCHESTRATOR`, `PEER`):**
     - **Strict `message_id` requirement (`dispatch_msg_id` NEVER substitutes!):** Require
       `isinstance(row["message_id"], str) and bool(row["message_id"])`.
     - **Cross-page host-badge ambiguity check (full thread in SQLite, immune to worker SSE replay):**
       Query strictly rows claiming a verified host badge:
       ```sql
       SELECT COUNT(*) FROM stream_events
       WHERE sandbox_addr = ? AND incarnation_id = ? AND thread_id = ?
         AND event_type = 'user_message' AND message_id = ?
         AND badge IN ('Operator', 'Orchestrator -o', 'Peer')
       ```
       Filtering by `badge IN ('Operator', 'Orchestrator -o', 'Peer')` guarantees that a
       compromised worker replaying a known `message_id` over SSE (which `oc_registry.py` stores
       as `badge = 'Sandbox-Local / Unverified'`) **cannot** retroactively strip provenance from
       the genuine `[Operator]` row, while DB tampering duplicating a host-badged row
       (`candidate_count != 1`, same page or across page boundaries) downgrades **all** claiming
       rows to `SANDBOX_LOCAL_UNVERIFIED` (`authority_rank = 0`, `verified_actor = None`,
       `untrusted_content = True`, `provenance_anomaly = True`,
       `anomaly_reason = "ambiguous_receipt_match"`).
     - **Exact 5-tuple receipt + envelope match (unique consumed receipt on 4-tuple):** Require BOTH:
       - `event_log` row matching exact `(msg_id = row.message_id, dst_addr = row.sandbox_addr, dst_incarnation = row.incarnation_id, dst_thread_id = row.thread_id)`, AND
       - `dispatch_receipts` rows for `(sandbox_addr, incarnation_id, session_id = row.thread_id, message_id = row.message_id)` with `consumed_at IS NOT NULL` (`LIMIT 2`) having **`len(receipts) == 1`** (so tampered multi-receipt rows never depend on arbitrary `fetchone()` order -> `len != 1` downgrades with `"ambiguous_receipt_match"`).
     - Verify ALL of:
       1. `receipt.badge == raw_badge` AND `_TRUST_CLASS_TO_BADGE[TrustClass(receipt.trust_class)].value == raw_badge`,
       2. `receipt.trust_class == event_log.trust_class` AND `receipt.src_actor == event_log.src_actor` AND `receipt.body_sha256 == event_log.body_sha256`,
       3. `text_for_hash is not None` (SQL verified `LENGTH(CAST(text AS BLOB)) <= 69632`) AND
          `sha256_canonical_body(text_for_hash) == receipt.body_sha256`, wrapping
          `sha256_canonical_body` in `try ... except (CoordValidationError, TypeError, ValueError):`
          so NUL, surrogate, or non-string tampered cells NEVER crash reads and cleanly downgrade
          with `anomaly_reason = "receipt_body_hash_mismatch"`.
     - On any failure -> downgrade to `SANDBOX_LOCAL_UNVERIFIED`, `authority_rank = 0`,
       `verified_actor = None`, `untrusted_content = True`, `provenance_anomaly = True`, closed-enum
       `anomaly_reason` (`"unbacked_host_badge"`, `"trust_class_mismatch"`,
       `"receipt_envelope_mismatch"`, or `"receipt_body_hash_mismatch"`).
     - On full verification -> preserve `effective_badge`, set `verified_actor = receipt.src_actor`,
       `authority_rank` (`3` for `OPERATOR`, `2` for `ORCHESTRATOR`, `1` for `PEER`), and
       `untrusted_content = (effective_badge not in (OPERATOR, ORCHESTRATOR))`.
3. **Inert Content, Multiline Unicode, `ArtifactRef`, & Strict JSON Safety:**
   - **`untrusted_content` exact rule:** Default `True` for all projected events EXCEPT `event_log`
     rows with `trust_class in (OPERATOR_DIRECTIVE, PARENT_TASK)` and provenance-verified
     `stream_events` `user_message` rows with `effective_badge in (OPERATOR, ORCHESTRATOR)`
     (explicitly `True` for `SYSTEM_ALERT`, `UNTRUSTED_PEER_DATA`, `TUI_INPUT`,
     `SANDBOX_LOCAL_UNVERIFIED`, and all non-`user_message` stream events).
   - **Multiline event text (`has_control_or_bidi`):** Permits normal `\n`, `\t`, and `\r\n` pairs
     (zero false positives on multiline messages/code blocks!), while flagging bare `\r`, NUL,
     other C0 (`0x00..0x1F` minus `\n`/`\t`), DEL (`0x7F`), C1 (`0x80..0x9F`), lone surrogates, and
     Unicode bidi override characters.
   - **Single-line metadata (`project_name`, `branch`, `task_brief`, `title`, `detail`, `reason`):**
     Scrubs ALL control/bidi characters (collapsing `\r`/`\n`/`\t` to spaces) and caps to
     `MAX_METADATA_TEXT_BYTES`.
   - **`artifact_refs_json` schema alignment:** Projects strictly `(blob_sha256, size_bytes,
     media_type)` matching `ArtifactRef` (`oc_coord_contract.py:299-313`), skipping invalid entries
     and setting `malformed_metadata = True` on corrupt or oversize (`> SQL_MAX_CELL_BYTES`) JSON.
   - **Defensive JSON & numeric safety (`allow_nan=False`):**
     - Non-finite SQLite `REAL` values (`NaN`/`Inf`) clamp to `0.0` with `malformed_metadata = True`.
     - Bounded/depth-capped (`<= SQL_MAX_CELL_BYTES`, depth `<= MAX_JSON_DEPTH`) decoding for
       `detail_json`, `allowed_threads_json`, `allowed_msg_kinds_json`, and `budget_json`, stripping
       `_UNTRUSTED_DETAIL_KEYS`, scrubbing control/bidi strings, and falling back to `{}` / `()` +
       `malformed_metadata = True` on corrupt or non-TEXT SQLite cells.

---

## 7. Failure & Recovery Matrix (Pinned Exception Mapping)

| Failure / Edge Condition | Exact Exception / Result |
|---|---|
| `caller` is not `PrincipalCtx` | `CoordValidationError("caller must be PrincipalCtx")` |
| `caller.role != CoordRole.OPERATOR` (e.g. `JOB`, `ORCHESTRATOR`, `EXTERNAL_PEER`) | `CoordAuthError("operator_role_required")` |
| `OPERATOR` with non-`None` `sandbox_addr` or `incarnation_id` | `CoordAuthError("operator_principal_must_not_bind_sandbox")` |
| `session_validator` configured, but `(read_session_id, session_generation)` omitted | `CoordAuthError("read_session_required")` |
| Only one of `(read_session_id, session_generation)` supplied, or invalid type/value | `CoordValidationError` |
| Session arguments supplied with no `session_validator` configured | `CoordPolicyError("read_session_validator_unconfigured")` |
| `session_validator` returns non-`True` or raises (pre-read or post-read) | `RevokedError("read_session_retired")` |
| `live_authority_checker` returns non-`True` or raises (pre-read or post-read) | `RevokedError("read_authority_revoked")` |
| Missing/symlinked/untrusted/production `state_dir`, missing `registry.sqlite`, symlink/FIFO/hardlink/wrong-UID/unsafe-mode on DB or `-wal`/`-shm`/`-journal` | `CoordPolicyError` |
| Corrupt SQLite DB, missing table, or read-only dir without WAL `-shm` | `CoordPolicyError("registry_unreadable")` |
| SQLite lock timeout (`BUSY`) / read progress deadline exceeded | `CoordPolicyError("registry_busy")` / `CoordPolicyError("read_deadline_exceeded")` |
| Symlink/FIFO/hardlink/wrong-UID/unsafe-mode/unreadable `.coord_degraded` or `.coord_session_active` | `health_status = "degraded"`, `degraded = True`, `marker_unreadable = True` — operator still gets diagnostics |
| Present `.coord_session_active` with no `live_degraded_checker` and no degraded/unconfirmed flags | `health_status = "unknown"`, `degraded = False`, `session_active_marker_present = True`, `live_status_available = False` |
| Live `live_degraded_checker` returns `False` with clean markers & zero unconfirmed bindings | `health_status = "healthy"`, `degraded = False`, `live_status_available = True` |
| Non-existent `target` sandbox on `get_sandbox_status` / `get_thread_events` / `get_sandbox_mailbox` | `CoordPolicyError("sandbox_not_found")` |
| Authorized `get_thread_events` on non-existent `thread_id` of an existing sandbox | Empty `ThreadEventsPage` (`events=()`, `has_more=False`, `thread_exists=False`) |
| Malformed, oversized, non-canonical, or scope/incarnation-mismatched cursor | `CoordValidationError` |
| `max_response_bytes` too small for envelope or minimal first item | `CoordValidationError("response_budget_too_small_...")` |
| Tampered/unbacked/ambiguous provenance badge, `body_sha256` mismatch, or oversize tampered `text` | Downgrade `effective_badge` to `SANDBOX_LOCAL_UNVERIFIED` (or `None` on non-user), `authority_rank = 0`, `provenance_anomaly = True` |
| Corrupt/oversize JSON metadata cell or `NaN`/`Inf` SQLite `REAL` | Safe fallback (`{}` / `()` / `0.0`) + `malformed_metadata = True` |

---

## 8. Open Choices Resolved in This Walkthrough (For Gate 1 Review)

1. **Standalone reader role scope:** Strictly `CoordRole.OPERATOR`-only (`sandbox_addr is None,
   incarnation_id is None`). Sandbox-scoped (`JOB`) and subtree-scoped (`ORCHESTRATOR`) reads are
   explicitly deferred to a future hub-owned walkthrough with live lease/fence/grant-generation
   authority, eliminating SQLite-only authority gaps and address-reuse history leaks without
   modifying shared files.
2. **Dedicated live-WAL `mode=ro` + `PRAGMA query_only = ON` connection per snapshot:** Protects
   all logical database state under single-transaction `BEGIN DEFERRED` / `ROLLBACK` snapshots and
   explicitly documents WAL `-shm`/`-wal` coordination sidecar behavior (confined via `umask(0o077)`).
3. **Strict per-event provenance downgrade on read:** Downgrades unbacked, tampered, cross-page
   ambiguous host-receipt matches, and un-attributable/revocation-tainted `TUI_INPUT` badges to
   `SANDBOX_LOCAL_UNVERIFIED` (`authority_rank = 0`, `provenance_anomaly = True`) without crashing
   operator forensic views.
4. **Collision-free base64url canonical JSON cursors keyed on `sandbox_addr` for tree paging:**
   Guarantees every valid `project_id` (including `:` or multi-KiB IDs) round-trips within
   `MAX_CURSOR_BYTES`, binds every cursor to `(op, scope_hash)`, and handles `(seq, rank)`
   boundaries without skipping same-`seq` stream rows.
5. **Hard end-to-end serialized UTF-8 JSON byte enforcement across all 4 APIs:** Accounts for JSON
   escaping and full envelope overhead (with compact `WorkspaceHealthSummary` on event/mailbox
   pages, dynamic binary-search first-item text shrinking, or explicit `CoordValidationError` if
   even a minimal item cannot fit).

---

## 9. Offline Qualification & Verification Plan (`test_projection.py`)

All tests run offline via `python3 -B -m unittest discover -s docs/prds/spikes/m/projection -p 'test_*.py'`
under both default `$HOME` and `TMPDIR=/tmp` using private owner-only synthetic fixtures:

1. **Filesystem admission, sidecars, FIFO/hardlink safety, & live-WAL semantics:**
   - Missing `registry.sqlite` raises `CoordPolicyError("registry_missing")` without creating it.
   - Symlinked `state_dir`, production host dir, symlinked DB, hardlinked DB (`os.link`),
     `0o644` DB, symlinked/hardlinked `-wal`/`-shm`/`-journal`, and FIFO at DB/sidecar/marker
     (`os.mkfifo`) all fail closed immediately without blocking or repairing modes.
   - Direct write attempt on opened projection connection fails with `sqlite3.OperationalError`.
   - Logical immutability verified across reads (unchanged rows, `seq_counter`, and hash-chained
     `audit_log`); read-only `0o500` dir without `-shm` maps cleanly to `CoordPolicyError("registry_unreadable")`.
2. **Operator-only admission & pre/post authority + session-generation fencing:**
   - `JOB`, root `ORCHESTRATOR`, sandbox-bound `ORCHESTRATOR`, `EXTERNAL_PEER`, `OPERATOR` with
     bound `sandbox_addr`, and non-`PrincipalCtx` all fail closed before touching SQLite.
   - Configured `session_validator` rejects omitted session args (`CoordAuthError`), partial pairs
     (`CoordValidationError`), retired session *before* read, and a paused read whose session OR
     `live_authority_checker` is revoked *during* the snapshot (`RevokedError`), returning zero data.
   - Session args without a configured validator raise `CoordPolicyError`.
3. **Health markers, lock-free observed status, & orphaned bindings:**
   - Standalone reader with `.coord_session_active` present (no `live_degraded_checker`) reports
     `health_status="unknown"`, `session_active_marker_present=True`, `live_status_available=False`
     without acquiring `.coord_hub.lock`; concurrent `CoordHub` startup succeeds with zero
     `_ERR_STATE_LOCKED` interference.
   - Restarted/crashed hub holding `.coord_hub.lock` with old `.coord_session_active` reports
     `health_status="unknown"` without `live_degraded_checker` and `health_status="degraded"`
     (`"live_hub_degraded"`) when `live_degraded_checker` returns `True`; positive
     `health_status="healthy"` is reported ONLY when `live_degraded_checker` returns `False` and
     markers/bindings are clean.
   - FIFO/symlink/unsafe-mode health markers report `health_status="degraded"`
     (`"marker_unreadable"`) without blocking.
   - Orphaned `external_transport_bindings` row (missing `sandboxes` row) is included via `LEFT JOIN`
     and `owner_id` is never leaked in responses.
4. **Hard response-byte bounds, SQL cell caps, cursors, deadline, & connection close:**
   - 1 KiB `max_response_bytes` page with escape-heavy (`"\\"\n\u0000`) and multibyte UTF-8 text
     stays strictly `<= 1024` UTF-8 bytes (`allow_nan=False`), truncating cleanly at UTF-8 boundary.
   - Extremely tiny budget that cannot fit the envelope or empty first item raises explicit
     `CoordValidationError`.
   - Long valid `project_id` (2 KiB containing `:`), two distinct >256-byte `project_id`s sharing
     a 256-byte prefix (kept in separate groups!), oversized >4 KiB `project_id` (isolated without
     materializing megabytes), `:` in `incarnation_id`/`msg_id`, and same-`seq` `event_log` +
     `stream_events` rows paginate across `limit=1` pages with zero skips or duplicates.
   - Oversized SQLite cells (e.g., 2 MiB `detail_json`, `text`, `project_id`) are SQL-gated before
     Python materialization (asserting both bounded bytes fetched and final serialized size).
   - Reusing a cursor on a different operation, target, thread, incarnation, or filter raises
     `CoordValidationError("cursor_scope_mismatch")`.
   - Lock-contention fixture with minimum `max_read_ms=50` against a held write lock aborts
     promptly with `CoordPolicyError("read_deadline_exceeded")` (well under 500 ms), alongside
     the large-query deadline fixture.
   - `open_readonly_snapshot` closes the SQLite connection immediately on normal return, anchor
     `SELECT` failure (e.g. corrupt DB / missing `seq_counter`), and query timeout (verified via
     closed-connection check / zero leaked descriptors).
   - Concurrent WAL writer mutating `sandboxes` + `routing_edges` + `outbox` during a held read
     snapshot never causes torn cross-table state.
5. **Per-event provenance verification & hostile/corrupt DB defense:**
   - Verified `[Operator]`, `[Orchestrator -o]`, `[Peer]`, and `[Sandbox-Local / Unverified]` rows
     project accurately; multiline `\n`/`\t` event text does NOT false-positive
     `has_control_or_bidi`, while bare `\r`/NUL/bidi override DOES flag it.
   - Genuine `[Operator]` row followed by a compromised worker's rejected SSE replay
     (`badge='Sandbox-Local / Unverified'` on the same `message_id`) **preserves `[Operator]`** on
     the genuine row while keeping the replay `SANDBOX_LOCAL_UNVERIFIED`.
   - Two tampered `badge='Operator'` rows on the same `message_id` **across page boundaries** (or
     two conflicting consumed `dispatch_receipts` on the same 4-tuple) BOTH downgrade to
     `SANDBOX_LOCAL_UNVERIFIED` (`"ambiguous_receipt_match"`).
   - `user_message` with `message_id=None` + valid `dispatch_msg_id` downgrades (`"unbacked_host_badge"`).
   - Oversize (`> 69,632` B) or NUL tampered `stream_events.text` on a host-badged row downgrades
     cleanly (`"receipt_body_hash_mismatch"`) without raising `CoordValidationError` or allocating
     megabytes.
   - Even 1 consumed `tui_enter_tokens` row with 1 `TUI_INPUT` candidate event on a live
     incarnation (as well as 1 token / 2 events and revoked incarnations) ALWAYS downgrades to
     `SANDBOX_LOCAL_UNVERIFIED` (`"tui_unverifiable_without_event_link"`).
   - Non-user event with non-null badge clears badge (`"non_user_event_has_badge"`).
   - `ArtifactRef` projects `(blob_sha256, size_bytes, media_type)` only; corrupt `artifact_refs_json`,
     `detail_json`, `budget_json`, oversize cells (`> SQL_MAX_CELL_BYTES`), and `NaN`/`Inf` SQLite
     `REAL` values degrade cleanly (`malformed_metadata=True`, strict `json.dumps(..., allow_nan=False)` succeeds).
6. **End-to-end synthetic `CoordHub` + `ExternallyFencedFakeTransport` integration:**
   - Full lifecycle (register, grant, send, stream, revoke, restart, fresh same-address successor,
     explicit historical incarnation query, non-existent `thread_id` returning empty page with
     `thread_exists=False`) verified end-to-end with logical DB/audit chain completely intact.
