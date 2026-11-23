# PRD N3 Operator-Only Human Inbox Read Projection Walkthrough (Gate 1)

Parent plans: [prd_n.md](../../../prd_n.md) · [prd_n3.md](../../../prd_n3.md) · Review gates:
[implementation review gates](../../../README.md#implementation-review-gates) · builds read-only on
[oc_coord_contract.py](../../m/oc_coord_contract.py),
[oc_address.py](../../m/oc_address.py),
[oc_schema.py](../../l/oc_schema.py),
[oc_broker_common.py](../../l/oc_broker_common.py), and
[oc_workflow_schema.py](../oc_workflow_schema.py)

---

## 1. Scope, Owned Boundary, and Explicit Non-Goals

This Gate 1 walkthrough specifies the **standalone, operator-only, strictly read-only Tier-B Human
Inbox projection slice** for PRD N3. It projects synthetic workflow/review SQLite snapshots into
bounded, scrubbed, redacted, JSON-safe envelopes with deterministic cryptographic review-pin
verification and **zero mutation or grant authority**.

### Owned File Boundary (Strictly Disjoint)

All documentation, implementation, and tests for this slice live exclusively under
`docs/prds/spikes/n/inbox-read/`:

1. `WALKTHROUGH.md` — this Gate 1 design and security walkthrough.
2. `oc_inbox_contract.py` — frozen dataclasses (each `<= 12` `__init__` params including `self`),
   schema version and hard bounds constants, closed enums, canonical base64url JSON cursor codec
   bound to `(op, scope_hash, snapshot_seq)`, deterministic `compute_review_pin_sha256()`, and
   strict `allow_nan=False` UTF-8 JSON serializer.
3. `oc_inbox_db.py` — verification-only filesystem admission (preserving `..` in raw
   symlink-ancestor inspection), non-blocking `O_NOFOLLOW | O_NONBLOCK` DB/sidecar checks,
   URI-before-`_UMASK_LOCK` `open_readonly_inbox_snapshot()` with `PRAGMA trusted_schema = OFF`,
   `PRAGMA cell_size_check = ON`, and `sqlite_master` trigger/view rejection, plus single monotonic
   deadline helpers.
4. `oc_inbox_projection.py` — `ReadOnlyInboxService` exposing strictly the three read APIs
   (`list_inbox_items`, `get_inbox_item`, `get_inbox_summary`) with SQL storage-class gating,
   review-pin verification, ANSI/C1/bidi/NUL/surrogate scrubbing, secret redaction, and hard
   end-to-end UTF-8 JSON byte-budget packing.
5. `test_inbox_read.py` — 100% offline `unittest` qualification and adversarial regression suite
   using private temporary synthetic SQLite fixtures.

**Zero edits to shared files:** This slice imports strictly read-only from `docs/prds/spikes/l/`,
`docs/prds/spikes/m/`, and `docs/prds/spikes/n/`:
- `oc_coord_contract`: `CoordAuthError`, `CoordPolicyError`, `CoordRole`, `CoordValidationError`,
  `PrincipalCtx`, `RevokedError`, `validate_opaque_token`, `_SHA256_HEX_RE`, `_MEDIA_TYPE_RE`.
- `oc_address`: `AddressError`, `_BIDI_CODEPOINTS`, `has_forbidden_control_or_bidi`,
  `parse_canonical_addr`.
- `oc_schema`: `PolicyError`, `assert_trusted_dir`, `check_not_host_production_dir`,
  `check_not_in_sandbox`.
- `oc_broker_common`: `_UMASK_LOCK`.
- `oc_workflow_schema`: `WorkflowSchemaError`, `canonical_json_bytes`, `domain_sha256`,
  `parse_namespaced_id`.

Zero modifications to `oc_coord_contract.py`, `oc_registry.py`, `oc_hub.py`, `oc_projection*.py`,
`oc_workflow_*.py`, production `oc-sandbox`, or any PRD `Human review` checkbox.

### Explicit Non-Goals & Strict Zero-Authority Boundary

- **Zero grant, approval, or mutation authority:** This service represents **Tier-B Human Inbox
  read projection only**. It exposes **no** `approve`, `reject`, `defer`, `resolve`, `snooze`,
  `post`, `note`, `consume_awakeable`, `mint_grant`, or Tier-A proposal APIs. It never writes
  `HumanDecisionReceipt` or `audit_log` rows and opens SQLite exclusively with `mode=ro` and
  `PRAGMA query_only = ON`.
- **No non-operator reads:** Standalone SQLite snapshots cannot enforce live `CoordHub` leases,
  `SubtreeBudget` boundaries, or target-incarnation revocation fences for `JOB`, `ORCHESTRATOR`, or
  `EXTERNAL_PEER` callers. Those roles are unconditionally rejected before filesystem or SQLite
  access; orchestrator MCP `inbox_*` tools belong to a future hub-owned slice.
- **No live UI, HTTP, WebSocket, Tauri, Podman, or `safe_run` operations:** No SvelteKit/Tauri
  chrome, no HTTP/UDS servers, no containerized `git rev-parse HEAD` workspace checks, and zero
  network or host-production-directory access.
- **No open PRD decisions resolved:** All open `(decision needed)` items in
  [prd_n.md](../../../prd_n.md) and [prd_n3.md](../../../prd_n3.md) (including project-scoped
  `[Orchestrator Overlay]` surfaces) remain open.

---

## 2. Operator-Only Admission & Pre/Post Fencing

### 2.1 Strict Operator-Only Caller Gate

Every public read method calls `_authorize_operator_caller(caller)` **before** validating filesystem
paths or opening SQLite:

```python
def authorize_operator_caller(caller: object) -> PrincipalCtx:
    if not isinstance(caller, PrincipalCtx):
        raise CoordValidationError("caller must be PrincipalCtx")
    if caller.role is not CoordRole.OPERATOR:
        raise CoordAuthError("operator_role_required")
    if caller.sandbox_addr is not None or caller.incarnation_id is not None:
        raise CoordAuthError("operator_principal_must_not_bind_sandbox")
    return caller
```

- `CoordRole.JOB`, `CoordRole.ORCHESTRATOR` (both root and sandbox-bound), `CoordRole.EXTERNAL_PEER`,
  any `OPERATOR` principal bound to a `sandbox_addr` or `incarnation_id`, and any non-`PrincipalCtx`
  object fail closed immediately with zero filesystem or SQLite probes (eliminating any
  review-item existence oracle).

### 2.2 Mandatory Pre-Read and Post-Read Session & Live-Authority Fencing

`ReadOnlyInboxService` accepts two optional host-trusted fencing callbacks:

- `session_validator: Callable[[PrincipalCtx, str, int], bool] | None = None`
- `live_authority_checker: Callable[[PrincipalCtx], bool] | None = None`

Fail-closed rules enforced on every read:

1. **Opaque token validation helper (maps `AddressError -> CoordValidationError`):**
   Every caller-supplied opaque token (`read_session_id`, `run_id`, `review_id`, cursor `rid`) is
   validated through a single wrapper calling `validate_opaque_token(val, label)` and catching
   `AddressError` (which `validate_opaque_token` raises on non-string or control/bidi characters)
   to re-raise as `CoordValidationError`.
2. **Session pair & mandatory enforcement:**
   - Supplying only one of `(read_session_id, session_generation)` raises
     `CoordValidationError("read_session_pair_required")`.
   - When supplied, `read_session_id` must pass wrapped `validate_opaque_token`, and
     `session_generation` must satisfy `type(v) is int and 1 <= v <= MAX_SQLITE_INT64` (rejecting
     `bool`, `<= 0`, floats, and >int64 values).
   - Supplying session coordinates when `session_validator is None` raises
     `CoordPolicyError("read_session_validator_unconfigured")`.
   - Omitting session coordinates when `session_validator is not None` raises
     `CoordAuthError("read_session_required")`.
3. **Strict `is True` pre-read AND post-read checks:**
   - Before touching the filesystem/SQLite **and** after completing snapshot assembly, byte-budget
     packing, and final deadline check (before returning):
     - If `session_validator` is configured, call
       `session_validator(caller, read_session_id, session_generation)`. Any return value other
       than literal `True` (`result is not True`, rejecting truthy objects such as `1` or `"ok"`)
       or any raised exception raises `RevokedError("read_session_retired")` and returns zero data.
     - If `live_authority_checker` is configured, call `live_authority_checker(caller)`. Any return
       value other than literal `True` or any raised exception raises
       `RevokedError("read_authority_revoked")` and returns zero data.
4. **Session echo:** When validated, `(read_session_id, session_generation)` is echoed as
   `ReadSessionEcho` on the returned envelope so callers can discard stale responses from retired
   session generations.

---

## 3. Verification-Only Filesystem Admission & Live-WAL SQLite Snapshot

### 3.1 Verification-Only Admission (`oc_inbox_db.py`)

`ReadOnlyInboxService` **never creates directories or files, never opens files for write, and never
repairs permissions via `chmod`/`fchmod` or `mkdir`**:

```python
DB_FILENAME = "inbox.sqlite"
DB_ALL_FILES = ("", "-wal", "-shm", "-journal")


def assert_raw_no_user_symlink_ancestors(raw: Path) -> None:
    # Anchor relative paths to Path.cwd() WITHOUT collapsing '..' via os.path.abspath()
    # or Path.resolve(), then lstat every prefix left-to-right so 'sym_rel/../state'
    # fails closed before SQLite opens!
    try:
        anchored = raw if raw.is_absolute() else (Path.cwd() / raw)
    except (OSError, ValueError) as exc:
        raise CoordPolicyError("state_dir_unreadable") from exc
    parts = anchored.parts
    if not parts:
        return
    acc = Path(parts[0])
    for idx, part in enumerate(parts):
        if idx > 0:
            acc = acc / part
        try:
            st = os.lstat(acc)
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            raise CoordPolicyError("state_dir_unreadable") from exc
        if stat.S_ISLNK(st.st_mode) and st.st_uid != 0:
            raise CoordPolicyError(f"state_dir_symlink_ancestor_rejected: {acc}")


def verify_regular_private_file_nofollow(path: Path, *, required: bool, label: str) -> None:
    # O_NOFOLLOW | O_NONBLOCK prevents hanging on a pre-placed FIFO before fstat().
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError as exc:
        if required:
            raise CoordPolicyError(f"{label}_missing") from exc
        return
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise CoordPolicyError(f"{label}_symlink_rejected") from exc
        raise CoordPolicyError(f"{label}_unreadable") from exc
    except ValueError as exc:
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


def verify_state_dir_and_db_readonly(
    state_dir: Path, sandbox_root: Path | None
) -> tuple[Path, Path]:
    try:
        raw = Path(state_dir)
        is_raw_symlink = raw.is_symlink()
    except (OSError, ValueError) as exc:
        raise CoordPolicyError("state_dir_unreadable") from exc
    if is_raw_symlink:
        raise CoordPolicyError("state_dir_symlink_rejected")
    assert_raw_no_user_symlink_ancestors(raw)
    try:
        phys = check_not_in_sandbox(raw, sandbox_root)
        check_not_host_production_dir(raw)
        check_not_host_production_dir(phys)
    except PolicyError as exc:
        raise CoordPolicyError(str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise CoordPolicyError("state_dir_unreadable") from exc
    try:
        if phys.is_symlink() or not phys.exists():
            raise CoordPolicyError("state_dir_missing_or_symlink")
        trusted_dir = assert_trusted_dir(phys, sandbox_root=sandbox_root)  # 0o700, euid, no symlinks
    except PolicyError as exc:
        raise CoordPolicyError(str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise CoordPolicyError("state_dir_unreadable") from exc
    db_path = trusted_dir / DB_FILENAME
    for idx, suffix in enumerate(DB_ALL_FILES):
        label = "inbox_db" if idx == 0 else f"inbox_db_sidecar_{suffix.lstrip('-')}"
        verify_regular_private_file_nofollow(
            Path(f"{db_path}{suffix}"), required=(idx == 0), label=label
        )
    return trusted_dir, db_path
```

- Preserving `..` in `assert_raw_no_user_symlink_ancestors` closes the `sym_rel/../state` bypass
  where `abspath()` would collapse a user-owned symlink before inspection.
- Every `os.lstat`, `Path.is_symlink`/`exists`, and `oc_schema` call maps `PolicyError`,
  `OSError` (`PermissionError`, `ENOTDIR`, etc.), and `ValueError` (embedded NUL byte in path)
  cleanly to `CoordPolicyError`, leaking zero unmapped filesystem exceptions.
- Root-owned OS directory aliases above `state_dir` (e.g., `/home -> /var/home` on Atomic Linux)
  remain permitted; any user-owned symlink ancestor or any symlink at/below `state_dir` is
  rejected.
- All four SQLite files (`inbox.sqlite`, `-wal`, `-shm`, `-journal`) enforce `S_ISREG`,
  `st_nlink == 1`, `st_uid == os.geteuid()`, and `(st_mode & 0o077) == 0` without blocking on FIFOs
  or mutating file modes.

### 3.2 URI-Before-`_UMASK_LOCK` `open_readonly_inbox_snapshot` & Single Monotonic Deadline

Every read call starts one monotonic deadline immediately after synchronous preflight:
`deadline = time.monotonic() + (max_read_ms / 1000.0)` (`50 <= max_read_ms <= 10_000`, default
`2000`).

```python
@contextmanager
def open_readonly_inbox_snapshot(db_path: Path, *, deadline: float) -> Iterator[sqlite3.Connection]:
    # Build and validate the SQLite URI BEFORE acquiring _UMASK_LOCK so a surrogate-escaped
    # POSIX path (UnicodeEncodeError) or URI failure can never strand _UMASK_LOCK!
    try:
        uri = f"file:{quote(str(db_path), safe='/')}?mode=ro"
    except UnicodeEncodeError as exc:
        raise CoordPolicyError("inbox_db_unreadable") from exc

    remaining_s = check_deadline_s(deadline)
    if not _UMASK_LOCK.acquire(timeout=remaining_s):
        raise CoordPolicyError("read_deadline_exceeded")
    try:
        conn: sqlite3.Connection | None = None
        # Recompute remaining budget AFTER acquiring _UMASK_LOCK; expiry prevents connect()!
        remaining_ms = check_deadline_ms(deadline)
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
            conn.execute("PRAGMA trusted_schema = OFF")
            conn.execute("PRAGMA cell_size_check = ON")
            apply_remaining_busy_timeout(conn, deadline)
            conn.set_progress_handler(lambda: 1 if time.monotonic() >= deadline else 0, 1000)
            conn.execute("BEGIN DEFERRED")
            # 1. Anchor the WAL read snapshot against sqlite_master FIRST using a constant projection
            #    (SELECT 1 — never transferring unbounded schema identifiers into Python), rejecting
            #    ANY trigger or view BEFORE querying inbox_seq_counter or any user table!
            unsafe_obj = execute_bounded(
                conn,
                "SELECT 1 FROM sqlite_master WHERE type IN ('trigger', 'view') LIMIT 1",
                (),
                deadline,
            ).fetchone()
            if unsafe_obj is not None:
                raise CoordPolicyError("inbox_db_unreadable")
            # 2. Verify all 4 required objects exist as ORDINARY tables (type = 'table', explicitly
            #    rejecting 'virtual', 'shadow', and 'view'!) via pragma_table_list BEFORE reading
            #    inbox_seq_counter!
            req_tables = execute_bounded(
                conn,
                "SELECT name, type FROM pragma_table_list "
                "WHERE schema = 'main' "
                "AND name IN ('inbox_seq_counter', 'review_items', 'workflow_runs', 'review_artifacts')",
                (),
                deadline,
            ).fetchall()
            if {r["name"] for r in req_tables if r["type"] == "table"} != {
                "inbox_seq_counter",
                "review_items",
                "workflow_runs",
                "review_artifacts",
            } or len(req_tables) != 4:
                raise CoordPolicyError("inbox_db_unreadable")
            # 3. ONLY after pragma_table_list ordinary-table verification, validate
            #    inbox_seq_counter inside the exact same anchored WAL snapshot transaction!
            execute_bounded(
                conn,
                "SELECT CASE WHEN typeof(last_seq) = 'integer' THEN last_seq ELSE NULL END "
                "AS last_seq FROM inbox_seq_counter WHERE id = 1",
                (),
                deadline,
            ).fetchone()
        except sqlite3.OperationalError as exc:
            safe_close(conn)
            raise map_sqlite_operational_error(exc, deadline) from exc
        except sqlite3.DatabaseError as exc:
            safe_close(conn)
            raise CoordPolicyError("inbox_db_unreadable") from exc
        except BaseException:
            safe_close(conn)
            raise
        finally:
            os.umask(old_umask)
    finally:
        _UMASK_LOCK.release()

    try:
        yield conn
    except sqlite3.OperationalError as exc:
        raise map_sqlite_operational_error(exc, deadline) from exc
    except sqlite3.DatabaseError as exc:
        raise CoordPolicyError("inbox_db_unreadable") from exc
    finally:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        finally:
            conn.close()
```

- **Hardened SQLite connection pragmas & `sqlite_master`-first snapshot anchor:**
  `PRAGMA trusted_schema = OFF` blocks schema-embedded unsafe SQL functions,
  `PRAGMA cell_size_check = ON` catches corrupt B-tree page cells early, and anchoring the
  `BEGIN DEFERRED` snapshot on `sqlite_master` FIRST (rejecting any `trigger` or `view` and
  confirming `inbox_seq_counter`, `review_items`, `workflow_runs`, and `review_artifacts` are all
  ordinary `type = 'table'` objects BEFORE reading `inbox_seq_counter`) guarantees a hostile view
  named `inbox_seq_counter` is rejected without its view body ever being evaluated.
- **Explicit Live-WAL semantics:** `mode=ro` + `PRAGMA query_only = ON` guarantees strict logical
  immutability (zero DB creation, zero SQL writes, zero `inbox_seq_counter` or `audit_log`
  mutations). When reading a live WAL database in a writable `0o700` directory, SQLite may map or
  create `-shm`/`-wal` coordination sidecars (confined to `0o600` via `umask(0o077)` under
  `_UMASK_LOCK`); opening a WAL DB in a read-only `0o500` directory without `-shm` fails closed
  with `CoordPolicyError("inbox_db_unreadable")`.
- **Unified deadline enforcement:** The single monotonic `deadline` governs `_UMASK_LOCK.acquire()`,
  post-lock `sqlite3.connect()` guard, per-query dynamic `PRAGMA busy_timeout` + retry loop in
  `execute_bounded()`, SQLite VM progress callbacks, inter-query checks, item verification and
  byte-budget packing/binary-search loops, AND a final post-serialization
  `check_deadline_ms(deadline)` before releasing the response.
- **Error mapping:** `OperationalError` with `"interrupted"` or `time.monotonic() >= deadline` ->
  `CoordPolicyError("read_deadline_exceeded")`; `"locked"`/`"busy"` before deadline ->
  `CoordPolicyError("inbox_db_busy")`; corrupt DB, missing table, present trigger/view, or other
  `DatabaseError` -> `CoordPolicyError("inbox_db_unreadable")`.

---

## 4. Synthetic SQLite Snapshot Schema & Deterministic Review Pins

### 4.1 Synthetic Snapshot Schema (Fixture-Owned Only)

Test fixtures create the synthetic SQLite snapshot `inbox.sqlite` (the projection service never
executes DDL or DML). Tables are standard non-`STRICT` SQLite tables so the projection explicitly
defends against hostile storage-class tampering (e.g., 2 MiB BLOBs in `INTEGER` or `REAL` columns):

```sql
CREATE TABLE inbox_seq_counter (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    last_seq INTEGER NOT NULL
);

CREATE TABLE workflow_runs (
    run_id        TEXT PRIMARY KEY,
    workflow_id   TEXT NOT NULL,           -- '(builtin|user)/<slug>'
    spec_digest   TEXT NOT NULL,           -- 64-hex
    policy_digest TEXT NOT NULL,           -- 64-hex
    status        TEXT NOT NULL,
    owner_role    TEXT NOT NULL,
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);

CREATE TABLE review_items (
    review_id             TEXT PRIMARY KEY,-- opaque token <= 96 B (_ID_TOKEN_RE)
    run_id                TEXT NOT NULL,   -- opaque token <= 96 B
    step_id               TEXT NOT NULL,   -- opaque token <= 96 B
    checkpoint_seq        INTEGER NOT NULL,-- 0..MAX_SQLITE_INT64
    item_revision         INTEGER NOT NULL,-- 1..MAX_SQLITE_INT64
    status                TEXT NOT NULL,   -- closed enum: pending|superseded|expired|resolved
    severity              TEXT NOT NULL,   -- closed enum: low|normal|high|critical
    priority_rank         INTEGER NOT NULL,-- 0..100
    lane_paused           INTEGER NOT NULL,-- strict {0, 1}; 1 permitted ONLY for host_workflow_engine
    requires_human_review INTEGER NOT NULL,-- strict {0, 1}
    source_kind           TEXT NOT NULL,   -- closed enum: host_workflow_engine|supervision_escalation|orchestrator_advisory|calibration_drift
    target_addr           TEXT,            -- nullable canonical target ('NAME', 'REMOTE / NAME', '@PEER')
    target_incarnation_id TEXT,            -- nullable opaque token <= 96 B
    title                 TEXT NOT NULL,
    summary_text          TEXT NOT NULL,   -- untrusted agent-authored prose
    artifact_sha256       TEXT NOT NULL,   -- 64-hex primary artifact digest
    policy_digest         TEXT NOT NULL,   -- 64-hex pinned workflow policy digest
    review_pin_sha256     TEXT NOT NULL,   -- stored canonical review pin (verified on read)
    metadata_json         TEXT NOT NULL,   -- bounded JSON object
    created_at            REAL NOT NULL,
    updated_at            REAL NOT NULL,
    expires_at            REAL             -- nullable finite timestamp
    -- Fixtures may additionally contain hostile/sensitive columns such as env_vars,
    -- auth_header, token, password, private_key, awakeable_token_hash; SQL queries
    -- use explicit column allowlists and NEVER SELECT those columns.
);

CREATE TABLE review_artifacts (
    artifact_id TEXT PRIMARY KEY,          -- opaque token <= 96 B
    review_id   TEXT NOT NULL,
    blob_sha256 TEXT NOT NULL,             -- 64-hex digest
    size_bytes  INTEGER NOT NULL,          -- non-negative int
    media_type  TEXT NOT NULL,             -- closed RFC media-type regex
    label       TEXT NOT NULL,             -- single-line display label
    is_primary  INTEGER NOT NULL,          -- strict {0, 1}
    created_at  REAL NOT NULL
);

CREATE INDEX idx_review_items_order
    ON review_items (priority_rank DESC, checkpoint_seq ASC, review_id ASC);
CREATE INDEX idx_review_items_run_status
    ON review_items (run_id, status);
CREATE INDEX idx_review_artifacts_review
    ON review_artifacts (review_id, is_primary DESC, artifact_id ASC);
```

### 4.2 Cryptographic Review Pin Calculation & Fail-Closed Verification

Every projected `InboxItem` computes and verifies a deterministic domain-separated SHA-256 review
pin over canonical JSON (reusing `oc_workflow_schema.domain_sha256`, which serializes with
`sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False`):

```python
REVIEW_PIN_DOMAIN = "oc-n3-inbox-review-pin-v1:"


def compute_review_pin_sha256(
    *,
    run_id: str,
    step_id: str,
    review_id: str,
    checkpoint_seq: int,
    artifact_sha256: str,
    policy_digest: str,
) -> str:
    # Strict pre-validation of all 6 inputs before hashing:
    # - run_id, step_id, review_id: clean non-empty opaque tokens (validate_opaque_token, <= 96 B)
    # - checkpoint_seq: type(x) is int and 0 <= x <= MAX_SQLITE_INT64
    # - artifact_sha256, policy_digest: exact 64-char lowercase hex (^[0-9a-f]{64}$)
    payload = {
        "artifact_sha256": artifact_sha256,
        "checkpoint_seq": checkpoint_seq,
        "policy_digest": policy_digest,
        "review_id": review_id,
        "run_id": run_id,
        "step_id": step_id,
    }
    return domain_sha256(REVIEW_PIN_DOMAIN, payload)
```

On every item read (`list_inbox_items` and `get_inbox_item`), primary-key `review_id` is admitted
first (SQL `typeof(review_id) = 'text' AND LENGTH(CAST(review_id AS BLOB)) <= 96` +
`validate_opaque_token` + `not contains_credential_pattern(review_id)`, mapping any failure to fixed
`CoordPolicyError("inbox_db_unreadable")` with zero echo of the raw identifier). Required
identifiers `run_id`, `step_id`, and `artifact_id` likewise fail closed with fixed
`CoordPolicyError("inbox_db_unreadable")` if they match `contains_credential_pattern`. The
projection then runs a strict 7-step ordered verification pipeline inside the same SQLite snapshot:

| Precedence | Check | Failure `anomaly_reason` (Closed Enum) | Resulting Flags |
|---|---|---|---|
| **1** | SQL `typeof()` & byte-length gate on all pin inputs + stored `review_pin_sha256` (`TEXT <= 96` for `run_id`/`step_id`, `TEXT == 64` for hex digests, `INTEGER >= 0` for `checkpoint_seq`) | `"tampered_storage_class"` | `pin_verified=False, pin_anomaly=True, review_ready=False` |
| **2** | Format validation of `run_id`, `step_id` (clean opaque tokens via `validate_opaque_token`, zero control/bidi/NUL/surrogate), and 64-char lowercase hex on `artifact_sha256`, `policy_digest`, stored `review_pin_sha256` | `"malformed_pin_input"` | `pin_verified=False, pin_anomaly=True, review_ready=False` |
| **3** | Constant-time pin equality: `hmac.compare_digest(stored_pin, recomputed_pin)` | `"review_pin_mismatch"` | `pin_verified=False, pin_anomaly=True, review_ready=False` |
| **4** | `workflow_runs` row exists for `run_id` (`LEFT JOIN workflow_runs w ON typeof(r.run_id) = 'text' AND w.run_id = r.run_id`) | `"workflow_run_missing"` | `pin_verified=False, pin_anomaly=True, review_ready=False` |
| **5** | `workflow_runs.policy_digest` is valid 64-hex `TEXT` and equals `review_items.policy_digest` | `"policy_digest_mismatch"` | `pin_verified=False, pin_anomaly=True, review_ready=False` |
| **6** | Primary `review_artifacts` check (`WHERE typeof(review_id) = 'text' AND review_id = ? AND ((typeof(is_primary) != 'integer' OR is_primary NOT IN (0, 1)) OR is_primary = 1) ORDER BY artifact_id ASC LIMIT 2`): malformed `is_primary` fails as `"tampered_storage_class"`; 0 rows -> `"primary_artifact_missing"`; `> 1` rows -> `"ambiguous_primary_artifact"`; malformed/invalid `artifact_id` (`validate_opaque_token`), `blob_sha256` (64-hex), `size_bytes` (`>= 0` int), `media_type` (`_MEDIA_TYPE_RE`), or `blob_sha256 != r.artifact_sha256` -> `"artifact_digest_mismatch"` (and malformed primary artifact `label` non-text/bad UTF-8 or non-finite/malformed `created_at` rolls into `malformed_metadata = True` for Step 7) | `"tampered_storage_class"` / `"primary_artifact_missing"` / `"ambiguous_primary_artifact"` / `"artifact_digest_mismatch"` | `pin_verified=False, pin_anomaly=True, review_ready=False` |
| **7** | **Complete item-level `malformed_metadata` & `source_kind`/`lane_paused` authority check:** covers ALL item metadata fields (`status`, `severity`, `source_kind` in closed enums; `priority_rank` int `0..100`; `item_revision` int `1..MAX_SQLITE_INT64`; `lane_paused` & `requires_human_review` strict int `{0, 1}`; **strict `prd_n3.md:54-59` gate-ownership invariant:** `lane_paused == 1` is permitted **ONLY** when `source_kind == "host_workflow_engine"` — any `lane_paused == 1` with `source_kind != "host_workflow_engine"`, including `source_kind == "orchestrator_advisory"`, clamps projected `lane_paused = False` and sets `malformed_metadata = True`; valid nullable `target_addr` via `parse_canonical_addr` and `target_incarnation_id` via `validate_opaque_token`; valid `workflow_runs.workflow_id` via `parse_namespaced_id`; clean UTF-8 `TEXT` on `title`/`summary_text`; finite numeric `created_at`/`updated_at` and nullable `expires_at`; valid bounded finite `metadata_json` with zero key collisions; valid primary artifact `label`/`created_at`). Any `malformed_metadata == True` fails Step 7 unconditionally. | `"malformed_item_metadata"` | `pin_verified=False, pin_anomaly=True, review_ready=False` |

**Fail-closed output invariants & `review_ready` scope note:**
- `review_pin_sha256` emits the **recomputed** deterministic digest when Steps 1–2 succeed, and
  `None` whenever a pin input is missing or tampered (a forged stored pin is never echoed as
  authoritative).
- `review_ready = (status == "pending") and pin_verified and (not pin_anomaly) and (not malformed_metadata)`.
  Because Step 7 folds all item-level `malformed_metadata` flags (including contradictory
  `orchestrator_advisory` + `lane_paused == 1`), `malformed_metadata == True` unconditionally yields
  `pin_verified = False, pin_anomaly = True, review_ready = False`.
- **Offline snapshot scope boundary for `review_ready`:** In this offline read-only snapshot slice,
  `review_ready` reflects **structural and cryptographic pin readiness only** (no hidden
  `time.time()` clock dependency). Live wall-clock `expires_at` expiry checks, live
  `workflow_runs.status` / `OPERATOR_ONLY` awakeable liveness, `item_revision` TOCTOU binding, and
  containerized `safe_run` `HEAD`/tree checks belong to the future daemon resolution slice.

---

## 5. SQL Storage-Class Gating, Sanitization, & Strict Redaction

### 5.1 SQL-Level `typeof()` & BLOB Byte-Length Gates on EVERY Column

Because SQLite tables are non-`STRICT`, every single selected column — including nominally numeric
flags, counters, sequence numbers, and timestamps — is gated inside SQL **before** any bytes cross
into Python:

- **Primary key (`review_id`):**
  `CASE WHEN typeof(r.review_id) = 'text' AND LENGTH(CAST(r.review_id AS BLOB)) <= 96 THEN r.review_id ELSE NULL END`.
  At row admission, Python requires `review_id is not None`, passes
  `validate_opaque_token(review_id, "review_id")`, AND runs `contains_credential_pattern(review_id)`
  (blocking credential-shaped tokens such as `"sk-ant-synthetic-secret1234"` that syntactically
  satisfy `_ID_TOKEN_RE`), mapping any failure to fixed `CoordPolicyError("inbox_db_unreadable")`
  with **zero echo of the raw identifier** (never serialized or placed in `next_cursor`).
- **Opaque tokens, addresses, workflow IDs, & hex digests (all checked via
  `contains_credential_pattern` before serialization or cursor encoding):**
  - `run_id`, `step_id`, `artifact_id`: `typeof = 'text' AND LENGTH(CAST(col AS BLOB)) <= 96`,
    validated via `validate_opaque_token` (matching `_ID_TOKEN_RE` max 96 chars). Any required
    identifier (`run_id`, `step_id`, `artifact_id`) matching `contains_credential_pattern` fails
    closed with fixed `CoordPolicyError("inbox_db_unreadable")` (zero echo, never serialized).
  - `target_incarnation_id` (nullable): exempts `IS NULL` (`col IS NULL -> NULL, malformed = 0`);
    non-`NULL` gated to `typeof = 'text' AND LENGTH(CAST(col AS BLOB)) <= 96` and validated via
    `validate_opaque_token`; invalid values clamp to `None` + `malformed_metadata = True`, and
    values matching `contains_credential_pattern` clamp to `None` + `malformed_metadata = True` +
    `redaction_applied = True` (never emitted).
  - `target_addr` (nullable): exempts `IS NULL`; non-`NULL` gated to
    `typeof = 'text' AND LENGTH(CAST(col AS BLOB)) <= 256` and validated via
    `parse_canonical_addr(raw)` (supporting `"NAME"`, `"REMOTE / NAME"`, and `"@PEER"`, requiring
    exact canonical equality `parsed.canonical == raw`); invalid values clamp to `None` +
    `malformed_metadata = True`, and values matching `contains_credential_pattern` clamp to `None`
    + `malformed_metadata = True` + `redaction_applied = True`.
  - `workflow_runs.workflow_id` (from `LEFT JOIN`): exempts `w.run_id IS NULL`; when run row exists,
    gated to `typeof = 'text' AND LENGTH(CAST(col AS BLOB)) <= 128` and validated via
    `parse_namespaced_id(raw, "workflow_id")` (allowing `"builtin/<slug>"` / `"user/<slug>"`);
    invalid values clamp to `None` + `malformed_metadata = True`, and values matching
    `contains_credential_pattern` clamp to `None` + `malformed_metadata = True` +
    `redaction_applied = True`.
  - `artifact_sha256`, `policy_digest`, `review_pin_sha256`, `blob_sha256`:
    `typeof = 'text' AND LENGTH(CAST(col AS BLOB)) = 64` + `_SHA256_HEX_RE`.
  - `media_type`: `typeof = 'text' AND LENGTH(CAST(col AS BLOB)) <= 128` + `_MEDIA_TYPE_RE`.
- **Closed enums (`status`, `severity`, `source_kind`):**
  - `VALID_STATUSES = frozenset({"pending", "superseded", "expired", "resolved"})`
  - `VALID_SEVERITIES = frozenset({"low", "normal", "high", "critical"})`
  - `VALID_SOURCE_KINDS = frozenset({"host_workflow_engine", "supervision_escalation", "orchestrator_advisory", "calibration_drift"})`
  - Gated via `typeof = 'text' AND LENGTH(CAST(col AS BLOB)) <= 64`; out-of-domain or non-TEXT
    values clamp to `"malformed"` and set `malformed_metadata = True`.
- **Strict boolean integer flags (`lane_paused`, `requires_human_review`, `is_primary`) &
  `source_kind`/`lane_paused` parity (`prd_n3.md:54-59`):**
  - Valid strictly when `typeof(col) = 'integer' AND col IN (0, 1)` (rejecting SQLite `REAL` `1.0`,
    `TEXT` `"1"`, out-of-domain integers `2`/`-1`, and BLOBs).
  - Non-integer or out-of-domain values return `NULL` + `*_malformed = 1` in SQL, clamp to `False`,
    and flag `malformed_metadata = True`.
  - Contradictory `lane_paused == 1` paired with `source_kind != "host_workflow_engine"` (including
    `source_kind == "orchestrator_advisory"`) clamps projected `lane_paused = False` and sets
    `malformed_metadata = True` (failing Step 7 in `list_inbox_items` and `get_inbox_item`), is
    excluded from `paused_lanes_count` in `get_inbox_summary`, and increments `malformed_rows_count`
    in `get_inbox_summary`.
- **Integer counters & pagination keys (`checkpoint_seq`, `item_revision`, `priority_rank`,
  `size_bytes`, `inbox_seq_counter.last_seq`):**
  - `inbox_seq_counter.last_seq`: strict SQLite `integer` in `0..MAX_SQLITE_INT64`, else
    `CoordPolicyError("inbox_db_unreadable")`.
  - `checkpoint_seq` (`>= 0`), `item_revision` (`>= 1`), `priority_rank` (`0..100`), `size_bytes`
    (`>= 0`): gated inside SQL via `typeof(col) = 'integer'` + range bounds so multi-MB BLOBs never
    cross into Python.
- **Numeric timestamps (`created_at`, `updated_at`, nullable `expires_at`):**
  - Required `created_at` / `updated_at`: `typeof(col) IN ('integer', 'real')`.
  - Nullable `expires_at`: explicitly exempts `expires_at IS NULL`
    (`(r.expires_at IS NOT NULL AND typeof(r.expires_at) NOT IN ('integer', 'real')) AS expires_at_malformed`).
    A valid non-expiring item (`expires_at IS NULL`) produces `expires_at = None, malformed = False`.
  - In Python, `math.isfinite()` rejects `NaN`, `Inf`, and `-Inf`, clamping to `0.0` (or `None` for
    `expires_at`) and setting `malformed_metadata = True` so `allow_nan=False` always succeeds.
- **JSON cell (`metadata_json`) with post-decode finite-float enforcement:**
  - `CASE WHEN typeof(r.metadata_json) = 'text' AND LENGTH(CAST(r.metadata_json AS BLOB)) <= 65536 THEN CAST(r.metadata_json AS BLOB) ELSE NULL END`
    plus `LENGTH(CAST(r.metadata_json AS BLOB)) AS metadata_bytes` and
    `(typeof(r.metadata_json) != 'text' OR LENGTH(CAST(r.metadata_json AS BLOB)) > 65536) AS metadata_malformed`.
  - Decoded with `parse_constant=_reject_json_constant` (rejects `NaN`/`Infinity` literals), catches
    `(ValueError, RecursionError)`, enforces `MAX_JSON_DEPTH = 8`, **AND recursively rejects any
    decoded `float` where `not math.isfinite(val)`** (catching valid JSON numeric exponents like
    `{"overflow": 1e400}` or `{"neg": -1e400}` that overflow IEEE-754 double to `inf`/`-inf` without
    invoking `parse_constant`!). Any non-finite float, depth violation, parse error, non-dict root,
    or oversize cell triggers the safe fallback (`metadata = {}`, `malformed_metadata = True`).
  - Caps surviving dict entries (`<= 32`) and list items (`<= 32`).
- **Untrusted prose & display strings (`summary_text`, `title`, `artifact.label`):**
  - Fetched as bounded SQL **BLOB** prefixes (`16384` B for `summary_text`, `1024` B for `title`
    and `label`), avoiding SQLite's `TEXT` NUL-truncation behavior and preserving embedded `b"\x00"`
    for detection.
  - When `original_bytes > len(raw_blob)`, `_trim_incomplete_utf8_tail()` backs up at most 3 trailing
    UTF-8 continuation bytes so a multibyte character split across the BLOB boundary decodes cleanly;
    truly invalid UTF-8 decodes with `errors="replace"` and sets `malformed_metadata = True` and
    `has_control_or_bidi = True`.
  - Emits explicit `text_suffix_uninspected = (original_summary_bytes > inspected_utf8_bytes)`.

### 5.2 Defense-in-Depth Scrubbing & Secret Redaction

Every projected text and metadata field passes through a deterministic two-stage scrubber +
redactor so **zero ANSI/C1 escapes, BiDi controls, NULs, surrogates, or matches for the enumerated
credential patterns** ever leave the projection (note: Stage-2 free-form text redaction provides
deterministic coverage of the enumerated credential patterns below rather than universal detection
of arbitrary unlabeled prose secrets):

1. **Stage 1 — ANSI / 8-Bit C1 / Control / BiDi / NUL / Surrogate Scrubbing:**
   - Strip complete escape & 8-bit C1 sequences first (in strict precedence order):
     1. 7-bit CSI: `\x1b\[[0-?]*[ -/]*[@-~]`
     2. 8-bit C1 CSI: `\x9b[0-?]*[ -/]*[@-~]`
     3. 7-bit OSC (terminated by BEL, 8-bit ST `\x9c`, 7-bit ST `\x1b\\`, OR unterminated):
        `\x1b\][^\x07\x9c\x1b]*(?:\x07|\x9c|\x1b\\)?`
     4. 8-bit C1 OSC (terminated OR unterminated):
        `\x9d[^\x07\x9c\x1b]*(?:\x07|\x9c|\x1b\\)?`
     5. 7-bit DCS/SOS/PM/APC (terminated by 8-bit ST `\x9c`, 7-bit ST `\x1b\\`, OR unterminated):
        `\x1b[P^_X][^\x9c\x1b]*(?:\x9c|\x1b\\)?`
     6. 8-bit C1 DCS/SOS/PM/APC:
        `[\x90\x98\x9e\x9f][^\x9c\x1b]*(?:\x9c|\x1b\\)?`
     7. Multi-byte / 3-byte ESC intermediate sequences (nF): `\x1b[ -/]+[0-~]`
     8. 2-byte ESC Fp/Fe/Fs sequences (widened to strip `ESC 7`, `ESC 8`, `ESC c`, etc.):
        `\x1b[0-~]`
   - Strip any trailing incomplete 7-bit ESC or 8-bit C1 CSI sequence split across a truncated BLOB
     prefix boundary:
     `(?:(?:\x1b(?:\[[0-?]*[ -/]*|\][^\x07\x9c\x1b]*|[P^_X][^\x9c\x1b]*|[ -/]+)?)|(?:\x9b[0-?]*[ -/]*))$`
   - For multiline `summary_text`: normalize `\r\n` -> `\n`, permit `\n` and `\t`, and strip bare
     `\r`, NUL (`\x00`), all other C0 (`0x00..0x1F`), DEL (`0x7F`), C1 (`0x80..0x9F`), lone
     surrogates (`0xD800..0xDFFF`), and all Unicode BiDi controls (`_BIDI_CODEPOINTS`: `U+061C`,
     `U+200E`, `U+200F`, `U+202A..U+202E`, `U+2066..U+2069`).
   - For single-line strings (`title`, `label`, `metadata` keys/values): collapse `\r\n`/`\r`/`\n`/`\t`
     to spaces, strip all escape/C0/DEL/C1/BiDi/surrogate codepoints, and cap to
     `MAX_METADATA_TEXT_BYTES` (`256` B; keys capped to `MAX_METADATA_KEY_BYTES = 64` B after
     sensitive-key and credential-pattern checks).
   - Any escape sequence, bare `\r`, NUL, forbidden control, C1, surrogate, invalid UTF-8 byte, or
     BiDi codepoint detected in `summary_text` sets `has_control_or_bidi = True` AND is removed from
     the emitted string.
2. **Stage 2 — Sensitive Key Stripping & Enumerated Credential-Pattern Redaction (`redaction_applied`):**
   - **SQL layer:** Sensitive columns (`env_vars`, `auth_header`, `token`, `password`, `private_key`,
     `awakeable_token_hash`, etc.) are never included in any `SELECT` column list.
   - **Enumerated credential-pattern redactor (`redact_sensitive_text` & `contains_credential_pattern`,
     applied to `summary_text`, `title`, `label`, surviving `metadata` string values, surviving
     `metadata` keys, AND all projected identifiers `review_id`, `run_id`, `step_id`, `artifact_id`,
     `target_incarnation_id`, `workflow_id`, `target_addr` before serialization or cursor encoding):**
     Replaces matches with `"[REDACTED]"` (or preserves key/scheme prefix as shown) and reports
     `redacted = True`:
     1. Bounded PEM private key blocks (including prefix-truncated blocks terminating at `$`):
        `-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]{0,32}PRIVATE KEY-----|$)`
        -> `"[REDACTED]"`
     2. URL basic-auth credentials:
        `(?i)((?:https?|postgres(?:ql)?|redis|ftp|sftp)://)[^\s/@:]+:[^\s/@]+@`
        -> `\1[REDACTED]@`
     3. HTTP/Bearer/Basic auth credentials:
        `(?i)\b(?:authorization\s*[:=]\s*)?(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{4,}`
        -> `"[REDACTED]"`
     4. Multi-token header lines (quoted JSON or unquoted line for non-Bearer/Basic `Authorization`,
        `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `Auth-Header`):
        - Quoted: `(?i)(?<![A-Za-z0-9_.-])((?:proxy[_-]?)?authorization|set[_-]?cookie|cookie|auth[_-]?header)(["']\s*[:=]\s*)(?:"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$))`
          -> `\1\2[REDACTED]`
        - Unquoted line: `(?i)(?<![A-Za-z0-9_.-])((?:proxy[_-]?)?authorization|set[_-]?cookie|cookie|auth[_-]?header)(\s*[:=]\s*)[^\r\n"'}{]+`
          -> `\1\2[REDACTED]`
     5. Known credential token prefixes & JWTs (including EOF-truncated 2nd/3rd JWT segments):
        `sk-ant-[A-Za-z0-9_-]{8,}`, `sk-[A-Za-z0-9_-]{8,}`, `ghp_[A-Za-z0-9]{8,}`,
        `gho_[A-Za-z0-9]{8,}`, `github_pat_[A-Za-z0-9_]{8,}`, `AKIA[0-9A-Z]{12,}`,
        `AIza[0-9A-Za-z_-]{12,}`, `xox[bpoas]-[0-9A-Za-z-]{8,}`, `ocjob_[A-Za-z0-9_-]{6,}`,
        `ocpeer_[A-Za-z0-9_-]{6,}`, and
        `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}(?:\.(?:[A-Za-z0-9_-]{8,}|[A-Za-z0-9_-]*$)|$)`
        -> `"[REDACTED]"`
     6. Inline / env-var-prefixed / JSON-serialized / EOF-truncated-quote KV secret assignments:
        `(?i)(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{0,48}(?:password|passwd|pwd|api[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|auth[_-]?header|authorization|cookie|set[_-]?cookie|credential|awakeable[_-]?token[_-]?hash|private[_-]?key|client[_-]?secret|secret[_-]?key|secret|token))(["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|[^\s"',;}{]+)`
        -> `\1\2[REDACTED]`
   - **Recursive untruncated normalized `metadata_json` key denylist + key pattern redaction +
     deterministic collision handling (runs at ALL nesting depths BEFORE key truncation):**
     - For every `dict` at depth `0..MAX_JSON_DEPTH` (including dicts nested inside dicts and
       lists), iterate `(raw_key, val)` in deterministic `sorted()` key order:
       1. Non-`str` keys set `malformed_metadata = True` and are skipped.
       2. Scrub ANSI/C1/control/bidi/NUL/surrogate from the **full untruncated** `raw_key` ->
          `full_key` (stripped). Empty `full_key` sets `malformed_metadata = True` and is skipped.
       3. Normalize `norm_key = re.sub(r"[\s_-]+", "", full_key.lower())`. If `norm_key` equals or
          contains any token in `("envvars", "authheader", "authorization", "proxyauthorization",
          "cookie", "setcookie", "token", "secret", "password", "passwd", "pwd", "privatekey",
          "apikey", "accesskey", "clientsecret", "bearer", "credential", "xapikey", "xauthtoken",
          "xgoogapikey", "awakeabletokenhash")`, **drop the entire key-value pair** and set
          `redaction_applied = True`.
       4. Run `redact_sensitive_text(full_key)` on the **full untruncated** `full_key`. If ANY
          Stage-2 credential pattern matches the key (e.g., `{"sk-ant-secret123456": "ok"}` or
          `{"Bearer eyJ...": "ok"}`), **drop the entire key-value pair** and set
          `redaction_applied = True`.
       5. Truncate surviving `full_key` to `MAX_METADATA_KEY_BYTES` (`64` B).
       6. **Deterministic collision rule:** If `truncated_key` already exists in `out` (two distinct
          raw keys collided after scrubbing or 64-byte truncation), **keep the first key in sorted
          order, drop the colliding duplicate, and set `malformed_metadata = True`**.
       7. Recursively sanitize and redact `val` (enforcing `<= MAX_METADATA_KEYS` keys and
          `<= MAX_METADATA_LIST_ITEMS` items; exceeding caps sets `malformed_metadata = True`).
3. **Unconditional untrusted provenance flag:** Every projected `InboxItem` emits
   `untrusted_content = True` for agent-authored `summary_text` (never promoting untrusted summary
   prose to operator authority).

---

## 6. Hard Bounds, Dataclass Contracts, Cursors, & Three Read APIs

### 6.1 Constants, Wire-Size Math, & Exact Frozen Dataclass Contracts (`oc_inbox_contract.py`)

```python
INBOX_SCHEMA_VERSION = "oc.n3.readonly_inbox@1"
REVIEW_PIN_DOMAIN = "oc-n3-inbox-review-pin-v1:"

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 100
MAX_ARTIFACTS_PER_ITEM = 16
MIN_RESPONSE_BYTES = 2048
MAX_RESPONSE_BYTES = 256 * 1024        # 256 KiB hard ceiling on complete UTF-8 JSON
DEFAULT_MAX_RESPONSE_BYTES = MAX_RESPONSE_BYTES
MAX_ITEM_TEXT_BYTES = 16 * 1024        # 16 KiB SQL BLOB prefix fetch per summary
MAX_METADATA_TEXT_BYTES = 256
MAX_METADATA_KEY_BYTES = 64
MAX_METADATA_KEYS = 32
MAX_METADATA_LIST_ITEMS = 32
SQL_MAX_CELL_BYTES = 65_536
MAX_JSON_DEPTH = 8
MAX_CURSOR_BYTES = 512
MAX_PRIORITY_RANK = 100
DEFAULT_MAX_READ_MS = 2000
MIN_READ_MS = 50
MAX_READ_MS = 10_000
MAX_SQLITE_INT64 = (1 << 63) - 1
```

All integer bounds (`limit`, `max_response_bytes`, `max_read_ms`, `session_generation`) reject
`bool`, non-`int`, and out-of-range values with `CoordValidationError`.

**Exact wire-size math justifying `MIN_RESPONSE_BYTES = 2048`:**
- Minimal 1-item `InboxPage` (empty `summary_text`, empty `metadata`, 3x 64-hex SHA-256 digests,
  `has_more=True`, typical `next_cursor`, `read_session`): **`1,401` UTF-8 bytes** (`647` B
  headroom inside `2,048` B for summary + metadata).
- Minimal 1-item `InboxPage` with **worst-case max-length cursor** (96-char `review_id` +
  `MAX_SQLITE_INT64` `seq` and `ss`, `281` B cursor): **`1,562` UTF-8 bytes** (`486` B headroom
  inside `2,048` B). *(If an adversarial row carries max-length 256 B `title` plus multiple 96 B
  tokens that exceed `2,048` B even with empty summary/metadata, packing fails closed with explicit
  `CoordValidationError("response_budget_too_small_for_item")`.)*
- Minimal `InboxItemDetailSnapshot` (`artifact_refs=()`, `read_session`): **`1,325` UTF-8 bytes**
  (`723` B headroom inside `2,048` B).
- `InboxSummarySnapshot` (`read_session` included): **`515` UTF-8 bytes** (`1,533` B headroom inside
  `2,048` B).

**Exact frozen dataclasses (`@dataclass(frozen=True, slots=True)`, EVERY constructor strictly
`<= 12` params including `self`, SonarCloud `S107`-clean):**

1. **`ReadSessionEcho`** (2 fields, 3 `__init__` params):
   `read_session_id: str`, `session_generation: int`.
2. **`InboxArtifactRef`** (10 fields, 11 `__init__` params):
   `artifact_id: str | None`, `blob_sha256: str | None`, `size_bytes: int`, `media_type: str`,
   `label: str`, `label_truncated: bool`, `is_primary: bool`, `created_at: float`,
   `redaction_applied: bool`, `malformed_metadata: bool`.
3. **`InboxItemIdentity`** (8 fields, 9 `__init__` params):
   `review_id: str`, `run_id: str | None`, `workflow_id: str | None`, `step_id: str | None`,
   `checkpoint_seq: int`, `item_revision: int`, `target_addr: str | None`,
   `target_incarnation_id: str | None`.
4. **`InboxItemState`** (10 fields, 11 `__init__` params):
   `status: str`, `severity: str`, `priority_rank: int`, `lane_paused: bool`,
   `requires_human_review: bool`, `source_kind: str`, `created_at: float`, `updated_at: float`,
   `expires_at: float | None`, `malformed_metadata: bool`.
5. **`InboxItemPresentation`** (9 fields, 10 `__init__` params):
   `title: str`, `title_truncated: bool`, `summary_text: str`, `text_truncated: bool`,
   `text_suffix_uninspected: bool`, `original_text_bytes: int`, `has_control_or_bidi: bool`,
   `untrusted_content: bool`, `redaction_applied: bool`.
6. **`InboxItemPinStatus`** (7 fields, 8 `__init__` params):
   `artifact_sha256: str | None`, `policy_digest: str | None`, `review_pin_sha256: str | None`,
   `pin_verified: bool`, `pin_anomaly: bool`, `anomaly_reason: str | None`, `review_ready: bool`.
7. **`InboxItem`** (6 fields, 7 `__init__` params; plus read-only convenience `@property` accessors
   for `review_id`, `run_id`, `status`, `severity`, `lane_paused`, `source_kind`, `summary_text`,
   `pin_verified`, `pin_anomaly`, `anomaly_reason`, `review_ready`, `malformed_metadata`):
   `identity: InboxItemIdentity`, `state: InboxItemState`, `presentation: InboxItemPresentation`,
   `pin: InboxItemPinStatus`, `metadata: Mapping[str, Any]`, `metadata_truncated: bool`.
   *(Serializes cleanly as `{"identity": ..., "state": ..., "presentation": ..., "pin": ..., "metadata": ..., "metadata_truncated": ...}`. `review_ready` reflects offline structural + cryptographic pin readiness only; see §4.2.)*
8. **`InboxPage`** (6 fields, 7 `__init__` params):
   `schema_version: str`, `snapshot_seq: int`, `items: tuple[InboxItem, ...]`, `has_more: bool`,
   `next_cursor: str | None`, `read_session: ReadSessionEcho | None`.
9. **`InboxItemDetailSnapshot`** (7 fields, 8 `__init__` params):
   `schema_version: str`, `snapshot_seq: int`, `item: InboxItem`,
   `artifact_refs: tuple[InboxArtifactRef, ...]`, `artifact_refs_truncated: bool`,
   `artifacts_malformed: bool`, `read_session: ReadSessionEcho | None`.
10. **`InboxSummarySnapshot`** (11 fields, 12 `__init__` params):
    `schema_version: str`, `snapshot_seq: int`, `total_items: int`,
    `counts_by_status: Mapping[str, int]`, `counts_by_severity: Mapping[str, int]`,
    `pending_by_severity: Mapping[str, int]`, `paused_lanes_count: int`,
    `requires_human_review_count: int`, `malformed_rows_count: int`,
    `pin_verification_scope: str` (`"item_read_only"`), `read_session: ReadSessionEcho | None`.

### 6.2 Collision-Free Base64url Canonical JSON Cursor Codec (Snapshot-Seq Bound)

Because opaque tokens permit `:`, cursors use canonical base64url-encoded JSON with `"v1."` prefix
(never `:`-delimited strings):

```text
cursor = "v1." + base64url_nopad(json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True, allow_nan=False).encode("utf-8"))
```

- **Keyset total order for `list_inbox_items`:**
  `(effective_priority DESC, effective_seq ASC, _ord_rid ASC)` computed inside a SQL CTE
  (`WITH ranked AS (...)`) so SQLite accepts `effective_priority` and `effective_seq` in the outer
  `WHERE` and `ORDER BY` clauses:
  - `effective_priority = CASE WHEN typeof(r.priority_rank) = 'integer' AND r.priority_rank BETWEEN 0 AND 100 THEN r.priority_rank ELSE 0 END`
  - `effective_seq = CASE WHEN typeof(r.checkpoint_seq) = 'integer' AND r.checkpoint_seq >= 0 THEN r.checkpoint_seq ELSE 9223372036854775807 END`
  - Because `effective_priority` is always an integer in `0..100`, `effective_seq` is always an
    integer in `0..MAX_SQLITE_INT64`, and `review_id` is the `PRIMARY KEY`, every row (including
    rows with tampered `priority_rank` or `checkpoint_seq` storage classes) occupies a unique,
    strictly ordered, bounded cursor position without skipping or crashing pagination.
- **Cursor payload (bound to `snapshot_seq` via `"ss"`):**
  `{"op": "inbox_list", "fh": "<16-hex>", "ss": snapshot_seq, "pr": int, "seq": int, "rid": "<review_id>"}`.
- **Strict decode validation:**
  - `isinstance(raw, str)`, `len(raw.encode("utf-8", errors="surrogatepass")) <= MAX_CURSOR_BYTES`,
    starts with `"v1."`, strict `[A-Za-z0-9_-]+` alphabet (no `=` padding), valid base64 length.
  - JSON decoded with `parse_constant=_reject_json_constant` catching `(ValueError, RecursionError)`,
    plus recursive finite-float rejection (blocking `1e400` overflow).
  - Canonical re-encoding must equal the exact input string (`encode_cursor(parsed) == raw`),
    rejecting whitespace, key-order, or base64-bit malleability.
  - Validates `"op" == "inbox_list"` and `"fh" == expected_scope_hash` (16-hex SHA-256 prefix over
    canonical `{"op": "inbox_list", "params": {"run_id": run_id, "statuses": statuses}}`); mismatch
    raises `CoordValidationError("cursor_scope_mismatch")`.
  - Validates `type(ss) is int and 0 <= ss <= MAX_SQLITE_INT64`,
    `type(pr) is int and 0 <= pr <= MAX_PRIORITY_RANK`,
    `type(seq) is int and 0 <= seq <= MAX_SQLITE_INT64`, wrapped
    `validate_opaque_token(rid, "review_id")`, and `not contains_credential_pattern(rid)` (rejecting
    credential-shaped cursor IDs as `CoordValidationError("cursor_malformed")` with zero echo).
- **Cross-page snapshot fencing & writer-side `inbox_seq_counter` contract:**
  - **Explicit fixture/daemon writer invariant:** Every projection-visible mutation (inserts,
    updates, or deletes on `review_items`, `workflow_runs`, or `review_artifacts`) MUST advance
    `inbox_seq_counter.last_seq` inside the **same** SQLite write transaction so `snapshot_seq`
    detects every cross-page change (and rolled-back transactions leave `last_seq` unchanged).
  - Inside `open_readonly_inbox_snapshot`, immediately after reading
    `snapshot_seq = read_inbox_seq_counter(conn, deadline)`, if `parsed_cursor is not None` and
    `snapshot_seq != parsed_cursor.snapshot_seq`, fail closed with
    `CoordValidationError("cursor_snapshot_changed")` so callers restart cleanly from page 1 rather
    than observing silent skips or duplicates after a concurrent priority, status, run, or artifact
    update!

### 6.3 Exact SQL & Walkthrough of the Three Read APIs

#### API 1: `list_inbox_items`

**Exact CTE-wrapped SQL query** (the outer `SELECT` enumerates ONLY the gated columns — never
returning `_ord_rid` to Python — so an oversized BLOB in `r.review_id` never crosses into Python
and fails closed as `review_id = NULL` -> `CoordPolicyError("inbox_db_unreadable")`):

```sql
WITH ranked AS (
    SELECT
        r.review_id AS _ord_rid,
        CASE WHEN typeof(r.review_id) = 'text' AND LENGTH(CAST(r.review_id AS BLOB)) <= 96
             THEN r.review_id ELSE NULL END AS review_id,
        CASE WHEN typeof(r.run_id) = 'text' AND LENGTH(CAST(r.run_id AS BLOB)) <= 96
             THEN r.run_id ELSE NULL END AS run_id,
        (typeof(r.run_id) != 'text' OR LENGTH(CAST(r.run_id AS BLOB)) > 96) AS run_id_malformed,
        CASE WHEN typeof(r.step_id) = 'text' AND LENGTH(CAST(r.step_id AS BLOB)) <= 96
             THEN r.step_id ELSE NULL END AS step_id,
        (typeof(r.step_id) != 'text' OR LENGTH(CAST(r.step_id AS BLOB)) > 96) AS step_id_malformed,
        CASE WHEN typeof(r.checkpoint_seq) = 'integer' AND r.checkpoint_seq >= 0
             THEN r.checkpoint_seq ELSE NULL END AS checkpoint_seq,
        (typeof(r.checkpoint_seq) != 'integer' OR r.checkpoint_seq < 0) AS checkpoint_seq_malformed,
        CASE WHEN typeof(r.checkpoint_seq) = 'integer' AND r.checkpoint_seq >= 0
             THEN r.checkpoint_seq ELSE 9223372036854775807 END AS effective_seq,
        CASE WHEN typeof(r.item_revision) = 'integer' AND r.item_revision >= 1
             THEN r.item_revision ELSE NULL END AS item_revision,
        (typeof(r.item_revision) != 'integer' OR r.item_revision < 1) AS item_revision_malformed,
        CASE WHEN typeof(r.status) = 'text' AND LENGTH(CAST(r.status AS BLOB)) <= 64
             THEN r.status ELSE NULL END AS status,
        (typeof(r.status) != 'text' OR LENGTH(CAST(r.status AS BLOB)) > 64) AS status_malformed,
        CASE WHEN typeof(r.severity) = 'text' AND LENGTH(CAST(r.severity AS BLOB)) <= 64
             THEN r.severity ELSE NULL END AS severity,
        (typeof(r.severity) != 'text' OR LENGTH(CAST(r.severity AS BLOB)) > 64) AS severity_malformed,
        CASE WHEN typeof(r.priority_rank) = 'integer' AND r.priority_rank BETWEEN 0 AND 100
             THEN r.priority_rank ELSE NULL END AS priority_rank,
        (typeof(r.priority_rank) != 'integer' OR r.priority_rank NOT BETWEEN 0 AND 100) AS priority_rank_malformed,
        CASE WHEN typeof(r.priority_rank) = 'integer' AND r.priority_rank BETWEEN 0 AND 100
             THEN r.priority_rank ELSE 0 END AS effective_priority,
        CASE WHEN typeof(r.lane_paused) = 'integer' AND r.lane_paused IN (0, 1)
             THEN r.lane_paused ELSE NULL END AS lane_paused,
        (typeof(r.lane_paused) != 'integer' OR r.lane_paused NOT IN (0, 1)) AS lane_paused_malformed,
        CASE WHEN typeof(r.requires_human_review) = 'integer' AND r.requires_human_review IN (0, 1)
             THEN r.requires_human_review ELSE NULL END AS requires_human_review,
        (typeof(r.requires_human_review) != 'integer' OR r.requires_human_review NOT IN (0, 1)) AS requires_human_review_malformed,
        CASE WHEN typeof(r.source_kind) = 'text' AND LENGTH(CAST(r.source_kind AS BLOB)) <= 64
             THEN r.source_kind ELSE NULL END AS source_kind,
        (typeof(r.source_kind) != 'text' OR LENGTH(CAST(r.source_kind AS BLOB)) > 64) AS source_kind_malformed,
        CASE WHEN r.target_addr IS NULL THEN NULL
             WHEN typeof(r.target_addr) = 'text' AND LENGTH(CAST(r.target_addr AS BLOB)) <= 256
             THEN r.target_addr ELSE NULL END AS target_addr,
        (r.target_addr IS NOT NULL AND (typeof(r.target_addr) != 'text' OR LENGTH(CAST(r.target_addr AS BLOB)) > 256)) AS target_addr_malformed,
        CASE WHEN r.target_incarnation_id IS NULL THEN NULL
             WHEN typeof(r.target_incarnation_id) = 'text' AND LENGTH(CAST(r.target_incarnation_id AS BLOB)) <= 96
             THEN r.target_incarnation_id ELSE NULL END AS target_incarnation_id,
        (r.target_incarnation_id IS NOT NULL AND (typeof(r.target_incarnation_id) != 'text' OR LENGTH(CAST(r.target_incarnation_id AS BLOB)) > 96)) AS target_incarnation_id_malformed,
        SUBSTR(CAST(r.title AS BLOB), 1, 1024) AS title_blob,
        LENGTH(CAST(r.title AS BLOB)) AS title_bytes,
        (typeof(r.title) != 'text') AS title_non_text,
        SUBSTR(CAST(r.summary_text AS BLOB), 1, 16384) AS summary_blob,
        LENGTH(CAST(r.summary_text AS BLOB)) AS original_summary_bytes,
        (typeof(r.summary_text) != 'text') AS summary_non_text,
        CASE WHEN typeof(r.artifact_sha256) = 'text' AND LENGTH(CAST(r.artifact_sha256 AS BLOB)) = 64
             THEN r.artifact_sha256 ELSE NULL END AS artifact_sha256,
        (typeof(r.artifact_sha256) != 'text' OR LENGTH(CAST(r.artifact_sha256 AS BLOB)) != 64) AS artifact_sha256_malformed,
        CASE WHEN typeof(r.policy_digest) = 'text' AND LENGTH(CAST(r.policy_digest AS BLOB)) = 64
             THEN r.policy_digest ELSE NULL END AS policy_digest,
        (typeof(r.policy_digest) != 'text' OR LENGTH(CAST(r.policy_digest AS BLOB)) != 64) AS policy_digest_malformed,
        CASE WHEN typeof(r.review_pin_sha256) = 'text' AND LENGTH(CAST(r.review_pin_sha256 AS BLOB)) = 64
             THEN r.review_pin_sha256 ELSE NULL END AS review_pin_sha256,
        (typeof(r.review_pin_sha256) != 'text' OR LENGTH(CAST(r.review_pin_sha256 AS BLOB)) != 64) AS review_pin_sha256_malformed,
        CASE WHEN typeof(r.metadata_json) = 'text' AND LENGTH(CAST(r.metadata_json AS BLOB)) <= 65536
             THEN CAST(r.metadata_json AS BLOB) ELSE NULL END AS metadata_blob,
        LENGTH(CAST(r.metadata_json AS BLOB)) AS metadata_bytes,
        (typeof(r.metadata_json) != 'text' OR LENGTH(CAST(r.metadata_json AS BLOB)) > 65536) AS metadata_malformed,
        CASE WHEN typeof(r.created_at) IN ('integer', 'real') THEN r.created_at ELSE NULL END AS created_at,
        (typeof(r.created_at) NOT IN ('integer', 'real')) AS created_at_malformed,
        CASE WHEN typeof(r.updated_at) IN ('integer', 'real') THEN r.updated_at ELSE NULL END AS updated_at,
        (typeof(r.updated_at) NOT IN ('integer', 'real')) AS updated_at_malformed,
        CASE WHEN r.expires_at IS NULL THEN NULL
             WHEN typeof(r.expires_at) IN ('integer', 'real') THEN r.expires_at ELSE NULL END AS expires_at,
        (r.expires_at IS NOT NULL AND typeof(r.expires_at) NOT IN ('integer', 'real')) AS expires_at_malformed,
        (w.run_id IS NOT NULL) AS workflow_run_present,
        CASE WHEN w.run_id IS NULL THEN NULL
             WHEN typeof(w.workflow_id) = 'text' AND LENGTH(CAST(w.workflow_id AS BLOB)) <= 128
             THEN w.workflow_id ELSE NULL END AS workflow_id,
        (w.run_id IS NOT NULL AND (typeof(w.workflow_id) != 'text' OR LENGTH(CAST(w.workflow_id AS BLOB)) > 128)) AS workflow_id_malformed,
        CASE WHEN w.run_id IS NULL THEN NULL
             WHEN typeof(w.policy_digest) = 'text' AND LENGTH(CAST(w.policy_digest AS BLOB)) = 64
             THEN w.policy_digest ELSE NULL END AS run_policy_digest,
        (w.run_id IS NOT NULL AND (typeof(w.policy_digest) != 'text' OR LENGTH(CAST(w.policy_digest AS BLOB)) != 64)) AS run_policy_digest_malformed
    FROM review_items r
    LEFT JOIN workflow_runs w ON typeof(r.run_id) = 'text' AND w.run_id = r.run_id
    WHERE 1 = 1
      -- optional: AND typeof(r.status) = 'text' AND r.status IN (?, ...)
      -- optional: AND typeof(r.run_id) = 'text' AND r.run_id = ?
)
SELECT
    review_id, run_id, run_id_malformed, step_id, step_id_malformed,
    checkpoint_seq, checkpoint_seq_malformed, effective_seq,
    item_revision, item_revision_malformed, status, status_malformed,
    severity, severity_malformed, priority_rank, priority_rank_malformed, effective_priority,
    lane_paused, lane_paused_malformed, requires_human_review, requires_human_review_malformed,
    source_kind, source_kind_malformed, target_addr, target_addr_malformed,
    target_incarnation_id, target_incarnation_id_malformed,
    title_blob, title_bytes, title_non_text,
    summary_blob, original_summary_bytes, summary_non_text,
    artifact_sha256, artifact_sha256_malformed,
    policy_digest, policy_digest_malformed,
    review_pin_sha256, review_pin_sha256_malformed,
    metadata_blob, metadata_bytes, metadata_malformed,
    created_at, created_at_malformed, updated_at, updated_at_malformed,
    expires_at, expires_at_malformed,
    workflow_run_present, workflow_id, workflow_id_malformed,
    run_policy_digest, run_policy_digest_malformed
FROM ranked
-- optional cursor predicate (matches ORDER BY total order without skipping BLOB PKs!):
-- WHERE (effective_priority < ?)
--    OR (effective_priority = ? AND effective_seq > ?)
--    OR (effective_priority = ? AND effective_seq = ? AND _ord_rid > ?)
ORDER BY effective_priority DESC, effective_seq ASC, _ord_rid ASC
LIMIT ?
```

**Flow & byte-budget packing rules (`list_inbox_items`):**

1. Validate `caller`, `statuses` (closed enum, rejects `str`/`bytes`/empty), optional `run_id`
   (wrapped `validate_opaque_token`), `limit` (`1..MAX_PAGE_LIMIT`), `max_response_bytes`
   (`MIN_RESPONSE_BYTES=2048..MAX_RESPONSE_BYTES`), `max_read_ms` (`50..10_000`), session pair, and
   `after_cursor`.
2. Run pre-read `session_validator` & `live_authority_checker` and verification-only filesystem
   admission.
3. Open `open_readonly_inbox_snapshot(db_path, deadline=deadline)`, read `snapshot_seq`, verify
   `parsed_cursor.snapshot_seq == snapshot_seq` (else `CoordValidationError("cursor_snapshot_changed")`),
   and fetch `limit + 1` rows via the CTE query above.
4. Check empty `InboxPage` with worst-case `next_cursor` fits `<= max_bytes`, else raise
   `CoordValidationError("response_budget_too_small_for_envelope")`.
5. Admit items `idx = 0..min(limit, len(rows)) - 1` one by one, calling `check_deadline_ms(deadline)`
   on every iteration:
   - Compute `remaining_exists = (idx + 1 < len(rows))`.
   - Measure `candidate_page` **including actual `has_more = remaining_exists` and the actual
     `next_cursor` encoded with `(scope_hash, snapshot_seq, effective_priority, effective_seq, review_id)`
     for item `idx` whenever `remaining_exists` is `True`** (never measuring with
     `next_cursor = None` when `has_more` will become `True`).
   - **First-item shrinking (`idx == 0`):**
     1. If item `0` does not fit, binary-search `presentation.summary_text` character length
        (`text_truncated = True`, deadline-checked per step) while measuring with actual
        `(has_more, next_cursor)`.
     2. If even zero-length `summary_text` does not fit while `item.metadata` is non-empty, drop
        `metadata` (`metadata = {}`, `metadata_truncated = True`) and **re-run binary search
        against the original scrubbed `summary_text`** so the freed metadata bytes can hold summary
        text.
     3. If even a zero-summary, empty-metadata first item cannot fit, raise
        `CoordValidationError("response_budget_too_small_for_item")`.
   - **Subsequent items (`idx > 0`):** If `candidate_page` with actual `(has_more, next_cursor)`
     exceeds `max_bytes`, stop before adding item `idx`, finalize `has_more = True` and
     `next_cursor` from item `idx - 1` (already proven to fit when `idx - 1` was measured with
     `remaining_exists = True`).
6. Perform final post-serialization assertion `len(serialize_inbox_bytes(page)) <= max_bytes` +
   `check_deadline_ms(deadline)`, close SQLite snapshot, run post-read authority/session fences,
   and return `page`.

#### API 2: `get_inbox_item`

1. Validate `caller`, required `review_id` (wrapped `validate_opaque_token`), `max_response_bytes`
   (`MIN_RESPONSE_BYTES=2048..MAX_RESPONSE_BYTES`), `max_read_ms`, and session pair.
2. Run pre-read authority/session fences + verification-only filesystem admission.
3. Inside `open_readonly_inbox_snapshot`: read `snapshot_seq`, select the single row by
   `WHERE typeof(r.review_id) = 'text' AND r.review_id = ?` (missing ->
   `CoordPolicyError("review_item_not_found")`), and build the verified `InboxItem` (running the
   identical 7-step verification pipeline as `list_inbox_items`).
4. Fetch bounded `review_artifacts` (`select_item_artifacts`, `LIMIT MAX_ARTIFACTS_PER_ITEM + 1`):
   ```sql
   SELECT
       CASE WHEN typeof(artifact_id) = 'text' AND LENGTH(CAST(artifact_id AS BLOB)) <= 96
            THEN artifact_id ELSE NULL END AS artifact_id,
       (typeof(artifact_id) != 'text' OR LENGTH(CAST(artifact_id AS BLOB)) > 96) AS artifact_id_malformed,
       CASE WHEN typeof(blob_sha256) = 'text' AND LENGTH(CAST(blob_sha256 AS BLOB)) = 64
            THEN blob_sha256 ELSE NULL END AS blob_sha256,
       (typeof(blob_sha256) != 'text' OR LENGTH(CAST(blob_sha256 AS BLOB)) != 64) AS blob_sha256_malformed,
       CASE WHEN typeof(size_bytes) = 'integer' AND size_bytes >= 0
            THEN size_bytes ELSE NULL END AS size_bytes,
       (typeof(size_bytes) != 'integer' OR size_bytes < 0) AS size_bytes_malformed,
       CASE WHEN typeof(media_type) = 'text' AND LENGTH(CAST(media_type AS BLOB)) <= 128
            THEN media_type ELSE NULL END AS media_type,
       (typeof(media_type) != 'text' OR LENGTH(CAST(media_type AS BLOB)) > 128) AS media_type_malformed,
       SUBSTR(CAST(label AS BLOB), 1, 1024) AS label_blob,
       LENGTH(CAST(label AS BLOB)) AS label_bytes,
       (typeof(label) != 'text') AS label_non_text,
       CASE WHEN typeof(is_primary) = 'integer' AND is_primary IN (0, 1)
            THEN is_primary ELSE NULL END AS is_primary,
       (typeof(is_primary) != 'integer' OR is_primary NOT IN (0, 1)) AS is_primary_malformed,
       CASE WHEN typeof(created_at) IN ('integer', 'real') THEN created_at ELSE NULL END AS created_at,
       (typeof(created_at) NOT IN ('integer', 'real')) AS created_at_malformed
   FROM review_artifacts
   WHERE typeof(review_id) = 'text' AND review_id = ?
   ORDER BY (CASE WHEN typeof(is_primary) = 'integer' AND is_primary = 1 THEN 1 ELSE 0 END) DESC,
            artifact_id ASC
   LIMIT ?
   ```
   - **Secondary (`is_primary = 0`) artifact degradation rules:**
     - Invalid/malformed `artifact_id` (`validate_opaque_token`) -> `None`, `a.malformed_metadata = True`.
     - Invalid/malformed `blob_sha256` (`_SHA256_HEX_RE`) -> `None`, `a.malformed_metadata = True`.
     - Invalid/negative/BLOB `size_bytes` -> `0`, `a.malformed_metadata = True`.
     - Invalid/malformed `media_type` (`_MEDIA_TYPE_RE`) -> `"application/octet-stream"`, `a.malformed_metadata = True`.
     - `label` -> BLOB-decoded, Stage-1 scrubbed + Stage-2 redacted, capped to `256` B
       (`label_truncated`, `redaction_applied`; non-text/bad UTF-8 -> `a.malformed_metadata = True`).
     - Non-finite or malformed `created_at` -> `0.0`, `a.malformed_metadata = True`.
     - **Rollup consistency:** Any tampered `is_primary` (`not in {0, 1}`) or malformed primary
       artifact fails Step 6/7 identically in BOTH `list_inbox_items` and `get_inbox_item`
       (`item.pin_verified = False, item.review_ready = False`). Malformed secondary
       (`is_primary = 0`) artifact rows set `a.malformed_metadata = True` AND roll up into
       `InboxItemDetailSnapshot.artifacts_malformed = True` (preserved even if secondary artifacts are
       trimmed for byte budget) without making `item.pin_verified` diverge between
       `list_inbox_items` and `get_inbox_item`.
5. **Progressive byte-budget shrinking (deadline-checked per step):**
   1. Binary-search `item.presentation.summary_text` (`text_truncated = True`).
   2. If still over budget and `item.metadata` is non-empty, drop `item.metadata`
      (`metadata_truncated = True`) and re-run binary search against the **original scrubbed
      `summary_text`**.
   3. If still over budget, trim `artifact_refs` via binary search (`artifact_refs_truncated = True`,
      down to `0` if needed) while preserving `item.pin`, `item.state.malformed_metadata`, and
      `artifacts_malformed`, then re-attempt summary fit.
   4. If even the minimal detail envelope cannot fit, raise
      `CoordValidationError("response_budget_too_small_for_envelope")`.
6. Assert serialized size `<= max_bytes` + `check_deadline_ms(deadline)`, close SQLite snapshot,
   run post-read authority/session fences, and return `InboxItemDetailSnapshot`.

#### API 3: `get_inbox_summary`

**Signature & response-budget contract:**
```python
def get_inbox_summary(
    self,
    caller: object,
    *,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    max_read_ms: int = DEFAULT_MAX_READ_MS,
    read_session_id: str | None = None,
    session_generation: int | None = None,
) -> InboxSummarySnapshot:
```
- Validates `caller`, `MIN_RESPONSE_BYTES <= max_response_bytes <= MAX_RESPONSE_BYTES`
  (`2048..256 KiB`, rejecting `bool`/non-`int`/out-of-range), `max_read_ms` (`50..10_000`), and
  session pair.
- Runs pre-read authority/session fences + verification-only filesystem admission.
- Executes strictly **three closed-enum bounded SQL aggregate queries** inside one `BEGIN DEFERRED`
  snapshot (transferring at most `5 + 5 + 1 = 11` rows total regardless of table size):

1. **`select_status_aggregate_counts` (`<= 5` rows, zero-filled in Python for all 5 keys):**
   ```sql
   SELECT
       CASE WHEN typeof(status) = 'text'
             AND status IN ('expired', 'pending', 'resolved', 'superseded')
            THEN status ELSE 'malformed' END AS bucket,
       COUNT(*) AS cnt
   FROM review_items
   GROUP BY 1
   ```
2. **`select_severity_aggregate_counts` (`<= 5` rows, zero-filled in Python for all 5 keys):**
   ```sql
   SELECT
       CASE WHEN typeof(severity) = 'text'
             AND severity IN ('critical', 'high', 'low', 'normal')
            THEN severity ELSE 'malformed' END AS bucket,
       COUNT(*) AS cnt,
       COALESCE(SUM(CASE WHEN typeof(status) = 'text' AND status = 'pending'
                         THEN 1 ELSE 0 END), 0) AS pending_cnt
   FROM review_items
   GROUP BY 1
   ```
3. **`select_structural_summary_totals` (exactly 1 row; `COALESCE` for empty tables; strict
   `typeof(...) = 'integer'` blocking `REAL` `1.0`; `paused_lanes_count` strictly requires
   `source_kind = 'host_workflow_engine'` per `prd_n3.md:54-59`; contradictory `lane_paused = 1`
   on `orchestrator_advisory` or any non-`host_workflow_engine` source increments
   `malformed_rows_count`; `IS NOT NULL` guards on nullable columns; finite-real checks):**
   ```sql
   SELECT
       COUNT(*) AS total_items,
       COALESCE(SUM(CASE WHEN typeof(source_kind) = 'text'
                          AND source_kind = 'host_workflow_engine'
                          AND typeof(lane_paused) = 'integer'
                          AND lane_paused = 1
                         THEN 1 ELSE 0 END), 0) AS paused_lanes_count,
       COALESCE(SUM(CASE WHEN typeof(requires_human_review) = 'integer' AND requires_human_review = 1
                         THEN 1 ELSE 0 END), 0) AS requires_human_review_count,
       COALESCE(SUM(CASE WHEN
             typeof(review_id) != 'text' OR LENGTH(CAST(review_id AS BLOB)) NOT BETWEEN 1 AND 96
          OR typeof(run_id) != 'text' OR LENGTH(CAST(run_id AS BLOB)) NOT BETWEEN 1 AND 96
          OR typeof(step_id) != 'text' OR LENGTH(CAST(step_id AS BLOB)) NOT BETWEEN 1 AND 96
          OR typeof(checkpoint_seq) != 'integer' OR checkpoint_seq < 0
          OR typeof(item_revision) != 'integer' OR item_revision < 1
          OR typeof(status) != 'text' OR status NOT IN ('expired', 'pending', 'resolved', 'superseded')
          OR typeof(severity) != 'text' OR severity NOT IN ('critical', 'high', 'low', 'normal')
          OR typeof(priority_rank) != 'integer' OR priority_rank NOT BETWEEN 0 AND 100
          OR typeof(lane_paused) != 'integer' OR lane_paused NOT IN (0, 1)
          OR typeof(requires_human_review) != 'integer' OR requires_human_review NOT IN (0, 1)
          OR typeof(source_kind) != 'text' OR source_kind NOT IN ('calibration_drift', 'host_workflow_engine', 'orchestrator_advisory', 'supervision_escalation')
          OR (typeof(lane_paused) = 'integer' AND lane_paused = 1 AND (typeof(source_kind) != 'text' OR source_kind != 'host_workflow_engine'))
          OR (target_addr IS NOT NULL AND (typeof(target_addr) != 'text' OR LENGTH(CAST(target_addr AS BLOB)) NOT BETWEEN 1 AND 256))
          OR (target_incarnation_id IS NOT NULL AND (typeof(target_incarnation_id) != 'text' OR LENGTH(CAST(target_incarnation_id AS BLOB)) NOT BETWEEN 1 AND 96))
          OR typeof(title) != 'text'
          OR typeof(summary_text) != 'text'
          OR typeof(artifact_sha256) != 'text' OR LENGTH(CAST(artifact_sha256 AS BLOB)) != 64
          OR typeof(policy_digest) != 'text' OR LENGTH(CAST(policy_digest AS BLOB)) != 64
          OR typeof(review_pin_sha256) != 'text' OR LENGTH(CAST(review_pin_sha256 AS BLOB)) != 64
          OR typeof(metadata_json) != 'text' OR LENGTH(CAST(metadata_json AS BLOB)) > 65536
          OR typeof(created_at) NOT IN ('integer', 'real') OR NOT (-9e999 < created_at AND created_at < 9e999)
          OR typeof(updated_at) NOT IN ('integer', 'real') OR NOT (-9e999 < updated_at AND updated_at < 9e999)
          OR (expires_at IS NOT NULL AND (typeof(expires_at) NOT IN ('integer', 'real') OR NOT (-9e999 < expires_at AND expires_at < 9e999)))
       THEN 1 ELSE 0 END), 0) AS malformed_rows_count
   FROM review_items
   ```
- Post-serialization UTF-8 byte-budget assertion (`len(serialize_inbox_bytes(snapshot)) <= max_bytes`
  else `CoordValidationError("response_budget_too_small_for_envelope")`) +
  `check_deadline_ms(deadline)`, close SQLite snapshot, run post-read authority/session fences, and
  return `InboxSummarySnapshot`.
- **Explicit aggregate boundary honesty:** `get_inbox_summary` executes strictly bounded SQL
  aggregates over `review_items` (`<= 11` rows transferred). Accordingly, `paused_lanes_count`
  reports `host_workflow_engine` pause flags (`typeof(source_kind) = 'text' AND source_kind =
  'host_workflow_engine' AND typeof(lane_paused) = 'integer' AND lane_paused = 1`),
  `malformed_rows_count` reports row-level structural, format, and `source_kind`/`lane_paused`
  contradiction anomalies on `review_items`, and `pin_verification_scope = "item_read_only"`
  explicitly reserves cross-table cryptographic `review_pin_sha256`, `workflow_runs`, and
  `review_artifacts` verification verdicts for item reads (`list_inbox_items` and `get_inbox_item`).

---

## 7. Failure & Recovery Matrix (Pinned Exception & Diagnostic Mapping)

| Failure / Attack Condition | Exact Exception / Diagnostic Result |
|---|---|
| `caller` is not `PrincipalCtx` | `CoordValidationError("caller must be PrincipalCtx")` |
| `caller.role != CoordRole.OPERATOR` (`JOB`, `ORCHESTRATOR`, `EXTERNAL_PEER`) | `CoordAuthError("operator_role_required")` (before FS/SQLite) |
| `OPERATOR` with non-`None` `sandbox_addr` or `incarnation_id` | `CoordAuthError("operator_principal_must_not_bind_sandbox")` |
| `session_validator` configured, but `(read_session_id, session_generation)` omitted | `CoordAuthError("read_session_required")` |
| Partial session pair, invalid token (`AddressError` mapped), `bool`, `<= 0`, or `> MAX_SQLITE_INT64` `session_generation` | `CoordValidationError` |
| Session args supplied while `session_validator is None` | `CoordPolicyError("read_session_validator_unconfigured")` |
| `session_validator` returns non-`True` (including truthy `1`/`"yes"`) or raises (pre or post read) | `RevokedError("read_session_retired")` (zero data returned) |
| `live_authority_checker` returns non-`True` or raises (pre or post read) | `RevokedError("read_authority_revoked")` (zero data returned) |
| Relative/raw symlink ancestor (`sym_rel/../state`), `PermissionError`/`ENOTDIR`/NUL-byte path, symlinked `state_dir`, sandbox path, host production dir, non-`0o700` dir, missing `inbox.sqlite`, symlink/FIFO/hardlink/wrong-UID/unsafe-mode (`0o644`) on DB or `-wal`/`-shm`/`-journal` | `CoordPolicyError` (fail closed immediately; zero blocking, zero `chmod`, zero file creation, zero unmapped `OSError`/`PolicyError`/`ValueError`) |
| Surrogate-escaped POSIX `db_path` failing URI `quote()` | `CoordPolicyError("inbox_db_unreadable")` before acquiring `_UMASK_LOCK` |
| Corrupt DB, missing or non-table required objects (`inbox_seq_counter`, `review_items`, `workflow_runs`, `review_artifacts`), present SQLite `trigger`/`view` in `sqlite_master`, malformed `inbox_seq_counter.last_seq`, or read-only `0o500` dir without `-shm` | `CoordPolicyError("inbox_db_unreadable")` (rejected via `sqlite_master` BEFORE evaluating any view or user table) |
| Corrupted primary key `review_items.review_id` (non-TEXT, `> 96` B, invalid opaque token, control/bidi/NUL) OR credential-shaped required identifier (`review_id`, `run_id`, `step_id`, `artifact_id`) | Fixed `CoordPolicyError("inbox_db_unreadable")` (zero echo of raw value; never serialized or placed in `next_cursor`) |
| Credential-shaped optional/nullable identifier (`target_addr`, `target_incarnation_id`, `workflow_id`) | Clamped to `None` + `malformed_metadata = True`, `redaction_applied = True`, `pin_verified = False`, `pin_anomaly = True`, `review_ready = False` (raw value never emitted) |
| Lock wait, `_UMASK_LOCK` wait, SQL VM progress, packing loop, or post-serialization exceeds `max_read_ms` | `CoordPolicyError("read_deadline_exceeded")` (connection closed; zero `connect()` if expired before lock) |
| SQLite `"locked"` / `"busy"` before deadline | `CoordPolicyError("inbox_db_busy")` |
| Non-existent `review_id` on `get_inbox_item` | `CoordPolicyError("review_item_not_found")` |
| Malformed, oversized, padded, non-canonical, `NaN`, `1e400` overflow, deeply nested (`RecursionError`), credential-shaped `rid`, or out-of-range (`< 0`, `> MAX_SQLITE_INT64`, `bool`) cursor | `CoordValidationError("cursor_malformed")` |
| Cursor reused across different `op`, `statuses`, or `run_id` | `CoordValidationError("cursor_scope_mismatch")` |
| Cursor `snapshot_seq` (`"ss"`) != current WAL `inbox_seq_counter.last_seq` | `CoordValidationError("cursor_snapshot_changed")` (caller restarts from page 1) |
| `max_response_bytes` out of `2048..256 KiB` or too small for envelope / minimal first item | `CoordValidationError("response_budget_too_small_for_envelope" / "response_budget_too_small_for_item")` |
| Item reads (`list_inbox_items`, `get_inbox_item`): tampered `review_pin_sha256`, missing/mismatched `workflow_runs.policy_digest`, missing/ambiguous/mismatched primary `review_artifacts`, tampered `is_primary`, contradictory `source_kind != 'host_workflow_engine'` + `lane_paused = 1`, or any item-level `malformed_metadata` | `pin_verified = False`, `pin_anomaly = True`, closed-enum `anomaly_reason`, `review_ready = False` (cross-table cryptographic pin and `review_artifacts` verdicts are evaluated on item reads) |
| Summary aggregate (`get_inbox_summary`): `review_items` structural/format anomalies or contradictory `source_kind != 'host_workflow_engine'` + `lane_paused = 1` | `paused_lanes_count` counts reported `host_workflow_engine` pause flags (`typeof(source_kind)='text' AND source_kind='host_workflow_engine' AND typeof(lane_paused)='integer' AND lane_paused=1`) only; `malformed_rows_count` counts row-level structural/format/contradiction anomalies on `review_items` (`pin_verification_scope = "item_read_only"`) |
| Malformed secondary (`is_primary = 0`) artifact in `get_inbox_item` | Clean per-artifact degradation (`a.malformed_metadata = True`) + `snapshot.artifacts_malformed = True` |
| Oversized BLOB (e.g., 2 MiB) in numeric timestamp, boolean flag, `priority_rank`, `checkpoint_seq`, `metadata_json`, or `summary_text` | Blocked inside SQL `typeof()` / `LENGTH(CAST(... AS BLOB))` / `SUBSTR(CAST(... AS BLOB), 1, cap)`; bounded diagnostic fallback + `malformed_metadata = True` |
| `NaN` / `Inf` / `-Inf` SQLite `REAL`, JSON `NaN`/`Infinity` literal, JSON numeric overflow (`1e400`), or deeply nested `metadata_json` (`RecursionError`) | Safe clamped fallback (`0.0` / `None` / `{}`) + `malformed_metadata = True`; `json.dumps(..., allow_nan=False)` succeeds |
| 7-bit ANSI CSI/OSC (with `\x9c` ST)/DCS (with `\x9c` ST)/3-byte nF/2-byte `[0-~]`, 8-bit C1 CSI/OSC/DCS/SOS/PM/APC, split UTF-8, split ESC/C1, BiDi, NUL, bare CR, C0/DEL/C1, or lone surrogate | Scrubbed from output, `has_control_or_bidi = True`, `text_suffix_uninspected` accurate; zero raw escape/control leakage |
| Env-var-prefixed (`DB_PASSWORD=`), JSON-serialized (`{"password": "..."}`), EOF-truncated quoted secret, EOF-truncated JWT, URL basic-auth (`https://u:p@host`), multi-token `Authorization`/`Cookie`/`Set-Cookie`, `credential`/`awakeable_token_hash`, PEM/bearer/API-key patterns, credential patterns inside `metadata_json` **keys**, recursive/hyphenated/camelCase/`> 256` B-padded sensitive `metadata_json` keys, or extra secret DB columns | Redacted to `[REDACTED]` / dropped / unselected; `redaction_applied = True` |
| Direct write attempt on opened snapshot connection | `sqlite3.OperationalError` (`mode=ro` + `PRAGMA query_only = ON`) |

---

## 8. Open Engineering Choices Submitted for Gate 1 Review

1. **Dedicated synthetic snapshot filename (`inbox.sqlite`) under verified `0o700` `state_dir`:**
   Keeps this PRD N3 read-projection slice completely decoupled from `registry.sqlite` while
   enforcing identical filesystem, sidecar, pragma (`trusted_schema=OFF`, `cell_size_check=ON`),
   trigger/view rejection, and live-WAL invariants.
2. **Composed `InboxItem` sub-dataclasses + `MIN_RESPONSE_BYTES = 2048`:** Composing `InboxItem`
   from `InboxItemIdentity`, `InboxItemState`, `InboxItemPresentation`, and `InboxItemPinStatus`
   keeps every dataclass constructor `<= 12` params (SonarCloud `S107`-clean), and `2,048` B
   provides ~`486–723` B of real content headroom on minimal 1-item pages (`1,401` B typical /
   `1,562` B max-cursor) and detail snapshots (`1,325` B).
3. **Snapshot-bound pagination cursors (`"ss": snapshot_seq`) over CTE-wrapped
   `(effective_priority DESC, effective_seq ASC, _ord_rid ASC)`:** Rejecting stale cursors with
   `CoordValidationError("cursor_snapshot_changed")` prevents cross-page skips/duplicates after
   priority mutations while keeping the projection strictly read-only.
4. **Strict `host_workflow_engine` exclusivity for `lane_paused = 1` (`prd_n3.md:54-59`):**
   Contradictory `orchestrator_advisory` (or any non-`host_workflow_engine`) rows with
   `lane_paused = 1` fail closed consistently across all three read APIs (`list_inbox_items`,
   `get_inbox_item`, and `get_inbox_summary`).
5. **Honest aggregate & redaction scope:** `get_inbox_summary` declares
   `pin_verification_scope = "item_read_only"` (strictly `<= 11` SQL aggregate rows), and Stage-2
   prose redaction claims deterministic coverage of its enumerated credential patterns (both in
   values and in surviving `metadata_json` keys).

---

## 9. Offline Qualification & Adversarial Verification Plan (`test_inbox_read.py`)

All tests run 100% offline via:
`python3 -B -m unittest discover -s docs/prds/spikes/n/inbox-read -p 'test_*.py'`
under both default `$HOME` and `TMPDIR=/tmp` using private `0o700` temporary directories and
synthetic SQLite fixtures (zero Podman, zero network, zero writes to production host directories):

1. **Operator-only admission, `AddressError` mapping, & pre/post fencing:**
   - Reject `JOB`, root `ORCHESTRATOR`, sandbox-bound `ORCHESTRATOR`, `EXTERNAL_PEER`, `OPERATOR`
     with non-`None` `sandbox_addr` or `incarnation_id`, and non-`PrincipalCtx` BEFORE filesystem or
     SQLite access (verified with non-existent `state_dir`).
   - Verify `AddressError` inputs (non-string, NUL/bidi/control chars) passed to `read_session_id`,
     `run_id`, `review_id`, and cursor `rid` raise `CoordValidationError` (never raw `AddressError`).
   - Verify `session_validator` mandatory enforcement (omitted args -> `CoordAuthError`, partial
     pair -> `CoordValidationError`, unconfigured validator -> `CoordPolicyError`, truthy non-`True`
     return `1`/`"ok"` -> `RevokedError`, raised exception -> `RevokedError`).
   - Verify **mid-read revocation** for both `session_validator` and `live_authority_checker`
     (passes pre-read, flips to `False` before post-read) -> raises `RevokedError` and returns zero
     data.
   - Verify `ReadSessionEcho` echoed on `InboxPage`, `InboxItemDetailSnapshot`, and
     `InboxSummarySnapshot`.
2. **Verification-only filesystem admission, SQLite trigger/view rejection, & unmapped-exception defense:**
   - Missing `inbox.sqlite` raises `CoordPolicyError("inbox_db_missing")` without creating any file.
   - Relative `state_dir` traversing a user-owned symlink via `..` (`sym_rel/../state`) fails closed
     before SQLite opens (`state_dir_symlink_ancestor_rejected`).
   - `PermissionError` (e.g., `0o000` parent), `ENOTDIR` (regular file as ancestor component), and
     embedded NUL byte (`"bad\x00path"`) in `state_dir` all map cleanly to
     `CoordPolicyError("state_dir_unreadable")` (zero raw `OSError`/`ValueError`/`PolicyError`).
   - Symlinked `state_dir`, sandbox-interior `state_dir`, host production dirs, non-`0o700`
     `state_dir`, symlinked DB/sidecars, FIFO (`os.mkfifo`) at DB and `-wal`/`-shm`/`-journal`
     (completes immediately without hanging), hardlinked (`os.link`) DB/sidecar, and `0o644`
     unsafe-mode DB/sidecar all fail closed without repairing modes (`stat` mode remains `0o644`).
   - Read-only `0o500` dir without `-shm` maps cleanly to `CoordPolicyError("inbox_db_unreadable")`.
   - Hostile SQLite `VIEW`, `TRIGGER`, and `VIRTUAL TABLE` (e.g., `CREATE VIRTUAL TABLE
     review_items USING fts5(...)` or `CREATE VIRTUAL TABLE inbox_seq_counter USING fts5(...)`)
     injected into `inbox.sqlite` — **including replacing `inbox_seq_counter` itself with a `VIEW`
     or `VIRTUAL TABLE`** — fail closed via `SELECT 1 FROM sqlite_master ...` and
     `pragma_table_list` (`type = 'table'` ordinary-table check, rejecting `'virtual'`/`'shadow'`/
     `'view'`) BEFORE any view/virtual-table body or projection read is evaluated, raising
     `CoordPolicyError("inbox_db_unreadable")` with clean connection close (while valid ordinary
     tables pass cleanly); missing required objects likewise fail closed; verify
     `PRAGMA trusted_schema = OFF` and `PRAGMA cell_size_check = ON` are active on opened snapshots.
3. **Deterministic cryptographic review pins, `orchestrator_advisory` vs `lane_paused == 1`, artifacts, & IDs:**
   - Valid pending `host_workflow_engine` item (`lane_paused = 1`) with nullable `expires_at = None`,
     `target_addr = None`, `target_incarnation_id = None` passes verification cleanly
     (`malformed_metadata = False, pin_verified = True, pin_anomaly = False, review_ready = True`).
   - **Contradictory `orchestrator_advisory` + `lane_paused = 1` fixture (otherwise valid
     cryptographic pin) verified across ALL THREE APIs:**
     - `list_inbox_items` and `get_inbox_item`: clamp `lane_paused = False`, set
       `malformed_metadata = True`, `pin_verified = False`, `pin_anomaly = True`,
       `anomaly_reason = "malformed_item_metadata"`, `review_ready = False`.
     - `get_inbox_summary`: excluded from `paused_lanes_count` (`0`) AND counted in
       `malformed_rows_count` (`>= 1`).
   - Valid `target_addr` forms (`"dev"`, `"macmini / dev"`, `"@peer1"`) and valid `workflow_id`
     forms (`"builtin/prd-delivery"`, `"user/custom-gate"`) verify cleanly; malformed `target_addr`
     or `workflow_id` clamps to `None`, sets `malformed_metadata = True`, and fails Step 7.
   - Valid `superseded`, `expired`, and `resolved` items verify pin (`pin_verified = True`) yet
     report `review_ready = False`.
   - 1-bit tampered `review_pin_sha256`, missing `workflow_runs` row, mismatched
     `workflow_runs.policy_digest`, missing/duplicate primary artifacts, tampered `is_primary = 2`
     or 2 MiB BLOB in `is_primary`, mismatched `blob_sha256`, and malformed primary artifact
     `created_at`/`label` all yield `pin_verified = False, pin_anomaly = True, review_ready = False`
     consistently across `list_inbox_items` and `get_inbox_item`.
   - Secondary (`is_primary = 0`) artifact with 2 MiB BLOB / negative `size_bytes` / invalid
     `media_type` / `Inf` `created_at` / invalid `artifact_id` degrades cleanly in `get_inbox_item`
     (`a.malformed_metadata = True`, `snapshot.artifacts_malformed = True`, valid JSON).
   - Non-token `review_items.review_id` (spaces, `> 96` B, control/bidi chars, BLOB) fails closed
     at admission with `CoordPolicyError("inbox_db_unreadable")`.
   - Tampered storage class on pin inputs (BLOB in `artifact_sha256`, `review_pin_sha256`, or
     `checkpoint_seq`; TEXT in `checkpoint_seq`) -> `"tampered_storage_class"`, `review_ready = False`,
     zero oversized BLOB transfer.
4. **Non-STRICT SQLite storage classes, `get_inbox_summary` SQL edge cases, `NaN`/`Inf`/`1e400`, & `RecursionError`:**
   - Empty `review_items` table returns `0` (not `None`) for all counts in `get_inbox_summary`.
   - Valid `NULL` `expires_at`/`target_addr`/`target_incarnation_id` rows produce
     `malformed_rows_count = 0` in `get_inbox_summary`.
   - SQLite `REAL` `lane_paused = 1.0` and `requires_human_review = 1.0` are NOT counted in
     `paused_lanes_count`/`requires_human_review_count` and ARE counted in `malformed_rows_count`.
   - 2 MiB BLOBs injected into `created_at`, `updated_at`, `expires_at`, `lane_paused`,
     `requires_human_review`, `priority_rank`, `metadata_json`, and `summary_text` are blocked
     inside SQL and surface `malformed_metadata = True, review_ready = False`.
   - Out-of-domain boolean flags (`lane_paused = 2`, `requires_human_review = -1`, `"1"`) and
     out-of-domain `status`/`severity` clamp safely (`False` / `"malformed"`) and increment
     `malformed` / `malformed_rows_count` in `get_inbox_summary`.
   - SQLite `9e999` (`Inf`), `-9e999` (`-Inf`), `NaN` in timestamps/metadata, **`metadata_json =
     '{"overflow": 1e400}'` verified in BOTH `list_inbox_items` and `get_inbox_item`**
     (`metadata == {}`, `malformed_metadata = True`, `pin_verified = False`, `review_ready = False`),
     and 2,000-level nested JSON in `metadata_json` or cursor input degrade cleanly without raising
     `RecursionError` or violating `json.dumps(..., allow_nan=False)`.
5. **ANSI / 8-bit C1 / BiDi / NUL / split-sequence scrubbing & secret redaction (values + keys):**
   - Inject 7-bit ANSI CSI (`\x1b[31m`), 7-bit OSC terminated by `\x9c` (`\x1b]0;title\x9csafe` ->
     preserves `"safe"`!), 7-bit DCS terminated by `\x9c` (`\x1bPdata\x9csafe` -> preserves
     `"safe"`!), unterminated 7-bit OSC (`\x1b]0;title`), 3-byte nF ESC (`\x1b(B`), 2-byte Fp/Fs ESC
     (`\x1b7`, `\x1b8`, `\x1bc`), 8-bit C1 CSI (`\x9b31m`), 8-bit C1 OSC (`\x9d0;title\x9c`), 8-bit
     C1 DCS/PM/APC (`\x90data\x9c`, `\x9fdata\x9c`), bare `\x1b`, Unicode BiDi (`\u202e`, `\u2066`),
     NUL (`a\x00b`), bare `\r`, DEL/C1 controls into `title`, `summary_text`, `metadata_json`, and
     `artifact.label`: assert zero raw escape/bidi/NUL bytes in serialized JSON,
     `has_control_or_bidi = True` on hostile summary, and `has_control_or_bidi = False` on clean
     multiline `\n`/`\t` summary.
   - Verify 4-byte UTF-8 emoji, 7-bit `\x1b[31m`, and 8-bit `\x9b31m` straddling the `16 KiB` BLOB
     prefix boundary decode cleanly without leaking `\x1b`/`\x9b` and set
     `text_suffix_uninspected = True`.
   - Verify env-var-prefixed secrets (`DB_PASSWORD=val`, `POSTGRES_PASSWORD="val"`,
     `MY_API_KEY=val`, `AWS_ACCESS_KEY=val`, `GITHUB_TOKEN=val`), JSON-serialized secrets
     (`{"password": "supersecret"}`), quoted secret truncated before closing `"` at the `16 KiB`
     BLOB boundary, JWT truncated in its 3rd segment at the `16 KiB` BLOB boundary, URL basic-auth
     (`https://alice:s3cr3t@host/p`), multi-token `Authorization: CustomScheme xyz`,
     `Cookie: sid=abc; k=v`, `Set-Cookie: a=b`, `credential=foo`, `awakeable_token_hash=deadbeef`,
     PEM private keys, bearer/API-key tokens, extra sensitive DB columns (`env_vars`, `auth_header`,
     `token`, `password`, `private_key`, `awakeable_token_hash`), recursive/hyphenated/camelCase/
     `> 256` B-padded sensitive keys in `metadata_json`, **AND a synthetic canary token placed
     inside a `metadata_json` key** (`{"sk-ant-canary12345678": "ok"}`, `{"Bearer eyJ...": "ok"}`)
     have zero occurrence in the final serialized JSON response and set `redaction_applied = True`
     and `untrusted_content = True`.
   - **Credential-shaped identifier defense:** Inject a synthetic credential-shaped primary key
     `review_id` (e.g., `"sk-ant-synthetic-12345678"`, which matches `_ID_TOKEN_RE`) and assert
     fixed `CoordPolicyError("inbox_db_unreadable")` with **zero echo** of the identifier value in
     the exception message (and never serialized or placed in `next_cursor`); likewise verify
     credential-shaped required `run_id`/`step_id`/`artifact_id` fail closed with fixed
     `CoordPolicyError("inbox_db_unreadable")` (zero echo), and credential-shaped nullable
     `target_incarnation_id` clamps to `None` with `malformed_metadata = True`,
     `redaction_applied = True`, `pin_verified = False`, `review_ready = False`.
   - Verify two distinct `metadata_json` keys colliding after 64-byte truncation keep the first key
     in sorted order deterministically and set `malformed_metadata = True`.
6. **2 KiB (`2048` B) UTF-8 JSON byte budget, `next_cursor` accounting, metadata-drop retry, & snapshot-bound int64 cursors:**
   - `max_response_bytes = 2048` with escape-heavy (`\"\\\n\u0000`) and 4-byte UTF-8 summary text
     stays strictly `<= 2048` UTF-8 bytes across `list_inbox_items` (including multi-item pages
     where `has_more = True` and `next_cursor` is emitted!), `get_inbox_item`, and
     `get_inbox_summary` (`allow_nan=False`), setting `text_truncated = True`.
   - First-item budget fixture (`max_response_bytes = 2048`) with large `metadata` + long
     `summary_text` verifies that after dropping `metadata` (`metadata_truncated = True`), Step 3
     retries against the **original** scrubbed `summary_text` and retains a non-empty summary prefix
     within `2048` bytes.
   - Too-small budget (`< 2048` or envelope/item overflow) raises explicit `CoordValidationError`.
   - Full `limit = 1` pagination across `checkpoint_seq = 0`, `checkpoint_seq = MAX_SQLITE_INT64`,
     equal-priority ties, `:` in `review_id`, `statuses` + `run_id` filters, and malformed
     `checkpoint_seq` rows yields zero skips and zero duplicates.
   - **Tie-group BLOB-PK continuation fixture (`limit = 1`):** Inside the same tie-group
     (`priority_rank = 0, checkpoint_seq = MAX_SQLITE_INT64`), place valid TEXT row 1 immediately
     followed by a corrupted BLOB primary-key row 2: Page 1 returns row 1 (`has_more = True`), and
     Page 2 with `next_cursor` reaches row 2 and fails closed with
     `CoordPolicyError("inbox_db_unreadable")` (proving continuation never silently skips BLOB PKs!).
   - **Two-page snapshot-change & rollback fixture:** (a) commit a projection-visible mutation
     (testing both a `review_items.priority_rank` update AND a joined `workflow_runs` /
     `review_artifacts` update) that advances `inbox_seq_counter.last_seq` inside the same write
     transaction -> passing page 1's `next_cursor` fails closed with
     `CoordValidationError("cursor_snapshot_changed")` with zero projection mutations; and (b) run
     a rolled-back write transaction -> `last_seq` remains unchanged and page 1's `next_cursor`
     continues to succeed on page 2!
   - Forged cursors (`seq = MAX_SQLITE_INT64 + 1`, `ss = MAX_SQLITE_INT64 + 1`, `seq = -1`,
     `seq = True`, `pr = 101`, `1e400`, credential-shaped `rid`, padding, non-canonical JSON, `NaN`,
     deep nesting, `> 512` B) raise `CoordValidationError("cursor_malformed")`; cross-filter
     (`statuses`/`run_id`) or cross-op cursor reuse raises
     `CoordValidationError("cursor_scope_mismatch")`.
7. **Deadline contention, URI-before-`_UMASK_LOCK`, connection close, & zero mutation authority:**
   - Held write lock with `max_read_ms = 50` aborts promptly with `CoordPolicyError("read_deadline_exceeded")`.
   - Held `_UMASK_LOCK` past `max_read_ms = 50` raises `CoordPolicyError("read_deadline_exceeded")`
     with zero `sqlite3.connect` calls.
   - Forced URI `quote()` failure (`UnicodeEncodeError`) happens before `_UMASK_LOCK` acquisition,
     verified by immediate acquisition of `_UMASK_LOCK` on another thread.
   - Simulated clock expiry inside packing loop AND post-serialization (across all three APIs)
     raises `CoordPolicyError("read_deadline_exceeded")`.
   - `open_readonly_inbox_snapshot` closes the SQLite connection immediately on normal exit, anchor
     `SELECT` failure (corrupt DB / missing `inbox_seq_counter`), trigger/view detection, and timeout.
   - Direct SQL write on opened snapshot connection raises `sqlite3.OperationalError`.
   - `ReadOnlyInboxService` public API inspection confirms zero grant/approve/reject/defer/mutate
     methods; before/after snapshot reads leave all tables, `inbox_seq_counter`, and any `audit_log`
     digest 100% unchanged.
