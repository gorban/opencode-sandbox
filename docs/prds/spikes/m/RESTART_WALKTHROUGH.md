# PRD M Shared Contract, Fenced Handoff, and Joint Restart Walkthrough

This Gate 1 implementation walkthrough covers the coordination lane under
`docs/prds/spikes/m/` (outside `docs/prds/spikes/m/local/`) starting from `main`
(`f823ba1f1f70504ec6d284a11f4da5eccc6d9799`). It aligns directly with the
cleared local adapter walkthrough (`docs/prds/spikes/m/local/ADAPTER_WALKTHROUGH.md`,
`f79732dc248c98be8bf2e1446f56d78c01c47ab9`) and defines the smallest qualifying
first pass for the [PRD M first PoC split](../../prd_m.md#first-poc-split):

1. Small additive adjustments to [oc_coord_contract.py](oc_coord_contract.py):
   `DispatchResult.permanent` and the narrow opt-in `ExternallyFencedTransport`
   protocol with explicit trusted owner attestation (`transport_owner_id()` and
   `confirm_incarnation_terminal()`).
2. Preserving the existing synchronous hub fence for all existing transports,
   while adding a narrowly opted-in split-phase handoff path **only** for
   operator-only, unmonitored, whole-incarnation externally-fenced relay
   adapters.
3. Durable external owner & abort tracking (`external_transport_bindings` in
   [oc_registry.py](oc_registry.py)) recorded **at `register_sandbox()` before
   any grant becomes dispatchable**, preserved across `revoked` transitions,
   and cleared **only** when the exact trusted owner confirms terminal state or
   verified relay stop—closing substituted-transport bypasses, double-failure
   (DB + teardown) crashes, and failed SQLite clear retries.
4. Transport-parameterized joint restart qualification fixtures and the
   combined-pass SQLite evidence verifier in `test_restart_qualification.py`.

**Explicitly deferred out of this first pass:** scoped native per-turn abort
(`abort_stream` / `revoke_grant` on real OpenCode), monitored/peer turns over
the split-phase cross-process relay, live reattachment after loss of the
trusted job owner process, production launcher wiring, live provider
credentials, real sandbox homes, and changes under `docs/prds/spikes/m/local/`
or `docs/prds/spikes/n/`. Scoped native abort requires a separate qualification
demonstrating that an **already executing** selected turn stops on the worker
while an independent turn on the same live incarnation remains usable, plus
worker-write-fence attestation of all applicable source, edge, and destination
authority. All open PRD M product decisions and final human review gates
remain open.

---

## 1. Ownership and File Boundaries

| Path | Owner | Changes in this slice |
|---|---|---|
| `docs/prds/spikes/m/RESTART_WALKTHROUGH.md` | Coordination lane | This Gate 1 walkthrough |
| `docs/prds/spikes/m/oc_coord_contract.py` | Coordination lane (sole owner) | Additive `DispatchResult.permanent` (strictly validated) and opt-in `ExternallyFencedTransport` protocol (`external_write_fence`, `transport_owner_id`, `confirm_incarnation_terminal`) |
| `docs/prds/spikes/m/oc_registry.py` | Coordination lane | Durable `external_transport_bindings` table and atomic helpers (`record_transport_binding`, `mark_transport_abort_requested`, `commit_external_revoke`, `mark_transport_terminal_confirmed`, `list_unconfirmed_transport_bindings`, `has_unconfirmed_transport_binding`, `list_unretired_aborted_bindings`, `get_transport_binding`) |
| `docs/prds/spikes/m/oc_hub.py` | Coordination lane | Narrowly opted-in split-phase dispatch for `ExternallyFencedTransport` (existing transports stay on synchronous fence), operator-only/unmonitored/sole-grant enforcement, pre-dispatch owner binding & durable terminal-confirmation gating, Phase 3 settlement ownership until durable/cleanup transfer, `DispatchResult.permanent` & detail sanitization, minimal-transport post-race abort settlement, validated `confirm_recovery(timeout_s=...)` |
| `docs/prds/spikes/m/oc_fake_worker.py` | Coordination lane | Test helper script modes (`permanent=True` refusal, paused pre-write / post-receipt hooks) and opt-in externally-fenced fake wrapper implementing exact-owner attestation |
| `docs/prds/spikes/m/test_restart_qualification.py` | Coordination lane | Transport-parameterized 5-checkpoint qualification suite (with paused-write race on a separate fresh job), explicit separate clean-restart fixture, substituted-transport & double-failure crash/restart fixtures, failed-DB-clear retry fixture, post-receipt barrier fixture, and `verify_combined_pass_evidence()` |
| `docs/prds/spikes/m/test_coord_contract.py`, `test_hub.py`, `test_gate2_regressions.py` | Coordination lane | Contract validation tests, split-fence & durable-owner-binding regressions, and equal-priority `priority=0` tightening for `test_r11_p2_1` |
| `docs/prds/spikes/m/local/*` | Local OpenCode lane | **Untouched** (read-only interface alignment) |

---

## 2. Small Shared Handoff, Refusal, and Owner-Attested Opt-In Protocol

### 2.1 Unchanged Public Pins and Bounds

The existing public shapes in `oc_coord_contract.py` already carry every pin
needed for the first local operator turn:

- `TurnDispatch`: `msg_id`, `sandbox_addr`, `incarnation_id`, `thread_id`,
  `trust_class`, `msg_kind`, `wire_text`, `body_sha256`, `artifact_refs`,
  `edge_id`, `lease_request_id`, `grant_generation`.
- `StreamEvent`: `event_type`, `sandbox_addr`, `incarnation_id`, `thread_id`,
  `seq_hint`, `message_id`, `text`, `file_path`, `detail`, `created_at`.
- `WorkerStatus`: `sandbox_addr`, `incarnation_id`, `state`, `active_turns`,
  `revoked`, `last_error`.

Logical-thread to one-use native-session mapping and any internal relay
identifiers stay private inside the adapter. Every emitted `StreamEvent` must
bind back to the host-assigned `(sandbox_addr, incarnation_id, thread_id,
message_id)` without elevating provenance.

- **Hub text/stream limits (`oc_coord_contract.py`):**
  `MAX_INLINE_BODY_BYTES = 65_536`, `MAX_FRAMED_BODY_BYTES = 69_632`,
  `MAX_STREAM_EVENT_BYTES = 262_144`, `MAX_TURN_STREAM_EVENTS = 2_048`,
  `MAX_REASON_BYTES = 256`.
- **Local worker HTTP frame cap (`docs/prds/spikes/m/local/client.py`):**
  `MAX_REQUEST = 65_536` bytes including request line, headers, and JSON body.
- **Adapter enforcement rule:** The adapter validates pins, `body_sha256`,
  absence of unsupported `artifact_refs`, reservation, and the fully encoded
  HTTP request size (`<= 65_536` bytes) **before dialing the relay socket or
  writing any bytes**, refusing invalid/oversize inputs without widening limits
  or silently truncating.

### 2.2 Additive Adjustment A: `DispatchResult.permanent` and Strict Validation

Physical wire handoff stays strictly 3-valued in `DispatchOutcome`
(`HANDED_OFF`, `ZERO_BYTES_SENT`, `UNCERTAIN`), matching `local/client.py`.
Add `permanent: bool = False` to `DispatchResult` with strict validation:

```python
@dataclass(frozen=True, slots=True)
class DispatchResult:
    outcome: DispatchOutcome
    stream_id: str | None = None
    detail: str = ""
    permanent: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, DispatchOutcome):
            raise CoordValidationError("outcome must be DispatchOutcome")
        if type(self.permanent) is not bool:
            raise CoordValidationError("permanent must be a bool")
        if not isinstance(self.detail, str):
            raise CoordValidationError("detail must be a string")
        if self.stream_id is not None and not isinstance(self.stream_id, str):
            raise CoordValidationError("stream_id must be a string or None")
        if self.permanent and self.outcome is not DispatchOutcome.ZERO_BYTES_SENT:
            raise CoordValidationError(
                "permanent refusal requires DispatchOutcome.ZERO_BYTES_SENT"
            )
```

**Hub handling of `DispatchResult`:**

1. Any non-`DispatchResult` return value from `transport.dispatch_turn()` fails
   closed as `UNCERTAIN` (never replayed).
2. Untrusted `result.detail` (on both `permanent=True` and `permanent=False`)
   is sanitized (stripping control/bidi/newline characters and truncating
   safely on UTF-8 boundaries to `<= MAX_REASON_BYTES`, falling back to
   `"dispatch_refused"` if empty) **before** calling `cancel_outbox_row()`,
   `append_audit()`, or constructing a host `StreamEvent`.
3. **`ZERO_BYTES_SENT(permanent=False)`** (e.g. single-turn slot busy,
   `BlockingIOError`, or raced with grant fence): if fenced or recovery rotated,
   transition `dispatch_started -> cancelled`; otherwise return to `pending`
   for retry.
4. **`ZERO_BYTES_SENT(permanent=True)`** (deterministic pre-write refusal:
   encoded HTTP frame `> 65_536` bytes, unsupported `artifact_refs`, pin or
   digest mismatch, or quarantined incarnation):
   - Transition `dispatch_started -> cancelled` with sanitized reason (never
     returned to `pending`; eliminates hot-retry loops).
   - Append bounded audit entry `dispatch_rejected_pre_write`.
   - When full liveness still holds (`not self._is_closed()`,
     `self._recovery_generation == start_rec_gen`,
     `not inflight.revoked_observed`, and
     `_classify_row_liveness_under_fence(..., src_incarnation=env.src_incarnation) == "live"`),
     record a host-authored `StreamEvent(event_type="turn_error", ...)` via
     `self._registry.record_stream_event(err_ev, dispatch_msg_id=env.msg_id)`
     and notify waiters.
5. **`UNCERTAIN`** (partial write, lost receipt, timeout, or transport
   exception): transition `dispatch_started -> uncertain`; never replay.

### 2.3 Additive Adjustment B: Narrow Opt-In `ExternallyFencedTransport` With Owner Attestation

Add one small `@runtime_checkable` sub-protocol in `oc_coord_contract.py` so
existing transports remain untouched on the synchronous hub fence and only an
explicitly opted-in, owner-attested cross-process relay adapter enters the
split-phase path:

```python
@runtime_checkable
class ExternallyFencedTransport(WorkerTransport, Protocol):
    """Opt-in protocol for an operator-only, unmonitored, whole-incarnation relay adapter."""

    @property
    def external_write_fence(self) -> bool:
        """Return True to opt into CoordHub's narrow operator-only split-phase handoff."""
        ...

    def transport_owner_id(self, sandbox_addr: str, incarnation_id: str) -> str:
        """Return the stable opaque trusted owner/job receipt identity (e.g. local-relay:<run_label>) for this exact incarnation; raise if unknown."""
        ...

    def confirm_incarnation_terminal(
        self,
        sandbox_addr: str,
        incarnation_id: str,
        *,
        owner_id: str,
        reason: str,
    ) -> bool:
        """Assert ownership of the exact (sandbox_addr, incarnation_id, owner_id) relay/job, publish terminal state or verify relay stop, close broker admission and readers, and return True iff positively confirmed. Must return False or raise on unknown identity, owner mismatch, or unconfirmed stop. Idempotent once terminal is confirmed."""
        ...
```

Hub detection:

```python
def _is_externally_fenced(self) -> bool:
    return (
        isinstance(self._transport, ExternallyFencedTransport)
        and getattr(self._transport, "external_write_fence", False) is True
    )
```

**Fail-closed authority restrictions enforced by `CoordHub` whenever
`_is_externally_fenced()` is `True`:**

1. `register_sandbox()`:
   - Requires `caller.role is CoordRole.OPERATOR`.
   - Rejects `lease is not None`, `controller_request_id is not None`, and
     `parent_addr is not None` (`CoordPolicyError("external_fence_operator_unmonitored_only")`).
   - Queries `owner_id = validate_opaque_token(self._transport.transport_owner_id(addr, clean_inc), "transport_owner_id")`
     and **atomically persists** `(addr, clean_inc, owner_id, abort_requested=0, terminal_confirmed=0)`
     in SQLite `external_transport_bindings` **before** the sandbox or any
     grant becomes dispatchable. If querying `owner_id` or persisting the
     binding fails, registration fails cleanly with zero dispatchable grant.
2. `grant_edge()`:
   - Requires `caller.role is CoordRole.OPERATOR`,
     `src_actor == caller.canonical_sender` (an `operator:*` principal),
     `src_incarnation is None`, `lease_request_id is None`, and
     `allowed_msg_kinds == frozenset({"prompt"})` (direct operator prompts
     only; rejects any non-prompt kind with
     `CoordPolicyError("external_fence_prompt_only")`).
   - Enforces **sole active grant per incarnation**: rejects creating a second
     active edge for a `dst_addr` that already has an active edge
     (`CoordPolicyError("external_fence_single_grant_only")`).
3. `send()` and `dispatch_once()`:
   - Re-checks eligibility both on admission (`send()`) and **before
     `mark_outbox_dispatch_started()`** when dispatching persisted rows after
     restart (`dispatch_once()`): requires `env.src_role is CoordRole.OPERATOR`,
     `src_actor.startswith("operator:")`, `src_incarnation is None`,
     `msg_kind == "prompt"`, `edge.lease_request_id is None`,
     `dst_sb.controller_request_id is None`, sole active edge on `dst_addr`,
     and a live `external_transport_bindings` row matching `(dst_addr, dst_incarnation)`
     with `abort_requested == 0` and `terminal_confirmed == 0` whose `owner_id`
     matches `self._transport.transport_owner_id(dst_addr, dst_incarnation)`.
   - Rejects incompatible calls upfront at `send()` (before writing to the
     outbox) and non-blockingly skips incompatible persisted rows at
     `dispatch_once()` **before incrementing `attempts` or calling the adapter**
     so eligible `prompt` rows still dispatch.

---

## 3. Fence Architecture, Settlement Ownership, and Durable Owner-Attested Abort Rules

### 3.1 Existing Transports Keep Synchronous Hub Fence Unchanged

When `_is_externally_fenced()` is `False` (`FakeWorkerTransport`, minimal
`WorkerTransport`, and all monitored/peer/multi-edge transports),
`CoordHub._dispatch_single_row()` keeps its existing synchronous `with fence:`
execution across `mark_outbox_dispatch_started -> dispatch_turn ->
_handle_dispatch_result_locked`. Monitored and peer turns stay exclusively on
this synchronous path.

### 3.2 Narrow Split-Phase Handoff (Only When `_is_externally_fenced()` Is `True`)

#### Phase 1 — Hub Pre-Write Admission Fence (holds `fence`, zero IPC)

1. Check `not closed`, `not degraded`, envelope exists, `liveness == "live"`,
   and operator-only/unmonitored/sole-grant/matching-owner eligibility holds.
2. Persist `pending -> dispatch_started` via `mark_outbox_dispatch_started()`.
3. Under `_meta_lock` (while still holding `fence`): atomically snapshot
   `start_rec_gen = self._recovery_generation`, recheck `not self._closed` and
   `not self._degraded`, and register `self._inflight_handoffs[env.msg_id] = inflight`.
   (If closed or degraded tripped before registration, call
   `return_outbox_to_pending()` before releasing `fence` and return `False`.)
4. **Release `fence`.**

#### Phase 2 — Bounded Relay First-Write Handoff (outside `fence`)

1. Call `result = self._transport.dispatch_turn(turn)` without holding `fence`.
2. Inside the adapter:
   - Validate pins, kind, digest, no `artifact_refs`, reservation, and encoded
     HTTP frame `<= 65_536` bytes before dialing (`ZERO_BYTES_SENT(permanent=True)`
     on refusal).
   - Send the framed request to the relay and wait (bounded, outside hub
     `fence`) **only** for the relay's 1-byte worker-write receipt (`b"H"`,
     `b"Z"`, or `b"U"`/EOF). Never wait for HTTP response headers/body or SSE
     inside `dispatch_turn()`.
   - On `b"H"`, bind the pinned prompt-reply & SSE readers to a unique
     `stream_id` and return `DispatchResult(HANDED_OFF, stream_id=stream_id)`.
     Payload and SSE parsing occur exclusively in `stream_events(stream_id)`.

#### Phase 3 — Settlement Ownership Retained Until Durable Recording or Tracked Cleanup Transfer

**Critical settlement-ownership invariant:** `env.msg_id` **MUST remain in
`self._inflight_handoffs`** across Phase 2, across re-acquiring `fence` in
Phase 3, and through **complete durable SQLite outcome recording OR transfer of
responsibility into tracked cleanup** (`_stream_authorities` /
`_pending_cleanup_streams` / `_pending_cleanup_incarnations`). Only in the
outer `finally:` **after Phase 3 releases `fence`** is `env.msg_id` popped from
`self._inflight_handoffs` and `self._inflight_cond.notify_all()` signaled.

Lock ordering remains strictly acyclic: `_register_lock -> fence -> _meta_lock`
(`confirm_recovery()` releases all `fences` in Phase 1 before waiting on
`_inflight_cond`, which uses `_meta_lock`). `close()` also calls
`self._inflight_cond.notify_all()`, and `confirm_recovery()` checks
`self._closed` in its wait loop so `close()` never stalls behind `timeout_s`.

Inside Phase 3 (holding `fence`, still owning `self._inflight_handoffs[msg_id]`):

1. Validate `isinstance(result, DispatchResult)`; non-`DispatchResult` or
   exception during Phase 2 fails closed as `UNCERTAIN`.
2. Check whether recovery rotated (`self._recovery_generation != start_rec_gen`):
   - **Late `HANDED_OFF(stream_id)` after recovery started:**
     - Do **not** call `mark_outbox_handed_off()`, do **not** launch
       `_consume_stream()`, and do **not** insert into `_stream_authorities`.
     - Record `stream_id` in `_pending_cleanup_streams` (with
       `_REASON_RECOVERY_RETIRED`) and ensure `(env.dst_addr, env.dst_incarnation)`
       is in `_pending_cleanup_incarnations` (its pre-registered
       `external_transport_bindings` row already carries its exact `owner_id`).
     - Transition outbox `dispatch_started -> uncertain` if still
       `dispatch_started`.
   - **Late `ZERO_BYTES_SENT` after recovery started:** cancel outbox row if
     still `dispatch_started`.
   - **Late `UNCERTAIN` / exception after recovery started:** mark outbox
     `uncertain` if still `dispatch_started`.
3. Same recovery generation (`self._recovery_generation == start_rec_gen`):
   - `ZERO_BYTES_SENT`: apply `permanent=True` or `permanent=False` rules (§2.2).
   - `UNCERTAIN` / missing `stream_id`: mark outbox `uncertain`; never replay.
   - `HANDED_OFF(stream_id)`: register `_StreamAuth` in `_stream_authorities`,
     check `_check_immediate_stream_abort_locked()`, persist
     `mark_outbox_handed_off(msg_id, stream_id=stream_id)` (on DB error, move
     `stream_id` to `_pending_cleanup_streams` with
     `_REASON_HANDOFF_PERSIST_FAILED`, ensure `(dst_addr, dst_incarnation)` is
     in `_pending_cleanup_incarnations`, mark `uncertain` / degraded).
4. **Outer `finally:` fail-safe:** if an unexpected error occurs before Phase 3
   records an outcome, mark the hub degraded and transfer any returned
   `stream_id` and `(env.dst_addr, env.dst_incarnation)` into
   `_pending_cleanup_streams` / `_pending_cleanup_incarnations` before popping
   `self._inflight_handoffs[msg_id]` and waking `_inflight_cond`.
5. **After releasing `fence`:** apply immediate abort (if needed) before
   launching `stream_events(stream_id)`.

### 3.3 Minimal-Transport Post-Race Abort Settlement & In-Flight Fencing

1. **In-flight scan during revoke & rotation:**
   - `_detach_meta_for_target()` scans `self._inflight_handoffs`: for any
     `inf.dst_addr == target_addr`, sets `inf.revoked_observed = True`, adds
     `inf.dst_incarnation` to `inc_set`, and adds `(inf.edge_id, inf.grant_generation)`
     to `_fenced_generations`.
   - `_rotate_existing_sandbox()` acquires affected edge `fences`, fences
     `(addr, existing.incarnation_id)` and matching `_inflight_handoffs`, and
     refuses replacement whenever any unconfirmed `external_transport_bindings`
     row exists for `addr` or terminal abort fails.
2. **Minimal-transport late-`HANDED_OFF` settlement (no `abort_stream`):**
   - In `_settle_stream_without_abort_stream()`, invoke the exact terminal
     incarnation abort (`confirm_incarnation_terminal()` when an external
     `owner_id` binding exists, or idempotent `abort_incarnation()` otherwise)
     for **all** minimal-transport terminal reasons (`_STATUS_REVOKED`,
     `_REASON_HANDOFF_PERSIST_FAILED`, `_REASON_RECOVERY_RETIRED`).
   - In `_apply_immediate_stream_abort()`, when the transport lacks
     `abort_stream`, invoke `_settle_stream_without_abort_stream()` synchronously
     *before* `_run_stream_task()` (enqueuing `_pending_cleanup_streams` and
     starting the retry worker only if it fails) so synchronous
     `dispatch_once(async_stream=False)` does not block inside `stream_events()`.
   - When cleanup settles any unconsumed stream, pop its `_stream_authorities`
     and `_stream_abort_reasons` entries cleanly.

### 3.4 Durable Pre-Dispatch Owner Binding, Double-Failure Safety, and Substituted-Transport Defense

A SQLite grant tombstone attests only to the hub's decision; it cannot attest
that a separately owned relay published terminal state or stopped. Nor may an
unknown transport or plain `FakeWorkerTransport` clear an external relay's
obligation by returning `False` for an incarnation it never served.

1. **Durable SQLite table (`oc_registry.py`):**
   ```sql
   CREATE TABLE IF NOT EXISTS external_transport_bindings (
       sandbox_addr TEXT NOT NULL,
       incarnation_id TEXT NOT NULL,
       owner_id TEXT NOT NULL,
       abort_requested INTEGER NOT NULL DEFAULT 0,
       terminal_confirmed INTEGER NOT NULL DEFAULT 0,
       reason TEXT NOT NULL DEFAULT '',
       created_at REAL NOT NULL,
       updated_at REAL NOT NULL,
       PRIMARY KEY (sandbox_addr, incarnation_id)
   )
   ```
   - **Pre-dispatch recording:** For every `ExternallyFencedTransport`,
     `register_sandbox()` records `(sandbox_addr, incarnation_id, owner_id,
     abort_requested=0, terminal_confirmed=0)` **atomically in the same
     registration transaction before any grant can be created or dispatched**.
   - **Preserved across `revoked`:** Updating `sandboxes.status = 'revoked'`
     and writing `grant_tombstones` **never** deletes or clears
     `external_transport_bindings`. Only explicit confirmation by the exact
     `owner_id` flips `terminal_confirmed = 1`.
   - **No-bypass owner attestation rule:** Whenever an unconfirmed binding
     `(sandbox_addr, incarnation_id, owner_id)` exists (`terminal_confirmed == 0`),
     clearing it **strictly requires**:
     1. `isinstance(self._transport, ExternallyFencedTransport)` AND
        `self._transport.external_write_fence is True`, AND
     2. `self._transport.confirm_incarnation_terminal(sandbox_addr, incarnation_id, owner_id=owner_id, reason=reason) is True`, AND
     3. SQLite `mark_transport_terminal_confirmed(sandbox_addr, incarnation_id, owner_id=owner_id)`
        commits cleanly (**DB clear BEFORE popping the in-memory
        `_pending_cleanup_incarnations` entry**, so a transient DB clear error
        keeps memory and SQLite aligned and retryable!).
     - A substituted transport (`FakeWorkerTransport`, minimal `WorkerTransport`,
       or another `ExternallyFencedTransport` that does not own `owner_id`)
       fails step (1) or (2), leaves `terminal_confirmed = 0`, keeps recovery
       degraded, and keeps replacement blocked.

2. **Exact ordering on `revoke()` — atomic success path, double-failure path, and failed-logical-retirement path:**
   - **Step 1 (in-memory fence):** Fence `_fenced_addrs`, `_fenced_targets`,
     `_fenced_generations`, `_inflight_handoffs`, and enqueue
     `(addr, inc_id)` in `_pending_cleanup_incarnations` (preserving the
     pre-registered `owner_id` from SQLite / in-memory cache).
   - **Step 2 (best-effort DB `abort_requested = 1`):** Attempt
     `mark_transport_abort_requested(addr, inc_id, reason=clean_reason)`.
     - **If this DB write fails:** call `_mark_degraded("revoke_abort_mark_failed")`,
       and **DO NOT skip Step 3** — continue immediately to physical teardown!
       Because `(addr, inc_id, owner_id, terminal_confirmed=0)` was **already
       durably committed at `register_sandbox()`**, the exact owner identity is
       already preserved on disk even when Step 2 fails.
   - **Step 3 (physical teardown outside `fence`):**
     - If an external `owner_id` binding exists: call
       `confirmed = (self._is_externally_fenced() and self._transport.confirm_incarnation_terminal(addr, inc_id, owner_id=owner_id, reason=clean_reason) is True)`
       (catching exceptions as `confirmed = False`).
   - **Step 4A (success path — `confirmed is True`):**
     - Commit logical retirement and terminal confirmation **atomically in a
       single SQLite `BEGIN IMMEDIATE` transaction** via
       `commit_external_revoke(target_addr=addr, incarnation_id=inc_id, owner_id=owner_id, actor=caller.canonical_sender, reason=clean_reason)`:
       1. Tombstone all matching active `routing_edges` in `grant_tombstones`,
          set `routing_edges.active = 0`, cancel all `pending` outbox rows, and
          delete unconsumed `dispatch_receipts` (matching
          `revoke_grant_and_cancel_outbox`).
       2. Update `sandboxes.status = 'revoked'` for `(addr, inc_id)`.
       3. Update `external_transport_bindings` to `abort_requested = 1,
          terminal_confirmed = 1, reason = clean_reason` for
          `(addr, inc_id, owner_id)`.
       4. Append the `"revoke"` entry to `audit_log`.
     - **Only after this atomic transaction commits** do we pop `(addr, inc_id)`
       from in-memory `_pending_cleanup_incarnations` and return
       `RevocationStatus(...)`.
     - **If `commit_external_revoke()` fails after physical teardown succeeded:**
       SQLite rolls back the entire transaction so `terminal_confirmed` stays
       `0` (keeping the external obligation intact alongside `.coord_degraded`),
       `CoordHub` calls `_mark_degraded("revoke_persistence_failed")`, retains
       `(addr, inc_id)` in `_pending_cleanup_incarnations`, keeps admission and
       replacement fenced, starts the cleanup retry worker, and **raises
       `CoordPolicyError(_ERR_REVOKED_UNCONFIRMED)`**. Because
       `confirm_incarnation_terminal()` is idempotent on an already-confirmed
       relay, retrying or running `confirm_recovery()` re-confirms and finishes
       logical retirement before dispatch or replacement—including on reopen
       with a legacy transport, which remains degraded and blocked until
       recovery completes logical retirement and exact-owner confirmation.
   - **Step 4B (failure path — `confirmed is False`, including double failure where Step 2 also failed):**
     - Call `_mark_degraded("transport_abort_unconfirmed")`.
     - Retain `(addr, inc_id)` in `_pending_cleanup_incarnations` and leave
       `terminal_confirmed = 0` in SQLite.
     - Still attempt best-effort logical retirement
       (`revoke_grant_and_cancel_outbox` + `sandboxes.status = 'revoked'` +
       audit); persisting `status = 'revoked'` preserves
       `external_transport_bindings(terminal_confirmed=0)` intact.
     - Start the cleanup retry worker, keep admission and replacement fenced,
       and **raise `CoordPolicyError(_ERR_REVOKED_UNCONFIRMED)`** as the
       externally visible result.
   - **Non-externally-fenced transports (`owner_id` absent):** preserve existing
     synchronous `revoke()` behavior (Step 1 fence -> Step 2 teardown -> Step 3
     logical retirement + audit, with background retry-to-settle on transient
     `abort_incarnation()` errors and replacement blocked while
     `_pending_cleanup_incarnations` holds `addr`).

3. **Replacement refusal gate (`register_sandbox()`):**
   - Refuses to register or replace `sandbox_addr` (`CoordPolicyError("transport_abort_unconfirmed")`)
     whenever **either** `_pending_cleanup_incarnations` contains `sandbox_addr`
     **or** SQLite `has_unconfirmed_transport_binding(sandbox_addr)` is `True`
     **or** SQLite `list_unretired_aborted_bindings()` contains `sandbox_addr`.

4. **Degraded startup reconstruction & `confirm_recovery(caller, *, reason=..., timeout_s: float = 2.0)`:**
   - Validate `timeout_s`: reject `bool`, non-finite (`NaN`/`Inf`), or
     `timeout_s < 0` (`CoordValidationError`).
   - **In `CoordHub.__init__()`:** query `list_unconfirmed_transport_bindings()`
     and `list_unretired_aborted_bindings()` (any binding with
     `abort_requested == 1` whose sandbox is not yet `revoked` or still has an
     active edge / `pending` outbox row). Boot **degraded** (`self._degraded = True`)
     and reconstruct `_pending_cleanup_incarnations` / `_fenced_targets`
     whenever:
     - `.coord_degraded` or `.coord_session_active` exists, OR
     - Any unconfirmed binding has `abort_requested == 1`, OR
     - Any unconfirmed binding's sandbox has `status == 'revoked'`, OR
     - Any `list_unretired_aborted_bindings()` entry exists (defends against
       unretired logical state even if `terminal_confirmed` were already `1`,
       including on reopen with a legacy transport), OR
     - Any unconfirmed binding exists whose `owner_id` is not actively owned by
       the currently attached `ExternallyFencedTransport` (i.e. substituted
       transport, legacy transport, or unknown `owner_id`).
   - **In `confirm_recovery()`:**
     - Phase 1 acquires all edge `fences`, fences all edges/sandboxes/inflight,
       reconstructs `_pending_cleanup_incarnations` from **all**
       `list_unconfirmed_transport_bindings()` plus active `sandboxes`,
       best-effort sets `abort_requested = 1` for every unconfirmed binding,
       releases `fences`, and immediately runs `_drain_pending_cleanups()`
       (calling `confirm_incarnation_terminal(..., owner_id=...)` for external
       bindings and committing `terminal_confirmed = 1` before popping memory).
     - Wait on `_inflight_cond` up to `timeout_s` (checking `self._closed`)
       until `_inflight_handoffs` is empty. If wedged past deadline, raise
       `CoordPolicyError(_ERR_CLEANUP_INCOMPLETE)` and remain degraded.
     - Re-run `_drain_pending_cleanups()`, then require **both**
       `not self._has_pending_cleanups()` AND
       `not self._registry.list_unconfirmed_transport_bindings()` before
       running Phase 2 DB retirements (tombstoning active edges, cancelling
       pending rows, marking orphaned `dispatch_started` uncertain, setting
       sandboxes `revoked`, auditing `confirm_recovery`) and unlinking
       `.coord_degraded`.

---

## 4. Joint Qualification Checkpoints, Fixture API, and Adversarial Suites

New module: `docs/prds/spikes/m/test_restart_qualification.py`.

### 4.1 Five Fixed Joint-Proof Checkpoints (Aligned With `ADAPTER_WALKTHROUGH.md`)

All checkpoints drive explicit `hub.dispatch_once()` with the background pump
disabled, one-use native sessions per dispatched prompt, and exact container /
owner identity verification:

1. **Checkpoint 1 (Job A) — Authorized operator turn with real stream and scratch edit:**
   - Register fresh `ExternallyFencedTransport` Job A (`inc_1`, `owner_id_a`) +
     sole unmonitored operator grant `G1`.
   - Reserve one-use session 1, submit & dispatch operator turn 1 -> observe
     streamed `text_delta` before `turn_completed`, independently verify the
     scratch file edit (`proof.txt`), and confirm SQLite `outbox.status ==
     'completed'` (`attempts == 1`), `badge IS NULL` on worker-derived events,
     and intact audit chain (`ok, count = reg.verify_audit_chain()` with
     `ok is True and count > 0`).
2. **Checkpoint 2A & 3 (Job A, shared job) — Held stream, queued old-incarnation turn, terminal revoke, and reopen against the same terminal worker/relay:**
   - Arm broker hold, reserve one-use session 2, dispatch turn 2 -> observe
     held stream active.
   - Queue turn 3 on `inc_1` (`G1`) without reserving a native session and
     without dispatching it (`outbox.status == 'pending'`).
   - Call `hub1.revoke(_OP, target=...)` -> confirm held stream closes, stale
     bearer returns HTTP 403 while both containers remain running (exact
     container IDs verified before and after), zero new broker admissions,
     `confirm_incarnation_terminal(..., owner_id=owner_id_a)` confirms terminal
     state, and `external_transport_bindings.terminal_confirmed == 1`.
   - Cleanly close Hub 1 and reopen Hub 2 against the persisted SQLite DB while
     the exact same terminal worker and relay remain running. Drive
     `hub2.dispatch_once()` -> verify turn 3 stays `cancelled` (`attempts == 0`,
     zero adapter invocations for that ID, zero new upstream admissions),
     `(edge_1, 1)` is in `grant_tombstones`, zero unconsumed `dispatch_receipts`
     remain, and re-registering `inc_1` raises `RevokedError`.
3. **Checkpoint 2B (Job B, separate fresh job) — Genuine paused-first-write race:**
   - Register a **separate fresh job** (`inc_pause_1`, `owner_id_b`) with one
     reserved one-use session and explicit opt-in hub `dispatch_once()`.
   - Pause the single turn inside the relay (`OpenCode.pause_prompt`,
     `local/client.py:448` / `local/probe.py:129`) and **wait for the genuine
     relay pause acknowledgement (`b"P"`)** before calling `hub.revoke()`.
   - Call `hub.revoke()` from a second thread -> assert `< 0.5s` completion
     without stalling on Phase 2, terminal fencing under `/grant/lock`, and
     upon releasing the pause, verify the relay's own positive
     `ZERO_BYTES_SENT` (`b"Z"`) receipt -> outbox row transitions
     `dispatch_started -> cancelled`, zero worker bytes written, zero new
     upstream admissions.
4. **Checkpoint 4 (Job C / dedicated opt-in synthetic transport) — Uncertain handoff never replayed:**
   - Dedicated opt-in transport (or separate job with host fixture discarding
     the real receipt) returns `UNCERTAIN` (`outbox.status == 'uncertain'`,
     `attempts == 1`).
   - Across both clean hub restart and degraded `confirm_recovery()`, assert
     `attempts == 1`, status remains `uncertain`, and zero replay dispatches
     occur.
5. **Checkpoint 5 (Job D) — Fresh authorized incarnation still works:**
   - After terminal confirmation/recovery, register fresh incarnation `inc_2`
     with fresh `owner_id_d`, fresh grant `G2`, and fresh broker/job ->
     dispatch authorized operator turn -> `completed` + streamed `text_delta` +
     `verify_combined_pass_evidence()` passes.

### 4.2 Explicit Separate Case: Clean Hub Restart on an Unrevoked Live Incarnation

Clean same-incarnation continuation is **strictly separate** from the revoked
case and is **not** claimed across loss of the trusted job owner process
(host-process exit closes `/grant/lifetime` and makes the relay permanently
inert per `docs/prds/spikes/m/local/ADAPTER_WALKTHROUGH.md`). It is tested as
a separate fixture (`test_clean_restart_unrevoked_eligible_row_authority`) with
explicit authority evidence required before `hub2` dispatches `msg_eligible`:

1. `hub1.close()` completed cleanly (`.coord_session_active` unlinked,
   `hub2.is_degraded is False`, no detached in-memory `BrokerLease`).
2. `sandboxes` row has `status == 'running'` and matching `incarnation_id`.
3. If externally fenced, `external_transport_bindings` has `abort_requested == 0`,
   `terminal_confirmed == 0`, and `transport.transport_owner_id()` matches the
   exact persisted `owner_id`.
4. `routing_edges` row is `active == 1` at `grant_generation`, absent from
   `grant_tombstones`.
5. Unmonitored operator edge (or controller-confirmed-active if controller-bound)
   and live transport grant (`status().revoked is False`).

### 4.3 Additional Mandatory Adversarial Fixtures in `test_restart_qualification.py`

- **Substituted transport & unknown incarnation cannot clear an external relay
  obligation (P1-1):**
  - Register `sb-1` (`inc_1`, `owner_id_1`) on `ExternallyFencedTransport` T1;
    fail physical teardown on `hub1.revoke()` -> `terminal_confirmed == 0`,
    degraded, raises `_ERR_REVOKED_UNCONFIRMED`.
  - Reopen `hub2` with (a) plain `FakeWorkerTransport`, and (b) a second
    `ExternallyFencedTransport` T2 with unknown/mismatched `owner_id`: in both
    cases `hub2` boots degraded, `confirm_recovery()` raises
    `_ERR_CLEANUP_INCOMPLETE`, `terminal_confirmed` stays `0`, and replacing
    `sb-1` with `inc_2` remains **blocked**.
  - Reopen `hub3` with the exact trusted owner T1 once fault clears ->
    `confirm_incarnation_terminal(..., owner_id=owner_id_1)` returns `True`,
    `terminal_confirmed` flips to `1`, `confirm_recovery()` reopens, and
    fresh `inc_2` succeeds.
- **Double failure (DB write error + physical teardown error) followed by hub
  loss & later `revoked` persistence (P1-2):**
  - Register `sb-1` (`inc_1`, `owner_id_1`) -> binding is already durable at
    registration.
  - Inject failure into **both** the revoke-time DB write
    (`mark_transport_abort_requested`) AND physical teardown
    (`confirm_incarnation_terminal`).
  - Call `hub1.revoke()` -> physical teardown is still attempted despite the DB
    error; raises `_ERR_REVOKED_UNCONFIRMED`, retains `.coord_degraded` and
    pre-registered `external_transport_bindings(terminal_confirmed=0)`.
  - Even if `sandboxes.status = 'revoked'` is persisted later, verify the
    unconfirmed binding stays intact. Drop `hub1` without clean close ->
    reopen `hub2` -> replacement with `inc_2` stays blocked until T1 confirms
    terminal for exact `owner_id_1`.
- **Failed logical retirement after physical confirmation succeeded (atomic rollback & legacy-transport reopen):**
  - Physical `confirm_incarnation_terminal()` returns `True`, then an injected
    DB error fails `commit_external_revoke()`. Verify SQLite rolls back so
    `terminal_confirmed` stays `0`, hub degrades and raises
    `_ERR_REVOKED_UNCONFIRMED`, admission and replacement stay blocked. Reopen
    with a legacy transport (`FakeWorkerTransport`) -> hub boots degraded,
    dispatches `0` rows, and refuses replacement and `confirm_recovery()`.
    Reopen with the exact owner T1 and run `confirm_recovery()` -> idempotently
    re-confirms terminal state and completes full logical retirement (grant
    tombstoned, pending row cancelled, sandbox `revoked`,
    `terminal_confirmed == 1`) before reopening.
- **Direct-prompt restriction at admission & zero-attempt persisted skip:**
  - On `ExternallyFencedTransport`, verify `grant_edge()` rejects non-prompt
    `allowed_msg_kinds` and `send()` rejects non-prompt `msg_kind` before
    writing to the outbox.
  - Seed a persisted incompatible non-prompt row (e.g. `cancel` or `review`)
    alongside an eligible `prompt` row in SQLite; run `dispatch_once()` and
    verify the incompatible row remains at `attempts == 0` with zero adapter
    invocations while the eligible `prompt` row dispatches and completes.
- **Post-receipt Phase-3 pause barrier:**
  - Pause Phase 3 immediately after `dispatch_turn()` returns
    `HANDED_OFF(stream_id)` and before Phase 3 re-acquires `fence` / settles
    ownership. Start `confirm_recovery()` from a second thread -> assert
    `confirm_recovery()` stays closed (`is_degraded is True`) until Phase 3
    transfers `stream_id` to tracked cleanup, records durable `uncertain`,
    releases `fence`, and only then pops `_inflight_handoffs` and wakes
    `confirm_recovery()` -> zero leaked `_stream_authorities`, zero ordinary
    deltas.
- **Minimal-transport late-`HANDED_OFF` race:**
  - `dispatch_turn()` finishes microseconds before `hub.revoke()` on an
    `ExternallyFencedTransport` without `abort_stream`; Phase 3 settles
    synchronously via `confirm_incarnation_terminal()`, records zero ordinary
    deltas, and leaves zero stranded `_pending_cleanup_streams`.
- **Permanent pre-write refusal & hostile detail sanitization:**
  - Oversize encoded HTTP frame (`> 65_536` bytes), unsupported `artifact_refs`,
    and hostile unsanitized `result.detail` (control chars / `> 256` bytes)
    return `ZERO_BYTES_SENT(permanent=True)` -> `cancelled`, zero retry on next
    `dispatch_once()`, sanitized audit `dispatch_rejected_pre_write`, and host
    `turn_error` with `dispatch_msg_id=env.msg_id` waking `wait()`.
- **Operator-only / unmonitored / sole-grant guardrails on
  `ExternallyFencedTransport`:**
  - Rejects `BrokerLease`, `controller_request_id`, non-operator `grant_edge`,
    `lease_request_id`, second active edge on same target, and pre-existing
    non-operator/monitored rows loaded across restart.
- **`confirm_recovery(timeout_s=...)` & `hub.close(timeout_s=...)` under paused
  Phase 2:**
  - Validates `timeout_s` (rejects `bool`, `NaN`, `Inf`, `< 0`), verifies wedged
    Phase-2 timeout fails closed (`_ERR_CLEANUP_INCOMPLETE` staying degraded;
    `_ERR_CLOSE_INCOMPLETE` retaining `.coord_session_active` and
    `_state_lock_fd`), and verifies `close()` interrupts `confirm_recovery()`
    wait promptly.
- **PR #50 hygiene follow-up:**
  - Tighten `test_r11_p2_1_unsupported_pending_peer_turn_does_not_block_eligible_turn_and_new_send_rejected`
    in `test_gate2_regressions.py` with an equal-priority (`priority=0`)
    ordering assertion.

### 4.4 Reusable Combined-Pass SQLite Evidence Verifier API

Exported from `docs/prds/spikes/m/test_restart_qualification.py` for the
combined attended pass:

```python
@dataclass(frozen=True, slots=True)
class CombinedPassExpectations:
    completed_msg_ids: tuple[str, ...] = ()
    cancelled_msg_ids: tuple[str, ...] = ()
    uncertain_msg_ids: tuple[str, ...] = ()
    aborted_msg_ids: tuple[str, ...] = ()
    expected_attempts: Mapping[str, int] = field(default_factory=dict)
    tombstoned_grants: tuple[tuple[str, int], ...] = ()
    expected_stream_substrings: Mapping[str, str] = field(default_factory=dict)
    expected_revoked_sandboxes: tuple[str, ...] = ()
    expected_unconfirmed_bindings: tuple[tuple[str, str], ...] = ()

def verify_combined_pass_evidence(
    registry: CoordRegistry,
    expectations: CombinedPassExpectations,
) -> dict[str, Any]:
    """Assert SQLite outbox, tombstones, receipts, stream provenance, unconfirmed bindings, and audit hash chain."""
    ...
```

`verify_combined_pass_evidence()` operates read-only on an existing
`CoordRegistry` (never touching `.coord_hub.lock` or `.coord_session_active`)
and verifies:

- Exact `outbox.status` and `attempts` (`0` for pre-handoff revoked, `1` for
  uncertain/completed, matching `expected_attempts`).
- Presence of every `(edge_id, grant_generation)` in `grant_tombstones`.
- Zero unconsumed `dispatch_receipts` (`consumed_at IS NULL`) for all
  `cancelled` and `aborted` messages.
- `stream_events` provenance: `badge IS NULL` on every non-`user_message`
  event, and non-elevated `badge` vs `event_log.trust_class` on `user_message`
  events.
- Required `text_delta` substring recorded strictly before `turn_completed`
  (`seq` order) for every entry in `expected_stream_substrings`.
- Every `expected_revoked_sandboxes` entry has `sandboxes.status == 'revoked'`.
- Exact unconfirmed `external_transport_bindings` set (empty by default).
- Unpacked `ok, count = registry.verify_audit_chain()` with `ok is True and count > 0`.

---

## 5. Verification Gates Before Implementation PR

1. Gate 1 walkthrough cleared by both external/security reviewers and Codex
   before writing implementation code.
2. Zero edits outside `docs/prds/spikes/m/` (and zero edits under `local/`).
3. `python3 -B -m unittest discover -s docs/prds/spikes/m -p 'test_*.py' -v`
   passes under both default `$HOME/.cache` and `/tmp` `TMPDIR` with zero
   `__pycache__` left behind.
4. Static hygiene and SonarCloud AST checks (cognitive complexity `<= 15`
   including nested closures, no bare `BaseException`, no nested `with`, no
   duplicated string literals `>= 3x`, `git diff --check` clean).
5. Reciprocal adversarial review and 10/10 green hosted checks before any merge
   decision by the user.
