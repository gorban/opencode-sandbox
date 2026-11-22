# PRD M Shared Contract, Fenced Handoff, and Joint Restart Walkthrough

This Gate 1 implementation walkthrough covers the coordination lane under
`docs/prds/spikes/m/` (outside `docs/prds/spikes/m/local/`) starting from `main`
(`f823ba1f1f70504ec6d284a11f4da5eccc6d9799`). It aligns directly with the local
adapter walkthrough (`docs/prds/spikes/m/local/ADAPTER_WALKTHROUGH.md`) and
defines the smallest qualifying first pass for the
[PRD M first PoC split](../../prd_m.md#first-poc-split):

1. Small additive adjustments to [oc_coord_contract.py](oc_coord_contract.py):
   `DispatchResult.permanent` and the narrow opt-in `ExternallyFencedTransport`
   protocol.
2. Preserving the existing synchronous hub fence for all existing transports,
   while adding a narrowly opted-in split-phase handoff path **only** for
   operator-only, unmonitored, whole-incarnation externally-fenced relay
   adapters.
3. Durable transport-abort tracking (`pending_transport_aborts` in
   [oc_registry.py](oc_registry.py)) so failed fence installation or hub crash
   cannot be bypassed by a SQLite tombstone alone and replacement stays fenced
   until terminal abort is confirmed.
4. Transport-parameterized joint restart qualification fixtures and the
   combined-pass SQLite evidence verifier in `test_restart_qualification.py`.

**Explicitly deferred out of this first pass:** scoped native per-turn abort
(`abort_stream` / `revoke_grant` on real OpenCode), monitored/peer turns over
the split-phase cross-process relay, production launcher wiring, live provider
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
| `docs/prds/spikes/m/oc_coord_contract.py` | Coordination lane (sole owner) | Additive `DispatchResult.permanent` (strictly validated) and opt-in `ExternallyFencedTransport` protocol |
| `docs/prds/spikes/m/oc_registry.py` | Coordination lane | Durable `pending_transport_aborts` table and helpers (`record_pending_transport_abort`, `clear_pending_transport_abort`, `list_pending_transport_aborts`, `has_pending_transport_abort`) |
| `docs/prds/spikes/m/oc_hub.py` | Coordination lane | Narrowly opted-in split-phase dispatch for `ExternallyFencedTransport` (existing transports stay on synchronous fence), operator-only/unmonitored/sole-grant enforcement, durable `pending_transport_aborts` gating & restart reconstruction, Phase 3 settlement ownership until durable/cleanup transfer, `DispatchResult.permanent` & detail sanitization, minimal-transport post-race abort settlement, validated `confirm_recovery(timeout_s=...)` |
| `docs/prds/spikes/m/oc_fake_worker.py` | Coordination lane | Test helper script modes (`permanent=True` refusal, paused pre-write / post-receipt hooks) and opt-in externally-fenced fake wrapper |
| `docs/prds/spikes/m/test_restart_qualification.py` | Coordination lane | Transport-parameterized 5-checkpoint qualification suite, explicit separate clean-restart fixture, failed-fence crash/restart fixture, post-receipt barrier fixture, and `verify_combined_pass_evidence()` |
| `docs/prds/spikes/m/test_coord_contract.py`, `test_hub.py`, `test_gate2_regressions.py` | Coordination lane | Contract validation tests, split-fence & durable-abort regressions, and equal-priority `priority=0` tightening for `test_r11_p2_1` |
| `docs/prds/spikes/m/local/*` | Local OpenCode lane | **Untouched** (read-only interface alignment) |

---

## 2. Small Shared Handoff, Refusal, and Opt-In Fence Contract

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

Logical-thread to native-session mapping and any internal relay identifiers
stay private inside the adapter. Every emitted `StreamEvent` must bind back to
the host-assigned `(sandbox_addr, incarnation_id, thread_id, message_id)`
without elevating provenance.

- **Hub text/stream limits (`oc_coord_contract.py`):**
  `MAX_INLINE_BODY_BYTES = 65_536`, `MAX_FRAMED_BODY_BYTES = 69_632`,
  `MAX_STREAM_EVENT_BYTES = 262_144`, `MAX_TURN_STREAM_EVENTS = 2_048`,
  `MAX_REASON_BYTES = 256`.
- **Local worker HTTP frame cap (`docs/prds/spikes/m/local/client.py`):**
  `MAX_REQUEST = 65_536` bytes including request line, headers, and JSON body.
- **Adapter enforcement rule:** The adapter validates pins, `body_sha256`,
  absence of unsupported `artifact_refs`, and the fully encoded HTTP request
  size (`<= 65_536` bytes) **before dialing the relay socket or writing any
  bytes**, refusing invalid/oversize inputs without widening limits or silently
  truncating.

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
   safely on UTF-8 boundaries to `<= MAX_REASON_BYTES`, falling back to a fixed
   token such as `"dispatch_refused"` if empty) **before** calling
   `cancel_outbox_row()`, `append_audit()`, or constructing a host
   `StreamEvent`. This prevents a hostile or long `detail` from raising
   `CoordValidationError` inside `cancel_outbox_row()` and stranding a row in
   `dispatch_started`.
3. **`ZERO_BYTES_SENT(permanent=False)`** (e.g. single-turn slot busy,
   `BlockingIOError`, or raced with grant fence): if fenced or recovery rotated,
   transition `dispatch_started -> cancelled`; otherwise return to `pending`
   for retry.
4. **`ZERO_BYTES_SENT(permanent=True)`** (deterministic pre-write refusal:
   encoded HTTP frame `> 65_536` bytes, unsupported `artifact_refs`, pin or
   digest mismatch, or incarnation poisoned by prior `UNCERTAIN` attempt):
   - Transition `dispatch_started -> cancelled` with sanitized reason (never
     returned to `pending`; eliminates infinite hot-retry loops).
   - Append bounded audit entry `dispatch_rejected_pre_write`.
   - When full liveness still holds (`not self._is_closed()`,
     `self._recovery_generation == start_rec_gen`,
     `not inflight.revoked_observed`, and
     `_classify_row_liveness_under_fence(..., src_incarnation=env.src_incarnation) == "live"`),
     record a host-authored `StreamEvent(event_type="turn_error", ...)` via
     `self._registry.record_stream_event(err_ev, dispatch_msg_id=env.msg_id)`
     (mandatory `dispatch_msg_id=env.msg_id` so scoped waiters receive their
     own error while `OPERATOR_DIRECTIVE` errors stay isolated from peer
     waiters) and notify waiters.
5. **`UNCERTAIN`** (partial write, lost receipt, timeout, or transport
   exception): transition `dispatch_started -> uncertain`; never replay.

### 2.3 Additive Adjustment B: Narrow Opt-In `ExternallyFencedTransport`

Add one small `@runtime_checkable` sub-protocol in `oc_coord_contract.py` so
existing transports remain untouched on the synchronous hub fence and only an
explicitly opted-in cross-process relay adapter enters the split-phase path:

```python
@runtime_checkable
class ExternallyFencedTransport(WorkerTransport, Protocol):
    """Opt-in protocol for an operator-only, unmonitored, whole-incarnation relay adapter."""

    @property
    def external_write_fence(self) -> bool:
        """Return True to opt into CoordHub's narrow operator-only split-phase handoff."""
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
2. `grant_edge()`:
   - Requires `caller.role is CoordRole.OPERATOR`,
     `src_actor == caller.canonical_sender` (an `operator:*` principal),
     `src_incarnation is None`, and `lease_request_id is None`.
   - Enforces **sole active grant per incarnation**: rejects creating a second
     active edge for a `dst_addr` that already has an active edge
     (`CoordPolicyError("external_fence_single_grant_only")`).
3. `send()` and `dispatch_once()`:
   - Re-checks eligibility both on admission (`send()`) and when dispatching
     persisted rows after restart (`dispatch_once()`): rejects (at `send()`) or
     non-blockingly skips (at `dispatch_once()`) any row whose `src_actor` is
     not `operator:*`, `src_incarnation is not None`, `edge.lease_request_id is
     not None`, sandbox has any `controller_request_id`, or `dst_addr` has more
     than one active edge.
4. **Terminal `abort_incarnation()` contract on `ExternallyFencedTransport`:**
   - Must close broker admission/held responses, publish terminal state under
     the relay's write fence (`/grant/lock` + `/grant/state = terminal`, or
     confirmed stop of the matching relay container), and close owned stream
     readers so `stream_events()` terminates promptly.
   - Returns `bool` (`True` if active turns/streams were stopped, `False` if
     idle) **only** when terminal grant state or verified relay stop is
     positively confirmed.
   - Must **raise an exception** (never return silently) if neither terminal
     state nor verified relay stop could be confirmed.

---

## 3. Fence Architecture, Settlement Ownership, and Durable Abort Rules

### 3.1 Existing Transports Keep Synchronous Hub Fence Unchanged

When `_is_externally_fenced()` is `False` (`FakeWorkerTransport`, minimal
`WorkerTransport`, and all monitored/peer/multi-edge transports),
`CoordHub._dispatch_single_row()` keeps its existing synchronous `with fence:`
execution across `mark_outbox_dispatch_started -> dispatch_turn ->
_handle_dispatch_result_locked`. Because controller-monitored and peer turns
run exclusively on this synchronous path, no controller-outage or per-edge
Phase-2 window is opened for existing transports.

### 3.2 Narrow Split-Phase Handoff (Only When `_is_externally_fenced()` Is `True`)

For an opted-in `ExternallyFencedTransport`, the relay's cross-process `flock`
on `/grant/lock` (`docs/prds/spikes/m/local/relay.py:83-102`) is the actual
worker-facing first-write fence, and the sole governing authority is the whole
incarnation grant. Holding `CoordHub._grant_fences[edge_id]` across
`dispatch_turn()` would wait for a relay receipt inside the synchronous hub
fence and stall `hub.revoke()` Step 1 before Step 2 can call
`abort_incarnation()`.

#### Phase 1 — Hub Pre-Write Admission Fence (holds `fence`, zero IPC)

1. Check `not closed`, `not degraded`, envelope exists, `liveness == "live"`,
   and operator-only/unmonitored/sole-grant eligibility holds.
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
   - Validate pins, digest, no `artifact_refs`, and encoded HTTP frame
     `<= 65_536` bytes before dialing (`ZERO_BYTES_SENT(permanent=True)` on
     refusal).
   - Reserve the single stream slot before worker I/O (`ZERO_BYTES_SENT(permanent=False)`
     if busy; `ZERO_BYTES_SENT(permanent=True)` if incarnation is blocked by a
     prior `UNCERTAIN` attempt).
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
`_pending_cleanup_streams` / `_pending_cleanup_incarnations` +
`pending_transport_aborts`). Only in the outer `finally:` **after Phase 3
releases `fence`** is `env.msg_id` popped from `self._inflight_handoffs` and
`self._inflight_cond.notify_all()` signaled.

Lock ordering remains strictly acyclic: `_register_lock -> fence -> _meta_lock`
(`confirm_recovery()` releases all `fences` in Phase 1 before waiting on
`_inflight_cond`, which uses `_meta_lock`). `close()` also calls
`self._inflight_cond.notify_all()`, and `confirm_recovery()` checks
`self._closed` in its wait loop so `close()` never stalls behind `timeout_s`.

Inside Phase 3 (holding `fence`, still owning `self._inflight_handoffs[msg_id]`):

1. Validate `isinstance(result, DispatchResult)`; non-`DispatchResult` or
   exception during Phase 2 is treated fail-closed as `UNCERTAIN`.
2. Check whether recovery rotated (`self._recovery_generation != start_rec_gen`):
   - **Late `HANDED_OFF(stream_id)` after recovery started:**
     - Do **not** call `mark_outbox_handed_off()`, do **not** launch
       `_consume_stream()`, and do **not** insert into `_stream_authorities`
       (zero leaked stream handle).
     - Record `stream_id` in `_pending_cleanup_streams` (with
       `_REASON_RECOVERY_RETIRED`) and ensure `(env.dst_addr, env.dst_incarnation)`
       is in `_pending_cleanup_incarnations` and SQLite `pending_transport_aborts`.
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
     `_REASON_HANDOFF_PERSIST_FAILED`, record `pending_transport_aborts`, mark
     `uncertain` / degraded).
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
     `inf.dst_incarnation` to `inc_set` (essential after restart or
     `lookup_failed`), and adds `(inf.edge_id, inf.grant_generation)` to
     `_fenced_generations`.
   - `_rotate_existing_sandbox()` acquires affected edge `fences`, fences
     `(addr, existing.incarnation_id)` and matching `_inflight_handoffs`,
     records durable `pending_transport_aborts`, and requires confirmed
     `abort_incarnation()` before permitting replacement.
2. **Minimal-transport late-`HANDED_OFF` settlement (no `abort_stream`):**
   - In `_settle_stream_without_abort_stream()`, call idempotent
     `abort_incarnation(dst_addr, dst_inc, reason=reason)` for **all**
     minimal-transport terminal reasons (`_STATUS_REVOKED`,
     `_REASON_HANDOFF_PERSIST_FAILED`, `_REASON_RECOVERY_RETIRED`), rather than
     assuming an empty `_pending_cleanup_incarnations` implies post-handoff
     settlement.
   - In `_apply_immediate_stream_abort()`, when the transport lacks
     `abort_stream`, invoke `_settle_stream_without_abort_stream()` synchronously
     *before* `_run_stream_task()` (enqueuing `_pending_cleanup_streams` and
     starting the retry worker only if it fails) so synchronous
     `dispatch_once(async_stream=False)` does not block inside `stream_events()`.
   - When cleanup settles any unconsumed stream (not only
     `_REASON_HANDOFF_PERSIST_FAILED`), pop its `_stream_authorities` and
     `_stream_abort_reasons` entries cleanly.

### 3.4 Durable Failed-Transport-Revoke & Restart Settlement Rule

A SQLite grant tombstone attests only to the hub's decision; it cannot attest
that a separately owned relay published terminal state or stopped.

1. **Durable SQLite table (`oc_registry.py`):**
   ```sql
   CREATE TABLE IF NOT EXISTS pending_transport_aborts (
       sandbox_addr TEXT NOT NULL,
       incarnation_id TEXT NOT NULL,
       reason TEXT NOT NULL,
       created_at REAL NOT NULL,
       PRIMARY KEY (sandbox_addr, incarnation_id)
   )
   ```
   Methods: `record_pending_transport_abort(sandbox_addr, incarnation_id, reason)`,
   `clear_pending_transport_abort(sandbox_addr, incarnation_id)`,
   `list_pending_transport_aborts()`, and
   `has_pending_transport_abort(sandbox_addr)`.
2. **Order during `revoke()`:**
   - Step 1: Fence in memory (`_fenced_addrs`, `_fenced_targets`,
     `_fenced_generations`, `_inflight_handoffs`, `_pending_cleanup_incarnations`).
   - Step 2: Best-effort persist `(addr, inc_id)` into SQLite
     `pending_transport_aborts` (on DB failure, mark degraded and continue
     teardown so transport abort is never skipped).
   - Step 3: Call `transport.abort_incarnation(addr, inc_id, reason=...)`
     outside `fence`:
     - On confirmed success (returns normally): remove `(addr, inc_id)` from
       `_pending_cleanup_incarnations` and clear it from SQLite
       `pending_transport_aborts`.
     - On failure (raises exception): keep `(addr, inc_id)` in **both**
       `_pending_cleanup_incarnations` and SQLite `pending_transport_aborts`,
       still persist the SQLite tombstone + `sandboxes.status = 'revoked'` +
       audit, start the cleanup retry worker, keep admission fenced, and—for
       `ExternallyFencedTransport`—immediately call
       `_mark_degraded("transport_abort_unconfirmed")` and **raise
       `CoordPolicyError(_ERR_REVOKED_UNCONFIRMED)`** as the externally visible
       result. (Existing non-externally-fenced transports preserve their
       background retry-to-settle behavior while still enforcing durable
       `pending_transport_aborts` replacement refusal and crash-restart
       reconstruction.)
3. **Replacement refusal gate:**
   - `register_sandbox()` checks both in-memory `_pending_cleanup_incarnations`
     and SQLite `has_pending_transport_abort(addr)` and refuses to register or
     replace `addr` (`CoordPolicyError("transport_abort_unconfirmed")`) until
     terminal abort of the prior incarnation is confirmed.
4. **Crash/restart reconstruction & `confirm_recovery(caller, *, reason=..., timeout_s: float = 2.0)`:**
   - Validate `timeout_s`: reject `bool`, non-finite (`NaN`/`Inf`), or
     `timeout_s < 0` (`CoordValidationError`).
   - On `confirm_recovery()`:
     - Phase 1 acquires all edge `fences`, fences all edges/sandboxes/inflight,
       reconstructs `_pending_cleanup_incarnations` from **both** SQLite
       `pending_transport_aborts` and `sandboxes` (persisting
       `pending_transport_aborts` for every incarnation being retired),
       releases `fences`, and immediately runs `_drain_pending_cleanups()`
       (calling `abort_incarnation()` so a paused relay unblocks rather than
       deadlocking; clearing `pending_transport_aborts` only on confirmed
       success).
     - Wait on `_inflight_cond` up to `timeout_s` (checking `self._closed`)
       until `_inflight_handoffs` is empty. If any pre-recovery handoff remains
       unsettled past deadline, raise `CoordPolicyError(_ERR_CLEANUP_INCOMPLETE)`
       and remain degraded.
     - Re-run `_drain_pending_cleanups()` to settle any stream/incarnation
       cleanup transferred by Phase 3, then verify both
       `not self._has_pending_cleanups()` and
       `not self._registry.list_pending_transport_aborts()` before running
       Phase 2 DB retirements and unlinking `.coord_degraded`.

---

## 4. Joint Qualification Checkpoints, Fixture API, and Adversarial Suites

New module: `docs/prds/spikes/m/test_restart_qualification.py`.

### 4.1 Five Fixed Joint-Proof Checkpoints (Shared Across Fake and Real Local Adapter)

Both the coordination lane (using an opt-in externally-fenced fake) and the
combined attended pass (using the real local OpenCode adapter) verify the exact
same five fixed checkpoints:

1. **Checkpoint 1 — Authorized operator turn with real stream and scratch edit:**
   - Register fresh incarnation `inc_1` + sole unmonitored operator grant `G1`.
   - Dispatch an authorized operator prompt -> observe streamed `text_delta`
     before `turn_completed`, independently verify the scratch file edit, and
     confirm SQLite `outbox.status == 'completed'` (`attempts == 1`),
     non-elevated provenance (`badge IS NULL` on worker-derived events), and
     intact audit hash chain (`ok, count = reg.verify_audit_chain()` with
     `ok is True and count > 0`).
2. **Checkpoint 2 — Held execution, paused pre-write race, and terminal fencing:**
   - Start a held execution turn (`stream_events` active) and pause a separate
     pre-write dispatch (`OpenCode.pause_prompt` at `local/client.py:448` /
     `local/probe.py:129`, or fake pre-write barrier).
   - Call `hub.revoke(_OP, target=...)` while the pre-write dispatch is paused:
     assert `hub.revoke()` completes in `< 0.5s` without stalling on Phase 2,
     the held stream closes, the stale bearer is refused (HTTP 403) while the
     containers remain running with zero new broker admissions, and releasing
     the pause yields positive `ZERO_BYTES_SENT` (`status == 'cancelled'`, zero
     bytes delivered to worker).
3. **Checkpoint 3 — Queued old-incarnation turn absent from worker after hub recovery/restart:**
   - Queue a `pending` turn on `inc_1` (`G1`) without dispatching it before
     revoke (and separately cover unclean crash restart leaving
     `.coord_session_active` + `pending` + orphaned `dispatch_started`).
   - Reopen Hub 2 against the persisted SQLite DB while the terminal worker and
     relay remain present (plus degraded crash-recovery via
     `confirm_recovery()`): verify zero worker delivery, `outbox.status ==
     'cancelled'` (`attempts == 0` for pre-handoff revoked), `(edge_1, 1)` in
     `grant_tombstones`, zero unconsumed `dispatch_receipts`, and refusal to
     re-register `inc_1` (`RevokedError`).
4. **Checkpoint 4 — Uncertain handoff never replayed:**
   - Persist an `UNCERTAIN` outcome (partial write / lost receipt ->
     `outbox.status == 'uncertain'`, `attempts == 1`).
   - Across both clean hub restart and degraded `confirm_recovery()`, assert
     `attempts` remains `1`, status remains `uncertain`, and the transport
     receives zero replay attempts for that `msg_id`.
5. **Checkpoint 5 — New authorized incarnation still works:**
   - After terminal abort confirmation / recovery, register a fresh incarnation
     `inc_2` with a fresh grant `G2` (and fresh broker/job on the real pass),
     dispatch an authorized operator turn, verify `completed` + stream delta +
     `verify_combined_pass_evidence()`.

### 4.2 Explicit Separate Case: Clean Hub Restart on an Unrevoked Live Incarnation

Clean same-incarnation continuation is **strictly separate** from the revoked
case and is **not** claimed across host-process loss on a real relay (because
host-process exit closes `/grant/lifetime` and makes the relay permanently
inert per `docs/prds/spikes/m/local/ADAPTER_WALKTHROUGH.md`). It is tested as
a separate fixture (`test_clean_restart_unrevoked_eligible_row_authority`) with
explicit authority evidence required before `hub2` dispatches `msg_eligible`:

1. `hub1.close()` completed cleanly (`.coord_session_active` unlinked,
   `hub2.is_degraded is False`, no detached in-memory `BrokerLease`).
2. `sandboxes` row has `status == 'running'` and matching `incarnation_id`.
3. `pending_transport_aborts` has **zero** rows for that `sandbox_addr`.
4. `routing_edges` row is `active == 1` at `grant_generation`, absent from
   `grant_tombstones`.
5. Unmonitored operator edge (or controller-confirmed-active if controller-bound)
   and live transport grant (`status().revoked is False`).

### 4.3 Additional Mandatory Adversarial Fixtures in `test_restart_qualification.py`

- **Failed fence installation + hub crash/loss + restart with old transport
  still present:** inject failure into `abort_incarnation()` on an
  `ExternallyFencedTransport` -> `hub1.revoke()` persists tombstone +
  `pending_transport_aborts`, marks degraded, raises `_ERR_REVOKED_UNCONFIRMED`,
  and refuses replacement with `inc_2`. Simulate hub crash (abandon `hub1`
  without clean close while old transport with live `inc_1` stays present) ->
  `hub2` boots degraded, first `confirm_recovery()` reconstructs `inc_1` from
  `pending_transport_aborts`, fails with `_ERR_CLEANUP_INCOMPLETE`, stays
  degraded, and still refuses `inc_2`. Clear transport fault -> second
  `confirm_recovery()` confirms terminal abort, clears `pending_transport_aborts`,
  and reopens -> fresh `inc_2` succeeds.
- **Post-receipt Phase-3 pause barrier:** pause Phase 3 immediately after
  `dispatch_turn()` returns `HANDED_OFF(stream_id)` and before Phase 3
  re-acquires `fence` / settles ownership. Start `confirm_recovery()` from a
  second thread -> assert `confirm_recovery()` stays closed
  (`is_degraded is True`) while the returned stream has no settled owner.
  Release the pause -> Phase 3 transfers `stream_id` to tracked cleanup,
  records durable `uncertain`, releases `fence`, and only then pops
  `_inflight_handoffs` and wakes `confirm_recovery()` -> recovery settles
  cleanup with zero leaked `_stream_authorities` and zero ordinary deltas.
- **Minimal-transport late-`HANDED_OFF` race:** `dispatch_turn()` finishes
  microseconds before `hub.revoke()` on an `ExternallyFencedTransport` without
  `abort_stream`; Phase 3 settles synchronously via idempotent
  `abort_incarnation()`, records zero ordinary deltas, and leaves zero stranded
  `_pending_cleanup_streams`.
- **Permanent pre-write refusal & hostile detail sanitization:** oversize
  encoded HTTP frame (`> 65_536` bytes), unsupported `artifact_refs`, and
  unsanitized `result.detail` (control chars / `> 256` bytes) return
  `ZERO_BYTES_SENT(permanent=True)` -> `cancelled`, zero retry on next
  `dispatch_once()`, sanitized audit `dispatch_rejected_pre_write`, and host
  `turn_error` with `dispatch_msg_id=env.msg_id` waking `wait()`.
- **Operator-only / unmonitored / sole-grant guardrails on
  `ExternallyFencedTransport`:** rejects `BrokerLease`, `controller_request_id`,
  non-operator `grant_edge`, `lease_request_id`, second active edge on same
  target, and pre-existing non-operator/monitored rows loaded across restart.
- **`confirm_recovery(timeout_s=...)` & `hub.close(timeout_s=...)` under paused
  Phase 2:** validates `timeout_s` (rejects `bool`, `NaN`, `Inf`, `< 0`),
  verifies wedged Phase-2 timeout fails closed (`_ERR_CLEANUP_INCOMPLETE`
  staying degraded; `_ERR_CLOSE_INCOMPLETE` retaining `.coord_session_active`
  and `_state_lock_fd`), and verifies `close()` interrupts `confirm_recovery()`
  wait promptly.
- **PR #50 hygiene follow-up:** tighten
  `test_r11_p2_1_unsupported_pending_peer_turn_does_not_block_eligible_turn_and_new_send_rejected`
  in `test_gate2_regressions.py` with an equal-priority (`priority=0`) ordering
  assertion.

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
    expected_pending_aborts: tuple[tuple[str, str], ...] = ()

def verify_combined_pass_evidence(
    registry: CoordRegistry,
    expectations: CombinedPassExpectations,
) -> dict[str, Any]:
    """Assert SQLite outbox, tombstones, receipts, stream provenance, pending aborts, and audit hash chain."""
    ...
```

`verify_combined_pass_evidence()` operates on an existing `CoordRegistry` (never
touching `.coord_hub.lock` or `.coord_session_active`) and verifies:

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
- Exact `pending_transport_aborts` set (empty by default).
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
