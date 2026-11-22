# PRD M Shared Contract, Fenced Handoff, and Joint Restart Walkthrough

This Gate 1 implementation walkthrough covers the coordination lane under
`docs/prds/spikes/m/` (outside `docs/prds/spikes/m/local/`) starting from `main`
(`f823ba1f1f70504ec6d284a11f4da5eccc6d9799`). It specifies:

1. Exact additive adjustments to the shared `WorkerTransport` contract in
   [oc_coord_contract.py](oc_coord_contract.py).
2. The split-phase hub fence and transport-owned worker-write fence required so
   `CoordHub` can drive both `FakeWorkerTransport` and the cross-process local
   OpenCode relay without waiting for relay receipts or HTTP/SSE inside the
   synchronous hub fence.
3. The transport-parameterized joint restart qualification suite
   (`test_restart_qualification.py`) and combined-pass SQLite evidence verifier
   for the [PRD M first PoC split](../../../prd_m.md#first-poc-split).

No production launcher wiring, live provider credentials, real sandbox homes, or
changes under `docs/prds/spikes/m/local/` or `docs/prds/spikes/n/` are in scope.
All open PRD M product decisions and final human review gates remain open.

---

## 1. Ownership and File Boundaries

| Path | Owner | Changes in this slice |
|---|---|---|
| `docs/prds/spikes/m/RESTART_WALKTHROUGH.md` | Coordination lane | This Gate 1 walkthrough |
| `docs/prds/spikes/m/oc_coord_contract.py` | Coordination lane (sole owner) | Additive `StreamAbortableTransport` protocol and `DispatchResult.permanent` |
| `docs/prds/spikes/m/oc_hub.py` | Coordination lane | 3-phase split dispatch fence, `revoke_grant` cleanup tracking, permanent pre-write refusal handling, minimal-transport post-race abort settlement |
| `docs/prds/spikes/m/oc_fake_worker.py` | Coordination lane | `revoke_grant()` support and paused pre-write / permanent-refusal script modes |
| `docs/prds/spikes/m/test_restart_qualification.py` | Coordination lane | New transport-parameterized restart qualification suite + combined-pass SQLite evidence verifier |
| `docs/prds/spikes/m/test_coord_contract.py`, `test_hub.py`, `test_gate2_regressions.py` | Coordination lane | Contract tests, split-fence race regressions, and equal-priority `priority=0` tightening for `test_r11_p2_1` |
| `docs/prds/spikes/m/local/*` | Local OpenCode lane | **Untouched** (read-only interface alignment) |

---

## 2. Shared Contract, Pins, and Bounded Limits

### 2.1 Unchanged Public Pins

The existing public shapes in `oc_coord_contract.py` already carry every pin
needed for the first local operator turn:

- `TurnDispatch`: `msg_id`, `sandbox_addr`, `incarnation_id`, `thread_id`,
  `trust_class`, `msg_kind`, `wire_text`, `body_sha256`, `artifact_refs`,
  `edge_id`, `lease_request_id`, `grant_generation`.
- `StreamEvent`: `event_type`, `sandbox_addr`, `incarnation_id`, `thread_id`,
  `seq_hint`, `message_id`, `text`, `file_path`, `detail`, `created_at`.
- `WorkerStatus`: `sandbox_addr`, `incarnation_id`, `state`, `active_turns`,
  `revoked`, `last_error`.

The adapter keeps logical-thread to native-session mapping and any internal
relay operation identifiers private. `TurnDispatch.thread_id` remains the
host-owned logical thread ID (for example `"main"`), and every emitted
`StreamEvent` must bind back to the host-assigned `(sandbox_addr, incarnation_id,
thread_id, message_id)` without elevating provenance. `CoordHub` continues to
own source, edge, and destination authority checks.

### 2.2 Size and Event Bounds (Zero Widening, Zero Silent Truncation)

- **Hub text/stream limits (`oc_coord_contract.py`):**
  - `MAX_INLINE_BODY_BYTES = 65_536`
  - `MAX_FRAMED_BODY_BYTES = 69_632`
  - `MAX_STREAM_EVENT_BYTES = 262_144`
  - `MAX_TURN_STREAM_EVENTS = 2_048`
- **Local worker HTTP frame cap (`docs/prds/spikes/m/local/client.py`):**
  - `MAX_REQUEST = 65_536` bytes for the complete HTTP/1.1 request including
    request line, headers, and JSON body.
- **Adapter enforcement rule:** Because an inline body that passes the hub's
  `65_536`-byte text check can exceed `65_536` bytes once JSON-escaped and
  wrapped in HTTP headers (or carry `artifact_refs` not yet supported by the
  local adapter), the adapter must enforce its encoded wire-frame limit and
  artifact support checks **before opening a worker socket or writing any
  bytes**. Oversize frames and unsupported artifact forms are refused cleanly
  without widening limits or silently truncating.

### 2.3 Additive Adjustment A: `DispatchResult.permanent`

Physical wire handoff still has exactly three outcomes in `DispatchOutcome`,
matching `local/client.py`:

- `HANDED_OFF`: every request byte was submitted to the worker socket under the
  write fence (`stream_id` required); distinct from turn completion.
- `ZERO_BYTES_SENT`: positive proof that zero request bytes reached the worker.
- `UNCERTAIN`: partial write, lost receipt, timeout, or transport exception;
  the hub must never replay the turn.

**Problem solved:** Currently, `CoordHub._handle_zero_bytes_result()` returns a
`ZERO_BYTES_SENT` row to `pending` whenever the grant is still live. If an
adapter refuses an oversize encoded HTTP frame or unsupported `artifact_refs`
before writing bytes and returns `ZERO_BYTES_SENT`, `OutboxDispatcher` would
re-dispatch that row in an infinite hot loop. Raising an exception instead would
misclassify a proven zero-byte refusal as `UNCERTAIN`.

**Adjustment:** Add `permanent: bool = False` to `DispatchResult`:

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
        if self.permanent and self.outcome is not DispatchOutcome.ZERO_BYTES_SENT:
            raise CoordValidationError("permanent refusal requires DispatchOutcome.ZERO_BYTES_SENT")
```

- Backwards-compatible default (`permanent=False`) preserves all existing callers
  and tests (`proves_zero_bytes_sent` remains `self.outcome is DispatchOutcome.ZERO_BYTES_SENT`).
- `DispatchResult(ZERO_BYTES_SENT, detail="<bounded_reason>", permanent=True)`:
  1. Transitions the outbox row `dispatch_started -> cancelled` (never returned to
     `pending`).
  2. Appends a bounded `dispatch_rejected_pre_write` audit entry with sanitized
     reason detail.
  3. When the edge and target are not fenced and recovery has not rotated,
     records a host-authored `turn_error` stream event tied to `env.msg_id` and
     notifies waiters so `wait()` callers fail fast rather than timing out.

### 2.4 Additive Adjustment B: `StreamAbortableTransport` Sub-Protocol

Add an opt-in `@runtime_checkable` sub-protocol in `oc_coord_contract.py`
extending `WorkerTransport`:

```python
@runtime_checkable
class StreamAbortableTransport(WorkerTransport, Protocol):
    def abort_stream(self, stream_id: str, *, reason: str) -> bool:
        """Stop worker execution for one stream without revoking its incarnation or other turns."""
        ...

    def revoke_grant(self, edge_id: str, grant_generation: int, *, reason: str) -> bool:
        """Fence (edge_id, grant_generation) under the worker-facing write fence so no byte is written after edge revoke."""
        ...
```

**Capability gating rules:**

1. **Base `WorkerTransport` (minimal operator-only unmonitored seam):**
   - Does not need `abort_stream()` or `revoke_grant()`.
   - `CoordHub` admits only unmonitored operator/self turns (zero
     controller-monitored `req_ids`, no independent sender `src != dst`).
   - Every applicable revocation on this seam revokes the entire incarnation via
     `abort_incarnation(sandbox_addr, incarnation_id, *, reason)`.
2. **`StreamAbortableTransport` (monitored, multi-edge, and peer-enabled seam):**
   - Required by `CoordHub` whenever a turn has any controller-monitored
     `req_ids` or an independent sender (`src_addr != dst_addr`), enforced
     upfront in `send()` and non-blockingly skipped in `dispatch_once()`.
   - `abort_stream(stream_id, *, reason)` must prove scoped cancellation of the
     selected turn on the worker without revoking the entire incarnation or
     falsely settling another turn. Closing a host-side reader socket alone is
     not sufficient evidence that worker execution stopped.
   - `revoke_grant(edge_id, grant_generation, *, reason)` serializes per-edge
     revocation with the transport's worker-facing first write when the
     destination incarnation remains alive for other edges.

---

## 3. Shared Fence Path: Why a Contract/Hub Adjustment Is Needed and Exact Ordering

### 3.1 Why Holding `CoordHub._grant_fences[edge_id]` Across `dispatch_turn()` Fails on a Cross-Process Relay

In `docs/prds/spikes/m/local/relay.py`, the actual worker-facing first write
(`worker.send(request)`) runs inside the isolated relay sidecar container under
the cross-process `flock` on `/grant/lock`, and the host receives a 1-byte
receipt (`b"H"`, `b"Z"`, or `b"U"`/EOF) over `/control/control.sock`.

Previously, `CoordHub._dispatch_single_row()` held `fence = _get_grant_fence(edge_id)`
across `mark_outbox_dispatch_started -> transport.dispatch_turn(turn) ->
_handle_dispatch_result_locked`. For a cross-process relay this creates two
contradictory failure modes:

- If `dispatch_turn()` waits for the relay's 1-byte receipt while `CoordHub`
  holds `fence`, `hub.revoke()` blocks in Step 1 (`_fence_target_in_memory`)
  waiting for `fence` and **cannot reach Step 2 (`transport.abort_incarnation()`)**
  to write `/grant/state = terminal` or stop a slow/paused relay. A paused relay
  race (`local/probe.py:pause_prompt`) deadlocks `hub.revoke()`.
- Conversely, if `dispatch_turn()` returned `HANDED_OFF` as soon as bytes were
  queued into `/control/control.sock` without waiting for the relay's worker
  write receipt, host socket enqueue would be misreported as worker handoff and
  positive `ZERO_BYTES_SENT` / `UNCERTAIN` evidence would be lost.

### 3.2 Exact 3-Phase Split-Fence Path

`CoordHub._dispatch_single_row()` splits into three explicit phases so the hub
never holds its synchronous in-process `fence` across transport IPC, while the
transport owns the bounded, worker-facing first-write fence:

#### Phase 1 — Hub Pre-Write Admission Fence (holds `fence`, microseconds, zero IPC)

1. Snapshot `start_rec_gen = self._recovery_generation`.
2. Check `not closed`, `not degraded`, envelope exists, `liveness == "live"`
   (edge active, generation not fenced or tombstoned, source/destination
   incarnations match, leases active).
3. Verify controller monitors are started and `StreamAbortableTransport` is
   present when required; verify zero `req_ids` in `_unavailable_requests`.
4. Atomically transition SQLite outbox `pending -> dispatch_started` via
   `mark_outbox_dispatch_started()`. (Guarantees at most one thread can enter
   Phase 2 for any `msg_id`.)
5. Register `inflight = _InflightAuth(...)` in `self._inflight_handoffs[msg_id]`
   under `_meta_lock`.
6. **Release `fence`.**

#### Phase 2 — Bounded Transport Handoff (outside `fence`)

1. Call `result = self._transport.dispatch_turn(turn)` without holding `fence`.
2. Adapter contract inside `dispatch_turn(turn)`:
   - Perform all pin checks, artifact support checks, and full HTTP wire-frame
     size validation (`<= 65_536` bytes) **before dialing `/control/control.sock`**;
     on refusal return `DispatchResult(ZERO_BYTES_SENT, detail=..., permanent=True)`.
   - Send one framed control request to the relay and wait (bounded by the
     handoff deadline, outside hub `fence`) **only** for the relay's 1-byte
     worker-write receipt (`b"H"`, `b"Z"`, or missing/`b"U"`). **Never** wait
     for HTTP response headers, JSON body, or SSE events inside `dispatch_turn()`.
   - Inside `relay.py:handoff()`: open `/grant/lock`, acquire cross-process
     `flock` (`take_fence`), recheck `/grant/state` + `/grant/lifetime`, perform
     one nonblocking `worker.send(request)`, release `/grant/lock`, and reply:
     - `b"Z"` -> `ZERO_BYTES_SENT(permanent=False)` (terminal grant, connect
       refused before write, `BlockingIOError`, or `0` bytes submitted).
     - `b"H"` -> `HANDED_OFF(stream_id=...)` (all bytes submitted to worker
       socket; open control/SSE stream bound to unique `stream_id` and consumed
       later in `stream_events(stream_id)`).
     - `b"U"` / EOF / timeout -> `UNCERTAIN` (partial remainder discarded,
       never replayed).

#### Phase 3 — Hub Post-Handoff Settlement (re-acquires `fence`, microseconds, zero IPC)

1. Always remove `env.msg_id` from `self._inflight_handoffs` and signal
   `self._inflight_cond` in a guaranteed cleanup block (even on exception).
2. Re-acquire `fence` and check whether `self._recovery_generation != start_rec_gen`,
   `inflight.revoked_observed`, `inflight.outage_observed`, or `_fenced_*` fired
   during Phase 2:
   - `ZERO_BYTES_SENT` with `permanent=True`: cancel outbox row
     (`dispatch_started -> cancelled`), audit `dispatch_rejected_pre_write`, emit
     host `turn_error` if live and same recovery generation; never return to
     `pending`.
   - `ZERO_BYTES_SENT` with `permanent=False`: recheck liveness under `fence`;
     if fenced or recovery rotated, cancel if still `dispatch_started`; else
     return to `pending`.
   - `UNCERTAIN` (or exception / missing `stream_id`): mark outbox `uncertain`
     if still `dispatch_started`; never replay.
   - `HANDED_OFF(stream_id)`:
     - Register `_StreamAuth` in `_stream_authorities[stream_id]` and check
       `_check_immediate_stream_abort_locked()`.
     - Persist `mark_outbox_handed_off(msg_id, stream_id=stream_id)` (on DB
       failure or recovery rotation, record `_REASON_HANDOFF_PERSIST_FAILED` in
       `_pending_cleanup_streams` and mark `uncertain` / degraded).
     - Release `fence`; immediately invoke `_apply_immediate_stream_abort()` if
       fenced/outage-observed during Phase 2, then launch `stream_events(stream_id)`
       only when persisted.

### 3.3 Linearizability Matrix Across All 6 Concurrent Races

| Concurrent Race During Phase 2 | Ordering & Fail-Closed Guarantee |
|---|---|
| 1. `hub.revoke(target)` while `dispatch_turn()` is paused pre-write (`pause_prompt`) | `revoke()` acquires `fence` immediately (zero stall), marks `_fenced_*` and `inflight.revoked_observed = True`, releases `fence`, and calls `abort_incarnation()` -> acquires `/grant/lock`, writes `/grant/state = terminal`, closes streams & broker. When paused dispatch resumes, relay acquires `/grant/lock`, sees terminal state, writes **0 bytes**, returns `b"Z"` -> Phase 3 transitions row to `cancelled`. |
| 2. `hub.revoke(target)` loses `/grant/lock` race by microseconds (`worker.send()` finished just before `abort_incarnation()`) | Write occurred strictly before `revoke()` completed. `abort_incarnation()` terminates the relay stream and broker hold; when `HANDED_OFF(stream_id)` reaches Phase 3, `_check_immediate_stream_abort_locked()` triggers immediate abort and drops all ordinary deltas. **Minimal-transport fix:** `_settle_stream_without_abort_stream()` now also settles `reason == "revoked"` via idempotent `abort_incarnation()` (rather than returning `False` forever and stranding `_pending_cleanup_streams`). |
| 3. Per-edge revocation ONLY (`edge_lease_revoked` or sender revoked on `A -> B` while `B` stays alive) | Admitted only on `StreamAbortableTransport`. Hub fences `(edge_id, grant_generation)` in memory, sets `inflight.revoked_observed = True`, releases `fence`, and calls `transport.revoke_grant(edge_id, grant_generation, reason=...)` under the transport's write fence. Failed `revoke_grant()` calls are retained in `_pending_cleanup_grants` and retried until settled (blocking `confirm_recovery()` and `close()`, and also settled if `abort_incarnation(dst)` succeeds). |
| 4. Controller outage (`_STATUS_UNAVAILABLE`) during Phase 2 | `_handle_request_unavailable()` sets `inflight.outage_observed = True` under `_meta_lock` without touching `fence`. Phase 3 immediately calls `abort_stream(stream_id, reason=_ERR_CTRL_UNAVAILABLE)` without permanently revoking the incarnation or grant. |
| 5. In-process `confirm_recovery()` while Phase 2 is executing | Phase 1 fences all edges/targets, marks all `_inflight_handoffs` with `revoked_observed = True`, enqueues their incarnations in `_pending_cleanup_incarnations`, releases `fences`, and immediately runs `_drain_pending_cleanups()` (calling `abort_incarnation()` so a paused relay unblocks instead of deadlocking). Before Phase 2 DB retirements and reopening, `confirm_recovery()` waits on `_inflight_cond` (bounded by `timeout_s`, default `2.0s`) until all pre-recovery `_inflight_handoffs` exit Phase 2 and settle Phase 3. If any wedged Phase-2 call refuses to exit before deadline, `confirm_recovery()` raises `CoordPolicyError(_ERR_CLEANUP_INCOMPLETE)` and remains degraded. |
| 6. `hub.close(timeout_s=...)` while Phase 2 is executing | `dispatch_once()` executes inside `_fg_ops` (or the pump thread), which `_drain_producers_and_streams(deadline)` waits for. If Phase 2 does not finish before `deadline`, `close()` raises `_ERR_CLOSE_INCOMPLETE` and retains `.coord_session_active` and `_state_lock_fd` (fail-closed). |

---

## 4. Transport-Parameterized Joint Restart Qualification Suite

New module: `docs/prds/spikes/m/test_restart_qualification.py`.

The suite exports a reusable, transport-parameterized harness and SQLite
evidence verifier (`RestartQualificationHarness` and
`verify_combined_pass_evidence()`) so the exact same hub/outbox/event/audit
assertions run first against `FakeWorkerTransport` and plug directly into the
real local OpenCode adapter during the combined attended synthetic pass.

### 4.1 Qualification Scenarios

1. **Coexisting Queued-Then-Revoked + Uncertain + Eligible Rows Across Clean Hub
   Restart (Same Live Worker Incarnation):**
   - Hub 1 registers `sb-qual` (`inc_live_1`, grant `G1`) and `sb-elig`
     (`inc_elig_1`, grant `G1`).
   - Enqueue `msg_uncertain` on `sb-qual` -> dispatch once with transport
     returning `UNCERTAIN` (`attempts=1`, `status='uncertain'`).
   - Enqueue `msg_revoked` on `sb-qual` (remains `pending` pre-handoff).
   - Enqueue `msg_eligible` on `sb-elig` (remains `pending`, unrevoked).
   - Revoke `sb-qual` while keeping the same live worker incarnation
     `inc_live_1` present in the transport (mirrors live containers checked for
     stale-bearer 403 before teardown).
   - Close Hub 1 cleanly and open Hub 2 against the same SQLite WAL DB and the
     same transport/incarnation.
   - Run `hub2.dispatch_once(async_stream=False)` and verify:
     - `msg_revoked`: **zero delivery** (never reaches `dispatch_turn`),
       `status='cancelled'`, `(edge_rev, 1)` tombstoned in `grant_tombstones`.
     - `msg_uncertain`: **zero replay** (`attempts == 1`, `status='uncertain'`).
     - `msg_eligible`: dispatched cleanly to `sb-elig` (`status='completed'`,
       `attempts == 1`, stream events persisted with host provenance).
     - Re-registering revoked `inc_live_1` raises `RevokedError`.
     - `verify_audit_chain()` is intact (`True`).
2. **Unclean Crash Restart (`.coord_session_active` Retained) with Coexisting
   `pending` + Orphaned `dispatch_started` + `uncertain` Rows:**
   - Simulate host crash leaving `.coord_session_active`, one `pending` row
     under old grant `G1`, one orphaned `dispatch_started` row, and one
     `uncertain` row.
   - Hub 2 boots degraded (`is_degraded == True`), refuses `send()`, and
     dispatches `0` rows.
   - Operator `confirm_recovery()` aborts the pre-crash incarnation, tombstones
     `G1`, transitions `pending -> cancelled`, transitions orphaned
     `dispatch_started -> uncertain` (zero replay), preserves existing
     `uncertain` (zero replay), audits `confirm_recovery`, and reopens cleanly.
   - Fresh incarnation `inc_live_2` + fresh grant `G2` dispatches and completes;
     old-grant rows remain undelivered and audit chain remains intact.
3. **Paused Pre-Write Phase-2 Race with Concurrent `hub.revoke()`:**
   - Pause `dispatch_turn()` before the worker-facing write (mirrors
     `local/probe.py:pause_prompt`).
   - Call `hub.revoke(target)` from a second thread while `dispatch_turn()` is
     paused; assert `hub.revoke()` completes in `< 0.5s` without waiting for the
     pause to release.
   - Release the pause; assert transport returns `ZERO_BYTES_SENT`, outbox row
     becomes `cancelled`, and **zero bytes** reach the worker.
4. **Late `HANDED_OFF` Race on Minimal `WorkerTransport` (Without `abort_stream`):**
   - Simulate `worker.send()` succeeding microseconds before `hub.revoke()`
     calls `abort_incarnation()`, then `dispatch_turn()` returning `HANDED_OFF`
     to Phase 3 on a minimal `WorkerTransport`.
   - Assert Phase 3 immediately settles via idempotent `abort_incarnation()`,
     zero ordinary deltas are recorded, outbox row becomes `aborted`, and
     `hub.close()` settles cleanly with zero stranded `_pending_cleanup_streams`.
5. **Per-Edge Revocation Race (`StreamAbortableTransport.revoke_grant`) With
   Live Destination Incarnation:**
   - Sandbox `sb-dst` has two edges: peer edge `E1` (`sb-src -> sb-dst`) and
     operator edge `E2` (`operator -> sb-dst`).
   - Pause `dispatch_turn()` on `E1` pre-write; revoke `sb-src` (or `E1` lease)
     while `sb-dst` stays alive.
   - Assert `revoke()` calls `revoke_grant(E1, 1)` without stalling, `E1`
     returns `ZERO_BYTES_SENT` and transitions to `cancelled` with zero worker
     delivery, and `E2` on the same live `sb-dst` incarnation completes normally.
   - Also cover failed `revoke_grant()` retry via `_pending_cleanup_grants`
     blocking `confirm_recovery()` / `close()` until settlement succeeds.
6. **Permanent Pre-Write Refusal (`ZERO_BYTES_SENT` + `permanent=True`):**
   - Transport refuses a valid hub-sized turn whose encoded worker HTTP frame
     exceeds `65_536` bytes (and a turn carrying unsupported `artifact_refs`)
     before any transport write, returning `ZERO_BYTES_SENT(permanent=True)`.
   - Assert row transitions `dispatch_started -> cancelled`, subsequent
     `dispatch_once()` dispatches `0` rows (zero hot-retry loop), audit log
     records `dispatch_rejected_pre_write`, and a concurrent `wait()` wakes
     promptly with the host-authored `turn_error` event.
7. **Combined-Pass SQLite Evidence Verifier (`verify_combined_pass_evidence`):**
   - Deterministic verifier taking a `CoordRegistry` (or `state_dir`) plus
     expected message IDs by outcome (`completed`, `cancelled`, `uncertain`,
     `aborted`) and tombstoned `(edge_id, grant_generation)` pairs; asserts
     exact outbox statuses/attempt counts, tombstones, non-elevated stream event
     provenance badges, and `verify_audit_chain() == True`.
8. **PR #50 Follow-Up Tightening (`test_r11_p2_1`):**
   - Extend `test_r11_p2_1_unsupported_pending_peer_turn_does_not_block_eligible_turn_and_new_send_rejected`
     in `test_gate2_regressions.py` to also cover the **equal-priority
     (`priority=0`)** case where the unsupported pending peer turn precedes an
     eligible `priority=0` turn in outbox `seq` order.

---

## 5. Verification Gates Before Implementation PR

1. Gate 1 walkthrough cleared by both security reviewer and Codex before writing
   implementation code.
2. Zero edits outside `docs/prds/spikes/m/` (and zero edits under `local/`).
3. `python3 -B -m unittest discover -s docs/prds/spikes/m -p 'test_*.py' -v`
   passes under both default `$HOME/.cache` and `/tmp` `TMPDIR` (with zero
   `__pycache__` left behind).
4. Static hygiene and SonarCloud AST checks (cognitive complexity `<= 15`
   including nested closures, no bare `BaseException`, no nested `with`, no
   duplicated string literals `>= 3x`, `git diff --check` clean).
5. Reciprocal adversarial review and 10/10 green hosted checks before any merge
   decision by the user.
