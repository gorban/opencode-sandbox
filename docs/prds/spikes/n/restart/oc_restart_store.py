"""Durable SQLite WAL workflow restart journal, read-only replay verifier, and supervisor."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import sqlite3
import sys
import threading
import time
from typing import Any, cast

_RESTART_DIR = Path(__file__).resolve().parent
_SPIKE_N_DIR = _RESTART_DIR.parent
_SPIKE_L_DIR = _SPIKE_N_DIR.parent / "l"
for _import_dir in (str(_RESTART_DIR), str(_SPIKE_N_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_restart_contract import (  # noqa: E402
    DEFAULT_MAX_OP_MS,
    ERR_AUTH_RETIRED_MID_STEP,
    ERR_AUTH_REVOKED_PRE_ENTRY,
    ERR_AUTH_STORE_REQUIRED,
    ERR_CANNOT_REQUEUE,
    ERR_CLOCK_PROVIDER_REQUIRED,
    ERR_IDEM_CONFLICT,
    ERR_MAX_ATTEMPTS_RECOVERY,
    ERR_MAX_EVENTS,
    ERR_MAX_RUNS,
    ERR_OP_DEADLINE,
    ERR_PROPOSED_STEPS_MISMATCH,
    ERR_RECON_CONFLICT,
    ERR_RECOVERY_REQUEUE,
    ERR_RECOVERY_UNCERTAIN,
    ERR_RUN_PAUSED_MID_STEP,
    ERR_RUN_PAUSED_PRE_ENTRY,
    ERR_SE_NO_AUTO_RETRY,
    ERR_STALE_EPOCH,
    EVENT_GENESIS_HASH,
    KEY_ATTEMPT_NO,
    KEY_DIRTY_RECOVERY,
    KEY_EVIDENCE_DIGEST,
    KEY_IDEM_KEY,
    KEY_LEASE_EPOCH,
    KEY_OUTPUT_DIGEST,
    KEY_PRIOR_EPOCH,
    KEY_REASON,
    KEY_RECON_KEY,
    KEY_REQUIRES_AUTHORITY,
    KEY_RESOLUTION,
    KEY_SIDE_EFFECTING,
    KEY_VIA_RECOVERY,
    MAX_REASON_BYTES,
    MAX_REPLAY_EVENTS,
    MAX_RUNS,
    OUTCOME_EFFECT_APPLIED,
    OUTCOME_NO_EFFECT,
    TERMINAL_RECONCILE_RESOLUTIONS,
    TERMINAL_RUN_STATUSES,
    WORKER_COMPLETED,
    WORKER_FAILED_RETRYABLE,
    WORKER_FAILED_TERMINAL,
    WORKER_FAILED_UNCERTAIN,
    CompleteStepRequest,
    CrashPoint,
    CreateRunRequest,
    EffectTrackerReceipt,
    EventType,
    FailStepRequest,
    HeartbeatAck,
    IdempotencyConflictError,
    IdempotencyOutcome,
    InvalidStepTransitionError,
    JournalIntegrityError,
    ReconcileResolution,
    ReconcileStepRequest,
    ReconciliationEvidenceError,
    ReconciliationReceipt,
    RecoveryReport,
    ReplayedSnapshot,
    ReplayMismatchError,
    RestartPolicyError,
    RestartStorageError,
    RestartValidationError,
    RunStatus,
    SimulatedSupervisorCrash,
    StaleEpochError,
    StepAckResult,
    StepExecutionOutcome,
    StepLeaseToken,
    StepSpec,
    StepStatus,
    SupervisorMetaRecord,
    SyntheticEffectTracker,
    WorkerStepResult,
    WorkflowRunRecord,
    WorkflowStepRecord,
    clock_to_wall_us,
    compute_event_hash,
    compute_run_status,
    derive_step_idempotency_key,
    derive_steps_from_plan,
    reduce_event_log,
    serialize_strict_json,
    validate_max_op_ms,
    validate_max_replay_events,
    validate_opaque_id,
    validate_reason,
    validate_step_id,
    verify_materialized_parity,
)
from oc_restart_db import (  # noqa: E402
    acquire_exclusive_supervisor_lock,
    admit_state_dir,
    assert_all_other_tables_empty,
    check_deadline_ms,
    check_deadline_s,
    count_obligations_strict,
    count_runs_strict,
    ensure_schema,
    execute_bounded,
    open_sqlite_bounded,
    read_idem_by_pk_strict,
    read_idempotency_strict,
    read_meta_strict,
    read_recon_by_pk_strict,
    read_reconciliations_strict,
    read_run_by_id_strict,
    read_run_steps_strict,
    read_runs_strict,
    read_step_by_pk_strict,
    read_steps_strict,
    release_lock_fd,
    safe_close,
    safe_rollback_and_close,
    scoped_op_deadline,
    stream_event_log_strict,
    verify_all_db_files,
    verify_no_unexpected_schema_objects,
)
from oc_workflow_plan import (  # noqa: E402
    AdmissionDeniedError,
    AdmissionReceipt,
    AuthorityError,
    ClockSnapshot,
    CompiledWorkflowPlan,
    RunAuthorityStore,
    compute_reachable_effects,
    recompute_plan_digests,
)

_ERR_TOKEN_TYPE = "token must be StepLeaseToken"
_ERR_JOURNAL_CLOSED = "journal_closed"
_ERR_RUN_NOT_RUNNING = "run_not_running"
_ERR_UNKNOWN_RUN = "unknown_run"
_ERR_MISSING_META = "supervisor_meta_missing"
_ERR_MISSING_IDEM = "missing_step_idempotency_key"
_ERR_EXPECTED_RECON_REQ = "expected ReconcileStepRequest"

_SQL_BEGIN_IMMEDIATE = "BEGIN IMMEDIATE"
_SQL_UPDATE_STEP_STATUS = (
    "UPDATE workflow_steps "
    "SET status = ?, output_digest = ?, failure_reason = ?, updated_at_us = ? "
    "WHERE run_id COLLATE BINARY = ? AND step_id COLLATE BINARY = ?"
)
_SQL_UPDATE_IDEM_OUTCOME = (
    "UPDATE step_idempotency_keys "
    "SET outcome_status = ?, output_digest = ?, failure_reason = ?, recorded_seq = ? "
    "WHERE run_id COLLATE BINARY = ? AND idempotency_key COLLATE BINARY = ?"
)
_SQL_UPDATE_RUN_STATUS = (
    "UPDATE workflow_runs SET status = ?, updated_at_us = ? WHERE run_id COLLATE BINARY = ?"
)
_SQL_UPDATE_META = (
    "UPDATE supervisor_meta "
    "SET current_epoch = ?, last_event_seq = ?, head_hash = ?, "
    "dirty_shutdown = ?, updated_at_us = ? "
    "WHERE id = 1"
)
_SQL_INSERT_EVENT = (
    "INSERT INTO workflow_event_log "
    "(seq, supervisor_epoch, event_type, run_id, step_id, payload_json, "
    "created_at_us, prev_hash, entry_hash) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


# --- Headroom & event-append helpers ---


def _assert_ordinary_capacity(
    last_seq: int,
    *,
    events_to_append: int,
    leased_after: int,
    uncertain_after: int,
    max_replay_events: int,
) -> None:
    obligations = leased_after + uncertain_after
    reserved = 1 if obligations == 0 else (3 + 2 * leased_after + uncertain_after)
    if last_seq + events_to_append + reserved > max_replay_events:
        raise RestartPolicyError(ERR_MAX_EVENTS)


def _assert_terminal_reconcile_capacity(
    last_seq: int,
    *,
    leased_after: int,
    uncertain_after: int,
    max_replay_events: int,
) -> None:
    obligations = leased_after + uncertain_after
    reserved = 1 if obligations == 0 else (obligations + 1)
    if last_seq + 1 + reserved > max_replay_events:
        raise RestartPolicyError(ERR_MAX_EVENTS)


def _assert_recovery_capacity(
    last_seq: int,
    *,
    prior_leased: int,
    resulting_uncertain: int,
    max_replay_events: int,
) -> None:
    if last_seq + 1 + prior_leased + resulting_uncertain + 1 > max_replay_events:
        raise RestartPolicyError(ERR_MAX_EVENTS)


def _assert_close_capacity(
    last_seq: int,
    *,
    leased_now: int,
    uncertain_now: int,
    max_replay_events: int,
) -> None:
    obligations = leased_now + uncertain_now
    needed = 1 if obligations == 0 else (3 + 2 * leased_now + uncertain_now)
    if last_seq + needed > max_replay_events:
        raise RestartPolicyError(ERR_MAX_EVENTS)


def _verify_and_replay_in_tx(
    conn: sqlite3.Connection,
    meta: SupervisorMetaRecord,
    *,
    max_replay_events: int,
    deadline: float,
) -> ReplayedSnapshot:
    events = stream_event_log_strict(
        conn, max_events=max_replay_events, deadline=deadline
    )
    if len(events) != meta.last_event_seq:
        raise ReplayMismatchError("event_count_meta_mismatch")
    replayed = reduce_event_log(events, deadline=deadline)
    actual_runs = read_runs_strict(conn, max_rows=len(replayed.runs), deadline=deadline)
    actual_steps = read_steps_strict(
        conn, max_rows=len(replayed.steps), deadline=deadline
    )
    actual_idems = read_idempotency_strict(
        conn, max_rows=len(replayed.idempotency_records), deadline=deadline
    )
    actual_recons = read_reconciliations_strict(
        conn, max_rows=len(replayed.reconciliation_records), deadline=deadline
    )
    verify_materialized_parity(
        meta=meta,
        replayed=replayed,
        actual_runs=actual_runs,
        actual_steps=actual_steps,
        actual_idems=actual_idems,
        actual_recons=actual_recons,
        deadline=deadline,
    )
    check_deadline_ms(deadline)
    return replayed


def _append_event_raw(
    conn: sqlite3.Connection,
    *,
    seq: int,
    prev_hash: str,
    epoch: int,
    event_type: EventType,
    run_id: str | None,
    step_id: str | None,
    payload: dict[str, Any],
    created_at_us: int,
    deadline: float,
) -> str:
    payload_str = serialize_strict_json(payload)
    entry_hash = compute_event_hash(
        seq=seq,
        supervisor_epoch=epoch,
        event_type=event_type.value,
        run_id=run_id,
        step_id=step_id,
        payload=payload,
        created_at_us=created_at_us,
        prev_hash=prev_hash,
    )
    execute_bounded(
        conn,
        _SQL_INSERT_EVENT,
        (
            seq,
            epoch,
            event_type.value,
            run_id,
            step_id,
            payload_str,
            created_at_us,
            prev_hash,
            entry_hash,
        ),
        deadline,
    )
    return entry_hash


def _recompute_and_update_run_status(
    conn: sqlite3.Connection,
    run_id: str,
    *,
    cancel_requested: bool,
    updated_at_us: int,
    deadline: float,
) -> RunStatus:
    steps = read_run_steps_strict(conn, run_id, deadline)
    new_status = compute_run_status(steps, cancel_requested=cancel_requested)
    execute_bounded(
        conn,
        _SQL_UPDATE_RUN_STATUS,
        (new_status.value, updated_at_us, run_id),
        deadline,
    )
    return new_status


def _bound_reason(text: str) -> str:
    raw = text.encode("utf-8")
    if len(raw) <= MAX_REASON_BYTES:
        return text
    trimmed = raw[:MAX_REASON_BYTES]
    while trimmed:
        try:
            return trimmed.decode("utf-8")
        except UnicodeDecodeError:
            trimmed = trimmed[:-1]
    return "reason_truncated"


# --- Lock-free read-only replay verification ---


def verify_journal_replay_readonly(
    state_dir: Path,
    *,
    sandbox_root: Path | None = None,
    max_op_ms: int = DEFAULT_MAX_OP_MS,
    max_replay_events: int = MAX_REPLAY_EVENTS,
) -> ReplayedSnapshot:
    """Verify full event hash chain & materialized-table parity read-only without acquiring lock."""
    op_ms = validate_max_op_ms(max_op_ms)
    cap = validate_max_replay_events(max_replay_events)
    deadline = time.monotonic() + (op_ms / 1000.0)
    _, db_path = admit_state_dir(
        state_dir, sandbox_root=sandbox_root, create_if_missing=False, deadline=deadline
    )
    conn = open_sqlite_bounded(db_path, readonly=True, deadline=deadline)
    try:
        with scoped_op_deadline(conn, deadline):
            verify_no_unexpected_schema_objects(
                conn, require_core_tables=True, deadline=deadline
            )
            meta = read_meta_strict(conn, allow_missing=False, deadline=deadline)
            if meta is None:
                raise JournalIntegrityError(_ERR_MISSING_META)
            return _verify_and_replay_in_tx(
                conn, meta, max_replay_events=cap, deadline=deadline
            )
    finally:
        safe_rollback_and_close(conn)


# --- Recovery step fencing helpers ---


def _fence_one_prior_leased_step(
    conn: sqlite3.Connection,
    step: WorkflowStepRecord,
    *,
    new_epoch: int,
    seq: int,
    prev_hash: str,
    created_at_us: int,
    deadline: float,
) -> tuple[str, str]:
    """Fence one prior-epoch leased step and return (new_head_hash, bucket)."""
    if step.idempotency_key is None:
        raise JournalIntegrityError(_ERR_MISSING_IDEM)
    if step.side_effecting:
        ev_type = EventType.STEP_MARKED_UNCERTAIN
        new_st = StepStatus.UNCERTAIN_NEEDS_RECONCILE
        new_idem = IdempotencyOutcome.UNCERTAIN_NEEDS_RECONCILE
        reason = ERR_RECOVERY_UNCERTAIN
        bucket = "uncertain"
    elif step.attempt_no < step.max_attempts:
        ev_type = EventType.STEP_REQUEUED_PENDING
        new_st = StepStatus.PENDING
        new_idem = IdempotencyOutcome.REQUEUED_PENDING
        reason = ERR_RECOVERY_REQUEUE
        bucket = "requeued"
    else:
        ev_type = EventType.STEP_FAILED_TERMINAL
        new_st = StepStatus.FAILED_TERMINAL
        new_idem = IdempotencyOutcome.FAILED_TERMINAL
        reason = ERR_MAX_ATTEMPTS_RECOVERY
        bucket = "failed"

    execute_bounded(
        conn,
        _SQL_UPDATE_STEP_STATUS,
        (new_st.value, None, reason, created_at_us, step.run_id, step.step_id),
        deadline,
    )
    execute_bounded(
        conn,
        _SQL_UPDATE_IDEM_OUTCOME,
        (new_idem.value, None, reason, seq, step.run_id, step.idempotency_key),
        deadline,
    )
    head = _append_event_raw(
        conn,
        seq=seq,
        prev_hash=prev_hash,
        epoch=new_epoch,
        event_type=ev_type,
        run_id=step.run_id,
        step_id=step.step_id,
        payload={
            KEY_ATTEMPT_NO: step.attempt_no,
            KEY_REASON: reason,
            KEY_VIA_RECOVERY: True,
        },
        created_at_us=created_at_us,
        deadline=deadline,
    )
    run = read_run_by_id_strict(conn, step.run_id, deadline)
    if run is None:
        raise JournalIntegrityError(_ERR_UNKNOWN_RUN)
    _recompute_and_update_run_status(
        conn,
        step.run_id,
        cancel_requested=run.cancel_requested,
        updated_at_us=created_at_us,
        deadline=deadline,
    )
    return head, bucket


# --- Durable SQLite WAL WorkflowRestartJournal ---


class WorkflowRestartJournal:
    """Single-owner hardened SQLite WAL durable journal with epoch fencing and hash chain."""

    def __init__(
        self,
        *,
        state_dir: Path,
        db_path: Path,
        lock_fd: int,
        conn: sqlite3.Connection,
        current_epoch: int,
        max_replay_events: int,
    ) -> None:
        self._state_dir = state_dir
        self._db_path = db_path
        self._lock_fd: int | None = lock_fd
        self._conn: sqlite3.Connection | None = conn
        self._current_epoch = current_epoch
        self._max_replay_events = max_replay_events
        self._conn_lock = threading.Lock()
        self._closed = False

    @property
    def current_epoch(self) -> int:
        return self._current_epoch

    @property
    def db_path(self) -> Path:
        return self._db_path

    @property
    def journal_id(self) -> str:
        return str(self._db_path.resolve())

    @property
    def state_dir(self) -> Path:
        return self._state_dir

    @classmethod
    def open_and_recover(
        cls,
        state_dir: Path,
        *,
        clock: ClockSnapshot,
        sandbox_root: Path | None = None,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
        max_replay_events: int = MAX_REPLAY_EVENTS,
        crash_point: CrashPoint = CrashPoint.NONE,
    ) -> tuple[WorkflowRestartJournal, RecoveryReport]:
        op_ms = validate_max_op_ms(max_op_ms)
        cap = validate_max_replay_events(max_replay_events)
        created_at_us = clock_to_wall_us(clock)
        deadline = time.monotonic() + (op_ms / 1000.0)
        trusted_dir, db_path = admit_state_dir(
            state_dir, sandbox_root=sandbox_root, create_if_missing=True, deadline=deadline
        )
        lock_fd = acquire_exclusive_supervisor_lock(trusted_dir, deadline=deadline)
        conn: sqlite3.Connection | None = None
        try:
            verify_all_db_files(db_path, required_main=False)
            conn = open_sqlite_bounded(db_path, readonly=False, deadline=deadline)
            with scoped_op_deadline(conn, deadline):
                report = cls._recover_inside_tx(
                    conn,
                    created_at_us=created_at_us,
                    max_replay_events=cap,
                    crash_point=crash_point,
                    deadline=deadline,
                )
            if crash_point is CrashPoint.AFTER_RECOVERY_COMMIT_BEFORE_DISPATCH:
                raise SimulatedSupervisorCrash("AFTER_RECOVERY_COMMIT_BEFORE_DISPATCH")
            journal = cls(
                state_dir=trusted_dir,
                db_path=db_path,
                lock_fd=lock_fd,
                conn=conn,
                current_epoch=report.supervisor_epoch,
                max_replay_events=cap,
            )
            return journal, report
        except BaseException:
            safe_rollback_and_close(conn)
            release_lock_fd(lock_fd)
            raise

    @staticmethod
    def _recover_inside_tx(
        conn: sqlite3.Connection,
        *,
        created_at_us: int,
        max_replay_events: int,
        crash_point: CrashPoint,
        deadline: float,
    ) -> RecoveryReport:
        execute_bounded(conn, _SQL_BEGIN_IMMEDIATE, (), deadline)
        verify_no_unexpected_schema_objects(
            conn, require_core_tables=False, deadline=deadline
        )
        ensure_schema(conn, deadline)
        meta = read_meta_strict(conn, allow_missing=True, deadline=deadline)
        if meta is None:
            assert_all_other_tables_empty(conn, deadline)
            new_epoch = 1
            prior_epoch = 0
            dirty_recovery = False
            seq = 0
            head_hash = EVENT_GENESIS_HASH
            leased_prior: list[WorkflowStepRecord] = []
            existing_uncertain = 0
            execute_bounded(
                conn,
                "INSERT INTO supervisor_meta "
                "(id, current_epoch, last_event_seq, head_hash, dirty_shutdown, updated_at_us) "
                "VALUES (1, 1, 0, ?, 1, ?)",
                (EVENT_GENESIS_HASH, created_at_us),
                deadline,
            )
        else:
            prior = _verify_and_replay_in_tx(
                conn, meta, max_replay_events=max_replay_events, deadline=deadline
            )
            new_epoch = meta.current_epoch + 1
            prior_epoch = meta.current_epoch
            dirty_recovery = meta.dirty_shutdown == 1
            seq = meta.last_event_seq
            head_hash = meta.head_hash
            leased_prior = sorted(
                (
                    s
                    for s in prior.steps.values()
                    if s.status is StepStatus.LEASED and s.lease_epoch < new_epoch
                ),
                key=lambda s: (s.run_id, s.step_order, s.step_id),
            )
            existing_uncertain = sum(
                1
                for s in prior.steps.values()
                if s.status is StepStatus.UNCERTAIN_NEEDS_RECONCILE
            )

        se_prior_count = sum(1 for s in leased_prior if s.side_effecting)
        _assert_recovery_capacity(
            seq,
            prior_leased=len(leased_prior),
            resulting_uncertain=existing_uncertain + se_prior_count,
            max_replay_events=max_replay_events,
        )

        seq += 1
        head_hash = _append_event_raw(
            conn,
            seq=seq,
            prev_hash=head_hash,
            epoch=new_epoch,
            event_type=EventType.SUPERVISOR_STARTED,
            run_id=None,
            step_id=None,
            payload={KEY_DIRTY_RECOVERY: dirty_recovery, KEY_PRIOR_EPOCH: prior_epoch},
            created_at_us=created_at_us,
            deadline=deadline,
        )
        buckets: dict[str, list[tuple[str, str, int]]] = {
            "requeued": [],
            "uncertain": [],
            "failed": [],
        }
        for step in leased_prior:
            seq += 1
            head_hash, bucket = _fence_one_prior_leased_step(
                conn,
                step,
                new_epoch=new_epoch,
                seq=seq,
                prev_hash=head_hash,
                created_at_us=created_at_us,
                deadline=deadline,
            )
            buckets[bucket].append((step.run_id, step.step_id, step.attempt_no))

        execute_bounded(
            conn,
            _SQL_UPDATE_META,
            (new_epoch, seq, head_hash, 1, created_at_us),
            deadline,
        )
        if crash_point is CrashPoint.DURING_RECOVERY_BEFORE_COMMIT:
            execute_bounded(conn, "ROLLBACK", (), deadline)
            raise SimulatedSupervisorCrash("DURING_RECOVERY_BEFORE_COMMIT")
        execute_bounded(conn, "COMMIT", (), deadline)
        return RecoveryReport(
            supervisor_epoch=new_epoch,
            prior_epoch=prior_epoch,
            dirty_recovery=dirty_recovery,
            last_event_seq=seq,
            head_hash=head_hash,
            fenced_requeued=tuple(buckets["requeued"]),
            fenced_uncertain=tuple(buckets["uncertain"]),
            fenced_failed=tuple(buckets["failed"]),
        )

    @contextmanager
    def _locked_conn(self, max_op_ms: int) -> Iterator[tuple[sqlite3.Connection, float]]:
        op_ms = validate_max_op_ms(max_op_ms)
        deadline = time.monotonic() + (op_ms / 1000.0)
        remaining_s = check_deadline_s(deadline)
        if not self._conn_lock.acquire(timeout=remaining_s):
            raise RestartStorageError(ERR_OP_DEADLINE)
        try:
            check_deadline_ms(deadline)
            if self._closed or self._conn is None:
                raise RestartStorageError(_ERR_JOURNAL_CLOSED)
            with scoped_op_deadline(self._conn, deadline):
                yield self._conn, deadline
        finally:
            self._conn_lock.release()

    @contextmanager
    def _write_tx(self, max_op_ms: int) -> Iterator[tuple[sqlite3.Connection, float]]:
        with self._locked_conn(max_op_ms) as (conn, deadline):
            execute_bounded(conn, _SQL_BEGIN_IMMEDIATE, (), deadline)
            try:
                yield conn, deadline
                execute_bounded(conn, "COMMIT", (), deadline)
            except BaseException:
                if conn.in_transaction:
                    try:
                        conn.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise

    def _require_meta_active(
        self, conn: sqlite3.Connection, deadline: float
    ) -> SupervisorMetaRecord:
        meta = read_meta_strict(conn, allow_missing=False, deadline=deadline)
        if meta is None:
            raise JournalIntegrityError(_ERR_MISSING_META)
        if meta.current_epoch != self._current_epoch:
            raise StaleEpochError(ERR_STALE_EPOCH)
        return meta

    def _finish_event_and_meta(
        self,
        conn: sqlite3.Connection,
        meta: SupervisorMetaRecord,
        *,
        event_type: EventType,
        run_id: str | None,
        step_id: str | None,
        payload: dict[str, Any],
        created_at_us: int,
        dirty_shutdown: int,
        deadline: float,
    ) -> tuple[int, str]:
        seq = meta.last_event_seq + 1
        head = _append_event_raw(
            conn,
            seq=seq,
            prev_hash=meta.head_hash,
            epoch=self._current_epoch,
            event_type=event_type,
            run_id=run_id,
            step_id=step_id,
            payload=payload,
            created_at_us=created_at_us,
            deadline=deadline,
        )
        execute_bounded(
            conn,
            _SQL_UPDATE_META,
            (self._current_epoch, seq, head, dirty_shutdown, created_at_us),
            deadline,
        )
        return seq, head

    # --- Public read & operational methods ---

    def get_meta(self, *, max_op_ms: int = DEFAULT_MAX_OP_MS) -> SupervisorMetaRecord:
        with self._locked_conn(max_op_ms) as (conn, deadline):
            meta = read_meta_strict(conn, allow_missing=False, deadline=deadline)
            if meta is None:
                raise JournalIntegrityError(_ERR_MISSING_META)
            return meta

    def get_run(
        self, run_id: str, *, max_op_ms: int = DEFAULT_MAX_OP_MS
    ) -> WorkflowRunRecord:
        clean_run = validate_opaque_id(run_id, "run_id")
        with self._locked_conn(max_op_ms) as (conn, deadline):
            run = read_run_by_id_strict(conn, clean_run, deadline)
            if run is None:
                raise InvalidStepTransitionError(f"unknown_run:{clean_run}")
            return run

    def get_step(
        self, run_id: str, step_id: str, *, max_op_ms: int = DEFAULT_MAX_OP_MS
    ) -> WorkflowStepRecord:
        clean_run = validate_opaque_id(run_id, "run_id")
        clean_step = validate_step_id(step_id, "step_id")
        with self._locked_conn(max_op_ms) as (conn, deadline):
            step = read_step_by_pk_strict(conn, clean_run, clean_step, deadline)
            if step is None:
                raise InvalidStepTransitionError(f"unknown_step:{clean_step}")
            return step

    def list_eligible_steps(
        self, run_id: str, *, max_op_ms: int = DEFAULT_MAX_OP_MS
    ) -> tuple[WorkflowStepRecord, ...]:
        clean_run = validate_opaque_id(run_id, "run_id")
        with self._locked_conn(max_op_ms) as (conn, deadline):
            run = read_run_by_id_strict(conn, clean_run, deadline)
            if run is None or run.status is not RunStatus.RUNNING or run.cancel_requested:
                return ()
            steps = read_run_steps_strict(conn, clean_run, deadline)
            eligible: list[WorkflowStepRecord] = []
            for step in sorted(steps.values(), key=lambda s: (s.step_order, s.step_id)):
                if step.status is not StepStatus.PENDING or step.attempt_no >= step.max_attempts:
                    continue
                if all(steps[dep].status is StepStatus.COMPLETED for dep in step.depends_on):
                    eligible.append(step)
            return tuple(eligible)

    def create_run(
        self,
        request: CreateRunRequest,
        *,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
    ) -> WorkflowRunRecord:
        if not isinstance(request, CreateRunRequest):
            raise RestartValidationError("expected CreateRunRequest")
        created_at_us = clock_to_wall_us(request.clock)
        with self._write_tx(max_op_ms) as (conn, deadline):
            meta = self._require_meta_active(conn, deadline)
            if count_runs_strict(conn, deadline) >= MAX_RUNS:
                raise RestartPolicyError(ERR_MAX_RUNS)
            if read_run_by_id_strict(conn, request.run_id, deadline) is not None:
                raise InvalidStepTransitionError("duplicate_run_id")
            leased_cnt, unc_cnt = count_obligations_strict(conn, deadline)
            _assert_ordinary_capacity(
                meta.last_event_seq,
                events_to_append=1,
                leased_after=leased_cnt,
                uncertain_after=unc_cnt,
                max_replay_events=self._max_replay_events,
            )
            execute_bounded(
                conn,
                "INSERT INTO workflow_runs "
                "(run_id, workflow_id, spec_digest, workflow_plan_digest, grant_generation, "
                "requires_authority, status, cancel_requested, created_epoch, created_at_us, updated_at_us) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)",
                (
                    request.run_id,
                    request.workflow_id,
                    request.spec_digest,
                    request.workflow_plan_digest,
                    request.grant_generation,
                    1 if request.requires_authority else 0,
                    RunStatus.RUNNING.value,
                    self._current_epoch,
                    created_at_us,
                    created_at_us,
                ),
                deadline,
            )
            for order, spec in enumerate(request.steps):
                execute_bounded(
                    conn,
                    "INSERT INTO workflow_steps "
                    "(run_id, step_id, step_order, state_name, effect_kind, side_effecting, "
                    "depends_on_json, max_attempts, status, attempt_no, lease_epoch, "
                    "idempotency_key, output_digest, failure_reason, updated_at_us) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, NULL, NULL, ?)",
                    (
                        request.run_id,
                        spec.step_id,
                        order,
                        spec.state_name,
                        spec.effect_kind,
                        1 if spec.side_effecting else 0,
                        serialize_strict_json(list(spec.depends_on)),
                        spec.max_attempts,
                        StepStatus.PENDING.value,
                        created_at_us,
                    ),
                    deadline,
                )
            self._finish_event_and_meta(
                conn,
                meta,
                event_type=EventType.RUN_CREATED,
                run_id=request.run_id,
                step_id=None,
                payload={
                    "grant_generation": request.grant_generation,
                    KEY_REQUIRES_AUTHORITY: request.requires_authority,
                    "spec_digest": request.spec_digest,
                    "steps": [s.to_payload_dict() for s in request.steps],
                    "workflow_id": request.workflow_id,
                    "workflow_plan_digest": request.workflow_plan_digest,
                },
                created_at_us=created_at_us,
                dirty_shutdown=1,
                deadline=deadline,
            )
            run = read_run_by_id_strict(conn, request.run_id, deadline)
            if run is None:
                raise JournalIntegrityError(_ERR_UNKNOWN_RUN)
            return run

    def lease_step(
        self,
        *,
        run_id: str,
        step_id: str,
        clock: ClockSnapshot,
        idempotency_key: str | None = None,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
    ) -> StepLeaseToken:
        clean_run = validate_opaque_id(run_id, "run_id")
        clean_step = validate_step_id(step_id, "step_id")
        now_us = clock_to_wall_us(clock)
        with self._write_tx(max_op_ms) as (conn, deadline):
            meta = self._require_meta_active(conn, deadline)
            run = read_run_by_id_strict(conn, clean_run, deadline)
            if run is None or run.status is not RunStatus.RUNNING or run.cancel_requested:
                raise InvalidStepTransitionError(_ERR_RUN_NOT_RUNNING)
            steps = read_run_steps_strict(conn, clean_run, deadline)
            step = steps.get(clean_step)
            if step is None or step.status is not StepStatus.PENDING:
                raise InvalidStepTransitionError("step_not_pending")
            if step.attempt_no >= step.max_attempts:
                raise InvalidStepTransitionError("step_max_attempts_reached")
            if any(steps[dep].status is not StepStatus.COMPLETED for dep in step.depends_on):
                raise InvalidStepTransitionError("step_dependency_not_completed")

            next_attempt = step.attempt_no + 1
            chosen_key = (
                validate_opaque_id(idempotency_key, KEY_IDEM_KEY)
                if idempotency_key is not None
                else derive_step_idempotency_key(
                    clean_run, clean_step, next_attempt, self._current_epoch
                )
            )
            if read_idem_by_pk_strict(conn, clean_run, chosen_key, deadline) is not None:
                raise IdempotencyConflictError(ERR_IDEM_CONFLICT)

            leased_cnt, unc_cnt = count_obligations_strict(conn, deadline)
            _assert_ordinary_capacity(
                meta.last_event_seq,
                events_to_append=1,
                leased_after=leased_cnt + 1,
                uncertain_after=unc_cnt,
                max_replay_events=self._max_replay_events,
            )
            seq = meta.last_event_seq + 1
            execute_bounded(
                conn,
                "UPDATE workflow_steps "
                "SET status = ?, attempt_no = ?, lease_epoch = ?, idempotency_key = ?, "
                "output_digest = NULL, failure_reason = NULL, updated_at_us = ? "
                "WHERE run_id COLLATE BINARY = ? AND step_id COLLATE BINARY = ?",
                (
                    StepStatus.LEASED.value,
                    next_attempt,
                    self._current_epoch,
                    chosen_key,
                    now_us,
                    clean_run,
                    clean_step,
                ),
                deadline,
            )
            execute_bounded(
                conn,
                "INSERT INTO step_idempotency_keys "
                "(run_id, idempotency_key, step_id, attempt_no, lease_epoch, "
                "outcome_status, output_digest, failure_reason, recorded_seq) "
                "VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
                (
                    clean_run,
                    chosen_key,
                    clean_step,
                    next_attempt,
                    self._current_epoch,
                    IdempotencyOutcome.LEASED.value,
                    seq,
                ),
                deadline,
            )
            _recompute_and_update_run_status(
                conn,
                clean_run,
                cancel_requested=run.cancel_requested,
                updated_at_us=now_us,
                deadline=deadline,
            )
            self._finish_event_and_meta(
                conn,
                meta,
                event_type=EventType.STEP_LEASED,
                run_id=clean_run,
                step_id=clean_step,
                payload={
                    KEY_ATTEMPT_NO: next_attempt,
                    KEY_IDEM_KEY: chosen_key,
                    KEY_LEASE_EPOCH: self._current_epoch,
                    KEY_SIDE_EFFECTING: step.side_effecting,
                },
                created_at_us=now_us,
                dirty_shutdown=1,
                deadline=deadline,
            )
            return StepLeaseToken(
                run_id=clean_run,
                step_id=clean_step,
                attempt_no=next_attempt,
                lease_epoch=self._current_epoch,
                idempotency_key=chosen_key,
            )

    def _verify_active_lease_in_conn(
        self,
        conn: sqlite3.Connection,
        token: StepLeaseToken,
        deadline: float,
        *,
        allow_paused_for_settlement: bool = False,
    ) -> tuple[WorkflowRunRecord, WorkflowStepRecord]:
        if token.lease_epoch != self._current_epoch:
            raise StaleEpochError(ERR_STALE_EPOCH)
        run = read_run_by_id_strict(conn, token.run_id, deadline)
        if run is None:
            raise InvalidStepTransitionError(_ERR_UNKNOWN_RUN)
        allowed_statuses = (
            (RunStatus.RUNNING, RunStatus.PAUSED_NEEDS_RECONCILE)
            if allow_paused_for_settlement
            else (RunStatus.RUNNING,)
        )
        if run.status not in allowed_statuses or run.cancel_requested:
            raise InvalidStepTransitionError(_ERR_RUN_NOT_RUNNING)
        step = read_step_by_pk_strict(conn, token.run_id, token.step_id, deadline)
        if step is None:
            raise InvalidStepTransitionError("unknown_step")
        if step.status is not StepStatus.LEASED:
            raise InvalidStepTransitionError(f"step_not_leased:{step.status.value}")
        if (
            step.attempt_no != token.attempt_no
            or step.lease_epoch != token.lease_epoch
            or step.idempotency_key != token.idempotency_key
        ):
            raise StaleEpochError(ERR_STALE_EPOCH)
        return run, step

    def verify_lease_for_entry(
        self, token: StepLeaseToken, *, max_op_ms: int = DEFAULT_MAX_OP_MS
    ) -> tuple[HeartbeatAck, WorkflowRunRecord, WorkflowStepRecord]:
        if not isinstance(token, StepLeaseToken):
            raise RestartValidationError(_ERR_TOKEN_TYPE)
        if token.lease_epoch != self._current_epoch:
            raise StaleEpochError(ERR_STALE_EPOCH)
        with self._locked_conn(max_op_ms) as (conn, deadline):
            self._require_meta_active(conn, deadline)
            run, step = self._verify_active_lease_in_conn(
                conn, token, deadline, allow_paused_for_settlement=True
            )
            ack = HeartbeatAck(
                run_id=token.run_id,
                step_id=token.step_id,
                attempt_no=token.attempt_no,
                lease_epoch=token.lease_epoch,
                supervisor_epoch=self._current_epoch,
            )
            return ack, run, step

    def verify_active_lease_with_run(
        self, token: StepLeaseToken, *, max_op_ms: int = DEFAULT_MAX_OP_MS
    ) -> tuple[HeartbeatAck, WorkflowRunRecord]:
        if not isinstance(token, StepLeaseToken):
            raise RestartValidationError(_ERR_TOKEN_TYPE)
        if token.lease_epoch != self._current_epoch:
            raise StaleEpochError(ERR_STALE_EPOCH)
        with self._locked_conn(max_op_ms) as (conn, deadline):
            self._require_meta_active(conn, deadline)
            run, _ = self._verify_active_lease_in_conn(conn, token, deadline)
            ack = HeartbeatAck(
                run_id=token.run_id,
                step_id=token.step_id,
                attempt_no=token.attempt_no,
                lease_epoch=token.lease_epoch,
                supervisor_epoch=self._current_epoch,
            )
            return ack, run

    def verify_active_lease(
        self, token: StepLeaseToken, *, max_op_ms: int = DEFAULT_MAX_OP_MS
    ) -> HeartbeatAck:
        ack, _ = self.verify_active_lease_with_run(token, max_op_ms=max_op_ms)
        return ack

    def heartbeat_step(
        self,
        token: StepLeaseToken,
        *,
        clock: ClockSnapshot,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
    ) -> HeartbeatAck:
        """Fenced read-only liveness check (zero event-log writes)."""
        clock_to_wall_us(clock)
        return self.verify_active_lease(token, max_op_ms=max_op_ms)

    def complete_step(
        self,
        request: CompleteStepRequest,
        *,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
    ) -> StepAckResult:
        if not isinstance(request, CompleteStepRequest):
            raise RestartValidationError("expected CompleteStepRequest")
        token = request.token
        if token.lease_epoch != self._current_epoch:
            raise StaleEpochError(ERR_STALE_EPOCH)
        now_us = clock_to_wall_us(request.clock)
        with self._write_tx(max_op_ms) as (conn, deadline):
            meta = self._require_meta_active(conn, deadline)
            idem = read_idem_by_pk_strict(
                conn, token.run_id, token.idempotency_key, deadline
            )
            if idem is None:
                raise StaleEpochError(ERR_STALE_EPOCH)
            if idem.outcome_status is IdempotencyOutcome.COMPLETED:
                exact = (
                    idem.step_id == token.step_id
                    and idem.attempt_no == token.attempt_no
                    and idem.lease_epoch == token.lease_epoch
                    and idem.output_digest == request.output_digest
                )
                if exact:
                    return StepAckResult(
                        run_id=token.run_id,
                        step_id=token.step_id,
                        status="deduplicated_already_completed",
                        attempt_no=token.attempt_no,
                        lease_epoch=token.lease_epoch,
                        duplicate=True,
                        seq=idem.recorded_seq,
                    )
                raise IdempotencyConflictError(ERR_IDEM_CONFLICT)
            if idem.outcome_status is not IdempotencyOutcome.LEASED:
                raise IdempotencyConflictError(ERR_IDEM_CONFLICT)

            run, _ = self._verify_active_lease_in_conn(
                conn, token, deadline, allow_paused_for_settlement=True
            )
            leased_cnt, unc_cnt = count_obligations_strict(conn, deadline)
            _assert_ordinary_capacity(
                meta.last_event_seq,
                events_to_append=1,
                leased_after=max(0, leased_cnt - 1),
                uncertain_after=unc_cnt,
                max_replay_events=self._max_replay_events,
            )
            seq = meta.last_event_seq + 1
            execute_bounded(
                conn,
                _SQL_UPDATE_STEP_STATUS,
                (
                    StepStatus.COMPLETED.value,
                    request.output_digest,
                    None,
                    now_us,
                    token.run_id,
                    token.step_id,
                ),
                deadline,
            )
            execute_bounded(
                conn,
                _SQL_UPDATE_IDEM_OUTCOME,
                (
                    IdempotencyOutcome.COMPLETED.value,
                    request.output_digest,
                    None,
                    seq,
                    token.run_id,
                    token.idempotency_key,
                ),
                deadline,
            )
            _recompute_and_update_run_status(
                conn,
                token.run_id,
                cancel_requested=run.cancel_requested,
                updated_at_us=now_us,
                deadline=deadline,
            )
            self._finish_event_and_meta(
                conn,
                meta,
                event_type=EventType.STEP_COMPLETED,
                run_id=token.run_id,
                step_id=token.step_id,
                payload={
                    KEY_ATTEMPT_NO: token.attempt_no,
                    KEY_IDEM_KEY: token.idempotency_key,
                    KEY_LEASE_EPOCH: token.lease_epoch,
                    KEY_OUTPUT_DIGEST: request.output_digest,
                },
                created_at_us=now_us,
                dirty_shutdown=1,
                deadline=deadline,
            )
            return StepAckResult(
                run_id=token.run_id,
                step_id=token.step_id,
                status=StepStatus.COMPLETED.value,
                attempt_no=token.attempt_no,
                lease_epoch=token.lease_epoch,
                duplicate=False,
                seq=seq,
            )

    def _apply_fail_transition(
        self,
        conn: sqlite3.Connection,
        meta: SupervisorMetaRecord,
        *,
        run: WorkflowRunRecord,
        step: WorkflowStepRecord,
        token: StepLeaseToken,
        reason: str,
        retryable: bool,
        uncertain: bool,
        now_us: int,
        deadline: float,
    ) -> StepAckResult:
        leased_cnt, unc_cnt = count_obligations_strict(conn, deadline)
        leased_after = max(0, leased_cnt - 1)
        unc_after = unc_cnt
        if uncertain:
            if not step.side_effecting:
                raise RestartValidationError("uncertain_failure_only_for_side_effecting")
            new_st = StepStatus.UNCERTAIN_NEEDS_RECONCILE
            new_idem = IdempotencyOutcome.UNCERTAIN_NEEDS_RECONCILE
            ev_type = EventType.STEP_MARKED_UNCERTAIN
            final_reason = reason
            unc_after = unc_cnt + 1
        elif retryable:
            if step.side_effecting:
                raise InvalidStepTransitionError(ERR_SE_NO_AUTO_RETRY)
            if step.attempt_no < step.max_attempts:
                new_st = StepStatus.PENDING
                new_idem = IdempotencyOutcome.REQUEUED_PENDING
                ev_type = EventType.STEP_REQUEUED_PENDING
                final_reason = reason
            else:
                new_st = StepStatus.FAILED_TERMINAL
                new_idem = IdempotencyOutcome.FAILED_TERMINAL
                ev_type = EventType.STEP_FAILED_TERMINAL
                final_reason = _bound_reason(f"max_attempts_exceeded: {reason}")
        else:
            new_st = StepStatus.FAILED_TERMINAL
            new_idem = IdempotencyOutcome.FAILED_TERMINAL
            ev_type = EventType.STEP_FAILED_TERMINAL
            final_reason = reason

        _assert_ordinary_capacity(
            meta.last_event_seq,
            events_to_append=1,
            leased_after=leased_after,
            uncertain_after=unc_after,
            max_replay_events=self._max_replay_events,
        )
        seq = meta.last_event_seq + 1
        execute_bounded(
            conn,
            _SQL_UPDATE_STEP_STATUS,
            (new_st.value, None, final_reason, now_us, token.run_id, token.step_id),
            deadline,
        )
        execute_bounded(
            conn,
            _SQL_UPDATE_IDEM_OUTCOME,
            (
                new_idem.value,
                None,
                final_reason,
                seq,
                token.run_id,
                token.idempotency_key,
            ),
            deadline,
        )
        _recompute_and_update_run_status(
            conn,
            token.run_id,
            cancel_requested=run.cancel_requested,
            updated_at_us=now_us,
            deadline=deadline,
        )
        self._finish_event_and_meta(
            conn,
            meta,
            event_type=ev_type,
            run_id=token.run_id,
            step_id=token.step_id,
            payload={
                KEY_ATTEMPT_NO: token.attempt_no,
                KEY_REASON: final_reason,
                KEY_VIA_RECOVERY: False,
            },
            created_at_us=now_us,
            dirty_shutdown=1,
            deadline=deadline,
        )
        return StepAckResult(
            run_id=token.run_id,
            step_id=token.step_id,
            status=new_st.value,
            attempt_no=token.attempt_no,
            lease_epoch=token.lease_epoch,
            duplicate=False,
            seq=seq,
        )

    @staticmethod
    def _dedup_failed_terminal(
        idem: Any, request: FailStepRequest
    ) -> StepAckResult:
        token = request.token
        exact = (
            not request.retryable
            and not request.uncertain
            and idem.step_id == token.step_id
            and idem.attempt_no == token.attempt_no
            and idem.lease_epoch == token.lease_epoch
            and idem.failure_reason == request.reason
        )
        if not exact:
            raise IdempotencyConflictError(ERR_IDEM_CONFLICT)
        return StepAckResult(
            run_id=token.run_id,
            step_id=token.step_id,
            status="deduplicated_already_failed",
            attempt_no=token.attempt_no,
            lease_epoch=token.lease_epoch,
            duplicate=True,
            seq=idem.recorded_seq,
        )

    def fail_step(
        self,
        request: FailStepRequest,
        *,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
    ) -> StepAckResult:
        if not isinstance(request, FailStepRequest):
            raise RestartValidationError("expected FailStepRequest")
        token = request.token
        if token.lease_epoch != self._current_epoch:
            raise StaleEpochError(ERR_STALE_EPOCH)
        now_us = clock_to_wall_us(request.clock)
        with self._write_tx(max_op_ms) as (conn, deadline):
            meta = self._require_meta_active(conn, deadline)
            idem = read_idem_by_pk_strict(
                conn, token.run_id, token.idempotency_key, deadline
            )
            if idem is None:
                raise StaleEpochError(ERR_STALE_EPOCH)
            if idem.outcome_status is IdempotencyOutcome.FAILED_TERMINAL:
                return self._dedup_failed_terminal(idem, request)
            if idem.outcome_status is not IdempotencyOutcome.LEASED:
                raise IdempotencyConflictError(ERR_IDEM_CONFLICT)

            run, step = self._verify_active_lease_in_conn(
                conn,
                token,
                deadline,
                allow_paused_for_settlement=(not request.retryable),
            )
            return self._apply_fail_transition(
                conn,
                meta,
                run=run,
                step=step,
                token=token,
                reason=request.reason,
                retryable=request.retryable,
                uncertain=request.uncertain,
                now_us=now_us,
                deadline=deadline,
            )

    def fail_step_with_authority_gate(
        self,
        *,
        token: StepLeaseToken,
        reason: str,
        clock_provider: Callable[[], ClockSnapshot],
        is_authority_active: Callable[[WorkflowRunRecord, ClockSnapshot], bool],
        max_op_ms: int = DEFAULT_MAX_OP_MS,
    ) -> StepAckResult:
        """Commit retryable pure failure or downgrade to failed_terminal inside BEGIN IMMEDIATE."""
        if not isinstance(token, StepLeaseToken):
            raise RestartValidationError(_ERR_TOKEN_TYPE)
        clean_reason = validate_reason(reason, KEY_REASON)
        if token.lease_epoch != self._current_epoch:
            raise StaleEpochError(ERR_STALE_EPOCH)
        with self._write_tx(max_op_ms) as (conn, deadline):
            meta = self._require_meta_active(conn, deadline)
            run, step = self._verify_active_lease_in_conn(
                conn, token, deadline, allow_paused_for_settlement=True
            )
            if step.side_effecting:
                raise InvalidStepTransitionError(ERR_SE_NO_AUTO_RETRY)
            t_now = clock_provider()
            now_us = clock_to_wall_us(t_now)
            if run.status is RunStatus.PAUSED_NEEDS_RECONCILE:
                retryable = False
                effective_reason = _bound_reason(
                    f"{ERR_RUN_PAUSED_MID_STEP}: {clean_reason}"
                )
            else:
                auth_ok = bool(is_authority_active(run, t_now))
                retryable = auth_ok
                effective_reason = (
                    clean_reason
                    if auth_ok
                    else _bound_reason(f"{ERR_AUTH_RETIRED_MID_STEP}: {clean_reason}")
                )
            return self._apply_fail_transition(
                conn,
                meta,
                run=run,
                step=step,
                token=token,
                reason=effective_reason,
                retryable=retryable,
                uncertain=False,
                now_us=now_us,
                deadline=deadline,
            )

    def _dedup_existing_reconciliation(
        self,
        existing: Any,
        request: ReconcileStepRequest,
    ) -> ReconciliationReceipt:
        same_semantics = (
            existing.step_id == request.step_id
            and existing.attempt_no == request.expected_attempt_no
            and existing.resolution is request.resolution
            and existing.output_digest == request.output_digest
            and existing.evidence_digest == request.evidence_digest
            and existing.reason == request.reason
        )
        if not same_semantics:
            raise IdempotencyConflictError(ERR_RECON_CONFLICT)
        return ReconciliationReceipt(
            run_id=existing.run_id,
            step_id=existing.step_id,
            attempt_no=existing.attempt_no,
            reconciled_epoch=existing.reconciled_epoch,
            reconciliation_key=existing.reconciliation_key,
            resolution=existing.resolution,
            output_digest=existing.output_digest,
            evidence_digest=existing.evidence_digest,
            reason=existing.reason,
            duplicate=True,
            seq=existing.recorded_seq,
        )

    @staticmethod
    def _resolve_requeue_clock_and_authority(
        request: ReconcileStepRequest,
        *,
        run: WorkflowRunRecord,
        authority_gate: Callable[[WorkflowRunRecord, ClockSnapshot], None] | None,
        clock_provider: Callable[[], ClockSnapshot] | None,
        require_live_clock: bool,
    ) -> int:
        auth_bound = run.requires_authority or require_live_clock
        if auth_bound and authority_gate is None:
            raise AuthorityError(ERR_AUTH_STORE_REQUIRED)
        if auth_bound and clock_provider is None:
            if not require_live_clock and authority_gate is not None:
                authority_gate(run, request.clock)
            raise RestartValidationError(ERR_CLOCK_PROVIDER_REQUIRED)
        effective_clock = (
            clock_provider() if clock_provider is not None else request.clock
        )
        now_us = clock_to_wall_us(effective_clock)
        if authority_gate is not None:
            authority_gate(run, effective_clock)
        return now_us

    def _validate_requeue_evidence(
        self,
        request: ReconcileStepRequest,
        *,
        run: WorkflowRunRecord,
        step: WorkflowStepRecord,
        tracker: SyntheticEffectTracker | None,
        tracker_receipt: EffectTrackerReceipt | None,
        authority_gate: Callable[[WorkflowRunRecord, ClockSnapshot], None] | None,
        clock_provider: Callable[[], ClockSnapshot] | None,
        require_live_clock: bool,
    ) -> int:
        if run.cancel_requested or step.attempt_no >= step.max_attempts:
            raise InvalidStepTransitionError(ERR_CANNOT_REQUEUE)
        if tracker is None:
            raise ReconciliationEvidenceError("missing_tracker_verifier")
        tracker.verify_receipt_for_step(
            tracker_receipt,
            step=step,
            current_epoch=self._current_epoch,
            expected_outcome=OUTCOME_NO_EFFECT,
            expected_evidence_digest=request.evidence_digest,
            journal_id=self.journal_id,
        )
        return self._resolve_requeue_clock_and_authority(
            request,
            run=run,
            authority_gate=authority_gate,
            clock_provider=clock_provider,
            require_live_clock=require_live_clock,
        )

    def _validate_completed_evidence(
        self,
        request: ReconcileStepRequest,
        *,
        step: WorkflowStepRecord,
        tracker: SyntheticEffectTracker | None,
        tracker_receipt: EffectTrackerReceipt | None,
        require_completed_receipt: bool,
    ) -> None:
        if require_completed_receipt and (tracker is None or tracker_receipt is None):
            raise ReconciliationEvidenceError("missing_tracker_receipt")
        if tracker is not None and tracker_receipt is not None:
            tracker.verify_receipt_for_step(
                tracker_receipt,
                step=step,
                current_epoch=self._current_epoch,
                expected_outcome=OUTCOME_EFFECT_APPLIED,
                expected_evidence_digest=request.evidence_digest,
                expected_output_digest=request.output_digest,
                journal_id=self.journal_id,
            )

    def _resolve_reconcile_timestamp(
        self,
        request: ReconcileStepRequest,
        *,
        run: WorkflowRunRecord,
        step: WorkflowStepRecord,
        tracker: SyntheticEffectTracker | None,
        tracker_receipt: EffectTrackerReceipt | None,
        authority_gate: Callable[[WorkflowRunRecord, ClockSnapshot], None] | None,
        clock_provider: Callable[[], ClockSnapshot] | None,
        require_live_clock: bool,
        require_completed_receipt: bool,
    ) -> int:
        if request.resolution is ReconcileResolution.REQUEUE_PENDING:
            return self._validate_requeue_evidence(
                request,
                run=run,
                step=step,
                tracker=tracker,
                tracker_receipt=tracker_receipt,
                authority_gate=authority_gate,
                clock_provider=clock_provider,
                require_live_clock=require_live_clock,
            )
        if request.resolution is ReconcileResolution.COMPLETED:
            self._validate_completed_evidence(
                request,
                step=step,
                tracker=tracker,
                tracker_receipt=tracker_receipt,
                require_completed_receipt=require_completed_receipt,
            )
        return clock_to_wall_us(request.clock)

    def _assert_reconcile_capacity(
        self,
        conn: sqlite3.Connection,
        last_seq: int,
        resolution: ReconcileResolution,
        deadline: float,
    ) -> None:
        leased_cnt, unc_cnt = count_obligations_strict(conn, deadline)
        unc_after = max(0, unc_cnt - 1)
        if resolution in TERMINAL_RECONCILE_RESOLUTIONS:
            _assert_terminal_reconcile_capacity(
                last_seq,
                leased_after=leased_cnt,
                uncertain_after=unc_after,
                max_replay_events=self._max_replay_events,
            )
            return
        _assert_ordinary_capacity(
            last_seq,
            events_to_append=1,
            leased_after=leased_cnt,
            uncertain_after=unc_after,
            max_replay_events=self._max_replay_events,
        )

    def reconcile_step(
        self,
        request: ReconcileStepRequest,
        *,
        tracker: SyntheticEffectTracker | None = None,
        tracker_receipt: EffectTrackerReceipt | None = None,
        authority_gate: Callable[[WorkflowRunRecord, ClockSnapshot], None] | None = None,
        clock_provider: Callable[[], ClockSnapshot] | None = None,
        require_live_clock: bool = False,
        require_completed_receipt: bool = False,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
    ) -> ReconciliationReceipt:
        if not isinstance(request, ReconcileStepRequest):
            raise RestartValidationError(_ERR_EXPECTED_RECON_REQ)
        if request.expected_epoch != self._current_epoch:
            raise StaleEpochError(ERR_STALE_EPOCH)
        with self._write_tx(max_op_ms) as (conn, deadline):
            meta = self._require_meta_active(conn, deadline)
            existing = read_recon_by_pk_strict(
                conn, request.run_id, request.reconciliation_key, deadline
            )
            if existing is not None:
                return self._dedup_existing_reconciliation(existing, request)

            run = read_run_by_id_strict(conn, request.run_id, deadline)
            step = read_step_by_pk_strict(conn, request.run_id, request.step_id, deadline)
            if run is None or step is None:
                raise InvalidStepTransitionError("unknown_run_or_step")
            if step.status is not StepStatus.UNCERTAIN_NEEDS_RECONCILE:
                raise InvalidStepTransitionError(f"step_not_uncertain:{step.status.value}")
            if step.attempt_no != request.expected_attempt_no or step.idempotency_key is None:
                raise StaleEpochError(ERR_STALE_EPOCH)

            now_us = self._resolve_reconcile_timestamp(
                request,
                run=run,
                step=step,
                tracker=tracker,
                tracker_receipt=tracker_receipt,
                authority_gate=authority_gate,
                clock_provider=clock_provider,
                require_live_clock=require_live_clock,
                require_completed_receipt=require_completed_receipt,
            )
            self._assert_reconcile_capacity(
                conn, meta.last_event_seq, request.resolution, deadline
            )
            return self._commit_reconcile_rows(
                conn, meta, run=run, step=step, request=request, now_us=now_us, deadline=deadline
            )

    def _commit_reconcile_rows(
        self,
        conn: sqlite3.Connection,
        meta: SupervisorMetaRecord,
        *,
        run: WorkflowRunRecord,
        step: WorkflowStepRecord,
        request: ReconcileStepRequest,
        now_us: int,
        deadline: float,
    ) -> ReconciliationReceipt:
        if step.idempotency_key is None:
            raise JournalIntegrityError(_ERR_MISSING_IDEM)
        status_map = {
            ReconcileResolution.COMPLETED: (
                StepStatus.COMPLETED,
                IdempotencyOutcome.COMPLETED,
            ),
            ReconcileResolution.REQUEUE_PENDING: (
                StepStatus.PENDING,
                IdempotencyOutcome.REQUEUED_PENDING,
            ),
            ReconcileResolution.FAILED_TERMINAL: (
                StepStatus.FAILED_TERMINAL,
                IdempotencyOutcome.FAILED_TERMINAL,
            ),
            ReconcileResolution.CANCELLED: (
                StepStatus.CANCELLED,
                IdempotencyOutcome.CANCELLED,
            ),
        }
        new_st, new_idem = status_map[request.resolution]
        idem_reason = (
            None if request.resolution is ReconcileResolution.COMPLETED else request.reason
        )
        seq = meta.last_event_seq + 1
        execute_bounded(
            conn,
            _SQL_UPDATE_STEP_STATUS,
            (
                new_st.value,
                request.output_digest,
                idem_reason,
                now_us,
                request.run_id,
                request.step_id,
            ),
            deadline,
        )
        execute_bounded(
            conn,
            _SQL_UPDATE_IDEM_OUTCOME,
            (
                new_idem.value,
                request.output_digest,
                idem_reason,
                seq,
                request.run_id,
                step.idempotency_key,
            ),
            deadline,
        )
        execute_bounded(
            conn,
            "INSERT INTO step_reconciliations "
            "(run_id, reconciliation_key, step_id, attempt_no, reconciled_epoch, "
            "resolution, output_digest, evidence_digest, reason, recorded_seq) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request.run_id,
                request.reconciliation_key,
                request.step_id,
                step.attempt_no,
                self._current_epoch,
                request.resolution.value,
                request.output_digest,
                request.evidence_digest,
                request.reason,
                seq,
            ),
            deadline,
        )
        _recompute_and_update_run_status(
            conn,
            request.run_id,
            cancel_requested=run.cancel_requested,
            updated_at_us=now_us,
            deadline=deadline,
        )
        self._finish_event_and_meta(
            conn,
            meta,
            event_type=EventType.STEP_RECONCILED,
            run_id=request.run_id,
            step_id=request.step_id,
            payload={
                KEY_ATTEMPT_NO: step.attempt_no,
                KEY_EVIDENCE_DIGEST: request.evidence_digest,
                KEY_OUTPUT_DIGEST: request.output_digest,
                KEY_REASON: request.reason,
                KEY_RECON_KEY: request.reconciliation_key,
                KEY_RESOLUTION: request.resolution.value,
            },
            created_at_us=now_us,
            dirty_shutdown=1,
            deadline=deadline,
        )
        return ReconciliationReceipt(
            run_id=request.run_id,
            step_id=request.step_id,
            attempt_no=step.attempt_no,
            reconciled_epoch=self._current_epoch,
            reconciliation_key=request.reconciliation_key,
            resolution=request.resolution,
            output_digest=request.output_digest,
            evidence_digest=request.evidence_digest,
            reason=request.reason,
            duplicate=False,
            seq=seq,
        )

    @staticmethod
    def _cancel_step_in_tx(
        conn: sqlite3.Connection,
        step: WorkflowStepRecord,
        *,
        clean_reason: str,
        seq: int,
        now_us: int,
        deadline: float,
    ) -> None:
        if step.status is StepStatus.PENDING:
            execute_bounded(
                conn,
                _SQL_UPDATE_STEP_STATUS,
                (
                    StepStatus.CANCELLED.value,
                    None,
                    clean_reason,
                    now_us,
                    step.run_id,
                    step.step_id,
                ),
                deadline,
            )
            return
        if step.status is not StepStatus.LEASED:
            return
        if step.idempotency_key is None:
            raise JournalIntegrityError(_ERR_MISSING_IDEM)
        new_st = (
            StepStatus.UNCERTAIN_NEEDS_RECONCILE
            if step.side_effecting
            else StepStatus.CANCELLED
        )
        new_idem = (
            IdempotencyOutcome.UNCERTAIN_NEEDS_RECONCILE
            if step.side_effecting
            else IdempotencyOutcome.CANCELLED
        )
        execute_bounded(
            conn,
            _SQL_UPDATE_STEP_STATUS,
            (new_st.value, None, clean_reason, now_us, step.run_id, step.step_id),
            deadline,
        )
        execute_bounded(
            conn,
            _SQL_UPDATE_IDEM_OUTCOME,
            (new_idem.value, None, clean_reason, seq, step.run_id, step.idempotency_key),
            deadline,
        )

    def cancel_run(
        self,
        run_id: str,
        *,
        reason: str,
        clock: ClockSnapshot,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
    ) -> RunStatus:
        clean_run = validate_opaque_id(run_id, "run_id")
        clean_reason = validate_reason(reason, KEY_REASON)
        now_us = clock_to_wall_us(clock)
        with self._write_tx(max_op_ms) as (conn, deadline):
            meta = self._require_meta_active(conn, deadline)
            run = read_run_by_id_strict(conn, clean_run, deadline)
            if run is None:
                raise InvalidStepTransitionError(_ERR_UNKNOWN_RUN)
            if run.status in TERMINAL_RUN_STATUSES or run.cancel_requested:
                raise InvalidStepTransitionError("run_already_terminal_or_cancelling")
            steps = read_run_steps_strict(conn, clean_run, deadline)
            leased_in_run = [s for s in steps.values() if s.status is StepStatus.LEASED]
            se_leased_in_run = sum(1 for s in leased_in_run if s.side_effecting)
            leased_all, unc_all = count_obligations_strict(conn, deadline)
            _assert_ordinary_capacity(
                meta.last_event_seq,
                events_to_append=1,
                leased_after=max(0, leased_all - len(leased_in_run)),
                uncertain_after=unc_all + se_leased_in_run,
                max_replay_events=self._max_replay_events,
            )
            seq = meta.last_event_seq + 1
            for step in sorted(steps.values(), key=lambda s: (s.step_order, s.step_id)):
                self._cancel_step_in_tx(
                    conn,
                    step,
                    clean_reason=clean_reason,
                    seq=seq,
                    now_us=now_us,
                    deadline=deadline,
                )
            execute_bounded(
                conn,
                "UPDATE workflow_runs SET cancel_requested = 1 WHERE run_id COLLATE BINARY = ?",
                (clean_run,),
                deadline,
            )
            new_run_status = _recompute_and_update_run_status(
                conn,
                clean_run,
                cancel_requested=True,
                updated_at_us=now_us,
                deadline=deadline,
            )
            self._finish_event_and_meta(
                conn,
                meta,
                event_type=EventType.RUN_CANCELLED,
                run_id=clean_run,
                step_id=None,
                payload={KEY_REASON: clean_reason},
                created_at_us=now_us,
                dirty_shutdown=1,
                deadline=deadline,
            )
            return new_run_status

    def close_clean(
        self,
        *,
        clock: ClockSnapshot,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
    ) -> int:
        """Append supervisor_stopped, set dirty_shutdown=0, and close connection + lock."""
        now_us = clock_to_wall_us(clock)
        op_ms = validate_max_op_ms(max_op_ms)
        deadline = time.monotonic() + (op_ms / 1000.0)
        remaining_s = check_deadline_s(deadline)
        if not self._conn_lock.acquire(timeout=remaining_s):
            raise RestartStorageError(ERR_OP_DEADLINE)
        try:
            check_deadline_ms(deadline)
            if self._closed or self._conn is None:
                raise RestartStorageError(_ERR_JOURNAL_CLOSED)
            conn = self._conn
            with scoped_op_deadline(conn, deadline):
                execute_bounded(conn, _SQL_BEGIN_IMMEDIATE, (), deadline)
                try:
                    meta = self._require_meta_active(conn, deadline)
                    leased_cnt, unc_cnt = count_obligations_strict(conn, deadline)
                    _assert_close_capacity(
                        meta.last_event_seq,
                        leased_now=leased_cnt,
                        uncertain_now=unc_cnt,
                        max_replay_events=self._max_replay_events,
                    )
                    seq, _ = self._finish_event_and_meta(
                        conn,
                        meta,
                        event_type=EventType.SUPERVISOR_STOPPED,
                        run_id=None,
                        step_id=None,
                        payload={},
                        created_at_us=now_us,
                        dirty_shutdown=0,
                        deadline=deadline,
                    )
                    execute_bounded(conn, "COMMIT", (), deadline)
                except BaseException:
                    if conn.in_transaction:
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                    raise
            self._closed = True
            self._conn = None
            safe_close(conn)
            lock_fd = self._lock_fd
            self._lock_fd = None
            release_lock_fd(lock_fd)
            return seq
        finally:
            self._conn_lock.release()

    def simulate_crash(self) -> None:
        """Abruptly close SQLite & lock FD leaving dirty_shutdown=1 (no supervisor_stopped)."""
        with self._conn_lock:
            if self._closed:
                return
            self._closed = True
            conn = self._conn
            self._conn = None
            safe_rollback_and_close(conn)
            lock_fd = self._lock_fd
            self._lock_fd = None
            release_lock_fd(lock_fd)


# --- DurableWorkflowSupervisor with single shared _lifecycle_gate ---


class DurableWorkflowSupervisor:
    """Crash-fault-injecting workflow supervisor with single _lifecycle_gate and plan binding."""

    def __init__(
        self,
        journal: WorkflowRestartJournal,
        *,
        tracker: SyntheticEffectTracker,
        authority_store: RunAuthorityStore | None = None,
    ) -> None:
        self._journal = journal
        self._tracker = tracker
        self._authority_store = authority_store
        self._lifecycle_gate = threading.RLock()
        self._tracker.attach_epoch(
            self._journal.current_epoch, journal_id=self._journal.journal_id
        )

    @property
    def journal(self) -> WorkflowRestartJournal:
        return self._journal

    @property
    def tracker(self) -> SyntheticEffectTracker:
        return self._tracker

    @classmethod
    def start_or_recover(
        cls,
        state_dir: Path,
        *,
        clock: ClockSnapshot,
        tracker: SyntheticEffectTracker,
        authority_store: RunAuthorityStore | None = None,
        sandbox_root: Path | None = None,
        max_op_ms: int = DEFAULT_MAX_OP_MS,
        max_replay_events: int = MAX_REPLAY_EVENTS,
        crash_point: CrashPoint = CrashPoint.NONE,
    ) -> tuple[DurableWorkflowSupervisor, RecoveryReport]:
        journal, report = WorkflowRestartJournal.open_and_recover(
            state_dir,
            clock=clock,
            sandbox_root=sandbox_root,
            max_op_ms=max_op_ms,
            max_replay_events=max_replay_events,
            crash_point=crash_point,
        )
        return (
            cls(journal, tracker=tracker, authority_store=authority_store),
            report,
        )

    def _reconstruct_receipt(self, run: WorkflowRunRecord) -> AdmissionReceipt:
        return AdmissionReceipt(
            run_id=run.run_id,
            grant_generation=run.grant_generation,
            workflow_plan_digest=run.workflow_plan_digest,
            workflow_id=run.workflow_id,
        )

    def _verify_live_run_record_authority(
        self, run: WorkflowRunRecord, clock: ClockSnapshot
    ) -> None:
        if self._authority_store is None:
            if run.requires_authority:
                raise AuthorityError(ERR_AUTH_STORE_REQUIRED)
            return
        receipt = self._reconstruct_receipt(run)
        self._authority_store.verify_active(
            receipt, clock=clock, expected_plan_digest=run.workflow_plan_digest
        )

    def _verify_live_run_authority(self, run_id: str, clock: ClockSnapshot) -> None:
        run = self._journal.get_run(run_id)
        self._verify_live_run_record_authority(run, clock)

    def _is_live_run_record_authority_active(
        self, run: WorkflowRunRecord, clock: ClockSnapshot
    ) -> bool:
        try:
            self._verify_live_run_record_authority(run, clock)
            return True
        except AuthorityError:
            return False

    def create_run_from_plan(
        self,
        *,
        plan: CompiledWorkflowPlan,
        receipt: AdmissionReceipt,
        clock: ClockSnapshot,
        proposed_steps: Sequence[StepSpec] | None = None,
    ) -> WorkflowRunRecord:
        """Create run strictly from auth_record.approved_plan's canonical derived DAG."""
        with self._lifecycle_gate:
            if self._authority_store is None:
                raise RestartPolicyError("authority_store_required_for_plan_run")
            auth_record = self._authority_store.verify_active(
                receipt, clock=clock, expected_plan_digest=plan.workflow_plan_digest
            )
            approved = auth_record.approved_plan
            recomp_spec, recomp_skill, recomp_plan = recompute_plan_digests(approved)
            recomp_effects = compute_reachable_effects(approved.spec)
            digests_ok = (
                (recomp_spec, recomp_skill, recomp_plan)
                == (
                    approved.spec_digest,
                    approved.skill_sha256,
                    approved.workflow_plan_digest,
                )
                and approved.workflow_plan_digest
                == auth_record.workflow_plan_digest
                == receipt.workflow_plan_digest
                == plan.workflow_plan_digest
                and approved.spec.id == receipt.workflow_id
                and recomp_effects == approved.reachable_effects
            )
            if not digests_ok:
                raise AdmissionDeniedError("PLAN_INTEGRITY_MISMATCH")
            canonical_steps = derive_steps_from_plan(approved)
            if proposed_steps is not None and tuple(proposed_steps) != canonical_steps:
                raise RestartPolicyError(ERR_PROPOSED_STEPS_MISMATCH)
            return self._journal.create_run(
                CreateRunRequest(
                    run_id=receipt.run_id,
                    workflow_id=approved.spec.id,
                    spec_digest=approved.spec_digest,
                    workflow_plan_digest=approved.workflow_plan_digest,
                    grant_generation=receipt.grant_generation,
                    steps=canonical_steps,
                    clock=clock,
                    requires_authority=True,
                )
            )

    def revoke_run_authority(self, run_id: str) -> None:
        with self._lifecycle_gate:
            if self._authority_store is not None:
                self._authority_store.revoke_run(run_id)

    def cancel_run(
        self, run_id: str, *, reason: str, clock: ClockSnapshot
    ) -> RunStatus:
        with self._lifecycle_gate:
            return self._journal.cancel_run(run_id, reason=reason, clock=clock)

    def simulate_crash(self) -> None:
        with self._lifecycle_gate:
            self._tracker.fence_epoch(self._journal.current_epoch + 1)
            self._journal.simulate_crash()

    def close_clean(self, *, clock: ClockSnapshot) -> int:
        with self._lifecycle_gate:
            return self._journal.close_clean(clock=clock)

    def reconcile_step(
        self,
        request: ReconcileStepRequest,
        *,
        tracker_receipt: EffectTrackerReceipt | None = None,
        clock_provider: Callable[[], ClockSnapshot] | None = None,
    ) -> ReconciliationReceipt:
        if not isinstance(request, ReconcileStepRequest):
            raise RestartValidationError(_ERR_EXPECTED_RECON_REQ)
        if request.resolution is ReconcileResolution.REQUEUE_PENDING:
            with self._lifecycle_gate:
                return self._journal.reconcile_step(
                    request,
                    tracker=self._tracker,
                    tracker_receipt=tracker_receipt,
                    authority_gate=self._verify_live_run_record_authority,
                    clock_provider=clock_provider,
                    require_live_clock=(self._authority_store is not None),
                )
        return self._journal.reconcile_step(
            request,
            tracker=self._tracker,
            tracker_receipt=tracker_receipt,
            require_completed_receipt=True,
        )

    def _settle_pre_entry_refusal(
        self, token: StepLeaseToken, *, reason: str, clock: ClockSnapshot
    ) -> None:
        self._tracker.fence_attempt(token)
        self._journal.fail_step(
            FailStepRequest(
                token=token,
                reason=reason,
                retryable=False,
                uncertain=False,
                clock=clock,
            )
        )

    def _enter_worker_under_gate(
        self,
        token: StepLeaseToken,
        clock_provider: Callable[[], ClockSnapshot],
    ) -> WorkflowStepRecord:
        with self._lifecycle_gate:
            _, run, step = self._journal.verify_lease_for_entry(token)
            t_entry = clock_provider()
            if run.status is RunStatus.PAUSED_NEEDS_RECONCILE:
                self._settle_pre_entry_refusal(
                    token, reason=ERR_RUN_PAUSED_PRE_ENTRY, clock=t_entry
                )
                raise InvalidStepTransitionError(ERR_RUN_PAUSED_PRE_ENTRY)
            try:
                self._verify_live_run_record_authority(run, t_entry)
            except AuthorityError:
                self._settle_pre_entry_refusal(
                    token, reason=ERR_AUTH_REVOKED_PRE_ENTRY, clock=t_entry
                )
                raise
            self._tracker.admit_attempt(token, journal_id=self._journal.journal_id)
            return step

    def _settle_worker_result(
        self,
        token: StepLeaseToken,
        work_result: WorkerStepResult,
        clock_provider: Callable[[], ClockSnapshot],
    ) -> StepExecutionOutcome:
        if work_result.outcome == WORKER_COMPLETED:
            t_done = clock_provider()
            out_digest = cast(str, work_result.output_digest)
            ack = self._journal.complete_step(
                CompleteStepRequest(token=token, output_digest=out_digest, clock=t_done)
            )
            return StepExecutionOutcome(token=token, ack=ack)

        if work_result.outcome == WORKER_FAILED_RETRYABLE:
            with self._lifecycle_gate:
                ack = self._journal.fail_step_with_authority_gate(
                    token=token,
                    reason=work_result.reason,
                    clock_provider=clock_provider,
                    is_authority_active=self._is_live_run_record_authority_active,
                )
            return StepExecutionOutcome(token=token, ack=ack)

        if work_result.outcome == WORKER_FAILED_UNCERTAIN:
            with self._lifecycle_gate:
                t_done = clock_provider()
                ack = self._journal.fail_step(
                    FailStepRequest(
                        token=token,
                        reason=work_result.reason,
                        retryable=False,
                        uncertain=True,
                        clock=t_done,
                    )
                )
            return StepExecutionOutcome(token=token, ack=ack)

        t_done = clock_provider()
        ack = self._journal.fail_step(
            FailStepRequest(
                token=token,
                reason=work_result.reason,
                retryable=False,
                uncertain=False,
                clock=t_done,
            )
        )
        return StepExecutionOutcome(token=token, ack=ack)

    def run_step_once(
        self,
        run_id: str,
        step_id: str,
        *,
        worker_fn: Callable[[StepLeaseToken], WorkerStepResult],
        clock_provider: Callable[[], ClockSnapshot],
        idempotency_key: str | None = None,
        crash_point: CrashPoint = CrashPoint.NONE,
        captured_tokens: list[StepLeaseToken] | None = None,
        on_after_lease_before_entry: Callable[[StepLeaseToken], None] | None = None,
    ) -> StepExecutionOutcome:
        t_lease = clock_provider()
        self._verify_live_run_authority(run_id, t_lease)

        token = self._journal.lease_step(
            run_id=run_id,
            step_id=step_id,
            clock=t_lease,
            idempotency_key=idempotency_key,
        )
        if captured_tokens is not None:
            captured_tokens.append(token)
        if crash_point is CrashPoint.AFTER_LEASE_COMMIT_BEFORE_WORKER:
            self.simulate_crash()
            raise SimulatedSupervisorCrash("AFTER_LEASE_COMMIT_BEFORE_WORKER")
        if on_after_lease_before_entry is not None:
            on_after_lease_before_entry(token)

        step_rec = self._enter_worker_under_gate(token, clock_provider)

        try:
            work_result = self._tracker.run_admitted(token, worker_fn=worker_fn)
        except SimulatedSupervisorCrash:
            raise
        except Exception as exc:
            work_result = WorkerStepResult(
                outcome=WORKER_FAILED_UNCERTAIN if step_rec.side_effecting else WORKER_FAILED_TERMINAL,
                reason=f"worker_exception:{type(exc).__name__}",
            )

        if crash_point is CrashPoint.AFTER_WORKER_EXEC_BEFORE_COMPLETE_COMMIT:
            self.simulate_crash()
            raise SimulatedSupervisorCrash("AFTER_WORKER_EXEC_BEFORE_COMPLETE_COMMIT")

        return self._settle_worker_result(token, work_result, clock_provider)
