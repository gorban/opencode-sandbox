"""Contracts, canonical JSON/hash chain, DAG status, pure replay reducer, and effect tracker."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
import hmac
import json
import math
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any, Literal, cast

_RESTART_DIR = Path(__file__).resolve().parent
_SPIKE_N_DIR = _RESTART_DIR.parent
_SPIKE_L_DIR = _SPIKE_N_DIR.parent / "l"
for _import_dir in (str(_RESTART_DIR), str(_SPIKE_N_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_workflow_plan import (  # noqa: E402
    OBSERVE_ONLY_ALLOWED_EFFECTS,
    ClockSnapshot,
    CompiledWorkflowPlan,
    compute_reachable_effects,
)
from oc_workflow_schema import (  # noqa: E402
    ALLOWED_EFFECTS,
    canonical_json_bytes,
    domain_sha256,
    parse_strict_bool,
    parse_strict_int,
    validate_clean_str,
)
from oc_workflow_supervision import ProgressFingerprint  # noqa: E402

RESTART_SCHEMA_VERSION = "oc.n.workflow_restart@1"
EVENT_GENESIS_HASH = "0" * 64
EVENT_HASH_DOMAIN = "oc-wf-restart-event-v1:"
IDEM_KEY_DOMAIN = "oc-wf-step-idem-v1:"
EVIDENCE_DIGEST_DOMAIN = "oc-wf-reconcile-evidence-v1:"
TRACKER_RECEIPT_DOMAIN = "oc-wf-tracker-receipt-v1:"

MAX_INT64 = (1 << 63) - 1
MIN_INT64 = -(1 << 63)
MAX_RUNS = 256
MAX_STEPS_PER_RUN = 64
MAX_STEP_ATTEMPTS = 16
MAX_REPLAY_EVENTS = 50_000
MAX_EVENT_PAYLOAD_BYTES = 16_384
MAX_JSON_DEPTH = 8
MAX_ID_BYTES = 128
MAX_REASON_BYTES = 256
MIN_OP_MS = 50
DEFAULT_MAX_OP_MS = 2_000
MAX_OP_MS = 10_000
DEFAULT_STEP_MAX_ATTEMPTS = 3

EFFECT_READ_METRICS = "read_metrics"
EFFECT_SPAWN_LANE = "spawn_lane"
OUTCOME_NO_EFFECT = "no_effect"
OUTCOME_EFFECT_APPLIED = "effect_applied"
OUTCOME_STILL_PENDING = "still_pending"
WORKER_COMPLETED = "completed"
WORKER_FAILED_RETRYABLE = "failed_retryable"
WORKER_FAILED_TERMINAL = "failed_terminal"
WORKER_FAILED_UNCERTAIN = "failed_uncertain"

PURE_IDEMPOTENT_EFFECTS: frozenset[str] = frozenset(
    {EFFECT_READ_METRICS, "update_health_projection"}
)
if not PURE_IDEMPOTENT_EFFECTS.issubset(OBSERVE_ONLY_ALLOWED_EFFECTS):
    raise RuntimeError("PURE_IDEMPOTENT_EFFECTS must be a subset of OBSERVE_ONLY_ALLOWED_EFFECTS")

_LANE_SHAPE_EFFECTS: frozenset[str] = frozenset({EFFECT_SPAWN_LANE, "acquire_lane_lease"})

_STATE_SHAPE_IMPLIED_EFFECTS: Mapping[str, frozenset[str]] = {
    "ship_lane": _LANE_SHAPE_EFFECTS,
    "scout_lane": _LANE_SHAPE_EFFECTS,
    "parallel_lanes": _LANE_SHAPE_EFFECTS,
    "deterministic": frozenset({"launch_sandbox"}),
    "human_gate_async": frozenset({"pause_lane_gate"}),
    "human_gate_blocking": frozenset({"blocking_gate"}),
}

_REPLAY_DEADLINE_STRIDE = 64

CORE_TABLE_NAMES: frozenset[str] = frozenset(
    {
        "supervisor_meta",
        "workflow_runs",
        "workflow_steps",
        "step_idempotency_keys",
        "step_reconciliations",
        "workflow_event_log",
    }
)

_SHA256_HEX_RE = re.compile(r"^[\da-f]{64}$", re.ASCII)
_OPAQUE_ID_RE = re.compile(r"^[a-zA-Z\d][a-zA-Z\d._:/-]{0,127}$", re.ASCII)
_STEP_ID_RE = re.compile(r"^[a-z\d][a-z\d_.-]{0,63}$", re.ASCII)

ERR_STALE_EPOCH = "stale_lease_epoch"
ERR_IDEM_CONFLICT = "idempotency_key_conflict"
ERR_RECON_CONFLICT = "reconciliation_key_conflict"
ERR_MAX_RUNS = "max_runs_exceeded"
ERR_MAX_EVENTS = "max_replay_events_exceeded"
ERR_PLAN_GRAPH_UNSUPPORTED = "plan_graph_unsupported"
ERR_PROPOSED_STEPS_MISMATCH = "proposed_steps_mismatch"
ERR_MUTATING_MUST_BE_SE = "mutating_effect_must_be_side_effecting"
ERR_CANNOT_REQUEUE = "cannot_requeue_cancelled_or_exhausted_step"
ERR_SE_NO_AUTO_RETRY = "side_effecting_step_cannot_auto_retry"
ERR_AUTH_REVOKED_PRE_ENTRY = "authority_revoked_pre_entry"
ERR_AUTH_RETIRED_MID_STEP = "authority_retired_mid_step"
ERR_RUN_PAUSED_PRE_ENTRY = "run_paused_before_worker_entry"
ERR_RUN_PAUSED_MID_STEP = "run_paused_mid_step"
ERR_AUTH_STORE_REQUIRED = "authority_store_required"
ERR_CLOCK_PROVIDER_REQUIRED = "clock_provider_required_for_requeue"
ERR_DUP_MATERIALIZED_KEY = "duplicate_materialized_key"
ERR_MAX_ATTEMPTS_RECOVERY = "max_attempts_exceeded_on_recovery"
ERR_RECOVERY_UNCERTAIN = "prior_epoch_side_effect_uncertain"
ERR_RECOVERY_REQUEUE = "prior_epoch_pure_step_requeued"
ERR_UNFENCED_LEASE = "unfenced_prior_epoch_lease"
ERR_HASH_CHAIN_BROKEN = "hash_chain_broken"
ERR_ENTRY_HASH_MISMATCH = "entry_hash_mismatch"
ERR_NON_CANONICAL_JSON = "non_canonical_payload_json"
ERR_JSON_DEPTH = "json_depth_exceeded"
ERR_DUP_JSON_KEY = "duplicate_json_key"
ERR_DISALLOWED_FLOAT = "disallowed_json_float"
ERR_MALFORMED_STORAGE = "malformed_storage_class"
ERR_META_MISSING_NONEMPTY = "meta_missing_nonempty_journal"
ERR_META_MISSING = "meta_missing"
ERR_META_MULTIPLE = "meta_multiple_rows"
ERR_INVALID_META_SEQ = "invalid_meta_seq"
ERR_UNEXPECTED_SCHEMA = "unexpected_schema_object"
ERR_EXTRA_ROWS = "unexpected_extra_materialized_rows"
ERR_MATERIALIZED_MISMATCH = "materialized_state_mismatch"
ERR_OP_DEADLINE = "op_deadline_exceeded"
ERR_LOCK_HELD = "supervisor_lock_held"
ERR_JOURNAL_CORRUPT = "journal_db_corrupt"
ERR_JOURNAL_UNREADABLE = "journal_unreadable"

KEY_ATTEMPT_NO = "attempt_no"
KEY_CANCEL_REQUESTED = "cancel_requested"
KEY_CREATED_AT_US = "created_at_us"
KEY_CREATED_EPOCH = "created_epoch"
KEY_CURRENT_EPOCH = "current_epoch"
KEY_DEPENDS_ON = "depends_on"
KEY_DIRTY_RECOVERY = "dirty_recovery"
KEY_EFFECT_KIND = "effect_kind"
KEY_ENTRY_HASH = "entry_hash"
KEY_EVIDENCE_DIGEST = "evidence_digest"
KEY_FAILURE_REASON = "failure_reason"
KEY_GRANT_GENERATION = "grant_generation"
KEY_IDEM_KEY = "idempotency_key"
KEY_JOURNAL_ID = "journal_id"
KEY_LAST_EVENT_SEQ = "last_event_seq"
KEY_LEASE_EPOCH = "lease_epoch"
KEY_MAX_ATTEMPTS = "max_attempts"
KEY_OUTPUT_DIGEST = "output_digest"
KEY_PRIOR_EPOCH = "prior_epoch"
KEY_REASON = "reason"
KEY_RECON_EPOCH = "reconciled_epoch"
KEY_RECON_KEY = "reconciliation_key"
KEY_RECORDED_SEQ = "recorded_seq"
KEY_REQUIRES_AUTHORITY = "requires_authority"
KEY_RESOLUTION = "resolution"
KEY_SIDE_EFFECTING = "side_effecting"
KEY_SPEC_DIGEST = "spec_digest"
KEY_STATE_NAME = "state_name"
KEY_STEP_ORDER = "step_order"
KEY_SUPERVISOR_EPOCH = "supervisor_epoch"
KEY_UPDATED_AT_US = "updated_at_us"
KEY_VIA_RECOVERY = "via_recovery"
KEY_WORKFLOW_ID = "workflow_id"
KEY_WORKFLOW_PLAN_DIGEST = "workflow_plan_digest"


class StepStatus(str, Enum):
    PENDING = "pending"
    LEASED = "leased"
    UNCERTAIN_NEEDS_RECONCILE = "uncertain_needs_reconcile"
    COMPLETED = WORKER_COMPLETED
    FAILED_TERMINAL = WORKER_FAILED_TERMINAL
    CANCELLED = "cancelled"


class RunStatus(str, Enum):
    RUNNING = "running"
    PAUSED_NEEDS_RECONCILE = "paused_needs_reconcile"
    COMPLETED = WORKER_COMPLETED
    FAILED = "failed"
    CANCELLED = "cancelled"


class IdempotencyOutcome(str, Enum):
    LEASED = "leased"
    COMPLETED = WORKER_COMPLETED
    FAILED_TERMINAL = WORKER_FAILED_TERMINAL
    REQUEUED_PENDING = "requeued_pending"
    UNCERTAIN_NEEDS_RECONCILE = "uncertain_needs_reconcile"
    CANCELLED = "cancelled"


class ReconcileResolution(str, Enum):
    COMPLETED = WORKER_COMPLETED
    REQUEUE_PENDING = "requeue_pending"
    FAILED_TERMINAL = WORKER_FAILED_TERMINAL
    CANCELLED = "cancelled"


class EventType(str, Enum):
    SUPERVISOR_STARTED = "supervisor_started"
    SUPERVISOR_STOPPED = "supervisor_stopped"
    RUN_CREATED = "run_created"
    STEP_LEASED = "step_leased"
    STEP_COMPLETED = "step_completed"
    STEP_FAILED_TERMINAL = "step_failed_terminal"
    STEP_REQUEUED_PENDING = "step_requeued_pending"
    STEP_MARKED_UNCERTAIN = "step_marked_uncertain"
    STEP_RECONCILED = "step_reconciled"
    RUN_CANCELLED = "run_cancelled"


class CrashPoint(str, Enum):
    NONE = "none"
    AFTER_LEASE_COMMIT_BEFORE_WORKER = "after_lease_commit_before_worker"
    AFTER_WORKER_EXEC_BEFORE_COMPLETE_COMMIT = "after_worker_exec_before_complete_commit"
    DURING_RECOVERY_BEFORE_COMMIT = "during_recovery_before_commit"
    AFTER_RECOVERY_COMMIT_BEFORE_DISPATCH = "after_recovery_commit_before_dispatch"


TERMINAL_RECONCILE_RESOLUTIONS: frozenset[ReconcileResolution] = frozenset(
    {
        ReconcileResolution.COMPLETED,
        ReconcileResolution.FAILED_TERMINAL,
        ReconcileResolution.CANCELLED,
    }
)
TERMINAL_RUN_STATUSES: frozenset[RunStatus] = frozenset(
    {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED}
)


class RestartError(RuntimeError):
    """Base error for PRD N durable workflow restart & replay kernel."""


class RestartValidationError(RestartError):
    """Malformed input, schema violation, or out-of-range value."""


class RestartPolicyError(RestartError):
    """Policy, plan-binding, or capacity-headroom refusal."""


class ReconciliationEvidenceError(RestartPolicyError):
    """Missing, mismatched, unfenced, or inconclusive tracker reconciliation evidence."""


class RestartStorageError(RestartError):
    """Filesystem admission, exclusive lock, deadline, or SQLite I/O failure."""


class JournalIntegrityError(RestartError):
    """Corrupt SQLite journal, broken hash chain, malformed JSON, or storage-class tamper."""


class ReplayMismatchError(JournalIntegrityError):
    """Event-log lifecycle violation or divergence from materialized SQLite tables."""


class StaleEpochError(RestartError):
    """Callback or reconciliation presented a stale or mismatched epoch/attempt token."""


class IdempotencyConflictError(RestartError):
    """Duplicate idempotency or reconciliation key reused or replayed with conflicting payload."""


class InvalidStepTransitionError(RestartError):
    """Illegal step or run state transition."""


class SimulatedSupervisorCrash(RestartError):
    """Deterministic offline crash-point fault injection."""


# --- Validation & canonical JSON/hash helpers ---


def _wrap_clean_str(
    value: Any, field_name: str, *, max_bytes: int, allow_empty: bool = False
) -> str:
    try:
        return validate_clean_str(
            value, field_name, max_bytes=max_bytes, allow_empty=allow_empty
        )
    except ValueError as exc:
        raise RestartValidationError(str(exc)) from exc


def validate_sha256_hex(value: Any, field_name: str) -> str:
    text = _wrap_clean_str(value, field_name, max_bytes=64)
    if _SHA256_HEX_RE.fullmatch(text) is None:
        raise RestartValidationError(f"{field_name}: expected lowercase 64-hex sha256")
    return text


def validate_opaque_id(value: Any, field_name: str) -> str:
    text = _wrap_clean_str(value, field_name, max_bytes=MAX_ID_BYTES)
    if _OPAQUE_ID_RE.fullmatch(text) is None:
        raise RestartValidationError(f"{field_name}: invalid opaque identifier")
    return text


def validate_step_id(value: Any, field_name: str = "step_id") -> str:
    text = _wrap_clean_str(value, field_name, max_bytes=64)
    if _STEP_ID_RE.fullmatch(text) is None:
        raise RestartValidationError(f"{field_name}: invalid step identifier")
    return text


def validate_reason(value: Any, field_name: str = KEY_REASON) -> str:
    return _wrap_clean_str(value, field_name, max_bytes=MAX_REASON_BYTES)


def validate_int64(value: Any, field_name: str, *, min_val: int = 0) -> int:
    try:
        return parse_strict_int(value, field_name, min_val=min_val, max_val=MAX_INT64)
    except ValueError as exc:
        raise RestartValidationError(str(exc)) from exc


def validate_bool(value: Any, field_name: str) -> bool:
    try:
        return parse_strict_bool(value, field_name)
    except ValueError as exc:
        raise RestartValidationError(str(exc)) from exc


def validate_max_op_ms(value: Any) -> int:
    try:
        return parse_strict_int(
            value, "max_op_ms", min_val=MIN_OP_MS, max_val=MAX_OP_MS
        )
    except ValueError as exc:
        raise RestartValidationError(str(exc)) from exc


def validate_max_replay_events(value: Any) -> int:
    try:
        return parse_strict_int(
            value, "max_replay_events", min_val=1, max_val=MAX_REPLAY_EVENTS
        )
    except ValueError as exc:
        raise RestartValidationError(str(exc)) from exc


_MAX_WALL_S = MAX_INT64 / 1_000_000.0
_ERR_CLOCK_RANGE = "clock_out_of_range"


def clock_to_wall_us(clock: Any) -> int:
    """Validate ClockSnapshot and convert wall_s to exact non-negative signed-64-bit microseconds."""
    if not isinstance(clock, ClockSnapshot):
        raise RestartValidationError("clock must be ClockSnapshot")
    try:
        mono_f = float(clock.monotonic_s) + 0.0
        wall_f = float(clock.wall_s) + 0.0
    except (OverflowError, TypeError, ValueError) as exc:
        raise RestartValidationError(_ERR_CLOCK_RANGE) from exc
    if not (math.isfinite(mono_f) and math.isfinite(wall_f)):
        raise RestartValidationError("clock values must be finite")
    if mono_f < 0.0 or wall_f < 0.0:
        raise RestartValidationError("clock values must be non-negative")
    if wall_f > _MAX_WALL_S:
        raise RestartValidationError(_ERR_CLOCK_RANGE)
    scaled = wall_f * 1_000_000.0
    if not math.isfinite(scaled):
        raise RestartValidationError(_ERR_CLOCK_RANGE)
    wall_us = round(scaled)
    if wall_us < 0 or wall_us > MAX_INT64:
        raise RestartValidationError(_ERR_CLOCK_RANGE)
    return int(wall_us)


def _step_json_string_state(ch: str, escaped: bool) -> tuple[bool, bool]:
    if escaped:
        return True, False
    if ch == "\\":
        return True, True
    if ch == '"':
        return False, False
    return True, False


def _step_json_depth(ch: str, depth: int, max_depth: int) -> tuple[int, bool]:
    if ch == '"':
        return depth, True
    if ch in ("{", "["):
        nxt = depth + 1
        if nxt > max_depth:
            raise JournalIntegrityError(ERR_JSON_DEPTH)
        return nxt, False
    if ch in ("}", "]"):
        nxt = depth - 1
        if nxt < 0:
            raise JournalIntegrityError(ERR_JSON_DEPTH)
        return nxt, False
    return depth, False


def prescan_json_depth(text: str, *, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Scan JSON nesting depth in O(N) before json.loads() to prevent RecursionError DoS."""
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            in_string, escaped = _step_json_string_state(ch, escaped)
        else:
            depth, in_string = _step_json_depth(ch, depth, max_depth)
    if in_string or depth != 0:
        raise JournalIntegrityError(ERR_NON_CANONICAL_JSON)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in pairs:
        if key in out:
            raise JournalIntegrityError(ERR_DUP_JSON_KEY)
        out[key] = val
    return out


def _reject_json_float(_token: str) -> Any:
    raise JournalIntegrityError(ERR_DISALLOWED_FLOAT)


def _reject_json_constant(_token: str) -> Any:
    raise JournalIntegrityError(ERR_DISALLOWED_FLOAT)


def _validate_json_scalar(obj: Any) -> bool:
    if obj is None or type(obj) is bool:
        return True
    if type(obj) is int:
        if obj < MIN_INT64 or obj > MAX_INT64:
            raise JournalIntegrityError("json_int_out_of_range")
        return True
    if isinstance(obj, str):
        try:
            validate_clean_str(obj, "json_leaf", allow_empty=True)
        except ValueError as exc:
            raise JournalIntegrityError(str(exc)) from exc
        return True
    return False


def _validate_json_tree(obj: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise JournalIntegrityError(ERR_JSON_DEPTH)
    if _validate_json_scalar(obj):
        return
    if isinstance(obj, list):
        for item in obj:
            _validate_json_tree(item, depth + 1)
        return
    if isinstance(obj, dict):
        for key, val in obj.items():
            _validate_json_tree(key, depth + 1)
            _validate_json_tree(val, depth + 1)
        return
    raise JournalIntegrityError(ERR_DISALLOWED_FLOAT)


def parse_canonical_json_blob(raw_blob: bytes, *, expect_list: bool = False) -> Any:
    """Decode bounded UTF-8 canonical JSON rejecting depth abuse, dup keys, floats, and drift."""
    if not isinstance(raw_blob, bytes) or len(raw_blob) > MAX_EVENT_PAYLOAD_BYTES:
        raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
    try:
        text = raw_blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JournalIntegrityError("invalid_utf8_json") from exc
    prescan_json_depth(text, max_depth=MAX_JSON_DEPTH)
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except JournalIntegrityError:
        raise
    except (RecursionError, ValueError) as exc:
        raise JournalIntegrityError(ERR_NON_CANONICAL_JSON) from exc
    if expect_list and not isinstance(decoded, list):
        raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
    if not expect_list and not isinstance(decoded, dict):
        raise JournalIntegrityError(ERR_MALFORMED_STORAGE)
    _validate_json_tree(decoded)
    expected_bytes = canonical_json_bytes(decoded)
    if not hmac.compare_digest(raw_blob, expected_bytes):
        raise JournalIntegrityError(ERR_NON_CANONICAL_JSON)
    return decoded


def serialize_strict_json(obj: Any) -> str:
    """Serialize float-free canonical JSON bounded by MAX_EVENT_PAYLOAD_BYTES."""
    _validate_json_tree(obj)
    raw = canonical_json_bytes(obj)
    if len(raw) > MAX_EVENT_PAYLOAD_BYTES:
        raise RestartValidationError("json_payload_exceeds_limit")
    return raw.decode("utf-8")


def compute_event_hash(
    *,
    seq: int,
    supervisor_epoch: int,
    event_type: str,
    run_id: str | None,
    step_id: str | None,
    payload: Mapping[str, Any],
    created_at_us: int,
    prev_hash: str,
) -> str:
    body = {
        KEY_CREATED_AT_US: created_at_us,
        "event_type": event_type,
        "payload": dict(payload),
        "prev_hash": prev_hash,
        "run_id": run_id,
        "seq": seq,
        "step_id": step_id,
        KEY_SUPERVISOR_EPOCH: supervisor_epoch,
    }
    return domain_sha256(EVENT_HASH_DOMAIN, body)


def derive_step_idempotency_key(
    run_id: str, step_id: str, attempt_no: int, lease_epoch: int
) -> str:
    digest = domain_sha256(
        IDEM_KEY_DOMAIN,
        {
            KEY_ATTEMPT_NO: attempt_no,
            KEY_LEASE_EPOCH: lease_epoch,
            "run_id": run_id,
            "step_id": step_id,
        },
    )
    return f"idem_{digest[:32]}"


def compute_tracker_receipt_digest(
    *,
    run_id: str,
    step_id: str,
    attempt_no: int,
    lease_epoch: int,
    idempotency_key: str,
    tracker_outcome: str,
    attempt_fenced: bool,
    output_digest: str | None,
) -> str:
    body = {
        "attempt_fenced": attempt_fenced,
        KEY_ATTEMPT_NO: attempt_no,
        KEY_IDEM_KEY: idempotency_key,
        KEY_LEASE_EPOCH: lease_epoch,
        KEY_OUTPUT_DIGEST: output_digest,
        "run_id": run_id,
        "step_id": step_id,
        "tracker_outcome": tracker_outcome,
    }
    return domain_sha256(TRACKER_RECEIPT_DOMAIN, body)


def compute_reconciliation_evidence_digest(
    receipt: EffectTrackerReceipt,
    *,
    fingerprint: ProgressFingerprint | None = None,
) -> str:
    """Return receipt digest (or combined receipt + ProgressFingerprint evidence digest)."""
    if fingerprint is None:
        return receipt.receipt_digest
    fp_dict = {
        "commit_sha": fingerprint.commit_sha,
        "diff_stat_hash": fingerprint.diff_stat_hash,
        "tree_oid": fingerprint.tree_oid,
        "verified_test_exit_seq": fingerprint.verified_test_exit_seq,
        "workflow_state_seq": fingerprint.workflow_state_seq,
    }
    return domain_sha256(
        EVIDENCE_DIGEST_DOMAIN,
        {"progress_fingerprint": fp_dict, "receipt_digest": receipt.receipt_digest},
    )


# --- Frozen domain dataclasses ---


@dataclass(frozen=True)
class StepSpec:
    step_id: str
    state_name: str
    effect_kind: str
    side_effecting: bool
    depends_on: tuple[str, ...] = ()
    max_attempts: int = DEFAULT_STEP_MAX_ATTEMPTS

    def __post_init__(self) -> None:
        validate_step_id(self.step_id, "step_id")
        validate_step_id(self.state_name, KEY_STATE_NAME)
        effect = _wrap_clean_str(self.effect_kind, KEY_EFFECT_KIND, max_bytes=64)
        if effect not in ALLOWED_EFFECTS:
            raise RestartValidationError(f"unsupported effect_kind: {effect!r}")
        se = validate_bool(self.side_effecting, KEY_SIDE_EFFECTING)
        if effect not in PURE_IDEMPOTENT_EFFECTS and not se:
            raise RestartValidationError(ERR_MUTATING_MUST_BE_SE)
        if not isinstance(self.depends_on, tuple):
            raise RestartValidationError("depends_on must be tuple[str, ...]")
        for dep in self.depends_on:
            validate_step_id(dep, KEY_DEPENDS_ON)
        if len(set(self.depends_on)) != len(self.depends_on):
            raise RestartValidationError("duplicate depends_on entry")
        try:
            parse_strict_int(
                self.max_attempts, KEY_MAX_ATTEMPTS, min_val=1, max_val=MAX_STEP_ATTEMPTS
            )
        except ValueError as exc:
            raise RestartValidationError(str(exc)) from exc

    def to_payload_dict(self) -> dict[str, Any]:
        return {
            KEY_DEPENDS_ON: list(self.depends_on),
            KEY_EFFECT_KIND: self.effect_kind,
            KEY_MAX_ATTEMPTS: self.max_attempts,
            KEY_SIDE_EFFECTING: self.side_effecting,
            KEY_STATE_NAME: self.state_name,
            "step_id": self.step_id,
        }


def _build_dag_adjacency(
    steps: Sequence[StepSpec],
) -> tuple[dict[str, int], dict[str, list[str]]]:
    by_id: dict[str, StepSpec] = {}
    for spec in steps:
        if not isinstance(spec, StepSpec):
            raise RestartValidationError("expected StepSpec")
        if spec.step_id in by_id:
            raise RestartValidationError(f"duplicate step_id: {spec.step_id}")
        by_id[spec.step_id] = spec
    in_degree = dict.fromkeys(by_id, 0)
    children: dict[str, list[str]] = {sid: [] for sid in by_id}
    for spec in steps:
        for dep in spec.depends_on:
            if dep not in by_id or dep == spec.step_id:
                raise RestartValidationError(f"invalid dependency {dep!r} on {spec.step_id!r}")
            in_degree[spec.step_id] += 1
            children[dep].append(spec.step_id)
    return in_degree, children


def validate_step_dag(steps: Sequence[StepSpec]) -> tuple[StepSpec, ...]:
    """Validate bounded non-empty acyclic DAG of StepSpecs."""
    if not steps or len(steps) > MAX_STEPS_PER_RUN:
        raise RestartValidationError(f"steps count must be 1..{MAX_STEPS_PER_RUN}")
    in_degree, children = _build_dag_adjacency(steps)
    queue: deque[str] = deque(sid for sid, deg in in_degree.items() if deg == 0)
    visited = 0
    while queue:
        cur = queue.popleft()
        visited += 1
        for nxt in children[cur]:
            in_degree[nxt] -= 1
            if in_degree[nxt] == 0:
                queue.append(nxt)
    if visited != len(in_degree):
        raise RestartValidationError("cyclic_step_dag")
    return tuple(steps)


@dataclass(frozen=True)
class StepDefinition:
    """Immutable step definition stored in workflow_steps."""

    step_id: str
    step_order: int
    state_name: str
    effect_kind: str
    side_effecting: bool
    depends_on: tuple[str, ...]
    max_attempts: int


@dataclass(frozen=True)
class StepLeaseToken:
    run_id: str
    step_id: str
    attempt_no: int
    lease_epoch: int
    idempotency_key: str

    def __post_init__(self) -> None:
        validate_opaque_id(self.run_id, "run_id")
        validate_step_id(self.step_id, "step_id")
        validate_int64(self.attempt_no, KEY_ATTEMPT_NO, min_val=1)
        validate_int64(self.lease_epoch, KEY_LEASE_EPOCH, min_val=1)
        validate_opaque_id(self.idempotency_key, KEY_IDEM_KEY)


@dataclass(frozen=True)
class CreateRunRequest:
    run_id: str
    workflow_id: str
    spec_digest: str
    workflow_plan_digest: str
    grant_generation: int
    steps: tuple[StepSpec, ...]
    clock: ClockSnapshot
    requires_authority: bool = False

    def __post_init__(self) -> None:
        validate_opaque_id(self.run_id, "run_id")
        validate_opaque_id(self.workflow_id, KEY_WORKFLOW_ID)
        validate_sha256_hex(self.spec_digest, KEY_SPEC_DIGEST)
        validate_sha256_hex(self.workflow_plan_digest, KEY_WORKFLOW_PLAN_DIGEST)
        validate_int64(self.grant_generation, KEY_GRANT_GENERATION, min_val=1)
        validate_step_dag(self.steps)
        clock_to_wall_us(self.clock)
        validate_bool(self.requires_authority, KEY_REQUIRES_AUTHORITY)


@dataclass(frozen=True)
class CompleteStepRequest:
    token: StepLeaseToken
    output_digest: str
    clock: ClockSnapshot

    def __post_init__(self) -> None:
        if not isinstance(self.token, StepLeaseToken):
            raise RestartValidationError("token must be StepLeaseToken")
        validate_sha256_hex(self.output_digest, KEY_OUTPUT_DIGEST)
        clock_to_wall_us(self.clock)


@dataclass(frozen=True)
class FailStepRequest:
    token: StepLeaseToken
    reason: str
    retryable: bool
    uncertain: bool
    clock: ClockSnapshot

    def __post_init__(self) -> None:
        if not isinstance(self.token, StepLeaseToken):
            raise RestartValidationError("token must be StepLeaseToken")
        validate_reason(self.reason, KEY_REASON)
        ret = validate_bool(self.retryable, "retryable")
        unc = validate_bool(self.uncertain, "uncertain")
        if ret and unc:
            raise RestartValidationError("retryable and uncertain cannot both be True")
        clock_to_wall_us(self.clock)


TrackerOutcome = Literal["no_effect", "effect_applied", "still_pending"]


@dataclass(frozen=True)
class EffectTrackerReceipt:
    run_id: str
    step_id: str
    attempt_no: int
    lease_epoch: int
    idempotency_key: str
    tracker_outcome: TrackerOutcome
    attempt_fenced: bool
    output_digest: str | None
    receipt_digest: str

    def __post_init__(self) -> None:
        validate_opaque_id(self.run_id, "run_id")
        validate_step_id(self.step_id, "step_id")
        validate_int64(self.attempt_no, KEY_ATTEMPT_NO, min_val=1)
        validate_int64(self.lease_epoch, KEY_LEASE_EPOCH, min_val=1)
        validate_opaque_id(self.idempotency_key, KEY_IDEM_KEY)
        if self.tracker_outcome not in (
            OUTCOME_NO_EFFECT,
            OUTCOME_EFFECT_APPLIED,
            OUTCOME_STILL_PENDING,
        ):
            raise RestartValidationError("invalid tracker_outcome")
        validate_bool(self.attempt_fenced, "attempt_fenced")
        if self.tracker_outcome == OUTCOME_EFFECT_APPLIED:
            validate_sha256_hex(self.output_digest, KEY_OUTPUT_DIGEST)
        elif self.output_digest is not None:
            raise RestartValidationError("output_digest only allowed when effect_applied")
        validate_sha256_hex(self.receipt_digest, "receipt_digest")


@dataclass(frozen=True)
class ReconcileStepRequest:
    run_id: str
    step_id: str
    expected_attempt_no: int
    expected_epoch: int
    reconciliation_key: str
    resolution: ReconcileResolution
    output_digest: str | None
    evidence_digest: str
    reason: str
    clock: ClockSnapshot

    def __post_init__(self) -> None:
        validate_opaque_id(self.run_id, "run_id")
        validate_step_id(self.step_id, "step_id")
        validate_int64(self.expected_attempt_no, "expected_attempt_no", min_val=1)
        validate_int64(self.expected_epoch, "expected_epoch", min_val=1)
        validate_opaque_id(self.reconciliation_key, KEY_RECON_KEY)
        if not isinstance(self.resolution, ReconcileResolution):
            raise RestartValidationError("resolution must be ReconcileResolution")
        if self.resolution is ReconcileResolution.COMPLETED:
            validate_sha256_hex(self.output_digest, KEY_OUTPUT_DIGEST)
        elif self.output_digest is not None:
            raise RestartValidationError("output_digest must be None unless resolution=completed")
        validate_sha256_hex(self.evidence_digest, KEY_EVIDENCE_DIGEST)
        validate_reason(self.reason, KEY_REASON)
        clock_to_wall_us(self.clock)


@dataclass(frozen=True)
class HeartbeatAck:
    run_id: str
    step_id: str
    attempt_no: int
    lease_epoch: int
    supervisor_epoch: int


@dataclass(frozen=True)
class StepAckResult:
    run_id: str
    step_id: str
    status: str
    attempt_no: int
    lease_epoch: int
    duplicate: bool
    seq: int


@dataclass(frozen=True)
class ReconciliationReceipt:
    run_id: str
    step_id: str
    attempt_no: int
    reconciled_epoch: int
    reconciliation_key: str
    resolution: ReconcileResolution
    output_digest: str | None
    evidence_digest: str
    reason: str
    duplicate: bool
    seq: int


@dataclass(frozen=True)
class RecoveryReport:
    supervisor_epoch: int
    prior_epoch: int
    dirty_recovery: bool
    last_event_seq: int
    head_hash: str
    fenced_requeued: tuple[tuple[str, str, int], ...]
    fenced_uncertain: tuple[tuple[str, str, int], ...]
    fenced_failed: tuple[tuple[str, str, int], ...]


WorkerOutcome = Literal[
    "completed", "failed_retryable", "failed_terminal", "failed_uncertain"
]


@dataclass(frozen=True)
class WorkerStepResult:
    outcome: WorkerOutcome
    output_digest: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.outcome not in (
            WORKER_COMPLETED,
            WORKER_FAILED_RETRYABLE,
            WORKER_FAILED_TERMINAL,
            WORKER_FAILED_UNCERTAIN,
        ):
            raise RestartValidationError("invalid worker outcome")
        if self.outcome == WORKER_COMPLETED:
            validate_sha256_hex(self.output_digest, KEY_OUTPUT_DIGEST)
        else:
            validate_reason(self.reason, KEY_REASON)


@dataclass(frozen=True)
class StepExecutionOutcome:
    token: StepLeaseToken
    ack: StepAckResult


@dataclass(frozen=True)
class SupervisorMetaRecord:
    current_epoch: int
    last_event_seq: int
    head_hash: str
    dirty_shutdown: int
    updated_at_us: int
    journal_id: str = "jnl_00000000000000000000000000000000"


@dataclass(frozen=True)
class WorkflowRunRecord:
    run_id: str
    workflow_id: str
    spec_digest: str
    workflow_plan_digest: str
    grant_generation: int
    requires_authority: bool
    status: RunStatus
    cancel_requested: bool
    created_epoch: int
    created_at_us: int
    updated_at_us: int


@dataclass(frozen=True)
class WorkflowStepRecord:
    run_id: str
    definition: StepDefinition
    status: StepStatus
    attempt_no: int
    lease_epoch: int
    idempotency_key: str | None
    output_digest: str | None
    failure_reason: str | None
    updated_at_us: int

    @property
    def step_id(self) -> str:
        return self.definition.step_id

    @property
    def step_order(self) -> int:
        return self.definition.step_order

    @property
    def state_name(self) -> str:
        return self.definition.state_name

    @property
    def effect_kind(self) -> str:
        return self.definition.effect_kind

    @property
    def side_effecting(self) -> bool:
        return self.definition.side_effecting

    @property
    def depends_on(self) -> tuple[str, ...]:
        return self.definition.depends_on

    @property
    def max_attempts(self) -> int:
        return self.definition.max_attempts


@dataclass(frozen=True)
class StepIdempotencyRecord:
    run_id: str
    idempotency_key: str
    step_id: str
    attempt_no: int
    lease_epoch: int
    outcome_status: IdempotencyOutcome
    output_digest: str | None
    failure_reason: str | None
    recorded_seq: int


@dataclass(frozen=True)
class StepReconciliationRecord:
    run_id: str
    reconciliation_key: str
    step_id: str
    attempt_no: int
    reconciled_epoch: int
    resolution: ReconcileResolution
    output_digest: str | None
    evidence_digest: str
    reason: str
    recorded_seq: int


@dataclass(frozen=True)
class JournalEvent:
    seq: int
    supervisor_epoch: int
    event_type: EventType
    run_id: str | None
    step_id: str | None
    payload: Mapping[str, Any]
    created_at_us: int
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True)
class ReplayedSnapshot:
    supervisor_epoch: int
    last_event_seq: int
    head_hash: str
    dirty_shutdown: int
    meta_updated_at_us: int
    runs: Mapping[str, WorkflowRunRecord]
    steps: Mapping[tuple[str, str], WorkflowStepRecord]
    idempotency_records: Mapping[tuple[str, str], StepIdempotencyRecord]
    reconciliation_records: Mapping[tuple[str, str], StepReconciliationRecord]
    journal_id: str = ""


# --- Pure DAG-aware run status derivation ---


def _has_blocked_ancestor(
    step_id: str,
    steps: Mapping[str, WorkflowStepRecord],
    memo: dict[str, bool],
) -> bool:
    cached = memo.get(step_id)
    if cached is not None:
        return cached
    blocked = False
    for dep_id in steps[step_id].depends_on:
        dep = steps[dep_id]
        if dep.status in (StepStatus.FAILED_TERMINAL, StepStatus.CANCELLED):
            blocked = True
            break
        if _has_blocked_ancestor(dep_id, steps, memo):
            blocked = True
            break
    memo[step_id] = blocked
    return blocked


def compute_run_status(
    steps: Mapping[str, WorkflowStepRecord],
    *,
    cancel_requested: bool,
) -> RunStatus:
    """Pure DAG-aware run status shared by SQLite mutations and reduce_event_log()."""
    statuses = {step.status for step in steps.values()}
    if StepStatus.UNCERTAIN_NEEDS_RECONCILE in statuses:
        return RunStatus.PAUSED_NEEDS_RECONCILE
    if cancel_requested:
        return RunStatus.CANCELLED
    if StepStatus.LEASED in statuses:
        return RunStatus.RUNNING
    memo: dict[str, bool] = {}
    has_runnable = any(
        step.status is StepStatus.PENDING
        and not _has_blocked_ancestor(step_id, steps, memo)
        for step_id, step in steps.items()
    )
    if has_runnable:
        return RunStatus.RUNNING
    if StepStatus.FAILED_TERMINAL in statuses:
        return RunStatus.FAILED
    if statuses == {StepStatus.COMPLETED}:
        return RunStatus.COMPLETED
    return RunStatus.CANCELLED


# --- Canonical plan step-graph derivation ---


def _pick_state_effect(state: Any, reachable: frozenset[str]) -> str:
    if (
        len(state.effects) > 1
        or state.shape == "wait_signal"
        or "wait_signal" in state.effects
    ):
        raise RestartPolicyError(ERR_PLAN_GRAPH_UNSUPPORTED)
    if state.shape != "observe" and state.shape not in _STATE_SHAPE_IMPLIED_EFFECTS:
        raise RestartPolicyError(ERR_PLAN_GRAPH_UNSUPPORTED)
    combined: set[str] = set(state.effects)
    combined.update(_STATE_SHAPE_IMPLIED_EFFECTS.get(state.shape, ()))
    if state.factory_id is not None:
        combined.add("invoke_factory")
    if not combined:
        chosen = EFFECT_READ_METRICS
    elif len(combined) == 1:
        chosen = next(iter(combined))
    else:
        raise RestartPolicyError(ERR_PLAN_GRAPH_UNSUPPORTED)
    if chosen not in reachable:
        raise RestartPolicyError(ERR_PLAN_GRAPH_UNSUPPORTED)
    return chosen


def _build_plan_deps_map(spec: Any, state_names: Sequence[str]) -> dict[str, list[str]]:
    state_set = set(state_names)
    deps_map: dict[str, list[str]] = {name: [] for name in state_names}
    for tr in spec.transitions:
        if tr.predicate is not None or tr.effects:
            raise RestartPolicyError(ERR_PLAN_GRAPH_UNSUPPORTED)
        if tr.src not in state_set or tr.dst not in state_set or tr.src == tr.dst:
            raise RestartPolicyError(ERR_PLAN_GRAPH_UNSUPPORTED)
        if tr.src in deps_map[tr.dst]:
            raise RestartPolicyError(ERR_PLAN_GRAPH_UNSUPPORTED)
        deps_map[tr.dst].append(tr.src)
    return deps_map


def derive_steps_from_plan(plan: CompiledWorkflowPlan) -> tuple[StepSpec, ...]:
    """Derive the canonical acyclic StepSpec DAG strictly from an admitted CompiledWorkflowPlan."""
    spec = plan.spec
    if not spec.states or spec.timers or spec.signal_handlers:
        raise RestartPolicyError(ERR_PLAN_GRAPH_UNSUPPORTED)
    reachable = compute_reachable_effects(spec)
    state_names = [st.name for st in spec.states]
    deps_map = _build_plan_deps_map(spec, state_names)
    derived: list[StepSpec] = []
    for st in spec.states:
        effect = _pick_state_effect(st, reachable)
        se = effect not in PURE_IDEMPOTENT_EFFECTS
        derived.append(
            StepSpec(
                step_id=st.name,
                state_name=st.name,
                effect_kind=effect,
                side_effecting=se,
                depends_on=tuple(deps_map[st.name]),
                max_attempts=DEFAULT_STEP_MAX_ATTEMPTS,
            )
        )
    try:
        return validate_step_dag(derived)
    except RestartValidationError as exc:
        raise RestartPolicyError(ERR_PLAN_GRAPH_UNSUPPORTED) from exc


# --- Pure deterministic replay reducer & parity verification ---


@dataclass
class _MutableReplayState:
    journal_id: str = ""
    epoch: int = 0
    last_seq: int = 0
    head_hash: str = EVENT_GENESIS_HASH
    dirty_shutdown: int = 1
    meta_updated_at_us: int = 0
    runs: dict[str, WorkflowRunRecord] = field(default_factory=dict)
    steps: dict[tuple[str, str], WorkflowStepRecord] = field(default_factory=dict)
    steps_by_run: dict[str, list[str]] = field(default_factory=dict)
    idempotency_records: dict[tuple[str, str], StepIdempotencyRecord] = field(
        default_factory=dict
    )
    reconciliation_records: dict[tuple[str, str], StepReconciliationRecord] = field(
        default_factory=dict
    )
    pending_recovery_queue: deque[tuple[str, str]] = field(default_factory=deque)


def _require_replay(cond: bool, msg: str) -> None:
    if not cond:
        raise ReplayMismatchError(msg)


def _run_steps_map(
    state: _MutableReplayState, run_id: str
) -> dict[str, WorkflowStepRecord]:
    return {
        sid: state.steps[(run_id, sid)]
        for sid in state.steps_by_run.get(run_id, ())
    }


def _refresh_run_status(
    state: _MutableReplayState, run_id: str, updated_at_us: int
) -> None:
    run = state.runs[run_id]
    new_status = compute_run_status(
        _run_steps_map(state, run_id), cancel_requested=run.cancel_requested
    )
    state.runs[run_id] = replace(run, status=new_status, updated_at_us=updated_at_us)


_STARTED_PAYLOAD_KEYS = frozenset({KEY_DIRTY_RECOVERY, KEY_JOURNAL_ID, KEY_PRIOR_EPOCH})
_RUN_CREATED_PAYLOAD_KEYS = frozenset(
    {
        KEY_GRANT_GENERATION,
        KEY_REQUIRES_AUTHORITY,
        KEY_SPEC_DIGEST,
        "steps",
        KEY_WORKFLOW_ID,
        KEY_WORKFLOW_PLAN_DIGEST,
    }
)
_STEP_PAYLOAD_KEYS = frozenset(
    {
        "step_id",
        KEY_STATE_NAME,
        KEY_EFFECT_KIND,
        KEY_SIDE_EFFECTING,
        KEY_DEPENDS_ON,
        KEY_MAX_ATTEMPTS,
    }
)
_STEP_LEASED_PAYLOAD_KEYS = frozenset(
    {KEY_ATTEMPT_NO, KEY_IDEM_KEY, KEY_LEASE_EPOCH, KEY_SIDE_EFFECTING}
)
_STEP_COMPLETED_PAYLOAD_KEYS = frozenset(
    {KEY_ATTEMPT_NO, KEY_IDEM_KEY, KEY_LEASE_EPOCH, KEY_OUTPUT_DIGEST}
)
_STEP_FAIL_PAYLOAD_KEYS = frozenset({KEY_ATTEMPT_NO, KEY_REASON, KEY_VIA_RECOVERY})
_STEP_RECONCILED_PAYLOAD_KEYS = frozenset(
    {
        KEY_ATTEMPT_NO,
        KEY_EVIDENCE_DIGEST,
        KEY_OUTPUT_DIGEST,
        KEY_REASON,
        KEY_RECON_KEY,
        KEY_RESOLUTION,
    }
)
_RUN_CANCELLED_PAYLOAD_KEYS = frozenset({KEY_REASON})


def _require_payload_keys(
    payload: Mapping[str, Any], expected: frozenset[str], msg: str
) -> None:
    if not isinstance(payload, Mapping) or set(payload.keys()) != expected:
        raise ReplayMismatchError(msg)


def _update_idem_for_step(
    state: _MutableReplayState,
    step: WorkflowStepRecord,
    *,
    outcome: IdempotencyOutcome,
    output_digest: str | None,
    failure_reason: str | None,
    recorded_seq: int,
) -> None:
    if step.idempotency_key is None:
        raise ReplayMismatchError("missing_step_idem_key")
    key = (step.run_id, step.idempotency_key)
    existing = state.idempotency_records.get(key)
    if existing is None:
        raise ReplayMismatchError("missing_idempotency_record")
    state.idempotency_records[key] = replace(
        existing,
        outcome_status=outcome,
        output_digest=output_digest,
        failure_reason=failure_reason,
        recorded_seq=recorded_seq,
    )


def _apply_supervisor_started(state: _MutableReplayState, event: JournalEvent) -> None:
    _require_replay(event.run_id is None and event.step_id is None, "started_scope_invalid")
    payload = event.payload
    _require_payload_keys(payload, _STARTED_PAYLOAD_KEYS, "started_payload_keys_invalid")
    dirty_val = validate_bool(payload[KEY_DIRTY_RECOVERY], KEY_DIRTY_RECOVERY)
    prior_ep = validate_int64(payload[KEY_PRIOR_EPOCH], KEY_PRIOR_EPOCH, min_val=0)
    jid = validate_opaque_id(payload[KEY_JOURNAL_ID], KEY_JOURNAL_ID)
    if event.seq == 1:
        _require_replay(
            event.supervisor_epoch == 1 and not dirty_val and prior_ep == 0,
            "invalid_genesis_started_event",
        )
        state.journal_id = jid
    else:
        _require_replay(
            len(state.pending_recovery_queue) == 0, ERR_UNFENCED_LEASE
        )
        _require_replay(
            event.supervisor_epoch == state.epoch + 1
            and prior_ep == state.epoch
            and dirty_val is (state.dirty_shutdown == 1)
            and jid == state.journal_id,
            "invalid_supervisor_started_transition",
        )
    state.dirty_shutdown = 1
    leased_prior = [
        step
        for step in state.steps.values()
        if step.status is StepStatus.LEASED and step.lease_epoch < event.supervisor_epoch
    ]
    leased_prior.sort(key=lambda s: (s.run_id, s.step_order, s.step_id))
    state.pending_recovery_queue = deque((s.run_id, s.step_id) for s in leased_prior)


def _apply_supervisor_stopped(state: _MutableReplayState, event: JournalEvent) -> None:
    _require_replay(event.run_id is None and event.step_id is None, "stopped_scope_invalid")
    _require_payload_keys(event.payload, frozenset(), "stopped_payload_invalid")
    state.dirty_shutdown = 0


def _decode_run_created_step(item: Any) -> StepSpec:
    if not isinstance(item, dict):
        raise ReplayMismatchError("run_created_step_not_dict")
    _require_payload_keys(item, _STEP_PAYLOAD_KEYS, "run_created_step_keys_invalid")
    raw_deps = item[KEY_DEPENDS_ON]
    if not isinstance(raw_deps, list):
        raise ReplayMismatchError("run_created_depends_not_list")
    return StepSpec(
        step_id=item["step_id"],
        state_name=item[KEY_STATE_NAME],
        effect_kind=item[KEY_EFFECT_KIND],
        side_effecting=item[KEY_SIDE_EFFECTING],
        depends_on=tuple(raw_deps),
        max_attempts=item[KEY_MAX_ATTEMPTS],
    )


def _apply_run_created(state: _MutableReplayState, event: JournalEvent) -> None:
    _require_replay(event.run_id is not None and event.step_id is None, "run_created_scope")
    run_id = str(event.run_id)
    _require_replay(run_id not in state.runs, "duplicate_run_id")
    _require_replay(len(state.runs) < MAX_RUNS, ERR_MAX_RUNS)
    p = event.payload
    _require_payload_keys(p, _RUN_CREATED_PAYLOAD_KEYS, "run_created_payload_keys_invalid")
    raw_steps = p["steps"]
    _require_replay(isinstance(raw_steps, list), "run_created_steps_invalid")
    specs = tuple(_decode_run_created_step(item) for item in raw_steps)
    validate_step_dag(specs)
    state.runs[run_id] = WorkflowRunRecord(
        run_id=run_id,
        workflow_id=validate_opaque_id(p[KEY_WORKFLOW_ID], KEY_WORKFLOW_ID),
        spec_digest=validate_sha256_hex(p[KEY_SPEC_DIGEST], KEY_SPEC_DIGEST),
        workflow_plan_digest=validate_sha256_hex(
            p[KEY_WORKFLOW_PLAN_DIGEST], KEY_WORKFLOW_PLAN_DIGEST
        ),
        grant_generation=validate_int64(
            p[KEY_GRANT_GENERATION], KEY_GRANT_GENERATION, min_val=1
        ),
        requires_authority=validate_bool(
            p[KEY_REQUIRES_AUTHORITY], KEY_REQUIRES_AUTHORITY
        ),
        status=RunStatus.RUNNING,
        cancel_requested=False,
        created_epoch=event.supervisor_epoch,
        created_at_us=event.created_at_us,
        updated_at_us=event.created_at_us,
    )
    state.steps_by_run[run_id] = [spec.step_id for spec in specs]
    for order, spec in enumerate(specs):
        defn = StepDefinition(
            step_id=spec.step_id,
            step_order=order,
            state_name=spec.state_name,
            effect_kind=spec.effect_kind,
            side_effecting=spec.side_effecting,
            depends_on=spec.depends_on,
            max_attempts=spec.max_attempts,
        )
        state.steps[(run_id, spec.step_id)] = WorkflowStepRecord(
            run_id=run_id,
            definition=defn,
            status=StepStatus.PENDING,
            attempt_no=0,
            lease_epoch=0,
            idempotency_key=None,
            output_digest=None,
            failure_reason=None,
            updated_at_us=event.created_at_us,
        )


def _get_step_for_event(
    state: _MutableReplayState, event: JournalEvent
) -> WorkflowStepRecord:
    _require_replay(event.run_id is not None and event.step_id is not None, "step_event_scope")
    key = (str(event.run_id), str(event.step_id))
    step = state.steps.get(key)
    if step is None:
        raise ReplayMismatchError("unknown_step_in_event")
    return step


def _apply_step_leased(state: _MutableReplayState, event: JournalEvent) -> None:
    step = _get_step_for_event(state, event)
    run = state.runs[step.run_id]
    _require_replay(
        run.status is RunStatus.RUNNING and not run.cancel_requested,
        "lease_on_non_running_run",
    )
    _require_replay(step.status is StepStatus.PENDING, "lease_on_non_pending_step")
    for dep in step.depends_on:
        _require_replay(
            state.steps[(step.run_id, dep)].status is StepStatus.COMPLETED,
            "lease_dependency_unmet",
        )
    p = event.payload
    _require_payload_keys(p, _STEP_LEASED_PAYLOAD_KEYS, "step_leased_payload_keys_invalid")
    attempt_no = validate_int64(p[KEY_ATTEMPT_NO], KEY_ATTEMPT_NO, min_val=1)
    lease_epoch = validate_int64(p[KEY_LEASE_EPOCH], KEY_LEASE_EPOCH, min_val=1)
    idem_key = validate_opaque_id(p[KEY_IDEM_KEY], KEY_IDEM_KEY)
    side_eff = validate_bool(p[KEY_SIDE_EFFECTING], KEY_SIDE_EFFECTING)
    _require_replay(
        attempt_no == step.attempt_no + 1
        and attempt_no <= step.max_attempts
        and lease_epoch == event.supervisor_epoch
        and side_eff is step.side_effecting,
        "invalid_step_leased_payload",
    )
    idem_pk = (step.run_id, idem_key)
    _require_replay(idem_pk not in state.idempotency_records, ERR_IDEM_CONFLICT)
    state.steps[(step.run_id, step.step_id)] = replace(
        step,
        status=StepStatus.LEASED,
        attempt_no=attempt_no,
        lease_epoch=lease_epoch,
        idempotency_key=idem_key,
        output_digest=None,
        failure_reason=None,
        updated_at_us=event.created_at_us,
    )
    state.idempotency_records[idem_pk] = StepIdempotencyRecord(
        run_id=step.run_id,
        idempotency_key=idem_key,
        step_id=step.step_id,
        attempt_no=attempt_no,
        lease_epoch=lease_epoch,
        outcome_status=IdempotencyOutcome.LEASED,
        output_digest=None,
        failure_reason=None,
        recorded_seq=event.seq,
    )
    _refresh_run_status(state, step.run_id, event.created_at_us)


def _require_settleable_run(state: _MutableReplayState, run_id: str) -> None:
    run = state.runs[run_id]
    _require_replay(
        run.status in (RunStatus.RUNNING, RunStatus.PAUSED_NEEDS_RECONCILE)
        and not run.cancel_requested,
        "settle_on_non_active_run",
    )


def _apply_step_completed(state: _MutableReplayState, event: JournalEvent) -> None:
    step = _get_step_for_event(state, event)
    _require_settleable_run(state, step.run_id)
    _require_replay(step.status is StepStatus.LEASED, "complete_on_non_leased_step")
    p = event.payload
    _require_payload_keys(
        p, _STEP_COMPLETED_PAYLOAD_KEYS, "step_completed_payload_keys_invalid"
    )
    attempt_no = validate_int64(p[KEY_ATTEMPT_NO], KEY_ATTEMPT_NO, min_val=1)
    lease_epoch = validate_int64(p[KEY_LEASE_EPOCH], KEY_LEASE_EPOCH, min_val=1)
    idem_key = validate_opaque_id(p[KEY_IDEM_KEY], KEY_IDEM_KEY)
    out_digest = validate_sha256_hex(p[KEY_OUTPUT_DIGEST], KEY_OUTPUT_DIGEST)
    _require_replay(
        attempt_no == step.attempt_no
        and lease_epoch == step.lease_epoch == event.supervisor_epoch
        and idem_key == step.idempotency_key,
        "complete_token_mismatch",
    )
    updated = cast(
        WorkflowStepRecord,
        replace(
            step,
            status=StepStatus.COMPLETED,
            output_digest=out_digest,
            failure_reason=None,
            updated_at_us=event.created_at_us,
        ),
    )
    state.steps[(step.run_id, step.step_id)] = updated
    _update_idem_for_step(
        state,
        updated,
        outcome=IdempotencyOutcome.COMPLETED,
        output_digest=out_digest,
        failure_reason=None,
        recorded_seq=event.seq,
    )
    _refresh_run_status(state, step.run_id, event.created_at_us)


def _parse_step_fail_payload(payload: Mapping[str, Any]) -> tuple[int, str, bool]:
    _require_payload_keys(payload, _STEP_FAIL_PAYLOAD_KEYS, "step_fail_payload_keys_invalid")
    attempt_no = validate_int64(payload[KEY_ATTEMPT_NO], KEY_ATTEMPT_NO, min_val=1)
    reason = validate_reason(payload[KEY_REASON], KEY_REASON)
    via_recovery = validate_bool(payload[KEY_VIA_RECOVERY], KEY_VIA_RECOVERY)
    return attempt_no, reason, via_recovery


def _apply_step_failed_terminal(state: _MutableReplayState, event: JournalEvent) -> None:
    step = _get_step_for_event(state, event)
    _require_replay(step.status is StepStatus.LEASED, "fail_on_non_leased_step")
    attempt_no, reason, via_recovery = _parse_step_fail_payload(event.payload)
    _require_replay(attempt_no == step.attempt_no, "fail_attempt_mismatch")
    if via_recovery:
        _require_replay(
            step.lease_epoch < event.supervisor_epoch
            and not step.side_effecting
            and step.attempt_no >= step.max_attempts,
            "invalid_recovery_fail_terminal",
        )
    else:
        _require_settleable_run(state, step.run_id)
        _require_replay(
            step.lease_epoch == event.supervisor_epoch, "fail_epoch_mismatch"
        )
    updated = cast(
        WorkflowStepRecord,
        replace(
            step,
            status=StepStatus.FAILED_TERMINAL,
            output_digest=None,
            failure_reason=reason,
            updated_at_us=event.created_at_us,
        ),
    )
    state.steps[(step.run_id, step.step_id)] = updated
    _update_idem_for_step(
        state,
        updated,
        outcome=IdempotencyOutcome.FAILED_TERMINAL,
        output_digest=None,
        failure_reason=reason,
        recorded_seq=event.seq,
    )
    _refresh_run_status(state, step.run_id, event.created_at_us)


def _apply_step_requeued(state: _MutableReplayState, event: JournalEvent) -> None:
    step = _get_step_for_event(state, event)
    _require_replay(step.status is StepStatus.LEASED, "requeue_on_non_leased_step")
    _require_replay(
        not step.side_effecting and step.attempt_no < step.max_attempts,
        "invalid_requeue_step",
    )
    attempt_no, reason, via_recovery = _parse_step_fail_payload(event.payload)
    _require_replay(attempt_no == step.attempt_no, "requeue_attempt_mismatch")
    if via_recovery:
        _require_replay(step.lease_epoch < event.supervisor_epoch, "requeue_epoch_invalid")
    else:
        run = state.runs[step.run_id]
        _require_replay(
            run.status is RunStatus.RUNNING and not run.cancel_requested,
            "requeue_on_non_running_run",
        )
        _require_replay(step.lease_epoch == event.supervisor_epoch, "requeue_epoch_invalid")
    _update_idem_for_step(
        state,
        step,
        outcome=IdempotencyOutcome.REQUEUED_PENDING,
        output_digest=None,
        failure_reason=reason,
        recorded_seq=event.seq,
    )
    state.steps[(step.run_id, step.step_id)] = replace(
        step,
        status=StepStatus.PENDING,
        output_digest=None,
        failure_reason=reason,
        updated_at_us=event.created_at_us,
    )
    _refresh_run_status(state, step.run_id, event.created_at_us)


def _apply_step_marked_uncertain(state: _MutableReplayState, event: JournalEvent) -> None:
    step = _get_step_for_event(state, event)
    _require_replay(
        step.status is StepStatus.LEASED and step.side_effecting,
        "uncertain_requires_leased_side_effecting",
    )
    attempt_no, reason, via_recovery = _parse_step_fail_payload(event.payload)
    _require_replay(attempt_no == step.attempt_no, "uncertain_attempt_mismatch")
    if via_recovery:
        _require_replay(step.lease_epoch < event.supervisor_epoch, "uncertain_epoch_invalid")
    else:
        _require_settleable_run(state, step.run_id)
        _require_replay(step.lease_epoch == event.supervisor_epoch, "uncertain_epoch_invalid")
    updated = cast(
        WorkflowStepRecord,
        replace(
            step,
            status=StepStatus.UNCERTAIN_NEEDS_RECONCILE,
            output_digest=None,
            failure_reason=reason,
            updated_at_us=event.created_at_us,
        ),
    )
    state.steps[(step.run_id, step.step_id)] = updated
    _update_idem_for_step(
        state,
        updated,
        outcome=IdempotencyOutcome.UNCERTAIN_NEEDS_RECONCILE,
        output_digest=None,
        failure_reason=reason,
        recorded_seq=event.seq,
    )
    _refresh_run_status(state, step.run_id, event.created_at_us)


_RECONCILE_STATUS_MAP: Mapping[
    ReconcileResolution, tuple[StepStatus, IdempotencyOutcome]
] = {
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


def _apply_step_reconciled(state: _MutableReplayState, event: JournalEvent) -> None:
    step = _get_step_for_event(state, event)
    run = state.runs[step.run_id]
    _require_replay(
        step.status is StepStatus.UNCERTAIN_NEEDS_RECONCILE,
        "reconcile_requires_uncertain",
    )
    p = event.payload
    _require_payload_keys(
        p, _STEP_RECONCILED_PAYLOAD_KEYS, "step_reconciled_payload_keys_invalid"
    )
    recon_key = validate_opaque_id(p[KEY_RECON_KEY], KEY_RECON_KEY)
    res_raw = p[KEY_RESOLUTION]
    _require_replay(isinstance(res_raw, str), "invalid_resolution")
    try:
        resolution = ReconcileResolution(str(res_raw))
    except ValueError as exc:
        raise ReplayMismatchError("invalid_resolution") from exc
    attempt_no = validate_int64(p[KEY_ATTEMPT_NO], KEY_ATTEMPT_NO, min_val=1)
    _require_replay(attempt_no == step.attempt_no, "reconcile_attempt_mismatch")
    if resolution is ReconcileResolution.REQUEUE_PENDING:
        _require_replay(
            not run.cancel_requested and step.attempt_no < step.max_attempts,
            ERR_CANNOT_REQUEUE,
        )
    out_digest = p[KEY_OUTPUT_DIGEST]
    if resolution is ReconcileResolution.COMPLETED:
        out_digest = validate_sha256_hex(out_digest, KEY_OUTPUT_DIGEST)
    else:
        _require_replay(out_digest is None, "reconcile_unexpected_output_digest")
    ev_digest = validate_sha256_hex(p[KEY_EVIDENCE_DIGEST], KEY_EVIDENCE_DIGEST)
    reason = validate_reason(p[KEY_REASON], KEY_REASON)
    recon_pk = (step.run_id, recon_key)
    _require_replay(recon_pk not in state.reconciliation_records, ERR_RECON_CONFLICT)

    new_step_status, new_idem_status = _RECONCILE_STATUS_MAP[resolution]
    idem_reason = None if resolution is ReconcileResolution.COMPLETED else reason
    _update_idem_for_step(
        state,
        step,
        outcome=new_idem_status,
        output_digest=out_digest,
        failure_reason=idem_reason,
        recorded_seq=event.seq,
    )
    state.steps[(step.run_id, step.step_id)] = replace(
        step,
        status=new_step_status,
        output_digest=out_digest,
        failure_reason=idem_reason,
        updated_at_us=event.created_at_us,
    )
    state.reconciliation_records[recon_pk] = StepReconciliationRecord(
        run_id=step.run_id,
        reconciliation_key=recon_key,
        step_id=step.step_id,
        attempt_no=step.attempt_no,
        reconciled_epoch=event.supervisor_epoch,
        resolution=resolution,
        output_digest=out_digest,
        evidence_digest=ev_digest,
        reason=reason,
        recorded_seq=event.seq,
    )
    _refresh_run_status(state, step.run_id, event.created_at_us)


def _cancel_step_in_replay(
    state: _MutableReplayState,
    step: WorkflowStepRecord,
    *,
    reason: str,
    event_seq: int,
    created_at_us: int,
) -> None:
    if step.status is StepStatus.PENDING:
        state.steps[(step.run_id, step.step_id)] = replace(
            step,
            status=StepStatus.CANCELLED,
            output_digest=None,
            failure_reason=reason,
            updated_at_us=created_at_us,
        )
        return
    if step.status is not StepStatus.LEASED:
        return
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
    updated = cast(
        WorkflowStepRecord,
        replace(
            step,
            status=new_st,
            output_digest=None,
            failure_reason=reason,
            updated_at_us=created_at_us,
        ),
    )
    state.steps[(step.run_id, step.step_id)] = updated
    _update_idem_for_step(
        state,
        updated,
        outcome=new_idem,
        output_digest=None,
        failure_reason=reason,
        recorded_seq=event_seq,
    )


def _apply_run_cancelled(state: _MutableReplayState, event: JournalEvent) -> None:
    _require_replay(event.run_id is not None and event.step_id is None, "cancel_scope")
    run_id = str(event.run_id)
    run = state.runs.get(run_id)
    if (
        run is None
        or run.status in TERMINAL_RUN_STATUSES
        or run.cancel_requested
    ):
        raise ReplayMismatchError("cancel_invalid_run_state")
    _require_payload_keys(
        event.payload, _RUN_CANCELLED_PAYLOAD_KEYS, "cancel_payload_keys_invalid"
    )
    reason = validate_reason(event.payload[KEY_REASON], KEY_REASON)
    run_steps = sorted(
        _run_steps_map(state, run_id).values(), key=lambda s: (s.step_order, s.step_id)
    )
    for step in run_steps:
        _cancel_step_in_replay(
            state,
            step,
            reason=reason,
            event_seq=event.seq,
            created_at_us=event.created_at_us,
        )
    state.runs[run_id] = replace(run, cancel_requested=True)
    _refresh_run_status(state, run_id, event.created_at_us)


def _check_recovery_drainage(state: _MutableReplayState, event: JournalEvent) -> None:
    if not state.pending_recovery_queue:
        return
    expected_pair = state.pending_recovery_queue[0]
    _require_replay(
        (event.run_id, event.step_id) == expected_pair, ERR_UNFENCED_LEASE
    )
    step = state.steps[expected_pair]
    if step.side_effecting:
        expected_type = EventType.STEP_MARKED_UNCERTAIN
    elif step.attempt_no < step.max_attempts:
        expected_type = EventType.STEP_REQUEUED_PENDING
    else:
        expected_type = EventType.STEP_FAILED_TERMINAL
    _require_replay(
        event.event_type is expected_type
        and event.payload.get(KEY_VIA_RECOVERY) is True,
        ERR_UNFENCED_LEASE,
    )
    state.pending_recovery_queue.popleft()


_EVENT_HANDLERS: Mapping[
    EventType, Callable[[_MutableReplayState, JournalEvent], None]
] = {
    EventType.SUPERVISOR_STARTED: _apply_supervisor_started,
    EventType.SUPERVISOR_STOPPED: _apply_supervisor_stopped,
    EventType.RUN_CREATED: _apply_run_created,
    EventType.STEP_LEASED: _apply_step_leased,
    EventType.STEP_COMPLETED: _apply_step_completed,
    EventType.STEP_FAILED_TERMINAL: _apply_step_failed_terminal,
    EventType.STEP_REQUEUED_PENDING: _apply_step_requeued,
    EventType.STEP_MARKED_UNCERTAIN: _apply_step_marked_uncertain,
    EventType.STEP_RECONCILED: _apply_step_reconciled,
    EventType.RUN_CANCELLED: _apply_run_cancelled,
}


def apply_event_strict(state: _MutableReplayState, event: JournalEvent) -> None:
    """Enforce all 4 epoch-lifecycle & recovery-drainage invariants and apply event."""
    if event.event_type is not EventType.SUPERVISOR_STARTED:
        _require_replay(event.seq > 1, "first_event_must_be_supervisor_started")
        _require_replay(
            event.supervisor_epoch == state.epoch and state.dirty_shutdown == 1,
            "event_outside_active_epoch",
        )
        _check_recovery_drainage(state, event)
    handler = _EVENT_HANDLERS.get(event.event_type)
    if handler is None:
        raise ReplayMismatchError("unknown_event_type")
    try:
        handler(state, event)
    except RestartValidationError as exc:
        raise ReplayMismatchError(str(exc)) from exc


def _check_replay_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise RestartStorageError(ERR_OP_DEADLINE)


def reduce_event_log(
    events: Sequence[JournalEvent],
    *,
    deadline: float | None = None,
) -> ReplayedSnapshot:
    """Pure deterministic replay from seq 0 verifying unbroken SHA-256 chain & lifecycle."""
    _check_replay_deadline(deadline)
    state = _MutableReplayState()
    for idx, event in enumerate(events):
        if idx % _REPLAY_DEADLINE_STRIDE == 0:
            _check_replay_deadline(deadline)
        _require_replay(event.seq == state.last_seq + 1, "event_seq_gap_or_order")
        if not hmac.compare_digest(event.prev_hash, state.head_hash):
            raise JournalIntegrityError(ERR_HASH_CHAIN_BROKEN)
        expected_hash = compute_event_hash(
            seq=event.seq,
            supervisor_epoch=event.supervisor_epoch,
            event_type=event.event_type.value,
            run_id=event.run_id,
            step_id=event.step_id,
            payload=event.payload,
            created_at_us=event.created_at_us,
            prev_hash=event.prev_hash,
        )
        if not hmac.compare_digest(event.entry_hash, expected_hash):
            raise JournalIntegrityError(ERR_ENTRY_HASH_MISMATCH)
        apply_event_strict(state, event)
        state.epoch = event.supervisor_epoch
        state.last_seq = event.seq
        state.head_hash = event.entry_hash
        state.meta_updated_at_us = event.created_at_us
    _check_replay_deadline(deadline)
    _require_replay(len(state.pending_recovery_queue) == 0, "incomplete_epoch_recovery")
    return ReplayedSnapshot(
        supervisor_epoch=state.epoch,
        last_event_seq=state.last_seq,
        head_hash=state.head_hash,
        dirty_shutdown=state.dirty_shutdown,
        meta_updated_at_us=state.meta_updated_at_us,
        runs=dict(state.runs),
        steps=dict(state.steps),
        idempotency_records=dict(state.idempotency_records),
        reconciliation_records=dict(state.reconciliation_records),
        journal_id=state.journal_id,
    )


def verify_materialized_parity(
    *,
    meta: SupervisorMetaRecord,
    replayed: ReplayedSnapshot,
    actual_runs: Mapping[str, WorkflowRunRecord],
    actual_steps: Mapping[tuple[str, str], WorkflowStepRecord],
    actual_idems: Mapping[tuple[str, str], StepIdempotencyRecord],
    actual_recons: Mapping[tuple[str, str], StepReconciliationRecord],
    deadline: float | None = None,
) -> None:
    """Unconditionally compare supervisor_meta and all 4 materialized tables against replay."""
    _check_replay_deadline(deadline)
    _require_replay(meta.last_event_seq >= 1, ERR_INVALID_META_SEQ)
    meta_tuple = (
        meta.current_epoch,
        meta.last_event_seq,
        meta.head_hash,
        meta.dirty_shutdown,
        meta.updated_at_us,
    )
    replayed_meta = (
        replayed.supervisor_epoch,
        replayed.last_event_seq,
        replayed.head_hash,
        replayed.dirty_shutdown,
        replayed.meta_updated_at_us,
    )
    _require_replay(meta_tuple == replayed_meta, ERR_MATERIALIZED_MISMATCH)
    _require_replay(meta.journal_id == replayed.journal_id, "meta_journal_id_mismatch")
    _check_replay_deadline(deadline)
    _require_replay(actual_runs == replayed.runs, ERR_MATERIALIZED_MISMATCH)
    _check_replay_deadline(deadline)
    _require_replay(actual_steps == replayed.steps, ERR_MATERIALIZED_MISMATCH)
    _check_replay_deadline(deadline)
    _require_replay(
        actual_idems == replayed.idempotency_records, ERR_MATERIALIZED_MISMATCH
    )
    _check_replay_deadline(deadline)
    _require_replay(
        actual_recons == replayed.reconciliation_records, ERR_MATERIALIZED_MISMATCH
    )
    _check_replay_deadline(deadline)


# --- External SyntheticEffectTracker (survives simulated supervisor crashes) ---


_AttemptKey = tuple[str, str, int, int, str]


@dataclass
class _AttemptRecord:
    status: str
    output_digest: str | None = None


class SyntheticEffectTracker:
    """External side-effect ledger surviving crashes, enforcing attempt admission & receipts."""

    def __init__(self, *, history_start_epoch: int = 1) -> None:
        start_ep = validate_int64(history_start_epoch, "history_start_epoch", min_val=1)
        self._lock = threading.Lock()
        self._history_start_epoch = start_ep
        self._attached = False
        self._bound_journal_id: str | None = None
        self._observed_epochs: set[int] = set()
        self._fenced_before_epoch = start_ep
        self._fenced_attempts: set[_AttemptKey] = set()
        self._attempts: dict[_AttemptKey, _AttemptRecord] = {}
        self._exec_counts: dict[tuple[str, str], int] = {}

    @property
    def history_start_epoch(self) -> int:
        with self._lock:
            return self._history_start_epoch

    @property
    def observed_epochs(self) -> frozenset[int]:
        with self._lock:
            return frozenset(self._observed_epochs)

    @property
    def bound_journal_id(self) -> str | None:
        with self._lock:
            return self._bound_journal_id

    @staticmethod
    def _key_for(token: StepLeaseToken) -> _AttemptKey:
        return (
            token.run_id,
            token.step_id,
            token.attempt_no,
            token.lease_epoch,
            token.idempotency_key,
        )

    @staticmethod
    def _clean_journal_id(journal_id: str | None) -> str | None:
        if journal_id is None:
            return None
        return _wrap_clean_str(journal_id, KEY_JOURNAL_ID, max_bytes=128)

    def _journal_matches_locked(self, journal_id: str | None) -> bool:
        if self._bound_journal_id is None:
            return journal_id is None
        return journal_id is not None and journal_id == self._bound_journal_id

    def attach_epoch(
        self, supervisor_epoch: int, *, journal_id: str | None = None
    ) -> None:
        ep = validate_int64(supervisor_epoch, "supervisor_epoch", min_val=1)
        clean_jid = self._clean_journal_id(journal_id)
        with self._lock:
            if clean_jid is not None:
                if self._bound_journal_id is None:
                    self._bound_journal_id = clean_jid
                elif clean_jid != self._bound_journal_id:
                    return
            elif self._bound_journal_id is not None:
                return
            self._fenced_before_epoch = max(self._fenced_before_epoch, ep)
            if not self._attached:
                self._attached = True
                self._history_start_epoch = max(self._history_start_epoch, ep)
            self._observed_epochs.add(ep)

    def fence_epoch(
        self, min_active_epoch: int, *, journal_id: str | None = None
    ) -> None:
        clean_jid = self._clean_journal_id(journal_id)
        with self._lock:
            if not self._journal_matches_locked(clean_jid):
                return
            self._fenced_before_epoch = max(self._fenced_before_epoch, min_active_epoch)

    def fence_attempt(
        self, token: StepLeaseToken, *, journal_id: str | None = None
    ) -> None:
        clean_jid = self._clean_journal_id(journal_id)
        with self._lock:
            if not self._journal_matches_locked(clean_jid):
                return
            self._fenced_attempts.add(self._key_for(token))

    def admit_attempt(
        self, token: StepLeaseToken, *, journal_id: str | None = None
    ) -> None:
        key = self._key_for(token)
        clean_jid = self._clean_journal_id(journal_id)
        with self._lock:
            if not self._journal_matches_locked(clean_jid):
                raise StaleEpochError(ERR_STALE_EPOCH)
            if (
                token.lease_epoch < self._fenced_before_epoch
                or key in self._fenced_attempts
                or (self._attached and token.lease_epoch not in self._observed_epochs)
            ):
                raise StaleEpochError(ERR_STALE_EPOCH)
            if key in self._attempts:
                raise IdempotencyConflictError(ERR_IDEM_CONFLICT)
            self._attempts[key] = _AttemptRecord(status="admitted")

    def run_admitted(
        self,
        token: StepLeaseToken,
        *,
        worker_fn: Callable[[StepLeaseToken], WorkerStepResult],
    ) -> WorkerStepResult:
        key = self._key_for(token)
        with self._lock:
            rec = self._attempts.get(key)
            if rec is None or rec.status != "admitted":
                raise InvalidStepTransitionError("attempt_not_admitted")
            self._attempts[key] = _AttemptRecord(status="running")
            self._exec_counts[(token.run_id, token.step_id)] = (
                self._exec_counts.get((token.run_id, token.step_id), 0) + 1
            )
        result = worker_fn(token)
        with self._lock:
            if result.outcome == WORKER_COMPLETED:
                self._attempts[key] = _AttemptRecord(
                    status=OUTCOME_EFFECT_APPLIED, output_digest=result.output_digest
                )
            elif result.outcome == WORKER_FAILED_UNCERTAIN:
                self._attempts[key] = _AttemptRecord(status=OUTCOME_STILL_PENDING)
            else:
                self._attempts[key] = _AttemptRecord(status="failed_no_effect")
        return result

    def count(self, run_id: str, step_id: str) -> int:
        with self._lock:
            return self._exec_counts.get((run_id, step_id), 0)

    @staticmethod
    def _resolve_receipt_outcome(
        rec: _AttemptRecord | None, *, fenced: bool, has_history: bool
    ) -> tuple[TrackerOutcome, str | None]:
        if rec is not None and rec.status == OUTCOME_EFFECT_APPLIED:
            return OUTCOME_EFFECT_APPLIED, rec.output_digest
        if rec is not None and rec.status in ("admitted", "running", OUTCOME_STILL_PENDING):
            return OUTCOME_STILL_PENDING, None
        if rec is None and not has_history:
            return OUTCOME_STILL_PENDING, None
        return (OUTCOME_NO_EFFECT if fenced else OUTCOME_STILL_PENDING), None

    def issue_receipt(
        self,
        *,
        token: StepLeaseToken,
        current_epoch: int,
        force_fence: bool = False,
        journal_id: str | None = None,
    ) -> EffectTrackerReceipt:
        key = self._key_for(token)
        clean_jid = self._clean_journal_id(journal_id)
        with self._lock:
            if not self._journal_matches_locked(clean_jid):
                fenced = False
                outcome: TrackerOutcome = OUTCOME_STILL_PENDING
                out_digest: str | None = None
            else:
                if force_fence:
                    self._fenced_attempts.add(key)
                fenced = (
                    token.lease_epoch < self._fenced_before_epoch
                    or token.lease_epoch < current_epoch
                    or key in self._fenced_attempts
                )
                has_history = (
                    token.lease_epoch in self._observed_epochs
                    if self._attached
                    else token.lease_epoch == self._history_start_epoch
                )
                outcome, out_digest = self._resolve_receipt_outcome(
                    self._attempts.get(key), fenced=fenced, has_history=has_history
                )
        digest = compute_tracker_receipt_digest(
            run_id=token.run_id,
            step_id=token.step_id,
            attempt_no=token.attempt_no,
            lease_epoch=token.lease_epoch,
            idempotency_key=token.idempotency_key,
            tracker_outcome=outcome,
            attempt_fenced=fenced,
            output_digest=out_digest,
        )
        return EffectTrackerReceipt(
            run_id=token.run_id,
            step_id=token.step_id,
            attempt_no=token.attempt_no,
            lease_epoch=token.lease_epoch,
            idempotency_key=token.idempotency_key,
            tracker_outcome=outcome,
            attempt_fenced=fenced,
            output_digest=out_digest,
            receipt_digest=digest,
        )

    @staticmethod
    def _verify_receipt_integrity_and_coords(
        receipt: EffectTrackerReceipt, step: WorkflowStepRecord
    ) -> None:
        expected_digest = compute_tracker_receipt_digest(
            run_id=receipt.run_id,
            step_id=receipt.step_id,
            attempt_no=receipt.attempt_no,
            lease_epoch=receipt.lease_epoch,
            idempotency_key=receipt.idempotency_key,
            tracker_outcome=receipt.tracker_outcome,
            attempt_fenced=receipt.attempt_fenced,
            output_digest=receipt.output_digest,
        )
        if not hmac.compare_digest(receipt.receipt_digest, expected_digest):
            raise ReconciliationEvidenceError("tampered_tracker_receipt")
        coords = (
            receipt.run_id,
            receipt.step_id,
            receipt.attempt_no,
            receipt.lease_epoch,
            receipt.idempotency_key,
        )
        expected_coords = (
            step.run_id,
            step.step_id,
            step.attempt_no,
            step.lease_epoch,
            step.idempotency_key,
        )
        if coords != expected_coords:
            raise ReconciliationEvidenceError("tracker_receipt_attempt_mismatch")

    def verify_receipt_for_step(
        self,
        receipt: EffectTrackerReceipt | None,
        *,
        step: WorkflowStepRecord,
        current_epoch: int,
        expected_outcome: TrackerOutcome,
        expected_evidence_digest: str,
        expected_output_digest: str | None = None,
        journal_id: str | None = None,
    ) -> None:
        if receipt is None or step.idempotency_key is None:
            raise ReconciliationEvidenceError("missing_tracker_receipt")
        clean_jid = self._clean_journal_id(journal_id)
        with self._lock:
            if not self._journal_matches_locked(clean_jid):
                raise ReconciliationEvidenceError("tracker_journal_mismatch")
        self._verify_receipt_integrity_and_coords(receipt, step)
        live = self.issue_receipt(
            token=StepLeaseToken(
                run_id=step.run_id,
                step_id=step.step_id,
                attempt_no=step.attempt_no,
                lease_epoch=step.lease_epoch,
                idempotency_key=step.idempotency_key,
            ),
            current_epoch=current_epoch,
            journal_id=clean_jid,
        )
        if not hmac.compare_digest(live.receipt_digest, receipt.receipt_digest):
            raise ReconciliationEvidenceError("tracker_receipt_state_mismatch")
        if receipt.tracker_outcome != expected_outcome:
            raise ReconciliationEvidenceError(
                f"tracker_outcome_mismatch:{receipt.tracker_outcome}"
            )
        if expected_outcome == OUTCOME_NO_EFFECT:
            if not receipt.attempt_fenced:
                raise ReconciliationEvidenceError("attempt_not_fenced")
            if not hmac.compare_digest(expected_evidence_digest, receipt.receipt_digest):
                raise ReconciliationEvidenceError("evidence_digest_mismatch")
        if expected_output_digest is not None and receipt.output_digest != expected_output_digest:
            raise ReconciliationEvidenceError("tracker_output_digest_mismatch")
