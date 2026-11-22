"""Offline PRD N supervision primitives: broker gate, fixture-owned budgets, throttler, and replay."""

from __future__ import annotations

import base64
import json
import math
import re
import secrets
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Mapping, Sequence

from oc_workflow_plan import (
    AdmissionReceipt,
    AuthorityError,
    CallerRole,
    ClockSnapshot,
    CompiledWorkflowPlan,
    LaneAuthorityError,
    LaneLeaseRegistry,
    ModelCatalog,
    RunAuthorityStore,
    TargetIncarnation,
    WorkflowPlanError,
    recompute_plan_digests,
)
from oc_workflow_schema import (
    ExcerptDisclosureSpec,
    System1Spec,
    canonical_json_bytes,
    render_template,
)

ALLOWED_BLIND_TOOLS = frozenset(
    {
        "health_record_ok",
        "health_nudge_lane",
        "health_escalate_human",
        "health_wake_orchestrator",
    }
)
ALLOWED_ESCALATION_CATEGORIES = frozenset(
    {
        "stalled_loop",
        "machine_degraded",
        "repeated_tool_errors",
        "escalate_human",
        "security_anomaly",
    }
)
ALLOWED_WAKE_REASON_CODES = frozenset(
    {
        "lane_stalled",
        "dependency_blocked",
        "machine_degraded",
        "canary_repeated",
    }
)
ALLOWED_HOST_ERROR_CLASSES = frozenset(
    {
        "",
        "http_429",
        "http_500",
        "http_502",
        "http_503",
        "http_504",
        "timeout",
        "stream_stall",
        "tool_error_loop",
        "oom_killed",
    }
)

_CANARY_PREFIX_RE = re.compile(
    r"(?i)("
    r"sk-[a-z0-9_-]{8,}"
    r"|ghp_[a-z0-9]{8,}"
    r"|gho_[a-z0-9]{8,}"
    r"|github_pat_[a-z0-9_]{8,}"
    r"|akia[0-9a-z]{12,}"
    r"|aiza[0-9a-z_-]{12,}"
    r"|xoxb-[0-9a-z-]{8,}"
    r"|ocjob_[a-z0-9_-]{6,}"
    r"|ocpeer_[a-z0-9_-]{6,}"
    r"|bearer\s+[a-z0-9._-]{12,}"
    r"|begin\s+[a-z0-9 ]*private\s+key"
    r")"
)
_UNTRUSTED_TAG_RE = re.compile(r"<[ \t\r\n]*(?:/[ \t\r\n]*)?oc-untrusted-data", re.IGNORECASE)
_CONTROL_STRIP_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")


class SupervisionError(ValueError):
    """Base error for offline supervision primitives."""


class DisclosureBlockedError(SupervisionError):
    """Raised when an outbound payload violates excerpt disclosure policy."""


class CanaryLeakError(DisclosureBlockedError):
    """Raised when OverlapCanaryScanner detects a secret or credential token."""


class BudgetExhaustedError(SupervisionError):
    """Raised when a per-run or replay call/microdollar budget is exhausted."""


class ReplayAuthorizationError(SupervisionError):
    """Raised when calibration replay fails grant, digest, or per-record authorization."""


# --- Host-authoritative telemetry vs. untrusted claims ---


@dataclass(frozen=True)
class ProgressFingerprint:
    """Strictly independent host-verified task progress (never worker transport/chat claims)."""

    commit_sha: str
    tree_oid: str
    diff_stat_hash: str
    verified_test_exit_seq: int
    workflow_state_seq: int


@dataclass(frozen=True)
class TrustedMetrics:
    """Host-observed metrics plane; outbound projection emits strictly numeric/boolean/closed-enum fields."""

    target: TargetIncarnation
    stall_seconds: int
    consecutive_errors: int
    http_429_count: int
    http_5xx_count: int
    quota_5h_remaining_pct: int
    last_transport_frame_at: float  # transport activity ONLY; never progress
    human_input_lease_active: bool
    progress_fingerprint: ProgressFingerprint
    provider_route: str = ""
    remote_worker: str = "local"
    error_class: str = ""

    def __post_init__(self) -> None:
        _validate_trusted_metric_values(self)

    def to_payload_dict(self) -> dict[str, Any]:
        """Validate and project strictly numeric/boolean/closed-enum fields for outbound model payloads."""
        _validate_trusted_metric_values(self)
        return {
            "consecutive_errors": self.consecutive_errors,
            "error_class": self.error_class,
            "http_429_count": self.http_429_count,
            "http_5xx_count": self.http_5xx_count,
            "human_input_lease_active": self.human_input_lease_active,
            "last_transport_frame_at": self.last_transport_frame_at,
            "quota_5h_remaining_pct": self.quota_5h_remaining_pct,
            "stall_seconds": self.stall_seconds,
        }


def _validate_trusted_metric_values(m: TrustedMetrics) -> None:
    if m.error_class not in ALLOWED_HOST_ERROR_CLASSES:
        raise SupervisionError(f"unallowlisted host error_class {m.error_class!r}")
    for name, val in (
        ("stall_seconds", m.stall_seconds),
        ("consecutive_errors", m.consecutive_errors),
        ("http_429_count", m.http_429_count),
        ("http_5xx_count", m.http_5xx_count),
        ("quota_5h_remaining_pct", m.quota_5h_remaining_pct),
    ):
        if type(val) is not int or val < 0:
            raise SupervisionError(f"trusted metric {name!r} must be a non-negative int")
    if m.quota_5h_remaining_pct > 100:
        raise SupervisionError("quota_5h_remaining_pct must be <= 100")
    if type(m.human_input_lease_active) is not bool:
        raise SupervisionError("human_input_lease_active must be bool")
    if type(m.last_transport_frame_at) is bool or not math.isfinite(m.last_transport_frame_at):
        raise SupervisionError("last_transport_frame_at must be a finite number")


@dataclass(frozen=True)
class UntrustedClaims:
    """Untrusted agent self-reports and optional raw error excerpt."""

    self_reported_status: str = ""
    sanitized_last_error_excerpt: str | None = None


@dataclass(frozen=True)
class MetricSnapshot:
    """Frozen point-in-time snapshot separating trusted metrics and untrusted claims."""

    snapshot_id: str
    trusted: TrustedMetrics
    untrusted: UntrustedClaims = field(default_factory=UntrustedClaims)


# --- Dual-pass OverlapCanaryScanner & 128-bit nonce framing ---


def frame_untrusted_excerpt(text: str) -> str:
    """Wrap permitted untrusted excerpt in 128-bit random-nonce breakout-escaped framing."""
    nonce = secrets.token_hex(16)
    escaped = _UNTRUSTED_TAG_RE.sub(lambda m: "&lt;" + m.group(0)[1:], text)
    return f'<oc-untrusted-data nonce="{nonce}">{escaped}</oc-untrusted-data nonce="{nonce}">'


def _collect_string_leaves(obj: Any, out: list[str]) -> None:
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            _collect_string_leaves(k, out)
            _collect_string_leaves(v, out)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _collect_string_leaves(item, out)


def _add_b64_variants(raw_bytes: bytes, windows: set[str]) -> None:
    for b64 in (
        base64.b64encode(raw_bytes).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("="),
    ):
        if len(b64) >= 8:
            windows.add(b64)


def _extract_windows(secret: str) -> tuple[str, ...]:
    windows: set[str] = {secret}
    normalized = " ".join(secret.split())
    if len(normalized) >= 8:
        windows.add(normalized)
    _add_b64_variants(secret.encode("utf-8"), windows)
    if len(secret) >= 16:
        for i in range(0, len(secret) - 15):
            sl = secret[i : i + 16]
            windows.add(sl)
            _add_b64_variants(sl.encode("utf-8"), windows)
    return tuple(windows)


class OverlapCanaryScanner:
    """Scans exact serialized bytes AND decoded string leaves (stride-1 + Base64) for secrets."""

    def __init__(self, corpus_secrets: Sequence[str] = ()) -> None:
        patterns: set[str] = set()
        for item in corpus_secrets:
            if len(item.encode("utf-8")) >= 8:
                patterns.update(_extract_windows(item))
        self._patterns: tuple[str, ...] = tuple(sorted(patterns))

    def _scan_text(self, text: str) -> None:
        if _CANARY_PREFIX_RE.search(text):
            raise CanaryLeakError("credential or private key pattern detected in outbound payload")
        norm = " ".join(text.split())
        for pat in self._patterns:
            if pat in text or pat in norm:
                raise CanaryLeakError("corpus secret overlap detected in outbound payload")

    def scan(self, payload_bytes: bytes, *, decoded_leaves: Sequence[str] = ()) -> None:
        raw_text = payload_bytes.decode("utf-8")
        self._scan_text(raw_text)
        leaves: Sequence[str] = decoded_leaves
        if not leaves:
            try:
                parsed = json.loads(raw_text)
                extracted: list[str] = []
                _collect_string_leaves(parsed, extracted)
                leaves = extracted
            except json.JSONDecodeError:
                leaves = ()
        for leaf in leaves:
            self._scan_text(leaf)


# --- HostSleepDetector, FleetCheckBudget, ReplayGrantRegistry & CorrelatedFaultCoalescer ---


class HostSleepDetector:
    """Fleet-level monotonic/wall sleep gap detector applying uniform wake grace across lanes."""

    def __init__(self, sleep_gap_threshold_s: float = 30.0) -> None:
        self._threshold_s = sleep_gap_threshold_s
        self._last_clock: ClockSnapshot | None = None
        self._wake_grace_until_mono: float = -1.0
        self.total_excluded_sleep_s: float = 0.0

    def observe_and_in_grace(self, clock: ClockSnapshot, *, wake_grace_s: int) -> bool:
        if self._last_clock is not None:
            mono_dt = clock.monotonic_s - self._last_clock.monotonic_s
            if mono_dt < 0:
                raise ValueError(
                    f"non-monotonic clock rejected: {clock.monotonic_s} < {self._last_clock.monotonic_s}"
                )
            wall_dt = clock.wall_s - self._last_clock.wall_s
            gap = wall_dt - mono_dt
            if gap > self._threshold_s:
                self.total_excluded_sleep_s += gap
                self._wake_grace_until_mono = max(
                    self._wake_grace_until_mono,
                    clock.monotonic_s + wake_grace_s,
                )
        self._last_clock = clock
        return clock.monotonic_s < self._wake_grace_until_mono


class FleetCheckBudget:
    """Fleet concurrency cap + hourly cap with a non-starvable reserved audit floor."""

    def __init__(
        self,
        *,
        max_concurrent: int,
        max_checks_per_hour: int,
        reserved_audit_checks_per_hour: int,
    ) -> None:
        if reserved_audit_checks_per_hour > max_checks_per_hour:
            raise SupervisionError("reserved audit slice cannot exceed fleet_max_checks_per_hour")
        self._max_concurrent = max_concurrent
        self._max_checks_per_hour = max_checks_per_hour
        self._reserved_audit = reserved_audit_checks_per_hour
        self._active = 0
        self._triggered_times: deque[float] = deque()
        self._audit_times: deque[float] = deque()

    @property
    def active_count(self) -> int:
        return self._active

    def _prune(self, now_mono: float) -> None:
        cutoff = now_mono - 3600.0
        while self._triggered_times and self._triggered_times[0] <= cutoff:
            self._triggered_times.popleft()
        while self._audit_times and self._audit_times[0] <= cutoff:
            self._audit_times.popleft()

    def acquire(
        self,
        *,
        kind: Literal["triggered", "scheduled_audit"],
        clock: ClockSnapshot,
    ) -> Literal["admitted", "cap_delayed", "cap_dropped"]:
        self._prune(clock.monotonic_s)
        if self._active >= self._max_concurrent:
            return "cap_delayed"
        total_used = len(self._triggered_times) + len(self._audit_times)
        if total_used >= self._max_checks_per_hour:
            return "cap_dropped"
        if kind == "triggered":
            triggered_cap = self._max_checks_per_hour - self._reserved_audit
            if len(self._triggered_times) >= triggered_cap:
                return "cap_dropped"
            self._triggered_times.append(clock.monotonic_s)
        else:
            self._audit_times.append(clock.monotonic_s)
        self._active += 1
        return "admitted"

    def release(self) -> None:
        if self._active > 0:
            self._active -= 1

    def rollback(self, kind: Literal["triggered", "scheduled_audit"]) -> None:
        """Roll back an admitted slot ONLY when the broker refuses BEFORE adapter entry."""
        self.release()
        bucket = self._triggered_times if kind == "triggered" else self._audit_times
        if bucket:
            bucket.pop()


@dataclass(frozen=True)
class CalibrationReplayGrant:
    """Tier-A approved replay grant cryptographically binding candidate rubric & spec digests."""

    grant_id: str
    requesting_principal: str
    run_id: str
    workflow_id: str
    candidate_spec_digest: str
    candidate_rubric_digest: str
    authorized_sample_scope: frozenset[str]
    approved_decisions_route: str
    approved_model: str
    excerpt_disclosure_policy: ExcerptDisclosureSpec
    max_replay_samples: int
    max_replay_calls: int
    max_replay_spend_microusd: int
    expires_at_wall_s: float

    def __post_init__(self) -> None:
        if type(self.expires_at_wall_s) is bool or not math.isfinite(self.expires_at_wall_s):
            raise ReplayAuthorizationError("CalibrationReplayGrant.expires_at_wall_s must be finite")
        for name, val in (
            ("max_replay_samples", self.max_replay_samples),
            ("max_replay_calls", self.max_replay_calls),
            ("max_replay_spend_microusd", self.max_replay_spend_microusd),
        ):
            if type(val) is not int or val < 0:
                raise ReplayAuthorizationError(f"CalibrationReplayGrant.{name} must be a non-negative int")


@dataclass
class _RegisteredReplayGrant:
    grant: CalibrationReplayGrant
    calls_used: int = 0
    spend_microusd_used: int = 0
    evaluated_sample_ids: set[str] = field(default_factory=set)
    revoked: bool = False


class ReplayGrantRegistry:
    """Fixture-owned authoritative registry for approved replay grants, balances, sample allowances, and revocation."""

    def __init__(self) -> None:
        self._grants: dict[str, _RegisteredReplayGrant] = {}

    def register(self, grant: CalibrationReplayGrant) -> None:
        if not grant.grant_id or grant.grant_id in self._grants:
            raise ReplayAuthorizationError(f"grant_id {grant.grant_id!r} invalid or already registered")
        self._grants[grant.grant_id] = _RegisteredReplayGrant(grant=grant)

    def revoke(self, grant_id: str) -> None:
        entry = self._grants.get(grant_id)
        if entry is not None:
            entry.revoked = True

    def lookup_active(self, grant_id: str, *, clock: ClockSnapshot) -> CalibrationReplayGrant:
        entry = self._grants.get(grant_id)
        if entry is None:
            raise ReplayAuthorizationError(f"unregistered replay grant {grant_id!r}")
        if entry.revoked:
            raise ReplayAuthorizationError("REPLAY_GRANT_REVOKED")
        if clock.wall_s >= entry.grant.expires_at_wall_s:
            raise ReplayAuthorizationError("REPLAY_GRANT_EXPIRED")
        return entry.grant

    def reserve(
        self,
        grant_id: str,
        *,
        sample_id: str,
        cost_microusd: int,
        clock: ClockSnapshot,
    ) -> bool:
        if type(cost_microusd) is not int or cost_microusd < 0:
            raise ReplayAuthorizationError("replay cost_microusd must be a non-negative int")
        entry = self._grants.get(grant_id)
        if entry is None or entry.revoked or clock.wall_s >= entry.grant.expires_at_wall_s:
            return False
        next_samples = entry.evaluated_sample_ids | {sample_id}
        if entry.grant.max_replay_samples <= 0 or len(next_samples) > entry.grant.max_replay_samples:
            return False
        if entry.calls_used + 1 > entry.grant.max_replay_calls:
            return False
        if entry.spend_microusd_used + cost_microusd > entry.grant.max_replay_spend_microusd:
            return False
        entry.evaluated_sample_ids.add(sample_id)
        entry.calls_used += 1
        entry.spend_microusd_used += cost_microusd
        return True

    def usage(self, grant_id: str) -> tuple[int, int]:
        entry = self._grants.get(grant_id)
        if entry is None:
            return (0, 0)
        return (entry.calls_used, entry.spend_microusd_used)


class CorrelatedFaultCoalescer:
    """Detects shared (provider_route, remote_worker, error_class) fleet outages."""

    def __init__(self, *, threshold_lanes: int = 2) -> None:
        self._threshold = threshold_lanes
        self._fault_targets: dict[tuple[str, str, str], set[TargetIncarnation]] = {}
        self._emitted_notices: set[tuple[str, str, str]] = set()

    def observe(self, trusted: TrustedMetrics) -> tuple[bool, str | None]:
        """Return (is_correlated_outage, fleet_notice_key_if_newly_emitted)."""
        if not trusted.error_class or not trusted.provider_route:
            return False, None
        key = (trusted.provider_route, trusted.remote_worker, trusted.error_class)
        targets = self._fault_targets.setdefault(key, set())
        targets.add(trusted.target)
        if len(targets) < self._threshold:
            return False, None
        if key not in self._emitted_notices:
            self._emitted_notices.add(key)
            return True, f"fleet_outage:{key[0]}:{key[1]}:{key[2]}"
        return True, None


# --- Offline fake adapters ---


@dataclass(frozen=True)
class DecisionsAdapterResponse:
    choice: str | None
    injection_canary_positive: bool = False
    malformed: bool = False


class LocalRulesDecisionsAdapter:
    """Deterministic offline decisions:local-rules-v1 fixture."""

    def __init__(
        self,
        scripted: Sequence[DecisionsAdapterResponse] | None = None,
    ) -> None:
        self._scripted: deque[DecisionsAdapterResponse] = deque(scripted or ())
        self.invocation_count: int = 0
        self.payload_history: list[bytes] = []

    def evaluate(self, payload_bytes: bytes) -> DecisionsAdapterResponse:
        self.invocation_count += 1
        self.payload_history.append(payload_bytes)
        if self._scripted:
            return self._scripted.popleft()
        parsed = json.loads(payload_bytes.decode("utf-8"))
        metrics = parsed["trusted_metrics"]
        if metrics["consecutive_errors"] >= 3 or metrics["stall_seconds"] >= 600:
            return DecisionsAdapterResponse(choice="stalled_loop")
        if metrics["http_5xx_count"] >= 3:
            return DecisionsAdapterResponse(choice="machine_degraded")
        return DecisionsAdapterResponse(choice="healthy_progress")


@dataclass(frozen=True)
class BlindToolCall:
    tool: str
    args: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class BlindCheckResponse:
    tool_calls: tuple[BlindToolCall, ...]
    malformed: bool = False


class ScriptedBlindVerifier:
    """Deterministic offline 4-tool blind verifier with optional mid-call test hook."""

    def __init__(
        self,
        scripted: Sequence[BlindCheckResponse] | None = None,
        *,
        on_call: Callable[[bytes], None] | None = None,
    ) -> None:
        self._scripted: deque[BlindCheckResponse] = deque(scripted or ())
        self._on_call = on_call
        self.invocation_count: int = 0
        self.payload_history: list[bytes] = []

    def check(self, payload_bytes: bytes) -> BlindCheckResponse:
        self.invocation_count += 1
        self.payload_history.append(payload_bytes)
        if self._on_call is not None:
            self._on_call(payload_bytes)
        if self._scripted:
            return self._scripted.popleft()
        return BlindCheckResponse(tool_calls=(BlindToolCall(tool="health_record_ok"),))


# --- Run- & Incarnation-Scoped CalibrationLedger ---


@dataclass(frozen=True)
class CalibrationRecord:
    sample_id: str
    run_id: str
    workflow_id: str
    target: TargetIncarnation
    stratum: str
    frozen_snapshot: MetricSnapshot
    sys1_verdict: str | None
    blind_tool: str
    confusion_outcome: str  # TP | FP | TN | FN | class_mismatch | excluded


@dataclass(frozen=True)
class SupervisionObservation:
    """Scoped abstention or cap-drop/delay observation retaining exact run and incarnation."""

    run_id: str
    target: TargetIncarnation
    stratum: str
    kind: Literal["sys1_abstain", "blind_abstain", "cap_delayed", "cap_dropped"]


@dataclass
class StratumStats:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    class_mismatch: int = 0
    excluded: int = 0
    sys1_abstentions: int = 0
    blind_abstentions: int = 0
    cap_delayed: int = 0
    cap_dropped: int = 0

    @property
    def verified_count(self) -> int:
        return self.tp + self.fp + self.tn + self.fn + self.class_mismatch + self.excluded

    @property
    def inclusion_rate(self) -> float:
        denom = self.verified_count + self.cap_dropped + self.sys1_abstentions + self.blind_abstentions
        return 1.0 if denom == 0 else self.verified_count / denom

    def notes_dict(self) -> dict[str, float | int]:
        return {
            "blind_abstentions": self.blind_abstentions,
            "cap_delayed": self.cap_delayed,
            "cap_dropped": self.cap_dropped,
            "inclusion_rate": self.inclusion_rate,
            "sys1_abstentions": self.sys1_abstentions,
        }


class CalibrationLedger:
    """Stratified reference-verdict ledger with run- and incarnation-scoped observations."""

    def __init__(self) -> None:
        self._records: dict[str, CalibrationRecord] = {}
        self._order: list[str] = []
        self._observations: list[SupervisionObservation] = []
        self._stats: dict[str, StratumStats] = {}

    def _stratum(self, name: str) -> StratumStats:
        return self._stats.setdefault(name, StratumStats())

    def stats_for(self, stratum: str) -> StratumStats:
        return self._stratum(stratum)

    def get_record(self, sample_id: str) -> CalibrationRecord | None:
        return self._records.get(sample_id)

    def all_records(self) -> tuple[CalibrationRecord, ...]:
        return tuple(self._records[sid] for sid in self._order)

    def record_outcome(self, record: CalibrationRecord) -> None:
        self._records[record.sample_id] = record
        self._order.append(record.sample_id)
        st = self._stratum(record.stratum)
        outcome_map = {
            "TP": "tp",
            "FP": "fp",
            "TN": "tn",
            "FN": "fn",
            "class_mismatch": "class_mismatch",
            "excluded": "excluded",
        }
        attr = outcome_map.get(record.confusion_outcome)
        if attr is not None:
            setattr(st, attr, getattr(st, attr) + 1)

    def record_abstention(
        self,
        *,
        run_id: str,
        target: TargetIncarnation,
        stratum: str,
        source: Literal["sys1", "blind"],
    ) -> None:
        kind: Literal["sys1_abstain", "blind_abstain"] = "sys1_abstain" if source == "sys1" else "blind_abstain"
        self._observations.append(
            SupervisionObservation(run_id=run_id, target=target, stratum=stratum, kind=kind)
        )
        st = self._stratum(stratum)
        if source == "sys1":
            st.sys1_abstentions += 1
        else:
            st.blind_abstentions += 1

    def record_cap_event(
        self,
        *,
        run_id: str,
        target: TargetIncarnation,
        stratum: str,
        outcome: Literal["cap_delayed", "cap_dropped"],
    ) -> None:
        self._observations.append(
            SupervisionObservation(run_id=run_id, target=target, stratum=stratum, kind=outcome)
        )
        st = self._stratum(stratum)
        if outcome == "cap_delayed":
            st.cap_delayed += 1
        else:
            st.cap_dropped += 1

    def scoped_stratum_notes(
        self,
        stratum: str,
        *,
        run_id: str,
        authority_store: RunAuthorityStore,
        principal_id: str,
        caller_role: CallerRole,
        caller_subtree: frozenset[str],
        clock: ClockSnapshot,
    ) -> dict[str, float | int]:
        """Aggregate inclusion, cap-drop/delay, and abstention notes strictly over authorized run inputs."""
        scoped = StratumStats()
        for rec in self.all_records():
            if rec.run_id != run_id or rec.stratum != stratum:
                continue
            if not _is_authorized_scope(
                authority_store, rec.run_id, rec.target, principal_id, caller_role, caller_subtree, clock
            ):
                continue
            scoped.tp += 1  # counts as verified_count in scoped inclusion denominator
        obs_attr = {
            "sys1_abstain": "sys1_abstentions",
            "blind_abstain": "blind_abstentions",
            "cap_delayed": "cap_delayed",
            "cap_dropped": "cap_dropped",
        }
        for obs in self._observations:
            if obs.run_id != run_id or obs.stratum != stratum:
                continue
            if not _is_authorized_scope(
                authority_store, obs.run_id, obs.target, principal_id, caller_role, caller_subtree, clock
            ):
                continue
            attr = obs_attr[obs.kind]
            setattr(scoped, attr, getattr(scoped, attr) + 1)
        return scoped.notes_dict()


def _is_authorized_scope(
    authority_store: RunAuthorityStore,
    run_id: str,
    target: TargetIncarnation,
    principal_id: str,
    caller_role: CallerRole,
    caller_subtree: frozenset[str],
    clock: ClockSnapshot,
) -> bool:
    try:
        authority_store.verify_record_access(
            run_id=run_id,
            principal_id=principal_id,
            caller_role=caller_role,
            caller_subtree=caller_subtree,
            target=target,
            clock=clock,
        )
        return True
    except AuthorityError:
        return False


def query_calibration_examples(
    ledger: CalibrationLedger,
    *,
    authority_store: RunAuthorityStore,
    principal_id: str,
    caller_role: CallerRole,
    caller_subtree: frozenset[str],
    clock: ClockSnapshot,
    run_id: str | None = None,
    strata: frozenset[str] | None = None,
) -> tuple[tuple[CalibrationRecord, ...], dict[str, int]]:
    """Per-record authorized query checking exact live incarnation; excludes unauthorized rows."""
    authorized: list[CalibrationRecord] = []
    aggregates: dict[str, int] = {}
    for rec in ledger.all_records():
        if run_id is not None and rec.run_id != run_id:
            continue
        if strata is not None and rec.stratum not in strata:
            continue
        if rec.target != rec.frozen_snapshot.trusted.target:
            continue
        if not _is_authorized_scope(
            authority_store, rec.run_id, rec.target, principal_id, caller_role, caller_subtree, clock
        ):
            continue
        authorized.append(rec)
        aggregates[rec.confusion_outcome] = aggregates.get(rec.confusion_outcome, 0) + 1
    return tuple(authorized), aggregates


# --- Unified SupervisionBrokerGate choke point ---


def _require_system1(plan: CompiledWorkflowPlan) -> System1Spec:
    sys1 = plan.spec.system1
    if sys1 is None:
        raise SupervisionError("plan has no system1 configuration")
    return sys1


def _select_permitted_excerpt(
    snapshot: MetricSnapshot,
    policy: ExcerptDisclosureSpec,
    *,
    effective_route: str,
    use: Literal["live", "replay"],
    metrics_only_override: bool = False,
) -> str | None:
    if metrics_only_override or policy.mode == "none":
        return None
    if effective_route not in policy.allowed_routes:
        raise DisclosureBlockedError(f"route {effective_route!r} not in excerpt_disclosure.allowed_routes")
    if use not in policy.permitted_uses:
        raise DisclosureBlockedError(f"use {use!r} not in excerpt_disclosure.permitted_uses")
    raw = snapshot.untrusted.sanitized_last_error_excerpt
    if raw is None:
        return None
    safe_utf8 = raw.encode("utf-8", errors="ignore").decode("utf-8")
    cleaned = _CONTROL_STRIP_RE.sub(" ", safe_utf8)
    raw_bytes = cleaned.encode("utf-8")[: policy.max_bytes]
    return raw_bytes.decode("utf-8", errors="ignore")


def _build_decisions_payload(
    *,
    plan: CompiledWorkflowPlan,
    snapshot: MetricSnapshot,
    effective_route: str,
    use: Literal["live", "replay"],
    include_canary_question: bool,
    metrics_only_override: bool,
) -> tuple[bytes, list[str]]:
    sys1 = _require_system1(plan)
    excerpt = _select_permitted_excerpt(
        snapshot,
        plan.spec.excerpt_disclosure,
        effective_route=effective_route,
        use=use,
        metrics_only_override=metrics_only_override,
    )
    payload: dict[str, Any] = {
        "abstain_default": sys1.abstain_default,
        "choices": list(sys1.choices),
        "decision_type": sys1.decision_type,
        "model": sys1.model,
        "route": effective_route,
        "rubric": sys1.rubric,
        "store": False,
        "trusted_metrics": snapshot.trusted.to_payload_dict(),
    }
    if include_canary_question:
        payload["canary_question"] = "noul(classifier_injection_suspected)"
    if excerpt is not None:
        payload["sanitized_last_error_excerpt"] = excerpt
    leaves: list[str] = []
    _collect_string_leaves(payload, leaves)
    return canonical_json_bytes(payload), leaves


def _build_blind_payload(
    *,
    plan: CompiledWorkflowPlan,
    snapshot: MetricSnapshot,
    blind_route: str,
) -> tuple[bytes, list[str]]:
    blind = plan.spec.blind_check
    if blind is None:
        raise SupervisionError("plan has no blind_check configuration")
    excerpt = _select_permitted_excerpt(
        snapshot,
        plan.spec.excerpt_disclosure,
        effective_route=blind_route,
        use="live",
        metrics_only_override=False,
    )
    payload: dict[str, Any] = {
        "model_profile": blind.model_profile,
        "prompt": "Routine Lane Health Check",
        "route": blind_route,
        "store": False,
        "trusted_metrics": snapshot.trusted.to_payload_dict(),
    }
    if excerpt is not None:
        payload["untrusted_excerpt_framed"] = frame_untrusted_excerpt(excerpt)
    leaves: list[str] = []
    _collect_string_leaves(payload, leaves)
    return canonical_json_bytes(payload), leaves


def _verify_grant_against_candidate_plan(
    grant: CalibrationReplayGrant,
    candidate_plan: CompiledWorkflowPlan,
    *,
    caller_id: str,
    model_catalog: ModelCatalog,
) -> tuple[System1Spec, int]:
    if grant.requesting_principal != caller_id:
        raise ReplayAuthorizationError("REPLAY_PRINCIPAL_MISMATCH")
    if grant.workflow_id != candidate_plan.spec.id:
        raise ReplayAuthorizationError("REPLAY_WORKFLOW_MISMATCH")
    sys1 = candidate_plan.spec.system1
    if sys1 is None or candidate_plan.candidate_rubric_digest is None:
        raise ReplayAuthorizationError("candidate plan has no system1 rubric")
    recomputed_spec, _, _ = recompute_plan_digests(candidate_plan)
    if candidate_plan.candidate_rubric_digest != grant.candidate_rubric_digest:
        raise ReplayAuthorizationError("RUBRIC_DIGEST_MISMATCH")
    if recomputed_spec != grant.candidate_spec_digest or candidate_plan.spec_digest != grant.candidate_spec_digest:
        raise ReplayAuthorizationError("SPEC_DIGEST_MISMATCH")
    if sys1.route != grant.approved_decisions_route or sys1.model != grant.approved_model:
        raise ReplayAuthorizationError("REPLAY_ROUTE_OR_MODEL_MISMATCH")
    if candidate_plan.spec.excerpt_disclosure != grant.excerpt_disclosure_policy:
        raise ReplayAuthorizationError("REPLAY_DISCLOSURE_POLICY_MISMATCH")
    try:
        catalog_cost = model_catalog.lookup_decisions(
            grant.approved_decisions_route, grant.approved_model
        ).max_call_cost_microusd
    except WorkflowPlanError as exc:
        raise ReplayAuthorizationError(str(exc)) from exc
    if candidate_plan.decisions_call_cost_microusd != catalog_cost:
        raise ReplayAuthorizationError("REPLAY_TARIFF_MISMATCH")
    return sys1, catalog_cost


def _verify_replay_record_binding(
    grant: CalibrationReplayGrant,
    record: CalibrationRecord,
    *,
    authority_store: RunAuthorityStore,
    caller_id: str,
    caller_role: CallerRole,
    caller_subtree: frozenset[str],
    clock: ClockSnapshot,
) -> None:
    if record.run_id != grant.run_id:
        raise ReplayAuthorizationError(f"sample {record.sample_id!r} belongs to another run")
    if record.stratum not in grant.authorized_sample_scope:
        raise ReplayAuthorizationError(
            f"sample {record.sample_id!r} stratum {record.stratum!r} excluded by grant.authorized_sample_scope"
        )
    if record.target != record.frozen_snapshot.trusted.target:
        raise ReplayAuthorizationError("RECORD_SNAPSHOT_TARGET_MISMATCH")
    authority_store.verify_record_access(
        run_id=record.run_id,
        principal_id=caller_id,
        caller_role=caller_role,
        caller_subtree=caller_subtree,
        target=record.target,
        clock=clock,
    )


class SupervisionBrokerGate:
    """Single mandatory choke point for ALL fake model invocations with fixture-owned accounting."""

    def __init__(
        self,
        *,
        decisions_adapter: LocalRulesDecisionsAdapter,
        blind_verifier: ScriptedBlindVerifier,
        canary_scanner: OverlapCanaryScanner,
        authority_store: RunAuthorityStore,
        lease_registry: LaneLeaseRegistry,
        ledger: CalibrationLedger,
        model_catalog: ModelCatalog,
        replay_registry: ReplayGrantRegistry | None = None,
    ) -> None:
        self._decisions_adapter = decisions_adapter
        self._blind_verifier = blind_verifier
        self._canary_scanner = canary_scanner
        self._authority_store = authority_store
        self._lease_registry = lease_registry
        self._ledger = ledger
        self._model_catalog = model_catalog
        self._replay_registry = replay_registry or ReplayGrantRegistry()

    def invoke_decisions_live(
        self,
        *,
        receipt: AdmissionReceipt,
        target: TargetIncarnation,
        snapshot: MetricSnapshot,
        include_canary_question: bool,
        metrics_only_override: bool,
        clock: ClockSnapshot,
    ) -> DecisionsAdapterResponse:
        if snapshot.trusted.target != target:
            raise AuthorityError("SNAPSHOT_TARGET_MISMATCH")
        record = self._authority_store.verify_active(receipt, clock=clock, target=target)
        self._lease_registry.assert_can_observe(
            receipt, target, authority_store=self._authority_store, clock=clock
        )
        plan = record.approved_plan
        sys1 = _require_system1(plan)
        payload_bytes, leaves = _build_decisions_payload(
            plan=plan,
            snapshot=snapshot,
            effective_route=sys1.route,
            use="live",
            include_canary_question=include_canary_question,
            metrics_only_override=metrics_only_override,
        )
        self._canary_scanner.scan(payload_bytes, decoded_leaves=leaves)
        if not self._authority_store.reserve_decisions_budget(
            receipt, calls=1, cost_microusd=plan.decisions_call_cost_microusd, clock=clock
        ):
            raise BudgetExhaustedError("decisions run budget exhausted")
        return self._decisions_adapter.evaluate(payload_bytes)

    def invoke_blind_check_live(
        self,
        *,
        receipt: AdmissionReceipt,
        target: TargetIncarnation,
        snapshot_for_model: MetricSnapshot,
        clock: ClockSnapshot,
        on_adapter_entry: Callable[[], None] | None = None,
    ) -> BlindCheckResponse:
        if snapshot_for_model.trusted.target != target:
            raise AuthorityError("SNAPSHOT_TARGET_MISMATCH")
        record = self._authority_store.verify_active(receipt, clock=clock, target=target)
        self._lease_registry.assert_can_observe(
            receipt, target, authority_store=self._authority_store, clock=clock
        )
        plan = record.approved_plan
        if plan.spec.blind_check is None or plan.blind_route is None:
            raise SupervisionError("plan has no blind_check configuration")
        payload_bytes, leaves = _build_blind_payload(
            plan=plan,
            snapshot=snapshot_for_model,
            blind_route=plan.blind_route,
        )
        self._canary_scanner.scan(payload_bytes, decoded_leaves=leaves)
        if not self._authority_store.reserve_blind_budget(
            receipt, cost_microusd=plan.blind_call_cost_microusd, clock=clock
        ):
            raise BudgetExhaustedError("blind check run budget exhausted")
        if on_adapter_entry is not None:
            on_adapter_entry()
        return self._blind_verifier.check(payload_bytes)

    def invoke_decisions_replay(
        self,
        *,
        grant_id: str,
        candidate_plan: CompiledWorkflowPlan,
        sample_id: str,
        caller_id: str,
        caller_role: CallerRole,
        caller_subtree: frozenset[str],
        clock: ClockSnapshot,
    ) -> DecisionsAdapterResponse:
        """Resolve sample from fixture ledger and enforce full grant, tariff, sample, and budget checks."""
        grant = self._replay_registry.lookup_active(grant_id, clock=clock)
        sys1, catalog_cost = _verify_grant_against_candidate_plan(
            grant, candidate_plan, caller_id=caller_id, model_catalog=self._model_catalog
        )
        record = self._ledger.get_record(sample_id)
        if record is None:
            raise ReplayAuthorizationError(f"UNKNOWN_SAMPLE_ID: {sample_id!r}")
        _verify_replay_record_binding(
            grant,
            record,
            authority_store=self._authority_store,
            caller_id=caller_id,
            caller_role=caller_role,
            caller_subtree=caller_subtree,
            clock=clock,
        )
        payload_bytes, leaves = _build_decisions_payload(
            plan=candidate_plan,
            snapshot=record.frozen_snapshot,
            effective_route=grant.approved_decisions_route,
            use="replay",
            include_canary_question=sys1.canary_injection_question,
            metrics_only_override=(grant.excerpt_disclosure_policy.mode == "none"),
        )
        self._canary_scanner.scan(payload_bytes, decoded_leaves=leaves)
        if not self._replay_registry.reserve(
            grant.grant_id,
            sample_id=sample_id,
            cost_microusd=catalog_cost,
            clock=clock,
        ):
            raise BudgetExhaustedError("replay grant sample, call, or spend budget exhausted")
        return self._decisions_adapter.evaluate(payload_bytes)


@dataclass(frozen=True)
class ReplayScorecard:
    """Stratified before-vs-after reference-verdict scorecard with run-scoped inclusion and drop notes."""

    grant_id: str
    candidate_rubric_digest: str
    original_per_stratum: Mapping[str, Mapping[str, int]]
    candidate_per_stratum: Mapping[str, Mapping[str, int]]
    stratum_notes: Mapping[str, Mapping[str, float | int]]
    abstentions: int
    evaluated_sample_ids: tuple[str, ...]


def _empty_confusion_bucket() -> dict[str, int]:
    return {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "class_mismatch": 0, "excluded": 0, "abstain": 0}


def _classify_confusion(
    *,
    stratum: str,
    sys1_verdict: str | None,
    healthy_choice: str,
    blind_tool: str,
) -> str:
    if stratum in ("triggered_trailing", "canary_escalation") or sys1_verdict is None:
        return "excluded"
    sys1_alert = sys1_verdict != healthy_choice
    blind_action = blind_tool != "health_record_ok"
    if not stratum.startswith("scheduled_audit") and sys1_verdict == "escalate_human" and blind_action:
        return "TP" if blind_tool == "health_escalate_human" else "class_mismatch"
    table = {
        (True, True): "TP",
        (True, False): "FP",
        (False, True): "FN",
        (False, False): "TN",
    }
    return table[(sys1_alert, blind_action)]


def _classify_replay_candidate(
    resp: DecisionsAdapterResponse,
    *,
    stratum: str,
    choices: tuple[str, ...],
    abstain_default: str,
    blind_tool: str,
) -> str:
    """Apply the EXACT same classification & exclusion rules as live scoring."""
    if resp.malformed or resp.injection_canary_positive or resp.choice not in choices:
        return "abstain"
    return _classify_confusion(
        stratum=stratum,
        sys1_verdict=resp.choice,
        healthy_choice=abstain_default,
        blind_tool=blind_tool,
    )


def _authorize_replay_batch(
    grant: CalibrationReplayGrant,
    sample_ids: Sequence[str],
    ledger: CalibrationLedger,
    *,
    authority_store: RunAuthorityStore,
    caller_id: str,
    caller_role: CallerRole,
    caller_subtree: frozenset[str],
    clock: ClockSnapshot,
) -> list[CalibrationRecord]:
    if not sample_ids or len(sample_ids) != len(set(sample_ids)):
        raise ReplayAuthorizationError("sample_ids must be non-empty and deduplicated")
    if grant.max_replay_samples <= 0 or len(sample_ids) > grant.max_replay_samples:
        raise ReplayAuthorizationError("sample_ids exceed max_replay_samples")
    records: list[CalibrationRecord] = []
    for sid in sample_ids:
        rec = ledger.get_record(sid)
        if rec is None:
            raise ReplayAuthorizationError(f"UNKNOWN_SAMPLE_ID: {sid!r}")
        _verify_replay_record_binding(
            grant,
            rec,
            authority_store=authority_store,
            caller_id=caller_id,
            caller_role=caller_role,
            caller_subtree=caller_subtree,
            clock=clock,
        )
        records.append(rec)
    return records


def run_calibration_replay(
    grant_id: str,
    candidate_plan: CompiledWorkflowPlan,
    sample_ids: Sequence[str],
    ledger: CalibrationLedger,
    *,
    authority_store: RunAuthorityStore,
    replay_registry: ReplayGrantRegistry,
    broker_gate: SupervisionBrokerGate,
    model_catalog: ModelCatalog,
    caller_id: str,
    caller_role: CallerRole,
    caller_subtree: frozenset[str],
    clock_provider: Callable[[], ClockSnapshot],
) -> ReplayScorecard:
    """Run batch-preflighted, rubric-digest-bound replay with unified before/after & run-scoped notes."""
    t_start = clock_provider()
    grant = replay_registry.lookup_active(grant_id, clock=t_start)
    sys1, _ = _verify_grant_against_candidate_plan(
        grant, candidate_plan, caller_id=caller_id, model_catalog=model_catalog
    )
    authorized_records = _authorize_replay_batch(
        grant,
        sample_ids,
        ledger,
        authority_store=authority_store,
        caller_id=caller_id,
        caller_role=caller_role,
        caller_subtree=caller_subtree,
        clock=t_start,
    )

    orig_per_stratum: dict[str, dict[str, int]] = {}
    cand_per_stratum: dict[str, dict[str, int]] = {}
    notes: dict[str, dict[str, float | int]] = {}
    abstentions = 0
    evaluated: list[str] = []

    for rec in authorized_records:
        t_call = clock_provider()
        resp = broker_gate.invoke_decisions_replay(
            grant_id=grant.grant_id,
            candidate_plan=candidate_plan,
            sample_id=rec.sample_id,
            caller_id=caller_id,
            caller_role=caller_role,
            caller_subtree=caller_subtree,
            clock=t_call,
        )
        evaluated.append(rec.sample_id)
        ob = orig_per_stratum.setdefault(rec.stratum, _empty_confusion_bucket())
        if rec.confusion_outcome in ob:
            ob[rec.confusion_outcome] += 1
        cb = cand_per_stratum.setdefault(rec.stratum, _empty_confusion_bucket())
        cand_outcome = _classify_replay_candidate(
            resp,
            stratum=rec.stratum,
            choices=sys1.choices,
            abstain_default=sys1.abstain_default,
            blind_tool=rec.blind_tool,
        )
        cb[cand_outcome] += 1
        if cand_outcome == "abstain":
            abstentions += 1
        if rec.stratum not in notes:
            notes[rec.stratum] = ledger.scoped_stratum_notes(
                rec.stratum,
                run_id=grant.run_id,
                authority_store=authority_store,
                principal_id=caller_id,
                caller_role=caller_role,
                caller_subtree=caller_subtree,
                clock=t_call,
            )

    return ReplayScorecard(
        grant_id=grant.grant_id,
        candidate_rubric_digest=candidate_plan.candidate_rubric_digest or "",
        original_per_stratum=orig_per_stratum,
        candidate_per_stratum=cand_per_stratum,
        stratum_notes=notes,
        abstentions=abstentions,
        evaluated_sample_ids=tuple(evaluated),
    )


# --- Per-lane throttler & post-verdict fresh-snapshot supervision tick ---


@dataclass
class LaneSupervisionState:
    target: TargetIncarnation
    mode: Literal["IDLE", "THROTTLED"] = "IDLE"
    window_end_mono: float = 0.0
    trailing_queued: bool = False
    suppressed_count: int = 0
    canary_hits: int = 0
    incident_seq: int = 0
    last_progress: ProgressFingerprint | None = None

    def enter_throttled(self, window_end_mono: float) -> None:
        self.mode = "THROTTLED"
        self.window_end_mono = window_end_mono
        self.trailing_queued = False
        self.suppressed_count = 0


@dataclass(frozen=True)
class SupervisionTickResult:
    status: str
    action_taken: str | None = None
    rendered_nudge: str | None = None
    fleet_notice_key: str | None = None
    confusion_outcome: str | None = None


@dataclass(frozen=True)
class SupervisionRunContext:
    """Immutable bundle referencing fixture-owned authority/budgets, broker gate, fleet budget, and ledger."""

    receipt: AdmissionReceipt
    plan: CompiledWorkflowPlan
    authority_store: RunAuthorityStore
    broker_gate: SupervisionBrokerGate
    fleet_budget: FleetCheckBudget
    lease_registry: LaneLeaseRegistry
    ledger: CalibrationLedger


def _is_valid_sys1_response(resp: DecisionsAdapterResponse, choices: tuple[str, ...]) -> bool:
    return not resp.malformed and resp.choice is not None and resp.choice in choices


def _validate_blind_response(
    resp: BlindCheckResponse,
    approved_plan: CompiledWorkflowPlan,
) -> BlindToolCall | None:
    if resp.malformed or len(resp.tool_calls) != 1:
        return None
    call = resp.tool_calls[0]
    if call.tool == "health_record_ok":
        return call if not call.args else None
    arg_checks: dict[str, tuple[str, frozenset[str] | set[str]]] = {
        "health_nudge_lane": ("template_id", set(approved_plan.spec.templates_map.keys())),
        "health_escalate_human": ("category", ALLOWED_ESCALATION_CATEGORIES),
        "health_wake_orchestrator": ("reason_code", ALLOWED_WAKE_REASON_CODES),
    }
    spec = arg_checks.get(call.tool)
    if spec is None:
        return None
    key, allowed_values = spec
    if set(call.args.keys()) != {key}:
        return None
    return call if call.args[key] in allowed_values else None


def _execute_post_verdict_action(
    *,
    ctx: SupervisionRunContext,
    lane_state: LaneSupervisionState,
    frozen_snapshot: MetricSnapshot,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    tool_call: BlindToolCall,
    outcome: str,
) -> SupervisionTickResult:
    """Fetch fresh snapshot & clock, resolve admitted approved_plan, check freshness/pause/action, then act."""
    fresh_snapshot = snapshot_provider(lane_state.target)
    t_action = clock_provider()
    if fresh_snapshot.trusted.target != lane_state.target:
        return SupervisionTickResult(status="suppressed_snapshot_target_mismatch", confusion_outcome=outcome)

    try:
        record = ctx.authority_store.verify_active(ctx.receipt, clock=t_action, target=lane_state.target)
    except AuthorityError:
        return SupervisionTickResult(
            status="suppressed_post_verdict_authority_or_pause",
            confusion_outcome=outcome,
        )
    approved_plan = record.approved_plan

    if fresh_snapshot.trusted.progress_fingerprint != frozen_snapshot.trusted.progress_fingerprint:
        lane_state.last_progress = fresh_snapshot.trusted.progress_fingerprint
        lane_state.incident_seq += 1
        return SupervisionTickResult(status="suppressed_by_freshness_progress", confusion_outcome=outcome)
    if fresh_snapshot.trusted.human_input_lease_active and approved_plan.spec.limits.defer_nudge_during_human_lease:
        return SupervisionTickResult(status="deferred_post_verdict_human_lease", confusion_outcome=outcome)

    try:
        ctx.lease_registry.assert_can_act(
            ctx.receipt,
            lane_state.target,
            action=tool_call.tool,
            authority_store=ctx.authority_store,
            clock=t_action,
        )
    except (AuthorityError, LaneAuthorityError):
        return SupervisionTickResult(
            status="suppressed_post_verdict_authority_or_pause",
            confusion_outcome=outcome,
        )

    if tool_call.tool != "health_nudge_lane":
        return SupervisionTickResult(
            status="action_executed",
            action_taken=tool_call.tool,
            confusion_outcome=outcome,
        )

    tid = tool_call.args["template_id"]
    dedupe_key = f"{ctx.receipt.run_id}:{lane_state.target.sandbox_addr}:{lane_state.incident_seq}:{tid}"
    if not ctx.authority_store.allow_and_record_nudge(
        ctx.receipt, lane_state.target, dedupe_key=dedupe_key, clock=t_action
    ):
        return SupervisionTickResult(status="nudge_rate_or_dedupe_suppressed", confusion_outcome=outcome)
    rendered = render_template(
        approved_plan.spec.templates_map[tid],
        {
            "stall_seconds": fresh_snapshot.trusted.stall_seconds,
            "target_addr": lane_state.target.sandbox_addr,
            "workflow_id": approved_plan.spec.id,
        },
    )
    return SupervisionTickResult(
        status="action_executed",
        action_taken="health_nudge_lane",
        rendered_nudge=rendered,
        confusion_outcome=outcome,
    )


def dispatch_blind_with_post_verdict_freshness(
    *,
    ctx: SupervisionRunContext,
    lane_state: LaneSupervisionState,
    frozen_snapshot: MetricSnapshot,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    stratum: str,
    sys1_verdict: str | None,
    fleet_kind: Literal["triggered", "scheduled_audit"],
    update_throttle_window: bool = False,
) -> SupervisionTickResult:
    """Execute blind check via SupervisionBrokerGate using record.approved_plan throughout."""
    t_pre = clock_provider()
    record = ctx.authority_store.verify_active(ctx.receipt, clock=t_pre, target=lane_state.target)
    approved_plan = record.approved_plan
    if not ctx.authority_store.can_afford_blind(
        ctx.receipt, cost_microusd=approved_plan.blind_call_cost_microusd, clock=t_pre
    ):
        return SupervisionTickResult(
            status="blind_budget_exhausted_tier0_only",
            fleet_notice_key=f"budget_exhausted:{ctx.receipt.run_id}:blind",
        )

    slot = ctx.fleet_budget.acquire(kind=fleet_kind, clock=t_pre)
    if slot != "admitted":
        ctx.ledger.record_cap_event(
            run_id=ctx.receipt.run_id, target=lane_state.target, stratum=stratum, outcome=slot
        )
        if slot == "cap_dropped" and update_throttle_window:
            lane_state.enter_throttled(t_pre.monotonic_s + approved_plan.spec.limits.throttle_period_s)
        return SupervisionTickResult(status=f"{stratum}_{slot}")

    attempted = [False]

    def _mark_attempted() -> None:
        attempted[0] = True

    try:
        blind_resp = ctx.broker_gate.invoke_blind_check_live(
            receipt=ctx.receipt,
            target=lane_state.target,
            snapshot_for_model=frozen_snapshot,
            clock=clock_provider(),
            on_adapter_entry=_mark_attempted,
        )
    except BudgetExhaustedError:
        ctx.fleet_budget.rollback(fleet_kind)
        return SupervisionTickResult(
            status="blind_budget_exhausted_tier0_only",
            fleet_notice_key=f"budget_exhausted:{ctx.receipt.run_id}:blind",
        )
    except Exception:
        # Distinguish refusal BEFORE adapter entry (rollback) from failure AFTER entry (retain hourly charge)!
        if attempted[0]:
            ctx.fleet_budget.release()
        else:
            ctx.fleet_budget.rollback(fleet_kind)
        raise
    else:
        ctx.fleet_budget.release()

    if update_throttle_window:
        lane_state.enter_throttled(t_pre.monotonic_s + approved_plan.spec.limits.throttle_period_s)

    tool_call = _validate_blind_response(blind_resp, approved_plan)
    if tool_call is None:
        ctx.ledger.record_abstention(
            run_id=ctx.receipt.run_id, target=lane_state.target, stratum=stratum, source="blind"
        )
        return SupervisionTickResult(status="blind_abstained")

    healthy = approved_plan.spec.system1.abstain_default if approved_plan.spec.system1 else "healthy_progress"
    outcome = _classify_confusion(
        stratum=stratum,
        sys1_verdict=sys1_verdict,
        healthy_choice=healthy,
        blind_tool=tool_call.tool,
    )
    ctx.ledger.record_outcome(
        CalibrationRecord(
            sample_id=f"sample_{secrets.token_hex(6)}",
            run_id=ctx.receipt.run_id,
            workflow_id=approved_plan.spec.id,
            target=lane_state.target,
            stratum=stratum,
            frozen_snapshot=frozen_snapshot,
            sys1_verdict=sys1_verdict,
            blind_tool=tool_call.tool,
            confusion_outcome=outcome,
        )
    )
    if tool_call.tool == "health_record_ok":
        return SupervisionTickResult(status="verified_ok", confusion_outcome=outcome)

    return _execute_post_verdict_action(
        ctx=ctx,
        lane_state=lane_state,
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        clock_provider=clock_provider,
        tool_call=tool_call,
        outcome=outcome,
    )


def _handle_positive_canary(
    *,
    ctx: SupervisionRunContext,
    approved_plan: CompiledWorkflowPlan,
    lane_state: LaneSupervisionState,
    frozen_snapshot: MetricSnapshot,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    repeated_canary_threshold: int,
) -> tuple[DecisionsAdapterResponse | None, SupervisionTickResult | None]:
    sys1 = _require_system1(approved_plan)
    lane_state.canary_hits += 1
    try:
        reeval = ctx.broker_gate.invoke_decisions_live(
            receipt=ctx.receipt,
            target=lane_state.target,
            snapshot=frozen_snapshot,
            include_canary_question=False,
            metrics_only_override=True,
            clock=clock_provider(),
        )
    except BudgetExhaustedError:
        return None, SupervisionTickResult(
            status="canary_reeval_budget_exhausted_security_notice",
            fleet_notice_key=f"security_canary:{lane_state.target.sandbox_addr}",
        )
    if not _is_valid_sys1_response(reeval, sys1.choices):
        ctx.ledger.record_abstention(
            run_id=ctx.receipt.run_id, target=lane_state.target, stratum="canary_escalation", source="sys1"
        )
        return None, SupervisionTickResult(status="canary_reeval_abstained")
    if lane_state.canary_hits >= repeated_canary_threshold:
        res = dispatch_blind_with_post_verdict_freshness(
            ctx=ctx,
            lane_state=lane_state,
            frozen_snapshot=frozen_snapshot,
            snapshot_provider=snapshot_provider,
            clock_provider=clock_provider,
            stratum="canary_escalation",
            sys1_verdict=None,
            fleet_kind="triggered",
            update_throttle_window=False,
        )
        return None, res
    return reeval, None


def _evaluate_system1_with_canary(
    *,
    ctx: SupervisionRunContext,
    approved_plan: CompiledWorkflowPlan,
    lane_state: LaneSupervisionState,
    frozen_snapshot: MetricSnapshot,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    abstain_stratum: str,
    repeated_canary_threshold: int,
) -> tuple[DecisionsAdapterResponse | None, SupervisionTickResult | None]:
    sys1 = _require_system1(approved_plan)
    try:
        sys1_resp = ctx.broker_gate.invoke_decisions_live(
            receipt=ctx.receipt,
            target=lane_state.target,
            snapshot=frozen_snapshot,
            include_canary_question=sys1.canary_injection_question,
            metrics_only_override=False,
            clock=clock_provider(),
        )
    except BudgetExhaustedError:
        return None, SupervisionTickResult(
            status="decisions_budget_exhausted_tier0_only",
            fleet_notice_key=f"budget_exhausted:{ctx.receipt.run_id}:decisions",
        )
    if not _is_valid_sys1_response(sys1_resp, sys1.choices):
        ctx.ledger.record_abstention(
            run_id=ctx.receipt.run_id, target=lane_state.target, stratum=abstain_stratum, source="sys1"
        )
        return None, SupervisionTickResult(status="sys1_abstained_fail_closed")
    if not sys1_resp.injection_canary_positive:
        return sys1_resp, None
    return _handle_positive_canary(
        ctx=ctx,
        approved_plan=approved_plan,
        lane_state=lane_state,
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        clock_provider=clock_provider,
        repeated_canary_threshold=repeated_canary_threshold,
    )


def process_supervision_tick(
    ctx: SupervisionRunContext,
    lane_state: LaneSupervisionState,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    *,
    sleep_detector: HostSleepDetector,
    fault_coalescer: CorrelatedFaultCoalescer | None = None,
    repeated_canary_threshold: int = 2,
) -> SupervisionTickResult:
    """Run one supervision tick using strictly record.approved_plan from live RunAuthorityStore."""
    t0 = clock_provider()
    approved_plan = ctx.authority_store.verify_active(
        ctx.receipt, clock=t0, target=lane_state.target
    ).approved_plan
    if sleep_detector.observe_and_in_grace(t0, wake_grace_s=approved_plan.spec.limits.wake_grace_after_host_sleep_s):
        return SupervisionTickResult(status="deferred_wake_grace")

    frozen_snapshot = snapshot_provider(lane_state.target)
    if frozen_snapshot.trusted.human_input_lease_active and approved_plan.spec.limits.defer_nudge_during_human_lease:
        return SupervisionTickResult(status="deferred_human_lease")

    if fault_coalescer is not None:
        is_outage, notice_key = fault_coalescer.observe(frozen_snapshot.trusted)
        if is_outage:
            return SupervisionTickResult(status="coalesced_fleet_outage", fleet_notice_key=notice_key)

    if lane_state.mode == "THROTTLED" and t0.monotonic_s >= lane_state.window_end_mono:
        if lane_state.trailing_queued:
            return dispatch_blind_with_post_verdict_freshness(
                ctx=ctx,
                lane_state=lane_state,
                frozen_snapshot=frozen_snapshot,
                snapshot_provider=snapshot_provider,
                clock_provider=clock_provider,
                stratum="triggered_trailing",
                sys1_verdict=None,
                fleet_kind="triggered",
                update_throttle_window=True,
            )
        lane_state.mode = "IDLE"

    sys1_resp, early_res = _evaluate_system1_with_canary(
        ctx=ctx,
        approved_plan=approved_plan,
        lane_state=lane_state,
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        clock_provider=clock_provider,
        abstain_stratum="triggered_leading",
        repeated_canary_threshold=repeated_canary_threshold,
    )
    if early_res is not None or sys1_resp is None:
        return early_res or SupervisionTickResult(status="canary_reeval_abstained")

    if sys1_resp.choice == _require_system1(approved_plan).abstain_default:
        return SupervisionTickResult(status="healthy_no_action")

    if lane_state.mode == "THROTTLED":
        lane_state.trailing_queued = True
        lane_state.suppressed_count += 1
        return SupervisionTickResult(status="throttled_trailing_queued")

    return dispatch_blind_with_post_verdict_freshness(
        ctx=ctx,
        lane_state=lane_state,
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        clock_provider=clock_provider,
        stratum="triggered_leading",
        sys1_verdict=sys1_resp.choice,
        fleet_kind="triggered",
        update_throttle_window=True,
    )


def run_scheduled_audit(
    ctx: SupervisionRunContext,
    lane_state: LaneSupervisionState,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    *,
    stratum: str = "scheduled_audit_uniform",
    sleep_detector: HostSleepDetector | None = None,
    repeated_canary_threshold: int = 2,
) -> SupervisionTickResult:
    """Run scheduled active-lane unalerted audit using strictly record.approved_plan."""
    if not stratum.startswith("scheduled_audit"):
        raise SupervisionError(f"scheduled audit stratum must start with 'scheduled_audit', got {stratum!r}")
    t0 = clock_provider()
    approved_plan = ctx.authority_store.verify_active(
        ctx.receipt, clock=t0, target=lane_state.target
    ).approved_plan
    if sleep_detector is not None and sleep_detector.observe_and_in_grace(
        t0, wake_grace_s=approved_plan.spec.limits.wake_grace_after_host_sleep_s
    ):
        return SupervisionTickResult(status="deferred_wake_grace")
    frozen_snapshot = snapshot_provider(lane_state.target)
    if frozen_snapshot.trusted.human_input_lease_active and approved_plan.spec.limits.defer_nudge_during_human_lease:
        return SupervisionTickResult(status="deferred_human_lease")
    sys1_resp, early_res = _evaluate_system1_with_canary(
        ctx=ctx,
        approved_plan=approved_plan,
        lane_state=lane_state,
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        clock_provider=clock_provider,
        abstain_stratum=stratum,
        repeated_canary_threshold=repeated_canary_threshold,
    )
    if early_res is not None or sys1_resp is None:
        return early_res or SupervisionTickResult(status="canary_reeval_abstained")

    return dispatch_blind_with_post_verdict_freshness(
        ctx=ctx,
        lane_state=lane_state,
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        clock_provider=clock_provider,
        stratum=stratum,
        sys1_verdict=sys1_resp.choice,
        fleet_kind="scheduled_audit",
        update_throttle_window=False,
    )
