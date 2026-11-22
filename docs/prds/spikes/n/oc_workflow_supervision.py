"""Offline PRD N supervision primitives: disclosure gate, throttler, blind verifier, and replay."""

from __future__ import annotations

import base64
import json
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
    LaneLeaseRegistry,
    RunAuthorityStore,
    TargetIncarnation,
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
_UNTRUSTED_CLOSE_RE = re.compile(r"</\s*oc-untrusted-data", re.IGNORECASE)
_CONTROL_STRIP_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


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
    """Host-observed metrics plane."""

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

    def to_payload_dict(self) -> dict[str, Any]:
        return {
            "consecutive_errors": self.consecutive_errors,
            "error_class": self.error_class,
            "http_429_count": self.http_429_count,
            "http_5xx_count": self.http_5xx_count,
            "human_input_lease_active": self.human_input_lease_active,
            "last_transport_frame_at": self.last_transport_frame_at,
            "provider_route": self.provider_route,
            "quota_5h_remaining_pct": self.quota_5h_remaining_pct,
            "remote_worker": self.remote_worker,
            "stall_seconds": self.stall_seconds,
            "target_addr": self.target.sandbox_addr,
            "target_incarnation_id": self.target.incarnation_id,
        }


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
    escaped = _UNTRUSTED_CLOSE_RE.sub("&lt;/oc-untrusted-data", text)
    return f'<oc-untrusted-data nonce="{nonce}">{escaped}</oc-untrusted-data>'


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


def _extract_windows(secret: str) -> tuple[str, ...]:
    windows: set[str] = {secret}
    normalized = " ".join(secret.split())
    if len(normalized) >= 8:
        windows.add(normalized)
    raw_bytes = secret.encode("utf-8")
    b64_std = base64.b64encode(raw_bytes).decode("ascii").rstrip("=")
    b64_url = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
    if len(b64_std) >= 8:
        windows.add(b64_std)
    if len(b64_url) >= 8:
        windows.add(b64_url)
    if len(secret) >= 16:
        for i in range(0, len(secret) - 15, 4):
            windows.add(secret[i : i + 16])
    return tuple(windows)


class OverlapCanaryScanner:
    """Scans exact serialized bytes AND decoded string leaves for corpus secrets and token prefixes."""

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
        for leaf in decoded_leaves:
            self._scan_text(leaf)


# --- Budgets, HostSleepDetector & CorrelatedFaultCoalescer ---


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


class DecisionsRunBudget:
    """Per-run System-1 hourly call and cumulative integer-microdollar spend budget."""

    def __init__(self, *, max_calls_per_hour: int, max_spend_microusd: int) -> None:
        self._max_calls_per_hour = max_calls_per_hour
        self._max_spend_microusd = max_spend_microusd
        self._call_times: deque[float] = deque()
        self.spend_microusd_used: int = 0

    def _prune(self, now_mono: float) -> None:
        cutoff = now_mono - 3600.0
        while self._call_times and self._call_times[0] <= cutoff:
            self._call_times.popleft()

    def reserve(self, *, calls: int, cost_microusd: int, clock: ClockSnapshot) -> bool:
        self._prune(clock.monotonic_s)
        if len(self._call_times) + calls > self._max_calls_per_hour:
            return False
        if self.spend_microusd_used + cost_microusd > self._max_spend_microusd:
            return False
        for _ in range(calls):
            self._call_times.append(clock.monotonic_s)
        self.spend_microusd_used += cost_microusd
        return True


class BlindCheckRunBudget:
    """Per-run cumulative integer-microdollar spend budget for blind checks."""

    def __init__(self, *, max_spend_microusd: int) -> None:
        self._max_spend_microusd = max_spend_microusd
        self.spend_microusd_used: int = 0

    def can_afford(self, cost_microusd: int) -> bool:
        return self.spend_microusd_used + cost_microusd <= self._max_spend_microusd

    def reserve(self, cost_microusd: int) -> bool:
        if not self.can_afford(cost_microusd):
            return False
        self.spend_microusd_used += cost_microusd
        return True


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


class NudgeRunBudget:
    """Per-target interval/hourly cap, per-run total cap, and dedupe_key coalescing."""

    def __init__(
        self,
        *,
        min_nudge_interval_s: int,
        max_per_target_per_hour: int,
        max_total_per_run: int,
    ) -> None:
        self._min_interval_s = min_nudge_interval_s
        self._max_per_target_hr = max_per_target_per_hour
        self._max_total = max_total_per_run
        self._target_times: dict[TargetIncarnation, deque[float]] = {}
        self.total_nudges: int = 0
        self._seen_dedupe_keys: set[str] = set()

    def allow_and_record_nudge(
        self,
        target: TargetIncarnation,
        *,
        dedupe_key: str,
        clock: ClockSnapshot,
    ) -> bool:
        if dedupe_key in self._seen_dedupe_keys:
            return False
        if self.total_nudges >= self._max_total:
            return False
        times = self._target_times.setdefault(target, deque())
        cutoff = clock.monotonic_s - 3600.0
        while times and times[0] <= cutoff:
            times.popleft()
        if len(times) >= self._max_per_target_hr:
            return False
        if times and (clock.monotonic_s - times[-1]) < self._min_interval_s:
            return False
        times.append(clock.monotonic_s)
        self.total_nudges += 1
        self._seen_dedupe_keys.add(dedupe_key)
        return True


class ReplayGrantBudget:
    """Stateful per-grant_id cumulative call, microdollar, and revocation tracker."""

    def __init__(self) -> None:
        self._calls: dict[str, int] = {}
        self._spend: dict[str, int] = {}
        self._revoked: set[str] = set()

    def revoke(self, grant_id: str) -> None:
        self._revoked.add(grant_id)

    def is_revoked(self, grant_id: str) -> bool:
        return grant_id in self._revoked

    def calls_used(self, grant_id: str) -> int:
        return self._calls.get(grant_id, 0)

    def spend_used(self, grant_id: str) -> int:
        return self._spend.get(grant_id, 0)

    def reserve(
        self,
        *,
        grant_id: str,
        max_calls: int,
        max_spend_microusd: int,
        cost_microusd: int,
    ) -> bool:
        if grant_id in self._revoked:
            return False
        used_calls = self._calls.get(grant_id, 0)
        used_spend = self._spend.get(grant_id, 0)
        if used_calls + 1 > max_calls:
            return False
        if used_spend + cost_microusd > max_spend_microusd:
            return False
        self._calls[grant_id] = used_calls + 1
        self._spend[grant_id] = used_spend + cost_microusd
        return True


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


# --- Unified SupervisionBrokerGate choke point ---


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
    cleaned = _CONTROL_STRIP_RE.sub(" ", raw)
    raw_bytes = cleaned.encode("utf-8")[: policy.max_bytes]
    return raw_bytes.decode("utf-8", errors="ignore")


def _require_system1(plan: CompiledWorkflowPlan) -> System1Spec:
    sys1 = plan.spec.system1
    if sys1 is None:
        raise SupervisionError("plan has no system1 configuration")
    return sys1


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


class SupervisionBrokerGate:
    """Single mandatory choke point for ALL fake model invocations."""

    def __init__(
        self,
        *,
        decisions_adapter: LocalRulesDecisionsAdapter,
        blind_verifier: ScriptedBlindVerifier,
        canary_scanner: OverlapCanaryScanner,
    ) -> None:
        self._decisions_adapter = decisions_adapter
        self._blind_verifier = blind_verifier
        self._canary_scanner = canary_scanner

    def invoke_decisions_live(
        self,
        *,
        receipt: AdmissionReceipt,
        plan: CompiledWorkflowPlan,
        target: TargetIncarnation,
        snapshot: MetricSnapshot,
        include_canary_question: bool,
        metrics_only_override: bool,
        authority_store: RunAuthorityStore,
        decisions_budget: DecisionsRunBudget,
        clock: ClockSnapshot,
    ) -> DecisionsAdapterResponse:
        authority_store.verify_active(
            receipt,
            clock=clock,
            expected_plan_digest=plan.workflow_plan_digest,
            target=target,
        )
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
        if not decisions_budget.reserve(
            calls=1,
            cost_microusd=plan.decisions_call_cost_microusd,
            clock=clock,
        ):
            raise BudgetExhaustedError("decisions run budget exhausted")
        return self._decisions_adapter.evaluate(payload_bytes)

    def invoke_blind_check_live(
        self,
        *,
        receipt: AdmissionReceipt,
        plan: CompiledWorkflowPlan,
        target: TargetIncarnation,
        snapshot_for_model: MetricSnapshot,
        authority_store: RunAuthorityStore,
        blind_budget: BlindCheckRunBudget,
        clock: ClockSnapshot,
    ) -> BlindCheckResponse:
        authority_store.verify_active(
            receipt,
            clock=clock,
            expected_plan_digest=plan.workflow_plan_digest,
            target=target,
        )
        if plan.spec.blind_check is None or plan.blind_route is None:
            raise SupervisionError("plan has no blind_check configuration")
        payload_bytes, leaves = _build_blind_payload(
            plan=plan,
            snapshot=snapshot_for_model,
            blind_route=plan.blind_route,
        )
        self._canary_scanner.scan(payload_bytes, decoded_leaves=leaves)
        if not blind_budget.reserve(plan.blind_call_cost_microusd):
            raise BudgetExhaustedError("blind check run budget exhausted")
        return self._blind_verifier.check(payload_bytes)

    def invoke_decisions_replay(
        self,
        *,
        grant: CalibrationReplayGrant,
        grant_budget: ReplayGrantBudget,
        candidate_plan: CompiledWorkflowPlan,
        record: CalibrationRecord,
        authority_store: RunAuthorityStore,
        caller_id: str,
        caller_role: CallerRole,
        caller_subtree: frozenset[str],
        clock: ClockSnapshot,
    ) -> DecisionsAdapterResponse:
        if grant_budget.is_revoked(grant.grant_id):
            raise ReplayAuthorizationError("REPLAY_GRANT_REVOKED")
        if clock.wall_s >= grant.expires_at_wall_s:
            raise ReplayAuthorizationError("REPLAY_GRANT_EXPIRED")
        authority_store.verify_record_access(
            run_id=record.run_id,
            principal_id=caller_id,
            caller_role=caller_role,
            caller_subtree=caller_subtree,
            target=record.target,
            clock=clock,
        )
        sys1 = candidate_plan.spec.system1
        if sys1 is None:
            raise ReplayAuthorizationError("candidate plan has no system1 configuration")
        payload_bytes, leaves = _build_decisions_payload(
            plan=candidate_plan,
            snapshot=record.frozen_snapshot,
            effective_route=grant.approved_decisions_route,
            use="replay",
            include_canary_question=sys1.canary_injection_question,
            metrics_only_override=(grant.excerpt_disclosure_policy.mode == "none"),
        )
        self._canary_scanner.scan(payload_bytes, decoded_leaves=leaves)
        if not grant_budget.reserve(
            grant_id=grant.grant_id,
            max_calls=grant.max_replay_calls,
            max_spend_microusd=grant.max_replay_spend_microusd,
            cost_microusd=candidate_plan.decisions_call_cost_microusd,
        ):
            raise BudgetExhaustedError("replay grant call or spend budget exhausted")
        return self._decisions_adapter.evaluate(payload_bytes)


# --- Stratified CalibrationLedger & Replay ---


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


class CalibrationLedger:
    """Stratified reference-verdict confusion, inclusion-rate, cap-drop, and abstention ledger."""

    def __init__(self) -> None:
        self._records: dict[str, CalibrationRecord] = {}
        self._order: list[str] = []
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

    def record_abstention(self, *, stratum: str, source: Literal["sys1", "blind"]) -> None:
        st = self._stratum(stratum)
        if source == "sys1":
            st.sys1_abstentions += 1
        else:
            st.blind_abstentions += 1

    def record_cap_event(self, *, stratum: str, outcome: Literal["cap_delayed", "cap_dropped"]) -> None:
        st = self._stratum(stratum)
        if outcome == "cap_delayed":
            st.cap_delayed += 1
        else:
            st.cap_dropped += 1


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
    """Per-record authorized query; unauthorized rows are excluded from both results and aggregates."""
    authorized: list[CalibrationRecord] = []
    aggregates: dict[str, int] = {}
    for rec in ledger.all_records():
        if run_id is not None and rec.run_id != run_id:
            continue
        if strata is not None and rec.stratum not in strata:
            continue
        try:
            authority_store.verify_record_access(
                run_id=rec.run_id,
                principal_id=principal_id,
                caller_role=caller_role,
                caller_subtree=caller_subtree,
                target=rec.target,
                clock=clock,
            )
        except AuthorityError:
            continue
        authorized.append(rec)
        aggregates[rec.confusion_outcome] = aggregates.get(rec.confusion_outcome, 0) + 1
    return tuple(authorized), aggregates


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


@dataclass(frozen=True)
class ReplayScorecard:
    grant_id: str
    candidate_rubric_digest: str
    per_stratum: Mapping[str, Mapping[str, int]]
    abstentions: int
    evaluated_sample_ids: tuple[str, ...]


def _verify_replay_grant_and_plan(
    grant: CalibrationReplayGrant,
    grant_budget: ReplayGrantBudget,
    candidate_plan: CompiledWorkflowPlan,
    sample_ids: Sequence[str],
    *,
    caller_id: str,
    clock: ClockSnapshot,
) -> None:
    if grant_budget.is_revoked(grant.grant_id):
        raise ReplayAuthorizationError("REPLAY_GRANT_REVOKED")
    if clock.wall_s >= grant.expires_at_wall_s:
        raise ReplayAuthorizationError("REPLAY_GRANT_EXPIRED")
    if grant.requesting_principal != caller_id:
        raise ReplayAuthorizationError("REPLAY_PRINCIPAL_MISMATCH")
    if grant.workflow_id != candidate_plan.spec.id:
        raise ReplayAuthorizationError("REPLAY_WORKFLOW_MISMATCH")
    if candidate_plan.spec.system1 is None or candidate_plan.candidate_rubric_digest is None:
        raise ReplayAuthorizationError("candidate plan has no system1 rubric")
    if candidate_plan.candidate_rubric_digest != grant.candidate_rubric_digest:
        raise ReplayAuthorizationError("RUBRIC_DIGEST_MISMATCH")
    if candidate_plan.spec_digest != grant.candidate_spec_digest:
        raise ReplayAuthorizationError("SPEC_DIGEST_MISMATCH")
    if (
        candidate_plan.spec.system1.route != grant.approved_decisions_route
        or candidate_plan.spec.system1.model != grant.approved_model
    ):
        raise ReplayAuthorizationError("REPLAY_ROUTE_OR_MODEL_MISMATCH")
    if candidate_plan.spec.excerpt_disclosure != grant.excerpt_disclosure_policy:
        raise ReplayAuthorizationError("REPLAY_DISCLOSURE_POLICY_MISMATCH")
    if not sample_ids or len(sample_ids) != len(set(sample_ids)):
        raise ReplayAuthorizationError("sample_ids must be non-empty and deduplicated")
    if len(sample_ids) > grant.max_replay_samples:
        raise ReplayAuthorizationError("sample_ids exceed max_replay_samples")


def _authorize_replay_records(
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
    authorized: list[CalibrationRecord] = []
    for sid in sample_ids:
        rec = ledger.get_record(sid)
        if rec is None:
            raise ReplayAuthorizationError(f"unknown sample_id {sid!r}")
        if rec.run_id != grant.run_id:
            raise ReplayAuthorizationError(f"sample {sid!r} belongs to another run")
        if rec.stratum not in grant.authorized_sample_scope:
            raise ReplayAuthorizationError(
                f"sample {sid!r} stratum {rec.stratum!r} excluded by grant.authorized_sample_scope"
            )
        authority_store.verify_record_access(
            run_id=rec.run_id,
            principal_id=caller_id,
            caller_role=caller_role,
            caller_subtree=caller_subtree,
            target=rec.target,
            clock=clock,
        )
        authorized.append(rec)
    return authorized


def _classify_replay_bucket(
    resp: DecisionsAdapterResponse,
    *,
    choices: tuple[str, ...],
    abstain_default: str,
    ref_action: bool,
) -> str:
    if resp.malformed or resp.choice not in choices:
        return "abstain"
    is_alert = resp.choice != abstain_default
    if is_alert:
        return "TP" if ref_action else "FP"
    return "FN" if ref_action else "TN"


def run_calibration_replay(
    grant: CalibrationReplayGrant,
    grant_budget: ReplayGrantBudget,
    candidate_plan: CompiledWorkflowPlan,
    sample_ids: Sequence[str],
    ledger: CalibrationLedger,
    *,
    authority_store: RunAuthorityStore,
    broker_gate: SupervisionBrokerGate,
    caller_id: str,
    caller_role: CallerRole,
    caller_subtree: frozenset[str],
    clock_provider: Callable[[], ClockSnapshot],
) -> ReplayScorecard:
    """Run rubric-digest-bound, per-record & stratum-authorized offline calibration replay."""
    t_start = clock_provider()
    _verify_replay_grant_and_plan(
        grant, grant_budget, candidate_plan, sample_ids, caller_id=caller_id, clock=t_start
    )
    sys1 = candidate_plan.spec.system1
    if sys1 is None:
        raise ReplayAuthorizationError("candidate plan has no system1 configuration")

    authorized_records = _authorize_replay_records(
        grant,
        sample_ids,
        ledger,
        authority_store=authority_store,
        caller_id=caller_id,
        caller_role=caller_role,
        caller_subtree=caller_subtree,
        clock=t_start,
    )

    per_stratum: dict[str, dict[str, int]] = {}
    abstentions = 0
    evaluated: list[str] = []
    for rec in authorized_records:
        resp = broker_gate.invoke_decisions_replay(
            grant=grant,
            grant_budget=grant_budget,
            candidate_plan=candidate_plan,
            record=rec,
            authority_store=authority_store,
            caller_id=caller_id,
            caller_role=caller_role,
            caller_subtree=caller_subtree,
            clock=clock_provider(),
        )
        evaluated.append(rec.sample_id)
        bucket = per_stratum.setdefault(rec.stratum, {"TP": 0, "FP": 0, "TN": 0, "FN": 0, "abstain": 0})
        outcome = _classify_replay_bucket(
            resp,
            choices=sys1.choices,
            abstain_default=sys1.abstain_default,
            ref_action=(rec.blind_tool != "health_record_ok"),
        )
        bucket[outcome] += 1
        if outcome == "abstain":
            abstentions += 1

    return ReplayScorecard(
        grant_id=grant.grant_id,
        candidate_rubric_digest=candidate_plan.candidate_rubric_digest or "",
        per_stratum=per_stratum,
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


def _is_valid_sys1_response(resp: DecisionsAdapterResponse, choices: tuple[str, ...]) -> bool:
    return not resp.malformed and resp.choice is not None and resp.choice in choices


def _validate_blind_response(
    resp: BlindCheckResponse,
    plan: CompiledWorkflowPlan,
) -> BlindToolCall | None:
    if resp.malformed or len(resp.tool_calls) != 1:
        return None
    call = resp.tool_calls[0]
    if call.tool == "health_record_ok":
        return call if not call.args else None
    arg_checks: dict[str, tuple[str, frozenset[str] | set[str]]] = {
        "health_nudge_lane": ("template_id", set(plan.spec.templates_map.keys())),
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
    if stratum.startswith("scheduled_audit"):
        if not sys1_alert and not blind_action:
            return "TN"
        if not sys1_alert and blind_action:
            return "FN"
        return "TP" if blind_action else "FP"
    # triggered_leading
    if sys1_alert and not blind_action:
        return "FP"
    if sys1_alert and blind_action:
        if sys1_verdict == "escalate_human" and blind_tool != "health_escalate_human":
            return "class_mismatch"
        return "TP"
    return "FN" if blind_action else "TN"


def _execute_post_verdict_action(
    *,
    lane_state: LaneSupervisionState,
    frozen_snapshot: MetricSnapshot,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    tool_call: BlindToolCall,
    outcome: str,
    receipt: AdmissionReceipt,
    plan: CompiledWorkflowPlan,
    authority_store: RunAuthorityStore,
    nudge_budget: NudgeRunBudget,
    lease_registry: LaneLeaseRegistry,
) -> SupervisionTickResult:
    """Fetch fresh snapshot & clock after blind verdict, verify freshness & live authority, then act."""
    fresh_snapshot = snapshot_provider(lane_state.target)
    t_action = clock_provider()
    if fresh_snapshot.trusted.progress_fingerprint != frozen_snapshot.trusted.progress_fingerprint:
        lane_state.last_progress = fresh_snapshot.trusted.progress_fingerprint
        lane_state.incident_seq += 1
        return SupervisionTickResult(
            status="suppressed_by_freshness_progress",
            confusion_outcome=outcome,
        )
    if fresh_snapshot.trusted.human_input_lease_active and plan.spec.limits.defer_nudge_during_human_lease:
        return SupervisionTickResult(status="deferred_post_verdict_human_lease", confusion_outcome=outcome)

    try:
        authority_store.verify_active(
            receipt, clock=t_action, expected_plan_digest=plan.workflow_plan_digest, target=lane_state.target
        )
    except AuthorityError:
        return SupervisionTickResult(
            status="suppressed_post_verdict_authority_expired",
            confusion_outcome=outcome,
        )

    if tool_call.tool != "health_nudge_lane":
        return SupervisionTickResult(
            status="action_executed",
            action_taken=tool_call.tool,
            confusion_outcome=outcome,
        )

    if plan.spec.autonomy == "observe_only":
        return SupervisionTickResult(status="blocked_observe_only", confusion_outcome=outcome)
    lease_registry.assert_can_nudge(
        receipt, lane_state.target, authority_store=authority_store, clock=t_action
    )
    tid = tool_call.args["template_id"]
    dedupe_key = f"{receipt.run_id}:{lane_state.target.sandbox_addr}:{lane_state.incident_seq}:{tid}"
    if not nudge_budget.allow_and_record_nudge(lane_state.target, dedupe_key=dedupe_key, clock=t_action):
        return SupervisionTickResult(status="nudge_rate_or_dedupe_suppressed", confusion_outcome=outcome)
    rendered = render_template(
        plan.spec.templates_map[tid],
        {
            "stall_seconds": fresh_snapshot.trusted.stall_seconds,
            "target_addr": lane_state.target.sandbox_addr,
            "workflow_id": plan.spec.id,
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
    lane_state: LaneSupervisionState,
    frozen_snapshot: MetricSnapshot,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    stratum: str,
    sys1_verdict: str | None,
    fleet_kind: Literal["triggered", "scheduled_audit"],
    receipt: AdmissionReceipt,
    plan: CompiledWorkflowPlan,
    authority_store: RunAuthorityStore,
    broker_gate: SupervisionBrokerGate,
    blind_budget: BlindCheckRunBudget,
    fleet_budget: FleetCheckBudget,
    nudge_budget: NudgeRunBudget,
    lease_registry: LaneLeaseRegistry,
    ledger: CalibrationLedger,
    update_throttle_window: bool = False,
) -> SupervisionTickResult:
    """Execute blind check through SupervisionBrokerGate and apply post-verdict fresh snapshot & clock."""
    t_pre = clock_provider()
    authority_store.verify_active(
        receipt, clock=t_pre, expected_plan_digest=plan.workflow_plan_digest, target=lane_state.target
    )
    if not blind_budget.can_afford(plan.blind_call_cost_microusd):
        return SupervisionTickResult(
            status="blind_budget_exhausted_tier0_only",
            fleet_notice_key=f"budget_exhausted:{receipt.run_id}:blind",
        )

    slot = fleet_budget.acquire(kind=fleet_kind, clock=t_pre)
    if slot != "admitted":
        ledger.record_cap_event(stratum=stratum, outcome=slot)
        if slot == "cap_dropped" and update_throttle_window:
            lane_state.enter_throttled(t_pre.monotonic_s + plan.spec.limits.throttle_period_s)
        return SupervisionTickResult(status=f"{stratum}_{slot}")

    if update_throttle_window:
        lane_state.enter_throttled(t_pre.monotonic_s + plan.spec.limits.throttle_period_s)

    try:
        blind_resp = broker_gate.invoke_blind_check_live(
            receipt=receipt,
            plan=plan,
            target=lane_state.target,
            snapshot_for_model=frozen_snapshot,
            authority_store=authority_store,
            blind_budget=blind_budget,
            clock=clock_provider(),
        )
    except BudgetExhaustedError:
        return SupervisionTickResult(
            status="blind_budget_exhausted_tier0_only",
            fleet_notice_key=f"budget_exhausted:{receipt.run_id}:blind",
        )
    finally:
        fleet_budget.release()

    tool_call = _validate_blind_response(blind_resp, plan)
    if tool_call is None:
        ledger.record_abstention(stratum=stratum, source="blind")
        return SupervisionTickResult(status="blind_abstained")

    healthy = plan.spec.system1.abstain_default if plan.spec.system1 else "healthy_progress"
    outcome = _classify_confusion(
        stratum=stratum,
        sys1_verdict=sys1_verdict,
        healthy_choice=healthy,
        blind_tool=tool_call.tool,
    )
    ledger.record_outcome(
        CalibrationRecord(
            sample_id=f"sample_{secrets.token_hex(6)}",
            run_id=receipt.run_id,
            workflow_id=plan.spec.id,
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
        lane_state=lane_state,
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        clock_provider=clock_provider,
        tool_call=tool_call,
        outcome=outcome,
        receipt=receipt,
        plan=plan,
        authority_store=authority_store,
        nudge_budget=nudge_budget,
        lease_registry=lease_registry,
    )


def _handle_positive_canary(
    *,
    lane_state: LaneSupervisionState,
    frozen_snapshot: MetricSnapshot,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    receipt: AdmissionReceipt,
    plan: CompiledWorkflowPlan,
    authority_store: RunAuthorityStore,
    broker_gate: SupervisionBrokerGate,
    decisions_budget: DecisionsRunBudget,
    blind_budget: BlindCheckRunBudget,
    fleet_budget: FleetCheckBudget,
    nudge_budget: NudgeRunBudget,
    lease_registry: LaneLeaseRegistry,
    ledger: CalibrationLedger,
    repeated_canary_threshold: int,
) -> tuple[DecisionsAdapterResponse | None, SupervisionTickResult | None]:
    sys1 = _require_system1(plan)
    lane_state.canary_hits += 1
    try:
        reeval = broker_gate.invoke_decisions_live(
            receipt=receipt,
            plan=plan,
            target=lane_state.target,
            snapshot=frozen_snapshot,
            include_canary_question=False,
            metrics_only_override=True,
            authority_store=authority_store,
            decisions_budget=decisions_budget,
            clock=clock_provider(),
        )
    except BudgetExhaustedError:
        return None, SupervisionTickResult(
            status="canary_reeval_budget_exhausted_security_notice",
            fleet_notice_key=f"security_canary:{lane_state.target.sandbox_addr}",
        )
    if not _is_valid_sys1_response(reeval, plan.spec.system1.choices):
        ledger.record_abstention(stratum="canary_escalation", source="sys1")
        return None, SupervisionTickResult(status="canary_reeval_abstained")
    if lane_state.canary_hits >= repeated_canary_threshold:
        res = dispatch_blind_with_post_verdict_freshness(
            lane_state=lane_state,
            frozen_snapshot=frozen_snapshot,
            snapshot_provider=snapshot_provider,
            clock_provider=clock_provider,
            stratum="canary_escalation",
            sys1_verdict=None,
            fleet_kind="triggered",
            receipt=receipt,
            plan=plan,
            authority_store=authority_store,
            broker_gate=broker_gate,
            blind_budget=blind_budget,
            fleet_budget=fleet_budget,
            nudge_budget=nudge_budget,
            lease_registry=lease_registry,
            ledger=ledger,
            update_throttle_window=False,
        )
        return None, res
    return reeval, None


def process_supervision_tick(
    lane_state: LaneSupervisionState,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    *,
    receipt: AdmissionReceipt,
    plan: CompiledWorkflowPlan,
    sleep_detector: HostSleepDetector,
    authority_store: RunAuthorityStore,
    broker_gate: SupervisionBrokerGate,
    decisions_budget: DecisionsRunBudget,
    blind_budget: BlindCheckRunBudget,
    fleet_budget: FleetCheckBudget,
    nudge_budget: NudgeRunBudget,
    lease_registry: LaneLeaseRegistry,
    ledger: CalibrationLedger,
    fault_coalescer: CorrelatedFaultCoalescer | None = None,
    repeated_canary_threshold: int = 2,
) -> SupervisionTickResult:
    """Run one supervision tick with sleep detection, throttler-before-System-1, and broker gate."""
    t0 = clock_provider()
    authority_store.verify_active(
        receipt, clock=t0, expected_plan_digest=plan.workflow_plan_digest, target=lane_state.target
    )
    if sleep_detector.observe_and_in_grace(t0, wake_grace_s=plan.spec.limits.wake_grace_after_host_sleep_s):
        return SupervisionTickResult(status="deferred_wake_grace")

    frozen_snapshot = snapshot_provider(lane_state.target)
    if frozen_snapshot.trusted.human_input_lease_active and plan.spec.limits.defer_nudge_during_human_lease:
        return SupervisionTickResult(status="deferred_human_lease")

    if fault_coalescer is not None:
        is_outage, notice_key = fault_coalescer.observe(frozen_snapshot.trusted)
        if is_outage:
            return SupervisionTickResult(status="coalesced_fleet_outage", fleet_notice_key=notice_key)

    # Check THROTTLED window boundary BEFORE System-1 so triggered_trailing genuinely bypasses System-1!
    if lane_state.mode == "THROTTLED" and t0.monotonic_s >= lane_state.window_end_mono:
        if lane_state.trailing_queued:
            return dispatch_blind_with_post_verdict_freshness(
                lane_state=lane_state,
                frozen_snapshot=frozen_snapshot,
                snapshot_provider=snapshot_provider,
                clock_provider=clock_provider,
                stratum="triggered_trailing",
                sys1_verdict=None,
                fleet_kind="triggered",
                receipt=receipt,
                plan=plan,
                authority_store=authority_store,
                broker_gate=broker_gate,
                blind_budget=blind_budget,
                fleet_budget=fleet_budget,
                nudge_budget=nudge_budget,
                lease_registry=lease_registry,
                ledger=ledger,
                update_throttle_window=True,
            )
        lane_state.mode = "IDLE"

    sys1 = _require_system1(plan)
    try:
        sys1_resp = broker_gate.invoke_decisions_live(
            receipt=receipt,
            plan=plan,
            target=lane_state.target,
            snapshot=frozen_snapshot,
            include_canary_question=sys1.canary_injection_question,
            metrics_only_override=False,
            authority_store=authority_store,
            decisions_budget=decisions_budget,
            clock=clock_provider(),
        )
    except BudgetExhaustedError:
        return SupervisionTickResult(
            status="decisions_budget_exhausted_tier0_only",
            fleet_notice_key=f"budget_exhausted:{receipt.run_id}:decisions",
        )

    if not _is_valid_sys1_response(sys1_resp, sys1.choices):
        ledger.record_abstention(stratum="triggered_leading", source="sys1")
        return SupervisionTickResult(status="sys1_abstained_fail_closed")

    if sys1_resp.injection_canary_positive:
        reeval, early_res = _handle_positive_canary(
            lane_state=lane_state,
            frozen_snapshot=frozen_snapshot,
            snapshot_provider=snapshot_provider,
            clock_provider=clock_provider,
            receipt=receipt,
            plan=plan,
            authority_store=authority_store,
            broker_gate=broker_gate,
            decisions_budget=decisions_budget,
            blind_budget=blind_budget,
            fleet_budget=fleet_budget,
            nudge_budget=nudge_budget,
            lease_registry=lease_registry,
            ledger=ledger,
            repeated_canary_threshold=repeated_canary_threshold,
        )
        if early_res is not None:
            return early_res
        if reeval is None:
            return SupervisionTickResult(status="canary_reeval_abstained")
        sys1_resp = reeval

    if sys1_resp.choice == sys1.abstain_default:
        return SupervisionTickResult(status="healthy_no_action")

    if lane_state.mode == "THROTTLED":
        lane_state.trailing_queued = True
        lane_state.suppressed_count += 1
        return SupervisionTickResult(status="throttled_trailing_queued")

    return dispatch_blind_with_post_verdict_freshness(
        lane_state=lane_state,
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        clock_provider=clock_provider,
        stratum="triggered_leading",
        sys1_verdict=sys1_resp.choice,
        fleet_kind="triggered",
        receipt=receipt,
        plan=plan,
        authority_store=authority_store,
        broker_gate=broker_gate,
        blind_budget=blind_budget,
        fleet_budget=fleet_budget,
        nudge_budget=nudge_budget,
        lease_registry=lease_registry,
        ledger=ledger,
        update_throttle_window=True,
    )


def run_scheduled_audit(
    lane_state: LaneSupervisionState,
    snapshot_provider: Callable[[TargetIncarnation], MetricSnapshot],
    clock_provider: Callable[[], ClockSnapshot],
    *,
    stratum: str = "scheduled_audit_uniform",
    receipt: AdmissionReceipt,
    plan: CompiledWorkflowPlan,
    authority_store: RunAuthorityStore,
    broker_gate: SupervisionBrokerGate,
    decisions_budget: DecisionsRunBudget,
    blind_budget: BlindCheckRunBudget,
    fleet_budget: FleetCheckBudget,
    nudge_budget: NudgeRunBudget,
    lease_registry: LaneLeaseRegistry,
    ledger: CalibrationLedger,
) -> SupervisionTickResult:
    """Run scheduled active-lane unalerted audit drawing from non-starvable fleet audit floor."""
    frozen_snapshot = snapshot_provider(lane_state.target)
    sys1 = _require_system1(plan)
    try:
        sys1_resp = broker_gate.invoke_decisions_live(
            receipt=receipt,
            plan=plan,
            target=lane_state.target,
            snapshot=frozen_snapshot,
            include_canary_question=sys1.canary_injection_question,
            metrics_only_override=False,
            authority_store=authority_store,
            decisions_budget=decisions_budget,
            clock=clock_provider(),
        )
    except BudgetExhaustedError:
        return SupervisionTickResult(status="decisions_budget_exhausted_tier0_only")
    if not _is_valid_sys1_response(sys1_resp, sys1.choices):
        ledger.record_abstention(stratum=stratum, source="sys1")
        return SupervisionTickResult(status="sys1_abstained_fail_closed")

    return dispatch_blind_with_post_verdict_freshness(
        lane_state=lane_state,
        frozen_snapshot=frozen_snapshot,
        snapshot_provider=snapshot_provider,
        clock_provider=clock_provider,
        stratum=stratum,
        sys1_verdict=sys1_resp.choice,
        fleet_kind="scheduled_audit",
        receipt=receipt,
        plan=plan,
        authority_store=authority_store,
        broker_gate=broker_gate,
        blind_budget=blind_budget,
        fleet_budget=fleet_budget,
        nudge_budget=nudge_budget,
        lease_registry=lease_registry,
        ledger=ledger,
        update_throttle_window=False,
    )
