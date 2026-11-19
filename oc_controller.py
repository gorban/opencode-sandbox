"""Offline approval policy for PRD I. Identity and adapter inputs are trusted fixtures."""
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from hashlib import sha256
import json
import re
from threading import Lock
from typing import Protocol


class Role(StrEnum):
    OPERATOR = "operator"
    ORCHESTRATOR = "orchestrator"
    WORKER_HOST = "worker_host"
    JOB = "job"


class Intent(StrEnum):
    PROBE_GRANT = "probe_grant"
    APPLY_ONCE = "apply_once"


class Operation(StrEnum):
    PROBE = "probe"
    APPLY = "apply"


class Decision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class State(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    ELIGIBLE_RETRY = "eligible_retry"
    REJECTED = "rejected"
    STALE = "stale"
    EXPIRED = "expired"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNCERTAIN = "uncertain"


class Reason(StrEnum):
    APPROVAL_NEEDED = "approval_needed"
    APPROVED = "approved"
    REJECTED = "rejected"
    STALE = "stale"
    EXPIRED = "expired"
    REVOKED = "revoked"
    READY = "ready"
    RETRY = "retry"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    UNAVAILABLE = "unavailable"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNCERTAIN = "uncertain"


class Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    DEFINITE_FAILURE = "definite_failure"
    TRANSIENT_FAILURE = "transient_failure"
    UNKNOWN = "unknown"


class ProbeResult(StrEnum):
    OK = "ok"


class Denied(Exception):
    """A principal, operation, or record is inaccessible."""


class InvalidRequest(Exception):
    """The request failed the closed schema or catalog checks."""


class Unavailable(Exception):
    """A trusted fixture lookup or clock sample could not be used."""


class Conflict(Exception):
    """The requested transition cannot be performed in the current state."""


class CapacityExceeded(Exception):
    """The subject's allocation for this incarnation has been exhausted."""


@dataclass(frozen=True, slots=True)
class Principal:
    role: Role
    identifier: str


@dataclass(frozen=True, slots=True)
class Subject:
    worker_enrollment: str
    job_incarnation: str
    channel: str


@dataclass(frozen=True, slots=True)
class Worker:
    enrollment: str
    operator: Principal


@dataclass(frozen=True, slots=True)
class Job:
    subject: Subject
    orchestrator: Principal
    proposal_budget: int


@dataclass(frozen=True, slots=True)
class Capability:
    identifier: str
    operation: Operation
    target: str


@dataclass(frozen=True, slots=True)
class Reference:
    identifier: str
    capability: str


@dataclass(frozen=True, slots=True)
class Proposal:
    intent: Intent
    alias: str
    reference: str


@dataclass(frozen=True, slots=True)
class Pin:
    target: str
    revision: str
    alias_generation: int


@dataclass(frozen=True, slots=True)
class Payload:
    format_version: int
    incarnation: str
    request_id: str
    revision: int
    subject: Subject
    operator_session: str
    intent: Intent
    operation: Operation
    alias: str
    pin: Pin
    scope: str
    reference: str
    capability: str
    expires_at: int

    def digest(self) -> str:
        encoded = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Status:
    request_id: str
    target: str
    state: State
    reason: Reason
    eligible: bool
    revoked: bool
    consumed: bool
    probe_result: ProbeResult | None = None


@dataclass(frozen=True, slots=True)
class View:
    payload: Payload
    digest: str
    status: Status


@dataclass(frozen=True, slots=True)
class Event:
    status: Status
    worker_enrollment: str
    job_incarnation: str


@dataclass(frozen=True, slots=True)
class _DecisionRecord:
    actor: Principal
    decision: Decision
    revision: int
    digest: str


@dataclass(frozen=True, slots=True)
class _Revocation:
    actor: Principal
    ticks: int | None


@dataclass(slots=True)
class _Request:
    payload: Payload
    digest: str
    state: State = State.PENDING
    reason: Reason = Reason.APPROVAL_NEEDED
    attempts: int = 0
    consumed: bool = False
    decision: _DecisionRecord | None = None
    revocation: _Revocation | None = None

    def effect_key(self) -> tuple[Operation, str, str]:
        return self.payload.operation, self.payload.pin.target, self.payload.scope


@dataclass(frozen=True, slots=True)
class Attempt:
    request_id: str
    number: int


class FixtureAdapter(Protocol):
    """Synchronous fixture only. All calls run under the controller lock.

    dispatch checks the pinned revision as part of its synthetic effect. For
    APPLY, its journal is the effect: SUCCEEDED means applied and DEFINITE_FAILURE
    means terminal proof of absence. A missing journal entry is UNKNOWN.
    """

    def target_revision(self, target: str) -> str | None: ...

    def set_target_revision(self, target: str, revision: str | None) -> None: ...

    def dispatch(self, attempt: Attempt, payload: Payload) -> Outcome: ...

    def reconcile(self, attempt: Attempt, payload: Payload) -> Outcome: ...


_ID = re.compile(r"[a-zA-Z0-9_-]{1,64}", re.ASCII)
_INCARNATION_ID = re.compile(r"[0-9a-f]{32}", re.ASCII)
_REQUEST_ID = re.compile(r"[0-9a-f]{64}", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_MAX_TICKS = (1 << 63) - 1
_MAX_PROPOSALS_PER_JOB = 1024
_PROBE_ATTEMPTS = 3
# Proposal, decision, each attempt's outcome, an expiry/stale transition,
# revocation, and reconciliation. Reserve this upper bound at admission.
_EVENTS_PER_REQUEST = 1 + 1 + _PROBE_ATTEMPTS + 1 + 1 + 1
_INTENTS = {
    Intent.PROBE_GRANT: (Operation.PROBE, "fixture:probe", _PROBE_ATTEMPTS),
    Intent.APPLY_ONCE: (Operation.APPLY, "fixture:apply", 1),
}
_DISPATCHABLE = (State.APPROVED, State.ELIGIBLE_RETRY)
_REVOCABLE = (State.PENDING, *_DISPATCHABLE, State.UNCERTAIN)


def _matches(value: object, pattern: re.Pattern, length: int) -> bool:
    return type(value) is str and len(value) <= length and pattern.fullmatch(value) is not None


def _valid_id(value: object) -> bool:
    return _matches(value, _ID, 64)


def _valid_principal(value: object, role: Role | None = None) -> bool:
    return (
        type(value) is Principal
        and type(value.role) is Role
        and (role is None or value.role is role)
        and _valid_id(value.identifier)
    )


def _valid_subject(value: object) -> bool:
    return type(value) is Subject and all(
        _valid_id(component)
        for component in (value.worker_enrollment, value.job_incarnation, value.channel)
    )


class Controller:
    """Authorize modeled identities and mediate a fixed, trusted fixture adapter.

    The trusted caller supplies a fresh incarnation ID and fixture adapter for
    each start. A clock returns monotonic integer ticks for that incarnation.
    """

    def __init__(
        self,
        *,
        incarnation: str,
        clock: Callable[[], int],
        lifetime: int,
        workers: Iterable[Worker],
        jobs: Iterable[Job],
        capabilities: Iterable[Capability],
        references: Iterable[Reference],
        adapter: FixtureAdapter,
    ):
        if not _matches(incarnation, _INCARNATION_ID, 32):
            raise ValueError("invalid fixture incarnation")
        if type(lifetime) is not int or not 0 < lifetime <= _MAX_TICKS:
            raise ValueError("invalid approval lifetime")
        self._incarnation = incarnation
        self._clock = clock
        self._lifetime = lifetime
        self._adapter = adapter
        self._lock = Lock()
        self._operators = {}
        for worker in workers:
            if (
                type(worker) is not Worker
                or not _valid_id(worker.enrollment)
                or not _valid_principal(worker.operator, Role.OPERATOR)
                or worker.enrollment in self._operators
            ):
                raise ValueError("invalid or duplicate worker assignment")
            self._operators[worker.enrollment] = worker.operator
        self._jobs = {}
        self._jobs_by_channel = {}
        incarnations = set()
        for job in jobs:
            if (
                type(job) is not Job
                or not _valid_subject(job.subject)
                or job.subject.worker_enrollment not in self._operators
                or job.subject.channel in self._jobs_by_channel
                or not _valid_principal(job.orchestrator, Role.ORCHESTRATOR)
                or type(job.proposal_budget) is not int
                or not 0 < job.proposal_budget <= _MAX_PROPOSALS_PER_JOB
            ):
                raise ValueError("invalid or duplicate job assignment")
            incarnation_key = job.subject.worker_enrollment, job.subject.job_incarnation
            if incarnation_key in incarnations:
                raise ValueError("multiple channels for one job incarnation")
            incarnations.add(incarnation_key)
            self._jobs[job.subject] = job
            self._jobs_by_channel[job.subject.channel] = job
        self._capabilities = {}
        for capability in capabilities:
            if (
                type(capability) is not Capability
                or not _valid_id(capability.identifier)
                or type(capability.operation) is not Operation
                or not _valid_id(capability.target)
                or capability.identifier in self._capabilities
            ):
                raise ValueError("invalid or duplicate capability")
            self._capabilities[capability.identifier] = capability
        self._references = {}
        for reference in references:
            if (
                type(reference) is not Reference
                or not _valid_id(reference.identifier)
                or not _valid_id(reference.capability)
                or reference.capability not in self._capabilities
                or reference.identifier in self._references
            ):
                raise ValueError("invalid or duplicate reference")
            self._references[reference.identifier] = reference

        proposal_limit = sum(job.proposal_budget for job in self._jobs.values())
        self._admitted = dict.fromkeys(self._jobs, 0)
        self._requests = {}
        self._events = {subject: [] for subject in self._jobs}
        self._reserved_events = 0
        self._event_limit = proposal_limit * _EVENTS_PER_REQUEST
        self._aliases = {}
        self._withdrawn = set()
        self._fences = set()

    def _set_alias(self, alias, target):
        """Change fixture resolution under the same lock as approval and dispatch."""
        if not _valid_id(alias) or (target is not None and not _valid_id(target)):
            raise ValueError("invalid alias binding")
        with self._lock:
            _, generation = self._aliases.get(alias, (None, 0))
            self._aliases[alias] = target, generation + 1

    def _set_target_revision(self, target, revision):
        if not _valid_id(target) or (revision is not None and not _valid_id(revision)):
            raise ValueError("invalid target revision")
        with self._lock:
            if self._adapter.target_revision(target) == revision:
                return
            self._adapter.set_target_revision(target, revision)
            # A changed resolution invalidates older pins even if later restored.
            for alias, (bound, generation) in self._aliases.items():
                if bound == target:
                    self._aliases[alias] = bound, generation + 1

    def _withdraw_capability(self, identifier):
        if not _valid_id(identifier) or identifier not in self._capabilities:
            raise ValueError("invalid capability")
        with self._lock:
            self._withdrawn.add(identifier)

    def _now(self):
        try:
            ticks = self._clock()
        except Exception:
            raise Unavailable() from None
        if type(ticks) is not int or not 0 <= ticks <= _MAX_TICKS:
            raise Unavailable()
        return ticks

    def _revocation_ticks(self):
        try:
            return self._now()
        except Unavailable:
            return None

    def _job(self, actor):
        if not _valid_principal(actor, Role.JOB):
            raise Denied()
        job = self._jobs_by_channel.get(actor.identifier)
        if job is None:
            raise Denied()
        return job

    def _operator(self, actor, worker):
        if not _valid_principal(actor, Role.OPERATOR) or self._operators.get(worker) != actor:
            raise Denied()

    def _reader(self, actor, subject):
        if not _valid_principal(actor):
            raise Denied()
        if actor.role is Role.OPERATOR and actor == self._operators[subject.worker_enrollment]:
            return
        if actor.role is Role.ORCHESTRATOR and actor == self._jobs[subject].orchestrator:
            return
        if actor.role is Role.JOB and actor.identifier == subject.channel:
            return
        raise Denied()

    def _request(self, request_id):
        if not _matches(request_id, _REQUEST_ID, 64):
            raise Denied()
        request = self._requests.get(request_id)
        if request is None:
            raise Denied()
        return request

    def _resolve(self, alias):
        target, generation = self._aliases.get(alias, (None, 0))
        if target is None:
            return None
        try:
            revision = self._adapter.target_revision(target)
        except Exception:
            raise Unavailable() from None
        if not _valid_id(revision):
            return None
        return Pin(target, revision, generation)

    def _live(self, request):
        """Evaluate the pin before taking the last clock sample for dispatch."""
        payload = request.payload
        try:
            pin_matches = (
                payload.capability not in self._withdrawn
                and self._resolve(payload.alias) == payload.pin
            )
            now = self._now()
        except Unavailable:
            return Reason.UNAVAILABLE
        if now >= payload.expires_at:
            return Reason.EXPIRED
        if not pin_matches:
            return Reason.STALE
        return Reason.READY

    def _eligibility(self, request):
        if request.revocation is not None:
            return Reason.REVOKED
        if request.state is State.PENDING:
            live = self._live(request)
            return request.reason if live is Reason.READY else live
        if request.state not in _DISPATCHABLE or request.consumed:
            return request.reason
        live = self._live(request)
        if live is not Reason.READY:
            return live
        ready = Reason.RETRY if request.state is State.ELIGIBLE_RETRY else Reason.READY
        return self._dispatch_eligibility(request, ready)

    def _dispatch_eligibility(self, request, ready):
        """Check in-memory dispatch blockers after a successful liveness check."""
        if request.attempts >= _INTENTS[request.payload.intent][2]:
            return Reason.ATTEMPTS_EXHAUSTED
        if request.effect_key() in self._fences:
            return Reason.UNAVAILABLE
        return ready

    def _status(self, request, reason):
        if request.revocation is not None:
            reason = Reason.REVOKED
        return Status(
            request.payload.request_id,
            request.payload.pin.target,
            request.state,
            reason,
            reason in (Reason.READY, Reason.RETRY),
            request.revocation is not None,
            request.consumed,
        )

    def _emit(self, request, reason, eligibility=None):
        subject = request.payload.subject
        # A transition and its event use the same checked eligibility. Event
        # construction performs no fixture reads after a state change.
        status = self._status(request, reason if eligibility is None else eligibility)
        self._events[subject].append(Event(
            replace(status, reason=reason), subject.worker_enrollment, subject.job_incarnation
        ))
        return status

    def _transition(self, request, state, reason, eligibility=None):
        request.state = state
        request.reason = reason
        return self._emit(request, reason, eligibility)

    def propose(self, actor: Principal, proposal: Proposal) -> Status:
        with self._lock:
            job = self._job(actor)
            if (
                type(proposal) is not Proposal
                or type(proposal.intent) is not Intent
                or not _valid_id(proposal.alias)
                or not _valid_id(proposal.reference)
            ):
                raise InvalidRequest()
            if (
                self._admitted[job.subject] >= job.proposal_budget
                or self._reserved_events + _EVENTS_PER_REQUEST > self._event_limit
            ):
                raise CapacityExceeded()
            reference = self._references.get(proposal.reference)
            if reference is None or reference.capability in self._withdrawn:
                raise InvalidRequest()
            binding = self._capabilities[reference.capability]
            operation, scope, _ = _INTENTS[proposal.intent]
            pin = self._resolve(proposal.alias)
            if pin is None or binding.operation is not operation or binding.target != pin.target:
                raise InvalidRequest()
            expires_at = self._now() + self._lifetime
            if expires_at > _MAX_TICKS:
                raise Unavailable()
            ordinal = self._admitted[job.subject] + 1
            # A subject's IDs do not expose the order of other subjects' requests.
            seed = f"{self._incarnation}:{job.subject.channel}:{ordinal}"
            request_id = sha256(seed.encode("ascii")).hexdigest()
            if request_id in self._requests:
                raise RuntimeError("fixture request ID collision")
            payload = Payload(
                1, self._incarnation, request_id, 1, job.subject,
                self._operators[job.subject.worker_enrollment].identifier, proposal.intent,
                operation, proposal.alias, pin, scope, reference.identifier, binding.identifier,
                expires_at,
            )
            request = _Request(payload, payload.digest())
            self._admitted[job.subject] += 1
            self._reserved_events += _EVENTS_PER_REQUEST
            self._requests[request_id] = request
            return self._emit(request, Reason.APPROVAL_NEEDED)

    def view(self, actor: Principal, request_id: str) -> View:
        with self._lock:
            request = self._request(request_id)
            payload = request.payload
            self._operator(actor, payload.subject.worker_enrollment)
            copied = replace(payload, subject=replace(payload.subject), pin=replace(payload.pin))
            return View(copied, request.digest, self._status(request, self._eligibility(request)))

    def status(self, actor: Principal, request_id: str) -> Status:
        with self._lock:
            request = self._request(request_id)
            self._reader(actor, request.payload.subject)
            return self._status(request, self._eligibility(request))

    def events(self, actor: Principal, subject: Subject) -> tuple[Event, ...]:
        with self._lock:
            if not _valid_subject(subject) or subject not in self._jobs:
                raise Denied()
            self._reader(actor, subject)
            return tuple(
                replace(event, status=replace(event.status)) for event in self._events[subject]
            )

    def decide(
        self, actor: Principal, request_id: str, revision: int, digest: str, decision: Decision
    ) -> Status:
        with self._lock:
            request = self._request(request_id)
            self._operator(actor, request.payload.subject.worker_enrollment)
            if (
                type(revision) is not int
                or revision != request.payload.revision
                or not _matches(digest, _DIGEST, 64)
                or digest != request.digest
                or type(decision) is not Decision
            ):
                raise InvalidRequest()
            if request.state is not State.PENDING or request.revocation is not None:
                raise Conflict()
            live = self._live(request)
            if live is Reason.EXPIRED:
                return self._transition(request, State.EXPIRED, live)
            if live is Reason.STALE:
                return self._transition(request, State.STALE, live)
            if live is not Reason.READY:
                return self._status(request, live)
            request.decision = _DecisionRecord(actor, decision, revision, digest)
            if decision is Decision.APPROVE:
                eligibility = self._dispatch_eligibility(request, Reason.READY)
                return self._transition(request, State.APPROVED, Reason.APPROVED, eligibility)
            return self._transition(request, State.REJECTED, Reason.REJECTED)

    def invoke(self, actor: Principal, request_id: str) -> Status:
        with self._lock:
            job = self._job(actor)
            request = self._request(request_id)
            if job.subject != request.payload.subject:
                raise Denied()
            if (
                request.state not in _DISPATCHABLE
                or request.revocation is not None
                or request.consumed
            ):
                raise Conflict()
            eligibility = self._eligibility(request)
            if eligibility is Reason.EXPIRED:
                return self._transition(request, State.EXPIRED, eligibility)
            if eligibility is Reason.STALE:
                return self._transition(request, State.STALE, eligibility)
            if eligibility not in (Reason.READY, Reason.RETRY):
                return self._status(request, eligibility)

            request.attempts += 1
            attempt = Attempt(request_id, request.attempts)
            one_shot = request.payload.intent is Intent.APPLY_ONCE
            # This record's full event budget was reserved on admission.
            if one_shot:
                request.consumed = True
                self._fences.add(request.effect_key())
            try:
                outcome = self._adapter.dispatch(attempt, request.payload)
            except Exception:
                outcome = Outcome.UNKNOWN

            if outcome is Outcome.SUCCEEDED or outcome is Outcome.DEFINITE_FAILURE:
                if one_shot:
                    self._fences.remove(request.effect_key())
                if outcome is Outcome.SUCCEEDED:
                    status = self._transition(request, State.SUCCEEDED, Reason.SUCCEEDED)
                    return status if one_shot else replace(status, probe_result=ProbeResult.OK)
                return self._transition(request, State.FAILED, Reason.FAILED)
            if one_shot:
                return self._transition(request, State.UNCERTAIN, Reason.UNCERTAIN)
            if request.attempts >= _PROBE_ATTEMPTS:
                return self._transition(request, State.FAILED, Reason.ATTEMPTS_EXHAUSTED)
            still_live = self._live(request)
            if still_live is not Reason.READY:
                return self._transition(request, State.FAILED, still_live)
            return self._transition(request, State.ELIGIBLE_RETRY, Reason.RETRY, Reason.RETRY)

    def _revoke(self, actor, request, now):
        if request.state not in _REVOCABLE or request.revocation is not None:
            return self._status(request, self._eligibility(request))
        request.revocation = _Revocation(actor, now)
        return self._emit(request, Reason.REVOKED)

    def revoke(self, actor: Principal, request_id: str) -> Status:
        with self._lock:
            request = self._request(request_id)
            self._operator(actor, request.payload.subject.worker_enrollment)
            return self._revoke(actor, request, self._revocation_ticks())

    def revoke_worker(self, actor: Principal, worker: str) -> tuple[Status, ...]:
        with self._lock:
            if not _valid_id(worker):
                raise Denied()
            self._operator(actor, worker)
            now = self._revocation_ticks()
            return tuple(
                self._revoke(actor, request, now)
                for request in self._requests.values()
                if request.payload.subject.worker_enrollment == worker
                and request.state in _REVOCABLE
            )

    def _reconcile(self, request_id: str) -> Status:
        """Controller-internal settlement from the exact fixture journal entry."""
        with self._lock:
            request = self._request(request_id)
            if request.state is not State.UNCERTAIN or not request.consumed:
                raise Conflict()
            attempt = Attempt(request_id, request.attempts)
            try:
                outcome = self._adapter.reconcile(attempt, request.payload)
            except Exception:
                outcome = Outcome.UNKNOWN
            if outcome is Outcome.SUCCEEDED or outcome is Outcome.DEFINITE_FAILURE:
                self._fences.remove(request.effect_key())
                if outcome is Outcome.SUCCEEDED:
                    return self._transition(request, State.SUCCEEDED, Reason.SUCCEEDED)
                return self._transition(request, State.FAILED, Reason.FAILED)
            return self._status(request, self._eligibility(request))
