"""Connect the attended CLI to the workstation-owned OpenAI route."""

from collections.abc import Iterator
from dataclasses import dataclass
import os
from pathlib import Path
import pwd
import re
import time

from .cli import (
    Approval,
    ConnectionBinding,
    MODEL,
    ManagedCleanup,
    ORCHESTRATOR_INPUT,
    PROPOSAL_MARKER,
    Reason,
    RouteUnavailable,
    Stage,
    WorkerEvidence,
)
from .connection import Binding, ConnectionError
from .exposure import Diagnostic, ExposureError, Phase, RecoveryMode, Slot, binding_digest
from .responses import MAX_EVENTS, StreamFailure, response_error


_CONNECTION_REASONS = {
    "chatgpt_plan_scope_missing": Reason.ROUTE_SCOPE,
    "connection_retired": Reason.CONNECTION_CHANGED,
    "managed_retirement_incomplete": Reason.MANAGED_RETIREMENT,
    "host_browser_unavailable": Reason.BROWSER_REQUIRED,
    "host_browser_placement_unavailable": Reason.BROWSER_REQUIRED,
    "openai_connection_required": Reason.CONNECTION_CHANGED,
    "openai_jose_prerequisite_missing": Reason.PYJWT_REQUIRED,
    "openai_model_unavailable": Reason.MODEL_UNAVAILABLE,
    "openai_reconnect_required": Reason.CONNECTION_CHANGED,
    "provider_network_error": Reason.PROVIDER_TRANSPORT,
    "provider_send_uncertain": Reason.PROVIDER_TRANSPORT,
    "openai_operation_timed_out": Reason.PROVIDER_TRANSPORT,
    "invalid_provider_http": Reason.PROVIDER_TRANSPORT,
    "invalid_provider_stream": Reason.PROVIDER_STREAM,
    "provider_stream_content_type": Reason.PROVIDER_STREAM_CONTENT_TYPE,
    "provider_stream_incomplete": Reason.PROVIDER_STREAM_INCOMPLETE,
    "provider_stream_limit": Reason.PROVIDER_STREAM_LIMIT,
    "provider_stream_json": Reason.PROVIDER_STREAM_JSON,
    "provider_stream_event_type": Reason.PROVIDER_STREAM_EVENT_TYPE,
    "provider_stream_named_done": Reason.PROVIDER_STREAM_NAMED_DONE,
    "provider_stream_after_terminal": Reason.PROVIDER_STREAM_AFTER_TERMINAL,
    "invalid_provider_json": Reason.PROVIDER_DATA,
    "invalid_openai_models": Reason.PROVIDER_DATA,
    "provider_response_too_large": Reason.PROVIDER_DATA,
    "provider_response_failed": Reason.PROVIDER_REJECTED,
    "chatgpt_plan_ineligible": Reason.PROVIDER_REJECTED,
    "chatgpt_request_unsupported": Reason.PROVIDER_REJECTED,
    "chatgpt_route_unavailable": Reason.PROVIDER_REJECTED,
    "chatgpt_usage_unavailable": Reason.PROVIDER_REJECTED,
    "chatgpt_auth_rejected": Reason.PROVIDER_REJECTED,
    "chatgpt_access_refused": Reason.PROVIDER_REJECTED,
    "chatgpt_unavailable": Reason.PROVIDER_REJECTED,
    "chatgpt_usage_limit": Reason.PROVIDER_LIMIT,
}
_PROVIDER_FAILURES = {"response.failed", "response.incomplete", "error"}
_RESPONSE_ID = re.compile(r"resp_[A-Za-z0-9_-]{1,123}")


def _proposal_body():
    return {
        "model": MODEL,
        "input": [{"type": "message", "role": "user", "content": ORCHESTRATOR_INPUT}],
        "store": False,
        "stream": True,
    }


def _response_id(response):
    identity = response.get("id") if type(response) is dict else None
    if type(identity) is not str or not _RESPONSE_ID.fullmatch(identity):
        raise RouteUnavailable(Reason.PROVIDER_IDENTITY)
    return identity


def _usage(response):
    if type(response) is not dict or response.get("status") != "completed":
        raise RouteUnavailable(Reason.PROVIDER_TERMINAL)
    if response.get("model") != MODEL:
        raise RouteUnavailable(Reason.PROVIDER_IDENTITY)
    usage = response.get("usage")
    if type(usage) is not dict:
        raise RouteUnavailable(Reason.PROVIDER_USAGE)
    counts = tuple(usage.get(key) for key in ("input_tokens", "output_tokens", "total_tokens"))
    if any(type(count) is not int or count < 0 for count in counts) or counts[0] + counts[1] != counts[2]:
        raise RouteUnavailable(Reason.PROVIDER_USAGE)
    return counts[:2]


def _proposal_marker(response):
    items = response.get("output")
    if type(items) is not list or any(type(item) is not dict for item in items):
        return ""
    visible = [item for item in items if item.get("type") != "reasoning"]
    if len(visible) != 1:
        return ""
    message = visible[0]
    if (message.get("type"), message.get("role"), message.get("status")) != ("message", "assistant", "completed"):
        return ""
    content = message.get("content")
    if (type(content) is list and len(content) == 1 and type(content[0]) is dict
            and content[0].get("type") == "output_text" and content[0].get("text") == PROPOSAL_MARKER):
        return PROPOSAL_MARKER
    return ""


def _slot(approval, phase):
    conn = approval.connection
    return Slot(approval.run_id, binding_digest(conn.registration_id, conn.generation, conn.selection_epoch), phase)


def _mapped_connection_error(error):
    return RouteUnavailable(_CONNECTION_REASONS.get(error.code, Reason.PROOF_FAILED))


class StreamRouteUnavailable(RouteUnavailable):
    def __init__(self, failure: StreamFailure):
        super().__init__(_CONNECTION_REASONS[failure.code])
        self.failure = failure


class WorkerRouteUnavailable(RouteUnavailable):
    def __init__(self, failure):
        super().__init__(Reason.PROOF_FAILED)
        self.failure = failure

    def describe(self):
        phase = f" {self.failure.phase}" if self.failure.phase is not None else ""
        return f"Managed OpenCode{phase} stopped during {self.failure.fault.value}."


def _mapped_exposure_error(error):
    reasons = {
        "unsettled_exposure": Reason.EXPOSURE,
        "exposure_bound_exceeded": Reason.EXPOSURE,
        "exposure_record_full": Reason.EXPOSURE_FULL,
        "diagnostic_already_reserved": Reason.DIAGNOSTIC_SPENT,
        "diagnostic_unavailable": Reason.DIAGNOSTIC_UNAVAILABLE,
    }
    return RouteUnavailable(reasons.get(str(error), Reason.EXPOSURE_UNAVAILABLE))


_EVENT_COMPLETED = "response.completed"


def _event_failure(kind, event):
    details = event.get("response") if kind == "response.failed" else event
    if isinstance(details, dict) and response_error(0, details) == "chatgpt_usage_limit":
        raise RouteUnavailable(Reason.PROVIDER_LIMIT)
    raise RouteUnavailable(Reason.PROVIDER_TERMINAL)


def _check_created_id(created_id, kind, event):
    if created_id is None:
        if kind != "response.created":
            raise RouteUnavailable(Reason.PROVIDER_IDENTITY)
        created = event.get("response")
        new_id = _response_id(created)
        if created.get("model", MODEL) != MODEL:
            raise RouteUnavailable(Reason.PROVIDER_IDENTITY)
        return new_id
    if kind == "response.created":
        raise RouteUnavailable(Reason.PROVIDER_IDENTITY)
    return created_id


def _proposal_reserve(ledger, slot, diagnostic):
    if diagnostic is None:
        ledger.require_next(slot)
        return lambda: ledger.reserve(slot)
    if type(diagnostic) is not Diagnostic or ledger.prepare_diagnostic(slot, stream=diagnostic.stream) != diagnostic:
        raise ExposureError("diagnostic_unavailable")
    return lambda: ledger.reserve_diagnostic(diagnostic)


def _verify_worker_evidence(evidence, dispatch, evidence_type):
    if (type(evidence) is not evidence_type or any(value is not True for value in (
        evidence.initial_receipt, evidence.continuation_receipt, evidence.native_tool,
    )) or dispatch.pending is not None or dispatch.delivered is not Phase.CONTINUATION):
        raise RouteUnavailable(Reason.PROOF_FAILED)
    return WorkerEvidence(evidence.native_terminal, evidence.exact_file, True, evidence.cleanup_verified)


def _running(deadline, cancelled):
    if ((cancelled is not None and cancelled.is_set())
            or (deadline is not None and time.monotonic() >= deadline)):
        raise RouteUnavailable(Reason.PROOF_FAILED)


@dataclass
class _WorkerDispatch:
    """Join broker admission to exactly one provider transport invocation."""

    backend: "WorkstationBackend"
    approval: Approval
    binding: Binding
    pending: Slot | None = None
    delivered: Phase | None = None
    stream_failure: StreamFailure | None = None

    def reserve(self, phase: str):
        if self.pending is not None or phase not in ("initial", "continuation"):
            raise RouteUnavailable(Reason.PROOF_FAILED)
        self.pending = _slot(self.approval, Phase(phase))

    def events(self, body, *, deadline, cancelled):
        slot = self.pending
        if slot is None:
            raise RouteUnavailable(Reason.PROOF_FAILED)
        self.pending = None

        def before_send():
            _running(deadline, cancelled)
            self.backend.ledger.reserve(slot)
            _running(deadline, cancelled)

        try:
            for event in self.backend.events(
                self.binding, slot, body, before_send, deadline=deadline, cancelled=cancelled,
            ):
                if event["type"] == _EVENT_COMPLETED:
                    self.delivered = slot.phase
                yield event
        except StreamFailure as failure:
            self.stream_failure = failure
            raise


class WorkstationBackend:
    def __init__(self, connection, ledger, *, label, selection_epoch, worker=None, placement_qualified=False,
                 recovery=False, allow_progress=False, trace_only=False, allow_metadata=False):
        self.connection_state = connection
        self.ledger = ledger
        self._label = label
        self._selection_epoch = selection_epoch
        self._worker = worker
        self._placement_qualified = placement_qualified
        self._recovery = recovery
        self._allow_progress = allow_progress
        self._trace_only = trace_only
        self._allow_metadata = allow_metadata
        self.media_fallbacks = {}

    def recovery_proof(self, approval, source, *, worker_only=False, after_retry=False,
                       trace_only=False, after_trace=False, moderation_trace=False):
        from .recovery import RecoveryLedger

        if not self._placement_qualified:
            raise RouteUnavailable(Reason.PLACEMENT)
        try:
            stage = Stage.WORKER if worker_only else Stage.ORCHESTRATOR
            phase = Phase.INITIAL if worker_only else Phase.ORCHESTRATOR
            self._require_approval(approval, stage)
            self._require_prerequisites(require_worker=not (trace_only or moderation_trace))
            ledger = RecoveryLedger(
                self.ledger, _slot(approval, phase), source,
                worker_only=worker_only, after_retry=after_retry, trace_only=trace_only, after_trace=after_trace,
                moderation_trace=moderation_trace,
            )
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        except ExposureError as error:
            raise _mapped_exposure_error(error) from None
        return WorkstationBackend(
            self.connection_state, ledger, label=self._label, selection_epoch=self._selection_epoch,
            worker=self._worker, placement_qualified=True, recovery=True,
            allow_progress=after_retry, trace_only=trace_only or moderation_trace, allow_metadata=after_trace,
        )

    def connection(self):
        try:
            selected = self.connection_state.binding()
        except ConnectionError as error:
            if error.code == "openai_connection_required":
                return None
            raise _mapped_connection_error(error) from None
        return ConnectionBinding(selected.profile, selected.generation, MODEL, self._label, self._selection_epoch)

    def verify(self):
        """Explicit, inference-free workstation probe checking active registration and model catalog."""
        from oc_providers.contracts import ReadinessState, VerifyResult

        try:
            binding = self.connection_state.binding()
            models = self.connection_state.models(binding)
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        if not models:
            raise RouteUnavailable(Reason.MODEL_UNAVAILABLE)
        return VerifyResult(
            provider="openai",
            label=self._label,
            readiness=ReadinessState.READY,
            models=tuple(models),
        )

    def require_acceptance(self, proposal, *, recovery=None):
        if recovery is not None and type(recovery) is not RecoveryMode:
            raise RouteUnavailable(Reason.DIAGNOSTIC_UNAVAILABLE)
        if not self._placement_qualified:
            raise RouteUnavailable(Reason.PLACEMENT)
        try:
            self._require_approval(proposal, Stage.ORCHESTRATOR)
            slot = _slot(proposal, Phase.ORCHESTRATOR)
            ticket = None
            if recovery is not None:
                ticket = self.ledger.prepare_diagnostic(slot, stream=recovery is RecoveryMode.STREAM)
            else:
                self.ledger.require_next(slot)
            self._require_prerequisites()
            return ticket
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        except ExposureError as error:
            raise _mapped_exposure_error(error) from None

    def _require_prerequisites(self, *, require_worker=True):
        try:
            self.connection_state.require_prerequisites()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        if require_worker and self._worker is None:
            from .worker import WorkerError, require_worker_prerequisites
            try:
                require_worker_prerequisites()
            except WorkerError:
                raise RouteUnavailable(Reason.PLACEMENT) from None

    def _require_approval(self, approval, stage):
        if (type(approval) is not Approval or approval.stage is not stage
                or type(approval.connection) is not ConnectionBinding
                or approval.connection.model != MODEL or self.connection() != approval.connection):
            raise RouteUnavailable(Reason.CONNECTION_CHANGED)
        binding = Binding(generation=approval.connection.generation, profile=approval.connection.registration_id)
        self.connection_state.require_active(binding)
        return binding

    def _event_options(self, slot, *, deadline, cancelled, diagnostic):
        options = {"deadline": deadline, "cancelled": cancelled} if deadline is not None else {}
        if diagnostic is not None and diagnostic.stream:
            options["inspect_media"] = True
        if self._recovery:
            options.update(
                inspect_media=True,
                observe_media=lambda category: self.media_fallbacks.setdefault(slot.phase, category),
                before_write=self.ledger.require_dispatch,
            )
        return options

    @staticmethod
    def _collect_events(events, deadline, cancelled):
        created_id = None
        terminal = None
        staged = []
        for count, event in enumerate(events, 1):
            _running(deadline, cancelled)
            if (count > MAX_EVENTS or terminal is not None or type(event) is not dict
                    or type(event.get("type")) is not str):
                raise RouteUnavailable(Reason.PROVIDER_STREAM)
            kind = event["type"]
            if kind in _PROVIDER_FAILURES:
                _event_failure(kind, event)
            created_id = _check_created_id(created_id, kind, event)
            if kind == _EVENT_COMPLETED:
                if _response_id(event.get("response")) != created_id:
                    raise RouteUnavailable(Reason.PROVIDER_IDENTITY)
                terminal = event
            else:
                # The transport already caps each frame and aggregate bytes.
                # Keep tool semantics downstream of accounting so even an
                # unacceptable tool result can have authoritative usage.
                staged.append(event)
        if terminal is None:
            raise RouteUnavailable(Reason.PROVIDER_MISSING_COMPLETION)
        return staged, terminal

    def events(self, binding, slot, body, before_send, *,
               deadline=None, cancelled=None, diagnostic=None) -> Iterator[dict]:
        _running(deadline, cancelled)
        options = self._event_options(slot, deadline=deadline, cancelled=cancelled, diagnostic=diagnostic)
        with self.connection_state.responses(binding, body, before_send, **options) as events:
            staged, terminal = self._collect_events(events, deadline, cancelled)
            usage = _usage(terminal.get("response"))
            if diagnostic is None:
                self.ledger.settle(slot, *usage)
            else:
                self.ledger.settle_diagnostic(diagnostic, *usage)
            for event in staged:
                _running(deadline, cancelled)
                yield event
            _running(deadline, cancelled)
            yield terminal

    def propose(self, approval, *, diagnostic=None):
        if not self._placement_qualified:
            raise RouteUnavailable(Reason.PLACEMENT)
        try:
            binding = self._require_approval(approval, Stage.ORCHESTRATOR)
            slot = _slot(approval, Phase.ORCHESTRATOR)
            reserve = _proposal_reserve(self.ledger, slot, diagnostic)
            for event in self.events(binding, slot, _proposal_body(), reserve, diagnostic=diagnostic):
                if event["type"] == _EVENT_COMPLETED:
                    return _proposal_marker(event["response"])
        except ConnectionError as error:
            if type(error) is StreamFailure and (self._recovery or (diagnostic is not None and diagnostic.stream)):
                raise StreamRouteUnavailable(error) from None
            raise _mapped_connection_error(error) from None
        except ExposureError as error:
            raise _mapped_exposure_error(error) from None
        raise RouteUnavailable(Reason.PROOF_FAILED)

    def _run_worker_proof(self, binding, worker_fn, dispatch):
        options = {"allow_progress": True} if self._allow_progress else {}
        if self._allow_metadata:
            options["allow_metadata"] = True
        evidence = worker_fn(
            dispatch.events, model=MODEL, before_dispatch=dispatch.reserve,
            lease_guard=lambda job: self.connection_state.worker_lease(binding, job), **options,
        )
        self.connection_state.require_active(binding)
        return evidence

    def prove(self, approval):
        if self._trace_only:
            raise RouteUnavailable(Reason.DIAGNOSTIC_UNAVAILABLE)
        if not self._placement_qualified:
            raise RouteUnavailable(Reason.PLACEMENT)
        from .worker import (
            WorkerCleanupError, WorkerError, WorkerEvidence as ManagedEvidence, WorkerProofError, run_worker,
        )

        dispatch = None
        try:
            binding = self._require_approval(approval, Stage.WORKER)
            self.ledger.require_next(_slot(approval, Phase.INITIAL))
            dispatch = _WorkerDispatch(self, approval, binding)
            evidence = self._run_worker_proof(binding, self._worker or run_worker, dispatch)
            return _verify_worker_evidence(evidence, dispatch, ManagedEvidence)
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        except ExposureError as error:
            raise _mapped_exposure_error(error) from None
        except WorkerCleanupError as error:
            raise ManagedCleanup(error.receipt_leaf) from None
        except WorkerError as error:
            if self._recovery and dispatch is not None and dispatch.stream_failure is not None:
                raise StreamRouteUnavailable(dispatch.stream_failure) from None
            if self._recovery and type(error) is WorkerProofError:
                raise WorkerRouteUnavailable(error) from None
            raise RouteUnavailable(Reason.PROOF_FAILED) from None

    def trace_initial(self, approval):
        if not self._trace_only:
            raise RouteUnavailable(Reason.DIAGNOSTIC_UNAVAILABLE)
        from .managed.protocol import body_for
        try:
            binding = self._require_approval(approval, Stage.WORKER)
            slot = _slot(approval, Phase.INITIAL)
            self.ledger.require_next(slot)
            yield from self.events(binding, slot, body_for(MODEL), lambda: self.ledger.reserve(slot))
        except StreamFailure as error:
            raise StreamRouteUnavailable(error) from None
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        except ExposureError as error:
            raise _mapped_exposure_error(error) from None


def _state_directory(home, caller_home):
    home = home.resolve(strict=True)
    if not caller_home.is_absolute() or caller_home.resolve() != home:
        raise RouteUnavailable(Reason.PROOF_FAILED)
    state = home / ".config" / "oc-sandbox" / "openai"
    sandbox = (home / "opencode-sandbox").resolve()
    if state.is_relative_to(sandbox) or sandbox.is_relative_to(state):
        raise RouteUnavailable(Reason.PROOF_FAILED)
    return state


def make_backend():
    try:
        state = _state_directory(Path(pwd.getpwuid(os.getuid()).pw_dir), Path(os.environ.get("HOME", "")))
    except (OSError, RuntimeError, ValueError):
        raise RouteUnavailable(Reason.PROOF_FAILED) from None
    from .profile_backend import ProfileBackend
    return ProfileBackend(state)
