"""Connect the attended CLI to the workstation-owned OpenAI route."""

from collections.abc import Iterator
from dataclasses import dataclass
import os
from pathlib import Path
import pwd
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
from .exposure import ExposureError, Phase, Slot, binding_digest


_CONNECTION_REASONS = {
    "chatgpt_plan_scope_missing": Reason.ROUTE_SCOPE,
    "connection_retired": Reason.CONNECTION_CHANGED,
    "managed_retirement_incomplete": Reason.MANAGED_RETIREMENT,
    "host_browser_unavailable": Reason.BROWSER_REQUIRED,
    "openai_connection_required": Reason.CONNECTION_CHANGED,
    "openai_jose_prerequisite_missing": Reason.PYJWT_REQUIRED,
    "openai_model_unavailable": Reason.MODEL_UNAVAILABLE,
    "openai_reconnect_required": Reason.CONNECTION_CHANGED,
}
_PROVIDER_TERMINALS = {"response.completed", "response.failed", "response.incomplete", "error"}


def _proposal_body():
    return {
        "model": MODEL,
        "input": [{"type": "message", "role": "user", "content": ORCHESTRATOR_INPUT}],
        "store": False,
        "stream": True,
    }


def _usage(response):
    if (type(response) is not dict or response.get("status") != "completed"
            or response.get("model") != MODEL):
        raise RouteUnavailable(Reason.PROOF_FAILED)
    usage = response.get("usage")
    if type(usage) is not dict:
        raise RouteUnavailable(Reason.PROOF_FAILED)
    counts = tuple(usage.get(key) for key in ("input_tokens", "output_tokens", "total_tokens"))
    if any(type(count) is not int or count < 0 for count in counts) or counts[0] + counts[1] != counts[2]:
        raise RouteUnavailable(Reason.PROOF_FAILED)
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

        for event in self.backend.events(self.binding, slot, body, before_send, deadline=deadline, cancelled=cancelled):
            if event["type"] == "response.completed":
                self.delivered = slot.phase
            yield event


class WorkstationBackend:
    def __init__(self, connection, ledger, *, label, selection_epoch, worker=None, placement_qualified=False):
        self.connection_state = connection
        self.ledger = ledger
        self._label = label
        self._selection_epoch = selection_epoch
        self._worker = worker
        self._placement_qualified = placement_qualified

    def connection(self):
        try:
            selected = self.connection_state.binding()
        except ConnectionError as error:
            if error.code == "openai_connection_required":
                return None
            raise _mapped_connection_error(error) from None
        return ConnectionBinding(selected.profile, selected.generation, MODEL, self._label, self._selection_epoch)

    def require_acceptance(self):
        if not self._placement_qualified:
            raise RouteUnavailable(Reason.PLACEMENT)
        from .worker import WorkerError, require_worker_prerequisites
        try:
            self.connection_state.require_prerequisites()
            if self._worker is None:
                require_worker_prerequisites()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
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

    def events(self, binding, slot, body, before_send, *, deadline=None, cancelled=None) -> Iterator[dict]:
        _running(deadline, cancelled)
        terminal = None
        options = {"deadline": deadline, "cancelled": cancelled} if deadline is not None else {}
        with self.connection_state.responses(binding, body, before_send, **options) as events:
            for event in events:
                _running(deadline, cancelled)
                if terminal is not None or type(event) is not dict or type(event.get("type")) is not str:
                    raise RouteUnavailable(Reason.PROOF_FAILED)
                kind = event["type"]
                if kind == "response.completed":
                    terminal = event
                elif kind in _PROVIDER_TERMINALS:
                    raise RouteUnavailable(Reason.PROOF_FAILED)
                else:
                    yield event
            if terminal is None:
                raise RouteUnavailable(Reason.PROOF_FAILED)
            self.ledger.settle(slot, *_usage(terminal.get("response")))
            _running(deadline, cancelled)
            yield terminal

    def propose(self, approval):
        if not self._placement_qualified:
            raise RouteUnavailable(Reason.PLACEMENT)
        try:
            binding = self._require_approval(approval, Stage.ORCHESTRATOR)
            slot = _slot(approval, Phase.ORCHESTRATOR)
            self.ledger.require_next(slot)
            for event in self.events(binding, slot, _proposal_body(), lambda: self.ledger.reserve(slot)):
                if event["type"] == "response.completed":
                    return _proposal_marker(event["response"])
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        except ExposureError:
            raise RouteUnavailable(Reason.EXPOSURE) from None
        raise RouteUnavailable(Reason.PROOF_FAILED)

    def prove(self, approval):
        if not self._placement_qualified:
            raise RouteUnavailable(Reason.PLACEMENT)
        from .worker import WorkerCleanupError, WorkerError, WorkerEvidence as ManagedEvidence, run_worker

        try:
            binding = self._require_approval(approval, Stage.WORKER)
            self.ledger.require_next(_slot(approval, Phase.INITIAL))
            dispatch = _WorkerDispatch(self, approval, binding)
            worker = self._worker or run_worker
            evidence = worker(dispatch.events, model=MODEL, before_dispatch=dispatch.reserve,
                              lease_guard=lambda job: self.connection_state.worker_lease(binding, job))
            self.connection_state.require_active(binding)
            if type(evidence) is not ManagedEvidence or any(value is not True for value in (
                evidence.initial_receipt, evidence.continuation_receipt, evidence.native_tool,
            )) or dispatch.pending is not None or dispatch.delivered is not Phase.CONTINUATION:
                raise RouteUnavailable(Reason.PROOF_FAILED)
            return WorkerEvidence(evidence.native_terminal, evidence.exact_file, True, evidence.cleanup_verified)
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        except ExposureError:
            raise RouteUnavailable(Reason.EXPOSURE) from None
        except WorkerCleanupError as error:
            raise ManagedCleanup(error.receipt_leaf) from None
        except WorkerError:
            raise RouteUnavailable(Reason.PROOF_FAILED) from None


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
