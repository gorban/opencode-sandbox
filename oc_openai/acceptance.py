"""Attended, fixed OpenAI proof used by the end-to-end test."""

from collections.abc import Callable
import re
import secrets
import time

from .cli import (
    MODEL, PROPOSAL_MARKER, Approval, Backend, ConnectionBinding, Reason, Stage,
    Terminal, WorkerEvidence, _UNAVAILABLE_MESSAGES, _production_backend, report_failure,
)
from .exposure import Diagnostic, RecoveryMode
from .live import StreamRouteUnavailable, WorkerRouteUnavailable
from .profiles import valid_label


_LOCAL_ID = re.compile(r"[A-Za-z0-9_-]{43}")
_USAGE_REVIEW = "Review the app's OpenAI-managed usage and credit settings before approving."


def _valid_binding(binding: ConnectionBinding | None) -> bool:
    return (
        type(binding) is ConnectionBinding
        and type(binding.registration_id) is str
        and _LOCAL_ID.fullmatch(binding.registration_id) is not None
        and type(binding.generation) is str
        and _LOCAL_ID.fullmatch(binding.generation) is not None
        and binding.model == MODEL
        and valid_label(binding.label)
        and type(binding.selection_epoch) is str
        and _LOCAL_ID.fullmatch(binding.selection_epoch) is not None
    )


def _matches_current(terminal: Terminal, backend: Backend, approval: Approval) -> bool:
    current = backend.connection()
    if not _valid_binding(current) or current != approval.connection:
        terminal.error(_UNAVAILABLE_MESSAGES[Reason.CONNECTION_CHANGED])
        return False
    return True


def _approve(
    terminal: Terminal, backend: Backend, approval: Approval, disclosure: str,
) -> bool:
    if not terminal.confirm(disclosure):
        terminal.error("Cancelled.")
        return False
    return _matches_current(terminal, backend, approval)


def _prepare_proposal(terminal: Terminal, backend: Backend, binding, proposal, recovery: RecoveryMode | None):
    if recovery is not None:
        ticket = backend.require_acceptance(proposal, recovery=recovery)
        stream = recovery is RecoveryMode.STREAM
        if type(ticket) is not Diagnostic or ticket.stream != stream:
            raise RouteUnavailable(Reason.DIAGNOSTIC_UNAVAILABLE)
        if stream:
            prior = "The original workstation request and first diagnostic both remain unknown."
            bounds = "2,766,000 input and 384,000 output tokens"
            question = "Send the one workstation stream diagnostic request?"
        else:
            prior = "The original workstation request remains unknown."
            bounds = "1,844,000 input and 256,000 output tokens"
            question = "Send the one workstation diagnostic request?"
        terminal.write(
            f"Active registration: {binding.label}. {prior} "
            f"This diagnostic sends one fixed text prompt to OpenAI using {MODEL}. Its reservation "
            "adds up to 922,000 input and 128,000 output tokens. Counting every earlier reservation "
            f"in full, the total reserved exposure is {bounds}. "
            f"{_USAGE_REVIEW} OpenAI determines actual usage and may use your ChatGPT "
            "plan or account credits. There is no verified hard spending cap. This diagnostic ends without a worker."
        )
        return ticket, question
    backend.require_acceptance(proposal)
    terminal.write(
        f"Active registration: {binding.label}. ChatGPT plan acceptance will send one fixed text "
        f"prompt to OpenAI using {MODEL}. "
        "The prompt only asks for a marker for the disposable proof. This approval reserves up "
        f"to 922,000 input and 128,000 output tokens. {_USAGE_REVIEW} "
        "OpenAI may use your ChatGPT plan or account credits. "
        "There is no verified hard spending cap. API-key fallback is disabled."
    )
    return None, "Send one GPT request to propose the proof?"


def _prove(terminal: Terminal, backend: Backend, *, recovery: RecoveryMode | None) -> int:
    binding = backend.connection()
    if not _valid_binding(binding):
        terminal.error("A connected ChatGPT account with the approved model is required.")
        return 1

    proposal = Approval(secrets.token_hex(16), binding, Stage.ORCHESTRATOR)
    operation = {
        RecoveryMode.FIRST: "Workstation diagnostic",
        RecoveryMode.STREAM: "Workstation stream diagnostic",
    }.get(recovery, "Workstation proposal")
    try:
        ticket, question = _prepare_proposal(terminal, backend, binding, proposal, recovery)
        if not _approve(terminal, backend, proposal, question):
            return 1
        response = backend.propose(proposal, diagnostic=ticket) if ticket is not None else backend.propose(proposal)
    except StreamRouteUnavailable as error:
        if recovery is RecoveryMode.STREAM:
            terminal.error(error.failure.describe())
        return report_failure(terminal, error, operation=operation)
    except Exception as error:
        return report_failure(terminal, error, operation=operation)
    if type(response) is not str or response != PROPOSAL_MARKER:
        terminal.error(f"{operation}: GPT did not return the required proof proposal.")
        return 1
    if recovery is not None:
        terminal.write("Verified the workstation diagnostic marker and usage. Earlier requests remain unresolved.")
        return 0

    worker = Approval(proposal.run_id, binding, Stage.WORKER)
    if not _matches_current(terminal, backend, worker):
        return 1
    terminal.write(
        f"Active registration: {binding.label}. GPT proposed the disposable local OpenCode proof. "
        "It writes one fixed scratch file. "
        f"The task and its fixed result use up to two separate OpenAI requests using {MODEL}. "
        "The continuation returns the fixed file outcome and any OpenAI-provided encrypted "
        "reasoning to the same endpoint. The encrypted reasoning stays outside the worker. "
        "This approval reserves up to 1,844,000 input and 256,000 output tokens in total. "
        f"{_USAGE_REVIEW} "
        "OpenAI may use your ChatGPT plan or account credits. There is no verified hard spending cap. "
        "API-key fallback is disabled."
    )
    if not _approve(terminal, backend, worker, "Start one local worker and authorize up to two requests?"):
        return 1
    return 0 if _finish_worker(terminal, backend, worker) else 1


def _finish_worker(terminal, backend, worker) -> bool:
    evidence = backend.prove(worker)
    if type(evidence) is not WorkerEvidence or not all(value is True for value in (
        evidence.native_terminal, evidence.exact_scratch, evidence.exact_receipt, evidence.owned_cleanup,
    )):
        terminal.error("Could not verify the local OpenCode proof and cleanup.")
        return False
    terminal.write("OpenCode completed the scratch-file proof. Verified tool delivery and worker cleanup.")
    return True


def _recovery(terminal, backend, source):
    binding = backend.connection()
    if not _valid_binding(binding):
        terminal.error("A connected ChatGPT account with the approved model is required.")
        return 1
    proposal = Approval(secrets.token_hex(16), binding, Stage.ORCHESTRATOR)
    with backend.recovery_proof(proposal, source) as proof:
        terminal.write(
            f"Active registration: {binding.label}. Reviewed proof source SHA-256 {source}. "
            f"One approval authorizes up to three requests to OpenAI using {MODEL} within five minutes. "
            "The fixed marker request must complete with verified usage. A matching marker then starts "
            "a disposable OpenCode worker without another prompt. It can write only the fixed proof "
            "bytes to /workspace/proof.txt. One continuation sends the fixed tool result and any "
            "OpenAI-provided encrypted reasoning to the same OpenAI endpoint. "
            "The three earlier workstation reservations remain unknown. This run adds up to "
            "2,766,000 input and 384,000 output tokens. The combined reservation is 5,532,000 input "
            f"and 768,000 output tokens. {_USAGE_REVIEW} OpenAI may use your ChatGPT plan or "
            "account credits. There is no verified hard spending cap. An uncertain send or an overage "
            "stops the proof. API-key fallback is disabled. Ctrl-C stops and retires the worker."
        )
        if not terminal.confirm("Authorize the single recovery proof?"):
            terminal.error("Cancelled.")
            return 1
        confirmed_at = time.monotonic()
        if not _matches_current(terminal, backend, proposal):
            return 1
        proof.ledger.approve(confirmed_at, terminal.attended)
        try:
            if proof.propose(proposal) != PROPOSAL_MARKER:
                terminal.error("Workstation recovery: GPT did not return the required proof proposal.")
                return 1
            terminal.write("Verified the recovery marker and usage. Starting the disposable OpenCode proof.")
            worker = Approval(proposal.run_id, binding, Stage.WORKER)
            if not _matches_current(terminal, backend, worker):
                return 1
            if not _finish_worker(terminal, proof, worker):
                return 1
            return 0
        except StreamRouteUnavailable as error:
            terminal.error(error.failure.describe())
            return report_failure(terminal, error, operation="Recovery proof")
        except WorkerRouteUnavailable as error:
            terminal.error(error.describe())
            return report_failure(terminal, error, operation="Recovery proof")
        finally:
            for phase, category in tuple(proof.media_fallbacks.items()):
                terminal.write(f"OpenAI response media compatibility used for {phase.value}: {category}.")


def run_attended(
    terminal: Terminal, *, backend_factory: Callable[[], Backend] = _production_backend,
    recovery: RecoveryMode | None = None, recovery_source: str | None = None,
) -> int:
    if not terminal.attended():
        terminal.error("An attended workstation terminal in the foreground is required.")
        return 2
    if ((recovery is not None and type(recovery) is not RecoveryMode)
            or (recovery_source is not None and (
                recovery is not None or type(recovery_source) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", recovery_source)
            ))):
        terminal.error("The OpenAI proof recovery mode is invalid.")
        return 2
    try:
        backend = backend_factory()
        if recovery_source is not None:
            return _recovery(terminal, backend, recovery_source)
        return _prove(terminal, backend, recovery=recovery)
    except (Exception, KeyboardInterrupt) as error:
        return report_failure(terminal, error)
