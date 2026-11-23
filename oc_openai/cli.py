"""Foreground operator approvals for one OpenAI worker proof."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from errno import ENOTTY
from fcntl import ioctl
import os
import re
import secrets
import termios
from typing import Protocol, TextIO

from .profiles import ProfileError, valid_label

MODEL = "gpt-6.2-sol"
PROPOSAL_MARKER = "OC_SANDBOX_WORKER_PROOF"
ORCHESTRATOR_INPUT = (
    "Propose the disposable oc-sandbox worker proof. "
    "Reply with exactly OC_SANDBOX_WORKER_PROOF and no other text."
)
_LABEL_COMMANDS = ("connect", "select")
_LOCAL_COMMANDS = ("status", "disconnect", "accept")
USAGE = "Usage: oc-sandbox openai {connect LABEL|select LABEL|status|disconnect|accept}"
_LOCAL_ID = re.compile(r"[A-Za-z0-9_-]{43}")
# The Linux device identity also matches the PTY master, so exclude that side explicitly.
_TIOCGDEV = 0x80045432
_TIOCGPTN = 0x80045430


class Stage(Enum):
    ORCHESTRATOR = "orchestrator"
    WORKER = "worker"


@dataclass(frozen=True)
class ConnectionBinding:
    """The local registration ID is an opaque profile ID, separate from the provider client ID."""

    registration_id: str
    generation: str
    model: str
    label: str
    selection_epoch: str


@dataclass(frozen=True)
class SavedProfile:
    label: str
    connected: bool


@dataclass(frozen=True)
class ConnectionStatus:
    saved: tuple[SavedProfile, ...]
    active: str | None


@dataclass(frozen=True)
class Approval:
    run_id: str
    connection: ConnectionBinding
    stage: Stage


@dataclass(frozen=True)
class WorkerEvidence:
    native_terminal: bool
    exact_scratch: bool
    exact_receipt: bool
    owned_cleanup: bool


class Reason(Enum):
    QUALIFICATION = "qualification"
    PYJWT_REQUIRED = "pyjwt_required"
    PLACEMENT = "placement"
    MODEL_UNAVAILABLE = "model_unavailable"
    ROUTE_SCOPE = "route_scope"
    CONNECTION_CHANGED = "connection_changed"
    EXPOSURE = "exposure"
    BROWSER_REQUIRED = "browser_required"
    PROOF_FAILED = "proof_failed"
    PROFILE_BUSY = "profile_busy"
    PROFILE_NOT_FOUND = "profile_not_found"
    PROFILE_CONFLICT = "profile_conflict"
    MANAGED_RETIREMENT = "managed_retirement"


_UNAVAILABLE_MESSAGES = {
    Reason.QUALIFICATION: "The live ChatGPT plan route is disabled pending qualification.",
    Reason.PYJWT_REQUIRED: "Sign in requires PyJWT with crypto support in the workstation Python.",
    Reason.PLACEMENT: "The current placement did not pass the managed worker prerequisites.",
    Reason.MODEL_UNAVAILABLE: f"The selected ChatGPT connection does not list {MODEL}.",
    Reason.ROUTE_SCOPE: "The selected ChatGPT connection lacks the required plan scope.",
    Reason.CONNECTION_CHANGED: "The selected ChatGPT connection changed. Start a new acceptance run.",
    Reason.EXPOSURE: (
        "A prior request is unsettled or exceeded its approved token bound. Further inference is suspended."
    ),
    Reason.BROWSER_REQUIRED: "Sign in requires the trusted workstation browser in the supported devbox session.",
    Reason.PROOF_FAILED: (
        "The managed OpenCode proof did not complete. Inspect the disposable worker cleanup evidence before trying again."
    ),
    Reason.PROFILE_BUSY: "A foreground ChatGPT request or worker proof is active. Wait for it to finish.",
    Reason.PROFILE_NOT_FOUND: "That saved ChatGPT registration is unavailable.",
    Reason.PROFILE_CONFLICT: "OpenAI returned a registration that conflicts with the saved labels.",
    Reason.MANAGED_RETIREMENT: "The selected registration still has a pending disconnection or worker retirement.",
}

_PROFILE_REASONS = {
    "profile_busy": Reason.PROFILE_BUSY,
    "profile_stale": Reason.CONNECTION_CHANGED,
    "profile_unknown": Reason.PROFILE_NOT_FOUND,
    "profile_client_conflict": Reason.PROFILE_CONFLICT,
    "profile_retiring": Reason.MANAGED_RETIREMENT,
}


class RouteUnavailable(RuntimeError):
    """The qualified live route is unavailable."""

    def __init__(self, reason: Reason = Reason.QUALIFICATION):
        self.reason = reason if type(reason) is Reason else Reason.QUALIFICATION
        super().__init__(self.reason.value)


class ManagedCleanup(RouteUnavailable):
    def __init__(self, receipt_leaf):
        super().__init__(Reason.PROOF_FAILED)
        self.receipt_leaf = receipt_leaf if (
            type(receipt_leaf) is str and re.fullmatch(r"oc-i4a-[a-z0-9_]{8}", receipt_leaf)
        ) else None


class Backend(Protocol):
    def connection(self) -> ConnectionBinding | None:
        """Read the current local selection without network calls or mutation."""
        ...

    def connect(self, label: str) -> None: ...

    def active_label(self) -> str | None: ...

    def status(self) -> ConnectionStatus:
        """Project local saved registration state without contacting OpenAI."""
        ...

    def select(self, label: str) -> None: ...

    def require_acceptance(self) -> None:
        """Check read-only local acceptance prerequisites without opening the provider route."""
        ...

    def disconnect(self) -> bool:
        """Fence local use and report whether upstream revocation was confirmed."""
        ...

    def propose(self, approval: Approval) -> str:
        """Send one authorized inference and return only a validated terminal response."""
        ...

    def prove(self, approval: Approval) -> WorkerEvidence:
        """Run the authorized proof and guarantee a cleanup attempt on every exit."""
        ...


class Terminal(Protocol):
    def attended(self) -> bool: ...

    def write(self, message: str) -> None: ...

    def error(self, message: str) -> None: ...

    def confirm(self, message: str) -> bool: ...


@dataclass
class StreamTerminal:
    reader: TextIO
    writer: TextIO
    errors: TextIO

    def attended(self) -> bool:
        try:
            with open("/dev/tty", "rb", buffering=0) as control:
                fd = control.fileno()
                if os.tcgetpgrp(fd) != os.getpgrp():
                    return False
                device = ioctl(fd, _TIOCGDEV, bytes(4))
                for stream in (self.reader, self.writer):
                    fd = stream.fileno()
                    try:
                        ioctl(fd, _TIOCGPTN, bytes(4))
                    except OSError as error:
                        if error.errno != ENOTTY:
                            return False
                    else:
                        return False
                    if ioctl(fd, _TIOCGDEV, bytes(4)) != device:
                        return False
                return True
        except (OSError, ValueError):
            return False

    def write(self, message: str) -> None:
        print(message, file=self.writer, flush=True)

    def error(self, message: str) -> None:
        print(f"oc-sandbox openai: {message}", file=self.errors, flush=True)

    def confirm(self, message: str) -> bool:
        if not self.attended():
            return False
        try:
            fd = self.reader.fileno()
            termios.tcflush(fd, termios.TCIFLUSH)
            self.write(f"{message} Type yes to approve.")
            # TextIO may read ahead into the next approval. Read this line directly.
            answer = b""
            while len(answer) < 4:
                char = os.read(fd, 1)
                if not char:
                    return False
                answer += char
                if char == b"\n":
                    return answer == b"yes\n" and self.attended()
        except (OSError, termios.error, ValueError):
            return False
        return False


def _production_backend() -> Backend:
    try:
        from .live import make_backend
    except ModuleNotFoundError as error:
        if error.name == "oc_openai.live":
            raise RouteUnavailable from None
        raise
    return make_backend()


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


def _accept(terminal: Terminal, backend: Backend) -> int:
    binding = backend.connection()
    if not _valid_binding(binding):
        terminal.error("A connected ChatGPT account with the approved model is required.")
        return 1

    backend.require_acceptance()
    run_id = secrets.token_hex(16)
    proposal = Approval(run_id, binding, Stage.ORCHESTRATOR)
    terminal.write(
        f"Active registration: {binding.label}. ChatGPT plan acceptance will send one fixed text "
        f"prompt to OpenAI using {MODEL}. "
        "The prompt only asks for a marker for the disposable proof. This approval reserves up "
        "to 922,000 input and 128,000 output tokens. Review the app's OpenAI-managed usage and "
        "credit settings before approving. OpenAI may use your ChatGPT plan or account credits. "
        "There is no verified hard spending cap. API-key fallback is disabled."
    )
    if not _approve(terminal, backend, proposal, "Send one GPT request to propose the proof?"):
        return 1
    response = backend.propose(proposal)
    if type(response) is not str or response != PROPOSAL_MARKER:
        terminal.error("GPT did not return the required proof proposal.")
        return 1

    worker = Approval(run_id, binding, Stage.WORKER)
    if not _matches_current(terminal, backend, worker):
        return 1
    terminal.write(
        f"Active registration: {binding.label}. GPT proposed the disposable local OpenCode proof. "
        "It writes one fixed scratch file. "
        f"The task and its fixed result use up to two separate OpenAI requests using {MODEL}. "
        "This approval reserves up to 1,844,000 input and 256,000 output tokens in total. "
        "Review the app's OpenAI-managed usage and credit settings before approving. "
        "OpenAI may use your ChatGPT plan or account credits. There is no verified hard spending cap. "
        "API-key fallback is disabled."
    )
    if not _approve(terminal, backend, worker, "Start one local worker and authorize up to two requests?"):
        return 1
    evidence = backend.prove(worker)
    if type(evidence) is not WorkerEvidence or not all(value is True for value in (
        evidence.native_terminal, evidence.exact_scratch, evidence.exact_receipt, evidence.owned_cleanup,
    )):
        terminal.error("Could not verify the local OpenCode proof and cleanup.")
        return 1
    terminal.write("OpenCode completed the scratch-file proof. Verified tool delivery and worker cleanup.")
    return 0


def _local_status(backend: Backend) -> ConnectionStatus:
    status = backend.status()
    if type(status) is not ConnectionStatus or type(status.saved) is not tuple:
        raise RouteUnavailable
    labels = set()
    for entry in status.saved:
        if (
            type(entry) is not SavedProfile or not valid_label(entry.label)
            or type(entry.connected) is not bool or entry.label in labels
        ):
            raise RouteUnavailable
        labels.add(entry.label)
    if status.active is not None and (not valid_label(status.active) or status.active not in labels):
        raise RouteUnavailable
    return status


def _show_status(terminal: Terminal, status: ConnectionStatus) -> None:
    if not status.saved:
        terminal.write("No ChatGPT registrations are saved.")
        return
    for entry in status.saved:
        active = ", active" if entry.label == status.active else ""
        connection = "connected" if entry.connected else "disconnected"
        terminal.write(f"{entry.label} ({connection}{active})")
    if status.active is None:
        terminal.write("No saved registration is active.")


def run(
    argv: Sequence[str], *, terminal: Terminal, backend_factory: Callable[[], Backend] = _production_backend,
) -> int:
    command = argv[0] if argv else ""
    labelled = command in _LABEL_COMMANDS
    if (
        (labelled and (len(argv) != 2 or not valid_label(argv[1])))
        or (not labelled and (len(argv) != 1 or command not in _LOCAL_COMMANDS))
    ):
        terminal.error(USAGE)
        return 2
    if command in ("connect", "accept") and not terminal.attended():
        terminal.error("An attended workstation terminal in the foreground is required.")
        return 2
    try:
        backend = backend_factory()
        if command == "connect":
            label = argv[1]
            active = backend.active_label()
            if active is not None and not valid_label(active):
                raise RouteUnavailable(Reason.CONNECTION_CHANGED)
            terminal.write(
                f"Active registration: {active}." if active is not None else "No registration is currently active."
            )
            terminal.write(
                f"Continue with ChatGPT for registration {label}. OpenAI receives the app's OAuth "
                "request and this installation's identifier. This workstation stores the verified "
                "account identity and provider tokens. Disconnect retires local tokens and attempts "
                "revocation with OpenAI. It retains registration labels and IDs, the verified "
                "account binding, and installation-wide numeric usage accounting. Acceptance "
                "sends fixed prompts to OpenAI only after separate authorization."
            )
            if not terminal.confirm(f"Continue with ChatGPT for {label} in the workstation browser?"):
                terminal.error("Cancelled.")
                return 1
            backend.connect(label)
            terminal.write(f"Connected ChatGPT registration {label} on this workstation.")
            return 0
        if command == "select":
            label = argv[1]
            backend.select(label)
            terminal.write(f"Selected ChatGPT registration {label}.")
            return 0
        if command == "status":
            _show_status(terminal, _local_status(backend))
            return 0
        if command == "disconnect":
            if backend.disconnect() is True:
                terminal.write("ChatGPT is disconnected on this workstation.")
                return 0
            terminal.error("ChatGPT is disconnected locally. Remote revocation could not be confirmed.")
            return 1
        return _accept(terminal, backend)
    except KeyboardInterrupt:
        terminal.error("Interrupted.")
        return 130
    except ManagedCleanup as error:
        terminal.error("Managed worker cleanup needs verification.")
        if error.receipt_leaf is not None:
            terminal.error(f"Private receipt directory /tmp/{error.receipt_leaf}")
        return 1
    except RouteUnavailable as error:
        terminal.error(_UNAVAILABLE_MESSAGES[error.reason])
        return 1
    except ProfileError as error:
        terminal.error(_UNAVAILABLE_MESSAGES[_PROFILE_REASONS.get(error.code, Reason.QUALIFICATION)])
        return 1
    except Exception:
        terminal.error("The ChatGPT plan command could not complete.")
        return 1
