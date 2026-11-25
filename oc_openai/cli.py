"""Workstation commands for OpenAI connections."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from errno import ENOTTY
from fcntl import ioctl
import os
import re
import termios
from typing import Protocol, TextIO

from .exposure import Diagnostic, RecoveryMode
from .profiles import ProfileError, valid_canonical_label, valid_label

MODEL = "gpt-6.2-sol"
PROPOSAL_MARKER = "OC_SANDBOX_WORKER_PROOF"
ORCHESTRATOR_INPUT = (
    "Propose the disposable oc-sandbox worker proof. "
    "Reply with exactly OC_SANDBOX_WORKER_PROOF and no other text."
)
_LABEL_COMMANDS = ("connect", "select")
_LOCAL_COMMANDS = ("status", "verify", "disconnect")
USAGE = "Usage: oc-sandbox openai {connect LABEL [--no-browser]|select LABEL|status|verify|disconnect [LABEL]}"
BrowserHandoff = Callable[[str, Callable[[], bool]], None]
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
    revocation_unconfirmed: bool = False
    published: bool = True


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
    EXPOSURE_FULL = "exposure_full"
    EXPOSURE_UNAVAILABLE = "exposure_unavailable"
    DIAGNOSTIC_SPENT = "diagnostic_spent"
    DIAGNOSTIC_UNAVAILABLE = "diagnostic_unavailable"
    BROWSER_REQUIRED = "browser_required"
    FOREGROUND_REQUIRED = "foreground_required"
    PROOF_FAILED = "proof_failed"
    PROVIDER_TRANSPORT = "provider_transport"
    PROVIDER_REJECTED = "provider_rejected"
    PROVIDER_LIMIT = "provider_limit"
    PROVIDER_DATA = "provider_data"
    PROVIDER_STREAM = "provider_stream"
    PROVIDER_STREAM_CONTENT_TYPE = "provider_stream_content_type"
    PROVIDER_STREAM_INCOMPLETE = "provider_stream_incomplete"
    PROVIDER_STREAM_LIMIT = "provider_stream_limit"
    PROVIDER_STREAM_JSON = "provider_stream_json"
    PROVIDER_STREAM_EVENT_TYPE = "provider_stream_event_type"
    PROVIDER_STREAM_NAMED_DONE = "provider_stream_named_done"
    PROVIDER_STREAM_AFTER_TERMINAL = "provider_stream_after_terminal"
    PROVIDER_TERMINAL = "provider_terminal"
    PROVIDER_IDENTITY = "provider_identity"
    PROVIDER_USAGE = "provider_usage"
    PROVIDER_MISSING_COMPLETION = "provider_missing_completion"
    PROFILE_BUSY = "profile_busy"
    PROFILE_CONNECT_BUSY = "profile_connect_busy"
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
    Reason.EXPOSURE_FULL: "The inference ledger is at capacity. Further inference is suspended.",
    Reason.EXPOSURE_UNAVAILABLE: "The inference ledger could not authorize this request.",
    Reason.DIAGNOSTIC_SPENT: "A diagnostic receipt already exists. Further inference is suspended.",
    Reason.DIAGNOSTIC_UNAVAILABLE: "The current connection and ledger do not qualify for this diagnostic.",
    Reason.BROWSER_REQUIRED: "Sign in requires the trusted workstation browser in the supported devbox session.",
    Reason.FOREGROUND_REQUIRED: "Sign-in links require an attended workstation terminal in the foreground.",
    Reason.PROOF_FAILED: "The proof did not complete.",
    Reason.PROVIDER_TRANSPORT: "The connection to OpenAI failed or closed unexpectedly.",
    Reason.PROVIDER_REJECTED: "OpenAI rejected the request.",
    Reason.PROVIDER_LIMIT: "OpenAI reported a ChatGPT plan usage limit.",
    Reason.PROVIDER_DATA: "OpenAI returned invalid or oversized response data.",
    Reason.PROVIDER_STREAM: "OpenAI returned an invalid or oversized event stream.",
    Reason.PROVIDER_STREAM_CONTENT_TYPE: "The OpenAI response had an unexpected event-stream content type.",
    Reason.PROVIDER_STREAM_INCOMPLETE: "The OpenAI stream ended before a line, event, or HTTP body was complete.",
    Reason.PROVIDER_STREAM_LIMIT: "The OpenAI stream exceeded its byte, line, or event limit.",
    Reason.PROVIDER_STREAM_JSON: "An OpenAI stream event contained invalid JSON.",
    Reason.PROVIDER_STREAM_EVENT_TYPE: "An OpenAI stream event had a missing, repeated, or conflicting event type.",
    Reason.PROVIDER_STREAM_NAMED_DONE: "The OpenAI stream sent a named [DONE] terminator.",
    Reason.PROVIDER_STREAM_AFTER_TERMINAL: "The OpenAI stream sent additional data after a terminal event.",
    Reason.PROVIDER_TERMINAL: "OpenAI reported a failed or incomplete response.",
    Reason.PROVIDER_IDENTITY: "The response identity or model did not match the request.",
    Reason.PROVIDER_USAGE: "The response did not contain valid terminal usage.",
    Reason.PROVIDER_MISSING_COMPLETION: "The stream ended without a completed response.",
    Reason.PROFILE_BUSY: "A foreground ChatGPT request or worker proof is active. Wait for it to finish.",
    Reason.PROFILE_CONNECT_BUSY: "A ChatGPT sign-in attempt is already active.",
    Reason.PROFILE_NOT_FOUND: "That saved ChatGPT registration is unavailable.",
    Reason.PROFILE_CONFLICT: "OpenAI returned a registration that conflicts with the saved labels.",
    Reason.MANAGED_RETIREMENT: "The selected registration still has a pending disconnection or worker retirement.",
}

_PROFILE_REASONS = {
    "profile_busy": Reason.PROFILE_BUSY,
    "profile_connect_busy": Reason.PROFILE_CONNECT_BUSY,
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

    def connect(self, label: str, *, handoff: BrowserHandoff | None = None) -> None: ...

    def active_label(self) -> str | None: ...

    def status(self) -> ConnectionStatus:
        """Project local saved registration state without contacting OpenAI."""
        ...

    def select(self, label: str) -> None: ...

    def require_acceptance(self, proposal: Approval, *, recovery: RecoveryMode | None = None) -> Diagnostic | None:
        """Check read-only local acceptance prerequisites without opening the provider route."""
        ...

    def disconnect(self) -> bool:
        """Fence local use and report whether upstream revocation was confirmed."""
        ...

    def propose(self, approval: Approval, *, diagnostic: Diagnostic | None = None) -> str:
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
            self.write(f"{message} [y/N]")
            # TextIO may read ahead into the next approval. Read this line directly.
            answer = b""
            while len(answer) < 4:
                char = os.read(fd, 1)
                if not char:
                    return False
                answer += char
                if char == b"\n":
                    return answer.lower() in (b"y\n", b"yes\n") and self.attended()
            termios.tcflush(fd, termios.TCIFLUSH)
        except (OSError, termios.error, ValueError):
            return False
        return False

    def _read_bounded_line(self, fd: int, max_len: int) -> bytes | None:
        answer = b""
        while len(answer) < max_len:
            char = os.read(fd, 1)
            if not char:
                return None
            answer += char
            if char == b"\n":
                return answer
        termios.tcflush(fd, termios.TCIFLUSH)
        return None

    def choose(self, message: str, options: Sequence[str]) -> int | None:
        if not options or not self.attended():
            return None
        try:
            fd = self.reader.fileno()
            termios.tcflush(fd, termios.TCIFLUSH)
            self.write(message)
            for idx, option in enumerate(options, 1):
                self.write(f"  {idx}. {option}")
            self.write(f"Enter 1-{len(options)} (or empty to cancel):")
            answer = self._read_bounded_line(fd, 8)
            if answer is None or not self.attended():
                return None
            raw = answer.decode("ascii", errors="ignore").strip()
            if not raw.isdecimal():
                return None
            choice = int(raw)
            return choice - 1 if 1 <= choice <= len(options) else None
        except (OSError, termios.error, ValueError):
            return None


def _production_backend() -> Backend:
    try:
        from .live import make_backend
    except ModuleNotFoundError as error:
        if error.name == "oc_openai.live":
            raise RouteUnavailable from None
        raise
    return make_backend()


def _local_status(backend: Backend) -> ConnectionStatus:
    status = backend.status()
    if type(status) is not ConnectionStatus or type(status.saved) is not tuple:
        raise RouteUnavailable
    labels = set()
    for entry in status.saved:
        if (
            type(entry) is not SavedProfile or not valid_label(entry.label)
            or type(entry.connected) is not bool or type(entry.revocation_unconfirmed) is not bool
            or type(entry.published) is not bool or entry.label in labels
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
        if not entry.published:
            connection = "sign-in incomplete"
        revocation = ", remote revocation unconfirmed" if entry.revocation_unconfirmed else ""
        terminal.write(f"{entry.label} ({connection}{active}{revocation})")
    if status.active is None:
        terminal.write("No saved registration is active.")


def _present_sign_in(terminal: Terminal, uri: str, launch: Callable[[], bool], *, manual: bool) -> None:
    if not terminal.attended():
        raise RouteUnavailable(Reason.FOREGROUND_REQUIRED)
    terminal.write(f"Sign-in link for this workstation\n{uri}")
    if manual:
        return
    if not terminal.attended():
        raise RouteUnavailable(Reason.FOREGROUND_REQUIRED)
    if not launch():
        terminal.write("Could not start the default browser. Copy the sign-in link above into another browser.")


def report_failure(terminal: Terminal, error: BaseException, *, operation: str = "") -> int:
    prefix = f"{operation}: " if operation else ""
    if isinstance(error, KeyboardInterrupt):
        terminal.error("Interrupted.")
        return 130
    if isinstance(error, ManagedCleanup):
        terminal.error("Managed worker cleanup needs verification.")
        if error.receipt_leaf is not None:
            terminal.error(f"Private receipt directory /tmp/{error.receipt_leaf}")
    elif isinstance(error, RouteUnavailable):
        terminal.error(prefix + _UNAVAILABLE_MESSAGES[error.reason])
    elif isinstance(error, ProfileError):
        terminal.error(prefix + _UNAVAILABLE_MESSAGES[_PROFILE_REASONS.get(error.code, Reason.QUALIFICATION)])
    else:
        terminal.error(prefix + "The ChatGPT plan command could not complete.")
    return 1


def _run_verify(terminal: Terminal, backend: Backend) -> int:
    result = backend.verify()
    if (not valid_label(result.label)
            or not isinstance(result.models, tuple) or not result.models
            or any(not isinstance(slug, str) or not slug or not slug.isascii() for slug in result.models)):
        raise RouteUnavailable(Reason.PROVIDER_DATA)
    models = ", ".join(result.models[:8])
    extra = f" (+{len(result.models) - 8} more)" if len(result.models) > 8 else ""
    terminal.write(f"Verified ChatGPT registration {result.label} ({result.readiness.value}): {models}{extra}")
    return 0


def _run_connect(terminal: Terminal, backend: Backend, label: str, *, manual: bool) -> int:
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
        "account binding, and installation-wide numeric usage accounting. The live proof "
        "sends fixed prompts to OpenAI only after separate authorization."
    )
    terminal.write(
        "If browser sign-in is needed, copy the sign-in link shown after approval into a browser "
        "on this workstation that can reach 127.0.0.1. Keep this terminal open."
    )
    if not terminal.confirm(f"Continue with ChatGPT for {label}?"):
        terminal.error("Cancelled.")
        return 1
    backend.connect(
        label, handoff=lambda uri, launch: _present_sign_in(terminal, uri, launch, manual=manual),
    )
    terminal.write(f"Connected ChatGPT registration {label} on this workstation.")
    return 0


def _valid_argv(argv: Sequence[str], command: str, *, labelled: bool, manual: bool) -> bool:
    if command == "connect":
        return (len(argv) == 2 or manual) and valid_canonical_label(argv[1])
    if labelled:
        return len(argv) == 2 and valid_label(argv[1])
    if command == "disconnect":
        return len(argv) == 1 or (len(argv) == 2 and valid_label(argv[1]))
    return len(argv) == 1 and command in _LOCAL_COMMANDS


def _run_disconnect(terminal: Terminal, backend: Backend, target_label: str | None) -> int:
    confirmed = backend.disconnect() if target_label is None else backend.disconnect(target_label)
    if confirmed is True:
        if target_label is None:
            terminal.write("ChatGPT is disconnected on this workstation.")
        else:
            terminal.write(f"ChatGPT registration {target_label} is disconnected on this workstation.")
        return 0
    terminal.error("ChatGPT is disconnected locally. Remote revocation could not be confirmed.")
    return 1


def run(
    argv: Sequence[str], *, terminal: Terminal, backend_factory: Callable[[], Backend] = _production_backend,
) -> int:
    command = argv[0] if argv else ""
    labelled = command in _LABEL_COMMANDS
    manual = command == "connect" and len(argv) == 3 and argv[2] == "--no-browser"
    if not _valid_argv(argv, command, labelled=labelled, manual=manual):
        terminal.error(USAGE)
        return 2
    if command == "connect" and not terminal.attended():
        terminal.error("An attended workstation terminal in the foreground is required.")
        return 2
    try:
        backend = backend_factory()
        if command == "connect":
            return _run_connect(terminal, backend, argv[1], manual=manual)
        if command == "select":
            label = argv[1]
            backend.select(label)
            terminal.write(f"Selected ChatGPT registration {label}.")
            return 0
        if command == "status":
            _show_status(terminal, _local_status(backend))
            return 0
        if command == "verify":
            return _run_verify(terminal, backend)
        return _run_disconnect(terminal, backend, argv[1] if len(argv) == 2 else None)
    except (Exception, KeyboardInterrupt) as error:
        return report_failure(terminal, error)
