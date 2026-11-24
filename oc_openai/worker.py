"""Launch the fixed local OpenCode acceptance workflow under a host-owned grant."""

import re
import secrets
import shutil
import tempfile
import time
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from .managed import protocol
from .managed.broker import Broker
from .managed.client import OpenCode, ProbeError, TurnEvents, TurnPins
from .managed.runtime import (
    Job, JobRuntimeError, PUBLIC_CONTROL_VALUE, SHARED_TMP, check_devbox, image_environments,
)

WORKER_IMAGE = "edc96b3f8ef46d2309577c259167813fc943edd6e344db08848e48ec3ed4f278"
RELAY_IMAGE = "2893cf9f584f34cfa2d0b8dd6ba9e63dfacd1e1105a304bb4f72317b00f89029"


class WorkerError(RuntimeError):
    """A bounded local worker failure."""


class WorkerProofError(WorkerError):
    def __init__(self, phase, fault):
        if phase not in (None, "initial", "continuation") or type(fault) is not protocol.Fault:
            raise ValueError("Invalid worker failure category")
        super().__init__("Managed worker proof did not complete")
        self.phase = phase
        self.fault = fault


class WorkerCleanupError(WorkerError):
    """Exact, retained private receipt for one uncertain worker cleanup."""

    def __init__(self, receipt_leaf):
        if type(receipt_leaf) is not str or not re.fullmatch(r"oc-i4a-[a-z0-9_]{8}", receipt_leaf):
            raise ValueError("Invalid managed worker receipt leaf")
        self.receipt_leaf = receipt_leaf
        super().__init__("Managed worker cleanup could not be verified")


@dataclass(frozen=True)
class WorkerEvidence:
    initial_receipt: bool = True
    continuation_receipt: bool = True
    native_tool: bool = True
    native_terminal: bool = True
    exact_file: bool = True
    cleanup_verified: bool = True


def require_worker_prerequisites():
    """Check the qualified host and both cached pins before a possible billed turn."""
    try:
        check_devbox()
        image_environments({"worker": WORKER_IMAGE, "relay": RELAY_IMAGE})
    except JobRuntimeError as error:
        raise WorkerError(str(error)) from None
    except OSError:
        raise WorkerError("Managed worker prerequisites could not be verified") from None


class _NativeWrite:
    def __init__(self):
        self.identity = None
        self.called = False
        self.succeeded = False

    def accept(self, event, observer):
        kind, data = event.get("type"), event.get("data")
        if (type(kind) is not str or not kind.startswith("session.tool.")
                or not observer.delivered or not isinstance(data, dict)
                or data.get("sessionID") != observer.pins.thread_id):
            return
        assistant_id, call_id = data.get("assistantMessageID"), data.get("id")
        if (type(assistant_id) is not str or assistant_id not in observer.assistants
                or type(call_id) is not str or not re.fullmatch(r"call_[A-Za-z0-9_-]{1,123}", call_id)):
            raise WorkerError("OpenCode reported unbound tool evidence")
        identity = (assistant_id, call_id)
        if kind == "session.tool.input.started":
            if self.identity is not None or data.get("name") != "write":
                raise WorkerError("OpenCode reported an unexpected tool start")
            self.identity = identity
            return
        if (identity != self.identity or kind == "session.tool.failed"
                or data.get("status") in ("failed", "error", "cancelled", "incomplete")):
            raise WorkerError("OpenCode reported an unexpected tool identity or failure")
        if kind == "session.tool.called":
            if (self.called or data.get("executed") is not False
                    or data.get("input") != {"path": protocol.PROOF_PATH,
                                            "content": protocol.PROOF_BYTES.decode("ascii")}):
                raise WorkerError("OpenCode reported an unexpected tool call")
            self.called = True
        elif kind == "session.tool.success":
            if (not self.called or self.succeeded or data.get("executed") is not False
                    or data.get("status", "completed") != "completed"):
                raise WorkerError("OpenCode reported an unexpected tool result")
            self.succeeded = True


def _native_turn(job):
    client = OpenCode(job.control_socket, PUBLIC_CONTROL_VALUE, sandbox_addr=job.run_label,
                      incarnation_id=job.incarnation, grant_generation=job.generation)
    thread = client.create_session(time.monotonic() + 12)
    pins = TurnPins(job.run_label, job.incarnation, thread, "msg_" + secrets.token_hex(16), job.generation)
    observer = TurnEvents(pins)
    deadline = min(time.monotonic() + 85, job.lease.deadline_ns / 1e9)
    early_text = ""
    final_text = ""
    tool = _NativeWrite()
    with client.events(deadline) as events:
        client.prompt(pins, protocol.PROMPT, time.monotonic() + 12)
        for native in events:
            event = observer.accept(native)
            tool.accept(native, observer)
            if event is not None:
                if event.kind == "text_delta":
                    if not tool.called:
                        early_text += event.text
                        matches = protocol.INITIAL_TEXT.startswith(early_text)
                    else:
                        final_text += event.text
                        matches = protocol.FINAL_TEXT.startswith(final_text)
                    if not matches:
                        raise WorkerError("OpenCode text did not match the approved workflow")
                elif event.kind == "turn_error":
                    raise WorkerError("OpenCode reported that the managed turn failed")
                elif event.kind == "turn_completed":
                    if (early_text in ("", protocol.INITIAL_TEXT) and final_text == protocol.FINAL_TEXT
                            and tool.succeeded):
                        return tool.identity[1]
                    raise WorkerError("OpenCode terminal lacks native text or tool evidence")
    raise WorkerError("OpenCode event subscription ended before the terminal")


def _cleanup(job, broker):
    # A failed terminal write still drops the lifetime and stops the relay.
    terminal_error = None
    if job.lease is not None:
        try:
            job.revoke()
        except (JobRuntimeError, OSError):
            terminal_error = WorkerError("Managed grant termination was unconfirmed")
    try:
        if broker is not None:
            broker.close()
    finally:
        job.close()
    if terminal_error is not None:
        raise terminal_error


def run_worker(responses, *, model, before_dispatch, worker_image=WORKER_IMAGE, relay_image=RELAY_IMAGE,
               lease_guard=None, allow_progress=False, allow_metadata=False):
    """Run one approved turn and return evidence only after exact cleanup.

    The trusted before_dispatch(phase) callback durably consumes that phase's
    reservation under the admission fence. The trusted responses(body, *,
    deadline, cancelled) callable yields decoded response events. It must
    observe the cancellation event and monotonic deadline before upstream
    send and while reading. It runs outside the relay delivery fence.
    The optional trusted lease_guard(job) context owns additional host
    revocation state from prepared placement through cleanup.
    """
    if (not callable(responses) or not callable(before_dispatch) or not isinstance(model, str)
            or (lease_guard is not None and not callable(lease_guard))
            or worker_image not in (WORKER_IMAGE, f"sha256:{WORKER_IMAGE}")
            or relay_image not in (RELAY_IMAGE, f"sha256:{RELAY_IMAGE}")):
        raise WorkerError("Invalid managed worker invocation")
    root = Path(tempfile.mkdtemp(prefix="oc-i4a-", dir=SHARED_TMP))
    job = Job(root, worker_image, relay_image, model, "inc_" + secrets.token_hex(16))
    broker = None
    verified = False
    clean = False
    try:
        with ExitStack() as stack:
            try:
                job.prepare()
                if lease_guard is not None:
                    stack.enter_context(lease_guard(job))
                job.assert_file(None)
                broker = Broker(
                    job, responses, before_dispatch, allow_progress=allow_progress, allow_metadata=allow_metadata,
                )
                broker.start()
                job.start()
                job.activate(broker)
                call_id = _native_turn(job)
                if not broker.done.wait(timeout=2) or not broker.complete(call_id):
                    raise WorkerError("Managed tool continuation receipt is missing")
                job.assert_file(protocol.PROOF_BYTES)
                verified = True
            except (JobRuntimeError, ProbeError, WorkerError, OSError, ValueError):
                if broker is None:
                    raise WorkerProofError(None, protocol.Fault.PLACEMENT) from None
                failure = broker.failure() or (None, protocol.Fault.NATIVE)
                raise WorkerProofError(*failure) from None
            finally:
                try:
                    try:
                        _cleanup(job, broker)
                    finally:
                        # Drain the guard after attempting terminal/resource
                        # cleanup. Its retained registration may need the
                        # receipt even when both containers are gone.
                        stack.close()
                    clean = True
                except (OSError, RuntimeError, ValueError):
                    raise WorkerCleanupError(root.name) from None
    finally:
        if clean:
            try:
                shutil.rmtree(root)
            except OSError:
                raise WorkerCleanupError(root.name) from None
    if not clean:
        raise WorkerCleanupError(root.name)
    if not verified:
        raise WorkerError("Managed worker result could not be verified")
    return WorkerEvidence()
