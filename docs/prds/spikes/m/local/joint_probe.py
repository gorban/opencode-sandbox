#!/usr/bin/env python3
"""Qualify the real CoordHub with a disposable, offline OpenCode 2.3.0 job."""

from __future__ import annotations

import argparse
from collections.abc import Iterator
from concurrent.futures import Future
from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import secrets
import shutil
import signal
import sys
import tempfile
import threading
import time
from typing import TYPE_CHECKING

from broker import Broker, EARLY_TEXT, HOLD_TEXT, PROOF_CONTENT, PROOF_PATH
from client import ProbeError, Subscription
from probe import TARGET, check, close_resources, image_id, interrupt, pause_for_operator, report, stale_bearer
from relay import grant_record
from runtime import Job, JobRuntimeError, account_home

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from adapter import LocalOpenCodeTransport, PauseBarrier
from oc_coord_contract import (
    MAX_TURN_STREAM_EVENTS,
    CoordRole,
    DispatchOutcome,
    DispatchResult,
    PrincipalCtx,
    RevokedError,
    SandboxRecord,
    StreamEvent,
    TurnDispatch,
)
from oc_hub import CoordHub
from oc_registry import CoordRegistry

if TYPE_CHECKING:
    from test_restart_qualification import CombinedPassExpectations


OPERATOR = PrincipalCtx(CoordRole.OPERATOR, "fixture")
THREAD = "main"
EDIT_PROMPT = f"Use the write tool to create {PROOF_PATH} with the fixture contents."


class ProofTransport(LocalOpenCodeTransport):
    """Observe adapter entry and stream reader retirement at the hub boundary."""

    def __init__(self, job: Job, broker: Broker, *, pause: PauseBarrier | None = None):
        super().__init__(job, broker, sandbox_addr=TARGET, thread_id=THREAD, pause=pause)
        self.dispatches: list[str] = []
        self.stream_closed = threading.Event()
        self._watched_stream: tuple[str, Subscription] | None = None
        self.terminal_entry_stream_id: str | None = None

    def dispatch_turn(self, turn: TurnDispatch) -> DispatchResult:
        self.dispatches.append(turn.msg_id)
        return super().dispatch_turn(turn)

    def stream_events(self, stream_id: str) -> Iterator[StreamEvent]:
        self.stream_closed.clear()
        try:
            yield from super().stream_events(stream_id)
        finally:
            self.stream_closed.set()

    def _open_reader(self, stream_id: str) -> Subscription:
        # The fixture checks the adapter's actual SSE socket without consuming events.
        with self._lock:
            reservation = self._reservation
            if (self._closed_admission or reservation is None or reservation.stream is None
                    or reservation.stream.id != stream_id or not reservation.stream.reading):
                raise ProbeError("held stream reader was not active")
            reservation.events.assert_open()
            return reservation.events

    def watch_held_reader(self, stream_id: str) -> Subscription:
        reader = self._open_reader(stream_id)
        self._watched_stream = stream_id, reader
        return reader

    def confirm_incarnation_terminal(self, sandbox_addr: str, incarnation_id: str, *,
                                     owner_id: str, reason: str) -> bool:
        exact_owner = (sandbox_addr, incarnation_id, owner_id) == (self.sandbox_addr, self.incarnation, self._owner_id)
        if exact_owner and self._watched_stream is not None:
            stream_id, reader = self._watched_stream
            self._watched_stream = None
            try:
                if self._open_reader(stream_id) is reader:
                    self.terminal_entry_stream_id = stream_id
            except (OSError, ProbeError):
                # Continue terminal cleanup even if the liveness observation failed.
                pass
        return super().confirm_incarnation_terminal(
            sandbox_addr, incarnation_id, owner_id=owner_id, reason=reason,
        )


@contextmanager
def live_job(args: argparse.Namespace, generation: int) -> Iterator[tuple[Job, Broker]]:
    root = Path(tempfile.mkdtemp(prefix="ocm-", dir="/tmp"))
    job = Job(root, args.opencode_image, args.relay_image, secrets.token_hex(24),
              secrets.token_hex(24), "inc_" + secrets.token_hex(16), generation)
    broker = None
    succeeded = False
    try:
        job.prepare()
        broker = Broker(job.provider_socket, job.token)
        broker.start()
        job.start()
        yield job, broker
        succeeded = True
    finally:
        sigint = signal.getsignal(signal.SIGINT)
        sigterm = signal.getsignal(signal.SIGTERM)
        try:
            error = close_resources(job, broker, None)
        finally:
            signal.signal(signal.SIGINT, sigint)
            signal.signal(signal.SIGTERM, sigterm)
        if not succeeded or error is not None:
            print(f"Private run directory retained at {root}.", file=sys.stderr)
            if succeeded and error is not None:
                raise ProbeError(error)
        else:
            try:
                shutil.rmtree(root)
            except OSError:
                raise ProbeError(f"Run directory cleanup failed at {root}.") from None
            report("Verified removal of the owned worker, relay, and private run directory.")


@contextmanager
def open_hub(state_dir: Path, transport: ProofTransport) -> Iterator[tuple[CoordHub, CoordRegistry]]:
    with CoordRegistry(state_dir) as registry:
        hub = CoordHub(registry, transport, state_dir)
        try:
            check(not hub.is_degraded, "fixture hub opened degraded")
            # All dispatch is explicit. The background pump is left stopped.
            yield hub, registry
        finally:
            hub.close()


def register(hub: CoordHub, job: Job) -> SandboxRecord:
    return hub.register_sandbox(
        OPERATOR, name=TARGET, incarnation_id=job.incarnation, project_id="fixture",
        project_name="Synthetic fixture", branch="fixture", task_brief="Verify local OpenCode handoff",
    )


def bind_grant(hub: CoordHub, transport: ProofTransport, job: Job) -> tuple[str, int]:
    registered = register(hub, job)
    check(registered.incarnation_id == job.incarnation, "hub registered a different incarnation")
    edge = hub.grant_edge(
        OPERATOR, src_actor=OPERATOR.canonical_sender, dst_addr=TARGET,
        allowed_threads=(THREAD,), allowed_msg_kinds=("prompt",), grant_generation=job.generation,
    )
    transport.bind_grant(edge)
    return edge.edge_id, edge.grant_generation


def queue_turn(hub: CoordHub, text: str, *, transport: ProofTransport | None = None) -> tuple[str, int]:
    if transport is not None:
        transport.reserve()
    queued = hub.send(OPERATOR, target=TARGET, thread_id=THREAD, body_text=text)
    if transport is not None:
        transport.bind(queued["msg_id"])
    return queued["msg_id"], queued["seq"]


def wait_for_delta(hub: CoordHub, msg_id: str, since_seq: int, marker: str) -> None:
    deadline = time.monotonic() + 12
    tail = ""
    while (seconds := deadline - time.monotonic()) > 0:
        read = hub.wait(OPERATOR, targets=(TARGET,), since_seq=since_seq, timeout_s=min(seconds, 0.5))
        since_seq = read["last_seq"]
        for event in read["events"]:
            if event.get("dispatch_msg_id") != msg_id:
                continue
            if event["event_type"] == "text_delta":
                check(event["badge"] is None, "worker text unexpectedly had a trust badge")
                text = tail + event["text"]
                if marker in text:
                    return
                tail = text[-len(marker):]
            elif event["event_type"] in ("turn_completed", "turn_error", "revoked"):
                raise ProbeError("stream ended before the matching fixture delta")
    raise ProbeError("matching fixture delta did not reach the hub")


def read_outbox(registry: CoordRegistry, msg_id: str, status: str):
    return next((row for row in registry.list_outbox(statuses=(status,)) if row["msg_id"] == msg_id), None)


def wait_for_settlement(registry: CoordRegistry, transport: ProofTransport, msg_id: str, status: str) -> None:
    check(transport.stream_closed.wait(4), "hub stream reader did not close")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        row = read_outbox(registry, msg_id, status)
        if row is not None and row["attempts"] == 1:
            return
        time.sleep(0.02)
    raise ProbeError("stream did not settle into the expected durable state")


def prove_edit(hub: CoordHub, registry: CoordRegistry, transport: ProofTransport, job: Job, broker: Broker) -> str:
    job.assert_file(None)
    msg_id, seq = queue_turn(hub, EDIT_PROMPT, transport=transport)
    check(hub.dispatch_once(async_stream=True) == 1, "hub did not dispatch the edit turn")
    wait_for_delta(hub, msg_id, seq, EARLY_TEXT)
    report("Observed the fixture text delta through the hub.")
    wait_for_settlement(registry, transport, msg_id, "completed")
    job.assert_file(PROOF_CONTENT.encode("utf-8"))
    snapshot = broker.snapshot()
    check(snapshot["admitted"] == 2 and snapshot["rejected"] == 0,
          "the edit did not use exactly two scripted provider admissions")
    report(f"Verified the exact scratch file bytes in {PROOF_PATH} after terminal completion.")
    return msg_id


def assert_terminal(registry: CoordRegistry, transport: ProofTransport, job: Job) -> None:
    owner_id = transport.transport_owner_id(TARGET, job.incarnation)
    terminal = grant_record(job.incarnation, job.generation, False)
    check(job.terminal and (job.grant / "state").read_bytes() == terminal,
          "the exact relay grant was not published terminal")
    binding = registry.get_transport_binding(TARGET, job.incarnation)
    check(binding is not None and binding["owner_id"] == owner_id
          and binding["terminal_confirmed"] is True and binding["abort_requested"] is True,
          "hub did not durably confirm terminal authority for this relay")


def prove_held_revoke(hub: CoordHub, registry: CoordRegistry, transport: ProofTransport, job: Job,
                      broker: Broker) -> tuple[str, str, int]:
    broker.arm_hold()
    held, seq = queue_turn(hub, "Begin the fixture response that stays open.", transport=transport)
    check(hub.dispatch_once(async_stream=True) == 1, "hub did not dispatch the held turn")
    check(broker.wait_for_hold(8), "provider response never entered its hold")
    wait_for_delta(hub, held, seq, HOLD_TEXT)
    queued, queued_seq = queue_turn(hub, "Queue this turn for the restart check.")
    row = read_outbox(registry, queued, "pending")
    check(row is not None and row["attempts"] == 0, "the queued turn was dispatched early")
    before = broker.snapshot()
    check(before == {"admitted": 3, "active": 1, "rejected": 0}, "expected one active provider hold")
    report("Observed the held response through the hub and queued a separate turn.")

    held_row = read_outbox(registry, held, "handed_off")
    check(held_row is not None and held_row["attempts"] == 1 and isinstance(held_row["stream_id"], str),
          "the held turn lost its durable handoff before revoke")
    stream_id = held_row["stream_id"]
    before_events = registry.list_events_since((TARGET,), queued_seq - 1, limit=MAX_TURN_STREAM_EVENTS + 8)
    before_revoke_seq = before_events[-1]["seq"] if before_events else queued_seq
    reader = transport.watch_held_reader(stream_id)
    revoked = hub.revoke(OPERATOR, target=TARGET)
    check(revoked.incarnation_id == job.incarnation, "hub revoked a different incarnation")
    check(transport.terminal_entry_stream_id == stream_id, "terminal cleanup did not begin with the held reader open")
    assert_terminal(registry, transport, job)
    check(broker.wait_for_hold_revoked(1), "the held provider socket did not shut down at revoke")
    wait_for_settlement(registry, transport, held, "aborted")
    closed_row = read_outbox(registry, held, "aborted")
    check(closed_row is not None and closed_row["stream_id"] == stream_id and reader.wire.sock.fileno() < 0,
          "revoke did not close the original reader and settle its durable handoff")
    after_events = registry.list_events_since((TARGET,), before_revoke_seq, limit=MAX_TURN_STREAM_EVENTS + 8)
    check(not any(event.get("dispatch_msg_id") == held and event["event_type"] not in ("revoked", "turn_error")
                  for event in after_events if event["source"] == "stream_event"),
          "ordinary held-stream output appeared after revoke started")
    job.assert_running()
    stale_bearer(job, time.monotonic() + 5)
    check(broker.snapshot() == {"admitted": before["admitted"], "active": 0, "rejected": 1},
          "stale bearer check changed admissions or left an active stream")
    report("Revoked through the hub, observed both streams close, and verified HTTP 403 for the stale bearer.")
    return held, queued, queued_seq


def prove_reopened(hub: CoordHub, registry: CoordRegistry, transport: ProofTransport, job: Job,
                   broker: Broker, queued: str, queued_seq: int, container_ids: dict[str, str]) -> None:
    job.assert_running()
    check(job.ids == container_ids, "worker or relay identity changed across hub reopen")
    assert_terminal(registry, transport, job)
    check(transport.confirm_incarnation_terminal(
        TARGET, job.incarnation, owner_id=transport.transport_owner_id(TARGET, job.incarnation),
        reason="fixture_terminal_check",
    ) is True, "trusted owner did not reconfirm the terminal relay after reopen")
    before = broker.snapshot()
    check(before == {"admitted": 3, "active": 0, "rejected": 1},
          "provider state changed while reopening the hub")
    check(hub.dispatch_once() == 0, "reopened hub dispatched a revoked row")
    check(queued not in transport.dispatches and broker.snapshot() == before,
          "the queued turn reached the adapter or admitted a provider request")
    row = read_outbox(registry, queued, "cancelled")
    check(row is not None and row["attempts"] == 0 and row["stream_id"] is None,
          "the queued turn gained a durable attempt or stream")
    # At most the held and queued turns can contribute events after admission.
    events = registry.list_events_since((TARGET,), queued_seq - 1, limit=2 * MAX_TURN_STREAM_EVENTS + 8)
    check(not any(event.get("dispatch_msg_id") == queued or event.get("message_id") == queued
                  for event in events if event["source"] == "stream_event"),
          "the queued turn gained a worker event")
    try:
        register(hub, job)
    except RevokedError:
        pass
    else:
        raise ProbeError("the reopened hub accepted the revoked incarnation")
    report("Reopened with the same running worker and relay. The old row stayed cancelled with zero dispatches.")


def prove_restart(args: argparse.Namespace, state_dir: Path) -> CombinedPassExpectations:
    from test_restart_qualification import CombinedPassExpectations, verify_combined_pass_evidence

    with live_job(args, generation=1) as (job, broker):
        transport = ProofTransport(job, broker)
        with open_hub(state_dir, transport) as (hub, registry):
            grant = bind_grant(hub, transport, job)
            first = prove_edit(hub, registry, transport, job, broker)
            if args.attended:
                pause_for_operator()
            held, queued, queued_seq = prove_held_revoke(hub, registry, transport, job, broker)
            job.assert_running()
            container_ids = job.ids.copy()
        evidence = CombinedPassExpectations(
            completed_msg_ids=(first,), cancelled_msg_ids=(queued,), aborted_msg_ids=(held,),
            expected_attempts={first: 1, queued: 0, held: 1}, tombstoned_grants=(grant,),
            expected_stream_substrings={first: EARLY_TEXT}, expected_revoked_sandboxes=(TARGET,),
        )
        with open_hub(state_dir, transport) as (hub, registry):
            prove_reopened(hub, registry, transport, job, broker, queued, queued_seq, container_ids)
            verify_combined_pass_evidence(registry, evidence)
    return evidence


def dispatch_paused(hub: CoordHub, registry: CoordRegistry, transport: ProofTransport, job: Job,
                    pause: PauseBarrier, msg_id: str) -> float:
    dispatched: Future[int] = Future()

    def dispatch() -> None:
        try:
            dispatched.set_result(hub.dispatch_once())
        except Exception as exc:
            dispatched.set_exception(exc)

    thread = threading.Thread(target=dispatch, daemon=True)
    thread.start()
    try:
        check(pause.acknowledged.wait(8), "relay did not return pause receipt P")
        started = read_outbox(registry, msg_id, "dispatch_started")
        check(started is not None and started["attempts"] == 1, "paused turn had no durable handoff attempt")
        start = time.monotonic()
        revoked = hub.revoke(OPERATOR, target=TARGET)
        elapsed = time.monotonic() - start
        check(elapsed < 0.5 and revoked.incarnation_id == job.incarnation,
              "revoke did not finish within 500 ms while the first write was paused")
        assert_terminal(registry, transport, job)
        paused = read_outbox(registry, msg_id, "dispatch_started")
        check(paused is not None and paused["attempts"] == 1 and paused["stream_id"] is None
              and not dispatched.done() and pause.outcome is None,
              "paused attempt settled before the relay returned a receipt")
        pause.release.set()
    finally:
        # On failure the bounded relay pause expires without authorizing a write.
        thread.join(12)
    check(not thread.is_alive(), "paused dispatch did not stop")
    dispatched.result(timeout=0)
    return elapsed


def prove_pause(args: argparse.Namespace, state_dir: Path) -> None:
    from test_restart_qualification import CombinedPassExpectations, verify_combined_pass_evidence

    with live_job(args, generation=1) as (job, broker):
        pause = PauseBarrier()
        transport = ProofTransport(job, broker, pause=pause)
        with open_hub(state_dir, transport) as (hub, registry):
            grant = bind_grant(hub, transport, job)
            msg_id, _ = queue_turn(hub, "Verify that the revoked turn writes zero bytes.", transport=transport)
            elapsed = dispatch_paused(hub, registry, transport, job, pause, msg_id)
            check(pause.outcome is DispatchOutcome.ZERO_BYTES_SENT, "relay did not return zero-write receipt Z")
            check(transport.dispatches == [msg_id], "paused turn was dispatched more than once")
            check(broker.snapshot() == {"admitted": 0, "active": 0, "rejected": 0},
                  "paused turn reached the provider")
            job.assert_running()
            assert_terminal(registry, transport, job)
            verify_combined_pass_evidence(registry, CombinedPassExpectations(
                cancelled_msg_ids=(msg_id,), expected_attempts={msg_id: 1},
                tombstoned_grants=(grant,), expected_revoked_sandboxes=(TARGET,),
            ))
            report(f"Observed relay receipt P, revoke in {elapsed * 1000:.0f} ms, then zero-write receipt Z.")


def prove_replacement(args: argparse.Namespace, state_dir: Path, prior: CombinedPassExpectations) -> None:
    from test_restart_qualification import verify_combined_pass_evidence

    with live_job(args, generation=2) as (job, broker):
        transport = ProofTransport(job, broker)
        with open_hub(state_dir, transport) as (hub, registry):
            grant = bind_grant(hub, transport, job)
            msg_id = prove_edit(hub, registry, transport, job, broker)
            hub.revoke(OPERATOR, target=TARGET)
            assert_terminal(registry, transport, job)
            verify_combined_pass_evidence(registry, replace(
                prior,
                completed_msg_ids=(*prior.completed_msg_ids, msg_id),
                expected_attempts={**prior.expected_attempts, msg_id: 1},
                tombstoned_grants=(*prior.tombstoned_grants, grant),
                expected_stream_substrings={**prior.expected_stream_substrings, msg_id: EARLY_TEXT},
            ))
            report("Verified a fresh authorized incarnation completed at the original address.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opencode-image", required=True, type=image_id, help="full local OpenCode 2.3.0 image ID")
    parser.add_argument("--relay-image", required=True, type=image_id, help="full local Python relay image ID")
    parser.add_argument("--attended", action="store_true", help="pause up to 30 seconds after the first edit")
    args = parser.parse_args(argv)
    if args.attended and not sys.stdin.isatty():
        parser.error("--attended requires a terminal")

    signal.signal(signal.SIGTERM, interrupt)
    root: Path | None = None
    try:
        # The registry checks every ancestor. The shared devbox /tmp is only for Podman scratch.
        root = Path(tempfile.mkdtemp(prefix=".ocm-joint-", dir=account_home().resolve()))
        evidence = prove_restart(args, root / "restart")
        prove_pause(args, root / "paused")
        prove_replacement(args, root / "restart", evidence)
        shutil.rmtree(root)
        report("Joint OpenCode and CoordHub proof passed with verified cleanup.")
        return 0
    except KeyboardInterrupt:
        error, code = "Run interrupted.", 130
    except (ProbeError, JobRuntimeError) as exc:
        error, code = str(exc), 1
    except Exception as exc:
        error, code = f"Run failed ({type(exc).__name__}).", 1
    if root is not None:
        error = f"{error} Private coordination state retained at {root}."
    print(error, file=sys.stderr)
    return code


if __name__ == "__main__":
    os.umask(0o077)
    sys.exit(main())
