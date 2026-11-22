#!/usr/bin/env python3
"""Run the standalone, offline OpenCode 2.3.0 proof from the trusted devbox."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import secrets
import select
import shutil
import signal
import sys
import tempfile
import time

from broker import Broker, EARLY_TEXT, HOLD_TEXT, MODEL_ID, MODEL_PATH, PROOF_CONTENT, PROOF_PATH
from client import (
    DispatchOutcome, OpenCode, ProbeError, Response, TurnEvent, TurnEvents, TurnPins, remaining, request, unix_wire,
)
from runtime import Job, RuntimeError as JobError


IMAGE_ID = re.compile(r"(?:sha256:)?[a-f0-9]{64}")
TARGET = "local-poc"


def image_id(value: str) -> str:
    if not IMAGE_ID.fullmatch(value):
        raise argparse.ArgumentTypeError("provide a full local image ID, with optional sha256: prefix")
    return value


def report(message: str) -> None:
    print(message, flush=True)


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeError(message)


def pins(job: Job, thread: str) -> TurnPins:
    return TurnPins(TARGET, job.incarnation, thread, "msg_" + secrets.token_hex(12), job.generation)


def marker_matches(event: TurnEvent, tails: dict[tuple[str, int], str], marker: str) -> bool:
    if event.text_part is None:
        return False
    seen = tails.get(event.text_part, "") + event.text
    tails[event.text_part] = seen[-len(marker):]
    return marker in seen


def observe(events, turn: TurnEvents, marker: str, *, wait_for_terminal: bool) -> None:
    tails: dict[tuple[str, int], str] = {}
    found = False
    for native in events:
        event = turn.accept(native)
        if event is None:
            continue
        if not found and marker_matches(event, tails, marker):
            if not wait_for_terminal:
                return
            found = True
            report("Observed the fixture text delta before the terminal event.")
        if event.kind == "turn_completed":
            check(found and wait_for_terminal, "turn completed before the expected text delta")
            return
        if event.kind == "turn_error":
            raise ProbeError("worker reported a turn failure or interruption")
    raise ProbeError("event stream ended before the proof was complete")


def stale_bearer(job: Job, deadline: float) -> None:
    raw = request("POST", MODEL_PATH, host="fixture.local", auth=f"Bearer {job.token}",
                  accept="text/event-stream", body={
                      "model": MODEL_ID, "stream": True,
                      "messages": [{"role": "user", "content": "Disposable fixture credential check"}],
                  })
    with unix_wire(job.provider_socket, deadline) as wire:
        wire.write(raw)
        response = Response(wire, status=403)
        check(b"".join(response.chunks(256)) == b"", "stale bearer denial was not empty")


def pause_for_operator() -> None:
    report("Press Enter to start the held response and revoke. This pause expires in 30 seconds.")
    ready, _, _ = select.select([sys.stdin], [], [], 30)
    if ready and sys.stdin.read(1) == "\n":
        return
    raise ProbeError("attended pause ended without Enter")


def prove(job: Job, broker: Broker, attended: bool) -> None:
    client = OpenCode(job.control_socket, job.password, sandbox_addr=TARGET,
                      incarnation_id=job.incarnation, grant_generation=job.generation)
    job.assert_file(None)
    report("Verified the scratch proof file is absent.")
    thread = client.create_session(time.monotonic() + 12)
    first = pins(job, thread)
    with client.events(time.monotonic() + 30) as events:
        client.prompt(first, f"Use the write tool to create {PROOF_PATH} with the fixture contents.",
                      time.monotonic() + 12)
        observe(events, TurnEvents(first), EARLY_TEXT, wait_for_terminal=True)
    job.assert_file(PROOF_CONTENT.encode("utf-8"))
    baseline = broker.snapshot()
    check(baseline["admitted"] == 2 and baseline["rejected"] == 0,
          "the proof did not use exactly the two scripted provider admissions")
    report(f"Verified the native write produced the expected bytes in {PROOF_PATH}.")
    if attended:
        pause_for_operator()

    held = pins(job, thread)
    deadline = time.monotonic() + 30
    with client.events(deadline) as events:
        broker.arm_hold()
        client.prompt(held, "Begin the fixture response that stays open.", time.monotonic() + 12)
        check(broker.wait_for_hold(min(8, remaining(deadline))), "the fixture stream never entered its hold")
        observe(events, TurnEvents(held), HOLD_TEXT, wait_for_terminal=False)
        before_revoke = broker.snapshot()
        check(before_revoke == {"admitted": baseline["admitted"] + 1, "active": 1, "rejected": 0},
              "the broker did not have exactly one active held stream")
        report("Observed the held model response with its broker stream still active.")

        # Separate attempt queued before revocation. The relay cannot attempt its
        # worker-facing write until the host releases this pause.
        with client.pause_prompt(pins(job, thread), "Verify the revoked fixture sends zero bytes.",
                                 time.monotonic() + 10) as paused:
            report("Paused a separate worker-facing write before the grant check.")
            events.assert_open()
            broker.revoke()
            job.revoke()
            events.await_eof(time.monotonic() + 2)
            outcome = paused.receipt()
            check(outcome is DispatchOutcome.ZERO_BYTES_SENT,
                  f"paused write did not prove zero bytes ({outcome.value})")
        check(broker.wait_for_hold_revoked(1), "the held broker socket did not shut down at revoke")
    report(f"Revoked the grant, observed closure of the model and control streams, and received {outcome.value}.")

    job.assert_running()
    stale_bearer(job, time.monotonic() + 5)
    after_revoke = broker.snapshot()
    check(after_revoke["admitted"] == before_revoke["admitted"] and after_revoke["active"] == 0
          and after_revoke["rejected"] == before_revoke["rejected"] + 1,
          "stale bearer check changed admissions or left an active broker stream")
    job.assert_running()
    report("Verified HTTP 403 for the stale bearer with both containers running and zero new admissions.")


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


def close_resources(job: Job, broker: Broker | None, error: str | None) -> str | None:
    # A second signal should not interrupt verified cleanup.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if broker is not None:
        try:
            broker.close()
        except Exception as exc:
            print(f"Broker cleanup failed ({type(exc).__name__}).", file=sys.stderr)
            error = error or "Broker cleanup failed."
    try:
        job.close()
    except JobError as exc:
        print(str(exc), file=sys.stderr)
        error = error or "Container cleanup failed."
    except Exception as exc:
        print(f"Container cleanup failed ({type(exc).__name__}).", file=sys.stderr)
        error = error or "Container cleanup failed."
    return error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opencode-image", required=True, type=image_id, help="full local OpenCode 2.3.0 image ID")
    parser.add_argument("--relay-image", required=True, type=image_id, help="full local Python relay image ID")
    parser.add_argument("--attended", action="store_true", help="pause up to 30 seconds after the first proof")
    args = parser.parse_args(argv)
    if args.attended and not sys.stdin.isatty():
        parser.error("--attended requires a terminal")

    signal.signal(signal.SIGTERM, interrupt)
    root = Path(tempfile.mkdtemp(prefix="ocm-", dir="/tmp"))
    job = Job(root, args.opencode_image, args.relay_image, secrets.token_hex(24),
              secrets.token_hex(24), "inc_" + secrets.token_hex(16))
    broker = None
    error = None
    interrupted = False
    try:
        job.prepare()
        broker = Broker(job.provider_socket, job.token)
        broker.start()
        job.start()
        prove(job, broker, args.attended)
    except KeyboardInterrupt:
        interrupted = True
        error = "Run interrupted."
    except (ProbeError, JobError) as exc:
        error = str(exc)
    except Exception as exc:
        error = f"Run failed ({type(exc).__name__})."
    finally:
        error = close_resources(job, broker, error)

    if error is None:
        try:
            shutil.rmtree(root)
        except OSError:
            error = "Run directory cleanup failed."
    if error is not None:
        print(f"{error} Private run directory retained at {root}.", file=sys.stderr)
        return 130 if interrupted else 1
    report("Verified removal of both owned containers and the run directory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
