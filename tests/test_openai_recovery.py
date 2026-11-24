"""Qualification of one recovery approval against a synthetic provider."""

from contextlib import closing, contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import pwd
import tempfile
import time
import unittest
from unittest.mock import patch

from oc_openai.acceptance import run_attended
from oc_openai import cli
from oc_openai.connection import Connection
from oc_openai.exposure import ExposureError, ExposureLedger, Phase, Slot, binding_digest
from oc_openai.live import WorkerRouteUnavailable, WorkstationBackend
from oc_openai.recovery import (
    RecoveryLedger, _REVIEWED_METADATA, _REVIEWED_PREVIOUS, _REVIEWED_PROGRESS, _REVIEWED_TRACE, _REVIEWED_WORKER,
)
from oc_openai.responses import Cancellation, OpenAITransport, StreamFailure, _StreamEvidence, encode_responses_body
from oc_openai.worker import WorkerCleanupError, WorkerProofError, run_worker
from test_openai_live import (
    FakeConnection, GENERATION, REGISTRATION, SELECTION_EPOCH, Terminal, fake_worker, proposal_events,
)
from test_openai_worker import fixture_events

SOURCE = "a" * 64
PRIOR_NAMES = ("exposure.json", "diagnostic.json", "diagnostic-stream.json")


class RecoveryProofTests(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.ledger = ExposureLedger(self.state)
        self.binding = binding_digest(REGISTRATION, GENERATION, SELECTION_EPOCH)
        self.ledger.reserve(self.slot("1"))
        self.ledger.reserve_diagnostic(self.ledger.prepare_diagnostic(self.slot("2")))
        self.stream = self.ledger.prepare_diagnostic(self.slot("3"), stream=True)
        self.ledger.reserve_diagnostic(self.stream)
        self.old = [(self.state / name).read_bytes() for name in PRIOR_NAMES]
        self.connection = FakeConnection(self.state)
        self.receipt = self.state / "recovery-proof.json"

    def slot(self, token, phase=Phase.ORCHESTRATOR):
        return Slot(token * 32, self.binding, phase)

    def run_recovery(self, terminal, worker=fake_worker):
        current = WorkstationBackend(
            self.connection, self.ledger, label="personal", selection_epoch=SELECTION_EPOCH,
            worker=worker, placement_qualified=True,
        )

        class Frontend:
            connection = current.connection

            @contextmanager
            def recovery_proof(self, proposal, source):
                proof = current.recovery_proof(proposal, source)
                try:
                    yield proof
                finally:
                    proof.ledger.close()

        outcome = run_attended(terminal, backend_factory=Frontend, recovery_source=SOURCE)
        self.assertEqual([(self.state / name).read_bytes() for name in PRIOR_NAMES], self.old)
        return outcome

    def prepare_worker_retry(self, *, worker=run_worker, settled=True):
        predecessor = self.slot("4")
        old = RecoveryLedger(self.ledger, predecessor, _REVIEWED_PREVIOUS)
        old.approve(time.monotonic(), lambda: True)
        old.reserve(predecessor)
        old.settle(predecessor, 3, 7)
        initial = replace(predecessor, phase=Phase.INITIAL)
        old.reserve(initial)
        if settled:
            old.settle(initial, 3, 2)
        old.close()
        backend = WorkstationBackend(
            self.connection, self.ledger, label="personal", selection_epoch=SELECTION_EPOCH,
            worker=worker, placement_qualified=True,
        )
        self.connection.recovery_receipt = "recovery-worker.json"
        approval = cli.Approval("5" * 32, backend.connection(), cli.Stage.WORKER)
        return backend, approval

    def prepare_progress_retry(self, *, worker=run_worker, settled=True):
        backend, approval = self.prepare_worker_retry(worker=worker)
        previous = backend.recovery_proof(approval, _REVIEWED_WORKER, worker_only=True)
        previous.ledger.approve(time.monotonic(), lambda: True)
        slot = self.slot("5", Phase.INITIAL)
        previous.ledger.reserve(slot)
        if settled:
            previous.ledger.settle(slot, 4, 5)
        previous.ledger.close()
        self.connection.recovery_receipt = "recovery-worker-progress.json"
        return backend, replace(approval, run_id="6" * 32)

    def prepare_trace(self, *, worker=None):
        backend, approval = self.prepare_progress_retry(
            worker=worker or (lambda *a, **kw: self.fail("worker started")),
        )
        previous = backend.recovery_proof(
            approval, _REVIEWED_PROGRESS, worker_only=True, after_retry=True,
        )
        previous.ledger.approve(time.monotonic(), lambda: True)
        slot = self.slot("6", Phase.INITIAL)
        previous.ledger.reserve(slot)
        previous.ledger.settle(slot, 4, 5)
        previous.ledger.close()
        return backend, replace(approval, run_id="7" * 32)

    def prepare_metadata_retry(self):
        backend, approval = self.prepare_trace(worker=run_worker)
        trace = backend.recovery_proof(
            approval, _REVIEWED_TRACE, worker_only=True, after_retry=True, trace_only=True,
        )
        trace.ledger.approve(time.monotonic(), lambda: True)
        slot = self.slot("7", Phase.INITIAL)
        trace.ledger.reserve(slot)
        trace.ledger.settle(slot, 4, 5)
        trace.ledger.close()
        self.connection.recovery_receipt = "recovery-worker-metadata.json"
        return backend, replace(approval, run_id="8" * 32)

    def test_one_consent_reaches_all_three_verified_phases(self):
        terminal = Terminal(True)
        self.assertEqual(self.run_recovery(terminal), 0, terminal.output)
        self.assertIn("5,532,000 input", terminal.output[0])
        self.assertIn("without another prompt", terminal.output[0])
        self.assertIn("Verified tool delivery and worker cleanup", terminal.output[-1])
        phases = json.loads(self.receipt.read_text())["phases"]
        self.assertEqual([row["phase"] for row in phases], [phase.value for phase in Phase])
        self.assertTrue(all(row["actual"] is not None for row in phases))
        self.assertEqual(len(self.connection.calls), 3)

    def test_wrong_marker_settles_only_proposal(self):
        self.connection.proposal = list(proposal_events("sensitive fixture text"))
        terminal = Terminal(True)
        self.assertEqual(self.run_recovery(terminal), 1)
        self.assertNotIn("sensitive fixture", " ".join(terminal.output))
        self.assertEqual(len(self.connection.calls), 1)
        phases = json.loads(self.receipt.read_text())["phases"]
        self.assertEqual([row["actual"] for row in phases], [[3, 7]])

    def test_sse_with_empty_media_parameters_settles_usage_without_probe(self):
        from test_openai_connection_transport import WireTests, _sse_chunks

        backend = WorkstationBackend(
            self.connection, self.ledger, label="personal", selection_epoch=SELECTION_EPOCH,
            worker=fake_worker, placement_qualified=True,
        )
        proposal = cli.Approval("4" * 32, backend.connection(), cli.Stage.ORCHESTRATOR)
        wire = _sse_chunks([
            b"data: " + json.dumps(event).encode("ascii") + b"\n\n" for event in proposal_events()
        ]).replace(b"Content-Type: text/event-stream\r\n",
                   b"Content-Type: text/event-stream; ; charset=utf-8;\r\n", 1)

        @contextmanager
        def route(binding, body, before_send, *, inspect_media, observe_media, before_write):
            def dispatch(write):
                before_send()
                before_write()
                return write()

            with OpenAITransport().responses(
                body, "synthetic-access", Cancellation(time.monotonic() + 2), dispatch,
                inspect_media=inspect_media, observe_media=observe_media,
            ) as events:
                yield events

        proof = backend.recovery_proof(proposal, SOURCE)
        proof.ledger.approve(time.monotonic(), lambda: True)
        with (WireTests().response(wire), patch.object(self.connection, "responses", route),
              patch("oc_openai.responses._inspect_prefix") as probe):
            self.assertEqual(proof.propose(proposal), cli.PROPOSAL_MARKER)
            probe.assert_not_called()
        phases = json.loads(self.receipt.read_text())["phases"]
        self.assertEqual([row["actual"] for row in phases], [[3, 7]])

    def test_invalid_usage_and_refused_consent_stop_before_worker(self):
        self.assertEqual(self.run_recovery(Terminal(False)), 1)
        self.assertFalse(self.receipt.exists())
        self.connection.proposal[-1]["response"]["usage"]["total_tokens"] += 1
        self.assertEqual(self.run_recovery(Terminal(True)), 1)
        self.assertEqual(len(self.connection.calls), 1)
        self.assertIsNone(json.loads(self.receipt.read_text())["phases"][-1]["actual"])
        self.assertEqual(self.run_recovery(Terminal()), 1)

    def test_expiry_blocks_dispatch_but_allows_in_flight_settlement(self):
        proposal = self.slot("4")
        proof = RecoveryLedger(self.ledger, proposal, SOURCE)
        with self.assertRaisesRegex(ExposureError, "diagnostic_unavailable"):
            proof.reserve(proposal)
        with patch("oc_openai.recovery.time.monotonic", return_value=1):
            proof.approve(1, lambda: True)
            proof.reserve(proposal)
        with patch("oc_openai.recovery.time.monotonic", return_value=301):
            with self.assertRaisesRegex(ExposureError, "diagnostic_unavailable"):
                proof.require_dispatch()
            proof.settle(proposal, 3, 7)
            with self.assertRaisesRegex(ExposureError, "diagnostic_unavailable"):
                proof.reserve(self.slot("4", Phase.INITIAL))
        self.assertEqual(json.loads(self.receipt.read_text())["phases"][-1]["actual"], [3, 7])

    def test_nonexact_predecessor_conflict_and_replay_fail_closed(self):
        proposal = self.slot("4")
        first = RecoveryLedger(self.ledger, proposal, SOURCE)
        competing = RecoveryLedger(self.ledger, self.slot("5"), SOURCE)
        identical = RecoveryLedger(self.ledger, proposal, SOURCE)
        for permit in (first, competing, identical):
            permit.approve(time.monotonic(), lambda: True)
        for phase in (Phase.INITIAL, Phase.CONTINUATION):
            with self.assertRaises(ExposureError):
                first.reserve(replace(proposal, phase=phase))
        first.reserve(proposal)
        with self.assertRaises(ExposureError):
            identical.settle(proposal, 1, 1)
        with self.assertRaises(ExposureError):
            competing.reserve(self.slot("5"))
        with self.assertRaises(ExposureError):
            first.reserve(proposal)
        with self.assertRaisesRegex(ExposureError, "unsettled_exposure"):
            first.reserve(replace(proposal, phase=Phase.INITIAL))
        with self.assertRaises(ExposureError):
            self.ledger.settle_diagnostic(self.stream, 1, 1)
        with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
            first.settle(proposal, 1, 128_001)
        with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
            first.reserve(replace(proposal, phase=Phase.INITIAL))
        first.close()
        with self.assertRaisesRegex(ExposureError, "diagnostic_already_reserved"):
            RecoveryLedger(self.ledger, self.slot("5"), SOURCE)

    def test_mutation_of_history_or_corrupt_recovery_state_fails_closed(self):
        proof = RecoveryLedger(self.ledger, self.slot("4"), SOURCE)
        proof.approve(time.monotonic(), lambda: True)
        self.receipt.write_text("false")
        self.receipt.chmod(0o600)
        with self.assertRaises(ExposureError):
            proof.reserve(self.slot("4"))
        self.assertEqual(self.receipt.read_text(), "false")
        self.receipt.unlink()
        old_stream = self.state / PRIOR_NAMES[-1]
        previous = json.loads(old_stream.read_text())
        old_stream.write_text(json.dumps({**previous, "run": "7" * 32}))
        with self.assertRaises(ExposureError):
            proof.reserve(self.slot("4"))
        self.assertFalse(self.receipt.exists())

    def test_expiry_or_foreground_loss_after_reservation_denies_first_byte(self):
        home = pwd.getpwuid(os.getuid()).pw_dir
        connection_dir = self.enterContext(tempfile.TemporaryDirectory(dir=home))
        connection = Connection(Path(connection_dir))
        proposal = self.slot("4")
        proof = RecoveryLedger(self.ledger, proposal, SOURCE)
        writes = []
        approved_at = time.monotonic()

        for expiry in (True, False):
            with self.subTest(expiry=expiry):
                proof = RecoveryLedger(self.ledger, proposal, SOURCE)
                current = approved_at
                still_attended = True

                def reserve():
                    nonlocal current, still_attended
                    proof.reserve(proposal)
                    if expiry:
                        current += 301
                    else:
                        still_attended = False

                with patch("oc_openai.recovery.time") as clock:
                    clock.monotonic.side_effect = lambda: current
                    proof.approve(approved_at, lambda: still_attended)
                    dispatch = connection._dispatch(
                        lambda record: None, Cancellation(time.monotonic() + 2), reserve,
                        before_write=proof.require_dispatch,
                    )
                    with self.assertRaisesRegex(ExposureError, "diagnostic_unavailable"):
                        dispatch(lambda: writes.append(True))
                self.assertEqual(writes, [])
                self.assertIsNone(json.loads(self.receipt.read_text())["phases"][0]["actual"])
                self.receipt.unlink()  # A new scenario in this test's synthetic directory.

    def test_foreground_loss_after_proposal_does_not_start_worker(self):
        terminal = Terminal(True)
        terminal.attended = lambda: not any(line.startswith("Verified the recovery") for line in terminal.output)
        self.assertEqual(self.run_recovery(terminal, worker=lambda *a, **kw: self.fail("worker started")), 1)
        phases = json.loads(self.receipt.read_text())["phases"]
        self.assertEqual([phase["actual"] for phase in phases], [[3, 7]])

    def test_blocking_revalidation_does_not_extend_the_consent(self):
        terminal = Terminal(True)
        original = self.connection.binding

        def advance():
            clock.monotonic.return_value = 301
            return original()

        with (patch("oc_openai.recovery.time") as clock,
              patch("oc_openai.acceptance.time") as approval_time):
            clock.monotonic.return_value = 1

            def timestamp():
                self.connection.binding = advance
                return 1

            approval_time.monotonic.side_effect = timestamp
            self.assertEqual(self.run_recovery(terminal), 1)
        self.assertEqual(self.connection.calls, [])
        self.assertFalse(self.receipt.exists())

    @unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned devbox Podman")
    def test_attended_recovery_with_pinned_worker_and_synthetic_upstream(self):
        terminal = Terminal(True)
        self.assertEqual(self.run_recovery(terminal, worker=run_worker), 0, terminal.output)
        self.assertEqual(len(self.connection.calls), 3)

    @unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned devbox Podman")
    def test_recovery_worker_refuses_unapproved_tool_after_settling_usage(self):
        def wrong_tool(body, **options):
            for event in fixture_events(body, **options):
                if event["type"] == "response.completed":
                    event["response"]["output"][-1]["arguments"] = '{"path":"/unexpected","content":"fixture"}'
                yield event

        self.connection.worker_events = wrong_tool
        terminal = Terminal(True)
        self.assertEqual(self.run_recovery(terminal, worker=run_worker), 1, terminal.output)
        self.assertEqual(len(self.connection.calls), 2)
        rows = json.loads(self.receipt.read_text())["phases"]
        self.assertEqual([row["actual"] for row in rows], [[3, 7], [3, 2]])
        self.assertNotIn("Private receipt directory", " ".join(terminal.output))
        self.assertIn("approved write-call validation", " ".join(terminal.output))

    def test_retry_needs_settled_worker_evidence(self):
        backend, approval = self.prepare_worker_retry(settled=False)
        with self.assertRaises(cli.RouteUnavailable):
            backend.recovery_proof(approval, SOURCE, worker_only=True)
        self.assertEqual(self.connection.calls, [])

    def test_progress_retry_rejects_unsettled_predecessor_and_fences_old_modes(self):
        backend, approval = self.prepare_progress_retry(settled=False)
        with self.assertRaises(cli.RouteUnavailable):
            backend.recovery_proof(approval, SOURCE, worker_only=True, after_retry=True)
        target = self.state / "recovery-worker-progress.json"
        target.write_text("corrupt")
        with self.assertRaises(ExposureError):
            self.ledger.require_quiescent()
        with self.assertRaisesRegex(ExposureError, "diagnostic_already_reserved"):
            RecoveryLedger(self.ledger, self.slot("9", Phase.INITIAL), SOURCE, worker_only=True)
        with self.assertRaises(cli.RouteUnavailable):
            backend.recovery_proof(approval, SOURCE, worker_only=True, after_retry=True)

    def test_progress_faults_settle_verified_usage_without_delivering_a_tool(self):
        import threading
        from oc_openai.managed import protocol

        observations = (
            ({"type": "response.synthetic_private_label"}, protocol.Fault.EVENT_UNKNOWN),
            ({"type": "response.output_item.added", "output_index": 0, "item": {"type": "custom_tool_call"}},
             protocol.Fault.EVENT_ITEM),
            ({"type": "response.refusal.delta", "delta": "fixture_private_reason"}, protocol.Fault.EVENT_UNSUPPORTED),
            *(
                ({"type": "response.queued", "response": {
                    "id": "resp_example1", "status": "queued", **contradiction,
                }}, protocol.Fault.EVENT_SEQUENCE)
                for contradiction in (
                    {"output": [{"type": "custom_tool_call"}]},
                    {"error": {"message": "fixture_private_reason"}},
                    {"incomplete_details": {"reason": "fixture_private_reason"}},
                )
            ),
        )
        for item, expected in observations:
            with self.subTest(expected=expected):
                def upstream(body, **kwargs):
                    for event in fixture_events(body, **kwargs):
                        yield event
                        if event["type"] == "response.created":
                            yield item

                def worker(responses, *, model, before_dispatch, lease_guard, allow_progress):
                    before_dispatch("initial")
                    cancel = threading.Event()
                    events = responses(protocol.body_for(model), deadline=time.monotonic() + 2, cancelled=cancel)
                    with self.assertRaises(protocol.Refused) as refusal:
                        protocol.validate(events, model, True, cancel, allow_progress=allow_progress)
                    raise WorkerProofError("initial", refusal.exception.fault)

                # Each subcase owns a fresh synthetic installation.
                case = RecoveryProofTests()
                case.setUp()
                try:
                    backend, approval = case.prepare_progress_retry(worker=worker)
                    case.connection.worker_events = upstream
                    proof = backend.recovery_proof(approval, SOURCE, worker_only=True, after_retry=True)
                    proof.ledger.approve(time.monotonic(), lambda: True)
                    with self.assertRaises(WorkerRouteUnavailable) as failure:
                        proof.prove(approval)
                    self.assertEqual(failure.exception.failure.fault, expected)
                    self.assertNotIn("private", failure.exception.describe())
                    rows = json.loads((case.state / "recovery-worker-progress.json").read_text())["phases"]
                    self.assertEqual([(row["phase"], row["actual"]) for row in rows], [("initial", [3, 2])])
                finally:
                    case.doCleanups()

    def test_trace_uses_same_initial_wire_body_with_one_settlement_and_no_worker(self):
        import threading
        from oc_openai.managed import protocol
        from test_openai_connection_transport import WireTests, _sse_chunks

        for unknown in (False, True):
            with self.subTest(unknown=unknown):
                case = RecoveryProofTests()
                case.setUp()
                try:
                    backend, approval = case.prepare_trace()
                    expected = protocol.body_for(cli.MODEL)
                    frames = list(fixture_events(expected, deadline=time.monotonic() + 2, cancelled=threading.Event()))
                    if unknown:
                        frames.insert(1, {"type": "response.fixture_unknown"})
                    wire = _sse_chunks([b"data: " + json.dumps(frame).encode() + b"\n\n" for frame in frames])

                    @contextmanager
                    def route(binding, body, before_send, *, inspect_media, observe_media, before_write):
                        def dispatch(write):
                            before_send()
                            before_write()
                            return write()

                        with OpenAITransport().responses(
                            body, "synthetic-access", Cancellation(time.monotonic() + 2), dispatch,
                            inspect_media=inspect_media, observe_media=observe_media,
                        ) as events:
                            yield events

                    proof = backend.recovery_proof(
                        approval, SOURCE, worker_only=True, after_retry=True, trace_only=True,
                    )
                    proof.ledger.approve(time.monotonic(), lambda: True)
                    with self.assertRaises(cli.RouteUnavailable):
                        proof.prove(approval)
                    with (WireTests().response(wire) as request, patch.object(case.connection, "responses", route),
                          patch.object(protocol, "project", side_effect=AssertionError("trace tried to deliver a tool")),
                          closing(proof.trace_initial(approval)) as upstream):
                        if unknown:
                            with self.assertRaises(protocol.Refused) as fault:
                                protocol.validate(upstream, cli.MODEL, True, threading.Event(), allow_progress=True)
                            self.assertIs(fault.exception.fault, protocol.Fault.EVENT_UNKNOWN)
                        else:
                            protocol.validate(upstream, cli.MODEL, True, threading.Event(), allow_progress=True)
                    self.assertEqual(request[2], encode_responses_body(expected))
                    rows = json.loads((case.state / "recovery-worker-trace.json").read_text())["phases"]
                    self.assertEqual([(row["phase"], row["actual"]) for row in rows], [("initial", [3, 2])])
                    with self.assertRaises(cli.RouteUnavailable):
                        list(proof.trace_initial(approval))
                finally:
                    case.doCleanups()

    def test_moderation_trace_retains_prior_phase_and_fences_execution_and_replay(self):
        import threading
        from oc_openai.managed import protocol

        backend, approval = self.prepare_metadata_retry()
        previous = backend.recovery_proof(
            approval, _REVIEWED_METADATA, worker_only=True, after_retry=True, after_trace=True,
        )
        previous.ledger.approve(time.monotonic(), lambda: True)
        slot = self.slot("8", Phase.INITIAL)
        previous.ledger.reserve(slot)
        previous.ledger.settle(slot, 3, 2)
        previous.ledger.close()
        prior = self.state / "recovery-worker-metadata.json"
        prior_contents = prior.read_bytes()
        self.connection.recovery_receipt = "recovery-worker-moderation.json"
        approval = replace(approval, run_id="9" * 32)

        def upstream(body, *, deadline, cancelled):
            for event in fixture_events(body, deadline=time.monotonic() + 2, cancelled=threading.Event()):
                yield event
                if event["type"] == "response.created":
                    yield {"type": "response.metadata", "response_id": event["response"]["id"],
                           "sequence_number": 1,
                           "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {}}}}

        self.connection.worker_events = upstream
        proof = backend.recovery_proof(
            approval, SOURCE, worker_only=True, after_retry=True, after_trace=True, moderation_trace=True,
        )
        proof.ledger.approve(time.monotonic(), lambda: True)
        with self.assertRaises(cli.RouteUnavailable):
            proof.prove(approval)
        with closing(proof.trace_initial(approval)) as events, self.assertRaises(protocol.Refused) as error:
            protocol.validate(events, cli.MODEL, True, threading.Event(), allow_progress=True, allow_metadata=True)
        self.assertIs(error.exception.fault, protocol.Fault.METADATA_MODERATION)
        self.assertEqual(len(self.connection.calls), 1)
        rows = json.loads((self.state / self.connection.recovery_receipt).read_bytes())["phases"]
        self.assertEqual([(row["phase"], row["actual"]) for row in rows], [("initial", [3, 2])])
        self.assertEqual(prior.read_bytes(), prior_contents)
        with self.assertRaises(cli.RouteUnavailable):
            list(proof.trace_initial(approval))

    def test_cleanup_receipt_takes_precedence_over_stream_diagnostic(self):
        import threading
        from oc_openai.managed.protocol import body_for

        def damaged_stream(_body, **_options):
            raise StreamFailure("provider_stream_incomplete", _StreamEvidence())

        def cleanup_uncertain(events, *, model, before_dispatch, lease_guard):
            before_dispatch("initial")
            with self.assertRaises(StreamFailure):
                list(events(body_for(model), deadline=time.monotonic() + 2, cancelled=threading.Event()))
            raise WorkerCleanupError("oc-i4a-01234567")

        backend, approval = self.prepare_worker_retry(worker=cleanup_uncertain)
        self.connection.worker_events = damaged_stream
        proof = backend.recovery_proof(approval, SOURCE, worker_only=True)
        proof.ledger.approve(time.monotonic(), lambda: True)
        with self.assertRaises(cli.ManagedCleanup) as error:
            proof.prove(approval)
        terminal = Terminal()
        self.assertEqual(cli.report_failure(terminal, error.exception), 1)
        self.assertIn("Private receipt directory /tmp/oc-i4a-01234567", terminal.output)

    @unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned devbox Podman")
    def test_worker_only_retry_delivers_tool_only_result_with_done_reasoning(self):
        def upstream(body, **kwargs):
            for event in fixture_events(body, **kwargs, reasoning=True, tool_only=True, done_only=True):
                yield event
                if event["type"] == "response.created":
                    yield {"type": "response.queued", "response": {**event["response"], "status": "queued"}}
                    yield {"type": "keepalive"}
                    yield {"type": "response.metadata", "response_id": event["response"]["id"],
                           "sequence_number": 1, "metadata": {"openai_verification_recommendation": [],
                               "openai_chatgpt_moderation_metadata": {"presentation": "inline"}}}

        backend, approval = self.prepare_metadata_retry()
        self.connection.worker_events = upstream
        before = self.receipt.read_bytes()
        before_worker = (self.state / "recovery-worker.json").read_bytes()
        proof = backend.recovery_proof(approval, SOURCE, worker_only=True, after_retry=True, after_trace=True)
        proof.ledger.approve(time.monotonic(), lambda: True)
        result = proof.prove(approval)
        self.assertTrue(result.native_terminal and result.exact_scratch and result.exact_receipt
                        and result.owned_cleanup)
        rows = json.loads((self.state / "recovery-worker-metadata.json").read_text())["phases"]
        self.assertEqual([row["phase"] for row in rows], ["initial", "continuation"])
        self.assertEqual(self.receipt.read_bytes(), before)
        self.assertEqual((self.state / "recovery-worker.json").read_bytes(), before_worker)
        self.assertEqual(len(self.connection.calls), 2)
        with self.assertRaises(cli.RouteUnavailable):
            backend.recovery_proof(approval, SOURCE, worker_only=True, after_retry=True, after_trace=True)

    @unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned devbox Podman")
    def test_safety_buffering_after_tool_item_blocks_delivery_and_continuation(self):
        backend, approval = self.prepare_metadata_retry()

        def upstream(body, **kwargs):
            for event in fixture_events(body, **kwargs, tool_only=True):
                if event["type"] == "response.completed":
                    yield {"type": "response.output_item.done", "output_index": 0,
                           "item": event["response"]["output"][0]}
                    yield {"type": "response.in_progress", "safety_buffering": {"active": True}}
                yield event

        self.connection.worker_events = upstream
        proof = backend.recovery_proof(approval, SOURCE, worker_only=True, after_retry=True, after_trace=True)
        proof.ledger.approve(time.monotonic(), lambda: True)
        with self.assertRaises(WorkerRouteUnavailable) as failure:
            proof.prove(approval)
        self.assertIn("safety buffering", failure.exception.describe())
        rows = json.loads((self.state / "recovery-worker-metadata.json").read_text())["phases"]
        self.assertEqual([(row["phase"], row["actual"]) for row in rows], [("initial", [3, 2])])
        self.assertEqual(len(self.connection.calls), 1)

    @unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned devbox Podman")
    def test_worker_only_conflicting_reasoning_settles_without_tool_or_continuation(self):
        backend, approval = self.prepare_worker_retry()

        def conflict(body, **kwargs):
            for event in fixture_events(body, **kwargs, reasoning=True, tool_only=True):
                if event["type"] == "response.output_item.done":
                    event["item"]["encrypted_content"] = "private_canary_different_value"
                yield event

        self.connection.worker_events = conflict
        proof = backend.recovery_proof(approval, SOURCE, worker_only=True)
        proof.ledger.approve(time.monotonic(), lambda: True)
        with self.assertRaises(WorkerRouteUnavailable) as failure:
            proof.prove(approval)
        self.assertIn("stateless reasoning validation", failure.exception.describe())
        self.assertNotIn("private_canary", failure.exception.describe())
        self.assertEqual(len(self.connection.calls), 1)
        rows = json.loads((self.state / "recovery-worker.json").read_text())["phases"]
        self.assertEqual([(row["phase"], row["actual"]) for row in rows], [("initial", [3, 2])])
