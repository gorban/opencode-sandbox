"""Exercise the attended command and accounting with a synthetic workstation connection."""

from contextlib import contextmanager
from copy import deepcopy
from functools import partial
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from oc_openai.acceptance import run_attended
from oc_openai import cli, live
from oc_openai.connection import Binding, ConnectionError
from oc_openai.exposure import ExposureLedger, Phase, RecoveryMode, Slot, binding_digest
from oc_openai.managed.protocol import body_for, validate
from oc_openai.profiles import ProfileError
from oc_openai.responses import response_error
from oc_openai.worker import WorkerEvidence, run_worker
from test_openai_worker import fixture_events

MODEL = cli.MODEL
REGISTRATION = "r" * 43
GENERATION = "g" * 43
SELECTION_EPOCH = "s" * 43
NEXT_GENERATION = "h" * 43


def proposal_events(text=cli.PROPOSAL_MARKER, *, tokens=(3, 7)):
    response = {"id": "resp_proposal", "model": MODEL}
    yield {"type": "response.created", "response": response}
    yield {"type": "response.completed", "response": {
        **response, "status": "completed",
        "output": [
            {"type": "reasoning", "summary": []},
            {"type": "message", "role": "assistant", "status": "completed",
             "content": [{"type": "output_text", "text": text}]},
        ],
        "usage": {"input_tokens": tokens[0], "output_tokens": tokens[1], "total_tokens": sum(tokens)},
    }}


class FakeConnection:
    def __init__(self, state):
        self.state = state
        self.selected = Binding(generation=GENERATION, profile=REGISTRATION)
        self.catalog = (MODEL,)
        self.calls = []
        self.proposal = list(proposal_events())
        self.proposal_error = None
        self.worker_events = fixture_events
        self.recovery_receipt = "recovery-proof.json"

    def require_prerequisites(self):
        pass

    def binding(self):
        if self.selected is None:
            raise ConnectionError("openai_connection_required")
        return self.selected

    def require_active(self, binding):
        if binding != self.selected:
            raise ConnectionError("connection_retired")

    @contextmanager
    def worker_lease(self, binding, job):
        self.require_active(binding)
        yield

    @contextmanager
    def responses(self, binding, body, before_send, *, deadline=None, cancelled=None, inspect_media=False,
                  observe_media=None, before_write=None):
        self.require_active(binding)
        if body["model"] not in self.catalog:
            raise ConnectionError("openai_model_unavailable")
        before_send()
        if before_write is not None:
            before_write()
            records = json.loads((self.state / self.recovery_receipt).read_text())["phases"]
        else:
            records = json.loads((self.state / "exposure.json").read_text())
        assert records[-1]["actual"] is None
        self.calls.append(deepcopy(body))
        if "instructions" not in body:
            if self.proposal_error is not None:
                raise self.proposal_error
            yield iter(self.proposal)
        else:
            yield self.worker_events(body, deadline=deadline, cancelled=cancelled)


class Terminal:
    def __init__(self, *approvals):
        self.approvals = iter(approvals)
        self.output = []

    def attended(self):
        return True

    def write(self, message):
        self.output.append(message)

    error = write

    def confirm(self, message):
        self.write(message)
        approval = next(self.approvals)
        return approval() if callable(approval) else approval


def fake_worker(events, *, model, before_dispatch, lease_guard):
    deadline = time.monotonic() + 10
    cancel = threading.Event()
    before_dispatch("initial")
    source = list(events(body_for(model), deadline=deadline, cancelled=cancel))
    output = source[-1]["response"]["output"]
    before_dispatch("continuation")
    list(events(body_for(model, output), deadline=deadline, cancelled=cancel))
    return WorkerEvidence()


class LiveBackendTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.state = Path(scratch.name)
        self.connection = FakeConnection(self.state)
        self.ledger = ExposureLedger(self.state)

    def backend(self, *, worker=fake_worker, placement=True):
        return live.WorkstationBackend(self.connection, self.ledger, label="personal", selection_epoch=SELECTION_EPOCH,
                                       worker=worker, placement_qualified=placement)

    def accept(self, terminal, backend):
        return run_attended(terminal, backend_factory=lambda: backend)

    def test_unsettled_reservation_refuses_before_approval_prompt(self):
        self.ledger.reserve(Slot(
            "1" * 32, binding_digest(REGISTRATION, GENERATION, SELECTION_EPOCH), Phase.ORCHESTRATOR,
        ))
        ledger = self.state / "exposure.json"
        before = ledger.read_bytes()
        terminal = Terminal()

        self.assertEqual(self.accept(terminal, self.backend()), 1)
        self.assertEqual(self.connection.calls, [])
        self.assertEqual(ledger.read_bytes(), before)
        self.assertEqual(len(terminal.output), 1)
        self.assertIn("Workstation proposal: A prior request is unsettled", terminal.output[0])

    def _hold_proposal(self):
        self.ledger.reserve(Slot(
            "1" * 32, binding_digest(REGISTRATION, GENERATION, SELECTION_EPOCH), Phase.ORCHESTRATOR,
        ))
        return (self.state / "exposure.json").read_bytes()

    def test_diagnostic_never_spawns_worker_or_opens_a_second_attempt(self):
        for name, events, result, usage in (
            ("complete", list(proposal_events()), 0, [3, 7]),
            ("wrong marker", list(proposal_events("private model output")), 1, [3, 7]),
            ("missing completion", [next(proposal_events())], 1, None),
            ("overage", list(proposal_events(tokens=(3, 128_001))), 1, [3, 128_001]),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as scratch:
                self.state = Path(scratch)
                self.connection = FakeConnection(self.state)
                self.ledger = ExposureLedger(self.state)
                before = self._hold_proposal()
                self.connection.proposal = events
                terminal = Terminal(True)
                backend = self.backend(worker=lambda *args, **kwargs: self.fail("worker ran during diagnostic"))

                self.assertEqual(run_attended(terminal, backend_factory=lambda: backend, recovery=RecoveryMode.FIRST),
                                 result)
                self.assertEqual(self.connection.calls, [live._proposal_body()])
                self.assertIn("total reserved exposure is 1,844,000 input and 256,000 output",
                              terminal.output[0])
                self.assertIn("Review the app's OpenAI-managed usage and credit settings before approving.",
                              terminal.output[0])
                self.assertEqual(terminal.output[1], "Send the one workstation diagnostic request?")
                self.assertNotIn("private model output", "\n".join(terminal.output))
                self.assertEqual((self.state / "exposure.json").read_bytes(), before)
                receipt = json.loads((self.state / "diagnostic.json").read_text())
                self.assertEqual(receipt["original_run"], "1" * 32)
                self.assertNotEqual(receipt["run"], receipt["original_run"])
                self.assertEqual(receipt["actual"], usage)

                self.ledger = ExposureLedger(self.state)
                for recovery in (None, RecoveryMode.FIRST):
                    stopped = Terminal()
                    self.assertEqual(run_attended(stopped, backend_factory=self.backend, recovery=recovery), 1)
                    self.assertEqual(len(stopped.output), 1)
                    self.assertIn("diagnostic receipt already exists", stopped.output[0])
                self.assertEqual(len(self.connection.calls), 1)

    def test_diagnostic_decline_interrupt_and_changed_selection_spend_no_ticket(self):
        original = self._hold_proposal()
        backend = self.backend()

        def interrupt():
            raise KeyboardInterrupt

        def rotate():
            self.connection.selected = Binding(generation=NEXT_GENERATION, profile=REGISTRATION)
            return True

        for answer, result in ((False, 1), (interrupt, 130), (rotate, 1)):
            with self.subTest(answer=answer):
                terminal = Terminal(answer)
                self.assertEqual(run_attended(terminal, backend_factory=lambda: backend, recovery=RecoveryMode.FIRST),
                                 result)
                self.assertFalse((self.state / "diagnostic.json").exists())
                self.assertEqual((self.state / "exposure.json").read_bytes(), original)
                self.assertEqual(self.connection.calls, [])

    def test_stream_diagnostic_counts_both_prior_reservations_and_cannot_repeat(self):
        for complete in (False, True):
            with self.subTest(complete=complete), tempfile.TemporaryDirectory() as scratch:
                self.state = Path(scratch)
                self.connection = FakeConnection(self.state)
                self.ledger = ExposureLedger(self.state)
                self._hold_proposal()
                prior = self.ledger.prepare_diagnostic(Slot(
                    "2" * 32, binding_digest(REGISTRATION, GENERATION, SELECTION_EPOCH), Phase.ORCHESTRATOR,
                ))
                self.ledger.reserve_diagnostic(prior)
                paths = [self.state / name for name in ("exposure.json", "diagnostic.json")]
                before = [path.read_bytes() for path in paths]
                if not complete:
                    self.connection.proposal_error = ConnectionError("provider_stream_json")
                backend = self.backend(worker=lambda *args, **kwargs: self.fail("stream diagnostic spawned a worker"))
                declined = Terminal(False)
                self.assertEqual(run_attended(declined, backend_factory=lambda: backend, recovery=RecoveryMode.STREAM), 1)
                self.assertFalse((self.state / "diagnostic-stream.json").exists())
                self.assertEqual(self.connection.calls, [])

                terminal = Terminal(True)
                self.assertEqual(run_attended(terminal, backend_factory=lambda: backend, recovery=RecoveryMode.STREAM),
                                 0 if complete else 1)
                self.assertIn("first diagnostic both remain unknown", terminal.output[0])
                self.assertIn("2,766,000 input and 384,000 output tokens", terminal.output[0])
                self.assertIn("Review the app's OpenAI-managed usage and credit settings", terminal.output[0])
                self.assertEqual(terminal.output[1], "Send the one workstation stream diagnostic request?")
                if not complete:
                    self.assertIn("An OpenAI stream event contained invalid JSON.", terminal.output[-1])
                self.assertEqual([path.read_bytes() for path in paths], before)
                receipt = json.loads((self.state / "diagnostic-stream.json").read_text())
                self.assertEqual(receipt["previous_diagnostic_run"], prior.request.run_id)
                self.assertEqual(receipt["actual"], [3, 7] if complete else None)

                self.ledger = ExposureLedger(self.state)
                for recovery in (None, RecoveryMode.FIRST, RecoveryMode.STREAM):
                    refused = Terminal()
                    self.assertEqual(run_attended(refused, backend_factory=self.backend, recovery=recovery), 1)
                    self.assertEqual(len(refused.output), 1)
                    self.assertIn("diagnostic receipt already exists", refused.output[0])
                self.assertEqual(self.connection.calls, [live._proposal_body()])

    def test_invalid_recovery_mode_is_rejected_before_backend(self):
        self._hold_proposal()
        for mode in (False, True, "stream"):
            with self.subTest(mode=mode):
                terminal = Terminal()
                self.assertEqual(run_attended(
                    terminal, backend_factory=lambda: self.fail("backend was constructed"), recovery=mode,
                ), 2)
                self.assertEqual(terminal.output, ["The OpenAI proof recovery mode is invalid."])
        self.assertEqual(self.connection.calls, [])
        self.assertFalse((self.state / "diagnostic.json").exists())

    def test_settled_full_ledger_reports_capacity_and_refuses_before_prompt(self):
        slot = Slot("1" * 32, binding_digest(REGISTRATION, GENERATION, SELECTION_EPOCH), Phase.ORCHESTRATOR)
        self.ledger.reserve(slot)
        self.ledger.settle(slot, 1, 1)
        ledger = self.state / "exposure.json"
        row = json.loads(ledger.read_text())[0]
        ledger.write_text(json.dumps([{**row, "run": f"{index:032x}"} for index in range(256)]))
        before = ledger.read_bytes()
        terminal = Terminal()

        self.assertEqual(self.accept(terminal, self.backend()), 1)
        self.assertEqual(self.connection.calls, [])
        self.assertEqual(ledger.read_bytes(), before)
        self.assertEqual(terminal.output, [
            "Workstation proposal: The inference ledger is at capacity. Further inference is suspended.",
        ])

    def test_proposal_lock_refusal_keeps_the_stage_label(self):
        terminal = Terminal(True)
        backend = self.backend()
        with patch.object(backend, "propose", side_effect=ProfileError("profile_busy")):
            self.assertEqual(self.accept(terminal, backend), 1)
        self.assertTrue(terminal.output[-1].startswith("Workstation proposal: A foreground ChatGPT"))
        self.assertEqual(self.connection.calls, [])

    def test_proposal_failure_has_a_fixed_stage_and_safe_cause(self):
        canary = "must-not-appear-in-terminal"
        rejected = response_error(403, {"error": {"code": canary, "message": canary}, "id": canary})
        created, completed = proposal_events()
        for category, error, events, detail in [
            ("connection", ConnectionError("provider_network_error"), [], "closed unexpectedly"),
            ("http", ConnectionError(rejected), [], "OpenAI rejected the request"),
            ("malformed stream", ConnectionError("invalid_provider_stream"), [], "invalid or oversized"),
            ("unknown exception", RuntimeError(canary), [], "plan command could not complete"),
            ("failed response", None, [created, {"type": "response.failed", "response": {
                "error": {"code": canary, "message": canary}, "id": canary,
            }}], "failed or incomplete"),
            ("usage limit", None, [created, {"type": "response.failed", "response": {"error": {
                "code": "subscription_sharing_usage_limit_exceeded", "message": canary,
            }}}], "plan usage limit"),
            ("wrong identity", None, [created, {**completed, "response": {
                **completed["response"], "id": canary,
            }}], "identity or model did not match"),
            ("no usage", None, [created, {**completed, "response": {
                **completed["response"], "usage": {"stray": canary},
            }}], "did not contain valid terminal usage"),
            ("clean EOF", None, [created], "ended without a completed response"),
        ]:
            with self.subTest(category=category), tempfile.TemporaryDirectory() as scratch:
                self.state = Path(scratch)
                self.connection = FakeConnection(self.state)
                self.ledger = ExposureLedger(self.state)
                self.connection.proposal_error = error
                self.connection.proposal = events
                terminal = Terminal(True)

                self.assertEqual(self.accept(terminal, self.backend()), 1)
                self.assertTrue(terminal.output[-1].startswith("Workstation proposal: "))
                self.assertIn(detail, terminal.output[-1])
                self.assertNotIn(canary, "\n".join(terminal.output))
                self.assertEqual(len(self.connection.calls), 1)
                rows = json.loads((self.state / "exposure.json").read_text())
                self.assertEqual([(row["phase"], row["actual"]) for row in rows], [("orchestrator", None)])

    def test_workstation_state_must_stay_outside_the_canonical_sandbox(self):
        with tempfile.TemporaryDirectory() as case:
            home = Path(case)
            expected = home / ".config" / "oc-sandbox" / "openai"
            self.assertEqual(live._state_directory(home, home), expected)
            with self.assertRaises(cli.RouteUnavailable):
                live._state_directory(home, home / "not-the-os-account-home")
            (home / "opencode-sandbox").symlink_to(home / ".config", target_is_directory=True)
            with self.assertRaises(cli.RouteUnavailable):
                live._state_directory(home, home)
            self.assertFalse(expected.exists())

    def test_attended_proof_reserves_exact_sequence_and_validates_evidence(self):
        self.connection.proposal[0]["response"].pop("model")
        terminal = Terminal(True, True)
        self.assertEqual(self.accept(terminal, self.backend()), 0, terminal.output)
        self.assertEqual(len(self.connection.calls), 3)
        input_items = self.connection.calls[0]["input"]
        self.assertEqual(input_items, [{"type": "message", "role": "user", "content": cli.ORCHESTRATOR_INPUT}])
        records = json.loads((self.state / "exposure.json").read_text())
        self.assertEqual([item["phase"] for item in records], ["orchestrator", "initial", "continuation"])
        self.assertEqual(len({(r["run"], r["binding"]) for r in records}), 1)
        self.assertEqual([item["actual"] for item in records], [[3, 7], [3, 2], [3, 2]])
        self.assertIn("Verified tool delivery and worker cleanup", terminal.output[-1])

    def test_unqualified_placement_or_missing_catalog_model_prevents_spend(self):
        self.assertEqual(self.accept(Terminal(True), self.backend(placement=False)), 1)
        self.connection.catalog = ()
        self.assertEqual(self.accept(Terminal(True), self.backend()), 1)
        self.assertEqual(self.connection.calls, [])

    def test_generation_change_during_second_consent_prevents_worker(self):
        def rotate():
            self.connection.selected = Binding(generation=NEXT_GENERATION, profile=REGISTRATION)
            return True

        def unexpected_worker(*args, **kwargs):
            self.fail("worker started for a stale approval")

        self.assertEqual(self.accept(Terminal(True, rotate), self.backend(worker=unexpected_worker)), 1)
        self.assertEqual(len(self.connection.calls), 1)

    def test_incomplete_send_blocks_retry_across_bindings(self):
        self.connection.proposal.pop()
        self.assertEqual(self.accept(Terminal(True), self.backend()), 1)
        self.connection.selected = Binding(generation=NEXT_GENERATION, profile=REGISTRATION)
        self.connection.proposal = list(proposal_events())
        self.assertEqual(self.accept(Terminal(True), self.backend()), 1)
        self.assertEqual(len(self.connection.calls), 1)

    def test_unbound_terminal_usage_keeps_a_hold_across_reopen(self):
        created, completed = list(proposal_events())
        response = completed["response"]
        cases = {
            "missing created": [completed],
            "duplicate created": [created, created, completed],
            "duplicate terminal": [created, completed, completed],
            "missing created ID": [{"type": "response.created", "response": {}}, completed],
            "missing terminal ID": [created, {**completed, "response": {
                key: value for key, value in response.items() if key != "id"
            }}],
            "wrong terminal ID": [created, {**completed, "response": {**response, "id": "resp_other"}}],
            "wrong created model": [{**created, "response": {**created["response"], "model": "other"}}, completed],
            "wrong terminal model": [created, {**completed, "response": {**response, "model": "other"}}],
            "wrong terminal status": [created, {**completed, "response": {**response, "status": "incomplete"}}],
        }
        for name, events in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as scratch:
                self.state = Path(scratch)
                self.connection = FakeConnection(self.state)
                self.ledger = ExposureLedger(self.state)
                self.connection.proposal = events
                self.assertEqual(self.accept(Terminal(True), self.backend()), 1)
                records = json.loads((self.state / "exposure.json").read_text())
                self.assertEqual(len(records), 1)
                self.assertIsNone(records[0]["actual"])
                self.connection.proposal = list(proposal_events())
                self.ledger = ExposureLedger(self.state)
                self.assertEqual(self.accept(Terminal(True), self.backend()), 1)
                self.assertEqual(len(self.connection.calls), 1)

    def test_authoritative_worker_overage_precedes_tool_semantics(self):
        def overage_events(body, **bounds):
            for event in fixture_events(body, **bounds):
                if event["type"] == "response.completed":
                    yield {"type": "response.output_item.added", "item": {"type": "unapproved_tool"}}
                    event["response"]["usage"] = {
                        "input_tokens": 3, "output_tokens": 128001, "total_tokens": 128004,
                    }
                yield event

        def validate_initial(events, *, model, before_dispatch, lease_guard):
            cancelled = threading.Event()
            before_dispatch("initial")
            return validate(events(body_for(model), deadline=time.monotonic() + 5, cancelled=cancelled),
                            model, True, cancelled)

        self.connection.worker_events = overage_events
        self.assertEqual(self.accept(Terminal(True, True), self.backend(worker=validate_initial)), 1)
        records = json.loads((self.state / "exposure.json").read_text())
        self.assertEqual([record["actual"] for record in records], [[3, 7], [3, 128001]])

    def test_marker_mismatch_stops_without_printing_provider_output(self):
        private = "do not project this unapproved string"
        self.connection.proposal = list(proposal_events(private))
        terminal = Terminal(True)
        self.assertEqual(self.accept(terminal, self.backend()), 1)
        self.assertNotIn(private, "\n".join(terminal.output))
        self.assertEqual(terminal.output[-1], "Workstation proposal: GPT did not return the required proof proposal.")
        self.assertEqual(len(self.connection.calls), 1)

    def test_offered_worker_evidence_requires_two_accounted_provider_completions(self):
        terminal = Terminal(True, True)
        self.assertEqual(self.accept(terminal, self.backend(worker=lambda *args, **kwargs: WorkerEvidence())), 1)
        self.assertEqual(len(self.connection.calls), 1)

    @unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned Podman/devbox host")
    def test_attended_proof_with_pinned_native_opencode_and_fake_upstream(self):
        self.connection.worker_events = partial(fixture_events, reasoning=True)
        terminal = Terminal(True, True)
        self.assertEqual(self.accept(terminal, self.backend(worker=run_worker)), 0, terminal.output)
        self.assertEqual(len(self.connection.calls), 3)
        self.assertNotIn("host_reasoning_ciphertext", "\n".join(terminal.output))
        self.assertNotIn("host_reasoning_ciphertext", (self.state / "exposure.json").read_text())


if __name__ == "__main__":
    unittest.main()
