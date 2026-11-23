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

from oc_openai import cli, live
from oc_openai.connection import Binding, ConnectionError
from oc_openai.exposure import ExposureLedger
from oc_openai.managed.protocol import body_for, validate
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
        self.worker_events = fixture_events

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
    def responses(self, binding, body, before_send, *, deadline=None, cancelled=None):
        self.require_active(binding)
        if body["model"] not in self.catalog:
            raise ConnectionError("openai_model_unavailable")
        before_send()
        records = json.loads((self.state / "exposure.json").read_text())
        assert records[-1]["actual"] is None
        self.calls.append(deepcopy(body))
        if "instructions" not in body:
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
        return cli.run(("accept",), terminal=terminal, backend_factory=lambda: backend)

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

    def test_full_cli_reserves_exact_sequence_and_validates_evidence(self):
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
        self.assertEqual(len(self.connection.calls), 1)

    def test_offered_worker_evidence_requires_two_accounted_provider_completions(self):
        terminal = Terminal(True, True)
        self.assertEqual(self.accept(terminal, self.backend(worker=lambda *args, **kwargs: WorkerEvidence())), 1)
        self.assertEqual(len(self.connection.calls), 1)

    @unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned Podman/devbox host")
    def test_full_cli_with_pinned_native_opencode_and_fake_upstream(self):
        self.connection.worker_events = partial(fixture_events, reasoning=True)
        terminal = Terminal(True, True)
        self.assertEqual(self.accept(terminal, self.backend(worker=run_worker)), 0, terminal.output)
        self.assertEqual(len(self.connection.calls), 3)
        self.assertNotIn("host_reasoning_ciphertext", "\n".join(terminal.output))
        self.assertNotIn("host_reasoning_ciphertext", (self.state / "exposure.json").read_text())


if __name__ == "__main__":
    unittest.main()
