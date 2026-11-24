import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from oc_openai.exposure import ExposureError, ExposureLedger, Phase, Slot, binding_digest


class ExposureLedgerTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.ledger = ExposureLedger(self.root)
        self.approved = binding_digest("r" * 43, "g" * 43)
        self.run = "b" * 32

    def slot(self, phase=Phase.ORCHESTRATOR, *, binding=None, run=None):
        return Slot(run or self.run, binding or self.approved, phase)

    def test_exact_authorized_sequence_and_replay_denial(self):
        proposal = self.slot()
        initial = self.slot(Phase.INITIAL)
        continuation = self.slot(Phase.CONTINUATION)
        with self.assertRaisesRegex(ExposureError, "unapproved_or_replayed_phase"):
            self.ledger.reserve(initial)
        self.ledger.reserve(proposal)
        self.ledger.settle(proposal, 100, 21)
        wrong_binding = self.slot(Phase.INITIAL, binding=binding_digest("r" * 43, "h" * 43))
        with self.assertRaisesRegex(ExposureError, "unapproved_or_replayed_phase"):
            self.ledger.reserve(wrong_binding)
        with self.assertRaisesRegex(ExposureError, "unapproved_or_replayed_phase"):
            self.ledger.reserve(proposal)
        self.ledger.reserve(initial)
        self.ledger.settle(initial, 22, 32)
        self.ledger.reserve(continuation)
        self.ledger.settle(continuation, 42, 52)
        with self.assertRaisesRegex(ExposureError, "unmatched_exposure_settlement"):
            self.ledger.settle(continuation, 42, 52)
        with self.assertRaisesRegex(ExposureError, "unapproved_or_replayed_phase"):
            self.ledger.reserve(continuation)

    def test_possible_send_survives_process_exit_and_blocks_new_headroom(self):
        command = """
from pathlib import Path
import os
import sys
from oc_openai.exposure import ExposureLedger, Phase, Slot

ExposureLedger(Path(sys.argv[1])).reserve(Slot(sys.argv[2], sys.argv[3], Phase.ORCHESTRATOR))
os._exit(91)
"""
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "-B", "-c", command, str(self.root), self.run, self.approved],
            cwd=root, stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 91)
        for slot in (self.slot(), self.slot(run="a" * 32, binding=binding_digest("t" * 43, "j" * 43))):
            with self.assertRaisesRegex(ExposureError, "unsettled_exposure"):
                self.ledger.reserve(slot)
        data = json.loads((self.root / "exposure.json").read_text())
        self.assertIsNone(data[-1]["actual"])
        self.assertEqual((data[-1]["max_input"], data[-1]["max_output"]), (922_000, 128_000))
        self.assertNotIn("r" * 43, (self.root / "exposure.json").read_text())

    def test_non_integer_usage_retains_reservation(self):
        proposal = self.slot()
        self.ledger.reserve(proposal)
        for bad_count in (True, -1, 2.0):
            with self.subTest(bad_count=bad_count):
                with self.assertRaisesRegex(ExposureError, "invalid_terminal_usage"):
                    self.ledger.settle(proposal, 1, bad_count)
        other_run = self.slot(run="f" * 32)
        with self.assertRaisesRegex(ExposureError, "unsettled_exposure"):
            self.ledger.reserve(other_run)

    def test_overage_is_recorded_and_suspends_all_further_inference(self):
        proposal = self.slot()
        self.ledger.reserve(proposal)
        with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
            self.ledger.settle(proposal, 1, 128_001)
        reopened = ExposureLedger(self.root)
        other_run = self.slot(run="f" * 32)
        with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
            reopened.reserve(other_run)
        self.assertEqual(json.loads((self.root / "exposure.json").read_text())[-1]["actual"], [1, 128_001])

    def test_unsafe_file_never_opened_for_writing(self):
        original = self.root / "keep"
        original.write_bytes(b"protected")
        (self.root / "exposure.json").symlink_to(original)
        proposal = self.slot()
        with self.assertRaises(ExposureError):
            self.ledger.reserve(proposal)
        self.assertEqual(original.read_bytes(), b"protected")

    def _reserve_then_exit_before_write(self, request, *, stream=False):
        command = """
from pathlib import Path
import os
import stat
import sys
from unittest.mock import patch
from oc_openai.exposure import ExposureLedger, Phase, Slot

ledger = ExposureLedger(Path(sys.argv[1]))
ticket = ledger.prepare_diagnostic(Slot(sys.argv[2], sys.argv[3], Phase.ORCHESTRATOR), stream=sys.argv[4] == "stream")
real_fsync = os.fsync
synced = []

def sync(fd):
    real_fsync(fd)
    synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))

with patch("oc_openai.exposure.os.fsync", sync):
    ledger.reserve_diagnostic(ticket)
assert synced == [False, True], synced
os._exit(91)
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", command, str(self.root), request.run_id, request.binding,
             "stream" if stream else "initial"],
            cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL, capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 91, result.stderr)

    def test_diagnostic_is_spent_after_durable_publish_before_any_write(self):
        self.ledger.reserve(self.slot())
        ledger_path = self.root / "exposure.json"
        original = ledger_path.read_bytes()
        request = self.slot(run="a" * 32)
        self._reserve_then_exit_before_write(request)
        self.assertEqual(ledger_path.read_bytes(), original)
        receipt = json.loads((self.root / "diagnostic.json").read_text())
        self.assertEqual(receipt["original_run"], self.run)
        self.assertIsNone(receipt["actual"])
        reopened = ExposureLedger(self.root)
        with self.assertRaisesRegex(ExposureError, "diagnostic_already_reserved"):
            reopened.prepare_diagnostic(request)
        with self.assertRaisesRegex(ExposureError, "diagnostic_already_reserved"):
            reopened.reserve(request)

    def test_diagnostic_exact_ticket_and_malformed_or_orphaned_receipt(self):
        self.ledger.reserve(self.slot())
        for ineligible in (self.slot(), self.slot(run="a" * 32, binding="1" * 64),
                           self.slot(Phase.INITIAL, run="a" * 32)):
            with self.subTest(ineligible=ineligible):
                with self.assertRaisesRegex(ExposureError, "diagnostic_unavailable"):
                    self.ledger.prepare_diagnostic(ineligible)
        ticket = self.ledger.prepare_diagnostic(self.slot(run="a" * 32))
        competitor = ExposureLedger(self.root).prepare_diagnostic(self.slot(run="c" * 32))
        self.ledger.reserve_diagnostic(ticket)
        with self.assertRaisesRegex(ExposureError, "diagnostic_already_reserved"):
            self.ledger.reserve_diagnostic(competitor)
        with self.assertRaisesRegex(ExposureError, "unmatched_exposure_settlement"):
            self.ledger.settle_diagnostic(competitor, 2, 3)
        receipt = self.root / "diagnostic.json"
        receipt.write_text("{")
        with self.assertRaisesRegex(ExposureError, "invalid_exposure_record"):
            self.ledger.settle_diagnostic(ticket, 2, 3)
        (self.root / "exposure.json").unlink()
        reopened = ExposureLedger(self.root)
        for attempt in (lambda: reopened.prepare_diagnostic(ticket.request),
                        lambda: reopened.require_next(ticket.request),
                        lambda: reopened.reserve(ticket.request), reopened.require_quiescent):
            with self.assertRaisesRegex(ExposureError, "diagnostic_already_reserved"):
                attempt()

    def test_stream_retry_crash_preserves_prior_receipts_and_blocks_all_modes(self):
        self.ledger.reserve(self.slot())
        old = self.ledger.prepare_diagnostic(self.slot(run="a" * 32))
        self.ledger.reserve_diagnostic(old)
        original = self.root / "exposure.json"
        first = self.root / "diagnostic.json"
        before = original.read_bytes(), first.read_bytes()
        request = self.slot(run="c" * 32)
        self._reserve_then_exit_before_write(request, stream=True)
        after = (original.read_bytes(), first.read_bytes())
        self.assertEqual(after, before)
        receipt = json.loads((self.root / "diagnostic-stream.json").read_text())
        self.assertEqual((receipt["original_run"], receipt["previous_diagnostic_run"], receipt["run"]),
                         (self.run, old.request.run_id, request.run_id))
        self.assertIsNone(receipt["actual"])

        # Ordinary and first-diagnostic routes must still refuse with an
        # unreadable or missing predecessor on reopening.
        for prior_bytes in (b"{", None):
            with self.subTest(prior_bytes=prior_bytes):
                if prior_bytes is None:
                    first.unlink()
                else:
                    first.write_bytes(prior_bytes)
                reopened = ExposureLedger(self.root)
                for attempt in (
                    lambda: reopened.require_next(request),
                    lambda: reopened.reserve(request),
                    lambda: reopened.prepare_diagnostic(request),
                    lambda: reopened.prepare_diagnostic(request, stream=True),
                    lambda: reopened.reserve_diagnostic(old),
                    lambda: reopened.settle_diagnostic(old, 2, 3),
                ):
                    with self.assertRaisesRegex(ExposureError, "diagnostic_already_reserved"):
                        attempt()

    def test_stream_retry_requires_two_distinct_unknown_predecessors(self):
        original = self.slot()
        self.ledger.reserve(original)
        request = self.slot(run="c" * 32)
        with self.assertRaisesRegex(ExposureError, "diagnostic_unavailable"):
            self.ledger.prepare_diagnostic(request, stream=True)
        first = self.ledger.prepare_diagnostic(self.slot(run="a" * 32))
        self.ledger.reserve_diagnostic(first)
        for wrong in (original, first.request, self.slot(run="c" * 32, binding="1" * 64)):
            with self.assertRaisesRegex(ExposureError, "diagnostic_unavailable"):
                self.ledger.prepare_diagnostic(wrong, stream=True)
        ticket = self.ledger.prepare_diagnostic(request, stream=True)
        self.ledger.settle_diagnostic(first, 3, 5)
        with self.assertRaisesRegex(ExposureError, "diagnostic_unavailable"):
            self.ledger.reserve_diagnostic(ticket)
        self.assertFalse((self.root / "diagnostic-stream.json").exists())


if __name__ == "__main__":
    unittest.main()
