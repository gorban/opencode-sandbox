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
        with self.assertRaisesRegex(ExposureError, "unapproved_or_replayed_phase"):
            self.ledger.reserve(self.slot(Phase.INITIAL, binding=binding_digest("r" * 43, "h" * 43)))
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
        with self.assertRaisesRegex(ExposureError, "unsettled_exposure"):
            self.ledger.reserve(self.slot(run="f" * 32))

    def test_overage_is_recorded_and_suspends_all_further_inference(self):
        proposal = self.slot()
        self.ledger.reserve(proposal)
        with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
            self.ledger.settle(proposal, 1, 128_001)
        with self.assertRaisesRegex(ExposureError, "exposure_bound_exceeded"):
            ExposureLedger(self.root).reserve(self.slot(run="f" * 32))
        self.assertEqual(json.loads((self.root / "exposure.json").read_text())[-1]["actual"], [1, 128_001])

    def test_unsafe_file_never_opened_for_writing(self):
        original = self.root / "keep"
        original.write_bytes(b"protected")
        (self.root / "exposure.json").symlink_to(original)
        with self.assertRaises(ExposureError):
            self.ledger.reserve(self.slot())
        self.assertEqual(original.read_bytes(), b"protected")


if __name__ == "__main__":
    unittest.main()
