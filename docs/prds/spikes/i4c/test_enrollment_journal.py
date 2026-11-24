"""Verify the synthetic host ledger keeps cancellation and readiness distinct."""

from pathlib import Path
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


SOURCE = Path(__file__).with_name("enrollment-journal.py")
ENROLLMENT = runpy.run_path(str(SOURCE))
Journal = ENROLLMENT["Journal"]
EnrollmentError = ENROLLMENT["EnrollmentError"]


class EnrollmentJournalTest(unittest.TestCase):
    def test_pending_survives_fresh_process_and_abandon_fences_success(self):
        with TemporaryDirectory() as scratch:
            journal = Journal(Path(scratch))
            generation = journal.begin()
            check = ("import runpy, sys; J = runpy.run_path(sys.argv[1])['Journal']; "
                     "assert J(sys.argv[2]).current() == {'generation': sys.argv[3], 'state': 'pending'}")
            subprocess.run([sys.executable, "-IB", "-c", check, str(SOURCE), scratch, generation],
                           check=True, timeout=3)
            new_process = Journal(Path(scratch))
            new_process.transition(generation, "abandoned")
            with self.assertRaises(EnrollmentError):
                journal.transition(generation, "ready")
            with self.assertRaises(EnrollmentError):
                journal.begin()
            self.assertEqual(new_process.current(), {"generation": generation, "state": "abandoned"})

    def test_publication_requires_current_pending_generation(self):
        with TemporaryDirectory() as scratch:
            journal = Journal(Path(scratch))
            generation = journal.begin()
            with self.assertRaises(EnrollmentError):
                journal.transition("x" * 32, "ready")
            journal.transition(generation, "ready")
            self.assertEqual(journal.current(), {"generation": generation, "state": "ready"})

    def test_refuses_symlink_and_invalid_state(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            elsewhere = root / "file"
            elsewhere.write_text("unchanged")
            state = root / "generation.json"
            state.symlink_to(elsewhere)
            with self.assertRaises(OSError):
                Journal(root).begin()
            self.assertEqual(elsewhere.read_text(), "unchanged")
            state.unlink()
            state.write_text('{"state":"pending","state":"ready"}')
            state.chmod(0o600)
            with self.assertRaises(EnrollmentError):
                Journal(root).current()


if __name__ == "__main__":
    unittest.main()
