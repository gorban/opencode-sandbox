from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from acp_readiness import RECEIPT, Record, RetirementUnconfirmed, _locked, _store, enroll_fixture
from acp_text_probe import isolated_placement, synthetic_state
from oc_orchestrator.runtime import Failure
from oc_providers import ReadinessState


class ScratchTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch("acp_text_probe.scratch_parent", return_value=scratch))
        self.enterContext(patch("acp_text_probe.check_private_directory"))

    def test_clean_states_and_placement_disappear(self):
        with synthetic_state() as state, isolated_placement(None) as placement:
            enroll_fixture(state)
            root = placement.root
        self.assertFalse(state.exists())
        self.assertFalse(root.exists())

    def test_placement_cleanup_cannot_discard_unconfirmed_peer_receipt(self):
        with self.assertRaises(RetirementUnconfirmed), patch("sys.stderr"):
            with synthetic_state() as state, isolated_placement(None) as placement:
                root = placement.root
                generation = enroll_fixture(state)
                with _locked(state) as directory:
                    _store(directory, RECEIPT, Record(generation, ReadinessState.REVOCATION_UNCONFIRMED, "a" * 32))
        self.assertFalse(root.exists())
        self.assertTrue((state / RECEIPT).is_file())

    def test_held_journal_lock_does_not_block_owner_cleanup(self):
        scope = synthetic_state()
        state = scope.__enter__()
        finished = threading.Event()
        errors = []

        def unwind():
            try:
                scope.__exit__(None, None, None)
            except (OSError, RuntimeError) as error:
                errors.append(error)
            finally:
                finished.set()

        with _locked(state), patch("sys.stderr"):
            thread = threading.Thread(target=unwind)
            thread.start()
            did_not_wait_for_lock = finished.wait(1)
        thread.join(2)
        self.assertTrue(did_not_wait_for_lock)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], Failure)
        self.assertTrue(state.exists())

    def test_failed_container_retirement_keeps_placement(self):
        with (patch("acp_text_probe.Placement.close", side_effect=Failure("cleanup unconfirmed")),
              self.assertRaises(Failure), patch("sys.stderr")):
            with isolated_placement(None) as placement:
                root = placement.root
        self.assertTrue(root.is_dir())

    def test_replacement_placement_root_is_preserved(self):
        with self.assertRaises(Failure), patch("sys.stderr"):
            with isolated_placement(None) as placement:
                root = placement.root
                original = root.with_name("moved-placement")
                root.rename(original)
                root.mkdir()
                marker = root / "fixture"
                marker.write_text("replacement")
        self.assertEqual(marker.read_text(), "replacement")
        self.assertTrue(original.is_dir())
