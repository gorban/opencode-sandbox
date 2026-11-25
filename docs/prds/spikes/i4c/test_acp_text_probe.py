from contextlib import ExitStack, suppress
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from acp_readiness import RECEIPT, Record, RetirementUnconfirmed, _locked, _store, enroll_fixture
from acp_text_probe import isolated_placement, synthetic_state
from oc_orchestrator.runtime import CONTAINER_SHELL, LABEL, OPEN_CODE, RELAY, Failure
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
        with patch("sys.stderr"), ExitStack() as scope:
            state = scope.enter_context(synthetic_state())
            root = scope.enter_context(isolated_placement(None)).root
            generation = enroll_fixture(state)
            with _locked(state) as directory:
                _store(directory, RECEIPT, Record(generation, ReadinessState.REVOCATION_UNCONFIRMED, "a" * 32))
            with self.assertRaises(RetirementUnconfirmed):
                scope.close()
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
              patch("sys.stderr"), ExitStack() as scope):
            root = scope.enter_context(isolated_placement(None)).root
            with self.assertRaisesRegex(Failure, "cleanup unconfirmed"):
                scope.close()
        self.assertTrue(root.is_dir())

    def test_replacement_placement_root_is_preserved(self):
        with patch("sys.stderr"), ExitStack() as scope:
            root = scope.enter_context(isolated_placement(None)).root
            original = root.with_name("moved-placement")
            root.rename(original)
            root.mkdir()
            marker = root / "fixture"
            marker.write_text("replacement")
            with self.assertRaisesRegex(Failure, "owned scratch directory changed"):
                scope.close()
        self.assertEqual(marker.read_text(), "replacement")
        self.assertTrue(original.is_dir())

    def test_original_scratch_inode_stays_pinned_after_unlink(self):
        for kind in ("placement", "state"):
            with self.subTest(kind=kind), patch("sys.stderr"), ExitStack() as scope:
                if kind == "placement":
                    root = scope.enter_context(isolated_placement(None)).root
                    (root / "placement.json").unlink(missing_ok=True)
                else:
                    root = scope.enter_context(synthetic_state())
                original = root.stat()
                root.rmdir()
                root.mkdir()
                marker = root / "replacement"
                marker.write_text("keep")
                pinned = []
                for fd in Path("/proc/self/fd").iterdir():
                    with suppress(FileNotFoundError):
                        if os.path.samestat(fd.stat(), original):
                            pinned.append(fd.name)
                with self.assertRaisesRegex(Failure, "scratch directory changed|synthetic state directory changed"):
                    scope.close()
                self.assertEqual(len(pinned), 1)
                self.assertFalse(os.path.samestat(root.stat(), original))
                self.assertEqual(marker.read_text(), "keep")

    def test_lost_create_with_empty_label_queries_retains_run_identity(self):
        lifeline = SimpleNamespace(check=lambda: None)

        def podman(command, *unused):
            if command == "create":
                raise Failure("synthetic create acknowledgement lost")
            self.assertEqual(command, "ps")
            return SimpleNamespace(stdout=b"")

        with (patch("oc_orchestrator.runtime.inspect",
                    return_value={"Id": OPEN_CODE, "Config": {"Env": []}}),
              patch("oc_orchestrator.runtime.podman", side_effect=podman) as host,
              patch("sys.stderr"), ExitStack() as scope):
            placement = scope.enter_context(isolated_placement(lifeline))
            root = placement.root
            with self.assertRaisesRegex(Failure, "acknowledgement lost"):
                placement.create("open-code", OPEN_CODE, "none", root / "worker.json",
                                 "/etc/opencode/opencode.json", {}, (), CONTAINER_SHELL)
            with self.assertRaisesRegex(Failure, "container creation is unconfirmed"):
                scope.close()

        self.assertEqual([call.args[0] for call in host.call_args_list], ["create", "ps", "ps"])
        self.assertEqual(json.loads((root / "placement.json").read_text()), {
            "label": LABEL, "value": placement.label, "names": placement.names,
        })

    def test_relay_preflight_failure_cleans_the_acknowledged_worker(self):
        lifeline = SimpleNamespace(check=lambda: None)
        worker_id = "a" * 64
        roots = []

        def inspect_image(_kind, image):
            if image == RELAY:
                raise Failure("relay image inspection failed")
            return {"Id": OPEN_CODE, "Config": {"Env": []}}

        def podman(command, *unused):
            return SimpleNamespace(stdout=worker_id.encode() if command == "create" else b"")

        def launch_pair():
            with isolated_placement(lifeline) as placement:
                root = placement.root
                roots.append(root)
                placement.create("open-code", OPEN_CODE, "none", root / "worker.json",
                                 "/etc/opencode/opencode.json", {}, (), CONTAINER_SHELL)
                placement.create("relay", RELAY, f"container:{worker_id}", root / "relay",
                                 "/fixture", {}, (), CONTAINER_SHELL)

        with (patch("oc_orchestrator.runtime.inspect", side_effect=inspect_image),
              patch("acp_text_probe.Placement.identity"),
              patch("acp_text_probe.Placement.verify"),
              patch("oc_orchestrator.runtime.podman", side_effect=podman) as host,
              patch("sys.stderr")):
            with self.assertRaisesRegex(Failure, "relay image inspection failed"):
                launch_pair()

        self.assertEqual([call.args[0] for call in host.call_args_list], ["create", "start", "ps", "rm", "ps"])
        self.assertIn(worker_id, host.call_args_list[3].args)
        self.assertEqual(len(roots), 1)
        self.assertFalse(roots[0].exists())
