"""Offline regressions for the joint driver's trusted state and pause gates."""

from pathlib import Path
import socket
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import joint_probe
from adapter import LocalOpenCodeTransport, PauseBarrier
from client import ProbeError, Wire
from oc_coord_contract import DispatchOutcome
from relay import grant_record


class TestJointProbe(unittest.TestCase):
    def test_coordination_root_is_created_in_the_account_home(self) -> None:
        with TemporaryDirectory() as home:
            account_home = Path(home).resolve()

            def check_location(_args, state_dir):
                root = state_dir.parent
                self.assertEqual(root.parent, account_home)
                self.assertEqual(root.stat().st_mode & 0o777, 0o700)

            with (
                mock.patch.object(joint_probe, "account_home", return_value=account_home),
                mock.patch.object(joint_probe, "prove_restart", side_effect=check_location),
                mock.patch.object(joint_probe, "prove_pause"),
                mock.patch.object(joint_probe, "prove_replacement"),
                mock.patch.object(joint_probe, "report"),
                mock.patch.object(joint_probe.signal, "signal"),
            ):
                self.assertEqual(joint_probe.main([
                    "--opencode-image", "a" * 64, "--relay-image", "b" * 64,
                ]), 0)
            self.assertEqual(list(account_home.iterdir()), [])

    def test_terminal_entry_observes_the_same_live_reader(self) -> None:
        for close_early in (False, True):
            with self.subTest(close_early=close_early):
                self._check_held_reader(close_early)

    def _check_held_reader(self, close_early: bool) -> None:
        ids = {"relay": "a" * 64}
        job = SimpleNamespace(
            incarnation="inc_fixture", generation=1, run_label="b" * 32, terminal=False,
            ids=ids, recorded_ids=ids.copy(), assert_running=lambda: None,
            provider_socket=Path("/fixture-provider.sock"), control_socket=Path("/fixture-control.sock"),
        )
        transport = joint_probe.ProofTransport(job, mock.Mock())
        reader, peer = socket.socketpair()
        with reader, peer:
            wire = Wire(reader, time.monotonic() + 5)
            subscription = SimpleNamespace(wire=wire, assert_open=wire.assert_open)
            stream_id = "stream_fixture"
            transport._reservation = SimpleNamespace(
                stream=SimpleNamespace(id=stream_id, reading=True), events=subscription,
            )
            self.assertIs(transport.watch_held_reader(stream_id), subscription)
            if close_early:
                peer.close()
            addr = joint_probe.TARGET
            owner = transport.transport_owner_id(addr, job.incarnation)
            with mock.patch.object(LocalOpenCodeTransport, "confirm_incarnation_terminal", return_value=True):
                self.assertTrue(transport.confirm_incarnation_terminal(
                    addr, job.incarnation, owner_id=owner, reason="fixture",
                ))
            self.assertEqual(transport.terminal_entry_stream_id, None if close_early else stream_id)

    def _pause_trial(self, grant: Path, *, durable: bool, premature: bool) -> PauseBarrier:
        job = SimpleNamespace(incarnation="inc_fixture", generation=1, grant=grant, terminal=False)
        pause = PauseBarrier()
        registry = mock.Mock()
        transport = mock.Mock()
        transport.transport_owner_id.return_value = "fixture_owner"
        hub = mock.Mock()

        def dispatch():
            pause.acknowledged.set()
            if pause.release.wait(1):
                pause.outcome = DispatchOutcome.ZERO_BYTES_SENT
            return 1

        def revoke(*_args, **_kwargs):
            (grant / "state").write_bytes(grant_record(job.incarnation, job.generation, False))
            job.terminal = True
            return SimpleNamespace(incarnation_id=job.incarnation)

        def list_outbox(*, statuses):
            self.assertEqual(statuses, ("dispatch_started",))
            self.assertFalse(pause.release.is_set())
            if premature and job.terminal:
                return []
            return [{"msg_id": "msg_fixture", "attempts": 1, "stream_id": None}]

        def get_binding(target, incarnation):
            self.assertEqual((target, incarnation), (joint_probe.TARGET, job.incarnation))
            self.assertTrue(job.terminal)
            self.assertFalse(pause.release.is_set())
            if not durable:
                return None
            return {"owner_id": "fixture_owner", "abort_requested": True, "terminal_confirmed": True}

        hub.dispatch_once.side_effect = dispatch
        hub.revoke.side_effect = revoke
        registry.list_outbox.side_effect = list_outbox
        registry.get_transport_binding.side_effect = get_binding

        args = (hub, registry, transport, job, pause, "msg_fixture")
        if not durable or premature:
            with self.assertRaises(ProbeError):
                joint_probe.dispatch_paused(*args)
        else:
            joint_probe.dispatch_paused(*args)
        registry.get_transport_binding.assert_called_once()
        return pause

    def test_pause_releases_after_terminal_confirmation(self) -> None:
        with TemporaryDirectory() as root:
            pause = self._pause_trial(Path(root), durable=True, premature=False)
        self.assertIs(pause.outcome, DispatchOutcome.ZERO_BYTES_SENT)

    def test_pause_does_not_release_without_durable_confirmation(self) -> None:
        with TemporaryDirectory() as root:
            pause = self._pause_trial(Path(root), durable=False, premature=False)
        self.assertFalse(pause.release.is_set())

    def test_pause_does_not_release_after_premature_settlement(self) -> None:
        with TemporaryDirectory() as root:
            pause = self._pause_trial(Path(root), durable=True, premature=True)
        self.assertFalse(pause.release.is_set())
