"""Test relay ordering and startup cleanup with synthetic local socketpairs."""

from concurrent.futures import ThreadPoolExecutor
import fcntl
from pathlib import Path
import socket
import struct
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import relay


ACTIVE = relay.grant_record("test-incarnation", 1, True)
TERMINAL = relay.grant_record("test-incarnation", 1, False)
REQUEST = b"synthetic fixture request"


def _frame(mode):
    return mode + struct.pack("!I", len(REQUEST)) + REQUEST


class ControlTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="fixture-relay-")
        self.addCleanup(directory.cleanup)
        self.grant = Path(directory.name)
        (self.grant / "lock").touch()
        (self.grant / "state").write_bytes(ACTIVE)
        lifetime = (self.grant / "lifetime").open("wb")
        self.addCleanup(lifetime.close)
        fcntl.flock(lifetime.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        grant = patch.object(relay, "GRANT", self.grant)
        grant.start()
        self.addCleanup(grant.stop)

    def _revoke(self):
        with (self.grant / "lock").open("rb") as lock:
            relay.take_fence(lock.fileno())
            (self.grant / "state").write_bytes(TERMINAL)

    def _pair(self):
        peers = socket.socketpair()
        for peer in peers:
            self.addCleanup(peer.close)
            peer.settimeout(2)
        return peers

    def test_terminal_grant_denies_each_control_mode_without_dialing(self):
        self._revoke()
        for mode in (b"N", b"P"):
            with self.subTest(mode=mode):
                client, server = self._pair()
                client.sendall(_frame(mode))
                with patch.object(relay.socket, "create_connection", side_effect=OSError()) as dial:
                    relay.control(server, ACTIVE)
                self.assertEqual(client.recv(1), b"Z")
                dial.assert_not_called()

    def test_paused_active_grant_dials_and_hands_off_only_after_release(self):
        client, server = self._pair()
        worker, receiver = self._pair()
        with (
            patch.object(relay.socket, "create_connection", return_value=worker) as dial,
            patch.object(relay, "copy_streams"),
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            submitted = executor.submit(relay.control, server, ACTIVE)
            client.sendall(_frame(b"P"))
            paused = client.recv(1)
            connections_before_release = dial.call_count
            client.sendall(b"G")
            receipt = client.recv(1)
            submitted.result(timeout=2)

        self.assertEqual(paused, b"P")
        self.assertEqual(connections_before_release, 0)
        self.assertEqual(receipt, b"H")
        self.assertEqual(receiver.recv(len(REQUEST)), REQUEST)
        dial.assert_called_once_with(relay.WORKER, timeout=relay.FRAME_TIMEOUT)

    def test_paused_grant_revoked_before_release_denies_without_dialing(self):
        client, server = self._pair()
        worker, receiver = self._pair()
        with (
            patch.object(relay.socket, "create_connection", return_value=worker) as dial,
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            submitted = executor.submit(relay.control, server, ACTIVE)
            client.sendall(_frame(b"P"))
            paused = client.recv(1)
            self._revoke()
            client.sendall(b"G")
            receipt = client.recv(1)
            submitted.result(timeout=2)

        self.assertEqual(paused, b"P")
        self.assertEqual(receipt, b"Z")
        dial.assert_not_called()
        worker.close()
        self.assertEqual(receiver.recv(1), b"")

    def test_revocation_during_dial_reaches_the_fenced_zero_write_path(self):
        client, server = self._pair()
        worker, receiver = self._pair()

        def revoke_during_dial(*_args, **_kwargs):
            self._revoke()
            return worker

        client.sendall(_frame(b"N"))
        with patch.object(relay.socket, "create_connection", side_effect=revoke_during_dial) as dial:
            relay.control(server, ACTIVE)
        dial.assert_called_once()
        self.assertEqual(client.recv(1), b"Z")
        self.assertEqual(receiver.recv(1), b"")


class ServeTest(unittest.TestCase):
    def test_thread_start_failure_closes_client_and_reuses_its_only_slot(self):
        model, driver = MagicMock(), MagicMock()
        model.__enter__.return_value = model
        driver.__enter__.return_value = driver
        first_client, next_client = MagicMock(), MagicMock()
        first_client.close.side_effect = OSError()
        driver.accept.side_effect = [(first_client, None), (next_client, None)]
        selector = MagicMock()
        selector.__enter__.return_value = selector
        ready = [(SimpleNamespace(fileobj=driver), relay.selectors.EVENT_READ)]
        selector.select.side_effect = [ready, ready, EOFError("finished synthetic accepts")]
        slots = [threading.BoundedSemaphore(1), threading.BoundedSemaphore(1)]
        first_thread = MagicMock()
        first_thread.start.side_effect = RuntimeError("synthetic thread start failure")

        def make_thread(target, args, **_options):
            if args[0] is first_client:
                return first_thread
            return SimpleNamespace(start=lambda: target(*args))

        with (
            patch.object(relay.os, "umask"),
            patch.object(relay.socket, "socket", side_effect=[model, driver]),
            patch.object(relay.selectors, "DefaultSelector", return_value=selector),
            patch.object(relay.threading, "BoundedSemaphore", side_effect=slots),
            patch.object(relay.threading, "Thread", side_effect=make_thread),
            patch.object(relay, "control") as control,
            self.assertRaisesRegex(EOFError, "finished synthetic accepts"),
        ):
            relay.serve(ACTIVE)

        first_client.close.assert_called_once()
        control.assert_called_once_with(next_client, ACTIVE)
        self.assertTrue(slots[1].acquire(blocking=False))


if __name__ == "__main__":
    unittest.main()
