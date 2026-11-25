"""Verify cross-process retirement using the relay's worker-socket fence."""

from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from oc_openai.connection import Connection, ConnectionError
from oc_openai.connection_job import PhysicalHost, WorkerLease
from oc_openai.managed.relay import Lease, deliver, grant_record, take_fence
from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier


_DISCONNECT = """
import os
from pathlib import Path
import sys
from oc_openai.connection import Connection, ConnectionError
from oc_openai.connection_job import PhysicalHost
from test_openai_connection import FixtureTransport

connection = Connection(Path(sys.argv[1]), transport=FixtureTransport(),
                        host_probe=lambda: PhysicalHost(sys.argv[3], sys.argv[4]))
if sys.argv[2] == "crash":
    original = connection._store.write
    def crash_before_commit(directory, record):
        if "retiring" in record and "worker_retiring" not in record:
            os._exit(91)
        original(directory, record)
    connection._store.write = crash_before_commit
try:
    print(connection.disconnect())
except ConnectionError as error:
    print(error.code)
"""

_HOST = PhysicalHost("b" * 64, "5c8257d9-c0a9-4e1d-ad25-63259528c1cf")
_OTHER_BOOT = "0200edee-dfa1-4f4a-9aa7-d2d0fb91cd71"


class WorkerLeaseTests(unittest.TestCase):
    def setUp(self):
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="oc-i4a-retire-", dir=home)))
        self.connection = Connection(self.state, browser=FixtureBrowser(),
                                     verifier=FixtureVerifier(), transport=FixtureTransport(),
                                     host_probe=lambda: _HOST)
        self.binding = self.connection.connect()
        root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="oc-i4a-", dir="/tmp")))
        grant = root / "grant"
        grant.mkdir(mode=0o700)
        self.marker = grant / "state"
        self.lock = grant / "lock"
        lifetime_path = grant / "lifetime"
        for path in (self.marker, self.lock, lifetime_path):
            path.touch(mode=0o600)
        self.marker.write_bytes(b"pending\n")
        self.lifetime = self.enterContext(lifetime_path.open("rb"))
        take_fence(self.lifetime.fileno())
        self.job = SimpleNamespace(root=root, incarnation="inc_" + "a" * 32, generation=7)
        self.active = grant_record(self.job.incarnation, self.job.generation, True)
        self.terminal = grant_record(self.job.incarnation, self.job.generation, False)
        self.lease = Lease(grant, self.active, time.monotonic_ns() + 15 * 10**9)

    def disconnect(self, mode="normal"):
        root = Path(__file__).resolve().parents[1]
        return subprocess.run(
            [sys.executable, "-B", "-c", _DISCONNECT, str(self.state), mode, _HOST.machine, _HOST.boot],
            cwd=root, env={**os.environ, "PYTHONPATH": str(root / "tests")},
            capture_output=True, text=True, timeout=5,
        )

    @contextmanager
    def running(self):
        with self.connection.worker_lease(self.binding, self.job):
            with self.lease.fence():
                self.marker.write_bytes(self.active)
            yield

    def test_buffered_output_is_fenced_after_retirement(self):
        client, relay = socket.socketpair()
        with client, relay, self.running():
            client.settimeout(0.1)
            relay.setblocking(False)
            self.assertEqual(deliver(self.lease, relay, b"before"), len(b"before"))
            self.assertEqual(client.recv(12), b"before")
            result = self.disconnect()
            self.assertEqual((result.returncode, result.stdout.strip()), (0, "True"), result.stderr)
            self.assertEqual(self.marker.read_bytes(), self.terminal)
            self.assertEqual(deliver(self.lease, relay, b"buffered"), 0)
            with self.assertRaises(TimeoutError):
                client.recv(1)

    def test_incomplete_retirement_blocks_admission_and_allows_retry(self):
        with self.running():
            with self.lock.open("rb") as blocker:
                take_fence(blocker.fileno())
                result = self.disconnect()
                self.assertEqual((result.returncode, result.stdout.strip()), (0, "managed_retirement_incomplete"))
                self.assertEqual(self.marker.read_bytes(), self.active)
                with self.assertRaisesRegex(ConnectionError, "connection_retired"):
                    self.connection.require_active(self.binding)
            result = self.disconnect()
            self.assertEqual((result.returncode, result.stdout.strip()), (0, "True"), result.stderr)
            self.assertEqual(self.marker.read_bytes(), self.terminal)

    def test_crash_after_terminal_publication_keeps_retirement_recoverable(self):
        with self.running():
            crashed = self.disconnect("crash")
            self.assertEqual(crashed.returncode, 91, crashed.stderr)
            self.assertEqual(self.marker.read_bytes(), self.terminal)
        # The original owner may finish exact terminal cleanup before retry.
        with self.assertRaisesRegex(ConnectionError, "connection_retired"):
            self.connection.require_active(self.binding)
        result = self.disconnect()
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "True"), result.stderr)

    def test_old_boot_is_inert_after_tmpfs_loss(self):
        reference = WorkerLease.capture(self.job, _HOST)
        changed = replace(_HOST, boot=_OTHER_BOOT)
        replace(reference, root="oc-i4a-missing0").terminal(changed)

    def test_foreign_view_does_not_retire_live_original_relay(self):
        client, relay = socket.socketpair()
        with client, relay, self.running():
            foreign = Connection(self.state, transport=FixtureTransport(),
                                 host_probe=lambda: PhysicalHost("c" * 64, _OTHER_BOOT))
            with self.assertRaisesRegex(ConnectionError, "managed_retirement_incomplete"):
                foreign.disconnect()
            with self.assertRaisesRegex(ConnectionError, "connection_retired"):
                self.connection.require_active(self.binding)
            self.assertEqual(self.marker.read_bytes(), self.active)
            relay.setblocking(False)
            self.assertEqual(deliver(self.lease, relay, b"origin"), 6)
            self.assertEqual(client.recv(6), b"origin")
            self.assertTrue(self.connection.disconnect())

    def test_rejects_lease_replacement_during_physical_probe(self):
        with self.running():
            def changed_during_probe():
                # This can take the store lock because the host probe holds none.
                with self.connection._store.locked() as directory:
                    state = self.connection._store.read(directory)
                    state["worker_lease"]["generation"] += 1
                    self.connection._store.write(directory, state)
                return replace(_HOST, boot=_OTHER_BOOT)

            replacement = Connection(self.state, transport=FixtureTransport(),
                                     host_probe=changed_during_probe)
            proof = replacement.physical_host_for_retirement()
            with self.assertRaisesRegex(ConnectionError, "managed_retirement_incomplete"):
                replacement.begin_disconnect(physical_host=proof)
            self.assertEqual(self.marker.read_bytes(), self.active)

    def test_physical_host_proof_requires_current_boot_agreement(self):
        machine = b"a" * 32
        with (patch("oc_openai.connection_job.check_devbox"),
              patch("oc_openai.connection_job._boot", return_value=_OTHER_BOOT),
              patch("oc_openai.connection_job.host_output") as host):
            host.return_value = machine + b"\n" + _HOST.boot.encode("ascii") + b"\n"
            self.assertIsNone(PhysicalHost.observe())
            host.return_value = machine + b"\n" + _OTHER_BOOT.encode("ascii") + b"\n"
            proof = PhysicalHost.observe()
            self.assertEqual(proof.boot, _OTHER_BOOT)
            self.assertNotEqual(proof.machine, machine.decode("ascii"))
            self.assertEqual(proof, PhysicalHost.observe())
            host.assert_called_with("cat", "/etc/machine-id", "/proc/sys/kernel/random/boot_id")

    def test_missing_marker_is_not_proof_until_exact_owner_lifetime_is_gone(self):
        reference = WorkerLease.capture(self.job, _HOST)
        self.marker.unlink()
        with self.assertRaisesRegex(ConnectionError, "managed_retirement_incomplete"):
            reference.terminal(_HOST)
        self.lifetime.close()
        reference.terminal(_HOST)
        self.assertEqual(self.marker.read_bytes(), self.terminal)
