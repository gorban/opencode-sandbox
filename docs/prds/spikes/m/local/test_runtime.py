"""Exercise grant and cleanup failures without invoking Podman."""

import json
from pathlib import Path
import socket
import stat
from subprocess import CompletedProcess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from relay import copy_streams, grant_active, grant_record
from runtime import Job, MEMORY_LIMITS, ROLE_LABEL, RuntimeError as JobError, atomic_write


WORKER = "a" * 64
RELAY = "b" * 64


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.job = Job(Path(self.scratch.name), WORKER, RELAY, "sample-token", "sample-password", "fixture")
        self.job.prepare()
        self.addCleanup(self.job.close)
        self.active = grant_record("fixture", 1, True)

    def test_failed_fence_open_invalidates_lifetime_even_if_state_and_relay_remain(self):
        def stop():
            self.assertFalse(grant_active(self.job.grant, self.active))
            raise JobError("relay stop unconfirmed")

        with (
            patch("runtime.os.open", side_effect=PermissionError),
            patch("runtime.Path.unlink", side_effect=PermissionError),
            patch.object(self.job, "_stop_relay", side_effect=stop) as relay,
            self.assertRaisesRegex(JobError, "stop unconfirmed"),
        ):
            self.job.revoke()
        relay.assert_called_once()
        self.assertEqual((self.job.grant / "state").read_bytes(), self.active)
        self.assertFalse(grant_active(self.job.grant, self.active))

    def test_failed_terminal_persist_holds_fence_until_verified_cleanup(self):
        with (
            patch("runtime.atomic_write", side_effect=OSError),
            patch.object(self.job, "_stop_relay", side_effect=JobError("relay stop unconfirmed")),
            self.assertRaisesRegex(JobError, "stop unconfirmed"),
        ):
            self.job.revoke()
        self.assertIsNotNone(self.job.held_fence)
        self.assertFalse(grant_active(self.job.grant, self.active))
        self.job.close()
        self.assertIsNone(self.job.held_fence)

    def test_cleanup_records_adopted_id_and_continues_after_removal_timeout(self):
        self.job.ids = {"worker": WORKER}
        self.job._write_receipt()
        issued = []
        remaining = {RELAY, WORKER}

        def run(*args, **kwargs):
            issued.append(args)
            if args[0] == "rm":
                self.assertEqual(self.job.recorded_ids["relay"], RELAY)
                self.assertIn(RELAY, self.job.receipt.read_text())
                remaining.discard(args[-1])
                if args[-1] == RELAY:
                    raise JobError("simulated removal timeout")
            elif args[:2] == ("container", "exists"):
                return CompletedProcess(args, int(args[-1] not in remaining))
            else:
                self.fail("Unexpected fake Podman command")

        with (
            patch("runtime.podman", side_effect=run),
            patch("runtime.inspected", return_value={"Config": {"Labels": {ROLE_LABEL: "relay"}}}),
            patch.object(self.job, "_identity"),
            patch.object(self.job, "_inventory", side_effect=lambda: sorted({RELAY} & remaining)) as inventory,
        ):
            self.job._remove_containers()
        self.assertEqual(
            [args[-1] for args in issued if args[0] == "rm"], [RELAY, WORKER]
        )
        self.assertEqual(
            {args[-1] for args in issued if args[:2] == ("container", "exists")}, {RELAY, WORKER}
        )
        self.assertEqual(inventory.call_count, 2)

    def test_lost_create_ack_retains_pending_receipt_after_empty_inventory(self):
        def unacknowledged_create(*args):
            receipt = json.loads(self.job.receipt.read_text())
            self.assertEqual(receipt["pending_create"], ["worker"])
            self.assertEqual(receipt["ids"], {})
            raise JobError("simulated host create timeout")

        try:
            with (
                patch("runtime.podman", side_effect=unacknowledged_create),
                patch.object(self.job, "_inventory", return_value=[]) as inventory,
            ):
                with self.assertRaisesRegex(JobError, "simulated host create timeout"):
                    self.job._create("worker", mode="none", mounts={}, tmpfs={}, env={}, command=[], workdir="/")
                with self.assertRaisesRegex(JobError, "acknowledgment was lost"):
                    self.job.close()
            self.assertEqual(inventory.call_count, 2)
            self.assertEqual(json.loads(self.job.receipt.read_text())["pending_create"], ["worker"])
        finally:
            # The only creation attempt was mocked, so tear-down has no containers.
            self.job.attempted_create = False

    def test_memory_ceiling_requires_bounded_memory_and_zero_swap(self):
        self.job.ids["worker"] = WORKER
        expected = str(MEMORY_LIMITS["worker"]).encode("ascii")
        response = CompletedProcess([], 0, stdout=expected + b"\n0\n")
        with patch("runtime.podman", return_value=response):
            self.job._verify_memory("worker")
            for output in (b"max\n0\n", expected + b"\nmax\n", expected + b"\n"):
                with self.subTest(output=output):
                    response.stdout = output
                    with self.assertRaisesRegex(JobError, "effective worker memory or swap limit"):
                        self.job._verify_memory("worker")

    def test_rootful_or_permissive_host_is_rejected_before_image_inspect(self):
        enforcing = Path(self.scratch.name) / "enforcing"
        enforcing.write_bytes(b"0")
        with patch("runtime.SELINUX_ENFORCE", enforcing), patch("runtime.podman") as run:
            with self.assertRaisesRegex(JobError, "SELinux enforcing"):
                self.job._check_images()
            run.assert_not_called()
            enforcing.write_bytes(b"1")
            run.return_value = CompletedProcess([], 0, stdout=b"false true v2\n")
            with self.assertRaisesRegex(JobError, "local rootless"):
                self.job._check_images()
            self.assertEqual(run.call_count, 1)

    def test_devbox_bridge_rejects_same_name_with_different_directory_inode(self):
        current = self.job.root.stat()
        devbox_bus = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=current.st_uid)
        fixed_tool = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        alternate = f"{current.st_dev}:{current.st_ino + 1}:{current.st_uid}:{current.st_mode:x}"
        with (
            patch("runtime.Path.read_bytes", return_value=b"unconfined_u:unconfined_r:spc_t:s0"),
            patch("runtime.Path.stat", side_effect=(devbox_bus, fixed_tool)),
            patch("runtime.host_output", side_effect=(
                str(current.st_uid).encode(),
                b"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
                alternate.encode(),
            )),
            self.assertRaisesRegex(JobError, "share the expected private run directory"),
        ):
            self.job._check_bridge(current)

    def test_stalled_stream_closes_after_grant_revocation(self):
        worker, source = socket.socketpair()
        target, consumer = socket.socketpair()
        stopped = threading.Event()

        def relay():
            with source, target:
                copy_streams({source: target}, source, self.job.grant, self.active)
            stopped.set()

        with worker, consumer, source, target:
            # Fill the relay's output buffer and then hold the peer idle.
            target.setblocking(False)
            target.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            with self.assertRaises(BlockingIOError):
                while True:
                    target.send(b"x" * 4096)
            worker.sendall(b"pending fixture response")
            thread = threading.Thread(target=relay, daemon=True)
            thread.start()
            try:
                self.assertFalse(stopped.wait(0.1))
                atomic_write(self.job.grant / "state", grant_record("fixture", 1, False))
                self.assertTrue(stopped.wait(1))
            finally:
                thread.join(timeout=1)


    def test_idle_control_stream_releases_worker_after_driver_disconnect(self):
        worker, source = socket.socketpair()
        target, driver = socket.socketpair()

        def relay():
            with source, target:
                copy_streams({source: target}, source, self.job.grant, self.active, watch_peer=target)

        with worker, source, target, driver:
            thread = threading.Thread(target=relay, daemon=True)
            thread.start()
            try:
                worker.settimeout(1)
                driver.close()
                self.assertEqual(worker.recv(1), b"")
                self.assertTrue(grant_active(self.job.grant, self.active))
            finally:
                thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
