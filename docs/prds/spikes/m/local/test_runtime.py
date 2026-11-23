"""Exercise grant and cleanup failures without invoking Podman."""

import json
import os
from pathlib import Path
import pwd
import socket
import stat
from subprocess import CompletedProcess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from relay import copy_streams, grant_active, grant_record
from runtime import Job, JobRuntimeError as JobError, MEMORY_LIMITS, ROLE_LABEL, atomic_write, host_command


WORKER = "a" * 64
RELAY = "b" * 64


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.scratch = tempfile.TemporaryDirectory(prefix="rt-", dir=self.home)
        self.addCleanup(self.scratch.cleanup)
        self.job = self.make_job(Path(self.scratch.name))
        self.job.prepare()
        self.addCleanup(self.job.close)
        self.active = grant_record("fixture", 1, True)

    def make_job(self, path):
        return Job(path, WORKER, RELAY, "sample-token", "sample-password", "fixture")

    def test_rejects_writable_parent_before_writing_into_precreated_leaf(self):
        parent = self.job.root / "world"
        parent.mkdir()
        parent.chmod(0o777)
        leaf = parent / "job"
        leaf.mkdir(mode=0o700)
        job = self.make_job(leaf)
        self.addCleanup(job.close)
        with self.assertRaisesRegex(JobError, "untrusted ancestor"):
            job.prepare()
        self.assertEqual(list(leaf.iterdir()), [])

    def test_rejects_user_symlink_ancestor_before_creating_missing_leaf(self):
        link = self.job.root / "alias"
        target = self.job.root / "target"
        target.mkdir()
        link.symlink_to(target, target_is_directory=True)
        job = self.make_job(link / "job")
        self.addCleanup(job.close)
        with self.assertRaises(JobError):
            job.prepare()
        self.assertFalse((target / "job").exists())

    def test_rejects_sandbox_and_production_state_before_writing_into_leaf(self):
        home = self.job.root / "fake-home"
        for protected in ("opencode-sandbox", ".config/oc-sandbox"):
            leaf = home / protected / "job"
            leaf.mkdir(mode=0o700, parents=True)
            job = self.make_job(leaf)
            self.addCleanup(job.close)
            with (
                self.subTest(protected=protected),
                patch("runtime.account_home", return_value=home, create=True),
                self.assertRaisesRegex(JobError, "sandbox or production state"),
            ):
                job.prepare()
            self.assertEqual(list(leaf.iterdir()), [])

    def test_prepare_keeps_canonical_paths_after_root_owned_home_alias(self):
        self.assertEqual(self.job.root, Path(self.scratch.name).resolve())
        self.assertEqual(self.job.provider_socket.parent.parent, self.job.root)

    def test_host_subprocess_scrubs_ambient_config_and_guest_transport(self):
        canary = {"CONTAINERS_CONF": "/fake/canary", "HOME": "/fake/home", "HTTP_PROXY": "canary"}
        for mode in ("local", "distrobox"):
            with (
                self.subTest(mode=mode),
                patch("runtime.HOST_MODE", mode),
                patch.dict(os.environ, canary),
                patch("runtime.subprocess.run") as run,
            ):
                host_command("env", timeout=4)
                command = run.call_args.args[0]
                env = run.call_args.kwargs["env"]
                self.assertIsNotNone(env)
                self.assertEqual(env["HOME"], str(self.home))
                self.assertNotIn("CONTAINERS_CONF", env)
                self.assertNotIn("HTTP_PROXY", env)
                if mode == "distrobox":
                    self.assertEqual(command[1:5], ["--no-pty", "--env=", "/usr/bin/env", "-i"])
                    self.assertEqual(command[-1], "/usr/bin/env")
                    self.assertIn(f"HOME={self.home}", command)

    def test_rejects_shared_worker_and_relay_mcs(self):
        self.job.ids["worker"] = WORKER
        label = "system_u:system_r:container_t:s0:c100,c200"
        mode = f"container:{WORKER}"
        details = {
            "Image": RELAY,
            "HostConfig": {
                "NetworkMode": mode, "ReadonlyRootfs": True, "SecurityOpt": ["no-new-privileges"],
                "Memory": MEMORY_LIMITS["relay"], "MemorySwap": MEMORY_LIMITS["relay"], "CgroupMode": "private",
                "IpcMode": "private", "PidMode": "private", "PidsLimit": 192,
            },
            "NetworkSettings": {"Networks": {"none": {}}},
            "Config": {"User": "0:0"},
            "ProcessLabel": label,
            "MountLabel": "system_u:object_r:container_file_t:s0:c100,c200",
        }
        with (
            patch.object(self.job, "_identity", return_value={
                "ProcessLabel": "system_u:system_r:container_t:s0:c200,c100",
            }),
            self.assertRaisesRegex(JobError, "distinct SELinux MCS categories"),
        ):
            self.job._verify_isolation("relay", mode, details)

    def test_host_pid_inspection_never_starts_that_role(self):
        for bad_role in ("worker", "relay"):
            with self.subTest(role=bad_role):
                self._assert_host_pid_refused(bad_role)

    def _assert_host_pid_refused(self, bad_role):
        root = Path(self.scratch.name) / bad_role
        root.mkdir(mode=0o700)
        job = self.make_job(root)
        job.prepare()
        emitted = []
        role_ids = {"worker": WORKER, "relay": RELAY}

        def run(*args):
            emitted.append(args)
            if args[0] == "create":
                role = "relay" if RELAY in args else "worker"
                return CompletedProcess(args, 0, stdout=role_ids[role].encode("ascii"))
            return CompletedProcess(args, 0, stdout=b"opencode v2.3.0\n")

        def verify(role, mode, _mounts, _tmpfs, _env):
            if role != bad_role:
                return
            details = {
                "Image": role_ids[role],
                "HostConfig": {
                    "NetworkMode": mode, "ReadonlyRootfs": True, "SecurityOpt": ["no-new-privileges"],
                    "IpcMode": "private", "PidMode": "host", "PidsLimit": 192, "CgroupMode": "private",
                    "Memory": MEMORY_LIMITS[role], "MemorySwap": MEMORY_LIMITS[role],
                },
                "NetworkSettings": {"Networks": {"none": {}}}, "Config": {"User": "0:0"},
                "ProcessLabel": "system_u:system_r:container_t:s0:c100,c200",
                "MountLabel": "system_u:object_r:container_file_t:s0:c100,c200",
            }
            job._verify_isolation(role, mode, details)

        try:
            with (
                socket.socket(socket.AF_UNIX) as provider,
                patch("runtime.podman", side_effect=run),
                patch.object(job, "_check_images"),
                patch.object(job, "_verify_running_label"),
                patch.object(job, "_verify_memory"),
                patch.object(job, "_verify_distinct_mcs"),
                patch.object(job, "_verify_container", side_effect=verify),
            ):
                provider.bind(str(job.provider_socket))
                with self.assertRaisesRegex(JobError, "isolation settings"):
                    job.start()
        finally:
            job.attempted_create = False
            job.close()
        creates = [args for args in emitted if args[0] == "create"]
        self.assertEqual(len(creates), 1 if bad_role == "worker" else 2)
        self.assertTrue(all("--pid=private" in args for args in creates))
        self.assertNotIn(("start", role_ids[bad_role]), emitted)

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
            env_file = Path(args[args.index("--env-file") + 1])
            self.assertEqual(env_file.parent, self.job.root)
            self.assertEqual(stat.S_IMODE(env_file.stat().st_mode), 0o600)
            self.assertEqual(env_file.read_text(), "OPENCODE_PASSWORD=sample-password\n")
            self.assertNotIn("sample-password", " ".join(args))
            raise JobError("simulated host create timeout")

        try:
            with (
                patch("runtime.podman", side_effect=unacknowledged_create),
                patch.object(self.job, "_inventory", return_value=[]) as inventory,
            ):
                with self.assertRaisesRegex(JobError, "simulated host create timeout"):
                    self.job._create(
                        "worker", mode="none", mounts={}, tmpfs={},
                        env={"OPENCODE_PASSWORD": "sample-password"}, command=[], workdir="/",
                    )
                self.assertFalse((self.job.root / "worker.env").exists())
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

    def test_invalid_guest_bridge_context_refuses_before_any_host_command(self):
        auth_context = self.job.root / "context"
        auth_context.write_bytes(b"fixture:fixture:untrusted_t:s0")
        leaf = self.job.root / "candidate"
        leaf.mkdir(mode=0o700)
        job = self.make_job(leaf)
        self.addCleanup(job.close)
        with (
            patch("runtime.HOST_MODE", "distrobox"),
            patch("runtime.SHARED_TMP", self.job.root, create=True),
            patch("runtime.SELINUX_PROCESS", auth_context),
            patch("runtime.host_output") as host,
            self.assertRaises(JobError),
        ):
            job.prepare()
        host.assert_not_called()
        self.assertEqual(list(leaf.iterdir()), [])

    def test_devbox_tmp_must_match_physical_root_owned_sticky_directory(self):
        shared_tmp = self.job.root / "tmp"
        shared_tmp.mkdir()
        shared_tmp.chmod(0o1777)
        entry = shared_tmp.lstat()
        identity = f"{entry.st_dev}:{entry.st_ino}:0:{entry.st_mode:x}".encode()
        with (
            patch("runtime.SHARED_TMP", shared_tmp, create=True),
            patch("runtime.host_output", return_value=identity) as host,
        ):
            self.job._check_shared_tmp()
            host.return_value = f"{entry.st_dev}:{entry.st_ino + 1}:0:{entry.st_mode:x}".encode()
            with self.assertRaisesRegex(JobError, "root-owned sticky host /tmp"):
                self.job._check_shared_tmp()

    def test_devbox_bridge_rejects_same_name_with_different_directory_inode(self):
        current = self.job.root.stat()
        devbox_bus = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=current.st_uid)
        fixed_tool = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        alternate = f"{current.st_dev}:{current.st_ino + 1}:{current.st_uid}:{current.st_mode:x}"
        with (
            patch("runtime.Path.read_bytes", return_value=b"unconfined_u:unconfined_r:spc_t:s0"),
            patch("runtime.Path.stat", side_effect=(devbox_bus, fixed_tool)),
            patch.object(self.job, "_check_shared_tmp", create=True),
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
