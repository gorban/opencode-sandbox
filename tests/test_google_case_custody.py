"""Inert regressions for the sealed fixture allocator and capsule publication."""

from contextlib import nullcontext
import errno
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

import google_connect_driver as driver
import google_home_controller as controller


_FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "google_connect_fixture", Path(__file__).with_name("google-connect-fixture.py"),
)
fixture = importlib.util.module_from_spec(_FIXTURE_SPEC)
_FIXTURE_SPEC.loader.exec_module(fixture)


class CapsulePublicationTest(unittest.TestCase):
    def test_protected_publish_never_starts_readable_under_permissive_umask(self):
        with TemporaryDirectory() as directory:
            leaf = Path(directory) / "receipt.json"
            seen = []
            original_write = os.write

            def write(fd, data):
                seen.append((stat.S_IMODE(os.fstat(fd).st_mode), stat.S_IMODE(leaf.stat().st_mode)))
                return original_write(fd, data)

            previous = os.umask(0)
            try:
                with patch.object(driver.os, "write", side_effect=write):
                    driver.write_protected(leaf, b"bound fixture")
            finally:
                os.umask(previous)
            self.assertEqual(seen, [(0o600, 0o600)])
            self.assertEqual(leaf.read_bytes(), b"bound fixture")
            self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o444)
            with self.assertRaises(FileExistsError):
                driver.write_protected(leaf, b"replace")
            self.assertEqual(leaf.read_bytes(), b"bound fixture")

    def test_write_or_prepublication_fsync_failure_stays_private(self):
        for failure in ("write", "fsync"):
            with self.subTest(failure=failure), TemporaryDirectory() as directory:
                leaf = Path(directory) / "receipt.json"
                with patch.object(driver.os, failure, side_effect=OSError(errno.EIO, "fixture failure")):
                    with self.assertRaises(OSError):
                        driver.write_protected(leaf, b"fixture")
                self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o600)
                with self.assertRaises(FileExistsError):
                    driver.write_protected(leaf, b"replace")

    def test_post_final_mode_fsync_uncertainty_revokes_publication(self):
        for target in ("file", "parent"):
            with self.subTest(target=target), TemporaryDirectory() as directory:
                leaf = Path(directory) / "receipt.json"
                seen = []
                original_sync = os.fsync
                injected = False

                def sync(fd):
                    nonlocal injected
                    called = "parent" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
                    mode = stat.S_IMODE(leaf.stat().st_mode)
                    seen.append((called, mode))
                    if called == target and mode == 0o444 and not injected:
                        injected = True
                        raise OSError(errno.EIO, "fixture late sync uncertainty")
                    return original_sync(fd)

                with patch.object(driver.os, "fsync", side_effect=sync):
                    with self.assertRaises(OSError):
                        driver.write_protected(leaf, b"bound complete fixture")
                self.assertTrue(injected)
                self.assertIn((target, 0o444), seen)
                self.assertEqual(seen[-2:], [("file", 0o600), ("parent", 0o600)])
                self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), 0o600)
                self.assertEqual(leaf.read_bytes(), b"bound complete fixture")
                with self.assertRaises(FileExistsError):
                    driver.write_protected(leaf, b"replace")

    def test_foreign_symlink_leaf_is_never_opened(self):
        with TemporaryDirectory() as directory:
            other = Path(directory) / "foreign"
            other.write_bytes(b"protected")
            leaf = Path(directory) / "receipt.json"
            leaf.symlink_to(other)
            with self.assertRaises(FileExistsError):
                driver.write_protected(leaf, b"replace")
            self.assertEqual(other.read_bytes(), b"protected")


class BootLeaseTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.runtime = self.root / "run"
        self.leases = self.runtime / "leases"
        self.leases.mkdir(parents=True, mode=0o700)
        self.capsule = self.root / "capsule"
        self.capsule.mkdir()
        self.original_boot = "00000000-0000-0000-0000-000000000001"
        self.boot = self.enterContext(patch.object(controller, "current_boot", return_value=self.original_boot))
        self.tree = "b" * 40
        self.pin = "a" * 64
        for name, path in (("CAPSULE", self.capsule), ("BOOT_RUNTIME", self.runtime), ("BOOT_LEASES", self.leases),
                           ("BINDING", self.capsule / "capsule-binding.json")):
            self.enterContext(patch.object(controller, name, path))
        self.enterContext(patch.object(controller, "protected_directory"))
        self.mount = self.enterContext(patch.object(controller, "boot_mount"))
        self.enterContext(patch.object(controller, "protected_bytes", side_effect=lambda path, _: path.read_bytes()))
        self.enterContext(patch.object(controller.os, "getuid", return_value=0))
        self.enterContext(patch.object(controller.os, "geteuid", return_value=0))
        stat_path, stat_fd = os.stat, os.fstat

        def root_owned(info):
            fields = list(info)
            fields[4] = 0
            return os.stat_result(fields)

        self.enterContext(patch.object(controller.os, "fstat", side_effect=lambda fd: root_owned(stat_fd(fd))))
        self.enterContext(patch.object(
            controller.os, "stat", side_effect=lambda *args, **kwargs: root_owned(stat_path(*args, **kwargs)),
        ))
        self.manifest = {"tree": self.tree, "source": {}}
        self.user = SimpleNamespace(pw_uid=1000, pw_gid=1001, pw_name=controller.ACCOUNT, pw_dir=controller.HOME)
        self.value = b"r" * controller.START_BYTES
        self.enterContext(patch.object(controller.secrets, "token_bytes", return_value=self.value))
        self.enterContext(patch.object(controller, "controller_identity", return_value={"pid": 193}))
        self.allocator = self.enterContext(patch.object(controller, "allocate_case_process"))
        self.start = self.enterContext(patch.object(controller, "observe_run", return_value=0))
        self.enterContext(patch.object(controller, "inspect_devbox", return_value="a" * 64))
        self.enterContext(patch.object(controller.pwd, "getpwnam", return_value=self.user))
        self.seal = {"uid": self.user.pw_uid, **self.manifest, "boot": self.original_boot}
        self.marker = Mock(side_effect=self.publish_marker)
        self.hooks = {
            "HOME_BEFORE": driver.HOME_BEFORE, "HOME_BEFORE_STAGE": driver.HOME_BEFORE_STAGE,
            "HOME_RESULT": driver.HOME_RESULT, "NATIVE_RESULT": driver.NATIVE_RESULT,
            "absent": driver.absent, "write_protected": self.marker,
            "install_seal": Mock(side_effect=lambda _tree, allocate: allocate()),
            "proof_file": Mock(return_value=self.seal), "validate_seal": Mock(),
        }
        self.enterContext(patch.object(controller, "pinned_driver", return_value=(self.hooks, self.manifest)))

    @staticmethod
    def publish_marker(path, payload):
        with path.open("xb") as output:
            output.write(payload)

    def prepare(self, capsule_id, *, manifest=None):
        binding = {
            "version": 1, "capsule": capsule_id, "boot": self.boot.return_value, "tree": self.tree,
            "manifest_sha256": manifest or self.pin, "capsule_id": controller.directory_id(self.capsule.stat()),
        }
        raw = json.dumps(binding).encode("ascii")
        controller.BINDING.write_bytes(raw)
        return sha256(raw).hexdigest()

    def test_lost_marker_cannot_renew_the_boot_lease_or_authorize_a_new_boot(self):
        old_id = "c" * 32
        binding = self.prepare(old_id)
        attempt = self.capsule / controller.ATTEMPT

        def fail_after_publication(path, payload):
            self.publish_marker(path, payload)
            raise OSError(errno.EIO, "synthetic uncertain marker sync")

        self.marker.side_effect = fail_after_publication
        with self.assertRaises(OSError):
            controller.run_controller(self.pin, binding)
        self.assertTrue(attempt.is_file())
        self.assertEqual(stat.S_IMODE((self.leases / old_id).stat().st_mode), 0o600)
        attempt.unlink()  # Independent synthetic loss of the persistent name.
        with self.assertRaises(FileExistsError):
            controller.run_controller(self.pin, binding)
        self.boot.return_value = "00000000-0000-0000-0000-000000000002"
        with self.assertRaises(controller.ControllerRefused):
            controller.run_controller(self.pin, binding)
        self.marker.assert_called_once()
        self.allocator.assert_not_called()
        self.start.assert_not_called()

        # Model an independently prepared replacement capsule after the boot changed.
        self.capsule.rename(self.root / "retained")
        self.capsule.mkdir()
        self.seal["boot"] = self.boot.return_value
        self.marker.side_effect = self.publish_marker
        new_binding = self.prepare("d" * 32)
        self.assertEqual(controller.run_controller(self.pin, new_binding), 0)
        with self.assertRaises(controller.ControllerRefused):
            controller.run_controller(self.pin, new_binding)
        self.allocator.assert_called_once_with(self.pin, new_binding, self.user, self.value)
        self.start.assert_called_once()
        self.assertNotIn(self.value, (self.capsule / controller.ATTEMPT).read_bytes())
        self.assertNotIn(self.value, (self.leases / ("d" * 32)).read_bytes())

    def test_root_callback_can_issue_only_one_allocation(self):
        binding = self.prepare("a" * 32)

        def repeated_callback(_tree, allocate):
            allocate()
            allocate()

        self.hooks["install_seal"].side_effect = repeated_callback
        with self.assertRaises(controller.ControllerRefused):
            controller.run_controller(self.pin, binding)
        self.allocator.assert_called_once_with(self.pin, binding, self.user, self.value)
        self.start.assert_not_called()

    def test_lease_uncertainty_and_wrong_mount_or_origin_precede_allocation(self):
        binding = self.prepare("e" * 32, manifest="f" * 64)
        with self.assertRaises(controller.ControllerRefused):
            controller.run_controller(self.pin, binding)
        binding = self.prepare("e" * 32)
        self.mount.side_effect = controller.ControllerRefused()
        with self.assertRaises(controller.ControllerRefused):
            controller.run_controller(self.pin, binding)
        self.assertFalse(list(self.leases.iterdir()))
        self.mount.side_effect = None
        with patch.object(controller.os, "fsync", side_effect=OSError(errno.EIO, "synthetic lease sync")):
            with self.assertRaises(OSError):
                controller.run_controller(self.pin, binding)
        with self.assertRaises(FileExistsError):
            controller.run_controller(self.pin, binding)
        self.marker.assert_not_called()
        self.allocator.assert_not_called()

    def test_prior_artifacts_or_failed_allocation_never_start_the_supervisor(self):
        binding = self.prepare("f" * 32)
        artifact = self.capsule / driver.NATIVE_RESULT
        artifact.touch()
        with self.assertRaises(controller.ControllerRefused):
            controller.run_controller(self.pin, binding)
        artifact.unlink()
        self.allocator.side_effect = subprocess.SubprocessError("synthetic failed allocation")
        with self.assertRaises(subprocess.SubprocessError):
            controller.run_controller(self.pin, binding)
        with self.assertRaises(controller.ControllerRefused):
            controller.run_controller(self.pin, binding)
        self.allocator.assert_called_once()
        self.start.assert_not_called()

    def test_failed_first_root_case_check_retains_attempt_and_refuses_retry(self):
        binding = self.prepare("a" * 32)
        self.hooks["install_seal"].side_effect = driver.install_seal
        self.allocator.return_value = {
            label: {
                "case": str(driver.USER_RUNTIME / "1000" / f"oc-g-connect-fixture-{index + 1:08x}"),
                "root_id": [1, 3 * index + 1], "home_id": [1, 3 * index + 2], "sandbox_id": [1, 3 * index + 3],
            }
            for index, label in enumerate(driver.LABELS)
        }
        with (
            patch.object(driver, "CAPSULE", self.capsule),
            patch.object(driver, "account", return_value=self.user),
            patch.object(driver, "topology", return_value=self.original_boot),
            patch.object(driver, "root_host"),
            patch.object(driver, "firewall", return_value="4" * 64),
            patch.object(driver, "source_inventory", return_value=dict.fromkeys(driver.SOURCE_FILES, "5" * 64)),
            patch.object(driver, "vendor_pair"),
            patch.object(driver, "home_snapshot"),
            patch.object(driver, "case_paths", side_effect=driver.Refused()) as verify,
        ):
            with self.assertRaises(driver.Refused):
                controller.run_controller(self.pin, binding)
            with self.assertRaises(controller.ControllerRefused):
                controller.run_controller(self.pin, binding)
        verify.assert_called_once()
        self.allocator.assert_called_once()
        self.start.assert_not_called()
        self.assertTrue((self.capsule / controller.ATTEMPT).is_file())
        self.assertFalse((self.capsule / "case-config").exists())


class AllocationAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.user = SimpleNamespace(pw_uid=1000, pw_gid=1001, pw_name=controller.ACCOUNT, pw_dir=controller.HOME)
        self.pins = ("a" * 64, "b" * 64)
        self.value = b"r" * controller.START_BYTES
        self.manifest = {"tree": "c" * 40, "controller": "d" * 64}
        self.binding = {"tree": self.manifest["tree"], "capsule": "e" * 32,
                        "boot": "00000000-0000-0000-0000-000000000001"}
        self.owner = {"pid": 912, "start_ticks": 768, "interpreter": controller.directory_id(os.stat(controller.PYTHON)),
                      "script": self.manifest["controller"],
                      "argv": controller.argument_digest(controller.controller_arguments(*self.pins))}
        self.attempt = {"version": 2, **self.binding, "manifest": self.pins[0], "binding": self.pins[1],
                        "controller": self.owner, "account": {"uid": 1000, "gid": 1001}}
        self.attempt["allocation"] = controller.allocation_digest(self.attempt, self.value)
        self.allocate = Mock(return_value={"synthetic": {}})
        hooks = {"read_catalog_start": lambda: driver.read_catalog_start(),
                 "require_unprivileged_allocator": driver.require_unprivileged_allocator,
                 "validate_allocation_attempt": driver.validate_allocation_attempt, "allocate_cases": self.allocate}
        self.enterContext(patch.object(controller, "pinned_driver", return_value=(hooks, self.manifest)))
        self.enterContext(patch.object(controller, "deployment_binding", return_value=self.binding))
        self.boot = self.enterContext(patch.object(controller, "current_boot", return_value=self.binding["boot"]))
        self.enterContext(patch.object(controller.pwd, "getpwnam", return_value=self.user))
        self.enterContext(patch.object(os, "getresuid", return_value=(1000,) * 3))
        self.uid = self.enterContext(patch.object(os, "getresgid", return_value=(1001,) * 3))
        self.enterContext(patch.object(os, "getgroups", return_value=[]))
        self.parent = self.enterContext(patch.object(os, "getppid", return_value=self.owner["pid"]))
        self.enterContext(patch.object(controller, "protected_bytes", side_effect=lambda *_: json.dumps(self.attempt).encode()))
        self.enterContext(patch.object(controller, "process_directory", return_value=nullcontext(456)))
        self.status = b"Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
        self.ticks = self.owner["start_ticks"]
        self.proc = self.enterContext(patch.object(controller, "proc_bytes", side_effect=self.proc_observation))
        self.display = self.enterContext(patch("builtins.print"))

    def proc_observation(self, process, leaf, _limit):
        self.assertEqual(process, 456)
        if leaf == "status":
            return self.status
        self.assertEqual(leaf, "stat")
        return f'{self.owner["pid"]} (synthetic parent) S {"0 " * 18}{self.ticks} 0\n'.encode()

    def attempt_with_pipe(self, data, *, named=False):
        with TemporaryDirectory() as tmp:
            if named:
                leaf = Path(tmp) / "named.fifo"
                os.mkfifo(leaf, 0o600)
                read = os.open(leaf, os.O_RDONLY | os.O_NONBLOCK)
                write = os.open(leaf, os.O_WRONLY | os.O_NONBLOCK)
            else:
                read, write = os.pipe2(os.O_CLOEXEC)
            try:
                os.write(write, data)
            finally:
                os.close(write)
            # An inert open pipe models a live pidfd. Parent observations use only status/stat.
            pidfd, alive = os.pipe2(os.O_CLOEXEC)
            try:
                with (
                    patch.object(os, "pidfd_open", return_value=pidfd) as pid_open,
                    patch.object(driver, "read_catalog_start", side_effect=lambda: self.original_read(read)),
                ):
                    return controller.run_case_allocator(*self.pins)
            finally:
                os.close(alive)
                if not pid_open.called:
                    os.close(pidfd)

    original_read = staticmethod(driver.read_catalog_start)

    def test_direct_repeated_and_replaced_descriptor_refuse_without_allocation(self):
        for data, named in ((b"", False), (self.value[:-1], False), (self.value + b"!", False),
                            (b"x" * len(self.value), False), (self.value, True)):
            with self.subTest(size=len(data), named=named), self.assertRaises((controller.ControllerRefused, driver.Refused)):
                self.attempt_with_pipe(data, named=named)
        self.allocate.assert_not_called()

    def test_valid_parent_without_executable_link_and_exact_one_use_delivery(self):
        original = os.stat

        def no_root_exe(path, *args, **kwargs):
            if str(path).endswith("/exe") or path == "exe":
                raise PermissionError("synthetic protected root executable link")
            return original(path, *args, **kwargs)

        with patch.object(os, "stat", side_effect=no_root_exe):
            self.assertEqual(self.attempt_with_pipe(self.value), 0)
        with self.assertRaises(driver.Refused):
            self.attempt_with_pipe(b"")
        self.allocate.assert_called_once()
        self.display.assert_called_once_with('{"synthetic": {}}')
        self.assertEqual([call.args[1] for call in self.proc.call_args_list], ["status", "stat", "status", "stat"])

    def test_wrong_boot_attempt_account_and_kernel_ids_refuse(self):
        original = dict(self.attempt)
        for case, changed in (
            ("boot", {"boot": "00000000-0000-0000-0000-000000000002"}),
            ("binding", {"binding": "f" * 64}),
            ("account", {"account": {"uid": 1002, "gid": 1001}}),
            ("malformed pid", {"controller": self.owner | {"pid": False}}),
        ):
            self.attempt = original | changed
            self.attempt["allocation"] = controller.allocation_digest(self.attempt, self.value)
            with self.subTest(case=case), self.assertRaises((controller.ControllerRefused, driver.Refused)):
                self.attempt_with_pipe(self.value)
        self.attempt = original
        self.uid.return_value = (1001, 1001, 0)
        with self.assertRaises(driver.Refused):
            self.attempt_with_pipe(self.value)
        self.allocate.assert_not_called()

    def test_changed_parent_status_ticks_boot_and_parent_death_refuse_at_last_check(self):
        good_status, good_ticks = self.status, self.ticks
        for case in ("bad uid", "malformed status", "bad ticks", "changed parent", "changed boot", "dead before allocate"):
            with self.subTest(case=case):
                self.status, self.ticks = good_status, good_ticks
                self.parent.side_effect = None
                self.boot.return_value = self.binding["boot"]
                context = nullcontext()
                if case == "bad uid":
                    self.status = self.status.replace(b"Uid:\t0", b"Uid:\t1000")
                elif case == "malformed status":
                    self.status += b"Uid:\t0\t0\t0\t0\n"
                elif case == "bad ticks":
                    self.ticks += 1
                elif case == "changed parent":
                    self.parent.side_effect = [self.owner["pid"], self.owner["pid"], self.owner["pid"], 913]
                elif case == "changed boot":
                    self.boot.return_value = "different boot"
                else:
                    context = patch.object(controller.select, "select", side_effect=[
                        ([0], [], []), ([0], [], []), ([], [], []), ([], [], []), ([0], [], []),
                    ])
                with context, self.assertRaises((controller.ControllerRefused, driver.Refused)):
                    self.attempt_with_pipe(self.value)
        self.allocate.assert_not_called()


class RootControllerIdentityTest(unittest.TestCase):
    def test_root_pins_executable_script_arguments_and_kernel_start(self):
        manifest_pin, binding_pin = "a" * 64, "b" * 64
        script = b"inert synthetic controller bytes"
        manifest = {"controller": sha256(script).hexdigest()}
        binding = {"boot": "synthetic boot"}
        pid = 430
        executable = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755, st_dev=24, st_ino=88)
        argv = b"\0".join(os.fsencode(item) for item in controller.controller_arguments(manifest_pin, binding_pin)) + b"\0"
        status = b"Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
        good_stat = f'{pid} (synthetic controller) S {"0 " * 18}991 0\n'.encode("ascii")
        for case in ("valid", "wrong args", "wrong script", "wrong inode", "wrong root ID", "malformed stat"):
            with self.subTest(case=case):
                observed = {"status": status,
                            "cmdline": argv if case != "wrong args" else argv + b"new argument\0",
                            "stat": good_stat if case != "malformed stat" else b"invalid"}
                named_exe = executable if case != "wrong inode" else SimpleNamespace(**(vars(executable) | {"st_ino": 89}))
                effective = (0, 0, 0) if case != "wrong root ID" else (0, 0, 1000)
                with (
                    patch.object(controller, "current_boot", return_value=binding["boot"]),
                    patch.object(controller, "process_directory", return_value=nullcontext(721)),
                    patch.object(controller, "proc_bytes", side_effect=lambda _, leaf, _limit: observed[leaf]),
                    patch.object(controller, "protected_bytes", return_value=script if case != "wrong script" else b"changed"),
                    patch.object(controller.os, "getpid", return_value=pid),
                    patch.object(controller.os, "getresuid", return_value=effective),
                    patch.object(controller.os, "getresgid", return_value=(0, 0, 0)),
                    patch.object(controller.os, "stat", side_effect=[executable, named_exe]),
                ):
                    if case == "valid":
                        self.assertEqual(controller.controller_identity(binding, manifest, manifest_pin, binding_pin), {
                            "pid": pid, "start_ticks": 991, "interpreter": [24, 88], "script": manifest["controller"],
                            "argv": sha256(argv).hexdigest(),
                        })
                    else:
                        with self.assertRaises(controller.ControllerRefused):
                            controller.controller_identity(binding, manifest, manifest_pin, binding_pin)

    def test_ordinary_directory_is_not_accepted_as_procfs(self):
        with TemporaryDirectory() as temporary:
            ordinary = Path(temporary)
            (ordinary / "430").mkdir()
            with patch.object(controller, "PROC", ordinary):
                untrusted = controller.process_directory(430)
                with self.assertRaises(controller.ControllerRefused):
                    self.enterContext(untrusted)


class OwnedChildCleanupTest(unittest.TestCase):
    def test_catalog_close_failure_reaps_child_and_preserves_primary_error(self):
        primary = OSError(errno.EIO, "synthetic parent close")
        initial = Mock()
        initial.close.side_effect = [primary, OSError(errno.EIO, "synthetic repeat close")]
        child = Mock(pid=4124)
        child.wait.side_effect = subprocess.TimeoutExpired(("fixture",), 5)
        command = ("fixture",)
        with (
            patch.object(controller.subprocess, "Popen", return_value=child) as spawn,
            patch.object(controller.os, "killpg") as kill,
            self.assertRaises(OSError) as outcome,
        ):
            controller.bounded_run(command, seconds=10, limit=4096, stdin=initial)
        self.assertIs(outcome.exception, primary)
        self.assertEqual(initial.close.call_count, 2)
        spawn.assert_called_once()
        kill.assert_called_once_with(child.pid, signal.SIGKILL)
        child.wait.assert_called_once_with(timeout=5)
        child.stdout.close.assert_called_once_with()
        self.assertTrue(any("not confirmed" in note for note in primary.__notes__))

    def test_catalog_spawn_and_pre_spawn_pipe_failure_close_the_owned_input(self):
        primary = OSError(errno.EIO, "synthetic missing fixture child")
        initial = Mock()
        command = ("fixture",)
        with (
            patch.object(controller.subprocess, "Popen", side_effect=primary),
            patch.object(controller.os, "killpg") as kill,
            self.assertRaises(OSError) as outcome,
        ):
            controller.bounded_run(command, seconds=10, limit=4096, stdin=initial)
        self.assertIs(outcome.exception, primary)
        initial.close.assert_called_once_with()
        kill.assert_not_called()
        fds = os.pipe2(os.O_CLOEXEC)
        value = b"x" * controller.START_BYTES
        with (
            patch.object(os, "pipe2", return_value=fds),
            patch.object(os, "write", side_effect=primary),
            patch.object(controller.subprocess, "Popen") as spawn,
            self.assertRaises(OSError) as outcome,
        ):
            controller.open_start_input(value)
        self.assertIs(outcome.exception, primary)
        spawn.assert_not_called()
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_pty_parent_close_failure_is_bounded_and_only_signals_the_owned_child(self):
        for retired, missing in ((True, False), (False, False), (False, True)):
            with self.subTest(retired=retired, missing=missing):
                self.pty_close_failure(retired=retired, missing=missing)

    def pty_close_failure(self, *, retired, missing):
        pid, master, clock = 3011, 4022, 0.0
        sent = []

        def pause(seconds):
            nonlocal clock
            clock += seconds

        def probe(_pid, _flags):
            if missing:
                raise ChildProcessError()
            return (pid, signal.SIGKILL) if retired and signal.SIGKILL in sent else (0, 0)

        primary = OSError(errno.EIO, "synthetic PTY parent close")
        initial = Mock()
        initial.close.side_effect = [primary, None]
        home, launcher = Path("/scratch/home"), Path("/scratch/fixture.py")
        with (
            patch.object(fixture.pty, "fork", return_value=(pid, master)) as spawn,
            patch.object(fixture.os, "close") as close,
            patch.object(fixture.os, "waitpid", side_effect=probe) as waitpid,
            patch.object(fixture.os, "kill", side_effect=lambda _, signum: sent.append(signum)) as kill,
            patch.object(fixture.time, "monotonic", side_effect=lambda: clock),
            patch.object(fixture.time, "sleep", side_effect=pause),
            patch.object(fixture, "observe_pty") as observe,
            self.assertRaises(OSError) as outcome,
        ):
            fixture.launch(home, launcher, "fixture-alpha", 73, initial)
        self.assertIs(outcome.exception, primary)
        self.assertLessEqual(clock, 5)
        self.assertEqual(initial.close.call_count, 2)
        spawn.assert_called_once_with()
        close.assert_called_once_with(master)
        observe.assert_not_called()
        self.assertTrue(all(call.args == (pid, os.WNOHANG) for call in waitpid.call_args_list))
        self.assertTrue(all(call.args[0] == pid for call in kill.call_args_list))
        self.assertEqual(sent, [] if missing else [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(bool(getattr(primary, "__notes__", ())), not retired)

    def test_pty_spawn_failure_closes_input_without_reaping_or_signalling(self):
        failure = OSError(errno.EIO, "synthetic failed fork")
        initial = Mock()
        home, launcher = Path("/scratch/home"), Path("/scratch/fixture.py")
        with (
            patch.object(fixture.pty, "fork", side_effect=failure),
            patch.object(fixture.os, "waitpid") as waitpid,
            patch.object(fixture.os, "kill") as kill,
            self.assertRaises(OSError) as outcome,
        ):
            fixture.launch(home, launcher, "fixture-alpha", 73, initial)
        self.assertIs(outcome.exception, failure)
        initial.close.assert_called_once_with()
        waitpid.assert_not_called()
        kill.assert_not_called()

    def test_projection_and_pty_close_faults_preserve_the_primary_error(self):
        pid, master, descriptor = 3011, 4022, 73
        primary = OSError(errno.EIO, "synthetic PTY closure")
        secondary = OSError(errno.EBADF, "synthetic projection closure")
        initial = Mock()
        seal = {"uid": 1000}
        scope, value = {}, b"x" * driver.START_BYTES
        with TemporaryDirectory() as directory:
            case = Path(directory)
            home = case / "home"
            source = case / "source"
            source.mkdir()
            launcher = source / "fixture.py"
            guard = {"guest": Mock(return_value=seal), "check_home_before": Mock(), "private_inventory": Mock(),
                     "require": driver.require, "case_paths": Mock(return_value=nullcontext((case, home, None))),
                     "prepare_descriptor": Mock(return_value=descriptor),
                     "one_case_start": Mock(return_value=nullcontext(initial))}
            try:
                with (
                    patch.object(fixture, "copy_fixture", return_value=(home, launcher, None)),
                    patch.object(fixture, "observe_bound_catalog", return_value=(None, None)),
                    patch.object(fixture, "observe_pty", return_value=(b"", False, False)),
                    patch.object(fixture.pty, "fork", return_value=(pid, master)) as spawn,
                    patch.object(fixture.os, "close", side_effect=[primary, secondary]) as close,
                    patch.object(fixture.os, "waitpid", return_value=(pid, 0)) as waitpid,
                    patch.object(fixture.os, "kill") as kill,
                    self.assertRaises(OSError) as outcome,
                ):
                    fixture.run_bound_catalog_cases(guard, (), seal, scope, value)
                self.assertIs(outcome.exception, primary)
                self.assertEqual(primary.__notes__, ["Synthetic case projection descriptor closure was not confirmed."])
                self.assertEqual([call.args for call in close.call_args_list], [(master,), (descriptor,)])
                initial.close.assert_called_once_with()
                spawn.assert_called_once_with()
                waitpid.assert_called_once_with(pid, os.WNOHANG)
                kill.assert_not_called()
            finally:
                source.chmod(0o700)

    def test_real_case_directory_close_faults_keep_the_pty_diagnostic_and_stop_startup(self):
        uid = os.getuid()
        pid, master, descriptor = 3011, 4022, 4073
        primary = OSError(errno.EIO, "synthetic startup close")
        initial = Mock()
        initial.close.side_effect = [primary, None]
        captured, closed = [], []
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / str(uid)
            case = runtime / "oc-g-connect-fixture-deadbeef"
            home = case / "home"
            sandbox = home / "opencode-sandbox"
            source = case / "source"
            for path in (runtime, case, home, sandbox, source):
                path.mkdir(mode=0o700)
            launcher = source / "fixture.py"
            label = driver.LABELS[0]
            seal = {"uid": uid, "cases": {label: {
                "case": str(case), "root_id": driver.identity(case.stat()), "home_id": driver.identity(home.stat()),
                "sandbox_id": driver.identity(sandbox.stat()), "config": "0" * 64,
            }}}
            directory_ids = {tuple(driver.identity(path.stat())): path for path in (runtime, case, home, sandbox)}
            original_close = os.close

            def fail_after_directory_close(fd):
                if fd in (master, descriptor):
                    return
                path = directory_ids.get(tuple(driver.identity(os.fstat(fd)))) if fd in pinned else None
                original_close(fd)
                pinned.discard(fd)
                if path is not None:
                    closed.append(path)
                    raise OSError(errno.EIO, "synthetic case directory close")

            original_open, pinned = os.open, set()

            def track_case_open(path, *args, **kwargs):
                fd = original_open(path, *args, **kwargs)
                if path in (runtime, case.name, "home", sandbox.name):
                    pinned.add(fd)
                return fd

            guard = {
                "isolated": Mock(), "verify_start_parent": Mock(), "read_catalog_start": Mock(return_value=b"x" * 32),
                "guest": Mock(return_value=seal), "authorize_home_start": Mock(return_value={}), "vendor_pair": Mock(),
                "private_inventory": Mock(), "require": driver.require, "check_home_before": Mock(),
                "case_paths": driver.case_paths, "prepare_descriptor": Mock(return_value=descriptor),
                "one_case_start": Mock(return_value=nullcontext(initial)),
            }
            run_cases = fixture.run_bound_catalog_cases

            def capture(*args):
                try:
                    return run_cases(*args)
                except BaseException as error:
                    captured.append(error)
                    raise

            # Substitute the capsule bootstrap only. The real case owner opens scratch directories.
            entry, loader, private_source = Mock(), Mock(), MagicMock()
            entry.resolve.return_value = entry
            loader.resolve.return_value = loader
            loader.parents = ()
            loader.lstat.return_value = SimpleNamespace(st_uid=0, st_mode=0o444)
            private_source.__truediv__.side_effect = (entry, loader, root / "tests")
            terminal = io.StringIO()
            fixture_sys = SimpleNamespace(flags=SimpleNamespace(isolated=True, dont_write_bytecode=True, no_site=True),
                                          path=[], stderr=terminal)
            try:
                with (
                    patch.object(driver, "USER_RUNTIME", root),
                    patch.object(fixture, "sys", fixture_sys),
                    patch.object(fixture, "Path", side_effect=[private_source, Mock(absolute=Mock(return_value=entry))]),
                    patch.object(fixture.argparse.ArgumentParser, "parse_args"),
                    patch.object(fixture.os, "umask"),
                    patch.object(fixture.runpy, "run_path", return_value=guard),
                    patch.object(fixture, "run_bound_catalog_cases", side_effect=capture),
                    patch.object(fixture, "copy_fixture", return_value=(home, launcher, None)) as copy_case,
                    patch.object(fixture, "observe_bound_catalog", return_value=(None, None)),
                    patch.object(fixture, "verify_bound_catalog") as verify,
                    patch.object(fixture.pty, "fork", return_value=(pid, master)) as spawn,
                    patch.object(os, "open", side_effect=track_case_open),
                    patch.object(os, "close", side_effect=fail_after_directory_close),
                    patch.object(os, "waitpid", side_effect=ChildProcessError()) as waitpid,
                    patch.object(os, "kill") as kill,
                ):
                    self.assertEqual(fixture.main(), 1)
                self.assertEqual(captured, [primary])
                self.assertEqual(closed, [sandbox, home, case, runtime])
                self.assertIn(fixture.PTY_UNCONFIRMED, primary.__notes__)
                self.assertIn(fixture.PTY_UNCONFIRMED, terminal.getvalue())
                self.assertTrue(case.exists())
                copy_case.assert_called_once()
                spawn.assert_called_once_with()
                waitpid.assert_called_once_with(pid, os.WNOHANG)
                kill.assert_not_called()
                verify.assert_not_called()
            finally:
                source.chmod(0o700)


class LiveStartTest(unittest.TestCase):
    def test_exact_anonymous_descriptor_is_consumed_and_closed(self):
        for raw in (None, b"", b"s" * 31, b"s" * 32, b"s" * 33):
            with self.subTest(length=len(raw) if raw is not None else None):
                if raw is None:
                    reader = os.open(os.devnull, os.O_RDONLY)
                else:
                    reader, writer = os.pipe2(os.O_CLOEXEC)
                    try:
                        os.write(writer, raw)
                    finally:
                        os.close(writer)
                if raw == b"s" * 32:
                    self.assertEqual(driver.read_catalog_start(reader), raw)
                else:
                    with self.assertRaises(driver.Refused):
                        driver.read_catalog_start(reader)
                with self.assertRaises(OSError):
                    os.fstat(reader)

    def test_named_fifo_is_refused_and_closed_even_after_unlink(self):
        for unlinked in (False, True):
            with self.subTest(unlinked=unlinked), TemporaryDirectory() as temporary:
                fifo = Path(temporary) / "startup.fifo"
                os.mkfifo(fifo, 0o600)
                reader = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                try:
                    if unlinked:
                        fifo.unlink()
                    os.write(writer, b"s" * driver.START_BYTES)
                finally:
                    os.close(writer)
                with self.assertRaises(driver.Refused):
                    driver.read_catalog_start(reader)
                with self.assertRaises(OSError):
                    os.fstat(reader)

    def test_bound_child_inherits_only_the_input_and_has_no_value_in_args_or_environment(self):
        value = b"s" * controller.START_BYTES
        script = (
            "import os; "
            "v=os.read(0,33); os.close(0); "
            "assert v==b's'*32 and v not in open('/proc/self/cmdline','rb').read(); "
            "assert all(v not in os.fsencode(x) for x in os.environ.values()); "
            "assert not os.path.exists('/proc/self/fd/'+__import__('sys').argv[1]); "
            "print('synthetic bounded descriptor closed')"
        )
        with controller.start_pipe(value) as reader:
            # Keep the original descriptor above 2 so subprocess can only duplicate stdin.
            fd = reader.fileno()
            self.assertGreaterEqual(fd, 3)
            result = controller.bounded_run(
                (os.path.realpath("/usr/bin/python3"), "-IBS", "-c", script, str(fd)),
                seconds=5, limit=100, stdin=reader,
            )
            self.assertTrue(reader.closed)
        self.assertEqual(result, (0, b"synthetic bounded descriptor closed\n"))

    def test_held_supervisor_refuses_invalid_or_replayed_start_without_an_extra_child(self):
        value = b"s" * controller.START_BYTES
        accepted = controller.START + value
        for name, frame, quiet, attempts in (
            ("missing", controller.ControllerRefused(), [None], 0),
            ("truncated", accepted[:-1], [None], 0),
            ("overlong", accepted + b"x", [None], 0),
            ("wrong opcode", controller.RELEASE + value, [None], 0),
            ("wrong proof", controller.START + b"w" * len(value), [None, None], 0),
            ("changed commitment", accepted, [None, None], 0),
            ("queued replay", accepted, [None, controller.ControllerRefused()], 0),
            ("late replay", accepted, [None, None, controller.ControllerRefused()], 1),
        ):
            with self.subTest(name=name):
                seal = {"uid": os.getuid(), "tree": "a" * 40, "source": {}}
                scope = {"uid": seal["uid"], "home_id": [2, 4], "seal": "1" * 64, "attempt": "2" * 64}
                before = {"start_sha256": driver.start_digest(scope, value),
                          "case_start_sha256": driver.case_start_commitments(scope, value)}
                if name == "changed commitment":
                    before["case_start_sha256"][driver.LABELS[0]] = "b" * 64
                inventory = Mock()
                channel = Mock()
                channel.read.side_effect = [frame]
                channel.require_quiet.side_effect = quiet
                hooks = {"guest": Mock(return_value=seal), "private_inventory": inventory,
                         "authorize_home_start": driver.authorize_home_start}
                with (
                    patch.object(controller, "pinned_driver", return_value=(hooks, seal)),
                    patch.dict(os.environ, {"HOME": controller.HOME}),
                    patch.object(controller, "Frames", return_value=channel),
                    patch.object(controller, "subreaper"),
                    patch.object(controller, "no_children"),
                    patch.object(controller, "bounded_run", return_value=(0, controller.POSITIVE)) as child,
                    patch.object(driver, "home_evidence_scope", return_value=scope),
                    patch.object(driver, "verified_home_before", return_value=before),
                    patch.object(driver, "ordinary_provider_roots") as ordinary,
                    self.assertRaises((controller.ControllerRefused, driver.Refused)),
                ):
                    controller.run_held_supervisor("pin")
                self.assertEqual(child.call_count, attempts)
                self.assertEqual(ordinary.call_count, attempts)
                self.assertEqual(inventory.call_count, 1 + attempts)
                channel.write.assert_called_once_with(controller.READY)

    def test_visible_before_after_late_sync_and_rollback_failure_never_sends_start(self):
        value = b"s" * controller.START_BYTES
        scope = {"seal": "1" * 64, "attempt": "2" * 64, "boot": "boot", "tree": "3" * 40,
                 "uid": os.getuid(), "home_id": [2, 4]}
        with TemporaryDirectory() as temporary, patch.object(driver, "CAPSULE", Path(temporary)):
            path = driver.CAPSULE / driver.HOME_BEFORE
            sync, chmod = os.fsync, os.fchmod

            def fail_sync(fd):
                if path.exists() and os.path.samestat(os.fstat(fd), driver.CAPSULE.stat()):
                    raise OSError(errno.EIO, "synthetic final directory sync")
                return sync(fd)

            def fail_rollback(fd, mode):
                if path.exists() and mode == 0o600:
                    raise OSError(errno.EIO, "synthetic rollback")
                return chmod(fd, mode)

            channel = Mock()
            channel.read.return_value = controller.READY
            owner = Mock()
            hooks = {"begin_home_attestation": driver.begin_home_attestation,
                     "record_incomplete_home_attestation": Mock(side_effect=OSError(errno.EIO, "synthetic result")),
                     "finish_home_attestation": Mock(), "capture_home_after": Mock()}
            with (
                patch.object(controller, "held_client", return_value=nullcontext(owner)),
                patch.object(controller, "Frames", return_value=channel),
                patch.object(controller.secrets, "token_bytes", return_value=value),
                patch.object(driver, "root_home_scope", return_value=({}, scope)),
                patch.object(driver, "case_paths", return_value=nullcontext()),
                patch.object(driver, "capture_home_evidence", return_value={"entries": 1, "sha256": "a" * 64}),
                patch.object(os, "fsync", side_effect=fail_sync),
                patch.object(os, "fchmod", side_effect=fail_rollback),
            ):
                with self.assertRaises(OSError):
                    controller.observe_run(hooks, ("synthetic",))
            channel.write.assert_not_called()
            hooks["record_incomplete_home_attestation"].assert_called_once_with("baseline")
            hooks["finish_home_attestation"].assert_not_called()
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
            self.assertNotIn(value, path.read_bytes())
            with (
                patch.object(driver, "home_evidence_scope", return_value=scope),
                patch.object(driver, "proof_file", side_effect=lambda leaf: json.loads(leaf.read_bytes())),
                patch.object(driver, "ordinary_provider_roots"),
            ):
                for missing_or_wrong in (b"", b"w" * controller.START_BYTES):
                    with self.subTest(length=len(missing_or_wrong)), self.assertRaises(driver.Refused):
                        driver.authorize_home_start({}, missing_or_wrong)


class CaseStartTest(unittest.TestCase):
    def setUp(self):
        self.scope = {"seal": "1" * 64, "attempt": "2" * 64, "uid": os.getuid(), "home_id": [2, 4]}
        self.start = b"original-synthetic-start-value!!"
        self.assertEqual(len(self.start), driver.START_BYTES)
        self.values = {label: driver.derive_case_start(self.scope, label, self.start) for label in driver.LABELS}
        self.before = {"version": 2, "scope": self.scope, "entries": 1, "sha256": "a" * 64,
                       "start_sha256": driver.start_digest(self.scope, self.start),
                       "case_start_sha256": driver.case_start_commitments(self.scope, self.start)}

    def test_start_case_after_exact_label_commitment_and_reject_other_label_or_attempt(self):
        label, other, _ = driver.LABELS
        self.assertEqual(len(set(self.values.values()) | {self.start}), 4)
        for scope, value, allowed in (
            (self.scope, self.values[label], True),
            (self.scope, self.values[other], False),
            (self.scope, self.start, False),
            (self.scope | {"attempt": "3" * 64}, self.values[label], False),
            (self.scope | {"seal": "3" * 64}, self.values[label], False),
        ):
            with (
                self.subTest(allowed=allowed, scope=scope),
                patch.object(driver, "home_evidence_scope", return_value=scope),
                patch.object(driver, "verified_home_before", return_value=self.before),
                patch.object(driver, "ordinary_provider_roots") as ordinary,
            ):
                if allowed:
                    driver.authorize_case_start({}, label, value)
                    ordinary.assert_called_once_with(scope["uid"], scope["home_id"])
                else:
                    with self.assertRaises(driver.Refused):
                        driver.authorize_case_start({}, label, value)
                    ordinary.assert_not_called()

    def test_case_consumes_label_before_spawn_and_retains_spent_state_after_failure(self):
        sent = set()
        first, second, _ = driver.LABELS

        def fail_spawn(attempt):
            nonlocal fd
            with attempt as reader:
                fd = reader.fileno()
                self.assertIn(first, sent)
                self.assertFalse(os.get_inheritable(fd))
                raise OSError(errno.EIO, "synthetic spawn failure")

        fd = None
        first_attempt = driver.one_case_start(self.scope, first, self.start, sent)
        with self.assertRaises(OSError):
            fail_spawn(first_attempt)
        with self.assertRaises(OSError):
            os.fstat(fd)
        retry = driver.one_case_start(self.scope, first, self.start, sent)
        with self.assertRaises(driver.Refused):
            self.enterContext(retry)
        with driver.one_case_start(self.scope, second, self.start, sent) as reader:
            self.assertEqual(driver.read_catalog_start(os.dup(reader.fileno())), self.values[second])

    def test_direct_case_entry_refuses_before_projection_or_vendor_even_with_before_record(self):
        uid = self.scope["uid"]
        with TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            label = driver.LABELS[0]
            entry = runtime / str(uid) / "oc-g-connect-fixture-deadbeef" / "source" / driver.DRIVER
            expected_before = runtime / driver.HOME_BEFORE
            expected_before.write_text(json.dumps(self.before))
            bad_values = (None, b"", self.start, self.values[driver.LABELS[1]], b"x" * 33)
            for bad in bad_values:
                with self.subTest(length=len(bad) if bad is not None else None):
                    fd, writer = os.pipe2(os.O_CLOEXEC)
                    try:
                        if bad is not None:
                            os.write(writer, bad)
                    finally:
                        os.close(writer)
                    argv = [str(entry), "--fixture", label, "99"]
                    if bad is not None:
                        argv.append(str(fd))
                    with (
                        patch.object(driver, "USER_RUNTIME", runtime),
                        patch.object(driver, "CAPSULE", runtime),
                        patch.object(driver, "__file__", str(entry)),
                        patch.object(driver.sys, "argv", argv),
                        patch.object(driver, "isolated"),
                        patch.object(driver, "verify_start_parent"),
                        patch.object(driver, "guest", return_value={}),
                        patch.object(driver, "home_evidence_scope", return_value=self.scope),
                        patch.object(driver, "proof_file", side_effect=lambda path: json.loads(path.read_bytes())),
                        patch.object(driver, "read_descriptor") as projection,
                        patch.object(driver, "case_paths") as paths,
                        patch.object(driver, "run_connect") as vendor,
                        patch("builtins.print") as output,
                    ):
                        try:
                            self.assertEqual(driver.main(), 1)
                        finally:
                            if bad is None:
                                os.close(fd)
                    if bad is not None:
                        with self.assertRaises(OSError):
                            os.fstat(fd)
                    projection.assert_not_called()
                    paths.assert_not_called()
                    vendor.assert_not_called()
                    output.assert_called_once_with("Offline Google fixture refused before enrollment.",
                                                   file=sys.stderr)

    def test_fresh_case_descriptor_reaches_one_synthetic_child_then_closes_before_vendor(self):
        label = driver.LABELS[0]
        payload_id = sha256(self.values[label]).hexdigest()
        vendor = (
            "import os,sys; fd=int(sys.argv[1]); "
            "assert not os.path.exists('/proc/self/fd/'+str(fd)); print('vendor fixture closed')"
        )
        fixture = (
            "import hashlib, os, subprocess, sys; "
            "from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
            "from google_connect_driver import read_catalog_start; "
            "value=read_catalog_start(int(sys.argv[2])); "
            "assert hashlib.sha256(value).hexdigest()==sys.argv[3]; "
            "assert value not in Path('/proc/self/cmdline').read_bytes(); "
            "assert value not in Path('/proc/self/environ').read_bytes(); "
            "result=subprocess.check_output([sys.executable,'-IBS','-c',sys.argv[4],sys.argv[2]],"
            "close_fds=False, env={'PATH':'/usr/bin:/bin'}); sys.stdout.buffer.write(result)"
        )
        with controller.start_pipe(self.start) as original, driver.one_case_start(
            self.scope, label, self.start, set(),
        ) as case:
            fd = case.fileno()
            result = subprocess.run(
                (sys.executable, "-IBS", "-c", fixture, str(Path(__file__).parent), str(fd), payload_id, vendor),
                stdin=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"}, pass_fds=(fd,),
                capture_output=True, timeout=5, check=True,
            )
            self.assertFalse(os.get_inheritable(original.fileno()))
        self.assertEqual(result.stdout, b"vendor fixture closed\n")
        self.assertEqual(result.stderr, b"")
        self.assertNotIn(self.start, result.stdout)
        self.assertNotIn(self.values[label], result.stdout)


class CaseCustodyTest(unittest.TestCase):
    def setUp(self):
        self.uid = os.getuid()
        self.gid = max(1, os.getgid())
        self.user = SimpleNamespace(pw_uid=self.uid, pw_gid=self.gid)
        self.directory = Path(self.enterContext(TemporaryDirectory()))
        self.runtime = self.directory / str(self.uid)
        self.runtime.mkdir(mode=0o700)
        self.enterContext(patch.object(driver, "USER_RUNTIME", self.directory))

    def allocate_as_owner(self, *names):
        # These mocks model the independently checked identity of the real local UID.
        previous = os.umask(0)
        try:
            with patch.object(driver, "account", return_value=self.user), \
                    patch.object(driver.os, "getresuid", return_value=(self.uid,) * 3), \
                    patch.object(driver.os, "getresgid", return_value=(self.gid,) * 3), \
                    patch.object(driver.os, "getgroups", return_value=[]), \
                    patch.object(driver, "token_hex", side_effect=names):
                return driver.allocate_cases()
        finally:
            os.umask(previous)

    def test_allocator_accepts_only_exact_drop_before_accessing_runtime(self):
        user = SimpleNamespace(pw_uid=1000, pw_gid=1001)
        for uids, gids, groups in (
            ((0, 0, 0), (1001,) * 3, []),
            ((1000, 1000, 0), (1001,) * 3, []),
            ((1000,) * 3, (1001, 1001, 0), []),
            ((1000,) * 3, (1001,) * 3, [1001]),
            ((1002,) * 3, (1001,) * 3, []),
        ):
            with self.subTest(uids=uids, gids=gids, groups=groups), \
                    patch.object(driver, "account", return_value=user), \
                    patch.object(driver, "runtime_directory") as runtime, \
                    patch.object(driver.os, "getresuid", return_value=uids), \
                    patch.object(driver.os, "getresgid", return_value=gids), \
                    patch.object(driver.os, "getgroups", return_value=groups):
                with self.assertRaises(driver.Refused):
                    driver.allocate_cases()
                runtime.assert_not_called()

    @unittest.skipIf(os.getuid() == 0, "inert allocator positives require an unprivileged test owner")
    def test_allocated_levels_are_anchored_and_collision_preserves_prior_cases(self):
        records = self.allocate_as_owner("01234567", "89abcdef", "aaaaaaaa")
        self.assertEqual(set(records), set(driver.LABELS))
        for label, allocation in records.items():
            seal = {"uid": self.uid, "cases": {label: {**allocation, "config": "0" * 64}}}
            with driver.case_paths(seal, label, pristine=True) as (case, home, sandbox):
                self.assertEqual(case.parent, self.runtime)
                for path, field in ((case, "root_id"), (home, "home_id"), (sandbox, "sandbox_id")):
                    self.assertEqual(driver.identity(path.stat()), allocation[field])
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        with self.assertRaises(FileExistsError):
            self.allocate_as_owner("01234567")
        self.assertEqual(len(list(self.runtime.iterdir())), 3)

    @unittest.skipIf(os.getuid() == 0, "inert allocator positives require an unprivileged test owner")
    def test_each_swapped_or_unexpected_level_is_rejected(self):
        for index, level in enumerate((".", "home", "home/opencode-sandbox")):
            with self.subTest(level=level):
                records = self.allocate_as_owner(f"{3 * index + 1:08x}", f"{3 * index + 2:08x}", f"{3 * index + 3:08x}")
                label = driver.LABELS[0]
                record = {**records[label], "config": "0" * 64}
                seal = {"uid": self.uid, "cases": {label: record}}
                path = Path(record["case"]) / level
                extra = path / "unexpected"
                extra.touch()
                unexpected = driver.case_paths(seal, label, pristine=True)
                with self.assertRaises(driver.Refused):
                    self.enterContext(unexpected)
                extra.unlink()
                original = path.with_name(path.name + "-old")
                path.rename(original)
                path.symlink_to(original)
                symlink = driver.case_paths(seal, label, pristine=True)
                with self.assertRaises(driver.Refused):
                    self.enterContext(symlink)
                path.unlink()
                path.mkdir(mode=0o700)
                replacement = driver.case_paths(seal, label, pristine=True)
                with self.assertRaises(driver.Refused):
                    self.enterContext(replacement)

    def test_root_does_not_allocate_or_adopt_case_on_raw_allocator_failure(self):
        allocator = Mock(side_effect=driver.Refused())
        capsule = self.directory / "capsule"
        capsule.mkdir()
        with patch.object(driver, "CAPSULE", capsule), patch.object(driver, "account", return_value=self.user), \
                patch.object(driver, "topology", return_value="boot"), patch.object(driver, "root_host"), \
                patch.object(driver, "firewall", return_value="hash"), patch.object(driver, "source_inventory"), \
                patch.object(driver, "vendor_pair"), patch.object(driver, "home_snapshot"), \
                patch.object(driver.os, "getuid", return_value=0), patch.object(driver.os, "geteuid", return_value=0), \
                patch.object(driver.os, "chown") as chown, patch.object(driver.os, "mkdir") as mkdir:
            with self.assertRaises(driver.Refused):
                driver.install_seal("1" * 40, allocator)
        allocator.assert_called_once_with()
        chown.assert_not_called()
        mkdir.assert_not_called()
        self.assertEqual(list(capsule.iterdir()), [])

    @unittest.skipIf(os.getuid() == 0, "inert allocator positives require an unprivileged test owner")
    def test_root_revalidates_all_cases_after_projection_and_before_seal(self):
        records = self.allocate_as_owner("01234567", "89abcdef", "aaaaaaaa")
        capsule, source = self.directory / "capsule", self.directory / "source"
        capsule.mkdir()
        leaf = source / driver.CONFIG
        leaf.parent.mkdir(parents=True)
        leaf.write_bytes(Path(driver.CONFIG).read_bytes())
        renamed = False

        def publish(path, payload):
            nonlocal renamed
            path.write_bytes(payload)
            if not renamed:
                case = Path(records[driver.LABELS[-1]]["case"])
                sandbox = case / "home/opencode-sandbox"
                sandbox.rename(sandbox.with_name("retained"))
                sandbox.mkdir(mode=0o700)
                renamed = True

        with patch.object(driver, "CAPSULE", capsule), patch.object(driver, "SOURCE", source), \
                patch.object(driver, "account", return_value=self.user), patch.object(driver, "root_host"), \
                patch.object(driver, "topology", return_value="00000000-0000-0000-0000-000000000001"), \
                patch.object(driver, "firewall", return_value="4" * 64), \
                patch.object(driver, "source_inventory", return_value=dict.fromkeys(driver.SOURCE_FILES, "5" * 64)), \
                patch.object(driver, "vendor_pair"), patch.object(driver, "home_snapshot"), \
                patch.object(driver.os, "getuid", return_value=0), patch.object(driver.os, "geteuid", return_value=0), \
                patch.object(driver.os, "chown") as chown, patch.object(driver, "write_protected", side_effect=publish):
            with self.assertRaises(driver.Refused):
                driver.install_seal("1" * 40, lambda: records)
        self.assertTrue(renamed)
        chown.assert_not_called()
        self.assertFalse((capsule / "seal.json").exists())

    def test_failed_exec_never_falls_back_to_root_and_existing_seal_is_refused(self):
        argv = ("fixture-allocator",)
        with patch.object(controller.subprocess, "Popen", side_effect=PermissionError()) as start:
            with self.assertRaises(PermissionError):
                controller.bounded_run(argv, seconds=10, limit=20, run_as=(1000, 1001))
        options = start.call_args.kwargs
        self.assertEqual(options["user"], 1000)
        self.assertEqual(options["group"], 1001)
        self.assertEqual(options["extra_groups"], ())
        self.assertTrue(options["close_fds"])
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertEqual(start.call_count, 1)

        user = SimpleNamespace(pw_uid=1000, pw_gid=1001, pw_name=controller.ACCOUNT, pw_dir=controller.HOME)
        hooks = {"absent": Mock(return_value=False), "install_seal": Mock()}
        with patch.object(controller, "pinned_driver", return_value=(hooks | {
                    "HOME_BEFORE_STAGE": "stage", "HOME_BEFORE": "before",
                    "HOME_RESULT": "after", "NATIVE_RESULT": "native",
                }, {})), patch.object(controller, "deployment_binding"), \
                patch.object(controller.pwd, "getpwnam", return_value=user), \
                patch.object(controller, "observe_run") as observe:
            with self.assertRaises(controller.ControllerRefused):
                controller.run_controller("pin", "binding")
            hooks["install_seal"].assert_not_called()
            observe.assert_not_called()

    def test_unprivileged_cannot_enter_root_install_or_choose_arbitrary_case_path(self):
        allocator = Mock()
        with patch.object(driver.os, "getuid", return_value=1000), patch.object(driver.os, "geteuid", return_value=1000):
            with self.assertRaises(driver.Refused):
                driver.install_seal("1" * 40, allocator)
        allocator.assert_not_called()
        with driver.runtime_directory(self.uid) as fd:
            outside = driver.pinned_case_tree(fd, "../outside", self.uid, create=True)
            with self.assertRaises(driver.Refused):
                self.enterContext(outside)

    def test_root_launcher_rejects_bad_or_blocked_allocator_results(self):
        user = SimpleNamespace(pw_uid=1000, pw_gid=1001)
        expected = (controller.PYTHON, "-IBS", str(controller.CONTROLLER), "--allocate-cases", "pin", "binding")
        value = b"s" * controller.START_BYTES
        for failure in ((1, b"{}"), (0, b"["), (0, b"[]"), subprocess.TimeoutExpired(expected, 10)):
            with self.subTest(failure=failure), patch.object(controller, "bounded_run", side_effect=[failure]) as child:
                with self.assertRaises((ValueError, controller.ControllerRefused, subprocess.TimeoutExpired)):
                    controller.allocate_case_process("pin", "binding", user, value)
                child.assert_called_once()
                self.assertEqual(child.call_args.args, (expected,))
                self.assertEqual(child.call_args.kwargs["run_as"], (1000, 1001))
                self.assertTrue(child.call_args.kwargs["stdin"].closed)
        with patch.object(controller, "bounded_run", return_value=(0, json.dumps({"fixture": {}}).encode())):
            self.assertEqual(controller.allocate_case_process("pin", "binding", user, value), {"fixture": {}})


if __name__ == "__main__":
    unittest.main()
