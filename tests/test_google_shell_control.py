"""Exercise the host-only control exchange without Podman or a provider."""

from contextlib import ExitStack, nullcontext
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import runpy
import select
import socket
import subprocess
import sys
import tempfile
import termios
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oc_google import control, shell
from oc_orchestrator import relay, runtime


TARGET = SimpleNamespace(label="personal", model="gemini-pro", system_digest="a" * 64)
WORKER, RELAY = "b" * 64, "c" * 64
OTHER_TTY = (0, 0, 0, 0, "0")


class SourceInventoryTests(unittest.TestCase):
    def test_only_inventoried_source_can_satisfy_its_import_name(self):
        entry = Path(__file__).resolve().parents[1] / "oc-google.py"
        verify_package = runpy.run_path(str(entry))["verify_package"]
        with tempfile.TemporaryDirectory() as scratch:
            package = Path(scratch)
            (package / "route.py").touch(mode=0o600)
            verify_package(package, ("route.py",))
            for alternate in ("route", "route.so", "route.pyc"):
                path = package / alternate
                path.mkdir()
                with self.assertRaisesRegex(ValueError, "unverified Google session import"):
                    verify_package(package, ("route.py",))
                path.rmdir()


def controlling_terminal():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY)


class ShellControlTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.parent = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="gs-")))
        self.stack.enter_context(patch.object(control, "scratch_parent", return_value=self.parent))

    def client(self, run_id, script=None):
        master, slave = pty.openpty()
        self.stack.callback(os.close, master)
        program = script or "print('ready', flush=True); input(); raise SystemExit(control.arm(sys.argv[2]))"
        code = (
            "from pathlib import Path; import sys; from oc_google import control; "
            "control.scratch_parent = lambda: Path(sys.argv[1]); " + program
        )
        try:
            child = subprocess.Popen([sys.executable, "-Bc", code, str(self.parent), run_id],
                                     stdin=slave, stdout=slave, stderr=slave, preexec_fn=controlling_terminal)
        finally:
            os.close(slave)

        def clean_child():
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)

        self.stack.callback(clean_child)
        return child, master

    def until(self, master, expected):
        result = bytearray()
        deadline = time.monotonic() + 5
        while expected not in result and (remaining := deadline - time.monotonic()) > 0:
            if not select.select([master], [], [], remaining)[0]:
                break
            try:
                result.extend(os.read(master, 4096))
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                break
        self.assertIn(expected, result)
        return result

    def arm_exchange(self, text=b"arm\n", repeat=False, readiness_failure=False):
        with control.owned_run() as (path, _, directory):
            child, master = self.client(path.name)
            self.until(master, b"ready")
            with control.ArmControl(directory, path.name, WORKER, RELAY, TARGET, OTHER_TTY) as server:
                # The server is polled like the shell owner. A short child-controlled
                # thread supplies the terminal text only after the detail is visible.
                output = []

                def answer():
                    try:
                        prompt = self.until(master, b"Type arm to authorize this one turn: ")
                        self.assertIn(b"personal", prompt)
                        self.assertIn(b"gemini-pro", prompt)
                        self.assertIn(b"Reply with exactly: ok", prompt)
                        self.assertIn(b"Account: current workstation Antigravity login", prompt)
                        os.write(master, text)
                        output.append("ok")
                    except AssertionError as error:
                        output.append(error)

                responder = threading.Thread(target=answer, daemon=True)
                responder.start()
                os.write(master, b"go\n")
                activation = []
                end = time.monotonic() + 5
                def activate(confirmed, commit, ready):
                    activation.append(confirmed())
                    commit()
                    if readiness_failure:
                        raise shell.Failure("relay startup failed")
                    ready()

                def advance():
                    while time.monotonic() < end and child.poll() is None and not server.consumed:
                        server.step(end, lambda: True, activate)

                if readiness_failure:
                    with self.assertRaisesRegex(shell.Failure, "relay startup failed"):
                        advance()
                else:
                    advance()
                responder.join(6)
                self.assertEqual(output, ["ok"])
                if readiness_failure:
                    transcript = self.until(master, b"Google shell arm committed, but relay readiness was not confirmed")
                    self.assertNotIn(b"Google shell armed for one turn.", transcript)
                    self.assertNotEqual(child.wait(timeout=3), 0)
                elif text == b"arm\n":
                    self.until(master, b"Google shell armed for one turn.")
                    self.assertEqual(child.wait(timeout=3), 0)
                    self.assertEqual(activation, [True])
                else:
                    self.until(master, b"Google shell arm confirmation refused")
                    self.assertNotEqual(child.wait(timeout=3), 0)
                    self.assertEqual(activation, [])
                if repeat:
                    duplicate, master = self.client(path.name)
                    self.until(master, b"ready")
                    os.write(master, b"go\n")
                    self.until(master, b"Google shell arm is unavailable")
                    self.assertNotEqual(duplicate.wait(timeout=3), 0)

    def test_distinct_foreground_terminal_confirms_once(self):
        self.arm_exchange(repeat=True)

    def test_committed_arm_will_not_report_success_if_relay_start_fails(self):
        self.arm_exchange(readiness_failure=True)

    def test_wrong_terminal_input_does_not_activate(self):
        self.arm_exchange(text=b"wrong\n")

    def test_shell_terminal_cannot_arm_itself(self):
        with control.owned_run() as (path, _, directory):
            child, master = self.client(path.name)
            self.until(master, b"ready")
            with control.ArmControl(directory, path.name, WORKER, RELAY, TARGET, control.terminal(child.pid)) as server:
                end = time.monotonic() + 5
                os.write(master, b"go\n")
                while time.monotonic() < end and child.poll() is None:
                    server.step(end, lambda: True, lambda *_: self.fail("same terminal armed"))
                self.until(master, b"invalid or expired Google shell arm offer")
                self.assertNotEqual(child.wait(timeout=3), 0)
                self.assertFalse(server.consumed)

    def test_stale_run_id_and_swapped_incarnation_are_rejected(self):
        run = "1" * 32
        data = {"run": run, "nonce": "2" * 64, "label": TARGET.label, "model": TARGET.model,
                "worker": WORKER, "relay": RELAY, "prompt": control.PROMPT}
        self.assertEqual(control.offer_for(control.encode(data), run), data)
        for replacement in ({"run": "3" * 32}, {"worker": RELAY}, {"model": "alternate-provider"}):
            with self.subTest(replacement=replacement), self.assertRaises(control.ControlError):
                control.offer_for(control.encode(data | replacement), run)

    def test_symlink_socket_is_rejected_before_connect(self):
        with control.owned_run() as (path, _, _), socket.socket(socket.AF_UNIX) as unrelated:
            unrelated.bind(str(self.parent / "unrelated"))
            (path / control.CONTROL_SOCKET).symlink_to(self.parent / "unrelated")
            child, master = self.client(path.name)
            self.until(master, b"ready")
            os.write(master, b"go\n")
            self.until(master, b"unsafe Google shell arm socket")
            self.assertNotEqual(child.wait(timeout=3), 0)

    def test_active_or_retained_placement_blocks_reuse(self):
        with control.owned_run() as (path, _, _):
            with self.assertRaisesRegex(control.ControlError, "already owns"):
                with control.owned_run():
                    self.fail("parallel placement became available")
        with self.assertRaisesRegex(control.ControlError, "needs inspection"):
            with control.owned_run():
                self.fail("retained placement became available")
        path.rmdir()
        with control.owned_run():
            pass

    def test_project_is_one_local_text_only_catalog(self):
        config = shell.project(TARGET, "one-use-token")
        self.assertEqual(config["model"], "google--personal/gemini-pro")
        self.assertEqual(config["plugins"], ["-opencode.tool.*"])
        self.assertEqual(set(config["providers"]), {"google--personal"})
        provider = config["providers"]["google--personal"]
        self.assertEqual(provider["settings"], {"baseURL": "http://127.0.0.1:8401/v1", "apiKey": "one-use-token"})
        self.assertEqual(provider["models"]["gemini-pro"]["capabilities"],
                         {"tools": False, "input": ["text"], "output": ["text"]})
        self.assertTrue(all(rule["effect"] == "deny" for rule in config["permissions"]))

    def test_pair_uses_exec_only_for_private_bun_scratch(self):
        placement = Mock(root=self.parent)
        placement.create.side_effect = [WORKER, RELAY]
        with patch.object(shell, "podman", return_value=SimpleNamespace(stdout=b"opencode v2.3.0")):
            self.assertEqual(shell.create_pair(placement), (WORKER, RELAY))
        worker, relay = placement.create.call_args_list
        self.assertEqual(worker.args[2], "none")
        self.assertEqual(worker.args[5]["TMPDIR"], "/job-tmp")
        self.assertEqual(worker.args[6], ("/job-home", "/job-tmp", "/workspace"))
        self.assertEqual(worker.kwargs, {"exec_tmpfs": ("/job-tmp",)})
        self.assertEqual(relay.args[2], f"container:{WORKER}")
        self.assertEqual(relay.kwargs, {})

    def test_detached_owner_observes_abrupt_launcher_loss(self):
        script = """
import time
from types import SimpleNamespace
from oc_google import shell

def owner(target, lifeline, terminal):
    print("owner ready", flush=True)
    while lifeline.active():
        time.sleep(.02)
    Path(sys.argv[1], "retired").touch()
    return 0

shell.run_owned = owner
shell.run_shell(SimpleNamespace(label="personal", model="gemini-pro", system_digest="a" * 64))
"""
        launcher, master = self.client("unused", script)
        self.until(master, b"owner ready")
        launcher.kill()
        launcher.wait(timeout=3)
        deadline = time.monotonic() + 5
        marker = self.parent / "retired"
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertTrue(marker.is_file())

    def test_arm_peer_loss_during_ingress_readiness_refuses_ack(self):
        with control.owned_run() as (path, _, directory):
            child, master = self.client(path.name)
            self.until(master, b"ready")
            with control.ArmControl(directory, path.name, WORKER, RELAY, TARGET, OTHER_TTY) as server:
                def answer():
                    self.until(master, b"Type arm to authorize this one turn: ")
                    os.write(master, b"arm\n")

                def lose_peer(confirmed, commit, ready):
                    self.assertTrue(confirmed())
                    commit()
                    child.kill()
                    child.wait(timeout=3)
                    self.assertFalse(confirmed())
                    ready()

                responder = threading.Thread(target=answer, daemon=True)
                responder.start()
                os.write(master, b"go\n")
                deadline = time.monotonic() + 5
                with self.assertRaisesRegex(control.ControlError, "terminal left during relay startup"):
                    while time.monotonic() < deadline and not server.consumed:
                        server.step(deadline, lambda: True, lose_peer)
                responder.join(5)
                self.assertFalse(responder.is_alive())

    def test_relay_does_not_listen_without_owner_release(self):
        ingress = Mock()
        inlet = Mock()
        outlet = Mock()

        def pending_arm(_):
            ingress.bind.assert_called_once_with(("127.0.0.1", relay.PORT))
            ingress.listen.assert_not_called()
            outlet.flush.assert_called_once_with()
            return b""

        inlet.read.side_effect = pending_arm
        with (patch.object(relay.sys, "argv", ["relay.py", "--owner-pipe"]),
              patch.object(relay.sys, "stdin", SimpleNamespace(buffer=inlet)),
              patch.object(relay.sys, "stdout", SimpleNamespace(buffer=outlet)),
              patch.object(relay, "Path", return_value=self.parent),
              patch.object(relay.socket, "socket", return_value=nullcontext(ingress))):
            (self.parent / "proof").write_bytes(b"p" * 32)
            with self.assertRaises(SystemExit):
                relay.main()
        ingress.listen.assert_not_called()

    def test_unconfirmed_retirement_retains_placement_on_clean_adapter_exit(self):
        with control.owned_run() as (path, _, directory):
            for confirmed in (False, True):
                with self.subTest(confirmed=confirmed):
                    placement = shell.ShellPlacement(path, directory, None)
                    session = SimpleNamespace(retirement_confirmed=confirmed)
                    target = SimpleNamespace(open_session=lambda _: nullcontext(session))
                    with ExitStack() as peers:
                        self.assertIs(shell.open_peer(placement, peers, target, lambda: False), session)
                    self.assertIs(placement.peer_unconfirmed, not confirmed)

    def test_private_placement_links_native_cleanup_receipt_before_peer_starts(self):
        with control.owned_run() as (path, _, directory):
            placement = shell.ShellPlacement(path, directory, None)
            native = path / "native"
            session = SimpleNamespace(retirement_confirmed=False)

            def open_session(_, *, record_root):
                record_root(native)
                receipt = json.loads((path / "placement.json").read_text())
                self.assertEqual(receipt["native_cleanup_root"], str(native))
                return nullcontext(session)

            target = SimpleNamespace(native_cleanup_record=True, open_session=open_session)
            with ExitStack() as peers:
                self.assertIs(shell.open_peer(placement, peers, target, lambda: False), session)
            self.assertTrue(placement.peer_unconfirmed)

    def test_failed_precreate_receipt_does_not_hide_prior_owned_worker(self):
        with control.owned_run() as (path, _, directory):
            placement = shell.ShellPlacement(path, directory, None)
            placement.attempted = True
            placement.ids["open-code"] = WORKER
            with (patch.object(placement, "record", side_effect=OSError("journal write failed")),
                  self.assertRaises(OSError)):
                placement.create("relay")
            self.assertTrue(placement.attempted)
            self.assertEqual(placement.ids, {"open-code": WORKER})

    def test_cleanup_persists_recovered_exact_id_before_removal(self):
        with control.owned_run() as (path, _, directory):
            placement = shell.ShellPlacement(path, directory, None)
            placement.attempted = placement.create_unconfirmed = True

            def host(command, *args, **_):
                if command == "rm":
                    self.assertEqual(args[-1], RELAY)
                    self.assertEqual(json.loads((path / "placement.json").read_text())["ids"], {"relay": RELAY})
                    raise runtime.Failure("cleanup removal failed")
                name = placement.names["relay"]
                return SimpleNamespace(stdout=f"{RELAY} {name}\n".encode())

            with (patch.object(placement, "identity") as identity,
                  patch.object(runtime, "podman", side_effect=host),
                  self.assertRaisesRegex(runtime.Failure, "cleanup left a container")):
                placement.close()
            identity.assert_called_once_with(RELAY, "relay")
            self.assertEqual(json.loads((path / "placement.json").read_text())["ids"], {"relay": RELAY})

    def test_tmpfs_defaults_to_noexec_and_rejects_outside_exec_path(self):
        placement = runtime.Placement(self.parent, Mock())
        image = runtime.OPEN_CODE
        args = ("open-code", image, "none", self.parent, "/cfg", {}, ("/workspace",), "/bin/sh")
        with (patch.object(runtime, "inspect", return_value={"Id": image, "Config": {"Env": []}}) as inspect,
              patch.object(runtime, "podman", return_value=SimpleNamespace(stdout=WORKER.encode())) as host,
              patch.object(placement, "identity"), patch.object(placement, "verify") as verify):
            placement.create(*args)
            self.assertIn(f"/workspace:{runtime.TMPFS},size=96m", host.call_args_list[0].args)
            self.assertEqual(verify.call_args.args[-1], {"/workspace": f"{runtime.TMPFS},size=96m"})
            inspect.reset_mock()
            host.reset_mock()
            with self.assertRaisesRegex(runtime.Failure, "outside the restricted placement"):
                placement.create(*args, exec_tmpfs=("/job-tmp",))
            inspect.assert_not_called()
            host.assert_not_called()

    def test_tmpfs_receipt_rejects_exec_or_unsafe_options_on_workspace(self):
        options = f"{runtime.TMPFS},size=96m"
        observed = f"{options},rprivate,tmpcopyup"
        accepted = {"/workspace": options}
        host = {"IpcMode": "private", "PidMode": "private", "CgroupMode": "private", "NetworkMode": "none",
                "ReadonlyRootfs": True, "AutoRemove": True, "PidsLimit": 192, "Memory": 1024**3,
                "MemorySwap": 1024**3, "SecurityOpt": ["no-new-privileges"], "Tmpfs": {"/workspace": observed}}
        data = {"HostConfig": host, "NetworkSettings": {"Networks": {"none": {}}},
                "Config": {"User": "0:0", "Env": []}, "Image": runtime.OPEN_CODE,
                "Mounts": [{"Type": "bind", "RW": False, "Source": str(self.parent), "Destination": "/cfg",
                            "Mode": "Z", "Propagation": "rprivate", "Options": ["nosuid", "nodev", "noexec"]}]}

        def verify():
            runtime.Placement.verify(data, runtime.OPEN_CODE, "none", self.parent, "/cfg", {}, accepted)

        verify()
        tampered = (observed.replace("noexec", "exec"), observed + ",suid", observed.replace("mode=0700", "mode=0777"))
        for flags in tampered:
            with self.subTest(flags=flags):
                host["Tmpfs"]["/workspace"] = flags
                with self.assertRaisesRegex(runtime.Failure, "did not match the restricted placement"):
                    verify()

    def test_cleanup_only_unlinks_known_members_and_preserves_unknown_state(self):
        with control.owned_run() as (path, parent, directory):
            placement = shell.ShellPlacement(path, directory, None)
            placement.record("initializing")
            shell.seed_run(directory, TARGET, "one-use-token", b"p" * 32)
            unknown = path / "unknown"
            unknown.write_text("blocking")
            with self.assertRaisesRegex(shell.Failure, "unexpected runtime state"):
                shell.remove_seeds(path, parent, directory)
            self.assertTrue((path / "placement.json").is_file())
            self.assertEqual(unknown.read_text(), "blocking")
            unknown.unlink()
            shell.remove_seeds(path, parent, directory)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
