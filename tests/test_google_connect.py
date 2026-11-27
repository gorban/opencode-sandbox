"""Exercise attended enrollment boundaries with local fixtures only."""

from contextlib import contextmanager, nullcontext, redirect_stderr
import errno
from io import StringIO
import os
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import RLock
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oc_google import connect
from oc_google.native_service import NativeInvocation


class TerminalOwnerTest(unittest.TestCase):
    def setUp(self):
        self.identity = self.enterContext(patch.object(connect._TerminalOwner, "_identify", return_value=(1, 2)))
        self.owner = connect._TerminalOwner(7)
        self.enterContext(patch.object(self.owner, "_ready", return_value=True))

    def test_short_offer_is_single_shot_and_revokes(self):
        with patch.object(connect, "_libc_write", return_value=1) as write:
            with self.assertRaises(connect.ConnectError):
                self.owner.offer(SimpleNamespace(url="https://example.invalid/synthetic"))
            self.assertFalse(self.owner.authorized())
        expected = b"Google sign-in link for this workstation\nhttps://example.invalid/synthetic\n"
        write.assert_called_once_with(7, expected, len(expected))

    def test_lost_foreground_stays_revoked_after_return(self):
        self.identity.return_value = (1, 3)
        self.assertFalse(self.owner.authorized())
        self.identity.return_value = (1, 2)
        self.assertFalse(self.owner.authorized())

    def test_job_control_signal_during_offer_revokes_after_write(self):
        def signal_and_write(_fd, data, _length):
            self.owner.mark_signal(signal.SIGCONT, None)
            return len(data)

        with patch.object(connect, "_libc_write", side_effect=signal_and_write) as write:
            with self.assertRaises(connect.ConnectError):
                self.owner.offer(SimpleNamespace(url="https://example.invalid/synthetic"))
            self.assertFalse(self.owner.authorized())
        write.assert_called_once()

    def test_queued_bytes_are_flushed_before_bounded_consent_read(self):
        calls = Mock()
        calls.read.side_effect = [b"y", b"\n"]
        with patch.object(connect.termios, "tcflush", calls.flush), patch.object(self.owner, "write_once", calls.notice), \
                patch.object(connect.os, "read", calls.read):
            self.assertTrue(self.owner.consent("fixture"))
        self.assertEqual([item[0] for item in calls.mock_calls], ["flush", "notice", "read", "read"])
        text = calls.notice.call_args.args[0]
        for wording in ("cloud-platform", "Broad access", "userinfo.email", "aicode", "offline refresh", "zero inference"):
            self.assertIn(wording, text)


class TerminalDescriptorTest(unittest.TestCase):
    def test_tty_identity_requires_readable_input_and_writable_output(self):
        def tty_ioctl(fd, operation, _buffer):
            if operation == connect._TIOCGPTN:
                raise OSError(errno.ENOTTY, "fixture terminal slave")
            return b"tty1"

        for input_mode, output_mode in ((os.O_WRONLY, os.O_RDWR), (os.O_RDWR, os.O_RDONLY)):
            with self.subTest(input_mode=input_mode, output_mode=output_mode), \
                    patch.object(connect, "terminal", return_value=(1, 2, 3, 4, 5)), \
                    patch.object(connect, "ioctl", side_effect=tty_ioctl), \
                    patch.object(connect.os, "tcgetpgrp", return_value=6), \
                    patch.object(connect.os, "getpgrp", return_value=6), \
                    patch.object(connect.os, "getsid", return_value=4), \
                    patch.object(connect, "fcntl", create=True,
                                 side_effect=lambda fd, _operation: (input_mode, output_mode)[fd]):
                with self.assertRaisesRegex(connect.ConnectError, "readable input and writable output"):
                    connect._TerminalOwner(7)


class ConnectTest(unittest.TestCase):
    def test_public_google_commands_redact_missing_config_before_any_resource(self):
        home = Path(self.enterContext(TemporaryDirectory(prefix="oc-google-missing-config-")))
        origin = Path(__file__).resolve().parents[1]
        source = home / "source"
        source.mkdir(mode=0o700)
        for name in ("oc-sandbox", "oc-google.py"):
            shutil.copy2(origin / name, source / name)
        for package in ("oc_google", "oc_orchestrator", "oc_providers"):
            shutil.copytree(origin / package, source / package, ignore=shutil.ignore_patterns("__pycache__"))

        config = source / "oc_providers/config.py"
        text = config.read_text(encoding="utf-8")
        start = text.index("def _account_home() -> Path:")
        stop = text.index("\n\ndef default_config_dir()", start)
        text = text[:start] + f"def _account_home() -> Path:\n    return Path({str(home)!r})" + text[stop:]
        config.write_text(text.replace('env_home = os.environ.get("HOME")', f"env_home = {str(home)!r}"), encoding="utf-8")

        # Fail visibly if the copied command reaches the terminal despite absent config.
        connect_copy = source / "oc_google/connect.py"
        with connect_copy.open("a", encoding="utf-8") as stream:
            stream.write('\ndef _attended_owner():\n    raise AssertionError("unexpected terminal setup")\n')
        messages = {
            "connect": b"Enable the Google subscription registration without a CLI override in providers.toml.",
            "shell": b"Enable a Google subscription registration in providers.toml first.",
        }
        for verb, message in messages.items():
            with self.subTest(verb=verb):
                result = subprocess.run([str(source / "oc-sandbox"), "google", verb, "fixture"], cwd=source,
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"oc-sandbox google: " + message + b"\n")
        self.assertEqual(list(home.iterdir()), [source])

    def test_cli_path_is_refused_before_terminal_or_resources(self):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path="/path/ignored")
        with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                patch.object(connect, "_attended_owner") as attended, patch.object(connect, "RegistrationJournal") as journal:
            with self.assertRaisesRegex(connect.ConnectError, "without a CLI override"):
                connect.connect_for("fixture")
        attended.assert_not_called()
        journal.assert_not_called()

    def test_success_follows_initial_and_cold_cleanups_and_uses_compiled_exchange(self):
        events = []
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        owner = SimpleNamespace(fence=RLock(), deadline=float("inf"), authorized=lambda: True, offer=Mock(), consent=lambda _: True,
                                write_once=lambda _: events.append("reported"))

        @contextmanager
        def place(parent, label, cold, owner):
            yield cold
            events.append(("clean", cold))

        enrollment = object()
        with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                patch.object(connect, "_attended_owner", return_value=nullcontext(owner)), \
                patch.object(connect, "_preflight"), patch.object(connect, "_private_runtime", place), \
                patch.object(connect, "_artifacts", return_value=nullcontext(1)), \
                patch.object(connect, "_prepare_runtime", side_effect=lambda custody, _: custody), \
                patch.object(connect, "enroll_metadata", return_value=enrollment) as enroll, \
                patch.object(connect, "reopen_metadata", side_effect=lambda *a, **k: events.append("cold")) as reopen:
            self.assertEqual(connect.connect_for("fixture"), 0)
        self.assertEqual(events, [("clean", False), "cold", ("clean", True), "reported"])
        self.assertIs(enroll.call_args.kwargs["destination"], connect.exchange)
        self.assertIs(reopen.call_args.kwargs["destination"], connect.exchange)
        self.assertIs(reopen.call_args.args[1], enrollment)

    def test_invalid_label_stops_before_config(self):
        with patch.object(connect, "load_provider_config") as config:
            with self.assertRaisesRegex(connect.ConnectError, "Invalid Google registration label"):
                connect.connect_for("../../sandbox")
        config.assert_not_called()


class RuntimeCustodyTest(unittest.TestCase):
    def setUp(self):
        self.parent = Path(self.enterContext(TemporaryDirectory()))
        self.owner = Mock(authorized=Mock(return_value=True))
        self.unit = "oc-google-acp-" + "1" * 24 + ".service"
        self.identity = NativeInvocation(self.unit, "2" * 32, b"/fixture", 123)

    def test_unknown_launch_retains_root_and_exact_durable_launch_record(self):
        record = Mock()
        with self.assertRaisesRegex(connect.CustodyUnconfirmed, "requires inspection"):
            with connect._private_runtime(self.parent, "fixture", False, self.owner) as custody:
                root = custody.root
                custody.bind(record)
                custody.before_spawn(self.unit)
        self.assertTrue(root.is_dir())
        event, data = record.call_args.args
        self.assertEqual((event, data["label"], data["root"], data["unit"], data["inode"]),
                         ("launch", "fixture", str(root), self.unit, root.stat().st_ino))

    def test_verified_retirement_permits_exact_runtime_and_private_key_cleanup(self):
        record = Mock()
        with connect._private_runtime(self.parent, "fixture", False, self.owner) as custody:
            root = custody.root
            (root / "local.key").touch(mode=0o600)
            custody.bind(record)
            custody.before_spawn(self.unit)
            custody.attest(self.identity)
            custody.retire(self.identity)
        self.assertEqual([item.args[0] for item in record.call_args_list], ["launch", "attested", "retired"])
        self.assertFalse(root.exists())
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_runtime_cleanup_failure_preserves_active_error_and_cause(self):
        cause = ValueError("fixture original cause")
        primary = connect.ConnectError("Google sign-in cancelled.")
        storage = OSError("fixture cleanup failed")

        with patch.object(connect._RuntimeCustody, "cleanup", side_effect=storage):
            with self.assertRaises(connect.ConnectError) as caught:
                with connect._private_runtime(self.parent, "fixture", False, self.owner) as custody:
                    root = custody.root
                    raise primary from cause
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        uncertainty, = primary.cleanup_uncertainties
        self.assertIsInstance(uncertainty, connect.CustodyUnconfirmed)
        self.assertIs(uncertainty.__cause__, storage)
        self.assertTrue(root.is_dir())

    def test_public_error_projection_keeps_safe_primary_and_inspection_notice(self):
        root = Path(__file__).resolve().parents[1]
        main = runpy.run_path(str(root / "oc-google.py"))["main"]

        def cancelled(_label):
            with connect._private_runtime(self.parent, "fixture", False, self.owner) as custody:
                custody.bind(Mock())
                custody.before_spawn(self.unit)
                raise connect.ConnectError("Google sign-in cancelled.")

        output = StringIO()
        with patch.dict(main.__globals__, verify_sources=Mock()), \
                patch.object(sys, "argv", ["oc-google.py", "connect", "fixture"]), \
                patch.object(connect, "connect_for", side_effect=cancelled), redirect_stderr(output):
            self.assertEqual(main(), 1)
        self.assertEqual(output.getvalue().splitlines(), [
            "oc-sandbox google: Google sign-in cancelled.",
            "oc-sandbox google: Google enrollment cleanup requires inspection.",
        ])
        self.assertEqual(len(list(self.parent.iterdir())), 1)

    def test_cold_disappearance_with_quarantine_requires_inspection(self):
        with self.assertRaisesRegex(connect.CustodyUnconfirmed, "requires inspection"):
            with connect._private_runtime(self.parent, "fixture", True, self.owner) as custody:
                quarantine = self.parent / custody.quarantine
                os.rename(custody.root, quarantine)
        self.assertTrue(quarantine.is_dir())
