"""Exercise attended enrollment boundaries with local fixtures only."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext, redirect_stderr, suppress
import errno
from io import StringIO
import os
from pathlib import Path
import pty
import runpy
import select
import shutil
import signal
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import RLock
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oc_google import auth_offer, connect, metadata_workflow, native_artifacts
from oc_google.native_service import NativeInvocation, NativeRetirementUnconfirmed
from oc_google.token_diagnostic import LoadBodyReason, PostTokenDiagnostic, PostTokenStage, TokenDiagnostic, TokenStage, scoped_post_token


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


    def test_decline_blank_timeout_or_read_race_latches_rejection(self):
        for label, chunks, ready in (
            ("decline", [b"n", b"\n"], True),
            ("blank", [b"\n"], True),
            ("timeout", [], False),
            ("read race", [BlockingIOError(errno.EAGAIN, "fixture input race")], True),
        ):
            with self.subTest(label=label):
                self.owner.cancelled = False
                with patch.object(connect.termios, "tcflush"), patch.object(self.owner, "write_once"), \
                        patch.object(self.owner, "_ready", return_value=ready), \
                        patch.object(connect.os, "read", side_effect=chunks):
                    self.assertFalse(self.owner.consent("fixture"))
                self.assertFalse(self.owner.authorized())


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

    def test_consent_refusal_precedes_runtime_openssl_and_journal(self):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        owner = Mock(consent=Mock(return_value=False))
        with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                patch.object(connect, "_attended_owner", return_value=nullcontext(owner)), \
                patch.object(connect, "_preflight"), patch.object(connect, "_private_runtime") as place, \
                patch.object(connect, "_artifacts", return_value=nullcontext(1)), \
                patch.object(connect, "verify_standalone_source", create=True) as source_check, \
                patch.object(connect, "host") as host, patch.object(connect, "RegistrationJournal") as journal:
            with self.assertRaisesRegex(connect.ConnectError, "cancelled"):
                connect.connect_for("fixture")
        source_check.assert_called_once_with(1)
        owner.consent.assert_called_once_with("fixture")
        place.assert_not_called()
        host.assert_not_called()
        journal.assert_not_called()

    def test_missing_or_untrusted_artifact_refuses_before_consent_or_effects(self):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        owner = Mock()
        for failure in ("missing", "symlink", "writable", "size"):
            with self.subTest(failure=failure), TemporaryDirectory() as path:
                source = Path(path)
                (source / "companion").write_bytes(b"fixture")
                member = source / "standalone"
                if failure == "symlink":
                    member.symlink_to(source / "companion")
                elif failure != "missing":
                    member.write_bytes(b"x" if failure == "size" else b"fixture")
                    member.chmod(0o620 if failure == "writable" else 0o600)
                source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                            patch.object(connect, "_attended_owner", return_value=nullcontext(owner)), \
                            patch.object(connect, "_preflight"), patch.object(connect, "_private_runtime") as place, \
                            patch.object(connect, "_artifacts", return_value=nullcontext(source_fd)), \
                            patch.object(native_artifacts, "_PINNED", {"standalone": (7, ""), "companion": (7, "")}), \
                            patch.object(connect, "host") as host, patch.object(connect, "RegistrationJournal") as journal:
                        with self.assertRaises(native_artifacts.NativeArtifactError):
                            connect.connect_for("fixture")
                finally:
                    os.close(source_fd)
                owner.consent.assert_not_called()
                place.assert_not_called()
                host.assert_not_called()
                journal.assert_not_called()

    def test_preflight_verifies_the_exact_host_shell_and_env_tools(self):
        def host(tool, *args, **_kwargs):
            replies = {
                "id": b"1000\n", "readlink": b"net:[123]\n",
                "stat": b"0 755\n", "test": b"",
            }
            return Mock(stdout=replies[tool])

        bridge = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with patch.object(connect.os, "getuid", return_value=1000), \
                patch.object(connect.os, "geteuid", return_value=1000), \
                patch.object(connect.os, "lstat", return_value=bridge), \
                patch.object(connect.os, "readlink", return_value="net:[123]"), \
                patch.object(connect, "check_private_directory"), patch.object(connect, "host", side_effect=host) as verify:
            connect._preflight(Path("/fixture"))
        for path in ("/usr/bin/sh", "/usr/bin/env"):
            self.assertIn(("stat", "-Lc", "%u %a", "--", path), [call.args for call in verify.call_args_list])
            self.assertIn(("test", "-x", path), [call.args for call in verify.call_args_list])

    def test_runtime_refuses_wrong_certificate_sans_or_nonprivate_tls_key(self):
        for failure in ("san", "key"):
            with self.subTest(failure=failure), TemporaryDirectory() as path:
                root = Path(path)
                key = root / "metadata-key.pem"
                key.touch(mode=0o600)
                key.chmod(0o640)
                root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                custody = SimpleNamespace(root=root, root_fd=root_fd, cold=False)
                output = (b"X509v3 Subject Alternative Name:\n DNS:oauth2.googleapis.com, DNS:cloudcode-pa.googleapis.com\n"
                          if failure == "key" else b"X509v3 Subject Alternative Name:\n DNS:other.invalid\n")
                message = "private TLS key" if failure == "key" else "certificate scope"
                try:
                    mkdir = os.mkdir
                    with patch.object(connect, "stage_standalone"), patch.object(connect, "check_private_directory"), \
                            patch.object(connect, "public_certificate"), patch.object(connect, "host", return_value=Mock(stdout=output)), \
                            patch.object(connect.os, "mkdir", wraps=mkdir) as make_directory:
                        with self.assertRaisesRegex(connect.ConnectError, message):
                            connect._prepare_runtime(custody, 1)
                    make_directory.assert_called_once_with("native", 0o700, dir_fd=root_fd)
                finally:
                    os.close(root_fd)

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
                patch.object(connect, "verify_standalone_source", create=True), \
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

    def test_keyboard_interrupt_preserves_redacted_cancellation_and_exit_code(self):
        origin = Path(__file__).resolve().parents[1]
        main = runpy.run_path(str(origin / "oc-google.py"))["main"]
        output = StringIO()
        with patch.dict(main.__globals__, verify_sources=Mock()), \
                patch.object(sys, "argv", ["oc-google.py", "connect", "fixture"]), \
                patch.object(connect, "connect_for", side_effect=KeyboardInterrupt("private fixture detail")), \
                redirect_stderr(output):
            self.assertEqual(main(), 130)
        self.assertEqual(output.getvalue(), "oc-sandbox google: Google sign-in cancelled.\n")

    def test_callback_diagnostic_uses_only_original_foreground_pty(self):
        self.assert_diagnostic_uses_original_pty(
            "callback", b"Google sign-in callback: The callback Referer header was refused.",
            b"synthetic-referer-marker",
        )

    def test_token_diagnostic_uses_only_original_foreground_pty(self):
        self.assert_diagnostic_uses_original_pty(
            "token", b"Google sign-in token reply: The token endpoint returned HTTP 400.",
            b"synthetic-token-marker",
        )

    def test_token_scope_diagnostic_uses_only_original_foreground_pty(self):
        self.assert_diagnostic_uses_original_pty(
            "scope", b"Google sign-in token reply: The token grant included an unapproved permission.",
            b"synthetic-unapproved-permission",
        )

    def test_token_diagnostic_text_covers_every_stage(self):
        self.assertEqual(set(connect._TOKEN_DETAILS), set(TokenStage))
        self.assertEqual(set(connect._POST_TOKEN_DETAILS), set(PostTokenStage))
        self.assertEqual(set(connect._LOAD_BODY_DETAILS), set(LoadBodyReason))

    def test_post_token_load_body_uses_only_original_foreground_pty(self):
        self.assert_diagnostic_uses_original_pty(
            "load", b"Google enrollment metadata: The LOAD metadata body was refused. Failed checks include "
            b"top-level field allowlist, current tier structure, original project.", b"synthetic-load-marker",
        )

    def test_load_body_details_only_use_the_bounded_exact_failure_snapshot(self):
        token = TokenDiagnostic()
        error = ValueError("synthetic raw exception")
        error.load_body_reasons = tuple(reversed(tuple(LoadBodyReason)))
        post = PostTokenDiagnostic()
        post.mark(error, PostTokenStage.LOAD_BODY)
        error.load_body_reasons = ("synthetic altered reason",)
        owner = Mock()
        connect._write_enrollment_detail(owner, error, token, post)
        line = owner.write_once.call_args.args[0]
        expected = ", ".join(connect._LOAD_BODY_DETAILS[reason] for reason in LoadBodyReason)
        self.assertEqual(line, "Google enrollment metadata: The LOAD metadata body was refused. "
                              f"Failed checks include {expected}.\n")
        self.assertLess(len(line.encode("ascii")), 512)
        for other, scope in ((ValueError(str(error)), post), (error, PostTokenDiagnostic())):
            owner.reset_mock()
            connect._write_enrollment_detail(owner, other, token, scope)
            owner.write_once.assert_not_called()
        owner.reset_mock()
        error.__context__ = ValueError("synthetic replaced context")
        connect._write_enrollment_detail(owner, error, token, post)
        owner.write_once.assert_not_called()

    def test_invalid_load_reason_metadata_keeps_the_plain_body_message(self):
        token, post, owner = TokenDiagnostic(), PostTokenDiagnostic(), Mock()
        error = ValueError("synthetic raw exception")
        error.load_body_reasons = (LoadBodyReason.SIZE, "synthetic open category")
        post.mark(error, PostTokenStage.LOAD_BODY)
        connect._write_enrollment_detail(owner, error, token, post)
        owner.write_once.assert_called_once_with("Google enrollment metadata: The LOAD metadata body was refused.\n")

    def test_post_token_detail_cannot_preempt_token_callback_or_inherit_custody(self):
        callback = metadata_workflow.CallbackWorkflowError(auth_offer.CallbackDiagnostic.NO_MATCHING_CALLBACK)
        token = RuntimeError("fixture token")
        token.token_stage = TokenStage.HTTP_400
        token_diagnostic = TokenDiagnostic()
        token_diagnostic.mark(token)
        for error, expected in (
            (callback, "Google sign-in callback: No matching callback was accepted.\n"),
            (token, "Google sign-in token reply: The token endpoint returned HTTP 400.\n"),
        ):
            with self.subTest(error=type(error).__name__):
                post = PostTokenDiagnostic()
                post.mark(error, PostTokenStage.LOAD_BODY)
                owner = Mock()
                connect._write_enrollment_detail(owner, error, token_diagnostic, post)
                owner.write_once.assert_called_once_with(expected)
        original = RuntimeError("original fixture failure")
        original.__context__ = NativeRetirementUnconfirmed("fixture custody uncertainty")
        post = PostTokenDiagnostic()
        post.mark(original, PostTokenStage.LOAD_BODY)
        owner = Mock()
        for error, attempt in (
            (original, post), (RuntimeError(str(original)), post), (original, PostTokenDiagnostic()),
        ):
            connect._write_enrollment_detail(owner, error, token_diagnostic, attempt)
        owner.write_once.assert_not_called()
        replaced_context = RuntimeError("fixture failure before cleanup")
        post = PostTokenDiagnostic()
        post.mark(replaced_context, PostTokenStage.LOAD_BODY)
        replaced_context.__context__ = RuntimeError("fixture cleanup replaced the context")
        connect._write_enrollment_detail(owner, replaced_context, token_diagnostic, post)
        owner.write_once.assert_not_called()

    def assert_diagnostic_uses_original_pty(self, kind, expected_stage, marker):
        origin = Path(__file__).resolve().parents[1]
        run_connect = runpy.run_path(str(origin / "oc-google.py"))["run_connect"]
        generic = b"oc-sandbox google: Workstation enrollment did not complete.\n"

        terminal_states = (("foreground", "background") if kind == "callback"
                           else ("foreground", "background", "interrupted", "custody"))
        if kind == "load":
            terminal_states += ("expired",)
        for terminal_state in terminal_states:
            with self.subTest(terminal_state=terminal_state):
                stderr = self.parent / f"stderr-{terminal_state}"
                runtime = self.parent / f"runtime-{terminal_state}"
                runtime.mkdir(mode=0o700)
                process, terminal = pty.fork()
                if process == 0:
                    with stderr.open("wb") as stream:
                        os.dup2(stream.fileno(), 2)
                    sys.stderr = os.fdopen(2, "w", buffering=1)
                    try:
                        self.run_pty_diagnostic_fixture(run_connect, runtime, terminal_state, kind)
                    except BaseException:
                        os._exit(2)
                    os._exit(0)

                output = bytearray()
                deadline = time.monotonic() + 5
                finished = False
                try:
                    while time.monotonic() < deadline:
                        if not select.select([terminal], [], [], .05)[0]:
                            continue
                        try:
                            chunk = os.read(terminal, 4096)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            chunk = b""
                        if not chunk:
                            finished = True
                            break
                        output.extend(chunk)
                        self.assertLess(len(output), 8192)
                finally:
                    if not finished:
                        with suppress(ProcessLookupError):
                            os.kill(process, signal.SIGKILL)
                    os.close(terminal)
                    _, status = os.waitpid(process, 0)
                self.assertTrue(finished)
                self.assertEqual(os.waitstatus_to_exitcode(status), 0)
                self.assertEqual(list(runtime.iterdir()), [])
                expected_stderr = generic
                if terminal_state == "custody":
                    expected_stderr += b"oc-sandbox google: Google enrollment cleanup requires inspection.\n"
                self.assertEqual(stderr.read_bytes(), expected_stderr)
                self.assertEqual(bytes(output).strip(), expected_stage if terminal_state == "foreground" else b"")
                self.assertNotIn(marker, output)
                self.assertNotIn(marker, stderr.read_bytes())
                runtime.rmdir()

    @staticmethod
    def run_pty_diagnostic_fixture(run_connect, runtime, terminal_state, kind):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        original_runtime = connect._private_runtime
        original_cleanup = connect._RuntimeCustody.cleanup
        blocker = None
        read_fd, write_fd = os.pipe()

        @contextmanager
        def place(parent, label, cold, owner):
            nonlocal blocker
            try:
                with original_runtime(parent, label, cold, owner) as custody:
                    yield custody
            finally:
                if terminal_state == "interrupted" and not cold:
                    os.kill(os.getpid(), signal.SIGINT)
                if terminal_state == "expired" and not cold:
                    owner.deadline = time.monotonic() - 1
                if terminal_state == "background" and not cold:
                    assert not list(runtime.iterdir())
                    blocker = os.fork()
                    if blocker == 0:
                        os.close(write_fd)
                        os.read(read_fd, 1)
                        os._exit(0)
                    os.setpgid(blocker, blocker)
                    os.tcsetpgrp(0, blocker)

        def cleanup(custody):
            original_cleanup(custody)
            if terminal_state == "custody" and not custody.cold:
                raise OSError("synthetic cleanup uncertainty")

        def refuse_callback(*args, authorized, fence, **kwargs):
            from test_google_auth_offer import exchange, offer, placement, request

            with placement(authorized=authorized, opened=False) as (gate, _recorder, port), \
                    ThreadPoolExecutor(max_workers=1) as browser:
                disclosed = gate.accept_offer(offer(port))
                payload = request(port, extra_headers=b"Referer: https://fixture.invalid/synthetic-referer-marker\x00\r\n")
                reply = browser.submit(exchange, port, payload)
                owner = SimpleNamespace(fence=fence, authorizes_offer=lambda _: True, active=authorized)
                try:
                    metadata_workflow._receive_callback(
                        disclosed, gate, notify=lambda _: None, deadline=time.monotonic() + 2, owner=owner,
                        profile=None,
                    )
                finally:
                    assert reply.result(timeout=3) == auth_offer.acknowledgement(False)

        def refuse_token(*args, authorized, fence, destination, diagnostic=None, post_diagnostic=None, **kwargs):
            from oc_google import enrollment, metadata_destination
            from test_google_enrollment import BEARER, LOAD_REQUEST, SUBJECT
            from test_google_metadata_destination import FakeChannel, IPV4, response
            from test_google_oauth_exchange import AUTHORIZATION, CODE, SCOPE, STATE, form, grant, offer

            if kind == "scope":
                channels = (FakeChannel(response(grant(scope=SCOPE + " synthetic-unapproved-permission"))),)
            elif kind == "load":
                channels = (
                    FakeChannel(response(grant())), FakeChannel(response(SUBJECT)),
                    FakeChannel(response(b'{"synthetic-load-marker":1}')),
                )
            else:
                channels = (FakeChannel(response(status=b"HTTP/1.1 400 synthetic-token-marker")),)
            trust = Mock(wrap_socket=Mock(side_effect=channels))
            gate = Mock(take_forwarded=Mock(return_value=auth_offer.Callback(STATE, CODE)))
            route_type = metadata_destination.MetadataRoute
            routes = (route_type.TOKEN, route_type.USERINFO, route_type.LOAD_CODE_ASSIST)
            sent = []

            def spend(route, send):
                with fence:
                    assert authorized() and route is routes[len(sent)]
                    send()
                    sent.append(route)

            # Passing the optional observer only when the launcher supplied it
            # also lets this PTY regression run against the unchanged baseline.
            options = {} if diagnostic is None else {"diagnostic": diagnostic}
            with patch.object(metadata_destination.socket, "socket", return_value=FakeChannel()), \
                    patch.object(metadata_destination, "_resolve", return_value=(2, IPV4)), \
                    patch.object(metadata_destination, "_system_tls_context", return_value=trust):
                try:
                    verified = enrollment.verify_initial_exchange(
                        offer=offer(), callback_gate=gate, authorization=AUTHORIZATION, form=form(),
                        bind_subject=Mock(), deadline=time.monotonic() + 2, spend=spend,
                        destination=destination, **options,
                    )
                    if kind == "load":
                        live = scoped_post_token(post_diagnostic, fence, authorized)
                        verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST, post_diagnostic=live)
                finally:
                    assert len(sent) == len(channels) and all(len(channel.sent) == 1 for channel in channels)

        refuse = refuse_callback if kind == "callback" else refuse_token
        try:
            with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                    patch.object(connect, "scratch_parent", return_value=runtime), \
                    patch.object(connect, "_preflight"), patch.object(connect, "_private_runtime", place), \
                    patch.object(connect, "_artifacts", return_value=nullcontext(1)), \
                    patch.object(connect, "verify_standalone_source"), \
                    patch.object(connect, "_prepare_runtime"), patch.object(connect, "RegistrationJournal"), \
                    patch.object(connect._TerminalOwner, "consent", return_value=True), \
                    patch.object(connect._RuntimeCustody, "cleanup", autospec=True, side_effect=cleanup), \
                    patch.object(connect, "enroll_metadata", side_effect=refuse):
                assert run_connect("fixture") == 1
        finally:
            os.close(write_fd)
            os.close(read_fd)
            if blocker is not None:
                os.waitpid(blocker, 0)

    def test_diagnostic_write_refusal_or_cleanup_uncertainty_preserves_primary_error(self):
        spec = SimpleNamespace(enabled=True, auth_mode="subscription", cli_path=None)
        for uncertain in (False, True):
            with self.subTest(uncertain=uncertain), TemporaryDirectory(dir=self.parent) as directory:
                runtime = Path(directory)
                owner = Mock(fence=RLock(), authorized=Mock(return_value=True), consent=Mock(return_value=True))
                primary = metadata_workflow.CallbackWorkflowError(auth_offer.CallbackDiagnostic.HEADER_REFERER)
                original_cleanup = connect._RuntimeCustody.cleanup

                def cleanup(custody):
                    original_cleanup(custody)
                    if uncertain and not custody.cold:
                        raise OSError("synthetic cleanup failure")

                def refuse_write(_message):
                    self.assertEqual(list(runtime.iterdir()), [])
                    raise connect.ConnectError("synthetic diagnostic output refusal")

                owner.write_once.side_effect = refuse_write
                with patch.object(connect, "load_provider_config", return_value=Mock(get=Mock(return_value=spec))), \
                        patch.object(connect, "scratch_parent", return_value=runtime), \
                        patch.object(connect, "_preflight"), patch.object(connect, "_attended_owner",
                                                                          return_value=nullcontext(owner)), \
                        patch.object(connect, "_artifacts", return_value=nullcontext(1)), \
                        patch.object(connect, "verify_standalone_source"), \
                        patch.object(connect, "_prepare_runtime"), patch.object(connect, "RegistrationJournal"), \
                        patch.object(connect, "enroll_metadata", side_effect=primary), \
                        patch.object(connect._RuntimeCustody, "cleanup", autospec=True, side_effect=cleanup):
                    with self.assertRaises(metadata_workflow.CallbackWorkflowError) as result:
                        connect.connect_for("fixture")
                self.assertIs(result.exception, primary)
                self.assertEqual(connect.needs_custody_inspection(primary), uncertain)
                self.assertEqual(owner.write_once.call_count, 0 if uncertain else 1)

    def test_cold_runtime_does_not_replace_replica_cleanup(self):
        with self.assertRaisesRegex(connect.CustodyUnconfirmed, "requires inspection"):
            with connect._private_runtime(self.parent, "fixture", True, self.owner) as custody:
                replica = custody.root / "profile"
                replica.mkdir()
        self.assertTrue(replica.is_dir())

    def test_cold_disappearance_with_quarantine_requires_inspection(self):
        with self.assertRaisesRegex(connect.CustodyUnconfirmed, "requires inspection"):
            with connect._private_runtime(self.parent, "fixture", True, self.owner) as custody:
                quarantine = self.parent / custody.quarantine
                os.rename(custody.root, quarantine)
        self.assertTrue(quarantine.is_dir())
