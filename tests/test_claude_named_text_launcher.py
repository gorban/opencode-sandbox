"""Real inert Python children for the standalone named Claude fixture launcher."""

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
from textwrap import dedent
from threading import Event
import time
import unittest
from unittest.mock import patch

from e2e import claude_named_text_launcher as launcher
from e2e import claude_named_text_protocol as wire
from tools.ci.supervisor import CheckError, PR_GET_CHILD_SUBREAPER, Supervisor, prctl


class InertClaudeLauncherTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)

    def variant(self, tail, *, before=""):
        source = launcher._SOURCE.read_text().split('if __name__ == "__main__":')[0]
        source += dedent(before) + "\nstatus = main()\n" + dedent(tail) + "\nsys.exit(status)\n"
        path = self.root / "variant.py"
        data = source.encode("utf-8")
        path.write_bytes(data)
        return launcher.FixtureTurn(self.work, _source=path, _source_digest=sha256(data).hexdigest())

    def assert_drained(self):
        with self.assertRaises(ChildProcessError):
            os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def assert_refused(self, turn, reason, *, cancelled=None, expected=launcher.FixtureLaunchError):
        with self.assertRaises(expected) as failure:
            turn.run("synthetic local text", cancelled=cancelled if cancelled is not None else Event())
        self.assertEqual(str(failure.exception), reason)
        self.assert_drained()
        with self.assertRaisesRegex(launcher.FixtureLaunchError, "^native_turn_spent$"):
            turn.run("second fixture text", cancelled=Event())

    def test_pinned_child_returns_one_reply_after_stdin_and_stdout_eof(self):
        turn = launcher.FixtureTurn(self.work)
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": "/do-not-inherit", "PYTHONPATH": "/do-not-inherit"}):
            result = turn.run("ordinary fixture text\n☀", cancelled=Event())
        self.assertEqual(result.text, "fixture: ordinary fixture text\n☀")
        self.assertEqual(result.input_tokens, len("ordinary fixture text\n☀".encode("utf-8")))
        self.assertEqual(result.output_tokens, len(result.text.encode("utf-8")))
        self.assert_drained()
        with self.assertRaisesRegex(launcher.FixtureLaunchError, "^native_turn_spent$"):
            turn.run("replayed request", cancelled=Event())

    def test_wrong_source_or_nonempty_workspace_refuses_before_launch(self):
        untrusted = self.root / "changed.py"
        untrusted.write_text("raise RuntimeError('must not start')")
        wrong_source = launcher.FixtureTurn(self.work, _source=untrusted)
        with patch.object(launcher.subprocess, "Popen", side_effect=AssertionError("unexpected child")):
            self.assert_refused(wrong_source, "native_source_unverified")
            (self.work / "unexpected").touch()
            self.assert_refused(launcher.FixtureTurn(self.work), "native_workspace_unverified")

    def test_stdout_and_stderr_must_end_at_the_clean_terminal_boundary(self):
        cases = (
            ('sys.stdout.buffer.write(b"{}\\n"); sys.stdout.buffer.flush()', "Unexpected named Claude text fixture message",
             wire.TextWireError),
            ('sys.stdout.buffer.write(b"{"); sys.stdout.buffer.flush()', "native_partial_frame",
             launcher.FixtureLaunchError),
            ('sys.stderr.write("private failure"); sys.stderr.flush()', "native_stderr", launcher.FixtureLaunchError),
            ('sys.stdout.buffer.write(b"x" * 8192); sys.stdout.buffer.flush()', "native_frame_limit",
             launcher.FixtureLaunchError),
            ('sys.exit(23)', "native_child_failed", launcher.FixtureLaunchError),
        )
        for tail, error, error_type in cases:
            with self.subTest(tail=tail):
                self.assert_refused(self.variant(tail), error, expected=error_type)

    def test_stubborn_child_with_open_pipe_cannot_publish_a_terminal_result(self):
        turn = self.variant('''
            import signal, time
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            time.sleep(60)
        ''')
        start = time.monotonic()
        self.assert_refused(turn, "native_deadline")
        self.assertLess(time.monotonic() - start, 8)

    def test_escaped_descendant_prevents_reply_even_after_leader_closes_pipes(self):
        turn = self.variant('''
            import os, signal, time
            seen, ready = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(seen)
                os.setsid()
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                for descriptor in (0, 1, 2):
                    os.close(descriptor)
                Path("escaped").write_text(str(os.getpid()))
                os.write(ready, b"x")
                os.close(ready)
                time.sleep(60)
                os._exit(0)
            os.close(ready)
            assert os.read(seen, 1) == b"x"
            os.close(seen)
        ''', before="from pathlib import Path")
        self.assert_refused(turn, "native_descendants_live")
        pid = int((self.work / "escaped").read_text())
        with self.assertRaises(ProcessLookupError):
            os.pidfd_open(pid)

    def test_cancel_before_start_and_after_one_send(self):
        stop = Event()
        stop.set()
        with patch.object(launcher.subprocess, "Popen", side_effect=AssertionError("unexpected child")):
            self.assert_refused(launcher.FixtureTurn(self.work), "native_cancelled", cancelled=stop)

        marker = self.work / "after-send"
        turn = self.variant('''
            import time
            assert status == 0
            Path("after-send").touch()
            time.sleep(60)
        ''', before="from pathlib import Path")
        self.assert_refused(turn, "native_cancelled", cancelled=type("CancelOnSend", (), {"is_set": staticmethod(marker.exists)})())
        self.assertTrue(marker.exists())

    def test_malformed_ready_prevents_the_handoff(self):
        marker = self.work / "unexpected-send"
        turn = self.variant(
            'if status == 0: Path("unexpected-send").touch()',
            before='''
                from pathlib import Path
                emit = _emit
                def _emit(output, value):
                    if value["type"] == "ready":
                        value["model"] = "wrong-fixture-model"
                    emit(output, value)
            ''',
        )
        self.assert_refused(turn, "Unexpected named Claude text fixture message", expected=wire.TextWireError)
        self.assertFalse(marker.exists())

    def _isolated_probe(self, name):
        command = """
import sys
import unittest
sys.path.insert(0, "tests")
from test_claude_named_text_launcher import InertClaudeLauncherTests

suite = unittest.TestSuite([InertClaudeLauncherTests(sys.argv[1])])
sys.exit(not unittest.TextTestRunner().run(suite).wasSuccessful())
"""
        result = subprocess.run(
            (sys.executable, "-B", "-c", command, name), capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_closed_stdin_after_verified_ready_does_not_kill_the_controller(self):
        self._isolated_probe("_closed_pipe_probe")

    def _closed_pipe_probe(self):
        turn = self.variant("", before='''
            import os, time
            from pathlib import Path
            def _exchange(stdin, output, *, session, model, profile, account):
                _emit(output, {"type": "ready", "session": session, "model": model, "profile": profile,
                               "account": account, "auth": "claude.ai", "provider": "firstParty",
                               "tools": [], "mcp": [], "hooks": []})
                while not Path("write-now").exists():
                    time.sleep(.005)
                os.close(0)
                owner = os.getppid()
                Path("stdin-closed").touch()
                deadline = time.monotonic() + 2
                while os.getppid() == owner and time.monotonic() < deadline:
                    time.sleep(.005)
        ''')
        original_send = launcher._send_once

        def after_verified_snapshot(process, packet, *checkpoint):
            (self.work / "write-now").touch()
            deadline = time.monotonic() + 1
            while not (self.work / "stdin-closed").exists():
                if time.monotonic() >= deadline:
                    raise AssertionError("the inert child did not close its stdin")
                time.sleep(.005)
            original_send(process, packet, *checkpoint)

        previous = signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        try:
            with patch.object(launcher, "_send_once", side_effect=after_verified_snapshot):
                self.assert_refused(turn, "native_write_uncertain")
            self.assertIs(signal.getsignal(signal.SIGPIPE), signal.SIG_DFL)
        finally:
            signal.signal(signal.SIGPIPE, previous)

    def test_unverified_drain_exits_owner_and_preserves_caller_environment(self):
        self._isolated_probe("_unverified_drain_probe")

    def _unverified_drain_probe(self):
        original_drain = Supervisor.drain
        pid_path = self.root / "unverified-owner"

        def lose_completion_evidence(supervisor, process):
            original_drain(supervisor, process)
            supervisor.drained = False
            pid_path.write_text(str(os.getpid()))
            raise OSError("simulated loss of retirement evidence")

        def environment():
            subreaper = ctypes.c_int()
            prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(subreaper))
            return subreaper.value, tuple(signal.getsignal(number) for number in (
                signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGCHLD, signal.SIGPIPE,
            ))

        before = environment()
        turn = self.variant('sys.stdout.buffer.write(b"{}\\n"); sys.stdout.buffer.flush()')
        with patch.object(Supervisor, "drain", autospec=True, side_effect=lose_completion_evidence):
            with self.assertRaises(wire.TextWireError) as failure:
                turn.run("fixture text", cancelled=Event())
        self.assertEqual(failure.exception.__notes__, ["Native descendant retirement could not be verified."])
        self.assertEqual(environment(), before)
        observed_pid = int(pid_path.read_text())
        self.assertNotEqual(observed_pid, os.getpid())
        with self.assertRaises(ProcessLookupError):
            os.close(os.pidfd_open(observed_pid))
        self.assert_drained()
        self.assert_refused(launcher.FixtureTurn(self.work), "native_workspace_quarantined")
        pinned = self.root / "original-workspace"
        self.work.rename(pinned)
        self.work.mkdir(mode=0o700)
        # This test already drained the inert child before injecting loss of proof.
        # Removing the marker verifies that the exact controller pin still refuses reuse.
        (pinned / ".oc-unknown-retirement").unlink()
        self.assert_refused(launcher.FixtureTurn(self.work), "native_workspace_quarantined")
        self.assert_refused(launcher.FixtureTurn(pinned), "native_workspace_quarantined")

    def test_ready_with_replaced_or_wrong_direction_stdin_refuses_before_handoff(self):
        for replacement in (
            'os.open("/dev/null", os.O_RDONLY)',
            'os.open("/proc/self/fd/0", os.O_WRONLY | os.O_NONBLOCK)',
        ):
            with self.subTest(replacement=replacement):
                turn = self.variant("", before=dedent('''
                    import os, time
                    def _exchange(stdin, output, *, session, model, profile, account):
                        replacement = REPLACEMENT
                        os.dup2(replacement, 0)
                        os.close(replacement)
                        _emit(output, {"type": "ready", "session": session, "model": model, "profile": profile,
                                       "account": account, "auth": "claude.ai", "provider": "firstParty",
                                       "tools": [], "mcp": [], "hooks": []})
                        time.sleep(60)
                ''').replace("REPLACEMENT", replacement))
                self.assert_refused(turn, "native_stdio_unverified")

    def test_stdio_metadata_unavailable_refuses_before_handoff(self):
        with patch.object(launcher, "_pipe_access", create=True, side_effect=PermissionError("inert denial")):
            self.assert_refused(launcher.FixtureTurn(self.work), "native_stdio_unverified")
    def test_expiry_during_real_descriptor_verification_cannot_write(self):
        verify = launcher._verify_started
        clock = time.monotonic
        wrote = self.root / "expired-write"
        write = launcher._WRITE
        expired = False

        def start_then_expire(*args):
            nonlocal expired
            verify(*args)
            expired = True

        def monotonic():
            return clock() + (launcher._TURN_SECONDS + 1 if expired else 0)

        def record_write(*args):
            wrote.touch()
            return write(*args)

        with (patch.object(launcher, "_verify_started", side_effect=start_then_expire),
              patch.object(launcher.time, "monotonic", side_effect=monotonic),
              patch.object(launcher, "_WRITE", side_effect=record_write)):
            self.assert_refused(launcher.FixtureTurn(self.work), "native_deadline")
        self.assertFalse(wrote.exists())

    def test_cancellation_during_real_descriptor_verification_cannot_write(self):
        verify = launcher._verify_started
        probe_cancellation = launcher._OwnerCancellation.is_set
        sockets = []
        cancel = self.root / "cancel-now"
        wrote = self.root / "cancelled-write"
        write = launcher._WRITE

        def observe_cancellation(owner):
            sockets[:] = [owner.connection]
            return probe_cancellation(owner)

        def start_and_wait_for_cancellation(*args):
            verify(*args)
            cancel.touch()
            if not select.select(sockets, [], [], 1)[0]:
                raise AssertionError("the controller did not close its cancellation half")

        def record_write(*args):
            wrote.touch()
            return write(*args)

        with (patch.object(launcher, "_verify_started", side_effect=start_and_wait_for_cancellation),
              patch.object(launcher._OwnerCancellation, "is_set", autospec=True, side_effect=observe_cancellation),
              patch.object(launcher, "_WRITE", side_effect=record_write)):
            cancelled = type("CancelOnMarker", (), {"is_set": staticmethod(cancel.exists)})()
            self.assert_refused(launcher.FixtureTurn(self.work), "native_cancelled", cancelled=cancelled)
        self.assertFalse(wrote.exists())

    def test_mixed_terminal_error_and_result_refuses_on_success_and_uncertainty_status(self):
        record = {
            "error": "FixtureLaunchError", "message": "unverified",
            "result": {"text": "false success", "input_tokens": 1, "output_tokens": 1, "terminal_digest": "a" * 64},
        }
        for status in (79, 0):
            with self.subTest(status=status):
                work = self.root / f"record-{status}"
                work.mkdir(mode=0o700)

                def mixed_owner(connection, *_):
                    connection.sendall(json.dumps(record).encode("ascii"))
                    os._exit(status)

                with patch.object(launcher, "_owner_entry", side_effect=mixed_owner):
                    self.assert_refused(launcher.FixtureTurn(work), "native_owner_failed")

    def test_caller_blocked_sigterm_does_not_disable_the_disposable_owner(self):
        verify = launcher._verify_started
        wrote = self.root / "write-after-signal"
        write = launcher._WRITE

        def start_then_signal_owner(*args):
            verify(*args)
            os.kill(os.getpid(), signal.SIGTERM)

        def record_write(*args):
            wrote.touch()
            return write(*args)

        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        try:
            with (patch.object(launcher, "_verify_started", side_effect=start_then_signal_owner),
                  patch.object(launcher, "_WRITE", side_effect=record_write)):
                self.assert_refused(
                    launcher.FixtureTurn(self.work), "Interrupted by SIGTERM", expected=CheckError,
                )
            self.assertFalse(wrote.exists())
            self.assertIn(signal.SIGTERM, signal.pthread_sigmask(signal.SIG_BLOCK, set()))
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def test_initial_observer_cannot_splice_a_different_workspace_into_native_start(self):
        alternate = self.root / "alternate"
        alternate.mkdir(mode=0o700)
        turn = self.variant(
            'Path("observed-home").write_text(os.environ["HOME"])',
            before="import os\nfrom pathlib import Path",
        )

        def mutate_workspace():
            turn.workspace = alternate
            return False

        cancelled = type("WorkspaceChangingObserver", (), {"is_set": staticmethod(mutate_workspace)})()
        turn.run("fixture text", cancelled=cancelled)
        self.assertFalse((alternate / "observed-home").exists())
        self.assertEqual((self.work / "observed-home").read_text(), str(self.work))
        self.assert_drained()

    def test_quarantine_keeps_the_original_path_despite_a_late_workspace_splice(self):
        self._isolated_probe("_quarantine_workspace_splice_probe")

    def _quarantine_workspace_splice_probe(self):
        alternate = self.root / "alternate"
        alternate.mkdir(mode=0o700)
        turn = self.variant('sys.stdout.buffer.write(b"{}\\n"); sys.stdout.buffer.flush()')
        original_drain = Supervisor.drain
        calls = 0

        def lose_completion_evidence(supervisor, process):
            original_drain(supervisor, process)
            supervisor.drained = False
            raise OSError("simulated loss of retirement evidence")

        def mutate_when_owner_is_running():
            nonlocal calls
            calls += 1
            if calls > 1:
                turn.workspace = alternate
            return False

        cancelled = type("LateWorkspaceObserver", (), {"is_set": staticmethod(mutate_when_owner_is_running)})()
        with patch.object(Supervisor, "drain", autospec=True, side_effect=lose_completion_evidence):
            with self.assertRaises(wire.TextWireError) as failure:
                turn.run("fixture text", cancelled=cancelled)
        self.assertEqual(failure.exception.__notes__, ["Native descendant retirement could not be verified."])
        self.assertEqual(turn.workspace, alternate)

        pinned = self.root / "retained-original"
        self.work.rename(pinned)
        self.work.mkdir(mode=0o700)
        self.assert_refused(launcher.FixtureTurn(self.work), "native_workspace_quarantined")
        # The inert child was drained before the test removed retirement evidence.
        # Remove its best-effort marker to test the process-owned inode block directly.
        (pinned / ".oc-unknown-retirement").unlink()
        self.assert_refused(launcher.FixtureTurn(pinned), "native_workspace_quarantined")
        self.assertEqual(launcher.FixtureTurn(alternate).run("fresh fixture", cancelled=Event()).text,
                         "fixture: fresh fixture")
        self.assert_drained()
