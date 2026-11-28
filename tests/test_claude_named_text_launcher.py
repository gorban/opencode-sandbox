"""Real inert Python children for the standalone named Claude fixture launcher."""

from contextlib import contextmanager
import ctypes
import errno
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import signal
import socket
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
        if cancelled is None:
            cancelled = Event()
        with self.assertRaises(expected) as failure:
            turn.run("synthetic local text", cancelled=cancelled)
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

    def test_stdin_close_report_preserves_send_refusals_and_blocks_success(self):
        for reason, writes in (("native_cancelled", b""), ("native_write_uncertain", b"x"),
                               ("native_owner_failed", b"w")):
            with self.subTest(reason=reason):
                self._stdin_close_report_probe(reason, writes)

    def _stdin_close_report_probe(self, reason, expected_writes):
        send = launcher._send_once
        write = launcher._WRITE
        is_cancelled = launcher._OwnerCancellation.is_set
        cancelled_at_send = False
        writes = self.root / f"{reason}-writes"
        released = self.root / f"{reason}-released"
        writes.touch()

        def observe_cancellation(owner):
            return cancelled_at_send or is_cancelled(owner)

        def observe_write(descriptor, packet, length):
            result = -1 if reason == "native_write_uncertain" else write(descriptor, packet, length)
            with writes.open("ab") as log:
                log.write(b"w" if result == length else b"x")
            return result

        def install_close_report(process, packet, checkpoint):
            nonlocal cancelled_at_send
            stream = process.stdin
            descriptor = stream.fileno()
            close = stream.close

            def close_and_report():
                stream.close = close
                close()
                with self.assertRaises(OSError) as failure:
                    os.fstat(descriptor)
                self.assertEqual(failure.exception.errno, errno.EBADF)
                released.write_text(str(process.pid))
                raise OSError("synthetic native stdin close report")

            stream.close = close_and_report
            cancelled_at_send = reason == "native_cancelled"
            send(process, packet, checkpoint)

        turn = launcher.FixtureTurn(self.work)
        cancelled = Event()
        with (patch.object(launcher, "_send_once", side_effect=install_close_report),
              patch.object(launcher._OwnerCancellation, "is_set", autospec=True, side_effect=observe_cancellation),
              patch.object(launcher, "_WRITE", side_effect=observe_write),
              self.assertRaises(launcher.FixtureLaunchError) as failure):
            turn.run("fixture text", cancelled=cancelled)

        self.assert_drained()
        native_pid = int(released.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(native_pid, 0)
        self.assertEqual(writes.read_bytes(), expected_writes)
        self.assertIs(type(failure.exception), launcher.FixtureLaunchError)
        self.assertEqual(str(failure.exception), reason)
        self.assertIsNone(failure.exception.__cause__)

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

    def test_pidfd_close_failure_does_not_clear_unverified_descendant_retirement(self):
        self._isolated_probe("_drain_and_pidfd_close_probe")

    def _drain_and_pidfd_close_probe(self):
        controller = os.getpid()
        original_drain = Supervisor.drain
        open_pidfd = os.pidfd_open
        close = os.close
        native_pidfd = None
        drain_failed = self.root / "drain-fault"
        close_failed = self.root / "close-fault"

        def open_and_track_native(pid, *args):
            nonlocal native_pidfd
            descriptor = open_pidfd(pid, *args)
            if os.getpid() != controller and pid != os.getpid() and native_pidfd is None:
                native_pidfd = descriptor
            return descriptor

        def lose_retirement_evidence(supervisor, process):
            original_drain(supervisor, process)
            supervisor.drained = False
            drain_failed.touch()
            raise OSError("synthetic drain failure")

        def close_with_fault(descriptor):
            close(descriptor)
            if os.getpid() != controller and descriptor == native_pidfd:
                close_failed.touch()
                raise OSError("synthetic native pidfd close failure")

        turn = self.variant('sys.stdout.buffer.write(b"{}\\n"); sys.stdout.buffer.flush()')
        cancelled = Event()
        with (patch.object(Supervisor, "drain", autospec=True, side_effect=lose_retirement_evidence),
              patch.object(os, "pidfd_open", side_effect=open_and_track_native),
              patch.object(os, "close", side_effect=close_with_fault),
              self.assertRaises((wire.TextWireError, launcher.FixtureLaunchError)) as failure):
            turn.run("fixture text", cancelled=cancelled)

        self.assertTrue(drain_failed.exists())
        self.assertTrue(close_failed.exists())
        self.assert_drained()
        self.assert_refused(launcher.FixtureTurn(self.work), "native_workspace_quarantined")
        self.assertIsInstance(failure.exception, wire.TextWireError)
        self.assertEqual(failure.exception.__notes__, ["Native descendant retirement could not be verified."])

    @contextmanager
    def post_fork_socket_close_fault(self, *, in_child):
        controller = os.getpid()
        socketpair = socket.socketpair
        close = socket.socket.close
        endpoints = []
        faulted = self.root / "socket-close-fault"

        def track_endpoints():
            pair = socketpair()
            endpoints[:] = pair
            return pair

        def close_with_fault(connection):
            close(connection)
            side = 0 if in_child else 1
            if (os.getpid() != controller) == in_child and endpoints and connection is endpoints[side]:
                endpoints[side] = None
                faulted.touch()
                raise OSError("synthetic post-fork socket close failure")

        with (patch.object(socket, "socketpair", side_effect=track_endpoints),
              patch.object(socket.socket, "close", autospec=True, side_effect=close_with_fault)):
            yield faulted

    def test_parent_socket_close_failure_reaps_the_exact_owner(self):
        fork = os.fork
        owned = []

        def track_owner():
            child = fork()
            if child:
                owned.append(child)
            return child

        def wait_for_controller_release(connection, *_):
            try:
                connection.settimeout(1)
                connection.recv(1)
            finally:
                os._exit(0)

        turn = launcher.FixtureTurn(self.work)
        cancelled = Event()
        with (self.post_fork_socket_close_fault(in_child=False) as faulted,
              patch.object(os, "fork", side_effect=track_owner),
              patch.object(launcher, "_owner_entry", side_effect=wait_for_controller_release),
              self.assertRaisesRegex(OSError, "synthetic post-fork socket close failure")):
            turn.run("fixture text", cancelled=cancelled)
        self.assertTrue(faulted.exists())
        self.assertEqual(len(owned), 1)
        # Drain the exact synthetic owner for old-red runs before reporting a regression.
        with self.assertRaises(ChildProcessError):
            launcher._reap_owner(owned[0], None, grace=1.5)
        self.assert_drained()

    def test_child_socket_close_failure_exits_without_resuming_controller_code(self):
        self._isolated_probe("_child_socket_close_probe")

    def _child_socket_close_probe(self):
        controller = os.getpid()
        escaped = self.root / "owner-returned-to-controller"
        turn = launcher.FixtureTurn(self.work)
        cancelled = Event()
        with self.post_fork_socket_close_fault(in_child=True) as faulted:
            try:
                with self.assertRaisesRegex(launcher.FixtureLaunchError, "^native_owner_failed$"):
                    turn.run("fixture text", cancelled=cancelled)
            finally:
                if os.getpid() != controller:
                    escaped.touch()
                    os._exit(70)
        self.assertTrue(faulted.exists())
        self.assertFalse(escaped.exists())
        self.assert_drained()

    @contextmanager
    def final_controller_close_fault(self, site):
        controller = os.getpid()
        open_pidfd = os.pidfd_open
        close_fd = os.close
        socketpair = socket.socketpair
        close_socket = socket.socket.close
        pidfd = control = None
        released = []

        def track_pidfd(pid, *args):
            nonlocal pidfd
            descriptor = open_pidfd(pid, *args)
            if os.getpid() == controller:
                pidfd = descriptor
            return descriptor

        def track_socketpair():
            nonlocal control
            control, owner = socketpair()
            return control, owner

        def report_after_close(descriptor):
            self.assert_drained()
            with self.assertRaises(OSError) as failure:
                os.fstat(descriptor)
            self.assertEqual(failure.exception.errno, errno.EBADF)
            released.append(descriptor)
            raise OSError("synthetic controller close report")

        def close_pidfd(descriptor):
            close_fd(descriptor)
            if site == "pidfd" and os.getpid() == controller and descriptor == pidfd:
                report_after_close(descriptor)

        def close_control(connection):
            descriptor = connection.fileno()
            close_socket(connection)
            if site == "control" and os.getpid() == controller and connection is control:
                report_after_close(descriptor)

        with (patch.object(os, "pidfd_open", side_effect=track_pidfd),
              patch.object(os, "close", side_effect=close_pidfd),
              patch.object(socket, "socketpair", side_effect=track_socketpair),
              patch.object(socket.socket, "close", autospec=True, side_effect=close_control)):
            yield released

    def test_controller_pidfd_release_preserves_checked_retirement_failure(self):
        self._isolated_probe("_controller_pidfd_release_probe")

    def _controller_pidfd_release_probe(self):
        self._controller_release_probe("pidfd")

    def test_controller_socket_release_preserves_checked_retirement_failure(self):
        self._isolated_probe("_controller_socket_release_probe")

    def _controller_socket_release_probe(self):
        self._controller_release_probe("control")

    def _controller_release_probe(self, site):
        work = self.root / "ordinary"
        work.mkdir(mode=0o700)
        cancelled = Event()
        ordinary = launcher.FixtureTurn(work).run("fixture text", cancelled=cancelled)
        self.assertEqual(ordinary.text, "fixture: fixture text")
        self.assert_drained()

        success_with_close_error = launcher.FixtureTurn(work)
        with (self.final_controller_close_fault(site) as released,
              self.assertRaisesRegex(OSError, "^synthetic controller close report$")):
            success_with_close_error.run("fixture text", cancelled=cancelled)
        self.assertEqual(len(released), 1)

        original_drain = Supervisor.drain

        def lose_retirement_evidence(supervisor, process):
            original_drain(supervisor, process)
            supervisor.drained = False
            raise OSError("synthetic retirement proof failure")

        turn = self.variant('sys.stdout.buffer.write(b"{}\\n"); sys.stdout.buffer.flush()')
        with (patch.object(Supervisor, "drain", autospec=True, side_effect=lose_retirement_evidence),
              self.final_controller_close_fault(site) as released,
              self.assertRaises(wire.TextWireError) as failure):
            turn.run("fixture text", cancelled=cancelled)

        self.assertEqual(len(released), 1)
        self.assertEqual(str(failure.exception), "Unexpected named Claude text fixture message")
        self.assertEqual(failure.exception.__notes__, ["Native descendant retirement could not be verified."])
        self.assert_drained()
        self.assert_refused(launcher.FixtureTurn(self.work), "native_workspace_quarantined")

    def test_workspace_pin_close_report_preserves_checked_refusal(self):
        (self.work / "nonempty").touch()
        open_fd = os.open
        close = os.close
        opened = []
        close_attempts = []
        close_report = OSError(errno.EIO, "synthetic workspace pin close report")

        def track_open(path, *args, **kwargs):
            fd = open_fd(path, *args, **kwargs)
            if path == self.work:
                opened.append(fd)
            return fd

        def close_and_report(fd):
            if fd not in opened:
                return close(fd)
            close_attempts.append(fd)
            close(fd)
            with self.assertRaises(OSError) as failure:
                os.fstat(fd)
            self.assertEqual(failure.exception.errno, errno.EBADF)
            raise close_report

        turn = launcher.FixtureTurn(self.work)
        cancelled = Event()
        with (patch.object(os, "open", side_effect=track_open),
              patch.object(os, "close", side_effect=close_and_report),
              patch.object(launcher, "_run_owner_process") as run_owner,
              self.assertRaises((launcher.FixtureLaunchError, OSError)) as failure):
            turn.run("fixture text", cancelled=cancelled)

        run_owner.assert_not_called()
        self.assertEqual(len(opened), 1)
        self.assertEqual(close_attempts, opened)
        self.assert_drained()
        self.assertIsInstance(failure.exception, launcher.FixtureLaunchError)
        self.assertEqual(str(failure.exception), "native_workspace_unverified")
        self.assertIs(failure.exception.__cause__, close_report)

    def test_startup_pin_close_report_preserves_checked_refusals(self):
        self._isolated_probe("_startup_pin_close_report_probe")

    def _startup_pin_close_report_probe(self):
        for site, reason in (("raw source", "native_source_unverified"),
                             ("source digest", "native_source_unverified"),
                             ("sealed source", "native_source_unverified"),
                             ("executable", "native_executable_unverified")):
            with self.subTest(site=site):
                self._assert_startup_pin_close_report(site, reason)

    def _assert_startup_pin_close_report(self, site, reason):
        source = launcher._SOURCE
        if site == "raw source":
            source = self.root / "inert-source-fifo"
            os.mkfifo(source)
        elif site == "source digest":
            source = self.root / "inert-wrong-digest.py"
            source.write_bytes(b"# synthetic wrong-digest source\n")
        raw_source = site in ("raw source", "source digest")
        executable = self.root if site == "executable" else launcher._PYTHON
        turn = launcher.FixtureTurn(self.work, _source=source)
        cancelled = Event()
        disposition = launcher._ExchangeDisposition()
        open_fd = os.open
        open_stream = os.fdopen
        create_memfd = os.memfd_create
        control_fd = launcher.fcntl.fcntl
        close_fd = os.close
        opened = []
        close_attempts = []
        close_report = OSError(errno.EIO, "synthetic startup pin close report")

        def report_after_close(fd, close):
            close_attempts.append(fd)
            close()
            with self.assertRaises(OSError) as failure:
                os.fstat(fd)
            self.assertEqual(failure.exception.errno, errno.EBADF)
            raise close_report

        def track_open(path, *args, **kwargs):
            fd = open_fd(path, *args, **kwargs)
            if site == "executable" and path == executable:
                opened.append(fd)
            return fd

        def track_stream(fd, *args, **kwargs):
            stream = open_stream(fd, *args, **kwargs)
            if raw_source:
                opened.append(fd)
                close = stream.close
                stream.close = lambda: report_after_close(fd, close)
            return stream

        def track_memfd(*args, **kwargs):
            fd = create_memfd(*args, **kwargs)
            if site == "sealed source":
                opened.append(fd)
            return fd

        def check_seals(fd, command, *args):
            if site == "sealed source" and command == launcher.fcntl.F_GET_SEALS and fd in opened:
                return 0
            return control_fd(fd, command, *args)

        def close_resource(fd):
            if not raw_source and fd in opened:
                return report_after_close(fd, lambda: close_fd(fd))
            return close_fd(fd)

        workspace = launcher._pin_workspace(self.work)
        try:
            with (patch.object(os, "open", side_effect=track_open),
                  patch.object(os, "fdopen", side_effect=track_stream),
                  patch.object(os, "memfd_create", side_effect=track_memfd),
                  patch.object(launcher.fcntl, "fcntl", side_effect=check_seals),
                  patch.object(os, "close", side_effect=close_resource),
                  patch.object(launcher, "_PYTHON", executable),
                  patch.object(subprocess, "Popen") as native_launch,
                  self.assertRaises((launcher.FixtureLaunchError, OSError)) as failure):
                turn._owned_exchange("fixture text", workspace=workspace, cancelled=cancelled,
                                     disposition=disposition)
        finally:
            close_fd(workspace.fd)

        native_launch.assert_not_called()
        self.assertEqual(len(opened), 1)
        self.assertEqual(close_attempts, opened)
        self.assert_drained()
        self.assertIsInstance(failure.exception, launcher.FixtureLaunchError)
        self.assertEqual(str(failure.exception), reason)
        self.assertIs(failure.exception.__cause__, close_report)

    def test_workspace_close_report_preserves_a_checked_refusal_and_blocks_a_valid_reply(self):
        controller = os.getpid()
        pin_workspace = launcher._pin_workspace
        read_owner = launcher._read_owner
        close = os.close
        cancelled = Event()
        for refused in (True, False):
            with self.subTest(refused=refused):
                workspace_fd = None
                checked = []
                releases = []
                close_report = OSError(errno.EIO, "synthetic workspace close report")

                def track_pin(workspace):
                    nonlocal workspace_fd
                    binding = pin_workspace(workspace)
                    workspace_fd = binding.fd
                    return binding

                def track_outcome(connection, pidfd, pid, cancellation):
                    record, status = read_owner(connection, pidfd, pid, cancellation)
                    checked.append((pid, record, status))
                    return record, status

                def close_and_report(fd):
                    close(fd)
                    if os.getpid() != controller or fd != workspace_fd:
                        return
                    self.assertEqual(len(checked), 1)
                    pid, record, status = checked[0]
                    self.assertEqual(status, 0)
                    self.assertEqual("error" in record, refused)
                    with self.assertRaises(ChildProcessError):
                        os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    with self.assertRaises(OSError) as failure:
                        os.fstat(fd)
                    self.assertEqual(failure.exception.errno, errno.EBADF)
                    releases.append(fd)
                    raise close_report

                turn = (self.variant('sys.stdout.buffer.write(b"{}\\n"); sys.stdout.buffer.flush()')
                        if refused else launcher.FixtureTurn(self.work))
                expected = wire.TextWireError if refused else OSError
                with (patch.object(launcher, "_pin_workspace", side_effect=track_pin),
                      patch.object(launcher, "_read_owner", side_effect=track_outcome),
                      patch.object(os, "close", side_effect=close_and_report),
                      self.assertRaises(expected) as failure):
                    turn.run("fixture text", cancelled=cancelled)

                self.assertEqual(releases, [workspace_fd])
                if refused:
                    self.assertEqual(str(failure.exception), "Unexpected named Claude text fixture message")
                    self.assertIs(failure.exception.__cause__, close_report)
                else:
                    self.assertIs(failure.exception, close_report)
                self.assert_drained()
