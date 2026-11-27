"""Check that native service teardown waits for the owned host invocation."""

import subprocess
import signal
from pathlib import Path
from threading import RLock
import unittest
from unittest.mock import Mock, call, patch

from oc_google.native_enrollment_acp import NativeAcpError
from oc_google.native_namespace import NativeNamespaceError
from oc_google.native_service import NativeInvocation, NativeRetirementUnconfirmed, NativeService, _run_service, _stop, open_cold_service


class NativeServiceTest(unittest.TestCase):
    unit = "oc-google-acp-0123456789abcdef01234567.service"
    description = "oc-sandbox ACP " + "a" * 32
    identity = NativeInvocation(unit, "e" * 32, ("/user.slice/app.slice/" + unit).encode(), 123)

    def setUp(self):
        self.pid_exited = self.enterContext(patch("oc_google.native_service._pid_exited", return_value=True))

    def test_cold_placement_refuses_a_profile_path_as_a_replica(self):
        with self.assertRaisesRegex(NativeNamespaceError, "staged replica"):
            open_cold_service(Path("/fixture"), None, replica=Path("/fixture/authoritative"), connector=None, ca=None,
                              authorized=lambda: True, fence=RLock())

    def test_unconfirmed_retirement_is_attached_to_the_primary_failure(self):
        namespace = Mock(unit=self.unit, description=self.description)
        primary = ValueError("fixture primary failure")
        unconfirmed = NativeRetirementUnconfirmed("fixture retirement hold")
        with patch("oc_google.native_service._spawn"), \
                patch("oc_google.native_service._pin", return_value=(self.identity, 9)), \
                patch("oc_google.native_service._stop", side_effect=unconfirmed), \
                patch("oc_google.native_service.os.close"):
            with self.assertRaises(ValueError) as caught, _run_service(namespace):
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertIs(caught.exception.__cause__, unconfirmed)

    def test_unconfirmed_retirement_preserves_the_post_stop_drain_failure(self):
        service = NativeService(self.unit, Mock(), self.description)
        primary = NativeAcpError("fixture drain failure")
        with patch("oc_google.native_service.signal.pidfd_send_signal"), \
                patch("oc_google.native_service.host", return_value=Mock(returncode=1, stdout=b"")):
            with self.assertRaises(NativeAcpError) as caught:
                _stop(service, self.identity, 9, after_stop=Mock(side_effect=primary))
        self.assertIs(caught.exception, primary)
        self.assertIsInstance(caught.exception.__cause__, NativeRetirementUnconfirmed)
        self.assertIsNone(service.retired)

    def test_broken_stdin_does_not_skip_other_retirement_checks(self):
        service = NativeService(self.unit, Mock(), self.description)
        service.process.stdin.close.side_effect = BrokenPipeError
        receipt = Mock(returncode=0, stdout=b"ActiveState=inactive\nControlGroup=\n")
        with patch("oc_google.native_service.signal.pidfd_send_signal"), \
                patch("oc_google.native_service.host", return_value=receipt):
            _stop(service, self.identity, 9)
        service.process.stdout.close.assert_called_once_with()
        service.process.wait.assert_called_once_with(timeout=3)
        self.assertEqual(service.retired, self.identity)

    def test_empty_unit_is_insufficient_while_original_pidfd_remains_live(self):
        service = NativeService(self.unit, Mock(), self.description)
        receipt = Mock(returncode=0, stdout=b"ActiveState=inactive\nControlGroup=\n")
        self.pid_exited.return_value = False
        with patch("oc_google.native_service.signal.pidfd_send_signal"), \
                patch("oc_google.native_service.host", return_value=receipt):
            with self.assertRaises(NativeRetirementUnconfirmed):
                _stop(service, self.identity, 9)
        self.pid_exited.assert_called_once_with(9)
        self.assertIsNone(service.retired)

    def test_custody_records_exact_reserved_unit_before_spawn_and_original_attestation(self):
        namespace = Mock(unit=self.unit, description=self.description)
        custody = Mock()
        with patch("oc_google.native_service._spawn") as spawn, \
                patch("oc_google.native_service._pin", return_value=(self.identity, 9)), \
                patch("oc_google.native_service._stop") as stop, patch("oc_google.native_service.os.close"):
            steps = Mock()
            steps.attach_mock(custody, "custody")
            steps.attach_mock(spawn, "spawn")

            def retire(service, identity, _fd, _after_stop):
                object.__setattr__(service, "retired", identity)

            stop.side_effect = retire
            with _run_service(namespace, custody=custody) as service:
                self.assertEqual(service.attested, self.identity)
        self.assertEqual(steps.mock_calls, [call.custody.before_spawn(self.unit), call.spawn(namespace),
                                          call.custody.attest(self.identity), call.custody.retire(self.identity)])

    def test_retirement_receipt_failure_preserves_active_error_and_cause(self):
        namespace = Mock(unit=self.unit, description=self.description)
        cause = OSError("fixture underlying primary cause")
        primary = ValueError("fixture enrollment failure")
        storage = OSError("fixture retirement receipt write failed")
        custody = Mock()
        custody.retire.side_effect = storage

        def stopped(service, identity, _fd):
            object.__setattr__(service, "retired", identity)

        with patch("oc_google.native_service._spawn"), \
                patch("oc_google.native_service._pin", return_value=(self.identity, 9)), \
                patch("oc_google.native_service._stop", side_effect=stopped), \
                patch("oc_google.native_service.os.close") as close:
            with self.assertRaises(ValueError) as caught, _run_service(namespace, custody=custody):
                raise primary from cause
        self.assertIs(caught.exception, primary)
        self.assertIs(primary.__cause__, cause)
        uncertainty, = primary.cleanup_uncertainties
        self.assertIsInstance(uncertainty, NativeRetirementUnconfirmed)
        self.assertIs(uncertainty.__cause__, storage)
        custody.retire.assert_called_once_with(self.identity)
        close.assert_called_once_with(9)

    def test_retirement_receipt_failure_alone_reports_typed_uncertainty(self):
        namespace = Mock(unit=self.unit, description=self.description)
        storage = OSError("fixture retirement receipt write failed")
        custody = Mock()
        custody.retire.side_effect = storage

        def stopped(service, identity, _fd, _after_stop):
            object.__setattr__(service, "retired", identity)

        with patch("oc_google.native_service._spawn"), \
                patch("oc_google.native_service._pin", return_value=(self.identity, 9)), \
                patch("oc_google.native_service._stop", side_effect=stopped), \
                patch("oc_google.native_service.os.close"):
            with self.assertRaises(NativeRetirementUnconfirmed) as caught, _run_service(namespace, custody=custody):
                pass
        self.assertIs(caught.exception.__cause__, storage)

    def test_failed_pin_reaps_launcher_even_when_both_pipe_closes_fail(self):
        namespace = Mock(unit=self.unit, description=self.description)
        process = Mock()
        process.poll.return_value = None
        process.stdin.close.side_effect = BrokenPipeError
        process.stdout.close.side_effect = OSError
        pin_error = NativeNamespaceError("fixture identity proof failure")
        with patch("oc_google.native_service._spawn", return_value=process), \
                patch("oc_google.native_service._pin", side_effect=pin_error):
            with self.assertRaises(NativeRetirementUnconfirmed) as result, _run_service(namespace):
                self.fail("a launcher without a pin escaped")
        self.assertIs(result.exception.__cause__, pin_error)
        process.stdin.close.assert_called_once_with()
        process.stdout.close.assert_called_once_with()
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=3)

    def test_interrupted_wait_preserves_the_post_stop_drain_failure(self):
        service = NativeService(self.unit, Mock(), self.description)
        interrupted = KeyboardInterrupt("fixture wait interruption")
        service.process.wait.side_effect = interrupted
        primary = NativeAcpError("fixture drain failure")
        with patch("oc_google.native_service.signal.pidfd_send_signal"):
            with self.assertRaises(NativeAcpError) as caught:
                _stop(service, self.identity, 9, after_stop=Mock(side_effect=primary))
        self.assertIs(caught.exception, primary)
        self.assertIsInstance(caught.exception.__cause__, NativeRetirementUnconfirmed)
        self.assertIs(caught.exception.__cause__.__cause__, interrupted)
        self.assertIsNone(service.retired)

    @patch("oc_google.native_service.os.readlink", return_value="pid:[123]")
    @patch("oc_google.native_service.host")
    def test_group_receipt_requires_exact_active_unit(self, host, _link):
        group = "/user.slice/app.slice/" + self.unit
        invocation = "e" * 32
        identity = (f"Id={self.unit}\nActiveState=active\nControlGroup={group}\nInvocationID={invocation}\n"
                    f"Description={self.description}\nMainPID=123\n").encode()
        host.side_effect = [Mock(stdout=b"pid:[123]\n"), Mock(stdout=identity)]
        process = Mock()
        process.poll.return_value = None
        service = NativeService(self.unit, process, self.description)
        self.assertEqual(service.control_group(), group.encode())

        host.side_effect = [Mock(stdout=b"pid:[123]\n"), Mock(stdout=identity.replace(b"app.slice/", b"app.slice/X"))]
        with self.assertRaises(NativeNamespaceError):
            service.control_group()

    @patch("oc_google.native_service.os.readlink", return_value="pid:[456]")
    @patch("oc_google.native_service.host")
    def test_different_pid_namespace_refuses_group_receipt(self, host, _link):
        host.return_value.stdout = b"pid:[123]\n"
        with self.assertRaises(NativeNamespaceError):
            NativeService(self.unit, Mock(), self.description).control_group()
        host.assert_called_once_with("readlink", "/proc/self/ns/pid", timeout=2)

    @patch("oc_google.native_service.host")
    @patch("oc_google.native_service.signal.pidfd_send_signal")
    def test_retirement_is_checked_after_host_launcher_exits(self, send, host):
        steps = Mock()
        steps.attach_mock(host, "host")
        steps.attach_mock(send, "send")
        process = steps.process
        host.return_value.stdout = b"ActiveState=inactive\nControlGroup=\n"
        host.return_value.returncode = 0

        _stop(NativeService(self.unit, process, self.description), self.identity, 9)

        self.assertEqual(steps.mock_calls, [
            call.send(9, signal.SIGTERM),
            call.process.stdin.close(), call.process.stdout.close(), call.process.wait(timeout=3),
            call.host("systemctl", "--user", "show", "--property=ActiveState,ControlGroup",
                      self.unit, timeout=5, check=False),
            call.host("test", "!", "-e", "/sys/fs/cgroup" + self.identity.group.decode(), timeout=2, check=False),
        ])

    @patch("oc_google.native_service.host")
    @patch("oc_google.native_service.signal.pidfd_send_signal")
    def test_nonempty_control_group_requires_private_tree_retention(self, send, host):
        host.return_value.stdout = b"ActiveState=inactive\nControlGroup=/still-owned.service\n"
        with self.assertRaises(NativeNamespaceError):
            _stop(NativeService(self.unit, Mock(), self.description), self.identity, 9)
        send.assert_called_once_with(9, signal.SIGTERM)

    @patch("oc_google.native_service.host")
    @patch("oc_google.native_service.signal.pidfd_send_signal")
    def test_replacement_unit_is_never_signalled_by_name(self, send, host):
        send.side_effect = ProcessLookupError
        host.side_effect = [Mock(stdout=b"ActiveState=active\nControlGroup=/replacement\n"), Mock(returncode=0)]
        with self.assertRaises(NativeNamespaceError):
            _stop(NativeService(self.unit, Mock(), self.description), self.identity, 9)
        send.assert_called_once_with(9, signal.SIGTERM)
        self.assertEqual([item.args[2] for item in host.call_args_list], ["show", "-e"])

    @patch("oc_google.native_service.host")
    @patch("oc_google.native_service.signal.pidfd_send_signal")
    def test_timed_out_launch_cannot_establish_retirement(self, send, host):
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired("systemd-run", 3), 1]
        with self.assertRaises(NativeNamespaceError):
            _stop(NativeService(self.unit, process, self.description), self.identity, 9)
        send.assert_called_once_with(9, signal.SIGTERM)
        host.assert_not_called()
        process.kill.assert_called_once_with()
