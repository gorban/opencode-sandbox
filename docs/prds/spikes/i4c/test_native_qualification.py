"""Offline regressions for the evidence accepted by the native qualification probe."""

from contextlib import nullcontext
from pathlib import Path
import runpy
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).parent
HOST = runpy.run_path(str(ROOT / "qualify-native.py"))
NATIVE = runpy.run_path(str(ROOT / "native-fixture.py"))


class QualificationTest(unittest.TestCase):
    def test_failed_stop_does_not_prove_cancellation(self):
        stop = HOST["stop"]
        requested = subprocess.CompletedProcess([], 1, stdout=b"")
        status = subprocess.CompletedProcess([], 0, stdout=b"ActiveState=failed\nControlGroup=\n")
        with patch.dict(stop.__globals__, host=Mock(side_effect=(requested, status))):
            with self.assertRaisesRegex(HOST["QualificationError"], "live service stop"):
                stop("fixture.service", require_success=True)

    def test_unresolved_start_receipt_requires_retention(self):
        process = Mock()
        process.wait.side_effect = subprocess.TimeoutExpired([], 5)
        with self.assertRaises(HOST["RetirementUnknown"]):
            HOST["wait_for_launch_receipt"](process)

    def test_only_exact_native_authentication_error_confirms_signed_out(self):
        check = NATIVE["require_authentication"]
        check({"error": {"code": -32000, "message": "Authentication required"}})
        for code, message in ((-32000.0, "Authentication required"), (-32000, "No authentication required")):
            with self.subTest(code=code, message=message), self.assertRaises(ValueError):
                check({"error": {"code": code, "message": message}})

    def test_agy_starts_in_empty_workspace_with_log_outside(self):
        verify = NATIVE["signed_out"]
        with TemporaryDirectory() as directory:
            workspace = Path(directory) / "empty"
            workspace.mkdir()

            def child(command, _env, *, acp, cwd):
                self.assertTrue(acp)
                self.assertEqual(cwd, workspace)
                self.assertEqual(Path(command[-1]).parent, workspace.parent)
                return nullcontext(object())

            hello = {"result": {"protocolVersion": 1}}
            signed_out = {"error": {"code": -32000, "message": "Authentication required"}}
            responses = Mock(side_effect=(hello, signed_out))
            with patch.dict(verify.__globals__, running=child, exchange=responses):
                verify(workspace, {})
                self.assertEqual(responses.call_count, 2)
            (workspace / "unexpected").touch()
            responses = Mock(return_value=hello)
            with patch.dict(verify.__globals__, running=child, exchange=responses):
                with self.assertRaisesRegex(ValueError, "workspace changed"):
                    verify(workspace, {})
                self.assertEqual(responses.call_count, 1)


if __name__ == "__main__":
    unittest.main()
