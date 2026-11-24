"""Verify that the developer test runner fences inputs and waits for cleanup."""

import importlib.util
import os
from pathlib import Path
import py_compile
import runpy
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests/e2e/live/test_openai_proof.py"
SPEC = importlib.util.spec_from_file_location("openai_proof_harness", HARNESS)
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class OpenAIProofHarnessTests(unittest.TestCase):
    def test_defaulted_opt_in_starts_no_driver(self):
        config = SimpleNamespace(
            invocation_params=SimpleNamespace(args=(str(HARNESS),)),
            args=[str(HARNESS)], getoption=lambda *_args, **_kwargs: True,
        )
        request = SimpleNamespace(config=config)

        class Skip(Exception):
            pass

        def skip(message):
            raise Skip(message)

        with patch.dict(sys.modules, {"pytest": SimpleNamespace(skip=skip)}):
            with patch.object(harness, "_run_driver", return_value=0) as launch:
                with self.assertRaisesRegex(Skip, "explicit --run-openai-live"):
                    harness.test_attended_openai_route(request)
                launch.assert_not_called()

    def test_defaulted_recovery_choice_starts_no_driver(self):
        config = SimpleNamespace(
            invocation_params=SimpleNamespace(args=("--run-openai-live", str(HARNESS))),
            args=[str(HARNESS)], getoption=lambda *_args, **_kwargs: True,
        )
        request = SimpleNamespace(config=config)

        class Refused(Exception):
            pass

        def fail(message, *, pytrace):
            raise Refused(message)

        with patch.dict(sys.modules, {"pytest": SimpleNamespace(fail=fail)}):
            with patch.object(harness, "_run_driver", return_value=0) as launch:
                with self.assertRaisesRegex(Refused, "explicit recovery option"):
                    harness.test_attended_openai_route(request)
                launch.assert_not_called()

    def test_untrusted_source_is_rejected_before_spawning(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            (root / "oc-openai.py").touch()
            driver = root / "tests/e2e/live/openai_driver.py"
            driver.parent.mkdir(parents=True)
            driver.symlink_to("/dev/null")
            with patch.object(harness, "_wait_for_proof") as launch:
                with self.assertRaisesRegex(ValueError, "source file is unprotected"):
                    harness._run_driver(root, root)
                launch.assert_not_called()

    def test_real_driver_refuses_unattended_invocation(self):
        result = subprocess.run(
            ["/usr/bin/python3", "-IB", str(HARNESS.with_name("openai_driver.py"))],
            cwd=ROOT, env={"HOME": "/nonexistent", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("An attended workstation terminal", result.stderr)

    def test_recovery_requires_digest_then_uses_a_source_only_snapshot(self):
        helpers = runpy.run_path(str(HARNESS.with_name("openai_driver.py")))
        digest, _ = harness._capture_sources(ROOT, HARNESS.with_name("openai_driver.py"))
        with patch.object(harness, "_wait_for_proof") as launch:
            with self.assertRaisesRegex(ValueError, "does not match reviewed source"):
                harness._run_driver(ROOT, ROOT, recovery_source="0" * 64)
            launch.assert_not_called()

        def run_snapshot(command, *, root, env):
            self.assertNotEqual(root, ROOT)
            self.assertEqual(helpers["snapshot_digest"](root), digest)
            result = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("An attended workstation terminal", result.stderr)
            return 2

        with patch.object(harness, "_wait_for_proof", side_effect=run_snapshot):
            self.assertEqual(harness._run_driver(ROOT, ROOT, recovery_source=digest), 2)

    def test_digest_mismatch_never_executes_candidate_driver(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            marker = root / "driver-executed"
            (root / "oc-openai.py").touch()
            (root / "oc_openai/managed").mkdir(parents=True)
            driver = root / "tests/e2e/live/openai_driver.py"
            driver.parent.mkdir(parents=True)
            driver.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
                "def proof_sources(root): return {}\n"
                "def source_digest(files): return 'different-digest'\n"
            )
            with patch.object(harness, "_wait_for_proof") as launch:
                with self.assertRaisesRegex(ValueError, "does not match reviewed source"):
                    harness._run_driver(root, root, recovery_source="0" * 64)
                launch.assert_not_called()
            self.assertFalse(marker.exists())

    def test_bootstrap_ignores_adjacent_bytecode(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            driver = root / "tests/e2e/live/openai_driver.py"
            driver.parent.mkdir(parents=True)
            driver.write_bytes(HARNESS.with_name(driver.name).read_bytes())
            bootstrap = root / "oc-openai.py"
            bootstrap.write_text(
                'from pathlib import Path\nPath("cached-bootstrap-ran").touch()\n'
                'def load_cli():\n    raise ImportError("fixture")\n',
            )
            py_compile.compile(str(bootstrap), doraise=True,
                               invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
            bootstrap.write_text('def load_cli():\n    raise ImportError("fixture")\n')
            result = subprocess.run(
                ["/usr/bin/python3", "-IB", str(driver)],
                cwd=root, env={"HOME": scratch, "PATH": "/usr/bin:/bin"},
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("trusted workstation source unavailable", result.stderr)
            self.assertFalse((root / "cached-bootstrap-ran").exists())

    def test_interrupt_waits_to_reap_child_after_cleanup(self):
        child_code = """
from pathlib import Path
import signal
import time
try:
    Path("created").touch()
    signal.pause()
finally:
    time.sleep(0.3)
    Path("created").unlink()
    Path("cleaned").touch()
"""
        parent_code = """
import runpy
import sys
from pathlib import Path
wait = runpy.run_path(sys.argv[1])["_wait_for_proof"]
try:
    wait([sys.executable, "-IB", "-c", sys.argv[2]], root=Path.cwd(), env={})
except KeyboardInterrupt:
    if Path("cleaned").is_file() and not Path("created").exists():
        sys.exit(130)
sys.exit(1)
"""
        with tempfile.TemporaryDirectory() as scratch:
            process = subprocess.Popen(
                ["/usr/bin/python3", "-IB", "-c", parent_code, str(HARNESS), child_code],
                start_new_session=True, cwd=scratch, env={},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                created = Path(scratch) / "created"
                deadline = time.monotonic() + 5
                while not created.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(created.exists(), "synthetic child did not start")
                os.killpg(process.pid, signal.SIGINT)
                self.assertEqual(process.wait(timeout=5), 130)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
