"""Contract checks for the portable CI runner using scratch fixtures and stubs."""

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.ci import run as ci
from tools.ci.supervisor import Supervisor


class PortableTests(unittest.TestCase):
    def test_inventory_order_and_separate_clean_environments(self):
        inherited = dict.fromkeys((
            'HOME', 'TMPDIR', 'XDG_RUNTIME_DIR', 'XDG_CONFIG_DIRS', 'PATH',
            'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_COUNT', 'GIT_TERMINAL_PROMPT',
            'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_SYSTEM',
            'GIT_DIR', 'GIT_INDEX_FILE', 'GIT_EXEC_PATH', 'GIT_TEMPLATE_DIR', 'GIT_SSH_COMMAND',
            'GIT_ASKPASS', 'SSH_ASKPASS', 'SSH_AUTH_SOCK', 'DBUS_SESSION_BUS_ADDRESS', 'WAYLAND_DISPLAY',
            'GITHUB_TOKEN', 'GITHUB_ENV', 'CONTAINER_HOST', 'CONTAINER_ID', 'DOCKER_HOST',
            'OC_TEST_SCRIPT', 'OC_TEST_LOCK_HELPER', 'OC_TEST_NO_PODMAN', 'BASH_ENV', 'PYTHONPATH',
        ), '/host/authority')
        expected = [
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_controller_core.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'bridge_merge_core.py'),
            ('python3', '-B', 'tests/setup-lifecycle.py'),
            ('python3', '-B', 'tests/host_state_leaves.py'),
            ('bash', 'tests/worktrees.sh'),
            ('python3', '-B', 'tests/worktree_review_regressions.py'),
            ('python3', '-B', 'tests/worktree_state_regressions.py'),
            ('bash', 'tests/postgres-host.sh'),
            ('python3', '-B', 'tests/parallel-isolated-test.py'),
            ('python3', '-B', 'tests/parallel-isolated.py'),
            ('bash', 'tests/security.sh'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_ci.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_ci_supervisor.py'),
        ]
        seen = []
        roots = set()

        def audit(command, env, timeout, supervisor, *, scratch):
            seen.append(command)
            root = Path(scratch)
            self.assertNotIn(root, roots)
            roots.add(root)
            self.assertGreater(timeout, 0)
            for directory in (root, *(Path(env[key]) for key in ci.SCRATCH_DIRS)):
                self.assertTrue(directory.is_relative_to(root))
                self.assertTrue(directory.is_dir())
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            expected_env = {
                **{key: str(root / subdir) for key, subdir in ci.SCRATCH_DIRS.items()},
                'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
                'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                'GIT_CONFIG_COUNT': '0', 'GIT_TERMINAL_PROMPT': '0',
            }
            if command == ('bash', 'tests/security.sh'):
                expected_env['OC_TEST_NO_PODMAN'] = '1'
            self.assertEqual(env, expected_env)
            probe = (sys.executable, '-B', '-c', 'import json, os; print(json.dumps(dict(os.environ)))')
            observed = subprocess.check_output(probe, env=env, text=True, timeout=3)
            self.assertEqual(json.loads(observed), expected_env)
            return 'Ran 1 test in 0.001s\n'

        with patch.dict(os.environ, inherited, clear=True), patch.object(ci, 'run', side_effect=audit):
            with redirect_stdout(io.StringIO()) as stdout:
                ci.tests(Supervisor())
        self.assertEqual(seen, expected)
        self.assertTrue(all(not root.exists() for root in roots))
        self.assertEqual([line for line in stdout.getvalue().splitlines() if line.startswith('SKIP')], [
            'SKIP real Podman security checks (portable profile has no configured isolated fixture)',
            'SKIP real Postgres acceptance (portable profile has no configured isolated fixture)',
            'SKIP SELinux/Wayland acceptance (portable profile has no configured isolated fixture)',
            'SKIP remote acceptance (unavailable in the portable profile)',
        ])

    def test_zero_or_missing_test_count_stops_before_next_suite(self):
        for output in ('Ran 0 tests in 0.000s\n\nOK\n', 'OK\n'):
            with self.subTest(output=output), redirect_stdout(io.StringIO()), \
                    patch.object(ci, 'run', return_value=output) as stub:
                with self.assertRaisesRegex(ci.CheckError, 'Controller core.*positive unittest count'):
                    ci.tests(Supervisor())
                self.assertEqual(stub.call_count, 1)

    def test_missing_suite_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as empty, patch.object(ci, 'ROOT', Path(empty)), \
                patch.object(ci, 'run') as stub:
            with self.assertRaisesRegex(ci.CheckError, 'Missing required file tests/test_controller_core.py'):
                ci.tests(Supervisor())
            stub.assert_not_called()

    def test_suite_failure_stops_before_next_suite(self):
        with redirect_stdout(io.StringIO()), \
                patch.object(ci, 'run', side_effect=ci.CheckError('broken suite')) as stub:
            with self.assertRaisesRegex(ci.CheckError, 'broken suite'):
                ci.tests(Supervisor())
            self.assertEqual(stub.call_count, 1)

    def test_first_interrupt_stays_latched_between_suites(self):
        supervisor = Supervisor()

        def finish(command, env, timeout, owner, *, scratch):
            owner.latch(signal.SIGTERM, None)
            owner.latch(signal.SIGINT, None)
            return 'Ran 1 test in 0.001s\n'

        with redirect_stdout(io.StringIO()), patch.object(ci, 'run', side_effect=finish) as stub:
            with self.assertRaisesRegex(ci.CheckError, 'Interrupted by SIGTERM') as failure:
                ci.tests(supervisor)
        self.assertEqual(failure.exception.status, 143)
        self.assertEqual(stub.call_count, 1)
        self.assertFalse(stub.call_args.kwargs['scratch'].exists())

    def test_supervisor_output_read_is_bounded(self):
        def finish(_command, *, cwd, env, log, timeout):
            log.write(b'ABCDEFGHIJ')
            return 0

        supervisor = Supervisor()
        with patch.object(supervisor, 'execute', side_effect=finish), patch.object(ci, 'MAX_LOG_BYTES', 5), \
                redirect_stdout(io.StringIO()) as stdout:
            with self.assertRaisesRegex(ci.CheckError, 'exceeded the 5-byte log limit'):
                ci.run(('fixture',), {}, 3, supervisor)
        self.assertEqual(stdout.getvalue(), 'ABCDE')


class QualityTests(unittest.TestCase):
    def test_scope_and_shellcheck_invocation(self):
        def fake_tools(command, env, timeout, supervisor, **kwargs):
            self.assertEqual(env, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
            self.assertGreater(timeout, 0)
            return '/binary/bash version\n' if command[0].endswith('/bash') else 'version: 0.9.0\n'

        shell_files = (
            'oc-sandbox', 'tests/parallel.sh', 'tests/postgres-host.sh', 'tests/security.sh', 'tests/worktrees.sh',
        )
        with patch.dict(os.environ, {'BASH_ENV': '/host/bashenv', 'SHELLCHECK_OPTS': '-x'}), \
                patch.object(ci, 'tool_required', side_effect=lambda name, path: f'/binary/{name}'), \
                patch.object(ci, 'run', side_effect=fake_tools) as stub, redirect_stdout(io.StringIO()):
            ci.quality(Supervisor())
        self.assertEqual([call.args[0] for call in stub.call_args_list], [
            ('/binary/bash', '--version'),
            ('/binary/shellcheck', '--version'),
            *(('/binary/bash', '-n', '--', name) for name in shell_files),
            ('/binary/shellcheck', '--norc', '--severity=error', '--', *shell_files),
        ])

    def test_new_active_sources_require_explicit_inventory_entries(self):
        with tempfile.TemporaryDirectory() as scratch, patch.object(ci, 'ROOT', Path(scratch)):
            archive = ci.ROOT / 'docs/prds/spikes'
            archive.mkdir(parents=True)
            (archive / 'probe.py').touch()
            ci.validate_scope()
            for name in ('new.sh', 'tests/fixtures/new.py', 'tools/ci/new.py'):
                with self.subTest(name=name):
                    path = ci.ROOT / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.touch()
                    with self.assertRaisesRegex(ci.CheckError, f'Unlisted quality source {name}'):
                        ci.quality(Supervisor())
                    path.unlink()

    def test_missing_or_unsupported_shellcheck_fails(self):
        with patch.dict(os.environ, {'PATH': '/nonexistent-quality-path'}), \
                self.assertRaisesRegex(ci.CheckError, 'Missing required tool shellcheck'):
            ci.quality(Supervisor())
        with patch.object(ci, 'tool_required', side_effect=lambda name, path: f'/binary/{name}'), \
                patch.object(ci, 'run', side_effect=('bash\n', 'version: 0.10.0\n')) as stub, \
                redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ci.CheckError, 'Quality requires ShellCheck 0.9.0'):
                ci.quality(Supervisor())
            self.assertEqual(stub.call_count, 2)


if __name__ == '__main__':
    unittest.main()
