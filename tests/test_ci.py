"""Contract checks for the portable CI runner using scratch fixtures and stubs."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.ci import core_coverage
from tools.ci import run as ci
from tools.ci import supervisor as lifecycle
from tools.ci.supervisor import Supervisor


class CoverageTests(unittest.TestCase):
    def test_checkout_cannot_shadow_coverage_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            python = root / 'venv/bin/python'
            subprocess.run([sys.executable, '-Im', 'venv', '--without-pip', str(root / 'venv')],
                           check=True, timeout=30)
            site_packages = subprocess.check_output(
                [str(python), '-IB', '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'],
                text=True, timeout=10,
            ).strip()
            self.assertTrue(Path(site_packages).resolve().is_relative_to(root.resolve()))
            package = Path(site_packages) / 'coverage'
            package.mkdir()
            (package / '__init__.py').touch()
            (package / 'cmdline.py').write_text(
                'import sys\nfrom pathlib import Path\n\n'
                'def main():\n'
                '    if sys.argv[1] == "run":\n'
                '        import core_fixture\n'
                '        assert core_fixture.loaded\n'
                '    with Path("calls").open("a") as calls:\n'
                '        print(sys.argv[1], file=calls)\n'
            )
            (root / 'core_fixture.py').write_text('loaded = True\n')
            (root / 'coverage.py').write_text('raise SystemExit(91)\n')
            with patch.object(core_coverage, 'ROOT', root), \
                    patch.object(core_coverage, 'install_coverage', return_value=str(python)), \
                    patch.object(core_coverage, 'report_coverage'):
                core_coverage.main()
            self.assertEqual((root / 'calls').read_text().splitlines(), ['run', 'run', 'json', 'xml'])


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
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_orchestrator_text.py'),
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
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_ci_toolchain.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_sonar_publisher.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_cli.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_cli_launcher.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_proof_harness.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_connection.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_connection_job.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_connection_transport.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_exposure.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_live.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_recovery.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_profile_backend.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_profiles.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_worker.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_provider_contracts.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_provider_config.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_provider_catalog.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_session_leases.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_session_protocol.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_session_broker.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_canary.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_openai_shell_e2e_harness.py'),
            ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_supply_chain_pins.py'),
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

    def test_interruption_latched_during_supervisor_teardown(self):
        prctl = lifecycle.prctl
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=sig.name):
                sets = 0

                def interrupt_on_restore(operation, argument):
                    nonlocal sets
                    prctl(operation, argument)
                    if operation == lifecycle.PR_SET_CHILD_SUBREAPER:
                        sets += 1
                        if sets == 2:
                            signal.getsignal(sig)(sig, None)

                with patch.object(lifecycle, 'prctl', side_effect=interrupt_on_restore), \
                        patch.object(ci, 'tests') as phase, patch.object(sys, 'argv', ['ci', 'tests']), \
                        redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual(ci.main(), 128 + sig)
                phase.assert_called_once()
                self.assertIn(f'Interrupted by {sig.name}', stderr.getvalue())

    def test_scratch_cleanup_error_preserves_original_base_exception(self):
        failure = KeyboardInterrupt('original portable test failure')
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / 'scratch'
            root.mkdir(mode=0o700)
            with patch.object(ci.tempfile, 'mkdtemp', return_value=str(root)), \
                    patch.object(ci, 'remove_scratch', side_effect=AssertionError('cleanup failed')) as cleanup, \
                    self.assertRaises(KeyboardInterrupt) as caught:
                with ci.suite_scratch(Supervisor()):
                    raise failure
        cleanup.assert_called_once()
        self.assertIs(caught.exception, failure)
        self.assertEqual(failure.__notes__, ['cleanup failed'])

    def test_supervisor_output_read_is_bounded(self):
        def finish(_command, *, cwd, env, log, timeout):
            log.write(b'ABCDEFGHIJ')
            return 0

        supervisor = Supervisor()
        with patch.object(supervisor, 'execute', side_effect=finish), patch.object(ci, 'MAX_LOG_BYTES', 5), \
                ci.suite_scratch(supervisor) as scratch, redirect_stdout(io.StringIO()) as stdout:
            with self.assertRaisesRegex(ci.CheckError, 'exceeded the 5-byte log limit'):
                ci.run(('fixture',), {}, 3, supervisor, scratch=scratch)
        self.assertEqual(stdout.getvalue(), 'ABCDE')


class QualityTests(unittest.TestCase):
    def test_scope_and_shellcheck_invocation(self):
        def fake_tools(command, env, timeout, supervisor, *, scratch, print_output=True):
            self.assertEqual(env, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
            self.assertGreater(timeout, 0)
            info = scratch.stat()
            self.assertEqual((info.st_uid, info.st_mode & 0o777), (os.getuid(), 0o700))
            return '/binary/bash version\n' if command[0].endswith('/bash') else 'version: 0.9.0\n'

        shell_files = (
            'oc-sandbox', 'tests/parallel.sh', 'tests/postgres-host.sh',
            'tests/bridge-manager-fixture.sh', 'tests/security.sh', 'tests/worktrees.sh',
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
        scratch_paths = {call.kwargs['scratch'] for call in stub.call_args_list}
        self.assertEqual(len(scratch_paths), 1)
        self.assertFalse(scratch_paths.pop().exists())

    def test_new_active_sources_require_explicit_inventory_entries(self):
        with tempfile.TemporaryDirectory() as scratch, patch.object(ci, 'ROOT', Path(scratch)):
            archive = ci.ROOT / 'docs/prds/spikes'
            archive.mkdir(parents=True)
            (archive / 'probe.py').touch()
            ci.validate_scope()
            for name in ('new.sh', 'tests/fixtures/new.py', 'tools/ci/new.py', 'oc_openai/new.py'):
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
            self.assertFalse(stub.call_args.kwargs['scratch'].exists())


class RenovateConfigTests(unittest.TestCase):
    """Renovate may only propose updates for the pins it is scoped to; a person merges them."""

    ROOT = Path(__file__).resolve().parents[1]

    def setUp(self):
        self.config = json.loads((self.ROOT / '.github/renovate.json').read_text(encoding='utf-8'))

    def image_pattern(self):
        (manager,) = self.config['customManagers']
        self.assertEqual(manager['customType'], 'regex')
        self.assertEqual(manager['managerFilePatterns'], ['/^oc-sandbox$/'])
        self.assertEqual(manager['datasourceTemplate'], 'docker')
        (pattern,) = manager['matchStrings']
        # Renovate uses RE2, which has no lookaround or backreferences.
        for unsupported in ('(?=', '(?!', '(?<=', '(?<!', '\\1'):
            self.assertNotIn(unsupported, pattern)
        return re.compile(pattern.replace('(?<', '(?P<'))

    def test_never_merges_or_publishes_vulnerability_state(self):
        self.assertIs(self.config['automerge'], False)
        self.assertIs(self.config['platformAutomerge'], False)
        self.assertEqual(self.config['vulnerabilityAlerts'], {'enabled': False})
        self.assertIs(self.config['osvVulnerabilityAlerts'], False)
        self.assertEqual(self.config['extends'], [':disableDependencyDashboard'])
        for rule in self.config['packageRules']:
            self.assertNotIn('automerge', rule)
            self.assertNotIn('platformAutomerge', rule)
            self.assertNotIn('vulnerabilityAlerts', rule)
            self.assertNotIn('osvVulnerabilityAlerts', rule)

    def test_schedule_and_concurrency(self):
        self.assertEqual(self.config['schedule'], ['* 0-5 * * 1'])
        self.assertEqual(self.config['prConcurrentLimit'], 3)
        self.assertEqual(self.config['prHourlyLimit'], 1)

    def test_scope_is_launcher_images_and_ci_tools(self):
        self.assertEqual(self.config['enabledManagers'], ['custom.regex', 'mise'])
        self.assertEqual(self.config['includePaths'], ['oc-sandbox', 'tools/ci/mise.toml', 'tools/ci/mise.lock'])
        self.assertEqual(self.config['minimumReleaseAge'], '7 days')
        self.assertEqual(self.config['minimumReleaseAgeBehaviour'], 'timestamp-required')
        self.assertEqual(self.config['internalChecksFilter'], 'strict')
        for rule in self.config['packageRules']:
            self.assertNotIn('minimumReleaseAge', rule)
        untimed = [rule for rule in self.config['packageRules']
                   if rule.get('minimumReleaseAgeBehaviour') == 'timestamp-optional']
        (registry_rule,) = untimed
        self.assertEqual(registry_rule['matchDatasources'], ['docker'])
        self.assertEqual(registry_rule['matchPackageNames'], ['ghcr.io/**', 'quay.io/**', 'registry.fedoraproject.org/**'])
        self.assertEqual(registry_rule['addLabels'], ['no-release-age-check'])

    def test_mise_artifacts_stay_under_manual_control(self):
        (mise_rule,) = [rule for rule in self.config['packageRules'] if rule.get('matchManagers') == ['mise']]
        self.assertIs(mise_rule['skipArtifactsUpdate'], True)
        self.assertEqual(mise_rule['addLabels'], ['needs-checksum-update'])

    def test_every_digest_pinned_launcher_image_is_matched(self):
        pattern = self.image_pattern()
        launcher = (self.ROOT / 'oc-sandbox').read_text(encoding='utf-8')
        matches = list(pattern.finditer(launcher))
        self.assertGreaterEqual(len(matches), 1)
        self.assertEqual(len(matches), launcher.count('@sha256:'))
        for found in matches:
            self.assertRegex(found.group('depName'), r'^[a-z0-9.-]+\.[a-z]+/')
            self.assertTrue(found.group('currentValue'))

    def test_image_pattern_forms(self):
        pattern = self.image_pattern()
        digest = 'sha256:' + 'a' * 64
        for name, tag in (('docker.io/library/python', '3.12-alpine'), ('ghcr.io/example/tool', '2.3.0'),
                          ('quay.io/example/stable', 'v6.2.0'), ('registry.example.org/base', '45')):
            found = pattern.search(f'FROM {name}:{tag}@{digest}')
            self.assertIsNotNone(found, name)
            self.assertEqual((found.group('depName'), found.group('currentValue'), found.group('currentDigest')),
                             (name, tag, digest))
        for unpinned in ('FROM registry.example.org/base:latest', f'FROM docker.io/library/python@{digest}',
                         'IMAGE=${OC_IMAGE:-quay.io/example/stable:latest}'):
            self.assertIsNone(pattern.search(unpinned), unpinned)


if __name__ == '__main__':
    unittest.main()
