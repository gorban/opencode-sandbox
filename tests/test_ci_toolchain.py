"""Offline checks for the managed mise and ShellCheck quality path."""

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from tools.ci import run as ci
from tools.ci import toolchain as tc
from tools.ci.supervisor import Supervisor, supervise


class FakeMise:
    def __init__(self, *, bad_config=None, changed_lock=False, wrong_path=None):
        self.bad_config = bad_config
        self.changed_lock = changed_lock
        self.wrong_path = wrong_path
        self.calls = []
        self.env = None

    def call(self, command, env, timeout, supervisor, *, scratch, print_output=True):
        mise, cd, project, *args = command
        assert (mise, cd, project) == (str(scratch / 'mise'), '--cd', str(scratch / 'project'))
        assert timeout > 0
        if self.env is None:
            self.env = env.copy()
        assert env == self.env
        self.calls.append(tuple(args))
        project = Path(project)
        if args == ['config', 'ls', '--json']:
            configs = [
                {'path': str(project / 'mise.toml'), 'tools': [tc.BACKEND], 'override': False},
                {'path': env['MISE_GLOBAL_CONFIG_FILE'], 'tools': [], 'override': False},
            ]
            if self.bad_config:
                return self.bad_config(project, configs)
            return json.dumps(configs)
        if args == ['install', '--locked']:
            if self.changed_lock:
                (project / 'mise.lock').write_text('changed by stub')
            self.installed = Path(env['MISE_INSTALLS_DIR']) / 'shellcheck'
            self.installed.touch(mode=0o700)
        if args == ['which', 'shellcheck']:
            return str(self.wrong_path(self.installed, scratch) if self.wrong_path else self.installed) + '\n'
        return ''


class ManagedQualityTests(unittest.TestCase):
    def manage(self, fake):
        def bootstrap(scratch, env, supervisor):
            self.assertFalse(any(key.startswith('MISE_') for key in env))
            self.assertEqual(env['PATH'], '/usr/bin:/bin')
            return scratch / 'mise'

        inherited = dict.fromkeys((
            'MISE_DATA_DIR', 'MISE_ENV', 'MISE_GLOBAL_CONFIG_FILE', 'MISE_TRUSTED_CONFIG_PATHS',
            'MISE_INSTALLS_DIR', 'MISE_SHARED_INSTALL_DIRS', 'MISE_CEILING_PATHS', 'HOME', 'XDG_CONFIG_HOME',
            'GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_API_TOKEN', 'MISE_GITHUB_TOKEN',
            'MISE_GITHUB_ATTESTATIONS', 'MISE_GITHUB_GITHUB_ATTESTATIONS',
            'https_proxy', 'LD_PRELOAD', 'BASH_ENV', 'PYTHONPATH', 'CURL_HOME',
        ), '/inherited/authority')
        with patch.object(tc, 'bootstrap_mise', side_effect=bootstrap), patch.object(ci, 'run', side_effect=fake.call), \
                patch.dict(os.environ, inherited, clear=True):
            tc.managed_quality(Supervisor(), hosted=False)

    def test_exact_locked_calls_and_private_configuration(self):
        fake = FakeMise()
        self.manage(fake)
        env = fake.env
        scratch = Path(env['MISE_CEILING_PATHS'])
        project = scratch / 'project'
        config_check = ('config', 'ls', '--json')
        self.assertEqual(fake.calls, [
            ('trust', str(project / 'mise.toml')), config_check, ('install', '--locked'),
            config_check, ('which', 'shellcheck'), config_check,
            ('exec', '--', '/usr/bin/python3', '-I', '-B', '-c', tc.QUALITY_GUARD,
             str(fake.installed), str(ci.ROOT / 'tools/ci/run.py')),
        ])
        expected = {
            'MISE_CEILING_PATHS': str(scratch), 'MISE_OVERRIDE_CONFIG_FILENAMES': 'mise.toml',
            'MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES': '.oc-ci-disabled-tool-versions',
            'MISE_IDIOMATIC_VERSION_FILE_ENABLE_TOOLS': '', 'MISE_TMP_DIR': env['TMPDIR'],
            'MISE_GLOBAL_CONFIG_FILE': str(scratch / 'empty.toml'),
            'MISE_SYSTEM_CONFIG_FILE': str(scratch / 'empty.toml'),
            'MISE_NO_ENV': '1', 'MISE_NO_HOOKS': '1', 'MISE_AUTO_INSTALL': '0',
            'MISE_PARANOID': '1', 'MISE_LOCKED': '1',
        }
        for key in tc.MISE_DIRS:
            self.assertTrue(Path(env[key]).is_relative_to(scratch))
            expected[key] = env[key]
        self.assertEqual(len({env[key] for key in tc.MISE_DIRS}), len(tc.MISE_DIRS))
        self.assertEqual({key: value for key, value in env.items() if key.startswith('MISE_')}, expected)
        self.assertFalse(any('inherited' in value for value in env.values()))
        self.assertFalse(scratch.exists())

    def test_unexpected_config_stops_before_install(self):
        bad_configs = (
            lambda project, configs: json.dumps([configs[0], configs[0]]),
            lambda project, configs: json.dumps([*configs, dict(configs[0], path=str(project.parent / 'mise.toml'))]),
            lambda project, configs: json.dumps([dict(configs[0], path=str(project / '.tool-versions')), configs[1]]),
            lambda project, configs: json.dumps([dict(configs[0], tools=['other']), configs[1]]),
            lambda project, configs: json.dumps([dict(configs[0], override=0), configs[1]]),
            lambda project, configs: 'not JSON',
            lambda project, configs: json.dumps(configs).replace('"override": false', '"override": true,"override": false'),
        )
        for bad in bad_configs:
            with self.subTest(bad=bad):
                fake = FakeMise(bad_config=bad)
                with self.assertRaises((ci.CheckError, ValueError)):
                    self.manage(fake)
                self.assertEqual([call[0] for call in fake.calls], ['trust', 'config'])

    def test_lock_mutation_and_paths_outside_install_root_abort(self):
        changed = FakeMise(changed_lock=True)
        with self.assertRaisesRegex(ci.CheckError, 'Private mise input changed: mise.lock'):
            self.manage(changed)
        self.assertEqual(changed.calls[-1], ('install', '--locked'))

        def outside_alias(installed, scratch):
            shared = scratch / 'mise-shared-installs' / 'shellcheck'
            shared.touch(mode=0o700)
            alias = installed.with_name('alias')
            alias.symlink_to(shared)
            return alias

        for bad_path in (lambda installed, scratch: Path('/usr/bin/shellcheck'), outside_alias):
            with self.subTest(bad_path=bad_path):
                fake = FakeMise(wrong_path=bad_path)
                with self.assertRaisesRegex(ci.CheckError, 'did not select an executable ShellCheck'):
                    self.manage(fake)
                self.assertEqual(fake.calls[-1], ('which', 'shellcheck'))

    def test_exec_guard_checks_effective_path_before_running_shared_quality(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            shellcheck = root / 'shellcheck'
            shellcheck.touch(mode=0o700)
            runner = root / 'run.py'
            runner.write_text('import sys; print("shared runner", sys.argv[1])\n')
            command = (tc.SYSTEM_PYTHON, '-I', '-B', '-c', tc.QUALITY_GUARD, str(shellcheck), str(runner))
            for path, expected in ((str(root), 0), ('/usr/bin:/bin', 1)):
                result = subprocess.run(command, env={'PATH': path}, text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual('shared runner quality' in result.stdout, expected == 0)


class PrerequisiteAndBootstrapTests(unittest.TestCase):
    def test_unsupported_platform_stops_before_reading_inputs(self):
        with patch.object(tc.platform, 'machine', return_value='aarch64'), \
                patch.object(tc, 'validated_inputs') as inputs, patch.object(tc, 'bootstrap_mise') as bootstrap:
            with self.assertRaisesRegex(ci.CheckError, 'requires Linux x86-64'):
                tc.managed_quality(Supervisor(), hosted=False)
        inputs.assert_not_called()
        bootstrap.assert_not_called()

    def test_hosted_first_checks_system_version_and_short_circuits_drift(self):
        for output, message in ((FileNotFoundError(), 'observed missing'), ('not a version', 'malformed output'),
                                ('version: 0.9.0\nversion: invalid report\n', 'malformed output'),
                                ('version: 0.10.0\n', 'observed 0.10.0'),
                                ('version: 0.9.0\n', 'checked inputs')):
            def probe(_command, _env, _timeout, _supervisor, *, scratch, print_output):
                info = scratch.stat()
                self.assertEqual((info.st_uid, info.st_mode & 0o777), (os.getuid(), 0o700))
                self.assertFalse(print_output)
                if isinstance(output, Exception):
                    raise output
                return output

            with self.subTest(output=output), patch.object(ci, 'run', side_effect=probe) as run, \
                    patch.object(tc, 'validated_inputs', side_effect=ci.CheckError('checked inputs')) as validated, \
                    patch.object(tc, 'bootstrap_mise') as bootstrap, redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ci.CheckError, message):
                    tc.managed_quality(Supervisor(), hosted=True)
                self.assertEqual(run.call_args.args[:2], (('/usr/bin/shellcheck', '--version'),
                                                         {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'}))
                self.assertEqual(run.call_count, 1)
                self.assertFalse(run.call_args.kwargs['scratch'].exists())
                self.assertEqual(validated.call_count, int(message == 'checked inputs'))
                bootstrap.assert_not_called()

    def test_shellcheck_pin_uses_the_public_asset_without_an_attestation_lookup(self):
        files = tc.validated_inputs()
        manifest = tomllib.loads(files['mise.toml'].decode())
        self.assertEqual(manifest['tools'][tc.BACKEND],
                         {'version': tc.SHELLCHECK, 'github_attestations': False})
        lock = tomllib.loads(files['mise.lock'].decode())
        platform = lock['tools'][tc.BACKEND][0][f'platforms.{tc.PLATFORM}']
        self.assertEqual(platform, {'url': tc.SHELLCHECK_URL, 'checksum': tc.SHELLCHECK_CHECKSUM})

    def test_input_pins_and_no_follow_before_bootstrap(self):
        files = tc.validated_inputs()
        with tempfile.TemporaryDirectory() as scratch, patch.object(ci, 'ROOT', Path(scratch)), \
                patch.object(tc, 'bootstrap_mise') as bootstrap:
            directory = ci.ROOT / 'tools/ci'
            directory.mkdir(parents=True)
            for name, content in files.items():
                (directory / name).write_bytes(content)
            for name, old, new in (('mise.toml', b'lockfile = true', b'lockfile = 1'),
                                   ('mise.toml', b'lockfile = true',
                                    b'lockfile = true\ngithub_attestations = false'),
                                   ('mise.toml', b'0.9.0', b'0.10.0'),
                                   ('mise.toml', b', github_attestations = false', b''),
                                   ('mise.toml', b'github_attestations = false', b'github_attestations = true'),
                                   ('mise.toml', b'github_attestations = false', b'github_attestations = "false"'),
                                   ('mise.toml', b'github_attestations = false', b'github_attestations = 0'),
                                   ('mise.lock', b'github.com', b'example.invalid'),
                                   ('mise.lock', tc.SHELLCHECK_CHECKSUM.encode(), b'sha256:wrong'),
                                   ('mise.lock', b'checksum = ',
                                    b'url_api = "https://api.github.com/repos/koalaman/shellcheck/releases/assets/88000708"\n'
                                    b'checksum = '),
                                   ('mise.lock', b'checksum = ',
                                    b'provenance = "github-attestations"\nchecksum = '),
                                   ('mise.lock', b'linux-x64', b'linux-arm64')):
                with self.subTest(name=name, new=new):
                    path = directory / name
                    path.write_bytes(files[name].replace(old, new))
                    with self.assertRaisesRegex(ci.CheckError, 'Invalid CI mise'):
                        tc.managed_quality(Supervisor(), hosted=False)
                    path.write_bytes(files[name])
            manifest = directory / 'mise.toml'
            backup = manifest.rename(directory / 'elsewhere.toml')
            manifest.symlink_to(backup)
            with self.assertRaises(OSError):
                tc.managed_quality(Supervisor(), hosted=False)
            bootstrap.assert_not_called()

    def test_download_is_bounded_and_archive_digest_precedes_parsing(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / 'mise.tar.xz').write_bytes(b'not an approved archive')
            command_env = {'PATH': '/usr/bin:/bin'}
            with patch.object(ci, 'run') as run, patch.object(tarfile, 'open') as parse:
                with self.assertRaisesRegex(ci.CheckError, 'archive SHA-256'):
                    tc.bootstrap_mise(root, command_env, Supervisor())
                parse.assert_not_called()
            command, env, timeout, _ = run.call_args.args
            self.assertEqual(command, (
                '/usr/bin/python3', '-I', '-B', '-c', tc.FILE_LIMITED_EXEC, str(tc.ARCHIVE_LIMIT),
                '/usr/bin/curl', '--disable', '--fail', '--silent', '--show-error', '--location',
                '--proto', '=https', '--proto-redir', '=https', '--max-redirs', '5',
                '--connect-timeout', '10', '--max-time', '90', '--max-filesize', str(tc.ARCHIVE_LIMIT),
                '--output', str(root / 'mise.tar.xz'), '--', tc.MISE_URL,
            ))
            self.assertEqual(env, command_env)
            self.assertGreater(timeout, 0)

    def test_kernel_caps_download_even_if_the_child_ignores_size(self):
        limit = 4096
        with supervise() as supervisor, ci.suite_scratch(supervisor) as root:
            archive = root / 'mise.tar.xz'
            env = {'PATH': '/usr/bin:/bin'}
            writer = ('/usr/bin/python3', '-I', '-B', '-c',
                      'from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b"x" * int(sys.argv[2]))',
                      str(archive), str(limit * 2))
            run = ci.run
            run(writer, env, 5, supervisor, scratch=root)
            self.assertEqual(archive.stat().st_size, 2 * limit)
            archive.unlink()

            def replace_curl(command, *args, **kwargs):
                return run((*command[:command.index('/usr/bin/curl')], *writer), *args, **kwargs)

            with patch.object(tc, 'ARCHIVE_LIMIT', limit), patch.object(ci, 'run', side_effect=replace_curl), \
                    patch.object(tc, 'extract_mise') as extract, redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ci.CheckError, 'Command exited with status'):
                    tc.bootstrap_mise(root, env, supervisor)
            self.assertEqual(archive.stat().st_size, limit)
            extract.assert_not_called()

    def test_download_wrapper_preserves_stricter_inherited_limits(self):
        py = '/usr/bin/python3'
        set_limits = ('import os, resource, sys; resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 2048)); '
                      'os.execv(sys.argv[1], sys.argv[1:])')
        read_limits = 'import resource; print(*resource.getrlimit(resource.RLIMIT_FSIZE))'
        command = (py, '-I', '-B', '-c', set_limits, py, '-I', '-B', '-c', tc.FILE_LIMITED_EXEC, '4096',
                   py, '-I', '-B', '-c', read_limits)
        result = subprocess.run(command, env={'PATH': '/usr/bin:/bin'}, text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '1024 2048\n')

    def test_stream_only_regular_pinned_mise_member_and_reject_duplicates(self):
        content = b'only the pinned binary bytes'
        checksum = hashlib.sha256(content).hexdigest()
        for members, digest, kind in ((1, checksum, tarfile.REGTYPE), (1, 'incorrect', tarfile.REGTYPE),
                                      (2, checksum, tarfile.REGTYPE), (1, checksum, tarfile.SYMTYPE)):
            with self.subTest(members=members, digest=digest, kind=kind), tempfile.TemporaryDirectory() as scratch:
                archive, output = Path(scratch) / 'mise.tar.xz', Path(scratch) / 'mise'
                with tarfile.open(archive, 'w:xz') as target:
                    member = tarfile.TarInfo(tc.MISE_MEMBER)
                    member.type = kind
                    member.size = len(content) if kind == tarfile.REGTYPE else 0
                    for _ in range(members):
                        target.addfile(member, io.BytesIO(content))
                sha = hashlib.sha256(archive.read_bytes()).hexdigest()
                with patch.object(tc, 'MISE_ARCHIVE_SHA', sha), patch.object(tc, 'MISE_BINARY_SHA', digest), \
                        patch.object(tc, 'MISE_BINARY_SIZE', len(content)):
                    if (members, digest, kind) == (1, checksum, tarfile.REGTYPE):
                        tc.extract_mise(archive, output, Supervisor())
                        self.assertEqual(output.read_bytes(), content)
                        self.assertTrue(os.access(output, os.X_OK))
                    else:
                        with self.assertRaises(ci.CheckError):
                            tc.extract_mise(archive, output, Supervisor())
                        self.assertFalse(os.access(output, os.X_OK))
