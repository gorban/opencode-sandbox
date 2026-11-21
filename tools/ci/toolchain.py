#!/usr/bin/env python3
"""Install the pinned CI quality tools in private scratch and run the shared checker."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tarfile
import tomllib

if __package__:
    from . import run as ci
else:
    import run as ci


BACKEND = 'github:koalaman/shellcheck'
PLATFORM = 'linux-x64'
SHELLCHECK = ci.SHELLCHECK_VERSION
SHELLCHECK_URL = (f'https://github.com/koalaman/shellcheck/releases/download/v{SHELLCHECK}/'
                  f'shellcheck-v{SHELLCHECK}.linux.x86_64.tar.xz')
SHELLCHECK_API = 'https://api.github.com/repos/koalaman/shellcheck/releases/assets/88000708'
SHELLCHECK_CHECKSUM = 'sha256:700324c6dd0ebea0117591c6cc9d7350d9c7c5c287acbad7630fa17b1d4d9e2f'
MISE_URL = 'https://github.com/jdx/mise/releases/download/v2026.10.21/mise-v2026.10.21-linux-x64.tar.xz'
MISE_ARCHIVE_SHA = 'e1743bb7628927f93d4ffb2c4e2c4f71186307612f59ebc7f85d52e3a7f42461'
MISE_BINARY_SHA = 'ccfe12d7a62c6fb9def2a20db1f210f13a51de881f21fd8c85db4b6312405d07'
MISE_MEMBER = 'mise/bin/mise'
MISE_BINARY_SIZE = 175698560
ARCHIVE_LIMIT = 64 * 1024 * 1024
CONFIG_LIMIT = 16 * 1024
SYSTEM_PYTHON = '/usr/bin/python3'

MISE_DIRS = {
    'MISE_CONFIG_DIR': 'mise-config',
    'MISE_DATA_DIR': 'mise-data',
    'MISE_CACHE_DIR': 'mise-cache',
    'MISE_STATE_DIR': 'mise-state',
    'MISE_SYSTEM_CONFIG_DIR': 'mise-system-config',
    'MISE_SYSTEM_DATA_DIR': 'mise-system-data',
    'MISE_SYSTEM_INSTALLS_DIR': 'mise-system-installs',
    'MISE_INSTALLS_DIR': 'mise-installs',
    'MISE_SHARED_INSTALL_DIRS': 'mise-shared-installs',
}

FILE_LIMITED_EXEC = '''
import os
import resource
import sys

limit = int(sys.argv[1])
soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
hard = limit if hard == resource.RLIM_INFINITY else min(hard, limit)
soft = hard if soft == resource.RLIM_INFINITY else min(soft, hard)
resource.setrlimit(resource.RLIMIT_FSIZE, (soft, hard))
argv = sys.argv[2:]
os.execv(argv[0], argv)
'''

QUALITY_GUARD = '''
import os
import shutil
import sys

expected, runner = sys.argv[1:]
observed = shutil.which('shellcheck')
if observed != expected:
    raise SystemExit(f'Managed ShellCheck mismatch: expected {expected!r}, observed {observed!r}')
os.execv('/usr/bin/python3', ['/usr/bin/python3', '-B', runner, 'quality'])
'''


@contextmanager
def bounded_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ci.CheckError(f'Expected a regular file of at most {limit} bytes: {path}')
        yield stream


def config_bytes(path):
    with bounded_regular(path, CONFIG_LIMIT) as stream:
        data = stream.read(CONFIG_LIMIT + 1)
    if len(data) > CONFIG_LIMIT:
        raise ci.CheckError(f'Overlong mise input: {path}')
    return data


def validated_inputs():
    files = {name: config_bytes(ci.ROOT / 'tools/ci' / name) for name in ('mise.toml', 'mise.lock')}
    manifest = tomllib.loads(files['mise.toml'].decode())
    if manifest != {'settings': {'lockfile': True, 'lockfile_platforms': [PLATFORM]},
                    'tools': {BACKEND: SHELLCHECK}} or manifest['settings']['lockfile'] is not True:
        raise ci.CheckError('Invalid CI mise manifest')

    lock = tomllib.loads(files['mise.lock'].decode())
    asset = {'checksum': SHELLCHECK_CHECKSUM, 'url': SHELLCHECK_URL}
    tool = {'version': SHELLCHECK, 'backend': BACKEND, 'specifiers': [SHELLCHECK],
            f'platforms.{PLATFORM}': asset}
    expected = {'lockfile_version': 3, 'tools': {BACKEND: [tool]}}
    if lock != expected:
        asset['url_api'] = SHELLCHECK_API
    if lock != expected or type(lock['lockfile_version']) is not int:
        raise ci.CheckError('Invalid CI mise lockfile')
    return files


def hosted_shellcheck(supervisor):
    command = ('/usr/bin/shellcheck', '--version')
    env = {'PATH': ci.SYSTEM_PATH, 'LC_ALL': 'C.UTF-8'}
    try:
        output = ci.run(command, env, ci.TOOL_TIMEOUT, supervisor, print_output=False)
    except FileNotFoundError:
        raise ci.CheckError(f'Hosted ShellCheck expected {SHELLCHECK}, observed missing') from None
    except (OSError, ci.CheckError) as exc:
        if supervisor.pending is not None:
            raise
        raise ci.CheckError(f'Hosted ShellCheck expected {SHELLCHECK}, observed probe failure: {exc}') from exc
    versions = [line for line in output.splitlines() if line.startswith('version:')]
    report = re.fullmatch(r'version: (\S+)', versions[0]) if len(versions) == 1 else None
    observed = report.group(1) if report else f'malformed output {output[:160]!r}'
    if observed != SHELLCHECK:
        raise ci.CheckError(f'Hosted ShellCheck expected {SHELLCHECK}, observed {observed}')
    print(f'Hosted ShellCheck expected {SHELLCHECK}, observed {observed}', flush=True)


def extract_mise(archive, executable, supervisor):
    with bounded_regular(archive, ARCHIVE_LIMIT) as source:
        if hashlib.file_digest(source, 'sha256').hexdigest() != MISE_ARCHIVE_SHA:
            raise ci.CheckError('Mise archive SHA-256 does not match the pin')
        source.seek(0)
        binary_digest = None
        try:
            with tarfile.open(fileobj=source, mode='r|xz') as release:
                for member in release:
                    supervisor.check_interrupted()
                    if member.name != MISE_MEMBER:
                        continue
                    if (binary_digest is not None or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                            or member.sparse is not None or member.size != MISE_BINARY_SIZE):
                        raise ci.CheckError(f'Invalid or duplicate mise archive member {MISE_MEMBER}')
                    binary_digest = hashlib.sha256()
                    with release.extractfile(member) as binary, executable.open('xb') as target:
                        while block := binary.read(1024 * 1024):
                            supervisor.check_interrupted()
                            binary_digest.update(block)
                            target.write(block)
        except tarfile.TarError as exc:
            raise ci.CheckError(f'Could not read verified mise archive: {exc}') from exc
    if binary_digest is None or binary_digest.hexdigest() != MISE_BINARY_SHA:
        raise ci.CheckError('Mise executable SHA-256 does not match the pin')
    executable.chmod(0o700)


def bootstrap_mise(scratch, env, supervisor):
    archive, executable = scratch / 'mise.tar.xz', scratch / 'mise'
    # Older curl needs a kernel limit when the response does not advertise its size.
    command = (SYSTEM_PYTHON, '-I', '-B', '-c', FILE_LIMITED_EXEC, str(ARCHIVE_LIMIT),
               '/usr/bin/curl', '--disable', '--fail', '--silent', '--show-error', '--location',
               '--proto', '=https', '--proto-redir', '=https', '--max-redirs', '5',
               '--connect-timeout', '10', '--max-time', '90', '--max-filesize', str(ARCHIVE_LIMIT),
               '--output', str(archive), '--', MISE_URL)
    ci.run(command, env, 95, supervisor, scratch=scratch)
    extract_mise(archive, executable, supervisor)
    return executable


def mise_environment(scratch, env, empty_config):
    paths = {key: scratch / name for key, name in MISE_DIRS.items()}
    for path in paths.values():
        path.mkdir(mode=0o700)
    return {
        **env, **{key: str(path) for key, path in paths.items()},
        'MISE_TMP_DIR': env['TMPDIR'],
        'MISE_CEILING_PATHS': str(scratch),
        'MISE_OVERRIDE_CONFIG_FILENAMES': 'mise.toml',
        'MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES': '.oc-ci-disabled-tool-versions',
        'MISE_IDIOMATIC_VERSION_FILE_ENABLE_TOOLS': '',
        'MISE_GLOBAL_CONFIG_FILE': str(empty_config),
        'MISE_SYSTEM_CONFIG_FILE': str(empty_config),
        'MISE_NO_ENV': '1',
        'MISE_NO_HOOKS': '1',
        'MISE_AUTO_INSTALL': '0',
        'MISE_PARANOID': '1',
        'MISE_LOCKED': '1',
    }


def unique_json_object(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise ci.CheckError('Duplicate key in effective mise config output')
    return value


def verify_effective_config(output, project_config, empty_config):
    configs = json.loads(output, object_pairs_hook=unique_json_object)
    expected = {str(project_config): [BACKEND], str(empty_config): []}
    if not isinstance(configs, list) or len(configs) != len(expected):
        raise ci.CheckError('Unexpected effective mise config files')
    for config in configs:
        if (not isinstance(config, dict) or set(config) != {'path', 'tools', 'override'}
                or not isinstance(config['path'], str) or config['path'] not in expected
                or config['override'] is not False or config['tools'] != expected.pop(config['path'])):
            raise ci.CheckError('Unexpected effective mise config entry')


def managed_shellcheck(output, install_root):
    paths = output.splitlines()
    if len(paths) != 1:
        raise ci.CheckError('Mise did not report exactly one managed ShellCheck path')
    path = Path(paths[0])
    if (not path.is_absolute() or not path.is_relative_to(install_root)
            or not path.resolve(strict=True).is_relative_to(install_root)
            or not path.is_file() or not os.access(path, os.X_OK)):
        raise ci.CheckError(f'Mise did not select an executable ShellCheck inside {install_root}')
    return str(path)


def managed_quality(supervisor, *, hosted):
    if hosted:
        hosted_shellcheck(supervisor)
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ci.CheckError('The pinned CI toolchain requires Linux x86-64')
    files = validated_inputs()
    with ci.suite_scratch(supervisor) as scratch:
        env = ci.suite_environment(scratch)
        mise = bootstrap_mise(scratch, env, supervisor)
        project = scratch / 'project'
        project.mkdir(mode=0o700)
        for name, content in files.items():
            (project / name).write_bytes(content)
        manifest = project / 'mise.toml'
        empty_config = scratch / 'empty.toml'
        empty_config.touch()
        env = mise_environment(scratch, env, empty_config)

        def call(*args, timeout=ci.TOOL_TIMEOUT, print_output=True):
            command = (str(mise), '--cd', str(project), *args)
            return ci.run(command, env, timeout, supervisor, scratch=scratch, print_output=print_output)

        def check_copies():
            for name, content in files.items():
                if config_bytes(project / name) != content:
                    raise ci.CheckError(f'Private mise input changed: {name}')
            if config_bytes(empty_config):
                raise ci.CheckError('Private empty mise config changed')

        def check_config():
            check_copies()
            output = call('config', 'ls', '--json', print_output=False)
            check_copies()
            verify_effective_config(output, manifest, empty_config)

        call('trust', str(manifest))
        check_config()
        call('install', '--locked', timeout=90)
        check_config()
        executable = managed_shellcheck(call('which', 'shellcheck', print_output=False), Path(env['MISE_INSTALLS_DIR']))
        check_config()
        runner = str(ci.ROOT / 'tools/ci/run.py')
        call('exec', '--', SYSTEM_PYTHON, '-I', '-B', '-c', QUALITY_GUARD, executable, runner, timeout=90)
        check_copies()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hosted', action='store_true', help='require the hosted ShellCheck version first')
    args = parser.parse_args()
    return ci.run_supervised(lambda supervisor: managed_quality(supervisor, hosted=args.hosted))


if __name__ == '__main__':
    sys.exit(main())
