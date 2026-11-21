"""Attended SonarCloud publisher. Launch from the reviewed Git object."""

import argparse
from getpass import getpass, GetPassWarning
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import warnings


MODULES = ('core_coverage', 'sonar_exec', 'sonar_checkout', 'sonar_cloud',
           'sonar_coverage', 'sonar_sandbox', 'sonar_state')
SHA = re.compile(r'[0-9a-f]{40}')
PUBLISHER_FILES = ('.sonarcloud.properties', *(f'tools/ci/{module}.py' for module in MODULES))
GIT = ('/usr/bin/git', '--no-pager', '--literal-pathspecs', '-c', 'core.hooksPath=/dev/null',
       '-c', 'core.fsmonitor=false')
GIT_ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_TERMINAL_PROMPT': '0'}
CHECKOUT_READS = {
    'root': ('rev-parse', '--show-toplevel'),
    'common-dir': ('rev-parse', '--path-format=absolute', '--git-common-dir'),
    'git-dir': ('rev-parse', '--path-format=absolute', '--git-dir'),
    'config': ('config', '--no-includes', '--name-only', '--list'),
    'replacements': ('for-each-ref', 'refs/replace'),
    'head': ('rev-parse', 'HEAD'),
    'status': ('status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none'),
}


def trusted_git(repo, operation):
    command = CHECKOUT_READS.get(operation)
    if command is None:
        raise ValueError('Unsupported publisher checkout operation')
    return subprocess.check_output(
        [*GIT, *command], cwd=repo, env=GIT_ENV, stderr=subprocess.DEVNULL, timeout=15,
    )


def publisher_blob(repo, revision, path):
    if not SHA.fullmatch(revision) or path not in PUBLISHER_FILES:
        raise ValueError('Publisher blob requires a reviewed commit and inventory path')
    entries = subprocess.check_output(
        [*GIT, 'ls-tree', '-z', revision, '--', path],
        cwd=repo, env=GIT_ENV, stderr=subprocess.DEVNULL, timeout=15,
    )
    entry = re.fullmatch(rb'100(?:644|755) blob ([0-9a-f]{40})\t([^\0]+)\0', entries)
    if not entry or entry[2] != path.encode('ascii'):
        raise ValueError('Publisher inventory entry must be a single regular Git blob')
    return subprocess.check_output(
        [*GIT, 'cat-file', 'blob', entry[1].decode('ascii')],
        cwd=repo, env=GIT_ENV, stderr=subprocess.DEVNULL, timeout=15,
    )


def trusted_directory(path, home):
    if not path.is_relative_to(home):
        raise ValueError('Use a trusted publisher checkout under your host home')
    sandbox = (home / 'opencode-sandbox').resolve()
    if path.is_relative_to(sandbox):
        raise ValueError('The publisher checkout must be outside the sandbox home')
    for item in (path, *path.parents):
        if not item.is_relative_to(home):
            break
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError('Publisher checkout or Git directory is not owner-controlled')


def trusted_checkout(repo, sha, home):
    trusted_directory(repo, home)
    if Path(os.fsdecode(trusted_git(repo, 'root').strip())).resolve() != repo:
        raise ValueError('Pass the root of the trusted publisher checkout')
    for operation in ('common-dir', 'git-dir'):
        directory = Path(os.fsdecode(trusted_git(repo, operation).strip())).resolve()
        trusted_directory(directory, home)
        for entry in ('info/grafts', 'objects/info/alternates', 'objects/info/http-alternates', 'shallow'):
            if os.path.lexists(directory / entry):
                raise ValueError('Trusted checkout uses unsupported Git object indirection')
    config = trusted_git(repo, 'config').lower().splitlines()
    if any(key.startswith((b'include.', b'includeif.', b'filter.')) for key in config):
        raise ValueError('Trusted checkout uses an external Git configuration or filter')
    if trusted_git(repo, 'replacements'):
        raise ValueError('Trusted checkout contains Git object replacements')
    if trusted_git(repo, 'head').decode().strip() != sha:
        raise ValueError('Trusted checkout HEAD differs from the reviewed publisher commit')
    if trusted_git(repo, 'status'):
        raise ValueError('Trusted publisher checkout must be clean')


def stage_modules(code, opts):
    for module in MODULES:
        data = publisher_blob(opts.checkout, opts.publisher, f'tools/ci/{module}.py')
        (code / f'{module}.py').write_bytes(data)
    sys.path.insert(0, str(code))
    config = publisher_blob(opts.checkout, opts.publisher, '.sonarcloud.properties')
    return config + b'\nsonar.sca.enabled=false\nsonar.scm.exclusions.disabled=true\n'


def token_from_terminal():
    try:
        with open('/dev/tty', 'w', encoding='utf-8') as tty, warnings.catch_warnings():
            if not tty.isatty():
                raise OSError('Not a terminal')
            warnings.simplefilter('error', GetPassWarning)
            value = getpass('SonarCloud analysis-only token (hidden): ', stream=tty)
    except (OSError, EOFError, GetPassWarning) as error:
        raise ValueError('A local terminal with hidden input is required') from error
    if not re.fullmatch(r'[A-Za-z0-9_-]{25,128}', value):
        raise ValueError('Unexpected token format')
    return value.encode('ascii')


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--publisher', required=True, help='full reviewed commit of the trusted publisher checkout')
    parser.add_argument('--head', required=True, help='exact reviewed main or PR head SHA')
    parser.add_argument('--base', help='exact reviewed main SHA for a PR')
    parser.add_argument('--pr', type=int, help='upstream pull request number')
    parser.add_argument('--prepare-only', action='store_true', help='measure in isolation without a scanner or token')
    opts = parser.parse_args(argv)
    if opts.pr is None:
        if opts.base is not None:
            parser.error('--base requires --pr')
        opts.base = opts.head
    elif opts.pr < 1 or opts.base is None:
        parser.error('--pr requires a positive number and an approved --base')
    if any(not SHA.fullmatch(sha) for sha in (opts.publisher, opts.head, opts.base)):
        parser.error('Use full lowercase commit SHAs')
    opts.checkout = opts.checkout.resolve(strict=True)
    return opts


def scanner_properties(revision, cloud):
    args = [f'sonar.host.url={cloud.SONAR}', f'sonar.organization={cloud.ORGANIZATION}',
            f'sonar.projectKey={cloud.PROJECT}', 'project.settings=/inputs/sonar-project.properties',
            f'sonar.scm.revision={revision.head}', 'sonar.scm.provider=git',
            'sonar.python.coverage.reportPaths=/inputs/coverage.xml',
            'sonar.working.directory=/tmp/scanner', 'sonar.qualitygate.wait=true',
            'sonar.qualitygate.timeout=120', 'sonar.scanner.skipJreProvisioning=true']
    if revision.number is not None:
        args += [f'sonar.pullrequest.key={revision.number}', f'sonar.pullrequest.branch={revision.branch}',
                 'sonar.pullrequest.base=main']
    return args


def verify_baseline(cloud, checkout, revision, state, identity, policy):
    from sonar_exec import PublishError
    from sonar_state import read_baseline

    old = read_baseline(*state)
    current = cloud.latest_main()
    if (old['identity'] != identity or old['policy'] != policy or old['head'] != revision.base
            or current[:2] != (old['result']['analysis'], revision.base)):
        raise PublishError('Current main or publisher policy differs from the attested baseline')
    baseline = checkout.Revision(revision.base, revision.base)
    metrics = old['result']['measures']
    if set(metrics) != set(identity['cores']):
        raise PublishError('The main baseline does not contain both measured cores')
    cloud.verify_metrics(baseline, metrics, set(metrics))
    if cloud.latest_main() != current:
        raise PublishError('The main analysis changed during verification')


def verify_admission(opts, revision, checkout, cloud, state, identity, policy=None):
    from sonar_exec import PublishError

    if checkout.resolve(cloud.github, opts.head, opts.base, opts.pr) != revision:
        raise PublishError('GitHub approval no longer matches the exact submission')
    automatic, current = cloud.mode_policy()
    if automatic or (policy is not None and current != policy):
        raise PublishError('Automatic Analysis is enabled or the gate policy changed')
    if revision.number:
        verify_baseline(cloud, checkout, revision, state, identity, current)
    return current


def publish(opts, root, state, config):
    import core_coverage as wheel
    import sonar_checkout as checkout
    import sonar_cloud as cloud
    import sonar_coverage as coverage
    import sonar_sandbox as sandbox
    from sonar_state import record_baseline

    revision = checkout.resolve(cloud.github, opts.head, opts.base, opts.pr)
    identity = {'publisher': opts.publisher, 'scanner': sandbox.SCANNER, 'python': sandbox.PYTHON,
                'wheel': wheel.WHEEL_HASH, 'properties': sha256(config).hexdigest(),
                'cores': sorted(wheel.CORES)}
    if not opts.prepare_only:
        policy = verify_admission(opts, revision, checkout, cloud, state, identity)
    source, git_env, merge_base = checkout.checkout(root, revision)
    required = checkout.changed_cores(source, git_env, merge_base, revision, wheel.CORES)
    measurement = root / 'measure'
    measurement.mkdir(mode=0o700)
    sandbox.measurement_inputs(measurement, wheel, cloud.download(wheel.WHEEL, 300_000))
    print(f'Measuring coverage for {revision.head} without credentials.', flush=True)
    with sandbox.private_store(root / 'measure-store') as store:
        raw = sandbox.measure(store, source, measurement, wheel)
    report = coverage.canonical_report(raw, source, wheel.CORES)
    receipt = {'identity': identity, 'head': revision.head, 'base': revision.base, 'pr': revision.number,
               'head_repository': revision.repository, 'merge_base': merge_base,
               'report_sha256': sha256(report.xml).hexdigest()}
    if opts.prepare_only:
        print(json.dumps({**receipt, 'phase': 'prepared', 'expected_measures': report.metrics}, sort_keys=True))
        return 0

    scan = root / 'scan'
    scan.mkdir(mode=0o700)
    (scan / 'coverage.xml').write_bytes(report.xml)
    (scan / 'sonar-project.properties').write_bytes(config)
    with sandbox.private_store(root / 'scan-store') as store:
        store.require('pull', '--quiet', sandbox.SCANNER, timeout=300)
        verify_admission(opts, revision, checkout, cloud, state, identity, policy)
        print(f'Ready to publish {revision.head} to SonarCloud.', flush=True)
        token = token_from_terminal()
        try:
            verify_admission(opts, revision, checkout, cloud, state, identity, policy)
            previous_check_id = cloud.native_check_id(revision) if revision.number else None
            since = cloud.now()
            result = sandbox.scanner(store, source, scan, scanner_properties(revision, cloud), token)
        finally:
            del token

    outcome = cloud.confirm(revision, result, since, report.metrics, required, previous_check_id)
    verify_admission(opts, revision, checkout, cloud, state, identity, policy)
    receipt.update(policy=policy, result=outcome, phase='published', previous_check_id=previous_check_id)
    if revision.number is None:
        record_baseline(*state, receipt)
    print(json.dumps(receipt, sort_keys=True))
    return int(outcome['gate'] != 'OK')


def run(opts, home):
    with tempfile.TemporaryDirectory(prefix='.oc-sonar-code-', dir=home) as temporary:
        config = stage_modules(Path(temporary), opts)
        from sonar_state import state_directory

        with state_directory(home) as state:
            root = Path(tempfile.mkdtemp(prefix='run-', dir=state[0]))
            try:
                return publish(opts, root, state, config)
            finally:
                if any((root / name).exists() for name in ('measure-store', 'scan-store')):
                    print(f'Private Podman cleanup needs attention at {root}', file=sys.stderr)
                else:
                    shutil.rmtree(root)


def stop(signum, _frame):
    raise KeyboardInterrupt(f'Interrupted by signal {signum}')


def require_host():
    if (os.getuid() == 0 or os.environ.get('CONTAINER_ID') or not Path('/usr/bin/podman').is_file()
            or Path('/run/.containerenv').exists() or Path('/.dockerenv').exists()):
        raise ValueError('Run from a Linux host terminal as an unprivileged rootless Podman user')


def main():
    if sys.argv[0] != '-' or not sys.flags.isolated:
        raise ValueError('Launch the reviewed publisher Git object using Python isolated stdin mode')
    require_host()
    os.environ.clear()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    signal.signal(signal.SIGHUP, stop)
    signal.signal(signal.SIGTERM, stop)
    opts = parse_args(sys.argv[1:])
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    trusted_checkout(opts.checkout, opts.publisher, home)
    return run(opts, home)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print('Sonar publisher interrupted.', file=sys.stderr)
        raise SystemExit(130) from None
    except (RuntimeError, ValueError) as error:
        print(f'Sonar publisher failed: {error}', file=sys.stderr)
        raise SystemExit(1) from None
    except (OSError, subprocess.SubprocessError, KeyError, TypeError) as error:
        print(f'Sonar publisher failed: {type(error).__name__}', file=sys.stderr)
        raise SystemExit(1) from None
