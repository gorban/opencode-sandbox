#!/usr/bin/env python3
"""Run the portable CI checks against the current working files."""

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

if __package__:
    from .supervisor import CheckError, supervise
else:
    from supervisor import CheckError, supervise


ROOT = Path(__file__).resolve().parents[2]
SYSTEM_PATH = '/usr/bin:/bin'
SUITE_TIMEOUT = 120
TOOL_TIMEOUT = 30
SHELLCHECK_VERSION = '0.9.0'
MAX_LOG_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Suite:
    name: str
    path: str
    command: tuple[str, ...]
    unittest: bool = False
    stub_security: bool = False


def discover(name, filename):
    command = ('python3', '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', filename)
    return Suite(name, f'tests/{filename}', command, unittest=True)


def script(name, path, *interpreter, unittest=False, stub_security=False):
    return Suite(name, path, (*interpreter, path), unittest=unittest, stub_security=stub_security)


SUITES = (
    discover('Controller core', 'test_controller_core.py'),
    discover('Restricted orchestrator text proof', 'test_orchestrator_text.py'),
    discover('Bridge merge core', 'bridge_merge_core.py'),
    script('Launcher and setup lifecycle', 'tests/setup-lifecycle.py', 'python3', '-B', unittest=True),
    script('Host state leaves', 'tests/host_state_leaves.py', 'python3', '-B'),
    script('Worktree shell', 'tests/worktrees.sh', 'bash'),
    script('Worktree review regressions', 'tests/worktree_review_regressions.py', 'python3', '-B'),
    script('Worktree state regressions', 'tests/worktree_state_regressions.py', 'python3', '-B'),
    script('Postgres host stubs', 'tests/postgres-host.sh', 'bash'),
    script('Isolated parallel runner mocks', 'tests/parallel-isolated-test.py', 'python3', '-B'),
    script('Isolated parallel runner source audit', 'tests/parallel-isolated.py', 'python3', '-B'),
    script('Security stubs', 'tests/security.sh', 'bash', stub_security=True),
    discover('CI runner contract', 'test_ci.py'),
    discover('CI supervisor contract', 'test_ci_supervisor.py'),
    discover('CI toolchain contract', 'test_ci_toolchain.py'),
    discover('Sonar publisher contract', 'test_sonar_publisher.py'),
    discover('OpenAI operator consent', 'test_openai_cli.py'),
    discover('OpenAI launcher dispatch', 'test_openai_cli_launcher.py'),
    discover('OpenAI attended test harness', 'test_openai_proof_harness.py'),
    discover('OpenAI workstation connection', 'test_openai_connection.py'),
    discover('OpenAI managed retirement', 'test_openai_connection_job.py'),
    discover('OpenAI provider transport', 'test_openai_connection_transport.py'),
    discover('OpenAI inference exposure', 'test_openai_exposure.py'),
    discover('OpenAI acceptance integration', 'test_openai_live.py'),
    discover('OpenAI recovery proof', 'test_openai_recovery.py'),
    discover('OpenAI registry integration', 'test_openai_profile_backend.py'),
    discover('OpenAI saved registrations', 'test_openai_profiles.py'),
    discover('OpenAI managed worker', 'test_openai_worker.py'),
    discover('Shared provider contracts', 'test_provider_contracts.py'),
    discover('Provider TOML config', 'test_provider_config.py'),
    discover('Provider profile set schema', 'test_provider_profile_sets.py'),
    discover('Multi-provider catalog', 'test_provider_catalog.py'),
    discover('OpenAI interactive session leases', 'test_openai_session_leases.py'),
    discover('OpenAI interactive session protocol', 'test_openai_session_protocol.py'),
    discover('OpenAI interactive session broker', 'test_openai_session_broker.py'),
    discover('OpenAI zero-tool canary', 'test_openai_canary.py'),
    discover('OpenAI interactive shell e2e harness', 'test_openai_shell_e2e_harness.py'),
    discover('Supply-chain pinning and image age invariants', 'test_supply_chain_pins.py'),
)

SHELL_FILES = (
    'oc-sandbox',
    'tests/parallel.sh',
    'tests/postgres-host.sh',
    'tests/bridge-manager-fixture.sh',
    'tests/security.sh',
    'tests/worktrees.sh',
)

PYTHON_FILES = (
    'oc-bridge.py',
    'oc-bridge-unit.py',
    'oc-opencode-run.py',
    'oc-opencode-supervisor.py',
    'oc-opencode-update.py',
    'oc-orchestrate.py',
    'oc-setup-lock.py',
    'oc_bridge_merge.py',
    'oc_controller.py',
    'oc-openai.py',
    'oc-openai-session.py',
    'oc_orchestrator/__init__.py',
    'oc_orchestrator/capture.py',
    'oc_orchestrator/claude.py',
    'oc_orchestrator/claude_fixture.py',
    'oc_orchestrator/claude_launch.py',
    'oc_orchestrator/claude_protocol.py',
    'oc_orchestrator/owner.py',
    'oc_orchestrator/protocol.py',
    'oc_orchestrator/relay.py',
    'oc_orchestrator/runtime.py',
    'oc_providers/__init__.py',
    'oc_providers/catalog.py',
    'oc_providers/config.py',
    'oc_providers/contracts.py',
    'oc_openai/__init__.py',
    'oc_openai/acceptance.py',
    'oc_openai/canary.py',
    'oc_openai/canary_ledger.py',
    'oc_openai/canary_protocol.py',
    'oc_openai/canary_relay.py',
    'oc_openai/canary_runtime.py',
    'oc_openai/cli.py',
    'oc_openai/connection.py',
    'oc_openai/connection_job.py',
    'oc_openai/connection_state.py',
    'oc_openai/exposure.py',
    'oc_openai/live.py',
    'oc_openai/managed/__init__.py',
    'oc_openai/managed/broker.py',
    'oc_openai/managed/client.py',
    'oc_openai/managed/protocol.py',
    'oc_openai/managed/relay.py',
    'oc_openai/managed/relay_receipt.py',
    'oc_openai/managed/runtime.py',
    'oc_openai/profile_backend.py',
    'oc_openai/profiles.py',
    'oc_openai/proof_gate.py',
    'oc_openai/recovery.py',
    'oc_openai/responses.py',
    'oc_openai/session_adapter.py',
    'oc_openai/session_broker.py',
    'oc_openai/session_protocol.py',
    'oc_openai/session_relay.py',
    'oc_openai/shell_cleanup_owner.py',
    'oc_openai/worker.py',
    'tests/bridge_merge_core.py',
    'tests/bridge-staging-isolated.py',
    'tests/e2e/live/conftest.py',
    'tests/e2e/live/openai_canary_driver.py',
    'tests/e2e/live/openai_driver.py',
    'tests/e2e/live/openai_shell_driver.py',
    'tests/e2e/live/run_openai_shell_live.py',
    'tests/e2e/live/test_openai_canary_e2e.py',
    'tests/e2e/live/test_openai_proof.py',
    'tests/e2e/live/test_openai_shell_e2e.py',
    'tests/host_state_leaves.py',
    'tests/orchestrator-owner-loss.py',
    'tests/parallel-isolated-test.py',
    'tests/parallel-isolated.py',
    'tests/postgres-host-real.py',
    'tests/setup-lifecycle.py',
    'tests/test_ci.py',
    'tests/test_ci_supervisor.py',
    'tests/test_ci_toolchain.py',
    'tests/test_controller_core.py',
    'tests/test_openai_canary.py',
    'tests/test_openai_cli.py',
    'tests/test_openai_cli_launcher.py',
    'tests/test_openai_connection.py',
    'tests/test_openai_connection_job.py',
    'tests/test_openai_connection_transport.py',
    'tests/test_openai_exposure.py',
    'tests/test_openai_live.py',
    'tests/test_openai_profile_backend.py',
    'tests/test_openai_profiles.py',
    'tests/test_openai_proof_harness.py',
    'tests/test_openai_recovery.py',
    'tests/test_openai_session_broker.py',
    'tests/test_openai_session_leases.py',
    'tests/test_openai_session_protocol.py',
    'tests/test_openai_shell_e2e_harness.py',
    'tests/test_openai_worker.py',
    'tests/test_orchestrator_text.py',
    'tests/test_provider_catalog.py',
    'tests/test_provider_config.py',
    'tests/test_provider_contracts.py',
    'tests/test_provider_profile_sets.py',
    'tests/test_sonar_publisher.py',
    'tests/test_supply_chain_pins.py',
    'tests/worktree_review_regressions.py',
    'tests/worktree_state_regressions.py',
    'tools/ci/core_coverage.py',
    'tools/ci/run.py',
    'tools/ci/sonar_checkout.py',
    'tools/ci/sonar_cloud.py',
    'tools/ci/sonar_http.py',
    'tools/ci/sonar_coverage.py',
    'tools/ci/sonar_exec.py',
    'tools/ci/sonar_publish.py',
    'tools/ci/sonar_sandbox.py',
    'tools/ci/sonar_state.py',
    'tools/ci/supervisor.py',
    'tools/ci/toolchain.py',
)

SCRATCH_DIRS = {
    'HOME': 'home',
    'TMPDIR': 'tmp',
    'XDG_CACHE_HOME': 'cache',
    'XDG_CONFIG_HOME': 'config',
    'XDG_DATA_HOME': 'data',
    'XDG_STATE_HOME': 'state',
    'XDG_RUNTIME_DIR': 'runtime',
    'XDG_CONFIG_DIRS': 'config-dirs',
    'XDG_DATA_DIRS': 'data-dirs',
}


def file_required(name):
    path = ROOT / name
    if not path.is_file():
        raise CheckError(f'Missing required file {name}')
    return path


def tool_required(name, path):
    executable = shutil.which(name, path=path)
    if executable is None:
        raise CheckError(f'Missing required tool {name}')
    return str(Path(executable).absolute())


def suite_environment(scratch):
    env = {
        'PATH': SYSTEM_PATH,
        'LC_ALL': 'C.UTF-8',
        'PYTHONDONTWRITEBYTECODE': '1',
        'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_CONFIG_COUNT': '0',
        'GIT_TERMINAL_PROMPT': '0',
    }
    for key, name in SCRATCH_DIRS.items():
        directory = scratch / name
        directory.mkdir(mode=0o700)
        env[key] = str(directory)
    return env


def run(command, env, timeout, supervisor, *, scratch, print_output=True):
    # A file avoids a pipe-reading wait if a descendant keeps the log open.
    with tempfile.TemporaryFile(dir=scratch) as log:
        status = None
        try:
            status = supervisor.execute(command, cwd=ROOT, env=env, log=log, timeout=timeout)
        finally:
            log.seek(0)
            data = log.read(MAX_LOG_BYTES + 1)
            output = data[:MAX_LOG_BYTES].decode('utf-8', errors='replace')
            if print_output or status != 0:
                print(output, end='', flush=True)
        if len(data) > MAX_LOG_BYTES:
            raise CheckError(f'Command exceeded the {MAX_LOG_BYTES}-byte log limit: {command!r}')
        if status != 0:
            raise CheckError(f'Command exited with status {status}: {command!r}')
    return output


def scratch_identity(directory):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise CheckError(f'Scratch directory has unsafe ownership or permissions: {directory}')
    return info.st_dev, info.st_ino


def remove_scratch(directory, identity, supervisor):
    if not supervisor.drained:
        raise CheckError(f'Child exit could not be verified. Retained scratch {directory}')
    if scratch_identity(directory) != identity or not shutil.rmtree.avoids_symlink_attacks:
        raise CheckError(f'Scratch identity could not be verified. Retained scratch {directory}')
    shutil.rmtree(directory)


@contextmanager
def suite_scratch(supervisor):
    directory = Path(tempfile.mkdtemp(prefix='oc-ci-', dir='/tmp'))
    identity = scratch_identity(directory)
    try:
        yield directory
    except BaseException as exc:
        try:
            remove_scratch(directory, identity, supervisor)
        except BaseException as cleanup:
            exc.add_note(str(cleanup))
        raise
    else:
        remove_scratch(directory, identity, supervisor)


def tests(supervisor):
    for name in ('python3', 'bash', 'git'):
        tool_required(name, SYSTEM_PATH)
    for suite in SUITES:
        supervisor.check_interrupted()
        file_required(suite.path)
        print(f'== {suite.name} ==', flush=True)
        with suite_scratch(supervisor) as directory:
            env = suite_environment(directory)
            if suite.stub_security:
                env['OC_TEST_NO_PODMAN'] = '1'
            output = run(suite.command, env, SUITE_TIMEOUT, supervisor, scratch=directory)
        if suite.unittest:
            counts = re.findall(r'^Ran (\d+) tests? in [\d.]+s$', output, re.ASCII | re.MULTILINE)
            if len(counts) != 1 or int(counts[0]) < 1:
                raise CheckError(f'{suite.name} did not report a positive unittest count')
    print('SKIP real Podman security checks (portable profile has no configured isolated fixture)')
    print('SKIP real Postgres acceptance (portable profile has no configured isolated fixture)')
    print('SKIP SELinux/Wayland acceptance (portable profile has no configured isolated fixture)')
    print('SKIP remote acceptance (unavailable in the portable profile)')


def validate_scope():
    # Keep additions to the active source directories visible without scanning archived probes.
    declared = set(SHELL_FILES + PYTHON_FILES)
    scopes = ((ROOT, ''), (ROOT / 'tests', '**/'), (ROOT / 'tools/ci', '**/'),
              (ROOT / 'oc_openai', '**/'), (ROOT / 'oc_providers', '**/'))
    for directory, prefix in scopes:
        for pattern in ('*.sh', '*.py'):
            for path in sorted(directory.glob(prefix + pattern)):
                name = path.relative_to(ROOT).as_posix()
                if path.is_file() and name not in declared:
                    raise CheckError(f'Unlisted quality source {name}')


def quality(supervisor):
    validate_scope()
    bash = tool_required('bash', SYSTEM_PATH)
    shellcheck = tool_required('shellcheck', os.environ.get('PATH', os.defpath))
    env = {'PATH': SYSTEM_PATH, 'LC_ALL': 'C.UTF-8'}
    with suite_scratch(supervisor) as scratch:
        print(sys.version.splitlines()[0], flush=True)
        bash_version = run((bash, '--version'), env, TOOL_TIMEOUT, supervisor, scratch=scratch, print_output=False)
        print(bash_version.partition('\n')[0], flush=True)
        version = run((shellcheck, '--version'), env, TOOL_TIMEOUT, supervisor, scratch=scratch)
        versions = re.findall(r'^version: (\S+)$', version, re.MULTILINE)
        if versions != [SHELLCHECK_VERSION]:
            raise CheckError(f'Quality requires ShellCheck {SHELLCHECK_VERSION}')

        for name in SHELL_FILES:
            file_required(name)
            run((bash, '-n', '--', name), env, TOOL_TIMEOUT, supervisor, scratch=scratch)
        for name in PYTHON_FILES:
            supervisor.check_interrupted()
            path = file_required(name)
            compile(path.read_bytes(), name, 'exec', dont_inherit=True)
        run((shellcheck, '--norc', '--severity=error', '--', *SHELL_FILES),
            env, TOOL_TIMEOUT, supervisor, scratch=scratch)
    print(f'Checked {len(SHELL_FILES)} shell files and {len(PYTHON_FILES)} Python files')


def run_supervised(phase):
    supervisor = None
    try:
        with supervise() as supervisor:
            phase(supervisor)
            supervisor.check_interrupted()
        # A handler can still latch a signal during supervisor teardown.
        supervisor.check_interrupted()
    except (CheckError, OSError, SyntaxError, ValueError) as exc:
        print(f'FAIL {exc}', file=sys.stderr)
        for note in getattr(exc, '__notes__', ()):
            print(note, file=sys.stderr)
        return 128 + supervisor.pending if supervisor and supervisor.pending else getattr(exc, 'status', 1)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('tests', 'quality'))
    args = parser.parse_args()
    return run_supervised({'tests': tests, 'quality': quality}[args.phase])


if __name__ == '__main__':
    sys.exit(main())
