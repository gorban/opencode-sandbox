"""Offline process-lifetime checks using only private fixture children."""

from contextlib import contextmanager
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from tools.ci.run import remove_scratch, scratch_identity
from tools.ci.supervisor import CheckError, Supervisor, WAIT_ALL_CHILDREN, child_event, signal_child, supervise


ROOT = Path(__file__).resolve().parents[1]


class OwnershipFlagsTest(unittest.TestCase):
    def test_pidfd_check_includes_non_sigchld_children(self):
        def waitid(_kind, _fd, flags):
            if not flags & WAIT_ALL_CHILDREN:
                raise ChildProcessError
            return None

        with patch.object(os, 'pidfd_open', return_value=-1), patch.object(os, 'close'), \
                patch.object(os, 'waitid', side_effect=waitid), patch.object(signal, 'pidfd_send_signal') as send:
            self.assertTrue(signal_child(123, signal.SIGKILL))
            send.assert_called_once_with(-1, signal.SIGKILL)

HARNESS = '''
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from tools.ci import run as ci

root, mode = Path(sys.argv[2]), sys.argv[3]
ci.ROOT = root
ci.SUITE_TIMEOUT = 1.5 if mode == 'timeout' else 12
mkdtemp = ci.tempfile.mkdtemp

def private_mkdtemp(suffix=None, prefix=None, dir=None):
    return mkdtemp(suffix=suffix, prefix=prefix, dir=root)

ci.tempfile.mkdtemp = private_mkdtemp
ci.SUITES = tuple(
    ci.Suite(name, 'fixture.py', (sys.executable, '-B', str(root / 'fixture.py'), str(root), case))
    for name, case in (('First fixture', mode), ('Second fixture', 'second'))
)
if mode == 'uncertain':
    from tools.ci.supervisor import Supervisor

    def uncertain_cleanup(self, child):
        raise OSError('injected cleanup uncertainty')

    Supervisor.drain = uncertain_cleanup
if mode in ('unexpected', 'unexpected-uncertain'):
    from tools.ci.supervisor import Supervisor

    reap = Supervisor.reap
    injected = False

    def fail_after_readiness(self, child, signalled):
        global injected
        if not injected and (root / 'primary').exists():
            injected = True
            raise RuntimeError('injected failure after child readiness')
        return reap(self, child, signalled)

    Supervisor.reap = fail_after_readiness
    if mode == 'unexpected-uncertain':
        def unexpected_cleanup_error(self, child):
            raise AssertionError('injected unexpected cleanup failure')

        Supervisor.drain = unexpected_cleanup_error
sys.argv = ['ci', 'tests']
raise SystemExit(ci.main())
'''

FIXTURE = '''
import os
from pathlib import Path
import signal
import sys
import time

root, mode = Path(sys.argv[1]), sys.argv[2]
if mode == 'second':
    (root / 'second-started').touch()
    raise SystemExit(0)
if mode in ('success', 'nonzero'):
    child = os.fork()
    if child == 0:
        os._exit(0)
    os.waitpid(child, 0)
    raise SystemExit(7 if mode == 'nonzero' else 0)

def ready(name):
    pending = root / (name + '.tmp')
    pending.touch()
    pending.rename(root / name)

bridge = os.fork()
if bridge == 0:
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    ready('detached')
    time.sleep(20)
    os._exit(0)
os.waitpid(bridge, 0)
deadline = time.monotonic() + 20
while time.monotonic() < deadline and not (root / 'detached').exists():
    time.sleep(0.02)
ready('primary')
while time.monotonic() < deadline and not (root / 'finish-primary').exists():
    time.sleep(0.02)
'''


def child_tree_empty():
    try:
        child_event()
    except ChildProcessError:
        return True
    return False


@contextmanager
def fixture_scratch(watchdog):
    root = Path(tempfile.mkdtemp(prefix='oc-ci-lifetime-', dir='/tmp'))
    identity = scratch_identity(root)
    try:
        yield root
    finally:
        remove_scratch(root, identity, watchdog)


def clean_fixtures(watchdog, process):
    try:
        if process is not None and process.poll() is None and signal_child(process.pid, signal.SIGKILL):
            process.wait(timeout=2)
    finally:
        watchdog.drain(process)


@contextmanager
def fixture_runner(mode):
    reference = os.environ.get('OC_CI_LIFETIME_REFERENCE', str(ROOT))
    # A frozen runner may leave a detached child behind. The outer subreaper can
    # adopt and reap it even if the test never saw its readiness file.
    with supervise() as watchdog, fixture_scratch(watchdog) as root:
        (root / 'fixture.py').write_text(FIXTURE)
        process = None
        watchdog.drained = False
        try:
            process = subprocess.Popen((sys.executable, '-B', '-c', HARNESS, reference, str(root), mode),
                                       cwd=root, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'},
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, start_new_session=True)
            yield root, process
        finally:
            try:
                clean_fixtures(watchdog, process)
            finally:
                if process is not None:
                    process.stdout.close()


class SupervisorTests(unittest.TestCase):
    def wait_ready(self, file, process):
        deadline = time.monotonic() + 5
        while not file.exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail(f'Runner exited before {file.name} was ready: {process.communicate(timeout=2)[0]}')
            time.sleep(0.02)
        self.assertTrue(file.exists(), f'Missing fixture readiness for {file.name}')

    def execute(self, mode, *, interrupt=None):
        with fixture_runner(mode) as (root, process):
            if mode not in ('nonzero', 'success'):
                self.wait_ready(root / 'primary', process)
                self.wait_ready(root / 'detached', process)
            if interrupt:
                self.assertTrue(signal_child(process.pid, interrupt), 'Could not signal the owned runner')
            if mode in ('leak', 'uncertain'):
                (root / 'finish-primary').touch()
            output, _ = process.communicate(timeout=8)
            return (process.returncode, output, child_tree_empty(),
                    sorted(root.glob('oc-ci-*')), (root / 'second-started').exists())

    def assert_clean_failure(self, result, code, message):
        status, output, empty, scratch, second_started = result
        self.assertTrue(empty, ('Fixture child tree was not drained', output))
        self.assertFalse(scratch, output)
        self.assertFalse(second_started, output)
        self.assertEqual(status, code, output)
        self.assertIn(message, output)

    def test_timeout_reaps_detached_double_fork(self):
        self.assert_clean_failure(self.execute('timeout'), 124, 'timed out')

    def test_direct_signals_reap_children_and_stop_schedule(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=sig.name):
                result = self.execute('interruption', interrupt=sig)
                self.assert_clean_failure(result, 128 + sig, f'Interrupted by {sig.name}')

    def test_successful_primary_leaving_child_is_a_failure(self):
        self.assert_clean_failure(self.execute('leak'), 1, 'exited with live children')

    def test_success_and_nonzero_after_complete_drain(self):
        status, output, empty, scratch, second_started = self.execute('success')
        self.assertEqual(status, 0, output)
        self.assertTrue(empty, output)
        self.assertFalse(scratch, output)
        self.assertTrue(second_started, output)
        self.assert_clean_failure(self.execute('nonzero'), 1, 'exited with status 7')

    def test_uncertain_cleanup_retains_scratch_and_stops_schedule(self):
        status, output, empty, scratch, second_started = self.execute('uncertain')
        self.assertEqual(status, 1, output)
        self.assertFalse(empty, output)
        self.assertEqual(len(scratch), 1, output)
        self.assertFalse(second_started, output)
        self.assertIn('injected cleanup uncertainty', output)
        self.assertIn(f'Retained scratch {scratch[0]}', output)

    def test_unexpected_error_after_readiness_drains_before_removing_scratch(self):
        self.assert_clean_failure(self.execute('unexpected'), 1,
                                  'RuntimeError: injected failure after child readiness')

    def test_unexpected_cleanup_error_preserves_original_error_and_scratch(self):
        status, output, empty, scratch, second_started = self.execute('unexpected-uncertain')
        self.assertEqual(status, 1, output)
        self.assertFalse(empty, output)
        self.assertFalse(second_started, output)
        self.assertEqual(len(scratch), 1, output)
        self.assertIn('RuntimeError: injected failure after child readiness', output)
        self.assertIn('Child cleanup could not be verified: injected unexpected cleanup failure', output)
        self.assertIn(f'Retained scratch {scratch[0]}', output)

    def test_signal_requires_parenthood_proof_after_pidfd_open(self):
        with patch('os.pidfd_open', return_value=42), patch('os.close') as close, \
                patch('os.waitid', side_effect=ChildProcessError) as wait, \
                patch('signal.pidfd_send_signal') as send:
            self.assertFalse(signal_child(123, signal.SIGTERM))
        wait.assert_called_once_with(os.P_PIDFD, 42, os.WEXITED | os.WNOHANG | os.WNOWAIT | WAIT_ALL_CHILDREN)
        close.assert_called_once_with(42)
        send.assert_not_called()

    def test_ready_file_cannot_supply_a_pid(self):
        with tempfile.TemporaryDirectory() as root:
            ready = Path(root) / 'primary'
            ready.write_text('12345')
            with patch('os.pidfd_open') as open_pid, patch('signal.pidfd_send_signal') as send:
                self.wait_ready(ready, None)
            open_pid.assert_not_called()
            send.assert_not_called()

    def test_watchdog_drains_after_partial_readiness(self):
        root = None
        failure = RuntimeError('stopped after first marker')

        def stop_after_first_marker():
            nonlocal root
            with fixture_runner('partial') as (root, process):
                self.wait_ready(root / 'primary', process)
                raise failure

        with self.assertRaises(RuntimeError) as caught:
            stop_after_first_marker()
        self.assertIs(caught.exception, failure)
        self.assertTrue(child_tree_empty())
        self.assertFalse(root.exists())

    def test_watchdog_retains_scratch_without_exit_proof(self):
        watchdog = Supervisor()
        watchdog.drained = False
        with tempfile.TemporaryDirectory() as scratch:
            parent = Path(scratch)
            root = parent / 'owned'
            root.mkdir(mode=0o700)
            (root / 'receipt').touch()
            with patch('tempfile.mkdtemp', return_value=str(root)), \
                    self.assertRaisesRegex(CheckError, f'Retained scratch {root}'):
                with fixture_scratch(watchdog):
                    pass
            self.assertTrue((root / 'receipt').is_file())
