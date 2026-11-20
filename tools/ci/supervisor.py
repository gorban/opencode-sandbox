"""Own portable CI subprocesses until Linux confirms they are gone."""

from contextlib import contextmanager
import ctypes
from enum import Enum, auto
import os
from pathlib import Path
import signal
import subprocess
import time


PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
WAIT_FLAGS = os.WEXITED | os.WNOHANG | os.WNOWAIT
WAIT_ALL_CHILDREN = 0x40000000  # Linux __WALL includes non-SIGCHLD clone children.
TERM_GRACE = 1.0
KILL_GRACE = 2.0
POLL_INTERVAL = 0.025
CHILDREN = Path('/proc/thread-self/children')


class CheckError(RuntimeError):
    def __init__(self, message, status=1):
        super().__init__(message)
        self.status = status


class Children(Enum):
    DRAINED = auto()
    LIVE = auto()
    REAP_PENDING = auto()


def prctl(operation, argument):
    if ctypes.CDLL(None, use_errno=True).prctl(operation, argument, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def child_event():
    return os.waitid(os.P_ALL, 0, WAIT_FLAGS | WAIT_ALL_CHILDREN)


def direct_children():
    with CHILDREN.open(encoding='ascii') as children:
        snapshot = children.read(64 * 1024 + 1)
    if len(snapshot) > 64 * 1024:
        raise CheckError('Too many direct children to inspect during cleanup')
    return tuple(int(pid) for pid in snapshot.split())


def signal_child(pid, sig):
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return False
    try:
        # A pidfd names one process, and waitid additionally proves it is our child.
        if os.waitid(os.P_PIDFD, fd, WAIT_FLAGS) is not None:
            return False
        signal.pidfd_send_signal(fd, sig)
        if sig == signal.SIGTERM:
            signal.pidfd_send_signal(fd, signal.SIGCONT)
        return True
    except (ChildProcessError, ProcessLookupError):
        return False
    finally:
        os.close(fd)


class Supervisor:
    def __init__(self):
        self.pending = None
        self.drained = True

    def latch(self, number, _frame):
        if self.pending is None:
            self.pending = signal.Signals(number)

    def check_interrupted(self):
        if self.pending is not None:
            raise CheckError(f'Interrupted by {self.pending.name}', 128 + self.pending)

    def reap(self, process, signalled):
        if process is not None and process.returncode is None and process.poll() is not None:
            signalled.discard(process.pid)
        for _ in range(32):
            try:
                event = child_event()
            except ChildProcessError:
                self.drained = True
                return Children.DRAINED
            if event is None:
                return Children.LIVE
            if process is not None and process.returncode is None and event.si_pid == process.pid:
                process.poll()
            else:
                os.waitpid(event.si_pid, os.WNOHANG | WAIT_ALL_CHILDREN)
            signalled.discard(event.si_pid)
        return Children.REAP_PENDING

    def drain(self, process):
        term_deadline = time.monotonic() + TERM_GRACE
        deadline = term_deadline + KILL_GRACE
        signalled = set()
        sig = signal.SIGTERM
        while time.monotonic() < deadline:
            if self.reap(process, signalled) is Children.DRAINED:
                return
            if sig == signal.SIGTERM and time.monotonic() >= term_deadline:
                sig = signal.SIGKILL
                signalled.clear()
            for pid in direct_children():
                if time.monotonic() >= deadline:
                    break
                if pid not in signalled and signal_child(pid, sig):
                    signalled.add(pid)
            time.sleep(POLL_INTERVAL)
        raise CheckError('Could not confirm all children exited before the cleanup deadline')

    def execute(self, command, *, cwd, env, log, timeout):
        self.check_interrupted()
        process = None
        self.drained = False
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + timeout
            signalled = set()
            while True:
                self.check_interrupted()
                if time.monotonic() >= deadline:
                    raise CheckError(f'Command timed out after {timeout}s: {command!r}', 124)
                state = self.reap(process, signalled)
                if state is Children.DRAINED:
                    return process.returncode
                if process.returncode is not None and state is Children.LIVE:
                    raise CheckError(f'Command exited with live children: {command!r}')
                time.sleep(POLL_INTERVAL)
        except (CheckError, OSError, ValueError) as exc:
            if not self.drained:
                try:
                    self.drain(process)
                except (CheckError, OSError, ValueError) as cleanup:
                    exc.add_note(f'Child cleanup could not be verified: {cleanup}')
            raise


@contextmanager
def supervise():
    if not all((hasattr(os, 'pidfd_open'), hasattr(os, 'P_PIDFD'),
                hasattr(signal, 'pidfd_send_signal'))):
        raise CheckError('Linux pidfd support is required for CI child ownership')
    proc = Path(f'/proc/{os.getpid()}/task/{os.getpid()}')
    if CHILDREN.parent.resolve(strict=True) != proc or len(list(proc.parent.iterdir())) != 1:
        raise CheckError('CI requires a single-threaded supervisor and its own procfs child list')
    direct_children()
    fd = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(fd, 0)
        try:
            os.waitid(os.P_PIDFD, fd, WAIT_FLAGS)
        except ChildProcessError:
            pass  # The supervisor is never its own child.
        else:
            raise CheckError('Could not verify waitid ownership checks')
    finally:
        os.close(fd)

    supervisor = Supervisor()
    old_handlers = {}
    previous_subreaper = ctypes.c_int()
    subreaper_set = False
    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[number] = signal.signal(number, supervisor.latch)
        old_handlers[signal.SIGCHLD] = signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        try:
            child_event()
        except ChildProcessError:
            pass
        else:
            raise CheckError('CI supervisor already has children')
        prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(previous_subreaper))
        prctl(PR_SET_CHILD_SUBREAPER, 1)
        subreaper_set = True
        yield supervisor
    finally:
        if supervisor.drained:
            try:
                if subreaper_set:
                    prctl(PR_SET_CHILD_SUBREAPER, previous_subreaper.value)
            finally:
                for number, handler in old_handlers.items():
                    signal.signal(number, handler)
