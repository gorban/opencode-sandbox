"""Linux-only subprocess backend for the explicitly scheduled Claude fixture."""

from contextlib import ExitStack
import ctypes
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import select
import signal
import stat
import subprocess
from threading import Event, Lock
import time

from oc_claude.fixture import RETIRE_SECONDS
from oc_claude.fixture_custody import _open_private_dir, _same_private_dir
from oc_claude.fixture_protocol import FRAME_LIMIT, STDERR_LIMIT, STDOUT_LIMIT, FixtureError, require


NATIVE = Path(__file__).with_name("claude_native_fixture.py")
PYTHON = Path("/usr/bin/python3")
BWRAP = Path("/usr/bin/bwrap")
SYSTEM = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
_LEADER_EXITED = b"fixture-native-leader-exited\n"
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
FILE = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
_PROFILE_FILES = ("registration.json", "credential")
_WRITE = ctypes.CDLL(None, use_errno=True).write
_WRITE.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t)
_WRITE.restype = ctypes.c_ssize_t
_GATE = """
import ctypes
import os
import signal
import sys

parent, gate, command, *args = sys.argv[1:]
gate = int(gate)
if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != int(parent):
    os._exit(120)
if os.read(gate, 1) != b'R' or os.getppid() != int(parent):
    os._exit(120)
os.close(gate)
os.execv(command, [command, *args])
"""


_DROP_SETUP_FDS = """
import os
import sys

for entry in os.listdir('/proc/self/fd'):
    fd = int(entry)
    if fd > 2:
        try:
            os.close(fd)
        except OSError:
            pass
if sys.argv[2] == 'leader_exit' and os.fork():
    leader, status = os.waitpid(-1, 0)
    assert status == 0
    os.close(1)
    os.write(2, b'fixture-native-leader-exited\\n')
    os.close(2)
    while True:
        try:
            os.waitpid(-1, 0)
        except ChildProcessError:
            os._exit(0)

os.execv('/usr/bin/python3', ['/usr/bin/python3', '-IB', '/fixture.py', *sys.argv[1:]])
"""


def _close(fd):
    if fd is not None:
        os.close(fd)


def _identity(info):
    return info.st_dev, info.st_ino


def _remaining(deadline, cancel):
    if cancel.is_set():
        raise FixtureError("cancelled")
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise FixtureError("deadline_exceeded")
    return seconds


class PollCancellation(Event):
    """Observe a separate owner's lifeline alongside explicit cancellation."""

    def __init__(self, owner_fd=None):
        super().__init__()
        self._owner_fd = owner_fd
        self._owner_poll = select.poll()
        if owner_fd is not None:
            self._owner_poll.register(owner_fd, select.POLLIN | select.POLLHUP | select.POLLERR)

    def __enter__(self):
        self.fd, self._writer = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        return self

    def __exit__(self, *_error):
        os.close(self.fd)
        os.close(self._writer)

    def is_set(self):
        return super().is_set() or bool(self._owner_poll.poll(0))

    def poll_fds(self):
        if self._owner_fd is None:
            return (self.fd,)
        return self.fd, self._owner_fd

    def wait(self, timeout):
        if self.is_set():
            return True
        poller = select.poll()
        for fd in self.poll_fds():
            poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        poller.poll(max(0, math.ceil(timeout * 1000)))
        return self.is_set()

    def set(self):
        super().set()
        try:
            os.write(self._writer, b"X")
        except BlockingIOError:
            pass


def _seal_image(name, data):
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        require(os.write(fd, data) == len(data))
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _SEALS)
        identity = _identity(os.fstat(fd))
        _verify_image(fd, data, identity)
        return fd, identity
    except BaseException:
        os.close(fd)
        raise


def _verify_image(fd, data, identity):
    info = os.fstat(fd)
    require(_identity(info) == identity and info.st_uid == os.geteuid() and stat.S_ISREG(info.st_mode))
    require(info.st_size == len(data) and fcntl.fcntl(fd, fcntl.F_GET_SEALS) & _SEALS == _SEALS)
    require(os.pread(fd, len(data) + 1, 0) == data)


class KernelLauncher:
    """Own one cgroup, pinned launch image and recovery record per fixture process."""

    def __init__(self, delegated, scratch, denied):
        self.delegated = delegated
        self.scratch = scratch
        self.denied = tuple(map(str, denied))
        self.scenario = "normal"
        self.children = []
        self.started = Event()
        self.sent = Event()
        self.leader_exited = Event()
        self.script = NATIVE.read_bytes()
        self.executable_identity = hashlib.sha256(self.script).hexdigest()
        self.profile_images = {}
        self._images_lock = Lock()

    def close(self):
        for objects in self.profile_images.values():
            for fd, _identity in objects:
                os.close(fd)
        self.profile_images.clear()

    def _profile_images(self, profile, stack):
        # The same memfd objects serve status and turn. New open descriptions
        # prevent one launch's cursor from shifting another launch's contents.
        pin = profile.snapshot()
        content = profile.image_bytes()
        with self._images_lock:
            if pin not in self.profile_images:
                with ExitStack() as create:
                    images = []
                    for name, data in zip(_PROFILE_FILES, content, strict=True):
                        fd, identity = _seal_image(name, data)
                        create.callback(os.close, fd)
                        images.append((fd, identity))
                    self.profile_images[pin] = tuple(images)
                    create.pop_all()
        readers = []
        for (fd, identity), data in zip(self.profile_images[pin], content, strict=True):
            reader = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_CLOEXEC)
            stack.callback(os.close, reader)
            _verify_image(reader, data, identity)
            readers.append(reader)
        return tuple(readers)

    def _namespace(self, profile_files, image, mode, session):
        command = [str(BWRAP), "--unshare-user", "--unshare-pid", "--as-pid-1", "--unshare-net", "--unshare-ipc",
                   "--unshare-uts", "--disable-userns", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
                   "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/tmp/work"]
        for name in ("lib", "lib64"):
            if Path("/usr", name).is_dir():
                command.extend(("--ro-bind", "/usr/" + name, "/usr/" + name, "--symlink", "usr/" + name, "/" + name))
        command.extend(("--ro-bind", str(PYTHON.resolve(strict=True)), str(PYTHON),
                        "--ro-bind-data", str(image), "/fixture.py",
                        "--dir", "/profile"))
        for descriptor, name in zip(profile_files, _PROFILE_FILES, strict=True):
            command.extend(("--ro-bind-data", str(descriptor), "/profile/" + name))
        command.extend(("--setenv", "HOME", "/tmp/work", "--chdir", "/tmp/work", "--",
                        str(PYTHON), "-IB", "-c", _DROP_SETUP_FDS, mode, self.scenario, session, *self.denied))
        return command

    def start(self, profile, mode, deadline, cancel):
        require(mode in {"status", "turn"} and profile.snapshot().executable_identity == self.executable_identity)
        _remaining(deadline, cancel)
        unit = None
        child = None
        process = None
        pidfd = None
        released = False
        try:
            with ExitStack() as stack:
                try:
                    profile_files = self._profile_images(profile, stack)
                    image, _identity = _seal_image("oc-claude-fixture", self.script)
                except OSError:
                    raise FixtureError("integrity_error") from None
                stack.callback(os.close, image)
                os.lseek(image, 0, os.SEEK_SET)
                _remaining(deadline, cancel)
                unit = _Cgroup(self.delegated, self.scratch)
                gate_read, gate_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
                stack.callback(os.close, gate_read)
                stack.callback(os.close, gate_write)
                os.set_blocking(gate_read, True)
                session = secrets.token_hex(16)
                command = self._namespace(profile_files, image, mode, session)
                _remaining(deadline, cancel)
                process = subprocess.Popen(
                    [str(PYTHON), "-IB", "-c", _GATE, str(os.getpid()), str(gate_read), *command],
                    stdin=subprocess.PIPE if mode == "turn" else subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=SYSTEM, cwd="/", bufsize=0,
                    pass_fds=(gate_read, image, *profile_files),
                )
                pidfd = os.pidfd_open(process.pid)
                unit.attach(process.pid)
                child = _KernelChild(self, unit, process, pidfd, profile.snapshot(), session)
                _remaining(deadline, cancel)
                require(child.is_live() and os.write(gate_write, b"R") == 1)
                released = True
                self.children.append(child)
                self.started.set()
                return child
        except (Exception, KeyboardInterrupt) as error:
            if unit is None:
                raise
            if child is not None:
                retired = child.retire(time.monotonic() + RETIRE_SECONDS)
            else:
                # No gate byte was issued so no fixture executable or descendants are possible.
                require(not released)
                retired = unit.retire(process, pidfd, time.monotonic() + RETIRE_SECONDS)
            if not retired:
                raise FixtureError("retirement_unverified") from None
            raise error


class _Cgroup:
    def __init__(self, delegated, scratch):
        scratch.require_reachable()
        self.parent = os.open(delegated, DIR)
        self.root = None
        self.identity = None
        self.scratch = scratch
        self.record = None
        self.record_fd = None
        self.name = "occlaude-" + secrets.token_hex(12)
        self.events = self.kill = self.procs = None
        try:
            parent_info = os.fstat(self.parent)
            require(parent_info.st_uid == os.geteuid())
            os.mkdir(self.name, mode=0o700, dir_fd=self.parent)
            leaf_info = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
            self.identity = _identity(leaf_info)
            self.root = os.open(self.name, DIR, dir_fd=self.parent)
            require(leaf_info.st_uid == os.geteuid() and leaf_info.st_dev == parent_info.st_dev
                    and _identity(os.fstat(self.root)) == self.identity)
            domain = self._file("cgroup.type", os.O_RDONLY)
            try:
                require(os.read(domain, 64) == b"domain\n")
            finally:
                os.close(domain)
            self.events = self._file("cgroup.events", os.O_RDONLY)
            self.kill = self._file("cgroup.kill", os.O_WRONLY)
            self.procs = self._file("cgroup.procs", os.O_RDWR)
            scratch.require_reachable()
            os.mkdir(self.name, mode=0o700, dir_fd=scratch.fd)
            self.record_fd, self.record_identity = _open_private_dir(self.name, scratch.fd)
            self.record = scratch.path / self.name
            record = os.open("recovery.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY | FILE,
                             0o600, dir_fd=self.record_fd)
            with os.fdopen(record, "w") as stream:
                json.dump({"cgroup": self.name, "parent": str(delegated), "identity": self.identity,
                           "scratch_identity": self.record_identity, "uid": os.geteuid()}, stream)
        except BaseException:
            # No process can have joined this unexposed leaf during setup.
            self._close_files()
            if self.identity is not None:
                self._remove_leaf()
            os.close(self.parent)
            raise

    def _file(self, name, flags):
        fd = os.open(name, flags | FILE, dir_fd=self.root)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}:
            os.close(fd)
            raise FixtureError("integrity_error")
        return fd

    def attach(self, pid):
        value = str(pid).encode("ascii")
        require(os.write(self.procs, value) == len(value))
        require(os.pread(self.procs, 4096, 0).splitlines() == [value])

    def empty(self):
        lines = os.pread(self.events, 1024, 0).splitlines()
        value = [line for line in lines if line.startswith(b"populated ")]
        require(value in ([b"populated 0"], [b"populated 1"]))
        return value == [b"populated 0"]

    def _close_files(self):
        for fd in (self.events, self.kill, self.procs, self.root, self.record_fd):
            _close(fd)

    def _remove_leaf(self):
        require(_identity(os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)) == self.identity)
        os.rmdir(self.name, dir_fd=self.parent)

    def retire(self, process, pidfd, deadline):
        confirmed = False
        try:
            for stream in (() if process is None else (process.stdin, process.stdout, process.stderr)):
                if stream is not None:
                    stream.close()
            if not self.empty():
                require(os.write(self.kill, b"1") == 1)
            if pidfd is not None and process.poll() is None:
                # Also covers a pre-attachment failure when the closed start gate is all the child received.
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            while not self.empty() or (process is not None and process.poll() is None):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                time.sleep(min(remaining, .01))
            if self.record_fd is not None:
                require(_same_private_dir(self.name, self.scratch.fd, self.record_identity))
            self._remove_leaf()
            if self.record_fd is not None:
                os.unlink("recovery.json", dir_fd=self.record_fd)
                require(_same_private_dir(self.name, self.scratch.fd, self.record_identity))
                os.rmdir(self.name, dir_fd=self.scratch.fd)
            confirmed = True
        except (OSError, FixtureError):
            pass
        finally:
            _close(pidfd)
            self._close_files()
            os.close(self.parent)
        return confirmed


class _KernelChild:
    def __init__(self, owner, unit, process, pidfd, pin, session):
        self.owner, self.unit, self.process, self.pidfd = owner, unit, process, pidfd
        self.pin, self.session = pin, session
        self.stdin = process.stdin
        self.stdout, self.stderr = stdout, stderr = process.stdout.fileno(), process.stderr.fileno()
        self.pipe_buf = os.fpathconf(self.stdin.fileno(), "PC_PIPE_BUF") if self.stdin else 0
        self.liveness = select.poll()
        self.liveness.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        self.buff = bytearray()
        self.budget = {stdout: STDOUT_LIMIT, stderr: STDERR_LIMIT}
        self.ended = set()
        self.retired = None
        os.set_blocking(stdout, False)
        os.set_blocking(stderr, False)
        if self.stdin is not None:
            os.set_blocking(self.stdin.fileno(), False)

    def is_live(self):
        return not self.liveness.poll(0)

    def verify_quiet(self):
        require(not self.buff and self.stdout not in self.ended)
        try:
            os.read(self.stdout, 1)
        except BlockingIOError:
            return
        except OSError:
            pass
        raise FixtureError("integrity_error")

    def write_once(self, packet):
        # Python's os.write retries some interrupted writes. This fixture spends exactly one syscall.
        written = _WRITE(self.stdin.fileno(), packet, len(packet))
        if written < 0:
            raise OSError(ctypes.get_errno(), "fixture write failed")
        return written

    def close_input(self):
        self.stdin.close()
        self.owner.sent.set()

    def _poll(self, deadline, cancel):
        poller = select.poll()
        for fd in self.budget.keys() - self.ended:
            poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        for fd in cancel.poll_fds():
            poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        for fd, _mask in poller.poll(max(1, int(_remaining(deadline, cancel) * 1000))):
            _remaining(deadline, cancel)
            try:
                chunk = os.read(fd, min(8192, self.budget[fd] + 1))
            except BlockingIOError:
                continue
            if not chunk:
                self.ended.add(fd)
                continue
            self.budget[fd] -= len(chunk)
            require(self.budget[fd] >= 0)
            if fd == self.stdout:
                self.buff.extend(chunk)
            elif chunk == _LEADER_EXITED:
                self.owner.leader_exited.set()

    def read_frame(self, deadline, cancel):
        while b"\n" not in self.buff:
            require(len(self.buff) < FRAME_LIMIT)
            if self.stdout in self.ended:
                require(not self.buff)
                raise FixtureError("provider_failed")
            self._poll(deadline, cancel)
        end = self.buff.index(b"\n") + 1
        require(end <= FRAME_LIMIT)
        frame = bytes(self.buff[:end])
        del self.buff[:end]
        return frame

    def finish(self, deadline, cancel):
        while self.ended != self.budget.keys():
            require(not self.buff)
            self._poll(deadline, cancel)
        require(not self.buff)
        while self.process.poll() is None:
            cancel.wait(min(.01, _remaining(deadline, cancel)))
        if self.process.returncode:
            raise FixtureError("provider_failed")

    def retire(self, deadline):
        if self.retired is None:
            self.retired = self.unit.retire(self.process, self.pidfd, deadline)
        return self.retired
