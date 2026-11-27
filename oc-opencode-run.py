#!/usr/bin/env python3
"""Forward signals and reap exited children while running OpenCode.

Execution modes (controlled strictly by host-supplied environment variables):
  - default (neither OC_OPENCODE_EXPECTED_SHA256 nor OC_OPENCODE_USE_VOLUME):
      baked-only; resolves OpenCode strictly outside $HOME/.opencode.
  - verified opt-in (OC_OPENCODE_EXPECTED_SHA256=<64-hex>):
      reads $HOME/.opencode/bin/opencode via trusted O_NOFOLLOW parent descriptors,
      copies its exact bytes into a private kernel-sealed immutable memfd while
      computing SHA-256, verifies digest parity, and executes /proc/self/fd/<fd>.
  - explicit unverified compatibility (OC_OPENCODE_USE_VOLUME=1):
      allows $HOME/.opencode/bin/opencode if present, else falls back to baked.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys

WAIT_ALL_CHILDREN = 0x40000000  # Linux __WALL includes non-SIGCHLD clone children.
CHECKSUM = re.compile(r'[0-9a-f]{64}', re.ASCII)
MAX_BINARY = 512 * 1024 * 1024
INSTALL_DIRNAME = '.opencode'
MFD_ALLOW_SEALING = getattr(os, 'MFD_ALLOW_SEALING', 2)
F_ADD_SEALS = getattr(fcntl, 'F_ADD_SEALS', 1033)
SEAL_IMMUTABLE = (
    getattr(fcntl, 'F_SEAL_SEAL', 1)
    | getattr(fcntl, 'F_SEAL_SHRINK', 2)
    | getattr(fcntl, 'F_SEAL_GROW', 4)
    | getattr(fcntl, 'F_SEAL_WRITE', 8)
)


def reap_exited_children():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG | WAIT_ALL_CHILDREN)
        except ChildProcessError:
            return
        if pid == 0:
            return


def _write_all(fd, chunk):
    remaining = memoryview(chunk)
    while remaining:
        written = os.write(fd, remaining)
        if written <= 0:
            raise OSError('short write while sealing OpenCode snapshot')
        remaining = remaining[written:]


def _open_volume_binary(home):
    """Open $HOME/.opencode/bin/opencode through O_NOFOLLOW parent descriptors."""
    opened = [os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)]
    try:
        for part in (INSTALL_DIRNAME, 'bin'):
            opened.append(
                os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=opened[-1])
            )
        fd = os.open('opencode', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=opened[-1])
    finally:
        for dfd in reversed(opened):
            os.close(dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not (st.st_mode & 0o111):
            raise ValueError('volume OpenCode binary is not an executable regular file')
        if st.st_size <= 0 or st.st_size > MAX_BINARY:
            raise ValueError('volume OpenCode binary has invalid size')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _load_verified_memfd(home, expected_sha256):
    """Copy exact bytes from $HOME/.opencode/bin/opencode into a sealed memfd and verify SHA-256."""
    src_fd = _open_volume_binary(home)
    mfd = os.memfd_create('opencode-verified', MFD_ALLOW_SEALING)
    try:
        hasher = hashlib.sha256()
        total = 0
        try:
            while True:
                chunk = os.read(src_fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BINARY:
                    raise ValueError('volume OpenCode binary exceeds size limit')
                hasher.update(chunk)
                _write_all(mfd, chunk)
        finally:
            os.close(src_fd)
        if total == 0 or hasher.hexdigest() != expected_sha256:
            raise ValueError('volume OpenCode binary digest does not match expected SHA-256')
        os.lseek(mfd, 0, os.SEEK_SET)
        os.fchmod(mfd, 0o700)
        fcntl.fcntl(mfd, F_ADD_SEALS, SEAL_IMMUTABLE)
        return mfd
    except BaseException:
        os.close(mfd)
        raise


def _is_under(path_str, root):
    try:
        Path(path_str).resolve().relative_to(root)
        return True
    except (OSError, ValueError):
        return False


def _resolve_baked_binary(home):
    volume_root = (Path(home) / INSTALL_DIRNAME).resolve()
    raw_path = os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin')
    filtered = [entry for entry in raw_path.split(os.pathsep) if entry and not _is_under(entry, volume_root)]
    candidate = shutil.which('opencode', path=os.pathsep.join(filtered))
    if not candidate:
        raise FileNotFoundError('baked OpenCode binary not found on system PATH')
    return candidate


def _resolve_volume_compat_binary(home):
    volume_bin = Path(home) / INSTALL_DIRNAME / 'bin' / 'opencode'
    if volume_bin.is_file() and not volume_bin.is_symlink() and os.access(volume_bin, os.X_OK):
        return str(volume_bin)
    return _resolve_baked_binary(home)


def _spawn_opencode(argv):
    expected = os.environ.get('OC_OPENCODE_EXPECTED_SHA256', '')
    use_volume = os.environ.get('OC_OPENCODE_USE_VOLUME', '')
    home = os.environ.get('HOME', '/root')
    if expected and use_volume:
        raise ValueError('OC_OPENCODE_EXPECTED_SHA256 and OC_OPENCODE_USE_VOLUME cannot both be set')
    if expected:
        if not CHECKSUM.fullmatch(expected):
            raise ValueError('OC_OPENCODE_EXPECTED_SHA256 must be a 64-character lowercase hex digest')
        mfd = _load_verified_memfd(home, expected)
        try:
            return subprocess.Popen(['opencode', *argv], executable=f'/proc/self/fd/{mfd}', pass_fds=(mfd,))
        finally:
            os.close(mfd)
    if use_volume == '1':
        binary = _resolve_volume_compat_binary(home)
    elif use_volume == '':
        binary = _resolve_baked_binary(home)
    else:
        raise ValueError('OC_OPENCODE_USE_VOLUME must be 1 or unset')
    return subprocess.Popen([binary, *argv])


def main():
    child_fd = None
    pending = set()

    def deliver(signum):
        try:
            signal.pidfd_send_signal(child_fd, signum)
        except ProcessLookupError:
            pass

    def forward(signum, _frame):
        if child_fd is None:
            pending.add(signum)
        else:
            deliver(signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, forward)
    try:
        child = _spawn_opencode(sys.argv[1:])
    except (OSError, ValueError) as exc:
        print(f'cannot start OpenCode: {exc}', file=sys.stderr)
        return 126 if isinstance(exc, ValueError) else 127
    child_fd = os.pidfd_open(child.pid)
    try:
        for sig in pending:
            deliver(sig)
        while child.returncode is None:
            pid, status = os.waitpid(-1, WAIT_ALL_CHILDREN)
            if pid == child.pid:
                child.returncode = os.waitstatus_to_exitcode(status)
    finally:
        fd, child_fd = child_fd, None
        os.close(fd)
    reap_exited_children()
    rc = child.returncode
    return rc if rc >= 0 else 128 - rc


if __name__ == '__main__':
    sys.exit(main())
