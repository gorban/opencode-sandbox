#!/usr/bin/env python3
"""Own the persistent setup lock for the lifetime of the calling shell's pipe.

The lock file lives in host-trusted state. It is opened without following a final
symlink, never unlinked, and checked for ownership, type, link count and identity.
"""
import fcntl
import os
import re
import select
import stat
import sys
import time


def has_write_lock(info, inode):
    for line in info:
        fields = line.split()
        if len(fields) < 8 or fields[0] != 'lock:' or fields[2:5] != ['FLOCK', 'ADVISORY', 'WRITE']:
            continue
        if int(fields[6].rsplit(':', 1)[1]) == inode:
            return True
    return False


def descriptor_holds_lock(proc, entry, opened):
    if not entry.name.isdigit():
        return False
    try:
        target = os.stat(entry.path)
        if (target.st_dev, target.st_ino) != (opened.st_dev, opened.st_ino):
            return False
        with open(f'{proc}/fdinfo/{entry.name}', encoding='ascii') as info:
            return has_write_lock(info, opened.st_ino)
    except (OSError, ValueError, IndexError):
        return False


def guard_holds_lock(pid, opened):
    """Verify diagnostic metadata against a same-user guard's locked descriptor."""
    proc = f'/proc/{pid}'
    try:
        if os.stat(proc).st_uid != os.geteuid():
            return False
        with os.scandir(f'{proc}/fd') as entries:
            return any(descriptor_holds_lock(proc, entry, opened) for entry in entries)
    except OSError:
        return False


def validate_lock_file(fd, directory, filename):
    opened = os.fstat(fd)
    named = os.stat(filename, dir_fd=directory, follow_symlinks=False)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid() or
        stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1 or
        (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
        raise ValueError('setup lock has unsafe ownership, mode, links or identity')


def setup_holder(fd):
    text = os.pread(fd, 256, 0).decode('ascii', 'replace').strip()
    match = re.fullmatch(r'pid=(\d+) instance=([a-z0-9-]+) guard=(\d+)', text, flags=re.ASCII)
    if match and guard_holds_lock(int(match[3]), os.fstat(fd)):
        return f'pid={match[1]} instance={match[2]}'
    return None


def report_lock_wait(fd, name, wait_started):
    holder = setup_holder(fd) if name == 'setup' else None
    if holder is not None or time.monotonic() - wait_started >= 1:
        print(f'Waiting for {name} ({holder or "holder unknown"}) to finish...', file=sys.stderr, flush=True)
        return True
    return False


def wait_for_lock(fd, name, mode, parent):
    announced = False
    wait_started = time.monotonic()
    lock = fcntl.LOCK_SH if mode == 'shared' else fcntl.LOCK_EX
    while os.getppid() == parent and not select.select([sys.stdin], [], [], 0)[0]:
        try:
            fcntl.flock(fd, lock | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            announced = announced or report_lock_wait(fd, name, wait_started)
            select.select([sys.stdin], [], [], 0.1)
    return False


def main():
    if (len(sys.argv) != 6 or sys.argv[2] not in ('installation', 'setup', 'lifecycle', 'worktree') or
        sys.argv[3] not in ('shared', 'exclusive') or not sys.argv[5].isdigit() or
        not re.fullmatch(r'[a-z0-9-]+', sys.argv[4])):
        raise ValueError('invalid setup-lock arguments')
    state, name, mode, instance, parent = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
    if name != 'lifecycle' and mode != 'exclusive': raise ValueError('this setup lock must be exclusive')
    filename = instance + '.lock' if name == 'worktree' else name + '.lock'
    directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        ds = os.fstat(directory)
        if ds.st_uid != os.geteuid() or ds.st_mode & 0o022:
            raise ValueError('setup state directory is not owned and protected from other users')
        fd = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            validate_lock_file(fd, directory, filename)
            if not wait_for_lock(fd, name, mode, parent):
                return 1  # parent exited or explicitly closed the pipe
            validate_lock_file(fd, directory, filename)
            if mode == 'exclusive':
                data = f'pid={parent} instance={instance} guard={os.getpid()}\n'.encode('ascii')
                os.ftruncate(fd, 0)
                os.pwrite(fd, data, 0)
            print('LOCKED', flush=True)
            while os.getppid() == parent:
                if select.select([sys.stdin], [], [], 0.2)[0]:
                    return 0
            return 0
        finally:
            os.close(fd)
    finally:
        os.close(directory)


if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError, ValueError) as exc:
        print(f'cannot acquire shared setup lock: {exc}', file=sys.stderr, flush=True)
        sys.exit(1)
