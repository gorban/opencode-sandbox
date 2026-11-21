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


def guard_holds_lock(pid, opened):
    """Verify diagnostic metadata against a same-user guard's locked descriptor."""
    proc = f'/proc/{pid}'
    try:
        if os.stat(proc).st_uid != os.geteuid():
            return False
        with os.scandir(f'{proc}/fd') as entries:
            for entry in entries:
                if not entry.name.isdigit():
                    continue
                try:
                    target = os.stat(entry.path)
                    if (target.st_dev, target.st_ino) != (opened.st_dev, opened.st_ino):
                        continue
                    with open(f'{proc}/fdinfo/{entry.name}', encoding='ascii') as info:
                        for line in info:
                            fields = line.split()
                            if len(fields) < 8 or fields[0] != 'lock:' or fields[2:5] != ['FLOCK', 'ADVISORY', 'WRITE']:
                                continue
                            if int(fields[6].rsplit(':', 1)[1]) == opened.st_ino:
                                return True
                except (OSError, ValueError, IndexError):
                    continue
    except OSError:
        pass
    return False


def main():
    if (len(sys.argv) != 6 or sys.argv[2] not in ('setup', 'lifecycle', 'worktree') or
        sys.argv[3] not in ('shared', 'exclusive') or not sys.argv[5].isdigit() or
        not re.fullmatch(r'[a-z0-9-]+', sys.argv[4])):
        raise ValueError('invalid setup-lock arguments')
    state, name, mode, instance, parent = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
    if name in ('setup', 'worktree') and mode != 'exclusive': raise ValueError('setup and worktree locks must be exclusive')
    filename = instance + '.lock' if name == 'worktree' else name + '.lock'
    directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        ds = os.fstat(directory)
        if ds.st_uid != os.geteuid() or ds.st_mode & 0o022:
            raise ValueError('setup state directory is not owned and protected from other users')
        fd = os.open(filename, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            def validate():
                opened = os.fstat(fd)
                named = os.stat(filename, dir_fd=directory, follow_symlinks=False)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid() or
                    stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1 or
                    (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
                    raise ValueError('setup lock has unsafe ownership, mode, links or identity')
            validate()
            announced = False
            wait_started = time.monotonic()
            while True:
                if os.getppid() != parent or select.select([sys.stdin], [], [], 0)[0]:
                    return 1  # parent exited or explicitly closed the pipe
                try:
                    fcntl.flock(fd, (fcntl.LOCK_SH if mode == 'shared' else fcntl.LOCK_EX) | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if not announced:
                        holder = None
                        if name == 'setup':
                            text = os.pread(fd, 256, 0).decode('ascii', 'replace').strip()
                            match = re.fullmatch(r'pid=(\d+) instance=([a-z0-9-]+) guard=(\d+)', text, flags=re.ASCII)
                            if match:
                                if guard_holds_lock(int(match[3]), os.fstat(fd)):
                                    holder = f'pid={match[1]} instance={match[2]}'
                        if holder is not None or time.monotonic() - wait_started >= 1:
                            print(f'Waiting for {name} ({holder or "holder unknown"}) to finish...', file=sys.stderr, flush=True)
                            announced = True
                    select.select([sys.stdin], [], [], 0.1)
            validate()
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
