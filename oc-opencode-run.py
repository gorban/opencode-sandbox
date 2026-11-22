#!/usr/bin/env python3
"""Forward signals and reap exited children while running OpenCode."""
import os
import signal
import subprocess
import sys


WAIT_ALL_CHILDREN = 0x40000000  # Linux __WALL includes non-SIGCHLD clone children.


def main():
    child_fd = None
    pending = set()
    def deliver(signum):
        try: signal.pidfd_send_signal(child_fd, signum)
        except ProcessLookupError: pass
    def forward(signum, _frame):
        if child_fd is None:
            pending.add(signum)
        else:
            deliver(signum)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(sig, forward)
    # The image entry point forwards OpenCode arguments within the same agent container.
    # Its image PATH includes the sandbox's writable OpenCode installation for self-updates.
    try: child = subprocess.Popen(['opencode', *sys.argv[1:]])
    except OSError as exc:
        print(f'cannot start OpenCode: {exc}', file=sys.stderr)
        return 127
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
    rc = child.returncode
    while True:
        try:
            if os.waitpid(-1, os.WNOHANG | WAIT_ALL_CHILDREN)[0] == 0: break
        except ChildProcessError: break
    return rc if rc >= 0 else 128 - rc


if __name__ == '__main__': sys.exit(main())
