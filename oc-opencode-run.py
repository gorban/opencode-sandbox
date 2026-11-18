#!/usr/bin/env python3
"""Forward signals and reap exited children while running OpenCode."""
import os
import signal
import subprocess
import sys


def main():
    child = None
    def forward(signum, _frame):
        if child is not None and child.poll() is None:
            try: child.send_signal(signum)
            except ProcessLookupError: pass
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(sig, forward)
    try: child = subprocess.Popen(['opencode', *sys.argv[1:]])
    except OSError as exc:
        print(f'cannot start OpenCode: {exc}', file=sys.stderr)
        return 127
    rc = child.wait()
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0: break
        except ChildProcessError: break
    return rc if rc >= 0 else 128 - rc


if __name__ == '__main__': sys.exit(main())
