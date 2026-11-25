"""Keep the offline placement owned if its operator-facing launcher exits."""

from contextlib import contextmanager
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import threading


class OwnerLost(RuntimeError):
    """The launcher stopped before the proof settled."""


class Lifeline:
    def __init__(self, pipe):
        self.pipe = pipe
        self.lost = threading.Event()
        self.lock = threading.Lock()
        self.revoke = None
        threading.Thread(target=self.watch, args=(pipe,), daemon=True).start()

    def watch(self, pipe):
        try:
            os.read(pipe, 1)
        except OSError:
            pass
        self.lost.set()
        with self.lock:
            if self.revoke is not None:
                self.revoke()

    def check(self):
        if not self.active():
            raise OwnerLost("launcher exited before the proof settled")

    def active(self):
        if self.lost.is_set():
            return False
        # Observe EOF even when the watcher has not been scheduled yet.
        ready = select.poll()
        ready.register(self.pipe, select.POLLIN | select.POLLHUP | select.POLLERR)
        return not ready.poll(0)

    @contextmanager
    def revoke_on_loss(self, revoke):
        with self.lock:
            self.check()
            self.revoke = revoke
        try:
            yield
        finally:
            with self.lock:
                self.revoke = None


def supervise(script: Path):
    command = [sys.executable, "-IB", str(script), "_owner"]
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True) as owner:
        try:
            if owner.stdout.read(1) == b"R":
                owner.stdin.write(b"S")
                owner.stdin.flush()
            return owner.wait()
        except KeyboardInterrupt:
            owner.stdin.close()
            owner.wait()
            raise


def accept_launch():
    if not stat.S_ISFIFO(os.fstat(0).st_mode) or not stat.S_ISFIFO(os.fstat(1).st_mode):
        raise OwnerLost("launcher lifeline is unavailable")
    os.write(1, b"R")
    if os.read(0, 1) != b"S":
        raise OwnerLost("launcher did not start the proof")
    return Lifeline(0)
