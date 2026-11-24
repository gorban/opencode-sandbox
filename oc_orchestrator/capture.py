"""Capture bounded output from a host command in the offline proof."""

from contextlib import nullcontext, suppress
import os
import selectors
import signal
import subprocess
import time


class CaptureError(RuntimeError):
    """A host command exceeded its time or output budget."""


def drain(process, deadline, limit):
    output = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CaptureError("command timeout")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, min(65536, limit + 1))
                limit -= len(chunk)
                if limit < 0:
                    raise CaptureError("command output exceeded its limit")
                if not chunk:
                    selector.unregister(key.fileobj)
                elif key.data is not None:
                    key.data.extend(chunk)
    return bytes(output)


def kill_group(process):
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def capture(command, *, env, timeout, limit, lifeline=None, on_revoke=None):
    deadline = time.monotonic() + timeout
    with subprocess.Popen(command, env=env, cwd="/", stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True) as process:
        try:
            def revoke():
                kill_group(process)
                if on_revoke is not None:
                    on_revoke()

            ownership = nullcontext() if lifeline is None else lifeline.revoke_on_loss(revoke)
            with ownership:
                output = drain(process, deadline, limit)
                result = process.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException:
            kill_group(process)
            process.wait()
            raise
        return subprocess.CompletedProcess(command, result, stdout=output)
