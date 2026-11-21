"""Bounded subprocess I/O for the trusted Sonar publisher."""

from contextlib import suppress
import os
import selectors
import signal
import subprocess
import time


class PublishError(RuntimeError):
    pass


def capture(command, *, cwd, env, timeout=30, limit=1_000_000, payload=None, monitor=None):
    """Read both streams under one byte and time budget. Never print child output."""
    stdin = subprocess.DEVNULL if payload is None else subprocess.PIPE
    deadline = time.monotonic() + timeout
    with subprocess.Popen(command, cwd=cwd, env=env, stdin=stdin, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True) as process:
        try:
            if payload is not None:
                with suppress(BrokenPipeError), process.stdin as stream:
                    stream.write(payload)
            stdout, stderr = drain_output(process, deadline, limit, monitor)
            if monitor is not None:
                monitor()
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    return code, stdout, stderr


def drain_output(process, deadline, budget, monitor):
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    with selectors.DefaultSelector() as selector:
        for stream, buffer in streams.items():
            selector.register(stream, selectors.EVENT_READ, buffer)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PublishError('Command timed out')
            if monitor is not None:
                monitor()
            for key, _ in selector.select(min(remaining, 0.25)):
                budget -= append_output(selector, key, budget)
    return bytes(streams[process.stdout]), bytes(streams[process.stderr])


def append_output(selector, key, budget):
    chunk = os.read(key.fd, min(65_536, budget + 1))
    if not chunk:
        selector.unregister(key.fileobj)
    elif len(chunk) > budget:
        raise PublishError('Command exceeded the output limit')
    else:
        key.data.extend(chunk)
    return len(chunk)
