"""Bounded subprocess I/O for the trusted Sonar publisher."""

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
        streams = {process.stdout: bytearray(), process.stderr: bytearray()}
        try:
            if payload is not None:
                try:
                    process.stdin.write(payload)
                    process.stdin.close()
                except BrokenPipeError:
                    pass
            with selectors.DefaultSelector() as selector:
                for stream in streams:
                    selector.register(stream, selectors.EVENT_READ)
                remaining_bytes = limit
                while selector.get_map():
                    remaining_time = deadline - time.monotonic()
                    if remaining_time <= 0:
                        raise PublishError('Command timed out')
                    if monitor is not None:
                        monitor()
                    for key, _ in selector.select(min(remaining_time, 0.25)):
                        data = os.read(key.fd, min(65_536, remaining_bytes + 1))
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        remaining_bytes -= len(data)
                        if remaining_bytes < 0:
                            raise PublishError('Command exceeded the output limit')
                        streams[key.fileobj].extend(data)
            if monitor is not None:
                monitor()
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
    return code, bytes(streams[process.stdout]), bytes(streams[process.stderr])
