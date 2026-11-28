"""Carry a bounded native loopback connection to its private Unix connector."""

import select
import socket
import os
import subprocess
import sys
from threading import Event, Thread
import time


_BLOCK = 16 * 1024
_WIRE_LIMIT = 512 * 1024
_CONNECTOR = "/run/oc-transport/metadata.sock"
_ENTRYPOINT = "/run/oc-native/agy_acp_server.par"


class NativeProxyError(RuntimeError):
    """The private native proxy failed to complete one bounded connection."""


def _time_left(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NativeProxyError("Google native connector deadline expired")
    return remaining


def _pump(local, broker, deadline):
    peers = {local: broker, broker: local}
    remaining = dict.fromkeys(peers, _WIRE_LIMIT)
    while peers:
        readable, _, _ = select.select(tuple(peers), (), (), _time_left(deadline))
        for source in readable:
            target = peers[source]
            source.settimeout(min(2, _time_left(deadline)))
            data = source.recv(min(_BLOCK, remaining[source] + 1))
            if not data:
                target.shutdown(socket.SHUT_WR)
                del peers[source]
                continue
            remaining[source] -= len(data)
            if remaining[source] < 0:
                raise NativeProxyError("Google native connector exceeded its byte limit")
            target.settimeout(min(2, _time_left(deadline)))
            target.sendall(data)


def open_loopback_proxy():
    """Bind only inside the native network namespace, before starting the child."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
    except OSError:
        listener.close()
        raise NativeProxyError("Google native loopback proxy is unavailable") from None
    return listener


def relay_connection(listener, connector, deadline):
    """Relay one native stream to the fixed Unix mount, without DNS or outbound TCP."""
    try:
        listener.settimeout(_time_left(deadline))
        local, _ = listener.accept()
        with local, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker:
            broker.settimeout(min(2, _time_left(deadline)))
            broker.connect(str(connector))
            _pump(local, broker, deadline)
    except OSError:
        raise NativeProxyError("Google native connector did not settle") from None


def _serve_loopback(listener, deadline, exchanges, failed):
    try:
        for _ in range(exchanges):
            relay_connection(listener, _CONNECTOR, deadline)
    except NativeProxyError:
        failed.set()


def _run_metadata(mode):
    """Run inside bubblewrap. Connect only to the already-owned metadata socket."""
    deadline = time.monotonic() + (195 if mode == "enroll" else 24)
    exchanges = 2 if mode == "enroll" else 3
    failed = Event()
    with open_loopback_proxy() as listener:
        proxy = f"http://127.0.0.1:{listener.getsockname()[1]}"
        environment = os.environ | {key: proxy for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")}
        process = subprocess.Popen([_ENTRYPOINT, "--uid="], env=environment, close_fds=True, stderr=subprocess.DEVNULL)
        worker = Thread(target=_serve_loopback, args=(listener, deadline, exchanges, failed), daemon=True)
        worker.start()
        try:
            while process.poll() is None:
                if failed.wait(min(.1, _time_left(deadline))):
                    raise NativeProxyError("Google native metadata relay retired early")
            return 1 if failed.is_set() else process.returncode
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)


if __name__ == "__main__":
    try:
        entrypoint, mode = sys.argv
        if entrypoint != "/run/oc-native/metadata-proxy.py" or mode not in {"enroll", "cold"}:
            raise NativeProxyError("Invalid private Google metadata relay mode")
        raise SystemExit(_run_metadata(mode))
    except (NativeProxyError, OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit(1) from None
