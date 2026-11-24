"""Observe one synthetic native login through the mounted fixture socket."""

import os
import pty
import re
import selectors
import socket
import subprocess
import threading
import time


SOCKET = "/run/oc-egress/observe.sock"
ROOT = "/run/oc-proof"
FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def bridge(listener, observed):
    try:
        conn, _ = listener.accept()
        with conn, socket.socket(socket.AF_UNIX) as unix:
            conn.settimeout(2)
            unix.settimeout(2)
            unix.connect(SOCKET)
            header = bytearray()
            while b"\r\n\r\n" not in header and len(header) < 8192:
                block = conn.recv(8192 - len(header))
                if not block:
                    return
                header.extend(block)
            unix.sendall(header)
            with unix.makefile("rb") as receipt:
                outcome = receipt.read(len(FORBIDDEN) + 1)
            if outcome == FORBIDDEN:
                conn.sendall(outcome)
                observed.set()
    except (OSError, ValueError):
        return


def observe(master, native, received):
    data = bytearray()
    sent = False
    cutoff = time.monotonic() + 10
    with selectors.DefaultSelector() as io:
        io.register(master, selectors.EVENT_READ)
        while time.monotonic() < cutoff and len(data) < 65536 and native.poll() is None and not received.is_set():
            if not io.select(.2):
                continue
            try:
                part = os.read(master, 4096)
            except OSError:
                break
            data.extend(part)
            if not sent and re.search(rb"(enter|paste).{0,90}(code|authorization)", data, re.IGNORECASE):
                os.write(master, b"4/oc-sandbox-synthetic-invalid-code\n")
                sent = True
    if not sent or not received.wait(.5):
        raise RuntimeError("expected offline native OAuth exchange was not observed")


def run_login(port, observed):
    proxy = f"http://127.0.0.1:{port}"
    env = {"HOME": ROOT, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TERM": "dumb",
           **{key: proxy for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")}}
    master, slave = pty.openpty()
    try:
        with os.fdopen(slave, "rb") as endpoint, subprocess.Popen(
                ["/run/oc-native/agy", "acp", "--login"], env=env, cwd=ROOT,
                stdin=endpoint, stdout=endpoint, stderr=endpoint) as native:
            try:
                observe(master, native, observed)
            finally:
                if native.poll() is None:
                    native.kill()
    finally:
        os.close(master)


if __name__ == "__main__":
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(12)
        receipt = threading.Event()
        worker = threading.Thread(target=bridge, args=(listener, receipt), daemon=True)
        worker.start()
        try:
            run_login(listener.getsockname()[1], receipt)
            print("NATIVE_CONNECT_DENIED")
        except (OSError, RuntimeError):
            raise SystemExit("NATIVE_EGRESS_FIXTURE_FAILED") from None
        finally:
            worker.join(2)
