"""Observe one synthetic native login through the mounted fixture socket."""

import os
import pty
import re
import runpy
import selectors
import socket
import subprocess
import sys
import threading
import time


SOCKET = "/run/oc-egress/observe.sock"
ROOT = "/run/oc-proof"
FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def bridge(listener, observed, *, tunnel=False):
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
            if tunnel:
                tls = runpy.run_path("/run/oc-native/tls-admission.py")
                deadline = time.monotonic() + 8
                tunnel_reply = tls["ESTABLISHED"]
                if tls["read_exact"](unix, len(tunnel_reply), deadline) != tunnel_reply:
                    return
                conn.sendall(tunnel_reply)
                try:
                    tls["relay"](conn, unix, deadline=deadline)
                finally:
                    observed.set()
                return
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


def run_login(port, observed, *, tunnel=False, private_env=None):
    proxy = f"http://127.0.0.1:{port}"
    env = {"HOME": ROOT, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TERM": "dumb",
           **{key: proxy for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")}}
    if private_env is not None:
        env.update(private_env)
    if tunnel:
        env["SSL_CERT_FILE"] = "/run/oc-native/synthetic-ca.pem"
        env["NODE_EXTRA_CA_CERTS"] = env["SSL_CERT_FILE"]
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
    tunnel = sys.argv[1:] == ["synthetic-tls"]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(12)
        receipt = threading.Event()
        worker = threading.Thread(target=bridge, args=(listener, receipt), kwargs={"tunnel": tunnel}, daemon=True)
        worker.start()
        try:
            run_login(listener.getsockname()[1], receipt, tunnel=tunnel)
            print("NATIVE_FAKE_TLS_FINISHED" if tunnel else "NATIVE_CONNECT_DENIED")
        except (OSError, RuntimeError):
            raise SystemExit("NATIVE_EGRESS_FIXTURE_FAILED") from None
        finally:
            worker.join(2)
