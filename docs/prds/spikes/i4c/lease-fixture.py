"""Use the revocable offline broker for the real pinned native client."""

from contextlib import suppress
import os
from pathlib import Path
import runpy
import select
import socket
from threading import Thread
import time


HERE = Path(__file__).parent
TUNNEL = runpy.run_path(str(HERE / "offline-tunnel.py"))
TLS = runpy.run_path(str(HERE / "tls-fixture.py"))


def owner_in_unit(pid, unit, run_host):
    try:
        pidfd = os.pidfd_open(pid)
    except OSError:
        return False
    try:
        group = run_host(["/usr/bin/systemctl", "--user", "show", "--property=ControlGroup", "--value", unit],
                         timeout=2)
        member = run_host(["/usr/bin/cat", f"/proc/{pid}/cgroup"], timeout=2)
        exact = group.stdout.strip()
        if (group.returncode or member.returncode or not exact.startswith(b"/") or
                not exact.endswith(b"/" + unit.encode("ascii"))):
            return False
        return b"0::" + exact in member.stdout.splitlines() and not select.select((pidfd,), (), (), 0)[0]
    finally:
        os.close(pidfd)


def create(generation, unit, run_host):
    return TUNNEL["OfflineAttempt"](generation, deadline=time.monotonic() + 22, expected_uid=os.getuid(),
                                    verify_owner=lambda pid: owner_in_unit(pid, unit, run_host))


def fake_dns(_hostname, port, **_kwargs):
    return ((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port)),)


def exchange(listener, path, lease, *, hostname, context, evidence, respond, authorize):
    try:
        client, _ = listener.accept()
        with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as local:
            tunnel = lease.admit(client, host=hostname)
            try:
                hello = lease.hello(tunnel, authorize=authorize)
                local.bind(str(path))
                local.listen(1)
                local.settimeout(2)
                lease.dial(tunnel, fake_resolve=fake_dns, fake_path=str(path))
                peer, _ = local.accept()
                with peer:
                    server = Thread(target=TLS["record_outcome"], args=(peer, context, evidence, respond), daemon=True)
                    server.start()
                    try:
                        lease.connected(tunnel)
                        lease.pump(tunnel, hello)
                    finally:
                        with suppress(OSError):
                            peer.shutdown(socket.SHUT_RDWR)
                        server.join(6)
            finally:
                with suppress(TUNNEL["AttemptClosed"]):
                    lease.finish(tunnel)
    except (OSError, RuntimeError, ValueError):
        return
