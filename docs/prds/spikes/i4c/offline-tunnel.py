"""One revocable enrollment attempt, wired only to Unix-domain fake peers."""

from contextlib import suppress
from dataclasses import dataclass
import errno
from pathlib import Path
import runpy
import socket
import struct
from threading import Lock, Timer
import time


HERE = Path(__file__).parent
POLICY = runpy.run_path(str(HERE / "egress-policy.py"))
TLS = runpy.run_path(str(HERE / "tls-admission.py"))
PHASES = (POLICY["TOKEN_HOST"], POLICY["USERINFO_HOST"])
CONNECT_PENDING = (0, errno.EINPROGRESS, errno.EAGAIN, errno.EALREADY)
CHUNK_SIZE = 8192


class AttemptClosed(RuntimeError):
    """The supervisor no longer owns the operation or its deadline passed."""


@dataclass(eq=False)
class PendingTunnel:
    generation: str
    host: str
    client: socket.socket
    hello_remaining: bytes = b""
    dial_started: bool = False
    remote: socket.socket | None = None
    connected: bool = False
    forwarded: int = 0
    transferred: int = 0


def retire_socket(peer):
    with suppress(OSError):
        peer.shutdown(socket.SHUT_RDWR)
    peer.close()


class OfflineAttempt:
    """Fence all observable fake-peer writes and one Unix dial per slot."""

    def __init__(self, generation, *, deadline, expected_pid, expected_uid):
        self.generation = generation
        self.deadline = deadline
        self.expected_peer = (expected_pid, expected_uid)
        self._lock = Lock()
        self._phase = 0
        self._active = None
        self._revoked = False
        self._deadline_timer = Timer(max(0, deadline - time.monotonic()), self.revoke)
        self._deadline_timer.daemon = True
        self._deadline_timer.start()

    def _available(self):
        if not self._revoked and time.monotonic() >= self.deadline:
            self._revoke()
        return not self._revoked

    def _require(self, tunnel):
        if not self._available() or tunnel is not self._active or tunnel.generation != self.generation:
            raise AttemptClosed("the enrollment attempt is closed")

    def admit(self, client, *, host):
        if client.family != socket.AF_UNIX:
            raise AttemptClosed("expected a private Unix peer")
        peer = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", peer)
        with self._lock:
            if (not self._available() or self._active is not None or self._phase >= len(PHASES)
                    or host != PHASES[self._phase] or (pid, uid) != self.expected_peer):
                raise AttemptClosed("the peer or enrollment slot is unavailable")
            self._active = PendingTunnel(self.generation, host, client)
            return self._active

    def hello(self, tunnel):
        POLICY["read_connect"](tunnel.client, hostname=tunnel.host, timeout=min(TLS["remaining"](self.deadline), 2))
        with self._lock:
            self._require(tunnel)
            # Short control response on a nonblocking socket, before entering TLS.
            tunnel.client.setblocking(False)
            if tunnel.client.send(TLS["ESTABLISHED"]) != len(TLS["ESTABLISHED"]):
                raise AttemptClosed("could not acknowledge the enrollment tunnel")
        accepted = TLS["read_client_hello"](tunnel.client, deadline=self.deadline,
                                            hostname=tunnel.host.encode("ascii"))
        with self._lock:
            self._require(tunnel)
            tunnel.client.setblocking(False)
            tunnel.hello_remaining = accepted
        return accepted

    def dial(self, tunnel, *, fake_resolve, fake_path):
        with self._lock:
            self._require(tunnel)
            if not tunnel.hello_remaining or tunnel.dial_started:
                raise AttemptClosed("the slot has no fresh Hello")
            tunnel.dial_started = True
        candidate = POLICY["resolve_token_endpoint"](resolve=fake_resolve, hostname=tunnel.host)[0]
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        peer.setblocking(False)
        with self._lock:
            try:
                self._require(tunnel)
                status = peer.connect_ex(fake_path)
                if status not in CONNECT_PENDING:
                    raise OSError(status, "fake enrollment peer connection failed")
            except BaseException:
                peer.close()
                raise
            tunnel.remote = peer
        return candidate

    def connected(self, tunnel):
        with self._lock:
            self._require(tunnel)
            if tunnel.remote is None or tunnel.remote.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                raise AttemptClosed("the synthetic peer did not connect")
            tunnel.remote.getpeername()
            tunnel.connected = True

    def write(self, tunnel, data, *, to_peer=True):
        with self._lock:
            self._require(tunnel)
            if (not tunnel.connected or not 0 < len(data) <= CHUNK_SIZE
                    or tunnel.transferred + len(data) > TLS["TUNNEL_LIMIT"]):
                raise AttemptClosed("the bounded transfer is unavailable")
            if tunnel.hello_remaining and (not to_peer or not tunnel.hello_remaining.startswith(data)):
                raise AttemptClosed("the validated Hello must be forwarded first")
            receiver = tunnel.remote if to_peer else tunnel.client
            sent = receiver.send(data)
            if to_peer:
                tunnel.forwarded += sent
                tunnel.hello_remaining = tunnel.hello_remaining[sent:]
            tunnel.transferred += sent
            return sent

    def _retire(self):
        if self._active is not None:
            retire_socket(self._active.client)
            if self._active.remote is not None:
                retire_socket(self._active.remote)
            self._active = None

    def finish(self, tunnel):
        with self._lock:
            self._require(tunnel)
            if not tunnel.forwarded or tunnel.hello_remaining:
                self._revoke()
                return
            self._phase += 1
            self._retire()
            if self._phase == len(PHASES):
                self._revoke()

    def _revoke(self):
        self._revoked = True
        self._deadline_timer.cancel()
        self._retire()

    def revoke(self):
        with self._lock:
            self._revoke()
