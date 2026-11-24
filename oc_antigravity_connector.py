"""A bounded, credential-free TLS qualification for pinned Antigravity hosts."""

from contextlib import suppress
import errno
import os
import select
import selectors
import socket
import ssl
from threading import Lock, Timer
import time

from oc_antigravity_dns import HOSTS, remaining, resolve


CHUNK = 8192
MAX_HANDSHAKE_BYTES = 262144
CONNECT_PENDING = {0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK}
WORKSTATION_ROOTS = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
DIAGNOSTIC_LIFETIME = 8.0


class ConnectorError(RuntimeError):
    """The scoped diagnostic connection is unavailable or retired."""


class DiagnosticAttempt:
    def __init__(self, hostname, *, owner_fd, deadline):
        if hostname not in HOSTS:
            raise ConnectorError("unrecognized provider destination")
        self.hostname = hostname
        self.deadline = deadline
        self._owner = os.dup(owner_fd)
        try:
            if os.readlink(f"/proc/self/fd/{self._owner}") != "anon_inode:[pidfd]":
                raise ConnectorError("diagnostic requires a process descriptor")
        except BaseException:
            os.close(self._owner)
            raise
        self._lock = Lock()
        self._sock = None
        self._spent = False
        self._timer = Timer(max(0, deadline - time.monotonic()), self.revoke)
        self._timer.daemon = True
        self._timer.start()

    def _close(self):
        self._timer.cancel()
        if self._owner is None:
            return
        owner, self._owner = self._owner, None
        connection, self._sock = self._sock, None
        try:
            if connection is not None:
                with suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)
                connection.close()
        finally:
            os.close(owner)

    def revoke(self):
        with self._lock:
            self._close()

    def _require(self):
        if self._owner is not None:
            status = select.poll()
            status.register(self._owner, select.POLLIN)
            if time.monotonic() < self.deadline and not status.poll(0):
                return
        self._close()
        raise ConnectorError("diagnostic attempt is closed")

    def connect(self, *, resolver=resolve, make_socket=socket.socket):
        with self._lock:
            self._require()
            if self._spent:
                raise ConnectorError("diagnostic dial already spent")
            self._spent = True
        family, address = resolver(self.hostname, deadline=self.deadline)
        with self._lock:
            self._require()
            self._sock = make_socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self._sock.setblocking(False)
            result = self._sock.connect_ex(address)
            if result not in CONNECT_PENDING:
                raise ConnectorError("numeric connection failed")
        self._ready(selectors.EVENT_WRITE)
        with self._lock:
            self._require()
            if self._sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) or self._sock.getpeername() != address:
                raise ConnectorError("could not verify exact numeric connection")

    def _ready(self, events):
        with selectors.DefaultSelector() as selector:
            with self._lock:
                self._require()
                if self._sock is None:
                    raise ConnectorError("diagnostic has no tracked socket")
                selector.register(self._sock, events)
            while not selector.select(min(remaining(self.deadline), .1)):
                with self._lock:
                    self._require()

    def send(self, data):
        while True:
            self._ready(selectors.EVENT_WRITE)
            with self._lock:
                self._require()
                try:
                    return self._sock.send(data)
                except BlockingIOError:
                    continue

    def receive(self):
        while True:
            self._ready(selectors.EVENT_READ)
            with self._lock:
                self._require()
                try:
                    return self._sock.recv(CHUNK)
                except BlockingIOError:
                    continue


def flush_handshake(attempt, outgoing, total):
    while outgoing.pending:
        buffer = memoryview(outgoing.read(CHUNK))
        total += len(buffer)
        if total > MAX_HANDSHAKE_BYTES:
            raise ConnectorError("diagnostic TLS send limit exceeded")
        while buffer:
            count = attempt.send(buffer)
            if not count:
                raise ConnectorError("diagnostic TLS peer stopped receiving")
            buffer = buffer[count:]
    return total


def certificate_handshake(attempt, context):
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ConnectorError("certificate and hostname verification are required")
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=attempt.hostname)
    inbound = outbound = 0
    while True:
        complete = False
        needs_read = False
        try:
            tls.do_handshake()
            complete = True
        except ssl.SSLWantReadError:
            needs_read = True
        except ssl.SSLWantWriteError:
            pass
        outbound = flush_handshake(attempt, outgoing, outbound)
        if complete:
            return tls.version()
        if needs_read:
            data = attempt.receive()
            inbound += len(data)
            if not data or inbound > MAX_HANDSHAKE_BYTES:
                raise ConnectorError("diagnostic TLS response closed or reached its limit")
            incoming.write(data)


def qualify_tls(hostname, *, owner_fd, deadline):
    """Verify one provider TLS connection without sending application data."""
    cutoff = min(deadline, time.monotonic() + DIAGNOSTIC_LIFETIME)
    attempt = DiagnosticAttempt(hostname, owner_fd=owner_fd, deadline=cutoff)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.hostname_checks_common_name = False
        context.load_verify_locations(cafile=WORKSTATION_ROOTS)
        attempt.connect()
        return certificate_handshake(attempt, context)
    finally:
        attempt.revoke()
