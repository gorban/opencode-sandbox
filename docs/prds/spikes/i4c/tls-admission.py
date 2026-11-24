"""Admit one bounded TLS ClientHello before passing bytes to a fake peer."""

import selectors
import socket
import time


NAME = b"oauth2.googleapis.com"
HELLO_LIMIT = 32768
RECORD_LIMIT = 16384
TUNNEL_LIMIT = 262144
ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"


class Refused(ValueError):
    """A malformed or out-of-scope TLS hello."""


class Wire:
    def __init__(self, data):
        self.data = memoryview(data)

    def take(self, count):
        if count > len(self.data):
            raise Refused()
        part, self.data = self.data[:count], self.data[count:]
        return part

    def number(self, width):
        return int.from_bytes(self.take(width))

    def vector(self, width):
        return self.take(self.number(width))

    def done(self):
        return not self.data


def one_host(data, required):
    encoded = Wire(data)
    hosts = Wire(encoded.vector(2))
    if not encoded.done() or hosts.number(1) != 0 or hosts.vector(2) != required or not hosts.done():
        raise Refused()


def require_server_name(hello, *, hostname=NAME):
    payload = Wire(hello)
    payload.take(34)
    payload.vector(1)  # Session ID
    payload.vector(2)  # Cipher suites
    payload.vector(1)  # Compression methods
    extensions = Wire(payload.vector(2))
    if not payload.done():
        raise Refused()
    seen = set()
    while not extensions.done():
        kind = extensions.number(2)
        value = extensions.vector(2)
        if kind in seen or kind in (0xFE0D, 0xFFCE):
            raise Refused()
        seen.add(kind)
        if kind == 0:
            one_host(value, hostname)
    if 0 not in seen:
        raise Refused()


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError()
    return seconds


def read_exact(peer, count, deadline):
    data = bytearray()
    while len(data) < count:
        peer.settimeout(remaining(deadline))
        part = peer.recv(count - len(data))
        if not part:
            raise Refused()
        data.extend(part)
    return data


def read_client_hello(peer, *, deadline, hostname=NAME):
    wire = bytearray()
    handshake = bytearray()
    for _ in range(8):
        header = read_exact(peer, 5, deadline)
        size = int.from_bytes(header[3:])
        if header[0] != 22 or header[1] != 3 or header[2] not in (1, 2, 3):
            raise Refused()
        if not 0 < size <= RECORD_LIMIT or len(wire) + len(header) + size > HELLO_LIMIT:
            raise Refused()
        record = read_exact(peer, size, deadline)
        wire.extend(header)
        wire.extend(record)
        handshake.extend(record)
        if len(handshake) < 4:
            continue
        expected = 4 + int.from_bytes(handshake[1:4])
        if handshake[0] != 1 or expected > HELLO_LIMIT or len(handshake) > expected:
            raise Refused()
        if len(handshake) == expected:
            require_server_name(handshake[4:], hostname=hostname)
            return bytes(wire)
    raise Refused()


def relay(first, second, *, deadline, transferred=0):
    with selectors.DefaultSelector() as ready:
        ready.register(first, selectors.EVENT_READ, second)
        ready.register(second, selectors.EVENT_READ, first)
        while ready.get_map():
            for event, _ in ready.select(min(remaining(deadline), 1)):
                source, target = event.fileobj, event.data
                source.settimeout(min(remaining(deadline), 1))
                block = source.recv(8192)
                if not block:
                    ready.unregister(source)
                    target.shutdown(socket.SHUT_WR)
                    continue
                transferred += len(block)
                if transferred > TUNNEL_LIMIT:
                    raise Refused()
                target.settimeout(min(remaining(deadline), 1))
                target.sendall(block)
