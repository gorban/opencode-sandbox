"""Resolve one pinned Antigravity destination with bounded, checked output."""

from contextlib import suppress
import ipaddress
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import time


HOSTS = ("oauth2.googleapis.com", "www.googleapis.com")
PORT = 443
MAX_ANSWERS = 32
MAX_WIRE = 4096
RESOLVER_LIFETIME = 2.0
GLOBAL_UNICAST_V6 = ipaddress.IPv6Network("2000::/3")
TRANSITION_V6 = (ipaddress.IPv6Network("2002::/16"), ipaddress.IPv6Network("2001::/32"))


class ResolverError(RuntimeError):
    """The pinned destination could not be resolved within policy."""


def public_sockaddr(family, address):
    if family == socket.AF_INET and type(address) is list and len(address) == 2:
        host, port = address
    elif (family == socket.AF_INET6 and type(address) is list and len(address) == 4
          and type(address[2]) is int and type(address[3]) is int and address[2:] == [0, 0]):
        host, port = address[:2]
    else:
        raise ResolverError("invalid address family or scope")
    if type(host) is not str or type(port) is not int or port != PORT or "%" in host:
        raise ResolverError("invalid numeric destination")
    try:
        numeric = ipaddress.ip_address(host)
    except ValueError as error:
        raise ResolverError("invalid numeric destination") from error
    correct = socket.AF_INET if numeric.version == 4 else socket.AF_INET6
    if (family != correct or not numeric.is_global or numeric.is_multicast or numeric.is_reserved
            or getattr(numeric, "ipv4_mapped", None) is not None or getattr(numeric, "is_site_local", False)):
        raise ResolverError("DNS returned a non-public destination")
    if family == socket.AF_INET:
        return str(numeric), PORT
    if numeric not in GLOBAL_UNICAST_V6 or any(numeric in reserved for reserved in TRANSITION_V6):
        raise ResolverError("DNS returned a non-public destination")
    return str(numeric), PORT, 0, 0


def validate_answers(payload):
    try:
        records = json.loads(payload)
    except (ValueError, RecursionError) as error:
        raise ResolverError("invalid resolver reply") from error
    if type(records) is not list or not 1 <= len(records) <= MAX_ANSWERS:
        raise ResolverError("unexpected DNS answer count")
    checked = []
    for record in records:
        if type(record) is not list or len(record) != 4:
            raise ResolverError("invalid resolver row")
        family, kind, protocol, address = record
        if (any(type(value) is not int for value in (family, kind, protocol)) or kind != socket.SOCK_STREAM
                or protocol != socket.IPPROTO_TCP):
            raise ResolverError("invalid resolver row")
        checked.append((family, public_sockaddr(family, address)))
    return tuple(dict.fromkeys(checked))


def remaining(deadline):
    wait = deadline - time.monotonic()
    if wait <= 0:
        raise TimeoutError("resolver deadline expired")
    return wait


def read_output(pipe, deadline):
    payload = bytearray()
    with selectors.DefaultSelector() as ready:
        ready.register(pipe, selectors.EVENT_READ)
        while ready.select(remaining(deadline)):
            piece = os.read(pipe.fileno(), MAX_WIRE + 1 - len(payload))
            if not piece:
                return bytes(payload)
            payload.extend(piece)
            if len(payload) > MAX_WIRE:
                raise ResolverError("resolver reply exceeded its byte limit")
    raise TimeoutError("resolver deadline expired")


def stop_child(child):
    if child.poll() is None:
        with suppress(ProcessLookupError):
            child.kill()
    try:
        child.wait(timeout=.5)
    except subprocess.TimeoutExpired as error:
        raise ResolverError("resolver process retirement could not be verified") from error


def capture_resolver(command, *, deadline):
    try:
        child = subprocess.Popen(command, env={"PATH": "/usr/bin:/bin", "LANG": "C"}, cwd="/", close_fds=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as error:
        raise ResolverError("resolver could not start") from error
    try:
        with child.stdout as pipe:
            payload = read_output(pipe, deadline)
        if child.wait(timeout=remaining(deadline)):
            raise ResolverError("resolver process failed")
        return payload
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ResolverError("resolver unavailable or timed out") from error
    finally:
        stop_child(child)


def resolve(host, *, deadline):
    if host not in HOSTS:
        raise ResolverError("unrecognized provider destination")
    child = [sys.executable, "-IBS", str(Path(__file__).resolve()), "--resolve-child", host]
    output = capture_resolver(child, deadline=min(deadline, time.monotonic() + RESOLVER_LIFETIME))
    return validate_answers(output)[0]


def resolver_child(host):
    if host not in HOSTS:
        return 2
    try:
        rows = socket.getaddrinfo(host + ".", PORT, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        if len(rows) > MAX_ANSWERS:
            return 1
        records = [(family, kind, protocol, address) for family, kind, protocol, _, address in rows]
        payload = json.dumps(records, separators=(",", ":")).encode("ascii")
        if len(payload) > MAX_WIRE:
            return 1
        sys.stdout.buffer.write(payload)
    except (OSError, ValueError):
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--resolve-child":
        raise SystemExit(2)
    raise SystemExit(resolver_child(sys.argv[2]))
