"""Admission policy for the observed, specific native OAuth tunnel."""

import ipaddress
import re
import socket
import time


TOKEN_HOST = "oauth2.googleapis.com"
PORT = 443
AUTHORITY = b"oauth2.googleapis.com:443"
REQUEST = b"CONNECT " + AUTHORITY + b" HTTP/1.1"
DELIMITER = b"\r\n\r\n"
HEADER_LIMIT = 8192


class Refused(ValueError):
    """The tunnel request is outside the measured enrollment phase."""


def enrollment_authority(header):
    if len(header) > HEADER_LIMIT or not header.endswith(DELIMITER):
        raise Refused()
    request, *lines = header[:-len(DELIMITER)].split(b"\r\n")
    if request != REQUEST:
        raise Refused()
    fields = {}
    for line in lines:
        name, separator, value = line.partition(b": ")
        name = name.lower()
        if not separator or name not in {b"host", b"user-agent"} or name in fields:
            raise Refused()
        if not re.fullmatch(rb"[ -~]{1,512}", value) or value != value.strip():
            raise Refused()
        fields[name] = value
    if fields.get(b"host") != AUTHORITY:
        raise Refused()
    return TOKEN_HOST


def read_connect(client, *, timeout=2):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while DELIMITER not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or len(data) == HEADER_LIMIT:
            raise Refused()
        client.settimeout(remaining)
        chunk = client.recv(min(2048, HEADER_LIMIT - len(data)))
        if not chunk:
            raise Refused()
        data.extend(chunk)
    return enrollment_authority(bytes(data))


def public_address(family, address):
    if family == socket.AF_INET and len(address) == 2:
        host, port = address
    elif family == socket.AF_INET6 and len(address) == 4 and address[2:] == (0, 0):
        host, port = address[:2]
    else:
        raise Refused()
    if port != PORT or "%" in host:
        raise Refused()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as error:
        raise Refused() from error
    expected_family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
    if (family != expected_family or not ip.is_global or ip.is_multicast or ip.is_reserved
            or getattr(ip, "ipv4_mapped", None) is not None or getattr(ip, "is_site_local", False)):
        raise Refused()
    if family == socket.AF_INET:
        return str(ip), PORT
    return str(ip), PORT, 0, 0


def resolve_token_endpoint(*, resolve=socket.getaddrinfo):
    records = resolve(TOKEN_HOST, PORT, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not 1 <= len(records) <= 32:
        raise Refused()
    endpoints = []
    for family, kind, protocol, _, address in records:
        if kind != socket.SOCK_STREAM or protocol != socket.IPPROTO_TCP:
            raise Refused()
        endpoints.append((family, public_address(family, address)))
    return tuple(dict.fromkeys(endpoints))
