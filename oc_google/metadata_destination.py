"""Single-connection HTTP/1.1 transport for the four Google metadata routes."""

from enum import Enum
import ipaddress
import os
from queue import Empty, Queue
import re
import socket
import ssl
from threading import Thread, get_ident
import time
from typing import Callable

from .account_binding import _valid_bearer
from .oauth_exchange import _valid_client


_HEADER_LIMIT = 8192
_ADDRESS_LIMIT = 32
_MAX_OPERATION_SECONDS = 30
_JSON = b"application/json"
_FORM = b"application/x-www-form-urlencoded"
_DELIMITER = b"\r\n\r\n"
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_LENGTH = re.compile(rb"[1-9][0-9]{0,5}")


class MetadataRoute(Enum):
    """Exact request endpoints and per-route byte bounds."""

    TOKEN = ("oauth2.googleapis.com", b"POST", b"/token", _FORM, 8192, 32768)
    USERINFO = ("www.googleapis.com", b"GET", b"/oauth2/v2/userinfo?fields=id", None, 0, 1024)
    LOAD_CODE_ASSIST = ("cloudcode-pa.googleapis.com", b"POST", b"/v1internal:loadCodeAssist", _JSON, 32768, 131072)
    FETCH_AVAILABLE_MODELS = (
        "daily-cloudcode-pa.googleapis.com", b"POST", b"/v1internal:fetchAvailableModels", _JSON, 32768, 131072,
    )


class MetadataDestinationError(RuntimeError):
    """A redacted refusal or unsettled Google metadata exchange."""


def _remaining(deadline):
    if type(deadline) not in (int, float):
        raise MetadataDestinationError("Invalid Google metadata deadline")
    try:
        remaining = deadline - time.monotonic()
    except OverflowError:
        remaining = 0
    if not 0 < remaining < float("inf"):
        raise MetadataDestinationError("Google metadata deadline expired")
    return remaining


def _request(route, authorization, body):
    if type(route) is not MetadataRoute:
        raise MetadataDestinationError("Unknown Google metadata route")
    host, method, target, media, max_request, max_reply = route.value
    if type(body) is not bytes or len(body) > max_request or (media is not None and not body):
        raise MetadataDestinationError("Invalid Google metadata request size")
    if route is MetadataRoute.TOKEN:
        authorized = authorization is None or _valid_client(authorization)
    else:
        authorized = (type(authorization) is bytes and len(authorization) <= 8199
                      and authorization.startswith(b"Bearer ") and _valid_bearer(authorization[7:]))
    if not authorized:
        raise MetadataDestinationError("Invalid Google metadata authorization")
    packet = [
        method + b" " + target + b" HTTP/1.1",
        b"Host: " + host.encode("ascii"),
        b"Accept: application/json",
        b"Accept-Encoding: identity",
        b"Connection: close",
        b"User-Agent: oc-sandbox",
    ]
    if authorization is not None:
        packet.append(b"Authorization: " + authorization)
    if media is not None:
        packet.extend((b"Content-Type: " + media, b"Content-Length: " + str(len(body)).encode("ascii")))
    return host, b"\r\n".join(packet) + _DELIMITER + body, max_reply


def _numeric_address(record):
    family, kind, number, _canonical, address = record
    if kind != socket.SOCK_STREAM or number != socket.IPPROTO_TCP or type(address) is not tuple:
        raise ValueError
    if family == socket.AF_INET and len(address) == 2:
        ip, port = address
        version = 4
    elif family == socket.AF_INET6 and len(address) == 4 and address[2:] == (0, 0):
        ip, port = address[:2]
        version = 6
    else:
        raise ValueError
    if type(ip) is not str or "%" in ip or type(port) is not int or port != 443:
        raise ValueError
    value = ipaddress.ip_address(ip)
    if (value.version != version or not value.is_global or value.is_multicast or value.is_reserved
            or value.is_loopback or value.is_link_local or value.is_unspecified
            or getattr(value, "is_site_local", False) or getattr(value, "ipv4_mapped", None) is not None
            or getattr(value, "sixtofour", None) is not None or getattr(value, "teredo", None) is not None):
        raise ValueError
    exact = (str(value), port)
    return family, exact if version == 4 else (*exact, 0, 0)


def _resolve(host, deadline):
    pending = Queue(maxsize=1)

    def resolve():
        try:
            pending.put(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP))
        except OSError:
            pending.put(None)

    # libc DNS has no per-call timeout. A late worker owns only the fixed lookup,
    # never a credential, a socket, or authority to connect.
    Thread(target=resolve, daemon=True).start()
    try:
        records = pending.get(timeout=_remaining(deadline))
        if not records or len(records) > _ADDRESS_LIMIT:
            raise ValueError
        addresses = tuple(map(_numeric_address, records))
    except (Empty, ValueError, TypeError):
        pass
    else:
        return addresses[0]
    raise MetadataDestinationError("Google metadata DNS did not return a bounded public address set")


def _system_tls_context():
    paths = ssl.get_default_verify_paths()
    # The non-openssl fields incorporate SSL_CERT_FILE and SSL_CERT_DIR.
    cafile, capath = paths.openssl_cafile, paths.openssl_capath
    cafile = cafile if cafile and os.path.isabs(cafile) and os.path.isfile(cafile) else None
    capath = capath if capath and os.path.isabs(capath) and os.path.isdir(capath) else None
    if cafile is None and capath is None:
        raise MetadataDestinationError("Google metadata system trust is unavailable")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=cafile, capath=capath)
    context.set_alpn_protocols(["http/1.1"])
    return context


def _recv(connection, count, deadline):
    connection.settimeout(_remaining(deadline))
    return connection.recv(count)


def _response(connection, limit, deadline):
    buffer = bytearray()
    while _DELIMITER not in buffer:
        if len(buffer) == _HEADER_LIMIT:
            raise MetadataDestinationError("Google metadata response header limit")
        chunk = _recv(connection, min(4096, _HEADER_LIMIT - len(buffer)), deadline)
        if not chunk:
            raise MetadataDestinationError("Incomplete Google metadata response")
        buffer.extend(chunk)
    head, _, body = buffer.partition(_DELIMITER)
    status, *lines = bytes(head).split(b"\r\n")
    if not re.fullmatch(rb"HTTP/1\.1 200 [ -~]*", status):
        raise MetadataDestinationError("Unexpected Google metadata HTTP status")
    fields = {}
    for line in lines:
        name, separator, value = line.partition(b":")
        name = name.lower()
        if (not separator or not _HEADER_NAME.fullmatch(name) or name in fields
                or not re.fullmatch(rb"[ -~]*", value)):
            raise MetadataDestinationError("Invalid Google metadata response header")
        fields[name] = value.strip(b" ")
    length = fields.get(b"content-length", b"")
    if ({b"transfer-encoding", b"trailer", b"upgrade"} & fields.keys()
            or fields.get(b"content-encoding", b"identity").lower() != b"identity"
            or fields.get(b"connection", b"close").lower() != b"close"
            or fields.get(b"content-type", b"").lower() not in {_JSON, _JSON + b"; charset=utf-8"}
            or not _LENGTH.fullmatch(length) or not len(body) <= int(length) <= limit):
        raise MetadataDestinationError("Invalid Google metadata response framing")
    size = int(length)
    while len(body) < size:
        chunk = _recv(connection, min(4096, size - len(body)), deadline)
        if not chunk:
            raise MetadataDestinationError("Incomplete Google metadata response")
        body.extend(chunk)
    if _recv(connection, 1, deadline):
        raise MetadataDestinationError("Unexpected bytes after Google metadata response")
    return bytes(body)


def _send_under_gate(connection, packet, deadline, deliver):
    owner = get_ident()
    active = True
    attempted = False
    sent = False

    def send():
        nonlocal attempted, sent
        if get_ident() != owner or not active or attempted:
            raise MetadataDestinationError("Google metadata write authority is unavailable")
        attempted = True
        connection.settimeout(_remaining(deadline))
        if connection.send(packet) != len(packet):
            raise MetadataDestinationError("Google metadata write was incomplete")
        sent = True

    try:
        deliver(send)
    finally:
        active = False
        packet = None
        connection = None
    if not sent:
        raise MetadataDestinationError("Google metadata request was not sent")


def exchange(
    route: MetadataRoute, *, authorization: bytes | None, body: bytes = b"", deadline: float,
    deliver: Callable[[Callable[[], None]], None],
) -> bytes:
    """Return one bounded raw JSON response from the exact metadata route.

    The trusted caller validates application data and supplies a monotonic
    deadline no more than 30 seconds ahead. TLS setup sends no HTTP
    application bytes. The caller's deliver
    function must durably spend the exact operation and hold the revocation
    fence while invoking its one-use send closure synchronously. Any uncertain
    write remains the caller's blocking receipt. No automatic retry is made.
    """
    if _remaining(deadline) > _MAX_OPERATION_SECONDS:
        raise MetadataDestinationError("Google metadata deadline exceeds the operation limit")
    host, packet, limit = _request(route, authorization, body)
    try:
        family, address = _resolve(host, deadline)
        context = _system_tls_context()
        with socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP) as plain:
            plain.settimeout(_remaining(deadline))
            plain.connect(address)
            plain.settimeout(_remaining(deadline))
            with context.wrap_socket(plain, server_hostname=host, suppress_ragged_eofs=False) as connection:
                if connection.selected_alpn_protocol() not in (None, "http/1.1"):
                    raise MetadataDestinationError("Unexpected Google metadata TLS protocol")
                _send_under_gate(connection, packet, deadline, deliver)
                return _response(connection, limit, deadline)
    except OSError:
        pass
    raise MetadataDestinationError("Google metadata transport did not settle")
