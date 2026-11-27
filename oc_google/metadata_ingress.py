"""Read one measured standalone ACP request on a private enrollment connection."""

from dataclasses import dataclass, field
import re
import time

from .account_binding import _valid_bearer
from .metadata_destination import MetadataDestinationError, MetadataRoute, _remaining
from .oauth_exchange import _valid_client


_HEADER_LIMIT = 8192
_HEADER_VALUE_LIMIT = 4096
_REQUEST_SECONDS = 2.5
_TRAILING_SECONDS = 0.015
_DELIMITER = b"\r\n\r\n"
_COMMON_HEADERS = frozenset({
    b"host", b"authorization", b"accept-encoding", b"connection", b"content-type",
    b"content-length", b"user-agent",
})
_TOKEN_HEADERS = _COMMON_HEADERS | {b"accept"}
_REFRESH_HEADERS = (_TOKEN_HEADERS - {b"authorization"}) | {b"x-goog-api-client"}
_INITIAL_ROUTES = frozenset({MetadataRoute.TOKEN, MetadataRoute.LOAD_CODE_ASSIST})
_LENGTH = re.compile(rb"[1-9][0-9]{0,4}")


class MetadataIngressError(ValueError):
    """A redacted rejection of an unexpected native request."""


@dataclass(frozen=True, slots=True)
class NativeMetadataRequest:
    """Inert request fields for the controller to validate under its own fence."""

    route: MetadataRoute
    authorization: bytes | None = field(repr=False)
    body: bytes = field(repr=False)

    def __reduce_ex__(self, _protocol):
        raise TypeError("Native metadata request must remain in memory")


def _read(connection, size, deadline):
    connection.settimeout(_remaining(deadline))
    chunk = connection.recv(size)
    if not chunk or len(chunk) > size:
        raise MetadataIngressError("Incomplete native metadata request")
    return chunk


def _read_header(connection, deadline):
    data = bytearray()
    while _DELIMITER not in data:
        if len(data) == _HEADER_LIMIT:
            raise MetadataIngressError("Native metadata request headers exceeded the size limit")
        data.extend(_read(connection, min(4096, _HEADER_LIMIT - len(data)), deadline))
    header, _, body = data.partition(_DELIMITER)
    request_line, *lines = bytes(header).split(b"\r\n")
    return request_line, lines, body


def _fields(lines, expected):
    fields = {}
    if len(lines) != len(expected):
        raise MetadataIngressError("Unexpected native metadata request headers")
    for line in lines:
        name, delimiter, raw = line.partition(b": ")
        key = name.lower()
        if (not delimiter or key not in expected or key in fields or not 1 <= len(raw) <= _HEADER_VALUE_LIMIT
                or raw != raw.strip(b" ") or any(not 32 <= char <= 126 for char in raw)):
            raise MetadataIngressError("Unexpected native metadata request headers")
        fields[key] = raw
    return fields


def _read_body(connection, body, size, deadline):
    if len(body) > size:
        raise MetadataIngressError("Unexpected bytes after native metadata request")
    while len(body) < size:
        body.extend(_read(connection, min(4096, size - len(body)), deadline))

    # The client may wait for a response, so a clean connection need not EOF.
    # Check for already observed trailing bytes. The owner closes this channel
    # after one request and never treats a delayed request as another operation.
    connection.settimeout(min(_TRAILING_SECONDS, _remaining(deadline)))
    try:
        trailing = connection.recv(1)
    except TimeoutError:
        trailing = b""
    if trailing:
        raise MetadataIngressError("Unexpected bytes after native metadata request")
    _remaining(deadline)
    return bytes(body)


def _read_request(connection, route, deadline, *, refresh=False):
    host, method, target, media, max_body, _ = route.value
    target_line, lines, initial_body = _read_header(connection, deadline)
    if target_line != method + b" " + target + b" HTTP/1.1":
        raise MetadataIngressError("Unexpected native metadata request route")
    token = route is MetadataRoute.TOKEN
    expected = _REFRESH_HEADERS if refresh else (_TOKEN_HEADERS if token else _COMMON_HEADERS)
    fields = _fields(lines, expected)
    connection_modes = (b"close", b"keep-alive") if token else (b"close",)
    if (fields[b"host"] != host.encode("ascii") or fields[b"content-type"] != media
            or fields[b"connection"] not in connection_modes):
        raise MetadataIngressError("Unexpected native metadata request framing")

    authorization = fields.get(b"authorization")
    if not refresh:
        authorized = (_valid_client(authorization) if token else
                      authorization.startswith(b"Bearer ") and _valid_bearer(authorization[7:]))
        if not authorized:
            raise MetadataIngressError("Invalid native metadata authorization framing")

    length = fields[b"content-length"]
    if not _LENGTH.fullmatch(length) or int(length) > max_body:
        raise MetadataIngressError("Invalid native metadata request length")
    return NativeMetadataRequest(route, authorization, _read_body(connection, initial_body, int(length), deadline))


def _read_bounded_request(connection, route, deadline, *, refresh=False):
    try:
        _remaining(deadline)
        return _read_request(connection, route, min(deadline, time.monotonic() + _REQUEST_SECONDS), refresh=refresh)
    except (OSError, MetadataDestinationError):
        pass
    raise MetadataIngressError("Native metadata request did not settle")


def read_enrollment_request(
    connection, *, route: MetadataRoute, deadline: float,
) -> NativeMetadataRequest:
    """Read the exact expected request on a controller-verified connection.

    The controller authenticates the private TLS placement and admits one
    request per connection, then closes it. A parsed request does not grant
    outbound authority. The controller still verifies the code or bearer and
    application body before any delivery.
    """
    if type(route) is not MetadataRoute or route not in _INITIAL_ROUTES:
        raise MetadataIngressError("Native metadata route is unavailable during enrollment")
    return _read_bounded_request(connection, route, deadline)


def read_cold_refresh_request(connection, *, deadline: float) -> NativeMetadataRequest:
    """Read the exact form-only token request on the verified cold native channel."""
    return _read_bounded_request(connection, MetadataRoute.TOKEN, deadline, refresh=True)


def read_cold_metadata_request(connection, *, route: MetadataRoute, deadline: float) -> NativeMetadataRequest:
    """Read an authenticated metadata request after the cold subject check."""
    if route not in (MetadataRoute.LOAD_CODE_ASSIST, MetadataRoute.FETCH_AVAILABLE_MODELS):
        raise MetadataIngressError("Native metadata route is unavailable after cold refresh")
    return _read_bounded_request(connection, route, deadline)
