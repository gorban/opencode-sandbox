"""Validate the pinned Google ACP offer and fence one loopback callback."""

import base64
from contextlib import nullcontext, suppress
from dataclasses import dataclass, field
from enum import Enum, auto
import hmac
import math
import os
import re
import select
import socket
from threading import Lock
import time
from urllib.parse import parse_qsl, unquote_to_bytes, urlencode, urlsplit

from .route import _send_once


HOST = "127.0.0.1"
CALLBACK_PATH = "/"
AUTHORITY = "accounts.google.com"
AUTH_PATH = "/o/oauth2/v2/auth"
AUTH_URL = f"https://{AUTHORITY}{AUTH_PATH}"
CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
SCOPES = frozenset(f"https://www.googleapis.com/auth/{name}"
                   for name in ("cloud-platform", "userinfo.email", "aicode"))
_BROWSER_SCOPES = SCOPES | {"email", "openid"}
_ISSUER = f"https://{AUTHORITY}"
_PARAMETERS = {"client_id": CLIENT_ID, "response_type": "code", "code_challenge_method": "S256",
               "access_type": "offline", "prompt": "consent"}
_FIELDS = _PARAMETERS.keys() | {"scope", "redirect_uri", "state", "code_challenge"}
_PRIVATE_PORTS = {9222, *range(8401, 8417)}
_LIMIT = 8192
_FIELDS_LIMIT = 24
_CALLBACK_FIELDS_LIMIT = 6
_CALLBACK_SECONDS = 2
_STATE = re.compile(r"[A-Za-z0-9_-]{30}")
_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_CODE = re.compile(r"[a-zA-Z0-9_./~-]{8,2048}")
_AUTHUSER = re.compile(r"[0-9]{1,3}")
_ERROR_DESCRIPTION_LIMIT = 256
_BAD_ESCAPE = re.compile(rb"%(?![0-9a-fA-F]{2})")
_SUCCESS_FIELDS = {"state", "code"}
_SUCCESS_METADATA = {"iss", "scope", "authuser", "prompt"}
_DENIAL_FIELDS = {"state", "error"}
_HEADERS = frozenset({
    b"host", b"accept", b"accept-encoding", b"accept-language", b"cache-control", b"connection", b"cookie",
    b"pragma", b"priority", b"sec-ch-ua", b"sec-ch-ua-mobile", b"sec-ch-ua-platform",
    b"sec-fetch-dest", b"sec-fetch-mode", b"sec-fetch-site", b"sec-fetch-storage-access",
    b"sec-fetch-user", b"sec-gpc", b"upgrade-insecure-requests", b"user-agent",
})


class Refused(RuntimeError):
    """A redacted authorization or callback failure."""


class Outcome(Enum):
    WAITING = auto()
    OFFERED = auto()
    OPEN = auto()
    FORWARDED = auto()
    DENIED = auto()
    CANCELLED = auto()
    UNCERTAIN = auto()


def _validate_port(port):
    if type(port) is not int or not 1024 <= port <= 65535 or port in _PRIVATE_PORTS:
        raise Refused("callback port is outside the approved range")


def redirect_uri(port):
    _validate_port(port)
    return f"http://{HOST}:{port}{CALLBACK_PATH}"


def _query_fields(query, count):
    if re.search(r"%(?![0-9a-fA-F]{2})", query):
        raise Refused("invalid authorization parameters")
    try:
        entries = parse_qsl(query, strict_parsing=True, max_num_fields=count, keep_blank_values=True,
                            errors="strict")
    except (UnicodeError, ValueError):
        raise Refused("invalid authorization parameters") from None
    fields = dict(entries)
    if len(fields) != len(entries):
        raise Refused("duplicate authorization parameters")
    return fields


def _exact_scopes(value, expected=SCOPES):
    scopes = value.split(" ")
    return len(scopes) == len(expected) and set(scopes) == expected


def _canonical_challenge(value):
    if not _CHALLENGE.fullmatch(value):
        return False
    decoded = base64.urlsafe_b64decode(value + "=")
    return base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value


@dataclass(frozen=True)
class Offer:
    url: str = field(repr=False)
    state: str = field(repr=False)
    challenge: str = field(repr=False)
    port: int


def validate_offer(raw, port):
    expected_redirect = redirect_uri(port)
    if (type(raw) is not str or not 1 <= len(raw) <= _LIMIT
            or any(not 33 <= ord(char) <= 126 for char in raw)
            or "#" in raw or not raw.startswith(AUTH_URL + "?")):
        raise Refused("invalid Google authorization origin")
    url = urlsplit(raw)
    fields = _query_fields(url.query, len(_FIELDS))
    if (fields.keys() != _FIELDS or any(fields[name] != value for name, value in _PARAMETERS.items())
            or fields["redirect_uri"] != expected_redirect or not _STATE.fullmatch(fields["state"])
            or not _canonical_challenge(fields["code_challenge"])):
        raise Refused("unexpected Google authorization parameters")
    if not _exact_scopes(fields["scope"]):
        raise Refused("unexpected Google authorization scopes")
    return Offer(raw, fields["state"], fields["code_challenge"], port)


@dataclass(frozen=True)
class Callback:
    state: str = field(repr=False)
    code: str | None = field(repr=False)


def _readable(channel, timeout_ms=0):
    poll = select.poll()
    poll.register(channel, select.POLLIN)
    return bool(poll.poll(timeout_ms))


def _read_request(connection, deadline):
    """Keep the bounded prefix for state recognition even on bad HTTP framing."""
    packet = bytearray()
    try:
        while b"\r\n\r\n" not in packet:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or len(packet) == _LIMIT:
                return bytes(packet), False
            connection.settimeout(remaining)
            block = connection.recv(_LIMIT - len(packet))
            if not block:
                return bytes(packet), False
            packet.extend(block)
        head, _, tail = packet.partition(b"\r\n\r\n")
        extra = tail or (_readable(connection) and connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT))
        return bytes(head), not extra
    except OSError:
        return bytes(packet), False


def _decode_component(raw):
    if _BAD_ESCAPE.search(raw) or any(not 33 <= byte <= 126 for byte in raw):
        raise Refused("invalid callback parameters")
    try:
        return unquote_to_bytes(raw).decode("utf-8", "strict")
    except UnicodeError:
        raise Refused("invalid callback parameters") from None


def _callback_fields(query):
    pairs = query.split(b"&", _CALLBACK_FIELDS_LIMIT)
    if len(pairs) > _CALLBACK_FIELDS_LIMIT:
        raise Refused("too many callback parameters")
    fields = {}
    for pair in pairs:
        raw_name, separator, raw_value = pair.partition(b"=")
        if not separator or not raw_name or b"=" in raw_value:
            raise Refused("invalid callback parameters")
        name = _decode_component(raw_name)
        if name in fields:
            raise Refused("duplicate callback parameters")
        if name == "scope":
            # Only the scope list uses a form-style separator as well as %20.
            value = _decode_component(raw_value.replace(b"+", b"%20"))
        else:
            value = _decode_component(raw_value)
        fields[name] = value
    return fields


def _states_from_rejected_request(head):
    """Recognize independent state pairs only to revoke, never to authorize."""
    first, line_end, _ = head.partition(b"\r\n")
    _, _, remainder = first.lstrip(b" ").partition(b" ")
    # Only recognition of a rejected request tolerates repeated ASCII spaces.
    remainder = remainder.strip(b" ")
    target, separator, version = remainder.rpartition(b" ")
    target_complete = bool(line_end or (separator and version.startswith(b"HTTP/")))
    if not separator or not target_complete:
        target = remainder
    path, separator, query = target.rstrip(b" ").partition(b"?")
    if path != b"/" or not separator:
        return
    query, fragment, _ = query.partition(b"#")
    pairs = query.split(b"&")
    if not target_complete and not fragment:
        # The final field may only be a prefix cut off by the read bound.
        pairs.pop()
    for pair in pairs:
        name, separator, value = pair.partition(b"=")
        if not separator:
            continue
        try:
            if _decode_component(name) == "state":
                state = _decode_component(value)
                if _STATE.fullmatch(state):
                    yield state
        except Refused:
            continue


def _safe_description(value):
    return 0 < len(value.encode("utf-8")) <= _ERROR_DESCRIPTION_LIMIT and value.isprintable()


def _callback_scopes(parameters):
    scope = parameters.get("scope")
    return (scope is None or _exact_scopes(scope)
            or (parameters.get("iss") == _ISSUER and _exact_scopes(scope, _BROWSER_SCOPES)))


def parse_callback(head, port):
    _validate_port(port)
    if type(head) is not bytes or len(head) > _LIMIT - 4:
        raise Refused("invalid callback headers")
    lines = head.split(b"\r\n")
    if not 2 <= len(lines) <= _FIELDS_LIMIT + 1:
        raise Refused("invalid callback headers")
    parts = lines[0].split(b" ")
    if (len(parts) != 3 or parts[0] != b"GET" or parts[2] != b"HTTP/1.1"
            or not parts[1] or any(not 33 <= value <= 126 for value in parts[1])):
        raise Refused("invalid callback request")
    fields = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        key = name.lower()
        if (not separator or key not in _HEADERS or key in fields
                or any(not 32 <= char <= 126 for char in value)):
            raise Refused("invalid callback header")
        # Keep only the Cookie name so a second field is still refused.
        fields[key] = None if key == b"cookie" else value.strip(b" ")
    if fields.get(b"host") != f"{HOST}:{port}".encode("ascii"):
        raise Refused("invalid callback host")
    path, separator, query = parts[1].partition(b"?")
    if path != CALLBACK_PATH.encode("ascii") or not separator or b"#" in query:
        raise Refused("invalid callback path")
    parameters = _callback_fields(query)
    state = parameters.get("state", "")
    if not _STATE.fullmatch(state):
        raise Refused("invalid callback state")
    if "iss" in parameters and parameters["iss"] != _ISSUER:
        raise Refused("invalid callback issuer")
    if _SUCCESS_FIELDS <= parameters.keys() <= _SUCCESS_FIELDS | _SUCCESS_METADATA:
        if (_CODE.fullmatch(parameters["code"])
                and _callback_scopes(parameters)
                and _AUTHUSER.fullmatch(parameters.get("authuser", "0"))
                and parameters.get("prompt", "none") in {"consent", "none"}):
            return Callback(state, parameters["code"])
    if (_DENIAL_FIELDS <= parameters.keys() <= _DENIAL_FIELDS | {"iss", "error_description"}
            and parameters["error"] == "access_denied"
            and _safe_description(parameters.get("error_description", "denied"))):
        return Callback(state, None)
    raise Refused("incompatible Google callback")


def acknowledgement(accepted):
    status = b"200 OK" if accepted else b"400 Bad Request"
    body = b"Callback processed. Return to the terminal.\n" if accepted else b"Callback refused. Return to the terminal.\n"
    return (b"HTTP/1.1 " + status + b"\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n"
            b"Content-Security-Policy: default-src 'none'\r\nX-Content-Type-Options: nosniff\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\nConnection: close\r\nContent-Length: "
            + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)


def bind_callback(port):
    """Hold the exact IPv4 workstation port before showing an offer."""
    _validate_port(port)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind((HOST, port))
        listener.listen(4)
        listener.setblocking(False)
        return listener
    except OSError:
        listener.close()
        raise Refused("workstation callback port could not be held") from None


def _socket_identity(channel):
    info = os.fstat(channel.fileno())
    return info.st_dev, info.st_ino


class CallbackGate:
    """Fence one pending attempt across two borrowed, owner-verified sockets.

    The controller checks the native listener and its private handoff before
    providing the channel. The authorization check binds the current generation,
    foreground terminal, and owner liveness, and returns True only while valid.
    """

    def __init__(self, listener, native_channel, *, native_port, authorized, deadline, fence=None):
        _validate_port(native_port)
        if type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline <= time.monotonic():
            raise Refused("callback deadline is invalid")
        try:
            local = (HOST, native_port)
            native = native_channel.getpeername()
            if (listener.family != socket.AF_INET or listener.gettimeout() != 0
                    or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                    or listener.getsockname() != local or _socket_identity(listener) == _socket_identity(native_channel)
                    or native_channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                    or not (native_channel.family == socket.AF_UNIX
                            or (native_channel.family == socket.AF_INET and native == local))):
                raise Refused("callback endpoints are invalid")
            self._listener_id = _socket_identity(listener)
            self._native_id = _socket_identity(native_channel)
        except (OSError, ValueError):
            raise Refused("callback endpoints are unavailable") from None
        self._listener = listener
        self._native = native_channel
        self._native_address = native
        self._address = local
        self._deadline = deadline
        self._authorized = authorized
        self._fence = nullcontext() if fence is None else fence
        self._lock = Lock()
        self._outcome = Outcome.WAITING
        self._state = None
        self._forwarded = None

    @property
    def outcome(self):
        with self._lock:
            return self._outcome

    def _authority_alive(self):
        try:
            return (time.monotonic() < self._deadline
                    and self._authorized() is True
                    and time.monotonic() < self._deadline)
        except (OSError, ValueError, RuntimeError):
            return False

    def _available(self):
        try:
            return (time.monotonic() < self._deadline
                    and self._listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                    and self._listener.getsockname() == self._address
                    and _socket_identity(self._listener) == self._listener_id
                    and self._native.getpeername() == self._native_address
                    and _socket_identity(self._native) == self._native_id
                    and not _readable(self._native)
                    and self._authority_alive())
        except (OSError, ValueError, RuntimeError):
            return False

    def accept_offer(self, raw):
        """Validate and return the only offer the controller may display."""
        with self._lock:
            if self._outcome is not Outcome.WAITING:
                raise Refused("authorization offer already attempted")
            self._outcome = Outcome.CANCELLED
            offer = validate_offer(raw, self._address[1])
            if not self._available():
                raise Refused("callback authority is unavailable")
            self._state = offer.state
            self._outcome = Outcome.OFFERED
            return offer

    def activate(self):
        """Open the callback only after the operator has received the offer."""
        with self._lock:
            if self._outcome is not Outcome.OFFERED:
                raise Refused("authorization offer cannot be activated")
            if not self._available():
                self._state = None
                self._outcome = Outcome.CANCELLED
                raise Refused("callback authority is unavailable")
            self._outcome = Outcome.OPEN

    def revoke(self):
        with self._lock:
            self._forwarded = None
            if self._outcome in {Outcome.WAITING, Outcome.OFFERED, Outcome.OPEN}:
                self._state = None
                self._outcome = Outcome.CANCELLED

    def take_forwarded(self):
        """Give the trusted owner the exact forwarded fields, once and in memory."""
        with self._lock:
            callback = self._forwarded
            self._forwarded = None
            if callback is not None and self._authority_alive():
                return callback
            return None

    def _reject_matching(self, head, address):
        with self._lock:
            if (self._outcome is Outcome.OPEN and address == self._address
                    and any(hmac.compare_digest(state, self._state) for state in _states_from_rejected_request(head))):
                self._state = None
                self._outcome = Outcome.CANCELLED

    def _receive_callback(self, connection, deadline):
        address = connection.getsockname()
        head, complete = _read_request(connection, deadline)
        if complete:
            try:
                callback = parse_callback(head, self._address[1])
            except Refused:
                pass
            else:
                return self._consume(callback, address)
        self._reject_matching(head, address)
        return False

    def _consume(self, callback, address):
        with self._fence, self._lock:
            if (self._outcome is not Outcome.OPEN or address != self._address
                    or not hmac.compare_digest(callback.state, self._state)):
                return False
            self._state = None
            self._outcome = Outcome.CANCELLED
            if callback.code is None:
                if not self._available():
                    return False
                self._outcome = Outcome.DENIED
                return True
            query = urlencode({"state": callback.state, "code": callback.code})
            data = (f"GET {CALLBACK_PATH}?{query} HTTP/1.1\r\n"
                    f"Host: {HOST}:{self._address[1]}\r\nConnection: close\r\n\r\n").encode("ascii")
            if not self._available():
                return False
            self._outcome = Outcome.UNCERTAIN
            try:
                if _send_once(self._native, data) == len(data) and self._authority_alive():
                    self._forwarded = callback
                    self._outcome = Outcome.FORWARDED
            except OSError:
                pass
            finally:
                if self._outcome is Outcome.UNCERTAIN:
                    try:
                        self._native.shutdown(socket.SHUT_WR)
                    except OSError:
                        with suppress(OSError):
                            self._native.close()
            return self._outcome is Outcome.FORWARDED

    def serve_one(self):
        """Handle at most one bounded browser request and reply with local text."""
        deadline = min(self._deadline, time.monotonic() + _CALLBACK_SECONDS)
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not _readable(self._listener, max(1, int(remaining * 1000))):
                    return
                try:
                    connection, peer = self._listener.accept()
                except BlockingIOError:
                    # Another reader can accept the connection after our poll.
                    continue
                break
        except (OSError, ValueError):
            return
        with connection:
            accepted = False
            try:
                accepted = peer[0] == HOST and self._receive_callback(connection, deadline)
            except (OSError, Refused):
                pass
            with suppress(OSError):
                connection.settimeout(.2)
                if accepted:
                    with self._fence, self._lock:
                        accepted = (self._authority_alive()
                                    and (self._outcome is Outcome.DENIED or self._forwarded is not None))
                        if not accepted and self._outcome is Outcome.FORWARDED:
                            self._forwarded = None
                            self._outcome = Outcome.UNCERTAIN
                        connection.sendall(acknowledgement(accepted))
                else:
                    connection.sendall(acknowledgement(False))
