"""Bounded workstation HTTPS and Responses SSE. No ambient proxy or API key."""

import contextlib
import http.client
import json
import queue
import re
import socket
import ssl
import threading
import time

from .connection_state import ConnectionError, decode_json

AUTH_HOST = "auth.openai.com"
API_HOST = "api.openai.com"
DISCOVERY = "/.well-known/openid-configuration"
JWKS = "/.well-known/jwks.json"
TOKEN = "/api/accounts/oauth/token"
MODELS = "/v1/models"
RESPONSES = "/v1/responses"
_ORIGINS = {
    AUTH_HOST: {("GET", DISCOVERY), ("GET", JWKS), ("POST", TOKEN)},
    API_HOST: {("GET", MODELS), ("POST", RESPONSES)},
}
MAX_JSON = 1024 * 1024
MAX_STREAM = 2 * 1024 * 1024
MAX_LINE = 256 * 1024
MAX_EVENTS = 2048
IO_TIMEOUT = 10
CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,16}(?:;[^\r\n]*)?\r\n\Z")


class Cancellation:
    def __init__(self, deadline, stopped=None):
        self.event = threading.Event()
        self._deadline = deadline
        self._stopped = stopped
        self._lock = threading.Lock()
        self._socket = None

    def check(self):
        if self._stopped is not None and self._stopped.is_set():
            raise ConnectionError("openai_operation_cancelled")
        if time.monotonic() >= self._deadline:
            raise ConnectionError("openai_operation_timed_out")
        if self.event.is_set():
            raise ConnectionError("connection_retired")

    def attach(self, sock):
        with self._lock:
            self.check()
            self._socket = sock

    def cancel(self):
        with self._lock:
            self.event.set()
            if self._socket is not None:
                with contextlib.suppress(OSError):
                    self._socket.shutdown(socket.SHUT_RDWR)

    def close(self):
        with self._lock:
            self._socket = None


def _address_list(host, cancellation):
    result = queue.Queue(maxsize=1)

    def resolve():
        try:
            result.put(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
        except OSError:
            result.put([])

    # The system resolver itself may block. It holds no token or socket to OpenAI.
    threading.Thread(target=resolve, daemon=True).start()
    for _ in range(IO_TIMEOUT * 10):
        cancellation.check()
        try:
            addresses = result.get(timeout=0.1)
            if addresses:
                return addresses[:8]
            break
        except queue.Empty:
            pass
    raise ConnectionError("provider_network_error")


def _connect(host, cancellation):
    context = ssl.create_default_context()
    for family, kind, protocol, _, address in _address_list(host, cancellation):
        cancellation.check()
        try:
            with socket.socket(family, kind, protocol) as plain:
                cancellation.attach(plain)
                plain.settimeout(IO_TIMEOUT)
                plain.connect(address)
                sock = context.wrap_socket(plain, server_hostname=host,
                                           do_handshake_on_connect=False,
                                           suppress_ragged_eofs=False)
                try:
                    cancellation.attach(sock)
                    sock.do_handshake()
                    return sock
                except BaseException:
                    sock.close()
                    raise
        except OSError:
            cancellation.check()
    raise ConnectionError("provider_network_error")


def _validate_http(response):
    encodings = response.headers.get_all("Content-Encoding", [])
    lengths = response.headers.get_all("Content-Length", [])
    transfers = response.headers.get_all("Transfer-Encoding", [])
    if (response.status < 200 or 300 <= response.status < 400
            or encodings not in ([], ["identity"])
            or len(lengths) > 1 or len(transfers) > 1
            or (transfers and (lengths or transfers[0].strip().lower() != "chunked"))
            or (lengths and (len(lengths[0]) > 20 or not lengths[0].isascii()
                             or not lengths[0].isdigit()))):
        raise ConnectionError("invalid_provider_http")


def _read_json(response):
    if response.length is not None and response.length > MAX_JSON:
        raise ConnectionError("provider_response_too_large")
    data = response.read(MAX_JSON + 1)
    if len(data) > MAX_JSON:
        raise ConnectionError("provider_response_too_large")
    if response.length not in (None, 0):
        raise ConnectionError("invalid_provider_http")
    try:
        value = decode_json(data) if data else {}
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, RecursionError):
        raise ConnectionError("invalid_provider_json") from None


class _HeaderReader:
    def __init__(self, stream):
        self._stream = stream

    def readline(self, limit):
        line = self._stream.readline(limit)
        if not line.endswith(b"\r\n"):
            raise http.client.HTTPException("incomplete response headers")
        return line

    def close(self):
        self._stream.close()


class _StrictResponse(http.client.HTTPResponse):
    def begin(self):
        raw = self.fp
        headers = _HeaderReader(raw)
        self.fp = headers
        try:
            super().begin()
        finally:
            if self.fp is headers:
                self.fp = raw

    def _get_chunk_left(self):
        remaining = self.chunk_left
        if not remaining:
            if remaining == 0 and self._safe_read(2) != b"\r\n":
                raise http.client.HTTPException("invalid chunk delimiter")
            size = self.fp.readline(MAX_LINE + 1)
            if len(size) > MAX_LINE or not CHUNK_SIZE.fullmatch(size):
                raise http.client.HTTPException("invalid chunk size")
            remaining = int(size.rstrip(b"\r\n").split(b";", 1)[0], 16)
            if remaining == 0:
                for _ in range(100):
                    line = self.fp.readline(MAX_LINE + 1)
                    if line == b"\r\n":
                        self._close_conn()
                        remaining = None
                        break
                    if len(line) > MAX_LINE or not line.endswith(b"\r\n") or b":" not in line:
                        raise http.client.HTTPException("incomplete chunk trailer")
                else:
                    raise http.client.HTTPException("too many chunk trailers")
            self.chunk_left = remaining
        return remaining


def _events(response, cancellation):
    if response.headers.get_content_type() != "text/event-stream":
        raise ConnectionError("invalid_provider_stream")
    data = []
    event_name = None
    received = 0
    events = 0
    done = False
    completed = None
    while True:
        cancellation.check()
        line = response.readline(MAX_LINE + 1)
        if not line:
            if data or response.length not in (None, 0):
                raise ConnectionError("invalid_provider_stream")
            cancellation.check()
            if completed is not None:
                yield completed
            return
        received += len(line)
        if received > MAX_STREAM or len(line) > MAX_LINE or not line.endswith(b"\n"):
            raise ConnectionError("provider_stream_limit")
        line = line.rstrip(b"\r\n")
        if done:
            if line:
                raise ConnectionError("invalid_provider_stream")
            continue
        if line.startswith(b"event:"):
            if event_name is not None:
                raise ConnectionError("invalid_provider_stream")
            event_name = line[6:].lstrip(b" ")
        elif line.startswith(b"data:"):
            field = line[5:]
            data.append(field[1:] if field.startswith(b" ") else field)
        elif not line and data:
            events += 1
            if events > MAX_EVENTS:
                raise ConnectionError("provider_stream_limit")
            payload = b"\n".join(data)
            if payload == b"[DONE]":
                if event_name is not None:
                    raise ConnectionError("invalid_provider_stream")
                data.clear()
                done = True
                continue
            try:
                frame = decode_json(payload)
                if not isinstance(frame, dict) or not isinstance(frame.get("type"), str):
                    raise ValueError
                if event_name is not None and frame["type"].encode("utf-8") != event_name:
                    raise ValueError
            except (ValueError, RecursionError):
                raise ConnectionError("invalid_provider_stream") from None
            data.clear()
            event_name = None
            cancellation.check()
            if completed is not None:
                raise ConnectionError("invalid_provider_stream")
            if frame["type"] == "response.completed":
                # A caller may stop consuming as soon as success is delivered.
                # Verify the remaining HTTP framing before exposing completion.
                completed = frame
            else:
                yield frame
        elif not line:
            event_name = None


class OpenAITransport:
    """Only fixed, directly connected TLS origins accepted in production."""

    def _allowed(self, host, method, path, revocation):
        if (method, path) in _ORIGINS.get(host, ()):
            return True
        # This path is taken only from the issuer's TLS-protected discovery.
        return (revocation and host == AUTH_HOST and method == "POST"
                and path.startswith("/") and not path.startswith("//")
                and path.isascii() and all(char.isalnum() or char in "/-._" for char in path))

    @contextlib.contextmanager
    def _request(self, host, path, *, method, body, content_type, bearer,
                 cancellation, dispatch, revocation=False):
        if not self._allowed(host, method, path, revocation):
            raise ConnectionError("invalid_provider_destination")
        if bearer is not None and (host != API_HOST or not bearer.isascii()
                                   or any(ord(char) <= 32 or ord(char) >= 127 for char in bearer)):
            raise ConnectionError("invalid_provider_credential")
        if len(body) > MAX_JSON:
            raise ConnectionError("provider_request_too_large")
        fields = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close",
                  "Accept-Encoding: identity", f"Content-Length: {len(body)}"]
        if path == RESPONSES:
            fields.append("Accept: text/event-stream")
        else:
            fields.append("Accept: application/json")
        if content_type:
            fields.append(f"Content-Type: {content_type}")
        if bearer is not None:
            fields.append(f"Authorization: Bearer {bearer}")
        packet = "\r\n".join([*fields, "", ""]).encode("ascii") + body
        try:
            with _connect(host, cancellation) as sock:
                def first_write():
                    # The durable generation lock covers only a nonblocking
                    # first write. TLS connect and response reads are outside it.
                    sock.setblocking(False)
                    try:
                        cancellation.check()
                        return sock.send(packet)
                    except OSError:
                        raise ConnectionError("provider_send_uncertain") from None
                    finally:
                        sock.settimeout(IO_TIMEOUT)

                sent = dispatch(first_write)
                cancellation.check()
                if not sent:
                    raise ConnectionError("provider_send_uncertain")
                if sent < len(packet):
                    sock.sendall(packet[sent:])
                cancellation.check()
                with contextlib.closing(_StrictResponse(sock, method=method)) as response:
                    response.begin()
                    _validate_http(response)
                    yield response
        except (OSError, http.client.HTTPException):
            cancellation.check()
            raise ConnectionError("provider_network_error") from None
        finally:
            cancellation.close()

    def json(self, host, path, *, cancellation, dispatch, body=None, bearer=None,
             revocation=False):
        method = "GET" if body is None else "POST"
        content_type = "application/x-www-form-urlencoded" if body is not None else None
        with self._request(host, path, method=method, body=body or b"",
                           content_type=content_type, bearer=bearer,
                           cancellation=cancellation, dispatch=dispatch,
                           revocation=revocation) as response:
            if revocation and response.status == 200:
                data = response.read(1)
                if not data and response.length not in (None, 0):
                    raise ConnectionError("invalid_provider_http")
                return response.status, {} if not data else {"unexpected_body": True}
            return response.status, _read_json(response)

    @contextlib.contextmanager
    def responses(self, body, bearer, cancellation, dispatch):
        try:
            encoded = json.dumps(body, allow_nan=False, ensure_ascii=True).encode("ascii")
        except (TypeError, ValueError, RecursionError):
            raise ConnectionError("invalid_responses_body") from None
        with self._request(API_HOST, RESPONSES, method="POST", body=encoded,
                           content_type="application/json", bearer=bearer,
                           cancellation=cancellation, dispatch=dispatch) as response:
            if response.status != 200:
                raise ConnectionError(response_error(response.status, _read_json(response)))
            yield _events(response, cancellation)


def response_error(status, body):
    error = body.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        known = {
            "subscription_sharing_usage_limit_exceeded": "chatgpt_usage_limit",
            "subscription_sharing_user_not_eligible": "chatgpt_plan_ineligible",
            "subscription_sharing_route_not_supported": "chatgpt_route_unavailable",
            "subscription_sharing_unsupported_capability": "chatgpt_request_unsupported",
            "subscription_sharing_usage_unavailable": "chatgpt_usage_unavailable",
        }
        if isinstance(code, str) and code in known:
            return known[code]
    return {401: "chatgpt_auth_rejected", 403: "chatgpt_access_refused",
            429: "chatgpt_usage_limit", 503: "chatgpt_unavailable"}.get(
                status, "provider_response_failed")
