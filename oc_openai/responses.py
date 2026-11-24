"""Bounded workstation HTTPS and Responses SSE. No ambient proxy or API key."""

import contextlib
from dataclasses import dataclass, replace
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
CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,16}[ \t]*(?:;[^\r\n]*)?\r\n\Z")
_SSE_END = re.compile(rb"\r\n|[\r\n]")
_STREAM_CODES = frozenset({
    "provider_stream_content_type", "provider_stream_incomplete", "provider_stream_limit",
    "provider_stream_json", "provider_stream_event_type", "provider_stream_named_done",
    "provider_stream_after_terminal", "provider_network_error",
})
_EVENT_COMPLETED = "response.completed"
_EVENT_NAMES = frozenset({
    "response.created", "response.in_progress", _EVENT_COMPLETED, "response.failed",
    "response.incomplete", "response.done", "response.output_text.delta", "response.output_text.done",
    "response.output_item.added", "response.output_item.done", "message", "done", "ping", "keepalive", "error",
})
_SSE_NAMES = {name.encode("ascii"): name for name in _EVENT_NAMES}
_SSE_NAMES.update({None: "none", b"": "empty"})
_MEDIA_TYPES = {
    "text/event-stream": "sse",
    "application/json": "json",
    "text/plain": "plain",
    "text/html": "html",
    "application/octet-stream": "octet-stream",
    "application/x-ndjson": "ndjson",
    "application/ndjson": "ndjson",
}
_PREFIX_LIMIT = 512
_SSE_PREFIXES = (b"data:", b"event:", b"data\n", b"data\r", b"event\n", b"event\r", b":")
_HTTP_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_HTTP_QUOTED = r'"(?:[\t !#-\[\]-~\x80-\xff]|\\[\t -~\x80-\xff])*"'
_HTTP_MEDIA = re.compile(rf"[ \t]*({_HTTP_TOKEN}/{_HTTP_TOKEN})[ \t]*")
_HTTP_PARAMETER = re.compile(rf";[ \t]*(?:({_HTTP_TOKEN})=(?:{_HTTP_TOKEN}|{_HTTP_QUOTED})[ \t]*)?")


@dataclass
class _StreamEvidence:
    media: str = "other"
    raw_bytes: int = 0
    lines: int = 0
    events: int = 0
    line: str = "none"
    sse: str = "none"
    json_type: str = "none"
    completed_seen: bool = False
    done_seen: bool = False
    media_fields: str | None = None
    prefix_shape: str = "not-read"
    prefix_bytes: int = 0


class StreamFailure(ConnectionError):
    """A provider stream failure with bounded, content-free structural evidence."""

    def __init__(self, code, evidence):
        super().__init__(code)
        self.evidence = replace(evidence)

    def describe(self):
        facts = self.evidence
        inspected = (
            f" media_fields={facts.media_fields} prefix={facts.prefix_shape} prefix_bytes={facts.prefix_bytes}"
            if facts.media_fields is not None else ""
        )
        return (
            f"Stream structure ({self.code}) media={facts.media} raw_bytes={facts.raw_bytes} "
            f"lines={facts.lines} events={facts.events} last_line={facts.line} "
            f"sse={facts.sse} json_type={facts.json_type} "
            f"completed_seen={int(facts.completed_seen)} done_seen={int(facts.done_seen)}{inspected}"
        )


@dataclass(frozen=True)
class StreamLimits:
    """Explicit per-call byte, line, event, and socket timeout ceilings."""

    max_json: int
    max_stream: int
    max_line: int
    max_events: int
    io_timeout: int

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in (
            self.max_json, self.max_stream, self.max_line, self.max_events, self.io_timeout,
        )):
            raise ValueError("StreamLimits values must be positive integers")


INTERACTIVE_STREAM_LIMITS = StreamLimits(
    max_json=4 * 1024 * 1024,
    max_stream=8 * 1024 * 1024,
    max_line=1024 * 1024,
    max_events=16_384,
    io_timeout=30,
)


def _active_limits(limits):
    if limits is not None:
        return limits
    return StreamLimits(MAX_JSON, MAX_STREAM, MAX_LINE, MAX_EVENTS, IO_TIMEOUT)


def encode_responses_body(body, *, max_json=None):
    """Prepare the exact bounded request bytes sent by the Responses connector."""
    limit = MAX_JSON if max_json is None else max_json
    try:
        encoded = json.dumps(body, allow_nan=False, ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        raise ConnectionError("invalid_responses_body") from None
    if len(encoded) > limit:
        raise ConnectionError("provider_request_too_large")
    return encoded


class Cancellation:
    def __init__(self, deadline, stopped=None):
        self.event = threading.Event()
        self._deadline = deadline
        self._stopped = stopped
        self._lock = threading.Lock()
        self._socket = None

    def check(self, *, allow_timeout=False):
        if self._stopped is not None and self._stopped.is_set():
            raise ConnectionError("openai_operation_cancelled")
        if self.event.is_set():
            raise ConnectionError("connection_retired")
        if time.monotonic() >= self._deadline:
            if allow_timeout:
                return False
            raise ConnectionError("openai_operation_timed_out")
        return True

    def attach(self, sock):
        with self._lock:
            self.check()
            self._socket = sock

    def cancel(self, *, expired=False):
        with self._lock:
            # Expiry wakes a blocked reader without marking the connection retired.
            if not expired:
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
    context.minimum_version = ssl.TLSVersion.TLSv1_2
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
    encodings = [item.strip().lower() for item in response.headers.get_all("Content-Encoding", [])]
    lengths = response.headers.get_all("Content-Length", [])
    transfers = response.headers.get_all("Transfer-Encoding", [])
    if (response.status < 200 or 300 <= response.status < 400
            or encodings not in ([], ["identity"])
            or len(lengths) > 1 or len(transfers) > 1
            or (transfers and (lengths or transfers[0].strip().lower() != "chunked"))
            or (lengths and (len(lengths[0]) > 20 or not lengths[0].isascii()
                             or not lengths[0].isdigit()))):
        raise ConnectionError("invalid_provider_http")


def _read_json(response, *, max_json=None):
    limit = MAX_JSON if max_json is None else max_json
    if response.length is not None and response.length > limit:
        raise ConnectionError("provider_response_too_large")
    data = response.read(limit + 1)
    if len(data) > limit:
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
    def __init__(self, sock, *, max_line=None, **kwargs):
        super().__init__(sock, **kwargs)
        self._max_line = MAX_LINE if max_line is None else max_line

    def begin(self):
        raw = self.fp
        headers = _HeaderReader(raw)
        self.fp = headers
        try:
            super().begin()
        finally:
            if self.fp is headers:
                self.fp = raw

    def _consume_chunk_trailers(self):
        for _ in range(100):
            line = self.fp.readline(self._max_line + 1)
            if line == b"\r\n":
                self._close_conn()
                return None
            if len(line) > self._max_line or not line.endswith(b"\r\n") or b":" not in line:
                raise http.client.HTTPException("incomplete chunk trailer")
        raise http.client.HTTPException("too many chunk trailers")

    def _get_chunk_left(self):
        remaining = self.chunk_left
        if not remaining:
            if remaining == 0 and self._safe_read(2) != b"\r\n":
                raise http.client.HTTPException("invalid chunk delimiter")
            size = self.fp.readline(self._max_line + 1)
            if len(size) > self._max_line or not CHUNK_SIZE.fullmatch(size):
                raise http.client.HTTPException("invalid chunk size")
            remaining = int(size.rstrip(b"\r\n").split(b";", 1)[0].strip(), 16)
            if remaining == 0:
                remaining = self._consume_chunk_trailers()
            self.chunk_left = remaining
        return remaining


def _split_sse_block(block, pending, trailing_cr, max_line):
    lines = []
    start = 0
    if trailing_cr:
        if block.startswith(b"\n"):
            pending.append(10)
            start = 1
        if len(pending) > max_line:
            raise ConnectionError("provider_stream_limit")
        lines.append(bytes(pending[:-(start + 1)]))
        pending.clear()
        trailing_cr = False
    for end in _SSE_END.finditer(block, start):
        pending.extend(block[start:end.end()])
        start = end.end()
        if len(pending) > max_line:
            raise ConnectionError("provider_stream_limit")
        # A trailing CR may be the first byte of a CRLF split across reads.
        if start == len(block) and end.group() == b"\r":
            trailing_cr = True
            break
        lines.append(bytes(pending[:-(end.end() - end.start())]))
        pending.clear()
    pending.extend(block[start:])
    if len(pending) > max_line:
        raise ConnectionError("provider_stream_limit")
    return lines, trailing_cr


def _stream_lines(response, cancellation, evidence, prefix=b"", *, limits=None):
    """Split SSE lines while charging the original bytes against both limits."""
    active = _active_limits(limits)
    pending = bytearray()
    received = 0
    trailing_cr = False
    while True:
        cancellation.check()
        block = prefix or response.read1(min(16_384, active.max_stream - received + 1))
        prefix = b""
        received += len(block)
        evidence.raw_bytes = received
        if received > active.max_stream:
            raise ConnectionError("provider_stream_limit")
        if not block and response.length not in (None, 0):
            raise ConnectionError("provider_stream_incomplete")
        lines, trailing_cr = _split_sse_block(block, pending, trailing_cr, active.max_line)
        yield from lines
        if not block:
            if pending:
                raise ConnectionError("provider_stream_incomplete")
            return


def _media_shape(headers):
    fields = headers.get_all("Content-Type", [])
    if not fields:
        return "none", "missing"
    if len(fields) != 1:
        return "multiple", "ambiguous"
    match = _HTTP_MEDIA.match(fields[0])
    if match is None:
        return "one", "ambiguous"
    media_type = match[1].lower()
    if media_type != headers.get_content_type():
        return "one", "ambiguous"
    offset = match.end()
    parameters = set()
    while offset < len(fields[0]):
        parameter = _HTTP_PARAMETER.match(fields[0], offset)
        if parameter is None:
            return "one", "ambiguous"
        if parameter[1] is not None:
            key = parameter[1].lower()
            if key in parameters:
                return "one", "ambiguous"
            parameters.add(key)
        offset = parameter.end()
    return "one", _MEDIA_TYPES.get(media_type, "other")


def _classify_prefix(prefix):
    text = prefix.removeprefix(b"\xef\xbb\xbf").lstrip(b" \r\n\t")
    if text.startswith(_SSE_PREFIXES):
        return "sse-like"
    if text.startswith((b"{", b"[")):
        return "json-like"
    if text.startswith(b"<"):
        return "markup-like"
    if not text or b"\xef\xbb\xbf".startswith(text) or any(tag.startswith(text) for tag in _SSE_PREFIXES):
        return None
    return "other"


def _inspect_prefix(response, cancellation, evidence):
    evidence.prefix_shape = "inconclusive"
    prefix = b""
    while len(prefix) < _PREFIX_LIMIT and cancellation.check(allow_timeout=True):
        try:
            block = response.read1(_PREFIX_LIMIT - len(prefix))
        except (OSError, http.client.HTTPException):
            cancellation.check(allow_timeout=True)
            return None
        evidence.raw_bytes += len(block)
        evidence.prefix_bytes += len(block)
        if not cancellation.check(allow_timeout=True):
            return None
        if not block:
            if not prefix and response.isclosed() and response.length in (None, 0):
                evidence.prefix_shape = "empty"
            return None
        prefix += block
        shape = _classify_prefix(prefix)
        if shape is not None:
            evidence.prefix_shape = shape
            return prefix
    return None


def _resolve_stream_prefix(response, cancellation, evidence, *, inspect_media, observe_media):
    prefix = b""
    if inspect_media or observe_media is not None:
        evidence.media_fields, evidence.media = _media_shape(response.headers)
    content_type = response.headers.get_content_type()
    expected_media = (
        evidence.media == "sse" if observe_media is not None else content_type == "text/event-stream"
    )
    if not expected_media:
        if inspect_media:
            inspected = _inspect_prefix(response, cancellation, evidence)
            if (observe_media is not None and evidence.media in {"missing", "plain", "octet-stream"}
                    and evidence.prefix_shape == "sse-like"):
                prefix = inspected
        else:
            evidence.media = _MEDIA_TYPES.get(content_type, "other")
        if not prefix:
            raise ConnectionError("provider_stream_content_type")
        observe_media(evidence.media)
    if not inspect_media and observe_media is None:
        evidence.media = "sse"
    return prefix


def _check_done_line(line, evidence):
    if line.startswith(b":"):
        evidence.line = "comment"
    elif line:
        evidence.line = "suffix"
    else:
        evidence.line = "separator"
    if line and not line.startswith(b":"):
        raise ConnectionError("provider_stream_after_terminal")


def _decode_sse_frame(payload, event_name, evidence):
    try:
        frame = decode_json(payload)
    except (ValueError, RecursionError):
        raise ConnectionError("provider_stream_json") from None
    if not isinstance(frame, dict) or not isinstance(frame.get("type"), str):
        raise ConnectionError("provider_stream_event_type")
    kind = frame["type"]
    evidence.json_type = kind if kind in _EVENT_NAMES else "other"
    evidence.completed_seen |= kind == _EVENT_COMPLETED
    try:
        if event_name not in (None, b"", b"message") and kind.encode("utf-8") != event_name:
            raise ConnectionError("provider_stream_event_type")
    except UnicodeEncodeError:
        raise ConnectionError("provider_stream_event_type") from None
    return frame, kind


class _SseParser:
    def __init__(self, evidence, active, prefix, cancellation):
        self.evidence = evidence
        self.active = active
        self.prefix = prefix
        self.cancellation = cancellation
        self.data = []
        self.event_name = None
        self.events = 0
        self.done = False
        self.completed = None

    def _flush_data(self):
        self.evidence.line = "separator"
        self.events += 1
        self.evidence.events = self.events
        if self.events > self.active.max_events:
            raise ConnectionError("provider_stream_limit")
        payload = b"\n".join(self.data)
        self.data.clear()
        name, self.event_name = self.event_name, None
        if payload == b"[DONE]":
            self.evidence.done_seen = True
            if name is not None and (self.completed is None or name not in {b"done", b"message"}):
                raise ConnectionError("provider_stream_named_done")
            self.done = True
            return None
        frame, kind = _decode_sse_frame(payload, name, self.evidence)
        self.cancellation.check()
        if self.completed is not None:
            raise ConnectionError("provider_stream_after_terminal")
        if kind == _EVENT_COMPLETED:
            # A caller may stop consuming as soon as success is delivered.
            # Verify the remaining HTTP framing before exposing completion.
            self.completed = frame
            return None
        return frame

    def _handle_other_line(self, line):
        self.evidence.line = "comment" if line.startswith(b":") else "field"
        standard_field = (
            line == b"id" or line.startswith(b"id:")
            or line == b"retry" or line.startswith(b"retry:")
        )
        if self.prefix and self.evidence.line == "field" and not standard_field:
            raise ConnectionError("provider_stream_event_type")

    def _feed_event_line(self, line):
        self.evidence.line = "event"
        if self.event_name is not None:
            raise ConnectionError("provider_stream_event_type")
        self.event_name = line[6:].removeprefix(b" ")
        self.evidence.sse = _SSE_NAMES.get(self.event_name, "other")

    def _feed_data_line(self, line):
        self.evidence.line = "data"
        if not self.data:
            self.evidence.sse = _SSE_NAMES.get(self.event_name, "other")
            self.evidence.json_type = "none"
        field = line[5:]
        self.data.append(field[1:] if field.startswith(b" ") else field)

    def _feed_separator(self):
        if self.data:
            return self._flush_data()
        self.evidence.line = "separator"
        if self.completed is not None and self.event_name is not None:
            raise ConnectionError("provider_stream_after_terminal")
        self.event_name = None
        return None

    def feed(self, line):
        if self.done:
            _check_done_line(line, self.evidence)
            return None
        if line == b"event" or line.startswith(b"event:"):
            self._feed_event_line(line)
            return None
        if line == b"data" or line.startswith(b"data:"):
            self._feed_data_line(line)
            return None
        if not line:
            return self._feed_separator()
        self._handle_other_line(line)
        return None


def _verify_tls_close(response, limits):
    sock = getattr(response, "_oc_sock", None)
    if not isinstance(sock, ssl.SSLSocket):
        raise ConnectionError("provider_network_error")
    sock.settimeout(min(5.0, limits.io_timeout))
    try:
        trailing = sock.recv(1)
    except OSError:
        raise ConnectionError("provider_network_error") from None
    if trailing:
        raise ConnectionError("provider_stream_after_terminal")


def _events(response, cancellation, evidence, *, inspect_media=False, observe_media=None, limits=None,
            require_done=False, require_tls_close=False):
    active = _active_limits(limits)
    prefix = _resolve_stream_prefix(
        response, cancellation, evidence, inspect_media=inspect_media, observe_media=observe_media,
    )
    parser = _SseParser(evidence, active, prefix, cancellation)
    first = True
    for line in _stream_lines(response, cancellation, evidence, prefix, limits=active):
        cancellation.check()
        evidence.lines += 1
        if first:
            line = line.removeprefix(b"\xef\xbb\xbf")
            first = False
        frame = parser.feed(line)
        if frame is not None:
            yield frame
    if parser.data:
        raise ConnectionError("provider_stream_incomplete")
    if parser.completed is not None and parser.event_name is not None:
        raise ConnectionError("provider_stream_after_terminal")
    if require_done and not evidence.done_seen:
        raise ConnectionError("provider_stream_incomplete")
    if require_tls_close:
        _verify_tls_close(response, active)
    cancellation.check()
    if parser.completed is not None:
        yield parser.completed


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
                 cancellation, dispatch, revocation=False, limits=None):
        active = _active_limits(limits)
        if not self._allowed(host, method, path, revocation):
            raise ConnectionError("invalid_provider_destination")
        if bearer is not None and (host != API_HOST or not bearer.isascii()
                                   or any(ord(char) <= 32 or ord(char) >= 127 for char in bearer)):
            raise ConnectionError("invalid_provider_credential")
        if len(body) > active.max_json:
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
                        sock.settimeout(active.io_timeout)

                sent = dispatch(first_write)
                cancellation.check()
                if not sent:
                    raise ConnectionError("provider_send_uncertain")
                if sent < len(packet):
                    sock.sendall(packet[sent:])
                cancellation.check()
                with contextlib.closing(_StrictResponse(sock, method=method, max_line=active.max_line)) as response:
                    response._oc_sock = sock
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
    def responses(self, body, bearer, cancellation, dispatch, *, inspect_media=False, observe_media=None,
                  limits=None, require_done=False, require_tls_close=False):
        active = _active_limits(limits)
        encoded = encode_responses_body(body, max_json=active.max_json)
        evidence = None
        try:
            with self._request(API_HOST, RESPONSES, method="POST", body=encoded,
                               content_type="application/json", bearer=bearer,
                               cancellation=cancellation, dispatch=dispatch, limits=active) as response:
                if response.status != 200:
                    try:
                        error_body = _read_json(response)
                    except ConnectionError as error:
                        if error.code not in {"invalid_provider_json", "provider_response_too_large"}:
                            raise
                        error_body = {}
                    raise ConnectionError(response_error(response.status, error_body))
                evidence = _StreamEvidence()
                yield _events(
                    response, cancellation, evidence, inspect_media=inspect_media,
                    observe_media=observe_media, limits=active,
                    require_done=require_done, require_tls_close=require_tls_close,
                )
        except ConnectionError as error:
            if evidence is not None and error.code in _STREAM_CODES:
                raise StreamFailure(error.code, evidence) from None
            raise


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
    return {401: "chatgpt_auth_rejected", 403: "chatgpt_access_refused", 503: "chatgpt_unavailable"}.get(
                status, "provider_response_failed")
