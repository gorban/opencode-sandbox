"""Bounded Unix-socket client for the disposable OpenCode worker."""

from __future__ import annotations

from base64 import b64encode
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import json
from math import isfinite
from pathlib import Path
import re
import select
import socket
import time


MAX_REQUEST = 65_536
MAX_HEADERS = 16_384
MAX_EVENT = 262_144
MAX_EVENTS = 2_048
MAX_STREAM = 4 * 1024 * 1024
JSON_MEDIA_TYPE = "application/json"
WORKSPACE = "/workspace"
MESSAGE_ID = re.compile(r"msg_[A-Za-z0-9]{1,92}")
INVALID_JSON_CHAR = re.compile(r"[\x00\ud800-\udfff]")


class ProbeError(RuntimeError):
    pass


class DispatchOutcome(str, Enum):
    HANDED_OFF = "handed_off"
    ZERO_BYTES_SENT = "zero_bytes_sent"
    UNCERTAIN = "uncertain"


def remaining(deadline: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise ProbeError("deadline expired")
    return seconds


def unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate JSON fields")
    return fields


def finite_float(text: str) -> float:
    number = float(text)
    if not isfinite(number):
        raise ValueError("nonfinite JSON number")
    return number


def validate_json_strings(value) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            validate_json_strings(key)
            validate_json_strings(item)
    elif isinstance(value, list):
        for item in value:
            validate_json_strings(item)
    elif isinstance(value, str) and INVALID_JSON_CHAR.search(value):
        raise ValueError("invalid JSON string character")


def object_json(data: bytes) -> dict:
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=unique_fields,
                            parse_float=finite_float, parse_constant=finite_float)
        validate_json_strings(result)
    except (ValueError, RecursionError) as error:
        raise ProbeError("invalid JSON response") from error
    if not isinstance(result, dict):
        raise ProbeError("expected a JSON object")
    return result


def request(method: str, path: str, *, host: str, auth: str, accept: str,
            body: dict | None = None) -> bytes:
    data = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = [
        f"{method} {path} HTTP/1.1", f"Host: {host}", f"Authorization: {auth}",
        "Connection: close", f"Accept: {accept}", "Accept-Encoding: identity",
    ]
    if body is not None:
        headers.extend([f"Content-Type: {JSON_MEDIA_TYPE}", f"Content-Length: {len(data)}"])
    raw = "\r\n".join(headers).encode("ascii") + b"\r\n\r\n" + data
    if len(raw) > MAX_REQUEST:
        raise ProbeError("request exceeds the relay limit")
    return raw


class Wire:
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock = sock
        self.deadline = deadline
        self.buffer = bytearray()

    def receive(self) -> None:
        self.sock.settimeout(remaining(self.deadline))
        data = self.sock.recv(16_384)
        if not data:
            raise ProbeError("unexpected EOF")
        self.buffer.extend(data)

    def write(self, data: bytes) -> None:
        self.sock.settimeout(remaining(self.deadline))
        self.sock.sendall(data)

    def take(self, count: int) -> bytes:
        while len(self.buffer) < count:
            self.receive()
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        return data

    def through(self, delimiter: bytes, limit: int) -> bytes:
        while True:
            index = self.buffer.find(delimiter)
            if index >= 0:
                count = index + len(delimiter)
                if count <= limit:
                    return self.take(count)
                break
            if len(self.buffer) >= limit:
                break
            self.receive()
        raise ProbeError("framing exceeded its size limit")

    def assert_open(self) -> None:
        # Linux reports peer shutdown even when unread data is queued on the socket.
        closed = select.POLLRDHUP | select.POLLHUP | select.POLLERR | select.POLLNVAL
        poll = select.poll()
        poll.register(self.sock, select.POLLRDHUP)
        if any(flags & closed for _, flags in poll.poll(0)):
            raise ProbeError("relay control event stream closed before revoke")

    def await_eof(self, deadline: float) -> None:
        """Observe orderly peer closure, including a possibly truncated event."""
        tail = len(self.buffer)
        self.buffer.clear()
        while tail <= MAX_EVENT:
            self.sock.settimeout(remaining(min(self.deadline, deadline)))
            try:
                data = self.sock.recv(16_384)
            except TimeoutError as error:
                raise ProbeError("relay left the control event stream open after revoke") from error
            if not data:
                return
            tail += len(data)
        raise ProbeError("relay sent excessive trailing data before control stream closure")


@contextmanager
def unix_wire(path: Path, deadline: float):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(remaining(deadline))
        sock.connect(str(path))
        yield Wire(sock, deadline)


class RelayExchange:
    """One request and its receipt, with an optional test-only pause before the fence."""

    def __init__(self, wire: Wire, raw: bytes, *, pause: bool):
        self.wire = wire
        self.pause_acknowledged = False
        self._early_zero = False
        self.read_receipt = False
        try:
            wire.write((b"P" if pause else b"N") + len(raw).to_bytes(4, "big") + raw)
            if pause:
                reply = wire.take(1)
                self.pause_acknowledged = reply == b"P"
                self._early_zero = reply == b"Z"
                if not (self.pause_acknowledged or self._early_zero):
                    raise ProbeError("unexpected pause response")
        except (OSError, ProbeError) as error:
            raise ProbeError("relay outcome uncertain before receipt") from error

    def receipt(self) -> DispatchOutcome:
        if self.read_receipt:
            raise ProbeError("relay receipt already consumed")
        self.read_receipt = True
        if self._early_zero:
            return DispatchOutcome.ZERO_BYTES_SENT
        try:
            if self.pause_acknowledged:
                self.wire.write(b"G")
            value = self.wire.take(1)
        except (OSError, ProbeError):
            return DispatchOutcome.UNCERTAIN
        return {
            b"H": DispatchOutcome.HANDED_OFF,
            b"Z": DispatchOutcome.ZERO_BYTES_SENT,
        }.get(value, DispatchOutcome.UNCERTAIN)


class _EventFrame:
    def __init__(self):
        self.data: list[bytes] = []
        self.size = 0
        self.line_count = 0
        self.event_count = 0

    def add_line(self, line: bytes) -> dict | None:
        self.line_count += 1
        if self.line_count > MAX_EVENTS * 8:
            raise ProbeError("event stream exceeds its line limit")
        if len(line) + self.size + 1 > MAX_EVENT:
            raise ProbeError("event exceeds its size limit")
        line = line.removesuffix(b"\r")
        if line.startswith(b"data:"):
            self.data.append(line[5:].removeprefix(b" "))
            self.size += len(line) + 1
            return None
        if line:
            if not line.startswith(b":"):
                raise ProbeError("unsupported event stream field")
            return None
        if not self.data:
            return None
        self.event_count += 1
        if self.event_count > MAX_EVENTS:
            raise ProbeError("event stream exceeds its event limit")
        event = object_json(b"\n".join(self.data))
        self.data.clear()
        self.size = 0
        return event


class Response:
    def __init__(self, wire: Wire, *, status: int, media: str | None = None):
        self.wire = wire
        lines = wire.through(b"\r\n\r\n", MAX_HEADERS)[:-4].split(b"\r\n")
        match = re.fullmatch(rb"HTTP/1\.[01] ([1-5]\d{2})(?: [\x20-\x7e]*)?", lines[0])
        if match is None:
            raise ProbeError("invalid HTTP response status")
        actual_status = int(match.group(1))
        if actual_status != status:
            raise ProbeError(f"unexpected HTTP status {actual_status}")
        headers = {}
        for line in lines[1:]:
            key, separator, value = line.partition(b":")
            key = key.lower()
            if (not separator or not re.fullmatch(rb"[a-z0-9-]+", key) or key in headers
                    or not re.fullmatch(rb"[\t\x20-\x7e]*", value)):
                raise ProbeError("invalid or duplicate HTTP response header")
            headers[key] = value.strip()
        if headers.get(b"content-encoding", b"identity").lower() != b"identity":
            raise ProbeError("compressed HTTP response refused")
        content_type = headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
        if media is not None and content_type != media.encode():
            raise ProbeError("unexpected HTTP response media type")

        transfer = headers.get(b"transfer-encoding")
        length = headers.get(b"content-length")
        self.length = None
        if transfer is None and length is not None and re.fullmatch(rb"(?:0|[1-9]\d{0,7})", length):
            self.length = int(length)
        elif transfer != b"chunked" or length is not None:
            raise ProbeError("unsupported HTTP response framing")

    def chunks(self, limit: int):
        if self.length is not None:
            yield from self._read_block(self.length, limit)
            return
        while length := self._chunk_length():
            yield from self._read_block(length, limit)
            limit -= length
            if self.wire.take(2) != b"\r\n":
                raise ProbeError("invalid HTTP chunk terminator")
        if self.wire.take(2) != b"\r\n":
            raise ProbeError("HTTP chunk trailers refused")

    def _chunk_length(self) -> int:
        line = self.wire.through(b"\r\n", 18)[:-2]
        if not re.fullmatch(rb"[0-9a-fA-F]{1,16}", line):
            raise ProbeError("invalid HTTP chunk size")
        return int(line, 16)

    def _read_block(self, length: int, limit: int):
        if length > limit:
            raise ProbeError("HTTP body exceeds its size limit")
        for offset in range(0, length, 16_384):
            yield self.wire.take(min(16_384, length - offset))

    def json(self) -> dict:
        return object_json(b"".join(self.chunks(MAX_REQUEST)))

    def events(self):
        pending = b""
        frame = _EventFrame()
        for chunk in self.chunks(MAX_STREAM):
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()
            for line in lines:
                event = frame.add_line(line)
                if event is not None:
                    yield event
            if len(pending) + frame.size > MAX_EVENT:
                raise ProbeError("event exceeds its size limit")
        if pending or frame.data:
            raise ProbeError("incomplete event stream frame")


class Subscription:
    def __init__(self, response: Response):
        self.wire = response.wire
        self.events = response.events()
        hello = next(self.events, {})
        if hello.get("type") != "server.connected":
            raise ProbeError("worker did not confirm event subscription")

    def __iter__(self):
        return self.events

    def assert_open(self) -> None:
        self.wire.assert_open()

    def await_eof(self, deadline: float) -> None:
        self.events.close()
        self.wire.await_eof(deadline)


@dataclass(frozen=True)
class TurnPins:
    sandbox_addr: str
    incarnation_id: str
    thread_id: str
    msg_id: str
    grant_generation: int


@dataclass(frozen=True)
class TurnEvent:
    kind: str
    text: str = ""
    text_part: tuple[str, int] | None = None


class TurnEvents:
    """Bind observed evidence to host pins after the matching input is delivered."""

    def __init__(self, pins: TurnPins):
        self.pins = pins
        self.delivered = False
        self.assistants = set()

    def accept(self, event: dict) -> TurnEvent | None:
        data = event.get("data")
        if not isinstance(data, dict) or data.get("sessionID") != self.pins.thread_id:
            return None
        kind = event.get("type")
        if kind == "session.inbox.delivered":
            self.delivered = data.get("inboxID") == self.pins.msg_id
            self.assistants.clear()
        if not self.delivered:
            return None
        assistant_id = data.get("assistantMessageID")
        if (kind == "session.step.started" and isinstance(assistant_id, str)
                and MESSAGE_ID.fullmatch(assistant_id)):
            self.assistants.add(assistant_id)
        if kind == "session.text.delta" and isinstance(assistant_id, str) and assistant_id in self.assistants:
            delta = data.get("delta")
            ordinal = data.get("ordinal")
            if isinstance(delta, str) and type(ordinal) is int and 0 <= ordinal < 2**53:
                return TurnEvent("text_delta", delta, (assistant_id, ordinal))
        if kind == "session.execution.succeeded":
            return TurnEvent("turn_completed")
        if kind in ("session.execution.failed", "session.execution.interrupted"):
            return TurnEvent("turn_error")
        return None


class OpenCode:
    def __init__(self, path: Path, password: str, *, sandbox_addr: str, incarnation_id: str,
                 grant_generation: int):
        self.path = path
        self.auth = "Basic " + b64encode(f"opencode:{password}".encode()).decode("ascii")
        self._job_pins = (sandbox_addr, incarnation_id, grant_generation)
        self._thread_id: str | None = None

    def _request(self, method: str, path: str, body: dict | None = None,
                 accept: str = JSON_MEDIA_TYPE) -> bytes:
        return request(method, path, host="127.0.0.1:4096", auth=self.auth, accept=accept, body=body)

    @contextmanager
    def _exchange(self, raw: bytes, deadline: float, *, pause: bool = False):
        with unix_wire(self.path, deadline) as wire:
            yield RelayExchange(wire, raw, pause=pause)

    @contextmanager
    def _response(self, raw: bytes, deadline: float, media: str):
        with self._exchange(raw, deadline) as exchange:
            outcome = exchange.receipt()
            if outcome is not DispatchOutcome.HANDED_OFF:
                raise ProbeError(f"relay did not hand off request ({outcome.value})")
            yield Response(exchange.wire, status=200, media=media)

    def create_session(self, deadline: float) -> str:
        if self._thread_id is not None:
            raise ProbeError("native session already pinned")
        raw = self._request("POST", "/api/session?directory=%2Fworkspace", {"title": "Local fixture"})
        with self._response(raw, deadline, JSON_MEDIA_TYPE) as response:
            data = response.json().get("data")
        if not isinstance(data, dict):
            raise ProbeError("session response lacks an identity")
        thread_id = data.get("id")
        location = data.get("location")
        if not isinstance(thread_id, str) or not re.fullmatch(r"ses_[A-Za-z0-9]{1,92}", thread_id):
            raise ProbeError("invalid native session ID")
        if not isinstance(location, dict) or location.get("directory") != WORKSPACE:
            raise ProbeError("session was not created in the disposable workspace")
        self._thread_id = thread_id
        return thread_id

    @contextmanager
    def events(self, deadline: float):
        raw = self._request("GET", "/api/event", accept="text/event-stream")
        with self._response(raw, deadline, "text/event-stream") as response:
            yield Subscription(response)

    def _prompt(self, pins: TurnPins, text: str) -> bytes:
        pinned = (pins.sandbox_addr, pins.incarnation_id, pins.grant_generation, pins.thread_id)
        if (self._thread_id is None or type(pins.grant_generation) is not int
                or pinned != (*self._job_pins, self._thread_id)):
            raise ProbeError("prompt does not match the pinned job and session")
        if not isinstance(pins.msg_id, str) or not MESSAGE_ID.fullmatch(pins.msg_id):
            raise ProbeError("invalid prompt message ID")
        return self._request("POST", f"/api/session/{pins.thread_id}/prompt", {
            "id": pins.msg_id, "text": text, "resume": True,
        })

    def prompt(self, pins: TurnPins, text: str, deadline: float) -> None:
        with self._response(self._prompt(pins, text), deadline, JSON_MEDIA_TYPE) as response:
            data = response.json().get("data")
        if (not isinstance(data, dict) or data.get("id") != pins.msg_id
                or data.get("sessionID") != pins.thread_id or data.get("type") != "user"):
            raise ProbeError("worker did not echo the pinned input")

    def pause_prompt(self, pins: TurnPins, text: str, deadline: float):
        return self._exchange(self._prompt(pins, text), deadline, pause=True)
