"""One authenticated, text-only turn against an in-process recording fake."""

from contextlib import suppress
import hmac
import json
import re
import socket
import threading
import time


PROMPT = "Reply with exactly: ok"
MODEL = "text-proof"
PORT = 8401
REQUEST_LIMIT = 64 * 1024
HEADER_LIMIT = 16 * 1024
PROOF_SIZE = 32
IDLE = 15
TOTAL = 60
PROJECTED_LIMIT = 256 * 1024
FRAME_LIMIT = 32 * 1024
FIXTURE_EVENTS = (b'{"text":"ok"}', b'{"finish":"stop"}')
HEADERS = frozenset({
    b"accept", b"accept-encoding", b"authorization", b"connection", b"content-length",
    b"content-type", b"host", b"user-agent", b"b3", b"traceparent", b"x-opencode-client",
    b"x-opencode-project", b"x-opencode-session", b"x-opencode-session-id", b"x-session-affinity",
    b"x-session-id",
})
BODY_FIELDS = frozenset({
    "messages", "model", "stream", "tools", "tool_choice", "stream_options",
    "max_completion_tokens", "max_tokens", "parallel_tool_calls", "temperature", "top_p",
})


class Refused(ValueError):
    """A response can safely report that the local proof refused the request."""


def unique(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise Refused()
    return obj


def recv(connection, length, deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise Refused()
    connection.settimeout(min(IDLE, left))
    chunk = connection.recv(length)
    if not chunk:
        raise Refused()
    return chunk


def fixed_bytes(connection, length, deadline):
    data = bytearray()
    while len(data) < length:
        data.extend(recv(connection, length - len(data), deadline))
    return bytes(data)


def request_body(connection, deadline):
    delimiter = b"\r\n\r\n"
    head = bytearray()
    while delimiter not in head:
        if len(head) == HEADER_LIMIT:
            raise Refused()
        head.extend(recv(connection, min(4096, HEADER_LIMIT - len(head)), deadline))
    headers, _, data = head.partition(delimiter)
    target, *lines = bytes(headers).split(b"\r\n")
    if target != b"POST /v1/chat/completions HTTP/1.1":
        raise Refused()
    fields = {}
    for line in lines:
        name, separator, value = line.partition(b":")
        name, value = name.lower(), value.strip(b" ")
        if not separator or name not in HEADERS or name in fields or not re.fullmatch(rb"[ -~]+", value):
            raise Refused()
        fields[name] = value
    if (fields.get(b"host") != f"127.0.0.1:{PORT}".encode()
            or fields.get(b"content-type", b"").lower() not in {b"application/json", b"application/json; charset=utf-8"}):
        raise Refused()
    length = fields.get(b"content-length", b"")
    if not re.fullmatch(rb"[1-9][0-9]{0,4}", length) or not len(data) <= int(length) <= REQUEST_LIMIT:
        raise Refused()
    return bytes(data) + fixed_bytes(connection, int(length) - len(data), deadline)


def text(content):
    if isinstance(content, str):
        return content
    if not isinstance(content, list) or any(
        not isinstance(item, dict) or set(item) != {"type", "text"} or item["type"] != "text"
        or not isinstance(item["text"], str) for item in content
    ):
        raise Refused()
    return "".join(item["text"] for item in content)


def accept_text(body):
    data = json.loads(body, object_pairs_hook=unique)
    if (not isinstance(data, dict) or data.keys() - BODY_FIELDS or data.get("model") != MODEL
            or data.get("stream") is not True or data.get("tools", []) != []
            or data.get("tool_choice") not in (None, "none", "auto")):
        raise Refused()
    messages = data.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 8:
        raise Refused()
    user = []
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise Refused()
        value = text(message["content"])
        if message["role"] == "user":
            user.append(value)
        elif message["role"] != "system":
            raise Refused()
    if user != [PROMPT]:
        raise Refused()


def reply_bytes(events):
    if len(events) > 128 or sum(map(len, events)) > 512 * 1024:
        raise Refused()
    if any(len(event) > FRAME_LIMIT for event in events):
        raise Refused()
    # The fake has exactly one allowed transcript. Extra events, including tool calls,
    # cannot enter OpenCode even after the admission has been recorded.
    if tuple(json.loads(event, object_pairs_hook=unique) for event in events) != ({"text": "ok"}, {"finish": "stop"}):
        raise Refused()
    base = {"id": "chatcmpl-offline", "object": "chat.completion.chunk", "created": 1, "model": MODEL}
    frames = (
        {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "ok"}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    )
    body = b"".join(b"data: " + json.dumps(frame).encode() + b"\n\n" for frame in frames) + b"data: [DONE]\n\n"
    if len(body) > PROJECTED_LIMIT:
        raise Refused()
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)


class RecordingFake:
    """Per-launch capability, one accepted request and no routable upstream."""

    def __init__(self, address, proof, *, after_send=None, events=FIXTURE_EVENTS):
        self.proof = proof
        self.after_send = after_send
        self.events = events
        self.lock = threading.Lock()
        self.active = True
        self.admissions = 0
        self.refusals = 0
        self.settlement = "unsent"
        self.connection = None
        self.listener = socket.socket(socket.AF_UNIX)
        try:
            self.listener.bind(str(address))
            self.listener.listen(2)
            self.listener.settimeout(0.2)
        except BaseException:
            self.listener.close()
            raise
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.revoke()
        self.thread.join(IDLE + 1)
        if self.thread.is_alive():
            raise RuntimeError("The offline broker did not stop")

    def revoke(self):
        with self.lock:
            self.active = False
            if self.connection is not None:
                with suppress(OSError):
                    self.connection.shutdown(socket.SHUT_RDWR)
            self.listener.close()

    def serve(self):
        while self.active:
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                with self.lock:
                    if not self.active:
                        return
                    self.connection = connection
                try:
                    self.turn(connection)
                except (OSError, ValueError, RecursionError):
                    with self.lock:
                        self.refusals += 1
                    with suppress(OSError):
                        connection.settimeout(0.2)
                        connection.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                finally:
                    with self.lock:
                        self.connection = None

    def turn(self, connection):
        deadline = time.monotonic() + TOTAL
        if not hmac.compare_digest(fixed_bytes(connection, PROOF_SIZE, deadline), self.proof):
            raise Refused()
        accept_text(request_body(connection, deadline))
        with self.lock:
            if not self.active or self.admissions:
                raise Refused()
            self.admissions += 1
            self.settlement = "recorded_offline"
        if self.after_send is not None:
            self.after_send()
        with self.lock:
            if self.active:
                connection.setblocking(False)
                response = reply_bytes(self.events)
                if connection.send(response) != len(response):
                    raise Refused()
