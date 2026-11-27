"""One authenticated, text-only turn against an in-process recording fake."""

from array import array
from contextlib import suppress
import hashlib
import hmac
import json
import os
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
OPTIONS = {"model": MODEL, "stream": True, "stream_options": {"include_usage": True}, "max_completion_tokens": 2048}
SYSTEM_DATE = re.compile(r"^Today's date: [A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{4}$", re.MULTILINE | re.ASCII)
SYSTEM_DIGEST = "7dbcff5fc8be1a8df35451a145f885302a0762341cb08e2c2bac7206192ad118"
REFUSAL = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


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


def request_body(connection, deadline, port, *, worker_token=b"offline-fixture"):
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
    if (fields.get(b"host") != f"127.0.0.1:{port}".encode()
            or not hmac.compare_digest(fields.get(b"authorization", b""), b"Bearer " + worker_token)
            or fields.get(b"content-type", b"").lower() not in {b"application/json", b"application/json; charset=utf-8"}):
        raise Refused()
    length = fields.get(b"content-length", b"")
    if not re.fullmatch(rb"[1-9]\d{0,4}", length) or not len(data) <= int(length) <= REQUEST_LIMIT:
        raise Refused()
    return bytes(data) + fixed_bytes(connection, int(length) - len(data), deadline)


def bad_constant(_value):
    raise Refused()


def accept_text(body, *, model=MODEL, system_digest=None, normalized_label=None):
    data = json.loads(body.decode("utf-8"), object_pairs_hook=unique, parse_constant=bad_constant)
    if not isinstance(data, dict):
        raise Refused()
    messages = data.pop("messages", None)
    if (json.dumps(data, sort_keys=True) != json.dumps(dict(OPTIONS, model=model), sort_keys=True)
            or not isinstance(messages, list) or len(messages) != 2
            or messages[1] != {"role": "user", "content": PROMPT}):
        raise Refused()
    system = messages[0]
    if (not isinstance(system, dict) or system.keys() != {"role", "content"} or system["role"] != "system"
            or not isinstance(system["content"], str)):
        raise Refused()
    normalized, count = SYSTEM_DATE.subn("Today's date: [date]", system["content"])
    if normalized_label is not None:
        if (type(normalized_label) is not tuple or len(normalized_label) != 2
                or any(type(label) is not str or len(label) > 32
                       or not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", label)
                       for label in normalized_label)):
            raise Refused()
        source_label, baseline_label = normalized_label
        display = f"{model} - {source_label} [subscription]"
        provider = f"Provider ID: google--{source_label}\n"
        if normalized.count(display) != 1 or normalized.count(provider) != 1:
            raise Refused()
        normalized = normalized.replace(display, f"{model} - {baseline_label} [subscription]")
        normalized = normalized.replace(provider, f"Provider ID: google--{baseline_label}\n")
    digest = SYSTEM_DIGEST if system_digest is None else system_digest
    if count != 1 or hashlib.sha256(normalized.encode()).hexdigest() != digest:
        raise Refused()


def receive_client(control, port):
    fds = array("i")
    marker, messages, flags, _ = control.recvmsg(1, socket.CMSG_SPACE(fds.itemsize * 2), socket.MSG_CMSG_CLOEXEC)
    try:
        for level, kind, data in messages:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
        if marker != b"F" or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC) or len(messages) != 1 or len(fds) != 1:
            raise Refused()
        client = socket.socket(fileno=fds[0])
        fds.pop()
    finally:
        for fd in fds:
            os.close(fd)
    try:
        if (client.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_INET
                or client.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or client.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL) != socket.IPPROTO_TCP
                or client.getsockname() != ("127.0.0.1", port) or client.getpeername()[0] != "127.0.0.1"):
            raise Refused()
        return client
    except BaseException:
        client.close()
        raise


def reply_bytes(events):
    if len(events) > 128 or sum(map(len, events)) > 512 * 1024:
        raise Refused()
    if any(len(event) > FRAME_LIMIT for event in events):
        raise Refused()
    # The fake has exactly one allowed transcript. Extra events, including tool calls,
    # cannot enter OpenCode even after the admission has been recorded.
    if tuple(json.loads(event, object_pairs_hook=unique) for event in events) != ({"text": "ok"}, {"finish": "stop"}):
        raise Refused()
    return text_reply_bytes(MODEL)


def text_reply_bytes(model):
    """Frame the exact verified text response for OpenCode."""
    base = {"id": "chatcmpl-offline", "object": "chat.completion.chunk", "created": 1, "model": model}
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

    def __init__(self, address, proof, *, port=PORT, authorized=lambda: True, before_delivery=None, events=FIXTURE_EVENTS):
        self.proof = proof
        self.port = port
        self.authorized = authorized
        self.before_delivery = before_delivery
        self.events = events
        self.lock = threading.Lock()
        self.active = True
        self.admissions = 0
        self.refusals = 0
        self.settlement = "unsent"
        self.recorded_body = None
        self.connection = None
        self.listener = socket.socket(socket.AF_UNIX)
        try:
            self.listener.bind(str(address))
            os.chmod(address, 0o600)
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
                try:
                    self.accept(connection)
                except (OSError, ValueError, RecursionError):
                    with self.lock:
                        self.refusals += 1
                finally:
                    with self.lock:
                        self.connection = None

    def track(self, connection):
        with self.lock:
            if not self.active or not self.authorized():
                raise Refused()
            self.connection = connection

    def accept(self, control):
        self.track(control)
        deadline = time.monotonic() + TOTAL
        if not hmac.compare_digest(fixed_bytes(control, PROOF_SIZE, deadline), self.proof):
            raise Refused()
        with receive_client(control, self.port) as client:
            self.track(client)
            self.deliver(client, deadline)

    def admit(self, body):
        accept_text(body)
        with self.lock:
            if not self.active or self.admissions or not self.authorized():
                raise Refused()
            self.admissions += 1
            self.settlement = "recorded_offline"
            self.recorded_body = body

    def deliver(self, client, deadline):
        try:
            self.admit(request_body(client, deadline, self.port))
            response = reply_bytes(self.events)
        except (OSError, ValueError, RecursionError):
            with self.lock:
                self.refusals += 1
            with suppress(OSError, Refused):
                self.write(client, REFUSAL)
            return
        if self.before_delivery is not None:
            self.before_delivery()
        self.write(client, response)

    def write(self, client, response):
        with self.lock:
            if self.active and self.authorized():
                client.setblocking(False)
                if client.send(response) != len(response):
                    raise Refused()

    def receipt(self):
        with self.lock:
            return self.admissions, self.refusals, self.settlement, self.recorded_body
