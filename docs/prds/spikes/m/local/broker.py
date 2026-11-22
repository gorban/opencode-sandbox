"""One host grant and one in-process model fixture on a private Unix socket."""

import contextlib
import hmac
import json
import math
import os
import re
import socket
import stat
import threading
import time
from pathlib import Path


MODEL_ID = "fixture-model"
MODEL_PATH = "/v1/chat/completions"
PROOF_PATH = "/workspace/proof.txt"
PROOF_CONTENT = "local OpenCode proof\n"
EARLY_TEXT = "Local fixture is writing the proof. "
COMPLETE_TEXT = "Local fixture wrote the proof."
HOLD_TEXT = "Local fixture response is held open. "
WRITE_CALL_ID = "call_local_fixture_write"

MAX_HEADER = 16 * 1024
MAX_BODY = 256 * 1024
MAX_CLIENTS = 8
REQUEST_TIMEOUT = 5.0
HOLD_TIMEOUT = 30.0
_END = b"\r\n\r\n"
_ALLOWED_HEADERS = {
    b"accept", b"accept-encoding", b"authorization", b"connection", b"content-length",
    b"content-type", b"host", b"user-agent",
    # Observed OpenCode 2.3.0 metadata. The broker does not use these values.
    b"b3", b"traceparent", b"x-opencode-client", b"x-opencode-project", b"x-opencode-session",
    b"x-opencode-session-id", b"x-session-affinity", b"x-session-id",
}
_ALLOWED_BODY = {
    "messages", "model", "stream", "tools", "tool_choice", "stream_options",
    "max_completion_tokens", "max_tokens", "parallel_tool_calls", "temperature", "top_p",
}
_DENIALS = {
    400: b"Bad Request",
    403: b"Forbidden",
    404: b"Not Found",
    422: b"Unprocessable Content",
}


class _Rejected(ValueError):
    def __init__(self, status=400):
        self.status = status


def _recv(conn, limit, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _Rejected()
    conn.settimeout(remaining)
    data = conn.recv(limit)
    if not data:
        raise _Rejected()
    return data


def _request(conn):
    deadline = time.monotonic() + REQUEST_TIMEOUT
    head = bytearray()
    while _END not in head:
        if len(head) == MAX_HEADER:
            raise _Rejected()
        head.extend(_recv(conn, min(4096, MAX_HEADER - len(head)), deadline))
    head, body = head.split(_END, 1)
    request, *lines = bytes(head).split(b"\r\n")
    if request != f"POST {MODEL_PATH} HTTP/1.1".encode("ascii"):
        raise _Rejected(404)

    headers = {}
    for line in lines:
        name, separator, value = line.partition(b":")
        name = name.lower()
        value = value.strip(b" ")
        if (not separator or name not in _ALLOWED_HEADERS or name in headers
                or not re.fullmatch(rb"[ -~]+", value)):
            raise _Rejected()
        headers[name] = value
    if not re.fullmatch(rb"fixture\.local|(?:127\.0\.0\.1|localhost)(?::\d{1,5})?",
                        headers.get(b"host", b"")):
        raise _Rejected()
    if headers.get(b"connection", b"close").lower() not in (b"close", b"keep-alive"):
        raise _Rejected()
    if headers.get(b"content-type", b"").lower() not in (
        b"application/json", b"application/json; charset=utf-8",
    ):
        raise _Rejected()
    length = headers.get(b"content-length", b"")
    if not re.fullmatch(rb"[1-9]\d{0,5}", length):
        raise _Rejected()
    length = int(length)
    if length > MAX_BODY:
        raise _Rejected()
    # Process exactly one frame. Any following bytes are discarded on close.
    del body[length:]
    while len(body) < length:
        body.extend(_recv(conn, min(4096, length - len(body)), deadline))
    return headers.get(b"authorization", b""), body


def _object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise _Rejected()
    return result


def _finite_number(value):
    result = float(value)
    if not math.isfinite(result):
        raise _Rejected()
    return result


def _payload(body):
    try:
        payload = json.loads(body.decode("utf-8"), object_pairs_hook=_object,
                             parse_constant=_finite_number, parse_float=_finite_number)
    except (ValueError, RecursionError):
        raise _Rejected() from None
    if (not isinstance(payload, dict) or payload.keys() - _ALLOWED_BODY
            or payload.get("model") != MODEL_ID or payload.get("stream") is not True):
        raise _Rejected()
    messages = payload.get("messages")
    if (not isinstance(messages, list) or not 1 <= len(messages) <= 64
            or any(not isinstance(message, dict) or message.get("role") not in (
                "system", "user", "assistant", "tool",
            ) for message in messages)
            or not any(message["role"] == "user" for message in messages)):
        raise _Rejected()
    tools = payload.get("tools", [])
    if not isinstance(tools, list) or len(tools) > 64:
        raise _Rejected()
    return messages, tools


def _write_input(tools):
    write_tools = [tool["function"] for tool in tools
                   if isinstance(tool, dict) and tool.get("type") == "function"
                   and isinstance(tool.get("function"), dict) and tool["function"].get("name") == "write"]
    if len(write_tools) != 1:
        raise _Rejected(422)
    parameters = write_tools[0].get("parameters")
    if not isinstance(parameters, dict) or parameters.get("type") != "object":
        raise _Rejected(422)
    required = parameters.get("required")
    properties = parameters.get("properties")
    if not isinstance(required, list) or not isinstance(properties, dict):
        raise _Rejected(422)
    # The pinned v2.3.0 native tool advertises `path`. Some runners advertise `filePath`.
    for path_field in ("path", "filePath"):
        if (len(required) == 2 and path_field in required and "content" in required
                and all(isinstance(properties.get(field), dict) and properties[field].get("type") == "string"
                        for field in (path_field, "content"))):
            return json.dumps({path_field: PROOF_PATH, "content": PROOF_CONTENT}, separators=(",", ":"))
    raise _Rejected(422)


def _event(step, delta, finish=None):
    frame = {
        "id": f"chatcmpl-local-{step}",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": MODEL_ID,
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
    }
    if finish:
        frame["usage"] = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    return b"data: " + json.dumps(frame, separators=(",", ":")).encode("ascii") + b"\n\n"


def _script(step, arguments):
    if step == "hold":
        delta = _event(step, {"role": "assistant", "content": HOLD_TEXT})
        # The held response never sends the terminal HTTP chunk or SSE event.
        chunk = f"{len(delta):x}\r\n".encode("ascii") + delta + b"\r\n"
        return (b"Transfer-Encoding: chunked", (chunk,))

    if step == "write":
        frames = (
            _event(step, {"role": "assistant", "content": EARLY_TEXT}),
            _event(step, {"tool_calls": [{"index": 0, "id": WRITE_CALL_ID, "type": "function",
                                          "function": {"name": "write", "arguments": arguments}}]}),
            _event(step, {}, "tool_calls"),
        )
    else:
        frames = (
            _event(step, {"role": "assistant", "content": COMPLETE_TEXT}),
            _event(step, {}, "stop"),
        )
    frames += (b"data: [DONE]\n\n",)
    length = sum(map(len, frames))
    return (f"Content-Length: {length}".encode("ascii"), frames)


def _shutdown(conn):
    with contextlib.suppress(OSError):
        conn.shutdown(socket.SHUT_RDWR)
    conn.close()


class Broker:
    def __init__(self, path: Path, token: str):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", token):
            raise ValueError("invalid fixture bearer")
        self._path = path
        self._authorization = b"Bearer " + token.encode("ascii")
        self._lock = threading.Lock()
        self._closed = False
        self._granted = False
        self._revoked = threading.Event()
        self._hold_ready = threading.Event()
        self._hold_revoked = threading.Event()
        self._hold_armed = False
        self._hold_conn = None
        self._ordinary_step = "write"
        self._listener = None
        self._listener_thread = None
        self._socket_identity = None
        self._clients = {}
        self._active = set()
        self._admitted = 0
        self._rejected = 0

    def start(self):
        with self._lock:
            if self._closed or self._granted or self._revoked.is_set():
                raise RuntimeError("fixture broker cannot restart")
            parent = self._path.parent.lstat()
            if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
                raise ValueError("fixture socket needs an owner-only directory")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(os.fspath(self._path))
                bound = self._path.lstat()
                self._socket_identity = (bound.st_dev, bound.st_ino)
                self._path.chmod(0o600)
                listener.listen(MAX_CLIENTS)
                listener.settimeout(0.1)
                thread = threading.Thread(target=self._accept, args=(listener,), daemon=True)
                thread.start()
            except BaseException:
                listener.close()
                self._unlink_socket()
                raise
            self._listener = listener
            self._granted = True
            self._listener_thread = thread

    def is_bound_to(self, path: Path, *, allow_revoked: bool = False) -> bool:
        """Verify the live listener and its originally bound, private socket."""
        if self._path != path:
            return False
        with self._lock:
            if (self._closed or not self._granted or self._listener is None or self._listener.fileno() < 0
                    or self._listener_thread is None or not self._listener_thread.is_alive()
                    or (not allow_revoked and self._revoked.is_set())):
                return False
            try:
                info = path.lstat()
            except OSError:
                return False
            return self._owns_socket(info) and info.st_uid == os.getuid() and not (info.st_mode & 0o077)

    def _owns_socket(self, info) -> bool:
        return self._socket_identity == (info.st_dev, info.st_ino) and stat.S_ISSOCK(info.st_mode)

    def _unlink_socket(self):
        with contextlib.suppress(FileNotFoundError):
            info = self._path.lstat()
            if self._owns_socket(info):
                self._path.unlink()

    def _accept(self, listener):
        while True:
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._lock:
                if self._closed:
                    conn.close()
                    return
                if len(self._clients) >= MAX_CLIENTS:
                    self._rejected += 1
                    conn.close()
                    continue
                thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
                self._clients[conn] = thread
                try:
                    thread.start()
                except RuntimeError:
                    self._clients.pop(conn)
                    self._rejected += 1
                    _shutdown(conn)

    def _admit(self, conn, authorization, messages, tools):
        with self._lock:
            authenticated = hmac.compare_digest(authorization, self._authorization)
            if not authenticated or not self._granted or self._revoked.is_set():
                raise _Rejected(403)
            step = self._ordinary_step
            arguments = None
            if self._hold_armed:
                self._hold_armed = False
                step = "hold"
                self._hold_conn = conn
            elif step == "write":
                arguments = _write_input(tools)
                self._ordinary_step = "complete"
            elif step == "complete" and any(message["role"] == "tool" and message.get("tool_call_id") == WRITE_CALL_ID
                                            for message in messages):
                self._ordinary_step = "done"
            else:
                raise _Rejected(422)
            self._admitted += 1
            self._active.add(conn)
            return step, arguments

    def _send(self, conn, data):
        # The nonblocking write and grant check use the same lock as revoke.
        # A partial write aborts this small, one-request connection.
        with self._lock:
            if conn not in self._active or conn.send(data) != len(data):
                raise OSError("fixture stream closed")

    def _handle(self, conn):
        try:
            authorization, body = _request(conn)
            messages, tools = _payload(body)
            conn.setblocking(False)
            step, arguments = self._admit(conn, authorization, messages, tools)
            framing, frames = _script(step, arguments)
            self._send(conn, b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                             b"Cache-Control: no-cache\r\nConnection: close\r\n" + framing + _END)
            for frame in frames:
                self._send(conn, frame)
            if step == "hold":
                self._hold_ready.set()
                self._revoked.wait(HOLD_TIMEOUT)
        except _Rejected as exc:
            with self._lock:
                self._rejected += 1
            with contextlib.suppress(OSError):
                conn.setblocking(False)
                conn.send(f"HTTP/1.1 {exc.status} ".encode("ascii") + _DENIALS[exc.status]
                          + b"\r\nContent-Length: 0\r\nConnection: close" + _END)
        except OSError:
            pass
        finally:
            with self._lock:
                self._active.discard(conn)
                self._clients.pop(conn)
                _shutdown(conn)

    def arm_hold(self):
        with self._lock:
            if not self._granted or self._revoked.is_set() or self._hold_armed or self._hold_conn is not None:
                raise RuntimeError("fixture hold cannot be armed")
            self._hold_armed = True

    def wait_for_hold(self, timeout: float) -> bool:
        return self._hold_ready.wait(timeout)

    def wait_for_hold_revoked(self, timeout: float) -> bool:
        return self._hold_revoked.wait(timeout)

    def revoke(self):
        with self._lock:
            self._revoked.set()
            for conn in self._active:
                _shutdown(conn)
                if conn is self._hold_conn:
                    self._hold_revoked.set()
            self._active.clear()

    def snapshot(self):
        with self._lock:
            return {"admitted": self._admitted, "active": len(self._active), "rejected": self._rejected}

    def close(self):
        self.revoke()
        with self._lock:
            self._closed = True
            if self._listener is not None:
                self._listener.close()
            for conn in self._clients:
                _shutdown(conn)
            threads = list(self._clients.values())
            if self._listener_thread is not None:
                threads.append(self._listener_thread)
        try:
            for thread in threads:
                thread.join(timeout=REQUEST_TIMEOUT + 1)
            if any(thread.is_alive() for thread in threads):
                raise RuntimeError("fixture broker thread did not stop")
        finally:
            self._unlink_socket()
