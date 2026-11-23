"""Disposable, synthetic M3a loopback HTTP fixture."""

import argparse
from dataclasses import dataclass
from http import HTTPStatus
import json
from math import ceil
from pathlib import Path
import re
import secrets
import select
import socket
import socketserver
import sys
import threading
import time

from oc_web_assets import AssetError, HTML_TYPE, load_build

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from oc_coord_contract import CoordRole, PrincipalCtx
from oc_ui_auth import DEFAULT_COOKIE_NAME, UiAuthDeniedError, UiAuthManager

EXCHANGE = "/api/auth/exchange"
SESSION = "/api/auth/session"
LOGOUT = "/api/auth/logout"
WORKSPACE = "/api/v1/workspace"
DASHBOARDS = frozenset(f"/dashboard/{name}" for name in ("projects", "sandboxes", "threads"))
METHODS = {EXCHANGE: "POST", SESSION: "GET", LOGOUT: "POST", WORKSPACE: "GET"}
TARGET = re.compile(rb"/[A-Za-z0-9_./-]*\Z")
HEADER = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
CODE = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII)
SURROGATE = re.compile(r"[\ud800-\udfff]")
BAD_VALUE = re.compile(rb"[\x00-\x08\x0a-\x1f\x7f]")
READ_LIMIT = 16 * 1024
BODY_LIMIT = 256
AUTH_LIMIT = 4 * 1024
WORKSPACE_LIMIT = 32 * 1024
HTTP_DEADLINE = 2.0
SEND_CHUNK = 8192
JSON_TYPE = "application/json"
COMMON_HEADERS = (
    ("Connection", "close"),
    ("Cache-Control", "no-store"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
)
OPERATOR = PrincipalCtx(CoordRole.OPERATOR, "operator")
PROJECTION = [{
    "id": "project-alpha", "label": "Fixture project",
    "sandboxes": [{
        "id": "sandbox-alpha", "label": "Fixture sandbox", "status": "running",
        "threads": [{
            "id": "thread-alpha", "label": "Fixture thread",
            "mailbox": [{"text": "Synthetic mailbox item"}],
            "events": [{"label": "Agent event", "text": "<b>Fixture agent text</b>"}],
            "provenance": [{"label": "Fixture provenance", "text": "Synthetic operator view"}],
        }],
    }],
}]


class RequestError(Exception):
    def __init__(self, status: int):
        self.status = status


class FixtureDenied(Exception):
    """An authenticated fixture session is unavailable."""


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _read_request(conn: socket.socket, deadline: float):
    """Read one bounded HTTP/1.1 request while retaining its original target."""
    data = bytearray()
    try:
        while b"\r\n\r\n" not in data:
            if len(data) >= READ_LIMIT:
                raise RequestError(400)
            _recv(conn, data, min(4096, READ_LIMIT - len(data)), deadline)
        head, body = data.split(b"\r\n\r\n", 1)
        request_line, *header_lines = head.split(b"\r\n")
        method, target = _parse_request_line(request_line)
        headers = _parse_headers(header_lines)
        size = _body_size(headers)
        if len(body) > size:
            raise RequestError(400)
        while len(body) < size:
            _recv(conn, body, size - len(body), deadline)
        if time.monotonic() >= deadline:
            raise TimeoutError
        return method, target, headers, bytes(body)
    finally:
        # A Python timeout socket would perform its own potentially blocking
        # readiness wait before send(), even with MSG_DONTWAIT.
        conn.settimeout(None)


def _parse_request_line(line):
    fields = line.split(b" ")
    if len(fields) != 3 or fields[2] != b"HTTP/1.1":
        raise RequestError(400)
    method, target, _ = fields
    if not HEADER.fullmatch(method):
        raise RequestError(400)
    if not target.startswith(b"/") or target.startswith(b"//"):
        raise RequestError(403)
    return method.decode("ascii"), target


def _parse_headers(lines):
    headers = {}
    for line in lines:
        name, sep, value = line.partition(b":")
        if not sep or not HEADER.fullmatch(name) or BAD_VALUE.search(value):
            raise RequestError(400)
        key = name.decode("ascii").lower()
        if key == "content-length" and key in headers:
            raise RequestError(400)
        if (key in headers or key in ("forwarded", "transfer-encoding", "expect")
                or key.startswith("x-forwarded-")):
            raise RequestError(403)
        headers[key] = value.strip(b" \t").decode("latin-1")
    return headers


def _body_size(headers):
    length = headers.get("content-length", "0")
    if not re.fullmatch(r"\d+", length, re.ASCII):
        raise RequestError(400)
    significant = length.lstrip("0") or "0"
    if len(significant) > 3 or int(significant) > BODY_LIMIT:
        raise RequestError(413)
    return int(significant)


def _recv(conn, data, size, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    conn.settimeout(remaining)
    chunk = conn.recv(size)
    if not chunk:
        raise EOFError
    data.extend(chunk)


def _frame(status, body=b"", content_type=None, extra=()):
    # A 204 has no message body and HTTP forbids Content-Length for that status.
    headers = COMMON_HEADERS
    if not any(key == "Content-Security-Policy" for key, _ in extra):
        headers += (("Content-Security-Policy", "frame-ancestors 'none'"),)
    if status != 204:
        headers += (("Content-Length", str(len(body))),)
    if content_type:
        headers += (("Content-Type", content_type),)
    head = [f"HTTP/1.1 {status} {HTTPStatus(status).phrase}"]
    head.extend(f"{key}: {value}" for key, value in headers + extra)
    return "\r\n".join(head).encode("ascii") + b"\r\n\r\n" + body


def _denial(status, extra=()):
    return _frame(status, b'{"error":"request_denied"}', JSON_TYPE, extra)


def _cookie(headers):
    matches = []
    for crumb in headers.get("cookie", "").split(";"):
        name, _, value = crumb.strip().partition("=")
        if name.rstrip() != DEFAULT_COOKIE_NAME:
            continue
        if name != DEFAULT_COOKIE_NAME:
            raise FixtureDenied
        matches.append(value)
    if len(matches) != 1 or not CODE.fullmatch(matches[0]):
        raise FixtureDenied
    return matches[0]


@dataclass(frozen=True)
class ReadContext:
    """Host-owned projection coordinates without cookie or CSRF credentials."""

    principal: PrincipalCtx
    read_session_id: str
    session_generation: int


@dataclass(frozen=True)
class Session:
    principal: PrincipalCtx
    session_hash: str
    read_alias: str
    generation: int
    csrf: str
    deadline: float

    def coords(self):
        return {"read_session_id": self.read_alias, "session_generation": self.generation}


class FixtureServer(socketserver.ThreadingTCPServer):
    """Own one pinned synthetic operator and linearize retirement with socket sends."""

    daemon_threads = False

    def __init__(self, build, *, clock=time.monotonic, idle=1800, absolute=28800,
                 principal=OPERATOR, reader=None, before_read=None, before_send=None,
                 on_backpressure=None, send_buffer=None):
        self.build = build
        self.clock = clock
        self.idle = idle
        self.principal = principal
        self.reader = reader if reader is not None else lambda _: PROJECTION
        self.before_read = before_read
        self.before_send = before_send
        self.on_backpressure = on_backpressure
        self.send_buffer = send_buffer
        self.guard = threading.Lock()
        self.capacity = threading.BoundedSemaphore(16)
        self.connection_guard = threading.Lock()
        self.connections: dict[socket.socket, float] = {}
        self.authority = True
        self.active = None
        self.generation = 0
        super().__init__(("127.0.0.1", 0), _Handler)
        port = self.server_address[1]
        self.host = f"127.0.0.1:{port}"
        self.origin = f"http://127.0.0.1:{port}"
        self.auth = UiAuthManager((self.host,), (self.origin,), idle_ttl_s=idle,
                                  absolute_ttl_s=absolute, max_sessions=2, clock=clock)

    def get_request(self):
        request, address = super().get_request()
        deadline = time.monotonic() + HTTP_DEADLINE
        with self.connection_guard:
            self.connections[request] = deadline
        return request, address

    def shutdown(self):
        # Stop new admissions and release-fenced sends before unblocking reads.
        self.revoke_authority()
        super().shutdown()
        with self.connection_guard:
            connections = tuple(self.connections)
        for request in connections:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Handler already closed it.

    def shutdown_request(self, request):
        with self.connection_guard:
            self.connections.pop(request, None)
        super().shutdown_request(request)

    def request_deadline(self, request):
        with self.connection_guard:
            return self.connections[request]

    def process_request(self, request, address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.capacity.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.capacity.release()

    def handle_error(self, request, client_address):
        # Errors never echo a request, credentials or synthetic private data.
        pass

    def mint(self, ttl=60):
        with self.guard:
            if not self._authorized():
                raise FixtureDenied
            return self.auth.mint_bootstrap_code(actor_id=self.principal.actor_id, ttl_s=ttl)

    def _authorized(self):
        return (self.authority and self.principal.role is CoordRole.OPERATOR
                and self.principal.sandbox_addr is None and self.principal.incarnation_id is None)

    def _retire(self):
        if self.active is not None:
            self.auth.revoke_session_by_hash(self.active.session_hash)
            self.active = None

    def revoke_authority(self):
        with self.guard:
            self.authority = False
            self._retire()

    def _session_status(self, session):
        """Check authority and sample the shared millisecond TTL under the guard."""
        if not self._authorized() or (session is not None and self.principal != session.principal):
            return 403, 0
        active = self.active
        if active is None:
            return 401, 0
        remaining_ms = int((active.deadline - self.clock()) * 1000)
        if remaining_ms <= 0:
            self._retire()
            return 401, 0
        if active is not session:
            return 401, 0
        return None, remaining_ms

    def _admit(self, headers):
        session = self.active
        denial, _ = self._session_status(session)
        if denial is not None:
            raise RequestError(denial)
        raw = _cookie(headers)
        record = self.auth.validate_session(raw, host_header=self.host, touch=False)
        if record.session_id_hash != session.session_hash:
            raise FixtureDenied
        return session

    def _exchange(self, headers, body):
        if headers.get("content-type") != JSON_TYPE:
            raise RequestError(415)
        try:
            payload = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
        except (ValueError, RecursionError):
            raise RequestError(400) from None
        if type(payload) is not dict or set(payload) != {"code"} or type(payload["code"]) is not str:
            raise RequestError(400)
        code = payload["code"]
        if not CODE.fullmatch(code):
            raise FixtureDenied
        with self.guard:
            if not self._authorized() or self.generation >= (1 << 53) - 1:
                raise RequestError(403)
            record, csrf, cookie = self.auth.exchange_bootstrap_code(
                code, host_header=self.host, origin_header=headers["origin"],
            )
            self._retire()
            self.generation += 1
            session = Session(
                self.principal, record.session_id_hash, secrets.token_urlsafe(24),
                self.generation, csrf, min(record.expires_at, record.last_seen_at + self.idle),
            )
            self.active = session
        return session, cookie

    def _logout(self, headers):
        with self.guard:
            self._admit(headers)
            try:
                self.auth.verify_http_mutation(
                    _cookie(headers), host_header=self.host, origin_header=headers["origin"],
                    csrf_token=headers.get("x-oc-csrf"),
                )
            except UiAuthDeniedError:
                raise RequestError(403) from None
            self._retire()

    def _session_frame(self, session, cookie, remaining_ms):
        body = _json_bytes({
            **session.coords(), "csrf_token": session.csrf, "expires_in_ms": remaining_ms,
        })
        if len(body) > AUTH_LIMIT:
            return None
        extra = (("Set-Cookie", cookie),) if cookie else ()
        return _frame(200, body, JSON_TYPE, extra)


def _unique_object(items):
    result = dict(items)
    if len(result) != len(items):
        raise ValueError("Duplicate key")
    return result


def _text(value, *, label=False):
    if type(value) is not str:
        raise ValueError("Invalid projection text")
    if label:
        if len(value) > 120 or SURROGATE.search(value):
            raise ValueError("Invalid projection label")
        return
    if len(value) > 256 or len(value.encode("utf-8")) > 256:
        raise ValueError("Projection text byte limit exceeded")


def _nodes(items, fields, limit):
    if type(items) is not list or len(items) > limit:
        raise ValueError("Projection list limit exceeded")
    ids = set()
    for item in items:
        if type(item) is not dict or set(item) != fields:
            raise ValueError("Unexpected projection fields")
        id_ = item["id"]
        if type(id_) is not str or not ID.fullmatch(id_):
            raise ValueError("Invalid projection ID")
        if id_ in ids:
            raise ValueError("Duplicate projection ID")
        ids.add(id_)
        _text(item["label"], label=True)
        yield item


def _entries(items, fields):
    if type(items) is not list or len(items) > 8:
        raise ValueError("Projection entry limit exceeded")
    for item in items:
        if type(item) is not dict or set(item) != fields:
            raise ValueError("Unexpected projection entry fields")
        for key, value in item.items():
            _text(value, label=key == "label")


def _workspace_bytes(session, projects):
    sandbox_count = 0
    thread_count = 0
    for project in _nodes(projects, {"id", "label", "sandboxes"}, 8):
        for sandbox in _nodes(project["sandboxes"], {"id", "label", "status", "threads"}, 16):
            sandbox_count += 1
            if sandbox_count > 16 or sandbox["status"] not in ("running", "stopped", "offline", "unknown"):
                raise ValueError("Invalid sandbox count or status")
            for thread in _nodes(
                sandbox["threads"], {"id", "label", "mailbox", "events", "provenance"}, 32,
            ):
                thread_count += 1
                if thread_count > 32:
                    raise ValueError("Projection thread limit exceeded")
                _entries(thread["mailbox"], {"text"})
                _entries(thread["events"], {"label", "text"})
                _entries(thread["provenance"], {"label", "text"})
    body = _json_bytes({"version": "oc.m3a.web@1", **session.coords(), "projects": projects})
    if len(body) > WORKSPACE_LIMIT:
        raise ValueError("Projection byte limit exceeded")
    return body


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        if self.server.send_buffer is not None:
            self.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.server.send_buffer)
        try:
            deadline = self.server.request_deadline(self.request)
            method, raw_target, headers, body = _read_request(self.request, deadline)
            if time.monotonic() >= deadline:
                return
        except RequestError as exc:
            self._send(_denial(exc.status), "")
            return
        except (OSError, EOFError):
            return

        try:
            self._route(method, raw_target, headers, body)
        except RequestError as exc:
            self._send(_denial(exc.status), "")
        except (FixtureDenied, UiAuthDeniedError):
            self._send(_denial(401), "")

    def _admitted_route(self, raw_target, headers):
        server = self.server
        origin = headers.get("origin")
        if headers.get("host") != server.host or (origin is not None and origin != server.origin):
            raise RequestError(403)
        if "upgrade" in headers.get("connection", "").lower() or "upgrade" in headers:
            raise RequestError(403)
        if not TARGET.fullmatch(raw_target):
            raise RequestError(404)
        route = raw_target.decode("ascii")
        if any(part in (".", "..") for part in route.split("/")) or "//" in route:
            raise RequestError(404)
        if (route not in METHODS and route not in DASHBOARDS
                and route not in server.build.assets and route != "/"):
            raise RequestError(404)
        return route

    def _route(self, method, raw_target, headers, body):
        route = self._admitted_route(raw_target, headers)
        allowed_method = METHODS.get(route, "GET")
        if method != allowed_method:
            self._send(_denial(405, (("Allow", allowed_method),)), route)
            return
        if (route in (EXCHANGE, LOGOUT) and headers.get("origin") != self.server.origin
                or route in (SESSION, WORKSPACE) and headers.get("x-oc-ui") != "1"):
            raise RequestError(403)
        if route != EXCHANGE and body:
            raise RequestError(400)

        if route in METHODS:
            self._serve_api(route, headers, body)
        else:
            self._serve_static(route)

    def _serve_api(self, route, headers, body):
        server = self.server
        if route == EXCHANGE:
            session, cookie = server._exchange(headers, body)
            self._send(None, route, session, cookie=cookie)
        elif route == LOGOUT:
            server._logout(headers)
            self._send(_frame(204), route)
        elif route in (SESSION, WORKSPACE):
            with server.guard:
                session = server._admit(headers)
            if route == WORKSPACE:
                self._workspace(route, session)
            else:
                self._send(None, route, session)

    def _serve_static(self, route):
        server = self.server
        if route == "/":
            self._send(_frame(303, extra=(("Location", "/dashboard/projects"),)), route)
        elif route in DASHBOARDS:
            frame = _frame(
                200, server.build.html, HTML_TYPE,
                (("Content-Security-Policy", server.build.csp),),
            )
            self._send(frame, route)
        else:
            asset = server.build.assets[route]
            self._send(_frame(200, asset.content, asset.content_type), route)

    def _workspace(self, route, session):
        server = self.server
        if server.before_read:
            server.before_read()
        try:
            with server.guard:
                denial, _ = server._session_status(session)
                if denial is not None:
                    raise RequestError(denial)
                context = ReadContext(session.principal, session.read_alias, session.generation)
                # The reader is trusted, bounded in-memory fixture code. It
                # returns stable data and may not block or perform I/O.
                projects = server.reader(context)
            body = _workspace_bytes(session, projects)
        except (ValueError, TypeError):
            self._send(_denial(503), route)
            return
        self._send(_frame(200, body, JSON_TYPE), route, session)

    def _send(self, frame, route, session=None, *, cookie=None):
        server = self.server
        offset = 0
        deadline = time.monotonic() + HTTP_DEADLINE
        while True:
            if server.before_send:
                server.before_send(route, offset)
            frame, session, sent = self._send_once(frame, session, cookie, offset, deadline)
            if sent is None:
                if server.on_backpressure:
                    server.on_backpressure(route, offset)
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not _wait_writable(self.request, remaining):
                    return
                continue
            if not sent or offset + sent == len(frame):
                return
            offset += sent

    def _send_once(self, frame, session, cookie, offset, deadline):
        server = self.server
        with server.guard:
            denial, remaining_ms = server._session_status(session) if session else (None, 0)
            if time.monotonic() >= deadline:
                return frame, session, 0
            if denial is not None:
                if offset:
                    return frame, session, 0
                frame, session = _denial(denial), None

            retry_frame = frame
            if frame is None:
                frame = server._session_frame(session, cookie, remaining_ms)
                if frame is None:
                    server._retire()
                    frame = retry_frame = _denial(401)
                    session = None

            try:
                view = memoryview(frame)[offset:offset + SEND_CHUNK]
                sent = self.request.send(view, socket.MSG_DONTWAIT)
            except BlockingIOError:
                # A private auth frame has no TTL until there is a successful send.
                return retry_frame, session, None
            except OSError:
                return frame, session, 0
            return frame, session, sent


def _wait_writable(conn, remaining):
    try:
        poller = select.poll()
        poller.register(conn, select.POLLOUT)
        return any(events & select.POLLOUT for _, events in poller.poll(ceil(remaining * 1000)))
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True, help="trusted SvelteKit build directory")
    args = parser.parse_args()
    try:
        build = load_build(args.build)
    except AssetError:
        parser.exit(1, "Invalid trusted UI build\n")

    with FixtureServer(build) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        try:
            print(json.dumps({"origin": server.origin, "code": server.mint()}), flush=True)
            for command in sys.stdin:
                if command.rstrip("\n") == "mint":
                    try:
                        code = server.mint()
                    except (FixtureDenied, UiAuthDeniedError):
                        print('{"error":"mint_denied"}', flush=True)
                    else:
                        print(json.dumps({"code": code}), flush=True)
                elif command.rstrip("\n") == "stop":
                    break
        except KeyboardInterrupt:
            pass
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
