"""Offline qualification using disposable TCP listeners and synthetic rows."""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import fcntl
from hashlib import sha256
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import resource
import socket
from tempfile import TemporaryDirectory
import threading
import time
import unittest

from oc_web_assets import AssetError, load_build
from oc_web_host import (
    DASHBOARDS, EXCHANGE, HTTP_DEADLINE, LOGOUT, PROJECTION, SESSION, WORKSPACE,
    CoordRole, FixtureDenied, FixtureServer, PrincipalCtx, _wait_writable,
)

SCRIPT = '''\nconst greeting = "café";\n'''
PAGE_PREFIX = "<!doctype html><meta charset=utf-8><title>café</title><script>".encode()
PAGE_SUFFIX = b"</script>"
HTML = PAGE_PREFIX + SCRIPT.encode() + PAGE_SUFFIX
SCRIPT_DIGEST = base64.b64encode(sha256(SCRIPT.encode()).digest()).decode()


def fixture_build(root, *, html=HTML, script=SCRIPT.encode()):
    (root / "200.html").write_bytes(html)
    (root / "csp-manifest.json").write_text(json.dumps({
        "version": 1,
        "html_sha256": sha256(html).hexdigest(),
        "inline_script_sha256": base64.b64encode(sha256(script).digest()).decode(),
    }))
    (root / "a.js").write_bytes(b"console.log('static');")
    return root


class Clock:
    now = 100.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@contextmanager
def running(build, *, server_class=FixtureServer, **params):
    with server_class(build, **params) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


def request(server, path, *, method="GET", headers=None, body=None):
    conn = HTTPConnection(*server.server_address, timeout=4)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        conn.close()


def do_exchange(server, code=None, **overrides):
    headers = {"Origin": server.origin, "Content-Type": "application/json", **overrides}
    return request(server, EXCHANGE, method="POST", headers=headers,
                   body=json.dumps({"code": code or server.mint()}))


def do_login(server):
    status, headers, body = do_exchange(server)
    assert status == 200
    return headers["set-cookie"].split(";", 1)[0], json.loads(body)


def do_read(server, cookie, path=WORKSPACE, **overrides):
    return request(server, path, headers={"X-OC-UI": "1", "Cookie": cookie, **overrides})


def do_logout(server, cookie, csrf):
    return request(server, LOGOUT, method="POST",
                   headers={"Origin": server.origin, "Cookie": cookie, "X-OC-CSRF": csrf})


def raw_request(server, message):
    with socket.create_connection(server.server_address, timeout=4) as conn:
        conn.sendall(message)
        return until_close(conn)


def until_close(conn):
    chunks = []
    while data := conn.recv(8192):
        chunks.append(data)
    return b"".join(chunks)


class Hold:
    def __init__(self):
        self.arrived = threading.Event()
        self.open = threading.Event()

    def __call__(self, *_):
        self.arrived.set()
        if not self.open.wait(3):
            raise TimeoutError("test barrier was never released")


class AssetTests(unittest.TestCase):
    def test_byte_exact_csp_and_in_memory_assets(self):
        with TemporaryDirectory() as root:
            root = fixture_build(Path(root))
            build = load_build(root)
            (root / "200.html").write_text("changed")
            (root / "a.js").write_text("changed")
            self.assertEqual(build.html, HTML)
            self.assertIn(f"script-src 'self' 'sha256-{SCRIPT_DIGEST}'", build.csp)
            self.assertIn("form-action 'none'", build.csp)
            self.assertEqual(build.assets["/a.js"].content, b"console.log('static');")
            self.assertNotIn("/csp-manifest.json", build.assets)
            self.assertNotIn("/200.html", build.assets)

    def test_rejects_invalid_byte_contract_even_with_matching_digests(self):
        for script in (b"\r\nvalid();", b"bad(\x00);", b"bad(\xff);"):
            with self.subTest(script=script), TemporaryDirectory() as root:
                path = fixture_build(Path(root), html=PAGE_PREFIX + script + PAGE_SUFFIX, script=script)
                with self.assertRaises(AssetError):
                    load_build(path)
        for html in (HTML + b"<script>other()</script>", b"no-script", HTML + b"\r\n",
                     HTML + b"\x00", HTML + b"<script src=a.js></script>",
                     HTML + b"<meta http-equiv=refresh>", HTML + b"<base href=/>",
                     HTML + b"<div onclick=one()>", HTML + b"<div style=color:red>"):
            with self.subTest(html=html), TemporaryDirectory() as root:
                path = fixture_build(Path(root), html=html)
                with self.assertRaises(AssetError):
                    load_build(path)

    def test_rejects_inert_script_even_when_hash_matches(self):
        for shell in (
            b"<html><frameset><script>",
            b"<html><title><script>",
            b"<html><title/><script>",
            b"<html><title /><script>",
        ):
            with self.subTest(shell=shell), TemporaryDirectory() as root:
                html = shell + SCRIPT.encode() + PAGE_SUFFIX
                path = fixture_build(Path(root), html=html)
                with self.assertRaises(AssetError):
                    load_build(path)

    def test_rejects_missing_or_mismatched_manifest(self):
        for filename in ("200.html", "csp-manifest.json"):
            with self.subTest(filename=filename), TemporaryDirectory() as root:
                path = fixture_build(Path(root))
                (path / filename).unlink()
                with self.assertRaises(AssetError):
                    load_build(path)
        with TemporaryDirectory() as root:
            path = fixture_build(Path(root))
            (path / "200.html").write_bytes(HTML + b"\n")
            with self.assertRaises(AssetError):
                load_build(path)
            fixture_build(path, script=b"wrong hashes")
            with self.assertRaises(AssetError):
                load_build(path)

    def test_rejects_unsafe_tree_entries_and_root(self):
        for name in ("linked.js", "named.pipe.js", "literal%20space.js", "service-worker.js",
                     "unexpected.html", "hardlinked.js", "api"):
            with self.subTest(name=name), TemporaryDirectory() as root:
                root = fixture_build(Path(root))
                node = root / name
                if name == "linked.js":
                    node.symlink_to(root / "a.js")
                elif name == "hardlinked.js":
                    os.link(root / "a.js", node)
                elif name == "api":
                    node.mkdir()
                elif name == "named.pipe.js":
                    os.mkfifo(node)
                else:
                    node.write_text("asset")
                with self.assertRaises(AssetError):
                    load_build(root)
        with TemporaryDirectory() as root:
            root = Path(root)
            real = root / "build"
            real.mkdir()
            fixture_build(real)
            symlink = root / "link"
            symlink.symlink_to(real, target_is_directory=True)
            with self.assertRaises(AssetError):
                load_build(symlink)
            link_in_build = real / "_app"
            link_in_build.symlink_to(root, target_is_directory=True)
            with self.assertRaises(AssetError):
                load_build(real)


class HostTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.build = load_build(fixture_build(Path(temp.name)))
        self.clock = Clock()

    def test_loopback_headers_routes_and_no_static_auth_data(self):
        with running(self.build) as server:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            status, headers, _ = request(server, "/")
            self.assertEqual((status, headers["location"]), (303, "/dashboard/projects"))
            self.assertEqual(headers["cache-control"], "no-store")
            self.assertEqual(headers["content-security-policy"], "frame-ancestors 'none'")
            for path in DASHBOARDS:
                status, headers, body = request(server, path)
                self.assertEqual((status, body), (200, HTML))
                self.assertEqual(headers["content-type"], "text/html; charset=utf-8")
                self.assertIn(f"'sha256-{SCRIPT_DIGEST}'", headers["content-security-policy"])
                self.assertEqual(headers["cache-control"], "no-store")
                self.assertEqual(headers["x-content-type-options"], "nosniff")
                self.assertEqual(headers["referrer-policy"], "no-referrer")
                self.assertNotIn("set-cookie", headers)
                self.assertNotIn(b"Fixture project", body)
            status, headers, body = request(server, "/a.js")
            self.assertEqual((status, body), (200, b"console.log('static');"))
            self.assertEqual(headers["content-type"], "text/javascript; charset=utf-8")
            for path in ("/api/unknown", "/events/missing", "/dashboard/typo", "/200.html",
                         "/%61.js", "/a.js?x=1", "/../a.js", "/./a.js", "/a.js/",
                         "/csp-manifest.json"):
                with self.subTest(path=path):
                    self.assertEqual(request(server, path)[0], 404)
            status, headers, _ = request(server, WORKSPACE, method="OPTIONS")
            self.assertEqual(status, 405)
            self.assertNotIn("access-control-allow-origin", headers)
            self.assertEqual(headers["content-security-policy"], "frame-ancestors 'none'")

    def test_host_origin_cookie_and_method_denials_precede_read(self):
        reads = []
        with running(self.build, reader=lambda principal: reads.append(principal)) as server:
            cookie, _ = do_login(server)
            for headers in (
                {"Host": "localhost:1"}, {"Host": server.host + ". "},
                {"Origin": "null"}, {"Origin": server.origin + "/"}, {"Origin": "http://127.0.0.1"},
                {"X-OC-UI": ""}, {"Forwarded": "host=" + server.host},
                {"X-Forwarded-Host": server.host}, {"Upgrade": "websocket"},
            ):
                with self.subTest(headers=headers):
                    self.assertEqual(do_read(server, cookie, **headers)[0], 403)
            self.assertEqual(do_read(server, cookie + "; " + cookie)[0], 401)
            self.assertEqual(do_read(server, "missing")[0], 401)
            self.assertEqual(request(server, WORKSPACE, method="POST")[0], 405)
            correct_host = f"Host: {server.host}"
            for target, fields in (
                (WORKSPACE, []), (WORKSPACE, [correct_host, correct_host]),
                (WORKSPACE, [correct_host, "Origin: " + server.origin, "Origin: " + server.origin]),
                (server.origin + WORKSPACE, [correct_host]),
                ("/" + WORKSPACE, [correct_host]),
                (WORKSPACE, [correct_host, "Transfer-Encoding: chunked"]),
            ):
                wire = "\r\n".join([f"GET {target} HTTP/1.1", *fields, "", ""]).encode()
                self.assertIn(b"HTTP/1.1 403 ", raw_request(server, wire))
            self.assertEqual(reads, [])

    def test_bootstrap_single_use_csrf_replacement_and_reload(self):
        with running(self.build, clock=self.clock, idle=10, absolute=40) as server:
            code = server.mint(ttl=2)
            self.assertEqual(do_exchange(server, code, Origin="null")[0], 403)
            self.assertEqual(request(server, EXCHANGE, method="POST")[0], 403)
            status, headers, body = do_exchange(server, code)
            self.assertEqual(status, 200)
            auth = json.loads(body)
            self.assertEqual(auth["expires_in_ms"], 10000)
            self.assertEqual(auth["session_generation"], 1)
            self.assertRegex(auth["read_session_id"], r"^[A-Za-z0-9_-]{32}$")
            self.assertLessEqual(len(body), 4 * 1024)
            self.assertEqual(headers["content-security-policy"], "frame-ancestors 'none'")
            cookie, *attributes = headers["set-cookie"].split("; ")
            self.assertEqual(attributes, ["HttpOnly", "SameSite=Strict", "Path=/"])
            self.assertNotIn(auth["read_session_id"], cookie)
            self.assertEqual(do_exchange(server, code)[0], 401)
            self.assertEqual(request(server, SESSION, headers={"Cookie": cookie})[0], 403)

            status, headers, body = do_read(server, cookie, path=SESSION)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), auth)
            self.assertNotIn("set-cookie", headers)
            self.assertEqual(do_logout(server, cookie, "wrong")[0], 403)
            status, headers, body = do_read(server, cookie)
            self.assertEqual(status, 200)
            workspace = json.loads(body)
            self.assertEqual(workspace["read_session_id"], auth["read_session_id"])
            self.assertEqual(workspace["session_generation"], auth["session_generation"])
            self.assertEqual(workspace["version"], "oc.m3a.web@1")
            self.assertEqual(workspace["projects"], PROJECTION)
            self.assertNotIn(auth["csrf_token"].encode(), body)
            self.assertNotIn("set-cookie", headers)

            status, headers, body = do_logout(server, cookie, auth["csrf_token"])
            self.assertEqual((status, body), (204, b""))
            self.assertNotIn("set-cookie", headers)
            self.assertEqual(do_read(server, cookie)[0], 401)
            second, fresh = do_login(server)
            self.assertNotEqual(second, cookie)
            self.assertNotEqual(fresh["read_session_id"], auth["read_session_id"])
            self.assertEqual(fresh["session_generation"], 2)
            third, replaced = do_login(server)
            self.assertNotEqual(third, second)
            self.assertEqual(replaced["session_generation"], 3)
            self.assertEqual(do_read(server, second)[0], 401)
            self.assertEqual(do_read(server, third)[0], 200)

    def test_concurrent_bootstrap_use_has_one_winner(self):
        with running(self.build, clock=self.clock) as server, ThreadPoolExecutor(2) as pool:
            code = server.mint()
            submits = [pool.submit(do_exchange, server, code) for _ in range(2)]
            responses = [req.result(3) for req in submits]
            self.assertEqual(sorted(status for status, _, _ in responses), [200, 401])
            self.assertEqual(sum("set-cookie" in headers for _, headers, _ in responses), 1)

    def test_expiry_does_not_refresh_and_bootstrap_expiry_is_inclusive(self):
        with running(self.build, clock=self.clock, idle=10, absolute=20) as server:
            code = server.mint(ttl=2)
            self.clock.advance(2)
            self.assertEqual(do_exchange(server, code)[0], 401)
            cookie, _ = do_login(server)
            self.clock.advance(7)
            self.assertEqual(json.loads(do_read(server, cookie, path=SESSION)[2])["expires_in_ms"], 3000)
            self.assertEqual(do_read(server, cookie)[0], 200)
            self.clock.advance(3)
            self.assertEqual(do_read(server, cookie)[0], 401)

    def test_equal_idle_and_absolute_deadlines(self):
        with running(self.build, clock=self.clock, idle=10, absolute=10) as server:
            cookie, _ = do_login(server)
            self.clock.advance(9)
            self.assertEqual(do_read(server, cookie)[0], 200)
            self.clock.advance(1)
            self.assertEqual(do_read(server, cookie)[0], 401)

    def test_non_operator_cannot_mint_or_exchange(self):
        principal = PrincipalCtx(CoordRole.ORCHESTRATOR, "fixture-nonoperator")
        with running(self.build, principal=principal) as server:
            with self.assertRaises(FixtureDenied):
                server.mint()
            private_code = server.auth.mint_bootstrap_code()
            self.assertEqual(do_exchange(server, private_code)[0], 403)

    def test_invalid_projection_fails_closed(self):
        projection = deepcopy(PROJECTION)
        projection[0]["unexpected"] = "hidden"
        with running(self.build, reader=lambda _: projection) as server:
            cookie, _ = do_login(server)
            status, _, body = do_read(server, cookie)
            self.assertEqual(status, 503)
            self.assertNotIn(b"hidden", body)

    def test_projection_label_scalar_and_text_byte_limits(self):
        for label, text, expected in (
            ("界" * 100, "x", 200),
            ("界" * 120, "é" * 128, 200),
            ("😀" * 120, "x", 200),
            ("a" * 121, "x", 503),
            ("ok", "é" * 129, 503),
            ("ok", "a" * 257, 503),
            ("\ud800", "x", 503),
            ("ok", "\udfff", 503),
        ):
            with self.subTest(label_length=len(label), text_length=len(text), expected=expected):
                projection = deepcopy(PROJECTION)
                projection[0]["label"] = label
                thread = projection[0]["sandboxes"][0]["threads"][0]
                thread["mailbox"][0]["text"] = text
                self._check_projection_text(projection, label, text, expected)

    def _check_projection_text(self, projection, label, text, expected):
        with running(self.build, reader=lambda _: projection) as server:
            cookie, _ = do_login(server)
            status, _, body = do_read(server, cookie)
            self.assertEqual(status, expected)
            if status == 200:
                project = json.loads(body)["projects"][0]
                self.assertEqual(project["label"], label)
                thread = project["sandboxes"][0]["threads"][0]
                self.assertEqual(thread["mailbox"][0]["text"], text)

    def test_retirement_before_read_or_first_release_denies(self):
        for retirement in ("logout", "expiry", "revoke", "replace"):
            for point in ("read", "release"):
                with self.subTest(retirement=retirement, point=point):
                    self._check_retirement_barrier(retirement, point)

    def _check_retirement_barrier(self, retirement, point):
        clock = Clock()
        hold = Hold()
        reads = []

        def reader(context):
            reads.append(context)
            return PROJECTION

        def before_send(route, offset):
            if route == WORKSPACE and offset == 0:
                hold()

        params = {"before_read": hold} if point == "read" else {"before_send": before_send}
        with running(self.build, clock=clock, idle=10, absolute=20,
                     reader=reader, **params) as server, ThreadPoolExecutor(2) as pool:
            cookie, auth = do_login(server)
            pending = pool.submit(do_read, server, cookie)
            try:
                self.assertTrue(hold.arrived.wait(1))
                self._retire_fixture_session(retirement, server, clock, cookie, auth)
            finally:
                hold.open.set()
            status, _, body = pending.result(3)
            self.assertEqual(status, 403 if retirement == "revoke" else 401)
            self.assertNotIn(b"Fixture project", body)
            self.assertEqual(len(reads), 0 if point == "read" else 1)

    def _retire_fixture_session(self, retirement, server, clock, cookie, auth):
        if retirement == "logout":
            self.assertEqual(do_logout(server, cookie, auth["csrf_token"])[0], 204)
        elif retirement == "expiry":
            clock.advance(10)
        elif retirement == "revoke":
            server.revoke_authority()
        else:
            _, fresh = do_login(server)
            self.assertGreater(fresh["session_generation"], auth["session_generation"])

    def test_logout_completes_while_partial_private_send_is_backpressured(self):
        projection = deepcopy(PROJECTION)
        sandbox = projection[0]["sandboxes"][0]
        one_thread = sandbox["threads"][0]
        sandbox["threads"] = [
            {**one_thread, "id": f"thread-{number}", "mailbox": [{"text": "x" * 240}] * 8}
            for number in range(13)
        ]
        sandbox["threads"][-1]["provenance"] = [{"label": "tail", "text": "suffix-marker"}]
        stalled = Hold()
        accepted = []

        def on_backpressure(route, offset):
            if route == WORKSPACE:
                accepted.append(offset)
                stalled()

        with running(self.build, reader=lambda _: projection,
                     send_buffer=1024, on_backpressure=on_backpressure) as server:
            cookie, auth = do_login(server)
            with socket.socket() as conn:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                conn.settimeout(3)
                conn.connect(server.server_address)
                conn.sendall((f"GET {WORKSPACE} HTTP/1.1\r\nHost: {server.host}\r\n"
                              f"X-OC-UI: 1\r\nCookie: {cookie}\r\n\r\n").encode())
                try:
                    self.assertTrue(stalled.arrived.wait(1))
                    self.assertGreater(accepted[0], 0)
                    self.assertEqual(do_logout(server, cookie, auth["csrf_token"])[0], 204)
                finally:
                    stalled.open.set()
                partial = until_close(conn)
                self.assertEqual(len(partial), accepted[0])
                self.assertIn(b"HTTP/1.1 200 ", partial)
                self.assertNotIn(b"suffix-marker", partial)
                self.assertEqual(do_read(server, cookie)[0], 401)

    def test_reader_holds_retirement_guard_and_receives_pinned_coordinates(self):
        observed = []

        def reader(context):
            unlocked = server.guard.acquire(blocking=False)
            if unlocked:
                server.guard.release()
            observed.append((unlocked, context))
            return PROJECTION

        with running(self.build, reader=reader) as server:
            cookie, auth = do_login(server)
            self.assertEqual(do_read(server, cookie)[0], 200)
            self.assertEqual(len(observed), 1)
            unlocked, context = observed[0]
            self.assertFalse(unlocked)
            self.assertEqual(context.principal, server.principal)
            self.assertEqual(context.read_session_id, auth["read_session_id"])
            self.assertEqual(context.session_generation, auth["session_generation"])
            self.assertFalse(hasattr(context, "csrf"))
            self.assertFalse(hasattr(context, "session_hash"))

    def test_poll_handles_high_socket_descriptor(self):
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != resource.RLIM_INFINITY and soft <= 1024:
            self.skipTest("open file limit prevents allocating descriptor 1024")
        left, right = socket.socketpair()
        with left, right:
            high_fd = fcntl.fcntl(left.fileno(), fcntl.F_DUPFD_CLOEXEC, 1024)
            with socket.socket(fileno=high_fd) as high:
                self.assertGreaterEqual(high.fileno(), 1024)
                while True:
                    try:
                        high.send(b"x" * 8192, socket.MSG_DONTWAIT)
                    except BlockingIOError:
                        break
                self.assertFalse(_wait_writable(high, 0.01))
                while True:
                    try:
                        right.recv(8192, socket.MSG_DONTWAIT)
                    except BlockingIOError:
                        break
                self.assertTrue(_wait_writable(high, 0.05))

    def test_auth_ttl_is_calculated_at_socket_release(self):
        for route in (EXCHANGE, SESSION):
            with self.subTest(route=route):
                clock = Clock()
                hold = Hold()

                def before_send(path, offset, target=route, release=hold):
                    if path == target and offset == 0:
                        release()

                with running(self.build, clock=clock, idle=10, absolute=20,
                             before_send=before_send) as server, ThreadPoolExecutor(2) as pool:
                    if route == EXCHANGE:
                        pending = pool.submit(do_exchange, server)
                    else:
                        cookie, _ = do_login(server)
                        pending = pool.submit(do_read, server, cookie, SESSION)
                    try:
                        self.assertTrue(hold.arrived.wait(1))
                        clock.advance(3)
                    finally:
                        hold.open.set()
                    status, _, body = pending.result(3)
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(body)["expires_in_ms"], 7000)

    def test_auth_denies_remaining_ttl_rounded_to_zero(self):
        with running(self.build, clock=self.clock, idle=10, absolute=20) as server:
            cookie, _ = do_login(server)
            self.clock.advance(9.9995)
            status, headers, body = do_read(server, cookie, path=SESSION)
            self.assertEqual(status, 401)
            self.assertNotIn("set-cookie", headers)
            self.assertNotIn(b"csrf_token", body)
            self.assertEqual(do_read(server, cookie)[0], 401)

    def test_held_exchange_retires_rounded_to_zero_session(self):
        self._check_held_rounded_to_zero_release(EXCHANGE)

    def test_held_workspace_retires_rounded_to_zero_session(self):
        self._check_held_rounded_to_zero_release(WORKSPACE)

    def _check_held_rounded_to_zero_release(self, route):
        hold = Hold()

        def before_send(path, offset):
            if path == route and offset == 0:
                hold()

        with running(self.build, clock=self.clock, idle=10, absolute=20,
                     before_send=before_send) as server, ThreadPoolExecutor(2) as pool:
            if route == EXCHANGE:
                pending = pool.submit(do_exchange, server)
            else:
                cookie, _ = do_login(server)
                pending = pool.submit(do_read, server, cookie)

            try:
                self.assertTrue(hold.arrived.wait(1))
                with server.guard:
                    session = server.active
                    self.assertIsNotNone(session)
                    self.clock.advance(9.9995)
            finally:
                hold.open.set()

            status, headers, body = pending.result(3)
            self.assertEqual(status, 401)
            self.assertNotIn("set-cookie", headers)
            self.assertNotIn(b"csrf_token", body)
            self.assertNotIn(b"Fixture project", body)
            with server.guard:
                self.assertIs(server.active, None, "expired fixture session remained active")
                self.assertFalse(server.auth.revoke_session_by_hash(session.session_hash))

    def test_malformed_framing_and_media_preserve_previous_session(self):
        with running(self.build) as server:
            cookie, auth = do_login(server)
            code = server.mint()
            self.assertEqual(do_exchange(server, code, **{"Content-Type": "text/plain"})[0], 415)
            for body in (b'{"code":"a","code":"b"}', b'{"code":NaN}', b'{"code":"a","role":"operator"}'):
                response = request(
                    server, EXCHANGE, method="POST", body=body,
                    headers={"Origin": server.origin, "Content-Type": "application/json"},
                )
                self.assertEqual(response[0], 400)
            for status, framing in (
                (400, "Content-Length: 0\r\nContent-Length: 0"),
                (400, "Content-Length: 0,0"),
                (400, "Content-Length: -1"),
                (413, "Content-Length: 257"),
                (413, "Content-Length: 999999999999999"),
            ):
                fields = (f"POST {EXCHANGE} HTTP/1.1\r\nHost: {server.host}\r\n"
                          f"Origin: {server.origin}\r\nContent-Type: application/json\r\n"
                          f"{framing}\r\n\r\n")
                self.assertIn(f"HTTP/1.1 {status} ".encode(), raw_request(server, fields.encode()))
            logout = request(
                server, LOGOUT, method="POST", body=b"x",
                headers={"Origin": server.origin, "Cookie": cookie, "X-OC-CSRF": auth["csrf_token"]},
            )
            self.assertEqual(logout[0], 400)
            self.assertEqual(do_read(server, cookie)[0], 200)
            self.assertEqual(do_exchange(server, code)[0], 200)

    def test_authority_revocation_denies_both_private_gets_and_exchange(self):
        reads = []
        with running(self.build, reader=lambda principal: reads.append(principal)) as server:
            code = server.mint()
            cookie, _ = do_login(server)
            server.revoke_authority()
            for route in (SESSION, WORKSPACE):
                status, headers, body = do_read(server, cookie, path=route)
                self.assertEqual(status, 403)
                self.assertNotIn("set-cookie", headers)
                self.assertNotIn(b"csrf_token", body)
            self.assertEqual(do_exchange(server, code)[0], 403)
            self.assertEqual(reads, [])

    def test_request_deadline_includes_delay_after_socket_acceptance(self):
        hold = Hold()

        class DelayedWorker(FixtureServer):
            def process_request_thread(self, request, address):
                if hold.open.is_set() or not delayed.is_set():
                    return super().process_request_thread(request, address)
                hold()
                return super().process_request_thread(request, address)

        delayed = threading.Event()
        reads = []
        with running(self.build, server_class=DelayedWorker,
                     reader=lambda principal: reads.append(principal)) as server:
            cookie, _ = do_login(server)
            delayed.set()
            with socket.create_connection(server.server_address, timeout=4) as conn:
                try:
                    self.assertTrue(hold.arrived.wait(1))
                    time.sleep(HTTP_DEADLINE + 0.05)
                    conn.sendall(workspace_request(server, cookie))
                finally:
                    hold.open.set()
                self.assertEqual(read_closed(conn), b"")
            self.assertEqual(reads, [])

    def test_trickling_headers_and_body_do_not_renew_deadline(self):
        reads = []
        with running(self.build, reader=lambda principal: reads.append(principal)) as server:
            cookie, auth = do_login(server)
            with ExitStack() as stack:
                peers = incomplete_peers(stack, server, cookie)
                starts = time.monotonic()
                while peers and time.monotonic() - starts < HTTP_DEADLINE + 0.5:
                    for conn in peers[:]:
                        try:
                            data = conn.recv(1024)
                        except TimeoutError:
                            try:
                                conn.sendall(b" ")
                            except (BrokenPipeError, ConnectionResetError):
                                data = b""
                            else:
                                continue
                        except ConnectionResetError:
                            data = b""
                        self.assertEqual(data, b"")
                        peers.remove(conn)
                    time.sleep(0.05)
                self.assertEqual(peers, [])
            status, _, body = do_read(server, cookie, path=SESSION)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["read_session_id"], auth["read_session_id"])
            self.assertEqual(reads, [])

    def test_shutdown_interrupts_incomplete_headers_and_body(self):
        both_accepted = threading.Event()

        class CountAccepted(FixtureServer):
            peer_count = 0

            def get_request(self):
                accepted = super().get_request()
                self.peer_count += 1
                if self.peer_count == 3:  # login then two incomplete requests
                    both_accepted.set()
                return accepted

        reads = []
        with running(self.build, server_class=CountAccepted,
                     reader=lambda principal: reads.append(principal)) as server:
            cookie, _ = do_login(server)
            with ExitStack() as stack:
                peers = incomplete_peers(stack, server, cookie)
                self.assertTrue(both_accepted.wait(1))
                start = time.monotonic()
                server.shutdown()
                server.server_close()
                self.assertLess(time.monotonic() - start, HTTP_DEADLINE / 2)
                for conn in peers:
                    self.assertEqual(read_closed(conn), b"")
            self.assertEqual(reads, [])


def workspace_request(server, cookie):
    return (f"GET {WORKSPACE} HTTP/1.1\r\nHost: {server.host}\r\n"
            f"X-OC-UI: 1\r\nCookie: {cookie}\r\n\r\n").encode()


def read_closed(conn):
    try:
        return until_close(conn)
    except ConnectionResetError:
        return b""


def incomplete_peers(stack, server, cookie):
    peers = []
    for data in (
        workspace_request(server, cookie)[:-2],
        (f"POST {EXCHANGE} HTTP/1.1\r\nHost: {server.host}\r\nOrigin: {server.origin}\r\n"
         "Content-Type: application/json\r\nContent-Length: 256\r\n\r\n{").encode(),
    ):
        conn = stack.enter_context(socket.create_connection(server.server_address, timeout=0.02))
        conn.sendall(data)
        peers.append(conn)
    return peers
