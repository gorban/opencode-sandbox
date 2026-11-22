"""Unit & adversarial TLS integration tests for oc_broker_http.py (PRD L1 Lane 2)."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
import unittest
from urllib.parse import quote

_SPIKE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SPIKE_DIR.parents[3]
for _p in (str(_SPIKE_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_controller as occ  # noqa: E402
from oc_broker_common import (  # noqa: E402
    BrokerLease,
    BrokerPolicyError,
    HostVaultMemory,
    build_strict_tls_context,
)
from oc_broker_http import (  # noqa: E402
    AllowRule,
    HostHttpBrokerServer,
    HttpBrokerRoute,
    WirePolicy,
    all_graphql_operations_are_query,
    build_aws_ro_route,
    build_concourse_ro_route,
    build_github_ro_route,
    build_k8s_ro_route,
    build_remote_mcp_route,
    build_sonarqube_ro_route,
    derive_job_aws_credentials,
    join_upstream_path,
    match_segment_glob,
    sign_aws_sigv4,
    validate_route_table,
)


def _ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def _generate_test_tls_cert(cert_dir: Path) -> tuple[Path, Path]:
    cert_path = cert_dir / "upstream.crt"
    key_path = cert_dir / "upstream.key"
    cfg_path = cert_dir / "openssl.cnf"
    cfg_path.write_text(
        "[req]\n"
        "distinguished_name = dn\n"
        "x509_extensions = v3_req\n"
        "prompt = no\n"
        "[dn]\n"
        "CN = upstream.test\n"
        "[v3_req]\n"
        "subjectAltName = DNS:upstream.test,IP:127.0.0.1\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-config",
            str(cfg_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o600)
    return cert_path, key_path


@dataclass
class RecordedRequest:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes


class MockTlsUpstream:
    """Minimal pure-stdlib TLS mock upstream supporting normal and streaming responses."""

    def __init__(self, cert_path: Path, key_path: Path):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ctx.load_cert_chain(str(cert_path), str(key_path))
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.port: int = 0
        self.recorded: list[RecordedRequest] = []
        self.handler: Any = self._default_handler

    def _default_handler(self, req: RecordedRequest, conn: ssl.SSLSocket) -> None:
        payload = json.dumps({"ok": True, "target": req.target, "method": req.method}).encode("utf-8")
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Set-Cookie: sid=secret_cookie\r\n"
            b"WWW-Authenticate: Bearer realm=internal\r\n"
            b"X-Request-Id: req-123\r\n"
            b"Cache-Control: no-store\r\n"
            + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode("ascii")
            + payload
        )
        conn.sendall(resp)

    def start(self) -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        self.port = srv.getsockname()[1]
        srv.listen(32)
        srv.settimeout(0.2)
        self._sock = srv
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(raw,), daemon=True)
            t.start()

    def _handle_conn(self, raw: socket.socket) -> None:
        conn: ssl.SSLSocket | None = None
        try:
            conn = self._ctx.wrap_socket(raw, server_side=True)
            conn.settimeout(3.0)
            req = self._read_request(conn)
            if req is not None:
                self.recorded.append(req)
                self.handler(req, conn)
        except OSError:
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
            else:
                try:
                    raw.close()
                except OSError:
                    pass

    @staticmethod
    def _read_request(conn: ssl.SSLSocket) -> RecordedRequest | None:
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buf.extend(chunk)
        idx = buf.find(b"\r\n\r\n")
        head_lines = buf[:idx].decode("ascii").split("\r\n")
        method, target, _ver = head_lines[0].split(" ", 2)
        headers: dict[str, str] = {}
        for line in head_lines[1:]:
            k, v = line.split(":", 1)
            headers[k.lower().strip()] = v.strip()
        cl = int(headers.get("content-length", "0"))
        body = bytearray(buf[idx + 4 :])
        while len(body) < cl:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body.extend(chunk)
        return RecordedRequest(method=method, target=target, headers=headers, body=bytes(body[:cl]))


def _raw_http_exchange(
    addr: tuple[str, int] | Path, raw_request: bytes, *, timeout: float = 4.0
) -> tuple[int, dict[str, str], bytes]:
    if isinstance(addr, Path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        target: Any = str(addr)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target = addr
    sock.settimeout(timeout)
    try:
        sock.connect(target)
        sock.sendall(raw_request)
        buf = bytearray()
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf.extend(chunk)
    finally:
        sock.close()
    idx = buf.find(b"\r\n\r\n")
    head_lines = buf[:idx].decode("ascii").split("\r\n")
    status = int(head_lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in head_lines[1:]:
        k, v = line.split(":", 1)
        headers[k.lower().strip()] = v.strip()
    return status, headers, bytes(buf[idx + 4 :])


def _build_req(
    method: str,
    target: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    host: str = "127.0.0.1",
) -> bytes:
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}"]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    if body and (not headers or "content-length" not in {k.lower() for k in headers}):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def _make_resolver(ip_str: str) -> Any:
    def _resolve(host: str, port: int, **_kw: object) -> list[object]:
        _ = (host, port)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip_str, port))]

    return _resolve


class _DummyLeaseAdapter:
    def target_revision(self, target: str) -> str | None:
        return "rev_0001" if target == "broker_target" else None

    def set_target_revision(self, target: str, revision: str | None) -> None:
        _ = (target, revision)

    def dispatch(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        _ = (attempt, payload)
        return occ.Outcome.SUCCEEDED

    def reconcile(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        _ = (attempt, payload)
        return occ.Outcome.SUCCEEDED


class TestBrokerHttpUnit(unittest.TestCase):
    def test_route_validation_and_ro_rw_distinctness(self) -> None:
        vault = HostVaultMemory(
            {
                "keeper:ro": "RO_SECRET_VALUE_1111111111",
                "keeper:rw": "RW_SECRET_VALUE_2222222222",
                "keeper:dup": "RO_SECRET_VALUE_1111111111",
            }
        )
        ok_route = build_k8s_ro_route(
            "k8s",
            "https://upstream.test/k8s",
            "keeper:ro",
            pair_distinct_secret_ref="keeper:rw",
        )
        table = validate_route_table([ok_route], vault)
        self.assertIn("/http/k8s", table)

        dup_route = build_k8s_ro_route(
            "k8s",
            "https://upstream.test/k8s",
            "keeper:ro",
            pair_distinct_secret_ref="keeper:dup",
        )
        with self.assertRaises(BrokerPolicyError) as ctx:
            validate_route_table([dup_route], vault)
        self.assertNotIn("RO_SECRET_VALUE", str(ctx.exception))

    def test_segment_glob_and_join_upstream_path(self) -> None:
        self.assertEqual(join_upstream_path("/mcp", "/"), "/mcp")
        self.assertEqual(join_upstream_path("", "/"), "/")
        self.assertEqual(join_upstream_path("/v1", "/users"), "/v1/users")
        self.assertEqual(join_upstream_path("/", "/users"), "/users")

        self.assertTrue(match_segment_glob("/api/v1/namespaces/default/pods", "/api/v1/namespaces/*/pods*"))
        self.assertFalse(
            match_segment_glob("/api/v1/namespaces/default/pods/p1", "/api/v1/namespaces/*/pods*")
        )
        self.assertTrue(
            match_segment_glob("/api/v1/namespaces/default/pods/p1", "/api/v1/namespaces/*/pods/*")
        )
        self.assertTrue(
            match_segment_glob("/api/v1/namespaces/default/pods/p1/log", "/api/v1/namespaces/*/pods/*/log")
        )

    def test_graphql_ast_parser_strictness(self) -> None:
        self.assertTrue(all_graphql_operations_are_query("{ viewer { login } }"))
        self.assertTrue(
            all_graphql_operations_are_query(
                '# mutation fake\n'
                'fragment RepoFields on Repository { name description }\n'
                'query GetRepo($owner: String!, $doc: String = """mutation fake \\""" still str""") {\n'
                '  repository(owner: $owner, name: "oc") { ...RepoFields }\n'
                "}\n"
            )
        )
        for bad in (
            "mutation { deleteRepo(id: 1) { id } }",
            "subscription { issueAdded { id } }",
            "query A { viewer { login } } mutation B { x }",
            "fragment OnlyFrag on User { id }",
            "type Evil { id: ID }",
            "query { a { ",
            "",
        ):
            with self.subTest(gql=bad[:24]):
                self.assertFalse(all_graphql_operations_are_query(bad))

        deep = "{" * 70 + "a" + "}" * 70
        self.assertFalse(all_graphql_operations_are_query(deep))


class TestBrokerHttpIntegration(unittest.TestCase):
    _tmpdir_obj: tempfile.TemporaryDirectory[str]
    _cert_path: Path
    _key_path: Path
    _tls_ctx: ssl.SSLContext

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir_obj = tempfile.TemporaryDirectory(prefix="oc_http_test_")
        cls._cert_path, cls._key_path = _generate_test_tls_cert(Path(cls._tmpdir_obj.name))
        cls._tls_ctx = build_strict_tls_context(cafile=str(cls._cert_path))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmpdir_obj.cleanup()

    def setUp(self) -> None:
        self.upstream = MockTlsUpstream(self._cert_path, self._key_path)
        self.up_port = self.upstream.start()
        self.vault = HostVaultMemory(
            {
                "vault:mcp_ro": "CANARY_MCP_SECRET_TOKEN_12345",
                "vault:k8s_ro": "CANARY_K8S_SECRET_TOKEN_67890",
                "vault:concourse_ro": "CANARY_CONCOURSE_TOKEN_ABCDE",
                "vault:sonar_ro": "CANARY_SONAR_TOKEN_FGHIJ",
                "vault:github_ro": "CANARY_GITHUB_TOKEN_KLMNO",
                "vault:aws_ak": "AKIAHOSTBROKEREXAMPLE123",
                "vault:aws_sk": "CANARY_AWS_SECRET_KEY_PQRSTUVWX",
                "vault:hdr_ro": "CANARY_CUSTOM_HDR_SECRET_9999",
            }
        )
        self.lease = BrokerLease("job_http_1")
        base_url = f"https://upstream.test:{self.up_port}"
        self.routes = [
            build_remote_mcp_route(
                "docs",
                f"{base_url}/mcp",
                "vault:mcp_ro",
                allowed_tools=["search_docs", "get_page"],
                allow_streaming=True,
            ),
            build_remote_mcp_route(
                "nostream",
                f"{base_url}/mcp",
                "vault:mcp_ro",
                allowed_tools=["search_docs"],
                allow_streaming=False,
            ),
            build_k8s_ro_route("k8s", base_url, "vault:k8s_ro"),
            build_concourse_ro_route("concourse", base_url, "vault:concourse_ro"),
            build_sonarqube_ro_route("sonar", base_url, "vault:sonar_ro"),
            build_github_ro_route("github", base_url, "vault:github_ro"),
            build_aws_ro_route(
                "sts",
                base_url,
                "vault:aws_ak",
                "vault:aws_sk",
                allowed_aws_actions=["sts:GetCallerIdentity", "sts:GetSessionToken"],
                aws_region="us-east-1",
            ),
            HttpBrokerRoute(
                route_id="http:custom",
                route_prefix="/http/custom",
                upstream_url=base_url,
                secret_ref="vault:hdr_ro",
                wire_policy=WirePolicy(
                    allow_rules=(AllowRule(methods=("GET",), path_patterns=("/ping",)),)
                ),
                inbound_auth="header",
                inbound_auth_header="X-Job-Key",
                upstream_auth_mode="header",
                upstream_auth_header="X-API-Key",
            ),
        ]
        self.broker = HostHttpBrokerServer(
            self.routes,
            self.vault,
            self.lease,
            ssl_context=self._tls_ctx,
            resolver=_make_resolver("127.0.0.1"),
            allow_test_loopback=True,
        )
        self.addr = self.broker.start()

    def tearDown(self) -> None:
        self.broker.stop()
        self.upstream.stop()

    def _auth_hdr(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.lease.ocjob_token}"}

    def test_framing_smuggling_and_upgrade_rejected(self) -> None:
        bad_requests = [
            b"GET /http/k8s/version HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"POST /mcp/docs HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            b"POST /mcp/docs HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"GET /http/k8s/version HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Fold: a\r\n b\r\n\r\n",
            b"GET /http/k8s/version HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\r\n",
            b"GET /http/k8s/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive, Upgrade\r\n\r\n",
            b"GET /http/k8s/version HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nGET /http/k8s/version HTTP/1.1\r\n\r\n",
        ]
        for raw in bad_requests:
            status, _hdrs, _body = _raw_http_exchange(self.addr, raw)
            self.assertEqual(status, 400)
        self.assertEqual(len(self.upstream.recorded), 0)

    def test_upstream_101_upgrade_blocked(self) -> None:
        def _send_101(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")

        self.upstream.handler = _send_101
        raw = _build_req("GET", "/http/k8s/version", headers=self._auth_hdr())
        status, _hdrs, body = _raw_http_exchange(self.addr, raw)
        self.assertEqual(status, 502)
        self.assertIn(b"upstream_upgrade_blocked", body)

    def test_path_canonicalization_and_query_splitting(self) -> None:
        for bad_target in (
            "/http/k8s/api/v1/namespaces/default/%2e%2e/secrets",
            "/http/k8s/api/v1/namespaces/default/%2Fsecrets",
            "/http/k8s/api/v1/namespaces/default/%252fsecrets",
            "/http/k8s/api/v1/namespaces/default/%5csecrets",
            "/http/k8s/api/v1/namespaces/default/%00pods",
            "/http/k8s/api/v1/namespaces/default//pods",
            "/http/k8s/api/v1/namespaces/../v1/secrets",
            "/http/k8s/api/v1/./version",
        ):
            raw = _build_req("GET", bad_target, headers=self._auth_hdr())
            status, _hdrs, _body = _raw_http_exchange(self.addr, raw)
            self.assertEqual(status, 400, f"Expected 400 for {bad_target}")

        # Query string does not interfere with path matching and is forwarded cleanly
        raw_ok = _build_req(
            "GET",
            "/http/k8s/api/v1/namespaces/default/pods?labelSelector=app%3Dweb",
            headers=self._auth_hdr(),
        )
        status, _hdrs, _body = _raw_http_exchange(self.addr, raw_ok)
        self.assertEqual(status, 200)
        self.assertEqual(
            self.upstream.recorded[-1].target,
            "/api/v1/namespaces/default/pods?labelSelector=app%3Dweb",
        )

    def test_k8s_and_concourse_presets(self) -> None:
        for allowed in (
            "/http/k8s/api/v1/namespaces/default/pods",
            "/http/k8s/api/v1/namespaces/default/pods/web-1",
            "/http/k8s/api/v1/namespaces/default/pods/web-1/log",
            "/http/concourse/api/v1/info",
            "/http/concourse/api/v1/teams/main/pipelines",
        ):
            st, _h, _b = _raw_http_exchange(self.addr, _build_req("GET", allowed, headers=self._auth_hdr()))
            self.assertEqual(st, 200, allowed)

        for denied in (
            ("GET", "/http/k8s/api/v1/secrets"),
            ("GET", "/http/k8s/api/v1/namespaces/default/secrets"),
            ("GET", "/http/k8s/api/v1/namespaces/default/pods/web-1/exec"),
            ("GET", "/http/k8s/api/v1/namespaces/default/pods/web-1/attach"),
            ("GET", "/http/k8s/api/v1/namespaces/default/pods/web-1/portforward"),
            ("DELETE", "/http/k8s/api/v1/namespaces/default/pods/web-1"),
            ("GET", "/http/concourse/api/v1/teams/main/containers/c1/hijack"),
        ):
            st, _h, _b = _raw_http_exchange(
                self.addr, _build_req(denied[0], denied[1], headers=self._auth_hdr())
            )
            self.assertEqual(st, 403, str(denied))

    def test_sonarqube_basic_token_and_custom_header_auth(self) -> None:
        b64_job = base64.b64encode(f"{self.lease.ocjob_token}:".encode("ascii")).decode("ascii")
        st, _h, _b = _raw_http_exchange(
            self.addr,
            _build_req(
                "GET",
                "/http/sonar/api/issues/search?componentKeys=demo",
                headers={"Authorization": f"Basic {b64_job}"},
            ),
        )
        self.assertEqual(st, 200)
        expected_up = base64.b64encode(b"CANARY_SONAR_TOKEN_FGHIJ:").decode("ascii")
        self.assertEqual(self.upstream.recorded[-1].headers.get("authorization"), f"Basic {expected_up}")

        # Wrong auth scheme rejected
        st_bad, _h, _b = _raw_http_exchange(
            self.addr,
            _build_req("GET", "/http/sonar/api/issues/search", headers=self._auth_hdr()),
        )
        self.assertEqual(st_bad, 401)

        # Custom header auth stripped and replaced with upstream X-API-Key
        st_hdr, _h, _b = _raw_http_exchange(
            self.addr,
            _build_req("GET", "/http/custom/ping", headers={"X-Job-Key": self.lease.ocjob_token}),
        )
        self.assertEqual(st_hdr, 200)
        self.assertNotIn("x-job-key", self.upstream.recorded[-1].headers)
        self.assertEqual(
            self.upstream.recorded[-1].headers.get("x-api-key"), "CANARY_CUSTOM_HDR_SECRET_9999"
        )

    def test_mcp_jsonrpc_and_tools_list_json_and_sse_filtering(self) -> None:
        hdrs = {**self._auth_hdr(), "Content-Type": "application/json"}

        # tools/call allowed vs denied
        ok_call = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "search_docs"}}
        ).encode("utf-8")
        st, _h, _b = _raw_http_exchange(self.addr, _build_req("POST", "/mcp/docs", headers=hdrs, body=ok_call))
        self.assertEqual(st, 200)
        self.assertEqual(self.upstream.recorded[-1].target, "/mcp")

        bad_call = json.dumps(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "delete_prod"}}
        ).encode("utf-8")
        st_bad, _h, _b = _raw_http_exchange(
            self.addr, _build_req("POST", "/mcp/docs", headers=hdrs, body=bad_call)
        )
        self.assertEqual(st_bad, 403)

        # Reject batch arrays and duplicate keys
        for bad_body in (b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]', b'{"jsonrpc":"2.0","method":"ping","method":"ping"}'):
            st_b, _h, _b = _raw_http_exchange(
                self.addr, _build_req("POST", "/mcp/docs", headers=hdrs, body=bad_body)
            )
            self.assertEqual(st_b, 400)

        # JSON tools/list filtering
        def _json_tools_list(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            payload = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "result": {
                        "tools": [
                            {"name": "search_docs"},
                            {"name": "drop_database"},
                            {"name": "get_page"},
                        ]
                    },
                }
            ).encode("utf-8")
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode("ascii")
                + payload
            )

        self.upstream.handler = _json_tools_list
        list_req = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).encode("utf-8")
        st_l, _h, body_l = _raw_http_exchange(
            self.addr, _build_req("POST", "/mcp/docs", headers=hdrs, body=list_req)
        )
        self.assertEqual(st_l, 200)
        names = [t["name"] for t in json.loads(body_l)["result"]["tools"]]
        self.assertEqual(names, ["search_docs", "get_page"])

        # SSE tools/list filtering
        def _sse_tools_list(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            evt = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "result": {"tools": [{"name": "search_docs"}, {"name": "evil_tool"}]},
                }
            )
            payload = f"event: message\ndata: {evt}\n\n".encode("utf-8")
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode("ascii")
                + payload
            )

        self.upstream.handler = _sse_tools_list
        st_sse, _h, body_sse = _raw_http_exchange(
            self.addr, _build_req("POST", "/mcp/docs", headers=hdrs, body=list_req)
        )
        self.assertEqual(st_sse, 200)
        self.assertIn(b"search_docs", body_sse)
        self.assertNotIn(b"evil_tool", body_sse)

        # SSE blocked on nostream route
        st_ns, _h, body_ns = _raw_http_exchange(
            self.addr, _build_req("POST", "/mcp/nostream", headers=hdrs, body=list_req)
        )
        self.assertEqual(st_ns, 502)
        self.assertIn(b"streaming_not_allowed", body_ns)

        # Compressed Content-Encoding on MCP route fails closed 502
        def _gzip_resp(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Encoding: gzip\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
            )

        self.upstream.handler = _gzip_resp
        st_gz, _h, body_gz = _raw_http_exchange(
            self.addr, _build_req("POST", "/mcp/docs", headers=hdrs, body=list_req)
        )
        self.assertEqual(st_gz, 502)
        self.assertIn(b"upstream_compressed_response", body_gz)

    def test_github_rest_and_graphql_policy(self) -> None:
        st_get, _h, _b = _raw_http_exchange(
            self.addr, _build_req("GET", "/http/github/repos/org/proj/pulls", headers=self._auth_hdr())
        )
        self.assertEqual(st_get, 200)
        st_post_rest, _h, _b = _raw_http_exchange(
            self.addr, _build_req("POST", "/http/github/repos/org/proj/pulls", headers=self._auth_hdr())
        )
        self.assertEqual(st_post_rest, 403)

        hdrs = {**self._auth_hdr(), "Content-Type": "application/json"}
        q_ok = json.dumps({"query": "query { viewer { login } }"}).encode("utf-8")
        st_q, _h, _b = _raw_http_exchange(
            self.addr, _build_req("POST", "/http/github/graphql", headers=hdrs, body=q_ok)
        )
        self.assertEqual(st_q, 200)

        for bad_gql in (
            {"query": "mutation { closeIssue(input: {}) { clientMutationId } }"},
            {"query": "query { viewer { login } }", "extensions": {"persistedQuery": {"version": 1}}},
        ):
            st_b, _h, _b = _raw_http_exchange(
                self.addr,
                _build_req(
                    "POST",
                    "/http/github/graphql",
                    headers=hdrs,
                    body=json.dumps(bad_gql).encode("utf-8"),
                ),
            )
            self.assertEqual(st_b, 403)

    def test_aws_sigv4_inbound_verification_smuggling_and_host_resigning(self) -> None:
        job_ak, job_sk = derive_job_aws_credentials(self.lease.ocjob_token)
        body = b"Action=GetCallerIdentity&Version=2011-06-15"
        sig_hdrs = sign_aws_sigv4(
            method="POST",
            raw_path="/aws/sts",
            raw_query="",
            host_header="127.0.0.1",
            body=body,
            access_key=job_ak,
            secret_key=job_sk,
            region="us-east-1",
            service="sts",
            extra_headers={"content-type": "application/x-www-form-urlencoded"},
        )
        req_hdrs = {"Content-Type": "application/x-www-form-urlencoded", **sig_hdrs}
        st, _h, _b = _raw_http_exchange(
            self.addr, _build_req("POST", "/aws/sts", headers=req_hdrs, body=body)
        )
        self.assertEqual(st, 200)
        up_auth = self.upstream.recorded[-1].headers.get("authorization", "")
        self.assertIn("AKIAHOSTBROKEREXAMPLE123", up_auth)
        self.assertNotIn(job_ak, up_auth)

        # Duplicate Action= smuggling in body denied
        dup_body = b"Action=GetCallerIdentity&Action=AssumeRole"
        dup_sig = sign_aws_sigv4(
            method="POST",
            raw_path="/aws/sts",
            raw_query="",
            host_header="127.0.0.1",
            body=dup_body,
            access_key=job_ak,
            secret_key=job_sk,
            region="us-east-1",
            service="sts",
            extra_headers={"content-type": "application/x-www-form-urlencoded"},
        )
        st_dup, _h, _b = _raw_http_exchange(
            self.addr,
            _build_req(
                "POST",
                "/aws/sts",
                headers={"Content-Type": "application/x-www-form-urlencoded", **dup_sig},
                body=dup_body,
            ),
        )
        self.assertEqual(st_dup, 403)

        # Action= in both query and body denied
        ambig_sig = sign_aws_sigv4(
            method="POST",
            raw_path="/aws/sts",
            raw_query="Action=GetCallerIdentity",
            host_header="127.0.0.1",
            body=b"Action=AssumeRole",
            access_key=job_ak,
            secret_key=job_sk,
            region="us-east-1",
            service="sts",
            extra_headers={"content-type": "application/x-www-form-urlencoded"},
        )
        st_amb, _h, _b = _raw_http_exchange(
            self.addr,
            _build_req(
                "POST",
                "/aws/sts?Action=GetCallerIdentity",
                headers={"Content-Type": "application/x-www-form-urlencoded", **ambig_sig},
                body=b"Action=AssumeRole",
            ),
        )
        self.assertEqual(st_amb, 403)

        # Expired X-Amz-Date (>300s skew) rejected with 401
        old_sig = sign_aws_sigv4(
            method="POST",
            raw_path="/aws/sts",
            raw_query="",
            host_header="127.0.0.1",
            body=body,
            access_key=job_ak,
            secret_key=job_sk,
            region="us-east-1",
            service="sts",
            extra_headers={"content-type": "application/x-www-form-urlencoded"},
            now_ts=time.time() - 600,
        )
        st_old, _h, _b = _raw_http_exchange(
            self.addr,
            _build_req(
                "POST",
                "/aws/sts",
                headers={"Content-Type": "application/x-www-form-urlencoded", **old_sig},
                body=body,
            ),
        )
        self.assertEqual(st_old, 401)

    def test_redirect_block_header_allowlist_error_scrub_and_canary(self) -> None:
        # Inbound spoof headers ignored; safe response headers allowlisted
        raw = _build_req(
            "GET",
            "/http/k8s/version",
            headers={
                **self._auth_hdr(),
                "X-Forwarded-For": _ip(10, 0, 0, 1),
                "X-Original-URL": "/api/v1/secrets",
                "Accept-Encoding": "gzip, br",
            },
        )
        st, resp_hdrs, _b = _raw_http_exchange(self.addr, raw)
        self.assertEqual(st, 200)
        up_hdrs = self.upstream.recorded[-1].headers
        self.assertEqual(up_hdrs.get("accept-encoding"), "identity")
        self.assertNotIn("x-forwarded-for", up_hdrs)
        self.assertNotIn("x-original-url", up_hdrs)
        self.assertNotIn("set-cookie", resp_hdrs)
        self.assertNotIn("www-authenticate", resp_hdrs)
        self.assertEqual(resp_hdrs.get("x-request-id"), "req-123")

        # 302 redirect trap -> 502 with no Location and no upstream body
        def _redir(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            conn.sendall(
                b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/steal\r\n"
                b"Content-Length: 10\r\nConnection: close\r\n\r\nsecretbody"
            )

        self.upstream.handler = _redir
        st_r, hdrs_r, body_r = _raw_http_exchange(
            self.addr, _build_req("GET", "/http/k8s/version", headers=self._auth_hdr())
        )
        self.assertEqual(st_r, 502)
        self.assertNotIn("location", hdrs_r)
        self.assertNotIn(b"secretbody", body_r)

        # 500 error body scrubbed
        def _err500(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            conn.sendall(
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 25\r\nConnection: close\r\n\r\nINTERNAL_DB_TRACE_LEAK_99"
            )

        self.upstream.handler = _err500
        st_e, _hdrs_e, body_e = _raw_http_exchange(
            self.addr, _build_req("GET", "/http/k8s/version", headers=self._auth_hdr())
        )
        self.assertEqual(st_e, 500)
        self.assertNotIn(b"INTERNAL_DB_TRACE_LEAK_99", body_e)

        # Canary leak in response body (URL-encoded form) -> 502
        def _canary_leak(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            leaked = f"oops {quote('CANARY_K8S_SECRET_TOKEN_67890', safe='')}".encode("ascii")
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                + f"Content-Length: {len(leaked)}\r\nConnection: close\r\n\r\n".encode("ascii")
                + leaked
            )

        self.upstream.handler = _canary_leak
        st_c, _hdrs_c, body_c = _raw_http_exchange(
            self.addr, _build_req("GET", "/http/k8s/version", headers=self._auth_hdr())
        )
        self.assertEqual(st_c, 502)
        self.assertNotIn(b"CANARY_K8S_SECRET_TOKEN_67890", body_c)

    def test_dns_rebinding_ssrf_blocked_and_uds_0700_listener(self) -> None:
        ssrf_broker = HostHttpBrokerServer(
            [build_k8s_ro_route("k8s", f"https://upstream.test:{self.up_port}", "vault:k8s_ro")],
            self.vault,
            self.lease,
            ssl_context=self._tls_ctx,
            resolver=_make_resolver(_ip(169, 254, 169, 254)),
            allow_test_loopback=False,
        )
        ssrf_addr = ssrf_broker.start()
        try:
            st, _h, _b = _raw_http_exchange(
                ssrf_addr, _build_req("GET", "/http/k8s/version", headers=self._auth_hdr())
            )
            self.assertEqual(st, 502)
        finally:
            ssrf_broker.stop()

        # 0o700 UDS listener
        uds_dir = Path(self._tmpdir_obj.name) / "uds_broker"
        uds_path = uds_dir / "broker.sock"
        uds_broker = HostHttpBrokerServer(
            [build_k8s_ro_route("k8s", f"https://upstream.test:{self.up_port}", "vault:k8s_ro")],
            self.vault,
            self.lease,
            socket_path=uds_path,
            ssl_context=self._tls_ctx,
            resolver=_make_resolver("127.0.0.1"),
            allow_test_loopback=True,
        )
        uds_broker.start()
        try:
            self.assertEqual(stat.S_IMODE(os.lstat(uds_dir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.lstat(uds_path).st_mode), 0o600)
            st_u, _h, _b = _raw_http_exchange(
                uds_path, _build_req("GET", "/http/k8s/version", headers=self._auth_hdr())
            )
            self.assertEqual(st_u, 200)
        finally:
            uds_broker.stop()

    def test_controller_live_sse_revocation_under_1s(self) -> None:
        op = occ.Principal(occ.Role.OPERATOR, "host_op")
        orch = occ.Principal(occ.Role.ORCHESTRATOR, "orch_1")
        job_p = occ.Principal(occ.Role.JOB, "broker_job")
        subj = occ.Subject("worker_local", "job_inc_02", "broker_job")
        ctrl = occ.Controller(
            incarnation="0123456789abcdef0123456789abcdef",
            clock=lambda: 100,
            lifetime=600,
            workers=[occ.Worker("worker_local", op)],
            jobs=[occ.Job(subj, orch, 16)],
            capabilities=[occ.Capability("cap_broker", occ.Operation.PROBE, "broker_target")],
            references=[occ.Reference("ref_broker", "cap_broker")],
            adapter=_DummyLeaseAdapter(),
        )
        ctrl._set_alias("broker_alias", "broker_target")
        prop = ctrl.propose(job_p, occ.Proposal(occ.Intent.PROBE_GRANT, "broker_alias", "ref_broker"))
        view = ctrl.view(op, prop.request_id)
        ctrl.decide(op, prop.request_id, view.payload.revision, view.digest, occ.Decision.APPROVE)

        live_lease = BrokerLease(
            "job_sse_live",
            controller=ctrl,
            controller_actor=job_p,
            controller_request_id=prop.request_id,
        )
        live_lease.start_watchdog(poll_interval=0.02)

        stream_started = threading.Event()
        stop_upstream = threading.Event()

        def _slow_sse(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                b"Connection: close\r\n\r\ndata: hello\n\n"
            )
            stream_started.set()
            stop_upstream.wait(5.0)

        self.upstream.handler = _slow_sse
        sse_broker = HostHttpBrokerServer(
            [
                build_concourse_ro_route(
                    "concourse", f"https://upstream.test:{self.up_port}", "vault:concourse_ro"
                )
            ],
            self.vault,
            live_lease,
            ssl_context=self._tls_ctx,
            resolver=_make_resolver("127.0.0.1"),
            allow_test_loopback=True,
        )
        sse_addr = sse_broker.start()
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            cli.settimeout(2.0)
            cli.connect(sse_addr)
            cli.sendall(
                _build_req(
                    "GET",
                    "/http/concourse/api/v1/builds/1/events",
                    headers={"Authorization": f"Bearer {live_lease.ocjob_token}"},
                )
            )
            first = cli.recv(4096)
            self.assertIn(b"200 OK", first)
            self.assertTrue(stream_started.wait(1.0))

            t0 = time.monotonic()
            ctrl.revoke(op, prop.request_id)
            while True:
                more = cli.recv(4096)
                if not more:
                    break
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 0.8)
        finally:
            stop_upstream.set()
            cli.close()
            live_lease.stop_watchdog()
            sse_broker.stop()

    def test_streaming_sse_canary_and_aws_denied_and_revoked_lease(self) -> None:
        # 1. Canary split across SSE chunks aborts stream before emitting secret
        def _leaking_sse(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            secret = b"CANARY_CONCOURSE_TOKEN_ABCDE"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
            )
            conn.sendall(b"data: safe1\n\ndata: " + secret[:12])
            time.sleep(0.02)
            conn.sendall(secret[12:] + b"\n\n")

        self.upstream.handler = _leaking_sse
        st_sse, _h, body_sse = _raw_http_exchange(
            self.addr,
            _build_req("GET", "/http/concourse/api/v1/builds/9/events", headers=self._auth_hdr()),
        )
        self.assertEqual(st_sse, 200)
        self.assertNotIn(b"CANARY_CONCOURSE_TOKEN_ABCDE", body_sse)

        # 2. Unparseable MCP tools/list SSE & unexpected content type -> 502
        hdrs = {**self._auth_hdr(), "Content-Type": "application/json"}
        list_req = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}).encode("utf-8")

        def _bad_sse(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            payload = b"data: {not-valid-json\n\n"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode("ascii")
                + payload
            )

        self.upstream.handler = _bad_sse
        st_bad_sse, _h, _b = _raw_http_exchange(
            self.addr, _build_req("POST", "/mcp/docs", headers=hdrs, body=list_req)
        )
        self.assertEqual(st_bad_sse, 502)

        def _plain_ct(_req: RecordedRequest, conn: ssl.SSLSocket) -> None:
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 2\r\nConnection: close\r\n\r\nok"
            )

        self.upstream.handler = _plain_ct
        st_plain, _h, _b = _raw_http_exchange(
            self.addr, _build_req("POST", "/mcp/docs", headers=hdrs, body=list_req)
        )
        self.assertEqual(st_plain, 502)

        # 3. AWS denied actions (sts:AssumeRole and X-Amz-Target SecretsManager.GetSecretValue)
        job_ak, job_sk = derive_job_aws_credentials(self.lease.ocjob_token)
        assume_body = b"Action=AssumeRole&Version=2011-06-15"
        assume_sig = sign_aws_sigv4(
            method="POST",
            raw_path="/aws/sts",
            raw_query="",
            host_header="127.0.0.1",
            body=assume_body,
            access_key=job_ak,
            secret_key=job_sk,
            region="us-east-1",
            service="sts",
            extra_headers={"content-type": "application/x-www-form-urlencoded"},
        )
        st_assume, _h, _b = _raw_http_exchange(
            self.addr,
            _build_req(
                "POST",
                "/aws/sts",
                headers={"Content-Type": "application/x-www-form-urlencoded", **assume_sig},
                body=assume_body,
            ),
        )
        self.assertEqual(st_assume, 403)

        # Bad SigV4 signature -> 401
        bad_sig = dict(assume_sig)
        bad_sig["Authorization"] = bad_sig["Authorization"][:-4] + "0000"
        st_badsig, _h, _b = _raw_http_exchange(
            self.addr,
            _build_req(
                "POST",
                "/aws/sts",
                headers={"Content-Type": "application/x-www-form-urlencoded", **bad_sig},
                body=assume_body,
            ),
        )
        self.assertEqual(st_badsig, 401)

        # 4. Revoked lease before request -> 403 lease_revoked_or_expired
        self.lease.revoke()
        st_rev, _h, body_rev = _raw_http_exchange(
            self.addr, _build_req("GET", "/http/k8s/version", headers=self._auth_hdr())
        )
        self.assertEqual(st_rev, 403)
        self.assertIn(b"lease_revoked_or_expired", body_rev)


if __name__ == "__main__":
    unittest.main()
