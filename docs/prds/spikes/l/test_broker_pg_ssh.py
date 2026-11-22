"""Unit & adversarial tests for oc_broker_pg.py and oc_broker_ssh.py (PRD L1 Lane 3)."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import shlex
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import quote

_SPIKE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SPIKE_DIR.parents[3]
for _p in (str(_SPIKE_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_controller as occ  # noqa: E402
from oc_broker_common import (  # noqa: E402
    BrokerAuthError,
    BrokerError,
    BrokerLease,
    BrokerPolicyError,
    CanaryLeakError,
    HostVaultMemory,
    build_strict_tls_context,
)
from oc_broker_pg import (  # noqa: E402
    HostPostgresBrokerServer,
    PG_CANCEL_REQUEST,
    PG_GSSENC_REQUEST,
    PG_PROTOCOL_V3,
    PG_SSL_REQUEST,
    PgBrokerRoute,
    _build_redaction_pattern,
    encode_pg_frame,
    encode_pg_startup,
    filter_parameter_status_body,
    read_pg_control_frame,
    recv_exact,
    scrub_error_or_notice_body,
    validate_pg_route,
)
from oc_broker_ssh import (  # noqa: E402
    HostSshBroker,
    SshApprovalAdapter,
    SshRawOutput,
    SshTarget,
    _run_streaming_subprocess,
    compute_ssh_command_digest,
)

MOCK_PG_HOST = "pg.mock.test"
MOCK_PG_USER = "app_ro_role_secret"
MOCK_PG_RW_USER = "app_rw_role_secret"
MOCK_PG_DB = "prod_analytics"
MOCK_PG_PASSWORD = "CANARY_PG_UPSTREAM_SECRET_991122/+"
MOCK_PG_RW_PASSWORD = "CANARY_PG_UPSTREAM_RW_SECRET_884455/+"


def _ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def _generate_test_cert(cert_dir: Path, hostname: str) -> tuple[Path, Path]:
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"
    cfg_path = cert_dir / "openssl.cnf"
    cfg_path.write_text(
        "[req]\n"
        "distinguished_name = dn\n"
        "x509_extensions = v3_req\n"
        "prompt = no\n"
        "[dn]\n"
        f"CN = {hostname}\n"
        "[v3_req]\n"
        f"subjectAltName = DNS:{hostname}\n",
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
            "2",
            "-nodes",
            "-config",
            str(cfg_path),
        ],
        check=True,
        capture_output=True,
    )
    os.chmod(key_path, 0o600)
    return cert_path, key_path


def _parse_startup_params(payload: bytes) -> dict[str, str]:
    parts = [p.decode("utf-8", errors="replace") for p in payload.split(b"\x00") if p]
    out: dict[str, str] = {}
    for idx in range(0, len(parts) - 1, 2):
        out[parts[idx]] = parts[idx + 1]
    return out


def _encode_kv_frame(msg_type: bytes, fields: list[tuple[bytes, str]]) -> bytes:
    parts = [code + val.encode("utf-8") + b"\x00" for code, val in fields]
    parts.append(b"\x00")
    return encode_pg_frame(msg_type, b"".join(parts))


def _encode_param_status(key: str, val: str) -> bytes:
    return encode_pg_frame(b"S", key.encode("utf-8") + b"\x00" + val.encode("utf-8") + b"\x00")


def _encode_datarow(payload: bytes) -> bytes:
    body = struct.pack("!HI", 1, len(payload)) + payload
    return encode_pg_frame(b"D", body)


@dataclass
class _MockPgState:
    startups: list[dict[str, str]] = field(default_factory=list)
    cancels: list[tuple[int, int]] = field(default_factory=list)
    cancel_event: threading.Event = field(default_factory=threading.Event)


class _MockUpstreamPgServer:
    """Local TLS-capable mock Postgres v3 server for deterministic broker tests."""

    def __init__(
        self,
        cert_path: Path,
        key_path: Path,
        *,
        password: str = MOCK_PG_PASSWORD,
        user: str = MOCK_PG_USER,
        auth_mode: str = "scram",
        reject_ssl: bool = False,
        corrupt_server_v: bool = False,
        repeat_auth: bool = False,
        scram_override: str | None = None,
        duplicate_backend_key: bool = False,
        stall_cancel: bool = False,
        real_pid: int = 424242,
        real_key: int = 989898,
    ):
        self._password = password
        self._user = user
        self._auth_mode = auth_mode
        self._reject_ssl = reject_ssl
        self._corrupt_server_v = corrupt_server_v
        self._repeat_auth = repeat_auth
        self._scram_override = scram_override
        self._duplicate_backend_key = duplicate_backend_key
        self._stall_cancel = stall_cancel
        self.real_pid = real_pid
        self.real_key = real_key
        self.state = _MockPgState()

        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ssl_ctx.load_cert_chain(str(cert_path), str(key_path))

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = int(self._sock.getsockname()[1])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            t.start()

    def _handle_conn(self, raw_conn: socket.socket) -> None:
        conn: socket.socket = raw_conn
        try:
            conn.settimeout(5.0)
            hdr = recv_exact(conn, 8)
            length, code = struct.unpack("!II", hdr)
            if code != PG_SSL_REQUEST or length != 8:
                return
            if self._reject_ssl:
                conn.sendall(b"N")
                return
            if self._stall_cancel and self.state.startups:
                time.sleep(2.5)
                return
            conn.sendall(b"S")
            conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
            self._handle_tls_session(conn)
        except (EOFError, OSError, ssl.SSLError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle_tls_session(self, conn: socket.socket) -> None:
        hdr = recv_exact(conn, 8)
        length, code = struct.unpack("!II", hdr)
        if code == PG_CANCEL_REQUEST and length == 16:
            pid, key = struct.unpack("!II", recv_exact(conn, 8))
            self.state.cancels.append((pid, key))
            self.state.cancel_event.set()
            return
        if code != PG_PROTOCOL_V3:
            return
        payload = recv_exact(conn, length - 8)
        self.state.startups.append(_parse_startup_params(payload))
        if not self._run_auth(conn):
            return
        self._send_post_auth_banner(conn)
        self._query_loop(conn)

    def _run_auth(self, conn: socket.socket) -> bool:
        if self._repeat_auth:
            conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 3)))
            read_pg_control_frame(conn)
            conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 3)))
            return False
        if self._auth_mode == "ok":
            conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 0)))
            return True
        if self._auth_mode == "cleartext":
            return self._auth_cleartext(conn)
        if self._auth_mode == "md5":
            return self._auth_md5(conn)
        return self._auth_scram(conn)

    def _auth_cleartext(self, conn: socket.socket) -> bool:
        conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 3)))
        mtype, body = read_pg_control_frame(conn)
        if mtype != b"p" or body[:-1].decode("utf-8") != self._password:
            return False
        conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 0)))
        return True

    def _auth_md5(self, conn: socket.socket) -> bool:
        salt = b"S1A2"
        conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 5) + salt))
        mtype, body = read_pg_control_frame(conn)
        inner = hashlib.md5((self._password + self._user).encode("utf-8")).hexdigest().encode("ascii")
        expected = f"md5{hashlib.md5(inner + salt).hexdigest()}\x00".encode("ascii")
        if mtype != b"p" or body != expected:
            return False
        conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 0)))
        return True

    def _auth_scram(self, conn: socket.socket) -> bool:
        conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 10) + b"SCRAM-SHA-256\x00\x00"))
        mtype, body = read_pg_control_frame(conn)
        if mtype != b"p":
            return False
        nul = body.index(b"\x00")
        c_first = body[nul + 5 :].decode("utf-8")
        c_first_bare = c_first.split(",,", 1)[1]
        c_nonce = c_first_bare.split("r=", 1)[1]

        if self._scram_override == "bad_utf8":
            conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 11) + b"\xff\xfe"))
            return False
        if self._scram_override == "empty_salt":
            s_first = f"r={c_nonce}srv,s=,i=4096"
            conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 11) + s_first.encode("utf-8")))
            return False
        if self._scram_override == "mandatory_ext":
            s_first = f"m=unsupported,r={c_nonce}srv,s=MTIzNA==,i=4096"
            conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 11) + s_first.encode("utf-8")))
            return False

        return self._finish_scram(conn, c_first_bare, c_nonce)

    def _finish_scram(self, conn: socket.socket, c_first_bare: str, c_nonce: str) -> bool:
        salt = b"0123456789abcdef"
        iters = 4096
        s_nonce = c_nonce + "srvnonce99"
        s_first = f"r={s_nonce},s={base64.b64encode(salt).decode('ascii')},i={iters}"
        conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 11) + s_first.encode("utf-8")))

        mtype, body = read_pg_control_frame(conn)
        if mtype != b"p":
            return False
        c_final = body.decode("utf-8")
        c_final_no_proof, proof_part = c_final.rsplit(",p=", 1)

        salted = hashlib.pbkdf2_hmac("sha256", self._password.encode("utf-8"), salt, iters)
        c_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        stored_key = hashlib.sha256(c_key).digest()
        auth_msg = f"{c_first_bare},{s_first},{c_final_no_proof}".encode("utf-8")
        c_sig = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
        expected_proof = base64.b64encode(bytes(a ^ b for a, b in zip(c_key, c_sig))).decode("ascii")
        if not hmac.compare_digest(proof_part, expected_proof):
            return False

        s_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        s_sig = hmac.new(s_key, auth_msg, hashlib.sha256).digest()
        v_val = "AAAA_BAD_SIG" if self._corrupt_server_v else base64.b64encode(s_sig).decode("ascii")
        conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 12) + f"v={v_val}".encode("utf-8")))
        conn.sendall(encode_pg_frame(b"R", struct.pack("!I", 0)))
        return True

    def _send_post_auth_banner(self, conn: socket.socket) -> None:
        conn.sendall(_encode_param_status("server_version", "16.4"))
        conn.sendall(_encode_param_status("client_encoding", "UTF8"))
        conn.sendall(_encode_param_status("session_authorization", self._user))
        conn.sendall(_encode_param_status("application_name", "secret_app"))
        conn.sendall(encode_pg_frame(b"K", struct.pack("!II", self.real_pid, self.real_key)))
        if self._duplicate_backend_key:
            conn.sendall(encode_pg_frame(b"K", struct.pack("!II", self.real_pid + 1, self.real_key + 1)))
        conn.sendall(encode_pg_frame(b"Z", b"I"))

    def _query_loop(self, conn: socket.socket) -> None:
        while not self._stop.is_set():
            mtype, body = read_pg_control_frame(conn)
            if mtype == b"X":
                return
            if mtype != b"Q":
                continue
            sql = body.rstrip(b"\x00").decode("utf-8", errors="replace")
            self._handle_query(conn, sql)

    def _handle_query(self, conn: socket.socket, sql: str) -> None:
        if sql == "SELECT big":
            conn.sendall(_encode_datarow(b"A" * 300_000))
            conn.sendall(encode_pg_frame(b"C", b"SELECT 1\x00"))
            conn.sendall(encode_pg_frame(b"Z", b"I"))
            return
        if sql == "SELECT canary":
            leaked = b"X" * 16_370 + self._password.encode("utf-8") + b"Y" * 100
            conn.sendall(_encode_datarow(leaked))
            conn.sendall(encode_pg_frame(b"Z", b"I"))
            return
        if sql == "SELECT err":
            msg = f"host {MOCK_PG_HOST.upper()} (127.0.0.1) role {self._user} pw {self._password}"
            conn.sendall(_encode_kv_frame(b"E", [(b"S", "ERROR"), (b"C", "42501"), (b"M", msg)]))
            conn.sendall(encode_pg_frame(b"Z", b"I"))
            return
        if sql == "SELECT notice":
            msg = f"notice from {MOCK_PG_HOST} for {self._user}"
            conn.sendall(_encode_kv_frame(b"N", [(b"S", "NOTICE"), (b"M", msg)]))
            conn.sendall(encode_pg_frame(b"Z", b"I"))
            return
        if sql == "SELECT sleep":
            self.state.cancel_event.wait(timeout=3.0)
            return
        conn.sendall(_encode_datarow(b"ok_row"))
        conn.sendall(encode_pg_frame(b"C", b"SELECT 1\x00"))
        conn.sendall(encode_pg_frame(b"Z", b"I"))


def _client_handshake(
    sock: socket.socket,
    token: str,
    *,
    send_ssl: bool = True,
    send_gss: bool = False,
    startup_user: str = "attacker_superuser",
    startup_db: str = "attacker_db",
    startup_options: str = "-c default_transaction_read_only=off",
) -> tuple[dict[str, str], tuple[int, int] | None]:
    if send_ssl:
        sock.sendall(struct.pack("!II", 8, PG_SSL_REQUEST))
        if recv_exact(sock, 1) != b"N":
            raise AssertionError("Expected 'N' reply to SSLRequest")
    if send_gss:
        sock.sendall(struct.pack("!II", 8, PG_GSSENC_REQUEST))
        if recv_exact(sock, 1) != b"N":
            raise AssertionError("Expected 'N' reply to GSSENCRequest")
    sock.sendall(encode_pg_startup(startup_user, startup_db, startup_options))

    mtype, body = read_pg_control_frame(sock)
    if mtype != b"R" or struct.unpack("!I", body[:4])[0] != 3:
        raise AssertionError("Expected AuthenticationCleartextPassword")
    sock.sendall(encode_pg_frame(b"p", token.encode("utf-8") + b"\x00"))

    mtype, body = read_pg_control_frame(sock)
    if mtype != b"R" or struct.unpack("!I", body[:4])[0] != 0:
        raise AssertionError("Expected AuthenticationOk")

    params: dict[str, str] = {}
    key_data: tuple[int, int] | None = None
    while True:
        mtype, body = read_pg_control_frame(sock)
        if mtype == b"S":
            k, v = body.split(b"\x00")[:2]
            params[k.decode("utf-8")] = v.decode("utf-8")
        elif mtype == b"K":
            key_data = struct.unpack("!II", body)
        elif mtype == b"Z":
            return params, key_data


def _parse_error_fields(body: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    pos = 0
    while pos < len(body):
        code = body[pos : pos + 1]
        if code == b"\x00":
            break
        nul = body.index(b"\x00", pos + 1)
        out[code.decode("ascii")] = body[pos + 1 : nul].decode("utf-8")
        pos = nul + 1
    return out


def _assert_socket_closed(sock: socket.socket) -> None:
    try:
        data = sock.recv(16)
    except ConnectionResetError:
        data = b""
    if data != b"":
        raise AssertionError(f"Expected closed socket, got {data!r}")


def _loopback_resolver(host: str, port: int, **_kw: object) -> list[object]:
    _ = host
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]


class _DummyLeaseAdapter:
    def target_revision(self, target: str) -> str | None:
        return "rev_0001" if target == "pg_target" else None

    def set_target_revision(self, target: str, revision: str | None) -> None:
        _ = (target, revision)

    def dispatch(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        _ = (attempt, payload)
        return occ.Outcome.SUCCEEDED

    def reconcile(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        _ = (attempt, payload)
        return occ.Outcome.SUCCEEDED


class TestHostPostgresBroker(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls._cert_path, cls._key_path = _generate_test_cert(Path(cls._tmpdir.name), MOCK_PG_HOST)
        cls._client_ssl = build_strict_tls_context(cafile=str(cls._cert_path))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmpdir.cleanup()

    def _make_vault(self) -> HostVaultMemory:
        return HostVaultMemory(
            {
                "keeper:pg_ro": MOCK_PG_PASSWORD,
                "keeper:pg_rw": MOCK_PG_RW_PASSWORD,
            }
        )

    def _make_route(self, port: int, *, mode: str = "ro") -> PgBrokerRoute:
        return PgBrokerRoute(
            route_id="pg:analytics",
            upstream_host=MOCK_PG_HOST,
            upstream_port=port,
            upstream_database=MOCK_PG_DB,
            upstream_user=MOCK_PG_USER,
            secret_ref="keeper:pg_ro",
            access_mode=mode,
            pair_distinct_user=MOCK_PG_RW_USER,
            pair_distinct_secret_ref="keeper:pg_rw",
        )

    def test_pg_route_distinctness_and_control_char_rejection(self) -> None:
        vault = self._make_vault()
        validate_pg_route(self._make_route(5432), vault)

        same_user = PgBrokerRoute(
            route_id="pg:bad1",
            upstream_host=MOCK_PG_HOST,
            upstream_port=5432,
            upstream_database=MOCK_PG_DB,
            upstream_user=MOCK_PG_USER,
            secret_ref="keeper:pg_ro",
            pair_distinct_user=MOCK_PG_USER,
            pair_distinct_secret_ref="keeper:pg_rw",
        )
        with self.assertRaises(BrokerPolicyError):
            validate_pg_route(same_user, vault)

        vault.set("keeper:pg_dup", MOCK_PG_PASSWORD)
        same_pw = PgBrokerRoute(
            route_id="pg:bad2",
            upstream_host=MOCK_PG_HOST,
            upstream_port=5432,
            upstream_database=MOCK_PG_DB,
            upstream_user=MOCK_PG_USER,
            secret_ref="keeper:pg_ro",
            pair_distinct_user=MOCK_PG_RW_USER,
            pair_distinct_secret_ref="keeper:pg_dup",
        )
        with self.assertRaises(BrokerPolicyError):
            validate_pg_route(same_pw, vault)

        nul_user = PgBrokerRoute(
            route_id="pg:bad3",
            upstream_host=MOCK_PG_HOST,
            upstream_port=5432,
            upstream_database=MOCK_PG_DB,
            upstream_user="app\x00options",
            secret_ref="keeper:pg_ro",
        )
        with self.assertRaises(BrokerPolicyError):
            validate_pg_route(nul_user, vault)

        # Non-loopback TCP listener host rejected
        with self.assertRaises(BrokerPolicyError):
            HostPostgresBrokerServer(
                self._make_route(5432),
                vault,
                BrokerLease("job_non_loopback"),
                host=_ip(0, 0, 0, 0),
            )

    def test_pg_upstream_ssl_refusal_aborts_no_downgrade(self) -> None:
        mock = _MockUpstreamPgServer(self._cert_path, self._key_path, reject_ssl=True)
        mock.start()
        lease = BrokerLease("job_ssl_refuse")
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                sock.sendall(encode_pg_startup("u", "d"))
                mtype, body = read_pg_control_frame(sock)
                self.assertEqual(mtype, b"R")
                self.assertEqual(struct.unpack("!I", body[:4])[0], 3)
                sock.sendall(encode_pg_frame(b"p", lease.ocjob_token.encode("utf-8") + b"\x00"))
                with self.assertRaises(EOFError):
                    read_pg_control_frame(sock)
            finally:
                sock.close()
            self.assertEqual(mock.state.startups, [])
        finally:
            srv.stop()
            mock.stop()

    def test_pg_scram_sha256_role_pinning_and_parameter_scrubbing(self) -> None:
        mock = _MockUpstreamPgServer(self._cert_path, self._key_path, auth_mode="scram")
        mock.start()
        lease = BrokerLease("job_scram")
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                params, key_data = _client_handshake(sock, lease.ocjob_token, send_ssl=True, send_gss=True)
                self.assertEqual(params.get("server_version"), "16.4")
                self.assertEqual(params.get("client_encoding"), "UTF8")
                self.assertNotIn("session_authorization", params)
                self.assertNotIn("application_name", params)
                self.assertIsNotNone(key_data)
                self.assertNotEqual(key_data, (mock.real_pid, mock.real_key))

                sock.sendall(encode_pg_frame(b"Q", b"SELECT ok\x00"))
                mtype, body = read_pg_control_frame(sock)
                self.assertEqual(mtype, b"D")
                self.assertIn(b"ok_row", body)
                sock.sendall(encode_pg_frame(b"X", b""))
            finally:
                sock.close()

            self.assertEqual(len(mock.state.startups), 1)
            up_params = mock.state.startups[0]
            self.assertEqual(up_params["user"], MOCK_PG_USER)
            self.assertEqual(up_params["database"], MOCK_PG_DB)
            self.assertEqual(up_params["options"], "-c default_transaction_read_only=on")
        finally:
            srv.stop()
            mock.stop()

    def test_pg_scram_edge_cases_and_repeated_auth_rejected(self) -> None:
        cases = [
            {"corrupt_server_v": True},
            {"scram_override": "bad_utf8"},
            {"scram_override": "empty_salt"},
            {"scram_override": "mandatory_ext"},
            {"repeat_auth": True},
        ]
        for idx, kwargs in enumerate(cases):
            mock = _MockUpstreamPgServer(self._cert_path, self._key_path, auth_mode="scram", **kwargs)
            mock.start()
            lease = BrokerLease(f"job_scram_edge_{idx}")
            srv = HostPostgresBrokerServer(
                self._make_route(mock.port),
                self._make_vault(),
                lease,
                resolver=_loopback_resolver,
                allow_test_loopback=True,
                ssl_context=self._client_ssl,
            )
            srv.start()
            try:
                sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
                try:
                    sock.sendall(encode_pg_startup("u", "d"))
                    read_pg_control_frame(sock)
                    sock.sendall(encode_pg_frame(b"p", lease.ocjob_token.encode("utf-8") + b"\x00"))
                    with self.subTest(case=kwargs), self.assertRaises(EOFError):
                        read_pg_control_frame(sock)
                finally:
                    sock.close()
            finally:
                srv.stop()
                mock.stop()

    def test_pg_duplicate_backend_key_data_rejected(self) -> None:
        mock = _MockUpstreamPgServer(
            self._cert_path, self._key_path, duplicate_backend_key=True
        )
        mock.start()
        lease = BrokerLease("job_dup_k")
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                with self.assertRaises(EOFError):
                    _client_handshake(sock, lease.ocjob_token)
            finally:
                sock.close()
        finally:
            srv.stop()
            mock.stop()

    def test_pg_cleartext_and_md5_upstream_auth(self) -> None:
        for mode in ("cleartext", "md5"):
            mock = _MockUpstreamPgServer(self._cert_path, self._key_path, auth_mode=mode)
            mock.start()
            lease = BrokerLease(f"job_{mode}")
            srv = HostPostgresBrokerServer(
                self._make_route(mock.port),
                self._make_vault(),
                lease,
                resolver=_loopback_resolver,
                allow_test_loopback=True,
                ssl_context=self._client_ssl,
            )
            srv.start()
            try:
                sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
                try:
                    params, _ = _client_handshake(sock, lease.ocjob_token)
                    self.assertEqual(params.get("server_version"), "16.4")
                    sock.sendall(encode_pg_frame(b"X", b""))
                finally:
                    sock.close()
            finally:
                srv.stop()
                mock.stop()

    def test_pg_client_bad_token_revoked_lease_and_ssl_retry_exhaustion(self) -> None:
        mock = _MockUpstreamPgServer(self._cert_path, self._key_path)
        mock.start()
        lease = BrokerLease("job_auth_err")
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            # Exceed SSLRequest retries (>3)
            sock_ssl = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                for _ in range(4):
                    sock_ssl.sendall(struct.pack("!II", 8, PG_SSL_REQUEST))
                    self.assertEqual(recv_exact(sock_ssl, 1), b"N")
                _assert_socket_closed(sock_ssl)
            finally:
                sock_ssl.close()

            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                sock.sendall(encode_pg_startup("u", "d"))
                read_pg_control_frame(sock)
                sock.sendall(encode_pg_frame(b"p", b"ocjob_wrong_token\x00"))
                mtype, body = read_pg_control_frame(sock)
                self.assertEqual(mtype, b"E")
                self.assertEqual(_parse_error_fields(body)["C"], "28P01")
            finally:
                sock.close()

            lease.revoke()
            sock2 = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                sock2.sendall(encode_pg_startup("u", "d"))
                mtype, body = read_pg_control_frame(sock2)
                self.assertEqual(mtype, b"E")
                self.assertEqual(_parse_error_fields(body)["C"], "28000")
            finally:
                sock2.close()
        finally:
            srv.stop()
            mock.stop()

    def test_pg_cancel_isolation_and_exact_len_16(self) -> None:
        mock = _MockUpstreamPgServer(self._cert_path, self._key_path)
        mock.start()
        lease = BrokerLease("job_cancel")
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                _, key_data = _client_handshake(sock, lease.ocjob_token)
                assert key_data is not None

                bad_c = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
                try:
                    bad_c.sendall(struct.pack("!III", 12, PG_CANCEL_REQUEST, 1))
                    _assert_socket_closed(bad_c)
                finally:
                    bad_c.close()

                other_c = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
                try:
                    other_c.sendall(struct.pack("!IIII", 16, PG_CANCEL_REQUEST, mock.real_pid, mock.real_key))
                    _assert_socket_closed(other_c)
                finally:
                    other_c.close()
                self.assertEqual(mock.state.cancels, [])

                good_c = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
                try:
                    good_c.sendall(struct.pack("!IIII", 16, PG_CANCEL_REQUEST, key_data[0], key_data[1]))
                    _assert_socket_closed(good_c)
                finally:
                    good_c.close()
                self.assertTrue(mock.state.cancel_event.wait(timeout=2.0))
                self.assertEqual(mock.state.cancels, [(mock.real_pid, mock.real_key)])
            finally:
                sock.close()
        finally:
            srv.stop()
            mock.stop()

    def test_pg_negative_and_huge_frame_lengths_rejected(self) -> None:
        mock = _MockUpstreamPgServer(self._cert_path, self._key_path)
        mock.start()
        lease = BrokerLease("job_badlen")
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            for bad_frame in (
                b"Q" + struct.pack("!i", 3),
                b"d" + struct.pack("!i", -1),
                b"d" + struct.pack("!i", 0x3FFF_FFFF),
            ):
                sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
                try:
                    _client_handshake(sock, lease.ocjob_token)
                    sock.sendall(bad_frame)
                    _assert_socket_closed(sock)
                finally:
                    sock.close()
        finally:
            srv.stop()
            mock.stop()

    def test_pg_slowloris_total_handshake_deadline(self) -> None:
        mock = _MockUpstreamPgServer(self._cert_path, self._key_path)
        mock.start()
        lease = BrokerLease("job_slowloris")
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            handshake_timeout=0.3,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=2.0)
            try:
                sock.sendall(b"\x00\x00")
                time.sleep(0.45)
                _assert_socket_closed(sock)
            finally:
                sock.close()
        finally:
            srv.stop()
            mock.stop()

    def test_pg_streaming_large_datarow_and_canary_abort(self) -> None:
        mock = _MockUpstreamPgServer(self._cert_path, self._key_path)
        mock.start()
        lease = BrokerLease("job_stream")
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                _client_handshake(sock, lease.ocjob_token)
                sock.sendall(encode_pg_frame(b"Q", b"SELECT big\x00"))
                hdr = recv_exact(sock, 5)
                self.assertEqual(hdr[:1], b"D")
                frame_len = struct.unpack("!i", hdr[1:5])[0]
                body = recv_exact(sock, frame_len - 4)
                self.assertEqual(len(body), 6 + 300_000)
                self.assertEqual(body[6:], b"A" * 300_000)
                read_pg_control_frame(sock)
                read_pg_control_frame(sock)

                sock.sendall(encode_pg_frame(b"Q", b"SELECT canary\x00"))
                received = bytearray()
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    received.extend(chunk)
                self.assertNotIn(MOCK_PG_PASSWORD.encode("utf-8"), received)
            finally:
                sock.close()
        finally:
            srv.stop()
            mock.stop()

    def test_pg_error_notice_and_wire_format_strictness(self) -> None:
        pat = _build_redaction_pattern(MOCK_PG_HOST, "127.0.0.1", MOCK_PG_USER, (MOCK_PG_PASSWORD,))
        with self.assertRaises(BrokerPolicyError):
            scrub_error_or_notice_body(b"Mhello\x00\x00trailing", pat)
        with self.assertRaises(BrokerPolicyError):
            filter_parameter_status_body(b"server_version\x0016.4\x00extra", pat)

        mock = _MockUpstreamPgServer(self._cert_path, self._key_path)
        mock.start()
        lease = BrokerLease("job_scrub")
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                _client_handshake(sock, lease.ocjob_token)
                sock.sendall(encode_pg_frame(b"Q", b"SELECT err\x00"))
                mtype, body = read_pg_control_frame(sock)
                self.assertEqual(mtype, b"E")
                fields = _parse_error_fields(body)
                self.assertNotIn(MOCK_PG_HOST.upper(), fields["M"])
                self.assertNotIn(MOCK_PG_HOST, fields["M"].lower())
                self.assertNotIn("127.0.0.1", fields["M"])
                self.assertNotIn(MOCK_PG_USER, fields["M"])
                self.assertNotIn(MOCK_PG_PASSWORD, fields["M"])
                self.assertIn("[redacted]", fields["M"])
                z_type, _ = read_pg_control_frame(sock)
                self.assertEqual(z_type, b"Z")

                sock.sendall(encode_pg_frame(b"Q", b"SELECT notice\x00"))
                ntype, nbody = read_pg_control_frame(sock)
                self.assertEqual(ntype, b"N")
                nfields = _parse_error_fields(nbody)
                self.assertNotIn(MOCK_PG_HOST, nfields["M"])
                self.assertNotIn(MOCK_PG_USER, nfields["M"])
                z_type, _ = read_pg_control_frame(sock)
                self.assertEqual(z_type, b"Z")
            finally:
                sock.close()
        finally:
            srv.stop()
            mock.stop()

    def test_pg_controller_revocation_sub_second_and_stalled_cancel_nonblocking(self) -> None:
        now = [100]
        op = occ.Principal(occ.Role.OPERATOR, "host_op")
        orch = occ.Principal(occ.Role.ORCHESTRATOR, "orch_1")
        job_p = occ.Principal(occ.Role.JOB, "pg_job")
        subj = occ.Subject("worker_local", "pg_inc_01", "pg_job")
        ctrl = occ.Controller(
            incarnation="0123456789abcdef0123456789abcdef",
            clock=lambda: now[0],
            lifetime=600,
            workers=[occ.Worker("worker_local", op)],
            jobs=[occ.Job(subj, orch, 16)],
            capabilities=[occ.Capability("cap_pg", occ.Operation.PROBE, "pg_target")],
            references=[occ.Reference("ref_pg", "cap_pg")],
            adapter=_DummyLeaseAdapter(),
        )
        ctrl._set_alias("pg_alias", "pg_target")
        prop = ctrl.propose(job_p, occ.Proposal(occ.Intent.PROBE_GRANT, "pg_alias", "ref_pg"))
        view = ctrl.view(op, prop.request_id)
        ctrl.decide(op, prop.request_id, view.payload.revision, view.digest, occ.Decision.APPROVE)

        mock = _MockUpstreamPgServer(self._cert_path, self._key_path, stall_cancel=True)
        mock.start()
        lease = BrokerLease(
            "job_revoke_pg",
            controller=ctrl,
            controller_actor=job_p,
            controller_request_id=prop.request_id,
        )
        lease.start_watchdog(poll_interval=0.02)
        srv = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv.start()
        try:
            sock = socket.create_connection(("127.0.0.1", srv.bound_port), timeout=5.0)
            try:
                _client_handshake(sock, lease.ocjob_token)
                sock.sendall(encode_pg_frame(b"Q", b"SELECT sleep\x00"))
                time.sleep(0.05)

                t0 = time.monotonic()
                ctrl.revoke(op, prop.request_id)
                sock.settimeout(1.5)
                eof = sock.recv(16)
                elapsed = time.monotonic() - t0
                self.assertEqual(eof, b"")
                self.assertLess(elapsed, 0.8)
            finally:
                sock.close()
        finally:
            lease.stop_watchdog()
            srv.stop()
            mock.stop()

    def test_pg_uds_0600_so_peercred_and_nonsocket_refusal(self) -> None:
        mock = _MockUpstreamPgServer(self._cert_path, self._key_path)
        mock.start()
        base = Path(self._tmpdir.name)
        uds_dir = base / "pg_uds_dir"
        uds_dir.mkdir(mode=0o700, exist_ok=True)

        # Refuse to unlink an existing regular file
        reg_file = uds_dir / "not_a_socket"
        reg_file.write_text("keep me", encoding="utf-8")
        srv_bad = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            BrokerLease("job_uds_bad"),
            uds_path=reg_file,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        with self.assertRaises(BrokerPolicyError):
            srv_bad.start()
        self.assertTrue(reg_file.exists())

        # Valid 0o600 UDS + SO_PEERCRED mismatch test
        uds_path = uds_dir / "pg.sock"
        lease = BrokerLease("job_uds_ok")
        srv_uid_mismatch = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            uds_path=uds_path,
            expected_uid=os.geteuid() + 1,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv_uid_mismatch.start()
        try:
            mode = stat.S_IMODE(os.lstat(uds_path).st_mode)
            self.assertEqual(mode, 0o600)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(str(uds_path))
                _assert_socket_closed(sock)
            finally:
                sock.close()
        finally:
            srv_uid_mismatch.stop()

        # Matching UID succeeds
        srv_ok = HostPostgresBrokerServer(
            self._make_route(mock.port),
            self._make_vault(),
            lease,
            uds_path=uds_path,
            resolver=_loopback_resolver,
            allow_test_loopback=True,
            ssl_context=self._client_ssl,
        )
        srv_ok.start()
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(str(uds_path))
                params, _ = _client_handshake(sock, lease.ocjob_token)
                self.assertEqual(params.get("server_version"), "16.4")
                sock.sendall(encode_pg_frame(b"X", b""))
            finally:
                sock.close()
        finally:
            srv_ok.stop()
            mock.stop()

    def test_gate2_r1_pg_uds_untrusted_dir_and_ipv6_loopback(self) -> None:
        # P1-2: PG UDS refuses group-writable ancestor (without chmodding), symlink, and sandbox_root
        base = Path(self._tmpdir.name)
        os.chmod(base, 0o700)
        sandbox = base / "sandbox_pg"
        sandbox.mkdir(mode=0o700)
        bad_dir = base / "pg_untrusted"
        bad_dir.mkdir(mode=0o700)
        os.chmod(bad_dir, 0o770)
        sym_dir = base / "pg_sym"
        sym_dir.symlink_to(base)
        route = self._make_route(5432)
        vault = self._make_vault()
        lease = BrokerLease("job_pg_uds_trust")
        for target in (bad_dir / "sub" / "pg.sock", sym_dir / "pg.sock", sandbox / "pg.sock"):
            srv = HostPostgresBrokerServer(
                route,
                vault,
                lease,
                uds_path=target,
                sandbox_root=sandbox,
                resolver=_loopback_resolver,
                allow_test_loopback=True,
                ssl_context=self._client_ssl,
            )
            with self.assertRaises(BrokerPolicyError):
                srv.start()
        self.assertEqual(stat.S_IMODE(os.lstat(bad_dir).st_mode), 0o770)
        self.assertFalse((bad_dir / "sub").exists())

        # P3-1: PG TCP listener supports IPv6 loopback ::1
        if socket.has_ipv6:
            srv6 = HostPostgresBrokerServer(
                route,
                vault,
                lease,
                host="::1",
                port=0,
                resolver=_loopback_resolver,
                allow_test_loopback=True,
                ssl_context=self._client_ssl,
            )
            try:
                srv6.start()
            except OSError:
                return
            try:
                self.assertGreater(srv6.bound_port, 0)
            finally:
                srv6.stop()


class TestHostSshBroker(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self._root = Path(self._tmpdir.name)
        os.chmod(self._root, 0o700)
        self._sandbox = self._root / "sandbox"
        self._sandbox.mkdir(mode=0o700)
        self._kh = self._root / "known_hosts"
        self._kh.write_text("ops.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAtest\n", encoding="utf-8")
        os.chmod(self._kh, 0o600)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _public_resolver(self, host: str, port: int, **_kw: object) -> list[object]:
        _ = host
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ip(93, 184, 216, 34), port))]

    def _make_target(self, **overrides: object) -> SshTarget:
        kwargs: dict[str, object] = {
            "user": "ops_ro",
            "host": "ops.example.com",
            "port": 2222,
            "known_hosts_path": self._kh,
        }
        kwargs.update(overrides)
        return SshTarget(**kwargs)  # type: ignore[arg-type]

    def test_ssh_presets_exact_hardened_argv_and_dns_pinning(self) -> None:
        calls: list[tuple[list[str], float, bool]] = []

        def _fake_runner(argv: list[str], *, timeout: float, shell: bool = False) -> SshRawOutput:
            calls.append((argv, timeout, shell))
            return SshRawOutput(0, b"ok\n", b"")

        broker = HostSshBroker(
            runner=_fake_runner,
            resolver=self._public_resolver,
            sandbox_root=self._sandbox,
        )
        target = self._make_target()

        broker.run_preset(target, "journalctl", {"unit": "caddy@prod.service", "lines": 50})
        broker.run_preset(target, "systemctl_status", {"unit": "postgresql.service"})
        broker.run_preset(target, "df", {"path": "/var/lib/containers"})
        broker.run_preset(target, "podman_ps", {"filter_name": "web_01"})

        self.assertEqual(len(calls), 4)
        expected_ip = _ip(93, 184, 216, 34)
        self.assertTrue(os.path.isabs(calls[0][0][0]))
        self.assertTrue(calls[0][0][0].endswith("/ssh"))
        expected_prefix = [
            calls[0][0][0],
            "-F", "/dev/null",
            "-n",
            "-T",
            "-o", "BatchMode=yes",
            "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f"UserKnownHostsFile={self._kh.resolve()}",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "ControlPersist=no",
            "-o", "ProxyCommand=none",
            "-o", "ProxyJump=none",
            "-o", "PermitLocalCommand=no",
            "-o", "Tunnel=no",
            "-o", f"HostName={expected_ip}",
            "-o", "HostKeyAlias=ops.example.com",
            "-o", "ConnectTimeout=10",
            "-p", "2222",
            "--",
            "ops_ro@ops.example.com",
        ]
        for argv, timeout, shell in calls:
            self.assertFalse(shell)
            self.assertEqual(timeout, 15.0)
            self.assertEqual(argv[:-1], expected_prefix)
            self.assertNotIn("IdentitiesOnly=yes", argv)

        self.assertEqual(calls[0][0][-1], "journalctl --no-pager -n 50 -u caddy@prod.service")
        self.assertEqual(calls[1][0][-1], "systemctl status --no-pager -- postgresql.service")
        self.assertEqual(calls[2][0][-1], "df -h -- /var/lib/containers")
        self.assertEqual(calls[3][0][-1], "podman ps --format json --filter name=web_01")

    def test_ssh_injection_and_target_validation_fail_closed(self) -> None:
        broker = HostSshBroker(
            runner=lambda *_a, **_k: SshRawOutput(0, b"", b""),
            resolver=self._public_resolver,
            sandbox_root=self._sandbox,
        )
        target = self._make_target()

        bad_preset_calls = [
            ("journalctl", {"unit": "-oProxyCommand=id"}),
            ("journalctl", {"unit": "sshd;id"}),
            ("journalctl", {"unit": "sshd$(whoami)"}),
            ("journalctl", {"unit": "sshd\nid"}),
            ("journalctl", {"unit": "sshd", "lines": 501}),
            ("systemctl_status", {"unit": "--all"}),
            ("df", {"path": "/var/../../etc/shadow"}),
            ("df", {"path": "-h"}),
            ("podman_ps", {"filter_name": "-a;id"}),
            ("unknown_preset", {}),
        ]
        for preset, params in bad_preset_calls:
            with self.subTest(preset=preset, params=params), self.assertRaises(BrokerPolicyError):
                broker.run_preset(target, preset, params)

        for bad_target in (
            self._make_target(user="-oProxyCommand=id"),
            self._make_target(host="-oProxyCommand=id"),
            self._make_target(port=0),
            self._make_target(port=70000),
        ):
            with self.subTest(target=bad_target), self.assertRaises(BrokerPolicyError):
                broker.run_preset(bad_target, "df")

        loopback_broker = HostSshBroker(
            runner=lambda *_a, **_k: SshRawOutput(0, b"", b""),
            sandbox_root=self._sandbox,
        )
        with self.assertRaises(BrokerPolicyError):
            loopback_broker.run_preset(self._make_target(host="127.0.0.1"), "df")

    def test_ssh_known_hosts_security_checks(self) -> None:
        broker = HostSshBroker(
            runner=lambda *_a, **_k: SshRawOutput(0, b"", b""),
            resolver=self._public_resolver,
            sandbox_root=self._sandbox,
        )

        sym = self._root / "kh_symlink"
        sym.symlink_to(self._kh)
        with self.assertRaises(BrokerPolicyError):
            broker.run_preset(self._make_target(known_hosts_path=sym), "df")

        hl_src = self._root / "kh_hard_src"
        hl_src.write_text("ops.example.com ssh-ed25519 AAAAtest\n", encoding="utf-8")
        os.chmod(hl_src, 0o600)
        hl_dst = self._root / "kh_hard_dst"
        os.link(hl_src, hl_dst)
        with self.assertRaises(BrokerPolicyError):
            broker.run_preset(self._make_target(known_hosts_path=hl_dst), "df")

        open_kh = self._root / "kh_open"
        open_kh.write_text("ops.example.com ssh-ed25519 AAAAtest\n", encoding="utf-8")
        os.chmod(open_kh, 0o640)
        with self.assertRaises(BrokerPolicyError):
            broker.run_preset(self._make_target(known_hosts_path=open_kh), "df")

        sb_kh = self._sandbox / "known_hosts"
        sb_kh.write_text("ops.example.com ssh-ed25519 AAAAtest\n", encoding="utf-8")
        os.chmod(sb_kh, 0o600)
        with self.assertRaises(BrokerPolicyError):
            broker.run_preset(self._make_target(known_hosts_path=sb_kh), "df")

        pct_kh = self._root / "kh_%h_expand"
        pct_kh.write_text("ops.example.com ssh-ed25519 AAAAtest\n", encoding="utf-8")
        os.chmod(pct_kh, 0o600)
        with self.assertRaises(BrokerPolicyError):
            broker.run_preset(self._make_target(known_hosts_path=pct_kh), "df")

    def _make_ssh_controller(self) -> tuple[occ.Controller, SshApprovalAdapter, list[int], occ.Principal, occ.Principal]:
        now = [100]
        op = occ.Principal(occ.Role.OPERATOR, "host_op")
        orch = occ.Principal(occ.Role.ORCHESTRATOR, "orch_1")
        job_p = occ.Principal(occ.Role.JOB, "ssh_job")
        subj = occ.Subject("worker_local", "ssh_inc_01", "ssh_job")
        adapter = SshApprovalAdapter()
        ctrl = occ.Controller(
            incarnation="fedcba9876543210fedcba9876543210",
            clock=lambda: now[0],
            lifetime=60,
            workers=[occ.Worker("worker_local", op)],
            jobs=[occ.Job(subj, orch, 16)],
            capabilities=[occ.Capability("cap_ssh_apply", occ.Operation.APPLY, "ssh_ops_host")],
            references=[occ.Reference("ref_ssh_apply", "cap_ssh_apply")],
            adapter=adapter,
        )
        ctrl._set_alias("ssh_ops_alias", "ssh_ops_host")
        return ctrl, adapter, now, op, job_p

    def test_ssh_controller_apply_once_gate_and_full_target_binding(self) -> None:
        ctrl, adapter, now, op, job_p = self._make_ssh_controller()
        captured: list[list[str]] = []

        def _runner(argv: list[str], *, timeout: float, shell: bool = False) -> SshRawOutput:
            _ = (timeout, shell)
            captured.append(argv)
            return SshRawOutput(0, b"restarted\n", b"")

        broker = HostSshBroker(
            runner=_runner,
            resolver=self._public_resolver,
            sandbox_root=self._sandbox,
        )
        target = self._make_target()
        cmd = ["systemctl", "restart", "my app;echo pwned"]

        # Reject env-var assignment smuggling and C0 control chars in custom argv
        with self.assertRaises(BrokerPolicyError):
            broker.propose_custom_command(
                target, ["LD_PRELOAD=/tmp/x.so", "id"],
                controller=ctrl, job_actor=job_p, alias="ssh_ops_alias",
                reference="ref_ssh_apply", target_id="ssh_ops_host",
            )
        with self.assertRaises(BrokerPolicyError):
            broker.propose_custom_command(
                target, ["echo", "bad\x1bseq"],
                controller=ctrl, job_actor=job_p, alias="ssh_ops_alias",
                reference="ref_ssh_apply", target_id="ssh_ops_host",
            )

        prop, digest = broker.propose_custom_command(
            target, cmd,
            controller=ctrl, job_actor=job_p, alias="ssh_ops_alias",
            reference="ref_ssh_apply", target_id="ssh_ops_host",
        )
        self.assertEqual(
            digest,
            compute_ssh_command_digest(
                target.user, target.host, target.port, cmd,
                known_hosts_path=self._kh.resolve(), allowed_cidrs=(),
            ),
        )

        # Unapproved fails closed
        with self.assertRaises(BrokerAuthError):
            broker.run_approved_command(
                target, cmd, controller=ctrl, adapter=adapter, job_actor=job_p, request_id=prop.request_id
            )

        # Approve & execute
        view = ctrl.view(op, prop.request_id)
        self.assertEqual(view.payload.pin.revision, digest)
        ctrl.decide(op, prop.request_id, view.payload.revision, view.digest, occ.Decision.APPROVE)
        res = broker.run_approved_command(
            target, cmd, controller=ctrl, adapter=adapter, job_actor=job_p, request_id=prop.request_id
        )
        self.assertEqual(res.stdout, b"restarted\n")
        self.assertEqual(captured[0][-1], " ".join(shlex.quote(tok) for tok in cmd))

        # Replay fails closed
        with self.assertRaises(BrokerAuthError):
            broker.run_approved_command(
                target, cmd, controller=ctrl, adapter=adapter, job_actor=job_p, request_id=prop.request_id
            )

        # Tampering known_hosts_path or allowed_cidrs after approval fails closed
        alt_kh = self._root / "alt_known_hosts"
        alt_kh.write_text("ops.example.com ssh-ed25519 AAAAalt\n", encoding="utf-8")
        os.chmod(alt_kh, 0o600)
        prop2, _ = broker.propose_custom_command(
            target, ["systemctl", "reload", "caddy"],
            controller=ctrl, job_actor=job_p, alias="ssh_ops_alias",
            reference="ref_ssh_apply", target_id="ssh_ops_host",
        )
        v2 = ctrl.view(op, prop2.request_id)
        ctrl.decide(op, prop2.request_id, v2.payload.revision, v2.digest, occ.Decision.APPROVE)
        with self.assertRaises(BrokerAuthError):
            broker.run_approved_command(
                self._make_target(known_hosts_path=alt_kh),
                ["systemctl", "reload", "caddy"],
                controller=ctrl, adapter=adapter, job_actor=job_p, request_id=prop2.request_id,
            )

        # Expired proposal fails closed
        prop3, _ = broker.propose_custom_command(
            target, ["systemctl", "reload", "nginx"],
            controller=ctrl, job_actor=job_p, alias="ssh_ops_alias",
            reference="ref_ssh_apply", target_id="ssh_ops_host",
        )
        v3 = ctrl.view(op, prop3.request_id)
        ctrl.decide(op, prop3.request_id, v3.payload.revision, v3.digest, occ.Decision.APPROVE)
        now[0] += 120
        with self.assertRaises(BrokerAuthError):
            broker.run_approved_command(
                target, ["systemctl", "reload", "nginx"],
                controller=ctrl, adapter=adapter, job_actor=job_p, request_id=prop3.request_id,
            )

        # Revoked proposal fails closed
        prop4, _ = broker.propose_custom_command(
            target, ["systemctl", "reload", "haproxy"],
            controller=ctrl, job_actor=job_p, alias="ssh_ops_alias",
            reference="ref_ssh_apply", target_id="ssh_ops_host",
        )
        v4 = ctrl.view(op, prop4.request_id)
        ctrl.decide(op, prop4.request_id, v4.payload.revision, v4.digest, occ.Decision.APPROVE)
        ctrl.revoke(op, prop4.request_id)
        with self.assertRaises(BrokerAuthError):
            broker.run_approved_command(
                target, ["systemctl", "reload", "haproxy"],
                controller=ctrl, adapter=adapter, job_actor=job_p, request_id=prop4.request_id,
            )

    def test_ssh_streaming_subprocess_cap_timeout_revoke_and_stderr_canary(self) -> None:
        secret = "SSH_CANARY_HOST_SECRET_774411/+"

        # Bounded streaming cap kills huge output producer without buffering in RAM
        res = _run_streaming_subprocess(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'Z' * 500000)"],
            timeout=5.0,
            max_output_bytes=64,
            canary_secrets=(secret,),
        )
        self.assertTrue(res.truncated)
        self.assertEqual(len(res.stdout), 64)

        # Timeout wraps cleanly into BrokerError without leaking stdout
        with self.assertRaises(BrokerError):
            _run_streaming_subprocess(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout=0.25,
                max_output_bytes=1024,
                canary_secrets=(secret,),
            )

        # Lease revocation kills in-flight subprocess in <1s
        lease = BrokerLease("job_ssh_revoke")
        def _revoke_soon() -> None:
            time.sleep(0.1)
            lease.revoke()

        threading.Thread(target=_revoke_soon, daemon=True).start()
        t0 = time.monotonic()
        with self.assertRaises(BrokerAuthError):
            _run_streaming_subprocess(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout=5.0,
                max_output_bytes=1024,
                canary_secrets=(secret,),
                lease=lease,
            )
        self.assertLess(time.monotonic() - t0, 0.9)

        # Stderr canary abort on real streaming runner
        with self.assertRaises(CanaryLeakError):
            _run_streaming_subprocess(
                [sys.executable, "-c", f"import sys; sys.stderr.write('err {secret}\\n')"],
                timeout=5.0,
                max_output_bytes=1024,
                canary_secrets=(secret,),
            )

        # Stdout encoded canary variants via injectable runner
        target = self._make_target()
        for leaked_bytes in (
            secret.encode("utf-8"),
            quote(secret, safe="").encode("ascii"),
            base64.b64encode(secret.encode("utf-8")).rstrip(b"="),
        ):
            leak_broker = HostSshBroker(
                runner=lambda *_a, _b=leaked_bytes, **_k: SshRawOutput(0, b"", b"err " + _b + b" end"),
                canary_secrets=[secret],
                resolver=self._public_resolver,
                sandbox_root=self._sandbox,
            )
            with self.subTest(leak=leaked_bytes[:12]), self.assertRaises(CanaryLeakError):
                leak_broker.run_preset(target, "df")

    def test_gate2_r1_ssh_identity_file_env_and_overflow_tail_canary(self) -> None:
        # P2-3: Pinned identity_file emits IdentitiesOnly=yes + IdentityFile and binds digest
        pub_key = self._root / "ops_ed25519.pub"
        pub_key.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey ops@test\n", encoding="utf-8")
        os.chmod(pub_key, 0o600)

        captured: list[list[str]] = []
        broker = HostSshBroker(
            runner=lambda argv, **_k: (captured.append(argv), SshRawOutput(0, b"ok", b""))[1],
            resolver=self._public_resolver,
            sandbox_root=self._sandbox,
        )
        pinned = self._make_target(identity_file=pub_key)
        broker.run_preset(pinned, "df")
        self.assertIn("IdentitiesOnly=yes", captured[-1])
        self.assertIn(f"IdentityFile={pub_key.resolve()}", captured[-1])

        d_no_id = compute_ssh_command_digest(
            "ops_ro", "ops.example.com", 2222, ["df", "-h"], known_hosts_path=self._kh.resolve()
        )
        d_with_id = compute_ssh_command_digest(
            "ops_ro",
            "ops.example.com",
            2222,
            ["df", "-h"],
            known_hosts_path=self._kh.resolve(),
            identity_file=pub_key.resolve(),
        )
        self.assertNotEqual(d_no_id, d_with_id)

        # Untrusted identity_file (group-readable or inside sandbox) fails closed
        bad_pub = self._root / "bad_id.pub"
        bad_pub.write_text("ssh-ed25519 AAAATest\n", encoding="utf-8")
        os.chmod(bad_pub, 0o640)
        with self.assertRaises(BrokerPolicyError):
            broker.run_preset(self._make_target(identity_file=bad_pub), "df")

        # P2-3: Minimal sanitized env strips arbitrary host env vars & SSH_ASKPASS while keeping SSH_AUTH_SOCK
        old_probe = os.environ.get("OC_HOST_SECRET_PROBE")
        old_askpass = os.environ.get("SSH_ASKPASS")
        old_sock = os.environ.get("SSH_AUTH_SOCK")
        os.environ["OC_HOST_SECRET_PROBE"] = "DO_NOT_LEAK_ME"
        os.environ["SSH_ASKPASS"] = "/bin/false"
        os.environ["SSH_AUTH_SOCK"] = "/run/user/1000/keeper-agent.sock"
        try:
            env_res = _run_streaming_subprocess(
                [sys.executable, "-c", "import json, os; print(json.dumps(dict(os.environ)))"],
                timeout=5.0,
                max_output_bytes=8192,
                canary_secrets=(),
            )
            child_env = json.loads(env_res.stdout.decode("utf-8"))
            self.assertNotIn("OC_HOST_SECRET_PROBE", child_env)
            self.assertNotIn("SSH_ASKPASS", child_env)
            self.assertEqual(child_env.get("SSH_ASKPASS_REQUIRE"), "never")
            self.assertEqual(child_env.get("SSH_AUTH_SOCK"), "/run/user/1000/keeper-agent.sock")
        finally:
            for k, v in (
                ("OC_HOST_SECRET_PROBE", old_probe),
                ("SSH_ASKPASS", old_askpass),
                ("SSH_AUTH_SOCK", old_sock),
            ):
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

        # P2-3: Overflow on stdout still finishes/scans buffered short canary tail in stderr
        secret = "SSH_OVERFLOW_TAIL_CANARY_882211"
        script = (
            "import sys, time; "
            f"sys.stderr.buffer.write({secret.encode('utf-8')!r}); sys.stderr.buffer.flush(); "
            "time.sleep(0.05); "
            "sys.stdout.buffer.write(b'A' * 65536); sys.stdout.buffer.flush()"
        )
        with self.assertRaises(CanaryLeakError):
            _run_streaming_subprocess(
                [sys.executable, "-c", script],
                timeout=5.0,
                max_output_bytes=64,
                canary_secrets=(secret,),
            )


if __name__ == "__main__":
    unittest.main()
