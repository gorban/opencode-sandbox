"""Per-job message-framed Host Postgres v3 wire proxy for PRD L1 (Path A).

Pure Python standard library only. Terminates sandbox Postgres connections on a
pod-local TCP or 0o700 UDS listener, authenticates the disposable per-job
ocjob_ token, connects upstream over strict TLS-only verify-full, pins upstream
role/database/options, synthesizes job-local BackendKeyData, scrubs
ParameterStatus/ErrorResponse/NoticeResponse frames, and streams large DataRow
and CopyData frames without full buffering.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import threading
from typing import Any
from urllib.parse import quote, quote_plus

from oc_broker_common import (
    BrokerAuthError,
    BrokerError,
    BrokerLease,
    BrokerPolicyError,
    CanaryLeakError,
    HostVaultMemory,
    MIN_SECRET_LEN,
    OverlapCanaryScanner,
    PgUpstreamCancelTarget,
    build_strict_tls_context,
    connect_tcp_pinned_ip,
    resolve_and_validate_ip,
    validate_allowed_cidrs,
)

PG_PROTOCOL_V3 = 196608
PG_SSL_REQUEST = 80877103
PG_GSSENC_REQUEST = 80877104
PG_CANCEL_REQUEST = 80877102

MAX_CONCURRENT_CONNS = 16
DEFAULT_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_IO_TIMEOUT = 30.0
MAX_STARTUP_BYTES = 16_384
MAX_CONTROL_FRAME_BYTES = 65_536
MAX_NEGOTIATION_RETRIES = 3
STREAM_CHUNK_BYTES = 16_384
MAX_SCRAM_ITERATIONS = 1_000_000

SAFE_PARAMETER_STATUS_KEYS = frozenset(
    {
        "client_encoding",
        "server_encoding",
        "standard_conforming_strings",
        "DateStyle",
        "TimeZone",
        "server_version",
        "integer_datetimes",
        "IntervalStyle",
        "is_superuser",
        "default_transaction_read_only",
    }
)


@dataclass(frozen=True, slots=True)
class PgBrokerRoute:
    """Host-only Postgres proxy route definition."""

    route_id: str
    upstream_host: str
    upstream_port: int
    upstream_database: str
    upstream_user: str
    secret_ref: str
    access_mode: str = "ro"
    allowed_cidrs: tuple[str, ...] = ()
    pair_distinct_user: str | None = None
    pair_distinct_secret_ref: str | None = None


def validate_pg_route(route: PgBrokerRoute, vault: HostVaultMemory) -> None:
    """Validate route coordinates, vault presence, and optional RO/RW distinctness."""
    if not isinstance(route, PgBrokerRoute):
        raise BrokerPolicyError("route must be a PgBrokerRoute")
    if not route.route_id.strip() or not route.upstream_host.strip():
        raise BrokerPolicyError("route_id and upstream_host must be non-empty")
    if type(route.upstream_port) is not int or not (1 <= route.upstream_port <= 65535):
        raise BrokerPolicyError("upstream_port must be an integer 1..65535")
    if not route.upstream_database.strip() or not route.upstream_user.strip():
        raise BrokerPolicyError("upstream_database and upstream_user must be non-empty")
    if route.access_mode not in ("ro", "rw"):
        raise BrokerPolicyError(f"Unsupported access_mode: {route.access_mode!r}")
    validate_allowed_cidrs(route.allowed_cidrs, context=f"pg:{route.route_id}.allowed_cidrs")
    password = vault.get(route.secret_ref)
    _verify_pair_distinctness(route, vault, password)


def _verify_pair_distinctness(
    route: PgBrokerRoute, vault: HostVaultMemory, password: str
) -> None:
    has_user = route.pair_distinct_user is not None
    has_ref = route.pair_distinct_secret_ref is not None
    if not has_user and not has_ref:
        return
    if not (has_user and has_ref):
        raise BrokerPolicyError(
            "pair_distinct_user and pair_distinct_secret_ref must both be provided"
        )
    assert route.pair_distinct_user is not None
    assert route.pair_distinct_secret_ref is not None
    pair_password = vault.get(route.pair_distinct_secret_ref)
    HostVaultMemory.assert_distinct_pg_credentials(
        route.upstream_user,
        password,
        route.pair_distinct_user,
        pair_password,
    )


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket or raise EOFError."""
    if n == 0:
        return b""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("Unexpected EOF on Postgres stream")
        buf.extend(chunk)
    return bytes(buf)


def encode_pg_frame(msg_type: bytes, body: bytes) -> bytes:
    """Encode a Postgres v3 message frame with big-endian uint32 length."""
    if len(msg_type) != 1:
        raise ValueError("msg_type must be a single byte")
    return msg_type + struct.pack("!I", len(body) + 4) + body


def encode_pg_error_response(
    sqlstate: str, message: str, *, severity: str = "FATAL"
) -> bytes:
    """Encode a Postgres v3 ErrorResponse ('E') frame."""
    parts = [
        b"S" + severity.encode("utf-8") + b"\x00",
        b"V" + severity.encode("utf-8") + b"\x00",
        b"C" + sqlstate.encode("ascii") + b"\x00",
        b"M" + message.encode("utf-8") + b"\x00",
        b"\x00",
    ]
    return encode_pg_frame(b"E", b"".join(parts))


def encode_pg_startup(user: str, database: str, options: str = "") -> bytes:
    """Encode a Postgres v3.0 StartupMessage pinned strictly to host-chosen params."""
    params = [b"user", user.encode("utf-8"), b"database", database.encode("utf-8")]
    if options:
        params.extend([b"options", options.encode("utf-8")])
    body = struct.pack("!I", PG_PROTOCOL_V3) + b"\x00".join(params) + b"\x00\x00"
    return struct.pack("!I", len(body) + 4) + body


def read_pg_frame_header(sock: socket.socket) -> tuple[bytes, int]:
    """Read 1-byte type and 4-byte uint32 length, rejecting length < 4."""
    header = recv_exact(sock, 5)
    msg_type = header[:1]
    length = struct.unpack("!I", header[1:5])[0]
    if length < 4:
        raise BrokerPolicyError(f"Invalid Postgres v3 frame length: {length}")
    return msg_type, length - 4


def read_pg_control_frame(
    sock: socket.socket, *, max_body: int = MAX_CONTROL_FRAME_BYTES
) -> tuple[bytes, bytes]:
    """Read a bounded Postgres v3 control frame."""
    msg_type, body_len = read_pg_frame_header(sock)
    if body_len > max_body:
        raise BrokerPolicyError(
            f"Postgres control frame {msg_type!r} exceeds {max_body} bytes"
        )
    return msg_type, recv_exact(sock, body_len)


def _require_strict_tls_context(ssl_context: ssl.SSLContext | None) -> ssl.SSLContext:
    ctx = ssl_context if ssl_context is not None else build_strict_tls_context()
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise BrokerPolicyError("Upstream Postgres TLS context must enforce verify-full")
    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
        raise BrokerPolicyError("Upstream Postgres TLS context must require TLS >= 1.2")
    return ctx


def pg_connect_strict_tls_only(
    ip: str,
    port: int,
    *,
    server_hostname: str,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
) -> ssl.SSLSocket:
    """Connect TCP to pinned IP, negotiate Postgres SSLRequest, and abort if refused."""
    ctx = _require_strict_tls_context(ssl_context)
    raw_sock = connect_tcp_pinned_ip(ip, port, timeout=timeout)
    try:
        raw_sock.sendall(struct.pack("!II", 8, PG_SSL_REQUEST))
        reply = recv_exact(raw_sock, 1)
        if reply != b"S":
            raise BrokerPolicyError("Upstream Postgres refused TLS (cleartext downgrade blocked)")
        return ctx.wrap_socket(raw_sock, server_hostname=server_hostname)
    except Exception:
        raw_sock.close()
        raise


def send_upstream_tls_cancel(
    target: PgUpstreamCancelTarget,
    *,
    timeout: float = 5.0,
) -> None:
    """Send a Postgres CancelRequest over strict TLS-only verify-full to pinned IP."""
    sock = pg_connect_strict_tls_only(
        target.ip,
        target.port,
        server_hostname=target.server_hostname,
        ssl_context=target.ssl_context,
        timeout=timeout,
    )
    try:
        frame = struct.pack("!IIII", 16, PG_CANCEL_REQUEST, target.real_pid, target.real_key)
        sock.sendall(frame)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _parse_scram_kv(message: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in message.split(","):
        if "=" not in part:
            raise BrokerPolicyError("Malformed SCRAM-SHA-256 attribute")
        k, v = part.split("=", 1)
        if k in out:
            raise BrokerPolicyError("Duplicate SCRAM-SHA-256 attribute")
        out[k] = v
    return out


def _compute_scram_exchange(
    client_first_bare: str, server_first: str, password: str, c_nonce: str
) -> tuple[str, str]:
    attrs = _parse_scram_kv(server_first)
    s_nonce = attrs.get("r", "")
    salt_b64 = attrs.get("s", "")
    iter_str = attrs.get("i", "")
    if not s_nonce.startswith(c_nonce) or len(s_nonce) <= len(c_nonce):
        raise BrokerAuthError("Invalid SCRAM-SHA-256 server nonce")
    try:
        iterations = int(iter_str)
        salt = base64.b64decode(salt_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise BrokerAuthError("Invalid SCRAM-SHA-256 salt or iteration count") from exc
    if not (1 <= iterations <= MAX_SCRAM_ITERATIONS):
        raise BrokerPolicyError("SCRAM-SHA-256 iteration count out of bounds")

    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    client_final_no_proof = f"c=biws,r={s_nonce}"
    auth_msg = f"{client_first_bare},{server_first},{client_final_no_proof}".encode("utf-8")
    client_sig = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
    proof_b64 = base64.b64encode(proof).decode("ascii")

    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    expected_sig = hmac.new(server_key, auth_msg, hashlib.sha256).digest()
    expected_v = base64.b64encode(expected_sig).decode("ascii")
    return f"{client_final_no_proof},p={proof_b64}", expected_v


def _handle_scram_sha256(sock: socket.socket, mech_bytes: bytes, password: str) -> None:
    mechs = [m.decode("ascii", errors="ignore") for m in mech_bytes.split(b"\x00") if m]
    if "SCRAM-SHA-256" not in mechs:
        raise BrokerPolicyError("Upstream SASL does not offer SCRAM-SHA-256")

    c_nonce = base64.b64encode(secrets.token_bytes(18)).decode("ascii")
    client_first_bare = f"n=,r={c_nonce}"
    client_first = f"n,,{client_first_bare}".encode("utf-8")
    init_body = b"SCRAM-SHA-256\x00" + struct.pack("!I", len(client_first)) + client_first
    sock.sendall(encode_pg_frame(b"p", init_body))

    msg_type, body = read_pg_control_frame(sock)
    if msg_type != b"R" or len(body) < 4 or struct.unpack("!I", body[:4])[0] != 11:
        raise BrokerAuthError("Expected AuthenticationSASLContinue from upstream")

    client_final, expected_v = _compute_scram_exchange(
        client_first_bare, body[4:].decode("utf-8"), password, c_nonce
    )
    sock.sendall(encode_pg_frame(b"p", client_final.encode("utf-8")))

    msg_type, body = read_pg_control_frame(sock)
    if msg_type != b"R" or len(body) < 4 or struct.unpack("!I", body[:4])[0] != 12:
        raise BrokerAuthError("Expected AuthenticationSASLFinal from upstream")

    final_attrs = _parse_scram_kv(body[4:].decode("utf-8"))
    server_v = final_attrs.get("v", "")
    if "e" in final_attrs or not hmac.compare_digest(server_v, expected_v):
        raise BrokerAuthError("SCRAM-SHA-256 server signature verification failed")


def _send_md5_password(sock: socket.socket, user: str, password: str, salt: bytes) -> None:
    if len(salt) != 4:
        raise BrokerPolicyError("Invalid MD5 salt length from upstream")
    inner = hashlib.md5((password + user).encode("utf-8")).hexdigest().encode("ascii")
    outer = hashlib.md5(inner + salt).hexdigest()
    sock.sendall(encode_pg_frame(b"p", f"md5{outer}\x00".encode("ascii")))


def authenticate_upstream_pg(
    up_sock: socket.socket,
    route: PgBrokerRoute,
    password: str,
) -> None:
    """Send pinned StartupMessage and complete upstream Postgres authentication."""
    options = "-c default_transaction_read_only=on" if route.access_mode == "ro" else ""
    up_sock.sendall(encode_pg_startup(route.upstream_user, route.upstream_database, options))

    while True:
        msg_type, body = read_pg_control_frame(up_sock)
        if msg_type == b"E":
            raise BrokerAuthError("Upstream Postgres rejected authentication")
        if msg_type != b"R" or len(body) < 4:
            raise BrokerPolicyError("Unexpected upstream frame during authentication")
        code = struct.unpack("!I", body[:4])[0]
        if code == 0:
            return
        if code == 3:
            up_sock.sendall(encode_pg_frame(b"p", password.encode("utf-8") + b"\x00"))
        elif code == 5:
            _send_md5_password(up_sock, route.upstream_user, password, body[4:])
        elif code == 10:
            _handle_scram_sha256(up_sock, body[4:], password)
        else:
            raise BrokerPolicyError(f"Unsupported upstream Postgres auth code: {code}")


def _build_redaction_tokens(
    upstream_host: str, upstream_ip: str, upstream_user: str, secrets_list: tuple[str, ...]
) -> tuple[str, ...]:
    tokens: set[str] = set()
    for val in (upstream_host, upstream_ip, upstream_user):
        if val:
            tokens.add(val)
    for sec in secrets_list:
        if len(sec) < MIN_SECRET_LEN:
            continue
        raw = sec.encode("utf-8")
        tokens.add(sec)
        tokens.add(quote(sec, safe=""))
        tokens.add(quote_plus(sec))
        tokens.add(base64.b64encode(raw).rstrip(b"=").decode("ascii"))
        tokens.add(base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"))
    return tuple(sorted(tokens, key=len, reverse=True))


def scrub_text(text: str, redactions: tuple[str, ...]) -> str:
    """Replace sensitive upstream tokens with [redacted]."""
    out = text
    for tok in redactions:
        if tok in out:
            out = out.replace(tok, "[redacted]")
    return out


def scrub_error_or_notice_body(body: bytes, redactions: tuple[str, ...]) -> bytes:
    """Parse ErrorResponse/NoticeResponse fields, scrub values, and re-encode."""
    out: list[bytes] = []
    pos = 0
    end = len(body)
    while pos < end:
        code = body[pos : pos + 1]
        if code == b"\x00":
            out.append(b"\x00")
            break
        nul = body.find(b"\x00", pos + 1)
        if nul == -1:
            raise BrokerPolicyError("Malformed ErrorResponse/NoticeResponse field")
        val = body[pos + 1 : nul].decode("utf-8", errors="replace")
        clean_val = scrub_text(val, redactions)
        out.append(code + clean_val.encode("utf-8") + b"\x00")
        pos = nul + 1
    if not out or out[-1] != b"\x00":
        out.append(b"\x00")
    return b"".join(out)


def filter_parameter_status_body(
    body: bytes, redactions: tuple[str, ...]
) -> bytes | None:
    """Allow only safe libpq ParameterStatus keys, scrubbing values."""
    parts = body.split(b"\x00")
    if len(parts) < 2:
        return None
    key = parts[0].decode("utf-8", errors="replace")
    if key not in SAFE_PARAMETER_STATUS_KEYS:
        return None
    val = parts[1].decode("utf-8", errors="replace")
    clean_val = scrub_text(val, redactions)
    return key.encode("utf-8") + b"\x00" + clean_val.encode("utf-8") + b"\x00"


def _read_startup_header(sock: socket.socket) -> tuple[int, int]:
    length = struct.unpack("!I", recv_exact(sock, 4))[0]
    if length < 8 or length > MAX_STARTUP_BYTES:
        raise BrokerPolicyError(f"Invalid Postgres startup packet length: {length}")
    code = struct.unpack("!I", recv_exact(sock, 4))[0]
    return length, code


def _read_client_initial_packet(sock: socket.socket) -> tuple[int, bytes]:
    for _ in range(MAX_NEGOTIATION_RETRIES + 1):
        length, code = _read_startup_header(sock)
        if code in (PG_SSL_REQUEST, PG_GSSENC_REQUEST):
            if length != 8:
                raise BrokerPolicyError("SSLRequest/GSSENCRequest must be exactly 8 bytes")
            sock.sendall(b"N")
            continue
        if code == PG_CANCEL_REQUEST:
            if length != 16:
                raise BrokerPolicyError("CancelRequest must be exactly 16 bytes")
            return PG_CANCEL_REQUEST, recv_exact(sock, 8)
        if code == PG_PROTOCOL_V3:
            return PG_PROTOCOL_V3, recv_exact(sock, length - 8)
        raise BrokerPolicyError(f"Unsupported Postgres startup code: {code}")
    raise BrokerPolicyError("Exceeded maximum Postgres SSL/GSS negotiation retries")


def _authenticate_client(client_sock: socket.socket, lease: BrokerLease) -> bool:
    if not lease.is_active():
        client_sock.sendall(encode_pg_error_response("28000", "lease revoked"))
        return False
    client_sock.sendall(encode_pg_frame(b"R", struct.pack("!I", 3)))
    msg_type, body = read_pg_control_frame(client_sock, max_body=MAX_STARTUP_BYTES)
    if msg_type != b"p" or not body.endswith(b"\x00"):
        client_sock.sendall(encode_pg_error_response("28P01", "authentication failed"))
        return False
    raw_token = body[:-1]
    if b"\x00" in raw_token:
        client_sock.sendall(encode_pg_error_response("28P01", "authentication failed"))
        return False
    candidate = raw_token.decode("utf-8", errors="replace")
    if not lease.verify_token(candidate):
        client_sock.sendall(encode_pg_error_response("28P01", "authentication failed"))
        return False
    if not lease.is_active():
        client_sock.sendall(encode_pg_error_response("28000", "lease revoked"))
        return False
    return True


def _stream_frame_with_canary(
    src: socket.socket,
    dst: socket.socket,
    msg_type: bytes,
    body_len: int,
    secrets_list: tuple[str, ...],
) -> None:
    scanner = OverlapCanaryScanner(secrets_list)
    dst.sendall(msg_type + struct.pack("!I", body_len + 4))
    remaining = body_len
    while remaining > 0:
        chunk = recv_exact(src, min(remaining, STREAM_CHUNK_BYTES))
        remaining -= len(chunk)
        emitted = scanner.feed(chunk)
        if emitted:
            dst.sendall(emitted)
    tail = scanner.finish()
    if tail:
        dst.sendall(tail)


def _stream_frame_passthrough(
    src: socket.socket, dst: socket.socket, msg_type: bytes, body_len: int
) -> None:
    dst.sendall(msg_type + struct.pack("!I", body_len + 4))
    remaining = body_len
    while remaining > 0:
        chunk = recv_exact(src, min(remaining, STREAM_CHUNK_BYTES))
        remaining -= len(chunk)
        dst.sendall(chunk)


@dataclass
class _RelayContext:
    lease: BrokerLease
    route: PgBrokerRoute
    upstream_ip: str
    ssl_context: ssl.SSLContext | None
    redactions: tuple[str, ...]
    secrets_list: tuple[str, ...]
    cancel_pair: tuple[int, int] | None = None
    revoke_cb: Callable[[], None] | None = None


def _handle_backend_key_data(
    up_sock: socket.socket,
    client_sock: socket.socket,
    body_len: int,
    ctx: _RelayContext,
) -> None:
    if body_len != 8:
        raise BrokerPolicyError("Invalid BackendKeyData frame length")
    real_pid, real_key = struct.unpack("!II", recv_exact(up_sock, 8))
    target = PgUpstreamCancelTarget(
        ip=ctx.upstream_ip,
        port=ctx.route.upstream_port,
        server_hostname=ctx.route.upstream_host,
        real_pid=real_pid,
        real_key=real_key,
        ssl_context=ctx.ssl_context,
    )
    local_pid, local_key = ctx.lease.register_pg_cancel(target)
    ctx.cancel_pair = (local_pid, local_key)

    fired = threading.Event()

    def _on_revoke() -> None:
        if not fired.is_set():
            fired.set()
            send_upstream_tls_cancel(target)

    ctx.revoke_cb = _on_revoke
    ctx.lease.add_revoke_callback(_on_revoke)
    client_sock.sendall(encode_pg_frame(b"K", struct.pack("!II", local_pid, local_key)))


def _relay_single_upstream_frame(
    up_sock: socket.socket, client_sock: socket.socket, ctx: _RelayContext
) -> None:
    msg_type, body_len = read_pg_frame_header(up_sock)
    if msg_type == b"K":
        _handle_backend_key_data(up_sock, client_sock, body_len, ctx)
        return
    if msg_type in (b"D", b"d"):
        _stream_frame_with_canary(up_sock, client_sock, msg_type, body_len, ctx.secrets_list)
        return
    if body_len > MAX_CONTROL_FRAME_BYTES:
        raise BrokerPolicyError(f"Upstream control frame {msg_type!r} exceeds limit")
    body = recv_exact(up_sock, body_len)
    if msg_type == b"S":
        filtered = filter_parameter_status_body(body, ctx.redactions)
        if filtered is not None:
            client_sock.sendall(encode_pg_frame(b"S", filtered))
        return
    if msg_type in (b"E", b"N"):
        scrubbed = scrub_error_or_notice_body(body, ctx.redactions)
        OverlapCanaryScanner(ctx.secrets_list).scan_bytes(scrubbed)
        client_sock.sendall(encode_pg_frame(msg_type, scrubbed))
        return
    OverlapCanaryScanner(ctx.secrets_list).scan_bytes(body)
    client_sock.sendall(encode_pg_frame(msg_type, body))


def _relay_client_to_upstream(
    client_sock: socket.socket, up_sock: socket.socket, stop_ev: threading.Event
) -> None:
    try:
        while not stop_ev.is_set():
            msg_type, body_len = read_pg_frame_header(client_sock)
            if msg_type == b"d":
                _stream_frame_passthrough(client_sock, up_sock, msg_type, body_len)
                continue
            if body_len > MAX_CONTROL_FRAME_BYTES:
                raise BrokerPolicyError(f"Client control frame {msg_type!r} exceeds limit")
            body = recv_exact(client_sock, body_len)
            up_sock.sendall(encode_pg_frame(msg_type, body))
            if msg_type == b"X":
                return
    except (EOFError, OSError, BrokerError):
        pass
    finally:
        stop_ev.set()
        _shutdown_quiet(up_sock)


def _shutdown_quiet(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _close_quiet(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


class HostPostgresBrokerServer:
    """Bounded per-job message-framed Postgres v3 proxy listener (TCP or 0o700 UDS)."""

    def __init__(
        self,
        route: PgBrokerRoute,
        vault: HostVaultMemory,
        lease: BrokerLease,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        uds_path: Path | None = None,
        max_concurrent_conns: int = MAX_CONCURRENT_CONNS,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        io_timeout: float = DEFAULT_IO_TIMEOUT,
        resolver: Callable[..., list[Any]] | None = None,
        allow_test_loopback: bool = False,
        ssl_context: ssl.SSLContext | None = None,
    ):
        validate_pg_route(route, vault)
        if type(max_concurrent_conns) is not int or max_concurrent_conns < 1:
            raise BrokerPolicyError("max_concurrent_conns must be >= 1")
        self.route = route
        self._vault = vault
        self.lease = lease
        self._host = host
        self._port = port
        self._uds_path = uds_path
        self._sem = threading.BoundedSemaphore(max_concurrent_conns)
        self._handshake_timeout = handshake_timeout
        self._io_timeout = io_timeout
        self._resolver = resolver
        self._allow_test_loopback = allow_test_loopback
        self._ssl_context = ssl_context

        self._listen_sock: socket.socket | None = None
        self._stop_ev = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._bound_port: int | None = None

    @property
    def bound_port(self) -> int:
        if self._bound_port is None:
            raise RuntimeError("Server is not listening on TCP")
        return self._bound_port

    def start(self) -> None:
        if self._listen_sock is not None:
            return
        self._stop_ev.clear()
        if self._uds_path is not None:
            self._listen_sock = self._bind_uds(self._uds_path)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self._host, self._port))
            sock.listen(32)
            sock.settimeout(0.2)
            self._listen_sock = sock
            self._bound_port = int(sock.getsockname()[1])

        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def _bind_uds(self, uds_path: Path) -> socket.socket:
        uds_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(uds_path.parent, 0o700)
        if uds_path.exists():
            uds_path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(uds_path))
        os.chmod(uds_path, 0o700)
        sock.listen(32)
        sock.settimeout(0.2)
        return sock

    def stop(self) -> None:
        self._stop_ev.set()
        if self._listen_sock is not None:
            _close_quiet(self._listen_sock)
            self._listen_sock = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None
        if self._uds_path is not None and self._uds_path.exists():
            try:
                self._uds_path.unlink()
            except OSError:
                pass

    def __enter__(self) -> HostPostgresBrokerServer:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def _accept_loop(self) -> None:
        assert self._listen_sock is not None
        while not self._stop_ev.is_set():
            try:
                client_sock, _ = self._listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._sem.acquire(blocking=False):
                _close_quiet(client_sock)
                continue
            t = threading.Thread(target=self._serve_client, args=(client_sock,), daemon=True)
            t.start()

    def _serve_client(self, client_sock: socket.socket) -> None:
        try:
            self._handle_connection(client_sock)
        except (EOFError, OSError, BrokerError, CanaryLeakError):
            pass
        finally:
            _close_quiet(client_sock)
            self._sem.release()

    def _handle_cancel_request(self, payload: bytes) -> None:
        local_pid, local_key = struct.unpack("!II", payload)
        target = self.lease.lookup_pg_cancel(local_pid, local_key)
        if target is not None:
            send_upstream_tls_cancel(target, timeout=self._handshake_timeout)

    def _handle_connection(self, client_sock: socket.socket) -> None:
        client_sock.settimeout(self._handshake_timeout)
        code, payload = _read_client_initial_packet(client_sock)
        if code == PG_CANCEL_REQUEST:
            self._handle_cancel_request(payload)
            return
        if not _authenticate_client(client_sock, self.lease):
            return

        password = self._vault.get(self.route.secret_ref)
        upstream_ip = resolve_and_validate_ip(
            self.route.upstream_host,
            self.route.allowed_cidrs,
            port=self.route.upstream_port,
            resolver=self._resolver,
            allow_test_loopback=self._allow_test_loopback,
        )
        up_sock = pg_connect_strict_tls_only(
            upstream_ip,
            self.route.upstream_port,
            server_hostname=self.route.upstream_host,
            ssl_context=self._ssl_context,
            timeout=self._handshake_timeout,
        )
        self._bridge_authenticated(client_sock, up_sock, upstream_ip, password)

    def _bridge_authenticated(
        self,
        client_sock: socket.socket,
        up_sock: ssl.SSLSocket,
        upstream_ip: str,
        password: str,
    ) -> None:
        secrets_list = (password,)
        redactions = _build_redaction_tokens(
            self.route.upstream_host, upstream_ip, self.route.upstream_user, secrets_list
        )
        ctx = _RelayContext(
            lease=self.lease,
            route=self.route,
            upstream_ip=upstream_ip,
            ssl_context=self._ssl_context,
            redactions=redactions,
            secrets_list=secrets_list,
        )
        self.lease.register_stream(client_sock)
        self.lease.register_stream(up_sock)
        try:
            authenticate_upstream_pg(up_sock, self.route, password)
            client_sock.sendall(encode_pg_frame(b"R", struct.pack("!I", 0)))
            client_sock.settimeout(self._io_timeout)
            up_sock.settimeout(self._io_timeout)
            self._run_bidirectional_relay(client_sock, up_sock, ctx)
        finally:
            self._cleanup_relay(client_sock, up_sock, ctx)

    def _run_bidirectional_relay(
        self,
        client_sock: socket.socket,
        up_sock: ssl.SSLSocket,
        ctx: _RelayContext,
    ) -> None:
        stop_ev = threading.Event()
        c2u = threading.Thread(
            target=_relay_client_to_upstream,
            args=(client_sock, up_sock, stop_ev),
            daemon=True,
        )
        c2u.start()
        try:
            while not stop_ev.is_set():
                _relay_single_upstream_frame(up_sock, client_sock, ctx)
        except (EOFError, OSError, BrokerError, CanaryLeakError):
            pass
        finally:
            stop_ev.set()
            _shutdown_quiet(client_sock)
            _shutdown_quiet(up_sock)
            c2u.join(timeout=1.0)

    def _cleanup_relay(
        self,
        client_sock: socket.socket,
        up_sock: ssl.SSLSocket,
        ctx: _RelayContext,
    ) -> None:
        if ctx.revoke_cb is not None:
            self.lease.remove_revoke_callback(ctx.revoke_cb)
        if ctx.cancel_pair is not None:
            self.lease.unregister_pg_cancel(*ctx.cancel_pair)
        self.lease.unregister_stream(client_sock)
        self.lease.unregister_stream(up_sock)
        _close_quiet(up_sock)
