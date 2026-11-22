"""Per-job message-framed Host Postgres v3 wire proxy for PRD L1 (Path A).

Pure Python standard library only. Terminates sandbox Postgres connections on a
pod-local loopback TCP or 0o600 UDS listener (with SO_PEERCRED verification),
authenticates the disposable per-job ocjob_ token, connects upstream over strict
TLS-only verify-full, pins upstream role/database/options, synthesizes job-local
BackendKeyData, scrubs ParameterStatus/ErrorResponse/NoticeResponse frames, and
streams large DataRow/CopyData frames through a serialized selectors loop.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import ssl
import struct
import threading
import time
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
    bind_loopback_tcp,
    bind_trusted_uds,
    build_strict_tls_context,
    cleanup_uds_socket,
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
MAX_STREAM_FRAME_BYTES = 256 * 1024 * 1024
MAX_PG_FRAME_LEN = 0x7FFF_FFFF
MAX_NEGOTIATION_RETRIES = 3
STREAM_CHUNK_BYTES = 16_384
MAX_SCRAM_ITERATIONS = 1_000_000
REVOKE_CANCEL_TIMEOUT = 1.5

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


def _check_clean_field(value: object, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise BrokerPolicyError(f"{label} must be a non-empty string")
    for ch in value:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or 0xD800 <= code <= 0xDFFF:
            raise BrokerPolicyError(f"Illegal control character in {label}")
    return value


def validate_pg_route(route: PgBrokerRoute, vault: HostVaultMemory) -> None:
    """Validate route coordinates, vault presence, and optional RO/RW distinctness."""
    if not isinstance(route, PgBrokerRoute):
        raise BrokerPolicyError("route must be a PgBrokerRoute")
    _check_clean_field(route.route_id, "route_id")
    _check_clean_field(route.upstream_host, "upstream_host")
    _check_clean_field(route.upstream_database, "upstream_database")
    _check_clean_field(route.upstream_user, "upstream_user")
    if type(route.upstream_port) is not int or not (1 <= route.upstream_port <= 65535):
        raise BrokerPolicyError("upstream_port must be an integer 1..65535")
    if route.access_mode not in ("ro", "rw"):
        raise BrokerPolicyError(f"Unsupported access_mode: {route.access_mode!r}")
    validate_allowed_cidrs(route.allowed_cidrs, context=f"pg:{route.route_id}.allowed_cidrs")
    password = vault.get(route.secret_ref)
    _verify_pair_distinctness(route, vault, password)


def _verify_pair_distinctness(
    route: PgBrokerRoute, vault: HostVaultMemory, password: str
) -> None:
    pair_user = route.pair_distinct_user
    pair_ref = route.pair_distinct_secret_ref
    if pair_user is None and pair_ref is None:
        return
    if pair_user is None or pair_ref is None:
        raise BrokerPolicyError(
            "pair_distinct_user and pair_distinct_secret_ref must both be provided"
        )
    pair_password = vault.get(pair_ref)
    HostVaultMemory.assert_distinct_pg_credentials(
        route.upstream_user,
        password,
        pair_user,
        pair_password,
    )


def _decode_utf8_strict(data: bytes, label: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BrokerPolicyError(f"Invalid UTF-8 in {label}") from exc


def _apply_deadline(sock: socket.socket, deadline: float | None) -> None:
    if deadline is None:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Postgres handshake deadline exceeded")
    sock.settimeout(remaining)


def recv_exact(
    sock: socket.socket, n: int, *, deadline: float | None = None
) -> bytes:
    """Read exactly n bytes from a socket or raise EOFError/TimeoutError."""
    if n == 0:
        return b""
    buf = bytearray()
    while len(buf) < n:
        _apply_deadline(sock, deadline)
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("Unexpected EOF on Postgres stream")
        buf.extend(chunk)
    return bytes(buf)


def encode_pg_frame(msg_type: bytes, body: bytes) -> bytes:
    """Encode a Postgres v3 message frame with signed int32 length check."""
    if len(msg_type) != 1:
        raise ValueError("msg_type must be a single byte")
    total_len = len(body) + 4
    if total_len > MAX_PG_FRAME_LEN:
        raise BrokerPolicyError("Postgres frame exceeds signed int32 maximum length")
    return msg_type + struct.pack("!i", total_len) + body


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
    total_len = len(body) + 4
    if total_len > MAX_STARTUP_BYTES:
        raise BrokerPolicyError("Upstream StartupMessage exceeds MAX_STARTUP_BYTES")
    return struct.pack("!i", total_len) + body


def read_pg_frame_header(
    sock: socket.socket, *, deadline: float | None = None
) -> tuple[bytes, int]:
    """Read 1-byte type and signed int32 length, rejecting length < 4."""
    header = recv_exact(sock, 5, deadline=deadline)
    msg_type = header[:1]
    length = struct.unpack("!i", header[1:5])[0]
    if length < 4:
        raise BrokerPolicyError(f"Invalid Postgres v3 frame length: {length}")
    return msg_type, length - 4


def read_pg_control_frame(
    sock: socket.socket,
    *,
    max_body: int = MAX_CONTROL_FRAME_BYTES,
    deadline: float | None = None,
) -> tuple[bytes, bytes]:
    """Read a bounded Postgres v3 control frame."""
    msg_type, body_len = read_pg_frame_header(sock, deadline=deadline)
    if body_len > max_body:
        raise BrokerPolicyError(
            f"Postgres control frame {msg_type!r} exceeds {max_body} bytes"
        )
    return msg_type, recv_exact(sock, body_len, deadline=deadline)


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
    timeout: float = REVOKE_CANCEL_TIMEOUT,
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
        _close_quiet(sock)


def _dispatch_async_cancel(target: PgUpstreamCancelTarget) -> None:
    def _worker() -> None:
        try:
            send_upstream_tls_cancel(target, timeout=REVOKE_CANCEL_TIMEOUT)
        except (OSError, BrokerError, EOFError):
            pass

    threading.Thread(target=_worker, daemon=True).start()


def _parse_scram_kv(message: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in message.split(","):
        if "=" not in part:
            raise BrokerPolicyError("Malformed SCRAM-SHA-256 attribute")
        k, v = part.split("=", 1)
        if not k or k in out:
            raise BrokerPolicyError("Empty or duplicate SCRAM-SHA-256 attribute")
        out[k] = v
    return out


def _compute_scram_exchange(
    client_first_bare: str, server_first: str, password: str, c_nonce: str
) -> tuple[str, str]:
    attrs = _parse_scram_kv(server_first)
    if "m" in attrs:
        raise BrokerPolicyError("Unsupported mandatory SCRAM-SHA-256 extension")
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
    if not salt or not (1 <= iterations <= MAX_SCRAM_ITERATIONS):
        raise BrokerPolicyError("SCRAM-SHA-256 salt or iteration count invalid")

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


def _handle_scram_sha256(
    sock: socket.socket, mech_bytes: bytes, password: str, *, deadline: float | None = None
) -> None:
    if b"SCRAM-SHA-256" not in mech_bytes.split(b"\x00"):
        raise BrokerPolicyError("Upstream SASL does not offer SCRAM-SHA-256")

    c_nonce = base64.b64encode(secrets.token_bytes(18)).decode("ascii")
    client_first_bare = f"n=,r={c_nonce}"
    client_first = f"n,,{client_first_bare}".encode("utf-8")
    init_body = b"SCRAM-SHA-256\x00" + struct.pack("!I", len(client_first)) + client_first
    sock.sendall(encode_pg_frame(b"p", init_body))

    msg_type, body = read_pg_control_frame(sock, deadline=deadline)
    if msg_type != b"R" or len(body) < 4 or struct.unpack("!I", body[:4])[0] != 11:
        raise BrokerAuthError("Expected AuthenticationSASLContinue from upstream")

    server_first = _decode_utf8_strict(body[4:], "SCRAM server-first-message")
    client_final, expected_v = _compute_scram_exchange(
        client_first_bare, server_first, password, c_nonce
    )
    sock.sendall(encode_pg_frame(b"p", client_final.encode("utf-8")))

    msg_type, body = read_pg_control_frame(sock, deadline=deadline)
    if msg_type != b"R" or len(body) < 4 or struct.unpack("!I", body[:4])[0] != 12:
        raise BrokerAuthError("Expected AuthenticationSASLFinal from upstream")

    server_final = _decode_utf8_strict(body[4:], "SCRAM server-final-message")
    final_attrs = _parse_scram_kv(server_final)
    server_v = final_attrs.get("v", "")
    if "e" in final_attrs or not hmac.compare_digest(server_v, expected_v):
        raise BrokerAuthError("SCRAM-SHA-256 server signature verification failed")


def _send_md5_password(sock: socket.socket, user: str, password: str, salt: bytes) -> None:
    if len(salt) != 4:
        raise BrokerPolicyError("Invalid MD5 salt length from upstream")
    inner = hashlib.md5((password + user).encode("utf-8")).hexdigest().encode("ascii")
    outer = hashlib.md5(inner + salt).hexdigest()
    sock.sendall(encode_pg_frame(b"p", f"md5{outer}\x00".encode("ascii")))


def _dispatch_auth_challenge(
    up_sock: socket.socket,
    code: int,
    rest: bytes,
    route: PgBrokerRoute,
    password: str,
    deadline: float | None,
) -> None:
    if code == 3:
        if rest:
            raise BrokerPolicyError("Unexpected payload in AuthenticationCleartextPassword")
        up_sock.sendall(encode_pg_frame(b"p", password.encode("utf-8") + b"\x00"))
        return
    if code == 5:
        _send_md5_password(up_sock, route.upstream_user, password, rest)
        return
    if code == 10:
        _handle_scram_sha256(up_sock, rest, password, deadline=deadline)
        return
    raise BrokerPolicyError(f"Unsupported upstream Postgres auth code: {code}")


def authenticate_upstream_pg(
    up_sock: socket.socket,
    route: PgBrokerRoute,
    password: str,
    *,
    deadline: float | None = None,
) -> None:
    """Send pinned StartupMessage and complete at most one upstream auth challenge."""
    options = "-c default_transaction_read_only=on" if route.access_mode == "ro" else ""
    up_sock.sendall(encode_pg_startup(route.upstream_user, route.upstream_database, options))

    challenged = False
    for _ in range(2):
        msg_type, body = read_pg_control_frame(up_sock, deadline=deadline)
        if msg_type == b"E":
            raise BrokerAuthError("Upstream Postgres rejected authentication")
        if msg_type != b"R" or len(body) < 4:
            raise BrokerPolicyError("Unexpected upstream frame during authentication")
        code = struct.unpack("!I", body[:4])[0]
        if code == 0:
            if len(body) != 4:
                raise BrokerPolicyError("Unexpected payload in AuthenticationOk")
            return
        if challenged:
            raise BrokerPolicyError("Repeated upstream Postgres authentication challenge")
        challenged = True
        _dispatch_auth_challenge(up_sock, code, body[4:], route, password, deadline)
    raise BrokerPolicyError("Upstream Postgres did not complete authentication")


def _build_redaction_pattern(
    upstream_host: str, upstream_ip: str, upstream_user: str, secrets_list: tuple[str, ...]
) -> re.Pattern[str] | None:
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
    if not tokens:
        return None
    ordered = sorted(tokens, key=len, reverse=True)
    return re.compile("|".join(re.escape(t) for t in ordered), re.IGNORECASE)


def scrub_text(text: str, pattern: re.Pattern[str] | None) -> str:
    """Case-insensitively replace sensitive upstream tokens with [redacted]."""
    if pattern is None:
        return text
    return pattern.sub("[redacted]", text)


def scrub_error_or_notice_body(body: bytes, pattern: re.Pattern[str] | None) -> bytes:
    """Parse ErrorResponse/NoticeResponse fields strictly, scrub values, and re-encode."""
    out: list[bytes] = []
    pos = 0
    end = len(body)
    if end == 0:
        raise BrokerPolicyError("Empty ErrorResponse/NoticeResponse body")
    while pos < end:
        code = body[pos : pos + 1]
        if code == b"\x00":
            if pos != end - 1:
                raise BrokerPolicyError("Trailing bytes after ErrorResponse/NoticeResponse terminator")
            out.append(b"\x00")
            return b"".join(out)
        nul = body.find(b"\x00", pos + 1)
        if nul == -1:
            raise BrokerPolicyError("Malformed ErrorResponse/NoticeResponse field")
        val = body[pos + 1 : nul].decode("utf-8", errors="replace")
        clean_val = scrub_text(val, pattern)
        out.append(code + clean_val.encode("utf-8") + b"\x00")
        pos = nul + 1
    raise BrokerPolicyError("Unterminated ErrorResponse/NoticeResponse frame")


def filter_parameter_status_body(
    body: bytes, pattern: re.Pattern[str] | None
) -> bytes | None:
    """Allow only safe libpq ParameterStatus keys with exact <k>\\0<v>\\0 wire format."""
    parts = body.split(b"\x00")
    if len(parts) != 3 or parts[2] != b"":
        raise BrokerPolicyError("Malformed ParameterStatus frame")
    key = _decode_utf8_strict(parts[0], "ParameterStatus key")
    if key not in SAFE_PARAMETER_STATUS_KEYS:
        return None
    val = parts[1].decode("utf-8", errors="replace")
    clean_val = scrub_text(val, pattern)
    return key.encode("utf-8") + b"\x00" + clean_val.encode("utf-8") + b"\x00"


def _read_startup_header(sock: socket.socket, deadline: float | None) -> tuple[int, int]:
    length = struct.unpack("!i", recv_exact(sock, 4, deadline=deadline))[0]
    if length < 8 or length > MAX_STARTUP_BYTES:
        raise BrokerPolicyError(f"Invalid Postgres startup packet length: {length}")
    code = struct.unpack("!I", recv_exact(sock, 4, deadline=deadline))[0]
    return length, code


def _read_client_initial_packet(
    sock: socket.socket, *, deadline: float | None = None
) -> tuple[int, bytes]:
    for _ in range(MAX_NEGOTIATION_RETRIES + 1):
        length, code = _read_startup_header(sock, deadline)
        if code in (PG_SSL_REQUEST, PG_GSSENC_REQUEST):
            if length != 8:
                raise BrokerPolicyError("SSLRequest/GSSENCRequest must be exactly 8 bytes")
            sock.sendall(b"N")
            continue
        if code == PG_CANCEL_REQUEST:
            if length != 16:
                raise BrokerPolicyError("CancelRequest must be exactly 16 bytes")
            return PG_CANCEL_REQUEST, recv_exact(sock, 8, deadline=deadline)
        if code == PG_PROTOCOL_V3:
            return PG_PROTOCOL_V3, recv_exact(sock, length - 8, deadline=deadline)
        raise BrokerPolicyError(f"Unsupported Postgres startup code: {code}")
    raise BrokerPolicyError("Exceeded maximum Postgres SSL/GSS negotiation retries")


def _authenticate_client(
    client_sock: socket.socket, lease: BrokerLease, *, deadline: float | None = None
) -> bool:
    if not lease.is_active():
        client_sock.sendall(encode_pg_error_response("28000", "lease revoked"))
        return False
    client_sock.sendall(encode_pg_frame(b"R", struct.pack("!I", 3)))
    msg_type, body = read_pg_control_frame(
        client_sock, max_body=MAX_STARTUP_BYTES, deadline=deadline
    )
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
    if body_len > MAX_STREAM_FRAME_BYTES:
        raise BrokerPolicyError("Upstream streaming frame exceeds maximum size")
    scanner = OverlapCanaryScanner(secrets_list)
    dst.sendall(msg_type + struct.pack("!i", body_len + 4))
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
    if body_len > MAX_STREAM_FRAME_BYTES:
        raise BrokerPolicyError("Client streaming frame exceeds maximum size")
    dst.sendall(msg_type + struct.pack("!i", body_len + 4))
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
    redaction_pattern: re.Pattern[str] | None
    secrets_list: tuple[str, ...]
    cancel_pair: tuple[int, int] | None = None
    revoke_cb: Callable[[], None] | None = None


def _handle_backend_key_data(
    up_sock: socket.socket,
    client_sock: socket.socket,
    body_len: int,
    ctx: _RelayContext,
) -> None:
    if ctx.cancel_pair is not None:
        raise BrokerPolicyError("Duplicate BackendKeyData frame rejected")
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
            _dispatch_async_cancel(target)

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
        filtered = filter_parameter_status_body(body, ctx.redaction_pattern)
        if filtered is not None:
            client_sock.sendall(encode_pg_frame(b"S", filtered))
        return
    if msg_type in (b"E", b"N"):
        scrubbed = scrub_error_or_notice_body(body, ctx.redaction_pattern)
        OverlapCanaryScanner(ctx.secrets_list).scan_bytes(scrubbed)
        client_sock.sendall(encode_pg_frame(msg_type, scrubbed))
        return
    OverlapCanaryScanner(ctx.secrets_list).scan_bytes(body)
    client_sock.sendall(encode_pg_frame(msg_type, body))


def _relay_single_client_frame(
    client_sock: socket.socket, up_sock: socket.socket
) -> bool:
    """Relay one framed message from client to upstream; return False on Terminate ('X')."""
    msg_type, body_len = read_pg_frame_header(client_sock)
    if msg_type == b"d":
        _stream_frame_passthrough(client_sock, up_sock, msg_type, body_len)
        return True
    if body_len > MAX_CONTROL_FRAME_BYTES:
        raise BrokerPolicyError(f"Client control frame {msg_type!r} exceeds limit")
    body = recv_exact(client_sock, body_len)
    up_sock.sendall(encode_pg_frame(msg_type, body))
    return msg_type != b"X"


def _get_peer_uid(conn: socket.socket) -> int:
    so_peercred = getattr(socket, "SO_PEERCRED", 17)
    raw = conn.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


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
    """Bounded per-job message-framed Postgres v3 proxy listener (loopback TCP or 0o600 UDS)."""

    def __init__(
        self,
        route: PgBrokerRoute,
        vault: HostVaultMemory,
        lease: BrokerLease,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        uds_path: Path | None = None,
        expected_uid: int | None = None,
        sandbox_root: Path | None = None,
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
        if uds_path is None:
            self._validate_loopback_host(host)
        self.route = route
        self._vault = vault
        self.lease = lease
        self._host = host
        self._port = port
        self._uds_path = uds_path
        self._expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self._sandbox_root = sandbox_root
        self._sem = threading.BoundedSemaphore(max_concurrent_conns)
        self._handshake_timeout = handshake_timeout
        self._io_timeout = io_timeout
        self._resolver = resolver
        self._allow_test_loopback = allow_test_loopback
        self._ssl_context = ssl_context

        self._listen_sock: socket.socket | None = None
        self._bound_uds_path: Path | None = None
        self._stop_ev = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._bound_port: int | None = None

    @staticmethod
    def _validate_loopback_host(host: str) -> None:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as exc:
            raise BrokerPolicyError(f"TCP listener host must be a loopback IP: {host!r}") from exc
        if not ip.is_loopback:
            raise BrokerPolicyError(f"TCP listener host must be loopback: {host!r}")

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
            self._listen_sock = self._bind_tcp()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def _bind_tcp(self) -> socket.socket:
        sock, bound_port = bind_loopback_tcp(self._host, self._port, backlog=32)
        self._bound_port = bound_port
        return sock

    def _bind_uds(self, raw_uds_path: Path) -> socket.socket:
        sock, bound_path = bind_trusted_uds(
            raw_uds_path,
            sandbox_root=self._sandbox_root,
            backlog=32,
        )
        self._bound_uds_path = bound_path
        return sock

    def stop(self) -> None:
        self._stop_ev.set()
        if self._listen_sock is not None:
            _close_quiet(self._listen_sock)
            self._listen_sock = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None
        if self._bound_uds_path is not None:
            cleanup_uds_socket(self._bound_uds_path)
            self._bound_uds_path = None

    def __enter__(self) -> HostPostgresBrokerServer:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def _accept_loop(self) -> None:
        listen_sock = self._listen_sock
        if listen_sock is None:
            return
        while not self._stop_ev.is_set():
            try:
                client_sock, _ = listen_sock.accept()
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
        except (EOFError, OSError, TimeoutError, BrokerError, CanaryLeakError):
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
        if client_sock.family == socket.AF_UNIX:
            if _get_peer_uid(client_sock) != self._expected_uid:
                return
        deadline = time.monotonic() + self._handshake_timeout
        code, payload = _read_client_initial_packet(client_sock, deadline=deadline)
        if code == PG_CANCEL_REQUEST:
            self._handle_cancel_request(payload)
            return
        if not _authenticate_client(client_sock, self.lease, deadline=deadline):
            return

        self.lease.register_stream(client_sock)
        try:
            self._connect_and_bridge(client_sock, deadline)
        finally:
            self.lease.unregister_stream(client_sock)

    def _connect_and_bridge(self, client_sock: socket.socket, deadline: float) -> None:
        password = self._vault.get(self.route.secret_ref)
        upstream_ip = resolve_and_validate_ip(
            self.route.upstream_host,
            self.route.allowed_cidrs,
            port=self.route.upstream_port,
            resolver=self._resolver,
            allow_test_loopback=self._allow_test_loopback,
        )
        remaining = max(0.1, deadline - time.monotonic())
        up_sock = pg_connect_strict_tls_only(
            upstream_ip,
            self.route.upstream_port,
            server_hostname=self.route.upstream_host,
            ssl_context=self._ssl_context,
            timeout=remaining,
        )
        secrets_list = (password,)
        redaction_pattern = _build_redaction_pattern(
            self.route.upstream_host, upstream_ip, self.route.upstream_user, secrets_list
        )
        ctx = _RelayContext(
            lease=self.lease,
            route=self.route,
            upstream_ip=upstream_ip,
            ssl_context=self._ssl_context,
            redaction_pattern=redaction_pattern,
            secrets_list=secrets_list,
        )
        try:
            self.lease.register_stream(up_sock)
            authenticate_upstream_pg(up_sock, self.route, password, deadline=deadline)
            client_sock.sendall(encode_pg_frame(b"R", struct.pack("!I", 0)))
            client_sock.settimeout(self._io_timeout)
            up_sock.settimeout(self._io_timeout)
            self._run_serialized_relay(client_sock, up_sock, ctx)
        finally:
            self._cleanup_relay(up_sock, ctx)

    def _run_serialized_relay(
        self,
        client_sock: socket.socket,
        up_sock: ssl.SSLSocket,
        ctx: _RelayContext,
    ) -> None:
        sel = selectors.DefaultSelector()
        sel.register(client_sock, selectors.EVENT_READ, data="client")
        sel.register(up_sock, selectors.EVENT_READ, data="upstream")
        last_activity = time.monotonic()
        try:
            while self.lease.is_active():
                if up_sock.pending() > 0:
                    _relay_single_upstream_frame(up_sock, client_sock, ctx)
                    last_activity = time.monotonic()
                    continue
                events = sel.select(timeout=0.2)
                if not events:
                    if time.monotonic() - last_activity > self._io_timeout:
                        return
                    continue
                if not self._process_relay_events(events, client_sock, up_sock, ctx):
                    return
                last_activity = time.monotonic()
        except (EOFError, OSError, TimeoutError, BrokerError, CanaryLeakError):
            pass
        finally:
            sel.close()
            _shutdown_quiet(client_sock)
            _shutdown_quiet(up_sock)

    def _process_relay_events(
        self,
        events: list[tuple[selectors.SelectorKey, int]],
        client_sock: socket.socket,
        up_sock: ssl.SSLSocket,
        ctx: _RelayContext,
    ) -> bool:
        for key, _ in events:
            if key.data == "upstream":
                _relay_single_upstream_frame(up_sock, client_sock, ctx)
            else:
                if not _relay_single_client_frame(client_sock, up_sock):
                    return False
        return True

    def _cleanup_relay(self, up_sock: ssl.SSLSocket, ctx: _RelayContext) -> None:
        if ctx.revoke_cb is not None:
            self.lease.remove_revoke_callback(ctx.revoke_cb)
        if ctx.cancel_pair is not None:
            self.lease.unregister_pg_cancel(*ctx.cancel_pair)
        self.lease.unregister_stream(up_sock)
        _close_quiet(up_sock)
