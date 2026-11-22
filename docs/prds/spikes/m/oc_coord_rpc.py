"""Hardened Unix Domain Socket Control & Coordination RPC Server for PRD M.

Pure Python standard library only. Enforces:
- Trusted 0o700 directory / 0o600 UDS binding via oc_broker_common.bind_trusted_uds
- Kernel SO_PEERCRED UID verification on every accepted connection before reading bytes
- Pre-parse sliding-window rate limiting so flood connections fail fast
- Bounded concurrent connections via ListenerWorkers and per-connection timeouts
- Bounded Content-Length framing (max 128 KiB, no pipelined trailing bytes)
- Strict JSON parsing (rejects duplicate keys, NaN/Infinity/overflow floats, NUL bytes,
  unpaired surrogates, nesting depth > 32, oversized payloads, non-object top-level JSON)
- Unforgeable PrincipalCtx binding derived solely from socket role or constant-time
  token binding, rejecting any client-forged identity fields with JSON-RPC -32602
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Hashable, Mapping, Sequence
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
from typing import Any, Protocol, runtime_checkable

_SPIKE_M_DIR = Path(__file__).resolve().parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
for _path in (_SPIKE_M_DIR, _SPIKE_L_DIR):
    _path_str = str(_path)
    if _path_str not in sys.path:
        sys.path.insert(0, _path_str)

from oc_address import AddressError  # noqa: E402
from oc_broker_common import (  # noqa: E402
    BoundUds,
    BrokerError,
    ListenerWorkers,
    bind_trusted_uds,
)
from oc_coord_contract import (  # noqa: E402
    MAX_ARTIFACTS_PER_MSG,
    ArtifactRef,
    CoordAuthError,
    CoordBackpressureError,
    CoordError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    DeadlockCycleError,
    IncarnationMismatchError,
    PrincipalCtx,
    RevocationStatus,
    RevokedError,
    validate_reason_text,
)

MAX_FRAME_BYTES = 131_072
MAX_RESPONSE_BYTES = 524_288
MAX_JSON_DEPTH = 32
MAX_CONCURRENT_CONNS = 16
MAX_HEADER_BYTES = 4_096
READ_TIMEOUT_SECONDS = 5.0
WRITE_TIMEOUT_SECONDS = 5.0
TOTAL_REQUEST_TIMEOUT_SECONDS = 15.0
MAX_WAIT_TIMEOUT_SECONDS = 60.0
MAX_WAIT_TARGETS = 64
MAX_RATE_LIMITER_KEYS = 1_024
MAX_SEQ_INT = (1 << 63) - 1

_UTF8 = "utf-8"
_STRICT = "strict"
_KEY_JSONRPC = "jsonrpc"
_KEY_ID = "id"
_KEY_AUTH_TOKEN = "auth_token"
_KEY_METHOD = "method"
_KEY_PARAMS = "params"
_KEY_TARGET = "target"
_KEY_BLOB_SHA256 = "blob_sha256"
_KEY_SIZE_BYTES = "size_bytes"
_ERR_RATE_LIMITED = "rate_limited"

ALLOWED_HEADERS: frozenset[str] = frozenset({"content-length", "content-type"})
ALLOWED_RPC_KEYS: frozenset[str] = frozenset(
    {_KEY_JSONRPC, _KEY_ID, _KEY_AUTH_TOKEN, _KEY_METHOD, _KEY_PARAMS}
)
ALLOWED_ARTIFACT_REF_KEYS: frozenset[str] = frozenset(
    {_KEY_BLOB_SHA256, _KEY_SIZE_BYTES, "media_type"}
)

FORBIDDEN_IDENTITY_KEYS: frozenset[str] = frozenset(
    {"src", "src_role", "src_actor", "trust_class", "principal", "badge", "caller"}
)

METHOD_SEND = "coord.send"
METHOD_STATUS = "coord.status"
METHOD_WAIT = "coord.wait"
METHOD_REVOKE = "coord.revoke"
METHOD_PROJECTION = "coord.projection"

ALLOWED_METHODS: frozenset[str] = frozenset(
    {METHOD_SEND, METHOD_STATUS, METHOD_WAIT, METHOD_REVOKE, METHOD_PROJECTION}
)

_METHOD_PARAM_ALLOWLISTS: dict[str, frozenset[str]] = {
    METHOD_SEND: frozenset(
        {_KEY_TARGET, "thread_id", "msg_kind", "body_text", "in_reply_to", "artifact_refs"}
    ),
    METHOD_STATUS: frozenset({_KEY_TARGET}),
    METHOD_WAIT: frozenset({"targets", "since_seq", "timeout_s"}),
    METHOD_REVOKE: frozenset({_KEY_TARGET, "reason"}),
    METHOD_PROJECTION: frozenset(),
}

ERR_CODE_PARSE = -32700
ERR_CODE_INVALID_REQUEST = -32600
ERR_CODE_METHOD_NOT_FOUND = -32601
ERR_CODE_INVALID_PARAMS = -32602
ERR_CODE_INTERNAL = -32603
ERR_CODE_AUTH = -32001
ERR_CODE_RATE_LIMIT = -32002
ERR_CODE_POLICY = -32003

_TRAILING_BYTES_MSG = "Trailing or pipelined bytes after Content-Length frame"
_HEADER_TOO_LARGE_MSG = "Header section too large"


class FramingError(ValueError):
    """Malformed, timed-out, or oversized Content-Length frame."""


class StrictJsonError(ValueError):
    """Strict JSON decode or schema safety violation."""


@runtime_checkable
class CoordHubProtocol(Protocol):
    """Interface contract matching Lane 2's CoordHub."""

    def send(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        thread_id: str = "main",
        msg_kind: str = "prompt",
        body_text: str,
        in_reply_to: str | None = None,
        artifact_refs: Sequence[ArtifactRef] = (),
    ) -> dict[str, Any]: ...

    def status(
        self,
        caller: PrincipalCtx,
        *,
        target: str | None = None,
    ) -> dict[str, Any]: ...

    def wait(
        self,
        caller: PrincipalCtx,
        *,
        targets: Sequence[str],
        since_seq: int = 0,
        timeout_s: float = 5.0,
    ) -> dict[str, Any]: ...

    def revoke(
        self,
        caller: PrincipalCtx,
        *,
        target: str,
        reason: str = "operator_revoked",
    ) -> RevocationStatus: ...

    def projection(self, caller: PrincipalCtx) -> dict[str, Any]: ...


def _validate_finite_positive(value: object, label: str) -> float:
    err_msg = f"{label} must be a finite positive number"
    if type(value) not in (int, float):
        raise ValueError(err_msg)
    try:
        num = float(value)
    except OverflowError as exc:
        raise ValueError(err_msg) from exc
    if not math.isfinite(num) or num <= 0.0:
        raise ValueError(err_msg)
    return num


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in pairs:
        if key in out:
            raise StrictJsonError(f"Duplicate JSON key: {key!r}")
        out[key] = val
    return out


def _reject_constants(val: str) -> Any:
    raise StrictJsonError(f"Non-standard JSON constant rejected: {val}")


def _validate_json_string(text: str) -> None:
    if "\x00" in text:
        raise StrictJsonError("NUL byte rejected in JSON string")
    try:
        text.encode(_UTF8, errors=_STRICT)
    except UnicodeEncodeError as exc:
        raise StrictJsonError("Unpaired UTF-16 surrogate rejected") from exc


def _check_depth_and_values(obj: Any, depth: int, max_depth: int) -> None:
    if depth > max_depth:
        raise StrictJsonError(f"JSON nesting depth exceeds {max_depth}")
    if isinstance(obj, str):
        _validate_json_string(obj)
        return
    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise StrictJsonError("Non-finite float value rejected")
        return
    if isinstance(obj, list):
        for item in obj:
            _check_depth_and_values(item, depth + 1, max_depth)
        return
    if isinstance(obj, dict):
        for key, val in obj.items():
            _check_depth_and_values(key, depth + 1, max_depth)
            _check_depth_and_values(val, depth + 1, max_depth)


def parse_strict_json(
    raw: bytes,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_bytes: int = MAX_FRAME_BYTES,
) -> dict[str, Any]:
    """Parse a strict JSON object rejecting oversized, NUL, non-UTF-8, dup-key, NaN/Inf, deep, or surrogate payloads."""
    if not isinstance(raw, (bytes, bytearray)):
        raise StrictJsonError("JSON payload must be bytes")
    if len(raw) > max_bytes:
        raise StrictJsonError(f"JSON payload exceeds {max_bytes} bytes")
    if b"\x00" in raw:
        raise StrictJsonError("NUL byte rejected in JSON payload")
    try:
        text = bytes(raw).decode(_UTF8, errors=_STRICT)
    except UnicodeDecodeError as exc:
        raise StrictJsonError("Invalid UTF-8 payload") from exc
    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constants,
        )
    except StrictJsonError:
        raise
    except RecursionError as exc:
        raise StrictJsonError(f"JSON nesting depth exceeds {max_depth}") from exc
    except Exception as exc:
        raise StrictJsonError(f"Invalid JSON: {exc}") from exc
    _check_depth_and_values(data, 0, max_depth)
    if not isinstance(data, dict):
        raise StrictJsonError("JSON-RPC payload must be a JSON object")
    return data


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return encoded.encode(_UTF8)


def encode_content_length_frame(payload: dict[str, Any]) -> bytes:
    """Encode a JSON object with a strict ASCII Content-Length header."""
    body = _canonical_json_bytes(payload)
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    return header + body


def _recv_with_deadline(
    conn: socket.socket, limit: int, deadline: float, read_timeout: float
) -> bytes:
    rem = deadline - time.monotonic()
    if rem <= 0:
        raise FramingError("Request deadline exceeded")
    conn.settimeout(min(read_timeout, rem))
    try:
        return conn.recv(limit)
    except TimeoutError as exc:
        raise FramingError("Socket read timeout") from exc
    except OSError as exc:
        raise FramingError(f"Socket read error: {exc}") from exc


def _read_header_section(
    conn: socket.socket,
    deadline: float,
    read_timeout: float,
    max_header_bytes: int = MAX_HEADER_BYTES,
) -> tuple[bytes, bytes]:
    buf = bytearray()
    header_end = -1
    while header_end == -1:
        chunk = _recv_with_deadline(conn, 1024, deadline, read_timeout)
        if not chunk:
            raise FramingError("Unexpected EOF reading headers")
        buf.extend(chunk)
        header_end = buf.find(b"\r\n\r\n")
        if header_end == -1 and len(buf) > max_header_bytes:
            raise FramingError(_HEADER_TOO_LARGE_MSG)
    if header_end > max_header_bytes:
        raise FramingError(_HEADER_TOO_LARGE_MSG)
    return bytes(buf[:header_end]), bytes(buf[header_end + 4 :])


def _parse_header_line(line: str, headers: dict[str, str]) -> None:
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in line):
        raise FramingError("Control character rejected in header")
    if ":" not in line:
        raise FramingError("Malformed header line")
    key, val = line.split(":", 1)
    lower_key = key.strip().lower()
    if lower_key not in ALLOWED_HEADERS:
        raise FramingError(f"Unsupported header rejected: {lower_key}")
    if lower_key in headers:
        raise FramingError(f"Duplicate header: {lower_key}")
    headers[lower_key] = val.strip()


def _parse_content_length(header_bytes: bytes, max_bytes: int) -> int:
    try:
        header_text = header_bytes.decode("ascii", errors=_STRICT)
    except UnicodeDecodeError as exc:
        raise FramingError("Non-ASCII header bytes rejected") from exc

    headers: dict[str, str] = {}
    for line in header_text.split("\r\n"):
        _parse_header_line(line, headers)

    cl_raw = headers.get("content-length")
    if cl_raw is None or not (cl_raw.isascii() and cl_raw.isdigit()):
        raise FramingError("Missing or invalid Content-Length")
    content_length = int(cl_raw)
    if content_length <= 0 or content_length > max_bytes:
        raise FramingError(f"Content-Length {content_length} out of bounds (1..{max_bytes})")
    return content_length


def _reject_pipelined_bytes(conn: socket.socket, read_timeout: float) -> None:
    conn.setblocking(False)
    try:
        extra = conn.recv(1, socket.MSG_PEEK)
        if extra:
            raise FramingError(_TRAILING_BYTES_MSG)
    except OSError:
        pass
    finally:
        conn.settimeout(read_timeout)


def read_content_length_frame(
    conn: socket.socket,
    *,
    max_bytes: int = MAX_FRAME_BYTES,
    read_timeout: float = READ_TIMEOUT_SECONDS,
    total_timeout: float = TOTAL_REQUEST_TIMEOUT_SECONDS,
) -> bytes:
    """Read exactly one bounded Content-Length framed payload without trailing bytes."""
    deadline = time.monotonic() + total_timeout
    header_bytes, rest = _read_header_section(conn, deadline, read_timeout)
    content_length = _parse_content_length(header_bytes, max_bytes)
    if len(rest) > content_length:
        raise FramingError(_TRAILING_BYTES_MSG)

    body = bytearray(rest)
    while len(body) < content_length:
        chunk = _recv_with_deadline(
            conn, min(8192, content_length - len(body) + 1), deadline, read_timeout
        )
        if not chunk:
            raise FramingError("Unexpected EOF reading body")
        body.extend(chunk)
        if len(body) > content_length:
            raise FramingError(_TRAILING_BYTES_MSG)

    _reject_pipelined_bytes(conn, read_timeout)
    return bytes(body)


def get_peer_uid(conn: socket.socket) -> int:
    """Read the kernel-verified peer UID from Linux SO_PEERCRED."""
    so_peercred = getattr(socket, "SO_PEERCRED", 17)
    raw = conn.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


class SlidingWindowRateLimiter:
    """Thread-safe bounded per-key sliding-window rate limiter."""

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60.0,
        *,
        max_keys: int = MAX_RATE_LIMITER_KEYS,
        clock: Callable[[], float] = time.monotonic,
    ):
        if type(max_requests) is not int or max_requests < 1:
            raise ValueError("max_requests must be a positive integer")
        valid_window = _validate_finite_positive(window_seconds, "window_seconds")
        if type(max_keys) is not int or max_keys < 1:
            raise ValueError("max_keys must be a positive integer")
        self.max_requests = max_requests
        self.window_seconds = valid_window
        self._max_keys = max_keys
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[Hashable, deque[float]] = {}

    def _prune_stale_keys(self, cutoff: float) -> None:
        stale = [key for key, q in self._hits.items() if not q or q[-1] <= cutoff]
        for key in stale:
            del self._hits[key]

    def allow(self, key: Hashable) -> bool:
        with self._lock:
            now = self._clock()
            cutoff = now - self.window_seconds
            q = self._hits.get(key)
            if q is None:
                if len(self._hits) >= self._max_keys:
                    self._prune_stale_keys(cutoff)
                if len(self._hits) >= self._max_keys:
                    return False
                q = deque()
                self._hits[key] = q
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode(_UTF8)).hexdigest()


def _parse_artifact_ref(raw: Any) -> ArtifactRef:
    if not isinstance(raw, dict):
        raise CoordValidationError("Each artifact_ref must be a JSON object")
    extra = sorted(set(raw.keys()) - ALLOWED_ARTIFACT_REF_KEYS)
    if extra:
        raise CoordValidationError(f"Unknown artifact_ref keys: {', '.join(extra)}")
    if _KEY_BLOB_SHA256 not in raw or _KEY_SIZE_BYTES not in raw:
        raise CoordValidationError("artifact_ref requires blob_sha256 and size_bytes")
    media_type = raw.get("media_type", "text/x-patch")
    return ArtifactRef(
        blob_sha256=raw[_KEY_BLOB_SHA256],
        size_bytes=raw[_KEY_SIZE_BYTES],
        media_type=media_type,
    )


def _require_str(params: dict[str, Any], key: str) -> str:
    val = params.get(key)
    if type(val) is not str:
        raise CoordValidationError(f"{key} must be a string")
    return val


def _optional_str_default(params: dict[str, Any], key: str, default: str) -> str:
    if key not in params or params[key] is None:
        return default
    val = params[key]
    if type(val) is not str:
        raise CoordValidationError(f"{key} must be a string or null")
    return val


def _optional_str(params: dict[str, Any], key: str) -> str | None:
    if key not in params or params[key] is None:
        return None
    val = params[key]
    if type(val) is not str:
        raise CoordValidationError(f"{key} must be a string or null")
    return val


def _parse_wait_params(params: dict[str, Any]) -> tuple[tuple[str, ...], int, float]:
    raw_targets = params.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise CoordValidationError("targets must be a non-empty list of strings")
    if len(raw_targets) > MAX_WAIT_TARGETS:
        raise CoordValidationError(f"targets exceeds maximum of {MAX_WAIT_TARGETS}")
    if any(type(t) is not str for t in raw_targets):
        raise CoordValidationError("every target in targets must be a string")
    deduped_targets = tuple(dict.fromkeys(raw_targets))
    since_seq = params.get("since_seq", 0)
    if type(since_seq) is not int or not (0 <= since_seq <= MAX_SEQ_INT):
        raise CoordValidationError(f"since_seq must be an integer in 0..{MAX_SEQ_INT}")
    raw_timeout = params.get("timeout_s", 5.0)
    if type(raw_timeout) not in (int, float):
        raise CoordValidationError("timeout_s must be a finite number")
    try:
        timeout_s = float(raw_timeout)
    except OverflowError as exc:
        raise CoordValidationError("timeout_s must be a finite number") from exc
    if not math.isfinite(timeout_s) or not (0.0 <= timeout_s <= MAX_WAIT_TIMEOUT_SECONDS):
        raise CoordValidationError(f"timeout_s must be in 0..{MAX_WAIT_TIMEOUT_SECONDS}")
    return deduped_targets, since_seq, timeout_s


def _serialize_revocation(status: RevocationStatus) -> dict[str, Any]:
    return {
        "target_addr": status.target_addr,
        "incarnation_id": status.incarnation_id,
        "revoked_edges": status.revoked_edges,
        "aborted_streams": status.aborted_streams,
        "elapsed_ms": status.elapsed_ms,
    }


def _rpc_ok(req_id: Any, result: Any) -> dict[str, Any]:
    return {_KEY_JSONRPC: "2.0", _KEY_ID: req_id, "result": result}


def _rpc_error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {_KEY_JSONRPC: "2.0", _KEY_ID: req_id, "error": {"code": code, "message": message}}


def _build_token_table(
    token_principals: Mapping[str, PrincipalCtx],
) -> dict[str, tuple[str, PrincipalCtx]]:
    table: dict[str, tuple[str, PrincipalCtx]] = {}
    for tok, principal in token_principals.items():
        if type(tok) is not str or not tok:
            raise ValueError("token_principals keys must be non-empty strings")
        if not isinstance(principal, PrincipalCtx):
            raise ValueError("token_principals values must be PrincipalCtx instances")
        digest = _hash_token(tok)
        table[digest] = (digest, principal)
    return table


class CoordUdsRpcServer:
    """Hardened 0o700-dir / 0o600 UDS JSON-RPC server for PRD M coordination."""

    def __init__(
        self,
        hub: CoordHubProtocol,
        socket_path: Path,
        *,
        sandbox_root: Path | None = None,
        role: CoordRole = CoordRole.OPERATOR,
        token_principals: Mapping[str, PrincipalCtx] | None = None,
        required_auth_token: str | None = None,
        expected_uid: int | None = None,
        max_concurrent_conns: int = MAX_CONCURRENT_CONNS,
        rate_limit_max: int = 60,
        rate_limit_window: float = 60.0,
        io_timeout: float = READ_TIMEOUT_SECONDS,
        peer_uid_getter: Callable[[socket.socket], int] = get_peer_uid,
    ):
        if type(max_concurrent_conns) is not int or max_concurrent_conns < 1:
            raise ValueError("max_concurrent_conns must be a positive integer")
        valid_io_timeout = _validate_finite_positive(io_timeout, "io_timeout")
        if token_principals is not None and required_auth_token is not None:
            raise ValueError("Specify at most one of token_principals or required_auth_token")
        if token_principals is None and role in (CoordRole.JOB, CoordRole.EXTERNAL_PEER):
            raise ValueError("JOB and EXTERNAL_PEER sockets require token_principals")
        if required_auth_token is not None and (
            type(required_auth_token) is not str or not required_auth_token
        ):
            raise ValueError("required_auth_token must be a non-empty string")

        self._hub = hub
        self._raw_socket_path = Path(socket_path)
        self._sandbox_root = sandbox_root
        self._role = role
        self._expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self._max_concurrent_conns = max_concurrent_conns
        self._read_timeout = valid_io_timeout
        self._write_timeout = valid_io_timeout
        self._peer_uid_getter = peer_uid_getter
        self._required_token_hash = (
            _hash_token(required_auth_token) if required_auth_token is not None else None
        )
        self._token_lock = threading.Lock()
        self._token_table: dict[str, tuple[str, PrincipalCtx]] | None = (
            _build_token_table(token_principals) if token_principals is not None else None
        )
        self._has_operator_principal = bool(
            self._token_table is not None
            and any(p.role is CoordRole.OPERATOR for _, p in self._token_table.values())
        )
        uid_rate_max = (
            min(rate_limit_max * max(1, len(self._token_table)), rate_limit_max * 16)
            if self._token_table is not None
            else rate_limit_max
        )
        self.rate_limiter = SlidingWindowRateLimiter(uid_rate_max, rate_limit_window)
        self.principal_rate_limiter = SlidingWindowRateLimiter(rate_limit_max, rate_limit_window)
        self._lifecycle = threading.Lock()
        self._workers = ListenerWorkers()
        self._listener: socket.socket | None = None
        self._bound: BoundUds | None = None
        self.socket_path: Path | None = None

    def __enter__(self) -> CoordUdsRpcServer:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()

    def start(self) -> Path:
        with self._lifecycle:
            if self._listener is not None or self._bound is not None:
                raise BrokerError("CoordUdsRpcServer is already running or awaiting stop cleanup")
            srv, bound = bind_trusted_uds(
                self._raw_socket_path,
                sandbox_root=self._sandbox_root,
                backlog=max(16, self._max_concurrent_conns * 2),
            )
            self._listener = srv
            self._bound = bound
            try:
                started = self._workers.start(
                    self._workers.serve,
                    srv,
                    self._handle_conn,
                    self._max_concurrent_conns,
                )
                if not started:
                    raise BrokerError("Failed to start CoordUdsRpcServer listener thread")
            except Exception:
                self._stop_locked()
                raise
            self.socket_path = bound.path
            return bound.path

    def stop(self) -> None:
        with self._lifecycle:
            self._stop_locked()

    def _stop_locked(self) -> None:
        if self._listener is None and self._bound is None:
            return
        self._workers.stop(self._listener, self._bound)
        self._bound = None
        self._workers = ListenerWorkers()
        self._listener = None
        self.socket_path = None

    def _lookup_token_principal(self, auth_token: Any) -> PrincipalCtx | None:
        if type(auth_token) is not str or not auth_token or self._token_table is None:
            return None
        digest = _hash_token(auth_token)
        with self._token_lock:
            entry = self._token_table.get(digest)
        if entry is not None and hmac.compare_digest(entry[0], digest):
            return entry[1]
        return None

    def _resolve_principal(self, peer_uid: int, auth_token: Any) -> PrincipalCtx | None:
        if self._token_table is not None:
            return self._lookup_token_principal(auth_token)
        if self._required_token_hash is not None:
            if type(auth_token) is not str or not auth_token:
                return None
            if not hmac.compare_digest(self._required_token_hash, _hash_token(auth_token)):
                return None
        return PrincipalCtx(role=self._role, actor_id=f"uid-{peer_uid}")

    def _validate_envelope(
        self, req: dict[str, Any], peer_uid: int
    ) -> tuple[Any, PrincipalCtx, str, dict[str, Any]] | dict[str, Any]:
        if set(req.keys()) - ALLOWED_RPC_KEYS:
            return _rpc_error(None, ERR_CODE_INVALID_REQUEST, "unknown_rpc_keys")
        req_id = req.get(_KEY_ID)
        if req_id is not None and type(req_id) not in (str, int):
            return _rpc_error(None, ERR_CODE_INVALID_REQUEST, "invalid_request_id")
        if req.get(_KEY_JSONRPC) != "2.0":
            return _rpc_error(req_id, ERR_CODE_INVALID_REQUEST, "invalid_jsonrpc_version")
        caller = self._resolve_principal(peer_uid, req.get(_KEY_AUTH_TOKEN))
        if caller is None:
            return _rpc_error(req_id, ERR_CODE_AUTH, "invalid_auth_token")
        method = req.get(_KEY_METHOD)
        if type(method) is not str or method not in ALLOWED_METHODS:
            return _rpc_error(req_id, ERR_CODE_METHOD_NOT_FOUND, "method_not_allowed")
        params = req.get(_KEY_PARAMS, {})
        if not isinstance(params, dict):
            return _rpc_error(req_id, ERR_CODE_INVALID_PARAMS, "params_must_be_object")
        return req_id, caller, method, params

    @staticmethod
    def _check_params(method: str, params: dict[str, Any]) -> str | None:
        forged = sorted(set(params.keys()) & FORBIDDEN_IDENTITY_KEYS)
        if forged:
            return f"forbidden_identity_params: {', '.join(forged)}"
        allowed = _METHOD_PARAM_ALLOWLISTS[method]
        extra = sorted(set(params.keys()) - allowed)
        if extra:
            return f"unknown_params_for_{method}: {', '.join(extra)}"
        return None

    def _dispatch_method(
        self, caller: PrincipalCtx, method: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        if method == METHOD_SEND:
            raw_refs = params.get("artifact_refs", [])
            if not isinstance(raw_refs, list):
                raise CoordValidationError("artifact_refs must be a list")
            if len(raw_refs) > MAX_ARTIFACTS_PER_MSG:
                raise CoordValidationError(
                    f"artifact_refs exceeds maximum of {MAX_ARTIFACTS_PER_MSG}"
                )
            refs = tuple(_parse_artifact_ref(item) for item in raw_refs)
            return self._hub.send(
                caller,
                target=_require_str(params, _KEY_TARGET),
                thread_id=_optional_str_default(params, "thread_id", "main"),
                msg_kind=_optional_str_default(params, "msg_kind", "prompt"),
                body_text=_require_str(params, "body_text"),
                in_reply_to=_optional_str(params, "in_reply_to"),
                artifact_refs=refs,
            )
        if method == METHOD_STATUS:
            return self._hub.status(caller, target=_optional_str(params, _KEY_TARGET))
        if method == METHOD_WAIT:
            targets, since_seq, timeout_s = _parse_wait_params(params)
            return self._hub.wait(caller, targets=targets, since_seq=since_seq, timeout_s=timeout_s)
        if method == METHOD_REVOKE:
            reason = validate_reason_text(
                _optional_str_default(params, "reason", "operator_revoked")
            )
            rev_status = self._hub.revoke(
                caller, target=_require_str(params, _KEY_TARGET), reason=reason
            )
            return _serialize_revocation(rev_status)
        return self._hub.projection(caller)

    def _execute_request(
        self, req_id: Any, caller: PrincipalCtx, method: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        param_err = self._check_params(method, params)
        if param_err is not None:
            return _rpc_error(req_id, ERR_CODE_INVALID_PARAMS, param_err)
        try:
            result = self._dispatch_method(caller, method, params)
            return _rpc_ok(req_id, result)
        except (CoordValidationError, AddressError) as exc:
            return _rpc_error(req_id, ERR_CODE_INVALID_PARAMS, str(exc))
        except CoordAuthError as exc:
            return _rpc_error(req_id, ERR_CODE_AUTH, str(exc))
        except CoordBackpressureError as exc:
            return _rpc_error(req_id, ERR_CODE_RATE_LIMIT, str(exc))
        except (CoordPolicyError, DeadlockCycleError, IncarnationMismatchError) as exc:
            return _rpc_error(req_id, ERR_CODE_POLICY, str(exc))
        except CoordError as exc:
            return _rpc_error(req_id, ERR_CODE_INTERNAL, str(exc))
        except Exception:
            return _rpc_error(req_id, ERR_CODE_INTERNAL, "internal_error")

    def _read_and_validate_conn(
        self, conn: socket.socket, peer_uid: int, *, uid_allowed: bool
    ) -> tuple[Any, PrincipalCtx, str, dict[str, Any]] | dict[str, Any]:
        # Production deployments should bind a dedicated operator UDS for full transport isolation;
        # on shared multi-principal sockets, use a tight overflow timeout for operator reserve checks.
        read_timeout = self._read_timeout if uid_allowed else min(self._read_timeout, 0.25)
        total_timeout = min(
            TOTAL_REQUEST_TIMEOUT_SECONDS, read_timeout * (3.0 if uid_allowed else 2.0)
        )
        try:
            raw_frame = read_content_length_frame(
                conn,
                max_bytes=MAX_FRAME_BYTES,
                read_timeout=read_timeout,
                total_timeout=total_timeout,
            )
            req = parse_strict_json(raw_frame, max_depth=MAX_JSON_DEPTH, max_bytes=MAX_FRAME_BYTES)
        except (FramingError, StrictJsonError) as exc:
            if not uid_allowed:
                return _rpc_error(None, ERR_CODE_RATE_LIMIT, _ERR_RATE_LIMITED)
            return _rpc_error(None, ERR_CODE_PARSE, str(exc))
        validated = self._validate_envelope(req, peer_uid)
        if isinstance(validated, dict):
            if not uid_allowed:
                return _rpc_error(None, ERR_CODE_RATE_LIMIT, _ERR_RATE_LIMITED)
            return validated
        if not uid_allowed and validated[1].role is not CoordRole.OPERATOR:
            return _rpc_error(validated[0], ERR_CODE_RATE_LIMIT, _ERR_RATE_LIMITED)
        return validated

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            peer_uid = self._peer_uid_getter(conn)
        except OSError:
            return
        if peer_uid != self._expected_uid:
            return
        uid_allowed = self.rate_limiter.allow(peer_uid)
        if not uid_allowed and not self._has_operator_principal:
            self._send(conn, _rpc_error(None, ERR_CODE_RATE_LIMIT, _ERR_RATE_LIMITED))
            return
        validated = self._read_and_validate_conn(conn, peer_uid, uid_allowed=uid_allowed)
        if isinstance(validated, dict):
            self._send(conn, validated)
            return
        req_id, caller, method, params = validated
        if self._token_table is not None and not self.principal_rate_limiter.allow(
            caller.canonical_sender
        ):
            self._send(conn, _rpc_error(req_id, ERR_CODE_RATE_LIMIT, "principal_rate_limited"))
            return
        self._send(conn, self._execute_request(req_id, caller, method, params))

    def _send(self, conn: socket.socket, payload: dict[str, Any]) -> None:
        try:
            try:
                frame = encode_content_length_frame(payload)
            except (TypeError, ValueError):
                frame = encode_content_length_frame(
                    _rpc_error(payload.get(_KEY_ID), ERR_CODE_INTERNAL, "response_serialization_error")
                )
            if len(frame) > MAX_RESPONSE_BYTES:
                frame = encode_content_length_frame(
                    _rpc_error(payload.get(_KEY_ID), ERR_CODE_INTERNAL, "response_too_large")
                )
            conn.settimeout(self._write_timeout)
            conn.sendall(frame)
        except OSError:
            pass


def uds_rpc_call(
    socket_path: Path,
    method: str,
    params: dict[str, Any],
    *,
    auth_token: str | None = None,
    timeout_s: float = 5.0,
    request_id: int | str = 1,
) -> dict[str, Any]:
    """Send one Content-Length framed JSON-RPC 2.0 request to a CoordUdsRpcServer."""
    payload: dict[str, Any] = {
        _KEY_JSONRPC: "2.0",
        _KEY_ID: request_id,
        _KEY_METHOD: method,
        _KEY_PARAMS: params,
    }
    if auth_token is not None:
        payload[_KEY_AUTH_TOKEN] = auth_token
    frame = encode_content_length_frame(payload)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout_s)
        sock.connect(str(socket_path))
        sock.sendall(frame)
        resp_raw = read_content_length_frame(
            sock,
            max_bytes=MAX_RESPONSE_BYTES,
            read_timeout=timeout_s,
            total_timeout=timeout_s,
        )
        return parse_strict_json(resp_raw, max_bytes=MAX_RESPONSE_BYTES)
    finally:
        sock.close()
