"""Restricted Orchestrator Config MCP Server over a private 0o700 Unix domain socket.

Pure Python standard library only. Enforces:
- Kernel SO_PEERCRED UID verification
- Early per-UID rate limiting BEFORE reading/parsing 256 KiB frames
- Content-Length framing (max 256 KiB, read/total timeouts, max 8 conns, no trailing junk)
- Strict JSON parsing (rejects duplicate keys, NaN/Infinity, unpaired surrogates, depth > 32)
- Per-incarnation 256-bit constant-time session token (rotated on restart)
- Closed READABLE / MUTABLE kind allowlists & immutable builtin/* namespace
"""

from __future__ import annotations

from collections import deque
import difflib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import threading
import time
from typing import Any

from oc_plan import PlanError, PlanOverrides, compile_plan, redact_plan_summary
from oc_schema import (
    MAX_CONFIG_FILE_BYTES,
    MUTABLE_ORCHESTRATOR_KINDS,
    PROPOSAL_ACTIONS,
    PROPOSAL_ID_RE,
    READABLE_ORCHESTRATOR_KINDS,
    SCHEMA_VERSION,
    SECURITY_DELTA_TRIGGERS,
    PolicyError,
    SchemaError,
    assert_trusted_dir,
    canonical_json,
    check_not_host_production_dir,
    check_not_in_sandbox,
    is_builtin_id,
    parse_toml_strict,
    read_regular_no_follow,
    validate_doc_by_kind,
    validate_opaque_id,
    validate_port_request,
)
from oc_store import (
    ConflictError,
    DigestMismatchError,
    ExpiredProposalError,
    HostConfigStore,
    PublishUncertainError,
    StaleProposalError,
    StoreError,
    _atomic_write_0600,
)

MAX_FRAME_BYTES = 262_144
MAX_RESPONSE_BYTES = 524_288
MAX_JSON_DEPTH = 32
MAX_CONCURRENT_CONNS = 8
READ_TIMEOUT_SECONDS = 5.0
WRITE_TIMEOUT_SECONDS = 5.0
TOTAL_REQUEST_TIMEOUT_SECONDS = 15.0
MAX_PREVIEW_DRAFT_OBJECTS = 16

OPERATOR_TOKEN_FILENAME = "operator.token"
ERR_INVALID_PROPOSAL_ID = "Invalid proposal_id"

ALLOWED_HEADERS = frozenset({"content-length", "content-type"})
ALLOWED_RPC_KEYS = frozenset({"jsonrpc", "id", "auth_token", "method", "params"})
ALLOWED_DRAFT_KEYS = frozenset({"kind", "id", "toml"})
ALLOWED_OVERRIDE_KEYS = frozenset({"with_mods", "without_mods", "env_bindings", "cli_ports"})

ALLOWED_MCP_METHODS = frozenset(
    {
        "config_list",
        "config_get",
        "config_schema",
        "config_diff",
        "config_history",
        "plan_preview",
        "config_propose_revision",
    }
)


class FramingError(ValueError):
    """Malformed or oversized Content-Length frame."""


class StrictJsonError(ValueError):
    """Strict JSON decode violation."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise StrictJsonError(f"Duplicate JSON key: {k!r}")
        out[k] = v
    return out


def _reject_constants(val: str) -> Any:
    raise StrictJsonError(f"Non-standard JSON constant rejected: {val}")


def _check_depth_and_surrogates(obj: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise StrictJsonError(f"JSON nesting depth exceeds {MAX_JSON_DEPTH}")
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise StrictJsonError("Unpaired UTF-16 surrogate rejected") from exc
    elif isinstance(obj, list):
        for item in obj:
            _check_depth_and_surrogates(item, depth + 1)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _check_depth_and_surrogates(k, depth + 1)
            _check_depth_and_surrogates(v, depth + 1)


def parse_strict_json(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
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
    except Exception as exc:
        raise StrictJsonError(f"Invalid JSON: {exc}") from exc
    _check_depth_and_surrogates(data, 0)
    if not isinstance(data, dict):
        raise StrictJsonError("JSON-RPC payload must be a JSON object")
    return data


def encode_content_length_frame(payload: dict[str, Any]) -> bytes:
    body = canonical_json(payload).encode("utf-8")
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
    conn: socket.socket, deadline: float, read_timeout: float, max_header_bytes: int = 4096
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
            raise FramingError("Header section too large")
    return bytes(buf[:header_end]), bytes(buf[header_end + 4 :])


def _parse_header_line(line: str, headers: dict[str, str]) -> None:
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in line):
        raise FramingError("Control character rejected in header")
    if ":" not in line:
        raise FramingError("Malformed header line")
    k, v = line.split(":", 1)
    lk = k.strip().lower()
    if lk not in ALLOWED_HEADERS:
        raise FramingError(f"Unsupported header rejected: {lk}")
    if lk in headers:
        raise FramingError(f"Duplicate header: {lk}")
    headers[lk] = v.strip()


def _parse_content_length(header_bytes: bytes, max_bytes: int) -> int:
    try:
        header_text = header_bytes.decode("ascii", errors="strict")
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
            raise FramingError("Pipelined trailing bytes rejected")
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
    deadline = time.monotonic() + total_timeout
    header_bytes, rest = _read_header_section(conn, deadline, read_timeout)
    content_length = _parse_content_length(header_bytes, max_bytes)
    if len(rest) > content_length:
        raise FramingError("Trailing or pipelined bytes after Content-Length frame")

    body = bytearray(rest)
    while len(body) < content_length:
        chunk = _recv_with_deadline(
            conn, min(8192, content_length - len(body) + 1), deadline, read_timeout
        )
        if not chunk:
            raise FramingError("Unexpected EOF reading body")
        body.extend(chunk)
        if len(body) > content_length:
            raise FramingError("Trailing or pipelined bytes after Content-Length frame")

    _reject_pipelined_bytes(conn, read_timeout)
    return bytes(body)


def _get_peer_uid(conn: socket.socket) -> int:
    # Linux SO_PEERCRED returns struct ucred { pid_t pid; uid_t uid; gid_t gid; } (3i)
    so_peercred = getattr(socket, "SO_PEERCRED", 17)
    raw = conn.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


class SlidingWindowRateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._hits: dict[int, deque[float]] = {}

    def allow(self, uid: int) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            q = self._hits.setdefault(uid, deque())
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                return False
            q.append(now)
            return True


def _redact_broker_services(broker_services: dict[str, Any]) -> dict[str, Any]:
    return {
        name: {
            "kind": cfg["kind"],
            "credential_delivery": cfg["credential_delivery"],
            "allow_streaming": bool(cfg.get("allow_streaming", False)),
            "has_read_only_secret": bool(cfg.get("read_only_secret_ref")),
            "has_write_secret": bool(cfg.get("write_secret_ref")),
        }
        for name, cfg in sorted(broker_services.items())
    }


def _redact_bundle_mcp(mcp_map: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for name, cfg in sorted(mcp_map.items()):
        entry = dict(cfg)
        entry.pop("allowed_cidrs", None)
        url = entry.get("url")
        if isinstance(url, str) and url.lower().startswith("https://"):
            entry["url"] = "<redacted-remote-url>"
        redacted[name] = entry
    return redacted


def _redact_object_for_orchestrator(kind: str, doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    if kind == "worker":
        # Omit private host addresses / ports
        out.pop("host", None)
        out.pop("port", None)
    elif kind == "service":
        # Expose secret slot presence metadata only (never vault/secret references)
        out["secret_slots"] = [
            {"slot": s["slot"], "target": s["target"], "mode": s["mode"], "configured": bool(s["secret_ref"])}
            for s in doc.get("secret_slots", [])
        ]
    elif kind == "bundle":
        if "broker_services" in out:
            out["broker_services"] = _redact_broker_services(doc.get("broker_services", {}))
        if "mcp" in out:
            out["mcp"] = _redact_bundle_mcp(doc.get("mcp", {}))
    return out


def _path_exists_or_symlink(path: Path) -> bool:
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False


class _BaseUdsRpcServer:
    """Shared hardened 0o700 UDS JSON-RPC server base for orchestrator & operator sockets."""

    _socket_filename: str = ""
    _conflict_files: tuple[str, ...] = ()
    _conflict_error: str = ""
    _dir_label: str = "socket_dir"
    _allowed_methods: frozenset[str] = frozenset()
    _invalid_token_error: str = "invalid_or_stale_token"

    def __init__(
        self,
        store: HostConfigStore,
        socket_dir: Path,
        *,
        expected_uid: int | None = None,
        rate_limit_max: int = 60,
        rate_limit_window: float = 60.0,
        write_timeout: float = WRITE_TIMEOUT_SECONDS,
    ):
        self.store = store
        self._raw_socket_dir = Path(socket_dir)
        self.socket_dir = self._raw_socket_dir
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self._write_timeout = write_timeout
        self.rate_limiter = SlidingWindowRateLimiter(rate_limit_max, rate_limit_window)
        self._conn_sem = threading.BoundedSemaphore(MAX_CONCURRENT_CONNS)
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.socket_path: Path | None = None

    def _expected_token(self) -> str:
        raise NotImplementedError

    def _before_bind(self) -> None:
        return None

    def _cleanup_extra(self) -> None:
        return None

    def _dispatch(self, req_id: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def start(self) -> Path:
        if self._raw_socket_dir.is_symlink():
            raise PolicyError(f"Expected non-symlink {self._dir_label}: {self._raw_socket_dir}")
        phys_dir = check_not_in_sandbox(self._raw_socket_dir, self.store.sandbox_root)
        check_not_host_production_dir(self._raw_socket_dir)
        if phys_dir.is_symlink():
            raise PolicyError(f"Expected non-symlink {self._dir_label}: {phys_dir}")
        if any(_path_exists_or_symlink(phys_dir / name) for name in self._conflict_files):
            raise PolicyError(f"{self._conflict_error}: {phys_dir}")
        phys_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(phys_dir, 0o700)
        self.socket_dir = assert_trusted_dir(phys_dir, sandbox_root=self.store.sandbox_root)
        sock_path = self.socket_dir / self._socket_filename
        try:
            st = os.lstat(sock_path)
        except FileNotFoundError:
            st = None
        if st is not None:
            if not stat.S_ISSOCK(st.st_mode):
                raise PolicyError(f"Refusing to unlink non-socket path: {sock_path}")
            sock_path.unlink()
        self._before_bind()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o177)
        try:
            srv.bind(str(sock_path))
        finally:
            os.umask(old_umask)
        os.chmod(sock_path, 0o600)
        srv.listen(16)
        srv.settimeout(0.2)
        self._sock = srv
        self.socket_path = sock_path
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return sock_path

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self.socket_path is not None:
            try:
                st = os.lstat(self.socket_path)
                if stat.S_ISSOCK(st.st_mode):
                    self.socket_path.unlink()
            except OSError:
                pass
        self._cleanup_extra()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if not self._conn_sem.acquire(blocking=False):
                conn.close()
                continue
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            t.start()

    def _validate_request_envelope(
        self, req: dict[str, Any]
    ) -> tuple[Any, str, dict[str, Any]] | dict[str, Any]:
        if set(req.keys()) - ALLOWED_RPC_KEYS:
            return self._error(None, -32600, "unknown_rpc_keys")
        req_id = req.get("id")
        if req_id is not None and not (type(req_id) is str or type(req_id) is int):
            return self._error(None, -32600, "invalid_request_id")
        if req.get("jsonrpc") != "2.0":
            return self._error(req_id, -32600, "invalid_jsonrpc_version")
        tok = req.get("auth_token")
        if type(tok) is not str or not hmac.compare_digest(tok, self._expected_token()):
            return self._error(req_id, -32001, self._invalid_token_error)
        method = req.get("method")
        if method not in self._allowed_methods:
            return self._error(req_id, -32601, "method_not_allowed")
        params = req.get("params", {})
        if not isinstance(params, dict):
            return self._error(req_id, -32602, "params_must_be_object")
        return req_id, method, params

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            peer_uid = _get_peer_uid(conn)
            if peer_uid != self.expected_uid:
                return
            # Check rate limit BEFORE reading or parsing up to 256 KiB of JSON!
            if not self.rate_limiter.allow(peer_uid):
                self._send(conn, self._error(None, -32002, "rate_limited"))
                return
            try:
                req = parse_strict_json(read_content_length_frame(conn))
            except (FramingError, StrictJsonError) as exc:
                self._send(conn, self._error(None, -32700, str(exc)))
                return
            validated = self._validate_request_envelope(req)
            if isinstance(validated, dict):
                self._send(conn, validated)
                return
            req_id, method, params = validated
            try:
                resp = self._dispatch(req_id, method, params)
            except Exception:
                resp = self._error(req_id, -32603, "internal_error")
            self._send(conn, resp)
        finally:
            try:
                conn.close()
            finally:
                self._conn_sem.release()

    def _send(self, conn: socket.socket, payload: dict[str, Any]) -> None:
        try:
            frame = encode_content_length_frame(payload)
            if len(frame) > MAX_RESPONSE_BYTES:
                frame = encode_content_length_frame(
                    self._error(payload.get("id"), -32603, "response_too_large")
                )
            conn.settimeout(self._write_timeout)
            conn.sendall(frame)
        except OSError:
            pass

    @staticmethod
    def _ok(req_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    @staticmethod
    def _check_closed_params(params: dict[str, Any], allowed: frozenset[str], method: str) -> None:
        extra = sorted(set(params.keys()) - allowed)
        if extra:
            raise SchemaError(f"Unknown params for {method}: {', '.join(extra)}")


class OrchestratorConfigMcpServer(_BaseUdsRpcServer):
    """Private 0o700 UDS JSON-RPC server mediating read-only queries & human-gated proposals."""

    _socket_filename = "mcp.sock"
    _conflict_files = ("operator.sock", OPERATOR_TOKEN_FILENAME)
    _conflict_error = "Refusing to start orchestrator MCP server in an operator socket directory"
    _dir_label = "socket_dir"
    _allowed_methods = ALLOWED_MCP_METHODS
    _invalid_token_error = "invalid_or_stale_session_token"

    def __init__(
        self,
        store: HostConfigStore,
        socket_dir: Path,
        *,
        expected_uid: int | None = None,
        rate_limit_max: int = 60,
        rate_limit_window: float = 60.0,
        write_timeout: float = WRITE_TIMEOUT_SECONDS,
    ):
        super().__init__(
            store,
            socket_dir,
            expected_uid=expected_uid,
            rate_limit_max=rate_limit_max,
            rate_limit_window=rate_limit_window,
            write_timeout=write_timeout,
        )
        self.session_token = secrets.token_hex(32)  # per-incarnation 256-bit token

    def _expected_token(self) -> str:
        return self.session_token

    @staticmethod
    def _require_bool_param(params: dict[str, Any], key: str, default: bool = False) -> bool:
        val = params.get(key, default)
        if type(val) is not bool:
            raise SchemaError(f"{key} must be boolean")
        return val

    @staticmethod
    def _validate_paging(params: dict[str, Any]) -> tuple[int, int]:
        limit = params.get("limit", 50)
        if type(limit) is not int or not (1 <= limit <= 100):
            raise SchemaError("limit must be an integer in 1..100")
        cursor = params.get("cursor")
        if cursor is None:
            return 0, limit
        if (
            type(cursor) is not str
            or not cursor.startswith("off:")
            or not (cursor[4:].isascii() and cursor[4:].isdigit())
        ):
            raise SchemaError("invalid paging cursor")
        return int(cursor[4:]), limit

    def _handle_config_schema(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(params, frozenset({"kind"}), "config_schema")
        kind = params.get("kind")
        if kind is not None and kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unknown kind: {kind!r}")
        return self._ok(
            req_id,
            {
                "schema_version": SCHEMA_VERSION,
                "readable_kinds": sorted(READABLE_ORCHESTRATOR_KINDS),
                "mutable_kinds": sorted(MUTABLE_ORCHESTRATOR_KINDS),
                "proposal_actions": sorted(PROPOSAL_ACTIONS),
                "security_delta_triggers": sorted(SECURITY_DELTA_TRIGGERS),
            },
        )

    def _handle_config_list(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(
            params, frozenset({"kind", "include_archived", "limit", "cursor"}), "config_list"
        )
        kind = params.get("kind")
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unsupported kind: {kind!r}")
        include_archived = self._require_bool_param(params, "include_archived", False)
        offset, limit = self._validate_paging(params)
        ids = self.store.list_ids(kind, include_archived=include_archived)
        page = ids[offset : offset + limit]
        items = [
            {
                "id": oid,
                "revision": self.store.get_revision(kind, oid),
                "builtin": is_builtin_id(oid),
                "archived": self.store.is_archived(kind, oid),
            }
            for oid in page
        ]
        next_cursor = f"off:{offset + limit}" if offset + limit < len(ids) else None
        return self._ok(req_id, {"items": items, "next_cursor": next_cursor})

    def _handle_config_get(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(params, frozenset({"kind", "id", "include_archived"}), "config_get")
        kind = params.get("kind")
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unsupported kind: {kind!r}")
        oid = validate_opaque_id(params.get("id"), label="id")
        include_archived = self._require_bool_param(params, "include_archived", False)
        doc = self.store.get(kind, oid, include_archived=include_archived)
        return self._ok(
            req_id,
            {
                "kind": kind,
                "id": oid,
                "revision": self.store.get_revision(kind, oid),
                "archived": self.store.is_archived(kind, oid),
                "document": _redact_object_for_orchestrator(kind, doc),
            },
        )

    def _handle_config_history(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(params, frozenset({"kind", "id", "limit", "cursor"}), "config_history")
        kind = params.get("kind")
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unsupported kind: {kind!r}")
        oid = validate_opaque_id(params.get("id"), label="id")
        offset, limit = self._validate_paging(params)
        hist = self.store.get_history(kind, oid)
        page = hist[offset : offset + limit]
        next_cursor = f"off:{offset + limit}" if offset + limit < len(hist) else None
        return self._ok(req_id, {"history": page, "next_cursor": next_cursor})

    def _handle_config_diff(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(params, frozenset({"kind", "id", "from_rev", "to_rev"}), "config_diff")
        kind = params.get("kind")
        if kind not in READABLE_ORCHESTRATOR_KINDS:
            raise SchemaError(f"Unsupported kind: {kind!r}")
        oid = validate_opaque_id(params.get("id"), label="id")
        from_rev = params.get("from_rev")
        to_rev = params.get("to_rev")
        if type(from_rev) is not int or type(to_rev) is not int or from_rev < 1 or to_rev < 1:
            raise SchemaError("from_rev and to_rev must be positive integers")
        doc_a = _redact_object_for_orchestrator(kind, self.store.get_revision_doc(kind, oid, from_rev))
        doc_b = _redact_object_for_orchestrator(kind, self.store.get_revision_doc(kind, oid, to_rev))
        a = (json.dumps(doc_a, indent=2, sort_keys=True) + "\n").splitlines(keepends=True)
        b = (json.dumps(doc_b, indent=2, sort_keys=True) + "\n").splitlines(keepends=True)
        diff = "".join(difflib.unified_diff(a, b, fromfile=f"r{from_rev}", tofile=f"r{to_rev}"))
        return self._ok(req_id, {"diff": diff})

    @staticmethod
    def _parse_draft_entry(item: Any) -> tuple[str, str, dict[str, Any]]:
        if not isinstance(item, dict):
            raise SchemaError("draft entry must be object")
        extra_draft = sorted(set(item.keys()) - ALLOWED_DRAFT_KEYS)
        if extra_draft:
            raise SchemaError(f"Unknown keys in draft entry: {', '.join(extra_draft)}")
        dkind = item.get("kind")
        if dkind not in MUTABLE_ORCHESTRATOR_KINDS:
            raise PolicyError(f"Draft kind {dkind!r} not allowed")
        did = validate_opaque_id(item.get("id"), label="draft.id")
        if is_builtin_id(did):
            raise PolicyError("Draft may not overlay builtin/*")
        dtoml = item.get("toml")
        if type(dtoml) is not str or len(dtoml.encode("utf-8")) > MAX_CONFIG_FILE_BYTES:
            raise SchemaError("draft.toml must be a bounded string")
        doc = validate_doc_by_kind(
            dkind,
            parse_toml_strict(dtoml, context=f"draft({dkind}/{did})"),
            expected_id=did,
            for_orchestrator=True,
        )
        return dkind, did, doc

    def _build_preview_view(self, draft: Any) -> Any:
        if draft is None:
            return self.store
        if not isinstance(draft, list) or len(draft) > MAX_PREVIEW_DRAFT_OBJECTS:
            raise SchemaError(f"draft must be a list of at most {MAX_PREVIEW_DRAFT_OBJECTS} items")
        entries: dict[tuple[str, str], tuple[str, dict[str, Any] | None]] = {}
        for item in draft:
            dkind, did, doc = self._parse_draft_entry(item)
            if (dkind, did) in entries:
                raise SchemaError(f"Duplicate draft entry for {dkind}/{did}")
            entries[(dkind, did)] = ("upsert", doc)
        return self.store.with_in_memory_overlay(entries)

    @staticmethod
    def _parse_preview_overrides(raw_ov: Any) -> PlanOverrides:
        if not isinstance(raw_ov, dict):
            raise SchemaError("overrides must be object")
        extra_ov = sorted(set(raw_ov.keys()) - ALLOWED_OVERRIDE_KEYS)
        if extra_ov:
            raise SchemaError(f"Unknown keys in overrides: {', '.join(extra_ov)}")
        raw_with = raw_ov.get("with_mods", [])
        raw_without = raw_ov.get("without_mods", [])
        if not isinstance(raw_with, list) or not isinstance(raw_without, list):
            raise SchemaError("overrides.with_mods and without_mods must be lists")
        with_mods = tuple(validate_opaque_id(x, label="overrides.with_mods[]") for x in raw_with)
        without_mods = tuple(validate_opaque_id(x, label="overrides.without_mods[]") for x in raw_without)
        raw_env = raw_ov.get("env_bindings", {})
        if not isinstance(raw_env, dict):
            raise SchemaError("overrides.env_bindings must be an object")
        env_bindings: dict[str, str] = {}
        for ek, ev in raw_env.items():
            if type(ek) is not str or type(ev) is not str:
                raise SchemaError("overrides.env_bindings keys and values must be strings")
            env_bindings[ek] = ev
        raw_ports = raw_ov.get("cli_ports", [])
        if not isinstance(raw_ports, list):
            raise SchemaError("overrides.cli_ports must be a list")
        cli_ports = tuple(validate_port_request(p, "overrides.cli_ports[]") for p in raw_ports)
        return PlanOverrides(
            with_mods=with_mods,
            without_mods=without_mods,
            env_bindings=env_bindings,
            cli_ports=cli_ports,
        )

    def _handle_plan_preview(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(
            params, frozenset({"sandbox_type", "worker", "draft", "overrides"}), "plan_preview"
        )
        st_id = validate_opaque_id(params.get("sandbox_type"), label="sandbox_type")
        worker_id = params.get("worker")
        if worker_id is not None:
            validate_opaque_id(worker_id, label="worker")
        view = self._build_preview_view(params.get("draft"))
        ov = self._parse_preview_overrides(params.get("overrides", {}))
        compiled = compile_plan(view, st_id, worker_id=worker_id, overrides=ov)
        return self._ok(req_id, redact_plan_summary(compiled))

    def _handle_config_propose_revision(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(
            params, frozenset({"kind", "id", "action", "proposed_toml"}), "config_propose_revision"
        )
        kind = params.get("kind")
        if kind not in MUTABLE_ORCHESTRATOR_KINDS:
            return self._error(req_id, -32003, "kind_or_namespace_not_mutable")
        oid = validate_opaque_id(params.get("id"), label="id")
        if is_builtin_id(oid):
            return self._error(req_id, -32003, "kind_or_namespace_not_mutable")
        prop = self.store.create_proposal(
            kind=kind,
            obj_id=oid,
            action=params.get("action", "upsert"),
            proposed_toml=params.get("proposed_toml"),
        )
        return self._ok(
            req_id,
            {
                "proposal_id": prop["id"],
                "proposal_digest": prop["digest"],
                "controller_request_id": prop["controller_request_id"],
                "security_delta": prop["security_delta"],
                "status": prop["status"],
            },
        )

    def _dispatch(self, req_id: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "config_schema": self._handle_config_schema,
            "config_list": self._handle_config_list,
            "config_get": self._handle_config_get,
            "config_history": self._handle_config_history,
            "config_diff": self._handle_config_diff,
            "plan_preview": self._handle_plan_preview,
            "config_propose_revision": self._handle_config_propose_revision,
        }
        handler = handlers.get(method)
        if handler is None:
            return self._error(req_id, -32601, "method_not_allowed")
        try:
            return handler(req_id, params)
        except PolicyError as exc:
            return self._error(req_id, -32003, str(exc))
        except ConflictError as exc:
            return self._error(req_id, -32004, str(exc))
        except (SchemaError, PlanError, KeyError, StoreError) as exc:
            return self._error(req_id, -32602, str(exc))


def call_mcp_uds(
    socket_path: Path,
    payload: dict[str, Any],
    *,
    raw_override: bytes | None = None,
) -> dict[str, Any]:
    """Helper client for testing Content-Length framed JSON-RPC calls over UDS."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as cli:
        cli.settimeout(5.0)
        cli.connect(str(socket_path))
        cli.sendall(raw_override if raw_override is not None else encode_content_length_frame(payload))
        resp_bytes = read_content_length_frame(cli)
        return parse_strict_json(resp_bytes)


ALLOWED_OPERATOR_METHODS = frozenset(
    {
        "operator_approve",
        "operator_reject",
        "operator_reconcile",
        "operator_status",
    }
)

_OPERATOR_ERROR_MAP: tuple[tuple[type[Exception], int], ...] = (
    (StaleProposalError, -32010),
    (DigestMismatchError, -32011),
    (ExpiredProposalError, -32012),
    (PublishUncertainError, -32013),
    (ConflictError, -32004),
    (PolicyError, -32003),
    (SchemaError, -32602),
    (KeyError, -32602),
    (StoreError, -32602),
)


class OperatorControlServer(_BaseUdsRpcServer):
    """Host-only 0o700 UDS control server for cross-process operator approve/reject/reconcile.

    Strictly separate from OrchestratorConfigMcpServer and NEVER mounted into the
    orchestrator sandbox. Shares the live HostConfigStore and oc_controller.Controller
    incarnation; restarting this server rotates both incarnation and operator.token so
    prior-incarnation proposals fail closed.
    """

    _socket_filename = "operator.sock"
    _conflict_files = ("mcp.sock",)
    _conflict_error = "Refusing to start host-only operator control server in an orchestrator socket directory"
    _dir_label = "operator socket_dir"
    _allowed_methods = ALLOWED_OPERATOR_METHODS
    _invalid_token_error = "invalid_or_stale_operator_token"

    def __init__(
        self,
        store: HostConfigStore,
        socket_dir: Path,
        *,
        expected_uid: int | None = None,
        rate_limit_max: int = 60,
        rate_limit_window: float = 60.0,
        write_timeout: float = WRITE_TIMEOUT_SECONDS,
    ):
        super().__init__(
            store,
            socket_dir,
            expected_uid=expected_uid,
            rate_limit_max=rate_limit_max,
            rate_limit_window=rate_limit_window,
            write_timeout=write_timeout,
        )
        self.operator_token = secrets.token_hex(32)
        self.token_path: Path | None = None

    def _expected_token(self) -> str:
        return self.operator_token

    def _before_bind(self) -> None:
        tok_path = self.socket_dir / OPERATOR_TOKEN_FILENAME
        _atomic_write_0600(tok_path, (self.operator_token + "\n").encode("ascii"))
        self.token_path = tok_path

    def _cleanup_extra(self) -> None:
        if self.token_path is not None:
            try:
                st = os.lstat(self.token_path)
                if stat.S_ISREG(st.st_mode):
                    self.token_path.unlink()
            except OSError:
                pass

    def _verify_config_dir_param(self, params: dict[str, Any]) -> None:
        cfg = params.get("config_dir")
        if cfg is not None and (type(cfg) is not str or cfg != str(self.store.config_dir)):
            raise PolicyError(
                f"Operator socket serves config_dir {str(self.store.config_dir)!r}, not {cfg!r}"
            )

    @staticmethod
    def _require_proposal_id(params: dict[str, Any]) -> str:
        pid = params.get("proposal_id")
        if type(pid) is not str or PROPOSAL_ID_RE.fullmatch(pid) is None:
            raise SchemaError(ERR_INVALID_PROPOSAL_ID)
        return pid

    def _handle_status(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(params, frozenset(), "operator_status")
        return self._ok(
            req_id,
            {
                "incarnation": self.store.incarnation,
                "store_revision": self.store.store_revision,
                "config_dir": str(self.store.config_dir),
            },
        )

    def _handle_approve(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(params, frozenset({"proposal_id", "digest", "config_dir"}), "operator_approve")
        self._verify_config_dir_param(params)
        pid = self._require_proposal_id(params)
        digest = params.get("digest")
        if type(digest) is not str or not digest:
            raise SchemaError("Invalid digest")
        new_rev = self.store.approve_proposal(pid, digest)
        return self._ok(req_id, {"approved": True, "revision": new_rev})

    def _handle_reject(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(params, frozenset({"proposal_id", "config_dir"}), "operator_reject")
        self._verify_config_dir_param(params)
        prop = self.store.reject_proposal(self._require_proposal_id(params))
        return self._ok(req_id, {"rejected": True, "status": prop["status"]})

    def _handle_reconcile(self, req_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        self._check_closed_params(params, frozenset({"proposal_id", "config_dir"}), "operator_reconcile")
        self._verify_config_dir_param(params)
        settled = self.store.reconcile_proposal(self._require_proposal_id(params))
        return self._ok(req_id, {"reconciled": True, "status": settled})

    def _dispatch(self, req_id: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "operator_status": self._handle_status,
            "operator_approve": self._handle_approve,
            "operator_reject": self._handle_reject,
            "operator_reconcile": self._handle_reconcile,
        }
        handler = handlers.get(method)
        if handler is None:
            return self._error(req_id, -32601, "method_not_allowed")
        try:
            return handler(req_id, params)
        except Exception as exc:
            for exc_cls, code in _OPERATOR_ERROR_MAP:
                if isinstance(exc, exc_cls):
                    return self._error(req_id, code, str(exc))
            raise


_CLIENT_ERROR_MAP: dict[int, type[Exception]] = {
    -32010: StaleProposalError,
    -32011: DigestMismatchError,
    -32012: ExpiredProposalError,
    -32013: PublishUncertainError,
    -32004: ConflictError,
    -32001: PolicyError,
    -32003: PolicyError,
    -32602: SchemaError,
}


def _validate_operator_socket(sock_p: Path, sandbox_root: Path | None) -> tuple[Path, Path]:
    if sock_p.is_symlink():
        raise PolicyError(f"Expected non-symlink operator Unix socket: {sock_p}")
    phys_sock = check_not_in_sandbox(sock_p, sandbox_root)
    check_not_host_production_dir(sock_p)
    parent = assert_trusted_dir(phys_sock.parent, sandbox_root=sandbox_root)
    st = os.lstat(phys_sock)
    if not stat.S_ISSOCK(st.st_mode):
        raise PolicyError(f"Expected operator Unix socket: {phys_sock}")
    if st.st_uid != os.geteuid():
        raise PolicyError(f"Operator socket not owned by current user: {phys_sock}")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise PolicyError(f"Operator socket permissions too open (require 0600): {phys_sock}")
    return phys_sock, parent


def _raise_operator_rpc_error(err_obj: dict[str, Any]) -> None:
    code = err_obj.get("code")
    msg = str(err_obj.get("message", "operator_error"))
    exc_cls = _CLIENT_ERROR_MAP.get(code)
    if exc_cls is not None:
        raise exc_cls(msg)
    raise StoreError(f"Operator RPC failed ({code}): {msg}")


def call_operator_uds(
    socket_path: Path,
    method: str,
    params: dict[str, Any],
    *,
    token: str | None = None,
    expected_config_dir: Path | None = None,
    expected_peer_uid: int | None = None,
    sandbox_root: Path | None = None,
) -> dict[str, Any]:
    """Invoke the host-only OperatorControlServer UDS and raise typed store/policy errors on failure."""
    phys_sock, parent = _validate_operator_socket(Path(socket_path), sandbox_root)
    want_uid = os.geteuid() if expected_peer_uid is None else expected_peer_uid
    if token is None:
        tok_path = parent / OPERATOR_TOKEN_FILENAME
        token = read_regular_no_follow(
            tok_path,
            max_bytes=256,
            require_owner_only=True,
            confined_root=parent,
            sandbox_root=sandbox_root,
        ).decode("ascii").strip()

    send_params = dict(params)
    if expected_config_dir is not None:
        exp_phys = check_not_in_sandbox(Path(expected_config_dir), sandbox_root)
        check_not_host_production_dir(Path(expected_config_dir))
        if method != "operator_status":
            send_params["config_dir"] = str(exp_phys)

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "auth_token": token,
        "method": method,
        "params": send_params,
    }
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as cli:
        cli.settimeout(5.0)
        cli.connect(str(phys_sock))
        # Verify server SO_PEERCRED UID BEFORE sending operator.token!
        if _get_peer_uid(cli) != want_uid:
            raise PolicyError("Operator socket peer UID mismatch; refusing to send operator token")
        cli.sendall(encode_content_length_frame(payload))
        resp = parse_strict_json(read_content_length_frame(cli))

    if "error" in resp:
        _raise_operator_rpc_error(resp["error"])
    return resp["result"]
