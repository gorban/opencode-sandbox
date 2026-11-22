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


def read_content_length_frame(
    conn: socket.socket,
    *,
    max_bytes: int = MAX_FRAME_BYTES,
    read_timeout: float = READ_TIMEOUT_SECONDS,
    total_timeout: float = TOTAL_REQUEST_TIMEOUT_SECONDS,
) -> bytes:
    deadline = time.monotonic() + total_timeout
    buf = bytearray()
    header_end = -1
    max_header_bytes = 4096

    def _recv_into(limit: int) -> bytes:
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise FramingError("Request deadline exceeded")
        conn.settimeout(min(read_timeout, rem))
        try:
            return conn.recv(limit)
        except (TimeoutError, socket.timeout) as exc:
            raise FramingError("Socket read timeout") from exc
        except OSError as exc:
            raise FramingError(f"Socket read error: {exc}") from exc

    while header_end == -1:
        chunk = _recv_into(1024)
        if not chunk:
            raise FramingError("Unexpected EOF reading headers")
        buf.extend(chunk)
        header_end = buf.find(b"\r\n\r\n")
        if header_end == -1 and len(buf) > max_header_bytes:
            raise FramingError("Header section too large")

    header_bytes = bytes(buf[:header_end])
    rest = bytes(buf[header_end + 4 :])
    try:
        header_text = header_bytes.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise FramingError("Non-ASCII header bytes rejected") from exc

    headers: dict[str, str] = {}
    for line in header_text.split("\r\n"):
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

    cl_raw = headers.get("content-length")
    if cl_raw is None or not (cl_raw.isascii() and cl_raw.isdigit()):
        raise FramingError("Missing or invalid Content-Length")
    content_length = int(cl_raw)
    if content_length <= 0 or content_length > max_bytes:
        raise FramingError(f"Content-Length {content_length} out of bounds (1..{max_bytes})")
    if len(rest) > content_length:
        raise FramingError("Trailing or pipelined bytes after Content-Length frame")

    body = bytearray(rest)
    while len(body) < content_length:
        chunk = _recv_into(min(8192, content_length - len(body) + 1))
        if not chunk:
            raise FramingError("Unexpected EOF reading body")
        body.extend(chunk)
        if len(body) > content_length:
            raise FramingError("Trailing or pipelined bytes after Content-Length frame")

    # Non-blocking peek to detect immediately pipelined junk bytes
    conn.setblocking(False)
    try:
        extra = conn.recv(1, socket.MSG_PEEK)
        if extra:
            raise FramingError("Pipelined trailing bytes rejected")
    except (BlockingIOError, ConnectionResetError, OSError):
        pass
    finally:
        conn.settimeout(read_timeout)

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
    return out


class OrchestratorConfigMcpServer:
    """Private 0o700 UDS JSON-RPC server mediating read-only queries & human-gated proposals."""

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
        self.session_token = secrets.token_hex(32)  # per-incarnation 256-bit token
        self.rate_limiter = SlidingWindowRateLimiter(rate_limit_max, rate_limit_window)
        self._conn_sem = threading.BoundedSemaphore(MAX_CONCURRENT_CONNS)
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.socket_path: Path | None = None

    def start(self) -> Path:
        check_not_in_sandbox(self._raw_socket_dir, self.store.sandbox_root)
        check_not_host_production_dir(self._raw_socket_dir)
        if self._raw_socket_dir.is_symlink():
            raise PolicyError(f"Expected non-symlink socket_dir: {self._raw_socket_dir}")
        self._raw_socket_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._raw_socket_dir, 0o700)
        self.socket_dir = assert_trusted_dir(self._raw_socket_dir, sandbox_root=self.store.sandbox_root)
        sock_path = self.socket_dir / "mcp.sock"
        try:
            st = os.lstat(sock_path)
        except FileNotFoundError:
            st = None
        if st is not None:
            if not stat.S_ISSOCK(st.st_mode):
                raise PolicyError(f"Refusing to unlink non-socket path: {sock_path}")
            sock_path.unlink()
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

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._conn_sem.acquire(blocking=False):
                conn.close()
                continue
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            t.start()

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
                raw_frame = read_content_length_frame(conn)
                req = parse_strict_json(raw_frame)
            except (FramingError, StrictJsonError) as exc:
                self._send(conn, self._error(None, -32700, str(exc)))
                return

            extra_rpc = set(req.keys()) - ALLOWED_RPC_KEYS
            if extra_rpc:
                self._send(conn, self._error(None, -32600, "unknown_rpc_keys"))
                return

            req_id = req.get("id")
            if req_id is not None and not (type(req_id) is str or type(req_id) is int):
                self._send(conn, self._error(None, -32600, "invalid_request_id"))
                return
            if req.get("jsonrpc") != "2.0":
                self._send(conn, self._error(req_id, -32600, "invalid_jsonrpc_version"))
                return
            tok = req.get("auth_token")
            if type(tok) is not str or not hmac.compare_digest(tok, self.session_token):
                self._send(conn, self._error(req_id, -32001, "invalid_or_stale_session_token"))
                return

            method = req.get("method")
            if method not in ALLOWED_MCP_METHODS:
                self._send(conn, self._error(req_id, -32601, "method_not_allowed"))
                return
            params = req.get("params", {})
            if not isinstance(params, dict):
                self._send(conn, self._error(req_id, -32602, "params_must_be_object"))
                return

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
        except (TimeoutError, OSError):
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
            offset = 0
        else:
            if (
                type(cursor) is not str
                or not cursor.startswith("off:")
                or not (cursor[4:].isascii() and cursor[4:].isdigit())
            ):
                raise SchemaError("invalid paging cursor")
            offset = int(cursor[4:])
        return offset, limit

    def _dispatch(self, req_id: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
        try:
            if method == "config_schema":
                self._check_closed_params(params, frozenset({"kind"}), method)
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

            if method == "config_list":
                self._check_closed_params(
                    params, frozenset({"kind", "include_archived", "limit", "cursor"}), method
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

            if method == "config_get":
                self._check_closed_params(params, frozenset({"kind", "id", "include_archived"}), method)
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

            if method == "config_history":
                self._check_closed_params(params, frozenset({"kind", "id", "limit", "cursor"}), method)
                kind = params.get("kind")
                if kind not in READABLE_ORCHESTRATOR_KINDS:
                    raise SchemaError(f"Unsupported kind: {kind!r}")
                oid = validate_opaque_id(params.get("id"), label="id")
                offset, limit = self._validate_paging(params)
                hist = self.store.get_history(kind, oid)
                page = hist[offset : offset + limit]
                next_cursor = f"off:{offset + limit}" if offset + limit < len(hist) else None
                return self._ok(req_id, {"history": page, "next_cursor": next_cursor})

            if method == "config_diff":
                self._check_closed_params(params, frozenset({"kind", "id", "from_rev", "to_rev"}), method)
                kind = params.get("kind")
                if kind not in READABLE_ORCHESTRATOR_KINDS:
                    raise SchemaError(f"Unsupported kind: {kind!r}")
                oid = validate_opaque_id(params.get("id"), label="id")
                from_rev = params.get("from_rev")
                to_rev = params.get("to_rev")
                if type(from_rev) is not int or type(to_rev) is not int or from_rev < 1 or to_rev < 1:
                    raise SchemaError("from_rev and to_rev must be positive integers")
                doc_a = _redact_object_for_orchestrator(
                    kind, self.store.get_revision_doc(kind, oid, from_rev)
                )
                doc_b = _redact_object_for_orchestrator(
                    kind, self.store.get_revision_doc(kind, oid, to_rev)
                )
                a = (json.dumps(doc_a, indent=2, sort_keys=True) + "\n").splitlines(keepends=True)
                b = (json.dumps(doc_b, indent=2, sort_keys=True) + "\n").splitlines(keepends=True)
                diff = "".join(difflib.unified_diff(a, b, fromfile=f"r{from_rev}", tofile=f"r{to_rev}"))
                return self._ok(req_id, {"diff": diff})

            if method == "plan_preview":
                self._check_closed_params(
                    params, frozenset({"sandbox_type", "worker", "draft", "overrides"}), method
                )
                st_id = validate_opaque_id(params.get("sandbox_type"), label="sandbox_type")
                worker_id = params.get("worker")
                if worker_id is not None:
                    validate_opaque_id(worker_id, label="worker")
                draft = params.get("draft")
                view: Any = self.store
                if draft is not None:
                    if not isinstance(draft, list) or len(draft) > MAX_PREVIEW_DRAFT_OBJECTS:
                        raise SchemaError(f"draft must be a list of at most {MAX_PREVIEW_DRAFT_OBJECTS} items")
                    entries: dict[tuple[str, str], tuple[str, dict[str, Any] | None]] = {}
                    for item in draft:
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
                        if (dkind, did) in entries:
                            raise SchemaError(f"Duplicate draft entry for {dkind}/{did}")
                        dtoml = item.get("toml")
                        if type(dtoml) is not str or len(dtoml.encode("utf-8")) > MAX_CONFIG_FILE_BYTES:
                            raise SchemaError("draft.toml must be a bounded string")
                        doc = validate_doc_by_kind(
                            dkind,
                            parse_toml_strict(dtoml, context=f"draft({dkind}/{did})"),
                            expected_id=did,
                            for_orchestrator=True,
                        )
                        entries[(dkind, did)] = ("upsert", doc)
                    view = self.store.with_in_memory_overlay(entries)

                raw_ov = params.get("overrides", {})
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
                without_mods = tuple(
                    validate_opaque_id(x, label="overrides.without_mods[]") for x in raw_without
                )

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
                cli_ports = tuple(
                    validate_port_request(p, "overrides.cli_ports[]") for p in raw_ports
                )

                ov = PlanOverrides(
                    with_mods=with_mods,
                    without_mods=without_mods,
                    env_bindings=env_bindings,
                    cli_ports=cli_ports,
                )
                compiled = compile_plan(view, st_id, worker_id=worker_id, overrides=ov)
                return self._ok(req_id, redact_plan_summary(compiled))

            if method == "config_propose_revision":
                self._check_closed_params(
                    params, frozenset({"kind", "id", "action", "proposed_toml"}), method
                )
                kind = params.get("kind")
                if kind not in MUTABLE_ORCHESTRATOR_KINDS:
                    return self._error(req_id, -32003, "kind_or_namespace_not_mutable")
                oid = validate_opaque_id(params.get("id"), label="id")
                if is_builtin_id(oid):
                    return self._error(req_id, -32003, "kind_or_namespace_not_mutable")
                action = params.get("action", "upsert")
                proposed_toml = params.get("proposed_toml")
                prop = self.store.create_proposal(
                    kind=kind,
                    obj_id=oid,
                    action=action,
                    proposed_toml=proposed_toml,
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

            return self._error(req_id, -32601, "method_not_allowed")
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


class OperatorControlServer:
    """Host-only 0o700 UDS control server for cross-process operator approve/reject/reconcile.

    Strictly separate from OrchestratorConfigMcpServer and NEVER mounted into the
    orchestrator sandbox. Shares the live HostConfigStore and oc_controller.Controller
    incarnation; restarting this server rotates both incarnation and operator.token so
    prior-incarnation proposals fail closed.
    """

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
        self.operator_token = secrets.token_hex(32)
        self.rate_limiter = SlidingWindowRateLimiter(rate_limit_max, rate_limit_window)
        self._conn_sem = threading.BoundedSemaphore(MAX_CONCURRENT_CONNS)
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.socket_path: Path | None = None
        self.token_path: Path | None = None

    def start(self) -> Path:
        check_not_in_sandbox(self._raw_socket_dir, self.store.sandbox_root)
        check_not_host_production_dir(self._raw_socket_dir)
        if self._raw_socket_dir.is_symlink():
            raise PolicyError(f"Expected non-symlink operator socket_dir: {self._raw_socket_dir}")
        self._raw_socket_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._raw_socket_dir, 0o700)
        self.socket_dir = assert_trusted_dir(self._raw_socket_dir, sandbox_root=self.store.sandbox_root)
        sock_path = self.socket_dir / "operator.sock"
        tok_path = self.socket_dir / "operator.token"
        try:
            st = os.lstat(sock_path)
        except FileNotFoundError:
            st = None
        if st is not None:
            if not stat.S_ISSOCK(st.st_mode):
                raise PolicyError(f"Refusing to unlink non-socket path: {sock_path}")
            sock_path.unlink()
        _atomic_write_0600(tok_path, (self.operator_token + "\n").encode("ascii"))
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
        self.token_path = tok_path
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
        if self.token_path is not None:
            try:
                st = os.lstat(self.token_path)
                if stat.S_ISREG(st.st_mode):
                    self.token_path.unlink()
            except OSError:
                pass

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._conn_sem.acquire(blocking=False):
                conn.close()
                continue
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            t.start()

    def _send(self, conn: socket.socket, payload: dict[str, Any]) -> None:
        try:
            frame = encode_content_length_frame(payload)
            if len(frame) > MAX_RESPONSE_BYTES:
                frame = encode_content_length_frame(
                    OrchestratorConfigMcpServer._error(payload.get("id"), -32603, "response_too_large")
                )
            conn.settimeout(self._write_timeout)
            conn.sendall(frame)
        except (TimeoutError, OSError):
            pass

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            peer_uid = _get_peer_uid(conn)
            if peer_uid != self.expected_uid:
                return
            if not self.rate_limiter.allow(peer_uid):
                self._send(conn, OrchestratorConfigMcpServer._error(None, -32002, "rate_limited"))
                return
            try:
                raw_frame = read_content_length_frame(conn)
                req = parse_strict_json(raw_frame)
            except (FramingError, StrictJsonError) as exc:
                self._send(conn, OrchestratorConfigMcpServer._error(None, -32700, str(exc)))
                return

            extra_rpc = set(req.keys()) - ALLOWED_RPC_KEYS
            if extra_rpc:
                self._send(conn, OrchestratorConfigMcpServer._error(None, -32600, "unknown_rpc_keys"))
                return
            req_id = req.get("id")
            if req_id is not None and not (type(req_id) is str or type(req_id) is int):
                self._send(conn, OrchestratorConfigMcpServer._error(None, -32600, "invalid_request_id"))
                return
            if req.get("jsonrpc") != "2.0":
                self._send(conn, OrchestratorConfigMcpServer._error(req_id, -32600, "invalid_jsonrpc_version"))
                return
            tok = req.get("auth_token")
            if type(tok) is not str or not hmac.compare_digest(tok, self.operator_token):
                self._send(
                    conn, OrchestratorConfigMcpServer._error(req_id, -32001, "invalid_or_stale_operator_token")
                )
                return
            method = req.get("method")
            if method not in ALLOWED_OPERATOR_METHODS:
                self._send(conn, OrchestratorConfigMcpServer._error(req_id, -32601, "method_not_allowed"))
                return
            params = req.get("params", {})
            if not isinstance(params, dict):
                self._send(conn, OrchestratorConfigMcpServer._error(req_id, -32602, "params_must_be_object"))
                return
            try:
                resp = self._dispatch(req_id, method, params)
            except Exception:
                resp = OrchestratorConfigMcpServer._error(req_id, -32603, "internal_error")
            self._send(conn, resp)
        finally:
            try:
                conn.close()
            finally:
                self._conn_sem.release()

    def _dispatch(self, req_id: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
        ok = OrchestratorConfigMcpServer._ok
        err = OrchestratorConfigMcpServer._error
        try:
            if method == "operator_status":
                OrchestratorConfigMcpServer._check_closed_params(params, frozenset(), method)
                return ok(
                    req_id,
                    {
                        "incarnation": self.store.incarnation,
                        "store_revision": self.store.store_revision,
                    },
                )
            if method == "operator_approve":
                OrchestratorConfigMcpServer._check_closed_params(
                    params, frozenset({"proposal_id", "digest"}), method
                )
                pid = params.get("proposal_id")
                digest = params.get("digest")
                if type(pid) is not str or PROPOSAL_ID_RE.fullmatch(pid) is None:
                    raise SchemaError("Invalid proposal_id")
                if type(digest) is not str or not digest:
                    raise SchemaError("Invalid digest")
                new_rev = self.store.approve_proposal(pid, digest)
                return ok(req_id, {"approved": True, "revision": new_rev})
            if method == "operator_reject":
                OrchestratorConfigMcpServer._check_closed_params(params, frozenset({"proposal_id"}), method)
                pid = params.get("proposal_id")
                if type(pid) is not str or PROPOSAL_ID_RE.fullmatch(pid) is None:
                    raise SchemaError("Invalid proposal_id")
                prop = self.store.reject_proposal(pid)
                return ok(req_id, {"rejected": True, "status": prop["status"]})
            if method == "operator_reconcile":
                OrchestratorConfigMcpServer._check_closed_params(params, frozenset({"proposal_id"}), method)
                pid = params.get("proposal_id")
                if type(pid) is not str or PROPOSAL_ID_RE.fullmatch(pid) is None:
                    raise SchemaError("Invalid proposal_id")
                settled = self.store.reconcile_proposal(pid)
                return ok(req_id, {"reconciled": True, "status": settled})
            return err(req_id, -32601, "method_not_allowed")
        except StaleProposalError as exc:
            return err(req_id, -32010, str(exc))
        except DigestMismatchError as exc:
            return err(req_id, -32011, str(exc))
        except ExpiredProposalError as exc:
            return err(req_id, -32012, str(exc))
        except PublishUncertainError as exc:
            return err(req_id, -32013, str(exc))
        except ConflictError as exc:
            return err(req_id, -32004, str(exc))
        except PolicyError as exc:
            return err(req_id, -32003, str(exc))
        except (SchemaError, KeyError, StoreError) as exc:
            return err(req_id, -32602, str(exc))


def call_operator_uds(
    socket_path: Path,
    method: str,
    params: dict[str, Any],
    *,
    token: str | None = None,
    sandbox_root: Path | None = None,
) -> dict[str, Any]:
    """Invoke the host-only OperatorControlServer UDS and raise typed store/policy errors on failure."""
    sock_p = Path(socket_path)
    check_not_in_sandbox(sock_p, sandbox_root)
    check_not_host_production_dir(sock_p)
    parent = assert_trusted_dir(sock_p.parent, sandbox_root=sandbox_root)
    st = os.lstat(sock_p)
    if not stat.S_ISSOCK(st.st_mode):
        raise PolicyError(f"Expected operator Unix socket: {sock_p}")
    if token is None:
        tok_path = parent / "operator.token"
        token = read_regular_no_follow(
            tok_path,
            max_bytes=256,
            require_owner_only=True,
            confined_root=parent,
            sandbox_root=sandbox_root,
        ).decode("ascii").strip()
    resp = call_mcp_uds(
        sock_p,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "auth_token": token,
            "method": method,
            "params": params,
        },
    )
    if "error" in resp:
        code = resp["error"].get("code")
        msg = str(resp["error"].get("message", "operator_error"))
        if code == -32010:
            raise StaleProposalError(msg)
        if code == -32011:
            raise DigestMismatchError(msg)
        if code == -32012:
            raise ExpiredProposalError(msg)
        if code == -32013:
            raise PublishUncertainError(msg)
        if code == -32004:
            raise ConflictError(msg)
        if code in (-32001, -32003):
            raise PolicyError(msg)
        if code == -32602:
            raise SchemaError(msg)
        raise StoreError(f"Operator RPC failed ({code}): {msg}")
    return resp["result"]
