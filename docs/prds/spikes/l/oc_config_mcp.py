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
import struct
import threading
import time
import tomllib
from typing import Any

from oc_plan import PlanError, PlanOverrides, compile_plan, redact_plan_summary
from oc_schema import (
    MAX_CONFIG_FILE_BYTES,
    MUTABLE_ORCHESTRATOR_KINDS,
    PROPOSAL_ACTIONS,
    READABLE_ORCHESTRATOR_KINDS,
    SCHEMA_VERSION,
    SECURITY_DELTA_TRIGGERS,
    PolicyError,
    SchemaError,
    canonical_json,
    is_builtin_id,
    validate_doc_by_kind,
    validate_opaque_id,
)
from oc_store import ConflictError, HostConfigStore, StoreError

MAX_FRAME_BYTES = 262_144
MAX_JSON_DEPTH = 32
MAX_CONCURRENT_CONNS = 8
READ_TIMEOUT_SECONDS = 5.0
TOTAL_REQUEST_TIMEOUT_SECONDS = 15.0
MAX_PREVIEW_DRAFT_OBJECTS = 16

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
        return conn.recv(limit)

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
    headers: dict[str, str] = {}
    for line in header_bytes.decode("ascii", errors="strict").split("\r\n"):
        if ":" not in line:
            raise FramingError("Malformed header line")
        k, v = line.split(":", 1)
        lk = k.strip().lower()
        if lk in headers:
            raise FramingError(f"Duplicate header: {lk}")
        headers[lk] = v.strip()

    cl_raw = headers.get("content-length")
    if cl_raw is None or not cl_raw.isdigit():
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
    except (BlockingIOError, ConnectionResetError):
        pass
    finally:
        conn.setblocking(True)

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
    ):
        self.store = store
        self.socket_dir = socket_dir.resolve()
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self.session_token = secrets.token_hex(32)  # per-incarnation 256-bit token
        self.rate_limiter = SlidingWindowRateLimiter(rate_limit_max, rate_limit_window)
        self._conn_sem = threading.BoundedSemaphore(MAX_CONCURRENT_CONNS)
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.socket_path: Path | None = None

    def start(self) -> Path:
        self.socket_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.socket_dir, 0o700)
        sock_path = self.socket_dir / "mcp.sock"
        if sock_path.exists():
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
        if self.socket_path is not None and self.socket_path.exists():
            try:
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

            req_id = req.get("id")
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

            resp = self._dispatch(req_id, method, params)
            self._send(conn, resp)
        finally:
            try:
                conn.close()
            finally:
                self._conn_sem.release()

    def _send(self, conn: socket.socket, payload: dict[str, Any]) -> None:
        try:
            conn.sendall(encode_content_length_frame(payload))
        except OSError:
            pass

    @staticmethod
    def _ok(req_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}

    @staticmethod
    def _validate_paging(params: dict[str, Any]) -> tuple[int, int]:
        limit = params.get("limit", 50)
        if type(limit) is not int or not (1 <= limit <= 100):
            raise SchemaError("limit must be an integer in 1..100")
        cursor = params.get("cursor")
        if cursor is None:
            offset = 0
        else:
            if type(cursor) is not str or not cursor.startswith("off:") or not cursor[4:].isdigit():
                raise SchemaError("invalid paging cursor")
            offset = int(cursor[4:])
        return offset, limit

    def _dispatch(self, req_id: Any, method: str, params: dict[str, Any]) -> dict[str, Any]:
        try:
            if method == "config_schema":
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
                kind = params.get("kind")
                if kind not in READABLE_ORCHESTRATOR_KINDS:
                    raise SchemaError(f"Unsupported kind: {kind!r}")
                include_archived = bool(params.get("include_archived", False))
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
                kind = params.get("kind")
                if kind not in READABLE_ORCHESTRATOR_KINDS:
                    raise SchemaError(f"Unsupported kind: {kind!r}")
                oid = validate_opaque_id(params.get("id"), label="id")
                doc = self.store.get(kind, oid, include_archived=bool(params.get("include_archived", False)))
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
                kind = params.get("kind")
                if kind not in READABLE_ORCHESTRATOR_KINDS:
                    raise SchemaError(f"Unsupported kind: {kind!r}")
                oid = validate_opaque_id(params.get("id"), label="id")
                from_rev = params.get("from_rev")
                to_rev = params.get("to_rev")
                if type(from_rev) is not int or type(to_rev) is not int or from_rev < 1 or to_rev < 1:
                    raise SchemaError("from_rev and to_rev must be positive integers")
                a = self.store.get_revision_toml(kind, oid, from_rev).splitlines(keepends=True)
                b = self.store.get_revision_toml(kind, oid, to_rev).splitlines(keepends=True)
                diff = "".join(difflib.unified_diff(a, b, fromfile=f"r{from_rev}", tofile=f"r{to_rev}"))
                return self._ok(req_id, {"diff": diff})

            if method == "plan_preview":
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
                            dkind, tomllib.loads(dtoml), expected_id=did, for_orchestrator=True
                        )
                        entries[(dkind, did)] = ("upsert", doc)
                    view = self.store.with_in_memory_overlay(entries)

                raw_ov = params.get("overrides", {})
                if not isinstance(raw_ov, dict):
                    raise SchemaError("overrides must be object")
                ov = PlanOverrides(
                    with_mods=tuple(raw_ov.get("with_mods", ())),
                    without_mods=tuple(raw_ov.get("without_mods", ())),
                    env_bindings=dict(raw_ov.get("env_bindings", {})),
                    cli_ports=tuple(raw_ov.get("cli_ports", ())),
                )
                compiled = compile_plan(view, st_id, worker_id=worker_id, overrides=ov)
                return self._ok(req_id, redact_plan_summary(compiled))

            if method == "config_propose_revision":
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
