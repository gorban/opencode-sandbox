"""Host-side interactive ChatGPT Responses broker and foreground pod supervisor."""

from contextlib import ExitStack, contextmanager, nullcontext, suppress
from dataclasses import dataclass
import fcntl
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

from .cli import Reason, RouteUnavailable, StreamTerminal, report_failure
from .connection import ConnectionError
from .exposure import ExposureError, ExposureLedger
from .live import make_backend
from .profiles import ProfileError
from .managed import relay as relay_mod
from .managed.runtime import (
    HOST_SPAWN,
    IMAGE_ID,
    MOUNT_LABEL,
    PROCESS_LABEL,
    SHARED_TMP,
    account_home,
    atomic_write,
    check_devbox,
    check_host,
    host_output,
    inspected,
    podman,
)
from .responses import INTERACTIVE_STREAM_LIMITS, StreamFailure
from .session_protocol import (
    MAX_INTERACTIVE_BODY,
    MAX_INTERACTIVE_HEADER,
    ReasoningVault,
    RequestRefused,
    SessionStreamProjector,
    StreamAborted,
    encode_chunk,
    format_error_response,
    format_models_response,
    sse_response_headers,
    parse_worker_request,
)

SESSION_TTL_NS = 12 * 3600 * 10**9
TURN_TIMEOUT_SECONDS = 300
MAX_CLIENTS = 8
MAX_REQUEST_FRAME = MAX_INTERACTIVE_HEADER + MAX_INTERACTIVE_BODY
REQUEST_LENGTH = struct.Struct("!I")
USAGE_LOG_LIMIT = 512 * 1024
USAGE_LOG_NAME = "session_usage.jsonl"
_INSTANCE_NAME = re.compile(r"(?:default|[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?)\Z")
_LEVEL_RE = re.compile(r"s0:c(\d+),c(\d+)\Z", re.ASCII)
_MEM_RE = re.compile(r"[1-9]\d{0,5}[kmgKMG]?\Z", re.ASCII)
_REL_SEG_RE = re.compile(r"[A-Za-z0-9._@+-]+\Z")
_TERM_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}\Z")
_PORT_KEY_RE = re.compile(r"(\d+)/tcp\Z", re.ASCII)
_PORT_LABEL_RE = re.compile(r"\d+:\d+\Z", re.ASCII)
_RELAY_MODULE = "relay.py"
_SESSION_RELAY_MODULE = "session_relay.py"
_RESERVED_INSTANCES = frozenset({
    "agent", "chromium", "chrome", "postgres", "pg", "dind", "home",
    "openai-relay", "openai-home",
})
_SPEC_KEYS = frozenset({
    "instance", "pod", "agent", "relay", "relay_image", "agent_image",
    "agent_mem", "level", "sandbox", "cwd", "home_vol", "chromium",
    "postgres", "pg_secret", "dind", "dind_run",
})

_ERROR_MAP = {
    "chatgpt_usage_limit": (429, "rate_limit_exceeded", "ChatGPT plan usage limit reached."),
    "chatgpt_auth_rejected": (401, "auth_rejected", "ChatGPT authentication was rejected."),
    "chatgpt_access_refused": (403, "access_refused", "ChatGPT access was refused."),
    "chatgpt_plan_ineligible": (403, "plan_ineligible", "ChatGPT plan is not eligible for this route."),
    "chatgpt_route_unavailable": (503, "route_unavailable", "ChatGPT route is unavailable."),
    "chatgpt_request_unsupported": (400, "request_unsupported", "Request capability is unsupported."),
    "chatgpt_usage_unavailable": (503, "usage_unavailable", "ChatGPT usage service is unavailable."),
    "chatgpt_unavailable": (503, "provider_unavailable", "OpenAI is temporarily unavailable."),
    "openai_model_unavailable": (400, "model_unavailable", "Requested model is unavailable on this plan."),
    "connection_retired": (401, "session_revoked", "ChatGPT session has been disconnected or revoked."),
    "openai_operation_timed_out": (504, "timeout", "Upstream response timed out."),
    "openai_operation_cancelled": (503, "cancelled", "Request was cancelled."),
    "exposure_hold_active": (403, "exposure_hold", "ChatGPT interactive dispatch is blocked by an exposure hold."),
    "exposure_hold_changed": (403, "exposure_hold", "ChatGPT exposure hold changed; interactive dispatch blocked."),
    "invalid_exposure_record": (403, "exposure_hold", "ChatGPT exposure record is invalid; interactive dispatch blocked."),
    "untrusted_exposure_store": (403, "exposure_hold", "ChatGPT exposure store failed trust checks."),
    "exposure_store_unavailable": (403, "exposure_hold", "ChatGPT exposure store is unavailable."),
    "provider_tls_close_timeout": (502, "provider_error", "OpenAI stream did not close cleanly."),
}


def append_session_usage(state_dir: Path, entry: dict) -> None:
    """Append one redacted, size-bounded JSONL accounting entry under flock."""
    line = (json.dumps(entry, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        dir_fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return
    try:
        dir_info = os.fstat(dir_fd)
        if dir_info.st_uid != os.getuid() or dir_info.st_mode & 0o077:
            return
        fd = os.open(USAGE_LOG_NAME, flags, 0o600, dir_fd=dir_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                return
            fcntl.flock(fd, fcntl.LOCK_EX)
            size = os.fstat(fd).st_size
            if size + len(line) > USAGE_LOG_LIMIT:
                os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_END)
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def _read_exact(sock: socket.socket, size: int, deadline: float) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        rem = deadline - time.monotonic()
        if rem <= 0:
            raise TimeoutError("broker read timed out")
        sock.settimeout(rem)
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise EOFError("broker peer closed")
        buf.extend(chunk)
    return bytes(buf)


@dataclass(frozen=True)
class SessionPolicy:
    """Optional exposure hold, selection fence, and revocation callbacks for SessionBroker."""

    exposure_dir: Path | None = None
    acknowledged_exposure_digest: str | None = None
    authorization: object = None
    is_selected: object = None
    on_revoke: object = None


class SessionBroker:
    """Host-side UDS broker mediating multi-turn OpenCode Responses requests."""

    def __init__(
        self,
        *,
        socket_path: Path,
        relay_proof: bytes,
        worker_token: str,
        lease: relay_mod.Lease,
        connection,
        binding,
        models: tuple[str, ...],
        profile_label: str,
        usage_dir: Path | None = None,
        policy: SessionPolicy | None = None,
    ):
        active_policy = policy or SessionPolicy()
        self.socket_path = Path(socket_path)
        self._proof = relay_proof
        self._worker_token = worker_token
        self._lease = lease
        self._connection = connection
        self._binding = binding
        self._models = tuple(models)
        self._allowed_models = frozenset(models)
        self._profile_label = profile_label
        self._usage_dir = Path(usage_dir) if usage_dir is not None else None
        resolved_exposure = active_policy.exposure_dir if active_policy.exposure_dir is not None else usage_dir
        self._exposure_dir = Path(resolved_exposure) if resolved_exposure is not None else None
        self._acknowledged_exposure_digest = active_policy.acknowledged_exposure_digest
        self._authorization = active_policy.authorization
        self._is_selected = active_policy.is_selected
        self._on_revoke = active_policy.on_revoke
        self._vault = ReasoningVault()
        self._vault_lock = threading.Lock()
        self._turn_counter = 0
        self._stopped = threading.Event()
        self._revoked = threading.Event()
        self._lock = threading.Lock()
        self._clients: dict[socket.socket, threading.Thread] = {}
        self._cancels: set[threading.Event] = set()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._watch_thread: threading.Thread | None = None
        self._socket_id: tuple[int, int] | None = None

    def start(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
            self.socket_path.chmod(0o600)
            info = self.socket_path.lstat()
            self._socket_id = (info.st_dev, info.st_ino)
            listener.listen(MAX_CLIENTS)
            listener.settimeout(relay_mod.GRANT_POLL)
        except BaseException:
            with suppress(OSError):
                listener.close()
            raise
        self._listener = listener
        self._accept_thread = threading.Thread(target=self._accept_loop, name="oc-chat-broker", daemon=True)
        self._watch_thread = threading.Thread(target=self._watch_revocation, name="oc-chat-watch", daemon=True)
        self._accept_thread.start()
        self._watch_thread.start()

    def _watch_revocation(self) -> None:
        while not self._stopped.is_set():
            retired = False
            try:
                self._connection.require_active(self._binding)
                if self._is_selected is not None and not self._is_selected():
                    retired = True
            except ConnectionError:
                retired = True
            if retired or self._lease.status() == "terminal":
                self._revoked.set()
                self._cancel_active_turns()
                if self._on_revoke is not None:
                    with suppress(Exception):
                        self._on_revoke()
                return
            self._stopped.wait(0.15)

    def _cancel_active_turns(self) -> None:
        with self._lock:
            for event in self._cancels:
                event.set()
            for peer in self._clients:
                with suppress(OSError):
                    peer.shutdown(socket.SHUT_RDWR)

    def _accept_loop(self) -> None:
        while not self._stopped.is_set() and not self._revoked.is_set():
            try:
                peer, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self._lock:
                if self._stopped.is_set() or self._revoked.is_set() or len(self._clients) >= MAX_CLIENTS:
                    peer.close()
                    continue
                worker = threading.Thread(target=self._handle_peer, args=(peer,), daemon=True)
                self._clients[peer] = worker
                try:
                    worker.start()
                except RuntimeError:
                    self._clients.pop(peer, None)
                    peer.close()

    def _record_usage(self, *, model: str | None, outcome: str, usage: tuple[int, int, int] | None = None) -> None:
        if self._usage_dir is None:
            return
        entry = {
            "ts": int(time.time()),
            "profile": self._profile_label,
            "model": model or "",
            "outcome": outcome,
            "input_tokens": usage[0] if usage else None,
            "output_tokens": usage[1] if usage else None,
        }
        append_session_usage(self._usage_dir, entry)

    def _next_response_id(self) -> str:
        with self._vault_lock:
            self._turn_counter += 1
            return f"resp_local_{self._turn_counter}"

    def _read_peer_request(self, peer: socket.socket) -> bytes | None:
        deadline = time.monotonic() + 15
        expected = relay_mod.PROOF_PREFIX + self._proof
        got = _read_exact(peer, len(expected), deadline)
        if not hmac.compare_digest(got, expected):
            return None
        size, = REQUEST_LENGTH.unpack(_read_exact(peer, REQUEST_LENGTH.size, deadline))
        if not 0 < size <= MAX_REQUEST_FRAME:
            return None
        return _read_exact(peer, size, deadline)

    @contextmanager
    def _exposure_fence(self):
        if self._exposure_dir is None:
            raise ConnectionError("exposure_store_unavailable")
        try:
            with ExposureLedger(self._exposure_dir).dispatch_fence(
                acknowledged_digest=self._acknowledged_exposure_digest,
            ):
                yield
        except ExposureError as exc:
            code = exc.args[0] if exc.args and type(exc.args[0]) is str else "exposure_hold_active"
            raise ConnectionError(code) from None

    def _require_turn_active(self) -> None:
        if self._stopped.is_set() or self._revoked.is_set() or not self._lease.active():
            raise StreamAborted("session_revoked")
        if self._is_selected is not None and not self._is_selected():
            raise StreamAborted("session_revoked")

    def _send_fenced(self, peer: socket.socket, payload: bytes) -> None:
        if not payload:
            return
        authorize = self._authorization or nullcontext
        active_fence = getattr(self._connection, "active_fence", None)
        conn_fence = (lambda: active_fence(self._binding)) if active_fence is not None else nullcontext
        try:
            with authorize(), conn_fence(), self._lease.fence():
                if self._stopped.is_set() or self._revoked.is_set() or not self._lease.active():
                    raise StreamAborted("session_revoked")
                if self._authorization is None and self._is_selected is not None and not self._is_selected():
                    raise StreamAborted("session_revoked")
                if active_fence is None:
                    self._connection.require_active(self._binding)
                peer.sendall(payload)
        except (ConnectionError, ProfileError, RouteUnavailable):
            raise StreamAborted("session_revoked") from None

    def _stream_responses_turn(self, peer: socket.socket, parsed, cancel: threading.Event,
                               state: dict) -> tuple[str, tuple[int, int, int] | None]:
        turn_deadline = min(time.monotonic() + TURN_TIMEOUT_SECONDS, self._lease.deadline_ns / 1e9)
        projector = SessionStreamProjector(
            model=parsed.model, local_response_id=self._next_response_id(), vault=self._vault,
            allowed_tools=parsed.allowed_tools,
        )

        def before_write():
            if self._stopped.is_set() or self._revoked.is_set() or not self._lease.active():
                raise ConnectionError("connection_retired")
            if self._authorization is None and self._is_selected is not None and not self._is_selected():
                raise ConnectionError("connection_retired")

        with self._connection.interactive_responses(
            self._binding, parsed.body, before_write,
            authorization=self._authorization,
            write_fence=self._exposure_fence,
            limits=INTERACTIVE_STREAM_LIMITS, deadline=turn_deadline,
            cancelled=cancel, inspect_media=True, observe_media=lambda _kind: None,
        ) as upstream_events:
            peer.settimeout(5)
            self._send_fenced(peer, sse_response_headers())
            state["headers_sent"] = True
            for event in upstream_events:
                self._require_turn_active()
                with self._vault_lock:
                    frames = projector.feed(event)
                for frame in frames:
                    self._send_fenced(peer, encode_chunk(frame))
            self._require_turn_active()
            with self._vault_lock:
                tail = projector.finalize()
            for frame in tail:
                self._send_fenced(peer, encode_chunk(frame))
            self._send_fenced(peer, b"0\r\n\r\n")
            return "completed", projector.usage

    def _send_peer_error(self, peer: socket.socket, headers_sent: bool, status: int, code: str, message: str) -> None:
        if not headers_sent:
            with suppress(OSError):
                peer.sendall(format_error_response(status, code, message))

    def _handle_peer(self, peer: socket.socket) -> None:
        cancel = threading.Event()
        with self._lock:
            self._cancels.add(cancel)
        state = {"headers_sent": False}
        model: str | None = None
        outcome = "error"
        usage = None
        try:
            raw = self._read_peer_request(peer)
            if raw is None:
                return
            if self._revoked.is_set() or not self._lease.active():
                peer.sendall(format_error_response(401, "session_revoked", "ChatGPT session is no longer active."))
                outcome = "session_revoked"
                return
            with self._vault_lock:
                parsed = parse_worker_request(
                    raw, expected_token=self._worker_token,
                    allowed_models=self._allowed_models, vault=self._vault,
                )
            if parsed.route == "models":
                peer.sendall(format_models_response(self._models))
                outcome = "models_ok"
                return
            model = parsed.model
            outcome, usage = self._stream_responses_turn(peer, parsed, cancel, state)
        except RequestRefused as error:
            outcome = error.code
            self._send_peer_error(peer, state["headers_sent"], error.status, error.code, error.message)
        except StreamAborted as error:
            outcome = error.code
            # If headers were already sent, intentionally omit terminating chunk 0\r\n\r\n.
            self._send_peer_error(peer, state["headers_sent"], 502, error.code, "Upstream response failed safety checks.")
        except RouteUnavailable:
            outcome = "connection_retired"
            self._send_peer_error(peer, state["headers_sent"], 401, "session_revoked", "ChatGPT session is no longer active.")
        except (ConnectionError, StreamFailure) as error:
            outcome = error.code
            status, code, msg = _ERROR_MAP.get(error.code, (502, "provider_error", "OpenAI request failed."))
            self._send_peer_error(peer, state["headers_sent"], status, code, msg)
        except (OSError, EOFError):
            outcome = "transport_error"
        finally:
            if model is not None:
                with suppress(Exception):
                    self._record_usage(model=model, outcome=outcome, usage=usage)
            with self._lock:
                self._cancels.discard(cancel)
                with suppress(OSError):
                    peer.shutdown(socket.SHUT_RDWR)
                with suppress(OSError):
                    peer.close()
                self._clients.pop(peer, None)

    def close(self) -> None:
        self._stopped.set()
        self._cancel_active_turns()
        if self._listener is not None:
            with suppress(OSError):
                self._listener.close()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1.5)
        if self._watch_thread is not None:
            self._watch_thread.join(timeout=1.5)
        with self._lock:
            threads = list(self._clients.values())
        deadline = time.monotonic() + 2
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if self._socket_id is not None and self.socket_path.exists():
            info = self.socket_path.lstat()
            if (info.st_dev, info.st_ino) == self._socket_id:
                with suppress(OSError):
                    self.socket_path.unlink()


def generate_opencode_config(*, worker_token: str, models: tuple[str, ...]) -> dict:
    """Build the read-only /etc/opencode/opencode.json enforcing local-only ChatGPT routing."""
    default_model = "gpt-6.2-sol" if "gpt-6.2-sol" in models else models[0]
    model_defs = {
        slug: {
            "name": slug,
            "capabilities": {"tools": True, "input": ["text"], "output": ["text"]},
            "limit": {"context": 128000, "output": 16384},
        }
        for slug in models
    }
    return {
        "$schema": "https://opencode.ai/config.json",
        "model": f"local/{default_model}",
        "update": "disable",
        "mcp": {
            "chrome-devtools": {
                "type": "local",
                "command": ["npx", "-y", "chrome-devtools-mcp@latest", "--browserUrl", "http://127.0.0.1:9222"],
            }
        },
        "providers": {
            "local": {
                "name": "ChatGPT Subscription (Workstation Broker)",
                "package": "@opencode/ai/providers/openai-compatible/responses",
                "settings": {
                    "baseURL": "http://127.0.0.1:8401/v1",
                    "apiKey": worker_token,
                    "store": False,
                    "include": ["reasoning.encrypted_content"],
                },
                "models": model_defs,
            }
        },
        "policies": [
            {"action": "integration.connect", "resource": "*", "effect": "deny"},
            {"action": "provider.use", "resource": "*", "effect": "deny"},
            {"action": "provider.use", "resource": "local", "effect": "allow"},
        ],
    }


class _SessionJob:
    """Private /tmp/oc-chat-XXXXXXXX grant, socket, and proof directory for one session."""

    def __init__(self, root: Path, incarnation: str, generation: int = 1):
        self.root = root
        self.incarnation = incarnation
        self.generation = generation
        self.grant = root / "grant"
        self.provider_socket = root / "provider" / "provider.sock"
        self.proof_file = root / "proof" / "relay"
        self.source_dir = root / "source"
        self.opencode_config = root / "opencode" / "opencode.json"
        self.relay_proof = secrets.token_bytes(relay_mod.PROOF_SIZE)
        self.lease: relay_mod.Lease | None = None
        self._lifetime_fd: int | None = None
        self._terminal = False

    def prepare(self, config_payload: dict) -> None:
        self.root.chmod(0o700)
        for sub in ("grant", "provider", "proof", "source", "opencode"):
            (self.root / sub).mkdir(mode=0o700)
        (self.grant / "lock").touch(mode=0o600)
        lifetime = self.grant / "lifetime"
        lifetime.touch(mode=0o600)
        fd = os.open(lifetime, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self._lifetime_fd = fd
        atomic_write(self.grant / "state", b"pending\n")
        (self.grant / "state").chmod(0o600)
        atomic_write(self.proof_file, self.relay_proof)
        self.proof_file.chmod(0o600)
        pkg_dir = Path(__file__).resolve().parent
        shutil.copyfile(pkg_dir / "managed" / _RELAY_MODULE, self.source_dir / _RELAY_MODULE)
        shutil.copyfile(pkg_dir / _SESSION_RELAY_MODULE, self.source_dir / _SESSION_RELAY_MODULE)
        (self.source_dir / _RELAY_MODULE).chmod(0o444)
        (self.source_dir / _SESSION_RELAY_MODULE).chmod(0o444)
        cfg_bytes = (json.dumps(config_payload, indent=2, ensure_ascii=True) + "\n").encode("ascii")
        atomic_write(self.opencode_config, cfg_bytes)
        self.opencode_config.chmod(0o444)
        deadline_ns = time.monotonic_ns() + SESSION_TTL_NS
        active = relay_mod.grant_record(self.incarnation, self.generation, True)
        self.lease = relay_mod.Lease(self.grant, active, deadline_ns)

    def activate(self) -> None:
        with self.lease.fence():
            if self.lease.status() != "pending":
                raise RuntimeError("session grant is no longer pending")
            atomic_write(self.grant / "state", self.lease.active_record)
            (self.grant / "state").chmod(0o600)

    def revoke(self) -> None:
        if self._terminal or self.lease is None:
            return
        self._terminal = True
        terminal = relay_mod.grant_record(self.incarnation, self.generation, False)
        error: Exception | None = None
        try:
            with self.lease.fence():
                atomic_write(self.grant / "state", terminal)
                (self.grant / "state").chmod(0o600)
        except OSError as exc:
            error = exc
        finally:
            if self._lifetime_fd is not None:
                fd, self._lifetime_fd = self._lifetime_fd, None
                with suppress(OSError):
                    os.close(fd)
        if error is not None:
            raise error


_SIBLING_PROCESS_LABEL = re.compile(r"[^:]+:[^:]+:[A-Za-z0-9_.-]+:s0:c(\d+),c(\d+)\Z", re.ASCII)


def _mcs_pair(label: str, *, allow_custom_type: bool = False) -> set[int] | None:
    pattern = _SIBLING_PROCESS_LABEL if allow_custom_type else PROCESS_LABEL
    match = pattern.fullmatch(label or "")
    if not match:
        return None
    pair = set(map(int, match.groups()))
    return pair if len(pair) == 2 else None


def _parse_pod_port_bindings(key, values, *, allow_postgres: bool) -> list[str]:
    match = _PORT_KEY_RE.fullmatch(key) if type(key) is str else None
    if not match or type(values) is not list:
        raise RuntimeError("Pod has unsupported port bindings")
    target = int(match.group(1))
    if not 1 <= target <= 65535 or target in (9222, 8401) or (target == 5432 and not allow_postgres):
        raise RuntimeError(f"Pod publishes forbidden port {target}")
    mapped: list[str] = []
    for entry in values:
        if type(entry) is not dict or entry.get("HostIp") != "127.0.0.1":
            raise RuntimeError("Pod publishes a non-loopback port")
        hp = entry.get("HostPort", "")
        if type(hp) is not str or not hp.isdecimal() or not 1 <= int(hp) <= 65535:
            raise RuntimeError("Pod has invalid host port binding")
        mapped.append(f"{int(hp)}:{target}")
    return mapped


def _verify_pod_ports(bindings, port_label: str, *, allow_postgres: bool) -> None:
    if bindings is None:
        bindings = {}
    if type(bindings) is not dict:
        raise RuntimeError("Pod port bindings are malformed")
    actual: list[str] = []
    for key, values in bindings.items():
        actual.extend(_parse_pod_port_bindings(key, values, allow_postgres=allow_postgres))
    expected = port_label.split(",") if port_label else []
    if any(not _PORT_LABEL_RE.fullmatch(item) for item in expected) or sorted(actual) != sorted(expected):
        raise RuntimeError("Pod port bindings do not match oc.ports label")


def _verify_pod(spec: dict) -> str:
    pod_info = inspected("pod", "inspect", spec["pod"])
    pod_id = pod_info.get("Id") or ""
    labels = pod_info.get("Labels") or {}
    if (type(pod_id) is not str or not IMAGE_ID.fullmatch(pod_id)
            or type(labels) is not dict
            or labels.get("oc.sandbox") != "1"
            or labels.get("oc.instance") != spec["instance"]):
        raise RuntimeError("Pod failed ownership verification")
    port_label = labels.get("oc.ports", "")
    if type(port_label) is not str:
        raise RuntimeError("Pod port label is malformed")
    infra = pod_info.get("InfraConfig") or {}
    if type(infra) is not dict:
        raise RuntimeError("Pod infra config is malformed")
    _verify_pod_ports(infra.get("PortBindings"), port_label, allow_postgres=bool(spec["pg_secret"]))
    return pod_id


def _verify_relay_mounts(details: dict, job: _SessionJob) -> None:
    expected = {
        "/source": job.source_dir,
        "/provider": job.provider_socket.parent,
        "/grant": job.grant,
        "/proof": job.proof_file.parent,
    }
    actual_mounts = details.get("Mounts") or []
    if len(actual_mounts) != len(expected) or {m.get("Destination") for m in actual_mounts} != set(expected):
        raise RuntimeError("Unexpected relay mount set")
    for binding in actual_mounts:
        target = expected.get(binding.get("Destination"))
        opts = set(binding.get("Options") or ())
        if (target is None or binding.get("Type") != "bind" or binding.get("Source") != str(target)
                or binding.get("RW") is not False or binding.get("Mode") not in ("Z", "")
                or binding.get("Propagation") != "rprivate"
                or not {"nosuid", "nodev", "noexec"} <= opts):
            raise RuntimeError("Relay bind mount failed verification")


def _verify_relay_labels(relay_id: str, details: dict, job: _SessionJob) -> None:
    expected_proc = (details.get("ProcessLabel") or "").encode("ascii")
    effective_proc = podman("exec", relay_id, "cat", "/proc/self/attr/current").stdout.removesuffix(b"\0")
    if effective_proc != expected_proc:
        raise RuntimeError("Unexpected effective relay SELinux process label")
    expected_mount = (details.get("MountLabel") or "").encode("ascii")
    paths = (
        job.source_dir,
        job.provider_socket.parent,
        job.provider_socket,
        job.grant,
        job.proof_file.parent,
        job.proof_file,
    )
    for path in paths:
        label = host_output("getfattr", "--only-values", "-n", "security.selinux", "--", str(path)).removesuffix(b"\0")
        if label != expected_mount:
            raise RuntimeError("Unexpected effective relay SELinux mount label")


def _inspect_sibling_mcs(name: str) -> set[int] | None:
    probe = podman("container", "inspect", name, check=False)
    if probe.returncode != 0:
        exists = podman("container", "exists", name, check=False)
        if exists.returncode == 1:
            return None
        raise RuntimeError(f"Could not inspect sibling container {name}")
    try:
        parsed = json.loads(probe.stdout)
    except ValueError:
        raise RuntimeError(f"Malformed inspect data for sibling container {name}") from None
    if type(parsed) is not list or len(parsed) != 1 or type(parsed[0]) is not dict:
        raise RuntimeError(f"Malformed inspect data for sibling container {name}")
    other_mcs = _mcs_pair(parsed[0].get("ProcessLabel") or "", allow_custom_type=True)
    if not other_mcs:
        raise RuntimeError(f"Missing SELinux label for sibling container {name}")
    return other_mcs


def _verify_sibling_mcs(other_containers: list[str], relay_mcs: set[int]) -> None:
    for name in other_containers:
        other_mcs = _inspect_sibling_mcs(name)
        if other_mcs is not None and other_mcs == relay_mcs:
            raise RuntimeError(f"Relay MCS collided with sibling container {name}")


def _verify_relay_isolation(relay_id: str, relay_image: str, pod_id: str, agent_level: str,
                            job: _SessionJob, other_containers: list[str]) -> None:
    details = inspected("container", "inspect", relay_id)
    host = details["HostConfig"]
    config = details["Config"]
    relay_mcs = _mcs_pair(details.get("ProcessLabel") or "")
    mount_label = details.get("MountLabel") or ""
    if (not relay_mcs
            or not MOUNT_LABEL.fullmatch(mount_label)
            or (details.get("ProcessLabel") or "").split(":", 3)[-1] != mount_label.split(":", 3)[-1]
            or details.get("Pod") != pod_id
            or details.get("Image", "").removeprefix("sha256:") != relay_image.removeprefix("sha256:")
            or not host.get("ReadonlyRootfs") or host.get("Privileged")
            or host.get("IpcMode") != "private" or host.get("PidMode") != "private"
            or host.get("CgroupMode") != "private" or config.get("User") != "0:0"
            or details.get("EffectiveCaps") or host.get("SecurityOpt") != ["no-new-privileges"]):
        raise RuntimeError("Relay container failed isolation verification")
    agent_match = _LEVEL_RE.fullmatch(agent_level)
    if not agent_match or set(map(int, agent_match.groups())) == relay_mcs:
        raise RuntimeError("Relay MCS collided with agent level")
    _verify_relay_mounts(details, job)
    _verify_relay_labels(relay_id, details, job)
    _verify_sibling_mcs(other_containers, relay_mcs)


def _remove_container_verified(container_id: str) -> None:
    podman("rm", "-f", container_id, check=False, timeout=8)
    exists = podman("container", "exists", container_id, check=False, timeout=4)
    if exists.returncode != 1:
        raise RuntimeError(f"Could not confirm container removal ({container_id[:12]})")


def _open_instance_lock(state_dir: Path, instance: str):
    """Acquire an exclusive per-instance launch lock under the private OpenAI state dir."""
    parent_fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            os.mkdir("sessions", 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        sess_fd = os.open("sessions", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            sinfo = os.fstat(sess_fd)
            if sinfo.st_uid != os.getuid() or sinfo.st_mode & 0o077:
                raise RuntimeError("Untrusted session lock directory")
            lock_fd = os.open(
                f"{instance}.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=sess_fd
            )
            try:
                linfo = os.fstat(lock_fd)
                if not stat.S_ISREG(linfo.st_mode) or linfo.st_uid != os.getuid() or linfo.st_mode & 0o077:
                    raise RuntimeError("Untrusted session lock file")
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BaseException:
                os.close(lock_fd)
                raise
            return lock_fd
        finally:
            os.close(sess_fd)
    finally:
        os.close(parent_fd)


def _wait_relay_bound(relay_id: str) -> None:
    probe = (
        "import socket; s=socket.create_connection(('127.0.0.1', 8401), 1); s.close()"
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        res = podman("exec", relay_id, "python3", "-c", probe, check=False, timeout=3)
        if res.returncode == 0:
            return
        time.sleep(0.1)
    raise RuntimeError("Interactive ChatGPT relay did not bind 127.0.0.1:8401")


def _valid_sandbox_path(path: str) -> bool:
    if not path.startswith("/") or any(ch in path for ch in ":, \t\r\n\x00"):
        return False
    parts = [part for part in path.split("/") if part]
    return bool(parts) and all(part not in (".", "..") for part in parts)


def _valid_relpath(path: str) -> bool:
    if not path or path.startswith("/") or path.endswith("/"):
        return False
    parts = path.split("/")
    return all(_REL_SEG_RE.fullmatch(part) and part not in (".", "..") for part in parts)


def _validate_optional_pair(first: str, second: str, exp_first: str, exp_second: str) -> bool:
    return (first == "" and second == "") or (first == exp_first and second == exp_second)


def _validate_spec(spec: dict) -> dict:
    if type(spec) is not dict or set(spec) != _SPEC_KEYS or not all(type(v) is str for v in spec.values()):
        raise ValueError("Invalid launch spec")
    instance = spec["instance"]
    if not _INSTANCE_NAME.fullmatch(instance) or instance in _RESERVED_INSTANCES:
        raise ValueError("Malformed instance name")
    expected_pod = "oc" if instance == "default" else f"oc-{instance}"
    level_match = _LEVEL_RE.fullmatch(spec["level"])
    level_ok = level_match is not None and len(set(map(int, level_match.groups()))) == 2
    derived_ok = (
        spec["pod"] == expected_pod
        and spec["agent"] == f"{expected_pod}-agent"
        and spec["relay"] == f"{expected_pod}-openai-relay"
        and spec["chromium"] == f"{expected_pod}-chromium"
        and spec["home_vol"] == f"{expected_pod}-openai-home"
        and _validate_optional_pair(spec["postgres"], spec["pg_secret"], f"{expected_pod}-postgres", f"{expected_pod}-pg-passfile")
        and _validate_optional_pair(spec["dind"], spec["dind_run"], f"{expected_pod}-dind", f"{expected_pod}-dind-run")
    )
    if (not derived_ok or not level_ok
            or not IMAGE_ID.fullmatch(spec["relay_image"])
            or not IMAGE_ID.fullmatch(spec["agent_image"])
            or not _MEM_RE.fullmatch(spec["agent_mem"])
            or not _valid_sandbox_path(spec["sandbox"])
            or not _valid_relpath(spec["cwd"])):
        raise ValueError("Malformed launch spec field")
    return spec


def _remove_stopped_owned_container(container_id: str) -> None:
    res = podman("rm", container_id, check=False, timeout=8)
    if res.returncode != 0:
        raise RuntimeError(f"Could not remove stopped container ({container_id[:12]})")
    exists = podman("container", "exists", container_id, check=False, timeout=4)
    if exists.returncode != 1:
        raise RuntimeError(f"Could not confirm stopped container removal ({container_id[:12]})")


def _inspect_existing_container(cname: str) -> dict | None:
    probe = podman("container", "inspect", cname, check=False)
    if probe.returncode != 0:
        exists = podman("container", "exists", cname, check=False)
        if exists.returncode == 1:
            return None
        raise RuntimeError(f"Could not inspect existing container {cname}")
    try:
        parsed = json.loads(probe.stdout)
    except ValueError:
        raise RuntimeError(f"Malformed inspect data for container {cname}") from None
    if type(parsed) is not list or len(parsed) != 1 or type(parsed[0]) is not dict:
        raise RuntimeError(f"Malformed inspect data for container {cname}")
    return parsed[0]


def _verify_stopped_container_owner(details: dict, cname: str, instance: str, expected_role: str | None) -> str:
    cid = details.get("Id") or ""
    state = details.get("State") or {}
    labels = (details.get("Config") or {}).get("Labels") or {}
    if type(state) is not dict or type(labels) is not dict:
        raise RuntimeError(f"Malformed inspect metadata for container {cname}")
    if state.get("Running") is True or state.get("Status") in ("running", "paused", "restarting", "stopping"):
        raise RuntimeError(f"Container {cname} is already running")
    role = labels.get("oc.role")
    role_ok = (role == expected_role) if expected_role is not None else (role in (None, ""))
    if (type(cid) is not str or not IMAGE_ID.fullmatch(cid)
            or labels.get("oc.sandbox") != "1"
            or labels.get("oc.instance") != instance
            or not role_ok):
        raise RuntimeError(f"Refusing to remove unowned stopped container {cname}")
    return cid


def _ensure_single_container_idle(cname: str, instance: str, expected_role: str | None) -> None:
    details = _inspect_existing_container(cname)
    if details is None:
        return
    cid = _verify_stopped_container_owner(details, cname, instance, expected_role)
    _remove_stopped_owned_container(cid)


def _ensure_containers_idle(agent_name: str, relay_name: str, instance: str) -> None:
    _ensure_single_container_idle(agent_name, instance, None)
    _ensure_single_container_idle(relay_name, instance, "openai-relay")


def _build_relay_args(spec: dict, job: _SessionJob) -> list[str]:
    return [
        "create", "--pull=never", "--name", spec["relay"], "--pod", spec["pod"],
        "--label", "oc.sandbox=1", "--label", f"oc.instance={spec['instance']}",
        "--label", "oc.role=openai-relay",
        "--http-proxy=false", "--image-volume=ignore", "--log-driver=none", "--restart=no",
        "--user=0:0", "--ipc=private", "--pid=private", "--cgroupns=private",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--read-only", "--pids-limit=64", "--memory=128m", "--memory-swap=128m",
        "-v", f"{job.source_dir}:/source:ro,Z,nosuid,nodev,noexec",
        "-v", f"{job.provider_socket.parent}:/provider:ro,Z,nosuid,nodev,noexec",
        "-v", f"{job.grant}:/grant:ro,Z,nosuid,nodev,noexec",
        "-v", f"{job.proof_file.parent}:/proof:ro,Z,nosuid,nodev,noexec",
        spec["relay_image"],
        "python3", "-B", "/source/session_relay.py",
        job.incarnation, str(job.generation), str(job.lease.deadline_ns),
    ]


def _build_agent_args(spec: dict, job: _SessionJob) -> list[str]:
    args = [
        "create", "-it", "--rm", "--pull=never", "--name", spec["agent"], "--pod", spec["pod"],
        "--label", "oc.sandbox=1", "--label", f"oc.instance={spec['instance']}",
        "--label", "oc.provider=openai",
        "--http-proxy=false", "--image-volume=ignore", "--restart=no",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--security-opt", f"label=level:{spec['level']}",
        "--pids-limit=512", "--memory", spec["agent_mem"],
        "-v", f"{spec['sandbox']}:/sandbox",
        "-v", f"{spec['home_vol']}:/root:Z",
        "-v", f"{job.opencode_config}:/etc/opencode/opencode.json:ro,Z,nosuid,nodev,noexec",
        "-w", f"/sandbox/{spec['cwd']}",
        "-e", f"OC_INSTANCE={spec['instance']}",
        "-e", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "-e", "OPENCODE_CONFIG=/etc/opencode/opencode.json",
        "-e", "OPENCODE_CONFIG_PROJECT_DISABLE=true",
        "-e", "OPENCODE_DISABLE_MODELS_FETCH=true",
        "-e", "OPENCODE_DISABLE_FREE_MODELS=true",
        "-e", "OPENCODE_DISABLE_AUTOUPDATE=true",
        "-e", "OPENCODE_DISABLE_CLAUDE_CODE=true",
    ]
    if spec["pg_secret"]:
        args.extend([
            "--secret", f"{spec['pg_secret']},type=mount,target=/run/secrets/oc-pgpass,mode=0600",
            "-e", "PGPASSFILE=/run/secrets/oc-pgpass",
        ])
    if spec["dind_run"]:
        args.extend([
            "-v", f"{spec['dind_run']}:/run/dind",
            "-e", "DOCKER_HOST=unix:///run/dind/podman.sock",
            "-e", "CONTAINER_HOST=unix:///run/dind/podman.sock",
        ])
    args.append(spec["agent_image"])
    return args


def _sanitized_term() -> str:
    raw = os.environ.get("TERM", "xterm-256color")
    return raw if _TERM_RE.fullmatch(raw) else "xterm-256color"


def _launch_agent_tty(agent_id: str, stop_event: threading.Event) -> int:
    uid = os.getuid()
    runtime_dir = f"/run/user/{uid}"
    home_dir = str(account_home())
    term = _sanitized_term()
    host_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": home_dir,
        "TERM": term,
        "XDG_RUNTIME_DIR": runtime_dir,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_dir}/bus",
    }
    spawn_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": home_dir,
        "TERM": term,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/host{runtime_dir}/bus",
    }
    cmd = [
        HOST_SPAWN, "--env=", "/usr/bin/env", "-i",
        *(f"{k}={v}" for k, v in host_env.items()),
        "/usr/bin/podman", "--remote=false", "--default-mounts-file=/dev/null",
        "start", "-ai", agent_id,
    ]
    child_proc = subprocess.Popen(cmd, env=spawn_env)
    while child_proc.poll() is None:
        if stop_event.wait(0.2):
            with suppress(OSError):
                child_proc.terminate()
            podman("stop", "-t", "2", agent_id, check=False, timeout=6)
            break
    return child_proc.wait()


def _teardown_session(job: _SessionJob, broker: SessionBroker | None,
                      container_ids: tuple[str | None, ...], stack: ExitStack) -> Exception | None:
    cleanup_error: Exception | None = None
    steps = [job.revoke]
    if broker is not None:
        steps.append(broker.close)
    for cid in container_ids:
        if cid is not None:
            steps.append(lambda c=cid: _remove_container_verified(c))
    steps.append(stack.close)
    for step in steps:
        try:
            step()
        except Exception as exc:
            cleanup_error = cleanup_error or exc
    return cleanup_error


def _run_session_body(spec: dict, backend, identity: tuple, models: tuple[str, ...],
                      job: _SessionJob, stop_event: threading.Event,
                      terminal: StreamTerminal, cleanup_state: dict) -> int:
    label, selection_epoch, conn, binding, acknowledged_digest = identity
    worker_token = secrets.token_urlsafe(32)
    relay_id: str | None = None
    agent_id: str | None = None
    broker: SessionBroker | None = None
    rc = 1
    with ExitStack() as stack:
        try:
            pod_id = _verify_pod(spec)
            job.prepare(generate_opencode_config(worker_token=worker_token, models=models))
            stack.enter_context(backend.session_lease(label, selection_epoch, binding, job))
            broker = SessionBroker(
                socket_path=job.provider_socket,
                relay_proof=job.relay_proof,
                worker_token=worker_token,
                lease=job.lease,
                connection=conn,
                binding=binding,
                models=models,
                profile_label=label,
                usage_dir=backend._state,
                policy=SessionPolicy(
                    exposure_dir=backend._state,
                    acknowledged_exposure_digest=acknowledged_digest,
                    authorization=lambda: backend.selected_fence(label, selection_epoch),
                    is_selected=lambda: backend.active_selection() == (label, selection_epoch),
                    on_revoke=stop_event.set,
                ),
            )
            broker.start()
            _ensure_containers_idle(spec["agent"], spec["relay"], spec["instance"])

            relay_id = podman(*_build_relay_args(spec, job)).stdout.decode("ascii").strip()
            if not IMAGE_ID.fullmatch(relay_id):
                raise RuntimeError("Podman did not return a complete relay container ID")
            podman("start", relay_id)
            siblings = [name for name in (spec["chromium"], spec["postgres"], spec["dind"]) if name]
            _verify_relay_isolation(relay_id, spec["relay_image"], pod_id, spec["level"], job, siblings)
            _wait_relay_bound(relay_id)
            if (stop_event.is_set() or broker._revoked.is_set()
                    or job.lease.status() != "pending" or time.monotonic_ns() >= job.lease.deadline_ns):
                raise ConnectionError("connection_retired")
            job.activate()

            if stop_event.is_set() or broker._revoked.is_set() or not job.lease.active():
                raise ConnectionError("connection_retired")
            agent_id = podman(*_build_agent_args(spec, job)).stdout.decode("ascii").strip()
            if not IMAGE_ID.fullmatch(agent_id):
                raise RuntimeError("Podman did not return a complete agent container ID")

            if stop_event.is_set() or broker._revoked.is_set() or not job.lease.active():
                raise ConnectionError("connection_retired")
            rc = _launch_agent_tty(agent_id, stop_event)
        finally:
            cleanup_error = _teardown_session(job, broker, (agent_id, relay_id), stack)
            if cleanup_error is None:
                cleanup_state["clean"] = True
            else:
                terminal.error(f"Provider session cleanup needs verification. Retained directory {job.root}")
                rc = 1
    return rc


def _resolve_interactive_exposure(backend, terminal: StreamTerminal) -> str | None:
    hold = ExposureLedger(backend._state).inspect_hold()
    if not hold.blocked:
        return None
    terminal.write(
        f"Prior exposure hold present ({hold.file_count} receipt file(s), "
        f"{hold.unsettled_count} unsettled, snapshot {hold.digest[:12]}). "
        "Existing receipt files will remain untouched."
    )
    return hold.digest


def run_interactive_session(spec: dict, terminal: StreamTerminal) -> int:
    """Supervise one interactive ChatGPT-backed oc-sandbox OpenCode session."""
    spec = _validate_spec(spec)
    if not terminal.attended():
        terminal.error("An attended foreground workstation terminal is required for --provider openai.")
        return 2
    try:
        check_devbox()
        check_host()
    except Exception:
        terminal.error("Interactive --provider openai requires the qualified devbox host with SELinux enforcing.")
        return 1

    try:
        backend = make_backend()
        label, selection_epoch, conn, binding = backend.active_connection()
        models = conn.models(binding)
        if not models:
            raise RouteUnavailable(Reason.MODEL_UNAVAILABLE)
        acknowledged_digest = _resolve_interactive_exposure(backend, terminal)
    except Exception as error:
        return report_failure(terminal, error, operation="ChatGPT session")

    preview = ", ".join(models[:6]) + (f" (+{len(models) - 6} more)" if len(models) > 6 else "")
    terminal.write(f"ChatGPT registration: {label} (models: {preview})")
    terminal.write(
        "No API-key fallback will be forwarded. Provider tokens stay on the workstation behind an "
        "isolated relay. One approval covers multiple interactive turns and subagents in this session "
        "with no verified spending ceiling. Disconnect with `oc-sandbox openai disconnect` or exit OpenCode."
    )
    prompt = (
        f"Acknowledge prior exposure snapshot and start interactive ChatGPT OpenCode session for instance '{spec['instance']}'?"
        if acknowledged_digest is not None
        else f"Start interactive ChatGPT OpenCode session for instance '{spec['instance']}'?"
    )
    if not terminal.confirm(prompt):
        terminal.error("Cancelled.")
        return 1

    try:
        instance_lock_fd = _open_instance_lock(backend._state, spec["instance"])
    except (OSError, RuntimeError):
        terminal.error(f"Instance '{spec['instance']}' already has an active provider session launch.")
        return 1

    root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir=SHARED_TMP))
    job = _SessionJob(root, "inc_" + secrets.token_hex(16))
    stop_event = threading.Event()
    prev_term = signal.signal(signal.SIGTERM, lambda _s, _f: stop_event.set())
    prev_hup = signal.signal(signal.SIGHUP, lambda _s, _f: stop_event.set())
    rc = 1
    cleanup_state = {"clean": False}
    try:
        identity = (label, selection_epoch, conn, binding, acknowledged_digest)
        rc = _run_session_body(spec, backend, identity, models, job, stop_event, terminal, cleanup_state)
    except KeyboardInterrupt:
        rc = 130
    except Exception as error:
        return report_failure(terminal, error, operation="ChatGPT session")
    finally:
        signal.signal(signal.SIGTERM, prev_term)
        signal.signal(signal.SIGHUP, prev_hup)
        with suppress(OSError):
            os.close(instance_lock_fd)
        if cleanup_state["clean"]:
            with suppress(OSError):
                shutil.rmtree(root)
    return rc
