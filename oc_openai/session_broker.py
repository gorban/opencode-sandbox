"""Host-side interactive ChatGPT Responses broker and foreground pod supervisor."""

from contextlib import ExitStack, suppress
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
from .live import make_backend
from .managed import relay as relay_mod
from .managed.runtime import (
    HOST_SPAWN,
    IMAGE_ID,
    MOUNT_LABEL,
    PROCESS_LABEL,
    SHARED_TMP,
    atomic_write,
    check_devbox,
    check_host,
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
_INSTANCE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")
_POD_NAME = re.compile(r"oc-[a-z0-9-]{1,40}\Z")
_LEVEL_RE = re.compile(r"s0:c\d+,c\d+\Z")

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
        is_selected=None,
        on_revoke=None,
    ):
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
        self._is_selected = is_selected
        self._on_revoke = on_revoke
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
        self._listener = listener
        listener.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        info = self.socket_path.lstat()
        self._socket_id = (info.st_dev, info.st_ino)
        listener.listen(MAX_CLIENTS)
        listener.settimeout(relay_mod.GRANT_POLL)
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
            for event in list(self._cancels):
                event.set()
            for peer in list(self._clients):
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

    def _handle_peer(self, peer: socket.socket) -> None:
        cancel = threading.Event()
        with self._lock:
            self._cancels.add(cancel)
        headers_sent = False
        model: str | None = None
        outcome = "error"
        usage = None
        try:
            deadline = time.monotonic() + 15
            expected = relay_mod.PROOF_PREFIX + self._proof
            got = _read_exact(peer, len(expected), deadline)
            if not hmac.compare_digest(got, expected):
                return
            size, = REQUEST_LENGTH.unpack(_read_exact(peer, REQUEST_LENGTH.size, deadline))
            if not 0 < size <= MAX_REQUEST_FRAME:
                return
            raw = _read_exact(peer, size, deadline)
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
            turn_deadline = min(time.monotonic() + TURN_TIMEOUT_SECONDS, self._lease.deadline_ns / 1e9)
            projector = SessionStreamProjector(
                model=model, local_response_id=self._next_response_id(), vault=self._vault,
            )

            def observe_media(_kind):
                pass

            def before_send():
                if self._stopped.is_set() or self._revoked.is_set() or not self._lease.active():
                    raise ConnectionError("connection_retired")
                if self._is_selected is not None and not self._is_selected():
                    raise ConnectionError("connection_retired")

            with self._connection.interactive_responses(
                self._binding, parsed.body, before_send,
                limits=INTERACTIVE_STREAM_LIMITS, deadline=turn_deadline,
                cancelled=cancel, inspect_media=True, observe_media=observe_media,
            ) as upstream_events:
                peer.settimeout(30)
                peer.sendall(sse_response_headers())
                headers_sent = True
                for event in upstream_events:
                    if self._stopped.is_set() or self._revoked.is_set() or not self._lease.active():
                        raise StreamAborted("session_revoked")
                    with self._vault_lock:
                        frames = projector.feed(event)
                    for frame in frames:
                        peer.sendall(encode_chunk(frame))
                with self._vault_lock:
                    tail = projector.finalize()
                for frame in tail:
                    peer.sendall(encode_chunk(frame))
                peer.sendall(b"0\r\n\r\n")
                usage = projector.usage
                outcome = "completed"
        except RequestRefused as error:
            outcome = error.code
            if not headers_sent:
                with suppress(OSError):
                    peer.sendall(format_error_response(error.status, error.code, error.message))
        except StreamAborted as error:
            outcome = error.code
            if not headers_sent:
                with suppress(OSError):
                    peer.sendall(format_error_response(502, error.code, "Upstream response failed safety checks."))
            # If headers were already sent, intentionally omit terminating chunk 0\r\n\r\n.
        except (ConnectionError, StreamFailure) as error:
            outcome = error.code
            if not headers_sent:
                status, code, msg = _ERROR_MAP.get(
                    error.code, (502, "provider_error", "OpenAI request failed.")
                )
                with suppress(OSError):
                    peer.sendall(format_error_response(status, code, msg))
        except (OSError, TimeoutError, EOFError):
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
        shutil.copyfile(pkg_dir / "managed" / "relay.py", self.source_dir / "relay.py")
        shutil.copyfile(pkg_dir / "session_relay.py", self.source_dir / "session_relay.py")
        (self.source_dir / "relay.py").chmod(0o444)
        (self.source_dir / "session_relay.py").chmod(0o444)
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
        except (OSError, TimeoutError) as exc:
            error = exc
        finally:
            if self._lifetime_fd is not None:
                fd, self._lifetime_fd = self._lifetime_fd, None
                with suppress(OSError):
                    os.close(fd)
        if error is not None:
            raise error


def _mcs_pair(label: str) -> set[int] | None:
    match = PROCESS_LABEL.fullmatch(label or "")
    if not match:
        return None
    pair = set(map(int, match.groups()))
    return pair if len(pair) == 2 else None


def _verify_relay_isolation(relay_id: str, relay_image: str, agent_level: str, other_containers: list[str]) -> None:
    details = inspected("container", "inspect", relay_id)
    host = details["HostConfig"]
    config = details["Config"]
    relay_mcs = _mcs_pair(details.get("ProcessLabel") or "")
    mount_label = details.get("MountLabel") or ""
    if (not relay_mcs
            or not MOUNT_LABEL.fullmatch(mount_label)
            or (details.get("ProcessLabel") or "").split(":", 3)[-1] != mount_label.split(":", 3)[-1]
            or details.get("Image", "").removeprefix("sha256:") != relay_image.removeprefix("sha256:")
            or not host.get("ReadonlyRootfs") or host.get("Privileged")
            or host.get("IpcMode") != "private" or host.get("PidMode") != "private"
            or host.get("CgroupMode") != "private" or config.get("User") != "0:0"
            or details.get("EffectiveCaps") or host.get("SecurityOpt") != ["no-new-privileges"]):
        raise RuntimeError("Relay container failed isolation verification")
    agent_match = re.fullmatch(r"s0:c(\d+),c(\d+)", agent_level)
    if agent_match and set(map(int, agent_match.groups())) == relay_mcs:
        raise RuntimeError("Relay MCS collided with agent level")
    for name in other_containers:
        probe = podman("container", "inspect", name, check=False)
        if probe.returncode != 0:
            continue
        try:
            other = json.loads(probe.stdout)[0]
        except (ValueError, IndexError, TypeError):
            continue
        other_mcs = _mcs_pair(other.get("ProcessLabel") or "")
        if other_mcs and other_mcs == relay_mcs:
            raise RuntimeError(f"Relay MCS collided with sibling container {name}")


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


def _validate_spec(spec: dict) -> dict:
    if type(spec) is not dict:
        raise ValueError("Invalid launch spec")
    required = {
        "instance", "pod", "agent", "relay", "relay_image", "agent_image",
        "agent_mem", "level", "sandbox", "cwd", "home_vol", "chromium",
    }
    if not required <= set(spec):
        raise ValueError("Incomplete launch spec")
    if (not _INSTANCE_NAME.fullmatch(spec["instance"])
            or not _POD_NAME.fullmatch(spec["pod"])
            or not _LEVEL_RE.fullmatch(spec["level"])):
        raise ValueError("Malformed instance, pod, or SELinux level")
    return spec


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
        label, conn, binding = backend.active_connection()
        models = conn.models(binding)
        if not models:
            raise RouteUnavailable(Reason.MODEL_UNAVAILABLE)
    except Exception as error:
        return report_failure(terminal, error, operation="ChatGPT session")

    preview = ", ".join(models[:6]) + (f" (+{len(models) - 6} more)" if len(models) > 6 else "")
    terminal.write(f"ChatGPT registration: {label} (models: {preview})")
    terminal.write(
        "No API-key fallback will be forwarded. Provider tokens stay on the workstation behind an "
        "isolated relay. One approval covers multiple interactive turns and subagents in this session "
        "with no verified spending ceiling. Disconnect with `oc-sandbox openai disconnect` or exit OpenCode."
    )
    if not terminal.confirm(f"Start interactive ChatGPT OpenCode session for instance '{spec['instance']}'?"):
        terminal.error("Cancelled.")
        return 1

    try:
        instance_lock_fd = _open_instance_lock(backend._state, spec["instance"])
    except (BlockingIOError, OSError, RuntimeError):
        terminal.error(f"Instance '{spec['instance']}' already has an active provider session launch.")
        return 1

    worker_token = secrets.token_urlsafe(32)
    root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir=SHARED_TMP))
    job = _SessionJob(root, "inc_" + secrets.token_hex(16))
    relay_name = spec["relay"]
    agent_name = spec["agent"]
    pod_name = spec["pod"]
    relay_id: str | None = None
    agent_id: str | None = None
    broker: SessionBroker | None = None
    child_proc: subprocess.Popen | None = None
    stop_event = threading.Event()

    def forward_sig(signum, _frame):
        stop_event.set()

    prev_term = signal.signal(signal.SIGTERM, forward_sig)
    prev_hup = signal.signal(signal.SIGHUP, forward_sig)
    rc = 1
    clean = False
    try:
        job.prepare(generate_opencode_config(worker_token=worker_token, models=models))
        with ExitStack() as stack:
            stack.enter_context(backend.session_lease(label, binding, job))
            try:
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
                    is_selected=lambda: backend.active_label() == label,
                    on_revoke=stop_event.set,
                )
                broker.start()

                for cname in (agent_name, relay_name):
                    st = podman("container", "inspect", "--format", "{{.State.Status}}", cname, check=False)
                    if st.returncode == 0 and st.stdout.strip() == b"running":
                        raise RuntimeError(f"Container {cname} is already running")
                    if st.returncode == 0:
                        podman("rm", "-f", cname, check=False)

                relay_args = [
                    "create", "--pull=never", "--name", relay_name, "--pod", pod_name,
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
                relay_id = podman(*relay_args).stdout.decode("ascii").strip()
                if not IMAGE_ID.fullmatch(relay_id):
                    raise RuntimeError("Podman did not return a complete relay container ID")
                podman("start", relay_id)
                siblings = [spec["chromium"]]
                if spec.get("postgres"):
                    siblings.append(spec["postgres"])
                _verify_relay_isolation(relay_id, spec["relay_image"], spec["level"], siblings)
                _wait_relay_bound(relay_id)
                if stop_event.is_set() or broker._revoked.is_set() or not job.lease.active():
                    raise ConnectionError("connection_retired")
                job.activate()

                agent_args = [
                    "create", "-it", "--rm", "--name", agent_name, "--pod", pod_name,
                    "--label", "oc.sandbox=1", "--label", f"oc.instance={spec['instance']}",
                    "--label", "oc.provider=openai",
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
                if spec.get("pg_secret"):
                    agent_args.extend([
                        "--secret", f"{spec['pg_secret']},type=mount,target=/run/secrets/oc-pgpass,mode=0600",
                        "-e", "PGPASSFILE=/run/secrets/oc-pgpass",
                    ])
                if spec.get("dind_run"):
                    agent_args.extend([
                        "-v", f"{spec['dind_run']}:/run/dind",
                        "-e", "DOCKER_HOST=unix:///run/dind/podman.sock",
                        "-e", "CONTAINER_HOST=unix:///run/dind/podman.sock",
                    ])
                agent_args.append(spec["agent_image"])
                if stop_event.is_set() or broker._revoked.is_set() or not job.lease.active():
                    raise ConnectionError("connection_retired")
                agent_id = podman(*agent_args).stdout.decode("ascii").strip()
                if not IMAGE_ID.fullmatch(agent_id):
                    raise RuntimeError("Podman did not return a complete agent container ID")

                uid = os.getuid()
                runtime_dir = f"/run/user/{uid}"
                start_env = {
                    "PATH": "/usr/bin:/bin",
                    "HOME": os.environ.get("HOME", ""),
                    "TERM": os.environ.get("TERM", "xterm-256color"),
                    "XDG_RUNTIME_DIR": f"/run/host{runtime_dir}",
                    "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/host{runtime_dir}/bus",
                }
                if stop_event.is_set() or broker._revoked.is_set() or not job.lease.active():
                    raise ConnectionError("connection_retired")
                child_proc = subprocess.Popen(
                    [HOST_SPAWN, "/usr/bin/podman", "--remote=false", "--default-mounts-file=/dev/null",
                     "start", "-ai", agent_id],
                    env=start_env,
                )
                while child_proc.poll() is None:
                    if stop_event.wait(0.2):
                        with suppress(OSError):
                            child_proc.terminate()
                        podman("stop", "-t", "2", agent_id, check=False, timeout=6)
                        break
                rc = child_proc.wait()
            finally:
                cleanup_error: Exception | None = None
                try:
                    job.revoke()
                except Exception as exc:
                    cleanup_error = exc
                if broker is not None:
                    try:
                        broker.close()
                    except Exception as exc:
                        cleanup_error = cleanup_error or exc
                for cid in (agent_id, relay_id):
                    if cid is not None:
                        try:
                            _remove_container_verified(cid)
                        except Exception as exc:
                            cleanup_error = cleanup_error or exc
                try:
                    stack.close()
                except Exception as exc:
                    cleanup_error = cleanup_error or exc
                if cleanup_error is None:
                    clean = True
                else:
                    terminal.error(f"Provider session cleanup needs verification. Retained directory {root}")
                    rc = 1
    except KeyboardInterrupt:
        rc = 130
    except Exception as error:
        return report_failure(terminal, error, operation="ChatGPT session")
    finally:
        signal.signal(signal.SIGTERM, prev_term)
        signal.signal(signal.SIGHUP, prev_hup)
        with suppress(OSError):
            os.close(instance_lock_fd)
        if clean:
            with suppress(OSError):
                shutil.rmtree(root)
    return rc
