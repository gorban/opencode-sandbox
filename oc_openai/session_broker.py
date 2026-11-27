"""Host-side interactive ChatGPT Responses broker and foreground pod supervisor."""

from collections.abc import Callable
from contextlib import contextmanager, nullcontext, suppress
from dataclasses import dataclass
import fcntl
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import select
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

from oc_providers.catalog import (
    LaunchRefusedError,
    build_multi_provider_opencode_config,
    parse_provider_filter,
    plan_interactive_launch,
    validate_opencode_config,
)
from oc_providers.config import (
    ProviderConfigError,
    _account_home,
    _check_dir_stat,
    _inside_sandbox,
    load_provider_config,
)
from oc_providers.contracts import (
    ProviderIntegrityError,
    RELAY_PORT_MAX,
    RELAY_PORT_MIN,
    RelayMountPaths,
    SlotHandle,
)
from oc_providers.registry import default_session_adapters
from .cli import Reason, RouteUnavailable, StreamTerminal, report_failure
from .connection import ConnectionError
from .exposure import ExposureError, ExposureLedger
from .live import make_backend
from .profiles import ProfileError
from .proof_gate import ProofGateError
from .managed import relay as relay_mod
from .managed.runtime import (
    HOST_SPAWN,
    IMAGE_ID,
    JobRuntimeError,
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
    "openai-relay", "openai-home", "relay",
})
_RELAY_INSTANCE_RE = re.compile(r"relay(?:-\d+)?\Z", re.ASCII)
_BASE_SPEC_KEYS = frozenset({
    "instance", "pod", "agent", "relay", "relay_image", "agent_image",
    "agent_mem", "level", "sandbox", "cwd", "home_vol", "chromium",
    "postgres", "pg_secret", "dind", "dind_run",
})
_OPTIONAL_SPEC_KEYS = frozenset({"provider_filter", "cli_ui_mode"})
_SPEC_KEYS = _BASE_SPEC_KEYS | _OPTIONAL_SPEC_KEYS
_VALID_CLI_UI_MODES = frozenset({"default", "full", "mini"})

_ERR_PROOF_NOT_ARMED = "proof_gate_not_armed"

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
    "exposure_lock_busy": (503, "exposure_busy", "ChatGPT exposure ledger is temporarily busy; retry shortly."),
    "invalid_exposure_record": (403, "exposure_hold", "ChatGPT exposure record is invalid; interactive dispatch blocked."),
    "untrusted_exposure_store": (403, "exposure_hold", "ChatGPT exposure store failed trust checks."),
    _ERR_PROOF_NOT_ARMED: (403, _ERR_PROOF_NOT_ARMED, "Proof gate is closed during discovery."),
    "proof_gate_spent": (403, "proof_gate_spent", "Proof gate single-send latch already spent."),
    "proof_gate_incarnation_mismatch": (403, "proof_gate_incarnation_mismatch", "Proof gate job incarnation mismatch."),
    "proof_slot_not_approved": (403, "proof_slot_not_approved", "Slot is not approved for this proof run."),
    "proof_gate_foreground_lost": (403, "proof_gate_foreground_lost", "Foreground workstation terminal authority lost."),
    "proof_gate_approval_drift": (403, "proof_gate_approval_drift", "Approved registration or provider policy drifted."),
    "proof_evidence_sync_failed": (403, "proof_evidence_sync_failed", "Durable proof evidence sync failed."),
    "proof_gate_relay_unverified": (403, "proof_gate_relay_unverified", "Replacement turn relay verification incomplete."),
    "exposure_history_mutated": (403, "exposure_history_mutated", "Exposure history changed before proof write."),
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
    """Optional exposure hold, selection fence, revocation, and proof-gate callbacks for SessionBroker."""

    exposure_dir: Path | None = None
    acknowledged_exposure_digest: str | None = None
    authorization: object = None
    is_selected: object = None
    on_revoke: object = None
    proof_gate: object = None
    job_incarnation: str | None = None


@dataclass(frozen=True)
class ProofSessionOptions:
    """In-process proof-session hooks supplied only by the verified foreground owner."""

    proof_gate: object
    preconfirmed_plan: object = None
    agent_runner: object = None
    on_session_root_created: object = None
    on_slot_prepare: object = None
    on_slot_begin: object = None
    on_slot_finish: object = None
    on_slot_lease_released: object = None


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
        expected_port: int = RELAY_PORT_MIN,
    ):
        active_policy = policy or SessionPolicy()
        self.socket_path = Path(socket_path)
        self._proof = relay_proof
        self._worker_token = worker_token
        self._expected_port = expected_port
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
        self._proof_gate = active_policy.proof_gate
        self._job_incarnation = active_policy.job_incarnation
        self._vault = ReasoningVault()
        self._vault_lock = threading.Lock()
        self._turn_counter = 0
        self._stopped = threading.Event()
        self._revoked = threading.Event()
        self._exposure_revoked = threading.Event()
        self._revoke_notified = False
        self._lock = threading.Lock()
        self._clients: dict[socket.socket, threading.Thread] = {}
        self._client_arrivals: dict[socket.socket, object] = {}
        self._streaming_peers: set[socket.socket] = set()
        self._cancels: set[threading.Event] = set()
        self._listener: socket.socket | None = None
        self._wake_r: int | None = None
        self._wake_w: int | None = None
        self._accept_thread: threading.Thread | None = None
        self._watch_thread: threading.Thread | None = None
        self._socket_id: tuple[int, int] | None = None

    def _wake_accept_loop(self) -> None:
        wake_w = self._wake_w
        if wake_w is not None:
            with suppress(OSError):
                os.write(wake_w, b"\x01")

    def _drain_wakeup(self) -> None:
        wake_r = self._wake_r
        if wake_r is None:
            return
        with suppress(OSError):
            os.read(wake_r, 64)

    def _bind_nonblocking_listener(self, path: Path) -> tuple[socket.socket, tuple[int, int]]:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound_id: tuple[int, int] | None = None
        try:
            listener.bind(str(path))
            info = path.lstat()
            bound_id = (info.st_dev, info.st_ino)
            path.chmod(0o600)
            listener.listen(MAX_CLIENTS)
            listener.setblocking(False)
            return listener, bound_id
        except BaseException:
            with suppress(OSError):
                listener.close()
            if bound_id is not None:
                with suppress(OSError):
                    cur = path.lstat()
                    if (cur.st_dev, cur.st_ino) == bound_id:
                        path.unlink()
            raise

    def _revoke_listener_on_publication_failure(self) -> None:
        self._trigger_revocation()
        old = self._listener
        self._listener = None
        if old is not None:
            with suppress(OSError):
                old.close()
        self._wake_accept_loop()

    def start(self) -> None:
        wake_r, wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            listener, self._socket_id = self._bind_nonblocking_listener(self.socket_path)
        except BaseException:
            os.close(wake_r)
            os.close(wake_w)
            raise
        self._wake_r = wake_r
        self._wake_w = wake_w
        self._listener = listener
        reg_drain = getattr(self._proof_gate, "register_accept_drain", None)
        if callable(reg_drain):
            try:
                reg_drain(self._rotate_listener_locked, self._revoke_listener_on_publication_failure)
            except TypeError:
                reg_drain(self._rotate_listener_locked)
        self._accept_thread = threading.Thread(target=self._accept_loop, name="oc-chat-broker", daemon=True)
        self._watch_thread = threading.Thread(target=self._watch_revocation, name="oc-chat-watch", daemon=True)
        self._accept_thread.start()
        self._watch_thread.start()

    def _exposure_mutated(self) -> bool:
        if self._exposure_dir is None:
            return False
        try:
            hold = ExposureLedger(self._exposure_dir).inspect_hold()
        except ExposureError as exc:
            code = exc.args[0] if exc.args and type(exc.args[0]) is str else ""
            if code == "exposure_lock_busy":
                return False
            return True
        if hold.blocked:
            return (
                self._acknowledged_exposure_digest is None
                or not hmac.compare_digest(hold.digest, self._acknowledged_exposure_digest)
            )
        return self._acknowledged_exposure_digest is not None

    def _trigger_revocation(self, *, exposure: bool = False, exclude_peer: socket.socket | None = None) -> None:
        if exposure:
            self._exposure_revoked.set()
        self._revoked.set()
        self._cancel_active_turns(exclude_peer=exclude_peer, streaming_only=exposure)
        notify = False
        with self._lock:
            if not self._revoke_notified:
                self._revoke_notified = True
                notify = True
        if notify and self._on_revoke is not None:
            with suppress(Exception):
                self._on_revoke()

    def _watch_revocation(self) -> None:
        while not self._stopped.is_set():
            retired = False
            exposure_changed = False
            try:
                self._connection.require_active(self._binding)
                if self._is_selected is not None and not self._is_selected():
                    retired = True
            except ConnectionError:
                retired = True
            if not retired and self._exposure_mutated():
                exposure_changed = True
                retired = True
            if retired or self._lease.status() == "terminal":
                self._trigger_revocation(exposure=exposure_changed)
                return
            self._stopped.wait(0.15)

    def _cancel_active_turns(self, *, exclude_peer: socket.socket | None = None, streaming_only: bool = False) -> None:
        with self._lock:
            for event in self._cancels:
                event.set()
            targets = self._streaming_peers if streaming_only else self._clients
            for peer in targets:
                if peer is exclude_peer:
                    continue
                with suppress(OSError):
                    peer.shutdown(socket.SHUT_RDWR)

    def _try_accept_from(self, listener: socket.socket | None) -> tuple[socket.socket | None, bool]:
        """Return (peer, fatal_error). BlockingIOError/EINTR/ECONNABORTED are non-fatal empty drains."""
        if listener is None or self._stopped.is_set():
            return None, False
        try:
            peer, _ = listener.accept()
            return peer, False
        except (BlockingIOError, InterruptedError, ConnectionAbortedError):
            return None, False
        except OSError:
            if self._stopped.is_set() or listener is not self._listener:
                return None, False
            return None, True

    def _try_accept_nonblocking(self) -> socket.socket | None:
        peer, fatal = self._try_accept_from(self._listener)
        if fatal:
            self._trigger_revocation()
        return peer

    def _dispatch_accepted_peer(self, peer: socket.socket, arrival) -> None:
        with suppress(OSError):
            peer.setblocking(True)
        with self._lock:
            if self._stopped.is_set() or len(self._clients) >= MAX_CLIENTS:
                peer.close()
                return
            worker = threading.Thread(target=self._handle_peer, args=(peer,), daemon=True)
            self._clients[peer] = worker
            self._client_arrivals[peer] = arrival
            try:
                worker.start()
            except RuntimeError:
                self._clients.pop(peer, None)
                self._client_arrivals.pop(peer, None)
                peer.close()

    def _rotate_listener_locked(self, pre_snapshot=None) -> None:
        """Atomically replace UDS listener (os.replace) and drain old backlog with pre_snapshot."""
        if self._stopped.is_set() or self._listener is None:
            return
        old_listener = self._listener
        tmp_path = self.socket_path.parent / f"s.{secrets.token_hex(4)}"
        new_listener, tmp_id = self._bind_nonblocking_listener(tmp_path)
        try:
            os.replace(tmp_path, self.socket_path)
            info = self.socket_path.lstat()
        except BaseException:
            with suppress(OSError):
                new_listener.close()
            with suppress(OSError):
                cur = tmp_path.lstat()
                if (cur.st_dev, cur.st_ino) == tmp_id:
                    tmp_path.unlink()
            raise
        self._listener = new_listener
        self._socket_id = (info.st_dev, info.st_ino)
        self._wake_accept_loop()
        # Every connection enqueued by the kernel BEFORE os.replace landed on old_listener.
        drain_arrival = pre_snapshot
        if drain_arrival is None and self._proof_gate is not None:
            drain_arrival = self._proof_gate.snapshot_arrival()
        try:
            while not self._stopped.is_set():
                peer, _ = self._try_accept_from(old_listener)
                if peer is None:
                    break
                self._dispatch_accepted_peer(peer, drain_arrival)
        finally:
            with suppress(OSError):
                old_listener.close()

    def _accept_one_serialized(self) -> tuple[socket.socket | None, object]:
        accept_fenced = getattr(self._proof_gate, "accept_with_snapshot", None)
        if callable(accept_fenced):
            return accept_fenced(self._try_accept_nonblocking)
        peer = self._try_accept_nonblocking()
        if peer is None:
            return None, None
        arrival = self._proof_gate.snapshot_arrival() if self._proof_gate is not None else None
        return peer, arrival

    def _poll_listener_once(self) -> bool:
        listener = self._listener
        wake_r = self._wake_r
        if listener is None:
            return False
        poller = select.poll()
        try:
            listen_fd = listener.fileno()
            if listen_fd < 0:
                return False
            poller.register(listen_fd, select.POLLIN)
            if wake_r is not None:
                poller.register(wake_r, select.POLLIN)
            events = poller.poll(int(relay_mod.GRANT_POLL * 1000))
        except (OSError, ValueError):
            if self._stopped.is_set():
                return False
            if listener is not self._listener:
                return True
            self._trigger_revocation()
            return False
        for fd, mask in events:
            if wake_r is not None and fd == wake_r:
                self._drain_wakeup()
            elif mask & (select.POLLERR | select.POLLNVAL) and listener is self._listener and not self._stopped.is_set():
                self._trigger_revocation()
                return False
        return True

    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            if not self._poll_listener_once():
                if self._stopped.is_set() or self._revoked.is_set():
                    return
                continue
            while not self._stopped.is_set():
                peer, arrival = self._accept_one_serialized()
                if peer is None:
                    break
                self._dispatch_accepted_peer(peer, arrival)

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
    def _exposure_fence(self, peer: socket.socket | None = None):
        if self._exposure_dir is None:
            raise ConnectionError("exposure_store_unavailable")
        try:
            with ExposureLedger(self._exposure_dir).dispatch_fence(
                acknowledged_digest=self._acknowledged_exposure_digest,
                wait=0.5,
            ):
                yield
        except ExposureError as exc:
            code = exc.args[0] if exc.args and type(exc.args[0]) is str else "exposure_hold_active"
            if code != "exposure_lock_busy":
                self._trigger_revocation(exposure=True, exclude_peer=peer)
            raise ConnectionError(code) from None

    def _require_turn_active(self) -> None:
        if self._stopped.is_set() or self._revoked.is_set() or not self._lease.active():
            raise StreamAborted("session_revoked")
        if self._is_selected is not None and not self._is_selected():
            raise StreamAborted("session_revoked")

    def _send_slice_fenced(self, peer: socket.socket, chunk: memoryview) -> int:
        authorize = self._authorization or nullcontext
        active_fence = getattr(self._connection, "active_fence", None)
        conn_fence = (lambda: active_fence(self._binding)) if active_fence is not None else nullcontext
        prev_timeout = peer.gettimeout()
        try:
            with authorize(), conn_fence(), self._lease.fence():
                if self._stopped.is_set() or self._revoked.is_set() or not self._lease.active():
                    raise StreamAborted("session_revoked")
                if self._authorization is None and self._is_selected is not None and not self._is_selected():
                    raise StreamAborted("session_revoked")
                if active_fence is None:
                    self._connection.require_active(self._binding)
                peer.setblocking(False)
                try:
                    sent = peer.send(chunk)
                except BlockingIOError:
                    return 0
                finally:
                    peer.settimeout(prev_timeout)
                if sent <= 0:
                    raise OSError("peer closed during fenced send")
                return sent
        except (ConnectionError, ProfileError, RouteUnavailable):
            raise StreamAborted("session_revoked") from None

    def _send_fenced(self, peer: socket.socket, payload: bytes) -> None:
        if not payload:
            return
        view = memoryview(payload)
        offset = 0
        deadline = time.monotonic() + 5.0
        while offset < len(view):
            if self._stopped.is_set() or self._revoked.is_set() or not self._lease.active():
                raise StreamAborted("session_revoked")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("fenced peer write timed out")
            _, writable, _ = select.select([], [peer], [], min(0.1, remaining))
            if not writable:
                continue
            offset += self._send_slice_fenced(peer, view[offset:])

    @contextmanager
    def _first_write_fence(self, peer: socket.socket | None = None):
        with self._lease.fence(), self._exposure_fence(peer):
            yield

    def _claim_proof_write(self, arrival, outbound_body) -> None:
        if self._proof_gate is None:
            return
        try:
            self._proof_gate.claim_for_write(
                arrival,
                outbound_body,
                job_incarnation=self._job_incarnation or "",
            )
        except ProofGateError as exc:
            code = exc.args[0] if exc.args and type(exc.args[0]) is str else _ERR_PROOF_NOT_ARMED
            raise ConnectionError(code) from None
        except Exception:
            raise ConnectionError(_ERR_PROOF_NOT_ARMED) from None

    def _stream_responses_turn(self, peer: socket.socket, parsed, cancel: threading.Event,
                               state: dict, *, arrival=None) -> tuple[str, tuple[int, int, int] | None]:
        turn_deadline = min(time.monotonic() + TURN_TIMEOUT_SECONDS, self._lease.deadline_ns / 1e9)
        outbound_body = parsed.body
        allowed_tools = parsed.allowed_tools
        if self._proof_gate is not None:
            outbound_body = self._proof_gate.validate_and_canonicalize(
                parsed.raw_body,
                arrival=arrival,
                job_incarnation=self._job_incarnation or "",
            )
            allowed_tools = frozenset()
        projector = SessionStreamProjector(
            model=parsed.model, local_response_id=self._next_response_id(), vault=self._vault,
            allowed_tools=allowed_tools,
        )

        def before_write():
            if self._stopped.is_set() or self._revoked.is_set() or not self._lease.active():
                raise ConnectionError("connection_retired")
            if self._authorization is None and self._is_selected is not None and not self._is_selected():
                raise ConnectionError("connection_retired")
            self._claim_proof_write(arrival, outbound_body)

        with self._connection.interactive_responses(
            self._binding, outbound_body, before_write,
            authorization=self._authorization,
            write_fence=lambda: self._first_write_fence(peer),
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
            if self._proof_gate is not None:
                self._proof_gate.record_delivery_complete(
                    usage=projector.usage,
                    completed_text=projector.completed_assistant_text,
                    streamed_text=projector.streamed_assistant_text,
                    tool_calls=projector.tool_calls,
                )
            return "completed", projector.usage

    def _send_peer_error(self, peer: socket.socket, headers_sent: bool, status: int, code: str, message: str) -> None:
        if not headers_sent:
            with suppress(OSError):
                peer.sendall(format_error_response(status, code, message))

    def _handle_peer(self, peer: socket.socket) -> None:
        cancel = threading.Event()
        with self._lock:
            arrival = self._client_arrivals.pop(peer, None)
            self._cancels.add(cancel)
        if arrival is None and self._proof_gate is not None:
            arrival = self._proof_gate.snapshot_arrival()
        state = {"headers_sent": False}
        model: str | None = None
        outcome = "error"
        usage = None
        try:
            raw = self._read_peer_request(peer)
            if raw is None:
                return
            if self._exposure_revoked.is_set():
                peer.sendall(format_error_response(
                    403, "exposure_hold", "ChatGPT interactive dispatch is blocked by an exposure hold.",
                ))
                outcome = "exposure_hold_active"
                return
            if self._revoked.is_set() or not self._lease.active():
                peer.sendall(format_error_response(401, "session_revoked", "ChatGPT session is no longer active."))
                outcome = "session_revoked"
                return
            with self._vault_lock:
                parsed = parse_worker_request(
                    raw, expected_token=self._worker_token,
                    allowed_models=self._allowed_models, vault=self._vault,
                    expected_port=self._expected_port,
                )
            if parsed.route == "models":
                peer.sendall(format_models_response(self._models))
                outcome = "models_ok"
                return
            model = parsed.model
            with self._lock:
                self._streaming_peers.add(peer)
            try:
                outcome, usage = self._stream_responses_turn(peer, parsed, cancel, state, arrival=arrival)
            finally:
                with self._lock:
                    self._streaming_peers.discard(peer)
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
                self._client_arrivals.pop(peer, None)

    def close(self) -> None:
        self._stopped.set()
        unreg_drain = getattr(self._proof_gate, "unregister_accept_drain", None)
        if callable(unreg_drain):
            unreg_drain(self._rotate_listener_locked)
        self._wake_accept_loop()
        self._cancel_active_turns()
        if self._listener is not None:
            with suppress(OSError):
                self._listener.close()
        current = threading.current_thread()
        if self._accept_thread is not None and self._accept_thread is not current:
            self._accept_thread.join(timeout=1.5)
        if self._watch_thread is not None and self._watch_thread is not current:
            self._watch_thread.join(timeout=1.5)
        for attr in ("_wake_r", "_wake_w"):
            fd = getattr(self, attr)
            if fd is not None:
                setattr(self, attr, None)
                with suppress(OSError):
                    os.close(fd)
        with self._lock:
            threads = list(self._clients.values())
        deadline = time.monotonic() + 2
        for thread in threads:
            if thread is not current:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if self._socket_id is not None and self.socket_path.exists():
            info = self.socket_path.lstat()
            if (info.st_dev, info.st_ino) == self._socket_id:
                with suppress(OSError):
                    self.socket_path.unlink()


def build_openai_provider_entry(
    *, label: str, port: int, worker_token: str, models: tuple[str, ...]
) -> dict:
    """Build one OpenCode `providers[<id>]` entry pointing at an isolated OpenAI relay port."""
    model_defs = {
        slug: {
            "name": slug,
            "capabilities": {"tools": True, "input": ["text"], "output": ["text"]},
            "limit": {"context": 128000, "output": 16384},
        }
        for slug in models
    }
    return {
        "name": f"ChatGPT Subscription ({label})",
        "package": "@opencode/ai/providers/openai-compatible/responses",
        "settings": {
            "baseURL": f"http://127.0.0.1:{port}/v1",
            "apiKey": worker_token,
            "store": False,
            "include": ["reasoning.encrypted_content"],
        },
        "models": model_defs,
    }


def generate_opencode_config(*, worker_token: str, models: tuple[str, ...]) -> dict:
    """Build the read-only /etc/opencode/opencode.json enforcing local-only ChatGPT routing."""
    default_model = "gpt-6.2-sol" if "gpt-6.2-sol" in models else models[0]
    provider = build_openai_provider_entry(
        label="Workstation Broker", port=RELAY_PORT_MIN, worker_token=worker_token, models=models,
    )
    provider["name"] = "ChatGPT Subscription (Workstation Broker)"
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
        "providers": {"local": provider},
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

    def prepare(self, config_payload: dict | None = None) -> None:
        self.root.chmod(0o700)
        subdirs = ("grant", "provider", "proof", "source", "opencode") if config_payload is not None else (
            "grant", "provider", "proof", "source"
        )
        for sub in subdirs:
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
        if config_payload is not None:
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


def _is_forbidden_pod_port(target: int, *, allow_postgres: bool) -> bool:
    return (
        not 1 <= target <= 65535
        or target == 9222
        or RELAY_PORT_MIN <= target <= RELAY_PORT_MAX
        or (target == 5432 and not allow_postgres)
    )


def _parse_pod_port_bindings(key, values, *, allow_postgres: bool) -> list[str]:
    match = _PORT_KEY_RE.fullmatch(key) if type(key) is str else None
    if not match or type(values) is not list:
        raise RuntimeError("Pod has unsupported port bindings")
    target = int(match.group(1))
    if _is_forbidden_pod_port(target, allow_postgres=allow_postgres):
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


def _verify_pod_with_containers(spec: dict) -> tuple[str, list[dict]]:
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
    containers = pod_info.get("Containers") or []
    if type(containers) is not list:
        raise RuntimeError("Pod container listing is malformed")
    return pod_id, [entry for entry in containers if type(entry) is dict]


def _verify_pod(spec: dict) -> str:
    pod_id, _containers = _verify_pod_with_containers(spec)
    return pod_id


_VALID_SLOT_ROUTE_STATES = frozenset({"pending", "active", "retired"})
_REQUIRED_CALLABLE_SLOT_HOOKS = (
    "revoke_grant",
    "close_broker",
    "activate_route",
    "route_state",
    "is_revoked",
    "has_active_clients",
    "mark_relay_created",
    "confirm_relay_removed",
    "authorize_lease_release",
    "deny_lease_release",
    "bind_release_authority",
    "lease_release_confirmed",
)


_OPTIONAL_CALLABLE_SLOT_HOOKS: tuple[str, ...] = ()


def _is_openai_slot_identity(handle: SlotHandle) -> bool:
    return (
        type(handle.scoped_id) is str
        and handle.scoped_id.startswith("openai--")
        and type(handle.provider_label) is str
        and (handle.provider_label.startswith("openai/") or handle.provider_label.startswith("openai--"))
    )


def _adapter_allows_legacy(adapter: object, kind: str) -> bool:
    return kind == "openai" and getattr(adapter, "kind", "openai") == "openai"


def _is_legacy_openai_handle(handle: SlotHandle, *, allow_legacy: bool = True) -> bool:
    if not allow_legacy or not _is_openai_slot_identity(handle):
        return False
    if isinstance(handle.job, _SessionJob) and isinstance(handle.broker, SessionBroker):
        return True
    has_legacy_broker = hasattr(handle.broker, "close") and hasattr(handle.broker, "_revoked")
    if isinstance(handle.job, _SessionJob) and has_legacy_broker:
        return True
    return hasattr(handle.job, "revoke") and has_legacy_broker


def _validate_relay_paths(paths: object, provider_label: str) -> RelayMountPaths:
    if not isinstance(paths, RelayMountPaths):
        raise ProviderIntegrityError(
            "incomplete_slot_handle",
            f"Slot handle for '{provider_label}' must provide RelayMountPaths.",
        )
    for field_name in ("source_dir", "provider_socket", "grant_dir", "proof_file"):
        if not isinstance(getattr(paths, field_name), Path):
            raise ProviderIntegrityError(
                "incomplete_slot_handle",
                f"Slot handle for '{provider_label}' has invalid relay path '{field_name}'.",
            )
    return paths


def _path_within_root(path: Path, root: Path) -> bool:
    if not path.is_absolute() or ".." in path.parts or "." in path.parts:
        return False
    if not path.is_relative_to(root):
        return False
    try:
        resolved_root = root.resolve(strict=True)
        resolved_parent = path.parent.resolve(strict=True)
    except OSError:
        return False
    if not (resolved_parent == resolved_root or resolved_parent.is_relative_to(resolved_root)):
        return False
    with suppress(OSError):
        if path.is_symlink():
            return False
    return True


def _verify_slot_handle_identity(
    handle: SlotHandle,
    *,
    expected_slot_index: int,
    expected_scoped_id: str,
    expected_provider_label: str,
    expected_port: int,
    expected_slot_root: Path,
    allow_legacy: bool = False,
) -> None:
    if (
        type(handle.slot_index) is not int
        or type(handle.scoped_id) is not str
        or type(handle.provider_label) is not str
        or type(handle.port) is not int
        or handle.slot_index != expected_slot_index
        or handle.scoped_id != expected_scoped_id
        or handle.provider_label != expected_provider_label
        or handle.port != expected_port
    ):
        raise ProviderIntegrityError(
            "slot_identity_mismatch",
            f"Slot handle identity did not match planned slot '{expected_provider_label}'.",
        )
    if (
        handle.relay_paths is None
        and _is_legacy_openai_handle(handle, allow_legacy=allow_legacy)
        and not hasattr(handle.job, "source_dir")
    ):
        return
    paths = _slot_relay_paths(handle, allow_legacy=allow_legacy)
    for field_name in ("source_dir", "provider_socket", "grant_dir", "proof_file"):
        candidate = getattr(paths, field_name)
        if not _path_within_root(candidate, expected_slot_root):
            raise ProviderIntegrityError(
                "slot_identity_mismatch",
                f"Slot handle relay path '{field_name}' escaped planned slot root.",
            )


def _validate_slot_handle(handle: SlotHandle, *, allow_legacy: bool = False) -> None:
    for opt_hook in _OPTIONAL_CALLABLE_SLOT_HOOKS:
        val = getattr(handle, opt_hook, None)
        if val is not None and not callable(val):
            raise ProviderIntegrityError(
                "invalid_slot_hook",
                f"Slot handle for '{handle.provider_label}' has non-callable hook '{opt_hook}'.",
            )
    if _is_legacy_openai_handle(handle, allow_legacy=allow_legacy):
        if handle.relay_paths is not None:
            _validate_relay_paths(handle.relay_paths, handle.provider_label)
        return
    _validate_relay_paths(handle.relay_paths, handle.provider_label)
    for hook_name in _REQUIRED_CALLABLE_SLOT_HOOKS:
        if not callable(getattr(handle, hook_name, None)):
            raise ProviderIntegrityError(
                "incomplete_slot_handle",
                f"Slot handle for '{handle.provider_label}' is missing required hook '{hook_name}'.",
            )


def _slot_relay_paths(handle: SlotHandle, *, allow_legacy: bool = False) -> RelayMountPaths:
    if handle.relay_paths is not None:
        return _validate_relay_paths(handle.relay_paths, handle.provider_label)
    if _is_legacy_openai_handle(handle, allow_legacy=allow_legacy) and hasattr(handle.job, "source_dir"):
        return RelayMountPaths(
            source_dir=handle.job.source_dir,
            provider_socket=handle.job.provider_socket,
            grant_dir=handle.job.grant,
            proof_file=handle.job.proof_file,
        )
    raise ProviderIntegrityError(
        "incomplete_slot_handle",
        f"Slot handle for '{handle.provider_label}' is missing relay_paths.",
    )


def _slot_is_revoked(handle: SlotHandle, *, allow_legacy: bool = False) -> bool:
    if handle.is_revoked is not None:
        result = handle.is_revoked()
        if type(result) is not bool:
            raise ProviderIntegrityError("invalid_slot_hook", "Slot is_revoked hook must return bool.")
        return result
    if _is_legacy_openai_handle(handle, allow_legacy=allow_legacy):
        return bool(handle.broker._revoked.is_set())
    raise ProviderIntegrityError(
        "incomplete_slot_handle",
        f"Slot handle for '{handle.provider_label}' is missing is_revoked hook.",
    )


def _legacy_lease_route_state(lease) -> str:
    if lease is None:
        return "retired"
    status = lease.status()
    if status == "pending":
        return "pending" if lease.deadline_ns > time.monotonic_ns() else "retired"
    if status == "active":
        return "active" if lease.active() else "retired"
    return "retired"


def _slot_route_state(handle: SlotHandle, *, allow_legacy: bool = False) -> str:
    if handle.route_state is not None:
        result = handle.route_state()
        if type(result) is not str or result not in _VALID_SLOT_ROUTE_STATES:
            raise ProviderIntegrityError("invalid_slot_hook", "Slot route_state hook returned invalid state.")
        return result
    if _is_legacy_openai_handle(handle, allow_legacy=allow_legacy):
        return _legacy_lease_route_state(getattr(handle.job, "lease", None))
    raise ProviderIntegrityError(
        "incomplete_slot_handle",
        f"Slot handle for '{handle.provider_label}' is missing route_state hook.",
    )


def _slot_has_active_clients(handle: SlotHandle, *, allow_legacy: bool = False) -> bool:
    if handle.has_active_clients is not None:
        result = handle.has_active_clients()
        if type(result) is not bool:
            raise ProviderIntegrityError("invalid_slot_hook", "Slot has_active_clients hook must return bool.")
        return result
    if _is_legacy_openai_handle(handle, allow_legacy=allow_legacy):
        if isinstance(handle.broker, SessionBroker):
            with handle.broker._lock:
                return bool(handle.broker._clients)
        return False
    raise ProviderIntegrityError(
        "incomplete_slot_handle",
        f"Slot handle for '{handle.provider_label}' is missing has_active_clients hook.",
    )


def _slot_revoke_grant(handle: SlotHandle, *, allow_legacy: bool = False) -> None:
    if handle.revoke_grant is not None:
        handle.revoke_grant()
        return
    if _is_legacy_openai_handle(handle, allow_legacy=allow_legacy):
        handle.job.revoke()
        return
    raise ProviderIntegrityError(
        "incomplete_slot_handle",
        f"Slot handle for '{handle.provider_label}' is missing revoke_grant hook.",
    )


def _slot_close_broker(handle: SlotHandle, *, allow_legacy: bool = False) -> None:
    if handle.close_broker is not None:
        handle.close_broker()
        return
    if _is_legacy_openai_handle(handle, allow_legacy=allow_legacy):
        handle.broker.close()
        return
    raise ProviderIntegrityError(
        "incomplete_slot_handle",
        f"Slot handle for '{handle.provider_label}' is missing close_broker hook.",
    )


def _slot_activate_route(handle: SlotHandle, *, allow_legacy: bool = False) -> None:
    if handle.activate_route is not None:
        handle.activate_route()
        return
    if _is_legacy_openai_handle(handle, allow_legacy=allow_legacy):
        handle.job.activate()
        return
    raise ProviderIntegrityError(
        "incomplete_slot_handle",
        f"Slot handle for '{handle.provider_label}' is missing activate_route hook.",
    )


def _slot_lease_release_confirmed(handle: SlotHandle, *, allow_legacy: bool = False) -> bool:
    checker = handle.lease_release_confirmed
    if checker is not None:
        result = checker()
        if type(result) is not bool:
            raise ProviderIntegrityError(
                "invalid_slot_hook", "Slot lease_release_confirmed hook must return bool.",
            )
        return result
    if _is_legacy_openai_handle(handle, allow_legacy=allow_legacy):
        return True
    raise ProviderIntegrityError(
        "incomplete_slot_handle",
        f"Slot handle for '{handle.provider_label}' is missing lease_release_confirmed hook.",
    )


def _extract_mount_paths(job_or_paths: _SessionJob | RelayMountPaths) -> RelayMountPaths:
    if isinstance(job_or_paths, RelayMountPaths):
        return job_or_paths
    return RelayMountPaths(
        source_dir=job_or_paths.source_dir,
        provider_socket=job_or_paths.provider_socket,
        grant_dir=job_or_paths.grant,
        proof_file=job_or_paths.proof_file,
    )


def _verify_relay_mounts(details: dict, job: _SessionJob | RelayMountPaths) -> None:
    paths = _extract_mount_paths(job)
    expected = {
        "/source": paths.source_dir,
        "/provider": paths.provider_socket.parent,
        "/grant": paths.grant_dir,
        "/proof": paths.proof_file.parent,
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


def _verify_relay_labels(relay_id: str, details: dict, job: _SessionJob | RelayMountPaths) -> None:
    expected_proc = (details.get("ProcessLabel") or "").encode("ascii")
    effective_proc = podman("exec", relay_id, "cat", "/proc/self/attr/current").stdout.removesuffix(b"\0")
    if effective_proc != expected_proc:
        raise RuntimeError("Unexpected effective relay SELinux process label")
    expected_mount = (details.get("MountLabel") or "").encode("ascii")
    mount_paths = _extract_mount_paths(job)
    paths = (
        mount_paths.source_dir,
        mount_paths.provider_socket.parent,
        mount_paths.provider_socket,
        mount_paths.grant_dir,
        mount_paths.proof_file.parent,
        mount_paths.proof_file,
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


def _valid_relay_security_opt(sec_opt: object, expected_level: str) -> bool:
    if type(sec_opt) is not list or not all(type(item) is str for item in sec_opt):
        return False
    if sec_opt == ["no-new-privileges"]:
        return True
    return len(sec_opt) == 2 and set(sec_opt) == {"no-new-privileges", f"label=level:{expected_level}"}


def _random_relay_mcs_level(forbidden_level: str) -> str:
    forbidden_match = _LEVEL_RE.fullmatch(forbidden_level or "")
    forbidden_pair = set(map(int, forbidden_match.groups())) if forbidden_match else set()
    rng = secrets.SystemRandom()
    while True:
        first, second = sorted(rng.sample(range(1024), 2))
        if {first, second} != forbidden_pair:
            return f"s0:c{first},c{second}"


def _verify_relay_host_flags(details: dict, relay_level: str, *, require_effective_caps: bool) -> bool:
    host = details["HostConfig"]
    config = details["Config"]
    caps_ok = (not details.get("EffectiveCaps")) if require_effective_caps else True
    return (
        bool(host.get("ReadonlyRootfs"))
        and not host.get("Privileged")
        and host.get("IpcMode") == "private"
        and host.get("PidMode") == "private"
        and host.get("CgroupMode") == "private"
        and config.get("User") == "0:0"
        and caps_ok
        and _valid_relay_security_opt(host.get("SecurityOpt"), relay_level)
    )


def _verify_relay_static_config(
    details: dict,
    relay_image: str,
    pod_id: str,
    agent_level: str,
    *,
    require_effective_caps: bool,
) -> set[int]:
    relay_mcs = _mcs_pair(details.get("ProcessLabel") or "")
    mount_label = details.get("MountLabel") or ""
    relay_level = (details.get("ProcessLabel") or "").split(":", 3)[-1]
    image_ok = details.get("Image", "").removeprefix("sha256:") == relay_image.removeprefix("sha256:")
    labels_ok = bool(relay_mcs) and bool(MOUNT_LABEL.fullmatch(mount_label)) and relay_level == mount_label.split(":", 3)[-1]
    if (
        not labels_ok
        or details.get("Pod") != pod_id
        or not image_ok
        or not _verify_relay_host_flags(details, relay_level, require_effective_caps=require_effective_caps)
    ):
        raise RuntimeError("Relay container failed isolation verification")
    agent_match = _LEVEL_RE.fullmatch(agent_level)
    if not agent_match or set(map(int, agent_match.groups())) == relay_mcs:
        raise RuntimeError("Relay MCS collided with agent level")
    return relay_mcs


def _verify_relay_prestart(
    relay_id: str,
    relay_image: str,
    pod_id: str,
    agent_level: str,
    job: _SessionJob | RelayMountPaths,
    other_containers: list[str],
) -> None:
    """Verify relay config, mounts, and non-colliding MCS against agent and siblings BEFORE start."""
    details = inspected("container", "inspect", relay_id)
    relay_mcs = _verify_relay_static_config(
        details, relay_image, pod_id, agent_level, require_effective_caps=False,
    )
    _verify_relay_mounts(details, job)
    _verify_sibling_mcs(other_containers, relay_mcs)


def _verify_relay_isolation(relay_id: str, relay_image: str, pod_id: str, agent_level: str,
                            job: _SessionJob | RelayMountPaths, other_containers: list[str]) -> None:
    details = inspected("container", "inspect", relay_id)
    relay_mcs = _verify_relay_static_config(
        details, relay_image, pod_id, agent_level, require_effective_caps=True,
    )
    _verify_relay_mounts(details, job)
    _verify_relay_labels(relay_id, details, job)
    _verify_sibling_mcs(other_containers, relay_mcs)


def _remove_container_verified(container_id: str) -> None:
    podman("rm", "-f", container_id, check=False, timeout=8)
    exists = podman("container", "exists", container_id, check=False, timeout=4)
    if exists.returncode != 1:
        raise RuntimeError(f"Could not confirm container removal ({container_id[:12]})")


def _normalize_lock_root(state_dir: Path) -> Path:
    path = Path(state_dir)
    if not path.is_absolute():
        raise RuntimeError("Session lock directory must be absolute")
    parts = [part for part in path.parts[1:] if part]
    if not parts or any(part in (".", "..") for part in parts):
        raise RuntimeError("Session lock directory is not normalized")
    if parts[0] == "home":
        home_path = Path("/home")
        var_home = Path("/var/home")
        try:
            home_stat = os.lstat(home_path)
            if stat.S_ISLNK(home_stat.st_mode) and home_stat.st_uid == 0 and home_path.resolve(strict=True) == var_home:
                vh_stat = os.lstat(var_home)
                if stat.S_ISDIR(vh_stat.st_mode) and vh_stat.st_uid == 0:
                    return var_home.joinpath(*parts[1:])
        except OSError:
            raise RuntimeError("Untrusted session lock directory") from None
    return Path("/", *parts)


def _open_lock_parent_fd(state_dir: Path) -> int:
    target = _normalize_lock_root(state_dir)
    uid = os.geteuid()
    try:
        sandbox = _account_home() / "opencode-sandbox"
    except ProviderConfigError as exc:
        raise RuntimeError(f"Untrusted account home for session lock: {exc}") from None
    parts = [part for part in target.parts[1:] if part]
    dir_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    current = Path("/")
    try:
        for index, part in enumerate(parts):
            current = current / part
            is_last = index == len(parts) - 1
            if _inside_sandbox(current, sandbox, check_contains=is_last):
                raise RuntimeError("Session lock directory overlaps agent sandbox")
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd,
            )
            os.close(dir_fd)
            dir_fd = next_fd
            try:
                _check_dir_stat(os.fstat(dir_fd), current=current, is_target=is_last, uid=uid)
            except ProviderConfigError:
                raise RuntimeError("Untrusted session lock directory") from None
        return dir_fd
    except BaseException:
        os.close(dir_fd)
        raise


def _verify_locked_path_identity(
    state_dir: Path, parent_fd: int, sess_fd: int, lock_fd: int, lock_name: str, uid: int,
) -> None:
    """Recheck parent, sessions dir, and lock file inodes against their live paths after flock."""
    live_parent_fd = _open_lock_parent_fd(state_dir)
    try:
        if not os.path.samestat(os.fstat(parent_fd), os.fstat(live_parent_fd)):
            raise RuntimeError("Session lock directory changed during acquisition")
        try:
            live_sess = os.stat("sessions", dir_fd=live_parent_fd, follow_symlinks=False)
        except OSError:
            raise RuntimeError("Session lock directory changed during acquisition") from None
        pinned_sess = os.fstat(sess_fd)
        if (
            not stat.S_ISDIR(live_sess.st_mode)
            or live_sess.st_uid != uid
            or live_sess.st_mode & 0o077
            or not os.path.samestat(pinned_sess, live_sess)
        ):
            raise RuntimeError("Session lock directory changed during acquisition")
        post_fd = os.fstat(lock_fd)
        try:
            post_path = os.stat(lock_name, dir_fd=sess_fd, follow_symlinks=False)
        except OSError:
            raise RuntimeError("Session lock file changed during acquisition") from None
        if not os.path.samestat(post_fd, post_path) or post_fd.st_nlink != 1:
            raise RuntimeError("Session lock file changed during acquisition")
    finally:
        os.close(live_parent_fd)


def _open_instance_lock(state_dir: Path, instance: str):
    """Acquire an exclusive per-instance launch lock under the private OpenAI state dir."""
    if type(instance) is not str or not _INSTANCE_NAME.fullmatch(instance):
        raise RuntimeError("Malformed instance name for session lock")
    uid = os.geteuid()
    parent_fd = _open_lock_parent_fd(state_dir)
    try:
        try:
            os.mkdir("sessions", 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        sess_fd = os.open("sessions", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            sinfo = os.fstat(sess_fd)
            if sinfo.st_uid != uid or sinfo.st_mode & 0o077:
                raise RuntimeError("Untrusted session lock directory")
            lock_name = f"{instance}.lock"
            lock_fd = os.open(
                lock_name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=sess_fd
            )
            try:
                linfo = os.fstat(lock_fd)
                if (
                    not stat.S_ISREG(linfo.st_mode)
                    or linfo.st_uid != uid
                    or linfo.st_mode & 0o077
                    or linfo.st_nlink != 1
                ):
                    raise RuntimeError("Untrusted session lock file")
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                _verify_locked_path_identity(state_dir, parent_fd, sess_fd, lock_fd, lock_name, uid)
            except BaseException:
                os.close(lock_fd)
                raise
            return lock_fd
        finally:
            os.close(sess_fd)
    finally:
        os.close(parent_fd)


def _wait_relay_bound(relay_id: str, port: int = RELAY_PORT_MIN) -> None:
    if type(port) is not int or not RELAY_PORT_MIN <= port <= RELAY_PORT_MAX:
        raise RuntimeError("Invalid relay port")
    probe = (
        f"import socket; s=socket.create_connection(('127.0.0.1', {port}), 1); s.close()"
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        res = podman("exec", relay_id, "python3", "-c", probe, check=False, timeout=3)
        if res.returncode == 0:
            return
        time.sleep(0.1)
    raise RuntimeError(f"Interactive provider relay did not bind 127.0.0.1:{port}")


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


def _validate_spec_options(spec: dict) -> dict:
    provider_filter = spec.get("provider_filter", "")
    cli_ui_mode = spec.get("cli_ui_mode", "default")
    if type(provider_filter) is not str or type(cli_ui_mode) is not str:
        raise ValueError("Invalid launch spec option")
    if provider_filter:
        try:
            parse_provider_filter(provider_filter)
        except LaunchRefusedError:
            raise ValueError("Invalid provider filter in launch spec") from None
    if cli_ui_mode not in _VALID_CLI_UI_MODES:
        raise ValueError("Invalid cli_ui_mode in launch spec")
    normalized = dict(spec)
    normalized["provider_filter"] = provider_filter
    normalized["cli_ui_mode"] = cli_ui_mode
    return normalized


def _validate_spec(spec: dict) -> dict:
    if (
        type(spec) is not dict
        or not _BASE_SPEC_KEYS <= set(spec) <= _SPEC_KEYS
        or not all(type(v) is str for v in spec.values())
    ):
        raise ValueError("Invalid launch spec")
    instance = spec["instance"]
    if (
        not _INSTANCE_NAME.fullmatch(instance)
        or instance in _RESERVED_INSTANCES
        or _RELAY_INSTANCE_RE.fullmatch(instance) is not None
    ):
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
    return _validate_spec_options(spec)


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


def _verify_stopped_container_owner(
    details: dict, cname: str, instance: str, expected_roles: tuple[str | None, ...]
) -> str:
    cid = details.get("Id") or ""
    state = details.get("State") or {}
    labels = (details.get("Config") or {}).get("Labels") or {}
    if type(state) is not dict or type(labels) is not dict:
        raise RuntimeError(f"Malformed inspect metadata for container {cname}")
    if state.get("Running") is True or state.get("Status") in ("running", "paused", "restarting", "stopping"):
        raise RuntimeError(f"Container {cname} is already running")
    role = labels.get("oc.role")
    normalized_role = None if role in (None, "") else role
    if (type(cid) is not str or not IMAGE_ID.fullmatch(cid)
            or labels.get("oc.sandbox") != "1"
            or labels.get("oc.instance") != instance
            or normalized_role not in expected_roles):
        raise RuntimeError(f"Refusing to remove unowned stopped container {cname}")
    return cid


def _ensure_single_container_idle(
    cname: str, instance: str, expected_roles: tuple[str | None, ...]
) -> None:
    details = _inspect_existing_container(cname)
    if details is None:
        return
    cid = _verify_stopped_container_owner(details, cname, instance, expected_roles)
    _remove_stopped_owned_container(cid)


def _ensure_pod_attached_idle(
    pod_containers: list[dict], instance: str, sidecar_names: set[str]
) -> None:
    for entry in pod_containers:
        cid = entry.get("Id")
        cname = entry.get("Name") or cid or "unknown"
        if type(cid) is not str or not IMAGE_ID.fullmatch(cid):
            raise RuntimeError("Malformed container entry in pod inspect")
        details = _inspect_existing_container(cid)
        if details is None or details.get("IsInfra") is True:
            continue
        actual_name = (details.get("Name") or "").lstrip("/")
        if actual_name in sidecar_names:
            continue
        verified_id = _verify_stopped_container_owner(
            details, actual_name or cname, instance, (None, "openai-relay", "provider-relay")
        )
        _remove_stopped_owned_container(verified_id)


def _ensure_containers_idle(
    agent_name: str,
    relay_name: str,
    instance: str,
    *,
    extra_relays: tuple[str, ...] = (),
    pod_containers: list[dict] | None = None,
    sidecar_names: set[str] | None = None,
) -> None:
    if pod_containers:
        _ensure_pod_attached_idle(pod_containers, instance, sidecar_names or set())
    _ensure_single_container_idle(agent_name, instance, (None,))
    _ensure_single_container_idle(relay_name, instance, ("openai-relay",))
    for slot_relay in extra_relays:
        _ensure_single_container_idle(slot_relay, instance, ("provider-relay",))


def _build_relay_args(
    spec: dict,
    job: _SessionJob,
    *,
    slot_index: int | None = None,
    port: int = RELAY_PORT_MIN,
    provider_label: str = "openai",
    relay_name_override: str | None = None,
    defer_bind: bool = False,
) -> list[str]:
    if type(port) is not int or not RELAY_PORT_MIN <= port <= RELAY_PORT_MAX:
        raise ValueError("Invalid relay port")
    if slot_index is None:
        relay_name = relay_name_override or spec["relay"]
        role_labels = ["--label", "oc.role=openai-relay"]
        mcs_args: list[str] = []
        port_args: list[str] = [str(port), "--defer-bind"] if defer_bind else []
    else:
        relay_name = relay_name_override or f"{spec['pod']}-relay-{slot_index}"
        role_labels = [
            "--label", "oc.role=provider-relay",
            "--label", f"oc.provider-slot={slot_index}",
            "--label", f"oc.provider={provider_label}",
        ]
        mcs_args = ["--security-opt", f"label=level:{_random_relay_mcs_level(spec.get('level', ''))}"]
        port_args = [str(port), "--defer-bind"] if defer_bind else [str(port)]
    return [
        "create", "--pull=never", "--name", relay_name, "--pod", spec["pod"],
        "--label", "oc.sandbox=1", "--label", f"oc.instance={spec['instance']}",
        *role_labels,
        "--http-proxy=false", "--image-volume=ignore", "--log-driver=none", "--restart=no",
        "--user=0:0", "--ipc=private", "--pid=private", "--cgroupns=private",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", *mcs_args,
        "--read-only", "--pids-limit=64", "--memory=128m", "--memory-swap=128m",
        "-v", f"{job.source_dir}:/source:ro,Z,nosuid,nodev,noexec",
        "-v", f"{job.provider_socket.parent}:/provider:ro,Z,nosuid,nodev,noexec",
        "-v", f"{job.grant}:/grant:ro,Z,nosuid,nodev,noexec",
        "-v", f"{job.proof_file.parent}:/proof:ro,Z,nosuid,nodev,noexec",
        spec["relay_image"],
        "python3", "-B", "/source/session_relay.py",
        job.incarnation, str(job.generation), str(job.lease.deadline_ns), *port_args,
    ]


def _build_agent_args(
    spec: dict,
    config_source: _SessionJob | Path,
    *,
    ui_mode: str = "full",
    provider_label: str = "managed",
) -> list[str]:
    if ui_mode not in ("full", "mini"):
        raise ValueError("Invalid ui_mode")
    config_path = config_source.opencode_config if isinstance(config_source, _SessionJob) else Path(config_source)
    args = [
        "create", "-it", "--rm", "--pull=never", "--name", spec["agent"], "--pod", spec["pod"],
        "--label", "oc.sandbox=1", "--label", f"oc.instance={spec['instance']}",
        "--label", f"oc.provider={provider_label}",
        "--label", f"oc.ui_mode={ui_mode}",
        "--http-proxy=false", "--image-volume=ignore", "--restart=no",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--security-opt", f"label=level:{spec['level']}",
        "--pids-limit=512", "--memory", spec["agent_mem"],
        "-v", f"{spec['sandbox']}:/sandbox",
        "-v", f"{spec['home_vol']}:/root:Z",
        "-v", f"{config_path}:/etc/opencode/opencode.json:ro,Z,nosuid,nodev,noexec",
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
    if ui_mode == "mini":
        args.append("mini")
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


class _SlotState:
    def __init__(self, slot_cm, handle: SlotHandle, slot_root: Path, *, allow_legacy: bool = False):
        self.slot_cm = slot_cm
        self.handle = handle
        self.slot_root = slot_root
        self.allow_legacy = allow_legacy
        self.relay_id: str | None = None
        self.creating_relay = False
        self.create_unconfirmed = False
        self.retiring = False
        self.retired = False
        self.retire_owner_active = False
        self.retire_timed_out = False
        self.grant_revoked = False
        self.broker_closed = False
        self.revoke_or_close_failed = False
        self.release_gate_opened = False
        self.exited = False
        self.store_released = False
        self.lease_confirmed_released = False


class _SessionSlotCoordinator:
    """Thread-safe coordinator for multi-instance slot startup, single-slot revocation, and teardown."""

    def __init__(self, stop_event: threading.Event):
        self._stop_event = stop_event
        self._lock = threading.Lock()
        self._slots: dict[int, _SlotState] = {}
        self._pre_revoked: set[int] = set()
        self._slot_roots: list[Path] = []
        self._slot_root_ids: dict[Path, tuple[int, int]] = {}
        self._slot_root_fds: dict[Path, tuple[int, int]] = {}
        self._created_containers: list[str] = []
        self._removed_containers: set[str] = set()
        self._retire_threads: list[threading.Thread] = []
        self._retire_thread_slots: dict[threading.Thread, int] = {}
        self._cleanup_error: Exception | None = None

    def _close_slot_root_fd(self, slot_root: Path) -> None:
        fds = self._slot_root_fds.pop(slot_root, None)
        if fds is not None:
            for fd in reversed(fds):
                with suppress(OSError):
                    os.close(fd)

    def release_slot_root_pins(self) -> None:
        with self._lock:
            while self._slot_root_fds:
                _, fds = self._slot_root_fds.popitem()
                for fd in reversed(fds):
                    with suppress(OSError):
                        os.close(fd)

    def __del__(self) -> None:
        self.release_slot_root_pins()

    def _remember_slot_root_locked(self, slot_root: Path) -> None:
        from .shell_cleanup_owner import _open_owned_dir_pin

        if slot_root not in self._slot_roots:
            self._slot_roots.append(slot_root)
        if slot_root not in self._slot_root_ids:
            pinned = _open_owned_dir_pin(str(slot_root))
            if pinned is not None:
                parent_fd, fd, dev, ino = pinned
                self._slot_root_ids[slot_root] = (dev, ino)
                self._slot_root_fds[slot_root] = (parent_fd, fd)

    def slot_allows_legacy(self, slot_index: int) -> bool:
        with self._lock:
            state = self._slots.get(slot_index)
            return bool(state.allow_legacy) if state is not None else False

    def _bind_registered_authority(self, state: _SlotState) -> None:
        if state.handle.bind_release_authority is None:
            return
        try:
            state.handle.bind_release_authority(lambda s=state: self._is_release_authorized(s))
        except Exception:
            with self._lock:
                self._slots.pop(state.handle.slot_index, None)
            raise

    def register_slot(
        self,
        slot_cm,
        handle: SlotHandle,
        slot_root: Path | None = None,
        *,
        allow_legacy: bool | None = None,
    ) -> _SlotState:
        effective_legacy = _is_openai_slot_identity(handle) if allow_legacy is None else bool(allow_legacy)
        _validate_slot_handle(handle, allow_legacy=effective_legacy)
        if slot_root is not None:
            resolved_root = slot_root
        elif _is_legacy_openai_handle(handle, allow_legacy=effective_legacy):
            resolved_root = handle.job.root
        else:
            raise ProviderIntegrityError(
                "incomplete_slot_handle",
                f"Slot handle for '{handle.provider_label}' requires explicit slot_root.",
            )
        state = _SlotState(slot_cm, handle, resolved_root, allow_legacy=effective_legacy)
        try:
            already_revoked = _slot_is_revoked(handle, allow_legacy=effective_legacy)
        except Exception as exc:
            self._record_error(exc)
            already_revoked = True
        with self._lock:
            if handle.slot_index in self._slots:
                raise ProviderIntegrityError(
                    "duplicate_slot_registration",
                    f"Slot index {handle.slot_index} is already registered.",
                )
            self._slots[handle.slot_index] = state
            self._remember_slot_root_locked(resolved_root)
            should_revoke = handle.slot_index in self._pre_revoked or already_revoked
            self._pre_revoked.discard(handle.slot_index)
        self._bind_registered_authority(state)
        if should_revoke:
            self.on_revoke(handle.slot_index)
        return state

    def track_slot_root(self, slot_root: Path) -> None:
        with self._lock:
            self._remember_slot_root_locked(slot_root)

    def remove_slot_roots(self, *, require_confirmed_leases: bool = False) -> None:
        from .shell_cleanup_owner import _remove_pinned_dir

        with self._lock:
            roots = list(self._slot_roots)
            root_ids = dict(self._slot_root_ids)
            confirmed = (
                {
                    s.slot_root
                    for s in self._slots.values()
                    if s.lease_confirmed_released and s.handle.lease_release_confirmed is not None
                }
                if require_confirmed_leases
                else None
            )
        for slot_root in roots:
            if confirmed is not None and slot_root not in confirmed:
                continue
            ident = root_ids.get(slot_root)
            fds = self._slot_root_fds.get(slot_root)
            parent_fd = fds[0] if fds is not None else None
            root_fd = fds[1] if fds is not None else None
            try:
                if ident is not None:
                    _remove_pinned_dir(
                        slot_root,
                        ident[0],
                        ident[1],
                        pinned_fd=root_fd,
                        pinned_parent_fd=parent_fd,
                    )
            finally:
                self._close_slot_root_fd(slot_root)

    def begin_relay_create(self, slot_index: int) -> bool:
        with self._lock:
            state = self._slots.get(slot_index)
            if state is None or state.retiring:
                return False
            state.creating_relay = True
            if state.handle.mark_relay_created is not None:
                state.handle.mark_relay_created()
            return True

    def finish_relay_create(self, slot_index: int, relay_id: str | None) -> bool:
        deny_state: _SlotState | None = None
        result = False
        with self._lock:
            state = self._slots.get(slot_index)
            if state is None:
                return False
            state.creating_relay = False
            if relay_id is not None:
                self._created_containers.append(relay_id)
                state.relay_id = relay_id
                if state.handle.mark_relay_created is not None:
                    state.handle.mark_relay_created()
                result = not state.retiring
            else:
                state.create_unconfirmed = True
                deny_state = state
                if self._cleanup_error is None:
                    self._cleanup_error = RuntimeError(
                        "Podman relay create did not complete with a verified container ID"
                    )
        if deny_state is not None:
            self._deny_slot_release(deny_state)
        return result

    def record_container(self, container_id: str, *, slot_index: int | None = None) -> bool:
        with self._lock:
            self._created_containers.append(container_id)
            if slot_index is not None:
                state = self._slots.get(slot_index)
                if state is not None:
                    state.creating_relay = False
                    state.relay_id = container_id
                    if state.handle.mark_relay_created is not None:
                        state.handle.mark_relay_created()
                    if state.retiring:
                        return False
            return True

    def _record_error_locked(self, exc: Exception) -> None:
        if self._cleanup_error is None:
            self._cleanup_error = exc

    def _record_error(self, exc: Exception) -> None:
        with self._lock:
            self._record_error_locked(exc)

    def _is_release_authorized(self, state: _SlotState) -> bool:
        with self._lock:
            relay_gone = state.relay_id is None or state.relay_id in self._removed_containers
            return (
                state.exited
                and not state.creating_relay
                and not state.create_unconfirmed
                and not state.retire_timed_out
                and state.grant_revoked
                and state.broker_closed
                and not state.revoke_or_close_failed
                and relay_gone
            )

    def _deny_slot_release(self, state: _SlotState) -> None:
        if state.handle.deny_lease_release is not None:
            try:
                state.handle.deny_lease_release()
            except Exception as exc:
                self._record_error(exc)

    def _finalize_slot_hold(self, state: _SlotState) -> None:
        with self._lock:
            if state.retire_timed_out or state.revoke_or_close_failed or not state.store_released:
                return
            if state.lease_confirmed_released:
                return
        finalize = getattr(state.handle, "finalize_lease_release", None)
        if callable(finalize):
            try:
                if finalize() is not True:
                    self._record_error(
                        RuntimeError("Slot durable lease hold could not be cleared after retirement")
                    )
                    return
            except Exception as exc:
                self._deny_slot_release(state)
                self._record_error(exc)
                return
        try:
            confirmed = _slot_lease_release_confirmed(state.handle, allow_legacy=state.allow_legacy)
        except Exception as exc:
            self._record_error(exc)
            return
        if not confirmed:
            self._record_error(
                RuntimeError("Slot lease release was not confirmed in the connection store")
            )
            return
        with self._lock:
            if not state.retire_timed_out:
                state.lease_confirmed_released = True
                state.retired = True

    def _exit_slot_lease(self, state: _SlotState, *, finalize_hold: bool) -> None:
        try:
            state.slot_cm.__exit__(None, None, None)
        except Exception as exc:
            self._deny_slot_release(state)
            self._record_error(exc)
            return
        with self._lock:
            if state.retire_timed_out:
                return
            state.store_released = True
        if finalize_hold or getattr(state.handle, "finalize_lease_release", None) is None:
            self._finalize_slot_hold(state)

    def _claim_retire_ownership(self, state: _SlotState) -> tuple[bool, bool, str | None]:
        """Return (already_done, claimed, fallback_relay_id_to_remove)."""
        timed_out = False
        fallback_rid: str | None = None
        with self._lock:
            if state.exited and state.lease_confirmed_released and not state.retire_timed_out:
                return True, False, None
            if state.retire_owner_active or state.retire_timed_out:
                state.retire_timed_out = True
                timed_out = True
                rid = state.relay_id
                fallback_rid = rid if (rid is not None and rid not in self._removed_containers) else None
            else:
                state.retire_owner_active = True
                return False, True, None
        if timed_out:
            self._deny_slot_release(state)
        return False, False, fallback_rid

    def _run_slot_shutdown_step(self, state: _SlotState, action: Callable[[], None], flag_attr: str) -> None:
        try:
            action()
            with self._lock:
                setattr(state, flag_attr, True)
        except Exception as exc:
            with self._lock:
                state.revoke_or_close_failed = True
            self._deny_slot_release(state)
            self._record_error(exc)

    def _revoke_and_close_slot(self, state: _SlotState) -> None:
        with self._lock:
            need_revoke = not state.grant_revoked
            need_close = not state.broker_closed
        if need_revoke:
            self._run_slot_shutdown_step(
                state, lambda: _slot_revoke_grant(state.handle, allow_legacy=state.allow_legacy), "grant_revoked",
            )
        if need_close:
            self._run_slot_shutdown_step(
                state, lambda: _slot_close_broker(state.handle, allow_legacy=state.allow_legacy), "broker_closed",
            )

    def _remove_slot_relay_if_needed(self, state: _SlotState) -> bool:
        with self._lock:
            relay_id = state.relay_id
            creating = state.creating_relay
            already_removed = relay_id in self._removed_containers if relay_id is not None else True
        if creating and relay_id is None:
            return False
        if relay_id is not None and not already_removed:
            try:
                _remove_container_verified(relay_id)
                with self._lock:
                    self._removed_containers.add(relay_id)
            except Exception as exc:
                self._record_error(exc)
        return True

    def _check_broker_quiescent(self, state: _SlotState) -> bool:
        try:
            has_clients = _slot_has_active_clients(state.handle, allow_legacy=state.allow_legacy)
        except Exception as exc:
            self._deny_slot_release(state)
            self._record_error(exc)
            return False
        if has_clients:
            self._deny_slot_release(state)
            self._record_error(RuntimeError("Slot broker still has active clients during teardown"))
            return False
        return True

    def _can_release_slot_locked(self, state: _SlotState, *, broker_quiescent: bool) -> bool:
        relay_gone = state.relay_id is None or state.relay_id in self._removed_containers
        return (
            not state.creating_relay
            and not state.create_unconfirmed
            and not state.retire_timed_out
            and state.grant_revoked
            and state.broker_closed
            and not state.revoke_or_close_failed
            and broker_quiescent
            and relay_gone
        )

    def _remove_timed_out_fallback_relay(self, fallback_rid: str | None, *, remove_relay_if_timed_out: bool) -> None:
        self._record_error(RuntimeError("Slot retirement worker is still active"))
        if not remove_relay_if_timed_out or fallback_rid is None:
            return
        try:
            _remove_container_verified(fallback_rid)
            with self._lock:
                self._removed_containers.add(fallback_rid)
        except Exception as exc:
            self._record_error(exc)

    def _open_relay_confirm_gate(self, state: _SlotState, *, broker_quiescent: bool) -> bool:
        open_confirm_relay = False
        invariants_ok = True
        with self._lock:
            if not self._can_release_slot_locked(state, broker_quiescent=broker_quiescent):
                self._record_error_locked(RuntimeError("Slot release invariants were not satisfied during teardown"))
                invariants_ok = False
            elif state.relay_id is not None and not state.release_gate_opened:
                state.release_gate_opened = True
                open_confirm_relay = True
        if not invariants_ok:
            self._deny_slot_release(state)
            return False
        if open_confirm_relay and state.handle.confirm_relay_removed is not None:
            try:
                state.handle.confirm_relay_removed()
            except Exception as exc:
                with self._lock:
                    state.revoke_or_close_failed = True
                self._deny_slot_release(state)
                self._record_error(exc)
                return False
        return True

    def _authorize_slot_release(self, state: _SlotState) -> bool:
        if state.handle.authorize_lease_release is not None:
            try:
                state.handle.authorize_lease_release()
            except Exception as exc:
                with self._lock:
                    state.revoke_or_close_failed = True
                self._deny_slot_release(state)
                self._record_error(exc)
                return False
        if not self._is_release_authorized(state):
            self._deny_slot_release(state)
            self._record_error(RuntimeError("Slot release authority lapsed before lease exit"))
            return False
        return True

    def _complete_slot_release(
        self, state: _SlotState, *, broker_quiescent: bool, finalize_hold: bool,
    ) -> None:
        if not self._open_relay_confirm_gate(state, broker_quiescent=broker_quiescent):
            return
        should_exit = False
        invariants_ok = True
        with self._lock:
            if not self._can_release_slot_locked(state, broker_quiescent=broker_quiescent):
                self._record_error_locked(RuntimeError("Slot release invariants changed before lease exit"))
                invariants_ok = False
            elif not state.exited:
                state.exited = True
                should_exit = True
        if not invariants_ok:
            self._deny_slot_release(state)
            return
        if should_exit and self._authorize_slot_release(state):
            self._exit_slot_lease(state, finalize_hold=finalize_hold)
        with self._lock:
            if state.lease_confirmed_released and not state.retire_timed_out:
                state.retired = True

    def _try_release_slot_lease(
        self,
        state: _SlotState,
        *,
        remove_relay_if_timed_out: bool = False,
        finalize_hold: bool = True,
    ) -> None:
        done, claimed, fallback_rid = self._claim_retire_ownership(state)
        if done:
            return
        if not claimed:
            self._remove_timed_out_fallback_relay(
                fallback_rid, remove_relay_if_timed_out=remove_relay_if_timed_out,
            )
            return
        try:
            self._revoke_and_close_slot(state)
            if not self._remove_slot_relay_if_needed(state):
                return
            broker_quiescent = self._check_broker_quiescent(state)
            self._complete_slot_release(state, broker_quiescent=broker_quiescent, finalize_hold=finalize_hold)
        finally:
            with self._lock:
                state.retire_owner_active = False

    def _finish_slot_retirement(self, state: _SlotState, *, finalize_hold: bool = True) -> None:
        self._try_release_slot_lease(state, finalize_hold=finalize_hold)

    def _start_slot_retirement(self, slot_index: int, *, stop_if_last: bool) -> None:
        with self._lock:
            state = self._slots.get(slot_index)
            if state is None:
                self._pre_revoked.add(slot_index)
                return
            if state.retiring:
                return
            state.retiring = True
            active_remaining = sum(1 for item in self._slots.values() if not item.retiring)
            worker = threading.Thread(
                target=self._finish_slot_retirement,
                args=(state,),
                kwargs={"finalize_hold": False},
                name=f"oc-slot-retire-{slot_index}",
                daemon=False,
            )
            self._retire_threads.append(worker)
            self._retire_thread_slots[worker] = slot_index
            try:
                worker.start()
            except RuntimeError as exc:
                self._retire_threads.remove(worker)
                self._retire_thread_slots.pop(worker, None)
                state.retiring = False
                if self._cleanup_error is None:
                    self._cleanup_error = exc
                self._stop_event.set()
                return
        if stop_if_last and active_remaining == 0:
            self._stop_event.set()

    def on_revoke(self, slot_index: int) -> None:
        """Retire only the revoked slot; stop the whole session iff zero active slots remain."""
        self._start_slot_retirement(slot_index, stop_if_last=True)

    def retire_slot_for_cutover(self, slot_index: int) -> None:
        """Retire the discovery slot cleanly during two-phase cutover without stopping the session."""
        self._start_slot_retirement(slot_index, stop_if_last=False)

    def any_active(self) -> bool:
        with self._lock:
            candidates = [state for state in self._slots.values() if not state.retiring]
        for state in candidates:
            try:
                if (
                    _slot_is_revoked(state.handle, allow_legacy=state.allow_legacy) is False
                    and _slot_route_state(state.handle, allow_legacy=state.allow_legacy) == "active"
                ):
                    return True
            except Exception:
                continue
        return False

    def _remove_leftover_container(self, cid: str, slot: _SlotState | None) -> None:
        if slot is not None:
            self._try_release_slot_lease(slot, remove_relay_if_timed_out=True)
            return
        try:
            _remove_container_verified(cid)
            with self._lock:
                self._removed_containers.add(cid)
        except Exception as exc:
            self._record_error(exc)

    def _exit_uncreated_slots(self) -> None:
        with self._lock:
            pending = [
                s for s in self._slots.values()
                if not s.exited or not s.lease_confirmed_released
            ]
        for slot in pending:
            self._try_release_slot_lease(slot, remove_relay_if_timed_out=True)
        with self._lock:
            still_unconfirmed = any(
                s.creating_relay
                or s.create_unconfirmed
                or s.retire_timed_out
                or not s.exited
                or not s.lease_confirmed_released
                for s in self._slots.values()
            )
        if still_unconfirmed:
            self._record_error(RuntimeError("Slot relay state remained unconfirmed during teardown"))

    def _handle_retire_thread_result(self, thread: threading.Thread, *, timed_out: bool) -> None:
        state: _SlotState | None = None
        with self._lock:
            slot_idx = self._retire_thread_slots.get(thread)
            if slot_idx is not None and slot_idx in self._slots:
                state = self._slots[slot_idx]
                if timed_out:
                    state.retire_timed_out = True
        if timed_out:
            if state is not None:
                self._deny_slot_release(state)
            self._record_error(
                RuntimeError(
                    f"Slot retirement thread '{thread.name}' did not finish; "
                    "durable lease publication state is uncertain"
                )
            )
            return
        if state is not None:
            self._finalize_slot_hold(state)

    def _join_retire_threads(self, threads: list[threading.Thread]) -> None:
        for thread in threads:
            thread.join(timeout=15)
            self._handle_retire_thread_result(thread, timed_out=thread.is_alive())

    def teardown_all(self, agent_id: str | None) -> Exception | None:
        if agent_id is not None:
            try:
                _remove_container_verified(agent_id)
                with self._lock:
                    self._removed_containers.add(agent_id)
            except Exception as exc:
                self._record_error(exc)

        with self._lock:
            threads = list(self._retire_threads)
            remaining_slots = [state for state in self._slots.values() if not state.retiring]
            for state in remaining_slots:
                state.retiring = True

        self._join_retire_threads(threads)

        for state in remaining_slots:
            self._finish_slot_retirement(state)

        with self._lock:
            leftover = [cid for cid in self._created_containers if cid not in self._removed_containers]
            slots_by_relay = {state.relay_id: state for state in self._slots.values() if state.relay_id is not None}
        for cid in reversed(leftover):
            self._remove_leftover_container(cid, slots_by_relay.get(cid))

        self._exit_uncreated_slots()
        with self._lock:
            return self._cleanup_error


def _write_session_opencode_config(root: Path, config_payload: dict) -> Path:
    root.chmod(0o700)
    cfg_dir = root / "opencode"
    cfg_dir.mkdir(mode=0o700, exist_ok=True)
    cfg_path = cfg_dir / "opencode.json"
    cfg_bytes = (json.dumps(config_payload, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    atomic_write(cfg_path, cfg_bytes)
    cfg_path.chmod(0o444)
    return cfg_path


def _start_slot_relay_deferred(
    spec: dict,
    pod_id: str,
    handle: SlotHandle,
    coordinator: _SessionSlotCoordinator,
    siblings: list[str],
    started_relay_ids: list[str],
    stop_event: threading.Event,
) -> str:
    """Create, pre-verify, start, and post-verify a deferred-bind relay before activation or TCP bind."""
    effective_legacy = coordinator.slot_allows_legacy(handle.slot_index)
    _validate_slot_handle(handle, allow_legacy=effective_legacy)
    if not coordinator.begin_relay_create(handle.slot_index):
        raise ConnectionError("connection_retired")
    try:
        res = podman(*handle.build_relay_args(spec), check=False)
    except BaseException:
        # Host create outcome is unknown (timeout / lost ack / interrupt): retain lease and grant dir.
        coordinator.finish_relay_create(handle.slot_index, None)
        raise
    if res.returncode != 0:
        # Return code comes from the host-spawn wrapper and does not prove the host-side
        # podman create finished; retain durable lease and grant dir without trusting name absence.
        coordinator.finish_relay_create(handle.slot_index, None)
        raise JobRuntimeError(f"Podman create failed ({res.returncode})")
    relay_id = res.stdout.decode("ascii").strip()
    if not IMAGE_ID.fullmatch(relay_id):
        coordinator.finish_relay_create(handle.slot_index, None)
        raise RuntimeError("Podman did not return a complete relay container ID")
    if not coordinator.finish_relay_create(handle.slot_index, relay_id):
        raise ConnectionError("connection_retired")
    relay_paths = _slot_relay_paths(handle, allow_legacy=effective_legacy)
    other_containers = [*siblings, *started_relay_ids]
    _verify_relay_prestart(
        relay_id,
        spec["relay_image"],
        pod_id,
        spec["level"],
        relay_paths,
        other_containers,
    )
    podman("start", relay_id)
    _verify_relay_isolation(
        relay_id,
        spec["relay_image"],
        pod_id,
        spec["level"],
        relay_paths,
        other_containers,
    )
    if (
        stop_event.is_set()
        or _slot_is_revoked(handle, allow_legacy=effective_legacy)
        or _slot_route_state(handle, allow_legacy=effective_legacy) != "pending"
    ):
        raise ConnectionError("connection_retired")
    return relay_id


def _start_and_verify_slot_relay(
    spec: dict,
    pod_id: str,
    handle: SlotHandle,
    coordinator: _SessionSlotCoordinator,
    siblings: list[str],
    started_relay_ids: list[str],
    stop_event: threading.Event,
) -> str:
    effective_legacy = coordinator.slot_allows_legacy(handle.slot_index)
    relay_id = _start_slot_relay_deferred(
        spec, pod_id, handle, coordinator, siblings, started_relay_ids, stop_event,
    )
    _wait_relay_bound(relay_id, port=handle.port)
    if (
        stop_event.is_set()
        or _slot_is_revoked(handle, allow_legacy=effective_legacy)
        or _slot_route_state(handle, allow_legacy=effective_legacy) != "pending"
    ):
        raise ConnectionError("connection_retired")
    _slot_activate_route(handle, allow_legacy=effective_legacy)
    return relay_id


def _notify_slot_prepare(proof_options, slot_key: str, *, container_name: str, slot_root: str = "") -> None:
    if proof_options is not None and proof_options.on_slot_prepare is not None:
        proof_options.on_slot_prepare(slot_key, container_name=container_name, slot_root=slot_root)


def _notify_slot_begin(proof_options, slot_key: str, *, container_name: str, grant_dir: str = "", slot_root: str = "") -> None:
    if proof_options is not None and proof_options.on_slot_begin is not None:
        proof_options.on_slot_begin(
            slot_key,
            container_name=container_name,
            grant_dir=grant_dir,
            slot_root=slot_root,
        )


def _notify_slot_finish(proof_options, slot_key: str, cid: str) -> None:
    if proof_options is not None and proof_options.on_slot_finish is not None:
        proof_options.on_slot_finish(slot_key, cid)


def _notify_slot_lease_released(proof_options, slot_key: str) -> None:
    if proof_options is not None and proof_options.on_slot_lease_released is not None:
        proof_options.on_slot_lease_released(slot_key)


class _ProofTurnCutover:
    """Manage two-phase discovery-to-turn relay cutover for the single approved proof slot."""

    def __init__(self, *, spec: dict, pod_id: str, coordinator: _SessionSlotCoordinator,
                 sidecars: list[str], started_relay_ids: list[str], stop_event: threading.Event,
                 proof_options: ProofSessionOptions):
        self._spec = spec
        self._pod_id = pod_id
        self._coordinator = coordinator
        self._sidecars = sidecars
        self._started_relay_ids = started_relay_ids
        self._stop_event = stop_event
        self._proof_options = proof_options
        self._approved_info: dict[str, object] | None = None
        self.tracked_slot_keys: list[str] = []
        self.tracked_slot_indices: dict[str, int] = {}

    def record_discovery_slot(self, *, slot_index: int, item, adapter, port: int,
                              worker_token: str, ack_digest: str | None) -> None:
        self._approved_info = {
            "slot_index": slot_index,
            "item": item,
            "adapter": adapter,
            "port": port,
            "worker_token": worker_token,
            "ack_digest": ack_digest,
        }

    def arm_turn_route(self, observed_row: str, observed_screen_digest: str) -> str:
        if self._approved_info is None or self._stop_event.is_set():
            raise ProofGateError(_ERR_PROOF_NOT_ARMED)
        gate = self._proof_options.proof_gate
        gate.verify_ready_for_arm()
        idx = int(self._approved_info["slot_index"])
        # Step A: completely retire discovery listener, join every discovery thread, verify relay & lease gone.
        self._coordinator.retire_slot_for_cutover(idx)
        with self._coordinator._lock:
            retire_entries = list(self._coordinator._retire_threads)
        self._coordinator._join_retire_threads(retire_entries)
        with self._coordinator._lock:
            disc_state = self._coordinator._slots.get(idx)
            still_running = any(t.is_alive() for t in self._coordinator._retire_threads)
            if (
                disc_state is None
                or not disc_state.retired
                or not disc_state.lease_confirmed_released
                or disc_state.handle.lease_release_confirmed is None
                or still_running
                or self._coordinator._cleanup_error is not None
            ):
                raise ProofGateError(_ERR_PROOF_NOT_ARMED)
        try:
            active_disc_clients = _slot_has_active_clients(disc_state.handle, allow_legacy=disc_state.allow_legacy)
        except Exception:
            raise ProofGateError(_ERR_PROOF_NOT_ARMED) from None
        if active_disc_clients:
            raise ProofGateError(_ERR_PROOF_NOT_ARMED)
        with self._coordinator._lock:
            if disc_state.relay_id in self._started_relay_ids:
                self._started_relay_ids.remove(disc_state.relay_id)
        disc_key = f"disc-{idx}"
        _notify_slot_lease_released(self._proof_options, disc_key)

        # Step B: prepare slot & arm BEFORE starting any worker-reachable replacement turn relay.
        turn_slot_index = len(self._coordinator._slots) + 100
        turn_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir=SHARED_TMP))
        self._coordinator.track_slot_root(turn_root)
        slot_key = f"turn-{idx}"
        turn_cname = f"{self._spec['pod']}-relay-{turn_slot_index}"
        self.tracked_slot_keys.append(slot_key)
        self.tracked_slot_indices[slot_key] = turn_slot_index
        _notify_slot_prepare(self._proof_options, slot_key, container_name=turn_cname, slot_root=str(turn_root))
        adapter = self._approved_info["adapter"]
        item = self._approved_info["item"]
        port = int(self._approved_info["port"])
        worker_token = str(self._approved_info["worker_token"])
        ack_digest = self._approved_info["ack_digest"]
        allow_legacy = _adapter_allows_legacy(adapter, item.spec.kind)
        slot_cm = adapter.open_slot(
            item,
            slot_index=turn_slot_index,
            slot_root=turn_root,
            port=port,
            worker_token=worker_token,
            acknowledged_exposure_digest=ack_digest,
            on_revoke=self._coordinator.on_revoke,
        )
        handle = slot_cm.__enter__()
        try:
            _validate_slot_handle(handle, allow_legacy=allow_legacy)
            _verify_slot_handle_identity(
                handle,
                expected_slot_index=turn_slot_index,
                expected_scoped_id=item.spec.scoped_id,
                expected_provider_label=item.spec.qualified_name,
                expected_port=port,
                expected_slot_root=turn_root,
                allow_legacy=allow_legacy,
            )
            self._coordinator.register_slot(slot_cm, handle, turn_root, allow_legacy=allow_legacy)
        except BaseException:
            slot_cm.__exit__(None, None, None)
            raise
        # Arm BEFORE creating or starting the deferred-bind replacement turn relay.
        arm_nonce = gate.arm(observed_row=observed_row, observed_screen_digest=observed_screen_digest)
        _notify_slot_begin(
            self._proof_options,
            slot_key,
            container_name=turn_cname,
            grant_dir=str(_slot_relay_paths(handle, allow_legacy=allow_legacy).grant_dir),
            slot_root=str(turn_root),
        )
        # B4: relay runs with --defer-bind (127.0.0.1:<port> stays unbound throughout isolation verification).
        turn_relay_id = _start_slot_relay_deferred(
            self._spec, self._pod_id, handle, self._coordinator,
            self._sidecars, self._started_relay_ids, self._stop_event,
        )
        _notify_slot_finish(self._proof_options, slot_key, turn_relay_id)
        self._started_relay_ids.append(turn_relay_id)
        # B5: mark verified -> activate (enables bind) -> wait bound.
        gate.mark_relay_verified(turn_relay_id)
        _slot_activate_route(handle, allow_legacy=allow_legacy)
        _wait_relay_bound(turn_relay_id, port=handle.port)
        return arm_nonce


def _open_single_admitted_slot(
    idx: int,
    item,
    session_ctx: dict[str, object],
) -> None:
    spec = session_ctx["spec"]
    pod_id = session_ctx["pod_id"]
    adapters = session_ctx["adapters"]
    coordinator = session_ctx["coordinator"]
    sidecars = session_ctx["sidecars"]
    started_relay_ids = session_ctx["started_relay_ids"]
    stop_event = session_ctx["stop_event"]
    proof_options = session_ctx["proof_options"]
    cutover = session_ctx["cutover"]
    approved_scoped = session_ctx["approved_scoped"]
    port = session_ctx["slot_ports"][item.spec.scoped_id]
    worker_token = session_ctx["slot_tokens"][item.spec.scoped_id]

    adapter = adapters[item.spec.kind]
    allow_legacy = _adapter_allows_legacy(adapter, item.spec.kind)
    ack_digest = (
        session_ctx["plan"].acknowledged_digests.get(item.exposure_hold.scope_id)
        if item.exposure_hold is not None
        else None
    )
    slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir=SHARED_TMP))
    coordinator.track_slot_root(slot_root)
    is_approved_disc = approved_scoped is not None and item.spec.scoped_id == approved_scoped
    slot_key = f"disc-{idx}" if is_approved_disc else f"slot-{idx}"
    cname = f"{spec['pod']}-relay-disc-{idx}" if is_approved_disc else f"{spec['pod']}-relay-{idx}"
    if cutover is not None:
        cutover.tracked_slot_keys.append(slot_key)
        cutover.tracked_slot_indices[slot_key] = idx
    _notify_slot_prepare(proof_options, slot_key, container_name=cname, slot_root=str(slot_root))
    open_fn = adapter.open_discovery_slot if is_approved_disc else adapter.open_slot
    slot_cm = open_fn(
        item,
        slot_index=idx,
        slot_root=slot_root,
        port=port,
        worker_token=worker_token,
        acknowledged_exposure_digest=ack_digest,
        on_revoke=coordinator.on_revoke,
    )
    handle = slot_cm.__enter__()
    try:
        _validate_slot_handle(handle, allow_legacy=allow_legacy)
        _verify_slot_handle_identity(
            handle,
            expected_slot_index=idx,
            expected_scoped_id=item.spec.scoped_id,
            expected_provider_label=item.spec.qualified_name,
            expected_port=port,
            expected_slot_root=slot_root,
            allow_legacy=allow_legacy,
        )
        coordinator.register_slot(slot_cm, handle, slot_root, allow_legacy=allow_legacy)
    except BaseException:
        slot_cm.__exit__(None, None, None)
        raise
    grant_dir = ""
    if handle.relay_paths is not None:
        grant_dir = str(handle.relay_paths.grant_dir)
    elif _is_legacy_openai_handle(handle, allow_legacy=allow_legacy):
        grant_dir = str(getattr(handle.job, "grant", ""))
    _notify_slot_begin(
        proof_options, slot_key, container_name=cname,
        grant_dir=grant_dir, slot_root=str(slot_root),
    )
    relay_id = _start_and_verify_slot_relay(
        spec, pod_id, handle, coordinator, sidecars, started_relay_ids, stop_event,
    )
    _notify_slot_finish(proof_options, slot_key, relay_id)
    started_relay_ids.append(relay_id)
    if is_approved_disc and cutover is not None:
        cutover.record_discovery_slot(
            slot_index=idx, item=item, adapter=adapter,
            port=port, worker_token=worker_token, ack_digest=ack_digest,
        )


def _start_session_agent(
    spec: dict,
    plan,
    config_path: Path,
    coordinator: _SessionSlotCoordinator,
    proof_options,
) -> str:
    provider_label = (
        plan.admitted[0].spec.kind
        if len({item.spec.kind for item in plan.admitted}) == 1
        else "multi"
    )
    _notify_slot_begin(proof_options, "agent", container_name=spec["agent"])
    agent_id = podman(
        *_build_agent_args(spec, config_path, ui_mode=plan.ui_mode, provider_label=provider_label)
    ).stdout.decode("ascii").strip()
    if not IMAGE_ID.fullmatch(agent_id):
        raise RuntimeError("Podman did not return a complete agent container ID")
    coordinator.record_container(agent_id)
    _notify_slot_finish(proof_options, "agent", agent_id)
    return agent_id


def _all_proof_slots_lease_confirmed(
    coordinator: _SessionSlotCoordinator,
    cutover: _ProofTurnCutover,
) -> bool:
    with coordinator._lock:
        for slot_key in cutover.tracked_slot_keys:
            slot_idx = cutover.tracked_slot_indices.get(slot_key)
            state = coordinator._slots.get(slot_idx) if slot_idx is not None else None
            if (
                state is None
                or not state.lease_confirmed_released
                or state.handle.lease_release_confirmed is None
            ):
                return False
    return True


def _finalize_session_teardown(
    coordinator: _SessionSlotCoordinator,
    agent_id: str | None,
    cutover: _ProofTurnCutover | None,
    proof_options,
    cleanup_state: dict,
    root: Path,
    terminal: StreamTerminal,
) -> bool:
    cleanup_error = coordinator.teardown_all(agent_id)
    if cleanup_error is not None:
        if hasattr(coordinator, "release_slot_root_pins"):
            coordinator.release_slot_root_pins()
        terminal.error(f"Provider session cleanup needs verification. Retained directory {root}")
        return False
    if proof_options is not None and cutover is not None:
        if not _all_proof_slots_lease_confirmed(coordinator, cutover):
            if hasattr(coordinator, "release_slot_root_pins"):
                coordinator.release_slot_root_pins()
            terminal.error(f"Provider session cleanup needs verification. Retained directory {root}")
            return False
        for key in (*cutover.tracked_slot_keys, "agent"):
            _notify_slot_lease_released(proof_options, key)
    if proof_options is None or proof_options.on_slot_lease_released is None:
        coordinator.remove_slot_roots(require_confirmed_leases=(proof_options is not None))
    elif hasattr(coordinator, "release_slot_root_pins"):
        coordinator.release_slot_root_pins()
    cleanup_state["clean"] = True
    return True


def _run_multi_slot_session(
    spec: dict,
    plan,
    adapters: dict,
    root: Path,
    stop_event: threading.Event,
    terminal: StreamTerminal,
    cleanup_state: dict,
) -> int:
    coordinator = _SessionSlotCoordinator(stop_event)
    proof_options = cleanup_state.get("proof_options")
    cutover: _ProofTurnCutover | None = None
    agent_id: str | None = None
    rc = 1
    try:
        pod_id, pod_containers = _verify_pod_with_containers(spec)
        slot_ports = {item.spec.scoped_id: RELAY_PORT_MIN + idx for idx, item in enumerate(plan.admitted)}
        slot_tokens = {item.spec.scoped_id: secrets.token_urlsafe(32) for item in plan.admitted}
        slot_names = [f"{spec['pod']}-relay-{idx}" for idx in range(len(plan.admitted))]

        config_payload = build_multi_provider_opencode_config(
            plan=plan, adapters=adapters, slot_ports=slot_ports, slot_tokens=slot_tokens,
        )
        if proof_options is not None:
            config_payload = proof_options.proof_gate.harden_opencode_config(config_payload)
            approval = proof_options.proof_gate.approval
            validate_opencode_config(
                config_payload,
                plan=plan,
                slot_ports=slot_ports,
                slot_tokens=slot_tokens,
                proof_hardened=True,
                expected_model=f"{approval.scoped_provider_id}/{approval.approved_model}",
            )
        config_path = _write_session_opencode_config(root, config_payload)

        sidecars = [name for name in (spec["chromium"], spec["postgres"], spec["dind"]) if name]
        _ensure_containers_idle(
            spec["agent"], spec["relay"], spec["instance"],
            extra_relays=tuple(slot_names), pod_containers=pod_containers, sidecar_names=set(sidecars),
        )

        started_relay_ids: list[str] = []
        if proof_options is not None:
            cutover = _ProofTurnCutover(
                spec=spec, pod_id=pod_id, coordinator=coordinator,
                sidecars=sidecars, started_relay_ids=started_relay_ids,
                stop_event=stop_event, proof_options=proof_options,
            )
        approved_scoped = (
            proof_options.proof_gate.approval.scoped_provider_id
            if proof_options is not None
            else None
        )
        session_ctx = {
            "spec": spec, "pod_id": pod_id, "plan": plan, "adapters": adapters,
            "coordinator": coordinator, "sidecars": sidecars,
            "started_relay_ids": started_relay_ids, "stop_event": stop_event,
            "proof_options": proof_options, "cutover": cutover,
            "approved_scoped": approved_scoped, "slot_ports": slot_ports,
            "slot_tokens": slot_tokens,
        }
        for idx, item in enumerate(plan.admitted):
            _open_single_admitted_slot(idx, item, session_ctx)

        if stop_event.is_set() or not coordinator.any_active():
            raise ConnectionError("connection_retired")
        agent_id = _start_session_agent(spec, plan, config_path, coordinator, proof_options)

        if stop_event.is_set() or not coordinator.any_active():
            raise ConnectionError("connection_retired")
        if proof_options is not None and proof_options.agent_runner is not None:
            rc = proof_options.agent_runner(agent_id, stop_event, cutover.arm_turn_route)
        else:
            rc = _launch_agent_tty(agent_id, stop_event)
    finally:
        if not _finalize_session_teardown(
            coordinator, agent_id, cutover, proof_options, cleanup_state, root, terminal,
        ):
            rc = 1
    return rc


def _report_session_error(terminal: StreamTerminal, error: BaseException) -> int:
    if isinstance(error, (LaunchRefusedError, ProviderIntegrityError)):
        terminal.error(str(error))
        return 1
    return report_failure(terminal, error, operation="Provider session")


def _validate_plan_entries_against_config(plan, config, err_plan_mismatch: str, err_config_mismatch: str) -> dict:
    enabled_by_scoped = {item.scoped_id: item for item in config.instances if item.enabled}
    seen_ids: set[str] = set()
    for item in plan.admitted:
        sid = item.spec.scoped_id
        if sid in seen_ids:
            raise LaunchRefusedError(err_plan_mismatch, "Preconfirmed plan contains duplicate admitted provider slots.")
        seen_ids.add(sid)
        cfg_item = enabled_by_scoped.get(sid)
        if cfg_item is None or cfg_item.kind != item.spec.kind or cfg_item.label != item.spec.label or cfg_item.auth_mode != item.spec.auth_mode:
            raise LaunchRefusedError(err_config_mismatch, "Preconfirmed plan slot is no longer enabled in current providers.toml.")
    return enabled_by_scoped


def _validate_plan_adapters_qualified(plan, active_adapters: dict | None) -> None:
    if active_adapters is None:
        return
    for item in plan.admitted:
        adapter = active_adapters.get(item.spec.kind)
        is_qual = getattr(adapter, "is_qualified", None)
        if not callable(is_qual) or is_qual(item.spec.auth_mode, "sandbox") is not True:
            raise LaunchRefusedError(
                "provider_unqualified",
                f"Provider '{item.spec.qualified_name}' is not qualified for sandbox execution.",
            )


def _validate_preconfirmed_plan(
    plan,
    proof_gate,
    config,
    live_config_digest: str | None,
    *,
    active_adapters: dict | None = None,
) -> None:
    err_plan_mismatch = "proof_plan_mismatch"
    err_config_mismatch = "proof_config_mismatch"
    approval = proof_gate.approval
    if plan.ui_mode != approval.ui_mode:
        raise LaunchRefusedError(err_plan_mismatch, "Preconfirmed plan ui_mode does not match proof approval.")
    if plan.initial_provider_id != approval.scoped_provider_id or plan.initial_model != approval.approved_model:
        raise LaunchRefusedError(err_plan_mismatch, "Preconfirmed plan initial route does not match proof approval.")
    admitted = [
        item for item in plan.admitted
        if item.spec.scoped_id == approval.scoped_provider_id
        and approval.approved_model in item.models
    ]
    if len(admitted) != 1:
        raise LaunchRefusedError(err_plan_mismatch, "Approved proof route is not uniquely admitted in preconfirmed plan.")
    if config is None:
        raise LaunchRefusedError(err_config_mismatch, "Current provider configuration does not admit the approved proof route.")
    enabled_by_scoped = _validate_plan_entries_against_config(plan, config, err_plan_mismatch, err_config_mismatch)
    _validate_plan_adapters_qualified(plan, active_adapters)
    approved_cfg = enabled_by_scoped.get(approval.scoped_provider_id)
    if approved_cfg is None or approved_cfg.auth_mode != approval.auth_mode:
        raise LaunchRefusedError(err_config_mismatch, "Approved proof route is no longer enabled in current providers.toml.")
    if (
        not approval.providers_config_digest
        or live_config_digest is None
        or not hmac.compare_digest(live_config_digest, approval.providers_config_digest)
    ):
        raise LaunchRefusedError("proof_config_digest_drift", "Current providers.toml digest drifted from approved proof configuration.")


def _resolve_session_plan(
    spec: dict,
    config,
    active_adapters: dict,
    terminal: StreamTerminal,
    proof_options: ProofSessionOptions | None,
    *,
    live_config_digest: str | None = None,
):
    if proof_options is not None and proof_options.preconfirmed_plan is not None:
        if proof_options.proof_gate is None:
            raise LaunchRefusedError("proof_gate_required", "Preconfirmed launch plan requires an active proof gate.")
        _validate_preconfirmed_plan(
            proof_options.preconfirmed_plan,
            proof_options.proof_gate,
            config,
            live_config_digest,
            active_adapters=active_adapters,
        )
        return proof_options.preconfirmed_plan
    return plan_interactive_launch(
        instance_name=spec["instance"],
        cwd=spec["cwd"],
        provider_filter=spec["provider_filter"],
        cli_ui_mode=spec["cli_ui_mode"],
        config=config,
        adapters=active_adapters,
        terminal=terminal,
    )


def _load_session_config(config_dir: Path | None, proof_options: ProofSessionOptions | None):
    if proof_options is not None and proof_options.preconfirmed_plan is not None:
        from oc_providers.config import load_provider_config_with_digest
        return load_provider_config_with_digest(config_dir=config_dir)
    return load_provider_config(config_dir=config_dir), None


def _resolve_adapters_and_lock_dir(
    adapters: dict | None,
    lock_dir: Path | None,
    proof_options: ProofSessionOptions | None,
) -> tuple[dict, Path]:
    proof_gate = proof_options.proof_gate if proof_options is not None else None
    if adapters is None:
        backend = make_backend()
        return (
            default_session_adapters(backend_factory=lambda: backend, proof_gate=proof_gate),
            lock_dir or backend._state,
        )
    return adapters, (lock_dir if lock_dir is not None else make_backend()._state)


def run_interactive_session(
    spec: dict,
    terminal: StreamTerminal,
    *,
    config_dir: Path | None = None,
    adapters: dict | None = None,
    lock_dir: Path | None = None,
    proof_options: ProofSessionOptions | None = None,
) -> int:
    """Supervise one interactive multi-provider oc-sandbox OpenCode session."""
    spec = _validate_spec(spec)
    if not terminal.attended():
        terminal.error("An attended foreground workstation terminal is required for managed provider sessions.")
        return 2
    try:
        check_devbox()
        check_host()
    except Exception:
        terminal.error("Interactive managed provider sessions require the qualified devbox host with SELinux enforcing.")
        return 1

    try:
        config, live_config_digest = _load_session_config(config_dir, proof_options)
        active_adapters, resolved_lock_dir = _resolve_adapters_and_lock_dir(adapters, lock_dir, proof_options)
        plan = _resolve_session_plan(
            spec,
            config,
            active_adapters,
            terminal,
            proof_options,
            live_config_digest=live_config_digest,
        )
    except Exception as error:
        return _report_session_error(terminal, error)

    try:
        instance_lock_fd = _open_instance_lock(resolved_lock_dir, spec["instance"])
    except BlockingIOError:
        terminal.error(f"Instance '{spec['instance']}' already has an active provider session launch.")
        return 1
    except (OSError, RuntimeError) as error:
        terminal.error(f"Could not acquire instance session lock: {error}")
        return 1

    root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir=SHARED_TMP))
    owner_removes_session_root = proof_options is not None and proof_options.on_session_root_created is not None
    stop_event = threading.Event()
    prev_term = signal.signal(signal.SIGTERM, lambda _s, _f: stop_event.set())
    prev_hup = signal.signal(signal.SIGHUP, lambda _s, _f: stop_event.set())
    rc = 1
    cleanup_state = {"clean": False, "proof_options": proof_options}
    try:
        if owner_removes_session_root:
            proof_options.on_session_root_created(str(root))
        rc = _run_multi_slot_session(
            spec, plan, active_adapters, root, stop_event, terminal, cleanup_state,
        )
    except KeyboardInterrupt:
        rc = 130
    except Exception as error:
        return _report_session_error(terminal, error)
    finally:
        signal.signal(signal.SIGTERM, prev_term)
        signal.signal(signal.SIGHUP, prev_hup)
        with suppress(OSError):
            os.close(instance_lock_fd)
        if cleanup_state["clean"] and not owner_removes_session_root:
            with suppress(OSError):
                shutil.rmtree(root)
    return rc
