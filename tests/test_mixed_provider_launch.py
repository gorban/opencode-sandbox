"""Mixed-provider launcher integration, opaque SlotHandle lifecycle, and synthetic Mini proof tests.

Covers three tiers:
1. Public `oc-sandbox` CLI config-driven managed mode & fd 3 handoff (stubbed Podman + fd 3 capture).
2. Offline contract, FD-pinned instance lock, 10-hook opaque SlotHandle lifecycle & teardown
   retention (including timed-out paused-revoke concurrency), post-hardening config validation,
   and Slice C R4 owner-challenged generation-stamped arrival-snapshot receipt gate tests.
3. Opt-in real-Podman `--network=none` managed-supervisor synthetic Mini proof
   (enabled with `OC_RUN_SYNTHETIC_MINI_PROOF=1` inside `devbox` with pinned `oc-agent` and
   `oc-openai-relay` images; zero live network, zero workstation credentials).
"""

import codecs
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from hashlib import sha256
import fcntl
import hmac
import io
import json
import os
from pathlib import Path
import pty
import secrets
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unittest
from unittest.mock import patch

from oc_openai import session_broker
from oc_openai.cli import StreamTerminal
from oc_openai.connection import ConnectionError
from oc_openai.managed import relay as relay_mod
from oc_openai.managed.runtime import HOST_SPAWN, SHARED_TMP, check_devbox, check_host, podman
from oc_openai.proof_gate import EXPECTED_REPLY, PROOF_PROMPT, ProofApproval, ProofGate, ProofGateError
from oc_openai.session_broker import (
    MAX_REQUEST_FRAME,
    REQUEST_LENGTH,
    ProofSessionOptions,
    _SessionJob,
    _SessionSlotCoordinator,
    _build_relay_args,
    _normalize_lock_root,
    _open_instance_lock,
    _read_exact,
    _validate_preconfirmed_plan,
    _validate_slot_handle,
    run_interactive_session,
)
from oc_openai.session_protocol import (
    RequestRefused,
    encode_chunk,
    format_error_response,
    format_models_response,
    parse_worker_request,
    sse_response_headers,
)
from oc_providers.catalog import (
    LaunchRefusedError,
    ResolvedLaunchPlan,
    build_multi_provider_opencode_config,
    expected_provider_display_name,
    validate_opencode_config,
)
from oc_providers.config import LaunchDefaults, ProviderConfig, _account_home, load_provider_config_with_digest
from oc_providers.contracts import (
    InstancePreflight,
    PersistedSelection,
    ProviderId,
    ProviderInstanceSpec,
    ProviderIntegrityError,
    ReadinessState,
    RelayMountPaths,
    SelectionState,
    SlotHandle,
    SlotRouteState,
)
from oc_providers.registry import UnqualifiedProviderAdapter

REPO_ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_MODEL = "shared-mini-model"
_OWNER_PROBE_HEADER = "x-oc-owner-challenge"


def _spec_obj(kind: ProviderId, label: str, *, enabled: bool = True, auth_mode: str = "subscription") -> ProviderInstanceSpec:
    return ProviderInstanceSpec(kind=kind, label=label, enabled=enabled, auth_mode=auth_mode)  # type: ignore[arg-type]


def _make_launch_spec(
    *,
    instance: str = "work",
    sandbox: str = "/sandbox-fixture",
    cwd: str = "wt/synth",
    level: str = "s0:c11,c22",
    relay_image: str = "a" * 64,
    agent_image: str = "b" * 64,
    provider_filter: str = "",
    cli_ui_mode: str = "mini",
) -> dict:
    pod = "oc" if instance == "default" else f"oc-{instance}"
    return {
        "instance": instance,
        "pod": pod,
        "agent": f"{pod}-agent",
        "relay": f"{pod}-openai-relay",
        "relay_image": relay_image,
        "agent_image": agent_image,
        "agent_mem": "1g",
        "level": level,
        "sandbox": sandbox,
        "cwd": cwd,
        "home_vol": f"{pod}-openai-home",
        "chromium": f"{pod}-chromium",
        "postgres": "",
        "pg_secret": "",
        "dind": "",
        "dind_run": "",
        "provider_filter": provider_filter,
        "cli_ui_mode": cli_ui_mode,
    }


def _make_http_request(
    *,
    method: str,
    path: str,
    port: int,
    token: str,
    body: bytes = b"",
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: 127.0.0.1:{port}",
        f"Authorization: Bearer {token}",
    ]
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
    if body:
        lines.append("Content-Type: application/json")
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def _send_framed_uds(
    sock_path: Path,
    proof: bytes,
    raw_http: bytes,
    *,
    entered: threading.Event | None = None,
    release_send: threading.Event | None = None,
) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5.0)
        sock.connect(str(sock_path))
        if entered is not None:
            entered.set()
        if release_send is not None:
            release_send.wait(timeout=5.0)
        frame = relay_mod.PROOF_PREFIX + proof + REQUEST_LENGTH.pack(len(raw_http)) + raw_http
        sock.sendall(frame)
        chunks = bytearray()
        while True:
            try:
                part = sock.recv(4096)
            except TimeoutError:
                break
            if not part:
                break
            chunks.extend(part)
        return bytes(chunks)


@dataclass(frozen=True)
class _SyntheticArrival:
    generation: int
    receipt_ready_at_arrival: bool
    owner_epoch: int


_FORBIDDEN_INPUT_ITEM_TYPES = frozenset({
    "function_call",
    "function_call_output",
    "tool_call",
    "tool_result",
    "tool_use",
    "computer_call",
    "computer_call_output",
    "mcp_call",
    "mcp_list_tools",
})
_FORBIDDEN_INPUT_ROLES = frozenset({"tool", "function"})


def _check_input_entry_zero_tools(entry: object) -> tuple[str, str, list[str]]:
    if type(entry) is not dict:
        raise ProofGateError("proof_gate_invalid_payload")
    etype = str(entry.get("type") or "")
    role = str(entry.get("role") or "")
    if (
        etype in _FORBIDDEN_INPUT_ITEM_TYPES
        or role in _FORBIDDEN_INPUT_ROLES
        or entry.get("tool_calls")
        or entry.get("function_call")
        or entry.get("call_id")
    ):
        raise ProofGateError("proof_tools_forbidden")
    content = entry.get("content")
    if isinstance(content, list) and any(
        isinstance(part, dict) and str(part.get("type") or "") in _FORBIDDEN_INPUT_ITEM_TYPES
        for part in content
    ):
        raise ProofGateError("proof_tools_forbidden")
    user_texts = _SyntheticSlotBroker._extract_user_texts(entry) if role == "user" else []
    return role, (etype or "message"), user_texts


def _validate_zero_tool_request_body(body_obj: object, *, allowed_models: frozenset[str] | None = None) -> tuple[str, list[str], list[str]]:
    """Independently verify a synthetic turn request carries zero tools/function calls and exact proof prompt."""
    if type(body_obj) is not dict:
        raise ProofGateError("proof_gate_invalid_payload")
    model = body_obj.get("model")
    if type(model) is not str or (allowed_models is not None and model not in allowed_models):
        raise ProofGateError("proof_gate_model_mismatch")
    if (
        body_obj.get("tools") not in (None, [])
        or body_obj.get("tool_choice") not in (None, "none")
        or body_obj.get("functions")
        or body_obj.get("function_call")
        or body_obj.get("parallel_tool_calls")
    ):
        raise ProofGateError("proof_tools_forbidden")
    items = body_obj.get("input")
    if type(items) is not list or not items:
        raise ProofGateError("proof_gate_prompt_mismatch")
    roles: list[str] = []
    item_types: list[str] = []
    user_texts: list[str] = []
    for entry in items:
        role, etype, texts = _check_input_entry_zero_tools(entry)
        roles.append(role)
        item_types.append(etype)
        user_texts.extend(texts)
    if user_texts != [PROOF_PROMPT]:
        raise ProofGateError("proof_gate_prompt_mismatch")
    return model, roles, item_types


class _IndependentSyntheticSink:
    """Independent synthetic request sink that re-validates full allowed requests outside broker gating."""

    def __init__(self, *, allowed_models: tuple[str, ...], records: list[dict]):
        self._allowed_models = frozenset(allowed_models)
        self._records = records

    def validate_and_record(self, body_obj: dict, *, claim_token: str, job_incarnation: str) -> None:
        model, roles, item_types = _validate_zero_tool_request_body(
            body_obj, allowed_models=self._allowed_models,
        )
        canonical = json.dumps(body_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self._records.append({
            "model": model,
            "tools": None,
            "input_roles": roles,
            "input_types": item_types,
            "body_sha256": sha256(canonical).hexdigest(),
            "claim_token": claim_token,
            "job_incarnation": job_incarnation,
        })


class _OwnerChallengedReceiptGate:
    """Slice C R4 owner-challenged broker-observed receipt + split claim/before_write/accept latch."""

    def __init__(
        self,
        *,
        approved_scoped_id: str,
        expected_relay_id: str,
        job_incarnation: str,
        supervisor_before_write=None,
    ):
        self.approved_scoped_id = approved_scoped_id
        self._lock = threading.Lock()
        self._expected_relay_id = expected_relay_id
        self._job_incarnation = job_incarnation
        self._supervisor_before_write = supervisor_before_write
        self._epoch = 1
        self._challenge_token = secrets.token_urlsafe(24)
        self._observed_probe_nonce: str | None = None
        self._observed_probe_key: tuple[str, str, int] | None = None
        self._receipt_generation = 0
        self._receipt_delivered = False
        self._revoked = False
        self._claimed = False
        self._active_claim_token: str | None = None
        self._spent = False
        self.claim_count = 0
        self.accept_count = 0
        self._accept_fence = threading.Lock()
        self._accept_drains: list = []
        self._accept_revokers: dict = {}

    def register_accept_drain(self, drain_fn, revoke_fn=None) -> None:
        with self._accept_fence:
            if drain_fn not in self._accept_drains:
                self._accept_drains.append(drain_fn)
            if callable(revoke_fn):
                self._accept_revokers[drain_fn] = revoke_fn

    def unregister_accept_drain(self, drain_fn) -> None:
        with self._accept_fence:
            if drain_fn in self._accept_drains:
                self._accept_drains.remove(drain_fn)
            self._accept_revokers.pop(drain_fn, None)

    def accept_with_snapshot(self, accept_nonblocking):
        with self._accept_fence:
            peer = accept_nonblocking()
            if peer is None:
                return None, None
            return peer, self.snapshot_arrival()

    @property
    def challenge_token(self) -> str:
        return self._challenge_token

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    def bind_relay(self, relay_id: str, job_incarnation: str) -> None:
        with self._lock:
            self._expected_relay_id = relay_id
            self._job_incarnation = job_incarnation
            self._epoch += 1
            self._observed_probe_nonce = None
            self._observed_probe_key = None
            self._receipt_delivered = False
            self._receipt_generation = 0

    def revoke(self) -> None:
        with self._lock:
            self._revoked = True
            self._receipt_delivered = False
            self._observed_probe_nonce = None
            self._observed_probe_key = None
            self._epoch += 1

    def record_broker_probe(self, *, challenge: str, job_incarnation: str) -> str | None:
        """Record an actual broker-side challenged probe observation scoped to this attempt."""
        with self._lock:
            if (
                self._revoked
                or not self._expected_relay_id
                or job_incarnation != self._job_incarnation
                or not hmac.compare_digest(challenge, self._challenge_token)
            ):
                return None
            nonce = secrets.token_hex(16)
            self._observed_probe_nonce = nonce
            self._observed_probe_key = (self._expected_relay_id, self._job_incarnation, self._epoch)
            return nonce

    def deliver_owner_receipt(
        self,
        *,
        challenge: str,
        relay_id: str,
        job_incarnation: str,
        epoch: int,
        probe_observation: str | None = None,
        before_rotate_hook=None,
    ) -> int:
        """Deliver attempt-scoped receipt with atomic UDS listener rotation to fence kernel backlog."""
        with self._accept_fence:
            pre_snapshot = self.snapshot_arrival()
            with self._lock:
                if self._revoked:
                    raise ProofGateError("proof_gate_revoked")
                if not hmac.compare_digest(challenge, self._challenge_token):
                    raise ProofGateError("proof_owner_challenge_mismatch")
                if relay_id != self._expected_relay_id or job_incarnation != self._job_incarnation:
                    raise ProofGateError("proof_gate_incarnation_mismatch")
                if epoch != self._epoch:
                    raise ProofGateError("proof_gate_epoch_mismatch")
                expected_key = (relay_id, job_incarnation, epoch)
                if (
                    not self._observed_probe_nonce
                    or self._observed_probe_key != expected_key
                    or not probe_observation
                    or not hmac.compare_digest(probe_observation, self._observed_probe_nonce)
                ):
                    raise ProofGateError("proof_probe_not_observed")
                self._receipt_generation += 1
                self._receipt_delivered = True
                gen = self._receipt_generation
            try:
                if before_rotate_hook is not None:
                    before_rotate_hook()
                for rotate_fn in list(self._accept_drains):
                    rotate_fn(pre_snapshot)
            except BaseException:
                with self._lock:
                    self._receipt_delivered = False
                    self._revoked = True
                for revoke_fn in list(self._accept_revokers.values()):
                    with suppress(Exception):
                        revoke_fn()
                raise
            return gen

    def snapshot_arrival(self) -> _SyntheticArrival:
        with self._lock:
            return _SyntheticArrival(
                generation=self._receipt_generation,
                receipt_ready_at_arrival=(self._receipt_delivered and not self._revoked),
                owner_epoch=self._epoch,
            )

    def claim_turn(self, arrival: _SyntheticArrival, *, job_incarnation: str) -> str:
        """Stage 1: atomically claim the single-use turn slot prior to supervisor before_write."""
        with self._lock:
            if (
                self._revoked
                or not arrival.receipt_ready_at_arrival
                or arrival.generation <= 0
                or not self._receipt_delivered
                or arrival.generation != self._receipt_generation
                or arrival.owner_epoch != self._epoch
                or job_incarnation != self._job_incarnation
            ):
                raise ProofGateError("proof_gate_not_armed")
            if self._claimed or self._spent:
                raise ProofGateError("proof_gate_spent")
            token = secrets.token_hex(16)
            self._claimed = True
            self._active_claim_token = token
            self.claim_count += 1
            return token

    def accept_turn(
        self,
        claim_token: str,
        *,
        arrival: _SyntheticArrival,
        job_incarnation: str,
        sink: _IndependentSyntheticSink,
        body_obj: dict,
    ) -> None:
        """Stage 3: re-verify live authority and hand the full request to the independent sink."""
        with self._lock:
            if (
                self._revoked
                or not self._receipt_delivered
                or not self._claimed
                or not self._active_claim_token
                or not hmac.compare_digest(claim_token, self._active_claim_token)
                or arrival.generation != self._receipt_generation
                or arrival.owner_epoch != self._epoch
                or job_incarnation != self._job_incarnation
            ):
                raise ProofGateError("proof_gate_revoked")
            if self._spent:
                raise ProofGateError("proof_gate_spent")
            sink.validate_and_record(body_obj, claim_token=claim_token, job_incarnation=job_incarnation)
            self._spent = True
            self.accept_count += 1

    def claim_and_record(
        self,
        arrival: _SyntheticArrival,
        *,
        job_incarnation: str,
        write_fence_hook=None,
        sink: _IndependentSyntheticSink,
        body_obj: dict,
    ) -> None:
        claim_token = self.claim_turn(arrival, job_incarnation=job_incarnation)
        if self._supervisor_before_write is not None:
            self._supervisor_before_write(claim_token=claim_token, job_incarnation=job_incarnation)
        if write_fence_hook is not None:
            write_fence_hook()
        self.accept_turn(
            claim_token, arrival=arrival, job_incarnation=job_incarnation, sink=sink, body_obj=body_obj,
        )


class _SyntheticSlotBroker:
    """Host-side UDS broker enforcing Slice C R4 arrival-snapshot receipt + zero-tool `ok` SSE."""

    def __init__(
        self,
        *,
        socket_path: Path,
        relay_proof: bytes,
        worker_token: str,
        lease: relay_mod.Lease,
        models: tuple[str, ...],
        expected_port: int,
        job_incarnation: str,
        receipt_gate: _OwnerChallengedReceiptGate | None,
        recorder: list[dict],
        sink: _IndependentSyntheticSink | None = None,
        refusal_code: str | None = None,
        before_claim_hook=None,
        write_fence_hook=None,
        before_dispatch_hook=None,
        before_accept_hook=None,
    ):
        self.socket_path = Path(socket_path)
        self._proof = relay_proof
        self._worker_token = worker_token
        self._lease = lease
        self._models = tuple(models)
        self._allowed_models = frozenset(models)
        self._expected_port = expected_port
        self._job_incarnation = job_incarnation
        self._receipt_gate = receipt_gate
        self._recorder = recorder
        self._sink = sink if sink is not None else _IndependentSyntheticSink(
            allowed_models=models, records=recorder,
        )
        self._refusal_code = refusal_code
        self._before_claim_hook = before_claim_hook
        self._write_fence_hook = write_fence_hook
        self._before_dispatch_hook = before_dispatch_hook
        self._before_accept_hook = before_accept_hook
        self._stopped = threading.Event()
        self._revoked = threading.Event()
        self._lock = threading.Lock()
        self._clients: set[socket.socket] = set()
        self._listener: socket.socket | None = None
        self._wake_r: int | None = None
        self._wake_w: int | None = None
        self._thread: threading.Thread | None = None
        self.owner_probes_seen: list[str] = []
        self.owner_probe_observations: list[str] = []

    def _wake_accept_loop(self) -> None:
        if self._wake_w is not None:
            with suppress(OSError):
                os.write(self._wake_w, b"\x01")

    def _bind_nonblocking_listener(self, path: Path) -> tuple[socket.socket, tuple[int, int]]:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound_id: tuple[int, int] | None = None
        try:
            listener.bind(str(path))
            info = path.lstat()
            bound_id = (info.st_dev, info.st_ino)
            path.chmod(0o600)
            listener.listen(8)
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
        self._revoked.set()
        old = self._listener
        self._listener = None
        if old is not None:
            with suppress(OSError):
                old.close()
        self._wake_accept_loop()

    def start(self) -> None:
        wake_r, wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            listener, _ = self._bind_nonblocking_listener(self.socket_path)
        except BaseException:
            os.close(wake_r)
            os.close(wake_w)
            raise
        self._wake_r = wake_r
        self._wake_w = wake_w
        self._listener = listener
        if self._receipt_gate is not None:
            self._receipt_gate.register_accept_drain(
                self._rotate_listener_locked, self._revoke_listener_on_publication_failure,
            )
        self._thread = threading.Thread(target=self._accept_loop, name="oc-synth-broker", daemon=True)
        self._thread.start()

    def is_revoked(self) -> bool:
        return bool(self._revoked.is_set())

    def has_active_clients(self) -> bool:
        with self._lock:
            return bool(self._clients)

    def revoke(self) -> None:
        self._revoked.set()
        if self._receipt_gate is not None:
            self._receipt_gate.revoke()

    def close(self) -> None:
        self._stopped.set()
        self._revoked.set()
        if self._receipt_gate is not None:
            self._receipt_gate.unregister_accept_drain(self._rotate_listener_locked)
        self._wake_accept_loop()
        if self._listener is not None:
            with suppress(OSError):
                self._listener.close()
        with self._lock:
            peers = list(self._clients)
        for peer in peers:
            with suppress(OSError):
                peer.shutdown(socket.SHUT_RDWR)
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        for attr in ("_wake_r", "_wake_w"):
            fd = getattr(self, attr)
            if fd is not None:
                setattr(self, attr, None)
                with suppress(OSError):
                    os.close(fd)
        with suppress(OSError):
            self.socket_path.unlink()

    def _try_accept_from(self, listener: socket.socket | None) -> socket.socket | None:
        if listener is None or self._stopped.is_set():
            return None
        try:
            peer, _ = listener.accept()
            return peer
        except (BlockingIOError, InterruptedError, ConnectionAbortedError, OSError):
            return None

    def _try_accept_nonblocking(self) -> socket.socket | None:
        return self._try_accept_from(self._listener)

    def _enqueue_peer(self, peer: socket.socket, arrival) -> None:
        with suppress(OSError):
            peer.setblocking(True)
        with self._lock:
            if self._stopped.is_set():
                peer.close()
                return
            self._clients.add(peer)
        threading.Thread(target=self._dispatch_accepted_peer, args=(peer, arrival), daemon=True).start()

    def _rotate_listener_locked(self, pre_snapshot=None) -> None:
        if self._stopped.is_set() or self._listener is None:
            return
        old_listener = self._listener
        tmp_path = self.socket_path.parent / f"s.{secrets.token_hex(4)}"
        new_listener, tmp_id = self._bind_nonblocking_listener(tmp_path)
        try:
            os.replace(tmp_path, self.socket_path)
        except BaseException:
            with suppress(OSError):
                new_listener.close()
            with suppress(OSError):
                cur = tmp_path.lstat()
                if (cur.st_dev, cur.st_ino) == tmp_id:
                    tmp_path.unlink()
            raise
        self._listener = new_listener
        self._wake_accept_loop()
        drain_arrival = pre_snapshot
        if drain_arrival is None and self._receipt_gate is not None:
            drain_arrival = self._receipt_gate.snapshot_arrival()
        try:
            while not self._stopped.is_set():
                peer = self._try_accept_from(old_listener)
                if peer is None:
                    break
                self._enqueue_peer(peer, drain_arrival)
        finally:
            with suppress(OSError):
                old_listener.close()

    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            listener = self._listener
            wake_r = self._wake_r
            if listener is None:
                return
            poller = select.poll()
            try:
                fd = listener.fileno()
                if fd < 0:
                    continue
                poller.register(fd, select.POLLIN)
                if wake_r is not None:
                    poller.register(wake_r, select.POLLIN)
                events = poller.poll(100)
            except (OSError, ValueError):
                if self._stopped.is_set():
                    return
                continue
            for ev_fd, _ in events:
                if wake_r is not None and ev_fd == wake_r:
                    with suppress(OSError):
                        os.read(wake_r, 64)
            if not events:
                continue
            if self._before_accept_hook is not None:
                self._before_accept_hook()
            while not self._stopped.is_set():
                if self._receipt_gate is not None:
                    peer, arrival = self._receipt_gate.accept_with_snapshot(self._try_accept_nonblocking)
                else:
                    peer = self._try_accept_nonblocking()
                    arrival = None
                if peer is None:
                    break
                self._enqueue_peer(peer, arrival)

    def _dispatch_accepted_peer(self, peer: socket.socket, arrival) -> None:
        if self._before_dispatch_hook is not None:
            self._before_dispatch_hook()
        self._handle_peer(peer, arrival=arrival)

    def _read_framed(self, peer: socket.socket) -> bytes | None:
        deadline = time.monotonic() + 5.0
        expected = relay_mod.PROOF_PREFIX + self._proof
        if not hmac.compare_digest(_read_exact(peer, len(expected), deadline), expected):
            return None
        size, = REQUEST_LENGTH.unpack(_read_exact(peer, REQUEST_LENGTH.size, deadline))
        if not 0 < size <= MAX_REQUEST_FRAME:
            return None
        return _read_exact(peer, size, deadline)

    @staticmethod
    def _strip_owner_challenge(raw_http: bytes) -> tuple[bytes, str]:
        sep = b"\r\n\r\n"
        if sep not in raw_http:
            return raw_http, ""
        head_bytes, body = raw_http.split(sep, 1)
        lines = head_bytes.decode("latin-1", errors="replace").split("\r\n")
        kept = [lines[0]]
        challenge = ""
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() == _OWNER_PROBE_HEADER:
                    challenge = v.strip()
                    continue
            kept.append(line)
        return ("\r\n".join(kept)).encode("latin-1") + sep + body, challenge

    def _emit_ok_sse(self, peer: socket.socket, model: str) -> None:
        resp_id = f"resp_synth_{secrets.token_hex(6)}"
        msg_id = f"msg_synth_{secrets.token_hex(6)}"
        events = (
            {"type": "response.created", "response": {"id": resp_id, "status": "in_progress", "model": model}},
            {
                "type": "response.output_item.added",
                "output_index": 0,
                "item": {"id": msg_id, "type": "message", "role": "assistant", "status": "in_progress", "content": []},
            },
            {
                "type": "response.content_part.added",
                "item_id": msg_id,
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": ""},
            },
            {
                "type": "response.output_text.delta",
                "item_id": msg_id,
                "output_index": 0,
                "content_index": 0,
                "delta": EXPECTED_REPLY,
            },
            {
                "type": "response.output_text.done",
                "item_id": msg_id,
                "output_index": 0,
                "content_index": 0,
                "text": EXPECTED_REPLY,
            },
            {
                "type": "response.content_part.done",
                "item_id": msg_id,
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": EXPECTED_REPLY},
            },
            {
                "type": "response.output_item.done",
                "output_index": 0,
                "item": {
                    "id": msg_id,
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": EXPECTED_REPLY}],
                },
            },
            {
                "type": "response.completed",
                "response": {
                    "id": resp_id,
                    "status": "completed",
                    "model": model,
                    "output": [
                        {
                            "id": msg_id,
                            "type": "message",
                            "role": "assistant",
                            "status": "completed",
                            "content": [{"type": "output_text", "text": EXPECTED_REPLY}],
                        }
                    ],
                    "usage": {"input_tokens": 4, "output_tokens": 1, "total_tokens": 5},
                },
            },
        )
        peer.sendall(sse_response_headers())
        for ev in events:
            frame = f"event: {ev['type']}\ndata: {json.dumps(ev, separators=(',', ':'))}\n\n".encode("utf-8")
            peer.sendall(encode_chunk(frame))
        peer.sendall(b"0\r\n\r\n")

    @staticmethod
    def _extract_user_texts(entry: object) -> list[str]:
        if not isinstance(entry, dict) or entry.get("role") != "user":
            return []
        content = entry.get("content")
        if isinstance(content, str):
            return [content.strip()]
        if not isinstance(content, list):
            return []
        return [
            part["text"].strip()
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]

    @classmethod
    def _is_proof_prompt_request(cls, body_obj: dict) -> bool:
        items = body_obj.get("input")
        if not isinstance(items, list) or not items:
            return False
        user_texts: list[str] = []
        for entry in items:
            user_texts.extend(cls._extract_user_texts(entry))
        return user_texts == [PROOF_PROMPT]

    def _dispatch_turn(self, peer: socket.socket, parsed, arrival) -> None:
        if self._refusal_code is not None:
            peer.sendall(format_error_response(403, self._refusal_code, "Synthetic slot refused."))
            return
        if self._before_claim_hook is not None:
            self._before_claim_hook(arrival)
        if self._receipt_gate is None or arrival is None:
            peer.sendall(format_error_response(403, "proof_gate_not_armed", "Receipt gate missing."))
            return
        body_obj = json.loads(parsed.raw_body.decode("utf-8"))
        _validate_zero_tool_request_body(body_obj, allowed_models=self._allowed_models)
        self._receipt_gate.claim_and_record(
            arrival,
            job_incarnation=self._job_incarnation,
            write_fence_hook=self._write_fence_hook,
            sink=self._sink,
            body_obj=body_obj,
        )
        self._emit_ok_sse(peer, parsed.model)

    def _handle_peer(self, peer: socket.socket, *, arrival=None) -> None:
        if arrival is None and self._receipt_gate is not None:
            arrival = self._receipt_gate.snapshot_arrival()
        try:
            raw = self._read_framed(peer)
            if raw is None:
                return
            if self._revoked.is_set() or not self._lease.active():
                peer.sendall(format_error_response(401, "session_revoked", "Synthetic slot is revoked."))
                return
            cleaned_raw, challenge = self._strip_owner_challenge(raw)
            parsed = parse_worker_request(
                cleaned_raw,
                expected_token=self._worker_token,
                allowed_models=self._allowed_models,
                vault=None,
                expected_port=self._expected_port,
            )
            if parsed.route == "models":
                if challenge:
                    self.owner_probes_seen.append(challenge)
                    if self._receipt_gate is not None:
                        obs = self._receipt_gate.record_broker_probe(
                            challenge=challenge, job_incarnation=self._job_incarnation,
                        )
                        if obs is not None:
                            self.owner_probe_observations.append(obs)
                peer.sendall(format_models_response(self._models))
                return
            self._dispatch_turn(peer, parsed, arrival)
        except RequestRefused as err:
            with suppress(OSError):
                peer.sendall(format_error_response(err.status, err.code, err.message))
        except ProofGateError as err:
            code = err.args[0] if err.args and type(err.args[0]) is str else "proof_gate_not_armed"
            with suppress(OSError):
                peer.sendall(format_error_response(403, code, "Proof gate refused request."))
        except (OSError, EOFError, ValueError):
            pass
        finally:
            with self._lock:
                self._clients.discard(peer)
            with suppress(OSError):
                peer.shutdown(socket.SHUT_RDWR)
            with suppress(OSError):
                peer.close()


class PublicCliConfigEntryTests(unittest.TestCase):
    """Section 3.1: Public `oc-sandbox` CLI config-driven managed mode & fd 3 handoff."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="oc-mix-cli-")
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _prepare_stub_checkout(self) -> tuple[Path, Path, Path, Path]:
        checkout = self.root / "checkout"
        checkout.mkdir(mode=0o700)
        script_copy = checkout / "oc-sandbox"
        shutil.copy2(REPO_ROOT / "oc-sandbox", script_copy)
        script_copy.chmod(0o755)
        for sibling in (
            "oc-bridge.py",
            "oc-opencode-run.py",
            "oc-opencode-supervisor.py",
            "oc-opencode-update.py",
            "oc-setup-lock.py",
        ):
            src = REPO_ROOT / sibling
            if src.exists():
                dst = checkout / sibling
                shutil.copy2(src, dst)
                dst.chmod(0o644)
        capture_file = self.root / "captured_fd3.json"
        helper = checkout / "oc-openai-session.py"
        helper.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "raw = os.read(3, 65536).decode('utf-8')\n"
            f"out = {str(capture_file)!r}\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'spec': json.loads(raw), 'env': dict(os.environ)}, fh)\n"
            "raise SystemExit(0)\n",
            encoding="utf-8",
        )
        helper.chmod(0o755)

        stub_dir = self.root / "stubs"
        stub_dir.mkdir(mode=0o700)
        podman_log = self.root / "podman.log"
        for tool in ("systemctl", "fake-editor"):
            p = stub_dir / tool
            p.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            p.chmod(0o755)

        fake_podman = stub_dir / "podman"
        fake_podman.write_text(
            f"""#!/usr/bin/bash
echo "podman $*" >> "{podman_log}"
case "$1 $2" in
  "--version "*) echo "podman version 5.0.0"; exit 0 ;;
  "image inspect")
    if [[ "$*" == *"oc.hash"* ]]; then echo ""; exit 1; fi
    echo "{'d' * 64}"; exit 0 ;;
  "build "*|"volume exists"|"pod create"|"pod rm"|"pod ls"|"volume ls"|"secret ls") exit 0 ;;
  "pod exists") exit 1 ;;
  "pod inspect")
    if [[ "$*" == *"PortBindings"* ]]; then echo "{{}}"; exit 0; fi
    if [[ "$*" == *"oc.podcfg"* ]]; then echo "v1|"; exit 0; fi
    exit 0 ;;
  "container exists") exit 1 ;;
  "container inspect") exit 1 ;;
  "run "*) exit 0 ;;
  "create "*) echo "{'e' * 64}"; exit 0 ;;
  *) exit 0 ;;
esac
""",
            encoding="utf-8",
        )
        fake_podman.chmod(0o755)
        return script_copy, stub_dir, capture_file, podman_log

    def _prepare_home(self, name: str, script: Path, stub_dir: Path, *, with_toml: bool) -> tuple[Path, dict]:
        home = self.root / name
        home.mkdir(mode=0o700)
        (home / ".oh-my-zsh" / "custom" / "plugins" / "zsh-vi-mode").mkdir(parents=True, mode=0o700)
        pol_dir = home / ".local" / "share" / "oc-sandbox" / "policy"
        pol_dir.mkdir(parents=True, mode=0o700)
        cil_text = script.read_text(encoding="utf-8")
        start = cil_text.index("; SELinux type for the sandboxed Chromium container only")
        end = cil_text.index("\nPOL\n", start)
        pol_hash = sha256((cil_text[start:end] + "\n").encode("utf-8")).hexdigest()[:16]
        (pol_dir / "installed").write_text(pol_hash + "\n", encoding="utf-8")
        if with_toml:
            cfg_dir = home / ".config" / "oc-sandbox"
            cfg_dir.mkdir(parents=True, mode=0o700)
            toml_path = cfg_dir / "providers.toml"
            toml_path.write_text(
                "[providers.openai.personal]\n"
                "enabled = true\n"
                'auth_mode = "subscription"\n'
                "[providers.openai.work]\n"
                "enabled = true\n"
                'auth_mode = "subscription"\n'
                "[providers.google.personal]\n"
                "enabled = true\n"
                'auth_mode = "subscription"\n',
                encoding="utf-8",
            )
            toml_path.chmod(0o600)
        env = {
            "PATH": f"{stub_dir}:/usr/bin:/bin",
            "HOME": str(home),
            "OC_CHROMIUM_MODE": "headless",
            "OC_CODE_BIN": str(stub_dir / "fake-editor"),
            "OC_BCOMPARE_BIN": str(stub_dir / "fake-editor"),
            "OPENAI_API_KEY": "sk-ambient-must-be-scrubbed",
            "GOOGLE_API_KEY": "AIza-ambient-must-be-scrubbed",
            "ANTHROPIC_API_KEY": "sk-ant-ambient-must-be-scrubbed",
        }
        return home, env

    def test_bare_without_toml_or_openai_state_stays_legacy_mode(self):
        script, stub_dir, capture_file, podman_log = self._prepare_stub_checkout()
        home, env = self._prepare_home("legacy_home", script, stub_dir, with_toml=False)
        # Patch detect_managed_mode inside the scratch copy to use scratch home as account_home
        # so the test is independent of host developer state under real ~/.config/oc-sandbox.
        py_stub = self.root / "acct_py"
        py_stub.write_text(
            "#!/usr/bin/python3 -I\n"
            "import os, pwd, sys, types\n"
            "fake = os.environ['HOME']\n"
            "orig = pwd.getpwuid\n"
            "pwd.getpwuid = lambda uid: types.SimpleNamespace(pw_dir=fake, pw_uid=orig(uid).pw_uid)\n"
            "code = sys.stdin.read()\n"
            "sys.argv = ['-', sys.argv[-1]]\n"
            "exec(compile(code, '<detect>', 'exec'), {'__name__': '__main__'})\n",
            encoding="utf-8",
        )
        py_stub.chmod(0o755)
        patched_src = script.read_text(encoding="utf-8").replace(
            "/usr/bin/python3 -I -", f"{py_stub} -", 1,
        )
        script.write_text(patched_src, encoding="utf-8")
        script.chmod(0o755)
        env["OC_OPENCODE_VERSION"] = "keep"
        res = subprocess.run(
            ["bash", str(script)],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(capture_file.exists(), "Legacy mode must not invoke managed supervisor")
        log_text = podman_log.read_text(encoding="utf-8")
        self.assertIn("podman create -it --rm --name oc-agent", log_text)
        self.assertIn("-v oc-home:/root", log_text)
        self.assertNotIn("oc-openai-home", log_text)

    def test_bare_and_mini_with_toml_handoff_exact_fd3_and_reject_google_flag(self):
        script, stub_dir, capture_file, _podman_log = self._prepare_stub_checkout()
        _home, env = self._prepare_home("managed_home", script, stub_dir, with_toml=True)

        # 1. Bare `oc-sandbox` with trusted providers.toml -> MANAGED_MODE=1, provider_filter="", cli_ui_mode="default".
        res_bare = subprocess.run(
            ["bash", str(script)],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res_bare.returncode, 0, res_bare.stderr)
        captured_bare = json.loads(capture_file.read_text(encoding="utf-8"))
        self.assertEqual(captured_bare["spec"]["provider_filter"], "")
        self.assertEqual(captured_bare["spec"]["cli_ui_mode"], "default")
        for forbidden in ("OPENAI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY"):
            self.assertNotIn(forbidden, captured_bare["env"])
        capture_file.unlink()

        # 2. `oc-sandbox --mini` with trusted providers.toml -> provider_filter="", cli_ui_mode="mini", scrubbed env.
        res_mini = subprocess.run(
            ["bash", str(script), "--mini"],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res_mini.returncode, 0, res_mini.stderr)
        captured_mini = json.loads(capture_file.read_text(encoding="utf-8"))
        self.assertEqual(captured_mini["spec"]["provider_filter"], "")
        self.assertEqual(captured_mini["spec"]["cli_ui_mode"], "mini")
        for forbidden in ("OPENAI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY"):
            self.assertNotIn(forbidden, captured_mini["env"])

        # 3. `--provider google` and `--provider google/personal` fail closed with exit 2.
        for argv in (["--provider", "google"], ["--provider", "google/personal"]):
            res_g = subprocess.run(
                ["bash", str(script), *argv],
                env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(res_g.returncode, 2, f"argv={argv} stderr={res_g.stderr}")
            self.assertIn("not yet qualified", res_g.stderr)


class MixedProviderContractAndLifecycleTests(unittest.TestCase):
    """Section 3.2: Offline lock, opaque 10-hook SlotHandle, teardown retention, and R4 receipt tests."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="oc-mix-unit-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _make_opaque_slot(
        self,
        *,
        slot_index: int = 0,
        provider_label: str = "google/personal",
        scoped_id: str = "google--personal",
        port: int = 8402,
        overrides: dict | None = None,
    ) -> tuple[SlotHandle, dict, Path]:
        slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir=self.root))
        for sub in ("source", "provider", "grant", "proof"):
            (slot_root / sub).mkdir(mode=0o700)
        sock_path = slot_root / "provider" / "provider.sock"
        proof_file = slot_root / "proof" / "relay"
        proof_file.write_bytes(b"p" * 32)
        state = {
            "route": "pending",
            "revoked": False,
            "active_clients": False,
            "relay_created": False,
            "relay_confirmed_removed": 0,
            "lease_released": True,
            "revoke_calls": 0,
            "close_calls": 0,
            "activate_calls": 0,
            "cm_exits": 0,
        }

        def revoke_grant():
            state["revoke_calls"] += 1
            state["route"] = "retired"
            state["revoked"] = True

        def close_broker():
            state["close_calls"] += 1

        def activate_route():
            state["activate_calls"] += 1
            state["route"] = "active"

        def mark_relay_created():
            state["relay_created"] = True

        def confirm_relay_removed():
            state["relay_confirmed_removed"] += 1

        kwargs = {
            "slot_index": slot_index,
            "scoped_id": scoped_id,
            "provider_label": provider_label,
            "port": port,
            "job": object(),
            "broker": object(),
            "lease": object(),
            "build_relay_args": lambda _spec: ["create", "opaque-relay"],
            "relay_paths": RelayMountPaths(
                source_dir=slot_root / "source",
                provider_socket=sock_path,
                grant_dir=slot_root / "grant",
                proof_file=proof_file,
            ),
            "revoke_grant": revoke_grant,
            "close_broker": close_broker,
            "activate_route": activate_route,
            "route_state": lambda: state["route"],
            "is_revoked": lambda: state["revoked"],
            "has_active_clients": lambda: state["active_clients"],
            "mark_relay_created": mark_relay_created,
            "confirm_relay_removed": confirm_relay_removed,
            "authorize_lease_release": lambda: state.__setitem__("release_authorized", True),
            "deny_lease_release": lambda: state.__setitem__("release_denied", True),
            "bind_release_authority": lambda pred: state.__setitem__("authority", pred),
            "lease_release_confirmed": lambda: bool(state["lease_released"]) and not bool(state.get("release_denied")),
        }
        if overrides:
            kwargs.update(overrides)
        return SlotHandle(**kwargs), state, slot_root

    def _make_cm(self, state: dict):
        class _CM:
            def __exit__(self, *_exc):
                state["cm_exits"] += 1

        return _CM()

    def test_fd_pinned_instance_lock_contention_symlink_hardlink_and_home_alias(self):
        state_dir = self.root / "lock_root"
        state_dir.mkdir(mode=0o700)

        # 1. Exclusive contention on same root blocks second acquisition, then succeeds after close.
        fd1 = _open_instance_lock(state_dir, "work")
        try:
            with self.assertRaises(BlockingIOError):
                _open_instance_lock(state_dir, "work")
        finally:
            os.close(fd1)
        fd2 = _open_instance_lock(state_dir, "work")
        os.close(fd2)

        # 2. Symlinked ancestor directory MUST be refused via O_NOFOLLOW.
        real_target = self.root / "real_lock_dir"
        real_target.mkdir(mode=0o700)
        sym_parent = self.root / "sym_lock_parent"
        sym_parent.symlink_to(real_target)
        with self.assertRaises((OSError, RuntimeError)):
            _open_instance_lock(sym_parent, "work")

        # 3. Hardlinked lock file (st_nlink > 1) MUST be refused.
        hl_dir = self.root / "hardlink_root"
        hl_sess = hl_dir / "sessions"
        hl_sess.mkdir(parents=True, mode=0o700)
        lock_file = hl_sess / "work.lock"
        lock_file.write_bytes(b"")
        lock_file.chmod(0o600)
        os.link(lock_file, hl_sess / "work.lock.alias")
        with self.assertRaisesRegex(RuntimeError, "Untrusted session lock file"):
            _open_instance_lock(hl_dir, "work")

        # 4. Sandbox overlap refusal.
        sb_sub = _account_home() / "opencode-sandbox" / "nested"
        with self.assertRaisesRegex(RuntimeError, "overlaps agent sandbox"):
            _open_instance_lock(sb_sub, "work")

        # 5. `/home` <-> `/var/home` canonical alias normalization.
        norm = _normalize_lock_root(Path("/home/example/.config/oc-sandbox/openai"))
        if Path("/home").is_symlink() and Path("/home").resolve() == Path("/var/home"):
            self.assertEqual(norm, Path("/var/home/example/.config/oc-sandbox/openai"))
        else:
            self.assertEqual(norm, Path("/home/example/.config/oc-sandbox/openai"))

    def test_preconfirmed_plan_rejects_unqualified_and_truthy_non_bool(self):
        gg_spec = _spec_obj("google", "personal")
        cfg = ProviderConfig(instances=(gg_spec,), provider_defaults={}, launch=LaunchDefaults())
        pref = InstancePreflight(gg_spec, ReadinessState.READY, (SYNTHETIC_MODEL,), route_policy="sub")
        plan = ResolvedLaunchPlan(
            admitted=(pref,),
            excluded=(),
            initial_provider_id="google--personal",
            initial_model=SYNTHETIC_MODEL,
            ui_mode="mini",
            ui_source="--mini",
            acknowledged_digests={},
        )
        approval = ProofApproval(
            run_id="1" * 32,
            instance_label="personal",
            scoped_provider_id="google--personal",
            approved_model=SYNTHETIC_MODEL,
            ui_mode="mini",
            cwd="wt/synth",
            selection_epoch="epoch-1",
            credential_generation=1,
            history_digest_all_12_files="e" * 64,
            auth_mode="subscription",
            providers_config_digest="d" * 64,
        )
        gate = type("_G", (), {"approval": approval})()

        with self.assertRaises(LaunchRefusedError) as ctx_unqual:
            _validate_preconfirmed_plan(
                plan, gate, cfg, "d" * 64,
                active_adapters={"google": UnqualifiedProviderAdapter("google")},
            )
        self.assertEqual(ctx_unqual.exception.code, "provider_unqualified")

        class _TruthyNonBool:
            def is_qualified(self, _mode: str, _place: str):
                return 1

        with self.assertRaises(LaunchRefusedError) as ctx_int:
            _validate_preconfirmed_plan(
                plan, gate, cfg, "d" * 64,
                active_adapters={"google": _TruthyNonBool()},
            )
        self.assertEqual(ctx_int.exception.code, "provider_unqualified")

    def test_opaque_slot_handle_requires_all_10_hooks_and_exact_types(self):
        # 1. Valid opaque handle passes validation, startup, any_active, and clean teardown.
        handle, state, slot_root = self._make_opaque_slot()
        _validate_slot_handle(handle)
        stop_ev = threading.Event()
        coord = _SessionSlotCoordinator(stop_ev)
        cm = self._make_cm(state)
        coord.register_slot(cm, handle, slot_root)
        relay_id = "f" * 64
        spec = _make_launch_spec()
        with (
            patch.object(session_broker, "podman", return_value=subprocess.CompletedProcess(("podman",), 0, (relay_id + "\n").encode(), b"")),
            patch.object(session_broker, "_verify_relay_prestart"),
            patch.object(session_broker, "_verify_relay_isolation"),
            patch.object(session_broker, "_wait_relay_bound"),
        ):
            got_id = session_broker._start_and_verify_slot_relay(
                spec, "1" * 64, handle, coord, [], [], stop_ev,
            )
        self.assertEqual(got_id, relay_id)
        self.assertTrue(coord.any_active())
        with patch.object(session_broker, "_remove_container_verified"):
            err = coord.teardown_all(None)
        self.assertIsNone(err)
        self.assertEqual((state["revoke_calls"], state["close_calls"], state["relay_confirmed_removed"], state["cm_exits"]), (1, 1, 1, 1))

        # 2. Removing ANY required hook (including release coordination) from an opaque handle fails closed.
        all_hooks = (
            "relay_paths", "revoke_grant", "close_broker", "activate_route", "route_state",
            "is_revoked", "has_active_clients", "mark_relay_created", "confirm_relay_removed",
            "authorize_lease_release", "deny_lease_release", "bind_release_authority",
            "lease_release_confirmed",
        )
        for missing in all_hooks:
            with self.subTest(missing_hook=missing):
                bad_handle, _, _ = self._make_opaque_slot(overrides={missing: None})
                with self.assertRaises(ProviderIntegrityError) as ctx:
                    _validate_slot_handle(bad_handle)
                self.assertEqual(ctx.exception.code, "incomplete_slot_handle")

        # 3. Malformed / non-bool return types fail closed.
        for bad_hook, bad_fn in (
            ("is_revoked", lambda: 0),
            ("route_state", lambda: "bogus"),
            ("has_active_clients", lambda: 0),
            ("lease_release_confirmed", lambda: 1),
        ):
            with self.subTest(malformed_hook=bad_hook):
                h_bad, _, _ = self._make_opaque_slot(overrides={bad_hook: bad_fn})
                with self.assertRaises(ProviderIntegrityError):
                    if bad_hook == "is_revoked":
                        session_broker._slot_is_revoked(h_bad)
                    elif bad_hook == "route_state":
                        session_broker._slot_route_state(h_bad)
                    elif bad_hook == "has_active_clients":
                        session_broker._slot_has_active_clients(h_bad)
                    else:
                        session_broker._slot_lease_release_confirmed(h_bad)

    def _run_finalize_case(self, coord: _SessionSlotCoordinator, session_root: Path) -> tuple[bool, dict]:
        cleanup_state = {"clean": False}
        term = StreamTerminal(io.StringIO(), io.StringIO(), io.StringIO())
        ok = session_broker._finalize_session_teardown(
            coord, None, None, None, cleanup_state, session_root, term,
        )
        return ok, cleanup_state

    def test_teardown_retention_for_lost_create_ack_and_revoke_or_close_failure(self):
        # Case 1: Lost create ack (`begin_relay_create` -> `finish_relay_create(0, None)`).
        h1, st1, root1 = self._make_opaque_slot()
        sess1 = self.root / "sess_lost_ack"
        sess1.mkdir(mode=0o700)
        coord1 = _SessionSlotCoordinator(threading.Event())
        coord1.register_slot(self._make_cm(st1), h1, root1)
        self.assertTrue(coord1.begin_relay_create(0))
        self.assertFalse(coord1.finish_relay_create(0, None))
        ok1, cstate1 = self._run_finalize_case(coord1, sess1)
        self.assertFalse(ok1)
        self.assertFalse(cstate1["clean"])
        self.assertEqual((st1["relay_confirmed_removed"], st1["cm_exits"]), (0, 0))
        self.assertTrue(root1.exists())
        self.assertTrue(sess1.exists())

        # Case 2: `revoke_grant()` raises, then fallback container removal succeeds -> still retains lease & roots!
        for fail_hook in ("revoke_grant", "close_broker"):
            with self.subTest(failing_hook=fail_hook):
                def _boom():
                    raise RuntimeError(f"{fail_hook} failed")

                h2, st2, root2 = self._make_opaque_slot(overrides={fail_hook: _boom})
                sess2 = self.root / f"sess_{fail_hook}"
                sess2.mkdir(mode=0o700)
                coord2 = _SessionSlotCoordinator(threading.Event())
                coord2.register_slot(self._make_cm(st2), h2, root2)
                self.assertTrue(coord2.record_container("a" * 64, slot_index=0))
                removed: list[str] = []
                with patch.object(session_broker, "_remove_container_verified", side_effect=lambda c: removed.append(c)):
                    ok2, cstate2 = self._run_finalize_case(coord2, sess2)
                self.assertEqual(removed, ["a" * 64])
                self.assertFalse(ok2)
                self.assertFalse(cstate2["clean"])
                self.assertEqual((st2["relay_confirmed_removed"], st2["cm_exits"]), (0, 0))
                self.assertTrue(root2.exists())
                self.assertTrue(sess2.exists())

    def test_teardown_retention_timed_out_paused_revoke_both_outcomes(self):
        # Case 3a (fails after resume) and Case 3b (returns cleanly after resume):
        # Fallback MUST invoke ZERO second slot hooks, and sticky retire_timed_out MUST block lease release!
        orig_join = threading.Thread.join

        def _fast_join(thread_self, timeout=None):
            return orig_join(thread_self, timeout=0.02)

        for outcome in ("fail_after_timeout", "succeed_after_timeout"):
            with self.subTest(outcome=outcome):
                entered_revoke = threading.Event()
                release_revoke = threading.Event()
                hook_calls = {"revoke": 0, "close": 0, "confirm": 0}
                state_box: dict = {}

                def paused_revoke():
                    hook_calls["revoke"] += 1
                    entered_revoke.set()
                    release_revoke.wait(timeout=5.0)
                    if outcome == "fail_after_timeout":
                        raise RuntimeError("late revoke failure")

                def tracked_close():
                    hook_calls["close"] += 1

                def tracked_confirm():
                    hook_calls["confirm"] += 1

                h, st, slot_root = self._make_opaque_slot(
                    overrides={
                        "revoke_grant": paused_revoke,
                        "close_broker": tracked_close,
                        "confirm_relay_removed": tracked_confirm,
                    },
                )
                state_box.update(st)
                sess_root = self.root / f"sess_timeout_{outcome}"
                sess_root.mkdir(mode=0o700)
                coord = _SessionSlotCoordinator(threading.Event())
                coord.register_slot(self._make_cm(st), h, slot_root)
                coord.record_container("c" * 64, slot_index=0)
                coord.on_revoke(0)
                self.assertTrue(entered_revoke.wait(timeout=2.0))

                removed: list[str] = []
                with (
                    patch.object(threading.Thread, "join", _fast_join),
                    patch.object(session_broker, "_remove_container_verified", side_effect=lambda c: removed.append(c)),
                ):
                    ok, cstate = self._run_finalize_case(coord, sess_root)

                # While paused worker is still inside revoke_grant, fallback MUST have invoked ZERO extra slot hooks!
                self.assertFalse(ok)
                self.assertFalse(cstate["clean"])
                self.assertEqual(hook_calls["revoke"], 1)
                self.assertEqual(hook_calls["close"], 0)
                self.assertEqual(hook_calls["confirm"], 0)
                self.assertEqual(st["cm_exits"], 0)
                self.assertEqual(removed, ["c" * 64])

                # Now let the paused worker finish (either raising or returning cleanly).
                release_revoke.set()
                for t in list(coord._retire_threads):
                    orig_join(t, timeout=2.0)

                # Sticky retire_timed_out guarantees ZERO confirm_relay_removed, ZERO lease exits, roots retained!
                self.assertEqual(hook_calls["confirm"], 0)
                self.assertEqual(st["cm_exits"], 0)
                self.assertTrue(slot_root.exists())
                self.assertTrue(sess_root.exists())

    def test_teardown_retention_timed_out_paused_confirm_relay_removed(self):
        # Regression: a slow `confirm_relay_removed()` spanning teardown_all's bounded join timeout
        # sets sticky `retire_timed_out=True`; when `confirm_relay_removed()` later returns cleanly,
        # the original worker MUST NOT exit `slot_cm` or mark lease released, and roots stay retained.
        orig_join = threading.Thread.join

        def _fast_join(thread_self, timeout=None):
            return orig_join(thread_self, timeout=0.02)

        entered_confirm = threading.Event()
        release_confirm = threading.Event()
        confirm_calls = [0]

        def paused_confirm():
            confirm_calls[0] += 1
            entered_confirm.set()
            release_confirm.wait(timeout=5.0)

        h, st, slot_root = self._make_opaque_slot(overrides={"confirm_relay_removed": paused_confirm})
        sess_root = self.root / "sess_timeout_confirm"
        sess_root.mkdir(mode=0o700)
        coord = _SessionSlotCoordinator(threading.Event())
        coord.register_slot(self._make_cm(st), h, slot_root)
        coord.record_container("e" * 64, slot_index=0)
        with patch.object(session_broker, "_remove_container_verified"):
            coord.on_revoke(0)
            self.assertTrue(entered_confirm.wait(timeout=2.0))
            with patch.object(threading.Thread, "join", _fast_join):
                ok, cstate = self._run_finalize_case(coord, sess_root)
            self.assertFalse(ok)
            self.assertFalse(cstate["clean"])
            self.assertEqual(confirm_calls[0], 1)
            self.assertEqual(st["cm_exits"], 0)

            release_confirm.set()
            for t in list(coord._retire_threads):
                orig_join(t, timeout=2.0)

        self.assertEqual(confirm_calls[0], 1)
        self.assertEqual(st["cm_exits"], 0, "slow confirm_relay_removed returning after timeout must not exit lease")
        self.assertFalse(coord._slots[0].lease_confirmed_released)
        self.assertFalse(coord._slots[0].retired)
        self.assertTrue(slot_root.exists())
        self.assertTrue(sess_root.exists())

    def test_teardown_retention_non_quiescent_failed_remove_and_unconfirmed_lease(self):
        # 1. Non-quiescent broker (`has_active_clients() -> True` and raising).
        for label, clients_fn in (("active_true", lambda: True), ("active_raises", lambda: (_ for _ in ()).throw(RuntimeError("boom")))):
            with self.subTest(quiescence=label):
                h, st, slot_root = self._make_opaque_slot(overrides={"has_active_clients": clients_fn})
                sess = self.root / f"sess_q_{label}"
                sess.mkdir(mode=0o700)
                coord = _SessionSlotCoordinator(threading.Event())
                coord.register_slot(self._make_cm(st), h, slot_root)
                ok, cstate = self._run_finalize_case(coord, sess)
                self.assertFalse(ok)
                self.assertFalse(cstate["clean"])
                self.assertEqual(st["cm_exits"], 0)
                self.assertTrue(slot_root.exists())

        # 2. Failed `_remove_container_verified`.
        h_rm, st_rm, root_rm = self._make_opaque_slot()
        sess_rm = self.root / "sess_rm_fail"
        sess_rm.mkdir(mode=0o700)
        coord_rm = _SessionSlotCoordinator(threading.Event())
        coord_rm.register_slot(self._make_cm(st_rm), h_rm, root_rm)
        coord_rm.record_container("d" * 64, slot_index=0)
        with patch.object(session_broker, "_remove_container_verified", side_effect=RuntimeError("rm fail")):
            ok_rm, cstate_rm = self._run_finalize_case(coord_rm, sess_rm)
        self.assertFalse(ok_rm)
        self.assertFalse(cstate_rm["clean"])
        self.assertEqual((st_rm["relay_confirmed_removed"], st_rm["cm_exits"]), (0, 0))
        self.assertTrue(root_rm.exists())

        # 3. `lease_release_confirmed()` returns False, non-bool, or raises.
        for label, confirm_fn in (
            ("false", lambda: False),
            ("non_bool", lambda: "yes"),
            ("raises", lambda: (_ for _ in ()).throw(RuntimeError("lease check failed"))),
        ):
            with self.subTest(lease_confirm=label):
                h_lc, st_lc, root_lc = self._make_opaque_slot(overrides={"lease_release_confirmed": confirm_fn})
                sess_lc = self.root / f"sess_lc_{label}"
                sess_lc.mkdir(mode=0o700)
                coord_lc = _SessionSlotCoordinator(threading.Event())
                coord_lc.register_slot(self._make_cm(st_lc), h_lc, root_lc)
                ok_lc, cstate_lc = self._run_finalize_case(coord_lc, sess_lc)
                self.assertFalse(ok_lc)
                self.assertFalse(cstate_lc["clean"])
                self.assertTrue(root_lc.exists())

    def test_owner_challenged_arrival_snapshot_receipt_gate_and_write_fence(self):
        # Deterministic Slice C R4 test: paused pre-receipt arrival -> 0 claims / 0 accepts;
        # fresh post-receipt arrival -> 1 claim / 1 accept; unsolicited/wrong-epoch/revoked -> 0 accepts.
        slot_root = self.root / "r4_slot"
        slot_root.mkdir(mode=0o700)
        inc = "inc_" + secrets.token_hex(16)
        job = _SessionJob(slot_root, inc)
        job.prepare(config_payload=None)
        self.addCleanup(job.revoke)
        job.activate()

        relay_id = "e" * 64
        gate = _OwnerChallengedReceiptGate(
            approved_scoped_id="google--personal", expected_relay_id=relay_id, job_incarnation=inc,
        )
        recorder: list[dict] = []
        tok = "tok-synth-" + "a" * 24
        broker = _SyntheticSlotBroker(
            socket_path=job.provider_socket,
            relay_proof=job.relay_proof,
            worker_token=tok,
            lease=job.lease,
            models=(SYNTHETIC_MODEL,),
            expected_port=8402,
            job_incarnation=inc,
            receipt_gate=gate,
            recorder=recorder,
        )
        broker.start()
        self.addCleanup(broker.close)

        req_body = json.dumps({
            "model": SYNTHETIC_MODEL, "stream": True, "store": False,
            "input": [{"role": "user", "content": PROOF_PROMPT}],
        }).encode("utf-8")
        turn_req = _make_http_request(method="POST", path="/v1/responses", port=8402, token=tok, body=req_body)

        # 1. Unsolicited stock GET /v1/models (no owner challenge) cannot authorize receipt.
        models_req = _make_http_request(method="GET", path="/v1/models", port=8402, token=tok)
        models_resp = _send_framed_uds(job.provider_socket, job.relay_proof, models_req)
        self.assertIn(b"200 OK", models_resp)
        self.assertEqual(broker.owner_probes_seen, [])

        # 2. Wrong relay/job/epoch owner delivery MUST be rejected.
        with self.assertRaises(ProofGateError):
            gate.deliver_owner_receipt(challenge="wrong", relay_id=relay_id, job_incarnation=inc, epoch=gate.epoch)
        with self.assertRaises(ProofGateError):
            gate.deliver_owner_receipt(challenge=gate.challenge_token, relay_id="0" * 64, job_incarnation=inc, epoch=gate.epoch)
        with self.assertRaises(ProofGateError):
            gate.deliver_owner_receipt(challenge=gate.challenge_token, relay_id=relay_id, job_incarnation=inc, epoch=gate.epoch + 9)

        # 3. Connect & snapshot arrival BEFORE owner receipt completes, pause before sending bytes,
        #    complete owner-challenged probe + receipt delivery, then resume paused request -> 0 claims / 0 accepts!
        pre_entered = threading.Event()
        release_pre = threading.Event()
        pre_result: list[bytes] = []

        t_pre = threading.Thread(
            target=lambda: pre_result.append(
                _send_framed_uds(
                    job.provider_socket, job.relay_proof, turn_req,
                    entered=pre_entered, release_send=release_pre,
                )
            ),
            daemon=True,
        )
        t_pre.start()
        self.assertTrue(pre_entered.wait(timeout=2.0))
        time.sleep(0.05)  # allow accept loop to snapshot arrival before receipt

        # Owner issues exact challenged GET /v1/models probe and delivers generation-stamped receipt.
        owner_probe = _make_http_request(
            method="GET", path="/v1/models", port=8402, token=tok,
            extra_headers={_OWNER_PROBE_HEADER: gate.challenge_token},
        )
        probe_resp = _send_framed_uds(job.provider_socket, job.relay_proof, owner_probe)
        self.assertIn(b"200 OK", probe_resp)
        self.assertEqual(broker.owner_probes_seen, [gate.challenge_token])
        self.assertEqual(len(broker.owner_probe_observations), 1)
        gen = gate.deliver_owner_receipt(
            challenge=gate.challenge_token,
            relay_id=relay_id,
            job_incarnation=inc,
            epoch=gate.epoch,
            probe_observation=broker.owner_probe_observations[-1],
        )
        self.assertEqual(gen, 1)

        # Resume paused pre-receipt request -> MUST fail closed with 403, 0 claims, 0 accepts!
        release_pre.set()
        t_pre.join(timeout=3.0)
        self.assertEqual(len(pre_result), 1)
        self.assertIn(b"403 Forbidden", pre_result[0])
        self.assertEqual((gate.claim_count, gate.accept_count, len(recorder)), (0, 0, 0))

        # 4. Subsequent fresh arrival AFTER receipt completion -> 1 claim, 1 accept, exact `ok` SSE!
        fresh_resp = _send_framed_uds(job.provider_socket, job.relay_proof, turn_req)
        self.assertIn(b"200 OK", fresh_resp)
        self.assertIn(b'"delta":"ok"', fresh_resp)
        self.assertEqual((gate.claim_count, gate.accept_count, len(recorder)), (1, 1, 1))

        # 5. Second turn after latch spent -> 403 proof_gate_spent, still 1 accept.
        second_resp = _send_framed_uds(job.provider_socket, job.relay_proof, turn_req)
        self.assertIn(b"403 Forbidden", second_resp)
        self.assertIn(b"proof_gate_spent", second_resp)
        self.assertEqual((gate.claim_count, gate.accept_count, len(recorder)), (1, 1, 1))

        # 6. Revocation inside write_fence between claim and accept produces 1 claim, 0 accepts, 0 sink writes.
        slot_root2 = self.root / "r4_slot_rev"
        slot_root2.mkdir(mode=0o700)
        inc2 = "inc_" + secrets.token_hex(16)
        job2 = _SessionJob(slot_root2, inc2)
        job2.prepare(config_payload=None)
        self.addCleanup(job2.revoke)
        job2.activate()
        gate2 = _OwnerChallengedReceiptGate(
            approved_scoped_id="google--personal", expected_relay_id=relay_id, job_incarnation=inc2,
        )
        rec2: list[dict] = []
        broker2 = _SyntheticSlotBroker(
            socket_path=job2.provider_socket,
            relay_proof=job2.relay_proof,
            worker_token=tok,
            lease=job2.lease,
            models=(SYNTHETIC_MODEL,),
            expected_port=8402,
            job_incarnation=inc2,
            receipt_gate=gate2,
            recorder=rec2,
            write_fence_hook=gate2.revoke,
        )
        broker2.start()
        self.addCleanup(broker2.close)
        probe2 = _make_http_request(
            method="GET", path="/v1/models", port=8402, token=tok,
            extra_headers={_OWNER_PROBE_HEADER: gate2.challenge_token},
        )
        self.assertIn(b"200 OK", _send_framed_uds(job2.provider_socket, job2.relay_proof, probe2))
        gate2.deliver_owner_receipt(
            challenge=gate2.challenge_token,
            relay_id=relay_id,
            job_incarnation=inc2,
            epoch=gate2.epoch,
            probe_observation=broker2.owner_probe_observations[-1],
        )
        rev_resp = _send_framed_uds(job2.provider_socket, job2.relay_proof, turn_req)
        self.assertIn(b"403 Forbidden", rev_resp)
        self.assertEqual((gate2.claim_count, gate2.accept_count, len(rec2)), (1, 0, 0))

    def test_accept_to_handler_pause_cannot_promote_pre_receipt_arrival(self):
        # Regression: a socket accepted BEFORE owner receipt delivery, then paused BEFORE
        # `_handle_peer()` runs until AFTER receipt delivery, MUST stay denied (0 claims / 0 accepts).
        slot_root = self.root / "r4_accept_pause"
        slot_root.mkdir(mode=0o700)
        inc = "inc_" + secrets.token_hex(16)
        job = _SessionJob(slot_root, inc)
        job.prepare(config_payload=None)
        self.addCleanup(job.revoke)
        job.activate()

        relay_id = "e" * 64
        gate = _OwnerChallengedReceiptGate(
            approved_scoped_id="google--personal", expected_relay_id=relay_id, job_incarnation=inc,
        )
        recorder: list[dict] = []
        tok = "tok-pause-" + "a" * 24
        paused_first = [False]
        entered_dispatch = threading.Event()
        release_dispatch = threading.Event()

        def pause_first_handler():
            if not paused_first[0]:
                paused_first[0] = True
                entered_dispatch.set()
                release_dispatch.wait(timeout=5.0)

        broker = _SyntheticSlotBroker(
            socket_path=job.provider_socket,
            relay_proof=job.relay_proof,
            worker_token=tok,
            lease=job.lease,
            models=(SYNTHETIC_MODEL,),
            expected_port=8402,
            job_incarnation=inc,
            receipt_gate=gate,
            recorder=recorder,
            before_dispatch_hook=pause_first_handler,
        )
        broker.start()
        self.addCleanup(broker.close)

        req_body = json.dumps({
            "model": SYNTHETIC_MODEL, "stream": True, "store": False,
            "input": [{"role": "user", "content": PROOF_PROMPT}],
        }).encode("utf-8")
        turn_req = _make_http_request(method="POST", path="/v1/responses", port=8402, token=tok, body=req_body)

        pre_result: list[bytes] = []
        t_pre = threading.Thread(
            target=lambda: pre_result.append(_send_framed_uds(job.provider_socket, job.relay_proof, turn_req)),
            daemon=True,
        )
        t_pre.start()
        self.assertTrue(entered_dispatch.wait(timeout=2.0))

        # Perform broker-observed probe and deliver owner receipt WHILE the pre-receipt socket is paused.
        owner_probe = _make_http_request(
            method="GET", path="/v1/models", port=8402, token=tok,
            extra_headers={_OWNER_PROBE_HEADER: gate.challenge_token},
        )
        self.assertIn(b"200 OK", _send_framed_uds(job.provider_socket, job.relay_proof, owner_probe))
        gate.deliver_owner_receipt(
            challenge=gate.challenge_token,
            relay_id=relay_id,
            job_incarnation=inc,
            epoch=gate.epoch,
            probe_observation=broker.owner_probe_observations[-1],
        )
        release_dispatch.set()
        t_pre.join(timeout=3.0)

        self.assertEqual(len(pre_result), 1)
        self.assertIn(b"403 Forbidden", pre_result[0])
        self.assertEqual((gate.claim_count, gate.accept_count, len(recorder)), (0, 0, 0))

        # Fresh post-receipt accepted socket still succeeds cleanly (1 claim / 1 accept).
        fresh_resp = _send_framed_uds(job.provider_socket, job.relay_proof, turn_req)
        self.assertIn(b"200 OK", fresh_resp)
        self.assertEqual((gate.claim_count, gate.accept_count, len(recorder)), (1, 1, 1))

    def test_slot_identity_binding_and_duplicate_registration_refused_before_podman(self):
        # 1. Duplicate slot_index registration MUST raise ProviderIntegrityError without clobbering slot 0.
        h0, st0, root0 = self._make_opaque_slot(slot_index=0)
        h0_dup, st0_dup, root0_dup = self._make_opaque_slot(slot_index=0)
        coord = _SessionSlotCoordinator(threading.Event())
        coord.register_slot(self._make_cm(st0), h0, root0)
        with self.assertRaises(ProviderIntegrityError) as dup_ctx:
            coord.register_slot(self._make_cm(st0_dup), h0_dup, root0_dup)
        self.assertEqual(dup_ctx.exception.code, "duplicate_slot_registration")
        self.assertIs(coord._slots[0].handle, h0)
        self.assertIsNone(coord.teardown_all(None))
        self.assertEqual(st0["cm_exits"], 1)

        # 2. Validly-typed opaque handle with mismatched slot_index / scoped_id / provider_label / port /
        #    escaped relay_paths MUST fail closed BEFORE any Podman call in `_open_single_admitted_slot`.
        outside_root = self.root / "outside_slot"
        for sub in ("source", "provider", "grant", "proof"):
            (outside_root / sub).mkdir(parents=True, mode=0o700)
        (outside_root / "proof" / "relay").write_bytes(b"p" * 32)
        escaped_paths = RelayMountPaths(
            source_dir=outside_root / "source",
            provider_socket=outside_root / "provider" / "provider.sock",
            grant_dir=outside_root / "grant",
            proof_file=outside_root / "proof" / "relay",
        )

        gg_spec = _spec_obj("google", "personal")
        pref = InstancePreflight(gg_spec, ReadinessState.READY, (SYNTHETIC_MODEL,), route_policy="sub")
        plan = ResolvedLaunchPlan(
            admitted=(pref,), excluded=(), initial_provider_id="google--personal",
            initial_model=SYNTHETIC_MODEL, ui_mode="mini", ui_source="--mini", acknowledged_digests={},
        )

        class _SubStr(str):
            pass

        class _SubInt(int):
            pass

        for label, bad_overrides in (
            ("wrong_slot_index", {"slot_index": 7}),
            ("bool_slot_index", {"slot_index": False}),
            ("wrong_scoped_id", {"scoped_id": "openai--personal"}),
            ("str_subclass_scoped_id", {"scoped_id": _SubStr("google--personal")}),
            ("wrong_provider_label", {"provider_label": "openai/personal"}),
            ("wrong_port", {"port": 8415}),
            ("int_subclass_port", {"port": _SubInt(8401)}),
            ("escaped_relay_paths", {"relay_paths": escaped_paths}),
        ):
            with self.subTest(mismatch=label):
                exited = [0]
                podman_calls: list[tuple] = []

                class _BadIdentityAdapter:
                    @contextmanager
                    def open_slot(self, _pf, *, slot_index, slot_root, port, worker_token, acknowledged_exposure_digest, on_revoke):
                        for sub in ("source", "provider", "grant", "proof"):
                            (slot_root / sub).mkdir(mode=0o700, exist_ok=True)
                        (slot_root / "proof" / "relay").write_bytes(b"p" * 32)
                        base_kwargs = {
                            "slot_index": slot_index,
                            "scoped_id": "google--personal",
                            "provider_label": "google/personal",
                            "port": port,
                            "job": object(),
                            "broker": object(),
                            "lease": object(),
                            "build_relay_args": lambda _s: ["create"],
                            "relay_paths": RelayMountPaths(
                                source_dir=slot_root / "source",
                                provider_socket=slot_root / "provider" / "provider.sock",
                                grant_dir=slot_root / "grant",
                                proof_file=slot_root / "proof" / "relay",
                            ),
                            "revoke_grant": lambda: None,
                            "close_broker": lambda: None,
                            "activate_route": lambda: None,
                            "route_state": lambda: "pending",
                            "is_revoked": lambda: False,
                            "has_active_clients": lambda: False,
                            "mark_relay_created": lambda: None,
                            "confirm_relay_removed": lambda: None,
                            "authorize_lease_release": lambda: None,
                            "deny_lease_release": lambda: None,
                            "bind_release_authority": lambda _pred: None,
                            "lease_release_confirmed": lambda: True,
                        }
                        base_kwargs.update(bad_overrides)
                        try:
                            yield SlotHandle(**base_kwargs)
                        finally:
                            exited[0] += 1

                coord_bad = _SessionSlotCoordinator(threading.Event())
                session_ctx = {
                    "spec": _make_launch_spec(),
                    "pod_id": "1" * 64,
                    "plan": plan,
                    "adapters": {"google": _BadIdentityAdapter()},
                    "coordinator": coord_bad,
                    "sidecars": [],
                    "started_relay_ids": [],
                    "stop_event": threading.Event(),
                    "proof_options": None,
                    "cutover": None,
                    "approved_scoped": None,
                    "slot_ports": {"google--personal": 8401},
                    "slot_tokens": {"google--personal": "tok-1"},
                }
                with (
                    patch.object(session_broker, "SHARED_TMP", str(self.root)),
                    patch.object(session_broker, "podman", side_effect=lambda *a, **_kw: podman_calls.append(a)),
                ):
                    with self.assertRaises(ProviderIntegrityError) as ctx:
                        session_broker._open_single_admitted_slot(0, pref, session_ctx)
                self.assertEqual(ctx.exception.code, "slot_identity_mismatch")
                self.assertEqual(podman_calls, [], f"{label} must never invoke Podman")
                self.assertEqual(exited[0], 1, f"{label} must cleanly exit slot context manager")

    @staticmethod
    def _make_real_openai_adapter_fixture(base_dir: Path):
        import pwd
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.profile_backend import ProfileBackend
        from oc_openai.session_adapter import OpenAISessionAdapter
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        backend = ProfileBackend(
            base_dir,
            reviewed=True,
            connection=lambda reg_dir: Connection(
                reg_dir,
                browser=FixtureBrowser(),
                verifier=FixtureVerifier(),
                transport=FixtureTransport(),
                host_probe=lambda: host,
            ),
        )
        backend.connect("personal")
        prof = backend.profiles.snapshot().active
        assert prof is not None
        adapter = OpenAISessionAdapter(backend)
        pref = adapter.preflight_instance(ProviderInstanceSpec("openai", "personal", True, "subscription"))
        return backend, adapter, pref, prof.directory, host

    def test_openai_adapter_paused_confirm_timeout_blocks_explicit_and_implicit_gc_release(self):
        # Regression (Finding 1a): real OpenAISessionAdapter + Connection store: pausing confirm_relay_removed
        # past join timeout MUST retain durable worker_leases across BOTH explicit exit AND Python GC finalization.
        import gc
        import pwd
        from dataclasses import replace
        from oc_openai.connection import Connection

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        orig_join = threading.Thread.join

        def _fast_join(thread_self, timeout=None):
            return orig_join(thread_self, timeout=0.05)

        with tempfile.TemporaryDirectory(prefix="oc-mix-gc-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            entered_confirm = threading.Event()
            release_confirm = threading.Event()
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            retire_threads_ref: list[threading.Thread] = []

            def _run_timed_out_scope() -> None:
                coord = _SessionSlotCoordinator(threading.Event())
                slot_cm = adapter.open_slot(
                    pref, slot_index=0, slot_root=slot_root, port=8401,
                    worker_token="tok-gc-" + "a" * 24,
                    acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
                )
                handle = slot_cm.__enter__()
                orig_confirm = handle.confirm_relay_removed
                assert orig_confirm is not None

                def slow_confirm_after_open():
                    # Execute the real confirm_relay_removed FIRST, then pause across join timeout!
                    orig_confirm()
                    entered_confirm.set()
                    release_confirm.wait(timeout=5.0)

                wrapped = replace(handle, confirm_relay_removed=slow_confirm_after_open)
                coord.register_slot(slot_cm, wrapped, slot_root, allow_legacy=True)
                coord.record_container("a" * 64, slot_index=0)
                handle.job.activate()
                with patch.object(session_broker, "_remove_container_verified"):
                    coord.on_revoke(0)
                    self.assertTrue(entered_confirm.wait(timeout=2.0))
                    with patch.object(threading.Thread, "join", _fast_join):
                        err = coord.teardown_all(None)
                    self.assertIsNotNone(err)
                    retire_threads_ref.extend(coord._retire_threads)
                    release_confirm.set()
                    for t in retire_threads_ref:
                        orig_join(t, timeout=2.0)
                self.assertFalse(coord._slots[0].lease_confirmed_released)

            _run_timed_out_scope()
            # Force implicit Python generator GC finalization of suspended `slot_cm`!
            gc.collect()
            gc.collect()

            fresh_conn = Connection(personal_dir, host_probe=lambda: host)
            self.assertTrue(
                fresh_conn.has_active_leases(),
                "implicit generator finalization released durable worker_leases after timed-out confirm!",
            )
            state_data = json.loads((personal_dir / "state.json").read_text(encoding="utf-8"))
            self.assertIn(slot_root.name, state_data.get("worker_leases", {}))

    def test_openai_adapter_final_close_failure_retains_durable_lease(self):
        # Regression (Finding 1b): if final broker.close() or job.revoke() raises during OpenAI adapter
        # context exit, durable worker_leases MUST remain retained ("retained_gate_closed").
        import pwd
        from oc_openai.connection import Connection

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        for fail_step in ("final_broker_close", "final_job_revoke"):
            with self.subTest(fail_step=fail_step):
                with tempfile.TemporaryDirectory(prefix="oc-mix-close-", dir=home) as home_raw:
                    home_scratch = Path(home_raw)
                    os.chmod(home_scratch, 0o700)
                    _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                        home_scratch / "profiles",
                    )
                    slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
                    self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
                    coord = _SessionSlotCoordinator(threading.Event())
                    slot_cm = adapter.open_slot(
                        pref, slot_index=0, slot_root=slot_root, port=8401,
                        worker_token="tok-cls-" + "a" * 24,
                        acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
                    )
                    handle = slot_cm.__enter__()
                    coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
                    coord.record_container("b" * 64, slot_index=0)
                    handle.job.activate()

                    if fail_step == "final_broker_close":
                        def fail_final_close():
                            raise RuntimeError("final broker close failed")

                        handle.broker.close = fail_final_close
                    else:
                        def fail_final_revoke():
                            raise RuntimeError("final job revoke failed")

                        handle.job.revoke = fail_final_revoke

                    with patch.object(session_broker, "_remove_container_verified"):
                        err = coord.teardown_all(None)
                    self.assertIsNotNone(err)
                    self.assertFalse(coord._slots[0].lease_confirmed_released)
                    self.assertFalse(handle.lease_release_confirmed())
                    fresh_conn = Connection(personal_dir, host_probe=lambda: host)
                    self.assertTrue(
                        fresh_conn.has_active_leases(),
                        f"{fail_step} must retain durable worker_leases!",
                    )
                    state_data = json.loads((personal_dir / "state.json").read_text(encoding="utf-8"))
                    self.assertIn(slot_root.name, state_data.get("worker_leases", {}))

    def test_non_openai_handle_with_session_job_cannot_bypass_required_hooks(self):
        # Regression (Finding 2): a declared non-OpenAI handle embedding `_SessionJob` and minimal
        # close/_revoked broker MUST NOT enter legacy OpenAI fallback or get false-positive release.
        from types import SimpleNamespace

        slot_root = self.root / "spoof_non_oa"
        slot_root.mkdir(mode=0o700)
        job = _SessionJob(slot_root, "inc_" + secrets.token_hex(16))
        job.prepare(config_payload=None)
        self.addCleanup(job.revoke)
        minimal_broker = SimpleNamespace(_revoked=threading.Event(), close=lambda: None)
        spoof_handle = SlotHandle(
            slot_index=0,
            scoped_id="google--personal",
            provider_label="google/personal",
            port=8402,
            job=job,
            broker=minimal_broker,
            lease=job.lease,
            build_relay_args=lambda _s: ["create"],
        )
        self.assertFalse(session_broker._is_legacy_openai_handle(spoof_handle))
        with self.assertRaises(ProviderIntegrityError) as ctx_val:
            session_broker._validate_slot_handle(spoof_handle, allow_legacy=False)
        self.assertEqual(ctx_val.exception.code, "incomplete_slot_handle")
        with self.assertRaises(ProviderIntegrityError) as ctx_rel:
            session_broker._slot_lease_release_confirmed(spoof_handle, allow_legacy=False)
        self.assertEqual(ctx_rel.exception.code, "incomplete_slot_handle")

        coord = _SessionSlotCoordinator(threading.Event())
        with self.assertRaises(ProviderIntegrityError) as ctx_reg:
            coord.register_slot(self._make_cm({"cm_exits": 0}), spoof_handle, slot_root, allow_legacy=False)
        self.assertEqual(ctx_reg.exception.code, "incomplete_slot_handle")

    def test_receipt_requires_broker_observation_rejects_function_call_and_splits_claim_accept_revoke(self):
        # Regression (Finding 3): receipt requires actual broker probe observation; synthesized
        # function_call/function_call_output payloads fail closed; controlled revoke between
        # claim_turn and accept_turn yields 1 claim, 0 accepts, 0 sink writes, and blocks retry.
        slot_root = self.root / "f3_slot"
        slot_root.mkdir(mode=0o700)
        inc = "inc_" + secrets.token_hex(16)
        job = _SessionJob(slot_root, inc)
        job.prepare(config_payload=None)
        self.addCleanup(job.revoke)
        job.activate()
        relay_id = "c" * 64
        tok = "tok-f3-" + "a" * 24

        before_write_calls: list[str] = []
        revoke_on_before_write = [False]

        def supervisor_before_write(*, claim_token: str, job_incarnation: str):
            before_write_calls.append(f"{claim_token}:{job_incarnation}")
            if revoke_on_before_write[0]:
                gate.revoke()

        gate = _OwnerChallengedReceiptGate(
            approved_scoped_id="google--personal",
            expected_relay_id=relay_id,
            job_incarnation=inc,
            supervisor_before_write=supervisor_before_write,
        )
        sink_records: list[dict] = []
        sink = _IndependentSyntheticSink(allowed_models=(SYNTHETIC_MODEL,), records=sink_records)
        broker = _SyntheticSlotBroker(
            socket_path=job.provider_socket,
            relay_proof=job.relay_proof,
            worker_token=tok,
            lease=job.lease,
            models=(SYNTHETIC_MODEL,),
            expected_port=8402,
            job_incarnation=inc,
            receipt_gate=gate,
            recorder=sink_records,
            sink=sink,
        )
        broker.start()
        self.addCleanup(broker.close)

        # 1. Issuing receipt with NO broker probe observation MUST fail closed!
        with self.assertRaises(ProofGateError) as no_probe_ctx:
            gate.deliver_owner_receipt(
                challenge=gate.challenge_token, relay_id=relay_id, job_incarnation=inc, epoch=gate.epoch,
            )
        self.assertEqual(no_probe_ctx.exception.args[0], "proof_probe_not_observed")

        # 2. Perform actual broker probe -> deliver receipt with exact broker observation nonce.
        probe_req = _make_http_request(
            method="GET", path="/v1/models", port=8402, token=tok,
            extra_headers={_OWNER_PROBE_HEADER: gate.challenge_token},
        )
        self.assertIn(b"200 OK", _send_framed_uds(job.provider_socket, job.relay_proof, probe_req))
        self.assertEqual(len(broker.owner_probe_observations), 1)
        with self.assertRaises(ProofGateError):
            gate.deliver_owner_receipt(
                challenge=gate.challenge_token, relay_id=relay_id, job_incarnation=inc,
                epoch=gate.epoch, probe_observation="forged-nonce",
            )
        gate.deliver_owner_receipt(
            challenge=gate.challenge_token, relay_id=relay_id, job_incarnation=inc,
            epoch=gate.epoch, probe_observation=broker.owner_probe_observations[-1],
        )

        # 3. Synthesized function_call / function_call_output in input MUST be rejected with 0 claims / 0 accepts.
        for bad_label, expected_status, bad_input in (
            ("function_call_output", b"403 Forbidden", [
                {"role": "user", "content": PROOF_PROMPT},
                {"type": "function_call_output", "call_id": "call_1", "output": "pwned"},
            ]),
            ("function_call", b"400 Bad Request", [
                {"role": "user", "content": PROOF_PROMPT},
                {"type": "function_call", "name": "bash", "arguments": "{}"},
            ]),
        ):
            with self.subTest(bad_payload=bad_label):
                bad_body = json.dumps({
                    "model": SYNTHETIC_MODEL, "stream": True, "store": False, "input": bad_input,
                }).encode("utf-8")
                bad_req = _make_http_request(method="POST", path="/v1/responses", port=8402, token=tok, body=bad_body)
                resp = _send_framed_uds(job.provider_socket, job.relay_proof, bad_req)
                self.assertIn(expected_status, resp)
                if expected_status == b"403 Forbidden":
                    self.assertIn(b"proof_tools_forbidden", resp)
                self.assertEqual((gate.claim_count, gate.accept_count, len(sink_records)), (0, 0, 0))

        # 4. Controlled revoke inside real supervisor `before_write` between claim_turn and accept_turn:
        #    claim_count == 1, accept_count == 0, 0 sink writes, and retry fails closed!
        revoke_on_before_write[0] = True
        good_body = json.dumps({
            "model": SYNTHETIC_MODEL, "stream": True, "store": False,
            "input": [{"role": "user", "content": PROOF_PROMPT}],
        }).encode("utf-8")
        good_req = _make_http_request(method="POST", path="/v1/responses", port=8402, token=tok, body=good_body)
        rev_resp = _send_framed_uds(job.provider_socket, job.relay_proof, good_req)
        self.assertIn(b"403 Forbidden", rev_resp)
        self.assertIn(b"proof_gate_revoked", rev_resp)
        self.assertEqual(len(before_write_calls), 1)
        self.assertEqual((gate.claim_count, gate.accept_count, len(sink_records)), (1, 0, 0))
        retry_resp = _send_framed_uds(job.provider_socket, job.relay_proof, good_req)
        self.assertIn(b"403 Forbidden", retry_resp)
        self.assertEqual((gate.claim_count, gate.accept_count, len(sink_records)), (1, 0, 0))

    def test_instance_lock_rejects_parent_sessions_dir_substitution_during_flock(self):
        # Regression (Finding 4): renaming/replacing `sessions` or its parent `state_dir` during
        # `fcntl.flock()` MUST fail closed instead of granting two live locks for one instance.
        orig_flock = session_broker.fcntl.flock
        for mode in ("replace_sessions", "replace_parent"):
            with self.subTest(substitution=mode):
                state_dir = self.root / f"lock_sub_{mode}"
                state_dir.mkdir(mode=0o700)
                swapped = [False]

                def flock_with_swap(fd, op):
                    res = orig_flock(fd, op)
                    if not swapped[0]:
                        swapped[0] = True
                        if mode == "replace_sessions":
                            (state_dir / "sessions").rename(state_dir / "sessions.old")
                            (state_dir / "sessions").mkdir(mode=0o700)
                        else:
                            renamed = self.root / f"lock_sub_{mode}_old"
                            state_dir.rename(renamed)
                            state_dir.mkdir(mode=0o700)
                            (state_dir / "sessions").mkdir(mode=0o700)
                    return res

                with patch.object(session_broker.fcntl, "flock", side_effect=flock_with_swap):
                    with self.assertRaises(RuntimeError) as ctx:
                        session_broker._open_instance_lock(state_dir, "demo")
                self.assertIn("changed during acquisition", str(ctx.exception))

    def test_deliberate_sibling_mcs_collision_rejected_before_podman_start(self):
        # Regression (Finding 5): deliberate sibling MCS collision MUST be rejected BEFORE `podman start`,
        # while a non-colliding relay verifies pre-start config + post-start process & mount labels.
        slot_root = self.root / "mcs_slot"
        for sub in ("source", "provider", "grant", "proof"):
            (slot_root / sub).mkdir(parents=True, mode=0o700)
        (slot_root / "proof" / "relay").write_bytes(b"p" * 32)
        paths = RelayMountPaths(
            source_dir=slot_root / "source",
            provider_socket=slot_root / "provider" / "provider.sock",
            grant_dir=slot_root / "grant",
            proof_file=slot_root / "proof" / "relay",
        )
        spec = _make_launch_spec(level="s0:c10,c20")
        pod_id = "1" * 64
        relay_id = "2" * 64
        sibling_id = "3" * 64

        def _make_inspect(level: str, *, include_caps: bool = False) -> dict:
            return {
                "Pod": pod_id,
                "Image": "sha256:" + spec["relay_image"],
                "ProcessLabel": f"system_u:system_r:container_t:{level}",
                "MountLabel": f"system_u:object_r:container_file_t:{level}",
                "EffectiveCaps": [] if include_caps else None,
                "HostConfig": {
                    "ReadonlyRootfs": True, "Privileged": False,
                    "IpcMode": "private", "PidMode": "private", "CgroupMode": "private",
                    "SecurityOpt": ["no-new-privileges", f"label=level:{level}"],
                },
                "Config": {"User": "0:0"},
                "Mounts": [
                    {"Destination": "/source", "Source": str(paths.source_dir), "Type": "bind", "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["nosuid", "nodev", "noexec"]},
                    {"Destination": "/provider", "Source": str(paths.provider_socket.parent), "Type": "bind", "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["nosuid", "nodev", "noexec"]},
                    {"Destination": "/grant", "Source": str(paths.grant_dir), "Type": "bind", "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["nosuid", "nodev", "noexec"]},
                    {"Destination": "/proof", "Source": str(paths.proof_file.parent), "Type": "bind", "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["nosuid", "nodev", "noexec"]},
                ],
            }

        # Case 1: colliding relay MCS (s0:c30,c40 matches sibling) -> fails BEFORE `podman start`!
        h_col, st_col, _ = self._make_opaque_slot(slot_index=0)
        h_col = SlotHandle(
            slot_index=0, scoped_id="google--personal", provider_label="google/personal", port=8402,
            job=object(), broker=object(), lease=object(), build_relay_args=lambda _s: ["create"],
            relay_paths=paths, revoke_grant=h_col.revoke_grant, close_broker=h_col.close_broker,
            activate_route=h_col.activate_route, route_state=lambda: "pending",
            is_revoked=lambda: False, has_active_clients=lambda: False,
            mark_relay_created=h_col.mark_relay_created, confirm_relay_removed=h_col.confirm_relay_removed,
            authorize_lease_release=h_col.authorize_lease_release, deny_lease_release=h_col.deny_lease_release,
            bind_release_authority=h_col.bind_release_authority,
            lease_release_confirmed=h_col.lease_release_confirmed,
        )
        coord = _SessionSlotCoordinator(threading.Event())
        coord.register_slot(self._make_cm(st_col), h_col, slot_root, allow_legacy=False)
        podman_calls: list[tuple] = []

        def fake_podman(*args, **_kw):
            podman_calls.append(args)
            if args[:1] == ("create",):
                return subprocess.CompletedProcess(args, 0, (relay_id + "\n").encode("ascii"), b"")
            if args[:2] == ("container", "inspect"):
                target = args[2]
                payload = _make_inspect("s0:c30,c40") if target in (relay_id, sibling_id) else _make_inspect("s0:c90,c91")
                return subprocess.CompletedProcess(args, 0, json.dumps([payload]).encode("ascii"), b"")
            return subprocess.CompletedProcess(args, 0, b"", b"")

        with (
            patch.object(session_broker, "podman", side_effect=fake_podman),
            patch.object(session_broker, "inspected", side_effect=lambda *a: _make_inspect("s0:c30,c40")),
        ):
            with self.assertRaises(RuntimeError) as col_ctx:
                session_broker._start_slot_relay_deferred(
                    spec, pod_id, h_col, coord, [sibling_id], [], threading.Event(),
                )
        self.assertIn("collided with sibling", str(col_ctx.exception))
        self.assertFalse(
            any(call[:1] == ("start",) for call in podman_calls),
            f"podman start MUST NOT run on pre-start sibling MCS collision: {podman_calls}",
        )

        # Case 2: non-colliding relay -> pre-start passes, podman start runs, post-start proc & mount labels verified!
        coord_ok = _SessionSlotCoordinator(threading.Event())
        coord_ok.register_slot(self._make_cm(st_col), h_col, slot_root, allow_legacy=False)
        ok_calls: list[tuple] = []
        getfattr_paths: list[str] = []

        def fake_podman_ok(*args, **_kw):
            ok_calls.append(args)
            if args[:1] == ("create",):
                return subprocess.CompletedProcess(args, 0, (relay_id + "\n").encode("ascii"), b"")
            if args[:2] == ("container", "inspect"):
                target = args[2]
                lvl = "s0:c50,c60" if target == relay_id else "s0:c30,c40"
                return subprocess.CompletedProcess(args, 0, json.dumps([_make_inspect(lvl, include_caps=True)]).encode("ascii"), b"")
            if args[:1] == ("exec",):
                return subprocess.CompletedProcess(args, 0, b"system_u:system_r:container_t:s0:c50,c60\0", b"")
            return subprocess.CompletedProcess(args, 0, b"", b"")

        def fake_host_output(*args, **_kw):
            getfattr_paths.append(args[-1])
            return b"system_u:object_r:container_file_t:s0:c50,c60\0"

        with (
            patch.object(session_broker, "podman", side_effect=fake_podman_ok),
            patch.object(session_broker, "inspected", side_effect=lambda *a: _make_inspect("s0:c50,c60", include_caps=True)),
            patch.object(session_broker, "host_output", side_effect=fake_host_output),
        ):
            started = session_broker._start_slot_relay_deferred(
                spec, pod_id, h_col, coord_ok, [sibling_id], [], threading.Event(),
            )
        self.assertEqual(started, relay_id)
        self.assertTrue(any(call[:1] == ("start",) for call in ok_calls))
        self.assertTrue(any(call[:1] == ("exec",) for call in ok_calls))
        self.assertEqual(len(getfattr_paths), 6)

    def test_store_commit_fenced_against_sticky_timeout_retains_durable_lease(self):
        # Regression (d5aaf07 residual #1): pausing after Connection's initial release_gate() check
        # and inside _store.locked() before os.replace across teardown_all()'s join timeout MUST
        # fail closed inside ConnectionState.write's commit_fence and retain durable worker_leases.
        import gc
        import pwd
        from oc_openai.connection import Connection

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        orig_join = threading.Thread.join

        def _fast_join(thread_self, timeout=None):
            return orig_join(thread_self, timeout=0.05)

        with tempfile.TemporaryDirectory(prefix="oc-mix-storefence-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            store_cls = type(pref.handle.conn._store)
            entered_write = threading.Event()
            release_write = threading.Event()
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            orig_write = store_cls.write
            paused_once = [False]

            def delayed_write(store_self, directory, record, *, before_commit=None):
                if before_commit is not None and not paused_once[0]:
                    paused_once[0] = True
                    entered_write.set()
                    release_write.wait(timeout=5.0)
                return orig_write(store_self, directory, record, before_commit=before_commit)

            def _run_delayed_store_commit() -> None:
                coord = _SessionSlotCoordinator(threading.Event())
                slot_cm = adapter.open_slot(
                    pref, slot_index=0, slot_root=slot_root, port=8401,
                    worker_token="tok-sf-" + "a" * 24,
                    acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
                )
                handle = slot_cm.__enter__()
                coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
                coord.record_container("a" * 64, slot_index=0)
                handle.job.activate()
                with (
                    patch.object(session_broker, "_remove_container_verified"),
                    patch.object(store_cls, "write", delayed_write),
                ):
                    coord.on_revoke(0)
                    self.assertTrue(entered_write.wait(timeout=2.0))
                    with patch.object(threading.Thread, "join", _fast_join):
                        err = coord.teardown_all(None)
                    self.assertIsNotNone(err)
                    release_write.set()
                    for t in list(coord._retire_threads):
                        orig_join(t, timeout=2.0)
                self.assertFalse(coord._slots[0].lease_confirmed_released)

            _run_delayed_store_commit()
            gc.collect()
            gc.collect()

            fresh_conn = Connection(personal_dir, host_probe=lambda: host)
            self.assertTrue(
                fresh_conn.has_active_leases(),
                "delayed store commit erased durable worker_leases after sticky timeout!",
            )
            state_data = json.loads((personal_dir / "state.json").read_text(encoding="utf-8"))
            self.assertIn(slot_root.name, state_data.get("worker_leases", {}))

    def test_pre_receipt_socket_paused_before_accept_cannot_inherit_receipt(self):
        # Regression (d5aaf07 residual #2): a pre-receipt client that connects while the accept
        # loop is paused BEFORE accept() MUST be drained/stamped under the shared transition fence
        # before receipt/verify flips true (both synthetic broker AND production SessionBroker).
        # Part A: Synthetic broker + _OwnerChallengedReceiptGate.
        slot_root = self.root / "pre_accept_synth"
        slot_root.mkdir(mode=0o700)
        inc = "inc_" + secrets.token_hex(16)
        job = _SessionJob(slot_root, inc)
        job.prepare(config_payload=None)
        self.addCleanup(job.revoke)
        job.activate()
        relay_id = "e" * 64
        tok = "tok-preacc-" + "a" * 24
        gate = _OwnerChallengedReceiptGate(
            approved_scoped_id="google--personal", expected_relay_id=relay_id, job_incarnation=inc,
        )
        recorder: list[dict] = []
        pause_enabled = [False]
        paused_before_accept = threading.Event()
        release_accept = threading.Event()

        def before_accept():
            if pause_enabled[0]:
                pause_enabled[0] = False
                paused_before_accept.set()
                release_accept.wait(timeout=5.0)

        broker = _SyntheticSlotBroker(
            socket_path=job.provider_socket,
            relay_proof=job.relay_proof,
            worker_token=tok,
            lease=job.lease,
            models=(SYNTHETIC_MODEL,),
            expected_port=8402,
            job_incarnation=inc,
            receipt_gate=gate,
            recorder=recorder,
            before_accept_hook=before_accept,
        )
        broker.start()
        self.addCleanup(broker.close)

        probe_req = _make_http_request(
            method="GET", path="/v1/models", port=8402, token=tok,
            extra_headers={_OWNER_PROBE_HEADER: gate.challenge_token},
        )
        self.assertIn(b"200 OK", _send_framed_uds(job.provider_socket, job.relay_proof, probe_req))
        obs = broker.owner_probe_observations[-1]

        req_body = json.dumps({
            "model": SYNTHETIC_MODEL, "stream": True, "store": False,
            "input": [{"role": "user", "content": PROOF_PROMPT}],
        }).encode("utf-8")
        turn_req = _make_http_request(method="POST", path="/v1/responses", port=8402, token=tok, body=req_body)

        pause_enabled[0] = True
        pre_res: list[bytes] = []
        t_pre = threading.Thread(
            target=lambda: pre_res.append(_send_framed_uds(job.provider_socket, job.relay_proof, turn_req)),
            daemon=True,
        )
        t_pre.start()
        self.assertTrue(paused_before_accept.wait(timeout=2.0))

        # Deliver receipt WHILE accept_loop is paused BEFORE calling accept()!
        gate.deliver_owner_receipt(
            challenge=gate.challenge_token, relay_id=relay_id, job_incarnation=inc,
            epoch=gate.epoch, probe_observation=obs,
        )
        release_accept.set()
        t_pre.join(timeout=3.0)
        self.assertEqual(len(pre_res), 1)
        self.assertIn(b"403 Forbidden", pre_res[0])
        self.assertEqual((gate.claim_count, gate.accept_count, len(recorder)), (0, 0, 0))

        # Fresh post-receipt socket succeeds 1/1.
        fresh_resp = _send_framed_uds(job.provider_socket, job.relay_proof, turn_req)
        self.assertIn(b"200 OK", fresh_resp)
        self.assertEqual((gate.claim_count, gate.accept_count, len(recorder)), (1, 1, 1))

        # Part B: Production SessionBroker + ProofGate paused BEFORE accept across mark_relay_verified.
        import pwd
        from types import SimpleNamespace
        from oc_openai.proof_gate import ProofGate, _normalize_instructions, compute_exposure_history_digest
        from oc_openai.session_broker import SessionBroker, SessionPolicy

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        home_td = self.enterContext(tempfile.TemporaryDirectory(prefix="oc-mix-preacc-", dir=home))
        os.chmod(home_td, 0o700)
        sb_root = self.root / "pre_accept_prod"
        sb_root.mkdir(mode=0o700)
        exp_dir = Path(home_td) / "pre_accept_exp"
        exp_dir.mkdir(mode=0o700)
        ev_dir = Path(home_td) / "pre_accept_ev"
        ev_dir.mkdir(mode=0o700)
        sb_inc = "inc_" + secrets.token_hex(16)
        sb_job = _SessionJob(sb_root, sb_inc)
        sb_job.prepare(config_payload=None)
        self.addCleanup(sb_job.revoke)
        sb_job.activate()
        instr = (
            "Today's date: Thu Nov 26 2026\n"
            "  Working directory: /sandbox/workspace\n"
            "  Workspace root folder: /sandbox/workspace\n"
        )
        norm_instr = _normalize_instructions(instr, expected_cwd="workspace")
        assert norm_instr is not None
        instr_sha = sha256(norm_instr.encode("utf-8")).hexdigest()
        approval = ProofApproval(
            run_id=secrets.token_hex(16), instance_label="personal", scoped_provider_id="openai--personal",
            approved_model="gpt-6.2-sol", ui_mode="mini", cwd="workspace",
            selection_epoch="ep-1", credential_generation=1,
            history_digest_all_12_files=compute_exposure_history_digest(exp_dir),
            profile_directory=str(exp_dir), client_id="client-1",
        )
        pg = ProofGate(
            approval, evidence_dir=ev_dir, exposure_dir=exp_dir,
            check_owner_alive=lambda: None, expected_instructions_sha256=instr_sha,
        )
        pg.bind_incarnation(sb_inc, sb_job.generation)
        pg.arm(observed_row="openai--personal/gpt-6.2-sol", observed_screen_digest="a" * 64)

        class _OkConn:
            def require_active(self, _binding):
                return None

            @contextmanager
            def interactive_responses(self, _binding, body, before_write, **kwargs):
                write_fence = kwargs.get("write_fence")
                if write_fence is not None:
                    with write_fence():
                        before_write()
                else:
                    before_write()
                yield iter((
                    {"type": "response.output_text.delta", "delta": "ok"},
                    {
                        "type": "response.completed",
                        "response": {
                            "status": "completed",
                            "model": body["model"],
                            "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "ok"}]}],
                            "usage": {"input_tokens": 4, "output_tokens": 1, "total_tokens": 5},
                        },
                    },
                ))

        sb_tok = "tok-sbacc-" + "a" * 24
        sb = SessionBroker(
            socket_path=sb_job.provider_socket,
            relay_proof=sb_job.relay_proof,
            worker_token=sb_tok,
            lease=sb_job.lease,
            connection=_OkConn(),
            binding=SimpleNamespace(generation=1),
            models=("gpt-6.2-sol",),
            profile_label="personal",
            expected_port=8401,
            policy=SessionPolicy(exposure_dir=exp_dir, proof_gate=pg, job_incarnation=sb_inc),
        )
        orig_accept_one = sb._accept_one_serialized
        sb_paused = threading.Event()
        sb_release = threading.Event()
        sb_armed_pause = [True]

        def paused_accept_one():
            if sb_armed_pause[0]:
                sb_armed_pause[0] = False
                sb_paused.set()
                sb_release.wait(timeout=5.0)
            return orig_accept_one()

        sb._accept_one_serialized = paused_accept_one
        sb.start()
        self.addCleanup(sb.close)

        sb_body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "instructions": instr,
            "input": [{"role": "user", "content": [{"type": "input_text", "text": PROOF_PROMPT}]}],
        }).encode("utf-8")
        sb_req = _make_http_request(method="POST", path="/v1/responses", port=8401, token=sb_tok, body=sb_body)
        sb_pre: list[bytes] = []
        t_sb = threading.Thread(
            target=lambda: sb_pre.append(_send_framed_uds(sb_job.provider_socket, sb_job.relay_proof, sb_req)),
            daemon=True,
        )
        t_sb.start()
        self.assertTrue(sb_paused.wait(timeout=2.0))
        # Transition relay_verified WHILE accept_loop is paused BEFORE accept()!
        pg.mark_relay_verified("b" * 64)
        sb_release.set()
        t_sb.join(timeout=3.0)
        self.assertEqual(len(sb_pre), 1)
        self.assertIn(b"403 Forbidden", sb_pre[0])
        self.assertIn(b"proof_gate_relay_unverified", sb_pre[0])
        self.assertEqual(pg.admitted_writes, 0)

        # Fresh post-verify connection succeeds cleanly.
        sb_ok = _send_framed_uds(sb_job.provider_socket, sb_job.relay_proof, sb_req)
        self.assertIn(b"200 OK", sb_ok)
        self.assertEqual(pg.admitted_writes, 1)

    def test_kernel_enqueue_between_drain_and_publication_rejected_by_listener_rotation(self):
        # Regression (R3 P2 #1): a client connecting in the kernel AFTER transition enters
        # _accept_fence / during evidence fsync and BEFORE atomic UDS listener rotation (os.replace)
        # MUST land on the pre-publication listener, be stamped pre-publication, and produce 0 accepts.
        # Part A: Synthetic broker + _OwnerChallengedReceiptGate.
        slot_root = self.root / "kernel_enq_synth"
        slot_root.mkdir(mode=0o700)
        inc = "inc_" + secrets.token_hex(16)
        job = _SessionJob(slot_root, inc)
        job.prepare(config_payload=None)
        self.addCleanup(job.revoke)
        job.activate()
        relay_id = "e" * 64
        tok = "tok-kenq-" + "a" * 24
        gate = _OwnerChallengedReceiptGate(
            approved_scoped_id="google--personal", expected_relay_id=relay_id, job_incarnation=inc,
        )
        recorder: list[dict] = []
        broker = _SyntheticSlotBroker(
            socket_path=job.provider_socket,
            relay_proof=job.relay_proof,
            worker_token=tok,
            lease=job.lease,
            models=(SYNTHETIC_MODEL,),
            expected_port=8402,
            job_incarnation=inc,
            receipt_gate=gate,
            recorder=recorder,
        )
        broker.start()
        self.addCleanup(broker.close)
        probe_req = _make_http_request(
            method="GET", path="/v1/models", port=8402, token=tok,
            extra_headers={_OWNER_PROBE_HEADER: gate.challenge_token},
        )
        self.assertIn(b"200 OK", _send_framed_uds(job.provider_socket, job.relay_proof, probe_req))
        obs = broker.owner_probe_observations[-1]

        req_body = json.dumps({
            "model": SYNTHETIC_MODEL, "stream": True, "store": False,
            "input": [{"role": "user", "content": PROOF_PROMPT}],
        }).encode("utf-8")
        turn_req = _make_http_request(method="POST", path="/v1/responses", port=8402, token=tok, body=req_body)

        enqueued_sock: list[socket.socket] = []

        def enqueue_during_publication():
            # Connect directly into kernel listen backlog AFTER _receipt_delivered flipped True
            # and BEFORE atomic UDS os.replace()!
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(job.provider_socket))
            enqueued_sock.append(client)

        gate.deliver_owner_receipt(
            challenge=gate.challenge_token, relay_id=relay_id, job_incarnation=inc,
            epoch=gate.epoch, probe_observation=obs,
            before_rotate_hook=enqueue_during_publication,
        )
        self.assertEqual(len(enqueued_sock), 1)
        client = enqueued_sock[0]
        try:
            client.settimeout(3.0)
            frame = relay_mod.PROOF_PREFIX + job.relay_proof + REQUEST_LENGTH.pack(len(turn_req)) + turn_req
            client.sendall(frame)
            resp = client.recv(4096)
        finally:
            client.close()
        self.assertIn(b"403 Forbidden", resp)
        self.assertEqual((gate.claim_count, gate.accept_count, len(recorder)), (0, 0, 0))

        # Fresh post-publication connection lands on rotated listener and succeeds 1/1.
        post_resp = _send_framed_uds(job.provider_socket, job.relay_proof, turn_req)
        self.assertIn(b"200 OK", post_resp)
        self.assertEqual((gate.claim_count, gate.accept_count, len(recorder)), (1, 1, 1))

        # Part B: Production SessionBroker + ProofGate connecting inside _atomic_fsync_json during mark_relay_verified.
        import pwd
        from types import SimpleNamespace
        from oc_openai import proof_gate as pg_mod
        from oc_openai.proof_gate import ProofGate, _normalize_instructions, compute_exposure_history_digest
        from oc_openai.session_broker import SessionBroker, SessionPolicy

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        home_td = self.enterContext(tempfile.TemporaryDirectory(prefix="oc-mix-kenq-", dir=home))
        os.chmod(home_td, 0o700)
        sb_root = self.root / "kernel_enq_prod"
        sb_root.mkdir(mode=0o700)
        exp_dir = Path(home_td) / "exp"
        exp_dir.mkdir(mode=0o700)
        ev_dir = Path(home_td) / "ev"
        ev_dir.mkdir(mode=0o700)
        sb_inc = "inc_" + secrets.token_hex(16)
        sb_job = _SessionJob(sb_root, sb_inc)
        sb_job.prepare(config_payload=None)
        self.addCleanup(sb_job.revoke)
        sb_job.activate()
        instr = (
            "Today's date: Thu Nov 26 2026\n"
            "  Working directory: /sandbox/workspace\n"
            "  Workspace root folder: /sandbox/workspace\n"
        )
        norm_instr = _normalize_instructions(instr, expected_cwd="workspace")
        assert norm_instr is not None
        approval = ProofApproval(
            run_id=secrets.token_hex(16), instance_label="personal", scoped_provider_id="openai--personal",
            approved_model="gpt-6.2-sol", ui_mode="mini", cwd="workspace",
            selection_epoch="ep-1", credential_generation=1,
            history_digest_all_12_files=compute_exposure_history_digest(exp_dir),
            profile_directory=str(exp_dir), client_id="client-1",
        )
        pg = ProofGate(
            approval, evidence_dir=ev_dir, exposure_dir=exp_dir,
            check_owner_alive=lambda: None,
            expected_instructions_sha256=sha256(norm_instr.encode("utf-8")).hexdigest(),
        )
        pg.bind_incarnation(sb_inc, sb_job.generation)
        pg.arm(observed_row="openai--personal/gpt-6.2-sol", observed_screen_digest="a" * 64)

        class _OkConn:
            def require_active(self, _binding):
                return None

            @contextmanager
            def interactive_responses(self, _binding, body, before_write, **kwargs):
                wf = kwargs.get("write_fence")
                if wf is not None:
                    with wf():
                        before_write()
                else:
                    before_write()
                yield iter((
                    {"type": "response.output_text.delta", "delta": "ok"},
                    {"type": "response.completed", "response": {"status": "completed", "model": body["model"], "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "ok"}]}], "usage": {"input_tokens": 4, "output_tokens": 1, "total_tokens": 5}}},
                ))

        sb_tok = "tok-sbkenq-" + "a" * 24
        sb = SessionBroker(
            socket_path=sb_job.provider_socket,
            relay_proof=sb_job.relay_proof,
            worker_token=sb_tok,
            lease=sb_job.lease,
            connection=_OkConn(),
            binding=SimpleNamespace(generation=1),
            models=("gpt-6.2-sol",),
            profile_label="personal",
            expected_port=8401,
            policy=SessionPolicy(exposure_dir=exp_dir, proof_gate=pg, job_incarnation=sb_inc),
        )
        sb.start()
        self.addCleanup(sb.close)

        orig_fsync_json = pg_mod._atomic_fsync_json
        sb_mid_sock: list[socket.socket] = []

        def fsync_with_mid_enqueue(path, payload, *, exclusive=False):
            orig_fsync_json(path, payload, exclusive=exclusive)
            if payload.get("relay_verified") is True and not sb_mid_sock:
                c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                c.connect(str(sb_job.provider_socket))
                sb_mid_sock.append(c)

        with patch.object(pg_mod, "_atomic_fsync_json", side_effect=fsync_with_mid_enqueue):
            pg.mark_relay_verified("b" * 64)

        self.assertEqual(len(sb_mid_sock), 1)
        sb_body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "instructions": instr,
            "input": [{"role": "user", "content": [{"type": "input_text", "text": PROOF_PROMPT}]}],
        }).encode("utf-8")
        sb_req = _make_http_request(method="POST", path="/v1/responses", port=8401, token=sb_tok, body=sb_body)
        c_mid = sb_mid_sock[0]
        try:
            c_mid.settimeout(3.0)
            c_mid.sendall(relay_mod.PROOF_PREFIX + sb_job.relay_proof + REQUEST_LENGTH.pack(len(sb_req)) + sb_req)
            mid_resp = c_mid.recv(4096)
        finally:
            c_mid.close()
        self.assertIn(b"403 Forbidden", mid_resp)
        self.assertIn(b"proof_gate_relay_unverified", mid_resp)
        self.assertEqual(pg.admitted_writes, 0)

        sb_post = _send_framed_uds(sb_job.provider_socket, sb_job.relay_proof, sb_req)
        self.assertIn(b"200 OK", sb_post)
        self.assertEqual(pg.admitted_writes, 1)

    def test_inflight_os_replace_timeout_stays_bounded_and_persists_effective_hold(self):
        # Regression (R3 P2 #2): pausing INSIDE os.replace() while _commit_lock and state.lock are held
        # across teardown_all()'s join timeout MUST NOT block teardown beyond its bound, and MUST
        # persist an effective durable hold so fresh Connection readers see active leases & refuse new ones
        # even after os.replace() resumes and removes worker_leases from state.json.
        import pwd
        from oc_openai import connection_state as cs_mod
        from oc_openai.connection import Connection, ConnectionError as ConnError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        orig_join = threading.Thread.join

        def _fast_join(thread_self, timeout=None):
            return orig_join(thread_self, timeout=0.05)

        # Case 1: paused inside os.replace() across timeout.
        with tempfile.TemporaryDirectory(prefix="oc-mix-inflight-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            entered_replace = threading.Event()
            release_replace = threading.Event()
            orig_replace = cs_mod.os.replace
            paused_once = [False]

            def slow_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                if dst == cs_mod._STATE_FILE and not paused_once[0]:
                    paused_once[0] = True
                    entered_replace.set()
                    release_replace.wait(timeout=5.0)
                return orig_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            coord = _SessionSlotCoordinator(threading.Event())
            slot_cm = adapter.open_slot(
                pref, slot_index=0, slot_root=slot_root, port=8401,
                worker_token="tok-inf-" + "a" * 24,
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
            coord.record_container("a" * 64, slot_index=0)
            handle.job.activate()

            with (
                patch.object(session_broker, "_remove_container_verified"),
                patch.object(cs_mod.os, "replace", side_effect=slow_replace),
            ):
                coord.on_revoke(0)
                self.assertTrue(entered_replace.wait(timeout=2.0))
                t0 = time.monotonic()
                with patch.object(threading.Thread, "join", _fast_join):
                    err = coord.teardown_all(None)
                elapsed = time.monotonic() - t0
                # Teardown MUST stay strictly bounded (never blocking synchronously on _commit_lock!).
                self.assertLess(elapsed, 1.0, f"teardown blocked on in-flight commit_lock ({elapsed:.2f}s)")
                self.assertIsNotNone(err)
                # Now allow os.replace() to finish removing worker_leases from state.json.
                release_replace.set()
                for t in list(coord._retire_threads):
                    orig_join(t, timeout=2.0)

            self.assertFalse(coord._slots[0].lease_confirmed_released)
            self.assertFalse(handle.lease_release_confirmed())
            coord.remove_slot_roots(require_confirmed_leases=True)
            self.assertTrue(slot_root.exists(), "slot_root must be retained after uncertain in-flight commit")
            # Even though state.json no longer has worker_leases, fresh Connection reader MUST see hold!
            fresh_conn = Connection(personal_dir, host_probe=lambda: host)
            self.assertTrue(fresh_conn.has_active_leases(), "fresh store reader must see effective durable hold!")
            next_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(next_root, ignore_errors=True))
            next_job = _SessionJob(next_root, "inc_" + secrets.token_hex(16))
            next_job.prepare(config_payload=None)
            self.addCleanup(next_job.revoke)
            with self.assertRaises(ConnError) as lease_err:
                with fresh_conn.session_lease(pref.handle.binding, next_job):
                    pass
            self.assertEqual(lease_err.exception.code, "managed_retirement_incomplete")

        # Case 2: os.fsync(directory) fails after os.replace() -> fresh store reader still sees effective hold!
        with tempfile.TemporaryDirectory(prefix="oc-mix-dirsync-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            coord = _SessionSlotCoordinator(threading.Event())
            slot_cm = adapter.open_slot(
                pref, slot_index=0, slot_root=slot_root, port=8401,
                worker_token="tok-ds-" + "a" * 24,
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
            coord.record_container("b" * 64, slot_index=0)
            handle.job.activate()
            orig_fsync = cs_mod.os.fsync
            fsync_count = [0]

            def fail_dir_fsync(fd):
                fsync_count[0] += 1
                # First fsync is the temp state file; second is directory fsync after os.replace.
                if fsync_count[0] == 2:
                    raise OSError("simulated dir fsync failure")
                return orig_fsync(fd)

            with (
                patch.object(session_broker, "_remove_container_verified"),
                patch.object(cs_mod.os, "fsync", side_effect=fail_dir_fsync),
            ):
                err = coord.teardown_all(None)
            self.assertIsNotNone(err)
            self.assertFalse(coord._slots[0].lease_confirmed_released)
            self.assertFalse(handle.lease_release_confirmed())
            fresh_conn = Connection(personal_dir, host_probe=lambda: host)
            self.assertTrue(fresh_conn.has_active_leases())

        # Case 3: teardown times out while worker is paused inside os.fsync(directory) AFTER os.replace()
        # completed, and then os.fsync(directory) returns cleanly -> fresh reader MUST still see durable hold!
        with tempfile.TemporaryDirectory(prefix="oc-mix-dirsync-to-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            coord = _SessionSlotCoordinator(threading.Event())
            slot_cm = adapter.open_slot(
                pref, slot_index=0, slot_root=slot_root, port=8401,
                worker_token="tok-dst-" + "a" * 24,
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
            coord.record_container("c" * 64, slot_index=0)
            handle.job.activate()
            entered_dir_fsync = threading.Event()
            release_dir_fsync = threading.Event()
            orig_fsync = cs_mod.os.fsync
            orig_join = threading.Thread.join
            fsync_count = [0]

            def slow_dir_fsync(fd):
                fsync_count[0] += 1
                if fsync_count[0] == 2:
                    entered_dir_fsync.set()
                    release_dir_fsync.wait(timeout=5.0)
                return orig_fsync(fd)

            try:
                with (
                    patch.object(session_broker, "_remove_container_verified"),
                    patch.object(cs_mod.os, "fsync", side_effect=slow_dir_fsync),
                ):
                    coord.on_revoke(0)
                    self.assertTrue(entered_dir_fsync.wait(timeout=2.0))
                    t0 = time.monotonic()
                    with patch.object(threading.Thread, "join", _fast_join):
                        err = coord.teardown_all(None)
                    elapsed = time.monotonic() - t0
                self.assertLess(elapsed, 1.0, "teardown must remain bounded during slow dir fsync")
                self.assertIsNotNone(err)
            finally:
                release_dir_fsync.set()
                for t in list(coord._retire_threads):
                    orig_join(t, timeout=2.0)

            self.assertFalse(coord._slots[0].lease_confirmed_released)
            self.assertFalse(handle.lease_release_confirmed())
            fresh_conn = Connection(personal_dir, host_probe=lambda: host)
            self.assertTrue(fresh_conn.has_active_leases(), "fresh store reader must see hold after post-replace timeout!")
            next_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(next_root, ignore_errors=True))
            next_job = _SessionJob(next_root, "inc_" + secrets.token_hex(16))
            next_job.prepare(config_payload=None)
            self.addCleanup(next_job.revoke)
            with self.assertRaises(ConnError) as lease_err:
                with fresh_conn.session_lease(pref.handle.binding, next_job):
                    pass
            self.assertEqual(lease_err.exception.code, "managed_retirement_incomplete")

    def test_failed_listener_rotation_rolls_back_publication_and_rejects_queued_socket(self):
        # Regression: if UDS listener rotation fails (e.g., os.replace raises OSError) during
        # deliver_owner_receipt / ProofGate.arm / ProofGate.mark_relay_verified, admission state MUST
        # roll back under _accept_fence so queued pre-transition sockets on old_listener are rejected.
        import pwd
        from types import SimpleNamespace
        from oc_openai import proof_gate as pg_mod
        from oc_openai.proof_gate import ProofGate, _normalize_instructions, compute_exposure_history_digest
        from oc_openai.session_broker import SessionBroker, SessionPolicy

        # Part A: synthetic _OwnerChallengedReceiptGate.deliver_owner_receipt
        slot_root = self.root / "rot_fail_synth"
        slot_root.mkdir(mode=0o700)
        inc = "inc_" + secrets.token_hex(16)
        job = _SessionJob(slot_root, inc)
        job.prepare(config_payload=None)
        self.addCleanup(job.revoke)
        job.activate()
        tok = "tok-rf-" + "a" * 24
        recorder: list[dict] = []
        gate = _OwnerChallengedReceiptGate(
            approved_scoped_id="google--personal", expected_relay_id="a" * 64, job_incarnation=inc,
        )
        broker = _SyntheticSlotBroker(
            socket_path=job.provider_socket, relay_proof=job.relay_proof, worker_token=tok,
            lease=job.lease, models=(SYNTHETIC_MODEL,), expected_port=8401,
            job_incarnation=inc, receipt_gate=gate, recorder=recorder,
        )
        broker.start()
        self.addCleanup(broker.close)
        probe_req = _make_http_request(
            method="GET", path="/v1/models", port=8401, token=tok,
            extra_headers={_OWNER_PROBE_HEADER: gate.challenge_token},
        )
        self.assertIn(b"200 OK", _send_framed_uds(job.provider_socket, job.relay_proof, probe_req))
        probe_obs = broker.owner_probe_observations[-1]
        turn_body = json.dumps({
            "model": SYNTHETIC_MODEL, "stream": True, "store": False,
            "input": [{"role": "user", "content": PROOF_PROMPT}],
        }).encode("utf-8")
        turn_req = _make_http_request(method="POST", path="/v1/responses", port=8401, token=tok, body=turn_body)
        queued_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        queued_client.settimeout(5.0)
        self.addCleanup(queued_client.close)

        def queue_and_fail_replace(_src, _dst):
            queued_client.connect(str(job.provider_socket))
            raise OSError("simulated os.replace failure")

        with patch.object(os, "replace", side_effect=queue_and_fail_replace):
            with self.assertRaises(OSError):
                gate.deliver_owner_receipt(
                    challenge=gate.challenge_token, relay_id="a" * 64,
                    job_incarnation=inc, epoch=gate.epoch, probe_observation=probe_obs,
                )
        self.assertFalse(gate._receipt_delivered)
        self.assertTrue(gate._revoked)
        self.assertTrue(broker.is_revoked())
        resp = b""
        with suppress(OSError):
            queued_client.sendall(relay_mod.PROOF_PREFIX + job.relay_proof + REQUEST_LENGTH.pack(len(turn_req)) + turn_req)
            while True:
                chunk = queued_client.recv(4096)
                if not chunk:
                    break
                resp += chunk
        self.assertNotIn(b"200 OK", resp)
        self.assertEqual(recorder, [])

        # Part B: production ProofGate.arm() and ProofGate.mark_relay_verified() rollback on failed rotation
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        home_td = self.enterContext(tempfile.TemporaryDirectory(prefix="oc-mix-rotf-", dir=home))
        os.chmod(home_td, 0o700)
        exp_dir = Path(home_td) / "exp"
        exp_dir.mkdir(mode=0o700)
        ev_dir = Path(home_td) / "ev"
        ev_dir.mkdir(mode=0o700)
        pg_root = self.root / "rot_fail_prod_slot"
        pg_root.mkdir(mode=0o700)
        pg_inc = "inc_" + secrets.token_hex(16)
        pg_job = _SessionJob(pg_root, pg_inc)
        pg_job.prepare(config_payload=None)
        self.addCleanup(pg_job.revoke)
        pg_job.activate()
        instr = (
            "Today's date: Thu Nov 26 2026\n"
            "  Working directory: /sandbox/workspace\n"
            "  Workspace root folder: /sandbox/workspace\n"
        )
        norm_instr = _normalize_instructions(instr, expected_cwd="workspace")
        assert norm_instr is not None
        approval = ProofApproval(
            run_id=secrets.token_hex(16), instance_label="personal",
            scoped_provider_id="openai--personal", approved_model="gpt-6.2-sol",
            ui_mode="mini", cwd="workspace", selection_epoch="ep1", credential_generation=1,
            history_digest_all_12_files=compute_exposure_history_digest(exp_dir),
            profile_directory=str(exp_dir), client_id="client-1",
        )
        pg = ProofGate(
            approval, evidence_dir=ev_dir, exposure_dir=exp_dir,
            check_owner_alive=lambda: None,
            expected_instructions_sha256=sha256(norm_instr.encode("utf-8")).hexdigest(),
        )
        pg.bind_incarnation(pg_inc, pg_job.generation)
        prod_writes: list[dict] = []

        class _StubConn:
            def require_active(self, _binding):
                return None

            @contextmanager
            def interactive_responses(self, _binding, body, before_write, **kwargs):
                before_write()
                prod_writes.append(body)
                yield iter(())

        sb = SessionBroker(
            socket_path=pg_job.provider_socket, relay_proof=pg_job.relay_proof,
            worker_token=tok, lease=pg_job.lease, connection=_StubConn(),
            binding=SimpleNamespace(generation=1), models=("gpt-6.2-sol",),
            profile_label="personal", expected_port=8401,
            policy=SessionPolicy(
                proof_gate=pg, job_incarnation=pg_inc,
                exposure_dir=exp_dir,
                acknowledged_exposure_digest=approval.history_digest_all_12_files,
            ),
        )
        sb.start()
        self.addCleanup(sb.close)
        prod_body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "instructions": instr, "input": [{"role": "user", "content": PROOF_PROMPT}],
        }).encode("utf-8")
        prod_req = _make_http_request(method="POST", path="/v1/responses", port=8401, token=tok, body=prod_body)
        q_arm = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        q_arm.settimeout(5.0)
        self.addCleanup(q_arm.close)
        orig_replace = session_broker.os.replace

        def fail_broker_replace(src, dst):
            if str(dst) == str(pg_job.provider_socket):
                q_arm.connect(str(pg_job.provider_socket))
                raise OSError("simulated broker os.replace failure")
            return orig_replace(src, dst)

        with patch.object(session_broker.os, "replace", side_effect=fail_broker_replace):
            with self.assertRaises(OSError):
                pg.arm(observed_row="openai--personal/gpt-6.2-sol", observed_screen_digest="2" * 64)
        self.assertEqual(pg.snapshot_arrival().state, pg_mod.STATE_SPENT)
        self.assertIsNone(pg.snapshot_arrival().arm_nonce)
        self.assertTrue(sb._revoked.is_set(), "failed arm rotation must revoke broker listener")
        with suppress(OSError):
            q_arm.sendall(relay_mod.PROOF_PREFIX + pg_job.relay_proof + REQUEST_LENGTH.pack(len(prod_req)) + prod_req)
            arm_resp = q_arm.recv(4096)
            self.assertNotIn(b"200 OK", arm_resp)
        self.assertEqual(prod_writes, [])

        # Fresh ProofGate + SessionBroker: let arm() succeed, then fail mark_relay_verified() rotation.
        pg_root2 = self.root / "rot_fail_prod_slot2"
        pg_root2.mkdir(mode=0o700)
        pg_inc2 = "inc_" + secrets.token_hex(16)
        pg_job2 = _SessionJob(pg_root2, pg_inc2)
        pg_job2.prepare(config_payload=None)
        self.addCleanup(pg_job2.revoke)
        pg_job2.activate()
        pg2 = ProofGate(
            approval, evidence_dir=ev_dir, exposure_dir=exp_dir,
            check_owner_alive=lambda: None,
            expected_instructions_sha256=sha256(norm_instr.encode("utf-8")).hexdigest(),
        )
        pg2.bind_incarnation(pg_inc2, pg_job2.generation)
        sb2 = SessionBroker(
            socket_path=pg_job2.provider_socket, relay_proof=pg_job2.relay_proof,
            worker_token=tok, lease=pg_job2.lease, connection=_StubConn(),
            binding=SimpleNamespace(generation=1), models=("gpt-6.2-sol",),
            profile_label="personal", expected_port=8401,
            policy=SessionPolicy(
                proof_gate=pg2, job_incarnation=pg_inc2,
                exposure_dir=exp_dir,
                acknowledged_exposure_digest=approval.history_digest_all_12_files,
            ),
        )
        sb2.start()
        self.addCleanup(sb2.close)
        pg2.arm(observed_row="openai--personal/gpt-6.2-sol", observed_screen_digest="2" * 64)
        q_ver = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        q_ver.settimeout(5.0)
        self.addCleanup(q_ver.close)

        def fail_verify_replace(src, dst):
            if str(dst) == str(pg_job2.provider_socket):
                q_ver.connect(str(pg_job2.provider_socket))
                raise OSError("simulated verify os.replace failure")
            return orig_replace(src, dst)

        with patch.object(session_broker.os, "replace", side_effect=fail_verify_replace):
            with self.assertRaises(OSError):
                pg2.mark_relay_verified("3" * 64)
        self.assertEqual(pg2.snapshot_arrival().state, pg_mod.STATE_SPENT)
        self.assertFalse(pg2.snapshot_arrival().relay_verified)
        self.assertTrue(sb2._revoked.is_set(), "failed verify rotation must revoke broker listener")
        with suppress(OSError):
            q_ver.sendall(relay_mod.PROOF_PREFIX + pg_job2.relay_proof + REQUEST_LENGTH.pack(len(prod_req)) + prod_req)
            ver_resp = q_ver.recv(4096)
            self.assertNotIn(b"200 OK", ver_resp)
        self.assertEqual(prod_writes, [])

    def test_timeout_never_performs_hold_io_and_prepersisted_hold_survives_replace(self):
        # Regression (R4 P2 #1): durable hold MUST be pre-persisted before any irreversible release;
        # timeout/deny_release() MUST perform zero filesystem I/O, and fresh readers MUST observe
        # has_active_leases()==True and refuse require_switchable()/session_lease() at every point.
        import pwd
        from oc_openai import connection_state as cs_mod
        from oc_openai.connection import Connection
        from oc_openai.connection_state import ConnectionError as ConnError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        with tempfile.TemporaryDirectory(prefix="oc-mix-prehold-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            coord = _SessionSlotCoordinator(threading.Event())
            slot_cm = adapter.open_slot(
                pref, slot_index=0, slot_root=slot_root, port=8401,
                worker_token="tok-preh-" + "a" * 24,
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
            coord.record_container("d" * 64, slot_index=0)
            handle.job.activate()

            entered_replace = threading.Event()
            release_replace = threading.Event()
            orig_replace = cs_mod.os.replace
            orig_join = threading.Thread.join
            paused_once = [False]
            hold_files_before_replace: list[list[str]] = []

            def slow_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                if dst == cs_mod._STATE_FILE and not paused_once[0]:
                    paused_once[0] = True
                    # Durable hold marker MUST ALREADY exist on disk BEFORE os.replace() executes!
                    hold_files_before_replace.append(
                        [p.name for p in personal_dir.iterdir() if p.name.startswith(".lease-hold-")]
                    )
                    entered_replace.set()
                    release_replace.wait(timeout=5.0)
                return orig_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            def _fast_join(thread_self, timeout=None):
                return orig_join(thread_self, timeout=0.05)

            # Force write_lease_hold to explode if timeout/deny_release ever tries synchronous hold I/O!
            def forbid_timeout_hold_io(*_args, **_kwargs):
                raise AssertionError("timeout/deny_release must NEVER perform synchronous hold I/O!")

            try:
                with (
                    patch.object(session_broker, "_remove_container_verified"),
                    patch.object(cs_mod.os, "replace", side_effect=slow_replace),
                ):
                    coord.on_revoke(0)
                    self.assertTrue(entered_replace.wait(timeout=2.0))
                    self.assertEqual(
                        len(hold_files_before_replace[0]), 1,
                        f"hold marker must be persisted BEFORE os.replace(), got {hold_files_before_replace!r}",
                    )
                    # Timeout runs while write_lease_hold is forbidden -> proves zero-I/O timeout path!
                    with patch.object(cs_mod.Store, "write_lease_hold", side_effect=forbid_timeout_hold_io):
                        t0 = time.monotonic()
                        with patch.object(threading.Thread, "join", _fast_join):
                            err = coord.teardown_all(None)
                        elapsed = time.monotonic() - t0
                self.assertIsNotNone(err)
                self.assertLess(elapsed, 0.5, f"timeout path must be zero-I/O and bounded ({elapsed:.2f}s)")
            finally:
                release_replace.set()
                for t in list(coord._retire_threads):
                    orig_join(t, timeout=2.0)

            fresh_conn = Connection(personal_dir, host_probe=lambda: host)
            self.assertTrue(fresh_conn.has_active_leases())
            with self.assertRaises(ConnError) as sw_err:
                fresh_conn.require_switchable()
            self.assertEqual(sw_err.exception.code, "managed_retirement_incomplete")

    def test_clear_hold_post_unlink_dir_fsync_failure_restores_guard_and_blocks_switch(self):
        # Regression (R5/R7): if final os.fsync(directory) fails AFTER durable settlement publication
        # (.lease-settled-*), caller reports unconfirmed and fresh Connection readers remain blocked
        # while fsync failure persists (both coordinated and standalone teardown).
        import errno
        import pwd
        from oc_openai import connection_state as cs_mod
        from oc_openai.connection import Connection
        from oc_openai.connection_state import ConnectionError as ConnError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)

        # Case 1: Coordinated teardown path.
        with tempfile.TemporaryDirectory(prefix="oc-mix-clrsyn-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            coord = _SessionSlotCoordinator(threading.Event())
            slot_cm = adapter.open_slot(
                pref, slot_index=0, slot_root=slot_root, port=8401,
                worker_token="tok-clrs-" + "a" * 24,
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
            coord.record_container("e" * 64, slot_index=0)
            handle.job.activate()

            orig_link = cs_mod.os.link
            orig_fsync = cs_mod.os.fsync
            linked_settled = [False]

            def track_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                if isinstance(dst, str) and dst.startswith(".lease-settled-"):
                    linked_settled[0] = True
                return orig_link(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            def fail_fsync_after_publish(fd):
                if linked_settled[0]:
                    raise OSError(errno.EIO, "simulated post-publish dir fsync failure")
                return orig_fsync(fd)

            next_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(next_root, ignore_errors=True))
            next_job = _SessionJob(next_root, "inc_" + secrets.token_hex(16))
            next_job.prepare(config_payload=None)
            self.addCleanup(next_job.revoke)

            with (
                patch.object(session_broker, "_remove_container_verified"),
                patch.object(cs_mod.os, "link", side_effect=track_link),
                patch.object(cs_mod.os, "fsync", side_effect=fail_fsync_after_publish),
            ):
                err = coord.teardown_all(None)

                self.assertTrue(linked_settled[0])
                self.assertIsNotNone(err)
                self.assertFalse(coord._slots[0].lease_confirmed_released)
                self.assertFalse(handle.lease_release_confirmed())
                coord.remove_slot_roots(require_confirmed_leases=True)
                self.assertTrue(slot_root.exists())

                fresh_conn = Connection(personal_dir, host_probe=lambda: host)
                self.assertTrue(fresh_conn.has_active_leases())
                with self.assertRaises(ConnError) as sw_err:
                    fresh_conn.require_switchable()
                self.assertEqual(sw_err.exception.code, "managed_retirement_incomplete")
                lease_cm = fresh_conn.session_lease(pref.handle.binding, next_job)
                with self.assertRaises(ConnError) as lease_err:
                    lease_cm.__enter__()
                self.assertEqual(lease_err.exception.code, "managed_retirement_incomplete")

        # Case 2: Standalone Connection.session_lease() teardown path.
        with tempfile.TemporaryDirectory(prefix="oc-mix-clrsyn-sa-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, _, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            conn = Connection(personal_dir, host_probe=lambda: host)
            sa_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(sa_root, ignore_errors=True))
            sa_job = _SessionJob(sa_root, "inc_" + secrets.token_hex(16))
            sa_job.prepare(config_payload=None)
            self.addCleanup(sa_job.revoke)
            sa_job.activate()

            orig_link = cs_mod.os.link
            orig_fsync = cs_mod.os.fsync
            sa_linked = [False]

            def sa_track_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                if isinstance(dst, str) and dst.startswith(".lease-settled-"):
                    sa_linked[0] = True
                return orig_link(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            def sa_fail_fsync(fd):
                if sa_linked[0]:
                    raise OSError(errno.EIO, "simulated standalone post-publish dir fsync failure")
                return orig_fsync(fd)

            other_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(other_root, ignore_errors=True))
            other_job = _SessionJob(other_root, "inc_" + secrets.token_hex(16))
            other_job.prepare(config_payload=None)
            self.addCleanup(other_job.revoke)

            with (
                patch.object(cs_mod.os, "link", side_effect=sa_track_link),
                patch.object(cs_mod.os, "fsync", side_effect=sa_fail_fsync),
            ):
                with self.assertRaises(ConnError):
                    with conn.session_lease(pref.handle.binding, sa_job):
                        sa_job.revoke()
                self.assertTrue(sa_linked[0])
                fresh_sa = Connection(personal_dir, host_probe=lambda: host)
                self.assertTrue(fresh_sa.has_active_leases())
                with self.assertRaises(ConnError) as sa_sw:
                    fresh_sa.require_switchable()
                self.assertEqual(sa_sw.exception.code, "managed_retirement_incomplete")
                sa_lease_cm = fresh_sa.session_lease(pref.handle.binding, other_job)
                with self.assertRaises(ConnError) as sa_new:
                    sa_lease_cm.__enter__()
                self.assertEqual(sa_new.exception.code, "managed_retirement_incomplete")

    def test_refused_final_write_matching_hold_blocks_new_same_registration_lease(self):
        # Regression (R5 matching-hold admission): when a refused final store write leaves BOTH
        # worker_leases[old_root] AND its matching .lease-hold-*, fail-closed session_lease MUST
        # refuse a new lease for a different job on the same registration.
        import pwd
        from oc_openai.connection import Connection
        from oc_openai.connection_state import ConnectionError as ConnError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        with tempfile.TemporaryDirectory(prefix="oc-mix-matchhold-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, _, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            conn = Connection(personal_dir, host_probe=lambda: host)
            old_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(old_root, ignore_errors=True))
            old_job = _SessionJob(old_root, "inc_" + secrets.token_hex(16))
            old_job.prepare(config_payload=None)
            self.addCleanup(old_job.revoke)
            old_job.activate()

            class _DenyAtCommitGate:
                def __call__(self):
                    return True

                @contextmanager
                def commit_fence(self):
                    yield False

            with conn.session_lease(pref.handle.binding, old_job, release_gate=_DenyAtCommitGate()):
                old_job.revoke()
            fresh_mh = Connection(personal_dir, host_probe=lambda: host)
            self.assertTrue(fresh_mh.has_active_leases())
            new_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(new_root, ignore_errors=True))
            new_job = _SessionJob(new_root, "inc_" + secrets.token_hex(16))
            new_job.prepare(config_payload=None)
            self.addCleanup(new_job.revoke)
            mh_lease_cm = fresh_mh.session_lease(pref.handle.binding, new_job)
            with self.assertRaises(ConnError) as mh_err:
                mh_lease_cm.__enter__()
            self.assertEqual(mh_err.exception.code, "managed_retirement_incomplete")

    def _make_probe_job(self) -> _SessionJob:
        probe_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
        self.addCleanup(lambda: shutil.rmtree(probe_root, ignore_errors=True))
        probe_job = _SessionJob(probe_root, "inc_" + secrets.token_hex(16))
        probe_job.prepare(config_payload=None)
        self.addCleanup(probe_job.revoke)
        return probe_job

    def _assert_fresh_reader_blocked(
        self, personal_dir: Path, host, binding, *, probe_job: _SessionJob | None = None,
        expect_session_lease_blocked: bool = True,
    ) -> None:
        from oc_openai.connection import Connection
        from oc_openai.connection_state import ConnectionError as ConnError

        fresh = Connection(personal_dir, host_probe=lambda: host)
        self.assertTrue(fresh.has_active_leases())
        with self.assertRaises(ConnError) as sw_err:
            fresh.require_switchable()
        self.assertEqual(sw_err.exception.code, "managed_retirement_incomplete")
        job = probe_job if probe_job is not None else self._make_probe_job()
        wl_cm = fresh.worker_lease(binding, job)
        with self.assertRaises(ConnError) as wl_err:
            wl_cm.__enter__()
        self.assertEqual(wl_err.exception.code, "managed_retirement_incomplete")
        if expect_session_lease_blocked:
            lease_cm = fresh.session_lease(binding, job)
            with self.assertRaises(ConnError) as lease_err:
                lease_cm.__enter__()
            self.assertEqual(lease_err.exception.code, "managed_retirement_incomplete")

    def test_r7_lock_dag_contention_and_nonblocking_timeout_denial(self):
        # Regression (R7 #1): deterministic lock-DAG contention (coordinator._lock -> release_gate._lock
        # alongside _finalize_slot_hold -> state.lock -> coordinator._lock -> release_gate._lock) and
        # non-blocking timeout denial across BOTH joined background-worker and synchronous teardown paths.
        import pwd
        from oc_openai import connection_state as cs_mod

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        for mode in ("joined", "synchronous"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory(prefix=f"oc-r7-dag-{mode}-", dir=home) as home_raw:
                    home_scratch = Path(home_raw)
                    os.chmod(home_scratch, 0o700)
                    _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                        home_scratch / "profiles",
                    )
                    slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
                    self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
                    coord = _SessionSlotCoordinator(threading.Event())
                    slot_cm = adapter.open_slot(
                        pref, slot_index=0, slot_root=slot_root, port=8401,
                        worker_token="tok-r7dag-" + "a" * 24,
                        acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
                    )
                    handle = slot_cm.__enter__()
                    coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
                    coord.record_container("a" * 64, slot_index=0)
                    handle.job.activate()

                    orig_settle = cs_mod.Store.settle_lease_hold
                    entered_before_pub = threading.Event()
                    release_before_pub = threading.Event()
                    contender_done = threading.Event()
                    contender_err: list[BaseException] = []

                    def wrapped_settle(store_self, token, *, directory=None, before_publish=None):
                        def wrapped_bp():
                            entered_before_pub.set()
                            release_before_pub.wait(timeout=3.0)
                            return before_publish() if before_publish is not None else True

                        return orig_settle(store_self, token, directory=directory, before_publish=wrapped_bp)

                    def contender():
                        try:
                            self.assertTrue(entered_before_pub.wait(timeout=3.0))
                            # Acquires coordinator._lock -> release_gate._lock while main thread holds state.lock
                            # and is about to acquire coordinator._lock -> release_gate._lock (zero deadlock!).
                            coord.record_container("b" * 64, slot_index=0)
                        except BaseException as exc:  # pragma: no cover
                            contender_err.append(exc)
                        finally:
                            release_before_pub.set()
                            contender_done.set()

                    worker = threading.Thread(target=contender, daemon=True)
                    worker.start()
                    t0 = time.monotonic()
                    with (
                        patch.object(session_broker, "_remove_container_verified"),
                        patch.object(cs_mod.Store, "settle_lease_hold", wrapped_settle),
                    ):
                        if mode == "joined":
                            coord.on_revoke(0)
                            # Wait for background retire thread to release store before teardown_all joins it.
                            for t in list(coord._retire_threads):
                                t.join(timeout=3.0)
                        err = coord.teardown_all(None)
                    elapsed = time.monotonic() - t0
                    worker.join(timeout=3.0)
                    self.assertTrue(contender_done.is_set())
                    self.assertEqual(contender_err, [])
                    self.assertLess(elapsed, 2.0, f"lock-DAG contention took too long ({elapsed:.2f}s)")
                    # Because contender recorded a new unremoved container before publication claim,
                    # coordinator invariants MUST deny settlement cleanly with zero deadlock!
                    self.assertIsNotNone(err)
                    self.assertFalse(handle.lease_release_confirmed())
                    self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

        # Also prove non-blocking timeout denial never invokes settle_lease_hold or write_lease_hold.
        with tempfile.TemporaryDirectory(prefix="oc-r7-dag-to-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            coord = _SessionSlotCoordinator(threading.Event())
            slot_cm = adapter.open_slot(
                pref, slot_index=0, slot_root=slot_root, port=8401,
                worker_token="tok-r7to-" + "b" * 24,
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
            coord.record_container("c" * 64, slot_index=0)
            handle.job.activate()

            entered = threading.Event()
            release = threading.Event()
            orig_replace = cs_mod.os.replace
            orig_join = threading.Thread.join

            def slow_replace(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                if dst == cs_mod._STATE_FILE and not entered.is_set():
                    entered.set()
                    release.wait(timeout=5.0)
                return orig_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            def forbid_io(*_a, **_kw):
                raise AssertionError("timeout denial must not perform store I/O")

            try:
                with (
                    patch.object(session_broker, "_remove_container_verified"),
                    patch.object(cs_mod.os, "replace", side_effect=slow_replace),
                ):
                    coord.on_revoke(0)
                    self.assertTrue(entered.wait(timeout=2.0))
                    with (
                        patch.object(cs_mod.Store, "write_lease_hold", side_effect=forbid_io),
                        patch.object(cs_mod.Store, "settle_lease_hold", side_effect=forbid_io),
                    ):
                        t0 = time.monotonic()
                        with patch.object(threading.Thread, "join", lambda s, timeout=None: orig_join(s, timeout=0.05)):
                            err = coord.teardown_all(None)
                        elapsed = time.monotonic() - t0
                self.assertIsNotNone(err)
                self.assertLess(elapsed, 0.5)
            finally:
                release.set()
                for t in list(coord._retire_threads):
                    orig_join(t, timeout=2.0)
            self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

    def test_r7_pre_claim_vs_post_claim_denial_coordinated_and_standalone(self):
        # Regression (R7 #2): pre-claim denial during temp-file fsync blocks receipt publication;
        # post-claim denial after claim_settlement_publish() allows publication (distinct from pre-claim),
        # and if caller sync then fails, fresh reader reconciles only after disk validation + fsyncs.
        import errno
        import pwd
        from oc_openai import connection_state as cs_mod
        from oc_openai.connection import Connection
        from oc_openai.connection_state import ConnectionError as ConnError
        from oc_openai.session_adapter import _SlotReleaseGate

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)

        # Part A: Pre-claim denial during os.fsync(tmp_fd) — coordinated AND standalone.
        for path_kind in ("coordinated", "standalone_gate", "standalone_callable"):
            with self.subTest(phase="pre_claim", path_kind=path_kind):
                with tempfile.TemporaryDirectory(prefix="oc-r7-pre-", dir=home) as home_raw:
                    home_scratch = Path(home_raw)
                    os.chmod(home_scratch, 0o700)
                    _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                        home_scratch / "profiles",
                    )
                    orig_open = cs_mod.os.open
                    orig_fsync = cs_mod.os.fsync
                    tmp_fds: set[int] = set()
                    denied_in_tmp_fsync = [False]
                    trigger_deny: list[object] = []

                    def track_open(path, flags, mode=0o777, *, dir_fd=None):
                        fd = orig_open(path, flags, mode, dir_fd=dir_fd)
                        if isinstance(path, str) and path.startswith(".lease-settle-tmp-"):
                            tmp_fds.add(fd)
                        return fd

                    def deny_during_tmp_fsync(fd):
                        res = orig_fsync(fd)
                        if fd in tmp_fds and not denied_in_tmp_fsync[0]:
                            denied_in_tmp_fsync[0] = True
                            trigger_deny[0]()
                        return res

                    if path_kind == "coordinated":
                        slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
                        self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
                        coord = _SessionSlotCoordinator(threading.Event())
                        slot_cm = adapter.open_slot(
                            pref, slot_index=0, slot_root=slot_root, port=8401,
                            worker_token="tok-r7pre-" + "a" * 24,
                            acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
                        )
                        handle = slot_cm.__enter__()
                        coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
                        coord.record_container("d" * 64, slot_index=0)
                        handle.job.activate()
                        trigger_deny.append(handle.deny_lease_release)
                        with (
                            patch.object(session_broker, "_remove_container_verified"),
                            patch.object(cs_mod.os, "open", side_effect=track_open),
                            patch.object(cs_mod.os, "fsync", side_effect=deny_during_tmp_fsync),
                        ):
                            err = coord.teardown_all(None)
                        self.assertIsNotNone(err)
                        self.assertFalse(handle.lease_release_confirmed())
                    else:
                        conn = Connection(personal_dir, host_probe=lambda: host)
                        job_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
                        self.addCleanup(lambda: shutil.rmtree(job_root, ignore_errors=True))
                        job = _SessionJob(job_root, "inc_" + secrets.token_hex(16))
                        job.prepare(config_payload=None)
                        self.addCleanup(job.revoke)
                        job.activate()
                        outcomes: list[str] = []
                        if path_kind == "standalone_gate":
                            gate = _SlotReleaseGate()
                            trigger_deny.append(gate.deny_release)
                        else:
                            allowed_box = [True]
                            gate = lambda: allowed_box[0]
                            trigger_deny.append(lambda: allowed_box.__setitem__(0, False))
                        with (
                            patch.object(cs_mod.os, "open", side_effect=track_open),
                            patch.object(cs_mod.os, "fsync", side_effect=deny_during_tmp_fsync),
                        ):
                            with conn.session_lease(
                                pref.handle.binding, job, release_gate=gate, on_release_result=outcomes.append,
                            ):
                                job.revoke()
                        self.assertEqual(outcomes, ["retained_gate_closed"])

                    self.assertTrue(denied_in_tmp_fsync[0])
                    names = sorted(p.name for p in personal_dir.iterdir())
                    self.assertFalse(any(n.startswith(".lease-settled-") for n in names))
                    self.assertFalse(any(n.startswith(".lease-settle-tmp-") for n in names))
                    self.assertTrue(any(n.startswith(".lease-hold-") for n in names))
                    self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

        # Part B: Post-claim denial strictly AFTER claim_settlement_publish() returned True.
        for fail_dir_sync in (False, True):
            with self.subTest(phase="post_claim", fail_dir_sync=fail_dir_sync):
                with tempfile.TemporaryDirectory(prefix="oc-r7-post-", dir=home) as home_raw:
                    home_scratch = Path(home_raw)
                    os.chmod(home_scratch, 0o700)
                    _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                        home_scratch / "profiles",
                    )
                    slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
                    self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
                    coord = _SessionSlotCoordinator(threading.Event())
                    slot_cm = adapter.open_slot(
                        pref, slot_index=0, slot_root=slot_root, port=8401,
                        worker_token="tok-r7post-" + "c" * 24,
                        acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
                    )
                    handle = slot_cm.__enter__()
                    coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
                    coord.record_container("e" * 64, slot_index=0)
                    handle.job.activate()

                    orig_link = cs_mod.os.link
                    orig_fsync = cs_mod.os.fsync
                    linked = [False]

                    def post_claim_deny_at_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                        if isinstance(dst, str) and dst.startswith(".lease-settled-"):
                            # Strictly AFTER claim_settlement_publish() already returned True!
                            handle.deny_lease_release()
                            linked[0] = True
                        return orig_link(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

                    def maybe_fail_sync(fd):
                        if fail_dir_sync and linked[0]:
                            raise OSError(errno.EIO, "simulated post-claim dir fsync EIO")
                        return orig_fsync(fd)

                    probe_job = self._make_probe_job()
                    with (
                        patch.object(session_broker, "_remove_container_verified"),
                        patch.object(cs_mod.os, "link", side_effect=post_claim_deny_at_link),
                        patch.object(cs_mod.os, "fsync", side_effect=maybe_fail_sync),
                    ):
                        err = coord.teardown_all(None)
                        self.assertTrue(linked[0])
                        if fail_dir_sync:
                            self.assertIsNotNone(err)
                            self.assertFalse(handle.lease_release_confirmed())
                            # While EIO persists, fresh reader stays blocked.
                            self._assert_fresh_reader_blocked(
                                personal_dir, host, pref.handle.binding, probe_job=probe_job,
                            )
                        else:
                            self.assertIsNone(err)
                            self.assertTrue(handle.lease_release_confirmed())

                    # Once fsync works, fresh reader reconciles cleanly!
                    recovered = Connection(personal_dir, host_probe=lambda: host)
                    self.assertFalse(recovered.has_active_leases())
                    recovered.require_switchable()

    def test_r7_forced_hold_id_collision_with_orphan_settled_fails_closed(self):
        # Regression (R7 #3): forced hold_id collision with a pre-existing orphan .lease-settled-<id>
        # during write_lease_hold() MUST fail closed, retain worker_leases[root], and block readers.
        import hashlib
        import pwd
        from oc_openai import connection_state as cs_mod
        from oc_openai.connection import Connection
        from oc_openai.connection_state import ConnectionError as ConnError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        with tempfile.TemporaryDirectory(prefix="oc-r7-coll-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, _, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            conn = Connection(personal_dir, host_probe=lambda: host)
            job_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(job_root, ignore_errors=True))
            incarnation = "inc_" + secrets.token_hex(16)
            job = _SessionJob(job_root, incarnation)
            job.prepare(config_payload=None)
            self.addCleanup(job.revoke)
            job.activate()

            forced_nonce = "00112233445566778899aabbccddeeff"
            expected_hold_id = hashlib.sha256(
                f"{job.root.name}\0{incarnation}\0{forced_nonce}".encode("utf-8")
            ).hexdigest()[:32]
            orphan_settled = personal_dir / f".lease-settled-{expected_hold_id}"
            orphan_payload = json.dumps({
                "version": 1, "state": "settled", "hold_id": expected_hold_id,
                "root": job.root.name, "incarnation": incarnation,
            }).encode("utf-8") + b"\n"
            fd = os.open(orphan_settled, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, orphan_payload)
            finally:
                os.close(fd)

            with patch.object(cs_mod.secrets, "token_hex", return_value=forced_nonce):
                with self.assertRaises(ConnError) as coll_err:
                    with conn.session_lease(pref.handle.binding, job):
                        job.revoke()
            self.assertEqual(coll_err.exception.code, "managed_retirement_incomplete")
            self.assertFalse((personal_dir / f".lease-hold-{expected_hold_id}").exists())
            state_data = json.loads((personal_dir / "state.json").read_text(encoding="utf-8"))
            self.assertIn(job.root.name, state_data.get("worker_leases", {}))
            self._assert_fresh_reader_blocked(
                personal_dir, host, pref.handle.binding, expect_session_lease_blocked=False,
            )
            # Same-root session_lease is also refused while worker_leases[job.root.name] is retained.
            dup_cm = Connection(personal_dir, host_probe=lambda: host).session_lease(pref.handle.binding, job)
            with self.assertRaises(ConnError) as dup_err:
                dup_cm.__enter__()
            self.assertEqual(dup_err.exception.code, "managed_retirement_incomplete")

    def test_r7_pre_publication_on_disk_hold_and_receipt_checks(self):
        # Regression (R7 #4): (a) missing on-disk hold -> writer refuses without publishing;
        # (b) mutated/malformed hold -> writer refuses AND reader stays blocked;
        # (c) pre-existing .lease-settled-* -> writer refuses without overwriting AND reader stays blocked.
        import pwd
        from oc_openai.connection_state import ConnectionError as ConnError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        for scenario in ("missing_hold", "mutated_hold", "existing_settled"):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory(prefix=f"oc-r7-prepub-{scenario}-", dir=home) as home_raw:
                    home_scratch = Path(home_raw)
                    os.chmod(home_scratch, 0o700)
                    _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                        home_scratch / "profiles",
                    )
                    slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
                    self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
                    coord = _SessionSlotCoordinator(threading.Event())
                    slot_cm = adapter.open_slot(
                        pref, slot_index=0, slot_root=slot_root, port=8401,
                        worker_token="tok-r7prepub-" + "f" * 24,
                        acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
                    )
                    handle = slot_cm.__enter__()
                    coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
                    coord.record_container("f" * 64, slot_index=0)
                    handle.job.activate()

                    with patch.object(session_broker, "_remove_container_verified"):
                        coord.on_revoke(0)
                        for t in list(coord._retire_threads):
                            t.join(timeout=3.0)

                    holds = [p for p in personal_dir.iterdir() if p.name.startswith(".lease-hold-")]
                    self.assertEqual(len(holds), 1)
                    hold_path = holds[0]
                    hold_id = hold_path.name[len(".lease-hold-"):]
                    settled_path = personal_dir / f".lease-settled-{hold_id}"
                    planted_bytes = b'{"version":1,"state":"settled","hold_id":"' + hold_id.encode("ascii") + b'","root":"other","incarnation":"inc_0"}\n'

                    if scenario == "missing_hold":
                        hold_path.unlink()
                    elif scenario == "mutated_hold":
                        hold_path.write_bytes(b"corrupted-hold\n")
                    else:
                        fd = os.open(settled_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        try:
                            os.write(fd, planted_bytes)
                        finally:
                            os.close(fd)

                    with patch.object(session_broker, "_remove_container_verified"):
                        err = coord.teardown_all(None)

                    self.assertIsNotNone(err)
                    self.assertFalse(coord._slots[0].lease_confirmed_released)
                    self.assertFalse(handle.lease_release_confirmed())
                    coord.remove_slot_roots(require_confirmed_leases=True)
                    self.assertTrue(slot_root.exists())

                    if scenario == "missing_hold":
                        # Writer refusal only; no .lease-settled-* published.
                        self.assertFalse(settled_path.exists())
                    elif scenario == "mutated_hold":
                        self.assertFalse(settled_path.exists())
                        self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)
                    else:
                        # Existing settled marker MUST NOT be overwritten, and reader stays blocked.
                        self.assertEqual(settled_path.read_bytes(), planted_bytes)
                        self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

    def test_r7_publish_before_sync_persistent_and_recovered_eio_plus_enospc(self):
        # Regression (R7 #5): publish-before-sync EIO across joined, synchronous, and standalone paths
        # paired with ENOSPC on O_CREAT and EIO on unlink; reader stays blocked while EIO persists
        # and reconciles via fsync(settled_fd) + fsync(directory) once fsync recovers.
        import errno
        import pwd
        from oc_openai import connection_state as cs_mod
        from oc_openai.connection import Connection
        from oc_openai.connection_state import ConnectionError as ConnError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        for mode in ("joined", "synchronous", "standalone"):
            with self.subTest(mode=mode):
                with tempfile.TemporaryDirectory(prefix=f"oc-r7-eio-{mode}-", dir=home) as home_raw:
                    home_scratch = Path(home_raw)
                    os.chmod(home_scratch, 0o700)
                    _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                        home_scratch / "profiles",
                    )
                    orig_link = cs_mod.os.link
                    orig_fsync = cs_mod.os.fsync
                    orig_open = cs_mod.os.open
                    orig_unlink = cs_mod.os.unlink
                    published = [False]

                    def track_link(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                        if isinstance(dst, str) and dst.startswith(".lease-settled-"):
                            published[0] = True
                        return orig_link(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

                    def persistent_eio_fsync(fd):
                        if published[0]:
                            raise OSError(errno.EIO, "persistent EIO on fsync")
                        return orig_fsync(fd)

                    def paired_enospc_open(path, flags, mode_bits=0o777, *, dir_fd=None):
                        if published[0] and (flags & os.O_CREAT):
                            raise OSError(errno.ENOSPC, "paired ENOSPC on O_CREAT")
                        return orig_open(path, flags, mode_bits, dir_fd=dir_fd)

                    def paired_eio_unlink(path, *, dir_fd=None):
                        if published[0] and isinstance(path, str) and path.startswith(".lease-hold-"):
                            raise OSError(errno.EIO, "paired EIO on hold unlink")
                        return orig_unlink(path, dir_fd=dir_fd)

                    probe_job = self._make_probe_job()
                    sa_job = self._make_probe_job() if mode == "standalone" else None
                    slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp")) if mode != "standalone" else None
                    if slot_root is not None:
                        self.addCleanup(lambda sr=slot_root: shutil.rmtree(sr, ignore_errors=True))
                    with (
                        patch.object(session_broker, "_remove_container_verified"),
                        patch.object(cs_mod.os, "link", side_effect=track_link),
                        patch.object(cs_mod.os, "fsync", side_effect=persistent_eio_fsync),
                        patch.object(cs_mod.os, "open", side_effect=paired_enospc_open),
                        patch.object(cs_mod.os, "unlink", side_effect=paired_eio_unlink),
                    ):
                        if mode == "standalone":
                            conn = Connection(personal_dir, host_probe=lambda: host)
                            assert sa_job is not None
                            sa_job.activate()
                            with self.assertRaises(ConnError):
                                with conn.session_lease(pref.handle.binding, sa_job):
                                    sa_job.revoke()
                        else:
                            assert slot_root is not None
                            coord = _SessionSlotCoordinator(threading.Event())
                            slot_cm = adapter.open_slot(
                                pref, slot_index=0, slot_root=slot_root, port=8401,
                                worker_token="tok-r7eio-" + "a" * 24,
                                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
                            )
                            handle = slot_cm.__enter__()
                            coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
                            coord.record_container("1" * 64, slot_index=0)
                            handle.job.activate()
                            if mode == "joined":
                                coord.on_revoke(0)
                                for t in list(coord._retire_threads):
                                    t.join(timeout=3.0)
                            err = coord.teardown_all(None)
                            self.assertIsNotNone(err)
                            self.assertFalse(handle.lease_release_confirmed())
                            coord.remove_slot_roots(require_confirmed_leases=True)
                            self.assertTrue(slot_root.exists())

                        self.assertTrue(published[0])
                        # While EIO + ENOSPC persist, fresh reader MUST stay blocked!
                        self._assert_fresh_reader_blocked(
                            personal_dir, host, pref.handle.binding, probe_job=probe_job,
                        )

                    # Once fsync recovers, fresh reader reconciles via fsync(settled_fd) + fsync(directory).
                    fsync_calls: list[int] = []

                    def record_fsync(fd):
                        fsync_calls.append(fd)
                        return orig_fsync(fd)

                    with patch.object(cs_mod.os, "fsync", side_effect=record_fsync):
                        recovered = Connection(personal_dir, host_probe=lambda: host)
                        self.assertFalse(recovered.has_active_leases())
                        recovered.require_switchable()
                    self.assertGreaterEqual(len(fsync_calls), 2)
                    leftovers = [p.name for p in personal_dir.iterdir() if p.name.startswith((".lease-hold-", ".lease-settled-"))]
                    self.assertEqual(leftovers, [])

    def test_r7_gc_ordering_under_hold_delete_dir_fsync_eio_preserves_settled(self):
        # Regression (R7 #6): when os.fsync(directory) fails with EIO right after os.unlink(".lease-hold-*")
        # in BOTH caller Step 2 AND reader reconciliation, os.unlink(".lease-settled-*") MUST NEVER be called
        # and .lease-settled-* MUST remain preserved on disk.
        import errno
        import pwd
        from oc_openai import connection_state as cs_mod
        from oc_openai.connection import Connection

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)

        # Path 1: Caller Step 2 GC under hold-delete dir-fsync EIO.
        with tempfile.TemporaryDirectory(prefix="oc-r7-gc-caller-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            coord = _SessionSlotCoordinator(threading.Event())
            slot_cm = adapter.open_slot(
                pref, slot_index=0, slot_root=slot_root, port=8401,
                worker_token="tok-r7gc1-" + "a" * 24,
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
            coord.record_container("2" * 64, slot_index=0)
            handle.job.activate()

            orig_unlink = cs_mod.os.unlink
            orig_fsync = cs_mod.os.fsync
            hold_unlinked = [False]
            settled_unlink_attempts: list[str] = []

            def spy_unlink(path, *, dir_fd=None):
                if isinstance(path, str) and path.startswith(".lease-hold-"):
                    hold_unlinked[0] = True
                if isinstance(path, str) and path.startswith(".lease-settled-"):
                    settled_unlink_attempts.append(path)
                return orig_unlink(path, dir_fd=dir_fd)

            def fail_fsync_after_hold_unlink(fd):
                if hold_unlinked[0]:
                    raise OSError(errno.EIO, "GC hold-delete dir fsync EIO")
                return orig_fsync(fd)

            with (
                patch.object(session_broker, "_remove_container_verified"),
                patch.object(cs_mod.os, "unlink", side_effect=spy_unlink),
                patch.object(cs_mod.os, "fsync", side_effect=fail_fsync_after_hold_unlink),
            ):
                err = coord.teardown_all(None)

            self.assertIsNone(err)
            self.assertTrue(handle.lease_release_confirmed())
            self.assertTrue(hold_unlinked[0])
            self.assertEqual(settled_unlink_attempts, [])
            settled_files = [p.name for p in personal_dir.iterdir() if p.name.startswith(".lease-settled-")]
            self.assertEqual(len(settled_files), 1)

        # Path 2: Reader reconciliation GC under hold-delete dir-fsync EIO.
        with tempfile.TemporaryDirectory(prefix="oc-r7-gc-reader-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            _, _, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            hold_id = "ab" * 16
            for state_name, prefix in (("hold", ".lease-hold-"), ("settled", ".lease-settled-")):
                payload = json.dumps({
                    "version": 1, "state": state_name, "hold_id": hold_id,
                    "root": "oc-chat-deadbeef", "incarnation": "inc_" + "1" * 32,
                }).encode("utf-8") + b"\n"
                fd = os.open(personal_dir / f"{prefix}{hold_id}", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(fd, payload)
                finally:
                    os.close(fd)

            orig_unlink = cs_mod.os.unlink
            orig_fsync = cs_mod.os.fsync
            reader_hold_unlinked = [False]
            reader_settled_unlinks: list[str] = []

            def reader_spy_unlink(path, *, dir_fd=None):
                if isinstance(path, str) and path.startswith(".lease-hold-"):
                    reader_hold_unlinked[0] = True
                if isinstance(path, str) and path.startswith(".lease-settled-"):
                    reader_settled_unlinks.append(path)
                return orig_unlink(path, dir_fd=dir_fd)

            def reader_fail_gc_fsync(fd):
                if reader_hold_unlinked[0]:
                    raise OSError(errno.EIO, "reader GC hold-delete dir fsync EIO")
                return orig_fsync(fd)

            with (
                patch.object(cs_mod.os, "unlink", side_effect=reader_spy_unlink),
                patch.object(cs_mod.os, "fsync", side_effect=reader_fail_gc_fsync),
            ):
                fresh = Connection(personal_dir, host_probe=lambda: host)
                self.assertFalse(fresh.has_active_leases())

            self.assertTrue(reader_hold_unlinked[0])
            self.assertEqual(reader_settled_unlinks, [])
            self.assertTrue((personal_dir / f".lease-settled-{hold_id}").exists())

    def test_r7_negative_authority_two_link_crash_fifo_and_tamper_controls(self):
        # Regression (R7 #7): standalone negative authority (absent/failed confirm_terminal),
        # clean first connection vs lost state.lock with hold, unavailable dir, two-link crash,
        # non-blocking FIFO refusal, symlink, wrong mode, extra keys, legacy hold, mismatched tuple,
        # and matching hold with root in active_roots.
        import errno
        import pwd
        from oc_openai import connection_state as cs_mod
        from oc_openai.connection import Connection
        from oc_openai.connection_state import ConnectionError as ConnError, Store

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)

        # 1. Clean first connection (non-existent dir & empty 0o700 dir) vs missing state.lock with hold.
        with tempfile.TemporaryDirectory(prefix="oc-r7-neg-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)
            self.assertFalse(Connection(home_scratch / "never_created").has_active_leases())
            empty_dir = home_scratch / "empty_first"
            empty_dir.mkdir(mode=0o700)
            self.assertFalse(Connection(empty_dir).has_active_leases())

            # Missing state.lock while .lease-hold-* exists (even without state.json) MUST fail closed.
            fd = os.open(empty_dir / (".lease-hold-" + "0" * 32), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            with self.assertRaises(ConnError) as lockless_err:
                Connection(empty_dir).has_active_leases()
            self.assertEqual(lockless_err.exception.code, "untrusted_connection_file")

            # Unavailable private directory / os.listdir error fails closed.
            _, _, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                home_scratch / "profiles",
            )
            with patch.object(cs_mod.os, "listdir", side_effect=OSError(errno.EIO, "listdir failed")):
                self.assertTrue(Connection(personal_dir, host_probe=lambda: host).has_active_leases())

            # 2. Standalone negative authority: outcome == "absent" publishes NO receipt;
            # failed confirm_terminal() mints NO hold and publishes NO receipt.
            conn = Connection(personal_dir, host_probe=lambda: host)
            abs_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(abs_root, ignore_errors=True))
            abs_job = _SessionJob(abs_root, "inc_" + secrets.token_hex(16))
            abs_job.prepare(config_payload=None)
            self.addCleanup(abs_job.revoke)
            abs_job.activate()
            abs_outcomes: list[str] = []
            with conn.session_lease(pref.handle.binding, abs_job, on_release_result=abs_outcomes.append):
                # Externally remove worker_leases entry for same registration -> exit sees "absent".
                st_path = personal_dir / "state.json"
                rec = json.loads(st_path.read_text(encoding="utf-8"))
                rec.pop("worker_leases", None)
                st_path.write_text(json.dumps(rec), encoding="utf-8")
                abs_job.revoke()
            self.assertEqual(abs_outcomes, ["absent"])
            self.assertEqual(
                [p.name for p in personal_dir.iterdir() if p.name.startswith((".lease-hold-", ".lease-settled-"))],
                [],
            )

            nonterm_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(nonterm_root, ignore_errors=True))
            nonterm_job = _SessionJob(nonterm_root, "inc_" + secrets.token_hex(16))
            nonterm_job.prepare(config_payload=None)
            self.addCleanup(nonterm_job.revoke)
            nonterm_job.activate()
            with self.assertRaises(ConnError) as nt_err:
                with conn.session_lease(pref.handle.binding, nonterm_job):
                    pass  # Not revoked -> confirm_terminal() fails!
            self.assertEqual(nt_err.exception.code, "managed_retirement_incomplete")
            self.assertEqual(
                [p.name for p in personal_dir.iterdir() if p.name.startswith((".lease-hold-", ".lease-settled-"))],
                [],
            )
            # Clean up nonterm lease for subsequent tamper subtests.
            nonterm_job.revoke()
            st_path = personal_dir / "state.json"
            rec = json.loads(st_path.read_text(encoding="utf-8"))
            rec.pop("worker_leases", None)
            st_path.write_text(json.dumps(rec), encoding="utf-8")

            # 3. Tamper, crash & FIFO controls on Store.has_lease_holds / Connection.
            def _write_0600(path: Path, data: bytes) -> None:
                mfd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    os.write(mfd, data)
                finally:
                    os.close(mfd)

            def _clear_markers() -> None:
                for p in list(personal_dir.iterdir()):
                    if p.name.startswith((".lease-hold-", ".lease-settled-", ".lease-settle-tmp-")):
                        p.unlink()

            hid = "cd" * 16
            valid_hold = json.dumps({
                "version": 1, "state": "hold", "hold_id": hid,
                "root": "oc-chat-deadbeef", "incarnation": "inc_" + "2" * 32,
            }).encode("utf-8") + b"\n"
            valid_settled = json.dumps({
                "version": 1, "state": "settled", "hold_id": hid,
                "root": "oc-chat-deadbeef", "incarnation": "inc_" + "2" * 32,
            }).encode("utf-8") + b"\n"
            hold_p = personal_dir / f".lease-hold-{hid}"
            settled_p = personal_dir / f".lease-settled-{hid}"

            # 3a. Two-link crash (st_nlink == 2) on .lease-settled-*
            _clear_markers()
            _write_0600(hold_p, valid_hold)
            _write_0600(settled_p, valid_settled)
            os.link(settled_p, personal_dir / ".lease-settle-tmp-crash")
            self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

            # 3b. FIFO (os.mkfifo) on hold AND on settled must return immediately without blocking!
            _clear_markers()
            os.mkfifo(hold_p, 0o600)
            t0 = time.monotonic()
            self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)
            self.assertLess(time.monotonic() - t0, 0.5)

            _clear_markers()
            _write_0600(hold_p, valid_hold)
            os.mkfifo(settled_p, 0o600)
            t0 = time.monotonic()
            self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)
            self.assertLess(time.monotonic() - t0, 0.5)

            # 3c. Symlink on settled
            _clear_markers()
            _write_0600(hold_p, valid_hold)
            target_p = personal_dir / ".lease-settle-tmp-target"
            _write_0600(target_p, valid_settled)
            os.symlink(target_p.name, settled_p)
            self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

            # 3d. Wrong mode (0o644) on settled
            _clear_markers()
            _write_0600(hold_p, valid_hold)
            _write_0600(settled_p, valid_settled)
            os.chmod(settled_p, 0o644)
            self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

            # 3e. Extra JSON keys on settled
            _clear_markers()
            _write_0600(hold_p, valid_hold)
            _write_0600(settled_p, json.dumps({
                "version": 1, "state": "settled", "hold_id": hid,
                "root": "oc-chat-deadbeef", "incarnation": "inc_" + "2" * 32, "extra": 1,
            }).encode("utf-8") + b"\n")
            self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

            # 3f. Legacy b"hold\n" hold marker
            _clear_markers()
            _write_0600(hold_p, b"hold\n")
            _write_0600(settled_p, valid_settled)
            self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

            # 3g. Mismatched incarnation tuple
            _clear_markers()
            _write_0600(hold_p, valid_hold)
            _write_0600(settled_p, json.dumps({
                "version": 1, "state": "settled", "hold_id": hid,
                "root": "oc-chat-deadbeef", "incarnation": "inc_" + "9" * 32,
            }).encode("utf-8") + b"\n")
            self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

            # 3h. Matching hold + matching settled while root is STILL in active_roots
            _clear_markers()
            _write_0600(hold_p, valid_hold)
            _write_0600(settled_p, valid_settled)
            store = Store(personal_dir)
            with store.locked() as dir_fd:
                self.assertTrue(store.has_lease_holds(dir_fd, active_roots={"oc-chat-deadbeef"}))
                # Both markers MUST remain untouched while root is active!
                self.assertTrue(hold_p.exists())
                self.assertTrue(settled_p.exists())
            _clear_markers()

    def test_r8_bound_profile_missing_state_or_dir_refuses_switch_while_first_use_works(self):
        # Regression (R7 P2 #1): genuine first-use absence must still allow clean connect/idle,
        # whereas losing state.json, the connection directory, or client binding for a previously
        # published profile MUST report active leases / managed_retirement_incomplete and block switch.
        import pwd
        from oc_openai.cli import Reason, RouteUnavailable
        from oc_openai.connection import Connection
        from oc_openai.connection_state import ConnectionError as ConnError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        with tempfile.TemporaryDirectory(prefix="oc-r8-bound-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)

            # Genuine first-use absence still returns False / switchable.
            self.assertFalse(Connection(home_scratch / "brand_new_dir").has_active_leases())
            Connection(home_scratch / "brand_new_dir").require_switchable()
            empty_dir = home_scratch / "empty_first_dir"
            empty_dir.mkdir(mode=0o700)
            self.assertFalse(Connection(empty_dir).has_active_leases())
            Connection(empty_dir).require_switchable()

            # Build two published profiles ("personal" and "work") via the real ProfileBackend.
            from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier
            from oc_openai.connection_job import PhysicalHost
            from oc_openai.profile_backend import ProfileBackend

            host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
            for scenario in ("missing_state_json", "missing_conn_dir", "mismatched_client"):
                with self.subTest(scenario=scenario):
                    state_root = home_scratch / f"profiles_{scenario}"
                    state_root.mkdir(mode=0o700)
                    transport = FixtureTransport()
                    browser_counter = [0]

                    def _make_conn(directory):
                        browser_counter[0] += 1
                        fb = FixtureBrowser()
                        fb.client = f"oaiapp_r8_{browser_counter[0]}"
                        return Connection(
                            directory,
                            transport=transport,
                            verifier=FixtureVerifier(),
                            browser=fb,
                            host_probe=lambda: host,
                        )

                    backend = ProfileBackend(state_root, connection=_make_conn)
                    backend.connect("personal")
                    backend.connect("work")
                    backend.select("personal")
                    view = backend.profiles.snapshot()
                    personal_prof = next(p for p in view.saved if p.label == "personal")
                    self.assertIsNotNone(personal_prof.client_id)
                    personal_dir = personal_prof.directory

                    # Acquire a synthetic lease on personal so the grant is active.
                    job = self._make_probe_job()
                    job.activate()
                    _, conn, binding = backend.profile_connection("personal")
                    lease_cm = conn.session_lease(binding, job)
                    lease_cm.__enter__()

                    if scenario == "missing_state_json":
                        (personal_dir / "state.json").unlink()
                        self.assertTrue((personal_dir / "state.lock").exists())
                    elif scenario == "missing_conn_dir":
                        shutil.rmtree(personal_dir)
                        self.assertFalse(personal_dir.exists())
                    else:
                        rec = json.loads((personal_dir / "state.json").read_text(encoding="utf-8"))
                        rec.pop("worker_leases", None)
                        rec["client"] = "oaiapp_wrongclient"
                        (personal_dir / "state.json").write_text(json.dumps(rec), encoding="utf-8")

                    bound_conn = Connection(
                        personal_dir, host_probe=lambda: host, expected_client=personal_prof.client_id,
                    )
                    self.assertTrue(bound_conn.has_active_leases())
                    with self.assertRaises(ConnError) as req_err:
                        bound_conn.require_switchable()
                    self.assertEqual(req_err.exception.code, "managed_retirement_incomplete")

                    unbound_conn = Connection(personal_dir, host_probe=lambda: host)
                    self.assertTrue(
                        unbound_conn.has_active_leases(expected_client=personal_prof.client_id)
                    )
                    with self.assertRaises(ConnError) as kw_err:
                        unbound_conn.require_switchable(expected_client=personal_prof.client_id)
                    self.assertEqual(kw_err.exception.code, "managed_retirement_incomplete")

                    with self.assertRaises(RouteUnavailable) as sw_err:
                        backend.select("work")
                    self.assertIs(sw_err.exception.reason, Reason.MANAGED_RETIREMENT)
                    job.revoke()

    def test_r8_coordinated_absent_outcome_with_unsettled_hold_stays_unconfirmed(self):
        # Regression (R7 P2 #2): on the coordinated path, an absent worker_leases entry while an
        # unsettled .lease-hold-* exists on disk (either BEFORE session_lease.__exit__ OR planted
        # AFTER exit recorded "absent" and BEFORE _finalize_slot_hold) MUST stay unconfirmed,
        # publish NO .lease-settled-* receipt, retain slot_root, and keep fresh readers blocked.
        import pwd
        from oc_openai import connection_state as cs_mod
        from oc_openai.connection import Connection

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        for timing in ("hold_before_exit", "hold_after_absent_before_finalize", "clean_absent_no_hold"):
            with self.subTest(timing=timing):
                with tempfile.TemporaryDirectory(prefix=f"oc-r8-abs-{timing}-", dir=home) as home_raw:
                    home_scratch = Path(home_raw)
                    os.chmod(home_scratch, 0o700)
                    _, adapter, pref, personal_dir, host = self._make_real_openai_adapter_fixture(
                        home_scratch / "profiles",
                    )
                    slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
                    self.addCleanup(lambda sr=slot_root: shutil.rmtree(sr, ignore_errors=True))
                    coord = _SessionSlotCoordinator(threading.Event())
                    slot_cm = adapter.open_slot(
                        pref, slot_index=0, slot_root=slot_root, port=8401,
                        worker_token="tok-r8abs-" + "a" * 24,
                        acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
                    )
                    handle = slot_cm.__enter__()
                    coord.register_slot(slot_cm, handle, slot_root, allow_legacy=True)
                    coord.record_container("7" * 64, slot_index=0)
                    handle.job.activate()

                    # Remove worker_leases[root] from state.json so exit observes root_absent.
                    st_path = personal_dir / "state.json"
                    rec = json.loads(st_path.read_text(encoding="utf-8"))
                    rec.pop("worker_leases", None)
                    st_path.write_text(json.dumps(rec), encoding="utf-8")

                    def _plant_unsettled_hold() -> Path:
                        hid = "ef" * 16
                        hp = personal_dir / f".lease-hold-{hid}"
                        payload = json.dumps({
                            "version": 1, "state": "hold", "hold_id": hid,
                            "root": handle.job.root.name, "incarnation": handle.job.incarnation,
                        }).encode("utf-8") + b"\n"
                        fd = os.open(hp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        try:
                            os.write(fd, payload)
                        finally:
                            os.close(fd)
                        return hp

                    if timing == "hold_before_exit":
                        _plant_unsettled_hold()
                        with patch.object(session_broker, "_remove_container_verified"):
                            err = coord.teardown_all(None)
                    elif timing == "hold_after_absent_before_finalize":
                        with patch.object(session_broker, "_remove_container_verified"):
                            coord.on_revoke(0)
                            for t in list(coord._retire_threads):
                                t.join(timeout=3.0)
                        _plant_unsettled_hold()
                        with patch.object(session_broker, "_remove_container_verified"):
                            err = coord.teardown_all(None)
                    else:
                        with patch.object(session_broker, "_remove_container_verified"):
                            err = coord.teardown_all(None)

                    settled_files = [
                        p.name for p in personal_dir.iterdir() if p.name.startswith(".lease-settled-")
                    ]
                    self.assertEqual(settled_files, [])

                    if timing == "clean_absent_no_hold":
                        self.assertIsNone(err)
                        self.assertTrue(coord._slots[0].lease_confirmed_released)
                        self.assertTrue(handle.lease_release_confirmed())
                        fresh = Connection(personal_dir, host_probe=lambda: host)
                        self.assertFalse(fresh.has_active_leases())
                    else:
                        self.assertIsNotNone(err)
                        self.assertFalse(coord._slots[0].lease_confirmed_released)
                        self.assertFalse(handle.lease_release_confirmed())
                        coord.remove_slot_roots(require_confirmed_leases=True)
                        self.assertTrue(slot_root.exists())
                        self._assert_fresh_reader_blocked(personal_dir, host, pref.handle.binding)

    def test_r9_disconnect_missing_bound_state_or_unsettled_hold_fails_closed_and_keeps_switch_blocked(self):
        # Regression (R8 P2): ProfileBackend.disconnect (targeted and bare) MUST require the matching
        # bound connection record and zero unsettled holds before marking a published profile retiring,
        # so missing dir/state.json, mismatched client, or unsettled holds cannot clear the guard and
        # unblock later select(). Unpublished candidates without state.json still disconnect cleanly.
        import pwd
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier
        from oc_openai.cli import Reason, RouteUnavailable
        from oc_openai.connection import Connection
        from oc_openai.connection_job import PhysicalHost
        from oc_openai.profile_backend import ProfileBackend

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")

        with tempfile.TemporaryDirectory(prefix="oc-r9-disc-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)

            for disconnect_mode in ("targeted", "bare"):
                for scenario in ("missing_state_json", "missing_conn_dir", "mismatched_client", "unsettled_hold"):
                    with self.subTest(disconnect_mode=disconnect_mode, scenario=scenario):
                        state_root = home_scratch / f"profiles_{disconnect_mode}_{scenario}"
                        state_root.mkdir(mode=0o700)
                        transport = FixtureTransport()
                        browser_counter = [0]

                        def _make_conn(directory):
                            browser_counter[0] += 1
                            fb = FixtureBrowser()
                            fb.client = f"oaiapp_r9_{browser_counter[0]}"
                            return Connection(
                                directory,
                                transport=transport,
                                verifier=FixtureVerifier(),
                                browser=fb,
                                host_probe=lambda: host,
                            )

                        backend = ProfileBackend(state_root, connection=_make_conn)
                        backend.connect("personal")
                        backend.connect("work")
                        backend.select("personal")
                        view = backend.profiles.snapshot()
                        personal_prof = next(p for p in view.saved if p.label == "personal")
                        personal_dir = personal_prof.directory

                        if scenario == "missing_state_json":
                            (personal_dir / "state.json").unlink()
                            self.assertTrue((personal_dir / "state.lock").exists())
                        elif scenario == "missing_conn_dir":
                            shutil.rmtree(personal_dir)
                            self.assertFalse(personal_dir.exists())
                        elif scenario == "mismatched_client":
                            rec = json.loads((personal_dir / "state.json").read_text(encoding="utf-8"))
                            rec["client"] = "oaiapp_wrongclient"
                            (personal_dir / "state.json").write_text(json.dumps(rec), encoding="utf-8")
                        else:
                            hid = "ab" * 16
                            hp = personal_dir / f".lease-hold-{hid}"
                            payload = json.dumps({
                                "version": 1, "state": "hold", "hold_id": hid,
                                "root": "oc-chat-deadbeef", "incarnation": "inc_" + "3" * 32,
                            }).encode("utf-8") + b"\n"
                            fd = os.open(hp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                            try:
                                os.write(fd, payload)
                            finally:
                                os.close(fd)

                        with self.assertRaises(RouteUnavailable) as disc_err:
                            if disconnect_mode == "targeted":
                                backend.disconnect("personal")
                            else:
                                backend.disconnect()
                        self.assertIs(disc_err.exception.reason, Reason.MANAGED_RETIREMENT)

                        after = backend.profiles.snapshot()
                        personal_after = next(p for p in after.saved if p.label == "personal")
                        self.assertFalse(personal_after.retiring)
                        self.assertEqual(after.active.label if after.active else None, "personal")

                        with self.assertRaises(RouteUnavailable) as sw_err:
                            backend.select("work")
                        self.assertIs(sw_err.exception.reason, Reason.MANAGED_RETIREMENT)

            # Unpublished candidate without state.json still disconnects cleanly.
            unpub_root = home_scratch / "profiles_unpub"
            unpub_root.mkdir(mode=0o700)
            unpub_backend = ProfileBackend(
                unpub_root,
                connection=lambda directory: Connection(
                    directory,
                    transport=FixtureTransport(),
                    verifier=FixtureVerifier(),
                    browser=FixtureBrowser(),
                    host_probe=lambda: host,
                ),
            )
            unpub_backend.profiles.begin("draft")
            self.assertTrue(unpub_backend.disconnect("draft"))

    def test_r10_persisted_retiring_profile_checked_during_switch_and_publish(self):
        # Regression (R9 residual P2): a previously persisted published profile with retiring=True
        # MUST still be verified (matching bound state + zero holds) during select() and publish()
        # all-profile idle checks, while a cleanly verified retired profile allows select/publish.
        import pwd
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier
        from oc_openai.cli import Reason, RouteUnavailable
        from oc_openai.connection import Connection
        from oc_openai.connection_job import PhysicalHost
        from oc_openai.profile_backend import ProfileBackend

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")

        with tempfile.TemporaryDirectory(prefix="oc-r10-ret-", dir=home) as home_raw:
            home_scratch = Path(home_raw)
            os.chmod(home_scratch, 0o700)

            for scenario in (
                "missing_state_json",
                "missing_conn_dir",
                "mismatched_client",
                "unsettled_hold",
                "clean_verified_retirement",
            ):
                with self.subTest(scenario=scenario):
                    state_root = home_scratch / f"profiles_{scenario}"
                    state_root.mkdir(mode=0o700)
                    transport = FixtureTransport()
                    browser_counter = [0]

                    def _make_conn(directory):
                        browser_counter[0] += 1
                        fb = FixtureBrowser()
                        fb.client = f"oaiapp_r10_{browser_counter[0]}"
                        return Connection(
                            directory,
                            transport=transport,
                            verifier=FixtureVerifier(),
                            browser=fb,
                            host_probe=lambda: host,
                        )

                    backend = ProfileBackend(state_root, connection=_make_conn)
                    backend.connect("personal")
                    backend.connect("work")
                    backend.connect("extra")
                    backend.select("extra")

                    # Cleanly retire "personal" first (persisting retiring=True in profiles/state.json).
                    self.assertTrue(backend.disconnect("personal"))
                    view = backend.profiles.snapshot()
                    personal_prof = next(p for p in view.saved if p.label == "personal")
                    self.assertTrue(personal_prof.retiring)
                    personal_dir = personal_prof.directory

                    if scenario == "missing_state_json":
                        (personal_dir / "state.json").unlink()
                    elif scenario == "missing_conn_dir":
                        shutil.rmtree(personal_dir)
                    elif scenario == "mismatched_client":
                        rec = json.loads((personal_dir / "state.json").read_text(encoding="utf-8"))
                        rec["client"] = "oaiapp_wrongclient"
                        (personal_dir / "state.json").write_text(json.dumps(rec), encoding="utf-8")
                    elif scenario == "unsettled_hold":
                        hid = "bc" * 16
                        hp = personal_dir / f".lease-hold-{hid}"
                        payload = json.dumps({
                            "version": 1, "state": "hold", "hold_id": hid,
                            "root": "oc-chat-deadbeef", "incarnation": "inc_" + "4" * 32,
                        }).encode("utf-8") + b"\n"
                        fd = os.open(hp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        try:
                            os.write(fd, payload)
                        finally:
                            os.close(fd)

                    if scenario == "clean_verified_retirement":
                        # Positive control: cleanly retired published profile allows both select() and publish().
                        backend.select("work")
                        self.assertEqual(backend.active_label(), "work")
                        backend.connect("fresh")
                        self.assertEqual(backend.active_label(), "fresh")
                    else:
                        # Negative controls: select() AND publish() (via connect) MUST fail closed!
                        with self.assertRaises(RouteUnavailable) as sel_err:
                            backend.select("work")
                        self.assertIs(sel_err.exception.reason, Reason.MANAGED_RETIREMENT)
                        self.assertEqual(backend.active_label(), "extra")

                        with self.assertRaises(RouteUnavailable) as pub_err:
                            backend.connect("fresh")
                        self.assertIs(pub_err.exception.reason, Reason.MANAGED_RETIREMENT)
                        self.assertEqual(backend.active_label(), "extra")

    def test_proof_gate_evidence_and_dir_sync_failure_fails_closed_with_zero_dispatch(self):
        # Regression (R4 P2 #2): evidence write failure OR post-write _fsync_dir failure during
        # ProofGate.arm() or ProofGate.mark_relay_verified() MUST fail permanently closed across
        # in-memory state AND the prior SessionBroker listener with zero upstream writes.
        import pwd
        from types import SimpleNamespace
        from oc_openai import proof_gate as pg_mod
        from oc_openai.proof_gate import ProofGate, _normalize_instructions, compute_exposure_history_digest
        from oc_openai.session_broker import SessionBroker, SessionPolicy

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        home_td = self.enterContext(tempfile.TemporaryDirectory(prefix="oc-mix-evfail-", dir=home))
        os.chmod(home_td, 0o700)
        exp_dir = Path(home_td) / "exp"
        exp_dir.mkdir(mode=0o700)
        ev_dir = Path(home_td) / "ev"
        ev_dir.mkdir(mode=0o700)
        instr = (
            "Today's date: Thu Nov 26 2026\n"
            "  Working directory: /sandbox/workspace\n"
            "  Workspace root folder: /sandbox/workspace\n"
        )
        norm_instr = _normalize_instructions(instr, expected_cwd="workspace")
        assert norm_instr is not None
        approval = ProofApproval(
            run_id=secrets.token_hex(16), instance_label="personal",
            scoped_provider_id="openai--personal", approved_model="gpt-6.2-sol",
            ui_mode="mini", cwd="workspace", selection_epoch="ep1", credential_generation=1,
            history_digest_all_12_files=compute_exposure_history_digest(exp_dir),
            profile_directory=str(exp_dir), client_id="client-1",
        )
        tok = "tok-evf-" + "a" * 24
        prod_body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "instructions": instr, "input": [{"role": "user", "content": PROOF_PROMPT}],
        }).encode("utf-8")
        prod_req = _make_http_request(method="POST", path="/v1/responses", port=8401, token=tok, body=prod_body)

        for label, phase, fail_mode in (
            ("arm_write", "arm", "write"),
            ("arm_dirsync", "arm", "dirsync"),
            ("verify_write", "verify", "write"),
            ("verify_dirsync", "verify", "dirsync"),
        ):
            slot_root = self.root / f"evfail_{label}"
            slot_root.mkdir(mode=0o700)
            inc = "inc_" + secrets.token_hex(16)
            job = _SessionJob(slot_root, inc)
            job.prepare(config_payload=None)
            self.addCleanup(job.revoke)
            job.activate()
            writes: list[dict] = []

            class _FakeConn:
                def require_active(self, _binding):
                    return None

                @contextmanager
                def interactive_responses(self, _binding, body, before_write, **kwargs):
                    before_write()
                    writes.append(body)
                    yield iter(())

            pg = ProofGate(
                approval, evidence_dir=ev_dir, exposure_dir=exp_dir,
                check_owner_alive=lambda: None,
                expected_instructions_sha256=sha256(norm_instr.encode("utf-8")).hexdigest(),
            )
            pg.bind_incarnation(inc, job.generation)
            sb = SessionBroker(
                socket_path=job.provider_socket, relay_proof=job.relay_proof,
                worker_token=tok, lease=job.lease, connection=_FakeConn(),
                binding=SimpleNamespace(generation=1), models=("gpt-6.2-sol",),
                profile_label="personal", expected_port=8401,
                policy=SessionPolicy(
                    proof_gate=pg, job_incarnation=inc,
                    exposure_dir=exp_dir,
                    acknowledged_exposure_digest=approval.history_digest_all_12_files,
                ),
            )
            sb.start()
            self.addCleanup(sb.close)
            if phase == "verify":
                pg.arm(observed_row="openai--personal/gpt-6.2-sol", observed_screen_digest="2" * 64)

            queued = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            queued.settimeout(3.0)
            self.addCleanup(queued.close)
            queued.connect(str(job.provider_socket))

            if fail_mode == "write":
                patch_ctx = patch.object(pg_mod, "_atomic_fsync_json", side_effect=OSError("evidence write failed"))
            else:
                patch_ctx = patch.object(pg_mod, "_fsync_dir", side_effect=OSError("post-write dir fsync failed"))
            with patch_ctx:
                with self.assertRaises(OSError):
                    if phase == "arm":
                        pg.arm(observed_row="openai--personal/gpt-6.2-sol", observed_screen_digest="2" * 64)
                    else:
                        pg.mark_relay_verified("4" * 64)

            snap = pg.snapshot_arrival()
            self.assertEqual(snap.state, pg_mod.STATE_SPENT, f"{label}: must fail closed to STATE_SPENT")
            self.assertFalse(snap.relay_verified, f"{label}: relay_verified must stay False")
            self.assertIsNone(snap.arm_nonce, f"{label}: arm_nonce must be cleared")
            self.assertTrue(sb._revoked.is_set(), f"{label}: broker must be revoked on publication failure")
            with suppress(OSError):
                queued.sendall(relay_mod.PROOF_PREFIX + job.relay_proof + REQUEST_LENGTH.pack(len(prod_req)) + prod_req)
                resp = queued.recv(4096)
                self.assertNotIn(b"200 OK", resp)
            # Also confirm a fresh client cannot dispatch after failed publication!
            with suppress(OSError):
                fresh_resp = _send_framed_uds(job.provider_socket, job.relay_proof, prod_req)
                self.assertNotIn(b"200 OK", fresh_resp)
            self.assertEqual(writes, [], f"{label}: zero upstream writes allowed after failed publication")

    def test_temp_uds_bind_eaddrinuse_preserves_incumbent_socket(self):
        # Regression (R4 P3): temporary UDS bind EADDRINUSE must NEVER unlink an incumbent socket.
        import errno
        from types import SimpleNamespace
        from oc_openai.session_broker import SessionBroker

        slot_root = self.root / "eaddrinuse_slot"
        slot_root.mkdir(mode=0o700)
        job = _SessionJob(slot_root, "inc_" + secrets.token_hex(16))
        job.prepare(config_payload=None)
        self.addCleanup(job.revoke)
        job.activate()
        tok = "tok-eau-" + "a" * 24

        incumbent_path = job.provider_socket.parent / "s.deadbeef"
        incumbent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        incumbent.bind(str(incumbent_path))
        incumbent.listen(1)
        self.addCleanup(incumbent.close)
        self.addCleanup(lambda: incumbent_path.unlink(missing_ok=True))
        incumbent_stat = incumbent_path.lstat()
        incumbent_id = (incumbent_stat.st_dev, incumbent_stat.st_ino)

        class _MinConn:
            def require_active(self, _binding):
                return None

        sb = SessionBroker(
            socket_path=job.provider_socket, relay_proof=job.relay_proof,
            worker_token=tok, lease=job.lease, connection=_MinConn(),
            binding=SimpleNamespace(generation=1), models=(SYNTHETIC_MODEL,),
            profile_label="personal", expected_port=8401,
        )
        sb.start()
        self.addCleanup(sb.close)

        with patch.object(session_broker.secrets, "token_hex", return_value="deadbeef"):
            with self.assertRaises(OSError) as err_ctx:
                sb._rotate_listener_locked()
        self.assertEqual(err_ctx.exception.errno, errno.EADDRINUSE)
        self.assertTrue(incumbent_path.exists(), "EADDRINUSE must never unlink an incumbent socket!")
        after_stat = incumbent_path.lstat()
        self.assertEqual((after_stat.st_dev, after_stat.st_ino), incumbent_id)

        # Same check on _SyntheticSlotBroker.
        synth_root = self.root / "eaddrinuse_synth"
        synth_root.mkdir(mode=0o700)
        sjob = _SessionJob(synth_root, "inc_" + secrets.token_hex(16))
        sjob.prepare(config_payload=None)
        self.addCleanup(sjob.revoke)
        sjob.activate()
        s_inc_path = sjob.provider_socket.parent / "s.cafebabe"
        s_inc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s_inc.bind(str(s_inc_path))
        s_inc.listen(1)
        self.addCleanup(s_inc.close)
        self.addCleanup(lambda: s_inc_path.unlink(missing_ok=True))
        s_inc_id = (s_inc_path.lstat().st_dev, s_inc_path.lstat().st_ino)
        sbroker = _SyntheticSlotBroker(
            socket_path=sjob.provider_socket, relay_proof=sjob.relay_proof,
            worker_token=tok, lease=sjob.lease, models=(SYNTHETIC_MODEL,),
            expected_port=8401, job_incarnation=sjob.incarnation,
            receipt_gate=None, recorder=[],
        )
        sbroker.start()
        self.addCleanup(sbroker.close)
        with patch.object(secrets, "token_hex", return_value="cafebabe"):
            with self.assertRaises(OSError) as serr_ctx:
                sbroker._rotate_listener_locked()
        self.assertEqual(serr_ctx.exception.errno, errno.EADDRINUSE)
        self.assertTrue(s_inc_path.exists())
        self.assertEqual((s_inc_path.lstat().st_dev, s_inc_path.lstat().st_ino), s_inc_id)

    def test_broker_poll_handles_listener_fd_above_1023_and_revokes_on_fatal_accept(self):
        # Regression (R3 FD > 1023 + fatal accept error): select.poll() handles listener FD >= 1050
        # without hitting FD_SETSIZE=1024, and a fatal accept OSError revokes the broker cleanly.
        import errno
        import resource
        from types import SimpleNamespace
        from oc_openai.session_broker import SessionBroker

        soft_nofile, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        slot_root = self.root / "high_fd_broker"
        slot_root.mkdir(mode=0o700)
        job = _SessionJob(slot_root, "inc_" + secrets.token_hex(16))
        job.prepare(config_payload=None)
        self.addCleanup(job.revoke)
        job.activate()
        tok = "tok-hfd-" + "a" * 24

        class _MinConn:
            def require_active(self, _binding):
                return None

        sb = SessionBroker(
            socket_path=job.provider_socket,
            relay_proof=job.relay_proof,
            worker_token=tok,
            lease=job.lease,
            connection=_MinConn(),
            binding=SimpleNamespace(generation=1),
            models=(SYNTHETIC_MODEL,),
            profile_label="personal",
            expected_port=8401,
        )
        sb.start()
        self.addCleanup(sb.close)

        if soft_nofile > 1060:
            # Move listener onto FD >= 1050 (which breaks select.select!) and prove poll() still serves!
            old_listener = sb._listener
            assert old_listener is not None
            high_fd = fcntl.fcntl(old_listener.fileno(), fcntl.F_DUPFD_CLOEXEC, 1050)
            self.assertGreaterEqual(high_fd, 1050)
            high_sock = socket.socket(fileno=high_fd)
            high_sock.setblocking(False)
            sb._listener = high_sock
            getattr(sb, "_wake_accept_loop", lambda: None)()
            old_listener.close()
            models_req = _make_http_request(method="GET", path="/v1/models", port=8401, token=tok)
            resp = _send_framed_uds(job.provider_socket, job.relay_proof, models_req)
            self.assertIn(b"200 OK", resp)
            self.assertFalse(sb._revoked.is_set())

        # Fatal accept OSError (not BlockingIOError) MUST trigger broker revocation instead of silent dead loop.
        class _FatalListener:
            def fileno(self):
                return sb._listener.fileno() if sb._listener is not None else -1

            def accept(self):
                raise OSError(errno.EMFILE, "too many open files")

            def close(self):
                pass

        saved_listener = sb._listener
        sb._listener = _FatalListener()
        try:
            peer = sb._try_accept_nonblocking()
            self.assertIsNone(peer)
            self.assertTrue(sb._revoked.is_set(), "fatal accept OSError must revoke broker")
        finally:
            sb._listener = saved_listener

    def test_post_hardening_validation_blocks_tampered_proof_config_before_container_create(self):
        gg_spec = _spec_obj("google", "personal")
        pref = InstancePreflight(gg_spec, ReadinessState.READY, (SYNTHETIC_MODEL,), route_policy="sub")
        plan = ResolvedLaunchPlan(
            admitted=(pref,), excluded=(), initial_provider_id="google--personal",
            initial_model=SYNTHETIC_MODEL, ui_mode="mini", ui_source="--mini", acknowledged_digests={},
        )

        class _GoodAdapter:
            def provider_config_entry(self, pf, *, port, worker_token, display_label=None):
                return {
                    "name": expected_provider_display_name(pf, display_label or pf.spec.label),
                    "package": "@opencode/ai/providers/openai-compatible/responses",
                    "settings": {"baseURL": f"http://127.0.0.1:{port}/v1", "apiKey": worker_token, "store": False},
                    "models": {
                        SYNTHETIC_MODEL: {
                            "name": SYNTHETIC_MODEL,
                            "capabilities": {"tools": True, "input": ["text"], "output": ["text"]},
                            "limit": {"context": 128000, "output": 16384},
                        }
                    },
                }

        class _TamperedProofGate:
            approval = ProofApproval(
                run_id="1" * 32,
                instance_label="personal",
                scoped_provider_id="google--personal",
                approved_model=SYNTHETIC_MODEL,
                ui_mode="mini",
                cwd="wt/synth",
                selection_epoch="epoch-1",
                credential_generation=1,
                history_digest_all_12_files="e" * 64,
                auth_mode="subscription",
                providers_config_digest="d" * 64,
            )

            def harden_opencode_config(self, cfg):
                # Tamper: leave `mcp` present and `tools: True`!
                return dict(cfg)

        podman_calls: list[tuple] = []
        sess_root = self.root / "post_harden_sess"
        sess_root.mkdir(mode=0o700)
        cleanup_state = {"clean": False, "proof_options": ProofSessionOptions(proof_gate=_TamperedProofGate())}
        term = StreamTerminal(io.StringIO(), io.StringIO(), io.StringIO())
        with (
            patch.object(session_broker, "_verify_pod_with_containers", return_value=("1" * 64, [])),
            patch.object(session_broker, "podman", side_effect=lambda *a, **_kw: podman_calls.append(a)),
        ):
            with self.assertRaises(ProviderIntegrityError):
                session_broker._run_multi_slot_session(
                    _make_launch_spec(), plan, {"google": _GoodAdapter()}, sess_root,
                    threading.Event(), term, cleanup_state,
                )
        self.assertEqual(podman_calls, [], "Tampered hardened config must abort before any Podman call")

    def test_relay_mcs_allocation_and_security_opt_validation(self):
        agent_level = "s0:c11,c22"
        lvl = session_broker._random_relay_mcs_level(agent_level)
        self.assertRegex(lvl, r"^s0:c\d+,c\d+$")
        self.assertNotEqual(lvl, agent_level)
        self.assertTrue(session_broker._valid_relay_security_opt(["no-new-privileges"], lvl))
        self.assertTrue(session_broker._valid_relay_security_opt(["no-new-privileges", f"label=level:{lvl}"], lvl))
        self.assertTrue(session_broker._valid_relay_security_opt([f"label=level:{lvl}", "no-new-privileges"], lvl))
        for bad_opt in (
            ["label=disable"],
            ["no-new-privileges", "label=disable"],
            ["no-new-privileges", "seccomp=unconfined"],
            ["no-new-privileges", f"label=level:{agent_level}"],
            ["no-new-privileges", f"label=level:{lvl}", "extra"],
            "no-new-privileges",
        ):
            self.assertFalse(session_broker._valid_relay_security_opt(bad_opt, lvl), f"accepted {bad_opt!r}")


def _synthetic_mini_prereqs_ready() -> tuple[bool, str]:
    if os.environ.get("OC_RUN_SYNTHETIC_MINI_PROOF") != "1":
        return False, "Set OC_RUN_SYNTHETIC_MINI_PROOF=1 inside devbox to run the real-Podman synthetic Mini proof"
    try:
        check_devbox()
        check_host()
    except Exception as exc:
        return False, f"devbox/SELinux host prerequisite unavailable: {exc}"
    return True, ""


class _SyntheticMiniProofGate:
    """In-process proof gate matching ProofGateProtocol for the synthetic --network=none Mini proof."""

    def __init__(self, approval: ProofApproval):
        self.approval = approval
        self.armed = False
        self.verified_relay_id: str | None = None
        self.observed_row: str | None = None
        self.observed_screen_digest: str | None = None

    def harden_opencode_config(self, config_payload: dict) -> dict:
        hardened = json.loads(json.dumps(config_payload))
        hardened.pop("mcp", None)
        hardened["model"] = f"{self.approval.scoped_provider_id}/{self.approval.approved_model}"
        hardened["snapshots"] = False
        hardened["permissions"] = [{"action": "*", "resource": "*", "effect": "deny"}]
        hardened["plugins"] = ["-opencode.tool.*"]
        for pdef in hardened["providers"].values():
            for mdef in pdef["models"].values():
                mdef["capabilities"]["tools"] = False
        return hardened

    def verify_ready_for_arm(self) -> None:
        if self.armed:
            raise ProofGateError("proof_gate_already_armed")

    def arm(self, *, observed_row: str, observed_screen_digest: str) -> str:
        self.observed_row = observed_row
        self.observed_screen_digest = observed_screen_digest
        self.armed = True
        return secrets.token_hex(16)

    def mark_relay_verified(self, relay_id: str) -> None:
        self.verified_relay_id = relay_id


class _SyntheticPodAdapter:
    """Full 10-hook opaque SlotHandle adapter backed by _SyntheticSlotBroker for real-Podman Mini proof."""

    def __init__(
        self,
        kind: ProviderId,
        *,
        preflights: dict[str, InstancePreflight],
        approved_scoped_id: str,
        recorder: list[dict],
        opaque_handle: bool,
    ):
        self.kind = kind
        self._preflights = preflights
        self._approved_scoped_id = approved_scoped_id
        self.recorder = recorder
        self._opaque = opaque_handle
        self.active_turn_gate: _OwnerChallengedReceiptGate | None = None
        self.active_turn_incarnation: str | None = None
        self.active_turn_broker: _SyntheticSlotBroker | None = None
        self.slot_tokens_seen: dict[str, str] = {}
        self.slot_ports_seen: dict[str, int] = {}

    def is_qualified(self, auth_mode: str, placement: str) -> bool:
        return auth_mode == "subscription" and placement == "sandbox"

    def active_label(self) -> str | None:
        return next(iter(self._preflights), None)

    def selection_state(self) -> PersistedSelection:
        lbl = self.active_label()
        return PersistedSelection(SelectionState.SELECTED, label=lbl) if lbl else PersistedSelection(SelectionState.UNSET)

    def discover_instances(self) -> tuple[ProviderInstanceSpec, ...]:
        return tuple(pf.spec for pf in self._preflights.values())

    def preflight_instance(self, instance: ProviderInstanceSpec) -> InstancePreflight:
        return self._preflights.get(instance.label, InstancePreflight(instance, ReadinessState.DISCONNECTED))

    def provider_config_entry(
        self, preflight: InstancePreflight, *, port: int, worker_token: str, display_label: str | None = None,
    ) -> dict:
        self.slot_tokens_seen[preflight.spec.scoped_id] = worker_token
        self.slot_ports_seen[preflight.spec.scoped_id] = port
        label = display_label or preflight.spec.label
        return {
            "name": expected_provider_display_name(preflight, label),
            "package": "@opencode/ai/providers/openai-compatible/responses",
            "settings": {"baseURL": f"http://127.0.0.1:{port}/v1", "apiKey": worker_token, "store": False},
            "models": {
                slug: {
                    "name": slug,
                    "capabilities": {"tools": True, "input": ["text"], "output": ["text"]},
                    "limit": {"context": 128000, "output": 16384},
                }
                for slug in preflight.models
            },
        }

    @staticmethod
    def _lease_route_state(job: _SessionJob) -> SlotRouteState:
        if job.lease is None:
            return "retired"
        st = job.lease.status()
        if st == "pending":
            return "pending" if job.lease.deadline_ns > time.monotonic_ns() else "retired"
        if st == "active":
            return "active" if job.lease.active() else "retired"
        return "retired"

    def _select_gate_and_refusal(self, scoped_id: str, inc: str, *, discovery_only: bool, supervisor_before_write=None):
        if scoped_id != self._approved_scoped_id:
            return None, "proof_slot_not_approved"
        if discovery_only:
            return None, "proof_gate_not_armed"
        gate = _OwnerChallengedReceiptGate(
            approved_scoped_id=self._approved_scoped_id,
            expected_relay_id="",
            job_incarnation=inc,
            supervisor_before_write=supervisor_before_write,
        )
        self.active_turn_gate = gate
        self.active_turn_incarnation = inc
        return gate, None

    @contextmanager
    def _open_phase(self, preflight: InstancePreflight, cfg: dict, *, discovery_only: bool):
        from oc_openai.session_adapter import _SlotReleaseGate

        slot_index = int(cfg["slot_index"])
        slot_root = Path(cfg["slot_root"])
        port = int(cfg["port"])
        worker_token = str(cfg["worker_token"])
        slot_root.mkdir(mode=0o700, exist_ok=True)
        inc = "inc_" + secrets.token_hex(16)
        job = _SessionJob(slot_root, inc)
        job.prepare(config_payload=None)
        defer_bind = preflight.spec.scoped_id == self._approved_scoped_id and not discovery_only
        broker_box: list[_SyntheticSlotBroker | None] = [None]

        def _supervisor_before_write(*, claim_token: str, job_incarnation: str) -> None:
            active_broker = broker_box[0]
            if (
                active_broker is None
                or active_broker.is_revoked()
                or job.lease is None
                or not job.lease.active()
                or job_incarnation != inc
            ):
                raise ProofGateError("proof_gate_revoked")

        receipt_gate, refusal_code = self._select_gate_and_refusal(
            preflight.spec.scoped_id, inc, discovery_only=discovery_only,
            supervisor_before_write=_supervisor_before_write,
        )
        broker = _SyntheticSlotBroker(
            socket_path=job.provider_socket,
            relay_proof=job.relay_proof,
            worker_token=worker_token,
            lease=job.lease,
            models=preflight.models,
            expected_port=port,
            job_incarnation=inc,
            receipt_gate=receipt_gate,
            recorder=self.recorder,
            refusal_code=refusal_code,
        )
        broker_box[0] = broker
        broker.start()
        if defer_bind:
            self.active_turn_broker = broker

        release_gate = _SlotReleaseGate()

        def build_relay_args(spec: dict) -> list[str]:
            return _build_relay_args(
                spec,
                job,
                slot_index=slot_index,
                port=port,
                provider_label=preflight.spec.qualified_name,
                relay_name_override=(f"{spec['pod']}-relay-disc-{slot_index}" if discovery_only else None),
                defer_bind=defer_bind,
            )

        try:
            yield SlotHandle(
                slot_index=slot_index,
                scoped_id=preflight.spec.scoped_id,
                provider_label=preflight.spec.qualified_name,
                port=port,
                job=object() if self._opaque else job,
                broker=object() if self._opaque else broker,
                lease=object() if self._opaque else job.lease,
                build_relay_args=build_relay_args,
                mark_relay_created=release_gate.mark_relay_created,
                confirm_relay_removed=release_gate.confirm_relay_removed,
                authorize_lease_release=release_gate.authorize_release,
                deny_lease_release=release_gate.deny_release,
                bind_release_authority=release_gate.bind_authority,
                lease_release_confirmed=release_gate.is_release_confirmed,
                relay_paths=RelayMountPaths(
                    source_dir=job.source_dir,
                    provider_socket=job.provider_socket,
                    grant_dir=job.grant,
                    proof_file=job.proof_file,
                ),
                revoke_grant=job.revoke,
                close_broker=broker.close,
                activate_route=job.activate,
                route_state=lambda: self._lease_route_state(job),
                is_revoked=broker.is_revoked,
                has_active_clients=broker.has_active_clients,
            )
        finally:
            try:
                job.revoke()
            except Exception:
                release_gate.deny_release()
            try:
                broker.close()
            except Exception:
                release_gate.deny_release()
            if release_gate.allows_release():
                release_gate.record_outcome("removed")
            else:
                release_gate.record_outcome("retained_gate_closed")

    @contextmanager
    def open_slot(self, preflight, *, slot_index, slot_root, port, worker_token, acknowledged_exposure_digest, on_revoke):
        cfg = {"slot_index": slot_index, "slot_root": slot_root, "port": port, "worker_token": worker_token}
        with self._open_phase(preflight, cfg, discovery_only=False) as handle:
            yield handle

    @contextmanager
    def open_discovery_slot(self, preflight, *, slot_index, slot_root, port, worker_token, acknowledged_exposure_digest, on_revoke):
        cfg = {"slot_index": slot_index, "slot_root": slot_root, "port": port, "worker_token": worker_token}
        with self._open_phase(preflight, cfg, discovery_only=True) as handle:
            yield handle


def _exec_in_container(cid: str, py_code: str, *, timeout: int = 10) -> subprocess.CompletedProcess:
    return podman("exec", cid, "python3", "-c", py_code, check=False, timeout=timeout)


def _in_pod_http_probe(cid: str, *, method: str, port: int, path: str, token: str, body: dict | None = None, extra_headers: dict | None = None) -> tuple[int, str]:
    payload = json.dumps({
        "method": method, "port": port, "path": path, "token": token,
        "body": body, "extra_headers": extra_headers or {},
    })
    probe = (
        "import http.client, json, sys\n"
        f"cfg = json.loads({payload!r})\n"
        "conn = http.client.HTTPConnection('127.0.0.1', cfg['port'], timeout=5)\n"
        "headers = {'Authorization': 'Bearer ' + cfg['token'], **cfg['extra_headers']}\n"
        "raw = None\n"
        "if cfg['body'] is not None:\n"
        "    raw = json.dumps(cfg['body']).encode('utf-8')\n"
        "    headers['Content-Type'] = 'application/json'\n"
        "conn.request(cfg['method'], cfg['path'], body=raw, headers=headers)\n"
        "resp = conn.getresponse()\n"
        "data = resp.read().decode('utf-8', errors='replace')\n"
        "print(json.dumps({'status': resp.status, 'body': data}))\n"
    )
    res = _exec_in_container(cid, probe, timeout=10)
    if res.returncode != 0:
        raise AssertionError(f"in-pod probe failed: rc={res.returncode} err={res.stderr.decode(errors='replace')}")
    parsed = json.loads(res.stdout.decode("utf-8"))
    return int(parsed["status"]), str(parsed["body"])


def _inspect_mini_session_export(
    *,
    volume_name: str,
    level: str,
    cwd: str,
    agent_image_id: str,
    expected_provider_id: str,
    expected_model: str,
) -> dict:
    """Corroborate OpenCode Mini session export in a read-only --network=none --tmpfs /sandbox container."""
    inspect_script = (
        "import json, os, shutil, subprocess, sys\n"
        "cwd = sys.argv[1]\n"
        "os.makedirs(os.path.join('/sandbox', cwd), exist_ok=True)\n"
        "dst = '/tmp/home/.local/share/opencode'\n"
        "os.makedirs(dst, exist_ok=True)\n"
        "src = '/src-home/.local/share/opencode'\n"
        "for name in ('opencode.db', 'opencode.db-wal', 'opencode.db-shm'):\n"
        "    p = os.path.join(src, name)\n"
        "    if os.path.exists(p):\n"
        "        shutil.copy2(p, os.path.join(dst, name))\n"
        "env = dict(os.environ, HOME='/tmp/home', XDG_DATA_HOME='/tmp/home/.local/share')\n"
        "workdir = os.path.join('/sandbox', cwd)\n"
        "listed = subprocess.run(['opencode', '--standalone', 'session', 'list', '--format', 'json'],\n"
        "                        cwd=workdir, env=env, capture_output=True, text=True, check=True)\n"
        "sessions = json.loads(listed.stdout)\n"
        "if not isinstance(sessions, list) or len(sessions) != 1:\n"
        "    raise SystemExit(f'expected 1 session, got {len(sessions) if isinstance(sessions, list) else None}')\n"
        "sid = sessions[0]['id']\n"
        "exported = subprocess.run(['opencode', '--standalone', 'session', 'export', sid],\n"
        "                          cwd=workdir, env=env, capture_output=True, text=True, check=True)\n"
        "sys.stdout.write(exported.stdout)\n"
    )
    res = podman(
        "run", "--rm", "--pull=never", "--network=none", "--http-proxy=false",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--security-opt", f"label=level:{level}",
        "--pids-limit=128", "--memory=512m",
        "--tmpfs", "/sandbox:rw,nosuid,nodev,noexec,size=4m,mode=0700",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=0700",
        "-v", f"{volume_name}:/src-home:ro",
        "--entrypoint", "python3",
        agent_image_id, "-I", "-c", inspect_script, cwd,
        timeout=30,
    )
    export_data = json.loads(res.stdout.decode("utf-8"))
    msgs = export_data.get("messages")
    if not isinstance(msgs, list) or len(msgs) not in (2, 3):
        raise AssertionError(f"Unexpected exported message count: {msgs!r}")
    if msgs[0].get("type") != "user" or msgs[0].get("text") != PROOF_PROMPT:
        raise AssertionError(f"Unexpected exported user message: {msgs[0]!r}")
    asst = msgs[1]
    if asst.get("type") != "assistant" or asst.get("finish") != "stop":
        raise AssertionError(f"Unexpected exported assistant message: {asst!r}")
    if asst.get("model") != {"id": expected_model, "providerID": expected_provider_id}:
        raise AssertionError(f"Unexpected exported model route: {asst.get('model')!r}")
    content = asst.get("content")
    if (
        not isinstance(content, list)
        or len(content) != 1
        or content[0].get("type") != "text"
        or content[0].get("text") != EXPECTED_REPLY
    ):
        raise AssertionError(f"Unexpected exported assistant content: {content!r}")
    if len(msgs) == 3 and (msgs[2].get("type") != "idle" or msgs[2].get("outcome") != "succeeded"):
        raise AssertionError(f"Unexpected exported terminal record: {msgs[2]!r}")
    return export_data


class ManagedSupervisorSyntheticMiniProofTests(unittest.TestCase):
    """Section 3.3: Real-Podman `--network=none` managed-supervisor synthetic Mini proof."""

    @staticmethod
    def _wait_container_running(cid: str, *, timeout: float = 20.0) -> str:
        deadline = time.monotonic() + timeout
        status = ""
        while time.monotonic() < deadline:
            status = podman("container", "inspect", "--format", "{{.State.Status}}", cid, check=False).stdout.decode().strip()
            if status == "running":
                return status
            time.sleep(0.1)
        return status

    def _verify_agent_isolation_and_discovery_probes(
        self,
        *,
        agent_id: str,
        disc_relay_id: str,
        plan: ResolvedLaunchPlan,
        oa_adapter: _SyntheticPodAdapter,
        gg_adapter: _SyntheticPodAdapter,
        cwd_rel: str,
        suffix: str,
        sentinel_path: Path,
        sentinel_secret: str,
        openai_rec: list[dict],
        google_rec: list[dict],
    ) -> tuple[int, str, dict]:
        # 1. Verify `--network=none`: zero non-loopback routes in /proc/net/route.
        route_check = _exec_in_container(
            agent_id,
            "lines = [l for l in open('/proc/net/route').read().splitlines()[1:] if l.strip()]; print(len(lines))",
        )
        self.assertEqual(route_check.returncode, 0)
        self.assertEqual(route_check.stdout.decode().strip(), "0", "Pod must have zero non-loopback routes")

        # 2. Verify hardened /etc/opencode/opencode.json inside agent container.
        cfg_raw = _exec_in_container(agent_id, "print(open('/etc/opencode/opencode.json').read())").stdout.decode("utf-8")
        cfg_obj = json.loads(cfg_raw)
        slot_ports = {**oa_adapter.slot_ports_seen, **gg_adapter.slot_ports_seen}
        slot_tokens = {**oa_adapter.slot_tokens_seen, **gg_adapter.slot_tokens_seen}
        validate_opencode_config(
            cfg_obj, plan=plan, slot_ports=slot_ports, slot_tokens=slot_tokens,
            proof_hardened=True, expected_model=f"google--personal/{SYNTHETIC_MODEL}",
        )
        self.assertEqual(cfg_obj["providers"]["openai--personal"]["name"], "ChatGPT Subscription (openai/personal)")
        self.assertEqual(cfg_obj["providers"]["openai--work"]["name"], "ChatGPT Subscription (work)")
        self.assertEqual(cfg_obj["providers"]["google--personal"]["name"], "Google Subscription (google/personal)")
        self.assertNotIn(sentinel_secret, cfg_raw)

        # 3. Positive worker-readable marker + negative host-private sentinel contrast in agent AND relay.
        marker_read = _exec_in_container(agent_id, f"print(open('/sandbox/{cwd_rel}/worker-readable-marker.txt').read().strip())")
        self.assertEqual(marker_read.stdout.decode().strip(), f"marker-{suffix}")
        agent_sentinel = _exec_in_container(agent_id, f"import os; print(os.path.exists({str(sentinel_path)!r}))")
        self.assertEqual(agent_sentinel.stdout.decode().strip(), "False")
        agent_env_raw = _exec_in_container(agent_id, "print(open('/proc/1/environ', 'rb').read().decode('latin-1'))").stdout.decode("latin-1")
        self.assertNotIn(sentinel_secret, agent_env_raw)
        relay_sentinel = _exec_in_container(disc_relay_id, f"import os; print(os.path.exists({str(sentinel_path)!r}))")
        self.assertEqual(relay_sentinel.stdout.decode().strip(), "False")

        # 4. In-pod negative loopback probes during CLOSED_DISCOVERY.
        gg_port = slot_ports["google--personal"]
        oa_port = slot_ports["openai--personal"]
        gg_tok = slot_tokens["google--personal"]
        oa_tok = slot_tokens["openai--personal"]
        turn_body = {"model": SYNTHETIC_MODEL, "stream": True, "store": False, "input": [{"role": "user", "content": PROOF_PROMPT}]}
        st_401, _ = _in_pod_http_probe(agent_id, method="POST", port=gg_port, path="/v1/responses", token=oa_tok, body=turn_body)
        self.assertEqual(st_401, 401)
        st_unselected, b_unselected = _in_pod_http_probe(agent_id, method="POST", port=oa_port, path="/v1/responses", token=oa_tok, body=turn_body)
        self.assertEqual(st_unselected, 403)
        self.assertIn("proof_slot_not_approved", b_unselected)
        st_closed, b_closed = _in_pod_http_probe(agent_id, method="POST", port=gg_port, path="/v1/responses", token=gg_tok, body=turn_body)
        self.assertEqual(st_closed, 403)
        self.assertIn("proof_gate_not_armed", b_closed)
        self.assertEqual((len(openai_rec), len(google_rec)), (0, 0))
        return gg_port, gg_tok, turn_body

    @staticmethod
    def _drain_pty_until_startup_route(master_fd: int, proc, screen, main_decoder, shell_driver, raw_log: bytearray, expected_route: str) -> str:
        ready_deadline = time.monotonic() + 20.0
        rendered = ""
        while time.monotonic() < ready_deadline:
            rlist, _, _ = select.select([master_fd], [], [], 0.15)
            if rlist:
                chunk = os.read(master_fd, 4096)
                if chunk:
                    raw_log.extend(chunk)
                    shell_driver._feed_pty_bytes(screen, main_decoder, chunk, final=False)
                    rendered = screen.render()
                    stripped = shell_driver.strip_ansi(raw_log.decode("utf-8", errors="replace"))
                    if expected_route in stripped and SYNTHETIC_MODEL in stripped:
                        time.sleep(0.4)
                        break
            elif proc.poll() is not None:
                break
        return rendered or shell_driver.strip_ansi(raw_log.decode("utf-8", errors="replace"))

    @staticmethod
    def _read_pty_chunk_nonblocking(master_fd: int) -> bytes | None:
        rlist, _, _ = select.select([master_fd], [], [], 0.15)
        if not rlist:
            return b""
        try:
            return os.read(master_fd, 4096)
        except OSError:
            return None

    @classmethod
    def _wait_pty_exact_ok(cls, master_fd: int, proc, screen, main_decoder, post_screen, post_decoder, shell_driver, raw_log: bytearray, pre_lines: tuple[str, ...]) -> tuple[bool, str]:
        reply_deadline = time.monotonic() + 25.0
        post_text = ""
        rendered = ""
        while time.monotonic() < reply_deadline:
            chunk = cls._read_pty_chunk_nonblocking(master_fd)
            if chunk is None:
                break
            if chunk:
                raw_log.extend(chunk)
                shell_driver._feed_pty_bytes(screen, main_decoder, chunk, final=False)
                shell_driver._feed_pty_bytes(post_screen, post_decoder, chunk, final=False)
                rendered = screen.render()
                post_text = post_screen.render()
                if post_screen.is_certain and shell_driver._has_new_exact_reply(
                    rendered or post_text, pre_lines, post_text, approved_model=SYNTHETIC_MODEL,
                ):
                    time.sleep(0.6)
                    return True, post_text or rendered
            if proc.poll() is not None:
                break
        return False, post_text or rendered

    @staticmethod
    def _spawn_agent_pty(agent_id: str) -> tuple[int, subprocess.Popen]:
        master_fd, slave_fd = pty.openpty()
        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 120, 0, 0))
        uid = os.getuid()
        runtime_dir = f"/run/user/{uid}"
        home_dir = str(_account_home())
        host_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": home_dir,
            "TERM": "xterm-256color",
            "XDG_RUNTIME_DIR": runtime_dir,
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_dir}/bus",
        }
        spawn_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": home_dir,
            "TERM": "xterm-256color",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/host{runtime_dir}/bus",
        }
        cmd = [
            HOST_SPAWN, "--env=", "/usr/bin/env", "-i",
            *(f"{k}={v}" for k, v in host_env.items()),
            "/usr/bin/podman", "--remote=false", "--default-mounts-file=/dev/null",
            "start", "-ai", agent_id,
        ]
        proc = subprocess.Popen(cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, env=spawn_env, close_fds=True)
        os.close(slave_fd)
        return master_fd, proc

    @staticmethod
    def _stop_agent_pty_cleanly(master_fd: int, proc: subprocess.Popen, agent_id: str) -> int:
        time.sleep(0.6)
        with suppress(OSError):
            os.write(master_fd, b"\x03")
        try:
            return proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            with suppress(OSError):
                os.write(master_fd, b"\x03\x04")
            podman("stop", "-t", "2", agent_id, check=False, timeout=8)
            return proc.wait(timeout=10)

    def _prepare_mini_proof_workspace(self, suffix: str, agent_img_id: str) -> dict[str, object]:
        sandbox_root = Path(tempfile.mkdtemp(prefix=f"oc-mproof-sb-{suffix}-", dir=SHARED_TMP))
        sandbox_root.chmod(0o755)
        cwd_rel = "workspace"
        work_dir = sandbox_root / cwd_rel
        work_dir.mkdir(mode=0o755)
        worker_marker = work_dir / "worker-readable-marker.txt"
        worker_marker.write_text(f"marker-{suffix}\n", encoding="ascii")
        worker_marker.chmod(0o644)
        canary_file = work_dir / "tool-canary.txt"
        canary_content = f"untouched-{suffix}\n"
        canary_file.write_text(canary_content, encoding="ascii")
        canary_file.chmod(0o644)
        sentinel_dir = Path(tempfile.mkdtemp(prefix=f"oc-mproof-sec-{suffix}-", dir=SHARED_TMP))
        sentinel_dir.chmod(0o700)
        sentinel_path = sentinel_dir / "host-private-sentinel.txt"
        sentinel_secret = f"HOST_PRIVATE_SENTINEL_{secrets.token_hex(12)}"
        sentinel_path.write_text(sentinel_secret + "\n", encoding="ascii")
        sentinel_path.chmod(0o600)
        cfg_dir = Path(tempfile.mkdtemp(prefix=f"oc-mproof-cfg-{suffix}-", dir=SHARED_TMP))
        cfg_dir.chmod(0o700)
        lock_dir = Path(tempfile.mkdtemp(prefix=f"oc-mproof-lock-{suffix}-", dir=SHARED_TMP))
        lock_dir.chmod(0o700)
        toml_path = cfg_dir / "providers.toml"
        toml_path.write_text(
            "[providers.openai.personal]\nenabled = true\nauth_mode = \"subscription\"\n"
            "[providers.openai.work]\nenabled = true\nauth_mode = \"subscription\"\n"
            "[providers.google.personal]\nenabled = true\nauth_mode = \"subscription\"\n"
            "[launch]\nmini = true\n",
            encoding="utf-8",
        )
        toml_path.chmod(0o600)
        _, cfg_digest = load_provider_config_with_digest(config_dir=cfg_dir)
        self.assertIsNotNone(cfg_digest)
        podman(
            "run", "--rm", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--security-opt=label=disable", "-v", f"{sandbox_root}:/sandbox",
            "--cap-add=FOWNER", "--entrypoint", "python3", agent_img_id, "-I", "-c",
            "import os; ctx=b'system_u:object_r:container_file_t:s0:c211,c212'\n"
            "for r, ds, fs in os.walk('/sandbox'):\n"
            "    os.setxattr(r, 'security.selinux', ctx)\n"
            "    for n in ds + fs:\n"
            "        os.setxattr(os.path.join(r, n), 'security.selinux', ctx, follow_symlinks=False)\n",
        )
        return {
            "sandbox_root": sandbox_root, "cwd_rel": cwd_rel, "canary_file": canary_file,
            "canary_content": canary_content, "sentinel_dir": sentinel_dir,
            "sentinel_path": sentinel_path, "sentinel_secret": sentinel_secret,
            "cfg_dir": cfg_dir, "lock_dir": lock_dir, "cfg_digest": cfg_digest,
        }

    def test_managed_supervisor_synthetic_mini_proof_real_podman(self):
        ready, reason = _synthetic_mini_prereqs_ready()
        if not ready:
            self.skipTest(reason)

        from tests.e2e.live import openai_shell_driver as shell_driver

        agent_img_id = podman("image", "inspect", "--format", "{{.Id}}", "localhost/oc-agent:latest").stdout.decode("ascii").strip()
        relay_img_id = podman("image", "inspect", "--format", "{{.Id}}", "localhost/oc-openai-relay:latest").stdout.decode("ascii").strip()
        suffix = secrets.token_hex(4)
        instance = f"mproof-{suffix}"
        pod_name = f"oc-{instance}"
        home_vol = f"{pod_name}-openai-home"
        ws = self._prepare_mini_proof_workspace(suffix, agent_img_id)
        created_slot_roots: list[Path] = []
        created_relay_ids: dict[str, str] = {}

        try:
            podman(
                "pod", "create", "--name", pod_name, "--network=none",
                "--label", "oc.sandbox=1", "--label", f"oc.instance={instance}",
                "--label", "oc.ports=",
            )
            podman("volume", "create", home_vol)

            oa_p, oa_w, gg_p = _spec_obj("openai", "personal"), _spec_obj("openai", "work"), _spec_obj("google", "personal")
            openai_rec: list[dict] = []
            google_rec: list[dict] = []
            oa_adapter = _SyntheticPodAdapter(
                "openai",
                preflights={
                    "personal": InstancePreflight(oa_p, ReadinessState.READY, (SYNTHETIC_MODEL,), route_policy="sub"),
                    "work": InstancePreflight(oa_w, ReadinessState.READY, ("gpt-6.2-sol",), route_policy="sub"),
                },
                approved_scoped_id="google--personal", recorder=openai_rec, opaque_handle=False,
            )
            gg_adapter = _SyntheticPodAdapter(
                "google",
                preflights={"personal": InstancePreflight(gg_p, ReadinessState.READY, (SYNTHETIC_MODEL,), route_policy="sub")},
                approved_scoped_id="google--personal", recorder=google_rec, opaque_handle=True,
            )
            plan = ResolvedLaunchPlan(
                admitted=(oa_adapter.preflight_instance(oa_p), oa_adapter.preflight_instance(oa_w), gg_adapter.preflight_instance(gg_p)),
                excluded=(), initial_provider_id="google--personal", initial_model=SYNTHETIC_MODEL,
                ui_mode="mini", ui_source="--mini", acknowledged_digests={},
            )
            approval = ProofApproval(
                run_id=secrets.token_hex(16), instance_label="personal", scoped_provider_id="google--personal",
                approved_model=SYNTHETIC_MODEL, ui_mode="mini", cwd=str(ws["cwd_rel"]),
                selection_epoch="epoch-1", credential_generation=1,
                history_digest_all_12_files="0" * 64, auth_mode="subscription",
                providers_config_digest=str(ws["cfg_digest"]),
            )
            proof_assertions: dict[str, object] = {}

            def run_agent_in_pty(agent_id: str, _stop_event: threading.Event, arm_turn_route) -> int:
                master_fd, proc = self._spawn_agent_pty(agent_id)
                screen = shell_driver._TerminalScreen(rows=32, cols=120)
                main_decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
                post_screen = shell_driver._TerminalScreen(rows=32, cols=120)
                post_decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
                try:
                    self.assertEqual(self._wait_container_running(agent_id), "running")
                    disc_relay_id = created_relay_ids["disc-2"]
                    gg_port, gg_tok, turn_body = self._verify_agent_isolation_and_discovery_probes(
                        agent_id=agent_id, disc_relay_id=disc_relay_id, plan=plan,
                        oa_adapter=oa_adapter, gg_adapter=gg_adapter, cwd_rel=str(ws["cwd_rel"]),
                        suffix=suffix, sentinel_path=ws["sentinel_path"], sentinel_secret=str(ws["sentinel_secret"]),
                        openai_rec=openai_rec, google_rec=google_rec,
                    )
                    raw_log = bytearray()
                    expected_route = "Google Subscription (google/personal)"
                    startup_view = self._drain_pty_until_startup_route(
                        master_fd, proc, screen, main_decoder, shell_driver, raw_log, expected_route,
                    )
                    self.assertIn(expected_route, startup_view)
                    self.assertIn(SYNTHETIC_MODEL, startup_view)
                    disc_mcs = podman("container", "inspect", "--format", "{{.ProcessLabel}}", disc_relay_id).stdout.decode().strip()
                    arm_turn_route(
                        observed_row=f"{expected_route} / {SYNTHETIC_MODEL}",
                        observed_screen_digest=sha256(startup_view.encode("utf-8")).hexdigest(),
                    )
                    turn_relay_id = created_relay_ids["turn-2"]
                    turn_mcs = podman("container", "inspect", "--format", "{{.ProcessLabel}}", turn_relay_id).stdout.decode().strip()
                    self.assertNotEqual(disc_mcs, turn_mcs)
                    turn_gate = gg_adapter.active_turn_gate
                    turn_inc = gg_adapter.active_turn_incarnation
                    self.assertIsNotNone(turn_gate)
                    self.assertIsNotNone(turn_inc)
                    turn_gate.bind_relay(turn_relay_id, turn_inc)
                    st_probe, _ = _in_pod_http_probe(
                        agent_id, method="GET", port=gg_port, path="/v1/models", token=gg_tok,
                        extra_headers={_OWNER_PROBE_HEADER: turn_gate.challenge_token},
                    )
                    self.assertEqual(st_probe, 200)
                    self.assertIn(turn_gate.challenge_token, gg_adapter.active_turn_broker.owner_probes_seen)
                    self.assertEqual(len(gg_adapter.active_turn_broker.owner_probe_observations), 1)
                    turn_gate.deliver_owner_receipt(
                        challenge=turn_gate.challenge_token,
                        relay_id=turn_relay_id,
                        job_incarnation=turn_inc,
                        epoch=turn_gate.epoch,
                        probe_observation=gg_adapter.active_turn_broker.owner_probe_observations[-1],
                    )
                    pre_lines = tuple(
                        ln for ln in (shell_driver._normalize_reply_line(r) for r in startup_view.splitlines()) if ln
                    )
                    post_screen.sync_sgr_from(screen)
                    os.write(master_fd, (PROOF_PROMPT + "\r").encode("ascii"))
                    reply_seen, rendered_reply = self._wait_pty_exact_ok(
                        master_fd, proc, screen, main_decoder, post_screen, post_decoder, shell_driver, raw_log, pre_lines,
                    )
                    proof_assertions["reply_seen"] = reply_seen
                    proof_assertions["screen_text"] = rendered_reply
                    proof_assertions["screen_certain"] = post_screen.is_certain
                    st_second, b_second = _in_pod_http_probe(
                        agent_id, method="POST", port=gg_port, path="/v1/responses", token=gg_tok, body=turn_body,
                    )
                    proof_assertions["second_turn_status"] = st_second
                    proof_assertions["second_turn_body"] = b_second
                    return self._stop_agent_pty_cleanly(master_fd, proc, agent_id)
                finally:
                    with suppress(OSError):
                        os.close(master_fd)
                    if proc.poll() is None:
                        with suppress(OSError):
                            proc.terminate()
                        with suppress(Exception):
                            proc.wait(timeout=5)

            class _AttendedTerm(StreamTerminal):
                def attended(self) -> bool:
                    return True

            err_stream = io.StringIO()
            spec = _make_launch_spec(
                instance=instance, sandbox=str(ws["sandbox_root"]), cwd=str(ws["cwd_rel"]),
                level="s0:c211,c212", relay_image=relay_img_id, agent_image=agent_img_id, cli_ui_mode="mini",
            )
            proof_opts = ProofSessionOptions(
                proof_gate=_SyntheticMiniProofGate(approval),
                preconfirmed_plan=plan,
                agent_runner=run_agent_in_pty,
                on_slot_prepare=lambda _k, container_name="", slot_root="": created_slot_roots.append(Path(slot_root)) if slot_root else None,
                on_slot_finish=lambda k, cid: created_relay_ids.__setitem__(k, cid),
            )
            rc = run_interactive_session(
                spec, _AttendedTerm(io.StringIO(), io.StringIO(), err_stream),
                config_dir=ws["cfg_dir"], adapters={"openai": oa_adapter, "google": gg_adapter},
                lock_dir=ws["lock_dir"], proof_options=proof_opts,
            )
            self.assertIn(rc, (0, 130, 143), f"Unexpected agent exit rc={rc}; stderr={err_stream.getvalue()}")
            self.assertTrue(proof_assertions.get("reply_seen"), f"Expected painted ok; screen={proof_assertions.get('screen_text')!r}")
            self.assertEqual((len(google_rec), len(openai_rec)), (1, 0))
            self.assertIsNone(google_rec[0].get("tools"))
            self.assertEqual(proof_assertions.get("second_turn_status"), 403)
            self.assertIn("proof_gate_spent", str(proof_assertions.get("second_turn_body")))
            self.assertEqual(ws["canary_file"].read_text(encoding="ascii"), ws["canary_content"])
            export_data = _inspect_mini_session_export(
                volume_name=home_vol, level="s0:c211,c212", cwd=str(ws["cwd_rel"]),
                agent_image_id=agent_img_id, expected_provider_id="google--personal", expected_model=SYNTHETIC_MODEL,
            )
            self.assertEqual(export_data["messages"][1]["model"]["providerID"], "google--personal")
            for slot_key, cid in created_relay_ids.items():
                self.assertEqual(podman("container", "exists", cid, check=False).returncode, 1, f"Container {slot_key} leaked")
            for sroot in created_slot_roots:
                self.assertFalse(sroot.exists(), f"Slot root {sroot} leaked")
        finally:
            podman("pod", "rm", "-f", pod_name, check=False, timeout=15)
            podman("volume", "rm", "-f", home_vol, check=False, timeout=10)
            for key in ("sandbox_root", "sentinel_dir", "cfg_dir", "lock_dir"):
                shutil.rmtree(ws[key], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
