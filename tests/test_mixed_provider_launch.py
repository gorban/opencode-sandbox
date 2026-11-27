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
    ) -> int:
        """Deliver attempt-scoped receipt requiring an actual matching broker probe observation."""
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
            return self._receipt_generation

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
        self._stopped = threading.Event()
        self._revoked = threading.Event()
        self._lock = threading.Lock()
        self._clients: set[socket.socket] = set()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.owner_probes_seen: list[str] = []
        self.owner_probe_observations: list[str] = []

    def start(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        listener.listen(8)
        listener.settimeout(0.1)
        self._listener = listener
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
        with suppress(OSError):
            self.socket_path.unlink()

    def _accept_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                peer, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            # Capture arrival snapshot immediately under the accepted-socket boundary BEFORE
            # spawning the handler thread so late handler scheduling cannot promote pre-receipt arrivals.
            arrival = self._receipt_gate.snapshot_arrival() if self._receipt_gate is not None else None
            with self._lock:
                if self._stopped.is_set():
                    peer.close()
                    continue
                self._clients.add(peer)
            threading.Thread(target=self._dispatch_accepted_peer, args=(peer, arrival), daemon=True).start()

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
            "lease_release_confirmed": lambda: state["lease_released"],
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

        # 2. Removing ANY of the 10 hooks from an opaque handle fails closed before container creation.
        all_hooks = (
            "relay_paths", "revoke_grant", "close_broker", "activate_route", "route_state",
            "is_revoked", "has_active_clients", "mark_relay_created", "confirm_relay_removed",
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

        for label, bad_overrides in (
            ("wrong_slot_index", {"slot_index": 7}),
            ("wrong_scoped_id", {"scoped_id": "openai--personal"}),
            ("wrong_provider_label", {"provider_label": "openai/personal"}),
            ("wrong_port", {"port": 8415}),
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
