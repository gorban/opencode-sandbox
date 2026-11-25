"""In-process 3-state proof gate and per-incarnation evidence ledger for OpenAI shell e2e.

Enforces single-send whole-request canonicalization strictly inside the verified foreground
owner process:
- Zero ambient file descriptors are read or accepted.
- Discovery stays closed to inference until the owner explicitly arms the gate after
  observing OpenCode TUI readiness and the exact approved route row.
- Arrival-time state snapshots keep pre-arming or queued requests permanently ineligible.
- Exact whole-request pinning rejects altered instructions, developer/system messages,
  and outbound tool declarations with zero upstream writes, then emits the 4-key
  canonical upstream body.
- Exclusive per-incarnation evidence is durably fsynced as ``unsettled`` before the first
  upstream byte and promoted to ``exact_ok_delivered`` only after validated terminal
  completion and successful final delivery.
"""

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time

from .exposure import (
    _CANARY_NAMES,
    _DIAGNOSTIC,
    _LEDGER,
    _RECOVERY_NAMES,
    _STREAM_DIAGNOSTIC,
)
from .session_protocol import RequestRefused


PROOF_PROMPT = "Reply with exactly: ok"
EXPECTED_REPLY = "ok"

STATE_CLOSED_DISCOVERY = "CLOSED_DISCOVERY"
STATE_ARMED = "ARMED"
STATE_SPENT = "SPENT"

# Pinned OpenCode v2.3.0 zero-tool interactive system prompt SHA-256 after normalizing
# only the exact expected working directory and workspace root lines for this run.
OPENCODE_ZERO_TOOL_INSTRUCTIONS_SHA256 = (
    "679baa94035612f6f07634102cae417f2f0aeb49d0f9ec55021b88569cac6cff"
)

CANONICAL_EXPOSURE_FILES: tuple[str, ...] = (
    _LEDGER,
    _DIAGNOSTIC,
    _STREAM_DIAGNOSTIC,
    *_RECOVERY_NAMES,
    *_CANARY_NAMES,
)

_MAX_PROOF_BODY_BYTES = 256 * 1024
_MAX_RECEIPT_BYTES = 256 * 1024
_KEY_MAX_OUTPUT_TOKENS = "max_output_tokens"
_KEY_PROMPT_CACHE_KEY = "prompt_cache_key"
_ALLOWED_PROOF_KEYS = frozenset({
    "model",
    "input",
    "instructions",
    "stream",
    "store",
    "include",
    _KEY_MAX_OUTPUT_TOKENS,
    _KEY_PROMPT_CACHE_KEY,
    "tools",
    "tool_choice",
    "parallel_tool_calls",
})
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_RUN_ID_RE = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_CACHE_KEY_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z", re.ASCII)
_INSTRUCTIONS_DATE_RE = re.compile(
    r"Today's date: (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
    r"(?:[ 0-3]?\d) 20\d{2}"
)
_ERR_NOT_ARMED = "proof_gate_not_armed"
_ERR_SPENT = "proof_gate_spent"
_ERR_INCARNATION = "proof_gate_incarnation_mismatch"
_ERR_SLOT = "proof_slot_not_approved"
_ERR_FOREGROUND_LOST = "proof_gate_foreground_lost"
_ERR_APPROVAL_DRIFT = "proof_gate_approval_drift"
_ERR_SYNC_FAILED = "proof_evidence_sync_failed"
_ERR_RELAY_UNVERIFIED = "proof_gate_relay_unverified"
_ERR_CONFIG_MISSING = "providers_config_missing"
_ERR_TOOLS = "proof_gate_tools_forbidden"
_ERR_INSTRUCTIONS = "proof_gate_instructions_mismatch"
_ERR_PROMPT = "proof_gate_prompt_mismatch"
_ERR_OPTIONS = "proof_gate_disallowed_options"


class ProofGateError(RuntimeError):
    """Fail-closed proof gate invariant or evidence-ledger error."""


@dataclass(frozen=True)
class ProofApproval:
    """Operator-approved immutable tuple for one interactive OpenAI shell proof run."""

    run_id: str
    instance_label: str
    scoped_provider_id: str
    approved_model: str
    ui_mode: str
    cwd: str
    selection_epoch: str
    credential_generation: int
    history_digest_all_12_files: str
    profile_directory: str = ""
    client_id: str = ""
    auth_mode: str = "subscription"
    route_policy: str = ""
    providers_config_digest: str = ""


@dataclass(frozen=True)
class ArrivalSnapshot:
    """Immutable arrival-time phase snapshot captured before reading a peer request body."""

    state: str
    arm_nonce: str | None
    job_incarnation: str | None


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate_json_key")
    return obj


def _reject_non_finite(_value: str) -> object:
    raise ValueError("non_finite_json")


def _require_private_dir(directory: Path) -> None:
    try:
        info = directory.lstat()
    except OSError:
        raise ProofGateError("untrusted proof directory") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ProofGateError("proof directory must be owner-only mode 0700")


def compute_providers_config_digest(config_dir: Path) -> str:
    """Compute a deterministic 64-hex SHA-256 digest of existing providers.toml (refuses missing config)."""
    try:
        dir_fd = os.open(config_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise ProofGateError(_ERR_CONFIG_MISSING) from None
    except OSError:
        raise ProofGateError("providers config directory unavailable") from None
    try:
        dir_info = os.fstat(dir_fd)
        if dir_info.st_uid not in (0, os.geteuid()) or dir_info.st_mode & 0o022:
            raise ProofGateError("unsafe providers config directory metadata")
        try:
            fd = os.open("providers.toml", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
        except FileNotFoundError:
            raise ProofGateError(_ERR_CONFIG_MISSING) from None
        except OSError:
            raise ProofGateError("unsafe providers.toml open") from None
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in (0, os.geteuid())
                or info.st_mode & 0o022
                or info.st_nlink != 1
            ):
                raise ProofGateError("unsafe providers.toml metadata")
            data = stream.read(_MAX_RECEIPT_BYTES + 1)
        if len(data) > _MAX_RECEIPT_BYTES:
            raise ProofGateError("providers.toml exceeds size cap")
        return sha256(b"PRESENT\0" + data).hexdigest()
    finally:
        os.close(dir_fd)


def verify_foreground_tty() -> None:
    """Verify this process group still owns the attended foreground controlling terminal."""
    import sys as _sys

    if not (_sys.stdin.isatty() and _sys.stdout.isatty() and _sys.stderr.isatty()):
        raise ProofGateError(_ERR_FOREGROUND_LOST)
    try:
        tty_fd = os.open("/dev/tty", os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        raise ProofGateError(_ERR_FOREGROUND_LOST) from None
    try:
        if os.tcgetpgrp(tty_fd) != os.getpgrp():
            raise ProofGateError(_ERR_FOREGROUND_LOST)
    except OSError:
        raise ProofGateError(_ERR_FOREGROUND_LOST) from None
    finally:
        os.close(tty_fd)


def compute_exposure_history_digest(exposure_dir: Path) -> str:
    """Compute a deterministic 64-hex SHA-256 digest over all 12 canonical receipt files.

    Always returns a non-null 64-hex digest (even when no hold is blocked or files are absent),
    distinguishing absent files from empty files and rejecting symlinks or unsafe modes.
    """
    try:
        dir_fd = os.open(exposure_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ProofGateError("exposure directory unavailable") from None
    try:
        dir_info = os.fstat(dir_fd)
        if dir_info.st_uid not in (0, os.geteuid()) or dir_info.st_mode & 0o022:
            raise ProofGateError("unsafe exposure directory ownership or mode")
        hasher = sha256()
        for name in CANONICAL_EXPOSURE_FILES:
            _hash_single_receipt(dir_fd, name, hasher)
        return hasher.hexdigest()
    finally:
        os.close(dir_fd)


def _hash_single_receipt(dir_fd: int, name: str, hasher) -> None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        hasher.update(name.encode("ascii") + b"\0ABSENT\0")
        return
    except OSError:
        raise ProofGateError(f"unsafe exposure receipt: {name}") from None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022
            or info.st_nlink != 1
        ):
            raise ProofGateError(f"unsafe exposure receipt metadata: {name}")
        data = stream.read(_MAX_RECEIPT_BYTES + 1)
    if len(data) > _MAX_RECEIPT_BYTES:
        raise ProofGateError(f"exposure receipt exceeds size cap: {name}")
    hasher.update(name.encode("ascii") + b"\0PRESENT\0" + sha256(data).digest())


def _normalize_instructions(instructions: str, *, expected_cwd: str) -> str | None:
    normalized, date_count = _INSTRUCTIONS_DATE_RE.subn("Today's date: [date]", instructions)
    if date_count != 1:
        return None
    if expected_cwd:
        wd_line = f"  Working directory: /sandbox/{expected_cwd}\n"
        ws_line = f"  Workspace root folder: /sandbox/{expected_cwd}\n"
        if normalized.count(wd_line) != 1 or normalized.count(ws_line) != 1:
            return None
        normalized = normalized.replace(wd_line, "  Working directory: /sandbox\n", 1)
        normalized = normalized.replace(ws_line, "  Workspace root folder: /sandbox\n", 1)
        return normalized
    if "  Working directory: /sandbox\n" not in normalized:
        return None
    if "  Workspace root folder: /sandbox\n" not in normalized:
        return None
    return normalized


def _valid_proof_input(items: object) -> bool:
    if type(items) is not list or len(items) != 1 or type(items[0]) is not dict:
        return False
    msg = items[0]
    if msg.get("role") != "user" or msg.get("type", "message") != "message":
        return False
    if not set(msg) <= {"type", "role", "content"}:
        return False
    content = msg.get("content")
    if content == PROOF_PROMPT:
        return True
    return (
        type(content) is list
        and len(content) == 1
        and type(content[0]) is dict
        and content[0] == {"type": "input_text", "text": PROOF_PROMPT}
    )


def _validate_optional_proof_fields(data: dict[str, object]) -> None:
    if _KEY_MAX_OUTPUT_TOKENS in data:
        cap = data[_KEY_MAX_OUTPUT_TOKENS]
        if type(cap) is not int or not 1 <= cap <= 32768:
            raise RequestRefused(403, _ERR_OPTIONS, "Invalid max_output_tokens for proof turn.")
    if _KEY_PROMPT_CACHE_KEY in data:
        key = data[_KEY_PROMPT_CACHE_KEY]
        if type(key) is not str or not _CACHE_KEY_RE.fullmatch(key):
            raise RequestRefused(403, _ERR_OPTIONS, "Invalid prompt_cache_key for proof turn.")
    if data.get("include", []) not in (None, [], ["reasoning.encrypted_content"]):
        raise RequestRefused(403, _ERR_OPTIONS, "Unsupported include option for proof turn.")


def canonical_proof_body(approved_model: str) -> dict[str, object]:
    """Build the exact 4-key canonical upstream body (zero tools, zero unconstrained instructions)."""
    return {
        "model": approved_model,
        "input": [{"type": "message", "role": "user", "content": PROOF_PROMPT}],
        "store": False,
        "stream": True,
    }


def _atomic_fsync_json(path: Path, payload: dict[str, object], *, exclusive: bool = False) -> None:
    raw = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            with _suppress_oserror():
                os.close(fd)
            raise
        _fsync_dir(path.parent)
        return
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        with _suppress_oserror():
            tmp.unlink(missing_ok=True)
        raise


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class _suppress_oserror:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, _exc, _tb) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)


class ClosedProofSlotGate:
    """Permanently-closed deny-all proof gate for non-approved admitted slots or discovery."""

    def __init__(self, scoped_provider_id: str, *, refusal_code: str = _ERR_SLOT):
        self.scoped_provider_id = scoped_provider_id
        self._refusal_code = refusal_code
        self._lock = threading.Lock()
        self._refusal_count = 0

    @property
    def refusal_count(self) -> int:
        with self._lock:
            return self._refusal_count

    def bind_incarnation(self, _incarnation: str, _generation: int) -> None:
        return None

    def snapshot_arrival(self) -> ArrivalSnapshot:
        return ArrivalSnapshot(state=STATE_SPENT, arm_nonce=None, job_incarnation=None)

    def validate_and_canonicalize(
        self,
        _raw_body: bytes,
        *,
        arrival: ArrivalSnapshot,
        job_incarnation: str,
    ) -> dict[str, object]:
        del arrival, job_incarnation
        with self._lock:
            self._refusal_count += 1
        raise RequestRefused(403, self._refusal_code, "Inference is closed on this slot.")

    def claim_for_write(
        self,
        _arrival: ArrivalSnapshot,
        _canonical_body: dict[str, object],
        *,
        job_incarnation: str,
    ) -> None:
        del job_incarnation
        raise ProofGateError(self._refusal_code)

    def record_delivery_complete(
        self,
        *,
        usage: tuple[int, int, int] | None,
        completed_text: str | None,
        streamed_text: str,
        tool_calls: int,
    ) -> None:
        del usage, completed_text, streamed_text, tool_calls
        raise ProofGateError(self._refusal_code)


class ProofGate:
    """In-process 3-state single-send proof gate bound to one broker job incarnation."""

    def __init__(
        self,
        approval: ProofApproval,
        *,
        evidence_dir: Path,
        exposure_dir: Path | None = None,
        check_owner_alive: Callable[[], None] | None = None,
        check_binding_intact: Callable[[ProofApproval], None] | None = None,
        expected_instructions_sha256: str = OPENCODE_ZERO_TOOL_INSTRUCTIONS_SHA256,
    ):
        self._validate_approval(approval, expected_instructions_sha256)
        _require_private_dir(evidence_dir)
        self.approval = approval
        self._evidence_dir = evidence_dir
        self._exposure_dir = exposure_dir
        self._check_owner_alive = check_owner_alive
        self._check_binding_intact = check_binding_intact
        self._expected_instructions_sha256 = expected_instructions_sha256
        self._lock = threading.Lock()
        self._state = STATE_CLOSED_DISCOVERY
        self._job_incarnation: str | None = None
        self._job_generation: int | None = None
        self._arm_nonce: str | None = None
        self._relay_verified = False
        self._verified_relay_id: str | None = None
        self._observed_row: str | None = None
        self._observed_screen_digest: str | None = None
        self._evidence_path: Path | None = None
        self._admitted_writes = 0
        self._write_attempted = False
        self._exact_ok_delivered = False
        self._outcome = "discovery_open"
        self._canonical_request_digest: str | None = None
        self._usage: tuple[int, int, int] | None = None
        self._tool_call_count = 0
        self._refusals: list[dict[str, object]] = []

    @staticmethod
    def _validate_approval(approval: ProofApproval, instructions_sha256: str) -> None:
        if not _RUN_ID_RE.fullmatch(approval.run_id):
            raise ProofGateError("invalid proof run_id")
        if approval.ui_mode not in ("full", "mini"):
            raise ProofGateError("invalid proof ui_mode")
        if not _SHA256_RE.fullmatch(approval.history_digest_all_12_files):
            raise ProofGateError("invalid 12-file exposure history digest")
        if not _SHA256_RE.fullmatch(instructions_sha256):
            raise ProofGateError("invalid expected instructions digest")
        if not approval.approved_model or not approval.instance_label or not approval.scoped_provider_id:
            raise ProofGateError("incomplete proof approval tuple")

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def evidence_path(self) -> Path | None:
        with self._lock:
            return self._evidence_path

    @property
    def admitted_writes(self) -> int:
        with self._lock:
            return self._admitted_writes

    @property
    def exact_ok_delivered(self) -> bool:
        with self._lock:
            return self._exact_ok_delivered

    @property
    def refusals(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            return tuple(dict(entry) for entry in self._refusals)

    def _evidence_snapshot_locked(self) -> dict[str, object]:
        return {
            "run_id": self.approval.run_id,
            "job_incarnation": self._job_incarnation,
            "job_generation": self._job_generation,
            "instance_label": self.approval.instance_label,
            "scoped_provider_id": self.approval.scoped_provider_id,
            "approved_model": self.approval.approved_model,
            "ui_mode": self.approval.ui_mode,
            "cwd": self.approval.cwd,
            "selection_epoch": self.approval.selection_epoch,
            "credential_generation": self.approval.credential_generation,
            "profile_directory": self.approval.profile_directory,
            "client_id": self.approval.client_id,
            "auth_mode": self.approval.auth_mode,
            "route_policy": self.approval.route_policy,
            "providers_config_digest": self.approval.providers_config_digest,
            "history_digest_all_12_files": self.approval.history_digest_all_12_files,
            "state": self._state,
            "relay_verified": self._relay_verified,
            "verified_relay_id": self._verified_relay_id,
            "arm_nonce_digest": sha256(self._arm_nonce.encode("ascii")).hexdigest() if self._arm_nonce else None,
            "observed_row": self._observed_row,
            "observed_screen_digest": self._observed_screen_digest,
            "admitted_writes": self._admitted_writes,
            "write_attempted": self._write_attempted,
            "exact_ok_delivered": self._exact_ok_delivered,
            "outcome": self._outcome,
            "canonical_request_digest": self._canonical_request_digest,
            "usage": list(self._usage) if self._usage is not None else None,
            "tool_call_count": self._tool_call_count,
            "refusal_count": len(self._refusals),
            "updated_at": int(time.time()),
        }

    def snapshot_evidence(self) -> dict[str, object]:
        with self._lock:
            return self._evidence_snapshot_locked()

    def _record_refusal_locked(self, code: str, *, arrival_state: str) -> None:
        if len(self._refusals) < 256:
            self._refusals.append({"code": code, "arrival_state": arrival_state, "ts": int(time.time())})

    def _verify_owner_and_history(self) -> None:
        if self._check_owner_alive is not None:
            self._check_owner_alive()
        if self._check_binding_intact is not None:
            self._check_binding_intact(self.approval)
        if self._exposure_dir is not None:
            current = compute_exposure_history_digest(self._exposure_dir)
            if not hmac.compare_digest(current, self.approval.history_digest_all_12_files):
                raise ProofGateError("exposure_history_mutated")

    def bind_incarnation(self, incarnation: str, generation: int) -> Path:
        """Bind this gate to the exact broker job incarnation and create exclusive evidence."""
        if not incarnation or not re.fullmatch(r"[A-Za-z0-9._-]{8,128}\Z", incarnation):
            raise ProofGateError("invalid job incarnation")
        if type(generation) is not int or generation < 0:
            raise ProofGateError("invalid job generation")
        with self._lock:
            if self._job_incarnation is not None:
                raise ProofGateError("job incarnation already bound")
            _require_private_dir(self._evidence_dir)
            evidence_path = self._evidence_dir / f"proof-{self.approval.run_id}-{incarnation}.json"
            self._job_incarnation = incarnation
            self._job_generation = generation
            self._evidence_path = evidence_path
            try:
                _atomic_fsync_json(evidence_path, self._evidence_snapshot_locked(), exclusive=True)
            except FileExistsError:
                self._job_incarnation = None
                self._job_generation = None
                self._evidence_path = None
                raise ProofGateError("duplicate per-incarnation evidence file") from None
            return evidence_path

    def snapshot_arrival(self) -> ArrivalSnapshot:
        """Capture arrival-time gate state before a peer request body is read."""
        with self._lock:
            return ArrivalSnapshot(
                state=self._state,
                arm_nonce=self._arm_nonce,
                job_incarnation=self._job_incarnation,
            )

    def verify_ready_for_arm(self) -> None:
        """Recheck foreground authority, registration/config binding, and exposure history before cutover."""
        self._verify_owner_and_history()
        with self._lock:
            if self._state != STATE_CLOSED_DISCOVERY:
                raise ProofGateError(f"cannot arm proof gate from state {self._state}")

    def arm(self, *, observed_row: str, observed_screen_digest: str) -> str:
        """Transition CLOSED_DISCOVERY -> ARMED after observing TUI readiness and exact row."""
        if not observed_row or not _SHA256_RE.fullmatch(observed_screen_digest):
            raise ProofGateError("arming requires observed_row and 64-hex observed_screen_digest")
        self._verify_owner_and_history()
        with self._lock:
            if self._state != STATE_CLOSED_DISCOVERY:
                raise ProofGateError(f"cannot arm proof gate from state {self._state}")
            if self._job_incarnation is None or self._evidence_path is None:
                raise ProofGateError("cannot arm proof gate before job incarnation binding")
            nonce = secrets.token_hex(32)
            self._arm_nonce = nonce
            self._observed_row = observed_row
            self._observed_screen_digest = observed_screen_digest
            self._state = STATE_ARMED
            self._outcome = "armed"
            _atomic_fsync_json(self._evidence_path, self._evidence_snapshot_locked(), exclusive=False)
            return nonce

    def mark_relay_verified(self, relay_id: str) -> None:
        """Record verified isolation + bind of the replacement turn relay before activating writes."""
        if not _SHA256_RE.fullmatch(relay_id):
            raise ProofGateError("invalid verified turn relay ID")
        self._verify_owner_and_history()
        with self._lock:
            if self._state != STATE_ARMED or self._evidence_path is None:
                raise ProofGateError("cannot verify relay outside ARMED state")
            if self._relay_verified:
                raise ProofGateError("turn relay already verified")
            self._relay_verified = True
            self._verified_relay_id = relay_id
            _atomic_fsync_json(self._evidence_path, self._evidence_snapshot_locked(), exclusive=False)

    def validate_and_canonicalize(
        self,
        raw_body: bytes,
        *,
        arrival: ArrivalSnapshot,
        job_incarnation: str,
    ) -> dict[str, object]:
        """Validate arrival phase and whole inbound request; return 4-key canonical upstream body."""
        self._check_arrival_eligible(arrival, job_incarnation)
        data = self._parse_strict_body(raw_body, arrival.state)
        self._validate_request_fields(data, arrival.state)
        return canonical_proof_body(self.approval.approved_model)

    def _check_arrival_eligible(self, arrival: ArrivalSnapshot, job_incarnation: str) -> None:
        with self._lock:
            if self._job_incarnation is None or not hmac.compare_digest(job_incarnation, self._job_incarnation):
                self._record_refusal_locked(_ERR_INCARNATION, arrival_state=arrival.state)
                raise RequestRefused(403, _ERR_INCARNATION, "Proof gate job incarnation mismatch.")
            if arrival.job_incarnation is None or not hmac.compare_digest(arrival.job_incarnation, self._job_incarnation):
                self._record_refusal_locked(_ERR_INCARNATION, arrival_state=arrival.state)
                raise RequestRefused(403, _ERR_INCARNATION, "Request arrived before incarnation binding.")
            if arrival.state == STATE_CLOSED_DISCOVERY or arrival.arm_nonce is None:
                self._record_refusal_locked(_ERR_NOT_ARMED, arrival_state=arrival.state)
                raise RequestRefused(403, _ERR_NOT_ARMED, "Proof gate is closed during discovery.")
            if self._state == STATE_SPENT or self._admitted_writes > 0:
                self._record_refusal_locked(_ERR_SPENT, arrival_state=arrival.state)
                raise RequestRefused(403, _ERR_SPENT, "Proof gate single-send latch already spent.")
            if self._state != STATE_ARMED or self._arm_nonce is None or not hmac.compare_digest(arrival.arm_nonce, self._arm_nonce):
                self._record_refusal_locked(_ERR_NOT_ARMED, arrival_state=arrival.state)
                raise RequestRefused(403, _ERR_NOT_ARMED, "Proof gate arming nonce mismatch.")
            if not self._relay_verified:
                self._record_refusal_locked(_ERR_RELAY_UNVERIFIED, arrival_state=arrival.state)
                raise RequestRefused(403, _ERR_RELAY_UNVERIFIED, "Replacement turn relay verification incomplete.")

    def _parse_strict_body(self, raw_body: bytes, arrival_state: str) -> dict[str, object]:
        if len(raw_body) > _MAX_PROOF_BODY_BYTES:
            self._refuse(_ERR_OPTIONS, arrival_state, "Proof request body exceeds size limit.")
        try:
            data = json.loads(
                raw_body.decode("utf-8"),
                object_pairs_hook=_unique_object_pairs,
                parse_constant=_reject_non_finite,
            )
        except (UnicodeDecodeError, ValueError, RecursionError):
            self._refuse(_ERR_OPTIONS, arrival_state, "Malformed JSON in proof request.")
        if type(data) is not dict or not set(data) <= _ALLOWED_PROOF_KEYS:
            self._refuse(_ERR_OPTIONS, arrival_state, "Unexpected keys in proof request.")
        return data

    def _refuse(self, code: str, arrival_state: str, message: str) -> None:
        with self._lock:
            self._record_refusal_locked(code, arrival_state=arrival_state)
        raise RequestRefused(403, code, message)

    def _validate_request_fields(self, data: dict[str, object], arrival_state: str) -> None:
        if (
            data.get("tools") not in (None, [])
            or data.get("tool_choice") not in (None, "none")
            or data.get("parallel_tool_calls") not in (None, False)
        ):
            self._refuse(_ERR_TOOLS, arrival_state, "Outbound tool declarations are forbidden in proof mode.")
        if (
            data.get("model") != self.approval.approved_model
            or data.get("stream") is not True
            or data.get("store", False) is not False
        ):
            self._refuse(_ERR_OPTIONS, arrival_state, "Model, stream, or store options do not match proof approval.")
        try:
            _validate_optional_proof_fields(data)
        except RequestRefused as exc:
            self._refuse(exc.code, arrival_state, exc.message)
        if not _valid_proof_input(data.get("input")):
            self._refuse(_ERR_PROMPT, arrival_state, "Request input does not match the exact approved proof prompt.")
        instructions = data.get("instructions")
        if type(instructions) is not str:
            self._refuse(_ERR_INSTRUCTIONS, arrival_state, "Missing or non-string instructions in proof request.")
        normalized = _normalize_instructions(instructions, expected_cwd=self.approval.cwd)
        if normalized is None:
            self._refuse(_ERR_INSTRUCTIONS, arrival_state, "Instructions working directory does not match proof cwd.")
        digest = sha256(normalized.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, self._expected_instructions_sha256):
            self._refuse(_ERR_INSTRUCTIONS, arrival_state, "Instructions digest does not match pinned OpenCode v2.3.0.")

    def claim_for_write(
        self,
        arrival: ArrivalSnapshot,
        canonical_body: dict[str, object],
        *,
        job_incarnation: str,
    ) -> None:
        """Atomically spend the single-send latch and fsync unsettled evidence before first byte."""
        self._verify_owner_and_history()
        body_digest = sha256(
            json.dumps(canonical_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
        with self._lock:
            if self._job_incarnation is None or not hmac.compare_digest(job_incarnation, self._job_incarnation):
                raise ProofGateError(_ERR_INCARNATION)
            if not self._relay_verified or self._verified_relay_id is None:
                raise ProofGateError(_ERR_RELAY_UNVERIFIED)
            if (
                self._state != STATE_ARMED
                or self._admitted_writes != 0
                or arrival.state != STATE_ARMED
                or arrival.arm_nonce is None
                or self._arm_nonce is None
                or not hmac.compare_digest(arrival.arm_nonce, self._arm_nonce)
                or arrival.job_incarnation is None
                or not hmac.compare_digest(arrival.job_incarnation, self._job_incarnation)
                or self._evidence_path is None
            ):
                raise ProofGateError(_ERR_SPENT if self._state == STATE_SPENT else _ERR_NOT_ARMED)
            self._state = STATE_SPENT
            self._admitted_writes = 1
            self._write_attempted = True
            self._outcome = "unsettled"
            self._canonical_request_digest = body_digest
            try:
                _atomic_fsync_json(self._evidence_path, self._evidence_snapshot_locked(), exclusive=False)
            except OSError:
                self._outcome = "sync_failed"
                raise ProofGateError(_ERR_SYNC_FAILED) from None

    @staticmethod
    def _disable_provider_tools(providers: dict[str, object]) -> None:
        for provider_entry in providers.values():
            entry_models = provider_entry.get("models") if isinstance(provider_entry, dict) else None
            if not isinstance(entry_models, dict):
                continue
            for model_cfg in entry_models.values():
                if isinstance(model_cfg, dict):
                    caps = dict(model_cfg.get("capabilities") or {})
                    caps["tools"] = False
                    model_cfg["capabilities"] = caps

    def harden_opencode_config(self, config_payload: dict[str, object]) -> dict[str, object]:
        """Apply the OpenAI-local zero-tool, zero-MCP proof overlay without mutating oc_providers/catalog.py."""
        providers = config_payload.get("providers")
        if not isinstance(providers, dict) or self.approval.scoped_provider_id not in providers:
            raise ProofGateError("approved provider missing from OpenCode config")
        approved_entry = providers[self.approval.scoped_provider_id]
        models = approved_entry.get("models") if isinstance(approved_entry, dict) else None
        if not isinstance(models, dict) or self.approval.approved_model not in models:
            raise ProofGateError("approved model missing from OpenCode config")
        self._disable_provider_tools(providers)
        config_payload["model"] = f"{self.approval.scoped_provider_id}/{self.approval.approved_model}"
        config_payload["snapshots"] = False
        config_payload["permissions"] = [{"action": "*", "resource": "*", "effect": "deny"}]
        config_payload["plugins"] = ["-opencode.tool.*"]
        config_payload.pop("mcp", None)
        return config_payload

    def record_delivery_complete(
        self,
        *,
        usage: tuple[int, int, int] | None,
        completed_text: str | None,
        streamed_text: str,
        tool_calls: int,
    ) -> None:
        """Settle evidence as exact_ok_delivered ONLY after validated completion + final peer write."""
        with self._lock:
            if self._state != STATE_SPENT or self._evidence_path is None:
                raise ProofGateError("cannot settle proof evidence before write admission")
            self._usage = usage
            self._tool_call_count = int(tool_calls)
            exact = (
                completed_text == EXPECTED_REPLY
                and streamed_text == EXPECTED_REPLY
                and tool_calls == 0
                and usage is not None
            )
            self._exact_ok_delivered = exact
            self._outcome = "exact_ok_delivered" if exact else "unexpected_output"
            _atomic_fsync_json(self._evidence_path, self._evidence_snapshot_locked(), exclusive=False)
