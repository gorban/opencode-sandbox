"""Shared Command, Event, Provenance, and WorkerTransport contract for PRD M.

Pure Python standard library with zero SQLite, UDS, or server imports so both
the coordination lane (fake worker) and the local OpenCode integration lane
(real disposable Podman job) can import and share identical types and invariants.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re
import secrets
from typing import Any, Protocol, runtime_checkable

from oc_address import (
    AddressError,
    TargetAddr,
    check_no_control_or_bidi,
    has_forbidden_control_or_bidi,
    parse_canonical_addr,
    validate_msg_kind,
    validate_thread_id,
)

MAX_INLINE_BODY_BYTES = 65_536
MAX_FRAMED_BODY_BYTES = MAX_INLINE_BODY_BYTES + 4_096
MAX_STREAM_EVENT_BYTES = 262_144
MAX_REASON_BYTES = 256
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_ARTIFACTS_PER_MSG = 8
MAX_ARTIFACTS_PER_EDGE = 64
EDGE_MAX_QUEUED_MSGS = 32
EDGE_MAX_QUEUED_BYTES = 1_048_576
DEFAULT_EDGE_MAX_ROUNDS = 16
DEFAULT_MAX_SUBTREE_DEPTH = 2
DEFAULT_MAX_CHILDREN_PER_PARENT = 8
DEFAULT_MAX_TOTAL_SANDBOXES = 16
MAX_TURN_STREAM_EVENTS = 2_048
MAX_BRIEF_BYTES = 4_096

_SHA256_HEX_RE = re.compile(r"^[\da-f]{64}$", re.ASCII)
_ID_TOKEN_RE = re.compile(r"^[a-zA-Z\d][a-zA-Z\d._:-]{0,95}$", re.ASCII)
_MEDIA_TYPE_RE = re.compile(r"^[a-z\d][a-z\d.+_-]{0,31}/[a-z\d][a-z\d.+_-]{0,63}$", re.ASCII)
_CLOSING_PEER_TAG_RE = re.compile(r"</\s*oc-peer-message", re.IGNORECASE)
_OPENING_PEER_TAG_RE = re.compile(r"<\s*oc-peer-message", re.IGNORECASE)


class CoordError(RuntimeError):
    """Base coordination failure."""


class CoordValidationError(CoordError):
    """Malformed address, payload, or schema violation."""


class CoordAuthError(CoordError):
    """Authentication, authorization, or capability edge denial."""


class CoordPolicyError(CoordError):
    """Security policy, budget, or trust-boundary refusal."""


class CoordBackpressureError(CoordError):
    """Per-edge mailbox count/byte or rate limit exceeded."""


class DeadlockCycleError(CoordError):
    """Directed wait-for cycle detected across waiting peers."""


class IncarnationMismatchError(CoordError):
    """Target sandbox incarnation rotated; stale delivery refused."""


class RevokedError(CoordAuthError):
    """Job, sandbox, worker, or peer grant was revoked."""


class CoordRole(str, Enum):
    OPERATOR = "operator"
    ORCHESTRATOR = "orchestrator"
    JOB = "job"
    EXTERNAL_PEER = "external_peer"


class TrustClass(str, Enum):
    OPERATOR_DIRECTIVE = "OPERATOR_DIRECTIVE"
    PARENT_TASK = "PARENT_TASK"
    UNTRUSTED_PEER_DATA = "UNTRUSTED_PEER_DATA"
    SYSTEM_ALERT = "SYSTEM_ALERT"


class ProvenanceBadge(str, Enum):
    OPERATOR = "Operator"
    ORCHESTRATOR = "Orchestrator -o"
    PEER = "Peer"
    TUI_INPUT = "TUI Input · In-Sandbox"
    SANDBOX_LOCAL_UNVERIFIED = "Sandbox-Local / Unverified"


ROLE_TO_TRUST_CLASS: dict[CoordRole, TrustClass] = {
    CoordRole.OPERATOR: TrustClass.OPERATOR_DIRECTIVE,
    CoordRole.ORCHESTRATOR: TrustClass.PARENT_TASK,
    CoordRole.JOB: TrustClass.UNTRUSTED_PEER_DATA,
    CoordRole.EXTERNAL_PEER: TrustClass.UNTRUSTED_PEER_DATA,
}

STREAM_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "user_message",
        "text_delta",
        "reasoning_delta",
        "tool_call",
        "file_edit",
        "turn_completed",
        "turn_error",
        "revoked",
    }
)

SANDBOX_LIFECYCLE_STATES: frozenset[str] = frozenset(
    {"starting", "running", "stopped", "revoked", "degraded"}
)

CONTROL_PRIORITY_KINDS: frozenset[str] = frozenset({"cancel"})


def mint_crypto_id(prefix: str) -> str:
    """Mint a host-generated 128-bit cryptographic identifier."""
    clean_prefix = check_no_control_or_bidi(prefix, "id prefix")
    if not clean_prefix or not re.fullmatch(r"[a-z\d_-]{1,24}", clean_prefix, re.ASCII):
        raise CoordValidationError(f"Invalid id prefix: {prefix!r}")
    return f"{clean_prefix}_{secrets.token_hex(16)}"


def validate_opaque_token(value: object, label: str) -> str:
    text = check_no_control_or_bidi(value, label)
    if _ID_TOKEN_RE.fullmatch(text) is None:
        raise CoordValidationError(f"Invalid {label}: {text!r}")
    return text


_SECURITY_PROFILE_RANK: dict[str, int] = {
    "standard": 0,
    "desktop-wayland": 1,
    "elevated-nested": 2,
}


def validate_reason_text(reason: object, label: str = "reason") -> str:
    """Validate a bounded control/bidi-free operational reason string."""
    text = check_no_control_or_bidi(reason, label)
    if len(text.encode("utf-8")) > MAX_REASON_BYTES:
        raise CoordValidationError(f"{label} exceeds {MAX_REASON_BYTES} bytes")
    return text


def _has_unpaired_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def validate_stream_text(text: object) -> str:
    """Validate bounded UTF-8 stream event text with zero NUL or unpaired surrogates."""
    if not isinstance(text, str):
        raise CoordValidationError("StreamEvent text must be a string")
    if "\x00" in text or _has_unpaired_surrogate(text):
        raise CoordValidationError("StreamEvent text contains NUL or unpaired surrogate")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CoordValidationError("StreamEvent text is not valid UTF-8") from exc
    if len(encoded) > MAX_STREAM_EVENT_BYTES:
        raise CoordValidationError("StreamEvent text exceeds maximum bounded size")
    return text


def canonicalize_body_text(text: object, *, max_bytes: int = MAX_INLINE_BODY_BYTES) -> str:
    """Canonicalize inline text identically on write-ahead dispatch and event ingestion."""
    if not isinstance(text, str):
        raise CoordValidationError("body_text must be a string")
    if "\x00" in text:
        raise CoordValidationError("NUL byte forbidden in body_text")
    if _has_unpaired_surrogate(text):
        raise CoordValidationError("Unpaired surrogate forbidden in body_text")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CoordValidationError("body_text is not valid UTF-8") from exc
    if len(encoded) > max_bytes:
        raise CoordValidationError(f"body_text exceeds {max_bytes} bytes; use artifact_refs")
    return normalized


def sha256_canonical_body(text: str, *, max_bytes: int = MAX_FRAMED_BODY_BYTES) -> str:
    """Compute canonical UTF-8 SHA-256 hex digest of normalized body text."""
    return hashlib.sha256(
        canonicalize_body_text(text, max_bytes=max_bytes).encode("utf-8")
    ).hexdigest()


def validate_sandbox_rel_path(path: object) -> str:
    """Validate a sandbox-relative file path reported by untrusted WorkerTransport events."""
    text = check_no_control_or_bidi(path, "sandbox file path")
    if not text or len(text) > 512:
        raise CoordValidationError("sandbox file path must be 1..512 chars")
    if text.startswith("/") or "\\" in text or ":" in text:
        raise CoordValidationError(f"Absolute or non-POSIX sandbox path rejected: {text!r}")
    parts = text.split("/")
    if any(seg in ("", ".", "..") for seg in parts):
        raise CoordValidationError(f"Traversal or empty path segment rejected: {text!r}")
    return text


def frame_untrusted_peer_message(
    body_text: str,
    *,
    verified_sender: str,
    msg_kind: str,
    nonce: str | None = None,
) -> tuple[str, str]:
    """Wrap UNTRUSTED_PEER_DATA inside dual-tag 128-bit random-nonce delimiters.

    Returns (framed_text, nonce_hex). Escapes literal peer tag boundaries and
    strips/rejects control or bidi characters in metadata.
    """
    sender_clean = check_no_control_or_bidi(verified_sender, "verified_sender")
    if not sender_clean or any(ch in sender_clean for ch in ('"', "'", "<", ">")):
        raise CoordValidationError(f"Invalid verified_sender metadata: {verified_sender!r}")
    kind_clean = validate_msg_kind(msg_kind)
    canon_body = canonicalize_body_text(body_text)
    chosen_nonce = nonce if nonce is not None else secrets.token_hex(16)
    if not re.fullmatch(r"[\da-f]{32}", chosen_nonce, re.ASCII):
        raise CoordValidationError("nonce must be 32 lowercase hex characters (128-bit)")
    if chosen_nonce in canon_body:
        chosen_nonce = secrets.token_hex(16)
        while chosen_nonce in canon_body:
            chosen_nonce = secrets.token_hex(16)
    neutralized = _CLOSING_PEER_TAG_RE.sub("&lt;/oc-peer-message", canon_body)
    neutralized = _OPENING_PEER_TAG_RE.sub("&lt;oc-peer-message", neutralized)
    open_tag = (
        f'<oc-peer-message nonce="{chosen_nonce}" from="{sender_clean}" '
        f'kind="{kind_clean}" trust="untrusted-peer">'
    )
    close_tag = f'</oc-peer-message nonce="{chosen_nonce}">'
    framed = f"{open_tag}\n{neutralized}\n{close_tag}"
    if len(framed.encode("utf-8")) > MAX_FRAMED_BODY_BYTES:
        raise CoordValidationError(
            f"Framed peer message exceeds {MAX_FRAMED_BODY_BYTES} bytes; use artifact_refs"
        )
    return framed, chosen_nonce


@dataclass(frozen=True, slots=True)
class PrincipalCtx:
    """Host-authenticated caller identity (never constructed from client payload)."""

    role: CoordRole
    actor_id: str
    sandbox_addr: str | None = None
    incarnation_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.role, CoordRole):
            raise CoordValidationError("role must be CoordRole")
        validate_opaque_token(self.actor_id, "actor_id")
        if self.sandbox_addr is not None:
            parse_canonical_addr(self.sandbox_addr)
        if self.incarnation_id is not None:
            validate_opaque_token(self.incarnation_id, "incarnation_id")
        if self.role is CoordRole.JOB and (
            self.sandbox_addr is None or self.incarnation_id is None
        ):
            raise CoordValidationError("JOB principal requires sandbox_addr and incarnation_id")
        if self.role is CoordRole.ORCHESTRATOR and self.sandbox_addr is not None and self.incarnation_id is None:
            raise CoordValidationError("Sandbox-bound ORCHESTRATOR requires incarnation_id")

    @property
    def trust_class(self) -> TrustClass:
        return ROLE_TO_TRUST_CLASS[self.role]

    @property
    def canonical_sender(self) -> str:
        if self.role is CoordRole.OPERATOR:
            return f"operator:{self.actor_id}"
        if self.role is CoordRole.ORCHESTRATOR:
            target = self.sandbox_addr if self.sandbox_addr is not None else self.actor_id
            return f"orchestrator:{target}"
        if self.sandbox_addr is not None:
            return self.sandbox_addr
        return self.actor_id


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    """Digest-pinned host-spooled artifact/patch reference."""

    blob_sha256: str
    size_bytes: int
    media_type: str = "text/x-patch"

    def __post_init__(self) -> None:
        if not isinstance(self.blob_sha256, str) or _SHA256_HEX_RE.fullmatch(self.blob_sha256) is None:
            raise CoordValidationError("blob_sha256 must be 64 lowercase hex characters")
        if type(self.size_bytes) is not int or not (0 < self.size_bytes <= MAX_ARTIFACT_BYTES):
            raise CoordValidationError(f"artifact size_bytes must be 1..{MAX_ARTIFACT_BYTES}")
        mt = check_no_control_or_bidi(self.media_type, "media_type")
        if _MEDIA_TYPE_RE.fullmatch(mt) is None:
            raise CoordValidationError(f"Invalid artifact media_type: {mt!r}")


def _optional_subset(
    parent_set: frozenset[str] | None, child_set: frozenset[str] | None
) -> bool:
    if parent_set is None:
        return True
    if child_set is None:
        return False
    return child_set.issubset(parent_set)


@dataclass(frozen=True, slots=True)
class SubtreeBudget:
    """Monotonic capability budget delegated to a root or sub-orchestrator.

    Empty frozenset() ALWAYS means deny-all (never unrestricted). For models and
    variants, None explicitly represents unrestricted; once narrowed to a
    frozenset, descendants can never widen back to None or add entries.
    """

    max_depth_remaining: int = DEFAULT_MAX_SUBTREE_DEPTH
    max_children: int = DEFAULT_MAX_CHILDREN_PER_PARENT
    max_total_sandboxes: int = DEFAULT_MAX_TOTAL_SANDBOXES
    allowed_workers: frozenset[str] = frozenset({"local"})
    allowed_sandbox_types: frozenset[str] = frozenset({"default"})
    allowed_models: frozenset[str] | None = None
    allowed_variants: frozenset[str] | None = None
    allowed_broker_routes: frozenset[str] = frozenset()
    max_security_profile: str = "standard"

    def __post_init__(self) -> None:
        if type(self.max_depth_remaining) is not int or not (0 <= self.max_depth_remaining <= DEFAULT_MAX_SUBTREE_DEPTH):
            raise CoordValidationError("max_depth_remaining out of bounds")
        if type(self.max_children) is not int or not (0 <= self.max_children <= 32):
            raise CoordValidationError("max_children out of bounds")
        if type(self.max_total_sandboxes) is not int or not (1 <= self.max_total_sandboxes <= 64):
            raise CoordValidationError("max_total_sandboxes out of bounds")
        if self.max_security_profile not in _SECURITY_PROFILE_RANK:
            raise CoordValidationError(f"Invalid max_security_profile: {self.max_security_profile!r}")

    def attenuates(self, child: SubtreeBudget) -> bool:
        """Return True iff self can delegate child with strictly narrower depth and <= capability."""
        if self.max_depth_remaining == 0 or child.max_depth_remaining >= self.max_depth_remaining:
            return False
        if child.max_children > self.max_children or child.max_total_sandboxes > self.max_total_sandboxes:
            return False
        sets_ok = (
            child.allowed_workers.issubset(self.allowed_workers)
            and child.allowed_sandbox_types.issubset(self.allowed_sandbox_types)
            and child.allowed_broker_routes.issubset(self.allowed_broker_routes)
            and _optional_subset(self.allowed_models, child.allowed_models)
            and _optional_subset(self.allowed_variants, child.allowed_variants)
        )
        if not sets_ok:
            return False
        return (
            _SECURITY_PROFILE_RANK[child.max_security_profile]
            <= _SECURITY_PROFILE_RANK[self.max_security_profile]
        )


@dataclass(frozen=True, slots=True)
class SandboxRecord:
    """Host-owned metadata for a registered sandbox instance."""

    sandbox_addr: str
    worker_ref: str
    instance_name: str
    incarnation_id: str
    job_id: str
    project_id: str
    project_name: str
    branch: str
    sandbox_type: str
    task_brief: str
    status: str = "running"
    controller_request_id: str | None = None
    parent_addr: str | None = None
    depth: int = 0
    created_at: float = 0.0
    updated_at: float = 0.0


@dataclass(frozen=True, slots=True)
class ThreadRecord:
    """Projected thread under Project -> Sandbox -> Thread."""

    sandbox_addr: str
    incarnation_id: str
    thread_id: str
    title: str
    status: str = "idle"
    last_seq: int = 0
    updated_at: float = 0.0


@dataclass(frozen=True, slots=True)
class RoutingEdge:
    """Default-deny capability edge authorizing messaging between two endpoints."""

    edge_id: str
    src_actor: str
    src_incarnation: str | None
    dst_addr: str
    allowed_threads: frozenset[str]
    allowed_msg_kinds: frozenset[str]
    max_rounds: int = DEFAULT_EDGE_MAX_ROUNDS
    turns_used: int = 0
    rate_limit_rpm: int = 60
    active: bool = True
    lease_request_id: str | None = None
    grant_generation: int = 1
    created_at: float = 0.0


@dataclass(frozen=True, slots=True)
class Envelope:
    """Host-stamped immutable coordination envelope persisted in registry & audit log."""

    msg_id: str
    seq: int
    src_role: CoordRole
    src_actor: str
    src_incarnation: str | None
    dst_addr: str
    dst_thread_id: str
    dst_incarnation: str
    trust_class: TrustClass
    msg_kind: str
    body_text: str
    body_sha256: str
    edge_id: str
    edge_turn_seq: int
    in_reply_to: str | None = None
    artifact_refs: tuple[ArtifactRef, ...] = ()
    created_at: float = 0.0


@dataclass(frozen=True, slots=True)
class StreamEvent:
    """Untrusted event emitted by a WorkerTransport during turn execution."""

    event_type: str
    sandbox_addr: str
    incarnation_id: str
    thread_id: str
    seq_hint: int = 0
    message_id: str | None = None
    text: str = ""
    file_path: str | None = None
    detail: Mapping[str, Any] = field(default_factory=dict)
    created_at: float = 0.0

    def __post_init__(self) -> None:
        if self.event_type not in STREAM_EVENT_TYPES:
            raise CoordValidationError(f"Unsupported StreamEvent type: {self.event_type!r}")
        parse_canonical_addr(self.sandbox_addr)
        validate_opaque_token(self.incarnation_id, "incarnation_id")
        validate_thread_id(self.thread_id)
        validate_stream_text(self.text)
        if self.file_path is not None:
            validate_sandbox_rel_path(self.file_path)


class DispatchOutcome(str, Enum):
    """Fenced transport handoff result for an outbox delivery attempt."""

    HANDED_OFF = "handed_off"
    ZERO_BYTES_SENT = "zero_bytes_sent"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """Result of a fenced, nonblocking first-write attempt on WorkerTransport."""

    outcome: DispatchOutcome
    stream_id: str | None = None
    detail: str = ""
    permanent: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, DispatchOutcome):
            raise CoordValidationError("outcome must be DispatchOutcome")
        if type(self.permanent) is not bool:
            raise CoordValidationError("permanent must be a bool")
        if not isinstance(self.detail, str):
            raise CoordValidationError("detail must be a string")
        if self.stream_id is not None and not isinstance(self.stream_id, str):
            raise CoordValidationError("stream_id must be a string or None")
        if self.permanent and self.outcome is not DispatchOutcome.ZERO_BYTES_SENT:
            raise CoordValidationError(
                "permanent refusal requires DispatchOutcome.ZERO_BYTES_SENT"
            )

    @property
    def proves_zero_bytes_sent(self) -> bool:
        return self.outcome is DispatchOutcome.ZERO_BYTES_SENT


@dataclass(frozen=True, slots=True)
class TurnDispatch:
    """Host-to-WorkerTransport command payload for executing one turn."""

    msg_id: str
    sandbox_addr: str
    incarnation_id: str
    thread_id: str
    trust_class: TrustClass
    msg_kind: str
    wire_text: str
    body_sha256: str
    artifact_refs: tuple[ArtifactRef, ...] = ()
    edge_id: str = ""
    lease_request_id: str | None = None
    grant_generation: int = 1


@dataclass(frozen=True, slots=True)
class WorkerStatus:
    """Point-in-time status reported by a WorkerTransport."""

    sandbox_addr: str
    incarnation_id: str
    state: str
    active_turns: int = 0
    revoked: bool = False
    last_error: str | None = None


@dataclass(frozen=True, slots=True)
class RevocationStatus:
    """Terminal result returned when revoking a sandbox, job, or peer."""

    target_addr: str
    incarnation_id: str
    revoked_edges: int
    aborted_streams: bool
    elapsed_ms: float


def validate_task_brief(brief: object) -> str:
    """Require a non-blank, bounded, control/bidi-free task brief (prd_i1)."""
    if not isinstance(brief, str):
        raise CoordValidationError("task_brief must be a non-empty string")
    if "\x00" in brief or has_forbidden_control_or_bidi(brief.replace("\n", " ").replace("\t", " ")):
        raise CoordValidationError("task_brief contains forbidden control or bidi characters")
    stripped = brief.strip()
    if not stripped:
        raise CoordValidationError("task_brief must not be blank")
    if len(stripped.encode("utf-8")) > MAX_BRIEF_BYTES:
        raise CoordValidationError(f"task_brief exceeds {MAX_BRIEF_BYTES} bytes")
    return stripped


@runtime_checkable
class WorkerTransport(Protocol):
    """Pluggable worker execution interface shared by FakeWorkerTransport and local OpenCode jobs."""

    def dispatch_turn(self, turn: TurnDispatch) -> DispatchResult:
        """Attempt fenced nonblocking handoff for (sandbox_addr, incarnation_id, thread_id)."""
        ...

    def stream_events(self, stream_id: str) -> Iterable[StreamEvent]:
        """Yield bounded StreamEvents until turn_completed, turn_error, or revoked."""
        ...

    def abort_incarnation(self, sandbox_addr: str, incarnation_id: str, *, reason: str) -> bool:
        """Immediately stop active streams for this incarnation and deny all subsequent dispatches."""
        ...

    def status(self, sandbox_addr: str, incarnation_id: str) -> WorkerStatus:
        """Return current transport status for the given sandbox incarnation."""
        ...


@runtime_checkable
class ExternallyFencedTransport(WorkerTransport, Protocol):
    """Opt-in protocol for an operator-only, unmonitored, whole-incarnation relay adapter."""

    @property
    def external_write_fence(self) -> bool:
        """Return True to opt into CoordHub's narrow operator-only split-phase handoff."""
        ...

    def transport_owner_id(self, sandbox_addr: str, incarnation_id: str) -> str:
        """Return the stable opaque trusted owner/job identity for this exact incarnation; raise if unknown."""
        ...

    def confirm_incarnation_terminal(
        self,
        sandbox_addr: str,
        incarnation_id: str,
        *,
        owner_id: str,
        reason: str,
    ) -> bool:
        """Confirm terminal grant or verified stop for the exact (sandbox_addr, incarnation_id, owner_id); return True iff positively confirmed."""
        ...


def is_control_priority(trust_class: TrustClass, msg_kind: str) -> bool:
    """Return True if an envelope belongs on the unstarvable Control Priority Queue."""
    return trust_class is TrustClass.OPERATOR_DIRECTIVE or msg_kind in CONTROL_PRIORITY_KINDS
