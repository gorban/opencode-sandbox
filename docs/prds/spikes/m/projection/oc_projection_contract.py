"""Read-only projection contract, bounds, and canonical cursor codec for PRD M3.1.

Pure Python standard library plus read-only imports from docs/prds/spikes/m.
All snapshot structures serialize strictly with ``allow_nan=False`` and stay
bounded by explicit UTF-8 JSON byte ceilings.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

_PROJECTION_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _PROJECTION_DIR.parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
for _import_dir in (str(_SPIKE_M_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_address import AddressError, parse_local_target  # noqa: E402
from oc_coord_contract import CoordValidationError, validate_opaque_token  # noqa: E402

PROJECTION_SCHEMA_VERSION = "oc.m3.readonly_projection@1"

MAX_SANDBOXES_PER_PAGE = 50
MAX_PROJECTS_PER_PAGE = 50
MAX_THREADS_PER_SANDBOX = 50
MAX_EDGES_PER_SANDBOX = 100
MAX_PAGE_LIMIT = 200
DEFAULT_PAGE_LIMIT = 50
MIN_RESPONSE_BYTES = 1024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_ITEM_TEXT_BYTES = 16 * 1024
MAX_METADATA_TEXT_BYTES = 256
MAX_PROJECT_ID_HASH_BYTES = 4096
SQL_MAX_CELL_BYTES = 65_536
MAX_HASH_TEXT_BYTES = 69_632
MAX_JSON_DEPTH = 8
MAX_CURSOR_BYTES = 512
MAX_UNCONFIRMED_BINDINGS_SUMMARY = 50
DEFAULT_MAX_READ_MS = 2000
MIN_READ_MS = 50
MAX_READ_MS = 10_000
MAX_MARKER_BYTES = 256
MAX_AMBIGUITY_CANDIDATES = 16

CURSOR_PREFIX = "v1."
_CURSOR_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)
_SCOPE_HASH_RE = re.compile(r"^[0-9a-f]{16}$", re.ASCII)

OP_TREE = "tree"
OP_EVENTS = "events"
OP_MAILBOX = "mailbox"
VALID_CURSOR_OPS = frozenset({OP_TREE, OP_EVENTS, OP_MAILBOX})

ERR_CURSOR_MALFORMED = "cursor_malformed"
ERR_CURSOR_SCOPE_MISMATCH = "cursor_scope_mismatch"

HEALTH_HEALTHY = "healthy"
HEALTH_DEGRADED = "degraded"
HEALTH_UNKNOWN = "unknown"

SOURCE_EVENT_LOG = "event_log"
SOURCE_STREAM_EVENT = "stream_event"

_K_SCHEMA_VERSION = "schema_version"
_K_SNAPSHOT_SEQ = "snapshot_seq"
_K_SANDBOX_ADDR = "sandbox_addr"
_K_INCARNATION_ID = "incarnation_id"
_K_READ_SESSION = "read_session"
_K_MALFORMED_METADATA = "malformed_metadata"
_K_NEXT_CURSOR = "next_cursor"
_K_UPDATED_AT = "updated_at"
_K_UTF8 = "utf-8"
_K_CREATED_AT = "created_at"


def _as_dict_if_present(obj: Any) -> Any:
    return None if obj is None else obj.to_dict()


@dataclass(frozen=True, slots=True)
class ReadSessionEcho:
    """Validated operator read-session coordinates echoed on snapshots."""

    read_session_id: str
    session_generation: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "read_session_id": self.read_session_id,
            "session_generation": self.session_generation,
        }


@dataclass(frozen=True, slots=True)
class UnconfirmedBindingSummary:
    """Bounded diagnostic view of an unconfirmed or malformed transport binding."""

    sandbox_addr: str | None
    incarnation_id: str | None
    abort_requested: bool
    terminal_confirmed: bool
    reason: str
    reason_truncated: bool
    updated_at: float
    sandbox_status: str | None
    current_incarnation: str | None
    sandbox_missing: bool
    malformed_identity: bool = False
    malformed_metadata: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SANDBOX_ADDR: self.sandbox_addr,
            _K_INCARNATION_ID: self.incarnation_id,
            "abort_requested": self.abort_requested,
            "terminal_confirmed": self.terminal_confirmed,
            "reason": self.reason,
            "reason_truncated": self.reason_truncated,
            _K_UPDATED_AT: self.updated_at,
            "sandbox_status": self.sandbox_status,
            "current_incarnation": self.current_incarnation,
            "sandbox_missing": self.sandbox_missing,
            "malformed_identity": self.malformed_identity,
            _K_MALFORMED_METADATA: self.malformed_metadata,
        }


@dataclass(frozen=True, slots=True)
class WorkspaceHealthSummary:
    """Compact fixed-footprint health summary embedded on event/mailbox pages."""

    health_status: str
    degraded: bool
    session_active_marker_present: bool
    live_status_available: bool
    has_unconfirmed_bindings: bool
    unconfirmed_bindings_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "health_status": self.health_status,
            "degraded": self.degraded,
            "session_active_marker_present": self.session_active_marker_present,
            "live_status_available": self.live_status_available,
            "has_unconfirmed_bindings": self.has_unconfirmed_bindings,
            "unconfirmed_bindings_count": self.unconfirmed_bindings_count,
        }


@dataclass(frozen=True, slots=True)
class WorkspaceHealth:
    """Full observed workspace health snapshot for tree and sandbox status views."""

    health_status: str
    degraded: bool
    degraded_reasons: tuple[str, ...]
    degraded_marker_present: bool
    degraded_marker_reason: str | None
    marker_unreadable: bool
    session_active_marker_present: bool
    live_status_available: bool
    has_unconfirmed_bindings: bool
    unconfirmed_bindings_count: int
    unconfirmed_bindings: tuple[UnconfirmedBindingSummary, ...]
    unconfirmed_bindings_truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "health_status": self.health_status,
            "degraded": self.degraded,
            "degraded_reasons": list(self.degraded_reasons),
            "degraded_marker_present": self.degraded_marker_present,
            "degraded_marker_reason": self.degraded_marker_reason,
            "marker_unreadable": self.marker_unreadable,
            "session_active_marker_present": self.session_active_marker_present,
            "live_status_available": self.live_status_available,
            "has_unconfirmed_bindings": self.has_unconfirmed_bindings,
            "unconfirmed_bindings_count": self.unconfirmed_bindings_count,
            "unconfirmed_bindings": [b.to_dict() for b in self.unconfirmed_bindings],
            "unconfirmed_bindings_truncated": self.unconfirmed_bindings_truncated,
        }


@dataclass(frozen=True, slots=True)
class ProjectedArtifactRef:
    """Projected digest-pinned artifact reference matching ArtifactRef."""

    blob_sha256: str
    size_bytes: int
    media_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "blob_sha256": self.blob_sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
        }


@dataclass(frozen=True, slots=True)
class ProjectedThreadSummary:
    """Bounded summary of one thread under a sandbox node."""

    thread_id: str
    incarnation_id: str
    is_current_incarnation: bool
    title: str
    title_truncated: bool
    status: str
    last_seq: int
    updated_at: float
    malformed_metadata: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "thread_id": self.thread_id,
            _K_INCARNATION_ID: self.incarnation_id,
            "is_current_incarnation": self.is_current_incarnation,
            "title": self.title,
            "title_truncated": self.title_truncated,
            "status": self.status,
            "last_seq": self.last_seq,
            _K_UPDATED_AT: self.updated_at,
            _K_MALFORMED_METADATA: self.malformed_metadata,
        }


@dataclass(frozen=True, slots=True)
class ProjectedSandboxNode:
    """Bounded read-only projection of one sandbox node."""

    sandbox_addr: str
    worker_ref: str
    instance_name: str
    incarnation_id: str
    job_id: str
    project_id: str
    project_id_sha256: str | None
    project_id_truncated: bool
    project_name: str
    project_name_truncated: bool
    branch: str
    branch_truncated: bool
    sandbox_type: str
    task_brief: str
    task_brief_truncated: bool
    status: str
    parent_addr: str | None
    depth: int
    created_at: float
    updated_at: float
    threads: tuple[ProjectedThreadSummary, ...]
    threads_truncated: bool
    historical_thread_count: int
    active_grant_count: int
    revoked_grant_count: int
    outbox_counts: Mapping[str, int]
    binding_state: str
    malformed_metadata: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SANDBOX_ADDR: self.sandbox_addr,
            "worker_ref": self.worker_ref,
            "instance_name": self.instance_name,
            _K_INCARNATION_ID: self.incarnation_id,
            "job_id": self.job_id,
            "project_id": self.project_id,
            "project_id_sha256": self.project_id_sha256,
            "project_id_truncated": self.project_id_truncated,
            "project_name": self.project_name,
            "project_name_truncated": self.project_name_truncated,
            "branch": self.branch,
            "branch_truncated": self.branch_truncated,
            "sandbox_type": self.sandbox_type,
            "task_brief": self.task_brief,
            "task_brief_truncated": self.task_brief_truncated,
            "status": self.status,
            "parent_addr": self.parent_addr,
            "depth": self.depth,
            _K_CREATED_AT: self.created_at,
            _K_UPDATED_AT: self.updated_at,
            "threads": [t.to_dict() for t in self.threads],
            "threads_truncated": self.threads_truncated,
            "historical_thread_count": self.historical_thread_count,
            "active_grant_count": self.active_grant_count,
            "revoked_grant_count": self.revoked_grant_count,
            "outbox_counts": dict(sorted(self.outbox_counts.items())),
            "binding_state": self.binding_state,
            _K_MALFORMED_METADATA: self.malformed_metadata,
        }


@dataclass(frozen=True, slots=True)
class ProjectedProjectGroup:
    """Project grouping within one workspace-tree page."""

    project_id: str
    project_id_sha256: str | None
    project_id_truncated: bool
    project_name: str
    sandboxes: tuple[ProjectedSandboxNode, ...]
    malformed_metadata: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "project_id_sha256": self.project_id_sha256,
            "project_id_truncated": self.project_id_truncated,
            "project_name": self.project_name,
            "sandboxes": [s.to_dict() for s in self.sandboxes],
            _K_MALFORMED_METADATA: self.malformed_metadata,
        }


@dataclass(frozen=True, slots=True)
class WorkspaceTreeSnapshot:
    """Bounded Project -> Sandbox -> Thread snapshot page."""

    schema_version: str
    snapshot_seq: int
    health: WorkspaceHealth
    projects: tuple[ProjectedProjectGroup, ...]
    has_more: bool
    next_cursor: str | None
    read_session: ReadSessionEcho | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SCHEMA_VERSION: self.schema_version,
            _K_SNAPSHOT_SEQ: self.snapshot_seq,
            "health": self.health.to_dict(),
            "projects": [p.to_dict() for p in self.projects],
            "has_more": self.has_more,
            _K_NEXT_CURSOR: self.next_cursor,
            _K_READ_SESSION: _as_dict_if_present(self.read_session),
        }


@dataclass(frozen=True, slots=True)
class ProjectedRoutingEdge:
    """Bounded read-only projection of a capability routing edge."""

    edge_id: str
    src_actor: str
    src_incarnation: str | None
    dst_addr: str
    allowed_threads: tuple[str, ...]
    allowed_msg_kinds: tuple[str, ...]
    max_rounds: int
    turns_used: int
    rate_limit_rpm: int
    active: bool
    grant_generation: int
    tombstoned: bool
    tombstone_reason: str | None
    tombstone_revoked_at: float | None
    created_at: float
    malformed_metadata: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "src_actor": self.src_actor,
            "src_incarnation": self.src_incarnation,
            "dst_addr": self.dst_addr,
            "allowed_threads": list(self.allowed_threads),
            "allowed_msg_kinds": list(self.allowed_msg_kinds),
            "max_rounds": self.max_rounds,
            "turns_used": self.turns_used,
            "rate_limit_rpm": self.rate_limit_rpm,
            "active": self.active,
            "grant_generation": self.grant_generation,
            "tombstoned": self.tombstoned,
            "tombstone_reason": self.tombstone_reason,
            "tombstone_revoked_at": self.tombstone_revoked_at,
            _K_CREATED_AT: self.created_at,
            _K_MALFORMED_METADATA: self.malformed_metadata,
        }


@dataclass(frozen=True, slots=True)
class ProjectedSubtreeBudget:
    """Read-only JSON-safe projection of SubtreeBudget."""

    max_depth_remaining: int
    max_children: int
    max_total_sandboxes: int
    allowed_workers: tuple[str, ...]
    allowed_sandbox_types: tuple[str, ...]
    allowed_models: tuple[str, ...] | None
    allowed_variants: tuple[str, ...] | None
    allowed_broker_routes: tuple[str, ...]
    max_security_profile: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_depth_remaining": self.max_depth_remaining,
            "max_children": self.max_children,
            "max_total_sandboxes": self.max_total_sandboxes,
            "allowed_workers": list(self.allowed_workers),
            "allowed_sandbox_types": list(self.allowed_sandbox_types),
            "allowed_models": None if self.allowed_models is None else list(self.allowed_models),
            "allowed_variants": (
                None if self.allowed_variants is None else list(self.allowed_variants)
            ),
            "allowed_broker_routes": list(self.allowed_broker_routes),
            "max_security_profile": self.max_security_profile,
        }


@dataclass(frozen=True, slots=True)
class SandboxStatusSnapshot:
    """Bounded detailed status snapshot for a single sandbox."""

    schema_version: str
    snapshot_seq: int
    health: WorkspaceHealth
    sandbox: ProjectedSandboxNode
    edges: tuple[ProjectedRoutingEdge, ...]
    edges_truncated: bool
    binding: UnconfirmedBindingSummary | None
    budget: ProjectedSubtreeBudget | None
    budget_malformed: bool
    read_session: ReadSessionEcho | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SCHEMA_VERSION: self.schema_version,
            _K_SNAPSHOT_SEQ: self.snapshot_seq,
            "health": self.health.to_dict(),
            "sandbox": self.sandbox.to_dict(),
            "edges": [e.to_dict() for e in self.edges],
            "edges_truncated": self.edges_truncated,
            "binding": _as_dict_if_present(self.binding),
            "budget": _as_dict_if_present(self.budget),
            "budget_malformed": self.budget_malformed,
            _K_READ_SESSION: _as_dict_if_present(self.read_session),
        }


@dataclass(frozen=True, slots=True)
class ProjectedThreadEvent:
    """Inert, provenance-verified projection of an event_log or stream_events row."""

    source: str
    source_rank: int
    seq: int
    event_type: str
    sandbox_addr: str
    incarnation_id: str
    thread_id: str
    msg_id: str | None
    message_id: str | None
    dispatch_msg_id: str | None
    src_role: str | None
    src_actor: str | None
    verified_actor: str | None
    trust_class: str | None
    msg_kind: str | None
    raw_badge: str | None
    effective_badge: str | None
    authority_rank: int
    untrusted_content: bool
    provenance_anomaly: bool
    anomaly_reason: str | None
    text: str
    text_truncated: bool
    text_suffix_uninspected: bool
    original_text_bytes: int
    has_control_or_bidi: bool
    file_path: str | None
    in_reply_to: str | None
    edge_id: str | None
    edge_turn_seq: int | None
    seq_hint: int | None
    artifact_refs: tuple[ProjectedArtifactRef, ...]
    detail: Mapping[str, Any]
    created_at: float
    malformed_metadata: bool = False

    def _optional_event_fields(self) -> tuple[tuple[str, Any], ...]:
        msg_id_val = None if self.source == SOURCE_EVENT_LOG else self.message_id
        same_actor = (
            self.source == SOURCE_EVENT_LOG and self.verified_actor == self.src_actor
        )
        ver_actor_val = None if same_actor else self.verified_actor
        raw_badge_val = None if self.raw_badge == self.effective_badge else self.raw_badge
        return (
            ("msg_id", self.msg_id),
            ("message_id", msg_id_val),
            ("dispatch_msg_id", self.dispatch_msg_id),
            ("src_role", self.src_role),
            ("src_actor", self.src_actor),
            ("verified_actor", ver_actor_val),
            ("trust_class", self.trust_class),
            ("msg_kind", self.msg_kind),
            ("raw_badge", raw_badge_val),
            ("anomaly_reason", self.anomaly_reason),
            ("file_path", self.file_path),
            ("in_reply_to", self.in_reply_to),
            ("edge_id", self.edge_id),
            ("edge_turn_seq", self.edge_turn_seq),
            ("seq_hint", self.seq_hint),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "source": self.source,
            "seq": self.seq,
            "event_type": self.event_type,
            "effective_badge": self.effective_badge,
            "authority_rank": self.authority_rank,
            "untrusted_content": self.untrusted_content,
            "text": self.text,
            "text_truncated": self.text_truncated,
            "original_text_bytes": self.original_text_bytes,
            _K_CREATED_AT: self.created_at,
        }
        flag_fields = (
            ("text_suffix_uninspected", self.text_suffix_uninspected),
            ("has_control_or_bidi", self.has_control_or_bidi),
            ("provenance_anomaly", self.provenance_anomaly),
            (_K_MALFORMED_METADATA, self.malformed_metadata),
        )
        for key, flag in flag_fields:
            if flag:
                out[key] = True
        for key, value in self._optional_event_fields():
            if value is not None:
                out[key] = value
        if self.artifact_refs:
            out["artifact_refs"] = [a.to_dict() for a in self.artifact_refs]
        if self.detail:
            out["detail"] = dict(self.detail)
        return out


@dataclass(frozen=True, slots=True)
class ThreadEventsPage:
    """Bounded paginated timeline for one sandbox incarnation thread."""

    schema_version: str
    snapshot_seq: int
    health: WorkspaceHealthSummary
    sandbox_addr: str
    applied_incarnation_id: str
    is_current_incarnation: bool
    stale_reason: str | None
    thread_id: str
    thread_exists: bool
    events: tuple[ProjectedThreadEvent, ...]
    has_more: bool
    next_cursor: str | None
    read_session: ReadSessionEcho | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            _K_SCHEMA_VERSION: self.schema_version,
            _K_SNAPSHOT_SEQ: self.snapshot_seq,
            "health": self.health.to_dict(),
            _K_SANDBOX_ADDR: self.sandbox_addr,
            "applied_incarnation_id": self.applied_incarnation_id,
            "is_current_incarnation": self.is_current_incarnation,
            "thread_id": self.thread_id,
            "thread_exists": self.thread_exists,
            "events": [e.to_dict() for e in self.events],
            "has_more": self.has_more,
        }
        if self.stale_reason is not None:
            out["stale_reason"] = self.stale_reason
        if self.next_cursor is not None:
            out[_K_NEXT_CURSOR] = self.next_cursor
        if self.read_session is not None:
            out[_K_READ_SESSION] = self.read_session.to_dict()
        return out


@dataclass(frozen=True, slots=True)
class ProjectedMailboxEntry:
    """Bounded read-only projection of one outbox row and joined metadata."""

    seq: int
    msg_id: str
    edge_id: str
    grant_generation: int
    src_actor: str | None
    src_role: str | None
    src_incarnation: str | None
    src_sandbox_status: str | None
    src_current_incarnation: str | None
    dst_incarnation: str
    thread_id: str
    trust_class: str | None
    msg_kind: str | None
    priority: int
    status: str
    body_bytes: int
    attempts: int
    stream_id: str | None
    detail: str
    detail_truncated: bool
    grant_active: bool | None
    grant_tombstoned: bool
    updated_at: float
    malformed_metadata: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "msg_id": self.msg_id,
            "edge_id": self.edge_id,
            "grant_generation": self.grant_generation,
            "src_actor": self.src_actor,
            "src_role": self.src_role,
            "src_incarnation": self.src_incarnation,
            "src_sandbox_status": self.src_sandbox_status,
            "src_current_incarnation": self.src_current_incarnation,
            "dst_incarnation": self.dst_incarnation,
            "thread_id": self.thread_id,
            "trust_class": self.trust_class,
            "msg_kind": self.msg_kind,
            "priority": self.priority,
            "status": self.status,
            "body_bytes": self.body_bytes,
            "attempts": self.attempts,
            "stream_id": self.stream_id,
            "detail": self.detail,
            "detail_truncated": self.detail_truncated,
            "grant_active": self.grant_active,
            "grant_tombstoned": self.grant_tombstoned,
            _K_UPDATED_AT: self.updated_at,
            _K_MALFORMED_METADATA: self.malformed_metadata,
        }


@dataclass(frozen=True, slots=True)
class MailboxPage:
    """Bounded paginated mailbox snapshot for one sandbox."""

    schema_version: str
    snapshot_seq: int
    health: WorkspaceHealthSummary
    sandbox_addr: str
    current_incarnation_id: str
    entries: tuple[ProjectedMailboxEntry, ...]
    has_more: bool
    next_cursor: str | None
    read_session: ReadSessionEcho | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SCHEMA_VERSION: self.schema_version,
            _K_SNAPSHOT_SEQ: self.snapshot_seq,
            "health": self.health.to_dict(),
            _K_SANDBOX_ADDR: self.sandbox_addr,
            "current_incarnation_id": self.current_incarnation_id,
            "entries": [e.to_dict() for e in self.entries],
            "has_more": self.has_more,
            _K_NEXT_CURSOR: self.next_cursor,
            _K_READ_SESSION: _as_dict_if_present(self.read_session),
        }


def serialize_projection_json(obj: Any) -> str:
    """Serialize a projection snapshot or mapping strictly without NaN/Infinity."""
    payload = obj.to_dict() if hasattr(obj, "to_dict") else obj
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def serialize_projection_bytes(obj: Any) -> bytes:
    """Return exact UTF-8 JSON bytes for hard response-size budget enforcement."""
    return serialize_projection_json(obj).encode("utf-8")


def compute_scope_hash(op: str, **params: Any) -> str:
    """Compute a 16-hex-char SHA-256 scope fingerprint for cursor binding."""
    canonical = json.dumps(
        {"op": op, "params": params},
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:16]


def encode_cursor(payload: Mapping[str, Any]) -> str:
    """Encode a canonical base64url JSON cursor bounded by MAX_CURSOR_BYTES."""
    raw_json = json.dumps(
        dict(payload),
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    cursor = f"{CURSOR_PREFIX}{encoded}"
    if len(cursor.encode("utf-8")) > MAX_CURSOR_BYTES:
        raise CoordValidationError("cursor_exceeds_max_bytes")
    return cursor


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"Forbidden JSON constant: {token}")


def _decode_raw_cursor_dict(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    raw_bytes = raw.encode("utf-8", errors="surrogatepass")
    if len(raw_bytes) > MAX_CURSOR_BYTES or not raw.startswith(CURSOR_PREFIX):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    b64_part = raw[len(CURSOR_PREFIX) :]
    if not b64_part or _CURSOR_B64URL_RE.fullmatch(b64_part) is None:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    pad_len = (-len(b64_part)) % 4
    if pad_len == 3:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        decoded_bytes = base64.urlsafe_b64decode(b64_part + ("=" * pad_len))
        parsed = json.loads(
            decoded_bytes.decode("utf-8"), parse_constant=_reject_json_constant
        )
    except (ValueError, UnicodeDecodeError) as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if not isinstance(parsed, dict):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        canonical = encode_cursor(parsed)
    except (ValueError, TypeError, CoordValidationError) as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if canonical != raw:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return parsed


def _validate_cursor_header(
    parsed: Mapping[str, Any], *, expected_op: str, expected_scope_hash: str
) -> None:
    op = parsed.get("op")
    fh = parsed.get("fh")
    if not isinstance(op, str) or op not in VALID_CURSOR_OPS:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if not isinstance(fh, str) or _SCOPE_HASH_RE.fullmatch(fh) is None:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if op != expected_op or fh != expected_scope_hash:
        raise CoordValidationError(ERR_CURSOR_SCOPE_MISMATCH)


def _is_strict_nonneg_int(val: Any) -> bool:
    return type(val) is int and val >= 0


def decode_tree_cursor(
    raw: object, *, expected_scope_hash: str
) -> str | None:
    """Decode and validate a workspace-tree cursor, returning ``after_addr``."""
    if raw is None:
        return None
    parsed = _decode_raw_cursor_dict(raw)
    _validate_cursor_header(parsed, expected_op=OP_TREE, expected_scope_hash=expected_scope_hash)
    if set(parsed.keys()) != {"op", "fh", "addr"}:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    addr = parsed["addr"]
    try:
        canonical = parse_local_target(addr).canonical
    except AddressError as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if canonical != addr:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return canonical


def encode_tree_cursor(*, scope_hash: str, sandbox_addr: str) -> str:
    return encode_cursor({"op": OP_TREE, "fh": scope_hash, "addr": sandbox_addr})


def decode_events_cursor(
    raw: object, *, expected_scope_hash: str, expected_incarnation_id: str
) -> tuple[int, int] | None:
    """Decode and validate a thread-events cursor, returning ``(seq, rank)``."""
    if raw is None:
        return None
    parsed = _decode_raw_cursor_dict(raw)
    _validate_cursor_header(parsed, expected_op=OP_EVENTS, expected_scope_hash=expected_scope_hash)
    if set(parsed.keys()) != {"op", "fh", "seq", "rank", "inc"}:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    seq = parsed["seq"]
    rank = parsed["rank"]
    inc = parsed["inc"]
    if not _is_strict_nonneg_int(seq) or type(rank) is not int or rank not in (0, 1):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        validate_opaque_token(inc, _K_INCARNATION_ID)
    except (AddressError, CoordValidationError) as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if inc != expected_incarnation_id:
        raise CoordValidationError(ERR_CURSOR_SCOPE_MISMATCH)
    return seq, rank


def encode_events_cursor(
    *, scope_hash: str, seq: int, rank: int, incarnation_id: str
) -> str:
    return encode_cursor(
        {
            "op": OP_EVENTS,
            "fh": scope_hash,
            "seq": seq,
            "rank": rank,
            "inc": incarnation_id,
        }
    )


def decode_mailbox_cursor(
    raw: object, *, expected_scope_hash: str
) -> tuple[int, str] | None:
    """Decode and validate a sandbox-mailbox cursor, returning ``(seq, msg_id)``."""
    if raw is None:
        return None
    parsed = _decode_raw_cursor_dict(raw)
    _validate_cursor_header(
        parsed, expected_op=OP_MAILBOX, expected_scope_hash=expected_scope_hash
    )
    if set(parsed.keys()) != {"op", "fh", "seq", "mid"}:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    seq = parsed["seq"]
    mid = parsed["mid"]
    if not _is_strict_nonneg_int(seq):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        validate_opaque_token(mid, "msg_id")
    except (AddressError, CoordValidationError) as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    return seq, mid


def encode_mailbox_cursor(*, scope_hash: str, seq: int, msg_id: str) -> str:
    return encode_cursor({"op": OP_MAILBOX, "fh": scope_hash, "seq": seq, "mid": msg_id})
