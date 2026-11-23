"""Read-only Tier-B Human Inbox contract, bounds, review-pin digest, and cursor codec.

Pure Python standard library plus strictly read-only imports from
docs/prds/spikes/{m,n}. Every dataclass constructor stays <= 12 parameters
(including ``self``), and all snapshots serialize strictly with
``allow_nan=False`` within explicit UTF-8 JSON byte ceilings.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, cast

_INBOX_DIR = Path(__file__).resolve().parent
_SPIKE_N_DIR = _INBOX_DIR.parent
_SPIKE_M_DIR = _SPIKE_N_DIR.parent / "m"
for _import_dir in (str(_SPIKE_N_DIR), str(_SPIKE_M_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_address import AddressError  # noqa: E402
from oc_coord_contract import (  # noqa: E402
    _SHA256_HEX_RE,
    CoordValidationError,
    validate_opaque_token,
)
from oc_workflow_schema import domain_sha256  # noqa: E402

INBOX_SCHEMA_VERSION = "oc.n3.readonly_inbox@1"
REVIEW_PIN_DOMAIN = "oc-n3-inbox-review-pin-v1:"
PIN_VERIFICATION_SCOPE_ITEM_ONLY = "item_read_only"

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 100
MAX_ARTIFACTS_PER_ITEM = 16
MIN_RESPONSE_BYTES = 2048
MAX_RESPONSE_BYTES = 256 * 1024
DEFAULT_MAX_RESPONSE_BYTES = MAX_RESPONSE_BYTES
MAX_ITEM_TEXT_BYTES = 16 * 1024
MAX_METADATA_TEXT_BYTES = 256
MAX_METADATA_KEY_BYTES = 64
MAX_METADATA_KEYS = 32
MAX_METADATA_LIST_ITEMS = 32
SQL_MAX_CELL_BYTES = 65_536
MAX_JSON_DEPTH = 8
MAX_CURSOR_BYTES = 512
MAX_OPAQUE_TOKEN_CHARS = 96
MAX_STATUS_FILTER_ITEMS = 16
MAX_PRIORITY_RANK = 100
DEFAULT_MAX_READ_MS = 2000
MIN_READ_MS = 50
MAX_READ_MS = 10_000
MAX_SQLITE_INT64 = (1 << 63) - 1

STATUS_PENDING = "pending"
STATUS_SUPERSEDED = "superseded"
STATUS_EXPIRED = "expired"
STATUS_RESOLVED = "resolved"
VALID_STATUSES: frozenset[str] = frozenset(
    {STATUS_PENDING, STATUS_SUPERSEDED, STATUS_EXPIRED, STATUS_RESOLVED}
)

SEVERITY_LOW = "low"
SEVERITY_NORMAL = "normal"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
VALID_SEVERITIES: frozenset[str] = frozenset(
    {SEVERITY_LOW, SEVERITY_NORMAL, SEVERITY_HIGH, SEVERITY_CRITICAL}
)

SOURCE_HOST_WORKFLOW_ENGINE = "host_workflow_engine"
SOURCE_SUPERVISION_ESCALATION = "supervision_escalation"
SOURCE_ORCHESTRATOR_ADVISORY = "orchestrator_advisory"
SOURCE_CALIBRATION_DRIFT = "calibration_drift"
VALID_SOURCE_KINDS: frozenset[str] = frozenset(
    {
        SOURCE_HOST_WORKFLOW_ENGINE,
        SOURCE_SUPERVISION_ESCALATION,
        SOURCE_ORCHESTRATOR_ADVISORY,
        SOURCE_CALIBRATION_DRIFT,
    }
)

BUCKET_MALFORMED = "malformed"

ANOMALY_TAMPERED_STORAGE = "tampered_storage_class"
ANOMALY_MALFORMED_PIN_INPUT = "malformed_pin_input"
ANOMALY_PIN_MISMATCH = "review_pin_mismatch"
ANOMALY_RUN_MISSING = "workflow_run_missing"
ANOMALY_POLICY_MISMATCH = "policy_digest_mismatch"
ANOMALY_ARTIFACT_MISSING = "primary_artifact_missing"
ANOMALY_ARTIFACT_AMBIGUOUS = "ambiguous_primary_artifact"
ANOMALY_ARTIFACT_MISMATCH = "artifact_digest_mismatch"
ANOMALY_MALFORMED_METADATA = "malformed_item_metadata"

VALID_PIN_ANOMALIES: frozenset[str] = frozenset(
    {
        ANOMALY_TAMPERED_STORAGE,
        ANOMALY_MALFORMED_PIN_INPUT,
        ANOMALY_PIN_MISMATCH,
        ANOMALY_RUN_MISSING,
        ANOMALY_POLICY_MISMATCH,
        ANOMALY_ARTIFACT_MISSING,
        ANOMALY_ARTIFACT_AMBIGUOUS,
        ANOMALY_ARTIFACT_MISMATCH,
        ANOMALY_MALFORMED_METADATA,
    }
)

CURSOR_PREFIX = "v1."
OP_INBOX_LIST = "inbox_list"
ERR_CURSOR_MALFORMED = "cursor_malformed"
ERR_CURSOR_SCOPE_MISMATCH = "cursor_scope_mismatch"
ERR_CURSOR_SNAPSHOT_CHANGED = "cursor_snapshot_changed"

REDACTED_MARKER = "[REDACTED]"
_UTF8 = "utf-8"

_CURSOR_B64URL_RE = re.compile(r"^[A-Za-z\d_-]+$", re.ASCII)
_SCOPE_HASH_RE = re.compile(r"^[\da-f]{16}$", re.ASCII)

# Stage-2 enumerated credential-pattern redactors (ordered).
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z\d ]{0,32}PRIVATE KEY-----[\s\S]*?"
    r"(?:-----END [A-Z\d ]{0,32}PRIVATE KEY-----|$)"
)
_URL_BASIC_AUTH_RE = re.compile(
    r"(?i)((?:https?|postgres(?:ql)?|redis|ftp|sftp)://)[^\s/@:]+:[^\s/@]*(@|$)"
)
_HEADER_QUOTED_RE = re.compile(
    r"(?i)(?<![a-z\d_.-])"
    r"((?:proxy[_-]?)?authorization|set[_-]?cookie|cookie|auth[_-]?header|x[_-]?api[_-]?key)"
    r"([\"']?\s*[:=]\s*)"
    r"(?:\"(?:\\[\s\S]|[^\"\\])*(?:\"|\\?$)|'(?:\\[\s\S]|[^'\\])*(?:'|\\?$))"
)
_HEADER_LINE_RE = re.compile(
    r"(?i)(?<![a-z\d_.-])"
    r"((?:proxy[_-]?)?authorization|set[_-]?cookie|cookie|auth[_-]?header|x[_-]?api[_-]?key)"
    r"(\s*[:=]\s*)[^\r\n]+"
)
_BEARER_BASIC_RE = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[^\s\"',;}{]{4,}"
)
_TOKEN_PREFIX_AND_JWT_RE = re.compile(
    r"(?:"
    r"sk-ant-[A-Za-z\d_-]{8,}"
    r"|sk-[A-Za-z\d_-]{8,}"
    r"|ghp_[A-Za-z\d]{8,}"
    r"|gho_[A-Za-z\d]{8,}"
    r"|github_pat_[A-Za-z\d_]{8,}"
    r"|AKIA[\dA-Z]{12,}"
    r"|AIza[\dA-Za-z_-]{12,}"
    r"|xox[bpoas]-[\dA-Za-z-]{8,}"
    r"|ocjob_[A-Za-z\d_-]{6,}"
    r"|ocpeer_[A-Za-z\d_-]{6,}"
    r"|eyJ[A-Za-z\d_-]{8,}\.eyJ[A-Za-z\d_-]{8,}"
    r"(?:\.(?:[A-Za-z\d_-]{8,}|[A-Za-z\d_-]*$)|$)"
    r")"
)
_KV_SECRET_RE = re.compile(
    r"(?i)"
    r"(password|passwd|pwd|api[_-]?key|access[_-]?key|access[_-]?token"
    r"|auth[_-]?token|auth[_-]?header|authorization|cookie|set[_-]?cookie"
    r"|credential|awakeable[_-]?token[_-]?hash|private[_-]?key"
    r"|client[_-]?secret|secret[_-]?key|secret|token)"
    r"([\"']?\s*[:=]\s*)"
    r"(?:\"(?:\\[\s\S]|[^\"\\])*(?:\"|\\?$)|'(?:\\[\s\S]|[^'\\])*(?:'|\\?$)|[^\s\"',;}{]+)"
)


def _replace_url_basic_auth(match: re.Match[str]) -> str:
    suffix = "@" if match.group(2) == "@" else ""
    return f"{match.group(1)}{REDACTED_MARKER}{suffix}"


_REDACT_RULES: tuple[
    tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]], ...
] = (
    (_PEM_BLOCK_RE, REDACTED_MARKER),
    (_URL_BASIC_AUTH_RE, _replace_url_basic_auth),
    (_HEADER_QUOTED_RE, rf"\1\2{REDACTED_MARKER}"),
    (_HEADER_LINE_RE, rf"\1\2{REDACTED_MARKER}"),
    (_BEARER_BASIC_RE, REDACTED_MARKER),
    (_TOKEN_PREFIX_AND_JWT_RE, REDACTED_MARKER),
    (_KV_SECRET_RE, rf"\1\2{REDACTED_MARKER}"),
)

_K_SCHEMA_VERSION = "schema_version"
_K_SNAPSHOT_SEQ = "snapshot_seq"
_K_READ_SESSION = "read_session"
_K_MALFORMED_METADATA = "malformed_metadata"
_K_REDACTION_APPLIED = "redaction_applied"
_K_CREATED_AT = "created_at"
_K_REVIEW_ID = "review_id"
_K_ARTIFACT_SHA256 = "artifact_sha256"
_K_POLICY_DIGEST = "policy_digest"
_K_CHECKPOINT_SEQ = "checkpoint_seq"


def redact_sensitive_text(text: str) -> tuple[str, bool]:
    """Deterministically redact enumerated credential patterns from text."""
    current = text
    redacted = False
    for pattern, repl in _REDACT_RULES:
        updated, count = pattern.subn(repl, current)
        if count > 0:
            current = updated
            redacted = True
    return current, redacted


def contains_credential_pattern(text: str) -> bool:
    """Return True if text matches any Stage-2 enumerated credential pattern."""
    return any(pattern.search(text) is not None for pattern, _ in _REDACT_RULES)


def validate_clean_opaque_token(value: object, label: str) -> str:
    """Validate an opaque token in O(1)-bounded time, mapping AddressError cleanly."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_OPAQUE_TOKEN_CHARS
        or not value.isascii()
    ):
        raise CoordValidationError(f"invalid_{label}")
    try:
        return validate_opaque_token(value, label)
    except (AddressError, CoordValidationError) as exc:
        raise CoordValidationError(f"invalid_{label}") from exc


def is_valid_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and _SHA256_HEX_RE.fullmatch(value) is not None


def is_strict_nonneg_int(val: Any, *, hi: int = MAX_SQLITE_INT64) -> bool:
    if type(val) is not int:
        return False
    num = cast(int, val)
    return 0 <= num <= hi


def is_json_tree_valid(value: Any, *, max_depth: int = MAX_JSON_DEPTH, depth: int = 0) -> bool:
    """Validate JSON nesting depth and reject non-finite floats (including 1e400 overflow)."""
    if depth > max_depth:
        return False
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(
            is_json_tree_valid(v, max_depth=max_depth, depth=depth + 1)
            for v in value.values()
        )
    if isinstance(value, list):
        return all(
            is_json_tree_valid(v, max_depth=max_depth, depth=depth + 1)
            for v in value
        )
    return True


def reject_json_constant(token: str) -> Any:
    raise ValueError(f"Forbidden JSON constant: {token}")


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
class InboxArtifactRef:
    """Bounded digest-pinned artifact reference attached to a review item."""

    artifact_id: str | None
    blob_sha256: str | None
    size_bytes: int
    media_type: str
    label: str
    label_truncated: bool
    is_primary: bool
    created_at: float
    redaction_applied: bool
    malformed_metadata: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "blob_sha256": self.blob_sha256,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "label": self.label,
            "label_truncated": self.label_truncated,
            "is_primary": self.is_primary,
            _K_CREATED_AT: self.created_at,
            _K_REDACTION_APPLIED: self.redaction_applied,
            _K_MALFORMED_METADATA: self.malformed_metadata,
        }


@dataclass(frozen=True, slots=True)
class InboxItemIdentity:
    """Identifiers and workflow coordinates for one review item."""

    review_id: str
    run_id: str | None
    workflow_id: str | None
    step_id: str | None
    checkpoint_seq: int
    item_revision: int
    target_addr: str | None
    target_incarnation_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_REVIEW_ID: self.review_id,
            "run_id": self.run_id,
            "workflow_id": self.workflow_id,
            "step_id": self.step_id,
            _K_CHECKPOINT_SEQ: self.checkpoint_seq,
            "item_revision": self.item_revision,
            "target_addr": self.target_addr,
            "target_incarnation_id": self.target_incarnation_id,
        }


@dataclass(frozen=True, slots=True)
class InboxItemState:
    """Lifecycle classification, timestamps, and metadata-health flags."""

    status: str
    severity: str
    priority_rank: int
    lane_paused: bool
    requires_human_review: bool
    source_kind: str
    created_at: float
    updated_at: float
    expires_at: float | None
    malformed_metadata: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "severity": self.severity,
            "priority_rank": self.priority_rank,
            "lane_paused": self.lane_paused,
            "requires_human_review": self.requires_human_review,
            "source_kind": self.source_kind,
            _K_CREATED_AT: self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            _K_MALFORMED_METADATA: self.malformed_metadata,
        }


@dataclass(frozen=True, slots=True)
class InboxItemPresentation:
    """Scrubbed, redacted, untrusted human-readable summary and title fields."""

    title: str
    title_truncated: bool
    summary_text: str
    text_truncated: bool
    text_suffix_uninspected: bool
    original_text_bytes: int
    has_control_or_bidi: bool
    untrusted_content: bool
    redaction_applied: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "title_truncated": self.title_truncated,
            "summary_text": self.summary_text,
            "text_truncated": self.text_truncated,
            "text_suffix_uninspected": self.text_suffix_uninspected,
            "original_text_bytes": self.original_text_bytes,
            "has_control_or_bidi": self.has_control_or_bidi,
            "untrusted_content": self.untrusted_content,
            _K_REDACTION_APPLIED: self.redaction_applied,
        }


@dataclass(frozen=True, slots=True)
class InboxItemPinStatus:
    """Cryptographic review-pin verification state and offline readiness."""

    artifact_sha256: str | None
    policy_digest: str | None
    review_pin_sha256: str | None
    pin_verified: bool
    pin_anomaly: bool
    anomaly_reason: str | None
    review_ready: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_ARTIFACT_SHA256: self.artifact_sha256,
            _K_POLICY_DIGEST: self.policy_digest,
            "review_pin_sha256": self.review_pin_sha256,
            "pin_verified": self.pin_verified,
            "pin_anomaly": self.pin_anomaly,
            "anomaly_reason": self.anomaly_reason,
            "review_ready": self.review_ready,
        }


@dataclass(frozen=True, slots=True)
class InboxItem:
    """Composed, strictly read-only projection of a Tier-B Human Inbox item."""

    identity: InboxItemIdentity
    state: InboxItemState
    presentation: InboxItemPresentation
    pin: InboxItemPinStatus
    metadata: Mapping[str, Any]
    metadata_truncated: bool

    @property
    def review_id(self) -> str:
        return self.identity.review_id

    @property
    def run_id(self) -> str | None:
        return self.identity.run_id

    @property
    def workflow_id(self) -> str | None:
        return self.identity.workflow_id

    @property
    def step_id(self) -> str | None:
        return self.identity.step_id

    @property
    def checkpoint_seq(self) -> int:
        return self.identity.checkpoint_seq

    @property
    def status(self) -> str:
        return self.state.status

    @property
    def severity(self) -> str:
        return self.state.severity

    @property
    def priority_rank(self) -> int:
        return self.state.priority_rank

    @property
    def lane_paused(self) -> bool:
        return self.state.lane_paused

    @property
    def source_kind(self) -> str:
        return self.state.source_kind

    @property
    def malformed_metadata(self) -> bool:
        return self.state.malformed_metadata

    @property
    def title(self) -> str:
        return self.presentation.title

    @property
    def summary_text(self) -> str:
        return self.presentation.summary_text

    @property
    def text_truncated(self) -> bool:
        return self.presentation.text_truncated

    @property
    def text_suffix_uninspected(self) -> bool:
        return self.presentation.text_suffix_uninspected

    @property
    def has_control_or_bidi(self) -> bool:
        return self.presentation.has_control_or_bidi

    @property
    def untrusted_content(self) -> bool:
        return self.presentation.untrusted_content

    @property
    def redaction_applied(self) -> bool:
        return self.presentation.redaction_applied

    @property
    def review_pin_sha256(self) -> str | None:
        return self.pin.review_pin_sha256

    @property
    def pin_verified(self) -> bool:
        return self.pin.pin_verified

    @property
    def pin_anomaly(self) -> bool:
        return self.pin.pin_anomaly

    @property
    def anomaly_reason(self) -> str | None:
        return self.pin.anomaly_reason

    @property
    def review_ready(self) -> bool:
        return self.pin.review_ready

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "state": self.state.to_dict(),
            "presentation": self.presentation.to_dict(),
            "pin": self.pin.to_dict(),
            "metadata": dict(self.metadata),
            "metadata_truncated": self.metadata_truncated,
        }


@dataclass(frozen=True, slots=True)
class InboxPage:
    """Bounded paginated snapshot page returned by ``list_inbox_items``."""

    schema_version: str
    snapshot_seq: int
    items: tuple[InboxItem, ...]
    has_more: bool
    next_cursor: str | None
    read_session: ReadSessionEcho | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SCHEMA_VERSION: self.schema_version,
            _K_SNAPSHOT_SEQ: self.snapshot_seq,
            "items": [item.to_dict() for item in self.items],
            "has_more": self.has_more,
            "next_cursor": self.next_cursor,
            _K_READ_SESSION: _as_dict_if_present(self.read_session),
        }


@dataclass(frozen=True, slots=True)
class InboxItemDetailSnapshot:
    """Bounded single-item detail snapshot returned by ``get_inbox_item``."""

    schema_version: str
    snapshot_seq: int
    item: InboxItem
    artifact_refs: tuple[InboxArtifactRef, ...]
    artifact_refs_truncated: bool
    artifacts_malformed: bool
    read_session: ReadSessionEcho | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SCHEMA_VERSION: self.schema_version,
            _K_SNAPSHOT_SEQ: self.snapshot_seq,
            "item": self.item.to_dict(),
            "artifact_refs": [art.to_dict() for art in self.artifact_refs],
            "artifact_refs_truncated": self.artifact_refs_truncated,
            "artifacts_malformed": self.artifacts_malformed,
            _K_READ_SESSION: _as_dict_if_present(self.read_session),
        }


@dataclass(frozen=True, slots=True)
class InboxSummarySnapshot:
    """Bounded closed-enum SQL aggregate summary returned by ``get_inbox_summary``."""

    schema_version: str
    snapshot_seq: int
    total_items: int
    counts_by_status: Mapping[str, int]
    counts_by_severity: Mapping[str, int]
    pending_by_severity: Mapping[str, int]
    paused_lanes_count: int
    requires_human_review_count: int
    malformed_rows_count: int
    pin_verification_scope: str
    read_session: ReadSessionEcho | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SCHEMA_VERSION: self.schema_version,
            _K_SNAPSHOT_SEQ: self.snapshot_seq,
            "total_items": self.total_items,
            "counts_by_status": dict(sorted(self.counts_by_status.items())),
            "counts_by_severity": dict(sorted(self.counts_by_severity.items())),
            "pending_by_severity": dict(sorted(self.pending_by_severity.items())),
            "paused_lanes_count": self.paused_lanes_count,
            "requires_human_review_count": self.requires_human_review_count,
            "malformed_rows_count": self.malformed_rows_count,
            "pin_verification_scope": self.pin_verification_scope,
            _K_READ_SESSION: _as_dict_if_present(self.read_session),
        }


@dataclass(frozen=True, slots=True)
class ParsedInboxCursor:
    """Validated keyset + snapshot-bound pagination cursor for ``list_inbox_items``."""

    snapshot_seq: int
    priority_rank: int
    checkpoint_seq: int
    review_id: str


def compute_review_pin_sha256(
    *,
    run_id: str,
    step_id: str,
    review_id: str,
    checkpoint_seq: int,
    artifact_sha256: str,
    policy_digest: str,
) -> str:
    """Compute canonical domain-separated SHA-256 review pin over 6 validated inputs."""
    clean_run = validate_clean_opaque_token(run_id, "run_id")
    clean_step = validate_clean_opaque_token(step_id, "step_id")
    clean_rev = validate_clean_opaque_token(review_id, _K_REVIEW_ID)
    if not is_strict_nonneg_int(checkpoint_seq):
        raise CoordValidationError("checkpoint_seq must be an int in 0..MAX_SQLITE_INT64")
    if not is_valid_sha256_hex(artifact_sha256):
        raise CoordValidationError("artifact_sha256 must be 64 lowercase hex chars")
    if not is_valid_sha256_hex(policy_digest):
        raise CoordValidationError("policy_digest must be 64 lowercase hex chars")
    payload = {
        _K_ARTIFACT_SHA256: artifact_sha256,
        _K_CHECKPOINT_SEQ: checkpoint_seq,
        _K_POLICY_DIGEST: policy_digest,
        _K_REVIEW_ID: clean_rev,
        "run_id": clean_run,
        "step_id": clean_step,
    }
    return domain_sha256(REVIEW_PIN_DOMAIN, payload)


def serialize_inbox_json(obj: Any) -> str:
    """Serialize an inbox snapshot or mapping strictly without NaN/Infinity."""
    payload = obj.to_dict() if hasattr(obj, "to_dict") else obj
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def serialize_inbox_bytes(obj: Any) -> bytes:
    """Return exact UTF-8 JSON bytes for hard response-size budget enforcement."""
    return serialize_inbox_json(obj).encode(_UTF8)


def compute_scope_hash(op: str, **params: Any) -> str:
    """Compute a 16-hex-char SHA-256 scope fingerprint for cursor binding."""
    canonical = json.dumps(
        {"op": op, "params": params},
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode(_UTF8)
    return hashlib.sha256(canonical).hexdigest()[:16]


def _encode_cursor_payload(payload: Mapping[str, Any]) -> str:
    raw_json = json.dumps(
        dict(payload),
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode(_UTF8)
    encoded = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    cursor = f"{CURSOR_PREFIX}{encoded}"
    if len(cursor.encode(_UTF8)) > MAX_CURSOR_BYTES:
        raise CoordValidationError("cursor_exceeds_max_bytes")
    return cursor


def encode_inbox_list_cursor(
    *,
    scope_hash: str,
    snapshot_seq: int,
    priority_rank: int,
    checkpoint_seq: int,
    review_id: str,
) -> str:
    """Encode a canonical base64url JSON cursor bound to (op, scope_hash, snapshot_seq)."""
    if not isinstance(scope_hash, str) or _SCOPE_HASH_RE.fullmatch(scope_hash) is None:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if not is_strict_nonneg_int(snapshot_seq):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if not is_strict_nonneg_int(priority_rank, hi=MAX_PRIORITY_RANK):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if not is_strict_nonneg_int(checkpoint_seq):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    clean_rid = validate_clean_opaque_token(review_id, _K_REVIEW_ID)
    if contains_credential_pattern(clean_rid):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return _encode_cursor_payload(
        {
            "op": OP_INBOX_LIST,
            "fh": scope_hash,
            "ss": snapshot_seq,
            "pr": priority_rank,
            "seq": checkpoint_seq,
            "rid": clean_rid,
        }
    )


def _extract_b64_cursor_part(raw: object) -> str:
    if not isinstance(raw, str):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if (
        len(raw) > MAX_CURSOR_BYTES
        or not raw.isascii()
        or not raw.startswith(CURSOR_PREFIX)
    ):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    b64_part = raw[len(CURSOR_PREFIX) :]
    if not b64_part or _CURSOR_B64URL_RE.fullmatch(b64_part) is None:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return b64_part


def _decode_raw_cursor_dict(raw: object) -> dict[str, Any]:
    b64_part = _extract_b64_cursor_part(raw)
    pad_len = (-len(b64_part)) % 4
    if pad_len == 3:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        decoded_bytes = base64.urlsafe_b64decode(b64_part + ("=" * pad_len))
        parsed = json.loads(
            decoded_bytes.decode(_UTF8), parse_constant=reject_json_constant
        )
    except (ValueError, RecursionError) as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if not isinstance(parsed, dict) or not is_json_tree_valid(parsed):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        canonical = _encode_cursor_payload(parsed)
    except (ValueError, TypeError, CoordValidationError) as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if canonical != raw:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return parsed


def _validate_cursor_header(
    parsed: Mapping[str, Any], expected_scope_hash: str
) -> None:
    op = parsed.get("op")
    fh = parsed.get("fh")
    if not isinstance(op, str) or not isinstance(fh, str):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if _SCOPE_HASH_RE.fullmatch(fh) is None:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if op != OP_INBOX_LIST or fh != expected_scope_hash:
        raise CoordValidationError(ERR_CURSOR_SCOPE_MISMATCH)
    if set(parsed.keys()) != {"op", "fh", "ss", "pr", "seq", "rid"}:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)


def decode_inbox_list_cursor(
    raw: object, *, expected_scope_hash: str
) -> ParsedInboxCursor | None:
    """Decode and strictly validate a snapshot-bound ``list_inbox_items`` cursor."""
    if raw is None:
        return None
    parsed = _decode_raw_cursor_dict(raw)
    _validate_cursor_header(parsed, expected_scope_hash)
    ss = parsed["ss"]
    pr = parsed["pr"]
    seq = parsed["seq"]
    rid = parsed["rid"]
    if (
        not is_strict_nonneg_int(ss)
        or not is_strict_nonneg_int(pr, hi=MAX_PRIORITY_RANK)
        or not is_strict_nonneg_int(seq)
    ):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        clean_rid = validate_clean_opaque_token(rid, _K_REVIEW_ID)
    except CoordValidationError as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if clean_rid != rid or contains_credential_pattern(clean_rid):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return ParsedInboxCursor(
        snapshot_seq=ss,
        priority_rank=pr,
        checkpoint_seq=seq,
        review_id=clean_rid,
    )
