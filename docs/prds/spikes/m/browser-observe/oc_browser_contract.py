"""Read-only browser frame & navigation provenance contract for PRD M3.4.

Pure Python standard library plus read-only imports from docs/prds/spikes/m.
All wire snapshots serialize strictly with ``allow_nan=False`` and stay
bounded by explicit UTF-8 JSON byte ceilings.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from types import MappingProxyType
from typing import Any

_BROWSER_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _BROWSER_DIR.parent
if str(_SPIKE_M_DIR) not in sys.path:
    sys.path.insert(0, str(_SPIKE_M_DIR))

from oc_address import (  # noqa: E402
    AddressError,
    TargetAddr,
    has_forbidden_control_or_bidi,
    parse_canonical_addr,
)
from oc_coord_contract import (  # noqa: E402
    CoordValidationError,
    SANDBOX_LIFECYCLE_STATES,
    validate_opaque_token,
)

BROWSER_OBSERVE_SCHEMA_VERSION = "oc.m3.browser_observe@1"

MAX_SQLITE_INT64 = (1 << 63) - 1
MAX_TRACKED_SANDBOXES = 256
MAX_SURFACES_PER_SANDBOX = 16
MAX_ROTATIONS_PER_SANDBOX = 256
MAX_QUARANTINE_HISTORY_PER_SURFACE = 32

MIN_FRAME_BYTES = 16
MAX_FRAME_BYTES = 512 * 1024
MIN_FRAME_WIDTH = 1
MAX_FRAME_WIDTH = 4096
MIN_FRAME_HEIGHT = 1
MAX_FRAME_HEIGHT = 4096
MAX_FRAME_PIXELS = 4096 * 2160
MAX_JPEG_SEGMENTS = 256

MAX_RAW_URL_BYTES = 8_192
MAX_DISPLAY_URL_BYTES = 2_048
MAX_PATH_BYTES = 256
MAX_RAW_TITLE_CHARS = 4_096
MAX_TITLE_BYTES = 256

MIN_FRAME_AGE_MS = 100
DEFAULT_MAX_FRAME_AGE_MS = 10_000
MAX_FRAME_AGE_MS = 300_000

MIN_RESPONSE_BYTES = 1024
MAX_WALL_RESPONSE_BYTES = 256 * 1024
MAX_SNAPSHOT_RESPONSE_BYTES = 768 * 1024
DEFAULT_WALL_LIMIT = 25
MAX_WALL_LIMIT = 100
MAX_CURSOR_BYTES = 512

ALLOWED_URL_SCHEMES: frozenset[str] = frozenset({"http", "https"})
ALLOWED_FRAME_MEDIA_TYPES: frozenset[str] = frozenset({"image/png", "image/jpeg"})
VALID_SANDBOX_STATUSES: frozenset[str] = SANDBOX_LIFECYCLE_STATES

TLS_EVIDENCE_SANDBOX_CA = "sandbox_internal_ca"
TLS_EVIDENCE_EXTERNAL_CA = "external_ca"
TLS_EVIDENCE_ERROR = "tls_error"
TLS_EVIDENCE_UNKNOWN = "unknown"
VALID_TLS_EVIDENCE: frozenset[str] = frozenset(
    {
        TLS_EVIDENCE_SANDBOX_CA,
        TLS_EVIDENCE_EXTERNAL_CA,
        TLS_EVIDENCE_ERROR,
        TLS_EVIDENCE_UNKNOWN,
    }
)

TLS_STATE_SANDBOX_CA = TLS_EVIDENCE_SANDBOX_CA
TLS_STATE_EXTERNAL_VERIFIED = "verified_external_tls"
TLS_STATE_HTTP_UNENCRYPTED = "http_unencrypted"
TLS_STATE_ERROR = TLS_EVIDENCE_ERROR
TLS_STATE_UNKNOWN = TLS_EVIDENCE_UNKNOWN
VALID_TLS_STATES: frozenset[str] = frozenset(
    {
        TLS_STATE_SANDBOX_CA,
        TLS_STATE_EXTERNAL_VERIFIED,
        TLS_STATE_HTTP_UNENCRYPTED,
        TLS_STATE_ERROR,
        TLS_STATE_UNKNOWN,
    }
)

ORIGIN_TRUST_SANDBOX_HTTPS = "sandbox_internal_https"
ORIGIN_TRUST_LOOPBACK_HTTP = "loopback_http"
ORIGIN_TRUST_EXTERNAL = "external_untrusted"
VALID_ORIGIN_TRUSTS: frozenset[str] = frozenset(
    {
        ORIGIN_TRUST_SANDBOX_HTTPS,
        ORIGIN_TRUST_LOOPBACK_HTTP,
        ORIGIN_TRUST_EXTERNAL,
    }
)

STALE_NAV_GENERATION = "stale_nav_generation"
STALE_UNKNOWN_NAV = "unknown_nav_generation"
STALE_SUPERSEDED_INCARNATION = "superseded_incarnation"
STALE_NON_MONOTONIC_SEQ = "non_monotonic_frame_seq"
STALE_SANDBOX_NOT_RUNNING = "sandbox_not_running"
STALE_CAPTURE_GENERATION = "stale_capture_generation"
STALE_TTL_EXPIRED = "frame_ttl_expired"
STALE_AWAITING_FRAME = "awaiting_frame_for_navigation"
STALE_AWAITING_NAV = "awaiting_navigation_for_capture_generation"
STALE_DISCONNECTED = "sandbox_disconnected"
STALE_CLOCK_REGRESSION = "clock_regression"
STALE_FRAME_SUPERSEDED = "frame_superseded"
OMIT_BUDGET_EXCEEDED = "response_budget_exceeded"

VALID_STALE_REASONS: frozenset[str] = frozenset(
    {
        STALE_NAV_GENERATION,
        STALE_UNKNOWN_NAV,
        STALE_SUPERSEDED_INCARNATION,
        STALE_NON_MONOTONIC_SEQ,
        STALE_SANDBOX_NOT_RUNNING,
        STALE_CAPTURE_GENERATION,
        STALE_TTL_EXPIRED,
        STALE_AWAITING_FRAME,
        STALE_AWAITING_NAV,
        STALE_DISCONNECTED,
        STALE_CLOCK_REGRESSION,
        STALE_FRAME_SUPERSEDED,
    }
)

CURSOR_PREFIX = "v1."
OP_BROWSER_WALL = "browser_wall"
_CURSOR_B64URL_RE = re.compile(r"^[\w-]+$", re.ASCII)
_SCOPE_HASH_RE = re.compile(r"^[\da-f]{16}$", re.ASCII)
_SHA256_HEX_RE = re.compile(r"^[\da-f]{64}$", re.ASCII)
_CURSOR_KEYS: frozenset[str] = frozenset({"op", "fh", "addr", "sid"})

ERR_CURSOR_MALFORMED = "cursor_malformed"
ERR_CURSOR_SCOPE_MISMATCH = "cursor_scope_mismatch"
ERR_INVALID_SANDBOX_TARGET = "invalid_sandbox_target"
ERR_PEER_TARGET_NOT_SANDBOX = "peer_target_not_sandbox"
ERR_UNTRUSTED_CONTENT_REQUIRED = "untrusted_content_must_be_true"
ERR_PAIRING_MISMATCH = "paired_frame_provenance_mismatch"
ERR_NON_FINITE_JSON = "non_finite_json_value"
_ERR_INVALID_SURFACE_KEY = "invalid_surface_key"

FLAG_USERINFO = "userinfo"
FLAG_QUERY = "query"
FLAG_FRAGMENT = "fragment"
FLAG_PATH_TRUNCATED = "path_truncated"
FLAG_TITLE_SCRUBBED = "title_scrubbed"
FLAG_TITLE_TRUNCATED = "title_truncated"

_UTF8 = "utf-8"
_K_SCHEMA_VERSION = "schema_version"
_K_SANDBOX_ADDR = "sandbox_addr"
_K_WORKER_REF = "worker_ref"
_K_INSTANCE_NAME = "instance_name"
_K_INCARNATION_ID = "incarnation_id"
_K_SURFACE_ID = "surface_id"
_K_CAPTURE_GENERATION = "capture_generation"
_K_SANDBOX_STATUS = "sandbox_status"
_K_NAV_GENERATION = "nav_generation"
_K_ORIGIN = "origin"
_K_PATH_REDACTED = "path_redacted"
_K_SCHEME = "scheme"
_K_TLS_VERIFIED = "tls_verified"
_K_ORIGIN_TRUST = "origin_trust"
_K_TLS_STATE = "tls_state"
_K_PAGE_TITLE_CLEAN = "page_title_clean"
_K_COMMITTED_AT = "committed_at"
_K_REDACTED_FLAGS = "redacted_flags"
_K_FRAME_SEQ = "frame_seq"
_K_MEDIA_TYPE = "media_type"
_K_WIDTH = "width"
_K_HEIGHT = "height"
_K_SIZE_BYTES = "size_bytes"
_K_FRAME_SHA256 = "frame_sha256"
_K_CAPTURED_AT = "captured_at"
_K_FRAME_STALE = "frame_stale"
_K_STALE_REASON = "stale_reason"
_K_FRAME_AGE_MS = "frame_age_ms"
_K_UNTRUSTED_CONTENT = "untrusted_content"
_K_FRAME_B64 = "frame_b64"
_K_FRAME_B64_OMITTED = "frame_b64_omitted_reason"
_K_DROPPED_COUNTS = "dropped_frame_counts"
_K_OBSERVED_AT = "observed_at"
_K_READ_SESSION = "read_session"
_K_NEXT_CURSOR = "next_cursor"
_K_HAS_MORE = "has_more"
_K_TILES = "tiles"
_K_NAV = "nav"
_K_FRAME = "frame"
_K_READ_SESSION_ID = "read_session_id"
_K_SESSION_GENERATION = "session_generation"


def require_bool(value: object, label: str) -> bool:
    """Require strict Python bool (rejecting int/str/None)."""
    if type(value) is not bool:
        raise CoordValidationError(f"invalid_bool_{label}")
    return value


def validate_positive_int(
    value: object, label: str, *, max_value: int = MAX_SQLITE_INT64
) -> int:
    """Require strict int in 1..max_value (rejecting bool and oversized ints)."""
    if type(value) is not int or not (1 <= value <= max_value):
        raise CoordValidationError(f"invalid_positive_int_{label}")
    return value


def validate_nonneg_int(
    value: object, label: str, *, max_value: int = MAX_SQLITE_INT64
) -> int:
    """Require strict int in 0..max_value (rejecting bool and negatives)."""
    if type(value) is not int or not (0 <= value <= max_value):
        raise CoordValidationError(f"invalid_nonneg_int_{label}")
    return value


def validate_finite_nonneg_float(value: object, label: str) -> float:
    """Require finite non-negative int/float (rejecting bool, NaN, Inf, overflow, < 0)."""
    err = f"invalid_float_{label}"
    if type(value) is bool or not isinstance(value, (int, float)):
        raise CoordValidationError(err)
    try:
        fval = float(value)
    except OverflowError as exc:
        raise CoordValidationError(err) from exc
    if not math.isfinite(fval) or fval < 0.0:
        raise CoordValidationError(err)
    return fval + 0.0


def parse_sandbox_target(raw: object) -> TargetAddr:
    """Parse canonical 'NAME' or 'REMOTE / NAME', rejecting '@PEER' and wrapping AddressError."""
    try:
        addr = parse_canonical_addr(raw)
    except AddressError as exc:
        raise CoordValidationError(ERR_INVALID_SANDBOX_TARGET) from exc
    if addr.kind == "peer":
        raise CoordValidationError(ERR_PEER_TARGET_NOT_SANDBOX)
    return addr


def validate_token_strict(value: object, label: str) -> str:
    """Validate an opaque identifier token without echoing raw input on failure."""
    try:
        return validate_opaque_token(value, label)
    except (AddressError, CoordValidationError) as exc:
        raise CoordValidationError(f"invalid_{label}") from exc


def serialize_json_str(payload: Any) -> str:
    """Serialize strictly to compact UTF-8 JSON with allow_nan=False."""
    raw = payload.to_dict() if hasattr(payload, "to_dict") else payload
    try:
        return json.dumps(
            raw, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise CoordValidationError(ERR_NON_FINITE_JSON) from exc


def serialize_json_bytes(payload: Any) -> bytes:
    """Serialize strictly to compact UTF-8 JSON bytes with allow_nan=False."""
    return serialize_json_str(payload).encode(_UTF8)


def _reject_non_finite_constant(token: str) -> Any:
    raise CoordValidationError(ERR_CURSOR_MALFORMED)


def compute_wall_scope_hash(*, include_disconnected: bool) -> str:
    """Compute 16-hex-char SHA-256 scope hash binding wall cursor to query filters."""
    clean_inc = require_bool(include_disconnected, "include_disconnected")
    canonical = json.dumps(
        {"op": OP_BROWSER_WALL, "include_disconnected": clean_inc},
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode(_UTF8)
    return hashlib.sha256(canonical).hexdigest()[:16]


def encode_wall_cursor(
    *, scope_hash: str, sandbox_addr: str, surface_id: str
) -> str:
    """Encode a canonical, unpadded base64url JSON cursor for list_browser_wall."""
    if not isinstance(scope_hash, str) or _SCOPE_HASH_RE.fullmatch(scope_hash) is None:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    clean_addr = parse_sandbox_target(sandbox_addr).canonical
    clean_sid = validate_token_strict(surface_id, _K_SURFACE_ID)
    payload = {
        "op": OP_BROWSER_WALL,
        "fh": scope_hash,
        "addr": clean_addr,
        "sid": clean_sid,
    }
    raw_json = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode(_UTF8)
    encoded = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    cursor = f"{CURSOR_PREFIX}{encoded}"
    if len(cursor.encode(_UTF8)) > MAX_CURSOR_BYTES:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return cursor


def _decode_cursor_json(body: str) -> dict[str, Any]:
    if not body or _CURSOR_B64URL_RE.fullmatch(body) is None:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    pad_len = (-len(body)) % 4
    if pad_len == 3:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        raw_bytes = base64.urlsafe_b64decode(f"{body}{'=' * pad_len}".encode("ascii"))
        parsed = json.loads(
            raw_bytes.decode(_UTF8), parse_constant=_reject_non_finite_constant
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if type(parsed) is not dict or set(parsed.keys()) != _CURSOR_KEYS:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return parsed


def _extract_cursor_fields(parsed: dict[str, Any]) -> tuple[str, str, str, str]:
    op_val = parsed["op"]
    fh_val = parsed["fh"]
    addr_val = parsed["addr"]
    sid_val = parsed["sid"]
    if not all(isinstance(v, str) for v in (op_val, fh_val, addr_val, sid_val)):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if _SCOPE_HASH_RE.fullmatch(fh_val) is None:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    canonical_addr = parse_sandbox_target(addr_val).canonical
    if canonical_addr != addr_val:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    clean_sid = validate_token_strict(sid_val, _K_SURFACE_ID)
    return op_val, fh_val, canonical_addr, clean_sid


def decode_wall_cursor(
    cursor: object, *, expected_scope_hash: str
) -> tuple[str, str] | None:
    """Decode and strictly verify a list_browser_wall cursor -> (addr, surface_id)."""
    if cursor is None:
        return None
    if (
        not isinstance(cursor, str)
        or not cursor.isascii()
        or len(cursor) > MAX_CURSOR_BYTES
        or not cursor.startswith(CURSOR_PREFIX)
    ):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    parsed = _decode_cursor_json(cursor[len(CURSOR_PREFIX) :])
    op_val, fh_val, canonical_addr, clean_sid = _extract_cursor_fields(parsed)
    if op_val != OP_BROWSER_WALL:
        raise CoordValidationError(ERR_CURSOR_SCOPE_MISMATCH)
    reencoded = encode_wall_cursor(
        scope_hash=fh_val, sandbox_addr=canonical_addr, surface_id=clean_sid
    )
    if reencoded != cursor:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if fh_val != expected_scope_hash:
        raise CoordValidationError(ERR_CURSOR_SCOPE_MISMATCH)
    return canonical_addr, clean_sid


@dataclass(frozen=True, slots=True)
class ReadSessionEcho:
    """Validated operator read-session coordinates echoed on snapshots."""

    read_session_id: str
    session_generation: int

    def __post_init__(self) -> None:
        validate_token_strict(self.read_session_id, _K_READ_SESSION_ID)
        validate_positive_int(self.session_generation, _K_SESSION_GENERATION)

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_READ_SESSION_ID: self.read_session_id,
            _K_SESSION_GENERATION: self.session_generation,
        }


@dataclass(frozen=True, slots=True)
class SurfaceKey:
    """Canonical identity for a browser capture surface."""

    sandbox_addr: str
    incarnation_id: str
    surface_id: str
    capture_generation: int

    def __post_init__(self) -> None:
        parsed = parse_sandbox_target(self.sandbox_addr)
        if parsed.canonical != self.sandbox_addr:
            raise CoordValidationError(ERR_INVALID_SANDBOX_TARGET)
        validate_token_strict(self.incarnation_id, _K_INCARNATION_ID)
        validate_token_strict(self.surface_id, _K_SURFACE_ID)
        validate_positive_int(self.capture_generation, _K_CAPTURE_GENERATION)


@dataclass(frozen=True, slots=True)
class NavClassification:
    """Origin trust, observed TLS state, and URL/title redaction flags."""

    origin_trust: str
    tls_state: str
    userinfo_redacted: bool = False
    query_redacted: bool = False
    fragment_redacted: bool = False
    path_truncated: bool = False
    title_scrubbed: bool = False
    title_truncated: bool = False

    def __post_init__(self) -> None:
        if self.origin_trust not in VALID_ORIGIN_TRUSTS:
            raise CoordValidationError("invalid_origin_trust")
        if self.tls_state not in VALID_TLS_STATES:
            raise CoordValidationError("invalid_tls_state")
        for flag_name, flag_val in (
            ("userinfo_redacted", self.userinfo_redacted),
            ("query_redacted", self.query_redacted),
            ("fragment_redacted", self.fragment_redacted),
            (FLAG_PATH_TRUNCATED, self.path_truncated),
            (FLAG_TITLE_SCRUBBED, self.title_scrubbed),
            (FLAG_TITLE_TRUNCATED, self.title_truncated),
        ):
            require_bool(flag_val, flag_name)

    @property
    def redacted_flags(self) -> tuple[str, ...]:
        pairs = (
            (self.fragment_redacted, FLAG_FRAGMENT),
            (self.path_truncated, FLAG_PATH_TRUNCATED),
            (self.query_redacted, FLAG_QUERY),
            (self.title_scrubbed, FLAG_TITLE_SCRUBBED),
            (self.title_truncated, FLAG_TITLE_TRUNCATED),
            (self.userinfo_redacted, FLAG_USERINFO),
        )
        return tuple(name for enabled, name in pairs if enabled)


def _has_space_or_backslash(text: str) -> bool:
    return any(ch.isspace() or ch == "\\" for ch in text)


@dataclass(frozen=True, slots=True)
class BrowserNavState:
    """Host-observed committed navigation record with redacted URL & scrubbed title."""

    surface_key: SurfaceKey
    nav_generation: int
    origin: str
    path_redacted: str
    scheme: str
    tls_verified: bool
    page_title_clean: str
    committed_at: float
    classification: NavClassification

    def __post_init__(self) -> None:
        if not isinstance(self.surface_key, SurfaceKey):
            raise CoordValidationError(_ERR_INVALID_SURFACE_KEY)
        validate_positive_int(self.nav_generation, _K_NAV_GENERATION)
        self._validate_origin()
        self._validate_path()
        self._validate_title()
        require_bool(self.tls_verified, _K_TLS_VERIFIED)
        validate_finite_nonneg_float(self.committed_at, _K_COMMITTED_AT)
        if not isinstance(self.classification, NavClassification):
            raise CoordValidationError("invalid_nav_classification")

    def _validate_origin(self) -> None:
        if self.scheme not in ALLOWED_URL_SCHEMES:
            raise CoordValidationError("invalid_url_scheme")
        if (
            not isinstance(self.origin, str)
            or not self.origin.isascii()
            or not self.origin.startswith(f"{self.scheme}://")
        ):
            raise CoordValidationError("invalid_origin")
        if (
            any(ch in self.origin for ch in ("@", "?", "#"))
            or _has_space_or_backslash(self.origin)
            or has_forbidden_control_or_bidi(self.origin)
        ):
            raise CoordValidationError("invalid_origin")

    def _validate_path(self) -> None:
        if (
            not isinstance(self.path_redacted, str)
            or not self.path_redacted.startswith("/")
            or any(ch in self.path_redacted for ch in ("?", "#"))
            or _has_space_or_backslash(self.path_redacted)
            or has_forbidden_control_or_bidi(self.path_redacted)
            or len(self.path_redacted.encode(_UTF8)) > MAX_PATH_BYTES
        ):
            raise CoordValidationError("invalid_path_redacted")
        if len(self.display_url.encode(_UTF8)) > MAX_DISPLAY_URL_BYTES:
            raise CoordValidationError("display_url_exceeds_limit")

    def _validate_title(self) -> None:
        if (
            not isinstance(self.page_title_clean, str)
            or has_forbidden_control_or_bidi(self.page_title_clean)
            or any(ch in self.page_title_clean for ch in ("\u2028", "\u2029"))
            or len(self.page_title_clean.encode(_UTF8)) > MAX_TITLE_BYTES
        ):
            raise CoordValidationError("invalid_page_title_clean")

    @property
    def sandbox_addr(self) -> str:
        return self.surface_key.sandbox_addr

    @property
    def incarnation_id(self) -> str:
        return self.surface_key.incarnation_id

    @property
    def surface_id(self) -> str:
        return self.surface_key.surface_id

    @property
    def capture_generation(self) -> int:
        return self.surface_key.capture_generation

    @property
    def display_url(self) -> str:
        return f"{self.origin}{self.path_redacted}"

    @property
    def origin_trust(self) -> str:
        return self.classification.origin_trust

    @property
    def tls_state(self) -> str:
        return self.classification.tls_state

    @property
    def userinfo_redacted(self) -> bool:
        return self.classification.userinfo_redacted

    @property
    def query_redacted(self) -> bool:
        return self.classification.query_redacted

    @property
    def fragment_redacted(self) -> bool:
        return self.classification.fragment_redacted

    @property
    def path_truncated(self) -> bool:
        return self.classification.path_truncated

    @property
    def title_scrubbed(self) -> bool:
        return self.classification.title_scrubbed

    @property
    def title_truncated(self) -> bool:
        return self.classification.title_truncated

    def to_compact_dict(self) -> dict[str, Any]:
        return {
            _K_NAV_GENERATION: self.nav_generation,
            _K_ORIGIN: self.origin,
            _K_PATH_REDACTED: self.path_redacted,
            _K_SCHEME: self.scheme,
            _K_TLS_VERIFIED: self.tls_verified,
            _K_ORIGIN_TRUST: self.origin_trust,
            _K_TLS_STATE: self.tls_state,
            _K_PAGE_TITLE_CLEAN: self.page_title_clean,
            _K_COMMITTED_AT: self.committed_at,
            _K_REDACTED_FLAGS: list(self.classification.redacted_flags),
        }

    def to_dict(self) -> dict[str, Any]:
        out = {
            _K_SANDBOX_ADDR: self.sandbox_addr,
            _K_INCARNATION_ID: self.incarnation_id,
            _K_SURFACE_ID: self.surface_id,
            _K_CAPTURE_GENERATION: self.capture_generation,
        }
        out.update(self.to_compact_dict())
        return out


@dataclass(frozen=True, slots=True)
class BrowserFrameMeta:
    """Header-inspected frame provenance metadata (zero raw bytes)."""

    surface_key: SurfaceKey
    nav_generation: int
    frame_seq: int
    media_type: str
    width: int
    height: int
    size_bytes: int
    frame_sha256: str
    captured_at: float

    def __post_init__(self) -> None:
        if not isinstance(self.surface_key, SurfaceKey):
            raise CoordValidationError(_ERR_INVALID_SURFACE_KEY)
        validate_positive_int(self.nav_generation, _K_NAV_GENERATION)
        validate_positive_int(self.frame_seq, _K_FRAME_SEQ)
        if self.media_type not in ALLOWED_FRAME_MEDIA_TYPES:
            raise CoordValidationError("frame_media_type_unsupported")
        validate_positive_int(self.width, _K_WIDTH, max_value=MAX_FRAME_WIDTH)
        validate_positive_int(self.height, _K_HEIGHT, max_value=MAX_FRAME_HEIGHT)
        if self.width * self.height > MAX_FRAME_PIXELS:
            raise CoordValidationError("frame_dimensions_out_of_bounds")
        if type(self.size_bytes) is not int or not (
            MIN_FRAME_BYTES <= self.size_bytes <= MAX_FRAME_BYTES
        ):
            raise CoordValidationError("frame_size_out_of_bounds")
        if (
            not isinstance(self.frame_sha256, str)
            or _SHA256_HEX_RE.fullmatch(self.frame_sha256) is None
        ):
            raise CoordValidationError("invalid_frame_sha256")
        validate_finite_nonneg_float(self.captured_at, _K_CAPTURED_AT)

    @property
    def sandbox_addr(self) -> str:
        return self.surface_key.sandbox_addr

    @property
    def incarnation_id(self) -> str:
        return self.surface_key.incarnation_id

    @property
    def surface_id(self) -> str:
        return self.surface_key.surface_id

    @property
    def capture_generation(self) -> int:
        return self.surface_key.capture_generation

    def to_compact_dict(self) -> dict[str, Any]:
        return {
            _K_FRAME_SEQ: self.frame_seq,
            _K_MEDIA_TYPE: self.media_type,
            _K_WIDTH: self.width,
            _K_HEIGHT: self.height,
            _K_SIZE_BYTES: self.size_bytes,
            _K_FRAME_SHA256: self.frame_sha256,
            _K_CAPTURED_AT: self.captured_at,
        }

    def to_dict(self) -> dict[str, Any]:
        out = {
            _K_SANDBOX_ADDR: self.sandbox_addr,
            _K_INCARNATION_ID: self.incarnation_id,
            _K_SURFACE_ID: self.surface_id,
            _K_CAPTURE_GENERATION: self.capture_generation,
            _K_NAV_GENERATION: self.nav_generation,
        }
        out.update(self.to_compact_dict())
        return out


@dataclass(frozen=True, slots=True)
class PairedBrowserFrame:
    """Structurally enforced navigation <-> frame provenance pairing unit."""

    nav: BrowserNavState
    frame: BrowserFrameMeta
    untrusted_content: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.nav, BrowserNavState) or not isinstance(
            self.frame, BrowserFrameMeta
        ):
            raise CoordValidationError(ERR_PAIRING_MISMATCH)
        if self.untrusted_content is not True:
            raise CoordValidationError(ERR_UNTRUSTED_CONTENT_REQUIRED)
        if (
            self.nav.surface_key != self.frame.surface_key
            or self.nav.nav_generation != self.frame.nav_generation
        ):
            raise CoordValidationError(ERR_PAIRING_MISMATCH)

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_NAV: self.nav.to_dict(),
            _K_FRAME: self.frame.to_compact_dict(),
            _K_UNTRUSTED_CONTENT: self.untrusted_content,
        }


@dataclass(frozen=True, slots=True)
class FrameAdmissionResult:
    """Outcome of a frame ingestion attempt against surface provenance fences."""

    accepted: bool
    stale_reason: str | None = None
    frame_meta: BrowserFrameMeta | None = None
    paired_frame: PairedBrowserFrame | None = None

    def __post_init__(self) -> None:
        require_bool(self.accepted, "accepted")
        if self.accepted:
            if (
                self.stale_reason is not None
                or self.frame_meta is None
                or self.paired_frame is None
            ):
                raise CoordValidationError("invalid_accepted_admission_result")
        else:
            if self.stale_reason not in VALID_STALE_REASONS:
                raise CoordValidationError("invalid_stale_reason")
            if self.frame_meta is not None or self.paired_frame is not None:
                raise CoordValidationError("rejected_admission_must_not_carry_frame")


@dataclass(frozen=True, slots=True)
class SandboxViewMeta:
    """Compact sandbox display context shared by snapshots and wall tiles."""

    worker_ref: str
    instance_name: str
    sandbox_status: str
    capture_generation: int

    def __post_init__(self) -> None:
        validate_token_strict(self.worker_ref, _K_WORKER_REF)
        validate_token_strict(self.instance_name, _K_INSTANCE_NAME)
        if self.sandbox_status not in VALID_SANDBOX_STATUSES:
            raise CoordValidationError("invalid_sandbox_status")
        validate_positive_int(self.capture_generation, _K_CAPTURE_GENERATION)


@dataclass(frozen=True, slots=True)
class FrameFreshness:
    """Read-time monotonic-clock freshness assessment."""

    frame_stale: bool
    stale_reason: str | None
    frame_age_ms: int | None

    def __post_init__(self) -> None:
        require_bool(self.frame_stale, _K_FRAME_STALE)
        if self.frame_stale:
            if self.stale_reason not in VALID_STALE_REASONS:
                raise CoordValidationError("invalid_stale_reason")
        elif self.stale_reason is not None:
            raise CoordValidationError("fresh_frame_must_not_have_stale_reason")
        if self.frame_age_ms is not None:
            validate_nonneg_int(self.frame_age_ms, _K_FRAME_AGE_MS)


@dataclass(frozen=True, slots=True)
class BrowserSurfaceAudit:
    """Immutable audit counters and read-session echo attached to snapshots."""

    dropped_frame_counts: Mapping[str, int]
    observed_at: float
    read_session: ReadSessionEcho | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.dropped_frame_counts, Mapping):
            raise CoordValidationError("invalid_dropped_frame_counts")
        clean_counts: dict[str, int] = {}
        for key, val in self.dropped_frame_counts.items():
            if not isinstance(key, str) or key not in VALID_STALE_REASONS:
                raise CoordValidationError("invalid_dropped_frame_reason")
            clean_counts[key] = validate_nonneg_int(val, "dropped_count")
        object.__setattr__(
            self, _K_DROPPED_COUNTS, MappingProxyType(clean_counts)
        )
        validate_finite_nonneg_float(self.observed_at, _K_OBSERVED_AT)
        if self.read_session is not None and not isinstance(
            self.read_session, ReadSessionEcho
        ):
            raise CoordValidationError("invalid_read_session")


@dataclass(frozen=True, slots=True)
class BrowserWallTile:
    """Metadata-only PiP Browser Wall tile (zero raw pixels)."""

    sandbox_meta: SandboxViewMeta
    surface_key: SurfaceKey
    nav: BrowserNavState | None
    frame_meta: BrowserFrameMeta | None
    freshness: FrameFreshness
    untrusted_content: bool = True

    def __post_init__(self) -> None:
        if self.untrusted_content is not True:
            raise CoordValidationError(ERR_UNTRUSTED_CONTENT_REQUIRED)
        if not isinstance(self.sandbox_meta, SandboxViewMeta):
            raise CoordValidationError("invalid_sandbox_meta")
        if not isinstance(self.surface_key, SurfaceKey):
            raise CoordValidationError(_ERR_INVALID_SURFACE_KEY)
        if self.sandbox_meta.capture_generation != self.surface_key.capture_generation:
            raise CoordValidationError(ERR_PAIRING_MISMATCH)
        if not isinstance(self.freshness, FrameFreshness):
            raise CoordValidationError("invalid_freshness")
        if self.nav is not None and self.nav.surface_key != self.surface_key:
            raise CoordValidationError(ERR_PAIRING_MISMATCH)
        if self.frame_meta is not None and (
            self.nav is None
            or self.frame_meta.surface_key != self.surface_key
            or self.frame_meta.nav_generation != self.nav.nav_generation
        ):
            raise CoordValidationError(ERR_PAIRING_MISMATCH)

    @property
    def sandbox_addr(self) -> str:
        return self.surface_key.sandbox_addr

    @property
    def incarnation_id(self) -> str:
        return self.surface_key.incarnation_id

    @property
    def surface_id(self) -> str:
        return self.surface_key.surface_id

    @property
    def capture_generation(self) -> int:
        return self.surface_key.capture_generation

    @property
    def frame_stale(self) -> bool:
        return self.freshness.frame_stale

    @property
    def stale_reason(self) -> str | None:
        return self.freshness.stale_reason

    @property
    def frame_age_ms(self) -> int | None:
        return self.freshness.frame_age_ms

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SANDBOX_ADDR: self.sandbox_addr,
            _K_WORKER_REF: self.sandbox_meta.worker_ref,
            _K_INSTANCE_NAME: self.sandbox_meta.instance_name,
            _K_INCARNATION_ID: self.incarnation_id,
            _K_SURFACE_ID: self.surface_id,
            _K_CAPTURE_GENERATION: self.capture_generation,
            _K_SANDBOX_STATUS: self.sandbox_meta.sandbox_status,
            _K_UNTRUSTED_CONTENT: self.untrusted_content,
            _K_FRAME_STALE: self.frame_stale,
            _K_STALE_REASON: self.stale_reason,
            _K_FRAME_AGE_MS: self.frame_age_ms,
            _K_NAV: None if self.nav is None else self.nav.to_compact_dict(),
            _K_FRAME: (
                None if self.frame_meta is None else self.frame_meta.to_compact_dict()
            ),
        }


@dataclass(frozen=True, slots=True)
class BrowserSurfaceSnapshot:
    """Operator-only, byte-bounded snapshot for one sandbox browser surface."""

    schema_version: str
    sandbox_meta: SandboxViewMeta
    surface_key: SurfaceKey
    nav: BrowserNavState | None
    paired_frame: PairedBrowserFrame | None
    freshness: FrameFreshness
    frame_b64: str | None
    frame_b64_omitted_reason: str | None
    audit: BrowserSurfaceAudit
    untrusted_content: bool = True

    def __post_init__(self) -> None:
        if self.schema_version != BROWSER_OBSERVE_SCHEMA_VERSION:
            raise CoordValidationError("invalid_schema_version")
        if self.untrusted_content is not True:
            raise CoordValidationError(ERR_UNTRUSTED_CONTENT_REQUIRED)
        if not isinstance(self.sandbox_meta, SandboxViewMeta) or not isinstance(
            self.surface_key, SurfaceKey
        ):
            raise CoordValidationError("invalid_snapshot_identity")
        if self.sandbox_meta.capture_generation != self.surface_key.capture_generation:
            raise CoordValidationError(ERR_PAIRING_MISMATCH)
        if not isinstance(self.freshness, FrameFreshness) or not isinstance(
            self.audit, BrowserSurfaceAudit
        ):
            raise CoordValidationError("invalid_snapshot_metadata")
        self._validate_pairing_and_pixels()

    def _validate_pairing_and_pixels(self) -> None:
        if self.nav is not None and self.nav.surface_key != self.surface_key:
            raise CoordValidationError(ERR_PAIRING_MISMATCH)
        if self.paired_frame is not None and self.paired_frame.nav != self.nav:
            raise CoordValidationError(ERR_PAIRING_MISMATCH)
        self._validate_frame_b64_fields()

    def _validate_frame_b64_fields(self) -> None:
        if self.frame_b64 is not None and (
            not isinstance(self.frame_b64, str)
            or self.freshness.frame_stale
            or self.paired_frame is None
            or self.frame_b64_omitted_reason is not None
        ):
            raise CoordValidationError("invalid_frame_b64_state")
        if self.frame_b64_omitted_reason is not None and (
            self.frame_b64_omitted_reason not in VALID_STALE_REASONS
            and self.frame_b64_omitted_reason != OMIT_BUDGET_EXCEEDED
        ):
            raise CoordValidationError("invalid_frame_b64_omitted_reason")

    @property
    def sandbox_addr(self) -> str:
        return self.surface_key.sandbox_addr

    @property
    def worker_ref(self) -> str:
        return self.sandbox_meta.worker_ref

    @property
    def instance_name(self) -> str:
        return self.sandbox_meta.instance_name

    @property
    def incarnation_id(self) -> str:
        return self.surface_key.incarnation_id

    @property
    def surface_id(self) -> str:
        return self.surface_key.surface_id

    @property
    def capture_generation(self) -> int:
        return self.surface_key.capture_generation

    @property
    def sandbox_status(self) -> str:
        return self.sandbox_meta.sandbox_status

    @property
    def frame_stale(self) -> bool:
        return self.freshness.frame_stale

    @property
    def stale_reason(self) -> str | None:
        return self.freshness.stale_reason

    @property
    def frame_age_ms(self) -> int | None:
        return self.freshness.frame_age_ms

    @property
    def dropped_frame_counts(self) -> Mapping[str, int]:
        return self.audit.dropped_frame_counts

    @property
    def observed_at(self) -> float:
        return self.audit.observed_at

    @property
    def read_session(self) -> ReadSessionEcho | None:
        return self.audit.read_session

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SCHEMA_VERSION: self.schema_version,
            _K_SANDBOX_ADDR: self.sandbox_addr,
            _K_WORKER_REF: self.worker_ref,
            _K_INSTANCE_NAME: self.instance_name,
            _K_INCARNATION_ID: self.incarnation_id,
            _K_SURFACE_ID: self.surface_id,
            _K_CAPTURE_GENERATION: self.capture_generation,
            _K_SANDBOX_STATUS: self.sandbox_status,
            _K_UNTRUSTED_CONTENT: self.untrusted_content,
            _K_FRAME_STALE: self.frame_stale,
            _K_STALE_REASON: self.stale_reason,
            _K_FRAME_AGE_MS: self.frame_age_ms,
            _K_FRAME_B64: self.frame_b64,
            _K_FRAME_B64_OMITTED: self.frame_b64_omitted_reason,
            _K_NAV: None if self.nav is None else self.nav.to_compact_dict(),
            _K_FRAME: (
                None
                if self.paired_frame is None
                else self.paired_frame.frame.to_compact_dict()
            ),
            _K_DROPPED_COUNTS: dict(sorted(self.dropped_frame_counts.items())),
            _K_OBSERVED_AT: self.observed_at,
            _K_READ_SESSION: (
                None if self.read_session is None else self.read_session.to_dict()
            ),
        }

    def to_json_bytes(self) -> bytes:
        return serialize_json_bytes(self)


@dataclass(frozen=True, slots=True)
class BrowserWallPage:
    """Paginated, metadata-only PiP Browser Wall response."""

    schema_version: str
    tiles: tuple[BrowserWallTile, ...]
    has_more: bool
    next_cursor: str | None
    observed_at: float
    read_session: ReadSessionEcho | None = None

    def __post_init__(self) -> None:
        if self.schema_version != BROWSER_OBSERVE_SCHEMA_VERSION:
            raise CoordValidationError("invalid_schema_version")
        if not isinstance(self.tiles, tuple) or not all(
            isinstance(t, BrowserWallTile) for t in self.tiles
        ):
            raise CoordValidationError("invalid_wall_tiles")
        require_bool(self.has_more, _K_HAS_MORE)
        if self.has_more and not isinstance(self.next_cursor, str):
            raise CoordValidationError("has_more_requires_next_cursor")
        if not self.has_more and self.next_cursor is not None:
            raise CoordValidationError("final_page_must_not_have_cursor")
        validate_finite_nonneg_float(self.observed_at, _K_OBSERVED_AT)
        if self.read_session is not None and not isinstance(
            self.read_session, ReadSessionEcho
        ):
            raise CoordValidationError("invalid_read_session")

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SCHEMA_VERSION: self.schema_version,
            _K_TILES: [tile.to_dict() for tile in self.tiles],
            _K_HAS_MORE: self.has_more,
            _K_NEXT_CURSOR: self.next_cursor,
            _K_OBSERVED_AT: self.observed_at,
            _K_READ_SESSION: (
                None if self.read_session is None else self.read_session.to_dict()
            ),
        }

    def to_json_bytes(self) -> bytes:
        return serialize_json_bytes(self)
