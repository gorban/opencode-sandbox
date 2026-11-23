"""Read-only terminal observation contract, bounds, and canonical cursor codec for PRD M3.3.

Pure Python standard library plus read-only imports from docs/prds/spikes/m.
All snapshot structures serialize strictly with ``allow_nan=False`` and stay
bounded by explicit UTF-8 JSON byte ceilings.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any

_TERMINAL_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _TERMINAL_DIR.parent
if str(_SPIKE_M_DIR) not in sys.path:
    sys.path.insert(0, str(_SPIKE_M_DIR))

from oc_address import AddressError, TargetAddr, parse_canonical_addr  # noqa: E402
from oc_coord_contract import CoordValidationError, validate_opaque_token  # noqa: E402

TERMINAL_OBSERVE_SCHEMA_VERSION = "oc.m3.terminal_observe@1"
VALID_TERMINAL_IDS: frozenset[str] = frozenset({"opencode-tui", "shell"})

MAX_ESC_SEQ_BYTES = 4096
MAX_SAFE_SGR_PARAM_BYTES = 64
MAX_SAFE_SGR_PARAMS = 16
MAX_SAFE_SGR_VALUE = 255
MAX_FEED_CHUNK_BYTES = 4 * 1024 * 1024

MAX_FRAME_TEXT_BYTES = 16 * 1024
DEFAULT_MAX_RING_FRAMES = 512
MAX_RING_FRAMES = 4096
DEFAULT_MAX_RING_BYTES = 1024 * 1024
MAX_RING_BYTES = 8 * 1024 * 1024
MAX_TRACKED_SANDBOXES = 64
MAX_RETIRED_INCARNATIONS = 1024

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200
MIN_RESPONSE_BYTES = 1024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_CURSOR_BYTES = 512
MAX_INT64 = (1 << 63) - 1

CURSOR_PREFIX = "v1."
OP_TERMINAL_REPLAY = "terminal_replay"
VALID_CURSOR_OPS: frozenset[str] = frozenset({OP_TERMINAL_REPLAY})

_CURSOR_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)
_SCOPE_HASH_RE = re.compile(r"^[0-9a-f]{16}$", re.ASCII)
_CURSOR_KEYS: frozenset[str] = frozenset({"op", "fh", "inc", "ep", "seq"})

ERR_CURSOR_MALFORMED = "cursor_malformed"
ERR_CURSOR_SCOPE_MISMATCH = "cursor_scope_mismatch"
ERR_CURSOR_TOO_LARGE = "cursor_exceeds_max_bytes"
ERR_BUDGET_ENVELOPE = "response_budget_too_small_for_envelope"
ERR_BUDGET_ITEM = "response_budget_too_small_for_item"
ERR_INVALID_TERMINAL_ID = "invalid_terminal_id"
ERR_INVALID_SANITIZER_MODE = "invalid_sanitizer_mode"
ERR_TARGET_MUST_BE_SANDBOX = "terminal_target_must_be_sandbox"

_K_UTF8 = "utf-8"
_K_SANDBOX_ADDR = "sandbox_addr"
_K_INCARNATION_ID = "incarnation_id"
_K_TERMINAL_ID = "terminal_id"
_K_STREAM_EPOCH = "stream_epoch"
_K_CAPTURED_AT = "captured_at"
_K_TEXT_BYTES = "text_bytes"
_K_TEXT_TRUNCATED = "text_truncated"
_K_ORIGINAL_SANITIZED_BYTES = "original_sanitized_bytes"
_K_RAW_INPUT_BYTES = "raw_input_bytes"
_K_UNTRUSTED_CONTENT = "untrusted_content"
_K_INPUT_BYTES = "input_bytes"
_K_OUTPUT_BYTES = "output_bytes"
_K_READ_SESSION_ID = "read_session_id"
_K_SESSION_GENERATION = "session_generation"
_K_NEXT_CURSOR = "next_cursor"
_K_READ_SESSION = "read_session"
_K_SCHEMA_VERSION = "schema_version"
_K_SANITIZER_MODE = "sanitizer_mode"
_K_STREAM_CLOSED = "stream_closed"
_K_STREAM_STATS = "stream_stats"
_K_FRAME_STATS = "frame_stats"

_STAT_DIAGNOSTIC_FIELDS: tuple[str, ...] = (
    "dropped_osc_count",
    "dropped_csi_count",
    "dropped_string_seq_count",
    "dropped_esc_count",
    "dropped_c0_c1_count",
    "dropped_bidi_count",
    "invalid_utf8_count",
    "overlong_seq_dropped_count",
    "neutralized_bare_cr_count",
    "allowed_sgr_count",
)


class SanitizerMode(str, Enum):
    """Output scrubbing mode for confined read-only terminal streams."""

    PLAIN = "plain"
    SAFE_SGR = "safe_sgr"


def validate_strict_int_range(
    value: object, label: str, min_val: int, max_val: int
) -> int:
    """Require a strict non-bool int within [min_val, max_val]."""
    if type(value) is not int or not (min_val <= value <= max_val):
        raise CoordValidationError(f"{label} must be an int in {min_val}..{max_val}")
    return value


def validate_finite_timestamp(value: object, label: str = _K_CAPTURED_AT) -> float:
    """Require a finite non-negative int/float timestamp (rejecting bool/NaN/Inf/overflow)."""
    if type(value) not in (int, float):
        raise CoordValidationError(f"{label} must be a finite non-negative number")
    try:
        ts = float(value)
    except OverflowError as exc:
        raise CoordValidationError(f"{label} must be finite and >= 0.0") from exc
    if not math.isfinite(ts) or ts < 0.0:
        raise CoordValidationError(f"{label} must be finite and >= 0.0")
    return 0.0 if ts == 0.0 else ts


def validate_terminal_token(value: object, label: str) -> str:
    """Validate an opaque identifier token, wrapping AddressError as CoordValidationError."""
    try:
        return validate_opaque_token(value, label)
    except AddressError as exc:
        raise CoordValidationError(str(exc)) from exc


def parse_terminal_target(raw: object) -> TargetAddr:
    """Parse canonical local or remote sandbox target address (rejecting @PEER)."""
    try:
        addr = parse_canonical_addr(raw)
    except AddressError as exc:
        raise CoordValidationError(str(exc)) from exc
    if addr.kind not in ("local", "remote"):
        raise CoordValidationError(ERR_TARGET_MUST_BE_SANDBOX)
    return addr


def validate_terminal_id(raw: object) -> str:
    """Validate a closed-allowlist terminal identifier ('opencode-tui' or 'shell')."""
    if not isinstance(raw, str) or raw not in VALID_TERMINAL_IDS:
        raise CoordValidationError(ERR_INVALID_TERMINAL_ID)
    return raw


def validate_sanitizer_mode(mode: object) -> SanitizerMode:
    """Validate a SanitizerMode enum value strictly."""
    if not isinstance(mode, SanitizerMode):
        raise CoordValidationError(ERR_INVALID_SANITIZER_MODE)
    return mode


@dataclass(frozen=True, slots=True)
class SanitizerStats:
    """Bounded diagnostic counters produced by TerminalOutputSanitizer."""

    input_bytes: int = 0
    output_bytes: int = 0
    dropped_osc_count: int = 0
    dropped_csi_count: int = 0
    dropped_string_seq_count: int = 0
    dropped_esc_count: int = 0
    dropped_c0_c1_count: int = 0
    dropped_bidi_count: int = 0
    invalid_utf8_count: int = 0
    overlong_seq_dropped_count: int = 0
    neutralized_bare_cr_count: int = 0
    allowed_sgr_count: int = 0

    def __post_init__(self) -> None:
        for attr in (_K_INPUT_BYTES, _K_OUTPUT_BYTES, *_STAT_DIAGNOSTIC_FIELDS):
            val = getattr(self, attr)
            if type(val) is not int or val < 0:
                raise CoordValidationError(f"SanitizerStats.{attr} must be non-negative int")

    def to_dict(self) -> dict[str, int]:
        out: dict[str, int] = {
            _K_INPUT_BYTES: self.input_bytes,
            _K_OUTPUT_BYTES: self.output_bytes,
        }
        for attr in _STAT_DIAGNOSTIC_FIELDS:
            out[attr] = getattr(self, attr)
        return out

    def to_compact_dict(self) -> dict[str, int]:
        out: dict[str, int] = {
            _K_INPUT_BYTES: self.input_bytes,
            _K_OUTPUT_BYTES: self.output_bytes,
        }
        for attr in _STAT_DIAGNOSTIC_FIELDS:
            val = getattr(self, attr)
            if val > 0:
                out[attr] = val
        return out


@dataclass(frozen=True, slots=True)
class ReadSessionEcho:
    """Validated operator read-session coordinates echoed on replay pages."""

    read_session_id: str
    session_generation: int

    def __post_init__(self) -> None:
        validate_terminal_token(self.read_session_id, _K_READ_SESSION_ID)
        validate_strict_int_range(self.session_generation, _K_SESSION_GENERATION, 1, MAX_INT64)

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_READ_SESSION_ID: self.read_session_id,
            _K_SESSION_GENERATION: self.session_generation,
        }


@dataclass(frozen=True, slots=True)
class TerminalReplayFrame:
    """Provenance-bound, sanitized, untrusted terminal output frame."""

    sandbox_addr: str
    incarnation_id: str
    terminal_id: str
    stream_epoch: int
    frame_seq: int
    captured_at: float
    text: str
    text_bytes: int
    text_truncated: bool
    original_sanitized_bytes: int
    raw_input_bytes: int
    frame_stats: SanitizerStats
    untrusted_content: bool = True

    def __post_init__(self) -> None:
        parse_terminal_target(self.sandbox_addr)
        validate_terminal_token(self.incarnation_id, _K_INCARNATION_ID)
        validate_terminal_id(self.terminal_id)
        validate_strict_int_range(self.stream_epoch, _K_STREAM_EPOCH, 1, MAX_INT64)
        validate_strict_int_range(self.frame_seq, "frame_seq", 1, MAX_INT64)
        validate_finite_timestamp(self.captured_at, _K_CAPTURED_AT)
        if not isinstance(self.text, str):
            raise CoordValidationError("frame text must be str")
        validate_strict_int_range(self.text_bytes, _K_TEXT_BYTES, 0, MAX_FRAME_TEXT_BYTES)
        if type(self.text_truncated) is not bool:
            raise CoordValidationError("text_truncated must be bool")
        validate_strict_int_range(
            self.original_sanitized_bytes, _K_ORIGINAL_SANITIZED_BYTES, 0, MAX_INT64
        )
        validate_strict_int_range(self.raw_input_bytes, _K_RAW_INPUT_BYTES, 0, MAX_FEED_CHUNK_BYTES)
        if not isinstance(self.frame_stats, SanitizerStats):
            raise CoordValidationError("frame_stats must be SanitizerStats")
        if self.untrusted_content is not True:
            raise CoordValidationError("terminal replay frames must set untrusted_content=True")

    def to_dict(self) -> dict[str, Any]:
        return {
            _K_SANDBOX_ADDR: self.sandbox_addr,
            _K_INCARNATION_ID: self.incarnation_id,
            _K_TERMINAL_ID: self.terminal_id,
            _K_STREAM_EPOCH: self.stream_epoch,
            "frame_seq": self.frame_seq,
            _K_CAPTURED_AT: self.captured_at,
            "text": self.text,
            _K_TEXT_BYTES: self.text_bytes,
            _K_TEXT_TRUNCATED: self.text_truncated,
            _K_ORIGINAL_SANITIZED_BYTES: self.original_sanitized_bytes,
            _K_RAW_INPUT_BYTES: self.raw_input_bytes,
            _K_FRAME_STATS: self.frame_stats.to_dict(),
            _K_UNTRUSTED_CONTENT: self.untrusted_content,
        }

    def to_page_item_dict(self) -> dict[str, Any]:
        """Compact per-frame wire representation omitting page-invariant identity fields."""
        out: dict[str, Any] = {
            "frame_seq": self.frame_seq,
            _K_CAPTURED_AT: self.captured_at,
            "text": self.text,
            _K_TEXT_BYTES: self.text_bytes,
            _K_RAW_INPUT_BYTES: self.raw_input_bytes,
            _K_FRAME_STATS: self.frame_stats.to_compact_dict(),
        }
        if self.text_truncated:
            out[_K_TEXT_TRUNCATED] = True
            out[_K_ORIGINAL_SANITIZED_BYTES] = self.original_sanitized_bytes
        return out


@dataclass(frozen=True, slots=True)
class TerminalReplayPage:
    """Bounded operator-only paginated terminal replay snapshot."""

    schema_version: str
    read_only: bool
    untrusted_content: bool
    sandbox_addr: str
    incarnation_id: str
    terminal_id: str
    stream_epoch: int
    sanitizer_mode: str
    stream_closed: bool
    ring_frames_retained: int
    ring_bytes_retained: int
    evicted_frame_count: int
    frames_evicted_before_page: bool
    stream_stats: SanitizerStats
    frames: tuple[TerminalReplayFrame, ...]
    has_more: bool
    next_cursor: str | None
    read_session: ReadSessionEcho | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            _K_SCHEMA_VERSION: self.schema_version,
            "read_only": self.read_only,
            _K_UNTRUSTED_CONTENT: self.untrusted_content,
            _K_SANDBOX_ADDR: self.sandbox_addr,
            _K_INCARNATION_ID: self.incarnation_id,
            _K_TERMINAL_ID: self.terminal_id,
            _K_STREAM_EPOCH: self.stream_epoch,
            _K_SANITIZER_MODE: self.sanitizer_mode,
            _K_STREAM_CLOSED: self.stream_closed,
            "ring_frames": self.ring_frames_retained,
            "ring_bytes": self.ring_bytes_retained,
            "evicted_frames": self.evicted_frame_count,
            "frames_evicted_before_page": self.frames_evicted_before_page,
            _K_STREAM_STATS: self.stream_stats.to_compact_dict(),
            "frames": [f.to_page_item_dict() for f in self.frames],
            "has_more": self.has_more,
        }
        if self.next_cursor is not None:
            out[_K_NEXT_CURSOR] = self.next_cursor
        if self.read_session is not None:
            out[_K_READ_SESSION] = self.read_session.to_dict()
        return out


def serialize_terminal_json(obj: Any) -> str:
    """Serialize a terminal snapshot or mapping strictly without NaN/Infinity."""
    payload = obj.to_dict() if hasattr(obj, "to_dict") else obj
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def serialize_terminal_bytes(obj: Any) -> bytes:
    """Return exact UTF-8 JSON bytes for hard response-size budget enforcement."""
    return serialize_terminal_json(obj).encode(_K_UTF8)


def compute_replay_scope_hash(
    *,
    target: str,
    terminal_id: str,
    incarnation_id: str,
    stream_epoch: int,
) -> str:
    """Compute a 16-hex-char SHA-256 scope fingerprint binding cursor to stream identity."""
    canonical = json.dumps(
        {
            "op": OP_TERMINAL_REPLAY,
            "params": {
                "target": target,
                _K_TERMINAL_ID: terminal_id,
                _K_INCARNATION_ID: incarnation_id,
                _K_STREAM_EPOCH: stream_epoch,
            },
        },
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode(_K_UTF8)
    return hashlib.sha256(canonical).hexdigest()[:16]


def _encode_cursor_dict(payload: Mapping[str, Any]) -> str:
    raw_json = json.dumps(
        dict(payload),
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ).encode(_K_UTF8)
    encoded = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    cursor = f"{CURSOR_PREFIX}{encoded}"
    if len(cursor.encode(_K_UTF8)) > MAX_CURSOR_BYTES:
        raise CoordValidationError(ERR_CURSOR_TOO_LARGE)
    return cursor


def encode_replay_cursor(
    *,
    scope_hash: str,
    incarnation_id: str,
    stream_epoch: int,
    frame_seq: int,
) -> str:
    """Encode a canonical collision-free base64url JSON cursor for terminal replay."""
    return _encode_cursor_dict(
        {
            "op": OP_TERMINAL_REPLAY,
            "fh": scope_hash,
            "inc": incarnation_id,
            "ep": stream_epoch,
            "seq": frame_seq,
        }
    )


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"Forbidden JSON constant: {token}")


def _decode_raw_cursor_dict(raw: object) -> dict[str, Any]:
    if not isinstance(raw, str):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    raw_bytes = raw.encode(_K_UTF8, errors="surrogatepass")
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
            decoded_bytes.decode(_K_UTF8), parse_constant=_reject_json_constant
        )
    except (ValueError, RecursionError) as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if not isinstance(parsed, dict):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        canonical = _encode_cursor_dict(parsed)
    except (ValueError, TypeError, CoordValidationError) as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    if canonical != raw:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return parsed


def _validate_cursor_fields(parsed: Mapping[str, Any]) -> tuple[str, str, str, int, int]:
    if set(parsed.keys()) != _CURSOR_KEYS:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    op = parsed["op"]
    fh = parsed["fh"]
    if not isinstance(op, str) or op not in VALID_CURSOR_OPS:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if not isinstance(fh, str) or _SCOPE_HASH_RE.fullmatch(fh) is None:
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    try:
        inc = validate_terminal_token(parsed["inc"], _K_INCARNATION_ID)
    except CoordValidationError as exc:
        raise CoordValidationError(ERR_CURSOR_MALFORMED) from exc
    ep = parsed["ep"]
    seq = parsed["seq"]
    if type(ep) is not int or not (1 <= ep <= MAX_INT64):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    if type(seq) is not int or not (1 <= seq <= MAX_INT64):
        raise CoordValidationError(ERR_CURSOR_MALFORMED)
    return op, fh, inc, ep, seq


def decode_replay_cursor(
    raw: object,
    *,
    expected_scope_hash: str,
    expected_incarnation_id: str,
    expected_stream_epoch: int,
) -> int | None:
    """Decode and scope-verify a terminal replay cursor, returning after_seq or None."""
    if raw is None:
        return None
    parsed = _decode_raw_cursor_dict(raw)
    op, fh, inc, ep, seq = _validate_cursor_fields(parsed)
    if (
        op != OP_TERMINAL_REPLAY
        or fh != expected_scope_hash
        or inc != expected_incarnation_id
        or ep != expected_stream_epoch
    ):
        raise CoordValidationError(ERR_CURSOR_SCOPE_MISMATCH)
    return seq
