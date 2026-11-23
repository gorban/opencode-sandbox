"""Standalone, operator-only read-only Tier-B Human Inbox projection service.

Public entry points:
- ``ReadOnlyInboxService`` (and alias ``HumanInboxReadProjection``)
  - ``list_inbox_items``
  - ``get_inbox_item``
  - ``get_inbox_summary``
- ``open_readonly_inbox_snapshot`` (re-exported from ``oc_inbox_db``)

Strictly zero grant, approve, reject, defer, resolve, awakeable, or DB-write
authority.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
import hmac
import json
import math
from pathlib import Path
import re
import sqlite3
import sys
import time
from typing import Any, TypeVar, cast

_INBOX_DIR = Path(__file__).resolve().parent
_SPIKE_N_DIR = _INBOX_DIR.parent
_SPIKE_M_DIR = _SPIKE_N_DIR.parent / "m"
_SPIKE_M_PROJ_DIR = _SPIKE_M_DIR / "projection"
_SPIKE_L_DIR = _SPIKE_N_DIR.parent / "l"
for _import_dir in (
    str(_INBOX_DIR),
    str(_SPIKE_N_DIR),
    str(_SPIKE_M_PROJ_DIR),
    str(_SPIKE_M_DIR),
    str(_SPIKE_L_DIR),
):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_address import (  # noqa: E402
    _BIDI_CODEPOINTS,
    AddressError,
    parse_canonical_addr,
)
from oc_coord_contract import (  # noqa: E402
    _MEDIA_TYPE_RE,
    CoordAuthError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    PrincipalCtx,
    RevokedError,
)
from oc_inbox_contract import (  # noqa: E402
    ANOMALY_ARTIFACT_AMBIGUOUS,
    ANOMALY_ARTIFACT_MISMATCH,
    ANOMALY_ARTIFACT_MISSING,
    ANOMALY_MALFORMED_METADATA,
    ANOMALY_MALFORMED_PIN_INPUT,
    ANOMALY_PIN_MISMATCH,
    ANOMALY_POLICY_MISMATCH,
    ANOMALY_RUN_MISSING,
    ANOMALY_TAMPERED_STORAGE,
    BUCKET_MALFORMED,
    DEFAULT_MAX_READ_MS,
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_PAGE_LIMIT,
    ERR_CURSOR_SNAPSHOT_CHANGED,
    INBOX_SCHEMA_VERSION,
    MAX_ARTIFACTS_PER_ITEM,
    MAX_JSON_DEPTH,
    MAX_METADATA_KEY_BYTES,
    MAX_METADATA_KEYS,
    MAX_METADATA_LIST_ITEMS,
    MAX_METADATA_TEXT_BYTES,
    MAX_PAGE_LIMIT,
    MAX_PRIORITY_RANK,
    MAX_READ_MS,
    MAX_RESPONSE_BYTES,
    MAX_SQLITE_INT64,
    MAX_STATUS_FILTER_ITEMS,
    MIN_READ_MS,
    MIN_RESPONSE_BYTES,
    OP_INBOX_LIST,
    PIN_VERIFICATION_SCOPE_ITEM_ONLY,
    SOURCE_HOST_WORKFLOW_ENGINE,
    SQL_MAX_CELL_BYTES,
    STATUS_PENDING,
    VALID_SEVERITIES,
    VALID_SOURCE_KINDS,
    VALID_STATUSES,
    InboxArtifactRef,
    InboxItem,
    InboxItemDetailSnapshot,
    InboxItemIdentity,
    InboxItemPinStatus,
    InboxItemPresentation,
    InboxItemState,
    InboxPage,
    InboxSummarySnapshot,
    ReadSessionEcho,
    compute_review_pin_sha256,
    compute_scope_hash,
    contains_credential_pattern,
    decode_inbox_list_cursor,
    encode_inbox_list_cursor,
    is_json_tree_valid,
    is_valid_sha256_hex,
    redact_sensitive_text,
    reject_json_constant,
    serialize_inbox_bytes,
    validate_clean_opaque_token,
)
from oc_inbox_db import (  # noqa: E402
    ERR_INBOX_UNREADABLE,
    check_deadline_ms,
    open_readonly_inbox_snapshot,
    read_inbox_seq_counter,
    select_item_artifacts,
    select_primary_artifacts_for_pin,
    select_review_items_page,
    select_severity_aggregate_counts,
    select_single_review_item,
    select_status_aggregate_counts,
    select_structural_summary_totals,
    verify_state_dir_and_db_readonly,
)
from oc_projection_decode import decode_bounded_blob  # noqa: E402
from oc_workflow_schema import (  # noqa: E402
    WorkflowSchemaError,
    parse_namespaced_id,
)

__all__ = [
    "HumanInboxReadProjection",
    "ReadOnlyInboxService",
    "open_readonly_inbox_snapshot",
]

_UTF8 = "utf-8"
_FALLBACK_MEDIA_TYPE = "application/octet-stream"
_ERR_BUDGET_ENVELOPE = "response_budget_too_small_for_envelope"
_ERR_BUDGET_ITEM = "response_budget_too_small_for_item"
_ERR_SESSION_RETIRED = "read_session_retired"
_ERR_AUTHORITY_REVOKED = "read_authority_revoked"
_PARAM_MAX_RESPONSE_BYTES = "max_response_bytes"
_PARAM_MAX_READ_MS = "max_read_ms"
_COL_REVIEW_ID = "review_id"
_COL_CREATED_AT = "created_at"
_COL_CREATED_AT_MALFORMED = "created_at_malformed"
_COL_IS_PRIMARY = "is_primary"
_COL_IS_PRIMARY_MALFORMED = "is_primary_malformed"
_COL_ARTIFACT_ID = "artifact_id"
_COL_ARTIFACT_ID_MALFORMED = "artifact_id_malformed"
_COL_BLOB_SHA256 = "blob_sha256"
_COL_BLOB_SHA256_MALFORMED = "blob_sha256_malformed"
_COL_SIZE_BYTES_MALFORMED = "size_bytes_malformed"
_COL_MEDIA_TYPE = "media_type"
_COL_MEDIA_TYPE_MALFORMED = "media_type_malformed"
_COL_LABEL_BLOB = "label_blob"
_COL_LABEL_BYTES = "label_bytes"
_COL_LABEL_NON_TEXT = "label_non_text"
_COL_STATUS_MALFORMED = "status_malformed"
_COL_TARGET_INC_ID = "target_incarnation_id"
_COL_WORKFLOW_ID = "workflow_id"
_COL_WORKFLOW_RUN_PRESENT = "workflow_run_present"
_COL_JOINED_RUN_ID = "joined_run_id"
_COL_CHECKPOINT_SEQ = "checkpoint_seq"
_T = TypeVar("_T")

# Stage-1 linear-time stack FSM states for ECMA-48 / VT100 escape stripping.
_ST_ESC = 1
_ST_ESC_INT = 2
_ST_CSI = 3
_ST_OSC = 4
_ST_STR = 5
_ST_OSC_ESC = 6
_ST_STR_ESC = 7
_C1_INTRODUCERS: dict[int, int] = {
    0x1B: _ST_ESC,
    0x9B: _ST_CSI,
    0x9D: _ST_OSC,
    0x90: _ST_STR,
    0x98: _ST_STR,
    0x9E: _ST_STR,
    0x9F: _ST_STR,
}

_KEY_NORM_RE = re.compile(r"[^a-z\d]+")
_SENSITIVE_KEY_TOKENS: tuple[str, ...] = (
    "envvars",
    "authheader",
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "privatekey",
    "apikey",
    "accesskey",
    "clientsecret",
    "bearer",
    "credential",
    "xapikey",
    "xauthtoken",
    "xgoogapikey",
    "awakeabletokenhash",
)


@dataclass(frozen=True, slots=True)
class _ListPackCtx:
    snapshot_seq: int
    page_limit: int
    scope_hash: str
    max_bytes: int
    session_echo: ReadSessionEcho | None
    deadline: float


@dataclass(frozen=True, slots=True)
class _DetailPackCtx:
    snapshot_seq: int
    max_bytes: int
    session_echo: ReadSessionEcho | None
    deadline: float


@dataclass(frozen=True, slots=True)
class _AdmittedReadCtx:
    caller: PrincipalCtx
    max_bytes: int
    deadline: float
    session_echo: ReadSessionEcho | None
    db_path: Path


@dataclass(frozen=True, slots=True)
class _PinEvalInputs:
    review_id: str
    run_id: str | None
    step_id: str | None
    checkpoint_seq: int | None
    artifact_sha256: str | None
    policy_digest: str | None
    stored_pin: str | None
    storage_tampered: bool
    format_invalid: bool


# --- Low-level BLOB decoding, Stage-1 scrubbing, and metadata_json sanitization ---


def _withhold_truncated_tail(text: str, sql_truncated: bool) -> tuple[str, bool]:
    """Drop the trailing incomplete non-whitespace token in O(tail_len) time."""
    if not sql_truncated or not text or text[-1].isspace():
        return text, False
    idx = len(text)
    while idx > 0 and not text[idx - 1].isspace():
        idx -= 1
    return text[:idx], True


def _is_ignored_escape_pad(code: int) -> bool:
    return (code < 0x20 and code not in (0x18, 0x1A, 0x1B)) or code == 0x7F


def _step_esc_dispatch(stack: list[int], code: int) -> bool:
    if _is_ignored_escape_pad(code):
        return True
    if code in (0x18, 0x1A):
        stack.pop()
        return True
    intro = _C1_INTRODUCERS.get(code)
    if intro is not None:
        stack.append(intro)
        return True
    if code == 0x5B:
        stack[-1] = _ST_CSI
        return True
    if code == 0x5D:
        stack[-1] = _ST_OSC
        return True
    if code in (0x50, 0x58, 0x5E, 0x5F):
        stack[-1] = _ST_STR
        return True
    if 0x20 <= code <= 0x2F:
        stack[-1] = _ST_ESC_INT
        return True
    stack.pop()
    return 0x30 <= code <= 0x7E


def _step_csi_or_interm(stack: list[int], state: int, code: int) -> bool:
    if _is_ignored_escape_pad(code):
        return True
    if code in (0x18, 0x1A):
        stack.pop()
        return True
    intro = _C1_INTRODUCERS.get(code)
    if intro is not None:
        stack.append(intro)
        return True
    cont_hi = 0x2F if state == _ST_ESC_INT else 0x3F
    final_lo = 0x30 if state == _ST_ESC_INT else 0x40
    if 0x20 <= code <= cont_hi:
        return True
    stack.pop()
    return final_lo <= code <= 0x7E


def _step_string_escape(stack: list[int], state: int, code: int) -> bool:
    if state in (_ST_OSC_ESC, _ST_STR_ESC):
        if _is_ignored_escape_pad(code) or code == 0x1B:
            return True
        if code in (0x5C, 0x18, 0x1A):
            stack.pop()
            return True
        stack[-1] = _ST_ESC
        return False
    if code in (0x9C, 0x18, 0x1A) or (state == _ST_OSC and code == 0x07):
        stack.pop()
        return True
    if code == 0x1B:
        stack[-1] = _ST_OSC_ESC if state == _ST_OSC else _ST_STR_ESC
    return True


def _advance_escape_stack(stack: list[int], code: int) -> bool:
    state = stack[-1]
    if state == _ST_ESC:
        return _step_esc_dispatch(stack, code)
    if state in (_ST_ESC_INT, _ST_CSI):
        return _step_csi_or_interm(stack, state, code)
    return _step_string_escape(stack, state, code)


def _strip_escape_sequences(text: str) -> tuple[str, bool]:
    """Linear-time stack FSM stripping 7-bit/8-bit, nested, padded, and split escapes."""
    out: list[str] = []
    stack: list[int] = []
    found = False
    for ch in text:
        code = ord(ch)
        while stack:
            if _advance_escape_stack(stack, code):
                break
        else:
            intro = _C1_INTRODUCERS.get(code)
            if intro is not None:
                found = True
                stack.append(intro)
            else:
                out.append(ch)
    return "".join(out), found


def _is_forbidden_codepoint(code: int, *, allow_multiline: bool) -> bool:
    if code in _BIDI_CODEPOINTS or 0x7F <= code <= 0x9F or 0xD800 <= code <= 0xDFFF:
        return True
    if code < 0x20:
        return not (allow_multiline and code in (0x09, 0x0A))
    return False


def _truncate_utf8_str(text: str, max_bytes: int) -> tuple[str, bool]:
    if len(text.encode(_UTF8)) <= max_bytes:
        return text, False
    lo = 0
    hi = len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(text[:mid].encode(_UTF8)) <= max_bytes:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo], True


def _scrub_multiline_text(text: str) -> tuple[str, bool]:
    """Strip ANSI/C1/control/bidi/NUL/bare-CR/surrogates while allowing \\n and \\t."""
    no_esc, found = _strip_escape_sequences(text)
    normalized = no_esc.replace("\r\n", "\n")
    out_chars: list[str] = []
    for ch in normalized:
        if _is_forbidden_codepoint(ord(ch), allow_multiline=True):
            found = True
            continue
        out_chars.append(ch)
    return "".join(out_chars), found


def _scrub_single_line_unbounded(text: str) -> str:
    no_esc, _ = _strip_escape_sequences(text)
    collapsed = (
        no_esc.replace("\r\n", " ")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace("\t", " ")
    )
    return "".join(
        "" if _is_forbidden_codepoint(ord(ch), allow_multiline=False) else ch
        for ch in collapsed
    )


def _decode_single_line_redacted(
    raw_blob: Any,
    raw_bytes: Any,
    non_text: Any,
    *,
    max_bytes: int = MAX_METADATA_TEXT_BYTES,
) -> tuple[str, bool, bool, bool]:
    """Return (clean_text, truncated, redaction_applied, malformed)."""
    orig_bytes = (
        cast(int, raw_bytes)
        if type(raw_bytes) is int and cast(int, raw_bytes) >= 0
        else 0
    )
    decoded, inspected_len, bad_utf8 = decode_bounded_blob(raw_blob, orig_bytes)
    sql_truncated = orig_bytes > inspected_len
    scrubbed = _scrub_single_line_unbounded(decoded)
    redacted_text, was_redacted = redact_sensitive_text(scrubbed)
    safe_text, tail_withheld = _withhold_truncated_tail(redacted_text, sql_truncated)
    clean, cut_in_py = _truncate_utf8_str(safe_text, max_bytes)
    truncated = cut_in_py or sql_truncated
    malformed = bool(non_text) or bad_utf8
    return clean, truncated, (was_redacted or tail_withheld), malformed


def _is_sensitive_key(full_key: str) -> bool:
    norm = _KEY_NORM_RE.sub("", full_key.lower())
    return any(tok in norm for tok in _SENSITIVE_KEY_TOKENS)


def _sanitize_json_value(value: Any, depth: int) -> tuple[Any, bool, bool]:
    """Return (clean_value, redaction_applied, malformed)."""
    if depth >= MAX_JSON_DEPTH:
        return None, False, True
    if value is None or isinstance(value, bool) or type(value) is int:
        return value, False, False
    if isinstance(value, float):
        return (value, False, False) if math.isfinite(value) else (0.0, False, True)
    if isinstance(value, str):
        scrubbed = _scrub_single_line_unbounded(value)
        redacted, did_redact = redact_sensitive_text(scrubbed)
        clean, _ = _truncate_utf8_str(redacted, MAX_METADATA_TEXT_BYTES)
        return clean, did_redact, False
    if isinstance(value, list):
        return _sanitize_json_list(value, depth)
    if isinstance(value, dict):
        return _sanitize_json_dict(value, depth)
    return None, False, True


def _sanitize_json_list(items: list[Any], depth: int) -> tuple[list[Any], bool, bool]:
    out: list[Any] = []
    redacted = False
    malformed = len(items) > MAX_METADATA_LIST_ITEMS
    for elem in items[:MAX_METADATA_LIST_ITEMS]:
        clean, did_red, bad = _sanitize_json_value(elem, depth + 1)
        redacted = redacted or did_red
        malformed = malformed or bad
        out.append(clean)
    return out, redacted, malformed


def _sorted_str_entries(
    mapping: Mapping[Any, Any],
) -> tuple[list[tuple[str, Any]], bool]:
    entries: list[tuple[str, Any]] = []
    malformed = False
    for raw_key, val in mapping.items():
        if isinstance(raw_key, str):
            entries.append((raw_key, val))
        else:
            malformed = True
    entries.sort(key=lambda kv: kv[0])
    return entries, malformed


def _sanitize_json_dict(
    mapping: Mapping[Any, Any], depth: int
) -> tuple[dict[str, Any], bool, bool]:
    out: dict[str, Any] = {}
    redacted = False
    str_entries, malformed = _sorted_str_entries(mapping)
    for raw_key, val in str_entries:
        full_key = _scrub_single_line_unbounded(raw_key).strip()
        if not full_key:
            malformed = True
            continue
        if _is_sensitive_key(full_key) or contains_credential_pattern(full_key):
            redacted = True
            continue
        trunc_key, _ = _truncate_utf8_str(full_key, MAX_METADATA_KEY_BYTES)
        if trunc_key in out:
            malformed = True
            continue
        if len(out) >= MAX_METADATA_KEYS:
            malformed = True
            break
        clean_val, did_red, bad = _sanitize_json_value(val, depth + 1)
        redacted = redacted or did_red
        malformed = malformed or bad
        out[trunc_key] = clean_val
    return out, redacted, malformed


def _parse_metadata_json(
    raw_blob: Any, raw_bytes: Any, malformed_flag: Any
) -> tuple[dict[str, Any], bool, bool]:
    """Return (metadata_dict, redaction_applied, malformed)."""
    if bool(malformed_flag) or raw_blob is None or not isinstance(raw_blob, (bytes, bytearray)):
        return {}, False, True
    if type(raw_bytes) is int and cast(int, raw_bytes) > SQL_MAX_CELL_BYTES:
        return {}, False, True
    try:
        parsed = json.loads(
            bytes(raw_blob).decode(_UTF8), parse_constant=reject_json_constant
        )
    except (ValueError, RecursionError):
        return {}, False, True
    if not isinstance(parsed, dict) or not is_json_tree_valid(parsed):
        return {}, False, True
    return _sanitize_json_dict(parsed, 0)


# --- Scalar & identifier validation helpers ---


def _safe_int(val: Any, malformed_flag: Any, *, default: int = 0) -> tuple[int, bool]:
    if bool(malformed_flag) or type(val) is not int:
        return default, True
    return cast(int, val), False


def _safe_bool_flag(
    val: Any, malformed_flag: Any, *, default: bool = False
) -> tuple[bool, bool]:
    if bool(malformed_flag) or type(val) is not int or val not in (0, 1):
        return default, True
    return cast(int, val) == 1, False


def _safe_finite_float(val: Any, malformed_flag: Any) -> tuple[float, bool]:
    if bool(malformed_flag) or val is None or isinstance(val, bool):
        return 0.0, True
    if not isinstance(val, (int, float)):
        return 0.0, True
    try:
        num = float(val)
    except OverflowError:
        return 0.0, True
    return (num, False) if math.isfinite(num) else (0.0, True)


def _safe_nullable_finite_float(
    val: Any, malformed_flag: Any
) -> tuple[float | None, bool]:
    if bool(malformed_flag):
        return None, True
    if val is None:
        return None, False
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None, True
    try:
        num = float(val)
    except OverflowError:
        return None, True
    return (num, False) if math.isfinite(num) else (None, True)


def _admit_primary_review_id(raw: Any) -> str:
    """Validate primary key review_id at admission; never echo raw value on failure."""
    if not isinstance(raw, str):
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    try:
        clean = validate_clean_opaque_token(raw, _COL_REVIEW_ID)
    except CoordValidationError as exc:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE) from exc
    if clean != raw or contains_credential_pattern(clean):
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    return clean


def _validate_required_non_pk_id(
    raw: Any, malformed_flag: Any, label: str
) -> tuple[str | None, bool, bool]:
    """Return (clean_id_or_None, storage_tampered, format_invalid).

    Raises fixed ``CoordPolicyError(ERR_INBOX_UNREADABLE)`` (zero echo) if a
    credential-shaped identifier is detected.
    """
    if bool(malformed_flag) or not isinstance(raw, str):
        return None, True, False
    if contains_credential_pattern(raw):
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    try:
        clean = validate_clean_opaque_token(raw, label)
    except CoordValidationError:
        return None, False, True
    if clean != raw:
        return None, False, True
    return clean, False, False


def _validate_nullable_target_addr(
    raw: Any, malformed_flag: Any
) -> tuple[str | None, bool, bool]:
    """Return (canonical_addr_or_None, redaction_applied, malformed)."""
    if bool(malformed_flag):
        return None, False, True
    if raw is None:
        return None, False, False
    if not isinstance(raw, str):
        return None, False, True
    if contains_credential_pattern(raw):
        return None, True, True
    try:
        parsed = parse_canonical_addr(raw)
    except AddressError:
        return None, False, True
    if parsed.canonical != raw:
        return None, False, True
    return parsed.canonical, False, False


def _validate_nullable_opaque_id(
    raw: Any, malformed_flag: Any, label: str
) -> tuple[str | None, bool, bool]:
    """Return (clean_token_or_None, redaction_applied, malformed)."""
    if bool(malformed_flag):
        return None, False, True
    if raw is None:
        return None, False, False
    if not isinstance(raw, str):
        return None, False, True
    if contains_credential_pattern(raw):
        return None, True, True
    try:
        clean = validate_clean_opaque_token(raw, label)
    except CoordValidationError:
        return None, False, True
    if clean != raw:
        return None, False, True
    return clean, False, False


def _validate_workflow_id(
    raw: Any, run_present: bool, malformed_flag: Any
) -> tuple[str | None, bool, bool]:
    """Return (workflow_id_or_None, redaction_applied, malformed)."""
    if not run_present:
        return None, False, False
    if bool(malformed_flag) or not isinstance(raw, str):
        return None, False, True
    if contains_credential_pattern(raw):
        return None, True, True
    try:
        full_id, _ns, _slug = parse_namespaced_id(raw, _COL_WORKFLOW_ID)
    except WorkflowSchemaError:
        return None, False, True
    return full_id, False, False


def _validate_closed_enum(
    raw: Any, malformed_flag: Any, allowed: frozenset[str]
) -> tuple[str, bool]:
    if bool(malformed_flag) or not isinstance(raw, str) or raw not in allowed:
        return BUCKET_MALFORMED, True
    return raw, False


# --- Caller, parameter, and pre/post session/authority fencing ---


def _validate_int_range(value: object, label: str, lo: int, hi: int) -> int:
    err_msg = f"{label} must be an int in {lo}..{hi}"
    if type(value) is not int:
        raise CoordValidationError(err_msg)
    num = cast(int, value)
    if num < lo or num > hi:
        raise CoordValidationError(err_msg)
    return num


def _validate_status_filter(
    statuses: Iterable[str] | None,
) -> tuple[str, ...] | None:
    if statuses is None:
        return None
    if isinstance(statuses, (str, bytes, bytearray)) or not isinstance(
        statuses, Iterable
    ):
        raise CoordValidationError("statuses must be an iterable of status strings")
    cleaned: set[str] = set()
    for idx, item in enumerate(statuses):
        if idx >= MAX_STATUS_FILTER_ITEMS:
            raise CoordValidationError("status_filter_too_many_entries")
        if not isinstance(item, str) or item not in VALID_STATUSES:
            raise CoordValidationError("unsupported_inbox_status_filter")
        cleaned.add(item)
    if not cleaned:
        raise CoordValidationError("statuses filter must not be empty")
    return tuple(sorted(cleaned))


def _require_operator_principal(caller: object) -> PrincipalCtx:
    if not isinstance(caller, PrincipalCtx):
        raise CoordValidationError("caller must be PrincipalCtx")
    if caller.role is not CoordRole.OPERATOR:
        raise CoordAuthError("operator_role_required")
    if (caller.sandbox_addr, caller.incarnation_id) != (None, None):
        raise CoordAuthError("operator_principal_must_not_bind_sandbox")
    return caller


def _validate_session_args(
    read_session_id: object, session_generation: object, *, has_validator: bool
) -> ReadSessionEcho | None:
    if read_session_id is None and session_generation is None:
        if has_validator:
            raise CoordAuthError("read_session_required")
        return None
    if read_session_id is None or session_generation is None:
        raise CoordValidationError("read_session_pair_required")
    clean_id = validate_clean_opaque_token(read_session_id, "read_session_id")
    if contains_credential_pattern(clean_id):
        raise CoordValidationError("invalid_read_session_id")
    gen_val = _validate_int_range(
        session_generation, "session_generation", 1, MAX_SQLITE_INT64
    )
    if not has_validator:
        raise CoordPolicyError("read_session_validator_unconfigured")
    return ReadSessionEcho(read_session_id=clean_id, session_generation=gen_val)


def _enforce_authority_fences(
    caller: PrincipalCtx,
    session_echo: ReadSessionEcho | None,
    session_validator: Callable[[PrincipalCtx, str, int], bool] | None,
    live_authority_checker: Callable[[PrincipalCtx], bool] | None,
) -> None:
    if session_validator is not None and session_echo is not None:
        try:
            ok = session_validator(
                caller, session_echo.read_session_id, session_echo.session_generation
            )
        except Exception as exc:
            raise RevokedError(_ERR_SESSION_RETIRED) from exc
        if ok is not True:
            raise RevokedError(_ERR_SESSION_RETIRED)
    if live_authority_checker is not None:
        try:
            ok = live_authority_checker(caller)
        except Exception as exc:
            raise RevokedError(_ERR_AUTHORITY_REVOKED) from exc
        if ok is not True:
            raise RevokedError(_ERR_AUTHORITY_REVOKED)


# --- 7-step review-pin verification & InboxItem / Artifact builders ---


def _is_primary_artifact_core_valid(
    art: Mapping[str, Any], expected_sha256: str
) -> bool:
    art_id = art[_COL_ARTIFACT_ID]
    if isinstance(art_id, str) and contains_credential_pattern(art_id):
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    if any(
        bool(art[col])
        for col in (
            _COL_ARTIFACT_ID_MALFORMED,
            _COL_BLOB_SHA256_MALFORMED,
            _COL_SIZE_BYTES_MALFORMED,
            _COL_MEDIA_TYPE_MALFORMED,
        )
    ):
        return False
    try:
        clean_aid = validate_clean_opaque_token(art_id, _COL_ARTIFACT_ID)
    except CoordValidationError:
        return False
    blob_sha = art[_COL_BLOB_SHA256]
    media_type = art[_COL_MEDIA_TYPE]
    return (
        clean_aid == art_id
        and is_valid_sha256_hex(blob_sha)
        and isinstance(media_type, str)
        and _MEDIA_TYPE_RE.fullmatch(media_type) is not None
        and not contains_credential_pattern(media_type)
        and hmac.compare_digest(blob_sha, expected_sha256)
    )


def _verify_primary_artifact_row(
    primary_rows: list[dict[str, Any]], expected_sha256: str
) -> tuple[str | None, bool]:
    """Return (anomaly_reason_or_None, primary_metadata_malformed)."""
    if any(bool(art[_COL_IS_PRIMARY_MALFORMED]) for art in primary_rows):
        return ANOMALY_TAMPERED_STORAGE, True
    if not primary_rows:
        return ANOMALY_ARTIFACT_MISSING, False
    if len(primary_rows) > 1:
        return ANOMALY_ARTIFACT_AMBIGUOUS, False
    art = primary_rows[0]
    if not _is_primary_artifact_core_valid(art, expected_sha256):
        return ANOMALY_ARTIFACT_MISMATCH, True
    _lbl, _ltrunc, _lred, bad_lbl = _decode_single_line_redacted(
        art[_COL_LABEL_BLOB], art[_COL_LABEL_BYTES], art[_COL_LABEL_NON_TEXT]
    )
    _cts, bad_cts = _safe_finite_float(
        art[_COL_CREATED_AT], art[_COL_CREATED_AT_MALFORMED]
    )
    return None, (bad_lbl or bad_cts)


def _recompute_pin_if_complete(
    pin_in: _PinEvalInputs,
) -> tuple[str, str, str, str, str] | None:
    if (
        pin_in.format_invalid
        or pin_in.run_id is None
        or pin_in.step_id is None
        or pin_in.checkpoint_seq is None
        or pin_in.artifact_sha256 is None
        or pin_in.policy_digest is None
        or pin_in.stored_pin is None
    ):
        return None
    recomputed = compute_review_pin_sha256(
        run_id=pin_in.run_id,
        step_id=pin_in.step_id,
        review_id=pin_in.review_id,
        checkpoint_seq=pin_in.checkpoint_seq,
        artifact_sha256=pin_in.artifact_sha256,
        policy_digest=pin_in.policy_digest,
    )
    return (
        recomputed,
        pin_in.stored_pin,
        pin_in.run_id,
        pin_in.policy_digest,
        pin_in.artifact_sha256,
    )


def _check_run_policy_corroboration(
    row: Mapping[str, Any], run_id: str, policy_digest: str
) -> tuple[str | None, bool]:
    if not bool(row[_COL_WORKFLOW_RUN_PRESENT]) or row[_COL_JOINED_RUN_ID] != run_id:
        return ANOMALY_RUN_MISSING, False
    run_pol = row["run_policy_digest"]
    bad_run_pol = bool(row["run_policy_digest_malformed"])
    if (
        bad_run_pol
        or not is_valid_sha256_hex(run_pol)
        or not hmac.compare_digest(run_pol, policy_digest)
    ):
        return ANOMALY_POLICY_MISMATCH, bad_run_pol
    return None, False


def _evaluate_review_pin(
    conn: sqlite3.Connection,
    row: Mapping[str, Any],
    pin_in: _PinEvalInputs,
    item_malformed: bool,
    deadline: float,
) -> tuple[InboxItemPinStatus, bool]:
    """Run Steps 1-7 fail-closed review-pin verification."""
    # Steps 1-2: storage class & format of 6 pin inputs + stored pin.
    if pin_in.storage_tampered:
        return _failed_pin(pin_in, None, ANOMALY_TAMPERED_STORAGE), True
    pin_tuple = _recompute_pin_if_complete(pin_in)
    if pin_tuple is None:
        return _failed_pin(pin_in, None, ANOMALY_MALFORMED_PIN_INPUT), True
    recomputed, stored_pin, run_id, policy_digest, artifact_sha256 = pin_tuple

    # Step 3: constant-time stored pin equality.
    if not hmac.compare_digest(stored_pin, recomputed):
        return _failed_pin(pin_in, recomputed, ANOMALY_PIN_MISMATCH), item_malformed

    # Steps 4-5: workflow_runs presence & policy_digest equality.
    run_anomaly, bad_run_pol = _check_run_policy_corroboration(
        row, run_id, policy_digest
    )
    if run_anomaly is not None:
        return (
            _failed_pin(pin_in, recomputed, run_anomaly),
            (item_malformed or bad_run_pol),
        )

    # Step 6: primary review_artifacts corroboration.
    primary_rows = select_primary_artifacts_for_pin(conn, pin_in.review_id, deadline)
    art_anomaly, bad_primary_meta = _verify_primary_artifact_row(
        primary_rows, artifact_sha256
    )
    combined_malformed = item_malformed or bad_primary_meta
    if art_anomaly is not None:
        return _failed_pin(pin_in, recomputed, art_anomaly), combined_malformed

    # Step 7: unconditional item-level malformed_metadata check.
    if combined_malformed:
        return _failed_pin(pin_in, recomputed, ANOMALY_MALFORMED_METADATA), True

    status_ok = row["status"] == STATUS_PENDING and not bool(row[_COL_STATUS_MALFORMED])
    return (
        InboxItemPinStatus(
            artifact_sha256=artifact_sha256,
            policy_digest=policy_digest,
            review_pin_sha256=recomputed,
            pin_verified=True,
            pin_anomaly=False,
            anomaly_reason=None,
            review_ready=status_ok,
        ),
        False,
    )


def _failed_pin(
    pin_in: _PinEvalInputs, recomputed: str | None, reason: str
) -> InboxItemPinStatus:
    return InboxItemPinStatus(
        artifact_sha256=pin_in.artifact_sha256,
        policy_digest=pin_in.policy_digest,
        review_pin_sha256=recomputed,
        pin_verified=False,
        pin_anomaly=True,
        anomaly_reason=reason,
        review_ready=False,
    )


def _extract_hex_digest(raw: Any) -> str | None:
    return raw if is_valid_sha256_hex(raw) else None


def _extract_pin_inputs(
    row: Mapping[str, Any], review_id: str
) -> _PinEvalInputs:
    run_id, bad_run_st, bad_run_fmt = _validate_required_non_pk_id(
        row["run_id"], row["run_id_malformed"], "run_id"
    )
    step_id, bad_step_st, bad_step_fmt = _validate_required_non_pk_id(
        row["step_id"], row["step_id_malformed"], "step_id"
    )
    bad_seq_st = bool(row["checkpoint_seq_malformed"]) or type(row[_COL_CHECKPOINT_SEQ]) is not int
    seq_val = None if bad_seq_st else int(row[_COL_CHECKPOINT_SEQ])

    bad_digest_st = any(
        bool(row[col])
        for col in (
            "artifact_sha256_malformed",
            "policy_digest_malformed",
            "review_pin_sha256_malformed",
        )
    )
    art_sha = _extract_hex_digest(row["artifact_sha256"])
    pol_sha = _extract_hex_digest(row["policy_digest"])
    stored_pin = _extract_hex_digest(row["review_pin_sha256"])

    storage_tampered = any((bad_run_st, bad_step_st, bad_seq_st, bad_digest_st))
    format_invalid = any(
        (bad_run_fmt, bad_step_fmt, art_sha is None, pol_sha is None, stored_pin is None)
    )
    return _PinEvalInputs(
        review_id=review_id,
        run_id=run_id,
        step_id=step_id,
        checkpoint_seq=seq_val,
        artifact_sha256=art_sha,
        policy_digest=pol_sha,
        stored_pin=stored_pin,
        storage_tampered=storage_tampered,
        format_invalid=format_invalid,
    )


def _build_presentation(
    row: Mapping[str, Any], extra_redacted: bool
) -> tuple[InboxItemPresentation, bool]:
    title, title_trunc, title_red, bad_title = _decode_single_line_redacted(
        row["title_blob"], row["title_bytes"], row["title_non_text"]
    )
    raw_orig = row["original_summary_bytes"]
    orig_bytes = (
        cast(int, raw_orig)
        if type(raw_orig) is int and cast(int, raw_orig) >= 0
        else 0
    )
    decoded_sum, inspected_len, bad_utf8 = decode_bounded_blob(
        row["summary_blob"], orig_bytes
    )
    suffix_uninspected = orig_bytes > inspected_len
    scrubbed_sum, has_ctrl = _scrub_multiline_text(decoded_sum)
    redacted_sum, sum_red = redact_sensitive_text(scrubbed_sum)
    safe_sum, tail_withheld = _withhold_truncated_tail(redacted_sum, suffix_uninspected)
    bad_summary = bool(row["summary_non_text"]) or bad_utf8
    pres = InboxItemPresentation(
        title=title,
        title_truncated=title_trunc,
        summary_text=safe_sum,
        text_truncated=suffix_uninspected,
        text_suffix_uninspected=suffix_uninspected,
        original_text_bytes=orig_bytes,
        has_control_or_bidi=(has_ctrl or bad_utf8),
        untrusted_content=True,
        redaction_applied=(title_red or sum_red or tail_withheld or extra_redacted),
    )
    return pres, (bad_title or bad_summary)


def _build_item_state(row: Mapping[str, Any]) -> tuple[InboxItemState, bool]:
    status_val, bad_status = _validate_closed_enum(
        row["status"], row[_COL_STATUS_MALFORMED], VALID_STATUSES
    )
    sev_val, bad_sev = _validate_closed_enum(
        row["severity"], row["severity_malformed"], VALID_SEVERITIES
    )
    src_val, bad_src = _validate_closed_enum(
        row["source_kind"], row["source_kind_malformed"], VALID_SOURCE_KINDS
    )
    pr_val, bad_pr = _safe_int(row["priority_rank"], row["priority_rank_malformed"])
    lane_paused, bad_lp = _safe_bool_flag(
        row["lane_paused"], row["lane_paused_malformed"]
    )
    req_rev, bad_req = _safe_bool_flag(
        row["requires_human_review"], row["requires_human_review_malformed"]
    )
    created_at, bad_cr = _safe_finite_float(
        row[_COL_CREATED_AT], row[_COL_CREATED_AT_MALFORMED]
    )
    updated_at, bad_up = _safe_finite_float(
        row["updated_at"], row["updated_at_malformed"]
    )
    expires_at, bad_ex = _safe_nullable_finite_float(
        row["expires_at"], row["expires_at_malformed"]
    )
    # Enforce prd_n3.md:54-59 exclusivity: only host_workflow_engine may pause a lane.
    lp_contradiction = lane_paused and (src_val != SOURCE_HOST_WORKFLOW_ENGINE)
    if lp_contradiction:
        lane_paused = False
    bad_state = any(
        (
            bad_status,
            bad_sev,
            bad_src,
            bad_pr,
            bad_lp,
            bad_req,
            bad_cr,
            bad_up,
            bad_ex,
            lp_contradiction,
        )
    )
    state = InboxItemState(
        status=status_val,
        severity=sev_val,
        priority_rank=pr_val,
        lane_paused=lane_paused,
        requires_human_review=req_rev,
        source_kind=src_val,
        created_at=created_at,
        updated_at=updated_at,
        expires_at=expires_at,
        malformed_metadata=bad_state,
    )
    return state, bad_state


def _build_verified_inbox_item(
    conn: sqlite3.Connection, row: Mapping[str, Any], *, deadline: float
) -> tuple[InboxItem, int, int]:
    """Return (InboxItem, effective_priority, effective_seq)."""
    check_deadline_ms(deadline)
    review_id = _admit_primary_review_id(row[_COL_REVIEW_ID])
    match_count = row["workflow_run_match_count"]
    if type(match_count) is not int or cast(int, match_count) > 1:
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    pin_in = _extract_pin_inputs(row, review_id)
    item_rev, bad_rev = _safe_int(
        row["item_revision"], row["item_revision_malformed"], default=0
    )
    t_addr, red_addr, bad_addr = _validate_nullable_target_addr(
        row["target_addr"], row["target_addr_malformed"]
    )
    t_inc, red_inc, bad_inc = _validate_nullable_opaque_id(
        row[_COL_TARGET_INC_ID],
        row["target_incarnation_id_malformed"],
        _COL_TARGET_INC_ID,
    )
    run_present = (
        bool(row[_COL_WORKFLOW_RUN_PRESENT])
        and pin_in.run_id is not None
        and row[_COL_JOINED_RUN_ID] == pin_in.run_id
    )
    wf_id, red_wf, bad_wf = _validate_workflow_id(
        row[_COL_WORKFLOW_ID],
        run_present,
        row["workflow_id_malformed"],
    )
    metadata, red_meta, bad_meta = _parse_metadata_json(
        row["metadata_blob"], row["metadata_bytes"], row["metadata_malformed"]
    )
    extra_redacted = red_addr or red_inc or red_wf or red_meta
    pres, bad_pres = _build_presentation(row, extra_redacted)
    state, bad_state = _build_item_state(row)

    item_malformed = any(
        (
            pin_in.storage_tampered,
            pin_in.format_invalid,
            bad_rev,
            bad_addr,
            bad_inc,
            bad_wf,
            bad_meta,
            bad_pres,
            bad_state,
        )
    )
    pin_status, final_malformed = _evaluate_review_pin(
        conn, row, pin_in, item_malformed, deadline
    )
    final_state = cast(
        InboxItemState,
        replace(state, malformed_metadata=final_malformed),
    )
    identity = InboxItemIdentity(
        review_id=review_id,
        run_id=pin_in.run_id,
        workflow_id=wf_id,
        step_id=pin_in.step_id,
        checkpoint_seq=pin_in.checkpoint_seq if pin_in.checkpoint_seq is not None else 0,
        item_revision=item_rev,
        target_addr=t_addr,
        target_incarnation_id=t_inc,
    )
    eff_pr = int(row["effective_priority"])
    eff_seq = int(row["effective_seq"])
    item = InboxItem(
        identity=identity,
        state=final_state,
        presentation=pres,
        pin=pin_status,
        metadata=metadata,
        metadata_truncated=False,
    )
    return item, eff_pr, eff_seq


def _extract_artifact_id(row: Mapping[str, Any]) -> tuple[str | None, bool]:
    raw_aid = row[_COL_ARTIFACT_ID]
    if isinstance(raw_aid, str) and contains_credential_pattern(raw_aid):
        raise CoordPolicyError(ERR_INBOX_UNREADABLE)
    if bool(row[_COL_ARTIFACT_ID_MALFORMED]) or not isinstance(raw_aid, str):
        return None, True
    try:
        cand = validate_clean_opaque_token(raw_aid, _COL_ARTIFACT_ID)
    except CoordValidationError:
        return None, True
    return (cand, False) if cand == raw_aid else (None, True)


def _extract_media_type(row: Mapping[str, Any]) -> tuple[str, bool, bool]:
    raw_mt = row[_COL_MEDIA_TYPE]
    mt_has_cred = isinstance(raw_mt, str) and contains_credential_pattern(raw_mt)
    bad_mt = (
        bool(row[_COL_MEDIA_TYPE_MALFORMED])
        or not isinstance(raw_mt, str)
        or _MEDIA_TYPE_RE.fullmatch(raw_mt) is None
        or mt_has_cred
    )
    return (_FALLBACK_MEDIA_TYPE if bad_mt else raw_mt), mt_has_cred, bad_mt


def _row_to_artifact_ref(row: Mapping[str, Any]) -> InboxArtifactRef:
    clean_aid, bad_aid = _extract_artifact_id(row)
    raw_sha = row[_COL_BLOB_SHA256]
    bad_sha = bool(row[_COL_BLOB_SHA256_MALFORMED]) or not is_valid_sha256_hex(raw_sha)
    clean_sha = None if bad_sha else str(raw_sha)

    size_bytes, bad_size = _safe_int(
        row["size_bytes"], row[_COL_SIZE_BYTES_MALFORMED], default=0
    )
    clean_mt, red_mt, bad_mt = _extract_media_type(row)

    label, lbl_trunc, lbl_red, bad_lbl = _decode_single_line_redacted(
        row[_COL_LABEL_BLOB], row[_COL_LABEL_BYTES], row[_COL_LABEL_NON_TEXT]
    )
    is_primary, bad_prim = _safe_bool_flag(
        row[_COL_IS_PRIMARY], row[_COL_IS_PRIMARY_MALFORMED]
    )
    created_at, bad_cr = _safe_finite_float(
        row[_COL_CREATED_AT], row[_COL_CREATED_AT_MALFORMED]
    )
    malformed = any((bad_aid, bad_sha, bad_size, bad_mt, bad_lbl, bad_prim, bad_cr))
    return InboxArtifactRef(
        artifact_id=clean_aid,
        blob_sha256=clean_sha,
        size_bytes=size_bytes,
        media_type=clean_mt,
        label=label,
        label_truncated=lbl_trunc,
        is_primary=is_primary,
        created_at=created_at,
        redaction_applied=(lbl_red or red_mt),
        malformed_metadata=malformed,
    )


# --- Hard UTF-8 JSON byte-budget packing helpers ---


def _assert_serialized_within_budget(
    obj: Any, max_bytes: int, deadline: float, *, err_code: str = _ERR_BUDGET_ENVELOPE
) -> None:
    check_deadline_ms(deadline)
    if len(serialize_inbox_bytes(obj)) > max_bytes:
        raise CoordValidationError(err_code)
    check_deadline_ms(deadline)


def _with_summary_prefix(item: InboxItem, full_summary: str, length: int) -> InboxItem:
    new_pres = cast(
        InboxItemPresentation,
        replace(
            item.presentation,
            summary_text=full_summary[:length],
            text_truncated=(item.presentation.text_truncated or length < len(full_summary)),
        ),
    )
    return cast(InboxItem, replace(item, presentation=new_pres))


def _binary_search_summary(
    item: InboxItem,
    original_summary: str,
    make_envelope: Callable[[InboxItem], Any],
    max_bytes: int,
    deadline: float,
) -> InboxItem | None:
    lo = 0
    hi = len(original_summary)
    best: InboxItem | None = None
    while lo <= hi:
        check_deadline_ms(deadline)
        mid = (lo + hi) // 2
        cand = _with_summary_prefix(item, original_summary, mid)
        if len(serialize_inbox_bytes(make_envelope(cand))) <= max_bytes:
            best = cand
            lo = mid + 1
        else:
            hi = mid - 1
    check_deadline_ms(deadline)
    return best


def _shrink_item_with_metadata_fallback(
    item: InboxItem,
    make_envelope: Callable[[InboxItem], Any],
    max_bytes: int,
    deadline: float,
) -> InboxItem | None:
    original_summary = item.presentation.summary_text
    fitted = _binary_search_summary(
        item, original_summary, make_envelope, max_bytes, deadline
    )
    if fitted is not None:
        return fitted
    if not item.metadata:
        return None
    dropped = cast(
        InboxItem, replace(item, metadata={}, metadata_truncated=True)
    )
    return _binary_search_summary(
        dropped, original_summary, make_envelope, max_bytes, deadline
    )


def _make_list_page(
    ctx: _ListPackCtx,
    items: tuple[InboxItem, ...],
    *,
    has_more: bool,
    next_cursor: str | None,
) -> InboxPage:
    return InboxPage(
        schema_version=INBOX_SCHEMA_VERSION,
        snapshot_seq=ctx.snapshot_seq,
        items=items,
        has_more=has_more,
        next_cursor=next_cursor,
        read_session=ctx.session_echo,
    )


def _check_empty_list_envelope(ctx: _ListPackCtx) -> None:
    worst_cursor = encode_inbox_list_cursor(
        scope_hash=ctx.scope_hash,
        snapshot_seq=ctx.snapshot_seq,
        priority_rank=MAX_PRIORITY_RANK,
        checkpoint_seq=MAX_SQLITE_INT64,
        review_id="r" * 96,
    )
    probe = _make_list_page(ctx, (), has_more=True, next_cursor=worst_cursor)
    _assert_serialized_within_budget(probe, ctx.max_bytes, ctx.deadline)


def _pack_bounded_inbox_page(
    conn: sqlite3.Connection,
    rows: list[dict[str, Any]],
    ctx: _ListPackCtx,
) -> InboxPage:
    _check_empty_list_envelope(ctx)
    if not rows:
        page = _make_list_page(ctx, (), has_more=False, next_cursor=None)
        _assert_serialized_within_budget(page, ctx.max_bytes, ctx.deadline)
        return page

    admitted: tuple[InboxItem, ...] = ()
    seen_review_ids: set[str] = set()
    last_cursor: str | None = None
    max_items = min(ctx.page_limit, len(rows))
    for idx in range(max_items):
        check_deadline_ms(ctx.deadline)
        item, eff_pr, eff_seq = _build_verified_inbox_item(
            conn, rows[idx], deadline=ctx.deadline
        )
        if item.review_id in seen_review_ids:
            raise CoordPolicyError(ERR_INBOX_UNREADABLE)
        seen_review_ids.add(item.review_id)
        remaining_exists = (idx + 1) < len(rows)
        item_cursor = encode_inbox_list_cursor(
            scope_hash=ctx.scope_hash,
            snapshot_seq=ctx.snapshot_seq,
            priority_rank=eff_pr,
            checkpoint_seq=eff_seq,
            review_id=item.review_id,
        )
        cand_cursor = item_cursor if remaining_exists else None
        cand_page = _make_list_page(
            ctx,
            (*admitted, item),
            has_more=remaining_exists,
            next_cursor=cand_cursor,
        )
        if len(serialize_inbox_bytes(cand_page)) <= ctx.max_bytes:
            admitted = (*admitted, item)
            last_cursor = item_cursor
            continue
        if idx == 0:
            fitted = _shrink_item_with_metadata_fallback(
                item,
                lambda it, rem=remaining_exists, cur=cand_cursor: _make_list_page(
                    ctx, (it,), has_more=rem, next_cursor=cur
                ),
                ctx.max_bytes,
                ctx.deadline,
            )
            if fitted is None:
                raise CoordValidationError(_ERR_BUDGET_ITEM)
            page = _make_list_page(
                ctx, (fitted,), has_more=remaining_exists, next_cursor=cand_cursor
            )
            _assert_serialized_within_budget(
                page, ctx.max_bytes, ctx.deadline, err_code=_ERR_BUDGET_ITEM
            )
            return page
        # Subsequent item overflowed: finalize previous admitted items with has_more=True.
        page = _make_list_page(ctx, admitted, has_more=True, next_cursor=last_cursor)
        _assert_serialized_within_budget(page, ctx.max_bytes, ctx.deadline)
        return page

    has_more = len(rows) > ctx.page_limit
    page = _make_list_page(
        ctx,
        admitted,
        has_more=has_more,
        next_cursor=last_cursor if has_more else None,
    )
    _assert_serialized_within_budget(page, ctx.max_bytes, ctx.deadline)
    return page


def _make_detail_snapshot(
    ctx: _DetailPackCtx,
    item: InboxItem,
    artifacts: tuple[InboxArtifactRef, ...],
    *,
    artifacts_truncated: bool,
    artifacts_malformed: bool,
) -> InboxItemDetailSnapshot:
    return InboxItemDetailSnapshot(
        schema_version=INBOX_SCHEMA_VERSION,
        snapshot_seq=ctx.snapshot_seq,
        item=item,
        artifact_refs=artifacts,
        artifact_refs_truncated=artifacts_truncated,
        artifacts_malformed=artifacts_malformed,
        read_session=ctx.session_echo,
    )


def _fit_inbox_item_detail(
    item: InboxItem,
    artifacts: tuple[InboxArtifactRef, ...],
    *,
    artifacts_truncated: bool,
    artifacts_malformed: bool,
    ctx: _DetailPackCtx,
) -> InboxItemDetailSnapshot:
    direct = _make_detail_snapshot(
        ctx,
        item,
        artifacts,
        artifacts_truncated=artifacts_truncated,
        artifacts_malformed=artifacts_malformed,
    )
    check_deadline_ms(ctx.deadline)
    if len(serialize_inbox_bytes(direct)) <= ctx.max_bytes:
        check_deadline_ms(ctx.deadline)
        return direct

    fitted_item = _shrink_item_with_metadata_fallback(
        item,
        lambda it: _make_detail_snapshot(
            ctx,
            it,
            artifacts,
            artifacts_truncated=artifacts_truncated,
            artifacts_malformed=artifacts_malformed,
        ),
        ctx.max_bytes,
        ctx.deadline,
    )
    if fitted_item is not None:
        snap = _make_detail_snapshot(
            ctx,
            fitted_item,
            artifacts,
            artifacts_truncated=artifacts_truncated,
            artifacts_malformed=artifacts_malformed,
        )
        _assert_serialized_within_budget(snap, ctx.max_bytes, ctx.deadline)
        return snap

    # Step 3: trim artifact_refs via binary search, then re-fit original summary.
    minimal_item = cast(
        InboxItem,
        replace(
            _with_summary_prefix(item, item.presentation.summary_text, 0),
            metadata={},
            metadata_truncated=(item.metadata_truncated or bool(item.metadata)),
        ),
    )
    best_count = _binary_search_artifact_count(
        minimal_item,
        artifacts,
        artifacts_truncated=artifacts_truncated,
        artifacts_malformed=artifacts_malformed,
        ctx=ctx,
    )
    if best_count is None:
        raise CoordValidationError(_ERR_BUDGET_ENVELOPE)

    trimmed_arts = artifacts[:best_count]
    trimmed_trunc = artifacts_truncated or (best_count < len(artifacts))
    dropped_meta_item = cast(
        InboxItem,
        replace(
            item,
            metadata={},
            metadata_truncated=(item.metadata_truncated or bool(item.metadata)),
        ),
    )
    refit = _binary_search_summary(
        dropped_meta_item,
        item.presentation.summary_text,
        lambda it: _make_detail_snapshot(
            ctx,
            it,
            trimmed_arts,
            artifacts_truncated=trimmed_trunc,
            artifacts_malformed=artifacts_malformed,
        ),
        ctx.max_bytes,
        ctx.deadline,
    )
    final_item = refit if refit is not None else minimal_item
    snap = _make_detail_snapshot(
        ctx,
        final_item,
        trimmed_arts,
        artifacts_truncated=trimmed_trunc,
        artifacts_malformed=artifacts_malformed,
    )
    _assert_serialized_within_budget(snap, ctx.max_bytes, ctx.deadline)
    return snap


def _binary_search_artifact_count(
    minimal_item: InboxItem,
    artifacts: tuple[InboxArtifactRef, ...],
    *,
    artifacts_truncated: bool,
    artifacts_malformed: bool,
    ctx: _DetailPackCtx,
) -> int | None:
    lo = 0
    hi = len(artifacts)
    best: int | None = None
    while lo <= hi:
        check_deadline_ms(ctx.deadline)
        mid = (lo + hi) // 2
        cand = _make_detail_snapshot(
            ctx,
            minimal_item,
            artifacts[:mid],
            artifacts_truncated=(artifacts_truncated or mid < len(artifacts)),
            artifacts_malformed=artifacts_malformed,
        )
        if len(serialize_inbox_bytes(cand)) <= ctx.max_bytes:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    check_deadline_ms(ctx.deadline)
    return best


# --- Public operator-only read-only Human Inbox service ---


class ReadOnlyInboxService:
    """Operator-only, strictly read-only Tier-B Human Inbox projection service.

    Exposes ONLY ``list_inbox_items``, ``get_inbox_item``, and
    ``get_inbox_summary`` — zero mutation, approval, grant, or awakeable APIs.
    """

    def __init__(
        self,
        state_dir: Path | str,
        *,
        sandbox_root: Path | str | None = None,
        session_validator: Callable[[PrincipalCtx, str, int], bool] | None = None,
        live_authority_checker: Callable[[PrincipalCtx], bool] | None = None,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._sandbox_root = Path(sandbox_root) if sandbox_root is not None else None
        self._session_validator = session_validator
        self._live_authority_checker = live_authority_checker

    def _admit_read_call(
        self,
        op: PrincipalCtx,
        *,
        max_response_bytes: int,
        max_read_ms: int,
        read_session_id: str | None,
        session_generation: int | None,
    ) -> _AdmittedReadCtx:
        max_bytes = _validate_int_range(
            max_response_bytes,
            _PARAM_MAX_RESPONSE_BYTES,
            MIN_RESPONSE_BYTES,
            MAX_RESPONSE_BYTES,
        )
        read_ms = _validate_int_range(
            max_read_ms, _PARAM_MAX_READ_MS, MIN_READ_MS, MAX_READ_MS
        )
        session_echo = _validate_session_args(
            read_session_id,
            session_generation,
            has_validator=(self._session_validator is not None),
        )
        _enforce_authority_fences(
            op, session_echo, self._session_validator, self._live_authority_checker
        )
        _trusted_dir, db_path = verify_state_dir_and_db_readonly(
            self._state_dir, self._sandbox_root
        )
        return _AdmittedReadCtx(
            caller=op,
            max_bytes=max_bytes,
            deadline=time.monotonic() + (read_ms / 1000.0),
            session_echo=session_echo,
            db_path=db_path,
        )

    def _run_fenced_snapshot(
        self,
        ctx: _AdmittedReadCtx,
        body: Callable[[sqlite3.Connection, int], _T],
    ) -> _T:
        """Execute snapshot read, close DB, recheck authority, then release result or error."""
        result: _T | None = None
        deferred_exc: Exception | None = None
        try:
            with open_readonly_inbox_snapshot(
                ctx.db_path, deadline=ctx.deadline
            ) as conn:
                snapshot_seq = read_inbox_seq_counter(conn, ctx.deadline)
                result = body(conn, snapshot_seq)
        except (CoordValidationError, CoordPolicyError) as exc:
            deferred_exc = exc

        _enforce_authority_fences(
            ctx.caller,
            ctx.session_echo,
            self._session_validator,
            self._live_authority_checker,
        )
        if deferred_exc is not None:
            raise deferred_exc
        return cast(_T, result)

    def list_inbox_items(
        self,
        caller: object,
        *,
        statuses: Iterable[str] | None = None,
        run_id: str | None = None,
        after_cursor: str | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_read_ms: int = DEFAULT_MAX_READ_MS,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> InboxPage:
        """Return a bounded, verified, redacted page of Tier-B inbox items."""
        op = _require_operator_principal(caller)
        clean_statuses = _validate_status_filter(statuses)
        clean_run_id = (
            validate_clean_opaque_token(run_id, "run_id") if run_id is not None else None
        )
        page_limit = _validate_int_range(limit, "limit", 1, MAX_PAGE_LIMIT)
        scope_hash = compute_scope_hash(
            OP_INBOX_LIST, statuses=clean_statuses, run_id=clean_run_id
        )
        parsed_cursor = decode_inbox_list_cursor(
            after_cursor, expected_scope_hash=scope_hash
        )
        ctx = self._admit_read_call(
            op,
            max_response_bytes=max_response_bytes,
            max_read_ms=max_read_ms,
            read_session_id=read_session_id,
            session_generation=session_generation,
        )

        def _query(conn: sqlite3.Connection, snapshot_seq: int) -> InboxPage:
            if parsed_cursor is not None and snapshot_seq != parsed_cursor.snapshot_seq:
                raise CoordValidationError(ERR_CURSOR_SNAPSHOT_CHANGED)
            rows = select_review_items_page(
                conn,
                statuses=clean_statuses,
                run_id=clean_run_id,
                cursor=parsed_cursor,
                limit=page_limit + 1,
                deadline=ctx.deadline,
            )
            pack_ctx = _ListPackCtx(
                snapshot_seq=snapshot_seq,
                page_limit=page_limit,
                scope_hash=scope_hash,
                max_bytes=ctx.max_bytes,
                session_echo=ctx.session_echo,
                deadline=ctx.deadline,
            )
            return _pack_bounded_inbox_page(conn, rows, pack_ctx)

        return self._run_fenced_snapshot(ctx, _query)

    def get_inbox_item(
        self,
        caller: object,
        *,
        review_id: str,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_read_ms: int = DEFAULT_MAX_READ_MS,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> InboxItemDetailSnapshot:
        """Return a bounded detailed single-item snapshot with verified pin and artifacts."""
        op = _require_operator_principal(caller)
        clean_review_id = validate_clean_opaque_token(review_id, _COL_REVIEW_ID)
        ctx = self._admit_read_call(
            op,
            max_response_bytes=max_response_bytes,
            max_read_ms=max_read_ms,
            read_session_id=read_session_id,
            session_generation=session_generation,
        )

        def _query(
            conn: sqlite3.Connection, snapshot_seq: int
        ) -> InboxItemDetailSnapshot:
            row = select_single_review_item(conn, clean_review_id, ctx.deadline)
            if row is None:
                raise CoordPolicyError("review_item_not_found")
            item, _eff_pr, _eff_seq = _build_verified_inbox_item(
                conn, row, deadline=ctx.deadline
            )
            raw_arts = select_item_artifacts(
                conn,
                clean_review_id,
                limit=MAX_ARTIFACTS_PER_ITEM + 1,
                deadline=ctx.deadline,
            )
            artifacts_truncated = len(raw_arts) > MAX_ARTIFACTS_PER_ITEM
            artifacts = tuple(
                _row_to_artifact_ref(art) for art in raw_arts[:MAX_ARTIFACTS_PER_ITEM]
            )
            artifacts_malformed = any(art.malformed_metadata for art in artifacts)
            detail_ctx = _DetailPackCtx(
                snapshot_seq=snapshot_seq,
                max_bytes=ctx.max_bytes,
                session_echo=ctx.session_echo,
                deadline=ctx.deadline,
            )
            return _fit_inbox_item_detail(
                item,
                artifacts,
                artifacts_truncated=artifacts_truncated,
                artifacts_malformed=artifacts_malformed,
                ctx=detail_ctx,
            )

        return self._run_fenced_snapshot(ctx, _query)

    def get_inbox_summary(
        self,
        caller: object,
        *,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_read_ms: int = DEFAULT_MAX_READ_MS,
        read_session_id: str | None = None,
        session_generation: int | None = None,
    ) -> InboxSummarySnapshot:
        """Return bounded O(1)-row SQL aggregate counts by status, severity, and health."""
        op = _require_operator_principal(caller)
        ctx = self._admit_read_call(
            op,
            max_response_bytes=max_response_bytes,
            max_read_ms=max_read_ms,
            read_session_id=read_session_id,
            session_generation=session_generation,
        )

        def _query(conn: sqlite3.Connection, snapshot_seq: int) -> InboxSummarySnapshot:
            status_counts = select_status_aggregate_counts(conn, ctx.deadline)
            sev_counts, pending_by_sev = select_severity_aggregate_counts(
                conn, ctx.deadline
            )
            totals = select_structural_summary_totals(conn, ctx.deadline)
            snapshot = InboxSummarySnapshot(
                schema_version=INBOX_SCHEMA_VERSION,
                snapshot_seq=snapshot_seq,
                total_items=totals["total_items"],
                counts_by_status=status_counts,
                counts_by_severity=sev_counts,
                pending_by_severity=pending_by_sev,
                paused_lanes_count=totals["paused_lanes_count"],
                requires_human_review_count=totals["requires_human_review_count"],
                malformed_rows_count=totals["malformed_rows_count"],
                pin_verification_scope=PIN_VERIFICATION_SCOPE_ITEM_ONLY,
                read_session=ctx.session_echo,
            )
            _assert_serialized_within_budget(snapshot, ctx.max_bytes, ctx.deadline)
            return snapshot

        return self._run_fenced_snapshot(ctx, _query)


HumanInboxReadProjection = ReadOnlyInboxService
