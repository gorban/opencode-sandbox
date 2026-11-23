"""Bounded cell decoding, JSON sanitization, and provenance re-verification.

Internal module supporting ``oc_projection.py`` and ``oc_projection_db.py``.
Handles UTF-8 BLOB prefix decoding without SQLite NUL truncation, control/bidi
detection, depth-capped JSON decoding, and per-event receipt provenance checks.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import json
import math
from pathlib import Path
import sqlite3
import sys
from typing import Any

_PROJECTION_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _PROJECTION_DIR.parent
_SPIKE_L_DIR = _SPIKE_M_DIR.parent / "l"
for _import_dir in (str(_PROJECTION_DIR), str(_SPIKE_M_DIR), str(_SPIKE_L_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_address import (  # noqa: E402
    _BIDI_CODEPOINTS,
    check_no_control_or_bidi,
    has_forbidden_control_or_bidi,
)
from oc_coord_contract import (  # noqa: E402
    ArtifactRef,
    CoordPolicyError,
    CoordValidationError,
    ProvenanceBadge,
    SubtreeBudget,
    TrustClass,
    sha256_canonical_body,
)
from oc_projection_contract import (  # noqa: E402
    MAX_AMBIGUITY_CANDIDATES,
    MAX_HASH_TEXT_BYTES,
    MAX_JSON_DEPTH,
    MAX_METADATA_TEXT_BYTES,
    SQL_MAX_CELL_BYTES,
    ProjectedArtifactRef,
    ProjectedSubtreeBudget,
)
from oc_registry import _TRUST_CLASS_TO_BADGE, _UNTRUSTED_DETAIL_KEYS  # noqa: E402

ANOMALY_NON_USER_BADGE = "non_user_event_has_badge"
ANOMALY_INVALID_BADGE = "invalid_or_missing_badge"
ANOMALY_TUI_UNVERIFIABLE = "tui_unverifiable_without_event_link"
ANOMALY_UNBACKED = "unbacked_host_badge"
ANOMALY_TRUST_MISMATCH = "trust_class_mismatch"
ANOMALY_ENVELOPE_MISMATCH = "receipt_envelope_mismatch"
ANOMALY_BODY_HASH_MISMATCH = "receipt_body_hash_mismatch"
ANOMALY_AMBIGUOUS_RECEIPT = "ambiguous_receipt_match"

_BADGE_UNVERIFIED = ProvenanceBadge.SANDBOX_LOCAL_UNVERIFIED.value
_BADGE_TUI = ProvenanceBadge.TUI_INPUT.value
_VALID_BADGES = frozenset(b.value for b in ProvenanceBadge)
_HOST_BADGES = frozenset(
    {
        ProvenanceBadge.OPERATOR.value,
        ProvenanceBadge.ORCHESTRATOR.value,
        ProvenanceBadge.PEER.value,
    }
)
_TRUSTED_BADGES = frozenset(
    {ProvenanceBadge.OPERATOR.value, ProvenanceBadge.ORCHESTRATOR.value}
)
_BADGE_AUTHORITY_RANK = {
    ProvenanceBadge.OPERATOR.value: 3,
    ProvenanceBadge.ORCHESTRATOR.value: 2,
    ProvenanceBadge.PEER.value: 1,
}
_COL_BODY_SHA256 = "body_sha256"
_COL_TRUST_CLASS = "trust_class"
_COL_SRC_ACTOR = "src_actor"
_UNTRUSTED_DETAIL_KEYS_LOWER = frozenset(k.lower() for k in _UNTRUSTED_DETAIL_KEYS)


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"Forbidden JSON constant: {token}")


def _trim_incomplete_utf8_tail(data: bytes) -> bytes:
    """Drop a single trailing incomplete UTF-8 sequence split by a byte prefix slice."""
    n = len(data)
    if n == 0:
        return data
    cont_count = 0
    idx = n - 1
    while idx >= 0 and cont_count < 3 and (data[idx] & 0xC0) == 0x80:
        cont_count += 1
        idx -= 1
    if idx < 0:
        return data
    lead = data[idx]
    if 0xC2 <= lead <= 0xDF:
        expected = 2
    elif 0xE0 <= lead <= 0xEF:
        expected = 3
    elif 0xF0 <= lead <= 0xF4:
        expected = 4
    else:
        return data
    if (n - idx) < expected:
        return data[:idx]
    return data


def decode_bounded_blob(
    raw_blob: bytes | None, original_bytes: int
) -> tuple[str, int, bool]:
    """Decode bounded SQL BLOB prefix at a UTF-8 boundary, preserving NUL for inspection."""
    if raw_blob is None:
        return "", 0, True
    if not isinstance(raw_blob, (bytes, bytearray)):
        raw_blob = str(raw_blob).encode("utf-8", errors="replace")
    raw = bytes(raw_blob)
    trimmed = _trim_incomplete_utf8_tail(raw) if original_bytes > len(raw) else raw
    try:
        return trimmed.decode("utf-8"), len(trimmed), False
    except UnicodeDecodeError:
        return trimmed.decode("utf-8", errors="replace"), len(trimmed), True


def _is_forbidden_codepoint(code: int, *, allow_multiline: bool) -> bool:
    if code in _BIDI_CODEPOINTS or 0x7F <= code <= 0x9F or 0xD800 <= code <= 0xDFFF:
        return True
    if code < 0x20:
        return not (allow_multiline and code in (0x09, 0x0A))
    return False


def has_multiline_control_or_bidi(text: str) -> bool:
    """Return True if text has bare CR, NUL, non-NL/TAB C0, DEL, C1, surrogate, or bidi."""
    idx = 0
    length = len(text)
    while idx < length:
        ch = text[idx]
        if ch == "\r":
            if idx + 1 < length and text[idx + 1] == "\n":
                idx += 2
                continue
            return True
        if _is_forbidden_codepoint(ord(ch), allow_multiline=True):
            return True
        idx += 1
    return False


def truncate_utf8_str(text: str, max_bytes: int) -> tuple[str, bool]:
    if len(text.encode("utf-8")) <= max_bytes:
        return text, False
    lo = 0
    hi = len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(text[:mid].encode("utf-8")) <= max_bytes:
            lo = mid
        else:
            hi = mid - 1
    return text[:lo], True


def scrub_single_line_str(
    text: str, *, max_bytes: int = MAX_METADATA_TEXT_BYTES
) -> tuple[str, bool]:
    collapsed = (
        text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    )
    cleaned = "".join(
        "" if _is_forbidden_codepoint(ord(ch), allow_multiline=False) else ch
        for ch in collapsed
    )
    return truncate_utf8_str(cleaned, max_bytes)


def decode_single_line_cell(
    raw_blob: Any,
    raw_bytes: Any,
    non_text: Any,
    *,
    max_bytes: int = MAX_METADATA_TEXT_BYTES,
) -> tuple[str, bool, bool]:
    orig_bytes = raw_bytes if type(raw_bytes) is int and raw_bytes >= 0 else 0
    decoded, inspected_len, bad_utf8 = decode_bounded_blob(raw_blob, orig_bytes)
    clean, cut_in_py = scrub_single_line_str(decoded, max_bytes=max_bytes)
    truncated = cut_in_py or (orig_bytes > inspected_len)
    malformed = bool(non_text) or bad_utf8
    return clean, truncated, malformed


def safe_int(val: Any, malformed_flag: Any, *, default: int = 0) -> tuple[int, bool]:
    if bool(malformed_flag) or type(val) is not int:
        return default, True
    return val, False


def safe_bool_flag(
    val: Any, malformed_flag: Any, *, default: bool = False
) -> tuple[bool, bool]:
    if bool(malformed_flag) or type(val) is not int or val not in (0, 1):
        return default, True
    return val == 1, False


def safe_finite_float(val: Any, malformed_flag: Any) -> tuple[float, bool]:
    if bool(malformed_flag) or val is None or isinstance(val, bool):
        return 0.0, True
    if not isinstance(val, (int, float)):
        return 0.0, True
    num = float(val)
    if not math.isfinite(num):
        return 0.0, True
    return num, False


def _check_json_depth(value: Any, depth: int = 0) -> bool:
    if depth > MAX_JSON_DEPTH:
        return False
    if isinstance(value, dict):
        return all(_check_json_depth(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return all(_check_json_depth(v, depth + 1) for v in value)
    return True


def _parse_json_cell(raw_blob: Any, raw_bytes: Any) -> tuple[Any, bool]:
    if raw_blob is None or not isinstance(raw_blob, (bytes, bytearray)):
        return None, True
    if type(raw_bytes) is int and raw_bytes > SQL_MAX_CELL_BYTES:
        return None, True
    try:
        parsed = json.loads(
            bytes(raw_blob).decode("utf-8"), parse_constant=_reject_json_constant
        )
    except (ValueError, RecursionError):
        return None, True
    if not _check_json_depth(parsed):
        return None, True
    return parsed, False


def _sanitize_json_value(value: Any, depth: int = 0) -> tuple[Any, bool]:
    if depth >= MAX_JSON_DEPTH:
        return None, True
    if value is None or isinstance(value, bool) or type(value) is int:
        return value, False
    if isinstance(value, float):
        return (value, False) if math.isfinite(value) else (0.0, True)
    if isinstance(value, str):
        clean, _ = scrub_single_line_str(value, max_bytes=MAX_METADATA_TEXT_BYTES)
        return clean, False
    if isinstance(value, list):
        return _sanitize_json_list(value, depth)
    if isinstance(value, dict):
        return _sanitize_json_dict(value, depth)
    return None, True


def _sanitize_json_list(items: list[Any], depth: int) -> tuple[list[Any], bool]:
    out: list[Any] = []
    malformed = False
    for elem in items[:64]:
        clean, bad = _sanitize_json_value(elem, depth + 1)
        malformed = malformed or bad
        out.append(clean)
    return out, malformed or (len(items) > 64)


def require_clean_primary_id(value: Any) -> str:
    """Require a non-empty TEXT identifier free of control, surrogate, and bidi chars."""
    if not isinstance(value, str) or not value or has_forbidden_control_or_bidi(value):
        raise CoordPolicyError("registry_unreadable")
    return value


def sanitize_optional_ref(
    value: Any, malformed_flag: Any = False
) -> tuple[str | None, bool]:
    """Validate an optional identifier/reference, mapping hostile chars to None + malformed."""
    if value is None:
        return None, bool(malformed_flag)
    if not isinstance(value, str) or not value or has_forbidden_control_or_bidi(value):
        return None, True
    return value, bool(malformed_flag)


def sanitize_enum_str(
    value: Any,
    allowed: frozenset[str] | None = None,
    *,
    fallback: str = "unknown",
) -> tuple[str, bool]:
    """Validate a status/enum token, clamping hostile or out-of-domain values cleanly."""
    if not isinstance(value, str) or not value or has_forbidden_control_or_bidi(value):
        return fallback, True
    if allowed is not None and value not in allowed:
        return fallback, True
    return value, False


def _sanitize_json_dict(
    mapping: Mapping[Any, Any], depth: int
) -> tuple[dict[str, Any], bool]:
    out: dict[str, Any] = {}
    malformed = False
    count = 0
    for key, val in mapping.items():
        if not isinstance(key, str):
            malformed = True
            continue
        clean_key, _ = scrub_single_line_str(key, max_bytes=64)
        clean_key = clean_key.strip()
        if not clean_key or clean_key.lower() in _UNTRUSTED_DETAIL_KEYS_LOWER:
            continue
        if count >= 64:
            malformed = True
            break
        clean_val, bad = _sanitize_json_value(val, depth + 1)
        malformed = malformed or bad
        out[clean_key] = clean_val
        count += 1
    return out, malformed


def parse_detail_json(raw_blob: Any, raw_bytes: Any) -> tuple[dict[str, Any], bool]:
    parsed, bad = _parse_json_cell(raw_blob, raw_bytes)
    if bad or not isinstance(parsed, dict):
        return {}, True
    return _sanitize_json_dict(parsed, 0)


def parse_string_list_json(
    raw_blob: Any, raw_bytes: Any
) -> tuple[tuple[str, ...], bool]:
    parsed, bad = _parse_json_cell(raw_blob, raw_bytes)
    if bad or not isinstance(parsed, list):
        return (), True
    out: list[str] = []
    malformed = False
    for item in parsed[:64]:
        if not isinstance(item, str):
            malformed = True
            continue
        clean, _ = scrub_single_line_str(item, max_bytes=128)
        out.append(clean)
    return tuple(out), malformed or (len(parsed) > 64)


def parse_artifact_refs_json(
    raw_blob: Any, raw_bytes: Any
) -> tuple[tuple[ProjectedArtifactRef, ...], bool]:
    parsed, bad = _parse_json_cell(raw_blob, raw_bytes)
    if bad or not isinstance(parsed, list):
        return (), True
    refs: list[ProjectedArtifactRef] = []
    malformed = False
    for item in parsed[:32]:
        if not isinstance(item, dict):
            malformed = True
            continue
        try:
            validated = ArtifactRef(
                blob_sha256=item.get("blob_sha256"),  # type: ignore[arg-type]
                size_bytes=item.get("size_bytes"),  # type: ignore[arg-type]
                media_type=item.get("media_type", "text/x-patch"),
            )
            refs.append(
                ProjectedArtifactRef(
                    blob_sha256=validated.blob_sha256,
                    size_bytes=validated.size_bytes,
                    media_type=validated.media_type,
                )
            )
        except (CoordValidationError, TypeError, ValueError):
            malformed = True
    return tuple(refs), malformed or (len(parsed) > 32)


def _validate_budget_str(value: Any, label: str) -> str:
    clean = check_no_control_or_bidi(value, label)
    if not clean or len(clean.encode("utf-8")) > MAX_METADATA_TEXT_BYTES:
        raise ValueError(f"Invalid budget {label}")
    return clean


def _parse_optional_str_frozenset(raw: Any, label: str) -> frozenset[str] | None:
    if raw is None:
        return None
    if not isinstance(raw, list) or len(raw) > 64:
        raise ValueError("Expected bounded list of strings or None")
    return frozenset(_validate_budget_str(x, label) for x in raw)


def _parse_required_str_frozenset(raw: Any, label: str) -> frozenset[str]:
    if not isinstance(raw, list) or len(raw) > 64:
        raise ValueError("Expected bounded list of strings")
    return frozenset(_validate_budget_str(x, label) for x in raw)


def parse_budget_json(
    raw_blob: Any, raw_bytes: Any
) -> tuple[ProjectedSubtreeBudget | None, bool]:
    parsed, bad = _parse_json_cell(raw_blob, raw_bytes)
    if bad or not isinstance(parsed, dict):
        return None, True
    try:
        budget = SubtreeBudget(
            max_depth_remaining=parsed["max_depth_remaining"],
            max_children=parsed["max_children"],
            max_total_sandboxes=parsed["max_total_sandboxes"],
            allowed_workers=_parse_required_str_frozenset(
                parsed["allowed_workers"], "allowed_workers"
            ),
            allowed_sandbox_types=_parse_required_str_frozenset(
                parsed["allowed_sandbox_types"], "allowed_sandbox_types"
            ),
            allowed_models=_parse_optional_str_frozenset(
                parsed.get("allowed_models"), "allowed_models"
            ),
            allowed_variants=_parse_optional_str_frozenset(
                parsed.get("allowed_variants"), "allowed_variants"
            ),
            allowed_broker_routes=_parse_required_str_frozenset(
                parsed["allowed_broker_routes"], "allowed_broker_routes"
            ),
            max_security_profile=_validate_budget_str(
                parsed["max_security_profile"], "max_security_profile"
            ),
        )
    except (KeyError, TypeError, ValueError, CoordValidationError):
        return None, True
    return (
        ProjectedSubtreeBudget(
            max_depth_remaining=budget.max_depth_remaining,
            max_children=budget.max_children,
            max_total_sandboxes=budget.max_total_sandboxes,
            allowed_workers=tuple(sorted(budget.allowed_workers)),
            allowed_sandbox_types=tuple(sorted(budget.allowed_sandbox_types)),
            allowed_models=(
                None
                if budget.allowed_models is None
                else tuple(sorted(budget.allowed_models))
            ),
            allowed_variants=(
                None
                if budget.allowed_variants is None
                else tuple(sorted(budget.allowed_variants))
            ),
            allowed_broker_routes=tuple(sorted(budget.allowed_broker_routes)),
            max_security_profile=budget.max_security_profile,
        ),
        False,
    )


def hash_strict_text_blob(blob: Any) -> str | None:
    if blob is None or not isinstance(blob, (bytes, bytearray)):
        return None
    try:
        text = bytes(blob).decode("utf-8")
        return sha256_canonical_body(text, max_bytes=MAX_HASH_TEXT_BYTES)
    except (CoordValidationError, TypeError, ValueError):
        return None


def _downgrade(reason: str) -> tuple[str, str | None, int, bool, bool, str]:
    return _BADGE_UNVERIFIED, None, 0, True, True, reason


def _count_full_tuple_stream_matches(
    conn: sqlite3.Connection,
    *,
    execute_fn: Callable[[sqlite3.Connection, str, tuple[Any, ...], float], sqlite3.Cursor],
    check_deadline_fn: Callable[[float], int],
    sandbox_addr: str,
    incarnation_id: str,
    thread_id: str,
    message_id: str,
    expected_sha256: str,
    deadline: float,
) -> tuple[int, bool]:
    candidates = execute_fn(
        conn,
        f"""
        SELECT seq,
               CASE WHEN typeof(text) = 'text' AND LENGTH(CAST(text AS BLOB)) <= {MAX_HASH_TEXT_BYTES}
                    THEN CAST(text AS BLOB) ELSE NULL END AS text_blob
        FROM stream_events
        WHERE sandbox_addr = ? AND incarnation_id = ? AND thread_id = ?
          AND event_type = 'user_message' AND message_id = ?
        ORDER BY seq ASC
        LIMIT ?
        """,
        (
            sandbox_addr,
            incarnation_id,
            thread_id,
            message_id,
            MAX_AMBIGUITY_CANDIDATES + 1,
        ),
        deadline,
    ).fetchall()
    if len(candidates) > MAX_AMBIGUITY_CANDIDATES:
        return 0, True
    matches = 0
    for cand in candidates:
        check_deadline_fn(deadline)
        digest = hash_strict_text_blob(cand["text_blob"])
        if digest is not None and digest == expected_sha256:
            matches += 1
    return matches, False


def _is_valid_actor_str(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not has_forbidden_control_or_bidi(value)
    )


def _receipt_matches_envelope(
    rcpt: Mapping[str, Any], ev: Mapping[str, Any]
) -> bool:
    rcpt_actor = rcpt[_COL_SRC_ACTOR]
    ev_actor = ev[_COL_SRC_ACTOR]
    rcpt_sha = rcpt[_COL_BODY_SHA256]
    ev_sha = ev[_COL_BODY_SHA256]
    if not (_is_valid_actor_str(rcpt_actor) and _is_valid_actor_str(ev_actor)):
        return False
    if not (isinstance(rcpt_sha, str) and bool(rcpt_sha) and isinstance(ev_sha, str)):
        return False
    return (
        rcpt[_COL_TRUST_CLASS] == ev[_COL_TRUST_CLASS]
        and rcpt_actor == ev_actor
        and rcpt_sha == ev_sha
    )


def _fetch_envelope_and_receipt(
    conn: sqlite3.Connection,
    *,
    execute_fn: Callable[[sqlite3.Connection, str, tuple[Any, ...], float], sqlite3.Cursor],
    sandbox_addr: str,
    incarnation_id: str,
    thread_id: str,
    msg_id: str,
    deadline: float,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    ev = execute_fn(
        conn,
        """
        SELECT
            CASE WHEN typeof(trust_class) = 'text' AND LENGTH(CAST(trust_class AS BLOB)) <= 64
                 THEN trust_class ELSE NULL END AS trust_class,
            CASE WHEN typeof(src_actor) = 'text' AND LENGTH(CAST(src_actor AS BLOB)) <= 256
                 THEN src_actor ELSE NULL END AS src_actor,
            CASE WHEN typeof(body_sha256) = 'text' AND LENGTH(CAST(body_sha256 AS BLOB)) <= 128
                 THEN body_sha256 ELSE NULL END AS body_sha256
        FROM event_log
        WHERE msg_id = ? AND dst_addr = ? AND dst_incarnation = ? AND dst_thread_id = ?
        """,
        (msg_id, sandbox_addr, incarnation_id, thread_id),
        deadline,
    ).fetchone()
    if ev is None:
        return None, []
    receipts = execute_fn(
        conn,
        """
        SELECT
            CASE WHEN typeof(badge) = 'text' AND LENGTH(CAST(badge AS BLOB)) <= 64
                 THEN badge ELSE NULL END AS badge,
            CASE WHEN typeof(trust_class) = 'text' AND LENGTH(CAST(trust_class AS BLOB)) <= 64
                 THEN trust_class ELSE NULL END AS trust_class,
            CASE WHEN typeof(src_actor) = 'text' AND LENGTH(CAST(src_actor AS BLOB)) <= 256
                 THEN src_actor ELSE NULL END AS src_actor,
            CASE WHEN typeof(body_sha256) = 'text' AND LENGTH(CAST(body_sha256 AS BLOB)) <= 128
                 THEN body_sha256 ELSE NULL END AS body_sha256
        FROM dispatch_receipts
        WHERE sandbox_addr = ? AND incarnation_id = ? AND session_id = ? AND message_id = ?
          AND typeof(consumed_at) IN ('integer', 'real')
        LIMIT 2
        """,
        (sandbox_addr, incarnation_id, thread_id, msg_id),
        deadline,
    ).fetchall()
    return ev, receipts


def _receipt_badge_matches(rcpt: Mapping[str, Any], raw_badge: str) -> bool:
    try:
        rcpt_tc = TrustClass(rcpt[_COL_TRUST_CLASS])
    except (ValueError, TypeError):
        return False
    return rcpt["badge"] == raw_badge and _TRUST_CLASS_TO_BADGE[rcpt_tc].value == raw_badge


def _verify_host_stream_provenance(
    conn: sqlite3.Connection,
    row: Mapping[str, Any],
    *,
    execute_fn: Callable[[sqlite3.Connection, str, tuple[Any, ...], float], sqlite3.Cursor],
    check_deadline_fn: Callable[[float], int],
    raw_badge: str,
    message_id: str | None,
    sandbox_addr: str,
    incarnation_id: str,
    thread_id: str,
    deadline: float,
) -> tuple[str, str | None, int, bool, bool, str | None]:
    if not _is_valid_actor_str(message_id):
        return _downgrade(ANOMALY_UNBACKED)
    assert message_id is not None

    ev, receipts = _fetch_envelope_and_receipt(
        conn,
        execute_fn=execute_fn,
        sandbox_addr=sandbox_addr,
        incarnation_id=incarnation_id,
        thread_id=thread_id,
        msg_id=message_id,
        deadline=deadline,
    )
    if ev is None or len(receipts) == 0:
        return _downgrade(ANOMALY_UNBACKED)
    if len(receipts) != 1:
        return _downgrade(ANOMALY_AMBIGUOUS_RECEIPT)

    rcpt = receipts[0]
    if not _receipt_badge_matches(rcpt, raw_badge):
        return _downgrade(ANOMALY_TRUST_MISMATCH)
    if not _receipt_matches_envelope(rcpt, ev):
        return _downgrade(ANOMALY_ENVELOPE_MISMATCH)

    rcpt_sha = rcpt[_COL_BODY_SHA256]
    row_digest = hash_strict_text_blob(row["text_for_hash_blob"])
    if row_digest is None or row_digest != rcpt_sha:
        return _downgrade(ANOMALY_BODY_HASH_MISMATCH)

    match_count, flood = _count_full_tuple_stream_matches(
        conn,
        execute_fn=execute_fn,
        check_deadline_fn=check_deadline_fn,
        sandbox_addr=sandbox_addr,
        incarnation_id=incarnation_id,
        thread_id=thread_id,
        message_id=message_id,
        expected_sha256=rcpt_sha,
        deadline=deadline,
    )
    if flood or match_count != 1:
        return _downgrade(ANOMALY_AMBIGUOUS_RECEIPT)

    return (
        raw_badge,
        rcpt[_COL_SRC_ACTOR],
        _BADGE_AUTHORITY_RANK[raw_badge],
        raw_badge not in _TRUSTED_BADGES,
        False,
        None,
    )


def evaluate_stream_provenance(
    conn: sqlite3.Connection,
    row: Mapping[str, Any],
    *,
    execute_fn: Callable[[sqlite3.Connection, str, tuple[Any, ...], float], sqlite3.Cursor],
    check_deadline_fn: Callable[[float], int],
    event_type: str,
    message_id: str | None,
    sandbox_addr: str,
    incarnation_id: str,
    thread_id: str,
    deadline: float,
) -> tuple[str | None, str | None, int, bool, bool, str | None]:
    raw_badge = row["badge"]
    badge_malformed = bool(row["badge_malformed"])
    if event_type != "user_message":
        if raw_badge is not None or badge_malformed:
            return None, None, 0, True, True, ANOMALY_NON_USER_BADGE
        return None, None, 0, True, False, None
    if badge_malformed or raw_badge not in _VALID_BADGES:
        return _downgrade(ANOMALY_INVALID_BADGE)
    if raw_badge == _BADGE_UNVERIFIED:
        return _BADGE_UNVERIFIED, None, 0, True, False, None
    if raw_badge == _BADGE_TUI:
        return _downgrade(ANOMALY_TUI_UNVERIFIABLE)
    if raw_badge in _HOST_BADGES:
        return _verify_host_stream_provenance(
            conn,
            row,
            execute_fn=execute_fn,
            check_deadline_fn=check_deadline_fn,
            raw_badge=raw_badge,
            message_id=message_id,
            sandbox_addr=sandbox_addr,
            incarnation_id=incarnation_id,
            thread_id=thread_id,
            deadline=deadline,
        )
    return _downgrade(ANOMALY_INVALID_BADGE)
