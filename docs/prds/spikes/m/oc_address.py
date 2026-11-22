"""Canonical local and fleet target addressing for PRD M coordination.

Pure Python standard library with zero SQLite, UDS, or server dependencies so
parallel coordination and local-integration lanes can share this module directly.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

RESERVED_INSTANCE_NAMES: frozenset[str] = frozenset(
    {"agent", "chromium", "chrome", "postgres", "pg", "dind", "home"}
)
RESERVED_WORKER_NAMES: frozenset[str] = frozenset({"local", "peer"})
VALID_MSG_KINDS: frozenset[str] = frozenset(
    {
        "prompt",
        "review_request",
        "review_findings",
        "question",
        "answer",
        "status_report",
        "cancel",
    }
)

_INSTANCE_RE = re.compile(r"^[a-z\d](?:[a-z\d-]{0,22}[a-z\d])?$", re.ASCII)
_REMOTE_RE = re.compile(r"^[a-z\d](?:[a-z\d-]{0,30}[a-z\d])?$", re.ASCII)
_THREAD_ID_RE = re.compile(r"^[a-z\d](?:[a-z\d-]{0,30}[a-z\d])?$", re.ASCII)

_BIDI_CODEPOINTS: frozenset[int] = frozenset(
    list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)) + [0x200E, 0x200F, 0x061C]
)


class AddressError(ValueError):
    """Raised when a sandbox, worker, peer, thread, or message-kind token is invalid."""


def has_forbidden_control_or_bidi(text: str) -> bool:
    """Return True if text contains ASCII/C1 control, surrogate, or Unicode bidi chars."""
    for ch in text:
        code = ord(ch)
        if (
            code < 0x20
            or 0x7F <= code <= 0x9F
            or 0xD800 <= code <= 0xDFFF
            or code in _BIDI_CODEPOINTS
        ):
            return True
    return False


def check_no_control_or_bidi(value: object, label: str) -> str:
    """Ensure value is a str with zero control, surrogate, or Unicode bidi codepoints."""
    if not isinstance(value, str):
        raise AddressError(f"{label} must be a string")
    if has_forbidden_control_or_bidi(value):
        raise AddressError(f"{label} contains forbidden control, surrogate, or bidi characters")
    return value


def _validate_instance_atom(raw: object, label: str) -> str:
    text = check_no_control_or_bidi(raw, label)
    if _INSTANCE_RE.fullmatch(text) is None:
        raise AddressError(f"Invalid {label}: {text!r}")
    if text in RESERVED_INSTANCE_NAMES:
        raise AddressError(f"Reserved {label} rejected: {text!r}")
    return text


def _validate_remote_atom(raw: object) -> str:
    text = check_no_control_or_bidi(raw, "remote worker name")
    if _REMOTE_RE.fullmatch(text) is None:
        raise AddressError(f"Invalid remote worker name: {text!r}")
    if text in RESERVED_WORKER_NAMES:
        raise AddressError(f"Reserved remote worker name rejected: {text!r}")
    return text


@dataclass(frozen=True, slots=True)
class TargetAddr:
    """Canonical bijective target address ('NAME', 'REMOTE / NAME', or '@PEER')."""

    kind: str  # "local" | "remote" | "peer"
    name: str
    remote: str | None = None

    @property
    def worker_ref(self) -> str:
        if self.kind == "local":
            return "local"
        if self.kind == "peer":
            return "peer"
        return self.remote or ""

    @property
    def canonical(self) -> str:
        return format_canonical_addr(self)


def format_canonical_addr(addr: TargetAddr) -> str:
    """Format a validated TargetAddr into its unique canonical wire string."""
    if not isinstance(addr, TargetAddr):
        raise AddressError("addr must be a TargetAddr")
    if addr.kind == "local":
        if addr.remote is not None:
            raise AddressError("Local TargetAddr must not carry a remote worker")
        return _validate_instance_atom(addr.name, "sandbox instance name")
    if addr.kind == "remote":
        rem = _validate_remote_atom(addr.remote)
        inst = _validate_instance_atom(addr.name, "sandbox instance name")
        return f"{rem} / {inst}"
    if addr.kind == "peer":
        if addr.remote is not None:
            raise AddressError("External peer TargetAddr must not carry a remote worker")
        peer = _validate_instance_atom(addr.name, "external peer name")
        return f"@{peer}"
    raise AddressError(f"Unsupported TargetAddr kind: {addr.kind!r}")


def parse_canonical_addr(raw: object) -> TargetAddr:
    """Parse canonical 'NAME', 'REMOTE / NAME', or '@PEER' strictly with bijection."""
    text = check_no_control_or_bidi(raw, "target address")
    if not text:
        raise AddressError("target address must not be empty")
    if text.startswith("@"):
        if "/" in text or " " in text:
            raise AddressError(f"Invalid external peer address: {text!r}")
        peer = _validate_instance_atom(text[1:], "external peer name")
        return TargetAddr(kind="peer", name=peer)
    if " / " in text:
        parts = text.split(" / ")
        if len(parts) != 2:
            raise AddressError(f"Invalid remote target address: {text!r}")
        rem = _validate_remote_atom(parts[0])
        inst = _validate_instance_atom(parts[1], "sandbox instance name")
        return TargetAddr(kind="remote", name=inst, remote=rem)
    if "/" in text or " " in text:
        raise AddressError(f"Non-canonical separator or whitespace in target address: {text!r}")
    inst = _validate_instance_atom(text, "sandbox instance name")
    return TargetAddr(kind="local", name=inst)


def parse_local_target(raw: object) -> TargetAddr:
    """Parse a strictly local sandbox target address ('NAME', rejecting remote and @PEER)."""
    addr = parse_canonical_addr(raw)
    if addr.kind != "local":
        raise AddressError(f"Only local sandbox target addresses are enabled in this slice: {raw!r}")
    return addr


def validate_thread_id(raw: object = "main") -> str:
    """Validate a typed wire thread_id (1..32 lowercase RFC-1123 label chars)."""
    text = check_no_control_or_bidi(raw, "thread_id")
    if _THREAD_ID_RE.fullmatch(text) is None:
        raise AddressError(f"Invalid thread_id: {text!r}")
    return text


def validate_msg_kind(raw: object) -> str:
    """Validate a closed wire message kind token."""
    text = check_no_control_or_bidi(raw, "msg_kind")
    if text not in VALID_MSG_KINDS:
        raise AddressError(f"Unsupported msg_kind: {text!r}")
    return text
