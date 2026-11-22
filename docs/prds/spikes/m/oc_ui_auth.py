"""Host Authentication, CSRF, Origin, and Scoped WebSocket Ticket Manager for PRD M3.

Pure Python standard library only. Provides a thread-safe state machine for the
hardened loopback Unified Control UI:
- Single-use 256-bit cryptographic bootstrap codes (SHA-256 stored, TTL <= 60s, bounded)
- Opaque 256-bit sessions (SHA-256 stored, HttpOnly; SameSite=Strict; Path=/, idle + absolute TTL)
- Exact loopback Host & Origin enforcement (defeats DNS rebinding, Origin: null, foreign origins)
- Session-bound CSRF double-submit verification (constant-time hmac.compare_digest)
- Single-use 256-bit scoped WebSocket tickets (TTL <= 30s, pinned to session + target_addr +
  incarnation_id + surface_kind + mode, atomic single-use consumption)
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import math
from pathlib import Path
import re
import secrets
import sys
import threading
import time
from urllib.parse import urlsplit

_SPIKE_M_DIR = Path(__file__).resolve().parent
if str(_SPIKE_M_DIR) not in sys.path:
    sys.path.insert(0, str(_SPIKE_M_DIR))

from oc_address import (  # noqa: E402
    AddressError,
    check_no_control_or_bidi,
    parse_local_target,
)
from oc_coord_contract import (  # noqa: E402
    CoordValidationError,
    validate_opaque_token,
)

MAX_BOOTSTRAP_TTL_S = 60.0
DEFAULT_IDLE_TTL_S = 1800.0
DEFAULT_ABSOLUTE_TTL_S = 28800.0
MAX_WS_TICKET_TTL_S = 30.0
DEFAULT_MAX_PENDING_CODES = 64
DEFAULT_MAX_SESSIONS = 64
DEFAULT_MAX_PENDING_WS_TICKETS = 128
DEFAULT_COOKIE_NAME = "oc_ui_session"

SURFACE_EVENTS = "events"
SURFACE_OPENCODE_TUI = "opencode-tui"
SURFACE_SHELL = "shell"
SURFACE_BROWSER = "browser"

MODE_OBSERVE = "observe"
MODE_INTERACTIVE = "interactive"
MODE_PIP_WALL = "pip_wall"

VALID_SURFACE_KINDS: frozenset[str] = frozenset(
    {SURFACE_EVENTS, SURFACE_OPENCODE_TUI, SURFACE_SHELL, SURFACE_BROWSER}
)
VALID_WS_MODES: frozenset[str] = frozenset({MODE_OBSERVE, MODE_INTERACTIVE, MODE_PIP_WALL})

_COOKIE_NAME_RE = re.compile(r"^[a-zA-Z\d_-]{1,64}$", re.ASCII)

_ERR_INVALID_SESSION = "Invalid or expired session"
_ERR_INVALID_HOST = "Host header rejected"
_ERR_INVALID_ORIGIN = "Origin header rejected"
_ERR_INVALID_BOOTSTRAP_CODE = "Invalid or expired bootstrap code"
_ERR_MISSING_CSRF = "Missing or invalid CSRF token"
_ERR_CSRF_MISMATCH = "CSRF token mismatch"
_ERR_INVALID_WS_TICKET = "Invalid or expired WebSocket ticket"


class UiAuthError(RuntimeError):
    """Base Unified Control UI authentication/authorization error."""


class UiAuthValidationError(UiAuthError):
    """Invalid configuration or malformed authentication/scope parameter."""


class UiAuthDeniedError(UiAuthError):
    """Authentication, CSRF, Host/Origin, TTL, capacity, or ticket scope denial."""


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """Host-owned immutable view of an active UI session (never contains raw session ID)."""

    session_id_hash: str
    actor_id: str
    created_at: float
    last_seen_at: float
    expires_at: float


@dataclass(frozen=True, slots=True)
class WsTicketScope:
    """Verified scope returned on atomic single-use WebSocket ticket consumption."""

    session_id_hash: str
    target_addr: str
    incarnation_id: str
    surface_kind: str
    mode: str
    created_at: float
    expires_at: float


@dataclass(slots=True)
class _BootstrapEntry:
    code_hash: str
    actor_id: str
    expires_at: float


@dataclass(slots=True)
class _SessionState:
    record: SessionRecord
    csrf_hash: str


@dataclass(slots=True)
class _WsTicketEntry:
    ticket_hash: str
    scope: WsTicketScope


def _sha256_hex(raw: str) -> str:
    try:
        encoded = raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise UiAuthDeniedError("Invalid token encoding") from exc
    return hashlib.sha256(encoded).hexdigest()


def _validate_finite_number(value: object, label: str) -> float:
    err_msg = f"{label} must be a finite number"
    if type(value) not in (int, float):
        raise UiAuthValidationError(err_msg)
    try:
        num = float(value)
    except OverflowError as exc:
        raise UiAuthValidationError(err_msg) from exc
    if not math.isfinite(num):
        raise UiAuthValidationError(err_msg)
    return num


def _is_loopback_hostname(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_raw_port(host_entry: str) -> None:
    if host_entry.startswith("["):
        closing = host_entry.find("]")
        if closing == -1:
            raise UiAuthValidationError(f"Malformed IPv6 host entry: {host_entry!r}")
        tail = host_entry[closing + 1 :]
        if not tail:
            return
        if not tail.startswith(":"):
            raise UiAuthValidationError(f"Malformed IPv6 port suffix: {host_entry!r}")
        raw_port = tail[1:]
    elif ":" in host_entry:
        _, raw_port = host_entry.rsplit(":", 1)
    else:
        return
    if not raw_port or not (raw_port.isascii() and raw_port.isdigit()) or raw_port.startswith("0"):
        raise UiAuthValidationError(f"Invalid port in allowed host: {host_entry!r}")


def _validate_loopback_host_entry(raw: object) -> str:
    try:
        text = check_no_control_or_bidi(raw, "allowed_host")
    except AddressError as exc:
        raise UiAuthValidationError(str(exc)) from exc
    if not text or any(ch.isspace() for ch in text) or "/" in text or "@" in text:
        raise UiAuthValidationError(f"Invalid allowed host entry: {raw!r}")
    _validate_raw_port(text)
    parsed = urlsplit(f"https://{text}")
    if parsed.netloc != text or parsed.hostname is None:
        raise UiAuthValidationError(f"Malformed allowed host entry: {raw!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UiAuthValidationError(f"Invalid port in allowed host: {raw!r}") from exc
    if port is not None and not (1 <= port <= 65535):
        raise UiAuthValidationError(f"Port out of range in allowed host: {raw!r}")
    if not _is_loopback_hostname(parsed.hostname):
        raise UiAuthValidationError(f"Non-loopback allowed host rejected: {raw!r}")
    return text


def _validate_loopback_origin_entry(raw: object) -> str:
    try:
        text = check_no_control_or_bidi(raw, "allowed_origin")
    except AddressError as exc:
        raise UiAuthValidationError(str(exc)) from exc
    if not text or any(ch.isspace() for ch in text) or text.lower() == "null":
        raise UiAuthValidationError(f"Invalid allowed origin entry: {raw!r}")
    parsed = urlsplit(text)
    if parsed.scheme not in ("http", "https"):
        raise UiAuthValidationError(f"Origin scheme must be http or https: {raw!r}")
    if parsed.path or parsed.query or parsed.fragment or "@" in parsed.netloc:
        raise UiAuthValidationError(f"Origin must not contain path, query, fragment, or userinfo: {raw!r}")
    _validate_loopback_host_entry(parsed.netloc)
    reconstructed = f"{parsed.scheme}://{parsed.netloc}"
    if reconstructed != text:
        raise UiAuthValidationError(f"Non-canonical allowed origin rejected: {raw!r}")
    return text


def _validate_positive_bound(value: int, label: str) -> int:
    if type(value) is not int or value < 1:
        raise UiAuthValidationError(f"{label} must be a positive integer")
    return value


def _validate_ws_scope(
    target_addr: str, incarnation_id: str, surface_kind: str, mode: str
) -> tuple[str, str, str, str]:
    try:
        canonical_target = parse_local_target(target_addr).canonical
        clean_incarnation = validate_opaque_token(incarnation_id, "incarnation_id")
    except (AddressError, CoordValidationError) as exc:
        raise UiAuthValidationError(str(exc)) from exc
    if type(surface_kind) is not str or surface_kind not in VALID_SURFACE_KINDS:
        raise UiAuthValidationError(f"Unsupported surface_kind: {surface_kind!r}")
    if type(mode) is not str or mode not in VALID_WS_MODES:
        raise UiAuthValidationError(f"Unsupported ws mode: {mode!r}")
    if mode == MODE_PIP_WALL and surface_kind != SURFACE_BROWSER:
        raise UiAuthValidationError("pip_wall mode is only permitted on the browser surface")
    if surface_kind == SURFACE_EVENTS and mode == MODE_INTERACTIVE:
        raise UiAuthValidationError("events surface does not permit interactive mode")
    return canonical_target, clean_incarnation, surface_kind, mode


class UiAuthManager:
    """Thread-safe loopback UI auth, CSRF, Origin, and scoped WebSocket ticket manager."""

    def __init__(
        self,
        allowed_hosts: Iterable[str],
        allowed_origins: Iterable[str],
        *,
        bootstrap_ttl_s: float = MAX_BOOTSTRAP_TTL_S,
        idle_ttl_s: float = DEFAULT_IDLE_TTL_S,
        absolute_ttl_s: float = DEFAULT_ABSOLUTE_TTL_S,
        ws_ticket_ttl_s: float = MAX_WS_TICKET_TTL_S,
        max_pending_codes: int = DEFAULT_MAX_PENDING_CODES,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_pending_ws_tickets: int = DEFAULT_MAX_PENDING_WS_TICKETS,
        cookie_name: str = DEFAULT_COOKIE_NAME,
        clock: Callable[[], float] = time.monotonic,
    ):
        hosts = frozenset(_validate_loopback_host_entry(h) for h in allowed_hosts)
        origins = frozenset(_validate_loopback_origin_entry(o) for o in allowed_origins)
        if not hosts or not origins:
            raise UiAuthValidationError("allowed_hosts and allowed_origins must be non-empty")
        for origin in origins:
            if urlsplit(origin).netloc not in hosts:
                raise UiAuthValidationError(
                    f"Allowed origin authority must appear in allowed_hosts: {origin!r}"
                )
        boot_ttl = _validate_finite_number(bootstrap_ttl_s, "bootstrap_ttl_s")
        idle_ttl = _validate_finite_number(idle_ttl_s, "idle_ttl_s")
        abs_ttl = _validate_finite_number(absolute_ttl_s, "absolute_ttl_s")
        ws_ttl = _validate_finite_number(ws_ticket_ttl_s, "ws_ticket_ttl_s")
        if not (0.0 < boot_ttl <= MAX_BOOTSTRAP_TTL_S):
            raise UiAuthValidationError(f"bootstrap_ttl_s must be in (0, {MAX_BOOTSTRAP_TTL_S}]")
        if idle_ttl <= 0.0 or abs_ttl < idle_ttl:
            raise UiAuthValidationError("idle_ttl_s must be > 0 and <= absolute_ttl_s")
        if not (0.0 < ws_ttl <= MAX_WS_TICKET_TTL_S):
            raise UiAuthValidationError(f"ws_ticket_ttl_s must be in (0, {MAX_WS_TICKET_TTL_S}]")
        if type(cookie_name) is not str or _COOKIE_NAME_RE.fullmatch(cookie_name) is None:
            raise UiAuthValidationError(f"Invalid cookie_name: {cookie_name!r}")

        self._allowed_hosts = hosts
        self._allowed_origins = origins
        self._bootstrap_ttl_s = boot_ttl
        self._idle_ttl_s = idle_ttl
        self._absolute_ttl_s = abs_ttl
        self._ws_ticket_ttl_s = ws_ttl
        self._max_pending_codes = _validate_positive_bound(max_pending_codes, "max_pending_codes")
        self._max_sessions = _validate_positive_bound(max_sessions, "max_sessions")
        self._max_pending_ws_tickets = _validate_positive_bound(
            max_pending_ws_tickets, "max_pending_ws_tickets"
        )
        self._cookie_name = cookie_name
        self._clock = clock

        self._lock = threading.Lock()
        self._pending_codes: dict[str, _BootstrapEntry] = {}
        self._sessions: dict[str, _SessionState] = {}
        self._ws_tickets: dict[str, _WsTicketEntry] = {}

    def _require_valid_host(self, host_header: object) -> str:
        if type(host_header) is not str or host_header not in self._allowed_hosts:
            raise UiAuthDeniedError(_ERR_INVALID_HOST)
        return host_header

    def _require_valid_origin(self, origin_header: object, *, host_header: str) -> None:
        if type(origin_header) is not str or origin_header not in self._allowed_origins:
            raise UiAuthDeniedError(_ERR_INVALID_ORIGIN)
        if urlsplit(origin_header).netloc != host_header:
            raise UiAuthDeniedError(_ERR_INVALID_ORIGIN)

    def _purge_expired_locked(self, now: float) -> None:
        expired_codes = [k for k, v in self._pending_codes.items() if now >= v.expires_at]
        for key in expired_codes:
            del self._pending_codes[key]

        expired_sessions = [
            k
            for k, st in self._sessions.items()
            if now >= st.record.expires_at or (now - st.record.last_seen_at) >= self._idle_ttl_s
        ]
        for key in expired_sessions:
            del self._sessions[key]

        expired_tickets = [
            k
            for k, tk in self._ws_tickets.items()
            if now >= tk.scope.expires_at or tk.scope.session_id_hash not in self._sessions
        ]
        for key in expired_tickets:
            del self._ws_tickets[key]

    @staticmethod
    def _touch_session_locked(state: _SessionState, now: float) -> SessionRecord:
        rec = state.record
        updated = SessionRecord(
            session_id_hash=rec.session_id_hash,
            actor_id=rec.actor_id,
            created_at=rec.created_at,
            last_seen_at=now,
            expires_at=rec.expires_at,
        )
        state.record = updated
        return updated

    def _get_active_session_locked(
        self, session_id: object, now: float, *, touch: bool
    ) -> _SessionState:
        if type(session_id) is not str or not session_id:
            raise UiAuthDeniedError(_ERR_INVALID_SESSION)
        digest = _sha256_hex(session_id)
        self._purge_expired_locked(now)
        state = self._sessions.get(digest)
        if state is None or not hmac.compare_digest(state.record.session_id_hash, digest):
            raise UiAuthDeniedError(_ERR_INVALID_SESSION)
        if touch:
            self._touch_session_locked(state, now)
        return state

    def mint_bootstrap_code(
        self, *, actor_id: str = "operator", ttl_s: float | None = None
    ) -> str:
        """Mint a single-use 256-bit bootstrap code stored only as a SHA-256 digest."""
        try:
            clean_actor = validate_opaque_token(actor_id, "actor_id")
        except (AddressError, CoordValidationError) as exc:
            raise UiAuthValidationError(str(exc)) from exc
        effective_ttl = (
            self._bootstrap_ttl_s
            if ttl_s is None
            else _validate_finite_number(ttl_s, "ttl_s")
        )
        if not (0.0 < effective_ttl <= MAX_BOOTSTRAP_TTL_S):
            raise UiAuthValidationError(f"ttl_s must be in (0, {MAX_BOOTSTRAP_TTL_S}]")

        raw_code = secrets.token_urlsafe(32)
        digest = _sha256_hex(raw_code)
        with self._lock:
            now = self._clock()
            self._purge_expired_locked(now)
            if len(self._pending_codes) >= self._max_pending_codes:
                raise UiAuthDeniedError("Pending bootstrap code table capacity exceeded")
            self._pending_codes[digest] = _BootstrapEntry(
                code_hash=digest,
                actor_id=clean_actor,
                expires_at=now + effective_ttl,
            )
        return raw_code

    def exchange_bootstrap_code(
        self,
        code: str,
        *,
        host_header: str,
        origin_header: str | None,
    ) -> tuple[SessionRecord, str, str]:
        """Atomically exchange a one-time bootstrap code for a session, CSRF token, and Set-Cookie."""
        valid_host = self._require_valid_host(host_header)
        self._require_valid_origin(origin_header, host_header=valid_host)
        if type(code) is not str or not code:
            raise UiAuthDeniedError(_ERR_INVALID_BOOTSTRAP_CODE)

        digest = _sha256_hex(code)
        raw_session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        session_hash = _sha256_hex(raw_session_id)
        csrf_hash = _sha256_hex(csrf_token)

        with self._lock:
            now = self._clock()
            self._purge_expired_locked(now)
            entry = self._pending_codes.pop(digest, None)
            if (
                entry is None
                or not hmac.compare_digest(entry.code_hash, digest)
                or now >= entry.expires_at
            ):
                raise UiAuthDeniedError(_ERR_INVALID_BOOTSTRAP_CODE)
            if len(self._sessions) >= self._max_sessions:
                raise UiAuthDeniedError("Active session table capacity exceeded")
            record = SessionRecord(
                session_id_hash=session_hash,
                actor_id=entry.actor_id,
                created_at=now,
                last_seen_at=now,
                expires_at=now + self._absolute_ttl_s,
            )
            self._sessions[session_hash] = _SessionState(record=record, csrf_hash=csrf_hash)

        set_cookie = f"{self._cookie_name}={raw_session_id}; HttpOnly; SameSite=Strict; Path=/"
        return record, csrf_token, set_cookie

    def validate_session(
        self, session_id: str, *, host_header: str, touch: bool = True
    ) -> SessionRecord:
        """Verify Host and active session (enforcing both idle and absolute TTLs)."""
        self._require_valid_host(host_header)
        with self._lock:
            now = self._clock()
            state = self._get_active_session_locked(session_id, now, touch=touch)
            return state.record

    def revoke_session(self, session_id: str) -> bool:
        """Revoke one session by raw session ID and purge all WS tickets bound to it."""
        if type(session_id) is not str or not session_id:
            return False
        try:
            digest = _sha256_hex(session_id)
        except UiAuthDeniedError:
            return False
        return self.revoke_session_by_hash(digest)

    def revoke_session_by_hash(self, session_id_hash: str) -> bool:
        """Revoke one session by its SHA-256 digest and purge all WS tickets bound to it."""
        if type(session_id_hash) is not str or not session_id_hash:
            return False
        with self._lock:
            removed = self._sessions.pop(session_id_hash, None)
            bound_tickets = [
                k
                for k, tk in self._ws_tickets.items()
                if tk.scope.session_id_hash == session_id_hash
            ]
            for key in bound_tickets:
                del self._ws_tickets[key]
            return removed is not None

    def revoke_all_sessions(self) -> int:
        """Revoke all active sessions and pending WS tickets; return revoked session count."""
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
            self._ws_tickets.clear()
            return count

    def verify_http_mutation(
        self,
        session_id: str,
        *,
        host_header: str,
        origin_header: str | None,
        csrf_token: str | None,
    ) -> SessionRecord:
        """Enforce exact Host, exact Origin (rejecting missing/null/foreign), session, and CSRF."""
        valid_host = self._require_valid_host(host_header)
        self._require_valid_origin(origin_header, host_header=valid_host)
        if type(csrf_token) is not str or not csrf_token:
            raise UiAuthDeniedError(_ERR_MISSING_CSRF)
        csrf_digest = _sha256_hex(csrf_token)
        with self._lock:
            now = self._clock()
            state = self._get_active_session_locked(session_id, now, touch=False)
            if not hmac.compare_digest(state.csrf_hash, csrf_digest):
                raise UiAuthDeniedError(_ERR_CSRF_MISMATCH)
            return self._touch_session_locked(state, now)

    def mint_ws_ticket(
        self,
        session_id: str,
        *,
        host_header: str,
        origin_header: str | None,
        csrf_token: str | None,
        target_addr: str,
        incarnation_id: str,
        surface_kind: str,
        mode: str = MODE_OBSERVE,
        ttl_s: float | None = None,
    ) -> str:
        """Mint a single-use 256-bit WS ticket pinned to session + target + incarnation + surface + mode."""
        valid_host = self._require_valid_host(host_header)
        self._require_valid_origin(origin_header, host_header=valid_host)
        if type(csrf_token) is not str or not csrf_token:
            raise UiAuthDeniedError(_ERR_MISSING_CSRF)
        canon_target, clean_inc, clean_surface, clean_mode = _validate_ws_scope(
            target_addr, incarnation_id, surface_kind, mode
        )
        effective_ttl = (
            self._ws_ticket_ttl_s
            if ttl_s is None
            else _validate_finite_number(ttl_s, "ttl_s")
        )
        if not (0.0 < effective_ttl <= MAX_WS_TICKET_TTL_S):
            raise UiAuthValidationError(f"ttl_s must be in (0, {MAX_WS_TICKET_TTL_S}]")

        csrf_digest = _sha256_hex(csrf_token)
        raw_ticket = secrets.token_urlsafe(32)
        ticket_digest = _sha256_hex(raw_ticket)

        with self._lock:
            now = self._clock()
            state = self._get_active_session_locked(session_id, now, touch=False)
            if not hmac.compare_digest(state.csrf_hash, csrf_digest):
                raise UiAuthDeniedError(_ERR_CSRF_MISMATCH)
            if len(self._ws_tickets) >= self._max_pending_ws_tickets:
                raise UiAuthDeniedError("Pending WebSocket ticket table capacity exceeded")
            rec = self._touch_session_locked(state, now)
            scope = WsTicketScope(
                session_id_hash=rec.session_id_hash,
                target_addr=canon_target,
                incarnation_id=clean_inc,
                surface_kind=clean_surface,
                mode=clean_mode,
                created_at=now,
                expires_at=now + effective_ttl,
            )
            self._ws_tickets[ticket_digest] = _WsTicketEntry(
                ticket_hash=ticket_digest, scope=scope
            )
        return raw_ticket

    @staticmethod
    def _verify_ws_scope_match(
        scope: WsTicketScope,
        *,
        canon_target: str,
        clean_inc: str,
        clean_surface: str,
        clean_mode: str,
    ) -> None:
        matched = (
            hmac.compare_digest(scope.target_addr, canon_target)
            and hmac.compare_digest(scope.incarnation_id, clean_inc)
            and hmac.compare_digest(scope.surface_kind, clean_surface)
            and hmac.compare_digest(scope.mode, clean_mode)
        )
        if not matched:
            raise UiAuthDeniedError("WebSocket ticket scope mismatch")

    @staticmethod
    def _require_session_digest(expected_session_id: str | None) -> str:
        if type(expected_session_id) is not str or not expected_session_id:
            raise UiAuthDeniedError(_ERR_INVALID_SESSION)
        return _sha256_hex(expected_session_id)

    def consume_ws_ticket(
        self,
        ticket: str,
        *,
        host_header: str,
        origin_header: str | None,
        expected_target_addr: str,
        expected_incarnation_id: str,
        expected_surface_kind: str,
        expected_mode: str,
        expected_session_id: str | None,
    ) -> WsTicketScope:
        """Atomically consume a single-use WS ticket after verifying Host, Origin, TTL, session, and scope pins."""
        valid_host = self._require_valid_host(host_header)
        self._require_valid_origin(origin_header, host_header=valid_host)
        canon_target, clean_inc, clean_surface, clean_mode = _validate_ws_scope(
            expected_target_addr, expected_incarnation_id, expected_surface_kind, expected_mode
        )
        if type(ticket) is not str or not ticket:
            raise UiAuthDeniedError(_ERR_INVALID_WS_TICKET)
        expected_session_digest = self._require_session_digest(expected_session_id)
        ticket_digest = _sha256_hex(ticket)

        with self._lock:
            now = self._clock()
            self._purge_expired_locked(now)
            entry = self._ws_tickets.pop(ticket_digest, None)
            if (
                entry is None
                or not hmac.compare_digest(entry.ticket_hash, ticket_digest)
                or now >= entry.scope.expires_at
            ):
                raise UiAuthDeniedError(_ERR_INVALID_WS_TICKET)
            scope = entry.scope
            if scope.session_id_hash not in self._sessions:
                raise UiAuthDeniedError(_ERR_INVALID_SESSION)
            if not hmac.compare_digest(scope.session_id_hash, expected_session_digest):
                raise UiAuthDeniedError(_ERR_INVALID_SESSION)
            self._verify_ws_scope_match(
                scope,
                canon_target=canon_target,
                clean_inc=clean_inc,
                clean_surface=clean_surface,
                clean_mode=clean_mode,
            )
            return scope
