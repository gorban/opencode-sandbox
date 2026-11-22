"""Shared host-broker security primitives for PRD L1 (Path A).

Pure Python standard library only. Provides:
- Connect-time DNS-pinned IP validation & strict TLS SNI dialing
- In-memory host vault store with runtime RO/RW secret distinctness checks
- Overlap-window streaming canary scanner (raw, URL-encoded, base64/urlsafe-b64)
- Per-job BrokerLease bound to real oc_controller.Controller with <1s teardown
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
import hmac
import ipaddress
import os
from pathlib import Path
import secrets
import socket
import ssl
import stat
import threading
from typing import Any
from urllib.parse import quote, quote_plus

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

MIN_SECRET_LEN = 12

OPERATOR_ALLOWED_PRIVATE_SUPERNETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network(((10 << 24), 8)),
    ipaddress.IPv4Network((((172 << 24) | (16 << 16)), 12)),
    ipaddress.IPv4Network((((192 << 24) | (168 << 16)), 16)),
    ipaddress.IPv4Network((((100 << 24) | (64 << 16)), 10)),
)


class BrokerError(RuntimeError):
    """Base host-broker failure."""


class BrokerAuthError(BrokerError):
    """Job token or lease authentication/revocation failure."""


class BrokerPolicyError(BrokerError):
    """SSRF, CIDR, distinctness, or L7 policy violation."""


class CanaryLeakError(BrokerError):
    """Defense-in-depth canary detected in upstream response stream."""


def validate_allowed_cidrs(
    cidrs: Sequence[str], *, context: str = "allowed_cidrs"
) -> tuple[str, ...]:
    """Validate operator-pinned CIDR opt-ins (strict subsets of RFC1918 or 100.64.0.0/10 only)."""
    if not isinstance(cidrs, (list, tuple)):
        raise BrokerPolicyError(f"{context} must be a list of CIDR strings")
    normalized: list[str] = []
    for raw in cidrs:
        if type(raw) is not str or "/" not in raw:
            raise BrokerPolicyError(f"Invalid CIDR in {context}: {raw!r}")
        try:
            net = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            raise BrokerPolicyError(f"Invalid CIDR in {context}: {raw!r}") from exc
        if not isinstance(net, ipaddress.IPv4Network):
            raise BrokerPolicyError(f"Only IPv4 RFC1918/CGNAT CIDRs allowed in {context}: {raw!r}")
        if not any(net.subnet_of(supernet) for supernet in OPERATOR_ALLOWED_PRIVATE_SUPERNETS):
            raise BrokerPolicyError(
                f"CIDR {raw!r} in {context} must be a subset of RFC1918 or 100.64.0.0/10"
            )
        normalized.append(str(net))
    return tuple(normalized)


def _parse_and_unwrap_ip(raw_ip: str) -> IPAddress:
    if "%" in raw_ip:
        raise BrokerPolicyError(f"Scoped IPv6 zone identifier rejected: {raw_ip!r}")
    ip = ipaddress.ip_address(raw_ip)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


NON_OVERRIDABLE_BLOCKED_V6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("64:ff9b::/96"),      # RFC 6052 NAT64 well-known prefix
    ipaddress.ip_network("64:ff9b:1::/48"),    # RFC 8215 local-use NAT64
    ipaddress.ip_network("2002::/16"),         # 6to4
    ipaddress.ip_network("2001::/32"),         # Teredo
    ipaddress.ip_network("::/96"),             # Deprecated IPv4-compatible IPv6
)


def _is_non_overridably_blocked(ip: IPAddress) -> bool:
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        return any(ip in net for net in NON_OVERRIDABLE_BLOCKED_V6_NETWORKS)
    return False


def _ip_matches_policy(
    ip: IPAddress,
    allowed_nets: tuple[ipaddress.IPv4Network, ...],
    *,
    allow_test_loopback: bool = False,
) -> bool:
    if allow_test_loopback and ip.is_loopback:
        return True
    if _is_non_overridably_blocked(ip):
        return False
    if ip.is_global:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in allowed_nets)
    return False


def _extract_resolved_ips(
    host: str, port: int, resolver: Callable[..., list[Any]] | None
) -> list[IPAddress]:
    clean_host = host.strip().lower().rstrip(".")
    if not clean_host:
        raise BrokerPolicyError("Upstream host must be non-empty")
    try:
        return [_parse_and_unwrap_ip(clean_host)]
    except ValueError:
        pass

    resolve_fn = resolver or socket.getaddrinfo
    try:
        infos = resolve_fn(clean_host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise BrokerPolicyError(f"DNS resolution failed for {clean_host!r}") from exc
    if not infos:
        raise BrokerPolicyError(f"DNS returned no addresses for {clean_host!r}")
    ips: list[IPAddress] = []
    for info in infos:
        sockaddr = info[4]
        raw_addr = sockaddr[0]
        ips.append(_parse_and_unwrap_ip(str(raw_addr)))
    return ips


def resolve_and_validate_ip(
    host: str,
    allowed_cidrs: Sequence[str] = (),
    *,
    port: int = 443,
    resolver: Callable[..., list[Any]] | None = None,
    allow_test_loopback: bool = False,
) -> str:
    """Resolve upstream host once at connect time and validate every returned address.

    Fails closed if ANY returned record hits a non-overridably blocked range
    (loopback, link-local/metadata, multicast, unspecified) unless allow_test_loopback
    is explicitly set for local mock-upstream unit tests.
    """
    norm_cidrs = validate_allowed_cidrs(allowed_cidrs)
    allowed_nets = tuple(ipaddress.ip_network(c, strict=True) for c in norm_cidrs)
    ips = _extract_resolved_ips(host, port, resolver)

    validated: list[str] = []
    for ip in ips:
        if not allow_test_loopback and _is_non_overridably_blocked(ip):
            raise BrokerPolicyError(
                f"Upstream host {host!r} resolved to non-overridably blocked address"
            )
        if _ip_matches_policy(ip, allowed_nets, allow_test_loopback=allow_test_loopback):
            validated.append(str(ip))

    if not validated:
        raise BrokerPolicyError(f"Upstream host {host!r} resolved to no policy-allowed IP")
    return validated[0]


def build_strict_tls_context(*, cafile: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def connect_tcp_pinned_ip(ip: str, port: int, *, timeout: float = 5.0) -> socket.socket:
    parsed = ipaddress.ip_address(ip)
    family = socket.AF_INET6 if isinstance(parsed, ipaddress.IPv6Address) else socket.AF_INET
    raw_sock = socket.socket(family, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)
    try:
        raw_sock.connect((str(parsed), port))
    except OSError:
        raw_sock.close()
        raise
    return raw_sock


def connect_tls_pinned_ip(
    ip: str,
    port: int,
    *,
    server_hostname: str,
    ssl_context: ssl.SSLContext | None = None,
    timeout: float = 5.0,
) -> ssl.SSLSocket:
    """Connect TCP directly to a pre-validated IP and wrap with strict TLS SNI verification."""
    ctx = ssl_context or build_strict_tls_context()
    raw_sock = connect_tcp_pinned_ip(ip, port, timeout=timeout)
    try:
        return ctx.wrap_socket(raw_sock, server_hostname=server_hostname)
    except Exception:
        raw_sock.close()
        raise


class HostVaultMemory:
    """In-memory host secret store; never writes secrets to disk or logs secret values."""

    def __init__(self, initial: dict[str, str] | None = None):
        self._lock = threading.Lock()
        self._secrets: dict[str, str] = {}
        if initial:
            for ref, value in initial.items():
                self.set(ref, value)

    def set(self, secret_ref: str, value: str) -> None:
        if type(secret_ref) is not str or not secret_ref.strip():
            raise BrokerPolicyError("secret_ref must be a non-empty string")
        if type(value) is not str or len(value) < MIN_SECRET_LEN:
            raise BrokerPolicyError(
                f"Host vault secret for {secret_ref!r} must be at least {MIN_SECRET_LEN} characters"
            )
        with self._lock:
            self._secrets[secret_ref] = value

    def get(self, secret_ref: str) -> str:
        with self._lock:
            if secret_ref not in self._secrets:
                raise BrokerPolicyError(f"Secret reference not loaded in host vault: {secret_ref!r}")
            return self._secrets[secret_ref]

    def has(self, secret_ref: str) -> bool:
        with self._lock:
            return secret_ref in self._secrets

    def assert_distinct_refs(self, ro_ref: str, rw_ref: str, *, label: str = "RO/RW") -> None:
        if ro_ref == rw_ref:
            raise BrokerPolicyError(f"{label} secret references must be distinct")
        ro_val = self.get(ro_ref)
        rw_val = self.get(rw_ref)
        if hmac.compare_digest(ro_val, rw_val):
            raise BrokerPolicyError(f"{label} resolved secret values must be strictly distinct")

    @staticmethod
    def assert_distinct_pg_credentials(
        ro_user: str, ro_password: str, rw_user: str, rw_password: str
    ) -> None:
        if hmac.compare_digest(ro_user, rw_user):
            raise BrokerPolicyError("Upstream Postgres RO and RW database roles must be distinct")
        if hmac.compare_digest(ro_password, rw_password):
            raise BrokerPolicyError("Upstream Postgres RO and RW passwords must be distinct")


def _secret_canary_needles(secret_values: Iterable[str]) -> tuple[bytes, ...]:
    needles: set[bytes] = set()
    for val in secret_values:
        if type(val) is not str or len(val) < MIN_SECRET_LEN:
            continue
        raw = val.encode("utf-8")
        needles.update(
            (
                raw,
                quote(val, safe="").encode("ascii"),
                quote_plus(val).encode("ascii"),
                base64.b64encode(raw).rstrip(b"="),
                base64.urlsafe_b64encode(raw).rstrip(b"="),
            )
        )
    return tuple(sorted(needles, key=len, reverse=True))


class OverlapCanaryScanner:
    """Streaming overlap-window scanner catching raw, URL-encoded, and base64 secret forms."""

    def __init__(self, secret_values: Iterable[str]):
        self._needles = _secret_canary_needles(secret_values)
        self._overlap = max((len(n) for n in self._needles), default=1) - 1
        self._tail = b""

    def feed(self, chunk: bytes) -> bytes:
        if not chunk or not self._needles:
            return chunk
        window = self._tail + chunk
        for needle in self._needles:
            if needle in window:
                raise CanaryLeakError("Upstream response blocked: secret canary detected")
        if self._overlap <= 0:
            return window
        if len(window) <= self._overlap:
            self._tail = window
            return b""
        emit = window[: -self._overlap]
        self._tail = window[-self._overlap :]
        return emit

    def finish(self) -> bytes:
        tail = self._tail
        self._tail = b""
        for needle in self._needles:
            if needle in tail:
                raise CanaryLeakError("Upstream response blocked: secret canary detected")
        return tail

    def scan_bytes(self, data: bytes) -> bytes:
        out = self.feed(data)
        return out + self.finish()


@dataclass(frozen=True, slots=True)
class PgUpstreamCancelTarget:
    ip: str
    port: int
    server_hostname: str
    real_pid: int
    real_key: int
    ssl_context: ssl.SSLContext | None = None


def generate_ocjob_token() -> str:
    return f"ocjob_{secrets.token_hex(32)}"


_UMASK_LOCK = threading.Lock()


def _unlink_uds_socket_only(sock_path: Path) -> None:
    try:
        st = os.lstat(sock_path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise BrokerPolicyError(f"Refusing to unlink non-socket path: {sock_path}")
    sock_path.unlink()


def cleanup_uds_socket(sock_path: Path | None) -> None:
    if sock_path is None:
        return
    try:
        _unlink_uds_socket_only(sock_path)
    except (OSError, BrokerPolicyError):
        pass


def _assert_existing_ancestor_chain_trusted(target_dir: Path, *, sandbox_root: Path | None) -> None:
    """Verify every existing ancestor of target_dir is owned by current user/root and not world-writable."""
    uid = os.geteuid()
    cur = target_dir
    while not cur.exists():
        if cur.parent == cur:
            break
        cur = cur.parent
    while True:
        ast = os.lstat(cur)
        if not stat.S_ISDIR(ast.st_mode) or stat.S_ISLNK(ast.st_mode):
            raise BrokerPolicyError(f"Expected non-symlink ancestor directory: {cur}")
        if ast.st_uid not in (uid, 0):
            raise BrokerPolicyError(f"Untrusted ancestor owner for {target_dir}: {cur}")
        if (ast.st_mode & 0o022) and not (ast.st_uid == 0 and (ast.st_mode & stat.S_ISVTX)):
            raise BrokerPolicyError(f"Writable ancestor directory for {target_dir}: {cur}")
        if cur.parent == cur:
            break
        cur = cur.parent
    _ = sandbox_root


def bind_trusted_uds(
    raw_socket_path: Path,
    *,
    sandbox_root: Path | None = None,
    backlog: int = 32,
) -> tuple[socket.socket, Path]:
    """Verify trust boundaries before creating/binding a 0o600 UDS under a shared umask lock."""
    from oc_schema import (
        PolicyError,
        assert_trusted_dir,
        check_not_host_production_dir,
        check_not_in_sandbox,
    )

    sock_p = Path(raw_socket_path)
    if sock_p.name in ("", ".", ".."):
        raise BrokerPolicyError(f"Invalid UDS socket path: {sock_p}")
    if sock_p.is_symlink() or sock_p.parent.is_symlink():
        raise BrokerPolicyError(f"Symlink UDS path or parent rejected: {sock_p}")
    try:
        phys_parent = check_not_in_sandbox(sock_p.parent, sandbox_root)
        check_not_in_sandbox(sock_p, sandbox_root)
        check_not_host_production_dir(sock_p.parent)
        if phys_parent.is_symlink():
            raise BrokerPolicyError(f"Symlink UDS parent rejected: {phys_parent}")
        if phys_parent.exists():
            # Verify existing directory BEFORE ever modifying permissions.
            trusted_parent = assert_trusted_dir(phys_parent, sandbox_root=sandbox_root)
        else:
            _assert_existing_ancestor_chain_trusted(phys_parent, sandbox_root=sandbox_root)
            phys_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(phys_parent, 0o700)
            trusted_parent = assert_trusted_dir(phys_parent, sandbox_root=sandbox_root)
    except PolicyError as exc:
        raise BrokerPolicyError(str(exc)) from exc

    phys_sock = trusted_parent / sock_p.name
    _unlink_uds_socket_only(phys_sock)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with _UMASK_LOCK:
            old_umask = os.umask(0o177)
            try:
                srv.bind(str(phys_sock))
            finally:
                os.umask(old_umask)
        os.chmod(phys_sock, 0o600)
        srv.listen(backlog)
        srv.settimeout(0.2)
        return srv, phys_sock
    except Exception:
        srv.close()
        raise


def bind_loopback_tcp(host: str, port: int, *, backlog: int = 32) -> tuple[socket.socket, int]:
    """Bind a loopback-only TCP listener supporting both IPv4 (127.0.0.1) and IPv6 (::1)."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise BrokerPolicyError(f"TCP listener host must be a loopback IP: {host!r}") from exc
    if not addr.is_loopback:
        raise BrokerPolicyError(f"TCP listener host must be loopback: {host!r}")
    family = socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
    srv = socket.socket(family, socket.SOCK_STREAM)
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((str(addr), port))
        srv.listen(backlog)
        srv.settimeout(0.2)
        bound_port = int(srv.getsockname()[1])
        return srv, bound_port
    except Exception:
        srv.close()
        raise


def _safe_shutdown(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


def _safe_shutdown_close(sock: socket.socket) -> None:
    _safe_shutdown(sock)
    try:
        sock.close()
    except OSError:
        pass


class BrokerLease:
    """Per-job broker lease binding a disposable ocjob_ token to oc_controller.Controller."""

    def __init__(
        self,
        job_id: str,
        *,
        ocjob_token: str | None = None,
        controller: Any = None,
        controller_actor: Any = None,
        controller_request_id: str | None = None,
    ):
        self.job_id = job_id
        self.ocjob_token = ocjob_token or generate_ocjob_token()
        if not self.ocjob_token.startswith("ocjob_") or len(self.ocjob_token) < 38:
            raise BrokerPolicyError("ocjob_token must start with 'ocjob_' and carry >=128 bits entropy")
        self._controller = controller
        self._controller_actor = controller_actor
        self._controller_request_id = controller_request_id

        self._lock = threading.Lock()
        self._revoked = False
        self._active_streams: set[socket.socket] = set()
        self._pg_cancel_map: dict[tuple[int, int], PgUpstreamCancelTarget] = {}
        self._revoke_callbacks: list[Callable[[], None]] = []
        self._watch_stop = threading.Event()
        self._watch_thread: threading.Thread | None = None

    def _controller_allows(self) -> bool:
        if self._controller is None or self._controller_request_id is None:
            return True
        try:
            st = self._controller.status(self._controller_actor, self._controller_request_id)
        except Exception:
            return False
        return bool(st.eligible and not st.revoked)

    def is_active(self) -> bool:
        with self._lock:
            if self._revoked:
                return False
        if not self._controller_allows():
            self.revoke()
            return False
        return True

    def verify_token(self, candidate: str) -> bool:
        if type(candidate) is not str:
            return False
        return hmac.compare_digest(candidate, self.ocjob_token)

    def register_stream(self, sock: socket.socket) -> None:
        controller_ok = self._controller_allows()
        with self._lock:
            if self._revoked or not controller_ok:
                self._revoked = True
                active = False
            else:
                self._active_streams.add(sock)
                active = True
        if not active:
            _safe_shutdown_close(sock)
            self.revoke()
            raise BrokerAuthError("lease_revoked_or_expired")

    def unregister_stream(self, sock: socket.socket) -> None:
        with self._lock:
            self._active_streams.discard(sock)

    def add_revoke_callback(self, callback: Callable[[], None]) -> None:
        already_revoked = False
        with self._lock:
            if self._revoked:
                already_revoked = True
            else:
                self._revoke_callbacks.append(callback)
        if already_revoked:
            try:
                callback()
            except Exception:
                pass

    def remove_revoke_callback(self, callback: Callable[[], None]) -> None:
        with self._lock:
            try:
                self._revoke_callbacks.remove(callback)
            except ValueError:
                pass

    def register_pg_cancel(self, target: PgUpstreamCancelTarget) -> tuple[int, int]:
        with self._lock:
            if self._revoked:
                raise BrokerAuthError("lease_revoked_or_expired")
            while True:
                local_pid = secrets.randbelow(0x7FFF_FFFE) + 1
                local_key = secrets.randbelow(0x7FFF_FFFE) + 1
                pair = (local_pid, local_key)
                if pair not in self._pg_cancel_map:
                    self._pg_cancel_map[pair] = target
                    return pair

    def lookup_pg_cancel(self, local_pid: int, local_key: int) -> PgUpstreamCancelTarget | None:
        if not self.is_active():
            return None
        with self._lock:
            return self._pg_cancel_map.get((local_pid, local_key))

    def unregister_pg_cancel(self, local_pid: int, local_key: int) -> None:
        with self._lock:
            self._pg_cancel_map.pop((local_pid, local_key), None)

    def revoke(self) -> None:
        with self._lock:
            self._revoked = True
            streams = list(self._active_streams)
            self._active_streams.clear()
            callbacks = list(self._revoke_callbacks)
            self._revoke_callbacks.clear()
            self._pg_cancel_map.clear()
        for cb in callbacks:
            try:
                cb()
            except Exception:
                pass
        for sock in streams:
            _safe_shutdown(sock)

    def start_watchdog(self, *, poll_interval: float = 0.05) -> None:
        if self._watch_thread is not None and self._watch_thread.is_alive():
            return
        self._watch_stop.clear()

        def _loop() -> None:
            while not self._watch_stop.wait(poll_interval):
                if not self.is_active():
                    return

        self._watch_thread = threading.Thread(target=_loop, daemon=True)
        self._watch_thread.start()

    def stop_watchdog(self) -> None:
        self._watch_stop.set()
        if self._watch_thread is not None:
            self._watch_thread.join(timeout=1.0)
            self._watch_thread = None
