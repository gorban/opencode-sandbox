"""Schema validation, trust-boundary checks, and canonical hashing for PRD L spike PoC.

Pure Python standard library only. Never touches real ~/.config/oc-sandbox/.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tomllib
from typing import Any
from urllib.parse import quote, urlparse, urlsplit

from oc_broker_common import BrokerPolicyError, validate_allowed_cidrs

SCHEMA_VERSION = 1

OPAQUE_ID_RE = re.compile(
    r"^[a-z0-9][a-z0-9_-]{0,31}(?:/[a-z0-9][a-z0-9_-]{0,31})?$",
    re.ASCII,
)
SIMPLE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$", re.ASCII)
SLOT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$", re.ASCII)
PROPOSAL_ID_RE = re.compile(r"^prop_[0-9a-f]{16}$", re.ASCII)
SECRET_REF_GRAMMAR_RE = re.compile(r"^[a-z][a-z0-9_-]{0,23}:[a-zA-Z0-9._/@:-]{1,128}$", re.ASCII)
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.ASCII)
NUMERIC_LABEL_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|\d+)$", re.ASCII)
DIGEST_IMAGE_RE = re.compile(
    r"^[a-z0-9][a-z0-9._/:@-]{1,200}@sha256:[0-9a-f]{64}$",
    re.ASCII,
)
CAPABILITY_NAME_RE = re.compile(r"^cap:[a-z0-9][a-z0-9._-]{0,63}$", re.ASCII)
CAPABILITY_PROVIDES_RE = re.compile(
    r"^(cap:[a-z0-9][a-z0-9._-]{0,63})@(\d+\.\d+(?:\.\d+)?)$",
    re.ASCII,
)
CAPABILITY_REQUIRES_RE = re.compile(
    r"^(cap:[a-z0-9][a-z0-9._-]{0,63})@(\^|>=|==)?(\d+\.\d+(?:\.\d+)?)$",
    re.ASCII,
)
MISE_TOOL_KEY_RE = re.compile(
    r"^(?:core|aqua|github|cargo|dotnet|npm|conda):[A-Za-z0-9._/@-]{1,96}$",
    re.ASCII,
)
MISE_EXACT_VERSION_RE = re.compile(
    r"^v?\d+\.\d+\.\d+(?:[+-][A-Za-z0-9._-]{1,32})?$",
    re.ASCII,
)
SECRET_REF_VALUE_RE = re.compile(r"^\{file:/run/secrets/[a-z0-9][a-z0-9_-]{0,47}\}$", re.ASCII)
SECRET_SLOT_EXTRACT_RE = re.compile(r"\{file:/run/secrets/([a-z0-9][a-z0-9_-]{0,47})\}", re.ASCII)
RAW_SECRET_PREFIXES = ("sk-ant-", "sk-", "AIza", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-")
RAW_SECRET_RE = re.compile(
    r"(?:^|[\s=:'\"(\[,])(" + "|".join(re.escape(p) for p in RAW_SECRET_PREFIXES) + r")"
)
MEM_LIMIT_RE = re.compile(r"^[1-9]\d{0,5}[mMgG]$", re.ASCII)
HOST_URL_SCHEMES = frozenset({"http", "https", "postgresql", "redis", "tcp"})
HOST_URL_PLACEHOLDERS = frozenset({"host", "port", "user", "db", "path"})
TEMPLATE_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}", re.ASCII)
SLOT_TOKEN_RE = re.compile(r"\{\{([a-z0-9][a-z0-9_-]{0,31})\}\}")

READABLE_ORCHESTRATOR_KINDS = frozenset(
    {"sandbox-type", "bundle", "service", "worker", "host-provider", "transport"}
)
MUTABLE_ORCHESTRATOR_KINDS = frozenset({"sandbox-type", "bundle", "service"})
PROPOSAL_ACTIONS = frozenset({"upsert", "archive", "unarchive"})

EXPOSURE_LEVELS = ("pod-only", "host-loopback", "instance-dns")
EXPOSURE_RANK = {name: idx for idx, name in enumerate(EXPOSURE_LEVELS)}

SECURITY_PROFILES = frozenset({"standard", "desktop-wayland", "elevated-nested"})
TLS_POLICIES = frozenset({"none", "optional", "required-when-ca-ready"})
CARDINALITIES = frozenset({"singleton", "named-instance"})
TIERS = frozenset({"interactive", "managed"})
TOPOLOGIES = frozenset({"pod-shared", "isolated-sidecars"})

CREDENTIAL_DELIVERY_MODES = frozenset({"host-brokered", "local-ephemeral", "raw-container-mount"})
INBOUND_AUTH_MODES = frozenset({"bearer", "basic-token", "aws-sigv4-job-key", "header"})
BODY_POLICIES = frozenset({"none", "mcp-jsonrpc", "graphql-query-only", "aws-sigv4"})
HTTP_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
SENSITIVE_HTTP_HEADERS = frozenset(
    {
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "cookie",
        "proxy-authorization",
        "x-auth-token",
        "x-access-token",
    }
)
BROKER_SERVICE_KINDS = frozenset({"http", "postgres", "ssh"})
FORBIDDEN_INBOUND_AUTH_HEADERS = frozenset(
    {"host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer"}
)
HEADER_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$", re.ASCII)
DB_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$", re.ASCII)
SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.ASCII)
ROUTE_ID_RE = re.compile(r"^(?:mcp|http|pg|ssh):[a-z0-9][a-z0-9_-]{0,31}$", re.ASCII)

# Exact closed set of security_delta triggers (PRD L + PRD L1)
SECURITY_DELTA_TRIGGERS = frozenset(
    {
        "security_profile_elevation",
        "exposure_widened",
        "auth_requirement_changed",
        "new_service_added",
        "service_image_changed",
        "new_mcp_server_added",
        "mcp_tool_surface_widened",
        "new_mise_tool_added",
        "persona_changed",
        "remote_endpoint_added",
        "remote_write_granted",
        "raw_remote_secret_mounted",
        "secret_slot_added",
        "resource_limit_increased",
    }
)

FORBIDDEN_ENV_EXACT = frozenset(
    {
        "PATH",
        "HOME",
        "SHELL",
        "IFS",
        "ENV",
        "BASH_ENV",
        "NODE_OPTIONS",
        "SSH_AUTH_SOCK",
        "OPENCODE_CONFIG",
        "OPENCODE_CONFIG_DIR",
        "OPENCODE_CONFIG_CONTENT",
        "BROWSER",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
    }
)
FORBIDDEN_ENV_PREFIXES = (
    "LD_",
    "PYTHON",
    "GIT_",
    "MISE_",
    "DBUS_",
    "OPENCODE_",
)
FORBIDDEN_ENV_SUFFIXES = (
    "_API_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
    "_PRIVATE_KEY",
)

MAX_CONFIG_FILE_BYTES = 65_536
MAX_SLOT_FILE_BYTES = 16_384
MAX_INSTRUCTIONS_TOTAL_BYTES = 16_384
MAX_MISSION_BYTES = 16_384
MAX_MISE_MANIFESTS = 64
MAX_MISE_TOOLS = 64
MAX_DAG_NODES = 64


class SchemaError(ValueError):
    """Validation failure against schema_version = 1 or trust boundary rules."""


class PolicyError(ValueError):
    """Security policy violation (exposure, auth, fallback escalation, forbidden resource)."""


def parse_toml_strict(text: str, *, context: str = "TOML") -> dict[str, Any]:
    try:
        parsed = tomllib.loads(text)
    except ValueError as exc:
        raise SchemaError(f"Malformed {context}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SchemaError(f"{context} root must be a table")
    return parsed


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_canonical_json(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def validate_opaque_id(value: object, *, label: str = "id") -> str:
    if type(value) is not str or OPAQUE_ID_RE.fullmatch(value) is None:
        raise SchemaError(f"Invalid {label}: {value!r}")
    return value


def is_builtin_id(obj_id: str) -> bool:
    return obj_id.startswith("builtin/")


def security_profile_allows_fallback(primary: str, fallback: str) -> bool:
    """Partial order: 'standard' is bottom; 'desktop-wayland' and 'elevated-nested' are incomparable."""
    if primary not in SECURITY_PROFILES or fallback not in SECURITY_PROFILES:
        return False
    return fallback == "standard" or fallback == primary


def security_profile_elevates(old_profile: str, new_profile: str) -> bool:
    """True if new_profile is not <= old_profile in the partial order."""
    return not security_profile_allows_fallback(old_profile, new_profile)


def parse_mem_bytes(spec: str) -> int:
    if type(spec) is not str or MEM_LIMIT_RE.fullmatch(spec) is None:
        raise SchemaError(f"Invalid memory limit: {spec!r}")
    num = int(spec[:-1])
    unit = spec[-1].lower()
    return num * (1024**2 if unit == "m" else 1024**3)


def _is_under(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents


def _init_path_worklist(raw: Path) -> deque[str]:
    parts = raw.parts[1:] if raw.is_absolute() else (*Path.cwd().parts[1:], *raw.parts)
    return deque(p for p in parts if p not in ("", "."))


def _assert_not_under(candidate: Path, forbidden_roots: list[Path], label: str) -> None:
    for froot in forbidden_roots:
        if _is_under(candidate, froot):
            raise PolicyError(f"Refusing host-trusted path traversing {label}: {candidate}")


def _is_symlink_path(candidate: Path) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(candidate).st_mode)
    except OSError:
        return False


def _expand_symlink_hop(cur: Path, worklist: deque[str]) -> Path:
    target = Path(os.readlink(cur))
    if target.is_absolute():
        next_cur = Path("/")
        tparts = [tp for tp in target.parts[1:] if tp not in ("", ".")]
    else:
        next_cur = cur.parent
        tparts = [tp for tp in target.parts if tp not in ("", ".")]
    for tp in reversed(tparts):
        worklist.appendleft(tp)
    return next_cur


def _walk_check_not_under_roots(
    path: Path,
    forbidden_roots: list[Path],
    label: str,
) -> Path:
    """Kernel-equivalent component worklist resolving symlinks and '..' in kernel order.

    Checks every intermediate component, '..' step, and symlink target against forbidden_roots,
    and returns the resulting verified physical Path without calling os.path.abspath() first.
    """
    worklist = _init_path_worklist(Path(path))
    cur = Path("/")
    _assert_not_under(cur, forbidden_roots, label)
    total_hops = 0
    while worklist:
        part = worklist.popleft()
        if part in ("", "."):
            continue
        cur = cur.parent if part == ".." else cur / part
        _assert_not_under(cur, forbidden_roots, label)
        if part == ".." or not _is_symlink_path(cur):
            continue
        total_hops += 1
        if total_hops > 40:
            raise PolicyError(f"Too many symlink hops checking trusted path: {path}")
        cur = _expand_symlink_hop(cur, worklist)
        _assert_not_under(cur, forbidden_roots, label)
    return cur


def _expand_root_variants(root: Path) -> list[Path]:
    raw = Path(os.path.abspath(str(root)))
    resolved = root.resolve()
    return [raw] if raw == resolved else [raw, resolved]


def check_not_in_sandbox(path: Path, sandbox_root: Path | None = None) -> Path:
    """Kernel-order component walk rejecting any prefix, '..' hop, or symlink hop inside $SB."""
    sb_base = sandbox_root or (Path.home() / "opencode-sandbox")
    roots = _expand_root_variants(sb_base)
    physical = _walk_check_not_under_roots(path, roots, "sandbox root")
    for froot in roots:
        if _is_under(physical, froot):
            raise PolicyError(f"Refusing host-trusted path inside sandbox root: {physical}")
    return physical


def check_not_host_production_dir(path: Path) -> Path:
    """Refuse initializing or accessing real host oc-sandbox config/data directories from the spike PoC."""
    candidates: list[Path] = [
        Path.home() / ".config" / "oc-sandbox",
        Path.home() / ".local" / "share" / "oc-sandbox",
    ]
    xdg_cfg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if xdg_cfg:
        candidates.append(Path(xdg_cfg) / "oc-sandbox")
    xdg_data = os.environ.get("XDG_DATA_HOME", "").strip()
    if xdg_data:
        candidates.append(Path(xdg_data) / "oc-sandbox")

    roots: list[Path] = []
    for cand in candidates:
        for variant in _expand_root_variants(cand):
            if variant not in roots:
                roots.append(variant)
    physical = _walk_check_not_under_roots(path, roots, "host production config directory")
    for froot in roots:
        if _is_under(physical, froot):
            raise PolicyError(f"Refusing PoC store inside host production directory: {physical}")
    return physical


def assert_trusted_dir(path: Path, *, sandbox_root: Path | None = None) -> Path:
    physical = check_not_in_sandbox(path, sandbox_root)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise PolicyError(f"Expected non-symlink directory: {path}")
    uid = os.geteuid()
    if st.st_uid != uid:
        raise PolicyError(f"Directory not owned by current user: {path}")
    if st.st_mode & 0o077:
        raise PolicyError(f"Directory permissions too open (require 0700): {path}")
    # Walk ancestors ensuring no group/world-writable non-sticky directories
    cur = physical.parent
    while True:
        ast = os.lstat(cur)
        if ast.st_uid not in (uid, 0):
            raise PolicyError(f"Untrusted ancestor owner for {path}: {cur}")
        if (ast.st_mode & 0o022) and not (ast.st_uid == 0 and (ast.st_mode & stat.S_ISVTX)):
            raise PolicyError(f"Writable ancestor directory for {path}: {cur}")
        if cur.parent == cur:
            break
        cur = cur.parent
    return physical


def _resolve_confined_parts(path: Path, confined_root: Path | None) -> tuple[Path, tuple[str, ...]]:
    effective_root = path.parent if confined_root is None else confined_root
    root_real = effective_root.resolve()
    try:
        rel = path.relative_to(effective_root)
    except ValueError:
        try:
            rel = path.relative_to(root_real)
        except ValueError as exc:
            raise PolicyError(f"Path escapes confined root: {path}") from exc
    if rel.is_absolute() or ".." in rel.parts or not rel.parts:
        raise PolicyError(f"Invalid or root-equal confined path: {path}")
    return root_real, rel.parts


def _open_confined_fd(path: Path, confined_root: Path | None) -> int:
    root_real, parts = _resolve_confined_parts(path, confined_root)
    dir_fd = os.open(root_real, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = nxt
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PolicyError(f"Symlink rejected in confined path: {path}") from exc
        raise
    finally:
        os.close(dir_fd)


def _read_verified_fd(fd: int, path: Path, max_bytes: int, require_owner_only: bool) -> bytes:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise PolicyError(f"Non-regular file rejected: {path}")
    if st.st_nlink != 1:
        raise PolicyError(f"Hardlinked file rejected: {path}")
    if st.st_uid != os.geteuid():
        raise PolicyError(f"File not owned by current user: {path}")
    if require_owner_only and (st.st_mode & 0o077):
        raise PolicyError(f"File permissions too open (require 0600): {path}")
    if st.st_mode & 0o022:
        raise PolicyError(f"Group/world-writable file rejected: {path}")
    if st.st_size > max_bytes:
        raise SchemaError(f"File exceeds {max_bytes} byte limit: {path}")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, 8192)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise SchemaError(f"File exceeded {max_bytes} byte limit during read: {path}")
        chunks.append(chunk)
    return b"".join(chunks)


def read_regular_no_follow(
    path: Path,
    *,
    max_bytes: int = MAX_CONFIG_FILE_BYTES,
    require_owner_only: bool = False,
    confined_root: Path | None = None,
    sandbox_root: Path | None = None,
) -> bytes:
    """Open regular file via confined dir_fd without following symlinks and verify metadata."""
    check_not_in_sandbox(path, sandbox_root)
    fd = _open_confined_fd(path, confined_root)
    try:
        return _read_verified_fd(fd, path, max_bytes, require_owner_only)
    finally:
        os.close(fd)


def _reject_unknown_keys(data: dict[str, Any], allowed: frozenset[str], context: str) -> None:
    extra = sorted(set(data.keys()) - allowed)
    if extra:
        raise SchemaError(f"Unknown keys in {context}: {', '.join(extra)}")


def _require_str(value: object, context: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str:
        raise SchemaError(f"{context} must be a string")
    if not allow_empty and not value.strip():
        raise SchemaError(f"{context} must be non-empty")
    return value


def _check_no_raw_secret_value(value: str, context: str) -> None:
    match = RAW_SECRET_RE.search(value)
    if match is not None:
        raise SchemaError(f"Raw secret prefix {match.group(1)!r} forbidden in {context}")


def validate_env_map(env: object, context: str) -> dict[str, str]:
    if env is None:
        return {}
    if not isinstance(env, dict):
        raise SchemaError(f"{context} must be a table")
    out: dict[str, str] = {}
    for k, v in env.items():
        if type(k) is not str or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", k):
            raise SchemaError(f"Invalid env key in {context}: {k!r}")
        if (
            k in FORBIDDEN_ENV_EXACT
            or any(k.startswith(p) for p in FORBIDDEN_ENV_PREFIXES)
            or any(k.endswith(s) for s in FORBIDDEN_ENV_SUFFIXES)
        ):
            raise PolicyError(f"Forbidden env key in {context}: {k}")
        if type(v) is not str:
            raise SchemaError(f"Env value for {k} in {context} must be a string")
        _check_no_raw_secret_value(v, f"{context}.{k}")
        out[k] = v
    return out


def validate_host_url_template(template: str, context: str) -> str:
    _require_str(template, context)
    parsed = urlparse(template)
    if parsed.scheme not in HOST_URL_SCHEMES:
        raise SchemaError(f"Unsupported scheme in {context}: {parsed.scheme!r}")
    if any(ch in template for ch in ("\r", "\n", "\x00")):
        raise SchemaError(f"Control character forbidden in {context}")
    for match in TEMPLATE_PLACEHOLDER_RE.finditer(template):
        name = match.group(1)
        if name not in HOST_URL_PLACEHOLDERS:
            raise SchemaError(f"Disallowed placeholder {{{name}}} in {context}")
    return template


def render_host_url(template: str, values: dict[str, Any]) -> str:
    validate_host_url_template(template, "host_url_template")

    def _sub(match: re.Match[str]) -> str:
        key = match.group(1)
        raw = str(values.get(key, ""))
        if key in ("host", "port"):
            return raw
        if key == "path":
            return quote(raw, safe="/")
        return quote(raw, safe="")

    return TEMPLATE_PLACEHOLDER_RE.sub(_sub, template)


def validate_pod_local_url(url: str, context: str) -> str:
    """Validate strictly pod-local http://127.0.0.1:<port>/... URLs (forbids userinfo, authority tricks, port 9222)."""
    _require_str(url, context)
    if any(ch in url for ch in ("\r", "\n", "\x00", " ")):
        raise PolicyError(f"{context} contains illegal characters")
    parsed = urlparse(url)
    if parsed.scheme != "http":
        raise PolicyError(f"{context} must use http://127.0.0.1:<port>")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise PolicyError(f"{context} must not contain userinfo")
    if parsed.hostname != "127.0.0.1":
        raise PolicyError(f"{context} hostname must be exact 127.0.0.1, got {parsed.hostname!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise PolicyError(f"{context} has invalid port") from exc
    if port is None or not (1 <= port <= 65535):
        raise PolicyError(f"{context} must specify an explicit valid port")
    if port == 9222:
        raise PolicyError(f"{context} may not target pod Chromium DevTools port 9222")
    return url


def _ip_allowed_by_cidrs(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allowed_cidrs: tuple[str, ...]) -> bool:
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if ip.is_global:
        return True
    if not allowed_cidrs or not isinstance(ip, ipaddress.IPv4Address):
        return False
    return any(ip in ipaddress.ip_network(cidr, strict=True) for cidr in allowed_cidrs)


def _validate_remote_host(
    host: str,
    allowed_hosts: frozenset[str],
    *,
    allowed_cidrs: tuple[str, ...] = (),
) -> None:
    if not host or len(host) > 253:
        raise PolicyError("Remote endpoint missing or oversized hostname")
    if host in allowed_hosts:
        return
    if host in ("localhost", "host.containers.internal", "host.docker.internal") or host.endswith(
        ".localhost"
    ):
        raise PolicyError(f"Remote endpoint host {host!r} blocked by SSRF policy")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if not _ip_allowed_by_cidrs(ip, allowed_cidrs):
            raise PolicyError(f"Non-global remote endpoint IP {host!r} blocked by SSRF policy")
        return
    # Reject non-canonical numeric/octal/hex IPv4 forms (0177.0.0.1, 2130706433, 0x7f000001, 127.1)
    labels = host.split(".")
    if all(NUMERIC_LABEL_RE.fullmatch(lbl) is not None for lbl in labels):
        raise PolicyError(f"Non-canonical numeric IP host {host!r} blocked by SSRF policy")
    if NUMERIC_LABEL_RE.fullmatch(labels[-1]) is not None:
        raise PolicyError(f"Numeric TLD host {host!r} blocked by SSRF policy")
    if len(labels) < 2 or any(DNS_LABEL_RE.fullmatch(lbl) is None for lbl in labels):
        raise PolicyError(f"Invalid remote endpoint DNS hostname: {host!r}")


def validate_remote_endpoint_url(
    url: str,
    *,
    allow_http: bool = False,
    allowed_hosts: frozenset[str] = frozenset(),
    allowed_cidrs: tuple[str, ...] = (),
) -> str:
    _require_str(url, "remote endpoint")
    if any(ch in url for ch in ("\r", "\n", "\x00", " ")):
        raise PolicyError("Remote endpoint contains illegal characters")
    parsed = urlparse(url)
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme not in allowed_schemes:
        raise PolicyError(f"Remote endpoint scheme {parsed.scheme!r} not allowed")
    if parsed.params or ";" in urlsplit(url).path:
        raise PolicyError("Path parameters (';') forbidden in remote endpoint URL")
    if parsed.fragment:
        raise PolicyError("Fragment forbidden in remote endpoint URL")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise PolicyError("Credentials embedded in remote endpoint URL are forbidden")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise PolicyError("Remote endpoint has invalid port") from exc
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    _validate_remote_host(host, allowed_hosts, allowed_cidrs=allowed_cidrs)
    return url


def canonicalize_remote_url(
    url: str,
    *,
    allow_http: bool = False,
    allowed_hosts: frozenset[str] = frozenset(),
    allowed_cidrs: tuple[str, ...] = (),
) -> str:
    """Validate and canonicalize a remote endpoint URL for exact grant matching & Plan IR hashing."""
    validated = validate_remote_endpoint_url(
        url, allow_http=allow_http, allowed_hosts=allowed_hosts, allowed_cidrs=allowed_cidrs
    )
    parsed = urlsplit(validated)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    host_fmt = f"[{ip.compressed}]" if isinstance(ip, ipaddress.IPv6Address) else host
    port = parsed.port
    default_port = 443 if scheme == "https" else 80
    netloc = host_fmt if (port is None or port == default_port) else f"{host_fmt}:{port}"
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def validate_mise_tools(tools: object, context: str) -> dict[str, str]:
    if tools is None:
        return {}
    if not isinstance(tools, dict):
        raise SchemaError(f"{context} must be a table")
    out: dict[str, str] = {}
    for key, ver in tools.items():
        if type(key) is not str or MISE_TOOL_KEY_RE.fullmatch(key) is None:
            raise SchemaError(f"Invalid qualified mise tool key in {context}: {key!r}")
        if type(ver) is not str or MISE_EXACT_VERSION_RE.fullmatch(ver) is None:
            raise SchemaError(
                f"Mise tool {key!r} must use an exact three-part pinned version, got {ver!r}"
            )
        out[key] = ver
    return out


def _validate_endpoint(ep: object, context: str) -> dict[str, Any]:
    if not isinstance(ep, dict):
        raise SchemaError(f"{context} must be a table")
    _reject_unknown_keys(
        ep,
        frozenset(
            {
                "name",
                "port",
                "protocol",
                "default_exposure",
                "max_exposure",
                "requires_auth",
                "auth_enforcer",
                "tls_policy",
                "host_url_template",
            }
        ),
        context,
    )
    name = _require_str(ep.get("name"), f"{context}.name")
    if SIMPLE_NAME_RE.fullmatch(name) is None:
        raise SchemaError(f"Invalid endpoint name: {name!r}")
    port = ep.get("port")
    if type(port) is not int or not (1 <= port <= 65535):
        raise SchemaError(f"{context}.port must be an integer 1..65535")
    protocol = _require_str(ep.get("protocol", "tcp"), f"{context}.protocol")
    if protocol not in ("tcp", "http", "https", "postgres", "redis"):
        raise SchemaError(f"Unsupported protocol in {context}: {protocol!r}")
    default_exp = ep.get("default_exposure", "pod-only")
    max_exp = ep.get("max_exposure", default_exp)
    if default_exp not in EXPOSURE_RANK or max_exp not in EXPOSURE_RANK:
        raise SchemaError(f"Invalid exposure in {context}")
    if EXPOSURE_RANK[default_exp] > EXPOSURE_RANK[max_exp]:
        raise SchemaError(f"{context}.default_exposure exceeds max_exposure")
    requires_auth = ep.get("requires_auth", False)
    if type(requires_auth) is not bool:
        raise SchemaError(f"{context}.requires_auth must be boolean")
    auth_enforcer = ep.get("auth_enforcer")
    if auth_enforcer is not None:
        _require_str(auth_enforcer, f"{context}.auth_enforcer")
        if SIMPLE_NAME_RE.fullmatch(auth_enforcer) is None:
            raise SchemaError(f"Invalid auth_enforcer id: {auth_enforcer!r}")
    tls_policy = ep.get("tls_policy", "none")
    if tls_policy not in TLS_POLICIES:
        raise SchemaError(f"Invalid tls_policy in {context}: {tls_policy!r}")
    tpl = ep.get("host_url_template")
    if tpl is not None:
        validate_host_url_template(tpl, f"{context}.host_url_template")
    return {
        "name": name,
        "port": port,
        "protocol": protocol,
        "default_exposure": default_exp,
        "max_exposure": max_exp,
        "requires_auth": requires_auth,
        "auth_enforcer": auth_enforcer,
        "tls_policy": tls_policy,
        "host_url_template": tpl,
    }


def _validate_volume(vol: object, context: str, *, for_orchestrator: bool) -> dict[str, Any]:
    if not isinstance(vol, dict):
        raise SchemaError(f"{context} must be a table")
    _reject_unknown_keys(
        vol,
        frozenset({"name", "kind", "target", "durable", "read_only", "image"}),
        context,
    )
    kind = vol.get("kind", "named")
    if kind not in ("named", "tmpfs", "image"):
        raise PolicyError(f"Unsupported or forbidden volume kind in {context}: {kind!r}")
    name = _require_str(vol.get("name"), f"{context}.name")
    if SIMPLE_NAME_RE.fullmatch(name) is None:
        raise SchemaError(f"Invalid volume name in {context}: {name!r}")
    target = _require_str(vol.get("target"), f"{context}.target")
    if not target.startswith("/") or ".." in Path(target).parts or "\x00" in target:
        raise SchemaError(f"Invalid container mount target in {context}: {target!r}")
    durable = vol.get("durable", False)
    read_only = vol.get("read_only", kind == "image")
    if type(durable) is not bool or type(read_only) is not bool:
        raise SchemaError(f"{context} durable/read_only must be boolean")
    image = vol.get("image")
    if kind == "image":
        if type(image) is not str or DIGEST_IMAGE_RE.fullmatch(image) is None:
            raise SchemaError(f"{context}.image must be digest-pinned (@sha256:...)")
        if not read_only:
            raise PolicyError(f"Image mount in {context} must be read_only=true")
    elif image is not None:
        raise SchemaError(f"{context}.image only allowed for kind='image'")
    _ = for_orchestrator
    return {
        "name": name,
        "kind": kind,
        "target": target,
        "durable": durable,
        "read_only": read_only,
        "image": image,
    }


def _validate_optional_instance_and_port(
    inst: object, iport: object, context: str
) -> tuple[str | None, int | None]:
    if inst is not None and (type(inst) is not str or SIMPLE_NAME_RE.fullmatch(inst) is None):
        raise SchemaError(f"Invalid {context}.instance: {inst!r}")
    if iport is not None and (type(iport) is not int or not (1 <= iport <= 65535)):
        raise SchemaError(f"Invalid {context}.instance_port: {iport!r}")
    return inst, iport


def _validate_service_requirement(req: object, context: str) -> dict[str, Any]:
    if isinstance(req, str):
        if CAPABILITY_REQUIRES_RE.fullmatch(req) is None and OPAQUE_ID_RE.fullmatch(req) is None:
            raise SchemaError(f"Invalid {context} requirement: {req!r}")
        return {"target": req, "provider": None, "instance": None, "instance_port": None}
    if not isinstance(req, dict):
        raise SchemaError(f"{context} item must be string or table")
    _reject_unknown_keys(
        req,
        frozenset({"capability", "service", "provider", "instance", "instance_port"}),
        context,
    )
    target = req.get("capability") or req.get("service")
    if type(target) is not str:
        raise SchemaError(f"{context} entry must specify capability or service")
    if req.get("capability") and CAPABILITY_REQUIRES_RE.fullmatch(target) is None:
        raise SchemaError(f"Invalid capability requirement in {context}: {target!r}")
    if req.get("service"):
        validate_opaque_id(target, label=f"{context}.service")
    prov = req.get("provider")
    if prov is not None:
        validate_opaque_id(prov, label=f"{context}.provider")
    inst, iport = _validate_optional_instance_and_port(req.get("instance"), req.get("instance_port"), context)
    return {"target": target, "provider": prov, "instance": inst, "instance_port": iport}


def _validate_doc_header(
    doc: object,
    *,
    kind_name: str,
    kind_tag: str,
    allowed_keys: frozenset[str],
    expected_id: str | None,
    for_orchestrator: bool,
) -> str:
    if not isinstance(doc, dict):
        raise SchemaError(f"{kind_name} document must be a TOML table")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise SchemaError(f"{kind_name} schema_version must be {SCHEMA_VERSION}")
    if doc.get("kind") != kind_tag:
        raise SchemaError(f"{kind_name} kind must be {kind_tag!r}")
    if kind_name == "service" and ("factory" in doc or "implementation" in doc):
        raise PolicyError("Raw factory/implementation paths forbidden; use opaque factory_id")
    _reject_unknown_keys(doc, allowed_keys, kind_name)
    obj_id = validate_opaque_id(doc.get("id"), label=f"{kind_name}.id")
    if expected_id is not None and obj_id != expected_id:
        raise SchemaError(f"{kind_name}.id {obj_id!r} does not match expected {expected_id!r}")
    if for_orchestrator and is_builtin_id(obj_id):
        raise PolicyError(f"builtin/* {kind_name}s are strictly immutable")
    return obj_id


def _is_digest_image(ref: object) -> bool:
    return type(ref) is str and DIGEST_IMAGE_RE.fullmatch(ref) is not None


def _validate_images_by_arch(
    images_by_arch: object, context: str, arch_field: str
) -> dict[str, str]:
    if not isinstance(images_by_arch, dict) or not images_by_arch:
        raise SchemaError(f"{context}: {arch_field} must be a non-empty table")
    for arch, ref in images_by_arch.items():
        if arch not in ("x86_64", "arm64"):
            raise SchemaError(f"Unsupported arch in {arch_field}: {arch!r}")
        if not _is_digest_image(ref):
            raise SchemaError(f"{context}: {arch_field}.{arch} must be digest-pinned")
    return images_by_arch


def _validate_digest_images(
    image: object,
    images_by_arch: object,
    *,
    context: str,
    image_field: str = "image",
    arch_field: str = "images_by_arch",
) -> tuple[str | None, dict[str, str] | None]:
    if image is not None and not _is_digest_image(image):
        raise SchemaError(f"{context}: {image_field} must be digest-pinned (@sha256:...)")
    norm_by_arch = (
        _validate_images_by_arch(images_by_arch, context, arch_field)
        if images_by_arch is not None
        else None
    )
    if image is None and norm_by_arch is None:
        raise SchemaError(f"{context} requires digest-pinned {image_field} or {arch_field}")
    return image, norm_by_arch


def _validate_service_resources(resources: object, svc_id: str) -> dict[str, Any]:
    if not isinstance(resources, dict):
        raise SchemaError(f"service {svc_id} must declare bounded resources table")
    _reject_unknown_keys(resources, frozenset({"memory", "pids_limit"}), "service.resources")
    mem = _require_str(resources.get("memory"), "service.resources.memory")
    parse_mem_bytes(mem)
    pids = resources.get("pids_limit")
    if type(pids) is not int or not (16 <= pids <= 4096):
        raise SchemaError("service.resources.pids_limit must be an int in 16..4096")
    return {"memory": mem, "pids_limit": pids}


def _validate_secret_slots(secret_slots: object) -> list[dict[str, Any]]:
    if not isinstance(secret_slots, list):
        raise SchemaError("service.secret_slots must be a list")
    norm_secrets: list[dict[str, Any]] = []
    for i, slot in enumerate(secret_slots):
        if not isinstance(slot, dict):
            raise SchemaError(f"service.secret_slots[{i}] must be a table")
        _reject_unknown_keys(slot, frozenset({"slot", "target", "mode", "secret_ref"}), f"secret_slots[{i}]")
        sname = _require_str(slot.get("slot"), f"secret_slots[{i}].slot")
        if SLOT_NAME_RE.fullmatch(sname) is None:
            raise SchemaError(f"Invalid secret slot name: {sname!r}")
        starget = _require_str(slot.get("target"), f"secret_slots[{i}].target")
        if not starget.startswith("/run/secrets/") or ".." in Path(starget).parts:
            raise PolicyError(f"Secret target must be under /run/secrets/: {starget!r}")
        smode = slot.get("mode", "0400")
        if smode not in ("0400", "0600"):
            raise SchemaError(f"Secret mode must be '0400' or '0600', got {smode!r}")
        sref = _require_str(slot.get("secret_ref"), f"secret_slots[{i}].secret_ref")
        _check_no_raw_secret_value(sref, f"secret_slots[{i}].secret_ref")
        if SECRET_REF_GRAMMAR_RE.fullmatch(sref) is None:
            raise SchemaError(
                f"secret_slots[{i}].secret_ref must match '<scheme>:<reference>' grammar, got {sref!r}"
            )
        norm_secrets.append({"slot": sname, "target": starget, "mode": smode, "secret_ref": sref})
    return norm_secrets


def _validate_readiness_probe(probe: object, *, for_orchestrator: bool) -> dict[str, Any] | None:
    if probe is None:
        return None
    if not isinstance(probe, dict):
        raise SchemaError("service.readiness_probe must be a table")
    _reject_unknown_keys(probe, frozenset({"kind", "port", "command"}), "service.readiness_probe")
    pkind = probe.get("kind")
    if pkind not in ("tcp", "exec_auth", "http_local"):
        raise SchemaError(f"Unsupported readiness_probe.kind: {pkind!r}")
    pport = probe.get("port")
    if pport is not None and (type(pport) is not int or not (1 <= pport <= 65535)):
        raise SchemaError("service.readiness_probe.port must be int 1..65535")
    pcmd = probe.get("command")
    if pcmd is not None:
        if for_orchestrator:
            raise PolicyError("Orchestrator proposals may not specify custom readiness_probe.command")
        if (
            not isinstance(pcmd, list)
            or not pcmd
            or any(type(a) is not str or not a or "\x00" in a for a in pcmd)
        ):
            raise SchemaError("service.readiness_probe.command must be non-empty list of strings")
    return {"kind": pkind, "port": pport, "command": list(pcmd) if pcmd is not None else None}


def _validate_service_capabilities(doc: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]], str | None, list[str]]:
    provides = doc.get("provides", [])
    if not isinstance(provides, list):
        raise SchemaError("service.provides must be a list")
    for cap in provides:
        if type(cap) is not str or CAPABILITY_PROVIDES_RE.fullmatch(cap) is None:
            raise SchemaError(f"Invalid capability provide spec: {cap!r}")
    requires = doc.get("requires", [])
    if not isinstance(requires, list):
        raise SchemaError("service.requires must be a list")
    norm_requires = [_validate_service_requirement(r, "service.requires[]") for r in requires]
    fallback = doc.get("fallback_service")
    if fallback is not None:
        validate_opaque_id(fallback, label="service.fallback_service")
    req_caps = doc.get("required_capabilities", [])
    if not isinstance(req_caps, list) or any(
        type(c) is not str or SIMPLE_NAME_RE.fullmatch(c) is None for c in req_caps
    ):
        raise SchemaError("service.required_capabilities must be a list of capability identifiers")
    return list(provides), norm_requires, fallback, list(req_caps)


_SERVICE_ALLOWED_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "id",
        "description",
        "image",
        "images_by_arch",
        "provides",
        "requires",
        "cardinality",
        "instance_port",
        "fallback_service",
        "required_capabilities",
        "security_profile",
        "factory_id",
        "resources",
        "endpoints",
        "volumes",
        "secret_slots",
        "env",
        "readiness_probe",
        "mise_tools",
        "post_install_hook",
    }
)


def validate_service_doc(
    doc: dict[str, Any],
    *,
    expected_id: str | None = None,
    for_orchestrator: bool = False,
) -> dict[str, Any]:
    svc_id = _validate_doc_header(
        doc,
        kind_name="service",
        kind_tag="service@1",
        allowed_keys=_SERVICE_ALLOWED_KEYS,
        expected_id=expected_id,
        for_orchestrator=for_orchestrator,
    )
    image, images_by_arch = _validate_digest_images(
        doc.get("image"), doc.get("images_by_arch"), context=f"service {svc_id}"
    )
    if doc.get("post_install_hook") is not None and for_orchestrator:
        raise PolicyError("Orchestrator proposals may not define post_install_hook")

    factory_id = doc.get("factory_id")
    if factory_id is not None and (type(factory_id) is not str or SIMPLE_NAME_RE.fullmatch(factory_id) is None):
        raise SchemaError(f"Invalid opaque factory_id: {factory_id!r}")

    sec_profile = doc.get("security_profile", "standard")
    if sec_profile not in SECURITY_PROFILES:
        raise SchemaError(f"Invalid security_profile: {sec_profile!r}")

    cardinality = doc.get("cardinality", "singleton")
    if cardinality not in CARDINALITIES:
        raise SchemaError(f"Invalid cardinality: {cardinality!r}")
    instance_port = doc.get("instance_port")
    if instance_port is not None and (type(instance_port) is not int or not 1 <= instance_port <= 65535):
        raise SchemaError("instance_port must be 1..65535")

    provides, norm_requires, fallback, req_caps = _validate_service_capabilities(doc)
    resources = _validate_service_resources(doc.get("resources"), svc_id)
    endpoints = [_validate_endpoint(e, f"service({svc_id}).endpoints[{i}]") for i, e in enumerate(doc.get("endpoints", []))]
    volumes = [
        _validate_volume(v, f"service({svc_id}).volumes[{i}]", for_orchestrator=for_orchestrator)
        for i, v in enumerate(doc.get("volumes", []))
    ]
    norm_secrets = _validate_secret_slots(doc.get("secret_slots", []))
    env = validate_env_map(doc.get("env"), f"service({svc_id}).env")
    mise_tools = validate_mise_tools(doc.get("mise_tools"), f"service({svc_id}).mise_tools")
    norm_probe = _validate_readiness_probe(doc.get("readiness_probe"), for_orchestrator=for_orchestrator)

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "service@1",
        "id": svc_id,
        "description": str(doc.get("description", "")),
        "image": image,
        "images_by_arch": images_by_arch,
        "provides": provides,
        "requires": norm_requires,
        "cardinality": cardinality,
        "instance_port": instance_port,
        "fallback_service": fallback,
        "required_capabilities": req_caps,
        "security_profile": sec_profile,
        "factory_id": factory_id,
        "resources": resources,
        "endpoints": endpoints,
        "volumes": volumes,
        "secret_slots": norm_secrets,
        "env": env,
        "readiness_probe": norm_probe,
        "mise_tools": mise_tools,
    }


def has_sensitive_headers(headers: dict[str, str]) -> bool:
    return any(hk.lower() in SENSITIVE_HTTP_HEADERS for hk in headers)


def _validate_mcp_headers(headers: object, context: str) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise SchemaError(f"{context} must be a table")
    norm_headers: dict[str, str] = {}
    for hk, hv in headers.items():
        if type(hk) is not str or type(hv) is not str:
            raise SchemaError(f"Invalid header in {context}")
        if hk.lower() in SENSITIVE_HTTP_HEADERS:
            if (
                not (hv.startswith("Bearer ") and SECRET_REF_VALUE_RE.fullmatch(hv[7:]))
                and SECRET_REF_VALUE_RE.fullmatch(hv) is None
            ):
                raise PolicyError(
                    f"Sensitive header {hk!r} in {context} must use {{file:/run/secrets/<slot>}}"
                )
        else:
            _check_no_raw_secret_value(hv, f"{context}.{hk}")
        norm_headers[hk] = hv
    return norm_headers


def _validate_mcp_secret_env(secret_env: object, context: str) -> dict[str, str]:
    if secret_env is None:
        return {}
    if not isinstance(secret_env, dict):
        raise SchemaError(f"{context} must be a table")
    out: dict[str, str] = {}
    for ek, ev in secret_env.items():
        if type(ek) is not str or type(ev) is not str or SECRET_REF_VALUE_RE.fullmatch(ev) is None:
            raise PolicyError(f"MCP secret_env {ek!r} in {context} must use {{file:/run/secrets/<slot>}}")
        out[ek] = ev
    return out


def extract_secret_slots(headers: dict[str, str], secret_env: dict[str, str]) -> set[str]:
    slots: set[str] = set()
    for val in list(headers.values()) + list(secret_env.values()):
        for m in SECRET_SLOT_EXTRACT_RE.finditer(val):
            slots.add(m.group(1))
    return slots


def _validate_tool_list(raw: object, context: str) -> list[str]:
    if not isinstance(raw, list) or any(type(t) is not str or SIMPLE_NAME_RE.fullmatch(t) is None for t in raw):
        raise SchemaError(f"{context} must be a list of tool identifiers")
    return list(raw)


def _validate_schema_allowed_cidrs(raw: object, context: str) -> list[str]:
    if raw is None:
        return []
    try:
        return list(validate_allowed_cidrs(raw, context=context))
    except BrokerPolicyError as exc:
        raise PolicyError(str(exc)) from exc


def _validate_path_glob(pat: object, context: str) -> str:
    if type(pat) is not str or not pat.startswith("/") or len(pat) > 256:
        raise SchemaError(f"{context} must be a path glob starting with '/'")
    if any(ord(ch) < 0x21 or ord(ch) >= 0x7F or ch in "\\?#;%" for ch in pat):
        raise PolicyError(f"Illegal character in path glob {context}: {pat!r}")
    if "//" in pat or "**" in pat:
        raise PolicyError(f"Empty segment or cross-segment '**' forbidden in {context}: {pat!r}")
    if pat != "/":
        for seg in pat[1:].split("/"):
            if seg in ("", ".", ".."):
                raise PolicyError(f"Invalid path segment in {context}: {pat!r}")
    return pat


def _validate_wire_allow_rule(rule: object, context: str) -> dict[str, Any]:
    if not isinstance(rule, dict):
        raise SchemaError(f"{context} must be a table")
    _reject_unknown_keys(rule, frozenset({"methods", "path_patterns", "body_policy"}), context)
    methods = rule.get("methods")
    if not isinstance(methods, list) or not methods or any(type(m) is not str or m not in HTTP_METHODS for m in methods):
        raise SchemaError(f"{context}.methods must be a non-empty list of HTTP methods")
    patterns = rule.get("path_patterns")
    if not isinstance(patterns, list) or not patterns:
        raise SchemaError(f"{context}.path_patterns must be a non-empty list of path globs")
    norm_patterns = [_validate_path_glob(p, f"{context}.path_patterns[{i}]") for i, p in enumerate(patterns)]
    body_policy = rule.get("body_policy", "none")
    if type(body_policy) is not str or body_policy not in BODY_POLICIES:
        raise SchemaError(f"Invalid {context}.body_policy: {body_policy!r}")
    return {
        "methods": list(methods),
        "path_patterns": norm_patterns,
        "body_policy": body_policy,
    }


def validate_wire_policy(raw: object, context: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SchemaError(f"{context} must be a table")
    _reject_unknown_keys(raw, frozenset({"denied_paths", "allow_rules"}), context)
    raw_denied = raw.get("denied_paths", [])
    if not isinstance(raw_denied, list):
        raise SchemaError(f"{context}.denied_paths must be a list")
    denied_paths = [_validate_path_glob(p, f"{context}.denied_paths[{i}]") for i, p in enumerate(raw_denied)]
    raw_rules = raw.get("allow_rules")
    if not isinstance(raw_rules, list):
        raise SchemaError(f"{context}.allow_rules must be a list")
    allow_rules = [_validate_wire_allow_rule(r, f"{context}.allow_rules[{i}]") for i, r in enumerate(raw_rules)]
    return {"denied_paths": denied_paths, "allow_rules": allow_rules}


def _validate_inbound_auth(
    raw_mode: object, raw_header: object, context: str
) -> tuple[str, str | None]:
    mode = "bearer" if raw_mode is None else raw_mode
    if type(mode) is not str or mode not in INBOUND_AUTH_MODES:
        raise SchemaError(f"Invalid {context}.inbound_auth: {mode!r}")
    if mode == "header":
        if type(raw_header) is not str or HEADER_NAME_RE.fullmatch(raw_header) is None:
            raise SchemaError(f"{context}.inbound_auth_header must be a valid HTTP header name when inbound_auth='header'")
        if raw_header.lower() in FORBIDDEN_INBOUND_AUTH_HEADERS:
            raise PolicyError(f"Forbidden {context}.inbound_auth_header: {raw_header!r}")
        return mode, raw_header
    if raw_header is not None:
        raise SchemaError(f"{context}.inbound_auth_header is only allowed when inbound_auth='header'")
    return mode, None


def _validate_allow_streaming(raw: object, context: str) -> bool:
    if raw is None:
        return False
    if type(raw) is not bool:
        raise SchemaError(f"{context}.allow_streaming must be boolean")
    return raw


def _validate_credential_delivery(
    raw: object, context: str, *, for_orchestrator: bool
) -> str | None:
    if raw is None:
        return None
    if type(raw) is not str or raw not in CREDENTIAL_DELIVERY_MODES:
        raise SchemaError(f"Invalid {context}.credential_delivery: {raw!r}")
    if for_orchestrator and raw == "raw-container-mount":
        raise PolicyError(
            f"Orchestrator proposals may not request credential_delivery='raw-container-mount' in {context}"
        )
    return raw


def default_concourse_wire_policy() -> dict[str, Any]:
    return {
        "denied_paths": [
            "/api/v1/teams/*/containers/*/hijack",
            "/api/v1/teams/*/containers/*/hijack/*",
        ],
        "allow_rules": [
            {
                "methods": ["GET", "HEAD"],
                "path_patterns": [
                    "/api/v1/info",
                    "/api/v1/teams/*/pipelines",
                    "/api/v1/teams/*/pipelines/*",
                    "/api/v1/teams/*/pipelines/*/jobs",
                    "/api/v1/teams/*/pipelines/*/jobs/*",
                    "/api/v1/teams/*/pipelines/*/jobs/*/builds",
                    "/api/v1/builds",
                    "/api/v1/builds/*",
                    "/api/v1/builds/*/plan",
                    "/api/v1/builds/*/events",
                    "/api/v1/teams/*/builds",
                    "/api/v1/teams/*/builds/*",
                ],
                "body_policy": "none",
            }
        ],
    }


def default_k8s_wire_policy() -> dict[str, Any]:
    return {
        "denied_paths": [
            "/api/v1/secrets",
            "/api/v1/secrets/*",
            "/api/v1/namespaces/*/secrets",
            "/api/v1/namespaces/*/secrets/*",
            "/api/v1/namespaces/*/pods/*/exec",
            "/api/v1/namespaces/*/pods/*/exec/*",
            "/api/v1/namespaces/*/pods/*/attach",
            "/api/v1/namespaces/*/pods/*/attach/*",
            "/api/v1/namespaces/*/pods/*/portforward",
            "/api/v1/namespaces/*/pods/*/portforward/*",
            "/api/v1/namespaces/*/pods/*/proxy",
            "/api/v1/namespaces/*/pods/*/proxy/*",
            "/api/v1/namespaces/*/services/*/proxy",
            "/api/v1/namespaces/*/services/*/proxy/*",
        ],
        "allow_rules": [
            {
                "methods": ["GET", "HEAD"],
                "path_patterns": [
                    "/version",
                    "/api",
                    "/apis",
                    "/api/v1/namespaces/*/pods",
                    "/api/v1/namespaces/*/pods/*",
                    "/api/v1/namespaces/*/pods/*/log",
                    "/api/v1/namespaces/*/events",
                    "/api/v1/namespaces/*/events/*",
                    "/api/v1/namespaces/*/services",
                    "/api/v1/namespaces/*/services/*",
                    "/apis/apps/v1/namespaces/*/deployments",
                    "/apis/apps/v1/namespaces/*/deployments/*",
                ],
                "body_policy": "none",
            }
        ],
    }


def default_sonarqube_wire_policy() -> dict[str, Any]:
    return {
        "denied_paths": [],
        "allow_rules": [
            {
                "methods": ["GET", "HEAD"],
                "path_patterns": [
                    "/api/qualitygates/*",
                    "/api/issues/search",
                    "/api/measures/component",
                    "/api/measures/component_tree",
                    "/api/hotspots/search",
                ],
                "body_policy": "none",
            }
        ],
    }


def default_github_wire_policy() -> dict[str, Any]:
    return {
        "denied_paths": [],
        "allow_rules": [
            {
                "methods": ["GET", "HEAD"],
                "path_patterns": [
                    "/repos/*/*",
                    "/repos/*/*/pulls",
                    "/repos/*/*/pulls/*",
                    "/repos/*/*/pulls/*/files",
                    "/repos/*/*/pulls/*/comments",
                    "/repos/*/*/issues",
                    "/repos/*/*/issues/*",
                    "/repos/*/*/issues/*/comments",
                    "/repos/*/*/commits",
                    "/repos/*/*/commits/*",
                ],
                "body_policy": "none",
            },
            {
                "methods": ["POST"],
                "path_patterns": ["/graphql"],
                "body_policy": "graphql-query-only",
            },
        ],
    }


def default_aws_wire_policy() -> dict[str, Any]:
    return {
        "denied_paths": [],
        "allow_rules": [
            {
                "methods": ["GET", "HEAD", "POST"],
                "path_patterns": ["/", "/*", "/*/*", "/*/*/*"],
                "body_policy": "aws-sigv4",
            }
        ],
    }


def default_mcp_wire_policy(*, allow_streaming: bool = False) -> dict[str, Any]:
    rules: list[dict[str, Any]] = [
        {"methods": ["POST"], "path_patterns": ["/"], "body_policy": "mcp-jsonrpc"}
    ]
    if allow_streaming:
        rules.append({"methods": ["GET"], "path_patterns": ["/"], "body_policy": "none"})
    return {"denied_paths": [], "allow_rules": rules}


_WIRE_POLICY_PRESET_BUILDERS = {
    "concourse": default_concourse_wire_policy,
    "k8s": default_k8s_wire_policy,
    "sonarqube": default_sonarqube_wire_policy,
    "github": default_github_wire_policy,
    "aws": default_aws_wire_policy,
    "mcp": default_mcp_wire_policy,
}


def get_default_wire_policy_preset(name: str) -> dict[str, Any]:
    builder = _WIRE_POLICY_PRESET_BUILDERS.get(name)
    if builder is None:
        raise SchemaError(f"Unknown wire_policy preset: {name!r}")
    return builder()


def _validate_mcp_target(
    name: str,
    cfg: dict[str, Any],
    context: str,
    *,
    for_orchestrator: bool,
    allowed_cidrs: tuple[str, ...] = (),
) -> tuple[str, str | None]:
    mtype = cfg.get("type")
    if mtype not in ("remote", "pinned-artifact"):
        raise PolicyError(f"MCP {name} must use type 'remote' or 'pinned-artifact', got {mtype!r}")
    if mtype == "remote":
        url = _require_str(cfg.get("url"), f"{context}.{name}.url")
        scheme = urlparse(url).scheme
        if scheme == "http":
            return mtype, validate_pod_local_url(url, f"{context}.{name}.url")
        if scheme == "https":
            return mtype, canonicalize_remote_url(url, allow_http=False, allowed_cidrs=allowed_cidrs)
        raise PolicyError(f"MCP {name} remote url must be https:// or pod-local http://127.0.0.1:<port>")
    art = _require_str(cfg.get("artifact_id"), f"{context}.{name}.artifact_id")
    if OPAQUE_ID_RE.fullmatch(art) is None:
        raise SchemaError(f"Invalid MCP artifact_id: {art!r}")
    if for_orchestrator and not is_builtin_id(art):
        raise PolicyError("Orchestrator MCP proposals must reference registered builtin/* artifacts")
    return mtype, None


def _validate_mcp_tool_sets(
    name: str, cfg: dict[str, Any], context: str
) -> tuple[list[str], list[str] | None, list[str]]:
    raw_ro = cfg.get("read_only_tools")
    raw_wr = cfg.get("write_tools")
    raw_tools = cfg.get("tools")
    if raw_ro is None and raw_wr is None:
        tools = _validate_tool_list(raw_tools if raw_tools is not None else [], f"{context}.{name}.tools")
        return tools, None, []
    read_only_tools = _validate_tool_list(raw_ro if raw_ro is not None else [], f"{context}.{name}.read_only_tools")
    write_tools = _validate_tool_list(raw_wr if raw_wr is not None else [], f"{context}.{name}.write_tools")
    overlap = sorted(set(read_only_tools) & set(write_tools))
    if overlap:
        raise SchemaError(f"{context}.{name} read_only_tools and write_tools overlap: {', '.join(overlap)}")
    combined = list(dict.fromkeys(read_only_tools + write_tools))
    if raw_tools is None:
        return combined, read_only_tools, write_tools
    explicit_tools = _validate_tool_list(raw_tools, f"{context}.{name}.tools")
    if set(explicit_tools) != set(combined):
        raise SchemaError(
            f"{context}.{name}.tools must equal read_only_tools U write_tools when both are specified"
        )
    return explicit_tools, read_only_tools, write_tools


def _validate_mcp_local_cfg(name: str, local_cfg: object, context: str) -> dict[str, Any] | None:
    if local_cfg is None:
        return None
    if not isinstance(local_cfg, dict):
        raise SchemaError(f"{context}.{name}.local must be a table")
    _reject_unknown_keys(
        local_cfg,
        frozenset({"binding_key", "service", "url", "headers", "secret_env"}),
        f"{context}.{name}.local",
    )
    bkey = _require_str(local_cfg.get("binding_key"), f"{context}.{name}.local.binding_key")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", bkey):
        raise SchemaError(f"Invalid local.binding_key: {bkey!r}")
    return {
        "binding_key": bkey,
        "service": validate_opaque_id(local_cfg.get("service"), label=f"{context}.{name}.local.service"),
        "url": validate_pod_local_url(local_cfg.get("url"), f"{context}.{name}.local.url"),
        "headers": _validate_mcp_headers(local_cfg.get("headers"), f"{context}.{name}.local.headers"),
        "secret_env": _validate_mcp_secret_env(local_cfg.get("secret_env"), f"{context}.{name}.local.secret_env"),
    }


def _validate_mcp_remote_cfg(
    name: str,
    remote_cfg: object,
    context: str,
    *,
    norm_headers: dict[str, str],
    norm_secret_env: dict[str, str],
    norm_local: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if remote_cfg is None:
        return None
    if not isinstance(remote_cfg, dict):
        raise SchemaError(f"{context}.{name}.remote must be a table")
    _reject_unknown_keys(
        remote_cfg,
        frozenset({"read_only_headers", "read_only_secret_env", "write_headers", "write_secret_env"}),
        f"{context}.{name}.remote",
    )
    ro_headers = _validate_mcp_headers(
        remote_cfg.get("read_only_headers"), f"{context}.{name}.remote.read_only_headers"
    )
    ro_secret_env = _validate_mcp_secret_env(
        remote_cfg.get("read_only_secret_env"), f"{context}.{name}.remote.read_only_secret_env"
    )
    wr_headers = _validate_mcp_headers(
        remote_cfg.get("write_headers"), f"{context}.{name}.remote.write_headers"
    )
    wr_secret_env = _validate_mcp_secret_env(
        remote_cfg.get("write_secret_env"), f"{context}.{name}.remote.write_secret_env"
    )
    # Enforce strict credential-slot separation across local, remote-RO, and remote-RW
    top_slots = extract_secret_slots(norm_headers, norm_secret_env)
    local_slots = (
        extract_secret_slots(norm_local["headers"], norm_local["secret_env"])
        if norm_local is not None
        else set()
    )
    ro_slots = extract_secret_slots(ro_headers, ro_secret_env)
    wr_slots = extract_secret_slots(wr_headers, wr_secret_env)
    if wr_slots & (ro_slots | local_slots | top_slots):
        shared = sorted(wr_slots & (ro_slots | local_slots | top_slots))
        raise PolicyError(
            f"MCP {name} remote write secret slot(s) must be distinct from read-only/local slots: {', '.join(shared)}"
        )
    if ro_slots & (local_slots | top_slots):
        shared = sorted(ro_slots & (local_slots | top_slots))
        raise PolicyError(
            f"MCP {name} remote read-only secret slot(s) must be distinct from local slots: {', '.join(shared)}"
        )
    return {
        "read_only_headers": ro_headers,
        "read_only_secret_env": ro_secret_env,
        "write_headers": wr_headers,
        "write_secret_env": wr_secret_env,
    }


def _resolve_pinned_artifact_delivery(
    name: str,
    raw_delivery: str | None,
    norm_headers: dict[str, str],
    norm_secret_env: dict[str, str],
) -> str:
    if raw_delivery == "host-brokered":
        raise PolicyError(f"pinned-artifact MCP {name!r} cannot use credential_delivery='host-brokered'")
    if not (norm_secret_env or has_sensitive_headers(norm_headers)):
        return raw_delivery or "local-ephemeral"
    if raw_delivery not in ("local-ephemeral", "raw-container-mount"):
        raise PolicyError(
            f"pinned-artifact MCP {name!r} with secret_env or sensitive headers requires explicit "
            f"credential_delivery='local-ephemeral' or interactive break-glass 'raw-container-mount'"
        )
    return raw_delivery


def _resolve_mcp_credential_delivery(
    name: str,
    mtype: str,
    norm_url: str | None,
    norm_local: dict[str, Any] | None,
    raw_delivery: str | None,
    norm_headers: dict[str, str],
    norm_secret_env: dict[str, str],
) -> str | None:
    if mtype == "pinned-artifact":
        return _resolve_pinned_artifact_delivery(name, raw_delivery, norm_headers, norm_secret_env)
    if (norm_url or "").startswith("https://"):
        if raw_delivery == "local-ephemeral":
            raise PolicyError(f"Remote MCP {name!r} cannot use credential_delivery='local-ephemeral'")
        return raw_delivery or "host-brokered"
    if norm_local is not None:
        return raw_delivery
    return raw_delivery or "local-ephemeral"


_MCP_ALLOWED_KEYS = frozenset(
    {
        "type",
        "url",
        "artifact_id",
        "args",
        "headers",
        "secret_env",
        "tools",
        "read_only_tools",
        "write_tools",
        "local",
        "remote",
        "credential_delivery",
        "inbound_auth",
        "inbound_auth_header",
        "allow_streaming",
        "allowed_cidrs",
        "wire_policy",
    }
)


def _validate_mcp_server(name: str, cfg: object, context: str, *, for_orchestrator: bool) -> dict[str, Any]:
    if SIMPLE_NAME_RE.fullmatch(name) is None:
        raise SchemaError(f"Invalid MCP server name in {context}: {name!r}")
    if not isinstance(cfg, dict):
        raise SchemaError(f"{context}.{name} must be a table")
    _reject_unknown_keys(cfg, _MCP_ALLOWED_KEYS, f"{context}.{name}")
    allowed_cidrs = _validate_schema_allowed_cidrs(cfg.get("allowed_cidrs"), f"{context}.{name}.allowed_cidrs")
    mtype, norm_url = _validate_mcp_target(
        name, cfg, context, for_orchestrator=for_orchestrator, allowed_cidrs=tuple(allowed_cidrs)
    )
    args = cfg.get("args", [])
    if not isinstance(args, list) or any(type(a) is not str for a in args):
        raise SchemaError(f"{context}.{name}.args must be list of strings")
    norm_headers = _validate_mcp_headers(cfg.get("headers"), f"{context}.{name}.headers")
    norm_secret_env = _validate_mcp_secret_env(cfg.get("secret_env"), f"{context}.{name}.secret_env")
    tools, read_only_tools, write_tools = _validate_mcp_tool_sets(name, cfg, context)
    norm_local = _validate_mcp_local_cfg(name, cfg.get("local"), context)
    norm_remote = _validate_mcp_remote_cfg(
        name,
        cfg.get("remote"),
        context,
        norm_headers=norm_headers,
        norm_secret_env=norm_secret_env,
        norm_local=norm_local,
    )
    raw_delivery = _validate_credential_delivery(
        cfg.get("credential_delivery"), f"{context}.{name}", for_orchestrator=for_orchestrator
    )
    cred_delivery = _resolve_mcp_credential_delivery(
        name, mtype, norm_url, norm_local, raw_delivery, norm_headers, norm_secret_env
    )
    inbound_auth, inbound_auth_header = _validate_inbound_auth(
        cfg.get("inbound_auth"), cfg.get("inbound_auth_header"), f"{context}.{name}"
    )
    allow_streaming = _validate_allow_streaming(cfg.get("allow_streaming"), f"{context}.{name}")
    raw_wp = cfg.get("wire_policy")
    wire_policy = validate_wire_policy(raw_wp, f"{context}.{name}.wire_policy") if raw_wp is not None else None
    return {
        "type": mtype,
        "url": norm_url,
        "artifact_id": cfg.get("artifact_id"),
        "args": list(args),
        "headers": norm_headers,
        "secret_env": norm_secret_env,
        "tools": list(tools),
        "read_only_tools": read_only_tools,
        "write_tools": list(write_tools),
        "local": norm_local,
        "remote": norm_remote,
        "credential_delivery": cred_delivery,
        "inbound_auth": inbound_auth,
        "inbound_auth_header": inbound_auth_header,
        "allow_streaming": allow_streaming,
        "allowed_cidrs": allowed_cidrs,
        "wire_policy": wire_policy,
    }


def _validate_bundle_local_services(raw_items: list[Any]) -> list[dict[str, Any]]:
    local_services = []
    for i, item in enumerate(raw_items):
        if not isinstance(item, dict):
            raise SchemaError(f"bundle.local_services[{i}] must be a table")
        _reject_unknown_keys(
            item,
            frozenset({"binding_key", "service", "instance", "instance_port"}),
            f"local_services[{i}]",
        )
        bkey = _require_str(item.get("binding_key"), f"local_services[{i}].binding_key")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", bkey):
            raise SchemaError(f"Invalid local_services binding_key: {bkey!r}")
        lsvc = validate_opaque_id(item.get("service"), label=f"local_services[{i}].service")
        inst, iport = _validate_optional_instance_and_port(
            item.get("instance"), item.get("instance_port"), "local_services"
        )
        local_services.append({"binding_key": bkey, "service": lsvc, "instance": inst, "instance_port": iport})
    return local_services


def _validate_bundle_persona(persona: object, bid: str) -> dict[str, Any] | None:
    if persona is None:
        return None
    if not isinstance(persona, dict):
        raise SchemaError("bundle.persona must be a table")
    _reject_unknown_keys(
        persona,
        frozenset({"name", "mission", "authority", "allowed_mcp_tools", "denied_mcp_tools", "checklists"}),
        "bundle.persona",
    )
    pname = _require_str(persona.get("name"), "bundle.persona.name")
    if SIMPLE_NAME_RE.fullmatch(pname) is None:
        raise SchemaError(f"Invalid persona name: {pname!r}")
    mission = _require_str(persona.get("mission"), "bundle.persona.mission")
    _check_no_raw_secret_value(mission, f"bundle({bid}).persona.mission")
    if len(mission.encode("utf-8")) > MAX_MISSION_BYTES:
        raise SchemaError("bundle.persona.mission exceeds byte limit")
    auth = persona.get("authority", "implementer")
    if auth not in ("implementer", "reviewer", "triage", "ops-ro"):
        raise SchemaError(f"Invalid persona authority: {auth!r}")
    allowed_tools = persona.get("allowed_mcp_tools")
    if allowed_tools is not None and (
        not isinstance(allowed_tools, list) or any(type(t) is not str for t in allowed_tools)
    ):
        raise SchemaError("persona.allowed_mcp_tools must be a list of strings")
    denied_tools = persona.get("denied_mcp_tools", [])
    if not isinstance(denied_tools, list) or any(type(t) is not str for t in denied_tools):
        raise SchemaError("persona.denied_mcp_tools must be a list of strings")
    checklists = persona.get("checklists", {})
    if not isinstance(checklists, dict):
        raise SchemaError("persona.checklists must be a table")
    return {
        "name": pname,
        "mission": mission,
        "authority": auth,
        "allowed_mcp_tools": list(allowed_tools) if allowed_tools is not None else None,
        "denied_mcp_tools": list(denied_tools),
        "checklists": checklists,
    }


def _validate_bundle_subagents(subagents: object) -> list[dict[str, Any]]:
    if not isinstance(subagents, list):
        raise SchemaError("bundle.subagents must be a list")
    norm_subagents = []
    for sa in subagents:
        if not isinstance(sa, dict):
            raise SchemaError("bundle.subagents[] must be a table")
        _reject_unknown_keys(sa, frozenset({"name", "description", "authority"}), "bundle.subagents[]")
        saname = _require_str(sa.get("name"), "subagent.name")
        if SIMPLE_NAME_RE.fullmatch(saname) is None:
            raise SchemaError(f"Invalid subagent name: {saname!r}")
        norm_subagents.append(
            {
                "name": saname,
                "description": _require_str(sa.get("description"), "subagent.description"),
                "authority": sa.get("authority", "reviewer"),
            }
        )
    return norm_subagents


def _validate_bundle_prompt_slots(prompt_slots: object) -> dict[str, str]:
    if not isinstance(prompt_slots, dict):
        raise SchemaError("bundle.prompt_slots must be a table")
    norm_slots: dict[str, str] = {}
    for sk, sv in prompt_slots.items():
        if type(sk) is not str or SLOT_NAME_RE.fullmatch(sk) is None:
            raise SchemaError(f"Invalid prompt_slot key: {sk!r}")
        if type(sv) is not str or sv.startswith("/") or ".." in Path(sv).parts or not sv.endswith((".md", ".txt")):
            raise PolicyError(f"prompt_slot {sk!r} must be a relative .md/.txt file inside bundle root")
        norm_slots[sk] = sv
    return norm_slots


def _validate_optional_secret_ref(raw: object, context: str, *, required: bool = False) -> str | None:
    if raw is None:
        if required:
            raise SchemaError(f"{context} is required")
        return None
    sref = _require_str(raw, context)
    _check_no_raw_secret_value(sref, context)
    if SECRET_REF_GRAMMAR_RE.fullmatch(sref) is None:
        raise SchemaError(f"{context} must match '<scheme>:<reference>' grammar, got {sref!r}")
    return sref


def _validate_client_env_var(raw: object, context: str) -> str | None:
    if raw is None:
        return None
    if type(raw) is not str or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", raw):
        raise SchemaError(f"Invalid env var name in {context}: {raw!r}")
    if (
        raw in FORBIDDEN_ENV_EXACT
        or any(raw.startswith(p) for p in FORBIDDEN_ENV_PREFIXES)
        or any(raw.endswith(s) for s in FORBIDDEN_ENV_SUFFIXES)
    ):
        raise PolicyError(f"Forbidden env var name in {context}: {raw}")
    return raw


_BROKER_HTTP_KEYS = frozenset(
    {
        "kind",
        "upstream_url",
        "credential_delivery",
        "inbound_auth",
        "inbound_auth_header",
        "allow_streaming",
        "allowed_cidrs",
        "read_only_secret_ref",
        "write_secret_ref",
        "preset",
        "wire_policy",
        "client_env_var",
    }
)


def _validate_broker_http_service(
    name: str, cfg: dict[str, Any], context: str, *, for_orchestrator: bool
) -> dict[str, Any]:
    _reject_unknown_keys(cfg, _BROKER_HTTP_KEYS, context)
    allowed_cidrs = _validate_schema_allowed_cidrs(cfg.get("allowed_cidrs"), f"{context}.allowed_cidrs")
    upstream_url = canonicalize_remote_url(
        _require_str(cfg.get("upstream_url"), f"{context}.upstream_url"),
        allow_http=False,
        allowed_cidrs=tuple(allowed_cidrs),
    )
    raw_delivery = _validate_credential_delivery(
        cfg.get("credential_delivery"), context, for_orchestrator=for_orchestrator
    )
    cred_delivery = raw_delivery or "host-brokered"
    if cred_delivery == "local-ephemeral":
        raise PolicyError(f"External HTTP broker service {name!r} cannot use credential_delivery='local-ephemeral'")
    inbound_auth, inbound_auth_header = _validate_inbound_auth(
        cfg.get("inbound_auth"), cfg.get("inbound_auth_header"), context
    )
    allow_streaming = _validate_allow_streaming(cfg.get("allow_streaming"), context)
    ro_ref = _validate_optional_secret_ref(cfg.get("read_only_secret_ref"), f"{context}.read_only_secret_ref")
    wr_ref = _validate_optional_secret_ref(cfg.get("write_secret_ref"), f"{context}.write_secret_ref")
    if ro_ref is not None and wr_ref is not None and ro_ref == wr_ref:
        raise PolicyError(f"{context} read_only_secret_ref and write_secret_ref must be distinct")
    preset = cfg.get("preset")
    raw_wp = cfg.get("wire_policy")
    if raw_wp is not None:
        wire_policy = validate_wire_policy(raw_wp, f"{context}.wire_policy")
    elif preset is not None:
        if type(preset) is not str:
            raise SchemaError(f"{context}.preset must be a string")
        wire_policy = get_default_wire_policy_preset(preset)
    else:
        raise SchemaError(f"{context} must specify wire_policy or preset")
    client_env_var = _validate_client_env_var(cfg.get("client_env_var"), f"{context}.client_env_var")
    return {
        "kind": "http",
        "upstream_url": upstream_url,
        "credential_delivery": cred_delivery,
        "inbound_auth": inbound_auth,
        "inbound_auth_header": inbound_auth_header,
        "allow_streaming": allow_streaming,
        "allowed_cidrs": allowed_cidrs,
        "read_only_secret_ref": ro_ref,
        "write_secret_ref": wr_ref,
        "preset": preset,
        "wire_policy": wire_policy,
        "client_env_var": client_env_var,
    }


_BROKER_PG_KEYS = frozenset(
    {
        "kind",
        "host",
        "port",
        "database",
        "sslmode",
        "read_only_user",
        "read_only_secret_ref",
        "write_user",
        "write_secret_ref",
        "credential_delivery",
        "allowed_cidrs",
    }
)


def _validate_pg_write_creds(
    cfg: dict[str, Any], ro_user: str, ro_ref: str | None, context: str
) -> tuple[str | None, str | None]:
    wr_user = cfg.get("write_user")
    wr_ref = _validate_optional_secret_ref(cfg.get("write_secret_ref"), f"{context}.write_secret_ref")
    if (wr_user is None) != (wr_ref is None):
        raise SchemaError(f"{context} must specify both write_user and write_secret_ref together")
    if wr_user is None:
        return None, None
    if type(wr_user) is not str or DB_IDENT_RE.fullmatch(wr_user) is None:
        raise SchemaError(f"Invalid {context}.write_user: {wr_user!r}")
    if wr_user == ro_user:
        raise PolicyError(f"{context} write_user must be distinct from read_only_user")
    if wr_ref == ro_ref:
        raise PolicyError(f"{context} write_secret_ref must be distinct from read_only_secret_ref")
    return wr_user, wr_ref


def _validate_broker_postgres_service(
    name: str, cfg: dict[str, Any], context: str, *, for_orchestrator: bool
) -> dict[str, Any]:
    _reject_unknown_keys(cfg, _BROKER_PG_KEYS, context)
    allowed_cidrs = _validate_schema_allowed_cidrs(cfg.get("allowed_cidrs"), f"{context}.allowed_cidrs")
    host = _require_str(cfg.get("host"), f"{context}.host").strip().lower().rstrip(".")
    _validate_remote_host(host, frozenset(), allowed_cidrs=tuple(allowed_cidrs))
    port = cfg.get("port", 5432)
    if type(port) is not int or not (1 <= port <= 65535):
        raise SchemaError(f"{context}.port must be an integer 1..65535")
    database = _require_str(cfg.get("database"), f"{context}.database")
    if DB_IDENT_RE.fullmatch(database) is None:
        raise SchemaError(f"Invalid {context}.database: {database!r}")
    sslmode = cfg.get("sslmode", "verify-full")
    if sslmode != "verify-full":
        raise PolicyError(f"External Postgres broker service {name!r} requires sslmode='verify-full', got {sslmode!r}")
    ro_user = _require_str(cfg.get("read_only_user"), f"{context}.read_only_user")
    if DB_IDENT_RE.fullmatch(ro_user) is None:
        raise SchemaError(f"Invalid {context}.read_only_user: {ro_user!r}")
    ro_ref = _validate_optional_secret_ref(
        cfg.get("read_only_secret_ref"), f"{context}.read_only_secret_ref", required=True
    )
    wr_user, wr_ref = _validate_pg_write_creds(cfg, ro_user, ro_ref, context)
    raw_delivery = _validate_credential_delivery(
        cfg.get("credential_delivery"), context, for_orchestrator=for_orchestrator
    )
    cred_delivery = raw_delivery or "host-brokered"
    if cred_delivery == "local-ephemeral":
        raise PolicyError(f"External Postgres broker service {name!r} cannot use credential_delivery='local-ephemeral'")
    return {
        "kind": "postgres",
        "host": host,
        "port": port,
        "database": database,
        "sslmode": sslmode,
        "read_only_user": ro_user,
        "read_only_secret_ref": ro_ref,
        "write_user": wr_user,
        "write_secret_ref": wr_ref,
        "credential_delivery": cred_delivery,
        "allowed_cidrs": allowed_cidrs,
    }


_BROKER_SSH_KEYS = frozenset(
    {
        "kind",
        "host",
        "port",
        "user",
        "known_hosts_ref",
        "allowed_presets",
        "credential_delivery",
        "allowed_cidrs",
    }
)


def _validate_broker_ssh_service(
    name: str, cfg: dict[str, Any], context: str, *, for_orchestrator: bool
) -> dict[str, Any]:
    _reject_unknown_keys(cfg, _BROKER_SSH_KEYS, context)
    allowed_cidrs = _validate_schema_allowed_cidrs(cfg.get("allowed_cidrs"), f"{context}.allowed_cidrs")
    host = _require_str(cfg.get("host"), f"{context}.host").strip().lower().rstrip(".")
    _validate_remote_host(host, frozenset(), allowed_cidrs=tuple(allowed_cidrs))
    port = cfg.get("port", 22)
    if type(port) is not int or not (1 <= port <= 65535):
        raise SchemaError(f"{context}.port must be an integer 1..65535")
    user = _require_str(cfg.get("user"), f"{context}.user")
    if SSH_USER_RE.fullmatch(user) is None:
        raise SchemaError(f"Invalid {context}.user: {user!r}")
    kh_ref = _validate_optional_secret_ref(cfg.get("known_hosts_ref"), f"{context}.known_hosts_ref", required=True)
    presets = _validate_tool_list(cfg.get("allowed_presets"), f"{context}.allowed_presets")
    if not presets:
        raise SchemaError(f"{context}.allowed_presets must be non-empty")
    raw_delivery = _validate_credential_delivery(
        cfg.get("credential_delivery"), context, for_orchestrator=for_orchestrator
    )
    cred_delivery = raw_delivery or "host-brokered"
    if cred_delivery != "host-brokered":
        raise PolicyError(f"SSH broker service {name!r} must use credential_delivery='host-brokered'")
    return {
        "kind": "ssh",
        "host": host,
        "port": port,
        "user": user,
        "known_hosts_ref": kh_ref,
        "allowed_presets": presets,
        "credential_delivery": cred_delivery,
        "allowed_cidrs": allowed_cidrs,
    }


def _validate_broker_services(
    raw: object, context: str, *, for_orchestrator: bool
) -> dict[str, dict[str, Any]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise SchemaError(f"{context} must be a table")
    out: dict[str, dict[str, Any]] = {}
    for name, cfg in raw.items():
        if type(name) is not str or SIMPLE_NAME_RE.fullmatch(name) is None:
            raise SchemaError(f"Invalid broker_services name in {context}: {name!r}")
        if not isinstance(cfg, dict):
            raise SchemaError(f"{context}.{name} must be a table")
        kind = cfg.get("kind")
        if kind == "http":
            out[name] = _validate_broker_http_service(name, cfg, f"{context}.{name}", for_orchestrator=for_orchestrator)
        elif kind == "postgres":
            out[name] = _validate_broker_postgres_service(
                name, cfg, f"{context}.{name}", for_orchestrator=for_orchestrator
            )
        elif kind == "ssh":
            out[name] = _validate_broker_ssh_service(name, cfg, f"{context}.{name}", for_orchestrator=for_orchestrator)
        else:
            raise SchemaError(f"Unsupported broker_services kind in {context}.{name}: {kind!r}")
    return out


_BUNDLE_ALLOWED_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "id",
        "description",
        "includes",
        "composition",
        "requires_services",
        "local_services",
        "mcp",
        "broker_services",
        "skills",
        "persona",
        "subagents",
        "instructions",
        "prompt_slots",
        "mise_tools",
    }
)


def validate_bundle_doc(
    doc: dict[str, Any],
    *,
    expected_id: str | None = None,
    for_orchestrator: bool = False,
) -> dict[str, Any]:
    bid = _validate_doc_header(
        doc,
        kind_name="bundle",
        kind_tag="bundle@1",
        allowed_keys=_BUNDLE_ALLOWED_KEYS,
        expected_id=expected_id,
        for_orchestrator=for_orchestrator,
    )
    includes = [validate_opaque_id(x, label="bundle.includes[]") for x in doc.get("includes", [])]
    comp = doc.get("composition", {})
    if not isinstance(comp, dict):
        raise SchemaError("bundle.composition must be a table")
    _reject_unknown_keys(comp, frozenset({"replace"}), "bundle.composition")
    replace_list = comp.get("replace", [])
    if not isinstance(replace_list, list) or any(r not in ("persona", "mcp") for r in replace_list):
        raise SchemaError("bundle.composition.replace may only contain 'persona' or 'mcp'")

    req_services = [
        _validate_service_requirement(item, "bundle.requires_services[]")
        for item in doc.get("requires_services", [])
    ]
    local_services = _validate_bundle_local_services(doc.get("local_services", []))

    raw_mcp = doc.get("mcp", {})
    if not isinstance(raw_mcp, dict):
        raise SchemaError("bundle.mcp must be a table")
    mcp = {
        k: _validate_mcp_server(k, v, f"bundle({bid}).mcp", for_orchestrator=for_orchestrator)
        for k, v in raw_mcp.items()
    }
    broker_services = _validate_broker_services(
        doc.get("broker_services"), f"bundle({bid}).broker_services", for_orchestrator=for_orchestrator
    )
    skills = [validate_opaque_id(s, label="bundle.skills[]") for s in doc.get("skills", [])]
    norm_persona = _validate_bundle_persona(doc.get("persona"), bid)
    norm_subagents = _validate_bundle_subagents(doc.get("subagents", []))

    instructions = doc.get("instructions", [])
    if not isinstance(instructions, list) or any(type(x) is not str for x in instructions):
        raise SchemaError("bundle.instructions must be a list of strings")
    for text in instructions:
        _check_no_raw_secret_value(text, f"bundle({bid}).instructions")

    norm_slots = _validate_bundle_prompt_slots(doc.get("prompt_slots", {}))
    mise_tools = validate_mise_tools(doc.get("mise_tools"), f"bundle({bid}).mise_tools")

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "bundle@1",
        "id": bid,
        "description": str(doc.get("description", "")),
        "includes": includes,
        "composition": {"replace": list(replace_list)},
        "requires_services": req_services,
        "local_services": local_services,
        "mcp": mcp,
        "broker_services": broker_services,
        "skills": skills,
        "persona": norm_persona,
        "subagents": norm_subagents,
        "instructions": list(instructions),
        "prompt_slots": norm_slots,
        "mise_tools": mise_tools,
    }


def validate_port_request(entry: object, context: str) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise SchemaError(f"{context} must be a table")
    _reject_unknown_keys(entry, frozenset({"service", "endpoint", "exposure", "host_port"}), context)
    svc = entry.get("service")
    if type(svc) is not str or not svc:
        raise SchemaError(f"{context}.service must be a non-empty string")
    if "@" in svc:
        base_id, inst = svc.split("@", 1)
        validate_opaque_id(base_id, label=f"{context}.service")
        if SIMPLE_NAME_RE.fullmatch(inst) is None:
            raise SchemaError(f"Invalid service instance alias in {context}: {inst!r}")
    else:
        validate_opaque_id(svc, label=f"{context}.service")
    ep = _require_str(entry.get("endpoint"), f"{context}.endpoint")
    if SIMPLE_NAME_RE.fullmatch(ep) is None:
        raise SchemaError(f"Invalid endpoint name in {context}: {ep!r}")
    exp = entry.get("exposure", "host-loopback")
    if type(exp) is not str or exp not in EXPOSURE_RANK:
        raise SchemaError(f"Invalid port exposure in {context}: {exp!r}")
    hp = entry.get("host_port")
    if hp is not None and (type(hp) is not int or not (1024 <= hp <= 65535)):
        raise SchemaError(f"{context}.host_port must be an integer 1024..65535")
    return {"service": svc, "endpoint": ep, "exposure": exp, "host_port": hp}


_SANDBOX_TYPE_ALLOWED_KEYS = frozenset(
    {
        "schema_version",
        "kind",
        "id",
        "description",
        "tier",
        "topology",
        "base_image",
        "base_images_by_arch",
        "default_worker",
        "bundles",
        "default_agent",
        "ports",
        "mise_overrides",
        "factory_id",
    }
)


def validate_sandbox_type_doc(
    doc: dict[str, Any],
    *,
    expected_id: str | None = None,
    for_orchestrator: bool = False,
) -> dict[str, Any]:
    stid = _validate_doc_header(
        doc,
        kind_name="sandbox-type",
        kind_tag="sandbox-type@1",
        allowed_keys=_SANDBOX_TYPE_ALLOWED_KEYS,
        expected_id=expected_id,
        for_orchestrator=for_orchestrator,
    )
    tier = doc.get("tier", "managed")
    if tier not in TIERS:
        raise SchemaError(f"Invalid sandbox-type.tier: {tier!r}")
    topology = doc.get("topology", "isolated-sidecars" if tier == "managed" else "pod-shared")
    if topology not in TOPOLOGIES:
        raise SchemaError(f"Invalid sandbox-type.topology: {topology!r}")

    base_image, base_by_arch = _validate_digest_images(
        doc.get("base_image"),
        doc.get("base_images_by_arch"),
        context="sandbox-type",
        image_field="base_image",
        arch_field="base_images_by_arch",
    )
    default_worker = doc.get("default_worker", "builtin/local-workstation")
    validate_opaque_id(default_worker, label="sandbox-type.default_worker")
    bundles = [validate_opaque_id(b, label="sandbox-type.bundles[]") for b in doc.get("bundles", [])]

    default_agent = doc.get("default_agent")
    if default_agent is not None and (type(default_agent) is not str or SIMPLE_NAME_RE.fullmatch(default_agent) is None):
        raise SchemaError(f"Invalid default_agent: {default_agent!r}")

    ports = [validate_port_request(p, f"sandbox-type.ports[{i}]") for i, p in enumerate(doc.get("ports", []))]
    mise_overrides = validate_mise_tools(doc.get("mise_overrides"), "sandbox-type.mise_overrides")
    factory_id = doc.get("factory_id")
    if factory_id is not None and (type(factory_id) is not str or SIMPLE_NAME_RE.fullmatch(factory_id) is None):
        raise SchemaError(f"Invalid opaque factory_id: {factory_id!r}")

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "sandbox-type@1",
        "id": stid,
        "description": str(doc.get("description", "")),
        "tier": tier,
        "topology": topology,
        "base_image": base_image,
        "base_images_by_arch": base_by_arch,
        "default_worker": default_worker,
        "bundles": bundles,
        "default_agent": default_agent,
        "ports": ports,
        "mise_overrides": mise_overrides,
        "factory_id": factory_id,
    }


def validate_host_provider_doc(doc: dict[str, Any], *, expected_id: str | None = None) -> dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION or doc.get("kind") != "host-provider@1":
        raise SchemaError("Invalid host-provider@1 document")
    _reject_unknown_keys(
        doc,
        frozenset({"schema_version", "kind", "id", "description", "engine", "capabilities", "lease_limits"}),
        "host-provider",
    )
    hpid = validate_opaque_id(doc.get("id"), label="host-provider.id")
    if expected_id is not None and hpid != expected_id:
        raise SchemaError("host-provider.id mismatch")
    caps = doc.get("capabilities", {})
    if not isinstance(caps, dict):
        raise SchemaError("host-provider.capabilities must be a table")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "host-provider@1",
        "id": hpid,
        "description": str(doc.get("description", "")),
        "engine": _require_str(doc.get("engine"), "host-provider.engine"),
        "capabilities": dict(caps),
        "lease_limits": dict(doc.get("lease_limits", {})),
    }


def validate_transport_doc(doc: dict[str, Any], *, expected_id: str | None = None) -> dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION or doc.get("kind") != "transport@1":
        raise SchemaError("Invalid transport@1 document")
    _reject_unknown_keys(
        doc,
        frozenset({"schema_version", "kind", "id", "description", "primitives", "requires_host_pinning"}),
        "transport",
    )
    tid = validate_opaque_id(doc.get("id"), label="transport.id")
    if expected_id is not None and tid != expected_id:
        raise SchemaError("transport.id mismatch")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "transport@1",
        "id": tid,
        "description": str(doc.get("description", "")),
        "primitives": list(doc.get("primitives", [])),
        "requires_host_pinning": bool(doc.get("requires_host_pinning", False)),
    }


def validate_worker_doc(doc: dict[str, Any], *, expected_id: str | None = None) -> dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION or doc.get("kind") != "worker@1":
        raise SchemaError("Invalid worker@1 document")
    _reject_unknown_keys(
        doc,
        frozenset(
            {
                "schema_version",
                "kind",
                "id",
                "description",
                "host_provider",
                "transport",
                "arch",
                "os",
                "host",
                "port",
                "capabilities_override",
                "lease_limits",
            }
        ),
        "worker",
    )
    wid = validate_opaque_id(doc.get("id"), label="worker.id")
    if expected_id is not None and wid != expected_id:
        raise SchemaError("worker.id mismatch")
    arch = doc.get("arch")
    if arch not in ("x86_64", "arm64"):
        raise SchemaError(f"Unsupported worker arch: {arch!r}")
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "worker@1",
        "id": wid,
        "description": str(doc.get("description", "")),
        "host_provider": validate_opaque_id(doc.get("host_provider"), label="worker.host_provider"),
        "transport": validate_opaque_id(doc.get("transport"), label="worker.transport"),
        "arch": arch,
        "os": _require_str(doc.get("os", "linux"), "worker.os"),
        "host": doc.get("host"),
        "port": doc.get("port"),
        "capabilities_override": dict(doc.get("capabilities_override", {})),
        "lease_limits": dict(doc.get("lease_limits", {})),
    }


def validate_doc_by_kind(
    kind: str,
    doc: dict[str, Any],
    *,
    expected_id: str | None = None,
    for_orchestrator: bool = False,
) -> dict[str, Any]:
    if kind == "service":
        return validate_service_doc(doc, expected_id=expected_id, for_orchestrator=for_orchestrator)
    if kind == "bundle":
        return validate_bundle_doc(doc, expected_id=expected_id, for_orchestrator=for_orchestrator)
    if kind == "sandbox-type":
        return validate_sandbox_type_doc(doc, expected_id=expected_id, for_orchestrator=for_orchestrator)
    if kind == "host-provider":
        if for_orchestrator:
            raise PolicyError("host-provider is not mutable via orchestrator")
        return validate_host_provider_doc(doc, expected_id=expected_id)
    if kind == "transport":
        if for_orchestrator:
            raise PolicyError("transport is not mutable via orchestrator")
        return validate_transport_doc(doc, expected_id=expected_id)
    if kind == "worker":
        if for_orchestrator:
            raise PolicyError("worker is not mutable via orchestrator")
        return validate_worker_doc(doc, expected_id=expected_id)
    raise SchemaError(f"Unknown kind: {kind!r}")


@dataclass(frozen=True, slots=True)
class SemVer:
    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, text: str) -> "SemVer":
        parts = [int(p) for p in text.split(".")]
        if len(parts) == 2:
            parts.append(0)
        return cls(parts[0], parts[1], parts[2])

    def as_tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


def capability_satisfies(provided: str, required: str) -> bool:
    pm = CAPABILITY_PROVIDES_RE.fullmatch(provided)
    rm = CAPABILITY_REQUIRES_RE.fullmatch(required)
    if not pm or not rm:
        return False
    p_name, p_ver_s = pm.group(1), pm.group(2)
    r_name, op, r_ver_s = rm.group(1), rm.group(2) or "==", rm.group(3)
    if p_name != r_name:
        return False
    pv = SemVer.parse(p_ver_s).as_tuple()
    rv = SemVer.parse(r_ver_s).as_tuple()
    if op == "==":
        return pv == rv
    if op == ">=":
        return pv >= rv
    if op == "^":
        if rv[0] > 0:
            return pv >= rv and pv[0] == rv[0]
        return pv >= rv and pv[0] == 0 and pv[1] == rv[1]
    return False
