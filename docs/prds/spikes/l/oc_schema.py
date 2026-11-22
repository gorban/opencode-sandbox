"""Schema validation, trust-boundary checks, and canonical hashing for PRD L spike PoC.

Pure Python standard library only. Never touches real ~/.config/oc-sandbox/.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.parse import quote, urlparse

SCHEMA_VERSION = 1

OPAQUE_ID_RE = re.compile(
    r"^[a-z0-9][a-z0-9_-]{0,31}(?:/[a-z0-9][a-z0-9_-]{0,31})?$",
    re.ASCII,
)
SIMPLE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$", re.ASCII)
SLOT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$", re.ASCII)
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
RAW_SECRET_PREFIXES = ("sk-", "sk-ant-", "AIza", "ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-")
MEM_LIMIT_RE = re.compile(r"^[1-9][0-9]{0,5}[mMgG]$", re.ASCII)
HOST_URL_SCHEMES = frozenset({"http", "https", "postgresql", "redis", "tcp"})
HOST_URL_PLACEHOLDERS = frozenset({"host", "port", "user", "db", "path"})
TEMPLATE_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_]+)\}")
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

# Exact closed set of security_delta triggers (PRD L)
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
MAX_MISE_MANIFESTS = 64
MAX_MISE_TOOLS = 64


class SchemaError(ValueError):
    """Validation failure against schema_version = 1 or trust boundary rules."""


class PolicyError(ValueError):
    """Security policy violation (exposure, auth, fallback escalation, forbidden resource)."""


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


def check_not_in_sandbox(path: Path, sandbox_root: Path | None = None) -> None:
    sb = (sandbox_root or (Path.home() / "opencode-sandbox")).resolve()
    resolved = path.resolve()
    if resolved == sb or sb in resolved.parents:
        raise PolicyError(f"Refusing host-trusted path inside sandbox root: {resolved}")


def assert_trusted_dir(path: Path, *, sandbox_root: Path | None = None) -> Path:
    check_not_in_sandbox(path, sandbox_root)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise PolicyError(f"Expected non-symlink directory: {path}")
    uid = os.geteuid()
    if st.st_uid != uid:
        raise PolicyError(f"Directory not owned by current user: {path}")
    if st.st_mode & 0o077:
        raise PolicyError(f"Directory permissions too open (require 0700): {path}")
    # Walk ancestors ensuring no group/world-writable non-sticky directories
    cur = path.resolve().parent
    while True:
        ast = os.lstat(cur)
        if ast.st_uid not in (uid, 0):
            raise PolicyError(f"Untrusted ancestor owner for {path}: {cur}")
        if (ast.st_mode & 0o022) and not (ast.st_uid == 0 and (ast.st_mode & stat.S_ISVTX)):
            raise PolicyError(f"Writable ancestor directory for {path}: {cur}")
        if cur.parent == cur:
            break
        cur = cur.parent
    return path


def read_regular_no_follow(
    path: Path,
    *,
    max_bytes: int = MAX_CONFIG_FILE_BYTES,
    require_owner_only: bool = False,
    confined_root: Path | None = None,
    sandbox_root: Path | None = None,
) -> bytes:
    """Open regular file without following symlinks and verify descriptor metadata."""
    check_not_in_sandbox(path, sandbox_root)
    if confined_root is not None:
        root_real = confined_root.resolve()
        # Walk every component from confined_root to path with O_NOFOLLOW
        try:
            rel = path.relative_to(confined_root)
        except ValueError as exc:
            raise PolicyError(f"Path escapes confined root: {path}") from exc
        if rel.is_absolute() or ".." in rel.parts:
            raise PolicyError(f"Path traversal rejected: {path}")
        dir_fd = os.open(root_real, os.O_RDONLY | os.O_DIRECTORY)
        try:
            parts = rel.parts
            for part in parts[:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
                os.close(dir_fd)
                dir_fd = nxt
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            fd = os.open(parts[-1], flags, dir_fd=dir_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PolicyError(f"Symlink rejected in confined path: {path}") from exc
            raise
        finally:
            os.close(dir_fd)
    else:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PolicyError(f"Symlink rejected: {path}") from exc
            raise

    try:
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
    for prefix in RAW_SECRET_PREFIXES:
        if value.startswith(prefix):
            raise SchemaError(f"Raw secret prefix {prefix!r} forbidden in {context}")


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


def validate_remote_endpoint_url(
    url: str,
    *,
    allow_http: bool = False,
    allowed_hosts: frozenset[str] = frozenset(),
) -> str:
    _require_str(url, "remote endpoint")
    if any(ch in url for ch in ("\r", "\n", "\x00", " ")):
        raise PolicyError("Remote endpoint contains illegal characters")
    parsed = urlparse(url)
    allowed_schemes = {"https"} | ({"http"} if allow_http else set())
    if parsed.scheme not in allowed_schemes:
        raise PolicyError(f"Remote endpoint scheme {parsed.scheme!r} not allowed")
    if parsed.username or parsed.password:
        raise PolicyError("Credentials embedded in remote endpoint URL are forbidden")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise PolicyError("Remote endpoint missing hostname")
    if host in allowed_hosts:
        return url
    if host in ("localhost", "host.containers.internal", "host.docker.internal") or host.endswith(
        ".localhost"
    ):
        raise PolicyError(f"Remote endpoint host {host!r} blocked by SSRF policy")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return url
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise PolicyError(f"Remote endpoint IP {host!r} blocked by SSRF policy")
    return url


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


def validate_service_doc(
    doc: dict[str, Any],
    *,
    expected_id: str | None = None,
    for_orchestrator: bool = False,
) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise SchemaError("service document must be a TOML table")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise SchemaError(f"service schema_version must be {SCHEMA_VERSION}")
    if doc.get("kind") != "service@1":
        raise SchemaError("service kind must be 'service@1'")
    allowed = frozenset(
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
    _reject_unknown_keys(doc, allowed, "service")
    if "factory" in doc or "implementation" in doc:
        raise PolicyError("Raw factory/implementation paths forbidden; use opaque factory_id")
    svc_id = validate_opaque_id(doc.get("id"), label="service.id")
    if expected_id is not None and svc_id != expected_id:
        raise SchemaError(f"service.id {svc_id!r} does not match expected {expected_id!r}")
    if for_orchestrator and is_builtin_id(svc_id):
        raise PolicyError("builtin/* services are strictly immutable")

    image = doc.get("image")
    images_by_arch = doc.get("images_by_arch")
    if image is not None:
        if type(image) is not str or DIGEST_IMAGE_RE.fullmatch(image) is None:
            raise SchemaError(f"service {svc_id}: image must be digest-pinned (@sha256:...)")
    if images_by_arch is not None:
        if not isinstance(images_by_arch, dict) or not images_by_arch:
            raise SchemaError(f"service {svc_id}: images_by_arch must be a non-empty table")
        for arch, ref in images_by_arch.items():
            if arch not in ("x86_64", "arm64"):
                raise SchemaError(f"Unsupported arch in images_by_arch: {arch!r}")
            if type(ref) is not str or DIGEST_IMAGE_RE.fullmatch(ref) is None:
                raise SchemaError(f"service {svc_id}: images_by_arch.{arch} must be digest-pinned")
    if image is None and images_by_arch is None:
        raise SchemaError(f"service {svc_id} requires digest-pinned image or images_by_arch")

    if doc.get("post_install_hook") is not None and for_orchestrator:
        raise PolicyError("Orchestrator proposals may not define post_install_hook")

    factory_id = doc.get("factory_id")
    if factory_id is not None:
        if type(factory_id) is not str or SIMPLE_NAME_RE.fullmatch(factory_id) is None:
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

    provides = doc.get("provides", [])
    if not isinstance(provides, list):
        raise SchemaError("service.provides must be a list")
    for cap in provides:
        if type(cap) is not str or CAPABILITY_PROVIDES_RE.fullmatch(cap) is None:
            raise SchemaError(f"Invalid capability provide spec: {cap!r}")

    requires = doc.get("requires", [])
    if not isinstance(requires, list):
        raise SchemaError("service.requires must be a list")
    norm_requires: list[dict[str, Any]] = []
    for req in requires:
        if isinstance(req, str):
            if CAPABILITY_REQUIRES_RE.fullmatch(req) is None and OPAQUE_ID_RE.fullmatch(req) is None:
                raise SchemaError(f"Invalid service requirement: {req!r}")
            norm_requires.append({"target": req, "provider": None, "instance": None})
        elif isinstance(req, dict):
            _reject_unknown_keys(req, frozenset({"capability", "service", "provider", "instance"}), "service.requires[]")
            target = req.get("capability") or req.get("service")
            if type(target) is not str:
                raise SchemaError("service.requires entry must specify capability or service")
            if req.get("capability") and CAPABILITY_REQUIRES_RE.fullmatch(target) is None:
                raise SchemaError(f"Invalid capability requirement: {target!r}")
            if req.get("service"):
                validate_opaque_id(target, label="service.requires.service")
            prov = req.get("provider")
            if prov is not None:
                validate_opaque_id(prov, label="service.requires.provider")
            inst = req.get("instance")
            if inst is not None and (type(inst) is not str or SIMPLE_NAME_RE.fullmatch(inst) is None):
                raise SchemaError(f"Invalid service.requires.instance: {inst!r}")
            norm_requires.append({"target": target, "provider": prov, "instance": inst})
        else:
            raise SchemaError("service.requires item must be string or table")

    fallback = doc.get("fallback_service")
    if fallback is not None:
        validate_opaque_id(fallback, label="service.fallback_service")

    req_caps = doc.get("required_capabilities", [])
    if not isinstance(req_caps, list) or any(type(c) is not str or SIMPLE_NAME_RE.fullmatch(c) is None for c in req_caps):
        raise SchemaError("service.required_capabilities must be a list of capability identifiers")

    resources = doc.get("resources")
    if not isinstance(resources, dict):
        raise SchemaError(f"service {svc_id} must declare bounded resources table")
    _reject_unknown_keys(resources, frozenset({"memory", "pids_limit"}), "service.resources")
    mem = _require_str(resources.get("memory"), "service.resources.memory")
    parse_mem_bytes(mem)
    pids = resources.get("pids_limit")
    if type(pids) is not int or not (16 <= pids <= 4096):
        raise SchemaError("service.resources.pids_limit must be an int in 16..4096")

    endpoints = [_validate_endpoint(e, f"service({svc_id}).endpoints[{i}]") for i, e in enumerate(doc.get("endpoints", []))]
    volumes = [_validate_volume(v, f"service({svc_id}).volumes[{i}]", for_orchestrator=for_orchestrator) for i, v in enumerate(doc.get("volumes", []))]

    secret_slots = doc.get("secret_slots", [])
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
        norm_secrets.append({"slot": sname, "target": starget, "mode": smode, "secret_ref": sref})

    env = validate_env_map(doc.get("env"), f"service({svc_id}).env")
    mise_tools = validate_mise_tools(doc.get("mise_tools"), f"service({svc_id}).mise_tools")

    probe = doc.get("readiness_probe")
    if probe is not None:
        if not isinstance(probe, dict):
            raise SchemaError("service.readiness_probe must be a table")
        _reject_unknown_keys(probe, frozenset({"kind", "port", "command"}), "service.readiness_probe")
        pkind = probe.get("kind")
        if pkind not in ("tcp", "exec_auth", "http_local"):
            raise SchemaError(f"Unsupported readiness_probe.kind: {pkind!r}")

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "service@1",
        "id": svc_id,
        "description": str(doc.get("description", "")),
        "image": image,
        "images_by_arch": images_by_arch,
        "provides": list(provides),
        "requires": norm_requires,
        "cardinality": cardinality,
        "instance_port": instance_port,
        "fallback_service": fallback,
        "required_capabilities": list(req_caps),
        "security_profile": sec_profile,
        "factory_id": factory_id,
        "resources": {"memory": mem, "pids_limit": pids},
        "endpoints": endpoints,
        "volumes": volumes,
        "secret_slots": norm_secrets,
        "env": env,
        "readiness_probe": probe,
        "mise_tools": mise_tools,
    }


def _validate_mcp_server(name: str, cfg: object, context: str, *, for_orchestrator: bool) -> dict[str, Any]:
    if SIMPLE_NAME_RE.fullmatch(name) is None:
        raise SchemaError(f"Invalid MCP server name in {context}: {name!r}")
    if not isinstance(cfg, dict):
        raise SchemaError(f"{context}.{name} must be a table")
    _reject_unknown_keys(
        cfg,
        frozenset({"type", "url", "artifact_id", "args", "headers", "secret_env", "tools", "local"}),
        f"{context}.{name}",
    )
    mtype = cfg.get("type")
    if mtype not in ("remote", "pinned-artifact"):
        raise PolicyError(f"MCP {name} must use type 'remote' or 'pinned-artifact', got {mtype!r}")
    if mtype == "remote":
        url = _require_str(cfg.get("url"), f"{context}.{name}.url")
        if not (url.startswith("http://127.0.0.1:") or url.startswith("https://")):
            raise PolicyError(f"MCP {name} remote url must be https:// or pod-local 127.0.0.1")
    else:
        art = _require_str(cfg.get("artifact_id"), f"{context}.{name}.artifact_id")
        if OPAQUE_ID_RE.fullmatch(art) is None:
            raise SchemaError(f"Invalid MCP artifact_id: {art!r}")
        if for_orchestrator and ("/" not in art or not art.startswith("builtin/")):
            raise PolicyError("Orchestrator MCP proposals must reference registered builtin/* artifacts")
    args = cfg.get("args", [])
    if not isinstance(args, list) or any(type(a) is not str for a in args):
        raise SchemaError(f"{context}.{name}.args must be list of strings")

    headers = cfg.get("headers", {})
    if not isinstance(headers, dict):
        raise SchemaError(f"{context}.{name}.headers must be a table")
    norm_headers: dict[str, str] = {}
    for hk, hv in headers.items():
        if type(hk) is not str or type(hv) is not str:
            raise SchemaError(f"Invalid header in {context}.{name}")
        if hk.lower() in ("authorization", "x-api-key", "x-goog-api-key"):
            if not (hv.startswith("Bearer ") and SECRET_REF_VALUE_RE.fullmatch(hv[7:])) and SECRET_REF_VALUE_RE.fullmatch(hv) is None:
                raise PolicyError(
                    f"Sensitive header {hk!r} in {context}.{name} must use {{file:/run/secrets/<slot>}}"
                )
        else:
            _check_no_raw_secret_value(hv, f"{context}.{name}.headers.{hk}")
        norm_headers[hk] = hv

    secret_env = cfg.get("secret_env", {})
    if not isinstance(secret_env, dict):
        raise SchemaError(f"{context}.{name}.secret_env must be a table")
    for ek, ev in secret_env.items():
        if type(ek) is not str or type(ev) is not str or SECRET_REF_VALUE_RE.fullmatch(ev) is None:
            raise PolicyError(f"MCP secret_env {ek!r} must use {{file:/run/secrets/<slot>}}")

    tools = cfg.get("tools", [])
    if not isinstance(tools, list) or any(type(t) is not str or SIMPLE_NAME_RE.fullmatch(t) is None for t in tools):
        raise SchemaError(f"{context}.{name}.tools must be a list of tool identifiers")

    local_cfg = cfg.get("local")
    norm_local = None
    if local_cfg is not None:
        if not isinstance(local_cfg, dict):
            raise SchemaError(f"{context}.{name}.local must be a table")
        _reject_unknown_keys(local_cfg, frozenset({"binding_key", "service", "url"}), f"{context}.{name}.local")
        bkey = _require_str(local_cfg.get("binding_key"), f"{context}.{name}.local.binding_key")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", bkey):
            raise SchemaError(f"Invalid local.binding_key: {bkey!r}")
        lsvc = validate_opaque_id(local_cfg.get("service"), label=f"{context}.{name}.local.service")
        lurl = _require_str(local_cfg.get("url"), f"{context}.{name}.local.url")
        norm_local = {"binding_key": bkey, "service": lsvc, "url": lurl}

    return {
        "type": mtype,
        "url": cfg.get("url"),
        "artifact_id": cfg.get("artifact_id"),
        "args": list(args),
        "headers": norm_headers,
        "secret_env": dict(secret_env),
        "tools": list(tools),
        "local": norm_local,
    }


def validate_bundle_doc(
    doc: dict[str, Any],
    *,
    expected_id: str | None = None,
    for_orchestrator: bool = False,
) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise SchemaError("bundle document must be a TOML table")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise SchemaError(f"bundle schema_version must be {SCHEMA_VERSION}")
    if doc.get("kind") != "bundle@1":
        raise SchemaError("bundle kind must be 'bundle@1'")
    _reject_unknown_keys(
        doc,
        frozenset(
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
                "skills",
                "persona",
                "subagents",
                "instructions",
                "prompt_slots",
                "mise_tools",
            }
        ),
        "bundle",
    )
    bid = validate_opaque_id(doc.get("id"), label="bundle.id")
    if expected_id is not None and bid != expected_id:
        raise SchemaError(f"bundle.id {bid!r} does not match expected {expected_id!r}")
    if for_orchestrator and is_builtin_id(bid):
        raise PolicyError("builtin/* bundles are strictly immutable")

    includes = [validate_opaque_id(x, label="bundle.includes[]") for x in doc.get("includes", [])]
    comp = doc.get("composition", {})
    if not isinstance(comp, dict):
        raise SchemaError("bundle.composition must be a table")
    _reject_unknown_keys(comp, frozenset({"replace"}), "bundle.composition")
    replace_list = comp.get("replace", [])
    if not isinstance(replace_list, list) or any(r not in ("persona", "mcp") for r in replace_list):
        raise SchemaError("bundle.composition.replace may only contain 'persona' or 'mcp'")

    req_services = []
    for item in doc.get("requires_services", []):
        if isinstance(item, str):
            if CAPABILITY_REQUIRES_RE.fullmatch(item) is None and OPAQUE_ID_RE.fullmatch(item) is None:
                raise SchemaError(f"Invalid bundle.requires_services item: {item!r}")
            req_services.append({"target": item, "provider": None, "instance": None})
        elif isinstance(item, dict):
            _reject_unknown_keys(item, frozenset({"capability", "service", "provider", "instance"}), "bundle.requires_services[]")
            target = item.get("capability") or item.get("service")
            if type(target) is not str:
                raise SchemaError("bundle.requires_services entry must set capability or service")
            if item.get("capability") and CAPABILITY_REQUIRES_RE.fullmatch(target) is None:
                raise SchemaError(f"Invalid capability requirement: {target!r}")
            if item.get("service"):
                validate_opaque_id(target, label="bundle.requires_services.service")
            prov = item.get("provider")
            if prov is not None:
                validate_opaque_id(prov, label="provider")
            inst = item.get("instance")
            if inst is not None and (type(inst) is not str or SIMPLE_NAME_RE.fullmatch(inst) is None):
                raise SchemaError(f"Invalid instance name: {inst!r}")
            req_services.append({"target": target, "provider": prov, "instance": inst})
        else:
            raise SchemaError("bundle.requires_services items must be string or table")

    local_services = []
    for i, item in enumerate(doc.get("local_services", [])):
        if not isinstance(item, dict):
            raise SchemaError(f"bundle.local_services[{i}] must be a table")
        _reject_unknown_keys(item, frozenset({"binding_key", "service", "instance"}), f"local_services[{i}]")
        bkey = _require_str(item.get("binding_key"), f"local_services[{i}].binding_key")
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", bkey):
            raise SchemaError(f"Invalid local_services binding_key: {bkey!r}")
        lsvc = validate_opaque_id(item.get("service"), label=f"local_services[{i}].service")
        inst = item.get("instance")
        if inst is not None and (type(inst) is not str or SIMPLE_NAME_RE.fullmatch(inst) is None):
            raise SchemaError(f"Invalid local_services instance: {inst!r}")
        local_services.append({"binding_key": bkey, "service": lsvc, "instance": inst})

    raw_mcp = doc.get("mcp", {})
    if not isinstance(raw_mcp, dict):
        raise SchemaError("bundle.mcp must be a table")
    mcp = {
        k: _validate_mcp_server(k, v, f"bundle({bid}).mcp", for_orchestrator=for_orchestrator)
        for k, v in raw_mcp.items()
    }

    skills = [validate_opaque_id(s, label="bundle.skills[]") for s in doc.get("skills", [])]

    persona = doc.get("persona")
    norm_persona = None
    if persona is not None:
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
        norm_persona = {
            "name": pname,
            "mission": mission,
            "authority": auth,
            "allowed_mcp_tools": list(allowed_tools) if allowed_tools is not None else None,
            "denied_mcp_tools": list(denied_tools),
            "checklists": checklists,
        }

    subagents = doc.get("subagents", [])
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

    instructions = doc.get("instructions", [])
    if not isinstance(instructions, list) or any(type(x) is not str for x in instructions):
        raise SchemaError("bundle.instructions must be a list of strings")
    for text in instructions:
        _check_no_raw_secret_value(text, f"bundle({bid}).instructions")

    prompt_slots = doc.get("prompt_slots", {})
    if not isinstance(prompt_slots, dict):
        raise SchemaError("bundle.prompt_slots must be a table")
    norm_slots: dict[str, str] = {}
    for sk, sv in prompt_slots.items():
        if type(sk) is not str or SLOT_NAME_RE.fullmatch(sk) is None:
            raise SchemaError(f"Invalid prompt_slot key: {sk!r}")
        if type(sv) is not str or sv.startswith("/") or ".." in Path(sv).parts or not sv.endswith((".md", ".txt")):
            raise PolicyError(f"prompt_slot {sk!r} must be a relative .md/.txt file inside bundle root")
        norm_slots[sk] = sv

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
        "skills": skills,
        "persona": norm_persona,
        "subagents": norm_subagents,
        "instructions": list(instructions),
        "prompt_slots": norm_slots,
        "mise_tools": mise_tools,
    }


def validate_sandbox_type_doc(
    doc: dict[str, Any],
    *,
    expected_id: str | None = None,
    for_orchestrator: bool = False,
) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise SchemaError("sandbox-type document must be a TOML table")
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise SchemaError(f"sandbox-type schema_version must be {SCHEMA_VERSION}")
    if doc.get("kind") != "sandbox-type@1":
        raise SchemaError("sandbox-type kind must be 'sandbox-type@1'")
    _reject_unknown_keys(
        doc,
        frozenset(
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
        ),
        "sandbox-type",
    )
    stid = validate_opaque_id(doc.get("id"), label="sandbox-type.id")
    if expected_id is not None and stid != expected_id:
        raise SchemaError(f"sandbox-type.id {stid!r} does not match expected {expected_id!r}")
    if for_orchestrator and is_builtin_id(stid):
        raise PolicyError("builtin/* sandbox-types are strictly immutable")

    tier = doc.get("tier", "managed")
    if tier not in TIERS:
        raise SchemaError(f"Invalid sandbox-type.tier: {tier!r}")
    topology = doc.get("topology", "isolated-sidecars" if tier == "managed" else "pod-shared")
    if topology not in TOPOLOGIES:
        raise SchemaError(f"Invalid sandbox-type.topology: {topology!r}")

    base_image = doc.get("base_image")
    base_by_arch = doc.get("base_images_by_arch")
    if base_image is not None and (type(base_image) is not str or DIGEST_IMAGE_RE.fullmatch(base_image) is None):
        raise SchemaError("sandbox-type.base_image must be digest-pinned (@sha256:...)")
    if base_by_arch is not None:
        if not isinstance(base_by_arch, dict) or not base_by_arch:
            raise SchemaError("base_images_by_arch must be a non-empty table")
        for arch, ref in base_by_arch.items():
            if arch not in ("x86_64", "arm64") or type(ref) is not str or DIGEST_IMAGE_RE.fullmatch(ref) is None:
                raise SchemaError(f"Invalid base_images_by_arch[{arch!r}]")
    if base_image is None and base_by_arch is None:
        raise SchemaError("sandbox-type requires digest-pinned base_image or base_images_by_arch")

    default_worker = doc.get("default_worker", "builtin/local-workstation")
    validate_opaque_id(default_worker, label="sandbox-type.default_worker")

    bundles = [validate_opaque_id(b, label="sandbox-type.bundles[]") for b in doc.get("bundles", [])]
    default_agent = doc.get("default_agent")
    if default_agent is not None and (type(default_agent) is not str or SIMPLE_NAME_RE.fullmatch(default_agent) is None):
        raise SchemaError(f"Invalid default_agent: {default_agent!r}")

    ports = []
    for i, p in enumerate(doc.get("ports", [])):
        if not isinstance(p, dict):
            raise SchemaError(f"sandbox-type.ports[{i}] must be a table")
        _reject_unknown_keys(p, frozenset({"service", "endpoint", "exposure", "host_port"}), f"ports[{i}]")
        svc = validate_opaque_id(p.get("service"), label=f"ports[{i}].service")
        ep = _require_str(p.get("endpoint"), f"ports[{i}].endpoint")
        exp = p.get("exposure", "host-loopback")
        if exp not in EXPOSURE_RANK:
            raise SchemaError(f"Invalid port exposure: {exp!r}")
        hp = p.get("host_port")
        if hp is not None and (type(hp) is not int or not 1024 <= hp <= 65535):
            raise SchemaError("host_port must be 1024..65535")
        ports.append({"service": svc, "endpoint": ep, "exposure": exp, "host_port": hp})

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
