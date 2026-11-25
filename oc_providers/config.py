"""Trusted operator TOML configuration loader for ~/.config/oc-sandbox/providers.toml."""

from dataclasses import dataclass
import os
from pathlib import Path
import pwd
import re
import stat
import tomllib

from .contracts import (
    MAX_PROVIDER_SLOTS,
    PROVIDER_DESCRIPTORS,
    ProviderId,
    ProviderInstanceSpec,
    ProviderIntegrityError,
    is_valid_instance_label,
    is_valid_model_slug,
)

CONFIG_FILENAME = "providers.toml"
MAX_CONFIG_BYTES = 64 * 1024

_TOP_LEVEL_KEYS = frozenset({"provider_defaults", "providers", "launch"})
_INSTANCE_KEYS = frozenset({"enabled", "auth_mode", "credential_ref", "cli_path", "default_model"})
_LAUNCH_KEYS = frozenset({"default_provider", "default_model", "mini"})
_CRED_REF_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z", re.ASCII)
_SECRET_PREFIXES = (
    "sk-", "sk_", "pk-", "pk_", "ghp_", "github_pat_", "xox", "aiza", "eyj", "akia", "asia",
)
_ERR_UNTRUSTED = "untrusted_provider_config"
_ERR_INVALID = "invalid_provider_config"


class ProviderConfigError(ProviderIntegrityError):
    """Fail-closed configuration error for providers.toml trust or schema violations."""


@dataclass(frozen=True)
class LaunchDefaults:
    """Trusted operator launch defaults from [launch]."""

    default_provider: tuple[ProviderId, str] | None = None
    default_model: str | None = None
    mini: bool = False


@dataclass(frozen=True)
class ProviderConfig:
    """Validated, immutable operator provider configuration from providers.toml."""

    instances: tuple[ProviderInstanceSpec, ...]
    provider_defaults: dict[ProviderId, str]
    launch: LaunchDefaults

    def get(self, kind: str, label: str) -> ProviderInstanceSpec | None:
        for item in self.instances:
            if item.kind == kind and item.label == label:
                return item
        return None


def _account_home() -> Path:
    entry = pwd.getpwuid(os.getuid())
    pw_dir = Path(entry.pw_dir)
    if not pw_dir.is_absolute():
        raise ProviderConfigError(_ERR_UNTRUSTED, "operator home directory is not absolute")
    return pw_dir.resolve(strict=True)


def default_config_dir() -> Path:
    """Resolve ~/.config/oc-sandbox strictly from the workstation account home."""
    pw_home = _account_home()
    env_home = os.environ.get("HOME")
    if not env_home or not Path(env_home).is_absolute():
        raise ProviderConfigError(_ERR_UNTRUSTED, "HOME must be set to the workstation account directory")
    try:
        caller_home = Path(env_home).resolve(strict=True)
    except OSError:
        raise ProviderConfigError(_ERR_UNTRUSTED, "untrusted HOME directory") from None
    if caller_home != pw_home:
        raise ProviderConfigError(_ERR_UNTRUSTED, "HOME does not match workstation account")
    return pw_home / ".config" / "oc-sandbox"


def _inside_sandbox(path: Path, sandbox: Path, *, check_contains: bool = True) -> bool:
    if path == sandbox or path.is_relative_to(sandbox):
        return True
    return check_contains and sandbox.is_relative_to(path)


_STICKY_TMP = Path("/tmp")  # NOSONAR(S5443) — checks sticky-bit ancestor during O_NOFOLLOW walk


def _check_dir_stat(info: os.stat_result, *, current: Path, is_target: bool, uid: int) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise ProviderConfigError(_ERR_UNTRUSTED, "provider config parent is not a directory")
    sticky_tmp = (
        not is_target
        and current == _STICKY_TMP
        and info.st_uid in (0, 65534)
        and bool(info.st_mode & stat.S_ISVTX)
    )
    if sticky_tmp:
        return
    if info.st_uid not in (0, uid) or (info.st_mode & 0o022):
        raise ProviderConfigError(_ERR_UNTRUSTED, "provider config directory is not protected")
    if is_target and info.st_uid != uid:
        raise ProviderConfigError(_ERR_UNTRUSTED, "provider config directory is not owned by user")


def _open_trusted_dir(target: Path, *, sandbox: Path) -> int | None:
    if not target.is_absolute():
        raise ProviderConfigError(_ERR_UNTRUSTED, "provider config directory must be absolute")
    uid = os.geteuid()
    parts = [part for part in target.parts[1:] if part]
    if any(part in (".", "..") for part in parts):
        raise ProviderConfigError(_ERR_UNTRUSTED, "provider config directory is not normalized")
    dir_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    current = Path("/")
    try:
        for index, part in enumerate(parts):
            current = current / part
            is_last = index == len(parts) - 1
            if _inside_sandbox(current, sandbox, check_contains=is_last):
                raise ProviderConfigError(_ERR_UNTRUSTED, "provider config overlaps agent sandbox")
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=dir_fd,
                )
            except FileNotFoundError:
                os.close(dir_fd)
                return None
            except OSError:
                raise ProviderConfigError(_ERR_UNTRUSTED, "unsafe provider config directory") from None
            os.close(dir_fd)
            dir_fd = next_fd
            _check_dir_stat(os.fstat(dir_fd), current=current, is_target=is_last, uid=uid)
        return dir_fd
    except BaseException:
        os.close(dir_fd)
        raise


def _read_trusted_toml_bytes(config_dir: Path, *, sandbox: Path) -> bytes | None:
    dir_fd = _open_trusted_dir(config_dir, sandbox=sandbox)
    if dir_fd is None:
        return None
    try:
        try:
            fd = os.open(
                CONFIG_FILENAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=dir_fd,
            )
        except FileNotFoundError:
            return None
        except OSError:
            raise ProviderConfigError(_ERR_UNTRUSTED, "unsafe providers.toml file") from None
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or (info.st_mode & 0o022)
            ):
                raise ProviderConfigError(_ERR_UNTRUSTED, "providers.toml has unsafe permissions or links")
            raw = stream.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ProviderConfigError(_ERR_INVALID, "providers.toml exceeds size limit")
        return raw
    finally:
        os.close(dir_fd)


def _validate_credential_ref(auth_mode: str, raw_ref: object) -> str | None:
    if auth_mode == "subscription":
        if raw_ref is not None:
            raise ProviderConfigError(_ERR_INVALID, "credential_ref is forbidden for subscription auth_mode")
        return None
    if type(raw_ref) is not str or not _CRED_REF_RE.fullmatch(raw_ref):
        raise ProviderConfigError(_ERR_INVALID, "api_key instances require a valid credential_ref slug")
    lower = raw_ref.lower()
    if any(lower.startswith(prefix) for prefix in _SECRET_PREFIXES):
        raise ProviderConfigError(_ERR_INVALID, "credential_ref must reference a host secret, not a raw key")
    return raw_ref


def _validate_cli_path(kind: str, raw_path: object, *, sandbox: Path) -> str | None:
    if raw_path is None:
        return None
    if not PROVIDER_DESCRIPTORS[kind].supports_cli_path:
        raise ProviderConfigError(_ERR_INVALID, f"cli_path is not supported for provider '{kind}'")
    if not isinstance(raw_path, str) or type(raw_path) is not str:
        raise ProviderConfigError(_ERR_INVALID, "cli_path must be a clean absolute path")
    if not raw_path.startswith("/") or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_path):
        raise ProviderConfigError(_ERR_INVALID, "cli_path must be a clean absolute path")
    parts = [part for part in raw_path.split("/") if part]
    if not parts or any(part in (".", "..") for part in parts) or raw_path != "/" + "/".join(parts):
        raise ProviderConfigError(_ERR_INVALID, "cli_path must be normalized without '.' or '..' or duplicate slashes")
    candidate = Path(raw_path)
    resolved = Path(os.path.realpath(raw_path))
    if _inside_sandbox(candidate, sandbox) or _inside_sandbox(resolved, sandbox):
        raise ProviderConfigError(_ERR_INVALID, "cli_path must not point inside the agent sandbox")
    return raw_path


def _parse_single_instance(
    kind: ProviderId, label: str, table: object, *, sandbox: Path
) -> ProviderInstanceSpec:
    if type(table) is not dict or not set(table) <= _INSTANCE_KEYS:
        raise ProviderConfigError(_ERR_INVALID, f"invalid fields in [providers.{kind}.{label}]")
    enabled = table.get("enabled")
    auth_mode = table.get("auth_mode")
    if type(enabled) is not bool:
        raise ProviderConfigError(_ERR_INVALID, f"enabled must be boolean in [providers.{kind}.{label}]")
    descriptor = PROVIDER_DESCRIPTORS[kind]
    if type(auth_mode) is not str or auth_mode not in descriptor.supported_auth_modes:
        raise ProviderConfigError(_ERR_INVALID, f"unsupported auth_mode in [providers.{kind}.{label}]")
    credential_ref = _validate_credential_ref(auth_mode, table.get("credential_ref"))
    cli_path = _validate_cli_path(kind, table.get("cli_path"), sandbox=sandbox)
    default_model = table.get("default_model")
    if default_model is not None and not is_valid_model_slug(default_model):
        raise ProviderConfigError(_ERR_INVALID, f"invalid default_model in [providers.{kind}.{label}]")
    return ProviderInstanceSpec(
        kind=kind,
        label=label,
        enabled=enabled,
        auth_mode=auth_mode,  # type: ignore[arg-type]
        credential_ref=credential_ref,
        cli_path=cli_path,
        default_model=default_model,
    )


def _parse_provider_kind(
    kind: str, kind_table: object, *, sandbox: Path
) -> list[ProviderInstanceSpec]:
    if kind not in PROVIDER_DESCRIPTORS or type(kind_table) is not dict:
        raise ProviderConfigError(_ERR_INVALID, f"unsupported provider table '{kind}'")
    seen_normalized: set[str] = set()
    parsed: list[ProviderInstanceSpec] = []
    for label, entry in sorted(kind_table.items()):
        if not is_valid_instance_label(label):
            raise ProviderConfigError(_ERR_INVALID, f"invalid instance label '{label}'")
        normalized = label.lower().replace("_", "-")
        if normalized in seen_normalized:
            raise ProviderConfigError(_ERR_INVALID, f"colliding instance label '{label}'")
        seen_normalized.add(normalized)
        parsed.append(_parse_single_instance(kind, label, entry, sandbox=sandbox))  # type: ignore[arg-type]
    return parsed


def _parse_providers(raw_providers: object, *, sandbox: Path) -> tuple[ProviderInstanceSpec, ...]:
    if raw_providers is None:
        return ()
    if type(raw_providers) is not dict:
        raise ProviderConfigError(_ERR_INVALID, "[providers] must be a table")
    instances: list[ProviderInstanceSpec] = []
    for kind, kind_table in sorted(raw_providers.items()):
        instances.extend(_parse_provider_kind(kind, kind_table, sandbox=sandbox))
    enabled_count = sum(1 for item in instances if item.enabled)
    if enabled_count > MAX_PROVIDER_SLOTS:
        raise ProviderConfigError(
            "too_many_provider_instances",
            f"at most {MAX_PROVIDER_SLOTS} enabled provider instances are supported",
        )
    return tuple(instances)


def _parse_provider_defaults(
    raw_defaults: object, known: set[tuple[str, str]]
) -> dict[ProviderId, str]:
    if raw_defaults is None:
        return {}
    if type(raw_defaults) is not dict:
        raise ProviderConfigError(_ERR_INVALID, "[provider_defaults] must be a table")
    defaults: dict[ProviderId, str] = {}
    for kind, label in raw_defaults.items():
        if kind not in PROVIDER_DESCRIPTORS or not is_valid_instance_label(label):
            raise ProviderConfigError(_ERR_INVALID, "invalid [provider_defaults] entry")
        if (kind, label) not in known:
            raise ProviderConfigError(
                _ERR_INVALID, f"provider_defaults.{kind} references undeclared instance '{label}'"
            )
        defaults[kind] = label  # type: ignore[index]
    return defaults


def _parse_default_provider(
    raw_value: object, known: set[tuple[str, str]]
) -> tuple[ProviderId, str] | None:
    if raw_value is None:
        return None
    if type(raw_value) is not str or raw_value.count("/") != 1:
        raise ProviderConfigError(_ERR_INVALID, "[launch].default_provider must be 'kind/label'")
    kind, label = raw_value.split("/", 1)
    if kind not in PROVIDER_DESCRIPTORS or not is_valid_instance_label(label) or (kind, label) not in known:
        raise ProviderConfigError(
            _ERR_INVALID, "[launch].default_provider must reference a declared provider instance"
        )
    return (kind, label)  # type: ignore[return-value]


def _parse_launch_defaults(raw_launch: object, known: set[tuple[str, str]]) -> LaunchDefaults:
    if raw_launch is None:
        return LaunchDefaults()
    if type(raw_launch) is not dict or not set(raw_launch) <= _LAUNCH_KEYS:
        raise ProviderConfigError(_ERR_INVALID, "invalid fields in [launch]")
    mini = raw_launch.get("mini", False)
    if type(mini) is not bool:
        raise ProviderConfigError(_ERR_INVALID, "[launch].mini must be boolean")
    default_provider = _parse_default_provider(raw_launch.get("default_provider"), known)
    default_model = raw_launch.get("default_model")
    if default_model is not None:
        if default_provider is None:
            raise ProviderConfigError(_ERR_INVALID, "[launch].default_model requires [launch].default_provider")
        if not is_valid_model_slug(default_model):
            raise ProviderConfigError(_ERR_INVALID, "invalid [launch].default_model")
    return LaunchDefaults(default_provider=default_provider, default_model=default_model, mini=mini)


def _parse_provider_config_bytes(raw: bytes, *, sandbox: Path) -> ProviderConfig:
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise ProviderConfigError(_ERR_INVALID, "malformed providers.toml") from None
    if type(parsed) is not dict or not set(parsed) <= _TOP_LEVEL_KEYS:
        raise ProviderConfigError(_ERR_INVALID, "unexpected top-level section in providers.toml")
    instances = _parse_providers(parsed.get("providers"), sandbox=sandbox)
    known = {(item.kind, item.label) for item in instances}
    provider_defaults = _parse_provider_defaults(parsed.get("provider_defaults"), known)
    launch = _parse_launch_defaults(parsed.get("launch"), known)
    return ProviderConfig(instances=instances, provider_defaults=provider_defaults, launch=launch)


def load_provider_config_with_digest(
    *,
    config_dir: Path | None = None,
    sandbox_dir: Path | None = None,
) -> tuple[ProviderConfig | None, str | None]:
    """Atomically read, hash, and strictly validate providers.toml from one captured byte buffer."""
    from hashlib import sha256

    pw_home = _account_home()
    target_dir = default_config_dir() if config_dir is None else Path(config_dir)
    sandbox = (pw_home / "opencode-sandbox").resolve() if sandbox_dir is None else Path(sandbox_dir).resolve()
    raw = _read_trusted_toml_bytes(target_dir, sandbox=sandbox)
    if raw is None:
        return None, None
    return _parse_provider_config_bytes(raw, sandbox=sandbox), sha256(raw).hexdigest()


def load_provider_config(
    *,
    config_dir: Path | None = None,
    sandbox_dir: Path | None = None,
) -> ProviderConfig | None:
    """Load and strictly validate providers.toml, returning None iff the file is absent."""
    config, _ = load_provider_config_with_digest(config_dir=config_dir, sandbox_dir=sandbox_dir)
    return config
