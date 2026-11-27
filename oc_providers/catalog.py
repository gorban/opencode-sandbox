"""Multi-provider launch catalog, disclosure, explicit model selection, and config generation."""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hmac
import inspect
import re
from typing import Protocol

from .config import ProviderConfig
from .contracts import (
    CliUiMode,
    ExcludedInstance,
    ExposureHoldSummary,
    InstancePreflight,
    MAX_PROVIDER_SLOTS,
    PROVIDERS,
    PickerRow,
    ProviderId,
    ProviderInstanceSpec,
    ProviderIntegrityError,
    ProviderSessionAdapter,
    ReadinessState,
    SelectionState,
    UiMode,
    is_valid_instance_label,
    is_valid_model_slug,
    sanitize_display_text,
)

_CANCELLED = "Cancelled."
_ERR_INVALID_ENTRY = "invalid_provider_entry"
_OPENCODE_SCHEMA = "https://opencode.ai/config.json"
_INCLUDE_SLUG_RE = re.compile(r"[a-z0-9._-]{1,64}\Z", re.ASCII)
_MODALITIES = frozenset({"text", "image"})
_SETTINGS_ALLOWED_KEYS = frozenset({"baseURL", "apiKey", "store", "include"})
_ENTRY_KEYS = frozenset({"name", "package", "settings", "models"})
_MODEL_DEF_KEYS = frozenset({"name", "capabilities", "limit"})
_CAPABILITY_KEYS = frozenset({"tools", "input", "output"})
_LIMIT_KEYS = frozenset({"context", "output"})
_NORMAL_TOP_KEYS = frozenset({"$schema", "model", "update", "mcp", "providers", "policies"})
_HARDENED_TOP_KEYS = frozenset(
    {"$schema", "model", "update", "providers", "policies", "snapshots", "permissions", "plugins"}
)
_HARDENED_PERMISSIONS = [{"action": "*", "resource": "*", "effect": "deny"}]
_HARDENED_PLUGINS = ["-opencode.tool.*"]

APPROVED_OPENCODE_PACKAGES_BY_KIND: dict[str, frozenset[str]] = {
    "openai": frozenset({"@opencode/ai/providers/openai-compatible/responses"}),
    "google": frozenset({
        "@opencode/ai/providers/openai-compatible/responses",
        "@opencode/ai/providers/openai-compatible/chat",
    }),
    "claude": frozenset({
        "@opencode/ai/providers/openai-compatible/responses",
        "@opencode/ai/providers/openai-compatible/chat",
    }),
}

PROVIDER_DISPLAY_PREFIX: dict[tuple[str, str], str] = {
    ("openai", "subscription"): "ChatGPT Subscription",
    ("google", "subscription"): "Google Subscription",
    ("claude", "subscription"): "Claude Subscription",
    ("openai", "api_key"): "OpenAI API",
    ("google", "api_key"): "Google API",
    ("claude", "api_key"): "Claude API",
}


def compute_display_labels(admitted: Sequence[InstancePreflight]) -> dict[str, str]:
    """Map each admitted scoped_id to a collision-disambiguated host display label."""
    counts = Counter(item.spec.label for item in admitted)
    return {
        item.spec.scoped_id: (
            item.spec.qualified_name if counts[item.spec.label] > 1 else item.spec.label
        )
        for item in admitted
    }


def expected_provider_display_name(item: InstancePreflight, display_label: str) -> str:
    """Build the exact host-authoritative OpenCode provider display name."""
    prefix = PROVIDER_DISPLAY_PREFIX.get((item.spec.kind, item.spec.auth_mode))
    if prefix is None:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Unsupported provider display prefix for {item.spec.kind}.")
    return sanitize_display_text(f"{prefix} ({display_label})")


def project_picker_rows(admitted: Sequence[InstancePreflight]) -> tuple[PickerRow, ...]:
    """Project host-authoritative display rows for admitted instances (projection prerequisite)."""
    display_labels = compute_display_labels(admitted)
    rows: list[PickerRow] = []
    for item in admitted:
        dlabel = display_labels[item.spec.scoped_id]
        policy = sanitize_display_text(item.route_policy, max_len=96) if item.route_policy else item.spec.auth_mode
        for slug in item.models:
            if not is_valid_model_slug(slug):
                raise ProviderIntegrityError("invalid_model_slug", f"Invalid upstream model slug '{slug}'.")
            rows.append(
                PickerRow(
                    scoped_provider_id=item.spec.scoped_id,
                    kind=item.spec.kind,
                    label=item.spec.label,
                    display_label=dlabel,
                    upstream_model_id=slug,
                    display_model=sanitize_display_text(slug),
                    auth_mode=item.spec.auth_mode,
                    route_policy=policy,
                )
            )
    rows.sort(key=lambda r: (r.display_model.casefold(), r.upstream_model_id, r.display_label, r.scoped_provider_id))
    return tuple(rows)


class LaunchRefusedError(RuntimeError):
    """Fail-closed launch refusal with a typed code and user-facing explanation."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class LaunchTerminal(Protocol):
    """Minimal attended terminal interface used by the multi-provider launch planner."""

    def attended(self) -> bool:
        ...

    def write(self, text: str) -> None:
        ...

    def error(self, text: str) -> None:
        ...

    def confirm(self, prompt: str) -> bool:
        ...

    def choose(self, prompt: str, options: Sequence[str]) -> int | None:
        ...


@dataclass(frozen=True)
class ResolvedLaunchPlan:
    """Confirmed, immutable multi-provider launch plan ready for broker/relay startup."""

    admitted: tuple[InstancePreflight, ...]
    excluded: tuple[ExcludedInstance, ...]
    acknowledged_digests: dict[str, str]
    initial_provider_id: str
    initial_model: str
    ui_mode: UiMode
    ui_source: str


def parse_provider_filter(raw: str) -> tuple[ProviderId, str | None]:
    """Parse optional --provider KIND or KIND/LABEL narrowing filter."""
    if not raw or type(raw) is not str:
        raise LaunchRefusedError("invalid_provider_filter", "Invalid --provider value.")
    if "/" not in raw:
        if raw not in PROVIDERS:
            raise LaunchRefusedError("unsupported_provider", f"Unsupported provider '{raw}'.")
        return raw, None  # type: ignore[return-value]
    if raw.count("/") > 1:
        raise LaunchRefusedError("invalid_provider_filter", f"Invalid --provider target '{raw}'.")
    kind, label = raw.split("/", 1)
    if kind not in PROVIDERS:
        raise LaunchRefusedError("unsupported_provider", f"Unsupported provider '{kind}'.")
    if not is_valid_instance_label(label):
        raise LaunchRefusedError("invalid_provider_filter", f"Invalid provider instance label '{label}'.")
    return kind, label  # type: ignore[return-value]


def resolve_ui_mode(cli_ui_mode: CliUiMode, config: ProviderConfig | None) -> tuple[UiMode, str]:
    """Resolve effective UI mode (full vs mini) and its provenance source."""
    if cli_ui_mode == "mini":
        return "mini", "--mini"
    if cli_ui_mode == "full":
        return "full", "--no-mini"
    if config is not None and config.launch.mini:
        return "mini", "providers.toml"
    return "full", "default"


def _resolve_narrowed_spec(
    kind: ProviderId,
    label: str | None,
    config: ProviderConfig | None,
    adapter: ProviderSessionAdapter | None,
) -> ProviderInstanceSpec:
    if adapter is None:
        raise LaunchRefusedError(
            "route_unqualified", f"Provider '{kind}' is not yet qualified for sandbox launch."
        )
    resolved_label = label
    if resolved_label is None:
        selection = adapter.selection_state()
        if selection.state is SelectionState.SELECTED and selection.label is not None:
            resolved_label = selection.label
        elif selection.state is SelectionState.DISCONNECTED:
            raise LaunchRefusedError(
                "selection_disconnected",
                f"The active '{kind}' registration was disconnected. Select another with "
                f"`oc-sandbox {kind} select <label>` or pass `--provider {kind}/<label>`.",
            )
        elif config is not None and kind in config.provider_defaults:
            resolved_label = config.provider_defaults[kind]
        else:
            raise LaunchRefusedError(
                "no_active_selection",
                f"No active '{kind}' registration selected. Run `oc-sandbox {kind} connect <label>` first.",
            )
    if config is not None:
        spec = config.get(kind, resolved_label)
        if spec is None:
            raise LaunchRefusedError(
                "instance_unknown",
                f"Provider instance '{kind}/{resolved_label}' is not declared in providers.toml.",
            )
        if not spec.enabled:
            raise LaunchRefusedError(
                "instance_disabled",
                f"Provider instance '{kind}/{resolved_label}' is disabled in providers.toml.",
            )
        return spec
    if not is_valid_instance_label(resolved_label):
        raise ProviderIntegrityError(
            "invalid_saved_label",
            f"Saved '{kind}' profile label '{resolved_label}' does not match canonical I4d naming.",
        )
    return ProviderInstanceSpec(kind=kind, label=resolved_label, enabled=True, auth_mode="subscription")


def _valid_models_tuple(models: object) -> bool:
    return (
        type(models) is tuple
        and bool(models)
        and all(is_valid_model_slug(slug) for slug in models)
        and len(set(models)) == len(models)
    )


def _preflight_narrowed(
    provider_filter: str,
    config: ProviderConfig | None,
    adapters: Mapping[str, ProviderSessionAdapter],
) -> tuple[list[InstancePreflight], list[ExcludedInstance]]:
    kind, label = parse_provider_filter(provider_filter)
    adapter = adapters.get(kind)
    spec = _resolve_narrowed_spec(kind, label, config, adapter)
    if adapter is None or adapter.is_qualified(spec.auth_mode, "sandbox") is not True:
        raise LaunchRefusedError(
            "route_unqualified",
            f"Provider instance '{spec.qualified_name}' ({spec.auth_mode}) is not qualified for sandbox launch.",
        )
    preflight = adapter.preflight_instance(spec)
    if preflight.readiness is not ReadinessState.READY or not _valid_models_tuple(preflight.models):
        raise LaunchRefusedError(
            f"provider_{preflight.readiness.value}",
            f"Provider instance '{spec.qualified_name}' is not ready ({preflight.readiness.value}).",
        )
    return [preflight], []


def _collect_default_specs(
    config: ProviderConfig | None,
    adapters: Mapping[str, ProviderSessionAdapter],
) -> tuple[ProviderInstanceSpec, ...]:
    if config is not None:
        return config.instances
    discovered: list[ProviderInstanceSpec] = []
    for kind in sorted(adapters):
        adapter = adapters[kind]
        if adapter.is_qualified("subscription", "sandbox") is True:
            discovered.extend(adapter.discover_instances())
    return tuple(discovered)


def _preflight_default_catalog(
    config: ProviderConfig | None,
    adapters: Mapping[str, ProviderSessionAdapter],
) -> tuple[list[InstancePreflight], list[ExcludedInstance]]:
    ready: list[InstancePreflight] = []
    excluded: list[ExcludedInstance] = []
    for spec in _collect_default_specs(config, adapters):
        if not spec.enabled:
            excluded.append(ExcludedInstance(spec.kind, spec.label, "disabled", "disabled in providers.toml"))
            continue
        adapter = adapters.get(spec.kind)
        if adapter is None or adapter.is_qualified(spec.auth_mode, "sandbox") is not True:
            excluded.append(
                ExcludedInstance(
                    spec.kind,
                    spec.label,
                    "unqualified",
                    f"{spec.auth_mode} route is not yet qualified for sandbox launch",
                )
            )
            continue
        preflight = adapter.preflight_instance(spec)
        if preflight.readiness is ReadinessState.READY and _valid_models_tuple(preflight.models):
            ready.append(preflight)
        else:
            excluded.append(
                ExcludedInstance(spec.kind, spec.label, preflight.readiness.value, preflight.readiness.value)
            )
    if len(ready) > MAX_PROVIDER_SLOTS:
        raise ProviderIntegrityError(
            "too_many_provider_instances",
            f"At most {MAX_PROVIDER_SLOTS} ready provider instances can run in one session.",
        )
    return ready, excluded


def _group_exposure_holds(
    candidates: Sequence[InstancePreflight],
) -> tuple[dict[str, list[InstancePreflight]], dict[str, ExposureHoldSummary]]:
    by_scope: dict[str, list[InstancePreflight]] = {}
    holds_by_scope: dict[str, ExposureHoldSummary] = {}
    for item in candidates:
        if item.exposure_hold is None:
            continue
        scope = item.exposure_hold.scope_id
        by_scope.setdefault(scope, []).append(item)
        existing = holds_by_scope.get(scope)
        if existing is not None and existing.digest != item.exposure_hold.digest:
            raise ProviderIntegrityError("exposure_hold_changed", "Inconsistent exposure hold snapshot.")
        holds_by_scope[scope] = item.exposure_hold
    return by_scope, holds_by_scope


def _resolve_exposure_holds(
    candidates: list[InstancePreflight],
    excluded: list[ExcludedInstance],
    terminal: LaunchTerminal,
    *,
    narrowed: bool,
) -> tuple[list[InstancePreflight], dict[str, str]]:
    by_scope, holds_by_scope = _group_exposure_holds(candidates)
    acknowledged: dict[str, str] = {}
    declined_scopes: set[str] = set()
    for scope, hold in holds_by_scope.items():
        affected = ", ".join(item.spec.qualified_name for item in by_scope[scope])
        terminal.write(
            f"Prior exposure hold for {affected} ({hold.file_count} receipt file(s), "
            f"{hold.unsettled_count} unsettled, snapshot {hold.digest[:12]}). "
            "Existing receipt files will remain untouched."
        )
        if terminal.confirm(f"Acknowledge prior exposure snapshot for {affected}?"):
            acknowledged[scope] = hold.digest
        elif narrowed:
            raise LaunchRefusedError("exposure_hold_declined", _CANCELLED)
        else:
            declined_scopes.add(scope)

    admitted: list[InstancePreflight] = []
    for item in candidates:
        if item.exposure_hold is not None and item.exposure_hold.scope_id in declined_scopes:
            excluded.append(
                ExcludedInstance(
                    item.spec.kind, item.spec.label, "exposure_hold_declined", "prior exposure hold not acknowledged"
                )
            )
            continue
        admitted.append(item)
    return admitted, acknowledged


def _select_model_for_instance(
    chosen: InstancePreflight, config: ProviderConfig | None
) -> str:
    if (
        config is not None
        and config.launch.default_provider == (chosen.spec.kind, chosen.spec.label)
        and config.launch.default_model is not None
    ):
        if config.launch.default_model in chosen.models:
            return config.launch.default_model
        raise LaunchRefusedError(
            "default_model_unavailable",
            f"Configured default model '{config.launch.default_model}' is unavailable on {chosen.spec.qualified_name}.",
        )
    if chosen.spec.default_model is not None:
        if chosen.spec.default_model in chosen.models:
            return chosen.spec.default_model
        raise LaunchRefusedError(
            "default_model_unavailable",
            f"Configured default model '{chosen.spec.default_model}' is unavailable on {chosen.spec.qualified_name}.",
        )
    return chosen.models[0]


def _prompt_initial_instance(
    admitted: Sequence[InstancePreflight], terminal: LaunchTerminal, reason: str
) -> InstancePreflight:
    terminal.write(reason)
    labels = [
        f"{item.spec.qualified_name} ({item.spec.auth_mode}; {item.route_policy})"
        for item in admitted
    ]
    picked = terminal.choose("Select initial active provider instance for this session:", labels)
    if picked is None or not 0 <= picked < len(admitted):
        raise LaunchRefusedError("cancelled", _CANCELLED)
    return admitted[picked]


def _find_admitted_instance(
    admitted: Sequence[InstancePreflight], target: tuple[ProviderId, str]
) -> InstancePreflight | None:
    return next(
        (item for item in admitted if (item.spec.kind, item.spec.label) == target),
        None,
    )


def _find_single_kind_active(
    admitted: Sequence[InstancePreflight], adapters: Mapping[str, ProviderSessionAdapter]
) -> InstancePreflight | None:
    kinds = {item.spec.kind for item in admitted}
    if len(kinds) != 1:
        return None
    only_kind = next(iter(kinds))
    active = adapters[only_kind].active_label()
    if active is None:
        return None
    return _find_admitted_instance(admitted, (only_kind, active))


def _choose_initial_instance(
    admitted: Sequence[InstancePreflight],
    config: ProviderConfig | None,
    adapters: Mapping[str, ProviderSessionAdapter],
    terminal: LaunchTerminal,
    *,
    narrowed: bool,
) -> InstancePreflight:
    if narrowed:
        return admitted[0]
    default_target = config.launch.default_provider if config is not None else None
    if default_target is not None:
        matched = _find_admitted_instance(admitted, default_target)
        if matched is not None:
            return matched
        target_name = f"{default_target[0]}/{default_target[1]}"
        return _prompt_initial_instance(
            admitted, terminal, f"Configured default provider '{target_name}' is unavailable."
        )
    if len(admitted) == 1:
        return admitted[0]
    active_match = _find_single_kind_active(admitted, adapters)
    if active_match is not None:
        return active_match
    return _prompt_initial_instance(
        admitted, terminal, "Multiple provider instances are ready with no explicit default configured."
    )


def _format_model_preview(models: tuple[str, ...]) -> str:
    return ", ".join(models[:6]) + (f" (+{len(models) - 6} more)" if len(models) > 6 else "")


def _report_excluded(excluded: Sequence[ExcludedInstance], terminal: LaunchTerminal) -> None:
    for item in excluded:
        terminal.write(
            f"Excluded provider {item.kind}/{item.label}: {item.detail} (zero relay started)."
        )


def plan_interactive_launch(
    *,
    instance_name: str,
    cwd: str,
    provider_filter: str,
    cli_ui_mode: CliUiMode,
    config: ProviderConfig | None,
    adapters: Mapping[str, ProviderSessionAdapter],
    terminal: LaunchTerminal,
) -> ResolvedLaunchPlan:
    """Resolve candidates, disclose exclusions/holds/models, and confirm an interactive launch."""
    ui_mode, ui_source = resolve_ui_mode(cli_ui_mode, config)
    narrowed = bool(provider_filter)
    if narrowed:
        candidates, excluded = _preflight_narrowed(provider_filter, config, adapters)
    else:
        candidates, excluded = _preflight_default_catalog(config, adapters)

    _report_excluded(excluded, terminal)
    if not candidates:
        raise LaunchRefusedError(
            "no_admitted_providers",
            "No enabled, qualified provider instances are ready. Connect a provider (for example "
            "`oc-sandbox openai connect personal`) or enable one in ~/.config/oc-sandbox/providers.toml.",
        )

    admitted, acknowledged = _resolve_exposure_holds(candidates, excluded, terminal, narrowed=narrowed)
    if not admitted:
        raise LaunchRefusedError("no_admitted_providers", "No provider instances admitted for launch.")

    initial_item = _choose_initial_instance(admitted, config, adapters, terminal, narrowed=narrowed)
    initial_model = _select_model_for_instance(initial_item, config)
    initial_provider_id = initial_item.spec.scoped_id

    display_labels = compute_display_labels(admitted)
    for item in admitted:
        preview = _format_model_preview(item.models)
        dlabel = display_labels[item.spec.scoped_id]
        terminal.write(
            f"Provider {dlabel} [{item.spec.scoped_id}]: "
            f"auth={item.spec.auth_mode}, policy={item.route_policy} (models: {preview})"
        )
    ui_label = "OpenCode Mini" if ui_mode == "mini" else "OpenCode"
    terminal.write(
        f"Initial active model: {initial_provider_id}/{initial_model} | "
        f"UI: {ui_label} ({ui_source}) | Workspace: /sandbox/{cwd}"
    )
    admitted_kinds = sorted({item.spec.kind for item in admitted})
    disconnect_hint = (
        f"Disconnect with `oc-sandbox {admitted_kinds[0]} disconnect [LABEL]` or exit OpenCode."
        if admitted_kinds == ["openai"]
        else "Disconnect the provider on the workstation or exit OpenCode."
    )
    terminal.write(
        "No API-key fallback will be forwarded. Provider tokens stay on the workstation behind "
        "isolated per-instance relays. One approval covers multiple interactive turns and subagents "
        f"in this session. {disconnect_hint}"
    )
    prompt = f"Start interactive {ui_label} session for instance '{instance_name}'?"
    if not terminal.confirm(prompt):
        raise LaunchRefusedError("cancelled", _CANCELLED)

    return ResolvedLaunchPlan(
        admitted=tuple(admitted),
        excluded=tuple(excluded),
        acknowledged_digests=acknowledged,
        initial_provider_id=initial_provider_id,
        initial_model=initial_model,
        ui_mode=ui_mode,
        ui_source=ui_source,
    )


def _validate_modalities(values: object) -> None:
    if (
        type(values) is not list
        or not values
        or len(values) > len(_MODALITIES)
        or any(type(v) is not str or v not in _MODALITIES for v in values)
        or len(set(values)) != len(values)
    ):
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "Invalid provider model modality declaration.")


def _validate_model_definition(slug: str, defn: object, *, proof_hardened: bool) -> None:
    if type(defn) is not dict or set(defn) != _MODEL_DEF_KEYS:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Unexpected model schema for '{slug}'.")
    name = defn["name"]
    try:
        sanitized = sanitize_display_text(name)
    except ValueError:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Invalid model display name for '{slug}'.") from None
    if name != sanitized:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Unsanitized model display name for '{slug}'.")
    caps = defn["capabilities"]
    if type(caps) is not dict or set(caps) != _CAPABILITY_KEYS or type(caps["tools"]) is not bool:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Invalid model capabilities for '{slug}'.")
    if proof_hardened and caps["tools"] is not False:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Hardened proof model '{slug}' must disable tools.")
    _validate_modalities(caps["input"])
    _validate_modalities(caps["output"])
    lim = defn["limit"]
    if type(lim) is not dict or set(lim) != _LIMIT_KEYS:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Invalid model limits for '{slug}'.")
    for key in ("context", "output"):
        bound = lim[key]
        if type(bound) is not int or not 1 <= bound <= 10_000_000:
            raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Invalid model {key} limit for '{slug}'.")


def _validate_provider_settings(settings: object, *, assigned_port: int, assigned_token: str) -> None:
    if type(settings) is not dict or not set(settings) <= _SETTINGS_ALLOWED_KEYS:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "Unexpected keys in provider settings.")
    if "baseURL" not in settings or "apiKey" not in settings:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "Provider settings missing baseURL or apiKey.")
    expected_url = f"http://127.0.0.1:{assigned_port}/v1"
    if type(settings["baseURL"]) is not str or settings["baseURL"] != expected_url:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "Provider baseURL does not match assigned loopback relay.")
    api_key = settings["apiKey"]
    if type(api_key) is not str or not api_key or not hmac.compare_digest(api_key, assigned_token):
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "Provider apiKey does not match assigned worker token.")
    if "store" in settings and type(settings["store"]) is not bool:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "Provider store setting must be boolean.")
    if "include" in settings:
        inc = settings["include"]
        if (
            type(inc) is not list
            or len(inc) > 8
            or any(type(v) is not str or _INCLUDE_SLUG_RE.fullmatch(v) is None for v in inc)
        ):
            raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "Invalid provider include setting.")


def _validate_provider_entry(
    entry: object,
    item: InstancePreflight,
    *,
    display_label: str,
    assigned_port: int,
    assigned_token: str,
    proof_hardened: bool,
) -> None:
    if type(entry) is not dict or set(entry) != _ENTRY_KEYS:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Unexpected provider entry schema for '{item.spec.scoped_id}'.")
    expected_name = expected_provider_display_name(item, display_label)
    if type(entry["name"]) is not str or entry["name"] != expected_name:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Provider display name mismatch for '{item.spec.scoped_id}'.")
    allowed_pkgs = APPROVED_OPENCODE_PACKAGES_BY_KIND.get(item.spec.kind, frozenset())
    if type(entry["package"]) is not str or entry["package"] not in allowed_pkgs:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Unapproved provider package for '{item.spec.scoped_id}'.")
    _validate_provider_settings(entry["settings"], assigned_port=assigned_port, assigned_token=assigned_token)
    models = entry["models"]
    if type(models) is not dict or set(models) != set(item.models):
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, f"Provider model map mismatch for '{item.spec.scoped_id}'.")
    for slug, defn in models.items():
        _validate_model_definition(slug, defn, proof_hardened=proof_hardened)


def _expected_policies(plan: ResolvedLaunchPlan) -> list[dict[str, str]]:
    policies: list[dict[str, str]] = [
        {"action": "integration.connect", "resource": "*", "effect": "deny"},
        {"action": "provider.use", "resource": "*", "effect": "deny"},
    ]
    for item in plan.admitted:
        policies.append({"action": "provider.use", "resource": item.spec.scoped_id, "effect": "allow"})
    return policies


def validate_opencode_config(
    config_payload: object,
    *,
    plan: ResolvedLaunchPlan,
    slot_ports: Mapping[str, int],
    slot_tokens: Mapping[str, str],
    proof_hardened: bool = False,
    expected_model: str | None = None,
) -> None:
    """Validate the full worker opencode.json payload before and after proof hardening."""
    if type(config_payload) is not dict:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "OpenCode config payload must be a dict.")
    expected_keys = _HARDENED_TOP_KEYS if proof_hardened else _NORMAL_TOP_KEYS
    if set(config_payload) != expected_keys:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "OpenCode config top-level keys do not match contract.")
    if config_payload["$schema"] != _OPENCODE_SCHEMA or config_payload["update"] != "disable":
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "OpenCode config schema or update policy mismatch.")
    target_model = expected_model or f"{plan.initial_provider_id}/{plan.initial_model}"
    if config_payload["model"] != target_model:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "OpenCode config initial model mismatch.")
    if config_payload["policies"] != _expected_policies(plan):
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "OpenCode config policy list mismatch.")
    if proof_hardened:
        if (
            config_payload["snapshots"] is not False
            or config_payload["permissions"] != _HARDENED_PERMISSIONS
            or config_payload["plugins"] != _HARDENED_PLUGINS
        ):
            raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "Hardened OpenCode proof config failed invariants.")
    providers = config_payload["providers"]
    expected_ids = {item.spec.scoped_id for item in plan.admitted}
    if type(providers) is not dict or set(providers) != expected_ids:
        raise ProviderIntegrityError(_ERR_INVALID_ENTRY, "OpenCode config provider keys do not match admitted plan.")
    display_labels = compute_display_labels(plan.admitted)
    for item in plan.admitted:
        sid = item.spec.scoped_id
        _validate_provider_entry(
            providers[sid],
            item,
            display_label=display_labels[sid],
            assigned_port=slot_ports[sid],
            assigned_token=slot_tokens[sid],
            proof_hardened=proof_hardened,
        )


def _adapter_accepts_display_label(adapter: ProviderSessionAdapter) -> bool:
    try:
        params = inspect.signature(adapter.provider_config_entry).parameters
    except (TypeError, ValueError):
        return False
    return "display_label" in params or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
    )


def build_multi_provider_opencode_config(
    *,
    plan: ResolvedLaunchPlan,
    adapters: Mapping[str, ProviderSessionAdapter],
    slot_ports: Mapping[str, int],
    slot_tokens: Mapping[str, str],
) -> dict:
    """Build and strictly validate one read-only /etc/opencode/opencode.json for all admitted slots."""
    display_labels = compute_display_labels(plan.admitted)
    providers_block: dict[str, dict] = {}
    for item in plan.admitted:
        scoped_id = item.spec.scoped_id
        adapter = adapters[item.spec.kind]
        dlabel = display_labels[scoped_id]
        if _adapter_accepts_display_label(adapter):
            entry = adapter.provider_config_entry(
                item,
                port=slot_ports[scoped_id],
                worker_token=slot_tokens[scoped_id],
                display_label=dlabel,
            )
        else:
            entry = adapter.provider_config_entry(
                item,
                port=slot_ports[scoped_id],
                worker_token=slot_tokens[scoped_id],
            )
        providers_block[scoped_id] = entry

    payload = {
        "$schema": _OPENCODE_SCHEMA,
        "model": f"{plan.initial_provider_id}/{plan.initial_model}",
        "update": "disable",
        "mcp": {
            "chrome-devtools": {
                "type": "local",
                "command": [
                    "npx", "-y", "chrome-devtools-mcp@latest", "--browserUrl", "http://127.0.0.1:9222"
                ],
            }
        },
        "providers": providers_block,
        "policies": _expected_policies(plan),
    }
    validate_opencode_config(
        payload,
        plan=plan,
        slot_ports=slot_ports,
        slot_tokens=slot_tokens,
        proof_hardened=False,
    )
    return payload
