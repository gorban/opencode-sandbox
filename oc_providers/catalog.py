"""Multi-provider launch catalog, disclosure, explicit model selection, and config generation."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from .config import ProviderConfig
from .contracts import (
    CliUiMode,
    ExcludedInstance,
    ExposureHoldSummary,
    InstancePreflight,
    MAX_PROVIDER_SLOTS,
    PROVIDERS,
    ProviderId,
    ProviderInstanceSpec,
    ProviderIntegrityError,
    ProviderSessionAdapter,
    ReadinessState,
    UiMode,
    is_valid_instance_label,
)


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
        persisted = adapter.active_label()
        if persisted is not None:
            resolved_label = persisted
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


def _preflight_narrowed(
    provider_filter: str,
    config: ProviderConfig | None,
    adapters: Mapping[str, ProviderSessionAdapter],
) -> tuple[list[InstancePreflight], list[ExcludedInstance]]:
    kind, label = parse_provider_filter(provider_filter)
    adapter = adapters.get(kind)
    spec = _resolve_narrowed_spec(kind, label, config, adapter)
    if adapter is None or not adapter.is_qualified(spec.auth_mode, "sandbox"):
        raise LaunchRefusedError(
            "route_unqualified",
            f"Provider instance '{spec.qualified_name}' ({spec.auth_mode}) is not qualified for sandbox launch.",
        )
    preflight = adapter.preflight_instance(spec)
    if preflight.readiness is not ReadinessState.READY or not preflight.models:
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
        if adapter.is_qualified("subscription", "sandbox"):
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
        if adapter is None or not adapter.is_qualified(spec.auth_mode, "sandbox"):
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
        if preflight.readiness is ReadinessState.READY and preflight.models:
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
            raise LaunchRefusedError("exposure_hold_declined", "Cancelled.")
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
        f"{item.spec.qualified_name} ({item.spec.auth_mode}; {item.billing_summary})"
        for item in admitted
    ]
    picked = terminal.choose("Select initial active provider instance for this session:", labels)
    if picked is None or not 0 <= picked < len(admitted):
        raise LaunchRefusedError("cancelled", "Cancelled.")
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

    for item in admitted:
        preview = _format_model_preview(item.models)
        terminal.write(
            f"Provider {item.spec.qualified_name} [{item.spec.scoped_id}]: "
            f"auth={item.spec.auth_mode}, billing={item.billing_summary} (models: {preview})"
        )
    ui_label = "OpenCode Mini" if ui_mode == "mini" else "OpenCode"
    terminal.write(
        f"Initial active model: {initial_provider_id}/{initial_model} | "
        f"UI: {ui_label} ({ui_source}) | Workspace: /sandbox/{cwd}"
    )
    terminal.write(
        "No API-key fallback will be forwarded. Provider tokens stay on the workstation behind "
        "isolated per-instance relays. One approval covers multiple interactive turns and subagents "
        "in this session. Disconnect with `oc-sandbox openai disconnect [LABEL]` or exit OpenCode."
    )
    prompt = f"Start interactive {ui_label} session for instance '{instance_name}'?"
    if not terminal.confirm(prompt):
        raise LaunchRefusedError("cancelled", "Cancelled.")

    return ResolvedLaunchPlan(
        admitted=tuple(admitted),
        excluded=tuple(excluded),
        acknowledged_digests=acknowledged,
        initial_provider_id=initial_provider_id,
        initial_model=initial_model,
        ui_mode=ui_mode,
        ui_source=ui_source,
    )


def build_multi_provider_opencode_config(
    *,
    plan: ResolvedLaunchPlan,
    adapters: Mapping[str, ProviderSessionAdapter],
    slot_ports: Mapping[str, int],
    slot_tokens: Mapping[str, str],
) -> dict:
    """Build one read-only /etc/opencode/opencode.json containing all admitted provider slots."""
    providers_block: dict[str, dict] = {}
    policies: list[dict[str, str]] = [
        {"action": "integration.connect", "resource": "*", "effect": "deny"},
        {"action": "provider.use", "resource": "*", "effect": "deny"},
    ]
    for item in plan.admitted:
        scoped_id = item.spec.scoped_id
        adapter = adapters[item.spec.kind]
        providers_block[scoped_id] = adapter.provider_config_entry(
            item,
            port=slot_ports[scoped_id],
            worker_token=slot_tokens[scoped_id],
        )
        policies.append({"action": "provider.use", "resource": scoped_id, "effect": "allow"})

    return {
        "$schema": "https://opencode.ai/config.json",
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
        "policies": policies,
    }
