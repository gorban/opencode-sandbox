"""Default workstation provider session adapter registry.

Production launches keep unqualified providers (Google, Claude) strictly closed and
excluded until their respective enrollment, transport, and live gates clear separately.
"""

from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from .contracts import (
    InstancePreflight,
    PersistedSelection,
    ProviderId,
    ProviderInstanceSpec,
    ProviderIntegrityError,
    ProviderSessionAdapter,
    ReadinessState,
    SelectionState,
    SlotHandle,
)

_ERR_UNQUALIFIED = "route_unqualified"


class UnqualifiedProviderAdapter:
    """Fail-closed placeholder adapter for providers not yet qualified for sandbox launch."""

    def __init__(self, kind: ProviderId):
        self.kind: ProviderId = kind

    def is_qualified(self, auth_mode: str, placement: str) -> bool:
        del auth_mode, placement
        return False

    def active_label(self) -> str | None:
        return None

    def selection_state(self) -> PersistedSelection:
        return PersistedSelection(SelectionState.UNSET)

    def discover_instances(self) -> tuple[ProviderInstanceSpec, ...]:
        return ()

    def preflight_instance(self, instance: ProviderInstanceSpec) -> InstancePreflight:
        return InstancePreflight(spec=instance, readiness=ReadinessState.UNQUALIFIED)

    def provider_config_entry(
        self,
        preflight: InstancePreflight,
        *,
        port: int,
        worker_token: str,
        display_label: str | None = None,
    ) -> dict:
        del preflight, port, worker_token, display_label
        raise ProviderIntegrityError(
            _ERR_UNQUALIFIED,
            f"Provider '{self.kind}' is not qualified for sandbox launch.",
        )

    @contextmanager
    def open_slot(
        self,
        preflight: InstancePreflight,
        *,
        slot_index: int,
        slot_root: Path,
        port: int,
        worker_token: str,
        acknowledged_exposure_digest: str | None,
        on_revoke: Callable[[int], None],
    ):
        del preflight, slot_index, slot_root, port, worker_token, acknowledged_exposure_digest, on_revoke
        raise ProviderIntegrityError(
            _ERR_UNQUALIFIED,
            f"Provider '{self.kind}' is not qualified for sandbox launch.",
        )
        yield SlotHandle(0, "", "", 0, None, None, None, lambda _s: [])  # pragma: no cover

    @contextmanager
    def open_discovery_slot(
        self,
        preflight: InstancePreflight,
        *,
        slot_index: int,
        slot_root: Path,
        port: int,
        worker_token: str,
        acknowledged_exposure_digest: str | None,
        on_revoke: Callable[[int], None],
    ):
        del preflight, slot_index, slot_root, port, worker_token, acknowledged_exposure_digest, on_revoke
        raise ProviderIntegrityError(
            _ERR_UNQUALIFIED,
            f"Provider '{self.kind}' is not qualified for sandbox launch.",
        )
        yield SlotHandle(0, "", "", 0, None, None, None, lambda _s: [])  # pragma: no cover


def default_session_adapters(
    *,
    backend_factory: Callable[[], object],
    proof_gate=None,
) -> dict[str, ProviderSessionAdapter]:
    """Build the production multi-provider adapter map without importing oc_openai at module import."""
    from oc_openai.session_adapter import OpenAISessionAdapter

    return {
        "openai": OpenAISessionAdapter(backend_factory(), proof_gate=proof_gate),
        "google": UnqualifiedProviderAdapter("google"),
        "claude": UnqualifiedProviderAdapter("claude"),
    }
