"""Pure metadata-only contracts for workstation provider registration and readiness.

This module intentionally holds only canonical provider identifiers, redacted
readiness DTOs, and the narrow workstation auth/session protocols. It carries
no I/O, no credentials, and no provider-specific stream, lease, or safety logic.
"""

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re
from typing import Literal, Protocol

ProviderId = Literal["openai", "claude", "google"]
AuthMode = Literal["subscription", "api_key"]
UiMode = Literal["full", "mini"]
CliUiMode = Literal["default", "full", "mini"]

PROVIDERS: frozenset[str] = frozenset({"openai", "claude", "google"})
AUTH_MODES: frozenset[str] = frozenset({"subscription", "api_key"})
MAX_PROVIDER_SLOTS = 16
RELAY_PORT_MIN = 8401
RELAY_PORT_MAX = RELAY_PORT_MIN + MAX_PROVIDER_SLOTS - 1

INSTANCE_LABEL_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z", re.ASCII)
LEGACY_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z", re.ASCII)
MODEL_SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)

BrowserHandoff = Callable[[str, Callable[[], bool]], None]


def is_valid_instance_label(value: object) -> bool:
    """Validate canonical I4d instance labels (lowercase ASCII, single inner hyphens, <= 32 chars)."""
    return type(value) is str and len(value) <= 32 and INSTANCE_LABEL_RE.fullmatch(value) is not None


def is_valid_model_slug(value: object) -> bool:
    return type(value) is str and MODEL_SLUG_RE.fullmatch(value) is not None


def scoped_provider_id(kind: ProviderId, label: str) -> str:
    """Return a collision-free OpenCode provider ID for one (kind, label) instance."""
    if kind not in PROVIDERS or not is_valid_instance_label(label):
        raise ValueError("invalid provider instance identifier")
    return f"{kind}--{label}"


@dataclass(frozen=True)
class ProviderDescriptor:
    """Declarative static capabilities for a supported provider kind."""

    kind: ProviderId
    supports_cli_path: bool
    supported_auth_modes: frozenset[str]


PROVIDER_DESCRIPTORS: dict[str, ProviderDescriptor] = {
    "openai": ProviderDescriptor(
        kind="openai",
        supports_cli_path=False,
        supported_auth_modes=frozenset({"subscription", "api_key"}),
    ),
    "claude": ProviderDescriptor(
        kind="claude",
        supports_cli_path=True,
        supported_auth_modes=frozenset({"subscription", "api_key"}),
    ),
    "google": ProviderDescriptor(
        kind="google",
        supports_cli_path=True,
        supported_auth_modes=frozenset({"subscription", "api_key"}),
    ),
}


class ReadinessState(str, Enum):
    """Closed, redacted local readiness classification for a provider route."""

    READY = "ready"
    DISCONNECTED = "disconnected"
    NEEDS_VERIFY = "needs_verify"
    RETIRING = "retiring"
    REVOCATION_UNCONFIRMED = "revocation_unconfirmed"
    UNQUALIFIED = "unqualified"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class SavedProfile:
    """Redacted local registration summary (never contains tokens or account IDs)."""

    provider: ProviderId
    label: str
    connected: bool
    revocation_unconfirmed: bool = False
    published: bool = True
    readiness: ReadinessState = ReadinessState.DISCONNECTED


@dataclass(frozen=True)
class ConnectionStatus:
    """Projected local registration state without network I/O or credential refresh."""

    provider: ProviderId
    saved: tuple[SavedProfile, ...]
    active: str | None


@dataclass(frozen=True)
class ActiveBinding:
    """Opaque metadata-only binding for the selected workstation registration."""

    provider: ProviderId
    registration_id: str
    generation: str
    label: str
    selection_epoch: str


@dataclass(frozen=True)
class VerifyResult:
    """Filtered output of an explicit, inference-free workstation readiness probe."""

    provider: ProviderId
    label: str
    readiness: ReadinessState
    models: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProviderInstanceSpec:
    """Trusted operator configuration for one named provider instance."""

    kind: ProviderId
    label: str
    enabled: bool
    auth_mode: AuthMode
    credential_ref: str | None = None
    cli_path: str | None = None
    default_model: str | None = None

    @property
    def qualified_name(self) -> str:
        return f"{self.kind}/{self.label}"

    @property
    def scoped_id(self) -> str:
        return scoped_provider_id(self.kind, self.label)


@dataclass(frozen=True)
class ExposureHoldSummary:
    """Redacted summary of a valid active exposure hold scoped to a ledger root."""

    scope_id: str
    file_count: int
    unsettled_count: int
    digest: str


class SelectionState(str, Enum):
    """Tri-state persisted selection status for a provider kind."""

    UNSET = "unset"
    SELECTED = "selected"
    DISCONNECTED = "disconnected"


@dataclass(frozen=True)
class PersistedSelection:
    """Distinguishes never-selected from explicitly disconnected persisted selection."""

    state: SelectionState
    label: str | None = None


@dataclass(frozen=True)
class InstancePreflight:
    """Redacted readiness and route-policy result for one candidate provider instance."""

    spec: ProviderInstanceSpec
    readiness: ReadinessState
    models: tuple[str, ...] = ()
    exposure_hold: ExposureHoldSummary | None = None
    route_policy: str = ""
    handle: object = None


@dataclass(frozen=True)
class ExcludedInstance:
    """Benign exclusion recorded during default multi-provider preflight."""

    kind: ProviderId
    label: str
    reason: str
    detail: str


@dataclass(frozen=True)
class SlotHandle:
    """Live per-instance broker/relay handle returned by ProviderSessionAdapter.open_slot."""

    slot_index: int
    scoped_id: str
    provider_label: str
    port: int
    job: object
    broker: object
    lease: object
    build_relay_args: Callable[[dict], list[str]]
    mark_relay_created: Callable[[], None] | None = None
    confirm_relay_removed: Callable[[], None] | None = None


class ProviderIntegrityError(RuntimeError):
    """Fail-closed trust or storage integrity failure (never silently excluded)."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


class ProviderAuthBackend(Protocol):
    """Narrow host-only registration and readiness contract shared by CLI and orchestrator."""

    def status(self) -> ConnectionStatus:
        """Project local saved registration state without network calls or token refresh."""
        ...

    def verify(self) -> VerifyResult:
        """Run an explicit, inference-free workstation readiness check."""
        ...

    def connect(self, label: str, *, handoff: BrowserHandoff | None = None) -> None:
        """Enroll an isolated provider registration from an attended foreground terminal."""
        ...

    def select(self, label: str) -> None:
        """Switch the active saved registration while idle."""
        ...

    def disconnect(self, label: str | None = None) -> bool:
        """Revoke local oc-sandbox authority first, then attempt provider-scoped cleanup."""
        ...

    def active_label(self) -> str | None:
        """Return the active registration label from local metadata only."""
        ...


class ProviderSessionAdapter(Protocol):
    """Provider-agnostic runtime adapter for default multi-provider sandbox sessions."""

    kind: ProviderId

    def is_qualified(self, auth_mode: str, placement: str) -> bool:
        """Return True iff (auth_mode, placement) has cleared qualification."""
        ...

    def active_label(self) -> str | None:
        """Return persisted active registration label from local metadata only."""
        ...

    def selection_state(self) -> PersistedSelection:
        """Return tri-state persisted selection (unset, selected, or disconnected)."""
        ...

    def discover_instances(self) -> tuple[ProviderInstanceSpec, ...]:
        """Discover saved workstation registrations when providers.toml is absent."""
        ...

    def preflight_instance(self, instance: ProviderInstanceSpec) -> InstancePreflight:
        """Preflight readiness, models, and exposure hold without inference."""
        ...

    def provider_config_entry(self, preflight: InstancePreflight, *, port: int, worker_token: str) -> dict:
        """Build the OpenCode `providers[scoped_id]` config dict for this admitted instance."""
        ...

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
    ) -> AbstractContextManager[SlotHandle]:
        """Acquire per-instance lease and start isolated broker for this admitted slot."""
        ...
