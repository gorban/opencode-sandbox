"""Pure metadata-only contracts for workstation provider registration and readiness.

This module intentionally holds only canonical provider identifiers, redacted
readiness DTOs, and the narrow workstation auth/readiness protocol. It carries
no I/O, no credentials, and no provider-specific stream, lease, or safety logic.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol

ProviderId = Literal["openai", "claude", "google"]
PROVIDERS: frozenset[str] = frozenset({"openai", "claude", "google"})

BrowserHandoff = Callable[[str, Callable[[], bool]], None]


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

    def disconnect(self) -> bool:
        """Revoke local oc-sandbox authority first, then attempt provider-scoped cleanup."""
        ...

    def active_label(self) -> str | None:
        """Return the active registration label from local metadata only."""
        ...
