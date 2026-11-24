"""Shared, provider-agnostic workstation registration and readiness contracts."""

from .contracts import (
    ActiveBinding,
    ConnectionStatus,
    PROVIDERS,
    ProviderAuthBackend,
    ProviderId,
    ReadinessState,
    SavedProfile,
    VerifyResult,
)

__all__ = [
    "ActiveBinding",
    "ConnectionStatus",
    "PROVIDERS",
    "ProviderAuthBackend",
    "ProviderId",
    "ReadinessState",
    "SavedProfile",
    "VerifyResult",
]
