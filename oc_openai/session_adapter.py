"""OpenAI ChatGPT subscription adapter for the multi-provider sandbox launcher."""

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import secrets

from oc_providers.contracts import (
    ExposureHoldSummary,
    InstancePreflight,
    PersistedSelection,
    ProviderId,
    ProviderInstanceSpec,
    ProviderIntegrityError,
    ReadinessState,
    SelectionState,
    SlotHandle,
    is_valid_instance_label,
)
from .cli import Reason, RouteUnavailable
from .connection import ConnectionError
from .exposure import ExposureError, ExposureLedger
from .live import make_backend
from .profiles import Profile, ProfileError
from .session_broker import (
    SessionBroker,
    SessionPolicy,
    _SessionJob,
    _build_relay_args,
    build_openai_provider_entry,
)

_ERR_PROFILE_INTEGRITY = "OpenAI profile registry failed integrity checks."

_INTEGRITY_REASONS = frozenset({
    Reason.EXPOSURE_UNAVAILABLE,
    Reason.PROFILE_CONFLICT,
    Reason.PROOF_FAILED,
    Reason.PROVIDER_DATA,
    Reason.PYJWT_REQUIRED,
    Reason.PLACEMENT,
})


@dataclass(frozen=True)
class _OpenAISlotTarget:
    profile: Profile
    conn: object
    binding: object


class OpenAISessionAdapter:
    """Host-only ProviderSessionAdapter for qualified ChatGPT subscription registrations."""

    kind: ProviderId = "openai"

    def __init__(self, backend=None):
        self._backend = backend

    def _get_backend(self):
        if self._backend is None:
            self._backend = make_backend()
        return self._backend

    def is_qualified(self, auth_mode: str, placement: str) -> bool:
        return auth_mode == "subscription" and placement == "sandbox"

    def active_label(self) -> str | None:
        backend = self._get_backend()
        try:
            return backend.active_label()
        except ProfileError as exc:
            raise ProviderIntegrityError(exc.code, _ERR_PROFILE_INTEGRITY) from None

    def selection_state(self) -> PersistedSelection:
        backend = self._get_backend()
        try:
            view = backend.profiles.snapshot()
        except ProfileError as exc:
            raise ProviderIntegrityError(exc.code, _ERR_PROFILE_INTEGRITY) from None
        if view.active is not None and not view.active.retiring:
            return PersistedSelection(SelectionState.SELECTED, label=view.active.label)
        if view.saved or view.unpublished:
            return PersistedSelection(SelectionState.DISCONNECTED)
        return PersistedSelection(SelectionState.UNSET)

    def discover_instances(self) -> tuple[ProviderInstanceSpec, ...]:
        backend = self._get_backend()
        try:
            view = backend.profiles.snapshot()
        except ProfileError as exc:
            raise ProviderIntegrityError(exc.code, _ERR_PROFILE_INTEGRITY) from None

        seen_normalized: set[str] = set()
        discovered: list[ProviderInstanceSpec] = []
        for profile in (*view.saved, *view.unpublished):
            if profile.retiring:
                try:
                    conn = backend._connection(profile.directory)
                    if conn.status() == "disconnected" and not conn.has_active_leases():
                        continue
                except ConnectionError as exc:
                    raise ProviderIntegrityError(
                        exc.code, "OpenAI credential store failed integrity checks."
                    ) from None
            if not is_valid_instance_label(profile.label):
                raise ProviderIntegrityError(
                    "invalid_saved_label",
                    f"Saved OpenAI registration '{profile.label}' does not match canonical I4d label syntax. "
                    f"Disconnect it with `oc-sandbox openai disconnect {profile.label}` and reconnect with a "
                    "lowercase alphanumeric/hyphen label.",
                )
            normalized = profile.label.lower().replace("_", "-")
            if normalized in seen_normalized:
                raise ProviderIntegrityError(
                    "colliding_saved_label",
                    f"Saved OpenAI registration '{profile.label}' collides with another label.",
                )
            seen_normalized.add(normalized)
            discovered.append(
                ProviderInstanceSpec(
                    kind="openai",
                    label=profile.label,
                    enabled=True,
                    auth_mode="subscription",
                )
            )
        return tuple(discovered)

    def _inspect_shared_exposure(self, backend) -> ExposureHoldSummary | None:
        try:
            hold = ExposureLedger(backend._state).inspect_hold()
        except ExposureError as exc:
            code = exc.args[0] if exc.args and type(exc.args[0]) is str else "exposure_store_unavailable"
            raise ProviderIntegrityError(
                code, f"OpenAI exposure ledger failed integrity checks ({code})."
            ) from None
        if not hold.blocked:
            return None
        return ExposureHoldSummary(
            scope_id="openai",
            file_count=hold.file_count,
            unsettled_count=hold.unsettled_count,
            digest=hold.digest,
        )

    def _preflight_models(self, conn, binding) -> tuple[str, ...]:
        try:
            models = conn.models(binding)
        except ConnectionError as exc:
            if exc.code in {
                "untrusted_connection_path", "untrusted_connection_file", "invalid_connection_state",
                "connection_storage_unavailable",
            }:
                raise ProviderIntegrityError(exc.code, "OpenAI credential store failed integrity checks.") from None
            return ()
        return tuple(models) if models else ()

    def preflight_instance(self, instance: ProviderInstanceSpec) -> InstancePreflight:
        if instance.kind != "openai" or not self.is_qualified(instance.auth_mode, "sandbox"):
            return InstancePreflight(spec=instance, readiness=ReadinessState.UNQUALIFIED)

        backend = self._get_backend()
        try:
            profile, conn, binding = backend.profile_connection(instance.label)
        except ProfileError as exc:
            raise ProviderIntegrityError(exc.code, _ERR_PROFILE_INTEGRITY) from None
        except RouteUnavailable as exc:
            if exc.reason in _INTEGRITY_REASONS:
                raise ProviderIntegrityError(exc.reason.value, f"OpenAI integrity check failed ({exc.reason.value}).") from None
            if exc.reason is Reason.PROFILE_NOT_FOUND:
                return InstancePreflight(spec=instance, readiness=ReadinessState.DISCONNECTED)
            return InstancePreflight(spec=instance, readiness=ReadinessState.NEEDS_VERIFY)

        exposure_hold = self._inspect_shared_exposure(backend)
        models = self._preflight_models(conn, binding)
        if not models:
            return InstancePreflight(spec=instance, readiness=ReadinessState.NEEDS_VERIFY)
        return InstancePreflight(
            spec=instance,
            readiness=ReadinessState.READY,
            models=models,
            exposure_hold=exposure_hold,
            route_policy="subscription (no verified spending ceiling)",
            handle=_OpenAISlotTarget(profile=profile, conn=conn, binding=binding),
        )

    def provider_config_entry(
        self, preflight: InstancePreflight, *, port: int, worker_token: str
    ) -> dict:
        return build_openai_provider_entry(
            label=preflight.spec.label,
            port=port,
            worker_token=worker_token,
            models=preflight.models,
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
        backend = self._get_backend()
        target = preflight.handle
        if not isinstance(target, _OpenAISlotTarget):
            raise ProviderIntegrityError("invalid_slot_handle", "Missing OpenAI preflight handle.")
        profile = target.profile
        if profile.client_id is None:
            raise ProviderIntegrityError("invalid_slot_handle", "OpenAI registration is not published.")

        slot_root.mkdir(mode=0o700, exist_ok=True)
        job = _SessionJob(slot_root, "inc_" + secrets.token_hex(16))
        job.prepare(config_payload=None)
        lease_cm = backend.profile_session_lease(
            profile.label,
            profile.epoch,
            target.binding,
            job,
            directory=profile.directory,
            client_id=profile.client_id,
        )
        lease = lease_cm.__enter__()
        broker: SessionBroker | None = None
        try:
            broker = SessionBroker(
                socket_path=job.provider_socket,
                relay_proof=job.relay_proof,
                worker_token=worker_token,
                lease=job.lease,
                connection=target.conn,
                binding=target.binding,
                models=preflight.models,
                profile_label=profile.label,
                usage_dir=backend._state,
                expected_port=port,
                policy=SessionPolicy(
                    exposure_dir=backend._state,
                    acknowledged_exposure_digest=acknowledged_exposure_digest,
                    authorization=lambda: backend.profile_fence(
                        profile.label, profile.epoch, directory=profile.directory, client_id=profile.client_id,
                    ),
                    is_selected=lambda: backend.profile_valid(
                        profile.label, profile.epoch, directory=profile.directory, client_id=profile.client_id,
                    ),
                    on_revoke=lambda: on_revoke(slot_index),
                ),
            )
            broker.start()

            def build_relay_args(spec: dict) -> list[str]:
                return _build_relay_args(
                    spec,
                    job,
                    slot_index=slot_index,
                    port=port,
                    provider_label=preflight.spec.qualified_name,
                )

            yield SlotHandle(
                slot_index=slot_index,
                scoped_id=preflight.spec.scoped_id,
                provider_label=preflight.spec.qualified_name,
                port=port,
                job=job,
                broker=broker,
                lease=lease,
                build_relay_args=build_relay_args,
            )
        finally:
            cleanup_error: Exception | None = None
            try:
                job.revoke()
            except Exception as exc:
                cleanup_error = cleanup_error or exc
            if broker is not None:
                try:
                    broker.close()
                except Exception as exc:
                    cleanup_error = cleanup_error or exc
            try:
                lease_cm.__exit__(None, None, None)
            except Exception as exc:
                cleanup_error = cleanup_error or exc
            if cleanup_error is not None:
                raise cleanup_error
