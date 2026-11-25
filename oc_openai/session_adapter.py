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
from .proof_gate import ClosedProofSlotGate
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

    def __init__(self, backend=None, *, proof_gate=None):
        self._backend = backend
        self._proof_gate = proof_gate

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

    def _select_slot_proof_gate(self, scoped_id: str, job: _SessionJob, *, discovery_only: bool):
        if self._proof_gate is None:
            return None
        if scoped_id != self._proof_gate.approval.scoped_provider_id:
            return ClosedProofSlotGate(scoped_id)
        if discovery_only:
            return ClosedProofSlotGate(scoped_id, refusal_code="proof_gate_not_armed")
        self._proof_gate.bind_incarnation(job.incarnation, job.generation)
        return self._proof_gate

    @staticmethod
    def _teardown_slot_resources(job: _SessionJob, broker: SessionBroker | None, lease_cm) -> None:
        cleanup_error: Exception | None = None
        for step in (
            job.revoke,
            (broker.close if broker is not None else None),
            (lambda: lease_cm.__exit__(None, None, None)),
        ):
            if step is None:
                continue
            try:
                step()
            except Exception as exc:
                cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise cleanup_error

    @contextmanager
    def _open_slot_phase(self, preflight: InstancePreflight, cfg: dict[str, object], *, discovery_only: bool):
        backend = self._get_backend()
        target = preflight.handle
        if not isinstance(target, _OpenAISlotTarget):
            raise ProviderIntegrityError("invalid_slot_handle", "Missing OpenAI preflight handle.")
        profile = target.profile
        if profile.client_id is None:
            raise ProviderIntegrityError("invalid_slot_handle", "OpenAI registration is not published.")

        slot_index = int(cfg["slot_index"])
        slot_root = Path(cfg["slot_root"])
        port = int(cfg["port"])
        worker_token = str(cfg["worker_token"])
        acknowledged_exposure_digest = cfg["acknowledged_exposure_digest"]
        on_revoke = cfg["on_revoke"]

        slot_root.mkdir(mode=0o700, exist_ok=True)
        job = _SessionJob(slot_root, "inc_" + secrets.token_hex(16))
        job.prepare(config_payload=None)
        slot_proof_gate = self._select_slot_proof_gate(
            preflight.spec.scoped_id, job, discovery_only=discovery_only,
        )
        release_state: dict[str, object] = {"allowed": True, "outcome": None}

        def record_release(outcome: str) -> None:
            release_state["outcome"] = outcome

        if hasattr(backend, "profile_session_lease_with_result"):
            lease_cm = backend.profile_session_lease_with_result(
                profile,
                target.binding,
                job,
                release_gate=lambda: bool(release_state["allowed"]),
                on_release_result=record_release,
            )
            has_release_result = True
        else:
            lease_cm = backend.profile_session_lease(
                profile.label,
                profile.epoch,
                target.binding,
                job,
                directory=profile.directory,
                client_id=profile.client_id,
                release_gate=lambda: bool(release_state["allowed"]),
            )
            has_release_result = False
        lease = lease_cm.__enter__()
        broker: SessionBroker | None = None
        defer_turn_bind = (
            self._proof_gate is not None
            and not discovery_only
            and slot_proof_gate is self._proof_gate
        )
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
                    proof_gate=slot_proof_gate,
                    job_incarnation=job.incarnation,
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
                    relay_name_override=(
                        f"{spec['pod']}-relay-disc-{slot_index}" if discovery_only else None
                    ),
                    defer_bind=defer_turn_bind,
                )

            def mark_relay_created() -> None:
                release_state["allowed"] = False

            def confirm_relay_removed() -> None:
                release_state["allowed"] = True

            def lease_release_confirmed() -> bool:
                return release_state["outcome"] in ("removed", "absent")

            yield SlotHandle(
                slot_index=slot_index,
                scoped_id=preflight.spec.scoped_id,
                provider_label=preflight.spec.qualified_name,
                port=port,
                job=job,
                broker=broker,
                lease=lease,
                build_relay_args=build_relay_args,
                mark_relay_created=mark_relay_created,
                confirm_relay_removed=confirm_relay_removed,
                lease_release_confirmed=(
                    lease_release_confirmed
                    if (has_release_result or self._proof_gate is not None)
                    else None
                ),
            )
        finally:
            self._teardown_slot_resources(job, broker, lease_cm)

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
        cfg = {
            "slot_index": slot_index,
            "slot_root": slot_root,
            "port": port,
            "worker_token": worker_token,
            "acknowledged_exposure_digest": acknowledged_exposure_digest,
            "on_revoke": on_revoke,
        }
        with self._open_slot_phase(preflight, cfg, discovery_only=False) as handle:
            yield handle

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
        cfg = {
            "slot_index": slot_index,
            "slot_root": slot_root,
            "port": port,
            "worker_token": worker_token,
            "acknowledged_exposure_digest": acknowledged_exposure_digest,
            "on_revoke": on_revoke,
        }
        with self._open_slot_phase(preflight, cfg, discovery_only=True) as handle:
            yield handle
