"""Select one workstation registration for the fixed attended acceptance."""

from contextlib import contextmanager
from pathlib import Path

from .cli import ConnectionStatus, Reason, RouteUnavailable, SavedProfile
from .connection import Connection, ConnectionError
from .exposure import ExposureError, ExposureLedger
from .live import WorkstationBackend, _mapped_connection_error, _mapped_exposure_error
from .profiles import Profiles


# The real account and inference paths require exact review of the integrated route.
_LOCAL_ACCEPTANCE_REVIEWED = True


class ProfileBackend:
    def __init__(self, state, *, connection=Connection, worker=None, reviewed=_LOCAL_ACCEPTANCE_REVIEWED):
        self._state = Path(state)
        self.profiles = Profiles(state)
        self.ledger = ExposureLedger(state)
        self._connection = connection
        self._worker = worker
        self._reviewed = reviewed

    def _backend(self, profile):
        return WorkstationBackend(
            self._connection(profile.directory), self.ledger,
            label=profile.label, selection_epoch=profile.epoch, worker=self._worker,
            placement_qualified=self._reviewed,
        )

    def _selected(self):
        profile = self.profiles.selected()
        return self._backend(profile) if profile is not None and not profile.retiring else None

    def _require_selected(self):
        backend = self._selected()
        if backend is None:
            raise RouteUnavailable(Reason.CONNECTION_CHANGED)
        return backend

    def connection(self):
        selected = self._selected()
        return selected.connection() if selected is not None else None

    def active_label(self):
        profile = self.profiles.selected()
        return profile.label if profile is not None else None

    def status(self):
        view = self.profiles.snapshot()
        try:
            saved = []
            for profile in (*view.saved, *view.unpublished):
                connection = self._connection(profile.directory)
                uncertain = connection.revocation_unconfirmed()
                published = profile.client_id is not None
                if published or uncertain or not connection.reclaimable_registration():
                    connected = published and not profile.retiring and connection.status() == "connected"
                    saved.append(SavedProfile(profile.label, connected, uncertain, published))
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        return ConnectionStatus(tuple(sorted(saved, key=lambda profile: profile.label)),
                                view.active.label if view.active is not None else None)

    def _require_idle(self, previous, target):
        if previous is None or previous.directory == target.directory:
            return
        try:
            self._connection(previous.directory).require_switchable()
            self.ledger.require_quiescent()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        except ExposureError as error:
            raise _mapped_exposure_error(error) from None

    def _select_ready(self, previous, target):
        self._require_idle(previous, target)
        try:
            self._connection(target.directory).binding()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None

    def select(self, label):
        self.profiles.select(label, self._select_ready)

    def connect(self, label, *, handoff=None):
        if not self._reviewed:
            raise RouteUnavailable(Reason.QUALIFICATION)
        try:
            self._connection(self._state / "registrations").require_prerequisites()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        with self.profiles.connect_candidate(
            label, reclaim=lambda profile: self._connection(profile.directory).reclaimable_registration(
                abandoned_attempt=True,
            ),
        ) as candidate:
            self._connect_candidate(candidate, handoff)

    def _connect_candidate(self, candidate, handoff):
        connection = self._connection(candidate.profile.directory)
        try:
            def publish(client_id):
                return self.profiles.publish(candidate, client_id, self._require_idle)

            saved = connection.saved_registration()
            if saved is None:
                connection.connect(
                    installation_host=candidate.profile.host_id, publication=publish,
                    authorization=lambda: self.profiles.authorize(candidate), handoff=handoff,
                )
            else:
                client_id, binding = saved
                with publish(client_id):
                    connection.require_active(binding)
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None

    def disconnect(self):
        observed = self.profiles.selected()
        physical_host = None
        if observed is not None:
            try:
                physical_host = self._connection(observed.directory).physical_host_for_retirement()
            except (ConnectionError, OSError):
                pass

        retirements = []
        errors = []

        def retire(profile):
            connection = self._connection(profile.directory)
            placement = physical_host if observed is not None and profile.directory == observed.directory else None
            try:
                if profile.client_id is not None and not profile.selected and connection.status() == "connected":
                    return False
                retirement = connection.begin_disconnect(physical_host=placement)
            except ConnectionError as error:
                raise _mapped_connection_error(error) from None
            retirements.append((connection, retirement))

        confirmed = True
        try:
            self.profiles.begin_disconnect(retire)
        finally:
            for connection, retirement in retirements:
                try:
                    if not connection.finish_disconnect(retirement):
                        confirmed = False
                except ConnectionError as error:
                    errors.append(error)
        if errors:
            raise _mapped_connection_error(errors[0]) from None
        return confirmed

    def require_acceptance(self, proposal, *, recovery=None):
        if not self._reviewed:
            raise RouteUnavailable(Reason.QUALIFICATION)
        if recovery is not None:
            with self.profiles.foreground():
                return self._require_selected().require_acceptance(proposal, recovery=recovery)
        return self._require_selected().require_acceptance(proposal)

    def propose(self, approval, *, diagnostic=None):
        with self.profiles.foreground():
            return self._require_selected().propose(approval, diagnostic=diagnostic)

    def prove(self, approval):
        with self.profiles.foreground():
            return self._require_selected().prove(approval)

    @contextmanager
    def recovery_proof(self, approval, source, *, worker_only=False, after_retry=False,
                       trace_only=False, after_trace=False, moderation_trace=False):
        if not self._reviewed:
            raise RouteUnavailable(Reason.QUALIFICATION)
        with self.profiles.foreground():
            proof = self._require_selected().recovery_proof(
                approval, source, worker_only=worker_only, after_retry=after_retry,
                trace_only=trace_only, after_trace=after_trace, moderation_trace=moderation_trace,
            )
            try:
                yield proof
            finally:
                proof.ledger.close()
