"""Select one workstation registration for the fixed attended acceptance."""

from .cli import ConnectionStatus, Reason, RouteUnavailable, SavedProfile
from .connection import Connection, ConnectionError
from .exposure import ExposureError, ExposureLedger
from .live import WorkstationBackend, _mapped_connection_error
from .profiles import Profiles


# The real account and inference paths require exact review of the integrated route.
_LOCAL_ACCEPTANCE_REVIEWED = False


class ProfileBackend:
    def __init__(self, state, *, connection=Connection, worker=None, reviewed=_LOCAL_ACCEPTANCE_REVIEWED):
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
            saved = tuple(SavedProfile(profile.label, not profile.retiring and
                                       self._connection(profile.directory).status() == "connected")
                          for profile in view.saved)
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        return ConnectionStatus(saved, view.active.label if view.active is not None else None)

    def _require_idle(self, previous, target):
        if previous is None or previous.directory == target.directory:
            return
        try:
            self._connection(previous.directory).require_switchable()
            self.ledger.require_quiescent()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        except ExposureError:
            raise RouteUnavailable(Reason.EXPOSURE) from None

    def _select_ready(self, previous, target):
        self._require_idle(previous, target)
        try:
            self._connection(target.directory).binding()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None

    def select(self, label):
        self.profiles.select(label, self._select_ready)

    def connect(self, label):
        if not self._reviewed:
            raise RouteUnavailable(Reason.QUALIFICATION)
        candidate = self.profiles.begin(label)
        connection = self._connection(candidate.profile.directory)
        try:
            def publish(client_id):
                return self.profiles.publish(candidate, client_id, self._require_idle)

            saved = connection.saved_registration()
            if saved is None:
                connection.connect(installation_host=candidate.profile.host_id, publication=publish)
            else:
                client_id, binding = saved
                with publish(client_id):
                    connection.require_active(binding)
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        finally:
            self.profiles.abandon(candidate)

    def disconnect(self):
        connection = retirement = None

        def retire(profile):
            nonlocal connection, retirement
            connection = self._connection(profile.directory)
            retirement = connection.begin_disconnect()

        try:
            self.profiles.begin_disconnect(retire)
            return connection.finish_disconnect(retirement) if connection is not None else True
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None

    def require_acceptance(self):
        if not self._reviewed:
            raise RouteUnavailable(Reason.QUALIFICATION)
        self._require_selected().require_acceptance()

    def propose(self, approval):
        with self.profiles.foreground():
            return self._require_selected().propose(approval)

    def prove(self, approval):
        with self.profiles.foreground():
            return self._require_selected().prove(approval)
