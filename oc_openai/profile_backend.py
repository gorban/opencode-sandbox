"""Select one workstation registration for the fixed attended acceptance."""

from contextlib import contextmanager
from pathlib import Path
import sys

from .cli import ConnectionStatus, Reason, RouteUnavailable, SavedProfile
from .connection import Connection, ConnectionError
from .exposure import ExposureError, ExposureLedger
from .live import WorkstationBackend, _mapped_connection_error, _mapped_exposure_error
from .profiles import ProfileError, Profiles


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

    def active_selection(self):
        """Return (label, selection_epoch) for the active non-retiring registration."""
        profile = self.profiles.selected()
        if profile is None or profile.retiring:
            return None
        return profile.label, profile.epoch

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

    def _require_all_idle(self, profiles):
        try:
            for profile in profiles:
                self._connection(profile.directory).require_switchable()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None

    def _require_idle(self, previous, target, *, allow_same=True):
        if previous is None or (allow_same and previous.directory == target.directory):
            return
        try:
            self._connection(previous.directory).require_switchable()
            self.ledger.require_quiescent()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        except ExposureError as error:
            raise _mapped_exposure_error(error) from None

    def _select_ready(self, previous, target):
        self._require_idle(previous, target, allow_same=False)
        try:
            self._connection(target.directory).binding()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None

    def select(self, label):
        self.profiles.select(label, self._select_ready, all_saved_check=self._require_all_idle)

    def verify(self):
        if not self._reviewed:
            raise RouteUnavailable(Reason.QUALIFICATION)
        with self.profiles.foreground():
            return self._require_selected().verify()

    def active_connection(self):
        """Return (label, selection_epoch, Connection, Binding) for the active registration."""
        if not self._reviewed:
            raise RouteUnavailable(Reason.QUALIFICATION)
        profile = self.profiles.selected()
        if profile is None or profile.retiring:
            raise RouteUnavailable(Reason.CONNECTION_CHANGED)
        conn = self._connection(profile.directory)
        try:
            binding = conn.binding()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        return profile.label, profile.epoch, conn, binding

    def profile_connection(self, label: str):
        """Return (profile, Connection, Binding) for a named published non-retiring registration."""
        if not self._reviewed:
            raise RouteUnavailable(Reason.QUALIFICATION)
        view = self.profiles.snapshot()
        profile = next((item for item in view.saved if item.label == label), None)
        if profile is None or profile.retiring:
            raise RouteUnavailable(Reason.PROFILE_NOT_FOUND if profile is None else Reason.CONNECTION_CHANGED)
        conn = self._connection(profile.directory)
        try:
            binding = conn.binding()
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None
        return profile, conn, binding

    def profile_valid(self, label: str, selection_epoch: str, *, directory: Path, client_id: str) -> bool:
        """Return True iff the named published registration still matches (epoch, directory, client_id)."""
        try:
            with self.profiles.profile_fence(
                label, selection_epoch, directory=directory, client_id=client_id,
            ):
                return True
        except ProfileError:
            return False

    def profile_fence(self, label: str, selection_epoch: str, *, directory: Path, client_id: str):
        """Hold profiles/state.lock while the named profile matches (epoch, directory, client_id)."""
        @contextmanager
        def _fence():
            try:
                with self.profiles.profile_fence(
                    label, selection_epoch, directory=directory, client_id=client_id,
                ):
                    yield
            except ProfileError:
                raise RouteUnavailable(Reason.CONNECTION_CHANGED) from None

        return _fence()

    @contextmanager
    def _acquire_session_lease(self, acquire_via, binding, job):
        if not self._reviewed:
            raise RouteUnavailable(Reason.QUALIFICATION)

        def acquire(profile):
            conn = self._connection(profile.directory)
            lease_cm = conn.session_lease(binding, job)
            try:
                return lease_cm, lease_cm.__enter__()
            except ConnectionError as error:
                raise _mapped_connection_error(error) from None

        try:
            lease_cm, lease = acquire_via(acquire)
        except ProfileError:
            raise RouteUnavailable(Reason.CONNECTION_CHANGED) from None

        exc = (None, None, None)
        try:
            yield lease
        except BaseException:
            exc = sys.exc_info()
            raise
        finally:
            try:
                lease_cm.__exit__(*exc)
            except ConnectionError as error:
                mapped = _mapped_connection_error(error)
                if exc[0] is None:
                    raise mapped from None
                raise mapped from exc[1]

    def profile_session_lease(self, label: str, selection_epoch: str, binding, job, *, directory: Path, client_id: str):
        """Acquire a session lease for a named published profile atomically under profiles.lock."""
        return self._acquire_session_lease(
            lambda acquire: self.profiles.with_profile(
                label, selection_epoch, acquire, directory=directory, client_id=client_id,
            ),
            binding,
            job,
        )

    def selected_fence(self, label, selection_epoch):
        """Return a context manager holding profiles/state.lock while (label, selection_epoch) is active."""
        @contextmanager
        def _fence():
            try:
                with self.profiles.selected_fence(label, selection_epoch):
                    yield
            except ProfileError:
                raise RouteUnavailable(Reason.CONNECTION_CHANGED) from None

        return _fence()

    def canary_fenced_write(self, label, selection_epoch, conn, binding, action):
        """Execute a final client write under profiles.lock -> store.lock."""
        try:
            return conn.fenced_write(binding, lambda: self.selected_fence(label, selection_epoch), action)
        except ConnectionError as error:
            raise _mapped_connection_error(error) from None

    def session_lease(self, label, selection_epoch, binding, job):
        """Acquire a concurrent session lease atomically under the profile registry mutex."""
        return self._acquire_session_lease(
            lambda acquire: self.profiles.with_selected(label, selection_epoch, acquire),
            binding,
            job,
        )

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
                return self.profiles.publish(
                    candidate, client_id, self._require_idle, all_saved_check=self._require_all_idle,
                )

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

    def _collect_retirement_hosts(self):
        hosts = {}
        view = self.profiles.snapshot()
        for profile in (*view.saved, *view.unpublished):
            try:
                proof = self._connection(profile.directory).physical_host_for_retirement()
            except (ConnectionError, OSError):
                proof = None
            if proof is not None:
                hosts[profile.directory] = proof
        return hosts

    def _begin_disconnect_pass(self, physical_hosts, retired_dirs, retirements, *, label: str | None = None):
        def has_leases(profile):
            if profile.directory in retired_dirs:
                return True
            try:
                return self._connection(profile.directory).has_active_leases()
            except ConnectionError as error:
                raise _mapped_connection_error(error) from None

        def retire(profile):
            if profile.directory in retired_dirs:
                return None
            connection = self._connection(profile.directory)
            placement = physical_hosts.get(profile.directory)
            try:
                if (label is None and profile.client_id is not None and not profile.selected
                        and connection.status() == "connected" and not connection.has_active_leases()):
                    return False
                retirement = connection.begin_disconnect(physical_host=placement)
            except ConnectionError as error:
                raise _mapped_connection_error(error) from None
            retired_dirs.add(profile.directory)
            retirements.append((connection, retirement))

        self.profiles.begin_disconnect(retire, inactive_filter=has_leases, label=label)

    def disconnect(self, label: str | None = None):
        retirements = []
        retired_dirs = set()
        errors = []
        confirmed = True
        try:
            for attempt in range(2):
                physical_hosts = self._collect_retirement_hosts()
                try:
                    self._begin_disconnect_pass(physical_hosts, retired_dirs, retirements, label=label)
                    break
                except RouteUnavailable as error:
                    if error.reason is Reason.MANAGED_RETIREMENT and attempt == 0:
                        continue
                    raise
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
