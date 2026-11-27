"""Own one metadata-only enrollment and cold check; keep consent in the caller."""

from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
import os
import stat
import time

from .auth_offer import CallbackDiagnostic, Outcome
from .enrollment_session import serve_cold_metadata, serve_initial_metadata
from .metadata_destination import MetadataDestinationError, MetadataRoute, _remaining
from .native_artifacts import StagedNativeBuild
from .native_enrollment_acp import NativeEnrollmentAcp
from .native_namespace import public_certificate, reserve_native_unit
from .native_service import NativeRetirementUnconfirmed, open_cold_service, open_enrollment_service, read_host_cgroup
from .native_transport import native_server_context, open_native_browser_listener, open_native_metadata_listener
from .registration import ColdObservation, _DIRECTORY, _write_private


class MetadataWorkflowError(RuntimeError):
    """The exact local metadata-only workflow could not complete."""


class CallbackWorkflowError(MetadataWorkflowError):
    """The callback did not yield an authorized metadata handoff."""

    def __init__(self, diagnostic):
        super().__init__("Google sign-in callback was unavailable")
        self.diagnostic = diagnostic


@dataclass(frozen=True, slots=True)
class MetadataRuntime:
    root: Path
    build: StagedNativeBuild
    certificate: Path
    private_key: Path
    custody: object | None = None

    def listeners(self, scope, *, cold):
        key = self.private_key.lstat()
        if (self.certificate.parent != self.root or self.private_key.parent != self.root
                or not stat.S_ISREG(key.st_mode) or key.st_uid != os.geteuid()
                or stat.S_IMODE(key.st_mode) != 0o600 or key.st_nlink != 1
                or os.path.samestat(key, self.certificate.lstat())):
            raise MetadataWorkflowError("Google metadata TLS key must remain private to its runtime owner")
        public_certificate(self.certificate)
        directory = self.root / "connector"
        runtime = os.open(self.root, _DIRECTORY)
        try:
            info = os.fstat(runtime)
            if (not os.path.samestat(info, self.root.lstat()) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise MetadataWorkflowError("Google metadata runtime is not private")
            os.mkdir("connector", 0o700, dir_fd=runtime)
        finally:
            os.close(runtime)
        routes = (MetadataRoute.TOKEN, MetadataRoute.LOAD_CODE_ASSIST)
        if cold:
            routes += (MetadataRoute.FETCH_AVAILABLE_MODELS,)
        contexts = {route: native_server_context(route, certificate=self.certificate, key=self.private_key)
                    for route in routes}
        return open_native_metadata_listener(directory, contexts=contexts, expected_group=scope.group,
                                             read_cgroup=read_host_cgroup, authorized=scope.active)


class _PhaseOwner:
    def __init__(self, authorized, fence, seconds):
        if fence is None:
            raise MetadataWorkflowError("Google metadata workflow requires the caller's revocation fence")
        self.fence = fence
        self._authorized = authorized
        self.deadline = time.monotonic() + seconds
        self.expired = False
        self.service = None
        self.identity = None
        self.open = True

    def authorized(self):
        with self.fence:
            if self.expired or time.monotonic() >= self.deadline:
                self.expired = True
                return False
            authorized = self._authorized() is True
            self.expired = time.monotonic() >= self.deadline
            return authorized and not self.expired

    def active(self):
        return (self.open and self.authorized() is True and self.service is not None
                and self.service.process.poll() is None)

    def group(self):
        if self.identity is None or not self.active():
            raise MetadataWorkflowError("Google metadata phase has no exact live invocation")
        return self.identity.group

    def bind(self, service, profile):
        with self.fence:
            self.service = service
            self.identity = service.attested
            profile.bind_native_invocation(service, authorized=self.active)

    def revoke(self):
        with self.fence:
            self.open = False

    def authorizes_offer(self, profile):
        profile.verify_native_invocation(authorized=self.active)
        return self.active()


def _receive_callback(offer, gate, *, notify, deadline, owner, profile):
    with owner.fence:
        _remaining(deadline)
        if not owner.authorizes_offer(profile):
            raise MetadataWorkflowError("Google sign-in owner retired before offer disclosure")
        notify(offer)
        _remaining(deadline)
        if not owner.authorizes_offer(profile):
            raise MetadataWorkflowError("Google sign-in owner retired after offer disclosure")
        gate.activate()
    while gate.outcome is Outcome.OPEN and owner.active():
        try:
            _remaining(deadline)
        except MetadataDestinationError as error:
            raise CallbackWorkflowError(CallbackDiagnostic.NO_MATCHING_CALLBACK) from error
        gate.serve_one()
    if gate.outcome is not Outcome.FORWARDED:
        raise CallbackWorkflowError(gate.diagnostic or CallbackDiagnostic.NO_MATCHING_CALLBACK)
    if not owner.active():
        raise CallbackWorkflowError(CallbackDiagnostic.FORWARDED_BEFORE_METADATA)


def _initialize_settings(profile):
    try:
        os.mkdir("antigravity-acp", 0o700, dir_fd=profile.fd)
        directory = os.open("antigravity-acp", _DIRECTORY, dir_fd=profile.fd)
        try:
            _write_private(directory, "settings.json", b'{"telemetry":{"enabled":false}}')
        finally:
            os.close(directory)
        os.fsync(profile.fd)
    except OSError:
        raise MetadataWorkflowError("Google enrollment settings could not be initialized") from None


def enroll_metadata(journal, runtime, *, disclose_offer, destination, authorized, fence):
    """Enroll under one owner and return an exact credential-bearing local registration.

    The caller owns the trusted attended gate, route destination and runtime
    directory. Disclosure only writes the link and returns without waiting for
    human input. The runtime contains no enrolled credential. The journal owns
    its distinct private profile and may retain a hold on failure.
    """
    owner = _PhaseOwner(authorized, fence, 180)
    with owner.fence:
        if not owner.authorized():
            raise MetadataWorkflowError("Google metadata enrollment owner is unavailable")
        enrollment = journal.begin(runtime.build.digest)
    with journal.enrollment_profile(enrollment) as profile, ExitStack() as listeners:
        with owner.fence:
            if not owner.authorized():
                raise MetadataWorkflowError("Google metadata enrollment owner retired before setup")
            _initialize_settings(profile)
        connector, accept = listeners.enter_context(runtime.listeners(owner, cold=False))
        browser, receive = listeners.enter_context(open_native_browser_listener(
            connector.parent, expected_group=owner.group, read_cgroup=read_host_cgroup,
            authorized=lambda: owner.authorizes_offer(profile), fence=owner.fence,
        ))
        acp = None
        unit = reserve_native_unit()
        custody = runtime.custody
        if custody is not None:
            custody.bind(profile.record_native_custody)
        with open_enrollment_service(runtime.root, runtime.build, profile=profile, connector=connector,
                                     ca=runtime.certificate, browser=browser,
                                     authorized=owner.authorized, fence=owner.fence,
                                     after_stop=lambda: acp.drain_retired_enrollment(), unit=unit, custody=custody) as service:
            try:
                owner.bind(service, profile)
                deadline = owner.deadline
                acp = NativeEnrollmentAcp(service.process, deadline, owner.active)
                acp.initialize()
                acp.verify_signed_out()
                acp.start_personal_sign_in()
                with receive(deadline) as (offer, gate):
                    _receive_callback(offer, gate, notify=disclose_offer, deadline=deadline, owner=owner, profile=profile)
                    observed = serve_initial_metadata(offer=offer, callback_gate=gate, profile=profile,
                                                      deadline=deadline, accept=accept, fence=owner.fence,
                                                      authorized=owner.active, destination=destination)
                    acp.finish_personal_sign_in()
            finally:
                owner.revoke()
        with owner.fence:
            profile.complete_enrollment(service, acp, completion=observed.completion, authorized=owner.authorized)
    return enrollment


def reopen_metadata(journal, enrollment, runtime, *, destination, authorized, fence):
    """Observe a fresh same-registration model catalog with zero prompts."""
    owner = _PhaseOwner(authorized, fence, 18)
    with owner.fence:
        if not owner.authorized() or runtime.build.digest != enrollment.build_digest:
            raise MetadataWorkflowError("Google cold metadata owner or native build changed")
        check = journal.begin_cold_check(enrollment)
    with journal.cold_profile(check) as profile:
        replica = None
        acp = None
        service = None
        try:
            with runtime.listeners(owner, cold=True) as (connector, accept):
                with owner.fence:
                    custody = runtime.custody
                    if custody is not None:
                        custody.bind(profile.record_native_custody)
                    replica = profile.stage_cold_source(runtime.root, reserve_native_unit(), authorized=owner.authorized)
                    if custody is not None:
                        custody.delegate_cold_cleanup()
                with open_cold_service(runtime.root, runtime.build, replica=replica, connector=connector,
                                       ca=runtime.certificate, authorized=owner.authorized, fence=owner.fence,
                                       after_stop=lambda: acp.drain_retired_metadata(), custody=custody) as service:
                    try:
                        owner.bind(service, profile)
                        deadline = owner.deadline
                        acp = NativeEnrollmentAcp(service.process, deadline, owner.active)
                        acp.initialize()
                        acp.open_metadata_session()
                        observed = serve_cold_metadata(profile=profile, deadline=deadline, accept=accept,
                                                       fence=owner.fence, authorized=owner.active, destination=destination)
                        acp.finish_metadata_session()
                    finally:
                        owner.revoke()
        except BaseException as error:
            if not isinstance(error, NativeRetirementUnconfirmed) and not isinstance(error.__cause__, NativeRetirementUnconfirmed):
                try:
                    _retire_replica(replica, service, owner.fence, runtime.custody)
                except (OSError, RuntimeError):
                    error.add_note("Google cold replica cleanup remains unresolved")
            raise
        _retire_replica(replica, service, owner.fence, runtime.custody)
        with owner.fence:
            profile.complete_cold_custody(ColdObservation(check, True, 0, True), completion=observed.completion,
                                          service=service, acp=acp, authorized=owner.authorized)
        return observed


def _retire_replica(replica, service, fence, custody):
    if replica is None or (custody is not None and not custody.cleanable):
        return
    with fence:
        if service is not None and service.retired is not None:
            replica.remove()
        else:
            replica.abandon_unlaunched()
