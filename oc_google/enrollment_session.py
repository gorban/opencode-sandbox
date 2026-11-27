"""Serve the initial metadata phase on the supervisor's private native channels."""

from dataclasses import dataclass
from functools import partial
import time

from .cold_catalog import verify_cold_catalog
from .enrollment import LoadObservation, verify_cold_refresh, verify_initial_exchange
from .metadata_destination import MetadataRoute, _remaining
from .metadata_ingress import MetadataIngressError, read_cold_metadata_request, read_cold_refresh_request, read_enrollment_request
from .oauth_exchange import OAuthExchangeError
from .registration import RegistrationUnavailable
from .token_diagnostic import PostTokenStage, scoped_post_token, observe_post_token


class EnrollmentSessionError(RuntimeError):
    """The active enrollment supervisor could not complete the metadata phase."""


@dataclass(frozen=True, slots=True, init=False)
class MetadataCompletion:
    scope: object
    cold: bool


def _completed_phase(profile, cold):
    receipt = object.__new__(MetadataCompletion)
    object.__setattr__(receipt, "scope", profile.phase_scope)
    object.__setattr__(receipt, "cold", cold)
    return receipt


@dataclass(frozen=True, slots=True)
class InitialMetadataObservation:
    load: LoadObservation
    completion: MetadataCompletion


def serve_initial_metadata(
    *, offer, callback_gate, profile, deadline, accept, fence, authorized, destination, diagnostic=None,
    post_diagnostic=None,
):
    """Serve the ordered native token and load requests and return a redacted observation.

    The supervisor authenticates each channel in the accept() context manager and supplies the same
    reenterable fence it uses for revocation. It owns process teardown and must
    retire the entire attempt on failure. A completed phase grants no readiness.
    """
    return _serve_metadata(
        offer=offer, callback_gate=callback_gate, profile=profile, deadline=deadline, accept=accept,
        fence=fence, authorized=authorized, destination=destination, cold=False, diagnostic=diagnostic,
        post_diagnostic=post_diagnostic,
    )


@dataclass(frozen=True, slots=True)
class ColdMetadataObservation:
    load: LoadObservation
    gemini_models: tuple[str, ...]
    completion: MetadataCompletion


def serve_cold_metadata(*, profile, deadline, accept, fence, authorized, destination, post_diagnostic=None):
    """Serve the exact cold metadata phase under the same supervisor contract."""
    return _serve_metadata(
        offer=None, callback_gate=None, profile=profile, deadline=deadline, accept=accept,
        fence=fence, authorized=authorized, destination=destination, cold=True, post_diagnostic=post_diagnostic,
    )


def _serve_metadata(*, offer, callback_gate, profile, deadline, accept, fence, authorized, destination, cold,
                    diagnostic=None, post_diagnostic=None):
    channel_in_use = None
    live_diagnostic = None

    def dispatch(route, *, deadline, **request):
        return destination(route, deadline=min(deadline, time.monotonic() + 30), **request)

    def active_authority():
        return (time.monotonic() < deadline and authorized() is True
                and (channel_in_use is None or channel_in_use.active() is True)
                and authorized() is True and time.monotonic() < deadline)

    def check_owner():
        _remaining(deadline)
        if not active_authority():
            raise EnrollmentSessionError("Google enrollment owner retired")
        if cold:
            profile.verify_cold_source()
        profile.verify_native_invocation(authorized=active_authority)
        if not active_authority():
            raise EnrollmentSessionError("Google enrollment owner retired")

    def diagnostic_authority(channel):
        if channel_in_use is not channel:
            return False
        check_owner()
        return True

    def spend(route, send):
        with fence:
            check_owner()
            diagnostic = live_diagnostic if route is MetadataRoute.LOAD_CODE_ASSIST else None
            with observe_post_token(diagnostic, PostTokenStage.LOAD_ADMISSION, RegistrationUnavailable):
                profile.spend_metadata(route, send, authorized=active_authority)

    def bind_subject(bearer, body):
        with fence:
            check_owner()
            return profile.bind_subject(bearer, body, authorized=active_authority)

    def prepare_refresh(form):
        with fence:
            check_owner()
            with observe_post_token(live_diagnostic, PostTokenStage.COLD_REFRESH,
                                    OAuthExchangeError, RegistrationUnavailable):
                return profile.refresh_form(form)

    def publish_io(operation, argument, route):
        try:
            operation(argument)
        except OSError:
            try:
                raise EnrollmentSessionError("Google native metadata reply did not settle") from None
            except EnrollmentSessionError as error:
                if route is MetadataRoute.LOAD_CODE_ASSIST and live_diagnostic is not None:
                    live_diagnostic.mark(error, PostTokenStage.LOAD_NATIVE_REPLY)
                raise

    def publish_reply(connection, body, *, route):
        packet = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Cache-Control: no-store\r\nConnection: close\r\nContent-Length: "
            + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
        )
        with fence:
            check_owner()
            try:
                publish_io(connection.settimeout, min(2, _remaining(deadline)), route)
                if not active_authority():
                    raise EnrollmentSessionError("Google enrollment owner retired")
                publish_io(connection.sendall, packet, route)
            except OSError:
                raise EnrollmentSessionError("Google native metadata reply did not settle") from None
            check_owner()

    def verified_token(connection):
        if cold:
            with observe_post_token(live_diagnostic, PostTokenStage.COLD_REFRESH, MetadataIngressError):
                token = read_cold_refresh_request(connection, deadline=deadline)
            return verify_cold_refresh(
                form=token.body, prepare_form=prepare_refresh, bind_subject=bind_subject, deadline=deadline,
                spend=spend, destination=dispatch, post_diagnostic=live_diagnostic,
            )
        token = read_enrollment_request(connection, route=MetadataRoute.TOKEN, deadline=deadline)
        return verify_initial_exchange(
            offer=offer, callback_gate=callback_gate, authorization=token.authorization,
            form=token.body, bind_subject=bind_subject, deadline=deadline, spend=spend, destination=dispatch,
            diagnostic=diagnostic,
        )

    def native_round_trip(route, handle):
        nonlocal channel_in_use, live_diagnostic
        publish = partial(publish_reply, route=route)
        with fence:
            check_owner()
        with accept(route, deadline) as channel:
            try:
                with fence:
                    channel_in_use = channel
                    live_diagnostic = scoped_post_token(
                        post_diagnostic, fence, lambda: diagnostic_authority(channel),
                    )
                    check_owner()
                reply = handle(channel.stream)
                publish(channel.stream, reply.body)
            finally:
                with fence:
                    live_diagnostic = None
                    channel_in_use = None
        return reply

    def load_reply(connection):
        with observe_post_token(live_diagnostic, PostTokenStage.LOAD_ADMISSION, MetadataIngressError):
            load = read_enrollment_request(connection, route=MetadataRoute.LOAD_CODE_ASSIST, deadline=deadline)
        return verified.load_code_assist(authorization=load.authorization, body=load.body, post_diagnostic=live_diagnostic)

    def catalog_reply(connection):
        with observe_post_token(live_diagnostic, PostTokenStage.COLD_CATALOG, MetadataIngressError):
            request = read_cold_metadata_request(connection, route=MetadataRoute.FETCH_AVAILABLE_MODELS,
                                                 deadline=deadline)
        return verify_cold_catalog(
            proof=verified.proof, load_reply=loaded, authorization=request.authorization, body=request.body,
            deadline=deadline, spend=spend, destination=dispatch, post_diagnostic=live_diagnostic,
        )

    verified = native_round_trip(MetadataRoute.TOKEN, verified_token)
    loaded = native_round_trip(MetadataRoute.LOAD_CODE_ASSIST, load_reply)
    observation = loaded.observation
    if cold:
        catalog = native_round_trip(MetadataRoute.FETCH_AVAILABLE_MODELS, catalog_reply)
    with fence:
        check_owner()
        completion = _completed_phase(profile, cold)
        if cold:
            return ColdMetadataObservation(observation, catalog.gemini_models, completion)
        return InitialMetadataObservation(observation, completion)
