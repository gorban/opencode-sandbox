"""Bind the initial Google token exchange to subject and metadata checks."""

from dataclasses import dataclass, field
import json
import re
from threading import Lock

from .account_binding import MetadataOperation, SubjectProof, _unique_fields
from .metadata_destination import MetadataRoute, exchange
from .oauth_exchange import (
    _reject_constant, validate_authorization_code_exchange, validate_cold_grant, validate_enrollment_grant,
)


_LOAD_BODY = {"metadata": {"ideType": "ANTIGRAVITY"}}
_LOAD_REQUEST = json.dumps(_LOAD_BODY, sort_keys=True).encode("ascii")
_REQUEST_LIMIT = 256
_REPLY_LIMIT = 4096
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_METADATA_FIELDS = {"currentTier", "cloudaicompanionProject"}


class EnrollmentMetadataError(ValueError):
    """A redacted denial of initial enrollment metadata."""


def _bounded_object(body, limit):
    if type(body) is bytes and 0 < len(body) <= limit:
        try:
            result = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            pass
        else:
            if type(result) is dict:
                return result
    raise EnrollmentMetadataError("Invalid Google enrollment metadata JSON")


def _validate_load_request(body):
    if _bounded_object(body, _REQUEST_LIMIT) != _LOAD_BODY:
        raise EnrollmentMetadataError("Invalid Google enrollment metadata request")


def _valid_identifier(value):
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _valid_tier(value):
    if type(value) is not dict or value.keys() != {"id", "name"} or not _valid_identifier(value["id"]):
        return False
    name = value["name"]
    return type(name) is str and 0 < len(name) <= 256 and name.isprintable()


@dataclass(frozen=True, slots=True)
class LoadObservation:
    """Report which typed metadata was present without identifying the account."""

    tier_reported: bool
    project_reported: bool


@dataclass(frozen=True, slots=True)
class VerifiedLoadReply:
    """A bounded private native reply and its redacted shape observation."""

    body: bytes = field(repr=False)
    observation: LoadObservation

    def __reduce_ex__(self, _protocol):
        raise TypeError("Google enrollment metadata reply must remain in memory")


def _observe_load_reply(body):
    fields = _bounded_object(body, _REPLY_LIMIT)
    if (fields.keys() - _METADATA_FIELDS
            or ("currentTier" in fields and not _valid_tier(fields["currentTier"]))
            or ("cloudaicompanionProject" in fields and not _valid_identifier(fields["cloudaicompanionProject"]))):
        raise EnrollmentMetadataError("Invalid Google enrollment metadata response")
    return LoadObservation("currentTier" in fields, "cloudaicompanionProject" in fields)


class _LoadCodeAssist:
    def __init__(self, proof, deadline, spend, destination):
        self._proof = proof
        self._deadline = deadline
        self._spend = spend
        self._destination = destination
        self._lock = Lock()
        self._claimed = False

    def __call__(self, *, authorization, body):
        with self._lock:
            if self._claimed:
                raise EnrollmentMetadataError("Google enrollment metadata attempt was already consumed")
            self._claimed = True
        if type(authorization) is not bytes or not authorization.startswith(b"Bearer "):
            raise EnrollmentMetadataError("Invalid Google enrollment metadata authorization")
        self._proof.require_metadata_bearer(MetadataOperation.LOAD_CODE_ASSIST, authorization[7:])
        _validate_load_request(body)
        route = MetadataRoute.LOAD_CODE_ASSIST
        reply = self._destination(
            route, authorization=authorization, body=_LOAD_REQUEST, deadline=self._deadline,
            deliver=lambda send: self._spend(route, send),
        )
        return VerifiedLoadReply(reply, _observe_load_reply(reply))


@dataclass(frozen=True, slots=True)
class VerifiedTokenReply:
    """Private native reply and proof for this enrollment's metadata."""

    body: bytes = field(repr=False)
    proof: SubjectProof = field(repr=False)
    _load: _LoadCodeAssist = field(repr=False, compare=False)

    def load_code_assist(self, *, authorization: bytes, body: bytes) -> VerifiedLoadReply:
        """Validate and spend a single native metadata attempt after subject proof."""
        return self._load(authorization=authorization, body=body)

    def __reduce_ex__(self, _protocol):
        raise TypeError("Google enrollment reply must remain in memory")


def verify_initial_exchange(
    *, offer, callback_gate, authorization, form, bind_subject, deadline, spend, destination=exchange,
):
    """Return the native token reply only after the same issued bearer proves a subject.

    The controller binds the subject under the current owner and profile locks. Its
    spend callback takes the exact route and one destination write closure,
    consumes the durable allowance, and shares the revocation/dispatch fence.
    The caller still owns native HTTP framing, exact peer and response delivery.
    """
    callback = callback_gate.take_forwarded()
    validate_authorization_code_exchange(offer, callback, authorization=authorization, body=form)
    token_reply = destination(
        MetadataRoute.TOKEN, authorization=authorization, body=form, deadline=deadline,
        deliver=lambda send: spend(MetadataRoute.TOKEN, send),
    )
    grant = validate_enrollment_grant(token_reply)
    return _bind_token_reply(token_reply, grant.access_token, bind_subject, deadline, spend, destination)


def verify_cold_refresh(*, form, prepare_form, bind_subject, deadline, spend, destination=exchange):
    """Refresh only the pinned cold profile and verify the same subject before reply."""
    body = prepare_form(form)
    token_reply = destination(
        MetadataRoute.TOKEN, authorization=None, body=body, deadline=deadline,
        deliver=lambda send: spend(MetadataRoute.TOKEN, send),
    )
    access = validate_cold_grant(token_reply)
    return _bind_token_reply(token_reply, access, bind_subject, deadline, spend, destination)


def _bind_token_reply(token_reply, access, bind_subject, deadline, spend, destination):
    subject_reply = destination(
        MetadataRoute.USERINFO, authorization=b"Bearer " + access, deadline=deadline,
        deliver=lambda send: spend(MetadataRoute.USERINFO, send),
    )
    proof = bind_subject(access, subject_reply)
    proof.require_metadata_bearer(MetadataOperation.LOAD_CODE_ASSIST, access)
    return VerifiedTokenReply(token_reply, proof, _LoadCodeAssist(proof, deadline, spend, destination))
