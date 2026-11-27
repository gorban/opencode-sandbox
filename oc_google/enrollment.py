"""Bind the initial Google token exchange to subject and metadata checks."""

from dataclasses import dataclass, field
import json
import math
import re
from threading import Lock

from .account_binding import AccountBindingError, MetadataOperation, SubjectProof, _unique_fields
from .metadata_destination import MetadataDestinationError, MetadataRoute, _ObservedDelivery, _ObservedPostDelivery, exchange
from .oauth_exchange import (
    _GrantRefused, _reject_constant, validate_authorization_code_exchange, validate_cold_grant,
    validate_enrollment_grant,
)
from .token_diagnostic import LoadBodyReason, ScopedPostTokenDiagnostic, PostTokenStage, TokenDiagnostic, observe_post_token


_LOAD_BODY = {"metadata": {"ideType": "ANTIGRAVITY"}}
_LOAD_REQUEST = json.dumps(_LOAD_BODY, sort_keys=True).encode("ascii")
_REQUEST_LIMIT = 256
_REPLY_LIMIT = 4096
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_METADATA_FIELDS = {"currentTier", "cloudaicompanionProject"}

_RICH_REPLY_LIMIT = 16 * 1024
_RICH_STRINGS = {"manageSubscriptionUri", "upgradeSubscriptionUri", "g1Tier"}
_RICH_FIELDS = _METADATA_FIELDS | _RICH_STRINGS | {
    "paidTier", "allowedTiers", "ineligibleTiers", "projectValidationError", "gcpManaged", "releaseChannel",
}
_PERSONAL_FLAGS = {"usesGcpTos", "userDefinedCloudaicompanionProject"}
_TIER_FLAGS = _PERSONAL_FLAGS | {"isDefault"}
_TIER_STRINGS = {
    "name", "description", "upgradeSubscriptionUri", "upgradeSubscriptionText", "upgradeButtonText",
    "clientExperienceTag", "referralInviteUri",
}
_TIER_FIELDS = _TIER_FLAGS | _TIER_STRINGS | {"id", "privacyNotice", "availableCredits", "upgradeSubscriptionType"}
_INELIGIBLE_STRINGS = {
    "reasonMessage", "tierName", "validationErrorMessage", "validationUrlLinkText", "validationUrl",
    "validationLearnMoreLinkText", "validationLearnMoreUrl",
}
_ENUM = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")


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


def _rich_bound_failure(value, depth=1):
    if type(value) is dict:
        if depth > 6 or len(value) > 24:
            return LoadBodyReason.STRUCTURE_LIMITS
        for key, item in value.items():
            failure = _rich_bound_failure(key) or _rich_bound_failure(item, depth + 1)
            if failure is not None:
                return failure
        return None
    if type(value) is list:
        if depth > 6 or len(value) > 16:
            return LoadBodyReason.STRUCTURE_LIMITS
        for item in value:
            failure = _rich_bound_failure(item, depth + 1)
            if failure is not None:
                return failure
        return None
    if type(value) is str:
        return None if len(value.encode("utf-8")) <= 1024 else LoadBodyReason.STRUCTURE_LIMITS
    if type(value) is float:
        return None if math.isfinite(value) else LoadBodyReason.JSON_OBJECT
    return None if value is None or type(value) in (bool, int) else LoadBodyReason.STRUCTURE_LIMITS


def _printable(value):
    return type(value) is str and (not value or value.isprintable())


def _known_enum_shape(value):
    return (type(value) is str and _ENUM.fullmatch(value) is not None
            or type(value) is int and 0 <= value < (1 << 31))


def _rich_tier(tier, *, flags=_TIER_FLAGS):
    if type(tier) is not dict or tier.keys() - _TIER_FIELDS or not _valid_identifier(tier.get("id")):
        return False
    return (all(_printable(tier[key]) for key in tier.keys() & _TIER_STRINGS)
            and all(type(tier[key]) is bool for key in tier.keys() & flags)
            and ("privacyNotice" not in tier or type(tier["privacyNotice"]) is dict)
            and ("availableCredits" not in tier or type(tier["availableCredits"]) is list
                 and all(type(credit) is dict for credit in tier["availableCredits"]))
            and ("upgradeSubscriptionType" not in tier or _known_enum_shape(tier["upgradeSubscriptionType"])))


def _retained_tier_shape(tier):
    return (_rich_tier(tier, flags=_TIER_FLAGS - _PERSONAL_FLAGS)
            and _valid_tier({key: tier.get(key) for key in ("id", "name")}))


def _nonpersonal_tier(tier):
    return type(tier) is dict and any(tier.get(key, False) is not False for key in _PERSONAL_FLAGS)


def _valid_alternatives(allowed, ineligible, active):
    if allowed is not None:
        if type(allowed) is not list or not all(_rich_tier(tier) for tier in allowed):
            return False
        ids = {tier["id"] for tier in allowed}
        if len(ids) != len(allowed):
            return False
        for alternative in allowed:
            for retained in active:
                if alternative["id"] == retained["id"] and (
                    alternative.get("name", retained["name"]) != retained["name"]
                    or alternative.get("usesGcpTos", False) is True
                    or alternative.get("userDefinedCloudaicompanionProject", False) is True
                ):
                    return False
    if ineligible is None:
        return True
    if type(ineligible) is not list:
        return False
    seen = {tier["id"] for tier in active}
    for row in ineligible:
        if (type(row) is not dict or row.keys() - (_INELIGIBLE_STRINGS | {"tierId", "reasonCode"})
                or not _valid_identifier(row.get("tierId")) or row["tierId"] in seen
                or any(not _printable(row[key]) for key in row.keys() & _INELIGIBLE_STRINGS)
                or ("reasonCode" in row and not _known_enum_shape(row["reasonCode"]))):
            return False
        seen.add(row["tierId"])
    return True


def _retained_tier(tier):
    retained = {"id": tier["id"], "name": tier["name"]}
    if "usesGcpTos" in tier:
        retained["usesGcpTos"] = tier["usesGcpTos"]
    return retained


def _load_body_refused(reasons):
    error = EnrollmentMetadataError("Invalid Google enrollment metadata response")
    error.load_body_reasons = tuple(reasons)
    return error


def _rich_load_reasons(fields, current, project, paid):
    reasons = []
    current_valid = _retained_tier_shape(current)
    paid_valid = paid is not None and _retained_tier_shape(paid)
    if fields.keys() - _RICH_FIELDS:
        reasons.append(LoadBodyReason.TOP_LEVEL_FIELDS)
    if not current_valid:
        reasons.append(LoadBodyReason.CURRENT_TIER)
    if not _valid_identifier(project):
        reasons.append(LoadBodyReason.ORIGINAL_PROJECT)
    if paid is not None and not paid_valid:
        reasons.append(LoadBodyReason.PAID_TIER)
    if (fields.get("gcpManaged", False) is not False or fields.get("projectValidationError") is not None
            or _nonpersonal_tier(current) or _nonpersonal_tier(paid)):
        reasons.append(LoadBodyReason.CONSUMER_PROJECT_POLICY)
    if (("releaseChannel" in fields and type(fields["releaseChannel"]) is not dict)
            or any(fields[key] is not None and not _printable(fields[key]) for key in fields.keys() & _RICH_STRINGS)):
        reasons.append(LoadBodyReason.OPTIONAL_METADATA)
    active = tuple(tier for tier, valid in ((current, current_valid), (paid, paid_valid)) if valid)
    if not _valid_alternatives(fields.get("allowedTiers"), fields.get("ineligibleTiers"), active):
        reasons.append(LoadBodyReason.ALTERNATIVE_TIER_POLICY)
    return reasons


def project_load_reply(body) -> VerifiedLoadReply:
    """Keep legacy bytes or project an already complete personal LOAD result."""
    try:
        return VerifiedLoadReply(body, _observe_load_reply(body))
    except EnrollmentMetadataError:
        pass

    try:
        fields = _bounded_object(body, _RICH_REPLY_LIMIT)
    except EnrollmentMetadataError as error:
        reason = (LoadBodyReason.SIZE if type(body) is bytes and not 0 < len(body) <= _RICH_REPLY_LIMIT
                  else LoadBodyReason.JSON_OBJECT)
        error.load_body_reasons = (reason,)
        raise
    try:
        bound_failure = _rich_bound_failure(fields)
    except UnicodeError:
        bound_failure = LoadBodyReason.JSON_OBJECT
    if bound_failure is not None:
        raise _load_body_refused((bound_failure,))
    current = fields.get("currentTier")
    paid = fields.get("paidTier")
    project = fields.get("cloudaicompanionProject")
    reasons = _rich_load_reasons(fields, current, project, paid)
    if reasons:
        raise _load_body_refused(reasons)
    projected = {"currentTier": _retained_tier(current), "cloudaicompanionProject": project}
    if paid is not None:
        projected["paidTier"] = _retained_tier(paid)
    body = json.dumps(projected, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return VerifiedLoadReply(body, LoadObservation(True, True))


class _LoadCodeAssist:
    def __init__(self, proof, deadline, spend, destination):
        self._proof = proof
        self._deadline = deadline
        self._spend = spend
        self._destination = destination
        self._lock = Lock()
        self._claimed = False

    def __call__(self, *, authorization, body, post_diagnostic=None):
        with observe_post_token(post_diagnostic, PostTokenStage.LOAD_ADMISSION,
                                EnrollmentMetadataError, AccountBindingError):
            with self._lock:
                if self._claimed:
                    raise EnrollmentMetadataError("Google enrollment metadata attempt was already consumed")
                self._claimed = True
            if type(authorization) is not bytes or not authorization.startswith(b"Bearer "):
                raise EnrollmentMetadataError("Invalid Google enrollment metadata authorization")
            self._proof.require_metadata_bearer(MetadataOperation.LOAD_CODE_ASSIST, authorization[7:])
            _validate_load_request(body)
        reply, observed = _exchange_observed(
            MetadataRoute.LOAD_CODE_ASSIST, authorization=authorization, body=_LOAD_REQUEST, deadline=self._deadline,
            spend=self._spend, destination=self._destination, post_diagnostic=post_diagnostic,
        )
        with observe_post_token(post_diagnostic if observed else None, PostTokenStage.LOAD_BODY,
                                EnrollmentMetadataError):
            return project_load_reply(reply)


@dataclass(frozen=True, slots=True)
class VerifiedTokenReply:
    """Private native reply and proof for this enrollment's metadata."""

    body: bytes = field(repr=False)
    proof: SubjectProof = field(repr=False)
    _load: _LoadCodeAssist = field(repr=False, compare=False)

    def load_code_assist(self, *, authorization: bytes, body: bytes, post_diagnostic=None) -> VerifiedLoadReply:
        """Validate and spend a single native metadata attempt after subject proof."""
        return self._load(authorization=authorization, body=body, post_diagnostic=post_diagnostic)

    def __reduce_ex__(self, _protocol):
        raise TypeError("Google enrollment reply must remain in memory")


def verify_initial_exchange(
    *, offer, callback_gate, authorization, form, bind_subject, deadline, spend, destination=exchange,
    diagnostic=None,
):
    """Return the native token reply only after the same issued bearer proves a subject.

    The controller binds the subject under the current owner and profile locks. Its
    spend callback takes the exact route and one destination write closure,
    consumes the durable allowance, and shares the revocation/dispatch fence.
    The caller still owns native HTTP framing, exact peer and response delivery.
    """
    callback = callback_gate.take_forwarded()
    validate_authorization_code_exchange(offer, callback, authorization=authorization, body=form)
    reply, observed = _exchange_observed(
        MetadataRoute.TOKEN, authorization=authorization, body=form, deadline=deadline,
        spend=spend, destination=destination, diagnostic=diagnostic,
    )
    try:
        grant = validate_enrollment_grant(reply)
    except _GrantRefused as error:
        if observed:
            diagnostic.mark(error)
        raise
    return _bind_token_reply(grant, bind_subject, deadline, spend, destination,
                             diagnostic=diagnostic if observed else None)


_POST_HTTP_STAGE = {
    MetadataRoute.TOKEN: PostTokenStage.COLD_REFRESH,
    MetadataRoute.USERINFO: PostTokenStage.COLD_SUBJECT,
    MetadataRoute.LOAD_CODE_ASSIST: PostTokenStage.LOAD_HTTP_REPLY,
    MetadataRoute.FETCH_AVAILABLE_MODELS: PostTokenStage.COLD_CATALOG,
}


def _exchange_observed(route, *, authorization, deadline, spend, destination, diagnostic=None,
                       post_diagnostic=None, **request):
    observed = object()

    def deliver(send):
        return spend(route, send)

    def observe(result):
        nonlocal observed
        observed = result

    if type(diagnostic) is TokenDiagnostic:
        deliver = _ObservedDelivery(route, deliver, observe)
    elif type(post_diagnostic) is ScopedPostTokenDiagnostic:
        deliver = _ObservedPostDelivery(route, deliver, observe)
    try:
        reply = destination(route, authorization=authorization, deadline=deadline, deliver=deliver, **request)
    except MetadataDestinationError as error:
        if error is observed:
            if type(diagnostic) is TokenDiagnostic:
                diagnostic.mark(error)
            else:
                post_diagnostic.mark(error, _POST_HTTP_STAGE[route])
        raise
    else:
        return reply, reply is observed
    finally:
        observed = None


def verify_cold_refresh(*, form, prepare_form, bind_subject, deadline, spend, destination=exchange,
                        post_diagnostic=None):
    """Refresh only the pinned cold profile and verify the same subject before reply."""
    body = prepare_form(form)
    reply, observed = _exchange_observed(
        MetadataRoute.TOKEN, authorization=None, body=body, deadline=deadline,
        spend=spend, destination=destination, post_diagnostic=post_diagnostic,
    )
    with observe_post_token(post_diagnostic if observed else None, PostTokenStage.COLD_REFRESH, _GrantRefused):
        grant = validate_cold_grant(reply)
    return _bind_token_reply(grant, bind_subject, deadline, spend, destination, post_diagnostic=post_diagnostic,
                             cold=True)


def _bind_token_reply(grant, bind_subject, deadline, spend, destination, *, diagnostic=None, post_diagnostic=None,
                      cold=False):
    access = grant.access_token
    subject_reply, observed = _exchange_observed(
        MetadataRoute.USERINFO, authorization=b"Bearer " + access, deadline=deadline,
        spend=spend, destination=destination, diagnostic=diagnostic, post_diagnostic=post_diagnostic if cold else None,
    )
    with observe_post_token(post_diagnostic if cold and observed else None, PostTokenStage.COLD_SUBJECT,
                            AccountBindingError):
        proof = bind_subject(access, subject_reply)
    proof.require_metadata_bearer(MetadataOperation.LOAD_CODE_ASSIST, access)
    return VerifiedTokenReply(grant.native_body, proof, _LoadCodeAssist(proof, deadline, spend, destination))
