"""Validate the standalone Google authorization-code exchange and initial grant."""

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
from urllib.parse import urlencode

from .account_binding import _unique_fields, _valid_bearer
from .auth_offer import (
    CLIENT_ID, SCOPES, Callback, Offer, Refused,
    _CODE, _STATE, _query_fields, redirect_uri, validate_offer,
)
from .token_diagnostic import TokenStage


_CODE_FIELDS = {"code", "code_verifier", "grant_type", "redirect_uri"}
_REFRESH_FIELDS = {"client_id", "client_secret", "grant_type", "refresh_token", "scope"}
_CREDENTIAL_FIELDS = {"client_id", "client_secret", "refresh_token", "token_uri", "scopes", "project_id"}
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
_ACCESS_FIELDS = {"access_token", "expires_in", "scope", "token_type"}
_GRANT_FIELDS = _ACCESS_FIELDS | {"refresh_token"}
_OPTIONAL_GRANT_FIELDS = {"refresh_token_expires_in"}
_IDENTITY_FIELD = "id_token"
_OIDC_SCOPES = SCOPES | {"email", "openid"}
_MAX_FORM = 8192
_MAX_BASIC = 2048
_MAX_GRANT = 32768
_MAX_TOKEN = 8192
_MAX_CREDENTIAL = 65536
_MAX_EXPIRY = (1 << 31) - 1
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_REFRESH_TOKEN = re.compile(r"[!-~]{1," + str(_MAX_TOKEN) + r"}")
_COMPACT_JWS = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", re.ASCII)


class OAuthExchangeError(ValueError):
    """A redacted rejection of OAuth application data."""

class _GrantRefused(OAuthExchangeError):
    def __init__(self, message, stage):
        super().__init__(message)
        self.token_stage = stage



def _valid_client(authorization):
    if type(authorization) is not bytes or len(authorization) > _MAX_BASIC or not authorization.startswith(b"Basic "):
        return False
    encoded = authorization.removeprefix(b"Basic ")
    try:
        credentials = base64.b64decode(encoded, validate=True)
    except ValueError:
        return False
    if base64.b64encode(credentials) != encoded:
        return False
    client, delimiter, secret = credentials.partition(b":")
    return (bool(delimiter and secret) and hmac.compare_digest(client, CLIENT_ID.encode("ascii"))
            and all(33 <= char <= 126 for char in secret))


def _matched_redirect(offer, callback):
    if (type(offer) is not Offer or type(callback) is not Callback
            or type(offer.state) is not str or not _STATE.fullmatch(offer.state)
            or type(offer.challenge) is not str
            or type(callback.state) is not str or not _STATE.fullmatch(callback.state)
            or not hmac.compare_digest(callback.state, offer.state)
            or type(callback.code) is not str or not _CODE.fullmatch(callback.code)):
        return None
    try:
        if validate_offer(offer.url, offer.port) == offer:
            return redirect_uri(offer.port)
    except Refused:
        pass
    return None


def _form(body, limit):
    if (type(body) is bytes and 0 < len(body) <= _MAX_FORM
            and all(33 <= byte <= 126 for byte in body)):
        try:
            return _query_fields(body.decode("ascii"), limit)
        except Refused:
            pass
    raise OAuthExchangeError("Invalid Google OAuth form")


def validate_authorization_code_exchange(
    offer: Offer, callback: Callback, *, authorization: bytes, body: bytes
) -> None:
    """Check one native request against the verified offer and matched callback."""
    redirect = _matched_redirect(offer, callback)
    if redirect is None:
        raise OAuthExchangeError("Invalid Google authorization-code binding")
    if not _valid_client(authorization):
        raise OAuthExchangeError("Invalid Google OAuth client framing")
    fields = _form(body, len(_CODE_FIELDS))
    if (fields.keys() != _CODE_FIELDS or fields["grant_type"] != "authorization_code"
            or fields["redirect_uri"] != redirect or not fields["code"].isascii()
            or not hmac.compare_digest(fields["code"], callback.code)
            or not _VERIFIER.fullmatch(fields["code_verifier"])):
        raise OAuthExchangeError("Invalid Google authorization-code form")
    verifier = fields["code_verifier"].encode("ascii")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).rstrip(b"=")
    if not hmac.compare_digest(challenge, offer.challenge.encode("ascii")):
        raise OAuthExchangeError("Google authorization-code verifier does not match the offer")


def _reject_constant(_name):
    raise ValueError


def _credential_fields(body):
    record = None
    if type(body) is bytes and 0 < len(body) <= _MAX_CREDENTIAL:
        try:
            record = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_fields,
                                parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            pass
    if (type(record) is not dict or record.keys() != _CREDENTIAL_FIELDS
            or record["client_id"] != CLIENT_ID or record["token_uri"] != _TOKEN_ENDPOINT):
        raise OAuthExchangeError("Invalid Google cold profile credential")
    scopes = record["scopes"]
    if (type(scopes) is not list or len(scopes) != len(SCOPES)
            or any(type(scope) is not str for scope in scopes) or set(scopes) != SCOPES):
        raise OAuthExchangeError("Invalid Google cold profile credential scopes")
    secret, refresh, project = record["client_secret"], record["refresh_token"], record["project_id"]
    if (type(secret) is not str or not _REFRESH_TOKEN.fullmatch(secret) or len(secret) > _MAX_BASIC
            or type(refresh) is not str or not _REFRESH_TOKEN.fullmatch(refresh)
            or type(project) is not str or len(project) > 128 or (project and not project.isprintable())):
        raise OAuthExchangeError("Invalid Google cold profile credential fields")
    return secret, refresh


def validate_refresh_form(body: bytes, *, pinned_credential: bytes) -> bytes:
    """Return a fixed token-endpoint form matching the controller's pinned file.

    The caller supplies bytes read from the exact held credential inode and
    provides the separate current-owner, ordered durable outbound allowance.
    """
    secret, refresh = _credential_fields(pinned_credential)
    fields = _form(body, len(_REFRESH_FIELDS))
    if (fields.keys() != _REFRESH_FIELDS or fields["grant_type"] != "refresh_token"
            or fields["client_id"] != CLIENT_ID
            or not fields["client_secret"].isascii() or not fields["refresh_token"].isascii()
            or not hmac.compare_digest(fields["client_secret"], secret)
            or not hmac.compare_digest(fields["refresh_token"], refresh)):
        raise OAuthExchangeError("Google refresh form does not match the pinned credential")
    scopes = fields["scope"].split(" ")
    if len(scopes) != len(SCOPES) or set(scopes) != SCOPES:
        raise OAuthExchangeError("Google refresh form scopes do not match")
    result = urlencode({
        "client_id": CLIENT_ID, "client_secret": secret, "grant_type": "refresh_token",
        "refresh_token": refresh, "scope": " ".join(sorted(SCOPES)),
    }).encode("ascii")
    if len(result) > _MAX_FORM:
        raise OAuthExchangeError("Google refresh form exceeded the size limit")
    return result


def _grant_fields(body, required, optional):
    fields = None
    if type(body) is bytes and 0 < len(body) <= _MAX_GRANT:
        try:
            fields = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            pass
    if type(fields) is not dict or not required <= fields.keys() <= required | optional:
        raise _GrantRefused("Invalid Google OAuth grant", TokenStage.GRANT_SHAPE)
    return fields


def _positive_expiry(value):
    return type(value) is int and 0 < value <= _MAX_EXPIRY


@dataclass(frozen=True, slots=True)
class AccessGrant:
    """An in-memory bearer and its projected native JSON reply."""

    access_token: bytes = field(repr=False)
    native_body: bytes = field(repr=False)

    def __reduce_ex__(self, _protocol):
        raise TypeError("Google OAuth grant must remain in memory")


@dataclass(frozen=True, slots=True)
class EnrollmentGrant(AccessGrant):
    refresh_token: bytes = field(repr=False)
    expires_in: int
    refresh_token_expires_in: int | None


def _access_from_grant(fields):
    scope = fields["scope"]
    scopes = scope.split(" ") if type(scope) is str else ()
    distinct = set(scopes)
    if len(scopes) != len(distinct) or distinct not in (SCOPES, _OIDC_SCOPES):
        raise _GrantRefused("Google OAuth grant scopes do not match", TokenStage.GRANT_SCOPE)
    if _IDENTITY_FIELD in fields:
        token = fields[_IDENTITY_FIELD]
        # An opaque compatibility field. The separate UserInfo response proves the subject.
        if (distinct != _OIDC_SCOPES or type(token) is not str or len(token) > _MAX_TOKEN
                or _COMPACT_JWS.fullmatch(token) is None):
            raise _GrantRefused("Invalid Google OAuth identity token field", TokenStage.GRANT_IDENTITY)
    access = fields["access_token"]
    if (fields["token_type"] != "Bearer" or type(access) is not str or not access.isascii()
            or not _valid_bearer(access.encode("ascii")) or not _positive_expiry(fields["expires_in"])):
        raise _GrantRefused("Invalid Google OAuth bearer grant", TokenStage.GRANT_BEARER)
    return access.encode("ascii")


def _reject_identity_alias(fields, *tokens):
    if _IDENTITY_FIELD in fields:
        identity = fields[_IDENTITY_FIELD].encode("ascii")
        if any(hmac.compare_digest(identity, token) for token in tokens):
            raise _GrantRefused("Google OAuth token roles overlap", TokenStage.GRANT_IDENTITY)


def _native_body(fields, allowed):
    projected = {name: fields[name] for name in allowed if name in fields}
    return json.dumps(projected, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def validate_enrollment_grant(body: bytes) -> EnrollmentGrant:
    """Validate and project the initial token reply after the caller checks HTTP."""
    fields = _grant_fields(body, _GRANT_FIELDS, _OPTIONAL_GRANT_FIELDS | {_IDENTITY_FIELD})
    access = _access_from_grant(fields)
    refresh = fields["refresh_token"]
    expires = fields["expires_in"]
    refresh_expires = fields.get("refresh_token_expires_in")
    if (type(refresh) is not str or not _REFRESH_TOKEN.fullmatch(refresh)
            or ("refresh_token_expires_in" in fields and not _positive_expiry(refresh_expires))):
        raise _GrantRefused("Invalid Google enrollment bearer grant", TokenStage.GRANT_REFRESH)
    refresh_bytes = refresh.encode("ascii")
    _reject_identity_alias(fields, access, refresh_bytes)
    native = _native_body(fields, _GRANT_FIELDS | _OPTIONAL_GRANT_FIELDS)
    return EnrollmentGrant(access, native, refresh_bytes, expires, refresh_expires)


def validate_cold_grant(body: bytes) -> AccessGrant:
    """Validate and project the cold token reply without credential rotation."""
    fields = _grant_fields(body, _ACCESS_FIELDS, {_IDENTITY_FIELD})
    access = _access_from_grant(fields)
    _reject_identity_alias(fields, access)
    return AccessGrant(access, _native_body(fields, _ACCESS_FIELDS))
