"""Validate the standalone Google authorization-code exchange and initial grant."""

import base64
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


_CODE_FIELDS = {"code", "code_verifier", "grant_type", "redirect_uri"}
_REFRESH_FIELDS = {"client_id", "client_secret", "grant_type", "refresh_token", "scope"}
_CREDENTIAL_FIELDS = {"client_id", "client_secret", "refresh_token", "token_uri", "scopes", "project_id"}
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
_ACCESS_FIELDS = {"access_token", "expires_in", "scope", "token_type"}
_GRANT_FIELDS = _ACCESS_FIELDS | {"refresh_token"}
_OPTIONAL_GRANT_FIELDS = {"refresh_token_expires_in"}
_MAX_FORM = 8192
_MAX_BASIC = 2048
_MAX_GRANT = 32768
_MAX_TOKEN = 8192
_MAX_CREDENTIAL = 65536
_MAX_EXPIRY = (1 << 31) - 1
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_REFRESH_TOKEN = re.compile(r"[!-~]{1," + str(_MAX_TOKEN) + r"}")


class OAuthExchangeError(ValueError):
    """A redacted rejection of OAuth application data."""


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
        raise OAuthExchangeError("Invalid Google OAuth grant")
    return fields


def _positive_expiry(value):
    return type(value) is int and 0 < value <= _MAX_EXPIRY


class EnrollmentGrant:
    """An in-memory bearer grant with redacted representation."""

    __slots__ = ("access_token", "refresh_token", "expires_in", "refresh_token_expires_in")

    def __init__(self, access_token: bytes, refresh_token: bytes, expires_in: int,
                 refresh_token_expires_in: int | None):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_in = expires_in
        self.refresh_token_expires_in = refresh_token_expires_in

    def __reduce_ex__(self, _protocol):
        raise TypeError("Google enrollment grant must remain in memory")


def _access_from_grant(fields):
    scope = fields["scope"]
    scopes = scope.split(" ") if type(scope) is str else ()
    if len(scopes) != len(SCOPES) or set(scopes) != SCOPES:
        raise OAuthExchangeError("Google OAuth grant scopes do not match")
    access = fields["access_token"]
    if (fields["token_type"] != "Bearer" or type(access) is not str or not access.isascii()
            or not _valid_bearer(access.encode("ascii")) or not _positive_expiry(fields["expires_in"])):
        raise OAuthExchangeError("Invalid Google OAuth bearer grant")
    return access.encode("ascii")


def validate_enrollment_grant(body: bytes) -> EnrollmentGrant:
    """Validate a bounded token response body after the caller checks HTTP."""
    fields = _grant_fields(body, _GRANT_FIELDS, _OPTIONAL_GRANT_FIELDS)
    access = _access_from_grant(fields)
    refresh = fields["refresh_token"]
    expires = fields["expires_in"]
    refresh_expires = fields.get("refresh_token_expires_in")
    if (type(refresh) is not str or not _REFRESH_TOKEN.fullmatch(refresh)
            or ("refresh_token_expires_in" in fields and not _positive_expiry(refresh_expires))):
        raise OAuthExchangeError("Invalid Google enrollment bearer grant")
    return EnrollmentGrant(access, refresh.encode("ascii"), expires, refresh_expires)


def validate_cold_grant(body: bytes) -> bytes:
    """Validate the cold reply's scoped bearer. Credential rotation is unqualified."""
    return _access_from_grant(_grant_fields(body, _ACCESS_FIELDS, set()))
