"""Synthetic authorization-code requests and initial Google token replies."""

import base64
from dataclasses import replace
import hashlib
import json
import pickle
import unittest
from urllib.parse import urlencode

from oc_google.auth_offer import AUTH_URL, CLIENT_ID, SCOPES, Callback, redirect_uri, validate_offer
from oc_google.oauth_exchange import (
    OAuthExchangeError,
    validate_authorization_code_exchange,
    validate_enrollment_grant,
    validate_refresh_form,
)


PORT = 48081
STATE = "a" * 30
CODE = "4/fixture-callback-code"
VERIFIER = "fixture-verifier." + "a" * 50
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode("ascii")).digest()).decode().rstrip("=")
SECRET = b"fixture-only-secret"
SCOPE = " ".join(sorted(SCOPES))
ACCESS = "fixture-access-token"
REFRESH = "fixture-refresh-token"


def basic(credentials):
    return b"Basic " + base64.b64encode(credentials)


AUTHORIZATION = basic(CLIENT_ID.encode("ascii") + b":" + SECRET)


def offer():
    return validate_offer(AUTH_URL + "?" + urlencode({
        "client_id": CLIENT_ID,
        "response_type": "code",
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
        "scope": SCOPE,
        "redirect_uri": redirect_uri(PORT),
        "state": STATE,
        "code_challenge": CHALLENGE,
    }), PORT)


def form(**changes):
    return urlencode({
        "code": CODE,
        "code_verifier": VERIFIER,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri(PORT),
    } | changes).encode("ascii")


def grant(**changes):
    return json.dumps({
        "access_token": ACCESS,
        "refresh_token": REFRESH,
        "expires_in": 3600,
        "scope": SCOPE,
        "token_type": "Bearer",
    } | changes).encode("utf-8")


def cold_credential(**changes):
    return json.dumps({
        "client_id": CLIENT_ID, "client_secret": SECRET.decode("ascii"),
        "refresh_token": REFRESH, "token_uri": "https://oauth2.googleapis.com/token",
        "scopes": sorted(SCOPES), "project_id": "fixture-project",
    } | changes).encode()


def refresh_form(**changes):
    return urlencode({
        "client_id": CLIENT_ID, "client_secret": SECRET.decode("ascii"),
        "grant_type": "refresh_token", "refresh_token": REFRESH, "scope": SCOPE,
    } | changes).encode("ascii")


class AuthorizationCodeExchangeTest(unittest.TestCase):
    def setUp(self):
        self.offer = offer()
        self.callback = Callback(STATE, CODE)

    def check(self, *, binding=None, callback=None, authorization=AUTHORIZATION, body=None):
        validate_authorization_code_exchange(
            self.offer if binding is None else binding,
            self.callback if callback is None else callback,
            authorization=authorization,
            body=form() if body is None else body,
        )

    def test_measured_four_fields_and_exact_pkce_match(self):
        self.check()

    def test_wrong_code_verifier_port_or_callback_state_is_denied(self):
        for body in (form(code="4/fixture-replacement-code"), form(code="４/fixture-callback-code"),
                     form(code_verifier="z" * 64), form(code_verifier="a" * 42),
                     form(code_verifier="a" * 129), form(redirect_uri=redirect_uri(PORT + 1)),
                     form(redirect_uri=redirect_uri(PORT).replace("127.0.0.1", "localhost")),
                     form(grant_type="refresh_token")):
            with self.subTest(body=body), self.assertRaises(OAuthExchangeError):
                self.check(body=body)
        for callback in (Callback("b" * 30, CODE), Callback(STATE, None), Callback(STATE, "a\r\n")):
            with self.subTest(callback=callback), self.assertRaises(OAuthExchangeError):
                self.check(callback=callback)
        with self.assertRaises(OAuthExchangeError):
            self.check(binding=replace(self.offer, port=9222))
        with self.assertRaises(OAuthExchangeError):
            self.check(binding=replace(self.offer, challenge=CHALLENGE + "="))
        alternate = "b" * 64
        changed = base64.urlsafe_b64encode(hashlib.sha256(alternate.encode()).digest()).decode().rstrip("=")
        with self.assertRaises(OAuthExchangeError):
            self.check(binding=replace(self.offer, challenge=changed), body=form(code_verifier=alternate))
        with self.assertRaises(OAuthExchangeError):
            self.check(binding=replace(self.offer, port=PORT + 1), body=form(redirect_uri=redirect_uri(PORT + 1)))

    def test_form_rejects_duplicates_unknown_fields_and_malformed_encoding(self):
        invalid = (form() + b"&code=other", form() + b"&%63ode=other", form(client_id=CLIENT_ID),
                   form(scope=SCOPE), form() + b"&", form() + b"%", b"code=only", b"", b"x" * 8193,
                   b"\xff" + form(), form(code=""))
        for body in invalid:
            with self.subTest(body=body), self.assertRaises(OAuthExchangeError):
                self.check(body=body)

    def test_basic_requires_canonical_framing_with_the_pinned_public_client_id(self):
        invalid = (b"", b"Bearer " + SECRET, AUTHORIZATION.replace(b"Basic", b"basic"),
                   AUTHORIZATION + b"=", AUTHORIZATION + b"\r\n", b"Basic !!",
                   basic(b"fixture-other-client:" + SECRET), basic(CLIENT_ID.encode()),
                   basic(CLIENT_ID.encode() + b":"), basic(CLIENT_ID.encode() + b":a\n"))
        for authorization in invalid:
            with self.subTest(authorization=authorization), self.assertRaises(OAuthExchangeError):
                self.check(authorization=authorization)


class EnrollmentGrantTest(unittest.TestCase):
    def test_exact_scope_set_and_typed_credentials(self):
        parsed = validate_enrollment_grant(grant(scope=" ".join(reversed(SCOPE.split(" ")))))
        self.assertEqual(parsed.access_token, ACCESS.encode())
        self.assertEqual(parsed.refresh_token, REFRESH.encode())
        self.assertEqual(parsed.expires_in, 3600)
        self.assertIsNone(parsed.refresh_token_expires_in)
        self.assertEqual(validate_enrollment_grant(grant(refresh_token_expires_in=7200)).refresh_token_expires_in,
                         7200)

    def test_refuses_incomplete_extended_duplicate_or_noncanonical_scope_lists(self):
        options = ("", None, SCOPE.split(" ", 1)[0], SCOPE + " openid", SCOPE + " " + SCOPE.split(" ")[0],
                   SCOPE.replace(" ", "  ", 1), SCOPE.replace(" ", "\t", 1), SCOPE.upper())
        for scope in options:
            with self.subTest(scope=scope), self.assertRaises(OAuthExchangeError):
                validate_enrollment_grant(grant(scope=scope))

    def test_refuses_malformed_or_unexpected_response_fields(self):
        without_refresh = json.loads(grant())
        del without_refresh["refresh_token"]
        without_scope = json.loads(grant())
        del without_scope["scope"]
        invalid = (
            json.dumps(without_refresh).encode(), json.dumps(without_scope).encode(),
            grant(token_type="DPoP"), grant(token_type="bearer"), grant(access_token="a b"),
            grant(access_token="é"), grant(access_token="g" * 8193),
            grant(refresh_token=""), grant(refresh_token="a\n"), grant(refresh_token="g" * 8193),
            grant(expires_in=True), grant(expires_in=1.0), grant(expires_in="3600"),
            grant(expires_in=0), grant(expires_in=-1), grant(expires_in=1 << 31),
            grant(expires_in=float("inf")), grant(refresh_token_expires_in=None),
            grant(refresh_token_expires_in=0), grant(refresh_token_expires_in=False),
            grant(id_token="unrequested-identity-assertion"), grant(unknown="fixture"),
            grant(error="invalid_grant"), grant()[:-1] + rb', "access\u005ftoken": "duplicate"}',
            b"\xef\xbb\xbf" + grant(), b" " * 32768 + grant(), b"{}", b"[]", b"\xff",
        )
        for body in invalid:
            with self.subTest(body=body[:100]), self.assertRaises(OAuthExchangeError):
                validate_enrollment_grant(body)

    def test_proof_and_errors_keep_credentials_redacted(self):
        parsed = validate_enrollment_grant(grant())
        for credential in (ACCESS, REFRESH):
            self.assertNotIn(credential, repr(parsed))
        with self.assertRaisesRegex(TypeError, "^Google enrollment grant must remain in memory$"):
            pickle.dumps(parsed)
        with self.assertRaises(OAuthExchangeError) as denied:
            validate_enrollment_grant(grant()[:-1])
        self.assertIsNone(denied.exception.__context__)
        self.assertNotIn(ACCESS, str(denied.exception))


class RefreshFormTest(unittest.TestCase):
    def test_reorders_the_same_scope_set_into_fixed_refresh_form(self):
        native = refresh_form(scope=" ".join(reversed(SCOPE.split())))
        self.assertEqual(validate_refresh_form(native, pinned_credential=cold_credential()), refresh_form())

    def test_refuses_changed_refresh_token_client_secret_or_scopes(self):
        for native in (
            refresh_form(refresh_token="other-token"), refresh_form(client_secret="other-secret"),
            refresh_form(client_id="other-client"), refresh_form(scope=SCOPE + " openid"),
            refresh_form(grant_type="authorization_code"), refresh_form() + b"&refresh_token=other",
        ):
            with self.assertRaises(OAuthExchangeError) as denied:
                validate_refresh_form(native, pinned_credential=cold_credential())
            self.assertNotIn(REFRESH, str(denied.exception))

    def test_credential_cannot_select_a_different_endpoint_or_schema(self):
        for record in (
            cold_credential(token_uri="https://other.invalid/token"), cold_credential(extra=True),
            cold_credential(scopes=[SCOPE]), cold_credential()[:-1] + b', "refresh_token": "other"}',
        ):
            with self.assertRaises(OAuthExchangeError):
                validate_refresh_form(refresh_form(), pinned_credential=record)


if __name__ == "__main__":
    unittest.main()
