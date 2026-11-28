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
    validate_cold_grant,
    validate_enrollment_grant,
    validate_refresh_form,
)
from oc_google.token_diagnostic import TokenStage


PORT = 48081
STATE = "a" * 30
CODE = "4/fixture-callback-code"
VERIFIER = "fixture-verifier." + "a" * 50
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode("ascii")).digest()).decode().rstrip("=")
SECRET = b"fixture-only-secret"
SCOPE = " ".join(sorted(SCOPES))
OIDC_SCOPE = "openid " + " ".join(reversed(SCOPE.split())) + " email"
EMAIL_URI = "https://www.googleapis.com/auth/userinfo.email"
SHORT_EMAIL_SCOPE = SCOPE.replace(EMAIL_URI, "email")
SCOPE_VARIANTS = (
    SCOPE,
    SCOPE + " openid",
    SHORT_EMAIL_SCOPE,
    SHORT_EMAIL_SCOPE + " openid",
    SCOPE + " email",
    OIDC_SCOPE,
)
ID_SENTINEL = "fixture-header.opaque_body.synthetic-signature"
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


def cold_grant(**changes):
    fields = json.loads(grant())
    del fields["refresh_token"]
    return json.dumps(fields | changes).encode("utf-8")


def native_json(fields):
    return json.dumps(fields, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


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

    def test_keeps_exact_reported_scope_and_projects_only_validated_initial_fields(self):
        cases = (
            grant(scope=OIDC_SCOPE),
            grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL, refresh_token_expires_in=7200),
            grant(scope=OIDC_SCOPE, id_token="a" * 8188 + ".b.c"),
            grant(),
        )
        for raw in cases:
            with self.subTest(labels=len(json.loads(raw)["scope"].split())):
                parsed = validate_enrollment_grant(raw)
                expected = json.loads(raw)
                expected.pop("id_token", None)
                self.assertEqual(parsed.native_body, native_json(expected))
                self.assertNotIn(b'"id_token"', parsed.native_body)
                self.assertNotIn(ID_SENTINEL, repr(parsed))
                self.assertEqual(parsed.access_token, ACCESS.encode("ascii"))

    def test_refuses_incomplete_extended_duplicate_or_noncanonical_scope_lists(self):
        options = ("", None, SCOPE.split(" ", 1)[0], SCOPE + " " + SCOPE.split(" ")[0],
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
        with self.assertRaisesRegex(TypeError, "must remain in memory$"):
            pickle.dumps(parsed)
        with self.assertRaises(OAuthExchangeError) as denied:
            validate_enrollment_grant(grant()[:-1])
        self.assertIsNone(denied.exception.__context__)
        self.assertNotIn(ACCESS, str(denied.exception))


class ColdGrantTest(unittest.TestCase):
    def test_cold_projection_preserves_reported_scope_and_strips_the_optional_identity_token(self):
        for raw in (cold_grant(), cold_grant(scope=OIDC_SCOPE), cold_grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL)):
            parsed = validate_cold_grant(raw)
            expected = json.loads(raw)
            expected.pop("id_token", None)
            self.assertEqual(parsed.native_body, native_json(expected))
            self.assertEqual(parsed.access_token, ACCESS.encode("ascii"))
            self.assertNotIn(ACCESS, repr(parsed))
            self.assertNotIn(ID_SENTINEL, repr(parsed))
            with self.assertRaises(TypeError):
                pickle.dumps(parsed)

    def test_distinct_compact_tokens_remain_eligible(self):
        access = ID_SENTINEL[:-1] + "x"
        refresh = ID_SENTINEL[:-1] + "y"
        initial = validate_enrollment_grant(grant(
            scope=OIDC_SCOPE, id_token=ID_SENTINEL, access_token=access, refresh_token=refresh,
        ))
        cold = validate_cold_grant(cold_grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL, access_token=access))
        self.assertEqual(initial.access_token, access.encode("ascii"))
        self.assertEqual(initial.refresh_token, refresh.encode("ascii"))
        self.assertEqual(cold.access_token, access.encode("ascii"))
        self.assertEqual(json.loads(initial.native_body)["scope"], OIDC_SCOPE)
        self.assertEqual(json.loads(cold.native_body)["scope"], OIDC_SCOPE)

    def test_both_grant_modes_refuse_unexpected_identity_or_scope_shapes(self):
        invalid_identity = ("a.b", "a.b.c.d", "a..c", "a.b.c=", "a.b.é", "a.b.c\n",
                            "a" * 8189 + ".b.c", None, False, [ID_SENTINEL])
        invalid_scope = (OIDC_SCOPE + " openid", OIDC_SCOPE.replace("email", "profile"),
                         OIDC_SCOPE.replace("openid ", ""), OIDC_SCOPE.replace(" ", "  ", 1))
        for factory, validate in (
            (grant, validate_enrollment_grant), (cold_grant, validate_cold_grant),
        ):
            invalid = [factory(id_token=ID_SENTINEL)]
            invalid.extend(factory(scope=OIDC_SCOPE, id_token=value) for value in invalid_identity)
            invalid.extend(factory(scope=value, id_token=ID_SENTINEL) for value in invalid_scope)
            raw = factory(scope=OIDC_SCOPE, id_token=ID_SENTINEL)
            invalid.append(raw[:-1] + rb', "id_token": "a.b.c"}')
            for index, body in enumerate(invalid):
                with self.subTest(mode=validate.__name__, case=index), self.assertRaises(OAuthExchangeError) as denied:
                    validate(body)
                self.assertNotIn(ID_SENTINEL, str(denied.exception))

    def test_cold_grant_refuses_rotation_and_unknown_fields_even_with_valid_oidc(self):
        for field in ({"refresh_token": REFRESH}, {"refresh_token_expires_in": 7200}, {"extra": ID_SENTINEL}):
            with self.assertRaises(OAuthExchangeError):
                validate_cold_grant(cold_grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL, **field))


class GrantScopeVariantsTest(unittest.TestCase):
    grant_paths = ((grant, validate_enrollment_grant), (cold_grant, validate_cold_grant))

    def test_six_scope_sets_preserve_exact_reported_native_reply(self):
        for factory, validate in self.grant_paths:
            for variant, scope in enumerate(SCOPE_VARIANTS):
                with self.subTest(mode=validate.__name__, variant=variant):
                    data = factory(scope=scope)
                    parsed = validate(data)
                    self.assertEqual(parsed.access_token, ACCESS.encode("ascii"))
                    self.assertEqual(parsed.native_body, native_json(json.loads(data)))
                    if factory is grant:
                        self.assertEqual(parsed.refresh_token, REFRESH.encode("ascii"))
                        self.assertEqual(parsed.expires_in, 3600)

    def test_identity_token_needs_exact_openid_and_never_shares_token_roles(self):
        for factory, validate in self.grant_paths:
            for variant, scope in enumerate(SCOPE_VARIANTS):
                with self.subTest(mode=validate.__name__, variant=variant):
                    data = factory(scope=scope, id_token=ID_SENTINEL)
                    if "openid" not in scope.split(" "):
                        with self.assertRaises(OAuthExchangeError) as denied:
                            validate(data)
                        self.assertIs(denied.exception.token_stage, TokenStage.GRANT_IDENTITY)
                        continue
                    parsed = validate(data)
                    expected = json.loads(data)
                    del expected["id_token"]
                    self.assertEqual(parsed.native_body, native_json(expected))
                    self.assertNotIn(ID_SENTINEL.encode("ascii"), parsed.native_body)
                    alias_roles = ("access_token", "refresh_token") if factory is grant else ("access_token",)
                    for role in alias_roles:
                        with self.assertRaises(OAuthExchangeError) as denied:
                            validate(factory(scope=scope, id_token=ID_SENTINEL, **{role: ID_SENTINEL}))
                        self.assertIs(denied.exception.token_stage, TokenStage.GRANT_IDENTITY)
                        self.assertNotIn(ID_SENTINEL, str(denied.exception))

    def test_scope_refusals_use_only_fixed_categories(self):
        first_label = SCOPE.split(" ")[0]
        resources = " ".join(label for label in SCOPE.split(" ") if label != EMAIL_URI)
        unknown = "synthetic-unapproved-permission"
        invalid = {
            TokenStage.GRANT_SCOPE_LIST: (
                None, [], "", " " + SCOPE, SCOPE + " ", SCOPE.replace(" ", "  ", 1),
                SCOPE.replace(" ", "\t", 1), SCOPE + "\n", SCOPE + "\x7f",
                SCOPE + "\u00a0" + unknown, SCOPE + " " + first_label, OIDC_SCOPE + " openid",
            ),
            TokenStage.GRANT_SCOPE_UNKNOWN: (
                SCOPE + " " + unknown, SCOPE + " profile", SCOPE + " OpenID",
                SCOPE.replace(EMAIL_URI, "Email"), SCOPE.replace("https://", "HTTPS://", 1),
                SCOPE.replace(EMAIL_URI, EMAIL_URI + "/"), SCOPE.replace(EMAIL_URI, "userinfo.email"),
            ),
            TokenStage.GRANT_SCOPE_RESOURCE: tuple(
                " ".join(label for label in SCOPE.split(" ") if label != omitted)
                for omitted in resources.split(" ")
            ),
            TokenStage.GRANT_SCOPE_EMAIL: (resources, resources + " openid"),
        }
        for factory, validate in self.grant_paths:
            for stage, cases in invalid.items():
                for index, scope in enumerate(cases):
                    with self.subTest(mode=validate.__name__, stage=stage, case=index):
                        with self.assertRaises(OAuthExchangeError) as denied:
                            validate(factory(scope=scope))
                        self.assertIs(denied.exception.token_stage, stage)
                        for marker in (unknown, EMAIL_URI, first_label, ACCESS, REFRESH):
                            self.assertNotIn(marker, str(denied.exception))


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
