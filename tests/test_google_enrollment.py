"""Exercise token and subject verification against a socket-free fake destination."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import pickle
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
import time
import unittest
from unittest.mock import Mock, patch

from oc_google import enrollment, registration
from oc_google.account_binding import AccountBindingError, MetadataOperation
from oc_google.auth_offer import Callback
from oc_google.enrollment import EnrollmentMetadataError, LoadObservation, verify_cold_refresh, verify_initial_exchange
from oc_google.metadata_destination import MetadataRoute
from oc_google.oauth_exchange import OAuthExchangeError
from google_registration_fixture import record_enrollment_retired
from test_google_oauth_exchange import ACCESS, AUTHORIZATION, CODE, STATE, cold_credential, form, grant, offer, refresh_form


SUBJECT = b'{"id":"2527739134"}'
BEARER = b"Bearer " + ACCESS.encode("ascii")
LOAD_REQUEST = b'{"metadata": {"ideType": "ANTIGRAVITY"}}'
LOAD_REPLY = (b'{"currentTier":{"id":"free-tier","name":"Synthetic fixture tier"},'
              b'"cloudaicompanionProject":"oc-synthetic-stage-a"}')


class ColdRefreshTest(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(registration._HeldProfile, "_native_current"))
        scratch = self.enterContext(TemporaryDirectory())
        self.enterContext(patch.object(registration, "_account_home", return_value=Path(scratch)))
        journal = registration.RegistrationJournal("fixture")
        enrolled = journal.begin("e" * 64)
        with journal.enrollment_profile(enrolled) as initial:
            initial.bind_subject(b"old-fixture-bearer", SUBJECT)
            native = initial.path / "antigravity-acp"
            native.mkdir(mode=0o700)
            credential = native / "acp_token.json"
            credential.touch(mode=0o600)
            credential.write_bytes(cold_credential())
        record_enrollment_retired(journal, enrolled)
        check = journal.begin_cold_check(enrolled)
        self.profile = self.enterContext(journal.cold_profile(check))
        self.sent = []
        self.subject = SUBJECT
        self.grant = json.loads(grant())
        del self.grant["refresh_token"]

    def spend(self, route, send):
        self.profile.spend_metadata(route, send, authorized=lambda: True)

    def destination(self, route, *, authorization, deadline, deliver, body=b""):
        self.assertGreater(deadline, time.monotonic())
        deliver(lambda: self.sent.append(route))
        if route is MetadataRoute.TOKEN:
            self.assertIsNone(authorization)
            self.assertEqual(body, refresh_form())
            return json.dumps(self.grant).encode()
        self.assertIs(route, MetadataRoute.USERINFO)
        self.assertEqual(authorization, BEARER)
        self.assertEqual(body, b"")
        return self.subject

    def refresh(self, body=None):
        return verify_cold_refresh(
            form=refresh_form() if body is None else body, prepare_form=self.profile.refresh_form,
            bind_subject=self.profile.bind_subject, deadline=time.monotonic() + 3,
            spend=self.spend, destination=self.destination,
        )

    def test_cold_refresh_verifies_same_subject_on_new_bearer(self):
        result = self.refresh()
        self.assertEqual(self.sent, [MetadataRoute.TOKEN, MetadataRoute.USERINFO])
        result.proof.require_metadata_bearer(MetadataOperation.FETCH_AVAILABLE_MODELS, ACCESS.encode())
        with self.assertRaises(AccountBindingError):
            result.proof.require_metadata_bearer(MetadataOperation.FETCH_AVAILABLE_MODELS, b"old-fixture-bearer")

    def test_different_subject_withholds_the_cold_bearer_reply(self):
        self.subject = b'{"id":"2527739135"}'
        with self.assertRaises(AccountBindingError):
            self.refresh()
        self.assertEqual(self.sent, [MetadataRoute.TOKEN, MetadataRoute.USERINFO])

    def test_wrong_refresh_secret_does_not_reach_destination(self):
        with self.assertRaises(OAuthExchangeError):
            self.refresh(refresh_form(client_secret="different-client-secret"))
        self.assertEqual(self.sent, [])

    def test_cold_grant_without_scope_stops_before_subject_lookup(self):
        del self.grant["scope"]
        with self.assertRaises(OAuthExchangeError):
            self.refresh()
        self.assertEqual(self.sent, [MetadataRoute.TOKEN])


class InitialExchangeTest(unittest.TestCase):
    def setUp(self):
        scratch = self.enterContext(TemporaryDirectory())
        self.enterContext(patch.object(registration, "_account_home", return_value=Path(scratch)))
        journal = registration.RegistrationJournal("fixture")
        enrollment = journal.begin("f" * 64)
        self.profile = self.enterContext(journal.enrollment_profile(enrollment))
        self.gate = Mock()
        self.gate.take_forwarded.side_effect = [Callback(STATE, CODE), None]
        self.steps = []
        self.token_reply = grant()
        self.subject_reply = SUBJECT
        self.load_reply = LOAD_REPLY
        self.load_entered = Event()
        self.load_release = None
        self.deadlines = []
        self.blocked = None

    def spend(self, route, send):
        self.steps.append(("permit", route))
        if route is self.blocked:
            raise RuntimeError("allowance is suspended")
        send()

    def destination(self, route, *, authorization, deadline, deliver, body=b""):
        self.assertGreater(deadline, time.monotonic())
        self.deadlines.append(deadline)
        deliver(lambda: self.steps.append(("write", route)))
        if route is MetadataRoute.TOKEN:
            self.assertEqual(authorization, AUTHORIZATION)
            self.assertEqual(body, form())
            return self.token_reply
        self.assertEqual(authorization, BEARER)
        if route is MetadataRoute.USERINFO:
            self.assertEqual(body, b"")
            return self.subject_reply
        self.assertIs(route, MetadataRoute.LOAD_CODE_ASSIST)
        self.assertEqual(body, LOAD_REQUEST)
        self.load_entered.set()
        if self.load_release is not None:
            self.assertTrue(self.load_release.wait(2))
        return self.load_reply

    def run_exchange(self, request=None):
        return verify_initial_exchange(
            offer=offer(), callback_gate=self.gate, authorization=AUTHORIZATION,
            form=form() if request is None else request, bind_subject=self.profile.bind_subject,
            deadline=time.monotonic() + 3, spend=self.spend, destination=self.destination,
        )

    def test_exact_reply_is_available_only_after_token_and_same_bearer_subject(self):
        reply = self.run_exchange()
        self.assertEqual(self.steps, [
            ("permit", MetadataRoute.TOKEN), ("write", MetadataRoute.TOKEN),
            ("permit", MetadataRoute.USERINFO), ("write", MetadataRoute.USERINFO),
        ])
        self.assertEqual(reply.body, self.token_reply)
        self.assertNotIn(ACCESS, repr(reply))
        with self.assertRaises(TypeError):
            pickle.dumps(reply)
        reply.proof.require_metadata_bearer(MetadataOperation.LOAD_CODE_ASSIST, ACCESS.encode("ascii"))
        with self.assertRaises(AccountBindingError):
            reply.proof.require_metadata_bearer(MetadataOperation.FETCH_AVAILABLE_MODELS, ACCESS.encode("ascii"))
        with self.assertRaises(OAuthExchangeError):
            self.run_exchange()
        self.assertEqual(len(self.steps), 4)

    def test_wrong_code_spends_no_destination_allowance(self):
        with self.assertRaises(OAuthExchangeError):
            self.run_exchange(form(code="different-callback"))
        self.assertEqual(self.steps, [])

    def test_incomplete_token_grant_stops_before_subject_lookup(self):
        self.token_reply = grant(scope="wrong-scope")
        with self.assertRaises(OAuthExchangeError):
            self.run_exchange()
        self.assertEqual(self.steps, [("permit", MetadataRoute.TOKEN), ("write", MetadataRoute.TOKEN)])

    def test_bad_subject_response_keeps_native_reply_unavailable(self):
        self.subject_reply = b"{}"
        with self.assertRaises(AccountBindingError):
            self.run_exchange()
        self.assertEqual(self.steps[-1], ("write", MetadataRoute.USERINFO))

    def test_revocation_before_subject_write_keeps_native_reply_unavailable(self):
        self.blocked = MetadataRoute.USERINFO
        with self.assertRaisesRegex(RuntimeError, "allowance is suspended"):
            self.run_exchange()
        self.assertEqual(self.steps, [
            ("permit", MetadataRoute.TOKEN), ("write", MetadataRoute.TOKEN),
            ("permit", MetadataRoute.USERINFO),
        ])

    def test_load_spends_once_on_verified_bearer_and_returns_private_typed_reply(self):
        verified = self.run_exchange()
        request = br' { "metadata" : { "ideType" : "\u0041NTIGRAVITY" } } '
        observed = verified.load_code_assist(authorization=BEARER, body=request)
        self.assertEqual(self.steps, [
            ("permit", MetadataRoute.TOKEN), ("write", MetadataRoute.TOKEN),
            ("permit", MetadataRoute.USERINFO), ("write", MetadataRoute.USERINFO),
            ("permit", MetadataRoute.LOAD_CODE_ASSIST), ("write", MetadataRoute.LOAD_CODE_ASSIST),
        ])
        self.assertEqual(len(set(self.deadlines)), 1)
        self.assertEqual(sha256(LOAD_REQUEST).hexdigest(),
                         "6edbeff306c1a622ffa1bfc2c2e5aeb87db552650f7a60c8cf250eb82dd834a7")
        self.assertEqual(observed.body, LOAD_REPLY)
        self.assertEqual(observed.observation, LoadObservation(tier_reported=True, project_reported=True))
        self.assertNotIn("free-tier", repr(observed))
        self.assertNotIn("oc-synthetic-stage-a", repr(observed))
        with self.assertRaises(TypeError):
            pickle.dumps(observed)
        with self.assertRaisesRegex(EnrollmentMetadataError, "already consumed"):
            verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST)
        self.assertEqual(len(self.steps), 6)

    def test_absent_metadata_stays_unknown(self):
        verified = self.run_exchange()
        self.load_reply = b"{}"
        observed = verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST)
        self.assertEqual(observed.body, b"{}")
        self.assertEqual(observed.observation, LoadObservation(tier_reported=False, project_reported=False))

    def test_wrong_load_bearer_consumes_local_attempt_without_destination_write(self):
        verified = self.run_exchange()
        with self.assertRaises(AccountBindingError):
            verified.load_code_assist(authorization=b"Bearer alternate-bearer", body=LOAD_REQUEST)
        with self.assertRaisesRegex(EnrollmentMetadataError, "already consumed"):
            verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST)
        self.assertEqual(len(self.steps), 4)

    def test_ambiguous_load_request_consumes_local_attempt_without_destination_write(self):
        verified = self.run_exchange()
        body = b'{"metadata":{"ideType":"ANTIGRAVITY","ideType":"ANTIGRAVITY"}}'
        with self.assertRaises(EnrollmentMetadataError):
            verified.load_code_assist(authorization=BEARER, body=body)
        with self.assertRaisesRegex(EnrollmentMetadataError, "already consumed"):
            verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST)
        self.assertEqual(len(self.steps), 4)

    def test_refused_load_spend_cannot_be_retried(self):
        verified = self.run_exchange()
        self.blocked = MetadataRoute.LOAD_CODE_ASSIST
        with self.assertRaisesRegex(RuntimeError, "allowance is suspended"):
            verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST)
        self.blocked = None
        with self.assertRaisesRegex(EnrollmentMetadataError, "already consumed"):
            verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST)
        self.assertEqual(self.steps[-1], ("permit", MetadataRoute.LOAD_CODE_ASSIST))
        self.assertEqual(len(self.steps), 5)

    def test_invalid_load_reply_consumes_attempt_without_private_reply_release(self):
        verified = self.run_exchange()
        self.load_reply = b'{"currentTier":{"id":"free-tier","email":"fixture@example.test"}}'
        with self.assertRaises(EnrollmentMetadataError):
            verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST)
        with self.assertRaisesRegex(EnrollmentMetadataError, "already consumed"):
            verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST)
        self.assertEqual(self.steps[-1], ("write", MetadataRoute.LOAD_CODE_ASSIST))
        self.assertEqual(len(self.steps), 6)

    def test_second_native_load_cannot_dispatch_while_first_is_pending(self):
        verified = self.run_exchange()
        self.load_release = Event()
        with ThreadPoolExecutor(max_workers=1) as workers:
            first = workers.submit(verified.load_code_assist, authorization=BEARER, body=LOAD_REQUEST)
            try:
                self.assertTrue(self.load_entered.wait(2))
                with self.assertRaisesRegex(EnrollmentMetadataError, "already consumed"):
                    verified.load_code_assist(authorization=BEARER, body=LOAD_REQUEST)
            finally:
                self.load_release.set()
            self.assertEqual(first.result(timeout=2).body, LOAD_REPLY)
        self.assertEqual(self.steps.count(("write", MetadataRoute.LOAD_CODE_ASSIST)), 1)


class LoadShapeTest(unittest.TestCase):
    def test_unknown_and_noncanonical_request_fields_are_refused(self):
        for body in (
            b"[]", b'{"metadata":null}', b'{"metadata":{"ideType":true}}',
            b'{"metadata":{"ideType":"antigravity"}}',
            b'{"metadata":{"ideType":"ANTIGRAVITY","extra":0}}',
            b'{"metadata":{"ideType":"ANTIGRAVITY"},"project":"other"}',
            b'{"metadata":{"ideType":NaN}}', LOAD_REQUEST + b" " * 256,
            LOAD_REQUEST + b"\xff",
        ):
            with self.subTest(body=body), self.assertRaises(EnrollmentMetadataError):
                enrollment._validate_load_request(body)

    def test_reply_rejects_unmeasured_or_unbounded_values(self):
        for body in (
            b'{"currentTier":{"id":"free-tier"}}',
            b'{"currentTier":{"id":"free-tier","id":"free-tier","name":"Fixture"}}',
            b'{"currentTier":{"id":"free-tier","name":"invalid\\u0000name"}}',
            b'{"currentTier":null}', b'{"cloudaicompanionProject":null}',
            b'{"cloudaicompanionProject":"fixture@example.test"}',
            b'{"cloudaicompanionProject":"oc-synthetic-stage-a","metadata":{}}',
            b"{}" + b" " * 4096,
        ):
            with self.subTest(body=body), self.assertRaises(EnrollmentMetadataError):
                enrollment._observe_load_reply(body)

    def test_each_observed_field_can_be_independently_unknown(self):
        self.assertEqual(enrollment._observe_load_reply(b'{"currentTier":{"id":"fixture","name":"Fixture"}}'),
                         LoadObservation(tier_reported=True, project_reported=False))
        self.assertEqual(enrollment._observe_load_reply(b'{"cloudaicompanionProject":"fixture-project"}'),
                         LoadObservation(tier_reported=False, project_reported=True))
