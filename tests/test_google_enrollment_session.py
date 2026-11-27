"""Join private native framing, the durable journal and a fake Google destination."""

import json
import os
from pathlib import Path
from contextlib import ExitStack, contextmanager, nullcontext
import ssl
from tempfile import TemporaryDirectory
from threading import RLock
import time
import unittest
from unittest.mock import Mock, patch

from oc_google import connect, metadata_destination, registration
from oc_google.account_binding import AccountBindingError
from oc_google.auth_offer import Callback
from oc_google.enrollment import EnrollmentMetadataError
from oc_google.enrollment_session import EnrollmentSessionError, serve_cold_metadata, serve_initial_metadata
from oc_google.oauth_exchange import OAuthExchangeError
from oc_google.metadata_destination import MetadataRoute
from oc_google.metadata_ingress import MetadataIngressError
from oc_google.native_enrollment_acp import NativeEnrollmentAcp
from oc_google.native_service import (
    NativeInvocation, NativeRetirementUnconfirmed, NativeService, open_cold_service, open_enrollment_service,
)
from oc_google.native_namespace import NativeNamespaceError
from oc_google.native_transport import NativeChannel
from oc_google.token_diagnostic import TokenDiagnostic, TokenStage
from google_registration_fixture import record_enrollment_retired
from test_google_enrollment import BEARER, LOAD_REPLY, LOAD_REQUEST, SUBJECT
from test_google_metadata_ingress import FakePeer, packet
from test_google_metadata_destination import FakeChannel, IPV4, chunked_response, response
from test_google_oauth_exchange import (
    AUTHORIZATION, CODE, ID_SENTINEL, OIDC_SCOPE, STATE, cold_credential, cold_grant,
    form, grant, native_json, offer, refresh_form,
)


TOKEN = MetadataRoute.TOKEN
USERINFO = MetadataRoute.USERINFO
LOAD = MetadataRoute.LOAD_CODE_ASSIST
CATALOG = MetadataRoute.FETCH_AVAILABLE_MODELS
_NATIVE_CURRENT = registration._HeldProfile._native_current


class NativePeer(FakePeer):
    def __init__(self, wire):
        super().__init__(wire, TimeoutError())
        self.replies = []
        self.closed = False
        self.live = True

    def active(self):
        return self.live

    def sendall(self, reply):
        self.replies.append(reply)

    def close(self):
        self.closed = True

    @contextmanager
    def channel(self):
        try:
            yield NativeChannel(self, self.active)
        finally:
            self.close()


def assert_alias_denied(test, raw_grant):
    test.responses[TOKEN] = raw_grant
    destination = test.destination

    def observe(route, **request):
        if route is not TOKEN:
            test.fail("Token alias reached UserInfo or another metadata route")
        return destination(route, **request)

    with patch.object(test, "destination", side_effect=observe):
        with test.assertRaisesRegex(OAuthExchangeError, "^Google OAuth token roles overlap$"):
            test.session()
    test.assertEqual(test.sent, [TOKEN])
    test.assertTrue(test.peers[TOKEN].closed)
    test.assertEqual(test.peers[TOKEN].replies, [])


class EnrollmentSessionTest(unittest.TestCase):
    def setUp(self):
        self.native_gate = self.enterContext(patch.object(registration._HeldProfile, "_native_current"))
        scratch = self.enterContext(TemporaryDirectory())
        self.journal_file = Path(scratch) / ".local/state/oc-sandbox/google/registrations/fixture/registration.json"
        self.enterContext(patch.object(registration, "_account_home", return_value=Path(scratch)))
        journal = registration.RegistrationJournal("fixture")
        enrollment = journal.begin("e" * 64)
        self.profile = self.enterContext(journal.enrollment_profile(enrollment))
        self.callback_gate = Mock()
        self.callback_gate.take_forwarded.return_value = Callback(STATE, CODE)
        self.fence = RLock()
        self.active = True
        self.retire_on_response = None
        self.peer_retire_on_response = None
        self.accepted = []
        self.sent = []
        self.responses = {TOKEN: grant(), USERINFO: SUBJECT, LOAD: LOAD_REPLY}
        self.peers = {
            TOKEN: NativePeer(packet(TOKEN, body=form(), changes={b"Authorization": AUTHORIZATION})),
            LOAD: NativePeer(packet(LOAD, body=LOAD_REQUEST, changes={b"Authorization": BEARER})),
        }

    def accept(self, route, deadline):
        self.assertGreater(deadline, time.monotonic())
        self.accepted.append(route)
        return self.peers[route].channel()

    def destination(self, route, *, authorization, deadline, deliver, body=b""):
        self.assertEqual(authorization, AUTHORIZATION if route is TOKEN else BEARER)
        if route is LOAD:
            self.assertEqual(body, LOAD_REQUEST)
            self.assertTrue(self.peers[TOKEN].closed)
        deliver(lambda: self.sent.append(route))
        if route is self.retire_on_response:
            with self.fence:
                self.active = False
        if route is self.peer_retire_on_response:
            self.peers[TOKEN].live = False
        return self.responses[route]

    def session(self, *, diagnostic=None):
        return serve_initial_metadata(
            offer=offer(), callback_gate=self.callback_gate, profile=self.profile,
            deadline=time.monotonic() + 3, accept=self.accept, fence=self.fence,
            authorized=lambda: self.active, destination=self.destination, diagnostic=diagnostic,
        )

    def attended_exchange(self, *, token_reply=None, userinfo=None, route_override=None):
        token = FakeChannel(response(grant() if token_reply is None else token_reply))
        token_socket, userinfo_socket = FakeChannel(), FakeChannel()
        trust = Mock(wrap_socket=Mock(side_effect=[token, userinfo]))
        self.enterContext(patch.object(metadata_destination, "_resolve", return_value=(2, IPV4)))
        self.enterContext(patch.object(metadata_destination, "_system_tls_context", return_value=trust))
        self.enterContext(patch.object(metadata_destination.socket, "socket",
                                       side_effect=[token_socket, userinfo_socket]))

        def deliver(route, **request):
            actual = route_override if route is USERINFO and route_override is not None else route
            if actual is LOAD:
                request["body"] = b"{}"
            return metadata_destination.exchange(actual, **request)

        self.destination = deliver
        return token, userinfo_socket

    def assert_token_only_refusal(self, *, spent, pending):
        saved = json.loads(self.journal_file.read_text())
        self.assertEqual(saved["enrollment_metadata_spent"], spent)
        self.assertIs(saved["metadata_pending"], pending)
        self.assertIsNone(saved["subject_digest"])
        self.assertEqual(self.accepted, [TOKEN])
        self.assertEqual(self.peers[TOKEN].replies, [])

    def test_attended_initial_token_rejection_has_exact_grant_stage(self):
        diagnostic = TokenDiagnostic()
        token, _ = self.attended_exchange(token_reply=grant(scope="synthetic-invalid-scope"))
        with self.assertRaises(OAuthExchangeError) as refusal:
            self.session(diagnostic=diagnostic)
        self.assertIs(diagnostic.stage(refusal.exception), TokenStage.GRANT_SCOPE_UNKNOWN)
        self.assertEqual(len(token.sent), 1)
        self.assert_token_only_refusal(spent=1, pending=False)
        self.assertNotIn("synthetic-invalid-scope", self.journal_file.read_text())

    def test_valid_token_then_userinfo_setup_failure_has_distinct_stage(self):
        diagnostic = TokenDiagnostic()
        token, userinfo_socket = self.attended_exchange()
        userinfo_socket.connect.side_effect = OSError("synthetic-userinfo-network")
        with self.assertRaises(metadata_destination.MetadataDestinationError) as refusal:
            self.session(diagnostic=diagnostic)
        self.assertIs(diagnostic.stage(refusal.exception), TokenStage.USERINFO_PRE_WRITE)
        self.assertEqual(len(token.sent), 1)
        self.assertFalse(userinfo_socket.sent)
        self.assert_token_only_refusal(spent=1, pending=False)

    def test_complete_chunked_token_and_ignored_vary_reach_validation_without_persistence(self):
        diagnostic = TokenDiagnostic()
        token, userinfo_socket = self.attended_exchange()
        raw_grant = grant()
        marker = b"synthetic-ignored-vary-value"
        encoded = f"{len(raw_grant):x}\r\n".encode("ascii") + raw_grant + b"\r\n0\r\n\r\n"
        token.chunks.clear()
        token.chunks.extend((
            chunked_response(encoded, headers=(b"Vary: " + marker, b"vary: Origin")),
            ssl.SSLEOFError("synthetic TLS shutdown"),
        ))
        userinfo_socket.connect.side_effect = OSError("synthetic UserInfo setup refusal")
        with self.assertRaises(metadata_destination.MetadataDestinationError) as refusal:
            self.session(diagnostic=diagnostic)
        self.assertIs(diagnostic.stage(refusal.exception), TokenStage.USERINFO_PRE_WRITE)
        self.assert_token_only_refusal(spent=1, pending=False)
        saved = self.journal_file.read_bytes()
        self.assertNotIn(marker, saved)
        self.assertNotIn(raw_grant, saved)
        self.assertNotIn(marker.decode("ascii"), str(refusal.exception))

    def test_userinfo_reservation_refusal_before_send_remains_generic(self):
        diagnostic = TokenDiagnostic()
        userinfo = FakeChannel()
        token, _ = self.attended_exchange(userinfo=userinfo)
        original = registration._HeldProfile._save

        def save(held, record, **kwargs):
            original(held, record, **kwargs)
            if record.enrollment_metadata_spent == 2 and record.metadata_pending:
                raise metadata_destination._MetadataSetupError("synthetic reservation refusal")

        with patch.object(registration._HeldProfile, "_save", autospec=True, side_effect=save):
            with self.assertRaises(metadata_destination.MetadataDestinationError) as refusal:
                self.session(diagnostic=diagnostic)
        self.assertIsNone(diagnostic.stage(refusal.exception))
        self.assertEqual(len(token.sent), 1)
        self.assertEqual(userinfo.sent, [])
        self.assert_token_only_refusal(spent=2, pending=True)

    def test_partial_userinfo_write_remains_generic(self):
        diagnostic = TokenDiagnostic()
        userinfo = FakeChannel()
        userinfo.send_limit = 1
        token, _ = self.attended_exchange(userinfo=userinfo)
        with self.assertRaises(registration.RegistrationUnavailable) as refusal:
            self.session(diagnostic=diagnostic)
        self.assertIsNone(diagnostic.stage(refusal.exception))
        self.assertEqual(len(token.sent), 1)
        self.assertEqual(len(userinfo.sent), 1)
        self.assert_token_only_refusal(spent=2, pending=True)

    def test_userinfo_diagnostic_refuses_other_route(self):
        diagnostic = TokenDiagnostic()
        token, other_socket = self.attended_exchange(route_override=LOAD)
        other_socket.connect.side_effect = OSError("synthetic-foreign-route")
        with self.assertRaises(metadata_destination.MetadataDestinationError) as refusal:
            self.session(diagnostic=diagnostic)
        self.assertIsNone(diagnostic.stage(refusal.exception))
        self.assertEqual(len(token.sent), 1)
        self.assert_token_only_refusal(spent=1, pending=False)

    def test_fake_typed_refusal_cannot_reuse_foreign_observation(self):
        diagnostic = TokenDiagnostic()
        foreign = TokenDiagnostic()
        error = metadata_destination._ResponseRefused("synthetic foreign refusal", TokenStage.HTTP_400)
        foreign.mark(error)
        fake = self.destination

        def fail_after_fake_write(route, **request):
            fake(route, **request)
            raise error

        self.destination = fail_after_fake_write
        with self.assertRaises(metadata_destination.MetadataDestinationError) as refusal:
            self.session(diagnostic=diagnostic)
        self.assertIs(refusal.exception, error)
        self.assertIsNone(diagnostic.stage(error))
        self.assert_token_only_refusal(spent=1, pending=False)

    def test_exact_operations_use_separate_native_connections(self):
        observation = self.session()
        self.assertTrue(observation.load.tier_reported and observation.load.project_reported)
        self.assertEqual(self.accepted, [TOKEN, LOAD])
        self.assertEqual(self.sent, [TOKEN, USERINFO, LOAD])
        for route in self.accepted:
            peer = self.peers[route]
            self.assertTrue(peer.closed)
            reply, = peer.replies
            headers, body = reply.split(b"\r\n\r\n", 1)
            self.assertIn(b"Connection: close", headers)
            expected = self.responses[route]
            if route is TOKEN:
                expected = native_json(json.loads(expected))
            self.assertEqual(body, expected)
        self.callback_gate.take_forwarded.assert_called_once_with()

    def test_initial_oidc_reply_reaches_native_with_scope_and_without_identity_token(self):
        self.responses[TOKEN] = grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL, refresh_token_expires_in=7200)
        self.session()
        self.assertEqual(self.sent, [TOKEN, USERINFO, LOAD])
        response, = self.peers[TOKEN].replies
        self.assertEqual(response.split(b"\r\n\r\n", 1)[1], native_json(json.loads(
            grant(scope=OIDC_SCOPE, refresh_token_expires_in=7200),
        )))
        self.assertNotIn(ID_SENTINEL.encode("ascii"), response)

    def test_invalid_initial_identity_stops_before_userinfo_or_native_reply(self):
        self.responses[TOKEN] = grant(id_token=ID_SENTINEL)
        with self.assertRaises(OAuthExchangeError):
            self.session()
        self.assertEqual(self.sent, [TOKEN])
        self.assertEqual(self.accepted, [TOKEN])
        self.assertTrue(self.peers[TOKEN].closed)
        self.assertEqual(self.peers[TOKEN].replies, [])

    def test_initial_identity_alias_as_access_never_leaves_token_exchange(self):
        assert_alias_denied(self, grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL, access_token=ID_SENTINEL))

    def test_initial_identity_alias_as_refresh_never_leaves_token_exchange(self):
        assert_alias_denied(self, grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL, refresh_token=ID_SENTINEL))

    def test_unverified_subject_withholds_token_and_closes_channel(self):
        self.responses[USERINFO] = b"{}"
        with self.assertRaises(AccountBindingError):
            self.session()
        self.assertEqual(self.sent, [TOKEN, USERINFO])
        self.assertEqual(self.accepted, [TOKEN])
        self.assertTrue(self.peers[TOKEN].closed)
        self.assertEqual(self.peers[TOKEN].replies, [])

    def test_revocation_before_reply_withholds_bytes_and_next_connection(self):
        self.retire_on_response = USERINFO
        with self.assertRaisesRegex(EnrollmentSessionError, "owner retired"):
            self.session()
        self.assertEqual(self.sent, [TOKEN, USERINFO])
        self.assertEqual(self.accepted, [TOKEN])
        self.assertTrue(self.peers[TOKEN].closed)
        self.assertEqual(self.peers[TOKEN].replies, [])
        self.assertIsNone(json.loads(self.journal_file.read_text())["subject_digest"])

    def test_generation_on_native_channel_is_closed_before_any_outbound_write(self):
        peer = NativePeer(packet(TOKEN, request_line=b"POST /v1internal:streamGenerateContent HTTP/1.1"))
        self.peers[TOKEN] = peer
        with self.assertRaises(MetadataIngressError):
            self.session()
        self.assertTrue(peer.closed)
        self.assertEqual(peer.replies, [])
        self.assertEqual(self.sent, [])
        self.callback_gate.take_forwarded.assert_not_called()

    def test_connector_loss_withholds_subject_and_reply_with_supervisor_still_active(self):
        self.peer_retire_on_response = USERINFO
        with self.assertRaisesRegex(EnrollmentSessionError, "owner retired"):
            self.session()
        self.assertTrue(self.active)
        self.assertEqual(self.sent, [TOKEN, USERINFO])
        self.assertEqual(self.peers[TOKEN].replies, [])
        self.assertIsNone(json.loads(self.journal_file.read_text())["subject_digest"])

    def test_live_peer_returning_after_owner_loss_cannot_spend_provider_write(self):
        checked_after_spend = False

        def verify_invocation():
            nonlocal checked_after_spend
            checked_after_spend |= json.loads(self.journal_file.read_text())["metadata_pending"]

        def peer_check():
            if checked_after_spend:
                self.active = False
            return True

        self.native_gate.side_effect = verify_invocation
        peer = self.peers[TOKEN]
        with patch.object(peer, "active", side_effect=peer_check):
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "authority"):
                self.session()
        self.assertEqual(self.sent, [])
        self.assertEqual(peer.replies, [])
        self.assertTrue(json.loads(self.journal_file.read_text())["metadata_pending"])

    def test_live_peer_returning_after_owner_loss_cannot_release_native_reply(self):
        peer = self.peers[TOKEN]
        reply_pending = False
        settimeout = peer.settimeout

        def note_reply_timeout(timeout):
            nonlocal reply_pending
            settimeout(timeout)
            reply_pending |= self.sent == [TOKEN, USERINFO]

        def peer_check():
            if reply_pending:
                self.active = False
            return True

        with patch.object(peer, "settimeout", side_effect=note_reply_timeout), \
                patch.object(peer, "active", side_effect=peer_check):
            with self.assertRaisesRegex(EnrollmentSessionError, "owner retired"):
                self.session()
        self.assertTrue(reply_pending)
        self.assertEqual(self.sent, [TOKEN, USERINFO])
        self.assertEqual(peer.replies, [])

    def test_invocation_loss_after_upstream_response_withholds_all_native_bytes(self):
        destination = self.destination

        def retire_after_userinfo(route, **request):
            result = destination(route, **request)
            if route is USERINFO:
                self.native_gate.side_effect = registration.RegistrationUnavailable("Exact invocation retired")
            return result

        self.destination = retire_after_userinfo
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "invocation retired"):
            self.session()
        self.assertEqual(self.sent, [TOKEN, USERINFO])
        self.assertTrue(self.active)
        self.assertTrue(self.peers[TOKEN].live)
        self.assertEqual(self.peers[TOKEN].replies, [])

    def test_enrollment_needs_the_bound_service_and_exact_drained_dialogue(self):
        unit = "oc-google-acp-" + "e" * 24 + ".service"
        identity = NativeInvocation(unit, "f" * 32, b"/fixture", 123)
        service = NativeService(unit, Mock(), "fixture", self.profile.phase_scope)
        other = NativeService(unit, service.process, "fixture", object())
        acp = object.__new__(NativeEnrollmentAcp)
        acp._process = service.process
        acp._drained_sign_in = False
        acp._drained_cold_session = True
        self.profile.reserve_enrollment_spawn(lambda: True)
        with self.assertRaises(registration.RegistrationUnavailable):
            self.profile.reserve_enrollment_spawn(lambda: True)
        object.__setattr__(service, "attested", identity)
        replacement = NativeInvocation(identity.unit, "f" * 32, identity.group, identity.pid + 1)
        with patch.object(NativeService, "invocation", return_value=replacement):
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "original attestation"):
                self.profile.bind_native_invocation(service, authorized=lambda: True)
        with patch.object(NativeService, "invocation", return_value=identity):
            with self.assertRaises(registration.RegistrationUnavailable):
                self.profile.bind_native_invocation(other, authorized=lambda: True)
            self.assertEqual(self.sent, [])
            self.profile.bind_native_invocation(service, authorized=lambda: True)
        result = self.session()
        native = self.profile.path / "antigravity-acp"
        native.mkdir(mode=0o700)
        token = native / "acp_token.json"
        token.touch(mode=0o600)
        token.write_bytes(cold_credential())
        object.__setattr__(service, "retired", identity)
        object.__setattr__(other, "retired", identity)
        with self.assertRaises(registration.RegistrationUnavailable):
            self.profile.complete_enrollment(service, acp, completion=result.completion, authorized=lambda: True)
        acp._drained_sign_in = True
        with self.assertRaises(registration.RegistrationUnavailable):
            self.profile.complete_enrollment(other, acp, completion=result.completion, authorized=lambda: True)
        status = self.profile.complete_enrollment(service, acp, completion=result.completion, authorized=lambda: True)
        self.assertIs(status.phase, registration.Phase.ENROLLMENT_RETIRED)


class ColdMetadataSessionTest(unittest.TestCase):
    def setUp(self):
        self.native_gate = self.enterContext(patch.object(registration._HeldProfile, "_native_current"))
        scratch = self.enterContext(TemporaryDirectory())
        self.enterContext(patch.object(registration, "_account_home", return_value=Path(scratch)))
        journal = registration.RegistrationJournal("fixture")
        enrolled = journal.begin("e" * 64)
        with journal.enrollment_profile(enrolled) as initial:
            initial.bind_subject(b"old-fixture-bearer", SUBJECT, authorized=lambda: True)
            native = initial.path / "antigravity-acp"
            native.mkdir(mode=0o700)
            self.credential = native / "acp_token.json"
            self.credential.touch(mode=0o600)
            self.credential.write_bytes(cold_credential())
        record_enrollment_retired(journal, enrolled)
        check = journal.begin_cold_check(enrolled)
        self.check = check
        self.profile_scope = self.enterContext(ExitStack())
        self.profile = self.profile_scope.enter_context(journal.cold_profile(check))
        self.journal = journal
        self.scratch = Path(scratch)
        self.fence = RLock()
        access = json.loads(grant())
        del access["refresh_token"]
        row = {"displayName": "Synthetic Gemini Pro", "model": "MODEL_FIXTURE",
               "modelProvider": "MODEL_PROVIDER_GOOGLE", "apiProvider": "API_PROVIDER_GOOGLE_GEMINI",
               "maxTokens": 4096, "maxOutputTokens": 512}
        self.responses = {
            TOKEN: json.dumps(access).encode(), USERINFO: SUBJECT, LOAD: LOAD_REPLY,
            CATALOG: json.dumps({
                "models": {"gemini-fixture": row, "other-fixture": row | {"apiProvider": "OTHER_FIXTURE"}},
                "defaultAgentModelId": "gemini-fixture", "agentModelSorts": [],
            }).encode(),
        }
        self.project = b'{"project":"oc-synthetic-stage-a"}'
        self.peers = {
            TOKEN: NativePeer(packet(TOKEN, body=refresh_form(), changes={
                b"Authorization": None, b"X-Goog-Api-Client": b"synthetic-client",
            })),
            LOAD: NativePeer(packet(LOAD, body=LOAD_REQUEST, changes={b"Authorization": BEARER})),
            CATALOG: self.catalog_peer(self.project),
        }
        self.sent = []

    def catalog_peer(self, body):
        return NativePeer(packet(CATALOG, body=body, changes={b"Authorization": BEARER, b"Connection": b"close"}))

    def destination(self, route, *, authorization, deadline, deliver, body=b""):
        self.assertGreater(deadline, time.monotonic())
        self.assertEqual(authorization, None if route is TOKEN else BEARER)
        if route is CATALOG:
            self.assertEqual(json.loads(body), json.loads(self.project))
        deliver(lambda: self.sent.append(route))
        return self.responses[route]

    def session(self):
        return serve_cold_metadata(
            profile=self.profile, deadline=time.monotonic() + 3, accept=lambda route, deadline: self.peers[route].channel(),
            fence=self.fence, authorized=lambda: True, destination=self.destination,
        )

    def test_cold_phase_observes_gemini_on_four_exact_metadata_routes(self):
        observation = self.session()
        self.assertEqual(observation.gemini_models, ("gemini-fixture",))
        self.assertEqual(self.sent, [TOKEN, USERINFO, LOAD, CATALOG])
        self.assertTrue(all(peer.closed and len(peer.replies) == 1 for peer in self.peers.values()))

    def test_cold_oidc_reply_reaches_native_with_scope_and_without_identity_token(self):
        self.responses[TOKEN] = cold_grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL)
        self.session()
        self.assertEqual(self.sent, [TOKEN, USERINFO, LOAD, CATALOG])
        response, = self.peers[TOKEN].replies
        self.assertEqual(response.split(b"\r\n\r\n", 1)[1], native_json(json.loads(cold_grant(scope=OIDC_SCOPE))))
        self.assertNotIn(ID_SENTINEL.encode("ascii"), response)

    def test_invalid_cold_oidc_envelope_stops_before_userinfo_or_native_reply(self):
        self.responses[TOKEN] = cold_grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL, refresh_token_expires_in=7200)
        with self.assertRaises(OAuthExchangeError):
            self.session()
        self.assertEqual(self.sent, [TOKEN])
        self.assertTrue(self.peers[TOKEN].closed)
        self.assertEqual(self.peers[TOKEN].replies, [])

    def test_cold_identity_alias_as_access_never_leaves_token_exchange(self):
        assert_alias_denied(self, cold_grant(scope=OIDC_SCOPE, id_token=ID_SENTINEL, access_token=ID_SENTINEL))

    def test_wrong_project_blocks_catalog_before_outbound_write(self):
        self.peers[CATALOG] = self.catalog_peer(b'{"project":"different-project"}')
        with self.assertRaises(EnrollmentMetadataError):
            self.session()
        self.assertEqual(self.sent, [TOKEN, USERINFO, LOAD])
        self.assertTrue(self.peers[CATALOG].closed)
        self.assertEqual(self.peers[CATALOG].replies, [])

    def test_invalid_catalog_is_withheld_from_native(self):
        self.responses[CATALOG] = b'{"models":{},"defaultAgentModelId":"missing","agentModelSorts":[]}'
        with self.assertRaises(EnrollmentMetadataError):
            self.session()
        self.assertEqual(self.sent, [TOKEN, USERINFO, LOAD, CATALOG])
        self.assertTrue(self.peers[CATALOG].closed)
        self.assertEqual(self.peers[CATALOG].replies, [])

    def test_missing_credential_cannot_use_an_available_catalog(self):
        self.credential.unlink()
        with self.assertRaises(registration.RegistrationUnavailable):
            self.session()
        self.assertEqual(self.sent, [])
        self.assertEqual(self.peers[TOKEN].replies, [])

    def test_in_place_change_after_refresh_write_stops_further_calls(self):
        inode = self.credential.stat().st_ino
        destination = self.destination

        def mutate_after_write(route, **request):
            reply = destination(route, **request)
            if route is TOKEN:
                self.credential.write_bytes(cold_credential(refresh_token="different-fixture-token"))
                self.assertEqual(self.credential.stat().st_ino, inode)
            return reply

        self.destination = mutate_after_write
        with self.assertRaises(registration.RegistrationUnavailable):
            self.session()
        self.assertEqual(self.sent, [TOKEN])
        self.assertTrue(self.peers[TOKEN].closed)
        self.assertEqual(self.peers[TOKEN].replies, [])

    def make_replica_root(self):
        runtime = self.scratch / "runtime"
        self.enterContext(patch.object(registration, "_RUNTIME_PARENT", runtime))
        root = runtime / str(os.geteuid()) / ("oc-g-" + "a" * 24)
        root.mkdir(mode=0o700, parents=True)
        root.parent.chmod(0o700)
        return root, "oc-google-acp-" + "b" * 24 + ".service"

    def test_exact_custody_publication_waits_for_root_removal(self):
        self.native_gate.side_effect = lambda: _NATIVE_CURRENT(self.profile.spend_metadata.__self__)
        root, unit = self.make_replica_root()
        replica = self.profile.stage_cold_source(root, unit, authorized=lambda: True)
        copy = replica.mount_path() / "antigravity-acp" / "acp_token.json"
        self.assertEqual(copy.read_bytes(), self.credential.read_bytes())
        self.assertNotEqual(copy.stat().st_ino, self.credential.stat().st_ino)
        with self.assertRaises(registration.RegistrationUnavailable):
            self.profile.spend_metadata(TOKEN, lambda: self.fail("sent before invocation"), authorized=lambda: True)
        process = Mock()
        service = NativeService(unit, process, "fixture")
        identity = NativeInvocation(unit, "c" * 32, b"/fixture", 123)
        object.__setattr__(service, "attested", identity)
        self.enterContext(patch.object(NativeService, "invocation", return_value=identity))
        replica.reserve_spawn(lambda: True)
        self.profile.bind_native_invocation(service, authorized=lambda: True)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "live or uncertain service"):
            replica.remove()
        result = self.session()
        observation = registration.ColdObservation(self.check, True, 0, True)
        acp = object.__new__(NativeEnrollmentAcp)
        acp._process = process
        acp._drained_cold_session = False
        settlement = {"completion": result.completion, "service": service, "acp": acp}
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "phase retirement is incomplete"):
            self.profile.complete_cold_custody(observation, **settlement, authorized=lambda: True)
        object.__setattr__(service, "retired", identity)
        acp._drained_cold_session = True
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "retirement is incomplete"):
            self.profile.complete_cold_custody(observation, **settlement, authorized=lambda: True)
        moved = root.with_name(root.name + "-moved")
        root.rename(moved)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "retirement is incomplete"):
            self.profile.complete_cold_custody(observation, **settlement, authorized=lambda: True)
        moved.rename(root)
        replica.remove()
        quarantine = root.with_name("." + root.name + "-retire")
        quarantine.mkdir()
        try:
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "retirement is incomplete"):
                self.profile.complete_cold_custody(observation, **settlement, authorized=lambda: True)
        finally:
            quarantine.rmdir()
        with self.assertRaises(registration.RegistrationUnavailable):
            self.profile.complete_cold_custody(observation, **settlement, authorized=lambda: False)
        status = self.profile.complete_cold_custody(observation, **settlement, authorized=lambda: True)
        self.assertIs(status.phase, registration.Phase.COLD_RETIREMENT_OBSERVED)

    def test_unstaged_cold_attempt_cannot_send_a_refresh(self):
        self.native_gate.side_effect = lambda: _NATIVE_CURRENT(self.profile.spend_metadata.__self__)
        with self.assertRaises(registration.RegistrationUnavailable):
            self.session()
        self.assertEqual(self.sent, [])

    def test_cold_profile_refused_before_enrollment_namespace_preparation(self):
        with patch("oc_google.native_service.prepare_enrollment_namespace") as prepare:
            with self.assertRaisesRegex(NativeNamespaceError, "pinned profile"):
                open_enrollment_service(self.scratch, None, profile=self.profile, connector=None, ca=None, browser=None,
                                        authorized=lambda: True, fence=self.fence)
        prepare.assert_not_called()

    def test_cold_spawn_refuses_lost_owner_or_changed_credential_after_staging(self):
        root, unit = self.make_replica_root()
        replica = self.profile.stage_cold_source(root, unit, authorized=lambda: True)
        active = True
        with patch("oc_google.native_service.check_private_directory"), \
                patch("oc_google.native_service.prepare_cold_namespace"), patch("oc_google.native_service._spawn") as spawn:
            first = open_cold_service(root, None, replica=replica, connector=None, ca=None,
                                      authorized=lambda: active, fence=self.fence)
            active = False
            with self.assertRaises(registration.RegistrationUnavailable), first:
                self.fail("spawned after cancellation")
            active = True
            second = open_cold_service(root, None, replica=replica, connector=None, ca=None,
                                       authorized=lambda: active, fence=self.fence)
            self.credential.write_bytes(cold_credential(refresh_token="changed-after-staging"))
            with self.assertRaises(registration.RegistrationUnavailable), second:
                self.fail("spawned after credential changed")
            spawn.assert_not_called()
        replica.abandon_unlaunched()
        self.assertFalse(root.exists())

    def exercise_prelaunch_owner_loss(self, when, failure=None):
        runtime = self.scratch / "runtime"
        parent = runtime / str(os.geteuid())
        parent.mkdir(mode=0o700, parents=True)
        self.enterContext(patch.object(registration, "_RUNTIME_PARENT", runtime))
        live = True
        authorized = lambda: live
        owner = Mock(authorized=authorized)
        unit = "oc-google-acp-" + "b" * 24 + ".service"
        slot = self.scratch / ".local/state/oc-sandbox/google/registrations/fixture"
        with (self.assertRaises(connect.CustodyUnconfirmed) if failure else nullcontext()):
            with connect._private_runtime(parent, "fixture", True, owner) as custody:
                root = custody.root
                replica = self.profile.stage_cold_source(root, unit, authorized=authorized)

                def record(event, value):
                    nonlocal live
                    if event == "no-spawn" and failure == "receipt":
                        raise OSError("fixture no-spawn sync failed")
                    self.profile.record_native_custody(event, value)
                    if event == "launch" and when == "after":
                        live = False

                custody.bind(record)
                before_spawn = custody.before_spawn

                def entered(reserved_unit):
                    nonlocal live
                    if when == "entry":
                        live = False
                    before_spawn(reserved_unit)

                mark = replica._failed_to_spawn

                def interrupted_marker(*args):
                    mark(*args)
                    raise OSError("fixture replica marker was interrupted")

                with ExitStack() as fixture:
                    fixture.enter_context(patch.object(custody, "before_spawn", side_effect=entered))
                    fixture.enter_context(patch("oc_google.native_service.check_private_directory"))
                    fixture.enter_context(patch("oc_google.native_service.prepare_cold_namespace",
                                                return_value=Mock(unit=unit)))
                    spawn = fixture.enter_context(patch("oc_google.native_service._spawn"))
                    if failure == "marker":
                        fixture.enter_context(patch.object(replica, "_failed_to_spawn", side_effect=interrupted_marker))
                    with self.assertRaisesRegex(RuntimeError, "owner retired before") as caught, open_cold_service(
                        root, None, replica=replica, connector=None, ca=None,
                        authorized=authorized, fence=self.fence, custody=custody,
                    ):
                        self.fail("a retired owner started the native service")
                    spawn.assert_not_called()

                replica.abandon_unlaunched()
                receipt = slot / "cold-native-no-spawn.json"
                if failure:
                    uncertainty, = caught.exception.cleanup_uncertainties
                    self.assertIsInstance(uncertainty, NativeRetirementUnconfirmed)
                    self.assertFalse(custody.cleanable)
                    self.assertFalse(replica.removed())
                    self.assertTrue((root / "profile").is_dir())
                    self.assertEqual(receipt.exists(), failure == "marker")
                else:
                    self.assertTrue(replica.removed())
                    self.assertFalse(root.exists())
                    self.assertEqual(json.loads(receipt.read_text())["unit"], unit)
        self.assertEqual(root.exists(), failure is not None)

    def test_owner_loss_at_custody_entry_keeps_replica_cleanup_with_the_replica(self):
        self.exercise_prelaunch_owner_loss("entry")

    def test_owner_loss_after_launch_receipt_keeps_replica_cleanup_with_the_replica(self):
        self.exercise_prelaunch_owner_loss("after")

    def test_failed_no_spawn_receipt_holds_the_cold_replica(self):
        self.exercise_prelaunch_owner_loss("after", failure="receipt")

    def test_unsettled_replica_marker_holds_the_cold_replica(self):
        self.exercise_prelaunch_owner_loss("after", failure="marker")

    def test_failed_launcher_exec_does_not_strand_a_credential_copy(self):
        root, unit = self.make_replica_root()
        replica = self.profile.stage_cold_source(root, unit, authorized=lambda: True)
        with patch("oc_google.native_service.check_private_directory"), \
                patch("oc_google.native_service.prepare_cold_namespace"), \
                patch("oc_google.native_service._spawn", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError), open_cold_service(
                root, None, replica=replica, connector=None, ca=None, authorized=lambda: True, fence=self.fence,
            ):
                self.fail("a missing launcher started")
        replica.abandon_unlaunched()
        self.assertFalse(root.exists())

    def test_interruption_before_replica_handoff_removes_the_owned_copy(self):
        root, unit = self.make_replica_root()
        authorization = Mock(side_effect=[True, True, KeyboardInterrupt])
        with self.assertRaises(KeyboardInterrupt):
            self.profile.stage_cold_source(root, unit, authorized=authorization)
        self.assertFalse(root.exists())

    def test_profile_cleans_unlaunched_copy_if_staging_descriptor_release_is_interrupted(self):
        root, unit = self.make_replica_root()
        native = root / "profile" / "antigravity-acp"
        close = os.close

        def interrupted_close(fd):
            path = os.readlink(f"/proc/self/fd/{fd}")
            close(fd)
            if path == str(native):
                raise KeyboardInterrupt

        with patch("oc_google.registration.os.close", side_effect=interrupted_close):
            with self.assertRaises(KeyboardInterrupt):
                self.profile.stage_cold_source(root, unit, authorized=lambda: True)
        self.assertTrue((native / "acp_token.json").is_file())
        self.profile_scope.close()
        self.assertFalse(root.exists())

    def test_profile_cleanup_error_preserves_an_active_interruption(self):
        primary = KeyboardInterrupt("fixture staging interruption")
        cleanup = OSError("fixture quarantine failure")
        held = Mock()
        held.close.side_effect = cleanup
        with self.assertRaises(KeyboardInterrupt) as result, registration._held_profile_lifetime(held):
            raise primary
        self.assertIs(result.exception, primary)
        self.assertIs(result.exception.__cause__, cleanup)

    def test_owner_loss_after_receipt_cannot_create_a_replica(self):
        root, unit = self.make_replica_root()
        current = iter((True, False))
        with self.assertRaises(registration.RegistrationUnavailable):
            self.profile.stage_cold_source(root, unit, authorized=lambda: next(current))
        self.assertFalse((root / "profile").exists())
        with self.assertRaises(registration.RegistrationUnavailable):
            self.profile.stage_cold_source(root, unit, authorized=lambda: True)

    def test_rotation_refuses_before_any_metadata_or_native_reply(self):
        self.responses[TOKEN] = grant(refresh_token="rotated-fixture-refresh")
        with self.assertRaises(OAuthExchangeError):
            self.session()
        self.assertEqual(self.sent, [TOKEN])
        self.assertEqual(self.peers[TOKEN].replies, [])
        self.profile_scope.close()
        self.assertIs(self.journal.status().phase, registration.Phase.COLD_CHECKING)
        with self.assertRaises(registration.RegistrationUnavailable):
            self.journal.begin_cold_check(self.check.enrollment)
