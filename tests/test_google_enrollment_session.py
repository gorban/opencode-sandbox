"""Join private native framing, the durable journal and a fake Google destination."""

import json
import os
from pathlib import Path
from contextlib import ExitStack, contextmanager
from tempfile import TemporaryDirectory
from threading import RLock
import time
import unittest
from unittest.mock import Mock, patch

from oc_google import registration
from oc_google.account_binding import AccountBindingError
from oc_google.auth_offer import Callback
from oc_google.enrollment import EnrollmentMetadataError
from oc_google.enrollment_session import EnrollmentSessionError, serve_cold_metadata, serve_initial_metadata
from oc_google.oauth_exchange import OAuthExchangeError
from oc_google.metadata_destination import MetadataRoute
from oc_google.metadata_ingress import MetadataIngressError
from oc_google.native_enrollment_acp import NativeEnrollmentAcp
from oc_google.native_service import NativeInvocation, NativeService, open_cold_service, open_enrollment_service
from oc_google.native_namespace import NativeNamespaceError
from oc_google.native_transport import NativeChannel
from google_registration_fixture import record_enrollment_retired
from test_google_enrollment import BEARER, LOAD_REPLY, LOAD_REQUEST, SUBJECT
from test_google_metadata_ingress import FakePeer, packet
from test_google_oauth_exchange import AUTHORIZATION, CODE, STATE, cold_credential, form, grant, offer, refresh_form


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

    def sendall(self, reply):
        self.replies.append(reply)

    def close(self):
        self.closed = True

    @contextmanager
    def channel(self):
        try:
            yield NativeChannel(self, lambda: self.live)
        finally:
            self.close()


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

    def session(self):
        return serve_initial_metadata(
            offer=offer(), callback_gate=self.callback_gate, profile=self.profile,
            deadline=time.monotonic() + 3, accept=self.accept, fence=self.fence,
            authorized=lambda: self.active, destination=self.destination,
        )

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
            self.assertEqual(body, self.responses[route])
        self.callback_gate.take_forwarded.assert_called_once_with()

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
            initial.bind_subject(b"old-fixture-bearer", SUBJECT)
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
