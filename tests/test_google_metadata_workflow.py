"""Protect the metadata-only workflow's setup and authorization boundaries."""

from contextlib import contextmanager, nullcontext
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import RLock
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oc_google import connect, native_service
from oc_google.auth_offer import CallbackDiagnostic, Outcome
from oc_google.enrollment import EnrollmentMetadataError
from oc_google.enrollment_session import ColdMetadataObservation
from oc_google.metadata_workflow import (
    BoundGoogleCatalog, CallbackWorkflowError, MetadataRuntime, MetadataWorkflowError,
    _receive_callback, enroll_metadata, reopen_metadata,
)
from oc_google.native_enrollment_acp import NativeAcpError
from oc_google.native_service import NativeInvocation, NativeRetirementUnconfirmed
from oc_google.registration import Enrollment, FileIdentity, Phase, RegistrationStatus, RegistrationUnavailable
from oc_google.token_diagnostic import PostTokenDiagnostic, PostTokenStage, TokenDiagnostic


class MetadataWorkflowTest(unittest.TestCase):
    def workflow_fixture(self):
        build = SimpleNamespace(digest="fixture")
        enrollment = Enrollment("fixture", "registration", "generation", "attempt", build.digest,
                                FileIdentity(1, 2), FileIdentity(1, 3))
        journal, profile, replica, service = Mock(), Mock(), Mock(), Mock()
        journal.label = enrollment.label
        service.process.poll.return_value = None
        service.retired = None
        profile.stage_cold_source.return_value = replica
        journal.begin.return_value = enrollment
        journal.enrollment_profile.return_value = nullcontext(profile)
        journal.cold_profile.return_value = nullcontext(profile)
        runtime = SimpleNamespace(root=Path("/fixture"), build=build, certificate=Path("/fixture/ca"), custody=None,
                                  listeners=Mock(return_value=nullcontext((Path("/fixture/metadata.sock"), Mock()))))

        @contextmanager
        def opened(*args, **kwargs):
            try:
                yield service
            finally:
                service.retired = service.attested

        return journal, profile, replica, enrollment, runtime, opened

    def test_missing_shared_fence_is_refused_before_journal_or_runtime(self):
        journal = Mock()
        with self.assertRaisesRegex(MetadataWorkflowError, "revocation fence"):
            enroll_metadata(journal, None, disclose_offer=Mock(), destination=Mock(), authorized=lambda: True, fence=None)
        with self.assertRaisesRegex(MetadataWorkflowError, "revocation fence"):
            reopen_metadata(journal, None, None, runtime_scope=nullcontext(), destination=Mock(), authorized=lambda: True, fence=None)
        self.assertEqual(journal.mock_calls, [])

    def test_revoked_offer_is_neither_activated_nor_disclosed(self):
        notify, gate = Mock(), Mock()
        owner = SimpleNamespace(fence=RLock(), authorizes_offer=lambda _: False)
        with self.assertRaisesRegex(MetadataWorkflowError, "owner retired"):
            _receive_callback(object(), gate, notify=notify, deadline=time.monotonic() + 1, owner=owner, profile=None)
        gate.activate.assert_not_called()
        notify.assert_not_called()

    def test_offer_delivery_and_fresh_owner_check_precede_activation(self):
        owner = SimpleNamespace(fence=RLock(), authorizes_offer=Mock(side_effect=[True, False]))
        gate = Mock()
        notify = Mock(side_effect=lambda _: gate.activate.assert_not_called())
        with self.assertRaisesRegex(MetadataWorkflowError, "after offer disclosure"):
            _receive_callback(object(), gate, notify=notify, deadline=time.monotonic() + 1,
                              owner=owner, profile=None)
        notify.assert_called_once()
        gate.activate.assert_not_called()

    def test_callback_workflow_distinguishes_refusal_absence_and_forwarded_owner_loss(self):
        cases = (
            (Outcome.CANCELLED, CallbackDiagnostic.HEADER_REFERER, CallbackDiagnostic.HEADER_REFERER),
            (Outcome.OPEN, None, CallbackDiagnostic.NO_MATCHING_CALLBACK),
            (Outcome.FORWARDED, None, CallbackDiagnostic.FORWARDED_BEFORE_METADATA),
        )
        owner = SimpleNamespace(fence=RLock(), authorizes_offer=lambda _: True, active=lambda: False)
        for outcome, stage, expected in cases:
            with self.subTest(outcome=outcome):
                gate = Mock(outcome=outcome, diagnostic=stage)
                with self.assertRaises(CallbackWorkflowError) as refused:
                    _receive_callback(object(), gate, notify=Mock(), deadline=time.monotonic() + 1,
                                      owner=owner, profile=None)
                self.assertIs(refused.exception.diagnostic, expected)

    def test_cold_phase_expiry_during_retirement_withholds_settlement(self):
        journal, profile, _replica, enrollment, runtime, opened = self.workflow_fixture()
        clock = Mock(return_value=100)

        @contextmanager
        def slow_retirement(*args, **kwargs):
            with opened() as service:
                yield service
                clock.return_value = 119

        def settle(*args, authorized, **kwargs):
            if not authorized():
                raise MetadataWorkflowError("Google metadata settlement owner expired")

        profile.complete_cold_custody.side_effect = settle
        with patch("oc_google.metadata_workflow.time.monotonic", clock), \
                patch("oc_google.metadata_workflow.open_cold_service", side_effect=slow_retirement), \
                patch("oc_google.metadata_workflow.NativeEnrollmentAcp"), \
                patch("oc_google.metadata_workflow.serve_cold_metadata") as observed:
            with self.assertRaisesRegex(MetadataWorkflowError, "settlement owner expired"):
                reopen_metadata(journal, enrollment, runtime, runtime_scope=nullcontext(), destination=Mock(), authorized=lambda: True,
                                fence=RLock())
        self.assertEqual(observed.call_args.kwargs["deadline"], 118)

    def test_missing_certificate_is_refused_before_replica_creation(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "key.pem"
            key.touch(mode=0o600)
            build = SimpleNamespace(digest="fixture")
            runtime = MetadataRuntime(root, build, root / "missing.pem", key)
            profile, journal = Mock(), Mock()
            journal.cold_profile.return_value = nullcontext(profile)
            with self.assertRaises(FileNotFoundError):
                reopen_metadata(journal, SimpleNamespace(build_digest=build.digest), runtime,
                                runtime_scope=nullcontext(), destination=Mock(),
                                authorized=lambda: True, fence=RLock())
            profile.stage_cold_source.assert_not_called()

    def test_enrollment_composes_offer_and_retired_metadata_completion(self):
        journal, profile, _replica, enrollment, runtime, opened = self.workflow_fixture()
        outcome, offer, gate, disclose = Mock(), object(), Mock(outcome=Outcome.FORWARDED), Mock()
        handoff = nullcontext((Path("/fixture/browser.sock"), lambda _: nullcontext((offer, gate))))
        with patch("oc_google.metadata_workflow._initialize_settings"), \
                patch("oc_google.metadata_workflow.open_enrollment_service", side_effect=opened), \
                patch("oc_google.metadata_workflow.open_native_browser_listener", return_value=handoff), \
                patch("oc_google.metadata_workflow.NativeEnrollmentAcp"), \
                patch("oc_google.metadata_workflow.serve_initial_metadata", return_value=outcome):
            result = enroll_metadata(journal, runtime, disclose_offer=disclose, destination=Mock(),
                                     authorized=lambda: True, fence=RLock())
        self.assertIs(result, enrollment)
        disclose.assert_called_once_with(offer)
        self.assertIs(profile.complete_enrollment.call_args.kwargs["completion"], outcome.completion)

    def test_actual_service_exit_uses_only_the_original_primary_drain_or_commit_error(self):
        for case, stage in (
            ("load", PostTokenStage.LOAD_BODY),
            ("unrelated", None),
            ("live ACP", PostTokenStage.AUTH_COMPLETE),
            ("live ACP pin lost", None),
            ("drain", PostTokenStage.ENROLLMENT_DRAIN),
            ("drain expired", None),
            ("retirement uncertain", None),
            ("commit", PostTokenStage.ENROLLMENT_COMMIT),
            ("commit expired", None),
        ):
            with self.subTest(case=case):
                journal, profile, _, _, runtime, _ = self.workflow_fixture()
                diagnostic = PostTokenDiagnostic()
                unit = "oc-google-acp-" + "1" * 24 + ".service"
                identity = NativeInvocation(unit, "2" * 32, b"/fixture", 123)
                namespace = SimpleNamespace(unit=unit, description="synthetic native")
                proc = Mock()
                proc.poll.return_value = None
                gate = Mock(outcome=Outcome.FORWARDED)
                handoff = nullcontext((Path("/fixture/browser.sock"), lambda _: nullcontext((object(), gate))))
                acp = Mock()
                primary_type = (RegistrationUnavailable if case.startswith("commit") else
                                EnrollmentMetadataError if case == "load" else NativeAcpError)
                primary = primary_type("synthetic primary")
                clock = Mock(return_value=100)

                @contextmanager
                def opened(*args, after_stop, **kwargs):
                    with native_service._run_service(namespace, after_stop) as service:
                        yield service

                def serve_initial(**kwargs):
                    if case == "load":
                        diagnostic.mark(primary, PostTokenStage.LOAD_BODY)
                    if case in {"load", "unrelated"}:
                        raise primary
                    return SimpleNamespace(completion=object())

                def commit(service, *_, **kwargs):
                    self.assertIs(service.retired, identity)
                    if case == "commit expired":
                        clock.return_value = 281
                    raise primary

                def drain():
                    if case == "drain expired":
                        clock.return_value = 281
                    raise primary

                def finish_auth():
                    if case == "live ACP pin lost":
                        profile.verify_native_invocation.side_effect = RegistrationUnavailable("synthetic native pin loss")
                    raise primary

                if case.startswith("live ACP"):
                    acp.finish_personal_sign_in.side_effect = finish_auth
                if case in {"drain", "drain expired", "retirement uncertain"}:
                    acp.drain_retired_enrollment.side_effect = drain
                if case.startswith("commit"):
                    profile.complete_enrollment.side_effect = commit
                receipt = Mock(returncode=int(case == "retirement uncertain"),
                               stdout=b"ActiveState=inactive\nControlGroup=\n")
                fd = os.open(os.devnull, os.O_RDONLY)
                with patch("oc_google.metadata_workflow.time.monotonic", clock), \
                        patch("oc_google.metadata_workflow._initialize_settings"), \
                        patch("oc_google.metadata_workflow.open_enrollment_service", side_effect=opened), \
                        patch("oc_google.metadata_workflow.open_native_browser_listener", return_value=handoff), \
                        patch("oc_google.metadata_workflow.NativeEnrollmentAcp", return_value=acp), \
                        patch("oc_google.metadata_workflow.serve_initial_metadata", side_effect=serve_initial), \
                        patch.object(native_service, "_spawn", return_value=proc), \
                        patch.object(native_service, "_pin", return_value=(identity, fd)), \
                        patch.object(native_service, "_pid_exited", return_value=True), \
                        patch.object(native_service.signal, "pidfd_send_signal") as stop, \
                        patch.object(native_service, "host", return_value=receipt):
                    with self.assertRaises(type(primary)) as result:
                        enroll_metadata(journal, runtime, disclose_offer=Mock(), destination=Mock(),
                                        authorized=lambda: True, fence=RLock(), post_diagnostic=diagnostic)
                self.assertIs(result.exception, primary)
                self.assertIs(diagnostic.stage(primary), stage)
                if case == "retirement uncertain":
                    self.assertIsInstance(primary.__cause__, NativeRetirementUnconfirmed)
                stop.assert_called_once()
                self.assertEqual(acp.drain_retired_enrollment.call_count,
                                 int(case not in {"load", "unrelated"} and not case.startswith("live ACP")))
                console = Mock()
                connect._write_enrollment_detail(console, primary, TokenDiagnostic(), diagnostic)
                if stage is None or case == "retirement uncertain":
                    console.write_once.assert_not_called()
                else:
                    console.write_once.assert_called_once()
                    self.assertNotIn("synthetic primary", console.write_once.call_args.args[0])

    def test_bound_catalog_requires_exact_commit_and_both_cleanup_exits(self):
        for case in ("flash", "decoy-only", "wrong-label", "wrong-generation", "commit-failed",
                     "changed-source", "owner-lost-after-commit", "lost-owner", "custody-exit", "runtime-exit"):
            with self.subTest(case=case):
                journal, profile, replica, enrollment, runtime, opened = self.workflow_fixture()
                allowed = case != "decoy-only"
                models = ("gemini-2.5-flash", "gemini-decoy") if allowed else ("gemini-decoy",)
                outcome = ColdMetadataObservation(None, models, object())
                phases = []
                authorized = Mock(return_value=True)
                diagnostic = PostTokenDiagnostic()

                @contextmanager
                def held_custody():
                    yield profile
                    phases.append("custody-exited")
                    if case == "custody-exit":
                        raise RuntimeError("cold custody cleanup")

                @contextmanager
                def private_runtime():
                    try:
                        yield
                    finally:
                        phases.append("runtime-exited")
                        if case == "lost-owner":
                            authorized.return_value = False
                        if case == "runtime-exit":
                            raise RuntimeError("cold runtime cleanup")

                def settle(*args, **kwargs):
                    replica.remove.assert_called_once_with()
                    self.assertIs(kwargs["completion"], outcome.completion)
                    self.assertTrue(kwargs["authorized"]())
                    if case == "commit-failed":
                        raise RegistrationUnavailable("cold commit failed")
                    if case == "owner-lost-after-commit":
                        authorized.return_value = False
                    return RegistrationStatus(
                        "another-label" if case == "wrong-label" else enrollment.label,
                        enrollment.registration_id,
                        "another-generation" if case == "wrong-generation" else enrollment.generation,
                        Phase.COLD_RETIREMENT_OBSERVED,
                    )

                def verify_cold_source():
                    phases.append("verified")
                    if case == "changed-source":
                        raise RegistrationUnavailable("cold profile changed")

                def publish(*args):
                    self.assertEqual(phases, ["verified", "custody-exited", "runtime-exited"])
                    return BoundGoogleCatalog(*args)

                journal.cold_profile.return_value = held_custody()
                profile.complete_cold_custody.side_effect = settle
                profile.verify_cold_source.side_effect = verify_cold_source
                with patch("oc_google.metadata_workflow.open_cold_service", side_effect=opened), \
                        patch("oc_google.metadata_workflow.NativeEnrollmentAcp"), \
                        patch("oc_google.metadata_workflow.serve_cold_metadata", return_value=outcome), \
                        patch("oc_google.metadata_workflow.BoundGoogleCatalog", side_effect=publish) as emitted:
                    def reopen():
                        return reopen_metadata(journal, enrollment, runtime, runtime_scope=private_runtime(),
                                               destination=Mock(), authorized=authorized, fence=RLock(),
                                               post_diagnostic=diagnostic)

                    if case in {"flash", "decoy-only"}:
                        expected = (BoundGoogleCatalog("google/fixture", "registration", "generation", "fixture",
                                                       ("gemini-2.5-flash",)) if allowed else None)
                        self.assertEqual(reopen(), expected)
                        self.assertEqual(emitted.call_count, int(allowed))
                    else:
                        with self.assertRaisesRegex(RuntimeError, {
                            "wrong-label": "projection changed",
                            "wrong-generation": "projection changed",
                            "commit-failed": "commit failed",
                            "changed-source": "profile changed",
                            "owner-lost-after-commit": "owner retired before projection",
                            "lost-owner": "owner retired before completion",
                            "custody-exit": "cold custody cleanup",
                            "runtime-exit": "cold runtime cleanup",
                        }[case]) as refusal:
                            reopen()
                        emitted.assert_not_called()
                        expected_stage = PostTokenStage.COLD_COMMIT if case == "commit-failed" else None
                        self.assertIs(diagnostic.stage(refusal.exception), expected_stage)
                        if case in {"commit-failed", "owner-lost-after-commit"}:
                            profile.verify_cold_source.assert_not_called()

    def test_cold_cleanup_error_preserves_the_primary_binding_failure(self):
        journal, profile, replica, enrollment, runtime, opened = self.workflow_fixture()
        primary = MetadataWorkflowError("binding revoked")
        profile.bind_native_invocation.side_effect = primary
        replica.remove.side_effect = OSError("fixture cleanup failure")
        with patch("oc_google.metadata_workflow.open_cold_service", side_effect=opened):
            with self.assertRaises(MetadataWorkflowError) as result:
                reopen_metadata(journal, enrollment, runtime, runtime_scope=nullcontext(), destination=Mock(), authorized=lambda: True, fence=RLock())
        self.assertIs(result.exception, primary)
        replica.remove.assert_called_once_with()
        profile.complete_cold_custody.assert_not_called()

    def test_uncertain_service_retirement_preserves_the_replica(self):
        journal, profile, replica, enrollment, runtime, _opened = self.workflow_fixture()
        with patch("oc_google.metadata_workflow.open_cold_service", side_effect=NativeRetirementUnconfirmed("held")):
            with self.assertRaises(NativeRetirementUnconfirmed):
                reopen_metadata(journal, enrollment, runtime, runtime_scope=nullcontext(), destination=Mock(), authorized=lambda: True, fence=RLock())
        replica.remove.assert_not_called()
        replica.abandon_unlaunched.assert_not_called()
        profile.complete_cold_custody.assert_not_called()
