"""Protect the metadata-only workflow's setup and authorization boundaries."""

from contextlib import contextmanager, nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import RLock
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from oc_google.auth_offer import Outcome
from oc_google.metadata_workflow import (
    MetadataRuntime, MetadataWorkflowError, _receive_callback, enroll_metadata, reopen_metadata,
)
from oc_google.native_service import NativeRetirementUnconfirmed


class MetadataWorkflowTest(unittest.TestCase):
    def workflow_fixture(self):
        build = SimpleNamespace(digest="fixture")
        enrollment = SimpleNamespace(build_digest=build.digest)
        journal, profile, replica, service = Mock(), Mock(), Mock(), Mock()
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
                service.retired = object()

        return journal, profile, replica, enrollment, runtime, opened

    def test_missing_shared_fence_is_refused_before_journal_or_runtime(self):
        journal = Mock()
        with self.assertRaisesRegex(MetadataWorkflowError, "revocation fence"):
            enroll_metadata(journal, None, disclose_offer=Mock(), destination=Mock(), authorized=lambda: True, fence=None)
        with self.assertRaisesRegex(MetadataWorkflowError, "revocation fence"):
            reopen_metadata(journal, None, None, destination=Mock(), authorized=lambda: True, fence=None)
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
                reopen_metadata(journal, enrollment, runtime, destination=Mock(), authorized=lambda: True,
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
                reopen_metadata(journal, SimpleNamespace(build_digest=build.digest), runtime, destination=Mock(),
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

    def test_cold_success_cleans_replica_before_publishing(self):
        journal, profile, replica, enrollment, runtime, opened = self.workflow_fixture()
        outcome = Mock()
        profile.complete_cold_custody.side_effect = lambda *a, **k: replica.remove.assert_called_once_with()
        with patch("oc_google.metadata_workflow.open_cold_service", side_effect=opened), \
                patch("oc_google.metadata_workflow.NativeEnrollmentAcp"), \
                patch("oc_google.metadata_workflow.serve_cold_metadata", return_value=outcome):
            observed = reopen_metadata(journal, enrollment, runtime, destination=Mock(),
                                       authorized=lambda: True, fence=RLock())
        self.assertIs(observed, outcome)

    def test_cold_cleanup_error_preserves_the_primary_binding_failure(self):
        journal, profile, replica, enrollment, runtime, opened = self.workflow_fixture()
        primary = MetadataWorkflowError("binding revoked")
        profile.bind_native_invocation.side_effect = primary
        replica.remove.side_effect = OSError("fixture cleanup failure")
        with patch("oc_google.metadata_workflow.open_cold_service", side_effect=opened):
            with self.assertRaises(MetadataWorkflowError) as result:
                reopen_metadata(journal, enrollment, runtime, destination=Mock(), authorized=lambda: True, fence=RLock())
        self.assertIs(result.exception, primary)
        replica.remove.assert_called_once_with()
        profile.complete_cold_custody.assert_not_called()

    def test_uncertain_service_retirement_preserves_the_replica(self):
        journal, profile, replica, enrollment, runtime, _opened = self.workflow_fixture()
        with patch("oc_google.metadata_workflow.open_cold_service", side_effect=NativeRetirementUnconfirmed("held")):
            with self.assertRaises(NativeRetirementUnconfirmed):
                reopen_metadata(journal, enrollment, runtime, destination=Mock(), authorized=lambda: True, fence=RLock())
        replica.remove.assert_not_called()
        replica.abandon_unlaunched.assert_not_called()
        profile.complete_cold_custody.assert_not_called()
