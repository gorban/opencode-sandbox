"""Exercise Google registration authority using fake profiles under a scratch home."""

from dataclasses import replace
import errno
import fcntl
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from oc_google import account_binding, registration
from oc_google.oauth_exchange import OAuthExchangeError
from google_registration_fixture import record_cold_observation, record_enrollment_retired
from test_google_oauth_exchange import cold_credential, refresh_form
from oc_google.metadata_destination import MetadataRoute


LABEL = "fixture"
BUILD = "a" * 64
FAKE_CREDENTIAL = b"synthetic fixture bytes never copied into the registration"
FAKE_SUBJECT = b'{"id":"408903144981226013344"}'
FAKE_BEARER = b"fixture-enrollment-bearer"
FAKE_REFRESHED = b"fixture-reopened-bearer"


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        home = tempfile.TemporaryDirectory(prefix="oc-google-reg-")
        self.addCleanup(home.cleanup)
        self.home = Path(home.name)
        account = patch.object(registration, "_account_home", return_value=self.home)
        account.start()
        self.addCleanup(account.stop)
        self.root = self.home / ".local/state/oc-sandbox/google"
        self.slot = self.root / "registrations" / LABEL
        self.receipt = self.slot / "registration.json"
        self.lock = self.slot / "registration.lock"
        self.journal = registration.RegistrationJournal(LABEL)
        self.enterContext(patch.object(registration._HeldProfile, "_native_current"))

    def profile_path(self, enrollment):
        return self.root / "profiles" / enrollment.generation

    def fake_credential(self, profile, name="acp_token.json"):
        container = profile / "antigravity-acp"
        container.mkdir(mode=0o700, exist_ok=True)
        credential = container / name
        credential.write_bytes(FAKE_CREDENTIAL)
        credential.chmod(0o600)
        return credential

    def enroll(self):
        enrollment = self.journal.begin(BUILD)
        with self.journal.enrollment_profile(enrollment) as profile:
            self.assertTrue(os.path.samestat(profile.path.stat(), os.fstat(profile.fd)))
            profile.bind_subject(FAKE_BEARER, FAKE_SUBJECT)
            credential = self.fake_credential(profile.path)
        record_enrollment_retired(self.journal, enrollment)
        return enrollment, credential

    def checked(self):
        enrollment, credential = self.enroll()
        check = self.journal.begin_cold_check(enrollment)
        with self.journal.cold_profile(check) as profile:
            self.assertEqual(profile.path, self.profile_path(enrollment))
            self.assertTrue(os.path.samestat(profile.path.stat(), os.fstat(profile.fd)))
            profile.bind_subject(FAKE_REFRESHED, FAKE_SUBJECT)
        return check, credential

    def test_refresh_is_bound_to_the_live_cold_profile(self):
        enrolled = self.journal.begin(BUILD)
        with self.journal.enrollment_profile(enrolled) as initial:
            with self.assertRaises(registration.RegistrationUnavailable):
                initial.refresh_form(refresh_form())
            initial.bind_subject(FAKE_BEARER, FAKE_SUBJECT)
            self.fake_credential(initial.path).write_bytes(cold_credential())
        record_enrollment_retired(self.journal, enrolled)
        check = self.journal.begin_cold_check(enrolled)
        with self.journal.cold_profile(check) as reopened:
            with self.assertRaises(OAuthExchangeError):
                reopened.refresh_form(refresh_form(refresh_token="different-token"))
            self.assertEqual(reopened.refresh_form(refresh_form()), refresh_form())
        with self.assertRaises(registration.RegistrationUnavailable):
            reopened.refresh_form(refresh_form())

    def test_pending_is_durable_before_single_start_and_status_ignores_environment(self):
        with patch.dict(os.environ, {"HOME": "/fake-home", "XDG_STATE_HOME": "/fake-state"}):
            self.assertIsNone(self.journal.status())
            self.assertFalse(self.root.exists())
            enrolled = self.journal.begin(BUILD)
            self.assertEqual(self.journal.status().phase, registration.Phase.PENDING)
        record = json.loads(self.receipt.read_text())
        self.assertEqual(record["phase"], "pending")
        self.assertEqual(record["enrollment"]["generation"], enrolled.generation)
        with self.journal.enrollment_profile(enrolled) as profile:
            self.assertEqual(json.loads(self.receipt.read_text())["phase"], "enrolling")
            self.assertEqual(list(profile.path.iterdir()), [])
            self.assertEqual(profile.path.parent, self.root / "profiles")
        with self.assertRaises(registration.RegistrationUnavailable):
            with self.journal.enrollment_profile(enrolled):
                self.fail("enrollment started twice")
        with self.assertRaises(registration.RegistrationUnavailable):
            self.journal.begin(BUILD)
        for path in (self.root, self.slot, self.profile_path(enrolled)):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        for path in (self.lock, self.receipt):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_cold_retirement_observation_is_bound_to_exact_redacted_check(self):
        check, credential = self.checked()
        blank = registration.ColdObservation(check, False, 0, True)
        for invalid in (blank, replace(blank, authenticated_metadata=True, native_retired=False),
                        replace(blank, authenticated_metadata=True, prompt_count=1),
                        replace(blank, authenticated_metadata=True, prompt_count=False),
                        replace(blank, authenticated_metadata=True, check=replace(check, nonce="b" * 32))):
            with self.subTest(invalid=invalid), self.assertRaises(registration.RegistrationUnavailable):
                record_cold_observation(self.journal, check, invalid)
        self.assertEqual(self.journal.status().phase, registration.Phase.COLD_CHECKING)
        proof = replace(blank, authenticated_metadata=True)
        status = record_cold_observation(self.journal, check, proof)
        self.assertEqual(status.phase, registration.Phase.COLD_RETIREMENT_OBSERVED)
        self.assertEqual(json.loads(self.receipt.read_text())["phase"], "cold-retirement-observed")
        self.assertEqual(registration.RegistrationJournal(LABEL).status(), status)
        self.assertEqual(credential.read_bytes(), FAKE_CREDENTIAL)
        self.assertNotIn(FAKE_CREDENTIAL, self.receipt.read_bytes())
        self.assertNotIn(check.nonce.encode(), self.receipt.read_bytes())
        with self.assertRaises(registration.RegistrationUnavailable):
            record_cold_observation(self.journal, check, proof)

    def test_wrong_generation_and_unstarted_cold_check_cannot_record_observation(self):
        enrollment, _ = self.enroll()
        with self.assertRaises(registration.RegistrationUnavailable):
            self.journal.begin_cold_check(replace(enrollment, generation="b" * 32))
        check = self.journal.begin_cold_check(enrollment)
        proof = registration.ColdObservation(check, True, 0, True)
        with self.assertRaises(registration.RegistrationUnavailable):
            record_cold_observation(self.journal, check, proof)
        with self.assertRaises(registration.RegistrationUnavailable):
            with self.journal.cold_profile(replace(check, nonce="c" * 32)):
                self.fail("stale cold check started")
        with self.journal.cold_profile(check):
            pass
        with self.assertRaises(registration.RegistrationUnavailable):
            with self.journal.cold_profile(check):
                self.fail("cold check started twice")

    def test_token_symlink_permissions_and_hardlink_refused(self):
        enrollment = self.journal.begin(BUILD)
        with self.journal.enrollment_profile(enrollment) as profile:
            profile.bind_subject(FAKE_BEARER, FAKE_SUBJECT)
            other = self.fake_credential(profile.path, name="other.json")
            token = other.with_name("acp_token.json")
            token.symlink_to(other.name)
        with self.assertRaises(registration.RegistrationUnavailable):
            record_enrollment_retired(self.journal, enrollment)
        token.unlink()
        os.link(other, token)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "credential file"):
            record_enrollment_retired(self.journal, enrollment)
        token.unlink()
        other.rename(token)
        token.chmod(0o640)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "credential file"):
            record_enrollment_retired(self.journal, enrollment)
        self.assertEqual(self.journal.status().phase, registration.Phase.ENROLLING)
        token.chmod(0o600)
        record_enrollment_retired(self.journal, enrollment)
        self.assertEqual(self.journal.begin_cold_check(enrollment).credential_identity,
                         registration.FileIdentity.of(token.stat()))

    @staticmethod
    def replace_private_file(path):
        replacement = path.with_name("replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(path)

    def test_token_inode_swapped_after_retirement_cannot_start_cold_check(self):
        enrollment, credential = self.enroll()
        self.replace_private_file(credential)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "exact Google credential"):
            self.journal.begin_cold_check(enrollment)
        self.assertEqual(json.loads(self.receipt.read_text())["phase"], "enrollment-retired")

    def test_token_swapped_during_cold_launch_publication_withholds_profile(self):
        enrollment, credential = self.enroll()
        check = self.journal.begin_cold_check(enrollment)
        real_sync = os.fsync

        def swap_during_sync(fd):
            if (os.path.samestat(self.slot.stat(), os.fstat(fd))
                    and json.loads(self.receipt.read_text())["phase"] == "cold-checking"):
                self.replace_private_file(credential)
            return real_sync(fd)

        with patch.object(registration.os, "fsync", side_effect=swap_during_sync):
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "exact Google credential"):
                with self.journal.cold_profile(check):
                    pass
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "interrupted write"):
            self.journal.status()

    def test_key_swapped_during_final_observation_latch_sync_reblocks_slot(self):
        check, _ = self.checked()
        key = self.slot / f"subject-{check.enrollment.generation}.key"
        real_sync = os.fsync

        def swap_during_sync(fd):
            if (os.path.samestat(self.lock.stat(), os.fstat(fd)) and os.pread(fd, 1, 0) == b""
                    and json.loads(self.receipt.read_text())["phase"] == "cold-retirement-observed"):
                self.replace_private_file(key)
            return real_sync(fd)

        with patch.object(registration.os, "fsync", side_effect=swap_during_sync):
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "exact Google subject key"):
                record_cold_observation(self.journal, check, registration.ColdObservation(check, True, 0, True))
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "interrupted write"):
            self.journal.status()

    def test_credential_inode_replacement_blocks_cold_observation(self):
        check, credential = self.checked()
        replacement = credential.with_name("replacement")
        replacement.write_bytes(FAKE_CREDENTIAL)
        replacement.chmod(0o600)
        replacement.replace(credential)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "exact Google credential"):
            record_cold_observation(self.journal, check, registration.ColdObservation(check, True, 0, True))
        self.assertEqual(json.loads(self.receipt.read_text())["phase"], "cold-checking")

    def test_profile_and_lock_replacement_fail_closed(self):
        enrolled = self.journal.begin(BUILD)
        profile = self.profile_path(enrolled)
        retired = profile.with_name("old")
        profile.rename(retired)
        profile.mkdir(mode=0o700)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "exact Google profile"):
            self.journal.status()
        profile.rmdir()
        retired.rename(profile)
        self.lock.rename(self.lock.with_name("previous.lock"))
        self.lock.touch(mode=0o600)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "registration identity"):
            self.journal.status()

    def test_slot_with_missing_or_duplicate_receipt_cannot_bootstrap(self):
        self.journal.begin(BUILD)
        raw = self.receipt.read_bytes().replace(b'"version":1', b'"version":1,"version":1')
        self.receipt.write_bytes(raw)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "invalid Google registration receipt"):
            self.journal.status()
        self.receipt.unlink()
        with self.assertRaises(registration.RegistrationUnavailable):
            self.journal.status()
        with self.assertRaises(registration.RegistrationUnavailable):
            self.journal.begin(BUILD)

    def test_nonblocking_contended_lock_leaves_record_pending(self):
        self.journal.begin(BUILD)
        with self.lock.open("rb") as competitor:
            fcntl.flock(competitor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            started = time.monotonic()
            with patch.object(registration, "_LOCK_TIME", .04):
                with self.assertRaisesRegex(registration.RegistrationUnavailable, "busy"):
                    self.journal.status()
            self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(self.journal.status().phase, registration.Phase.PENDING)

    def test_uncertain_parent_sync_keeps_blocking_receipt_across_new_instance(self):
        check, _ = self.checked()
        real_sync = os.fsync

        def torn(fd):
            if os.path.samestat(self.slot.stat(), os.fstat(fd)):
                raise OSError(errno.EIO, "synthetic parent sync failure")
            return real_sync(fd)

        with patch.object(registration.os, "fsync", side_effect=torn):
            with self.assertRaises(registration.RegistrationUnavailable):
                record_cold_observation(self.journal, check, registration.ColdObservation(check, True, 0, True))
        self.assertEqual(self.lock.read_bytes(), b"!")
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "inspection after an interrupted write"):
            registration.RegistrationJournal(LABEL).status()

    def test_uncertain_latch_clear_fsync_keeps_fresh_open_blocked(self):
        check, _ = self.checked()
        real_sync = os.fsync

        def fail_clear(fd):
            if os.path.samestat(self.lock.stat(), os.fstat(fd)) and os.pread(fd, 1, 0) == b"":
                raise OSError(errno.EIO, "synthetic latch clear sync failure")
            return real_sync(fd)

        with patch.object(registration.os, "fsync", side_effect=fail_clear):
            with self.assertRaises(registration.RegistrationUnavailable):
                record_cold_observation(self.journal, check, registration.ColdObservation(check, True, 0, True))
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "inspection after an interrupted write"):
            registration.RegistrationJournal(LABEL).status()

    def test_failed_latch_restore_parks_exact_lock_instead_of_reopening_slot(self):
        check, _ = self.checked()
        real_sync, real_write = os.fsync, os.pwrite
        lock_info = self.lock.stat()
        failed_clear = False

        def fail_clear(fd):
            nonlocal failed_clear
            if os.path.samestat(lock_info, os.fstat(fd)) and os.pread(fd, 1, 0) == b"":
                failed_clear = True
                raise OSError(errno.EIO, "synthetic latch clear sync failure")
            return real_sync(fd)

        def fail_restore(fd, data, offset):
            if failed_clear and os.path.samestat(lock_info, os.fstat(fd)):
                raise OSError(errno.EIO, "synthetic latch restore failure")
            return real_write(fd, data, offset)

        with (patch.object(registration.os, "fsync", side_effect=fail_clear),
              patch.object(registration.os, "pwrite", side_effect=fail_restore)):
            with self.assertRaises(registration.RegistrationUnavailable):
                record_cold_observation(self.journal, check, registration.ColdObservation(check, True, 0, True))
        self.assertFalse(self.lock.exists())
        parked, = self.slot.glob(".registration-held-*")
        self.assertTrue(os.path.samestat(lock_info, parked.stat()))
        with self.assertRaises(registration.RegistrationUnavailable):
            registration.RegistrationJournal(LABEL).status()

    def test_generation_key_and_digest_are_private_and_independent(self):
        first = self.journal.begin(BUILD)
        other = registration.RegistrationJournal("second")
        second = other.begin(BUILD)
        keys = [self.slot / f"subject-{first.generation}.key",
                self.slot.with_name("second") / f"subject-{second.generation}.key"]
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 and path.stat().st_nlink == 1 for path in keys))
        self.assertNotEqual(keys[0].read_bytes(), keys[1].read_bytes())
        self.assertEqual([len(path.read_bytes()) for path in keys], [32, 32])
        self.assertEqual(registration.FileIdentity.of(keys[0].stat()), first.subject_key_identity)
        with self.journal.enrollment_profile(first) as profile:
            self.assertFalse(keys[0].is_relative_to(profile.path))
            proof = profile.bind_subject(FAKE_BEARER, FAKE_SUBJECT)
            proof.require_metadata_bearer(account_binding.MetadataOperation.LOAD_CODE_ASSIST, FAKE_BEARER)
        with other.enrollment_profile(second) as profile:
            other_proof = profile.bind_subject(FAKE_BEARER, FAKE_SUBJECT)
        self.assertNotEqual(proof.digest, other_proof.digest)
        raw = self.receipt.read_bytes()
        self.assertEqual(json.loads(raw)["subject_digest"], proof.digest.hex())
        self.assertNotIn(keys[0].read_bytes(), raw)
        self.assertNotIn(b"408903144981226013344", raw)
        self.assertNotIn(FAKE_BEARER, raw)

    def test_subject_bind_is_one_shot_after_refusal_or_profile_exit(self):
        enrollment = self.journal.begin(BUILD)
        with self.journal.enrollment_profile(enrollment) as profile:
            with self.assertRaises(account_binding.AccountBindingError):
                profile.bind_subject(FAKE_BEARER, b"not a subject")
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "already spent"):
                profile.bind_subject(FAKE_BEARER, FAKE_SUBJECT)
            self.fake_credential(profile.path)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "already spent"):
            profile.bind_subject(FAKE_BEARER, FAKE_SUBJECT)
        self.assertIsNone(json.loads(self.receipt.read_text())["subject_digest"])
        record_enrollment_retired(self.journal, enrollment)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "no subject binding"):
            self.journal.begin_cold_check(enrollment)

    def test_enrollment_profile_replacement_during_bind_cannot_persist_digest(self):
        enrollment = self.journal.begin(BUILD)
        real_bind = account_binding.bind_subject

        def swapped(*args):
            profile.path.rename(profile.path.with_name("displaced"))
            profile.path.mkdir(mode=0o700)
            return real_bind(*args)

        with self.journal.enrollment_profile(enrollment) as profile, patch.object(registration, "bind_subject", swapped):
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "directory changed"):
                profile.bind_subject(FAKE_BEARER, FAKE_SUBJECT)
        self.assertIsNone(json.loads(self.receipt.read_text())["subject_digest"])

    def test_same_cold_subject_gets_new_phase_proof_only_once(self):
        enrollment, _ = self.enroll()
        original = json.loads(self.receipt.read_text())["subject_digest"]
        check = registration.RegistrationJournal(LABEL).begin_cold_check(enrollment)
        with self.journal.cold_profile(check) as profile:
            proof = profile.bind_subject(FAKE_REFRESHED, FAKE_SUBJECT)
            proof.require_metadata_bearer(account_binding.MetadataOperation.FETCH_AVAILABLE_MODELS, FAKE_REFRESHED)
            with self.assertRaises(account_binding.AccountBindingError):
                proof.require_metadata_bearer(account_binding.MetadataOperation.FETCH_AVAILABLE_MODELS, FAKE_BEARER)
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "already spent"):
                profile.bind_subject(FAKE_REFRESHED, FAKE_SUBJECT)
        observed = record_cold_observation(self.journal, check, registration.ColdObservation(check, True, 0, True))
        self.assertEqual(observed.phase, registration.Phase.COLD_RETIREMENT_OBSERVED)
        self.assertEqual(json.loads(self.receipt.read_text())["subject_digest"], original)

    def test_wrong_cold_subject_cannot_be_retried_or_reported_as_observed(self):
        enrollment, _ = self.enroll()
        check = self.journal.begin_cold_check(enrollment)
        with self.journal.cold_profile(check) as profile:
            with self.assertRaises(account_binding.AccountBindingError):
                profile.bind_subject(FAKE_REFRESHED, b'{"id":"123456"}')
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "already spent"):
                profile.bind_subject(FAKE_REFRESHED, FAKE_SUBJECT)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "no subject observation"):
            record_cold_observation(self.journal, check, registration.ColdObservation(check, True, 0, True))

    def test_subject_key_replacement_and_hardlink_fail_closed(self):
        enrollment, _ = self.enroll()
        key = self.slot / f"subject-{enrollment.generation}.key"
        original = key.with_name("saved.subject")
        os.link(key, original)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "subject key changed"):
            self.journal.begin_cold_check(enrollment)
        original.unlink()
        key.rename(original)
        key.write_bytes(original.read_bytes())
        key.chmod(0o600)
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "subject key changed"):
            self.journal.begin_cold_check(enrollment)

    def test_metadata_spends_persist_exact_phase_prefix_before_each_send(self):
        enrollment = self.journal.begin(BUILD)
        routes = (MetadataRoute.TOKEN, MetadataRoute.USERINFO, MetadataRoute.LOAD_CODE_ASSIST)
        writes = []

        def exercise(profile, phase_routes, counter, bearer):
            for index, route in enumerate(phase_routes, 1):
                def send():
                    pending = json.loads(self.receipt.read_text())
                    self.assertTrue(pending["metadata_pending"])
                    self.assertEqual(pending[counter], index)
                    writes.append(route)
                profile.spend_metadata(route, send, authorized=lambda: True)
                held = json.loads(self.receipt.read_text())
                self.assertFalse(held["metadata_pending"])
                self.assertEqual(held[counter], index)
                if route is MetadataRoute.USERINFO:
                    profile.bind_subject(bearer, FAKE_SUBJECT)

        def refuse(profile, route):
            with self.assertRaises(registration.RegistrationUnavailable):
                profile.spend_metadata(route, lambda: writes.append("unexpected"), authorized=lambda: True)

        with self.journal.enrollment_profile(enrollment) as profile:
            refuse(profile, MetadataRoute.USERINFO)
            refuse(profile, "generation")
            self.assertEqual(json.loads(self.receipt.read_text())["enrollment_metadata_spent"], 0)
            exercise(profile, routes, "enrollment_metadata_spent", FAKE_BEARER)
            refuse(profile, MetadataRoute.TOKEN)
            refuse(profile, MetadataRoute.FETCH_AVAILABLE_MODELS)
            self.fake_credential(profile.path)
        refuse(profile, MetadataRoute.TOKEN)
        record_enrollment_retired(self.journal, enrollment)
        check = self.journal.begin_cold_check(enrollment)
        cold_routes = (*routes, MetadataRoute.FETCH_AVAILABLE_MODELS)
        with self.journal.cold_profile(check) as cold:
            refuse(cold, MetadataRoute.LOAD_CODE_ASSIST)
            exercise(cold, cold_routes, "cold_metadata_spent", FAKE_REFRESHED)
            refuse(cold, MetadataRoute.FETCH_AVAILABLE_MODELS)
        refuse(cold, MetadataRoute.TOKEN)
        self.assertEqual(writes, [*routes, *cold_routes])
        observed = record_cold_observation(self.journal, check, registration.ColdObservation(check, True, 0, True))
        self.assertEqual(observed.phase, registration.Phase.COLD_RETIREMENT_OBSERVED)
        saved = json.loads(self.receipt.read_text())
        self.assertEqual((saved["enrollment_metadata_spent"], saved["cold_metadata_spent"]), (3, 4))
        self.assertFalse(saved["metadata_pending"])

    def test_authority_loss_after_reservation_persists_hold_and_sends_zero(self):
        enrollment = self.journal.begin(BUILD)
        writes = []
        with self.journal.enrollment_profile(enrollment) as profile:
            self.fake_credential(profile.path)
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "authority"):
                profile.spend_metadata(MetadataRoute.TOKEN, lambda: writes.append("pre-cancel"),
                                       authorized=lambda: False)
            self.assertEqual(json.loads(self.receipt.read_text())["enrollment_metadata_spent"], 0)
            checks = iter((True, False))
            with self.assertRaisesRegex(registration.RegistrationUnavailable, "authority"):
                profile.spend_metadata(MetadataRoute.TOKEN, lambda: writes.append("unexpected"),
                                       authorized=lambda: next(checks))
            saved = json.loads(self.receipt.read_text())
            self.assertEqual(saved["enrollment_metadata_spent"], 1)
            self.assertTrue(saved["metadata_pending"])
            with self.assertRaises(registration.RegistrationUnavailable):
                profile.spend_metadata(MetadataRoute.USERINFO, lambda: writes.append("retry"), authorized=lambda: True)
        self.assertEqual(writes, [])
        with self.assertRaises(registration.RegistrationUnavailable):
            record_enrollment_retired(registration.RegistrationJournal(LABEL), enrollment)

    def test_authority_loss_during_each_settlement_sync_persists_hold(self):
        for window in ("temporary", "directory", "latch"):
            with self.subTest(window=window):
                journal = registration.RegistrationJournal(window)
                enrollment = journal.begin(BUILD)
                directory = self.slot.with_name(window)
                lock = directory / "registration.lock"
                lock_identity = lock.stat()
                real_sync = os.fsync
                writes = []
                authorized = True

                def lose_during_sync(fd):
                    nonlocal authorized
                    if writes:
                        info = os.fstat(fd)
                        is_target = (
                            (window == "temporary"
                             and Path(os.readlink(f"/proc/self/fd/{fd}")).name.startswith(".registration-"))
                            or (window == "directory" and os.path.samestat(directory.stat(), info))
                            or (window == "latch" and os.path.samestat(lock_identity, info) and not os.pread(fd, 1, 0))
                        )
                        if is_target:
                            authorized = False
                    return real_sync(fd)

                with journal.enrollment_profile(enrollment) as profile:
                    with (patch.object(registration.os, "fsync", side_effect=lose_during_sync),
                          self.assertRaisesRegex(registration.RegistrationUnavailable, "authority")):
                        profile.spend_metadata(MetadataRoute.TOKEN, lambda: writes.append("one"),
                                               authorized=lambda: authorized)
                    with self.assertRaises(registration.RegistrationUnavailable):
                        profile.spend_metadata(MetadataRoute.USERINFO, lambda: self.fail("wrote after lost authority"),
                                               authorized=lambda: True)

                self.assertEqual(writes, ["one"])
                self.assertEqual(lock.read_bytes(), b"!")
                with self.assertRaisesRegex(registration.RegistrationUnavailable, "interrupted write"):
                    registration.RegistrationJournal(window).status()

    def test_uncertain_send_return_consumes_and_blocks_additional_routes(self):
        for label, outcome in (("raised", OSError("synthetic short write")), ("short", 1)):
            with self.subTest(label=label):
                journal = registration.RegistrationJournal(label)
                enrollment = journal.begin(BUILD)
                calls = []

                def send():
                    calls.append(label)
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                with journal.enrollment_profile(enrollment) as profile:
                    with self.assertRaisesRegex(registration.RegistrationUnavailable, "write is unsettled"):
                        profile.spend_metadata(MetadataRoute.TOKEN, send, authorized=lambda: True)
                    with self.assertRaises(registration.RegistrationUnavailable):
                        profile.spend_metadata(MetadataRoute.TOKEN, send, authorized=lambda: True)
                    with self.assertRaises(registration.RegistrationUnavailable):
                        profile.bind_subject(FAKE_BEARER, FAKE_SUBJECT)
                self.assertEqual(calls, [label])
                saved = json.loads((self.slot.with_name(label) / "registration.json").read_text())
                self.assertEqual(saved["enrollment_metadata_spent"], 1)
                self.assertTrue(saved["metadata_pending"])

    def test_reentrant_callback_cannot_spend_or_bind_again(self):
        enrollment = self.journal.begin(BUILD)
        with self.journal.enrollment_profile(enrollment) as profile:
            def send():
                with self.assertRaises(registration.RegistrationUnavailable):
                    profile.spend_metadata(MetadataRoute.TOKEN, lambda: self.fail("reentrant write"),
                                           authorized=lambda: True)
                with self.assertRaises(registration.RegistrationUnavailable):
                    profile.bind_subject(FAKE_BEARER, FAKE_SUBJECT)

            profile.spend_metadata(MetadataRoute.TOKEN, send, authorized=lambda: True)
        saved = json.loads(self.receipt.read_text())
        self.assertEqual(saved["enrollment_metadata_spent"], 1)
        self.assertFalse(saved["metadata_pending"])

    def test_token_swap_during_cold_spend_keeps_hold_and_sends_zero(self):
        enrollment, credential = self.enroll()
        check = self.journal.begin_cold_check(enrollment)
        real_sync = os.fsync

        def swap_pending(fd):
            if (os.path.samestat(self.slot.stat(), os.fstat(fd))
                    and json.loads(self.receipt.read_text())["metadata_pending"]):
                self.replace_private_file(credential)
            return real_sync(fd)

        with self.journal.cold_profile(check) as profile:
            with (patch.object(registration.os, "fsync", side_effect=swap_pending),
                  self.assertRaisesRegex(registration.RegistrationUnavailable, "exact Google credential")):
                profile.spend_metadata(MetadataRoute.TOKEN, lambda: self.fail("wrote after identity changed"),
                                       authorized=lambda: True)
        saved = json.loads(self.receipt.read_text())
        self.assertEqual(saved["cold_metadata_spent"], 1)
        self.assertTrue(saved["metadata_pending"])
        with self.assertRaisesRegex(registration.RegistrationUnavailable, "interrupted write"):
            registration.RegistrationJournal(LABEL).status()

    def test_canonical_state_never_follows_a_profile_or_state_symlink(self):
        someplace = self.home / "other-state"
        someplace.mkdir()
        (self.home / ".local").symlink_to(someplace, target_is_directory=True)
        with self.assertRaises(registration.RegistrationUnavailable):
            self.journal.begin(BUILD)
        self.assertEqual(list(someplace.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
