from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import acp_readiness as acp
from oc_providers import ReadinessState as State


class SyntheticReadinessTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.journal = self.root / acp.JOURNAL
        self.profile = self.root / acp.PROFILE
        self.generation = acp.enroll_fixture(self.root)

    def probe(self, scene="ready", **kwargs):
        return acp.probe_fixture(self.root, self.generation, scene, **kwargs)

    def test_enrollment_requires_fresh_readiness(self):
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.NEEDS_VERIFY))
        with patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "synthetic-private-socket"}):
            self.assertIs(self.probe("split"), State.READY)
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.READY))
        journal = self.journal.read_text()
        self.assertNotIn("synthetic-private-session", journal)
        self.assertNotIn(json.loads(self.profile.read_text())["credential"], journal)
        self.assertEqual(self.profile.stat().st_mode & 0o777, 0o600)
        self.assert_scratch_clean()

    def assert_scratch_clean(self):
        self.assertEqual({item.name for item in self.root.iterdir()},
                         {acp.JOURNAL, acp.PROFILE, acp.VERIFIER, "readiness.lock", acp.ENROLLMENT_LOCK})

    def test_signed_out_and_expired_have_distinct_readiness(self):
        with TemporaryDirectory() as root:
            generation = acp.enroll_fixture(root, expires_at=0)
            self.assertIs(acp.probe_fixture(root, generation), State.NEEDS_VERIFY)
            self.assertEqual(acp.read_status(root), acp.Record(generation, State.NEEDS_VERIFY))
        self.profile.unlink()
        self.assertIs(self.probe(), State.DISCONNECTED)
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.DISCONNECTED))
        self.assertIs(self.probe("split"), State.DISCONNECTED)

    def test_wrong_or_corrupt_private_profile_cannot_publish_ready(self):
        with TemporaryDirectory() as other:
            acp.enroll_fixture(other)
            self.profile.write_bytes((Path(other) / acp.PROFILE).read_bytes())
        with self.assertRaisesRegex(acp.IntegrityError, "rejected its private profile"):
            self.probe()
        self.profile.write_text("{broken")
        with self.assertRaisesRegex(acp.IntegrityError, "rejected its private profile"):
            self.probe()
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.NEEDS_VERIFY))

    def test_foreign_credential_with_matching_profile_metadata_is_rejected(self):
        original = self.profile.read_text()
        profile = json.loads(original)
        self.assertIs(self.probe(), State.READY)
        with TemporaryDirectory() as other:
            other_generation = acp.enroll_fixture(other)
            self.assertIs(acp.probe_fixture(other, other_generation), State.READY)
            other_credential = json.loads((Path(other) / acp.PROFILE).read_text())["credential"]

        self.profile.write_text(json.dumps({**profile, "credential": other_credential}))
        with self.assertRaisesRegex(acp.IntegrityError, "rejected its private profile"):
            self.probe()
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.NEEDS_VERIFY))
        self.profile.write_text(original)
        self.assertIs(self.probe(), State.READY)

    def test_valid_profile_requires_independent_verifier_record(self):
        verifier = self.root / acp.VERIFIER
        self.assertNotIn(json.loads(self.profile.read_text())["credential"], verifier.read_text())
        self.assertEqual(verifier.stat().st_mode & 0o777, 0o600)
        verifier.unlink()
        with self.assertRaisesRegex(acp.IntegrityError, "rejected its private profile"):
            self.probe()
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.NEEDS_VERIFY))

    def test_open_enrollment_handle_prevents_launch_until_closed(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)
            with acp.enrollment_fixture(root) as generation:
                with patch.object(acp.subprocess, "Popen") as launch:
                    self.assertIs(acp.probe_fixture(root, generation), State.NEEDS_VERIFY)
                    launch.assert_not_called()
                self.assertFalse((root / acp.PROFILE).exists())
            self.assertTrue((root / acp.PROFILE).is_file())
            self.assertIs(acp.probe_fixture(root, generation), State.READY)

    def test_fresh_peer_independently_requires_a_closed_enrollment_handle(self):
        with acp._locked(self.root) as directory:
            lock = os.open(acp.ENROLLMENT_LOCK, os.O_RDWR, dir_fd=directory)
            self.addCleanup(os.close, lock)
            acp.fcntl.flock(lock, acp.fcntl.LOCK_EX | acp.fcntl.LOCK_NB)
            with TemporaryDirectory(dir=self.root) as scratch:
                args = [sys.executable, "-IBS", str(acp.FIXTURE), "ready", str(self.root), self.generation]
                process = subprocess.Popen(args, cwd=scratch, env={"HOME": "/nonexistent", "LANG": "C.UTF-8"},
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                           bufsize=0)
                try:
                    with self.assertRaisesRegex(acp.IntegrityError, "rejected its private profile"):
                        acp._transcript(process, Path(scratch), 2)
                finally:
                    self.assertTrue(acp._retire(process))

    def test_bad_transcript_never_publishes_readiness_or_retains_raw_output(self):
        self.assertIs(self.probe(), State.READY)
        for scene in ("wrong-id", "wrong-version", "duplicate", "malformed", "empty-session", "truncated",
                      "oversized", "unsolicited", "trailing", "bad-exit", "timeout"):
            with self.subTest(scene=scene):
                with self.assertRaisesRegex(acp.ProtocolError, "synthetic ACP") as error:
                    self.probe(scene, timeout=.25 if scene == "timeout" else 2)
                self.assertNotIn("synthetic-private-", str(error.exception))
                self.assertNotIn("synthetic-private-", self.journal.read_text())
                self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.NEEDS_VERIFY))

    def test_cancel_with_confirmed_retirement_leaves_generation_unverified(self):
        with patch.object(acp, "_transcript", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            self.probe()
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.NEEDS_VERIFY))
        self.assert_scratch_clean()

    def test_unconfirmed_retirement_keeps_evidence_and_blocks_new_processes(self):
        retire = acp._retire

        def unconfirmed(process):
            self.assertTrue(retire(process))
            return False

        with patch.object(acp, "_retire", side_effect=unconfirmed):
            self.assertIs(self.probe(), State.REVOCATION_UNCONFIRMED)
        retained = acp.read_status(self.root)
        self.assertIs(retained.readiness, State.REVOCATION_UNCONFIRMED)
        self.assertEqual(retained.generation, self.generation)
        self.assertTrue((self.root / retained.check).is_dir())
        with patch.object(acp.subprocess, "Popen") as launch:
            self.assertIs(self.probe(), State.REVOCATION_UNCONFIRMED)
            with self.assertRaises(acp.IntegrityError):
                acp.enroll_fixture(self.root)
            launch.assert_not_called()
        self.assertEqual(acp.read_status(self.root), retained)

    def test_missing_process_receipt_keeps_provisional_evidence(self):
        with patch.object(acp.subprocess, "Popen", side_effect=OSError):
            self.assertIs(self.probe(), State.REVOCATION_UNCONFIRMED)
        record = acp.read_status(self.root)
        self.assertEqual(record.generation, self.generation)
        self.assertTrue((self.root / record.check).is_dir())

    def test_stale_generation_cannot_launch_or_change_record(self):
        with patch.object(acp.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(acp.IntegrityError, "generation changed"):
                acp.probe_fixture(self.root, "0" * 32)
            launch.assert_not_called()
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.NEEDS_VERIFY))

    def test_replaced_receipt_cannot_publish_a_late_success(self):
        def replace_receipt(*_args):
            self.journal.write_text(json.dumps({"generation": "0" * 32, "readiness": "needs_verify", "check": None}))
            return State.READY

        with (patch.object(acp, "_transcript", side_effect=replace_receipt),
              self.assertRaisesRegex(acp.IntegrityError, "exact synthetic readiness check changed")):
            self.probe()
        with self.assertRaisesRegex(acp.IntegrityError, "receipt does not match its journal"):
            acp.read_status(self.root)
        self.assertEqual(json.loads(self.journal.read_text())["generation"], "0" * 32)
        self.assertTrue((self.root / acp.RECEIPT).is_file())

    def test_concurrent_enrollment_cannot_start_a_second_generation(self):
        with TemporaryDirectory() as root:
            with ThreadPoolExecutor(max_workers=2) as workers:
                attempts = [workers.submit(acp.enroll_fixture, root) for _ in range(2)]
            outcomes = [result.exception() or result.result() for result in attempts]
            self.assertEqual(sum(isinstance(outcome, acp.IntegrityError) for outcome in outcomes), 1)
            self.assertIn(acp.read_status(root).generation, outcomes)

    def test_corrupt_journal_blocks_probe_and_reenrollment(self):
        bad_records = ("{", '{"generation":"first","generation":"second"}', "[]", "x" * 1025,
                       json.dumps({"generation": self.generation, "readiness": "revocation_unconfirmed", "check": None}))
        with patch.object(acp.subprocess, "Popen") as launch:
            for bad in bad_records:
                with self.subTest(bad=bad[:50]):
                    self.journal.write_text(bad)
                    with self.assertRaisesRegex(acp.IntegrityError, "corrupt synthetic readiness journal"):
                        self.probe()
                    with self.assertRaises(acp.IntegrityError):
                        acp.enroll_fixture(self.root)
                    self.assertEqual(self.journal.read_text(), bad)
            launch.assert_not_called()

    def test_unsafe_store_files_are_integrity_errors(self):
        self.journal.chmod(0o644)
        with self.assertRaisesRegex(acp.IntegrityError, "unsafe private journal file"):
            self.probe()
        self.journal.unlink()
        os.mkfifo(self.journal, 0o600)
        with self.assertRaises(acp.IntegrityError):
            self.probe()
        self.journal.unlink()
        self.journal.symlink_to("missing")
        with self.assertRaises(acp.IntegrityError):
            self.probe()

    def test_inability_to_sync_provisional_receipt_prevents_launch(self):
        with patch.object(acp.os, "fsync", side_effect=OSError), patch.object(acp.subprocess, "Popen") as launch:
            with self.assertRaises(acp.IntegrityError):
                self.probe()
            launch.assert_not_called()

    def test_inability_to_sync_final_journal_retains_fence_after_rename(self):
        fsync = os.fsync
        syncs = 0

        def fail_final_directory_sync(fd):
            nonlocal syncs
            syncs += 1
            if syncs == 4:
                raise OSError
            fsync(fd)

        with patch.object(acp.os, "fsync", side_effect=fail_final_directory_sync), self.assertRaises(acp.IntegrityError):
            self.probe()
        self.assertEqual(json.loads(self.journal.read_text())["readiness"], "ready")
        retained = acp.read_status(self.root)
        self.assertIs(retained.readiness, State.REVOCATION_UNCONFIRMED)
        self.assertTrue((self.root / retained.check).is_dir())
        with patch.object(acp.subprocess, "Popen") as launch:
            self.assertIs(self.probe(), State.REVOCATION_UNCONFIRMED)
            launch.assert_not_called()

    def test_post_unlink_sync_failure_does_not_reverse_a_durable_commit(self):
        fsync = os.fsync
        syncs = 0
        before_eviction = None

        def fail_after_unlink(fd):
            nonlocal syncs, before_eviction
            syncs += 1
            if syncs == 4:
                before_eviction = (self.root / acp.RECEIPT).read_bytes()
            if syncs == 5:
                self.assertFalse((self.root / acp.RECEIPT).exists())
                raise OSError("injected after receipt unlink")
            fsync(fd)

        with patch.object(acp.os, "fsync", side_effect=fail_after_unlink):
            self.assertIs(self.probe(), State.READY)
        self.assertEqual(syncs, 5)
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.READY))
        self.assertIs(self.probe(), State.READY)
        # A crash may restore a receipt whose removal was never synced. It remains a fence.
        fd = os.open(self.root / acp.RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(before_eviction)
        with patch.object(acp.subprocess, "Popen") as launch:
            self.assertIs(self.probe(), State.REVOCATION_UNCONFIRMED)
            launch.assert_not_called()
