from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
import errno
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import Mock, patch

import acp_readiness as acp
from oc_providers import ReadinessState as State


PROFILE_REJECTED = "rejected its private profile"


def _pidfd_ready(fd, timeout):
    with selectors.DefaultSelector() as io:
        io.register(fd, selectors.EVENT_READ)
        return bool(io.select(timeout))


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
        with self.assertRaisesRegex(acp.IntegrityError, PROFILE_REJECTED):
            self.probe()
        self.profile.write_text("{broken")
        with self.assertRaisesRegex(acp.IntegrityError, PROFILE_REJECTED):
            self.probe()
        self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.NEEDS_VERIFY))

    def test_foreign_credential_with_matching_profile_metadata_is_rejected(self):
        self.assertIs(self.probe(), State.READY)
        with TemporaryDirectory() as other:
            other_generation = acp.enroll_fixture(other)
            self.assertIs(acp.probe_fixture(other, other_generation), State.READY)
            other_credential = json.loads((Path(other) / acp.PROFILE).read_text())["credential"]

        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(acp.PROFILE, os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory)
        finally:
            os.close(directory)
        with os.fdopen(fd, "r+", encoding="ascii") as fixture:
            original = fixture.read()
            profile = json.loads(original)
            fixture.seek(0)
            json.dump({**profile, "credential": other_credential}, fixture)
            fixture.truncate()
            fixture.flush()
            with self.assertRaisesRegex(acp.IntegrityError, PROFILE_REJECTED):
                self.probe()
            self.assertEqual(acp.read_status(self.root), acp.Record(self.generation, State.NEEDS_VERIFY))
            fixture.seek(0)
            fixture.write(original)
            fixture.truncate()
        self.assertIs(self.probe(), State.READY)

    def test_valid_profile_requires_independent_verifier_record(self):
        verifier = self.root / acp.VERIFIER
        self.assertNotIn(json.loads(self.profile.read_text())["credential"], verifier.read_text())
        self.assertEqual(verifier.stat().st_mode & 0o777, 0o600)
        verifier.unlink()
        with self.assertRaisesRegex(acp.IntegrityError, PROFILE_REJECTED):
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
                workspace = Path(scratch)
                process = subprocess.Popen(args, cwd=scratch, env={"HOME": "/nonexistent", "LANG": "C.UTF-8"},
                                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                           bufsize=0, start_new_session=True)
                with acp._owned_pidfd(process) as pidfd:
                    try:
                        with self.assertRaisesRegex(acp.IntegrityError, PROFILE_REJECTED):
                            acp._transcript(process, pidfd, workspace, 2)
                    finally:
                        self.assertTrue(acp._retire(process, pidfd))

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

        def unconfirmed(process, pidfd):
            self.assertTrue(retire(process, pidfd))
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

    def test_timeout_surfaces_unconfirmed_retirement_with_cause_and_blocks_retry(self):
        retire = acp._retire

        def unconfirmed(process, pidfd):
            self.assertTrue(retire(process, pidfd))
            return False

        with (patch.object(acp, "_retire", side_effect=unconfirmed),
              self.assertRaises(acp.RetirementUnconfirmed) as error):
            self.probe("timeout", timeout=.25)
        self.assertIsInstance(error.exception.__cause__, acp.ProtocolError)
        self.assertIn("deadline expired", str(error.exception.__cause__))
        retained = acp.read_status(self.root)
        self.assertIs(retained.readiness, State.REVOCATION_UNCONFIRMED)
        with patch.object(acp.subprocess, "Popen") as launch:
            self.assertIs(self.probe(), State.REVOCATION_UNCONFIRMED)
            launch.assert_not_called()

    def test_peer_created_workspace_file_prevents_publication(self):
        original = self.journal.read_bytes()
        with self.assertRaises(acp.IntegrityError) as error:
            self.probe("dirty-workspace")
        self.assertEqual(self.journal.read_bytes(), original)
        self.assertIn("workspace is not empty", str(error.exception))
        retained = acp.read_status(self.root)
        self.assertIs(retained.readiness, State.REVOCATION_UNCONFIRMED)
        self.assertTrue((self.root / retained.check / "peer-created").is_file())

    def test_pipe_close_failure_does_not_escape_retirement(self):
        process = Mock()
        process.stdin.close.side_effect = OSError
        with patch.object(acp, "_retire_group", return_value=False):
            self.assertFalse(acp._retire(process, 0))
        process.stdout.close.assert_called_once_with()

    def test_automatic_reaping_refuses_group_signals_for_owned_child(self):
        process = subprocess.Popen([sys.executable, "-IBS", "-c", "import sys; sys.stdin.read()"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True, bufsize=0)
        with acp._owned_pidfd(process) as pidfd:
            try:
                previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
                try:
                    with (patch.object(os, "killpg") as numeric,
                          patch.object(signal, "pidfd_send_signal") as stable):
                        self.assertFalse(acp._retire_group(process, pidfd))
                        numeric.assert_not_called()
                        stable.assert_not_called()
                finally:
                    signal.signal(signal.SIGCHLD, previous)
            finally:
                self.assertTrue(acp._retire(process, pidfd))

    def test_unavailable_pidfd_group_flag_stops_before_transcript(self):
        popen = acp.subprocess.Popen
        launched = []

        def capture(*args, **kwargs):
            process = popen(*args, **kwargs)
            launched.append(process)
            return process

        unsupported = OSError(errno.EINVAL, "group flag unavailable")
        with (patch.object(acp.subprocess, "Popen", side_effect=capture),
              patch.object(signal, "pidfd_send_signal", side_effect=unsupported) as group_signal,
              patch.object(acp, "_transcript") as transcript):
            self.assertIs(self.probe(), State.REVOCATION_UNCONFIRMED)
            transcript.assert_not_called()
        self.assertEqual(len(launched), 1)
        self.assertEqual(group_signal.call_count, 1)
        self.assertIsNotNone(launched[0].returncode)
        self.assertTrue(launched[0].stdin.closed)
        self.assertTrue(launched[0].stdout.closed)
        self.assertIs(acp.read_status(self.root).readiness, State.REVOCATION_UNCONFIRMED)

    def test_finish_leaves_group_leader_unreaped_for_owned_descendant_retirement(self):
        script = (
            "import subprocess, sys\n"
            "child = subprocess.Popen([sys.executable, '-IBS', '-c', 'import time; time.sleep(30)'], "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "print(child.pid, flush=True)\n"
            "sys.stdin.buffer.read()\n"
        )
        process = subprocess.Popen([sys.executable, "-IBS", "-c", script], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
                                   env={}, bufsize=0)
        with acp._owned_pidfd(process) as pidfd, selectors.DefaultSelector() as io:
            deadline = time.monotonic() + 2
            channel = acp._Channel(process, pidfd, io, deadline)
            descendant = int(channel._read())
            descendant_fd = os.pidfd_open(descendant)
            try:
                channel.finish()
                self.assertIsNone(process.returncode)
                self.assertFalse(_pidfd_ready(descendant_fd, 0))
                self.assertTrue(acp._retire(process, pidfd))
                self.assertTrue(_pidfd_ready(descendant_fd, 1))
                self.assertIsNotNone(process.returncode)
            finally:
                with suppress(ProcessLookupError):
                    signal.pidfd_send_signal(descendant_fd, signal.SIGKILL)
                os.close(descendant_fd)
                if process.returncode is None:
                    acp._retire(process, pidfd)

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
        self.assertTrue((self.root / acp.RECEIPT).is_file())
        self.assertFalse((self.root / retained.check).exists())
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
