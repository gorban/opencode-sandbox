from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import errno
import hashlib
from io import BytesIO
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

import acp_readiness as readiness
import acp_text_peer as peer
import acp_text_session as acp


class SyntheticTextSessionTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.generation = readiness.enroll_fixture(self.root)

    def open(self, scene="ready", **kwargs):
        return acp.open_text_session(self.root, self.generation, scene, **kwargs)

    def assert_startup_refused(self, assertion, scene="ready", **kwargs):
        context = self.open(scene, **kwargs)
        with ExitStack() as resources, assertion:
            resources.enter_context(context)

    def assert_state(self, state):
        self.assertEqual(readiness.read_status(self.root), readiness.Record(self.generation, state))
        self.assertFalse((self.root / readiness.RECEIPT).exists())
        self.assertFalse(any(item.is_dir() for item in self.root.iterdir()))

    def test_ready_and_fragmented_pair_exact_text_and_one_actual_prompt(self):
        for scene in ("ready", "split"):
            with self.subTest(scene=scene):
                with self.open(scene) as session:
                    session.send_prompt()
                    self.assertEqual(session.complete(), "ok")
                    self.assertEqual(session.prompt_count, 1)
                    self.assertIsNotNone(session.process.returncode)
                    self.assertFalse((self.root / session.attempt).exists())
                    self.assertFalse((self.root / readiness.RECEIPT).exists())
                    with self.assertRaises(acp.ProtocolError):
                        session.send_prompt()
                self.assertEqual(session.prompt_count, 1)
                self.assert_state(acp.ReadinessState.READY)

    def test_framer_preserves_fragmented_and_coalesced_frames(self):
        with self.open() as session:
            # Isolate read boundaries so the assertions are independent of kernel pipe scheduling.
            frames = [b'{"first":1}\n', b'{"second":2}\n', b'{"third":3}\n']
            reads = [frames[0][:5], frames[0][5:] + frames[1] + frames[2][:3], frames[2][3:]]
            with patch.object(acp, "_read", side_effect=reads) as read:
                deadline = time.monotonic() + 1
                self.assertEqual(session._next_frame(deadline), {"first": 1})
                self.assertEqual(session._next_frame(deadline), {"second": 2})
                self.assertEqual(read.call_count, 2)
                self.assertEqual(session._next_frame(deadline), {"third": 3})
                self.assertEqual(read.call_count, 3)
            self.assertEqual(session.buffer, b"")

    def test_never_sent_closes_and_observes_zero_prompts_even_if_cancelled(self):
        cancelled = Event()
        with self.open(cancelled=cancelled.is_set) as session:
            self.assertIsNone(session.prompt_count)
            cancelled.set()
        self.assertEqual(session.prompt_count, 0)
        self.assert_state(acp.ReadinessState.READY)

    def test_broker_revocation_retires_idle_peer_before_owner_context_exit(self):
        with self.open() as session, ThreadPoolExecutor(max_workers=1) as broker:
            broker.submit(session.retire).result(5)
            self.assertEqual(session.prompt_count, 0)
            self.assertFalse((self.root / readiness.RECEIPT).exists())
            self.assertIsNotNone(session.process.returncode)
            broker.submit(session.retire).result(5)
        self.assert_state(acp.ReadinessState.READY)

    def test_early_and_mixed_reject_despite_valid_terminal_and_one_observed_prompt(self):
        for scene in ("early", "mixed"):
            with self.subTest(scene=scene):
                with self.open(scene) as session:
                    # Startup already received the private confirmation that early text is queued.
                    self.assertFalse(session.prompt_attempted)
                    session.send_prompt()
                    with self.assertRaisesRegex(acp.ProtocolError, "post-prompt evidence"):
                        session.complete()
                    self.assertEqual(session.prompt_count, 1)
                self.assert_state(acp.ReadinessState.NEEDS_VERIFY)

    def test_permission_after_valid_text_and_other_transcript_failures_release_no_text(self):
        outcomes = {
            "permission": "response",
            "wrong-stop": "terminal result",
            "wrong-id": "response",
            "wrong-session": "session",
            "trailing": "trailing",
            "bad-exit": "cleanly",
            "over-frames": "frame count",
            "bad-receipt": "post-prompt evidence",
            "extra-receipt": "post-prompt evidence",
        }
        for scene, message in outcomes.items():
            with self.subTest(scene=scene), self.open(scene) as session:
                session.send_prompt()
                with self.assertRaisesRegex(acp.ProtocolError, message):
                    session.complete()
                self.assertEqual(session.prompt_count, None if scene == "extra-receipt" else 1)
                self.assertIsNotNone(session.process.returncode)
        self.assert_state(acp.ReadinessState.NEEDS_VERIFY)

    def test_strict_startup_errors_refuse_before_admission(self):
        for scene in ("malformed", "duplicate", "cr", "bom", "bad-utf8", "constant",
                      "bool-id", "extra-result", "extra-envelope", "truncated", "oversized",
                      "coalesced-init", "coalesced-session", "wrong-version", "empty-line"):
            with self.subTest(scene=scene):
                self.assert_startup_refused(self.assertRaises(acp.ProtocolError), scene)
                self.assert_state(acp.ReadinessState.NEEDS_VERIFY)

    def test_deadlines_for_startup_and_turn_are_distinct(self):
        self.assert_startup_refused(self.assertRaisesRegex(acp.ProtocolError, "deadline"),
                                    "init-timeout", timeout=.2)
        self.assert_state(acp.ReadinessState.NEEDS_VERIFY)
        timeout = .5
        with self.open(timeout=timeout) as session:
            time.sleep(timeout + .03)
            session.send_prompt()
            self.assertEqual(session.complete(), "ok")
        with self.open("timeout", timeout=timeout) as session:
            session.send_prompt()
            with self.assertRaisesRegex(acp.ProtocolError, "deadline"):
                session.complete()
            self.assertEqual(session.prompt_count, 1)
            self.assertIsNotNone(session.process.returncode)
        self.assert_state(acp.ReadinessState.NEEDS_VERIFY)

    def test_session_startup_cancels_while_competing_journal_lock_stays_held(self):
        def open_session(cancelled):
            with self.open(cancelled=cancelled):
                self.fail("cancelled startup must not yield a session")

        self.assert_contended_journal_cancellation(self.root, open_session)
        self.assert_state(acp.ReadinessState.NEEDS_VERIFY)

    def test_enrollment_cancels_while_competing_journal_lock_stays_held(self):
        with TemporaryDirectory() as scratch:
            root = Path(scratch)

            def enroll(cancelled):
                return readiness.enroll_fixture(root, deadline=time.monotonic() + 5, cancelled=cancelled)

            self.assert_contended_journal_cancellation(root, enroll)
            self.assertIsNone(readiness.read_status(root))
            self.assertFalse((root / readiness.ENROLLMENT_LOCK).exists())
            self.assertFalse((root / readiness.PROFILE).exists())

    def test_enrollment_completion_cancels_while_competing_journal_lock_stays_held(self):
        with TemporaryDirectory() as scratch, ThreadPoolExecutor(max_workers=1) as worker:
            root = Path(scratch)
            generation_started = Event()
            complete = Event()
            cancelled = Event()
            blocked = Event()

            def enroll():
                with readiness.enrollment_fixture(root, deadline=time.monotonic() + 5,
                                                  cancelled=cancelled.is_set):
                    generation_started.set()
                    self.assertTrue(complete.wait(5))

            outcome = worker.submit(enroll)
            try:
                self.assertTrue(generation_started.wait(1))
                with readiness._locked(root), self.observe_flock_contention(blocked):
                    complete.set()
                    self.assertTrue(blocked.wait(1))
                    self.assertFalse(outcome.done())
                    cancelled.set()
                    with self.assertRaisesRegex(acp.ProtocolError, "journal.*cancelled"):
                        outcome.result(1)
            finally:
                complete.set()
            self.assertFalse((root / readiness.PROFILE).exists())
            self.assertFalse((root / readiness.VERIFIER).exists())
            self.assertEqual(readiness.read_status(root).readiness, acp.ReadinessState.NEEDS_VERIFY)
            with readiness._locked(root) as directory, readiness._enrollment_handle(directory) as closed:
                self.assertTrue(closed)

    def test_session_startup_journal_and_initialize_share_absolute_deadline(self):
        initialize = acp._TextSession.initialize
        with (
            patch.object(readiness, "_locked", wraps=readiness._locked) as locked,
            patch.object(acp._TextSession, "initialize", autospec=True, side_effect=initialize) as start,
            self.open(timeout=1.5),
        ):
            self.assertEqual(locked.call_args.kwargs["deadline"], start.call_args.args[-1])

    def test_contended_session_startup_expires_before_lock_release(self):
        with ThreadPoolExecutor(max_workers=1) as worker, readiness._locked(self.root):
            def enter_session():
                with self.open(timeout=.15):
                    self.fail("startup must fail before lock release")

            outcome = worker.submit(enter_session)
            with self.assertRaisesRegex(acp.ProtocolError, "journal.*deadline"):
                outcome.result(1)
        self.assert_state(acp.ReadinessState.NEEDS_VERIFY)

    def assert_contended_journal_cancellation(self, root, operation):
        for initially_cancelled in (True, False):
            with self.subTest(initially_cancelled=initially_cancelled):
                cancelled = Event()
                blocked = Event()
                if initially_cancelled:
                    cancelled.set()
                with (
                    ThreadPoolExecutor(max_workers=1) as worker,
                    readiness._locked(root),
                    self.observe_flock_contention(blocked),
                ):
                    outcome = worker.submit(operation, cancelled.is_set)
                    if not initially_cancelled:
                        self.assertTrue(blocked.wait(1))
                        self.assertFalse(outcome.done())
                        cancelled.set()
                    with self.assertRaisesRegex(acp.ProtocolError, "journal.*cancelled"):
                        outcome.result(1)
                    if initially_cancelled:
                        self.assertFalse(blocked.is_set())

    @staticmethod
    def observe_flock_contention(blocked):
        flock = readiness.fcntl.flock

        def observed(lock, operation):
            try:
                return flock(lock, operation)
            except BlockingIOError:
                blocked.set()
                raise

        return patch.object(readiness.fcntl, "flock", side_effect=observed)

    def test_byte_bound_precedes_decode(self):
        with (
            self.open() as session,
            patch.object(acp, "MAX_BYTES", session.received + 1),
            patch.object(acp, "_read", return_value=b"xx"),
        ):
            deadline = time.monotonic() + 1
            with self.assertRaisesRegex(acp.ProtocolError, "byte bound"):
                session._next_frame(deadline)

    def test_short_and_interrupted_prompt_writes_spend_attempt_without_retry(self):
        def partial(fd, packet):
            self.assertFalse(os.get_blocking(fd))
            self.assertLess(len(packet), os.fpathconf(fd, "PC_PIPE_BUF"))
            return os.write(fd, packet[:8])

        for effect, outcome in ((partial, "incomplete"),
                                (InterruptedError(errno.EINTR, "injected"), "uncertain")):
            with self.subTest(outcome=outcome):
                with self.open() as session, patch.object(acp, "_prompt_write", side_effect=effect) as write:
                    with self.assertRaisesRegex(acp.ProtocolError, outcome):
                        session.send_prompt()
                    with self.assertRaisesRegex(acp.ProtocolError, "spent"):
                        session.send_prompt()
                    with self.assertRaises(acp.ProtocolError):
                        session.complete()
                    write.assert_called_once()
                self.assertEqual(session.prompt_count, 0)
                self.assert_state(acp.ReadinessState.NEEDS_VERIFY)

    def test_signed_out_fails_before_prompt_and_persists_disconnected(self):
        (self.root / readiness.PROFILE).unlink()
        self.assert_startup_refused(self.assertRaisesRegex(acp.ProtocolError, "session was refused"))
        self.assert_state(acp.ReadinessState.DISCONNECTED)

    def test_uncertain_retirement_keeps_exact_workspace_and_blocks_reuse(self):
        retire = readiness._retire

        def uncertain(*args):
            self.assertTrue(retire(*args))
            return False

        with patch.object(readiness, "_retire", side_effect=uncertain) as retire_spy:
            with self.open() as session:
                session.send_prompt()
                with self.assertRaises(acp.RetirementUnconfirmed):
                    session.complete()
                self.assertEqual(session.prompt_count, 1)
            retire_spy.assert_called_once()
        self.assertEqual(readiness.read_status(self.root), readiness.Record(
            self.generation, acp.ReadinessState.REVOCATION_UNCONFIRMED, session.attempt
        ))
        self.assertTrue((self.root / session.attempt).is_dir())
        self.assert_startup_refused(self.assertRaises(acp.RetirementUnconfirmed))

    def test_owner_exit_during_the_broker_finalizer_transfers_resources(self):
        entered = Event()
        leave = Event()
        retire = readiness._retire

        def held_retirement(process, pidfd):
            entered.set()
            try:
                self.assertTrue(leave.wait(5))
                os.fstat(pidfd)
            finally:
                retired = retire(process, pidfd)
            return retired

        with (
            ThreadPoolExecutor(max_workers=1) as broker,
            patch.object(readiness, "_retire", side_effect=held_retirement) as retire_spy,
        ):
            try:
                with ExitStack() as peer_scope:
                    session = peer_scope.enter_context(self.open())
                    session.send_prompt()
                    outcome = broker.submit(session.complete)
                    self.assertTrue(entered.wait(5))
                    with self.assertRaisesRegex(acp.RetirementUnconfirmed, "still owns"):
                        peer_scope.close()
                self.assertTrue((self.root / readiness.RECEIPT).is_file())
            finally:
                leave.set()
            with self.assertRaises(acp.PublicationUnconfirmed):
                outcome.result(5)
            retire_spy.assert_called_once()
        self.assertEqual(readiness.read_status(self.root).readiness, acp.ReadinessState.REVOCATION_UNCONFIRMED)
        self.assertTrue((self.root / session.attempt).is_dir())

    def test_owner_exit_during_journal_publication_keeps_blocking_receipt(self):
        entered = Event()
        leave = Event()
        store = readiness._store

        def held_store(directory, target, record):
            if target == readiness.JOURNAL:
                entered.set()
                self.assertTrue(leave.wait(5))
            return store(directory, target, record)

        with ThreadPoolExecutor(max_workers=1) as broker, patch.object(readiness, "_store", side_effect=held_store):
            try:
                with ExitStack() as peer_scope:
                    session = peer_scope.enter_context(self.open())
                    session.send_prompt()
                    outcome = broker.submit(session.complete)
                    self.assertTrue(entered.wait(5))
                    self.assertEqual(session.process.returncode, 0)
                    with self.assertRaisesRegex(acp.PublicationUnconfirmed, "peer retired"):
                        peer_scope.close()
                self.assertTrue((self.root / readiness.RECEIPT).is_file())
            finally:
                leave.set()
            with self.assertRaises(acp.PublicationUnconfirmed):
                outcome.result(5)
        self.assertEqual(readiness.read_status(self.root), readiness.Record(
            self.generation, acp.ReadinessState.REVOCATION_UNCONFIRMED, session.attempt
        ))
        self.assertTrue((self.root / session.attempt).is_dir())

    def test_owner_exit_during_workspace_removal_reports_pending_publication(self):
        removed = Event()
        leave = Event()
        remove = readiness._remove_workspace

        def held_removal(*args):
            remove(*args)
            removed.set()
            self.assertTrue(leave.wait(5))

        with (
            ThreadPoolExecutor(max_workers=1) as broker,
            patch.object(readiness, "_remove_workspace", side_effect=held_removal),
        ):
            try:
                with ExitStack() as peer_scope:
                    session = peer_scope.enter_context(self.open())
                    session.send_prompt()
                    outcome = broker.submit(session.complete)
                    self.assertTrue(removed.wait(5))
                    with self.assertRaisesRegex(acp.PublicationUnconfirmed, "peer retired"):
                        peer_scope.close()
                self.assertEqual(session.process.returncode, 0)
                self.assertFalse((self.root / session.attempt).exists())
            finally:
                leave.set()
            with self.assertRaises(acp.PublicationUnconfirmed):
                outcome.result(5)
        self.assertEqual(readiness.read_status(self.root), readiness.Record(
            self.generation, acp.ReadinessState.REVOCATION_UNCONFIRMED, session.attempt
        ))
        self.assert_startup_refused(self.assertRaises(acp.RetirementUnconfirmed))

    def test_owner_exit_after_receipt_commit_preserves_confirmed_retirement(self):
        finishing = Event()
        after_commit = Event()
        leave = Event()
        fsync = os.fsync

        def held_fsync(fd):
            if finishing.is_set() and not (self.root / readiness.RECEIPT).exists():
                after_commit.set()
                self.assertTrue(leave.wait(5))
            return fsync(fd)

        with ThreadPoolExecutor(max_workers=1) as broker, patch.object(acp.os, "fsync", side_effect=held_fsync):
            try:
                with self.open() as session:
                    session.send_prompt()
                    finishing.set()
                    outcome = broker.submit(session.complete)
                    self.assertTrue(after_commit.wait(5))
                self.assertFalse(outcome.done())
            finally:
                leave.set()
            self.assertEqual(outcome.result(5), "ok")
        self.assert_state(acp.ReadinessState.READY)


class SyntheticPeerEvidenceTest(unittest.TestCase):
    def test_receipt_precedes_wrong_session_and_frame_overflow(self):
        for scene in ("wrong-session", "over-frames"):
            with self.subTest(scene=scene):
                emitted, receipt = self._capture_turn(scene)

                self.assertEqual(len(receipt), 1)
                prefix_length, count, chunks, digest = receipt[0]
                valid_chunks = ["ok"]
                if scene == "over-frames":
                    valid_chunks += [""] * (acp.MAX_FRAMES - 3)
                self.assertEqual(emitted[:prefix_length], [peer.update(text) for text in valid_chunks])
                if scene == "over-frames":
                    self.assertEqual(emitted[prefix_length]["id"], peer.PROMPT_ID)
                else:
                    self.assertNotEqual(emitted[prefix_length]["params"]["sessionId"], peer.SESSION)
                expected_digest = hashlib.sha256()
                for chunk in valid_chunks:
                    peer.hash_chunk(expected_digest, chunk)
                self.assertEqual((count, chunks, digest), (1, len(valid_chunks), expected_digest.hexdigest()))

    def _capture_turn(self, scene):
        emitted = []
        receipt = []

        def record(evidence, count, _scene):
            receipt.append((len(emitted), count, evidence.chunks, evidence.digest.hexdigest()))

        def stdout(raw):
            emitted.append(peer.frame_body(raw[:-1]))

        with (
            patch.object(peer, "read_request", return_value=True),
            patch.object(peer.sys, "stdin", SimpleNamespace(buffer=BytesIO())),
            patch.object(peer, "stdout", side_effect=stdout),
            patch.object(peer.TurnEvidence, "write", new=record),
        ):
            self.assertEqual(peer.turn(scene, peer.TurnEvidence(-1, "synthetic")), 0)
        return emitted, receipt


if __name__ == "__main__":
    unittest.main()
