"""Verify enrollment reservations persist and pending can outlive its attempt."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from oc_antigravity_enrollment import EnrollmentJournal, EnrollmentUnavailable, HOSTS


class EnrollmentJournalTest(unittest.TestCase):
    def setUp(self):
        self.path = Path(self.enterContext(TemporaryDirectory()))
        self.journal = EnrollmentJournal(self.path)
        self.identity = self.journal.begin("a" * 64)

    def test_slots_are_ordered_and_spent_across_reopen(self):
        token, userinfo = HOSTS
        with self.assertRaises(EnrollmentUnavailable):
            self.journal.reserve(self.identity, userinfo)
        self.journal.reserve(self.identity, token)
        reopened = EnrollmentJournal(self.path)
        self.assertEqual(reopened.status().active_slot, token)
        with self.assertRaises(EnrollmentUnavailable):
            reopened.reserve(self.identity, token)
        reopened.retired(self.identity, token)
        with self.assertRaises(EnrollmentUnavailable):
            reopened.reserve(self.identity, token)
        reopened.reserve(self.identity, userinfo)
        reopened.retired(self.identity, userinfo)
        with self.assertRaises(EnrollmentUnavailable):
            reopened.begin_cold_check(self.identity)
        reopened.record_attempt_retirement(self.identity)
        check = reopened.begin_cold_check(self.identity)
        reopened.mark_ready_after_cold_check(self.identity, check)
        self.assertEqual(self.journal.status().state, "ready")

    def test_cancel_keeps_same_pending_generation_and_fences_old_attempt(self):
        token, userinfo = HOSTS
        self.journal.reserve(self.identity, token)
        self.journal.retired(self.identity, token)
        EnrollmentJournal(self.path).revoke(self.identity)
        reopened = EnrollmentJournal(self.path)
        self.assertEqual(reopened.status().identity, self.identity)
        self.assertEqual(reopened.status().state, "pending")
        with self.assertRaises(EnrollmentUnavailable):
            self.journal.reserve(self.identity, userinfo)
        with self.assertRaises(EnrollmentUnavailable):
            self.journal.begin("a" * 64)
        with self.assertRaises(EnrollmentUnavailable):
            self.journal.begin_cold_check(self.identity)
        reopened.record_attempt_retirement(self.identity)
        reopened.abandon(self.identity)
        with self.assertRaises(EnrollmentUnavailable):
            self.journal.begin_cold_check(self.identity)
        self.assertEqual(self.journal.status().state, "abandoned")

    def test_stale_generation_cannot_change_any_state(self):
        wrong = replace(self.identity, generation="f" * 32)
        before = self.journal.status()
        with self.assertRaises(EnrollmentUnavailable):
            self.journal.revoke(wrong)
        with self.assertRaises(EnrollmentUnavailable):
            self.journal.begin_cold_check(wrong)
        self.assertEqual(self.journal.status(), before)

    def test_concurrent_claims_spend_one_slot(self):
        def claim():
            try:
                EnrollmentJournal(self.path).reserve(self.identity, HOSTS[0])
            except EnrollmentUnavailable:
                return False
            return True

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(lambda _: claim(), range(2))), [False, True])

    def test_fifo_cannot_replace_the_registration_record(self):
        record = self.path / "enrollment.json"
        record.unlink()
        os.mkfifo(record, 0o600)
        with self.assertRaises(EnrollmentUnavailable):
            self.journal.status()

    def test_cancel_during_cold_check_blocks_late_readiness(self):
        self.journal.revoke(self.identity)
        self.journal.record_attempt_retirement(self.identity)
        check = self.journal.begin_cold_check(self.identity)
        EnrollmentJournal(self.path).revoke(self.identity)
        with self.assertRaises(EnrollmentUnavailable):
            self.journal.mark_ready_after_cold_check(self.identity, check)
        self.assertEqual(self.journal.status().state, "pending")

    def test_abandoned_attempt_can_record_retirement_without_reopening(self):
        self.journal.reserve(self.identity, HOSTS[0])
        self.journal.abandon(self.identity)
        reopened = EnrollmentJournal(self.path)
        reopened.record_attempt_retirement(self.identity)
        current = reopened.status()
        self.assertTrue(current.attempt_retired)
        self.assertIsNone(current.active_slot)
        self.assertEqual(current.state, "abandoned")
        with self.assertRaises(EnrollmentUnavailable):
            reopened.reserve(self.identity, HOSTS[0])


if __name__ == "__main__":
    unittest.main()
