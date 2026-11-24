"""Check that revoked enrollment uses the same second-host gate as normal sign-in."""

from pathlib import Path
import runpy
from threading import Thread
import unittest
from unittest.mock import Mock, patch


ENROLL = runpy.run_path(str(Path(__file__).with_name("enrollment-fixture.py")))


class EnrollmentAttemptTest(unittest.TestCase):
    def test_cancel_flows_through_second_peer_admission(self):
        journal = Mock()
        journal.current.return_value = {"generation": "generation", "state": "pending"}
        attempt = Mock()
        attempt.admit_userinfo.return_value = False
        evidence = []

        def exchange(_listener, _context, receipts, **kwargs):
            if kwargs.get("hostname") == ENROLL["USERINFO"]:
                self.assertFalse(kwargs["authorize"]())
                return
            receipts.append("synthetic_token_issued")

        fixture = ENROLL["FIXTURE"]
        with patch.dict(fixture, {"serve_once": Mock(side_effect=exchange)}):
            with patch.object(ENROLL["ssl"], "SSLContext"):
                ENROLL["serve"](Mock(), Path("/synthetic"), evidence, journal, "generation", attempt)
            self.assertEqual(fixture["serve_once"].call_count, 2)
        self.assertEqual(evidence, ["synthetic_token_issued"])
        attempt.admit_userinfo.assert_called_once()
        attempt.touch.assert_not_called()

    def test_same_gate_permits_live_attempt_and_refuses_revoked_attempt(self):
        for revoke in (False, True):
            with self.subTest(revoke=revoke):
                attempt = ENROLL["Attempt"](pause=True)
                disposition = []
                worker = Thread(target=lambda: disposition.append(attempt.admit_userinfo()))
                worker.start()
                try:
                    self.assertTrue(attempt.userinfo_arrival.wait(1))
                    if revoke:
                        attempt.cancel()
                        self.assertTrue(attempt.refused.is_set())
                    else:
                        attempt.resume.set()
                finally:
                    attempt.retirement_checked.set()
                    worker.join(2)
                self.assertEqual(disposition, [not revoke])


if __name__ == "__main__":
    unittest.main()
