import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from threading import Barrier

from quota_core import CLOCK_MAX, FixtureGrant, QuotaCore, Settlement


FIXTURE = json.loads(Path(__file__).with_name("fixture.json").read_text(encoding="utf-8"))
START = FIXTURE["observed_at"]
GRANT = FixtureGrant(**FIXTURE["grant"])
SHORT = "5h_rolling"
LONG = "7d_weekly"


class QuotaCoreTest(unittest.TestCase):
    def setUp(self):
        self.now = START
        self.core = QuotaCore(lambda: self.now, GRANT)
        self.windows = deepcopy(FIXTURE["windows"])

    def observe(self):
        return self.core.observe(self.windows, self.now)

    def reserve(self, request_id="request"):
        return self.core.reserve(request_id, GRANT.route, GRANT.model)

    def settlement(self, charge=4, request_id="request"):
        return Settlement(request_id, GRANT.route, GRANT.model, charge, True)

    def reserve_and_mark(self, request_id="request"):
        self.assertTrue(self.reserve(request_id))
        self.assertTrue(self.core.mark_may_have_sent(request_id))

    def assert_unverified(self):
        admission = self.core.ordinary_admission()
        self.assertFalse(admission.allowed)
        self.assertEqual(admission.reason, "quota_unverified")

    def test_cold_start_and_healthy_minimum(self):
        self.assert_unverified()
        self.assertTrue(self.observe())
        admission = self.core.ordinary_admission()
        self.assertTrue(admission.allowed)
        self.assertEqual(admission.headroom_bps, 2500)
        self.assertFalse(admission.low_headroom)

    def test_low_headroom_at_999_but_not_1000(self):
        for remaining, warning in [(999, True), (1000, False)]:
            with self.subTest(remaining=remaining):
                self.now += 1
                self.windows[SHORT]["remaining_bps"] = remaining
                self.assertTrue(self.observe())
                admission = self.core.ordinary_admission()
                self.assertTrue(admission.allowed)
                self.assertEqual(admission.headroom_bps, remaining)
                self.assertIs(admission.low_headroom, warning)

    def test_report_either_exhausted_window_and_break_ties_by_short_window(self):
        for short, long, blocking in [(0, 1, SHORT), (1, 0, LONG), (0, 0, SHORT)]:
            with self.subTest(short=short, long=long):
                self.now += 1
                self.windows[SHORT]["remaining_bps"] = short
                self.windows[LONG]["remaining_bps"] = long
                self.assertTrue(self.observe())
                admission = self.core.ordinary_admission()
                self.assertFalse(admission.allowed)
                self.assertEqual(admission.reason, "quota_exhausted")
                self.assertEqual(admission.blocking_window, blocking)
                self.assertEqual(admission.resets_at, self.windows[blocking]["resets_at"])
                self.assertEqual(self.core.accounting().admitted_ids, 0)

    def test_long_window_exhaustion_precedes_short_ttl_expiry(self):
        self.windows[LONG]["remaining_bps"] = 0
        self.assertTrue(self.observe())
        self.now = START + 300
        self.assertEqual(self.core.ordinary_admission().blocking_window, LONG)
        self.now = START + 899
        self.assertEqual(self.core.ordinary_admission().blocking_window, LONG)
        self.now = START + 900
        self.assert_unverified()

    def test_short_ttl_boundary_and_same_time_replay_does_not_refresh(self):
        self.assertTrue(self.observe())
        self.now = START + 299
        self.assertTrue(self.core.ordinary_admission().allowed)
        self.now += 1
        self.assertTrue(self.core.observe(self.windows, START))
        self.assert_unverified()
        self.assertTrue(self.observe())
        self.assertTrue(self.core.ordinary_admission().allowed)

    def test_reset_equality_each_window_requires_new_evidence(self):
        for name in (SHORT, LONG):
            with self.subTest(name=name):
                self.setUp()
                self.windows[name]["resets_at"] = START + 2
                self.windows[name]["remaining_bps"] = 0
                self.assertTrue(self.observe())
                self.now = START + 1
                self.assertEqual(self.core.ordinary_admission().blocking_window, name)
                self.now += 1
                self.assert_unverified()
                self.assertTrue(self.core.observe(self.windows, START))
                self.assert_unverified()
                self.windows[name] = deepcopy(FIXTURE["windows"][name])
                self.assertTrue(self.observe())
                self.assertTrue(self.core.ordinary_admission().allowed)

    def test_invalid_observation_times_preserve_evidence(self):
        self.assertTrue(self.observe())
        for timestamp in (START - 1, START + 1, -1, CLOCK_MAX + 1, True, float(START)):
            with self.subTest(timestamp=timestamp):
                self.assertFalse(self.core.observe({}, timestamp))
                self.assertTrue(self.core.ordinary_admission().allowed)

    def test_equal_timestamp_conflict_stays_poisoned_until_new_complete_sample(self):
        self.assertTrue(self.observe())
        self.assertTrue(self.observe())
        self.windows[LONG]["remaining_bps"] = 1000
        self.assertFalse(self.observe())
        self.assert_unverified()
        self.assertFalse(self.core.observe(FIXTURE["windows"], START))
        self.assertFalse(self.core.observe(FIXTURE["windows"], START - 1))
        self.assert_unverified()
        self.now += 1
        self.assertTrue(self.observe())
        self.assertEqual(self.core.ordinary_admission().headroom_bps, 1000)

    def test_current_partial_or_malformed_snapshot_closes_both_windows(self):
        invalid_fields = [
            {"remaining_bps": True, "resets_at": START + 10},
            {"remaining_bps": 10_001, "resets_at": START + 10},
            {"remaining_bps": -1, "resets_at": START + 10},
            {"remaining_bps": 1, "resets_at": START + 1},
            {"remaining_bps": 1, "resets_at": START + 18_002},
            {"remaining_bps": 1, "resets_at": CLOCK_MAX + 1},
        ]
        malformed = [{}] + [dict(self.windows, **{SHORT: raw}) for raw in invalid_fields]
        for snapshot in malformed:
            with self.subTest(snapshot=snapshot):
                self.setUp()
                self.assertTrue(self.observe())
                self.now += 1
                self.assertFalse(self.core.observe(snapshot, self.now))
                self.assert_unverified()
                self.assertFalse(self.core.observe(self.windows, START))
                self.assertFalse(self.observe())
                self.now += 1
                self.assertTrue(self.observe())
                self.assertTrue(self.core.ordinary_admission().allowed)

    def test_partial_snapshot_advances_time_even_without_previous_valid_evidence(self):
        for previous_sample in (False, True):
            with self.subTest(previous_sample=previous_sample):
                self.setUp()
                if previous_sample:
                    self.assertTrue(self.observe())
                self.now = START + 2
                self.assertFalse(self.core.observe({SHORT: self.windows[SHORT]}, self.now))
                self.assertFalse(self.core.observe(self.windows, START + 1))
                self.assertFalse(self.observe())
                self.assert_unverified()
                self.now += 1
                self.assertTrue(self.observe())
                self.assertTrue(self.core.ordinary_admission().allowed)

    def test_clock_endpoints_and_invalid_values(self):
        self.now = 0
        self.assertTrue(self.reserve("zero"))
        self.assertTrue(self.core.release_pre_send("zero"))
        self.now = CLOCK_MAX
        self.assertTrue(self.reserve("maximum"))
        self.assertTrue(self.core.release_pre_send("maximum"))

        for invalid in (False, None, "now", 0.0, -1, CLOCK_MAX + 1, CLOCK_MAX - 1):
            with self.subTest(invalid=invalid):
                self.now = invalid
                self.assertFalse(self.reserve())
        self.now = CLOCK_MAX
        self.assertTrue(self.reserve())

    def test_clock_recovery_preserves_evidence_and_keeps_settlement_available(self):
        self.assertTrue(self.observe())
        self.assertTrue(self.reserve("release"))
        self.now = START - 1
        self.assertFalse(self.core.observe({}, START - 1))
        self.assert_unverified()
        self.assertFalse(self.core.mark_may_have_sent("release"))
        self.assertTrue(self.core.release_pre_send("release"))
        self.assertFalse(self.reserve())

        self.now = START
        self.assertTrue(self.core.ordinary_admission().allowed)
        self.reserve_and_mark()
        self.now = CLOCK_MAX + 1
        self.assertTrue(self.core.settle(self.settlement()))
        self.assertEqual(self.core.accounting().spent, 4)
        self.now = START + 300
        self.assert_unverified()

    def test_route_model_and_hard_bound_are_required(self):
        self.assertFalse(self.core.reserve("request", "wrong-route", GRANT.model))
        self.assertFalse(self.core.reserve("request", GRANT.route, "wrong-model"))
        for invalid in (None, 0, -1, True, 6.0):
            with self.subTest(invalid=invalid):
                core = QuotaCore(lambda: self.now, replace(GRANT, hard_bound=invalid))
                self.assertFalse(core.reserve("request", GRANT.route, GRANT.model))
                self.assertEqual(core.accounting().admitted_ids, 0)
        self.assertTrue(self.reserve())

    def test_invalid_budget_does_not_consume_a_slot(self):
        for invalid in (None, True, -1, 10.0):
            with self.subTest(invalid=invalid):
                core = QuotaCore(lambda: self.now, replace(GRANT, budget=invalid))
                original = core.accounting()
                self.assertFalse(core.reserve("request", GRANT.route, GRANT.model))
                self.assertEqual(core.accounting(), original)

    def test_ordinary_denial_has_no_reservation_and_explicit_reserve_is_independent(self):
        self.windows[SHORT]["remaining_bps"] = 0
        self.assertTrue(self.observe())
        original = self.core.accounting()
        self.assertEqual(self.core.ordinary_admission().reason, "quota_exhausted")
        self.assertEqual(self.core.accounting(), original)
        self.assertTrue(self.reserve())

    def test_spent_plus_bound_at_budget_and_above_budget(self):
        for charge, allowed in [(4, True), (5, False)]:
            with self.subTest(charge=charge):
                self.setUp()
                self.reserve_and_mark("first")
                self.assertTrue(self.core.settle(self.settlement(charge, "first")))
                self.assertIs(self.reserve("second"), allowed)
                self.assertEqual(self.core.accounting().spent, charge)

    def test_two_callers_compete_for_one_slot(self):
        start = Barrier(2)

        def compete(request_id):
            start.wait()
            return self.reserve(request_id)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(compete, ["first", "second"]))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(self.core.accounting().active.bound, 6)
        self.assertEqual(self.core.accounting().admitted_ids, 1)

    def test_release_before_send_and_uncertainty_after_send(self):
        self.assertTrue(self.reserve("released"))
        self.assertFalse(self.core.release_pre_send("wrong"))
        self.assertTrue(self.core.release_pre_send("released"))
        self.assertFalse(self.core.mark_may_have_sent("released"))
        self.assertFalse(self.reserve("released"))

        self.assertTrue(self.reserve())
        self.assertFalse(self.core.mark_may_have_sent("wrong"))
        self.assertFalse(self.core.settle(self.settlement()))
        self.assertTrue(self.core.mark_may_have_sent("request"))
        self.assertFalse(self.core.mark_may_have_sent("request"))
        self.assertFalse(self.core.release_pre_send("request"))
        self.assertFalse(self.core.settle(None))
        self.assertFalse(self.reserve("another"))
        self.assertEqual(self.core.accounting().active.bound, 6)

    def test_unauthoritative_invalid_and_mismatched_settlements_preserve_full_hold(self):
        self.reserve_and_mark()
        valid = self.settlement()
        original = self.core.accounting()
        for invalid in (
            None,
            replace(valid, authoritative_final=False),
            replace(valid, authoritative_final=1),
            replace(valid, route="wrong-route"),
            replace(valid, model="wrong-model"),
            replace(valid, request_id="wrong-request"),
            replace(valid, charge=True),
            replace(valid, charge=-1),
            replace(valid, charge=4.0),
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(self.core.settle(invalid))
                self.assertEqual(self.core.accounting(), original)
        self.assertTrue(self.core.settle(valid))
        self.assertEqual(self.core.accounting().spent, 4)
        self.assertIsNone(self.core.accounting().active)
        self.assertFalse(self.reserve())

    def test_exact_receipt_replay_leaves_different_active_request_intact(self):
        self.reserve_and_mark("A")
        receipt = self.settlement(request_id="A")
        self.assertTrue(self.core.settle(receipt))
        self.assertTrue(self.reserve("B"))
        original = self.core.accounting()
        self.assertTrue(self.core.settle(receipt))
        self.assertEqual(self.core.accounting(), original)

        self.assertTrue(self.core.mark_may_have_sent("B"))
        original = self.core.accounting()
        self.assertTrue(self.core.settle(receipt))
        self.assertEqual(self.core.accounting(), original)
        self.assertTrue(self.core.settle(self.settlement(charge=0, request_id="B")))
        self.assertEqual(self.core.accounting().spent, 4)

    def test_conflicting_final_evidence_suspends_without_recharging_or_releasing(self):
        for conflict in ({"charge": 3}, {"route": "other-route"}, {"model": "other-model"}):
            with self.subTest(conflict=conflict):
                self.setUp()
                evidence = self.settlement(charge=2, request_id="A")
                self.reserve_and_mark("A")
                self.assertTrue(self.core.settle(evidence))
                self.reserve_and_mark("B")
                original = self.core.accounting()
                self.assertFalse(self.core.settle(replace(evidence, **conflict)))
                suspended = replace(original, suspended=True)
                self.assertEqual(self.core.accounting(), suspended)
                self.assertTrue(self.core.settle(evidence))
                self.assertEqual(self.core.accounting(), suspended)
                self.assertTrue(self.core.settle(self.settlement(charge=1, request_id="B")))
                self.assertFalse(self.reserve("new"))

    def test_final_evidence_after_release_suspends_and_preserves_other_hold(self):
        for sent in (False, True):
            with self.subTest(sent=sent):
                self.setUp()
                self.assertTrue(self.reserve("released"))
                self.assertTrue(self.core.release_pre_send("released"))
                self.assertTrue(self.reserve("other"))
                if sent:
                    self.assertTrue(self.core.mark_may_have_sent("other"))
                original = self.core.accounting()
                evidence = self.settlement(request_id="released")
                self.assertFalse(self.core.settle(evidence))
                self.assertEqual(self.core.accounting(), replace(original, suspended=True))
                if sent:
                    self.assertTrue(self.core.settle(self.settlement(request_id="other")))
                else:
                    self.assertFalse(self.core.mark_may_have_sent("other"))
                    self.assertTrue(self.core.release_pre_send("other"))
                self.assertFalse(self.reserve("new"))

    def test_partial_malformed_or_unauthoritative_terminal_evidence_is_inert(self):
        for released in (False, True):
            with self.subTest(released=released):
                self.setUp()
                receipt = self.settlement(charge=2, request_id="terminal")
                if released:
                    self.assertTrue(self.reserve("terminal"))
                    self.assertTrue(self.core.release_pre_send("terminal"))
                else:
                    self.reserve_and_mark("terminal")
                    self.assertTrue(self.core.settle(receipt))
                self.reserve_and_mark("active")
                original = self.core.accounting()
                for invalid in (
                    None,
                    {"request_id": "terminal", "authoritative_final": True},
                    replace(receipt, route=""),
                    replace(receipt, route="a" * 65),
                    replace(receipt, model="bad model"),
                    replace(receipt, model=False),
                    replace(receipt, charge=None),
                    replace(receipt, charge=True),
                    replace(receipt, route="other", authoritative_final=False),
                    replace(receipt, charge=3, authoritative_final=1),
                ):
                    with self.subTest(evidence=invalid):
                        self.assertFalse(self.core.settle(invalid))
                        self.assertEqual(self.core.accounting(), original)

    def test_over_bound_is_recorded_before_suspension(self):
        self.reserve_and_mark()
        evidence = self.settlement(7)
        self.assertTrue(self.core.settle(evidence))
        accounting = self.core.accounting()
        self.assertEqual(accounting.spent, 7)
        self.assertIsNone(accounting.active)
        self.assertTrue(accounting.suspended)
        self.assertTrue(self.core.settle(evidence))
        self.assertEqual(self.core.accounting(), accounting)
        self.assertFalse(self.reserve("another"))

    def test_receipt_cap_preserves_first_id_and_allows_eighth_to_settle(self):
        for first_released in (False, True):
            with self.subTest(first_released=first_released):
                self.setUp()
                first = self.settlement(0, "first")
                self.assertTrue(self.reserve("first"))
                if first_released:
                    self.assertTrue(self.core.release_pre_send("first"))
                else:
                    self.assertTrue(self.core.mark_may_have_sent("first"))
                    self.assertTrue(self.core.settle(first))

                for number in range(2, 8):
                    request_id = f"request-{number}"
                    self.assertTrue(self.reserve(request_id))
                    self.assertTrue(self.core.release_pre_send(request_id))
                self.reserve_and_mark("eighth")
                self.assertEqual(self.core.accounting().admitted_ids, 8)
                self.assertFalse(self.reserve("ninth"))
                self.assertTrue(self.core.settle(self.settlement(0, "eighth")))

                full = self.core.accounting()
                self.assertEqual(full.admitted_ids, 8)
                self.assertEqual(full.spent, 0)
                self.assertIsNone(full.active)
                self.assertFalse(full.suspended)
                self.assertFalse(self.reserve("first"))
                self.assertFalse(self.reserve("ninth"))
                self.assertEqual(self.core.accounting(), full)

                if first_released:
                    self.assertFalse(self.core.settle(first))
                    self.assertEqual(self.core.accounting(), replace(full, suspended=True))
                else:
                    self.assertTrue(self.core.settle(first))
                    self.assertEqual(self.core.accounting(), full)

    def test_request_id_syntax_and_length(self):
        for invalid in ("", "a" * 65, "bad\n", "has space", "non-ascii-é", True, 1):
            with self.subTest(invalid=invalid):
                self.assertFalse(self.reserve(invalid))
        self.assertTrue(self.reserve("-" * 63 + "_"))
        self.assertTrue(self.core.release_pre_send("-" * 63 + "_"))
        self.assertTrue(self.reserve("A"))
