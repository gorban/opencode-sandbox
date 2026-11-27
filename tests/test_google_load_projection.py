"""Keep legacy LOAD bytes and project only the pinned native early-return shape."""

from copy import deepcopy
import json
import time
import unittest

from oc_google.account_binding import bind_subject
from oc_google.enrollment import EnrollmentMetadataError, LoadObservation, _LoadCodeAssist
from oc_google.metadata_destination import MetadataRoute


PROJECT = "synthetic-projection-project"
BEARER = b"synthetic-load-bearer"
CURRENT = {"id": "free-tier", "name": "Synthetic current", "usesGcpTos": False}
PAID = {"id": "paid-tier", "name": "Synthetic paid"}
PROJECTED = {"currentTier": CURRENT, "paidTier": PAID, "cloudaicompanionProject": PROJECT}


def rich_load():
    return {
        "currentTier": {**CURRENT, "description": "Fixture description",
                        "privacyNotice": {"showNotice": True}, "availableCredits": [{"label": "fixture"}],
                        "upgradeSubscriptionType": "UPGRADE", "userDefinedCloudaicompanionProject": False},
        "cloudaicompanionProject": PROJECT,
        "paidTier": {**PAID, "referralInviteUri": "https://fixture.invalid/invite", "upgradeSubscriptionType": 1},
        "allowedTiers": [{"id": "free-tier", "name": "Synthetic current", "usesGcpTos": False},
                         {"id": "paid-tier"}, {"id": "managed-other", "usesGcpTos": True,
                                              "userDefinedCloudaicompanionProject": True}],
        "ineligibleTiers": [{"tierId": "negative-other", "reasonCode": 1, "reasonMessage": "Synthetic not offered"}],
        "projectValidationError": None,
        "gcpManaged": False,
        "releaseChannel": {"type": "STABLE", "name": "fixture"},
        "manageSubscriptionUri": "https://fixture.invalid/manage",
        "upgradeSubscriptionUri": None,
        "g1Tier": "fixture",
    }


def encode(fields):
    return json.dumps(fields, separators=(",", ":")).encode("ascii")


class LoadProjectionTests(unittest.TestCase):
    def load(self, body):
        proof = bind_subject(b"x" * 32, BEARER, b'{"id":"2898"}')
        writes = []

        def destination(route, *, authorization, deadline, deliver, **kwargs):
            self.assertIs(route, MetadataRoute.LOAD_CODE_ASSIST)
            self.assertEqual(authorization, b"Bearer " + BEARER)
            deliver(lambda: writes.append(route))
            return body

        load = _LoadCodeAssist(proof, time.monotonic() + 3, lambda _route, send: send(), destination)
        try:
            return load(authorization=b"Bearer " + BEARER, body=b'{"metadata":{"ideType":"ANTIGRAVITY"}}')
        finally:
            self.assertEqual(writes, [MetadataRoute.LOAD_CODE_ASSIST])

    def test_legacy_replies_are_forwarded_byte_for_byte(self):
        variants = (
            (b' { }\n', False, False),
            (b'{ "cloudaicompanionProject" : "project-one" }', False, True),
            (b'{"currentTier" : {"name":"Plan", "id":"free"}}\r\n', True, False),
            (b'{ "cloudaicompanionProject": "project-one", "currentTier":{"name":"Plan","id":"free"} }', True, True),
        )
        for raw, tier, project in variants:
            with self.subTest(tier=tier, project=project):
                reply = self.load(raw)
                self.assertIs(reply.body, raw)
                self.assertEqual(reply.observation, LoadObservation(tier, project))

    def test_rich_reply_projects_exact_active_tier_project_and_policy(self):
        raw = encode(rich_load())
        reply = self.load(raw)
        self.assertEqual(json.loads(reply.body), PROJECTED)
        self.assertEqual(reply.observation, LoadObservation(True, True))
        self.assertNotIn(b"fixture.invalid", reply.body)

    def test_null_paid_and_missing_family_flag_do_not_synthesize_fields(self):
        value = rich_load()
        value["paidTier"] = None
        del value["currentTier"]["usesGcpTos"]
        value["allowedTiers"] = None
        value["ineligibleTiers"] = None
        expected = {"currentTier": {"id": CURRENT["id"], "name": CURRENT["name"]},
                    "cloudaicompanionProject": PROJECT}
        self.assertEqual(json.loads(self.load(encode(value)).body), expected)

    def test_non_personal_or_missing_original_branch_is_refused(self):
        matrix = (
            ("currentTier", None, True), ("cloudaicompanionProject", None, True),
            ("cloudaicompanionProject", "", False), ("currentTier", {"name": "Plan"}, False),
            ("gcpManaged", True, False), ("gcpManaged", None, False),
            ("projectValidationError", {}, False), ("projectValidationError", False, False),
            ("paidTier", {"id": "paid"}, False), ("unexpected", True, False),
        )
        for key, invalid, missing in matrix:
            with self.subTest(key=key, missing=missing, invalid=invalid):
                fields = rich_load()
                if missing:
                    fields.pop(key)
                else:
                    fields[key] = invalid
                with self.assertRaises(EnrollmentMetadataError):
                    self.load(encode(fields))
        for tier in ("paidTier", "currentTier"):
            for key in ("usesGcpTos", "userDefinedCloudaicompanionProject"):
                for invalid in (True, None, 0, "false"):
                    with self.subTest(tier=tier, key=key, invalid=invalid):
                        fields = rich_load()
                        fields[tier][key] = invalid
                        with self.assertRaises(EnrollmentMetadataError):
                            self.load(encode(fields))

    def test_contradictory_active_alternatives_and_negative_entries_are_refused(self):
        alternatives = [
            {"id": "free-tier", "name": "Different"},
            {"id": "paid-tier", "usesGcpTos": True},
            {"id": "free-tier", "userDefinedCloudaicompanionProject": True},
            {"id": "paid-tier", "isDefault": 1},
        ]
        for row in alternatives:
            with self.subTest(row=row):
                fields = rich_load()
                fields["allowedTiers"] = [row]
                with self.assertRaises(EnrollmentMetadataError):
                    self.load(encode(fields))
        for key, invalid in (
            ("allowedTiers", [{"id": "other"}, {"id": "other"}]),
            ("allowedTiers", [{"name": "No ID"}]),
            ("ineligibleTiers", [{"tierId": "free-tier"}]),
            ("ineligibleTiers", [{"tierId": "paid-tier"}]),
            ("ineligibleTiers", [{"tierId": "other"}, {"tierId": "other"}]),
            ("ineligibleTiers", [{"tierId": "other", "otherReason": "fixture"}]),
            ("ineligibleTiers", [{"tierId": "other", "reasonCode": -1}]),
            ("ineligibleTiers", [{"tierId": "other", "reasonMessage": True}]),
        ):
            with self.subTest(key=key, invalid=invalid):
                fields = rich_load()
                fields[key] = invalid
                with self.assertRaises(EnrollmentMetadataError):
                    self.load(encode(fields))

    def test_rich_schema_checks_types_nulls_and_bounds(self):
        for key, invalid in (
            ("description", None), ("description", "\n"), ("name", "a" * 257), ("privacyNotice", []),
            ("availableCredits", {}), ("availableCredits", [1]), ("isDefault", "false"),
            ("upgradeSubscriptionType", 2 ** 31), ("upgradeSubscriptionType", -1),
            ("upgradeSubscriptionType", "with space"), ("arbitrary", "not a descriptor field"),
        ):
            with self.subTest(key=key, invalid=invalid):
                fields = rich_load()
                fields["currentTier"][key] = invalid
                with self.assertRaises(EnrollmentMetadataError):
                    self.load(encode(fields))
        for key, invalid in (
            ("releaseChannel", []), ("releaseChannel", None),
            ("releaseChannel", {"rows": [0] * 17}),
            ("releaseChannel", {"rows": {str(i): False for i in range(25)}}),
            ("releaseChannel", {"a": {"b": {"c": {"d": {"e": {"too": "deep"}}}}}}),
            ("releaseChannel", {"long": "é" * 513}), ("manageSubscriptionUri", 1), ("g1Tier", "\n"),
            ("releaseChannel", {str(i): "x" * 1024 for i in range(16)}),
        ):
            with self.subTest(key=key):
                fields = rich_load()
                fields[key] = invalid
                with self.assertRaises(EnrollmentMetadataError):
                    self.load(encode(fields))

    def test_rich_json_refuses_duplicates_nonfinite_and_surrogate(self):
        value = deepcopy(rich_load())
        for literal in (b'{"key":1,"key":2}', b'{"key":NaN}', b'{"key":1e999}', b'{"key":"\\ud800"}'):
            with self.subTest(literal=literal), self.assertRaises(EnrollmentMetadataError):
                value["releaseChannel"] = "PLACEHOLDER"
                self.load(encode(value).replace(b'"PLACEHOLDER"', literal))


if __name__ == "__main__":
    unittest.main()
