"""Synthetic subject and bearer continuity for Google metadata."""

import hmac
import pickle
import unittest
from unittest.mock import Mock

from oc_google.account_binding import AccountBindingError, MetadataOperation, bind_subject, rebind_subject


KEY = b"k" * 32
INITIAL = b"fixture-enrollment-bearer"
REFRESHED = b"fixture-refreshed-bearer"
SUBJECT = b'{"id":"00123456"}'
REPLACEMENT = b'{"id":"00123457"}'


class GoogleAccountBindingTest(unittest.TestCase):
    def test_enrollment_proof_denies_catalog_until_a_verified_reopen(self):
        original = bind_subject(KEY, INITIAL, SUBJECT)
        original.require_metadata_bearer(MetadataOperation.LOAD_CODE_ASSIST, INITIAL)
        with self.assertRaisesRegex(AccountBindingError, "unavailable in this phase"):
            original.require_metadata_bearer(MetadataOperation.FETCH_AVAILABLE_MODELS, INITIAL)

        refreshed = rebind_subject(KEY, REFRESHED, SUBJECT, original.digest)
        refreshed.require_metadata_bearer(MetadataOperation.LOAD_CODE_ASSIST, REFRESHED)
        refreshed.require_metadata_bearer(MetadataOperation.FETCH_AVAILABLE_MODELS, REFRESHED)

    def test_same_subject_after_refresh_requires_same_phase_bearer(self):
        original = bind_subject(KEY, INITIAL, SUBJECT)
        refreshed = rebind_subject(KEY, REFRESHED, SUBJECT, original.digest)
        self.assertEqual(original.digest, refreshed.digest)

        for operation in MetadataOperation:
            refreshed.require_metadata_bearer(operation, REFRESHED)
            with self.assertRaises(AccountBindingError):
                refreshed.require_metadata_bearer(operation, INITIAL)

    def test_replacement_subject_or_bearer_stops_before_metadata(self):
        original = bind_subject(KEY, INITIAL, SUBJECT)
        destination = Mock()

        def metadata(subject_response, bearer):
            proof = rebind_subject(KEY, REFRESHED, subject_response, original.digest)
            proof.require_metadata_bearer(MetadataOperation.LOAD_CODE_ASSIST, bearer)
            destination()

        with self.assertRaisesRegex(AccountBindingError, "subject does not match"):
            metadata(REPLACEMENT, REFRESHED)
        with self.assertRaisesRegex(AccountBindingError, "bearer does not match"):
            metadata(SUBJECT, b"replacement-bearer")
        destination.assert_not_called()
        metadata(SUBJECT, REFRESHED)
        destination.assert_called_once_with()

    def test_digest_is_keyed_length_framed_and_preserves_opaque_digits(self):
        issuer = b"https://www.googleapis.com/oauth2/v2/userinfo"
        message = (
            b"oc-sandbox/google/account-subject/v1\x00"
            + len(issuer).to_bytes(4, "big") + issuer
            + b"\x00\x00\x00\x08" + b"00123456"
        )
        digest = bind_subject(KEY, INITIAL, SUBJECT).digest
        self.assertEqual(digest, hmac.digest(KEY, message, "sha256"))
        self.assertEqual(digest, bind_subject(KEY, INITIAL, b' { "id": "00123456" }\n').digest)
        self.assertNotEqual(digest, bind_subject(KEY, INITIAL, b'{"id":"123456"}').digest)
        self.assertNotEqual(digest, bind_subject(b"b" * 32, INITIAL, SUBJECT).digest)

    def test_subject_body_must_be_bounded_exact_utf8_object(self):
        invalid = (
            b"", b"null", b'["00123456"]', b"{}", b'{"sub":"00123456"}',
            b'{"id":"00123456","email":"synthetic@example.invalid"}',
            b'{"id":"00123456","hd":"example.invalid"}',
            b'{"id":"00123456","id":"00123456"}',
            rb'{"id":"00123456","\u0069d":"00123456"}',
            b'{"id":{"id":"00123456"}}', b'{"id":00123456}', b'{"id":123456}',
            b'{"id":true}', b'{"id":NaN}', b'{"id":null}', b'{"id":""}',
            b'{"id":"-1"}', b'{"id":"1e3"}', b'{"id":"1 "}', b'{"id":"1\x00"}',
            '{"id":"１２３"}'.encode(), b'{"id":"' + b"1" * 65 + b'"}',
            b'{"id":"00123456"}{}', b'{"id":"00123456","bad":"\xff"}',
            b" " * 1024 + SUBJECT, SUBJECT.decode(),
        )
        for body in invalid:
            with self.subTest(body=body), self.assertRaisesRegex(AccountBindingError, "^Invalid Google account subject response$"):
                bind_subject(KEY, INITIAL, body)
        bind_subject(KEY, INITIAL, b'{"id":"' + b"1" * 64 + b'"}')

    def test_reopen_requires_original_digest_and_valid_key(self):
        original = bind_subject(KEY, INITIAL, SUBJECT)
        for expected in (None, b"", original.digest.hex(), b"x" * 31):
            with self.subTest(expected=expected), self.assertRaises(AccountBindingError):
                rebind_subject(KEY, REFRESHED, SUBJECT, expected)
        with self.assertRaises(AccountBindingError):
            rebind_subject(b"x" * 32, REFRESHED, SUBJECT, original.digest)
        with self.assertRaises(AccountBindingError):
            bind_subject(b"k" * 31, INITIAL, SUBJECT)

    def test_proof_is_metadata_only_and_never_reprs_or_serializes_the_bearer(self):
        proof = bind_subject(KEY, INITIAL, SUBJECT)
        for operation in ("streamGenerateContent", "loadCodeAssist", None):
            with self.subTest(operation=operation), self.assertRaises(AccountBindingError):
                proof.require_metadata_bearer(operation, INITIAL)
        for bearer in ("fixture-enrollment-bearer", b"", b"a b", b"a\r\n", b"z" * 8193):
            with self.subTest(bearer_type=type(bearer)), self.assertRaises(AccountBindingError):
                proof.require_metadata_bearer(MetadataOperation.LOAD_CODE_ASSIST, bearer)
        self.assertNotIn(INITIAL.decode(), repr(proof))
        self.assertNotIn("00123456", repr(proof))
        with self.assertRaisesRegex(TypeError, "^Google account proof must remain in memory$"):
            pickle.dumps(proof)

    def test_parser_denial_does_not_carry_the_invalid_json_source(self):
        with self.assertRaises(AccountBindingError) as denied:
            bind_subject(KEY, INITIAL, b'{"id":"fixture-only-sensitive-input"')
        self.assertIsNone(denied.exception.__context__)
        self.assertNotIn("fixture-only-sensitive-input", str(denied.exception))


if __name__ == "__main__":
    unittest.main()
