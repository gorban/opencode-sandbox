"""Offline wire, accounting and retirement checks for the fixed Flash fixture."""

from copy import copy, deepcopy
import json
import pickle
import unittest
from dataclasses import replace
from threading import Event, RLock, Thread
from unittest.mock import patch

from oc_google import generation


_HEADER_END = b"\r\n\r\n"


def packet(first, fields, body):
    lines = [first, *fields, b"Content-Length: " + str(len(body)).encode("ascii")]
    return b"\r\n".join(lines) + _HEADER_END + body


def request_body():
    return {
        "model": "gemini-2.5-flash", "project": "oc-synthetic-stage-a",
        "request": {
            "contents": [{"role": "user", "parts": [{"text": "Reply with exactly: ok"}]}],
            "sessionId": "0",
            "systemInstruction": {"role": "user", "parts": [{"text": "Fixture system instruction."}]},
            "toolConfig": {"functionCallingConfig": {"mode": "AUTO"}},
            "generationConfig": {"maxOutputTokens": 65535},
        },
    }


def request(document=None, *, body=None):
    if body is None:
        body = json.dumps(document if document is not None else request_body()).encode("ascii")
    return packet(b"POST /v1internal:streamGenerateContent?alt=sse HTTP/1.1", [
        b"Host: gemini-fixture.invalid", b"Content-Type: application/json", b"Connection: close",
        b"Authorization: Bearer fixture-generation",
    ], body)


def response_body():
    return {"response": {
        "modelVersion": "fixture-gemini-2.5-flash-v1",
        "candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}]}, "finishReason": "STOP", "index": 0}],
        "usageMetadata": {"promptTokenCount": 7, "candidatesTokenCount": 1, "thoughtsTokenCount": 0,
                          "totalTokenCount": 8},
    }}


def event(document):
    return b"data: " + json.dumps(document).encode("ascii") + b"\n\n"


def response(document=None, *, body=None):
    if body is None:
        body = event(document if document is not None else response_body())
    return packet(b"HTTP/1.1 200 OK", [b"Content-Type: text/event-stream", b"Connection: close"], body)


class WireTests(unittest.TestCase):
    def test_projection_rebuilds_exact_model_and_restrictive_settings(self):
        projected = generation.project_generation(request(), end_of_input=True)
        head, body = projected.split(_HEADER_END)
        lines = head.split(b"\r\n")
        self.assertEqual(lines[0], b"POST /v1internal:streamGenerateContent?alt=sse HTTP/1.1")
        self.assertCountEqual(lines[1:], [
            b"host: gemini-fixture.invalid", b"content-type: application/json", b"connection: close",
            b"authorization: Bearer fixture-generation", b"content-length: " + str(len(body)).encode("ascii"),
        ])
        expected = request_body()
        expected["request"]["toolConfig"] = {"functionCallingConfig": {"mode": "NONE"}}
        expected["request"]["generationConfig"] = {"maxOutputTokens": 64, "thinkingConfig": {"thinkingBudget": 0}}
        self.assertEqual(json.loads(body), expected)
        self.assertEqual(body, json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("ascii"))

    def test_rejects_invalid_request_framing(self):
        good = request()
        cases = [
            good.replace(b"POST", b"GET", 1), good.replace(b"?alt=sse", b""),
            good.replace(b"gemini-fixture.invalid", b"daily-cloudcode-pa.googleapis.com"),
            good.replace(b"Host:", b"host: gemini-fixture.invalid\r\nHost:"),
            good.replace(b"Content-Length: ", b"Content-Length: 0"),
            good.replace(b"Host: ", b"Host:\t"), good.replace(b"Host:", b"X-Other: value\r\nHost:"),
            good.replace(b"Host:", b"Transfer-Encoding: chunked\r\nHost:"),
            good.replace(b"Host:", b"Expect: 100-continue\r\nHost:"),
            good.replace(b"Host:", b"Content-Encoding: gzip\r\nHost:"),
            good.replace(b"fixture-generation", b"wrong"), good + b"late bytes", good[:-1],
            good.replace(b"Authorization: ", b"Authorization: " + b"x" * 8192),
            request(body=b"x" * 24577), request(body=b"\xff"),
            request(body=b"{" + b"\"x\":[" * 1200 + b"0" + b"]}" * 1200),
        ]
        for invalid in cases:
            with self.subTest(packet=invalid[:100]), self.assertRaises(generation.GenerationRefused):
                generation.project_generation(invalid, end_of_input=True)
        with self.assertRaises(generation.GenerationRefused):
            generation.project_generation(good, end_of_input=False)

    def test_rejects_drift_in_native_envelope(self):
        for scope, field, item in (
            ((), "model", "MODEL_GOOGLE_GEMINI_2_5_FLASH"), ((), "project", "other"), ((), "tools", []),
            (("request",), "tools", []), (("request",), "cachedContent", "file"), (("request",), "sessionId", 0),
            (("request", "generationConfig"), "maxOutputTokens", 65535.0),
            (("request", "generationConfig"), "maxOutputTokens", 65536),
            (("request", "generationConfig"), "candidateCount", 1),
            (("request", "generationConfig"), "thinkingConfig", {"thinkingLevel": "low"}),
            (("request", "toolConfig", "functionCallingConfig"), "mode", "NONE"),
            (("request",), "contents", [{"role": "user", "parts": [{"text": generation.PROMPT}, {"inlineData": {}}]}]),
            (("request",), "contents", [{"role": "user", "parts": [{"text": "wrong"}]}]),
        ):
            with self.subTest(scope=scope, field=field, item=item):
                document = request_body()
                target = document
                for key in scope:
                    target = target[key]
                target[field] = item
                with self.assertRaises(generation.GenerationRefused):
                    generation.project_generation(request(document), end_of_input=True)
        duplicate = json.dumps(request_body()).encode("ascii").replace(b'"maxOutputTokens":', b'"maxOutputTokens": 1, "maxOutputTokens":')
        with self.assertRaises(generation.GenerationRefused):
            generation.project_generation(request(body=duplicate), end_of_input=True)

    def test_reply_accepts_exact_usage_bound_and_optional_zero_tool_count(self):
        result = response_body()
        result["response"]["usageMetadata"] = {"promptTokenCount": 128, "candidatesTokenCount": 64,
                                               "thoughtsTokenCount": 0, "toolUsePromptTokenCount": 0,
                                               "totalTokenCount": 192}
        self.assertEqual(generation.validate_generation_reply(response(result), end_of_input=True), event(result))
        self.assertEqual(generation.validate_generation_reply(response(), end_of_input=True), event(response_body()))

    def test_reply_refuses_inexact_counts_or_typed_values(self):
        for key, value in (
            ("promptTokenCount", 129), ("promptTokenCount", 0), ("candidatesTokenCount", 65),
            ("candidatesTokenCount", 0), ("candidatesTokenCount", True), ("candidatesTokenCount", 1.0),
            ("thoughtsTokenCount", 1), ("thoughtsTokenCount", False), ("toolUsePromptTokenCount", 1),
            ("toolUsePromptTokenCount", False), ("totalTokenCount", 7), ("totalTokenCount", 193),
        ):
            with self.subTest(key=key, value=value):
                result = response_body()
                usage = result["response"]["usageMetadata"]
                usage[key] = value
                if key != "totalTokenCount":
                    usage["totalTokenCount"] = sum(count for name, count in usage.items() if name != "totalTokenCount")
                with self.assertRaises(generation.GenerationRefused):
                    generation.validate_generation_reply(response(result), end_of_input=True)

    def test_reply_requires_eof_exact_framing_and_no_extra_events(self):
        ok = event(response_body())
        invalid = [response(body=body) for body in (
            ok + b"late bytes", ok + ok, ok.replace(b"\n", b"\r\n"), b": comment\n" + ok,
            b"event: update\n" + ok, ok[:-1], ok + b"\n", b"data: {\xff}\n\n", b"x" * 8193,
            ok.replace(b'"index": 0', b'"index": 1, "index": 0'),
        )]
        invalid += [response() + b"late bytes", response().replace(b"200 OK", b"301 Moved"),
                    response().replace(b"text/event-stream", b"application/json"),
                    response().replace(b"Content-Length:", b"Content-Encoding: gzip\r\nContent-Length:")]
        for bad in invalid:
            with self.subTest(packet=bad[:100]), self.assertRaises(generation.GenerationRefused):
                generation.validate_generation_reply(bad, end_of_input=True)
        with self.assertRaises(generation.GenerationRefused):
            generation.validate_generation_reply(response(), end_of_input=False)

    def test_reply_refuses_tools_thoughts_grounding_and_unknown_fields(self):
        for note in ("functionCall", "functionResponse", "executableCode", "codeExecutionResult", "inlineData",
                     "fileData", "thought", "thoughtSignature", "unknown"):
            with self.subTest(note=note):
                document = response_body()
                document["response"]["candidates"][0]["content"]["parts"][0][note] = {}
                with self.assertRaises(generation.GenerationRefused):
                    generation.validate_generation_reply(response(document), end_of_input=True)
        for scope, field, value in (
            ((), "metadata", {}), (("response",), "modelVersion", "wrong"),
            (("response",), "promptFeedback", {}), (("response", "candidates", 0), "groundingMetadata", {}),
            (("response", "candidates", 0), "finishReason", "MAX_TOKENS"),
            (("response", "candidates", 0), "index", False),
            (("response", "usageMetadata"), "toolUsePromptTokensDetails", []),
        ):
            with self.subTest(scope=scope, field=field):
                document = response_body()
                target = document
                for key in scope:
                    target = target[key]
                target[field] = value
                with self.assertRaises(generation.GenerationRefused):
                    generation.validate_generation_reply(response(document), end_of_input=True)


class AttemptTests(unittest.TestCase):
    def setUp(self):
        self.binding = generation.GenerationBinding(object(), object(), 1, "gemini-2.5-flash")
        self.now = 10.0
        self.active = True

    def create(self, packet=None, *, eof=True, authorized=None):
        sink = generation.FakeDestination(response() if packet is None else packet, end_of_input=eof)
        owner = authorized if authorized is not None else lambda binding: self.active and binding is self.binding
        self.attempt = generation.GenerationAttempt(self.binding, sink, authorized=owner, now=lambda: self.now)
        return sink

    def run_attempt(self, packet=None, *, binding=None):
        binding = self.binding if binding is None else binding
        return self.attempt.run(binding, request() if packet is None else packet, end_of_input=True)

    def assert_receipt(self, state, native, attempts, complete, released=0):
        self.assertEqual(self.attempt.receipt(), generation.GenerationReceipt(state, native, attempts, complete, released))

    def test_success_releases_once_and_spends_attempt_for_every_caller(self):
        self.create()
        alias_wrapper = self.attempt.run
        result = self.run_attempt()
        self.assertIs(type(result), bytes)
        self.assertEqual(result, event(response_body()))
        with self.assertRaises(generation.GenerationRefused):
            alias_wrapper(self.binding, request(), end_of_input=True)
        self.assert_receipt(generation.GenerationState.SENT, 2, 1, 1, 1)

    def test_attempt_takes_no_observable_release_callback(self):
        self.create()
        with self.assertRaises(TypeError):
            self.attempt.run(self.binding, request(), end_of_input=True,
                             release=lambda *_: self.fail("release callback ran"))
        self.assert_receipt(generation.GenerationState.UNSPENT, 0, 0, 0)

    def test_alias_epoch_and_selected_binding_are_exact(self):
        with self.assertRaises(generation.GenerationRefused):
            replace(self.binding, alias="MODEL_GOOGLE_GEMINI_2_5_FLASH")
        with self.assertRaises(generation.GenerationRefused):
            replace(self.binding, epoch=True)
        self.create()
        for binding in (replace(self.binding), replace(self.binding, epoch=2), replace(self.binding, job=object())):
            with self.assertRaises(generation.GenerationRefused):
                self.run_attempt(binding=binding)
        self.assert_receipt(generation.GenerationState.UNSPENT, 3, 0, 0)

    def test_malformed_input_can_precede_valid_request_with_no_write(self):
        self.create()
        with self.assertRaises(generation.GenerationRefused):
            self.run_attempt(b"invalid")
        self.assert_receipt(generation.GenerationState.UNSPENT, 1, 0, 0)
        self.run_attempt()
        self.assert_receipt(generation.GenerationState.SENT, 2, 1, 1, 1)

    def test_independent_recording_and_retirement_bind_attempt_and_digest(self):
        sink = self.create()
        self.run_attempt()
        first_receipt = sink.receipt()
        self.assertIsNotNone(first_receipt)
        self.assertEqual(first_receipt.packet_digest, generation.sha256(generation.project_generation(
            request(), end_of_input=True)).digest())
        with self.assertRaises(generation.GenerationRefused):
            generation.GenerationAttempt(self.binding, sink, authorized=lambda _binding: True)
        self.assertIs(sink.receipt(), first_receipt)

    def test_matching_write_count_cannot_settle_with_the_wrong_receipt_digest(self):
        self.create()
        original = generation.FakeDestination.receipt

        def receipt(sink):
            return replace(original(sink), packet_digest=b"wrong digest")

        with patch.object(generation.FakeDestination, "receipt", receipt), self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, 1)

    def test_legacy_run_refuses_a_substituted_write_receipt_before_read(self):
        self.create()
        original = generation.FakeDestination.receipt

        def copied(sink):
            return copy(original(sink))

        with (
            patch.object(generation.FakeDestination, "receipt", copied),
            patch.object(generation.FakeDestination, "read", side_effect=AssertionError("unverified sink receipt reached read")),
            self.assertRaisesRegex(generation.GenerationRefused, "dispatch is unconfirmed"),
        ):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, 1)

    def test_revocation_after_claim_before_first_write(self):
        def authorized(_binding):
            if self.attempt.receipt().state is generation.GenerationState.CLAIMED:
                self.attempt.revoke()
            return True
        self.create(authorized=authorized)
        with self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 0, 0)
        with self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNCERTAIN, 2, 0, 0)

    def test_failed_initial_authority_check_cannot_be_retried(self):
        def authorized(_binding):
            if not self.active:
                raise OSError("authority check failed")
            return True

        self.active = False
        self.create(authorized=authorized)
        with self.assertRaises(OSError):
            self.run_attempt()
        self.active = True
        with self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNSPENT, 2, 0, 0)

    def test_revocation_inside_writer_denies_at_fake_acceptance(self):
        self.create()
        original = generation.FakeDestination.write

        def write(sink, *args, **kwargs):
            self.attempt.revoke()
            return original(sink, *args, **kwargs)
        with patch.object(generation.FakeDestination, "write", write), self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, 0)

    def test_liveness_loss_during_dispatch_holds_even_after_complete_record(self):
        self.create()
        original = generation.FakeDestination.write

        def write(sink, *args, **kwargs):
            result = original(sink, *args, **kwargs)
            self.active = False
            return result
        with patch.object(generation.FakeDestination, "write", write), self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.active = True
        with self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNCERTAIN, 2, 1, 1)

    def test_incomplete_write_and_unknown_after_receipt_are_spent(self):
        original = generation.FakeDestination.write

        def after(sink, *args, **kwargs):
            original(sink, *args, **kwargs)
            raise OSError("write completion unknown")
        for write, failure, complete in ((lambda *_a, **_k: 1, generation.GenerationRefused, 0),
                                         (lambda *_a, **_k: True, generation.GenerationRefused, 0), (after, OSError, 1)):
            with self.subTest(complete=complete):
                self.create()
                with patch.object(generation.FakeDestination, "write", write), self.assertRaises(failure):
                    self.run_attempt()
                self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, complete)

    def test_invalid_suffix_non_eof_or_unconfirmed_retirement_never_releases(self):
        valid = response()
        bad = response(body=event(response_body()) + b'data: {"functionCall":{}}\n\n')
        for body, eof, uncertain in ((bad, True, False), (valid, False, False), (valid, True, True)):
            with self.subTest(eof=eof, uncertain=uncertain):
                self.create(body, eof=eof)
                retire = (lambda *_a, **_k: True) if uncertain else generation.FakeDestination.retire
                with patch.object(generation.FakeDestination, "retire", retire), self.assertRaises(generation.GenerationRefused):
                    self.run_attempt()
                self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, 1)

    def test_retirement_for_another_attempt_cannot_settle(self):
        original = generation.FakeDestination.retire
        self.create()

        def retire(sink, receipt, **kwargs):
            real = original(sink, receipt, **kwargs)
            swapped = replace(receipt, attempt=object())
            return replace(real, receipt=swapped)
        with patch.object(generation.FakeDestination, "retire", retire), self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, 1)

    def test_retirement_proof_must_be_the_sink_record_even_with_exact_visit(self):
        original = generation.FakeDestination.retire
        for record in (False, True):
            with self.subTest(record=record):
                self.create()

                def retire(sink, receipt, **kwargs):
                    if record:
                        original(sink, receipt, **kwargs)
                    return generation._Retirement(receipt)

                with patch.object(generation.FakeDestination, "retire", retire), self.assertRaises(generation.GenerationRefused):
                    self.run_attempt()
                self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, 1)

    def test_authority_loss_after_fake_retirement_never_releases(self):
        self.create()
        original = generation.FakeDestination.retire

        def retire(sink, *args, **kwargs):
            receipt = original(sink, *args, **kwargs)
            self.attempt.revoke()
            return receipt
        with patch.object(generation.FakeDestination, "retire", retire), self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, 1)

    def test_reentry_while_unspent_and_during_retirement_cannot_change_outer_outcome(self):
        entered = False
        original = generation.FakeDestination.retire

        def authorized(_binding):
            nonlocal entered
            if not entered:
                entered = True
                with self.assertRaises(generation.GenerationRefused):
                    self.run_attempt()
                self.assert_receipt(generation.GenerationState.UNSPENT, 2, 0, 0)
            return True

        def retire(sink, *args, **kwargs):
            with self.assertRaises(generation.GenerationRefused):
                self.run_attempt()
            self.assert_receipt(generation.GenerationState.SENT, 3, 1, 1)
            return original(sink, *args, **kwargs)

        self.create(authorized=authorized)
        with patch.object(generation.FakeDestination, "retire", retire):
            self.assertEqual(self.run_attempt(), event(response_body()))
        self.assert_receipt(generation.GenerationState.SENT, 3, 1, 1, 1)

    def test_cross_thread_revocation_during_paused_fake_io_returns_no_reply(self):
        for stage in ("read", "retire"):
            with self.subTest(stage=stage):
                self.create()
                original = getattr(generation.FakeDestination, stage)
                paused, resume, revoked = Event(), Event(), Event()
                replies, failures = [], []

                def pause(sink, *args, **kwargs):
                    paused.set()
                    if not resume.wait(5):
                        raise RuntimeError("test fake I/O remained paused")
                    return original(sink, *args, **kwargs)

                def run():
                    try:
                        replies.append(self.run_attempt())
                    except BaseException as error:
                        failures.append(error)

                def revoke():
                    self.attempt.revoke()
                    revoked.set()

                runner = Thread(target=run, daemon=True)
                revoker = Thread(target=revoke, daemon=True)
                with patch.object(generation.FakeDestination, stage, pause):
                    runner.start()
                    try:
                        self.assertTrue(paused.wait(2))
                        revoker.start()
                        self.assertTrue(revoked.wait(2), "revocation waited for paused fake I/O")
                    finally:
                        resume.set()
                        runner.join(2)
                        if revoker.ident is not None:
                            revoker.join(2)
                self.assertFalse(runner.is_alive() or revoker.is_alive())
                self.assertEqual(replies, [])
                self.assertEqual(len(failures), 1)
                self.assertIsInstance(failures[0], generation.GenerationRefused)
                self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, 1)

    def test_concurrent_replay_cannot_settle_while_owner_reads(self):
        self.create()
        original = generation.FakeDestination.read
        paused, resume, replay_finished = Event(), Event(), Event()
        replies, failures = [], []

        def read(sink, *args, **kwargs):
            paused.set()
            if not resume.wait(5):
                raise RuntimeError("test fake read remained paused")
            return original(sink, *args, **kwargs)

        def run():
            replies.append(self.run_attempt())

        def replay():
            try:
                self.run_attempt()
            except generation.GenerationRefused as error:
                failures.append(error)
            finally:
                replay_finished.set()

        owner = Thread(target=run, daemon=True)
        contender = Thread(target=replay, daemon=True)
        with patch.object(generation.FakeDestination, "read", read):
            owner.start()
            try:
                self.assertTrue(paused.wait(2))
                contender.start()
                self.assertTrue(replay_finished.wait(2))
                self.assert_receipt(generation.GenerationState.SENT, 2, 1, 1)
            finally:
                resume.set()
                owner.join(2)
                if contender.ident is not None:
                    contender.join(2)
        self.assertFalse(owner.is_alive() or contender.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertEqual(replies, [event(response_body())])
        self.assert_receipt(generation.GenerationState.SENT, 2, 1, 1, 1)

    def test_reentry_during_initial_clock_read_cannot_open_another_attempt(self):
        started = False

        def clock():
            nonlocal started
            if not started:
                started = True
                with self.assertRaises(generation.GenerationRefused):
                    self.run_attempt()
                self.assert_receipt(generation.GenerationState.UNSPENT, 2, 0, 0)
            return self.now

        self.attempt = generation.GenerationAttempt(
            self.binding, generation.FakeDestination(response(), end_of_input=True),
            authorized=lambda _binding: True, now=clock,
        )
        self.run_attempt()
        self.assert_receipt(generation.GenerationState.SENT, 2, 1, 1, 1)

    def test_one_deadline_across_callbacks_and_requests(self):
        self.create()
        with self.assertRaises(generation.GenerationRefused):
            self.run_attempt(b"invalid")
        self.now = 12.5
        with self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNSPENT, 2, 0, 0)

        self.now = 10.0
        self.create()
        original = generation.FakeDestination.read

        def read(sink, *args, **kwargs):
            self.assertEqual(kwargs["deadline"], 12.5)
            reply = original(sink, *args, **kwargs)
            self.now = 12.5
            return reply
        with patch.object(generation.FakeDestination, "read", read), self.assertRaises(generation.GenerationRefused):
            self.run_attempt()
        self.assert_receipt(generation.GenerationState.UNCERTAIN, 1, 1, 1)


class SplitAttemptTests(unittest.TestCase):
    def setUp(self):
        self.binding = generation.GenerationBinding(object(), object(), 1, generation.MODEL_ALIAS)
        self.now = 10.0
        self.current = True

    def create(self, *, authorized=None):
        sink = generation.FakeDestination(response(), end_of_input=True)
        if authorized is None:
            authorized = lambda exact: self.current and exact is self.binding
        return generation.GenerationAttempt(self.binding, sink, authorized=authorized, now=lambda: self.now), sink

    def prepare(self, attempt, *, deadline=None):
        return attempt.prepare(self.binding, request(), end_of_input=True, deadline=deadline)

    def test_split_uses_exact_evidence_and_only_checks_owner_inside_effect_and_settlement(self):
        checking_authority = True

        def authorized(binding):
            self.assertTrue(checking_authority, "outside observation invoked the owner's check")
            return binding is self.binding

        attempt, sink = self.create(authorized=authorized)
        expected_packet = generation.project_generation(request(), end_of_input=True)
        with patch.object(generation, "project_generation", return_value=expected_packet) as projection:
            prepared = self.prepare(attempt)
            projection.assert_called_once()
        self.assertEqual(prepared.byte_count, len(expected_packet))
        self.assertEqual(prepared.packet_digest, generation.sha256(expected_packet).digest())
        self.assertIsNone(sink.receipt())
        in_effect = True
        checks = []

        def admit():
            checks.append(in_effect)
            return in_effect

        write = attempt.write_prepared(prepared, admit=admit)
        in_effect = False
        self.assertEqual(checks, [True])
        self.assertIs(write.sink_receipt, sink.receipt())
        self.assertEqual((write.byte_count, write.packet_digest), (prepared.byte_count, prepared.packet_digest))
        self.assertEqual(attempt.receipt().releases, 0)

        checking_authority = False
        completed = attempt.observe(write)
        self.assertIs(completed.write, write)
        self.assertIs(completed.retirement.receipt, write.sink_receipt)
        self.assertEqual(completed.reply_digest, generation.sha256(event(response_body())).digest())
        self.assertFalse(hasattr(completed, "body"))
        self.assertEqual(attempt.receipt().releases, 0)

        checking_authority = True
        self.assertEqual(attempt.settle(write, completed), event(response_body()))
        attempt.revoke()
        with self.assertRaises(generation.GenerationRefused):
            attempt.settle(write, completed)
        self.assertEqual(attempt.receipt(), generation.GenerationReceipt(generation.GenerationState.SENT, 1, 1, 1, 1))

    def test_copy_foreign_preparation_and_revocation_have_no_effect(self):
        attempt, sink = self.create()
        other, _ = self.create()
        prepared = self.prepare(attempt)
        for fake in (copy(prepared), replace(prepared), self.prepare(other)):
            with self.assertRaises(generation.GenerationRefused):
                attempt.write_prepared(fake, admit=lambda: self.fail("Rejected preparation queried the journal"))
        self.assertEqual(attempt.receipt().destination_attempts, 0)
        for resource in (attempt, sink):
            for clone in (copy, deepcopy, pickle.dumps):
                with self.subTest(kind=type(resource).__name__, operation=clone.__name__):
                    with self.assertRaisesRegex(TypeError, "exclusive fixture ownership"):
                        clone(resource)
        attempt.revoke()
        self.assertEqual(attempt.receipt().state, generation.GenerationState.UNSPENT)
        with self.assertRaises(generation.GenerationRefused):
            attempt.write_prepared(prepared, admit=lambda: self.fail("Revoked preparation queried the journal"))
        self.assertIsNone(sink.receipt())

    def test_finite_deadline_cannot_be_extended_by_repreparing(self):
        attempt, sink = self.create()
        with self.assertRaises(generation.GenerationRefused):
            attempt.prepare(self.binding, b"invalid", end_of_input=True, deadline=10.25)
        self.now = 10.1
        prepared = self.prepare(attempt, deadline=20.0)
        self.now = 10.25
        with self.assertRaises(generation.GenerationRefused):
            attempt.write_prepared(prepared, admit=lambda: self.fail("Expired preparation queried the journal"))
        self.assertIsNone(sink.receipt())
        self.assertEqual(attempt.receipt().destination_attempts, 0)

    def test_missing_or_revoked_effect_has_no_independent_sink_receipt(self):
        for status in ("invalid", "non-bool", "revoked", "owner-lost"):
            with self.subTest(status=status):
                self.current = True
                attempt, sink = self.create()
                prepared = self.prepare(attempt)
                checks = []

                def admit():
                    checks.append(status)
                    if status == "revoked":
                        attempt.revoke()
                    if status == "owner-lost":
                        self.current = False
                    return {"invalid": False, "non-bool": 1}.get(status, True)

                with self.assertRaises(generation.GenerationRefused):
                    attempt.write_prepared(prepared, admit=admit)
                self.assertIsNone(sink.receipt())
                self.assertEqual(attempt.receipt(), generation.GenerationReceipt(
                    generation.GenerationState.UNCERTAIN, 1, 1, 0, 0,
                ))
                with self.assertRaises(generation.GenerationRefused):
                    attempt.write_prepared(prepared, admit=admit)
                self.assertEqual(checks, [status])

    def test_captured_write_check_is_unusable_after_synchronous_effect(self):
        attempt, _ = self.create()
        original = generation.FakeDestination.write
        saved = []
        admissions = []

        def write(sink, *args, **kwargs):
            saved.append((kwargs["check"], kwargs["deadline"]))
            return original(sink, *args, **kwargs)

        def admit():
            admissions.append(True)
            return True

        with patch.object(generation.FakeDestination, "write", write):
            attempt.write_prepared(self.prepare(attempt), admit=admit)
        check, deadline = saved[0]
        with self.assertRaises(generation.GenerationRefused):
            check(deadline)
        self.assertEqual(admissions, [True])

    def test_substituted_same_shape_sink_receipt_fails_at_write_boundary(self):
        attempt, sink = self.create()
        original = generation.FakeDestination.receipt

        def copied(sink):
            return copy(original(sink))

        with patch.object(generation.FakeDestination, "receipt", copied):
            with self.assertRaisesRegex(generation.GenerationRefused, "dispatch is unconfirmed"):
                attempt.write_prepared(self.prepare(attempt), admit=lambda: True)
        self.assertIsNotNone(sink.receipt())
        self.assertEqual(attempt.receipt(), generation.GenerationReceipt(
            generation.GenerationState.UNCERTAIN, 1, 1, 1, 0,
        ))

    def test_replayed_or_copied_write_and_completion_cannot_release(self):
        attempt, sink = self.create()
        write = attempt.write_prepared(self.prepare(attempt), admit=lambda: True)
        with self.assertRaises(generation.GenerationRefused):
            attempt.observe(copy(write))
        observed = attempt.observe(write)
        with self.assertRaises(generation.GenerationRefused):
            attempt.observe(write)
        with self.assertRaises(generation.GenerationRefused):
            attempt.settle(copy(write), observed)
        with self.assertRaises(generation.GenerationRefused):
            attempt.settle(write, copy(observed))
        with self.assertRaises(generation.GenerationRefused):
            attempt.settle(write, observed)
        self.assertIs(sink.receipt(), write.sink_receipt)
        self.assertEqual(attempt.receipt(), generation.GenerationReceipt(
            generation.GenerationState.UNCERTAIN, 1, 1, 1, 0,
        ))

    def test_revoke_before_settlement_immediately_holds_the_exact_write(self):
        for observed in (False, True):
            with self.subTest(observed=observed):
                attempt, sink = self.create()
                prepared = self.prepare(attempt)
                write = attempt.write_prepared(prepared, admit=lambda: True)
                completion = attempt.observe(write) if observed else None
                self.assertEqual(attempt.receipt().state, generation.GenerationState.SENT)
                attempt.revoke()
                attempt.revoke()
                held = generation.GenerationReceipt(generation.GenerationState.UNCERTAIN, 1, 1, 1, 0)
                self.assertEqual(attempt.receipt(), held)
                with self.assertRaises(generation.GenerationRefused):
                    attempt.settle(write, completion)
                with self.assertRaises(generation.GenerationRefused):
                    attempt.observe(write)
                with self.assertRaises(generation.GenerationRefused):
                    attempt.write_prepared(prepared, admit=lambda: self.fail("Revoked write queried the journal"))
                self.assertIs(sink.receipt(), write.sink_receipt)
                self.assertEqual(attempt.receipt(), held)

    def test_owner_loss_before_settlement_keeps_observed_reply_private(self):
        attempt, _ = self.create()
        write = attempt.write_prepared(self.prepare(attempt), admit=lambda: True)
        observed = attempt.observe(write)
        self.current = False
        with self.assertRaises(generation.GenerationRefused):
            attempt.settle(write, observed)
        self.assertEqual(attempt.receipt().releases, 0)

    def test_blocked_observation_allows_shared_fence_revocation_and_no_new_write(self):
        for method in ("read", "retire", "confirms_retirement"):
            with self.subTest(method=method):
                self.assert_observation_can_be_revoked(method)

    def assert_observation_can_be_revoked(self, method):
        shared_fence = RLock()
        attempt, sink = self.create()
        prepared = self.prepare(attempt)
        with shared_fence:
            write = attempt.write_prepared(prepared, admit=lambda: True)
        original = getattr(generation.FakeDestination, method)
        paused, resume, revoked = Event(), Event(), Event()
        observations, failures = [], []

        def pause(sink, *args, **kwargs):
            paused.set()
            if not resume.wait(5):
                raise RuntimeError("synthetic observation did not resume")
            return original(sink, *args, **kwargs)

        def observe():
            try:
                observations.append(attempt.observe(write))
            except BaseException as exc:
                failures.append(exc)

        def revoke():
            with shared_fence:
                attempt.revoke()
                revoked.set()

        reader = Thread(target=observe, daemon=True)
        disposer = Thread(target=revoke, daemon=True)
        with patch.object(generation.FakeDestination, method, pause):
            reader.start()
            try:
                self.assertTrue(paused.wait(2))
                disposer.start()
                self.assertTrue(revoked.wait(2), "stalled observation held the owner or leaf fence")
                with self.assertRaises(generation.GenerationRefused):
                    attempt.write_prepared(prepared, admit=lambda: self.fail("Replay queried the journal"))
            finally:
                resume.set()
                reader.join(2)
                if disposer.ident is not None:
                    disposer.join(2)
        self.assertFalse(reader.is_alive() or disposer.is_alive())
        self.assertEqual(observations, [])
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], generation.GenerationRefused)
        self.assertIs(sink.receipt(), write.sink_receipt)
        self.assertEqual(attempt.receipt(), generation.GenerationReceipt(
            generation.GenerationState.UNCERTAIN, 1, 1, 1, 0,
        ))
