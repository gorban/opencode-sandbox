"""Tests for interactive Responses request sanitizer, reasoning vault, and fail-closed SSE projector."""

import json
import unittest

from oc_openai.session_protocol import (
    HANDLE_PREFIX,
    ReasoningVault,
    RequestRefused,
    SessionStreamProjector,
    StreamAborted,
    format_models_response,
    parse_worker_request,
)


def _http_req(method, path, body=None, *, token="tok-secret", host="127.0.0.1:8401", extra_headers=None):
    raw_body = b"" if body is None else json.dumps(body).encode("utf-8")
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"Authorization: Bearer {token}",
    ]
    if body is not None:
        lines.append("Content-Type: application/json")
        lines.append(f"Content-Length: {len(raw_body)}")
    if extra_headers:
        lines.extend(extra_headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + raw_body


class SessionProtocolTests(unittest.TestCase):
    def setUp(self):
        self.models = frozenset({"gpt-6.2-sol", "gpt-6.2-mini"})
        self.vault = ReasoningVault()

    def test_rejects_csrf_bad_host_bad_auth_and_forbidden_fields(self):
        base = {"model": "gpt-6.2-sol", "stream": True, "store": False,
                "input": [{"role": "user", "content": "hello"}]}
        bad_requests = [
            (_http_req("POST", "/v1/responses", base, extra_headers=["Origin: http://evil.invalid"]), 403),
            (_http_req("POST", "/v1/responses", base, extra_headers=["Sec-Fetch-Site: cross-site"]), 403),
            (_http_req("POST", "/v1/responses", base, extra_headers=["Cookie: a=1"]), 403),
            (_http_req("POST", "/v1/responses", base, host="evil.invalid:8401"), 403),
            (_http_req("POST", "/v1/responses", base, token="wrong"), 401),
            (_http_req("POST", "/v1/responses", {**base, "store": True}), 400),
            (_http_req("POST", "/v1/responses", {**base, "stream": False}), 400),
            (_http_req("POST", "/v1/responses", {**base, "previous_response_id": "resp_1"}), 400),
            (_http_req("POST", "/v1/responses", {**base, "metadata": {"a": "b"}}), 400),
            (_http_req("POST", "/v1/responses", {**base, "tools": [{"type": "web_search"}]}), 400),
            (_http_req("POST", "/v1/responses", {**base, "tool_choice": {"type": "web_search"}}), 400),
            (_http_req("POST", "/v1/responses", {**base, "input": [{"type": "item_reference", "id": "x"}]}), 400),
            (_http_req("POST", "/v1/responses", {**base, "input": [{"role": "user", "content": [{"type": "input_image", "image_url": "http://169.254.169.254/"}]}]}), 400),
            (_http_req("POST", "/v1/responses", {**base, "model": "unlisted-model"}), 400),
        ]
        for raw, expected_status in bad_requests:
            with self.subTest(expected_status=expected_status):
                with self.assertRaises(RequestRefused) as err:
                    parse_worker_request(raw, expected_token="tok-secret",
                                         allowed_models=self.models, vault=self.vault)
                self.assertEqual(err.exception.status, expected_status)

    def test_sanitizes_valid_request_and_omits_max_output_tokens(self):
        body = {
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "max_output_tokens": 2048,
            "tools": [{"type": "function", "name": "read", "parameters": {"type": "object"}}],
            "input": [{"role": "user", "content": "hi"}],
        }
        parsed = parse_worker_request(
            _http_req("POST", "/v1/responses", body),
            expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
        )
        self.assertEqual(parsed.route, "responses")
        self.assertNotIn("max_output_tokens", parsed.body)
        self.assertFalse(parsed.body["store"])
        self.assertTrue(parsed.body["stream"])

    def test_models_route_and_translation(self):
        parsed = parse_worker_request(
            _http_req("GET", "/v1/models"),
            expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
        )
        self.assertEqual(parsed.route, "models")
        resp = format_models_response(("gpt-6.2-sol",))
        self.assertIn(b'"object":"list"', resp)
        self.assertIn(b'"id":"gpt-6.2-sol"', resp)

    def test_reasoning_vault_binding_stripping_and_forgery_rejection(self):
        projector = SessionStreamProjector(model="gpt-6.2-sol", local_response_id="resp_local_1", vault=self.vault)
        out = []
        out.extend(projector.feed({
            "type": "response.created",
            "response": {"id": "resp_upstream_secret_1", "status": "in_progress"},
        }))
        # output_item.added must strip unfinished ciphertext!
        added = projector.feed({
            "type": "response.output_item.added", "output_index": 0,
            "item": {"type": "reasoning", "id": "rs_upstream_1", "summary": [],
                     "encrypted_content": "unfinished_secret_cipher"},
        })
        self.assertNotIn(b"unfinished_secret_cipher", b"".join(added))
        self.assertNotIn(b"rs_upstream_1", b"".join(added))

        done = projector.feed({
            "type": "response.output_item.done", "output_index": 0,
            "item": {"type": "reasoning", "id": "rs_upstream_1", "summary": [],
                     "encrypted_content": "AUTHENTIC_CIPHER_BLOB", "status": "completed"},
        })
        added_json = json.loads(added[0].split(b"data: ", 1)[1])
        done_json = json.loads(done[0].split(b"data: ", 1)[1])
        local_id = done_json["item"]["id"]
        self.assertEqual(added_json["item"]["id"], local_id)
        handle = done_json["item"]["encrypted_content"]
        self.assertTrue(handle.startswith(HANDLE_PREFIX))
        self.assertNotIn("AUTHENTIC_CIPHER_BLOB", json.dumps(done_json))
        self.assertNotIn("resp_upstream_secret_1", b"".join(out).decode())

        # Before finalize(), the staged handle MUST NOT be replayable!
        replay_body = {
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "input": [
                {"type": "reasoning", "id": local_id, "summary": [], "encrypted_content": handle},
                {"role": "user", "content": "next"},
            ],
        }
        with self.assertRaises(RequestRefused) as pre_err:
            parse_worker_request(
                _http_req("POST", "/v1/responses", replay_body),
                expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
            )
        self.assertEqual(pre_err.exception.status, 400)

        # Complete and finalize -> commits handle to ReasoningVault.
        projector.feed({
            "type": "response.completed",
            "response": {"id": "resp_upstream_secret_1", "status": "completed", "output": []},
        })
        projector.finalize()

        # Valid replay succeeds and restores authentic ciphertext & upstream item ID.
        parsed = parse_worker_request(
            _http_req("POST", "/v1/responses", replay_body),
            expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
        )
        self.assertEqual(parsed.body["input"][0]["id"], "rs_upstream_1")
        self.assertEqual(parsed.body["input"][0]["encrypted_content"], "AUTHENTIC_CIPHER_BLOB")

        # Forged ID, cross-model replay, or raw ciphertext all fail closed with HTTP 400.
        for bad_item, bad_model in (
            ({"type": "reasoning", "id": "rs_other", "summary": [], "encrypted_content": handle}, "gpt-6.2-sol"),
            ({"type": "reasoning", "id": local_id, "summary": [], "encrypted_content": handle}, "gpt-6.2-mini"),
            ({"type": "reasoning", "id": local_id, "summary": [], "encrypted_content": "raw_cipher"}, "gpt-6.2-sol"),
        ):
            with self.assertRaises(RequestRefused) as err:
                parse_worker_request(
                    _http_req("POST", "/v1/responses", {"model": bad_model, "stream": True, "store": False, "input": [bad_item]}),
                    expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
                )
            self.assertEqual(err.exception.status, 400)

    def test_buffers_function_call_completion_until_finalize_and_enforces_strict_metadata_allowlist(self):
        projector = SessionStreamProjector(model="gpt-6.2-sol", local_response_id="resp_local_2", vault=self.vault)
        projector.feed({"type": "response.created", "response": {"id": "resp_up_2", "status": "in_progress"}})
        # Benign unblocked prompt metadata is dropped host-only.
        self.assertEqual(projector.feed({
            "type": "response.metadata", "response_id": "resp_up_2", "sequence_number": 1,
            "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {"outputs": [{"is_blocked": False}]}}},
        }), [])
        # Text deltas stream live; function_call completion frames are buffered.
        text_out = projector.feed({"type": "response.output_text.delta", "delta": "hi"})
        self.assertEqual(len(text_out), 1)
        self.assertEqual(projector.feed({
            "type": "response.function_call_arguments.done", "call_id": "call_1", "arguments": "{}",
        }), [])
        self.assertEqual(projector.feed({
            "type": "response.output_item.done", "output_index": 0,
            "item": {"type": "function_call", "call_id": "call_1", "name": "read", "arguments": "{}"},
        }), [])
        self.assertEqual(projector.feed({
            "type": "response.completed",
            "response": {"id": "resp_up_2", "status": "completed", "output": [],
                         "usage": {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8}},
        }), [])
        tail = projector.finalize()
        self.assertEqual(len(tail), 3)
        self.assertEqual(projector.usage, (5, 3, 8))

        # Affirmative / unknown / guardian / bool-seq metadata MUST abort fail-closed.
        bad_metadata_events = [
            {"type": "response.metadata", "response_id": "resp_up_3", "sequence_number": True, "metadata": {}},
            {"type": "response.metadata", "response_id": "resp_up_3", "sequence_number": 1,
             "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {"outputs": [{"is_blocked": True}]}}}},
            {"type": "response.metadata", "response_id": "resp_up_3", "sequence_number": 1,
             "metadata": {"openai_chatgpt_moderation_metadata": {"unknown_signal": True}}},
            {"type": "response.metadata", "response_id": "resp_up_3", "sequence_number": 1,
             "metadata": {"openai_verification_recommendation": ["review"]}},
            {"type": "response.output_text.delta", "delta": "x", "nested": {"guardian": {"risk": "high"}}},
            {"type": "response.output_text.delta", "delta": "x", "safety_buffering": True},
        ]
        for bad in bad_metadata_events:
            p = SessionStreamProjector(model="gpt-6.2-sol", local_response_id="resp_local_3", vault=self.vault)
            p.feed({"type": "response.created", "response": {"id": "resp_up_3", "status": "in_progress"}})
            with self.subTest(bad=bad), self.assertRaises(StreamAborted):
                p.feed(bad)

    def test_gate2_regressions_strict_event_projection_buffering_and_header_bounds(self):
        # Oversized Content-Length digits raise RequestRefused (not ValueError).
        huge_cl = (
            b"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            b"Authorization: Bearer tok-secret\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + b"9" * 5000 + b"\r\n\r\n{}"
        )
        with self.assertRaises(RequestRefused) as err:
            parse_worker_request(huge_cl, expected_token="tok-secret",
                                 allowed_models=self.models, vault=self.vault)
        self.assertEqual(err.exception.status, 400)

        # Strict event projection strips unknown fields/annotations and buffers ALL function_call frames.
        p = SessionStreamProjector(model="gpt-6.2-sol", local_response_id="resp_local_4", vault=self.vault)
        p.feed({"type": "response.created", "response": {"id": "resp_up_4", "status": "in_progress"}})
        done_text = p.feed({
            "type": "response.output_text.done", "text": "clean",
            "annotations": [{"type": "url_citation", "url": "http://leak"}],
            "secret_upstream_field": "must_not_leak",
        })
        self.assertNotIn(b"must_not_leak", done_text[0])
        self.assertNotIn(b"url_citation", done_text[0])

        # function_call added + arguments.delta MUST be buffered (not emitted live).
        self.assertEqual(p.feed({
            "type": "response.output_item.added", "output_index": 0,
            "item": {"type": "function_call", "id": "fc_up_1", "call_id": "call_9", "name": "bash", "arguments": ""},
        }), [])
        self.assertEqual(p.feed({
            "type": "response.function_call_arguments.delta", "output_index": 0,
            "call_id": "call_9", "delta": '{"cmd":"id"}',
        }), [])

        # Unknown reasoning item_id and response_id mismatch both abort fail-closed.
        with self.assertRaises(StreamAborted):
            p.feed({"type": "response.reasoning_text.delta", "item_id": "rs_unknown", "delta": "x"})
        with self.assertRaises(StreamAborted):
            p.feed({"type": "response.output_text.delta", "response_id": "resp_wrong", "delta": "x"})

    def test_schema_version_bool_rejected_and_compact_json_content_type_accepted(self):
        # P2 #2a: Python bool True == 1 must be rejected for moderation schema_version.
        p = SessionStreamProjector(model="gpt-6.2-sol", local_response_id="resp_local_5", vault=self.vault)
        p.feed({"type": "response.created", "response": {"id": "resp_up_5", "status": "in_progress"}})
        with self.assertRaises(StreamAborted) as err:
            p.feed({
                "type": "response.metadata",
                "response_id": "resp_up_5",
                "sequence_number": 1,
                "metadata": {"openai_chatgpt_moderation_metadata": {"schema_version": True}},
            })
        self.assertEqual(err.exception.code, "metadata_moderation")

        # P2 #2b: RFC 9110 application/json;charset=utf-8 (without space after semicolon) is valid.
        body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "input": [{"role": "user", "content": "hi"}],
        }).encode("utf-8")
        raw = (
            "POST /v1/responses HTTP/1.1\r\n"
            "Host: 127.0.0.1:8401\r\n"
            "Authorization: Bearer tok-secret\r\n"
            "Content-Type: application/json;charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body
        parsed = parse_worker_request(
            raw, expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
        )
        self.assertEqual(parsed.route, "responses")
        self.assertEqual(parsed.model, "gpt-6.2-sol")


if __name__ == "__main__":
    unittest.main()
