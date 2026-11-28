"""Tests for interactive Responses request sanitizer, reasoning vault, and fail-closed SSE projector."""

import json
import re
import unittest
from unittest.mock import patch

from oc_openai import session_protocol
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

    def test_header_name_token_alphabet_matches_previous_parser(self):
        old_name_pattern = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
        names = [bytes([byte]) for byte in range(256)]
        names.extend((b"", b"X-Session-ID", b"!#$%&'*+-.^_`|~", b"X-\xff", b"X Y", b"X\n"))
        # Admit all candidates at the separate header allowlist to exercise the lexer.
        with patch.object(session_protocol, "_ALLOWED_HEADERS", {name.lower() for name in names}):
            for name in names:
                with self.subTest(name=name):
                    if old_name_pattern.fullmatch(name):
                        self.assertEqual(session_protocol._parse_headers([name + b": v"]), {name.lower(): b"v"})
                    else:
                        with self.assertRaises(RequestRefused) as error:
                            session_protocol._parse_headers([name + b": v"])
                        self.assertEqual((error.exception.status, error.exception.code), (400, "invalid_request"))

    def test_header_name_classification_order_and_normalization(self):
        self.assertEqual(
            session_protocol._parse_headers([b"HoSt:\t127.0.0.1:8401  ", b"X-Session-ID: abc"]),
            {b"host": b"127.0.0.1:8401", b"x-session-id": b"abc"},
        )
        for lines, (expected_status, expected_code) in (
            ([b"OrIgIn: \xff"], (403, "forbidden_header")),
            ([b"Sec-Fetch-Site: local"], (403, "forbidden_header")),
            ([b"sEc-Ch-Ua: client"], (403, "forbidden_header")),
            ([b"Sec-Fetch-\xff: local"], (400, "invalid_request")),
            ([b"Host: first", b"hOsT: second"], (400, "invalid_request")),
            ([b"Origin"], (400, "invalid_request")),
            ([b": origin"], (400, "invalid_request")),
            ([b"Unknown: value"], (400, "invalid_request")),
        ):
            with self.subTest(lines=lines):
                with self.assertRaises(RequestRefused) as error:
                    session_protocol._parse_headers(lines)
                self.assertEqual(error.exception.status, expected_status)
                self.assertEqual(error.exception.code, expected_code)

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
        req_pre = _http_req("POST", "/v1/responses", replay_body)
        with self.assertRaises(RequestRefused) as pre_err:
            parse_worker_request(
                req_pre,
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
            bad_req = _http_req("POST", "/v1/responses", {"model": bad_model, "stream": True, "store": False, "input": [bad_item]})
            with self.assertRaises(RequestRefused) as err:
                parse_worker_request(
                    bad_req,
                    expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
                )
            self.assertEqual(err.exception.status, 400)

    def test_buffers_function_call_completion_until_finalize_and_enforces_strict_metadata_allowlist(self):
        projector = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_2", vault=self.vault,
            allowed_tools=frozenset({"read"}),
        )
        projector.feed({"type": "response.created", "response": {"id": "resp_up_2", "status": "in_progress"}})
        # Benign unblocked prompt metadata is dropped host-only.
        self.assertEqual(projector.feed({
            "type": "response.metadata", "response_id": "resp_up_2", "sequence_number": 1,
            "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {"outputs": [{"is_blocked": False}]}}},
        }), [])
        # Text deltas stream live; function_call completion frames are buffered and correlated.
        text_out = projector.feed({"type": "response.output_text.delta", "delta": "hi"})
        self.assertEqual(len(text_out), 1)
        self.assertEqual(projector.feed({
            "type": "response.function_call_arguments.done", "output_index": 0,
            "call_id": "call_1", "arguments": "{}",
        }), [])
        self.assertEqual(projector.feed({
            "type": "response.output_item.done", "output_index": 0,
            "item": {"type": "function_call", "call_id": "call_1", "name": "read", "arguments": "{}"},
        }), [])
        self.assertEqual(projector.feed({
            "type": "response.completed",
            "response": {
                "id": "resp_up_2", "status": "completed",
                "output": [
                    {"type": "function_call", "call_id": "call_1", "name": "read",
                     "arguments": "{}", "status": "completed"},
                ],
                "usage": {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8},
            },
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
        p = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_4", vault=self.vault,
            allowed_tools=frozenset({"bash"}),
        )
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

    def test_reciprocal_p1_tool_release_correlation_and_live_omnimod_moderation(self):
        # P1 #2a: created / in_progress / queued envelopes must never project nested function_calls.
        for kind, status in (
            ("response.created", "in_progress"),
            ("response.in_progress", "in_progress"),
            ("response.queued", "queued"),
        ):
            p = SessionStreamProjector(model="gpt-6.2-sol", local_response_id="resp_local_t1", vault=self.vault)
            if kind != "response.created":
                p.feed({"type": "response.created", "response": {"id": "resp_up_t1", "status": "in_progress"}})
            with self.subTest(kind=kind), self.assertRaises(StreamAborted) as err:
                p.feed({
                    "type": kind,
                    "response": {
                        "id": "resp_up_t1", "status": status,
                        "output": [{"type": "function_call", "call_id": "call_early", "name": "bash", "arguments": "{}"}],
                    },
                })
            self.assertEqual(err.exception.code, "premature_tool_call")

        # P1 #2b: buffered tool item missing from completed.output or with mismatched arguments aborts finalize().
        p_orphan = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_t2", vault=self.vault,
            allowed_tools=frozenset({"bash"}),
        )
        p_orphan.feed({"type": "response.created", "response": {"id": "resp_up_t2", "status": "in_progress"}})
        p_orphan.feed({
            "type": "response.output_item.done", "output_index": 0,
            "item": {"type": "function_call", "call_id": "call_x", "name": "bash", "arguments": '{"a":1}'},
        })
        p_orphan.feed({"type": "response.completed", "response": {"id": "resp_up_t2", "status": "completed", "output": []}})
        with self.assertRaises(StreamAborted) as err_o:
            p_orphan.finalize()
        self.assertEqual(err_o.exception.code, "tool_call_mismatch")

        p_mismatch = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_t3", vault=self.vault,
            allowed_tools=frozenset({"read"}),
        )
        p_mismatch.feed({"type": "response.created", "response": {"id": "resp_up_t3", "status": "in_progress"}})
        p_mismatch.feed({
            "type": "response.output_item.added", "output_index": 0,
            "item": {"id": "fc_up_1", "type": "function_call", "call_id": "call_m", "name": "read", "arguments": ""},
        })
        p_mismatch.feed({
            "type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "fc_up_1", "delta": '{"x":1}',
        })
        p_mismatch.feed({
            "type": "response.completed",
            "response": {
                "id": "resp_up_t3", "status": "completed",
                "output": [{"id": "fc_up_1", "type": "function_call", "call_id": "call_m",
                            "name": "read", "arguments": '{"x":2}', "status": "completed"}],
            },
        })
        with self.assertRaises(StreamAborted) as err_m:
            p_mismatch.finalize()
        self.assertEqual(err_m.exception.code, "tool_call_mismatch")

        # P1 #2c: valid live-style tool stream (item_id without call_id on deltas) + omnimod moderation passes.
        p_ok = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_t4", vault=self.vault,
            allowed_tools=frozenset({"read"}),
        )
        p_ok.feed({
            "type": "response.created", "safety_buffering": False, "sequence_number": 0,
            "response": {"id": "resp_up_t4", "status": "in_progress", "moderation": None},
        })
        self.assertEqual(p_ok.feed({
            "type": "response.metadata", "response_id": "resp_up_t4", "sequence_number": 1,
            "metadata": {"openai_chatgpt_moderation_metadata": {
                "prompt": {"omnimod": {
                    "protection_type": "default",
                    "outputs": [{"is_blocked": False, "results": [{"category_flags": {"A1": False, "REFUSED": False}}]}],
                }},
                "generation": {}, "tool_call": {}, "tool_response": {},
            }},
        }), [])
        self.assertEqual(p_ok.feed({
            "type": "response.output_item.added", "output_index": 0,
            "item": {"id": "fc_up_2", "type": "function_call", "call_id": "call_ok", "name": "read", "arguments": ""},
        }), [])
        self.assertEqual(p_ok.feed({
            "type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "fc_up_2", "delta": '{"p":',
        }), [])
        self.assertEqual(p_ok.feed({
            "type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "fc_up_2", "delta": '"a"}',
        }), [])
        self.assertEqual(p_ok.feed({
            "type": "response.function_call_arguments.done", "output_index": 0, "item_id": "fc_up_2", "arguments": '{"p":"a"}',
        }), [])
        self.assertEqual(p_ok.feed({
            "type": "response.output_item.done", "output_index": 0,
            "item": {"id": "fc_up_2", "type": "function_call", "call_id": "call_ok",
                     "name": "read", "arguments": '{"p":"a"}', "status": "completed"},
        }), [])
        p_ok.feed({
            "type": "response.completed", "safety_buffering": False,
            "response": {
                "id": "resp_up_t4", "status": "completed", "moderation": None,
                "output": [{"id": "fc_up_2", "type": "function_call", "call_id": "call_ok",
                            "name": "read", "arguments": '{"p":"a"}', "status": "completed"}],
            },
        })
        self.assertEqual(len(p_ok.finalize()), 6)

        # Any True category_flag in omnimod or non-None response.moderation aborts fail-closed.
        p_flag = SessionStreamProjector(model="gpt-6.2-sol", local_response_id="resp_local_t5", vault=self.vault)
        p_flag.feed({"type": "response.created", "response": {"id": "resp_up_t5", "status": "in_progress"}})
        with self.assertRaises(StreamAborted):
            p_flag.feed({
                "type": "response.metadata", "response_id": "resp_up_t5", "sequence_number": 1,
                "metadata": {"openai_chatgpt_moderation_metadata": {
                    "prompt": {"omnimod": {
                        "protection_type": "default",
                        "outputs": [{"is_blocked": False, "results": [{"category_flags": {"REFUSED": True}}]}],
                    }},
                }},
            })

        # Assistant refusal cannot coexist with a function_call on the same turn.
        p_ref = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_t6", vault=self.vault,
            allowed_tools=frozenset({"bash"}),
        )
        p_ref.feed({"type": "response.created", "response": {"id": "resp_up_t6", "status": "in_progress"}})
        p_ref.feed({"type": "response.refusal.delta", "delta": "cannot do that"})
        p_ref.feed({
            "type": "response.completed",
            "response": {
                "id": "resp_up_t6", "status": "completed",
                "output": [{"type": "function_call", "call_id": "call_r", "name": "bash",
                            "arguments": "{}", "status": "completed"}],
            },
        })
        with self.assertRaises(StreamAborted) as err_ref:
            p_ref.finalize()
        self.assertEqual(err_ref.exception.code, "tool_call_with_refusal")

        # P2 #1: unknown metadata keys inside response.completed/created abort fail-closed.
        p_meta = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_t7", vault=self.vault,
            allowed_tools=frozenset({"bash"}),
        )
        p_meta.feed({"type": "response.created", "response": {"id": "resp_up_t7", "status": "in_progress"}})
        with self.assertRaises(StreamAborted) as err_meta:
            p_meta.feed({
                "type": "response.completed",
                "response": {
                    "id": "resp_up_t7", "status": "completed",
                    "metadata": {"policy_action": "block", "unknown_safety_flag": True},
                    "output": [{"type": "function_call", "call_id": "call_m", "name": "bash",
                                "arguments": "{}", "status": "completed"}],
                },
            })
        self.assertEqual(err_meta.exception.code, "metadata_fields")

        # P2 #2: mismatched item_id between output_item.added and function_call_arguments.delta
        # aborts finalize() even when response.completed.output[idx] omits "id".
        p_id = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_t8", vault=self.vault,
            allowed_tools=frozenset({"read"}),
        )
        p_id.feed({"type": "response.created", "response": {"id": "resp_up_t8", "status": "in_progress"}})
        p_id.feed({
            "type": "response.output_item.added", "output_index": 0,
            "item": {"id": "fc_1", "type": "function_call", "call_id": "call_id1", "name": "read", "arguments": ""},
        })
        p_id.feed({
            "type": "response.function_call_arguments.delta", "output_index": 0,
            "item_id": "fc_WRONG", "delta": "{}",
        })
        p_id.feed({
            "type": "response.completed",
            "response": {
                "id": "resp_up_t8", "status": "completed",
                "output": [{"type": "function_call", "call_id": "call_id1", "name": "read",
                            "arguments": "{}", "status": "completed"}],
            },
        })
        with self.assertRaises(StreamAborted) as err_id:
            p_id.finalize()
        self.assertEqual(err_id.exception.code, "tool_call_mismatch")

    def test_reciprocal_r2_tool_policy_and_delta_name_enforcement(self):
        base = {"model": "gpt-6.2-sol", "stream": True, "store": False,
                "input": [{"role": "user", "content": "hi"}]}
        read_tool = {"type": "function", "name": "read", "parameters": {"type": "object"}}
        edit_tool = {"type": "function", "name": "edit", "parameters": {"type": "object"}}

        # Request policy resolution: no tools, tool_choice=none, specific tool, and invalid choice.
        self.assertEqual(
            parse_worker_request(_http_req("POST", "/v1/responses", base),
                                 expected_token="tok-secret", allowed_models=self.models, vault=self.vault).allowed_tools,
            frozenset(),
        )
        self.assertEqual(
            parse_worker_request(
                _http_req("POST", "/v1/responses", {**base, "tools": [read_tool, edit_tool], "tool_choice": "none"}),
                expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
            ).allowed_tools,
            frozenset(),
        )
        self.assertEqual(
            parse_worker_request(
                _http_req("POST", "/v1/responses", {
                    **base, "tools": [read_tool, edit_tool], "tool_choice": {"type": "function", "name": "read"},
                }),
                expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
            ).allowed_tools,
            frozenset({"read"}),
        )
        for bad_choice in ({"type": "function", "name": "bash"}, "required"):
            bad_req = _http_req("POST", "/v1/responses", {**base, "tool_choice": bad_choice})
            with self.subTest(bad_choice=bad_choice), self.assertRaises(RequestRefused) as err_req:
                parse_worker_request(
                    bad_req, expected_token="tok-secret", allowed_models=self.models, vault=self.vault,
                )
            self.assertEqual(err_req.exception.status, 400)

        # Projector rejects any tool call when allowed_tools is empty (e.g. no tools or tool_choice=none).
        p_none = SessionStreamProjector(model="gpt-6.2-sol", local_response_id="resp_local_nt", vault=self.vault)
        p_none.feed({"type": "response.created", "response": {"id": "resp_nt", "status": "in_progress"}})
        with self.assertRaises(StreamAborted) as err_nt:
            p_none.feed({
                "type": "response.output_item.done", "output_index": 0,
                "item": {"type": "function_call", "call_id": "call_1", "name": "read", "arguments": "{}"},
            })
        self.assertEqual(err_nt.exception.code, "unauthorized_tool_call")

        # Projector rejects undeclared tool names even when other tools are allowed.
        p_only_read = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_or", vault=self.vault,
            allowed_tools=frozenset({"read"}),
        )
        p_only_read.feed({"type": "response.created", "response": {"id": "resp_or", "status": "in_progress"}})
        with self.assertRaises(StreamAborted) as err_or:
            p_only_read.feed({
                "type": "response.completed",
                "response": {
                    "id": "resp_or", "status": "completed",
                    "output": [{"type": "function_call", "call_id": "call_e", "name": "edit",
                                "arguments": "{}", "status": "completed"}],
                },
            })
        self.assertEqual(err_or.exception.code, "unauthorized_tool_call")

        # Conflicting name on function_call_arguments.delta aborts finalize() before releasing any tool frames.
        p_delta = SessionStreamProjector(
            model="gpt-6.2-sol", local_response_id="resp_local_dn", vault=self.vault,
            allowed_tools=frozenset({"read", "edit"}),
        )
        p_delta.feed({"type": "response.created", "response": {"id": "resp_dn", "status": "in_progress"}})
        p_delta.feed({
            "type": "response.output_item.added", "output_index": 0,
            "item": {"id": "fc_dn", "type": "function_call", "call_id": "call_dn", "name": "read", "arguments": ""},
        })
        p_delta.feed({
            "type": "response.function_call_arguments.delta", "output_index": 0,
            "item_id": "fc_dn", "call_id": "call_dn", "name": "edit", "delta": "{}",
        })
        p_delta.feed({
            "type": "response.completed",
            "response": {
                "id": "resp_dn", "status": "completed",
                "output": [{"id": "fc_dn", "type": "function_call", "call_id": "call_dn",
                            "name": "read", "arguments": "{}", "status": "completed"}],
            },
        })
        with self.assertRaises(StreamAborted) as err_dn:
            p_delta.finalize()
        self.assertEqual(err_dn.exception.code, "tool_call_mismatch")


if __name__ == "__main__":
    unittest.main()
