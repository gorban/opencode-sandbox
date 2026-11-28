"""Prereview protocol checks using synthetic in-memory messages."""

from hashlib import sha256
from http.client import HTTPResponse
import io
import json
import unittest

from e2e import claude_named_text_child as child
from e2e import claude_named_text_protocol as wire
from oc_openai.session_protocol import RequestRefused


MODEL = "claude-fixture"
SESSION = "1" * 32
CHALLENGE = "2" * 32
TOKEN = "synthetic-worker-token"
PORT = 8401
PROFILE = "fixture-profile"
ACCOUNT = "fixture-account"
INSTRUCTIONS = "Pinned stock startup instructions in the unit fixture."
TEXT = "Summarize this local Unicode sample. ☀"


def _request(body, *, token=TOKEN):
    encoded = json.dumps(body).encode("utf-8")
    return _request_bytes(encoded, token=token)


def _request_bytes(encoded, *, token=TOKEN):
    return (
        "POST /v1/responses HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{PORT}\r\n"
        f"Authorization: Bearer {token}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(encoded)}\r\n\r\n"
    ).encode("ascii") + encoded


def _lower(raw):
    return wire.lower_stock_request(
        raw, token=TOKEN, port=PORT, model=MODEL,
        instructions_digest=sha256(INSTRUCTIONS.encode()).hexdigest(), stock_output_limit=16384,
    )


def _body(text=TEXT):
    return {
        "model": MODEL, "store": False, "stream": True, "instructions": INSTRUCTIONS,
        "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}],
        "max_output_tokens": 16384, "include": ["reasoning.encrypted_content"], "prompt_cache_key": "ses_measured",
    }


def _packet(text=TEXT):
    return wire.native_packet(text, session=SESSION, challenge=CHALLENGE, pipe_buf=4096)


def _child_output(stdin):
    output = io.BytesIO()
    status = child._exchange(
        io.BytesIO(stdin), output, session=SESSION, model=MODEL, profile=PROFILE, account=ACCOUNT,
    )
    return status, output.getvalue().splitlines(keepends=True)


def _ready(frame):
    wire.verify_ready(frame, session=SESSION, model=MODEL, profile=PROFILE, account=ACCOUNT)


def _result(frames):
    return wire.read_native_turn(
        frames, session=SESSION, challenge=CHALLENGE, model=MODEL, max_input=512, max_output=1024,
    )


def _frame_update(raw, **edits):
    return json.dumps({**json.loads(raw), **edits}).encode() + b"\n"


class _ReplySocket:
    def __init__(self, payload):
        self.stream = io.BytesIO(payload)

    def makefile(self, _mode):
        return self.stream


class NamedClaudeTextProtocolTests(unittest.TestCase):
    def test_translates_one_fresh_message_to_bounded_native_text_and_stock_sse(self):
        text = _lower(_request(_body()))
        packet = _packet(text)
        self.assertEqual(json.loads(packet), {
            "type": "user", "role": "user", "text": TEXT, "session": SESSION, "challenge": CHALLENGE,
        })
        status, (ready, *frames) = _child_output(packet)
        self.assertEqual(status, 0)
        _ready(ready)
        result = _result(frames)
        self.assertEqual(result.text, f"fixture: {TEXT}")
        self.assertEqual(result.terminal_digest, sha256(frames[-1]).hexdigest())
        response = HTTPResponse(_ReplySocket(wire.render_stock_reply(result, response_id=SESSION, model=MODEL)))
        response.begin()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "text/event-stream")
        events = [
            json.loads(line.removeprefix(b"data: "))
            for line in response.read().splitlines()
            if line.startswith(b"data: ")
        ]
        self.assertEqual([event["type"] for event in events], [
            "response.created", "response.output_item.added", "response.content_part.added",
            "response.output_text.delta", "response.output_text.done", "response.content_part.done",
            "response.output_item.done", "response.completed",
        ])
        self.assertEqual(events[3]["delta"], result.text)
        completed = events[-1]["response"]
        self.assertEqual(completed["model"], MODEL)
        self.assertEqual(completed["output"], [events[-2]["item"]])
        self.assertEqual(completed["usage"]["total_tokens"], result.input_tokens + result.output_tokens)

    def test_stock_envelopes_outside_the_measured_shape_refuse(self):
        edits_examples = (
            {"instructions": "Generate a conversation title"}, {"instructions": "\ud800"},
            {"tools": []}, {"tools": [{"type": "web_search"}]}, {"tool_choice": "auto"},
            {"previous_response_id": "resp_replay"}, {"store": True}, {"stream": False},
            {"model": "claude-other"}, {"include": []}, {"max_output_tokens": 16383},
            {"max_output_tokens": 16384.0}, {"prompt_cache_key": "wrong-cache"},
        )
        for edits in edits_examples:
            with self.subTest(edits=edits), self.assertRaises((wire.TextWireError, RequestRefused)):
                _lower(_request({**_body(), **edits}))

    def test_only_one_fresh_user_message_and_one_bounded_plain_text_part(self):
        original = _body()["input"]
        for change in (
            original * 2,
            [{**original[0], "role": "assistant"}],
            [{**original[0], "id": "replayed-message"}],
            [{**original[0], "content": original[0]["content"] * 2}],
            [{**original[0], "content": [{**original[0]["content"][0], "type": "input_image"}]}],
        ):
            with self.assertRaises((wire.TextWireError, RequestRefused)):
                _lower(_request({**_body(), "input": change}))
        for prompt in ("", " ", "ab\0cd", "\ud800", "é" * 257):
            with self.assertRaises((wire.TextWireError, RequestRefused)):
                _lower(_request(_body(prompt)))
        self.assertEqual(_lower(_request(_body("é" * 256))), "é" * 256)

    def test_stock_non_string_role_and_part_type_are_refused(self):
        for value in ([], {}, 1, None):
            for field in ("role", "part_type"):
                with self.subTest(field=field, value=value):
                    body = _body()
                    item = body["input"][0]
                    if field == "role":
                        item["role"] = value
                    else:
                        item["content"][0]["type"] = value
                    with self.assertRaises((wire.TextWireError, RequestRefused)):
                        _lower(_request(body))

    def test_other_token_and_duplicate_json_refuse(self):
        with self.assertRaises(RequestRefused):
            _lower(_request(_body(), token="different-job-token"))
        duplicate = b'{"store":true,' + json.dumps(_body()).encode("utf-8")[1:]
        with self.assertRaises((wire.TextWireError, RequestRefused)):
            _lower(_request_bytes(duplicate))
        with self.assertRaises(wire.TextWireError):
            _lower(_request_bytes(json.dumps(_body()).encode("utf-16")))
        body = {**_body(), "extra": "x" * (32 * 1024)}
        with self.assertRaises(wire.TextWireError):
            _lower(_request(body))

    def test_fake_child_requires_one_packet_followed_by_eof(self):
        status, (ready,) = _child_output(_packet() * 2)
        self.assertEqual(status, 1)
        _ready(ready)
        with self.assertRaises(wire.TextWireError):
            wire.native_packet(TEXT, session=SESSION, challenge=CHALLENGE, pipe_buf=16)

    def test_fake_child_refuses_duplicate_packet_fields(self):
        for extra in (b'"role":"user",', b'"role":"assistant",', b'"text":"discarded",'):
            with self.subTest(extra=extra):
                status, frames = _child_output(b"{" + extra + _packet()[1:])
                self.assertEqual(status, 1)
                self.assertEqual(len(frames), 1)
                _ready(frames[0])

    def test_native_stdout_requires_exactly_one_line_per_frame(self):
        _, (ready, delta, terminal) = _child_output(_packet())
        pretty_ready = json.dumps(json.loads(ready), indent=2).encode() + b"\n"
        for kind, frame in (("pretty READY", pretty_ready), ("CRLF READY", ready[:-1] + b"\r\n")):
            with self.subTest(kind=kind), self.assertRaises(wire.TextWireError):
                _ready(frame)
        for index, raw in enumerate((delta, terminal)):
            with self.subTest(frame=json.loads(raw)["type"]), self.assertRaises(wire.TextWireError):
                frames = [delta, terminal]
                frames[index] = json.dumps(json.loads(raw), indent=2).encode() + b"\n"
                _result(frames)
        self.assertEqual(_result(_child_output(_packet("one\ntwo"))[1][1:]).text, "fixture: one\ntwo")

    def test_ready_requires_the_exact_model_profile_and_empty_tool_inventory(self):
        _, (ready, *_) = _child_output(_packet())
        for edits in (
            {"session": "3" * 32}, {"model": "alternate"}, {"profile": "wrong"},
            {"account": "wrong"}, {"hooks": ["unexpected"]}, {"tools": ["unexpected"]}, {"mcp": ["unexpected"]},
        ):
            with self.assertRaises(wire.TextWireError):
                _ready(_frame_update(ready, **edits))

    def test_native_uncertainty_yields_no_completed_reply(self):
        _, (_, delta, terminal) = _child_output(_packet())
        for frames in (
            [], [delta], [terminal], [delta, terminal, delta], [delta] * 17 + [terminal],
            [_frame_update(delta, text="é" * 2049), terminal],
            [_frame_update(delta, type="tool_call"), terminal],
            [_frame_update(delta, model="alternate"), terminal],
            [_frame_update(delta, challenge="3" * 32), terminal],
            [delta, _frame_update(terminal, model="alternate")],
            [delta, _frame_update(terminal, tool_calls=True)],
            [delta, _frame_update(terminal, tool_calls=1)],
            [delta, _frame_update(terminal, output_tokens=False)],
            [delta, _frame_update(terminal, input_tokens=513)],
            [delta, _frame_update(terminal, output_tokens=1025)],
            [delta, _frame_update(terminal, output_tokens=1.5)],
            [delta, b'{"type":"result","type":"result"}\n'],
        ):
            with self.assertRaises(wire.TextWireError):
                _result(frames)
