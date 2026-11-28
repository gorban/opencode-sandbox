"""Offline regressions for preclaim validation of native stock workspace searches."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(Path(__file__).resolve().parent)]

from oc_openai.session_protocol import RequestRefused, StreamAborted, parse_worker_request
from stock_worker_tools_capture import FIXTURE_BEARER, PORT, Observer
from stock_worker_tools_history import canonical, upstream_body
from stock_worker_tools_projection import describe_source
from stock_worker_tools_protocol import MODEL, FixtureMismatch, call_id, response_events
from stock_worker_tools_search import SEARCH_PROMPT, SEARCH_SCHEMA_SHA256, SEARCH_TOOLS, _SCHEMAS
from stock_worker_tools_stream import project_stream, scripted_response, terminal_output
from stock_worker_tools_turns import HANDOFF_END

SESSION = "ses_StockSearchTest"
ILLUSTRATIVE_INSTRUCTIONS = "Synthetic instructions for the offline search tests"


class SearchTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="oc-stock-search-test-")
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        workspace = root / "job"
        workspace.mkdir()
        with patch("stock_worker_tools_capture.WORKSPACE", workspace), \
                patch("stock_worker_tools_capture.ThreadingHTTPServer.__init__"):
            self.observer = Observer("search", root / "exposure.sqlite")
        self.turns = self.observer.turns
        self.authority = self.observer.authority
        self.script = self.observer.upstream.script
        self.script.setup()
        self.tools = [{**json.loads(schema), "strict": False, "description": "Fixture description"}
                      for schema in _SCHEMAS.values()]
        self.body = {
            "model": MODEL,
            "input": [{"type": "message", "role": "user",
                       "content": [{"type": "input_text", "text": SEARCH_PROMPT}]}],
            "instructions": ILLUSTRATIVE_INSTRUCTIONS,
            "stream": True,
            "store": False,
            "include": ["reasoning.encrypted_content"],
            "prompt_cache_key": SESSION,
            "max_output_tokens": 16_384,
            "tools": self.tools,
        }
        instructions_pin = hashlib.sha256(ILLUSTRATIVE_INSTRUCTIONS.encode()).hexdigest()
        fixture_pins = patch.multiple("stock_worker_tools_history", _CHAT_INSTRUCTIONS=instructions_pin,
                                      _TOOL_DEFINITIONS=dict.fromkeys(SEARCH_TOOLS))
        fixture_pins.start()
        self.addCleanup(fixture_pins.stop)

    def dispatch(self, body):
        wire = canonical(body)
        wire_request = (
            f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
            f"Authorization: Bearer {FIXTURE_BEARER}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(wire)}\r\n\r\n"
        ).encode("ascii") + wire
        parsed = parse_worker_request(wire_request, expected_token=FIXTURE_BEARER,
                                      allowed_models=frozenset({MODEL}), vault=self.observer.vault)
        return self.observer.dispatch(body, upstream_body(parsed, SEARCH_TOOLS))

    def stage(self):
        request, response = self.dispatch(self.body)
        frames, usage = project_stream(response, self.observer.vault, SEARCH_TOOLS, "resp_search_test")
        calls, message = terminal_output(frames[-1], search=True)
        return request, self.turns.settle(self.authority, request, calls=calls, completed_message=message,
                                          usage=usage)

    def handoff(self, request, pending):
        self.turns.deliver(self.authority, request, pending, lambda _frame: None, (b"synthetic terminal", HANDOFF_END))

    def append_result(self, index):
        identifier = call_id(index, SEARCH_TOOLS)
        self.body["input"].extend((
            {"type": "function_call", "id": "fc_local_1", "call_id": identifier, "name": SEARCH_TOOLS[index],
             "arguments": json.dumps(self.script.arguments[index])},
            {"type": "function_call_output", "call_id": identifier, "output": self.script.expected[index]},
        ))

    def assert_refused(self, changed, match, error=FixtureMismatch):
        initial = self.turns.records(), self.observer.upstream.writes
        with self.assertRaisesRegex(error, match):
            self.dispatch(changed)
        self.assertEqual((self.turns.records(), self.observer.upstream.writes), initial)

    def test_search_schema_changes_refuse_before_claim_at_each_stage(self):
        for stage in range(3):
            for tool_index, tool_name in enumerate(SEARCH_TOOLS):
                with self.subTest(stage=stage, tool=tool_name):
                    exact = self.tools[tool_index]["parameters"]
                    properties = exact["properties"]
                    additions = {**properties, "other": {"type": "string"}}
                    removals = {key: value for key, value in properties.items() if key != "pattern"}
                    mutations = {**properties, "limit": {**properties["limit"], "exclusiveMinimum": False}}
                    for altered in (additions, removals, mutations):
                        changed = deepcopy(self.body)
                        changed["tools"][tool_index]["parameters"]["properties"] = altered
                        self.assert_refused(changed, "Unmeasured stock search schema")
                    changed = deepcopy(self.body)
                    changed["tools"].pop(tool_index)
                    self.assert_refused(changed, "Unmeasured stock tool declarations")
                    changed["tools"].insert(tool_index, {**self.tools[tool_index], "name": "unavailable"})
                    self.assert_refused(changed, "Unmeasured stock tool declarations")
                    changed = deepcopy(self.body)
                    changed["tools"][tool_index]["description"] = "x" * 8193
                    self.assert_refused(changed, "Unmeasured stock search declaration")
                    changed = deepcopy(self.body)
                    changed["tools"][tool_index]["type"] = "web_search"
                    self.assert_refused(changed, "", RequestRefused)
            # Top-level descriptions may differ while the typed schema stays pinned.
            self.body["tools"][0]["description"] += " changed"
            self.handoff(*self.stage())
            if stage < 2:
                self.append_result(stage)
        self.assertEqual(self.observer.upstream.writes, 3)
        self.assertEqual([row["actual_input"] for row in self.turns.verified_records()], [2, 2, 2])

    def test_pending_foreign_mismatched_and_retired_search_cannot_claim(self):
        request, pending = self.stage()
        self.append_result(0)
        self.assert_refused(self.body, "Stock route busy or foreign session")
        self.handoff(request, pending)
        self.assert_refused({**self.body, "prompt_cache_key": "ses_OlderChat"}, "Stock route busy or foreign session")
        for key, value, match in (("output", "other", "Wrong stock search result"),
                                  ("call_id", "call_other", "Invalid stock result shape or identity")):
            modified = deepcopy(self.body)
            modified["input"][2][key] = value
            self.assert_refused(modified, match)
        changed = deepcopy(self.body)
        args = {**self.script.arguments[0], "pattern": "*.different"}
        changed["input"][1]["arguments"] = json.dumps(args)
        self.assert_refused(changed, "New stock tool batch differs")
        self.turns.retire()
        self.assert_refused(self.body, "Stale or expired stock fixture authority")

    def test_search_stream_with_unavailable_local_tool_cannot_open_batch(self):
        events = response_events(0, {"path": "fixture-only"}, tools=("read",))
        with self.assertRaisesRegex(StreamAborted, "unauthorized_tool_call"):
            project_stream(scripted_response(events), self.observer.vault, SEARCH_TOOLS, "resp_search_test")
        self.assertEqual(self.turns.records(), [])

    def test_search_module_is_in_measured_source_projection(self):
        self.assertIn("tests/e2e/stock_worker_tools_search.py", describe_source(ROOT))

    def test_exact_canonical_schema_pins(self):
        for name, schema in _SCHEMAS.items():
            self.assertEqual(hashlib.sha256(canonical(json.loads(schema))).hexdigest(), SEARCH_SCHEMA_SHA256[name])


if __name__ == "__main__":
    unittest.main()
