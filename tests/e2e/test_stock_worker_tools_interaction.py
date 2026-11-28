"""Portable guards for the stock terminal question and synthetic skill cases."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parent)]

from stock_worker_tools_history import bounded_text, canonical, stock_history
from stock_worker_tools_interaction import (
    PROMPT, SKILL_BYTES, SKILL_ID, Interaction, _SCHEMAS, verify_tool,
)
from stock_worker_tools_protocol import FixtureMismatch


class InteractionTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name)
        self.workspace = root / "job"
        self.home = root / "home"
        self.workspace.mkdir()
        self.home.mkdir()

    def script(self, case, generation="a" * 32):
        script = Interaction(case, generation, self.workspace)
        script.setup(self.home)
        return script

    def continuation(self, script):
        return {"prompt_cache_key": "ses_validchat", "input": [
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": PROMPT}]},
            {"type": "function_call", "id": "fc_local_1", "name": script.tool,
             "call_id": script.call_id, "arguments": json.dumps(script.arguments)},
            {"type": "function_call_output", "call_id": script.call_id, "output": script.expected_result()},
        ]}

    def validate(self, script, body):
        return script.verify_input(body, stock_history(body["input"], interaction=script))

    def test_independently_frozen_schema_rejects_nested_drift(self):
        for tool, projection in _SCHEMAS.items():
            with self.subTest(tool=tool):
                declaration = {**json.loads(projection), "strict": False, "description": "bounded"}
                verify_tool(declaration, canonical, bounded_text)
                declaration["parameters"]["properties"].clear()
                with self.assertRaisesRegex(FixtureMismatch, "Unmeasured stock interaction schema"):
                    verify_tool(declaration, canonical, bounded_text)

    def test_question_blocks_before_input_and_binds_after_input(self):
        script = self.script("question")
        complete = self.continuation(script)
        first = {**complete, "input": complete["input"][:1]}
        self.assertIsNone(self.validate(script, first))
        script.respond(first, None)
        with self.assertRaisesRegex(FixtureMismatch, "unanswered"):
            self.validate(script, complete)
        script.selected = True
        with self.assertRaisesRegex(FixtureMismatch, "No matching"):
            self.validate(script, {**complete, "prompt_cache_key": "ses_anotherchat"})
        forged = deepcopy(complete)
        forged["input"][2]["output"] += " "
        with self.assertRaisesRegex(FixtureMismatch, "Incorrect stock interaction result"):
            self.validate(script, forged)
        result = self.validate(script, complete)
        script.respond(complete, result)
        with self.assertRaisesRegex(FixtureMismatch, "No matching"):
            self.validate(script, complete)

    def test_same_answer_cannot_resolve_another_issued_question(self):
        original = self.script("question")
        second = self.script("question", "b" * 32)
        old_answer = self.continuation(original)
        first = {**old_answer, "input": old_answer["input"][:1]}
        second.respond(first, None)
        second.selected = True
        with self.assertRaisesRegex(FixtureMismatch, "No matching"):
            self.validate(second, old_answer)

    def test_skill_inventory_and_input_reject_undeclared_sources(self):
        script = self.script("skill")
        complete = self.continuation(script)
        first = {**complete, "input": complete["input"][:1]}
        script.respond(first, None)
        forged = deepcopy(complete)
        forged["input"][1]["arguments"] = json.dumps({"id": SKILL_ID + "-other"})
        with self.assertRaisesRegex(FixtureMismatch, "Unexpected stock interaction tool or arguments"):
            self.validate(script, forged)
        extra = script.source.parent / "other-job-data"
        extra.write_text("harmless unrelated job data")
        with self.assertRaisesRegex(FixtureMismatch, "inventory changed"):
            self.validate(script, complete)
        extra.unlink()
        script.source.write_bytes(SKILL_BYTES + b" ")
        with self.assertRaisesRegex(FixtureMismatch, "inventory changed"):
            self.validate(script, complete)

    def test_unavailable_skill_requires_exact_native_error(self):
        script = self.script("skill-unavailable")
        complete = self.continuation(script)
        first = {**complete, "input": complete["input"][:1]}
        script.respond(first, None)
        history = stock_history(complete["input"], interaction=script)
        with self.assertRaisesRegex(FixtureMismatch, "Incorrect native skill denial"):
            script.verify_unavailable(complete, history)
        complete["input"][2]["output"] = json.dumps({"error": script.refusal(), "content": []}, separators=(",", ":"))
        history = stock_history(complete["input"], interaction=script)
        script.verify_unavailable(complete, history)
        with self.assertRaisesRegex(FixtureMismatch, "cannot continue"):
            self.validate(script, complete)


if __name__ == "__main__":
    unittest.main()
