"""Offline regressions for the synthetic stock causal first-write contract."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
from dataclasses import replace
import hashlib
from http.client import HTTPException
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
from threading import Barrier, Event, current_thread
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(Path(__file__).resolve().parent)]

from oc_openai.connection_state import ConnectionError as ProviderConnectionError
from oc_openai.session_protocol import ReasoningVault, StreamAborted
from stock_worker_tools_history import (
    MAX_BATCH, MAX_INPUT, MAX_OUTPUT, classify, digest, stock_history, stock_pair,
)
from stock_worker_tools_protocol import MODEL, TITLE_PROMPT, FixtureMismatch, encode_sse, response_events
from stock_worker_tools_stream import SyntheticResponse, project_stream, terminal_output
from stock_worker_tools_turns import HANDOFF_END, Authority, FixtureTurns

AUTHORITY = Authority("job", "slot", "generation", "/v1/responses", MODEL)
SESSION = "ses_OfflineTest"


def user(text):
    return {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}


def call_and_result(identifier, *, name="read", arguments='{"path":"proof.txt"}', output="result\n"):
    return [
        {"type": "function_call", "id": "fc_local_1", "call_id": identifier, "name": name, "arguments": arguments},
        {"type": "function_call_output", "call_id": identifier, "output": output},
    ]


def assistant(text):
    return {"type": "message", "role": "assistant", "id": "msg_local_1", "status": "completed",
            "content": [{"type": "output_text", "text": text}]}


class HistoryTests(unittest.TestCase):
    def test_canonicalizes_only_argument_structure_and_retains_projected_id_and_exact_text(self):
        wire = call_and_result("call", arguments='{"path":"file","offset":1}')
        expected = stock_pair(*wire)
        wire[0]["arguments"] = '{ "offset":1,"path":"file" }'
        self.assertEqual(stock_pair(*wire), expected)
        wire[0]["id"] = "fc_local_2"
        self.assertNotEqual(stock_pair(*wire).call, expected.call)
        wire[0]["id"] = "fc_local_1"
        wire[1]["output"] += " "
        self.assertNotEqual(stock_pair(*wire).identity, expected.identity)

    def test_rejects_duplicate_unknown_arguments_wrong_types_result_metadata_and_unmeasured_order(self):
        for arguments in ('{"path":"file","path":"first"}', '{"path":"file","extra":true}',
                          '{"path":"file","offset":true}', '{"path":"file","limit":-1}', '[]'):
            with self.subTest(arguments=arguments):
                call, result = call_and_result("call", arguments=arguments)
                with self.assertRaises(FixtureMismatch):
                    stock_pair(call, result)
        call, result = call_and_result("call")
        with self.assertRaises(FixtureMismatch):
            stock_pair(call, {**result, "id": "unmeasured"})
        reversed_pair = [user("ordinary"), result, call]
        with self.assertRaises(FixtureMismatch):
            stock_history(reversed_pair)
        duplicate_pair = [user("ordinary"), call, result, call, result]
        with self.assertRaises(FixtureMismatch):
            stock_history(duplicate_pair)

    def test_requires_entire_measured_title_shape(self):
        instructions = "Synthetic exact title instructions"
        body = {"model": MODEL, "input": [user(TITLE_PROMPT)], "instructions": instructions,
                "stream": True, "store": False, "prompt_cache_key": SESSION,
                "include": ["reasoning.encrypted_content"]}
        with patch("stock_worker_tools_history._TITLE_INSTRUCTIONS", hashlib.sha256(instructions.encode()).hexdigest()):
            self.assertIsNone(classify(body))
            for bad in ({"instructions": instructions + " "}, {"tools": []}, {"prompt_cache_key": "alien"},
                        {"input": [user("Summarize the restored conversation.")]}, {"input": [user(TITLE_PROMPT)] * 2}):
                with self.subTest(bad=bad), self.assertRaises(FixtureMismatch):
                    classify({**body, **bad})

    def test_rejects_hosted_mutated_or_extra_tool_declarations(self):
        instructions = "Synthetic exact ordinary instructions"
        tool = {"type": "function", "name": "read", "parameters": {"type": "object"}}
        body = {"model": MODEL, "input": [user("ordinary")], "instructions": instructions,
                "stream": True, "store": False, "prompt_cache_key": SESSION, "max_output_tokens": 16_384,
                "include": ["reasoning.encrypted_content"], "tools": [tool]}
        with patch.multiple("stock_worker_tools_history",
                            _CHAT_INSTRUCTIONS=hashlib.sha256(instructions.encode()).hexdigest(),
                            _TOOL_DEFINITIONS={"read": digest(tool)}):
            self.assertEqual(classify(body), stock_history(body["input"]))
            for tools in ([], [tool, tool], [{**tool, "type": "web_search"}], [{**tool, "strict": True}]):
                with self.subTest(tools=tools), self.assertRaises(FixtureMismatch):
                    classify({**body, "tools": tools})


class FixtureTurnsTests(unittest.TestCase):
    def setUp(self):
        fd = tempfile.TemporaryDirectory(prefix="oc-stock-turn-test-")
        self.addCleanup(fd.cleanup)
        self.path = Path(fd.name) / "exposure.sqlite"
        self.now = 10
        self.turns = FixtureTurns(self.path, AUTHORITY, clock=lambda: self.now)
        self.sent = []
        self.history = [user("first verified user message")]

    def send(self, request):
        self.sent.append(request.sequence)
        return request.sequence

    def dispatch(self, history=None, *, authority=AUTHORITY, session=SESSION, send=None):
        return self.turns.dispatch(authority, session, stock_history(self.history if history is None else history),
                                   self.send if send is None else send)[0]

    def assert_refused(self, match, history=None, **kwargs):
        expected = self.turns.records(), list(self.sent)
        with self.assertRaisesRegex(FixtureMismatch, match):
            self.dispatch(history, **kwargs)
        actual = self.turns.records(), self.sent
        self.assertEqual(actual, expected)

    def stage(self, request, *pairs, usage=(2, 3, 5), message=None):
        return self.turns.settle(AUTHORITY, request, calls=tuple(stock_pair(*pair).call for pair in pairs),
                                 completed_message=digest(message) if message else None, usage=usage)

    def deliver(self, request, pending, write=None, frames=(b"terminal", HANDOFF_END)):
        delivered = []
        self.turns.deliver(AUTHORITY, request, pending, delivered.append if write is None else write, frames)
        return delivered

    def test_cumulative_prefix_comparison_and_exact_one_suffix_per_durable_claim(self):
        for index in range(3):
            request = self.dispatch()
            pair = call_and_result(f"call_{index}")
            pending = self.stage(request, pair)
            self.assertEqual(self.deliver(request, pending), [b"terminal", HANDOFF_END])
            self.history.extend(pair)
        for edit in ("output", "arguments", "call_id", "id", "omission", "order"):
            modified = deepcopy(self.history)
            if edit == "output":
                modified[2]["output"] += " "
            elif edit == "arguments":
                modified[1]["arguments"] = '{"path":"other.txt"}'
            elif edit == "call_id":
                modified[1]["call_id"] = modified[2]["call_id"] = "changed_call"
            elif edit == "id":
                modified[1]["id"] = "fc_local_2"
            elif edit == "omission":
                del modified[1:3]
            else:
                modified[1:5] = modified[3:5] + modified[1:3]
            with self.subTest(edit=edit):
                self.assert_refused("Earlier stock tool history differs", modified)
        request = self.dispatch()
        self.deliver(request, self.stage(request, message=assistant("done")))
        records = self.turns.records()
        self.assertEqual(len(records), 4)
        self.assertIsNone(records[0]["parent"])
        self.assertEqual([row["suffix"] for row in records[1:]],
                         [f'["{stock_pair(*self.history[n:n+2]).identity}"]' for n in (1, 3, 5)])
        self.assertEqual(len({row["parent"] for row in records[1:]}), 3)
        self.assertEqual([(row["actual_input"], row["actual_output"]) for row in records], [(2, 3)] * 4)

    def test_latest_batch_requires_complete_ordered_results_once(self):
        request = self.dispatch()
        first, second = call_and_result("a"), call_and_result("b")
        self.deliver(request, self.stage(request, first, second))
        self.assert_refused("New stock tool batch differs", [*self.history, *first])
        self.assert_refused("New stock tool batch differs", [*self.history, *second, *first])
        self.assert_refused("New stock tool batch differs", [*self.history, *first, *second, *call_and_result("c")])
        modified = deepcopy(second)
        modified[0]["arguments"] = '{"path":"different"}'
        self.assert_refused("New stock tool batch differs", [*self.history, *first, *modified])
        self.dispatch([*self.history, *first, *second])
        self.assertEqual(self.sent, [1, 2])

    def test_settlement_and_complete_handoff_are_required(self):
        request = self.dispatch()
        pair = call_and_result("first")
        self.history.extend(pair)
        self.assert_refused("busy")
        pending = self.stage(request, pair)
        self.assert_refused("busy")
        self.deliver(request, pending)
        self.dispatch()
        self.assertEqual(self.sent, [1, 2])

    def test_continuation_adjacent_to_final_boundary_receives_published_batch(self):
        request = self.dispatch()
        pair = call_and_result("first")
        self.history.extend(pair)
        pending = self.stage(request, pair)
        final_written = Event()
        continuation_done = Event()
        delivering_thread = current_thread()
        authority_lock = self.turns._lock
        assert_done = self.assertTrue

        class ReleaseToContinuation:
            def __enter__(self):
                authority_lock.acquire()

            def __exit__(self, *_args):
                authority_lock.release()
                if current_thread() is delivering_thread and final_written.is_set():
                    assert_done(continuation_done.wait(5))

        def send(frame):
            if frame == HANDOFF_END:
                final_written.set()

        def continue_at_final_boundary():
            try:
                self.assertTrue(final_written.wait(5))
                return self.dispatch()
            finally:
                continuation_done.set()

        with patch.object(self.turns, "_lock", ReleaseToContinuation()), ThreadPoolExecutor() as pool:
            continuation = pool.submit(continue_at_final_boundary)
            self.deliver(request, pending, write=send)
            self.assertEqual(continuation.result(timeout=5).parent, pending.identity)
        self.assertEqual(self.sent, [1, 2])
        self.assertEqual(len(self.turns.records()), 2)

    def test_actual_partial_socket_handoff_fails_closed(self):
        request = self.dispatch()
        pair = call_and_result("first")
        self.history.extend(pair)
        pending = self.stage(request, pair)
        broker, worker = socket.socketpair()
        with closing(broker), closing(worker):
            def lose_peer():
                yield b"partial"
                self.assertEqual(worker.recv(7), b"partial")
                worker.close()
                yield b"final"

            frames = lose_peer()
            with self.assertRaises(BrokenPipeError):
                self.deliver(request, pending, write=broker.sendall, frames=frames)
        self.assert_refused("Stale or expired")
        self.assertEqual(self.turns.records()[0]["actual_output"], 3)

    def test_missing_final_boundary_never_opens_batch(self):
        request = self.dispatch()
        pair = call_and_result("first")
        self.history.extend(pair)
        pending = self.stage(request, pair)
        with self.assertRaisesRegex(FixtureMismatch, "Incomplete stock fixture handoff"):
            self.deliver(request, pending, frames=(b"terminal",))
        self.assert_refused("Stale or expired")

    def test_observed_mixed_scope_record_latches_hold_even_if_exact_rows_return(self):
        request = self.dispatch()
        pair = call_and_result("first")
        pending = self.stage(request, pair)
        self.deliver(request, pending)
        self.history.extend(pair)
        original = self.turns.records()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE exposure SET actual_output = 1")
        self.assert_refused("needs reconciliation")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE exposure SET actual_output = 3")
        self.assertEqual(self.turns.records(), original)
        self.assert_refused("Stale or expired")
        self.assertEqual(self.sent, [1])

    def test_wrong_model_terminal_cannot_settle_usage_or_qualify_batch(self):
        request = self.dispatch()
        pair = call_and_result("call_worker_proof_patch", name="patch", arguments='{"patchText":"synthetic"}')
        self.history.extend(pair)
        events = list(response_events(0, {"patchText": "synthetic"}))
        events[-1]["response"]["model"] = "wrong-model"
        response = SyntheticResponse(encode_sse(events))
        vault = ReasoningVault()
        projected_writes = []
        try:
            frames, usage = project_stream(response, vault, ("patch",), "resp_local_wrong_model")
        except FixtureMismatch as error:
            self.turns.fail(request)
            self.assertRegex(str(error), "Wrong synthetic terminal model")
        else:
            calls, message = terminal_output(frames[-1])
            pending = self.turns.settle(AUTHORITY, request, calls=calls, completed_message=message, usage=usage)
            self.deliver(request, pending, write=projected_writes.append)
            self.fail("Wrong synthetic terminal model was accepted")
        self.assertEqual(projected_writes, [])
        self.assertIsNone(self.turns.records()[0]["actual_input"])
        self.assertIsNone(self.turns.records()[0]["actual_output"])
        self.assert_refused("Stale or expired")
        self.assertEqual(self.sent, [1])

    def test_crossed_monotonic_deadline_after_claim_starts_no_write(self):
        original = self.turns._claim

        def slow_commit(request):
            original(request)
            self.now += 300

        with patch.object(self.turns, "_claim", side_effect=slow_commit):
            with self.assertRaisesRegex(FixtureMismatch, "Stale or expired"):
                self.dispatch()
        self.assertEqual(self.sent, [])
        self.assertIsNone(self.turns.records()[0]["actual_input"])

    def test_owner_loss_on_final_boundary_never_opens_batch(self):
        request = self.dispatch()
        pair = call_and_result("first")
        self.history.extend(pair)
        pending = self.stage(request, pair)

        def lose_authority_after_write(frame):
            if frame == HANDOFF_END:
                self.now += 300

        with self.assertRaisesRegex(FixtureMismatch, "Stale or expired"):
            self.deliver(request, pending, write=lose_authority_after_write)
        self.assert_refused("Stale or expired")
        self.assertEqual(self.turns.records()[0]["actual_output"], 3)

    def test_wrong_bindings_expiration_and_restart_refuse_before_claim(self):
        for field in ("job", "route", "slot", "generation", "model"):
            with self.subTest(field=field):
                self.assert_refused("Stale or expired", authority=replace(AUTHORITY, **{field: "foreign"}))
        pair = call_and_result("restored")
        self.assert_refused("unverified restore", [*self.history, *pair])
        request = self.dispatch()
        self.deliver(request, self.stage(request, pair))
        self.history.extend(pair)
        self.assert_refused("foreign session", session="ses_Other")
        self.now = 310
        self.assert_refused("Stale or expired")
        with self.assertRaises(FileExistsError):
            FixtureTurns(self.path, AUTHORITY)

    def test_failed_durable_claim_does_not_send_and_failed_settlement_never_opens(self):
        with patch.object(self.turns, "_claim", side_effect=sqlite3.OperationalError("fixture fault")):
            with self.assertRaises(sqlite3.OperationalError):
                self.dispatch()
        self.assertEqual(self.sent, [])
        self.assertEqual(self.turns.records(), [])
        sibling = self.path.with_name("settlement.sqlite")
        self.turns = FixtureTurns(sibling, AUTHORITY, clock=lambda: self.now)
        request = self.dispatch()
        pair = call_and_result("first")
        self.history.extend(pair)
        with patch.object(self.turns, "_settle_usage", side_effect=sqlite3.OperationalError("fixture fault")):
            with self.assertRaises(sqlite3.OperationalError):
                self.stage(request, pair)
        self.assert_refused("Stale or expired")
        self.assertIsNone(self.turns.records()[0]["actual_input"])

    def test_uncertain_claim_retains_exact_spend_and_full_reservation(self):
        request = self.dispatch()
        pair = call_and_result("first")
        pending = self.stage(request, pair)
        self.deliver(request, pending)
        self.history.extend(pair)

        def drop(next_request):
            self.send(next_request)
            raise ConnectionError("synthetic first write dropped")

        with self.assertRaises(ConnectionError):
            self.dispatch(send=drop)
        record = self.turns.records()[-1]
        self.assertEqual(record["parent"], pending.identity)
        self.assertEqual(record["suffix"], f'["{stock_pair(*pair).identity}"]')
        self.assertEqual((record["reserved_input"], record["reserved_output"]), (MAX_INPUT, MAX_OUTPUT))
        self.assertIsNone(record["actual_input"])
        self.assert_refused("Stale or expired")

    def test_commit_error_retains_only_exact_unresolved_claim_after_verified_prefix(self):
        request = self.dispatch()
        pair = call_and_result("first")
        pending = self.stage(request, pair)
        self.deliver(request, pending)
        self.history.extend(pair)
        first, = self.turns.verified_records()
        claim = self.turns._claim
        primary = sqlite3.OperationalError("synthetic error after SQLite commit")

        def commit_then_fail(request):
            claim(request)
            raise primary

        with patch.object(self.turns, "_claim", side_effect=commit_then_fail):
            with self.assertRaises(sqlite3.OperationalError) as raised:
                self.dispatch()
        self.assertIs(raised.exception, primary)
        settled, unresolved = self.turns.verified_records()
        self.assertEqual(settled, first)
        self.assertEqual(self.turns.records(), [settled, unresolved])
        self.assertEqual((unresolved["sequence"], unresolved["turn"], unresolved["parent"]),
                         (2, 1, pending.identity))
        self.assertEqual(unresolved["suffix"], f'["{stock_pair(*pair).identity}"]')
        self.assertEqual((unresolved["reserved_input"], unresolved["reserved_output"]), (MAX_INPUT, MAX_OUTPUT))
        self.assertIsNone(unresolved["actual_input"])
        self.assertIsNone(unresolved["actual_output"])
        self.assert_refused("Stale or expired")
        self.assertEqual(self.sent, [1])

        for field, sequence in (("actual_input", 1), ("reserved_input", 2)):
            with self.subTest(field=field):
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute(f"UPDATE exposure SET {field} = ? WHERE sequence = ?", (1, sequence))
                with self.assertRaisesRegex(FixtureMismatch, "needs reconciliation"):
                    self.turns.verified_records()
                with closing(sqlite3.connect(self.path)) as db, db:
                    exact_value = (settled, unresolved)[sequence - 1][field]
                    db.execute(f"UPDATE exposure SET {field} = ? WHERE sequence = ?", (exact_value, sequence))
                self.assert_refused("Stale or expired")

    def test_rolled_back_claim_does_not_invent_a_record_or_allow_retry(self):
        def rollback(request):
            with closing(self.turns._connect()) as db, db:
                db.execute("INSERT INTO exposure VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           self.turns._claimed_row(request))
                raise sqlite3.OperationalError("synthetic error before SQLite commit")

        with patch.object(self.turns, "_claim", side_effect=rollback):
            with self.assertRaises(sqlite3.OperationalError):
                self.dispatch()
        self.assertEqual(self.turns.verified_records(), [])
        self.assert_refused("Stale or expired")
        self.assertEqual(self.sent, [])

    def test_unresolved_claim_rejects_equal_sqlite_real_reservation(self):
        self.dispatch()
        (original,) = self.turns.verified_records()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("ALTER TABLE exposure RENAME TO original_exposure")
            db.execute("""CREATE TABLE exposure AS
                SELECT sequence, authority, turn, parent, suffix, CAST(reserved_input AS REAL) AS reserved_input,
                       reserved_output, actual_input, actual_output FROM original_exposure""")
            self.assertEqual(db.execute("SELECT typeof(reserved_input) FROM exposure").fetchone(), ("real",))
        self.assertEqual(self.turns.records(), [original])
        with self.assertRaisesRegex(FixtureMismatch, "needs reconciliation"):
            self.turns.verified_records()
        self.assert_refused("Stale or expired")

    def test_overage_is_recorded_and_closes_grant(self):
        request = self.dispatch()
        pair = call_and_result("a")
        with self.assertRaisesRegex(FixtureMismatch, "exceeded reservation"):
            self.stage(request, pair, usage=(MAX_INPUT + 1, MAX_OUTPUT, MAX_INPUT + MAX_OUTPUT + 1))
        self.assertEqual(self.turns.records()[0]["actual_input"], MAX_INPUT + 1)
        self.assert_refused("Stale or expired")

    def test_batch_count_and_terminal_usage_fail_closed(self):
        request = self.dispatch()
        pairs = [call_and_result(f"call{i}") for i in range(MAX_BATCH + 1)]
        with self.assertRaisesRegex(FixtureMismatch, "terminal output"):
            self.stage(request, *pairs)
        self.assert_refused("Stale or expired")
        self.assertIsNone(self.turns.records()[0]["actual_input"])

    def race(self):
        barrier = Barrier(2)

        def attempt():
            barrier.wait(timeout=5)
            try:
                return self.dispatch()
            except FixtureMismatch as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=2) as pool:
            a, b = pool.submit(attempt), pool.submit(attempt)
            return [a.result(timeout=5), b.result(timeout=5)]

    def test_duplicate_concurrency_before_settlement_before_handoff_and_after_handoff(self):
        request = self.dispatch()
        pair = call_and_result("first")
        self.history.extend(pair)
        self.assertEqual(self.race(), ["Stock route busy or foreign session"] * 2)
        pending = self.stage(request, pair)
        self.assertEqual(self.race(), ["Stock route busy or foreign session"] * 2)
        self.deliver(request, pending)
        raced = self.race()
        self.assertEqual([value.sequence for value in raced if not isinstance(value, str)], [2])
        self.assertIn("Stock route busy or foreign session", raced)
        self.assertEqual(self.sent, [1, 2])
        self.assertEqual(len(self.turns.records()), 2)

    def test_two_turns_and_eight_first_writes_even_if_all_settle_below_budget(self):
        for index in range(7):
            request = self.dispatch()
            if index == 3:
                final = assistant("first done")
                self.deliver(request, self.stage(request, message=final))
                self.history.extend((final, user("second verified user message")))
                changed = deepcopy(self.history)
                changed[-2]["content"][0]["text"] += " "
                self.assert_refused("Unverified completed stock history", changed)
            else:
                pair = call_and_result(f"call_{index}")
                self.deliver(request, self.stage(request, pair))
                self.history.extend(pair)
        raced = self.race()
        (request,) = [value for value in raced if not isinstance(value, str)]
        self.assertEqual(request.sequence, 8)
        self.assertIn("Stock route busy or foreign session", raced)
        final = assistant("second done")
        self.deliver(request, self.stage(request, message=final))
        # The measured request grammar separately refuses three user turns.
        twice = stock_history(self.history)
        third = replace(twice, closed=(*twice.closed, twice.user, *(pair.identity for pair in twice.pairs),
                                        digest(final)), pairs=())
        with self.assertRaisesRegex(FixtureMismatch, "Stock user turn limit"):
            self.turns.dispatch(AUTHORITY, SESSION, third, self.send)
        self.assertEqual(self.sent, list(range(1, 9)))
        self.assertEqual([record["turn"] for record in self.turns.records()], [1] * 4 + [2] * 4)

    def test_no_fourth_continuation_after_third_returns_another_batch(self):
        for index in range(3):
            request = self.dispatch()
            pair = call_and_result(f"call_{index}")
            self.deliver(request, self.stage(request, pair))
            self.history.extend(pair)
        request = self.dispatch()
        fourth = call_and_result("fourth")
        with self.assertRaisesRegex(FixtureMismatch, "continuation limit"):
            self.stage(request, fourth)
        self.history.extend(fourth)
        self.assert_refused("Stale or expired")
        self.assertEqual(self.sent, [1, 2, 3, 4])


class StreamTests(unittest.TestCase):
    def project(self, payload, boundary=b"0\r\n\r\n"):
        return project_stream(SyntheticResponse(payload, boundary), ReasoningVault(), ("patch",), "resp_local_test")

    def test_requires_terminal_line_delimiter_clean_http_boundary_and_clean_eof(self):
        events = tuple(response_events(0, {"patchText": "synthetic"}))
        payload = encode_sse(events)
        frames, usage = self.project(payload)
        self.assertEqual(usage, (2, 3, 5))
        calls, message = terminal_output(frames[-1])
        self.assertEqual([call.call_id for call in calls], ["call_worker_proof_patch"])
        self.assertIsNone(message)
        for data, boundary in ((encode_sse(events[:-1]), b"0\r\n\r\n"), (payload[:-1], b"0\r\n\r\n"),
                               (payload, b"0\r\n"), (payload, b"0\r\n\r\ntrailing")):
            with self.subTest(boundary=boundary, body_length=len(data)), self.assertRaises(
                    (ProviderConnectionError, FixtureMismatch, HTTPException, StreamAborted)):
                self.project(data, boundary)

    def test_impostor_or_usage_free_terminal_never_qualifies(self):
        events = list(response_events(0, {"patchText": "synthetic"}))
        usage = events[-1]["response"].pop("usage")
        _, observed = self.project(encode_sse(events))
        self.assertIsNone(observed)
        events[-1]["response"]["usage"] = usage
        with self.assertRaisesRegex(FixtureMismatch, "moderation metadata"):
            self.project(encode_sse([events[0], *events[2:]]))
        events[-1]["response"]["id"] = "other_response"
        with self.assertRaisesRegex(StreamAborted, "invalid_completed"):
            self.project(encode_sse(events))


if __name__ == "__main__":
    unittest.main()
