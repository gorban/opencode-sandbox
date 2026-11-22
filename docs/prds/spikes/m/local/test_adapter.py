"""Synthetic one-job transport tests. All worker and relay sockets are local pairs."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import json
from pathlib import Path
import socket
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

_SPIKE_M_DIR = str(Path(__file__).resolve().parent.parent)
if _SPIKE_M_DIR not in sys.path:
    sys.path.insert(0, _SPIKE_M_DIR)

from oc_coord_contract import DispatchOutcome, RoutingEdge, TrustClass, TurnDispatch, sha256_canonical_body

from adapter import LocalOpenCodeTransport, PauseBarrier
from broker import Broker
from client import DispatchOutcome as RelayOutcome, OpenCode, ProbeError, Wire
from runtime import JobRuntimeError


TARGET = "fixture"
INCARNATION = "inc_fixture"
THREAD = "main"
EDGE = "edge_fixture"
MESSAGE = "msg_fixture"
TEXT = "Synthetic fixture task."


def native(id_, kind, session, **fields):
    return {"id": id_, "type": kind, "data": {"sessionID": session, **fields}}


class FakeEvents:
    def __init__(self, wire):
        self.wire = wire
        self.frames = []

    def __iter__(self):
        return iter(self.frames)


class FakeExchange:
    def __init__(self, wire, outcome, paused):
        self.wire = wire
        self.outcome = outcome
        self.pause_acknowledged = paused

    def receipt(self):
        return self.outcome


class Fixture:
    def __init__(self):
        self.sessions = iter(("ses_one", "ses_two"))
        self.outcome = RelayOutcome.HANDED_OFF
        self.reply = "match"
        self.reply_reads = 0
        self.prompts = []
        self.events_closed = 0
        self.replies_closed = 0
        self.previous = None
        self.only_foreign_terminal = False
        self.omit_terminal = False

    def open_code(self, *args, **kwargs):
        return FakeOpenCode(self, *args, **kwargs)

    def native_events(self, session, input_id):
        assistant = "msg_assistant"
        delivered = native("evt_input", "session.inbox.delivered", session, inboxID=input_id)
        started = native("evt_step", "session.step.started", session, assistantMessageID=assistant)
        delta = native("evt_delta", "session.text.delta", session, assistantMessageID=assistant,
                       ordinal=0, delta="fixture")
        yield delivered
        yield started
        if self.previous is not None:
            yield native("evt_foreign", "session.execution.succeeded", self.previous)
        yield delta
        yield delta
        if not self.only_foreign_terminal and not self.omit_terminal:
            yield native("evt_done", "session.execution.succeeded", session)
        self.previous = session


class FakeOpenCode(OpenCode):
    def __init__(self, fixture, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fixture = fixture
        self.subscription = None

    def create_session(self, deadline):
        self._thread_id = next(self.fixture.sessions)
        return self._thread_id

    @contextmanager
    def events(self, deadline):
        driver, peer = socket.socketpair()
        with driver, peer:
            self.subscription = FakeEvents(Wire(driver, deadline))
            try:
                yield self.subscription
            finally:
                self.fixture.events_closed += 1

    def read_prompt_reply(self, wire, pins, deadline):
        self.fixture.reply_reads += 1
        return super().read_prompt_reply(wire, pins, deadline)

    @contextmanager
    def prompt_exchange(self, encoded, deadline, *, pause=False):
        self.fixture.prompts.append(encoded)
        input_id = json.loads(encoded.split(b"\r\n\r\n", 1)[1])["id"]
        driver, peer = socket.socketpair()
        with driver, peer:
            self._fill_reply(peer, input_id)
            self.subscription.frames = list(self.fixture.native_events(self._thread_id, input_id))
            try:
                yield FakeExchange(Wire(driver, deadline), self.fixture.outcome, pause)
            finally:
                self.fixture.replies_closed += 1

    def _fill_reply(self, peer, input_id):
        mode = self.fixture.reply
        if mode == "lost":
            peer.shutdown(socket.SHUT_WR)
            return
        data = {"data": {"id": input_id if mode == "match" else "msg_other",
                         "sessionID": self._thread_id, "type": "user"}}
        body = json.dumps(data).encode("ascii")
        head = (f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode("ascii")
        peer.sendall(head + body)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        client = patch("adapter.OpenCode", side_effect=self.fixture.open_code)
        client.start()
        self.addCleanup(client.stop)
        self.job = Mock(
            incarnation=INCARNATION, generation=1, run_label="a" * 32,
            ids={"relay": "b" * 64}, recorded_ids={"relay": "b" * 64},
            control_socket=Path("/unused"), password="synthetic", terminal=False, assert_running=Mock(),
            provider_socket=Path("/unused-provider"),
        )
        self.job.revoke.side_effect = self._mark_terminal
        self.broker = Mock()
        self.broker.is_bound_to.return_value = True
        self.transport = self.make_transport()
        self.addCleanup(self.clean_transport)

    def _mark_terminal(self):
        self.job.terminal = True

    def make_transport(self, *, pause=None):
        transport = LocalOpenCodeTransport(self.job, self.broker, sandbox_addr=TARGET, thread_id=THREAD, pause=pause)
        transport.bind_grant(RoutingEdge(EDGE, "operator:fixture", None, TARGET,
                                         frozenset({THREAD}), frozenset({"prompt"})))
        return transport

    def clean_transport(self):
        self.job.revoke.side_effect = self._mark_terminal
        self.transport.abort_incarnation(TARGET, INCARNATION, reason="fixture done")

    def turn(self, msg_id=MESSAGE, text=TEXT):
        return TurnDispatch(msg_id, TARGET, INCARNATION, THREAD, TrustClass.OPERATOR_DIRECTIVE,
                            "prompt", text, sha256_canonical_body(text), edge_id=EDGE)

    def prepare(self, msg_id=MESSAGE):
        self.transport.reserve()
        self.transport.bind(msg_id)

    def test_handoff_reads_no_http_payload_and_binds_events_to_the_host(self):
        self.prepare()
        result = self.transport.dispatch_turn(self.turn())
        self.assertIs(result.outcome, DispatchOutcome.HANDED_OFF)
        self.assertEqual(self.fixture.reply_reads, 0)
        self.assertEqual(self.fixture.replies_closed, 0)
        self.assertEqual(list(self.transport.stream_events("unknown_stream")), [])
        events = list(self.transport.stream_events(result.stream_id))
        self.assertEqual([event.event_type for event in events], ["text_delta", "turn_completed"])
        self.assertEqual(events[0].text, "fixture")
        for event in events:
            self.assertEqual((event.sandbox_addr, event.incarnation_id, event.thread_id, event.message_id),
                             (TARGET, INCARNATION, THREAD, MESSAGE))
            self.assertIsNone(event.file_path)
            self.assertEqual(event.detail, {})
        self.assertEqual(self.fixture.events_closed, 1)
        self.assertEqual(self.fixture.replies_closed, 1)
        self.assertEqual(list(self.transport.stream_events(result.stream_id)), [])

    def test_deterministic_invalid_turns_never_open_prompt_exchange(self):
        self.prepare()
        turn = self.turn()
        variations = (
            {"sandbox_addr": "other"}, {"incarnation_id": "inc_other"}, {"thread_id": "different"},
            {"edge_id": "edge_other"}, {"grant_generation": 2}, {"grant_generation": True},
            {"lease_request_id": "lease_fixture"}, {"trust_class": TrustClass.SYSTEM_ALERT},
            {"msg_kind": "review"}, {"artifact_refs": ("unsupported",)}, {"msg_id": "msg_other"},
        )
        for change in variations:
            with self.subTest(change=change):
                result = self.transport.dispatch_turn(replace(turn, **change))
                self.assertIs(result.outcome, DispatchOutcome.ZERO_BYTES_SENT)
                self.assertTrue(result.permanent)
        self.assertEqual(self.fixture.prompts, [])

    def test_digest_and_encoded_http_oversize_are_permanent(self):
        self.prepare()
        wrong_digest = replace(self.turn(), body_sha256="0" * 64)
        result = self.transport.dispatch_turn(wrong_digest)
        self.assertIs(result.outcome, DispatchOutcome.ZERO_BYTES_SENT)
        self.assertTrue(result.permanent)
        self.prepare("msg_next")
        result = self.transport.dispatch_turn(self.turn("msg_next", "é" * 16_000))
        self.assertIs(result.outcome, DispatchOutcome.ZERO_BYTES_SENT)
        self.assertTrue(result.permanent)
        self.assertEqual(self.fixture.prompts, [])

    def test_permanent_digest_and_replay_refusals_take_precedence_over_busy(self):
        self.prepare()
        first = self.transport.dispatch_turn(self.turn())
        self.assertIs(first.outcome, DispatchOutcome.HANDED_OFF)
        wrong_digest = replace(self.turn("msg_next"), body_sha256="0" * 64)
        for invalid in (wrong_digest, self.turn()):
            with self.subTest(message=invalid.msg_id):
                refused = self.transport.dispatch_turn(invalid)
                self.assertIs(refused.outcome, DispatchOutcome.ZERO_BYTES_SENT)
                self.assertTrue(refused.permanent)
        future = self.transport.dispatch_turn(self.turn("msg_next"))
        self.assertIs(future.outcome, DispatchOutcome.ZERO_BYTES_SENT)
        self.assertFalse(future.permanent)
        self.assertEqual(len(self.fixture.prompts), 1)

    def test_reserve_refuses_changed_or_terminal_job_before_creating_session(self):
        self.addCleanup(setattr, self.job, "ids", self.job.ids)
        self.addCleanup(setattr, self.job, "terminal", self.job.terminal)
        states = (({"relay": "c" * 64}, False), (self.job.ids, True))
        for ids, terminal in states:
            with self.subTest(terminal=terminal), patch("adapter.OpenCode") as native:
                self.job.ids, self.job.terminal = ids, terminal
                with self.assertRaisesRegex(ProbeError, "job is unavailable"):
                    self.transport.reserve()
                native.assert_not_called()

    def test_constructor_rejects_foreign_broker_or_replaced_provider_inode(self):
        with TemporaryDirectory() as directory:
            expected = Path(directory) / "provider.sock"
            foreign = Path(directory) / "different.sock"
            correct = Broker(expected, "synthetic")
            other = Broker(foreign, "synthetic")
            self.addCleanup(correct.close)
            self.addCleanup(other.close)
            correct.start()
            other.start()
            self.job.provider_socket = expected
            with self.assertRaisesRegex(ProbeError, "broker binding"):
                self.make_transport_with_broker(other)
            expected.unlink()
            with socket.socket(socket.AF_UNIX) as replacement:
                replacement.bind(str(expected))
                with self.assertRaisesRegex(ProbeError, "broker binding"):
                    self.make_transport_with_broker(correct)
            self.job.revoke.assert_not_called()
            self.job.provider_socket = Path("/unused-provider")

    def make_transport_with_broker(self, broker):
        return LocalOpenCodeTransport(self.job, broker, sandbox_addr=TARGET, thread_id=THREAD)

    def test_revoke_fences_exact_job_when_broker_binding_is_lost(self):
        self.prepare()
        owner = self.transport.transport_owner_id(TARGET, INCARNATION)
        self.broker.is_bound_to.return_value = False
        self.addCleanup(setattr, self.broker.is_bound_to, "return_value", True)
        self.assertFalse(self.transport.confirm_incarnation_terminal(
            TARGET, INCARNATION, owner_id=owner, reason="fixture"))
        self.broker.revoke.assert_not_called()
        self.job.revoke.assert_called_once()
        self.assertTrue(self.job.terminal)
        self.assertFalse(self.transport.status(TARGET, INCARNATION).revoked)
        self.assertTrue(self.transport.dispatch_turn(self.turn()).permanent)
        self.assertEqual(self.fixture.prompts, [])
        self.assertEqual(self.fixture.events_closed, 1)

    def test_positive_zero_can_retry_the_same_unwritten_reserved_prompt(self):
        self.prepare()
        self.fixture.outcome = RelayOutcome.ZERO_BYTES_SENT
        result = self.transport.dispatch_turn(self.turn())
        self.assertIs(result.outcome, DispatchOutcome.ZERO_BYTES_SENT)
        self.assertFalse(result.permanent)
        self.fixture.outcome = RelayOutcome.HANDED_OFF
        result = self.transport.dispatch_turn(self.turn())
        self.assertIs(result.outcome, DispatchOutcome.HANDED_OFF)
        self.assertEqual(len(self.fixture.prompts), 2)
        self.assertEqual(self.fixture.prompts[0], self.fixture.prompts[1])

    def test_uncertain_receipt_quarantines_before_return(self):
        self.prepare()
        self.fixture.outcome = RelayOutcome.UNCERTAIN
        result = self.transport.dispatch_turn(self.turn())
        self.assertIs(result.outcome, DispatchOutcome.UNCERTAIN)
        self.assertEqual(self.transport.status(TARGET, INCARNATION).state, "degraded")
        result = self.transport.dispatch_turn(self.turn())
        self.assertTrue(result.permanent)
        self.assertEqual(len(self.fixture.prompts), 1)
        self.assertEqual(self.fixture.events_closed, 1)
        self.assertEqual(self.fixture.replies_closed, 1)

    def test_post_handoff_missing_reply_preserves_handoff_and_blocks_new_turn(self):
        self._assert_post_handoff_failure(reply="lost")

    def test_post_handoff_foreign_reply_preserves_handoff_and_blocks_new_turn(self):
        self._assert_post_handoff_failure(reply="foreign")

    def test_post_handoff_missing_terminal_blocks_new_turn(self):
        self.fixture.omit_terminal = True
        self._assert_post_handoff_failure(reply="match")

    def _assert_post_handoff_failure(self, *, reply):
        self.fixture.reply = reply
        self.prepare()
        result = self.transport.dispatch_turn(self.turn())
        self.assertIs(result.outcome, DispatchOutcome.HANDED_OFF)
        events = list(self.transport.stream_events(result.stream_id))
        self.assertEqual(events[-1].event_type, "turn_error")
        self.assertEqual(events[-1].text, "native_stream_unconfirmed")
        with self.assertRaisesRegex(ProbeError, "unavailable"):
            self.transport.reserve()
        refused = self.transport.dispatch_turn(self.turn("msg_next"))
        self.assertTrue(refused.permanent)
        self.assertEqual(len(self.fixture.prompts), 1)
        self.assertEqual(self.fixture.events_closed, 1)
        self.assertEqual(self.fixture.replies_closed, 1)

    def test_previous_terminal_cannot_settle_the_second_message(self):
        self.prepare()
        result = self.transport.dispatch_turn(self.turn())
        self.assertEqual(list(self.transport.stream_events(result.stream_id))[-1].event_type, "turn_completed")
        self.prepare("msg_next")
        self.fixture.only_foreign_terminal = True
        result = self.transport.dispatch_turn(self.turn("msg_next"))
        events = list(self.transport.stream_events(result.stream_id))
        self.assertEqual([event.event_type for event in events], ["text_delta", "turn_error"])
        self.assertEqual(events[-1].message_id, "msg_next")

    def test_reused_session_id_is_rejected_before_second_prompt(self):
        self.fixture.sessions = iter(("ses_one", "ses_one"))
        self.prepare()
        result = self.transport.dispatch_turn(self.turn())
        list(self.transport.stream_events(result.stream_id))
        with self.assertRaisesRegex(ProbeError, "session ID was reused"):
            self.transport.reserve()
        self.assertEqual(len(self.fixture.prompts), 1)

    def test_exact_owner_and_positive_terminal_receipt_required(self):
        owner = self.transport.transport_owner_id(TARGET, INCARNATION)
        with self.assertRaisesRegex(ProbeError, "unknown"):
            self.transport.transport_owner_id(TARGET, "inc_other")
        self.assertFalse(self.transport.confirm_incarnation_terminal(
            TARGET, INCARNATION, owner_id="other", reason="fixture"))
        self.assertFalse(self.transport.confirm_incarnation_terminal(
            TARGET, "inc_other", owner_id=owner, reason="fixture"))
        self.job.revoke.assert_not_called()
        self.job.revoke.side_effect = JobRuntimeError("fixed synthetic error")
        self.assertFalse(self.transport.confirm_incarnation_terminal(
            TARGET, INCARNATION, owner_id=owner, reason="fixture"))
        self.job.revoke.side_effect = self._mark_terminal
        self.assertTrue(self.transport.confirm_incarnation_terminal(
            TARGET, INCARNATION, owner_id=owner, reason="fixture"))
        self.assertTrue(self.transport.status(TARGET, INCARNATION).revoked)
        self.assertTrue(self.transport.confirm_incarnation_terminal(
            TARGET, INCARNATION, owner_id=owner, reason="fixture"))

    def test_pause_does_not_hold_local_lock_across_receipt_or_discard_positive_zero(self):
        pause = PauseBarrier()
        self.transport = self.make_transport(pause=pause)
        self.fixture.outcome = RelayOutcome.ZERO_BYTES_SENT
        self.prepare()
        owner = self.transport.transport_owner_id(TARGET, INCARNATION)
        with ThreadPoolExecutor(max_workers=2) as workers:
            dispatch = workers.submit(self.transport.dispatch_turn, self.turn())
            try:
                self.assertTrue(pause.acknowledged.wait(1))
                revoke = workers.submit(self.transport.confirm_incarnation_terminal, TARGET, INCARNATION,
                                        owner_id=owner, reason="fixture")
                self.assertTrue(revoke.result(timeout=1))
                self.assertFalse(dispatch.done())
            finally:
                pause.release.set()
            result = dispatch.result(timeout=1)
        self.assertIs(result.outcome, DispatchOutcome.ZERO_BYTES_SENT)
        self.assertIs(pause.outcome, DispatchOutcome.ZERO_BYTES_SENT)
        self.assertEqual(self.fixture.events_closed, 1)
        self.assertEqual(self.fixture.replies_closed, 1)


if __name__ == "__main__":
    unittest.main()
