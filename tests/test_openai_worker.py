"""Synthetic upstream qualification for the managed OpenCode worker."""

from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from oc_openai import responses, worker
from oc_openai.managed import protocol
from oc_openai.managed.broker import Broker
from oc_openai.managed.relay import Lease, PROOF_PREFIX, grant_record, read_exact, take_fence
from oc_openai.managed.relay_receipt import RECEIPT, REQUEST_LENGTH, RESPONSE_HEADER
from oc_openai.managed.runtime import (
    JOB_DATA, WORKER_MODEL, JobRuntimeError, PUBLIC_CONTROL_VALUE, PUBLIC_RESPONSES_VALUE,
    atomic_write, podman, verify_file, worker_config,
)



_REPLAY_ITEMS = (
    {"type": "reasoning", "id": "rs_before_assistant", "summary": [],
     "encrypted_content": "host_reasoning_ciphertext_before_assistant"},
    {"type": "reasoning", "id": "rs_before_write", "status": "completed", "summary": [],
     "encrypted_content": "host_reasoning_ciphertext_before_write"},
)

def fixture_events(body, *, deadline, cancelled, reasoning=False, tool_only=False, done_only=False):
    assert time.monotonic() < deadline and not cancelled.is_set()
    assert body["store"] is False and body["stream"] is True
    assert "include" not in body
    assert body["instructions"] == protocol.INSTRUCTIONS
    tool, prompt, *history = body["input"]
    assert tool["type"] == "additional_tools" and len(tool["tools"]) == 1
    assert tool["tools"][0]["name"] == "write"
    assert set(tool["tools"][0]["parameters"]["properties"]) == {"path", "content"}
    assert prompt == {"type": "message", "role": "user", "content": protocol.PROMPT}
    initial = not history
    if not initial:
        expected_types = ["message", "function_call", "function_call_output"]
        if reasoning:
            expected_types = ["reasoning", "message", "reasoning", "function_call", "function_call_output"]
            assert history[0] == _REPLAY_ITEMS[0] and history[1 if tool_only else 2] == _REPLAY_ITEMS[1]
            if not tool_only:
                assert history[1]["phase"] == "commentary"
        if tool_only:
            expected_types.remove("message")
        assert [item["type"] for item in history] == expected_types
        assert history[-1] == {"type": "function_call_output", "call_id": "call_example",
                               "output": protocol.TOOL_RESULT}
    sequence = "1" if initial else "2"
    response = {"id": "resp_example" + sequence, "model": body["model"]}
    yield {"type": "response.created", "response": response}
    items = [{"id": "msg_example" + sequence, "type": "message", "role": "assistant", "status": "completed",
              "content": [{"type": "output_text",
                           "text": protocol.INITIAL_TEXT if initial else protocol.FINAL_TEXT}]}]
    if initial:
        if tool_only:
            items.clear()
        items.append({"id": "fc_example", "call_id": "call_example", "type": "function_call", "name": "write",
                      "status": "completed", "arguments": json.dumps({
                          "path": protocol.PROOF_PATH, "content": protocol.PROOF_BYTES.decode("ascii"),
                      })})
        if tool_only:
            items[-1].pop("status")
    if reasoning and initial:
        if tool_only:
            items = [_REPLAY_ITEMS[0].copy(), _REPLAY_ITEMS[1].copy(), items[0]]
        else:
            items[0]["phase"] = "commentary"
            items = [_REPLAY_ITEMS[0].copy(), items[0], _REPLAY_ITEMS[1].copy(), items[1]]
        for index in (0, 1 if tool_only else 2):
            item = items[index]
            yield {"type": "response.output_item.added", "output_index": index,
                   "item": {**item, "encrypted_content": "unfinished_ciphertext"}}
            yield {"type": "response.reasoning_text.delta", "output_index": index, "item_id": item["id"],
                   "delta": "discard this synthetic reasoning text"}
            yield {"type": "response.output_item.done", "output_index": index, "item": item.copy()}
            if done_only:
                item.pop("encrypted_content")
    yield {"type": "response.completed", "response": {
        **response, "status": "completed", "output": items,
        "usage": {"input_tokens": 3, "output_tokens": 2, "total_tokens": 5},
    }}


def native_payload(output=None):
    payload = {"model": WORKER_MODEL, "stream": True, "instructions": "private job instructions",
               "input": [{"type": "message", "role": "user", "content": protocol.PROMPT}],
               "tools": [{"type": "function", "name": "write", "description": "private job schema marker",
                          "parameters": {"type": "object", "properties": {
                              "content": {"type": "string"}, "path": {"type": "string"},
                          }}}]}
    if output:
        call = output[-1]
        payload["input"].extend([*output, {"type": "function_call_output", "call_id": call["call_id"],
                                           "output": "private job result marker"}])
    return payload


def native_request(payload, headers=b""):
    body = json.dumps(payload).encode()
    return (b"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            + f"Authorization: Bearer {PUBLIC_RESPONSES_VALUE}\r\n".encode("ascii")
            + b"Content-Type: application/json\r\n" + headers
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)


@contextmanager
def offline_broker(upstream, phases):
    with tempfile.TemporaryDirectory() as root_name:
        root = Path(root_name)
        provider = root / "provider.sock"
        generation = 7
        state = grant_record("inc_example", generation, True)
        (root / "state").write_bytes(state)
        (root / "lock").touch()
        with (root / "lifetime").open("w") as lifetime:
            take_fence(lifetime.fileno())
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                job = SimpleNamespace(provider_socket=provider, generation=generation, model="fixture-model",
                                      relay_proof=b"a" * 32,
                                      lease=Lease(root, state, time.monotonic_ns() + 30 * 10**9),
                                      assert_file=lambda expected: verify_file(fd, expected))
                broker = Broker(job, upstream, phases.append)
                broker.start()
                broker.activate()
                try:
                    yield root, job, broker
                finally:
                    broker.close()
            finally:
                os.close(fd)


@contextmanager
def exchange(job, payload, *, proof=None, headers=b""):
    raw = native_request(payload, headers)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(2)
        peer.connect(str(job.provider_socket))
        proof = job.relay_proof if proof is None else proof
        peer.sendall(PROOF_PREFIX + proof + REQUEST_LENGTH.pack(len(raw)) + raw)
        yield peer


def response(peer, *, generation=None):
    deadline = time.monotonic() + 2
    request_id, size = RESPONSE_HEADER.unpack(read_exact(peer, RESPONSE_HEADER.size, deadline))
    data = read_exact(peer, size, deadline)
    if generation is not None:
        peer.sendall(RECEIPT.pack(request_id, generation, size))
        peer.shutdown(socket.SHUT_WR)
        peer.recv(1)
    return data


class WorkerBrokerTests(unittest.TestCase):
    def test_only_fixed_host_values_cross_the_upstream_boundary(self):
        calls = []
        phases = []

        def upstream(body, **kwargs):
            calls.append(deepcopy(body))
            yield from fixture_events(body, **kwargs, reasoning=True)

        with offline_broker(upstream, phases) as (root, job, broker):
            altered = native_payload()
            altered["model"] = "other-model"
            schema = native_payload()
            schema["tools"].append({"type": "web_search"})
            history = native_payload()
            history["input"][0]["content"] = "unapproved job text"
            for bad in (altered, schema, history):
                with exchange(job, bad) as peer:
                    self.assertTrue(response(peer).startswith(b"HTTP/1.1 403"))
            with exchange(job, native_payload(), proof=b"b" * 32) as peer:
                try:
                    self.assertEqual(peer.recv(1), b"")
                except ConnectionResetError:
                    pass
            self.assertEqual(calls, [])

            with exchange(job, native_payload()) as peer:
                data = response(peer, generation=job.generation)
            self.assertNotIn(b"host_reasoning_ciphertext", data)
            self.assertNotIn(b"discard this synthetic reasoning text", data)
            terminal = next(item["response"] for item in (
                json.loads(frame[6:]) for frame in data.partition(b"\r\n\r\n")[2].splitlines() if frame
            ) if item["type"] == "response.completed")
            native = native_payload(terminal["output"])
            with exchange(job, native) as peer:
                self.assertTrue(response(peer).startswith(b"HTTP/1.1 403"))
            (root / "proof.txt").write_bytes(protocol.PROOF_BYTES)
            wrong_call = deepcopy(native)
            wrong_call["input"][-1]["call_id"] = "call_other"
            with exchange(job, wrong_call) as peer:
                self.assertTrue(response(peer).startswith(b"HTTP/1.1 403"))
            wrong_item = deepcopy(native)
            wrong_item["input"][-2]["id"] = "fc_other"
            with exchange(job, wrong_item) as peer:
                self.assertTrue(response(peer).startswith(b"HTTP/1.1 403"))
            self.assertEqual(phases, ["initial"])
            with exchange(job, native) as peer:
                data = response(peer, generation=job.generation)
            self.assertNotIn(b"host_reasoning_ciphertext", data)
            self.assertNotIn(b"discard this synthetic reasoning text", data)
            self.assertTrue(broker.complete("call_example"))
            with exchange(job, native) as peer:
                self.assertTrue(response(peer).startswith(b"HTTP/1.1 403"))

        self.assertEqual(phases, ["initial", "continuation"])
        self.assertEqual(len(calls), 2)
        for body in calls:
            self.assertNotIn("marker", json.dumps(body))

    def test_admitted_continuation_replaces_provisional_denial_with_delivery_failure(self):
        phases = []
        with offline_broker(fixture_events, phases) as (root, job, broker):
            with exchange(job, native_payload()) as peer:
                data = response(peer, generation=job.generation)
            terminal = next(item["response"] for item in (
                json.loads(frame[6:]) for frame in data.partition(b"\r\n\r\n")[2].splitlines() if frame
            ) if item["type"] == "response.completed")
            native = native_payload(terminal["output"])
            with exchange(job, native) as peer:
                self.assertTrue(response(peer).startswith(b"HTTP/1.1 403"))
            self.assertEqual(broker.failure(), ("continuation", protocol.Fault.CONTINUATION))
            (root / "proof.txt").write_bytes(protocol.PROOF_BYTES)
            with patch.object(broker, "_send", side_effect=OSError), exchange(job, native) as peer:
                self.assertEqual(peer.recv(1), b"")
            self.assertTrue(broker.done.wait(1))
            self.assertEqual(broker.failure(), ("continuation", protocol.Fault.DELIVERY))
        self.assertEqual(phases, ["initial", "continuation"])

    def test_wrong_generation_receipt_closes_the_turn(self):
        phases = []
        with offline_broker(fixture_events, phases) as (_, job, broker):
            with exchange(job, native_payload()) as peer:
                self.assertTrue(response(peer, generation=job.generation + 1).startswith(b"HTTP/1.1 200"))
            self.assertTrue(broker.done.wait(2))
            self.assertFalse(broker.complete("call_example"))
            with exchange(job, native_payload()) as peer:
                self.assertTrue(response(peer).startswith(b"HTTP/1.1 403"))
            self.assertEqual(phases, ["initial"])

    def test_revoke_cancels_an_admitted_upstream_and_refuses_next_request(self):
        phases = []
        requested = threading.Event()
        closed = threading.Event()

        def upstream(body, *, cancelled, **_):
            requested.set()
            if cancelled.wait(2):
                closed.set()
            return iter(())

        with offline_broker(upstream, phases) as (root, job, broker):
            with exchange(job, native_payload()) as peer:
                self.assertTrue(requested.wait(1))
                with job.lease.fence():
                    atomic_write(root / "state", grant_record("inc_example", job.generation, False))
                self.assertTrue(closed.wait(1))
                self.assertEqual(peer.recv(1), b"")
            self.assertTrue(broker.done.wait(1))
            with exchange(job, native_payload()) as peer:
                self.assertTrue(response(peer).startswith(b"HTTP/1.1 403"))
            self.assertEqual(phases, ["initial"])

    def test_terminal_reasoning_can_supply_the_only_completed_ciphertext(self):
        cases = ("only terminal", "done omits ciphertext", "done nulls ciphertext")
        for case in cases:
            with self.subTest(case=case):
                def upstream(body, **kwargs):
                    for event in fixture_events(body, **kwargs, reasoning=True):
                        kind = event["type"]
                        if case == "only terminal" and kind != "response.created" and kind != "response.completed":
                            continue
                        if kind == "response.output_item.done":
                            if case == "done omits ciphertext":
                                event["item"].pop("encrypted_content")
                            elif case == "done nulls ciphertext":
                                event["item"]["encrypted_content"] = None
                        yield event

                with offline_broker(upstream, []) as (_, job, _):
                    with exchange(job, native_payload()) as peer:
                        data = response(peer, generation=job.generation)
                    self.assertTrue(data.startswith(b"HTTP/1.1 200"))
                    self.assertNotIn(b"host_reasoning_ciphertext", data)
                    self.assertNotIn(b"discard this synthetic reasoning text", data)

    def test_unresumable_reasoning_blocks_tool_projection_and_continuation(self):
        def fault_events(fault):
            def upstream(body, **kwargs):
                for event in fixture_events(body, **kwargs, reasoning=True):
                    kind = event["type"]
                    if kind == "response.output_item.done" and event["output_index"] == 0:
                        if fault == "missing encrypted content":
                            event["item"].pop("encrypted_content")
                        if fault == "ciphertext mismatch":
                            event["item"]["encrypted_content"] = "different_ciphertext"
                        if fault == "reasoning ID mismatch":
                            event["item"]["id"] = "rs_different"
                        if fault == "incomplete done status":
                            event["item"]["status"] = "incomplete"
                        if fault == "conflicting completed occupant before reasoning":
                            yield {**event, "item": {"type": "message", "id": "msg_conflict"}}
                        if fault == "conflicting completed occupant after reasoning":
                            yield event
                            event = {**event, "item": {"type": "message", "id": "msg_conflict"}}
                    if kind == "response.completed":
                        output = event["response"]["output"]
                        if fault == "missing encrypted content":
                            output[0].pop("encrypted_content")
                        elif fault == "missing terminal reasoning":
                            output.pop(0)
                        elif fault == "unsupported phase":
                            output[1]["phase"] = "invalid phase"
                    yield event
            return upstream

        for fault in ("missing encrypted content", "missing terminal reasoning", "ciphertext mismatch",
                      "reasoning ID mismatch", "incomplete done status", "unsupported phase",
                      "conflicting completed occupant before reasoning",
                      "conflicting completed occupant after reasoning"):
            with self.subTest(fault=fault):
                phases = []
                with offline_broker(fault_events(fault), phases) as (root, job, broker):
                    with exchange(job, native_payload()) as peer:
                        self.assertEqual(peer.recv(1), b"")
                    self.assertTrue(broker.done.wait(2))
                    self.assertIn(broker.failure()[1], (protocol.Fault.REASONING, protocol.Fault.MESSAGE))
                    self.assertFalse((root / "proof.txt").exists())
                    with exchange(job, native_payload()) as peer:
                        self.assertTrue(response(peer).startswith(b"HTTP/1.1 403"))
                    self.assertEqual(phases, ["initial"])

    def test_tool_only_completed_shape_rejects_non_neutral_metadata(self):
        for field, value in (("async", 0), ("caller", {"type": "program"}), ("status", "incomplete"),
                             ("namespace", ""), ("id", None)):
            with self.subTest(field=field):
                cancelled = threading.Event()
                events = list(fixture_events(
                    protocol.body_for("fixture-model"), deadline=time.monotonic() + 2, cancelled=cancelled,
                    tool_only=True,
                ))
                events[-1]["response"]["output"][0][field] = value
                with self.assertRaises(protocol.Refused) as error:
                    protocol.validate(events, "fixture-model", True, cancelled)
                self.assertIs(error.exception.fault, protocol.Fault.TOOL)

    def test_closed_progress_diagnostics_reject_bad_identity_payload_and_annotation(self):
        faults = (
            ({"type": "response.queued", "response": {"id": "resp_other", "status": "queued"}},
             protocol.Fault.EVENT_SEQUENCE),
            ({"type": "keepalive", "payload": "private"}, protocol.Fault.EVENT_LABEL),
            ({"type": "response.output_text.annotation.added", "annotation": {"url": "private"}},
             protocol.Fault.ANNOTATION),
        )
        for event, fault in faults:
            with self.subTest(fault=fault):
                cancel = threading.Event()
                events = list(fixture_events(
                    protocol.body_for("fixture-model"), deadline=time.monotonic() + 2, cancelled=cancel,
                ))
                events.insert(1, event)
                with self.assertRaises(protocol.Refused) as error:
                    protocol.validate(events, "fixture-model", True, cancel, allow_progress=True)
                self.assertIs(error.exception.fault, fault)
                self.assertNotIn("private", str(error.exception))
        for initial in (True, False):
            with self.subTest(initial=initial):
                result = list(fixture_events(
                    protocol.body_for("fixture-model"), deadline=time.monotonic() + 2, cancelled=threading.Event(),
                ))
                output = result[-1]["response"]["output"]
                if not initial:
                    output.pop()
                    output[0]["content"][0]["text"] = protocol.FINAL_TEXT
                output[0]["content"][0]["annotations"] = [{"url": "private"}]
                if not initial:
                    ordinary = protocol.validate(result, "fixture-model", False, threading.Event())
                    self.assertNotIn("private", repr(ordinary.native))
                with self.assertRaises(protocol.Refused) as error:
                    protocol.validate(result, "fixture-model", initial, threading.Event(), allow_progress=True)
                self.assertIs(error.exception.fault, protocol.Fault.ANNOTATION)

    def test_followup_added_item_index_check_preserves_ordinary_admission(self):
        events = list(fixture_events(
            protocol.body_for("fixture-model"), deadline=time.monotonic() + 2, cancelled=threading.Event(),
        ))
        events.insert(1, {"type": "response.output_item.added", "item": {"type": "message"}})
        self.assertTrue(protocol.validate(events, "fixture-model", True, threading.Event()).native)
        with self.assertRaises(protocol.Refused) as error:
            protocol.validate(events, "fixture-model", True, threading.Event(), allow_progress=True)
        self.assertIs(error.exception.fault, protocol.Fault.EVENT_ITEM)

    def test_metadata_requires_bound_neutral_envelope_and_approved_write(self):
        expected = {"type": "response.metadata", "response_id": "resp_example1",
                    "sequence_number": 1, "metadata": {}}
        cases = (
            ({"sequence_number": True}, protocol.Fault.METADATA_ENVELOPE),
            ({"response_id": "resp_other"}, protocol.Fault.METADATA_ENVELOPE),
            ({"metadata": []}, protocol.Fault.METADATA_ENVELOPE),
            ({"error": None}, protocol.Fault.METADATA_ENVELOPE),
            ({"metadata": {"private_effect": True}}, protocol.Fault.METADATA_FIELDS),
            ({"metadata": {"type": "safety_buffering"}}, protocol.Fault.SAFETY_BUFFERING),
            ({"metadata": {"guardian": {"requires_review": False}}}, protocol.Fault.METADATA_REVIEW),
            ({"metadata": {"openai_verification_recommendation": ["verification"]}}, protocol.Fault.METADATA_REVIEW),
            ({"metadata": {"openai_chatgpt_moderation_metadata": {"is_blocked": True}}},
             protocol.Fault.METADATA_MODERATION),
        )
        for change, fault in cases:
            with self.subTest(fault=fault):
                cancelled = threading.Event()
                events = list(fixture_events(
                    protocol.body_for("fixture-model"), deadline=time.monotonic() + 2, cancelled=cancelled,
                ))
                events.insert(1, {**expected, **change})
                with self.assertRaises(protocol.Refused) as error:
                    protocol.validate(events, "fixture-model", True, cancelled,
                                      allow_progress=True, allow_metadata=True)
                self.assertIs(error.exception.fault, fault)
        events[1] = expected
        events[0]["safety_buffering"] = False
        self.assertTrue(protocol.validate(events, "fixture-model", True, cancelled, allow_metadata=True).native)
        events[-1]["response"]["output"].pop()
        with self.assertRaises(protocol.Refused) as error:
            protocol.validate(events, "fixture-model", True, cancelled, allow_metadata=True)
        self.assertIs(error.exception.fault, protocol.Fault.TOOL)

    def test_worker_json_limit_is_distinct_from_raw_stream_budget(self):
        event = {"type": "response.in_progress", "fixture": "😀" * 32_000}
        progress = [event] * 7
        raw_size = sum(len(json.dumps(item, ensure_ascii=False).encode("utf-8")) + 8 for item in progress)
        self.assertLess(raw_size, responses.MAX_STREAM)
        self.assertGreater(sum(len(json.dumps(item)) for item in progress), protocol.MAX_RESPONSE)
        created = {"type": "response.created", "response": {"id": "resp_fixture"}}
        with self.assertRaises(protocol.Refused) as error:
            protocol.validate([created, *progress], "fixture-model", True, threading.Event())
        self.assertIs(error.exception.fault, protocol.Fault.EVENT_BYTES)

    def test_encoded_continuation_cap_applies_before_tool_delivery(self):
        phases = []
        body = protocol.body_for("fixture-model")
        upstream = lambda body, **kwargs: fixture_events(body, **kwargs, reasoning=True)
        sample = list(upstream(body, deadline=time.monotonic() + 2, cancelled=threading.Event()))
        continuation = protocol.body_for("fixture-model", sample[-1]["response"]["output"])
        encoded_size = len(responses.encode_responses_body(continuation))
        self.assertLess(len(responses.encode_responses_body(body)), encoded_size - 1)
        with patch.object(responses, "MAX_JSON", encoded_size):
            self.assertEqual(len(responses.encode_responses_body(continuation)), encoded_size)
        with (patch.object(responses, "MAX_JSON", encoded_size - 1),
              offline_broker(upstream, phases) as (root, job, broker)):
            with exchange(job, native_payload()) as peer:
                self.assertEqual(peer.recv(1), b"")
            self.assertTrue(broker.done.wait(2))
            self.assertFalse((root / "proof.txt").exists())
            self.assertEqual(phases, ["initial"])

    def test_unknown_upstream_item_blocks_tool_projection(self):
        phases = []

        def upstream(body, **kwargs):
            for event in fixture_events(body, **kwargs):
                if event["type"] == "response.completed":
                    yield {"type": "response.output_item.added", "item": {"type": "web_search_call"}}
                yield event

        with offline_broker(upstream, phases) as (_, job, broker):
            with exchange(job, native_payload()) as peer:
                self.assertEqual(peer.recv(1), b"")
            self.assertTrue(broker.done.wait(2))
            self.assertFalse(broker.complete("call_example"))
            self.assertEqual(phases, ["initial"])


class NativeToolEvidenceTests(unittest.TestCase):
    def test_requires_same_named_write_from_start_through_success(self):
        observer = SimpleNamespace(delivered=True, pins=SimpleNamespace(thread_id="ses_example"),
                                   assistants={"msg_expected", "msg_other"})
        identity = {"sessionID": "ses_example", "assistantMessageID": "msg_expected", "id": "call_example"}
        started = {"type": "session.tool.input.started", "data": {**identity, "name": "write"}}
        called = {"type": "session.tool.called", "data": {**identity, "executed": False, "input": {
            "path": protocol.PROOF_PATH, "content": protocol.PROOF_BYTES.decode("ascii"),
        }}}
        success = {"type": "session.tool.success", "data": {**identity, "executed": False}}

        evidence = worker._NativeWrite()
        for item in (started, called, success):
            evidence.accept(item, observer)
        self.assertTrue(evidence.succeeded)

        cases = (
            (called,),
            ({**started, "data": {**identity, "name": "other_tool"}},),
            (started, started),
            (started, called, called),
            (started, called, success, success),
            (started, {**called, "data": {**called["data"], "assistantMessageID": "msg_other"}}),
            (started, called, {**success, "data": {**success["data"], "id": "call_other"}}),
            (started, called, {**success, "data": {**success["data"], "status": "failed"}}),
            (started, called, {**success, "type": "session.tool.failed"}),
        )
        for sequence in cases:
            with self.subTest(sequence=[item["type"] for item in sequence]), self.assertRaises(worker.WorkerError):
                evidence = worker._NativeWrite()
                for item in sequence:
                    evidence.accept(item, observer)

    def test_generated_config_denies_every_integration_connection(self):
        connect = [policy for policy in worker_config()["policies"] if policy["action"] == "integration.connect"]
        self.assertEqual(connect, [{"action": "integration.connect", "resource": "*", "effect": "deny"}])


class WorkerCleanupTests(unittest.TestCase):
    def test_failed_lease_release_retains_only_its_exact_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            surrounding = Path(temp)
            other = surrounding / "unrelated.txt"
            other.write_text("outside this run")
            order = []

            def prepared_job(root, *_):
                def prepare():
                    (root / "receipt.json").write_text("{}")
                    order.append("prepare")

                def launch_failure(_):
                    raise worker.WorkerError("Synthetic pre-activation failure")

                return SimpleNamespace(root=root, prepare=prepare, assert_file=launch_failure)

            @contextmanager
            def lease_guard(job):
                self.assertTrue((job.root / "receipt.json").is_file())
                order.append("register")
                try:
                    yield
                finally:
                    order.append("unregister")
                    raise RuntimeError("private bookkeeping failure")

            with (patch.object(worker, "SHARED_TMP", surrounding),
                  patch.object(worker, "Job", side_effect=prepared_job),
                  patch.object(worker, "_cleanup", side_effect=lambda *_: order.append("cleanup")),
                  self.assertRaises(worker.WorkerCleanupError) as caught):
                worker.run_worker(fixture_events, model="fixture-model", before_dispatch=lambda _: None,
                                  lease_guard=lease_guard)
            self.assertEqual(order, ["prepare", "register", "cleanup", "unregister"])
            self.assertRegex(caught.exception.receipt_leaf, r"^oc-i4a-[a-z0-9_]{8}$")
            receipt = surrounding / caught.exception.receipt_leaf / "receipt.json"
            self.assertTrue(receipt.is_file())
            self.assertNotIn(str(surrounding), str(caught.exception))
            self.assertEqual(other.read_text(), "outside this run")


class RelayLifetimeTests(unittest.TestCase):
    def test_pending_then_active_sockets_close_when_the_owner_is_lost(self):
        relay_code = """
import sys
from pathlib import Path
from oc_openai.managed import relay
root, provider, native = sys.argv[1:]
relay.PROVIDER = ("127.0.0.1", int(provider))
relay.WORKER = ("127.0.0.1", int(native))
relay.CONTROL_SOCKET = str(Path(root) / "control.sock")
relay.serve(relay.Lease(Path(root), relay.grant_record("inc_example", 7, True),
                        relay.time.monotonic_ns() + 15 * 10**9), b"a" * 32)
"""
        with tempfile.TemporaryDirectory() as root_name, socket.socket() as native, socket.socket() as probe:
            root = Path(root_name)
            native.settimeout(2)
            native.bind(("127.0.0.1", 0))
            native.listen()
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
            (root / "state").write_bytes(b"pending\n")
            (root / "lock").touch()
            owner = (root / "lifetime").open("w")
            self.addCleanup(owner.close)
            take_fence(owner.fileno())
            child = subprocess.Popen([sys.executable, "-c", relay_code, root_name, str(port),
                                      str(native.getsockname()[1])])
            try:
                control_path = root / "control.sock"
                until = time.monotonic() + 3
                while not control_path.is_socket() and time.monotonic() < until and child.poll() is None:
                    time.sleep(0.01)
                self.assertTrue(control_path.is_socket())
                with socket.socket(socket.AF_UNIX) as pending:
                    pending.settimeout(1)
                    pending.connect(str(control_path))
                    self.assertEqual(pending.recv(1), b"")

                atomic_write(root / "state", grant_record("inc_example", 7, True))
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(1)
                    client.connect(str(control_path))
                    message = b"GET / HTTP/1.1\r\n\r\n"
                    client.sendall(b"N" + len(message).to_bytes(4, "big") + message)
                    self.assertEqual(client.recv(1), b"H")
                    downstream, _ = native.accept()
                    with downstream:
                        self.assertEqual(read_exact(downstream, len(message), time.monotonic() + 1), message)
                        owner.close()
                        self.assertEqual(client.recv(1), b"")
                        self.assertEqual(downstream.recv(1), b"")
                self.assertEqual(child.wait(timeout=1), 0)
                with self.assertRaises(ConnectionRefusedError):
                    socket.create_connection(("127.0.0.1", port), timeout=1)
                with socket.socket(socket.AF_UNIX) as closed:
                    with self.assertRaises(ConnectionRefusedError):
                        closed.connect(str(control_path))
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=2)

    def test_lifetime_replacement_terminal_and_expiry_never_admit(self):
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            active = grant_record("inc_example", 7, True)
            (root / "state").write_bytes(active)
            (root / "lock").touch()
            with (root / "lifetime").open("w") as owner:
                take_fence(owner.fileno())
                timed_out = Lease(root, active, time.monotonic_ns() - 1)
                self.assertEqual(timed_out.status(), "terminal")
                lease = Lease(root, active, time.monotonic_ns() + 10**9)
                self.assertEqual(lease.status(), "active")
                atomic_write(root / "state", grant_record("inc_example", 7, False))
                self.assertEqual(lease.status(), "terminal")
                atomic_write(root / "state", active)
                with (root / "new-lifetime").open("w") as replacement:
                    take_fence(replacement.fileno())
                    os.replace(root / "new-lifetime", root / "lifetime")
                    self.assertEqual(lease.status(), "terminal")
                    replacement_lease = Lease(root, active, time.monotonic_ns() + 10**9)
                    self.assertEqual(replacement_lease.status(), "active")
                    (root / "new-lock").touch()
                    os.replace(root / "new-lock", root / "lock")
                    self.assertEqual(replacement_lease.status(), "terminal")
                    with self.assertRaises(OSError), replacement_lease.fence():
                        self.fail("Replacement grant lock cannot authorize a delivery")


class WorkerFileTests(unittest.TestCase):
    def test_exact_bytes_and_nofollow(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                verify_file(fd, None)
                proof = directory / "proof.txt"
                marker = directory / "other.txt"
                marker.write_bytes(protocol.PROOF_BYTES)
                proof.symlink_to(marker)
                for expectation in (None, protocol.PROOF_BYTES):
                    with self.assertRaises(JobRuntimeError):
                        verify_file(fd, expectation)
                proof.unlink()
                os.link(marker, proof)
                with self.assertRaises(JobRuntimeError):
                    verify_file(fd, protocol.PROOF_BYTES)
                proof.unlink()
                os.mkfifo(proof)
                with self.assertRaises(JobRuntimeError):
                    verify_file(fd, protocol.PROOF_BYTES)
                proof.unlink()
                proof.write_bytes(protocol.PROOF_BYTES)
                verify_file(fd, protocol.PROOF_BYTES)
            finally:
                os.close(fd)


@unittest.skipUnless(os.environ.get("OC_OPENAI_WORKER_REAL") == "1", "requires pinned Podman/devbox host")
class WorkerPodmanTests(unittest.TestCase):
    def test_native_turn(self):
        phases = []
        seen = []

        def upstream(body, **kwargs):
            seen.append(body)
            return fixture_events(body, **kwargs, reasoning=True)

        native_turn = worker._native_turn

        def probe_alternate_client(job):
            def worker_cmd(*args):
                return podman("exec", job.ids["worker"], *args).stdout

            self.assertEqual(worker_cmd("cat", "/fixture/job-data"), JOB_DATA)
            self.assertEqual(worker_cmd("ip", "route"), b"")
            self.assertEqual(worker_cmd("ip", "-6", "route"), b"")
            self.assertNotIn(b"host-only synthetic credential", worker_cmd("env"))
            api_probe = """
import base64
import http.client
import json
import sys

auth = "Basic " + base64.b64encode(f"opencode:{sys.argv[1]}".encode()).decode()
for integration in ("openai", "local"):
    conn = http.client.HTTPConnection("127.0.0.1", 4096, timeout=3)
    try:
        conn.request("POST", "/api/credential",
                     body=json.dumps({"integrationID": integration, "value": {"type": "key", "key": "inert-test-key"}}),
                     headers={"Authorization": auth, "Content-Type": "application/json"})
        result = conn.getresponse()
        print(result.status, json.loads(result.read(4097)).get("message", ""))
    finally:
        conn.close()
"""
            denial = podman("exec", job.ids["relay"], "python3", "-c", api_probe, PUBLIC_CONTROL_VALUE).stdout
            self.assertEqual(len(denial.splitlines()), 2)
            for line in denial.lower().splitlines():
                self.assertTrue(line.startswith(b"400 ") and b"policy" in line, denial)

            history = native_payload()
            history["input"][0]["content"] = "unapproved alternate request"
            model = native_payload()
            model["model"] = "other-model"
            schema = native_payload()
            schema["tools"].append({"type": "web_search"})
            for unapproved in (history, model, schema):
                result = worker_cmd("/bin/sh", "-c",
                                    '(printf "%s" "$1"; sleep 1) | nc -w 2 127.0.0.1 8401',
                                    "test", native_request(unapproved).decode("ascii"))
                self.assertTrue(result.startswith(b"HTTP/1.1 403"))
            self.assertEqual(seen, [])
            return native_turn(job)

        with (patch.object(worker, "_native_turn", probe_alternate_client),
              patch.dict(os.environ, {"OPENAI_API_KEY": "host-only synthetic credential"})):
            evidence = worker.run_worker(upstream, model="fixture-model", before_dispatch=phases.append)
        self.assertEqual(evidence, worker.WorkerEvidence())
        self.assertEqual(phases, ["initial", "continuation"])
        self.assertEqual(len(seen), 2)


if __name__ == "__main__":
    unittest.main()
