"""Local transport and fence tests for the synthetic ACP text broker."""

from contextlib import ExitStack, suppress
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import Mock, patch

import acp_text_broker as broker_module
from acp_readiness import ProtocolError, RetirementUnconfirmed, enroll_fixture
from acp_text_broker import BrokerReceipt, TextBroker
from acp_text_session import open_text_session
from oc_orchestrator import protocol
from oc_orchestrator.owner import Lifeline
from oc_orchestrator.relay import handoff


PROOF = b"p" * protocol.PROOF_SIZE
SYSTEM = "Broker fixture.\nToday's date: Tue Nov 24 2026"
SYSTEM_DIGEST = hashlib.sha256(b"Broker fixture.\nToday's date: [date]").hexdigest()


def request_body(**changes):
    return json.dumps({
        **protocol.OPTIONS,
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": protocol.PROMPT}],
        **changes,
    }).encode()


def listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(3)
        return server
    except BaseException:
        server.close()
        raise


def response(client):
    data = bytearray()
    while len(data) <= protocol.PROJECTED_LIMIT:
        try:
            chunk = client.recv(4096)
        except ConnectionResetError:
            break
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class TextBrokerTest(unittest.TestCase):
    def setUp(self):
        stack = self.enterContext(ExitStack())
        self.address = Path(stack.enter_context(TemporaryDirectory())) / "broker.sock"
        self.server = stack.enter_context(listener())
        self.port = self.server.getsockname()[1]
        stack.enter_context(patch.object(protocol, "SYSTEM_DIGEST", SYSTEM_DIGEST))
        self.peer = Mock(spec=["send_prompt", "complete", "retire"])
        self.peer.complete.return_value = "ok"
        self.body = request_body()
        self.answer = protocol.reply_bytes(protocol.FIXTURE_EVENTS)

    def broker(self, *, authorized=lambda: True):
        return TextBroker(self.address, PROOF, port=self.port, authorized=authorized)

    def open_peer(self, resources, broker, scene="ready"):
        root = Path(resources.enter_context(TemporaryDirectory()))
        return resources.enter_context(open_text_session(root, enroll_fixture(root), scene,
                                                         cancelled=broker.cancelled))

    def request(self, *, server=None, proof=PROOF, body=None, path="/v1/chat/completions"):
        server = self.server if server is None else server
        body = self.body if body is None else body
        host, port = server.getsockname()
        head = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                "Authorization: Bearer offline-fixture\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode()
        client = socket.create_connection((host, port), timeout=3)
        try:
            client.sendall(head + body)
            connection, _ = server.accept()
            with connection:
                if proof == PROOF:
                    handoff(connection, self.address, proof)
                else:
                    with suppress(BrokenPipeError, ConnectionResetError):
                        handoff(connection, self.address, proof)
            return client
        except BaseException:
            client.close()
            raise

    def test_only_one_authenticated_handoff_can_release_an_answer(self):
        with self.broker() as broker:
            broker.arm(self.peer)
            with self.request() as client:
                self.assertEqual(response(client), self.answer)
            with self.request() as client:
                self.assertEqual(response(client), protocol.REFUSAL)
            self.assertEqual(broker.receipt(), BrokerReceipt(1, 1, 1, len(self.answer), self.body))
        self.peer.send_prompt.assert_called_once_with()
        self.peer.complete.assert_called_once_with()

    def test_arming_rejects_a_handoff_already_in_the_transport_queue(self):
        start = Event()
        serve = TextBroker._serve

        def delayed(broker):
            if start.wait(3):
                serve(broker)

        with ExitStack() as resources, patch.object(TextBroker, "_serve", delayed), self.broker() as broker:
            peer = self.open_peer(resources, broker)
            try:
                with self.request() as client:
                    broker.arm(peer)
                    start.set()
                    self.assertEqual(response(client), b"")
                    self.assertEqual(broker.receipt(), BrokerReceipt(0, 0, 1, 0, None))
            finally:
                start.set()
        self.assertEqual(peer.prompt_count, 0)

    def test_invalid_forwarded_endpoint_proof_route_and_body_cannot_prompt(self):
        with self.broker() as broker, listener() as different:
            broker.arm(self.peer)
            for options, expected in (
                ({"server": different}, b""),
                ({"proof": b"x" * len(PROOF)}, b""),
                ({"path": "/v1/models"}, protocol.REFUSAL),
                ({"body": request_body(model="other")}, protocol.REFUSAL),
            ):
                with self.subTest(options=options), self.request(**options) as client:
                    self.assertEqual(response(client), expected)
            self.assertEqual(broker.receipt(), BrokerReceipt(0, 0, 4, 0, None))
        self.peer.send_prompt.assert_not_called()
        self.peer.complete.assert_not_called()

    def test_parsed_request_cannot_claim_after_explicit_revoke(self):
        parsed, release = Event(), Event()
        validate = protocol.accept_text

        def pause(body):
            validate(body)
            parsed.set()
            if not release.wait(3):
                raise AssertionError("The validation barrier was not released")

        with ExitStack() as resources, patch.object(protocol, "accept_text", pause), self.broker() as broker:
            peer = self.open_peer(resources, broker)
            broker.arm(peer)
            try:
                with self.request() as client:
                    self.assertTrue(parsed.wait(2))
                    broker.revoke()
                    release.set()
                    self.assertEqual(response(client), b"")
            finally:
                release.set()
        self.assertEqual(broker.receipt(), BrokerReceipt(0, 0, 1, 0, None))
        self.assertEqual(peer.prompt_count, 0)

    def test_negative_acp_transcripts_release_zero_http_answer_bytes(self):
        for scene in ("early", "mixed", "permission", "wrong-stop", "trailing"):
            with self.subTest(scene=scene), ExitStack() as resources, ExitStack() as broker_scope:
                # Each negative control gets its own private socket and one-shot peer.
                self.address = Path(resources.enter_context(TemporaryDirectory())) / "broker.sock"
                broker = broker_scope.enter_context(self.broker())
                peer = self.open_peer(resources, broker, scene)
                broker.arm(peer)
                with self.request() as client:
                    self.assertEqual(response(client), b"")
                with self.assertRaises(ProtocolError):
                    broker_scope.close()
                self.assertEqual(peer.prompt_count, 1)
                self.assertEqual(broker.outcome(), BrokerReceipt(1, 0, 1, 0, self.body))

    def test_owner_eof_blocks_release_even_before_the_watcher_runs(self):
        completing, release = Event(), Event()

        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as pipe, os.fdopen(write_fd, "wb") as owner:
            with patch("oc_orchestrator.owner.threading.Thread.start"):
                lifeline = Lifeline(pipe.fileno())
            with ExitStack() as resources, self.broker(authorized=lifeline.active) as broker:
                peer = self.open_peer(resources, broker)
                settle = peer.complete

                def pause_after_completion():
                    text = settle()
                    completing.set()
                    if not release.wait(3):
                        raise AssertionError("The completion barrier was not released")
                    return text

                peer.complete = pause_after_completion
                broker.arm(peer)
                try:
                    with self.request() as client:
                        self.assertTrue(completing.wait(2))
                        owner.close()
                        self.assertTrue(broker.cancelled())
                        release.set()
                        self.assertEqual(response(client), b"")
                        self.assertFalse(lifeline.lost.is_set())
                finally:
                    release.set()
        self.assertEqual(broker.receipt(), BrokerReceipt(1, 0, 1, 0, self.body))
        self.assertEqual(peer.prompt_count, 1)

    def test_owner_eof_retires_an_armed_idle_peer_before_context_exit(self):
        retired = Event()
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as pipe, os.fdopen(write_fd, "wb") as owner:
            lifeline = Lifeline(pipe.fileno())
            with (ExitStack() as resources, self.broker(authorized=lifeline.active) as broker,
                  lifeline.revoke_on_loss(broker.revoke)):
                peer = self.open_peer(resources, broker)
                settle = peer.retire

                def retire():
                    self.assertEqual(broker.outcome(), BrokerReceipt(0, 0, 0, 0, None))
                    settle()
                    retired.set()

                peer.retire = retire
                broker.arm(peer)
                owner.close()
                self.assertTrue(retired.wait(2))
                self.assertEqual(peer.prompt_count, 0)

    def test_failed_prompt_write_spends_the_claim_and_reaches_owner(self):
        self.peer.send_prompt.side_effect = ProtocolError("synthetic partial prompt write")
        with ExitStack() as broker_scope:
            broker = broker_scope.enter_context(self.broker())
            broker.arm(self.peer)
            with self.request() as client:
                self.assertEqual(response(client), b"")
            self.assertEqual(broker.outcome(), BrokerReceipt(1, 0, 1, 0, self.body))
            self.assertTrue(broker.cancelled())
            with self.assertRaisesRegex(ProtocolError, "partial prompt write"):
                broker_scope.close()
        self.peer.send_prompt.assert_called_once_with()
        self.peer.complete.assert_not_called()

    def test_failed_verification_reaches_owner_without_response_bytes(self):
        self.peer.complete.side_effect = ProtocolError("synthetic peer refused its transcript")
        with ExitStack() as broker_scope:
            broker = broker_scope.enter_context(self.broker())
            broker.arm(self.peer)
            with self.request() as client:
                self.assertEqual(response(client), b"")
            self.assertEqual(broker.outcome(), BrokerReceipt(1, 0, 1, 0, self.body))
            with self.assertRaisesRegex(ProtocolError, "peer refused its transcript"):
                broker.receipt()
            with self.assertRaisesRegex(ProtocolError, "peer refused its transcript"):
                broker_scope.close()
        self.peer.send_prompt.assert_called_once_with()
        self.peer.complete.assert_called_once_with()

    def test_retirement_failure_is_added_to_the_primary_error(self):
        self.peer.complete.side_effect = ProtocolError("synthetic transcript failed")
        self.peer.retire.side_effect = RetirementUnconfirmed("synthetic retirement unconfirmed")
        with ExitStack() as broker_scope:
            broker = broker_scope.enter_context(self.broker())
            broker.arm(self.peer)
            with self.request() as client:
                self.assertEqual(response(client), b"")
            with self.assertRaisesRegex(ProtocolError, "transcript failed") as failure:
                broker_scope.close()
        self.assertEqual(failure.exception.__notes__, [
            "Offline ACP peer retirement also failed: synthetic retirement unconfirmed",
        ])

    def test_short_response_is_not_retried_or_counted_as_an_answer(self):
        send = broker_module._send_once
        prefix = self.answer[:17]
        with (patch.object(broker_module, "_send_once", side_effect=lambda client, _: send(client, prefix)) as write,
              self.broker() as broker):
            broker.arm(self.peer)
            with self.request() as client:
                self.assertEqual(response(client), prefix)
            self.assertEqual(broker.receipt(), BrokerReceipt(1, 0, 1, len(prefix), self.body))
        write.assert_called_once()
        self.peer.send_prompt.assert_called_once_with()

    def test_interrupted_response_is_not_retried_or_counted_as_zero_bytes(self):
        with (patch.object(broker_module, "_libc_send", return_value=-1) as write,
              patch.object(broker_module.ctypes, "get_errno", return_value=errno.EINTR),
              self.broker() as broker):
            broker.arm(self.peer)
            with self.request() as client:
                self.assertEqual(response(client), b"")
            self.assertEqual(broker.receipt(), BrokerReceipt(1, 0, 1, None, self.body))
        write.assert_called_once()
        self.peer.send_prompt.assert_called_once_with()
