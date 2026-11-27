"""Exercise the managed Gemini route with real local sockets and a synthetic session."""

from contextlib import suppress
import hashlib
import json
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import Mock

from oc_google.route import TurnBroker
from oc_orchestrator import protocol
from oc_orchestrator.relay import handoff


MODEL = "gemini-test"
WORKER_TOKEN = "test-worker-capability"
PROOF = b"p" * protocol.PROOF_SIZE
SYSTEM = "Pinned Gemini shell.\nToday's date: Wed Nov 25 2026"
DIGEST = hashlib.sha256(b"Pinned Gemini shell.\nToday's date: [date]").hexdigest()
MESSAGES = [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": protocol.PROMPT}]


def request_body(**fields):
    return json.dumps({**protocol.OPTIONS, "model": MODEL, "messages": MESSAGES, **fields}).encode()


class TurnBrokerTest(unittest.TestCase):
    def setUp(self):
        self.address = Path(self.enterContext(TemporaryDirectory())) / "provider.sock"
        self.listener = self.enterContext(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        self.session = Mock(spec=["send_prompt", "complete", "retire"])
        self.session.complete.return_value = "ok"

    def broker(self, *, authorized=lambda: True):
        return TurnBroker(self.address, PROOF, authorized=authorized, worker_token=WORKER_TOKEN,
                          model=MODEL, system_digest=DIGEST, port=self.port)

    def request(self, *, body=None, token=WORKER_TOKEN, proof=PROOF):
        if body is None:
            body = request_body()
        head = (f"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                f"Authorization: Bearer {token}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode()
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as client:
            client.sendall(head + body)
            accepted, _ = self.listener.accept()
            with accepted, suppress(BrokenPipeError, ConnectionResetError):
                handoff(accepted, self.address, proof)
            response = bytearray()
            with suppress(ConnectionResetError):
                while chunk := client.recv(4096):
                    response.extend(chunk)
            return bytes(response)

    def test_exact_request_answers_once_after_verifying_the_peer(self):
        with self.broker() as broker:
            self.assertEqual(self.request(), b"")
            self.session.send_prompt.assert_not_called()
            broker.arm(self.session)
            answer = self.request()
            headers, _, stream = answer.partition(b"\r\n\r\n")
            self.assertTrue(headers.startswith(b"HTTP/1.1 200 OK\r\n"))
            first, terminal, done = stream.strip().split(b"\n\n")
            first = json.loads(first.removeprefix(b"data: "))
            terminal = json.loads(terminal.removeprefix(b"data: "))
            self.assertEqual(first["model"], MODEL)
            self.assertEqual(first["choices"], [
                {"index": 0, "delta": {"role": "assistant", "content": "ok"}, "finish_reason": None},
            ])
            self.assertEqual(terminal["choices"], [{"index": 0, "delta": {}, "finish_reason": "stop"}])
            self.assertEqual(done, b"data: [DONE]")
            self.assertEqual(self.request(), protocol.REFUSAL)
            receipt = broker.receipt()
            self.assertEqual((receipt.claims, receipt.answers, receipt.response_bytes), (1, 1, len(answer)))
        self.session.send_prompt.assert_called_once_with()
        self.session.complete.assert_called_once_with()
        self.session.retire.assert_called_once_with()

    def test_only_the_exact_worker_token_and_measured_text_shape_can_claim(self):
        with self.broker() as broker:
            broker.arm(self.session)
            self.assertEqual(self.request(proof=b"x" * len(PROOF)), b"")
            for token in ("offline-fixture", "other-worker-token"):
                with self.subTest(token=token):
                    self.assertEqual(self.request(token=token), protocol.REFUSAL)
            for fields in (
                {"model": MODEL + "-other"},
                {"tools": []},
                {"stream": 1},
                {"messages": [*MESSAGES, {"role": "assistant", "content": "ok"}]},
                {"messages": [MESSAGES[0], {**MESSAGES[1], "name": "operator"}]},
                {"messages": [MESSAGES[0], {**MESSAGES[1], "content": protocol.PROMPT + "\n"}]},
                {"messages": [MESSAGES[0], {**MESSAGES[1], "role": "assistant"}]},
                {"messages": [{**MESSAGES[0], "content": SYSTEM + "\nOther context"}, MESSAGES[1]]},
            ):
                with self.subTest(fields=fields):
                    self.assertEqual(self.request(body=request_body(**fields)), protocol.REFUSAL)
            duplicate_model = request_body().replace(b'{"model":', b'{"model":"other","model":', 1)
            self.assertEqual(self.request(body=duplicate_model), protocol.REFUSAL)
            receipt = broker.receipt()
            self.assertEqual((receipt.claims, receipt.answers, receipt.response_bytes), (0, 0, 0))
        self.session.send_prompt.assert_not_called()
        self.session.complete.assert_not_called()

    def test_owner_loss_after_prompt_admission_blocks_the_answer(self):
        owner = Event()
        owner.set()

        def complete():
            owner.clear()
            return "ok"

        self.session.complete.side_effect = complete
        with self.broker(authorized=owner.is_set) as broker:
            broker.arm(self.session)
            self.assertEqual(self.request(), b"")
            receipt = broker.receipt()
            self.assertEqual((receipt.claims, receipt.answers, receipt.response_bytes), (1, 0, 0))
        self.session.send_prompt.assert_called_once_with()
        self.session.retire.assert_called_once_with()

    def test_failed_attended_ack_keeps_the_broker_unarmed(self):
        def refuse_ack():
            self.session.send_prompt.assert_not_called()
            raise RuntimeError("arm acknowledgement failed")

        with self.broker() as broker:
            with self.assertRaisesRegex(RuntimeError, "arm acknowledgement failed"):
                broker.arm(self.session, confirm=refuse_ack)
            self.assertEqual(self.request(), b"")
            self.assertEqual(broker.outcome().claims, 0)
        self.session.send_prompt.assert_not_called()

    def test_unverified_text_fails_without_releasing_an_answer(self):
        self.session.complete.return_value = "other"
        broker = self.broker()
        with self.assertRaisesRegex(RuntimeError, "did not verify exact fixture text"), broker:
            broker.arm(self.session)
            self.assertEqual(self.request(), b"")
            receipt = broker.outcome()
            self.assertEqual((receipt.claims, receipt.answers, receipt.response_bytes), (1, 0, 0))
        self.session.send_prompt.assert_called_once_with()
        self.session.retire.assert_called_once_with()
