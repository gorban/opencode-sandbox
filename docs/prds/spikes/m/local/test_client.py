from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from client import DispatchOutcome, OpenCode, ProbeError, RelayExchange, Response, TurnEvent, TurnEvents, TurnPins, Wire
from probe import observe
import relay


INVALID_JSON = "invalid JSON response"


def event(kind, session="ses_pinned", **data):
    return {"type": kind, "data": {"sessionID": session, **data}}


class ClientTests(unittest.TestCase):
    def response(self, raw, media=None):
        client, peer = socket.socketpair()
        self.addCleanup(client.close)
        with peer:
            peer.sendall(raw)
        return Response(Wire(client, time.monotonic() + 1), status=200, media=media)

    def json_response(self, body):
        head = f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii")
        return self.response(head + body)

    def test_decode_chunked_events_across_boundaries(self):
        head = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n")
        chunks = [b"data: {\"type\":", b"\"server.connected\"}\n\n: heartbeat\n\n"]
        wire = b"".join(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n" for chunk in chunks)
        response = self.response(head + wire + b"0\r\n\r\n", "text/event-stream")
        self.assertEqual(list(response.events()), [{"type": "server.connected"}])

    def test_refuse_redirect_and_compression(self):
        for raw, message in [
            (b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n", "status 302"),
            (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n", "compressed"),
        ]:
            with self.subTest(message=message), self.assertRaisesRegex(ProbeError, message):
                self.response(raw)

    def test_refuse_ambiguous_or_oversized_http_body(self):
        with self.assertRaisesRegex(ProbeError, "framing"):
            self.response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n")
        response = self.response(b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n")
        with self.assertRaisesRegex(ProbeError, "size"):
            response.json()

    def test_require_canonical_content_length(self):
        for length in (b"00", b"01", b"00000001"):
            raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + length + b"\r\n\r\n"
            with self.subTest(length=length), self.assertRaisesRegex(ProbeError, "framing"):
                self.response(raw)
        response = self.json_response(b"")
        self.assertEqual(list(response.chunks(0)), [])

    def test_reject_nonfinite_json_numbers(self):
        for number in (b"NaN", b"Infinity", b"-Infinity", b"1e400", b"-1e400"):
            with self.subTest(number=number):
                response = self.json_response(b'{"data":[{"number":' + number + b"}]}")
                with self.assertRaisesRegex(ProbeError, INVALID_JSON):
                    response.json()

    def test_reject_nul_and_unpaired_surrogates_in_nested_json_strings(self):
        for escaped in (rb"\u0000", rb"\ud800", rb"\udfff"):
            for body in (
                b'{"data":{"' + escaped + b'":0}}',
                b'{"data":[{"value":"' + escaped + b'"}]}',
            ):
                with self.subTest(body=body):
                    response = self.json_response(body)
                    with self.assertRaisesRegex(ProbeError, INVALID_JSON):
                        response.json()

    def test_accept_valid_escaped_json_and_utf8(self):
        body = rb'{"value":"\ud83d\ude80\n\\u0000 ' + "café".encode() + b'", "number":1e20}'
        response = self.json_response(body)
        self.assertEqual(response.json(), {"value": "🚀\n\\u0000 café", "number": 1e20})

    def test_apply_json_validation_to_sse_data(self):
        body = b'data: {"type":"server.connected","data":{"n":1e400}}\n\n'
        events = self.json_response(body).events()
        with self.assertRaisesRegex(ProbeError, INVALID_JSON):
            next(events)

    def test_cli_entrypoint_sets_owner_only_umask_without_import_side_effect(self):
        result = subprocess.run(
            [sys.executable, "-B", "-c", """
import os
import runpy
import sys

os.umask(0o022)
import probe
assert os.umask(0o022) == 0o022, "import changed the caller's umask"
sys.argv[1:] = ["--help"]
try:
    runpy.run_module("probe", run_name="__main__")
except SystemExit as exit:
    assert exit.code == 0
assert os.umask(0o077) == 0o077, "CLI entrypoint did not set umask 077"
"""],
            cwd=Path(__file__).resolve().parent, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_close_evidence_requires_peer_eof(self):
        client, peer = socket.socketpair()
        with client, peer:
            wire = Wire(client, time.monotonic() + 1)
            peer.sendall(b"trailing bytes")
            deadline = time.monotonic() + 0.02
            with self.assertRaisesRegex(ProbeError, "left the control event stream open"):
                wire.await_eof(deadline)
            peer.shutdown(socket.SHUT_WR)
            wire.await_eof(time.monotonic() + 0.2)

    def test_preclosed_peer_fails_liveness_even_with_queued_data(self):
        client, peer = socket.socketpair()
        with client, peer:
            wire = Wire(client, time.monotonic() + 1)
            peer.sendall(b"trailing event data")
            wire.assert_open()
            peer.shutdown(socket.SHUT_WR)
            with self.assertRaisesRegex(ProbeError, "closed before revoke"):
                wire.assert_open()

    def test_map_only_explicit_handoff_receipts(self):
        for raw, expected in [
            (b"H", DispatchOutcome.HANDED_OFF),
            (b"Z", DispatchOutcome.ZERO_BYTES_SENT),
            (b"U", DispatchOutcome.UNCERTAIN),
        ]:
            with self.subTest(raw=raw):
                client, peer = socket.socketpair()
                with client, peer:
                    peer.sendall(raw)
                    exchange = RelayExchange(Wire(client, time.monotonic() + 1), b"request", pause=False)
                    self.assertIs(exchange.receipt(), expected)
                    self.assertEqual(peer.recv(12), b"N\x00\x00\x00\x07request")
        client, peer = socket.socketpair()
        with client, peer:
            exchange = RelayExchange(Wire(client, time.monotonic() + 1), b"request", pause=False)
            peer.shutdown(socket.SHUT_WR)
            self.assertIs(exchange.receipt(), DispatchOutcome.UNCERTAIN)

    def test_already_terminal_pause_returns_zero_without_dial_or_release(self):
        active = relay.grant_record("fixture", 1, True)
        client, peer = socket.socketpair()
        with client, peer, TemporaryDirectory() as directory:
            grant = Path(directory)
            (grant / "state").write_bytes(relay.grant_record("fixture", 1, False))
            with ((grant / "lifetime").open("xb") as lifetime,
                  patch.object(relay, "GRANT", grant),
                  patch.object(relay.socket, "create_connection") as dial,
                  ThreadPoolExecutor(max_workers=1) as pool):
                relay.take_fence(lifetime.fileno())
                handled = pool.submit(relay.control, peer, active)
                exchange = RelayExchange(Wire(client, time.monotonic() + 1), b"request", pause=True)
                self.assertFalse(exchange.pause_acknowledged)
                self.assertIs(exchange.receipt(), DispatchOutcome.ZERO_BYTES_SENT)
                handled.result(timeout=1)
                dial.assert_not_called()
                peer.setblocking(False)
                with self.assertRaises(BlockingIOError):
                    peer.recv(1)

    def test_pause_requires_acknowledgment_before_releasing(self):
        client, peer = socket.socketpair()
        with client, peer:
            peer.sendall(b"PZ")
            deadline = time.monotonic() + 1
            exchange = RelayExchange(Wire(client, deadline), b"request", pause=True)
            self.assertTrue(exchange.pause_acknowledged)
            self.assertIs(exchange.receipt(), DispatchOutcome.ZERO_BYTES_SENT)
            self.assertEqual(relay.read_exact(peer, 13, deadline), b"P\x00\x00\x00\x07requestG")

        for reply in (b"H", b"U", b""):
            with self.subTest(reply=reply):
                client, peer = socket.socketpair()
                with client, peer:
                    peer.sendall(reply)
                    peer.shutdown(socket.SHUT_WR)
                    deadline = time.monotonic() + 1
                    wire = Wire(client, deadline)
                    with self.assertRaisesRegex(ProbeError, "outcome uncertain"):
                        RelayExchange(wire, b"request", pause=True)
                    self.assertEqual(relay.read_exact(peer, 12, deadline), b"P\x00\x00\x00\x07request")
                    peer.setblocking(False)
                    with self.assertRaises(BlockingIOError):
                        peer.recv(1)

    def test_turn_filters_session_input_and_assistant_identity(self):
        turn = TurnEvents(TurnPins("local-poc", "inc", "ses_pinned", "msg_pinned", 1))

        delta = event("session.text.delta", assistantMessageID="msg_native", ordinal=0, delta="fixture")
        terminal = event("session.execution.succeeded")
        self.assertIsNone(turn.accept(delta))
        self.assertIsNone(turn.accept(event("session.inbox.delivered", "ses_other", inboxID="msg_pinned")))
        self.assertIsNone(turn.accept(event("session.inbox.delivered", inboxID="msg_other")))
        self.assertIsNone(turn.accept(terminal))
        self.assertIsNone(turn.accept(event("session.inbox.delivered", inboxID="msg_pinned")))
        self.assertIsNone(turn.accept(delta))
        self.assertIsNone(turn.accept(event("session.step.started", assistantMessageID="msg_native")))
        self.assertEqual(turn.accept(delta), TurnEvent("text_delta", "fixture", ("msg_native", 0)))
        self.assertIsNone(turn.accept(event("session.execution.succeeded", "ses_other")))
        self.assertEqual(turn.accept(terminal), TurnEvent("turn_completed"))

    def test_marker_assembles_only_within_one_assistant_text_part(self):
        pins = TurnPins("local-poc", "inc", "ses_pinned", "msg_pinned", 1)
        prefix = [
            event("session.inbox.delivered", inboxID="msg_pinned"),
            event("session.step.started", assistantMessageID="msg_one"),
            event("session.step.started", assistantMessageID="msg_two"),
            event("session.text.delta", assistantMessageID="msg_one", ordinal=0, delta="fixture "),
        ]
        terminal = event("session.execution.succeeded")
        for assistant, ordinal in [("msg_one", 1), ("msg_two", 0), ("msg_one", None), ("msg_one", False)]:
            with self.subTest(assistant=assistant, ordinal=ordinal):
                unrelated = event("session.text.delta", assistantMessageID=assistant, ordinal=ordinal, delta="text")
                with self.assertRaisesRegex(ProbeError, "before the expected text delta"):
                    observe([*prefix, unrelated, terminal], TurnEvents(pins), "fixture text", wait_for_terminal=False)

        interleaved = event("session.text.delta", assistantMessageID="msg_one", ordinal=1, delta="other")
        matching = event("session.text.delta", assistantMessageID="msg_one", ordinal=0, delta="text")
        observe([*prefix, interleaved, matching, terminal], TurnEvents(pins), "fixture text", wait_for_terminal=False)

    def test_prompt_checks_all_selected_job_and_session_pins_before_exchange(self):
        client = OpenCode(Path("/unused"), "fixture", sandbox_addr="local-poc",
                          incarnation_id="inc_current", grant_generation=2)
        valid = TurnPins("local-poc", "inc_current", "ses_pinned", "msg_pinned", 2)
        deadline = time.monotonic() + 1
        with patch("client.unix_wire") as open_socket:
            with self.assertRaisesRegex(ProbeError, "pinned job and session"):
                client.prompt(valid, "fixture", deadline)
            open_socket.assert_not_called()

        with patch.object(client, "_response") as response:
            result = response.return_value.__enter__.return_value
            result.json.return_value = {"data": {"id": valid.thread_id, "location": {"directory": "/workspace"}}}
            self.assertEqual(client.create_session(deadline), valid.thread_id)
            response.reset_mock()
            with self.assertRaisesRegex(ProbeError, "session already pinned"):
                client.create_session(deadline)
            response.assert_not_called()

        changes = (
            {"sandbox_addr": "other-target"},
            {"incarnation_id": "inc_previous"},
            {"thread_id": "ses_other"},
            {"grant_generation": 1},
            {"grant_generation": 2.0},
        )
        def paused_prompt(pins, text, deadline):
            with client.pause_prompt(pins, text, deadline):
                self.fail("mismatched prompt reached the relay exchange")

        for send in (client.prompt, paused_prompt):
            with patch("client.unix_wire") as open_socket:
                for change in changes:
                    with self.subTest(send=send.__name__, change=change):
                        mismatched = replace(valid, **change)
                        with self.assertRaisesRegex(ProbeError, "pinned job and session"):
                            send(mismatched, "fixture", deadline)
                open_socket.assert_not_called()

        with patch.object(client, "_exchange") as exchange:
            client.pause_prompt(valid, "fixture", deadline)
            exchange.assert_called_once()


if __name__ == "__main__":
    unittest.main()
