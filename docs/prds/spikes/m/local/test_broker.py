"""Exercise the host broker with local synthetic requests only."""

import contextlib
import http.client
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import broker as broker_module
from broker import (COMPLETE_TEXT, EARLY_TEXT, HOLD_TEXT, MAX_BODY, MODEL_ID, MODEL_PATH,
                    PROOF_CONTENT, PROOF_PATH, WRITE_CALL_ID, Broker)


TOKEN = "synthetic-fixture-bearer"


def _payload(*, path_field=None, tool_result=False):
    messages = [{"role": "user", "content": "Synthetic fixture turn"}]
    body = {"model": MODEL_ID, "stream": True, "messages": messages}
    if path_field:
        body["tools"] = [{
            "type": "function",
            "function": {
                "name": "write",
                "description": "Fixture native tool schema",
                "parameters": {
                    "type": "object",
                    "properties": {path_field: {"type": "string"}, "content": {"type": "string"}},
                    "required": [path_field, "content"],
                },
            },
        }]
    if tool_result:
        messages.append({"role": "tool", "tool_call_id": WRITE_CALL_ID, "content": "Synthetic write result"})
    return json.dumps(body).encode("ascii")


def _headers(body, *, path=MODEL_PATH, token=TOKEN, extra=b""):
    return (f"POST {path} HTTP/1.1\r\nHost: fixture.local\r\nAuthorization: Bearer {token}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
            "Accept: text/event-stream\r\n").encode("ascii") + extra + b"\r\n"


def _frames(data):
    return [line.removeprefix(b"data: ") for line in data.splitlines() if line.startswith(b"data: ")]


class BrokerTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="fixture-broker-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "model.sock"
        self.broker = Broker(self.path, TOKEN)
        self.addCleanup(self.broker.close)
        self.broker.start()

    @contextlib.contextmanager
    def _connect(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(2)
            conn.connect(str(self.path))
            yield conn

    def _exchange(self, body, **options):
        with self._connect() as conn:
            conn.sendall(_headers(body, **options) + body)
            with http.client.HTTPResponse(conn) as response:
                response.begin()
                result = response.status, response.read()
            self.assertEqual(conn.recv(1), b"")
            return result

    def test_streams_text_before_native_write_then_completes(self):
        extra = (b"b3: fixture\r\ntraceparent: fixture\r\nx-opencode-client: fixture\r\n"
                 b"x-opencode-project: fixture\r\nx-opencode-session: fixture\r\n"
                 b"x-opencode-session-id: fixture\r\nx-session-affinity: fixture\r\nx-session-id: fixture\r\n")
        status, data = self._exchange(_payload(path_field="path"), extra=extra)
        self.assertEqual(status, 200)
        early, write, finish, done = _frames(data)
        self.assertIn(EARLY_TEXT, json.loads(early)["choices"][0]["delta"]["content"])
        call, = json.loads(write)["choices"][0]["delta"]["tool_calls"]
        self.assertEqual(call["id"], WRITE_CALL_ID)
        self.assertEqual(call["function"]["name"], "write")
        self.assertEqual(json.loads(call["function"]["arguments"]), {"path": PROOF_PATH, "content": PROOF_CONTENT})
        self.assertEqual(json.loads(finish)["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(done, b"[DONE]")

        self.assertEqual(self._exchange(_payload())[0], 422)
        status, data = self._exchange(_payload(tool_result=True))
        self.assertEqual(status, 200)
        complete, finish, done = _frames(data)
        self.assertEqual(json.loads(complete)["choices"][0]["delta"]["content"], COMPLETE_TEXT)
        self.assertEqual(json.loads(finish)["choices"][0]["finish_reason"], "stop")
        self.assertEqual(done, b"[DONE]")
        self.assertEqual(self.broker.snapshot(), {"admitted": 2, "active": 0, "rejected": 1})

    def test_write_requires_the_advertised_native_tool(self):
        self.assertEqual(self._exchange(_payload()), (422, b""))
        self.assertEqual(self._exchange(_payload(path_field="otherPath")), (422, b""))
        self.assertEqual(self.broker.snapshot(), {"admitted": 0, "active": 0, "rejected": 2})

    def test_revoke_closes_registered_stream_and_denies_stale_bearer(self):
        body = _payload()
        self.broker.arm_hold()
        with self._connect() as active, self._connect() as pending:
            pending.sendall(_headers(body) + body[:-1])
            active.sendall(_headers(body) + body)
            with http.client.HTTPResponse(active) as response:
                response.begin()
                self.assertEqual(response.status, 200)
                self.assertTrue(response.chunked)
                self.assertTrue(self.broker.wait_for_hold(2))
                frame = json.loads(response.readline().removeprefix(b"data: "))
                self.assertEqual(frame["choices"][0]["delta"]["content"], HOLD_TEXT)
                self.assertEqual(response.readline(), b"\n")
                before = self.broker.snapshot()
                self.assertEqual(before, {"admitted": 1, "active": 1, "rejected": 0})

                self.broker.revoke()
                self.assertTrue(self.broker.wait_for_hold_revoked(0))
                self.assertEqual(self.broker.snapshot()["active"], 0)
                with self.assertRaises(http.client.IncompleteRead) as closed:
                    response.read()
                self.assertEqual(closed.exception.partial, b"")

            pending.sendall(body[-1:])
            with http.client.HTTPResponse(pending) as response:
                response.begin()
                self.assertEqual(response.status, 403)
                self.assertEqual(response.read(), b"")

        self.assertEqual(self._exchange(body), (403, b""))
        self.assertEqual(self.broker.snapshot(), {"admitted": 1, "active": 0, "rejected": 2})
        with self.assertRaises(RuntimeError):
            self.broker.start()
        with self.assertRaises(RuntimeError):
            self.broker.arm_hold()

    def test_rejects_unrecognised_route_framing_and_json(self):
        body = _payload(path_field="filePath")
        for options, status in [
            ({"path": "/v1/models"}, 404),
            ({"path": MODEL_PATH + "?fixture=true"}, 404),
            ({"token": "different-synthetic-bearer"}, 403),
            ({"extra": b"Transfer-Encoding: chunked\r\n"}, 400),
            ({"extra": b"Content-Encoding: gzip\r\n"}, 400),
            ({"extra": b"Content-Length: 10\r\n"}, 400),
            ({"extra": b"Expect: 100-continue\r\n"}, 400),
        ]:
            with self.subTest(options=options):
                self.assertEqual(self._exchange(body, **options), (status, b""))
        for invalid in (
            body.replace(b'"stream": true', b'"stream": false'),
            body.replace(b'"stream": true', b'"stream": true, "stream": true'),
            body.replace(b'"stream": true', b'"stream": true, "temperature": 1e999'),
            body.replace(b'"fixture-model"', b'"other-model"'),
            body + b'{}',
        ):
            self.assertEqual(self._exchange(invalid), (400, b""))
        with self._connect() as conn:
            conn.sendall(_headers(body).replace(f"Content-Length: {len(body)}".encode("ascii"),
                                               f"Content-Length: {MAX_BODY + 1}".encode("ascii")))
            with http.client.HTTPResponse(conn) as response:
                response.begin()
                self.assertEqual(response.status, 400)
        self.assertEqual(self.broker.snapshot()["admitted"], 0)

    def test_ignores_bytes_after_the_single_declared_http_request(self):
        body = _payload(path_field="path")
        request = _headers(body) + body
        next_body = _payload(tool_result=True)
        following = _headers(next_body) + next_body
        with self._connect() as conn:
            conn.sendall(request + following)
            with http.client.HTTPResponse(conn) as response:
                response.begin()
                self.assertEqual(response.status, 200)
                self.assertEqual(_frames(response.read())[-1], b"[DONE]")
                self.assertEqual(conn.recv(1), b"")
        self.assertEqual(self.broker.snapshot(), {"admitted": 1, "active": 0, "rejected": 0})

    def test_listener_start_failure_releases_socket_and_allows_fresh_start(self):
        path = self.path.with_name("retry.sock")
        broker = Broker(path, TOKEN)
        self.addCleanup(broker.close)
        with patch.object(threading.Thread, "start", side_effect=RuntimeError("synthetic thread failure")):
            with self.assertRaisesRegex(RuntimeError, "synthetic thread failure"):
                broker.start()
        self.assertFalse(path.exists())
        broker.start()
        self.assertTrue(path.is_socket())

    def test_client_thread_start_failure_releases_its_only_slot(self):
        with patch.object(broker_module, "MAX_CLIENTS", 1):
            with patch.object(threading.Thread, "start", side_effect=RuntimeError("synthetic thread failure")):
                with self._connect() as conn:
                    self.assertEqual(conn.recv(1), b"")
            self.assertEqual(self.broker.snapshot(), {"admitted": 0, "active": 0, "rejected": 1})
            self.assertEqual(self._exchange(_payload(path_field="path"))[0], 200)

    def test_cleanup_unlinks_the_socket_even_if_join_fails(self):
        with patch.object(self.broker._listener_thread, "join", side_effect=RuntimeError("synthetic join failure")):
            with self.assertRaisesRegex(RuntimeError, "synthetic join failure"):
                self.broker.close()
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
