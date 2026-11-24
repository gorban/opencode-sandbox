"""Portable checks for the isolated orchestrator entry and its recording fake."""

import json
from pathlib import Path
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Event
import unittest

from oc_orchestrator.protocol import MODEL, PORT, PROMPT, RecordingFake


ROOT = Path(__file__).resolve().parents[1]
PROOF = b"p" * 32


def payload(**changes):
    return {"model": MODEL, "stream": True, "messages": [{"role": "user", "content": PROMPT}], **changes}


def connect(address, body, proof=PROOF):
    message = json.dumps(body).encode()
    headers = f"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nContent-Type: application/json\r\nContent-Length: {len(message)}\r\n\r\n".encode()
    client = socket.socket(socket.AF_UNIX)
    client.settimeout(3)
    try:
        client.connect(str(address))
        client.sendall(proof + headers + message)
    except BaseException:
        client.close()
        raise
    return client


def response(client):
    data = bytearray()
    while len(data) < 65536:
        try:
            block = client.recv(4096)
        except ConnectionResetError:
            break
        if not block:
            break
        data.extend(block)
    return bytes(data)


class OrchestratorTest(unittest.TestCase):
    def test_launcher_has_a_side_effect_free_help_and_refuses_normal_options(self):
        with TemporaryDirectory() as home:
            for flags, exit_code in ((["--help"], 0), ([], 2), (["--synthetic-check", "-d"], 2),
                                     (["--synthetic-check", "-P", "8401"], 2)):
                result = subprocess.run(["bash", str(ROOT / "oc-sandbox"), "orchestrate", *flags],
                                        env={"PATH": "/usr/bin:/bin", "HOME": home}, text=True,
                                        capture_output=True, timeout=6, check=False)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                self.assertEqual(list(Path(home).iterdir()), [])
                if flags == ["--help"]:
                    self.assertIn("--synthetic-check", result.stdout)
                if not flags:
                    self.assertIn("live_route_unqualified", result.stderr)

    def test_exact_transcript_once_and_no_tools(self):
        with TemporaryDirectory() as root:
            address = Path(root) / "proof.sock"
            with RecordingFake(address, PROOF) as broker:
                for body, proof in ((payload(tools=[{"type": "function"}]), PROOF),
                                    (payload(web_search_options={}), PROOF),
                                    (payload(model="foreign"), PROOF)):
                    with connect(address, body, proof) as client:
                        self.assertIn(b"403 Forbidden", response(client))
                with connect(address, payload(), b"q" * 32) as client:
                    self.assertNotIn(b"200 OK", response(client))
                self.assertEqual(broker.admissions, 0)
                with connect(address, payload()) as client:
                    self.assertIn(b'"content": "ok"', response(client))
                with connect(address, payload()) as client:
                    self.assertIn(b"403 Forbidden", response(client))
                self.assertEqual(broker.admissions, 1)

    def test_provider_tool_event_is_withheld_after_one_send(self):
        with TemporaryDirectory() as root:
            address = Path(root) / "proof.sock"
            with RecordingFake(address, PROOF, events=(b'{"tool":"write"}',)) as broker:
                with connect(address, payload()) as client:
                    data = response(client)
                self.assertIn(b"403 Forbidden", data)
                self.assertNotIn(b"write", data)
                self.assertEqual(broker.admissions, 1)

    def test_revocation_before_delivery_closes_stream_and_keeps_send_count(self):
        recorded = Event()
        release = Event()

        def hold():
            recorded.set()
            release.wait(3)

        with TemporaryDirectory() as root:
            address = Path(root) / "proof.sock"
            with RecordingFake(address, PROOF, after_send=hold) as broker:
                with connect(address, payload()) as client:
                    try:
                        self.assertTrue(recorded.wait(2))
                        broker.revoke()
                        self.assertEqual(response(client), b"")
                        self.assertEqual(broker.admissions, 1)
                        self.assertEqual(broker.settlement, "recorded_offline")
                    finally:
                        release.set()


if __name__ == "__main__":
    unittest.main()
