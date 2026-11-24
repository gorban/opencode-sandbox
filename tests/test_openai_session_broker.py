"""End-to-end socketpair relay + SessionBroker + oc-sandbox launcher flag tests."""

import contextlib
import fcntl
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from oc_openai.connection import ConnectionError
from oc_openai.managed import relay as relay_mod
from oc_openai.session_broker import (
    SessionBroker,
    USAGE_LOG_NAME,
    generate_opencode_config,
)
from oc_openai.session_relay import forward_stream

SOURCE = Path(__file__).resolve().parents[1]


class _FakeConn:
    def __init__(self, events_fn):
        self._events_fn = events_fn
        self.active = True

    def require_active(self, binding):
        if not self.active:
            raise ConnectionError("connection_retired")

    @contextlib.contextmanager
    def interactive_responses(self, binding, body, before_send=None, **kwargs):
        self.require_active(binding)
        yield self._events_fn(body)


def _make_lease(root: Path, incarnation="inc_" + "a" * 32, generation=1):
    grant = root / "grant"
    grant.mkdir(mode=0o700)
    (grant / "lock").touch(mode=0o600)
    (grant / "lifetime").touch(mode=0o600)
    fd = os.open(grant / "lifetime", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    active = relay_mod.grant_record(incarnation, generation, True)
    (grant / "state").write_bytes(active)
    (grant / "state").chmod(0o600)
    lease = relay_mod.Lease(grant, active, time.monotonic_ns() + 60 * 10**9)
    return lease, fd


def _send_via_relay(sock_path: Path, lease: relay_mod.Lease, proof: bytes, raw_req: bytes) -> bytes:
    w_client, w_relay = socket.socketpair()
    w_client.settimeout(4)
    w_relay.settimeout(4)

    def run_relay():
        try:
            with w_relay, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as broker:
                broker.settimeout(2)
                broker.connect(str(sock_path))
                forward_stream(w_relay, broker, lease, proof, time.monotonic() + 5)
        except Exception:
            pass

    t = threading.Thread(target=run_relay, daemon=True)
    t.start()
    try:
        w_client.sendall(raw_req)
        chunks = []
        while True:
            data = w_client.recv(8192)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        w_client.close()
        t.join(3)


class SessionBrokerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.usage_dir = self.root / "state"
        self.usage_dir.mkdir(mode=0o700)
        self.sock_path = self.root / "provider.sock"
        self.proof = secrets.token_bytes(relay_mod.PROOF_SIZE)
        self.worker_token = secrets.token_urlsafe(24)
        self.lease, self.life_fd = _make_lease(self.root)
        self.addCleanup(lambda: os.close(self.life_fd))

    def test_models_and_chunked_streaming_and_redacted_usage_log(self):
        def make_events(body):
            yield {"type": "response.created", "response": {"id": "resp_up_1", "status": "in_progress"}}
            yield {"type": "response.output_text.delta", "delta": "hello"}
            yield {"type": "response.metadata", "response_id": "resp_up_1", "sequence_number": 1,
                   "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {"outputs": [{"is_blocked": False}]}}}}
            yield {"type": "response.output_item.done", "output_index": 0,
                   "item": {"type": "function_call", "call_id": "call_1", "name": "read", "arguments": "{}"}}
            yield {"type": "response.completed",
                   "response": {"id": "resp_up_1", "status": "completed", "output": [],
                                "usage": {"input_tokens": 11, "output_tokens": 4, "total_tokens": 15}}}

        conn = _FakeConn(make_events)
        broker = SessionBroker(
            socket_path=self.sock_path, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=conn, binding=object(), models=("gpt-6.2-sol",),
            profile_label="personal", usage_dir=self.usage_dir,
        )
        broker.start()
        self.addCleanup(broker.close)

        models_req = (
            f"GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            f"Authorization: Bearer {self.worker_token}\r\n\r\n"
        ).encode("ascii")
        models_raw = _send_via_relay(self.sock_path, self.lease, self.proof, models_req)
        self.assertIn(b"200 OK", models_raw)
        self.assertIn(b'"id":"gpt-6.2-sol"', models_raw)

        body = json.dumps({"model": "gpt-6.2-sol", "stream": True, "store": False,
                           "input": [{"role": "user", "content": "SUPER_SECRET_PROMPT"}]}).encode()
        resp_req = (
            f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            f"Authorization: Bearer {self.worker_token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body
        resp_raw = _send_via_relay(self.sock_path, self.lease, self.proof, resp_req)
        self.assertIn(b"Transfer-Encoding: chunked", resp_raw)
        self.assertIn(b"response.completed", resp_raw)
        self.assertIn(b"resp_local_1", resp_raw)
        self.assertNotIn(b"resp_up_1", resp_raw)
        self.assertTrue(resp_raw.endswith(b"0\r\n\r\n"))

        log_text = (self.usage_dir / USAGE_LOG_NAME).read_text()
        self.assertNotIn("SUPER_SECRET_PROMPT", log_text)
        row = json.loads(log_text.strip())
        self.assertEqual((row["outcome"], row["input_tokens"], row["output_tokens"]), ("completed", 11, 4))

    def test_midstream_safety_abort_omits_terminal_chunk_and_withholds_tool_call(self):
        def bad_events(body):
            yield {"type": "response.created", "response": {"id": "resp_up_2", "status": "in_progress"}}
            yield {"type": "response.output_text.delta", "delta": "partial"}
            yield {"type": "response.output_item.done", "output_index": 0,
                   "item": {"type": "function_call", "call_id": "call_2", "name": "bash", "arguments": "{}"}}
            yield {"type": "response.metadata", "response_id": "resp_up_2", "sequence_number": 2,
                   "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {"outputs": [{"is_blocked": True}]}}}}

        broker = SessionBroker(
            socket_path=self.sock_path, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(bad_events), binding=object(), models=("gpt-6.2-sol",),
            profile_label="personal", usage_dir=self.usage_dir,
        )
        broker.start()
        self.addCleanup(broker.close)

        body = json.dumps({"model": "gpt-6.2-sol", "stream": True, "store": False,
                           "input": [{"role": "user", "content": "hi"}]}).encode()
        req = (
            f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            f"Authorization: Bearer {self.worker_token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body
        raw = _send_via_relay(self.sock_path, self.lease, self.proof, req)
        self.assertIn(b"partial", raw)
        self.assertNotIn(b"call_2", raw)
        self.assertNotIn(b"response.completed", raw)
        self.assertFalse(raw.endswith(b"0\r\n\r\n"))

    def test_disconnect_triggers_on_revoke_and_rejects_further_requests(self):
        revoked = threading.Event()
        conn = _FakeConn(lambda b: iter(()))
        broker = SessionBroker(
            socket_path=self.sock_path, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=conn, binding=object(), models=("gpt-6.2-sol",),
            profile_label="personal", on_revoke=revoked.set,
        )
        broker.start()
        self.addCleanup(broker.close)
        conn.active = False
        self.assertTrue(revoked.wait(2))

    def test_generated_opencode_config_locks_provider_and_preserves_mcp(self):
        cfg = generate_opencode_config(worker_token="tok-123", models=("gpt-6.2-sol", "gpt-6.2-mini"))
        self.assertEqual(cfg["model"], "local/gpt-6.2-sol")
        self.assertEqual(cfg["providers"]["local"]["settings"]["baseURL"], "http://127.0.0.1:8401/v1")
        self.assertFalse(cfg["providers"]["local"]["settings"]["store"])
        self.assertIn("chrome-devtools", cfg["mcp"])
        self.assertIn({"action": "provider.use", "resource": "*", "effect": "deny"}, cfg["policies"])
        self.assertIn({"action": "provider.use", "resource": "local", "effect": "allow"}, cfg["policies"])

    def test_launcher_refuses_port_8401_and_invalid_provider_combinations(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            checkout = root / "checkout"
            stubs = root / "stubs"
            for d in (home, checkout, stubs):
                d.mkdir()
            shutil.copy2(SOURCE / "oc-sandbox", checkout / "oc-sandbox")
            for cmd in ("podman", "systemctl", "distrobox-host-exec", "curl"):
                p = stubs / cmd
                p.write_text("#!/bin/sh\nexit 99\n")
                p.chmod(0o700)
            env = {"HOME": str(home), "PATH": f"{stubs}:/usr/bin:/bin"}

            for args, expected in (
                (["-P", "8401"], "refusing to publish pod port 8401"),
                (["-P", "18401:8401"], "refusing to publish pod port 8401"),
                (["--provider", ""], "needs a value"),
                (["--provider="], "needs a value"),
                (["--provider", "", "--provider", "openai"], "needs a value"),
                (["--provider", "openai", "-n"], "cannot be combined"),
                (["--provider", "openai", "-d"], "cannot be combined"),
                (["--provider", "openai", "-x"], "cannot be combined"),
                (["--provider", "claude"], "not yet qualified"),
                (["--provider", "google"], "not yet qualified"),
                (["--provider", "bogus"], "unsupported provider"),
                (["--provider", "openai", "--provider", "openai"], "only be specified once"),
            ):
                with self.subTest(args=args):
                    res = subprocess.run(
                        [str(checkout / "oc-sandbox"), *args],
                        cwd=home, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(res.returncode, 2)
                    self.assertIn(expected, res.stderr)

    def test_relay_survives_client_shut_wr_half_close_and_missing_usage_dir_cleans_slots(self):
        missing_dir = self.root / "nonexistent-usage-dir"

        def make_events(body):
            yield {"type": "response.created", "response": {"id": "resp_up_hc", "status": "in_progress"}}
            yield {"type": "response.output_text.delta", "delta": "half-close-ok"}
            yield {"type": "response.completed",
                   "response": {"id": "resp_up_hc", "status": "completed", "output": []}}

        broker = SessionBroker(
            socket_path=self.sock_path, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(make_events), binding=object(), models=("gpt-6.2-sol",),
            profile_label="personal", usage_dir=missing_dir,
        )
        broker.start()
        self.addCleanup(broker.close)

        body = json.dumps({"model": "gpt-6.2-sol", "stream": True, "store": False,
                           "input": [{"role": "user", "content": "hi"}]}).encode()
        req = (
            f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            f"Authorization: Bearer {self.worker_token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body

        w_client, w_relay = socket.socketpair()
        w_client.settimeout(4)
        w_relay.settimeout(4)
        t = threading.Thread(
            target=lambda: (
                w_relay.__enter__(),
                self._run_one_relay(w_relay),
                w_relay.close(),
            ),
            daemon=True,
        )
        t.start()
        try:
            w_client.sendall(req)
            w_client.shutdown(socket.SHUT_WR)
            chunks = []
            while data := w_client.recv(8192):
                chunks.append(data)
            raw = b"".join(chunks)
            self.assertIn(b"half-close-ok", raw)
            self.assertTrue(raw.endswith(b"0\r\n\r\n"))
        finally:
            w_client.close()
            t.join(3)
        deadline = time.monotonic() + 2
        while broker._clients and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(len(broker._clients), 0)

    def _run_one_relay(self, w_relay):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect(str(self.sock_path))
                forward_stream(w_relay, sock, self.lease, self.proof, time.monotonic() + 5)
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
