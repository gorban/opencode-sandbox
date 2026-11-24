"""Synthetic acceptance and security tests for the single-turn zero-tool ChatGPT canary."""

from array import array
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from oc_openai import canary, canary_protocol, canary_runtime
from oc_openai.canary_ledger import CANARY_FILE, I4A_HOLD_FILES, CanaryLedger, CanaryLedgerError
from oc_openai.canary_protocol import (
    EXPECTED_REPLY,
    PORT,
    PROMPT,
    CanaryUnsettledError,
    Refused,
    consume_upstream_stream,
    receive_client,
    verify_opencode_json_stdout,
)
from oc_openai.canary_runtime import OwnerLost, PipeLifeline, container_categories
from oc_openai.connection import Connection, ConnectionError
from oc_openai.exposure import binding_digest
from oc_openai.profile_backend import ProfileBackend
from oc_openai.responses import Cancellation, OpenAITransport, StreamFailure
from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier
from test_openai_live import Terminal


_MEASURED_INSTRUCTIONS_HEADER = (
    "Today's date: Mon Nov 23 2026\n"
    "Synthetic placeholder instructions."
)


def _forbid_host_browser(url):
    raise AssertionError(f"unit test attempted to open host browser: {url}")


def _enter_cm(cm):
    with cm:
        pass


def _http_post(path: str, token: str, payload: dict, *, port: int = PORT) -> bytes:
    raw = json.dumps(payload).encode("utf-8")
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Authorization: Bearer {token}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(raw)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + raw


def _http_get(path: str, token: str, *, port: int = PORT) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Authorization: Bearer {token}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def _send_via_uds(sock_path: Path, proof: bytes, request_bytes: bytes, *, port: int) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        actual_port = listener.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(("127.0.0.1", actual_port))
            accepted, _ = listener.accept()
            with accepted:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as uds:
                    uds.settimeout(5)
                    uds.connect(str(sock_path))
                    uds.sendall(proof)
                    rights = (socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [accepted.fileno()]))
                    uds.sendmsg([b"F"], [rights])
            client.sendall(request_bytes)
            chunks = []
            while True:
                data = client.recv(8192)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks)


def _valid_inbound_payload(model: str = "gpt-6.2-sol", instructions: str = _MEASURED_INSTRUCTIONS_HEADER) -> dict:
    return {
        "model": model,
        "stream": True,
        "store": False,
        "max_output_tokens": 64,
        "include": ["reasoning.encrypted_content"],
        "prompt_cache_key": "ses_" + "A" * 26,
        "instructions": instructions,
        "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": PROMPT}]}],
    }


def _ok_events(model: str = "gpt-6.2-sol", *, resp_id: str = "resp_ok_1", text: str = EXPECTED_REPLY, extra=()):
    return [
        {"type": "response.created", "response": {"id": resp_id, "model": model, "status": "in_progress"}},
        *extra,
        {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": text},
        {"type": "response.output_text.done", "output_index": 0, "content_index": 0, "text": text},
        {
            "type": "response.completed",
            "response": {
                "id": resp_id,
                "model": model,
                "status": "completed",
                "output": [{
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": text}],
                }],
                "usage": {"input_tokens": 11, "output_tokens": 2, "total_tokens": 13},
            },
        },
    ]


class CanaryLedgerTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.scratch = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="oc-canary-test-", dir=home)))
        self.state = self.scratch / "state"
        self.state.mkdir(mode=0o700)
        self.ledger = CanaryLedger(self.state)
        self.binding = binding_digest("a" * 43, "b" * 43, "c" * 43)

    def _seed_all_nine_i4a_files(self) -> dict[str, bytes]:
        samples = {}
        for name in I4A_HOLD_FILES:
            if name == "exposure.json":
                payload = [{"run": "1" * 32, "binding": "2" * 64, "phase": "orchestrator",
                            "max_input": 100, "max_output": 20, "actual": [10, 5]}]
            elif name in ("diagnostic.json", "diagnostic-stream.json"):
                payload = {"run": "3" * 32, "binding": "2" * 64, "phase": "orchestrator",
                           "max_input": 50, "max_output": 10, "actual": None}
            else:
                payload = {"phases": [{"phase": "initial", "max_input": 40, "max_output": 8, "actual": [4, 2]}]}
            raw = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
            path = self.state / name
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            samples[name] = raw
        return samples

    def test_all_nine_i4a_files_inspected_readonly_and_corrupt_or_unsafe_fails(self):
        before = self._seed_all_nine_i4a_files()
        snap = self.ledger.preflight()
        self.assertEqual(snap.present_files, I4A_HOLD_FILES)
        self.assertEqual(snap.record_count, 9)
        self.assertEqual(snap.unsettled_count, 2)
        for name, expected in before.items():
            self.assertEqual((self.state / name).read_bytes(), expected)

        # Unsafe mode fails visibly.
        target = self.state / I4A_HOLD_FILES[-1]
        os.chmod(target, 0o644)
        with self.assertRaisesRegex(CanaryLedgerError, "canary_storage_unavailable"):
            self.ledger.preflight()
        os.chmod(target, 0o600)

        # Corrupt JSON fails visibly.
        target.write_bytes(b"{broken")
        with self.assertRaisesRegex(CanaryLedgerError, "canary_history_corrupt"):
            self.ledger.preflight()

    def test_single_use_across_settled_unsettled_history_change_and_lock_contention(self):
        self._seed_all_nine_i4a_files()
        snap = self.ledger.preflight()

        # Mutating history between consent and reserve fails closed.
        (self.state / "diagnostic.json").write_bytes(
            b'{"run":"' + b"4" * 32 + b'","max_input":50,"max_output":10,"actual":null}\n'
        )
        os.chmod(self.state / "diagnostic.json", 0o600)
        with self.assertRaisesRegex(CanaryLedgerError, "canary_history_changed"):
            self.ledger.reserve("1" * 32, self.binding, "gpt-6.2-sol", snap.digest)
        self.assertFalse((self.state / CANARY_FILE).exists())

        # Fresh snapshot allows one reservation; unsettled hold blocks replay.
        snap2 = self.ledger.preflight()
        self.ledger.reserve("1" * 32, self.binding, "gpt-6.2-sol", snap2.digest)
        with self.assertRaisesRegex(CanaryLedgerError, "canary_unsettled_hold"):
            self.ledger.preflight()
        with self.assertRaisesRegex(CanaryLedgerError, "canary_unsettled_hold"):
            self.ledger.reserve("2" * 32, self.binding, "gpt-6.2-sol", snap2.digest)

        # Settling STILL permanently blocks replay (single-use across restarts & profile changes).
        outcome = self.ledger.settle("1" * 32, allow_delivery=True, input_tokens=10, output_tokens=1)
        self.assertEqual(outcome, "ok_settled")
        data = json.loads((self.state / CANARY_FILE).read_text())
        self.assertIs(data["delivered"], False)
        self.ledger.mark_delivered("1" * 32)
        self.assertIs(json.loads((self.state / CANARY_FILE).read_text())["delivered"], True)
        with self.assertRaisesRegex(CanaryLedgerError, "canary_already_spent"):
            self.ledger.preflight()
        with self.assertRaisesRegex(CanaryLedgerError, "canary_already_spent"):
            self.ledger.reserve("3" * 32, self.binding, "gpt-6.2-sol", snap2.digest)

        # Concurrent canary.lock contention fails immediately.
        with self.ledger.exclusive_run():
            other = CanaryLedger(self.state)
            cm = other.exclusive_run()
            with self.assertRaisesRegex(CanaryLedgerError, "canary_busy"):
                _enter_cm(cm)

    def test_single_use_survives_profile_recreation_and_switch(self):
        conns = {}

        def factory(directory):
            if directory not in conns:
                browser = FixtureBrowser()
                browser.client = f"oaiapp_{directory.name}"
                conns[directory] = Connection(
                    directory, transport=FixtureTransport(), verifier=FixtureVerifier(), browser=browser,
                )
            return conns[directory]

        backend = ProfileBackend(self.state, connection=factory, reviewed=True)
        backend.connect("first")
        snap = self.ledger.preflight()
        self.ledger.reserve("a" * 32, self.binding, "gpt-6.2-sol", snap.digest)
        self.ledger.settle("a" * 32, allow_delivery=True, input_tokens=5, output_tokens=1)

        # Switching or disconnecting/reconnecting a brand-new profile cannot mint a fresh slot.
        backend.connect("second")
        backend.disconnect()
        backend.connect("recreated")
        term = Terminal(True)
        rc = canary.run_canary(term, backend_factory=lambda: backend)
        self.assertEqual(rc, 1)
        self.assertTrue(any("canary_already_spent" in line for line in term.output))


class CanaryProtocolAndBrokerTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.scratch = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="oc-canary-proto-", dir=home)))
        self.state = self.scratch / "state"
        self.state.mkdir(mode=0o700)
        self.ledger = CanaryLedger(self.state)
        self.binding = binding_digest("a" * 43, "b" * 43, "c" * 43)
        norm = canary_protocol.SYSTEM_DATE.sub("Today's date: [date]", _MEASURED_INSTRUCTIONS_HEADER)
        self.patch_digest = patch.object(
            canary_protocol, "SYSTEM_DIGEST", hashlib.sha256(norm.encode("utf-8")).hexdigest(),
        )
        self.enterContext(self.patch_digest)

    def test_cli_grammar_and_direct_owner_spoofing_zero_sends(self):
        self.assertEqual(canary.parse_canary_argv([]), canary.CanaryArgs(None, False))
        self.assertEqual(canary.parse_canary_argv(["--synthetic-check"]), canary.CanaryArgs(None, True))
        self.assertEqual(
            canary.parse_canary_argv(["--model", "gpt-6.2-sol", "--synthetic-check"]),
            canary.CanaryArgs("gpt-6.2-sol", True),
        )
        for bad in (["-i", "foo"], ["-P", "8080"], ["--provider", "openai"], ["--model", "../bad"], ["--unknown"]):
            with self.assertRaises(ValueError):
                canary.parse_canary_argv(bad)

        # Direct _owner invocation with synthetic pipes has zero provider imports or sends.
        runtime_src = Path(canary_runtime.__file__).read_text(encoding="utf-8")
        for forbidden in ("oc_openai.connection", "oc_openai.responses", "oc_openai.canary_ledger", "api.openai.com"):
            self.assertNotIn(forbidden, runtime_src)
        proc = subprocess.run(
            [sys.executable, "-IB", str(Path(canary_runtime.__file__).resolve()), "_owner"],
            input=b'{"model":"../invalid","token":"short"}\n',
            capture_output=True, timeout=5,
        )
        self.assertEqual(proc.returncode, 2)

    def test_stream_settlement_decoupled_from_delivery_permission(self):
        # Neutral moderation metadata + explicitly empty reasoning item -> allow_delivery=True.
        neutral = (
            {"type": "response.metadata", "response_id": "resp_ok_1", "sequence_number": 1,
             "metadata": {"openai_chatgpt_moderation_metadata": {"prompt": {"outputs": [{"is_blocked": False}]}}}},
            {"type": "response.output_item.added", "output_index": 0,
             "item": {"id": "rs_1", "type": "reasoning", "status": "completed", "summary": []}},
        )
        ok_out = consume_upstream_stream(_ok_events(extra=neutral), bound_model="gpt-6.2-sol", check_alive=lambda: None)
        self.assertTrue(ok_out.allow_delivery)
        self.assertEqual((ok_out.input_tokens, ok_out.output_tokens), (11, 2))

        # Refused turns with verified completion settle usage (allow_delivery=False):
        # (a) tool item, (b) guardian/ambiguous metadata, (c) encrypted_content reasoning, (d) wrong text.
        refused_cases = (
            _ok_events(extra=({"type": "response.output_item.added", "output_index": 0,
                               "item": {"id": "fc_1", "type": "function_call", "name": "bash", "arguments": "{}"}},)),
            _ok_events(extra=({"type": "response.metadata", "response_id": "resp_ok_1", "sequence_number": 1,
                               "metadata": {"openai_verification_recommendation": [{"action": "review"}]}},)),
            _ok_events(extra=({"type": "response.output_item.added", "output_index": 0,
                               "item": {"id": "rs_1", "type": "reasoning", "encrypted_content": "cipher"}},)),
            _ok_events(text="okay"),
        )
        for evs in refused_cases:
            out = consume_upstream_stream(evs, bound_model="gpt-6.2-sol", check_alive=lambda: None)
            self.assertFalse(out.allow_delivery)
            self.assertEqual((out.input_tokens, out.output_tokens), (11, 2))

        # Truncated stream without completion raises CanaryUnsettledError.
        truncated = _ok_events()[:-1]
        with self.assertRaises(CanaryUnsettledError):
            consume_upstream_stream(truncated, bound_model="gpt-6.2-sol", check_alive=lambda: None)

    def test_broker_models_aux_first_second_turn_and_crash_boundaries(self):
        token = secrets.token_hex(32)
        proof = secrets.token_bytes(32)
        sock_path = self.scratch / "provider.sock"
        snap = self.ledger.preflight()
        upstream_bodies = []

        @contextmanager
        def fake_upstream(body, *, before_write, deadline, cancelled):
            before_write()
            upstream_bodies.append(body)
            yield _ok_events()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        broker = canary.CanaryBroker(
            sock_path, proof=proof, worker_token=token, bound_model="gpt-6.2-sol",
            ledger=self.ledger, run_id="1" * 32, binding_hash=self.binding,
            history_digest=snap.digest, upstream_stream=fake_upstream,
            fenced_client_write=lambda fn: fn(), check_alive=lambda: None, port=port,
        )
        broker.start()
        try:
            # GET /v1/models with wrong token refused; valid token returns only bound model (0 upstream calls).
            bad_m = _send_via_uds(sock_path, proof, _http_get("/v1/models", "wrong", port=port), port=port)
            self.assertTrue(bad_m.startswith(b"HTTP/1.1 403"))
            ok_m = _send_via_uds(sock_path, proof, _http_get("/v1/models", token, port=port), port=port)
            self.assertTrue(ok_m.startswith(b"HTTP/1.1 200"))
            self.assertIn(b"gpt-6.2-sol", ok_m)
            self.assertEqual(upstream_bodies, [])

            # Tool-free auxiliary request FIRST -> HTTP 403 and 0 upstream inference POSTs!
            aux = _valid_inbound_payload()
            aux["input"][0]["content"][0]["text"] = "Summarize this title"
            aux_resp = _send_via_uds(sock_path, proof, _http_post("/v1/responses", token, aux, port=port), port=port)
            self.assertTrue(aux_resp.startswith(b"HTTP/1.1 403"))
            self.assertEqual(upstream_bodies, [])

            # Outbound tools -> HTTP 403 and 0 upstream POSTs!
            with_tools = _valid_inbound_payload()
            with_tools["tools"] = [{"type": "function", "name": "bash", "parameters": {}}]
            t_resp = _send_via_uds(sock_path, proof, _http_post("/v1/responses", token, with_tools, port=port), port=port)
            self.assertTrue(t_resp.startswith(b"HTTP/1.1 403"))
            self.assertEqual(upstream_bodies, [])

            # Valid turn -> HTTP 200, 1 upstream POST, canonical 4-key body (no include / no max_output_tokens).
            ok_resp = _send_via_uds(
                sock_path, proof, _http_post("/v1/responses", token, _valid_inbound_payload(), port=port), port=port,
            )
            self.assertTrue(ok_resp.startswith(b"HTTP/1.1 200"))
            self.assertEqual(len(upstream_bodies), 1)
            self.assertEqual(set(upstream_bodies[0]), {"model", "input", "store", "stream"})
            self.assertEqual(broker.ledger_outcome, "ok_settled")

            # Second valid request AFTER valid turn -> HTTP 403 and STILL 1 total upstream POST!
            second = _send_via_uds(
                sock_path, proof, _http_post("/v1/responses", token, _valid_inbound_payload(), port=port), port=port,
            )
            self.assertTrue(second.startswith(b"HTTP/1.1 403"))
            self.assertEqual(len(upstream_bodies), 1)
        finally:
            broker.close()

    def test_post_reserve_pre_write_crash_spends_slot_with_zero_upstream_sends(self):
        token = secrets.token_hex(32)
        proof = secrets.token_bytes(32)
        sock_path = self.scratch / "crash.sock"
        snap = self.ledger.preflight()
        writes = []

        @contextmanager
        def upstream_after_reserve(body, *, before_write, deadline, cancelled):
            before_write()
            writes.append(body)
            yield _ok_events()

        def simulate_kill():
            raise OwnerLost("killed after reserve before write")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        broker = canary.CanaryBroker(
            sock_path, proof=proof, worker_token=token, bound_model="gpt-6.2-sol",
            ledger=self.ledger, run_id="2" * 32, binding_hash=self.binding,
            history_digest=snap.digest, upstream_stream=upstream_after_reserve,
            fenced_client_write=lambda fn: fn(), check_alive=lambda: None,
            port=port, after_reserve=simulate_kill,
        )
        broker.start()
        try:
            resp = _send_via_uds(
                sock_path, proof, _http_post("/v1/responses", token, _valid_inbound_payload(), port=port), port=port,
            )
            self.assertEqual(resp, b"")
            self.assertEqual(writes, [])
            record = json.loads((self.state / CANARY_FILE).read_text())
            self.assertEqual(record["outcome"], "unsettled")
            self.assertIsNone(record["actual"])
        finally:
            broker.close()

    def test_revocation_at_both_write_boundaries_and_synchronous_lifeline_poll(self):
        # Synchronous PipeLifeline.active() catches EOF even without starting watcher thread.
        r_fd, w_fd = os.pipe()
        try:
            life = PipeLifeline(r_fd)
            self.assertTrue(life.active())
            os.close(w_fd)
            w_fd = -1
            self.assertFalse(life.active())
        finally:
            os.close(r_fd)
            if w_fd >= 0:
                os.close(w_fd)

        # Boundary 1 & 2: profile disconnect before first upstream write & before final client write.
        class _CanaryTransport(FixtureTransport):
            @contextmanager
            def responses(self, body, bearer, cancellation, dispatch, **_kwargs):
                with super().responses(body, bearer, cancellation, dispatch) as events:
                    yield events

        conns = {}
        transports = {}

        def factory(directory):
            if directory not in conns:
                browser = FixtureBrowser()
                browser.client = f"oaiapp_{directory.name}"
                transport = _CanaryTransport()
                transports[directory] = transport
                conns[directory] = Connection(
                    directory, transport=transport, verifier=FixtureVerifier(), browser=browser,
                )
            return conns[directory]

        backend = ProfileBackend(self.state, connection=factory, reviewed=True)
        backend.connect("work")
        label, epoch, conn, binding = backend.active_connection()

        # Revoke before final client write -> canary_fenced_write refuses with 0 client writes.
        client_writes = []
        backend.disconnect()
        with self.assertRaises(canary.RouteUnavailable):
            backend.canary_fenced_write(label, epoch, conn, binding, lambda: client_writes.append(b"ok"))
        self.assertEqual(client_writes, [])

        # Reconnect and revoke before first upstream write -> canary_responses refuses with 0 sends.
        backend.connect("work")
        label2, epoch2, conn2, binding2 = backend.active_connection()
        backend.disconnect()
        upstream_cm = conn2.canary_responses(
            binding2, canary_protocol.canonical_upstream_body("gpt-6.2-sol"),
            authorization=lambda: backend.selected_fence(label2, epoch2),
            before_write=lambda: None,
        )
        with self.assertRaises((ConnectionError, canary.RouteUnavailable)):
            _enter_cm(upstream_cm)
        self.assertFalse((self.state / CANARY_FILE).exists())

        # Same-label reselection must be refused while an exposure hold exists, and when idle
        # rotates selection_epoch so both canary write fences fail closed.
        backend.connect("work")
        label3, epoch3, conn3, binding3 = backend.active_connection()
        (self.state / "exposure.json").write_bytes(
            b'[{"run":"' + b"9" * 32 + b'","binding":"' + b"8" * 64
            + b'","phase":"orchestrator","max_input":100,"max_output":20,"actual":null}]\n'
        )
        os.chmod(self.state / "exposure.json", 0o600)
        with self.assertRaises(canary.RouteUnavailable):
            backend.select("work")
        (self.state / "exposure.json").unlink()
        backend.select("work")
        with self.assertRaises(canary.RouteUnavailable):
            backend.canary_fenced_write(label3, epoch3, conn3, binding3, lambda: client_writes.append(b"x"))
        self.assertEqual(client_writes, [])
        stale_cm = conn3.canary_responses(
            binding3, canary_protocol.canonical_upstream_body("gpt-6.2-sol"),
            authorization=lambda: backend.selected_fence(label3, epoch3),
            before_write=lambda: None,
        )
        with self.assertRaises(canary.RouteUnavailable):
            _enter_cm(stale_cm)

        # Interactive --provider openai entry point is explicitly unavailable on the canary branch.
        checkout = Path(__file__).resolve().parents[1]
        res = subprocess.run(
            ["bash", str(checkout / "oc-sandbox"), "--provider", "openai"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("not yet qualified", res.stderr)

    def test_broker_refused_turn_settles_usage_and_delivers_zero_bytes(self):
        token = secrets.token_hex(32)
        proof = secrets.token_bytes(32)
        sock_path = self.scratch / "refused.sock"
        snap = self.ledger.preflight()

        @contextmanager
        def tool_upstream(body, *, before_write, deadline, cancelled):
            before_write()
            yield _ok_events(extra=({
                "type": "response.output_item.added", "output_index": 0,
                "item": {"id": "fc_1", "type": "function_call", "name": "bash", "arguments": "{}"},
            },))

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        broker = canary.CanaryBroker(
            sock_path, proof=proof, worker_token=token, bound_model="gpt-6.2-sol",
            ledger=self.ledger, run_id="3" * 32, binding_hash=self.binding,
            history_digest=snap.digest, upstream_stream=tool_upstream,
            fenced_client_write=lambda fn: fn(), check_alive=lambda: None, port=port,
        )
        broker.start()
        try:
            resp = _send_via_uds(
                sock_path, proof, _http_post("/v1/responses", token, _valid_inbound_payload(), port=port), port=port,
            )
            self.assertEqual(resp, b"")
            self.assertEqual(broker.delivered_bytes, 0)
            self.assertEqual(broker.ledger_outcome, "refused_settled")
            rec = json.loads((self.state / CANARY_FILE).read_text())
            self.assertEqual(rec["outcome"], "refused_settled")
            self.assertEqual(rec["actual"], [11, 2])
            self.assertIs(rec["delivered"], False)
        finally:
            broker.close()


class CanaryRealPodmanTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("OC_OPENAI_CANARY_REAL") == "1", "requires qualified devbox Podman")
    def test_real_podman_synthetic_check_and_sigkill_owner_cleanup(self):
        term = Terminal(True)
        self.assertEqual(canary.run_synthetic_check(term), 0, term.output)
        self.assertTrue(any("exact 'ok'" in line for line in term.output), term.output)

        # SIGKILL Stage 1: killing a foreground launcher drops the pipe; detached _owner cleans containers & scratch.
        script = (
            "import os, secrets, signal, socket, sys\n"
            "from oc_openai.canary_runtime import DetachedOwnerSession\n"
            "owner = DetachedOwnerSession('gpt-6.2-sol', secrets.token_hex(32))\n"
            "root, _ = owner.prepare()\n"
            "srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "srv.bind(str(root / 'relay' / 'provider.sock'))\n"
            "os.chmod(root / 'relay' / 'provider.sock', 0o600)\n"
            "srv.listen(1)\n"
            "owner.start_containers()\n"
            "print(str(root), flush=True)\n"
            "os.kill(os.getpid(), signal.SIGKILL)\n"
        )
        proc = subprocess.run(
            [sys.executable, "-B", "-c", script],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, -signal.SIGKILL)
        root_path = Path(proc.stdout.strip())
        deadline = time.monotonic() + 15
        while root_path.exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(root_path.exists())
        leftover = canary_runtime.podman(
            "ps", "--all", "--filter", f"label={canary_runtime.LABEL}", "--quiet", check=False,
        ).stdout.strip()
        self.assertEqual(leftover, b"")


class CanaryTransportAndPlacementTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))

    def test_real_transport_terminal_framing_qualification(self):
        """Qualify Content-Length and chunked completions without [DONE], plus truncated failure."""
        completed_evt = _ok_events()[-1]
        created_evt = _ok_events()[0]
        sse_no_done = (
            f"data: {json.dumps(created_evt)}\n\n"
            f"data: {json.dumps(completed_evt)}\n\n"
        ).encode("ascii")
        chunk_hex = f"{len(sse_no_done):x}\r\n".encode("ascii")
        cases = (
            ("content_length_no_done",
             b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
             + f"Content-Length: {len(sse_no_done)}\r\n\r\n".encode("ascii") + sse_no_done,
             True),
            ("chunked_no_done",
             b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
             + chunk_hex + sse_no_done + b"\r\n0\r\n\r\n",
             True),
            ("truncated_chunked",
             b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
             + chunk_hex + sse_no_done + b"\r\n0\r\n",
             False),
        )
        for name, wire, should_settle in cases:
            with self.subTest(name=name):
                local, peer = socket.socketpair()
                local.settimeout(2)
                peer.settimeout(2)

                def serve(p=peer, w=wire):
                    with p, p.makefile("rb") as incoming:
                        incoming.readline()
                        cl = 0
                        while (ln := incoming.readline()) not in (b"", b"\r\n"):
                            if ln.lower().startswith(b"content-length:"):
                                cl = int(ln.split(b":", 1)[1].strip())
                        incoming.read(cl)
                        p.sendall(w)

                t = threading.Thread(target=serve, daemon=True)
                t.start()
                try:
                    with patch("oc_openai.responses._connect", lambda _h, c: (c.attach(local), local)[1]):
                        cm = OpenAITransport().responses(
                            canary_protocol.canonical_upstream_body("gpt-6.2-sol"),
                            "synthetic-access", Cancellation(time.monotonic() + 2), lambda w: w(),
                            limits=canary.CANARY_STREAM_LIMITS,
                        )
                        if should_settle:
                            with cm as events:
                                out = consume_upstream_stream(
                                    events, bound_model="gpt-6.2-sol", check_alive=lambda: None,
                                )
                            self.assertTrue(out.allow_delivery)
                            self.assertEqual((out.input_tokens, out.output_tokens), (11, 2))
                        else:
                            def _run_truncated():
                                with cm as events:
                                    consume_upstream_stream(
                                        events, bound_model="gpt-6.2-sol", check_alive=lambda: None,
                                    )

                            with self.assertRaises(StreamFailure):
                                _run_truncated()
                finally:
                    local.close()
                    t.join(2)

    def test_mcs_categories_stdout_verifier_and_scm_rights_rejections(self):
        # MCS category pair comparison matches container_t vs container_file_t.
        cats = container_categories({
            "ProcessLabel": "system_u:system_r:container_t:s0:c10,c20",
            "MountLabel": "system_u:object_r:container_file_t:s0:c20,c10",
        })
        self.assertEqual(cats, frozenset({"c10", "c20"}))
        with self.assertRaises(canary_runtime.RuntimeFailure):
            container_categories({
                "ProcessLabel": "system_u:system_r:container_t:s0:c10,c20",
                "MountLabel": "system_u:object_r:container_file_t:s0:c10,c99",
            })

        # OpenCode stdout verifier accepts only exact single 'ok' with stop finish and zero errors/tools.
        good = (
            b'{"type":"step_start"}\n'
            b'{"type":"text","part":{"type":"text","text":"ok"}}\n'
            b'{"type":"step_finish","part":{"reason":"stop"}}\n'
        )
        self.assertTrue(verify_opencode_json_stdout(good))
        self.assertFalse(verify_opencode_json_stdout(good + b'{"type":"text","part":{"type":"text","text":"ok"}}\n'))
        self.assertFalse(verify_opencode_json_stdout(good + b'{"type":"tool_use"}\n'))

        # SCM_RIGHTS rejects non-AF_INET FDs cleanly.
        c1, c2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        u1, u2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            c2.sendmsg([b"F"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [u1.fileno()]))])
            with self.assertRaises(Refused):
                receive_client(c1, port=PORT)
        finally:
            for s in (c1, c2, u1, u2):
                s.close()


if __name__ == "__main__":
    unittest.main()
