"""Tests for concurrent worker_leases, migration, retirement, and StreamLimits."""

import contextlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import secrets
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from oc_openai.connection import Connection, ConnectionError
from oc_openai.connection_job import PhysicalHost, WorkerLease
from oc_openai.connection_state import MAX_WORKER_LEASES
from oc_openai.managed import relay as relay_mod
from oc_openai.responses import (
    Cancellation,
    OpenAITransport,
    StreamLimits,
)
from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier


class _FakeJob:
    def __init__(self, root: Path, incarnation: str, generation: int = 1):
        self.root = root
        self.incarnation = incarnation
        self.generation = generation
        self.grant = root / "grant"
        self.grant.mkdir(mode=0o700)
        (self.grant / "lock").touch(mode=0o600)
        (self.grant / "lifetime").touch(mode=0o600)
        self._fd = os.open(self.grant / "lifetime", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (self.grant / "state").write_bytes(relay_mod.grant_record(incarnation, generation, True))
        (self.grant / "state").chmod(0o600)

    def revoke(self):
        (self.grant / "state").write_bytes(relay_mod.grant_record(self.incarnation, self.generation, False))
        (self.grant / "state").chmod(0o600)
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


class SessionLeaseTests(unittest.TestCase):
    def setUp(self):
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        self.host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        self.transport = FixtureTransport()
        self.connection = Connection(
            self.scratch / "profile",
            transport=self.transport,
            browser=FixtureBrowser(),
            verifier=FixtureVerifier(),
            host_probe=lambda: self.host,
        )
        self.binding = self.connection.connect()

    def _make_job(self, prefix="oc-chat-"):
        root = Path(tempfile.mkdtemp(prefix=prefix, dir="/tmp"))
        self.addCleanup(lambda: root.exists() and __import__("shutil").rmtree(root, ignore_errors=True))
        job = _FakeJob(root, "inc_" + secrets.token_hex(16))
        self.addCleanup(job.revoke)
        return job

    def test_concurrent_session_leases_refuse_switch_and_retire_together_on_disconnect(self):
        job_a = self._make_job()
        job_b = self._make_job()
        with self.connection.session_lease(self.binding, job_a), self.connection.session_lease(self.binding, job_b):
            with self.assertRaises(ConnectionError) as err:
                self.connection.require_switchable()
            self.assertEqual(err.exception.code, "managed_retirement_incomplete")

            with self.assertRaises(ConnectionError) as mix:
                with self.connection.worker_lease(self.binding, self._make_job("oc-i4a-")):
                    pass
            self.assertEqual(mix.exception.code, "managed_retirement_incomplete")

            self.assertTrue(self.connection.disconnect())
            self.assertEqual(
                (job_a.grant / "state").read_bytes(),
                relay_mod.grant_record(job_a.incarnation, job_a.generation, False),
            )
            self.assertEqual(
                (job_b.grant / "state").read_bytes(),
                relay_mod.grant_record(job_b.incarnation, job_b.generation, False),
            )

    def test_session_lease_enforces_max_worker_leases_bound(self):
        jobs = [self._make_job() for _ in range(MAX_WORKER_LEASES + 1)]
        with contextlib.ExitStack() as stack:
            for job in jobs[:MAX_WORKER_LEASES]:
                stack.enter_context(self.connection.session_lease(self.binding, job))
            with self.assertRaises(ConnectionError) as err:
                with self.connection.session_lease(self.binding, jobs[-1]):
                    pass
            self.assertEqual(err.exception.code, "managed_retirement_incomplete")
            for job in jobs[:MAX_WORKER_LEASES]:
                job.revoke()

    def test_partial_disconnect_failure_retains_unconfirmed_lease(self):
        job_a = self._make_job()
        job_b = self._make_job()
        with self.connection.session_lease(self.binding, job_a), self.connection.session_lease(self.binding, job_b):
            proof = self.connection.physical_host_for_retirement()
            orig_terminal = WorkerLease.terminal
            failing_root = sorted([job_a.root.name, job_b.root.name])[1]

            def flaky_terminal(lease_self, host):
                if lease_self.root == failing_root:
                    raise ConnectionError("managed_retirement_incomplete")
                return orig_terminal(lease_self, host)

            with patch.object(WorkerLease, "terminal", flaky_terminal):
                with self.assertRaises(ConnectionError) as err:
                    self.connection.begin_disconnect(physical_host=proof)
                self.assertEqual(err.exception.code, "managed_retirement_incomplete")

            state = json.loads((self.scratch / "profile" / "state.json").read_text())
            self.assertTrue(state.get("worker_retiring"))
            self.assertEqual(list(state["worker_leases"].keys()), [failing_root])
            # Retry cleanly succeeds once host recovers.
            self.connection.begin_disconnect(physical_host=proof)
            job_a.revoke()
            job_b.revoke()

    def test_interactive_responses_retries_once_on_presend_token_rotation(self):
        body = {"model": "gpt-6.2-sol", "store": False, "stream": True, "input": [{"role": "user", "content": "hi"}]}
        calls = {"responses": 0, "before_send": 0}
        orig_responses = self.transport.responses

        @contextlib.contextmanager
        def rotating_responses(req_body, bearer, cancellation, dispatch, **kwargs):
            calls["responses"] += 1
            if calls["responses"] == 1:
                raise ConnectionError("openai_access_token_changed")
            with orig_responses(req_body, bearer, cancellation, dispatch) as ev:
                yield ev

        self.transport.responses = rotating_responses
        with self.connection.interactive_responses(
            self.binding, body, lambda: calls.__setitem__("before_send", calls["before_send"] + 1),
        ) as events:
            received = list(events)
        self.assertEqual(calls["responses"], 2)
        self.assertEqual(calls["before_send"], 1)
        self.assertTrue(any(e.get("type") == "response.completed" for e in received))

    def test_stream_limits_and_sse_id_retry_under_missing_content_type(self):
        payload = (
            b'event: response.created\nid: evt_1\nretry: 1000\ndata: {"type":"response.created","response":{"id":"resp_1"}}\n\n'
            b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_1","status":"completed"}}\n\n'
        )
        wire = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Encoding: IDENTITY\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            + f"{len(payload):x} \r\n".encode("ascii") + payload + b"\r\n0\r\n\r\n"
        )
        local, peer = socket.socketpair()
        local.settimeout(2)
        peer.settimeout(2)

        def serve():
            with peer, peer.makefile("rb") as incoming:
                headers = {}
                incoming.readline()
                while (line := incoming.readline()) not in (b"", b"\r\n"):
                    k, v = line.split(b":", 1)
                    headers[k.lower()] = v.strip()
                incoming.read(int(headers.get(b"content-length", b"0")))
                peer.sendall(wire)

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        observed = []
        try:
            with patch("oc_openai.responses._connect", lambda h, c: (c.attach(local), local)[1]):
                limits = StreamLimits(max_json=1024 * 1024, max_stream=4 * 1024 * 1024,
                                      max_line=512 * 1024, max_events=4096, io_timeout=15)
                with OpenAITransport().responses(
                    {"model": "gpt-6.2-sol", "store": False, "stream": True, "input": []},
                    "synthetic-access", Cancellation(time.monotonic() + 2), lambda w: w(),
                    inspect_media=True, observe_media=observed.append, limits=limits,
                ) as events:
                    kinds = [e["type"] for e in events]
            self.assertEqual(observed, ["missing"])
            self.assertEqual(kinds, ["response.created", "response.completed"])
        finally:
            local.close()
            t.join(2)

    def test_interactive_responses_honors_long_turn_deadline_without_30s_clamp(self):
        body = {"model": "gpt-6.2-sol", "store": False, "stream": True, "input": [{"role": "user", "content": "hi"}]}
        captured = []
        orig_op = self.connection._operation

        @contextlib.contextmanager
        def spy_op(generation, check, *, timeout=30, deadline=None, cancelled=None):
            captured.append(timeout)
            with orig_op(generation, check, timeout=timeout, deadline=deadline, cancelled=cancelled) as c:
                yield c

        orig_resp = self.transport.responses

        @contextlib.contextmanager
        def accept_opts(req_body, bearer, cancellation, dispatch, **kwargs):
            with orig_resp(req_body, bearer, cancellation, dispatch) as ev:
                yield ev

        with patch.object(self.connection, "_operation", spy_op), patch.object(self.transport, "responses", accept_opts):
            with self.connection.interactive_responses(
                self.binding, body, deadline=time.monotonic() + 300,
            ) as events:
                list(events)
        self.assertEqual(len(captured), 1)
        self.assertGreater(captured[0], 250)

    def test_profile_backend_active_connection_requires_reviewed_and_disconnect_retires_leased(self):
        from oc_openai.cli import Reason, RouteUnavailable
        from oc_openai.profile_backend import ProfileBackend

        unreviewed = ProfileBackend(self.scratch / "pb-unreviewed", reviewed=False)
        with self.assertRaises(RouteUnavailable) as err:
            unreviewed.active_connection()
        self.assertEqual(err.exception.reason, Reason.QUALIFICATION)


if __name__ == "__main__":
    unittest.main()
