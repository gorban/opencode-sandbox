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
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from oc_openai.connection import ConnectionError
from oc_openai.managed import relay as relay_mod
from oc_openai.session_broker import (
    SessionBroker,
    SessionPolicy,
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
    def interactive_responses(self, binding, body, before_send=None, *, authorization=None,
                              write_fence=None, **kwargs):
        self.require_active(binding)
        auth_ctx = authorization() if authorization is not None else contextlib.nullcontext()
        fence_ctx = write_fence() if write_fence is not None else contextlib.nullcontext()
        with auth_ctx, fence_ctx:
            if before_send is not None:
                before_send()
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
                   "response": {
                       "id": "resp_up_1", "status": "completed",
                       "output": [
                           {"type": "function_call", "call_id": "call_1", "name": "read",
                            "arguments": "{}", "status": "completed"},
                       ],
                       "usage": {"input_tokens": 11, "output_tokens": 4, "total_tokens": 15},
                   }}

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

        body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "tools": [{"type": "function", "name": "read", "parameters": {"type": "object"}}],
            "input": [{"role": "user", "content": "SUPER_SECRET_PROMPT"}],
        }).encode()
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

        body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "tools": [{"type": "function", "name": "bash", "parameters": {"type": "object"}}],
            "input": [{"role": "user", "content": "hi"}],
        }).encode()
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
            profile_label="personal", policy=SessionPolicy(on_revoke=revoked.set),
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
                (["-i", "openai-relay", "-k"], "invalid instance name"),
                (["-i", "openai-home", "-k"], "invalid instance name"),
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
            profile_label="personal", usage_dir=missing_dir, policy=SessionPolicy(exposure_dir=self.usage_dir),
        )
        broker.start()
        self.addCleanup(broker.close)

        body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "tools": [{"type": "function", "name": "bash", "parameters": {"type": "object"}}],
            "input": [{"role": "user", "content": "hi"}],
        }).encode()
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

    def _valid_spec(self, *, instance="default", with_dind=False):
        pod = "oc" if instance == "default" else f"oc-{instance}"
        return {
            "instance": instance,
            "pod": pod,
            "agent": f"{pod}-agent",
            "relay": f"{pod}-openai-relay",
            "relay_image": "a" * 64,
            "agent_image": "b" * 64,
            "agent_mem": "4g",
            "level": "s0:c10,c20",
            "sandbox": "/home/user/opencode-sandbox",
            "cwd": "construct" if instance == "default" else f"wt/{instance}",
            "home_vol": f"{pod}-openai-home",
            "chromium": f"{pod}-chromium",
            "postgres": "",
            "pg_secret": "",
            "dind": f"{pod}-dind" if with_dind else "",
            "dind_run": f"{pod}-dind-run" if with_dind else "",
        }

    def test_validate_spec_and_verify_pod_reject_malformed_inputs(self):
        from oc_openai.session_broker import _validate_spec, _verify_pod

        # Default instance uses pod='oc' and must validate cleanly.
        spec = self._valid_spec(instance="default", with_dind=True)
        self.assertEqual(_validate_spec(spec)["pod"], "oc")

        bad_cases = [
            {**spec, "cwd": "../escape"},
            {**spec, "sandbox": "/home/user/sb:ro"},
            {**spec, "agent_mem": "4g,privileged"},
            {**spec, "agent_image": "not-a-sha256"},
            {**spec, "pod": "oc-other"},
            {**spec, "dind_run": ""},
            {**spec, "extra": "unexpected"},
            {**spec, "level": "s0:c10,c10"},
        ]
        for bad in bad_cases:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _validate_spec(bad)

        # Pod re-verification must reject published sensitive port 8401.
        bad_pod = {
            "Id": "c" * 64,
            "Labels": {"oc.sandbox": "1", "oc.instance": "default", "oc.ports": "8401:8401"},
            "InfraConfig": {"PortBindings": {"8401/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8401"}]}},
        }
        with patch("oc_openai.session_broker.inspected", return_value=bad_pod):
            with self.assertRaisesRegex(RuntimeError, "forbidden port"):
                _verify_pod(spec)

    def test_run_interactive_session_activates_pending_scrubs_host_spawn_and_verifies_dind_isolation(self):
        from unittest.mock import patch
        from oc_openai.cli import StreamTerminal
        from oc_openai import session_broker

        spec = self._valid_spec(instance="default", with_dind=True)
        pod_id = "d" * 64
        relay_id = "e" * 64
        agent_id = "f" * 64
        proc_label = "system_u:system_r:container_t:s0:c30,c40"
        mount_label = "system_u:object_r:container_file_t:s0:c30,c40"

        created_roots = []
        popen_calls = []
        agent_create_args = []
        inspected_siblings = []

        class _FakeBackend:
            def __init__(self, state_dir: Path):
                from oc_openai.profiles import Profile
                self._state = state_dir
                self._state.mkdir(parents=True, exist_ok=True)
                self._state.chmod(0o700)
                self.selected = ("work", "epoch-1")
                self._profile = Profile(
                    "work", state_dir / "work",
                    "urn:uuid:" + "0" * 8 + "-0000-4000-8000-" + "0" * 12,
                    "epoch-1", "client-1", False, True,
                )

            def active_label(self):
                return "work"

            @property
            def profiles(self):
                from oc_openai.profiles import RegistryView
                prof = self._profile

                class _Snap:
                    def snapshot(self):
                        return RegistryView((prof,), prof)
                return _Snap()

            def profile_connection(self, label):
                assert label == "work"

                class _Conn:
                    def models(self, _binding):
                        return ("gpt-6.2-sol",)

                    def require_active(self, _binding):
                        return None
                return self._profile, _Conn(), object()

            def profile_valid(self, label, epoch, *, directory, client_id):
                return (label, epoch, directory, client_id) == (
                    "work", "epoch-1", self._profile.directory, "client-1",
                )

            @contextlib.contextmanager
            def profile_fence(self, label, epoch, *, directory, client_id):
                assert self.profile_valid(label, epoch, directory=directory, client_id=client_id)
                yield

            @contextlib.contextmanager
            def profile_session_lease(self, label, epoch, binding, job, *, directory, client_id, release_gate=None):
                assert self.profile_valid(label, epoch, directory=directory, client_id=client_id)
                created_roots.append(job.root)
                yield job.lease

        class _FakeProc:
            def poll(self):
                return 0

            def wait(self):
                return 0

        def fake_inspected(*args):
            if args[:2] == ("pod", "inspect"):
                return {
                    "Id": pod_id,
                    "Labels": {"oc.sandbox": "1", "oc.instance": "default", "oc.ports": ""},
                    "InfraConfig": {"PortBindings": {}},
                }
            if args[:2] == ("container", "inspect") and args[2] == relay_id:
                root = created_roots[-1]
                return {
                    "Id": relay_id,
                    "Pod": pod_id,
                    "Image": spec["relay_image"],
                    "ProcessLabel": proc_label,
                    "MountLabel": mount_label,
                    "EffectiveCaps": [],
                    "Config": {"User": "0:0"},
                    "HostConfig": {
                        "ReadonlyRootfs": True,
                        "Privileged": False,
                        "IpcMode": "private",
                        "PidMode": "private",
                        "CgroupMode": "private",
                        "SecurityOpt": ["no-new-privileges"],
                    },
                    "Mounts": [
                        {"Destination": "/source", "Type": "bind", "Source": str(root / "source"),
                         "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["ro", "Z", "nosuid", "nodev", "noexec"]},
                        {"Destination": "/provider", "Type": "bind", "Source": str(root / "provider"),
                         "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["ro", "Z", "nosuid", "nodev", "noexec"]},
                        {"Destination": "/grant", "Type": "bind", "Source": str(root / "grant"),
                         "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["ro", "Z", "nosuid", "nodev", "noexec"]},
                        {"Destination": "/proof", "Type": "bind", "Source": str(root / "proof"),
                         "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["ro", "Z", "nosuid", "nodev", "noexec"]},
                    ],
                }
            raise AssertionError(f"unexpected inspected call: {args}")

        def fake_podman(*args, check=True, timeout=12):
            if args[0] == "create" and (spec["relay"] in args or f"{spec['pod']}-relay-0" in args):
                return subprocess.CompletedProcess(args, 0, (relay_id + "\n").encode(), b"")
            if args[0] == "create" and spec["agent"] in args:
                agent_create_args.extend(args)
                return subprocess.CompletedProcess(args, 0, (agent_id + "\n").encode(), b"")
            if args[:2] == ("container", "inspect") and args[2] in (spec["agent"], spec["relay"], f"{spec['pod']}-relay-0"):
                return subprocess.CompletedProcess(args, 1, b"", b"")
            if args[:2] == ("container", "inspect"):
                inspected_siblings.append(args[2])
                sib_label = "system_u:system_r:container_t:s0:c50,c60"
                return subprocess.CompletedProcess(args, 0, json.dumps([{"ProcessLabel": sib_label}]).encode(), b"")
            if args[:2] == ("container", "exists"):
                return subprocess.CompletedProcess(args, 1, b"", b"")
            if args[:2] == ("exec", relay_id) and args[2] == "cat":
                return subprocess.CompletedProcess(args, 0, proc_label.encode("ascii") + b"\0", b"")
            if args[:2] == ("exec", relay_id) and args[2] == "python3":
                return subprocess.CompletedProcess(args, 0, b"", b"")
            return subprocess.CompletedProcess(args, 0, b"", b"")

        def fake_host_output(prog, *args):
            assert prog == "getfattr"
            return mount_label.encode("ascii") + b"\0"

        def fake_popen(cmd, *, env=None):
            popen_calls.append((cmd, env))
            return _FakeProc()

        class _FakeTerm(StreamTerminal):
            def __init__(self):
                self.lines = []
                self.errors = []

            def attended(self):
                return True

            def write(self, text):
                self.lines.append(text)

            def error(self, text):
                self.errors.append(text)

            def confirm(self, _prompt):
                return True

        term = _FakeTerm()
        backend = _FakeBackend(self.root / "state")
        empty_cfg = self.root / "empty_cfg"
        empty_cfg.mkdir(mode=0o700)
        lock_dir = self.root / "lock_state"
        lock_dir.mkdir(mode=0o700)
        with (patch.object(session_broker, "check_devbox"),
              patch.object(session_broker, "check_host"),
              patch.object(session_broker, "make_backend", return_value=backend),
              patch.object(session_broker, "SHARED_TMP", str(self.root)),
              patch.object(session_broker, "inspected", side_effect=fake_inspected),
              patch.object(session_broker, "podman", side_effect=fake_podman),
              patch.object(session_broker, "host_output", side_effect=fake_host_output),
              patch.object(session_broker.subprocess, "Popen", side_effect=fake_popen)):
            rc = session_broker.run_interactive_session(spec, term, config_dir=empty_cfg, lock_dir=lock_dir)

        self.assertEqual(rc, 0, term.errors)
        # P1 #1: runtime directory cleaned up after pending -> activate -> start -> teardown.
        self.assertEqual(len(created_roots), 1)
        self.assertFalse(created_roots[0].exists())
        # P1 #2: host-spawn scrubs env and passes physical host /run/user/<uid>, NOT /run/host/run/user/<uid>.
        self.assertEqual(len(popen_calls), 1)
        cmd, spawn_env = popen_calls[0]
        uid = os.getuid()
        self.assertIn("--env=", cmd)
        self.assertIn("/usr/bin/env", cmd)
        self.assertIn("-i", cmd)
        self.assertIn(f"XDG_RUNTIME_DIR=/run/user/{uid}", cmd)
        self.assertIn(f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus", cmd)
        self.assertNotIn("XDG_RUNTIME_DIR", spawn_env)
        self.assertEqual(spawn_env["DBUS_SESSION_BUS_ADDRESS"], f"unix:path=/run/host/run/user/{uid}/bus")
        # P1 #4a: dind inspected alongside chromium, and agent_args has hardened flags.
        self.assertIn("oc-dind", inspected_siblings)
        for flag in ("--pull=never", "--http-proxy=false", "--image-volume=ignore", "--restart=no"):
            self.assertIn(flag, agent_create_args)

        # P1 #4a fail-closed: sibling inspect JSON parse failure or missing ProcessLabel must raise.
        with patch.object(
            session_broker, "podman",
            return_value=subprocess.CompletedProcess(("podman",), 0, b"not-json", b""),
        ):
            with self.assertRaisesRegex(RuntimeError, "Malformed inspect data"):
                session_broker._verify_sibling_mcs(["oc-dind"], {30, 40})
        with patch.object(
            session_broker, "podman",
            return_value=subprocess.CompletedProcess(("podman",), 0, b"[{\"ProcessLabel\": \"\"}]", b""),
        ):
            with self.assertRaisesRegex(RuntimeError, "Missing SELinux label"):
                session_broker._verify_sibling_mcs(["oc-dind"], {30, 40})

    def _run_session_helper_fd3(self, helper: Path, fd: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["/usr/bin/bash", "-c", 'exec "$1" -IB "$2" 3<&"$3"', "_", sys.executable, str(helper), str(fd)],
            pass_fds=(fd,),
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
        )

    def test_session_helper_rejects_duplicate_json_keys_and_socket_fd3(self):
        checkout = Path(__file__).resolve().parent.parent
        helper = checkout / "oc-openai-session.py"
        valid = json.dumps(self._valid_spec(instance="work")).encode("utf-8")
        dup_payload = b'{"instance":"work",' + valid[1:]

        # Baseline: valid spec reaches run_interactive_session() and exits 2 for unattended stdin.
        r_ok, w_ok = os.pipe()
        try:
            os.write(w_ok, valid)
            os.close(w_ok)
            w_ok = -1
            ok_res = self._run_session_helper_fd3(helper, r_ok)
            self.assertEqual(ok_res.returncode, 2, ok_res.stderr)
            self.assertIn("attended foreground workstation terminal", ok_res.stderr)
        finally:
            os.close(r_ok)
            if w_ok >= 0:
                os.close(w_ok)

        # Duplicate JSON key must be rejected by decode_json() before run_interactive_session().
        r_dup, w_dup = os.pipe()
        try:
            os.write(w_dup, dup_payload)
            os.close(w_dup)
            w_dup = -1
            dup_res = self._run_session_helper_fd3(helper, r_dup)
            self.assertEqual(dup_res.returncode, 1, dup_res.stderr)
            self.assertIn("supervisor unavailable", dup_res.stderr)
        finally:
            os.close(r_dup)
            if w_dup >= 0:
                os.close(w_dup)

        # Non-regular / non-FIFO FD 3 (e.g. a socket) must be rejected by fstat(3).
        s_a, s_b = socket.socketpair()
        try:
            s_b.sendall(valid)
            s_b.shutdown(socket.SHUT_WR)
            sock_res = self._run_session_helper_fd3(helper, s_a.fileno())
            self.assertEqual(sock_res.returncode, 1, sock_res.stderr)
            self.assertIn("supervisor unavailable", sock_res.stderr)
        finally:
            s_a.close()
            s_b.close()

    def test_numeric_regexes_reject_non_ascii_digits(self):
        from oc_openai import session_broker

        self.assertIsNone(session_broker._MEM_RE.fullmatch("4\u0662m"))
        self.assertIsNone(session_broker._LEVEL_RE.fullmatch("s0:c\u0661,c2"))
        self.assertIsNone(session_broker._PORT_KEY_RE.fullmatch("\uff18\uff10/tcp"))
        self.assertIsNone(session_broker._PORT_LABEL_RE.fullmatch("\uff18\uff10:\uff18\uff10"))
        self.assertIsNotNone(session_broker._MEM_RE.fullmatch("42m"))
        self.assertIsNotNone(session_broker._LEVEL_RE.fullmatch("s0:c1,c2"))
        self.assertIsNotNone(session_broker._PORT_KEY_RE.fullmatch("80/tcp"))
        self.assertIsNotNone(session_broker._PORT_LABEL_RE.fullmatch("80:80"))

    def test_reciprocal_p1_exposure_hold_blocks_with_zero_upstream_writes_and_rejects_corrupt(self):
        from oc_openai.exposure import ExposureError, ExposureLedger, Phase, Slot, binding_digest

        ledger = ExposureLedger(self.usage_dir)
        b_hash = binding_digest("a" * 43, "b" * 43, "c" * 43)
        ledger.reserve(Slot("1" * 32, b_hash, Phase.ORCHESTRATOR))

        upstream_calls = []

        def make_events(body):
            upstream_calls.append(body)
            yield {"type": "response.created", "response": {"id": "resp_blocked", "status": "in_progress"}}
            yield {"type": "response.completed", "response": {"id": "resp_blocked", "status": "completed", "output": []}}

        # Unacknowledged blocking receipt MUST refuse with 403 and 0 upstream calls.
        broker = SessionBroker(
            socket_path=self.sock_path, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(make_events), binding=object(), models=("gpt-6.2-sol",),
            profile_label="personal", usage_dir=self.usage_dir, policy=SessionPolicy(exposure_dir=self.usage_dir),
        )
        broker.start()
        self.addCleanup(broker.close)

        body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "tools": [{"type": "function", "name": "bash", "parameters": {"type": "object"}}],
            "input": [{"role": "user", "content": "hi"}],
        }).encode()
        req = (
            f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            f"Authorization: Bearer {self.worker_token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body
        resp = _send_via_relay(self.sock_path, self.lease, self.proof, req)
        self.assertIn(b"403 Forbidden", resp)
        self.assertIn(b"exposure_hold", resp)
        self.assertEqual(upstream_calls, [])

        # Exact foreground-acknowledged snapshot allows dispatch, but any new receipt immediately blocks again.
        hold = ledger.inspect_hold()
        self.assertTrue(hold.blocked)
        broker.close()
        sock2 = self.root / "provider2.sock"
        broker2 = SessionBroker(
            socket_path=sock2, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(make_events), binding=object(), models=("gpt-6.2-sol",),
            profile_label="personal", usage_dir=self.usage_dir,
            policy=SessionPolicy(exposure_dir=self.usage_dir, acknowledged_exposure_digest=hold.digest),
        )
        broker2.start()
        self.addCleanup(broker2.close)
        resp2 = _send_via_relay(sock2, self.lease, self.proof, req)
        self.assertIn(b"response.completed", resp2)
        self.assertEqual(len(upstream_calls), 1)

        # Adding a valid new diagnostic receipt invalidates the pinned snapshot digest -> 0 further upstream calls.
        diag = self.usage_dir / "diagnostic.json"
        diag_payload = {
            "original_run": "1" * 32,
            "binding": b_hash,
            "run": "2" * 32,
            "phase": "orchestrator",
            "max_input": 922_000,
            "max_output": 128_000,
            "actual": None,
        }
        diag.write_text(json.dumps(diag_payload), encoding="ascii")
        diag.chmod(0o600)
        resp3 = _send_via_relay(sock2, self.lease, self.proof, req)
        self.assertIn(b"403 Forbidden", resp3)
        self.assertEqual(len(upstream_calls), 1)

        # Corrupt JSON, NaN constants, and schema-tampered receipts are NEVER acknowledgeable or unblocked.
        diag.write_text("{corrupt", encoding="ascii")
        with self.assertRaises(ExposureError):
            ledger.inspect_hold()
        diag.write_text(json.dumps({"corrupt": 123, "tampered": True}), encoding="ascii")
        with self.assertRaises(ExposureError):
            ledger.inspect_hold()
        diag.write_text('{"original_run": NaN}', encoding="ascii")
        with self.assertRaises(ExposureError):
            ledger.inspect_hold()
        diag.unlink()

        # Tampered or overage canary.json MUST fail closed (never silently unblocked); valid overage blocks.
        canary_dir = self.root / "canary_hold_check"
        canary_dir.mkdir(mode=0o700)
        c_ledger = ExposureLedger(canary_dir)
        c_path = canary_dir / "canary.json"
        for bad_canary in (
            {"outcome": "ok_settled", "tampered": True},
            {"run_id": "a" * 32, "binding": b_hash, "model": "gpt-6.2-sol", "history_digest": "0" * 64,
             "max_input": 922_000, "max_output": 128_000, "actual": None, "outcome": "ok_settled", "delivered": True},
            {"run_id": "a" * 32, "binding": b_hash, "model": "gpt-6.2-sol", "history_digest": "0" * 64,
             "max_input": 922_000, "max_output": 128_000, "actual": [999_999, 1], "outcome": "ok_settled", "delivered": True},
        ):
            c_path.write_text(json.dumps(bad_canary), encoding="ascii")
            c_path.chmod(0o600)
            with self.assertRaises(ExposureError):
                c_ledger.inspect_hold()
        valid_overage = {
            "run_id": "a" * 32, "binding": b_hash, "model": "gpt-6.2-sol", "history_digest": "0" * 64,
            "max_input": 922_000, "max_output": 128_000, "actual": [922_001, 1],
            "outcome": "overage_settled", "delivered": False,
        }
        c_path.write_text(json.dumps(valid_overage), encoding="ascii")
        c_path.chmod(0o600)
        self.assertTrue(c_ledger.inspect_hold().blocked)
        c_path.unlink()

        # Valid unsettled recovery-proof.json accurately reports unsettled_count=1 and rejects corrupt recovery.
        rec_path = canary_dir / "recovery-proof.json"
        rec_path.write_text(json.dumps({
            "version": 1, "prior": ["1" * 32], "source": "a" * 64,
            "phases": [{"run": "3" * 32, "binding": b_hash, "phase": "orchestrator",
                        "max_input": 922_000, "max_output": 128_000, "actual": None}],
        }), encoding="ascii")
        rec_path.chmod(0o600)
        rec_hold = c_ledger.inspect_hold()
        self.assertTrue(rec_hold.blocked)
        self.assertEqual(rec_hold.unsettled_count, 1)
        rec_path.write_text(json.dumps({"corrupt": 123}), encoding="ascii")
        with self.assertRaises(ExposureError):
            c_ledger.inspect_hold()

    def test_reciprocal_p2_container_ownership_and_exception_cleanup_propagation(self):
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.cli import StreamTerminal

        # Foreign stopped container (missing oc.sandbox=1 / matching oc.instance) MUST be refused without rm.
        rm_calls = []

        def fake_podman_foreign(*args, check=True, timeout=12):
            if args[:2] == ("container", "inspect"):
                return subprocess.CompletedProcess(
                    args, 0,
                    json.dumps([{"Id": "a" * 64, "State": {"Running": False, "Status": "exited"},
                                 "Config": {"Labels": {"oc.sandbox": "1", "oc.instance": "other"}}}]).encode(),
                    b"",
                )
            if args[0] == "rm":
                rm_calls.append(args)
            return subprocess.CompletedProcess(args, 0, b"", b"")

        with patch.object(session_broker, "podman", side_effect=fake_podman_foreign):
            with self.assertRaisesRegex(RuntimeError, "unowned stopped container"):
                session_broker._ensure_containers_idle("oc-work-agent", "oc-work-openai-relay", "work")
        self.assertEqual(rm_calls, [])

        # Owned stopped container is removed strictly by exact 64-hex ID without --force.
        owned_id = "b" * 64

        def fake_podman_owned(*args, check=True, timeout=12):
            if args[:2] == ("container", "inspect") and args[2] == "oc-work-agent":
                return subprocess.CompletedProcess(
                    args, 0,
                    json.dumps([{"Id": owned_id, "State": {"Running": False, "Status": "exited"},
                                 "Config": {"Labels": {"oc.sandbox": "1", "oc.instance": "work"}}}]).encode(),
                    b"",
                )
            if args[:2] == ("container", "inspect"):
                return subprocess.CompletedProcess(args, 1, b"", b"")
            if args[:2] == ("container", "exists"):
                return subprocess.CompletedProcess(args, 1, b"", b"")
            if args[0] == "rm":
                rm_calls.append(args)
            return subprocess.CompletedProcess(args, 0, b"", b"")

        with patch.object(session_broker, "podman", side_effect=fake_podman_owned):
            session_broker._ensure_containers_idle("oc-work-agent", "oc-work-openai-relay", "work")
        self.assertEqual(rm_calls, [("rm", owned_id)])

        # Verified teardown on KeyboardInterrupt still removes owned private scratch dir.
        spec = self._valid_spec(instance="work")
        created_roots = []

        class _InterruptBackend:
            def __init__(self, state_dir: Path):
                self._state = state_dir
                self._state.mkdir(parents=True, exist_ok=True)
                self._state.chmod(0o700)

            def active_label(self):
                return "work"

            def profile_connection(self, label):
                from oc_openai.profiles import Profile

                class _Conn:
                    def models(self, _binding):
                        return ("gpt-6.2-sol",)
                prof = Profile(label, self._state / label, "urn:uuid:" + "0" * 8 + "-0000-4000-8000-" + "0" * 12,
                               "epoch-1", "client-1", False, True)
                return prof, _Conn(), object()

            @property
            def profiles(self):
                from oc_openai.profiles import Profile, RegistryView
                prof = Profile("work", self._state / "work", "urn:uuid:" + "0" * 8 + "-0000-4000-8000-" + "0" * 12,
                               "epoch-1", "client-1", False, True)

                class _Snap:
                    def snapshot(self):
                        return RegistryView((prof,), prof)
                return _Snap()

        class _Term(StreamTerminal):
            def __init__(self):
                self.errors = []

            def attended(self):
                return True

            def write(self, _text):
                return None

            def error(self, text):
                self.errors.append(text)

            def confirm(self, _prompt):
                return True

            def choose(self, _prompt, _options):
                return 0

        def fake_verify_pod(_spec):
            raise KeyboardInterrupt

        empty_cfg_dir = self.root / "int_cfg"
        empty_cfg_dir.mkdir(mode=0o700)
        int_lock_dir = self.root / "int_lock_state"
        int_lock_dir.mkdir(mode=0o700)
        with (patch.object(session_broker, "check_devbox"),
              patch.object(session_broker, "check_host"),
              patch.object(session_broker, "make_backend", return_value=_InterruptBackend(self.root / "int_state")),
              patch.object(session_broker, "SHARED_TMP", str(self.root)),
              patch.object(session_broker, "_verify_pod_with_containers", side_effect=fake_verify_pod)):
            before_dirs = set(self.root.glob("oc-chat-*"))
            rc = session_broker.run_interactive_session(spec, _Term(), config_dir=empty_cfg_dir, lock_dir=int_lock_dir)
            after_dirs = set(self.root.glob("oc-chat-*"))
        self.assertEqual(rc, 130)
        self.assertEqual(after_dirs, before_dirs)

    def test_reciprocal_p1_selection_fence_same_label_and_write_critical_section(self):
        import pwd
        from unittest.mock import patch
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.profile_backend import ProfileBackend
        from oc_openai.cli import RouteUnavailable
        from oc_openai.session_broker import _SessionJob
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        def _forbid_host_browser(url):
            raise AssertionError(f"unit test attempted to open host browser: {url}")

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))

        # 1. Connection.interactive_responses runs authorization -> store.lock -> before_send -> write atomically.
        order = []
        state_dir = scratch / "fence_conn"
        verifier = FixtureVerifier()
        transport = FixtureTransport()
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")

        @contextlib.contextmanager
        def ordered_responses(body, access, cancellation, dispatch, **kwargs):
            def write():
                order.append("write")
                return "ok"
            dispatch(write)
            yield iter([
                {"type": "response.created", "response": {"id": "resp_f1", "status": "in_progress"}},
                {"type": "response.completed", "response": {"id": "resp_f1", "status": "completed", "output": []}},
            ])

        transport.responses = ordered_responses
        conn = Connection(
            state_dir, transport=transport, verifier=verifier,
            browser=FixtureBrowser(), host_probe=lambda: host,
        )
        binding = conn.connect()

        @contextlib.contextmanager
        def auth_ctx():
            order.append("auth_enter")
            try:
                yield
            finally:
                order.append("auth_exit")

        def check_inside_lock():
            order.append("before_write")

        body = {"model": "gpt-6.2-sol", "stream": True, "store": False,
                "input": [{"role": "user", "content": "hi"}]}
        with conn.interactive_responses(binding, body, check_inside_lock, authorization=auth_ctx) as events:
            list(events)
        self.assertEqual(order, ["auth_enter", "before_write", "write", "auth_exit"])

        # 2. Same-label select() is refused while an interactive session lease is active.
        prof_dir = scratch / "fence_profiles"
        shared_verifier = FixtureVerifier()
        shared_transport = FixtureTransport()
        backend = ProfileBackend(
            prof_dir,
            connection=lambda d: Connection(
                d, transport=shared_transport, verifier=shared_verifier,
                browser=FixtureBrowser(), host_probe=lambda: host,
            ),
        )
        backend.connect("personal")
        label, epoch, _pconn, pbinding = backend.active_connection()
        job_dir = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
        self.addCleanup(lambda: job_dir.exists() and shutil.rmtree(job_dir, ignore_errors=True))
        job = _SessionJob(job_dir, "inc_" + "1" * 32)
        job.prepare({"model": "local/gpt-6.2-sol"})
        self.addCleanup(job.revoke)
        with backend.session_lease(label, epoch, pbinding, job):
            with self.assertRaises(RouteUnavailable):
                backend.select("personal")
            job.revoke()

        # 3. Mid-stream revocation before finalize() withholds buffered function_call frames.
        selected = [True]

        def revoke_after_completed(_body):
            yield {"type": "response.created", "response": {"id": "resp_rev", "status": "in_progress"}}
            yield {"type": "response.output_item.done", "output_index": 0,
                   "item": {"type": "function_call", "call_id": "call_rev", "name": "bash", "arguments": "{}"}}
            yield {"type": "response.completed", "response": {
                "id": "resp_rev", "status": "completed",
                "output": [{"type": "function_call", "call_id": "call_rev", "name": "bash",
                            "arguments": "{}", "status": "completed"}],
            }}
            selected[0] = False

        sock_rev = self.root / "provider_rev.sock"
        broker_rev = SessionBroker(
            socket_path=sock_rev, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(revoke_after_completed), binding=object(),
            models=("gpt-6.2-sol",), profile_label="personal", usage_dir=self.usage_dir,
            policy=SessionPolicy(exposure_dir=self.usage_dir, is_selected=lambda: selected[0]),
        )
        broker_rev.start()
        self.addCleanup(broker_rev.close)
        req_body = json.dumps({
            **body,
            "tools": [{"type": "function", "name": "bash", "parameters": {"type": "object"}}],
        }).encode()
        req = (
            f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            f"Authorization: Bearer {self.worker_token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(req_body)}\r\n\r\n"
        ).encode("ascii") + req_body
        raw_rev = _send_via_relay(sock_rev, self.lease, self.proof, req)
        self.assertNotIn(b"call_rev", raw_rev)
        self.assertFalse(raw_rev.endswith(b"0\r\n\r\n"))

    def test_live_e2e_regressions_real_selected_fence_poststart_mounts_and_chromium_selinux(self):
        import pwd
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.profile_backend import ProfileBackend
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        # 1. Post-start Podman clears Mounts[].Mode from "Z" to ""; accept "" and "Z", still reject "z".
        job_root = self.root / "mnt_job"
        job_root.mkdir(mode=0o700)
        mnt_job = session_broker._SessionJob(job_root, "inc_" + "2" * 32)
        mnt_job.prepare({"model": "local/gpt-6.2-sol"})
        self.addCleanup(mnt_job.revoke)
        mounts = [
            {"Destination": dst, "Type": "bind", "Source": str(src), "RW": False,
             "Mode": "", "Propagation": "rprivate", "Options": ["nosuid", "nodev", "noexec", "rbind"]}
            for dst, src in (
                ("/source", mnt_job.source_dir),
                ("/provider", mnt_job.provider_socket.parent),
                ("/grant", mnt_job.grant),
                ("/proof", mnt_job.proof_file.parent),
            )
        ]
        session_broker._verify_relay_mounts({"Mounts": mounts}, mnt_job)
        mounts[0]["Mode"] = "z"
        with self.assertRaises(RuntimeError):
            session_broker._verify_relay_mounts({"Mounts": mounts}, mnt_job)

        # 2. Sibling oc-chromium custom SELinux type (oc_chromium.process) extracts MCS pair cleanly.
        self.assertEqual(
            session_broker._mcs_pair("system_u:system_r:oc_chromium.process:s0:c99,c993", allow_custom_type=True),
            {99, 993},
        )
        self.assertIsNone(session_broker._mcs_pair("system_u:system_r:oc_chromium.process:s0:c99,c993"))

        # 3. Real ProfileBackend.selected_fence + active_selection in SessionBroker never self-deadlocks flock.
        def _forbid_host_browser(url):
            raise AssertionError(f"unit test attempted to open host browser: {url}")

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        shared_verifier = FixtureVerifier()
        shared_transport = FixtureTransport()

        @contextlib.contextmanager
        def ok_responses(body, access, cancellation, dispatch, **kwargs):
            dispatch(lambda: "sent")
            yield iter([
                {"type": "response.created", "response": {"id": "resp_real_fence", "status": "in_progress"}},
                {"type": "response.output_text.delta", "delta": "ok"},
                {"type": "response.completed", "response": {
                    "id": "resp_real_fence", "status": "completed", "output": [],
                    "usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3},
                }},
            ])

        shared_transport.responses = ok_responses
        backend = ProfileBackend(
            scratch / "real_fence_profiles",
            connection=lambda d: Connection(
                d, transport=shared_transport, verifier=shared_verifier,
                browser=FixtureBrowser(), host_probe=lambda: host,
            ),
        )
        backend.connect("personal")
        label, epoch, conn, binding = backend.active_connection()
        sock_real = self.root / "provider_real_fence.sock"
        broker_real = SessionBroker(
            socket_path=sock_real, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=conn, binding=binding, models=("gpt-6.2-sol",),
            profile_label=label, usage_dir=backend._state,
            policy=SessionPolicy(
                exposure_dir=backend._state,
                authorization=lambda: backend.selected_fence(label, epoch),
                is_selected=lambda: backend.active_selection() == (label, epoch),
            ),
        )
        broker_real.start()
        self.addCleanup(broker_real.close)
        body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "tools": [{"type": "function", "name": "bash", "parameters": {"type": "object"}}],
            "input": [{"role": "user", "content": "hi"}],
        }).encode()
        req = (
            f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            f"Authorization: Bearer {self.worker_token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body
        raw = _send_via_relay(sock_real, self.lease, self.proof, req)
        self.assertIn(b"200 OK", raw)
        self.assertIn(b"response.completed", raw)

    def test_reciprocal_r2_exposure_lock_spans_first_write_and_blocks_concurrent_reservation(self):
        import pwd
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.exposure import ExposureError, ExposureLedger, Phase, Slot, binding_digest
        from oc_openai.profile_backend import ProfileBackend
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        def _forbid_host_browser(url):
            raise AssertionError(f"unit test attempted to open host browser: {url}")

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        shared_verifier = FixtureVerifier()
        shared_transport = FixtureTransport()
        lock_contested = []
        state_holder = []

        @contextlib.contextmanager
        def checking_responses(body, access, cancellation, dispatch, **kwargs):
            def write():
                ledger = ExposureLedger(state_holder[0])
                slot = Slot("a" * 32, binding_digest("a" * 43, "b" * 43), Phase.ORCHESTRATOR)
                try:
                    ledger.reserve(slot)
                    lock_contested.append("UNLOCKED_RACE")
                except ExposureError as exc:
                    lock_contested.append(exc.args[0])
                return "sent"

            dispatch(write)
            yield iter([
                {"type": "response.created", "response": {"id": "resp_lock", "status": "in_progress"}},
                {"type": "response.completed", "response": {"id": "resp_lock", "status": "completed", "output": []}},
            ])

        shared_transport.responses = checking_responses
        backend = ProfileBackend(
            scratch / "exp_fence_profiles",
            connection=lambda d: Connection(
                d, transport=shared_transport, verifier=shared_verifier,
                browser=FixtureBrowser(), host_probe=lambda: host,
            ),
        )
        backend.connect("personal")
        state_holder.append(backend._state)
        label, epoch, conn, binding = backend.active_connection()
        sock_exp = self.root / "provider_exp_fence.sock"
        broker = SessionBroker(
            socket_path=sock_exp, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=conn, binding=binding, models=("gpt-6.2-sol",),
            profile_label=label, usage_dir=backend._state,
            policy=SessionPolicy(
                exposure_dir=backend._state,
                authorization=lambda: backend.selected_fence(label, epoch),
                is_selected=lambda: backend.active_selection() == (label, epoch),
            ),
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
        raw = _send_via_relay(sock_exp, self.lease, self.proof, req)
        self.assertIn(b"response.completed", raw)
        # During write(), exposure.lock MUST have been held so concurrent reserve() failed closed.
        self.assertEqual(lock_contested, ["exposure_lock_busy"])
        # Once write() finishes, exposure.lock is released cleanly.
        ExposureLedger(backend._state).reserve(Slot("b" * 32, binding_digest("a" * 43, "b" * 43), Phase.ORCHESTRATOR))

    def test_reciprocal_r2_mid_batch_revocation_withholds_remaining_terminal_tool_frames(self):
        selected = [True]

        def two_tool_events(_body):
            yield {"type": "response.created", "response": {"id": "resp_mb", "status": "in_progress"}}
            yield {"type": "response.output_item.added", "output_index": 0,
                   "item": {"id": "fc_mb_1", "type": "function_call", "call_id": "call_first",
                            "name": "read", "arguments": ""}}
            yield {"type": "response.output_item.done", "output_index": 0,
                   "item": {"id": "fc_mb_1", "type": "function_call", "call_id": "call_first",
                            "name": "read", "arguments": '{"p":"a"}', "status": "completed"}}
            yield {"type": "response.output_item.done", "output_index": 1,
                   "item": {"id": "fc_mb_2", "type": "function_call", "call_id": "call_SECOND_WITHHELD",
                            "name": "edit", "arguments": '{"p":"b"}', "status": "completed"}}
            yield {"type": "response.completed", "response": {
                "id": "resp_mb", "status": "completed",
                "output": [
                    {"id": "fc_mb_1", "type": "function_call", "call_id": "call_first",
                     "name": "read", "arguments": '{"p":"a"}', "status": "completed"},
                    {"id": "fc_mb_2", "type": "function_call", "call_id": "call_SECOND_WITHHELD",
                     "name": "edit", "arguments": '{"p":"b"}', "status": "completed"},
                ],
            }}

        from oc_openai import session_broker
        orig_encode = session_broker.encode_chunk

        def revoke_after_first_tool_frame(payload):
            chunk = orig_encode(payload)
            if b"call_first" in payload:
                selected[0] = False
            return chunk

        sock_mb = self.root / "provider_midbatch.sock"
        broker = SessionBroker(
            socket_path=sock_mb, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(two_tool_events), binding=object(),
            models=("gpt-6.2-sol",), profile_label="personal", usage_dir=self.usage_dir,
            policy=SessionPolicy(exposure_dir=self.usage_dir, is_selected=lambda: selected[0]),
        )
        broker.start()
        self.addCleanup(broker.close)

        body = json.dumps({
            "model": "gpt-6.2-sol", "stream": True, "store": False,
            "tools": [
                {"type": "function", "name": "read", "parameters": {"type": "object"}},
                {"type": "function", "name": "edit", "parameters": {"type": "object"}},
            ],
            "input": [{"role": "user", "content": "hi"}],
        }).encode()
        req = (
            f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
            f"Authorization: Bearer {self.worker_token}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode("ascii") + body
        with patch.object(session_broker, "encode_chunk", side_effect=revoke_after_first_tool_frame):
            raw = _send_via_relay(sock_mb, self.lease, self.proof, req)
        self.assertNotIn(b"call_SECOND_WITHHELD", raw)
        self.assertNotIn(b"response.completed", raw)
        self.assertFalse(raw.endswith(b"0\r\n\r\n"))

    def test_reciprocal_r2_recovery_receipt_requires_matching_predecessor(self):
        from hashlib import sha256
        from oc_openai.exposure import ExposureError, ExposureLedger, binding_digest

        b_hash = binding_digest("a" * 43, "b" * 43)
        rec_dir = self.root / "pred_check"
        rec_dir.mkdir(mode=0o700)
        ledger = ExposureLedger(rec_dir)

        canary_payload = {
            "run_id": "a" * 32, "binding": b_hash, "model": "gpt-6.2-sol", "history_digest": "0" * 64,
            "max_input": 922_000, "max_output": 128_000, "actual": None,
            "outcome": "unsettled", "delivered": False,
        }
        canary_raw = json.dumps(canary_payload, sort_keys=True).encode("ascii")
        canary_digest = sha256(canary_raw).hexdigest()
        recovery_payload = {
            "run_id": "b" * 32, "binding": b_hash, "model": "gpt-6.2-sol", "history_digest": "0" * 64,
            "max_input": 922_000, "max_output": 128_000, "actual": [10, 5],
            "outcome": "ok_settled", "delivered": True,
            "prior_canary_run_id": "a" * 32, "prior_canary_digest": canary_digest,
        }

        rec_path = rec_dir / "canary-recovery.json"
        rec_path.write_text(json.dumps(recovery_payload), encoding="ascii")
        rec_path.chmod(0o600)

        # 1. Missing canary.json predecessor MUST fail closed (never pass inspection).
        with self.assertRaisesRegex(ExposureError, "invalid_exposure_record"):
            ledger.inspect_hold()

        # 2. Mismatched predecessor digest or run_id MUST fail closed.
        canary_path = rec_dir / "canary.json"
        canary_path.write_bytes(json.dumps({**canary_payload, "run_id": "c" * 32}).encode("ascii"))
        canary_path.chmod(0o600)
        with self.assertRaisesRegex(ExposureError, "invalid_exposure_record"):
            ledger.inspect_hold()

        # 3. Already-settled canary.json with matching digest still mismatches unsettled precondition.
        settled_canary = {**canary_payload, "actual": [5, 2], "outcome": "ok_settled", "delivered": True}
        settled_raw = json.dumps(settled_canary, sort_keys=True).encode("ascii")
        canary_path.write_bytes(settled_raw)
        rec_path.write_text(
            json.dumps({**recovery_payload, "prior_canary_digest": sha256(settled_raw).hexdigest()}),
            encoding="ascii",
        )
        with self.assertRaisesRegex(ExposureError, "invalid_exposure_record"):
            ledger.inspect_hold()

        # 4. Exact matching unsettled canary.json predecessor passes inspection and reports blocked=True.
        canary_path.write_bytes(canary_raw)
        rec_path.write_text(json.dumps(recovery_payload), encoding="ascii")
        hold = ledger.inspect_hold()
        self.assertTrue(hold.blocked)
        self.assertEqual((hold.file_count, hold.unsettled_count), (2, 1))

        # 5. Orphan diagnostic.json without exposure.json also fails closed.
        diag_dir = self.root / "orphan_diag"
        diag_dir.mkdir(mode=0o700)
        diag_path = diag_dir / "diagnostic.json"
        diag_path.write_text(json.dumps({
            "original_run": "1" * 32, "binding": b_hash, "run": "2" * 32,
            "phase": "orchestrator", "max_input": 922_000, "max_output": 128_000, "actual": [5, 5],
        }), encoding="ascii")
        diag_path.chmod(0o600)
        diag_ledger = ExposureLedger(diag_dir)
        with self.assertRaisesRegex(ExposureError, "invalid_exposure_record"):
            diag_ledger.inspect_hold()

    def test_reciprocal_r2_stalled_peer_never_holds_locks_during_fenced_send(self):
        auth_lock = threading.Lock()
        auth_acquires = []

        @contextlib.contextmanager
        def tracked_auth():
            auth_lock.acquire()
            try:
                yield
            finally:
                auth_lock.release()

        broker = SessionBroker(
            socket_path=self.sock_path, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(lambda _b: iter(())), binding=object(),
            models=("gpt-6.2-sol",), profile_label="personal", usage_dir=self.usage_dir,
            policy=SessionPolicy(exposure_dir=self.usage_dir, authorization=tracked_auth),
        )

        # Create a stalled Unix socket pair whose peer stops reading so a large payload fills the kernel buffer.
        writer, reader = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(writer.close)
        self.addCleanup(reader.close)
        with contextlib.suppress(OSError):
            writer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            reader.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        writer.settimeout(5)

        errors = []
        started = threading.Event()

        def run_send():
            started.set()
            try:
                broker._send_fenced(writer, b"x" * (1024 * 1024))
            except Exception as exc:
                errors.append(exc)

        t = threading.Thread(target=run_send, daemon=True)
        t.start()
        self.assertTrue(started.wait(1))
        time.sleep(0.05)

        # Concurrent auth + lease lock acquisition (simulating disconnect / revocation) MUST NOT stall!
        t0 = time.monotonic()
        acquired = auth_lock.acquire(timeout=0.5)
        elapsed = time.monotonic() - t0
        if acquired:
            auth_lock.release()
            auth_acquires.append(elapsed)
        self.assertTrue(acquired, "stalled peer held authorization lock across blocking socket send")
        self.assertLess(elapsed, 0.5)

        # Mid-write revocation must abort _send_fenced promptly instead of waiting 5 seconds.
        t_rev = time.monotonic()
        broker._revoked.set()
        t.join(1.5)
        self.assertFalse(t.is_alive(), "_send_fenced did not abort promptly on mid-write revocation")
        self.assertLess(time.monotonic() - t_rev, 1.0)
        self.assertEqual(len(errors), 1)
        self.assertEqual(getattr(errors[0], "code", None), "session_revoked")

    def test_reciprocal_r3_first_write_holds_lease_fence_revocation_wins_and_canary_e2e_blocks(self):
        import pwd
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.exposure import binding_digest
        from oc_openai.profile_backend import ProfileBackend
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        def _forbid_host_browser(url):
            raise AssertionError(f"unit test attempted to open host browser: {url}")

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        shared_verifier = FixtureVerifier()
        shared_transport = FixtureTransport()
        writes = []
        lease_lock_held = []

        @contextlib.contextmanager
        def checking_responses(body, access, cancellation, dispatch, **kwargs):
            def write():
                writes.append("write")
                fd = os.open(self.lease.directory / "lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        lease_lock_held.append(False)
                    except BlockingIOError:
                        lease_lock_held.append(True)
                finally:
                    os.close(fd)
                return "sent"

            dispatch(write)
            yield iter([
                {"type": "response.created", "response": {"id": "resp_lf", "status": "in_progress"}},
                {"type": "response.completed", "response": {"id": "resp_lf", "status": "completed", "output": []}},
            ])

        shared_transport.responses = checking_responses
        backend = ProfileBackend(
            scratch / "lease_fence_profiles",
            connection=lambda d: Connection(
                d, transport=shared_transport, verifier=shared_verifier,
                browser=FixtureBrowser(), host_probe=lambda: host,
            ),
        )
        backend.connect("personal")
        label, epoch, conn, binding = backend.active_connection()
        sock_lf = self.root / "provider_lf.sock"
        broker = SessionBroker(
            socket_path=sock_lf, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=conn, binding=binding, models=("gpt-6.2-sol",),
            profile_label=label, usage_dir=backend._state,
            policy=SessionPolicy(
                exposure_dir=backend._state,
                authorization=lambda: backend.selected_fence(label, epoch),
                is_selected=lambda: backend.active_selection() == (label, epoch),
            ),
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

        # 1. Active turn MUST hold the job grant lock across the first provider write.
        raw_ok = _send_via_relay(sock_lf, self.lease, self.proof, req)
        self.assertIn(b"response.completed", raw_ok)
        self.assertEqual(lease_lock_held, [True])
        self.assertEqual(len(writes), 1)

        # 2. Unsettled canary-e2e.json MUST block first dispatch with 0 upstream writes.
        e2e_path = backend._state / "canary-e2e.json"
        e2e_path.write_text(json.dumps({
            "run_id": "a" * 32, "binding": binding_digest("a" * 43, "b" * 43), "model": "gpt-6.2-sol",
            "history_digest": "0" * 64, "max_input": 922_000, "max_output": 128_000,
            "actual": None, "outcome": "unsettled", "delivered": False,
        }), encoding="ascii")
        e2e_path.chmod(0o600)
        raw_e2e = _send_via_relay(sock_lf, self.lease, self.proof, req)
        self.assertIn(b"403 Forbidden", raw_e2e)
        self.assertEqual(len(writes), 1)
        e2e_path.unlink()

        # 3. Revocation winning the lease fence before first write records 0 additional upstream writes.
        rev_win_root = self.root / "rev_win_root"
        rev_win_root.mkdir(mode=0o700)
        lease2, life_fd2 = _make_lease(rev_win_root)
        self.addCleanup(lambda: os.close(life_fd2))
        sock_rw = self.root / "provider_rw.sock"
        broker_rw = SessionBroker(
            socket_path=sock_rw, relay_proof=self.proof, worker_token=self.worker_token,
            lease=lease2, connection=conn, binding=binding, models=("gpt-6.2-sol",),
            profile_label=label, usage_dir=backend._state,
            policy=SessionPolicy(
                exposure_dir=backend._state,
                authorization=lambda: backend.selected_fence(label, epoch),
                is_selected=lambda: backend.active_selection() == (label, epoch),
            ),
        )
        broker_rw.start()
        self.addCleanup(broker_rw.close)

        results = []
        with lease2.fence():
            t = threading.Thread(target=lambda: results.append(_send_via_relay(sock_rw, lease2, self.proof, req)))
            t.start()
            time.sleep(0.1)
            terminal = relay_mod.grant_record("inc_" + "a" * 32, 1, False)
            (lease2.directory / "state").write_bytes(terminal)
            (lease2.directory / "state").chmod(0o600)
        t.join(5)
        self.assertEqual(len(writes), 1, "revocation won the lease fence yet provider write still executed")
        self.assertEqual(len(results), 1)
        self.assertNotIn(b"response.completed", results[0])

    def test_multi_instance_isolation_single_slot_revocation_and_lockouts(self):
        import pwd
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.cli import RouteUnavailable
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.profile_backend import ProfileBackend
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.contracts import ProviderInstanceSpec
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        def _forbid_host_browser(url):
            raise AssertionError(f"unit test attempted to open host browser: {url}")

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))

        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        writes_by_dir: dict[Path, int] = {}
        shared_verifier = FixtureVerifier()

        def _make_conn(directory: Path):
            transport = FixtureTransport()
            transport.user = f"user-{directory.name}"
            browser = FixtureBrowser()
            browser.client = f"oaiapp_{directory.name}"

            @contextlib.contextmanager
            def fake_responses(body, access, cancellation, dispatch, **kwargs):
                def write():
                    writes_by_dir[directory] = writes_by_dir.get(directory, 0) + 1
                    return "ok"
                dispatch(write)
                yield iter([
                    {"type": "response.created", "response": {"id": f"resp_{directory.name}", "status": "in_progress"}},
                    {"type": "response.output_item.added", "output_index": 0,
                     "item": {"id": f"rs_{directory.name}", "type": "reasoning", "summary": []}},
                    {"type": "response.output_item.done", "output_index": 0,
                     "item": {"id": f"rs_{directory.name}", "type": "reasoning", "summary": [],
                              "encrypted_content": f"enc_{directory.name}"}},
                    {"type": "response.completed", "response": {
                        "id": f"resp_{directory.name}", "status": "completed",
                        "output": [{"id": f"rs_{directory.name}", "type": "reasoning", "summary": [],
                                    "encrypted_content": f"enc_{directory.name}"}],
                        "usage": {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7},
                    }},
                ])

            transport.responses = fake_responses
            return Connection(
                directory, transport=transport, verifier=shared_verifier,
                browser=browser, host_probe=lambda: host,
            )

        prof_dir = scratch / "multi_profiles"
        backend = ProfileBackend(prof_dir, connection=_make_conn)
        backend.connect("personal")
        backend.connect("work")

        adapter = OpenAISessionAdapter(backend)
        pref_a = adapter.preflight_instance(ProviderInstanceSpec("openai", "personal", True, "subscription"))
        pref_b = adapter.preflight_instance(ProviderInstanceSpec("openai", "work", True, "subscription"))
        self.assertEqual(pref_a.readiness.value, "ready")
        self.assertEqual(pref_b.readiness.value, "ready")

        stop_event = threading.Event()
        coordinator = session_broker._SessionSlotCoordinator(stop_event)
        removed_relays: list[str] = []

        def fake_remove(cid: str):
            removed_relays.append(cid)

        tok_a = "tok-personal-" + "a" * 24
        tok_b = "tok-work-" + "b" * 24
        slot_a_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
        slot_b_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
        self.addCleanup(lambda: shutil.rmtree(slot_a_root, ignore_errors=True))
        self.addCleanup(lambda: shutil.rmtree(slot_b_root, ignore_errors=True))
        slot_a_cm = adapter.open_slot(
            pref_a, slot_index=0, slot_root=slot_a_root, port=8401,
            worker_token=tok_a, acknowledged_exposure_digest=None, on_revoke=coordinator.on_revoke,
        )
        slot_b_cm = adapter.open_slot(
            pref_b, slot_index=1, slot_root=slot_b_root, port=8402,
            worker_token=tok_b, acknowledged_exposure_digest=None, on_revoke=coordinator.on_revoke,
        )
        with patch.object(session_broker, "_remove_container_verified", side_effect=fake_remove):
            handle_a = slot_a_cm.__enter__()
            handle_b = slot_b_cm.__enter__()
            coordinator.register_slot(slot_a_cm, handle_a)
            coordinator.register_slot(slot_b_cm, handle_b)
            coordinator.record_container("1" * 64, slot_index=0)
            coordinator.record_container("2" * 64, slot_index=1)
            handle_a.job.activate()
            handle_b.job.activate()
            try:
                body = json.dumps({
                    "model": "gpt-6.2-sol", "stream": True, "store": False,
                    "input": [{"role": "user", "content": "hi"}],
                }).encode()
                req_a = (
                    f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
                    f"Authorization: Bearer {tok_a}\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode("ascii") + body

                # 1. Wrong Host header (8401 on slot B=8402) returns 403; cross-slot token A with Host 8402 returns 401.
                wrong_host = _send_via_relay(handle_b.job.provider_socket, handle_b.job.lease, handle_b.job.relay_proof, req_a)
                self.assertIn(b"403 Forbidden", wrong_host)
                req_a_on_b_host = (
                    f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8402\r\n"
                    f"Authorization: Bearer {tok_a}\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode("ascii") + body
                replay_resp = _send_via_relay(handle_b.job.provider_socket, handle_b.job.lease, handle_b.job.relay_proof, req_a_on_b_host)
                self.assertIn(b"401 Unauthorized", replay_resp)
                self.assertEqual(writes_by_dir, {})

                # 2. Both slots serve isolated turns; vault handle from slot A is rejected by slot B.
                resp_a = _send_via_relay(handle_a.job.provider_socket, handle_a.job.lease, handle_a.job.relay_proof, req_a)
                self.assertIn(b"response.completed", resp_a)
                marker = b'"encrypted_content":"oc_rs_'
                start = resp_a.index(marker) + len(b'"encrypted_content":"')
                handle_from_a = resp_a[start:resp_a.index(b'"', start)].decode("ascii")

                cross_vault_body = json.dumps({
                    "model": "gpt-6.2-sol", "stream": True, "store": False,
                    "input": [
                        {"type": "reasoning", "id": "rs_local_1", "summary": [], "encrypted_content": handle_from_a},
                        {"role": "user", "content": "continue"},
                    ],
                }).encode()
                req_cross = (
                    f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8402\r\n"
                    f"Authorization: Bearer {tok_b}\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(cross_vault_body)}\r\n\r\n"
                ).encode("ascii") + cross_vault_body
                resp_cross = _send_via_relay(handle_b.job.provider_socket, handle_b.job.lease, handle_b.job.relay_proof, req_cross)
                self.assertIn(b"400 Bad Request", resp_cross)

                # 3. select() refused while active leases exist.
                with self.assertRaises(RouteUnavailable):
                    backend.select("personal")

                # 4. Targeted disconnect("work") retires ONLY slot B while slot A keeps serving cleanly!
                backend.disconnect("work")
                deadline = time.monotonic() + 3.0
                while "2" * 64 not in removed_relays and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertIn("2" * 64, removed_relays)
                self.assertFalse(stop_event.is_set(), "disconnecting one slot must not stop the remaining slot")

                # 5. Even with active=None (work was active and disconnected), connect("third") MUST be refused
                #    while personal still holds an active lease!
                with self.assertRaises(RouteUnavailable):
                    backend.connect("third")

                # Slot A still serves turns cleanly after slot B was disconnected.
                resp_a2 = _send_via_relay(handle_a.job.provider_socket, handle_a.job.lease, handle_a.job.relay_proof, req_a)
                self.assertIn(b"response.completed", resp_a2)

                # 6. Disconnecting the final remaining slot sets stop_event and retires relay A.
                backend.disconnect("personal")
                self.assertTrue(stop_event.wait(3.0))
            finally:
                self.assertIsNone(coordinator.teardown_all(None))
        self.assertIn("1" * 64, removed_relays)

    def test_mini_mode_agent_args_and_launcher_flags_and_ports(self):
        from oc_openai import session_broker

        spec = self._valid_spec(instance="work")
        cfg_path = self.root / "opencode.json"
        cfg_path.write_text("{}", encoding="ascii")

        args_full = session_broker._build_agent_args(spec, cfg_path, ui_mode="full")
        args_mini = session_broker._build_agent_args(spec, cfg_path, ui_mode="mini")
        self.assertEqual(args_full[-1], spec["agent_image"])
        self.assertEqual(args_mini[-2:], [spec["agent_image"], "mini"])
        for env_flag in (
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "OPENCODE_CONFIG=/etc/opencode/opencode.json",
            "OPENCODE_CONFIG_PROJECT_DISABLE=true",
            "OPENCODE_DISABLE_MODELS_FETCH=true",
            "OPENCODE_DISABLE_FREE_MODELS=true",
            "OPENCODE_DISABLE_AUTOUPDATE=true",
            "OPENCODE_DISABLE_CLAUDE_CODE=true",
        ):
            self.assertIn(env_flag, args_full)
            self.assertIn(env_flag, args_mini)
        with self.assertRaises(ValueError):
            session_broker._build_agent_args(spec, cfg_path, ui_mode="invalid")

        # Reserved relay instance names rejected in _validate_spec; ports 8401..8416 forbidden.
        for bad_inst in ("relay", "relay-0", "relay-15"):
            bad_spec = self._valid_spec(instance=bad_inst)
            with self.assertRaises(ValueError):
                session_broker._validate_spec(bad_spec)
        for port in (8401, 8402, 8416):
            with self.assertRaisesRegex(RuntimeError, "forbidden port"):
                session_broker._parse_pod_port_bindings(
                    f"{port}/tcp", [{"HostIp": "127.0.0.1", "HostPort": str(port)}], allow_postgres=False,
                )

        # Launcher CLI validation for --mini, --no-mini, --provider KIND/LABEL, -i relay-0, and -P 8416.
        repo = Path(__file__).resolve().parents[1]
        script = repo / "oc-sandbox"
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root / "cli_home")}
        (self.root / "cli_home").mkdir(mode=0o700, exist_ok=True)
        for argv, expected in (
            (["--mini", "--no-mini"], "only be specified once"),
            (["--mini", "-n"], "cannot be combined"),
            (["--no-mini", "-d"], "cannot be combined"),
            (["--provider", "claude/personal"], "not yet qualified"),
            (["--provider", "openai/Bad_Label"], "invalid provider instance label"),
            (["-i", "relay-0", "-n"], "invalid instance name"),
            (["-P", "8416", "-n"], "refusing to publish pod port 8416"),
        ):
            res = subprocess.run(
                ["bash", str(script), *argv],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(res.returncode, 2, f"argv={argv} stderr={res.stderr}")
            self.assertIn(expected, res.stderr)

    def _make_real_profile_backend(self, state_dir: Path):
        from unittest.mock import patch
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.profile_backend import ProfileBackend
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        def _forbid_host_browser(url):
            raise AssertionError(f"unit test attempted to open host browser: {url}")

        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        shared_verifier = FixtureVerifier()

        def _make_conn(directory: Path):
            transport = FixtureTransport()
            transport.user = f"user-{directory.name}"
            browser = FixtureBrowser()
            browser.client = f"oaiapp_{directory.name}"
            return Connection(
                directory, transport=transport, verifier=shared_verifier,
                browser=browser, host_probe=lambda: host,
            )

        return ProfileBackend(state_dir, connection=_make_conn)

    def test_gate4_corrupt_or_world_writable_connection_state_aborts_default_launch(self):
        import pwd
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.catalog import plan_interactive_launch
        from oc_providers.contracts import ProviderIntegrityError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        backend = self._make_real_profile_backend(scratch / "corrupt_state_profiles")
        backend.connect("personal")
        backend.connect("work")

        view = backend.profiles.snapshot()
        work_profile = next(p for p in view.saved if p.label == "work")
        state_file = work_profile.directory / "state.json"
        original_bytes = state_file.read_bytes()

        adapter = OpenAISessionAdapter(backend)

        class _Term:
            def attended(self):
                return True
            def write(self, _text):
                pass
            def error(self, _text):
                pass
            def confirm(self, _prompt):
                return True
            def choose(self, _prompt, _options):
                return 0

        # 1. Corrupt JSON in one registration's state.json MUST abort the entire default launch.
        term = _Term()
        state_file.write_text("{corrupt-json", encoding="utf-8")
        with self.assertRaises(ProviderIntegrityError):
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="",
                cli_ui_mode="default", config=None, adapters={"openai": adapter}, terminal=term,
            )

        # 2. World-writable state.json (0o666) MUST also abort with ProviderIntegrityError.
        state_file.write_bytes(original_bytes)
        os.chmod(state_file, 0o666)
        try:
            with self.assertRaises(ProviderIntegrityError):
                plan_interactive_launch(
                    instance_name="default", cwd="construct", provider_filter="",
                    cli_ui_mode="default", config=None, adapters={"openai": adapter}, terminal=term,
                )
        finally:
            os.chmod(state_file, 0o600)

    def test_gate4_legacy_noncanonical_label_disconnect_unblocks_discovery(self):
        import pwd
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.contracts import ProviderIntegrityError

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        backend = self._make_real_profile_backend(scratch / "legacy_label_profiles")
        # Simulate a pre-existing legacy registration with uppercase + underscore (valid before I4d).
        backend.connect("legacy-seed")
        reg_state = backend._state / "profiles" / "state.json"
        data = json.loads(reg_state.read_text(encoding="utf-8"))
        data["registrations"]["Work_2"] = data["registrations"].pop("legacy-seed")
        data["active"] = "Work_2"
        reg_state.write_text(json.dumps(data), encoding="utf-8")
        reg_state.chmod(0o600)

        adapter = OpenAISessionAdapter(backend)

        with self.assertRaisesRegex(ProviderIntegrityError, "Work_2"):
            adapter.discover_instances()

        backend.disconnect("Work_2")
        backend.connect("work-2")
        discovered = adapter.discover_instances()
        self.assertEqual([spec.label for spec in discovered], ["work-2"])

    def test_gate4_real_profile_selection_disconnected_refuses_default_fallback(self):
        import pwd
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.catalog import LaunchRefusedError, plan_interactive_launch
        from oc_providers.config import LaunchDefaults, ProviderConfig
        from oc_providers.contracts import ProviderInstanceSpec, SelectionState

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        backend = self._make_real_profile_backend(scratch / "tri_state_profiles")
        adapter = OpenAISessionAdapter(backend)

        cfg = ProviderConfig(
            instances=(
                ProviderInstanceSpec("openai", "backup", True, "subscription"),
                ProviderInstanceSpec("openai", "personal", True, "subscription"),
            ),
            provider_defaults={"openai": "backup"},
            launch=LaunchDefaults(),
        )

        class _Term:
            def attended(self):
                return True
            def write(self, _text):
                pass
            def error(self, _text):
                pass
            def confirm(self, _prompt):
                return True
            def choose(self, _prompt, _options):
                return 0

        # Fresh empty registry is UNSET and resolves [provider_defaults].openai -> backup (which is disconnected).
        term = _Term()
        self.assertEqual(adapter.selection_state().state, SelectionState.UNSET)
        with self.assertRaises(LaunchRefusedError) as ctx_empty:
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="openai",
                cli_ui_mode="default", config=cfg, adapters={"openai": adapter}, terminal=term,
            )
        self.assertEqual(ctx_empty.exception.code, "provider_disconnected")
        self.assertIn("openai/backup", str(ctx_empty.exception))

        # Connect backup, then personal (active), then disconnect personal -> active=None => DISCONNECTED.
        backend.connect("backup")
        backend.connect("personal")
        backend.disconnect("personal")
        self.assertEqual(adapter.selection_state().state, SelectionState.DISCONNECTED)

        # Bare `--provider openai` MUST refuse instead of silently falling back to `backup`.
        with self.assertRaises(LaunchRefusedError) as ctx_disc:
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="openai",
                cli_ui_mode="default", config=cfg, adapters={"openai": adapter}, terminal=term,
            )
        self.assertEqual(ctx_disc.exception.code, "selection_disconnected")

    def test_gate4_coordinator_retains_lease_on_failed_relay_removal_and_handles_races(self):
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.connection import ConnectionError
        from oc_providers.contracts import SlotHandle

        class _FakeJob:
            def __init__(self, root: Path):
                self.root = root
                self.revoked = 0
                self.lease = None

            def revoke(self):
                self.revoked += 1

        class _FakeBroker:
            def __init__(self):
                self._revoked = threading.Event()
                self.closed = 0

            def close(self):
                self.closed += 1

        class _FakeCM:
            def __init__(self):
                self.exits = 0

            def __exit__(self, *_exc):
                self.exits += 1

        # 1. Failed relay removal MUST NOT call slot_cm.__exit__ (lease retained on disk) and MUST report error.
        stop_ev = threading.Event()
        coord = session_broker._SessionSlotCoordinator(stop_ev)
        cm = _FakeCM()
        job = _FakeJob(self.root / "slot0")
        broker = _FakeBroker()
        handle = SlotHandle(
            slot_index=0, scoped_id="openai--personal", provider_label="openai/personal",
            port=8401, job=job, broker=broker, lease=None, build_relay_args=lambda _s: ["create"],
        )
        coord.register_slot(cm, handle)
        self.assertTrue(coord.record_container("a" * 64, slot_index=0))
        with patch.object(session_broker, "_remove_container_verified", side_effect=RuntimeError("rm failed")):
            err = coord.teardown_all(None)
        self.assertIsNotNone(err)
        self.assertEqual(cm.exits, 0, "lease context manager exited despite unverified relay removal")
        self.assertEqual(job.revoked, 1)
        self.assertEqual(broker.closed, 1)

        # 2. Hung retirement thread MUST record a cleanup error in teardown_all instead of returning None.
        gate = threading.Event()
        stop_ev2 = threading.Event()
        coord2 = session_broker._SessionSlotCoordinator(stop_ev2)
        hung_thread = threading.Thread(target=gate.wait, args=(5.0,), name="oc-slot-retire-hung", daemon=True)
        hung_thread.start()
        coord2._retire_threads.append(hung_thread)
        orig_join = threading.Thread.join

        def _fast_join(thread_self, timeout=None):
            return orig_join(thread_self, timeout=0.02)

        try:
            with patch.object(threading.Thread, "join", _fast_join):
                err2 = coord2.teardown_all(None)
            self.assertIsNotNone(err2)
            self.assertIn("did not finish", str(err2))
        finally:
            gate.set()
            hung_thread.join(timeout=2.0)

        # 3. Pre-registration revocation + startup revocation race MUST prevent `podman start`.
        stop_ev3 = threading.Event()
        coord3 = session_broker._SessionSlotCoordinator(stop_ev3)
        coord3.on_revoke(0)  # Fired before register_slot!
        cm3 = _FakeCM()
        job3 = _FakeJob(self.root / "slot3")
        broker3 = _FakeBroker()
        handle3 = SlotHandle(
            slot_index=0, scoped_id="openai--personal", provider_label="openai/personal",
            port=8401, job=job3, broker=broker3, lease=None, build_relay_args=lambda _s: ["create", "relay"],
        )
        podman_calls: list[tuple] = []

        def fake_podman(*args, **_kwargs):
            podman_calls.append(args)
            if args[0] == "create":
                return subprocess.CompletedProcess(args, 0, ("b" * 64 + "\n").encode(), b"")
            return subprocess.CompletedProcess(args, 0, b"", b"")

        spec3 = self._valid_spec()
        with patch.object(session_broker, "podman", side_effect=fake_podman):
            coord3.register_slot(cm3, handle3)
            with self.assertRaisesRegex(ConnectionError, "connection_retired"):
                session_broker._start_and_verify_slot_relay(
                    spec3, "c" * 64, handle3, coord3, [], [], stop_ev3,
                )
        self.assertFalse(
            any(call[0] == "start" for call in podman_calls),
            f"podman start was called for a revoked slot: {podman_calls}",
        )
        with patch.object(session_broker, "_remove_container_verified"):
            coord3.teardown_all(None)

    def test_gate4_partial_startup_rollback_and_sibling_relay_mcs_collision(self):
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.cli import StreamTerminal
        from oc_providers.catalog import ResolvedLaunchPlan
        from oc_providers.contracts import (
            InstancePreflight,
            ProviderInstanceSpec,
            ReadinessState,
            SlotHandle,
        )

        spec = self._valid_spec()
        pod_id = "1" * 64
        relay0_id = "2" * 64
        relay1_id = "3" * 64

        # 1. Sibling relay MCS collision between slot 0 and slot 1 MUST raise RuntimeError.
        mcs_dir = self.root / "mcs_slot1"
        mcs_dir.mkdir(mode=0o700)
        job1 = session_broker._SessionJob(mcs_dir, "inc_" + "e" * 32)
        job1.prepare(config_payload=None)
        self.addCleanup(job1.revoke)
        shared_label = "system_u:system_r:container_t:s0:c30,c40"
        mount_label = "system_u:object_r:container_file_t:s0:c30,c40"

        def fake_inspected(*args):
            if args[:2] == ("container", "inspect") and args[2] == relay1_id:
                return {
                    "Id": relay1_id,
                    "Pod": pod_id,
                    "Image": spec["relay_image"],
                    "ProcessLabel": shared_label,
                    "MountLabel": mount_label,
                    "EffectiveCaps": [],
                    "Config": {"User": "0:0"},
                    "HostConfig": {
                        "ReadonlyRootfs": True, "Privileged": False,
                        "IpcMode": "private", "PidMode": "private", "CgroupMode": "private",
                        "SecurityOpt": ["no-new-privileges"],
                    },
                    "Mounts": [
                        {"Destination": "/source", "Type": "bind", "Source": str(job1.source_dir),
                         "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["ro", "Z", "nosuid", "nodev", "noexec"]},
                        {"Destination": "/provider", "Type": "bind", "Source": str(job1.provider_socket.parent),
                         "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["ro", "Z", "nosuid", "nodev", "noexec"]},
                        {"Destination": "/grant", "Type": "bind", "Source": str(job1.grant),
                         "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["ro", "Z", "nosuid", "nodev", "noexec"]},
                        {"Destination": "/proof", "Type": "bind", "Source": str(job1.proof_file.parent),
                         "RW": False, "Mode": "Z", "Propagation": "rprivate", "Options": ["ro", "Z", "nosuid", "nodev", "noexec"]},
                    ],
                }
            raise AssertionError(f"unexpected inspected: {args}")

        def fake_podman_mcs(*args, **_kwargs):
            if args[:2] == ("exec", relay1_id) and args[2] == "cat":
                return subprocess.CompletedProcess(args, 0, shared_label.encode() + b"\0", b"")
            if args[:2] == ("container", "inspect") and args[2] == relay0_id:
                return subprocess.CompletedProcess(
                    args, 0, json.dumps([{"ProcessLabel": shared_label}]).encode(), b"",
                )
            return subprocess.CompletedProcess(args, 0, b"", b"")

        with (
            patch.object(session_broker, "inspected", side_effect=fake_inspected),
            patch.object(session_broker, "podman", side_effect=fake_podman_mcs),
            patch.object(session_broker, "host_output", return_value=mount_label.encode() + b"\0"),
        ):
            with self.assertRaisesRegex(RuntimeError, "collided with sibling container"):
                session_broker._verify_relay_isolation(
                    relay1_id, spec["relay_image"], pod_id, spec["level"], job1, [relay0_id],
                )

        # 2. Partial startup rollback: slot 0 succeeds, slot 1 fails -> relay 0 verified-removed & slot 0 exited.
        slot0_exits = []
        removed = []

        class _RollbackAdapter:
            def provider_config_entry(self, preflight, *, port, worker_token, display_label=None):
                return session_broker.build_openai_provider_entry(
                    label=display_label or preflight.spec.label,
                    port=port,
                    worker_token=worker_token,
                    models=preflight.models,
                )

            @contextlib.contextmanager
            def open_slot(self, preflight, *, slot_index, slot_root, port, worker_token, acknowledged_exposure_digest, on_revoke):
                if slot_index == 1:
                    raise RuntimeError("slot 1 boom")

                class _MiniJob:
                    def __init__(self, r):
                        self.root = r
                        self.lease = None
                    def revoke(self):
                        pass

                class _MiniBroker:
                    def __init__(self):
                        self._revoked = threading.Event()
                    def close(self):
                        pass

                try:
                    yield SlotHandle(
                        slot_index=slot_index, scoped_id=preflight.spec.scoped_id,
                        provider_label=preflight.spec.qualified_name, port=port,
                        job=_MiniJob(slot_root), broker=_MiniBroker(), lease=None,
                        build_relay_args=lambda _s: ["create"],
                    )
                finally:
                    slot0_exits.append(slot_index)

        p0 = InstancePreflight(ProviderInstanceSpec("openai", "personal", True, "subscription"), ReadinessState.READY, ("gpt-6.2-sol",))
        p1 = InstancePreflight(ProviderInstanceSpec("openai", "work", True, "subscription"), ReadinessState.READY, ("gpt-6.2-sol",))
        plan = ResolvedLaunchPlan(
            admitted=(p0, p1), excluded=(), initial_provider_id="openai--personal",
            initial_model="gpt-6.2-sol", ui_mode="full", ui_source="default",
            acknowledged_digests={},
        )
        import io
        term = StreamTerminal(io.StringIO(), io.StringIO(), io.StringIO())
        cleanup_state = {"clean": False}
        rb_root = self.root / "rb_root"
        rb_root.mkdir(mode=0o700)

        def fake_start_slot(spec_arg, pod_arg, handle, coordinator, siblings, started, stop_ev):
            coordinator.record_container(relay0_id, slot_index=handle.slot_index)
            return relay0_id

        rb_adapter = _RollbackAdapter()
        rb_stop = threading.Event()
        with (
            patch.object(session_broker, "SHARED_TMP", str(self.root)),
            patch.object(session_broker, "_verify_pod_with_containers", return_value=(pod_id, [])),
            patch.object(session_broker, "_ensure_containers_idle"),
            patch.object(session_broker, "_start_and_verify_slot_relay", side_effect=fake_start_slot),
            patch.object(session_broker, "_remove_container_verified", side_effect=lambda cid: removed.append(cid)),
        ):
            with self.assertRaisesRegex(RuntimeError, "slot 1 boom"):
                session_broker._run_multi_slot_session(
                    spec, plan, {"openai": rb_adapter}, rb_root,
                    rb_stop, term, cleanup_state,
                )
        self.assertEqual(removed, [relay0_id])
        self.assertEqual(slot0_exits, [0])
        self.assertTrue(cleanup_state["clean"])

    def test_gate4_launcher_mini_managed_mode_symlink_config_and_pod_relays(self):
        repo = Path(__file__).resolve().parents[1]
        script = repo / "oc-sandbox"
        stub_dir = self.root / "stubs"
        stub_dir.mkdir(mode=0o700)
        podman_log = self.root / "podman.log"

        # Build safe stubbed podman + systemctl + editor binaries inside scratch tmp.
        fake_editor = stub_dir / "fake-editor"
        fake_editor.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_editor.chmod(0o755)

        fake_systemctl = stub_dir / "systemctl"
        fake_systemctl.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_systemctl.chmod(0o755)

        fake_podman = stub_dir / "podman"
        fake_podman.write_text(
            f"""#!/usr/bin/bash
echo "podman $*" >> "{podman_log}"
case "$1 $2" in
  "--version "*) echo "podman version 5.0.0"; exit 0 ;;
  "image inspect")
    if [[ "$*" == *"oc.hash"* ]]; then echo ""; exit 1; fi
    echo "{('d' * 64)}"; exit 0 ;;
  "build "*) exit 0 ;;
  "volume exists") exit 0 ;;
  "pod exists")
    if [[ -n "${{STUB_POD_EXISTS_RC:-}}" ]]; then exit "$STUB_POD_EXISTS_RC"; fi
    if [[ -n "${{STUB_POD_PRESENT:-}}" && "$3" == "oc" ]]; then exit 0; fi
    exit 1 ;;
  "pod inspect")
    if [[ "$*" == *"oc.ports"* ]]; then echo ""; exit 0; fi
    if [[ "$*" == *"PortBindings"* ]]; then echo "{{}}"; exit 0; fi
    if [[ "$*" == *"oc.podcfg"* ]]; then echo "v1|"; exit 0; fi
    if [[ "$*" == *".Containers"* ]]; then printf '%b' "${{STUB_POD_CONTAINERS:-}}"; exit 0; fi
    exit 0 ;;
  "pod create"|"pod rm"|"pod ls") exit 0 ;;
  "volume ls"|"secret ls") exit 0 ;;
  "container exists")
    target="${{@: -1}}"
    if [[ -n "${{STUB_RUNNING_RELAY:-}}" && "$target" == "$STUB_RUNNING_RELAY" ]]; then exit 0; fi
    exit 1 ;;
  "container inspect")
    target="${{@: -1}}"
    if [[ "$*" == *"oc.role"* && "$*" != *"{{{{.Id}}}}"* ]]; then
      if [[ "$target" == *-relay-* ]]; then echo "provider-relay"; exit 0; fi
      echo ""; exit 0
    fi
    if [[ "$*" == *"{{{{.Id}}}}"* ]]; then
      if [[ -n "${{STUB_RUNNING_RELAY:-}}" && "$target" == "$STUB_RUNNING_RELAY" ]]; then
        echo "{('f' * 64)} running 1 default provider-relay"; exit 0
      fi
      exit 1
    fi
    if [[ "$*" == *".State.Status"* ]]; then
      if [[ -n "${{STUB_RUNNING_RELAY:-}}" && "$target" == "$STUB_RUNNING_RELAY" ]]; then echo "running"; exit 0; fi
      if [[ "$target" == "oc-chromium" ]]; then echo "running"; exit 0; fi
      exit 1
    fi
    if [[ "$*" == *".Image"* && "$target" == "oc-chromium" ]]; then echo "{('d' * 64)}"; exit 0; fi
    exit 1 ;;
  "exec oc-chromium") exit 0 ;;
  "run "*) exit 0 ;;
  "create "*) echo "{('e' * 64)}"; exit 0 ;;
  *) exit 0 ;;
esac
""",
            encoding="utf-8",
        )
        fake_podman.chmod(0o755)

        def _prepare_home(name: str) -> tuple[Path, dict]:
            h = self.root / name
            h.mkdir(mode=0o700)
            (h / ".oh-my-zsh" / "custom" / "plugins" / "zsh-vi-mode").mkdir(parents=True, mode=0o700)
            state_dir = h / ".local" / "share" / "oc-sandbox"
            pol_dir = state_dir / "policy"
            pol_dir.mkdir(parents=True, mode=0o700)
            # Pre-seed policy installed digest so pkexec/sudo is never invoked.
            cil_text = script.read_text(encoding="utf-8")
            start = cil_text.index("; SELinux type for the sandboxed Chromium container only")
            end = cil_text.index("\nPOL\n", start)
            import hashlib
            pol_hash = hashlib.sha256((cil_text[start:end] + "\n").encode("utf-8")).hexdigest()[:16]
            (pol_dir / "installed").write_text(pol_hash + "\n", encoding="utf-8")
            env = {
                "PATH": f"{stub_dir}:/usr/bin:/bin",
                "HOME": str(h),
                "OC_CHROMIUM_MODE": "headless",
                "OC_CODE_BIN": str(fake_editor),
                "OC_BCOMPARE_BIN": str(fake_editor),
                "OPENAI_API_KEY": "sk-test-never-forward",
            }
            return h, env

        # 1. Bare `--mini` with zero provider config/state MUST enter managed mode (no updater, no ambient API key).
        podman_log.write_text("", encoding="utf-8")
        _, env1 = _prepare_home("mini_clean_home")
        res1 = subprocess.run(
            ["bash", str(script), "--mini"],
            env=env1, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res1.returncode, 2, res1.stderr)
        self.assertIn("attended foreground workstation terminal", res1.stderr)
        log1 = podman_log.read_text(encoding="utf-8")
        self.assertNotIn("OPENAI_API_KEY", log1)
        self.assertNotIn("oc-opencode-update", log1)
        self.assertIn("oc-openai-relay", log1)

        # 2. Symlinked $HOME/.config/oc-sandbox pointing outside $SB MUST enter managed mode (never silent legacy fallback).
        podman_log.write_text("", encoding="utf-8")
        h2, env2 = _prepare_home("symlink_cfg_home")
        target_empty = self.root / "empty_target_cfg"
        target_empty.mkdir(mode=0o700)
        (h2 / ".config").mkdir(mode=0o700)
        (h2 / ".config" / "oc-sandbox").symlink_to(target_empty)
        res2 = subprocess.run(
            ["bash", str(script)],
            env=env2, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res2.returncode, 2, res2.stderr)
        self.assertIn("attended foreground workstation terminal", res2.stderr)

        # 3. pod_relays / any_relay_running: running `oc-relay-0` blocks `-r -n`, and exact `pod inspect` is used.
        podman_log.write_text("", encoding="utf-8")
        _, env3 = _prepare_home("relay_busy_home")
        env3["OC_OPENCODE_VERSION"] = "keep"
        env3["STUB_POD_PRESENT"] = "1"
        env3["STUB_POD_CONTAINERS"] = "oc-chromium\\noc-relay-0\\n"
        env3["STUB_RUNNING_RELAY"] = "oc-relay-0"
        res3 = subprocess.run(
            ["bash", str(script), "-r", "-n"],
            env=env3, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(res3.returncode, 1, res3.stderr)
        self.assertIn("Provider relay is running in instance 'default'", res3.stderr)
        log3 = podman_log.read_text(encoding="utf-8")
        self.assertNotIn("ps -a --filter pod=", log3)
        self.assertIn("pod inspect oc --format {{range .Containers}}", log3)

        # 4. pod_relays fail-closed: when `podman pod exists oc` fails (rc=125), any_relay_running blocks `-r -n`.
        _, env4 = _prepare_home("relay_err_home")
        # Check pod_relays directly via a subshell sourcing just the helper behavior.
        check_rc = subprocess.run(
            [
                "bash", "-c",
                r'eval "$(sed -n "/^cstate()/,/^remove_stale_relays()/p" "$1" | sed "\$d")"; '
                'pm() { podman "$@"; }; '
                'any_relay_running oc',
                "_", str(script),
            ],
            env={**env4, "STUB_POD_EXISTS_RC": "125"},
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(check_rc.returncode, 0, "any_relay_running must fail closed (return 0) on pod exists error")

    def test_gate4_r2_swapped_credential_client_id_refused_with_zero_provider_calls(self):
        import pwd
        from unittest.mock import patch
        from oc_openai.cli import RouteUnavailable
        from oc_openai.connection import Connection, ConnectionError, PhysicalHost
        from oc_openai.profile_backend import ProfileBackend
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.contracts import ProviderInstanceSpec, ProviderIntegrityError
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier

        def _forbid_host_browser(url):
            raise AssertionError(f"unit test attempted to open host browser: {url}")

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        self.enterContext(patch("oc_openai.connection._open_host_browser", side_effect=_forbid_host_browser))

        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        shared_verifier = FixtureVerifier()
        provider_calls: list[str] = []

        def _make_conn(directory: Path):
            transport = FixtureTransport()
            transport.user = f"user-{directory.name}"
            browser = FixtureBrowser()
            browser.client = f"oaiapp_{directory.name}"
            orig_json = transport.json

            def counting_json(*args, **kwargs):
                provider_calls.append(f"json:{args[:2]}")
                return orig_json(*args, **kwargs)

            transport.json = counting_json
            return Connection(
                directory, transport=transport, verifier=shared_verifier,
                browser=browser, host_probe=lambda: host,
            )

        backend = ProfileBackend(scratch / "swapped_cred_profiles", connection=_make_conn)
        backend.connect("personal")
        backend.connect("work")

        # Grab valid personal binding BEFORE swap to test mid-session swap rejection too.
        _prof_before, conn_before, valid_personal_binding = backend.profile_connection("personal")
        provider_calls.clear()

        # Copy work's valid credential state.json into personal's store (client_id mismatch!).
        view = backend.profiles.snapshot()
        personal_prof = next(p for p in view.saved if p.label == "personal")
        work_prof = next(p for p in view.saved if p.label == "work")
        (personal_prof.directory / "state.json").write_bytes((work_prof.directory / "state.json").read_bytes())
        (personal_prof.directory / "state.json").chmod(0o600)

        adapter = OpenAISessionAdapter(backend)
        personal_spec = ProviderInstanceSpec("openai", "personal", True, "subscription")
        with self.assertRaises(ProviderIntegrityError):
            adapter.preflight_instance(personal_spec)
        self.assertEqual(provider_calls, [], "mismatched client_id must trigger zero provider calls")

        with self.assertRaises(RouteUnavailable):
            backend.select("personal")
        with self.assertRaises(ConnectionError):
            conn_before.require_active(valid_personal_binding)
        with self.assertRaises(ConnectionError):
            conn_before.models(valid_personal_binding)
        self.assertEqual(provider_calls, [], "mid-session client_id swap must trigger zero provider calls")

    def test_gate4_r2_bare_launch_checks_account_home_and_fails_closed_on_inspect_error(self):
        repo = Path(__file__).resolve().parents[1]
        script = repo / "oc-sandbox"
        src = script.read_text(encoding="utf-8")

        # Extract detect_managed_mode from oc-sandbox and test with synthetic account_home vs alternate HOME.
        self.assertIn("detect_managed_mode()", src)
        start = src.index("detect_managed_mode()")
        end = src.index("\nMANAGED_MODE=0", start)
        fn_src = src[start:end]

        acct_home = self.root / "acct_home"
        alt_home = self.root / "empty_alt_home"
        acct_cfg = acct_home / ".config" / "oc-sandbox"
        acct_cfg.mkdir(parents=True, mode=0o700)
        alt_home.mkdir(mode=0o700)
        (acct_cfg / "providers.toml").write_text("[launch]\nmini = true\n", encoding="utf-8")
        (acct_cfg / "providers.toml").chmod(0o600)

        # Wrap python3 in stub PATH to override pwd.getpwuid to return synthetic acct_home (without touching real $HOME).
        py_stub_dir = self.root / "py_stub"
        py_stub_dir.mkdir(mode=0o700)
        py_wrapper = py_stub_dir / "python3"
        py_wrapper.write_text(
            "#!/usr/bin/python3 -I\n"
            "import os, pwd, sys, types\n"
            "fake_dir = os.environ['SYNTHETIC_ACCT_HOME']\n"
            "orig_getpwuid = pwd.getpwuid\n"
            "def _patched(uid):\n"
            "    entry = orig_getpwuid(uid)\n"
            "    return types.SimpleNamespace(pw_dir=fake_dir, pw_uid=entry.pw_uid)\n"
            "pwd.getpwuid = _patched\n"
            "code = sys.stdin.read()\n"
            "sys.argv = ['-', sys.argv[-1]]\n"
            "exec(compile(code, '<detect_managed_mode>', 'exec'), {'__name__': '__main__'})\n",
            encoding="utf-8",
        )
        py_wrapper.chmod(0o755)
        patched_fn = fn_src.replace("/usr/bin/python3 -I -", f"{py_wrapper} -")

        def _run_detect(caller_home: Path, synthetic_acct: Path) -> subprocess.CompletedProcess:
            cmd = f"set -euo pipefail\ndie() {{ echo \"$*\" >&2; exit 2; }}\nPROVIDER_SET=0 UI_MODE_SET=0\n{patched_fn}\nif detect_managed_mode; then echo MANAGED; else echo LEGACY; fi\n"
            return subprocess.run(
                ["bash", "-c", cmd],
                env={"PATH": "/usr/bin:/bin", "HOME": str(caller_home), "SYNTHETIC_ACCT_HOME": str(synthetic_acct)},
                capture_output=True, text=True, timeout=10,
            )

        # 1. Alternate empty HOME while account_home has [launch].mini = true MUST select MANAGED!
        r_mismatch = _run_detect(alt_home, acct_home)
        self.assertEqual(r_mismatch.returncode, 0, r_mismatch.stderr)
        self.assertEqual(r_mismatch.stdout.strip(), "MANAGED")

        # 2. Confirmed absence in BOTH account_home and caller HOME selects LEGACY.
        clean_acct = self.root / "clean_acct_home"
        clean_acct.mkdir(mode=0o700)
        r_clean = _run_detect(alt_home, clean_acct)
        self.assertEqual(r_clean.returncode, 0, r_clean.stderr)
        self.assertEqual(r_clean.stdout.strip(), "LEGACY")

        # 3. Unreadable account_home/.config (EACCES) MUST fail closed (die rc=2), NOT fall back to LEGACY!
        locked_acct = self.root / "locked_acct_home"
        locked_cfg = locked_acct / ".config"
        locked_cfg.mkdir(parents=True, mode=0o700)
        os.chmod(locked_cfg, 0o000)
        try:
            r_err = _run_detect(alt_home, locked_acct)
            self.assertEqual(r_err.returncode, 2, r_err.stdout + r_err.stderr)
            self.assertIn("cannot verify provider configuration state", r_err.stderr)
        finally:
            os.chmod(locked_cfg, 0o700)

    def test_gate4_r2_unconfirmed_relay_removal_retains_durable_lease_after_gc(self):
        import gc
        import pwd
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.contracts import ProviderInstanceSpec

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        backend = self._make_real_profile_backend(scratch / "durable_lease_profiles")
        backend.connect("personal")
        view = backend.profiles.snapshot()
        personal_dir = next(p.directory for p in view.saved if p.label == "personal")
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")

        def _run_failed_teardown_in_inner_scope() -> Path:
            adapter = OpenAISessionAdapter(backend)
            pref = adapter.preflight_instance(ProviderInstanceSpec("openai", "personal", True, "subscription"))
            stop_ev = threading.Event()
            coord = session_broker._SessionSlotCoordinator(stop_ev)
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            slot_cm = adapter.open_slot(
                pref, slot_index=0, slot_root=slot_root, port=8401,
                worker_token="tok-durable-" + "a" * 24,
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root)
            coord.record_container("a" * 64, slot_index=0)
            handle.job.activate()
            with patch.object(session_broker, "_remove_container_verified", side_effect=RuntimeError("rm failed")):
                err = coord.teardown_all(None)
            self.assertIsNotNone(err)
            return slot_root

        retained_root = _run_failed_teardown_in_inner_scope()
        # Force generator GC finalization after launcher scope has exited!
        gc.collect()
        gc.collect()

        fresh_conn = Connection(personal_dir, host_probe=lambda: host)
        self.assertTrue(
            fresh_conn.has_active_leases(),
            "generator finalization erased durable worker_leases despite unconfirmed relay removal!",
        )
        state_data = json.loads((personal_dir / "state.json").read_text(encoding="utf-8"))
        self.assertIn(retained_root.name, state_data.get("worker_leases", {}))

    def test_gate4_r2_exposure_hold_mutation_permanently_retires_slot_even_after_settle(self):
        import pwd
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.exposure import binding_digest
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.contracts import ProviderInstanceSpec

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        backend = self._make_real_profile_backend(scratch / "exposure_retire_profiles")
        backend.connect("personal")
        adapter = OpenAISessionAdapter(backend)
        pref = adapter.preflight_instance(ProviderInstanceSpec("openai", "personal", True, "subscription"))

        # 1. Live coordinator slot: adding a synthetic exposure hold MUST retire lease, broker, and relay
        #    via the watcher, and settling the hold afterwards MUST NOT revive the retired grant.
        stop_ev = threading.Event()
        coord = session_broker._SessionSlotCoordinator(stop_ev)
        removed: list[str] = []
        slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
        self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
        slot_cm = adapter.open_slot(
            pref, slot_index=0, slot_root=slot_root, port=8401,
            worker_token="tok-exp-" + "a" * 24,
            acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
        )
        e2e_path = backend._state / "canary-e2e.json"
        hold_payload = json.dumps({
            "run_id": "a" * 32, "binding": binding_digest("a" * 43, "b" * 43), "model": "gpt-6.2-sol",
            "history_digest": "0" * 64, "max_input": 922_000, "max_output": 128_000,
            "actual": None, "outcome": "unsettled", "delivered": False,
        })
        with patch.object(session_broker, "_remove_container_verified", side_effect=lambda cid: removed.append(cid)):
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root)
            coord.record_container("f" * 64, slot_index=0)
            handle.job.activate()
            try:
                e2e_path.write_text(hold_payload, encoding="ascii")
                e2e_path.chmod(0o600)
                self.assertTrue(stop_ev.wait(3.0), "watcher did not retire slot after exposure hold mutation")
                deadline = time.monotonic() + 3.0
                while "f" * 64 not in removed and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertIn("f" * 64, removed)
                self.assertEqual(handle.job.lease.status(), "terminal")
                self.assertTrue(handle.broker._revoked.is_set())

                # Settle the hold: the retired grant and broker MUST remain permanently unusable!
                e2e_path.unlink()
                self.assertEqual(handle.job.lease.status(), "terminal")
                self.assertTrue(handle.broker._revoked.is_set())
            finally:
                self.assertIsNone(coord.teardown_all(None))

        # 2. Standalone broker: exposure refusal permanently fences the broker even after hold settlement.
        writes: list[str] = []

        def make_events(_body):
            writes.append("write")
            yield {"type": "response.created", "response": {"id": "resp_e", "status": "in_progress"}}
            yield {"type": "response.completed", "response": {"id": "resp_e", "status": "completed", "output": []}}

        exp_dir = self.root / "standalone_exp"
        exp_dir.mkdir(mode=0o700)
        sock_e = self.root / "provider_exp_perm.sock"
        broker = SessionBroker(
            socket_path=sock_e, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(make_events), binding=object(), models=("gpt-6.2-sol",),
            profile_label="personal", usage_dir=exp_dir, policy=SessionPolicy(exposure_dir=exp_dir),
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

        ok_resp = _send_via_relay(sock_e, self.lease, self.proof, req)
        self.assertIn(b"response.completed", ok_resp)
        self.assertEqual(len(writes), 1)

        hold_file = exp_dir / "canary-e2e.json"
        hold_file.write_text(hold_payload, encoding="ascii")
        hold_file.chmod(0o600)
        blocked_resp = _send_via_relay(sock_e, self.lease, self.proof, req)
        self.assertIn(b"403 Forbidden", blocked_resp)
        self.assertEqual(len(writes), 1)

        # Settle hold: broker MUST stay permanently revoked with 0 additional upstream writes!
        hold_file.unlink()
        after_settle = _send_via_relay(sock_e, self.lease, self.proof, req)
        self.assertIn(b"403 Forbidden", after_settle)
        self.assertEqual(len(writes), 1)

    def test_gate4_r2_relay_guard_blocks_paused_restarting_inspect_error_and_removes_by_id(self):
        repo = Path(__file__).resolve().parents[1]
        script = repo / "oc-sandbox"
        stub_dir = self.root / "relay_guard_stubs"
        stub_dir.mkdir(mode=0o700)
        rm_log = self.root / "relay_rm.log"
        relay_cid = "a" * 64

        fake_podman = stub_dir / "podman"
        fake_podman.write_text(
            f"""#!/usr/bin/bash
case "$1 $2" in
  "pod exists") exit 0 ;;
  "pod inspect") printf 'oc-relay-0\\n'; exit 0 ;;
  "container exists")
    if [[ "${{3:-}}" == "oc-relay-0" ]]; then exit 0; fi
    exit 1 ;;
  "container inspect")
    if [[ "$*" == *"oc.role"* && "$*" != *".Id"* ]]; then
      echo "provider-relay"; exit 0
    fi
    if [[ "${{STUB_INSPECT_FAIL:-}}" == "1" ]]; then exit 125; fi
    echo "{relay_cid} ${{STUB_RELAY_STATE:-exited}} 1 ${{STUB_RELAY_INST:-default}} provider-relay"; exit 0 ;;
  "rm "*)
    echo "rm $*" >> "{rm_log}"; exit 0 ;;
  *) exit 0 ;;
esac
""",
            encoding="utf-8",
        )
        fake_podman.chmod(0o755)

        def _run_helper(fn_call: str, **extra_env) -> subprocess.CompletedProcess:
            return subprocess.run(
                [
                    "bash", "-c",
                    r'eval "$(sed -n "/^cstate()/,/^# The helper holds/p" "$1" | sed "\$d")"; '
                    'ILABEL=default; pm() { podman "$@"; }; '
                    + fn_call,
                    "_", str(script),
                ],
                env={"PATH": f"{stub_dir}:/usr/bin:/bin", **extra_env},
                capture_output=True, text=True, timeout=10,
            )

        # 1. paused, restarting, and inspect error 125 MUST all report busy (return 0) from any_relay_running.
        for label, extra in (
            ("paused", {"STUB_RELAY_STATE": "paused"}),
            ("restarting", {"STUB_RELAY_STATE": "restarting"}),
            ("inspect_125", {"STUB_INSPECT_FAIL": "1"}),
        ):
            res = _run_helper("any_relay_running oc", **extra)
            self.assertEqual(res.returncode, 0, f"{label} was treated as idle!")

        # 2. Positively stopped owned relay -> idle (rc=1) and remove_stale_relays removes by verified 64-hex ID!
        rm_log.write_text("", encoding="utf-8")
        res_idle = _run_helper("any_relay_running oc", STUB_RELAY_STATE="exited")
        self.assertEqual(res_idle.returncode, 1)
        res_rm = _run_helper("remove_stale_relays oc", STUB_RELAY_STATE="exited")
        self.assertEqual(res_rm.returncode, 0, res_rm.stderr)
        rm_lines = rm_log.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(rm_lines, [f"rm rm -- {relay_cid}"])

        # 3. Foreign stopped relay (oc.instance=other) MUST be refused without removing it!
        rm_log.write_text("", encoding="utf-8")
        res_foreign = _run_helper("remove_stale_relays oc", STUB_RELAY_STATE="exited", STUB_RELAY_INST="other")
        self.assertNotEqual(res_foreign.returncode, 0)
        self.assertEqual(rm_log.read_text(encoding="utf-8"), "")

    def test_gate4_r3_settling_acknowledged_hold_retires_old_grant(self):
        import pwd
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.exposure import ExposureError, ExposureLedger, binding_digest
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.contracts import ProviderInstanceSpec

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        backend = self._make_real_profile_backend(scratch / "ack_settle_profiles")
        backend.connect("personal")

        hold_payload = json.dumps({
            "run_id": "a" * 32, "binding": binding_digest("a" * 43, "b" * 43), "model": "gpt-6.2-sol",
            "history_digest": "0" * 64, "max_input": 922_000, "max_output": 128_000,
            "actual": None, "outcome": "unsettled", "delivered": False,
        })
        e2e_path = backend._state / "canary-e2e.json"
        e2e_path.write_text(hold_payload, encoding="ascii")
        e2e_path.chmod(0o600)
        ack_hold = ExposureLedger(backend._state).inspect_hold()
        self.assertTrue(ack_hold.blocked)

        # 1. Live coordinator slot with acknowledged hold stays healthy while hold is unchanged,
        #    then retires immediately once the acknowledged hold is settled.
        adapter = OpenAISessionAdapter(backend)
        pref = adapter.preflight_instance(ProviderInstanceSpec("openai", "personal", True, "subscription"))
        stop_ev = threading.Event()
        coord = session_broker._SessionSlotCoordinator(stop_ev)
        removed: list[str] = []
        slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
        self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
        slot_cm = adapter.open_slot(
            pref, slot_index=0, slot_root=slot_root, port=8401,
            worker_token="tok-ack-" + "a" * 24,
            acknowledged_exposure_digest=ack_hold.digest, on_revoke=coord.on_revoke,
        )
        with patch.object(session_broker, "_remove_container_verified", side_effect=lambda cid: removed.append(cid)):
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root)
            coord.record_container("e" * 64, slot_index=0)
            handle.job.activate()
            try:
                time.sleep(0.25)
                self.assertFalse(stop_ev.is_set(), "unchanged acknowledged hold should stay active")
                # Settle the acknowledged hold -> watcher MUST retire the old grant!
                e2e_path.unlink()
                self.assertTrue(stop_ev.wait(3.0), "settling an acknowledged hold must retire the slot")
                deadline = time.monotonic() + 3.0
                while "e" * 64 not in removed and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertIn("e" * 64, removed)
                self.assertEqual(handle.job.lease.status(), "terminal")
                self.assertTrue(handle.broker._revoked.is_set())
            finally:
                self.assertIsNone(coord.teardown_all(None))

        # 2. First-write dispatch_fence and standalone broker also refuse after acknowledged hold settles.
        exp_dir = self.root / "ack_settle_standalone"
        exp_dir.mkdir(mode=0o700)
        hold_file = exp_dir / "canary-e2e.json"
        hold_file.write_text(hold_payload, encoding="ascii")
        hold_file.chmod(0o600)
        ledger = ExposureLedger(exp_dir)
        hold2 = ledger.inspect_hold()
        writes: list[str] = []

        def make_events(_body):
            writes.append("write")
            yield {"type": "response.created", "response": {"id": "resp_ack", "status": "in_progress"}}
            yield {"type": "response.completed", "response": {"id": "resp_ack", "status": "completed", "output": []}}

        sock_ack = self.root / "provider_ack_settle.sock"
        broker = SessionBroker(
            socket_path=sock_ack, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(make_events), binding=object(), models=("gpt-6.2-sol",),
            profile_label="personal", usage_dir=exp_dir,
            policy=SessionPolicy(exposure_dir=exp_dir, acknowledged_exposure_digest=hold2.digest),
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

        ok_resp = _send_via_relay(sock_ack, self.lease, self.proof, req)
        self.assertIn(b"response.completed", ok_resp)
        self.assertEqual(len(writes), 1)

        hold_file.unlink()
        with self.assertRaises(ExposureError) as exp_ctx:
            with ledger.dispatch_fence(acknowledged_digest=hold2.digest):
                pass
        self.assertEqual(exp_ctx.exception.args[0], "exposure_hold_changed")
        after_settle = _send_via_relay(sock_ack, self.lease, self.proof, req)
        self.assertIn(b"403 Forbidden", after_settle)
        self.assertEqual(len(writes), 1)

    def test_gate4_r3_ordinary_exposure_lock_contention_does_not_retire_healthy_slot(self):
        from oc_openai.exposure import ExposureError, ExposureLedger

        exp_dir = self.root / "lock_contention_exp"
        exp_dir.mkdir(mode=0o700)
        ledger = ExposureLedger(exp_dir)
        writes: list[str] = []

        def make_events(_body):
            writes.append("write")
            yield {"type": "response.created", "response": {"id": "resp_busy", "status": "in_progress"}}
            yield {"type": "response.completed", "response": {"id": "resp_busy", "status": "completed", "output": []}}

        revoked_cb: list[str] = []
        sock_busy = self.root / "provider_lock_busy.sock"
        broker = SessionBroker(
            socket_path=sock_busy, relay_proof=self.proof, worker_token=self.worker_token,
            lease=self.lease, connection=_FakeConn(make_events), binding=object(), models=("gpt-6.2-sol",),
            profile_label="personal", usage_dir=exp_dir,
            policy=SessionPolicy(exposure_dir=exp_dir, on_revoke=lambda: revoked_cb.append("revoked")),
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

        # Hold normal dispatch_fence across multiple watcher poll cycles (>0.35s) AND past send wait (0.5s).
        with ledger.dispatch_fence(wait=1.0):
            with self.assertRaises(ExposureError) as busy_ctx:
                ledger.inspect_hold()
            self.assertEqual(busy_ctx.exception.args[0], "exposure_lock_busy")
            time.sleep(0.35)
            self.assertFalse(broker._revoked.is_set(), "ordinary lock contention must not retire a healthy slot")
            self.assertEqual(revoked_cb, [])
            busy_resp = _send_via_relay(sock_busy, self.lease, self.proof, req)
            self.assertIn(b"503 Service Unavailable", busy_resp)
            self.assertIn(b"exposure_busy", busy_resp)
            self.assertEqual(len(writes), 0)
            self.assertFalse(broker._revoked.is_set(), "busy send refusal must not permanently retire slot")

        # Once the lock is released, the healthy slot MUST still complete turns cleanly.
        ok_resp = _send_via_relay(sock_busy, self.lease, self.proof, req)
        self.assertIn(b"response.completed", ok_resp)
        self.assertEqual(len(writes), 1)
        self.assertEqual(revoked_cb, [])

    def test_gate4_r3_revocation_during_relay_create_retains_durable_lease_on_failed_remove(self):
        import gc
        import pwd
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.connection import Connection, ConnectionError, PhysicalHost
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.contracts import ProviderInstanceSpec

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        backend = self._make_real_profile_backend(scratch / "create_race_profiles")
        backend.connect("personal")
        view = backend.profiles.snapshot()
        personal_dir = next(p.directory for p in view.saved if p.label == "personal")
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        created_id = "c" * 64

        def _run_mid_create_revocation() -> Path:
            adapter = OpenAISessionAdapter(backend)
            pref = adapter.preflight_instance(ProviderInstanceSpec("openai", "personal", True, "subscription"))
            stop_ev = threading.Event()
            coord = session_broker._SessionSlotCoordinator(stop_ev)
            slot_root = Path(tempfile.mkdtemp(prefix="oc-chat-", dir="/tmp"))
            self.addCleanup(lambda: shutil.rmtree(slot_root, ignore_errors=True))
            slot_cm = adapter.open_slot(
                pref, slot_index=0, slot_root=slot_root, port=8401,
                worker_token="tok-create-race-" + "a" * 24,
                acknowledged_exposure_digest=None, on_revoke=coord.on_revoke,
            )
            handle = slot_cm.__enter__()
            coord.register_slot(slot_cm, handle, slot_root)

            in_create = threading.Event()
            release_create = threading.Event()
            podman_calls: list[tuple] = []

            def paused_podman(*args, **_kwargs):
                podman_calls.append(args)
                if args[0] == "create":
                    in_create.set()
                    self.assertTrue(release_create.wait(5.0))
                    return subprocess.CompletedProcess(args, 0, (created_id + "\n").encode(), b"")
                return subprocess.CompletedProcess(args, 0, b"", b"")

            def trigger_revoke_mid_create():
                self.assertTrue(in_create.wait(5.0))
                coord.on_revoke(0)
                with coord._lock:
                    threads = list(coord._retire_threads)
                for th in threads:
                    th.join(timeout=5.0)
                release_create.set()

            revoker = threading.Thread(target=trigger_revoke_mid_create, daemon=True)
            revoker.start()
            spec = self._valid_spec()
            with patch.object(session_broker, "podman", side_effect=paused_podman):
                with self.assertRaisesRegex(ConnectionError, "connection_retired"):
                    session_broker._start_and_verify_slot_relay(
                        spec, "1" * 64, handle, coord, [], [], stop_ev,
                    )
            revoker.join(timeout=5.0)
            self.assertFalse(any(call[0] == "start" for call in podman_calls))

            with patch.object(session_broker, "_remove_container_verified", side_effect=RuntimeError("rm failed")):
                err = coord.teardown_all(None)
            self.assertIsNotNone(err)
            return slot_root

        retained_root = _run_mid_create_revocation()
        gc.collect()
        gc.collect()

        fresh_conn = Connection(personal_dir, host_probe=lambda: host)
        self.assertTrue(
            fresh_conn.has_active_leases(),
            "revocation during relay create erased durable lease despite failed removal!",
        )
        state_data = json.loads((personal_dir / "state.json").read_text(encoding="utf-8"))
        self.assertIn(retained_root.name, state_data.get("worker_leases", {}))

    def test_gate4_r4_exists_timeout_after_failed_create_preserves_error_root_and_lease(self):
        import gc
        import io
        import pwd
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.cli import StreamTerminal
        from oc_openai.connection import Connection, PhysicalHost
        from oc_openai.managed.runtime import JobRuntimeError
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.catalog import ResolvedLaunchPlan
        from oc_providers.contracts import ProviderInstanceSpec

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        backend = self._make_real_profile_backend(scratch / "exists_timeout_profiles")
        backend.connect("personal")
        view = backend.profiles.snapshot()
        personal_dir = next(p.directory for p in view.saved if p.label == "personal")
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")

        created_slot_roots: list[Path] = []
        orig_mkdtemp = tempfile.mkdtemp

        def tracking_mkdtemp(*args, **kwargs):
            path = Path(orig_mkdtemp(*args, **kwargs))
            created_slot_roots.append(path)
            self.addCleanup(lambda p=path: shutil.rmtree(p, ignore_errors=True))
            return str(path)

        def failing_podman(*args, **_kwargs):
            if args[0] == "create":
                raise JobRuntimeError("create timed out")
            if args[:2] == ("container", "exists"):
                raise JobRuntimeError("exists probe timed out")
            return subprocess.CompletedProcess(args, 0, b"", b"")

        err_buf = io.StringIO()
        cleanup_state = {"clean": False}
        rb_root = self.root / "r4_root"
        rb_root.mkdir(mode=0o700)

        def _run_failed_create():
            adapter = OpenAISessionAdapter(backend)
            pref = adapter.preflight_instance(ProviderInstanceSpec("openai", "personal", True, "subscription"))
            plan = ResolvedLaunchPlan(
                admitted=(pref,), excluded=(), initial_provider_id="openai--personal",
                initial_model="gpt-6.2-sol", ui_mode="full", ui_source="default",
                acknowledged_digests={},
            )
            term = StreamTerminal(io.StringIO(), io.StringIO(), err_buf)
            spec = self._valid_spec()
            stop_ev = threading.Event()
            with (
                patch.object(session_broker.tempfile, "mkdtemp", side_effect=tracking_mkdtemp),
                patch.object(session_broker, "_verify_pod_with_containers", return_value=("1" * 64, [])),
                patch.object(session_broker, "_ensure_containers_idle"),
                patch.object(session_broker, "podman", side_effect=failing_podman),
            ):
                with self.assertRaisesRegex(JobRuntimeError, "create timed out"):
                    session_broker._run_multi_slot_session(
                        spec, plan, {"openai": adapter}, rb_root, stop_ev, term, cleanup_state,
                    )

        _run_failed_create()
        gc.collect()
        gc.collect()

        self.assertFalse(cleanup_state["clean"])
        self.assertEqual(len(created_slot_roots), 1)
        self.assertTrue(created_slot_roots[0].exists(), "unconfirmed slot_root must be retained for inspection")
        self.assertIn("Provider session cleanup needs verification", err_buf.getvalue())
        fresh_conn = Connection(personal_dir, host_probe=lambda: host)
        self.assertTrue(
            fresh_conn.has_active_leases(),
            "durable lease must remain on disk when container exists probe times out after failed create",
        )

    def _setup_create_outcome_env(self, label: str):
        import pwd
        from oc_openai.connection import PhysicalHost

        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        scratch = Path(self.enterContext(tempfile.TemporaryDirectory(dir=home)))
        backend = self._make_real_profile_backend(scratch / label)
        backend.connect("personal")
        view = backend.profiles.snapshot()
        personal_dir = next(p.directory for p in view.saved if p.label == "personal")
        host = PhysicalHost("a" * 64, "11111111-2222-3333-4444-555555555555")
        return backend, personal_dir, host

    def _run_create_outcome_case(
        self, env, *, case_id: str, podman_fn, expected_pat: str, expect_retained: bool,
    ):
        import gc
        import io
        from unittest.mock import patch
        from oc_openai import session_broker
        from oc_openai.cli import StreamTerminal
        from oc_openai.connection import Connection
        from oc_openai.managed.runtime import JobRuntimeError
        from oc_openai.session_adapter import OpenAISessionAdapter
        from oc_providers.catalog import ResolvedLaunchPlan
        from oc_providers.contracts import ProviderInstanceSpec

        backend, personal_dir, host = env
        created_slot_roots: list[Path] = []
        orig_mkdtemp = tempfile.mkdtemp

        def tracking_mkdtemp(*args, **kwargs):
            path = Path(orig_mkdtemp(*args, **kwargs))
            created_slot_roots.append(path)
            self.addCleanup(lambda p=path: shutil.rmtree(p, ignore_errors=True))
            return str(path)

        err_buf = io.StringIO()
        cleanup_state = {"clean": False}
        rb_root = self.root / f"create_case_{case_id}"
        rb_root.mkdir(mode=0o700)

        def _invoke():
            adapter = OpenAISessionAdapter(backend)
            pref = adapter.preflight_instance(ProviderInstanceSpec("openai", "personal", True, "subscription"))
            plan = ResolvedLaunchPlan(
                admitted=(pref,), excluded=(), initial_provider_id="openai--personal",
                initial_model="gpt-6.2-sol", ui_mode="full", ui_source="default",
                acknowledged_digests={},
            )
            term = StreamTerminal(io.StringIO(), io.StringIO(), err_buf)
            spec = self._valid_spec()
            stop_ev = threading.Event()
            with (
                patch.object(session_broker.tempfile, "mkdtemp", side_effect=tracking_mkdtemp),
                patch.object(session_broker, "_verify_pod_with_containers", return_value=("1" * 64, [])),
                patch.object(session_broker, "_ensure_containers_idle"),
                patch.object(session_broker, "_verify_relay_prestart"),
                patch.object(session_broker, "podman", side_effect=podman_fn),
            ):
                with self.assertRaisesRegex(JobRuntimeError, expected_pat):
                    session_broker._run_multi_slot_session(
                        spec, plan, {"openai": adapter}, rb_root, stop_ev, term, cleanup_state,
                    )

        _invoke()
        gc.collect()
        gc.collect()

        self.assertEqual(len(created_slot_roots), 1)
        fresh_conn = Connection(personal_dir, host_probe=lambda: host)
        if expect_retained:
            self.assertFalse(cleanup_state["clean"])
            self.assertTrue((created_slot_roots[0] / "grant").is_dir(), "grant dir must be retained")
            self.assertIn("Provider session cleanup needs verification", err_buf.getvalue())
            self.assertTrue(fresh_conn.has_active_leases(), "durable lease must be retained on uncertain create")
            # Clear retained lease so subsequent subtests start cleanly.
            state_path = personal_dir / "state.json"
            data = json.loads(state_path.read_text(encoding="utf-8"))
            data.pop("worker_leases", None)
            state_path.write_text(json.dumps(data), encoding="utf-8")
            state_path.chmod(0o600)
        else:
            self.assertTrue(cleanup_state["clean"])
            self.assertFalse(created_slot_roots[0].exists(), "grant dir must be cleaned after verified removal")
            self.assertFalse(fresh_conn.has_active_leases(), "durable lease must be released after verified removal")

    def test_gate4_r5_lost_create_ack_retains_lease_and_grant_dir_even_if_exists_reports_absent(self):
        from oc_openai.managed.runtime import JobRuntimeError

        env = self._setup_create_outcome_env("lost_ack_profiles")
        for mode, expected_pat in (("lost_ack", "lost ack"), ("timeout_124", r"Podman create failed \(124\)")):
            with self.subTest(mode=mode):
                def flaky_podman(*args, _mode=mode, **_kwargs):
                    if args[0] == "create":
                        if _mode == "lost_ack":
                            raise JobRuntimeError("Podman create failed or timed out (lost ack)")
                        return subprocess.CompletedProcess(args, 124, b"", b"")
                    if args[:2] == ("container", "exists"):
                        return subprocess.CompletedProcess(args, 1, b"", b"")
                    return subprocess.CompletedProcess(args, 0, b"", b"")

                self._run_create_outcome_case(
                    env, case_id=f"r5_{mode}", podman_fn=flaky_podman,
                    expected_pat=expected_pat, expect_retained=True,
                )

    def test_gate4_r6_host_wrapper_nonzero_create_retains_lease_and_grant_dir(self):
        from oc_openai.managed.runtime import JobRuntimeError

        env = self._setup_create_outcome_env("wrapper_fail_profiles")
        # Wrapper SIGTERM (-15), bridge failure (1), and unverified nonzero (125) lack host-side
        # create completion evidence and MUST retain both durable lease and grant dir even when
        # `podman container exists` transiently reports absence (rc=1).
        for label, rc in (("sigterm", -15), ("bridge_1", 1), ("exit_125", 125)):
            with self.subTest(label=label, rc=rc):
                def wrapper_fail_podman(*args, _rc=rc, **_kwargs):
                    if args[0] == "create":
                        return subprocess.CompletedProcess(args, _rc, b"", b"")
                    if args[:2] == ("container", "exists"):
                        return subprocess.CompletedProcess(args, 1, b"", b"")
                    return subprocess.CompletedProcess(args, 0, b"", b"")

                self._run_create_outcome_case(
                    env, case_id=f"r6_{label}", podman_fn=wrapper_fail_podman,
                    expected_pat=rf"Podman create failed \({rc}\)", expect_retained=True,
                )

        # Control: verified create returning a 64-hex ID followed by verified removal of that exact
        # ID cleanly releases both the durable lease and the grant directory.
        created_id = "d" * 64
        removed_ids: list[str] = []

        def verified_create_then_fail_start(*args, **_kwargs):
            if args[0] == "create":
                return subprocess.CompletedProcess(args, 0, (created_id + "\n").encode("ascii"), b"")
            if args[0] == "start":
                raise JobRuntimeError("simulated start failure")
            if args[:2] == ("rm", "-f"):
                removed_ids.append(args[2])
                return subprocess.CompletedProcess(args, 0, (args[2] + "\n").encode("ascii"), b"")
            if args[:2] == ("container", "exists") and args[2] == created_id:
                return subprocess.CompletedProcess(args, 1, b"", b"")
            return subprocess.CompletedProcess(args, 0, b"", b"")

        self._run_create_outcome_case(
            env, case_id="r6_verified_control", podman_fn=verified_create_then_fail_start,
            expected_pat="simulated start failure", expect_retained=False,
        )
        self.assertEqual(removed_ids, [created_id])


if __name__ == "__main__":
    unittest.main()
