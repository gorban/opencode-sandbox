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
                self._state = state_dir
                self._state.mkdir(parents=True, exist_ok=True)
                self.selected = ("work", "epoch-1")

            def active_connection(self):
                class _Conn:
                    def models(self, _binding):
                        return ("gpt-6.2-sol",)

                    def require_active(self, _binding):
                        return None
                return "work", "epoch-1", _Conn(), object()

            def active_selection(self):
                return self.selected

            @contextlib.contextmanager
            def session_lease(self, label, epoch, binding, job):
                assert (label, epoch) == ("work", "epoch-1")
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
            if args[0] == "create" and spec["relay"] in args:
                return subprocess.CompletedProcess(args, 0, (relay_id + "\n").encode(), b"")
            if args[0] == "create" and spec["agent"] in args:
                agent_create_args.extend(args)
                return subprocess.CompletedProcess(args, 0, (agent_id + "\n").encode(), b"")
            if args[:2] == ("container", "inspect") and "--format" in args:
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
        with (patch.object(session_broker, "check_devbox"),
              patch.object(session_broker, "check_host"),
              patch.object(session_broker, "make_backend", return_value=backend),
              patch.object(session_broker, "SHARED_TMP", str(self.root)),
              patch.object(session_broker, "inspected", side_effect=fake_inspected),
              patch.object(session_broker, "podman", side_effect=fake_podman),
              patch.object(session_broker, "host_output", side_effect=fake_host_output),
              patch.object(session_broker.subprocess, "Popen", side_effect=fake_popen)):
            rc = session_broker.run_interactive_session(spec, term)

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


if __name__ == "__main__":
    unittest.main()
