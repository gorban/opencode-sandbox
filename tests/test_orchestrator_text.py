"""Portable checks for the isolated orchestrator entry and its recording fake."""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory, TemporaryFile
from threading import Event, Thread
import unittest
from unittest.mock import patch

from oc_orchestrator.capture import CaptureError, capture
from oc_orchestrator.claude import Broker, NativeFrames, native_process
from oc_orchestrator.claude_fixture import extra_descriptors
from oc_orchestrator.claude_protocol import PREFIX, SETTINGS, ProtocolError, select_native, validate_sdk
from oc_orchestrator.owner import Lifeline
from oc_orchestrator.protocol import OPTIONS, PROMPT, RecordingFake, accept_text
from oc_orchestrator.relay import handoff
from oc_orchestrator.runtime import Failure, Placement, container_categories, verify_result


ROOT = Path(__file__).resolve().parents[1]
PROOF = b"p" * 32
SYSTEM = "Fixture system content.\nToday's date: Tue Nov 24 2026"
TEST_DIGEST = hashlib.sha256(b"Fixture system content.\nToday's date: [date]").hexdigest()


def payload(**changes):
    return {**OPTIONS, "messages": [{"role": "system", "content": SYSTEM},
                                    {"role": "user", "content": PROMPT}], **changes}


@contextmanager
def route(address, **options):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        with (patch("oc_orchestrator.protocol.SYSTEM_DIGEST", TEST_DIGEST),
              RecordingFake(address, PROOF, port=listener.getsockname()[1], **options) as broker):
            yield listener, broker


def connect(address, listener, body, proof=PROOF, *, authorization="Bearer offline-fixture"):
    message = json.dumps(body).encode()
    host, port = listener.getsockname()
    headers = (f"POST /v1/chat/completions HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Authorization: {authorization}\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(message)}\r\n\r\n").encode()
    client = socket.create_connection((host, port), timeout=3)
    try:
        client.sendall(headers + message)
        accepted, _ = listener.accept()
        with accepted:
            handoff(accepted, address, proof)
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
    def test_claude_synthetic_admits_only_the_known_sdk_launch_modes(self):
        discovery = [*PREFIX, "--no-session-persistence", *SETTINGS]
        turn = [*PREFIX, "--model=haiku", "--include-partial-messages",
                "--session-id=00000000-0000-4000-8000-000000000001", *SETTINGS]
        self.assertIsNone(select_native(discovery))
        self.assertEqual(select_native(turn), "00000000-0000-4000-8000-000000000001")
        for unexpected in ([*turn, "--tools=Read"], [*turn, "--model=opus"], [*discovery, "--mcp-config=test"]):
            with self.subTest(unexpected=unexpected), self.assertRaises(ProtocolError):
                select_native(unexpected)

    def test_claude_synthetic_rejects_mcp_and_changed_model_before_forwarding(self):
        def request(subtype, **fields):
            return {"type": "control_request", "request_id": "fixture", "request": {"subtype": subtype, **fields}}

        validate_sdk(request("initialize"), None, 0)
        validate_sdk(request("set_model", model="haiku"), None, 1)
        for unexpected, position in ((request("initialize", sdkMcpServers=["unapproved"]), 0),
                                     (request("set_model", model="opus"), 1),
                                     (request("get_context_usage"), 1)):
            with self.subTest(unexpected=unexpected), self.assertRaises(ProtocolError):
                validate_sdk(unexpected, None, position)

    def test_claude_synthetic_rejects_any_extra_prompt_block(self):
        session = "00000000-0000-4000-8000-000000000001"
        fixed = {"type": "text", "text": "Reply with exactly: ok"}
        for parts in ([fixed], [fixed, {"type": "text", "text": "Unexpected instructions"}]):
            message = {"type": "user", "message": {"content": parts}}
            if len(parts) == 1:
                validate_sdk(message, session, 1)
            else:
                with self.assertRaises(ProtocolError):
                    validate_sdk(message, session, 1)

    def test_claude_probe_detects_an_inherited_descriptor_above_15(self):
        with TemporaryFile() as marker:
            marker.write(b"synthetic private marker")
            descriptor = fcntl.fcntl(marker.fileno(), fcntl.F_DUPFD, 40)
            try:
                self.assertIn(descriptor, set(extra_descriptors()))
            finally:
                os.close(descriptor)

    def test_owner_loss_retires_a_stalled_native_process_and_socket(self):
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as pipe, os.fdopen(write_fd, "wb") as owner:
            lifeline = Lifeline(pipe.fileno())
            broker = Broker(None, "", lifeline)
            first, second = socket.socketpair()
            with native_process(["/usr/bin/sleep", "60"]) as process, first as client, second as peer:
                cancelled = Event()

                def read_native():
                    try:
                        NativeFrames(process.stdout).next_line()
                    except ProtocolError:
                        cancelled.set()

                reader = Thread(target=read_native)
                with (broker.own(broker.children, process), broker.own(broker.clients, client),
                      lifeline.revoke_on_loss(broker.retire)):
                    reader.start()
                    owner.close()
                    self.assertTrue(cancelled.wait(1))
                    self.assertIsNotNone(process.wait(timeout=1))
                    peer.settimeout(1)
                    self.assertEqual(peer.recv(1), b"")
                reader.join(timeout=1)
                self.assertFalse(reader.is_alive())

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

    def test_direct_launcher_ignores_hostile_discovery_inputs(self):
        with TemporaryDirectory() as home:
            root = Path(home)
            commands = ("bash", "readlink", "realpath", "getent", "startup")
            for name in commands:
                script = root / name
                script.write_text(f"#!/bin/sh\ntouch '{root}/untrusted-binary-ran'\nexit 12\n")
                script.chmod(0o755)
            result = subprocess.run([ROOT / "oc-sandbox", "orchestrate", "--help"], cwd=root,
                                    env={"PATH": f"{root}:/usr/bin:/bin", "HOME": str(root / "fake-home"),
                                         "BASH_ENV": str(root / "startup")}, text=True,
                                    capture_output=True, timeout=6, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((root / "untrusted-binary-ran").exists())

    def test_exact_transcript_once_and_no_tools(self):
        with TemporaryDirectory() as root:
            address = Path(root) / "proof.sock"
            with route(address) as (listener, broker):
                for body, proof in ((payload(tools=[{"type": "function"}]), PROOF),
                                    (payload(web_search_options={}), PROOF),
                                    (payload(model="foreign"), PROOF)):
                    with connect(address, listener, body, proof) as client:
                        self.assertIn(b"403 Forbidden", response(client))
                with connect(address, listener, payload(), b"q" * 32) as client:
                    self.assertEqual(response(client), b"")
                self.assertEqual(broker.admissions, 0)
                with connect(address, listener, payload()) as client:
                    self.assertIn(b'"content": "ok"', response(client))
                with connect(address, listener, payload()) as client:
                    self.assertIn(b"403 Forbidden", response(client))
                self.assertEqual(broker.admissions, 1)

    def test_unapproved_system_options_and_key_are_refused(self):
        with TemporaryDirectory() as root:
            address = Path(root) / "proof.sock"
            with route(address) as (listener, broker):
                self.assertEqual(address.stat().st_mode & 0o777, 0o600)
                altered = payload()["messages"] + [{"role": "system", "content": "unexpected behavior"}]
                for body in (payload(messages=altered), payload(max_completion_tokens=1),
                             payload(stream_options={"include_usage": 1}), payload(temperature=float("nan"))):
                    with connect(address, listener, body) as client:
                        self.assertIn(b"403 Forbidden", response(client))
                with connect(address, listener, payload(), authorization="Bearer wrong") as client:
                    self.assertIn(b"403 Forbidden", response(client))
                self.assertEqual(broker.admissions, 0)

    def test_provider_tool_event_is_withheld_after_one_send(self):
        with TemporaryDirectory() as root:
            address = Path(root) / "proof.sock"
            with route(address, events=(b'{"tool":"write"}',)) as (listener, broker):
                with connect(address, listener, payload()) as client:
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
            with route(address, before_delivery=hold) as (listener, broker):
                with connect(address, listener, payload()) as client:
                    try:
                        self.assertTrue(recorded.wait(2))
                        broker.revoke()
                        self.assertEqual(response(client), b"")
                        self.assertEqual(broker.admissions, 1)
                        self.assertEqual(broker.settlement, "recorded_offline")
                    finally:
                        release.set()

    def test_owner_eof_fences_even_while_watcher_is_delayed(self):
        for expected in (0, 1):
            with self.subTest(expected_sends=expected), TemporaryDirectory() as root:
                self.check_owner_eof(Path(root) / "proof.sock", expected)

    def check_owner_eof(self, address, expected):
        paused, release = Event(), Event()

        def hold():
            paused.set()
            release.wait(3)

        def validate(body):
            accept_text(body)
            if not expected:
                hold()

        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb") as read_end, os.fdopen(write_fd, "wb") as write_end:
            with patch("oc_orchestrator.owner.threading.Thread.start"):
                lifeline = Lifeline(read_end.fileno())
            with (patch("oc_orchestrator.protocol.accept_text", side_effect=validate),
                  route(address, authorized=lifeline.active, before_delivery=hold if expected else None) as (listener, broker),
                  connect(address, listener, payload()) as client):
                try:
                    self.assertTrue(paused.wait(2))
                    write_end.close()
                    release.set()
                    self.assertEqual(response(client), b"")
                    self.assertEqual(broker.receipt()[0], expected)
                    self.assertFalse(lifeline.lost.is_set())
                finally:
                    release.set()

    def test_native_result_belongs_to_one_successful_turn(self):
        events = [{"type": kind, "sessionID": "session", "part": {
            "type": kind.replace("_", "-"), "sessionID": "session", "messageID": "turn", **fields}}
            for kind, fields in (("step_start", {}), ("text", {"text": "ok"}), ("step_finish", {"reason": "stop"}))]

        def verify(items):
            verify_result(b"\n".join(json.dumps(item).encode() for item in items))

        verify(events)
        for invalid in (events[1:], [None, *events[1:]], [events[0], {"type": "text"}, events[2]],
                        [*events[:2], {**events[2], "part": {**events[2]["part"], "reason": "length"}}],
                        [*events[:2], {**events[2], "sessionID": "other"}]):
            with self.assertRaises(Failure):
                verify(invalid)

    def test_output_bounds_include_stderr(self):
        self.assertEqual(capture([sys.executable, "-c", "print('ok')"], env={}, timeout=3, limit=1024).stdout, b"ok\n")
        for descriptor in (1, 2):
            with self.assertRaises(CaptureError):
                capture([sys.executable, "-c", f"import os; os.write({descriptor}, b'x' * 4096)"],
                        env={}, timeout=3, limit=1024)

    def test_selinux_process_labels_match_mount_categories(self):
        process = "user:role:container_t:s0:c1,c2"
        self.assertEqual(container_categories({"ProcessLabel": process, "MountLabel": "u:r:container_file_t:s0:c2,c1"}),
                         {"c1", "c2"})
        for categories in ("c1,c1", "c3,c4"):
            with self.assertRaises(Failure):
                container_categories({"ProcessLabel": process, "MountLabel": f"u:r:container_file_t:s0:{categories}"})

    def test_cleanup_attempts_worker_after_relay_removal_fails(self):
        placement = Placement(Path("/unused"), None)
        placement.attempted = True
        placement.ids = {"relay": "1" * 64, "open-code": "2" * 64}
        removals = []

        def podman(*args):
            if args[0] == "ps":
                return subprocess.CompletedProcess(args, 0, stdout=b"relay-remains\n" if "--quiet" in args else b"")
            removals.append(args[-1])
            if args[-1] == placement.ids["relay"]:
                raise Failure("relay removal failed")
            return subprocess.CompletedProcess(args, 0, stdout=b"")

        with (patch("oc_orchestrator.runtime.podman", side_effect=podman),
              patch.object(placement, "identity"), self.assertRaisesRegex(Failure, "cleanup left a container")):
            placement.close()
        self.assertEqual(removals, [placement.ids["relay"], placement.ids["open-code"]])


if __name__ == "__main__":
    unittest.main()
