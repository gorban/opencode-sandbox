"""Portable checks for the isolated orchestrator entry and its recording fake."""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory, TemporaryFile
from threading import Event, Thread
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from oc_orchestrator.capture import CaptureError, capture
from oc_orchestrator.claude import Broker, NativeFrames, fixture_instances, native_process, run_proof as run_claude_proof
from oc_orchestrator.claude_fixture import extra_descriptors, turn
from oc_orchestrator.claude_protocol import (
    LIMIT, PREFIX, SETTINGS, STOCK_MODEL, TURN_INITIALIZE, USER, ProtocolError, decode, encode,
    select_native, validate_sdk, validate_turn_output,
)
from oc_orchestrator.owner import Lifeline
from oc_orchestrator.protocol import OPTIONS, PROMPT, RecordingFake, Refused, accept_text
from oc_orchestrator.relay import handoff
from oc_orchestrator.runtime import Failure, Placement, container_categories, verify_result


ROOT = Path(__file__).resolve().parents[1]
PROOF = b"p" * 32
SYSTEM = "Fixture system content.\nToday's date: Tue Nov 24 2026"
TEST_DIGEST = hashlib.sha256(b"Fixture system content.\nToday's date: [date]").hexdigest()


def payload(**changes):
    return {**OPTIONS, "messages": [{"role": "system", "content": SYSTEM},
                                    {"role": "user", "content": PROMPT}], **changes}


class NamedProviderSystemTest(unittest.TestCase):
    def test_measured_transcript_accepts_only_the_named_label_substitution(self):
        baseline = "Provider google/elgoog; selected label elgoog.\nToday's date: [date]"
        actual = baseline.replace("elgoog", "custom-google").replace("[date]", "Tue Nov 24 2026")
        digest = hashlib.sha256(baseline.encode()).hexdigest()
        request = payload(messages=[{"role": "system", "content": actual},
                                    {"role": "user", "content": PROMPT}])
        accept_text(json.dumps(request).encode(), system_digest=digest,
                    normalized_label=("custom-google", "elgoog"))
        for broken in (
            actual.replace("selected label custom-google", "selected label wrong"),
            actual.replace("selected label custom-google", "selected label custom-google extra"),
            actual.replace("selected label custom-google", "selected label"),
        ):
            with self.subTest(broken=broken), self.assertRaises(Refused):
                modified = payload(messages=[{"role": "system", "content": broken},
                                             {"role": "user", "content": PROMPT}])
                accept_text(json.dumps(modified).encode(), system_digest=digest,
                            normalized_label=("custom-google", "elgoog"))


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

    def test_claude_synthetic_rejects_altered_control_requests_before_forwarding(self):
        def request(subtype, **fields):
            return {"type": "control_request", "request_id": "fixture", "request": {"subtype": subtype, **fields}}

        initialize = request("initialize", systemPrompt=[""], skills=[])
        validate_sdk(initialize, None, 0)
        validate_sdk(request("set_model", model="haiku"), None, 1)
        validate_sdk(request("get_context_usage", detail="summary"), None, 2)
        for unexpected, position in (
                (request("initialize", systemPrompt=[""], skills=[], sdkMcpServers=["unapproved"]), 0),
                (request("initialize", systemPrompt=[""], skills=[], unchecked={}), 0),
                (request("set_model", model="opus"), 1),
                (request("get_context_usage", detail="summary"), 1),
                ({**initialize, "request_id": False}, 0)):
            with self.subTest(unexpected=unexpected), self.assertRaises(ProtocolError):
                validate_sdk(unexpected, None, position)

    def test_claude_synthetic_rejects_any_extra_prompt_block(self):
        session = "00000000-0000-4000-8000-000000000001"
        fixed = {"type": "text", "text": "Reply with exactly: ok"}
        user = {"type": "user", "message": {"content": [fixed], "role": "user"}, "parent_tool_use_id": None,
                "client_composed": True, "uuid": session}
        validate_sdk(user, session, 1)
        for unexpected in ({**user, "client_composed": 1},
                           {**user, "message": {"content": [fixed, {"type": "text", "text": "Unexpected"}],
                                                 "role": "user"}}):
            with self.subTest(unexpected=unexpected), self.assertRaises(ProtocolError):
                validate_sdk(unexpected, session, 1)

    def test_claude_synthetic_binds_one_send_to_an_exact_approved_route(self):
        with TemporaryDirectory(dir="/tmp") as directory:
            instances, personal = fixture_instances(Path(directory))
        team = "claude--team"
        self.assertEqual((personal, set(instances)), ("claude--personal", {personal, team}))
        self.assertTrue(all(item.models == ("haiku",) and item.spec.auth_mode == "subscription"
                            for item in instances.values()))
        broker = Broker(None, SimpleNamespace(check=lambda: None), instances, {})
        writes = []

        def dispatch(binding):
            broker.dispatch(binding, lambda: writes.append(binding))

        def propose(slot):
            return broker.identify(broker.offer(slot, "haiku"))

        def activate(binding):
            return broker.activate(binding, STOCK_MODEL)

        def refuse_launch(route):
            args = [*PREFIX, "--model=haiku", "--include-partial-messages",
                    "--session-id=00000000-0000-4000-8000-000000000001", *SETTINGS]
            client, peer = socket.socketpair()
            with client, peer:
                peer.sendall(encode({"route": route, "argv": args}))
                with patch("oc_orchestrator.claude.native_process") as native:
                    with self.assertRaises(ProtocolError):
                        broker.serve(client)
                    native.assert_not_called()

        route = broker.offer(personal, "haiku")
        first = broker.identify(route)
        client, peer = socket.socketpair()
        with client, peer:
            peer.sendall(encode({"route": route, "observed_model": STOCK_MODEL}))
            with self.assertRaises(ProtocolError):
                broker.serve(client)
            self.assertEqual(response(peer), b"")
        self.assertIsNone(broker.selection)
        self.assertEqual(broker.sends, 0)
        with self.assertRaises(ProtocolError):
            dispatch(first)
        refuse_launch(route)
        with self.assertRaises(ProtocolError):
            broker.activate(first, "claude-agent/opus")
        with self.assertRaises(ProtocolError):
            broker.identify({**route, "model": "opus"})
        first_turn_route = activate(first)

        alternate_route = broker.offer(team, "haiku")
        alternate = broker.identify(alternate_route)
        with self.assertRaises(ProtocolError):
            dispatch(alternate)
        # Exercise the actual broker connection check using a valid proof from the other slot.
        refuse_launch({**first_turn_route, "proof": alternate_route["proof"]})
        refuse_launch(alternate_route)

        broker.cancel()
        self.assertEqual(broker.selection, first)
        replacement = propose(team)
        self.assertNotEqual(alternate, replacement)
        with self.assertRaises(ProtocolError):
            activate(alternate)
        activate(replacement)
        with self.assertRaises(ProtocolError):
            dispatch(first)
        latest_route = broker.offer(personal, "haiku")
        latest = broker.identify(latest_route)
        latest_route = activate(latest)
        refuse_launch(first_turn_route)
        refuse_launch({**latest_route, "proof": first_turn_route["proof"]})
        with self.assertRaises(ProtocolError):
            dispatch(first)
        with self.assertRaises(ProtocolError):
            dispatch(replacement)
        self.assertEqual(writes, [])
        dispatch(latest)
        with self.assertRaises(ProtocolError):
            dispatch(latest)
        refuse_launch(latest_route)
        self.assertEqual(writes, [latest])
        self.assertEqual(broker.sends, 1)

    def test_claude_queued_discovery_cannot_spend_the_turn_latch_after_activation(self):
        session = "00000000-0000-4000-8000-000000000001"
        slot = "claude--personal"
        broker = Broker(Path("/unused"), SimpleNamespace(check=lambda: None),
                        {slot: SimpleNamespace(models=("haiku",))}, {slot: "fixture"})
        discovery = broker.offer(slot, "haiku")
        approved = broker.identify(discovery)
        args = [*PREFIX, "--model=haiku", "--include-partial-messages", f"--session-id={session}", *SETTINGS]
        initialize = {"type": "control_request", "request_id": "fixture", "request": TURN_INITIALIZE}
        user = {**USER, "parent_tool_use_id": None, "uuid": session, "client_composed": True}
        native_writes = []

        def queue_request(peer, route):
            peer.sendall(encode({"route": route, "argv": args}) + encode(initialize) + encode(user))
            peer.shutdown(socket.SHUT_WR)

        def exchange(_client, stream, _process, binding, selected_session):
            validate_sdk(decode(stream.readline()), selected_session, 0)
            request = validate_sdk(decode(stream.readline()), selected_session, 1)
            broker.dispatch(binding, lambda: native_writes.append(request))

        with (patch.object(broker, "exchange", side_effect=exchange),
              patch("oc_orchestrator.claude.native_process") as native):
            queued, peer = socket.socketpair()
            with queued, peer:
                queue_request(peer, discovery)
                selected = broker.activate(approved, STOCK_MODEL)
                try:
                    broker.serve(queued)
                except ProtocolError:
                    pass
                self.assertEqual(broker.sends, 0)
                native.assert_not_called()
                self.assertEqual(response(peer), b"")

            self.assertNotEqual(discovery["proof"], selected["proof"])
            self.assertEqual(selected, {**discovery, "proof": selected["proof"]})
            accepted, peer = socket.socketpair()
            with accepted, peer:
                queue_request(peer, selected)
                broker.serve(accepted)
            native.assert_called_once()
            self.assertEqual((broker.sends, native_writes), (1, [USER]))

    def test_claude_stale_discovery_proof_cannot_be_rebound_after_a_b_a(self):
        personal, team = "claude--personal", "claude--team"
        instances = {slot: SimpleNamespace(models=("haiku",)) for slot in (personal, team)}
        broker = Broker(None, SimpleNamespace(check=lambda: None), instances, {})
        retired = broker.offer(personal, "haiku")
        broker.offer(team, "haiku")
        current = broker.offer(personal, "haiku")
        broker.identify(current)
        with self.assertRaises(ProtocolError):
            broker.identify({**current, "proof": retired["proof"]})
        self.assertEqual(broker.sends, 0)

    def test_claude_discovery_errors_and_pending_requests_prevent_the_turn(self):
        for case in ("completed", "queued", "active"):
            with self.subTest(case=case), TemporaryDirectory(dir="/tmp") as directory:
                root = Path(directory) / "scratch"
                root.mkdir(mode=0o700)
                stages = []
                brokers = []
                request_sent, handler_started, release_handler = Event(), Event(), Event()
                original_poll, original_serve = Broker.poll, Broker.serve

                def poll(broker, listener, *phase):
                    if case == "queued":
                        (phase[0] if phase else request_sent).wait(timeout=3)
                    return original_poll(broker, listener, *phase)

                def serve(broker, client):
                    if case != "active":
                        return original_serve(broker, client)
                    with client, broker.own(broker.clients, client):
                        handler_started.set()
                        release_handler.wait(timeout=1)

                def run_frontend(root, stage, _lifeline, broker):
                    stages.append(stage)
                    brokers.append(broker)
                    if stage == "turn":
                        # Count the send old launchers permit after a failed discovery.
                        broker.dispatch(broker.selection, lambda: None)
                        return subprocess.CompletedProcess([], 1, stdout=b"")
                    address = root / "socket" / stage / "native.sock"
                    if not address.exists():
                        address = root / "socket" / "native.sock"
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                        peer.settimeout(3)
                        peer.connect(str(address))
                        peer.sendall(b"{}\n")
                        peer.shutdown(socket.SHUT_WR)
                        request_sent.set()
                        if case == "completed":
                            self.assertEqual(response(peer), b"")
                        elif case == "active":
                            self.assertTrue(handler_started.wait(timeout=3))
                    return subprocess.CompletedProcess([], 0, stdout=STOCK_MODEL.encode() + b"\n")

                lifeline = SimpleNamespace(check=lambda: None, active=lambda: True)
                with (patch("oc_orchestrator.claude.mkdtemp", return_value=str(root)),
                      patch("oc_orchestrator.claude.seed"),
                      patch("oc_orchestrator.claude.run_frontend", side_effect=run_frontend),
                      patch.object(Broker, "poll", new=poll),
                      patch.object(Broker, "serve", new=serve)):
                    with self.assertRaises(Failure):
                        run_claude_proof(lifeline)
                self.assertEqual(brokers[0].sends, 0)
                self.assertEqual(stages, ["discovery"])
                self.assertIsNone(brokers[0].selection)

    def test_claude_fixture_permissions_under_user_private_group_umask(self):
        with TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory) / "scratch"
            root.mkdir(mode=0o700)
            stages = []

            def inspect_stage(root, stage, _lifeline, _broker):
                stages.append(stage)
                for folder in ("state", f"state/{stage}", f"state/{stage}/tmp", "socket", f"socket/{stage}",
                               "frontend", f"frontend/{stage}", "profiles", "provider-config", "workspace"):
                    self.assertEqual(stat.S_IMODE((root / folder).stat().st_mode), 0o700)
                for file in ("provider-config/providers.toml", f"socket/{stage}/native.sock",
                             f"frontend/{stage}/route.json", "profiles/claude--personal"):
                    self.assertEqual(stat.S_IMODE((root / file).stat().st_mode), 0o600)
                if stage == "discovery":
                    return subprocess.CompletedProcess([], 0, stdout=STOCK_MODEL.encode() + b"\n")
                return subprocess.CompletedProcess([], 1, stdout=b"")

            lifeline = SimpleNamespace(check=lambda: None, active=lambda: True)
            old_umask = os.umask(0o002)
            try:
                with (patch("oc_orchestrator.claude.mkdtemp", return_value=str(root)),
                      patch("oc_orchestrator.claude.seed"),
                      patch("oc_orchestrator.claude.run_frontend", side_effect=inspect_stage)):
                    with self.assertRaisesRegex(Failure, "could not verify the isolated OpenCode turn"):
                        run_claude_proof(lifeline)
                self.assertEqual(os.umask(0o002), 0o002)
            finally:
                os.umask(old_umask)
            self.assertEqual(stages, ["discovery", "turn"])

    def test_claude_fixture_config_rejection_reports_setup_failure(self):
        unsupported = SimpleNamespace(kind="openai")
        config = SimpleNamespace(launch=SimpleNamespace(default_provider=("claude", "personal")),
                                 instances=(unsupported,))
        with (TemporaryDirectory(dir="/tmp") as directory,
              patch("oc_providers.config.load_provider_config", return_value=config)):
            with self.assertRaisesRegex(Failure, "fixture provider configuration is unsupported"):
                fixture_instances(Path(directory))

    def test_claude_raw_wire_errors_are_typed_and_produce_no_output(self):
        malformed = {
            "invalid JSON": b'{"bad":}\n',
            "invalid UTF-8": b'{"bad":"\xff"}\n',
            "duplicate": b'{"bad":1,"bad":2}\n',
            "NaN": b'{"bad":NaN}\n',
            "Infinity": b'{"bad":Infinity}\n',
            "over limit": b" " * LIMIT + b"\n",
            "truncated": b"{",
            "empty": b"",
            "nested": b"[" * 10000 + b"]" * 10000 + b"\n",
        }
        broker = Broker(None, SimpleNamespace(check=lambda: None), {}, {})
        for name, payload in malformed.items():
            with self.subTest(name=name):
                with self.assertRaises(ProtocolError):
                    decode(payload)
                client, peer = socket.socketpair()
                with client, peer:
                    peer.settimeout(3)
                    peer.sendall(payload)
                    peer.shutdown(socket.SHUT_WR)
                    with self.assertRaises(ProtocolError):
                        broker.serve(client)
                    self.assertEqual(response(peer), b"")
            self.assertEqual(broker.sends, 0)

        for payload in (malformed["over limit"], malformed["truncated"], malformed["empty"]):
            with TemporaryFile() as native:
                native.write(payload)
                native.seek(0)
                frames = NativeFrames(native)
                with self.assertRaises(ProtocolError):
                    frames.next_line()

    def test_claude_synthetic_requires_a_complete_native_tool_free_turn(self):
        session = "00000000-0000-4000-8000-000000000001"
        frames = list(turn(session))
        validate_turn_output(frames, session)
        tool_frame = {**frames[1], "event": {**frames[1]["event"], "content_block": {"type": "tool_use"}}}
        assistant_tool = {**frames[6], "message": {**frames[6]["message"], "content": [{"type": "tool_use"}]}}
        for invalid in ([*frames, tool_frame], frames[:-1], [frames[0], tool_frame, *frames[2:]],
                        [*frames[:6], assistant_tool, frames[-1]],
                        [*frames[:-1], {**frames[-1], "permission_denials": [{"tool_name": "Read"}]}]):
            with self.subTest(invalid_types=[frame["type"] for frame in invalid]):
                with self.assertRaises(ProtocolError):
                    validate_turn_output(invalid, session)

    def test_claude_broker_withholds_raw_malformed_and_trailing_native_frames(self):
        session = "00000000-0000-4000-8000-000000000001"
        slot = "claude--personal"
        init = {"type": "control_request", "request_id": "fixture", "request": {
            "subtype": "initialize", "skills": [], "systemPromptSnapshot": False,
            "appendSystemPrompt": ("<runtime_info>You are running in OpenCode through the Claude Code harness. "
                                   "Mention this only when asked.</runtime_info>"),
            "hooks": {"PostToolUse": [{"hookCallbackIds": ["hook_1"]}],
                      "PreToolUse": [{"hookCallbackIds": ["hook_0"]}]},
        }}
        prompt = {"type": "user", "message": {"role": "user", "content": [
            {"type": "text", "text": "Reply with exactly: ok"}]}, "client_composed": True,
            "parent_tool_use_id": None, "uuid": session}
        init_reply = {"type": "control_response", "response": {
            "subtype": "success", "request_id": "fixture", "response": {
                "claude_code_version": "2.1.330", "models": [
                    {"value": "haiku", "resolvedModel": "claude-fixture", "displayName": "Fixture Haiku",
                     "description": "Synthetic", "supportsEffort": False}],
                "account": {"tokenSource": "claude.ai", "subscriptionType": "pro", "apiProvider": "firstParty"},
                "commands": [], "agents": [], "output_style": "default", "available_output_styles": ["default"],
            },
        }}
        good = list(turn(session))
        bad_index = {**good[1], "event": {**good[1]["event"], "index": False}}
        bad_role = {**good[6], "message": {**good[6]["message"], "role": "tool"}}
        bad_id = {**good[6], "message": {**good[6]["message"], "id": "another"}}
        bad_content = {**good[6], "message": {**good[6]["message"],
                                             "content": [{"type": "tool_use", "text": "ok"}]}}
        bad_count = {**good[-1], "num_turns": True}
        malformed_reply = {**init_reply, "response": {**init_reply["response"], "request_id": "wrong-id"}}
        cases = (
            ("valid", [init_reply], good, 1),
            ("unexpected control", [malformed_reply], good, 0),
            ("trailing control", [init_reply, init_reply], good, 0),
            ("boolean index", [init_reply], [good[0], bad_index, *good[2:]], 1),
            ("wrong assistant role", [init_reply], [*good[:6], bad_role, good[-1]], 1),
            ("wrong assistant id", [init_reply], [*good[:6], bad_id, good[-1]], 1),
            ("wrong assistant content", [init_reply], [*good[:6], bad_content, good[-1]], 1),
            ("boolean count", [init_reply], [*good[:-1], bad_count], 1),
            ("trailing turn", [init_reply], [*good, good[0]], 1),
        )
        for name, controls, output, sends in cases:
            with self.subTest(name=name), TemporaryDirectory() as directory:
                broker = Broker(Path(directory), SimpleNamespace(check=lambda: None),
                                {slot: SimpleNamespace(models=("haiku",))}, {slot: "fixture"})
                route = broker.offer(slot, "haiku")
                binding = broker.identify(route)
                route = broker.activate(binding, STOCK_MODEL)
                wire = []
                read_end, write_end = os.pipe()
                client, peer = socket.socketpair()

                with (os.fdopen(read_end, "rb") as native_out, os.fdopen(write_end, "wb") as native_in,
                      client, peer):
                    def inject(frames):
                        native_in.write(b"".join(encode(frame) for frame in frames))
                        native_in.flush()

                    def finish():
                        inject(output)
                        native_in.close()

                    def write(payload):
                        wire.append(json.loads(payload))

                    def flush():
                        inject(controls)

                    process = Mock(stdout=native_out, wait=lambda timeout: 0,
                                              stdin=SimpleNamespace(write=write, flush=flush, close=finish))

                    @contextmanager
                    def fake_native(_command):
                        yield process

                    args = [*PREFIX, "--model=haiku", "--include-partial-messages", f"--session-id={session}",
                            *SETTINGS]
                    peer.sendall(encode({"route": route, "argv": args}) + encode(init) + encode(prompt))
                    peer.shutdown(socket.SHUT_WR)
                    with patch("oc_orchestrator.claude.native_process", fake_native):
                        if name == "valid":
                            broker.serve(client)
                        else:
                            with self.assertRaises(ProtocolError):
                                broker.serve(client)
                    self.assertEqual(broker.sends, sends)
                    self.assertEqual(sum(frame["type"] == "user" for frame in wire), sends)
                    if name == "valid":
                        self.assertEqual(response(peer), b"".join(encode(frame) for frame in [init_reply, *good]))
                        self.assertEqual(broker.receipt, binding)
                        self.assertEqual(wire[0]["request"], {"subtype": "initialize"})
                    else:
                        self.assertEqual(response(peer), encode(init_reply) if sends else b"")
                        self.assertIsNone(broker.receipt)

    def test_claude_cleanup_recovers_directory_permissions_without_following_symlink(self):
        with TemporaryDirectory(dir="/tmp") as directory:
            parent = Path(directory)
            root = parent / "scratch"
            root.mkdir(mode=0o700)
            outside = parent / "outside"
            outside.mkdir()
            outside.chmod(0)

            def fail_after_frontend_write(*_args, **_kwargs):
                hostile = root / "state" / "hostile"
                hostile.mkdir()
                (hostile / "nested").mkdir()
                (hostile / "nested" / "file").write_text("fake job data")
                (hostile / "link").symlink_to(outside, target_is_directory=True)
                (hostile / "nested").chmod(0)
                hostile.chmod(0)
                raise CaptureError("synthetic frontend failed")

            original_chmod = os.chmod

            def older_kernel_chmod(path, mode, **kwargs):
                if kwargs.get("follow_symlinks") is False:
                    raise NotImplementedError("fchmodat2 unavailable")
                return original_chmod(path, mode, **kwargs)

            lifeline = SimpleNamespace(check=lambda: None, active=lambda: True)
            with (patch("oc_orchestrator.claude.mkdtemp", return_value=str(root)),
                  patch("oc_orchestrator.claude.seed"),
                  patch("oc_orchestrator.claude.os.chmod", new=older_kernel_chmod),
                  patch("oc_orchestrator.claude.capture", side_effect=fail_after_frontend_write)):
                with self.assertRaisesRegex(Failure, "within its bound"):
                    run_claude_proof(lifeline)
            self.assertFalse(root.exists())
            self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0)

    def test_claude_cleanup_retains_scratch_when_retirement_cannot_be_verified(self):
        with TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory) / "scratch"
            root.mkdir(mode=0o700)
            lifeline = SimpleNamespace(check=lambda: None, active=lambda: True)
            with (patch("oc_orchestrator.claude.mkdtemp", return_value=str(root)),
                  patch("oc_orchestrator.claude.seed"),
                  patch("oc_orchestrator.claude.Thread"),
                  patch("oc_orchestrator.claude.capture", side_effect=CaptureError("synthetic frontend failed")),
                  patch("oc_orchestrator.claude.Broker.retire", side_effect=OSError("synthetic failure"))):
                with self.assertRaisesRegex(Failure, "retirement could not be verified"):
                    run_claude_proof(lifeline)
            self.assertTrue((root / "workspace" / "job.txt").is_file())

    def test_claude_owner_retains_scratch_without_waiting_indefinitely_for_native_child(self):
        session = "00000000-0000-4000-8000-000000000001"
        args = [*PREFIX, "--model=haiku", "--include-partial-messages", f"--session-id={session}", *SETTINGS]
        started = Event()
        processes = []

        def record_process(_broker, _client, _stream, process, _binding, _session):
            process.wait = Mock(wraps=process.wait)
            processes.append(process)
            started.set()

        def run_frontend(root, stage, _lifeline, _broker):
            if stage == "discovery":
                return subprocess.CompletedProcess([], 0, stdout=STOCK_MODEL.encode() + b"\n")
            route = json.loads((root / "frontend" / "turn" / "route.json").read_text())
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.connect(str(root / "socket" / stage / "native.sock"))
                peer.sendall(encode({"route": route, "argv": args}))
                self.assertTrue(started.wait(timeout=3))
            return subprocess.CompletedProcess([], 1, stdout=b"")

        with TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory) / "scratch"
            root.mkdir(mode=0o700)
            lifeline = SimpleNamespace(check=lambda: None, active=lambda: True)
            try:
                with (patch("oc_orchestrator.claude.mkdtemp", return_value=str(root)),
                      patch("oc_orchestrator.claude.seed"),
                      patch("oc_orchestrator.claude.run_frontend", side_effect=run_frontend),
                      patch("oc_orchestrator.claude.native_command", return_value=["/usr/bin/sleep", "6"]),
                      patch("oc_orchestrator.claude.Broker.exchange", new=record_process),
                      patch("oc_orchestrator.claude.kill_group")):
                    with self.assertRaisesRegex(Failure, "retirement could not be verified"):
                        run_claude_proof(lifeline)
                self.assertEqual(processes[0].wait.call_args_list, [call(timeout=2)])
                self.assertIsNone(processes[0].poll())
                self.assertTrue(processes[0].stdin.closed)
                self.assertTrue(processes[0].stdout.closed)
                self.assertTrue((root / "workspace" / "job.txt").is_file())
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=2)

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
            broker = Broker(None, lifeline, {}, {})
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
