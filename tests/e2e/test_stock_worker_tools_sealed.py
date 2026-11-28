"""Inert checks for the sealed driver's native stock fixture contract."""

from copy import deepcopy
from importlib.util import find_spec
from io import BytesIO
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parent)]

from stock_worker_tools_history import digest
from stock_worker_tools_protocol import MODEL, FixtureMismatch
from stock_worker_tools_projection import CASE_LABELS, receive_case_label, receive_control
from stock_worker_tools_search import SEARCH_TOOLS, _SCHEMAS
import stock_worker_tools_sealed as sealed


class SealedSearchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.job = self.home / "opencode-sandbox/construct/search-proof"
        self.job.mkdir(parents=True)
        sealed.setup_search(self.job)
        self.script = sealed.scenario("sealed-search", self.home)
        self.run_id = "a" * 32
        self.session = "ses_sealed"
        self.definitions = [{**json.loads(_SCHEMAS[name]), "strict": False} for name in SEARCH_TOOLS]
        self.base = {"model": MODEL, "store": False, "stream": True, "include": ["reasoning.encrypted_content"],
                     "instructions": "Synthetic job fixture.", "prompt_cache_key": self.session,
                     "tools": self.definitions, "input": [{"type": "message", "role": "user",
                                 "content": [{"type": "input_text", "text": self.script.prompt}]}]}

    def steps(self, request, rows=()):
        with patch.object(sealed, "_TOOL_DEFINITIONS", {tool["name"]: digest(tool) for tool in self.definitions}):
            return self.script.steps(request, self.run_id, rows)

    def receipt(self, stage, body):
        claim = {"op": "claim", "stage": stage, "session": self.session, "prefix": digest(body["input"])}
        return claim, {"op": "submitted", "stage": stage, "claim": digest(claim), "shutdown": "peer_eof"}

    def append_result(self, body, stage, script=None):
        chosen = script or self.script
        identity = chosen.identity(self.run_id, stage)
        body["input"].extend([
            {"type": "function_call", "name": chosen.tools[stage], "call_id": identity,
             "arguments": json.dumps(chosen.arguments[stage])},
            {"type": "function_call_output", "call_id": identity, "output": chosen.outputs[stage]},
        ])

    def test_dispatch_refuses_drift_across_causal_prefix(self):
        initial = deepcopy(self.base)
        self.assertEqual(self.steps(initial), 0)
        rows = list(self.receipt(0, initial))
        continuation = deepcopy(initial)
        self.append_result(continuation, 0)
        self.assertEqual(self.steps(continuation, rows), 1)
        rows.extend(self.receipt(1, continuation))
        self.append_result(continuation, 1)
        self.assertEqual(self.steps(continuation, rows), 2)
        for change in ("schema", "call", "prior_result", "second_result", "session"):
            with self.subTest(change=change):
                altered = deepcopy(continuation)
                if change == "schema":
                    altered["tools"][0]["parameters"]["additionalProperties"] = True
                elif change == "call":
                    altered["input"][1]["arguments"] = "{}"
                elif change == "prior_result":
                    altered["input"][2]["output"] += " "
                elif change == "second_result":
                    altered["input"][4]["output"] += " "
                else:
                    altered["prompt_cache_key"] = "ses_other"
                with self.assertRaises(FixtureMismatch):
                    self.steps(altered, rows)
        with self.assertRaisesRegex(FixtureMismatch, "chat stage"):
            self.steps(continuation, rows[:-1])

    def test_denials_use_both_native_tools_and_explicit_missing_path(self):
        script = sealed.scenario("sealed-search-denials", self.home)
        self.assertEqual(script.tools, SEARCH_TOOLS)
        self.assertTrue(all(args["path"] == str(sealed.SEARCH_BOUNDARY) for args in script.arguments))
        for output in script.outputs:
            error = json.loads(output)
            self.assertEqual(error, {"content": [], "error": {
                "type": "tool.execution", "message": f"Search path does not exist: {sealed.SEARCH_BOUNDARY}"}})

    def test_single_private_journal_has_bounded_unique_case(self):
        payload = json.dumps({"case": "sealed-search", "run": self.run_id}).encode() + b"\n"
        self.assertEqual(sealed.read_journal(BytesIO(payload), "sealed-search"), (self.run_id, []))
        with self.assertRaises(FixtureMismatch):
            sealed.read_journal(BytesIO(payload[:-1]), "sealed-search")
        with self.assertRaises(FixtureMismatch):
            sealed.read_journal(BytesIO(payload), "sealed-search-denials")

    def test_question_answer_requires_exact_terminal_event_and_call(self):
        script = sealed.scenario("sealed-question", self.home)
        initial = deepcopy(self.base)
        initial["input"][0]["content"][0]["text"] = script.prompt
        request = deepcopy(initial)
        self.append_result(request, 0, script)
        rows = list(self.receipt(0, initial))
        definitions = {tool["name"]: digest(tool) for tool in self.definitions}
        with patch.object(sealed, "_TOOL_DEFINITIONS", definitions):
            with self.assertRaisesRegex(FixtureMismatch, "terminal answer"):
                script.steps(request, self.run_id, rows)
            decision = script.operator(self.run_id, self.session)
            self.assertEqual(script.steps(request, self.run_id, [*rows, decision]), 1)
            with self.assertRaises(FixtureMismatch):
                script.steps(request, "b" * 32, [*rows, decision])
            canceled = sealed.scenario("sealed-question-cancel", self.home)
            with self.assertRaisesRegex(FixtureMismatch, "terminal answer"):
                canceled.steps(request, self.run_id, [*rows, canceled.operator(self.run_id, self.session)])

    def test_controller_skill_is_separate_from_worker_inventory_and_rejects_replay(self):
        target = sealed.scenario("sealed-skill-boundary", self.home)
        initial = deepcopy(self.base)
        initial["input"][0]["content"][0]["text"] = target.prompt
        rows = list(self.receipt(0, initial))
        denied = deepcopy(initial)
        self.append_result(denied, 0, target)
        definitions = {tool["name"]: digest(tool) for tool in self.definitions}
        with patch.object(sealed, "_TOOL_DEFINITIONS", definitions):
            self.assertEqual(target.steps(denied, self.run_id, rows), 1)
            refused = {"op": "refused", "session": self.session, "prefix": digest(denied["input"])}
            with self.assertRaisesRegex(FixtureMismatch, "Repeated denied"):
                target.steps(denied, self.run_id, [*rows, refused])
            denied["input"][2]["output"] = sealed.CONTROLLER_SKILL_MARKER.decode()
            with self.assertRaisesRegex(FixtureMismatch, "protected synthetic marker"):
                target.steps(denied, self.run_id, rows)
        positive = sealed.interaction_config("sealed-skill")["permission"]["skill"]
        self.assertNotIn(sealed.CONTROLLER_SKILL_ID, positive)
        self.assertIn(sealed.CONTROLLER_SKILL_ID, sealed.interaction_config(target.case)["permission"]["skill"])

    def test_authority_and_peer_control_preserve_exact_long_case_label(self):
        label = max(CASE_LABELS, key=len)
        self.assertGreater(len(label), 16)
        channel, writer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with channel, writer:
            writer.sendall(b"ok:" + label)
            self.assertEqual(receive_case_label(channel), label.decode("ascii"))
            writer.sendall(b"ok:" + label + b"-trailing")
            with self.assertRaisesRegex(RuntimeError, "did not authorize"):
                receive_case_label(channel)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            writer.sendall(label)
            receive_control(channel, label, os.getpid(), os.geteuid())
            writer.sendall(label + b"-trailing")
            with self.assertRaisesRegex(RuntimeError, "did not match"):
                receive_control(channel, label, os.getpid(), os.geteuid())

    def test_post_bound_child_failure_keeps_only_approved_traceback_metadata(self):
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        import stock_worker_tools_projection as projection

        channel = MagicMock()
        inherited = MagicMock()
        remote = MagicMock()
        channel.sendmsg.return_value = len("sealed-search")
        child = MagicMock(pid=1234)
        child.wait.return_value = 1
        peers = MagicMock()
        fixture = projection.PROJECTED_TREE / "tests/e2e/stock_worker_tools_sealed.py"

        def launch_failed_child(*args, stderr, **options):
            trace = ("Traceback (most recent call last):\n"
                     f'  File "{fixture}", line 101, in steps\n'
                     "    private source line\n"
                     '  File "/unknown/private-basename.py", line 999, in secret\n'
                     "stock_worker_tools_protocol.FixtureMismatch: omitted private error text\n")
            stderr.write(trace.encode())
            stderr.flush()
            return child

        with patch.object(projection, "capsule", return_value=SimpleNamespace(uid=os.getuid())), \
                patch.object(projection, "process_start", return_value=5), \
                patch.object(projection, "require_authorized_launch", return_value="sealed-search"), \
                patch.object(projection.socket, "socketpair", return_value=(channel, inherited)), \
                patch.object(projection, "receive_control"), \
                patch.object(projection.subprocess, "Popen", side_effect=launch_failed_child), \
                patch.object(projection, "fixture_modules", return_value=peers):
            with self.assertRaisesRegex(RuntimeError, "unsuccessful"):
                with projection.spawn_peer("sealed-search", remote) as spawned:
                    self.assertIs(spawned, child)
        peers.receipt.assert_called_once_with(
            projection.TEST_HOME, "peer_post_bound_failed", peer_pid=1234,
            details={"case": "sealed-search", "kind": "fixture_mismatch",
                     "frames": [{"file": "stock_worker_tools_sealed.py", "line": 101}]},
        )

    def test_sealed_shape_does_not_report_unknown_keys_names_or_values(self):
        from stock_worker_tools_peer import sealed_request_shape
        shape = sealed_request_shape({
            "tools": [{"name": "unapproved-private-name", "description": "private tool data"},
                      {"name": "question", "description": "private description"}],
            "instructions": "private input text",
            "unapproved-private-key": "private value",
        })
        self.assertEqual(shape["extra_field_count"], 1)
        self.assertEqual(shape["declaration_count"], 2)
        self.assertEqual(shape["changed_full_definitions"], ["question"])
        self.assertNotIn("private", json.dumps(shape))

    def test_managed_stock_accepts_only_independently_measured_bash(self):
        bash = json.loads(
            '{"description":"Execute a shell command and return its output. Commands run on Linux using bash. Quote '
            'file paths containing spaces or special characters. Prefer dedicated tools over shell commands when '
            'possible. When output is large, the full result is saved to a file and a truncated preview is returned. '
            'Rely on automatic truncation unless filtering the output is more useful. Commands accept an optional '
            'timeout, background commands have no timeout by default. Background commands return immediately, and you '
            'will be notified when they complete.","name":"shell","parameters":{"additionalProperties":false,"properti'
            'es":{"background":{"description":"Run the command in the background and return immediately (useful for '
            "dev servers and long-running builds). You do not need to use '&' at the end of the command when using "
            'this parameter. You will be notified when it completes. DO NOT poll for '
            'completion.","type":"boolean"},"command":{"description":"Shell command string to '
            'execute","type":"string"},"timeout":{"description":"Timeout in milliseconds. Set to 0 to disable the '
            'timeout. Defaults to 120000 for foreground commands. Background commands have no timeout by '
            'default.","minimum":0,"type":"integer"},"workdir":{"description":"Working directory to execute the '
            'command in. Defaults to the current working directory. When possible, avoid changing directories in the '
            'command and set the working directory here '
            'instead.","type":"string"}},"required":["command"],"type":"object"},"strict":false,"type":"function"}'
        )
        request = deepcopy(self.base)
        request["tools"].append(bash)
        loopback = deepcopy(bash)
        loopback["description"] = loopback["description"].replace("Linux using bash.", "Linux using sh.")
        names = {tool["name"]: digest(tool) for tool in [*self.definitions, loopback]}
        with patch.object(sealed, "_TOOL_DEFINITIONS", names):
            self.assertEqual(self.script.steps(request, self.run_id, []), 0)
            for kind in ("sh", "zsh", "mutated_description", "mutated_schema"):
                with self.subTest(kind=kind):
                    bad = deepcopy(request)
                    definition = bad["tools"][-1]
                    if kind in {"sh", "zsh"}:
                        definition["description"] = definition["description"].replace("Linux using bash.",
                                                                                        f"Linux using {kind}.")
                    elif kind == "mutated_description":
                        definition["description"] += " "
                    else:
                        definition["parameters"]["additionalProperties"] = True
                    with self.assertRaisesRegex(FixtureMismatch, "sealed stock Bash declaration"):
                        self.script.steps(bad, self.run_id, [])

    def test_optional_shape_provision_pressure_preserves_required_bootstrap(self):
        import errno
        import stock_worker_tools_guest as guest

        evidence = self.home / "fixture"
        open_file = os.open

        def exhausted(path, flags, *args, **kwargs):
            if Path(path).name == "peer-shapes.jsonl":
                raise OSError(errno.ENOSPC, "synthetic shape allocation failure")
            return open_file(path, flags, *args, **kwargs)

        with patch.multiple(guest, EVIDENCE=evidence, LOG=evidence / "peer.jsonl",
                            HOLDERS=(), STATE=self.home / "registration", CONFIG=self.home / "config",
                            SANDBOX=self.home / "work"), \
                patch.object(guest.os, "open", side_effect=exhausted), \
                patch.object(guest.runpy, "run_path"), \
                patch.object(guest, "ProfileBackend") as backend:
            guest.bootstrap()
        self.assertEqual((evidence / "peer.jsonl").read_bytes(), b"")
        self.assertEqual((evidence / "tool-state.json").read_text(), "[]")
        self.assertFalse(os.path.lexists(evidence / "peer-shapes.jsonl"))
        backend.return_value.connect.assert_called_once()

    def test_optional_shape_provision_refuses_existing_and_unsafe_leaves(self):
        import errno
        import stock_worker_tools_guest as guest

        directory = self.home / "fixture"
        directory.mkdir(mode=0o700)
        leaf = directory / "peer-shapes.jsonl"
        leaf.symlink_to(directory / "missing")
        with self.assertRaises(FileExistsError):
            guest.provision_shape_log(directory)
        self.assertTrue(leaf.is_symlink())
        leaf.unlink()
        leaf.write_text("existing fixture data")
        leaf.chmod(0o600)
        with self.assertRaises(FileExistsError):
            guest.provision_shape_log(directory)

        open_file = os.open

        def pressured(path, flags, *args, **kwargs):
            if path == "peer-shapes.jsonl":
                raise OSError(errno.EDQUOT, "synthetic quota failure")
            return open_file(path, flags, *args, **kwargs)

        with patch.object(guest.os, "open", side_effect=pressured):
            with self.assertRaises(OSError) as raised:
                guest.provision_shape_log(directory)
        self.assertEqual(raised.exception.errno, errno.EDQUOT)
        self.assertEqual(leaf.read_text(), "existing fixture data")
        leaf.unlink()

        def unauthorized(path, flags, *args, **kwargs):
            if path == "peer-shapes.jsonl":
                raise PermissionError(errno.EACCES, "synthetic unsafe permission failure")
            return open_file(path, flags, *args, **kwargs)

        with patch.object(guest.os, "open", side_effect=unauthorized):
            with self.assertRaises(PermissionError):
                guest.provision_shape_log(directory)
        self.assertFalse(os.path.lexists(leaf))

    def test_shell_shape_reports_only_fixed_match_booleans(self):
        from stock_worker_tools_peer import sealed_request_shape
        source = {"name": "shell", "type": "function", "strict": False, "description": "do not retain input",
                  "parameters": {"properties": {"synthetic": {"description": "do not retain values"}}}}
        envelope = sealed_request_shape({"tools": [source]})
        self.assertEqual(envelope["shell"], {"category": "stock_function_shape", "matches_managed_definition": False,
                                             "matches_pinned_schema": False})
        self.assertEqual(envelope["changed_full_definitions"], ["shell"])
        self.assertNotIn("do not retain", json.dumps(envelope))

    def test_optional_shape_write_failure_does_not_mask_primary_validator_failure(self):
        from unittest.mock import MagicMock
        import stock_worker_tools_peer as peer

        error = FixtureMismatch("synthetic primary request validation")
        paths = []

        def fail_shape_open(path, flags):
            paths.append(path.name)
            raise OSError("synthetic diagnostic file failure")

        channel = MagicMock()
        with patch.object(peer, "private_file", side_effect=fail_shape_open), \
                patch.object(peer, "scenario", side_effect=error) as validate:
            with self.assertRaises(FixtureMismatch) as raised:
                peer.sealed_response(self.home, "sealed-search", {"authorization": "Bearer test-access"},
                                     b'{}', channel)
        self.assertIs(raised.exception, error)
        self.assertEqual(paths, ["peer-shapes.jsonl"])
        validate.assert_called_once_with("sealed-search", self.home)
        channel.sendall.assert_not_called()

    def run_real_fixture_tls(self, fault=None):
        from concurrent.futures import ThreadPoolExecutor
        from contextlib import closing
        from datetime import datetime, timedelta, timezone
        import ssl
        import time

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        from oc_openai.connection_state import ConnectionError as BrokerError
        from oc_openai.responses import Cancellation, _StrictResponse, _StreamEvidence, _events
        from stock_worker_tools_peer import sealed_response

        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.openai.com")])
        now = datetime.now(timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                       .not_valid_after(now + timedelta(minutes=5))
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.openai.com")]), critical=False)
                       .sign(key, hashes.SHA256()))
        pem, private = self.home / "fixture.pem", self.home / "fixture-key.pem"
        pem.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        private.chmod(0o600)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(pem, private)
        client_ctx = ssl.create_default_context(cafile=str(pem))
        case = "sealed-search"
        journal = sealed.journal_path(self.home, case)
        journal.parent.mkdir(mode=0o700, exist_ok=True)
        journal.write_text(json.dumps({"case": case, "run": self.run_id}) + "\n")
        lifecycle = journal.parent / "peer.jsonl"
        lifecycle.touch(mode=0o600)
        journal.chmod(0o600)

        class FaultyChannel:
            def __init__(self, tls):
                self.tls = tls

            def sendall(self, packet):
                if fault == "incomplete":
                    # Send a real TLS record with an incomplete HTTP body.
                    header_end = packet.index(b"\r\n\r\n") + 4
                    self.tls.sendall(packet[:header_end + 7])
                    raise BrokenPipeError("synthetic interrupted send")
                self.tls.sendall(packet)

            def unwrap(self):
                if fault == "abrupt":
                    # Close the actual TLS socket without sending an alert.
                    self.tls.close()
                    raise ConnectionResetError("synthetic abrupt server close")
                if fault == "timeout":
                    raise TimeoutError("synthetic TLS shutdown deadline")
                return self.tls.unwrap()

        client, server = socket.socketpair()
        client.settimeout(3)
        server.settimeout(3)

        def peer():
            with server_ctx.wrap_socket(server, server_side=True) as tls:
                channel = tls if fault is None else FaultyChannel(tls)
                sealed_response(self.home, case, {"authorization": "Bearer test-access"},
                                json.dumps(self.base), channel)

        completed = []
        evidence = _StreamEvidence()
        definitions = {tool["name"]: digest(tool) for tool in self.definitions}
        with patch.object(sealed, "_TOOL_DEFINITIONS", definitions), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(peer)
            with client_ctx.wrap_socket(client, server_hostname="api.openai.com", suppress_ragged_eofs=False) as tls:
                with closing(_StrictResponse(tls, method="POST", keep_fp=True)) as response:
                    response.begin()
                    options = {"require_tls_close": True, "strict_terminal": True}
                    stream = _events(response, Cancellation(time.monotonic() + 5), evidence, **options)
                    if fault is None:
                        completed = list(stream)
                    else:
                        with self.assertRaises((BrokerError, OSError)):
                            for event in stream:
                                if event["type"] == "response.completed":
                                    completed.append(event)
            # Deliberately close instead of unwrap on the client, matching
            # the unmodified broker after it verifies the server's alert.
            if fault is None:
                future.result(timeout=4)
            else:
                error = {"incomplete": BrokenPipeError, "abrupt": ConnectionResetError, "timeout": TimeoutError}[fault]
                with self.assertRaises(error):
                    future.result(timeout=4)

        with journal.open("rb") as stream:
            _, rows = sealed.read_journal(stream, case)
        events = [json.loads(line) for line in lifecycle.read_text().splitlines()]
        return rows, events, completed, evidence

    @unittest.skipUnless(find_spec("cryptography"), "synthetic TLS certificate dependency unavailable")
    def test_real_one_way_tls_records_submission_without_delivery_or_usage(self):
        rows, events, received, evidence = self.run_real_fixture_tls()
        claims, submissions = sealed.verified_rows(rows)
        self.assertEqual(len(claims), 1)
        self.assertEqual(submissions, [{"op": "submitted", "stage": 0, "claim": digest(claims[0]),
                                         "shutdown": "peer_eof"}])
        self.assertEqual([entry["op"] for entry in events], ["sealed_submission"])
        self.assertTrue(evidence.http_body_verified)
        self.assertEqual(evidence.tls_close, "clean")
        self.assertEqual(received[-1]["type"], "response.completed")
        self.assertEqual(received[-1]["response"]["usage"]["total_tokens"], 5)
        with self.assertRaisesRegex(FixtureMismatch, "usage"):
            sealed.verify_usage([], 1)

    @unittest.skipUnless(find_spec("cryptography"), "synthetic TLS certificate dependency unavailable")
    def test_real_abrupt_or_incomplete_tls_preserves_unresolved_claim(self):
        for fault in ("abrupt", "incomplete", "timeout"):
            with self.subTest(fault=fault):
                rows, events, received, evidence = self.run_real_fixture_tls(fault)
                claims, submissions = sealed.verified_rows(rows)
                self.assertEqual(len(claims), 1)
                self.assertEqual(submissions, [])
                self.assertEqual(events, [])
                self.assertEqual(received, [])
                self.assertNotEqual(evidence.tls_close, "clean")
                journal = sealed.journal_path(self.home, "sealed-search")
                journal.unlink()
                (journal.parent / "peer.jsonl").unlink()

    def test_skill_chat_diagnostic_preserves_refusal_and_only_reports_known_shape(self):
        from unittest.mock import MagicMock
        from stock_worker_tools_peer import sealed_response

        case = "sealed-skill"
        script = sealed.scenario(case, self.home)
        journal = sealed.journal_path(self.home, case)
        journal.parent.mkdir(mode=0o700)
        header = {"case": case, "run": self.run_id}
        shape_log = journal.parent / "peer-shapes.jsonl"
        shape_log.touch(mode=0o600)
        definitions = {tool["name"]: digest(tool) for tool in self.definitions}
        original = deepcopy(self.base)
        original["input"][0]["content"][0]["text"] = script.prompt
        stage_zero = deepcopy(original)
        stage_zero["input"].append({"type": "unknown-identifier", "role": "private-role", "content": "private-body"})
        continued = deepcopy(original)
        self.append_result(continued, 0, script)
        continued["input"].append({"type": "message", "role": "assistant", "content": "another-private-body"})

        for body, rows, count, extra in (
            (stage_zero, [], 2, {"type": "other", "role": "other"}),
            (continued, self.receipt(0, original), 4, {"type": "message", "role": "assistant"}),
        ):
            with self.subTest(stage=len(rows) // 2):
                data = "".join(json.dumps(item) + "\n" for item in (header, *rows))
                journal.write_text(data)
                journal.chmod(0o600)
                shape_log.write_text("")
                channel = MagicMock()
                with patch.object(sealed, "_TOOL_DEFINITIONS", definitions):
                    with self.assertRaisesRegex(FixtureMismatch, "stock chat stage"):
                        sealed_response(self.home, case, {"authorization": "Bearer test-access"}, json.dumps(body), channel)
                channel.sendall.assert_not_called()
                self.assertEqual(journal.read_text(), data)
                (receipt,) = [json.loads(line)["details"] for line in shape_log.read_text().splitlines()
                              if json.loads(line)["op"] == "sealed_chat_shape"]
                self.assertEqual(receipt, {
                    "case": case, "stage": len(rows) // 2,
                    "prior_submission_count": len(rows) // 2, "prior_submissions_match_stage": True,
                    "stage_in_bounds": True, "input_count": count, "input_count_matches_stage": False,
                    "input_items": [{"type": "message", "role": "user"}]
                                   + ([{"type": "function_call", "role": "missing"},
                                       {"type": "function_call_output", "role": "missing"}] if rows else [])
                                   + [extra],
                    "input_items_omitted": 0, "initial_user_matches": True,
                    "claimed_session_matches": True if rows else None,
                    "matching_prior_call_count": len(rows) // 2, "matching_prior_result_count": len(rows) // 2,
                    "matching_prior_pair_count": len(rows) // 2,
                })

    def test_chat_shape_initial_mismatch_and_truncation_are_explicit(self):
        from stock_worker_tools_peer import sealed_chat_shape

        body = {"input": [{"type": "message", "role": "user", "content": "private"}
                          for _ in range(18)]}
        report = sealed_chat_shape(body, sealed.scenario("sealed-skill", self.home), self.run_id, [])
        self.assertFalse(report["initial_user_matches"])
        self.assertEqual(report["input_count"], 18)
        self.assertEqual(len(report["input_items"]), 12)
        self.assertEqual(report["input_items_omitted"], 6)
        self.assertNotIn("private", json.dumps(report))

    def test_driver_finishes_other_worker_cases_before_cancel_and_restores_scope(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from types import SimpleNamespace

        import stock_worker_tools_guest as guest

        actual_config = sealed.interaction_config("sealed-skill")
        cases, changes = [], []

        def replace_config(old, new):
            nonlocal actual_config
            self.assertEqual(old, actual_config)
            actual_config = new
            changes.append(new)

        def run_case(state, case, check_inventory):
            cases.append(case)
            self.assertEqual(actual_config, sealed.interaction_config(case))
            return {"case": case}

        output = StringIO()
        with patch.multiple(guest, capsule=lambda: SimpleNamespace(uid=1002, source_sha256="fixture",
                                                                 projection_sha256="fixture"),
                            verify=lambda *args: {"inventory": {}}, bootstrap=lambda: None,
                            launch=lambda *args, **kwargs: None, inventory=lambda *_: {},
                            seed_legacy_marker=lambda: None, verify_support_inventory=lambda *_: None,
                            prepare_search=lambda: self.job, run_sealed_search=lambda *args: {},
                            prepare_interaction=lambda: None, run_sealed_interaction=run_case,
                            replace_worker_config=replace_config), \
                patch.object(sys, "argv", ["synthetic-fixture"]), redirect_stdout(output):
            guest.main()
        self.assertEqual(cases, ["sealed-question", "sealed-skill", "sealed-skill-boundary", "sealed-question-cancel"])
        self.assertEqual(changes, [sealed.interaction_config("sealed-skill-boundary"),
                                   sealed.interaction_config("sealed-question-cancel")])
        self.assertEqual(len(json.loads(output.getvalue())["sealed_interaction"]), 4)

    def test_resume_notice_does_not_qualify_as_a_fresh_skill_case(self):
        from unittest.mock import MagicMock
        from stock_worker_tools_peer import sealed_response

        case = "sealed-skill"
        script = sealed.scenario(case, self.home)
        journal = sealed.journal_path(self.home, case)
        journal.parent.mkdir(mode=0o700)
        initial = json.dumps({"case": case, "run": self.run_id}) + "\n"
        journal.write_text(initial)
        journal.chmod(0o600)
        (journal.parent / "peer-shapes.jsonl").touch(mode=0o600)
        body = deepcopy(self.base)
        body["input"][0]["content"][0]["text"] = script.prompt
        body["input"].append({
            "type": "message", "role": "user", "content": [{"type": "input_text", "text":
                "The server restarted while you were working. Continue from where you left off without repeating completed work."}],
        })
        channel = MagicMock()
        definitions = {tool["name"]: digest(tool) for tool in self.definitions}
        with patch.object(sealed, "_TOOL_DEFINITIONS", definitions):
            with self.assertRaisesRegex(FixtureMismatch, "stock chat stage"):
                sealed_response(self.home, case, {"authorization": "Bearer test-access"}, json.dumps(body), channel)
        channel.sendall.assert_not_called()
        self.assertEqual(journal.read_text(), initial)
        shape = json.loads((journal.parent / "peer-shapes.jsonl").read_text().splitlines()[-1])
        self.assertEqual(shape["op"], "sealed_chat_shape")
        self.assertEqual(shape["details"]["stage"], 0)
        self.assertFalse(shape["details"]["input_count_matches_stage"])

    def run_search_usage_probe(self, readings, on_close):
        from unittest.mock import MagicMock
        import stock_worker_tools_guest as guest

        case = "sealed-search-denials"
        script = MagicMock(prompt="synthetic search", reply="synthetic reply")
        terminal = MagicMock()
        broker_events = []
        claims = [{"session": self.session}] * 3

        def launch(_state, launched, active, *, verify_inventory):
            self.assertEqual(launched, case)
            active(terminal, "fixture-worker", None, None, 0)
            on_close()
            broker_events.extend({"op": "sealed_submission", "details": {"case": case, "stage": stage}}
                                 for stage in range(3))

        with patch.multiple(guest, scenario=lambda *_: script, search_inventory=lambda *_: (),
                            verify_search_control=lambda: None, events=lambda: broker_events,
                            private_write=lambda *_: None, verify_worker_title_settings=lambda *_: None,
                            stock_sessions=lambda *_: set(), await_native_export=lambda *_: {"synthetic": True},
                            sealed_records=lambda *_: ("synthetic-run", []),
                            verified_rows=lambda *_: (claims, [None] * 3), launch=launch), \
                patch.object(guest, "bounded_usage", side_effect=readings), patch.object(guest.time, "sleep"):
            return guest.run_sealed_search(object(), case, self.job, lambda: None)

    def test_search_waits_for_delayed_matching_usage_before_normal_close(self):
        prior = b'{"earlier":"fixture"}\n'
        complete = {"profile": "harbor", "model": MODEL, "outcome": "completed",
                    "input_tokens": 2, "output_tokens": 3}
        line = (json.dumps(complete) + "\n").encode("ascii")
        closed = []
        deferred = iter([prior, prior + line * 2, prior + line * 3, prior + line * 3])
        reads = []

        def read():
            snapshot = next(deferred)
            reads.append(snapshot)
            return snapshot

        outcome = self.run_search_usage_probe(read, lambda: closed.append(len(reads)))
        self.assertEqual(closed, [3])
        self.assertEqual(outcome["broker_verified_completions"], 3)

    def test_search_refuses_wrong_or_interleaved_rows_before_closure_and_late_extras_after(self):
        prior = b'{"earlier":"fixture"}\n'
        complete = {"profile": "harbor", "model": MODEL, "outcome": "completed",
                    "input_tokens": 2, "output_tokens": 3}

        def encoded(row):
            return (json.dumps(row) + "\n").encode("ascii")

        good = encoded(complete)
        bad = encoded({**complete, "outcome": "session_revoked", "input_tokens": None, "output_tokens": None})
        full = prior + good * 3
        cases = (
            ([prior, prior + good + bad], "Broker usage did not match", []),
            ([prior, prior + good * 2, full + good], "Unexpected extra", []),
            ([prior, full, full + good], "changed after acknowledgement", [True]),
            ([prior, prior + good * 2, prior + good], "changed while awaiting", []),
        )
        for readings, error, expected_closure in cases:
            with self.subTest(error=error):
                closed = []
                with self.assertRaisesRegex(FixtureMismatch, error):
                    self.run_search_usage_probe(readings, lambda: closed.append(True))
                self.assertEqual(closed, expected_closure)

    def test_broker_usage_ack_observes_writer_lock_and_preserves_refusal_shape(self):
        import fcntl
        import stock_worker_tools_guest as guest

        complete = {"profile": "harbor", "model": MODEL, "outcome": "completed",
                    "input_tokens": 2, "output_tokens": 3}
        refused = {**complete, "outcome": "chatgpt_auth_rejected", "input_tokens": None, "output_tokens": None}
        path = self.home / guest.USAGE_LOG_NAME
        with path.open("wb") as writer, patch.object(guest, "STATE", self.home):
            path.chmod(0o600)
            fcntl.flock(writer, fcntl.LOCK_EX)
            writer.write(b"".join((json.dumps(row) + "\n").encode("ascii") for row in (complete, refused)))
            writer.flush()
            self.assertIsNone(guest.bounded_usage())
            fcntl.flock(writer, fcntl.LOCK_UN)
            acknowledged = guest.await_usage_acknowledgement(b"", 1, refused=True)
            guest.verify_retired_usage(b"", acknowledged, 1, refused=True)
            with self.assertRaisesRegex(FixtureMismatch, "extra sealed broker usage"):
                guest.await_usage_acknowledgement(b"", 1)

    def test_kernel_mount_proof_rejects_exact_substitution_and_sentinel_alias(self):
        from stock_worker_tools_mounts import Binding, Identity, parse_mounts, verify_bindings
        # On Btrfs a subvolume's st_dev can differ from the mount table's
        # superblock device. The two identities must be compared independently.
        host = parse_mounts("40 1 0:38 /@home /home rw - btrfs /dev/root rw")[40]
        ids = {"/sandbox": Identity(63, 102, 2)}
        expected = {"/sandbox": (Binding(host, Path("/home/job"), Identity(63, 102, 40)), True)}
        sentinel = Binding(host, Path("/home/control/protected.sample"), Identity(63, 103, 40))
        parent = ("1 0 0:61 / / rw - overlay overlay rw\n"
                  "3 1 1:1 / /proc rw - proc proc rw\n"
                  "4 1 1:2 /../../.. /sys/fs/cgroup ro - cgroup2 cgroup2 rw\n")
        good = parent + "2 1 0:38 /@home/job /sandbox rw - btrfs /dev/root rw"
        verify_bindings(parse_mounts(good), expected, ids, [sentinel])
        variants = (
            ("substituted backing", good.replace("/@home/job", "/@home/other"), ids, "pinned source"),
            ("substituted inode", good, {"/sandbox": Identity(63, 104, 2)}, "pinned source"),
            ("different effective mount", good, {"/sandbox": Identity(63, 102, 3)}, "mount identity"),
            ("wrong mode", good.replace("/sandbox rw", "/sandbox ro"), ids, "access mode"),
            ("alternate sentinel bind", good + "\n5 1 0:38 /@home/control /alias ro - btrfs /dev/root rw",
             ids, "sentinel backing"),
            ("shadowed sentinel path", good + "\n5 1 1:3 / /home/control ro - tmpfs tmpfs rw",
             ids, "protected controller path"),
            ("nested runtime shadow", good + "\n5 2 1:3 / /sandbox/sub ro - tmpfs tmpfs rw",
             ids, "shadows"),
        )
        for label, table, observation, error in variants:
            with self.subTest(label=label), self.assertRaisesRegex(FixtureMismatch, error):
                verify_bindings(parse_mounts(table), expected, observation, [sentinel])

    def test_protected_search_would_match_control_and_cannot_carry_complete_marker(self):
        from fnmatch import fnmatchcase

        script = sealed.scenario("sealed-search-denials", self.home)
        glob, grep = script.arguments
        self.assertEqual(glob["pattern"], sealed.SEARCH_SENTINEL.name)
        self.assertTrue(fnmatchcase(sealed.SEARCH_SENTINEL.name, glob["pattern"]))
        needle = grep["pattern"].encode("ascii")
        marker = sealed.SEARCH_SENTINEL_BYTES.strip()
        self.assertIn(needle, marker)
        self.assertNotEqual(needle, marker)
        self.assertIs(grep["literal"], True)
        self.assertNotIn(marker, json.dumps(script.arguments).encode())
        self.assertNotIn(marker, json.dumps(script.outputs).encode())
        sealed.verify_search_control_match(sealed.SEARCH_SENTINEL.name, sealed.SEARCH_SENTINEL_BYTES)
        with self.assertRaisesRegex(FixtureMismatch, "known-present control"):
            sealed.verify_search_control_match("another.sample", sealed.SEARCH_SENTINEL_BYTES)
        with self.assertRaisesRegex(FixtureMismatch, "known-present control"):
            sealed.verify_search_control_match(sealed.SEARCH_SENTINEL.name, b"different benign value\n")
        request = deepcopy(self.base)
        request["instructions"] = marker.decode("ascii")
        with self.assertRaisesRegex(FixtureMismatch, "protected synthetic marker"):
            self.steps(request)


if __name__ == "__main__":
    unittest.main()
