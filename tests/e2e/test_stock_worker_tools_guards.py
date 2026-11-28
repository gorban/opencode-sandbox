"""Inert guards for the offline worker-tools proof fixtures."""

from copy import deepcopy
from io import StringIO
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(Path(__file__).resolve().parent)]

from oc_openai.session_broker import SessionBroker
from oc_openai.session_protocol import ReasoningVault, SessionStreamProjector, StreamAborted
from stock_worker_tools_capture import Terminal, await_idle, verify_scope
from stock_worker_tools_guest import (
    HOLD_READER, TCP_CONNECT, WIRE, broker_exchange, confirm_foreground, reap_held_child, run_cleanup,
    verify_direct_broker, verify_loopback_listener, verify_outside_candidates, verify_relay_mcs,
)
from stock_worker_tools_host import firewall_shape
from stock_worker_tools_projection import capsule, describe_source, project_sources
from stock_worker_tools_protocol import (
    LABEL, MODEL, PROMPT, PROVIDER, REFUSED_FILE, TITLE, TITLE_PROMPT, TOOL_NAMES, FixtureMismatch, ToolScript, call_id,
    expected_result, refused_events, response_events,
)


class CaptureGuardTests(unittest.TestCase):
    def test_refuses_non_loopback_namespace_before_workspace_access(self):
        with patch("stock_worker_tools_capture.socket.if_nameindex", return_value=[(1, "lo"), (2, "eth0")]):
            with self.assertRaisesRegex(FixtureMismatch, "loopback-only"):
                verify_scope()

    def test_capsule_cannot_run_from_checkout(self):
        with self.assertRaisesRegex(RuntimeError, "outside its fixed root-owned"):
            capsule()

    def test_copied_projection_mutates_only_the_exact_tls_function(self):
        source = ROOT / "oc_openai/responses.py"
        with tempfile.TemporaryDirectory() as work:
            location = Path(work) / "oc_openai"
            location.mkdir()
            copied = location / source.name
            before = source.read_text()
            copied.write_text(before)
            project_sources(Path(work))
            after = copied.read_text()
            marker = "def _connect(host, cancellation):\n"
            boundary = "\n\ndef _validate_http(response):"
            self.assertEqual(before.split(marker)[0], after.split(marker)[0])
            self.assertEqual(before.split(boundary)[1], after.split(boundary)[1])
            self.assertIn("stock_worker_tools_projection.py", after)
            compile(after, str(copied), "exec")
            copied.write_text(before.replace(marker, "def different_function():\n"))
            with self.assertRaisesRegex(RuntimeError, "TLS seam changed"):
                project_sources(Path(work))

    def test_source_inventory_covers_driver_and_real_admission(self):
        files = describe_source(ROOT)
        for name in ("oc-sandbox", "oc-openai-session.py", "oc_openai/session_protocol.py",
                     "oc_openai/session_broker.py", "tests/e2e/stock_worker_tools_guest.py",
                     "tests/e2e/stock_worker_tools_peer.py"):
            self.assertIn(name, files)


class DriverGuardTests(unittest.TestCase):
    def test_foreground_wait_returns_the_matching_terminal_capture(self):
        term = Terminal(Path("/tmp/unopened"), {})
        expected = "Start interactive OpenCode session for instance 'default'? [y/N]"
        with patch.object(term, "run", return_value=expected + "\n"):
            self.assertEqual(term.await_screen(lambda line: expected in line, "route approval"), expected + "\n")

    def test_http_status_survives_timeout_after_headers(self):
        request = {"host": "127.0.0.1", "port": 8401, "method": "GET",
                   "path": "/v1/models", "body": None, "token": "test"}
        response = MagicMock(status=200)
        response.read.side_effect = TimeoutError("body did not arrive")
        stdout = StringIO()
        with patch("http.client.HTTPConnection") as connection, patch("sys.stdout", stdout), \
                patch("sys.stdin", StringIO(json.dumps(request))):
            connection.return_value.getresponse.return_value = response
            exec(WIRE, {})
            connection.return_value.close.assert_called_once_with()
        self.assertEqual(json.loads(stdout.getvalue()), {"status": 200, "body": ""})

    def test_egress_probe_performs_only_bounded_socket_connect(self):
        stdout = StringIO()
        with patch("socket.create_connection") as connect, patch("sys.stdout", stdout), \
                patch("sys.stdin", StringIO('["192.0.2.1", 443]')):
            exec(TCP_CONNECT, {})
        connect.assert_called_once_with(("192.0.2.1", 443), timeout=3)
        self.assertTrue(json.loads(stdout.getvalue()))
        self.assertEqual([entry[0] for entry in connect.return_value.mock_calls], ["__enter__", "__exit__"])

    def test_held_reader_reap_escalates_and_bounds_both_waits(self):
        child = MagicMock()
        child.poll.return_value = None
        timeout = subprocess.TimeoutExpired("held-reader", 2)
        child.wait.side_effect = [timeout, timeout]
        with self.assertRaises(subprocess.TimeoutExpired):
            reap_held_child(child)
        self.assertEqual(child.mock_calls, [
            call.poll(), call.terminate(), call.wait(timeout=2), call.kill(), call.wait(timeout=2),
        ])

    def test_outside_tcp_connection_without_http_headers_is_still_reachable(self):
        request = {"host": "192.0.2.1", "port": 8401, "method": "GET",
                   "path": "/v1/models", "body": None, "token": "test"}
        stdout = StringIO()
        with patch("http.client.HTTPConnection") as connection, patch("sys.stdout", stdout), \
                patch("sys.stdin", StringIO(json.dumps(request))):
            connection.return_value.getresponse.side_effect = ConnectionResetError()
            exec(WIRE, {})
        self.assertIsNone(json.loads(stdout.getvalue())["status"])  # The earlier predicate accepted this.
        host, sibling = object(), object()
        with patch("stock_worker_tools_guest.tcp_connect", side_effect=[False, False, False, True]) as connect:
            with self.assertRaisesRegex(FixtureMismatch, "independently networked container connected"):
                verify_outside_candidates(host, sibling, ("192.0.2.1",))
        self.assertEqual(connect.call_args_list, [
            call(host, "127.0.0.1", 8401), call(sibling, "127.0.0.1", 8401),
            call(host, "192.0.2.1", 8401), call(sibling, "192.0.2.1", 8401),
        ])

    def test_direct_broker_control_authenticates_the_exact_private_frame(self):
        support = runpy.run_path(str(ROOT / "tests/test_openai_session_broker.py"))
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        lease, fd = support["_make_lease"](root)
        self.addCleanup(os.close, fd)
        (root / "provider").mkdir()
        (root / "proof").mkdir()
        proof = os.urandom(32)
        (root / "proof/relay").write_bytes(proof)
        upstream = MagicMock(side_effect=AssertionError("Local model catalog must not dispatch upstream"))
        broker = SessionBroker(socket_path=root / "provider/provider.sock", relay_proof=proof,
                               worker_token="test-token", lease=lease, connection=support["_FakeConn"](upstream),
                               binding=object(), models=(MODEL,), profile_label=LABEL)
        broker.start()
        self.addCleanup(broker.close)
        # The earlier unframed probe closes regardless of whether the caller knows the actual proof.
        raw = (b"GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n"
               b"Authorization: Bearer test-token\r\n\r\n")
        self.assertEqual(broker_exchange(broker.socket_path, raw), b"")
        verify_direct_broker(root, "test-token")
        with patch("stock_worker_tools_guest.broker_exchange", return_value=b""):
            with self.assertRaisesRegex(FixtureMismatch, "framed private relay control"):
                verify_direct_broker(root, "test-token")
        upstream.assert_not_called()

    def test_foreground_checks_complete_disclosure_before_sending_yes(self):
        provider = (f"Provider openai/{LABEL} [{PROVIDER}]: auth=subscription, "
                    f"policy=subscription (no verified spending ceiling) (models: {MODEL})")
        launch = (f"Initial active model: {PROVIDER}/{MODEL} | UI: OpenCode (default) | "
                  "Workspace: /sandbox/construct")
        prompt = "Start interactive OpenCode session for instance 'default'? [y/N]"
        term = MagicMock()
        for altered in (launch.replace(MODEL, MODEL + "-unexpected"), launch + "/unexpected"):
            with self.subTest(altered=altered), patch("stock_worker_tools_guest.assert_no_slot") as no_slot:
                term.await_screen.return_value = "\n".join(
                    (provider, altered, "No API-key fallback will be forwarded.", prompt))
                # Both prefixes matched the earlier launcher predicate.
                self.assertIn(f"Initial active model: {PROVIDER}/{MODEL}", altered)
                self.assertIn("Workspace: /sandbox/construct", altered)
                with self.assertRaisesRegex(FixtureMismatch, "differs from the approved launch"):
                    confirm_foreground(term, approve=True)
                term.type_line.assert_not_called()
                no_slot.assert_not_called()
        term.await_screen.return_value = "\n".join((provider, launch, "No API-key fallback will be forwarded.", prompt))
        with patch("stock_worker_tools_guest.assert_no_slot") as no_slot:
            confirm_foreground(term, approve=True)
        no_slot.assert_called_once_with()
        term.type_line.assert_called_once_with("y")

    def test_idle_requires_the_final_title(self):
        pending = {"messages": [{"type": "idle"}], "info": {"title": "pending"}}
        complete = {"messages": [{"type": "idle"}], "info": {"title": TITLE}}
        observed = iter((pending, complete))
        with patch("stock_worker_tools_capture.time.sleep"):
            self.assertIs(await_idle(lambda: next(observed)), complete)

    def test_listener_accepts_exact_ipv4_loopback_and_rejects_wildcards(self):
        local = "0: 0100007F:20D1 00000000:0000 0A"
        self.assertIsNone(verify_loopback_listener(local))
        for wildcard in ("00000000", "00000000000000000000000000000000"):
            with self.subTest(wildcard=wildcard), self.assertRaisesRegex(FixtureMismatch, "only on IPv4 loopback"):
                verify_loopback_listener(local + f"\n1: {wildcard}:20D1 00000000:0000 0A")

    def test_failed_proof_preserves_primary_and_checks_all_cleanup(self):
        def action(log):
            executed.append(log)
            raise RuntimeError(log)

        executed = []
        primary = RuntimeError("primary fixture error")
        run_cleanup(primary, lambda: action("container"), lambda: action("lease"))
        self.assertEqual(str(primary), "primary fixture error")
        self.assertEqual(executed, ["container", "lease"])
        self.assertEqual(primary.__notes__, ["Fixture cleanup: RuntimeError: container",
                                            "Fixture cleanup: RuntimeError: lease"])

    def test_held_reader_requires_framed_http_and_sse_and_compiles(self):
        compile(HOLD_READER, "held-reader", "exec")
        self.assertIn("response.status != 200", HOLD_READER)
        self.assertIn("event: response.created", HOLD_READER)
        self.assertIn("'event': 'timeout'", HOLD_READER)
        self.assertIn("'event': 'closed'", HOLD_READER)


class PodMcsGuardTests(unittest.TestCase):
    def setUp(self):
        pod_id = "a" * 64
        process_prefix = "system_u:system_r:container_t:"
        mount_prefix = "system_u:object_r:container_file_t:"
        self.infra = {
            "Id": "b" * 64, "Pod": pod_id, "IsInfra": True,
            "ProcessLabel": process_prefix + "s0:c349,c422",
            "Image": "", "ImageName": "", "Path": "/catatonit", "Args": ["-P"],
            "Mounts": [], "HostConfig": {"Privileged": False},
        }
        self.worker = {"Id": "c" * 64, "Pod": pod_id, "IsInfra": False,
                       "ProcessLabel": process_prefix + "s0:c643,c775"}
        self.relay = {"Id": "d" * 64, "Pod": pod_id, "IsInfra": False,
                      "ProcessLabel": process_prefix + "s0:c349,c422",
                      "MountLabel": mount_prefix + "s0:c349,c422"}
        self.browser = {"Id": "e" * 64, "Pod": pod_id, "IsInfra": False,
                        "ProcessLabel": process_prefix + "s0:c17,c332"}
        self.details = [self.infra, self.worker, self.relay, self.browser]
        self.pod = {"Id": pod_id, "InfraContainerID": self.infra["Id"], "InfraConfig": {"PortBindings": {}},
                    "Containers": [{"Id": item["Id"]} for item in self.details]}

    def verify(self, *, details=None):
        verify_relay_mcs(self.pod, self.worker, self.relay, self.details if details is None else details)

    def test_measured_pause_label_was_rejected_by_old_all_sibling_predicate(self):
        level = self.relay["ProcessLabel"].split(":", 3)[-1]
        self.assertFalse(all(other["Id"] == self.relay["Id"] or other["ProcessLabel"].split(":", 3)[-1] != level
                             for other in self.details))
        self.verify()

    def test_rejects_changed_pause_process_image_mounts_or_privilege(self):
        changes = {
            "Image": "f" * 64, "ImageName": "substitute", "Path": "/bin/sh", "Args": ["-c"],
            "Mounts": [{"Destination": "/sandbox"}], "HostConfig": {"Privileged": True}, "IsInfra": False,
        }
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaisesRegex(FixtureMismatch, "qualified pause"):
                self.verify(details=[{**self.infra, field: value}, *self.details[1:]])

    def test_rejects_duplicate_missing_and_foreign_inspected_membership(self):
        with self.assertRaisesRegex(FixtureMismatch, "inspection changed membership"):
            self.verify(details=[*self.details[:-1], self.infra])
        with self.assertRaisesRegex(FixtureMismatch, "inspection changed membership"):
            self.verify(details=[*self.details[:-1], {**self.browser, "Pod": "f" * 64}])
        with self.assertRaisesRegex(FixtureMismatch, "Duplicate infrastructure"):
            self.verify(details=[*self.details[:-1], {**self.browser, "IsInfra": True}])
        self.pod["Containers"].append({"Id": self.relay["Id"]})
        with self.assertRaisesRegex(FixtureMismatch, "membership is missing or ambiguous"):
            self.verify()

    def test_rejects_real_sibling_collision_with_categories_in_reverse_order(self):
        self.browser["ProcessLabel"] = self.relay["ProcessLabel"].replace("c349,c422", "c422,c349")
        with self.assertRaisesRegex(FixtureMismatch, "shared with an application sibling"):
            self.verify()

    def test_rejects_unqualified_real_sibling_category(self):
        for suffix in ("s0", "s0:c3,c3", "s0:c17,c1024"):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(FixtureMismatch, "category"):
                self.verify(details=[*self.details[:-1], {**self.browser, "ProcessLabel":
                                     "system_u:system_r:container_t:" + suffix}])


def nft_table():
    name = "oc_gemini_fixture"
    base = {"family": "inet", "table": name}
    rules = [
        {**base, "chain": "output", "expr": [
            {"match": {"left": {"meta": {"key": "oifname"}}, "op": "==", "right": "lo"}},
            {"accept": None},
        ]},
        {**base, "chain": "output", "expr": [
            {"match": {"left": {"ct": {"key": "direction"}}, "op": "==", "right": "reply"}},
            {"match": {"left": {"payload": {"protocol": "tcp", "field": "sport"}}, "op": "==", "right": 22}},
            {"match": {"left": {"ct": {"key": "state"}}, "op": "in", "right": "established"}},
            {"accept": None},
        ]},
    ]
    return [{"table": {"family": "inet", "name": name}}, *(
        {"chain": {**base, "name": hook, "type": "filter", "hook": hook, "prio": 0, "policy": "drop"}}
        for hook in ("output", "forward")), *({"rule": rule} for rule in rules)]


class FirewallGuardTests(unittest.TestCase):
    def test_accepts_only_expected_loopback_and_management_reply(self):
        table = nft_table()
        expected = firewall_shape(json.dumps({"nftables": table}))
        self.assertEqual(len(expected), 64)
        table[-1]["rule"]["expr"][0]["match"]["right"] = "original"
        with self.assertRaisesRegex(RuntimeError, "Unexpected exception"):
            firewall_shape(json.dumps({"nftables": table}))


class ProtocolGuardTests(unittest.TestCase):
    workspace = "/sandbox/construct"
    tools = [
        {"type": "function", "name": name, "parameters": {"type": "object", "properties": properties}}
        for name, properties in (
            ("patch", {"patchText": {"type": "string"}}),
            ("read", {"path": {"type": "string"}}),
            ("shell", {"command": {"type": "string"}, "timeout": {"type": "integer"},
                       "workdir": {"type": "string"}}),
        )
    ]

    def setUp(self):
        self.script = ToolScript(self.workspace)
        self.base = {"model": MODEL, "store": False, "stream": True,
                     "input": [{"role": "user", "content": PROMPT}], "tools": self.tools}

    def request(self, count):
        value = deepcopy(self.base)
        for stage in range(count):
            value["input"].extend([
                {"type": "function_call", "name": TOOL_NAMES[stage], "call_id": call_id(stage),
                 "arguments": json.dumps(self.script.arguments[stage])},
                {"type": "function_call_output", "call_id": call_id(stage),
                 "output": expected_result(stage, self.workspace)},
            ])
        return value

    def test_public_fixture_script_requires_exact_results_and_auxiliary_title(self):
        self.script.respond({**self.base, "tools": [], "input": [{"role": "user", "content": TITLE_PROMPT}]})
        for stage in range(4):
            self.script.respond(self.request(stage))
        self.script.verify_done()
        with self.assertRaisesRegex(FixtureMismatch, "Unexpected stock inference"):
            self.script.respond(self.request(3))

    def test_rejects_changed_tool_result_before_sending_later_tool(self):
        self.script.respond(self.request(0))
        invalid = self.request(1)
        invalid["input"][-1]["output"] += "changed"
        with self.assertRaisesRegex(FixtureMismatch, "patch result differed"):
            self.script.respond(invalid)
        self.assertEqual(len(self.script.requests), 1)

    def test_negative_hosted_fixture_precedes_rejection_with_a_valid_buffered_worker_call(self):
        events = list(refused_events("hosted", self.base, self.workspace))
        self.assertEqual(events[-2]["item"]["name"], "patch")
        self.assertIn(REFUSED_FILE, events[-2]["item"]["arguments"])
        projector = SessionStreamProjector(model=MODEL, local_response_id="resp_local_probe",
                                           vault=ReasoningVault(), allowed_tools=frozenset({"patch"}))
        observed = [frame for item in events[:-1] for frame in projector.feed(item)]
        self.assertNotIn(b"function_call", b"".join(observed))
        with self.assertRaisesRegex(StreamAborted, "unsupported_event"):
            projector.feed(events[-1])

    def test_hosted_event_cannot_release_earlier_buffered_tool_frames(self):
        for event in ("response.web_search_call.completed", "response.mcp_call.completed",
                      "response.code_interpreter_call.completed"):
            with self.subTest(event=event):
                projector = SessionStreamProjector(model=MODEL, local_response_id="resp_local_probe",
                                                   vault=ReasoningVault(), allowed_tools=frozenset({"patch"}))
                sequence = list(response_events(0, {"patchText": "synthetic"}))
                observed = [frame for item in sequence[:-1] for frame in projector.feed(item)]
                self.assertNotIn(b"function_call", b"".join(observed))
                with self.assertRaises(StreamAborted):
                    projector.feed({"type": event})


if __name__ == "__main__":
    unittest.main()
