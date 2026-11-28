"""Verify the enrollment dialogue refuses ACP traffic outside metadata setup."""

from contextlib import ExitStack
import json
import os
import select
import time
from types import SimpleNamespace
import unittest

from oc_google.native_enrollment_acp import NativeAcpError, NativeEnrollmentAcp


class NativeEnrollmentAcpTest(unittest.TestCase):
    def setUp(self):
        files = self.enterContext(ExitStack())
        requests, source = os.pipe()
        output, replies = os.pipe()
        self.requests = files.enter_context(os.fdopen(requests, "rb", buffering=0))
        self.replies = files.enter_context(os.fdopen(replies, "wb", buffering=0))
        process = SimpleNamespace(stdin=files.enter_context(os.fdopen(source, "wb", buffering=0)),
                                  stdout=files.enter_context(os.fdopen(output, "rb", buffering=0)))
        self.authorized = True
        self.acp = NativeEnrollmentAcp(process, time.monotonic() + 1, lambda: self.authorized)
        self.request_id = None
        self.scheduled = []
        original = self.acp._send

        def send(ident, method, params):
            original(ident, method, params)
            self.request_id = ident
            if self.scheduled:
                self.replies.write(b"".join(self.scheduled))
                self.scheduled.clear()

        self.acp._send = send

    def reply(self, ident, **payload):
        frame = json.dumps({"jsonrpc": "2.0", "id": ident, **payload}).encode() + b"\n"
        if ident == self.request_id:
            self.replies.write(frame)
        else:
            self.scheduled.append(frame)

    def usage(self, session="local-fixture", **counts):
        frame = {"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": session, "update": {
            "sessionUpdate": "usage_update", "size": 4096, "used": 0, **counts,
        }}}
        packet = json.dumps(frame).encode() + b"\n"
        if self.scheduled:
            self.scheduled.append(packet)
        else:
            self.replies.write(packet)

    def initialize(self):
        self.reply(1, result={"protocolVersion": 1, "agentInfo": {"version": "1.5.2"},
                              "authMethods": [{"id": "oauth-personal"}]})
        self.acp.initialize()

    def test_enrollment_is_single_use_and_will_not_open_a_prompt(self):
        self.initialize()
        self.reply(2, error={"code": -32000, "message": "Authentication required"})
        self.acp.verify_signed_out()
        self.acp.start_personal_sign_in()
        self.reply(3, result={})
        self.acp.finish_personal_sign_in()
        self.replies.close()
        self.acp.drain_retired_enrollment()
        with self.assertRaises(NativeAcpError):
            self.acp.open_metadata_session()
        self.assertEqual([json.loads(self.requests.readline())["method"] for _ in range(3)],
                         ["initialize", "session/new", "authenticate"])

    def test_reopen_has_no_mcp_or_enabled_tools(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.reply(2, result={"sessionId": "local-fixture"})
        self.acp.finish_metadata_session()
        self.requests.readline()
        self.assertEqual(json.loads(self.requests.readline())["params"], {
            "cwd": "/run/oc-proof/empty", "mcpServers": [], "_meta": {"antigravity": {"enabledTools": []}},
        })

    def test_callback_stops_the_exact_dialogue(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.replies.write(b'{"jsonrpc":"2.0","id":2,"method":"session/request_permission","params":{}}\n')
        with self.assertRaises(NativeAcpError):
            self.acp.finish_metadata_session()
        self.reply(2, result={"sessionId": "later"})
        with self.assertRaises(NativeAcpError):
            self.acp.finish_metadata_session()

    def test_ambiguous_reply_is_rejected(self):
        self.replies.write(b'{"jsonrpc":"2.0","id":9,"id":1,"result":{}}\n')
        with self.assertRaises(NativeAcpError):
            self.acp.initialize()

    def test_matching_usage_and_session_reply_can_arrive_together(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.usage()
        self.reply(2, result={"sessionId": "local-fixture"})
        self.acp.finish_metadata_session()

    def test_usage_is_refused_in_the_wrong_phase(self):
        self.usage()
        with self.assertRaises(NativeAcpError):
            self.acp.initialize()

    def test_usage_in_initialize_suffix_cannot_satisfy_cold_session(self):
        self.reply(1, result={"protocolVersion": 1, "agentInfo": {"version": "1.5.2"},
                              "authMethods": [{"id": "oauth-personal"}]})
        self.usage()
        with self.assertRaises(NativeAcpError):
            self.acp.initialize()

    def test_already_queued_early_notification_prevents_next_request(self):
        self.initialize()
        self.usage()
        with self.assertRaisesRegex(NativeAcpError, "pending before the request"):
            self.acp.open_metadata_session()

    def test_wrong_phase_output_arriving_during_writable_wait_is_refused(self):
        self.initialize()
        wait = self.acp._wait

        def late(descriptor, event):
            wait(descriptor, event)
            if event == select.POLLOUT:
                self.usage()

        self.acp._wait = late
        with self.assertRaisesRegex(NativeAcpError, "became pending before dispatch"):
            self.acp.open_metadata_session()

    def test_sign_in_rejects_trailing_callback(self):
        self.initialize()
        self.reply(2, error={"code": -32000, "message": "Authentication required"})
        self.acp.verify_signed_out()
        self.acp.start_personal_sign_in()
        self.reply(3, result={})
        self.replies.write(b'{"jsonrpc":"2.0","id":9,"method":"session/request_permission","params":{}}\n')
        with self.assertRaises(NativeAcpError):
            self.acp.finish_personal_sign_in()

    def test_enrollment_drain_refuses_a_late_catalog(self):
        self.initialize()
        self.reply(2, error={"code": -32000, "message": "Authentication required"})
        self.acp.verify_signed_out()
        self.acp.start_personal_sign_in()
        self.reply(3, result={})
        self.acp.finish_personal_sign_in()
        self.catalog()
        self.replies.close()
        with self.assertRaises(NativeAcpError):
            self.acp.drain_retired_enrollment()

    def test_usage_must_describe_the_same_session(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.usage(session="wrong-fixture")
        self.reply(2, result={"sessionId": "local-fixture"})
        with self.assertRaises(NativeAcpError):
            self.acp.finish_metadata_session()

    def test_duplicate_usage_refuses_completion(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.usage()
        self.usage()
        self.reply(2, result={"sessionId": "local-fixture"})
        with self.assertRaises(NativeAcpError):
            self.acp.finish_metadata_session()

    def test_usage_after_the_result_refuses_completion(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.reply(2, result={"sessionId": "local-fixture"})
        self.usage()
        self.replies.close()
        self.acp.finish_metadata_session()
        with self.assertRaises(NativeAcpError):
            self.acp.drain_retired_metadata()

    def test_usage_does_not_coerce_bools(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.usage(used=False)
        self.reply(2, result={"sessionId": "local-fixture"})
        with self.assertRaises(NativeAcpError):
            self.acp.finish_metadata_session()

    def catalog(self, session="local-fixture", names=("plan", "logout", "usage")):
        frame = {"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": session, "update": {
            "sessionUpdate": "available_commands_update",
            "availableCommands": [{"name": name, "description": "Fixture description"} for name in names],
        }}}
        self.replies.write(json.dumps(frame).encode() + b"\n")

    def test_exact_late_catalog_is_discarded_at_clean_eof(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.reply(2, result={"sessionId": "local-fixture"})
        self.acp.finish_metadata_session()
        self.authorized = False
        self.catalog()
        self.replies.close()
        self.acp.drain_retired_metadata()

    def test_foreign_catalog_is_rejected_even_if_coalesced(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.reply(2, result={"sessionId": "local-fixture"})
        self.catalog("wrong-fixture")
        self.replies.close()
        self.acp.finish_metadata_session()
        with self.assertRaises(NativeAcpError):
            self.acp.drain_retired_metadata()

    def test_duplicate_catalog_is_rejected(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.reply(2, result={"sessionId": "local-fixture"})
        self.catalog()
        self.catalog()
        self.replies.close()
        self.acp.finish_metadata_session()
        with self.assertRaises(NativeAcpError):
            self.acp.drain_retired_metadata()

    def test_partial_catalog_frame_is_rejected(self):
        self.initialize()
        self.acp.open_metadata_session()
        self.reply(2, result={"sessionId": "local-fixture"})
        self.replies.write(b'{"jsonrpc":"2.0"')
        self.replies.close()
        self.acp.finish_metadata_session()
        with self.assertRaises(NativeAcpError):
            self.acp.drain_retired_metadata()
