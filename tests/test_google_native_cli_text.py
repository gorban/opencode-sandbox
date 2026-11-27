"""Exercise the fixed text command without credentials or provider traffic."""

from contextlib import ExitStack
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from oc_google.native_text import target_from_config

from oc_google.native_text import NativeCliTextError, _Acp, _NativeRetirement, _OpenCodeSession, _one_turn, _open_session
consent = runpy.run_path(str(Path(__file__).resolve().parent / "e2e/live/conftest.py"))
public_driver = runpy.run_path(str(Path(__file__).resolve().parent / "e2e/live/google_public_shell_driver.py"))


def option(ident, current, choices):
    return {"id": ident, "currentValue": current, "options": [{"value": choice} for choice in choices]}


class NativeCliTextTest(unittest.TestCase):
    def test_uncertain_native_retirement_keeps_private_actor_receipt(self):
        with TemporaryDirectory() as base:
            root = Path(base) / "native"
            root.mkdir(mode=0o700)
            retirement = _NativeRetirement(root)
            actor = SimpleNamespace(pid=os.getpid())
            with ExitStack() as clean:
                slot = retirement.reserve("native-acp")
                retirement.track(clean, actor, slot)
                with patch("oc_google.native_text._retire", side_effect=subprocess.TimeoutExpired("native", 3)):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        clean.close()
            self.assertTrue(retirement.uncertain)
            retirement.remove_scratch_if_retired()
            receipt = root / "native-cleanup.json"
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(receipt.read_text())["actors"][0]["pid"], os.getpid())

    def test_failed_actor_record_and_retirement_keeps_pending_receipt(self):
        with TemporaryDirectory() as base:
            root = Path(base) / "native"
            root.mkdir(mode=0o700)
            retirement = _NativeRetirement(root)
            actor = SimpleNamespace(pid=os.getpid())
            with ExitStack() as clean:
                proxy_slot = retirement.reserve("keyring-proxy")
                retirement.track(clean, actor, proxy_slot)
                native_slot = retirement.reserve("native-acp")
                with patch.object(retirement, "_persist", side_effect=OSError("synthetic receipt failure")):
                    with self.assertRaises(OSError):
                        retirement.track(clean, actor, native_slot)
                with patch("oc_google.native_text._retire", side_effect=subprocess.TimeoutExpired("native", 3)):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        clean.close()
            retirement.remove_scratch_if_retired()
            receipt = json.loads((root / "native-cleanup.json").read_text())
            self.assertEqual(receipt["actors"][0]["state"], "tracked")
            self.assertEqual(receipt["actors"][1], {"role": "native-acp", "state": "launch-pending"})

    def test_public_driver_failure_summary_never_echoes_terminal_data(self):
        secret = "synthetic-sensitive-terminal-value"
        result = public_driver["failure_summary"](
            f"Provider request failed {secret}\nFixture exit 7\n")
        self.assertEqual(result, "Public Google shell failed: provider-refusal; exit=7")
        self.assertNotIn(secret, result)

    def test_public_driver_preserves_primary_failure_when_capture_fails(self):
        class Terminal:
            def start(self, *_):
                raise RuntimeError("primary synthetic failure")

            def screen(self, *_args, **_kwargs):
                raise LookupError("capture failed")

            def close(self):
                pass

        output = io.StringIO()
        with (TemporaryDirectory() as base,
              patch.object(sys, "stdin", SimpleNamespace(isatty=lambda: False,
                                                        buffer=io.BytesIO(b"pytest approved public shell\n"))),
              patch("runpy.run_path", return_value={"Terminal": lambda _: Terminal()}),
              patch("pathlib.Path.home", return_value=Path(base)),
              redirect_stdout(output),
              self.assertRaisesRegex(RuntimeError, "primary synthetic failure")):
            public_driver["main"]()
        self.assertIn("Public Google shell failed: incomplete-shell; exit=None", output.getvalue())

    def test_failed_retirement_stays_unconfirmed_on_repeat(self):
        calls = []

        def close():
            calls.append("close")
            if len(calls) == 1:
                raise TimeoutError("synthetic retirement uncertainty")

        session = _OpenCodeSession(SimpleNamespace(close=close), SimpleNamespace())
        with self.assertRaises(TimeoutError):
            session.retire()
        with self.assertRaises(NativeCliTextError):
            session.retire()
        self.assertEqual(calls, ["close"])
        self.assertFalse(session.retirement_confirmed)

    def test_isolated_live_driver_rejects_invalid_route_without_import_error(self):
        driver = Path(__file__).parent / "e2e/live/google_text_driver.py"
        result = subprocess.run(["/usr/bin/python3", "-IBS", str(driver), "invalid"],
                                cwd=driver.parents[3], input=b"", capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"ModuleNotFoundError", result.stderr)

    def test_named_google_provider_uses_its_config_label(self):
        instance = SimpleNamespace(label="custom-google", enabled=True, auth_mode="subscription",
                                   default_model="gemini-4-hydrogen")
        config = SimpleNamespace(get=lambda kind, label: instance if (kind, label) ==
                                 ("google", "custom-google") else None)
        with patch("oc_providers.config.load_provider_config", return_value=config):
            target = target_from_config("custom-google")
        self.assertEqual((target.label, target.model), ("custom-google", "gemini-4-hydrogen"))

    def text(self, updates, *, stop="end_turn"):
        sent = []

        def request(method, params, on_update, **_timing):
            sent.append((method, params))
            for update in updates:
                on_update(update)
            return {"stopReason": stop}

        return SimpleNamespace(request=request, session="fixture-session",
                               verify_terminal_tail=lambda: None), sent

    @staticmethod
    def chunk(text):
        return {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": text}}

    def test_passive_updates_and_exact_text_complete_a_single_fixed_request(self):
        peer, sent = self.text([{"sessionUpdate": "session_info_update"}, {"sessionUpdate": "plan"},
                                self.chunk("o"), {"sessionUpdate": "usage_update"}, self.chunk("k")])
        _one_turn(peer)
        self.assertEqual(sent, [("session/prompt", {"sessionId": "fixture-session", "prompt": [
            {"type": "text", "text": "Reply with exactly: ok. Do not use any tools."},
        ]})])

    def test_tools_nontext_and_inexact_completion_withhold_output(self):
        cases = (
            ({"sessionUpdate": "tool_call"}, "end_turn"),
            ({"sessionUpdate": "tool_call_update"}, "end_turn"),
            ({"sessionUpdate": []}, "end_turn"),
            ({"sessionUpdate": "agent_message_chunk", "content": {"type": "image"}}, "end_turn"),
            (self.chunk("!"), "end_turn"),
            ({"sessionUpdate": "usage_update"}, "cancelled"),
        )
        for update, stop in cases:
            with self.subTest(update=update, stop=stop):
                peer, sent = self.text([self.chunk("ok"), update], stop=stop)
                with self.assertRaises(NativeCliTextError):
                    _one_turn(peer)
                self.assertEqual(len(sent), 1)

    def test_session_turn_selects_confirmed_default_mode_and_advertised_gemini(self):
        calls = []

        def request(method, params, _update):
            calls.append((method, params))
            if method == "initialize":
                return {"protocolVersion": 1}
            if method == "session/new":
                return {"sessionId": "fixture-session", "configOptions": [
                    option("model", "gemini-default", ["gemini-default", "gemini-test"]),
                    option("mode", "auto", ["auto", "default"]),
                ]}
            ident, value = params["configId"], params["value"]
            return {"configOptions": [option(ident, value, [value])]}

        peer = SimpleNamespace(request=request)
        self.assertEqual(_open_session(peer, "gemini-test"), "gemini-test")
        self.assertEqual(calls[0][1]["clientInfo"], {"name": "oc-sandbox", "version": "0"})
        self.assertEqual(calls[1], ("session/new", {"cwd": "/workspace", "mcpServers": []}))
        self.assertEqual([payload["value"] for _, payload in calls[2:]], ["default", "gemini-test"])

    def test_client_refuses_callback_and_other_session_update(self):
        for frame in (
            {"id": 9, "method": "session/request_permission", "params": {}},
            {"method": "session/update", "params": {"sessionId": "other", "update": {}}},
        ):
            with self.subTest(frame=frame):
                response_read, response_write = os.pipe()
                request_read, request_write = os.pipe()
                with (os.fdopen(response_read, "rb", buffering=0) as native_stdout,
                      os.fdopen(response_write, "wb", buffering=0) as response,
                      os.fdopen(request_read, "rb", buffering=0) as _request,
                      os.fdopen(request_write, "wb", buffering=0) as native_stdin):
                    response.write(json.dumps({"jsonrpc": "2.0", **frame}).encode() + b"\n")
                    peer = _Acp(SimpleNamespace(stdin=native_stdin, stdout=native_stdout))
                    peer.session = "exact"
                    with self.assertRaises(NativeCliTextError):
                        peer.request("session/prompt", {}, self.fail, seconds=1)

    def test_completed_turn_with_queued_frame_has_no_verified_tail(self):
        response_read, response_write = os.pipe()
        request_read, request_write = os.pipe()
        with (os.fdopen(response_read, "rb", buffering=0) as native_stdout,
              os.fdopen(response_write, "wb", buffering=0) as response,
              os.fdopen(request_read, "rb", buffering=0) as _request,
              os.fdopen(request_write, "wb", buffering=0) as native_stdin):
            result = {"jsonrpc": "2.0", "id": 1, "result": {"stopReason": "end_turn"}}
            trailing = {"jsonrpc": "2.0", "method": "unexpected", "params": {}}
            response.write(json.dumps(result).encode() + b"\n" + json.dumps(trailing).encode() + b"\n")
            response.flush()
            child = SimpleNamespace(stdin=native_stdin, stdout=native_stdout,
                                    poll=lambda: 0, wait=lambda timeout: 0)
            peer = _Acp(child)
            self.assertEqual(peer.receive(1, "session/prompt", self.fail, seconds=1), result["result"])
            with self.assertRaises(NativeCliTextError):
                peer.verify_terminal_tail()


class GoogleConsentTest(unittest.TestCase):
    def session(self, flags, cases, **options):
        opts = dict.fromkeys(flags, True) | options
        config = SimpleNamespace(
            getoption=lambda name, default=False: opts.get(name, default),
            getini=lambda _name: [],
            invocation_params=SimpleNamespace(args=(*flags, "tests/e2e/live")),
        )
        items = [SimpleNamespace(path=consent["_GOOGLE_TEST"], originalname=case) for case in cases]
        return SimpleNamespace(config=config, items=items)

    def test_collection_limits_approval_to_opted_in_selected_cases(self):
        native = "test_google_cached_login_text"
        shell = "test_google_opencode_text"
        public = "test_google_public_shell"
        flags = ("--run-google-text-live", "--run-google-opencode-live",
                 "--run-google-public-shell-live")
        with patch.dict(os.environ, {"PYTEST_ADDOPTS": ""}):
            select = consent["_selected_google_cases"]
            self.assertEqual(list(select(self.session(flags, (native, shell, public)))), [native, shell, public])
            self.assertEqual(list(select(self.session(flags, (shell,)))), [shell])
            self.assertEqual(select(self.session((), (native, shell))), {})
            self.assertEqual(select(self.session(flags, (native, shell), collectonly=True)), {})

    def test_inherited_or_parallel_live_selection_is_refused(self):
        flag = "--run-google-opencode-live"
        shell = "test_google_opencode_text"
        select = consent["_selected_google_cases"]
        with patch.dict(os.environ, {"PYTEST_ADDOPTS": flag}):
            with self.assertRaisesRegex(ValueError, "inherited pytest option forbidden"):
                select(self.session((flag,), (shell,)))
        with patch.dict(os.environ, {"PYTEST_ADDOPTS": ""}):
            with self.assertRaisesRegex(ValueError, "one local pytest process"):
                select(self.session((flag,), (shell,), numprocesses=2))

    def test_claim_is_single_use_and_bound_to_the_selected_case(self):
        case = "test_google_opencode_text"
        config = SimpleNamespace(_oc_google_live_cases={case})
        node = SimpleNamespace(originalname="test_google_cached_login_text")
        request = SimpleNamespace(config=config, node=node)
        claim = consent["claim_google_case"]
        self.assertFalse(claim(request))
        node.originalname = case
        self.assertTrue(claim(request))
        self.assertFalse(claim(request))
