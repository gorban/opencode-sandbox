"""Exercise the workstation connection with synthetic issuer and Responses traffic."""

import contextlib
from html.parser import HTMLParser
import http.client
import json
import os
import pwd
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from oc_openai.connection import (AUTHORIZE, Binding, Connection, ConnectionError,
                                  DIRECT_SCOPE, INITIAL_CLIENT, RESOURCE)
from oc_openai.responses import API_HOST, AUTH_HOST, DISCOVERY, JWKS, MODELS, TOKEN


CLIENT = "oaiapp_fixture-registration"
SUBJECT = "opaque-fixture-subject"
REVOKE = "/api/accounts/oauth/revoke"
MODEL = "gpt-6.2-sol"
BODY = {"model": MODEL, "store": False, "stream": True,
        "input": [{"role": "user", "content": "synthetic"}]}


class FixtureVerifier:
    def __init__(self):
        self.subject = SUBJECT
        self.last = None

    def preflight(self):
        pass

    def verify(self, token, keys, client, nonce):
        self.last = token, keys, client, nonce
        return self.subject


class FixtureBrowser:
    def __init__(self):
        self.last = None
        self.client = CLIENT
        self.assertions = None
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.hold = False
        self.invalid = False
        self.redirect = None
        self.mode = None
        self.referrer = None

    def __call__(self, target):
        class Meta(HTMLParser):
            def handle_starttag(self, tag, attrs):
                if tag == "meta":
                    self.fields.append(dict(attrs))

        uri = urlsplit(target)
        if uri.scheme != "file" or uri.netloc or uri.query or uri.fragment:
            raise AssertionError("authorization material passed directly to browser launcher")
        self.redirect = Path(unquote(uri.path))
        self.mode = self.redirect.stat().st_mode & 0o777
        meta = Meta()
        meta.fields = []
        meta.feed(self.redirect.read_text())
        refresh = next(item["content"] for item in meta.fields if item.get("http-equiv") == "refresh")
        self.referrer = next(item["content"] for item in meta.fields if item.get("name") == "referrer")
        self.last = urlsplit(refresh.removeprefix("0;url="))
        self.ready.set()
        if not self.hold:
            threading.Thread(target=self.send, daemon=True).start()

    def send(self):
        values = parse_qs(self.last.query)
        address = urlsplit(values["redirect_uri"][0])
        query = {"state": values["state"][0], "code": "first-use-code"}
        if self.client is not None:
            query["client_id"] = self.client
        try:
            with contextlib.closing(http.client.HTTPConnection(
                address.hostname, address.port, timeout=2,
            )) as client:
                if self.invalid:
                    for malformed in (
                        {"state": "wrong", "code": "rejected"},
                        {"state": [query["state"], query["state"]], "code": "duplicated"},
                    ):
                        client.request("GET", address.path + "?" + urlencode(malformed, doseq=True))
                        response = client.getresponse()
                        if response.status != 400:
                            raise AssertionError(f"unexpected callback status {response.status}")
                        response.read()
                client.request("GET", address.path + "?" + urlencode(query))
                response = client.getresponse()
                response.read()
                if response.status != 200:
                    raise AssertionError(f"unexpected callback status {response.status}")
        except BaseException as error:
            self.assertions = error
        finally:
            self.finished.set()


class FixtureTransport:
    def __init__(self):
        self.calls = []
        self.tokens = {"id_token": "test-identity", "access_token": "test-access",
                       "refresh_token": "test-refresh", "token_type": "Bearer",
                       "expires_in": 3600, "scope": DIRECT_SCOPE}
        self.next_tokens = {**self.tokens, "access_token": "next-access",
                            "refresh_token": "next-refresh"}
        self.token_block = None
        self.token_started = threading.Event()
        self.revoke_block = None
        self.revoke_started = threading.Event()
        self.response_block = False
        self.response_started = threading.Event()
        self.response_cancelled = threading.Event()
        self.sent = 0
        self.exchange_status = 200
        self.refresh_outcome = None
        self.models_outcome = None
        self.interrupt_token = False

    def json(self, host, path, *, cancellation, dispatch, body=None, bearer=None,
             revocation=False):
        form = parse_qs(body.decode()) if body else None
        dispatch(lambda: self.calls.append((host, path, form, bearer)))
        if (host, path) == (AUTH_HOST, TOKEN):
            self.token_started.set()
            if self.interrupt_token:
                raise KeyboardInterrupt
            if self.token_block is not None and not self.token_block.wait(3):
                raise AssertionError("test did not release token request")
            if form["grant_type"] == ["refresh_token"]:
                if self.refresh_outcome is not None:
                    return self.refresh_outcome
                return 200, self.next_tokens.copy()
            return self.exchange_status, self.tokens.copy()
        if (host, path) == (AUTH_HOST, JWKS):
            return 200, {"keys": ["synthetic"]}
        if (host, path) == (AUTH_HOST, DISCOVERY):
            return 200, {"issuer": "https://auth.openai.com",
                         "revocation_endpoint": "https://auth.openai.com" + REVOKE}
        if (host, path) == (AUTH_HOST, REVOKE) and revocation:
            self.revoke_started.set()
            if self.revoke_block is not None and not self.revoke_block.wait(3):
                raise AssertionError("test did not release revocation request")
            return 200, {}
        if (host, path) == (API_HOST, MODELS):
            if self.models_outcome is not None:
                return self.models_outcome
            return 200, {"models": [{"slug": MODEL, "visibility": "list"},
                                    {"slug": "hidden", "visibility": "hide"}]}
        raise AssertionError("unexpected provider destination")

    @contextlib.contextmanager
    def responses(self, body, bearer, cancellation, dispatch):
        def send():
            self.sent += 1
            self.calls.append((API_HOST, "/v1/responses", body, bearer))

        dispatch(send)

        def events():
            self.response_started.set()
            if self.response_block:
                if not cancellation.event.wait(3):
                    raise AssertionError("active request did not observe cross-instance retirement")
                self.response_cancelled.set()
                cancellation.check()
            yield {"type": "response.completed"}

        yield events()


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.tmp = self.enterContext(tempfile.TemporaryDirectory(prefix="oc-siwc-test-", dir=home))
        self.state = Path(self.tmp) / "local"
        self.transport = FixtureTransport()
        self.browser = FixtureBrowser()
        self.verifier = FixtureVerifier()
        self.now = 1_000_000
        self.connection = self.make_connection()

    def make_connection(self):
        return Connection(self.state, transport=self.transport, verifier=self.verifier,
                          browser=self.browser, clock=lambda: self.now)

    def assert_code(self, code, callback):
        with self.assertRaises(ConnectionError) as caught:
            callback()
        self.assertEqual(caught.exception.code, code)

    def start(self, callback):
        result = []

        def run():
            try:
                result.append(callback())
            except BaseException as error:
                result.append(error)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 4)
        return worker, result

    def auth(self):
        try:
            return self.connection.connect()
        finally:
            if not self.browser.hold:
                self.assertTrue(self.browser.finished.wait(2))
                if self.browser.assertions:
                    raise self.browser.assertions

    def test_connect_catalog_and_responses(self):
        self.browser.invalid = True
        self.assertEqual(self.connection.status(), "disconnected")
        self.assertFalse(self.state.exists())
        binding = self.auth()
        self.assertIsInstance(binding, Binding)
        self.assertEqual(self.connection.binding(), binding)
        self.assertEqual(self.connection.status(), "connected")
        self.assertEqual(self.connection.models(binding), (MODEL,))
        self.assertEqual(self.transport.sent, 0)
        self.assertEqual(self.transport.calls[0][0:2], (AUTH_HOST, TOKEN))
        fields = parse_qs(self.browser.last.query)
        self.assertEqual(self.browser.last.geturl().split("?")[0], AUTHORIZE)
        self.assertEqual(self.browser.mode, 0o600)
        self.assertEqual(self.browser.referrer, "no-referrer")
        self.assertFalse(self.browser.redirect.exists())
        self.assertEqual(fields["client_id"], [INITIAL_CLIENT])
        self.assertEqual(fields["agent_name_hint"], ["oc-sandbox"])
        self.assertEqual(fields["resource"], [RESOURCE])
        self.assertEqual(fields["code_challenge_method"], ["S256"])
        self.assertEqual(fields["redirect_uri"], self.transport.calls[0][2]["redirect_uri"])
        self.assertEqual(self.verifier.last, ("test-identity", {"keys": ["synthetic"]},
                                               CLIENT, fields["nonce"][0]))
        recorded = []

        def before():
            self.assertEqual(self.transport.sent, 0)
            recorded.append("recorded")

        with self.connection.responses(binding, BODY, before) as events:
            self.assertEqual(list(events), [{"type": "response.completed"}])
        self.assertEqual(recorded, ["recorded"])
        self.assertEqual(self.transport.calls[-1], (API_HOST, "/v1/responses", BODY, "test-access"))
        self.assertEqual(self.transport.calls[-2][0:2], (API_HOST, MODELS))
        self.assertEqual(self.transport.calls[-2][-1], self.transport.calls[-1][-1])
        self.assertEqual((self.state / "state.json").stat().st_mode & 0o777, 0o600)
        self.assertNotIn(SUBJECT, repr(binding))
        self.assertNotIn(CLIENT, repr(binding))

    def test_no_direct_grant_uses_token_scope_not_callback_and_retains_registration(self):
        self.transport.tokens["scope"] = "openid email offline_access"
        self.assert_code("chatgpt_plan_scope_missing", self.auth)
        self.assertEqual(self.connection.status(), "chatgpt_plan_scope_missing")
        self.assert_code("openai_connection_required", self.connection.binding)
        self.assertEqual(self.transport.sent, 0)
        self.assertNotIn("test-refresh", (self.state / "state.json").read_text())

    def test_reauthorize_omitted_client_and_reject_mismatch(self):
        first = self.auth()
        initial_host = parse_qs(self.browser.last.query)["ext_agent_host_id"]
        self.assertTrue(self.connection.disconnect())
        self.assert_code("connection_retired", lambda: self.connection.require_active(first))
        self.browser.client = "oaiapp_substituted"
        self.assert_code("invalid_openai_callback", self.auth)
        self.assertEqual([call[1] for call in self.transport.calls].count(TOKEN), 1)
        self.browser.client = None
        self.verifier.subject = "different-fixture-subject"
        self.assert_code("openai_account_mismatch", self.auth)
        self.verifier.subject = SUBJECT
        second = self.auth()
        self.assertEqual(second.profile, first.profile)
        self.assertNotEqual(second.generation, first.generation)
        fields = parse_qs(self.browser.last.query)
        self.assertEqual(fields["client_id"], [CLIENT])
        self.assertEqual(fields["ext_agent_host_id"], initial_host)
        self.assertNotIn("agent_name_hint", fields)

    def test_failed_code_exchange_retains_issued_registration_for_next_authorization(self):
        self.transport.exchange_status = 400
        self.assert_code("openai_exchange_failed", self.auth)
        self.transport.exchange_status = 200
        self.browser.client = None
        self.auth()
        self.assertEqual(parse_qs(self.browser.last.query)["client_id"], [CLIENT])

    def test_disconnect_fences_exchange_and_durable_revoke_goes_first(self):
        self.transport.token_block = threading.Event()
        worker, result = self.start(self.auth)
        self.assertTrue(self.transport.token_started.wait(2))
        other = self.make_connection()
        self.assertFalse(other.disconnect())  # exchange may have completed upstream
        self.transport.token_block.set()
        worker.join(3)
        self.assertEqual(result[0].code, "connection_retired")
        self.assertEqual(other.status(), "disconnected")

    def test_disconnect_fences_pending_unconsumed_callback(self):
        self.browser.hold = True
        worker, result = self.start(self.auth)
        self.assertTrue(self.browser.ready.wait(2))
        self.assertTrue(self.make_connection().disconnect())
        worker.join(3)
        self.assertEqual(result[0].code, "connection_retired")
        self.assertEqual(self.transport.calls, [])

    def test_parallel_refresh_uses_new_token_once_and_does_not_hold_state_lock(self):
        binding = self.auth()
        self.now += 3590
        self.transport.token_started.clear()
        self.transport.token_block = threading.Event()
        first, first_result = self.start(lambda: self.connection.models(binding))
        self.assertTrue(self.transport.token_started.wait(2))
        second, second_result = self.start(lambda: self.make_connection().models(binding))
        self.assertEqual(self.connection.status(), "connected")
        self.transport.token_block.set()
        first.join(3)
        second.join(3)
        self.assertEqual(first_result, [(MODEL,)])
        self.assertEqual(second_result, [(MODEL,)])
        refreshes = [entry[2] for entry in self.transport.calls if entry[1] == TOKEN
                     and entry[2]["grant_type"] == ["refresh_token"]]
        self.assertEqual(len(refreshes), 1)
        self.assertEqual(refreshes[0]["refresh_token"], ["test-refresh"])
        self.assertNotIn("scope", refreshes[0])
        self.assertEqual([entry[3] for entry in self.transport.calls if entry[1] == MODELS],
                         ["next-access", "next-access"])
        self.assertNotIn("test-refresh", (self.state / "state.json").read_text())

    def test_disconnect_cancels_refresh_and_prevents_late_replacement(self):
        binding = self.auth()
        self.now += 3590
        self.transport.token_started.clear()
        self.transport.token_block = threading.Event()
        refresh, refresh_outcome = self.start(lambda: self.connection.models(binding))
        self.assertTrue(self.transport.token_started.wait(2))
        self.transport.revoke_block = threading.Event()
        other = self.make_connection()
        retire, retire_result = self.start(other.disconnect)
        self.assertTrue(self.transport.revoke_started.wait(2))
        self.assert_code("connection_retired", lambda: self.connection.require_active(binding))
        self.assertEqual(other.status(), "disconnecting")
        self.transport.token_block.set()
        self.transport.revoke_block.set()
        refresh.join(3)
        retire.join(3)
        self.assertEqual(refresh_outcome[0].code, "connection_retired")
        self.assertEqual(retire_result, [False])
        state = (self.state / "state.json").read_text()
        self.assertNotIn("next-refresh", state)
        self.assertNotIn("test-refresh", state)
        self.assertEqual(other.status(), "disconnected")

    def test_terminal_refresh_requires_connection_and_transient_preserves_it(self):
        binding = self.auth()
        self.now += 3590
        self.transport.refresh_outcome = (503, {"error": "temporarily_unavailable"})
        self.assert_code("openai_refresh_failed", lambda: self.connection.models(binding))
        self.assertEqual(self.connection.status(), "connected")
        self.now += 31
        self.transport.refresh_outcome = (400, {"error": "invalid_grant"})
        self.assert_code("openai_reconnect_required", lambda: self.connection.models(binding))
        self.assertEqual(self.connection.status(), "disconnected")

    def test_interrupted_exchange_uncertainty_survives_a_later_successful_revoke(self):
        self.transport.interrupt_token = True
        with self.assertRaises(KeyboardInterrupt):
            self.auth()
        self.assertFalse(self.make_connection().disconnect())
        self.transport.interrupt_token = False
        self.browser.client = None
        self.auth()
        self.assertFalse(self.make_connection().disconnect())
        self.assertFalse(self.make_connection().disconnect())
        self.assertTrue(any(call[1] == REVOKE for call in self.transport.calls))

    def test_interrupted_refresh_cannot_reuse_rotating_token(self):
        binding = self.auth()
        self.now += 3590
        self.transport.interrupt_token = True
        with self.assertRaises(KeyboardInterrupt):
            self.connection.models(binding)
        self.assert_code("connection_retired", lambda: self.make_connection().models(binding))
        self.assertFalse(self.make_connection().disconnect())
        self.assertNotIn("test-refresh", (self.state / "state.json").read_text())

    def test_restart_with_durable_refresh_dispatch_marker_refuses_replay(self):
        binding = self.auth()
        store = self.connection._store
        with store.locked() as directory:
            snapshot = store.read(directory)
            snapshot["refresh_pending"] = {
                "ticket": "orphaned-transaction", "until": self.now + 35, "may_have_sent": True,
            }
            store.write(directory, snapshot)
        self.now += 36
        calls = self.transport.calls.copy()
        restarted = self.make_connection()
        self.assert_code("openai_reconnect_required", lambda: restarted.models(binding))
        self.assertEqual(self.transport.calls, calls)
        self.assertFalse(restarted.disconnect())

    def test_catalog_missing_model_does_not_spend(self):
        binding = self.auth()
        self.transport.models_outcome = (200, {"models": [{"slug": MODEL, "visibility": "hide"}]})

        def send():
            with self.connection.responses(binding, BODY, lambda: self.fail("spent")):
                self.fail("sent")

        self.assert_code("openai_model_unavailable", send)
        self.assertEqual(self.transport.sent, 0)

    def test_rotation_after_catalog_refuses_old_token_before_spend(self):
        binding = self.auth()
        self.now += 3570 - 1

        original = self.transport.responses

        @contextlib.contextmanager
        def rotate(body, bearer, cancellation, dispatch):
            self.now += 2
            self.assertEqual(self.make_connection().models(binding), (MODEL,))
            with original(body, bearer, cancellation, dispatch) as results:
                yield results

        self.transport.responses = rotate

        def send():
            with self.connection.responses(binding, BODY, lambda: self.fail("spent")):
                self.fail("sent")

        self.assert_code("openai_access_token_changed", send)
        self.assertEqual(self.transport.sent, 0)

    def test_retirement_between_spend_hook_and_upstream_write(self):
        binding = self.auth()
        recorded = []

        def spend():
            recorded.append(True)
            self.assertTrue(self.make_connection().disconnect())

        def invoke():
            with self.connection.responses(binding, BODY, spend):
                self.fail("retired proof allowed")

        self.assert_code("connection_retired", invoke)
        self.assertEqual(recorded, [True])
        self.assertEqual(self.transport.sent, 0)

    def test_durable_retirement_interrupts_active_reads_in_independent_instance(self):
        binding = self.auth()
        self.transport.response_block = True

        def send():
            with self.connection.responses(binding, BODY, lambda: None) as events:
                return list(events)

        worker, result = self.start(send)
        self.assertTrue(self.transport.response_started.wait(2))
        self.assertTrue(self.make_connection().disconnect())
        self.assertTrue(self.transport.response_cancelled.wait(2))
        worker.join(3)
        self.assertEqual(result[0].code, "connection_retired")
        self.assertEqual(self.transport.sent, 1)

    def test_caller_stop_interrupts_reads_without_retiring_connection(self):
        binding = self.auth()
        stopped = threading.Event()
        self.transport.response_block = True

        def send():
            with self.connection.responses(binding, BODY, lambda: None,
                                           deadline=time.monotonic() + 3, cancelled=stopped) as events:
                return list(events)

        worker, result = self.start(send)
        self.assertTrue(self.transport.response_started.wait(2))
        stopped.set()
        self.assertTrue(self.transport.response_cancelled.wait(2))
        worker.join(3)
        self.assertEqual(result[0].code, "openai_operation_cancelled")
        self.connection.require_active(binding)
        self.assertEqual(self.transport.sent, 1)

    def test_expired_deadline_and_preset_stop_neither_refresh_nor_spend(self):
        binding = self.auth()
        self.now += 3590
        calls = self.transport.calls.copy()
        stop = threading.Event()
        stop.set()

        def send(**options):
            with self.connection.responses(binding, BODY, lambda: self.fail("spent"), **options):
                self.fail("sent")

        self.assert_code("openai_operation_cancelled", lambda: send(cancelled=stop))
        self.assert_code("openai_operation_timed_out", lambda: send(deadline=time.monotonic() - 1))
        self.assertEqual(calls, self.transport.calls)

    def test_rejects_symlink_and_nonprivate_snapshot(self):
        self.auth()
        snapshot = self.state / "state.json"
        os.chmod(snapshot, 0o644)
        self.assert_code("untrusted_connection_file", self.connection.status)
        os.chmod(snapshot, 0o600)
        other = snapshot.with_name("renamed")
        snapshot.rename(other)
        snapshot.symlink_to(other.name)
        with self.assertRaises(ConnectionError):
            self.connection.status()
        data = json.loads(other.read_bytes())
        self.assertEqual(data["tokens"]["access"], "test-access")


if __name__ == "__main__":
    unittest.main()
