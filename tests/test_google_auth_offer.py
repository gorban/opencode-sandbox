"""Offline checks for the Google ACP offer and its local callback fence."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
import errno
import socket
from threading import Barrier, Event, Lock
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import quote, urlencode

from oc_google import auth_offer as auth


STATE = "a" * 29 + "B"
CHALLENGE = "A" * 43
CODE = "4/synthetic_test-code"


def offer(port, **changes):
    fields = {
        "client_id": auth.CLIENT_ID,
        "response_type": "code",
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
        "scope": " ".join(sorted(auth.SCOPES)),
        "redirect_uri": auth.redirect_uri(port),
        "state": STATE,
        "code_challenge": CHALLENGE,
        **changes,
    }
    return auth.AUTH_URL + "?" + urlencode(fields)


def request(port, *, code=CODE, state=STATE, target="/", method="GET", host=None, extra_query="",
            extra_headers=b"", tail=b""):
    params = {"state": state, "code": code} if code is not None else {"state": state, "error": "access_denied"}
    if host is None:
        host = f"{auth.HOST}:{port}"
    return (f"{method} {target}?{urlencode(params)}{extra_query} HTTP/1.1\r\n"
            f"Host: {host}\r\nConnection: close\r\n").encode() + extra_headers + b"\r\n" + tail


@contextmanager
def placement(*, authorized=lambda: True, opened=True):
    native, recorder = socket.socketpair()
    with native, recorder, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((auth.HOST, 0))
        listener.listen(4)
        listener.setblocking(False)
        port = listener.getsockname()[1]
        gate = auth.CallbackGate(listener, native, native_port=port, authorized=authorized,
                                 deadline=time.monotonic() + 10)
        if opened:
            gate.accept_offer(offer(port))
            gate.activate()
        yield gate, recorder, port


def exchange(port, payload, start=None):
    if start is not None:
        start.wait(2)
    with socket.create_connection((auth.HOST, port), timeout=2) as client:
        client.sendall(payload)
        try:
            client.shutdown(socket.SHUT_WR)
        except OSError as error:
            if error.errno != errno.ENOTCONN:
                raise
        data = bytearray()
        with suppress(ConnectionResetError):
            while chunk := client.recv(4096):
                data.extend(chunk)
        return bytes(data)


class OfferTest(unittest.TestCase):
    def test_requires_the_exact_measured_offer(self):
        self.assertEqual(auth.AUTH_URL, "https://accounts.google.com/o/oauth2/v2/auth")
        self.assertEqual(auth.CLIENT_ID, "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com")
        self.assertEqual(auth.SCOPES, {
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/aicode",
        })
        port = 49000
        raw = offer(port)
        selected = auth.validate_offer(raw, port)
        self.assertEqual((selected.url, selected.state, selected.challenge, selected.port),
                         (raw, STATE, CHALLENGE, port))
        self.assertNotIn(raw, repr(selected))
        self.assertNotIn(STATE, repr(selected))
        self.assertNotIn(CHALLENGE, repr(selected))

        for invalid in (
            raw + "#", raw + "\n", raw + "%", raw + "&state=" + STATE,
            raw.replace("https://", "http://", 1),
            raw.replace("accounts.google.com", "accounts.google.com:443", 1),
            raw.replace("accounts.google.com", "other.invalid@accounts.google.com", 1),
            raw.replace("/o/oauth2/v2/auth", "/o/oauth2/auth", 1),
            offer(port, redirect_uri="http://localhost:49000/"),
            offer(port, redirect_uri="http://[::1]:49000/"),
            offer(port, redirect_uri="http://127.0.0.1:049000/"),
            offer(port, redirect_uri="http://127.0.0.1:49000"),
            offer(port, redirect_uri="http://127.0.0.1:49000/?"),
            offer(port, redirect_uri=auth.redirect_uri(port + 1)),
            offer(port, scope=" ".join(sorted(auth.SCOPES) + [next(iter(auth.SCOPES))])),
            offer(port, scope=next(iter(auth.SCOPES))),
            offer(port, prompt="none"), offer(port, client_id="other-public-client"),
            offer(port, access_type="online"), offer(port, response_type="token"),
            offer(port, state=STATE + "x"), offer(port, state=STATE[:-1] + "\x00"),
            offer(port, code_challenge_method="plain"),
            offer(port, code_challenge=CHALLENGE[:-1] + "B"), offer(port, extra="1"),
        ):
            with self.subTest(length=len(invalid)), self.assertRaises(auth.Refused):
                auth.validate_offer(invalid, port)

    def test_port_is_exclusive_and_reserved_ports_are_refused(self):
        for port in (0, True, 443, 9222, 8401, 8416, 65536):
            with self.subTest(port=port), self.assertRaises(auth.Refused):
                auth.redirect_uri(port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind((auth.HOST, 0))
            occupied.listen()
            with self.assertRaisesRegex(auth.Refused, "callback port could not be held"):
                auth.bind_callback(occupied.getsockname()[1])

    def test_invalid_offer_consumes_the_only_offer_slot(self):
        with placement(opened=False) as (gate, _, port):
            with self.assertRaises(auth.Refused):
                gate.accept_offer(offer(port, state="result"))
            self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
            with self.assertRaisesRegex(auth.Refused, "already attempted"):
                gate.accept_offer(offer(port))
            with self.assertRaises(auth.Refused):
                gate.activate()


class CallbackGateTest(unittest.TestCase):
    def assert_no_native_bytes(self, recorder):
        recorder.setblocking(False)
        with self.assertRaises(BlockingIOError):
            recorder.recv(4096)

    def exchange(self, gate, port, payload):
        with ThreadPoolExecutor(max_workers=1) as workers:
            served = workers.submit(gate.serve_one)
            answer = exchange(port, payload)
            served.result(timeout=3)
            return answer

    def test_matching_callbacks_race_and_only_one_canonical_request_is_forwarded(self):
        with placement() as (gate, recorder, port), ThreadPoolExecutor(max_workers=4) as workers:
            start = Barrier(2)
            servers = [workers.submit(gate.serve_one) for _ in range(2)]
            payload = request(port, extra_headers=b"User-Agent: fixture\r\n")
            clients = [workers.submit(exchange, port, payload, start) for _ in range(2)]
            self.assertCountEqual([client.result(timeout=3) for client in clients],
                                  [auth.acknowledgement(True), auth.acknowledgement(False)])
            for server in servers:
                server.result(timeout=3)
            recorder.settimeout(1)
            self.assertEqual(recorder.recv(4096), request(port))
            self.assert_no_native_bytes(recorder)
            self.assertEqual(gate.outcome, auth.Outcome.FORWARDED)

    def test_losing_a_nonblocking_accept_race_waits_for_the_next_callback(self):
        simultaneous = Barrier(2)
        first_polls = Lock()
        lost_accept = Event()
        readable = auth._readable
        accept = socket.socket.accept
        ready_polls = 0

        def wait_for_initial_readiness(channel, timeout_ms=0):
            nonlocal ready_polls
            ready = readable(channel, timeout_ms)
            if ready and timeout_ms:
                with first_polls:
                    ready_polls += 1
                    synchronize = ready_polls <= 2
                if synchronize:
                    simultaneous.wait(1)
            return ready

        def track_accept(channel):
            try:
                return accept(channel)
            except BlockingIOError:
                lost_accept.set()
                raise

        with (placement() as (gate, recorder, port), ThreadPoolExecutor(max_workers=2) as workers,
              patch.object(auth, "_readable", side_effect=wait_for_initial_readiness),
              patch.object(socket.socket, "accept", track_accept)):
            servers = [workers.submit(gate.serve_one) for _ in range(2)]
            self.assertEqual(exchange(port, request(port)), auth.acknowledgement(True))
            self.assertTrue(lost_accept.wait(1))
            self.assertEqual(exchange(port, request(port)), auth.acknowledgement(False))
            for server in servers:
                server.result(timeout=3)
            recorder.settimeout(1)
            self.assertEqual(recorder.recv(4096), request(port))
            self.assert_no_native_bytes(recorder)

    def test_legacy_and_metadata_envelopes_forward_identical_canonical_fields(self):
        scopes = " ".join(sorted(auth.SCOPES))
        for suffix in (
            "",
            "&" + urlencode({"scope": scopes, "authuser": "0", "prompt": "consent"}),
            "&scope=" + quote(scopes) + "&authuser=12&prompt=none",
            "&prompt=consent", "&authuser=1",
        ):
            with self.subTest(suffix=suffix), placement() as (gate, recorder, port):
                payload = request(port, extra_query=suffix, extra_headers=b"User-Agent: fixture\r\n")
                self.assertEqual(self.exchange(gate, port, payload), auth.acknowledgement(True))
                recorder.settimeout(1)
                self.assertEqual(recorder.recv(4096), request(port))
                self.assert_no_native_bytes(recorder)
                self.assertEqual(gate.outcome, auth.Outcome.FORWARDED)

    def test_owner_can_take_forwarded_fields_only_once(self):
        with placement() as (gate, _, port), ThreadPoolExecutor(max_workers=2) as workers:
            self.assertIsNone(gate.take_forwarded())
            payload = request(port, extra_query="&authuser=1&prompt=none")
            self.assertEqual(self.exchange(gate, port, payload), auth.acknowledgement(True))
            readers = [workers.submit(gate.take_forwarded) for _ in range(2)]
            results = [reader.result(timeout=2) for reader in readers]
            self.assertCountEqual(results, [None, auth.Callback(STATE, CODE)])
            selected = next(callback for callback in results if callback is not None)
            self.assertNotIn(STATE, repr(selected))
            self.assertNotIn(CODE, repr(selected))

    def test_owner_loss_or_revocation_clears_the_forwarded_handoff(self):
        for explicit in (True, False):
            with self.subTest(explicit=explicit):
                alive = Event()
                alive.set()
                with placement(authorized=alive.is_set) as (gate, _, port):
                    self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(True))
                    if explicit:
                        gate.revoke()
                    else:
                        alive.clear()
                    self.assertIsNone(gate.take_forwarded())
                    alive.set()
                    self.assertIsNone(gate.take_forwarded())
                    self.assertEqual(gate.outcome, auth.Outcome.FORWARDED)

    def test_unrelated_or_wrong_state_requests_leave_attempt_pending(self):
        with placement() as (gate, recorder, port):
            start = b"GET /?ignored="
            state_prefix = b"&state=" + STATE.encode()
            truncated_wrong_state = (start + b"a" * (8192 - len(start) - len(state_prefix))
                                     + state_prefix + b"extra HTTP/1.1\r\n\r\n")
            requests = [
                request(port, state="b" * 30),
                request(port, state="b" * 30, extra_query="&unknown=%zz"),
                request(port, target="/favicon.ico"),
                request(port, target="http://127.0.0.1/"),
                request(port, state="b" * 30, extra_query="#&state=" + STATE),
                f"GET /?code=not-the-state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode(),
            ]
            for payload in requests:
                with self.subTest(length=len(payload)):
                    self.assertEqual(self.exchange(gate, port, payload), auth.acknowledgement(False))
                    self.assertEqual(gate.outcome, auth.Outcome.OPEN)
            self.assertIn(self.exchange(gate, port, truncated_wrong_state), (b"", auth.acknowledgement(False)))
            self.assertEqual(gate.outcome, auth.Outcome.OPEN)
            self.assert_no_native_bytes(recorder)
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(True))

    def test_matching_invalid_envelope_is_terminal_without_native_bytes(self):
        scopes = " ".join(sorted(auth.SCOPES))
        encoded_live_state = "".join(f"%{ord(char):02X}" for char in STATE)
        for options in (
            {"extra_query": "&hd=workspace.example"},
            {"code": None, "extra_query": "&hd=workspace.example"},
            {"extra_query": "&unknown=%zz"},
            {"extra_query": "&unknown=%ff"},
            {"extra_query": "&code=duplicate"},
            {"extra_query": "&%73tate=" + "b" * 30},
            {"state": "b" * 30, "extra_query": "&broken&state=" + encoded_live_state},
            {"state": "b" * 30, "extra_query": "&broken=%zz&state=" + encoded_live_state},
            {"extra_query": "&scope=" + quote(scopes + " " + next(iter(auth.SCOPES)))},
            {"extra_query": "&scope=" + quote(next(iter(auth.SCOPES)))},
            {"extra_query": "&scope=" + quote(scopes + " unknown")},
            {"extra_query": "&authuser=1234"},
            {"extra_query": "&authuser=%D9%A1"},
            {"extra_query": "&authuser=1+2"},
            {"extra_query": "&prompt=login"},
            {"extra_query": "&prompt=consent&prompt=none"},
            {"extra_query": "&error=access_denied"},
            {"code": None, "extra_query": "&scope=" + quote(scopes)},
            {"code": None, "extra_query": "&error_description=" + "a" * 257},
            {"code": None, "extra_query": "&error_description=denied%0D%0Aignored"},
            {"code": None, "extra_query": "&error_description=%E2%80%8B"},
            {"code": None, "extra_query": "&error_description=" + quote("é" * 129)},
            {"extra_query": "#fragment"},
            {"extra_query": "&&prompt=none"},
            {"extra_query": "&prompt=none&"},
            {"extra_query": "&prompt=%" + "a" * 8192},
            {"code": "literal\nnewline"},
            {"method": "POST"},
            {"host": "localhost"},
            {"extra_headers": b"Content-Length: 1\r\n", "tail": b"x"},
            {"extra_headers": b"Transfer-Encoding: chunked\r\n"},
            {"extra_headers": b"Authorization: private\r\n"},
            {"extra_headers": b"Host: other\r\n"},
            {"extra_headers": b"User-Agent: " + b"a" * 8192 + b"\r\n"},
            {"tail": b"GET / HTTP/1.1\r\n\r\n"},
        ):
            with self.subTest(options=list(options)), placement() as (gate, recorder, port):
                reply = self.exchange(gate, port, request(port, **options))
                self.assertIn(reply, (b"", auth.acknowledgement(False)))
                self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
                self.assertIsNone(gate.take_forwarded())
                self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
                self.assert_no_native_bytes(recorder)

    def test_denial_is_consumed_with_no_forward_and_ack_is_static(self):
        for suffix in ("", "&error_description=The%20operator%20declined%2E",
                       "&error_description=" + quote("Autorización cancelada.")):
            with self.subTest(suffix=suffix), placement() as (gate, recorder, port):
                declined = self.exchange(gate, port, request(port, code=None, extra_query=suffix))
                replay = self.exchange(gate, port, request(port))
                self.assertEqual(declined, auth.acknowledgement(True))
                self.assertEqual(replay, auth.acknowledgement(False))
                self.assertEqual(gate.outcome, auth.Outcome.DENIED)
                self.assertIsNone(gate.take_forwarded())
                self.assert_no_native_bytes(recorder)
                for reply in (declined, replay):
                    self.assertNotIn(STATE.encode(), reply)
                    self.assertNotIn(CODE.encode(), reply)
                    self.assertNotIn(b"operator declined", reply)
                    self.assertNotIn(b"Location:", reply)
                    self.assertIn(b"Cache-Control: no-store\r\n", reply)
                    self.assertIn(b"Referrer-Policy: no-referrer\r\n", reply)

    def test_cancellation_or_owner_loss_prevents_forwarding(self):
        for explicit in (True, False):
            with self.subTest(explicit=explicit):
                alive = Event()
                alive.set()
                with placement(authorized=alive.is_set) as (gate, recorder, port):
                    if explicit:
                        gate.revoke()
                    else:
                        alive.clear()
                    self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
                    self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
                    self.assert_no_native_bytes(recorder)

    def test_authorization_crossing_deadline_blocks_native_forward(self):
        now = time.monotonic()
        expire = Event()

        def authorize():
            nonlocal now
            if expire.is_set():
                now += 20
            return True

        with (patch.object(auth, "time", SimpleNamespace(monotonic=lambda: now)),
              placement(authorized=authorize) as (gate, recorder, port)):
            expire.set()
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
            self.assert_no_native_bytes(recorder)

    def test_authorization_crossing_deadline_blocks_forwarded_handoff(self):
        now = time.monotonic()
        expire = Event()

        def authorize():
            nonlocal now
            if expire.is_set():
                now += 20
            return True

        with (patch.object(auth, "time", SimpleNamespace(monotonic=lambda: now)),
              placement(authorized=authorize) as (gate, _, port)):
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(True))
            expire.set()
            self.assertIsNone(gate.take_forwarded())
            self.assertIsNone(gate.take_forwarded())

    def test_matching_state_with_extra_request_line_spaces_revokes_only(self):
        for prefix, suffix in ((b"GET  ", b" HTTP/1.1"), (b"GET ", b"   HTTP/1.1"),
                               (b"  GET   ", b"  HTTP/1.1  ")):
            with self.subTest(spacing=(prefix, suffix)), placement() as (gate, recorder, port):
                fields = urlencode({"code": CODE, "state": STATE}).encode("ascii")
                head = f"\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode("ascii")
                for wrong in (b"/favicon.ico?" + fields,
                              b"/?" + fields.replace(STATE.encode(), b"b" * 30),
                              b"/?" + fields + b" ambiguous"):
                    self.assertEqual(self.exchange(gate, port, prefix + wrong + suffix + head),
                                     auth.acknowledgement(False))
                    self.assertEqual(gate.outcome, auth.Outcome.OPEN)
                self.assertEqual(self.exchange(gate, port, prefix + b"/?" + fields + suffix + head),
                                 auth.acknowledgement(False))
                self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
                self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
                self.assert_no_native_bytes(recorder)

    def test_short_forward_is_uncertain_and_cannot_replay(self):
        def short_write(channel, payload):
            return channel.send(payload[:4])

        with placement() as (gate, recorder, port), patch.object(auth, "_send_once", side_effect=short_write) as send:
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(True))
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            self.assertEqual(gate.outcome, auth.Outcome.UNCERTAIN)
            self.assertIsNone(gate.take_forwarded())
            recorder.settimeout(1)
            self.assertEqual(recorder.recv(4096), b"GET ")
            self.assertEqual(recorder.recv(4096), b"")
            send.assert_called_once()

    def test_revocation_during_forward_cannot_reopen_the_attempt(self):
        entered, released = Event(), Event()
        cancel_requested = Event()
        send_once = auth._send_once

        def forward(channel, data):
            entered.set()
            if not released.wait(2):
                raise AssertionError("test did not release the forward writer")
            return send_once(channel, data)

        with placement() as (gate, recorder, port), patch.object(auth, "_send_once", side_effect=forward) as send:
            with ThreadPoolExecutor(max_workers=3) as workers:
                server = workers.submit(gate.serve_one)
                client = workers.submit(exchange, port, request(port))

                def cancel():
                    cancel_requested.set()
                    gate.revoke()

                try:
                    self.assertTrue(entered.wait(2))
                    revoked = workers.submit(cancel)
                    self.assertTrue(cancel_requested.wait(2))
                    self.assertFalse(revoked.done())
                finally:
                    released.set()
                self.assertEqual(client.result(timeout=3), auth.acknowledgement(True))
                server.result(timeout=3)
                revoked.result(timeout=3)
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            self.assertEqual(gate.outcome, auth.Outcome.FORWARDED)
            recorder.settimeout(1)
            self.assertEqual(recorder.recv(4096), request(port))
            self.assert_no_native_bytes(recorder)
            send.assert_called_once()
