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
ISSUER = "https://accounts.google.com"
ORIGINAL_SCOPES = " ".join(sorted(auth.SCOPES))
OBSERVED_SCOPES = ORIGINAL_SCOPES + " email openid"
OBSERVED_QUERY = "&" + urlencode({"iss": ISSUER, "scope": OBSERVED_SCOPES, "authuser": "1", "prompt": "consent"})
COOKIE_MARKER = b"synthetic-loopback-cookie"
COOKIE_HEADER = b"CoOkIe: fixture=" + COOKIE_MARKER + b"; other=2\r\n"
REFERER_MARKER = b"synthetic-loopback-referer"
REFERER_HEADER = b"ReFeReR: https://fixture.invalid/" + REFERER_MARKER + b"\r\n"


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
            offer(port, scope=OBSERVED_SCOPES),
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
            port = occupied.getsockname()[1]
            with self.assertRaisesRegex(auth.Refused, "callback port could not be held"):
                auth.bind_callback(port)

    def test_invalid_offer_consumes_the_only_offer_slot(self):
        with placement(opened=False) as (gate, _, port):
            invalid = offer(port, state="result")
            with self.assertRaises(auth.Refused):
                gate.accept_offer(invalid)
            self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
            valid = offer(port)
            with self.assertRaisesRegex(auth.Refused, "already attempted"):
                gate.accept_offer(valid)
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

    def test_callback_refusal_records_only_reviewed_stages(self):
        cases = {
            "FRAMING": {},
            "TARGET": {"host": "localhost"},
            "PARAMETERS": {"extra_query": "&hd=fixture.invalid"},
            "HEADER_REFERER": {"extra_headers": REFERER_HEADER.removesuffix(b"\r\n") + b"\x00\r\n"},
            "HEADER_ORIGIN": {"extra_headers": b"Origin: https://fixture.invalid\r\n"},
            "HEADER_DNT": {"extra_headers": b"DNT: 1\r\n"},
            "HEADER_COOKIE": {"extra_headers": b"Cookie: synthetic\x00\r\n"},
            "HEADER_CONTENT_LENGTH": {"extra_headers": b"Content-Length: 1\r\n"},
            "HEADER_TRANSFER_ENCODING": {"extra_headers": b"Transfer-Encoding: synthetic\r\n"},
            "HEADER_SEC_PURPOSE": {"extra_headers": b"Sec-Purpose: synthetic\r\n"},
            "HEADER_OTHER": {"extra_headers": b"X-Synthetic-Unapproved: marker\r\n"},
            "HEADER_DUPLICATE": {"extra_headers": COOKIE_HEADER + b"cookie: synthetic\r\n"},
        }
        for stage, options in cases.items():
            with self.subTest(stage=stage), placement() as (gate, recorder, port):
                payload = request(port, **options)
                if stage == "FRAMING":
                    payload = payload.removesuffix(b"\r\n")
                self.assertEqual(self.exchange(gate, port, payload), auth.acknowledgement(False))
                self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
                self.assertEqual(getattr(getattr(gate, "diagnostic", None), "name", None), stage)
                self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
                self.assertEqual(gate.diagnostic.name, stage)
                self.assert_no_native_bytes(recorder)

    def test_unrelated_requests_leave_no_callback_diagnostic(self):
        with placement() as (gate, recorder, port):
            headers = b"Referer: https://fixture.invalid/synthetic\r\n"
            payloads = (
                request(port, state="b" * 30),
                request(port, state="b" * 30, extra_headers=headers),
                request(port, target="/favicon.ico", extra_headers=headers),
            )
            for payload in payloads:
                self.assertEqual(self.exchange(gate, port, payload), auth.acknowledgement(False))
                self.assertIs(gate.outcome, auth.Outcome.OPEN)
                self.assertIsNone(gate.diagnostic)
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(True))
            self.assertIsNone(gate.diagnostic)
            recorder.settimeout(1)
            self.assertEqual(recorder.recv(4096), request(port))

    def test_consumed_callback_reports_authority_loss_or_denial(self):
        alive = Event()
        alive.set()
        with placement(authorized=alive.is_set) as (gate, recorder, port):
            alive.clear()
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            self.assertIs(gate.outcome, auth.Outcome.CANCELLED)
            self.assertIs(gate.diagnostic, auth.CallbackDiagnostic.AUTHORITY_UNAVAILABLE)
            self.assert_no_native_bytes(recorder)
        with placement() as (gate, recorder, port):
            self.assertEqual(self.exchange(gate, port, request(port, code=None)), auth.acknowledgement(True))
            self.assertIs(gate.outcome, auth.Outcome.DENIED)
            self.assertIs(gate.diagnostic, auth.CallbackDiagnostic.SIGN_IN_DENIED)
            self.assert_no_native_bytes(recorder)

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

    def test_observed_browser_envelope_forwards_only_canonical_state_and_code(self):
        for suffix in (
            OBSERVED_QUERY,
            "&iss=" + ISSUER + "&scope=" + quote(OBSERVED_SCOPES) + "&authuser=1&prompt=consent",
            "&" + urlencode({"iss": ISSUER, "scope": " ".join(reversed(OBSERVED_SCOPES.split(" "))),
                              "authuser": "1", "prompt": "consent"}),
            "&iss=" + ISSUER,
            "&iss=" + ISSUER + "&scope=" + quote(ORIGINAL_SCOPES),
        ):
            with self.subTest(suffix=suffix), placement() as (gate, recorder, port):
                browser = self.exchange(gate, port, request(port, extra_query=suffix))
                self.assertEqual(browser, auth.acknowledgement(True))
                recorder.settimeout(1)
                self.assertEqual(recorder.recv(4096), request(port))
                self.assertEqual(gate.take_forwarded(), auth.Callback(STATE, CODE))
                self.assert_no_native_bytes(recorder)

    def test_sec_gpc_is_ignored_and_preserves_only_canonical_state_and_code(self):
        for value in (b"1", b"fixture-ignored"):
            with self.subTest(typical=value == b"1"), placement() as (gate, recorder, port):
                header = b"SeC-gPc: " + value + b"\r\n"
                browser = request(port, extra_query=OBSERVED_QUERY, extra_headers=header)
                self.assertEqual(self.exchange(gate, port, browser), auth.acknowledgement(True))
                recorder.settimeout(1)
                self.assertEqual(recorder.recv(4096), request(port))
                self.assertEqual(gate.take_forwarded(), auth.Callback(STATE, CODE))
                self.assertIsNone(gate.take_forwarded())
                self.assert_no_native_bytes(recorder)

    def test_ambiguous_or_unapproved_gpc_headers_cancel_matching_callback(self):
        hint = b"Sec-GPC: 1\r\n"
        cases = {
            "duplicate": hint + b"sEc-gPc: 1\r\n",
            "control": b"Sec-GPC: \x001\r\n",
            "non-ASCII": b"Sec-GPC: \xff\r\n",
            "DNT": hint + b"DNT: 1\r\n",
            "unknown": hint + b"X-Privacy-Option: 1\r\n",
            "lookalike": b"Sec_GPC: 1\r\n",
        }
        for case, headers in cases.items():
            with self.subTest(case=case), placement() as (gate, recorder, port):
                browser = request(port, extra_query=OBSERVED_QUERY, extra_headers=headers)
                self.assertEqual(self.exchange(gate, port, browser), auth.acknowledgement(False))
                self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
                self.assertIsNone(gate.take_forwarded())
                self.assert_no_native_bytes(recorder)

    def test_cookie_is_discarded_before_native_forward_and_acknowledgment(self):
        for gpc in (b"", b"Sec-GPC: 1\r\n"):
            with self.subTest(gpc=bool(gpc)), placement() as (gate, recorder, port):
                browser = request(port, extra_query=OBSERVED_QUERY, extra_headers=COOKIE_HEADER + gpc)
                reply = self.exchange(gate, port, browser)
                self.assertEqual(reply, auth.acknowledgement(True))
                recorder.settimeout(1)
                native = recorder.recv(4096)
                self.assertEqual(native, request(port))
                self.assertNotIn(COOKIE_MARKER, reply)
                self.assertNotIn(COOKIE_MARKER, native)
                self.assertEqual(gate.take_forwarded(), auth.Callback(STATE, CODE))
                self.assertIsNone(gate.take_forwarded())
                self.assert_no_native_bytes(recorder)

    def test_referer_cookie_and_gpc_preserve_only_canonical_state_and_code(self):
        for referer in (REFERER_HEADER, b"Referer: " + REFERER_MARKER + b"\r\n"):
            with self.subTest(url=referer == REFERER_HEADER), placement() as (gate, recorder, port):
                headers = referer + COOKIE_HEADER + b"Sec-GPC: 1\r\n"
                browser = request(port, extra_query=OBSERVED_QUERY, extra_headers=headers)
                reply = self.exchange(gate, port, browser)
                self.assertEqual(reply, auth.acknowledgement(True))
                self.assertIn(b"Referrer-Policy: no-referrer\r\n", reply)
                recorder.settimeout(1)
                native = recorder.recv(4096)
                self.assertEqual(native, request(port))
                for marker in (COOKIE_MARKER, REFERER_MARKER):
                    self.assertNotIn(marker, native)
                    self.assertNotIn(marker, reply)
                self.assertEqual(gate.take_forwarded(), auth.Callback(STATE, CODE))
                self.assertIsNone(gate.take_forwarded())
                self.assertEqual(self.exchange(gate, port, browser), auth.acknowledgement(False))
                self.assert_no_native_bytes(recorder)

    def test_referer_does_not_relax_callback_validation(self):
        cases = {
            "duplicate": {"extra_headers": REFERER_HEADER + b"referer: duplicate\r\n"},
            "control byte": {"extra_headers": REFERER_HEADER.replace(b"\r\n", b"\x00\r\n")},
            "non-ASCII byte": {"extra_headers": REFERER_HEADER.replace(b"\r\n", b"\xff\r\n")},
            "size bound": {"extra_headers": REFERER_HEADER.replace(b"\r\n", b"a" * auth._LIMIT + b"\r\n")},
            "origin": {"extra_headers": REFERER_HEADER + b"Origin: https://fixture.invalid\r\n"},
            "unknown header": {"extra_headers": REFERER_HEADER + b"X-Browser-Metadata: fixture\r\n"},
            "wrong host": {"host": "localhost"},
            "wrong issuer": {"extra_query": OBSERVED_QUERY.replace(ISSUER.partition("://")[2], "fixture.invalid")},
            "request body": {"tail": b"fixture"},
        }
        categories = {
            "duplicate": auth.CallbackDiagnostic.HEADER_DUPLICATE,
            "control byte": auth.CallbackDiagnostic.HEADER_REFERER,
            "non-ASCII byte": auth.CallbackDiagnostic.HEADER_REFERER,
            "size bound": auth.CallbackDiagnostic.FRAMING,
            "origin": auth.CallbackDiagnostic.HEADER_ORIGIN,
            "unknown header": auth.CallbackDiagnostic.HEADER_OTHER,
            "wrong host": auth.CallbackDiagnostic.TARGET,
            "wrong issuer": auth.CallbackDiagnostic.PARAMETERS,
            "request body": auth.CallbackDiagnostic.FRAMING,
        }
        for case, options in cases.items():
            with self.subTest(case=case), placement() as (gate, recorder, port):
                payload = request(port, **({"extra_headers": REFERER_HEADER, "extra_query": OBSERVED_QUERY} | options))
                reply = self.exchange(gate, port, payload)
                if case == "size bound":
                    self.assertIn(reply, (b"", auth.acknowledgement(False)))
                else:
                    self.assertEqual(reply, auth.acknowledgement(False))
                self.assertNotIn(REFERER_MARKER, reply)
                self.assertIs(gate.outcome, auth.Outcome.CANCELLED)
                self.assertIs(gate.diagnostic, categories[case])
                self.assertIsNone(gate.take_forwarded())
                self.assert_no_native_bytes(recorder)

    def test_cookie_does_not_relax_callback_validation(self):
        cases = {
            "duplicate": {"extra_headers": COOKIE_HEADER + b"cOoKiE: fixture=duplicate\r\n"},
            "control byte": {"extra_headers": COOKIE_HEADER.replace(b";", b"\x00;")},
            "non-ASCII byte": {"extra_headers": COOKIE_HEADER.replace(b";", b"\xff;")},
            "authorization": {"extra_headers": COOKIE_HEADER + b"Authorization: Bearer fixture\r\n"},
            "origin": {"extra_headers": COOKIE_HEADER + b"Origin: https://accounts.google.com\r\n"},
            "unknown header": {"extra_headers": COOKIE_HEADER + b"X-Browser-Metadata: fixture\r\n"},
            "size bound": {"extra_headers": COOKIE_HEADER.replace(b";", b"a" * auth._LIMIT)},
            "unapproved parameter": {"extra_query": "&hd=fixture.invalid"},
            "wrong host": {"host": "localhost"},
            "request body": {"tail": b"fixture"},
        }
        for case, options in cases.items():
            with self.subTest(case=case), placement() as (gate, recorder, port):
                browser = request(port, **({"extra_headers": COOKIE_HEADER, "extra_query": OBSERVED_QUERY} | options))
                reply = self.exchange(gate, port, browser)
                if case == "size bound":
                    self.assertIn(reply, (b"", auth.acknowledgement(False)))
                else:
                    self.assertEqual(reply, auth.acknowledgement(False))
                self.assertNotIn(COOKIE_MARKER, reply)
                self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
                self.assertIsNone(gate.take_forwarded())
                self.assert_no_native_bytes(recorder)

        with placement() as (gate, recorder, port):
            browser = request(port, state="b" * 30, extra_query=OBSERVED_QUERY, extra_headers=COOKIE_HEADER)
            self.assertEqual(self.exchange(gate, port, browser), auth.acknowledgement(False))
            self.assertEqual(gate.outcome, auth.Outcome.OPEN)
            self.assert_no_native_bytes(recorder)

    def test_malformed_cookie_refusal_does_not_expose_its_value(self):
        header = COOKIE_HEADER.removesuffix(b"\r\n") + b"\x00\r\n"
        head = request(49000, extra_query=OBSERVED_QUERY, extra_headers=header).removesuffix(b"\r\n\r\n")
        with self.assertRaisesRegex(auth.Refused, "^invalid callback header$") as refusal:
            auth.parse_callback(head, 49000)
        self.assertNotIn(COOKIE_MARKER.decode("ascii"), str(refusal.exception))

    def test_chromium_client_hints_preserve_only_canonical_state_and_code(self):
        hints = (b'Sec-CH-UA: "Chromium";v="131", "Not_A Brand";v="24"\r\n'
                 b"Sec-CH-UA-Mobile: ?0\r\n"
                 b'sec-CH-ua-platform: "Linux"\r\n')
        with placement() as (gate, recorder, port):
            browser = request(port, extra_query=OBSERVED_QUERY, extra_headers=hints)
            self.assertEqual(self.exchange(gate, port, browser), auth.acknowledgement(True))
            recorder.settimeout(1)
            self.assertEqual(recorder.recv(4096), request(port))
            self.assertEqual(gate.take_forwarded(), auth.Callback(STATE, CODE))
            self.assertIsNone(gate.take_forwarded())
            self.assert_no_native_bytes(recorder)

    def test_unapproved_or_ambiguous_chromium_hint_headers_cancel_matching_callback(self):
        approved = (b'Sec-CH-UA: "Chromium";v="131"\r\n'
                    b"Sec-CH-UA-Mobile: ?0\r\n"
                    b'Sec-CH-UA-Platform: "Linux"\r\n')
        cases = {
            "case-insensitive duplicate": approved + b"sec-ch-uA: duplicate\r\n",
            "control character": approved.replace(b"?0", b"?0\x00"),
            "non-ASCII value": approved.replace(b"Linux", b"Linu\xff"),
            "unknown hint": approved + b'Sec-CH-UA-Full-Version: "131.0"\r\n',
            "lookalike name": approved + b"Sec_CH_UA: fixture\r\n",
            "authorization": approved + b"Authorization: Bearer fixture\r\n",
            "forwarded": approved + b"X-Forwarded-Host: fixture.invalid\r\n",
        }
        for case, headers in cases.items():
            with self.subTest(case=case), placement() as (gate, recorder, port):
                browser = request(port, extra_query=OBSERVED_QUERY, extra_headers=headers)
                self.assertEqual(self.exchange(gate, port, browser), auth.acknowledgement(False))
                self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
                self.assertIsNone(gate.take_forwarded())
                self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
                self.assert_no_native_bytes(recorder)

    def test_storage_access_hint_is_ignored_in_forward_and_acknowledgment(self):
        hints = (b'Sec-CH-UA: "Chromium";v="131"\r\n'
                 b"Sec-CH-UA-Mobile: ?0\r\n"
                 b'Sec-CH-UA-Platform: "Linux"\r\n')
        for value in (b"none", b"active", b"fixture-unused"):
            with self.subTest(value=value), placement() as (gate, recorder, port):
                headers = hints + b"Sec-Fetch-Storage-Access: " + value + b"\r\n"
                browser = request(port, extra_query=OBSERVED_QUERY, extra_headers=headers)
                reply = self.exchange(gate, port, browser)
                self.assertEqual(reply, auth.acknowledgement(True))
                self.assertNotIn(b"activate-storage-access:", reply.lower())
                recorder.settimeout(1)
                self.assertEqual(recorder.recv(4096), request(port))
                self.assertEqual(gate.take_forwarded(), auth.Callback(STATE, CODE))
                self.assert_no_native_bytes(recorder)

    def test_ambiguous_storage_access_or_origin_cancels_matching_callback(self):
        hint = b"Sec-Fetch-Storage-Access: none\r\n"
        for headers in (
            hint + b"sEc-fEtCh-StOrAgE-aCcEsS: active\r\n",
            hint.replace(b"none", b"non\x00e"),
            hint + b"Origin: https://accounts.google.com\r\n",
        ):
            with self.subTest(headers=headers), placement() as (gate, recorder, port):
                browser = request(port, extra_query=OBSERVED_QUERY, extra_headers=headers)
                reply = self.exchange(gate, port, browser)
                self.assertEqual(reply, auth.acknowledgement(False))
                self.assertNotIn(b"activate-storage-access:", reply.lower())
                self.assertEqual(gate.outcome, auth.Outcome.CANCELLED)
                self.assertIsNone(gate.take_forwarded())
                self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
                self.assert_no_native_bytes(recorder)

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
            {"extra_query": "&scope=" + quote(OBSERVED_SCOPES)},
            {"extra_query": "&iss=" + ISSUER + "&scope=" + quote(scopes + " email")},
            {"extra_query": "&iss=" + ISSUER + "&scope=" + quote(scopes + " openid")},
            {"extra_query": "&iss=" + ISSUER + "&scope=" + quote(OBSERVED_SCOPES + " email")},
            {"extra_query": "&iss=" + ISSUER + "&scope=" + quote(OBSERVED_SCOPES + " unknown")},
            {"extra_query": "&iss=" + ISSUER + "&scope=" + quote("email openid")},
            {"extra_query": "&iss=" + ISSUER + "&scope=" + quote(scopes + " email openid ")},
            {"extra_query": "&iss=&scope=" + quote(OBSERVED_SCOPES)},
            {"extra_query": "&iss=https://other.example&scope=" + quote(OBSERVED_SCOPES)},
            {"extra_query": "&iss=http://accounts.google.com"},
            {"extra_query": "&iss=https://accounts.google.com/"},
            {"extra_query": "&iss=accounts.google.com"},
            {"extra_query": "&iss=https%3A%2F%2Faccounts.google.com%00"},
            {"extra_query": "&iss=%ff"},
            {"extra_query": "&iss=" + ISSUER + "&%69ss=" + ISSUER},
            {"extra_query": "&iss=" + ISSUER + "&iss=https://other.example"},
            {"extra_query": "&scope=" + quote(scopes) + "&scope=" + quote(OBSERVED_SCOPES)},
            {"extra_query": OBSERVED_QUERY + "&hd=workspace.example"},
            {"extra_query": OBSERVED_QUERY + "&error=access_denied"},
            {"extra_query": OBSERVED_QUERY + "&unknown=seventh"},
            {"extra_query": "&authuser=1234"},
            {"extra_query": "&authuser=%D9%A1"},
            {"extra_query": "&authuser=1+2"},
            {"extra_query": "&prompt=login"},
            {"extra_query": "&prompt=consent&prompt=none"},
            {"extra_query": "&error=access_denied"},
            {"code": None, "extra_query": "&scope=" + quote(scopes)},
            {"code": None, "extra_query": "&iss=https://other.example"},
            {"code": None, "extra_query": "&iss=" + ISSUER + "&iss=" + ISSUER},
            {"code": None, "extra_query": "&iss=" + ISSUER + "&scope=" + quote(OBSERVED_SCOPES)},
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
                       "&error_description=" + quote("Autorización cancelada."),
                       "&iss=" + ISSUER, "&" + urlencode({"iss": ISSUER, "error_description": "Operator declined."})):
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
                    self.assertNotIn(ISSUER.encode(), reply)
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
                    self.assertEqual(self.exchange(gate, port, request(port, extra_query=OBSERVED_QUERY)),
                                     auth.acknowledgement(False))
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

    def test_owner_loss_after_consume_withholds_success_ack(self):
        live = Event()
        live.set()
        consume = auth.CallbackGate._consume

        def revoke_after_forward(gate, callback, address):
            accepted = consume(gate, callback, address)
            live.clear()
            return accepted

        with placement(authorized=live.is_set) as (gate, _recorder, port), \
                patch.object(auth.CallbackGate, "_consume", autospec=True, side_effect=revoke_after_forward):
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            self.assertEqual(gate.outcome, auth.Outcome.UNCERTAIN)
            self.assertIs(gate.diagnostic, auth.CallbackDiagnostic.HANDOFF_UNCONFIRMED)
            live.set()
            self.assertIsNone(gate.take_forwarded())
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))

    def test_owner_loss_inside_full_forward_withholds_success_ack(self):
        live = Event()
        live.set()
        original_send = auth._send_once

        def forward(channel, data):
            sent = original_send(channel, data)
            live.clear()
            return sent

        with placement(authorized=live.is_set) as (gate, _recorder, port), \
                patch.object(auth, "_send_once", side_effect=forward) as send:
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            self.assertEqual(gate.outcome, auth.Outcome.UNCERTAIN)
            live.set()
            self.assertIsNone(gate.take_forwarded())
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            send.assert_called_once()

    def test_short_forward_is_uncertain_and_cannot_replay(self):
        def short_write(channel, payload):
            return channel.send(payload[:4])

        with placement() as (gate, recorder, port), patch.object(auth, "_send_once", side_effect=short_write) as send:
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            self.assertEqual(gate.outcome, auth.Outcome.UNCERTAIN)
            self.assertIs(gate.diagnostic, auth.CallbackDiagnostic.HANDOFF_UNCONFIRMED)
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
                reply = client.result(timeout=3)
                server.result(timeout=3)
                revoked.result(timeout=3)
            # Revocation can win before or after browser acknowledgement. Both
            # orders preserve the one private write and refuse replay.
            expected = {
                auth.acknowledgement(True): auth.Outcome.FORWARDED,
                auth.acknowledgement(False): auth.Outcome.UNCERTAIN,
            }
            self.assertIn(reply, expected)
            self.assertEqual(gate.outcome, expected[reply])
            self.assertIsNone(gate.take_forwarded())
            self.assertEqual(self.exchange(gate, port, request(port)), auth.acknowledgement(False))
            recorder.settimeout(1)
            self.assertEqual(recorder.recv(4096), request(port))
            self.assert_no_native_bytes(recorder)
            send.assert_called_once()
