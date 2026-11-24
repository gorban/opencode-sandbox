"""Test production HTTP framing on an in-process socket pair."""

import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import pwd
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from oc_openai.connection import IDTokenVerifier, ISSUER
from oc_openai.responses import API_HOST, AUTH_HOST, TOKEN
from oc_openai.responses import Cancellation, ConnectionError, OpenAITransport
from oc_openai.responses import _StrictResponse


BODY = {"model": "gpt-6.2-sol", "store": False, "stream": True, "input": []}


def _sse_chunks(parts, suffix=b"0\r\nX-Fixture: trailer\r\n\r\n"):
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
            + b"".join(f"{len(part):x}\r\n".encode("ascii") + part + b"\r\n" for part in parts) + suffix)


class WireTests(unittest.TestCase):
    @contextlib.contextmanager
    def response(self, wire, expected_host=API_HOST, *, hold=None):
        local, peer = socket.socketpair()
        local.settimeout(2)
        peer.settimeout(2)
        request = []

        def serve():
            with peer, peer.makefile("rb") as incoming:
                headers = {}
                request.append(incoming.readline())
                while True:
                    line = incoming.readline()
                    if line in (b"", b"\r\n"):
                        break
                    key, val = line.split(b":", 1)
                    headers[key.lower()] = val.strip()
                request.append(headers)
                request.append(incoming.read(int(headers[b"content-length"])))
                peer.sendall(wire)
                if hold is not None:
                    hold.wait(3)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        def connect(host, cancellation):
            self.assertEqual(host, expected_host)
            cancellation.attach(local)
            return local

        try:
            with patch("oc_openai.responses._connect", connect):
                yield request
        finally:
            if hold is not None:
                hold.set()
            local.close()
            thread.join(3)
            self.assertFalse(thread.is_alive())

    def streams(self):
        return OpenAITransport().responses(
            BODY, "synthetic-workstation-access", Cancellation(time.monotonic() + 2),
            lambda write: write(),
        )

    def _first_event(self):
        with self.streams() as events:
            return next(events)

    def _all_events(self):
        with self.streams() as events:
            return list(events)

    def test_http_rejections_are_not_reported_as_stream_or_plan_limit_failures(self):
        from oc_openai.acceptance import run_attended
        from oc_openai.exposure import ExposureLedger
        from oc_openai.live import WorkstationBackend
        from test_openai_live import FakeConnection, Terminal, SELECTION_EPOCH

        canary = "must-not-appear-in-terminal"
        for status, content_type, body, expected in (
            (429, "application/json", json.dumps({"error": {"code": canary, "message": canary}}),
             "OpenAI rejected the request."),
            (503, "text/plain", canary, "OpenAI rejected the request."),
            (429, "application/json", json.dumps({"error": {"code": "subscription_sharing_usage_limit_exceeded"}}),
             "OpenAI reported a ChatGPT plan usage limit."),
        ):
            with self.subTest(status=status, body_type=content_type, expected=expected), tempfile.TemporaryDirectory() as scratch:
                state = Path(scratch)
                connection = FakeConnection(state)
                backend = WorkstationBackend(connection, ExposureLedger(state), label="personal",
                                             selection_epoch=SELECTION_EPOCH, worker=object(),
                                             placement_qualified=True)

                def route(binding, request_body, before_send, **options):
                    def dispatch(write):
                        before_send()
                        return write()
                    return OpenAITransport().responses(
                        request_body, "synthetic-workstation-access", Cancellation(time.monotonic() + 2), dispatch,
                    )

                response = (f"HTTP/1.1 {status} Fixture\r\nContent-Type: {content_type}\r\n"
                            f"X-Request-ID: {canary}\r\nContent-Length: {len(body)}\r\n\r\n{body}").encode("ascii")
                terminal = Terminal(True)
                with self.response(response) as request, patch.object(connection, "responses", route):
                    self.assertEqual(run_attended(terminal, backend_factory=lambda: backend), 1)
                self.assertEqual(request[0], b"POST /v1/responses HTTP/1.1\r\n")
                self.assertEqual(terminal.output[-1], f"Workstation proposal: {expected}")
                self.assertNotIn(canary, "\n".join(terminal.output))
                rows = json.loads((state / "exposure.json").read_text())
                self.assertEqual([(row["phase"], row["actual"]) for row in rows], [("orchestrator", None)])

    def test_catalog_failure_precedes_inference_and_reports_response_data(self):
        from oc_openai.acceptance import run_attended
        from oc_openai.connection import Connection
        from oc_openai.exposure import ExposureLedger
        from oc_openai.live import WorkstationBackend
        from oc_openai.responses import MAX_JSON
        from test_openai_connection import FixtureBrowser, FixtureTransport, FixtureVerifier
        from test_openai_live import Terminal, SELECTION_EPOCH

        canary = b"must-not-appear-in-terminal"
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        for length in (len(canary), MAX_JSON + 1):
            with self.subTest(length=length), tempfile.TemporaryDirectory(dir=home) as scratch:
                state = Path(scratch)
                connection = Connection(state / "profile", transport=FixtureTransport(),
                                        browser=FixtureBrowser(), verifier=FixtureVerifier())
                connection.connect()
                connection._transport = OpenAITransport()
                backend = WorkstationBackend(connection, ExposureLedger(state), label="personal",
                                             selection_epoch=SELECTION_EPOCH, worker=object(),
                                             placement_qualified=True)
                response = (b"HTTP/1.1 503 Fixture\r\nContent-Type: text/plain\r\n"
                            + f"Content-Length: {length}\r\n\r\n".encode("ascii") + canary)
                terminal = Terminal(True)
                ledger = state / "exposure.json"
                self.assertFalse(ledger.exists())
                with self.response(response) as request:
                    self.assertEqual(run_attended(terminal, backend_factory=lambda: backend), 1)
                self.assertEqual(len(request), 3)
                self.assertEqual(request[0], b"GET /v1/models HTTP/1.1\r\n")
                self.assertEqual(terminal.output[-1],
                                 "Workstation proposal: OpenAI returned invalid or oversized response data.")
                self.assertNotIn(canary.decode(), "\n".join(terminal.output))
                self.assertFalse(ledger.exists())

    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "synthetic TLS certificate dependency unavailable")
    def test_close_delimited_response_requires_clean_tls_shutdown(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, API_HOST)])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(private.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(minutes=5))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(API_HOST)]), critical=False)
            .sign(private, hashes.SHA256())
        )
        pem = certificate.public_bytes(serialization.Encoding.PEM)
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.load_verify_locations(cadata=pem.decode("ascii"))
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with tempfile.TemporaryDirectory() as directory:
            cert_path = Path(directory) / "fixture-cert.pem"
            key_path = Path(directory) / "fixture-key.pem"
            cert_path.write_bytes(pem)
            key_path.write_bytes(private.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
            server_context.load_cert_chain(cert_path, key_path)

        response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
                    b'data: {"type":"response.completed"}\n\ndata: [DONE]\n\n')
        for clean in (False, True):
            with self.subTest(clean=clean), socket.socket() as listener:
                listener.settimeout(2)
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                addresses = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", listener.getsockname())]
                errors = []

                def serve():
                    try:
                        raw, _ = listener.accept()
                        with raw:
                            raw.settimeout(2)
                            with server_context.wrap_socket(raw, server_side=True) as peer:
                                with peer.makefile("rb") as incoming:
                                    size = 0
                                    while (line := incoming.readline()) not in (b"", b"\r\n"):
                                        if line.lower().startswith(b"content-length:"):
                                            size = int(line.split(b":", 1)[-1])
                                    incoming.read(size)
                                peer.sendall(response)
                                if clean:
                                    # The fixture has sent close_notify even if the
                                    # client closes before sending one in return.
                                    with contextlib.suppress(ssl.SSLEOFError):
                                        peer.unwrap().close()
                    except Exception as error:
                        errors.append(error)

                thread = threading.Thread(target=serve, daemon=True)
                thread.start()
                try:
                    with (patch("oc_openai.responses._address_list", return_value=addresses),
                          patch("oc_openai.responses.ssl.create_default_context", return_value=client_context)):
                        if clean:
                            with self.streams() as events:
                                self.assertEqual(list(events), [{"type": "response.completed"}])
                        else:
                            with self.assertRaises(ConnectionError) as error:
                                self._first_event()
                            self.assertEqual(error.exception.code, "provider_network_error")
                finally:
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(errors, [])

    def test_only_fixed_http_request_and_complete_sse_frames(self):
        event = b'event: response.completed\r\ndata: {"type":"response.completed"}\r\n\r\n'
        wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                + f"{len(event):X}\r\n".encode("ascii") + event + b"\r\n0\r\n\r\n")
        with self.response(wire) as request, self.streams() as events:
            self.assertEqual(list(events), [{"type": "response.completed"}])
        self.assertEqual(request[0], b"POST /v1/responses HTTP/1.1\r\n")
        self.assertEqual(request[1][b"authorization"], b"Bearer synthetic-workstation-access")
        self.assertEqual(request[1][b"host"], b"api.openai.com")
        self.assertNotIn(b"max_output_tokens", request[2])

    def test_malformed_event_and_premature_http_eof_fail(self):
        for event, extra in (
            (b'event: response.failed\ndata: {"type":"response.completed"}\n\n', 0),
            (b'data: {"type":"response.completed","type":"response.failed"}\n\n', 0),
            (b'data: {"type":"response.completed"}\n', 0),
            (b'data: {"type":"response.completed"}\n\n', 1),
        ):
            with self.subTest(event=event, extra=extra):
                length = str(len(event) + extra).encode("ascii")
                wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                        b"Content-Length: " + length + b"\r\n\r\n" + event)
                with self.response(wire), self.streams() as events, self.assertRaises(ConnectionError):
                    list(events)

    def test_completion_unavailable_until_done_and_http_framing_finish(self):
        completed = b'data: {"type":"response.completed"}\n\ndata: [DONE]\n\n'
        size = f"{len(completed):x}\r\n".encode("ascii")
        header = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
        chunk_header = header + b"Transfer-Encoding: chunked\r\n\r\n"
        cases = (
            header + b"Content-Length: " + str(len(completed) + 1).encode("ascii") + b"\r\n\r\n" + completed,
            chunk_header + size + completed + b"\r\n0\r\n",
            chunk_header + size + completed + b"\x00\x000\r\n\r\n",
            header + b"\r\n" + completed + b'data: {"type":"response.failed"}\n\n',
        )
        for wire in cases:
            with self.subTest(wire=wire), self.response(wire), self.assertRaises(ConnectionError):
                self._first_event()
        with self.response(chunk_header + size + completed + b"\r\n0\r\n\r\n"), self.streams() as events:
            self.assertEqual(list(events), [{"type": "response.completed"}])

    def test_sse_standard_lines_count_bom_and_delimiters_at_exact_caps(self):
        bom = b"\xef\xbb\xbf"
        created = b'data: {"type":"response.created"}'
        completed = b'data: {"type":"response.completed"}'
        for ending in (b"\r", b"\n", b"\r\n"):
            with self.subTest(ending=ending):
                longest = bom + b": " + b"x" * 100 + ending
                body = longest + ending.join((created, b"", completed, b"", b"data: [DONE]", b"", b""))
                wire = _sse_chunks([body[index:index + 1] for index in range(len(body))])
                with (patch.multiple("oc_openai.responses", MAX_LINE=len(longest), MAX_STREAM=len(body)),
                      self.response(wire), self.streams() as events):
                    self.assertEqual([event["type"] for event in events], ["response.created", "response.completed"])
                for limits in ({"MAX_LINE": len(longest) - 1}, {"MAX_STREAM": len(body) - 1}):
                    with (patch.multiple("oc_openai.responses", **limits), self.response(wire),
                          self.streams() as events, self.assertRaisesRegex(ConnectionError, "provider_stream_limit")):
                        for event in events:
                            self.assertNotEqual(event["type"], "response.completed")

        body = bom + created + b"\r\n\r\n" + completed + b"\r\n\r\n"
        wire = _sse_chunks([body[index:index + 1] for index in range(len(body))])
        with self.response(wire), self.streams() as events:
            self.assertEqual([event["type"] for event in events], ["response.created", "response.completed"])

    def test_named_done_requires_completed_response_and_clean_framing(self):
        completed = b'data: {"type":"response.completed"}\n\n'
        for name in (b"done", b"message"):
            sentinel = b"event: " + name + b"\ndata: [DONE]\n\n"
            parts = [completed, sentinel, b": keepalive\r\n\r\n"]
            with self.subTest(name=name), self.response(_sse_chunks(parts)), self.streams() as events:
                self.assertEqual(list(events), [{"type": "response.completed"}])
            for wire, reason in (
                (_sse_chunks([sentinel, completed]), "provider_stream_named_done"),
                (_sse_chunks([completed, b"event:  " + name + b"\ndata: [DONE]\n\n"]),
                 "provider_stream_named_done"),
                (_sse_chunks([*parts, completed]), "provider_stream_after_terminal"),
                (_sse_chunks(parts, b"0\r\nX-Fixture: trailer\r\n"), "provider_network_error"),
            ):
                with (self.subTest(name=name, reason=reason), self.response(wire),
                      self.assertRaisesRegex(ConnectionError, reason), self.streams() as events):
                    for event in events:
                        self.assertNotEqual(event["type"], "response.completed")
        other = b"event: response.failed\ndata: [DONE]\n\n"
        with (self.response(_sse_chunks([completed, other])), self.streams() as events,
              self.assertRaisesRegex(ConnectionError, "provider_stream_named_done")):
            for event in events:
                self.assertNotEqual(event["type"], "response.completed")

    def test_sse_cancellation_after_http_body_withholds_completion(self):
        completed = b'data: {"type":"response.completed"}\n\n'
        cancellation = Cancellation(time.monotonic() + 2)
        read1 = _StrictResponse.read1

        def cancel_at_end(response, count):
            block = read1(response, count)
            if not block:
                cancellation.event.set()
            return block

        with (
            self.response(_sse_chunks([completed, b"event: done\ndata: [DONE]\n\n"])),
            patch.object(_StrictResponse, "read1", cancel_at_end),
            OpenAITransport().responses(BODY, "synthetic-access", cancellation, lambda write: write()) as events,
            self.assertRaisesRegex(ConnectionError, "connection_retired"),
        ):
            for event in events:
                self.assertNotEqual(event["type"], "response.completed")

    def test_generic_sse_names_use_the_json_type_without_weakening_named_checks(self):
        created = b'data: {"type":"response.created"}\n\n'
        completed = b'data: {"type":"response.completed"}\n\n'
        for generic in (b"event:\n", b"event: message\n"):
            parts = [generic + created, generic + completed]
            with self.subTest(generic=generic), self.response(_sse_chunks(parts)), self.streams() as events:
                self.assertEqual([event["type"] for event in events], ["response.created", "response.completed"])
        for frame, reason in (
            (b"event:\nevent: message\n" + created, "provider_stream_event_type"),
            (b"event: message\ndata: {}\n\n", "provider_stream_event_type"),
            (b"event: response.failed\n" + completed, "provider_stream_event_type"),
            (completed + b"event:\ndata: [DONE]\n\n", "provider_stream_named_done"),
        ):
            with (self.subTest(frame=frame), self.response(_sse_chunks([frame])),
                  self.assertRaisesRegex(ConnectionError, reason), self.streams() as events):
                for event in events:
                    self.assertNotEqual(event["type"], "response.completed")

    def test_stream_evidence_is_structural_and_only_shown_in_the_final_mode(self):
        from oc_openai.acceptance import run_attended
        from oc_openai.exposure import ExposureLedger, Phase, RecoveryMode, Slot, binding_digest
        from oc_openai.live import WorkstationBackend
        from test_openai_live import FakeConnection, Terminal, REGISTRATION, GENERATION, SELECTION_EPOCH, proposal_events

        canary = b"opaque-canary-must-not-appear"
        created, completed = [b"data: " + json.dumps(event).encode("ascii") + b"\n\n"
                              for event in proposal_events()]
        extra_event = b'event: ' + canary + b'\ndata: {"type":"' + canary + b'"}\n\n'
        cases = (
            (None, b"text/event-stream", extra_event, ""),
            (RecoveryMode.FIRST, b"text/event-stream", extra_event, ""),
            (RecoveryMode.STREAM, b"text/event-stream", extra_event,
             "provider_stream_after_terminal {bytes} lines=7 events=3 last_line=separator "
             "sse=other json_type=other completed_seen=1 done_seen=0"
             " media_fields=one prefix=not-read prefix_bytes=0"),
            (RecoveryMode.STREAM, b"text/" + canary, extra_event,
             "provider_stream_content_type media=other raw_bytes={probe} lines=0 events=0 last_line=none "
             "sse=none json_type=none completed_seen=0 done_seen=0"
             " media_fields=one prefix=sse-like prefix_bytes={probe}"),
            (RecoveryMode.STREAM, b"text / event-stream", extra_event,
             "provider_stream_content_type media=ambiguous raw_bytes={probe} lines=0 events=0 last_line=none "
             "sse=none json_type=none completed_seen=0 done_seen=0"
             " media_fields=one prefix=sse-like prefix_bytes={probe}"),
            (RecoveryMode.STREAM, b"text/event-stream", b"event\ndata: [DONE]\n\n",
             "provider_stream_named_done {bytes} lines=7 events=3 last_line=separator "
             "sse=empty json_type=none completed_seen=1 done_seen=1"
             " media_fields=one prefix=not-read prefix_bytes=0"),
            (RecoveryMode.STREAM, b"text/event-stream", b"data\ndata: [DONE]\n\n",
             "provider_stream_json {bytes} lines=7 events=3 last_line=separator "
             "sse=none json_type=none completed_seen=1 done_seen=0"
             " media_fields=one prefix=not-read prefix_bytes=0"),
        )
        for mode, media, suffix, summary in cases:
            with self.subTest(mode=mode, summary=summary), tempfile.TemporaryDirectory() as scratch:
                state = Path(scratch)
                ledger = ExposureLedger(state)
                binding = binding_digest(REGISTRATION, GENERATION, SELECTION_EPOCH)
                if mode is not None:
                    ledger.reserve(Slot("1" * 32, binding, Phase.ORCHESTRATOR))
                if mode is RecoveryMode.STREAM:
                    ledger.reserve_diagnostic(ledger.prepare_diagnostic(Slot("2" * 32, binding, Phase.ORCHESTRATOR)))
                connection = FakeConnection(state)
                backend = WorkstationBackend(connection, ledger, label="fixture", selection_epoch=SELECTION_EPOCH,
                                             worker=object(), placement_qualified=True)
                delivered = []

                @contextlib.contextmanager
                def route(binding, request_body, before_send, **options):
                    def dispatch(write):
                        before_send()
                        return write()

                    def observe(events):
                        for event in events:
                            delivered.append(event["type"])
                            yield event

                    with OpenAITransport().responses(
                        request_body, "synthetic-access", Cancellation(time.monotonic() + 2), dispatch,
                        inspect_media=options.get("inspect_media", False),
                    ) as events:
                        yield observe(events)

                body = created + completed + suffix
                wire = (b"HTTP/1.1 200 OK\r\nContent-Type: " + media
                        + f"\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
                terminal = Terminal(True)
                with self.response(wire), patch.object(connection, "responses", route):
                    self.assertEqual(run_attended(terminal, backend_factory=lambda: backend, recovery=mode), 1)
                self.assertNotIn(canary.decode(), "\n".join(terminal.output))
                self.assertNotIn("response.completed", delivered)
                structure = [line for line in terminal.output if line.startswith("Stream structure")]
                if mode is RecoveryMode.STREAM:
                    code, facts = summary.split(" ", 1)
                    facts = facts.format(bytes=f"media=sse raw_bytes={len(body)}", probe=min(len(body), 512))
                    self.assertEqual(structure, [f"Stream structure ({code}) {facts}"])
                    held = json.loads((state / "diagnostic-stream.json").read_text())
                elif mode is RecoveryMode.FIRST:
                    self.assertEqual(structure, [])
                    held = json.loads((state / "diagnostic.json").read_text())
                else:
                    self.assertEqual(structure, [])
                    held = json.loads((state / "exposure.json").read_text())[-1]
                self.assertIsNone(held["actual"])

    def test_unexpected_media_probe_is_bounded_and_opt_in(self):
        from oc_openai.responses import StreamFailure

        canary = b"never-report-this-value"
        tests = (
            (b"", [b"d", b"a", b"ta: " + canary], b"0\r\n\r\n", "none", "missing",
             "sse-like", len(b"data: " + canary)),
            (b"Content-Type: malformed-" + canary + b"\r\n", [b"{" + canary], b"0\r\n\r\n",
             "one", "ambiguous", "json-like", 1 + len(canary)),
            (b"Content-Type: text/html\r\nContent-Type: application/json\r\n", [b"<" + canary],
             b"0\r\n\r\n", "multiple", "ambiguous", "markup-like", 1 + len(canary)),
            (b"Content-Type: text/plain\r\n", [b" " * 900], b"0\r\n\r\n",
             "one", "plain", "inconclusive", 512),
            (b"Content-Type: application/x-ndjson\r\n", [], b"0\r\n\r\n",
             "one", "ndjson", "empty", 0),
            (b"Content-Type: text/plain\r\n", [b"d"], b"0\r\n",
             "one", "plain", "inconclusive", 1),
        )
        for fields, parts, end, count, media, shape, size in tests:
            with self.subTest(count=count, media=media, shape=shape):
                wire = (b"HTTP/1.1 200 OK\r\n" + fields + b"Transfer-Encoding: chunked\r\n\r\n"
                        + b"".join(f"{len(part):x}\r\n".encode("ascii") + part + b"\r\n" for part in parts) + end)
                with (self.response(wire) as request, self.assertRaises(StreamFailure) as failure,
                      OpenAITransport().responses(
                          BODY, "synthetic-access", Cancellation(time.monotonic() + 2), lambda write: write(),
                          inspect_media=True,
                      ) as events):
                    self.assertEqual(list(events), [])
                self.assertEqual(failure.exception.code, "provider_stream_content_type")
                facts = failure.exception.evidence
                self.assertEqual(
                    (facts.media_fields, facts.media, facts.prefix_shape, facts.raw_bytes, facts.prefix_bytes),
                    (count, media, shape, size, size),
                )
                self.assertNotIn(canary.decode(), failure.exception.describe())
                self.assertEqual(request[1][b"accept"], b"text/event-stream")
                self.assertIs(json.loads(request[2])["stream"], True)

        wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\ndata")
        with self.response(wire), patch.object(_StrictResponse, "read1") as read:
            with self.assertRaises(StreamFailure):
                self._all_events()
            read.assert_not_called()

    def test_stalled_media_probe_keeps_header_evidence_at_expiry(self):
        from oc_openai.connection import Connection
        from oc_openai.responses import StreamFailure

        wire = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\n"
        hold = threading.Event()
        home = pwd.getpwuid(os.getuid()).pw_dir
        with tempfile.TemporaryDirectory(dir=home) as scratch, self.response(wire, hold=hold):
            connection = Connection(Path(scratch))
            started = time.monotonic()
            with (connection._operation("fixture", lambda record: None, timeout=0.6) as cancellation,
                  self.assertRaises(StreamFailure) as failure,
                  OpenAITransport().responses(
                      BODY, "synthetic-access", cancellation, lambda write: write(), inspect_media=True,
                  ) as events):
                self.assertEqual(list(events), [])
            self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(
            failure.exception.describe(),
            "Stream structure (provider_stream_content_type) media=plain raw_bytes=0 lines=0 events=0 "
            "last_line=none sse=none json_type=none completed_seen=0 done_seen=0 "
            "media_fields=one prefix=inconclusive prefix_bytes=0",
        )

    def test_media_probe_propagates_cancel_and_retirement(self):
        wire = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\ndata"
        read1 = _StrictResponse.read1
        for code in ("openai_operation_cancelled", "connection_retired"):
            stopped = threading.Event()
            cancellation = Cancellation(time.monotonic() + 2, stopped)
            interrupt = stopped.set if code == "openai_operation_cancelled" else cancellation.cancel

            def read_then_interrupt(response, count):
                block = read1(response, count)
                interrupt()
                return block

            with (self.subTest(code=code), self.response(wire),
                  patch.object(_StrictResponse, "read1", read_then_interrupt),
                  self.assertRaisesRegex(ConnectionError, code),
                  OpenAITransport().responses(
                      BODY, "synthetic-access", cancellation, lambda write: write(), inspect_media=True,
                  ) as events):
                self.assertEqual(list(events), [])

    def test_recovery_media_replays_only_eligible_strict_sse(self):
        from oc_openai.responses import StreamFailure

        prefix = b": progress\n\n"
        created = b'data: {"type":"response.created"}\n\n'
        completed = b'data: {"type":"response.completed"}\n\n'
        standard = b"Content-Type: text/event-stream\r\n"
        plain = b"Content-Type: text/plain\r\n"
        for headers, media in (
            (standard, None), (plain, "plain"), (b"", "missing"),
            (b'Content-Type: text/plain; charset="utf-8"\r\n', "plain"),
            (b"Content-Type: application/octet-stream\r\n", "octet-stream"),
        ):
            parts = [prefix[:1], prefix[1:], created[:3], created[3:], completed]
            wire = _sse_chunks(parts).replace(standard, headers, 1)
            categories = []
            with (self.subTest(media=media), self.response(wire),
                  OpenAITransport().responses(
                      BODY, "synthetic-access", Cancellation(time.monotonic() + 2), lambda write: write(),
                      inspect_media=True, observe_media=categories.append,
                  ) as events):
                self.assertEqual([event["type"] for event in events], ["response.created", "response.completed"])
            self.assertEqual(categories, [] if media is None else [media])
        for headers, parts, suffix, failure_code in (
            (standard + plain, [created, completed], b"0\r\n\r\n", "provider_stream_content_type"),
            (b"Content-Type: text/plain; charset=(comment)utf-8\r\n", [created, completed], b"0\r\n\r\n",
             "provider_stream_content_type"),
            (b"Content-Type: application/json\r\n", [created, completed], b"0\r\n\r\n",
             "provider_stream_content_type"),
            (plain, [b'{"type":"response.created"}\n'], b"0\r\n\r\n", "provider_stream_content_type"),
            (plain, [b"<html>\n"], b"0\r\n\r\n", "provider_stream_content_type"),
            (plain, [prefix, b"<sensitive canary>\n", created, completed], b"0\r\n\r\n",
             "provider_stream_event_type"),
            (plain, [created, completed], b"0\r\n", "provider_network_error"),
        ):
            wire = _sse_chunks(parts, suffix).replace(standard, headers, 1)
            with (self.subTest(headers=headers, failure=failure_code), self.response(wire),
                  self.assertRaises(StreamFailure) as failure, OpenAITransport().responses(
                      BODY, "synthetic-access", Cancellation(time.monotonic() + 2), lambda write: write(),
                      inspect_media=True, observe_media=lambda category: None,
                  ) as events):
                for event in events:
                    self.assertNotEqual(event["type"], "response.completed")
            self.assertEqual(failure.exception.code, failure_code)
            self.assertNotIn("sensitive canary", failure.exception.describe())
            if failure_code == "provider_network_error":
                self.assertEqual(failure.exception.evidence.raw_bytes, len(created) + len(completed))

    def test_worker_response_keeps_media_probe_disabled(self):
        from oc_openai.cli import Approval, Reason, RouteUnavailable, Stage
        from oc_openai.exposure import ExposureLedger, Phase
        from oc_openai.live import WorkstationBackend, _slot
        from test_openai_live import FakeConnection, SELECTION_EPOCH, fake_worker

        wire = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\ndata"
        with tempfile.TemporaryDirectory() as scratch:
            state = Path(scratch)
            connection = FakeConnection(state)
            ledger = ExposureLedger(state)
            backend = WorkstationBackend(connection, ledger, label="fixture", selection_epoch=SELECTION_EPOCH,
                                         worker=fake_worker, placement_qualified=True)
            approval = Approval("1" * 32, backend.connection(), Stage.WORKER)
            proposal = _slot(approval, Phase.ORCHESTRATOR)
            ledger.reserve(proposal)
            ledger.settle(proposal, 3, 7)

            def route(binding, request_body, before_send, **options):
                self.assertNotIn("inspect_media", options)

                def dispatch(write):
                    before_send()
                    return write()
                return OpenAITransport().responses(
                    request_body, "synthetic-access", Cancellation(time.monotonic() + 2), dispatch,
                )

            with (self.response(wire), patch.object(connection, "responses", route),
                  patch.object(_StrictResponse, "read1") as read, self.assertRaises(RouteUnavailable) as failure):
                backend.prove(approval)
            self.assertIs(failure.exception.reason, Reason.PROVIDER_STREAM_CONTENT_TYPE)
            read.assert_not_called()

    def test_stream_diagnostics_are_specific_and_never_release_failed_completion(self):
        from oc_openai.acceptance import run_attended
        from oc_openai.exposure import ExposureLedger
        from oc_openai.live import WorkstationBackend
        from test_openai_live import FakeConnection, Terminal, SELECTION_EPOCH, proposal_events

        canary = b"must-not-appear-in-terminal"
        created, completed = [b"data: " + json.dumps(event).encode("ascii") + b"\n\n"
                              for event in proposal_events()]
        done = b"data: [DONE]\n\n"
        stream = created + completed
        cases = [
            ("control", stream + done, "", {}, 0),
            ("content type", stream, "unexpected event-stream content type.", {}, 0),
            ("short line", stream + b"data: " + canary, "ended before a line, event, or HTTP body was complete.", {}, 0),
            ("open event", stream + b"data: " + canary + b"\n",
             "ended before a line, event, or HTTP body was complete.", {}, 0),
            ("short body", stream, "ended before a line, event, or HTTP body was complete.", {}, 1),
            ("bytes", stream, "exceeded its byte, line, or event limit.", {"MAX_STREAM": len(stream) - 1}, 0),
            ("line", stream, "exceeded its byte, line, or event limit.", {"MAX_LINE": len(completed) - 3}, 0),
            ("events", stream, "exceeded its byte, line, or event limit.", {"MAX_EVENTS": 1}, 0),
            ("invalid JSON", created + b"data: " + canary + b"\n\n", "contained invalid JSON.", {}, 0),
            ("missing type", created + b"data: {}\n\n", "had a missing, repeated, or conflicting event type.", {}, 0),
            ("conflicting type", created + b"event: " + canary + b"\n" + completed,
             "had a missing, repeated, or conflicting event type.", {}, 0),
            ("named terminator", stream + b"event: " + canary + b"\n" + done, "sent a named [DONE] terminator.", {}, 0),
            ("extra event", stream + created, "sent additional data after a terminal event.", {}, 0),
            ("open named event", stream + b"event: response.failed\n",
             "sent additional data after a terminal event.", {}, 0),
            ("named event without data", stream + b"event: response.failed\n\n",
             "sent additional data after a terminal event.", {}, 0),
            ("suffix", stream + done + b"retry: " + canary + b"\n", "sent additional data after a terminal event.", {}, 0),
        ]
        for name, body, message, limits, extra in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as scratch:
                state = Path(scratch)
                connection = FakeConnection(state)
                backend = WorkstationBackend(connection, ExposureLedger(state), label="fixture",
                                             selection_epoch=SELECTION_EPOCH, worker=object(),
                                             placement_qualified=True)
                terminal = Terminal(True, False)
                delivered = []

                @contextlib.contextmanager
                def route(binding, request_body, before_send, **options):
                    def dispatch(write):
                        before_send()
                        return write()

                    def observe(events):
                        for event in events:
                            delivered.append(event["type"])
                            yield event

                    with OpenAITransport().responses(
                        request_body, "synthetic-workstation-access", Cancellation(time.monotonic() + 2), dispatch,
                    ) as events:
                        yield observe(events)

                media_type = canary if name == "content type" else b"text/event-stream"
                wire = (b"HTTP/1.1 200 OK\r\nContent-Type: " + media_type
                        + f"\r\nContent-Length: {len(body) + extra}\r\n\r\n".encode("ascii") + body)
                with (self.response(wire), patch.object(connection, "responses", route),
                      patch.multiple("oc_openai.responses", **limits) if limits else contextlib.nullcontext()):
                    self.assertEqual(run_attended(terminal, backend_factory=lambda: backend), 1)
                self.assertNotIn(canary.decode(), "\n".join(terminal.output))
                rows = json.loads((state / "exposure.json").read_text())
                self.assertEqual(len(rows), 1)
                if message:
                    self.assertNotIn("response.completed", delivered)
                    self.assertTrue(terminal.output[-1].startswith("Workstation proposal: "))
                    self.assertTrue(terminal.output[-1].endswith(message), terminal.output)
                    self.assertIsNone(rows[0]["actual"])
                else:
                    self.assertEqual(delivered, ["response.created", "response.completed"])
                    self.assertEqual(rows[0]["actual"], [3, 7])
                    self.assertIn("Start one local worker and authorize up to two requests?", terminal.output)

    def test_empty_revoke_requires_complete_headers_and_body_framing(self):
        def revoke():
            return OpenAITransport().json(
                AUTH_HOST, "/api/accounts/oauth/revoke", body=b"token=inert", revocation=True,
                cancellation=Cancellation(time.monotonic() + 2), dispatch=lambda write: write())

        header = b"HTTP/1.1 200 OK\r\n"
        for body in (b"Content-Length: 1\r\n\r\n",
                     b"Content-Length: 0\r\n",
                     b"Transfer-Encoding: chunked\r\n\r\n0\r\n"):
            with self.subTest(body=body), self.response(header + body, AUTH_HOST):
                with self.assertRaises(ConnectionError):
                    revoke()
        for body in (b"Content-Length: 0\r\n\r\n",
                     b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"):
            with self.subTest(body=body), self.response(header + body, AUTH_HOST):
                self.assertEqual(revoke(), (200, {}))

    def test_redirect_never_followed_and_opaque_error_is_redacted(self):
        values = (
            (b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://other.invalid/\r\n\r\n",
             "invalid_provider_http"),
            (b'HTTP/1.1 403 Forbidden\r\n\r\n{"detail":"private-account-marker"}',
             "chatgpt_access_refused"),
        )
        for wire, expected in values:
            with self.subTest(expected=expected), self.response(wire):
                with self.assertRaises(ConnectionError) as error, self.streams():
                    self.fail("unauthorized response opened")
                self.assertEqual(error.exception.code, expected)

    def test_no_generic_destination_or_bearer_on_auth_origin(self):
        transport = OpenAITransport()
        with patch("oc_openai.responses._connect") as connect:
            for host, path in (("fixture.invalid", TOKEN), (AUTH_HOST, TOKEN)):
                cancel = Cancellation(time.monotonic() + 2)
                with self.subTest(host=host), self.assertRaises(ConnectionError):
                    transport.json(host, path, bearer="secret", body=b"grant_type=refresh_token",
                                   cancellation=cancel,
                                   dispatch=lambda write: write())
            connect.assert_not_called()


class IdentityTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("jwt"), "reviewed PyJWT prerequisite unavailable")
    def test_verify_canonical_signature_and_reject_wrong_claims_and_algorithm(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from jwt.algorithms import RSAAlgorithm

        import json
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
        key.update(kid="test-key", alg="RS256", use="sig")
        keys = {"keys": [key]}
        now = int(time.time())
        claims = {"iss": ISSUER, "sub": "fixture-only-subject", "aud": ["oaiapp_test"],
                  "exp": now + 120, "iat": now, "nonce": "test-nonce"}
        verifier = IDTokenVerifier()

        def token(value, signing=private, algorithm="RS256"):
            return jwt.encode(value, signing, algorithm=algorithm, headers={"kid": "test-key"})

        self.assertEqual(verifier.verify(token(claims), keys, "oaiapp_test", "test-nonce"),
                         "fixture-only-subject")
        invalid = [
            token({**claims, "aud": ["oaiapp_other"]}),
            token({**claims, "iss": "https://fixture.invalid"}),
            token({**claims, "nonce": "wrong"}),
            token({**claims, "exp": now - 60}),
            token(claims, signing=b"x" * 32, algorithm="HS256"),
            token(claims, signing=rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ]
        for index, encoded in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(ConnectionError):
                verifier.verify(encoded, keys, "oaiapp_test", "test-nonce")

    def test_missing_verifier_dependency_fails_closed(self):
        with patch.dict("sys.modules", {"jwt": None}), self.assertRaises(ConnectionError) as caught:
            IDTokenVerifier().preflight()
        self.assertEqual(caught.exception.code, "openai_jose_prerequisite_missing")


if __name__ == "__main__":
    unittest.main()
