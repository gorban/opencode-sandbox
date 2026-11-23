"""Test production HTTP framing on an in-process socket pair."""

import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
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


BODY = {"model": "gpt-6.2-sol", "store": False, "stream": True, "input": []}


class WireTests(unittest.TestCase):
    @contextlib.contextmanager
    def response(self, wire, expected_host=API_HOST):
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
            local.close()
            thread.join(3)
            self.assertFalse(thread.is_alive())

    def streams(self):
        return OpenAITransport().responses(
            BODY, "synthetic-workstation-access", Cancellation(time.monotonic() + 2),
            lambda write: write(),
        )

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
                            with self.assertRaises(ConnectionError) as error, self.streams() as events:
                                next(events)
                                self.fail("completion escaped without a TLS close_notify")
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
                with self.streams() as events:
                    next(events)
                    self.fail("completion escaped before valid framing")
        with self.response(chunk_header + size + completed + b"\r\n0\r\n\r\n"), self.streams() as events:
            self.assertEqual(list(events), [{"type": "response.completed"}])

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
                with self.subTest(host=host), self.assertRaises(ConnectionError):
                    transport.json(host, path, bearer="secret", body=b"grant_type=refresh_token",
                                   cancellation=Cancellation(time.monotonic() + 2),
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
