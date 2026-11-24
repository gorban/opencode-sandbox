"""Qualify pinned agy certificate behavior using only a fake Unix TLS peer."""

from contextlib import suppress
import os
from pathlib import Path
import runpy
import secrets
import socket
import ssl
from threading import Thread
import time


HERE = Path(__file__).parent
POLICY = runpy.run_path(str(HERE / "egress-policy.py"))
TLS = runpy.run_path(str(HERE / "tls-admission.py"))
HOST = "oauth2.googleapis.com"
REPLY = b'{"error":"invalid_grant"}'


def create_certificates(directory, run_host):
    def openssl(*args):
        command = ["/usr/bin/env", "--chdir", os.fspath(directory), "/usr/bin/openssl", *args]
        if run_host(command, timeout=5).returncode:
            raise OSError("could not generate synthetic certificates")

    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-noenc", "-days", "1", "-subj", "/CN=Synthetic Antigravity Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign",
            "-keyout", "ca.key", "-out", "ca.pem")
    for label, host in (("match", HOST), ("wrong-name", "other.fixture.invalid")):
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-noenc",
                "-subj", f"/CN={host}", "-addext", f"subjectAltName=DNS:{host}",
                "-keyout", f"{label}.key", "-out", f"{label}.csr")
        openssl("x509", "-req", "-in", f"{label}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-set_serial", str(secrets.randbits(80)), "-days", "1", "-copy_extensions", "copy",
                "-out", f"{label}.pem")
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-noenc", "-days", "1", "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}",
            "-keyout", "untrusted.key", "-out", "untrusted.pem")


def received_token_post(peer):
    with peer.makefile("rb") as stream:
        request = stream.readline(1024)
        size = None
        for _ in range(20):
            field = stream.readline(1024)
            if field == b"\r\n":
                break
            if not field.endswith(b"\r\n"):
                return False
            name, _, value = field.partition(b":")
            if name.lower() == b"content-length":
                if size is not None or not value.strip().isdigit():
                    return False
                size = int(value.strip())
        else:
            return False
        return (request == b"POST /token HTTP/1.1\r\n" and size is not None and 0 < size <= 8192
                and b"oc-sandbox-synthetic-invalid-code" in stream.read(size))


def fake_oauth(peer, cancel_ready):
    if not received_token_post(peer):
        return "unexpected_request"
    if cancel_ready is not None:
        cancel_ready.touch(exist_ok=False)
        return "cancelled_open_peer" if not peer.recv(1) else "unexpected_request"
    peer.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: "
                 + str(len(REPLY)).encode("ascii") + b"\r\nConnection: close\r\n\r\n" + REPLY)
    return "synthetic_token_post"


def record_outcome(sock, context, evidence, cancel_ready):
    with sock:
        sock.settimeout(5)
        try:
            with context.wrap_socket(sock, server_side=True) as peer:
                evidence.append(fake_oauth(peer, cancel_ready))
        except ssl.SSLError as error:
            if error.reason in {"SSLV3_ALERT_BAD_CERTIFICATE", "TLSV1_ALERT_UNKNOWN_CA",
                                "SSLV3_ALERT_CERTIFICATE_UNKNOWN"}:
                evidence.append("certificate_rejected")
        except OSError:
            return


def serve_once(listener, context, evidence, cancel_ready=None):
    try:
        client, _ = listener.accept()
        with client:
            deadline = time.monotonic() + 7
            POLICY["read_connect"](client)
            client.sendall(TLS["ESTABLISHED"])
            validated_hello = TLS["read_client_hello"](client, deadline=deadline)
            broker, fake = socket.socketpair()
            with broker, fake:
                server = Thread(target=record_outcome, args=(fake, context, evidence, cancel_ready), daemon=True)
                server.start()
                try:
                    broker.sendall(validated_hello)
                    TLS["relay"](client, broker, deadline=deadline, transferred=len(validated_hello))
                finally:
                    with suppress(OSError):
                        broker.shutdown(socket.SHUT_RDWR)
                    server.join(6)
    except (OSError, ValueError):
        return


def qualify(directory, programs, *, launch, run_host):
    certificates = directory / "certificates"
    certificates.mkdir(mode=0o700)
    create_certificates(certificates, run_host)
    (programs / "synthetic-ca.pem").write_bytes((certificates / "ca.pem").read_bytes())
    for label, certificate, expected in (
            ("match", "match", "synthetic_token_post"), ("wrong-name", "wrong-name", "certificate_rejected"),
            ("untrusted", "untrusted", "certificate_rejected"), ("cancel-open", "match", "cancelled_open_peer")):
        profile, socket_directory = directory / label, directory / f"{label}-socket"
        profile.mkdir(mode=0o700)
        socket_directory.mkdir(mode=0o700)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificates / f"{certificate}.pem", certificates / f"{certificate}.key")
        cancel_ready = profile / "cancel-ready" if label == "cancel-open" else None
        evidence = []
        with socket.socket(socket.AF_UNIX) as listener:
            address = socket_directory / "observe.sock"
            listener.bind(os.fspath(address))
            address.chmod(0o600)
            listener.listen(1)
            listener.settimeout(6)
            broker = Thread(target=serve_once, args=(listener, context, evidence, cancel_ready), daemon=True)
            broker.start()
            verify = launch(profile, socket_directory, cancel=cancel_ready is not None)
            broker.join(7)
            if verify is not None and (verify.returncode or verify.stdout.strip() != b"NATIVE_FAKE_TLS_FINISHED"):
                return label
            if broker.is_alive() or evidence != [expected]:
                return label
    return None
