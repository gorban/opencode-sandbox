"""Exercise ordered native enrollment and its journal with two fake TLS peers."""

from pathlib import Path
import json
import runpy
import socket
import ssl
from threading import Thread


HERE = Path(__file__).parent
FIXTURE = runpy.run_path(str(HERE / "tls-fixture.py"))
STATE = runpy.run_path(str(HERE / "enrollment-journal.py"))
ACCESS = "synthetic-enrollment-fixture-access"
USERINFO = FIXTURE["POLICY"]["USERINFO_HOST"]


def json_reply(peer, value):
    body = json.dumps(value).encode("ascii")
    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                 + str(len(body)).encode("ascii") + b"\r\nConnection: close\r\n\r\n" + body)


def tokenize(peer):
    if not FIXTURE["received_token_post"](peer):
        return "invalid_token_request"
    json_reply(peer, {"access_token": ACCESS, "refresh_token": "synthetic-enrollment-fixture-refresh",
                      "expires_in": 3600, "token_type": "Bearer"})
    return "synthetic_token_issued"


def userinfo(peer):
    with peer.makefile("rb") as request:
        if request.readline(512) != b"GET /oauth2/v2/userinfo HTTP/1.1\r\n":
            return "invalid_userinfo_request"
        authorization = []
        for _ in range(20):
            header = request.readline(1024)
            if header == b"\r\n":
                break
            if not header.endswith(b"\r\n"):
                return "invalid_userinfo_request"
            name, _, value = header.partition(b":")
            if name.lower() == b"authorization":
                authorization.append(value.strip())
        else:
            return "invalid_userinfo_request"
    if authorization != [f"Bearer {ACCESS}".encode("ascii")]:
        return "invalid_userinfo_authorization"
    json_reply(peer, {"id": "42", "name": "Synthetic User", "email": "synthetic@example.invalid",
                      "verified_email": True})
    return "synthetic_userinfo_completed"


def serve(listener, certs, evidence, journal, generation, marker):
    if journal.current() != {"generation": generation, "state": "pending"}:
        return
    token = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    token.load_cert_chain(certs / "match.pem", certs / "match.key")
    FIXTURE["serve_once"](listener, token, evidence, respond=tokenize)
    if evidence != ["synthetic_token_issued"]:
        return
    if marker is not None:
        marker.touch(exist_ok=False)
        return
    profile = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    profile.load_cert_chain(certs / "userinfo.pem", certs / "userinfo.key")
    FIXTURE["serve_once"](listener, profile, evidence, hostname=USERINFO, respond=userinfo)


def qualification_case(root, certificates, *, launch, cancel):
    root.mkdir(mode=0o700)
    profile, state, broker = (root / name for name in ("profile", "state", "broker"))
    for directory in (profile, state, broker):
        directory.mkdir(mode=0o700)
    journal = STATE["Journal"](state)
    generation = journal.begin()
    marker = profile / "cancel-ready" if cancel else None
    evidence = []
    with socket.socket(socket.AF_UNIX) as listener:
        address = broker / "observe.sock"
        listener.bind(str(address))
        address.chmod(0o600)
        listener.listen(1)
        listener.settimeout(8)
        forwarder = Thread(target=serve, args=(listener, certificates, evidence, journal, generation, marker),
                           daemon=True)
        forwarder.start()
        result = launch(profile, broker, cancel=cancel)
        forwarder.join(2)
        if forwarder.is_alive():
            return "fake enrollment peer did not retire"
    if cancel:
        if evidence != ["synthetic_token_issued"] or journal.current() != {"generation": generation, "state": "pending"}:
            return "interrupted enrollment did not preserve pending"
        journal.transition(generation, "abandoned")
        try:
            journal.transition(generation, "ready")
        except STATE["EnrollmentError"]:
            return "interrupted"
        return "late enrollment completion bypassed abandonment"
    if result.returncode or result.stdout.strip() != b"NATIVE_SYNTHETIC_ENROLLMENT":
        return "native synthetic enrollment did not complete both peer exchanges"
    if evidence != ["synthetic_token_issued", "synthetic_userinfo_completed"]:
        return "native enrollment sequence or authorization did not match"
    fresh = launch(profile, None, cancel=False)
    if fresh.returncode:
        return "could not reopen the synthetic private profile"
    if fresh.stdout.strip() == b"NATIVE_RESTART_ACP_READY":
        journal.transition(generation, "ready")
        return "ready"
    if fresh.stdout.strip() != b"NATIVE_ENROLLMENT_STILL_PENDING":
        return "fresh native ACP proof did not give a verified result"
    if journal.current() != {"generation": generation, "state": "pending"}:
        return "fresh native ACP uncertainty did not preserve pending"
    return "pending"


def qualify(directory, programs, *, launch, run_host):
    certificates = directory / "enroll-certs"
    certificates.mkdir(mode=0o700)
    FIXTURE["create_certificates"](certificates, run_host, userinfo=True)
    (programs / "synthetic-ca.pem").write_bytes((certificates / "ca.pem").read_bytes())
    cancelled = qualification_case(directory / "interrupted", certificates, launch=launch, cancel=True)
    if cancelled != "interrupted":
        return cancelled
    return qualification_case(directory / "enrolled", certificates, launch=launch, cancel=False)
