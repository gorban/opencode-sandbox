"""Exercise ordered native enrollment and its journal with two fake TLS peers."""

from pathlib import Path
import json
import runpy
import secrets
import socket
import ssl
from threading import Event, Thread


HERE = Path(__file__).parent
FIXTURE = runpy.run_path(str(HERE / "tls-fixture.py"))
STATE = runpy.run_path(str(HERE / "enrollment-journal.py"))
GUARD = runpy.run_path(str(HERE / "lease-fixture.py"))
ACCESS = "synthetic-enrollment-fixture-access"
USERINFO = FIXTURE["POLICY"]["USERINFO_HOST"]


class Attempt:
    def __init__(self, *, pause, lease=None):
        self.pause = pause
        self.lease = lease
        self.userinfo_arrival = Event()
        self.resume = Event()
        self.revoked = Event()
        self.refused = Event()
        self.retirement_checked = Event()

    def cancel(self):
        self.revoked.set()
        self.resume.set()
        if not self.refused.wait(2):
            raise STATE["EnrollmentError"]("the revoked attempt did not refuse userinfo")
        if self.lease is not None:
            self.lease.revoke()

    def admit_userinfo(self):
        self.userinfo_arrival.set()
        if self.pause and not self.resume.wait(5):
            return False
        if not self.revoked.is_set():
            return True
        self.refused.set()
        self.retirement_checked.wait(4)
        return False


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


def serve(listener, certs, evidence, journal, generation, attempt, fake_dir=None):
    def pending():
        return journal.current() == {"generation": generation, "state": "pending"}

    def forward(hostname, context, respond, authorize):
        if fake_dir is None:
            FIXTURE["serve_once"](listener, context, evidence, hostname=hostname, respond=respond,
                                  authorize=authorize)
            return
        endpoint = "token.sock" if hostname == FIXTURE["HOST"] else "userinfo.sock"
        GUARD["exchange"](listener, fake_dir / endpoint, attempt.lease, hostname=hostname, context=context,
                          evidence=evidence, respond=respond, authorize=authorize)

    if not pending():
        return
    token = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    token.load_cert_chain(certs / "match.pem", certs / "match.key")
    forward(FIXTURE["HOST"], token, tokenize, pending)
    if evidence != ["synthetic_token_issued"]:
        return
    profile = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    profile.load_cert_chain(certs / "userinfo.pem", certs / "userinfo.key")
    forward(USERINFO, profile, userinfo, lambda: attempt.admit_userinfo() and pending())


def qualification_case(root, certificates, *, launch, run_host, cancel=False, expired=False):
    root.mkdir(mode=0o700)
    profile, state, broker, fake = (root / name for name in ("profile", "state", "broker", "fake"))
    for directory in (profile, state, broker, fake):
        directory.mkdir(mode=0o700)
    journal = STATE["Journal"](state)
    generation = journal.begin()
    unit = f"oc-agy-fake-enroll-{secrets.token_hex(8)}.service"
    lease = GUARD["create"](generation, unit, run_host)
    attempt = Attempt(pause=cancel, lease=lease)
    evidence = []
    with socket.socket(socket.AF_UNIX) as listener:
        address = broker / "observe.sock"
        listener.bind(str(address))
        address.chmod(0o600)
        listener.listen(1)
        listener.settimeout(8)
        forwarder = Thread(target=serve, args=(listener, certificates, evidence, journal, generation, attempt, fake),
                           daemon=True)
        forwarder.start()
        try:
            result = launch(profile, broker, attempt=attempt if cancel else None, unit=unit)
        finally:
            lease.revoke()
        forwarder.join(2)
        if forwarder.is_alive():
            return "fake enrollment peer did not retire"
    if cancel:
        if (not attempt.refused.is_set() or evidence != ["synthetic_token_issued"]
                or journal.current() != {"generation": generation, "state": "pending"}):
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
    fresh = launch(profile, None, expired=expired)
    if fresh.returncode:
        return "could not reopen the synthetic private profile"
    if expired:
        if (fresh.stdout.strip() != b"NATIVE_EXPIRED_REFRESH_DENIED"
                or journal.current() != {"generation": generation, "state": "pending"}):
            return "expired token denial did not preserve pending"
        return "expired"
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
    cancelled = qualification_case(directory / "interrupted", certificates, launch=launch, run_host=run_host, cancel=True)
    if cancelled != "interrupted":
        return cancelled
    expired = qualification_case(directory / "expired", certificates, launch=launch, run_host=run_host, expired=True)
    if expired != "expired":
        return expired
    return qualification_case(directory / "enrolled", certificates, launch=launch, run_host=run_host)
