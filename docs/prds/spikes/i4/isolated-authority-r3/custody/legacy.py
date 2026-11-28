"""Adapters that exercise the unchanged archived legacy paths without upstream I/O."""

from array import array
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import time

from bootstrap import CustodyRefused


def require(condition, error):
    if not condition:
        raise CustodyRefused(error)


def unavailable(*_args, **_kwargs):
    raise CustodyRefused("unexpected legacy external operation")


class LegacyVerifier:
    def preflight(self):
        """The seeded fixture does not perform identity-token verification."""
        return None

    verify = staticmethod(unavailable)


class LegacyTransport:
    def __init__(self, mode, access):
        self.mode = mode
        self.access = access
        self.sends = 0

    def json(self, host, endpoint, *, bearer, cancellation, dispatch):
        from oc_openai.canary import MODEL
        from oc_openai.responses import API_HOST, MODELS

        require((host, endpoint, bearer) == (API_HOST, MODELS, self.access),
                "unexpected legacy catalog request")
        cancellation.check()
        return dispatch(lambda: (200, {"models": [{"slug": MODEL, "visibility": "list"}]}))

    def _events(self, body, cancellation):
        if self.mode == "proof":
            from test_openai_live import fixture_events, proposal_events

            if "instructions" not in body:
                return proposal_events()
            return fixture_events(body, deadline=time.monotonic() + 3, cancelled=cancellation.event)
        if self.mode == "canary":
            from test_openai_canary import _ok_events

            return _ok_events(body["model"])
        response = {"id": "resp_custody_fixture", "model": body["model"]}
        return iter((
            {"type": "response.created", "response": {**response, "status": "in_progress"}},
            {"type": "response.output_text.delta", "delta": "synthetic"},
            {"type": "response.completed", "response": {
                **response, "status": "completed", "output": [],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            }},
        ))

    @contextmanager
    def responses(self, body, access, cancellation, dispatch, **_options):
        require(access == self.access, "wrong legacy registration reached the fixture transport")
        cancellation.check()
        dispatch(self._count_send)
        yield self._events(body, cancellation)

    def _count_send(self):
        self.sends += 1


def _connection_factory(transport):
    from oc_openai.connection import Connection

    def connection(path):
        return Connection(path, transport=transport, verifier=LegacyVerifier(),
                          browser=unavailable, host_probe=unavailable)
    return connection


def _legacy_backend(state, mode, *, worker=None):
    from oc_openai.profile_backend import ProfileBackend

    access = "inert-" + secrets.token_urlsafe(24)
    transport = LegacyTransport(mode, access)
    factory = _connection_factory(transport)
    backend = ProfileBackend(state, connection=factory, worker=worker)
    candidate = backend.profiles.begin("legacy")
    client = "oaiapp_fixture_" + secrets.token_hex(16)
    connection = factory(candidate.profile.directory)
    with connection._store.locked(create=True) as directory:
        connection._store.write(directory, {
            "version": 1, "profile": secrets.token_urlsafe(32), "generation": secrets.token_urlsafe(32),
            "client": client, "subject": "synthetic-legacy",
            "tokens": {"access": access, "refresh": "inert-" + secrets.token_urlsafe(24),
                       "expiry": int(time.time()) + 3600},
        })
    with backend.profiles.publish(candidate, client) as published:
        require(published == candidate.profile, "legacy profile publication differs")
    return backend, transport


class LegacyOwner:
    def __init__(self, root, model, token):
        self.root = root
        self.model = model
        self.token = token

    def prepare(self):
        from oc_openai.canary_protocol import PROOF_SIZE

        (self.root / "relay").mkdir(mode=0o700, parents=True)
        self.proof = secrets.token_bytes(PROOF_SIZE)
        return self.root, self.proof

    def check_alive(self):
        """No detached workstation owner is started by this fixture."""
        return None

    def start_containers(self):
        """The measured scratch Unix relay is driven directly."""
        return None

    def wait_opencode(self):
        from oc_openai import canary
        from oc_openai.canary_relay import handoff
        from test_openai_canary import _http_post, _valid_inbound_payload

        request = _http_post("/v1/responses", self.token, _valid_inbound_payload(self.model))
        client, broker = socket.socketpair()
        with client, broker:
            client.settimeout(3)
            handoff(broker, self.root / "relay" / canary._RELAY_SOCK, self.proof)
            broker.close()
            client.sendall(request)
            with client.makefile("rb") as stream:
                response = stream.read(256 * 1024 + 1)
            require(len(response) <= 256 * 1024, "legacy canary fixture output exceeds limit")
        if b"200 OK" not in response:
            return 1, b"", b"", True, None
        records = (
            ["step_start", {"type": "step-start", "sessionID": "ses_f", "messageID": "msg_f"}],
            ["text", {"type": "text", "sessionID": "ses_f", "messageID": "msg_f", "text": "ok"}],
            ["step_finish", {"type": "step-finish", "sessionID": "ses_f", "messageID": "msg_f", "reason": "stop"}],
        )
        stdout = b"".join((json.dumps({"type": kind, "sessionID": "ses_f", "part": part}) + "\n").encode("ascii")
                          for kind, part in records)
        return 0, stdout, b"", True, None

    def close(self):
        shutil.rmtree(self.root)
        return 0


def _receive_unix_client(control, port):
    """The offline placement seam accepts one connected Unix stream instead of TCP."""
    from oc_openai.canary_protocol import Refused

    received = array("i")
    marker, ancillary, flags, _ = control.recvmsg(
        1, socket.CMSG_SPACE(received.itemsize * 2), socket.MSG_CMSG_CLOEXEC,
    )
    try:
        for level, kind, payload in ancillary:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                received.frombytes(payload[:len(payload) - len(payload) % received.itemsize])
        if (marker != b"F" or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or len(ancillary) != 1 or len(received) != 1):
            raise Refused("invalid_fixture_handoff")
        client = socket.socket(fileno=received[0])
        received.pop()
    finally:
        for fd in received:
            os.close(fd)
    try:
        if client.family != socket.AF_UNIX or client.type != socket.SOCK_STREAM:
            raise Refused("invalid_fixture_socket")
        client.getpeername()
        return client
    except BaseException:
        client.close()
        raise


def _run_e2e_canary(case, mode, protected, backend, owner_factory):
    from oc_openai import canary
    from oc_openai.canary_ledger import CanaryLedgerError
    from oc_openai.connection import ConnectionError

    path = protected if mode == "protected" else None
    if mode == "alternate":
        path = case / "alt"
        path.mkdir(mode=0o700)
    try:
        result = canary.run_live_canary_e2e(backend_factory=lambda: backend,
                                           owner_factory=owner_factory, ledger_dir=path)
    except (PermissionError, CanaryLedgerError, ConnectionError):
        if mode != "protected":
            raise
        return
    require(mode != "protected" and result.ok and result.upstream_calls == 1,
            "legacy e2e accounting did not match placement")
    ledger = path or case / "state"
    require((ledger / "canary-e2e.json").exists(), "legacy e2e ledger absent")


def _require_protected_registration(transport, protected):
    from oc_openai.connection import ConnectionError

    connection = _connection_factory(transport)(protected)
    try:
        connection.binding()
    except (PermissionError, ConnectionError):
        return
    raise CustodyRefused("legacy registration crossed the holder boundary")


def _canary(case, mode, legacy_archive, protected):
    from unittest.mock import patch
    from oc_openai import canary, canary_protocol
    from oc_openai.canary_ledger import CANARY_FILE
    from test_openai_canary import _MEASURED_INSTRUCTIONS_HEADER
    from test_openai_live import Terminal

    backend, transport = _legacy_backend(case / "state", "canary")
    owner_factory = lambda model, token: LegacyOwner(case / "owner", model, token)
    normalized = canary_protocol.SYSTEM_DATE.sub("Today's date: [date]", _MEASURED_INSTRUCTIONS_HEADER)
    with (patch.object(canary_protocol, "SYSTEM_DIGEST", sha256(normalized.encode()).hexdigest()),
          patch.object(canary, "receive_client", _receive_unix_client)):
        if mode == "canary":
            result = canary.run_canary(Terminal(True), backend_factory=lambda: backend,
                                       owner_factory=owner_factory, source_root=legacy_archive)
            require(result == 0 and (case / "state" / CANARY_FILE).exists(), "legacy canary did not settle")
        else:
            _run_e2e_canary(case, mode, protected, backend, owner_factory)
    require(transport.sends == int(mode != "protected"), "unexpected legacy canary send count")
    if mode == "protected":
        _require_protected_registration(transport, protected)
    return transport.sends


def _proof(case):
    from oc_openai.acceptance import run_attended
    from test_openai_live import Terminal, fake_worker

    backend, transport = _legacy_backend(case / "state", "proof", worker=fake_worker)
    status = run_attended(Terminal(True, True), backend_factory=lambda: backend)
    require(status == 0 and transport.sends == 3, "legacy proof did not dispatch exactly three fixture requests")
    history = json.loads((case / "state" / "exposure.json").read_bytes())
    require([row["phase"] for row in history] == ["orchestrator", "initial", "continuation"]
            and all(row["actual"] is not None for row in history), "legacy proof did not settle")
    return transport.sends


def _ordinary(case):
    from oc_openai.session_broker import SessionBroker, SessionPolicy, USAGE_LOG_NAME
    from oc_openai.managed import relay
    from test_openai_session_broker import _make_lease, _send_via_relay

    backend, transport = _legacy_backend(case / "state", "ordinary")
    label, epoch, connection, binding = backend.active_connection()
    token = secrets.token_urlsafe(24)
    proof = secrets.token_bytes(relay.PROOF_SIZE)
    lease, life_fd = _make_lease(case)
    broker = SessionBroker(socket_path=case / "relay", relay_proof=proof, worker_token=token, lease=lease,
                           connection=connection, binding=binding, models=connection.models(binding),
                           profile_label=label, usage_dir=case / "state",
                           policy=SessionPolicy(exposure_dir=case / "state",
                                                authorization=lambda: backend.selected_fence(label, epoch)))
    try:
        broker.start()
        body = b'{"model":"gpt-6.2-sol","stream":true,"store":false,"input":[{"role":"user","content":"fixture"}]}'
        head = (f"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:8401\r\nAuthorization: Bearer {token}\r\n"
                f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode("ascii")
        response = _send_via_relay(case / "relay", lease, proof, head + body)
        require(b"response.completed" in response and transport.sends == 1, "legacy ordinary send missing")
        usage_file = case / "state" / USAGE_LOG_NAME
        require(json.loads(usage_file.read_bytes())["outcome"] == "completed", "legacy ordinary usage missing")
    finally:
        broker.close()
        os.close(life_fd)
    return transport.sends


def run_legacy(scratch, legacy_archive, protected=None):
    scratch = Path(scratch)
    cases = ("canonical", "alternate", "canary", "proof", "ordinary")
    sends = {}
    for mode in cases:
        case = scratch / mode
        case.mkdir(mode=0o700)
        if mode == "proof":
            sends[mode] = _proof(case)
        elif mode == "ordinary":
            sends[mode] = _ordinary(case)
        else:
            sends[mode] = _canary(case, mode, legacy_archive, None)
    if protected is not None:
        case = scratch / "protected"
        case.mkdir(mode=0o700)
        sends["protected"] = _canary(case, "protected", legacy_archive, protected)
    return sends
