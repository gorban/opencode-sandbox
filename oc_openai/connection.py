"""Workstation-only Sign in with ChatGPT and generation-bound upstream I/O."""

import base64
import contextlib
import hashlib
import hmac
import http.server
import math
import os
import re
import secrets
import stat
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from .connection_job import LeaseHostProof, PhysicalHost, WorkerLease
from .connection_state import ConnectionError, Store
from .profiles import ProfileError
from .responses import AUTH_HOST, API_HOST, DISCOVERY, JWKS, MODELS, TOKEN
from .responses import Cancellation, OpenAITransport, response_error

RESOURCE = "https://api.openai.com/v1"
ISSUER = "https://auth.openai.com"
AUTHORIZE = ISSUER + "/api/accounts/authorize"
INITIAL_CLIENT = "dynamic_agent_client"
CALLBACK = "/auth/callback"
BROWSER_START = "/start/"
DIRECT_SCOPE = "chatgpt.tokens.use.direct"
SCOPES = f"openid profile email offline_access resource.invoke {DIRECT_SCOPE}"
CONNECT_SECONDS = 180
REQUEST_SECONDS = 30
REFRESH_SECONDS = 35
RETIRE_SECONDS = 35
POLL_SECONDS = 0.15
CLIENT = re.compile(r"oaiapp_[A-Za-z0-9_-]{1,140}\Z")
TERMINAL_REFRESH = {
    "invalid_grant", "invalid_refresh_token", "token_expired",
    "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused",
}


@dataclass(frozen=True)
class Binding:
    """Opaque local identifiers for the selected profile and its current generation."""

    generation: str
    profile: str


@dataclass(frozen=True)
class Retirement:
    generation: str
    client: str | None
    refresh: str | None = field(repr=False)
    uncertain: bool


def _random():
    return secrets.token_urlsafe(32)


def _pkce(verifier):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _form(fields):
    return urlencode(fields).encode("ascii")


def _value(value, *, max_length=24 * 1024):
    return (isinstance(value, str) and 0 < len(value) <= max_length
            and all(32 < ord(char) < 127 for char in value))


def _usable_id_token_library():
    try:
        import jwt
        from jwt.algorithms import RSAAlgorithm, has_crypto
        if not has_crypto or not hasattr(RSAAlgorithm, "from_jwk"):
            raise ImportError
        return jwt
    except (ImportError, AttributeError):
        raise ConnectionError("openai_jose_prerequisite_missing") from None


class IDTokenVerifier:
    def preflight(self):
        _usable_id_token_library()

    def verify(self, token, keys, client, nonce):
        jwt = _usable_id_token_library()
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (header.get("alg") != "RS256" or not _value(kid, max_length=160)
                    or set(header) & {"crit", "jwk", "jku", "x5u"}):
                raise ValueError
            jwks = keys.get("keys")
            if not isinstance(jwks, list) or len(jwks) > 64:
                raise ValueError
            matches = [key for key in jwks if isinstance(key, dict) and key.get("kid") == kid]
            if len(matches) != 1:
                raise ValueError
            jwk = matches[0]
            if (jwk.get("kty") != "RSA" or jwk.get("use", "sig") != "sig"
                    or jwk.get("alg", "RS256") != "RS256"):
                raise ValueError
            key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
            if not 2048 <= key.key_size <= 4096:
                raise ValueError
            claims = jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER,
                                audience=client, leeway=5,
                                options={"require": ["sub", "exp", "iat", "nonce"]})
            subject = claims.get("sub")
            audience = claims.get("aud")
            if audience != client and audience != [client]:
                raise ValueError
            if (not _value(subject, max_length=256) or claims["nonce"] != nonce
                    or type(claims["exp"]) is not int or type(claims["iat"]) is not int
                    or claims.get("azp", client) != client):
                raise ValueError
            return subject
        except (jwt.PyJWTError, ValueError, TypeError, AttributeError):
            raise ConnectionError("invalid_openai_identity") from None


class _CallbackServer(http.server.HTTPServer):
    allow_reuse_address = False

    def get_request(self):
        client, address = super().get_request()
        try:
            self.cancellation.attach(client)
            client.settimeout(0.5)
            return client, address
        except BaseException:
            client.close()
            raise

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            self.cancellation.close()

    def handle_error(self, request, client_address):
        # Base server debug output would disclose the authorization request.
        pass


class _Callback(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        # Parser errors can otherwise echo a request target containing a capability.
        super().send_error(code)

    def _start_browser(self, expected_host):
        start = getattr(self.server, "browser_start", None)
        if (start is None or self.path != start.path
                or self.requestline != f"GET {start.path} {self.request_version}"
                or self.headers.get_all("Host") != [expected_host]
                or self.headers.get_all("Origin") not in (None, [f"http://{expected_host}"])
                or self.headers.get_all("Sec-Fetch-Site") not in (None, ["none"], ["same-origin"])
                or self.headers.get_all("Content-Length") not in (None, ["0"])
                or self.headers.get_all("Transfer-Encoding") is not None):
            self.send_error(404)
            return

        self.close_connection = True
        timeout = self.connection.gettimeout()
        self.connection.setblocking(False)
        try:
            with start.authorize():
                self.server.browser_start = None
                # A partial or failed write spends the capability. Never retry.
                with contextlib.suppress(OSError):
                    self.connection.send(start.response)
        except (ConnectionError, ProfileError) as error:
            self.server.browser_start = None
            self.server.failure = error
        finally:
            self.connection.settimeout(timeout)
        if self.server.failure is not None:
            self.send_error(410)

    def do_GET(self):
        server = self.server
        expected_host = f"127.0.0.1:{server.server_port}"
        if self.path.startswith(BROWSER_START):
            self._start_browser(expected_host)
            return
        result = None
        try:
            path = urlsplit(self.path)
            fields = parse_qs(path.query, strict_parsing=True, keep_blank_values=True,
                              errors="strict", max_num_fields=12)
            if (self.headers.get_all("Host") != [expected_host] or path.scheme
                    or path.netloc or path.fragment or path.path != CALLBACK
                    or len(path.query) > 8192 or any(len(values) != 1 for values in fields.values())):
                raise ValueError
            state = fields.get("state", [""])[0]
            if not state.isascii() or not hmac.compare_digest(state, server.state):
                raise ValueError
            if "iss" in fields and fields["iss"][0] != ISSUER:
                raise ValueError
            if ("code" in fields) == ("error" in fields):
                raise ValueError
            if "error" in fields:
                if not _value(fields["error"][0], max_length=128):
                    raise ValueError
                result = ("denied", None, None)
            else:
                code = fields["code"][0]
                client = fields.get("client_id", [None])[0]
                if not _value(code, max_length=4096):
                    raise ValueError
                result = ("ok", code, client)
            if server.result is not None:
                raise ValueError
            if result[0] == "ok" and server.observe_registration is not None:
                if not isinstance(client, str) or CLIENT.fullmatch(client) is None:
                    raise ValueError
                server.observe_registration()
            server.result = result
        except (UnicodeError, ValueError):
            result = None
        except ConnectionError as error:
            server.failure = error
            result = None
        if server.failure is not None:
            status, content = 503, b"Callback unavailable. Return to the oc-sandbox terminal."
        elif result is not None:
            status, content = 200, b"Return to the oc-sandbox terminal."
        else:
            status, content = 400, b"Invalid callback."
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(content)


@dataclass(frozen=True)
class _BrowserStart:
    path: str = field(repr=False)
    response: bytes = field(repr=False)
    authorize: Callable[[], contextlib.AbstractContextManager] = field(repr=False)


def _browser_redirect_response(destination):
    return (
        "HTTP/1.0 303 See Other\r\n"
        f"Location: {destination}\r\n"
        "Cache-Control: no-store\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def _check_browser_placement():
    uid = os.getuid()
    host_runtime = f"/run/user/{uid}"
    guest_runtime = "/run/host" + host_runtime
    guest_bus = guest_runtime + "/bus"
    try:
        directory = os.stat(guest_runtime, follow_symlinks=False)
        bus = os.stat(guest_bus, follow_symlinks=False)
    except OSError:
        raise ConnectionError("host_browser_placement_unavailable") from None
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != uid
            or directory.st_mode & 0o077 or not stat.S_ISSOCK(bus.st_mode)
            or bus.st_uid != uid):
        raise ConnectionError("host_browser_placement_unavailable")
    return host_runtime, guest_runtime, guest_bus


def _open_host_browser(url):
    host_runtime, guest_runtime, guest_bus = _check_browser_placement()
    try:
        subprocess.Popen(
            ["/usr/bin/host-spawn", "-cwd", "/", "-no-pty", "/usr/bin/env",
             f"DBUS_SESSION_BUS_ADDRESS=unix:path={host_runtime}/bus",
             f"XDG_RUNTIME_DIR={host_runtime}", "/usr/bin/xdg-open", url],
            env={"PATH": "/usr/bin:/bin", "XDG_RUNTIME_DIR": guest_runtime,
                 "DBUS_SESSION_BUS_ADDRESS": f"unix:path={guest_bus}"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        raise ConnectionError("host_browser_unavailable") from None


def _active(record, binding):
    return (record.get("generation") == binding.generation
            and record.get("profile") == binding.profile and bool(record.get("tokens"))
            and record.get("worker_retiring") is not True)


def _parse_tokens(value, now):
    access, replacement = value.get("access_token"), value.get("refresh_token")
    scope, expires_in = value.get("scope"), value.get("expires_in")
    kind = value.get("token_type")
    if (not _value(access) or not _value(replacement) or not isinstance(scope, str)
            or len(scope) > 2048 or not isinstance(kind, str) or kind.lower() != "bearer"
            or type(expires_in) is not int or not 1 <= expires_in <= 3600):
        raise ConnectionError("invalid_openai_token_response")
    if DIRECT_SCOPE not in scope.split():
        raise ConnectionError("chatgpt_plan_scope_missing")
    earliest = value.get("earliest_refresh_at")
    if type(earliest) not in (int, float) or not now <= earliest <= now + expires_in:
        earliest = None
    return {"access": access, "refresh": replacement, "expiry": now + expires_in,
            "earliest": earliest}


class Connection:
    def __init__(self, state_dir: Path, *, transport=None, verifier=None, browser=None, clock=None,
                 host_probe=None):
        self._store = Store(Path(state_dir))
        self._transport = transport if transport is not None else OpenAITransport()
        self._verifier = verifier if verifier is not None else IDTokenVerifier()
        self._browser = browser if browser is not None else _open_host_browser
        self._clock = clock if clock is not None else time.time
        self._host_probe = host_probe if host_probe is not None else PhysicalHost.observe
        self._running = {}
        self._running_lock = threading.Lock()

    def require_prerequisites(self):
        self._verifier.preflight()

    def status(self):
        with self._store.locked() as directory:
            record = self._store.read(directory)
        now = self._clock()
        if record.get("retiring", 0) > now or record.get("worker_retiring") is True:
            return "disconnecting"
        if record.get("pending", {}).get("expires", 0) > now:
            return "connecting"
        if record.get("tokens"):
            return "connected"
        if record.get("scope_missing"):
            return "chatgpt_plan_scope_missing"
        return "disconnected"

    @staticmethod
    def _uncertain(record):
        return (record.get("revocation_unconfirmed") is True
                or record.get("pending", {}).get("may_have_sent") is True
                or record.get("refresh_pending", {}).get("may_have_sent") is True)

    def revocation_unconfirmed(self):
        """Report durable possible issuance or rotation independent of selection."""
        with self._store.locked() as directory:
            return self._uncertain(self._store.read(directory))

    def reclaimable_registration(self, *, abandoned_attempt=False):
        """Check label eligibility. Abandonment requires the exclusive Connect lifetime lock."""
        with self._store.locked() as directory:
            record = self._store.read(directory)
            if "pending" in record and abandoned_attempt is not True:
                return False
            return not self._uncertain(record) and not {
                "client", "pending_client", "tokens", "refresh_pending",
                "worker_lease", "worker_retiring", "retiring",
            }.intersection(record) and record.get("registration_observed") is not True

    def binding(self):
        with self._store.locked() as directory:
            record = self._store.read(directory)
            if not record.get("tokens") or record.get("worker_retiring") is True:
                raise ConnectionError("openai_connection_required")
            return Binding(record["generation"], record["profile"])

    def saved_registration(self):
        """Recover a verified registration whose selection publication was interrupted."""
        with self._store.locked() as directory:
            record = self._store.read(directory)
            if not record.get("tokens") or record.get("worker_retiring") is True:
                return None
            return record["client"], Binding(record["generation"], record["profile"])

    def require_active(self, binding):
        with self._store.locked() as directory:
            record = self._store.read(directory)
            if not _active(record, binding):
                raise ConnectionError("connection_retired")

    def _require_dispatchable(self, record, binding, access):
        if not _active(record, binding):
            raise ConnectionError("connection_retired")
        tokens = record["tokens"]
        if tokens["expiry"] <= self._clock() or tokens["access"] != access:
            raise ConnectionError("openai_access_token_changed")

    def require_switchable(self):
        with self._store.locked() as directory:
            record = self._store.read(directory)
            if record.get("worker_lease") is not None or record.get("worker_retiring") is True:
                raise ConnectionError("managed_retirement_incomplete")

    @contextlib.contextmanager
    def worker_lease(self, binding, job):
        lease = WorkerLease.capture(job, self._host_probe())
        with self._store.locked() as directory:
            record = self._store.read(directory)
            if not _active(record, binding) or "worker_lease" in record:
                raise ConnectionError("managed_retirement_incomplete")
            record["worker_lease"] = lease.record()
            self._store.write(directory, record)
        try:
            yield
        finally:
            with self._store.locked() as directory:
                record = self._store.read(directory)
                if record.get("worker_lease") == lease.record():
                    lease.confirm_terminal()
                    record.pop("worker_lease")
                    self._store.write(directory, record)

    @contextlib.contextmanager
    def _operation(self, generation, check, *, timeout=REQUEST_SECONDS,
                   deadline=None, cancelled=None):
        end = time.monotonic() + timeout
        if deadline is not None:
            end = min(end, deadline)
        cancellation = Cancellation(end, cancelled)
        cancellation.check()
        finished = threading.Event()
        with self._running_lock:
            self._running.setdefault(generation, set()).add(cancellation)

        def monitor():
            while not finished.wait(POLL_SECONDS):
                try:
                    cancellation.check()
                    with self._store.locked() as directory:
                        check(self._store.read(directory))
                except ConnectionError as error:
                    cancellation.cancel(expired=error.code == "openai_operation_timed_out")
                    break

        watcher = threading.Thread(target=monitor, daemon=True)
        watcher.start()
        try:
            with self._store.locked() as directory:
                check(self._store.read(directory))
            yield cancellation
        finally:
            finished.set()
            with self._running_lock:
                active = self._running[generation]
                active.remove(cancellation)
                if not active:
                    del self._running[generation]
            cancellation.cancel()
            watcher.join()

    def _cancel(self, generation):
        with self._running_lock:
            for operation in self._running.get(generation, ()):
                operation.cancel()

    def _dispatch(self, check, cancellation, before_send=None, *, journal=None,
                  authorization=contextlib.nullcontext, before_write=None):
        used = False

        def dispatch(write):
            nonlocal used
            cancellation.check()
            if before_send is not None:
                with self._store.locked() as directory:
                    check(self._store.read(directory))
                if used:
                    raise ConnectionError("openai_dispatch_already_attempted")
                used = True
                before_send()
            with authorization(), self._store.locked() as directory:
                record = self._store.read(directory)
                check(record)
                cancellation.check()
                if journal is not None:
                    transaction = record[journal]
                    if transaction.get("may_have_sent"):
                        raise ConnectionError("openai_dispatch_already_attempted")
                    transaction["may_have_sent"] = True
                    self._store.write(directory, record)
                    cancellation.check()
                if before_write is not None:
                    before_write()
                return write()
        return dispatch

    def _try_browser(self, target, cancellation):
        cancellation.check()
        try:
            self._browser(target)
        except ConnectionError as error:
            if error.code != "host_browser_unavailable":
                raise
            return False
        return True

    def connect(self, *, installation_host=None, publication=None, authorization=None, handoff=None):
        """Sign in within a short registry authorization guard at each local effect."""
        self.require_prerequisites()
        if handoff is not None:
            _check_browser_placement()
        authorize = authorization or contextlib.nullcontext
        generation = _random()
        state, nonce, pkce = _random(), _random(), _random()
        expires = self._clock() + CONNECT_SECONDS
        exchange_rejected = False

        def is_pending(record):
            if (record.get("generation") != generation
                    or self._clock() >= record.get("pending", {}).get("expires", 0)):
                raise ConnectionError("connection_retired")

        with authorize(), self._store.locked(create=True) as directory:
            record = self._store.read(directory)
            if record.get("tokens"):
                raise ConnectionError("openai_already_connected")
            if record.get("retiring", 0) > self._clock() or record.get("worker_retiring") is True:
                raise ConnectionError("openai_disconnect_in_progress")
            if record.get("pending", {}).get("expires", 0) > self._clock():
                raise ConnectionError("openai_connect_in_progress")
            if record.get("pending", {}).get("may_have_sent"):
                record["revocation_unconfirmed"] = True
            previous = record.get("generation")
            host_id = record.setdefault("host_id", installation_host or uuid.uuid4().urn)
            if installation_host is not None and host_id != installation_host:
                raise ConnectionError("openai_account_mismatch")
            profile = record.setdefault("profile", _random())
            client = record.get("client") or record.get("pending_client")
            subject = record.get("subject")
            ask_again = record.get("scope_missing") is True
            record.update(generation=generation, pending={"expires": expires})
            self._store.write(directory, record)
        self._cancel(previous)

        def observe_registration():
            with self._store.locked() as directory:
                record = self._store.read(directory)
                if record.get("profile") != profile or record.get("host_id") != host_id:
                    raise ConnectionError("connection_retired")
                # Retain issuance evidence across retirement without granting
                # a stale callback any client, code or token authority.
                if record.get("registration_observed") is not True:
                    record["registration_observed"] = True
                    self._store.write(directory, record)

        try:
            with self._operation(generation, is_pending, timeout=CONNECT_SECONDS) as cancellation:
                dispatch = self._dispatch(is_pending, cancellation)
                with _CallbackServer(("127.0.0.1", 0), _Callback) as server:
                    server.cancellation = cancellation
                    server.timeout = POLL_SECONDS
                    server.state = state
                    server.result = None
                    server.failure = None
                    server.observe_registration = observe_registration if client is None else None
                    redirect = f"http://127.0.0.1:{server.server_port}{CALLBACK}"
                    fields = {"client_id": client or INITIAL_CLIENT, "ext_agent_host_id": host_id,
                              "response_type": "code", "redirect_uri": redirect, "scope": SCOPES,
                              "resource": RESOURCE, "state": state, "nonce": nonce,
                              "code_challenge_method": "S256", "code_challenge": _pkce(pkce)}
                    if client is None:
                        fields["agent_name_hint"] = "oc-sandbox"
                    elif ask_again:
                        fields["prompt"] = "consent"
                    cancellation.check()
                    destination = AUTHORIZE + "?" + urlencode(fields)
                    with contextlib.ExitStack() as resources:
                        if handoff is None:
                            target = resources.enter_context(self._store.browser_redirect(destination))
                            self._browser(target)
                        else:
                            @contextlib.contextmanager
                            def authorize_start():
                                with authorize(), self._store.locked() as directory:
                                    is_pending(self._store.read(directory))
                                    cancellation.check()
                                    yield

                            def launch():
                                cancellation.check()
                                target = resources.enter_context(self._store.browser_redirect(destination))
                                return self._try_browser(target, cancellation)

                            path = BROWSER_START + _random()
                            server.browser_start = _BrowserStart(path, _browser_redirect_response(destination),
                                                                 authorize_start)
                            handoff(f"http://127.0.0.1:{server.server_port}{path}", launch)
                        while server.result is None and server.failure is None:
                            cancellation.check()
                            server.handle_request()
                        if server.failure is not None:
                            raise server.failure
                        kind, code, returned_client = server.result
                with authorize(), self._store.locked() as directory:
                    record = self._store.read(directory)
                    is_pending(record)
                    if record["pending"].get("consumed"):
                        raise ConnectionError("invalid_openai_callback")
                    record["pending"]["consumed"] = True
                    if kind != "ok":
                        raise ConnectionError("openai_consent_declined")
                    if client is None:
                        if not isinstance(returned_client, str) or not CLIENT.fullmatch(returned_client):
                            raise ConnectionError("invalid_openai_callback")
                        client = returned_client
                        record["pending_client"] = client
                    elif returned_client is not None and returned_client != client:
                        raise ConnectionError("invalid_openai_callback")
                    self._store.write(directory, record)
                params = _form({"grant_type": "authorization_code", "client_id": client,
                                "code": code, "code_verifier": pkce, "redirect_uri": redirect,
                                "resource": RESOURCE})
                status, value = self._transport.json(
                    AUTH_HOST, TOKEN, body=params, cancellation=cancellation,
                    dispatch=self._dispatch(is_pending, cancellation, journal="pending",
                                            authorization=authorize))
                if status != 200:
                    exchange_rejected = status == 400 and value.get("error") == "invalid_grant"
                    raise ConnectionError("openai_exchange_failed")
                id_token = value.get("id_token")
                if not _value(id_token):
                    raise ConnectionError("invalid_openai_identity")
                status, keys = self._transport.json(AUTH_HOST, JWKS,
                                                    cancellation=cancellation, dispatch=dispatch)
                if status != 200:
                    raise ConnectionError("openai_keys_unavailable")
                verified = self._verifier.verify(id_token, keys, client, nonce)
                if not _value(verified, max_length=256) or (subject is not None and verified != subject):
                    raise ConnectionError("openai_account_mismatch")
                scope = value.get("scope")
                scope_missing = not isinstance(scope, str) or DIRECT_SCOPE not in scope.split()
                tokens = None if scope_missing else _parse_tokens(value, self._clock())
                publish = publication(client) if publication is not None and not scope_missing else authorize()
                with publish:
                    with self._store.locked() as directory:
                        record = self._store.read(directory)
                        is_pending(record)
                        cancellation.check()
                        record.update(client=client, subject=verified, profile=profile,
                                      scope_missing=scope_missing)
                        record.pop("pending", None)
                        record.pop("pending_client", None)
                        if tokens is not None:
                            record["tokens"] = tokens
                        elif _value(value.get("refresh_token")):
                            record["revocation_unconfirmed"] = True
                        self._store.write(directory, record)
                if scope_missing:
                    raise ConnectionError("chatgpt_plan_scope_missing")
                return Binding(generation, profile)
        finally:
            with self._store.locked() as directory:
                record = self._store.read(directory)
                if record.get("generation") == generation:
                    pending = record.pop("pending", None)
                    if pending:
                        if pending.get("may_have_sent") and not exchange_rejected:
                            record["revocation_unconfirmed"] = True
                        self._store.write(directory, record)

    def _refresh(self, binding, *, deadline=None, cancelled=None):
        wait_until = time.monotonic() + REFRESH_SECONDS + 1
        if deadline is not None:
            wait_until = min(wait_until, deadline)
        waiting = Cancellation(wait_until, cancelled)
        ticket = _random()
        while True:
            waiting.check()
            with self._store.locked() as directory:
                waiting.check()
                record = self._store.read(directory)
                if not _active(record, binding):
                    raise ConnectionError("connection_retired")
                now = self._clock()
                tokens = record["tokens"]
                pending = record.get("refresh_pending", {})
                if pending and pending["until"] <= now:
                    record.pop("refresh_pending")
                    if pending.get("may_have_sent"):
                        record.pop("tokens")
                        record["revocation_unconfirmed"] = True
                    self._store.write(directory, record)
                    if pending.get("may_have_sent"):
                        raise ConnectionError("openai_reconnect_required")
                    pending = {}
                if not pending:
                    expiry = tokens["expiry"]
                    earliest = tokens.get("earliest")
                    if expiry > now + 30 or (earliest is not None and now < earliest < expiry):
                        return tokens["access"]
                    if record.get("refresh_retry_after", 0) > now:
                        if expiry > now:
                            return tokens["access"]
                        raise ConnectionError("openai_refresh_deferred")
                    client = record["client"]
                    record["refresh_pending"] = {"ticket": ticket, "until": now + REFRESH_SECONDS}
                    self._store.write(directory, record)
                    break
            pause = min(POLL_SECONDS, max(0, wait_until - time.monotonic()))
            if cancelled is None:
                time.sleep(pause)
            else:
                cancelled.wait(pause)

        def is_current(record):
            if (not _active(record, binding)
                    or record.get("refresh_pending", {}).get("ticket") != ticket
                    or self._clock() >= record["refresh_pending"]["until"]):
                raise ConnectionError("connection_retired")

        outcome = None
        scope_missing = False

        try:
            with self._operation(binding.generation, is_current,
                                 deadline=deadline, cancelled=cancelled) as cancellation:
                status, value = self._transport.json(
                    AUTH_HOST, TOKEN, cancellation=cancellation,
                    dispatch=self._dispatch(is_current, cancellation, journal="refresh_pending"),
                    body=_form({"grant_type": "refresh_token", "client_id": client,
                                "refresh_token": tokens["refresh"], "resource": RESOURCE}))
                error = value.get("error")
                if isinstance(error, str) and error in TERMINAL_REFRESH:
                    outcome = "invalid"
                    raise ConnectionError("openai_reconnect_required")
                if status != 200:
                    if (status, error) in ((429, "slow_down"), (503, "temporarily_unavailable")):
                        outcome = "retry"
                    raise ConnectionError("openai_refresh_failed")
                replacement = _parse_tokens(value, self._clock())
                if replacement["refresh"] == tokens["refresh"]:
                    raise ConnectionError("invalid_openai_token_response")
                with self._store.locked() as directory:
                    record = self._store.read(directory)
                    is_current(record)
                    cancellation.check()
                    record["tokens"] = replacement
                    record.pop("refresh_pending", None)
                    record.pop("refresh_retry_after", None)
                    self._store.write(directory, record)
                return replacement["access"]
        except ConnectionError as error:
            scope_missing = error.code == "chatgpt_plan_scope_missing"
            raise
        finally:
            with self._store.locked() as directory:
                record = self._store.read(directory)
                if (record.get("generation") == binding.generation
                        and record.get("refresh_pending", {}).get("ticket") == ticket):
                    pending = record.pop("refresh_pending")
                    unknown = pending.get("may_have_sent") and outcome is None
                    if unknown or outcome == "invalid":
                        record.pop("tokens", None)
                        if scope_missing:
                            record["scope_missing"] = True
                        if unknown:
                            record["revocation_unconfirmed"] = True
                    elif outcome == "retry":
                        record["refresh_retry_after"] = self._clock() + 30
                    self._store.write(directory, record)

    def _models(self, binding, access, cancellation):
        status, value = self._transport.json(
            API_HOST, MODELS, bearer=access, cancellation=cancellation,
            dispatch=self._dispatch(
                lambda record: self._require_dispatchable(record, binding, access), cancellation))
        self.require_active(binding)
        if status != 200:
            raise ConnectionError(response_error(status, value))
        models = value.get("models")
        if not isinstance(models, list):
            raise ConnectionError("invalid_openai_models")
        return tuple(model["slug"] for model in models if isinstance(model, dict)
                     and model.get("visibility") == "list"
                     and _value(model.get("slug"), max_length=128))

    def _current(self, binding):
        def check(record):
            if not _active(record, binding):
                raise ConnectionError("connection_retired")
        return check

    def models(self, binding):
        access = self._refresh(binding)
        with self._operation(binding.generation, self._current(binding)) as cancellation:
            return self._models(binding, access, cancellation)

    @contextlib.contextmanager
    def responses(self, binding, body, before_send, *, deadline=None, cancelled=None, inspect_media=False,
                  observe_media=None, before_write=None):
        if (not isinstance(body, dict) or body.get("store") is not False
                or body.get("stream") is not True or not isinstance(body.get("input"), list)
                or body.get("model") != "gpt-6.2-sol"
                or set(body) - {"model", "input", "instructions", "store", "stream"}):
            raise ConnectionError("invalid_responses_body")
        if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise ConnectionError("invalid_openai_deadline")
        access = self._refresh(binding, deadline=deadline, cancelled=cancelled)

        with self._operation(binding.generation, self._current(binding),
                             deadline=deadline, cancelled=cancelled) as cancellation:
            if body["model"] not in self._models(binding, access, cancellation):
                raise ConnectionError("openai_model_unavailable")
            dispatch = self._dispatch(
                lambda record: self._require_dispatchable(record, binding, access),
                cancellation, before_send, before_write=before_write,
            )
            options = {"inspect_media": True} if inspect_media else {}
            if observe_media is not None:
                options["observe_media"] = observe_media
            with self._transport.responses(body, access, cancellation, dispatch, **options) as events:
                def guarded():
                    for event in events:
                        cancellation.check()
                        self.require_active(binding)
                        yield event
                yield guarded()

    def disconnect(self):
        return self.finish_disconnect(self.begin_disconnect(
            physical_host=self.physical_host_for_retirement()))

    def physical_host_for_retirement(self):
        """Collect host evidence for one exact lease without holding the store lock."""
        with self._store.locked() as directory:
            record = self._store.read(directory)
            lease = WorkerLease.parse(record["worker_lease"]) if "worker_lease" in record else None
        if lease is None:
            return None
        host = self._host_probe()
        return LeaseHostProof(lease, host) if type(host) is PhysicalHost else None

    def begin_disconnect(self, *, physical_host=None):
        """Order local token and worker retirement before any provider I/O."""
        generation = _random()
        with self._store.locked() as directory:
            record = self._store.read(directory)
            if not record:
                return None
            if record.get("retiring", 0) > self._clock():
                raise ConnectionError("openai_disconnect_in_progress")
            if "worker_lease" in record:
                record["worker_retiring"] = True
                self._store.write(directory, record)
                lease = WorkerLease.parse(record["worker_lease"])
                host = (physical_host.host if type(physical_host) is LeaseHostProof
                        and physical_host.lease == lease else None)
                lease.terminal(host)
                record.pop("worker_lease")
            record.pop("worker_retiring", None)
            previous = record.get("generation")
            client = record.get("client")
            tokens = record.pop("tokens", None)
            refreshing = record.pop("refresh_pending", {})
            pending = record.pop("pending", {})
            record.pop("scope_missing", None)
            record.pop("refresh_retry_after", None)
            uncertain = bool(record.get("revocation_unconfirmed") or
                             pending.get("may_have_sent") or refreshing.get("may_have_sent"))
            if tokens is not None or uncertain:
                record["revocation_unconfirmed"] = True
            record.update(generation=generation, retiring=self._clock() + RETIRE_SECONDS)
            self._store.write(directory, record)
        self._cancel(previous)
        return Retirement(generation, client, tokens["refresh"] if tokens is not None else None, uncertain)

    def finish_disconnect(self, retirement):
        """Attempt upstream revocation after local retirement has committed."""
        if retirement is None:
            return True
        generation = retirement.generation

        def retiring(record):
            if (record.get("generation") != generation
                    or self._clock() >= record.get("retiring", 0)):
                raise ConnectionError("connection_retired")

        confirmed = False
        try:
            if retirement.refresh is None:
                return not retirement.uncertain
            with self._operation(generation, retiring) as cancellation:
                dispatch = self._dispatch(retiring, cancellation)
                status, value = self._transport.json(AUTH_HOST, DISCOVERY,
                                                     cancellation=cancellation, dispatch=dispatch)
                destination = value.get("revocation_endpoint")
                if status != 200 or value.get("issuer") != ISSUER or not isinstance(destination, str):
                    return False
                parsed = urlsplit(destination)
                if parsed.scheme != "https" or parsed.netloc != AUTH_HOST or parsed.query or parsed.fragment:
                    return False
                status, value = self._transport.json(
                    AUTH_HOST, parsed.path, cancellation=cancellation, dispatch=dispatch,
                    body=_form({"token": retirement.refresh, "token_type_hint": "refresh_token",
                                "client_id": retirement.client}), revocation=True)
                confirmed = status == 200 and not value and not retirement.uncertain
                return confirmed
        except (ConnectionError, ValueError):
            return False
        finally:
            with self._store.locked() as directory:
                record = self._store.read(directory)
                if record.get("generation") == generation:
                    record.pop("retiring", None)
                    if confirmed:
                        record.pop("revocation_unconfirmed", None)
                    self._store.write(directory, record)
