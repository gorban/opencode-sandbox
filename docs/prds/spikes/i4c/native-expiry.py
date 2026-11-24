"""Measure refresh attempts for an expired synthetic item with no egress."""

import json
from queue import SimpleQueue
import socket
from threading import Thread


SYNTHETIC_ACCESS = "synthetic-enrollment-fixture-access"
SYNTHETIC_REFRESH = "synthetic-enrollment-fixture-refresh"
ACCOUNT = ("service", "gemini", "username", "antigravity")
REQUEST = b"CONNECT oauth2.googleapis.com:443 HTTP/1.1"


def expire_fixture(call, env):
    lookup = ["/usr/bin/secret-tool", "lookup", *ACCOUNT]
    account = json.loads(call(lookup, env))
    token = account["token"]
    if token["access_token"] != SYNTHETIC_ACCESS or token["refresh_token"] != SYNTHETIC_REFRESH:
        raise ValueError("expected only the synthetic keyring record")
    token["expiry"] = "2000-01-01T00:00:00Z"
    call(["/usr/bin/secret-tool", "store", "--label=expired synthetic fixture", *ACCOUNT], env,
         json.dumps(account).encode("ascii"))
    if json.loads(call(lookup, env)) != account:
        raise ValueError("could not stage expired synthetic fixture")


def observe_only(listener, receipts):
    try:
        client, _ = listener.accept()
        with client:
            client.settimeout(1)
            with client.makefile("rb") as request:
                first_line = request.readline(256)
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            receipts.put(first_line == REQUEST + b"\r\n")
    except OSError:
        return


def check_expired(call, new_session, workspace, env):
    expire_fixture(call, env)
    receipts = SimpleQueue()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(6)
        worker = Thread(target=observe_only, args=(listener, receipts), daemon=True)
        worker.start()
        route = f"http://127.0.0.1:{listener.getsockname()[1]}"
        private = {**env, **{key: route for key in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")}}
        try:
            reply = new_session(workspace, private)
            denied_session = "error" in reply
        except ValueError as error:
            denied_session = str(error) == "ACP response timed out"
        finally:
            worker.join(7)
        if not denied_session or worker.is_alive() or receipts.empty() or receipts.get_nowait() is not True:
            raise ValueError("expired native session did not establish the expected denial")
