"""Run only native sign-in with a private profile and two synthetic tunnel attempts."""

from pathlib import Path
import runpy
import socket
import subprocess
import sys
from threading import Event, Thread


WORK = Path("/run/oc-proof")
DIR = Path("/run/oc-native")
EGRESS = runpy.run_path(str(DIR / "native-egress.py"))
NATIVE = runpy.run_path(str(DIR / "native-fixture.py"))
PASSWORD = b"unlock-only-this-synthetic-profile"
MARKER = b"synthetic-enrollment-restart"


def forward(listener, done):
    try:
        for _ in range(2):
            transfer = Event()
            EGRESS["bridge"](listener, transfer, tunnel=True)
            if not transfer.is_set():
                return
        done.set()
    except OSError:
        return


def private_environment(home):
    return {"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "XDG_DATA_HOME": str(home / "data"),
            "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache")}


def sign_in():
    home = WORK / "home"
    home.mkdir(mode=0o700)
    with NATIVE["keyring"](WORK / "initial-bus", private_environment(home), PASSWORD) as private:
        NATIVE["call"](["/usr/bin/secret-tool", "store", "--label=synthetic enrollment", *NATIVE["ATTRIBUTES"]],
                       private, MARKER)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(8)
            done = Event()
            broker = Thread(target=forward, args=(listener, done), daemon=True)
            broker.start()
            EGRESS["run_login"](listener.getsockname()[1], done, tunnel=True, private_env=private)
            broker.join(1)
            if broker.is_alive() or not done.is_set():
                raise ValueError("native synthetic enrollment did not complete both exchanges")
    print("NATIVE_SYNTHETIC_ENROLLMENT")


def check_restart(*, expired=False):
    home = WORK / "home"
    with NATIVE["keyring"](WORK / "restart-bus", private_environment(home), PASSWORD) as private:
        marker = NATIVE["call"](["/usr/bin/secret-tool", "lookup", *NATIVE["ATTRIBUTES"]], private)
        if marker.rstrip(b"\n") != MARKER:
            raise ValueError("synthetic keyring item was not reopened")
        workspace = WORK / "empty"
        workspace.mkdir(mode=0o700)
        if expired:
            test = runpy.run_path(str(DIR / "native-expiry.py"))
            test["check_expired"](NATIVE["call"], NATIVE["new_session"], workspace, private)
            print("NATIVE_EXPIRED_REFRESH_DENIED")
            return
        reply = NATIVE["new_session"](workspace, private)
    result = reply.get("result")
    if isinstance(result, dict) and isinstance(result.get("sessionId"), str) and result["sessionId"]:
        print("NATIVE_RESTART_ACP_READY")
    else:
        print("NATIVE_ENROLLMENT_STILL_PENDING")


if __name__ == "__main__":
    try:
        if Path("/run/oc-egress/observe.sock").is_socket():
            sign_in()
        else:
            check_restart(expired=sys.argv[1:] == ["expired"])
    except (OSError, KeyError, TypeError, ValueError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit("NATIVE_SYNTHETIC_ENROLLMENT_FAILED") from None
