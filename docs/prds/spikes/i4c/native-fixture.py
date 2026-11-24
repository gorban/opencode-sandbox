"""Inner synthetic fixture for the Antigravity qualification launcher."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time


WORK = Path("/run/oc-proof")
NATIVE = Path("/run/oc-native")
ATTRIBUTES = ("application", "oc-sandbox", "purpose", "i4c-offline-fixture")


def check_isolation(outside, port):
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
    if status["NoNewPrivs"].strip() != "1" or int(status["CapEff"], 16):
        raise ValueError("unexpected process authority")
    blocked = (Path(outside) / "marker", Path(outside) / "private.sock", Path("/home"), Path("/run/user"))
    if any(path.exists() for path in blocked):
        raise ValueError("host file or socket visible")
    if {line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:]} != {"lo"}:
        raise ValueError("unexpected network device")
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            raise ValueError("host-side listener reachable")
    with socket.socket() as local:
        local.bind(("127.0.0.1", 0))
        local.listen(1)
        with socket.create_connection(local.getsockname(), timeout=1), local.accept()[0]:
            pass


@contextmanager
def running(command, env, *, payload=None, acp=False, cwd=WORK):
    with subprocess.Popen(command, env=env, cwd=cwd, bufsize=0,
                          stdin=subprocess.PIPE if payload or acp else subprocess.DEVNULL,
                          stdout=subprocess.PIPE if acp else subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
        try:
            if payload is not None:
                with proc.stdin as pipe:
                    pipe.write(payload)
            yield proc
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)


def call(command, env, data=None):
    return subprocess.run(command, env=env, cwd=WORK, input=data, capture_output=True, timeout=3, check=True).stdout


def wait_for_socket(path, service):
    for _ in range(30):
        if path.is_socket():
            return
        if service.poll() is not None:
            break
        time.sleep(.05)
    raise ValueError("private bus did not start")


def verify_keyring_owner(process, env):
    for _ in range(20):
        try:
            owner = call(["/usr/bin/gdbus", "call", "--session", "--timeout", "1", "--dest", "org.freedesktop.DBus",
                          "--object-path", "/org/freedesktop/DBus", "--method", "org.freedesktop.DBus.GetConnectionUnixProcessID",
                          "org.freedesktop.secrets"], env)
        except subprocess.CalledProcessError:
            if process.poll() is not None:
                break
            time.sleep(.05)
            continue
        if owner.strip() == f"(uint32 {process.pid},)".encode():
            return
        break
    raise ValueError("private Secret Service did not have its expected owner")


@contextmanager
def keyring(runtime, common, password):
    runtime.mkdir(mode=0o700)
    bus = runtime / "bus"
    control = runtime / "control"
    control.mkdir(mode=0o700)
    config = runtime / "bus.xml"
    config.write_text(f'''<busconfig><type>session</type><listen>unix:path={bus}</listen><auth>EXTERNAL</auth>
<policy context="default"><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy></busconfig>''')
    env = {**common, "XDG_RUNTIME_DIR": str(runtime), "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
           "GNOME_KEYRING_CONTROL": str(control)}
    with running(["/usr/bin/dbus-daemon", "--nofork", "--nopidfile", f"--config-file={config}"], common) as daemon:
        wait_for_socket(bus, daemon)
        command = [str(NATIVE / "gnome-keyring-daemon"), "--foreground", "--unlock", "--components=secrets",
                   f"--control-directory={control}"]
        with running(command, {**env, "LD_LIBRARY_PATH": str(NATIVE)}, payload=password) as service:
            verify_keyring_owner(service, env)
            yield env


def unique(fields):
    result = dict(fields)
    if len(result) != len(fields):
        raise ValueError("duplicate ACP key")
    return result


def exchange(proc, request_id, method, params):
    request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    proc.stdin.write(json.dumps(request).encode() + b"\n")
    output = bytearray()
    deadline = time.monotonic() + 5
    with selectors.DefaultSelector() as io:
        io.register(proc.stdout, selectors.EVENT_READ)
        while not output.endswith(b"\n"):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not io.select(remaining):
                raise ValueError("ACP response timed out")
            block = os.read(proc.stdout.fileno(), 8192)
            if not block or len(output) + len(block) > 256 * 1024:
                raise ValueError("ACP response closed or exceeded its bound")
            output.extend(block)
    reply = json.loads(output, object_pairs_hook=unique)
    if (not isinstance(reply, dict) or reply.get("jsonrpc") != "2.0" or type(reply.get("id")) is not int
            or reply["id"] != request_id or "method" in reply or ("result" in reply) == ("error" in reply)):
        raise ValueError("unexpected ACP envelope")
    return reply


def require_authentication(reply):
    error = reply.get("error")
    if not isinstance(error, dict) or type(error.get("code")) is not int or error["code"] != -32000:
        raise ValueError("expected signed-out ACP result")
    message = error.get("message")
    if not isinstance(message, str) or message.strip(" \r\n\t").lower() != "authentication required":
        raise ValueError("expected signed-out ACP result")


def new_session(workspace, env):
    argv = [str(NATIVE / "agy"), "acp", "--sandbox", "--disable-telemetry", "--include-default-customizations=false",
            "--log-file", str(workspace.parent / "native.log")]
    with running(argv, env, acp=True, cwd=workspace) as proc:
        hello = exchange(proc, 1, "initialize", {"protocolVersion": 1, "clientCapabilities": {}})
        result = hello.get("result")
        if not isinstance(result, dict) or type(result.get("protocolVersion")) is not int or result["protocolVersion"] != 1:
            raise ValueError("wrong ACP protocol")
        if any(workspace.iterdir()):
            raise ValueError("ACP workspace changed before session creation")
        return exchange(proc, 2, "session/new", {"cwd": str(workspace), "mcpServers": []})


def signed_out(workspace, env):
    require_authentication(new_session(workspace, env))


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main():
    outside, port, action = sys.argv[1:]
    check_isolation(outside, int(port))
    signal.signal(signal.SIGTERM, interrupted)
    with TemporaryDirectory(dir=WORK) as scratch:
        root = Path(scratch)
        home = root / "home"
        home.mkdir(mode=0o700)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(home), "XDG_DATA_HOME": str(home / "data"),
               "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache")}
        password, fixture = secrets.token_hex(24).encode(), secrets.token_hex(16).encode()
        with keyring(root / "first", env, password) as private:
            call(["/usr/bin/secret-tool", "store", "--label=offline fixture", *ATTRIBUTES], private, fixture)
            if action == "cancel":
                (WORK / "cancel-ready").touch()
                signal.pause()
                raise ValueError("cancellation fixture resumed unexpectedly")
        with keyring(root / "second", env, password) as private:
            value = call(["/usr/bin/secret-tool", "lookup", *ATTRIBUTES], private)
            if value.rstrip(b"\n") != fixture:
                raise ValueError("synthetic item did not survive restart")
            workspace = root / "empty"
            workspace.mkdir(mode=0o700)
            signed_out(workspace, private)
    print("ACP_SIGNED_OUT")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("CANCELLED", flush=True)
        raise SystemExit(130) from None
    except (OSError, subprocess.SubprocessError, ValueError, KeyError):
        raise SystemExit("OFFLINE_FIXTURE_FAILED") from None
