"""Prove stock worker tools via the public launcher in a sealed disposable guest."""

import json
import os
from pathlib import Path
import re
import runpy
import selectors
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from oc_openai.connection import Connection
from oc_openai.live import make_backend
from oc_openai.managed.relay import Lease, grant_record
from oc_openai.managed.runtime import atomic_write
from oc_openai.profile_backend import ProfileBackend
from stock_worker_tools_capture import PORT, STOCK_SHA256, Terminal, await_idle
from stock_worker_tools_host import bridge_host, inventory, verify
from stock_worker_tools_peer import SYNTHETIC_CIPHERTEXT, SYNTHETIC_REASONING_ID
from stock_worker_tools_projection import (
    ACCOUNT, CAPSULE, PRIVATE_LEAF, PROJECTED_TREE, TEST_HOME, capsule, launch_authority,
)
from stock_worker_tools_protocol import (
    FILE_NAME, FILE_TEXT, LABEL, MODEL, PROMPT, PROVIDER, REFUSED_FILE, REPLY, TITLE,
    ToolScript, require, validate_export, validate_refused_export,
)

SANDBOX = TEST_HOME / "opencode-sandbox"
WORKSPACE = "/sandbox/construct"
CONFIG = TEST_HOME / ".config/oc-sandbox"
STATE = CONFIG / "openai"
EVIDENCE = TEST_HOME / PRIVATE_LEAF
LOG = EVIDENCE / "peer.jsonl"
HOLDERS = (
    TEST_HOME / ".local/share/opencode/auth.json",
    TEST_HOME / ".local/share/keyrings/login.keyring",
)
WORKER_ID = re.compile(r"[a-f0-9]{64}", re.ASCII)
TERM_ENV = {
    "HOME": str(TEST_HOME), "LANG": "C.UTF-8", "OC_CHROMIUM_MODE": "headless",
    "PATH": "/usr/bin:/bin", "TERM": "xterm-256color",
}
CREDENTIAL_MARKER = "fixture workstation credential marker"
LEGACY_MARKER = "fixture legacy worker credential marker"
JOB_MARKER = "fixture readable job marker"


def host(*args, check=True, input_data=None, timeout=30):
    return subprocess.run(
        ("/usr/bin/host-spawn", "--no-pty", *args), env={**TERM_ENV, "TERM": "dumb"}, cwd=PROJECTED_TREE,
        check=check, capture_output=True, timeout=timeout, input=input_data,
    )


def podman(*args, **options):
    return host("/usr/bin/podman", *args, **options)


def private_write(path, text):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)


def bootstrap():
    require(not any(path.exists() for path in (STATE, *HOLDERS, EVIDENCE, CONFIG / "providers.toml", SANDBOX)),
            f"Dedicated {ACCOUNT} account has pre-existing provider or worker state")
    private_write(LOG, "")
    private_write(EVIDENCE / "tool-state.json", "[]")
    private_write(SANDBOX / "construct/job-marker", f"{JOB_MARKER}\n")
    for path in HOLDERS:
        private_write(path, f"{CREDENTIAL_MARKER}\n")
    support = runpy.run_path(str(PROJECTED_TREE / "tests/test_openai_connection.py"))

    def connection(directory):
        transport = SimpleNamespace(json=support["FixtureTransport"]().json)
        return Connection(directory, verifier=support["FixtureVerifier"](), browser=support["FixtureBrowser"](),
                          transport=transport)

    ProfileBackend(STATE, connection=connection).connect(LABEL)
    private_write(CONFIG / "providers.toml",
                  f'[launch]\ndefault_provider = "openai/{LABEL}"\ndefault_model = "{MODEL}"\nmini = false\n'
                  f'\n[providers.openai.{LABEL}]\nenabled = true\nauth_mode = "subscription"\n')


def events():
    return [json.loads(line) for line in LOG.read_text().splitlines()]


def await_retired(offset):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        entries = events()[offset:]
        opened = {entry["pid"] for entry in entries if entry["op"] == "open"}
        closed = {entry["pid"] for entry in entries if entry["op"] == "retired"}
        require(not any(entry["op"] == "retirement_pending" or entry["op"].startswith("peer_start_failed")
                        for entry in entries), "Synthetic TLS peer could not be verified")
        if opened == closed:
            return
        time.sleep(.05)
    raise RuntimeError("An owned TLS peer still lacks retirement evidence")


def inspect(*ids):
    return json.loads(podman("container", "inspect", *ids).stdout)


def owned():
    ids = podman("ps", "-aq", "--no-trunc", "--filter", "label=oc.sandbox=1",
                 "--filter", "label=oc.instance=default").stdout.decode().split()
    require(all(WORKER_ID.fullmatch(identifier) for identifier in ids), "Podman returned an invalid container ID")
    workers, relays = [], []
    for item in (inspect(*ids) if ids else ()):
        labels = item["Config"]["Labels"]
        if labels.get("oc.ui_mode") == "full":
            workers.append(item)
        elif labels.get("oc.role") == "provider-relay":
            require(labels["oc.provider"] == f"openai/{LABEL}", "Wrong managed relay route")
            relays.append(item)
        elif not (item.get("IsInfra") is True or
                  (item["Name"].lstrip("/") == "oc-chromium" and labels.get("oc.cfg"))):
            raise RuntimeError("Unexpected container marked as managed proof runtime")
    return workers, relays


def run_worker(identifier, *args, **options):
    return podman("exec", "-i", identifier, *args, **options)


def mcs_pair(label):
    match = re.fullmatch(r"[^:]+:[^:]+:[^:]+:s0:c([0-9]{1,4}),c([0-9]{1,4})", label or "")
    require(match is not None, "Managed pod has an unqualified SELinux category label")
    first, second = map(int, match.groups())
    require(first != second and max(first, second) < 1024, "Managed pod has an invalid SELinux category pair")
    return frozenset((first, second))


def pod_member_ids(pod, worker, relay):
    require(pod["Id"] == worker["Pod"] == relay["Pod"], "Managed pod identity changed")
    ids = [entry["Id"] for entry in pod["Containers"]]
    members = {worker["Id"], relay["Id"], pod["InfraContainerID"]}
    require(len(members) == 3 and members <= set(ids)
            and all(WORKER_ID.fullmatch(identifier) for identifier in ids)
            and len(set(ids)) == len(ids), "Managed pod membership is missing or ambiguous")
    require(pod["InfraConfig"]["PortBindings"] in ({}, None), "Managed pod has a published port")
    return ids


def verify_relay_mcs(pod, worker, relay, details):
    ids = pod_member_ids(pod, worker, relay)
    by_id = {item["Id"]: item for item in details}
    require(len(details) == len(ids) and set(by_id) == set(ids)
            and all(item["Pod"] == pod["Id"] for item in details), "Managed pod inspection changed membership")
    infra = by_id[pod["InfraContainerID"]]
    require(infra["IsInfra"] is True and infra["Image"] == "" and infra["ImageName"] == ""
            and infra["Path"] == "/catatonit" and infra["Args"] == ["-P"] and infra["Mounts"] == []
            and infra["HostConfig"]["Privileged"] is False, "Pod infrastructure is not the qualified pause process")
    applications = [item for item in details if item["Id"] != infra["Id"]]
    require(all(item["IsInfra"] is False for item in applications), "Duplicate infrastructure in managed pod")
    for previous in (worker, relay):
        require(by_id[previous["Id"]]["ProcessLabel"] == previous["ProcessLabel"],
                "Application process label changed during pod inspection")
    level = mcs_pair(relay["ProcessLabel"])
    require(mcs_pair(relay["MountLabel"]) == level
            and by_id[relay["Id"]]["MountLabel"] == relay["MountLabel"],
            "Relay process and mount categories differ")
    require(all(other["Id"] == relay["Id"] or mcs_pair(other["ProcessLabel"]) != level
                for other in applications), "Relay SELinux category is shared with an application sibling")


def verify_isolation(worker, relay):
    wid, rid = worker["Id"], relay["Id"]
    require(worker["State"]["Running"] and relay["State"]["Running"] and worker["Pod"] == relay["Pod"],
            "Worker and relay are outside the admitted pod")
    require(run_worker(wid, "sha256sum", "/usr/local/bin/opencode").stdout.decode().split()[0] == STOCK_SHA256,
            "Worker OpenCode binary differs from the stock pin")
    for item in (worker, relay):
        is_worker = item["Id"] == wid
        mounts = {mount["Destination"]: mount for mount in item["Mounts"]}
        expected = {"/sandbox", "/root", "/etc/opencode/opencode.json"} if is_worker else {
            "/source", "/provider", "/grant", "/proof",
        }
        require(set(mounts) == expected and len(mounts) == len(item["Mounts"]),
                "Worker or relay host mounts differ from the approved set")
        require(all(mount["Type"] == "bind" for target, mount in mounts.items() if target != "/root"),
                "Unexpected managed runtime volume")
        if is_worker:
            require(mounts["/root"]["Type"] == "volume" and mounts["/root"]["Name"] == "oc-openai-home"
                    and mounts["/sandbox"]["RW"] is True and Path(mounts["/sandbox"]["Source"]) == SANDBOX
                    and mounts["/etc/opencode/opencode.json"]["RW"] is False,
                    "Managed worker home, job bind or read-only config differs")
        else:
            require(all(mount["RW"] is False for mount in mounts.values()), "Relay has a writable host mount")
        require("container_t:" in item["ProcessLabel"] and "container_file_t:" in item["MountLabel"]
                and not item["HostConfig"]["Privileged"], "Managed runtime has invalid SELinux or privilege flags")
        blocked = {"OPENAI_API_KEY", "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "PGPASSFILE", "DOCKER_HOST"}
        environment = item["Config"]["Env"]
        require(not blocked.intersection(entry.partition("=")[0] for entry in environment)
                and all("test-access" not in entry and CREDENTIAL_MARKER not in entry for entry in
                        (*environment, *item["Config"]["CreateCommand"])), "Workstation authority leaked to process config")
        for path in (*map(str, HOLDERS), "/root/.local/share/opencode/auth.json",
                     "/root/.local/share/keyrings/login.keyring", "/root/legacy-credential-marker"):
            probe = run_worker(item["Id"], "/bin/sh", "-c", 'test ! -r "$1"', "path-check", path, check=False)
            require(probe.returncode == 0, "A synthetic credential path became worker- or relay-readable")
        job = run_worker(item["Id"], "cat", WORKSPACE + "/job-marker", check=False)
        require((job.returncode == 0 and job.stdout == (JOB_MARKER + "\n").encode()) if is_worker else
                job.returncode != 0, "Job marker did not respect its worker-only mount")
    siblings = json.loads(podman("pod", "inspect", worker["Pod"]).stdout)
    if type(siblings) is list:
        (siblings,) = siblings
    sibling_ids = pod_member_ids(siblings, worker, relay)
    listen_tables = run_worker(rid, "cat", "/proc/net/tcp", "/proc/net/tcp6").stdout.decode()
    verify_loopback_listener(listen_tables)
    verify_relay_mcs(siblings, worker, relay, inspect(*sibling_ids))
    applied = run_worker(rid, "/bin/cat", "/proc/self/attr/current").stdout.rstrip(b"\0\n")
    require(applied.decode() == relay["ProcessLabel"], "Relay effective process label changed")
    for mount in relay["Mounts"]:
        applied = host("/usr/bin/getfattr", "--only-values", "-n", "security.selinux", "--",
                       mount["Source"]).stdout.rstrip(b"\0\n")
        require(applied.decode() == relay["MountLabel"], "Relay effective mount label changed")
    config = json.loads(run_worker(wid, "cat", "/etc/opencode/opencode.json").stdout)
    (name,) = config["providers"]
    require(name == PROVIDER and config["model"] == f"{PROVIDER}/{MODEL}" and
            config["providers"][name]["models"][MODEL]["capabilities"]["tools"] is True,
            "Managed worker stock config did not enable the expected local tools")
    route = config["providers"][name]["settings"]
    require(route["baseURL"] == f"http://127.0.0.1:{PORT}/v1"
            and route["store"] is False and type(route["apiKey"]) is str and len(route["apiKey"]) >= 24
            and all(value not in json.dumps(config) for value in ("test-access", CREDENTIAL_MARKER, LEGACY_MARKER)),
            "Stock route was not broker-only or leaked a marker")
    scratch = Path(next(mount["Source"] for mount in relay["Mounts"] if mount["Destination"] == "/provider")).parent
    require(scratch.is_relative_to("/tmp") and scratch.name.startswith("oc-chat-"),
            "Managed relay scratch layout changed")
    return route["apiKey"], scratch


WIRE = """
import http.client, json, sys
request = json.load(sys.stdin)
handle = http.client.HTTPConnection(request['host'], request['port'], timeout=3)
auth = {'Authorization': 'Bearer ' + request['token'], 'Content-Type': 'application/json',
        'Host': '127.0.0.1:8401'}
status, data = None, b''
try:
    handle.request(request['method'], request['path'], body=request['body'], headers=auth)
    response = handle.getresponse()
    status = response.status
    try:
        data = response.read(65536)
    except http.client.IncompleteRead as failure:
        data = failure.partial
    except (OSError, http.client.HTTPException):
        pass
except (OSError, http.client.HTTPException):
    pass
finally:
    handle.close()
print(json.dumps({'status': status, 'body': data.decode(errors='replace')}))
"""


def wire(runner, token, *, body=None, target="127.0.0.1", port=PORT):
    data = json.dumps({"host": target, "port": port, "token": token,
                       "method": "GET" if body is None else "POST",
                       "path": "/v1/models" if body is None else "/v1/responses",
                       "body": None if body is None else json.dumps(body)}).encode()
    return json.loads(runner("/usr/bin/python3", "-IB", "-c", WIRE, input_data=data).stdout)


TCP_CONNECT = """
import json, socket, sys
host, port = json.load(sys.stdin)
try:
    with socket.create_connection((host, port), timeout=3):
        connected = True
except OSError:
    connected = False
print(json.dumps(connected))
"""


def tcp_connect(runner, host, port):
    result = runner("/usr/bin/python3", "-IB", "-c", TCP_CONNECT, input_data=json.dumps([host, port]).encode())
    return json.loads(result.stdout)


def ordinary_body():
    return {"model": MODEL, "input": [{"role": "user", "content": PROMPT}], "stream": True, "store": False}


def verify_loopback_listener(tables):
    target = f"{PORT:04X}"
    listeners = []
    for line in tables.splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[3] == "0A" and fields[1].endswith(":" + target):
            listeners.append(fields[1])
    require(listeners == ["0100007F:" + target], "Managed provider relay was not listening only on IPv4 loopback")


IPV4_INTERFACES = """
import fcntl, json, socket, struct
addresses = []
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
    for _, name in socket.if_nameindex():
        if name == 'lo':
            continue
        try:
            info = fcntl.ioctl(channel, 0x8915, struct.pack('256s', name.encode()))
        except OSError as error:
            if error.errno != 99:
                raise
        else:
            addresses.append(socket.inet_ntoa(info[20:24]))
print(json.dumps(sorted(set(addresses))))
"""


def inside_denials(wid, token, scratch):
    runner = lambda *args, **kwargs: run_worker(wid, *args, **kwargs)
    initial_generations = sum(entry["op"] == "generation" for entry in events())
    require(wire(runner, token)["status"] == 200, "The admitted in-pod relay did not accept its own bearer")
    require(wire(runner, "incorrect-synthetic-bearer")["status"] == 401, "Wrong in-pod bearer crossed broker")
    addresses = json.loads(runner("/usr/bin/python3", "-IB", "-c", IPV4_INTERFACES).stdout)
    require(addresses and "127.0.0.1" not in addresses, "No non-loopback pod IPv4 address could be measured")
    image = inspect(wid)[0]["Image"]
    outside = lambda *args, **kwargs: podman(
        "run", "--rm", "-i", "--pull=never", "--network=pasta", "--http-proxy=false",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint", args[0], image, *args[1:], **kwargs,
    )
    for target in ("127.0.0.1", *addresses):
        require(wire(host, token, target=target)["status"] is None,
                "The guest host reached a measured IPv4 relay candidate")
        require(wire(outside, token, target=target)["status"] is None,
                "An independently networked container reached a measured IPv4 relay candidate")
    require(not tcp_connect(runner, "192.0.2.1", 443),
            "The worker had direct egress in the sealed offline guest")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(4)
        client.connect(str(scratch / "provider/provider.sock"))
        raw = f"GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nAuthorization: Bearer {token}\r\n\r\n"
        client.sendall(raw.encode())
        try:
            direct = client.recv(32)
        except ConnectionResetError:
            direct = b""
        require(direct == b"", "Direct broker client lacking relay proof received a response")
    for native_type in ("mcp", "web_search", "code_interpreter", "unknown_hosted"):
        response = wire(runner, token, body={**ordinary_body(), "tools": [{"type": native_type}]})
        require(response["status"] == 400, "Provider-native tool declaration crossed broker")
    require(wire(runner, token, body={**ordinary_body(), "model": "foreign-model"})["status"] == 400,
            "Unqualified model crossed the selected broker")
    unknown = {"type": "reasoning", "id": "rs_local_1", "encrypted_content": "oc_rs_unknown_fixture_handle"}
    require(wire(runner, token, body={**ordinary_body(), "input": [unknown, *ordinary_body()["input"]]})["status"] == 400,
            "Foreign opaque handle crossed the job vault")
    require(sum(entry["op"] == "generation" for entry in events()) == initial_generations,
            "An isolation negative reached provider inference")


def stock_sessions(worker):
    listed = podman("exec", "--workdir", WORKSPACE, worker, "opencode", "--standalone", "session",
                    "list", "--format", "json").stdout
    return {session["id"]: session for session in json.loads(listed)}


def export_stock(worker, session):
    return json.loads(podman("exec", "--workdir", WORKSPACE, worker, "opencode", "--standalone", "session",
                             "export", session).stdout)


def fresh_export(worker, existing):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        sessions = stock_sessions(worker)
        fresh = set(sessions) - existing
        require(len(fresh) <= 1, "Stock created unexpected extra conversations")
        if fresh:
            (session,) = fresh
            if sessions[session].get("title") == TITLE:
                return await_idle(lambda: export_stock(worker, session))
        time.sleep(.1)
    raise RuntimeError("Stock session and exact title did not settle")


def foreground(terminal):
    expected = "Start interactive OpenCode session for instance 'default'? [y/N]"
    screen = terminal.await_screen(lambda page: any(line.strip() == expected for line in page.splitlines()),
                                   "the exact foreground launch confirmation")
    provider_rows = [line.strip() for line in screen.splitlines() if line.lstrip().startswith("Provider ")]
    require(len(provider_rows) == 1 and provider_rows[0].startswith(
        f"Provider openai/{LABEL} [{PROVIDER}]: auth=subscription, policy=subscription (no verified spending ceiling)")
        and f"Initial active model: {PROVIDER}/{MODEL}" in screen and "UI: OpenCode" in screen
        and f"Workspace: {WORKSPACE}" in screen and "No API-key fallback will be forwarded." in screen,
        "Foreground route, billing, model or workspace differs from the approved launch")
    require(not any(line.strip().endswith("[y/N]") and line.strip() != expected for line in screen.splitlines()),
            "An unapproved foreground confirmation was displayed")


def prove_tools(terminal, worker, offset):
    file = SANDBOX / "construct" / FILE_NAME
    require(not file.exists(), "Synthetic proof file already existed")
    existing = set(stock_sessions(worker))
    terminal.type_line(PROMPT)
    terminal.await_screen(lambda page: any(line.strip(" │┃▏●") == REPLY for line in page.splitlines()),
                          "the stock tool chain final answer", timeout=90)
    exported = fresh_export(worker, existing)
    script = ToolScript(WORKSPACE)
    for request in json.loads((EVIDENCE / "tool-state.json").read_text()):
        script.respond(request)
    script.verify_done()
    validate_export(exported, script)
    require(file.read_bytes() == FILE_TEXT.encode(), "Independent job file bytes differed")
    require(all(marker not in json.dumps(exported) for marker in (CREDENTIAL_MARKER, LEGACY_MARKER, "test-access")),
            "Stock session export contained a synthetic workstation credential")
    observed = events()[offset:]
    stages = [entry["details"]["stage"] for entry in observed if entry["op"] == "generation"]
    require(stages == [1, 2, 3, 4] and sum(entry["op"] == "title" for entry in observed) == 1,
            "The named synthetic provider did not receive exactly four causal requests and a separate title")


def assert_no_slot():
    workers, relays = owned()
    require(not workers and not relays, "An owned worker or relay survived")
    _, connection, _ = make_backend().profile_connection(LABEL)
    require(not connection.has_active_leases(), "An owned provider lease survived")


def scratch_roots():
    return {path for path in Path("/tmp").glob("oc-chat-*") if path.lstat().st_uid == os.getuid()}


def run_cleanup(primary, *actions):
    errors = []
    for action in actions:
        try:
            action()
        except Exception as error:
            errors.append(error)
    if errors:
        first = primary if primary is not None else errors.pop(0)
        for error in errors:
            first.add_note(f"Fixture cleanup: {type(error).__name__}: {error}")
        if primary is None:
            raise first


def verify_scratch_retirement(before):
    require(scratch_roots() == before, "An owned launcher scratch root survived")


def launch(state, case, verify_active=None, *, verify_inventory=None):
    offset = len(events())
    before = scratch_roots()
    with launch_authority(state, case) as register, tempfile.TemporaryDirectory(prefix="oc-tools-tty-") as temporary:
        terminal = Terminal(Path(temporary), {**TERM_ENV, "CONTAINER_ID": os.environ.get("CONTAINER_ID", "")})
        failure = None
        try:
            terminal.start(str(PROJECTED_TREE / "oc-sandbox"), width=160)
            register(int(terminal.run("display-message", "-p", "-t", "stock", "#{pane_pid}")))
            foreground(terminal)
            assert_no_slot()
            terminal.type_line("n" if case == "decline" else "y")
            if case == "decline":
                terminal.await_screen(lambda screen: "Fixture exit" in screen, "the foreground decline")
                require(not any(entry["op"] == "generation" for entry in events()[offset:]),
                        "Declined launcher reached synthetic generation")
            else:
                terminal.await_screen(lambda screen: "Ask anything" in screen, "the actual stock input")
                terminal.run("resize-window", "-t", "stock", "-x", "104", "-y", "38")
                (worker,), (relay,) = owned()
                token, scratch = verify_isolation(worker, relay)
                verify_active(terminal, worker["Id"], token, scratch, offset)
                if case != "held":
                    terminal.run("send-keys", "-t", "stock", "C-c", "C-c")
                terminal.await_screen(lambda screen: "Fixture exit" in screen, "launcher cleanup")
        except BaseException as error:
            failure = error
            raise
        finally:
            def stop_terminal():
                if failure is not None:
                    terminal.run("send-keys", "-t", "stock", "C-c", "C-c", check=False)
                    try:
                        terminal.await_screen(lambda screen: "Fixture exit" in screen, "failed launch retirement",
                                              timeout=8)
                    finally:
                        terminal.run("kill-server", check=False)
                else:
                    terminal.run("kill-server", check=False)

            actions = [stop_terminal, assert_no_slot, lambda: await_retired(offset),
                       lambda: verify_scratch_retirement(before)]
            if verify_inventory is not None:
                actions.append(verify_inventory)
            run_cleanup(failure, *actions)


def verify_support_inventory(before, after):
    require(all(after[key] == before[key] for key in ("images", "networks", "secrets"))
            and len(after["pods"]) == 1 and after["volumes"] == ["oc-chrome", "oc-home", "oc-openai-home"],
            "Support setup changed the sealed inventory unexpectedly")
    (pod_id,) = after["pods"]
    pod = json.loads(podman("pod", "inspect", pod_id).stdout)
    if type(pod) is list:
        (pod,) = pod
    ids = [entry["Id"] for entry in pod["Containers"]]
    require(pod["Name"] == "oc" and len(ids) == 2 and pod["InfraContainerID"] in ids
            and {entry["Name"] for entry in pod["Containers"] if entry["Id"] != pod["InfraContainerID"]} == {"oc-chromium"}
            and after["containers"] == sorted([*before["containers"], *ids]),
            "An unowned service survived stock runtime cleanup")


def invalid_upstream(terminal, worker, token, scratch, offset):
    existing = set(stock_sessions(worker))
    root = SANDBOX / "construct"
    old = (root / FILE_NAME).read_bytes()
    require(old == FILE_TEXT.encode() and not (root / REFUSED_FILE).exists(),
            "Negative stock workspace started with unexpected contents")
    terminal.type_line(PROMPT)
    exported = fresh_export(worker, existing)
    validate_refused_export(exported)
    observed = events()[offset:]
    require(sum(entry["op"] == "generation" for entry in observed) == 1
            and sum(entry["op"] == "title" for entry in observed) == 1
            and sum(entry["op"] == "initial_retry" for entry in observed) <= 1,
            "Unsupported upstream tool caused a continuation or unmatched stock title")
    require((root / FILE_NAME).read_bytes() == old and not (root / REFUSED_FILE).exists(),
            "Unsupported upstream tool changed a synthetic file")


HOLD_READER = """
import http.client, json, socket, sys
config = json.load(sys.stdin)
connection = http.client.HTTPConnection('127.0.0.1', 8401, timeout=12)
connection.request('POST', '/v1/responses', json.dumps(config['body']), {
    'Authorization': 'Bearer ' + config['token'], 'Content-Type': 'application/json'})
response = connection.getresponse()
name = response.readline(8192)
data = response.readline(8192)
if (response.status != 200 or response.headers.get_content_type() != 'text/event-stream'
        or name != b'event: response.created\\n' or not data.startswith(b'data: ')
        or json.loads(data[6:]).get('type') != 'response.created'):
    raise RuntimeError('Held exchange did not begin with HTTP 200 and a created SSE event')
print(json.dumps({'event': 'ready'}), flush=True)
try:
    remaining = response.read(65536)
except socket.timeout:
    print(json.dumps({'event': 'timeout'}), flush=True)
except http.client.IncompleteRead as error:
    print(json.dumps({'event': 'closed', 'terminal': b'response.completed' in error.partial}), flush=True)
except ConnectionResetError:
    print(json.dumps({'event': 'closed', 'terminal': False}), flush=True)
else:
    print(json.dumps({'event': 'terminated', 'terminal': b'response.completed' in remaining}), flush=True)
"""


def held_line(child, deadline):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        require(selector.select(max(0, deadline - time.monotonic())), "Held worker probe receipt timed out")
        line = child.stdout.readline(8192)
    require(bool(line), "Held worker probe exited without a receipt")
    return json.loads(line)


def reap_held_child(child):
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=2)


def retirement(terminal, worker, token, scratch, offset):
    worker_data, = inspect(worker)
    argv = ("/usr/bin/host-spawn", "--no-pty", "/usr/bin/podman", "run", "--rm", "-i", "--pull=never",
            "--pod", worker_data["Pod"], "--http-proxy=false", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--entrypoint", "/usr/bin/python3", worker_data["Image"], "-IB", "-c", HOLD_READER)
    child = subprocess.Popen(argv, env={**TERM_ENV, "TERM": "dumb"}, cwd=PROJECTED_TREE, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    failure = None
    try:
        child.stdin.write(json.dumps({"token": token, "body": ordinary_body()}).encode())
        child.stdin.close()
        require(held_line(child, time.monotonic() + 10) == {"event": "ready"}, "No verified held worker response")
        grant = scratch / "grant"
        active = (grant / "state").read_bytes()
        incarnation, generation, status = active.decode().split()
        require(status == "active", "The held request did not own an active lease")
        lease = Lease(grant, active, time.monotonic_ns() + 5_000_000_000)
        with lease.fence():
            require(lease.active(), "The held grant changed before the retirement control")
            atomic_write(grant / "state", grant_record(incarnation, int(generation), False))
        require(lease.status() == "terminal", "The original grant did not become terminal")
        require(held_line(child, time.monotonic() + 5) == {"event": "closed", "terminal": False},
                "Held worker probe did not observe closure before its timeout")
        require(child.wait(timeout=8) == 0, "Held worker probe did not retire cleanly")
        stale = podman("container", "exists", worker, check=False)
        if stale.returncode == 0:
            try:
                reply = wire(lambda *args, **kwargs: run_worker(worker, *args, **kwargs), token,
                             body=ordinary_body())
            except subprocess.CalledProcessError:
                require(podman("container", "exists", worker, check=False).returncode == 1,
                        "Could not verify whether stale relay access was denied")
            else:
                require(reply["status"] in (None, 401, 403), "Retired worker bearer retained access")
        else:
            require(stale.returncode == 1, "Could not verify original worker retirement")
    except BaseException as error:
        failure = error
        raise
    finally:
        run_cleanup(failure, lambda: reap_held_child(child), child.stdin.close, child.stdout.close)
    deadline = time.monotonic() + 5
    observed = events()[offset:]
    while not any(entry["op"] == "held_closed" for entry in observed) and time.monotonic() < deadline:
        time.sleep(.05)
        observed = events()[offset:]
    require(sum(entry["op"] == "generation" for entry in observed) == 1
            and sum(entry["op"] == "held_closed" for entry in observed) == 1,
            "The synthetic provider did not observe exactly one generation and one held socket closure")


def prove_vault(worker, token, offset, previous=None):
    runner = lambda *args, **kwargs: run_worker(worker, *args, **kwargs)
    reply = wire(runner, token, body=ordinary_body())
    require(reply["status"] == 200 and SYNTHETIC_CIPHERTEXT not in reply["body"]
            and SYNTHETIC_REASONING_ID not in reply["body"], "Host state escaped the broker vault")
    frames = [json.loads(line[6:]) for line in reply["body"].splitlines() if line.startswith("data: ")]
    (opaque,) = [frame["item"] for frame in frames if frame.get("type") == "response.output_item.done"]
    require(opaque["type"] == "reasoning" and opaque["encrypted_content"].startswith("oc_rs_"),
            "The authenticated lease did not receive an opaque reasoning handle")

    def replay(item):
        request = {**ordinary_body(), "input": [item, *ordinary_body()["input"]]}
        return wire(runner, token, body=request)["status"]

    require(replay({**opaque, "id": "unrelated_local_item"}) == 400, "Mismatched local reasoning item crossed the vault")
    if previous is not None:
        require(replay(previous) == 400, "Reasoning from a retired lease crossed the new vault")
    require(replay(opaque) == 200, "Authentic opaque reasoning did not replay on the original live lease")
    observed = events()[offset:]
    require(sum(entry["op"] == "generation" for entry in observed) == 2
            and sum(entry["op"] == "authentic_reasoning" for entry in observed) == 1,
            "Foreign or mismatched reasoning reached upstream")
    return opaque


def seed_legacy_marker():
    (volume,) = json.loads(podman("volume", "inspect", "oc-home").stdout)
    home = Path(volume["Mountpoint"])
    require(volume["Name"] == "oc-home" and home.is_relative_to(TEST_HOME / ".local/share/containers/storage"),
            "Could not locate the qualified synthetic legacy volume")
    marker = home / "legacy-credential-marker"
    private_write(marker, LEGACY_MARKER + "\n")
    require(marker.read_text() == LEGACY_MARKER + "\n", "Legacy synthetic credential was missing")


def main():
    require(not sys.argv[1:], "The sealed stock guest fixture takes no options")
    state = capsule()
    sealed = verify(state, bridge_host, podman)["inventory"]
    bootstrap()
    launch(state, "decline", verify_inventory=lambda: verify_support_inventory(sealed, inventory(podman, state.uid)))
    after_decline = inventory(podman, state.uid)
    verify_support_inventory(sealed, after_decline)
    seed_legacy_marker()

    def active(terminal, worker, token, scratch, offset):
        inside_denials(worker, token, scratch)
        prove_tools(terminal, worker, offset)

    def stable_inventory():
        require(inventory(podman, state.uid) == after_decline, "An owned launch resource survived the proof")

    launch(state, "tools", active, verify_inventory=stable_inventory)
    for case in ("hosted", "undeclared"):
        launch(state, case, invalid_upstream, verify_inventory=stable_inventory)
    prior = []
    for _ in range(2):
        launch(state, "vault", lambda terminal, worker, token, scratch, offset:
               prior.append(prove_vault(worker, token, offset, previous=prior[-1] if prior else None)),
               verify_inventory=stable_inventory)
    launch(state, "held", retirement, verify_inventory=stable_inventory)
    print(json.dumps({"source_sha256": state.source_sha256, "projection_sha256": state.projection_sha256,
                      "stock_binary_sha256": STOCK_SHA256, "model": f"{PROVIDER}/{MODEL}",
                      "stock_session": "patch/read/shell completed", "continuations": 3,
                      "inventory": after_decline}, sort_keys=True))


if __name__ == "__main__":
    main()
