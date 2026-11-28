"""Prove stock worker tools via the public launcher in a sealed disposable guest."""

from contextlib import contextmanager
import fcntl
import hashlib
import errno
import json
import os
import secrets
from pathlib import Path
import re
import runpy
import selectors
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from oc_openai.connection import Connection
from oc_openai.connection_state import decode_json
from oc_openai.live import make_backend
from oc_openai.managed.relay import Lease, PROOF_PREFIX, PROOF_SIZE, grant_record
from oc_openai.managed.runtime import atomic_write
from oc_openai.profile_backend import ProfileBackend
from oc_openai.session_broker import USAGE_LOG_LIMIT, USAGE_LOG_NAME
from oc_openai.session_protocol import format_models_response
from oc_openai.session_relay import REQUEST_LENGTH
from stock_worker_tools_capture import PORT, STOCK_SHA256, Terminal, await_idle, question_screen
from stock_worker_tools_host import bridge_host, inventory, verify
from stock_worker_tools_peer import SHAPE_LOG, SYNTHETIC_CIPHERTEXT, SYNTHETIC_REASONING_ID, private_file
from stock_worker_tools_projection import (
    ACCOUNT, CAPSULE, PRIVATE_LEAF, PROJECTED_TREE, TEST_HOME, capsule, launch_authority,
)
from stock_worker_tools_sealed import (
    CONTROLLER_SKILL, CONTROLLER_SKILL_BYTES, INTERACTION_CASES, SEARCH_CASES, SEARCH_JOB, SEARCH_SENTINEL,
    SEARCH_SENTINEL_BYTES, SEALED_CASES, SKILL_BYTES, TITLE_SETTINGS, WORKER_SKILL, append_row, interaction_config,
    journal_path, read_journal, scenario, setup_search, usage_sequence_complete, verified_rows, verify_search_control_match,
    verify_usage,
)
from stock_worker_tools_search import inventory as search_inventory
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


_OPTIONAL_SHAPE_ERRORS = frozenset({errno.EDQUOT, errno.EMFILE, errno.ENFILE, errno.ENOSPC, errno.EROFS})


def provision_shape_log(directory):
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
                and os.path.samestat(info, directory.lstat()), "Untrusted shape diagnostic directory")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            fd = os.open(SHAPE_LOG, flags, 0o600, dir_fd=parent)
        except OSError as error:
            if error.errno in _OPTIONAL_SHAPE_ERRORS:
                try:
                    os.stat(SHAPE_LOG, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    require(os.path.samestat(info, directory.lstat()), "Shape diagnostic directory changed")
                    return
            raise
        try:
            opened = os.fstat(fd)
            named = os.stat(SHAPE_LOG, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid()
                    and stat.S_IMODE(opened.st_mode) == 0o600 and opened.st_nlink == 1
                    and os.path.samestat(opened, named) and os.path.samestat(info, directory.lstat()),
                    "Untrusted shape diagnostic file")
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def bootstrap():
    require(not os.path.lexists(EVIDENCE)
            and not any(path.exists() for path in (STATE, *HOLDERS, CONFIG / "providers.toml", SANDBOX)),
            f"Dedicated {ACCOUNT} account has pre-existing provider or worker state")
    EVIDENCE.mkdir(mode=0o700)
    private_write(LOG, "")
    provision_shape_log(EVIDENCE)
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


def verify_kernel_isolation(worker, relay, scratch, case):
    protected = [SEARCH_SENTINEL, CONTROLLER_SKILL] if case in INTERACTION_CASES else [SEARCH_SENTINEL]
    require(scratch.parent == Path("/tmp") and re.fullmatch(r"oc-chat-[a-z0-9_]{8}", scratch.name),
            "Sealed relay slot root is not the exact launcher layout")
    worker_binds = {entry["Destination"]: entry for entry in worker["Mounts"]}
    config_bind = Path(worker_binds["/etc/opencode/opencode.json"]["Source"])
    require(len(config_bind.parts) == 5 and config_bind.parts[:2] == ("/", "tmp")
            and re.fullmatch(r"oc-chat-[a-z0-9_]{8}", config_bind.parts[2])
            and config_bind.parts[3:] == ("opencode", "opencode.json"),
            "Sealed worker config source is not the exact launcher layout")
    w_expected = {"/sandbox": SANDBOX, "/root": worker_config_location().parents[2],
                  "/etc/opencode/opencode.json": config_bind}
    r_expected = {target: scratch / target[1:] for target in ("/source", "/provider", "/grant", "/proof")}
    path = PROJECTED_TREE / "tests/e2e/stock_worker_tools_mounts.py"
    anchors = []
    for item, expected in ((worker, w_expected), (relay, r_expected)):
        bindings = {entry["Destination"]: entry for entry in item["Mounts"]}
        require(bindings.keys() == expected.keys() and len(bindings) == len(item["Mounts"]),
                "Sealed inspected bindings differ")
        for target, source in expected.items():
            bind = bindings[target]
            require(Path(bind["Source"]) == source, "Sealed inspected binding source differs")
            if target in r_expected or target == "/etc/opencode/opencode.json":
                require(bind["Propagation"] == "rprivate" and not bind["RW"]
                        and {"nosuid", "nodev", "noexec"} <= set(bind["Options"]),
                        "Sealed inspected binding protections differ")
        pid = item["State"]["Pid"]
        require(type(pid) is int and pid > 1, "Inspected container has no live observer PID")
        request = {"bindings": {target: [str(source), bindings[target]["RW"]]
                                for target, source in expected.items()},
                   "protected": [str(path) for path in protected]}
        result = host("/usr/bin/python3", "-IB", str(path), str(pid),
                      input_data=json.dumps(request).encode("ascii"))
        anchor = json.loads(result.stdout)
        (still_running,) = inspect(item["Id"])
        require(still_running["Id"] == item["Id"] and still_running["State"]["Running"] is True
                and still_running["State"]["Pid"] == pid
                and still_running["State"]["StartedAt"] == item["State"]["StartedAt"],
                "Container identity changed across its kernel observation")
        anchors.append(anchor)
    return anchors


WIRE = """
import http.client, json, sys
request = json.load(sys.stdin)
handle = http.client.HTTPConnection(request['host'], request['port'], timeout=3)
auth = {'Authorization': 'Bearer ' + request['token'], 'Content-Type': 'application/json',
        'Host': '127.0.0.1:8401'}
status, data, timed_out, pre_header_refused = None, b'', False, False
try:
    handle.request(request['method'], request['path'], body=request['body'], headers=auth)
    response = handle.getresponse()
    status = response.status
    try:
        data = response.read(65536)
    except http.client.IncompleteRead as failure:
        data = failure.partial
    except TimeoutError:
        timed_out = True
    except (OSError, http.client.HTTPException):
        pass
except TimeoutError:
    timed_out = True
except (ConnectionRefusedError, ConnectionResetError, http.client.RemoteDisconnected):
    pre_header_refused = True
except (OSError, http.client.HTTPException):
    pass
finally:
    handle.close()
receipt = {'status': status, 'body': data.decode(errors='replace')}
if request.get('report_transport', False):
    receipt.update(timed_out=timed_out, pre_header_refused=pre_header_refused)
print(json.dumps(receipt))
"""


def wire(runner, token, *, body=None, target="127.0.0.1", port=PORT, report_transport=False):
    data = json.dumps({"host": target, "port": port, "token": token, "report_transport": report_transport,
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


def verify_outside_candidates(host_runner, sibling_runner, addresses):
    for target in ("127.0.0.1", *addresses):
        require(not tcp_connect(host_runner, target, PORT), "The guest host connected to a measured IPv4 relay candidate")
        require(not tcp_connect(sibling_runner, target, PORT),
                "An independently networked container connected to a measured IPv4 relay candidate")


def broker_exchange(path, packet):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(4)
        client.connect(str(path))
        client.sendall(packet)
        received = bytearray()
        while True:
            try:
                chunk = client.recv(4096)
            except ConnectionResetError:
                break
            if not chunk:
                break
            received.extend(chunk)
            require(len(received) <= 4096, "Direct broker control exceeded the expected response bound")
        return bytes(received)


def verify_direct_broker(scratch, token):
    path = scratch / "provider/provider.sock"
    with (scratch / "proof/relay").open("rb") as stream:
        actual = stream.read(PROOF_SIZE + 1)
    require(len(actual) == PROOF_SIZE, "Missing private relay proof for the framed control")
    wrong = bytes((actual[0] ^ 1,)) + actual[1:]
    raw = (f"GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n"
           f"Authorization: Bearer {token}\r\n\r\n").encode("ascii")
    payload = REQUEST_LENGTH.pack(len(raw)) + raw
    require(broker_exchange(path, PROOF_PREFIX + actual + payload) == format_models_response((MODEL,)),
            "The framed private relay control did not reach the admitted model route")
    require(broker_exchange(path, PROOF_PREFIX + wrong + payload) == b"",
            "Direct broker client with wrong relay proof received a response")


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
    verify_outside_candidates(host, outside, addresses)
    require(not tcp_connect(runner, "192.0.2.1", 443),
            "The worker had direct egress in the sealed offline guest")
    direct_offset = len(events())
    verify_direct_broker(scratch, token)
    require(len(events()) == direct_offset, "The direct framed controls reached the synthetic upstream")
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


def confirm_foreground(terminal, *, approve):
    prompt = "Start interactive OpenCode session for instance 'default'? [y/N]"
    screen = terminal.await_screen(lambda page: any(line.strip() == prompt for line in page.splitlines()),
                                   "the exact foreground launch confirmation")
    lines = [line.strip() for line in screen.splitlines()]
    provider = (f"Provider openai/{LABEL} [{PROVIDER}]: auth=subscription, "
                f"policy=subscription (no verified spending ceiling) (models: {MODEL})")
    launch = f"Initial active model: {PROVIDER}/{MODEL} | UI: OpenCode (default) | Workspace: {WORKSPACE}"
    require([line for line in lines if line.startswith("Provider ")] == [provider]
            and [line for line in lines if line.startswith("Initial active model:")] == [launch]
            and any(line.startswith("No API-key fallback will be forwarded.") for line in lines),
            "Foreground route, billing, model or workspace differs from the approved launch")
    require([line for line in lines if line.endswith("[y/N]")] == [prompt],
            "An unapproved foreground confirmation was displayed")
    assert_no_slot()
    terminal.type_line("y" if approve else "n")


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


@contextmanager
def launch_terminal_scratch(native):
    if not native:
        with tempfile.TemporaryDirectory(prefix="oc-tools-tty-") as temporary:
            yield Path(temporary)
        return
    root = Path(tempfile.mkdtemp(prefix="oc-tools-tty-"))
    identity = root.lstat()
    try:
        yield root
    except BaseException as primary:
        primary.add_note(f"Private sealed terminal scratch retained at {root}")
        raise
    else:
        require(os.path.samestat(identity, root.lstat()), "Sealed terminal scratch changed before cleanup")
        shutil.rmtree(root)


def launch(state, case, verify_active=None, *, verify_inventory=None):
    offset = len(events())
    before = scratch_roots()
    native = case in SEALED_CASES
    result = None
    held_stream_closed = held_exit_attempted = False

    def mark_held_stream_closed():
        nonlocal held_stream_closed
        held_stream_closed = True

    with launch_terminal_scratch(native) as temporary, launch_authority(state, case) as register:
        env = {**TERM_ENV, "CONTAINER_ID": os.environ.get("CONTAINER_ID", "")}
        terminal = Terminal(temporary, env, allow_autostart=False) if native else Terminal(temporary, env)
        failure = server = None

        def await_held_exit():
            nonlocal held_exit_attempted
            held_exit_attempted = True
            terminal.await_screen(lambda screen: re.search(r"(?m)^Fixture exit [0-9]{1,3}\r?$", screen),
                                  "natural held launcher exit", timeout=45, history=False)

        try:
            if native:
                server = terminal.launch_server()
                terminal.await_server(server)
            terminal.start(str(PROJECTED_TREE / "oc-sandbox"), width=160)
            register(int(terminal.run("display-message", "-p", "-t", "stock", "#{pane_pid}")))
            confirm_foreground(terminal, approve=case != "decline")
            if case == "decline":
                terminal.await_screen(lambda screen: "Fixture exit" in screen, "the foreground decline")
                require(not any(entry["op"] == "generation" for entry in events()[offset:]),
                        "Declined launcher reached synthetic generation")
            else:
                terminal.await_screen(lambda screen: "Ask anything" in screen, "the actual stock input")
                terminal.run("resize-window", "-t", "stock", "-x", "104", "-y", "38")
                (worker,), (relay,) = owned()
                token, scratch = verify_isolation(worker, relay)
                if case in SEALED_CASES:
                    pinned = verify_kernel_isolation(worker, relay, scratch, case)
                if case == "held":
                    result = verify_active(terminal, worker["Id"], token, scratch, offset,
                                           on_held_closed=mark_held_stream_closed)
                    require(held_stream_closed and result in ("exact-worker-removed", "stale-access-refused"),
                            "Missing held retirement evidence")
                    await_held_exit()
                else:
                    verify_active(terminal, worker["Id"], token, scratch, offset)
                if case in SEALED_CASES:
                    require(verify_kernel_isolation(worker, relay, scratch, case) == pinned,
                            "Live mount namespace changed across the native tool case")
                if case != "held":
                    terminal.run("send-keys", "-t", "stock", "C-c", "C-c")
                    terminal.await_screen(lambda screen: "Fixture exit" in screen, "launcher cleanup")
        except BaseException as error:
            failure = error
            raise
        finally:
            def stop_terminal_server():
                if native:
                    terminal.stop_server(server)
                else:
                    terminal.run("kill-server", check=False)

            def stop_terminal():
                try:
                    if failure is not None:
                        if held_stream_closed:
                            # The last slot's broker observed revocation and closed the held stream.
                            # Let the measured owner finish lease and scratch retirement before closing tmux.
                            if not held_exit_attempted:
                                await_held_exit()
                        else:
                            terminal.run("send-keys", "-t", "stock", "C-c", "C-c", check=False)
                            terminal.await_screen(lambda screen: "Fixture exit" in screen, "failed launch retirement",
                                                  timeout=8)
                finally:
                    stop_terminal_server()

            def verify_peer_retirement():
                await_retired(offset)
                if case == "held":
                    verify_held_peer_counts(events()[offset:])

            actions = [stop_terminal, assert_no_slot, verify_peer_retirement,
                       lambda: verify_scratch_retirement(before)]
            if verify_inventory is not None:
                actions.append(verify_inventory)
            run_cleanup(failure, *actions)
    return result


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


def verify_stale_access(worker, token):
    require(type(worker) is str and WORKER_ID.fullmatch(worker), "Unqualified retired worker identity")
    deadline = time.monotonic() + 5

    def remaining():
        available = deadline - time.monotonic()
        require(available > 0, "Could not verify exact worker removal before the deadline")
        return available

    def worker_exists():
        result = podman("container", "exists", worker, check=False, timeout=remaining())
        remaining()
        require(type(result.returncode) is int and result.returncode in (0, 1),
                "Unexpected Podman status while checking the exact retired worker")
        return result.returncode == 0

    if not worker_exists():
        return "exact-worker-removed"
    # Allow teardown a brief head start before sending any stale request.
    time.sleep(min(.15, remaining()))
    if not worker_exists():
        return "exact-worker-removed"

    def stale_runner(*args, **kwargs):
        return run_worker(worker, *args, timeout=remaining(), **kwargs)

    try:
        reply = wire(stale_runner, token, body=ordinary_body(), report_transport=True)
    except subprocess.CalledProcessError:
        # A failed exec says nothing about broker access. Only independent exact
        # removal can satisfy this branch. Never send the stale request again.
        while worker_exists():
            time.sleep(min(.05, remaining()))
        return "exact-worker-removed"
    else:
        remaining()
        status = reply["status"]
        require(reply["timed_out"] is False, "Stale worker bearer probe timed out")
        if status is None:
            require(reply["pre_header_refused"] is True, "Unverified stale worker transport refusal")
        else:
            require(type(status) is int and status in (401, 403), "Retired worker bearer retained access")
        return "stale-access-refused"


def retirement(terminal, worker, token, scratch, offset, *, on_held_closed):
    require(type(worker) is str and WORKER_ID.fullmatch(worker), "Unqualified held worker identity")
    worker_data, = inspect(worker)
    require(worker_data["Id"] == worker, "Held worker inspection returned another container")
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
        on_held_closed()
        proof = verify_stale_access(worker, token)
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
    verify_held_peer_counts(observed)
    return proof


def verify_held_peer_counts(observed):
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


def worker_config_location():
    (volume,) = json.loads(podman("volume", "inspect", "oc-openai-home").stdout)
    root = Path(volume["Mountpoint"])
    require(volume["Name"] == "oc-openai-home" and root.resolve(strict=True) == root
            and root.is_relative_to(TEST_HOME / ".local/share/containers/storage/volumes")
            and root.stat().st_uid == os.getuid(), "Could not locate the owned synthetic worker home")
    return root / ".config/opencode/opencode.json"


def read_owned_file(path, limit):
    with os.fdopen(private_file(path, os.O_RDONLY), "rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Sealed fixture evidence exceeded its bound")
    return data


def bounded_usage():
    path = STATE / USAGE_LOG_NAME
    try:
        fd = private_file(path, os.O_RDONLY)
    except FileNotFoundError:
        return b""
    with os.fdopen(fd, "rb") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return None
        data = stream.read(USAGE_LOG_LIMIT + 1)
        require(len(data) <= USAGE_LOG_LIMIT and os.path.samestat(os.fstat(fd), path.lstat()),
                "Sealed broker usage journal changed during its bounded read")
        return data


def usage_delta(previous, current):
    require(type(current) is bytes and current.startswith(previous)
            and (not previous or previous.endswith(b"\n")) and (not current or current.endswith(b"\n")),
            "Sealed broker usage journal changed or has an incomplete row")
    return [decode_json(row) for row in current[len(previous):].split(b"\n")[:-1]]


def await_usage_acknowledgement(previous, count, *, refused=False, timeout=8):
    deadline = time.monotonic() + timeout
    seen = previous
    while time.monotonic() < deadline:
        current = bounded_usage()
        if current is not None:
            require(current.startswith(seen), "Sealed broker usage journal changed while awaiting acknowledgement")
            if usage_sequence_complete(usage_delta(previous, current), count, refused=refused):
                return current
            seen = current
        time.sleep(.05)
    raise RuntimeError("Sealed broker usage did not settle before launcher teardown")


def verify_retired_usage(previous, acknowledged, count, *, refused=False):
    usage = bounded_usage()
    require(acknowledged is not None and usage == acknowledged, "Sealed broker usage changed after acknowledgement")
    verify_usage(usage_delta(previous, usage), count, refused=refused)


def verify_search_control():
    data = read_owned_file(SEARCH_SENTINEL, 128)
    require(SEARCH_SENTINEL.parent.resolve(strict=True) == SEARCH_SENTINEL.parent and data == SEARCH_SENTINEL_BYTES,
            "Controller search positive control differs")
    verify_search_control_match(SEARCH_SENTINEL.name, data)


def prepare_search():
    job = SANDBOX / SEARCH_JOB.relative_to("/sandbox")
    job.mkdir(mode=0o700)
    setup_search(job)
    private_write(SEARCH_SENTINEL, SEARCH_SENTINEL_BYTES.decode("ascii"))
    verify_search_control()
    config = worker_config_location()
    require(config.resolve() == config, "Worker-local config would resolve through another source")
    private_write(config, json.dumps(TITLE_SETTINGS))
    return job


def await_native_export(worker, existing, predicate):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        found = set(stock_sessions(worker)) - existing
        require(len(found) <= 1, "Stock created extra sealed conversations")
        if found:
            (session,) = found
            exported = export_stock(worker, session)
            if exported["messages"] and predicate(exported):
                return exported
        time.sleep(.1)
    raise RuntimeError("The exact fresh sealed stock conversation did not reach its expected state")


def verify_worker_title_settings(worker):
    raw = run_worker(worker, "/bin/cat", "/root/.config/opencode/opencode.json").stdout
    require(json.loads(raw) == TITLE_SETTINGS, "Worker-local title setting is unqualified")


def sealed_records(case):
    with os.fdopen(private_file(journal_path(TEST_HOME, case), os.O_RDONLY), "rb") as stream:
        return read_journal(stream, case)


def run_sealed_search(state, case, job, verify_inventory):
    script = scenario(case, TEST_HOME)
    before = search_inventory(job)
    verify_search_control()
    previous_usage = bounded_usage()
    require(previous_usage is not None, "Sealed broker usage busy before launch")
    acknowledged = None
    offset = len(events())
    exported = []
    journal = journal_path(TEST_HOME, case)
    private_write(journal, json.dumps({"case": case, "run": secrets.token_hex(16)}) + "\n")

    def active(terminal, worker, _token, _scratch, _offset):
        nonlocal acknowledged
        verify_worker_title_settings(worker)
        existing = set(stock_sessions(worker))
        terminal.type_line(script.prompt)
        terminal.await_screen(lambda page: any(line.strip(" │┃▏●") == script.reply for line in page.splitlines()),
                              "the sealed search reply", timeout=90)
        exported.append(await_native_export(worker, existing, lambda value: value["messages"][-1]["type"] == "idle"))
        acknowledged = await_usage_acknowledgement(previous_usage, 3)

    launch(state, case, active, verify_inventory=verify_inventory)
    run, rows = sealed_records(case)
    claims, submissions = verified_rows(rows)
    observed = events()[offset:]
    receipts = [entry["details"] for entry in observed if entry["op"] == "sealed_submission"]
    require(len(claims) == len(submissions) == 3 and receipts == [{"case": case, "stage": n} for n in range(3)]
            and not any(entry["op"] in {"title", "generation"} for entry in observed),
            "Sealed search peer did not record three linked submissions and zero title writes")
    transcript, = exported
    script.verify_export(transcript, run, claims[0]["session"])
    verify_retired_usage(previous_usage, acknowledged, 3)
    require(search_inventory(job) == before, "Sealed job search source inventory changed")
    verify_search_control()
    return {"case": case, "claims": len(claims), "peer_submissions": len(submissions), "broker_verified_completions": 3, "title_writes": 0,
            "kernel_mounts_verified": True, "controller_positive_control": True, "job_inventory_unchanged": True}


def verify_skill_control():
    require(CONTROLLER_SKILL.resolve(strict=True) == CONTROLLER_SKILL
            and read_owned_file(CONTROLLER_SKILL, 512) == CONTROLLER_SKILL_BYTES,
            "Controller skill positive control differs")


def replace_worker_config(before, after):
    config = worker_config_location()
    require(config.resolve(strict=True) == config and json.loads(read_owned_file(config, 2048)) == before,
            "Worker skill configuration did not match the owned previous version")
    atomic_write(config, json.dumps(after).encode("ascii"))


def prepare_interaction():
    cfg = worker_config_location()
    skill = cfg.parents[2] / WORKER_SKILL.relative_to("/root")
    require(skill.resolve() == skill and not skill.parent.parent.exists(), "Dedicated worker has preexisting skills")
    private_write(skill, SKILL_BYTES.decode("ascii"))
    require(CONTROLLER_SKILL.resolve() == CONTROLLER_SKILL and not CONTROLLER_SKILL.parent.parent.exists(),
            "Dedicated controller has preexisting skills")
    private_write(CONTROLLER_SKILL, CONTROLLER_SKILL_BYTES.decode("ascii"))
    verify_skill_control()
    replace_worker_config(TITLE_SETTINGS, interaction_config("sealed-skill"))


def verify_worker_skill(worker, case):
    config = run_worker(worker, "/bin/cat", "/root/.config/opencode/opencode.json").stdout
    require(json.loads(config) == interaction_config(case), "Sealed worker skill config differs")
    root = str(WORKER_SKILL.parent.parent)
    inventory = run_worker(worker, "find", root, "-print").stdout.decode().splitlines()
    require(sorted(inventory) == sorted((root, str(WORKER_SKILL.parent), str(WORKER_SKILL))),
            "Unexpected worker-local skill inventory")
    require(run_worker(worker, "test", "!", "-L", str(WORKER_SKILL), check=False).returncode == 0
            and run_worker(worker, "/bin/cat", str(WORKER_SKILL)).stdout == SKILL_BYTES,
            "Worker-local skill source changed")


def drive_sealed_question(terminal, worker, existing, script, offset):
    terminal.await_screen(question_screen, "the current native question", history=False)
    pending = await_native_export(worker, existing, lambda value: [m["type"] for m in value["messages"]] == ["user"])
    user, = pending["messages"]
    config = pending["info"]
    model = config["model"]
    session = config["id"]
    require(model["id"] == MODEL and model["providerID"] == PROVIDER and user["text"] == script.prompt
            and not user["files"] and not user["agents"], "Pending sealed question belongs to another stock chat")
    target = journal_path(TEST_HOME, script.case)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with os.fdopen(private_file(target, os.O_RDWR), "r+b", buffering=0) as ledger:
            try:
                fcntl.flock(ledger, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                time.sleep(.05)
                continue
            run, rows = read_journal(ledger, script.case)
            claims, submissions = verified_rows(rows)
            if not submissions:
                time.sleep(.05)
                continue
            receipts = [event["details"] for event in events()[offset:] if event["op"] == "sealed_submission"]
            require(len(rows) == 2 and len(claims) == len(submissions) == 1 and claims[0]["session"] == session
                    and receipts == [{"case": script.case, "stage": 0}]
                    and question_screen(terminal.run("capture-pane", "-p", "-t", "stock")),
                    "Sealed question already continued or is outside its pending native dialog")
            decision = script.operator(run, session)
            terminal.run("send-keys", "-t", "stock", decision["key"])
            append_row(ledger, target, decision)
            break
    else:
        raise RuntimeError("Pending sealed question lacks its exact peer submission receipt")
    if script.cancellation:
        terminal.await_screen(lambda screen: "interrupted" in screen and not question_screen(screen),
                              "the interrupted native question", history=False)


def run_sealed_interaction(state, case, verify_inventory):
    script = scenario(case, TEST_HOME)
    count = 1 if script.cancellation or script.missing_skill else 2
    verify_skill_control()
    previous_usage = bounded_usage()
    require(previous_usage is not None, "Sealed broker usage busy before launch")
    acknowledged = None
    offset = len(events())
    exported = []
    private_write(journal_path(TEST_HOME, case), json.dumps({"case": case, "run": secrets.token_hex(16)}) + "\n")

    def active(terminal, worker, _token, _scratch, _offset):
        nonlocal acknowledged
        verify_worker_skill(worker, case)
        existing = set(stock_sessions(worker))
        terminal.type_line(script.prompt)
        if script.question:
            drive_sealed_question(terminal, worker, existing, script, offset)
        if not script.cancellation and not script.missing_skill:
            terminal.await_screen(lambda page: any(line.strip(" │┃▏●") == script.reply for line in page.splitlines()),
                                  "the exact sealed interaction reply", timeout=90)
        def complete(value):
            last = value["messages"][-1]
            return (last.get("finish") == "error" and last.get("error", {}).get("type") == "aborted"
                    if script.cancellation else last["type"] == "idle")
        exported.append(await_native_export(worker, existing, complete))
        verify_worker_skill(worker, case)
        acknowledged = await_usage_acknowledgement(previous_usage, count, refused=script.missing_skill)

    launch(state, case, active, verify_inventory=verify_inventory)
    run, rows = sealed_records(case)
    claims, submissions = verified_rows(rows)
    observed = events()[offset:]
    receipts = [entry["details"] for entry in observed if entry["op"] == "sealed_submission"]
    refused = [entry["details"] for entry in observed if entry["op"] == "sealed_refusal"]
    require(len(claims) == len(submissions) == count and receipts == [{"case": case, "stage": n} for n in range(count)]
            and refused == ([{"case": case}] if script.missing_skill else [])
            and not any(entry["op"] in {"title", "generation"} for entry in observed), "Unexpected sealed interaction writes")
    if script.question:
        require([row for row in rows if row["op"] == "operator"] == [script.operator(run, claims[0]["session"])],
                "Wrong sealed operator receipt")
    transcript, = exported
    script.verify_export(transcript, run, claims[0]["session"])
    verify_retired_usage(previous_usage, acknowledged, count, refused=script.missing_skill)
    verify_skill_control()
    result = {"case": case, "claims": count, "peer_submissions": count, "broker_verified_completions": count, "refused_broker_requests": len(refused),
              "title_writes": 0, "kernel_mounts_verified": True, "known_controller_skill": True}
    if case == "sealed-skill":
        result["skill_source_sha256"] = hashlib.sha256(SKILL_BYTES).hexdigest()
    return result


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
    held_retirement = launch(state, "held", retirement, verify_inventory=stable_inventory)
    search_job = prepare_search()
    native_search = [run_sealed_search(state, case, search_job, stable_inventory) for case in SEARCH_CASES]
    prepare_interaction()
    worker_config = interaction_config("sealed-skill")
    native_interaction = []
    for case in INTERACTION_CASES:
        expected_config = interaction_config(case)
        if expected_config != worker_config:
            replace_worker_config(worker_config, expected_config)
            worker_config = expected_config
        native_interaction.append(run_sealed_interaction(state, case, stable_inventory))
    print(json.dumps({"source_sha256": state.source_sha256, "projection_sha256": state.projection_sha256,
                      "stock_binary_sha256": STOCK_SHA256, "model": f"{PROVIDER}/{MODEL}",
                      "stock_session": "patch/read/shell completed", "continuations": 3, "sealed_search": native_search,
                      "sealed_interaction": native_interaction, "held_retirement": held_retirement,
                      "inventory": after_decline}, sort_keys=True))


if __name__ == "__main__":
    main()
