"""Start and verify the two disposable containers for the offline text proof."""

import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time

from .protocol import MODEL, PORT, PROMPT, RecordingFake


OPEN_CODE = "edc96b3f8ef46d2309577c259167813fc943edd6e344db08848e48ec3ed4f278"
RELAY = "2893cf9f584f34cfa2d0b8dd6ba9e63dfacd1e1105a304bb4f72317b00f89029"
LABEL = "io.oc-sandbox.orchestrator-proof"
FULL_ID = re.compile(r"[0-9a-f]{64}")
SECURITY_LABEL = re.compile(r"[^:]+:[^:]+:container_t:(s0:c\d+,c\d+)")
TMPFS = "rw,nosuid,nodev,noexec,mode=0700"
ALLOWED_IMAGE_ENV = {
    OPEN_CODE: {"PATH", "BUN_RUNTIME_TRANSPILER_CACHE_PATH"},
    RELAY: {"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256", "PYTHONDONTWRITEBYTECODE"},
}


class Failure(RuntimeError):
    """Redacted verification error for the operator."""


def host(program, *args, timeout=12, check=True):
    uid = os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    bus = f"/run/user/{uid}/bus"
    env = {"PATH": "/usr/bin:/bin", "HOME": home, "LC_ALL": "C",
           "XDG_RUNTIME_DIR": f"/run/user/{uid}", "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}"}
    command = ["/usr/bin/host-spawn", "--no-pty", "--env=", "/usr/bin/env", "-i",
               *(f"{key}={value}" for key, value in env.items()), "/usr/bin/timeout", "--kill-after=1s",
               f"{timeout}s", f"/usr/bin/{program}", *args]
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/host{bus}"
    try:
        result = subprocess.run(command, env=env, cwd="/", stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout + 4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(f"host {program} unavailable or timed out") from None
    if result.returncode and check:
        raise Failure(f"host {program} {args[0]} did not complete ({result.returncode})")
    return result


def podman(*args, **options):
    check = options.pop("check", True)
    result = host("podman", "--remote=false", "--default-mounts-file=/dev/null", *args, check=False, **options)
    if check and result.returncode:
        raise Failure(f"Podman {args[0]} did not complete ({result.returncode})")
    return result


def inspect(kind, identity):
    result = json.loads(podman(kind, "inspect", identity).stdout)
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise Failure("unexpected Podman inspection receipt")
    return result[0]


def preflight(root):
    uid = os.getuid()
    bridge = Path("/usr/bin/host-spawn").lstat()
    info = root.lstat()
    top = root.parent.lstat()
    if (not uid or root.parent != Path("/tmp") or not stat.S_ISDIR(top.st_mode) or not top.st_mode & stat.S_ISVTX
            or not stat.S_ISREG(bridge.st_mode) or bridge.st_uid != 0 or bridge.st_mode & 0o022
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700):
        raise Failure("unsafe host bridge or scratch path")
    if (host("id", "-ru").stdout.strip() != str(uid).encode()
            or host("cat", "/sys/fs/selinux/enforce").stdout.strip() != b"1"
            or host("cat", "/proc/sys/crypto/fips_enabled").stdout.strip() != b"0"
            or podman("info", "--format", "{{.Host.Security.Rootless}} {{.Host.Security.SELinuxEnabled}} {{.Host.CgroupsVersion}}").stdout.strip()
            != b"true true v2"):
        raise Failure("requires the qualified rootless SELinux host")
    for directory, entry, owner in ((root, info, uid), (root.parent, top, 0)):
        expected = f"{entry.st_dev}:{entry.st_ino}:{owner}:{entry.st_mode:x}".encode()
        if host("stat", "-c", "%d:%i:%u:%f", "--", str(directory)).stdout.strip() != expected:
            raise Failure("host and devbox do not share the private scratch path")


def environment(entries):
    fields = dict(item.split("=", 1) for item in entries)
    if len(fields) != len(entries):
        raise Failure("duplicate image environment key")
    return fields


def config():
    deny_tools = [{"action": "*", "resource": "*", "effect": "deny"}]
    return {"model": f"local/{MODEL}", "update": "disable", "snapshots": False,
            "defaultAgent": "offline", "permissions": deny_tools,
            "plugins": ["-opencode.tool.*"],
            "agents": {"offline": {"mode": "primary", "permissions": deny_tools},
                       **{name: {"disabled": True} for name in ("build", "plan", "general", "explore", "title", "summary", "compaction")}},
            "policies": [{"action": "provider.use", "resource": "*", "effect": "deny"},
                         {"action": "provider.use", "resource": "local", "effect": "allow"},
                         {"action": "integration.connect", "resource": "*", "effect": "deny"}],
            "providers": {"local": {"name": "Offline text proof",
                "package": "@opencode/ai/providers/openai-compatible",
                "settings": {"baseURL": f"http://127.0.0.1:{PORT}/v1", "apiKey": "offline-fixture"},
                "models": {MODEL: {"name": "Offline text", "capabilities": {"tools": False,
                   "input": ["text"], "output": ["text"]}, "limit": {"context": 65536, "output": 2048}}}}}}


class Placement:
    """Verify the pinned container settings and remove only this launch's resources."""

    def __init__(self, root):
        self.root = root
        self.label = secrets.token_hex(16)
        self.names = {role: f"oc-orch-{self.label}-{role}" for role in ("open-code", "relay")}
        self.ids = {}
        self.attempted = False

    def create(self, role, image, network, source, target, env, tmpfs, executable, *args):
        image_data = inspect("image", image)
        inherited = environment(image_data["Config"].get("Env") or [])
        if image_data["Id"].removeprefix("sha256:") != image or inherited.keys() - ALLOWED_IMAGE_ENV[image]:
            raise Failure("unexpected pinned image identity or environment")
        memory = "1g" if image == OPEN_CODE else "128m"
        command = ["create", "--pull=never", "--network", network, "--name", self.names[role],
                   "--label", f"{LABEL}={self.label}", "--http-proxy=false", "--user=0:0", "--cap-drop=all",
                   "--security-opt=no-new-privileges", "--read-only", "--read-only-tmpfs=false",
                   "--image-volume=ignore", "--log-driver=none", "--restart=no", "--pids-limit=192",
                   "--ipc=private", "--pid=private", "--cgroupns=private", "--memory", memory,
                   "--memory-swap", memory, "--entrypoint", executable,
                   "--volume", f"{source}:{target}:ro,Z,nosuid,nodev,noexec"]
        for name, value in env.items():
            command.extend(("--env", f"{name}={value}"))
        for path in tmpfs:
            command.extend(("--tmpfs", f"{path}:{TMPFS},size=96m"))
        self.attempted = True
        identifier = podman(*command, image, *args).stdout.decode("ascii").strip()
        if not FULL_ID.fullmatch(identifier):
            raise Failure("missing immutable container ID")
        self.ids[role] = identifier
        data = self.identity(identifier, role)
        self.verify(data, image, network, source, target, inherited | env | {"container": "podman"}, tmpfs)
        podman("start", identifier)
        return identifier

    def identity(self, identifier, role):
        data = inspect("container", identifier)
        if (data["Id"] != identifier or data["Name"].removeprefix("/") != self.names[role]
                or data["Config"]["Labels"].get(LABEL) != self.label):
            raise Failure("container identity did not match its launch")
        return data

    @staticmethod
    def verify(data, image, network, source, target, env, tmpfs):
        host_config = data["HostConfig"]
        networks = data["NetworkSettings"]
        settings = data["Config"]
        memory = 1024**3 if image == OPEN_CODE else 128 * 1024**2
        isolation = {"IpcMode": "private", "PidMode": "private", "CgroupMode": "private",
                     "NetworkMode": network, "ReadonlyRootfs": True, "PidsLimit": 192,
                     "Memory": memory, "MemorySwap": memory}
        if (any(host_config.get(key) != value for key, value in isolation.items())
                or any(host_config.get(key) for key in ("PortBindings", "PublishAllPorts", "Privileged", "CapAdd", "Devices"))
                or data.get("EffectiveCaps") or networks.get("Ports") or settings.get("ExposedPorts")
                or set(networks.get("Networks") or {}) != {"none"} or settings.get("User") != "0:0"
                or host_config.get("SecurityOpt") != ["no-new-privileges"]
                or data["Image"].removeprefix("sha256:") != image
                or environment(settings["Env"]) != env
                or set(host_config.get("Tmpfs") or {}) != set(tmpfs)):
            raise Failure("container settings did not match the restricted placement")
        mount, = data["Mounts"]
        if (mount.get("Type") != "bind" or mount.get("RW") is not False or mount.get("Source") != str(source)
                or mount.get("Destination") != target or mount.get("Mode") != "Z" or mount.get("Propagation") != "rprivate"
                or not {"nosuid", "nodev", "noexec"} <= set(mount.get("Options") or ())):
            raise Failure("unexpected container mount")

    def verify_pair(self, worker, relay):
        labels = [self.identity(cid, role)["ProcessLabel"] for role, cid in self.ids.items()]
        if not all(SECURITY_LABEL.fullmatch(label or "") for label in labels) or len(set(labels)) != 2:
            raise Failure("OpenCode and relay SELinux labels are not distinct")
        for kind in ("net", "pid", "ipc", "cgroup"):
            path = "/proc/self/ns/" + kind
            worker_ns = podman("exec", worker, "/usr/bin/readlink", path).stdout.strip()
            relay_ns = podman("exec", relay, "/usr/local/bin/python3", "-IB", "-c",
                              "import os, sys; print(os.readlink(sys.argv[1]))", path).stdout.strip()
            if ((worker_ns == relay_ns) != (kind == "net")
                    or host("readlink", path).stdout.strip() in (worker_ns, relay_ns)):
                raise Failure(f"unexpected {kind} namespace placement")
        podman("exec", worker, "/bin/sh", "-ec",
               'test ! -e /fixture && test ! -e /sandbox && test ! -e /run/host && test ! -e /run/user'
               ' && test ! -e /var/run/docker.sock && test ! -e "$1"', "fixture", pwd.getpwuid(os.getuid()).pw_dir)
        podman("exec", relay, "/bin/sh", "-ec", 'test -S /fixture/provider.sock && test -r /fixture/proof')

    def close(self):
        if not self.attempted:
            return
        selector = f"label={LABEL}={self.label}"
        items = podman("ps", "--all", "--no-trunc", "--filter", selector, "--format", "{{.ID}} {{.Names}}").stdout.splitlines()
        owned = {}
        for row in items:
            identity, name = row.decode("ascii").split()
            role = next((key for key, expected in self.names.items() if expected == name), None)
            if role is None or role in owned or not FULL_ID.fullmatch(identity) or self.ids.get(role, identity) != identity:
                raise Failure("cleanup could not identify all owned containers")
            self.identity(identity, role)
            owned[role] = identity
        for role in ("relay", "open-code"):
            if role in owned:
                podman("rm", "--force", "--time", "1", "--ignore", owned[role])
        if podman("ps", "--all", "--filter", selector, "--quiet").stdout.strip():
            raise Failure("cleanup left a container")


def seeds(root):
    worker = root / "worker"
    relay = root / "relay"
    worker.mkdir(mode=0o700)
    relay.mkdir(mode=0o700)
    (worker / "opencode.json").write_text(json.dumps(config()))
    shutil.copyfile(Path(__file__).with_name("relay.py"), relay / "relay.py")
    proof = secrets.token_bytes(32)
    (relay / "proof").write_bytes(proof)
    return worker, relay, proof


def run_open_code(worker):
    if podman("exec", worker, "opencode", "--version").stdout.strip() != b"opencode v2.3.0":
        raise Failure("unexpected OpenCode version")
    project = config()
    project["providers"]["local"]["settings"]["baseURL"] = "http://127.0.0.1:9/v1"
    podman("exec", worker, "/bin/sh", "-ec", 'printf %s "$1" > /workspace/opencode.json',
           "fixture", json.dumps(project))
    wire = podman("exec", "--workdir", "/workspace", worker, "opencode", "run", "--format", "json", "--agent", "offline",
                  "--model", f"local/{MODEL}", PROMPT, timeout=65).stdout
    if len(wire) > 256 * 1024:
        raise Failure("OpenCode event output exceeded its bound")
    events = [json.loads(line) for line in wire.splitlines() if line.strip()]
    if not events or any(event.get("type") not in {"step_start", "text", "step_finish"} for event in events):
        raise Failure("OpenCode emitted an unexpected event")
    result = "".join(event["part"]["text"] for event in events if event["type"] == "text")
    if result != "ok" or events[-1].get("type") != "step_finish":
        raise Failure("OpenCode did not complete the exact text proof")


def wait_relay(relay):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        rows = podman("exec", relay, "/usr/local/bin/python3", "-IB", "-c",
                      "print(open('/proc/net/tcp').read(), end='')").stdout.splitlines()[1:]
        if any(row.split()[1] == f"0100007F:{PORT:04X}".encode() and row.split()[3] == b"0A" for row in rows):
            return
        time.sleep(0.05)
    raise Failure("the private relay did not listen")


def run_proof(mode):
    if mode != "distrobox":
        raise Failure("the offline check currently requires the qualified devbox placement")
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="oc-orch-", dir="/tmp"))
    placement = Placement(root)
    try:
        preflight(root)
        worker_files, relay_files, proof = seeds(root)
        with RecordingFake(relay_files / "provider.sock", proof) as broker:
            worker = placement.create("open-code", OPEN_CODE, "none", worker_files / "opencode.json",
                                      "/etc/opencode/opencode.json", {"HOME": "/job-home", "TMPDIR": "/job-tmp",
                                      "XDG_CONFIG_HOME": "/job-home/config", "OPENCODE_CONFIG_PROJECT_DISABLE": "true"},
                                      ("/job-home", "/job-tmp", "/workspace"), "/bin/sh", "-c", "exec sleep 90")
            relay = placement.create("relay", RELAY, f"container:{worker}", relay_files, "/fixture", {}, (),
                                     "/usr/local/bin/python3", "-IB", "/fixture/relay.py")
            placement.verify_pair(worker, relay)
            wait_relay(relay)
            run_open_code(worker)
            if broker.admissions != 1 or broker.refusals or broker.settlement != "recorded_offline":
                raise Failure("the recording fake did not observe exactly one text-only send")
    finally:
        placement.close()
        shutil.rmtree(root)
