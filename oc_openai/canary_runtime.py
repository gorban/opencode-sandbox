"""Cleanup-only detached container owner for the single-turn zero-tool ChatGPT canary.

This module intentionally has zero imports of OAuth, profile, ledger, or upstream
provider transport code. A direct invocation of ``_owner`` with synthetic pipes
is structurally incapable of making any provider request.
"""

import base64
from contextlib import suppress
import errno
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


OPEN_CODE = "edc96b3f8ef46d2309577c259167813fc943edd6e344db08848e48ec3ed4f278"
RELAY = "2893cf9f584f34cfa2d0b8dd6ba9e63dfacd1e1105a304bb4f72317b00f89029"
RELAY_PYTHON = "/usr/local/bin/python3"
CONTAINER_SHELL = "/bin/sh"
LABEL = "io.oc-sandbox.openai-canary"
PORT = 8401
PROMPT = "Reply with exactly: ok"
EXPECTED_OPENCODE_VERSION = b"opencode v2.3.0"
OUTPUT_LIMIT = 256 * 1024
FULL_ID = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
MODEL_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z", re.ASCII)
TOKEN_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
PROCESS_LABEL = re.compile(r"[^:]+:[^:]+:container_t:s0:(c\d+),(c\d+)\Z", re.ASCII)
MOUNT_LABEL = re.compile(r"[^:]+:[^:]+:container_file_t:s0:(c\d+),(c\d+)\Z", re.ASCII)
TMPFS = "rw,nosuid,nodev,noexec,mode=0700"
ALLOWED_IMAGE_ENV = {
    OPEN_CODE: frozenset({"PATH", "BUN_RUNTIME_TRANSPILER_CACHE_PATH"}),
    RELAY: frozenset({"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256", "PYTHONDONTWRITEBYTECODE"}),
}
_HOST_BRIDGE = "/usr/bin/host-spawn"


class RuntimeFailure(RuntimeError):
    """Redacted container placement or lifecycle error."""


class OwnerLost(RuntimeError):
    """Peer process died before the canary settled."""


def _kill_process_group(proc: subprocess.Popen) -> None:
    with suppress(OSError):
        os.killpg(proc.pid, signal.SIGKILL)
    with suppress(OSError):
        proc.kill()
    with suppress(OSError, subprocess.TimeoutExpired):
        proc.wait(timeout=5)


def _bounded_capture(command, *, env, timeout, limit=OUTPUT_LIMIT, lifeline=None):
    with subprocess.Popen(
        command, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    ) as proc:
        deadline = time.monotonic() + timeout
        out_buf = bytearray()
        err_buf = bytearray()
        pipes = {proc.stdout.fileno(): (proc.stdout, out_buf), proc.stderr.fileno(): (proc.stderr, err_buf)}
        for fd in pipes:
            os.set_blocking(fd, False)
        try:
            _drain_pipes(pipes, deadline, limit, lifeline)
        except BaseException:
            _kill_process_group(proc)
            raise
        rc = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        return subprocess.CompletedProcess(command, rc, bytes(out_buf), bytes(err_buf))


def _drain_pipes(pipes, deadline, limit, lifeline):
    poller = select.poll()
    for fd in pipes:
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    life_fd = lifeline.fd if lifeline is not None else None
    if life_fd is not None:
        poller.register(life_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    total = 0
    while pipes:
        if lifeline is not None:
            lifeline.check()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeFailure("host command timed out")
        events = poller.poll(min(100, int(remaining * 1000) + 1))
        for fd, _mask in events:
            if fd == life_fd:
                lifeline.check()
                continue
            stream, buf = pipes[fd]
            total = _read_pipe_fd(fd, stream, buf, pipes, poller, total, limit)


def _read_pipe_fd(fd, stream, buf, pipes, poller, total, limit):
    try:
        chunk = os.read(fd, 8192)
    except OSError as error:
        if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            return total
        chunk = b""
    if not chunk:
        poller.unregister(fd)
        pipes.pop(fd, None)
        stream.close()
        return total
    total += len(chunk)
    if total > limit:
        raise RuntimeFailure("host command exceeded output limit")
    buf.extend(chunk)
    return total


def host(program, *args, timeout=15, check=True, lifeline=None):
    uid = os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    bus = f"/run/user/{uid}/bus"
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": home,
        "LC_ALL": "C",
        "XDG_RUNTIME_DIR": f"/run/user/{uid}",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
    }
    command = [
        _HOST_BRIDGE, "--no-pty", "--env=", "/usr/bin/env", "-i",
        *(f"{k}={v}" for k, v in env.items()),
        "/usr/bin/timeout", "--kill-after=1s", f"{timeout}s",
        f"/usr/bin/{program}", *args,
    ]
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/host{bus}"
    try:
        result = _bounded_capture(command, env=env, timeout=timeout + 5, lifeline=lifeline)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeFailure(f"host {program} did not complete within bounds") from None
    if result.returncode and check:
        raise RuntimeFailure(f"host {program} failed ({result.returncode})")
    return result


def podman(*args, timeout=15, check=True, lifeline=None):
    return host(
        "podman", "--remote=false", "--default-mounts-file=/dev/null", *args,
        timeout=timeout, check=check, lifeline=lifeline,
    )


def inspect_object(kind: str, identity: str, *, lifeline=None) -> dict:
    raw = podman(kind, "inspect", identity, lifeline=lifeline).stdout
    try:
        parsed = json.loads(raw)
    except ValueError:
        raise RuntimeFailure("unexpected Podman inspect JSON") from None
    if type(parsed) is not list or len(parsed) != 1 or type(parsed[0]) is not dict:
        raise RuntimeFailure("unexpected Podman inspect receipt")
    return parsed[0]


def scratch_parent() -> Path:
    return Path("/run/user") / str(os.getuid())


def check_private_directory(directory: Path) -> None:
    uid = os.getuid()
    try:
        info = directory.lstat()
    except OSError:
        raise RuntimeFailure("unsafe private scratch directory") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeFailure("unsafe private scratch directory")
    expected = f"{info.st_dev}:{info.st_ino}:{uid}:{info.st_mode:x}".encode("ascii")
    observed = host("stat", "-c", "%d:%i:%u:%f", "--", str(directory)).stdout.strip()
    if observed != expected:
        raise RuntimeFailure("host and devbox do not share private scratch path")


def preflight_host() -> None:
    uid = os.getuid()
    try:
        bridge = Path(_HOST_BRIDGE).lstat()
    except OSError:
        raise RuntimeFailure("unsafe host bridge") from None
    if not uid or not stat.S_ISREG(bridge.st_mode) or bridge.st_uid != 0 or bridge.st_mode & 0o022:
        raise RuntimeFailure("unsafe host bridge")
    info_fmt = "{{.Host.Security.Rootless}} {{.Host.Security.SELinuxEnabled}} {{.Host.CgroupsVersion}}"
    if (host("id", "-ru").stdout.strip() != str(uid).encode("ascii")
            or host("cat", "/sys/fs/selinux/enforce").stdout.strip() != b"1"
            or host("cat", "/proc/sys/crypto/fips_enabled").stdout.strip() != b"0"
            or podman("info", "--format", info_fmt).stdout.strip() != b"true true v2"):
        raise RuntimeFailure("requires qualified rootless SELinux host")
    check_private_directory(scratch_parent())


def parse_env_list(entries: list[str]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for item in entries:
        key, sep, value = item.partition("=")
        if not sep or key in fields:
            raise RuntimeFailure("invalid or duplicate image environment key")
        fields[key] = value
    return fields


def container_categories(data: dict) -> frozenset[str]:
    proc = PROCESS_LABEL.fullmatch(data.get("ProcessLabel") or "")
    mount = MOUNT_LABEL.fullmatch(data.get("MountLabel") or "")
    if proc is None or mount is None:
        raise RuntimeFailure("invalid container SELinux labels")
    categories = frozenset(proc.groups())
    if len(categories) != 2 or categories != frozenset(mount.groups()):
        raise RuntimeFailure("container process and mount SELinux categories do not agree")
    return categories


def opencode_canary_config(model: str, worker_token: str) -> dict:
    deny_tools = [{"action": "*", "resource": "*", "effect": "deny"}]
    disabled = {
        name: {"disabled": True}
        for name in ("build", "plan", "general", "explore", "title", "summary", "compaction")
    }
    return {
        "model": f"local/{model}",
        "update": "disable",
        "snapshots": False,
        "defaultAgent": "canary",
        "permissions": deny_tools,
        "plugins": ["-opencode.tool.*"],
        "agents": {
            "canary": {"mode": "primary", "permissions": deny_tools},
            **disabled,
        },
        "policies": [
            {"action": "provider.use", "resource": "*", "effect": "deny"},
            {"action": "provider.use", "resource": "local", "effect": "allow"},
            {"action": "integration.connect", "resource": "*", "effect": "deny"},
        ],
        "providers": {
            "local": {
                "name": "ChatGPT Canary",
                "package": "@opencode/ai/providers/openai-compatible/responses",
                "settings": {
                    "baseURL": f"http://127.0.0.1:{PORT}/v1",
                    "apiKey": worker_token,
                },
                "models": {
                    model: {
                        "name": model,
                        "capabilities": {"tools": False, "input": ["text"], "output": ["text"]},
                        "limit": {"context": 65536, "output": 64},
                    },
                },
            },
        },
    }


def _write_private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        sent = 0
        while sent < len(data):
            sent += os.write(fd, view[sent:])
    finally:
        os.close(fd)


def seed_scratch(root: Path, model: str, worker_token: str) -> tuple[Path, Path, bytes]:
    worker = root / "worker"
    relay = root / "relay"
    worker.mkdir(mode=0o700)
    relay.mkdir(mode=0o700)
    os.chmod(worker, 0o700)
    os.chmod(relay, 0o700)
    cfg_bytes = json.dumps(opencode_canary_config(model, worker_token), ensure_ascii=True).encode("ascii")
    _write_private_file(worker / "opencode.json", cfg_bytes)
    relay_src = Path(__file__).with_name("canary_relay.py").read_bytes()
    _write_private_file(relay / "relay.py", relay_src)
    proof = secrets.token_bytes(32)
    _write_private_file(relay / "proof", proof)
    return worker, relay, proof


class PipeLifeline:
    """Synchronous single-threaded poll-backed peer liveness monitor."""

    def __init__(self, read_fd: int):
        self.fd = read_fd
        self._closed = False

    def active(self) -> bool:
        if self._closed:
            return False
        poller = select.poll()
        poller.register(self.fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        ready = poller.poll(0)
        if any(mask & (select.POLLHUP | select.POLLERR) for _, mask in ready):
            self._closed = True
            return False
        return True

    def check(self) -> None:
        if not self.active():
            raise OwnerLost("peer lifeline closed")


def _verify_host_config(data: dict, *, image: str, network: str, env: dict, tmpfs: tuple[str, ...]) -> None:
    hc = data["HostConfig"]
    net = data["NetworkSettings"]
    cfg = data["Config"]
    memory = 1024**3 if image == OPEN_CODE else 128 * 1024**2
    expected = {
        "IpcMode": "private", "PidMode": "private", "CgroupMode": "private",
        "NetworkMode": network, "ReadonlyRootfs": True, "AutoRemove": True,
        "PidsLimit": 192, "Memory": memory, "MemorySwap": memory,
    }
    if (any(hc.get(k) != v for k, v in expected.items())
            or any(hc.get(k) for k in ("PortBindings", "PublishAllPorts", "Privileged", "CapAdd", "Devices"))
            or data.get("EffectiveCaps") or net.get("Ports") or cfg.get("ExposedPorts")
            or set(net.get("Networks") or {}) != {"none"} or cfg.get("User") != "0:0"
            or hc.get("SecurityOpt") != ["no-new-privileges"]
            or data["Image"].removeprefix("sha256:") != image
            or parse_env_list(cfg["Env"]) != env
            or set(hc.get("Tmpfs") or {}) != set(tmpfs)):
        raise RuntimeFailure("container settings failed restricted placement check")


def _verify_single_mount(data: dict, *, source: Path, target: str) -> None:
    mounts = data.get("Mounts") or []
    if len(mounts) != 1:
        raise RuntimeFailure("unexpected container mount count")
    mount = mounts[0]
    if (mount.get("Type") != "bind" or mount.get("RW") is not False
            or mount.get("Source") != str(source) or mount.get("Destination") != target
            or mount.get("Mode") != "Z" or mount.get("Propagation") != "rprivate"
            or not {"nosuid", "nodev", "noexec"} <= set(mount.get("Options") or ())):
        raise RuntimeFailure("unexpected container mount options")


class CanaryPlacement:
    """Create, verify, run, and verify teardown of the two disposable canary containers."""

    def __init__(self, lifeline: PipeLifeline):
        self.lifeline = lifeline
        self.label = secrets.token_hex(16)
        self.names = {role: f"oc-canary-{self.label}-{role}" for role in ("worker", "relay")}
        self.ids: dict[str, str] = {}
        self.attempted = False

    def _identity(self, identifier: str, role: str) -> dict:
        data = inspect_object("container", identifier)
        if (data["Id"] != identifier or data["Name"].removeprefix("/") != self.names[role]
                or data["Config"]["Labels"].get(LABEL) != self.label):
            raise RuntimeFailure("container identity mismatch")
        return data

    def create_and_start(self, role: str, image: str, network: str, source: Path, target: str,
                         env: dict[str, str], tmpfs: tuple[str, ...], executable: str, *args: str) -> str:
        self.lifeline.check()
        image_data = inspect_object("image", image, lifeline=self.lifeline)
        inherited = parse_env_list(image_data["Config"].get("Env") or [])
        if image_data["Id"].removeprefix("sha256:") != image or inherited.keys() - ALLOWED_IMAGE_ENV[image]:
            raise RuntimeFailure("unexpected pinned image identity or environment")
        memory = "1g" if image == OPEN_CODE else "128m"
        cmd = [
            "create", "--rm", "--pull=never", "--network", network, "--name", self.names[role],
            "--label", f"{LABEL}={self.label}", "--http-proxy=false", "--user=0:0", "--cap-drop=all",
            "--security-opt=no-new-privileges", "--read-only", "--read-only-tmpfs=false",
            "--image-volume=ignore", "--log-driver=none", "--restart=no", "--pids-limit=192",
            "--ipc=private", "--pid=private", "--cgroupns=private", "--memory", memory,
            "--memory-swap", memory, "--entrypoint", executable,
            "--volume", f"{source}:{target}:ro,Z,nosuid,nodev,noexec",
        ]
        for key, value in env.items():
            cmd.extend(("--env", f"{key}={value}"))
        for path in tmpfs:
            cmd.extend(("--tmpfs", f"{path}:{TMPFS},size=96m"))
        self.attempted = True
        identifier = podman(*cmd, image, *args, lifeline=self.lifeline).stdout.decode("ascii").strip()
        if not FULL_ID.fullmatch(identifier):
            raise RuntimeFailure("missing immutable container ID")
        self.ids[role] = identifier
        data = self._identity(identifier, role)
        _verify_host_config(data, image=image, network=network, env=inherited | env | {"container": "podman"}, tmpfs=tmpfs)
        _verify_single_mount(data, source=source, target=target)
        self.lifeline.check()
        podman("start", identifier, lifeline=self.lifeline)
        self.lifeline.check()
        return identifier

    def verify_pair(self) -> None:
        worker = self.ids["worker"]
        relay = self.ids["relay"]
        labels = [container_categories(self._identity(cid, role)) for role, cid in self.ids.items()]
        if len(set(labels)) != 2:
            raise RuntimeFailure("OpenCode and relay SELinux category pairs are not distinct")
        for kind in ("net", "pid", "ipc", "cgroup"):
            ns_path = "/proc/self/ns/" + kind
            w_ns = podman("exec", worker, "/usr/bin/readlink", ns_path, lifeline=self.lifeline).stdout.strip()
            r_ns = podman(
                "exec", relay, RELAY_PYTHON, "-IB", "-c",
                "import os, sys; print(os.readlink(sys.argv[1]))", ns_path, lifeline=self.lifeline,
            ).stdout.strip()
            h_ns = host("readlink", ns_path, lifeline=self.lifeline).stdout.strip()
            if (w_ns == r_ns) != (kind == "net") or h_ns in (w_ns, r_ns):
                raise RuntimeFailure(f"unexpected {kind} namespace placement")
        version = podman("exec", worker, "/usr/local/bin/opencode", "--version", lifeline=self.lifeline).stdout.strip()
        if version != EXPECTED_OPENCODE_VERSION:
            raise RuntimeFailure("unexpected OpenCode version in pinned image")
        home = pwd.getpwuid(os.getuid()).pw_dir
        podman(
            "exec", worker, CONTAINER_SHELL, "-ec",
            'test ! -e /fixture && test ! -e /sandbox && test ! -e /run/host && test ! -e /run/user'
            ' && test ! -e /var/run/docker.sock && test ! -e "$1"',
            "canary", home, lifeline=self.lifeline,
        )
        podman("exec", relay, CONTAINER_SHELL, "-ec", "test -S /fixture/provider.sock && test -r /fixture/proof",
               lifeline=self.lifeline)

    def run_opencode(self, model: str, *, timeout: int = 65) -> subprocess.CompletedProcess:
        worker = self.ids["worker"]
        return podman(
            "exec", "-w", "/workspace", worker,
            "/usr/local/bin/opencode", "run", "--format", "json",
            "--agent", "canary", "--model", f"local/{model}", PROMPT,
            timeout=timeout, check=False, lifeline=self.lifeline,
        )

    def close(self) -> None:
        if not self.attempted:
            return
        selector = f"label={LABEL}={self.label}"
        owned = dict(self.ids)
        with suppress(RuntimeFailure):
            rows = podman("ps", "--all", "--no-trunc", "--filter", selector,
                          "--format", "{{.ID}} {{.Names}}").stdout.splitlines()
            by_name = {name.encode("ascii"): role for role, name in self.names.items()}
            for row in rows:
                cid, _, cname = row.partition(b" ")
                if cname in by_name and re.fullmatch(rb"[0-9a-f]{64}\Z", cid):
                    owned.setdefault(by_name[cname], cid.decode("ascii"))
        for role in ("relay", "worker"):
            cid = owned.get(role)
            if cid is None:
                continue
            with suppress(RuntimeFailure, KeyError, OSError, TypeError, ValueError):
                self._identity(cid, role)
                podman("rm", "--force", "--time", "1", "--ignore", cid, check=False)
        leftover = podman("ps", "--all", "--filter", selector, "--quiet", check=True).stdout.strip()
        if leftover:
            raise RuntimeFailure("canary cleanup left a container")


def _read_owner_line(fd: int, limit: int = 4096) -> bytes:
    buf = bytearray()
    while len(buf) < limit:
        ch = os.read(fd, 1)
        if not ch:
            raise OwnerLost("launcher closed pipe")
        if ch == b"\n":
            return bytes(buf)
        buf.extend(ch)
    raise RuntimeFailure("owner protocol line too long")


def _write_owner_line(fd: int, payload: dict) -> None:
    raw = (json.dumps(payload, ensure_ascii=True) + "\n").encode("ascii")
    view = memoryview(raw)
    sent = 0
    while sent < len(raw):
        sent += os.write(fd, view[sent:])


def _teardown_owner(placement: CanaryPlacement, root: Path | None) -> tuple[bool, str]:
    errors = []
    try:
        placement.close()
    except (RuntimeFailure, OSError) as exc:
        errors.append(str(exc))
    if root is not None:
        try:
            if root.exists():
                shutil.rmtree(root)
            if root.exists():
                errors.append("scratch directory still exists after cleanup")
        except OSError as exc:
            errors.append(f"scratch removal failed: {exc}")
    return (not errors), "; ".join(errors)


def _run_owner_containers(placement: CanaryPlacement, worker_dir: Path, relay_dir: Path, model: str):
    w_id = placement.create_and_start(
        "worker", OPEN_CODE, "none", worker_dir, "/etc/opencode",
        {
            "HOME": "/job-home",
            "TMPDIR": "/job-tmp",
            "XDG_CONFIG_HOME": "/job-home/config",
            "OPENCODE_CONFIG_PROJECT_DISABLE": "true",
        },
        ("/job-home", "/job-tmp", "/workspace"),
        CONTAINER_SHELL, "-c", "exec sleep 90",
    )
    placement.create_and_start(
        "relay", RELAY, f"container:{w_id}", relay_dir, "/fixture",
        {}, (), RELAY_PYTHON, "-IB", "/fixture/relay.py",
    )
    placement.verify_pair()
    _write_owner_line(1, {"started": True})
    return placement.run_opencode(model)


def _owner_main() -> int:
    if not stat.S_ISFIFO(os.fstat(0).st_mode) or not stat.S_ISFIFO(os.fstat(1).st_mode):
        return 2
    _write_owner_line(1, {"ready": True})
    spec = json.loads(_read_owner_line(0).decode("ascii"))
    model = spec.get("model")
    token = spec.get("token")
    if type(model) is not str or not MODEL_RE.fullmatch(model) or type(token) is not str or not TOKEN_RE.fullmatch(token):
        return 2
    lifeline = PipeLifeline(0)
    placement = CanaryPlacement(lifeline)
    root: Path | None = None
    result = None
    run_error: str | None = None
    try:
        preflight_host()
        root = Path(tempfile.mkdtemp(prefix="oc-canary-", dir=scratch_parent()))
        os.chmod(root, 0o700)
        worker_dir, relay_dir, proof = seed_scratch(root, model, token)
        _write_owner_line(1, {"root": str(root), "proof": proof.hex()})
        start_msg = json.loads(_read_owner_line(0).decode("ascii"))
        if start_msg.get("start") is not True:
            return 2
        result = _run_owner_containers(placement, worker_dir, relay_dir, model)
    except (OwnerLost, RuntimeFailure, OSError, ValueError) as error:
        run_error = str(error)
    cleanup_ok, cleanup_err = _teardown_owner(placement, root)
    if run_error is not None:
        with suppress(OSError):
            _write_owner_line(1, {"error": run_error, "cleanup_verified": cleanup_ok, "cleanup_error": cleanup_err})
        return 1
    with suppress(OSError):
        _write_owner_line(1, {
            "done": True,
            "rc": result.returncode,
            "stdout_b64": base64.b64encode(result.stdout).decode("ascii"),
            "stderr_b64": base64.b64encode(result.stderr).decode("ascii"),
            "cleanup_verified": cleanup_ok,
            "cleanup_error": cleanup_err,
        })
    if cleanup_ok:
        return 0
    return 1


class DetachedOwnerSession:
    """Foreground handle to the cleanup-only detached _owner subprocess."""

    def __init__(self, model: str, worker_token: str):
        self.model = model
        self.worker_token = worker_token
        self.proc: subprocess.Popen | None = None
        self.root: Path | None = None
        self.proof: bytes | None = None

    def _read_msg(self, timeout: float = 30.0) -> dict:
        if self.proc is None or self.proc.stdout is None:
            raise OwnerLost("owner not running")
        fd = self.proc.stdout.fileno()
        deadline = time.monotonic() + timeout
        buf = bytearray()
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while len(buf) < OUTPUT_LIMIT * 2:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise OwnerLost("owner timed out")
            ready = poller.poll(int(rem * 1000) + 1)
            if not ready:
                raise OwnerLost("owner timed out")
            ch = os.read(fd, 1)
            if not ch:
                raise OwnerLost("owner exited unexpectedly")
            if ch == b"\n":
                return json.loads(buf.decode("ascii"))
            buf.extend(ch)
        raise OwnerLost("owner message too large")

    def active(self) -> bool:
        if self.proc is None or self.proc.poll() is not None or self.proc.stdout is None:
            return False
        poller = select.poll()
        poller.register(self.proc.stdout.fileno(), select.POLLHUP | select.POLLERR)
        return not poller.poll(0)

    def check_alive(self) -> None:
        if not self.active():
            raise OwnerLost("cleanup owner exited")

    def prepare(self) -> tuple[Path, bytes]:
        cmd = [sys.executable, "-IB", str(Path(__file__).resolve()), "_owner"]
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
        hello = self._read_msg(timeout=15.0)
        if hello.get("ready") is not True:
            raise OwnerLost("owner failed handshake")
        _write_owner_line(self.proc.stdin.fileno(), {"model": self.model, "token": self.worker_token})
        seeded = self._read_msg(timeout=20.0)
        if "error" in seeded:
            raise RuntimeFailure(seeded["error"])
        root = Path(seeded["root"])
        check_private_directory(root)
        if root.parent != scratch_parent():
            raise RuntimeFailure("unexpected owner scratch parent")
        self.root = root
        self.proof = bytes.fromhex(seeded["proof"])
        return root, self.proof

    def start_containers(self) -> None:
        self.check_alive()
        _write_owner_line(self.proc.stdin.fileno(), {"start": True})
        msg = self._read_msg(timeout=30.0)
        if "error" in msg:
            raise RuntimeFailure(msg["error"])
        if msg.get("started") is not True:
            raise OwnerLost("owner failed to start containers")

    def wait_opencode(self, timeout: float = 85.0) -> tuple[int, bytes, bytes, bool, str]:
        msg = self._read_msg(timeout=timeout)
        if "error" in msg:
            raise RuntimeFailure(msg["error"])
        if msg.get("done") is not True:
            raise OwnerLost("owner exited before opencode finished")
        return (
            int(msg["rc"]),
            base64.b64decode(msg["stdout_b64"]),
            base64.b64decode(msg["stderr_b64"]),
            bool(msg.get("cleanup_verified")),
            str(msg.get("cleanup_error") or ""),
        )

    def close(self) -> int:
        if self.proc is None:
            return 0
        with suppress(OSError):
            if self.proc.stdin is not None:
                self.proc.stdin.close()
        with suppress(OSError):
            if self.proc.stdout is not None:
                self.proc.stdout.close()
        try:
            rc = self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = self.proc.wait(timeout=5)
        self.proc = None
        return rc


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "_owner":
        raise SystemExit(_owner_main())
    raise SystemExit(2)
