"""Create and verify the two containers for one offline OpenCode PoC job."""

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

from relay import grant_record, take_fence


LABEL = "io.oc-sandbox.local-poc"
ROLE_LABEL = f"{LABEL}.role"
IMAGE_ID = re.compile(r"[0-9a-f]{64}")
SHA256_PREFIX = "sha256:"
RELAY_FILE = "relay.py"
WORKSPACE = "/workspace"
WORKER_TEMP = "/job-tmp"
NETNS_PATH = "/proc/self/ns/net"
NETNS_LINK = re.compile(rb"net:\[\d+\]")
PROCESS_LABEL = re.compile(r"[^:]+:[^:]+:container_t:s0:c(\d+),c(\d+)", re.ASCII)
MOUNT_LABEL = re.compile(r"[^:]+:[^:]+:container_file_t:s0:c\d+,c\d+", re.ASCII)
SAFE_PIN = re.compile(r"[A-Za-z0-9_.-]{1,128}")
TMPFS_OPTIONS = "rw,nosuid,nodev,noexec,mode=0700"
ROLES = ("relay", "worker")
MEMORY_LIMITS = {"relay": 128 * 1024**2, "worker": 1024**3}
FIPS_STATUS = "/proc/sys/crypto/fips_enabled"
IMAGE_ENV = {
    "worker": {"PATH", "BUN_RUNTIME_TRANSPILER_CACHE_PATH"},
    "relay": {"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256", "PYTHONDONTWRITEBYTECODE"},
}
SELINUX_ENFORCE = Path("/sys/fs/selinux/enforce")
SELINUX_PROCESS = Path("/proc/self/attr/current")
HOST_MODE = os.environ.get("OC_POC_PODMAN_HOST", "local")
HOST_SPAWN = "/usr/bin/host-spawn"
# Before writing, verify root ownership and the sticky bit on the parent, and
# match its host and guest device/inode in devbox. Open the private 0700 leaf without following symlinks.
SHARED_TMP = Path("/tmp")  # NOSONAR(S5443)
SYSTEM_HOME = Path("/home")
NETWORK_LEAK_FIELDS = ("Gateway", "IPAddress", "IPv6Gateway", "GlobalIPv6Address", "MacAddress")
PROBE_TCP = (
    "import socket; "
    "socket.create_connection(('127.0.0.1', 4096), 0.5).close()"
)
PROBE_FILE = (
    f'p={WORKSPACE}/proof.txt; '
    'if [ -L "$p" ]; then exit 2; fi; '
    'if [ ! -e "$p" ]; then printf A; exit; fi; '
    'if [ ! -f "$p" ]; then exit 2; fi; '
    'printf F; head -c "$1" "$p"'
)


class JobRuntimeError(RuntimeError):
    """A concise diagnostic containing only trusted labels, roles, and identifiers."""


def account_home() -> Path:
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def host_command(program: str, *args: str, timeout: int = 12) -> subprocess.CompletedProcess:
    command = [f"/usr/bin/{program}", *args]
    uid = os.getuid()
    runtime_dir = f"/run/user/{uid}"
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(account_home()),
        "XDG_RUNTIME_DIR": runtime_dir,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime_dir}/bus",
        "LC_ALL": "C",
    }
    if HOST_MODE == "distrobox":
        # Clear the physical host command's inherited environment as well as the
        # bridge's inputs. The inner timeout survives loss of the bridge reply.
        command = [
            HOST_SPAWN, "--no-pty", "--env=", "/usr/bin/env", "-i",
            *(f"{key}={value}" for key, value in environment.items()),
            "/usr/bin/timeout", "--kill-after=1s", f"{timeout}s", *command,
        ]
        environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/host{runtime_dir}/bus"
    elif HOST_MODE != "local":
        raise JobRuntimeError("Unsupported OC_POC_PODMAN_HOST value")
    try:
        return subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, env=environment,
            timeout=timeout + 4 if HOST_MODE == "distrobox" else timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise JobRuntimeError(f"Host {program} command failed or timed out") from None


def host_output(program: str, *args: str) -> bytes:
    result = host_command(program, *args, timeout=4)
    if result.returncode != 0:
        raise JobRuntimeError(f"Host {program} check failed ({result.returncode})")
    return result.stdout


def podman(*args: str, timeout: int = 12, check: bool = True) -> subprocess.CompletedProcess:
    try:
        result = host_command("podman", "--remote=false", "--default-mounts-file=/dev/null", *args, timeout=timeout)
    except JobRuntimeError:
        raise JobRuntimeError(f"Podman {args[0]} failed or timed out") from None
    if check and result.returncode != 0:
        raise JobRuntimeError(f"Podman {args[0]} failed ({result.returncode})")
    return result


def inspected(*args: str) -> dict:
    try:
        value, = json.loads(podman(*args).stdout)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (TypeError, ValueError):
        raise JobRuntimeError(f"Invalid Podman {args[0]} receipt") from None


def atomic_write(path: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def directory_identity(info: os.stat_result, uid: int) -> bytes:
    return f"{info.st_dev}:{info.st_ino}:{uid}:{info.st_mode:x}".encode("ascii")


def check_scratch_ancestors(path: Path, shared_tmp: bool) -> None:
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        if stat.S_ISLNK(info.st_mode):
            if ancestor == SYSTEM_HOME and info.st_uid == 0 and ancestor.readlink() in {
                Path("var/home"), Path("/var/home"),
            }:
                continue
            raise JobRuntimeError("Run directory has an untrusted symlink ancestor")
        if (
            ancestor == SHARED_TMP and stat.S_ISDIR(info.st_mode)
            and info.st_mode & stat.S_ISVTX and (info.st_uid == 0 or shared_tmp)
        ):
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise JobRuntimeError("Run directory has an untrusted ancestor")


def check_scratch_location(path: Path) -> None:
    home = account_home()
    protected = [
        Path("/sandbox"), home / "opencode-sandbox", home / "code" / "opencode-sandbox",
        home / ".local" / "bin", home / ".local" / "share" / "oc-sandbox",
        home / ".config" / "oc-sandbox", home / ".config" / "systemd" / "user",
    ]
    for name in ("XDG_DATA_HOME", "XDG_CONFIG_HOME"):
        configured = Path(os.environ.get(name, ""))
        if configured.is_absolute():
            protected.append(configured / "oc-sandbox")
    if any(path.is_relative_to(location) or path.is_relative_to(location.resolve()) for location in protected):
        raise JobRuntimeError("Run directory is within sandbox or production state")


def check_host() -> None:
    try:
        source = (
            host_output("cat", str(SELINUX_ENFORCE))
            if HOST_MODE == "distrobox" else SELINUX_ENFORCE.read_bytes()
        )
        enforcing = source.strip() == b"1"
    except (OSError, JobRuntimeError):
        enforcing = False
    if not enforcing:
        raise JobRuntimeError("This PoC requires SELinux enforcing on the Podman host")
    mode = podman(
        "info", "--format", "{{.Host.Security.Rootless}} {{.Host.Security.SELinuxEnabled}} {{.Host.CgroupsVersion}}"
    ).stdout.strip()
    if os.geteuid() == 0 or mode != b"true true v2":
        raise JobRuntimeError("This PoC requires local rootless Podman with SELinux labeling and cgroup v2")
    # Podman can add FIPS mounts separately from its default subscription file.
    if host_output("cat", FIPS_STATUS).strip() != b"0":
        raise JobRuntimeError("This PoC requires the Podman host FIPS mode to be disabled")


def worker_config() -> dict:
    return {
        "model": "local/fixture-model",
        "update": "disable",
        "snapshots": False,
        "providers": {
            "local": {
                "name": "Offline scripted model",
                "package": "@opencode/ai/providers/openai-compatible",
                "settings": {
                    "baseURL": "http://127.0.0.1:8401/v1",
                    "apiKey": "{env:OC_POC_MODEL_TOKEN}",
                },
                "models": {
                    "fixture-model": {
                        "name": "Synthetic fixture",
                        "capabilities": {"tools": True, "input": ["text"], "output": ["text"]},
                        "limit": {"context": 65536, "output": 2048},
                    }
                },
            }
        },
        "permissions": [
            {"action": "*", "resource": "*", "effect": "deny"},
            {"action": "edit", "resource": "proof.txt", "effect": "allow"},
        ],
        "policies": [
            {"action": "provider.use", "resource": "*", "effect": "deny"},
            {"action": "provider.use", "resource": "local", "effect": "allow"},
        ],
    }


def parse_env(entries: list[str]) -> dict[str, str]:
    values = {}
    for entry in entries:
        name, value = entry.split("=", 1)
        values[name] = value
    return values


class Job:
    def __init__(
        self,
        root: Path,
        opencode_image: str,
        relay_image: str,
        token: str,
        password: str,
        incarnation: str,
        generation: int = 1,
    ):
        self.root = root.absolute()
        self.images = {"worker": opencode_image.removeprefix(SHA256_PREFIX), "relay": relay_image.removeprefix(SHA256_PREFIX)}
        self.incarnation = incarnation
        self.generation = generation
        self.token = token
        self.password = password
        self.run_label = secrets.token_hex(16)
        self.names = {role: f"oc-poc-{self.run_label}-{role}" for role in ROLES}
        self.ids: dict[str, str] = {}
        self.recorded_ids: dict[str, str] = {}
        self.pending_create: set[str] = set()
        self.image_env: dict[str, list[str]] = {}
        self.provider_socket = self.root / "provider" / "provider.sock"
        self.control_socket = self.root / "control" / "control.sock"
        self.grant = self.root / "grant"
        self.receipt = self.root / "receipt.json"
        self.terminal = False
        self.attempted_create = False
        self.held_fence: int | None = None
        self.lifetime: int | None = None

    def _write_receipt(self) -> None:
        atomic_write(self.receipt, (json.dumps({
            "label": f"{LABEL}={self.run_label}",
            "names": self.names,
            "ids": self.ids,
            "pending_create": sorted(self.pending_create),
        }, sort_keys=True) + "\n").encode("ascii"))
        self.recorded_ids = self.ids.copy()

    def prepare(self) -> None:
        if (
            not all(SAFE_PIN.fullmatch(value) for value in (self.incarnation, self.token, self.password))
            or self.password == self.token
            or type(self.generation) is not int
            or not 1 <= self.generation < 2**63
        ):
            raise JobRuntimeError("Invalid synthetic job pins")
        root = self._scratch_root()
        self.root = root
        self.provider_socket = root / "provider" / "provider.sock"
        self.control_socket = root / "control" / "control.sock"
        self.grant = root / "grant"
        self.receipt = root / "receipt.json"
        if any(len(os.fsencode(path)) >= 108 for path in (self.provider_socket, self.control_socket)):
            raise JobRuntimeError("Run directory is too long for Unix sockets")
        try:
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise JobRuntimeError("Run directory must already exist as a private directory") from None
        try:
            self._prepare_directory(directory_fd)
        finally:
            os.close(directory_fd)

    def _scratch_root(self) -> Path:
        if ".." in self.root.parts or any(char in str(self.root) for char in ":,\n"):
            raise JobRuntimeError("Run directory contains an unsupported component")
        shared_tmp = HOST_MODE == "distrobox"
        if shared_tmp and self.root.parent != SHARED_TMP:
            raise JobRuntimeError("Devbox run directory must be a leaf under the shared /tmp")
        if not shared_tmp and HOST_MODE != "local":
            raise JobRuntimeError("Unsupported OC_POC_PODMAN_HOST value")
        try:
            check_scratch_ancestors(self.root, shared_tmp)
            resolved = self.root.parent.resolve(strict=True) / self.root.name
            if resolved != self.root:
                check_scratch_ancestors(resolved, shared_tmp)
            check_scratch_location(resolved)
        except JobRuntimeError:
            raise
        except (OSError, RuntimeError):
            raise JobRuntimeError("Run directory ancestry could not be verified") from None
        return resolved

    def _check_shared_tmp(self) -> None:
        entry = SHARED_TMP.lstat()
        physical = host_output("stat", "-c", "%d:%i:%u:%f", "--", str(SHARED_TMP)).strip()
        if (
            not stat.S_ISDIR(entry.st_mode) or not entry.st_mode & stat.S_ISVTX
            or physical != directory_identity(entry, 0)
        ):
            raise JobRuntimeError("Devbox run directory parent is not the root-owned sticky host /tmp")

    def _prepare_directory(self, directory_fd: int) -> None:
        info = os.fstat(directory_fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid() or os.listdir(directory_fd):
            raise JobRuntimeError("Run directory must be empty, private, and owned by this user")
        if HOST_MODE == "distrobox":
            self._check_bridge(info)
        for name in ("provider", "control", "grant", "fixture", "source"):
            os.mkdir(name, mode=0o700, dir_fd=directory_fd)
        (self.grant / "lock").touch(mode=0o600, exist_ok=False)
        self.lifetime = os.open(self.grant / "lifetime", os.O_RDONLY | os.O_CREAT | os.O_EXCL, 0o600)
        take_fence(self.lifetime)
        atomic_write(self.grant / "state", grant_record(self.incarnation, self.generation, True))
        atomic_write(self.root / "fixture" / "opencode.json", json.dumps(worker_config()).encode("ascii"))
        shutil.copyfile(Path(__file__).with_name(RELAY_FILE), self.root / "source" / RELAY_FILE)
        (self.root / "source" / RELAY_FILE).chmod(0o600)
        self._write_receipt()

    def _check_bridge(self, info: os.stat_result) -> None:
        try:
            devbox_context = SELINUX_PROCESS.read_bytes().strip(b"\0\n")
            bus = Path(f"/run/host/run/user/{info.st_uid}/bus").stat()
            bridge = Path(HOST_SPAWN).stat()
        except OSError:
            raise JobRuntimeError("Devbox host bridge and existing session bus are required") from None
        if (
            not re.fullmatch(rb"[^:]+:[^:]+:spc_t:s0", devbox_context)
            or not stat.S_ISSOCK(bus.st_mode)
            or bus.st_uid != info.st_uid
            or not stat.S_ISREG(bridge.st_mode)
            or bridge.st_uid != 0
            or bridge.st_mode & 0o022
        ):
            raise JobRuntimeError("Unexpected devbox host bridge context or ownership")
        self._check_shared_tmp()
        host_uid = host_output("id", "-ru").strip()
        host_context = host_output("cat", str(SELINUX_PROCESS)).strip(b"\0\n")
        host_directory = host_output("stat", "-c", "%d:%i:%u:%f", "--", str(self.root)).strip()
        expected_directory = directory_identity(info, info.st_uid)
        if (
            host_uid != str(info.st_uid).encode("ascii")
            or not re.fullmatch(rb"[^:]+:[^:]+:unconfined_t:s0-s0:c0.c1023", host_context)
            or host_directory != expected_directory
        ):
            raise JobRuntimeError("Devbox and Podman host did not share the expected private run directory")

    def _check_images(self) -> None:
        check_host()
        for role, image in self.images.items():
            if not IMAGE_ID.fullmatch(image):
                raise JobRuntimeError(f"{role} image must be a full local image ID")
            details = inspected("image", "inspect", image)
            if details.get("Id", "").removeprefix(SHA256_PREFIX) != image:
                raise JobRuntimeError(f"{role} local image ID did not match")
            env = (details.get("Config") or {}).get("Env") or []
            names = {entry.partition("=")[0] for entry in env}
            if len(names) != len(env) or not names <= IMAGE_ENV[role] or "PATH" not in names:
                raise JobRuntimeError(f"Unexpected environment in the pinned {role} image")
            self.image_env[role] = env

    def _create(
        self,
        role: str,
        *,
        mode: str,
        mounts: dict[str, tuple[Path, bool]],
        tmpfs: dict[str, str],
        env: dict[str, str],
        command: list[str],
        workdir: str,
    ) -> None:
        memory = f"{MEMORY_LIMITS[role]}b"
        args = ["create", "--pull=never", "--network", mode,
                "--name", self.names[role], "--label", f"{LABEL}={self.run_label}",
                "--label", f"{ROLE_LABEL}={role}", "--http-proxy=false",
                "--user=0:0", "--cap-drop=all", "--security-opt=no-new-privileges",
                "--read-only", "--read-only-tmpfs=false", "--image-volume=ignore",
                "--log-driver=none", "--restart=no", "--pids-limit=192", "--ipc=private",
                "--pid=private",
                "--memory", memory, "--memory-swap", memory, "--cgroupns=private",
                "--workdir", workdir]
        for destination, (source, writable) in mounts.items():
            access = "rw" if writable else "ro"
            args.extend(("--volume", f"{source}:{destination}:{access},Z,nosuid,nodev,noexec"))
        for destination, options in tmpfs.items():
            args.extend(("--tmpfs", f"{destination}:{options}"))
        env_file = self.root / "worker.env" if env else None
        if env_file is not None:
            args.extend(("--env-file", str(env_file)))
        try:
            if env_file is not None:
                atomic_write(env_file, "".join(f"{name}={value}\n" for name, value in env.items()).encode("ascii"))
            self.pending_create.add(role)
            self._write_receipt()
            self.attempted_create = True
            result = podman(*args, self.images[role], *command)
        finally:
            if env_file is not None:
                env_file.unlink(missing_ok=True)
        try:
            container_id = result.stdout.decode("ascii").strip()
        except UnicodeError:
            raise JobRuntimeError(f"Invalid {role} create receipt") from None
        if not IMAGE_ID.fullmatch(container_id):
            raise JobRuntimeError(f"Invalid {role} create receipt")
        self.ids[role] = container_id
        self.pending_create.remove(role)
        self._write_receipt()
        self._verify_container(role, mode, mounts, tmpfs, env)

    def _identity(self, role: str, container_id: str) -> dict:
        details = inspected("container", "inspect", container_id)
        labels = (details.get("Config") or {}).get("Labels") or {}
        if (
            details.get("Id") != container_id
            or details.get("Name", "").removeprefix("/") != self.names[role]
            or labels.get(LABEL) != self.run_label
            or labels.get(ROLE_LABEL) != role
        ):
            raise JobRuntimeError(f"Podman {role} identity did not match its receipt")
        return details

    def _verify_container(self, role, mode, mounts, tmpfs, env) -> None:
        details = self._identity(role, self.ids[role])
        self._verify_isolation(role, mode, details)
        expected_env = parse_env(self.image_env[role])
        expected_env.update(container="podman", **env)
        actual_env = parse_env(details["Config"]["Env"])
        if actual_env != expected_env:
            raise JobRuntimeError(f"Unexpected {role} environment")
        self._verify_mounts(role, mounts, tmpfs, details)

    def _verify_isolation(self, role, mode, details) -> None:
        host = details["HostConfig"]
        network = details["NetworkSettings"]
        config = details["Config"]
        if (
            details.get("Image", "").removeprefix(SHA256_PREFIX) != self.images[role]
            or host.get("NetworkMode") != mode
            or host.get("PortBindings")
            or host.get("PublishAllPorts")
            or network.get("Ports")
            or config.get("ExposedPorts")
            or any(network.get(field) for field in NETWORK_LEAK_FIELDS)
            or set(network.get("Networks") or {}) != {"none"}
            or any(
                (network["Networks"]["none"] or {}).get(field)
                for field in NETWORK_LEAK_FIELDS
            )
            or host.get("Privileged")
            or host.get("IpcMode") != "private"
            or host.get("PidMode") != "private"
            or host.get("PidsLimit") != 192
            or config.get("User") != "0:0"
            or not host.get("ReadonlyRootfs")
            or host.get("Devices")
            or host.get("CapAdd")
            or details.get("EffectiveCaps")
            or host.get("SecurityOpt") != ["no-new-privileges"]
            or host.get("Memory") != MEMORY_LIMITS[role]
            or host.get("MemorySwap") != MEMORY_LIMITS[role]
            or host.get("CgroupMode") != "private"
            or not PROCESS_LABEL.fullmatch(details.get("ProcessLabel") or "")
            or not MOUNT_LABEL.fullmatch(details.get("MountLabel") or "")
            or details["ProcessLabel"].split(":", 3)[-1] != details["MountLabel"].split(":", 3)[-1]
        ):
            raise JobRuntimeError(f"Unexpected {role} isolation settings")
        if role == "relay":
            self._verify_distinct_mcs(details["ProcessLabel"])

    def _verify_distinct_mcs(self, relay_label: str) -> None:
        worker_label = self._identity("worker", self.ids["worker"]).get("ProcessLabel") or ""
        worker_mcs = PROCESS_LABEL.fullmatch(worker_label)
        relay_mcs = PROCESS_LABEL.fullmatch(relay_label)
        if worker_mcs and relay_mcs:
            worker_categories = set(map(int, worker_mcs.groups()))
            relay_categories = set(map(int, relay_mcs.groups()))
            if len(worker_categories) == len(relay_categories) == 2 and worker_categories != relay_categories:
                return
        raise JobRuntimeError("Worker and relay must have distinct SELinux MCS categories")

    def _verify_mounts(self, role, mounts, tmpfs, details) -> None:
        actual_mounts = details["Mounts"] or []
        if len(actual_mounts) != len(mounts) or {mount.get("Destination") for mount in actual_mounts} != set(mounts):
            raise JobRuntimeError(f"Unexpected {role} mount count")
        for binding in actual_mounts:
            expected = mounts.get(binding.get("Destination"))
            if (
                not expected
                or binding.get("Type") != "bind"
                or binding.get("Source") != str(expected[0])
                or binding.get("RW") is not expected[1]
                or binding.get("Mode") != "Z"
                or binding.get("Propagation") != "rprivate"
                or not {"nosuid", "nodev", "noexec"} <= set(binding.get("Options") or ())
            ):
                raise JobRuntimeError(f"Unexpected {role} bind mount")
        actual_tmpfs = {
            path: set(options.split(",")) - {"rprivate", "tmpcopyup"}
            for path, options in (details["HostConfig"].get("Tmpfs") or {}).items()
        }
        if actual_tmpfs != {path: set(options.split(",")) for path, options in tmpfs.items()}:
            raise JobRuntimeError(f"Unexpected {role} tmpfs mounts")

    def _verify_running_label(self, role: str) -> None:
        container_id = self.ids[role]
        details = self._identity(role, container_id)
        expected = details["ProcessLabel"].encode("ascii")
        effective = podman("exec", container_id, "cat", "/proc/self/attr/current").stdout.removesuffix(b"\0")
        if effective != expected:
            raise JobRuntimeError(f"Unexpected effective {role} SELinux process label")
        expected_mount_label = details["MountLabel"].encode("ascii")
        for mount in details["Mounts"]:
            try:
                if HOST_MODE == "distrobox":
                    value = host_output(
                        "getfattr", "--only-values", "-n", "security.selinux", "--", mount["Source"],
                    )
                else:
                    value = os.getxattr(mount["Source"], "security.selinux")
                label = value.removesuffix(b"\0")
            except (OSError, JobRuntimeError):
                raise JobRuntimeError(f"Could not verify {role} bind mount label") from None
            if label != expected_mount_label:
                raise JobRuntimeError(f"Unexpected effective {role} bind mount label")

    def _verify_memory(self, role: str) -> None:
        limits = podman(
            "exec", self.ids[role], "cat", "/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.swap.max",
        ).stdout.splitlines()
        if limits != [str(MEMORY_LIMITS[role]).encode("ascii"), b"0"]:
            raise JobRuntimeError(f"Unexpected effective {role} memory or swap limit")

    def start(self) -> None:
        if (
            self.attempted_create or self.terminal or self.lifetime is None
            or not self.receipt.is_file() or not self.provider_socket.is_socket()
        ):
            raise JobRuntimeError("Job is not prepared with a bound provider socket")
        self._check_images()
        self._create(
            "worker", mode="none", env={
                "HOME": "/job-home",
                "TMPDIR": WORKER_TEMP,
                "OPENCODE_CONFIG": "/fixture/opencode.json",
                "OPENCODE_PASSWORD": self.password,
                "OC_POC_MODEL_TOKEN": self.token,
            },
            mounts={"/fixture": (self.root / "fixture", False)},
            tmpfs={
                "/job-home": f"{TMPFS_OPTIONS},size=96m",
                WORKSPACE: f"{TMPFS_OPTIONS},size=32m",
                WORKER_TEMP: f"{TMPFS_OPTIONS},size=32m",
            },
            command=["serve", "--hostname", "127.0.0.1", "--port", "4096", "--log-level", "none"],
            workdir=WORKSPACE,
        )
        podman("start", self.ids["worker"])
        self._verify_running_label("worker")
        self._verify_memory("worker")
        version = podman("exec", self.ids["worker"], "opencode", "--version").stdout.strip()
        if version != b"opencode v2.3.0":
            raise JobRuntimeError("Pinned worker did not report OpenCode 2.3.0")
        self._create(
            "relay", mode=f"container:{self.ids['worker']}", env={},
            mounts={
                "/source": (self.root / "source", False),
                "/provider": (self.provider_socket.parent, False),
                "/grant": (self.grant, False),
                "/control": (self.control_socket.parent, True),
            },
            tmpfs={}, command=["python3", "-B", f"/source/{RELAY_FILE}", self.incarnation, str(self.generation)],
            workdir="/",
        )
        podman("start", self.ids["relay"])
        self.assert_running()
        self._verify_running_label("relay")
        self._verify_memory("relay")
        namespaces = {
            podman("exec", self.ids[role], "readlink", NETNS_PATH).stdout.strip()
            for role in ROLES
        }
        host_namespace = (
            host_output("readlink", NETNS_PATH).strip() if HOST_MODE == "distrobox"
            else os.readlink(NETNS_PATH).encode("ascii")
        )
        if len(namespaces) != 1 or not all(NETNS_LINK.fullmatch(item) for item in namespaces):
            raise JobRuntimeError("Relay did not join the worker network namespace")
        if not NETNS_LINK.fullmatch(host_namespace) or host_namespace in namespaces:
            raise JobRuntimeError("Worker joined the host network namespace")

        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.control_socket.is_socket() and podman(
                "exec", self.ids["relay"], "python3", "-c", PROBE_TCP, check=False, timeout=3
            ).returncode == 0:
                return
            time.sleep(0.1)
        raise JobRuntimeError("Isolated OpenCode listener did not become ready")

    def assert_running(self) -> None:
        for role in ROLES:
            details = self._identity(role, self.ids[role])
            if details["State"]["Status"] != "running" or not details["State"]["Running"]:
                raise JobRuntimeError(f"Expected the {role} to be running")

    def assert_file(self, expected: bytes | None) -> None:
        length = 1 if expected is None else len(expected) + 1
        output = podman("exec", self.ids["worker"], "/bin/sh", "-ec", PROBE_FILE, "--", str(length)).stdout
        receipt = b"A" if expected is None else b"F" + expected
        if output != receipt:
            raise JobRuntimeError("Workspace proof file did not match expected state")

    def _drop_lifetime(self) -> None:
        if self.lifetime is not None:
            fd, self.lifetime = self.lifetime, None
            try:
                os.close(fd)
            except OSError:
                # If closing errors, prevent new relay opens of the lifetime inode.
                (self.grant / "lifetime").unlink(missing_ok=True)

    def revoke(self) -> None:
        if self.terminal:
            return
        fd = None
        locked = False
        try:
            if self.lifetime is None:
                raise JobRuntimeError("Job lifetime already closed")
            fd = os.open(self.grant / "lock", os.O_RDONLY | os.O_NOFOLLOW)
            take_fence(fd)
            locked = True
            terminal = grant_record(self.incarnation, self.generation, False)
            atomic_write(self.grant / "state", terminal)
            if (self.grant / "state").read_bytes() != terminal:
                raise JobRuntimeError("Terminal grant receipt did not match")
            self.terminal = True
        except (OSError, JobRuntimeError):
            if locked:
                self.held_fence, fd = fd, None
            self._failed_revoke()
        finally:
            if fd is not None:
                os.close(fd)

    def _failed_revoke(self) -> None:
        # Close the independent liveness fence even when the write fence could
        # not be opened or acquired. Its stable inode is never rearmed.
        try:
            self._drop_lifetime()
        except OSError:
            pass
        try:
            (self.grant / "state").unlink(missing_ok=True)
        except OSError:
            pass
        self._stop_relay()
        if self.held_fence is not None:
            os.close(self.held_fence)
            self.held_fence = None
        self.terminal = True
        raise JobRuntimeError("Terminal grant could not be confirmed; relay stopped") from None

    def _stop_relay(self) -> None:
        container_id = self.ids.get("relay")
        if not container_id:
            raise JobRuntimeError("Terminal grant could not be confirmed; relay identity unavailable") from None
        try:
            self._identity("relay", container_id)
            try:
                podman("stop", "--time", "0", container_id, check=False)
            except JobRuntimeError:
                # A timed-out command may still have stopped the exact relay.
                pass
            state = self._identity("relay", container_id)["State"]
            if state["Status"] in ("exited", "stopped") and not state["Running"]:
                return
        except JobRuntimeError:
            pass
        raise JobRuntimeError("Terminal grant could not be confirmed; relay stop unconfirmed") from None

    def _inventory(self) -> list[str]:
        ids = podman(
            "ps", "--all", "--quiet", "--no-trunc", "--filter", f"label={LABEL}={self.run_label}"
        ).stdout.decode("ascii").splitlines()
        if any(not IMAGE_ID.fullmatch(container_id) for container_id in ids):
            raise JobRuntimeError("Unexpected container ID in run inventory")
        return ids

    def close(self) -> None:
        try:
            self._drop_lifetime()
        finally:
            if self.attempted_create:
                self._remove_containers()
            if self.held_fence is not None:
                os.close(self.held_fence)
                self.held_fence = None

    def _discover_containers(self) -> dict[str, str]:
        # The command that created a container may have timed out before returning
        # its ID. Adopt only freshly verified label/name/role matches.
        try:
            inventory = self._inventory()
        except JobRuntimeError:
            inventory = []
        candidates = self.ids.copy()
        for container_id in inventory:
            try:
                details = inspected("container", "inspect", container_id)
                role = (details.get("Config") or {}).get("Labels", {}).get(ROLE_LABEL)
                if role in ROLES and candidates.get(role, container_id) == container_id:
                    self._identity(role, container_id)
                    candidates[role] = container_id
            except JobRuntimeError:
                # Continue with other exact IDs even if one inspection failed.
                pass

        return candidates

    def _remove_recorded(self, candidates: dict[str, str]) -> None:
        for role in ROLES:
            container_id = candidates.get(role)
            if not container_id or self.recorded_ids.get(role) != container_id:
                continue
            try:
                self._identity(role, container_id)
                podman("rm", "--force", "--time", "0", container_id, check=False)
            except JobRuntimeError:
                # Timeout or loss of the result is reconciled independently below.
                pass

    def _check_removed(self, candidates: dict[str, str]) -> None:
        try:
            clean = not self._inventory()
        except JobRuntimeError:
            clean = False
        for container_id in candidates.values():
            try:
                absent = podman("container", "exists", container_id, check=False).returncode == 1
            except JobRuntimeError:
                absent = False
            clean = clean and absent
        if not clean:
            raise JobRuntimeError("Job container cleanup unconfirmed; receipt retained")

    def _remove_containers(self) -> None:
        candidates = self._discover_containers()
        self.ids.update(candidates)
        if self.ids != self.recorded_ids:
            try:
                self._write_receipt()
            except OSError:
                # An ID without a confirmed receipt is left for recovery.
                pass
        self._remove_recorded(candidates)
        self._check_removed(candidates)
        if self.pending_create:
            # A late host create can occur even after an empty final inventory.
            raise JobRuntimeError("Podman create acknowledgment was lost; cleanup unconfirmed, receipt retained")
        self.attempted_create = False
