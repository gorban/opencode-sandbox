"""Create the selected sidecars in the existing local proof's worker network."""

from dataclasses import dataclass
import json
from pathlib import Path
import secrets

from profile_plan import CDP_SERVICE, PG_SERVICE, ProfileError
from runtime import (
    IMAGE_ID, NETNS_PATH, PROCESS_LABEL, Job, JobRuntimeError, atomic_write, host_output, inspected, parse_env, podman,
)


LABEL = "io.oc-sandbox.profile-poc"
ROLE = f"{LABEL}.role"
PASSWORD = "/run/profile-pg-password"
PG_DATA = "/pgscratch/data"
PG_INIT = (
    f"initdb -D {PG_DATA} --username=postgres --auth-local=peer --auth-host=scram-sha-256 "
    "--pwfile=/run/profile-pg-password --no-sync --no-instructions >/dev/null; "
    f"exec postgres -D {PG_DATA} -c listen_addresses=127.0.0.1 -c unix_socket_directories=/tmp "
    "-c password_encryption=scram-sha-256"
)
CDP_COMMAND = (
    "--headless", "--no-sandbox", "--disable-gpu", "--disable-background-networking",
    "--no-first-run", "--user-data-dir=/tmp/chromium", "--remote-debugging-address=127.0.0.1",
    "--remote-debugging-port=9222", "about:blank",
)


def private_tmpfs(size: str) -> str:
    return f"rw,nosuid,nodev,noexec,mode=1777,size={size}"


@dataclass(frozen=True)
class Recipe:
    name: str
    uid: int
    image: str
    memory: int
    entrypoint: str
    command: tuple[str, ...]
    tmpfs: dict[str, str]
    bind: Path | None = None


def recipe(service: str, image: str, root: Path) -> Recipe:
    if service == PG_SERVICE:
        password = root / "postgres-password"
        atomic_write(password, (secrets.token_hex(24) + "\n").encode("ascii"))
        # The private directory is host-owner-only. The single-file :Z bind
        # permits the isolated database UID to read its synthetic password.
        password.chmod(0o444)
        return Recipe("postgres", 999, image, 1024**3, "/bin/sh", ("-ec", PG_INIT),
                      {"/pgscratch": private_tmpfs("192m"), "/tmp": private_tmpfs("16m")}, password)
    if service == CDP_SERVICE:
        return Recipe("chromium", 65534, image, 2 * 1024**3, "/usr/bin/chromium-browser",
                      CDP_COMMAND, {"/tmp": private_tmpfs("128m")})
    raise ProfileError("Unknown fixture sidecar")


def _same_tmpfs(actual: dict, expected: dict) -> bool:
    def flags(spec):
        return set(spec.split(",")) - {"rprivate", "tmpcopyup"}

    return {target: flags(spec) for target, spec in actual.items()} == {
        target: flags(spec) for target, spec in expected.items()
    }


def _check_ports(details: dict) -> None:
    host = details["HostConfig"]
    net = details["NetworkSettings"]
    if host.get("PortBindings") or host.get("PublishAllPorts") or any((net.get("Ports") or {}).values()):
        raise ProfileError("A fixture sidecar has a published port")


def _check_mounts(details: dict, spec: Recipe) -> None:
    mounts = details.get("Mounts") or []
    if not _same_tmpfs(details["HostConfig"].get("Tmpfs") or {}, spec.tmpfs):
        raise ProfileError("Fixture sidecar tmpfs did not match")
    if spec.bind is None and not mounts:
        return
    if spec.bind is None or len(mounts) != 1:
        raise ProfileError("Fixture sidecar mounts did not match")
    mount = mounts[0]
    if (
        (mount.get("Type"), mount.get("Destination"), mount.get("Source"), mount.get("RW"))
        != ("bind", PASSWORD, str(spec.bind), False)
        or mount.get("Mode") != "Z"
        or mount.get("Propagation") != "rprivate"
        or not {"nosuid", "nodev", "noexec"} <= set(mount.get("Options") or ())
    ):
        raise ProfileError("Fixture password bind did not match")


def _mcs(details: dict) -> frozenset[str]:
    process = PROCESS_LABEL.fullmatch(details.get("ProcessLabel") or "")
    if process is None:
        raise ProfileError("Fixture sidecar lacks a confined SELinux process label")
    categories = frozenset(process.groups())
    mount = details.get("MountLabel") or ""
    if len(categories) != 2 or not mount.startswith("system_u:object_r:container_file_t:s0:"):
        raise ProfileError("Fixture sidecar lacks a confined SELinux mount label")
    if mount.split(":")[-1] != details["ProcessLabel"].split(":")[-1]:
        raise ProfileError("Fixture sidecar SELinux categories did not match")
    return categories


def _verify_pre_start(details: dict, spec: Recipe, worker: str) -> None:
    host = details["HostConfig"]
    config = details["Config"]
    _check_ports(details)
    _check_mounts(details, spec)
    if (
        details.get("Image", "").removeprefix("sha256:") != spec.image
        or config.get("User") != f"{spec.uid}:{spec.uid}"
        or details.get("Path") != spec.entrypoint or tuple(details.get("Args") or ()) != spec.command
        or host.get("NetworkMode") != f"container:{worker}"
        or host.get("IpcMode") != "private" or host.get("PidMode") not in ("", "private")
        or host.get("Privileged") or host.get("Devices") or host.get("CapAdd") or details.get("EffectiveCaps")
        or host.get("SecurityOpt") != ["no-new-privileges"] or not host.get("ReadonlyRootfs")
        or host.get("Memory") != spec.memory or host.get("MemorySwap") != spec.memory
        or host.get("CgroupMode") != "private" or host.get("PidsLimit") != 256
        or details["State"]["Running"]
    ):
        raise ProfileError("Fixture sidecar pre-start isolation did not match")


def _verify_effective(container_id: str, details: dict, spec: Recipe, worker: str) -> None:
    label = podman("exec", container_id, "cat", "/proc/self/attr/current").stdout.removesuffix(b"\0")
    if not details["State"]["Running"] or label != details["ProcessLabel"].encode("ascii"):
        raise ProfileError("Fixture sidecar is not running in the expected SELinux context")
    uid = podman("exec", container_id, "id", "-u").stdout.strip()
    if uid != str(spec.uid).encode("ascii"):
        raise ProfileError("Fixture sidecar does not run as the intended user")
    ns = podman("exec", container_id, "readlink", NETNS_PATH).stdout
    if ns != podman("exec", worker, "readlink", NETNS_PATH).stdout:
        raise ProfileError("Fixture sidecar did not join the worker network")
    for namespace in ("pid", "ipc", "mnt"):
        path = f"/proc/self/ns/{namespace}"
        if podman("exec", container_id, "readlink", path).stdout == podman("exec", worker, "readlink", path).stdout:
            raise ProfileError("Fixture sidecar shares a non-network worker namespace")
    paths = ("memory.max", "memory.swap.max", "pids.max")
    limits = podman("exec", container_id, "cat", *(f"/sys/fs/cgroup/{name}" for name in paths)).stdout.splitlines()
    if limits != [str(spec.memory).encode("ascii"), b"0", b"256"]:
        raise ProfileError("Fixture sidecar resource limits did not match")
    if spec.bind is not None:
        value = host_output("getfattr", "--only-values", "-n", "security.selinux", "--", str(spec.bind))
        if value.removesuffix(b"\0") != details["MountLabel"].encode("ascii"):
            raise ProfileError("Fixture password bind SELinux label did not match")


def _arguments(spec: Recipe, worker: str, name: str, run: str) -> list[str]:
    memory = f"{spec.memory}b"
    args = [
        "create", "--pull=never", "--name", name, "--label", f"{LABEL}={run}",
        "--label", f"{ROLE}={spec.name}", "--network", f"container:{worker}",
        "--user", f"{spec.uid}:{spec.uid}", "--ipc=private", "--pid=private",
        "--cap-drop=all", "--security-opt=no-new-privileges", "--read-only",
        "--read-only-tmpfs=false", "--image-volume=ignore", "--http-proxy=false", "--env-host=false",
        "--restart=no", "--log-driver=none", "--memory", memory, "--memory-swap", memory,
        "--pids-limit=256", "--cgroupns=private", "--env=HOME=/tmp", "--env=container=podman",
        "--entrypoint", spec.entrypoint,
    ]
    if spec.bind is not None:
        args.extend(("--volume", f"{spec.bind}:{PASSWORD}:ro,Z,nosuid,nodev,noexec"))
    for target, options in spec.tmpfs.items():
        args.extend(("--tmpfs", f"{target}:{options}"))
    return [*args, spec.image, *spec.command]


class Sidecars:
    """Keep sidecar ownership distinct from the reviewed worker/relay ledger."""

    def __init__(self, job: Job) -> None:
        self.job = job
        self.path = job.root / "sidecars.json"
        self.run = secrets.token_hex(16)
        self.names: dict[str, str] = {}
        self.ids: dict[str, str] = {}
        self.pending: set[str] = set()
        self.recorded: dict[str, str] = {}
        self.categories = {_mcs(job._identity(role, cid)) for role, cid in job.ids.items()}

    def _remember(self) -> None:
        record = {"label": f"{LABEL}={self.run}", "names": self.names, "ids": self.ids, "pending": sorted(self.pending)}
        atomic_write(self.path, json.dumps(record, sort_keys=True).encode("ascii") + b"\n")
        self.recorded = self.ids.copy()

    def _identity(self, role: str, cid: str) -> dict:
        details = inspected("container", "inspect", cid)
        labels = (details.get("Config") or {}).get("Labels") or {}
        if (
            (details.get("Id"), details.get("Name"), labels.get(LABEL), labels.get(ROLE))
            != (cid, self.names[role], self.run, role)
        ):
            raise ProfileError("Fixture sidecar identity did not match its receipt")
        return details

    def start(self, spec: Recipe) -> None:
        worker = self.job.ids["worker"]
        role = spec.name
        name = self.names[role] = f"oc-profile-{self.run}-{role}"
        self.pending.add(role)
        self._remember()
        cid = podman(*_arguments(spec, worker, name, self.run)).stdout.decode("ascii").strip()
        if not IMAGE_ID.fullmatch(cid) or cid in self.ids.values():
            raise ProfileError("Invalid sidecar create receipt")
        self.ids[role] = cid
        self.pending.remove(role)
        self._remember()
        details = self._identity(role, cid)
        _verify_pre_start(details, spec, worker)
        image_env = (inspected("image", "inspect", spec.image).get("Config") or {}).get("Env") or []
        expected_env = {**parse_env(image_env), "HOME": "/tmp", "container": "podman"}
        if parse_env(details["Config"]["Env"]) != expected_env:
            raise ProfileError("Fixture sidecar environment did not match pinned image and fixed settings")
        categories = _mcs(details)
        if categories in self.categories:
            raise ProfileError("Fixture sidecars require separate SELinux categories")
        self.categories.add(categories)
        podman("start", cid)
        _verify_effective(cid, self._identity(role, cid), spec, worker)

    def inventory(self) -> set[str]:
        result = podman("ps", "--all", "--quiet", "--no-trunc", "--filter", f"label={LABEL}={self.run}")
        ids = set(result.stdout.decode("ascii").splitlines())
        if any(not IMAGE_ID.fullmatch(cid) for cid in ids):
            raise ProfileError("Invalid sidecar inventory")
        return ids

    def close(self) -> None:
        for role, cid in reversed(tuple(self.recorded.items())):
            try:
                self._identity(role, cid)
                podman("rm", "--force", "--time", "0", cid, check=False)
            except (ProfileError, JobRuntimeError):
                # A fresh absence check determines the outcome.
                pass
        known = set(self.ids.values())
        if (
            self.pending
            or self.inventory()
            or any(podman("container", "exists", cid, check=False).returncode != 1 for cid in known)
        ):
            raise ProfileError("Fixture sidecar cleanup unconfirmed; receipt retained")
