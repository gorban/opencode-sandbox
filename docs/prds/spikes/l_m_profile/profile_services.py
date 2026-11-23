"""Create the selected sidecars in the existing local proof's worker network."""

from dataclasses import dataclass
import json
from pathlib import Path
import re
import secrets

from profile_plan import CDP_SERVICE, PG_SERVICE, ProfileError
from runtime import (
    IMAGE_ID, NETWORK_LEAK_FIELDS, PROCESS_LABEL, Job, JobRuntimeError, atomic_write, host_output, inspected,
    parse_env, podman,
)


LABEL = "io.oc-sandbox.profile-poc"
ROLE = f"{LABEL}.role"
PASSWORD = "/run/profile-pg-password"
PASSWORD_FILE = "postgres-password"
PG_DATA = "/pgscratch/data"
SIDECAR_STATE = "/scratch"
SERVICE_ROLE = {PG_SERVICE: "postgres", CDP_SERVICE: "chromium"}
NAMESPACES = ("net", "pid", "ipc", "mnt")
# The qualified rootless Podman host expands --cap-drop=all to its default set.
PODMAN_DEFAULT_CAPS = frozenset({
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_NET_BIND_SERVICE",
    "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_CHROOT",
})
PG_INIT = (
    f"initdb -D {PG_DATA} --username=postgres --auth-local=peer --auth-host=scram-sha-256 "
    "--pwfile=/run/profile-pg-password --no-sync --no-instructions >/dev/null; "
    f"exec postgres -D {PG_DATA} -c listen_addresses=127.0.0.1 -c unix_socket_directories={SIDECAR_STATE} "
    "-c password_encryption=scram-sha-256"
)
CDP_COMMAND = (
    "--headless", "--no-sandbox", "--disable-gpu", "--disable-background-networking",
    "--no-first-run", f"--user-data-dir={SIDECAR_STATE}/chromium", "--remote-debugging-address=127.0.0.1",
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
        password = root / PASSWORD_FILE
        atomic_write(password, (secrets.token_hex(24) + "\n").encode("ascii"))
        # The private directory is host-owner-only. The single-file :Z bind
        # permits the isolated database UID to read its synthetic password.
        password.chmod(0o444)
        return Recipe(SERVICE_ROLE[service], 999, image, 1024**3, "/bin/sh", ("-ec", PG_INIT),
                      {"/pgscratch": private_tmpfs("192m"), SIDECAR_STATE: private_tmpfs("16m")}, password)
    if service == CDP_SERVICE:
        return Recipe(SERVICE_ROLE[service], 65534, image, 2 * 1024**3, "/usr/bin/chromium-browser",
                      CDP_COMMAND, {SIDECAR_STATE: private_tmpfs("128m")})
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
    networks = net.get("Networks") or {}
    if (
        set(networks) != {"none"}
        or any(net.get(field) for field in NETWORK_LEAK_FIELDS)
        or any((networks["none"] or {}).get(field) for field in NETWORK_LEAK_FIELDS)
    ):
        raise ProfileError("A fixture sidecar has unexpected network settings")


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
    _check_sandbox_settings(details)
    _check_cgroup(host, spec.memory)
    if (
        details.get("Image", "").removeprefix("sha256:") != spec.image
        or config.get("User") != f"{spec.uid}:{spec.uid}"
        or details.get("Path") != spec.entrypoint or tuple(details.get("Args") or ()) != spec.command
        or host.get("NetworkMode") != f"container:{worker}"
        or host.get("IpcMode") != "private" or host.get("PidMode") != "private"
        or details["State"]["Running"]
    ):
        raise ProfileError("Fixture sidecar pre-start isolation did not match")


def _check_sandbox_settings(details: dict) -> None:
    host = details["HostConfig"]
    drops = {cap.upper() for cap in host.get("CapDrop") or ()}
    if (
        host.get("Privileged") or host.get("Devices") or host.get("CapAdd") or details.get("EffectiveCaps")
        or drops not in ({"ALL"}, PODMAN_DEFAULT_CAPS)
        or host.get("SecurityOpt") != ["no-new-privileges"] or not host.get("ReadonlyRootfs")
    ):
        raise ProfileError("Fixture sidecar sandbox settings did not match")


def _check_cgroup(host: dict, memory: int) -> None:
    if (
        host.get("Memory") != memory or host.get("MemorySwap") != memory
        or host.get("CgroupMode") != "private" or host.get("PidsLimit") != 256
    ):
        raise ProfileError("Fixture sidecar resource limits did not match")


def _namespace_ids(container_id: str | None = None) -> dict[str, bytes]:
    paths = tuple(f"/proc/self/ns/{name}" for name in NAMESPACES)
    if container_id is None:
        output = host_output("readlink", *paths)
    else:
        command = 'for path do readlink "$path"; done'
        output = podman("exec", container_id, "/bin/sh", "-ec", command, "--", *paths).stdout
    identities = output.splitlines()
    if len(identities) != len(NAMESPACES):
        raise ProfileError("Fixture process returned an incomplete namespace identity")
    result = dict(zip(NAMESPACES, identities, strict=True))
    for name, value in result.items():
        if not re.fullmatch(rb"%s:\[\d+\]" % name.encode("ascii"), value):
            raise ProfileError("Fixture process returned an invalid namespace identity")
    return result


def _verify_effective(container_id: str, details: dict, spec: Recipe) -> None:
    label = podman("exec", container_id, "cat", "/proc/self/attr/current").stdout.removesuffix(b"\0")
    if not details["State"]["Running"] or label != details["ProcessLabel"].encode("ascii"):
        raise ProfileError("Fixture sidecar is not running in the expected SELinux context")
    uid = podman("exec", container_id, "id", "-u").stdout.strip()
    if uid != str(spec.uid).encode("ascii"):
        raise ProfileError("Fixture sidecar does not run as the intended user")
    status = podman("exec", container_id, "cat", "/proc/self/status").stdout.splitlines()
    if b"CapEff:\t0000000000000000" not in status or b"NoNewPrivs:\t1" not in status:
        raise ProfileError("Fixture sidecar effective capability settings did not match")
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
        "--pids-limit=256", "--cgroupns=private", f"--env=HOME={SIDECAR_STATE}",
        f"--env=TMPDIR={SIDECAR_STATE}", "--env=container=podman",
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
        worker = _namespace_ids(job.ids["worker"])
        self.network_namespace = worker["net"]
        self.namespaces = [_namespace_ids(), worker, _namespace_ids(job.ids["relay"])]

    def _verify_namespaces(self, cid: str) -> None:
        current = _namespace_ids(cid)
        if current["net"] != self.network_namespace:
            raise ProfileError("Fixture sidecar did not join the worker network")
        for name in ("pid", "ipc", "mnt"):
            if any(other[name] == current[name] for other in self.namespaces):
                raise ProfileError("Fixture sidecar shares a non-network namespace")
        self.namespaces.append(current)

    def _remember(self) -> None:
        record = {"label": f"{LABEL}={self.run}", "names": self.names, "ids": self.ids, "pending": sorted(self.pending)}
        atomic_write(self.path, json.dumps(record, sort_keys=True).encode("ascii") + b"\n")
        self.recorded = self.ids.copy()

    def _identity(self, role: str, cid: str) -> dict:
        details = inspected("container", "inspect", cid)
        labels = (details.get("Config") or {}).get("Labels") or {}
        if (
            (details.get("Id"), (details.get("Name") or "").removeprefix("/"), labels.get(LABEL), labels.get(ROLE))
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
        if not IMAGE_ID.fullmatch(cid) or cid in self.ids.values() or cid in self.job.ids.values():
            raise ProfileError("Invalid sidecar create receipt")
        self.ids[role] = cid
        self.pending.remove(role)
        self._remember()
        details = self._identity(role, cid)
        _verify_pre_start(details, spec, worker)
        image_env = (inspected("image", "inspect", spec.image).get("Config") or {}).get("Env") or []
        expected_env = {**parse_env(image_env), "HOME": SIDECAR_STATE, "TMPDIR": SIDECAR_STATE, "container": "podman"}
        if parse_env(details["Config"]["Env"]) != expected_env:
            raise ProfileError("Fixture sidecar environment did not match pinned image and fixed settings")
        categories = _mcs(details)
        if categories in self.categories:
            raise ProfileError("Fixture sidecars require separate SELinux categories")
        self.categories.add(categories)
        podman("start", cid)
        _verify_effective(cid, self._identity(role, cid), spec)
        self._verify_namespaces(cid)

    def inventory(self) -> set[str]:
        result = podman("ps", "--all", "--quiet", "--no-trunc", "--filter", f"label={LABEL}={self.run}")
        ids = set(result.stdout.decode("ascii").splitlines())
        if any(not IMAGE_ID.fullmatch(cid) for cid in ids):
            raise ProfileError("Invalid sidecar inventory")
        return ids

    def _recover_unrecorded_ids(self) -> None:
        for cid in self.inventory():
            try:
                details = inspected("container", "inspect", cid)
                labels = (details.get("Config") or {}).get("Labels") or {}
                role = labels.get(ROLE)
                if (
                    role in self.names and role not in self.recorded
                    and self.ids.get(role, cid) == cid and cid not in self.job.ids.values()
                ):
                    self._identity(role, cid)
                    self.ids[role] = cid
                    self._remember()
            except (OSError, ProfileError, JobRuntimeError):
                # Refuse this candidate without skipping other exact receipts.
                continue

    def close(self) -> None:
        if self.pending or self.ids != self.recorded:
            try:
                self._recover_unrecorded_ids()
            except (ProfileError, JobRuntimeError):
                # Verified receipts for other roles can still be used below.
                pass
        for role, cid in reversed(tuple(self.recorded.items())):
            try:
                self._identity(role, cid)
                podman("rm", "--force", "--time", "0", cid, check=False)
            except (ProfileError, JobRuntimeError):
                # A fresh absence check determines the outcome.
                pass
        known = set(self.ids.values())
        remaining = self.inventory()
        present = [cid for cid in known if podman("container", "exists", cid, check=False).returncode != 1]
        if not remaining and not present and SERVICE_ROLE[PG_SERVICE] not in self.pending:
            (self.job.root / PASSWORD_FILE).unlink(missing_ok=True)
        if self.pending or remaining or present:
            raise ProfileError("Fixture sidecar cleanup unconfirmed; receipt retained")
