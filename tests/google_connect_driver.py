"""Verify and open one sealed, synthetic Google connect case."""

from contextlib import ExitStack, contextmanager
import fcntl
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from types import ModuleType


CAPSULE = Path("/home/.oc-gemini-cold-proof")
SOURCE = CAPSULE / "source"
VENDOR = CAPSULE / "vendor"
TEST_HOME = Path("/home/oc-gemini-proof")
USER_RUNTIME = Path("/run/user")
ACCOUNT = "oc-gemini-proof"
DRIVER = "google_connect_driver.py"
LABELS = ("fixture-alpha", "fixture-beta", "fixture-no-flash")
CONFIG = "oc_providers/config.py"
ARTIFACT = ".local/share/oc-sandbox/google/standalone-1.5.2"
RUNTIME = (
    "oc_google/__init__.py",
    "oc_google/account_binding.py",
    "oc_google/auth_offer.py",
    "oc_google/cold_catalog.py",
    "oc_google/connect.py",
    "oc_google/enrollment.py",
    "oc_google/enrollment_session.py",
    "oc_google/metadata_destination.py",
    "oc_google/metadata_ingress.py",
    "oc_google/metadata_workflow.py",
    "oc_google/native_artifacts.py",
    "oc_google/native_browser.py",
    "oc_google/native_enrollment_acp.py",
    "oc_google/native_namespace.py",
    "oc_google/native_peer.py",
    "oc_google/native_proxy.py",
    "oc_google/native_service.py",
    "oc_google/native_transport.py",
    "oc_google/oauth_exchange.py",
    "oc_google/registration.py",
    "oc_google/token_diagnostic.py",
    "oc_google/workstation_io.py",
    "oc_orchestrator/__init__.py",
    "oc_orchestrator/capture.py",
    "oc_orchestrator/protocol.py",
    "oc_orchestrator/runtime.py",
    "oc_providers/__init__.py",
    "oc_providers/config.py",
    "oc_providers/contracts.py",
)
PROJECT_FILES = (*RUNTIME, DRIVER)
SOURCE_FILES = (*RUNTIME, f"tests/{DRIVER}", "tests/google-connect-fixture.py",
                "tests/google_registration_fixture.py", "tests/test_google_enrollment.py",
                "tests/test_google_oauth_exchange.py")
PINS = {
    "agy_acp_server.par": (714384320, "f472860b79c4816a32817e589afdb01cec0ca731e5fa428eae873b14be12387f"),
    "localharness_external": (139194456, "072fc497e7814b0e25a7d80109bceddacd815eb351d2e48ce579a05510e0cfdf"),
}
NFT = ("/usr/sbin/nft", "-j", "list", "table", "inet", "oc_gemini_fixture")
SHARED_FS = {"9p", "virtiofs", "vboxsf", "fuse.sshfs", "cifs", "nfs", "nfs4", "vmhgfs", "fuse.vmhgfs-fuse"}
SEALED = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
MAX_PROOF = 32768
HOME_BEFORE = "home-before.json"
HOME_RESULT = "home-result.json"
NATIVE_RESULT = "native-result.json"
NATIVE_POSITIVE = (b"Verified three named offline catalogs, two Flash candidates, zero prompts and six retired runtimes.\n"
                   b"Scoped native inventory empty.\n")
HOME_ENTRY_LIMIT = 131072
HOME_ABSENT = frozenset(map(Path, (".config/oc-sandbox", ".local/state/oc-sandbox", ARTIFACT)))
HOME_SAFE_PARENTS = frozenset(parent for reserved in HOME_ABSENT for parent in reserved.parents)
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class Refused(RuntimeError):
    """Fixture preflight refused with no private diagnostic payload."""


def require(condition):
    if not condition:
        raise Refused("Offline Google fixture seal or placement is unavailable.")


def checked_node(path, uid, *, directory=False, private=False):
    require(path.is_absolute() and path.resolve(strict=True) == path)
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    require(kind(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o022)
    require(directory or info.st_nlink == 1)
    if private:
        require(stat.S_IMODE(info.st_mode) == 0o700)
    return info


def protected(path, *, directory=False):
    for parent in reversed(path.parents):
        checked_node(parent, 0, directory=True)
    return checked_node(path, 0, directory=directory)


def read_proof(raw):
    def unique(pairs):
        values = dict(pairs)
        require(len(values) == len(pairs))
        return values

    require(len(raw) <= MAX_PROOF)
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict)
    return value


def proof_file(path):
    info = protected(path)
    require(stat.S_IMODE(info.st_mode) == 0o444 and info.st_size <= MAX_PROOF)
    return read_proof(path.read_bytes())


def digest(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def firewall(raw):
    objects = read_proof(raw)["nftables"]
    groups = {"table": [], "chain": [], "rule": []}
    for row in objects:
        (kind, body), = row.items()
        if kind == "metainfo":
            continue
        require(kind in groups)
        groups[kind].append({key: value for key, value in body.items() if key not in {"handle", "index"}})
    table = "oc_gemini_fixture"
    base = {"family": "inet", "table": table}
    require(groups["table"] == [{"family": "inet", "name": table}])
    require(groups["chain"] == [
        {**base, "name": hook, "type": "filter", "hook": hook, "prio": 0, "policy": "drop"}
        for hook in ("output", "forward")
    ])
    established = {"left": {"ct": {"key": "state"}}, "op": "==", "right": "established"}
    expected = [
        {**base, "chain": "output", "expr": [
            {"match": {"left": {"meta": {"key": "oifname"}}, "op": "==", "right": "lo"}}, {"accept": None},
        ]},
        {**base, "chain": "output", "expr": [
            {"match": {"left": {"ct": {"key": "direction"}}, "op": "==", "right": "reply"}},
            {"match": {"left": {"payload": {"protocol": "tcp", "field": "sport"}}, "op": "==", "right": 22}},
            {"match": established}, {"accept": None},
        ]},
    ]
    allowed = [expected[0], {**expected[1], "expr": [
        *expected[1]["expr"][:2], {"match": {**established, "op": "in"}}, {"accept": None},
    ]}]
    require(groups["rule"] in (expected, allowed))
    return sha256(json.dumps(groups | {"rule": expected}, sort_keys=True).encode()).hexdigest()


def bridge(*args):
    protected(Path("/usr/bin/host-spawn"))
    uid = os.getuid()
    runtime = f"/run/user/{uid}"
    command = ("/usr/bin/host-spawn", "--no-pty", "--env=", "/usr/bin/env", "-i", "PATH=/usr/bin:/bin",
               "LANG=C.UTF-8", f"HOME={TEST_HOME}", f"XDG_RUNTIME_DIR={runtime}",
               f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus", *args)
    return subprocess.run(command, cwd="/", check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
                          env={"HOME": str(TEST_HOME), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}).stdout


def root_host(*args):
    return subprocess.run(args, cwd="/", check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=10, env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8"}).stdout


def local_placement(run):
    mounts = run("/usr/bin/findmnt", "-rn", "-o", "FSTYPE").decode("ascii").splitlines()
    require(mounts and not SHARED_FS.intersection(mounts))
    boot = run("/usr/bin/cat", "/proc/sys/kernel/random/boot_id").decode("ascii").strip()
    require(re.fullmatch(r"[0-9a-f-]{36}", boot))
    return boot


def topology(host):
    require(host("/usr/bin/systemd-detect-virt", "--vm").strip() in (b"kvm", b"qemu"))
    require(host("/usr/bin/cat", "/sys/fs/selinux/enforce").strip() == b"1")
    return local_placement(host)


def identity(info):
    return [info.st_dev, info.st_ino]


def account():
    user = pwd.getpwnam(ACCOUNT)
    require(user.pw_uid > 0 and user.pw_dir == str(TEST_HOME))
    return user


def hex_text(value, length):
    return type(value) is str and len(value) == length and re.fullmatch(r"[a-f0-9]+", value) is not None


def sealed_case(record, uid):
    require(type(record) is dict and record.keys() == {"case", "root_id", "home_id", "sandbox_id", "config"})
    require(type(record["case"]) is str and hex_text(record["config"], 64))
    case = Path(record["case"])
    require(str(case) == record["case"] and case.parent == USER_RUNTIME / str(uid))
    require(re.fullmatch(r"oc-g-connect-fixture-[a-z0-9_]{8}", case.name))
    for key in ("root_id", "home_id", "sandbox_id"):
        pair = record[key]
        require(type(pair) is list and len(pair) == 2 and all(type(number) is int for number in pair))
        require(pair[0] >= 0 and pair[1] > 0)
    return case


def validate_seal(seal):
    require(type(seal) is dict and seal.keys() == {"version", "uid", "boot", "tree", "source", "firewall", "cases"})
    require(type(seal["version"]) is int and seal["version"] == 1 and type(seal["uid"]) is int and seal["uid"] > 0)
    require(type(seal["boot"]) is str and re.fullmatch(r"[0-9a-f-]{36}", seal["boot"]))
    require(hex_text(seal["tree"], 40) and hex_text(seal["firewall"], 64))
    source = seal["source"]
    require(type(source) is dict and set(source) == set(SOURCE_FILES))
    require(all(hex_text(checksum, 64) for checksum in source.values()))
    cases = seal["cases"]
    require(type(cases) is dict and set(cases) == set(LABELS))
    require(len({sealed_case(record, seal["uid"]) for record in cases.values()}) == len(LABELS))


def guest():
    protected(CAPSULE, directory=True)
    seal = proof_file(CAPSULE / "seal.json")
    validate_seal(seal)
    user = account()
    require(seal["uid"] == os.getuid() == os.geteuid() == user.pw_uid)
    require(topology(bridge) == seal["boot"] == local_placement(root_host))
    require(bridge("/usr/bin/id", "-ru").strip() == str(user.pw_uid).encode("ascii"))
    for namespace in ("net", "pid"):
        path = f"/proc/self/ns/{namespace}"
        require(bridge("/usr/bin/readlink", path).strip() == os.readlink(path).encode("ascii"))
    require(firewall(bridge("/usr/bin/sudo", "-n", *NFT)) == seal["firewall"])
    runtime = USER_RUNTIME / str(user.pw_uid)
    info = checked_node(runtime, user.pw_uid, directory=True, private=True)
    placement = f"{info.st_dev}:{info.st_ino}:{info.st_uid}:{info.st_mode:x}".encode("ascii")
    require(bridge("/usr/bin/stat", "-c", "%d:%i:%u:%f", "--", str(runtime)).strip() == placement)
    require(source_inventory() == seal["source"])
    return seal


def source_inventory():
    projected = set(SOURCE_FILES)
    directories = {str(parent) for name in projected for parent in Path(name).parents}
    seen = {str(path.relative_to(SOURCE)) for path in SOURCE.rglob("*")}
    require(seen == projected | (directories - {"."}))
    expected = {}
    for name in SOURCE_FILES:
        path = SOURCE / name
        require(stat.S_IMODE(protected(path).st_mode) == 0o444)
        expected[name] = digest(path)
    return expected


def vendor_pair():
    require(set(path.name for path in VENDOR.iterdir()) == set(PINS))
    for name, (size, checksum) in PINS.items():
        path = VENDOR / name
        info = protected(path)
        require(stat.S_IMODE(info.st_mode) == 0o444 and info.st_size == size and digest(path) == checksum)
    return VENDOR


def metadata(info):
    return (info.st_mode, info.st_uid, info.st_gid, info.st_dev, info.st_ino, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def record_home_node(checksum, relative, node):
    require(relative not in HOME_ABSENT)
    require(relative not in HOME_SAFE_PARENTS or stat.S_ISDIR(node[0]))
    path = os.fsencode(relative)
    checksum.update(len(path).to_bytes(4, "big"))
    checksum.update(path)
    checksum.update(repr(node).encode("ascii") + b"\n")


def home_entries(fd, relative, checksum, remaining, *, depth):
    require(depth <= 64)
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            require(remaining > 0)
            remaining -= 1
            names.append(entry.name)
    for name in sorted(names, key=os.fsencode):
        path = relative / name
        original = metadata(os.stat(name, dir_fd=fd, follow_symlinks=False))
        record_home_node(checksum, path, original)
        if stat.S_ISDIR(original[0]):
            child = os.open(name, DIRECTORY, dir_fd=fd)
            try:
                require(metadata(os.fstat(child)) == original)
                remaining = home_entries(child, path, checksum, remaining, depth=depth + 1)
                require(metadata(os.fstat(child)) == original)
            finally:
                os.close(child)
        require(metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) == original)
    return remaining


def home_snapshot(uid):
    initial = metadata(checked_node(TEST_HOME, uid, directory=True))
    fd = os.open(TEST_HOME, DIRECTORY)
    checksum = sha256()
    try:
        require(metadata(os.fstat(fd)) == initial)
        root = Path(".")
        record_home_node(checksum, root, initial)
        remaining = home_entries(fd, root, checksum, HOME_ENTRY_LIMIT - 1, depth=0)
        require(metadata(os.fstat(fd)) == initial == metadata(TEST_HOME.lstat()))
    finally:
        os.close(fd)
    return HOME_ENTRY_LIMIT - remaining, checksum.hexdigest()


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def nofollow_stat(name, directory):
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def require_absent_beneath(root_fd, relative):
    with ExitStack() as pins:
        parent = root_fd
        root = metadata(os.fstat(parent))
        links = []
        for name in relative.parts[:-1]:
            info = nofollow_stat(name, parent)
            if info is None:
                break
            require(stat.S_ISDIR(info.st_mode))
            child = os.open(name, DIRECTORY, dir_fd=parent)
            pins.callback(os.close, child)
            observed = metadata(info)
            require(metadata(os.fstat(child)) == observed)
            links.append((parent, name, child, observed))
            parent = child
        else:
            require(nofollow_stat(relative.name, parent) is None)
        for parent, name, child, observed in reversed(links):
            current = nofollow_stat(name, parent)
            require(current is not None and metadata(current) == metadata(os.fstat(child)) == observed)
        require(metadata(os.fstat(root_fd)) == root)


def ordinary_provider_roots(uid, expected_id):
    initial = checked_node(TEST_HOME, uid, directory=True)
    fd = os.open(TEST_HOME, DIRECTORY)
    try:
        require(identity(initial) == identity(os.fstat(fd)) == expected_id)
        for relative in HOME_ABSENT:
            require_absent_beneath(fd, relative)
        require(metadata(os.fstat(fd)) == metadata(initial) == metadata(TEST_HOME.lstat()))
    finally:
        os.close(fd)


def home_evidence_scope(seal):
    seal_file = CAPSULE / "seal.json"
    require(proof_file(seal_file) == seal)
    home = checked_node(TEST_HOME, seal["uid"], directory=True)
    return {"seal": digest(seal_file), "tree": seal["tree"], "boot": seal["boot"],
            "uid": seal["uid"], "home_id": identity(home)}


def verified_home_before(scope):
    require(absent(CAPSULE / HOME_RESULT) and absent(CAPSULE / NATIVE_RESULT))
    before = proof_file(CAPSULE / HOME_BEFORE)
    require(before.keys() == {"version", "scope", "entries", "sha256"})
    require(type(before["version"]) is int and before["version"] == 1 and before["scope"] == scope)
    require(type(before["scope"]["uid"]) is int and all(type(item) is int for item in before["scope"]["home_id"]))
    require(type(before["entries"]) is int and 1 <= before["entries"] <= HOME_ENTRY_LIMIT)
    require(hex_text(before["sha256"], 64))
    return before


def check_home_before(seal):
    scope = home_evidence_scope(seal)
    verified_home_before(scope)
    ordinary_provider_roots(scope["uid"], scope["home_id"])


def root_home_scope():
    isolated()
    require(os.getuid() == os.geteuid() == 0)
    require(Path(__file__).absolute() == SOURCE / "tests" / DRIVER)
    protected(Path(__file__).absolute())
    seal = proof_file(CAPSULE / "seal.json")
    validate_seal(seal)
    require(seal["uid"] == account().pw_uid and topology(root_host) == seal["boot"])
    require(firewall(root_host(*NFT)) == seal["firewall"] and source_inventory() == seal["source"])
    return seal, home_evidence_scope(seal)


def capture_home_evidence(scope):
    uid = scope["uid"]
    require(identity(checked_node(TEST_HOME, uid, directory=True)) == scope["home_id"])
    entries, checksum = home_snapshot(uid)
    require(identity(checked_node(TEST_HOME, uid, directory=True)) == scope["home_id"])
    return {"entries": entries, "sha256": checksum}


def begin_home_attestation():
    seal, scope = root_home_scope()
    require(all(absent(CAPSULE / name) for name in (HOME_BEFORE, HOME_RESULT, NATIVE_RESULT)))
    for label in LABELS:
        with case_paths(seal, label, pristine=True):
            pass
    before = {"version": 1, "scope": scope, **capture_home_evidence(scope)}
    write_protected(CAPSULE / HOME_BEFORE, json.dumps(before, sort_keys=True).encode("ascii"))


def capture_home_after():
    _, scope = root_home_scope()
    verified_home_before(scope)
    before = digest(CAPSULE / HOME_BEFORE)
    return {"scope": scope, "home_before_sha256": before, "after": capture_home_evidence(scope)}


def finish_home_attestation(exit_status, child_output, controller_verified, captured):
    require(type(exit_status) is int and exit_status == 0)
    require(type(child_output) is bytes and child_output == NATIVE_POSITIVE and controller_verified is True)
    seal, scope = root_home_scope()
    before = verified_home_before(scope)
    before_path = CAPSULE / HOME_BEFORE
    before_digest = digest(before_path)
    require(captured.keys() == {"scope", "home_before_sha256", "after"}
            and captured["scope"] == scope and captured["home_before_sha256"] == before_digest)
    after = captured["after"]
    require(type(after) is dict and after.keys() == {"entries", "sha256"}
            and type(after["entries"]) is int and 1 <= after["entries"] <= HOME_ENTRY_LIMIT
            and hex_text(after["sha256"], 64))
    require(all(absent(sealed_case(record, seal["uid"])) for record in seal["cases"].values()))
    stable = after == {"entries": before["entries"], "sha256": before["sha256"]}
    native = {"version": 1, "scope": scope, "exit_status": exit_status,
              "output_sha256": sha256(child_output).hexdigest(), "verified": True}
    native_path = CAPSULE / NATIVE_RESULT
    native_payload = json.dumps(native, sort_keys=True).encode("ascii")
    write_protected(native_path, native_payload)
    require(proof_file(native_path) == native and digest(native_path) == sha256(native_payload).hexdigest())
    require(proof_file(before_path) == before and digest(before_path) == before_digest)
    result = {"version": 1, "scope": scope, "exit_status": exit_status, "after": after,
              "native_result_sha256": sha256(native_payload).hexdigest(),
              "home_before_sha256": before_digest, "home_unchanged": stable, "completed": stable}
    write_protected(CAPSULE / HOME_RESULT, json.dumps(result, sort_keys=True).encode("ascii"))
    if stable:
        print("Trusted controller verified the ordinary dedicated home unchanged.")
    return 0 if stable else 1


def record_incomplete_home_attestation(phase):
    require(phase in ("ready", "baseline", "child", "capture", "release", "persist"))
    _, scope = root_home_scope()
    path = CAPSULE / HOME_RESULT
    if absent(path):
        result = {"version": 1, "scope": scope, "phase": phase, "after": None,
                  "home_unchanged": None, "completed": False, "custody": "unconfirmed"}
        write_protected(path, json.dumps(result, sort_keys=True).encode("ascii"))


def private_inventory(uid):
    base = USER_RUNTIME / str(uid)
    require(not any(re.fullmatch(r"\.?oc-g-[0-9a-f]{24}(?:-retire)?", leaf.name) for leaf in base.iterdir()))
    require(not bridge("/usr/bin/systemctl", "--user", "list-units", "--all", "--plain",
                       "--full", "--no-legend", "oc-google-acp-*").strip())


def project_config(original, home):
    begin = "def _account_home() -> Path:\n"
    boundary = "\n\ndef default_config_dir()"
    require(original.count(begin) == 1 and original.count(boundary) == 1)
    prefix, rest = original.split(begin)
    _, suffix = rest.split(boundary)
    return prefix + begin + f"    return Path({str(home)!r})" + boundary + suffix


def write_protected(path, payload):
    with path.open("xb") as stream:
        stream.write(payload)
        os.fchmod(stream.fileno(), 0o444)


def install_seal(tree):
    """Create fixed case bindings inside the disposable guest as root."""
    require(os.getuid() == os.geteuid() == 0 and re.fullmatch(r"[a-f0-9]{40}", tree))
    user = account()
    uid, gid = user.pw_uid, user.pw_gid
    boot = topology(root_host)
    policy = firewall(root_host(*NFT))
    source = source_inventory()
    vendor_pair()
    home_snapshot(uid)
    cases = CAPSULE / "case-config"
    cases.mkdir(mode=0o755)
    records = {}
    runtime = USER_RUNTIME / str(uid)
    checked_node(runtime, uid, directory=True, private=True)
    for label in LABELS:
        case = Path(tempfile.mkdtemp(prefix="oc-g-connect-fixture-", dir=runtime))
        home = case / "home"
        sandbox = home / "opencode-sandbox"
        home.mkdir(mode=0o700)
        sandbox.mkdir(mode=0o700)
        for directory in (sandbox, home, case):
            os.chown(directory, uid, gid)
        leaf = cases / label / "config.py"
        leaf.parent.mkdir(mode=0o755)
        code = project_config((SOURCE / CONFIG).read_text(encoding="utf-8"), home)
        write_protected(leaf, code.encode("utf-8"))
        records[label] = {"case": str(case), "root_id": identity(case.stat()), "home_id": identity(home.stat()),
                          "sandbox_id": identity(sandbox.stat()), "config": digest(leaf)}
    proof = {"version": 1, "uid": uid, "boot": boot, "tree": tree, "source": source,
             "firewall": policy, "cases": records}
    validate_seal(proof)
    write_protected(CAPSULE / "seal.json", json.dumps(proof, sort_keys=True).encode("ascii"))


def exact_children(fd, expected):
    original = metadata(os.fstat(fd))
    pending = set(expected)
    with os.scandir(fd) as children:
        for child in children:
            require(child.name in pending)
            pending.remove(child.name)
    require(not pending and metadata(os.fstat(fd)) == original)


@contextmanager
def case_paths(seal, label, *, pristine=False):
    require(label in LABELS)
    record = seal["cases"][label]
    case = sealed_case(record, seal["uid"])
    home, sandbox = case / "home", case / "home/opencode-sandbox"
    with ExitStack() as pins:
        parent = None
        for path, key in ((case, "root_id"), (home, "home_id"), (sandbox, "sandbox_id")):
            info = checked_node(path, seal["uid"], directory=True, private=True)
            fd = os.open(str(path) if parent is None else path.name, DIRECTORY, dir_fd=parent)
            pins.callback(os.close, fd)
            require(identity(info) == identity(os.fstat(fd)) == record[key])
            if key == "sandbox_id":
                exact_children(fd, ())
            elif pristine:
                exact_children(fd, ("home",) if key == "root_id" else ("opencode-sandbox",))
            parent = fd
        yield case, home, sandbox


def copied_source(path, uid, files):
    require(path.resolve(strict=True) == path)
    checked_node(path, uid, directory=True)
    expected = set(files) - {CONFIG}
    dirs = {str(parent) for name in expected for parent in Path(name).parents}
    observed = {}
    for child in path.rglob("*"):
        relative = str(child.relative_to(path))
        if relative in dirs:
            info = checked_node(child, uid, directory=True)
            require(stat.S_IMODE(info.st_mode) == 0o500)
        else:
            require(relative in expected)
            require(stat.S_IMODE(checked_node(child, uid).st_mode) == 0o400)
            observed[relative] = digest(child)
    require(set(observed) == expected and stat.S_IMODE(path.stat().st_mode) == 0o500)
    return observed


def prepare_descriptor(case, label, seal):
    root = case / "source"
    files = copied_source(root, seal["uid"], PROJECT_FILES)
    fd = os.memfd_create("oc-google-fixture", os.MFD_ALLOW_SEALING)
    try:
        data = json.dumps({"tree": seal["tree"], "label": label, "case": str(case), "files": files,
                           "config": seal["cases"][label]["config"]}, sort_keys=True).encode("ascii")
        require(len(data) <= MAX_PROOF and os.write(fd, data) == len(data))
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALED)
        os.set_inheritable(fd, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_descriptor(fd):
    require(fd >= 3 and fcntl.fcntl(fd, fcntl.F_GET_SEALS) == SEALED)
    data = os.pread(fd, MAX_PROOF + 1, 0)
    return read_proof(data)


def load_projected_config(seal, label, home):
    target = CAPSULE / "case-config" / label / "config.py"
    require(stat.S_IMODE(protected(target).st_mode) == 0o444)
    expected = project_config((SOURCE / CONFIG).read_text(encoding="utf-8"), home).encode("utf-8")
    payload = target.read_bytes()
    require(payload == expected and sha256(payload).hexdigest() == seal["cases"][label]["config"])
    name = "oc_providers.config"
    require(name not in sys.modules)
    module = ModuleType(name)
    module.__file__ = str(target)
    module.__package__ = "oc_providers"
    sys.modules[name] = module
    exec(compile(payload, str(target), "exec"), module.__dict__)
    return module


def verify_case_vendor(directory, uid):
    for name, (size, checksum) in PINS.items():
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        fd = os.open(name, flags, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_size == size and info.st_uid in (0, uid)
                    and info.st_nlink == 1 and not info.st_mode & 0o022)
            content = sha256()
            remaining = size
            while remaining:
                chunk = stream.read(min(remaining, 1024 * 1024))
                require(chunk)
                content.update(chunk)
                remaining -= len(chunk)
            require(not stream.read(1) and content.hexdigest() == checksum)
            require(metadata(os.fstat(fd)) == metadata(info)
                    == metadata(os.stat(name, dir_fd=directory, follow_symlinks=False)))


def case_precheck(config, home, sandbox, label, uid):
    from oc_google import connect, metadata_destination

    require(getattr(metadata_destination, "SYNTHETIC_FIXTURE_EXCHANGE", None) is True
            and not hasattr(metadata_destination, "_request") and not hasattr(metadata_destination, "_resolve"))
    require(config._account_home() == home)
    config_dir = home / ".config/oc-sandbox"
    artifact = home / ARTIFACT
    require(config.default_config_dir() == config_dir and os.environ.get("HOME") == str(home))
    require(all(path.is_relative_to(home) and not path.is_relative_to(sandbox) for path in (config_dir, artifact)))
    config_info = checked_node(config_dir, uid, directory=True, private=True)
    sandbox_info = checked_node(sandbox, uid, directory=True, private=True)
    checked_node(config_dir / "providers.toml", uid)
    expected = checked_node(artifact, uid, directory=True, private=True)
    require(len({tuple(identity(info)) for info in (config_info, sandbox_info, expected)}) == 3)
    current = config.load_provider_config()
    require(current is not None and len(current.instances) == 1)
    spec = current.get("google", label)
    require(spec is not None and spec.enabled and spec.auth_mode == "subscription" and spec.cli_path is None)
    with connect._artifacts() as fd:
        require(os.path.samestat(expected, os.fstat(fd)))
        verify_case_vendor(fd, uid)


def isolated():
    require(sys.executable == "/usr/bin/python3" and sys.flags.isolated
            and sys.flags.dont_write_bytecode and sys.flags.no_site)
    for item in sys.path:
        path = Path(item)
        require(path.is_absolute() and (path.is_relative_to("/usr/lib") or path.is_relative_to("/usr/lib64")))


def main():
    try:
        isolated()
        _, action, label, descriptor = sys.argv
        driver = Path(__file__).absolute()
        require(driver.name == DRIVER and driver.parent.name == "source"
                and driver.parent.parent.parent == USER_RUNTIME / str(os.getuid()))
        require(action == "--fixture" and label in LABELS and descriptor.isascii() and descriptor.isdecimal())
        fd = int(descriptor)
        try:
            projection = read_descriptor(fd)
        finally:
            if fd >= 3:
                os.close(fd)
        seal = guest()
        check_home_before(seal)
        with case_paths(seal, label) as (case, home, sandbox):
            source = case / "source"
            require(Path(__file__).absolute() == source / DRIVER)
            require(projection == {"tree": seal["tree"], "label": label, "case": str(case),
                                   "files": copied_source(source, seal["uid"], PROJECT_FILES),
                                   "config": seal["cases"][label]["config"]})
            require(not (source / CONFIG).exists())
            sys.path.append(str(source))
            config = load_projected_config(seal, label, home)
            case_precheck(config, home, sandbox, label, seal["uid"])
            with case_paths(seal, label):
                return run_connect(label)
    except (OSError, ImportError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError):
        print("Offline Google fixture refused before enrollment.", file=sys.stderr)
        return 1


def run_connect(label):
    from oc_google.connect import ConnectError, CustodyUnconfirmed, connect_for, needs_custody_inspection
    from oc_google.native_service import NativeRetirementUnconfirmed

    try:
        return connect_for(label)
    except (OSError, ValueError, RuntimeError, KeyboardInterrupt) as error:
        interrupted = isinstance(error, KeyboardInterrupt)
        cleanup_only = isinstance(error, (CustodyUnconfirmed, NativeRetirementUnconfirmed))
        if cleanup_only:
            message = "Google enrollment cleanup requires inspection."
        elif isinstance(error, ConnectError):
            message = str(error)
        elif interrupted:
            message = "Google sign-in cancelled."
        else:
            message = "Workstation enrollment did not complete."
        print(f"oc-sandbox google: {message}", file=sys.stderr)
        if not cleanup_only and needs_custody_inspection(error):
            print("oc-sandbox google: Google enrollment cleanup requires inspection.", file=sys.stderr)
        return 130 if interrupted else 1



if __name__ == "__main__":
    raise SystemExit(main())
