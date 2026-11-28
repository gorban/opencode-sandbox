"""Verify and open one sealed, synthetic Google connect case."""

from contextlib import ExitStack, contextmanager
import fcntl
from hashlib import file_digest, sha256
from hmac import compare_digest, digest as hmac_digest
import json
import os
from pathlib import Path
import pwd
import re
import select
import stat
import subprocess
import sys
import time
from secrets import token_hex
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
HOME_BEFORE_STAGE = ".home-before-staging"
HOME_RESULT = "home-result.json"
NATIVE_RESULT = "native-result.json"
ALLOCATION_ATTEMPT = "allocation-attempt.json"
START_BYTES = 32
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


def validate_allocation_attempt(attempt):
    require(attempt.keys() == {
        "version", "binding", "capsule", "boot", "tree", "manifest", "account", "controller", "allocation",
    })
    require(type(attempt["version"]) is int and attempt["version"] == 2)
    require(all(hex_text(attempt[name], 64) for name in ("binding", "manifest", "allocation"))
            and hex_text(attempt["capsule"], 32) and hex_text(attempt["tree"], 40)
            and type(attempt["boot"]) is str
            and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", attempt["boot"]))
    account_record = attempt["account"]
    require(type(account_record) is dict and account_record.keys() == {"uid", "gid"}
            and all(type(number) is int and number > 0 for number in account_record.values()))
    owner = attempt["controller"]
    require(type(owner) is dict and owner.keys() == {"pid", "start_ticks", "interpreter", "script", "argv"})
    require(type(owner["pid"]) is int and owner["pid"] > 1
            and type(owner["start_ticks"]) is int and owner["start_ticks"] > 0
            and hex_text(owner["script"], 64) and hex_text(owner["argv"], 64))
    interpreter = owner["interpreter"]
    require(type(interpreter) is list and len(interpreter) == 2 and all(type(part) is int for part in interpreter))
    require(interpreter[0] >= 0 and interpreter[1] > 0)


def home_evidence_scope(seal):
    seal_file = CAPSULE / "seal.json"
    require(proof_file(seal_file) == seal)
    attempt_path = CAPSULE / ALLOCATION_ATTEMPT
    attempt = proof_file(attempt_path)
    validate_allocation_attempt(attempt)
    require(attempt["boot"] == seal["boot"] and attempt["tree"] == seal["tree"]
            and attempt["account"]["uid"] == seal["uid"])
    home = checked_node(TEST_HOME, seal["uid"], directory=True)
    return {"seal": digest(seal_file), "attempt": digest(attempt_path), "tree": seal["tree"], "boot": seal["boot"],
            "uid": seal["uid"], "home_id": identity(home)}


def verified_home_before(scope):
    require(absent(CAPSULE / HOME_RESULT) and absent(CAPSULE / NATIVE_RESULT))
    before = proof_file(CAPSULE / HOME_BEFORE)
    require(before.keys() == {"version", "scope", "entries", "sha256", "start_sha256", "case_start_sha256"})
    require(type(before["version"]) is int and before["version"] == 2 and before["scope"] == scope)
    require(type(before["scope"]["uid"]) is int and all(type(item) is int for item in before["scope"]["home_id"]))
    require(type(before["entries"]) is int and 1 <= before["entries"] <= HOME_ENTRY_LIMIT)
    require(hex_text(before["sha256"], 64) and hex_text(before["start_sha256"], 64))
    cases = before["case_start_sha256"]
    require(type(cases) is dict and set(cases) == set(LABELS))
    require(all(hex_text(checksum, 64) for checksum in cases.values()))
    return before


def check_home_before(seal):
    scope = home_evidence_scope(seal)
    verified_home_before(scope)
    ordinary_provider_roots(scope["uid"], scope["home_id"])


def start_digest(scope, value):
    require(type(value) is bytes and len(value) == START_BYTES)
    encoded = json.dumps(scope, sort_keys=True, separators=(",", ":")).encode("ascii")
    return sha256(b"oc-gemini-fixture:start:v1\0" + encoded + b"\0" + value).hexdigest()


def case_start_binding(scope, label):
    require(label in LABELS)
    binding = {"seal": scope["seal"], "attempt": scope["attempt"], "uid": scope["uid"], "label": label}
    return json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("ascii")


def derive_case_start(scope, label, start):
    require(type(start) is bytes and len(start) == START_BYTES)
    return hmac_digest(start, b"oc-gemini-fixture:derive-case-start:v1\0" + case_start_binding(scope, label), "sha256")


def case_start_digest(scope, label, value):
    require(type(value) is bytes and len(value) == START_BYTES)
    binding = case_start_binding(scope, label)
    return sha256(b"oc-gemini-fixture:case-start:v1\0" + binding + b"\0" + value).hexdigest()


def case_start_commitments(scope, start):
    return {label: case_start_digest(scope, label, derive_case_start(scope, label, start)) for label in LABELS}


def authorize_home_start(seal, value):
    scope = home_evidence_scope(seal)
    before = verified_home_before(scope)
    require(compare_digest(before["start_sha256"], start_digest(scope, value)))
    require(before["case_start_sha256"] == case_start_commitments(scope, value))
    ordinary_provider_roots(scope["uid"], scope["home_id"])
    return scope


def authorize_case_start(seal, label, value):
    scope = home_evidence_scope(seal)
    before = verified_home_before(scope)
    expected = case_start_digest(scope, label, value)
    require(compare_digest(before["case_start_sha256"][label], expected))
    ordinary_provider_roots(scope["uid"], scope["home_id"])


def read_catalog_start(fd=0):
    """Consume the anonymous one-way startup descriptor before case or vendor access."""
    with owned_case_fd(fd):
        deadline = time.monotonic() + 2
        info = os.fstat(fd)
        require(stat.S_ISFIFO(info.st_mode) and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
        # Linux renders unnamed pipefs descriptors differently from named FIFOs,
        # including named FIFOs whose directory entry was removed after opening.
        require(os.readlink(f"/proc/self/fd/{fd}") == f"pipe:[{info.st_ino}]")
        os.set_blocking(fd, False)
        value = bytearray()
        while len(value) <= START_BYTES:
            remaining = deadline - time.monotonic()
            require(remaining > 0 and select.select([fd], [], [], remaining)[0])
            piece = os.read(fd, START_BYTES + 1 - len(value))
            if not piece:
                require(len(value) == START_BYTES)
                return bytes(value)
            value.extend(piece)
        raise Refused("Offline Google fixture start descriptor refused.")


@contextmanager
def one_case_start(scope, label, start, sent):
    require(label not in sent)
    sent.add(label)
    value = derive_case_start(scope, label, start)
    reader, writer = os.pipe2(os.O_CLOEXEC)
    try:
        try:
            require(os.write(writer, value) == START_BYTES)
        except BaseException as error:
            close_start_preserving(error, os.close, writer)
            raise
        os.close(writer)
        stream = os.fdopen(reader, "rb", buffering=0)
    except BaseException as error:
        close_start_preserving(error, os.close, reader)
        raise
    del value
    try:
        yield stream
    except BaseException as error:
        close_start_preserving(error, stream.close)
        raise
    else:
        stream.close()


def close_start_preserving(error, close, *args):
    try:
        close(*args)
    except BaseException:
        error.add_note("Protected fixture start descriptor closure was not confirmed.")


def measured_parent(pid, argv, *, supervisor=False):
    require(pid > 1)
    process = Path(f"/proc/{pid}")
    original = process.stat()
    require(original.st_uid == os.getuid() and os.path.samefile(process / "exe", "/usr/bin/python3"))
    with (process / "cmdline").open("rb") as stream:
        expected = b"\0".join(os.fsencode(part) for part in argv) + b"\0"
        suffix = 65 if supervisor else 0
        observed = stream.read(len(expected) + suffix + 1)
    if supervisor:
        require(observed.startswith(expected) and re.fullmatch(rb"[a-f0-9]{64}\x00", observed[len(expected):]))
    else:
        require(observed == expected)
    with (process / "stat").open("rb") as stream:
        fields = stream.read(4096).rpartition(b") ")[2].split()
    require(len(fields) >= 20 and os.path.samestat(original, process.stat()))
    return int(fields[1])


def verify_start_parent(*, case_child=False):
    parent = os.getppid()
    interpreter = ("/usr/bin/python3", "-IBS")
    supervisor = parent
    if case_child:
        entry = SOURCE / "tests/google-connect-fixture.py"
        supervisor = measured_parent(parent, (*interpreter, entry, "--bound-catalog"))
    controller = CAPSULE / "google_home_controller.py"
    measured_parent(supervisor, (*interpreter, controller, "--held-exec"), supervisor=True)
    require(os.getppid() == parent)


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


def begin_home_attestation(value):
    seal, scope = root_home_scope()
    require(all(absent(CAPSULE / name) for name in (HOME_BEFORE, HOME_RESULT, NATIVE_RESULT)))
    for label in LABELS:
        with case_paths(seal, label, pristine=True):
            pass
    before = {"version": 2, "scope": scope, "start_sha256": start_digest(scope, value),
              "case_start_sha256": case_start_commitments(scope, value),
              **capture_home_evidence(scope)}
    payload = json.dumps(before, sort_keys=True).encode("ascii")
    publish_home_before(payload)
    require(verified_home_before(scope) == before and digest(CAPSULE / HOME_BEFORE) == sha256(payload).hexdigest())


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
    require(type(payload) is bytes and 0 < len(payload) <= MAX_PROOF)
    uid = os.geteuid()
    parent_info = checked_node(path.parent, uid, directory=True)
    with ExitStack() as pins:
        parent = os.open(path.parent, DIRECTORY)
        pins.callback(os.close, parent)
        require(os.path.samestat(parent_info, os.fstat(parent)))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(path.name, flags, 0o600, dir_fd=parent)
        pins.callback(os.close, fd)

        def verify(mode, size):
            node = os.fstat(fd)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISREG(node.st_mode) and node.st_uid == uid and node.st_nlink == 1
                    and stat.S_IMODE(node.st_mode) == mode and node.st_size == size)
            require(metadata(node) == metadata(named)
                    and os.path.samestat(parent_info, path.parent.lstat()))

        verify(0o600, 0)
        data = memoryview(payload)
        while data:
            length = os.write(fd, data)
            require(length > 0)
            data = data[length:]
        verify(0o600, len(payload))
        os.fsync(fd)
        try:
            os.fchmod(fd, 0o444)
            verify(0o444, len(payload))
            os.fsync(fd)
            os.fsync(parent)
            verify(0o444, len(payload))
        except BaseException:
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
                os.fsync(parent)
            except OSError:
                pass
            raise


def publish_home_before(payload):
    """Sync the finalized record privately, then publish it under the pinned capsule."""
    uid = os.geteuid()
    original = checked_node(CAPSULE, uid, directory=True)
    with ExitStack() as pins:
        parent = os.open(CAPSULE, DIRECTORY)
        pins.callback(os.close, parent)
        require(os.path.samestat(original, os.fstat(parent)))
        os.mkdir(HOME_BEFORE_STAGE, mode=0o700, dir_fd=parent)
        staged = os.open(HOME_BEFORE_STAGE, DIRECTORY, dir_fd=parent)
        pins.callback(os.close, staged)
        stage_info = private_dir_identity(os.fstat(staged), uid)
        path = CAPSULE / HOME_BEFORE_STAGE / HOME_BEFORE
        require(stage_info == identity(path.parent.lstat()))
        write_protected(path, payload)
        fd = os.open(HOME_BEFORE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=staged)
        pins.callback(os.close, fd)
        node = os.fstat(fd)
        require(stat.S_ISREG(node.st_mode) and node.st_uid == uid and node.st_nlink == 1
                and stat.S_IMODE(node.st_mode) == 0o444 and node.st_size == len(payload)
                and os.pread(fd, len(payload) + 1, 0) == payload)
        require(os.path.samestat(original, CAPSULE.lstat())
                and stage_info == identity(os.stat(HOME_BEFORE_STAGE, dir_fd=parent, follow_symlinks=False)))
        os.link(HOME_BEFORE, HOME_BEFORE, src_dir_fd=staged, dst_dir_fd=parent, follow_symlinks=False)
        try:
            os.unlink(HOME_BEFORE, dir_fd=staged)
            os.fsync(staged)
            os.rmdir(HOME_BEFORE_STAGE, dir_fd=parent)
            os.fsync(parent)
            named = os.stat(HOME_BEFORE, dir_fd=parent, follow_symlinks=False)
            require(os.path.samestat(node, named) and named.st_nlink == 1 and named.st_uid == uid
                    and stat.S_IMODE(named.st_mode) == 0o444 and named.st_size == len(payload)
                    and os.path.samestat(original, CAPSULE.lstat()))
        except BaseException:
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
                os.fsync(parent)
            except OSError:
                pass
            raise


def private_dir_identity(info, uid):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700)
    return identity(info)


def close_case_preserving(error, fd):
    try:
        os.close(fd)
    except BaseException:
        error.add_note("Protected fixture case descriptor closure was not confirmed.")


@contextmanager
def owned_case_fd(fd):
    try:
        yield fd
    except BaseException as error:
        close_case_preserving(error, fd)
        raise
    else:
        os.close(fd)


@contextmanager
def runtime_directory(uid):
    path = USER_RUNTIME / str(uid)
    expected = private_dir_identity(checked_node(path, uid, directory=True), uid)
    with owned_case_fd(os.open(path, DIRECTORY)) as fd:
        require(private_dir_identity(os.fstat(fd), uid) == expected)
        yield fd
        require(private_dir_identity(os.fstat(fd), uid) == private_dir_identity(path.lstat(), uid) == expected)


@contextmanager
def pinned_case_tree(runtime, name, uid, *, create=False, pristine=False, identities=None):
    require(type(name) is str and re.fullmatch(r"oc-g-connect-fixture-[a-z0-9_]{8}", name))
    with ExitStack() as pins:
        parent = runtime
        links = []
        if create:
            user = account()
            require(uid == user.pw_uid)
            require_unprivileged_allocator(user)
        for child, expected_children in ((name, ("home",)), ("home", ("opencode-sandbox",)), ("opencode-sandbox", ())):
            if create:
                os.mkdir(child, 0o700, dir_fd=parent)
            expected = private_dir_identity(os.stat(child, dir_fd=parent, follow_symlinks=False), uid)
            if identities is not None:
                require(expected == identities[len(links)])
            fd = pins.enter_context(owned_case_fd(os.open(child, DIRECTORY, dir_fd=parent)))
            require(private_dir_identity(os.fstat(fd), uid) == expected)
            links.append((parent, child, fd, expected, expected_children))
            parent = fd

        def verify():
            for directory, child, fd, expected, expected_children in reversed(links):
                require(private_dir_identity(os.fstat(fd), uid)
                        == private_dir_identity(os.stat(child, dir_fd=directory, follow_symlinks=False), uid)
                        == expected)
                if pristine or not expected_children:
                    exact_children(fd, expected_children)

        verify()
        yield tuple(expected for _, _, _, expected, _ in links)
        verify()


def require_unprivileged_allocator(user):
    uid, gid = user.pw_uid, user.pw_gid
    require(uid > 0 and gid > 0 and os.getresuid() == (uid, uid, uid)
            and os.getresgid() == (gid, gid, gid) and os.getgroups() == [])


def allocate_cases():
    user = account()
    uid = user.pw_uid
    require_unprivileged_allocator(user)
    os.umask(0o077)
    records = {}
    with runtime_directory(uid) as runtime:
        for label in LABELS:
            name = "oc-g-connect-fixture-" + token_hex(4)
            with pinned_case_tree(runtime, name, uid, create=True, pristine=True) as identities:
                root, home, sandbox = identities
                records[label] = {"case": str(USER_RUNTIME / str(uid) / name),
                                  "root_id": root, "home_id": home, "sandbox_id": sandbox}
    return records


def install_seal(tree, allocator):
    """Verify unprivileged case bindings and write only protected guest capsule files."""
    require(os.getuid() == os.geteuid() == 0 and re.fullmatch(r"[a-f0-9]{40}", tree))
    uid = account().pw_uid
    boot = topology(root_host)
    policy = firewall(root_host(*NFT))
    source = source_inventory()
    vendor_pair()
    home_snapshot(uid)
    cases = CAPSULE / "case-config"
    require(absent(cases) and absent(CAPSULE / "seal.json"))
    allocations = allocator()
    require(type(allocations) is dict and set(allocations) == set(LABELS))
    records = {}
    for label, allocation in allocations.items():
        require(type(allocation) is dict and allocation.keys() == {"case", "root_id", "home_id", "sandbox_id"})
        records[label] = {**allocation, "config": "0" * 64}
    proof = {"version": 1, "uid": uid, "boot": boot, "tree": tree, "source": source,
             "firewall": policy, "cases": records}
    validate_seal(proof)
    for label in LABELS:
        with case_paths(proof, label, pristine=True):
            pass
    cases.mkdir(mode=0o755)
    original = (SOURCE / CONFIG).read_text(encoding="utf-8")
    for label, record in records.items():
        leaf = cases / label / "config.py"
        leaf.parent.mkdir(mode=0o755)
        home = sealed_case(record, uid) / "home"
        code = project_config(original, home)
        write_protected(leaf, code.encode("utf-8"))
        record["config"] = digest(leaf)
    for label in LABELS:
        with case_paths(proof, label, pristine=True):
            pass
    write_protected(CAPSULE / "seal.json", json.dumps(proof, sort_keys=True).encode("ascii"))


def exact_children(fd, expected):
    original = metadata(os.fstat(fd))
    pending = set(expected)
    # A fresh open of the held directory avoids consuming or reusing its offsets.
    with owned_case_fd(os.open(".", DIRECTORY, dir_fd=fd)) as scan:
        require(metadata(os.fstat(scan)) == original)
        with os.scandir(scan) as children:
            for child in children:
                require(child.name in pending)
                pending.remove(child.name)
    require(not pending and metadata(os.fstat(fd)) == original)


@contextmanager
def case_paths(seal, label, *, pristine=False):
    require(label in LABELS)
    uid = seal["uid"]
    record = seal["cases"][label]
    case = sealed_case(record, uid)
    expected = tuple(record[key] for key in ("root_id", "home_id", "sandbox_id"))
    with runtime_directory(uid) as runtime, pinned_case_tree(
        runtime, case.name, uid, pristine=pristine, identities=expected,
    ):
        yield case, case / "home", case / "home/opencode-sandbox"


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
    except BaseException as error:
        close_case_preserving(error, fd)
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
        _, action, label, descriptor, start_descriptor = sys.argv
        driver = Path(__file__).absolute()
        require(driver.name == DRIVER and driver.parent.name == "source"
                and driver.parent.parent.parent == USER_RUNTIME / str(os.getuid()))
        require(action == "--fixture" and label in LABELS)
        require(all(raw.isascii() and raw.isdecimal() and len(raw) <= 9 for raw in (descriptor, start_descriptor)))
        fd, start_fd = int(descriptor), int(start_descriptor)
        require(fd >= 3 and start_fd >= 3 and fd != start_fd)
        verify_start_parent(case_child=True)
        start = read_catalog_start(start_fd)
        seal = guest()
        authorize_case_start(seal, label, start)
        del start
        with owned_case_fd(fd):
            projection = read_descriptor(fd)
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
