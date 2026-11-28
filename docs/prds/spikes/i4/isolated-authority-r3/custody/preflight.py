"""Single-file appliance bootstrap. Install independently of the reviewed bundle."""

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import sys


SOURCE = Path("/opt/oc-r3/appliance")
INSTALLATION = Path("/etc/oc-r3/service.json")
BOOTSTRAP = Path("/usr/libexec/oc-r3-preflight.py")
PYTHON = "/usr/bin/python3"
LEGACY = "fa6d7f4f807ddda140eadb2e98a285a4133753b8"
PLAN_OVERLAY = "0f196987923eefe25d7dc9b971b990d7e0ed8f6d"
CORRECTED_OVERLAY = "6f8b05686e38730c8245ee41afc3e14ba9ad8873"
_OBJECT = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_HANDLE = re.compile(r"r[0-9a-f]{32}")
_MAX_FILE = 2 << 20
_MAX_MANIFEST = 1 << 20
_MAX_FILES = 4096
_FLAGS = os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | _FLAGS
_PROCFS = 0x9FA0
_REQUIRED = {
    "custody/preflight.py", "custody/run.py", "custody/roles.py", "custody/bootstrap.py",
    "custody/measurement.py", "custody/legacy.py", "custody/restart.py", "spike/descriptor.py",
    "spike/receipt.py", "spike/test_receipt.py", "legacy/oc_openai/canary.py",
    "legacy/oc_openai/connection.py", "legacy/oc_openai/acceptance.py", "legacy/oc_openai/session_broker.py",
}


class MeasurementRefused(RuntimeError):
    """No candidate source can be entered."""


def canonical(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _decode(raw):
    value = json.loads(raw.decode("ascii"))
    if type(value) is not list or canonical(value) != raw:
        raise MeasurementRefused("noncanonical manifest")
    return value


def require_path(path):
    if not path or path.startswith("/") or any(piece in ("", ".", "..", ".git") for piece in path.split("/")):
        raise MeasurementRefused("unsafe measured path")
    return PurePosixPath(path)


def _identity(info):
    return info.st_dev, info.st_ino


def _safe_info(info, expected_uid, *, directory):
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != expected_uid or mode & 0o7022:
        raise MeasurementRefused("unprotected measurement source")
    if directory and not stat.S_ISDIR(info.st_mode):
        raise MeasurementRefused("invalid measurement directory")
    if not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise MeasurementRefused("invalid measured source file")


@contextmanager
def _open_root(path, *, sealed):
    if not path.is_absolute() or path.anchor != "/" or ".." in path.parts:
        raise MeasurementRefused("noncanonical measurement root")
    fd = os.open("/", _DIRECTORY)
    try:
        if sealed:
            _safe_info(os.fstat(fd), 0, directory=True)
        for part in path.parts[1:]:
            child = os.open(part, _DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
            if sealed:
                _safe_info(os.fstat(fd), 0, directory=True)
        yield fd
    finally:
        os.close(fd)


def _read(directory, name, limit, *, uid=None, mount=None):
    node = os.open(name, os.O_RDONLY | _FLAGS, dir_fd=directory)
    with os.fdopen(node, "rb") as stream:
        info = os.fstat(stream.fileno())
        if uid is not None:
            _safe_info(info, uid, directory=False)
        if mount is not None:
            mount.check(node)
        if info.st_size > limit:
            raise MeasurementRefused("measured input exceeds bound")
        data = stream.read(limit + 1)
        if uid is not None and _identity(info) != _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)):
            raise MeasurementRefused("measurement file changed")
    if len(data) > limit:
        raise MeasurementRefused("measured input exceeds bound")
    return data


@contextmanager
def _proc_self(*, check_inherited=False):
    proc = os.open("/proc", _DIRECTORY)
    try:
        own = str(os.getpid())
        if os.readlink("self", dir_fd=proc) != own:
            raise MeasurementRefused("unexpected procfs PID view")
        own_fd = os.open(own, _DIRECTORY, dir_fd=proc)
        try:
            if check_inherited:
                _check_entry_descriptors(own_fd, proc)

            import ctypes

            data = (ctypes.c_long * 32)()
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.fstatfs(proc, ctypes.byref(data)) != 0 or data[0] != _PROCFS:
                raise MeasurementRefused("genuine mountinfo unavailable")
            yield own_fd
        finally:
            os.close(own_fd)
    finally:
        os.close(proc)


def _mount_id(proc, fd):
    info = os.open("fdinfo", _DIRECTORY, dir_fd=proc)
    try:
        text = _read(info, str(fd), 2048).decode("ascii")
    finally:
        os.close(info)
    values = [line.split()[1:] for line in text.splitlines() if line.startswith("mnt_id:")]
    if len(values) != 1 or len(values[0]) != 1 or not values[0][0].isdecimal():
        raise MeasurementRefused("descriptor mount identity unavailable")
    return values[0][0]


def _mount_record(raw, path, selected, device):
    lines = [line.split() for line in raw.decode("ascii").splitlines()]
    if any(len(line) < 10 or "-" not in line[6:] for line in lines):
        raise MeasurementRefused("invalid mount table")
    if len({line[0] for line in lines}) != len(lines):
        raise MeasurementRefused("duplicate mount identity")
    expected = str(path)
    source = [entry for entry in lines if entry[4] == expected]
    if len(source) != 1 or source[0][0] != selected or source[0][2] != device or source[0][3] != "/":
        raise MeasurementRefused("source is not the exact mounted filesystem")
    if any(line[4].startswith(expected + "/") for line in lines):
        raise MeasurementRefused("nested mount below measured source")
    if any(line[2] == device and line[0] != selected for line in lines):
        raise MeasurementRefused("source filesystem has another mount")
    record = source[0]
    separator = record.index("-")
    if len(record) != separator + 4:
        raise MeasurementRefused("invalid source mount record")
    for flags in (record[5], record[-1]):
        options = flags.split(",")
        if "ro" not in options or "rw" in options:
            raise MeasurementRefused("source or superblock is writable")
    return tuple(record)


class _SealedMount:
    def __init__(self, proc, fd, path):
        self.proc = proc
        self.selected = _mount_id(proc, fd)
        self.device = os.fstat(fd).st_dev
        self.check(fd)
        device = f"{os.major(self.device)}:{os.minor(self.device)}"
        self.record = _mount_record(_read(proc, "mountinfo", 1 << 20), path, self.selected, device)

    def check(self, fd):
        if (os.fstat(fd).st_dev != self.device or _mount_id(self.proc, fd) != self.selected
                or not os.fstatvfs(fd).f_flag & os.ST_RDONLY):
            raise MeasurementRefused("measured descriptor left the read-only mount")


def _entries(directory, uid, mount, prefix=""):
    for name in sorted(os.listdir(directory)):
        relative = prefix + name
        require_path(relative)
        if relative == "manifest":
            continue
        if len(relative) > 512 or relative.count("/") > 18:
            raise MeasurementRefused("measured path exceeds bounds")
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISDIR(named.st_mode):
            child = os.open(name, _DIRECTORY, dir_fd=directory)
            try:
                opened = os.fstat(child)
                _safe_info(opened, uid, directory=True)
                if _identity(opened) != _identity(named):
                    raise MeasurementRefused("measurement directory changed")
                if mount is not None:
                    mount.check(child)
                yield [relative + "/", "directory"]
                yield from _entries(child, uid, mount, prefix=relative + "/")
            finally:
                os.close(child)
        else:
            _safe_info(named, uid, directory=False)
            yield [relative, sha256(_read(directory, name, _MAX_FILE, uid=uid, mount=mount)).hexdigest()]


def _scan(directory, uid, mount):
    _safe_info(os.fstat(directory), uid, directory=True)
    entries = []
    for entry in _entries(directory, uid, mount):
        if len(entries) == _MAX_FILES:
            raise MeasurementRefused("measured file list exceeds bound")
        entries.append(entry)
    return entries


def scan(root, expected_uid, *, manifest_pending=False):
    with _open_root(Path(root), sealed=False) as directory:
        if manifest_pending and "manifest" in os.listdir(directory):
            raise MeasurementRefused("source manifest already exists")
        return _scan(directory, expected_uid, None)


def _verify(directory, expected, mount):
    if not _DIGEST.fullmatch(expected):
        raise MeasurementRefused("untrusted source measurement input")
    uid = 0 if mount is not None else os.geteuid()
    _safe_info(os.fstat(directory), uid, directory=True)
    raw = _read(directory, "manifest", _MAX_MANIFEST, uid=uid, mount=mount)
    if sha256(raw).hexdigest() != expected:
        raise MeasurementRefused("source manifest pin does not match")
    value = _decode(raw)
    if (len(value) != 5 or value[:2] != ["r3-custody", LEGACY] or value[2] not in (PLAN_OVERLAY, CORRECTED_OVERLAY)
            or type(value[3]) is not str or not _OBJECT.fullmatch(value[3])):
        raise MeasurementRefused("unrecognized measured source")
    entries = _scan(directory, uid, mount)
    if value[4] != entries:
        raise MeasurementRefused("appliance source changed")
    if mount is not None and (value[2] != CORRECTED_OVERLAY or not _REQUIRED <= {path for path, _ in entries}):
        raise MeasurementRefused("corrected complete source required")
    return {"legacy": value[1], "overlay": value[2], "candidate": value[3]}


def verify_bundle(root, expected, *, sealed=False):
    root = Path(root)
    with _open_root(root, sealed=sealed) as directory:
        if sealed:
            with _proc_self() as proc:
                mount = _SealedMount(proc, directory, root)
                return _verify(directory, expected, mount)
        return _verify(directory, expected, None)


def _run_checked(root, pin, arguments, activate, *, sealed):
    # The offline tests provide a harmless callback. The independently
    # installed entry always selects the sealed mount check and fixed exec.
    with _open_root(root, sealed=sealed) as directory:
        if not sealed:
            _verify(directory, pin, None)
            return activate(root / "custody" / "run.py", arguments)
        with _proc_self() as proc:
            mount = _SealedMount(proc, directory, root)
            _verify(directory, pin, mount)
            with _open_root(root, sealed=True) as current:
                fresh = _SealedMount(proc, current, root)
                if _identity(os.fstat(current)) != _identity(os.fstat(directory)) or fresh.record != mount.record:
                    raise MeasurementRefused("source mount changed before exec")
    return activate(root / "custody" / "run.py", arguments)


def _install_pins(pin):
    inputs = (INSTALLATION, BOOTSTRAP)
    results = []
    for path in inputs:
        with _open_root(path.parent, sealed=True) as parent:
            raw = _read(parent, path.name, _MAX_FILE, uid=0)
            results.append(raw)
    if _decode(results[0]) != ["r3-service-v1", sha256(results[1]).hexdigest(), pin]:
        raise MeasurementRefused("independent installation pins disagree")


def _check_entry_descriptors(proc, proc_root):
    for fd in (0, 1, 2):
        os.fstat(fd)
    directory = os.open("fd", _DIRECTORY, dir_fd=proc)
    try:
        for name in os.listdir(directory):
            fd = int(name)
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if fd not in (0, 1, 2, directory, proc, proc_root):
                raise MeasurementRefused("unexpected bootstrap descriptor")
            if fd in (0, 1, 2) and stat.S_ISSOCK(info.st_mode):
                with socket.socket(fileno=os.dup(fd)) as endpoint:
                    if endpoint.family != socket.AF_UNIX:
                        raise MeasurementRefused("unexpected bootstrap Internet socket")
    finally:
        os.close(directory)


def _exec(entry, args):
    os.chdir("/")
    os.execve(PYTHON, [PYTHON, "-I", "-S", "-B", str(entry), *args], {"OC_R3_PREIMPORT": args[1]})


def main(args):
    try:
        if (os.getuid() != 0 or os.geteuid() != 0 or Path(__file__).resolve() != BOOTSTRAP
                or not sys.flags.isolated or not sys.flags.no_site or not sys.flags.dont_write_bytecode
                or os.environ or len(args) not in (3, 4) or args[0] not in ("sealed", "restart")
                or bool(len(args) == 4) != (args[0] == "restart")
                or not all(_DIGEST.fullmatch(value) for value in args[1:3])
                or (len(args) == 4 and not _HANDLE.fullmatch(args[3]))):
            raise MeasurementRefused("independent sealed service unavailable")
        _install_pins(args[1])
        with _proc_self(check_inherited=True):
            pass
        _run_checked(SOURCE, args[1], args, _exec, sealed=True)
    except (MeasurementRefused, OSError, ValueError, RecursionError):
        print('{"result":"preimport_refused"}')
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
