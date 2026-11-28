"""Read host and admitted-container mount identities from trusted host procfs."""

from contextlib import ExitStack
from dataclasses import astuple, dataclass
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stock_worker_tools_protocol import require


@dataclass(frozen=True)
class Mount:
    mount_id: int
    device: str
    root: Path
    target: Path
    mode: str
    filesystem: str


@dataclass(frozen=True)
class Identity:
    device: int
    inode: int
    mount_id: int


@dataclass(frozen=True)
class Binding:
    source_mount: Mount
    source_path: Path
    identity: Identity

    def filesystem_path(self):
        require(self.source_path.is_relative_to(self.source_mount.target),
                "Pinned source is outside its kernel mount")
        return self.source_mount.root / self.source_path.relative_to(self.source_mount.target)


def parse_mounts(text):
    mounts = {}
    for line in text.splitlines():
        head, separator, tail = line.partition(" - ")
        fields, filesystem = head.split(), tail.split()
        require(separator and len(fields) >= 6 and len(filesystem) == 3
                and fields[0].isdigit() and re.fullmatch(r"[0-9]+:[0-9]+", fields[2]),
                "Malformed kernel mount inventory")
        paths = [Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)) for value in fields[3:5]]
        mode = set(fields[5].split(",")) & {"rw", "ro"}
        mount_id = int(fields[0])
        root, target = paths
        virtual_cgroup_root = filesystem[0] in {"cgroup", "cgroup2"} and root.is_absolute()
        require(mount_id not in mounts and len(mode) == 1 and target.is_absolute() and ".." not in target.parts
                and (virtual_cgroup_root or root.is_absolute() and ".." not in root.parts),
                "Ambiguous kernel mount record")
        mounts[mount_id] = Mount(mount_id, fields[2], *paths, mode.pop(), filesystem[0])
    require(bool(mounts), "Empty kernel mount inventory")
    return mounts


def intersects(first, second):
    return first.is_relative_to(second) or second.is_relative_to(first)


def verify_bindings(mounts, expected, observed, protected):
    targets = [Path(path) for path in expected]
    require(expected.keys() == observed.keys() and bool(protected), "Incomplete sealed kernel observation")
    for mount in mounts.values():
        for sentinel in protected:
            require(not (mount.device == sentinel.source_mount.device
                         and mount.filesystem == sentinel.source_mount.filesystem
                         and intersects(mount.root, sentinel.filesystem_path())),
                    "Kernel mount exposes a controller sentinel backing path")
            # The process root is a genuine system mount and is checked separately
            # by the backing-path rule above. All other overlaps are unqualified.
            require(mount.target == Path("/") or not intersects(mount.target, sentinel.source_path),
                    "Unexpected mount overlapping a protected controller path")
        require(mount.target in targets or mount.target == Path("/")
                or not any(intersects(mount.target, target) for target in targets),
                "A kernel mount shadows a qualified runtime path")

    for name, (source, writable) in expected.items():
        target = Path(name)
        matches = [mount for mount in mounts.values() if mount.target == target]
        target_id = observed[name]
        require(len(matches) == 1 and matches[0].mount_id == target_id.mount_id
                and matches[0].mode == ("rw" if writable else "ro"), "Kernel mount identity or access mode differs")
        mount = matches[0]
        require((target_id.device, target_id.inode) == (source.identity.device, source.identity.inode)
                and (mount.device, mount.filesystem, mount.root)
                == (source.source_mount.device, source.source_mount.filesystem, source.filesystem_path()),
                "Mounted object does not match the independently pinned source")


def read_at(directory, name, size=1024 * 1024):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        text = stream.read(size + 1)
    require(len(text) <= size, "Kernel observation exceeded its bound")
    return text


def open_at(path, start, stack):
    require(path.is_absolute() and ".." not in path.parts and path != Path("/"), "Invalid stock bind path")
    fd = start
    for part in path.parts[1:-1]:
        fd = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        stack.callback(os.close, fd)
    fd = os.open(path.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=fd)
    stack.callback(os.close, fd)
    require(not stat.S_ISLNK(os.fstat(fd).st_mode), "A sealed mount proof path is a symbolic link")
    return fd


def identity(fd):
    info = os.fstat(fd)
    metadata = Path(f"/proc/self/fdinfo/{fd}").read_text()
    lines = [line.split() for line in metadata.splitlines() if line.startswith("mnt_id:")]
    require(len(lines) == 1 and len(lines[0]) == 2 and lines[0][1].isdigit(), "Pinned kernel mount ID unavailable")
    return Identity(info.st_dev, info.st_ino, int(lines[0][1]))


def process_anchor(proc):
    # The process comm can contain whitespace and parentheses. Start time is
    # field 22, which follows the final closing parenthesis.
    tail = read_at(proc, "stat", 8192).rpartition(") ")[2].split()
    require(len(tail) >= 20 and tail[19].isdigit(), "Container process start time unavailable")
    namespace = os.stat("ns/mnt", dir_fd=proc)
    root = os.stat("root", dir_fd=proc)
    return tail[19], (namespace.st_dev, namespace.st_ino), (root.st_dev, root.st_ino)


def observe(pid, bindings, protected):
    require(type(pid) is int and pid > 1 and 1 <= len(bindings) <= 4 and 1 <= len(protected) <= 2,
            "Unexpected sealed kernel observation inputs")
    with ExitStack() as stack:
        proc = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, proc)
        initial = process_anchor(proc)
        process_root = os.open("root", os.O_PATH | os.O_DIRECTORY, dir_fd=proc)
        stack.callback(os.close, process_root)
        host_root = os.open("/", os.O_PATH | os.O_DIRECTORY)
        stack.callback(os.close, host_root)
        host_mounts = parse_mounts(Path("/proc/self/mountinfo").read_text(encoding="utf-8"))
        mounts = parse_mounts(read_at(proc, "mountinfo"))

        def source(path):
            fd = open_at(path, host_root, stack)
            current = identity(fd)
            return Binding(host_mounts[current.mount_id], path, current), fd

        expected, target_ids = {}, {}
        for destination, (path, writable) in bindings.items():
            require(type(writable) is bool, "Missing inspected bind mode")
            approved, _ = source(Path(path))
            target_ids[destination] = identity(open_at(Path(destination), process_root, stack))
            expected[destination] = approved, writable

        sentinels = []
        for item in protected:
            path = Path(item)
            sentinel, fd = source(path)
            metadata = os.fstat(fd)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
                    "Protected controller sentinel must be a single-link regular file")
            sentinels.append(sentinel)
            try:
                open_at(path, process_root, stack)
            except (FileNotFoundError, NotADirectoryError):
                pass
            else:
                raise RuntimeError("Controller sentinel resolved under the pinned process root")

        verify_bindings(mounts, expected, target_ids, sentinels)
        require(process_anchor(proc) == initial and parse_mounts(read_at(proc, "mountinfo")) == mounts,
                "Container mount namespace changed during observation")
        return {"process": initial, "bindings": {name: astuple(value) for name, value in target_ids.items()},
                "sentinels": [astuple(item.identity) for item in sentinels]}


def main():
    require(len(sys.argv) == 2 and sys.argv[1].isdigit(), "Sealed procfs observer needs one measured process")
    request = json.loads(sys.stdin.read(8192))
    require(type(request) is dict and request.keys() == {"bindings", "protected"}, "Wrong sealed mount request")
    print(json.dumps(observe(int(sys.argv[1]), request["bindings"], request["protected"])))


if __name__ == "__main__":
    main()
