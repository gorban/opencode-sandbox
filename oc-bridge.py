#!/usr/bin/env -S python3 -I
"""Host side of the oc-sandbox bridge (installed as ~/.local/bin/oc-bridge by oc-sandbox).

Everything below OC_SB is writable by the sandboxed agent, at any moment. So this program never hands
a pathname inside OC_SB to anything (desktop tools included), and never resolves one by name:

* Every component is opened with openat(O_NOFOLLOW) relative to the descriptor of its parent, starting
  from OC_SB itself (a mount point the agent cannot replace). A symlink anywhere fails the open
  (ELOOP/ENOTDIR) instead of being followed, and renaming a directory after it was opened cannot move
  the descriptor out of the sandbox: renames inside the bind mount stay inside it.
* Files are opened O_NONBLOCK, then checked with fstat() on the open descriptor, so a FIFO or device
  swapped in cannot block or be read.
* VS Code / Beyond Compare open a *copy* in OC_BRIDGE_STAGE (host-owned, mode 0700, never mounted).
  The watcher checks and reads each staged save through the same no-follow regular-file descriptor.
  It writes a replacement in private host staging and checks the target before renaming
  into its pinned sandbox parent. An observed conflict is saved under a new sibling name
  without replacing an older conflict copy. An edit can still race the final check and rename.
  A session with an unsuccessful final write-back keeps its staged copies for recovery.

Modes:  oc-bridge                 process the request queue (oc-bridge.service)
        oc-bridge session DIR     run the tool on a staged copy, write edits back (internal)
"""
import errno
import fcntl
from itertools import islice
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time

SB = os.environ.get("OC_SB", os.path.expanduser("~/opencode-sandbox"))
STAGE = os.environ.get("OC_BRIDGE_STAGE", os.path.expanduser("~/.local/share/oc-sandbox/bridge-stage"))
TOOLS = {"code": os.environ.get("OC_CODE_BIN", ""), "bcompare": os.environ.get("OC_BCOMPARE_BIN", "")}
LAUNCH = os.environ.get("OC_BRIDGE_LAUNCH", "systemd-run --user --quiet --collect").split()
SELINUX_LEVEL = os.environ.get("OC_BRIDGE_SELINUX_LEVEL")
CONFIG_VARS = ("OC_SB", "OC_BRIDGE_STAGE", "OC_CODE_BIN", "OC_BCOMPARE_BIN", "OC_BRIDGE_SELINUX_LEVEL")

MAX_REQUESTS = 20         # per run
MAX_QUEUE_SCAN = 256
MAX_REQUEST_BYTES = 8192
MAX_PATHS = 8             # per request
MAX_MANIFEST_BYTES = 256 << 10
MAX_FILE = 64 << 20       # bytes per copied file
MAX_TREE_FILES = 5000     # per directory snapshot (bcompare only)
MAX_TREE_DEPTH = 64
MAX_SESSION_BYTES = 512 << 20
MAX_STAGE_SESSIONS = 8
STAGE_MAX_AGE = 7 * 86400

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def log(msg):
    print(f"oc-bridge: {msg}", file=sys.stderr, flush=True)


class Refused(Exception):
    pass


class OverBudget(Refused):
    pass


# ---- descriptor-relative traversal of the sandbox ------------------------------------------------

def open_root():
    return os.open(SB, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)


def components(sandbox_path):
    """'/sandbox/a/b' -> ['a', 'b'] (the agent's canonical path; '.', '..' and '' are refused)."""
    if not sandbox_path.startswith("/sandbox/"):
        raise Refused(f"not under /sandbox: {sandbox_path!r}")
    parts = sandbox_path[len("/sandbox/"):].split("/")
    if not canonical_parts(parts):
        raise Refused(f"non-canonical path: {sandbox_path!r}")
    return parts


def canonical_parts(parts):
    return isinstance(parts, list) and 0 < len(parts) <= MAX_TREE_DEPTH and all(
        isinstance(part, str) and part not in ("", ".", "..") and "/" not in part and "\0" not in part
        for part in parts
    )


def open_dirs(root_fd, parts):
    """Open root/parts[0]/.../parts[-1] as directories without following any symlink."""
    fd = os.dup(root_fd)
    try:
        for p in parts:
            nfd = os.open(p, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except OSError as e:
        os.close(fd)
        raise Refused(f"cannot open directory {'/'.join(parts)!r}: {e.strerror}") from None


def open_regular(dir_fd, name):
    try:
        fd = os.open(name, FILE_FLAGS, dir_fd=dir_fd)
    except OSError as e:
        raise Refused(f"cannot open {name!r}: {e.strerror}") from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise Refused(f"not a regular file: {name!r}")
    return fd, st


def ident(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns]


def staged_identity(st):
    return [st.st_ino, st.st_size, st.st_mtime_ns]


def copy_identity(st):
    return (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode), st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def write_all(fd, chunk):
    remaining = memoryview(chunk)
    while remaining:
        written = os.write(fd, remaining)
        if written == 0:
            raise OSError(errno.EIO, "file write made no progress")
        remaining = remaining[written:]


def copy_stable_file(source, out, limit):
    src_fd, before = source
    if before.st_size > limit:
        raise Refused(f"file exceeds the {limit}-byte copy limit")
    total = 0
    while chunk := os.read(src_fd, 1 << 20):
        total += len(chunk)
        if total > limit:
            raise Refused(f"file exceeds the {limit}-byte copy limit")
        write_all(out, chunk)
    os.fsync(out)
    if total != before.st_size or copy_identity(before) != copy_identity(os.fstat(src_fd)):
        raise Refused("source changed during the copy")
    return total


def copy_fd_to(source, dst_dir_fd, name, limit, mode=0o600):
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                  mode, dir_fd=dst_dir_fd)
    try:
        return copy_stable_file(source, out, limit)
    except BaseException:
        os.unlink(name, dir_fd=dst_dir_fd)
        raise
    finally:
        os.close(out)


# ---- staging (host-owned) ------------------------------------------------------------------------

def mkdirs_private(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def stage_dir_fd(base_fd, parts):
    """Create/open base/parts... inside the (host-owned) stage directory."""
    fd = os.dup(base_fd)
    for p in parts:
        try:
            os.mkdir(p, 0o700, dir_fd=fd)
        except FileExistsError:
            pass
        nfd = os.open(p, DIR_FLAGS, dir_fd=fd)
        os.close(fd)
        fd = nfd
    return fd


def snapshot_tree(src_fd, dst_fd, budget, depth=0):
    """Copy a directory (regular files and subdirectories only; symlinks etc. are skipped)."""
    if depth >= MAX_TREE_DEPTH:
        raise OverBudget("directory snapshot is too deep")
    with os.scandir(src_fd) as entries:
        for entry in entries:
            budget["files"] -= 1
            if budget["files"] < 0:
                raise OverBudget("directory snapshot has too many entries")
            snapshot_entry(src_fd, dst_fd, entry.name, budget, depth)


def snapshot_entry(src_fd, dst_fd, name, budget, depth):
    try:
        st = os.stat(name, dir_fd=src_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            sub = os.open(name, DIR_FLAGS, dir_fd=src_fd)
            try:
                os.mkdir(name, 0o700, dir_fd=dst_fd)
                dsub = os.open(name, DIR_FLAGS, dir_fd=dst_fd)
                try:
                    snapshot_tree(sub, dsub, budget, depth + 1)
                finally:
                    os.close(dsub)
            finally:
                os.close(sub)
        elif stat.S_ISREG(st.st_mode):
            fd, fst = open_regular(src_fd, name)
            try:
                copy_into_session((fd, fst), dst_fd, name, budget, 0o400)
            finally:
                os.close(fd)
    except OverBudget:
        raise
    except (OSError, Refused) as e:
        log(f"snapshot: skipped {name!r}: {e}")


def copy_into_session(source, directory, name, budget, mode=0o600):
    if source[1].st_size > budget["bytes"]:
        raise OverBudget("session snapshot exceeds the byte limit")
    budget["bytes"] -= copy_fd_to(source, directory, name, min(MAX_FILE, budget["bytes"]), mode)


def reserve_session():
    mkdirs_private(STAGE)
    stage_fd = os.open(STAGE, DIR_FLAGS)
    try:
        fcntl.flock(stage_fd, fcntl.LOCK_EX)
        with os.scandir(stage_fd) as contents:
            if sum(entry.is_dir(follow_symlinks=False) for entry in contents) >= MAX_STAGE_SESSIONS:
                raise OverBudget("too many staged editor sessions")
        sid = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(4)
        os.mkdir(sid, 0o700, dir_fd=stage_fd)
        return os.path.join(STAGE, sid)
    finally:
        os.close(stage_fd)


def code_workspace(tool, leaf):
    return tool == "code" and leaf.casefold().endswith(".code-workspace")


def stage_request(tool, paths):
    if tool not in TOOLS:
        raise Refused(f"unknown tool {tool!r}")
    if not TOOLS[tool]:
        raise Refused(f"{tool} is not configured")
    session = reserve_session()
    try:
        entries = stage_files(session, tool, paths)
        if entries:
            with open(os.path.join(session, "manifest.json"), "x") as f:
                json.dump({"tool": tool, "entries": entries}, f)
            return session
    except BaseException:
        shutil.rmtree(session, ignore_errors=True)
        raise
    shutil.rmtree(session, ignore_errors=True)
    return None


def stage_files(session, tool, paths):
    budget = {"files": MAX_TREE_FILES, "bytes": MAX_SESSION_BYTES}
    entries, root = [], open_root()
    try:
        base = os.open(session, DIR_FLAGS)
    except BaseException:
        os.close(root)
        raise
    try:
        for sp in dict.fromkeys(paths[:MAX_PATHS]):
            try:
                parts = components(sp)
                if code_workspace(tool, parts[-1]):
                    raise Refused("code does not open workspace definition files")
                parent = open_dirs(root, parts[:-1])
                try:
                    st = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                    dparent = stage_dir_fd(base, ["files"] + parts[:-1])
                    try:
                        staged = os.path.join(session, "files", *parts)
                        if stat.S_ISDIR(st.st_mode):
                            if tool == "code":
                                raise Refused(f"code opens files only, not folders: {sp!r}")
                            src = open_dirs(parent, [parts[-1]])
                            try:
                                os.mkdir(parts[-1], 0o700, dir_fd=dparent)
                                dst = os.open(parts[-1], DIR_FLAGS, dir_fd=dparent)
                                try:
                                    snapshot_tree(src, dst, budget)
                                finally:
                                    os.close(dst)
                            finally:
                                os.close(src)
                            entries.append({"parts": parts, "staged": staged, "kind": "dir"})
                        else:
                            fd, fst = open_regular(parent, parts[-1])
                            try:
                                copy_into_session((fd, fst), dparent, parts[-1], budget)
                            finally:
                                os.close(fd)
                            sst = os.stat(staged)
                            entries.append({"parts": parts, "staged": staged, "kind": "file",
                                            "mode": stat.S_IMODE(fst.st_mode), "target": ident(fst),
                                            "seen": staged_identity(sst)})
                    finally:
                        os.close(dparent)
                finally:
                    os.close(parent)
            except OverBudget:
                raise
            except (Refused, OSError) as e:
                log(f"{tool}: skipped {sp!r}: {e}")
    finally:
        os.close(base)
        os.close(root)
    return entries


# ---- write-back --------------------------------------------------------------------------------

def write_back(entry, source):
    """Copy the edited staged file back into the sandbox, never through a symlink."""
    root = open_root()
    try:
        parent = open_dirs(root, entry["parts"][:-1])
    finally:
        os.close(root)
    try:
        stage = os.open(STAGE, DIR_FLAGS)
        try:
            tmp = f".oc-bridge-{secrets.token_hex(12)}"
            out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          entry.get("mode", 0o644) & 0o777, dir_fd=stage)
            try:
                copy_stable_file(source, out, MAX_FILE)
                if SELINUX_LEVEL is not None:
                    if not re.fullmatch(r"s0:c[0-9]+,c[0-9]+", SELINUX_LEVEL):
                        raise Refused("invalid configured bridge SELinux level")
                    context = f"system_u:object_r:container_file_t:{SELINUX_LEVEL}"
                    os.setxattr(out, "security.selinux", context.encode("ascii"))
                try:
                    publish_save(entry, parent, stage, tmp, ident(os.fstat(out)))
                except OSError as error:
                    if error.errno == errno.EXDEV:
                        raise Refused("host stage and sandbox must share a mount for write-back") from error
                    raise
            finally:
                os.close(out)
                try:
                    os.unlink(tmp, dir_fd=stage)
                except FileNotFoundError:
                    pass
        finally:
            os.close(stage)
    finally:
        os.close(parent)


def publish_save(entry, parent, stage, tmp, prepared):
    parts, name = entry["parts"], entry["parts"][-1]
    try:
        cur = os.stat(name, dir_fd=parent, follow_symlinks=False)
        unchanged = stat.S_ISREG(cur.st_mode) and ident(cur) == entry["target"]
    except FileNotFoundError:
        unchanged = False
    if unchanged:
        dest = name
        os.rename(tmp, dest, src_dir_fd=stage, dst_dir_fd=parent)
    else:
        dest = name + ".host-edit"
        if len(os.fsencode(dest)) > os.fpathconf(parent, 'PC_NAME_MAX'):
            dest = "host-edit-" + secrets.token_hex(12)
        os.link(tmp, dest, src_dir_fd=stage, dst_dir_fd=parent, follow_symlinks=False)
    if ident(os.stat(dest, dir_fd=parent, follow_symlinks=False)) != prepared:
        raise Refused("published file changed before verification")
    if unchanged:
        entry["target"] = prepared
    else:
        log(f"{'/'.join(parts)} changed in the sandbox; saved your edit as {dest}")


def open_staged_file(files_fd, parts):
    parent = open_dirs(files_fd, parts[:-1])
    try:
        return open_regular(parent, parts[-1])
    finally:
        os.close(parent)


def sync(files_fd, entries):
    complete = True
    for entry in entries:
        if entry["kind"] != "file":
            continue
        parts = entry["parts"]
        try:
            src_fd, st = open_staged_file(files_fd, parts)
        except (Refused, OSError):
            complete = False
            continue
        try:
            seen = staged_identity(st)
            if seen != entry["seen"]:
                write_back(entry, (src_fd, st))
                entry["seen"] = seen
        except (Refused, OSError) as err:
            complete = False
            log(f"write-back of {'/'.join(parts)} failed: {err}")
        finally:
            os.close(src_fd)
    return complete


def valid_identity(value, length):
    return (isinstance(value, list) and len(value) == length
            and all(type(number) is int for number in value))


def validate_session_entry(tool, entry):
    if not isinstance(entry, dict) or not canonical_parts(entry.get("parts")):
        raise Refused("non-canonical staged path")
    if code_workspace(tool, entry["parts"][-1]):
        raise Refused("code does not open workspace definition files")
    kind = entry.get("kind")
    if kind == "dir" and tool == "bcompare":
        return
    if (kind != "file" or type(entry.get("mode", 0o644)) is not int
            or not valid_identity(entry.get("seen"), 3)
            or not valid_identity(entry.get("target"), 4)):
        raise Refused("invalid staged entry")


def read_session_manifest(session_fd):
    fd, _ = open_regular(session_fd, "manifest.json")
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise Refused("session manifest exceeds the size limit")
    try:
        manifest = json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise Refused("invalid session manifest") from exc
    if not isinstance(manifest, dict):
        raise Refused("invalid session manifest")
    tool, entries = manifest.get("tool"), manifest.get("entries")
    if not isinstance(tool, str) or not TOOLS.get(tool):
        raise Refused("invalid or unconfigured session tool")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_PATHS:
        raise Refused("invalid session entry count")
    recorded_paths = set()
    for entry in entries:
        validate_session_entry(tool, entry)
        path = tuple(entry["parts"])
        if path in recorded_paths:
            raise Refused("duplicate staged path")
        recorded_paths.add(path)
    return tool, entries


def staged_arguments(session, files_fd, entries):
    paths = []
    for entry in entries:
        parts = entry["parts"]
        if entry["kind"] == "dir":
            os.close(open_dirs(files_fd, parts))
        else:
            fd, st = open_staged_file(files_fd, parts)
            try:
                if staged_identity(st) != entry["seen"] or st.st_size > MAX_FILE:
                    raise Refused("staged file changed or exceeds the size limit before editor launch")
            finally:
                os.close(fd)
        # Older manifests store an absolute path. The current session and
        # checked components determine the editor argument.
        paths.append(os.path.join(session, "files", *parts))
    return paths


def run_session(session):
    real = os.path.realpath(session)
    if os.path.dirname(real) != os.path.realpath(STAGE):
        raise Refused("session directory is not in the stage directory")
    session_fd = os.open(real, DIR_FLAGS)
    try:
        tool, entries = read_session_manifest(session_fd)
        files_fd = open_dirs(session_fd, ["files"])
    finally:
        os.close(session_fd)
    try:
        staged = staged_arguments(real, files_fd, entries)
        options = ["--wait", "--"] if tool == "code" else []
        proc = subprocess.Popen([TOOLS[tool], *options, *staged], stdin=subprocess.DEVNULL)
        while proc.poll() is None:
            time.sleep(1)
            sync(files_fd, entries)
        complete = sync(files_fd, entries)
    finally:
        os.close(files_fd)
    if complete:
        shutil.rmtree(real, ignore_errors=True)
    else:
        log(f"could not copy all staged saves back; recover them in {real!r}")


# ---- queue -------------------------------------------------------------------------------------

def unlink_entry(bridge_fd, dir_fd, name):
    """Discard a queue entry without following it or walking any nested directory."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            try:
                os.rmdir(name, dir_fd=dir_fd)
            except OSError as error:
                if error.errno != errno.ENOTEMPTY:
                    raise
                os.rename(name, "ignored-" + secrets.token_hex(12),
                          src_dir_fd=dir_fd, dst_dir_fd=bridge_fd)
        else:
            os.unlink(name, dir_fd=dir_fd)
    except (Refused, OSError):
        pass


def open_queue_dir(parent, name):
    """Open a queue component without following links, removing an invalid leaf if possible."""
    try:
        return os.open(name, DIR_FLAGS, dir_fd=parent)
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            log(f"{name} is not a real directory; removing it (oc-sandbox recreates it)")
            try:
                os.unlink(name, dir_fd=parent)
            except OSError:
                pass
        return None


def read_request(q, name):
    fd, before = open_regular(q, name)
    try:
        data = os.read(fd, MAX_REQUEST_BYTES + 1)
        if len(data) > MAX_REQUEST_BYTES or before.st_size != len(data):
            raise Refused("oversized or incomplete bridge request")
    finally:
        os.close(fd)
    lines = data.decode("utf-8", "surrogateescape").split("\n")
    return lines[0], [line for line in lines[1:] if line]


def expire_stage():
    try:
        now = time.time()
        for e in os.scandir(STAGE):
            if e.is_dir(follow_symlinks=False) and now - e.stat(follow_symlinks=False).st_mtime > STAGE_MAX_AGE:
                shutil.rmtree(e.path, ignore_errors=True)
    except FileNotFoundError:
        pass


def process_queue():
    expire_stage()
    root = open_root()
    try:
        bridge = open_queue_dir(root, ".bridge")
    finally:
        os.close(root)
    if bridge is None:
        return
    try:
        q = open_queue_dir(bridge, "requests")
        if q is not None:
            try:
                drain_queue(bridge, q)
            finally:
                os.close(q)
    finally:
        os.close(bridge)


def drain_queue(bridge, q):
    with os.scandir(q) as contents:
        names = sorted(entry.name for entry in islice(contents, MAX_QUEUE_SCAN))
    try:
        for name in [n for n in names if n.endswith(".req")][:MAX_REQUESTS]:
            try:
                tool, paths = read_request(q, name)
                session = stage_request(tool, paths)
                if session:
                    launch_session(session)
            except (Refused, OSError, subprocess.CalledProcessError) as e:
                log(f"request {name!r} ignored: {e}")
    finally:
        for name in names:
            unlink_entry(bridge, q, name)


def launch_session(session):
    # The transient unit does not inherit our environment.
    setenv = [f"--setenv={k}={os.environ[k]}" for k in CONFIG_VARS if k in os.environ]
    try:
        subprocess.run([*LAUNCH, *setenv, "--", sys.executable, "-I", os.path.realpath(__file__),
                        "session", session], check=True, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        shutil.rmtree(session, ignore_errors=True)
        raise


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "session":
        try:
            run_session(sys.argv[2])
        except (Refused, OSError) as exc:
            log(f"session refused: {exc}")
            sys.exit(2)
    elif len(sys.argv) == 1:
        process_queue()
    else:
        raise SystemExit(__doc__)
