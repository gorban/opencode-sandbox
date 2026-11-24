"""Exercise Antigravity's offline native dependencies in a rootless host namespace."""

import argparse
import hashlib
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
from tempfile import mkdtemp
import time


PINS = {
    "agy": ("7b004d26c3fdea25a7c9d456de4bfaccef4be1e4cc7fd6db628859c5c941fa2d", 320_000_000, 0o500),
    "gnome-keyring-daemon": ("9413d04497ba31b80c9e998c7b9fead378efb04cb53777f0cb1f16551d802458", 2_000_000, 0o500),
    "libgck-1.so.0": ("35375b6bdb4993ca8aea9ef8b253a5a20b432e4381d6ec8552e1be9756dc5578", 2_000_000, 0o400),
    "libgcr-base-3.so.1": ("4938ad69f1bd226631c8422838512712b11434c33abbf89a7f20e47e148337f3", 2_000_000, 0o400),
}
HOST = "/usr/bin/host-spawn"
SYSTEMCTL = "/usr/bin/systemctl"
NATIVE = "/run/oc-native"
SCRATCH = "/run/oc-proof"


class QualificationError(RuntimeError):
    """A fixed failure suitable for operator output."""


class RetirementUnknown(QualificationError):
    """Private scratch must remain until the host service is verified stopped."""


def workstation_env(uid):
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": pwd.getpwuid(uid).pw_dir,
            "XDG_RUNTIME_DIR": f"/run/user/{uid}", "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/host/run/user/{uid}/bus"}


def host(command, *, timeout=10):
    return subprocess.run([HOST, "--no-pty", *command], cwd="/", env=workstation_env(os.getuid()),
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False)


def private_shared_runtime():
    uid = os.getuid()
    runtime = Path(f"/run/user/{uid}")
    info = runtime.lstat()
    if not uid or info.st_uid != uid or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise QualificationError("requires a private non-root workstation runtime directory")
    measured = host(["/usr/bin/stat", "-c", "%d:%i:%u:%f", "--", str(runtime)])
    expected = f"{info.st_dev}:{info.st_ino}:{uid}:{info.st_mode:x}".encode()
    if measured.returncode or measured.stdout.strip() != expected:
        raise QualificationError("host and devbox runtime identity differ")
    return runtime


def stage(source, target):
    digest, limit, mode = PINS[target.name]
    with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as reader:
        info = os.fstat(reader.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise QualificationError("unsafe local native dependency")
        sha = hashlib.sha256()
        size = 0
        with target.open("xb") as out:
            while block := reader.read(1024 * 1024):
                size += len(block)
                if size > limit:
                    raise QualificationError("native dependency exceeded its size limit")
                sha.update(block)
                out.write(block)
        if sha.hexdigest() != digest:
            raise QualificationError(f"unrecognized local {target.name} build")
        target.chmod(mode)


def seed(root, agy, keyring):
    programs, config, work, outside = (root / name for name in ("native", "etc", "work", "outside"))
    for directory in (programs, config, work, outside):
        directory.mkdir(mode=0o700)
    stage(agy, programs / "agy")
    for name in PINS.keys() - {"agy"}:
        stage(keyring / name, programs / name)
    shutil.copyfile(Path(__file__).with_name("native-fixture.py"), programs / "native-fixture.py")
    uid, gid = os.getuid(), os.getgid()
    (config / "passwd").write_text(f"root:x:0:0:root:/root:/bin/false\nfixture:x:{uid}:{gid}:fixture:{SCRATCH}:/bin/false\n")
    (config / "group").write_text(f"root:x:0:\nfixture:x:{gid}:\n")
    (config / "machine-id").write_text(secrets.token_hex(16) + "\n")
    (outside / "marker").write_text("synthetic workstation fixture\n")
    return programs, config, work, outside


def command(unit, programs, config, work, outside, port, interruption):
    return ["/usr/bin/systemd-run", "--user", "--quiet", "--wait", "--pipe", "--collect",
            f"--unit={unit}", "--property=KillMode=control-group", "--property=RuntimeMaxSec=25s",
            "--property=TimeoutStopSec=3s", "--property=NoNewPrivileges=yes", "--expand-environment=no", "--",
            "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns", "--cap-drop", "ALL",
            "--new-session", "--die-with-parent", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin",
            "--setenv", "LANG", "C.UTF-8", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--ro-bind", str(config), "/etc", "--ro-bind", str(programs), NATIVE, "--bind", str(work), SCRATCH,
            "--chdir", SCRATCH, "--", "/usr/bin/python3", "-IBS", f"{NATIVE}/native-fixture.py", str(outside),
            str(port), "cancel" if interruption else "complete"]


def stop(unit):
    try:
        host([SYSTEMCTL, "--user", "stop", unit])
        status = host([SYSTEMCTL, "--user", "show", "--property=ActiveState,ControlGroup", unit])
    except (KeyboardInterrupt, OSError, subprocess.SubprocessError) as error:
        raise RetirementUnknown("could not verify qualification service retirement") from error
    fields = dict(line.split(b"=", 1) for line in status.stdout.splitlines() if b"=" in line)
    if status.returncode or fields.get(b"ControlGroup") != b"" or fields.get(b"ActiveState") not in (b"inactive", b"failed"):
        raise RetirementUnknown("the exact qualification service did not retire")


def verify_completion(unit, launch, work):
    try:
        verify = host(launch, timeout=33)
    except (KeyboardInterrupt, OSError, subprocess.SubprocessError) as error:
        raise RetirementUnknown("the launch receipt was interrupted") from error
    finally:
        stop(unit)
    if verify.stdout.strip() != b"ACP_SIGNED_OUT" or verify.returncode or any(work.iterdir()):
        raise QualificationError("native fixture did not confirm its expected result and cleanup")


def verify_interruption(unit, launch, work):
    with subprocess.Popen([HOST, "--no-pty", *launch], cwd="/", env=workstation_env(os.getuid()),
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as service:
        deadline = time.monotonic() + 12
        observed = False
        try:
            while service.poll() is None and time.monotonic() < deadline:
                if (work / "cancel-ready").is_file():
                    observed = True
                    break
                time.sleep(.05)
            else:
                raise QualificationError("could not observe the live private keyring before cancellation")
        except KeyboardInterrupt as error:
            if not observed:
                raise RetirementUnknown("the launch receipt was interrupted") from error
            raise
        finally:
            stop(unit)
            service.wait(timeout=5)


def run(root, agy, keyring):
    programs, config, work, outside = seed(root, agy, keyring)
    remote_net = host(["/usr/bin/readlink", "/proc/self/ns/net"])
    if remote_net.returncode or remote_net.stdout.strip() != os.readlink("/proc/self/ns/net").encode():
        raise QualificationError("devbox and workstation do not share the test listener namespace")
    with socket.socket() as listener, socket.socket(socket.AF_UNIX) as private_socket:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        private_socket.bind(str(outside / "private.sock"))
        private_socket.listen(1)
        for interruption, verify in ((False, verify_completion), (True, verify_interruption)):
            unit = f"oc-agy-offline-{secrets.token_hex(8)}.service"
            launch = command(unit, programs, config, work, outside, listener.getsockname()[1], interruption)
            verify(unit, launch, work)


def interrupt(_number, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agy", type=Path, required=True)
    parser.add_argument("--keyring-bundle", type=Path, required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupt)
    directory = None
    retain = False
    try:
        directory = Path(mkdtemp(prefix="oc-agy-native-", dir=private_shared_runtime()))
        run(directory, args.agy, args.keyring_bundle)
    except RetirementUnknown as error:
        retain = True
        print(f"Antigravity qualification: {error}. Retained synthetic scratch {directory}", file=sys.stderr)
        return 1
    except QualificationError as error:
        print(f"Antigravity qualification: {error}", file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError):
        print("Antigravity qualification: workstation setup or cleanup failed", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if directory is not None and not retain:
            shutil.rmtree(directory)
    print("Rootless isolation, synthetic keyring restart, signed-out ACP and cancellation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
