"""Construct the measured signed-out standalone ACP host placement."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import shutil
import stat

from .native_artifacts import StagedNativeBuild


BROWSER_MOUNT_TARGET = "/usr/bin/xdg-open"

_NATIVE = "/run/oc-native"
_WORK = "/run/oc-proof"
_REPLICA_FD = "@oc-replica-fd@"
_PUBLIC_PEM = re.compile(rb"(?:-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----(?:\r?\n|$))+\Z")
_OPEN_REPLICA = """
import os
import stat
import sys

source, device, inode, executable, *arguments = sys.argv[1:]
fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
info = os.fstat(fd)
if ((info.st_dev, info.st_ino, info.st_uid) != (int(device), int(inode), os.geteuid())
        or stat.S_IMODE(info.st_mode) != 0o700 or arguments.count('@oc-replica-fd@') != 1):
    raise SystemExit(1)
arguments[arguments.index('@oc-replica-fd@')] = str(fd)
os.set_inheritable(fd, True)
os.execv(executable, [executable, *arguments])
"""


class NativeNamespaceError(RuntimeError):
    """The rootless native fixture cannot be placed as measured."""


@dataclass(frozen=True, slots=True)
class NativeNamespace:
    unit: str
    description: str
    argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _MetadataMounts:
    profile: Path
    connector: Path
    ca: Path
    browser: Path | None = None
    mount_source: tuple[Path, int, int] | None = None


def _private(path):
    node = path.lstat()
    return stat.S_ISDIR(node.st_mode) and node.st_uid == os.getuid() and stat.S_IMODE(node.st_mode) == 0o700


def _new_tree(path):
    path.mkdir(mode=0o700)
    if not _private(path):
        raise NativeNamespaceError("Standalone Google ACP directory is not private")


def prepare_signed_out_namespace(root: Path, build: StagedNativeBuild) -> NativeNamespace:
    """Place the exact standalone binary with an empty private home and no network.

    The caller owns the fresh runtime root, starts the generated unit, and
    confirms its retirement before removing the root. No signup or live route
    is enabled in this placement.
    """
    return _prepare_namespace(root, build)


def reserve_native_unit():
    return f"oc-google-acp-{secrets.token_hex(12)}.service"


def prepare_cold_namespace(root: Path, build: StagedNativeBuild, *, profile, mount_source, connector, ca, unit=None) -> NativeNamespace:
    """Allow only a pinned profile and the listener's private metadata socket."""
    return _prepare_namespace(root, build, transport=_MetadataMounts(profile, connector, ca, mount_source=mount_source), unit=unit)


def prepare_enrollment_namespace(root, build, *, profile, mount_source, connector, ca, browser, unit=None):
    """Limit the OAuth handoff to the owner-only private socket in the namespace."""
    return _prepare_namespace(root, build, transport=_MetadataMounts(profile, connector, ca, browser, mount_source),
                              unit=unit)


def _prepare_namespace(root, build, *, transport=None, unit=None):
    uid, gid = os.getuid(), os.getgid()
    try:
        if (not uid or not root.is_absolute() or not _private(root)
                or build.entrypoint != root / "native" / "agy_acp_server.par" or not _private(root / "native")):
            raise NativeNamespaceError("Unverified standalone Google ACP staging root")
        config, work = root / "etc", root / "work"
        _new_tree(config)
        _new_tree(work)
        _new_tree(work / "home")
        _new_tree(work / "gemini")
        _new_tree(work / "empty")
        environment = [("HOME", _WORK + "/home"), ("GEMINI_HOME", _WORK + "/gemini")]
        for key in ("CONFIG", "CACHE", "DATA", "STATE", "RUNTIME"):
            name = key.lower()
            _new_tree(work / "home" / name)
            suffix = "DIR" if key == "RUNTIME" else "HOME"
            environment.append((f"XDG_{key}_{suffix}", f"{_WORK}/home/{name}"))
        if transport is None:
            gemini = work / "gemini" / "antigravity-acp"
            _new_tree(gemini)
            (gemini / "settings.json").write_text('{"telemetry":{"enabled":false}}', encoding="ascii")
            (gemini / "settings.json").chmod(0o600)
        (config / "passwd").write_text(
            f"root:x:0:0:root:/root:/bin/false\nfixture:x:{uid}:{gid}:fixture:{_WORK}:/bin/false\n", encoding="ascii",
        )
        (config / "group").write_text(f"root:x:0:\nfixture:x:{gid}:\n", encoding="ascii")
        (config / "machine-id").write_text(secrets.token_hex(16) + "\n", encoding="ascii")
        (config / "cpu-possible").write_text("0-255\n", encoding="ascii")
    except OSError:
        raise NativeNamespaceError("Standalone Google ACP runtime staging is unavailable") from None
    if unit is None:
        unit = reserve_native_unit()
    if type(unit) is not str or re.fullmatch(r"oc-google-acp-[a-f0-9]{24}\.service", unit) is None:
        raise NativeNamespaceError("Invalid native Google unit name")
    description = "oc-sandbox ACP " + secrets.token_hex(16)
    lifetime = "196s" if transport is not None and transport.browser is not None else "25s"
    setenv = tuple(arg for key, value in environment for arg in ("--setenv", key, value))
    mounts, command = _native_command(root, transport)
    bootstrap = ()
    if transport is not None and transport.mount_source is not None:
        source, device, inode = transport.mount_source
        bootstrap = ("/usr/bin/python3", "-IBS", "-c", _OPEN_REPLICA, str(source), str(device), str(inode))
    return NativeNamespace(unit, description, (
        "/usr/bin/systemd-run", "--user", "--quiet", "--wait", "--pipe", "--collect", f"--unit={unit}",
        f"--description={description}",
        "--property=KillMode=control-group", f"--property=RuntimeMaxSec={lifetime}", "--property=TimeoutStopSec=3s",
        "--property=NoNewPrivileges=yes", "--expand-environment=no", "--", *bootstrap, "/usr/bin/bwrap", "--unshare-all",
        "--unshare-user", "--disable-userns", "--cap-drop", "ALL", "--new-session", "--die-with-parent",
        "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8",
        "--setenv", "TMPDIR", "/tmp", *setenv,
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--ro-bind", str(config), "/etc", "--ro-bind", str(root / "native"), _NATIVE,
        "--bind", str(work), _WORK,
        "--ro-bind", str(config / "cpu-possible"), "/sys/devices/system/cpu/possible",
        *mounts, "--chdir", _WORK + "/empty", "--", *command,
    ))


def _private_socket(path, name):
    return path.name == name and _private(path.parent) and stat.S_ISSOCK(path.lstat().st_mode)


def _stage_shim(root, source, name, mode):
    shim = root / "native" / name
    with Path(__file__).with_name(source).open("rb") as reader, shim.open("xb") as writer:
        shutil.copyfileobj(reader, writer)
    shim.chmod(mode)
    return shim


def public_certificate(pem):
    """Read certificate-only PEM and refuse a combined private-key bundle."""
    try:
        fd = os.open(pem, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise NativeNamespaceError("Google native TLS certificate is not trusted")
            data = source.read(65537)
            if len(data) > 65536 or len(data) != info.st_size or _PUBLIC_PEM.fullmatch(data) is None:
                raise NativeNamespaceError("Google native TLS mount requires certificate-only PEM")
            return data
    except OSError:
        raise NativeNamespaceError("Google native TLS certificate is unavailable") from None


def _native_command(root, mounts):
    if mounts is None:
        return (), (_NATIVE + "/agy_acp_server.par", "--uid=")
    profile, connector, ca, browser = mounts.profile, mounts.connector, mounts.ca, mounts.browser
    paths = (profile, connector, ca) if browser is None else (profile, connector, ca, browser)
    try:
        cert_info = ca.lstat()
        if (any(not path.is_absolute() or path.resolve(strict=True) != path for path in paths)
                or not _private(profile) or not _private_socket(connector, "metadata.sock")
                or not stat.S_ISREG(cert_info.st_mode) or cert_info.st_uid != os.geteuid()
                or cert_info.st_nlink != 1 or cert_info.st_mode & 0o022 or ca.parent != root):
            raise NativeNamespaceError("Invalid private Google metadata mounts")
        if mounts.mount_source is not None:
            source, device, inode = mounts.mount_source
            pinned = source.stat()
            if (re.fullmatch(r"/proc/[1-9][0-9]*/fd/[0-9]+", str(source)) is None
                    or not os.path.samestat(profile.lstat(), pinned) or (pinned.st_dev, pinned.st_ino) != (device, inode)):
                raise NativeNamespaceError("Google native metadata mount is not the pinned profile")
        public_ca = root / "native-public-ca.pem"
        with public_ca.open("xb") as output:
            output.write(public_certificate(ca))
        public_ca.chmod(0o400)
        _stage_shim(root, "native_proxy.py", "metadata-proxy.py", 0o400)
        browser_mounts = ()
        if browser is not None:
            if not _private_socket(browser, "browser.sock"):
                raise NativeNamespaceError("Invalid private Google callback mount")
            shim = _stage_shim(root, "native_browser.py", "browser-offer", 0o500)
            browser_mounts = ("--ro-bind", str(browser), "/run/oc-transport/browser.sock",
                              "--ro-bind", str(shim), BROWSER_MOUNT_TARGET,
                              "--setenv", "BROWSER", _NATIVE + "/browser-offer")
    except OSError:
        raise NativeNamespaceError("Could not stage the private native metadata relay") from None
    cert = "/run/oc-transport/metadata-ca.pem"
    replica_mount = (("--bind", str(profile)) if mounts.mount_source is None else ("--bind-fd", _REPLICA_FD))
    return (
        *replica_mount, _WORK + "/gemini",
        "--ro-bind", str(connector), "/run/oc-transport/metadata.sock",
        "--ro-bind", str(public_ca), cert,
        "--setenv", "SSL_CERT_FILE", cert, "--setenv", "REQUESTS_CA_BUNDLE", cert,
        "--setenv", "CURL_CA_BUNDLE", cert, *browser_mounts,
    ), ("/usr/bin/python3", "-IBS", _NATIVE + "/metadata-proxy.py", "enroll" if browser is not None else "cold")
