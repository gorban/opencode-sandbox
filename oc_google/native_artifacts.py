"""Stage the exact qualified standalone Antigravity editor ACP artifacts."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat


_PINNED = {
    "agy_acp_server.par": (714384320, "f472860b79c4816a32817e589afdb01cec0ca731e5fa428eae873b14be12387f"),
    "localharness_external": (139194456, "072fc497e7814b0e25a7d80109bceddacd815eb351d2e48ce579a05510e0cfdf"),
}
_ENTRY = "agy_acp_server.par"
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class NativeArtifactError(RuntimeError):
    """The launcher must refuse to start an unverified native build."""


@dataclass(frozen=True, slots=True)
class StagedNativeBuild:
    entrypoint: Path
    digest: str


def _fingerprint(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _open_member(source, name, size):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=source)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                or info.st_mode & 0o022 or info.st_size != size):
            raise NativeArtifactError("Unrecognized standalone Google ACP artifact")
    except BaseException:
        os.close(fd)
        raise
    return fd, info


def verify_standalone_source(source_fd: int):
    """Check the two pinned members before consent without reading their contents."""
    try:
        for name, (size, _) in _PINNED.items():
            fd, _ = _open_member(source_fd, name, size)
            os.close(fd)
    except OSError:
        raise NativeArtifactError("Standalone Google ACP artifacts are unavailable") from None


def _copy_member(source, destination, name, size, digest):
    fd, before = _open_member(source, name, size)
    with os.fdopen(fd, "rb") as reader:
        created = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=destination)
        with os.fdopen(created, "wb") as out:
            remaining = size
            checksum = hashlib.sha256()
            while remaining:
                chunk = reader.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise NativeArtifactError("Standalone Google ACP artifact changed during staging")
                checksum.update(chunk)
                out.write(chunk)
                remaining -= len(chunk)
            if (checksum.hexdigest() != digest or reader.read(1)
                    or _fingerprint(before) != _fingerprint(os.fstat(reader.fileno()))):
                raise NativeArtifactError("Standalone Google ACP artifact did not match its pin")
            out.flush()
            os.fchmod(out.fileno(), 0o500)
            os.fsync(out.fileno())


def stage_standalone(source: Path | int, destination: Path) -> StagedNativeBuild:
    """Copy the fixed pair into a launcher-owned empty private directory.

    The private staging tree belongs to the supervisor. It may contain an
    incomplete file after refusal and may be mounted only after success.
    """
    try:
        if not destination.is_absolute() or destination.resolve(strict=True) != destination:
            raise NativeArtifactError("Standalone Google ACP staging path is not canonical")
        src = os.dup(source) if isinstance(source, int) else os.open(source, _DIRECTORY)
        try:
            dst = os.open(destination, _DIRECTORY)
            try:
                info = os.fstat(dst)
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or os.listdir(dst):
                    raise NativeArtifactError("Standalone Google ACP staging is not private and empty")
                for name, (size, digest) in _PINNED.items():
                    _copy_member(src, dst, name, size, digest)
                if not os.path.samestat(info, destination.lstat()):
                    raise NativeArtifactError("Standalone Google ACP staging directory changed")
                os.fsync(dst)
            finally:
                os.close(dst)
        finally:
            os.close(src)
    except OSError:
        raise NativeArtifactError("Standalone Google ACP staging is unavailable") from None
    identity = hashlib.sha256(b"oc-sandbox/google-standalone-acp/v1\0")
    for name, (size, digest) in sorted(_PINNED.items()):
        identity.update(f"{name}\0{size}\0{digest}\n".encode("ascii"))
    return StagedNativeBuild(destination / _ENTRY, identity.hexdigest())
