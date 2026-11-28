"""Packaging and appliance measurement for the offline custody fixture."""

from hashlib import sha256
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

from bootstrap import CustodyRefused
from preflight import (
    CORRECTED_OVERLAY, LEGACY, PLAN_OVERLAY, _MAX_FILE, _MAX_FILES, _MAX_MANIFEST, _OBJECT,
    canonical, require_path, scan,
)


_SPIKE = PurePosixPath("docs/prds/spikes/i4/isolated-authority-r3")
_SPIKE_FILES = {"descriptor.py", "receipt.py", "test_receipt.py", "WALKTHROUGH.md"}
_MAX_ARCHIVE = 32 << 20


def _archive(tree, source):
    args = ["/usr/bin/git", "archive", "--format=tar", tree]
    if source is not None:
        args.extend(["--", str(source)])
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        archive = process.stdout.read(_MAX_ARCHIVE + 1)
        if len(archive) > _MAX_ARCHIVE:
            process.kill()
            raise CustodyRefused("source archive exceeds limit")
        if process.wait(timeout=5):
            raise CustodyRefused("source archive unavailable")
    return archive


def _extract(tree, source, destination, *, flat=False):
    archive = _archive(tree, source)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for index, member in enumerate(tar):
            if index >= _MAX_FILES:
                raise CustodyRefused("source archive exceeds entry limit")
            name = require_path(member.name.rstrip("/"))
            if member.isdir():
                continue
            if source is not None:
                name = name.relative_to(source)
            if flat and (len(name.parts) != 1 or name.name not in _SPIKE_FILES):
                continue
            if not member.isfile() or not 0 <= member.size <= _MAX_FILE:
                raise CustodyRefused("invalid measured archive file")
            output = destination / name
            output.parent.mkdir(mode=0o755, exist_ok=True, parents=True)
            with tar.extractfile(member) as stream, output.open("xb") as writer:
                writer.write(stream.read(_MAX_FILE + 1))
            output.chmod(0o444)


def build_bundle(destination, candidate, overlay=PLAN_OVERLAY):
    """Create an unprivileged scratch bundle. Installation is an operator task."""
    if not _OBJECT.fullmatch(candidate) or overlay not in (PLAN_OVERLAY, CORRECTED_OVERLAY):
        raise CustodyRefused("unrecognized source objects")
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    destinations = {name: destination / name for name in ("custody", "spike", "legacy")}
    for directory in destinations.values():
        directory.mkdir(mode=0o755)
    _extract(candidate, _SPIKE / "custody", destinations["custody"])
    _extract(overlay, _SPIKE, destinations["spike"], flat=True)
    _extract(LEGACY, None, destinations["legacy"])
    if {file.name for file in destinations["spike"].iterdir()} != _SPIKE_FILES:
        raise CustodyRefused("receipt overlay does not match required files")
    entries = scan(destination.absolute(), expected_uid=os.geteuid(), manifest_pending=True)
    payload = canonical(["r3-custody", LEGACY, overlay, candidate, entries])
    if len(payload) > _MAX_MANIFEST:
        raise CustodyRefused("measurement manifest exceeds bound")
    manifest = destination / "manifest"
    with manifest.open("xb") as stream:
        stream.write(payload)
    manifest.chmod(0o444)
    return sha256(payload).hexdigest()
