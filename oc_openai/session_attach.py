"""Invocation-private Podman evidence for a filtered attached start."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

from .connection_state import decode_json
from .managed.runtime import JobRuntimeError, host_output


_MAX_EVENT_BYTES = 64 * 1024


def _identity(info: os.stat_result) -> bytes:
    return f"{info.st_dev}:{info.st_ino}:{info.st_uid}:{stat.S_IMODE(info.st_mode):o}:{info.st_nlink}".encode("ascii")


def verify_shared_file(path: Path, fd: int) -> None:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
        or not os.path.samestat(info, path.lstat())
        or host_output("stat", "-c", "%d:%i:%u:%a:%h", "--", str(path)).strip() != _identity(info)
    ):
        raise JobRuntimeError("Could not confirm a private shared attach evidence file")


def _read_positive_attach(fd: int, path: Path, container_id: str) -> None:
    verify_shared_file(path, fd)
    raw = os.read(fd, _MAX_EVENT_BYTES + 1)
    if len(raw) > _MAX_EVENT_BYTES or not raw.endswith(b"\n"):
        raise JobRuntimeError("Podman did not verify the attached worker")
    matches = 0
    try:
        for line in raw.splitlines():
            event = decode_json(line)
            if (
                type(event) is dict and event.get("Type") == "container"
                and event.get("Status") == "attach" and event.get("ID") == container_id
            ):
                matches += 1
    except ValueError:
        raise JobRuntimeError("Malformed Podman attach evidence") from None
    if matches != 1:
        raise JobRuntimeError("Podman did not verify the attached worker")


@contextmanager
def private_shared_file(path: Path):
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o600)
    try:
        verify_shared_file(path, fd)
        yield fd
    finally:
        os.close(fd)


@contextmanager
def filtered_attach_evidence(root: Path, container_id: str):
    event_path = root / "worker-attach.events"
    config = root / "worker-attach.conf"
    with private_shared_file(event_path) as event_fd, private_shared_file(config) as config_fd:
        source = '[engine]\nevents_logger="file"\nevents_logfile_path=' + json.dumps(str(event_path)) + "\n"
        data = source.encode("ascii")
        if os.write(config_fd, data) != len(data):
            raise JobRuntimeError("Could not write Podman attach configuration")
        yield SimpleNamespace(
            variables={"CONTAINERS_CONF_OVERRIDE": str(config)},
            options=("--events-backend=file",),
            verify=lambda: _read_positive_attach(event_fd, event_path, container_id),
        )
