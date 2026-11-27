"""Verify the effective user-manager records for the installed host bridge."""

import os
from pathlib import Path
import re
import shlex
import stat
import sys


BRIDGE = "oc-bridge."
TIMER, LEGACY, DRAIN = (BRIDGE + name for name in ("timer", "path", "service"))
FEDORA_DROP_IN = "/usr/lib/systemd/user/service.d/10-timeout-abort.conf"
BRIDGE_ENV = {
    "OC_SB", "OC_BRIDGE_STAGE", "OC_BRIDGE_SELINUX_LEVEL", "OC_CODE_BIN", "OC_BCOMPARE_BIN",
    "OC_BRIDGE_BLOCKING_TOOLS",
}
IDENTITY_FIELDS = {
    "Id", "LoadState", "ActiveState", "Job", "FragmentPath", "DropInPaths",
    "Triggers", "TriggeredBy", "WantedBy", "RequiredBy", "UpheldBy",
}
SERVICE_FIELDS = {
    "Type", "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost",
    "ExecReload", "ExecCondition", "Environment", "EnvironmentFiles",
    "PassEnvironment", "UnsetEnvironment",
}
ACTIVE_STATES = {
    "inactive", "active", "failed", "activating", "deactivating", "reloading",
    "maintenance", "refreshing",
}


def require(condition):
    if not condition:
        raise ValueError("the bridge manager record did not verify")


def properties(raw, fields):
    result = {}
    for line in raw.splitlines():
        name, sep, value = line.partition("=")
        require(sep and name in fields and name not in result)
        result[name] = value
    return result


def known_path(observed, *expected):
    # Resolve only paths established by the launcher. A manager-provided alias
    # may otherwise cross agent-writable directories before reaching storage.
    return any(observed in (value, os.path.realpath(value)) for value in expected)


def one_command(record, expected):
    require(record.startswith("{ path=") and record.endswith(" }") and record.count("{") == record.count("}") == 1)
    path, argv_marker, rest = record.removeprefix("{ path=").partition(" ; argv[]=")
    command, errors_marker, _ = rest.partition(" ; ignore_errors=no ; ")
    require(argv_marker and errors_marker)
    runner = shlex.split(path)
    argv = shlex.split(command)
    require(len(runner) == 1 and len(argv) == len(expected) and known_path(runner[0], expected[0]))
    require(known_path(argv[0], expected[0]) and argv[1:] == expected[1:])


def check_environment(record, sandbox, stage, caller_stage):
    result = {}
    for value in shlex.split(record):
        key, sep, content = value.partition("=")
        require(sep and key in BRIDGE_ENV and key not in result)
        result[key] = content
    require(known_path(result.get("OC_SB", ""), sandbox))
    require(known_path(result.get("OC_BRIDGE_STAGE", ""), stage, caller_stage))


def check_service(record, runner, sandbox, stage, caller_stage, phase):
    require(record.get("Type") == "oneshot")
    require(set(record["TriggeredBy"].split()) <= {TIMER, LEGACY})
    require(not any(record[key] for key in ("WantedBy", "RequiredBy", "UpheldBy")))
    if record["DropInPaths"]:
        require(record["DropInPaths"] == FEDORA_DROP_IN)
        info = os.stat(FEDORA_DROP_IN, follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    hooks = ("ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload", "ExecCondition",
             "EnvironmentFiles", "PassEnvironment", "UnsetEnvironment")
    # The manager omits empty command and environment arrays from show output.
    require(not any(record.get(name) for name in hooks))
    if record.get("ExecStartPre"):
        require(phase in {"existing", "disarmed"})
        one_command(record["ExecStartPre"], ["/usr/bin/sleep", "1"])
    one_command(record["ExecStart"], [runner])
    check_environment(record["Environment"], sandbox, stage, caller_stage)


def check_unit(raw, name, units, caller_units, runner, sandbox, stage, caller_stage, phase):
    record = properties(raw, IDENTITY_FIELDS | SERVICE_FIELDS)
    require(IDENTITY_FIELDS <= record.keys() and record["Id"] == name)
    load, active, job = (record[key] for key in ("LoadState", "ActiveState", "Job"))
    require(load in {"loaded", "not-found"} and active in ACTIVE_STATES and re.fullmatch(r"\d*", job, re.ASCII))
    if load == "not-found":
        require(phase in {"existing", "disarmed"} and not record["FragmentPath"] and not record["DropInPaths"])
        require(active == "inactive" and not job)
        require(not any(record[key] for key in ("Triggers", "TriggeredBy", "WantedBy", "RequiredBy", "UpheldBy")))
    else:
        fragment = Path(record["FragmentPath"])
        require(fragment.name == name and known_path(str(fragment.parent), units, caller_units))
        if name == DRAIN:
            check_service(record, runner, sandbox, stage, caller_stage, phase)
        else:
            require(not record["DropInPaths"] and record["Triggers"] == DRAIN)
    require(name in {TIMER, LEGACY, DRAIN})
    if phase in {"replacement", "disarmed"}:
        require(active in {"inactive", "failed"} and not job)
        if name in {TIMER, LEGACY}:
            require(not any(record[key] for key in ("WantedBy", "RequiredBy", "UpheldBy")))
    print(f"LoadState={load}\nActiveState={active}\nJob={job}")


def check_links(raw, name):
    path_list = properties(raw, {"UnitPath"})
    require(name in {TIMER, LEGACY})
    paths = shlex.split(path_list["UnitPath"])
    require(paths and all(Path(path).is_absolute() for path in paths))
    for directory in map(Path, paths):
        try:
            children = list(directory.iterdir())
        except FileNotFoundError:
            continue
        for child in children:
            if child.name.endswith((".wants", ".requires", ".upholds")):
                try:
                    (child / name).lstat()
                except FileNotFoundError:
                    continue
                raise ValueError("a host bridge activation link remains")


def main():
    raw = sys.stdin.read(65537)
    require(len(raw) <= 65536)
    mode, *args = sys.argv[1:]
    if mode == "links":
        check_links(raw, *args)
    else:
        require(mode == "unit")
        check_unit(raw, *args)


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError):
        raise SystemExit("host bridge manager state could not be verified") from None
