#!/usr/bin/env python3
"""Verify the real relay's revocation and retirement after launcher SIGKILL."""

from contextlib import nullcontext
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from oc_orchestrator.owner import Lifeline
from oc_orchestrator.runtime import Failure, LABEL, fixture_request, inspect, placed_broker, podman, run_open_code, scratch_parent


def launch_label(root, count):
    scope = ("--all",) if count == 1 else ()
    identifiers = podman("ps", *scope, "--filter", f"label={LABEL}", "--quiet", "--no-trunc").stdout.splitlines()
    labels = []
    for identifier in identifiers:
        try:
            data = inspect("container", identifier.decode("ascii"))
        except Failure:
            continue
        if any(Path(mount["Source"]).is_relative_to(root) for mount in data["Mounts"]):
            labels.append(data["Config"]["Labels"][LABEL])
    if len(labels) == count and len(set(labels)) == 1:
        return labels[0]
    return None


def wait_for_launch(launcher, count):
    children = Path(f"/proc/{launcher.pid}/task/{launcher.pid}/children")
    deadline = time.monotonic() + 30
    while launcher.poll() is None and time.monotonic() < deadline:
        for pid in children.read_text().split():
            for root in scratch_parent().glob(f"oc-orch-{pid}-*"):
                label = launch_label(root, count)
                if label:
                    return root, label
        time.sleep(0.03)
    raise Failure(f"could not observe the requested test-owned placement stage ({count})")


def wait_for_retirement(root, label):
    deadline = time.monotonic() + 25
    selector = f"label={LABEL}={label}"
    while time.monotonic() < deadline:
        if not root.exists() and not podman("ps", "--all", "--filter", selector, "--quiet").stdout.strip():
            return
        time.sleep(0.08)
    raise Failure("the detached owner did not retire both containers and private scratch")


def check_owner_loss(count):
    env = {"PATH": "/usr/bin:/bin", "CONTAINER_ID": os.environ["CONTAINER_ID"]}
    with subprocess.Popen([ROOT / "oc-sandbox", "orchestrate", "--synthetic-check"], cwd=ROOT,
                          env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as launcher:
        try:
            run = wait_for_launch(launcher, count)
        except BaseException:
            if launcher.poll() is None:
                launcher.terminate()
            raise
        launcher.kill()
        launcher.wait(timeout=5)
    wait_for_retirement(*run)
    print(f"Launcher loss at placement stage {count} retired the owned containers and private scratch.")


def check_before_delivery():
    lifeline = SimpleNamespace(check=lambda: None, active=lambda: True, revoke_on_loss=lambda _: nullcontext())
    with placed_broker(lifeline) as (worker, _, initial):
        run_open_code(worker)
        body = initial.receipt()[3]
        if not body:
            raise Failure("no recorded OpenCode request")

    read_fd, write_fd = os.pipe()
    with os.fdopen(read_fd, "rb") as read_end, os.fdopen(write_fd, "wb") as write_end:
        lifeline = Lifeline(read_end.fileno())
        with placed_broker(lifeline, before_delivery=write_end.close) as (_, relay, broker):
            reply = fixture_request(relay, body, count_bytes=True)
            if reply != b"0\n" or broker.receipt() != (1, 0, "recorded_offline", body):
                raise Failure("owner EOF did not fence the response after one admission")
    print("Owner EOF before delivery through the running relay yielded zero raw client bytes.")


def main():
    if not os.environ.get("CONTAINER_ID"):
        raise Failure("requires the qualified devbox placement")
    check_owner_loss(1)
    check_owner_loss(2)
    check_before_delivery()


if __name__ == "__main__":
    main()
