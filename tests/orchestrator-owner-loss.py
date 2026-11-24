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

from oc_orchestrator.runtime import Failure, LABEL, fixture_request, inspect, placed_broker, podman, run_open_code


def running_label(root):
    identifiers = podman("ps", "--filter", f"label={LABEL}", "--quiet", "--no-trunc").stdout.splitlines()
    labels = []
    for identifier in identifiers:
        try:
            data = inspect("container", identifier.decode("ascii"))
        except Failure:
            continue
        if any(Path(mount["Source"]).is_relative_to(root) for mount in data["Mounts"]):
            labels.append(data["Config"]["Labels"][LABEL])
    if len(labels) == 2 and labels[0] == labels[1]:
        return labels[0]
    return None


def wait_for_launch(launcher):
    children = Path(f"/proc/{launcher.pid}/task/{launcher.pid}/children")
    deadline = time.monotonic() + 30
    while launcher.poll() is None and time.monotonic() < deadline:
        for pid in children.read_text().split():
            for root in Path("/tmp").glob(f"oc-orch-{pid}-*"):
                label = running_label(root)
                if label:
                    return root, label
        time.sleep(0.03)
    raise Failure("could not observe both test-owned containers running")


def wait_for_retirement(root, label):
    deadline = time.monotonic() + 25
    selector = f"label={LABEL}={label}"
    while time.monotonic() < deadline:
        if not root.exists() and not podman("ps", "--all", "--filter", selector, "--quiet").stdout.strip():
            return
        time.sleep(0.08)
    raise Failure("the detached owner did not retire both containers and private scratch")


def check_owner_loss():
    env = {"PATH": "/usr/bin:/bin", "CONTAINER_ID": os.environ["CONTAINER_ID"]}
    with subprocess.Popen([ROOT / "oc-sandbox", "orchestrate", "--synthetic-check"], cwd=ROOT,
                          env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as launcher:
        try:
            run = wait_for_launch(launcher)
        except BaseException:
            if launcher.poll() is None:
                launcher.terminate()
            raise
        launcher.kill()
        launcher.wait(timeout=5)
    wait_for_retirement(*run)
    print("Launcher loss retired both owned containers and private scratch.")


def check_before_delivery():
    lifeline = SimpleNamespace(check=lambda: None, revoke_on_loss=lambda _: nullcontext())
    with placed_broker("distrobox", lifeline) as (worker, _, initial):
        run_open_code(worker)
        body = initial.receipt()[3]
        if not body:
            raise Failure("no recorded OpenCode request")

    def revoke():
        broker.revoke()

    with placed_broker("distrobox", lifeline, before_delivery=revoke) as (_, relay, broker):
        reply = fixture_request(relay, body)
        if reply != b"\n" or broker.receipt() != (1, 0, "recorded_offline", body):
            raise Failure("revocation did not fence the response after one admission")
    print("Revoked before delivery through the running relay and observed zero client bytes.")


def main():
    if not os.environ.get("CONTAINER_ID"):
        raise Failure("requires the qualified devbox placement")
    check_owner_loss()
    check_before_delivery()


if __name__ == "__main__":
    main()
