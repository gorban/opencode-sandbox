"""Seal and verify the short-lived offline QEMU guest for the stock worker tool proof."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).parent))

from stock_worker_tools_projection import ACCOUNT, CAPSULE, PROJECTED_TREE, TEST_HOME, checked_node, path_digest


NFT = "/usr/sbin/nft"
TABLE = ("list", "table", "inet", "oc_gemini_fixture")
MANIFEST = CAPSULE / "host.json"
HOST_ID = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
SHARED_FILESYSTEMS = {"9p", "virtiofs", "vboxsf", "fuse.sshfs", "cifs", "nfs", "nfs4", "vmhgfs", "fuse.vmhgfs-fuse"}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def firewall_shape(raw):
    """Check the complete named table, discarding kernel handles and version metadata."""
    objects = json.loads(raw)["nftables"]
    table = []
    chains = []
    rules = []
    for item in objects:
        (kind, info), = item.items()
        if kind == "metainfo":
            continue
        fields = {key: value for key, value in info.items() if key not in {"handle", "index"}}
        if kind == "table":
            table.append(fields)
        elif kind == "chain":
            chains.append(fields)
        elif kind == "rule":
            rules.append(fields)
        else:
            raise RuntimeError("Unexpected object in the offline guest nftables table")
    name = "oc_gemini_fixture"
    base = {"family": "inet", "table": name}
    require(table == [{"family": "inet", "name": name}], "Unexpected offline guest table")
    require(chains == [
        {**base, "name": hook, "type": "filter", "hook": hook, "prio": 0, "policy": "drop"}
        for hook in ("output", "forward")
    ], "The offline guest must drop routed and locally originated non-loopback traffic")
    established = {"left": {"ct": {"key": "state"}}, "op": "==", "right": "established"}
    expected = [
        {**base, "chain": "output", "expr": [
            {"match": {"left": {"meta": {"key": "oifname"}}, "op": "==", "right": "lo"}},
            {"accept": None},
        ]},
        {**base, "chain": "output", "expr": [
            {"match": {"left": {"ct": {"key": "direction"}}, "op": "==", "right": "reply"}},
            {"match": {"left": {"payload": {"protocol": "tcp", "field": "sport"}}, "op": "==", "right": 22}},
            {"match": established},
            {"accept": None},
        ]},
    ]
    equivalent = [
        expected[0],
        {**expected[1], "expr": [*expected[1]["expr"][:2],
                                 {"match": {**established, "op": "in"}}, {"accept": None}]},
    ]
    require(rules in (expected, equivalent), "Unexpected exception to offline guest egress policy")
    # nft renders this exact scalar connection state comparison as either form.
    rules = expected
    measured = [table, chains, rules]
    return hashlib.sha256(json.dumps(measured, sort_keys=True).encode()).hexdigest()


def guest_identity(host):
    def read(path):
        return host("/usr/bin/cat", path).stdout.decode().strip()

    require(host("/usr/bin/systemd-detect-virt", "--vm").stdout.strip() in {b"kvm", b"qemu"},
            "The fixture requires a disposable QEMU/KVM guest")
    require(read("/sys/fs/selinux/enforce") == "1", "Guest SELinux is not enforcing")
    fields = host("/usr/bin/findmnt", "-rn", "-o", "FSTYPE").stdout.decode().splitlines()
    require(fields and not SHARED_FILESYSTEMS.intersection(fields), "The guest has a host shared filesystem")
    boot = read("/proc/sys/kernel/random/boot_id")
    require(re.fullmatch(r"[a-f0-9-]{36}", boot), "Missing guest boot identity")
    return boot


def inventory(podman, uid):
    format_string = "\n".join((
        "{{.Store.GraphRoot}}", "{{.Store.RunRoot}}", "{{.Host.Security.Rootless}}",
        "{{.Host.Security.SELinuxEnabled}}", "{{.Host.CgroupsVersion}}",
    ))
    expected_roots = [str(TEST_HOME / ".local/share/containers/storage"), f"/run/user/{uid}/containers"]
    mode = podman("info", "--format", format_string).stdout.decode().splitlines()
    require(mode == [*expected_roots, "true", "true", "v2"], "The dedicated private rootless Podman store is unavailable")

    def lines(*args):
        return podman(*args).stdout.decode().splitlines()

    ids = lines("ps", "-aq", "--no-trunc")
    images = lines("images", "-aq", "--no-trunc")
    require(all(HOST_ID.fullmatch(value.removeprefix("sha256:")) for value in (*ids, *images)),
            "The guest returned an unqualified container or image ID")
    return {
        "containers": sorted(ids),
        "images": sorted({value.removeprefix("sha256:") for value in images}),
        "pods": sorted(lines("pod", "ps", "-q", "--no-trunc")),
        "volumes": sorted(lines("volume", "ls", "-q")),
        "secrets": sorted(lines("secret", "ls", "--format", "{{.Name}}")),
        "networks": sorted(lines("network", "ls", "--format", "{{.Name}}")),
    }


def seal(devbox, images):
    require(os.getuid() == os.geteuid() == 0, "Seal the disposable guest as root")
    account = pwd.getpwnam(ACCOUNT)
    require(account.pw_uid > 0 and account.pw_dir == str(TEST_HOME), "Missing dedicated guest UID")
    require(HOST_ID.fullmatch(devbox) and images and all(HOST_ID.fullmatch(image) for image in images),
            "Supply the exact reviewed devbox ID and every warmed image ID")
    checked_node(CAPSULE, directory=True, read_only=True)
    manifest = CAPSULE / "manifest.json"
    checked_node(manifest, directory=False, read_only=True)

    def host(*args):
        return subprocess.run(args, check=True, capture_output=True, cwd="/", timeout=30,
                              env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8"})

    def podman(*args):
        return host("/usr/sbin/runuser", "-u", ACCOUNT, "--", "/usr/bin/env", "-i",
                    f"HOME={TEST_HOME}", f"XDG_RUNTIME_DIR=/run/user/{account.pw_uid}",
                    "PATH=/usr/bin:/bin", "/usr/bin/podman", *args)

    boot = guest_identity(host)
    firewall = firewall_shape(host(NFT, "-j", *TABLE).stdout)
    baseline = inventory(podman, account.pw_uid)
    require(baseline == {"containers": [devbox], "images": sorted(set(images)), "pods": [], "volumes": [],
                         "secrets": [], "networks": ["podman"]},
            "The dedicated store has resources outside the approved offline baseline")
    require(podman("container", "inspect", "--format", "{{.State.Running}}", devbox).stdout.strip() == b"true",
            "The sole approved devbox is not running")
    data = {"boot": boot, "uid": account.pw_uid, "firewall": firewall,
            "capsule": path_digest(manifest), "inventory": baseline}
    fd = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, sort_keys=True)
        stream.write("\n")


def bridge_host(*args):
    return subprocess.run(
        ("/usr/bin/host-spawn", "--no-pty", *args), cwd=PROJECTED_TREE, check=True, capture_output=True, timeout=20,
        env={"HOME": str(TEST_HOME), "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "TERM": "dumb"},
    )


def verified_artifact(state, host):
    checked_node(MANIFEST, directory=False, read_only=True)
    artifact = json.loads(MANIFEST.read_text())
    require(artifact["capsule"] == path_digest(CAPSULE / "manifest.json")
            and artifact["uid"] == state.uid and artifact["boot"] == guest_identity(host),
            "Guest identity or boot does not match the sealed offline test environment")
    live_firewall = host("/usr/bin/sudo", "-n", NFT, "-j", *TABLE).stdout
    require(firewall_shape(live_firewall) == artifact["firewall"], "The live guest outbound policy changed")
    return artifact


def verify_live(state):
    verified_artifact(state, bridge_host)


def verify(state, host, podman):
    artifact = verified_artifact(state, host)
    require(inventory(podman, state.uid) == artifact["inventory"], "The private guest Podman inventory changed")
    return {key: artifact[key] for key in ("boot", "firewall", "inventory")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("devbox_id")
    parser.add_argument("--image", action="append", required=True)
    args = parser.parse_args()
    seal(args.devbox_id, args.image)


if __name__ == "__main__":
    main()
