"""Bounded readiness checks from the exact OpenCode worker and database IDs."""

import json
import struct
import time

from profile_plan import CDP_SERVICE, PG_SERVICE, ProfileError, Selection
from profile_services import PASSWORD, SERVICE_ROLE, Sidecars
from runtime import Job, NETNS_LINK, NETNS_PATH, host_output, podman


PG_PARAMS = b"user\0postgres\0database\0postgres\0\0"
PG_STARTUP = struct.pack("!II", 8 + len(PG_PARAMS), 196608) + PG_PARAMS
PG_METHOD = b"SCRAM-SHA-256\0\0"
PG_CHALLENGE = b"R" + struct.pack("!II", 8 + len(PG_METHOD), 10) + PG_METHOD
HTTP_REQUEST = b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:9222\r\nConnection: close\r\n\r\n"
SHELL = "/bin/sh"
MAX_LISTENER_TABLE = 32768
LOOPBACK_ADDRESSES = {b"0100007F", b"00000000000000000000000001000000"}


def _exchange(worker: str, port: int, request: bytes, byte_limit: int) -> bytes:
    encoded = "".join(f"\\0{octet:03o}" for octet in request)
    return podman(
        "exec", worker, SHELL, "-ec",
        '{ printf "%b" "$1"; sleep 1; } | busybox nc -nw 2 127.0.0.1 "$2" | head -c "$3"',
        "--", encoded, str(port), str(byte_limit), timeout=4,
    ).stdout


def _wait_until(check, explanation: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.15)
    raise ProfileError(explanation)


def _chrome_response(response: bytes) -> bool:
    header, separator, body = response.partition(b"\r\n\r\n")
    if not separator or not header.startswith((b"HTTP/1.0 200 ", b"HTTP/1.1 200 ")):
        return False
    try:
        record = json.loads(body)
    except ValueError:
        return False
    return (
        isinstance(record, dict)
        and isinstance(record.get("Browser"), str)
        and record["Browser"].startswith("Chrome/")
        and isinstance(record.get("Protocol-Version"), str)
    )


def _verify_database(worker: str, postgres: str) -> None:
    _wait_until(
        lambda: _exchange(worker, 5432, PG_STARTUP, len(PG_CHALLENGE)) == PG_CHALLENGE,
        "OpenCode worker did not receive PostgreSQL's SCRAM challenge",
    )
    args = (
        "psql", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres",
        "-XwAtq", "-c", "SELECT 1",
    )
    success = podman(
        "exec", postgres, SHELL, "-ec",
        'PGPASSWORD=$(cat "$1"); export PGPASSWORD; shift; exec "$@"',
        "--", PASSWORD, *args, timeout=4,
    )
    rejection = podman(
        "exec", "--env=PGPASSWORD=invalid-fixture-password", postgres, *args, check=False, timeout=4,
    )
    if success.stdout != b"1\n" or rejection.returncode != 2 or b"password authentication failed" not in rejection.stderr:
        raise ProfileError("PostgreSQL did not verify SCRAM and reject invalid credentials")


def _verify_chromium(worker: str, present: bool) -> None:
    if present:
        _wait_until(
            lambda: _chrome_response(_exchange(worker, 9222, HTTP_REQUEST, 16384)),
            "OpenCode worker did not receive Chromium's DevTools version",
        )
        return
    refusal = podman(
        "exec", worker, SHELL, "-ec",
        'busybox wget -T 2 -O /dev/null http://127.0.0.1:9222/json/version',
        check=False, timeout=4,
    )
    if refusal.returncode != 1 or b"Connection refused" not in refusal.stderr:
        raise ProfileError("Skipped Chromium port did not explicitly refuse a worker connection")


def _verify_listeners(worker: str, with_chromium: bool) -> None:
    tables = [
        podman("exec", worker, "busybox", "head", "-c", str(MAX_LISTENER_TABLE + 1), path, timeout=4).stdout
        for path in ("/proc/net/tcp", "/proc/net/tcp6")
    ]
    if any(len(table) > MAX_LISTENER_TABLE for table in tables):
        raise ProfileError("Profile listener evidence exceeds the byte limit")
    sockets = b"\n".join(tables).splitlines()
    ports = {b"1538", b"2406"}
    listeners = set()
    for line in sockets:
        fields = line.split()
        if len(fields) < 4 or fields[3] != b"0A":
            continue
        address, _, port = fields[1].partition(b":")
        if address not in LOOPBACK_ADDRESSES:
            raise ProfileError("Fixture has a non-loopback TCP listener")
        if port in ports:
            listeners.add((address, port))
    expected = {(b"0100007F", b"1538")}
    if with_chromium:
        expected.add((b"0100007F", b"2406"))
    if listeners != expected:
        raise ProfileError("Profile listener addresses did not match the selected loopback endpoints")


def verify_services(job: Job, sidecars: Sidecars, selection: Selection) -> None:
    expected = {SERVICE_ROLE[service] for service in selection.services}
    if sidecars.ids.keys() != expected or sidecars.ids != sidecars.recorded or sidecars.pending:
        raise ProfileError("Sidecar launch receipts did not match the compiled selection")
    worker = job.ids["worker"]
    netns = podman("exec", worker, "readlink", NETNS_PATH).stdout.strip()
    hostnet = host_output("readlink", NETNS_PATH).strip()
    devices = podman("exec", worker, "cat", "/proc/net/dev").stdout.splitlines()[2:]
    names = [line.partition(b":")[0].strip() for line in devices]
    if not NETNS_LINK.fullmatch(netns) or not NETNS_LINK.fullmatch(hostnet) or netns == hostnet or names != [b"lo"]:
        raise ProfileError("Fixture network is not a private loopback-only namespace")
    if sidecars.inventory() != set(sidecars.ids.values()):
        raise ProfileError("Unexpected profile sidecar inventory")
    with_chromium = CDP_SERVICE in selection.services
    _verify_database(worker, sidecars.ids[SERVICE_ROLE[PG_SERVICE]])
    _verify_chromium(worker, with_chromium)
    _verify_listeners(worker, with_chromium)
