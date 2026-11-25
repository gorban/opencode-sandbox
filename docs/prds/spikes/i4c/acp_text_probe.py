"""Run the pinned OpenCode orchestrator fixture through a bundled ACP peer."""

from contextlib import ExitStack, contextmanager
import fcntl
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile


SOURCE = Path(__file__).resolve()
if __name__ == "__main__" and not sys.flags.isolated:
    raise SystemExit("Run the ACP spike with python3 -IB from the trusted checkout.")
sys.path[:0] = [str(SOURCE.parent), str(SOURCE.parents[4])]

from acp_readiness import RetirementUnconfirmed, _private_file, _status, enroll_fixture
from acp_text_broker import TextBroker
from acp_text_session import PublicationUnconfirmed, open_text_session
from oc_orchestrator.owner import OwnerLost, accept_launch, supervise
from oc_orchestrator.protocol import PORT, REFUSAL
from oc_orchestrator.runtime import (
    CONTAINER_SHELL, OPEN_CODE, RELAY, RELAY_PYTHON, Failure, Placement,
    check_private_directory, fixture_request, podman, preflight, run_open_code,
    scratch_parent, seeds, wait_relay,
)
from oc_providers import ReadinessState


@contextmanager
def synthetic_state():
    root = Path(tempfile.mkdtemp(prefix="oc-acp-text-state-", dir=scratch_parent()))
    created = root.lstat()
    retained = False
    try:
        check_private_directory(root)
        yield root
    except (RetirementUnconfirmed, PublicationUnconfirmed):
        retained = True
        print(f"ACP spike retained synthetic state at {root}", file=sys.stderr)
        raise
    finally:
        if not retained:
            discard_synthetic_state(root, created)


def remove_owned_directory(root, created):
    if not os.path.samestat(root.lstat(), created):
        raise Failure("the owned scratch directory changed")
    shutil.rmtree(root)


def discard_synthetic_state(root, created):
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if not os.path.samestat(os.fstat(directory), created):
                raise Failure("the synthetic state directory changed")
            lock = os.open("readiness.lock", os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                           0o600, dir_fd=directory)
            try:
                _private_file(lock)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Failure("the synthetic ACP journal is still locked") from None
                status = _status(directory)
                if status is not None and status.readiness is ReadinessState.REVOCATION_UNCONFIRMED:
                    raise RetirementUnconfirmed("synthetic ACP retirement is unconfirmed")
                remove_owned_directory(root, created)
            finally:
                os.close(lock)
        finally:
            os.close(directory)
    except (OSError, RuntimeError):
        print(f"ACP spike retained synthetic state at {root}", file=sys.stderr)
        raise


@contextmanager
def isolated_placement(lifeline):
    root = Path(tempfile.mkdtemp(prefix="oc-acp-text-placement-", dir=scratch_parent()))
    created = root.lstat()
    placement = Placement(root, lifeline)
    try:
        check_private_directory(root)
        yield placement
    finally:
        try:
            placement.close()
            remove_owned_directory(root, created)
        except (OSError, Failure):
            print(f"ACP spike retained placement at {root}", file=sys.stderr)
            raise


def create_inert_pair(placement, worker_files, relay_files):
    home = {"HOME": "/job-home", "TMPDIR": "/job-tmp", "XDG_CONFIG_HOME": "/job-home/config",
            "OPENCODE_CONFIG_PROJECT_DISABLE": "true"}
    worker = placement.create("open-code", OPEN_CODE, "none", worker_files / "opencode.json",
                              "/etc/opencode/opencode.json", home, ("/job-home", "/job-tmp", "/workspace"),
                              CONTAINER_SHELL, "-c", "exec sleep 90")
    relay = placement.create("relay", RELAY, f"container:{worker}", relay_files, "/fixture", {}, (),
                             CONTAINER_SHELL, "-c", "exec sleep 90")
    placement.verify_pair(worker, relay)
    return worker, relay


def verify_prearm_refusal(relay):
    # Placement has verified that these containers share only the network namespace.
    # Observe the socket table first, then exercise a negative connection in that namespace.
    program = """import errno, socket, sys
port = int(sys.argv[1])
for name in ('tcp', 'tcp6'):
    with open('/proc/net/' + name) as table:
        for row in list(table)[1:]:
            fields = row.split()
            if fields[3] == '0A' and int(fields[1].rsplit(':', 1)[1], 16) == port:
                raise SystemExit(1)
with socket.socket() as client:
    client.settimeout(1)
    if client.connect_ex(('127.0.0.1', port)) != errno.ECONNREFUSED:
        raise SystemExit(1)
"""
    podman("exec", relay, RELAY_PYTHON, "-IB", "-c", program, str(PORT))


def verify_worker(lifeline, worker, relay, broker, peer):
    lifeline.check()
    podman("exec", "--detach", relay, RELAY_PYTHON, "-IB", "/fixture/relay.py")
    wait_relay(relay)  # Passive observation, with no socket handoff.
    lifeline.check()
    try:
        run_open_code(worker)
    except Failure:
        broker.receipt()  # Prefer a settled broker error to the worker's generic failure.
        raise
    lifeline.check()
    receipt = broker.receipt()
    if ((receipt.claims, receipt.answers, receipt.refusals) != (1, 1, 0)
            or not receipt.response_bytes or not receipt.request_body or peer.prompt_count != 1):
        raise Failure("the worker and peer did not settle exactly one text turn")
    refusal = fixture_request(relay, receipt.request_body).strip()
    if refusal != REFUSAL.split(b"\r\n", 1)[0]:
        raise Failure("the relay did not refuse the replay")
    replay = broker.receipt()
    if (replay.claims, replay.answers, replay.refusals, peer.prompt_count) != (1, 1, 1, 1):
        raise Failure("replay changed the settled synthetic turn")


def run_proof(lifeline):
    os.umask(0o077)
    preflight()
    lifeline.check()
    with synthetic_state() as state, isolated_placement(lifeline) as placement:
        worker_files, relay_files, proof = seeds(placement.root)
        # The broker is always revoked and joined before the peer context can finalize.
        with ExitStack() as peer_scope, TextBroker(
                relay_files / "provider.sock", proof, authorized=lifeline.active) as broker:
            with lifeline.revoke_on_loss(broker.revoke):
                worker, relay = create_inert_pair(placement, worker_files, relay_files)
                verify_prearm_refusal(relay)
                peer = peer_scope.enter_context(open_text_session(
                    state, enroll_fixture(state), cancelled=broker.cancelled))
                broker.arm(peer)
                verify_worker(lifeline, worker, relay, broker, peer)
    lifeline.check()


def interrupt(_number, _frame):
    raise KeyboardInterrupt


def main():
    if sys.argv[1:] == ["_owner"]:
        try:
            run_proof(accept_launch())
        except (Failure, OwnerLost, PublicationUnconfirmed, RetirementUnconfirmed) as error:
            print(f"ACP spike: {error}", file=sys.stderr)
            return 1
        except (KeyError, OSError, RecursionError, RuntimeError, TypeError, ValueError) as error:
            print(f"ACP spike: verification failed ({type(error).__name__})", file=sys.stderr)
            return 1
        return 0
    if sys.argv[1:]:
        print("Usage: python3 -IB docs/prds/spikes/i4c/acp_text_probe.py", file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    try:
        result = supervise(SOURCE)
    except KeyboardInterrupt:
        return 130
    if result == 0:
        print("OpenCode returned exact ok through the fake ACP peer. One prompt, zero tools, replay denied.")
        print("Verified retirement of the peer, worker, relay and private scratch.")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
