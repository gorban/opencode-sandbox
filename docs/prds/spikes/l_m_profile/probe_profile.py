"""Run two narrow compiled-profile variants against disposable local OpenCode."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import signal
import sys
import tempfile


SPIKES = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SPIKES / "l"))
sys.path.insert(0, str(SPIKES / "m" / "local"))

from broker import Broker
from probe import close_resources, image_id, interrupt, prove, report
from profile_checks import verify_services
from profile_plan import (
    CDP_SERVICE, PG_SERVICE, RELAY_REF, SERVICE_IMAGES, WORKER_REF, ProfileError, compile_fixture, verify_image,
)
from profile_services import Sidecars, recipe
from runtime import Job, JobRuntimeError, inspected


def _images(args, services: tuple[str, ...]) -> dict[str, str]:
    images = {PG_SERVICE: args.postgres_image}
    if CDP_SERVICE in services:
        if args.chromium_image is None:
            raise ProfileError("The Chromium variant requires a pinned local Chromium image ID")
        images[CDP_SERVICE] = args.chromium_image
    verify_image(args.opencode_image, WORKER_REF, inspected)
    verify_image(args.relay_image, RELAY_REF, inspected)
    for service, image in images.items():
        verify_image(image, SERVICE_IMAGES[service], inspected)
    return images


def _cleanup(job: Job, broker: Broker | None, sidecars: Sidecars | None, error: str | None) -> str | None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if broker is not None:
        try:
            broker.close()
        except Exception as exc:
            error = error or "Broker cleanup failed."
            print(f"Broker cleanup failed ({type(exc).__name__}).", file=sys.stderr)
    if sidecars is not None:
        try:
            sidecars.close()
        except Exception:
            error = error or "Sidecar cleanup unconfirmed."
            print("Sidecar cleanup unconfirmed. Inspect the private run receipt.", file=sys.stderr)
    return close_resources(job, None, error)


def run(args) -> int:
    selection = compile_fixture(without_chromium=args.without_chromium)
    report(f"Plan {selection.digest}. Services {', '.join(selection.services)}.")
    if args.plan_only:
        return 0
    images = _images(args, selection.services)
    root = Path(tempfile.mkdtemp(prefix="ocm-", dir="/tmp"))
    job = Job(root, args.opencode_image, args.relay_image, secrets.token_hex(24),
              secrets.token_hex(24), "inc_" + secrets.token_hex(16))
    sidecars = None
    broker = None
    error = None
    interrupted = False
    try:
        job.prepare()
        broker = Broker(job.provider_socket, job.token)
        broker.start()
        job.start()
        sidecars = Sidecars(job)
        for service in selection.services:
            sidecars.start(recipe(service, images[service], job.root))
        verify_services(job, sidecars, selection)
        report("Verified worker-local services and zero port publication.")
        prove(job, broker, False)
    except KeyboardInterrupt:
        interrupted = True
        error = "Profile proof interrupted."
    except (ProfileError, JobRuntimeError) as exc:
        error = str(exc)
    except Exception as exc:
        error = f"Profile proof failed ({type(exc).__name__})."
    finally:
        error = _cleanup(job, broker, sidecars, error)
    if error is not None:
        print(f"{error} Private run directory retained at {root}.", file=sys.stderr)
        return 130 if interrupted else 1
    try:
        shutil.rmtree(root)
    except OSError:
        print(f"Run directory cleanup failed at {root}.", file=sys.stderr)
        return 1
    report("Verified removal of all owned containers and the private run directory.")
    return 0


def _local_image_id(value: str) -> str:
    return image_id(value).removeprefix("sha256:")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--without-chromium", action="store_true")
    for role in ("opencode", "relay", "postgres", "chromium"):
        parser.add_argument(f"--{role}-image", type=_local_image_id)
    args = parser.parse_args(argv)
    if not args.plan_only and not (args.opencode_image and args.relay_image and args.postgres_image):
        parser.error("Full local OpenCode, relay, and Postgres image IDs are required for a live proof")
    signal.signal(signal.SIGTERM, interrupt)
    try:
        return run(args)
    except Exception as exc:
        message = str(exc) if isinstance(exc, (ProfileError, JobRuntimeError)) else type(exc).__name__
        print(f"Profile preflight or cleanup failed: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.umask(0o077)
    sys.exit(main())
