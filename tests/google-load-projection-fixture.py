#!/usr/bin/env python3
"""Compare original and projected LOAD replies through the pinned fake Connect path."""

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import runpy
import shutil
import sys
import tempfile


SOURCE = Path(__file__).resolve().parent.parent
PINS = {
    "tests/google-token-oidc-fixture.py": "31089eb66ff228a8bfc2021ffbe35c38667edb7ebe220d52675ccbff17a5971d",
    "oc_google/native_proxy.py": "8d9b849cfb0cf5631e3d689f4706c8471ee88253b770bf72bd106824b789ec36",
}
_SOURCE_BASE = "a17c88de749de1f0019e791b15f4c48d08c6eeb1"


def configure_trial(tools, fixture, directory, root, *, project, sent_shape, original):
    scopes = tools["response_scopes"](fixture)["outbound"]
    tools["configure_trial"](fixture, directory, root, scopes=(scopes, scopes))
    replace = tools["replace"]
    destination = directory / "oc_google/metadata_destination.py"
    replace(destination, "    return _replies[idx]", f"""
    if idx == 6 and (route.value[0] != "daily-cloudcode-pa.googleapis.com"
                     or json.loads(body) != {{"project": {project!r}}}):
        raise MetadataDestinationError("Synthetic LOAD changed the consumer endpoint or catalog project")
    return _replies[idx]""".lstrip("\n"))

    if original:
        enrollment = directory / "oc_google/enrollment.py"
        replace(enrollment, "\n            return project_load_reply(reply)", """
            verified = project_load_reply(reply)
            return VerifiedLoadReply(reply, verified.observation)""")

    session = directory / "oc_google/enrollment_session.py"
    load_log = root / "load-delivery.jsonl"
    wire = (f"json.loads(reply.body) != {sent_shape!r}" if not original
            else f"reply.body != {fixture.LOAD_REPLY!r}")
    replace(session, "from dataclasses import dataclass", "from dataclasses import dataclass\nimport json")
    replace(session, "                publish(channel.stream, reply.body)", f"""
                if route is MetadataRoute.LOAD_CODE_ASSIST and ({wire}):
                    raise EnrollmentSessionError("Synthetic native LOAD body differs from this trial")
                publish(channel.stream, reply.body)
                if route is MetadataRoute.LOAD_CODE_ASSIST:
                    with open({str(load_log)!r}, "a", encoding="ascii") as sink:
                        sink.write(json.dumps({{"phase": "cold" if cold else "initial", "body_exact": True}}) + "\\n")
""".strip("\n"))

    # Observe and refuse even a connection attempted after the expected native exchanges.
    proxy = directory / "oc_google/native_proxy.py"
    replace(proxy, "            relay_connection(listener, _CONNECTOR, deadline)\n    except NativeProxyError:",
            "            relay_connection(listener, _CONNECTOR, deadline)\n"
            "        if select.select((listener,), (), (), _time_left(deadline))[0]:\n"
            "            failed.set()\n"
            "    except NativeProxyError:")
    replace(proxy, "            return 1 if failed.is_set() else process.returncode",
            "            return 1 if failed.is_set() or select.select((listener,), (), (), 0)[0] else process.returncode")
    return load_log


def verify_observations(tools, root, load_log):
    observations = tools["read_observations"](root)
    for phase in ("initial", "cold"):
        expected = {"phase": phase, "userinfo_expected_bearer": True}
        if expected not in observations:
            raise AssertionError("Synthetic subject was not bound on the expected bearer")
    refresh, = (entry for entry in observations if entry["phase"] == "cold-request")
    replica, = (entry for entry in observations if entry["phase"] == "cold-replica-retired")
    if any(receipt["credential_scope_authorized_three"] is not True for receipt in (refresh, replica)):
        raise AssertionError("Native credential scopes differed between phases")
    if (refresh["native_refresh_scope_authorized_three"] is not True
            or refresh["native_refresh_scope_equals_persisted"] is not True):
        raise AssertionError("Fresh native refresh changed the authorized scopes")
    lines = [json.loads(line) for line in load_log.read_text(encoding="ascii").splitlines()]
    if lines != [{"phase": phase, "body_exact": True} for phase in ("initial", "cold")]:
        raise AssertionError("The native LOAD delivery evidence differs")


def run_trial(tools, fixture, vendor, *, kind, project, expected, original):
    root = Path(tempfile.mkdtemp(prefix="oc-g-load-fixture-", dir=f"/run/user/{os.getuid()}"))
    source = root / "source"
    success = False
    try:
        home, launcher, routes = fixture.copy_fixture(root, vendor)
        log = configure_trial(tools, fixture, source, root, project=project,
                              sent_shape=expected, original=original)
        pin = tools["seal"](source)
        fixture.launch(home, launcher)
        state = home / ".local/state/oc-sandbox/google/registrations/fixture"
        receipt = json.loads((state / "registration.json").read_text(encoding="ascii"))
        operations = tuple(routes.read_text(encoding="ascii").splitlines())
        if (receipt["phase"] != "cold-retirement-observed" or operations != fixture.STEPS
                or tools["exact_retirements"](state) != 2):
            raise AssertionError("Synthetic LOAD changed the phase, exact operation sequence or retirement")
        verify_observations(tools, root, log)
        print(json.dumps({"base": _SOURCE_BASE, "variant": kind, "wire": "original" if original else "projection",
                          "fixture_source_sha256": pin, "operations": operations, "consumer_catalog": True,
                          "catalog_project_exact": True, "both_subjects_verified": True, "scopes_preserved": True,
                          "native_loads_exact": 2, "exact_retirements": 2, "extra_native_connections_refused": True},
                         sort_keys=True), flush=True)
        success = True
        return pin
    finally:
        if success:
            for path in source.rglob("*"):
                if path.is_dir():
                    path.chmod(0o700)
            source.chmod(0o700)
            shutil.rmtree(root)
        else:
            print(json.dumps({"variant": kind, "wire": "original" if original else "projection",
                              "retained_synthetic_fixture": str(root)}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", type=Path, required=True, help="Directory with the exact pinned standalone pair")
    parser.add_argument("--variant", choices=("rich", "default"), action="append")
    arguments = parser.parse_args()
    vendor = arguments.vendor.resolve(strict=True)
    for name, digest in PINS.items():
        if sha256((SOURCE / name).read_bytes()).hexdigest() != digest:
            raise ValueError("An exact reviewed fake fixture dependency differs from its pin")
    sys.path[:0] = [str(SOURCE / "tests"), str(SOURCE)]
    from test_google_load_projection import PROJECT, PROJECTED, encode, rich_load

    tools = runpy.run_path(str(SOURCE / "tests/google-token-oidc-fixture.py"))
    fixture = tools["load_source"](SOURCE)
    for kind in arguments.variant or ("rich", "default"):
        fields = rich_load()
        expected = PROJECTED
        if kind == "default":
            fields["paidTier"] = None
            fields["currentTier"].pop("usesGcpTos")
            current = PROJECTED["currentTier"]
            expected = {"currentTier": {key: current[key] for key in ("id", "name")},
                        "cloudaicompanionProject": PROJECT}
        fixture.LOAD_REPLY = encode(fields)
        for original in (True, False):
            run_trial(tools, fixture, vendor, kind=kind, project=PROJECT, expected=expected, original=original)


if __name__ == "__main__":
    main()
