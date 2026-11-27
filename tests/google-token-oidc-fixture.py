#!/usr/bin/env python3
"""Verify production token projection in a disposable launcher with no upstream transport."""

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


CALLBACK_PINS = {
    "oc_google/auth_offer.py": "16b0854d94da72e571a0b4db8a73d1d3877599b895e6714947f41fc253671b12",
    "tests/google-connect-fixture.py": "423f99ddbbc83abe67081cfb272d9a48854281868a516ee9f3ad97e37cefd23f",
}
MATRIX = ((False, False), (False, True), (True, False), (True, True))
FIXTURE_ID_TOKEN = "fixtureOpaque.fakeValue.sandboxDummy"
INITIAL_BEARER = "synthetic-initial-opaque-bearer"
COLD_BEARER = "synthetic-cold-opaque-bearer"


def load_source(source):
    for name, pin in CALLBACK_PINS.items():
        if sha256((source / name).read_bytes()).hexdigest() != pin:
            raise ValueError("The reviewed synthetic callback source differs from its pin")
    sys.path[:0] = [str(source / "tests"), str(source)]
    spec = importlib.util.spec_from_file_location("sealed_connect_fixture", source / "tests/google-connect-fixture.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    return fixture


def replace(source, original, patched):
    data = source.read_text(encoding="utf-8")
    if data.count(original) != 1:
        raise ValueError("A copied-source measurement anchor changed")
    source.write_text(data.replace(original, patched), encoding="utf-8")


def configure_trial(fixture, directory, root, *, initial_five, cold_five):
    token = json.loads(fixture.grant())
    legacy = token["scope"]
    initial = dict(token, access_token=INITIAL_BEARER)
    cold = dict(token, access_token=COLD_BEARER)
    del cold["refresh_token"]
    for reply, full in ((initial, initial_five), (cold, cold_five)):
        if full:
            reply.update(scope=fixture.BROWSER_SCOPE, id_token=FIXTURE_ID_TOKEN)
    destination = directory / "oc_google/metadata_destination.py"
    contents = destination.read_text(encoding="utf-8")
    prefix, separator, _ = contents.partition("\ndef _request(")
    if not separator or contents.count("\ndef _request(") != 1:
        raise ValueError("The copied destination structure changed")
    destination.write_text(prefix + f"""
import hmac
import json
from urllib.parse import parse_qs

_steps = {fixture.STEPS!r}
_token = ({initial!r}, {cold!r})
_legacy = {legacy!r}
_five = {fixture.BROWSER_SCOPE!r}
_identity = {FIXTURE_ID_TOKEN!r}
_replies = (None, {fixture.SUBJECT!r}, {fixture.LOAD_REPLY!r},
            None, {fixture.SUBJECT!r}, {fixture.LOAD_REPLY!r}, {fixture.catalog()!r})
_routes = {str(root / 'synthetic-routes')!r}
_observations = {str(root / 'token-observations.jsonl')!r}
_observed = []


def _measure(result):
    with open(_observations, "a", encoding="ascii") as out:
        out.write(json.dumps(result, sort_keys=True) + "\\n")


def _sanitized(cold):
    # The fake raw grant includes the opaque sentinel only for the five-label fixture.
    data = dict(_token[int(cold)])
    identity = data.pop("id_token", None)
    if data["scope"] not in (_legacy, _five) or ((identity == _identity) != (data["scope"] == _five)):
        raise MetadataDestinationError("Synthetic grant did not match the trial")
    return json.dumps(data, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def check_native_token(body, *, cold):
    if (b"id_token" in body or _identity.encode("ascii") in body
            or not hmac.compare_digest(body, _sanitized(cold))):
        raise MetadataDestinationError("Synthetic native reply was not sanitized")
    return {{"phase": "cold" if cold else "initial", "native_token_published": True,
             "identity_token_absent": True, "reported_labels": len(json.loads(body)["scope"].split(" "))}}


def record_native_token(receipt):
    _measure(receipt)


_credential_keys = {{"client_id", "client_secret", "refresh_token", "token_uri", "scopes", "project_id"}}


def _equal_scopes(value, reference):
    return (type(value) is list and type(reference) is list and len(value) == len(reference)
            and all(type(scope) is str for scope in value + reference) and set(value) == set(reference))


def observe_cold_replica(credential):
    profile = json.loads(credential)
    scopes = profile.get("scopes") if type(profile) is dict else None
    _measure({{"phase": "cold-replica-retired", "credential_schema_exact": (
        type(profile) is dict and set(profile) == _credential_keys),
        "credential_scope_authorized_three": _equal_scopes(scopes, _legacy.split(" ")),
        "persisted_label_count": len(scopes) if type(scopes) is list else None}})


def observe_cold_refresh(credential, form):
    profile = json.loads(credential)
    scopes = profile.get("scopes") if type(profile) is dict else None
    fields = parse_qs(form.decode("ascii"), strict_parsing=True)
    native = fields.get("scope", [""])[0].split(" ")
    expected = _legacy.split(" ")

    _measure({{"phase": "cold-request",
              "credential_schema_exact": type(profile) is dict and set(profile) == _credential_keys,
              "credential_scope_authorized_three": _equal_scopes(scopes, expected),
              "native_refresh_scope_authorized_three": _equal_scopes(native, expected),
              "native_refresh_scope_equals_persisted": _equal_scopes(native, scopes),
              "native_refresh_order_equals_persisted": native == scopes,
              "persisted_label_count": len(scopes) if type(scopes) is list else None,
              "cold_request_label_count": len(native),
              "native_refresh_form_schema_exact": set(fields) == {{
                  "client_id", "client_secret", "grant_type", "refresh_token", "scope",
              }}}})


def exchange(route, *, authorization, body=b"", deadline, deliver):
    idx = len(_observed)
    if idx >= len(_steps) or route.name != _steps[idx]:
        raise MetadataDestinationError("Synthetic operation order differs")
    _remaining(deadline)
    if idx in (1, 2, 4, 5, 6):
        expected = b"Bearer " + _token[int(idx >= 4)]["access_token"].encode("ascii")
        if type(authorization) is not bytes or not hmac.compare_digest(authorization, expected):
            raise MetadataDestinationError("Synthetic route did not use its independently expected bearer")
    if idx == 3 and (authorization is not None or set(
            parse_qs(body.decode("ascii"), strict_parsing=True)["scope"][0].split(" ")) != set(_legacy.split(" "))):
        raise MetadataDestinationError("Synthetic destination cold request used unexpected authorized scopes")

    def report():
        if len(_observed) != idx:
            raise MetadataDestinationError("Synthetic spend was repeated")
        _observed.append(route.name)
        with open(_routes, "a", encoding="ascii") as sink:
            sink.write(route.name + "\\n")

    deliver(report)
    if len(_observed) != idx + 1:
        raise MetadataDestinationError("Synthetic spend did not record its operation")
    if idx in (0, 3):
        return json.dumps(_token[int(idx == 3)], ensure_ascii=True, indent=2).encode("ascii")
    if idx in (1, 4):
        _measure({{"phase": "cold" if idx == 4 else "initial", "userinfo_expected_bearer": True}})
    return _replies[idx]
""", encoding="utf-8")
    session = directory / "oc_google/enrollment_session.py"
    replace(session, "from .metadata_destination import MetadataRoute, _remaining",
            "from .metadata_destination import MetadataRoute, _remaining, check_native_token, record_native_token")
    replace(session, "                publish(channel.stream, reply.body)",
            "                token_receipt = (check_native_token(reply.body, cold=cold)\n"
            "                                 if route is MetadataRoute.TOKEN else None)\n"
            "                publish(channel.stream, reply.body)\n"
            "                if token_receipt is not None:\n"
            "                    record_native_token(token_receipt)")
    registration = directory / "oc_google/registration.py"
    replace(registration, "from .metadata_destination import MetadataRoute",
            "from .metadata_destination import MetadataRoute, observe_cold_refresh, observe_cold_replica")
    replace(registration, "                result = validate_refresh_form(form, pinned_credential=body)",
            "                observe_cold_refresh(body, form)\n"
            "                result = validate_refresh_form(form, pinned_credential=body)")
    replace(registration, "        self._remove_files()\n\n    def _remove_files(self):", """
        try:
            native = os.open("antigravity-acp", _DIRECTORY, dir_fd=self._profile_fd)
            try:
                fd = os.open("acp_token.json", os.O_RDONLY | _FILE, dir_fd=native)
                try:
                    observe_cold_replica(os.pread(fd, _CREDENTIAL_LIMIT + 1, 0))
                finally:
                    os.close(fd)
            finally:
                os.close(native)
        finally:
            self._remove_files()

    def _remove_files(self):""".lstrip("\n"))


def seal(directory):
    manifest = {}
    for item in directory.rglob("*"):
        info = item.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError("Unexpected entry in copied launcher")
        if stat.S_ISREG(info.st_mode):
            manifest[item] = sha256(item.read_bytes()).digest()
            item.chmod(0o500 if item.name == "oc-sandbox" else 0o400)
    for item in sorted((p for p in directory.rglob("*") if p.is_dir()), reverse=True):
        item.chmod(0o500)
    directory.chmod(0o500)
    if any(sha256(path.read_bytes()).digest() != pin for path, pin in manifest.items()):
        raise ValueError("Copied launcher changed while sealing")
    return sha256(b"".join(
        str(path.relative_to(directory)).encode("ascii") + b"\0" + value
        for path, value in sorted(manifest.items())
    )).hexdigest()


def read_observations(root):
    path = root / "token-observations.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def exact_retirements(state):
    count = 0
    for phase in ("enrollment", "cold"):
        files = [state / f"{phase}-native-{kind}.json" for kind in ("launch", "attested", "retired")]
        if not all(path.is_file() for path in files):
            continue
        launched, attested, retired = (json.loads(path.read_text(encoding="ascii")) for path in files)
        scratch = Path(launched["root"])
        if (launched["unit"] != attested["unit"] or attested != retired or scratch.exists()
                or scratch.with_name("." + scratch.name + "-retire").exists()):
            raise ValueError("The exact synthetic runtime did not retire")
        count += 1
    return count


def report_trial(fixture, vendor, *, initial_five, cold_five):
    root = Path(tempfile.mkdtemp(prefix="oc-g-oidc-fixture-", dir=f"/run/user/{os.getuid()}"))
    directory = root / "source"
    success = False
    expected = [5 if full else 3 for full in (initial_five, cold_five)]
    try:
        home, launcher, log = fixture.copy_fixture(root, vendor)
        configure_trial(fixture, directory, root, initial_five=initial_five, cold_five=cold_five)
        manifest = seal(directory)
        fixture.launch(home, launcher)
        state = home / ".local/state/oc-sandbox/google/registrations/fixture"
        operations = tuple(log.read_text(encoding="ascii").splitlines())
        observations = read_observations(root)
        if operations != fixture.STEPS or exact_retirements(state) != 2:
            raise AssertionError("Synthetic launcher operation or retirement sequence differs")
        receipt = json.loads((state / "registration.json").read_text(encoding="ascii"))
        if receipt["phase"] != "cold-retirement-observed":
            raise AssertionError("No settled synthetic cold observation")
        phases = ("initial", "cold")
        for phase, labels in zip(phases, expected):
            if ({"phase": phase, "userinfo_expected_bearer": True} not in observations
                    or {"phase": phase, "native_token_published": True,
                        "identity_token_absent": True, "reported_labels": labels} not in observations):
                raise AssertionError("Synthetic native delivery evidence differs")
        refresh, = (entry for entry in observations if entry["phase"] == "cold-request")
        for key in ("credential_schema_exact", "credential_scope_authorized_three",
                    "native_refresh_scope_authorized_three", "native_refresh_scope_equals_persisted",
                    "native_refresh_form_schema_exact"):
            if refresh[key] is not True:
                raise AssertionError("Native did not retain the authorized three-label scope")
        replica, = (entry for entry in observations if entry["phase"] == "cold-replica-retired")
        if replica["credential_schema_exact"] is not True or replica["credential_scope_authorized_three"] is not True:
            raise AssertionError("The retired native replica did not retain the authorized three-label scope")
        print(json.dumps({"trial_labels": expected, "operations": operations, "exact_retirements": 2,
                          "source_sha256": manifest, "observations": observations}, sort_keys=True), flush=True)
        success = True
    finally:
        if success:
            for path in directory.rglob("*"):
                if path.is_dir():
                    path.chmod(0o700)
            directory.chmod(0o700)
            shutil.rmtree(root)
        else:
            print(json.dumps({"trial_labels": expected, "observations": read_observations(root),
                              "retained_synthetic_fixture": str(root)}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--vendor", required=True, type=Path)
    args = parser.parse_args()
    fixture = load_source(args.source.resolve(strict=True))
    for initial, cold in MATRIX:
        report_trial(fixture, args.vendor.resolve(strict=True), initial_five=initial, cold_five=cold)


if __name__ == "__main__":
    main()
