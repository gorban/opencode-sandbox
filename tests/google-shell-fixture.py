#!/usr/bin/env python3
"""Exercise an isolated OpenCode shell with an explicit test peer."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("oc_google", "oc_orchestrator", "oc_providers")
SPIKE = Path("docs/prds/spikes/i4c")
PEER_FILES = ("acp_fixture.py", "acp_readiness.py", "acp_text_peer.py", "acp_text_session.py")
ENTRY = "oc-google.py"
MODEL = "gemini-2.5-pro"
LABEL = "fixture"
NATIVE_MODEL = "gemini-4-hydrogen"
NATIVE_LABEL = "elgoog"
PROMPT = "Reply with exactly: ok"
SYSTEM_DIGEST = "cd7021db39cf648e085a4dc4ff92e3879c87bd384fc2d33cc5f99c0092dbe74a"
# OpenCode's normalized system message includes the selected model and provider IDs.
NATIVE_SYSTEM_DIGEST = "5e9e60d4323abaec8d0a7d4dc4f0257da8ed1f647f7d48f4a39078e8cfd2d99c"
RUN_PATTERN = re.compile(r"Google shell run ([0-9a-f]{32})\.")
ENV = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "TERM": "xterm-256color", "LANG": "C.UTF-8"}


class FixtureError(RuntimeError):
    """A fixed diagnostic for a failed OpenCode fixture check."""


def snapshot_inputs(native=False):
    paths = [Path("oc-sandbox"), Path(ENTRY)]
    for package in PACKAGES:
        paths.extend(path.relative_to(ROOT) for path in (ROOT / package).glob("*.py"))
    paths.extend(SPIKE / name for name in PEER_FILES)
    return {str(name): (ROOT / name).read_bytes() for name in sorted(paths)}


def identity(files):
    record = b"".join(f"{name}:{hashlib.sha256(data).hexdigest()}\n".encode("ascii")
                      for name, data in sorted(files.items()))
    return hashlib.sha256(record).hexdigest()


def substitute(source, original, replacement):
    if source.count(original) != 1:
        raise RuntimeError("Google fixture source anchor changed")
    return source.replace(original, replacement)


def fixture_sources(files, scene):
    files = files.copy()
    cli = files[ENTRY].decode("utf-8")
    cli = substitute(cli, '        "route.py", "shell.py", "native_text.py", "token_diagnostic.py",\n    ),',
                     '        "route.py", "shell.py", "native_text.py", "token_diagnostic.py", "fixture_peer.py",\n    ),')
    model, label = (NATIVE_MODEL, NATIVE_LABEL) if scene == "native" else (MODEL, LABEL)
    cli = substitute(cli, "    from oc_google.native_text import target_from_config\n",
                     "    from oc_google.fixture_peer import target_from_config\n")
    files[ENTRY] = cli.encode("utf-8")
    if scene == "native":
        files["oc_google/fixture_peer.py"] = f"""
from oc_google.native_text import open_opencode_session
from oc_providers.config import load_provider_config
from pathlib import Path

def target_from_config(label):
    from types import SimpleNamespace
    from functools import partial
    config = load_provider_config(config_dir=Path(__file__).resolve().parents[2] / "config")
    instance = config.get("google", label) if config else None
    if instance is None or not instance.enabled or instance.auth_mode != "subscription":
        raise ValueError("The test subscription is not enabled.")
    model = instance.default_model
    if (label, model) != ({label!r}, {model!r}):
        raise ValueError("The test model transcript has not been measured.")
    return SimpleNamespace(label=label, model=model, system_digest={NATIVE_SYSTEM_DIGEST!r},
                           open_session=partial(open_opencode_session, model))
""".lstrip().encode()
    else:
        files["oc_google/fixture_peer.py"] = fake_peer_source(scene)
    return files


def fake_peer_source(scene):
    return f"""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import json
import sys

SOURCE = Path(__file__).resolve().parents[1]
ROOT = SOURCE.parent
sys.path.append(str(SOURCE / {str(SPIKE)!r}))
import acp_readiness
import acp_text_session
from oc_providers.config import load_provider_config


@contextmanager
def open_session(cancelled):
    root = ROOT / "peer"
    root.mkdir(mode=0o700)
    generation = acp_readiness.enroll_fixture(root)
    with acp_text_session.open_text_session(root, generation, {scene!r}, timeout=15, cancelled=cancelled) as session:
        yield session
    result = acp_readiness.read_status(root)
    (ROOT / "peer-evidence").write_text(json.dumps(
        {{"prompts": session.prompt_count, "state": result.readiness.value}}))


def target_from_config(label):
    config = load_provider_config(config_dir=ROOT / "config")
    instance = config.get("google", label) if config else None
    if instance is None or not instance.enabled or instance.auth_mode != "subscription":
        raise ValueError("The test subscription is not enabled.")
    model = instance.default_model
    if (label, model) != ({LABEL!r}, {MODEL!r}):
        raise ValueError("The test model transcript has not been measured.")
    return SimpleNamespace(label=label, model=model, system_digest={SYSTEM_DIGEST!r},
                           open_session=open_session)
""".lstrip().encode()


def write_fixture(files, tree, private, expected, label, model):
    config = private / "config"
    config.mkdir(mode=0o700)
    source = config / "providers.toml"
    source.write_text(f'[providers.google.{label}]\nenabled = true\nauth_mode = "subscription"\n'
                      f'default_model = "{model}"\n')
    source.chmod(0o600)
    tree.mkdir(mode=0o700)
    for name, data in files.items():
        path = tree / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o500 if name == "oc-sandbox" else 0o400)
    for directory in reversed(sorted((path for path in tree.rglob("*") if path.is_dir()))):
        directory.chmod(0o500)
    result = {str(path.relative_to(tree)): path.read_bytes() for path in tree.rglob("*") if path.is_file()}
    if identity(result) != expected:
        raise RuntimeError("Google fixture copy differs from the projected manifest")


class Terminal:
    def __init__(self, root):
        self.command = ("/usr/bin/tmux", "-f", "/dev/null", "-S", str(root / "t"))

    def run(self, *args, check=True):
        return subprocess.run((*self.command, *args), env=ENV, check=check, timeout=10,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

    def start(self, name, source, *args):
        isolated = (source, "google", *args)
        self.run("new-session", "-d", "-s", name, "-x", "145", "-y", "38", "/usr/bin/bash", "-c",
                 shlex.join(isolated) + '; result=$?; printf "\\nFixture exit %s\\n" "$result"; sleep 120')

    def keys(self, name, *keys):
        self.run("send-keys", "-t", name, *keys)

    def type_line(self, name, value):
        self.run("send-keys", "-t", name, "-l", value)
        self.keys(name, "Enter")

    def screen(self, name, history=False):
        args = ("-S", "-") if history else ()
        return self.run("capture-pane", "-p", "-t", name, *args)

    def await_screen(self, name, predicate, description, *, timeout=30, history=False):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            screen = self.screen(name, history)
            if predicate(screen):
                return screen
            if history and "Fixture exit" in screen:
                break
            time.sleep(.1)
        raise FixtureError(f"The OpenCode fixture did not observe {description}.")

    def close(self):
        self.run("kill-server", check=False)


def runtime_path(run_id):
    return Path("/run/user") / str(os.getuid()) / "oc-gshell" / run_id


def wait_for_cleanup(run_id):
    deadline = time.monotonic() + 45
    while runtime_path(run_id).exists() and time.monotonic() < deadline:
        time.sleep(.1)
    if runtime_path(run_id).exists():
        raise RuntimeError("The Google shell retained its run directory")


def check_prearm_listener(run_id, source):
    line = (runtime_path(run_id) / "placement.json").read_text()
    relay = json.loads(line)["ids"]["relay"]
    if not re.fullmatch(r"[0-9a-f]{64}", relay):
        raise RuntimeError("The fixture did not see its exact relay")
    command = """import errno, socket
with socket.socket() as sock:
    sock.settimeout(1)
    assert sock.connect_ex(('127.0.0.1', 8401)) == errno.ECONNREFUSED
"""
    check = ("from oc_orchestrator.runtime import podman, RELAY_PYTHON; "
             "import sys; podman('exec', sys.argv[1], RELAY_PYTHON, '-IB', '-c', sys.argv[2])")
    subprocess.run(("/usr/bin/python3", "-IBS", "-c",
                    "import sys; sys.path.append(sys.argv.pop(1)); " + check,
                    str(source), relay, command), env=ENV, check=True, timeout=12)


def exact_answer(screen, display):
    rows = [line.strip(" │┃") for line in screen.splitlines()]
    prompt = [index for index, row in enumerate(rows) if row.startswith(PROMPT)]
    answer = [index for index, row in enumerate(rows) if row == "ok"]
    if len(prompt) != 1 or len(answer) != 1 or not prompt[0] < answer[0] <= prompt[0] + 6:
        return False
    end = rows[answer[0] + 1:answer[0] + 5]
    return any(row.startswith(f"Restricted-Text · {display} · ") for row in end)


def selected_model(screen, model, label):
    return "Select model" not in screen and any(
        model in row and f"[subscription] {label}" in row for row in screen.splitlines()
    )


def drive(term, launcher, private, scene):
    model, label = (NATIVE_MODEL, NATIVE_LABEL) if scene == "native" else (MODEL, LABEL)
    display = f"{model} - {label} [subscription]"
    term.start("shell", launcher, "shell", label)
    run_id = None
    try:
        screen = term.await_screen("shell", RUN_PATTERN.search, "run identity", history=True)
        run_id = RUN_PATTERN.search(screen)[1]
        term.await_screen("shell", lambda s: "Ask anything" in s, "the OpenCode input")
        term.keys("shell", "C-x", "m")
        term.await_screen("shell", lambda s: "Select model" in s and display in s, "the Gemini picker row")
        term.keys("shell", "Enter")
        selected = term.await_screen("shell", lambda s: "Select model" not in s
                                     and ("Select variant" in s or selected_model(s, model, label)), "selected Gemini model")
        if "Select variant" in selected:
            term.keys("shell", "Escape")
            term.await_screen("shell", lambda s: "Select variant" not in s and selected_model(s, model, label),
                              "dismissed variant picker")
        check_prearm_listener(run_id, Path(launcher).parent)
        if (private / "peer").exists():
            raise RuntimeError("The ACP peer launched before arming")
        term.start("arm", launcher, "arm", run_id)
        term.await_screen("arm", lambda s: "Type arm to authorize this one turn:" in s, "the trusted arm prompt")
        term.type_line("arm", "arm")
        term.await_screen("arm", lambda s: "Fixture exit 0" in s, "successful arming", history=True)
        term.start("replay", launcher, "arm", run_id)
        term.await_screen("replay", lambda s: "oc-sandbox google: The shell arm did not complete." in s
                          and "Fixture exit 1" in s,
                          "duplicate approval refusal", history=True)
        term.type_line("shell", PROMPT)
        if scene != "bad-receipt":
            term.await_screen("shell", lambda s: exact_answer(s, display), "the exact assistant reply", timeout=50)
            term.keys("shell", "C-x", "n")
            term.await_screen("shell", lambda s: "Ask anything" in s and PROMPT not in s,
                              "fresh conversation for exact request replay")
            term.type_line("shell", PROMPT)
            term.await_screen("shell", lambda s: "Provider request failed with HTTP 403" in s,
                              "HTTP refusal of the repeated first prompt")
            if scene != "native":
                term.keys("shell", "C-c", "C-c")
                term.await_screen("shell", lambda s: "Fixture exit 0" in s, "ordinary shell exit", history=True)
        else:
            screen = term.await_screen("shell", lambda s: "Fixture exit 1" in s, "refusal of invalid ACP evidence",
                                       history=True)
            if exact_answer(screen, display):
                raise RuntimeError("The shell displayed an answer after invalid ACP evidence")
    finally:
        term.close()
        if run_id:
            wait_for_cleanup(run_id)
    if scene == "native":
        return
    peer = json.loads((private / "peer-evidence").read_text())
    expected = "ready" if scene == "ready" else "needs_verify"
    if peer != {"prompts": 1, "state": expected}:
        raise RuntimeError("The fake ACP peer did not verify the expected prompt and retirement receipt")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha256")
    parser.add_argument("--entry-sha256")
    parser.add_argument("--fixture-sha256")
    parser.add_argument("--scene", choices=("ready", "bad-receipt"), default="ready")
    args = parser.parse_args()
    files = snapshot_inputs()
    projected = fixture_sources(files, args.scene)
    actual = (identity(files), hashlib.sha256(files[ENTRY]).hexdigest(), identity(projected))
    expected = (args.source_sha256, args.entry_sha256, args.fixture_sha256)
    if not any(expected):
        print(*actual)
        return
    if actual != expected:
        raise SystemExit("Google shell fixture manifest changed")
    run_projection(projected, args.fixture_sha256, args.scene)
    print(f"Verified stock OpenCode through the private Google shell fixture ({args.scene}).")


def run_projection(projected, projection_digest, scene):
    private = Path(tempfile.mkdtemp(prefix=".gsh-", dir=Path.home()))
    tree = private / "source"
    try:
        model, label = (NATIVE_MODEL, NATIVE_LABEL) if scene == "native" else (MODEL, LABEL)
        write_fixture(projected, tree, private, projection_digest, label, model)
        print(f"Fixture source {projection_digest}", flush=True)
        drive(Terminal(private), str(tree / "oc-sandbox"), private, scene)
    finally:
        if (private / "peer/readiness-inflight.json").exists():
            print(f"Retained the unresolved fixture evidence in {private}", flush=True)
        else:
            for path in tree.rglob("*"):
                if path.is_dir():
                    path.chmod(0o700)
            shutil.rmtree(private)


if __name__ == "__main__":
    main()
