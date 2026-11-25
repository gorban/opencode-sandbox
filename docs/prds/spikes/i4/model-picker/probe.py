#!/usr/bin/env python3
"""Drive the stock OpenCode full and Mini pickers with a disposable offline catalog."""

import argparse
from contextlib import contextmanager
import hashlib
import http.server
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time


SHA256 = "2e0e4656521ca56e5ba16a00d48429958b8105b3fa6466710a4350e68759381f"
PORT = 8401
PROMPT = "Reply with exactly: ok"
ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "TERM": "xterm-256color",
    "OPENCODE_CONFIG_PROJECT_DISABLE": "true",
    "OPENCODE_DISABLE_MODELS_FETCH": "true",
    "OPENCODE_DISABLE_FREE_MODELS": "true",
    "OPENCODE_DISABLE_AUTOUPDATE": "true",
    "OPENCODE_DISABLE_CLAUDE_CODE": "true",
}
# Two kinds have the label "personal". Every kind has the same v2 upstream ID.
# The v1 name includes the v2 ID and another account's display label as data.
DEFAULT = ("claude--personal", "opal-v2")
SELECT = ("google--personal", "opal-v2")
CATALOG = {
    "claude--personal": {
        "opal-v2": "Opal v2 - claude/personal [subscription]",
        "zircon": "Zircon - claude/personal [subscription]",
    },
    "claude--work": {
        "opal-v2": "Opal v2 - work [metered]",
        "opal-v1": "Opal v1 (opal-v2 work) - work [metered]",
    },
    "google--personal": {
        "opal-v2": "Opal v2 - google/personal [subscription]",
    },
}
PROVIDER_NAMES = {
    "claude--personal": "claude/personal",
    "claude--work": "work",
    "google--personal": "google/personal",
}
TARGET_LABEL = CATALOG[SELECT[0]][SELECT[1]]
LABELS = [label for models in CATALOG.values() for label in models.values()]
MODEL_IDS = set().union(*CATALOG.values())
SAVED_ROUTE = "/".join(SELECT)
APPROVED_TARGET = f"/{SELECT[0]}/v1/chat/completions"
EXPECTED_REQUEST = {
    "phase": "approved", "method": "POST", "target": APPROVED_TARGET,
    "scope": SELECT[0], "model": SELECT[1], "fixed_prompt": True,
    "tools_advertised": False, "accepted": True,
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def seed(source, target):
    digest = hashlib.sha256()
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as binary, target.open("xb") as copy:
        info = os.fstat(binary.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 512 * 1024 * 1024,
                "OpenCode fixture must be a bounded regular file")
        while block := binary.read(1024 * 1024):
            copy.write(block)
            digest.update(block)
    require(digest.hexdigest() == SHA256, "OpenCode fixture SHA-256 differs from repository pin")
    target.chmod(0o500)


def config(port, *, stale=False, collision_model=None):
    active = {scope: models.copy() for scope, models in CATALOG.items() if not stale or scope != SELECT[0]}
    if collision_model:
        active["claude--work"][collision_model] = TARGET_LABEL
    deny = [{"action": "*", "resource": "*", "effect": "deny"}]
    policies = [{"action": action, "resource": "*", "effect": "deny"}
                for action in ("provider.use", "integration.connect", "mcp.use", "skill.use", "websearch.use")]
    policies.extend({"action": "provider.use", "resource": scope, "effect": "allow"} for scope in active)
    return {
        "model": "/".join(DEFAULT),
        "update": "disable",
        "share": "disabled",
        "snapshots": False,
        "defaultAgent": "fixture",
        "permissions": deny,
        "plugins": ["-opencode.tool.*"],
        "agents": {
            "fixture": {"mode": "primary", "permissions": deny},
            **{agent: {"disabled": True} for agent in
               ("build", "plan", "general", "explore", "title", "summary", "compaction")},
        },
        "policies": policies,
        "providers": {
            scope: {
                "name": PROVIDER_NAMES[scope],
                "package": "@opencode/ai/providers/openai-compatible",
                "settings": {"baseURL": f"http://127.0.0.1:{port}/{scope}/v1", "apiKey": "offline-fixture"},
                "models": {
                    model: {
                        "name": label,
                        "capabilities": {"tools": False, "input": ["text"], "output": ["text"]},
                        "limit": {"context": 65536, "output": 2048},
                    }
                    for model, label in rows.items()
                },
            }
            for scope, rows in active.items()
        },
    }


def stream(model):
    common = {"id": "chatcmpl-picker", "object": "chat.completion.chunk", "created": 1, "model": model}
    frames = [
        dict(common, choices=[{"index": 0, "delta": {"role": "assistant", "content": "ok"}, "finish_reason": None}]),
        dict(common, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}]),
    ]
    return ("".join(f"data: {json.dumps(frame)}\n\n" for frame in frames) + "data: [DONE]\n\n").encode()


class Fake(http.server.HTTPServer):
    """The test controller owns the one-shot gate. The frontend only gets a URL."""

    def __init__(self):
        super().__init__(("127.0.0.1", PORT), Handler)
        self.timeout = 1
        self.lock = threading.Lock()
        self.events = []
        self.allow = None
        self.phase = "startup"

    def mark(self, phase, allow=None):
        with self.lock:
            self.phase = phase
            self.allow = allow

    def snapshot(self):
        with self.lock:
            return self.events[:]

    def record(self, method, target, authorization, payload):
        scope = next((scope for scope in CATALOG if target == f"/{scope}/v1/chat/completions"), None)
        model = payload.get("model")
        messages = payload.get("messages")
        exact = (isinstance(messages, list) and bool(messages)
                 and messages[-1] == {"role": "user", "content": PROMPT})
        tools = bool(payload.get("tools") or payload.get("tool_choice"))
        with self.lock:
            accepted = (
                method == "POST" and self.allow is not None and self.allow == (scope, model)
                and exact and not tools and payload.get("stream") is True
                and authorization == "Bearer offline-fixture"
            )
            if accepted:
                self.allow = None
            # A second record already fails the exact-log check. Cap the diagnostic log.
            if len(self.events) < 16:
                self.events.append({
                    "phase": self.phase, "method": method[:32], "target": target[:160],
                    "scope": scope, "model": model if isinstance(model, str) and model in MODEL_IDS else None,
                    "fixed_prompt": exact, "tools_advertised": tools, "accepted": accepted,
                })
            return accepted


@contextmanager
def serving(fake):
    server = threading.Thread(target=fake.serve_forever, daemon=True)
    server.start()
    try:
        yield
    finally:
        # shutdown() waits for the synchronous handler, so bound that wait too.
        shutdown = threading.Thread(target=fake.shutdown, daemon=True)
        deadline = time.monotonic() + 3
        shutdown.start()
        server.join(timeout=max(0, deadline - time.monotonic()))
        shutdown.join(timeout=max(0, deadline - time.monotonic()))
        require(not server.is_alive() and not shutdown.is_alive(), "fake server did not stop within 3 seconds")


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, *args):
        pass

    def __getattr__(self, name):
        # BaseHTTPRequestHandler dispatches syntactically valid HTTP methods as do_METHOD.
        if name.startswith("do_"):
            return self.handle_request
        raise AttributeError(name)

    def handle_request(self):
        payload = {}
        if self.command == "POST":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if 0 < length <= 65536:
                    payload = json.loads(self.rfile.read(length))
            except (OSError, ValueError):
                pass
        if not isinstance(payload, dict):
            payload = {}
        # Use the request-line target before the base class normalizes leading slashes.
        target = self.requestline.split()[1]
        if self.server.record(self.command, target, self.headers.get("Authorization"), payload):
            body = stream(payload["model"])
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
        else:
            body = b'{"error":{"message":"Offline fixture gate closed","type":"invalid_request_error"}}'
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class Terminal:
    def __init__(self, env, command):
        self.env = env
        self.tmux = ["/usr/bin/tmux", "-f", "/dev/null", "-S", "/output/tmux.sock"]
        self.run("new-session", "-d", "-x", "145", "-y", "38", "-c", "/workspace", *command)
        try:
            self.pane_pidfd = os.pidfd_open(int(self.run("display-message", "-p", "#{pane_pid}")))
        except BaseException:
            self.run("kill-server", check=False)
            raise

    def run(self, *args, check=True):
        return subprocess.run([*self.tmux, *args], env=self.env, check=check, timeout=5,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

    def key(self, *keys):
        self.run("send-keys", *keys)

    def type(self, value):
        self.run("send-keys", "-l", value)

    def screen(self):
        return self.run("capture-pane", "-p")

    def await_screen(self, predicate, label, timeout=18):
        deadline = time.monotonic() + timeout
        while True:
            picture = self.screen()
            if predicate(picture):
                return picture
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Waiting for {label}:\n{picture}")
            time.sleep(0.08)

    def picker(self, mode):
        if mode == "full":
            self.key("C-x", "m")
        else:
            self.key("C-p")
            self.await_screen(lambda screen: "Commands" in screen, "Mini command palette")
            self.type("Switch model")
            self.await_screen(lambda screen: "Switch model" in screen, "Mini Switch model command")
            self.key("Enter")
        return self.await_screen(lambda screen: "Select model" in screen and CATALOG[DEFAULT[0]][DEFAULT[1]] in screen,
                                 f"{mode} model picker")

    def close(self):
        try:
            self.run("kill-server", check=False)
            require(select.select([self.pane_pidfd], [], [], 3)[0], "frontend pane did not exit within 3 seconds")
        finally:
            os.close(self.pane_pidfd)


def rows(picture):
    return [label for line in picture.splitlines() if "Fixture ·" not in line for label in LABELS if label in line]


def request_log_matches(events):
    return events == [EXPECTED_REQUEST]


def stale_refusal(mode, screen):
    if mode == "full":
        return "Model unavailable" in screen and f"{SAVED_ROUTE} is not available" in screen
    return any(line.strip() == f"Model unavailable: {SAVED_ROUTE}" for line in screen.splitlines())


def exact_ok(screen):
    return any(line.strip(" ┃│") == "ok" for line in screen.splitlines())


def evidence(screen):
    return [line.strip() for line in screen.splitlines()
            if any(term in line.lower() for term in ("opal", "unavailable", "error", "forbidden",
                                                     "select model", "reply with exactly", "no results"))]


def environment(root):
    values = dict(ENV)
    for key, leaf in {
        "HOME": "home", "XDG_CONFIG_HOME": "config", "XDG_DATA_HOME": "data",
        "XDG_STATE_HOME": "state", "XDG_CACHE_HOME": "cache", "XDG_RUNTIME_DIR": "runtime",
        "TMPDIR": "tmp",
    }.items():
        path = root / leaf
        path.mkdir(exist_ok=True, mode=0o700)
        values[key] = str(path)
    values["OPENCODE_CONFIG"] = "/config/opencode.json"
    return values


def frontend(profile, mode, *, resumed=False):
    return [
        "/usr/bin/bwrap", "--unshare-all", "--share-net", "--die-with-parent", "--proc", "/proc",
        "--dev", "/dev", "--tmpfs", "/tmp", "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib64", "/lib64",
        "--ro-bind", "/program/opencode", "/program/opencode", "--ro-bind", "/config", "/config",
        "--ro-bind", "/workspace", "/workspace", "--bind", str(profile), str(profile),
        "--chdir", "/workspace", "--", "/program/opencode",
        *(["mini"] if mode == "mini" else []), *(["--continue"] if resumed else []),
    ]


def collision_case(mode, fake, collision_model):
    profile = Path("/output") / f"{mode}-collision-{collision_model}"
    profile.mkdir()
    env = environment(profile)
    env["OPENCODE_CONFIG"] = f"/config/collision-{collision_model}.json"
    fake.mark(f"collision-{collision_model}")
    terminal = Terminal(env, frontend(profile, mode))
    try:
        terminal.await_screen(
            lambda screen: CATALOG[DEFAULT[0]][DEFAULT[1]] in screen or "ctrl+p" in screen.lower(),
            f"{mode} collision prompt",
        )
        browse = terminal.picker(mode)
        require(rows(browse).count(TARGET_LABEL) == 2, f"{mode} lost a duplicate title in browse:\n{browse}")
        terminal.type("google/personal")

        def ready(screen):
            if rows(screen) != [TARGET_LABEL, TARGET_LABEL]:
                return False
            return mode == "full" or any(
                TARGET_LABEL in line and line.rstrip().endswith(" work") for line in screen.splitlines()
            )

        result = terminal.await_screen(ready, f"{mode} duplicate display names for {collision_model}")
        return {
            "work_model": collision_model,
            "browse": [line.strip() for line in browse.splitlines()
                       if TARGET_LABEL in line or line.strip() in PROVIDER_NAMES.values()],
            "search": [line.strip() for line in result.splitlines() if TARGET_LABEL in line],
        }
    finally:
        terminal.close()


def case(mode):
    profile = Path("/output") / mode
    env = environment(profile)
    with Fake() as fake, serving(fake):
        terminal = Terminal(env, frontend(profile, mode))
        try:
            terminal.await_screen(
                lambda screen: CATALOG[DEFAULT[0]][DEFAULT[1]] in screen or "ctrl+p" in screen.lower(),
                f"{mode} initial prompt",
            )
            browse = terminal.picker(mode)
            require(sorted(rows(browse)) == sorted(LABELS), f"{mode} did not display every fixture row:\n{browse}")
            lineage = sorted(label for label in LABELS if label.startswith("Opal"))
            terminal.type("Opal v2")
            search = terminal.await_screen(lambda screen: sorted(rows(screen)) == lineage,
                                           f"{mode} filtered search for the Opal rows")
            for _ in range(len("Opal v2")):
                terminal.key("BSpace")
            terminal.type("google/personal")
            terminal.await_screen(lambda screen: rows(screen) == [TARGET_LABEL], f"{mode} exact target search")
            terminal.key("Enter")
            selected = terminal.await_screen(lambda screen: "Select model" not in screen and TARGET_LABEL in screen,
                                             f"{mode} selected model")
            if "Select variant" in selected:
                terminal.key("Escape")
                terminal.await_screen(lambda screen: "Select variant" not in screen, f"{mode} resumed composer")
            fake.mark("approved", SELECT)
            terminal.type(PROMPT)
            terminal.key("Enter")
            try:
                terminal.await_screen(exact_ok, f"{mode} exact assistant ok")
            except RuntimeError as error:
                raise RuntimeError(f"{error}\nFake request log: {fake.snapshot()}") from error
            time.sleep(0.4)
            terminal.key("C-c")
            time.sleep(0.3)
        finally:
            terminal.close()
        fake.mark("stale")
        env["OPENCODE_CONFIG"] = "/config/stale.json"
        terminal = Terminal(env, frontend(profile, mode, resumed=True))
        try:
            terminal.await_screen(lambda screen: PROMPT in screen and exact_ok(screen),
                                  f"{mode} resumed session")
            time.sleep(0.4)
            before = terminal.screen()
            stale_picker = terminal.picker(mode)
            remaining = sorted(label for label in LABELS if label != TARGET_LABEL)
            require(sorted(rows(stale_picker)) == remaining, f"{mode} stale picker rows differ:\n{stale_picker}")
            terminal.key("Escape")
            terminal.await_screen(lambda screen: "Select model" not in screen, f"{mode} stale composer")
            terminal.type(PROMPT)
            terminal.await_screen(lambda screen: screen.count(PROMPT) >= 2,
                                  f"{mode} typed stale prompt in composer")
            terminal.key("Enter")
            try:
                after = terminal.await_screen(lambda screen: stale_refusal(mode, screen),
                                              f"{mode} local refusal of {SAVED_ROUTE}")
            except RuntimeError as error:
                raise RuntimeError(f"{error}\nFake request log: {fake.snapshot()}") from error
            time.sleep(0.5)
        finally:
            terminal.close()
        collisions = [collision_case(mode, fake, model) for model in ("opal-v1", "opal-v2")]
    events = fake.snapshot()
    require(request_log_matches(events), f"{mode} expected only the approved Google POST: {events}")
    return {
        "mode": mode, "browse": rows(browse), "search": rows(search),
        "stale_picker": rows(stale_picker), "collisions": collisions,
        "stale_before": evidence(before),
        "stale_after": evidence(after),
        "requests": events,
    }


def isolated():
    require({name for _, name in socket.if_nameindex()} == {"lo"}, "probe requires a loopback-only namespace")
    version_root = Path("/output/version")
    version_root.mkdir()
    result = subprocess.run(["/program/opencode", "--version"], text=True,
                            env=environment(version_root), capture_output=True, timeout=10)
    require(result.returncode == 0, f"version check failed: {result.stderr}")
    version = result.stdout.strip()
    require(version in {"2.3.0", "opencode v2.3.0"}, f"unexpected OpenCode version {version!r}")
    print(json.dumps({"opencode_version": version, "sha256": SHA256, "interfaces": ["lo"]}), flush=True)
    for mode in ("full", "mini"):
        (Path("/output") / mode).mkdir()
        print(json.dumps(case(mode), indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    source = args.binary or home / ".cache/oc-sandbox/fixtures/opencode-2.3.0"
    with tempfile.TemporaryDirectory(prefix="oc-picker-") as scratch:
        root = Path(scratch)
        for leaf in ("program", "config", "output", "workspace"):
            (root / leaf).mkdir()
        for name, options in {
            "opencode": {}, "stale": {"stale": True},
            "collision-opal-v1": {"collision_model": "opal-v1"},
            "collision-opal-v2": {"collision_model": "opal-v2"},
        }.items():
            (root / f"config/{name}.json").write_text(json.dumps(config(PORT, **options)))
        seed(source, root / "program/opencode")
        shutil.copyfile(Path(__file__), root / "program/probe.py")
        command = [
            "/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib64", "/lib64",
            "--ro-bind", str(root / "program"), "/program", "--ro-bind", str(root / "config"), "/config",
            "--bind", str(root / "output"), "/output", "--bind", str(root / "workspace"), "/workspace",
            "--chdir", "/workspace", "--", "/usr/bin/python3", "-IB", "-c",
            "import runpy; runpy.run_path('/program/probe.py')['isolated']()",
        ]
        subprocess.run(command, env=ENV, check=True, timeout=180)


if __name__ == "__main__":
    main()
