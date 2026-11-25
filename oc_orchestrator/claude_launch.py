"""Run the stock local Claude Agent integration inside the synthetic OpenCode namespace."""

from contextlib import suppress
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time


sys.path.insert(0, str(Path(__file__).parent))
from claude_fixture import verify_frontend_boundary
from claude_protocol import PROMPT, STOCK_MODEL

CODE = "/opt/proof/opencode"


def endpoint(server, path):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline and server.poll() is None:
        match = re.search(r"(?am)^server listening on (http://127\.0\.0\.1:[1-9]\d{0,4})$", path.read_text())
        if match:
            return match[1]
        time.sleep(.05)
    raise RuntimeError("fixture server did not listen")


def request(address, *args):
    return subprocess.run([CODE, *args, "--server", address], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, check=True, timeout=8)


def run(stage):
    if stage not in ("discovery", "turn"):
        raise RuntimeError("unknown fixture stage")
    verify_frontend_boundary()
    password = secrets.token_hex(24)
    os.environ.update(OPENCODE_PASSWORD=password, OPENCODE_SERVER_PASSWORD=password)
    log = Path("/state/server.log")
    with log.open("w") as output, subprocess.Popen([CODE, "serve", "--hostname", "127.0.0.1", "--port", "0"],
                                                   stdout=output, stderr=subprocess.STDOUT) as server:
        try:
            address = endpoint(server, log)
            # This registers the offline SDK fixture inside the disposable frontend.
            request(address, "auth", "login", "claude-agent")
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if STOCK_MODEL.encode() in request(address, "models").stdout.splitlines():
                    break
                time.sleep(.15)
            else:
                raise RuntimeError("fixture model unavailable")
            if stage == "discovery":
                result = STOCK_MODEL.encode() + b"\n"
            else:
                result = request(address, "run", "--agent", "fixture", "--model", STOCK_MODEL,
                                 "--title", "Claude local proof", "--format", "json", PROMPT).stdout
        finally:
            with suppress(ProcessLookupError):
                server.kill()
            server.wait(timeout=2)
    sys.stdout.buffer.write(result)


if __name__ == "__main__":
    run(sys.argv[1])
