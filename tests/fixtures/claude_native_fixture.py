"""Synthetic subprocess for the isolated Claude fixture tests."""

import json
import os
from pathlib import Path
import socket
import sys
import time


def send(frame):
    sys.stdout.write(json.dumps(frame, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def check_isolation(denied):
    assert os.getcwd() == "/tmp/work"
    assert set(os.environ) <= {"HOME", "PATH", "LANG", "PWD", "LC_CTYPE"}
    assert os.environ["HOME"] == "/tmp/work"
    assert sorted(name for _index, name in socket.if_nameindex()) == ["lo"]
    for path in denied:
        try:
            Path(path).read_bytes()
        except OSError:
            continue
        raise RuntimeError("Unexpected fixture mount")
    for fd in os.listdir("/proc/self/fd"):
        if int(fd) > 2:
            try:
                os.fstat(int(fd))
            except OSError:
                continue
            raise RuntimeError("Unexpected fixture descriptor")


def main():
    mode, scenario, session, *denied = sys.argv[1:]
    assert mode in {"status", "turn"}
    assert scenario in {"normal", "leader_exit", "stall_ready", "stall_output", "oversize"}
    check_isolation(denied)
    profile = Path("/profile")
    for name in ("registration.json", "credential"):
        try:
            descriptor = os.open(profile / name, os.O_WRONLY | os.O_CLOEXEC)
        except OSError:
            pass
        else:
            os.close(descriptor)
            raise RuntimeError("Unexpected writable fixture image")
    record = json.loads((profile / "registration.json").read_text())
    assert (profile / "credential").read_text() == "synthetic-only-" + record["profile"]
    if mode == "status":
        assert not sys.stdin.read(1)
        send({"type": "status", "logged_in": True, "auth": "claude.ai", "provider": "firstParty", **record})
        return

    if scenario == "stall_ready":
        time.sleep(60)
    expiry = record.pop("expires_at")
    assert expiry > time.time()
    send({"type": "ready", "session": session, "auth": "claude.ai", "provider": "firstParty",
          "tools": [], "mcp": [], "hooks": [], **record})
    frame = json.loads(sys.stdin.readline(8192))
    assert not sys.stdin.read(1)
    assert set(frame) == {"type", "session", "challenge", "role", "text"}
    assert frame["type"] == frame["role"] == "user" and frame["session"] == session

    if scenario == "leader_exit":
        pipe_read, pipe_write = os.pipe()
        if os.fork():
            os.close(pipe_write)
            assert os.read(pipe_read, 1) == b"R"
            os._exit(0)
        os.close(pipe_read)
        os.setsid()
        os.write(pipe_write, b"R")
        os.close(pipe_write)
        time.sleep(60)
        return
    if scenario == "stall_output":
        time.sleep(60)
        return
    if scenario == "oversize":
        sys.stderr.write("x" * 9000)
        sys.stderr.flush()

    route = {"session": session, "challenge": frame["challenge"], "model": record["model"]}
    send({"type": "delta", **route, "role": "assistant", "text": "fixture:" + frame["text"]})
    send({"type": "result", **route, "stop": "end_turn", "tool_calls": 0})


if __name__ == "__main__":
    main()
