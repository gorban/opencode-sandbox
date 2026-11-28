"""Inert stand-in for the offline named Claude text wire protocol."""

import json
import re
import sys


_ID = re.compile(r"[0-9a-f]{32}")


def _emit(output, value):
    output.write(json.dumps(value, ensure_ascii=False).encode("utf-8") + b"\n")
    output.flush()


def _unique_fields(entries):
    fields = dict(entries)
    if len(fields) != len(entries):
        raise ValueError("Duplicate fixture packet field")
    return fields


def _exchange(stdin, output, *, session, model, profile, account):
    _emit(output, {
        "type": "ready", "session": session, "model": model, "profile": profile, "account": account,
        "auth": "claude.ai", "provider": "firstParty", "tools": [], "mcp": [], "hooks": [],
    })
    packet = stdin.readline(4097)
    if not packet.endswith(b"\n") or len(packet) > 4096 or stdin.read(1):
        return 1
    try:
        frame = json.loads(packet.decode("utf-8"), object_pairs_hook=_unique_fields)
        if type(frame) is not dict or frame.keys() != {"type", "session", "challenge", "role", "text"}:
            return 1
        challenge, text = frame["challenge"], frame["text"]
        if (frame["type"] != "user" or frame["role"] != "user" or frame["session"] != session
                or type(challenge) is not str or not _ID.fullmatch(challenge)
                or type(text) is not str or not text.strip() or "\0" in text or len(text.encode("utf-8")) > 512):
            return 1
    except (ValueError, RecursionError):
        return 1
    route = {"session": session, "challenge": challenge, "model": model}
    reply = f"fixture: {text}"
    _emit(output, {"type": "delta", **route, "role": "assistant", "text": reply})
    _emit(output, {
        "type": "result", **route, "stop": "end_turn", "tool_calls": 0,
        "input_tokens": len(text.encode("utf-8")), "output_tokens": len(reply.encode("utf-8")),
    })
    return 0


def main():
    if len(sys.argv) != 5:
        return 1
    session, model, profile, account = sys.argv[1:]
    return _exchange(sys.stdin.buffer, sys.stdout.buffer, session=session, model=model, profile=profile, account=account)


if __name__ == "__main__":
    sys.exit(main())
