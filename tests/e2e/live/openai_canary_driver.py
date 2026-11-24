"""Run the zero-tool OpenCode + OpenAI live canary in the verified workstation interpreter."""

import json
from pathlib import Path
import re
import signal
import sys


_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)


def _parse_model(argv: list[str]) -> str | None:
    if not argv:
        return None
    if len(argv) == 2 and argv[0] == "--model" and _MODEL_RE.fullmatch(argv[1]):
        return argv[1]
    raise ValueError("unsupported driver arguments")


def main() -> int:
    if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        return 2
    try:
        model = _parse_model(sys.argv[1:])
    except ValueError:
        return 2
    root = Path(__file__).resolve().parents[3]
    bootstrap = root / "oc-openai.py"
    try:
        namespace = {"__file__": str(bootstrap), "__name__": "openai_bootstrap"}
        exec(compile(bootstrap.read_bytes(), str(bootstrap), "exec"), namespace)
        namespace["load_cli"]()
        from oc_openai.canary import run_live_canary_e2e
    except (ImportError, KeyError, OSError, SyntaxError, ValueError):
        print("OpenAI canary e2e: trusted workstation source unavailable.", file=sys.stderr)
        return 1

    def interrupt_once(_signum, _frame):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, interrupt_once)
    try:
        result = run_live_canary_e2e(requested_model=model)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    summary = {
        "ok": result.ok,
        "label": result.label,
        "model": result.model,
        "upstream_calls": result.upstream_calls,
        "ledger_outcome": result.ledger_outcome,
        "delivered_bytes": result.delivered_bytes,
        "media_fallback": result.media_fallback,
        "input_tokens": result.input_tokens,
        "output_tokens": result.output_tokens,
        "opencode_rc": result.opencode_rc,
        "stdout_verified": result.stdout_verified,
        "cleanup_verified": result.cleanup_verified,
        "details": result.details,
    }
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
