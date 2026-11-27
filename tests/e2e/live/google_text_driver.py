"""Approved live checks of the production native ACP session."""

from pathlib import Path
import runpy
import sys

def run_text(model):
    from oc_google.native_text import _one_turn, open_native

    with open_native(model, "oc-sandbox") as (client, selected):
        print(f"Gemini model {selected} via the workstation Antigravity subscription.")
        _one_turn(client)
    print("ok")
    return 0


def run_opencode(fixture):
    from oc_google.native_text import NativeCliTextError
    from oc_orchestrator.runtime import preflight

    preflight()
    files = fixture["snapshot_inputs"](native=True)
    projection = fixture["fixture_sources"](files, "native")
    digest = fixture["identity"](projection)
    try:
        fixture["run_projection"](projection, digest, "native")
    except fixture["FixtureError"] as error:
        raise NativeCliTextError(str(error)) from None
    print(f"OpenCode rendered the exact reply from {fixture['NATIVE_MODEL']} "
          f"- {fixture['NATIVE_LABEL']} [subscription]: ok")
    return 0


def main():
    root = Path(__file__).resolve().parents[3]
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ("native", "opencode"):
            return 2
        route = sys.argv[1]
        if sys.stdin.isatty() or sys.stdin.buffer.read(33) != f"pytest approved {route}\n".encode("ascii"):
            return 2
        runpy.run_path(str(root / "oc-google.py"))["verify_sources"]()
        from oc_google.native_text import NativeCliTextError

        fixture = runpy.run_path(str(root / "tests/google-shell-fixture.py"))
        try:
            return run_opencode(fixture) if route == "opencode" else run_text(fixture["NATIVE_MODEL"])
        except NativeCliTextError as error:
            print(f"Gemini ACP test: {error}", file=sys.stderr)
    except KeyboardInterrupt:
        return 130
    except (EOFError, OSError, ValueError, RuntimeError):
        print("Gemini ACP test: The workstation proof did not complete.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
