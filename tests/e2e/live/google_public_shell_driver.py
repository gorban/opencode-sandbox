"""Attended live check of the public Google shell and named model picker."""

from pathlib import Path
import re
import runpy
import sys
import tempfile


def failure_summary(screen):
    category = "provider-refusal" if "Provider request failed" in screen else "incomplete-shell"
    exits = re.findall(r"^Fixture exit ([0-9]{1,3})$", screen, flags=re.MULTILINE)
    exit_code = int(exits[-1]) if exits and int(exits[-1]) <= 255 else None
    return f"Public Google shell failed: {category}; exit={exit_code}"


def main():
    if sys.stdin.isatty() or sys.stdin.buffer.read(32) != b"pytest approved public shell\n":
        return 2
    source = Path(__file__).resolve().parents[3]
    fixture = runpy.run_path(str(source / "tests/google-shell-fixture.py"))
    display = "gemini-4-hydrogen - elgoog [subscription]"
    run_id = None
    with tempfile.TemporaryDirectory(prefix=".oc-public-", dir=Path.home()) as root:
        term = fixture["Terminal"](Path(root))
        try:
            term.start("shell", str(source / "oc-sandbox"), "shell", "elgoog")
            screen = term.await_screen("shell", fixture["RUN_PATTERN"].search,
                                       "public shell run identity", history=True, timeout=50)
            run_id = fixture["RUN_PATTERN"].search(screen)[1]
            term.await_screen("shell", lambda s: "Ask anything" in s, "the OpenCode input", timeout=35)
            term.keys("shell", "C-x", "m")
            term.await_screen("shell", lambda s: "Select model" in s and display in s,
                              "the named Gemini picker row")
            term.keys("shell", "Enter")
            selected = term.await_screen(
                "shell", lambda s: "Select model" not in s and
                ("Select variant" in s or fixture["selected_model"](s, "gemini-4-hydrogen", "elgoog")),
                "the selected Gemini model",
            )
            if "Select variant" in selected:
                term.keys("shell", "Escape")
                term.await_screen("shell", lambda s: fixture["selected_model"](
                    s, "gemini-4-hydrogen", "elgoog"), "the dismissed variant picker")
            print("Public OpenCode picker showed the named Gemini subscription.", flush=True)
            term.start("arm", str(source / "oc-sandbox"), "arm", run_id)
            term.await_screen("arm", lambda s: "Type arm to authorize this one turn:" in s,
                              "the trusted arm prompt", timeout=50)
            term.type_line("arm", "arm")
            term.await_screen("arm", lambda s: "Fixture exit 0" in s,
                              "arm completion", history=True, timeout=50)
            term.type_line("shell", "Reply with exactly: ok")
            term.await_screen("shell", lambda s: fixture["exact_answer"](s, display),
                              "the exact Gemini response", timeout=75)
            print("Public OpenCode shell displayed exact Gemini response: ok", flush=True)
            term.keys("shell", "C-c", "C-c")
            term.await_screen("shell", lambda s: "Fixture exit 0" in s,
                              "shell cleanup", history=True, timeout=35)
        except BaseException:
            screen = term.screen("shell", history=True)
            print(failure_summary(screen), flush=True)
            raise
        finally:
            term.close()
            if run_id:
                fixture["wait_for_cleanup"](run_id)
    print("Public shell run directory retired.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
