"""Options and shared direct-CLI opt-in helpers for live workstation tests."""

from collections.abc import Sequence
import os
from pathlib import Path
import re
import shlex
import sys


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_STORE_TRUE = "store_true"
_REVIEWED_SHA256 = "REVIEWED_SHA256"
_GOOGLE_TEST = Path(__file__).with_name("test_google_text_e2e.py")
_GOOGLE_CASES = {
    "test_google_cached_login_text": ("--run-google-text-live", "native ACP"),
    "test_google_opencode_text": ("--run-google-opencode-live", "isolated OpenCode via ACP"),
    "test_google_public_shell": ("--run-google-public-shell-live", "public OpenCode Google shell"),
}

# Known pytest short options by arity. Any unknown short option immediately preceding
# a live option fails closed as ambiguous rather than guessing boolean arity.
_VALUE_SHORT_OPTS = frozenset({"k", "m", "o", "c", "p", "W", "r"})
_BOOL_SHORT_OPTS = frozenset({"v", "q", "s", "x", "l", "a", "i", "h"})

# Known value-taking long options across pytest and live suites.
_VALUE_LONG_OPTS = frozenset({
    "--rootdir",
    "--confcutdir",
    "--basetemp",
    "--junitxml",
    "--junit-prefix",
    "--maxfail",
    "--tb",
    "--show-capture",
    "--durations",
    "--durations-min",
    "--log-level",
    "--log-format",
    "--log-date-format",
    "--log-cli-level",
    "--log-file",
    "--override-ini",
    "--color",
    "--code-highlight",
    "--capture",
    "--deselect",
    "--ignore",
    "--ignore-glob",
    "--recover-proof-live",
    "--openai-canary-model",
    "--openai-canary-source-sha256",
    "--openai-shell-mode",
    "--openai-shell-model",
    "--openai-shell-instance",
    "--openai-shell-source-sha256",
    "--openai-shell-agent-image-id",
    "--openai-shell-relay-image-id",
    "--claude-shell-mode",
    "--claude-shell-model",
    "--claude-shell-source-sha256",
})

_BOOL_LONG_OPTS = frozenset({
    "--verbose",
    "--quiet",
    "--exitfirst",
    "--showlocals",
    "--strict-markers",
    "--strict-config",
    "--no-header",
    "--no-summary",
    "--full-trace",
    "--collect-only",
    "--run-openai-live",
    "--recover-openai-live",
    "--recover-stream-live",
    "--run-openai-canary-live",
    "--run-openai-shell-live",
    "--run-claude-shell-live",
    "--run-google-text-live",
    "--run-google-opencode-live",
    "--run-google-public-shell-live",
})


def pytest_addoption(parser):
    parser.addoption("--run-google-opencode-live", action=_STORE_TRUE,
                     help="Offer one attended fixed-text prompt from isolated OpenCode via workstation ACP.")
    parser.addoption("--run-google-public-shell-live", action=_STORE_TRUE,
                     help="Offer one attended fixed-text prompt through the public named Google shell.")
    parser.addoption("--run-google-text-live", action=_STORE_TRUE,
                     help="Offer one attended fixed-text prompt through the cached workstation Antigravity login.")
    parser.addoption("--run-openai-live", action=_STORE_TRUE,
                     help="Offer the two attended approvals for the live OpenAI proof.")
    parser.addoption("--recover-openai-live", action=_STORE_TRUE,
                     help="Offer one recovery diagnostic for the unresolved workstation proposal.")
    parser.addoption("--recover-stream-live", action=_STORE_TRUE,
                     help="Offer the final workstation diagnostic for the revised SSE parser.")
    parser.addoption("--recover-proof-live", metavar=_REVIEWED_SHA256,
                     help="Offer the one-approval recovery proof with exact reviewed source.")
    parser.addoption("--run-openai-canary-live", action=_STORE_TRUE,
                     help="Run the live zero-tool OpenCode + OpenAI subscription canary e2e test.")
    parser.addoption("--openai-canary-model", default=None,
                     help="Optional reviewed model slug for --run-openai-canary-live.")
    parser.addoption("--openai-canary-source-sha256", metavar=_REVIEWED_SHA256, default=None,
                     help="Required exact 64-hex SHA-256 source-tree pin for --run-openai-canary-live.")
    parser.addoption("--run-openai-shell-live", action=_STORE_TRUE,
                     help="Run the live OpenAI interactive shell e2e (requires explicit mode/model/pins).")
    parser.addoption("--openai-shell-mode", choices=("full", "mini"), default=None,
                     help="Required explicit UI mode (full or mini) for --run-openai-shell-live.")
    parser.addoption("--openai-shell-model", default=None,
                     help="Required expected upstream model slug for --run-openai-shell-live.")
    parser.addoption("--openai-shell-instance", default=None,
                     help="Required configured OpenAI instance label for --run-openai-shell-live.")
    parser.addoption("--openai-shell-source-sha256", metavar=_REVIEWED_SHA256, default=None,
                     help="Required exact 64-hex SHA-256 source-tree pin for --run-openai-shell-live.")
    parser.addoption("--openai-shell-agent-image-id", metavar="IMAGE_SHA256", default=None,
                     help="Required exact 64-hex SHA-256 pin for localhost/oc-agent:latest.")
    parser.addoption("--openai-shell-relay-image-id", metavar="IMAGE_SHA256", default=None,
                     help="Required exact 64-hex SHA-256 pin for localhost/oc-openai-relay:latest.")


def _resolve_argv(argv: Sequence[str] | None) -> tuple[str, ...]:
    source = sys.argv[1:] if argv is None else argv
    return tuple(str(tok) for tok in source)


def _classify_short_cluster(token: str) -> str:
    """Return 'bool', 'inline_value', 'needs_value', or 'ambiguous' for a -xyz token."""
    body = token[1:]
    if not body:
        return "ambiguous"
    for pos, ch in enumerate(body):
        if ch in _VALUE_SHORT_OPTS:
            return "inline_value" if pos + 1 < len(body) else "needs_value"
        if ch not in _BOOL_SHORT_OPTS:
            return "ambiguous"
    return "bool"


def _scan_direct_cli(argv: Sequence[str] | None = None) -> tuple[list[tuple[str, str | None]], list[str]]:
    """Tokenize direct CLI args before the first unconsumed '--' into (options, positionals).

    Unknown short/long options without '=' consume the following token conservatively so a
    subsequent live flag or value cannot be spoofed through an unknown option's value slot.
    """
    tokens = _resolve_argv(argv)
    options: list[tuple[str, str | None]] = []
    positionals: list[str] = []
    idx = 0
    count = len(tokens)
    while idx < count:
        tok = tokens[idx]
        if tok == "--":
            positionals.extend(tokens[idx + 1:])
            break
        if tok.startswith("--"):
            idx = _consume_long_token(tokens, idx, options)
        elif tok.startswith("-") and tok != "-":
            idx = _consume_short_token(tokens, idx, options)
        else:
            positionals.append(tok)
            idx += 1
    return options, positionals


def _consume_long_token(tokens: tuple[str, ...], idx: int, options: list[tuple[str, str | None]]) -> int:
    tok = tokens[idx]
    if "=" in tok:
        name, val = tok.split("=", 1)
        options.append((name, val))
        return idx + 1
    if tok in _VALUE_LONG_OPTS:
        val = tokens[idx + 1] if idx + 1 < len(tokens) else None
        options.append((tok, val))
        return idx + 2 if idx + 1 < len(tokens) else idx + 1
    if tok in _BOOL_LONG_OPTS:
        options.append((tok, None))
        return idx + 1
    # Unknown long option without '=': fail closed by consuming the next token if present.
    val = tokens[idx + 1] if idx + 1 < len(tokens) else None
    options.append((tok, val))
    return idx + 2 if idx + 1 < len(tokens) else idx + 1


def _consume_short_token(tokens: tuple[str, ...], idx: int, options: list[tuple[str, str | None]]) -> int:
    tok = tokens[idx]
    kind = _classify_short_cluster(tok)
    if kind in ("bool", "inline_value"):
        options.append((tok, None))
        return idx + 1
    # Both 'needs_value' and 'ambiguous' consume the following token conservatively.
    val = tokens[idx + 1] if idx + 1 < len(tokens) else None
    options.append((tok, val))
    return idx + 2 if idx + 1 < len(tokens) else idx + 1


def _token_consumes_next(tok: str) -> bool:
    if tok.startswith("--"):
        return "=" not in tok and tok not in _BOOL_LONG_OPTS
    if tok.startswith("-") and tok != "-":
        return _classify_short_cluster(tok) in ("needs_value", "ambiguous")
    return False


def direct_cli_tokens(argv: Sequence[str] | None = None) -> tuple[str, ...]:
    """Return raw direct CLI tokens strictly before the first unconsumed '--'."""
    tokens = _resolve_argv(argv)
    idx = 0
    count = len(tokens)
    while idx < count:
        tok = tokens[idx]
        if tok == "--":
            return tokens[:idx]
        idx += 2 if _token_consumes_next(tok) and idx + 1 < count else 1
    return tokens


def explicit_cli_flag(flag: str, argv: Sequence[str] | None = None) -> bool:
    """Return True iff `flag` appears once as an unconsumed boolean option before '--'; raise on duplicates."""
    if not flag.startswith("--"):
        return False
    options, _ = _scan_direct_cli(argv)
    matches = [opt for opt in options if opt[0] == flag]
    if not matches:
        return False
    if len(matches) > 1 or matches[0][1] is not None:
        raise ValueError(f"duplicate or ambiguous direct CLI flag: {flag}")
    return True


def explicit_cli_option(option: str, argv: Sequence[str] | None = None) -> tuple[bool, str | None]:
    """Extract a direct value-taking CLI option before '--'; raise ValueError on ambiguity/duplicates."""
    if not option.startswith("--"):
        raise ValueError("option name must start with '--'")
    options, _ = _scan_direct_cli(argv)
    matches = [opt for opt in options if opt[0] == option]
    if not matches:
        return False, None
    if len(matches) > 1:
        raise ValueError(f"duplicate direct CLI option: {option}")
    value = matches[0][1]
    if value is None or value == "" or value.startswith("--"):
        raise ValueError(f"missing or ambiguous value for {option}")
    return True, value


def validate_source_sha256_pin(value: str | None) -> str:
    """Validate pure 64-lowercase-hex SHA-256 pin syntax (separate from snapshot measurement)."""
    if type(value) is not str or not _SHA256_RE.fullmatch(value):
        raise ValueError("expected exact 64-lowercase-hex SHA-256 pin")
    return value


def _inherited_option_tokens(request) -> list[str]:
    inherited: list[str] = []
    env_raw = os.environ.get("PYTEST_ADDOPTS", "")
    if env_raw:
        inherited.extend(shlex.split(env_raw))
    try:
        ini_addopts = request.config.getini("addopts")
    except (AttributeError, KeyError, ValueError):
        ini_addopts = None
    if isinstance(ini_addopts, str):
        if ini_addopts.strip():
            inherited.extend(shlex.split(ini_addopts))
    elif isinstance(ini_addopts, (list, tuple)):
        for item in ini_addopts:
            if type(item) is not str:
                raise ValueError("unexpected non-string addopts entry")
            inherited.append(item)
    elif ini_addopts is not None:
        raise ValueError("unexpected addopts type")
    return inherited


def assert_no_inherited_live_options(
    request,
    prefixes: Sequence[str],
    *,
    target_relpath: str | None = None,
) -> None:
    """Fail closed if PYTEST_ADDOPTS or ini addopts sets any live option or supplies the live target."""
    inherited = _inherited_option_tokens(request)
    target_name = Path(target_relpath).name if target_relpath else None
    for tok in inherited:
        head = tok.split("=", 1)[0]
        if any(head.startswith(prefix) for prefix in prefixes):
            raise ValueError(f"inherited pytest option forbidden for live runs: {head}")
        if target_relpath and (tok == target_relpath or tok.endswith(f"/{target_name}") or tok == target_name):
            raise ValueError("live test target cannot be supplied via inherited pytest options")


def require_explicit_test_target(request, target_file: Path) -> bool:
    """Verify the single live test file was directly named in invocation_params.args and config.args."""
    resolved = target_file.resolve(strict=True)
    _, direct_positionals = _scan_direct_cli(request.config.invocation_params.args)
    if len(direct_positionals) != 1:
        return False
    config_args = list(getattr(request.config, "args", ()))
    if len(config_args) != 1:
        return False
    inv_dir = Path(getattr(request.config.invocation_params, "dir", Path.cwd()))
    try:
        raw_direct = Path(direct_positionals[0].split("::", 1)[0])
        raw_config = Path(config_args[0].split("::", 1)[0])
        direct_target = (raw_direct if raw_direct.is_absolute() else inv_dir / raw_direct).resolve(strict=True)
        config_target = (raw_config if raw_config.is_absolute() else inv_dir / raw_config).resolve(strict=True)
    except OSError:
        return False
    return direct_target == resolved and config_target == resolved


def _approve_google_cases(routes: list[str]) -> bool:
    try:
        with open("/dev/tty", "r+b", buffering=0) as terminal:
            if os.tcgetpgrp(terminal.fileno()) != os.getpgrp():
                return False
            terminal.write(
                (f"Google Antigravity subscription test routes: {', '.join(routes)}.\n"
                 f"Maximum fixed Hydrogen prompts: {len(routes)}. Native retries or usage may still occur.\n"
                 "Authorize this test selection? [y/N] ").encode("ascii")
            )
            return (terminal.readline(16).strip().lower() == b"y"
                    and os.tcgetpgrp(terminal.fileno()) == os.getpgrp())
    except OSError:
        return False


def _selected_google_cases(session):
    config = session.config
    flags = tuple(flag for flag, _ in _GOOGLE_CASES.values())
    if config.getoption("collectonly", False) or not any(config.getoption(flag) for flag in flags):
        return {}
    assert_no_inherited_live_options(session, flags)
    direct_flags = {flag for flag in flags if explicit_cli_flag(flag, config.invocation_params.args)}
    if direct_flags != {flag for flag in flags if config.getoption(flag)}:
        raise ValueError("Pass Google subscription test flags directly on the pytest command line.")
    cases = {}
    for item in session.items:
        case = getattr(item, "originalname", None)
        if item.path == _GOOGLE_TEST and case in _GOOGLE_CASES:
            flag, route = _GOOGLE_CASES[case]
            if flag in direct_flags:
                cases[case] = route
    if cases and (config.getoption("numprocesses", 0) or hasattr(config, "workerinput")):
        raise ValueError("Google subscription tests require one local pytest process.")
    return cases


def pytest_collection_finish(session):
    """Approve only selected Google subscription tests, once, before any test runs."""
    import pytest

    config = session.config
    config._oc_google_live_cases = set()
    try:
        cases = _selected_google_cases(session)
    except ValueError as error:
        raise pytest.UsageError(str(error)) from None
    if cases and _approve_google_cases(list(cases.values())):
        config._oc_google_live_cases = set(cases)


def claim_google_case(request):
    """Consume one authorization from the exact selected collection."""
    cases = request.config._oc_google_live_cases
    case = request.node.originalname
    if case not in cases:
        return False
    cases.remove(case)
    return True
