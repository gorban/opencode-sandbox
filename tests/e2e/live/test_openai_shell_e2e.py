"""Opt-in live OpenAI interactive shell e2e pytest (`full` and `mini`).

Skipped by default unless invoked directly via `tests/e2e/live/run_openai_shell_live.py`
(running from an owner-only read-only verified snapshot) with explicit direct CLI flags.
"""

from pathlib import Path
import re
import sys

_LIVE_DIR = Path(__file__).resolve().parent
_SNAPSHOT_ROOT = _LIVE_DIR.parents[2]
for _path in (str(_SNAPSHOT_ROOT), str(_LIVE_DIR)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from conftest import (
    assert_no_inherited_live_options,
    explicit_cli_flag,
    explicit_cli_option,
    require_explicit_test_target,
    validate_source_sha256_pin,
)
from openai_shell_driver import ShellLiveConfig, run_openai_shell_live
from run_openai_shell_live import SnapshotError, verify_read_only_snapshot


LIVE_FLAG = "--run-openai-shell-live"
MODE_OPT = "--openai-shell-mode"
MODEL_OPT = "--openai-shell-model"
INSTANCE_OPT = "--openai-shell-instance"
SOURCE_PIN_OPT = "--openai-shell-source-sha256"
AGENT_IMG_OPT = "--openai-shell-agent-image-id"
RELAY_IMG_OPT = "--openai-shell-relay-image-id"

_LIVE_PREFIXES = (LIVE_FLAG, "--openai-shell-")
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?\Z", re.ASCII)


class SkipLiveTest(Exception):
    """Raised when the explicit live opt-in flag was not supplied."""


class InvalidLiveInvocation(ValueError):
    """Raised when live invocation options or snapshot provenance fail closed."""


def _require_direct_option(request, option: str, dest: str) -> str:
    argv = request.config.invocation_params.args
    try:
        present, raw_val = explicit_cli_option(option, argv)
    except ValueError as exc:
        raise InvalidLiveInvocation(str(exc)) from None
    parsed = request.config.getoption(dest)
    if not present or raw_val is None or parsed != raw_val:
        raise InvalidLiveInvocation(f"{option} must be passed directly on pytest CLI and match parsed config")
    return raw_val


def _require_direct_image_pin(request, option: str) -> str:
    raw_val = _require_direct_option(request, option, option)
    try:
        return validate_source_sha256_pin(raw_val)
    except ValueError as exc:
        raise InvalidLiveInvocation(f"{option}: {exc}") from None


def validate_live_invocation(request, *, test_file: Path | None = None) -> ShellLiveConfig:
    """Validate direct CLI opt-in, option agreement, target, and read-only snapshot provenance."""
    try:
        assert_no_inherited_live_options(
            request,
            _LIVE_PREFIXES,
            target_relpath="tests/e2e/live/test_openai_shell_e2e.py",
        )
    except ValueError as exc:
        raise InvalidLiveInvocation(str(exc)) from None

    argv = request.config.invocation_params.args
    try:
        direct_enabled = explicit_cli_flag(LIVE_FLAG, argv)
    except ValueError as exc:
        raise InvalidLiveInvocation(str(exc)) from None

    parsed_enabled = bool(request.config.getoption(LIVE_FLAG))
    if not direct_enabled:
        if parsed_enabled:
            raise InvalidLiveInvocation(f"{LIVE_FLAG} must be passed directly in pytest CLI args")
        raise SkipLiveTest(f"Pass {LIVE_FLAG} via tests/e2e/live/run_openai_shell_live.py to run live OpenAI shell e2e.")
    if not parsed_enabled:
        raise InvalidLiveInvocation(f"{LIVE_FLAG} was not recognized by pytest")

    resolved_test = (test_file or Path(__file__)).resolve()
    if not require_explicit_test_target(request, resolved_test):
        raise InvalidLiveInvocation("Live OpenAI shell e2e requires naming tests/e2e/live/test_openai_shell_e2e.py directly")

    mode = _require_direct_option(request, MODE_OPT, MODE_OPT)
    if mode not in ("full", "mini"):
        raise InvalidLiveInvocation(f"{MODE_OPT} must be 'full' or 'mini'")

    model = _require_direct_option(request, MODEL_OPT, MODEL_OPT)
    if not _MODEL_RE.fullmatch(model):
        raise InvalidLiveInvocation(f"{MODEL_OPT} must be a valid model slug")

    instance_label = _require_direct_option(request, INSTANCE_OPT, INSTANCE_OPT)
    if not _LABEL_RE.fullmatch(instance_label):
        raise InvalidLiveInvocation(f"{INSTANCE_OPT} must be a valid configured instance label")

    source_pin_raw = _require_direct_option(request, SOURCE_PIN_OPT, SOURCE_PIN_OPT)
    try:
        source_sha256 = validate_source_sha256_pin(source_pin_raw)
    except ValueError as exc:
        raise InvalidLiveInvocation(f"{SOURCE_PIN_OPT}: {exc}") from None

    agent_image_id = _require_direct_image_pin(request, AGENT_IMG_OPT)
    relay_image_id = _require_direct_image_pin(request, RELAY_IMG_OPT)
    if agent_image_id == relay_image_id:
        raise InvalidLiveInvocation(f"{AGENT_IMG_OPT} and {RELAY_IMG_OPT} must be distinct reviewed image IDs")

    snapshot_root = resolved_test.parents[3]
    try:
        verify_read_only_snapshot(snapshot_root, source_sha256)
    except SnapshotError as exc:
        raise InvalidLiveInvocation(str(exc)) from None

    return ShellLiveConfig(
        ui_mode=mode,
        model=model,
        instance_label=instance_label,
        source_sha256=source_sha256,
        snapshot_root=snapshot_root,
        agent_image_id=agent_image_id,
        relay_image_id=relay_image_id,
    )


def test_openai_interactive_shell_live_ok(request) -> None:
    """Drive the real OpenAI interactive OpenCode session for exact 'ok' with zero tools."""
    import pytest

    try:
        config = validate_live_invocation(request)
    except SkipLiveTest as exc:
        pytest.skip(str(exc))
    except InvalidLiveInvocation as exc:
        pytest.fail(str(exc), pytrace=False)

    result = run_openai_shell_live(config)
    assert result.admitted_writes == 1
    assert result.exact_ok_delivered is True
    assert result.export_verified is True
    assert result.cleanup_verified is True
    assert result.receipt_history_unchanged is True
    assert result.agent_rc == 0
    assert result.ok is True
