"""Verified foreground owner for the opt-in OpenAI interactive shell live e2e (`full` & `mini`).

Retains 100% of attended /dev/tty approval, two-phase discovery-to-turn arming cutover,
and upstream dispatch authority in a single verified foreground process running from a
read-only verified snapshot. Delegates disposable pod/volume/worktree/slot durability
and SIGKILL-surviving teardown to the zero-OAuth DetachedShellCleanupOwner.
"""

import codecs
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
import fcntl
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time

from oc_openai.cli import StreamTerminal
from oc_openai.exposure import ExposureLedger
from oc_openai.live import make_backend
from oc_openai.managed.runtime import HOST_SPAWN, account_home, check_devbox, check_host
from oc_openai.proof_gate import (
    EXPECTED_REPLY,
    PROOF_PROMPT,
    ProofApproval,
    ProofGate,
    ProofGateError,
    compute_exposure_history_digest,
    compute_providers_config_digest,
)
from oc_openai.session_adapter import OpenAISessionAdapter
from oc_openai.session_broker import ProofSessionOptions, run_interactive_session
from oc_openai.shell_cleanup_owner import (
    DetachedShellCleanupOwner,
    JournalSpec,
    _is_devbox,
    _run_podman,
)
from oc_providers.catalog import ResolvedLaunchPlan, _preflight_default_catalog
from oc_providers.config import load_provider_config_with_digest


_HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_LEVEL_RE = re.compile(r"s0:c\d+,c\d+\Z", re.ASCII)
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_SCREEN_CAP = 256 * 1024
_IMAGE_ROLE_LABEL = "io.github.gorban.opencode-sandbox.image"
_DEFAULT_PATH = "/usr/bin:/bin"
_DEFAULT_TERM = "xterm-256color"
_DBUS_ENV_KEY = "DBUS_SESSION_BUS_ADDRESS"
_ERR_APPROVAL_DRIFT = "proof_gate_approval_drift"


class ShellDriverError(RuntimeError):
    """Fail-closed live shell driver preflight, approval, or verification error."""


@dataclass(frozen=True)
class ShellLiveConfig:
    """Validated operator inputs for one live OpenAI interactive shell e2e run."""

    ui_mode: str
    model: str
    instance_label: str
    source_sha256: str
    snapshot_root: Path
    agent_image_id: str
    relay_image_id: str


@dataclass(frozen=True)
class ShellLiveResult:
    """Strictly content-free verification result for one OpenAI shell live e2e run."""

    ok: bool
    run_id: str
    ui_mode: str
    instance_label: str
    model: str
    admitted_writes: int
    exact_ok_delivered: bool
    export_verified: bool
    cleanup_verified: bool
    receipt_history_unchanged: bool
    agent_rc: int
    evidence_path: str
    tui_reply_observed: bool = False


@dataclass
class _PtyState:
    armed: bool = False
    prompt_sent: bool = False
    prompt_offset: int = 0
    pre_prompt_lines: tuple[str, ...] = ()
    reply_observed: bool = False


def strip_ansi(text: str) -> str:
    """Remove ANSI/VT escape sequences for bounded TUI screen matching."""
    return _ANSI_RE.sub("", text)


_CSI_TOKEN_RE = re.compile(r"\x1b\[([0-?]*[ -/]*)([@-~])")
_ALT_SCREEN_MODES = frozenset({"47", "1047", "1049"})
_GEOMETRY_DEC_MODES = frozenset({"3", "6", "40", "69"})
_SAFE_DEC_MODES = frozenset({"1", "12", "25", "1000", "1002", "1003", "1004", "1006", "2004", "2026", "2027"})
_SAFE_XTWINOPS = frozenset({14, 15, 16, 18, 19, 20, 21, 22, 23})
_CURSOR_MOVES = frozenset({"H", "f", "A", "B", "C", "D", "E", "F", "G", "d"})
_EXACT_ASSISTANT_LINE_RE = re.compile(r"(?:[Aa]ssistant\s*:|[●◆▪■])\s*ok\Z")
_USER_PREFIX_RE = re.compile(r"^(?:[Yy]ou\s*:|[Uu]ser\s*:|[>›❯])\s*")
_PROMPT_WORDS_RE = re.compile(r"\s+".join(re.escape(w) for w in PROOF_PROMPT.split()))
_EXACT_OK_WORD_RE = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(EXPECTED_REPLY)}(?![A-Za-z0-9_])")
_BORDER_CHARS = " \t│┃┆┊║|"
_ST_STRING_INTRODUCERS = frozenset({"P", "X", "^", "_"})
_C1_ST_INTRODUCERS = frozenset({"\x90", "\x98", "\x9e", "\x9f"})
_DEC_SPECIAL_GRAPHICS = str.maketrans(
    "_`abcdefghijklmnopqrstuvwxyz{|}~",
    " ◆▒␉␌␍␊°±␤␋┘┐┌└┼⎺⎻─⎼⎽├┤┴┬│≤≥π≠£·",
)


def _normalize_reply_line(raw: str) -> str:
    return " ".join(raw.strip(_BORDER_CHARS).split())


def _is_explicit_assistant_header(line: str) -> bool:
    if not line:
        return False
    low = line.lower()
    return low in ("assistant", "assistant:") or low.startswith("assistant:") or low.startswith("assistant ")


def _is_model_turn_footer(line: str, approved_model: str) -> bool:
    if not approved_model or PROOF_PROMPT in line:
        return False
    if "·" in line:
        parts = [seg.strip() for seg in line.split("·")]
        return len(parts) >= 2 and bool(parts[0]) and parts[1] == approved_model
    return line.startswith("▣") and line[1:].strip() == approved_model


def _is_wrapped_prompt_tail(lines: list[str], idx: int) -> bool:
    cur_clean = _USER_PREFIX_RE.sub("", lines[idx])
    if cur_clean != EXPECTED_REPLY:
        return False
    for lookback in (1, 2, 3):
        if idx - lookback < 0:
            continue
        prefix = " ".join(_USER_PREFIX_RE.sub("", lines[k]) for k in range(idx - lookback, idx))
        if PROOF_PROMPT in prefix:
            continue
        if PROOF_PROMPT in f"{prefix} {cur_clean}":
            return True
    return False


class _TerminalScreen:
    """Bounded VT100/xterm virtual screen tracking current rendered TUI rows.

    Fails closed (`is_certain == False`, `render() == ""`) whenever an unrecognized
    or malformed escape sequence could have mutated screen contents, until a full
    screen clear re-establishes known contents.
    """

    def __init__(self, rows: int = 32, cols: int = 120) -> None:
        self.rows = rows
        self.cols = cols
        self.row = 0
        self.col = 0
        self._wrap_pending = False
        self._g0 = "B"
        self._g1 = "B"
        self._gl = 0
        self._autowrap = True
        self._in_alt_screen = False
        default_saved = ((0, 0), False, ("B", "B", 0), (False, None, None))
        self._saved_states: dict[bool, tuple] = {False: default_saved, True: default_saved}
        self._scroll_top = 0
        self._scroll_bottom = rows - 1
        self._grids: dict[bool, list[list[str]]] = {
            False: self._blank_grid(),
            True: self._blank_grid(),
        }
        self._pending = ""
        self._uncertain_by_screen: dict[bool, bool] = {False: False, True: False}
        self._stream_invalid = False
        self._ctrl_state: str | None = None
        self._ctrl_esc_seen = False
        self._concealed = False
        self._fg: tuple[str, int] | tuple[str, int, int, int] | None = None
        self._bg: tuple[str, int] | tuple[str, int, int, int] | None = None

    def _blank_grid(self) -> list[list[str]]:
        return [[" "] * self.cols for _ in range(self.rows)]

    @property
    def grid(self) -> list[list[str]]:
        return self._grids[self._in_alt_screen]

    @grid.setter
    def grid(self, value: list[list[str]]) -> None:
        self._grids[self._in_alt_screen] = value

    @property
    def _uncertain(self) -> bool:
        return self._uncertain_by_screen[self._in_alt_screen]

    @_uncertain.setter
    def _uncertain(self, value: bool) -> None:
        self._uncertain_by_screen[self._in_alt_screen] = value

    def _save_cursor(self) -> None:
        self._saved_states[self._in_alt_screen] = (
            (self.row, self.col),
            self._wrap_pending,
            (self._g0, self._g1, self._gl),
            (self._concealed, self._fg, self._bg),
        )

    def _restore_cursor(self) -> None:
        pos, wrap_pending, charset, sgr = self._saved_states[self._in_alt_screen]
        self.row, self.col = pos
        self._wrap_pending = wrap_pending
        self._g0, self._g1, self._gl = charset
        self._concealed, self._fg, self._bg = sgr

    @property
    def is_certain(self) -> bool:
        return (
            not self._stream_invalid
            and not self._uncertain
            and not self._pending
            and self._ctrl_state is None
        )

    def invalidate(self) -> None:
        self._stream_invalid = True
        self._uncertain_by_screen = {False: True, True: True}

    def sync_sgr_from(self, other: "_TerminalScreen") -> None:
        self._concealed = other._concealed
        self._fg = other._fg
        self._bg = other._bg
        self._g0 = other._g0
        self._g1 = other._g1
        self._gl = other._gl
        self._autowrap = other._autowrap
        self._in_alt_screen = other._in_alt_screen
        self._saved_states = dict(other._saved_states)
        self._uncertain_by_screen = {
            False: other._uncertain_by_screen[False] if self._in_alt_screen else False,
            True: other._uncertain_by_screen[True] if not self._in_alt_screen else False,
        }
        if other._stream_invalid:
            self._stream_invalid = True
            self._uncertain_by_screen = {False: True, True: True}

    def _reset_sgr(self) -> None:
        self._concealed = False
        self._fg = None
        self._bg = None

    def _is_text_hidden(self) -> bool:
        return self._concealed or (self._fg is not None and self._fg == self._bg)

    def _reset_screen(self, *, reset_cursor: bool = False, full_reset: bool = True) -> None:
        self.grid = self._blank_grid()
        self._uncertain = False
        self._wrap_pending = False
        if reset_cursor:
            self.row = 0
            self.col = 0
            self._scroll_top = 0
            self._scroll_bottom = self.rows - 1
        if full_reset:
            self._reset_sgr()
            self._g0 = "B"
            self._g1 = "B"
            self._gl = 0
            self._autowrap = True
            self._in_alt_screen = False
            self._grids = {False: self._blank_grid(), True: self._blank_grid()}
            self._uncertain_by_screen = {False: False, True: False}
            default_saved = ((0, 0), False, ("B", "B", 0), (False, None, None))
            self._saved_states = {False: default_saved, True: default_saved}

    def _erase_display(self, mode: int) -> None:
        if mode == 2:
            self._reset_screen(reset_cursor=False, full_reset=False)
            return
        if mode == 3:
            return
        if mode == 0:
            self._wrap_pending = False
            for c in range(self.col, self.cols):
                self.grid[self.row][c] = " "
            for r in range(self.row + 1, self.rows):
                self.grid[r] = [" "] * self.cols
        elif mode == 1:
            self._wrap_pending = False
            for r in range(0, self.row):
                self.grid[r] = [" "] * self.cols
            for c in range(0, min(self.col + 1, self.cols)):
                self.grid[self.row][c] = " "
        else:
            self._uncertain = True

    def _erase_line(self, mode: int) -> None:
        if mode == 2:
            self._wrap_pending = False
            self.grid[self.row] = [" "] * self.cols
        elif mode == 0:
            self._wrap_pending = False
            for c in range(self.col, self.cols):
                self.grid[self.row][c] = " "
        elif mode == 1:
            self._wrap_pending = False
            for c in range(0, min(self.col + 1, self.cols)):
                self.grid[self.row][c] = " "
        else:
            self._uncertain = True

    @staticmethod
    def _csi_nums(params: str) -> list[int]:
        clean = params.lstrip("?")
        if not clean:
            return []
        return [int(part) if part.isdigit() else 0 for part in clean.split(";")]

    def _move_cursor(self, final: str, nums: list[int]) -> None:
        self._wrap_pending = False
        n1 = nums[0] if nums and nums[0] > 0 else 1
        n2 = nums[1] if len(nums) > 1 and nums[1] > 0 else 1
        if final in ("H", "f"):
            self.row = max(0, min(self.rows - 1, n1 - 1))
            self.col = max(0, min(self.cols - 1, n2 - 1))
        elif final == "A":
            self.row = max(0, self.row - n1)
        elif final == "B":
            self.row = min(self.rows - 1, self.row + n1)
        elif final == "C":
            self.col = min(self.cols - 1, self.col + n1)
        elif final == "D":
            self.col = max(0, self.col - n1)
        elif final == "E":
            self.row = min(self.rows - 1, self.row + n1)
            self.col = 0
        elif final == "F":
            self.row = max(0, self.row - n1)
            self.col = 0
        elif final == "G":
            self.col = max(0, min(self.cols - 1, n1 - 1))
        elif final == "d":
            self.row = max(0, min(self.rows - 1, n1 - 1))

    def _erase_chars(self, count: int) -> None:
        self._wrap_pending = False
        for c in range(self.col, min(self.cols, self.col + count)):
            self.grid[self.row][c] = " "

    def _delete_chars(self, count: int) -> None:
        self._wrap_pending = False
        tail = self.grid[self.row][self.col + count:]
        self.grid[self.row][self.col:] = tail + [" "] * (self.cols - self.col - len(tail))

    def _insert_chars(self, count: int) -> None:
        self._wrap_pending = False
        step = min(count, self.cols - self.col)
        tail = self.grid[self.row][self.col:self.cols - step]
        self.grid[self.row][self.col:] = [" "] * step + tail

    def _scroll_region(self, top: int, bottom: int, count: int, *, up: bool) -> None:
        height = bottom - top + 1
        step = min(max(1, count), height)
        blanks = [[" "] * self.cols for _ in range(step)]
        region = self.grid[top:bottom + 1]
        self.grid[top:bottom + 1] = (region[step:] + blanks) if up else (blanks + region[:-step])

    def _delete_lines(self, count: int) -> None:
        self._wrap_pending = False
        if self._scroll_top <= self.row <= self._scroll_bottom:
            self._scroll_region(self.row, self._scroll_bottom, count, up=True)

    def _insert_lines(self, count: int) -> None:
        self._wrap_pending = False
        if self._scroll_top <= self.row <= self._scroll_bottom:
            self._scroll_region(self.row, self._scroll_bottom, count, up=False)

    def _set_scroll_margins(self, nums: list[int]) -> None:
        top = (nums[0] - 1) if nums and nums[0] > 0 else 0
        bottom = (nums[1] - 1) if len(nums) > 1 and nums[1] > 0 else (self.rows - 1)
        if 0 <= top < bottom < self.rows:
            self._scroll_top = top
            self._scroll_bottom = bottom
        self.row = 0
        self.col = 0
        self._wrap_pending = False

    def _handle_alt_screen_mode(self, mode: str, final: str) -> None:
        if mode == "1049" and final == "h":
            self._save_cursor()
            self._in_alt_screen = True
            self._reset_screen(reset_cursor=False, full_reset=False)
            return
        if mode == "1049":
            self._in_alt_screen = False
            self._restore_cursor()
            return
        if final == "h":
            self._in_alt_screen = True
        elif self._in_alt_screen:
            if mode == "1047":
                self._reset_screen(reset_cursor=False, full_reset=False)
            self._in_alt_screen = False

    def _apply_dec_mode(self, mode: str, final: str) -> None:
        if mode in _ALT_SCREEN_MODES:
            self._handle_alt_screen_mode(mode, final)
        elif mode == "7":
            self._autowrap = final == "h"
        elif mode == "1048":
            if final == "h":
                self._save_cursor()
            else:
                self._restore_cursor()
        elif mode in _GEOMETRY_DEC_MODES:
            self.invalidate()
        elif mode not in _SAFE_DEC_MODES:
            self._uncertain = True

    def _handle_mode_csi(self, params: str, final: str) -> None:
        if not params.startswith("?"):
            self._uncertain = True
            return
        raw_modes = [p for p in params[1:].split(";") if p]
        if not raw_modes:
            self._uncertain = True
            return
        for raw in raw_modes:
            if not raw.isdigit():
                self._uncertain = True
                continue
            self._apply_dec_mode(raw.lstrip("0") or "0", final)

    def _handle_edit_csi(self, final: str, first: int) -> bool:
        count = first or 1
        if final == "J":
            self._erase_display(first)
        elif final == "K":
            self._erase_line(first)
        elif final == "X":
            self._erase_chars(count)
        elif final == "P":
            self._delete_chars(count)
        elif final == "@":
            self._insert_chars(count)
        elif final == "M":
            self._delete_lines(count)
        elif final == "L":
            self._insert_lines(count)
        elif final == "S":
            self._scroll_region(self._scroll_top, self._scroll_bottom, count, up=True)
        elif final == "T":
            self._scroll_region(self._scroll_top, self._scroll_bottom, count, up=False)
        else:
            return False
        return True

    @staticmethod
    def _parse_colon_color(parts: list[str]) -> tuple[str, int] | tuple[str, int, int, int] | None:
        nums = [int(p) if p.isdigit() else 0 for p in parts]
        if len(nums) >= 3 and nums[1] == 5:
            return ("idx", nums[2])
        if len(nums) >= 6 and nums[1] == 2:
            return ("rgb", nums[3], nums[4], nums[5])
        if len(nums) == 5 and nums[1] == 2:
            return ("rgb", nums[2], nums[3], nums[4])
        return None

    def _apply_sgr_color_token(self, token: str) -> None:
        parts = token.split(":")
        head = int(parts[0]) if parts[0].isdigit() else -1
        if head in (38, 48):
            color = self._parse_colon_color(parts)
            if head == 38:
                self._fg = color
            else:
                self._bg = color

    def _parse_semicolon_color(
        self, tokens: list[str], idx: int,
    ) -> tuple[tuple[str, int] | tuple[str, int, int, int] | None, int]:
        if idx + 1 >= len(tokens) or not tokens[idx + 1].isdigit():
            return None, len(tokens)
        mode = int(tokens[idx + 1])
        if mode == 5 and idx + 2 < len(tokens) and tokens[idx + 2].isdigit():
            return ("idx", int(tokens[idx + 2])), idx + 3
        if mode == 2 and idx + 4 < len(tokens) and all(tokens[idx + k].isdigit() for k in (2, 3, 4)):
            return ("rgb", int(tokens[idx + 2]), int(tokens[idx + 3]), int(tokens[idx + 4])), idx + 5
        return None, len(tokens)

    def _apply_simple_sgr(self, code: int) -> None:
        if code == 0:
            self._reset_sgr()
        elif code == 8:
            self._concealed = True
        elif code == 28:
            self._concealed = False
        elif 30 <= code <= 37:
            self._fg = ("idx", code - 30)
        elif 90 <= code <= 97:
            self._fg = ("idx", code - 90 + 8)
        elif code == 39:
            self._fg = None
        elif 40 <= code <= 47:
            self._bg = ("idx", code - 40)
        elif 100 <= code <= 107:
            self._bg = ("idx", code - 100 + 8)
        elif code == 49:
            self._bg = None

    def _apply_extended_sgr(self, code: int, tokens: list[str], idx: int) -> int:
        color, next_idx = self._parse_semicolon_color(tokens, idx)
        if code == 38:
            self._fg = color
        elif code == 48:
            self._bg = color
        return next_idx

    def _handle_sgr(self, params: str) -> None:
        if not params:
            self._reset_sgr()
            return
        if any(ch not in "0123456789;:" for ch in params):
            self._uncertain = True
            return
        tokens = params.split(";")
        idx = 0
        while idx < len(tokens):
            tok = tokens[idx]
            if ":" in tok:
                self._apply_sgr_color_token(tok)
                idx += 1
                continue
            code = int(tok) if tok.isdigit() else 0
            if code in (38, 48, 58):
                idx = self._apply_extended_sgr(code, tokens, idx)
                continue
            self._apply_simple_sgr(code)
            idx += 1

    @staticmethod
    def _is_ignored_csi(params: str, final: str) -> bool:
        if final in ("n", "c"):
            return True
        if final == "q" and params.endswith(" "):
            return True
        if final == "t":
            first = params.split(";", 1)[0]
            return first.isdigit() and int(first) in _SAFE_XTWINOPS
        return False

    def _handle_cursor_csi(self, final: str, params: str, nums: list[int]) -> None:
        if final in _CURSOR_MOVES:
            self._move_cursor(final, nums)
        elif final == "r":
            self._set_scroll_margins(nums)
        elif final == "s":
            if not params:
                self._save_cursor()
            else:
                self.invalidate()
        elif not params and final == "u":
            self._restore_cursor()
        else:
            self._uncertain = True

    def _handle_csi(self, params: str, final: str) -> None:
        if final == "m":
            self._handle_sgr(params)
            return
        if self._is_ignored_csi(params, final):
            return
        if final == "t" or (final == "|" and ("*" in params or "$" in params)):
            self.invalidate()
            return
        if final in ("h", "l"):
            self._handle_mode_csi(params, final)
            return
        if any(ch not in "0123456789;" for ch in params):
            self._uncertain = True
            return
        nums = self._csi_nums(params)
        if self._handle_edit_csi(final, nums[0] if nums else 0):
            return
        self._handle_cursor_csi(final, params, nums)

    def _linefeed(self) -> None:
        self._wrap_pending = False
        if self.row == self._scroll_bottom:
            self._scroll_region(self._scroll_top, self._scroll_bottom, 1, up=True)
        elif self.row + 1 < self.rows:
            self.row += 1

    def _map_charset_glyph(self, ch: str) -> str | None:
        active_cs = self._g1 if self._gl else self._g0
        if active_cs == "B":
            return ch
        if active_cs == "0":
            return ch.translate(_DEC_SPECIAL_GRAPHICS)
        self._uncertain = True
        return None

    def _put_printable(self, ch: str) -> None:
        mapped = self._map_charset_glyph(ch)
        if mapped is None:
            return
        if self._wrap_pending:
            self._wrap_pending = False
            if self._autowrap:
                self.col = 0
                self._linefeed()
        self.grid[self.row][self.col] = " " if self._is_text_hidden() else mapped
        if self.col + 1 < self.cols:
            self.col += 1
        else:
            self._wrap_pending = True

    def _put_char(self, ch: str) -> None:
        if ch == "\ufffd" or 0x80 <= ord(ch) <= 0x9F:
            self.invalidate()
            return
        if ch == "\x0e":
            self._gl = 1
        elif ch == "\x0f":
            self._gl = 0
        elif ch == "\r":
            self.col = 0
            self._wrap_pending = False
        elif ch in ("\n", "\x0b", "\x0c"):
            self._linefeed()
        elif ch == "\b":
            self.col = max(0, self.col - 1)
            self._wrap_pending = False
        elif ch == "\t":
            new_col = min(self.cols - 1, ((self.col // 8) + 1) * 8)
            if new_col != self.col:
                self.col = new_col
                self._wrap_pending = False
        elif ch >= " " and ch != "\x7f":
            self._put_printable(ch)

    def _consume_two_byte_escape(self, nxt: str) -> bool:
        if nxt == "c":
            self._reset_screen(reset_cursor=True, full_reset=True)
        elif nxt == "7":
            self._save_cursor()
        elif nxt == "8":
            self._restore_cursor()
        elif nxt == "D":
            self._linefeed()
        elif nxt == "E":
            self.col = 0
            self._linefeed()
        elif nxt == "M":
            self._wrap_pending = False
            if self.row == self._scroll_top:
                self._scroll_region(self._scroll_top, self._scroll_bottom, 1, up=False)
            elif self.row > 0:
                self.row -= 1
        elif nxt in ("=", ">"):
            return True
        else:
            return False
        return True

    def _consume_csi_escape(self, data: str, idx: int) -> int | None:
        m = _CSI_TOKEN_RE.match(data, idx)
        if m is None:
            if len(data) - idx < 64:
                return None
            self._uncertain = True
            self._ctrl_state = "csi_discard"
            return idx + 2
        self._handle_csi(m.group(1), m.group(2))
        return m.end()

    def _consume_ctrl_string_step(self, ch: str) -> None:
        if ch in ("\x18", "\x1a"):
            self._uncertain = True
            self._ctrl_state = None
            self._ctrl_esc_seen = False
            return
        if self._ctrl_state == "csi_discard":
            if "@" <= ch <= "~":
                self._ctrl_state = None
            return
        if self._ctrl_esc_seen:
            self._ctrl_esc_seen = False
            if ch == "\\":
                self._ctrl_state = None
                return
        if ch == "\x1b":
            self._ctrl_esc_seen = True
            return
        if ch == "\x9c" or (self._ctrl_state == "osc" and ch == "\x07"):
            self._ctrl_state = None

    def _consume_charset_escape(self, data: str, idx: int, nxt: str) -> int | None:
        if idx + 2 >= len(data):
            return None
        cs = data[idx + 2]
        if nxt == "(":
            self._g0 = cs
        elif nxt == ")":
            self._g1 = cs
        else:
            self._uncertain = True
        return idx + 3

    def _consume_escape(self, data: str, idx: int) -> int | None:
        if idx + 1 >= len(data):
            return None
        nxt = data[idx + 1]
        if nxt == "[":
            return self._consume_csi_escape(data, idx)
        if nxt == "]":
            self._ctrl_state = "osc"
            self._ctrl_esc_seen = False
            return idx + 2
        if nxt in _ST_STRING_INTRODUCERS:
            self._uncertain = True
            self._ctrl_state = "st"
            self._ctrl_esc_seen = False
            return idx + 2
        if nxt in ("(", ")", "*", "+"):
            return self._consume_charset_escape(data, idx, nxt)
        if not self._consume_two_byte_escape(nxt):
            self._uncertain = True
        return idx + 2

    def _enter_c1_control(self, ch: str) -> bool:
        if ch == "\x9d":
            self._ctrl_state = "osc"
            self._ctrl_esc_seen = False
            return True
        if ch in _C1_ST_INTRODUCERS:
            self._uncertain = True
            self._ctrl_state = "st"
            self._ctrl_esc_seen = False
            return True
        if ch == "\x9b":
            self._uncertain = True
            self._ctrl_state = "csi_discard"
            return True
        return False

    def feed(self, text: str) -> None:
        if self._stream_invalid:
            return
        data = self._pending + text
        self._pending = ""
        idx = 0
        total = len(data)
        while idx < total:
            ch = data[idx]
            if self._ctrl_state is not None:
                self._consume_ctrl_string_step(ch)
                idx += 1
                continue
            if ch == "\x1b":
                advanced = self._consume_escape(data, idx)
                if advanced is None:
                    self._pending = data[idx:]
                    return
                idx = advanced
                continue
            if self._enter_c1_control(ch):
                idx += 1
                continue
            self._put_char(ch)
            idx += 1

    def render(self) -> str:
        if not self.is_certain:
            return ""
        return "\n".join("".join(row).rstrip() for row in self.grid)


def render_terminal_screen(raw: str, *, rows: int = 32, cols: int = 120) -> str:
    """Render raw PTY output through a bounded VT100 screen and return only visible rows."""
    screen = _TerminalScreen(rows=rows, cols=cols)
    screen.feed(raw)
    return screen.render()


def _read_private_regular(path: Path, *, max_bytes: int = 128 * 1024) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise ShellDriverError(f"trusted host file unavailable: {path}") from None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022
            or info.st_nlink != 1
        ):
            raise ShellDriverError(f"unsafe trusted host file metadata: {path}")
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ShellDriverError(f"trusted host file exceeds size cap: {path}")
    return data


def read_sb_level(state_dir: Path) -> str:
    """Read and validate the host-trusted SELinux MCS level from $STATE/sb-level."""
    raw = _read_private_regular(state_dir / "sb-level", max_bytes=128).decode("ascii", errors="replace").strip()
    if not _LEVEL_RE.fullmatch(raw):
        raise ShellDriverError("invalid SELinux MCS level in sb-level")
    return raw


def load_built_image_ids(built_images_path: Path) -> frozenset[str]:
    """Read host-trusted 64-hex image IDs recorded in ~/.local/share/oc-sandbox/built-images."""
    raw = _read_private_regular(built_images_path, max_bytes=256 * 1024).decode("ascii", errors="replace")
    ids = {line.strip() for line in raw.splitlines() if _HEX64.fullmatch(line.strip())}
    return frozenset(ids)


def verify_reviewed_role_image(
    *,
    role: str,
    image_id: str,
    built_images_path: Path,
    podman_runner=_run_podman,
) -> str:
    """Verify an explicit 64-hex image ID exists locally, is owned in built-images, and matches role."""
    if role not in ("agent", "relay"):
        raise ShellDriverError("unsupported image role")
    if not _HEX64.fullmatch(image_id):
        raise ShellDriverError(f"invalid reviewed image ID for role {role}")
    owned_ids = load_built_image_ids(built_images_path)
    if image_id not in owned_ids:
        raise ShellDriverError(f"image {image_id[:12]} ({role}) is not recorded in {built_images_path}")
    res = podman_runner(["image", "inspect", image_id], timeout=15.0)
    if res.returncode != 0:
        raise ShellDriverError(f"reviewed {role} image {image_id[:12]} is not present locally")
    try:
        parsed = json.loads(res.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ShellDriverError(f"malformed image inspect output for {role}") from None
    entry = parsed[0] if isinstance(parsed, list) and parsed else parsed
    if not isinstance(entry, dict) or entry.get("Id") != image_id:
        raise ShellDriverError(f"image inspect ID mismatch for {role}")
    labels = entry.get("Labels")
    if not isinstance(labels, dict):
        config = entry.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else {}
    if not isinstance(labels, dict) or labels.get(_IMAGE_ROLE_LABEL) != role:
        raise ShellDriverError(f"image {image_id[:12]} does not carry required role label '{role}'")
    return image_id


def compute_locked_exposure_digest(exposure_dir: Path) -> str:
    """Compute the full 12-file exposure digest while holding ExposureLedger._locked()."""
    ledger = ExposureLedger(exposure_dir)
    with ledger._locked():
        return compute_exposure_history_digest(exposure_dir)


def prompt_attended_approval(summary: dict[str, object]) -> None:
    """Present exact approval details directly on /dev/tty and require typed confirmation."""
    if not StreamTerminal(sys.stdin, sys.stdout, sys.stderr).attended():
        raise ShellDriverError("attended foreground TTY is required for live OpenAI shell approval")
    run_id = str(summary["run_id"])
    expected_phrase = f"APPROVE {run_id[:8]}"
    lines = [
        "",
        "=== Live OpenAI Interactive Shell E2E Approval ===",
        f"  run_id                : {run_id}",
        f"  instance_label        : {summary['instance_label']}",
        f"  scoped_provider_id    : {summary['scoped_provider_id']}",
        f"  approved_model        : {summary['approved_model']}",
        f"  ui_mode               : {summary['ui_mode']}",
        f"  route_policy          : {summary['route_policy']}",
        f"  client_id             : {summary['client_id']}",
        f"  selection_epoch       : {summary['selection_epoch']}",
        f"  reg_generation        : {summary['registration_generation']}",
        f"  providers_cfg_sha256  : {summary['providers_config_digest']}",
        f"  exposure_12file_sha256: {summary['history_digest_all_12_files']}",
        f"  agent_image_id        : {summary['agent_image_id']}",
        f"  relay_image_id        : {summary['relay_image_id']}",
        f"  source_sha256         : {summary['source_sha256']}",
        "  scope                 : 1-send latched zero-tool turn ('Reply with exactly: ok')",
        f"Type exact confirmation phrase '{expected_phrase}' to authorize (anything else aborts):",
        "> ",
    ]
    rfd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    rfd_owned = True
    wfd = -1
    wfd_owned = False
    try:
        wfd = os.dup(rfd)
        wfd_owned = True
        tty_in = os.fdopen(rfd, "r", encoding="utf-8", buffering=1)
        rfd_owned = False
        tty_out = os.fdopen(wfd, "w", encoding="utf-8", buffering=1)
        wfd_owned = False
        with tty_in, tty_out:
            tty_out.write("\n".join(lines))
            tty_out.flush()
            response = tty_in.readline()
    finally:
        if wfd_owned:
            with suppress(OSError):
                os.close(wfd)
        if rfd_owned:
            with suppress(OSError):
                os.close(rfd)
    if not response or response.strip() != expected_phrase:
        raise ShellDriverError("operator declined live OpenAI shell approval")


def _collect_parts(parts: object, texts: list[str]) -> int:
    if not isinstance(parts, list):
        return 0
    tool_parts = 0
    for part in parts:
        if not isinstance(part, dict):
            continue
        ptype = part.get("type")
        if ptype == "text" and isinstance(part.get("text"), str):
            texts.append(part["text"])
        elif ptype in ("tool", "tool-invocation", "tool_call", "function_call"):
            tool_parts += 1
    return tool_parts


def _verify_export_messages(export_data: dict[str, object]) -> None:
    messages = export_data.get("messages")
    if not isinstance(messages, list) or len(messages) != 2:
        raise ShellDriverError("session export must contain exactly one user message and one assistant message")
    user_msg, asst_msg = messages
    if not isinstance(user_msg, dict) or not isinstance(asst_msg, dict):
        raise ShellDriverError("session export message entries must be JSON objects")
    user_info = user_msg.get("info") if isinstance(user_msg.get("info"), dict) else user_msg
    asst_info = asst_msg.get("info") if isinstance(asst_msg.get("info"), dict) else asst_msg
    if user_info.get("role") != "user" or asst_info.get("role") != "assistant":
        raise ShellDriverError("session export roles must be exact [user, assistant]")
    user_texts: list[str] = []
    asst_texts: list[str] = []
    tool_parts = _collect_parts(user_msg.get("parts"), user_texts)
    tool_parts += _collect_parts(asst_msg.get("parts"), asst_texts)
    if tool_parts != 0:
        raise ShellDriverError("session export recorded unexpected tool calls")
    if "".join(user_texts) != PROOF_PROMPT:
        raise ShellDriverError("session export user prompt did not match exact proof prompt")
    if "".join(asst_texts) != EXPECTED_REPLY:
        raise ShellDriverError("session export assistant reply did not match exact untrimmed 'ok'")


def inspect_session_export(
    *,
    volume_name: str,
    level: str,
    cwd: str,
    agent_image_id: str,
    podman_runner=_run_podman,
) -> bool:
    """Verify via pinned-ID --network=none --tmpfs /sandbox container that exported session is exact 'ok' with 0 tools."""
    inspect_script = (
        "import json, os, shutil, subprocess, sys\n"
        "cwd = sys.argv[1]\n"
        "os.makedirs(os.path.join('/sandbox', cwd), exist_ok=True)\n"
        "dst = '/tmp/home/.local/share/opencode'\n"
        "os.makedirs(dst, exist_ok=True)\n"
        "src = '/src-home/.local/share/opencode'\n"
        "for name in ('opencode.db', 'opencode.db-wal', 'opencode.db-shm'):\n"
        "    p = os.path.join(src, name)\n"
        "    if os.path.exists(p):\n"
        "        shutil.copy2(p, os.path.join(dst, name))\n"
        "env = dict(os.environ, HOME='/tmp/home', XDG_DATA_HOME='/tmp/home/.local/share')\n"
        "workdir = os.path.join('/sandbox', cwd)\n"
        "listed = subprocess.run(['opencode', '--standalone', 'session', 'list', '--format', 'json'],\n"
        "                        cwd=workdir, env=env, capture_output=True, text=True, check=True)\n"
        "sessions = json.loads(listed.stdout)\n"
        "if not isinstance(sessions, list) or len(sessions) != 1:\n"
        "    raise SystemExit(f'expected 1 session, got {len(sessions) if isinstance(sessions, list) else None}')\n"
        "sid = sessions[0]['id']\n"
        "exported = subprocess.run(['opencode', '--standalone', 'session', 'export', sid],\n"
        "                          cwd=workdir, env=env, capture_output=True, text=True, check=True)\n"
        "sys.stdout.write(exported.stdout)\n"
    )
    res = podman_runner(
        [
            "run", "--rm", "--pull=never", "--network=none", "--http-proxy=false",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--security-opt", f"label=level:{level}",
            "--pids-limit=128", "--memory=512m",
            "--tmpfs", "/sandbox:rw,nosuid,nodev,noexec,size=4m,mode=0700",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=0700",
            "-v", f"{volume_name}:/src-home:ro",
            "--entrypoint", "python3",
            agent_image_id, "-I", "-c", inspect_script, cwd,
        ],
        timeout=30.0,
    )
    if res.returncode != 0:
        raise ShellDriverError(f"session export inspection failed ({res.returncode})")
    try:
        export_data = json.loads(res.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ShellDriverError("session export returned invalid JSON") from None
    _verify_export_messages(export_data)
    return True


def _agent_start_command(agent_id: str) -> tuple[list[str], dict[str, str]]:
    uid = os.getuid()
    runtime_dir = f"/run/user/{uid}"
    home_dir = str(account_home())
    if _is_devbox():
        host_env = {
            "PATH": _DEFAULT_PATH,
            "HOME": home_dir,
            "TERM": _DEFAULT_TERM,
            "XDG_RUNTIME_DIR": runtime_dir,
            _DBUS_ENV_KEY: f"unix:path={runtime_dir}/bus",
        }
        spawn_env = {
            "PATH": _DEFAULT_PATH,
            "HOME": home_dir,
            "TERM": _DEFAULT_TERM,
            _DBUS_ENV_KEY: f"unix:path=/run/host{runtime_dir}/bus",
        }
        cmd = [
            HOST_SPAWN, "--env=", "/usr/bin/env", "-i",
            *(f"{k}={v}" for k, v in host_env.items()),
            "/usr/bin/podman", "--remote=false", "--default-mounts-file=/dev/null",
            "start", "-ai", agent_id,
        ]
        return cmd, spawn_env
    env = {
        "PATH": _DEFAULT_PATH,
        "HOME": home_dir,
        "TERM": _DEFAULT_TERM,
        "XDG_RUNTIME_DIR": runtime_dir,
        _DBUS_ENV_KEY: f"unix:path={runtime_dir}/bus",
    }
    cmd = ["/usr/bin/podman", "--remote=false", "--default-mounts-file=/dev/null", "start", "-ai", agent_id]
    return cmd, env


def _read_pty_bytes(master_fd: int, timeout: float) -> bytes | None:
    ready, _, _ = select.select([master_fd], [], [], timeout)
    if not ready:
        return b""
    chunks = bytearray()
    while len(chunks) < _SCREEN_CAP:
        try:
            chunk = os.read(master_fd, 4096)
        except OSError:
            return bytes(chunks) if chunks else None
        if not chunk:
            return bytes(chunks) if chunks else None
        chunks.extend(chunk)
        if not select.select([master_fd], [], [], 0.0)[0]:
            break
    return bytes(chunks)


_ANY_SCOPED_RE = re.compile(r"(?<![A-Za-z0-9_-])openai--[a-z0-9][a-z0-9-]*(?![A-Za-z0-9_-])")
_ANY_DISPLAY_LABEL_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:ChatGPT\s+Subscription|OpenAI)\s*\(([a-z0-9][a-z0-9-]*)\)(?![A-Za-z0-9_-])"
)


def _line_has_conflicting_provider(line: str, approval: ProofApproval) -> bool:
    for found in _ANY_SCOPED_RE.findall(line):
        if found != approval.scoped_provider_id:
            return True
    for found_label in _ANY_DISPLAY_LABEL_RE.findall(line):
        if found_label != approval.instance_label:
            return True
    return False


def _provider_matches_line(text: str, approval: ProofApproval, scoped_re: re.Pattern[str], label_re: re.Pattern[str]) -> bool:
    if _line_has_conflicting_provider(text, approval):
        return False
    return scoped_re.search(text) is not None or label_re.search(text) is not None


def _line_matches_route(
    line: str,
    approval: ProofApproval,
    exact_route_re: re.Pattern[str],
    model_re: re.Pattern[str],
    scoped_re: re.Pattern[str],
    label_re: re.Pattern[str],
) -> bool:
    if _line_has_conflicting_provider(line, approval):
        return False
    if exact_route_re.search(line) is not None:
        return True
    return _provider_matches_line(line, approval, scoped_re, label_re) and model_re.search(line) is not None


def _pair_matches_route(
    a: str,
    b: str,
    approval: ProofApproval,
    model_re: re.Pattern[str],
    scoped_re: re.Pattern[str],
    label_re: re.Pattern[str],
) -> bool:
    if _line_has_conflicting_provider(a, approval) or _line_has_conflicting_provider(b, approval):
        return False
    pair_a = _provider_matches_line(a, approval, scoped_re, label_re) and model_re.search(b) is not None
    pair_b = model_re.search(a) is not None and _provider_matches_line(b, approval, scoped_re, label_re)
    return pair_a or pair_b


def _screen_has_conflicting_route(lines: list[str], approval: ProofApproval, model_re: re.Pattern[str]) -> bool:
    esc_model = re.escape(approval.approved_model)
    any_slash_re = re.compile(rf"(?<![A-Za-z0-9._/-])openai--([a-z0-9][a-z0-9-]*)/{esc_model}(?![A-Za-z0-9._/-])")
    for line in lines:
        if any(f"openai--{lbl}" != approval.scoped_provider_id for lbl in any_slash_re.findall(line)):
            return True
        if _line_has_conflicting_provider(line, approval) and model_re.search(line) is not None:
            return True
    for a, b in zip(lines, lines[1:]):
        if _line_has_conflicting_provider(a, approval) and model_re.search(b) is not None:
            return True
        if model_re.search(a) is not None and _line_has_conflicting_provider(b, approval):
            return True
    return False


def _needs_terminal_render(text: str) -> bool:
    return (
        "\x1b" in text
        or "\r" in text
        or "\b" in text
        or "\ufffd" in text
        or any(0x80 <= ord(ch) <= 0x9F for ch in text)
    )


def extract_observed_route_row(clean: str, approval: ProofApproval) -> str | None:
    """Return an unambiguous currently rendered route row matching approved provider and model."""
    rendered = render_terminal_screen(clean) if _needs_terminal_render(clean) else clean
    esc_model = re.escape(approval.approved_model)
    esc_scoped = re.escape(approval.scoped_provider_id)
    esc_label = re.escape(approval.instance_label)
    exact_route_re = re.compile(rf"(?<![A-Za-z0-9._/-]){esc_scoped}/{esc_model}(?![A-Za-z0-9._/-])")
    model_re = re.compile(rf"(?<![A-Za-z0-9._/-]){esc_model}(?![A-Za-z0-9._/-])")
    scoped_re = re.compile(rf"(?<![A-Za-z0-9_-]){esc_scoped}(?![A-Za-z0-9_-])")
    label_re = re.compile(rf"(?<![A-Za-z0-9_-])(?:ChatGPT\s+Subscription|OpenAI)\s*\({esc_label}\)(?![A-Za-z0-9_-])")

    lines = [ln for ln in (" ".join(raw.split()) for raw in rendered.splitlines()) if ln]
    if _screen_has_conflicting_route(lines, approval, model_re):
        return None
    for line in lines:
        if _line_matches_route(line, approval, exact_route_re, model_re, scoped_re, label_re):
            return line[:200]
    for a, b in zip(lines, lines[1:]):
        if _pair_matches_route(a, b, approval, model_re, scoped_re, label_re):
            return f"{a} | {b}"[:200]
    return None


def _line_is_visible_assistant_reply(lines: list[str], idx: int, approved_model: str) -> bool:
    line = lines[idx]
    if _EXACT_ASSISTANT_LINE_RE.fullmatch(line) is not None:
        return True
    if line != EXPECTED_REPLY or _is_wrapped_prompt_tail(lines, idx):
        return False
    prev_line = lines[idx - 1] if idx > 0 else ""
    if _is_explicit_assistant_header(prev_line):
        return True
    next_line = lines[idx + 1] if idx + 1 < len(lines) else ""
    return PROOF_PROMPT in prev_line and _is_model_turn_footer(next_line, approved_model)


def _visible_assistant_reply_lines(lines: list[str], approved_model: str) -> Counter[str]:
    return Counter(
        lines[idx]
        for idx in range(len(lines))
        if _line_is_visible_assistant_reply(lines, idx, approved_model)
    )


def _non_prompt_line_counts(lines: list[str]) -> Counter[str]:
    return Counter(
        lines[idx]
        for idx in range(len(lines))
        if not _is_wrapped_prompt_tail(lines, idx)
    )


def _post_prompt_has_reply_text(post_prompt_text: str) -> bool:
    if not post_prompt_text:
        return False
    cleaned_lines = [
        _USER_PREFIX_RE.sub("", ln)
        for ln in (_normalize_reply_line(r) for r in post_prompt_text.splitlines())
        if ln
    ]
    without_prompt = _PROMPT_WORDS_RE.sub(" ", " ".join(cleaned_lines))
    return _EXACT_OK_WORD_RE.search(without_prompt) is not None


def _has_new_exact_reply(
    rendered: str,
    pre_prompt_lines: tuple[str, ...],
    post_prompt_text: str | None,
    *,
    approved_model: str = "",
) -> bool:
    if post_prompt_text is not None and not _post_prompt_has_reply_text(post_prompt_text):
        return False
    cur_lines = [ln for ln in (_normalize_reply_line(r) for r in rendered.splitlines()) if ln]
    pre_lines = list(pre_prompt_lines)
    new_replies = _visible_assistant_reply_lines(cur_lines, approved_model) - _visible_assistant_reply_lines(
        pre_lines, approved_model,
    )
    if not new_replies:
        return False
    new_non_prompt = _non_prompt_line_counts(cur_lines) - _non_prompt_line_counts(pre_lines)
    return any(new_non_prompt[line] > 0 for line in new_replies)


def _step_pty_driver(
    master_fd: int,
    clean: str,
    elapsed: float,
    proof_gate: ProofGate,
    arm_turn_route,
    state: _PtyState,
    *,
    post_prompt_text: str | None = None,
) -> bool:
    if not state.armed:
        if proof_gate.admitted_writes != 0:
            raise ShellDriverError("unexpected upstream write during CLOSED_DISCOVERY")
        observed_row = extract_observed_route_row(clean, proof_gate.approval)
        if observed_row is not None and elapsed >= 1.5:
            screen_digest = sha256(clean.encode("utf-8")).hexdigest()
            arm_turn_route(observed_row, screen_digest)
            state.armed = True
        elif elapsed > 25.0:
            raise ShellDriverError("timed out waiting for OpenCode TUI readiness row")
        return False
    if not state.prompt_sent:
        state.prompt_offset = len(clean)
        state.pre_prompt_lines = tuple(ln for ln in (_normalize_reply_line(r) for r in clean.splitlines()) if ln)
        os.write(master_fd, (PROOF_PROMPT + "\r").encode("ascii"))
        state.prompt_sent = True
        return False
    model_name = getattr(getattr(proof_gate, "approval", None), "approved_model", "")
    if proof_gate.exact_ok_delivered and _has_new_exact_reply(
        clean, state.pre_prompt_lines, post_prompt_text, approved_model=model_name,
    ):
        state.reply_observed = True
        time.sleep(0.6)
        with suppress(OSError):
            os.write(master_fd, b"\x03")
        return True
    if elapsed > 90.0:
        raise ShellDriverError("timed out waiting for exact 'ok' delivery in OpenCode TUI")
    return False


@dataclass
class _PtyScreens:
    main: _TerminalScreen
    main_decoder: object
    post: _TerminalScreen
    post_decoder: object


def _feed_pty_bytes(screen: _TerminalScreen, decoder, data: bytes, *, final: bool = False) -> None:
    try:
        decoded = decoder.decode(data, final=final)
    except UnicodeDecodeError:
        screen.invalidate()
        return
    if decoded:
        screen.feed(decoded)


def _record_final_pty_reply(
    master_fd: int,
    screens: _PtyScreens,
    proof_gate: ProofGate,
    state: _PtyState,
) -> None:
    tail_chunk = _read_pty_bytes(master_fd, 0.05)
    if tail_chunk:
        _feed_pty_bytes(screens.main, screens.main_decoder, tail_chunk, final=False)
        if state.prompt_sent:
            _feed_pty_bytes(screens.post, screens.post_decoder, tail_chunk, final=False)
    _feed_pty_bytes(screens.main, screens.main_decoder, b"", final=True)
    if state.prompt_sent:
        _feed_pty_bytes(screens.post, screens.post_decoder, b"", final=True)
    if not state.reply_observed and state.prompt_sent and proof_gate.exact_ok_delivered:
        model_name = getattr(getattr(proof_gate, "approval", None), "approved_model", "")
        if _has_new_exact_reply(
            screens.main.render(), state.pre_prompt_lines, screens.post.render(), approved_model=model_name,
        ):
            state.reply_observed = True


def _wait_or_stop_agent_proc(proc: subprocess.Popen[bytes], agent_id: str) -> int:
    try:
        return proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            proc.terminate()
        _run_podman(["stop", "-t", "2", agent_id], timeout=10.0)
        return proc.wait(timeout=5)


def _drive_agent_pty(
    agent_id: str,
    stop_event,
    proof_gate: ProofGate,
    arm_turn_route,
    *,
    outcome: dict[str, bool] | None = None,
) -> int:
    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 120, 0, 0))
    cmd, env = _agent_start_command(agent_id)
    proc = subprocess.Popen(cmd, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, env=env, close_fds=True)
    os.close(slave_fd)
    screens = _PtyScreens(
        main=_TerminalScreen(rows=32, cols=120),
        main_decoder=codecs.getincrementaldecoder("utf-8")(errors="strict"),
        post=_TerminalScreen(rows=32, cols=120),
        post_decoder=codecs.getincrementaldecoder("utf-8")(errors="strict"),
    )
    state = _PtyState()
    started = time.monotonic()
    try:
        while proc.poll() is None and not stop_event.is_set():
            chunk = _read_pty_bytes(master_fd, 0.15)
            if chunk is None:
                break
            if chunk:
                _feed_pty_bytes(screens.main, screens.main_decoder, chunk, final=False)
                if state.prompt_sent:
                    _feed_pty_bytes(screens.post, screens.post_decoder, chunk, final=False)
            rendered = screens.main.render()
            post_text = screens.post.render() if state.prompt_sent else ""
            was_sent = state.prompt_sent
            done = _step_pty_driver(
                master_fd,
                rendered,
                time.monotonic() - started,
                proof_gate,
                arm_turn_route,
                state,
                post_prompt_text=post_text,
            )
            if not was_sent and state.prompt_sent:
                screens.post.sync_sgr_from(screens.main)
            if done:
                break
        _record_final_pty_reply(master_fd, screens, proof_gate, state)
        return _wait_or_stop_agent_proc(proc, agent_id)
    finally:
        if outcome is not None:
            outcome["reply_observed"] = state.reply_observed
        with suppress(OSError):
            os.close(master_fd)


def _select_admitted_item(plan, scoped_provider_id: str, model: str):
    matches = [item for item in plan.admitted if item.spec.scoped_id == scoped_provider_id]
    if len(matches) != 1:
        raise ShellDriverError(f"configured OpenAI instance '{scoped_provider_id}' is not admitted for launch")
    item = matches[0]
    if model not in item.models:
        raise ShellDriverError(f"model '{model}' is not in verified catalog for '{scoped_provider_id}'")
    return item


def _read_private_json_no_lock(path: Path) -> dict[str, object]:
    """Read an atomically replaced private JSON store file without acquiring flock."""
    try:
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise ProofGateError(_ERR_APPROVAL_DRIFT) from None
    try:
        dinfo = os.fstat(dir_fd)
        if dinfo.st_uid != os.geteuid() or dinfo.st_mode & 0o077:
            raise ProofGateError(_ERR_APPROVAL_DRIFT)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
        with os.fdopen(fd, "rb") as stream:
            finfo = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(finfo.st_mode)
                or finfo.st_uid != os.geteuid()
                or finfo.st_mode & 0o077
                or finfo.st_nlink != 1
            ):
                raise ProofGateError(_ERR_APPROVAL_DRIFT)
            raw = stream.read(262_145)
    except ProofGateError:
        raise
    except OSError:
        raise ProofGateError(_ERR_APPROVAL_DRIFT) from None
    finally:
        os.close(dir_fd)
    if len(raw) > 262_144:
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise ProofGateError(_ERR_APPROVAL_DRIFT) from None
    if not isinstance(parsed, dict):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    return parsed


def _verify_live_binding_intact(
    approval: ProofApproval,
    *,
    backend,
    config_dir: Path,
    target_binding,
) -> None:
    """Lock-free drift recheck safe inside arm() and inside before_write() under held fences."""
    del target_binding
    current_cfg_digest = compute_providers_config_digest(config_dir)
    if not hmac.compare_digest(current_cfg_digest, approval.providers_config_digest):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    profiles_root = Path(backend.profiles._root)
    prof_state = _read_private_json_no_lock(profiles_root / "profiles" / "state.json")
    registrations = prof_state.get("registrations")
    if not isinstance(registrations, dict) or approval.instance_label not in registrations:
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    entry = registrations[approval.instance_label]
    if not isinstance(entry, dict):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    entry_dir = str(profiles_root / "registrations" / str(entry.get("key") or ""))
    if (
        entry.get("retiring") is not False
        or entry_dir != approval.profile_directory
        or str(entry.get("client_id") or "") != approval.client_id
        or str(prof_state.get("epoch") or "") != approval.selection_epoch
    ):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)
    reg_state = _read_private_json_no_lock(Path(approval.profile_directory) / "state.json")
    if (
        reg_state.get("generation") != approval.credential_generation
        or str(reg_state.get("client") or "") != approval.client_id
        or not reg_state.get("tokens")
        or reg_state.get("worker_retiring") is True
    ):
        raise ProofGateError(_ERR_APPROVAL_DRIFT)


def build_driver_session_spec(
    jspec: JournalSpec,
    *,
    relay_image_id: str,
    ui_mode: str,
    agent_mem: str = "4g",
) -> dict[str, str]:
    """Build the session spec matching `oc-sandbox` / `oc-sandbox --mini` fd-3 JSON schema."""
    return {
        "instance": jspec.instance,
        "pod": jspec.pod_name,
        "agent": f"oc-{jspec.instance}-agent",
        "relay": f"oc-{jspec.instance}-openai-relay",
        "relay_image": relay_image_id,
        "agent_image": jspec.agent_image_id,
        "agent_mem": agent_mem,
        "level": jspec.level,
        "sandbox": str(jspec.sandbox_dir),
        "cwd": jspec.cwd,
        "home_vol": jspec.volume_name,
        "chromium": f"oc-{jspec.instance}-chromium",
        "postgres": "",
        "pg_secret": "",
        "dind": "",
        "dind_run": "",
        "provider_filter": "",
        "cli_ui_mode": "mini" if ui_mode == "mini" else "default",
    }


def _build_preflight_plan(provider_config, preflight_adapter, scoped_id: str, config: ShellLiveConfig):
    plan_candidates, excluded = _preflight_default_catalog(provider_config, {"openai": preflight_adapter})
    acknowledged_digests: dict[str, str] = {}
    hold_notes: list[str] = []
    for item in plan_candidates:
        if item.exposure_hold is not None:
            acknowledged_digests[item.exposure_hold.scope_id] = item.exposure_hold.digest
            hold_notes.append(
                f"{item.spec.qualified_name}: {item.exposure_hold.file_count} files, "
                f"{item.exposure_hold.unsettled_count} unsettled, {item.exposure_hold.digest[:12]}"
            )
    plan = ResolvedLaunchPlan(
        admitted=tuple(plan_candidates),
        excluded=tuple(excluded),
        acknowledged_digests=acknowledged_digests,
        initial_provider_id=scoped_id,
        initial_model=config.model,
        ui_mode=config.ui_mode,
        ui_source="cli",
    )
    admitted = _select_admitted_item(plan, scoped_id, config.model)
    return plan, admitted, hold_notes


def run_openai_shell_live(config: ShellLiveConfig) -> ShellLiveResult:
    """Execute one attended live OpenAI interactive shell e2e run inside the verified foreground owner."""
    check_devbox()
    check_host()
    if config.agent_image_id == config.relay_image_id:
        raise ShellDriverError("agent and relay image IDs must be distinct")
    home = account_home()
    state_dir = home / ".local/share/oc-sandbox"
    config_dir = home / ".config/oc-sandbox"
    sandbox_dir = home / "opencode-sandbox"
    built_images_path = state_dir / "built-images"
    level = read_sb_level(state_dir)

    agent_image_id = verify_reviewed_role_image(
        role="agent", image_id=config.agent_image_id, built_images_path=built_images_path,
    )
    relay_image_id = verify_reviewed_role_image(
        role="relay", image_id=config.relay_image_id, built_images_path=built_images_path,
    )

    provider_config, providers_cfg_digest = load_provider_config_with_digest(config_dir=config_dir)
    if provider_config is None or providers_cfg_digest is None:
        raise ShellDriverError("providers.toml is required for configuration-first live OpenAI shell e2e")
    backend = make_backend()
    exposure_dir = backend._state
    history_digest_before = compute_locked_exposure_digest(exposure_dir)

    terminal = StreamTerminal(sys.stdin, sys.stdout, sys.stderr)
    preflight_adapter = OpenAISessionAdapter(backend)
    scoped_id = f"openai--{config.instance_label}"
    instance_name = f"e2e-{secrets.token_hex(4)}"
    run_id = secrets.token_hex(16)
    cwd = f"wt/{instance_name}"

    plan, admitted, hold_notes = _build_preflight_plan(provider_config, preflight_adapter, scoped_id, config)
    target = admitted.handle
    approval = ProofApproval(
        run_id=run_id,
        instance_label=config.instance_label,
        scoped_provider_id=scoped_id,
        approved_model=config.model,
        ui_mode=config.ui_mode,
        cwd=cwd,
        selection_epoch=target.profile.epoch,
        credential_generation=target.binding.generation,
        history_digest_all_12_files=history_digest_before,
        profile_directory=str(target.profile.directory),
        client_id=str(target.profile.client_id or ""),
        auth_mode=admitted.spec.auth_mode,
        route_policy=admitted.route_policy,
        providers_config_digest=providers_cfg_digest,
    )

    prompt_attended_approval({
        "run_id": run_id,
        "instance_label": config.instance_label,
        "scoped_provider_id": scoped_id,
        "approved_model": config.model,
        "ui_mode": config.ui_mode,
        "route_policy": admitted.route_policy + (f" | prior holds: {'; '.join(hold_notes)}" if hold_notes else ""),
        "client_id": approval.client_id,
        "selection_epoch": approval.selection_epoch,
        "registration_generation": approval.credential_generation,
        "providers_config_digest": providers_cfg_digest,
        "history_digest_all_12_files": history_digest_before,
        "agent_image_id": agent_image_id,
        "relay_image_id": relay_image_id,
        "source_sha256": config.source_sha256,
    })

    evidence_dir = Path(tempfile.mkdtemp(prefix="oc-shell-evidence-"))
    os.chmod(evidence_dir, 0o700)
    session_stop: dict[str, object] = {"event": None}

    def _check_foreground() -> None:
        ev = session_stop["event"]
        if (ev is not None and ev.is_set()) or not terminal.attended():
            raise ProofGateError("proof_gate_foreground_lost")

    proof_gate = ProofGate(
        approval,
        evidence_dir=evidence_dir,
        exposure_dir=exposure_dir,
        check_owner_alive=_check_foreground,
        check_binding_intact=lambda appr: _verify_live_binding_intact(
            appr, backend=backend, config_dir=config_dir, target_binding=target.binding,
        ),
    )
    owner = DetachedShellCleanupOwner(helper_module=config.snapshot_root / "oc_openai/shell_cleanup_owner.py")
    owner.start()
    export_verified = False
    cleanup_result = {"cleanup_verified": False}
    agent_rc = 1
    try:
        jspec = JournalSpec(
            run_id=run_id,
            instance=instance_name,
            pod_name=f"oc-{instance_name}",
            volume_name=f"oc-{instance_name}-openai-home",
            sandbox_dir=sandbox_dir,
            cwd=cwd,
            level=level,
            agent_image_id=agent_image_id,
            journal_path=evidence_dir / f"owner-{run_id}.json",
        )
        created = owner.create(
            spec=jspec,
            lock_helper=config.snapshot_root / "oc-setup-lock.py",
            state_dir=state_dir,
        )
        spec = build_driver_session_spec(jspec, relay_image_id=relay_image_id, ui_mode=config.ui_mode)
        proof_adapter = OpenAISessionAdapter(backend, proof_gate=proof_gate)
        pty_outcome = {"reply_observed": False}

        def _run_agent(aid, ev, arm_fn):
            session_stop["event"] = ev
            return _drive_agent_pty(aid, ev, proof_gate, arm_fn, outcome=pty_outcome)

        proof_options = ProofSessionOptions(
            proof_gate=proof_gate,
            preconfirmed_plan=plan,
            agent_runner=_run_agent,
            on_session_root_created=owner.register_session_root,
            on_slot_prepare=owner.prepare_slot,
            on_slot_begin=owner.begin_slot_create,
            on_slot_finish=owner.finish_slot_create,
            on_slot_lease_released=owner.mark_lease_released,
        )
        agent_rc = run_interactive_session(
            spec,
            terminal,
            adapters={"openai": proof_adapter},
            lock_dir=exposure_dir,
            proof_options=proof_options,
        )
        settled_verified = proof_gate.exact_ok_delivered and proof_gate.verify_settled_evidence()
        if settled_verified:
            export_verified = inspect_session_export(
                volume_name=str(created["volume_name"]),
                level=level,
                cwd=cwd,
                agent_image_id=agent_image_id,
            )
    finally:
        cleanup_result = owner.teardown()

    history_digest_after = compute_locked_exposure_digest(exposure_dir)
    receipts_unchanged = hmac.compare_digest(history_digest_before, history_digest_after)
    cleanup_verified = bool(cleanup_result.get("cleanup_verified"))
    settled_on_disk = proof_gate.exact_ok_delivered and proof_gate.verify_settled_evidence()
    tui_reply_observed = bool(pty_outcome.get("reply_observed"))
    overall_ok = (
        agent_rc == 0
        and proof_gate.admitted_writes == 1
        and settled_on_disk
        and tui_reply_observed
        and export_verified
        and cleanup_verified
        and receipts_unchanged
    )
    return ShellLiveResult(
        ok=overall_ok,
        run_id=run_id,
        ui_mode=config.ui_mode,
        instance_label=config.instance_label,
        model=config.model,
        admitted_writes=proof_gate.admitted_writes,
        exact_ok_delivered=settled_on_disk,
        export_verified=export_verified,
        cleanup_verified=cleanup_verified,
        receipt_history_unchanged=receipts_unchanged,
        agent_rc=agent_rc,
        evidence_path=str(proof_gate.evidence_path or evidence_dir),
        tui_reply_observed=tui_reply_observed,
    )
