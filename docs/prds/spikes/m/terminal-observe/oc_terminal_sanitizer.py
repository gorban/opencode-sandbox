"""Stateful streaming VT/UTF-8 terminal output sanitizer for PRD M3.3.

Implements a strict default-deny 7-state byte-stream FSM with O(1) bounded
parser memory, RFC 3629 strict UTF-8 decoding (in both GROUND and OSC/DCS
string payloads), raw and UTF-8 C1 control neutralization, CRLF/bare-CR
normalization, closed SAFE_SGR allowlisting, and 8-slot cross-frame SGR
state closure.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import re
import sys

_TERMINAL_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _TERMINAL_DIR.parent
for _import_dir in (str(_TERMINAL_DIR), str(_SPIKE_M_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_address import _BIDI_CODEPOINTS  # noqa: E402
from oc_coord_contract import CoordValidationError  # noqa: E402
from oc_terminal_contract import (  # noqa: E402
    MAX_ESC_SEQ_BYTES,
    MAX_FEED_CHUNK_BYTES,
    MAX_SAFE_SGR_PARAM_BYTES,
    MAX_SAFE_SGR_PARAMS,
    MAX_SAFE_SGR_VALUE,
    SanitizerMode,
    SanitizerStats,
    validate_sanitizer_mode,
)

SGR_RESET = "\x1b[0m"
_SGR_RESET_SHORT = "\x1b[m"
_SGR_RESET_LEN = len(SGR_RESET.encode("utf-8"))
_SGR_SEQ_RE = re.compile(r"\x1b\[([0-9;]*)m", re.ASCII)

_C1_INTRODUCER_BYTES: frozenset[int] = frozenset({0x90, 0x98, 0x9B, 0x9D, 0x9E, 0x9F})
_STRING_SEQ_ESC_FINALS: frozenset[int] = frozenset({0x50, 0x58, 0x5E, 0x5F})
_STRING_SEQ_C1_BYTES: frozenset[int] = frozenset({0x90, 0x98, 0x9E, 0x9F})

_BASIC_SAFE_SGR_CODES: frozenset[int] = frozenset(
    {0, 1, 2, 3, 4, 7, 9, 22, 23, 24, 27, 29, 39, 49}
    | set(range(30, 38))
    | set(range(40, 48))
    | set(range(90, 98))
    | set(range(100, 108))
)

_SGR_BOOL_ON_ATTR: dict[int, str] = {
    1: "bold",
    2: "faint",
    3: "italic",
    4: "underline",
    7: "inverse",
    9: "strike",
}
_SGR_BOOL_OFF_ATTR: dict[int, str] = {
    23: "italic",
    24: "underline",
    27: "inverse",
    29: "strike",
}
_SGR_BOOL_ORDER: tuple[tuple[str, str], ...] = (
    ("bold", "1"),
    ("faint", "2"),
    ("italic", "3"),
    ("underline", "4"),
    ("inverse", "7"),
    ("strike", "9"),
)

_K_UTF8 = "utf-8"
_REPLACEMENT_CHAR = "\ufffd"


class _State(Enum):
    GROUND = "ground"
    UTF8_PENDING = "utf8_pending"
    ESC = "esc"
    ESC_INTERMEDIATE = "esc_intermediate"
    CSI = "csi"
    OSC = "osc"
    STRING_SEQ = "string_seq"


@dataclass(slots=True)
class _MutableStats:
    input_bytes: int = 0
    output_bytes: int = 0
    dropped_osc_count: int = 0
    dropped_csi_count: int = 0
    dropped_string_seq_count: int = 0
    dropped_esc_count: int = 0
    dropped_c0_c1_count: int = 0
    dropped_bidi_count: int = 0
    invalid_utf8_count: int = 0
    overlong_seq_dropped_count: int = 0
    neutralized_bare_cr_count: int = 0
    allowed_sgr_count: int = 0

    def freeze(self) -> SanitizerStats:
        return SanitizerStats(
            input_bytes=self.input_bytes,
            output_bytes=self.output_bytes,
            dropped_osc_count=self.dropped_osc_count,
            dropped_csi_count=self.dropped_csi_count,
            dropped_string_seq_count=self.dropped_string_seq_count,
            dropped_esc_count=self.dropped_esc_count,
            dropped_c0_c1_count=self.dropped_c0_c1_count,
            dropped_bidi_count=self.dropped_bidi_count,
            invalid_utf8_count=self.invalid_utf8_count,
            overlong_seq_dropped_count=self.overlong_seq_dropped_count,
            neutralized_bare_cr_count=self.neutralized_bare_cr_count,
            allowed_sgr_count=self.allowed_sgr_count,
        )


@dataclass(slots=True)
class _SgrState:
    """O(1) 8-slot active SGR attribute tracker for self-contained SAFE_SGR frames."""

    bold: bool = False
    faint: bool = False
    italic: bool = False
    underline: bool = False
    inverse: bool = False
    strike: bool = False
    fg: str | None = None
    bg: str | None = None

    def reset(self) -> None:
        self.bold = False
        self.faint = False
        self.italic = False
        self.underline = False
        self.inverse = False
        self.strike = False
        self.fg = None
        self.bg = None

    def _apply_color_code(self, code: int) -> None:
        if code == 39:
            self.fg = None
            return
        if code == 49:
            self.bg = None
            return
        if (30 <= code <= 37) or (90 <= code <= 97):
            self.fg = str(code)
            return
        if (40 <= code <= 47) or (100 <= code <= 107):
            self.bg = str(code)

    def _apply_simple_code(self, code: int) -> None:
        if code == 0:
            self.reset()
            return
        if code == 22:
            self.bold = False
            self.faint = False
            return
        if code in _SGR_BOOL_ON_ATTR:
            setattr(self, _SGR_BOOL_ON_ATTR[code], True)
            return
        if code in _SGR_BOOL_OFF_ATTR:
            setattr(self, _SGR_BOOL_OFF_ATTR[code], False)
            return
        self._apply_color_code(code)

    def apply_codes(self, codes: list[int]) -> None:
        idx = 0
        total = len(codes)
        while idx < total:
            code = codes[idx]
            if code in (38, 48) and idx + 2 < total and codes[idx + 1] == 5:
                val = f"{code};5;{codes[idx + 2]}"
                if code == 38:
                    self.fg = val
                else:
                    self.bg = val
                idx += 3
                continue
            self._apply_simple_code(code)
            idx += 1

    def is_open(self) -> bool:
        return (
            self.bold
            or self.faint
            or self.italic
            or self.underline
            or self.inverse
            or self.strike
            or self.fg is not None
            or self.bg is not None
        )

    def to_sgr_seq(self) -> str:
        parts = [code for attr, code in _SGR_BOOL_ORDER if getattr(self, attr)]
        if self.fg is not None:
            parts.append(self.fg)
        if self.bg is not None:
            parts.append(self.bg)
        if not parts:
            return ""
        return f"\x1b[{';'.join(parts)}m"


def _utf8_lead_spec(byte: int) -> tuple[int, int, int] | None:
    """Return (total_bytes, min_second, max_second) per RFC 3629, or None if invalid."""
    if 0xC2 <= byte <= 0xDF:
        return (2, 0x80, 0xBF)
    if byte == 0xE0:
        return (3, 0xA0, 0xBF)
    if (0xE1 <= byte <= 0xEC) or (0xEE <= byte <= 0xEF):
        return (3, 0x80, 0xBF)
    if byte == 0xED:
        return (3, 0x80, 0x9F)
    if byte == 0xF0:
        return (4, 0x90, 0xBF)
    if 0xF1 <= byte <= 0xF3:
        return (4, 0x80, 0xBF)
    if byte == 0xF4:
        return (4, 0x80, 0x8F)
    return None


def _parse_sgr_tokens(raw_params: bytes) -> list[int] | None:
    if len(raw_params) > MAX_SAFE_SGR_PARAM_BYTES or not raw_params.isascii():
        return None
    if not raw_params:
        return [0]
    tokens = raw_params.decode("ascii").split(";")
    if len(tokens) > MAX_SAFE_SGR_PARAMS:
        return None
    nums: list[int] = []
    for tok in tokens:
        if not (1 <= len(tok) <= 3) or not tok.isdigit():
            return None
        val = int(tok)
        if val > MAX_SAFE_SGR_VALUE:
            return None
        nums.append(val)
    return nums


def parse_allowed_safe_sgr(raw_params: bytes) -> list[int] | None:
    """Validate closed SAFE_SGR parameter bytes, returning parsed codes or None."""
    nums = _parse_sgr_tokens(raw_params)
    if nums is None:
        return None
    idx = 0
    total = len(nums)
    while idx < total:
        code = nums[idx]
        if code in _BASIC_SAFE_SGR_CODES:
            idx += 1
            continue
        if code in (38, 48):
            if idx + 2 >= total or nums[idx + 1] != 5 or nums[idx + 2] > MAX_SAFE_SGR_VALUE:
                return None
            idx += 3
            continue
        return None
    return nums


class TerminalOutputSanitizer:
    """Stateful streaming VT/UTF-8 sanitizer with O(1) parser buffers."""

    def __init__(self, *, mode: SanitizerMode = SanitizerMode.PLAIN) -> None:
        self._mode = validate_sanitizer_mode(mode)
        self._state = _State.GROUND
        self._pending_cr = False
        self._utf8_buf = bytearray()
        self._utf8_expected = 0
        self._utf8_min_next = 0x80
        self._utf8_max_next = 0xBF
        self._csi_buf = bytearray()
        self._csi_valid = False
        self._csi_has_intermediate = False
        self._from_c1 = False
        self._seq_bytes = 0
        self._seq_overlong = False
        self._seq_counted = False
        self._esc_seen = False
        self._str_utf8_rem = 0
        self._str_utf8_min = 0x80
        self._str_utf8_max = 0xBF
        self._str_utf8_is_c2 = False
        self._sgr_state = _SgrState()
        self._stats = _MutableStats()
        self._state_handlers = {
            _State.GROUND: self._handle_ground,
            _State.UTF8_PENDING: self._handle_utf8_pending,
            _State.ESC: self._handle_esc,
            _State.ESC_INTERMEDIATE: self._handle_esc_intermediate,
            _State.CSI: self._handle_csi,
            _State.OSC: self._handle_string_seq,
            _State.STRING_SEQ: self._handle_string_seq,
        }

    @property
    def mode(self) -> SanitizerMode:
        return self._mode

    @property
    def stats(self) -> SanitizerStats:
        return self._stats.freeze()

    @property
    def active_sgr_seq(self) -> str:
        """Canonical active SGR sequence (<= 34 B) or '' when in default style / PLAIN mode."""
        if self._mode is not SanitizerMode.SAFE_SGR:
            return ""
        return self._sgr_state.to_sgr_seq()

    @property
    def parser_buffer_bytes(self) -> int:
        """Current internal parser byte buffer occupancy (always bounded O(1))."""
        return len(self._utf8_buf) + len(self._csi_buf)

    def reset(self) -> None:
        """Reset FSM, buffers, SGR state, and stats to clean ground state."""
        self._state = _State.GROUND
        self._pending_cr = False
        self._clear_utf8_state()
        self._reset_seq_state()
        self._sgr_state.reset()
        self._stats = _MutableStats()

    def _clear_utf8_state(self) -> None:
        self._utf8_buf.clear()
        self._utf8_expected = 0
        self._utf8_min_next = 0x80
        self._utf8_max_next = 0xBF

    def _clear_str_utf8_state(self) -> None:
        self._str_utf8_rem = 0
        self._str_utf8_min = 0x80
        self._str_utf8_max = 0xBF
        self._str_utf8_is_c2 = False

    def _reset_seq_state(self) -> None:
        self._csi_buf.clear()
        self._csi_valid = False
        self._csi_has_intermediate = False
        self._from_c1 = False
        self._seq_bytes = 0
        self._seq_overlong = False
        self._seq_counted = False
        self._esc_seen = False
        self._clear_str_utf8_state()

    def _increment_active_drop_counter(self) -> None:
        if self._seq_counted:
            return
        self._seq_counted = True
        if self._state is _State.OSC:
            self._stats.dropped_osc_count += 1
        elif self._state is _State.STRING_SEQ:
            self._stats.dropped_string_seq_count += 1
        elif self._state is _State.CSI:
            self._stats.dropped_csi_count += 1
        elif self._state in (_State.ESC, _State.ESC_INTERMEDIATE):
            self._stats.dropped_esc_count += 1

    def _charge_seq_bytes(self, count: int = 1) -> None:
        self._seq_bytes += count
        if self._seq_bytes > MAX_ESC_SEQ_BYTES and not self._seq_overlong:
            self._seq_overlong = True
            self._csi_valid = False
            self._csi_buf.clear()
            self._stats.overlong_seq_dropped_count += 1
            self._increment_active_drop_counter()

    def _enter_esc(self) -> None:
        self._reset_seq_state()
        self._state = _State.ESC
        self._seq_bytes = 1

    def _enter_csi(self, *, from_c1: bool, initial_bytes: int) -> None:
        self._reset_seq_state()
        self._state = _State.CSI
        self._from_c1 = from_c1
        self._csi_valid = (not from_c1) and (self._mode is SanitizerMode.SAFE_SGR)
        self._seq_bytes = initial_bytes

    def _enter_string_state(
        self, state: _State, *, from_c1: bool, initial_bytes: int
    ) -> None:
        self._reset_seq_state()
        self._state = state
        self._from_c1 = from_c1
        self._seq_bytes = initial_bytes

    def _dispatch_c1_byte(self, byte: int, *, initial_bytes: int) -> None:
        self._stats.dropped_c0_c1_count += 1
        if byte == 0x9B:
            self._enter_csi(from_c1=True, initial_bytes=initial_bytes)
        elif byte == 0x9D:
            self._enter_string_state(_State.OSC, from_c1=True, initial_bytes=initial_bytes)
        elif byte in _STRING_SEQ_C1_BYTES:
            self._enter_string_state(
                _State.STRING_SEQ, from_c1=True, initial_bytes=initial_bytes
            )

    def _handle_ground_byte(self, byte: int, out: list[str]) -> None:
        if byte == 0x0D:
            self._pending_cr = True
            return
        if byte in (0x09, 0x0A) or 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
            return
        if byte == 0x1B:
            self._enter_esc()
            return
        if byte < 0x20 or byte == 0x7F:
            self._stats.dropped_c0_c1_count += 1
            return
        if 0x80 <= byte <= 0x9F:
            self._dispatch_c1_byte(byte, initial_bytes=1)
            return
        spec = _utf8_lead_spec(byte)
        if spec is None:
            out.append(_REPLACEMENT_CHAR)
            self._stats.invalid_utf8_count += 1
            return
        self._utf8_buf.clear()
        self._utf8_buf.append(byte)
        self._utf8_expected, self._utf8_min_next, self._utf8_max_next = spec
        self._state = _State.UTF8_PENDING

    def _handle_ground(self, byte: int, out: list[str]) -> None:
        if self._pending_cr:
            self._pending_cr = False
            if byte == 0x0A:
                out.append("\n")
                return
            out.append("\n")
            self._stats.neutralized_bare_cr_count += 1
            self._stats.dropped_c0_c1_count += 1
        self._handle_ground_byte(byte, out)

    def _handle_utf8_pending(self, byte: int, out: list[str]) -> None:
        if not (self._utf8_min_next <= byte <= self._utf8_max_next):
            out.append(_REPLACEMENT_CHAR)
            self._stats.invalid_utf8_count += 1
            self._clear_utf8_state()
            self._state = _State.GROUND
            self._handle_ground_byte(byte, out)
            return
        self._utf8_buf.append(byte)
        self._utf8_min_next = 0x80
        self._utf8_max_next = 0xBF
        if len(self._utf8_buf) < self._utf8_expected:
            return
        ch = self._utf8_buf.decode(_K_UTF8)
        cp = ord(ch)
        self._clear_utf8_state()
        self._state = _State.GROUND
        if 0x80 <= cp <= 0x9F:
            self._dispatch_c1_byte(cp, initial_bytes=2)
        elif cp in _BIDI_CODEPOINTS:
            self._stats.dropped_bidi_count += 1
        else:
            out.append(ch)

    def _promote_esc_to_csi(self) -> None:
        had_padding = self._seq_bytes > 1
        self._state = _State.CSI
        self._from_c1 = False
        self._csi_buf.clear()
        self._csi_has_intermediate = False
        self._csi_valid = (
            (not had_padding)
            and (not self._seq_overlong)
            and (self._mode is SanitizerMode.SAFE_SGR)
        )
        self._charge_seq_bytes(1)

    def _promote_esc_to_string(self, state: _State) -> None:
        self._state = state
        self._from_c1 = False
        self._esc_seen = False
        self._clear_str_utf8_state()
        self._charge_seq_bytes(1)

    def _handle_esc(self, byte: int, out: list[str]) -> None:
        if byte == 0x5B:
            self._promote_esc_to_csi()
            return
        if byte == 0x5D:
            self._promote_esc_to_string(_State.OSC)
            return
        if byte in _STRING_SEQ_ESC_FINALS:
            self._promote_esc_to_string(_State.STRING_SEQ)
            return
        if 0x20 <= byte <= 0x2F:
            self._state = _State.ESC_INTERMEDIATE
            self._charge_seq_bytes(1)
            return
        if 0x30 <= byte <= 0x7E:
            self._charge_seq_bytes(1)
            self._increment_active_drop_counter()
            self._reset_seq_state()
            self._state = _State.GROUND
            return
        if byte == 0x1B:
            self._increment_active_drop_counter()
            self._enter_esc()
            return
        if byte in (0x18, 0x1A):
            self._increment_active_drop_counter()
            self._stats.dropped_c0_c1_count += 1
            self._reset_seq_state()
            self._state = _State.GROUND
            return
        if byte < 0x20 or byte == 0x7F:
            self._charge_seq_bytes(1)
            self._stats.dropped_c0_c1_count += 1
            return
        self._increment_active_drop_counter()
        self._reset_seq_state()
        self._state = _State.GROUND
        self._handle_ground_byte(byte, out)

    def _handle_esc_intermediate(self, byte: int, out: list[str]) -> None:
        if 0x20 <= byte <= 0x2F:
            self._charge_seq_bytes(1)
            return
        if 0x30 <= byte <= 0x7E:
            self._charge_seq_bytes(1)
            self._increment_active_drop_counter()
            self._reset_seq_state()
            self._state = _State.GROUND
            return
        if byte == 0x1B:
            self._increment_active_drop_counter()
            self._enter_esc()
            return
        if byte in (0x18, 0x1A):
            self._increment_active_drop_counter()
            self._stats.dropped_c0_c1_count += 1
            self._reset_seq_state()
            self._state = _State.GROUND
            return
        if byte < 0x20 or byte == 0x7F:
            self._charge_seq_bytes(1)
            self._stats.dropped_c0_c1_count += 1
            return
        self._increment_active_drop_counter()
        self._reset_seq_state()
        self._state = _State.GROUND
        self._handle_ground_byte(byte, out)

    def _finish_csi(self, final_byte: int, out: list[str]) -> None:
        self._charge_seq_bytes(1)
        allowed_codes = (
            parse_allowed_safe_sgr(bytes(self._csi_buf))
            if (
                self._csi_valid
                and final_byte == 0x6D
                and not self._from_c1
                and not self._seq_overlong
            )
            else None
        )
        if allowed_codes is not None:
            params_text = self._csi_buf.decode("ascii")
            out.append(f"\x1b[{params_text}m")
            self._sgr_state.apply_codes(allowed_codes)
            self._stats.allowed_sgr_count += 1
        else:
            self._increment_active_drop_counter()
        self._reset_seq_state()
        self._state = _State.GROUND

    def _handle_csi_param_byte(self, byte: int) -> None:
        self._charge_seq_bytes(1)
        is_sgr_char = (0x30 <= byte <= 0x39) or byte == 0x3B
        if (
            self._csi_valid
            and not self._csi_has_intermediate
            and is_sgr_char
            and len(self._csi_buf) < MAX_SAFE_SGR_PARAM_BYTES
        ):
            self._csi_buf.append(byte)
        else:
            self._csi_valid = False
            self._csi_buf.clear()

    def _handle_csi(self, byte: int, out: list[str]) -> None:
        if 0x30 <= byte <= 0x3F:
            self._handle_csi_param_byte(byte)
            return
        if 0x20 <= byte <= 0x2F:
            self._charge_seq_bytes(1)
            self._csi_has_intermediate = True
            self._csi_valid = False
            self._csi_buf.clear()
            return
        if 0x40 <= byte <= 0x7E:
            self._finish_csi(byte, out)
            return
        if byte == 0x1B:
            self._increment_active_drop_counter()
            self._enter_esc()
            return
        if byte in (0x18, 0x1A):
            self._increment_active_drop_counter()
            self._stats.dropped_c0_c1_count += 1
            self._reset_seq_state()
            self._state = _State.GROUND
            return
        if byte < 0x20 or byte == 0x7F:
            self._charge_seq_bytes(1)
            self._csi_valid = False
            self._csi_buf.clear()
            self._stats.dropped_c0_c1_count += 1
            return
        self._increment_active_drop_counter()
        self._reset_seq_state()
        self._state = _State.GROUND
        self._handle_ground_byte(byte, out)

    def _close_string_seq(self) -> None:
        self._increment_active_drop_counter()
        self._reset_seq_state()
        self._state = _State.GROUND

    def _handle_string_c2_second(self, byte: int) -> None:
        self._str_utf8_is_c2 = False
        if byte == 0x9C:
            self._charge_seq_bytes(2)
            self._close_string_seq()
            return
        if byte in _C1_INTRODUCER_BYTES:
            self._close_string_seq()
            self._dispatch_c1_byte(byte, initial_bytes=2)
            return
        self._charge_seq_bytes(2)

    def _handle_string_utf8_cont(self, byte: int, out: list[str]) -> None:
        if self._str_utf8_min <= byte <= self._str_utf8_max:
            self._str_utf8_rem -= 1
            self._str_utf8_min = 0x80
            self._str_utf8_max = 0xBF
            if self._str_utf8_is_c2:
                self._handle_string_c2_second(byte)
            else:
                self._charge_seq_bytes(1)
            return
        if self._str_utf8_is_c2:
            self._charge_seq_bytes(1)
        self._clear_str_utf8_state()
        self._handle_string_normal(byte, out)

    def _handle_string_normal(self, byte: int, out: list[str]) -> None:
        if byte in _C1_INTRODUCER_BYTES:
            self._close_string_seq()
            self._handle_ground_byte(byte, out)
            return
        if byte == 0x07 and self._state is _State.OSC:
            self._charge_seq_bytes(1)
            self._close_string_seq()
            return
        if byte == 0x9C:
            self._charge_seq_bytes(1)
            self._close_string_seq()
            return
        if byte in (0x18, 0x1A):
            self._charge_seq_bytes(1)
            self._stats.dropped_c0_c1_count += 1
            self._close_string_seq()
            return
        if byte == 0x1B:
            self._esc_seen = True
            return
        spec = _utf8_lead_spec(byte)
        if spec is not None:
            total, min_next, max_next = spec
            if byte != 0xC2:
                self._charge_seq_bytes(1)
            self._str_utf8_rem = total - 1
            self._str_utf8_min = min_next
            self._str_utf8_max = max_next
            self._str_utf8_is_c2 = byte == 0xC2
            return
        self._charge_seq_bytes(1)

    def _handle_string_seq(self, byte: int, out: list[str]) -> None:
        if self._esc_seen:
            self._esc_seen = False
            if byte == 0x5C:
                self._charge_seq_bytes(2)
                self._close_string_seq()
            else:
                self._increment_active_drop_counter()
                self._enter_esc()
                self._handle_esc(byte, out)
            return
        if self._str_utf8_rem > 0:
            self._handle_string_utf8_cont(byte, out)
            return
        self._handle_string_normal(byte, out)

    def _step_byte(self, byte: int, out: list[str]) -> None:
        self._state_handlers[self._state](byte, out)

    def feed(self, chunk: bytes) -> str:
        """Sanitize a raw byte chunk, preserving streaming FSM state across calls."""
        if not isinstance(chunk, bytes):
            raise CoordValidationError("chunk must be bytes")
        if len(chunk) > MAX_FEED_CHUNK_BYTES:
            raise CoordValidationError("chunk exceeds MAX_FEED_CHUNK_BYTES")
        self._stats.input_bytes += len(chunk)
        out: list[str] = []
        for byte in chunk:
            self._step_byte(byte, out)
        text = "".join(out)
        self._stats.output_bytes += len(text.encode(_K_UTF8))
        return text

    def flush(self) -> str:
        """Finalize pending CR, UTF-8, or unterminated escape state at EOF (idempotent)."""
        out: list[str] = []
        if self._pending_cr:
            self._pending_cr = False
            out.append("\n")
            self._stats.neutralized_bare_cr_count += 1
            self._stats.dropped_c0_c1_count += 1
        if self._state is _State.UTF8_PENDING:
            self._clear_utf8_state()
            self._state = _State.GROUND
            out.append(_REPLACEMENT_CHAR)
            self._stats.invalid_utf8_count += 1
        elif self._state is not _State.GROUND:
            if self._state in (_State.OSC, _State.STRING_SEQ) and (
                self._esc_seen or self._str_utf8_is_c2
            ):
                self._charge_seq_bytes(1)
            self._increment_active_drop_counter()
            self._reset_seq_state()
            self._state = _State.GROUND
        text = "".join(out)
        self._stats.output_bytes += len(text.encode(_K_UTF8))
        return text


def diff_sanitizer_stats(before: SanitizerStats, after: SanitizerStats) -> SanitizerStats:
    """Compute per-frame delta between two cumulative SanitizerStats snapshots."""
    return SanitizerStats(
        input_bytes=after.input_bytes - before.input_bytes,
        output_bytes=after.output_bytes - before.output_bytes,
        dropped_osc_count=after.dropped_osc_count - before.dropped_osc_count,
        dropped_csi_count=after.dropped_csi_count - before.dropped_csi_count,
        dropped_string_seq_count=after.dropped_string_seq_count - before.dropped_string_seq_count,
        dropped_esc_count=after.dropped_esc_count - before.dropped_esc_count,
        dropped_c0_c1_count=after.dropped_c0_c1_count - before.dropped_c0_c1_count,
        dropped_bidi_count=after.dropped_bidi_count - before.dropped_bidi_count,
        invalid_utf8_count=after.invalid_utf8_count - before.invalid_utf8_count,
        overlong_seq_dropped_count=(
            after.overlong_seq_dropped_count - before.overlong_seq_dropped_count
        ),
        neutralized_bare_cr_count=(
            after.neutralized_bare_cr_count - before.neutralized_bare_cr_count
        ),
        allowed_sgr_count=after.allowed_sgr_count - before.allowed_sgr_count,
    )


def sgr_is_open(text: str) -> bool:
    """Return True iff sanitized SAFE_SGR text ends with any active SGR attribute."""
    if "\x1b[" not in text:
        return False
    state = _SgrState()
    for match in _SGR_SEQ_RE.finditer(text):
        codes = parse_allowed_safe_sgr(match.group(1).encode("ascii"))
        if codes is not None:
            state.apply_codes(codes)
    return state.is_open()


def back_up_mid_sgr(prefix: str, mode: SanitizerMode) -> str:
    """Back up a SAFE_SGR prefix before any dangling incomplete ESC[... sequence."""
    if mode is not SanitizerMode.SAFE_SGR:
        return prefix
    last_esc = prefix.rfind("\x1b")
    if last_esc == -1:
        return prefix
    if "m" not in prefix[last_esc:]:
        return prefix[:last_esc]
    return prefix


def wrap_self_contained_sgr_frame(
    text: str,
    prefix_sgr: str,
    sgr_open_end: bool,
    *,
    mode: SanitizerMode,
) -> str:
    """Wrap a non-empty SAFE_SGR chunk so every stored frame starts and ends in default style."""
    if mode is not SanitizerMode.SAFE_SGR or not text:
        return text
    result = text
    if prefix_sgr and not result.startswith((SGR_RESET, _SGR_RESET_SHORT)):
        result = f"{prefix_sgr}{result}"
    if sgr_open_end:
        result = f"{result}{SGR_RESET}"
    return result


def _cut_utf8_prefix(raw: bytes, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    end = min(len(raw), max_bytes)
    if end < len(raw):
        while end > 0 and (raw[end] & 0xC0) == 0x80:
            end -= 1
    return raw[:end].decode(_K_UTF8)


def truncate_sanitized_text_utf8(
    text: str,
    max_bytes: int,
    *,
    mode: SanitizerMode,
) -> tuple[str, int, bool]:
    """Truncate sanitized text to <= max_bytes UTF-8 without splitting UTF-8 or SGRs."""
    validate_sanitizer_mode(mode)
    raw = text.encode(_K_UTF8)
    if len(raw) <= max_bytes:
        return text, len(raw), False
    prefix = back_up_mid_sgr(_cut_utf8_prefix(raw, max_bytes), mode)
    if mode is SanitizerMode.SAFE_SGR and sgr_is_open(prefix):
        short = back_up_mid_sgr(_cut_utf8_prefix(raw, max_bytes - _SGR_RESET_LEN), mode)
        prefix = f"{short}{SGR_RESET}" if sgr_is_open(short) else short
    return prefix, len(prefix.encode(_K_UTF8)), True


def sanitize_bytes(
    data: bytes,
    *,
    mode: SanitizerMode = SanitizerMode.PLAIN,
) -> tuple[str, SanitizerStats]:
    """Sanitize a complete byte payload through a fresh sanitizer and flush."""
    sanitizer = TerminalOutputSanitizer(mode=mode)
    out = sanitizer.feed(data) + sanitizer.flush()
    return out, sanitizer.stats


def sanitize_text_str(
    text: str,
    *,
    mode: SanitizerMode = SanitizerMode.PLAIN,
) -> tuple[str, SanitizerStats]:
    """Sanitize a Python string (neutralizing lone surrogates via surrogatepass + RFC 3629)."""
    if not isinstance(text, str):
        raise CoordValidationError("text must be str")
    if len(text) > MAX_FEED_CHUNK_BYTES:
        raise CoordValidationError("text exceeds MAX_FEED_CHUNK_BYTES")
    return sanitize_bytes(text.encode(_K_UTF8, errors="surrogatepass"), mode=mode)
