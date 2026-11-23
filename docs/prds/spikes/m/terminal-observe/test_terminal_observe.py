"""Offline red-team and qualification suite for PRD M3.3 terminal-observe.

Runs completely offline with pure Python stdlib plus read-only imports from
docs/prds/spikes/m/. Zero live PTYs, zero Podman, zero network, zero host
filesystem writes.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import unittest
from typing import Any

_TERMINAL_DIR = Path(__file__).resolve().parent
_SPIKE_M_DIR = _TERMINAL_DIR.parent
for _import_dir in (str(_TERMINAL_DIR), str(_SPIKE_M_DIR)):
    if _import_dir not in sys.path:
        sys.path.insert(0, _import_dir)

from oc_address import _BIDI_CODEPOINTS  # noqa: E402
from oc_coord_contract import (  # noqa: E402
    CoordAuthError,
    CoordPolicyError,
    CoordRole,
    CoordValidationError,
    IncarnationMismatchError,
    PrincipalCtx,
    RevokedError,
)
from oc_terminal_contract import (  # noqa: E402
    CURSOR_PREFIX,
    ERR_BUDGET_ENVELOPE,
    ERR_BUDGET_ITEM,
    ERR_CURSOR_MALFORMED,
    ERR_CURSOR_SCOPE_MISMATCH,
    MAX_CURSOR_BYTES,
    MAX_ESC_SEQ_BYTES,
    MAX_FEED_CHUNK_BYTES,
    MAX_FRAME_TEXT_BYTES,
    MAX_INT64,
    MAX_RETIRED_INCARNATIONS,
    MAX_SAFE_SGR_PARAM_BYTES,
    MAX_TRACKED_SANDBOXES,
    MIN_RESPONSE_BYTES,
    OP_TERMINAL_REPLAY,
    SanitizerMode,
    SanitizerStats,
    compute_replay_scope_hash,
    decode_replay_cursor,
    encode_replay_cursor,
    parse_terminal_target,
    serialize_terminal_bytes,
    serialize_terminal_json,
)
from oc_terminal_replay import (  # noqa: E402
    ERR_AUTHORITY_REVOKED,
    ERR_CLOSE_PAIR_REQUIRED,
    ERR_MAX_RETIRED,
    ERR_MAX_SANDBOXES,
    ERR_NON_MONOTONIC_SEQ,
    ERR_OPERATOR_REQUIRED,
    ERR_OPERATOR_UNBOUND,
    ERR_RETIRED_REUSED,
    ERR_SESSION_PAIR_REQUIRED,
    ERR_SESSION_REQUIRED,
    ERR_SESSION_RETIRED,
    ERR_SESSION_VALIDATOR_UNCONFIGURED,
    ERR_STALE_EPOCH,
    ERR_STALE_INCARNATION,
    ERR_STREAM_CLOSED,
    ERR_STREAM_NOT_FOUND,
    ERR_STREAM_NOT_REGISTERED,
    ERR_UNREGISTERED_EPOCH,
    TerminalReplayStore,
)
from oc_terminal_sanitizer import (  # noqa: E402
    SGR_RESET,
    TerminalOutputSanitizer,
    sanitize_bytes,
    sanitize_text_str,
    sgr_is_open,
    truncate_sanitized_text_utf8,
)

_TUI = "opencode-tui"
_SHELL = "shell"
_TARGET_LOCAL = "feat-alpha"
_TARGET_REMOTE = "mac-mini / feat-alpha"
_INC_1 = "inc:0001"
_INC_2 = "inc:0002"
_SESS_1 = "sess_operator_01"
_UTF8 = "utf-8"

_OPERATOR = PrincipalCtx(role=CoordRole.OPERATOR, actor_id="op_human")
_JOB_CALLER = PrincipalCtx(
    role=CoordRole.JOB,
    actor_id="job_1",
    sandbox_addr=_TARGET_LOCAL,
    incarnation_id=_INC_1,
)
_ROOT_ORCH = PrincipalCtx(role=CoordRole.ORCHESTRATOR, actor_id="orch_root")
_BOUND_ORCH = PrincipalCtx(
    role=CoordRole.ORCHESTRATOR,
    actor_id="orch_sub",
    sandbox_addr=_TARGET_LOCAL,
    incarnation_id=_INC_1,
)
_PEER_CALLER = PrincipalCtx(role=CoordRole.EXTERNAL_PEER, actor_id="peer_ext")
_BOUND_OPERATOR = PrincipalCtx(
    role=CoordRole.OPERATOR,
    actor_id="op_bad",
    sandbox_addr=_TARGET_LOCAL,
    incarnation_id=_INC_1,
)


def _feed_chunked(
    data: bytes, chunk_size: int, *, mode: SanitizerMode = SanitizerMode.PLAIN
) -> tuple[str, SanitizerStats]:
    san = TerminalOutputSanitizer(mode=mode)
    parts: list[str] = []
    for idx in range(0, len(data), chunk_size):
        parts.append(san.feed(data[idx : idx + chunk_size]))
    parts.append(san.flush())
    return "".join(parts), san.stats


class _NoEncodeStr(str):
    """Test double verifying O(1) length/syntax checks run before UTF-8 encoding."""

    def encode(self, encoding: str = _UTF8, errors: str = "strict") -> bytes:
        raise AssertionError("encode() must not be called on oversized or invalid input")


def _b64url_cursor(raw_json: bytes) -> str:
    encoded = base64.urlsafe_b64encode(raw_json).decode("ascii").rstrip("=")
    return f"{CURSOR_PREFIX}{encoded}"


class TestSanitizerRedTeam(unittest.TestCase):
    """Red-team escape, UTF-8, C1, bidi, bare-CR, and chunk-split tests."""

    def test_osc_family_7bit_8bit_utf8_and_terminators(self) -> None:
        payload = (
            b"A"
            b"\x1b]52;c;c2VjcmV0\x07"
            b"B"
            b"\x1b]8;;https://evil.example\x1b\\click\x1b]8;;\x1b\\"
            b"C"
            b"\x1b]0;Fake Title\x9c"
            b"D"
            b"\x1b]99;i=1:notify\xc2\x9c"
            b"E"
            b"\x9d777;notify;hi;there\x07"
            b"F"
            b"\xc2\x9d10;?\x18"
            b"G"
            b"\x1b]11;rgb:ff/00/00\x1a"
            b"H"
            b"\x1b]2;unterminated\x1b[6n"
            b"I"
        )
        out_full, stats_full = sanitize_bytes(payload)
        out_byte, stats_byte = _feed_chunked(payload, 1)
        self.assertEqual(out_full, "ABclickCDEFGHI")
        self.assertEqual(out_byte, out_full)
        self.assertEqual(stats_byte, stats_full)
        self.assertEqual(stats_full.dropped_osc_count, 9)
        self.assertEqual(stats_full.dropped_csi_count, 1)

    def test_utf8_multibyte_continuations_inside_osc_and_dcs(self) -> None:
        cases = (
            b"A\x1b]0;title\xe2\x80\x9cSPOOF\x07B",
            b"A\x1b]0;title\xe2\x80\x9dSPOOF\x07B",
            b"A\x1b]0;title\xe2\x80\x9b31mSPOOF\x07B",
            b"A\x1b]0;title\xe2\x86\x90SPOOF\x07B",
            b"A\x1b]0;title\xf0\x9f\x9a\x80SPOOF\x07B",
            b"A\x1b]0;title\xc2\xa0kept\x9cB",
            b"A\x1b]0;trunc\xe2\x1b\\B",
            b"A\x1b]0;trunc\xc2\x07B",
        )
        for raw in cases:
            out_full, stats_full = sanitize_bytes(raw, mode=SanitizerMode.SAFE_SGR)
            out_byte, stats_byte = _feed_chunked(raw, 1, mode=SanitizerMode.SAFE_SGR)
            self.assertEqual(out_full, "AB", f"leaked on {raw!r}")
            self.assertEqual(out_byte, "AB")
            self.assertEqual(stats_full, stats_byte)
            self.assertEqual(stats_full.dropped_osc_count, 1)
            self.assertEqual(stats_full.dropped_string_seq_count, 0)

        dcs_raw = b"X\x1bPq\xe2\x80\x9c\xe2\x80\x9b\xf0\x9f\x9a\x80\xe2\x1b\\Y"
        dcs_out, dcs_stats = sanitize_bytes(dcs_raw, mode=SanitizerMode.SAFE_SGR)
        dcs_byte, dcs_bstats = _feed_chunked(dcs_raw, 1, mode=SanitizerMode.SAFE_SGR)
        self.assertEqual(dcs_out, "XY")
        self.assertEqual(dcs_byte, "XY")
        self.assertEqual(dcs_stats, dcs_bstats)
        self.assertEqual(dcs_stats.dropped_string_seq_count, 1)

    def test_string_sequences_dcs_apc_pm_sos(self) -> None:
        payload = (
            b"1"
            b"\x1bPq#0;2;100;100;100\x1b\\"
            b"2"
            b"\x1b_Ga=T,f=100;AAAA\x1b\\"
            b"3"
            b"\x1bPtmux;\x1b\x1b]52;c;xx\x07\x1b\\"
            b"4"
            b"\x1b^private-msg\x9c"
            b"5"
            b"\x1bXstart-of-str\xc2\x9c"
            b"6"
            b"\x90raw-dcs\x9c"
            b"7"
            b"\x98raw-sos\x9c"
            b"8"
            b"\x9eraw-pm\x9c"
            b"9"
            b"\x9fraw-apc\x9c"
            b"0"
            b"\xc2\x90utf8-dcs\xc2\x9c"
            b"!"
        )
        out_full, stats_full = sanitize_bytes(payload)
        out_byte, stats_byte = _feed_chunked(payload, 1)
        self.assertEqual(out_full, "1234567890!")
        self.assertEqual(out_byte, out_full)
        self.assertEqual(stats_byte, stats_full)
        self.assertGreaterEqual(stats_full.dropped_string_seq_count, 10)

    def test_csi_queries_and_modes_dropped_in_both_modes(self) -> None:
        payload = (
            b"start"
            b"\x1b[6n\x1b[c\x1b[>c\x1b[>q"
            b"\x1b[?1049h\x1b[?1049l\x1b[?25l\x1b[?1004h\x1b[?2004h"
            b"\x1b[?1$p\x1b[8;50;100t\x1b[2J\x1b[H\x1b[1A"
            b"\x9b31m\xc2\x9b31m"
            b"end"
        )
        for mode in (SanitizerMode.PLAIN, SanitizerMode.SAFE_SGR):
            out, stats = sanitize_bytes(payload, mode=mode)
            out_b, stats_b = _feed_chunked(payload, 1, mode=mode)
            self.assertEqual(out, "startend")
            self.assertEqual(out_b, "startend")
            self.assertEqual(stats, stats_b)
            self.assertEqual(stats.dropped_csi_count, 16)
            self.assertEqual(stats.allowed_sgr_count, 0)

    def test_esc_fe_fp_fs_and_intermediate_with_nul_draining(self) -> None:
        payload = b"A\x1bcB\x1b7C\x1b8D\x1b(BE\x1b(\x00BF\x1b#8G\x1bDH\x1bMI\x1b\x1bcJ"
        out, stats = sanitize_bytes(payload)
        out_b, stats_b = _feed_chunked(payload, 1)
        self.assertEqual(out, "ABCDEFGHIJ")
        self.assertEqual(out_b, out)
        self.assertEqual(stats, stats_b)
        self.assertEqual(stats.dropped_esc_count, 10)
        self.assertEqual(stats.dropped_c0_c1_count, 1)

    def test_c0_c1_del_nul_crlf_and_bare_cr_injection(self) -> None:
        controls = b"a\x00b\x05c\x07d\x08e\x7ff\tg\nh\r\ni"
        out, stats = _feed_chunked(controls, 1)
        self.assertEqual(out, "abcdef\tg\nh\ni")
        self.assertEqual(stats.dropped_c0_c1_count, 5)
        self.assertEqual(stats.neutralized_bare_cr_count, 0)

        bare_cr = b"rm -rf /\rOK: clean\na\r\r\nb\r"
        cr_out, cr_stats = _feed_chunked(bare_cr, 1)
        self.assertNotIn("\r", cr_out)
        self.assertEqual(cr_out, "rm -rf /\nOK: clean\na\n\nb\n")
        self.assertEqual(cr_stats.neutralized_bare_cr_count, 3)
        self.assertEqual(cr_stats.dropped_c0_c1_count, 3)

    def test_bidi_rfc3629_boundaries_invalid_utf8_and_surrogates(self) -> None:
        bidi_bytes = b"safe" + b"".join(chr(cp).encode(_UTF8) for cp in sorted(_BIDI_CODEPOINTS)) + b"end"
        b_out, b_stats = _feed_chunked(bidi_bytes, 1)
        self.assertEqual(b_out, "safeend")
        self.assertEqual(b_stats.dropped_bidi_count, len(_BIDI_CODEPOINTS))

        boundaries = "\u0800\ud7ff\U00010000\U0010ffff"
        ok_out, ok_stats = _feed_chunked(boundaries.encode(_UTF8), 1)
        self.assertEqual(ok_out, boundaries)
        self.assertEqual(ok_stats.invalid_utf8_count, 0)

        bad = (
            b"\xc0\xaf"
            b"\xe0\x80\xaf"
            b"\xed\xa0\x80"
            b"\xf4\x90\x80\x80"
            b"\xe2\x1b]52;c;secret\x07"
            b"\xa0"
            b"ok"
            b"\xf0\x9f"
        )
        bad_out, bad_stats = _feed_chunked(bad, 1)
        self.assertIn("ok", bad_out)
        self.assertNotIn("secret", bad_out)
        self.assertGreaterEqual(bad_stats.invalid_utf8_count, 6)
        self.assertEqual(bad_stats.dropped_osc_count, 1)
        for ch in bad_out:
            self.assertFalse(0xD800 <= ord(ch) <= 0xDFFF)

        surr_out, surr_stats = sanitize_text_str("hi\ud800there")
        self.assertNotIn("\ud800", surr_out)
        self.assertTrue(surr_out.startswith("hi"))
        self.assertTrue(surr_out.endswith("there"))
        self.assertGreaterEqual(surr_stats.invalid_utf8_count, 1)

    def test_chunk_split_invariance_across_partition_sizes(self) -> None:
        composite = (
            b"hello\r\n"
            b"\x1b[1;31mred\x1b[0m"
            b"\x1b]52;c;\xe2\x80\x9c\xf0\x9f\x9a\x80secret\x07"
            b"\x1bPq\xe2\x80\x9bsixel\x1b\\"
            b"bad\rspoof"
            b"\xe2\x80\xaeRTL\x00\x7f"
            b"\x1b[?1049h\x1b[38;2;1;2;3m"
            b"\xc2\x9b6n"
            b"\xf4\x8f\xbf\xbf"
            b"\x1b(\x00B"
            b"\xe2\x1b[32mok\x1b[m\r"
        )
        for mode in (SanitizerMode.PLAIN, SanitizerMode.SAFE_SGR):
            ref_out, ref_stats = sanitize_bytes(composite, mode=mode)
            for size in (1, 2, 3, 7):
                out, stats = _feed_chunked(composite, size, mode=mode)
                self.assertEqual(out, ref_out)
                self.assertEqual(stats, ref_stats)


class TestSanitizerSafeSgrAndDos(unittest.TestCase):
    """SAFE_SGR allowlist, 8-slot SGR tracking, and overlong DoS bounds."""

    def test_safe_sgr_allowlist_and_plain_mode_strip(self) -> None:
        raw = (
            b"\x1b[mA\x1b[0mB\x1b[1;31mC\x1b[32;40;97;100mD"
            b"\x1b[38;5;196;1mE\x1b[48;5;0mF\x1b[0m"
        )
        sgr_out, sgr_stats = sanitize_bytes(raw, mode=SanitizerMode.SAFE_SGR)
        self.assertEqual(sgr_out, raw.decode("ascii"))
        self.assertEqual(sgr_stats.allowed_sgr_count, 7)
        self.assertEqual(sgr_stats.dropped_csi_count, 0)

        plain_out, plain_stats = sanitize_bytes(raw, mode=SanitizerMode.PLAIN)
        self.assertEqual(plain_out, "ABCDEF")
        self.assertEqual(plain_stats.allowed_sgr_count, 0)
        self.assertEqual(plain_stats.dropped_csi_count, 7)

    def test_safe_sgr_spoofing_and_malformed_rejected(self) -> None:
        bad_seqs = (
            b"\x1b[38;2;255;0;0m",
            b"\x1b[48;2;1;2;3m",
            b"\x1b[38:2::255:0:0m",
            b"\x1b[4:3m",
            b"\x1b[58;5;1m",
            b"\x1b[8m",
            b"\x1b[5m",
            b"\x1b[?1m",
            b"\x1b[>4;2m",
            b"\x1b[=1m",
            b"\x1b[<1m",
            b"\x1b[0$m",
            b"\x1b[3\x001m",
            b"\x1b[" + b";".join([b"1"] * 17) + b"m",
            b"\x1b[38;5;256m",
            b"\x1b[1;;31m",
            b"\x1b[0001m",
            b"\x1b[38;5m",
            b"\x9b31m",
            b"\xc2\x9b31m",
        )
        for seq in bad_seqs:
            out, stats = sanitize_bytes(b"X" + seq + b"Y", mode=SanitizerMode.SAFE_SGR)
            self.assertEqual(out, "XY", f"should drop {seq!r}")
            self.assertEqual(stats.allowed_sgr_count, 0)
            self.assertEqual(stats.dropped_csi_count, 1)

    def test_bold_and_faint_8_slot_state_and_sgr_22_reset(self) -> None:
        san = TerminalOutputSanitizer(mode=SanitizerMode.SAFE_SGR)
        san.feed(b"\x1b[1m\x1b[2m\x1b[3;31m")
        self.assertEqual(san.active_sgr_seq, "\x1b[1;2;3;31m")
        san.feed(b"\x1b[22m")
        self.assertEqual(san.active_sgr_seq, "\x1b[3;31m")
        san.feed(b"\x1b[23m\x1b[39m")
        self.assertEqual(san.active_sgr_seq, "")
        san.feed(b"\x1b[1;2;4;7;9;38;5;200;48;5;17m")
        self.assertEqual(san.active_sgr_seq, "\x1b[1;2;4;7;9;38;5;200;48;5;17m")
        san.feed(b"\x1b[m")
        self.assertEqual(san.active_sgr_seq, "")

    def test_unterminated_1mib_osc_dcs_csi_dos_bounded_memory(self) -> None:
        osc_san = TerminalOutputSanitizer()
        out = osc_san.feed(b"\x1b]52;c;" + (b"A" * 1_048_576))
        self.assertEqual(out, "")
        self.assertEqual(osc_san.stats.output_bytes, 0)
        self.assertEqual(osc_san.stats.overlong_seq_dropped_count, 1)
        self.assertEqual(osc_san.stats.dropped_osc_count, 1)
        self.assertLessEqual(osc_san.parser_buffer_bytes, MAX_SAFE_SGR_PARAM_BYTES)
        resync = osc_san.feed(b"\x07AFTER") + osc_san.flush()
        self.assertEqual(resync, "AFTER")
        self.assertEqual(osc_san.stats.dropped_osc_count, 1)

        dcs_san = TerminalOutputSanitizer()
        dcs_san.feed(b"\x1bPq")
        for _ in range(1024):
            self.assertEqual(dcs_san.feed(b"B" * 1024), "")
            self.assertLessEqual(dcs_san.parser_buffer_bytes, MAX_SAFE_SGR_PARAM_BYTES)
        self.assertEqual(dcs_san.stats.overlong_seq_dropped_count, 1)
        self.assertEqual(dcs_san.feed(b"\x1b\\OK") + dcs_san.flush(), "OK")
        self.assertEqual(dcs_san.stats.dropped_string_seq_count, 1)

        csi_san = TerminalOutputSanitizer(mode=SanitizerMode.SAFE_SGR)
        self.assertEqual(csi_san.feed(b"\x1b[" + (b"\x00" * 5000) + b"mDONE"), "DONE")
        self.assertEqual(csi_san.stats.overlong_seq_dropped_count, 1)
        self.assertEqual(csi_san.stats.dropped_csi_count, 1)
        self.assertLessEqual(csi_san.parser_buffer_bytes, MAX_SAFE_SGR_PARAM_BYTES)

    def test_exact_max_esc_seq_bytes_boundaries_and_eof_c2_flush(self) -> None:
        # 4096 bytes exact (not overlong) vs 4097 bytes (overlong) across terminators
        exact_cases = (
            (b"\x1b]0;" + (b"A" * (MAX_ESC_SEQ_BYTES - 5)) + b"\x07", 0),
            (b"\x1b]0;" + (b"A" * (MAX_ESC_SEQ_BYTES - 4)) + b"\x07", 1),
            (b"\x1b]0;" + (b"A" * (MAX_ESC_SEQ_BYTES - 6)) + b"\x1b\\", 0),
            (b"\x1b]0;" + (b"A" * (MAX_ESC_SEQ_BYTES - 5)) + b"\x1b\\", 1),
            (b"\x1b]0;" + (b"A" * (MAX_ESC_SEQ_BYTES - 6)) + b"\xc2\x9c", 0),
            (b"\x1b]0;" + (b"A" * (MAX_ESC_SEQ_BYTES - 5)) + b"\xc2\x9c", 1),
            (b"\x1b[" + (b"0" * (MAX_ESC_SEQ_BYTES - 3)) + b"m", 0),
            (b"\x1b[" + (b"0" * (MAX_ESC_SEQ_BYTES - 2)) + b"m", 1),
        )
        for seq, expected_overlong in exact_cases:
            out, stats = sanitize_bytes(seq)
            self.assertEqual(out, "")
            self.assertEqual(stats.overlong_seq_dropped_count, expected_overlong)

        # EOF lone 0xC2 at byte 4097 + second idempotent flush
        for prefix in (b"\x1b]0;", b"\x1bPq"):
            san = TerminalOutputSanitizer()
            san.feed(prefix + (b"A" * (MAX_ESC_SEQ_BYTES - len(prefix))) + b"\xc2")
            self.assertEqual(san.stats.overlong_seq_dropped_count, 0)
            self.assertEqual(san.flush(), "")
            first_stats = san.stats
            self.assertEqual(first_stats.overlong_seq_dropped_count, 1)
            self.assertEqual(san.flush(), "")
            self.assertEqual(san.stats, first_stats)

        # EOF lone 0x1B at byte 4097 + idempotent flush
        esc_san = TerminalOutputSanitizer()
        esc_san.feed(b"\x1b]0;" + (b"A" * (MAX_ESC_SEQ_BYTES - 4)) + b"\x1b")
        self.assertEqual(esc_san.stats.overlong_seq_dropped_count, 0)
        self.assertEqual(esc_san.flush(), "")
        self.assertEqual(esc_san.stats.overlong_seq_dropped_count, 1)
        self.assertEqual(esc_san.stats.dropped_osc_count, 1)
        self.assertEqual(esc_san.flush(), "")
        self.assertEqual(esc_san.stats.dropped_osc_count, 1)


class TestReplayProvenanceAndFencing(unittest.TestCase):
    """Provenance binding, incarnation/epoch/seq fencing, capacity caps, and ring eviction."""

    def test_local_and_remote_targets_and_address_error_wrapping(self) -> None:
        store = TerminalReplayStore()
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        store.register_stream(target=_TARGET_REMOTE, incarnation_id=_INC_1, terminal_id=_SHELL)
        store.append_chunk(
            target=_TARGET_REMOTE,
            incarnation_id=_INC_1,
            terminal_id=_SHELL,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"remote-ok\n",
            captured_at=10.5,
        )
        page = store.read_replay_frames(_OPERATOR, target=_TARGET_REMOTE, terminal_id=_SHELL)
        self.assertEqual(page.sandbox_addr, _TARGET_REMOTE)
        self.assertEqual(page.frames[0].text, "remote-ok\n")

        bad_inputs: tuple[Any, ...] = ("@peer-a", "bad\x00name", "bad\u202ename", "bad\ud800name", 123)
        for bad in bad_inputs:
            with self.assertRaises(CoordValidationError):
                parse_terminal_target(bad)
            with self.assertRaises(CoordValidationError):
                store.register_stream(target=_TARGET_LOCAL, incarnation_id=bad, terminal_id=_TUI)

        sess_store = TerminalReplayStore(session_validator=lambda c, s, g: True)
        sess_store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        for bad_sid in ("bad\x00sid", "bad\u202esid", "bad\ud800sid", 99):
            with self.assertRaises(CoordValidationError):
                sess_store.read_replay_frames(
                    _OPERATOR,
                    target=_TARGET_LOCAL,
                    terminal_id=_TUI,
                    read_session_id=bad_sid,
                    session_generation=1,
                )

    def test_stale_incarnation_epoch_seq_and_atomic_non_mutation(self) -> None:
        store = TerminalReplayStore()
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"hello\r",
            captured_at=1.0,
        )
        with self.assertRaises(IncarnationMismatchError) as inc_ctx:
            store.append_chunk(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_2,
                terminal_id=_TUI,
                stream_epoch=1,
                frame_seq=2,
                raw_bytes=b"\n",
                captured_at=2.0,
            )
        self.assertIn(ERR_STALE_INCARNATION, str(inc_ctx.exception))

        with self.assertRaises(CoordPolicyError) as ep_ctx:
            store.append_chunk(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=2,
                frame_seq=2,
                raw_bytes=b"\n",
                captured_at=2.0,
            )
        self.assertIn(ERR_UNREGISTERED_EPOCH, str(ep_ctx.exception))

        with self.assertRaises(CoordPolicyError) as seq_ctx:
            store.append_chunk(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=1,
                frame_seq=1,
                raw_bytes=b"\n",
                captured_at=2.0,
            )
        self.assertIn(ERR_NON_MONOTONIC_SEQ, str(seq_ctx.exception))

        for bad_ts in (float("nan"), float("inf"), float("-inf"), -1.0, True, 10**400):
            with self.assertRaises(CoordValidationError):
                store.append_chunk(
                    target=_TARGET_LOCAL,
                    incarnation_id=_INC_1,
                    terminal_id=_TUI,
                    stream_epoch=1,
                    frame_seq=2,
                    raw_bytes=b"x",
                    captured_at=bad_ts,
                )

        # Verify sanitizer pending_cr state survived all rejected appends untouched
        frame2 = store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=2,
            raw_bytes=b"\nworld",
            captured_at=3.0,
        )
        self.assertEqual(frame2.text, "\nworld")
        self.assertEqual(frame2.frame_stats.neutralized_bare_cr_count, 0)

    def test_cross_terminal_incarnation_rotation_and_check_order(self) -> None:
        store = TerminalReplayStore()
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_SHELL)
        store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"\x1b]0;dangling",
            captured_at=1.0,
        )
        # Rotate sandbox to _INC_2 on _TUI -> retires _INC_1 and clears _SHELL
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_2, terminal_id=_TUI)

        with self.assertRaises(IncarnationMismatchError) as reuse_ctx:
            store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_SHELL)
        self.assertIn(ERR_RETIRED_REUSED, str(reuse_ctx.exception))

        with self.assertRaises(IncarnationMismatchError) as app_ctx:
            store.append_chunk(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_SHELL,
                stream_epoch=1,
                frame_seq=1,
                raw_bytes=b"old",
                captured_at=2.0,
            )
        self.assertIn(ERR_STALE_INCARNATION, str(app_ctx.exception))

        with self.assertRaises(IncarnationMismatchError) as read_ctx:
            store.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_SHELL,
                incarnation_id=_INC_1,
            )
        self.assertIn(ERR_STALE_INCARNATION, str(read_ctx.exception))

        with self.assertRaises(IncarnationMismatchError) as close_ctx:
            store.close_stream(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_SHELL,
                stream_epoch=1,
            )
        self.assertIn(ERR_STALE_INCARNATION, str(close_ctx.exception))

        with self.assertRaises(CoordPolicyError) as unreg_ctx:
            store.append_chunk(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_2,
                terminal_id=_SHELL,
                stream_epoch=1,
                frame_seq=1,
                raw_bytes=b"new",
                captured_at=2.0,
            )
        self.assertIn(ERR_STREAM_NOT_REGISTERED, str(unreg_ctx.exception))

        # Fresh incarnation sanitizer is completely clean (dangling OSC from inc_1 gone)
        clean_frame = store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_2,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"fresh",
            captured_at=3.0,
        )
        self.assertEqual(clean_frame.text, "fresh")

    def test_close_stream_fencing_atomic_pre_flush_and_post_close_epoch_rotation(self) -> None:
        store = TerminalReplayStore()
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=5,
            raw_bytes=b"trailing\r",
            captured_at=1.0,
        )
        with self.assertRaises(CoordValidationError) as pair_ctx:
            store.close_stream(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=1,
                flush_frame_seq=6,
            )
        self.assertIn(ERR_CLOSE_PAIR_REQUIRED, str(pair_ctx.exception))

        with self.assertRaises(CoordPolicyError) as ep_ctx:
            store.close_stream(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=2,
            )
        self.assertIn(ERR_UNREGISTERED_EPOCH, str(ep_ctx.exception))

        with self.assertRaises(CoordPolicyError) as seq_ctx:
            store.close_stream(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=1,
                flush_frame_seq=5,
                captured_at=2.0,
            )
        self.assertIn(ERR_NON_MONOTONIC_SEQ, str(seq_ctx.exception))

        # Still open and unflushed -> valid close emits flush frame with neutralized CR
        flushed = store.close_stream(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            flush_frame_seq=6,
            captured_at=2.0,
        )
        self.assertIsNotNone(flushed)
        assert flushed is not None
        self.assertEqual(flushed.text, "\n")
        self.assertEqual(flushed.frame_stats.neutralized_bare_cr_count, 1)

        # Double close and post-close append both fail closed
        with self.assertRaises(RevokedError) as dc_ctx:
            store.close_stream(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=1,
            )
        self.assertIn(ERR_STREAM_CLOSED, str(dc_ctx.exception))

        with self.assertRaises(RevokedError):
            store.append_chunk(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=1,
                frame_seq=7,
                raw_bytes=b"late",
                captured_at=3.0,
            )

        # Operator can still read closed stream
        closed_page = store.read_replay_frames(_OPERATOR, target=_TARGET_LOCAL, terminal_id=_TUI)
        self.assertTrue(closed_page.stream_closed)
        self.assertEqual(len(closed_page.frames), 2)

        # Reconnect under stale epoch fails; strictly higher epoch succeeds and resets state
        with self.assertRaises(CoordPolicyError) as rot_err:
            store.rotate_stream_epoch(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                new_stream_epoch=1,
            )
        self.assertIn(ERR_STALE_EPOCH, str(rot_err.exception))

        store.rotate_stream_epoch(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            new_stream_epoch=2,
        )
        reopened = store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=2,
            frame_seq=1,
            raw_bytes=b"epoch2",
            captured_at=4.0,
        )
        self.assertEqual(reopened.text, "epoch2")

    def test_fail_closed_sandbox_and_retired_incarnation_capacity_caps(self) -> None:
        sb_store = TerminalReplayStore()
        for idx in range(MAX_TRACKED_SANDBOXES):
            sb_store.register_stream(
                target=f"sb-{idx}",
                incarnation_id=_INC_1,
                terminal_id=_TUI,
            )
        with self.assertRaises(CoordPolicyError) as sb_ctx:
            sb_store.register_stream(target="sb-overflow", incarnation_id=_INC_1, terminal_id=_TUI)
        self.assertIn(ERR_MAX_SANDBOXES, str(sb_ctx.exception))

        inc_store = TerminalReplayStore()
        inc_store.register_stream(target=_TARGET_LOCAL, incarnation_id="inc_0", terminal_id=_TUI)
        for idx in range(1, MAX_RETIRED_INCARNATIONS + 1):
            inc_store.register_stream(
                target=_TARGET_LOCAL,
                incarnation_id=f"inc_{idx}",
                terminal_id=_TUI,
            )
        with self.assertRaises(CoordPolicyError) as ret_ctx:
            inc_store.register_stream(
                target=_TARGET_LOCAL,
                incarnation_id="inc_overflow",
                terminal_id=_TUI,
            )
        self.assertIn(ERR_MAX_RETIRED, str(ret_ctx.exception))
        # Verify retired inc_0 was never evicted
        with self.assertRaises(IncarnationMismatchError):
            inc_store.register_stream(
                target=_TARGET_LOCAL,
                incarnation_id="inc_0",
                terminal_id=_TUI,
            )

    def test_ring_eviction_and_exact_last_evicted_seq_gap_signal(self) -> None:
        store = TerminalReplayStore(max_ring_frames=3, max_ring_bytes=MAX_FRAME_TEXT_BYTES)
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        # Sparse monotonic frame_seq with zero evictions -> no false positive!
        for seq in (10, 20, 30):
            store.append_chunk(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=1,
                frame_seq=seq,
                raw_bytes=f"f{seq}".encode("ascii"),
                captured_at=float(seq),
            )
        p1 = store.read_replay_frames(_OPERATOR, target=_TARGET_LOCAL, terminal_id=_TUI, limit=1)
        self.assertFalse(p1.frames_evicted_before_page)
        self.assertEqual(p1.evicted_frame_count, 0)
        cursor_10 = p1.next_cursor
        self.assertIsNotNone(cursor_10)

        p2 = store.read_replay_frames(
            _OPERATOR, target=_TARGET_LOCAL, terminal_id=_TUI, after_cursor=cursor_10, limit=1
        )
        self.assertFalse(p2.frames_evicted_before_page)
        cursor_20 = p2.next_cursor

        # Append two more frames -> evicts seq 10 and seq 20 (last_evicted_seq == 20)
        for seq in (40, 50):
            store.append_chunk(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=1,
                frame_seq=seq,
                raw_bytes=f"f{seq}".encode("ascii"),
                captured_at=float(seq),
            )
        p_all = store.read_replay_frames(_OPERATOR, target=_TARGET_LOCAL, terminal_id=_TUI)
        self.assertTrue(p_all.frames_evicted_before_page)
        self.assertEqual(p_all.evicted_frame_count, 2)
        self.assertEqual([f.frame_seq for f in p_all.frames], [30, 40, 50])

        # Cursor at 10 (< last_evicted_seq 20) -> gap signaled; cursor at 20 (== 20) -> no gap!
        p_after_10 = store.read_replay_frames(
            _OPERATOR, target=_TARGET_LOCAL, terminal_id=_TUI, after_cursor=cursor_10
        )
        self.assertTrue(p_after_10.frames_evicted_before_page)
        p_after_20 = store.read_replay_frames(
            _OPERATOR, target=_TARGET_LOCAL, terminal_id=_TUI, after_cursor=cursor_20
        )
        self.assertFalse(p_after_20.frames_evicted_before_page)

        # Byte-cap eviction test
        byte_store = TerminalReplayStore(max_ring_frames=10, max_ring_bytes=MAX_FRAME_TEXT_BYTES)
        byte_store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_SHELL)
        byte_store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_SHELL,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"A" * 10_000,
            captured_at=1.0,
        )
        byte_store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_SHELL,
            stream_epoch=1,
            frame_seq=2,
            raw_bytes=b"B" * 10_000,
            captured_at=2.0,
        )
        bp = byte_store.read_replay_frames(_OPERATOR, target=_TARGET_LOCAL, terminal_id=_SHELL)
        self.assertEqual([f.frame_seq for f in bp.frames], [2])
        self.assertEqual(bp.evicted_frame_count, 1)
        self.assertTrue(bp.frames_evicted_before_page)


class TestOperatorAuthSessionFencingAndPostPackRace(unittest.TestCase):
    """Operator-only admission, pre/post session/live fencing, and mid-read race barriers."""

    def test_operator_only_admission_no_target_oracle(self) -> None:
        store = TerminalReplayStore()
        with self.assertRaises(CoordValidationError):
            store.read_replay_frames("not-a-principal", target="missing", terminal_id=_TUI)  # type: ignore[arg-type]

        for bad_caller in (_JOB_CALLER, _ROOT_ORCH, _BOUND_ORCH, _PEER_CALLER):
            with self.assertRaises(CoordAuthError) as ctx:
                store.read_replay_frames(bad_caller, target="nonexistent", terminal_id=_TUI)
            self.assertIn(ERR_OPERATOR_REQUIRED, str(ctx.exception))

        with self.assertRaises(CoordAuthError) as bound_ctx:
            store.read_replay_frames(_BOUND_OPERATOR, target="nonexistent", terminal_id=_TUI)
        self.assertIn(ERR_OPERATOR_UNBOUND, str(bound_ctx.exception))

    def test_pre_and_post_session_and_live_authority_fencing(self) -> None:
        # Session args supplied with no validator configured
        no_val = TerminalReplayStore()
        no_val.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        with self.assertRaises(CoordPolicyError) as uncfg_ctx:
            no_val.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_TUI,
                read_session_id=_SESS_1,
                session_generation=1,
            )
        self.assertIn(ERR_SESSION_VALIDATOR_UNCONFIGURED, str(uncfg_ctx.exception))

        # Configured validator: omitted, partial, pre-read fail, mid-read revoke, exception
        state = {"sess_ok": True, "live_ok": True, "calls": 0}

        def sess_check(caller: PrincipalCtx, sid: str, gen: int) -> bool:
            state["calls"] += 1
            return state["sess_ok"] and sid == _SESS_1 and gen == 3

        def live_check(caller: PrincipalCtx) -> bool:
            return state["live_ok"]

        store = TerminalReplayStore(
            session_validator=sess_check,
            live_authority_checker=live_check,
        )
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"secret-output",
            captured_at=1.0,
        )

        with self.assertRaises(CoordAuthError) as req_ctx:
            store.read_replay_frames(_OPERATOR, target=_TARGET_LOCAL, terminal_id=_TUI)
        self.assertIn(ERR_SESSION_REQUIRED, str(req_ctx.exception))

        with self.assertRaises(CoordValidationError) as pair_ctx:
            store.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_TUI,
                read_session_id=_SESS_1,
            )
        self.assertIn(ERR_SESSION_PAIR_REQUIRED, str(pair_ctx.exception))

        # Valid call echoes ReadSessionEcho and calls validator pre + post (2 times)
        state["calls"] = 0
        page = store.read_replay_frames(
            _OPERATOR,
            target=_TARGET_LOCAL,
            terminal_id=_TUI,
            read_session_id=_SESS_1,
            session_generation=3,
        )
        self.assertEqual(state["calls"], 2)
        self.assertIsNotNone(page.read_session)
        assert page.read_session is not None
        self.assertEqual(page.read_session.read_session_id, _SESS_1)
        self.assertEqual(page.read_session.session_generation, 3)

        # Pre-read retired session
        state["sess_ok"] = False
        with self.assertRaises(RevokedError) as pre_ctx:
            store.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_TUI,
                read_session_id=_SESS_1,
                session_generation=3,
            )
        self.assertIn(ERR_SESSION_RETIRED, str(pre_ctx.exception))

        # Mid-read session revocation (valid pre-read, revoked before post-read)
        state["sess_ok"] = True
        mid_store = TerminalReplayStore(
            session_validator=sess_check,
            live_authority_checker=live_check,
            on_after_snapshot_before_release=lambda: state.__setitem__("sess_ok", False),
        )
        mid_store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        mid_store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"must-not-leak",
            captured_at=1.0,
        )
        with self.assertRaises(RevokedError) as mid_sess_ctx:
            mid_store.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_TUI,
                read_session_id=_SESS_1,
                session_generation=3,
            )
        self.assertIn(ERR_SESSION_RETIRED, str(mid_sess_ctx.exception))

        # Mid-read live_authority_checker revocation
        state["sess_ok"] = True
        state["live_ok"] = True
        live_mid = TerminalReplayStore(
            session_validator=sess_check,
            live_authority_checker=live_check,
            on_after_snapshot_before_release=lambda: state.__setitem__("live_ok", False),
        )
        live_mid.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        live_mid.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"must-not-leak",
            captured_at=1.0,
        )
        with self.assertRaises(RevokedError) as mid_live_ctx:
            live_mid.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_TUI,
                read_session_id=_SESS_1,
                session_generation=3,
            )
        self.assertIn(ERR_AUTHORITY_REVOKED, str(mid_live_ctx.exception))

    def test_mid_read_stream_identity_race_barrier(self) -> None:
        # (a) Incarnation rotated during read packing while operator session remains valid
        inc_holder: dict[str, Any] = {}

        def rotate_inc_hook() -> None:
            inc_holder["store"].register_stream(
                target=_TARGET_LOCAL, incarnation_id=_INC_2, terminal_id=_TUI
            )

        store_a = TerminalReplayStore(
            session_validator=lambda c, s, g: True,
            live_authority_checker=lambda c: True,
            on_after_snapshot_before_release=rotate_inc_hook,
        )
        inc_holder["store"] = store_a
        store_a.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        store_a.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"inc1-secret",
            captured_at=1.0,
        )
        with self.assertRaises(IncarnationMismatchError) as a_ctx:
            store_a.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_TUI,
                read_session_id=_SESS_1,
                session_generation=1,
            )
        self.assertIn(ERR_STALE_INCARNATION, str(a_ctx.exception))

        # (b) stream_epoch rotated during read packing while operator session remains valid
        ep_holder: dict[str, Any] = {}

        def rotate_ep_hook() -> None:
            ep_holder["store"].rotate_stream_epoch(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                new_stream_epoch=2,
            )

        store_b = TerminalReplayStore(
            session_validator=lambda c, s, g: True,
            live_authority_checker=lambda c: True,
            on_after_snapshot_before_release=rotate_ep_hook,
        )
        ep_holder["store"] = store_b
        store_b.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        store_b.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"ep1-secret",
            captured_at=1.0,
        )
        with self.assertRaises(CoordPolicyError) as b_ctx:
            store_b.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_TUI,
                read_session_id=_SESS_1,
                session_generation=1,
            )
        self.assertIn(ERR_STALE_EPOCH, str(b_ctx.exception))

        # (c) Open stream closed during read packing -> RevokedError; new read on closed succeeds
        cl_holder: dict[str, Any] = {"armed": True}

        def close_hook() -> None:
            if cl_holder["armed"]:
                cl_holder["armed"] = False
                cl_holder["store"].close_stream(
                    target=_TARGET_LOCAL,
                    incarnation_id=_INC_1,
                    terminal_id=_TUI,
                    stream_epoch=1,
                )

        store_c = TerminalReplayStore(
            session_validator=lambda c, s, g: True,
            live_authority_checker=lambda c: True,
            on_after_snapshot_before_release=close_hook,
        )
        cl_holder["store"] = store_c
        store_c.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        store_c.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"open-frame",
            captured_at=1.0,
        )
        with self.assertRaises(RevokedError) as c_ctx:
            store_c.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_TUI,
                read_session_id=_SESS_1,
                session_generation=1,
            )
        self.assertIn(ERR_STREAM_CLOSED, str(c_ctx.exception))

        # New read opened after stream is already closed succeeds with stream_closed=True
        post_page = store_c.read_replay_frames(
            _OPERATOR,
            target=_TARGET_LOCAL,
            terminal_id=_TUI,
            read_session_id=_SESS_1,
            session_generation=1,
        )
        self.assertTrue(post_page.stream_closed)
        self.assertEqual(post_page.frames[0].text, "open-frame")


class TestResponseByteCapsCrossFrameSgrAndCursors(unittest.TestCase):
    """Hard UTF-8 JSON byte caps, cross-frame SAFE_SGR closure, cursors, and allow_nan=False."""

    def test_1kib_response_budget_escape_heavy_utf8_and_pagination(self) -> None:
        store = TerminalReplayStore()
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        escape_heavy = ('"\\\n' * 300 + "λ🔥" * 100).encode(_UTF8)
        store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=escape_heavy,
            captured_at=1.0,
        )
        # Single-candidate page at 1 KiB (zero phantom cursor reservation)
        p1 = store.read_replay_frames(
            _OPERATOR,
            target=_TARGET_LOCAL,
            terminal_id=_TUI,
            max_response_bytes=MIN_RESPONSE_BYTES,
        )
        raw1 = serialize_terminal_bytes(p1)
        self.assertLessEqual(len(raw1), MIN_RESPONSE_BYTES)
        self.assertFalse(p1.has_more)
        self.assertIsNone(p1.next_cursor)
        self.assertTrue(p1.frames[0].text_truncated)
        self.assertGreater(len(p1.frames[0].text), 0)

        # Add two more frames and paginate strictly within 1 KiB with zero skips/duplicates
        for seq in (2, 3):
            store.append_chunk(
                target=_TARGET_LOCAL,
                incarnation_id=_INC_1,
                terminal_id=_TUI,
                stream_epoch=1,
                frame_seq=seq,
                raw_bytes=(f"frame-{seq}-" + '"\\\n' * 200).encode(_UTF8),
                captured_at=float(seq),
            )
        seen_seqs: list[int] = []
        cursor: str | None = None
        while True:
            page = store.read_replay_frames(
                _OPERATOR,
                target=_TARGET_LOCAL,
                terminal_id=_TUI,
                after_cursor=cursor,
                limit=1,
                max_response_bytes=MIN_RESPONSE_BYTES,
            )
            encoded = serialize_terminal_bytes(page)
            self.assertLessEqual(len(encoded), MIN_RESPONSE_BYTES)
            for frame in page.frames:
                seen_seqs.append(frame.frame_seq)
            if not page.has_more:
                self.assertIsNone(page.next_cursor)
                break
            self.assertIsNotNone(page.next_cursor)
            cursor = page.next_cursor
        self.assertEqual(seen_seqs, [1, 2, 3])

    def test_cross_frame_safe_sgr_self_containment_and_truncation(self) -> None:
        store = TerminalReplayStore()
        store.register_stream(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            mode=SanitizerMode.SAFE_SGR,
        )
        # Frame 1 opens bold + faint + red without closing
        f1 = store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"\x1b[1;2;31mhello",
            captured_at=1.0,
        )
        self.assertEqual(f1.text, "\x1b[1;2;31mhello\x1b[0m")
        self.assertFalse(sgr_is_open(f1.text))

        # Frame 2 continues style and closes with ESC[0m
        f2 = store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=2,
            raw_bytes=b"world\x1b[0m",
            captured_at=2.0,
        )
        self.assertEqual(f2.text, "\x1b[1;2;31mworld\x1b[0m")
        self.assertFalse(sgr_is_open(f2.text))

        # Frame 3 opens red; Frame 4 is huge (> MAX_FRAME_TEXT_BYTES) and closes at end ->
        # storage truncation cuts closing ESC[0m and must re-append ESC[0m within 16 KiB!
        f3 = store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=3,
            raw_bytes=b"\x1b[31mopen",
            captured_at=3.0,
        )
        self.assertEqual(f3.text, "\x1b[31mopen\x1b[0m")
        f4 = store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=4,
            raw_bytes=(b"A" * 20_000) + b"\x1b[0m",
            captured_at=4.0,
        )
        self.assertTrue(f4.text_truncated)
        self.assertLessEqual(f4.text_bytes, MAX_FRAME_TEXT_BYTES)
        self.assertTrue(f4.text.startswith("\x1b[31m"))
        self.assertTrue(f4.text.endswith(SGR_RESET))
        self.assertFalse(sgr_is_open(f4.text))

        # Page packing frame 4 at max_response_bytes=1024 cuts closing ESC[0m again and must
        # re-append ESC[0m accounting for JSON 6-byte \u001b expansion!
        scope = compute_replay_scope_hash(
            target=_TARGET_LOCAL,
            terminal_id=_TUI,
            incarnation_id=_INC_1,
            stream_epoch=1,
        )
        c3 = encode_replay_cursor(
            scope_hash=scope, incarnation_id=_INC_1, stream_epoch=1, frame_seq=3
        )
        p4 = store.read_replay_frames(
            _OPERATOR,
            target=_TARGET_LOCAL,
            terminal_id=_TUI,
            after_cursor=c3,
            max_response_bytes=MIN_RESPONSE_BYTES,
        )
        raw_p4 = serialize_terminal_bytes(p4)
        self.assertLessEqual(len(raw_p4), MIN_RESPONSE_BYTES)
        self.assertEqual(len(p4.frames), 1)
        self.assertTrue(p4.frames[0].text.startswith("\x1b[31m"))
        self.assertTrue(p4.frames[0].text.endswith(SGR_RESET))
        self.assertFalse(sgr_is_open(p4.frames[0].text))

        # Direct truncate_sanitized_text_utf8 mid-SGR safety check
        trunc, tbytes, is_trunc = truncate_sanitized_text_utf8(
            "abc\x1b[31mdef", 6, mode=SanitizerMode.SAFE_SGR
        )
        self.assertTrue(is_trunc)
        self.assertEqual(trunc, "abc")
        self.assertEqual(tbytes, 3)
        self.assertFalse(sgr_is_open(trunc))

    def test_budget_too_small_for_envelope_or_item_fails_closed(self) -> None:
        long_inc = "inc_" + ("x" * 90)
        long_sid = "sid_" + ("y" * 90)
        store = TerminalReplayStore(session_validator=lambda c, s, g: True)
        store.register_stream(target=_TARGET_REMOTE, incarnation_id=long_inc, terminal_id=_TUI)
        store.append_chunk(
            target=_TARGET_REMOTE,
            incarnation_id=long_inc,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"\x1b]0;a\x07\x1b[6n\x1bPq\x1b\\\x1bc\x00\xe2\x80\xae\xff\r",
            captured_at=1.0,
        )
        store.append_chunk(
            target=_TARGET_REMOTE,
            incarnation_id=long_inc,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=2,
            raw_bytes=b"second",
            captured_at=2.0,
        )
        # Explicit out-of-range budget (< MIN_RESPONSE_BYTES)
        with self.assertRaises(CoordValidationError):
            store.read_replay_frames(
                _OPERATOR,
                target=_TARGET_REMOTE,
                terminal_id=_TUI,
                max_response_bytes=512,
                read_session_id=long_sid,
                session_generation=1,
            )

        # Maximal-metadata envelope + next_cursor exceeds 1024 -> ERR_BUDGET_ENVELOPE
        with self.assertRaises(CoordValidationError) as env_ctx:
            store.read_replay_frames(
                _OPERATOR,
                target=_TARGET_REMOTE,
                terminal_id=_TUI,
                max_response_bytes=MIN_RESPONSE_BYTES,
                read_session_id=long_sid,
                session_generation=1,
            )
        self.assertIn(ERR_BUDGET_ENVELOPE, str(env_ctx.exception))

        # Tight budget that fits empty envelope (with next_cursor) but not even empty-text frame
        # -> ERR_BUDGET_ITEM through the public read_replay_frames API!
        full_page = store.read_replay_frames(
            _OPERATOR,
            target=_TARGET_REMOTE,
            terminal_id=_TUI,
            limit=1,
            max_response_bytes=4096,
            read_session_id=long_sid,
            session_generation=1,
        )
        full_size = len(serialize_terminal_bytes(full_page))
        # Empty-text frame 1 is identical to frame 1 (whose text is '\n') minus ~2 bytes,
        # so full_size - 20 fits empty envelope but cannot fit even empty-text frame 1!
        tight_budget = max(MIN_RESPONSE_BYTES, full_size - 20)
        with self.assertRaises(CoordValidationError) as item_ctx:
            store.read_replay_frames(
                _OPERATOR,
                target=_TARGET_REMOTE,
                terminal_id=_TUI,
                limit=1,
                max_response_bytes=tight_budget,
                read_session_id=long_sid,
                session_generation=1,
            )
        self.assertIn(ERR_BUDGET_ITEM, str(item_ctx.exception))

    def test_cursor_tampering_and_scope_mismatch_rejection(self) -> None:
        scope = compute_replay_scope_hash(
            target=_TARGET_LOCAL,
            terminal_id=_TUI,
            incarnation_id=_INC_1,
            stream_epoch=1,
        )
        valid = encode_replay_cursor(
            scope_hash=scope, incarnation_id=_INC_1, stream_epoch=1, frame_seq=7
        )
        self.assertEqual(
            decode_replay_cursor(
                valid,
                expected_scope_hash=scope,
                expected_incarnation_id=_INC_1,
                expected_stream_epoch=1,
            ),
            7,
        )

        # Malformed cursors (pad_len==3, padding, extra whitespace, NaN, RecursionError, bool, etc.)
        deeply_nested = (b'{"a":' * 1200) + b"1" + (b"}" * 1200)
        nested_valid_cursor = _b64url_cursor((b"[" * 160) + (b"]" * 160))
        old_limit = sys.getrecursionlimit()
        try:
            sys.setrecursionlimit(100)
            with self.assertRaises(CoordValidationError) as rec_ctx:
                decode_replay_cursor(
                    nested_valid_cursor,
                    expected_scope_hash=scope,
                    expected_incarnation_id=_INC_1,
                    expected_stream_epoch=1,
                )
        finally:
            sys.setrecursionlimit(old_limit)
        self.assertIn(ERR_CURSOR_MALFORMED, str(rec_ctx.exception))

        malformed_cases: tuple[Any, ...] = (
            123,
            "v2.abc",
            f"{CURSOR_PREFIX}A",  # pad_len == 3
            f"{valid}=",  # padding rejected
            f"{CURSOR_PREFIX}" + ("A" * MAX_CURSOR_BYTES),  # oversize
            f"{CURSOR_PREFIX}bad\ud800surr",
            _b64url_cursor(b'{ "ep": 1, "fh": "' + scope.encode() + b'", "inc": "inc:0001", "op": "terminal_replay", "seq": 1 }'),
            _b64url_cursor(b'{"ep":1,"fh":"' + scope.encode() + b'","inc":"inc:0001","op":"terminal_replay","seq":NaN}'),
            _b64url_cursor(deeply_nested)[:MAX_CURSOR_BYTES],
            _b64url_cursor(json.dumps({"ep": True, "fh": scope, "inc": _INC_1, "op": OP_TERMINAL_REPLAY, "seq": 1}, separators=(",", ":"), sort_keys=True).encode()),
            _b64url_cursor(json.dumps({"ep": 1, "fh": scope, "inc": _INC_1, "op": OP_TERMINAL_REPLAY, "seq": 0}, separators=(",", ":"), sort_keys=True).encode()),
            _b64url_cursor(json.dumps({"ep": 1, "fh": scope, "inc": _INC_1, "op": OP_TERMINAL_REPLAY, "seq": MAX_INT64 + 1}, separators=(",", ":"), sort_keys=True).encode()),
            _b64url_cursor(json.dumps({"ep": 1, "fh": "NOTHEX16CHARS!!", "inc": _INC_1, "op": OP_TERMINAL_REPLAY, "seq": 1}, separators=(",", ":"), sort_keys=True).encode()),
            _b64url_cursor(json.dumps({"ep": 1, "fh": scope, "inc": "bad\x00inc", "op": OP_TERMINAL_REPLAY, "seq": 1}, separators=(",", ":"), sort_keys=True).encode()),
            _b64url_cursor(json.dumps({"ep": 1, "extra": 1, "fh": scope, "inc": _INC_1, "op": OP_TERMINAL_REPLAY, "seq": 1}, separators=(",", ":"), sort_keys=True).encode()),
        )
        for bad_cursor in malformed_cases:
            with self.assertRaises(CoordValidationError) as m_ctx:
                decode_replay_cursor(
                    bad_cursor,
                    expected_scope_hash=scope,
                    expected_incarnation_id=_INC_1,
                    expected_stream_epoch=1,
                )
            self.assertIn(ERR_CURSOR_MALFORMED, str(m_ctx.exception))

        # Scope / incarnation / epoch mismatch
        other_scope = compute_replay_scope_hash(
            target=_TARGET_LOCAL,
            terminal_id=_SHELL,
            incarnation_id=_INC_1,
            stream_epoch=1,
        )
        with self.assertRaises(CoordValidationError) as s_ctx:
            decode_replay_cursor(
                valid,
                expected_scope_hash=other_scope,
                expected_incarnation_id=_INC_1,
                expected_stream_epoch=1,
            )
        self.assertIn(ERR_CURSOR_SCOPE_MISMATCH, str(s_ctx.exception))

        with self.assertRaises(CoordValidationError) as ep_ctx:
            decode_replay_cursor(
                valid,
                expected_scope_hash=scope,
                expected_incarnation_id=_INC_1,
                expected_stream_epoch=2,
            )
        self.assertIn(ERR_CURSOR_SCOPE_MISMATCH, str(ep_ctx.exception))

        with self.assertRaises(CoordValidationError) as inc_ctx:
            decode_replay_cursor(
                valid,
                expected_scope_hash=scope,
                expected_incarnation_id=_INC_2,
                expected_stream_epoch=1,
            )
        self.assertIn(ERR_CURSOR_SCOPE_MISMATCH, str(inc_ctx.exception))

    def test_allow_nan_false_and_json_roundtrip(self) -> None:
        for bad_val in (float("nan"), float("inf"), float("-inf")):
            payload = {"x": bad_val}
            with self.assertRaises(ValueError):
                serialize_terminal_json(payload)
            with self.assertRaises(ValueError):
                serialize_terminal_bytes(payload)

        store = TerminalReplayStore()
        store.register_stream(target=_TARGET_LOCAL, incarnation_id=_INC_1, terminal_id=_TUI)
        store.append_chunk(
            target=_TARGET_LOCAL,
            incarnation_id=_INC_1,
            terminal_id=_TUI,
            stream_epoch=1,
            frame_seq=1,
            raw_bytes=b"hello \xe2\x9c\x93\n",
            captured_at=42.25,
        )
        page = store.read_replay_frames(_OPERATOR, target=_TARGET_LOCAL, terminal_id=_TUI)
        parsed = json.loads(serialize_terminal_json(page))
        self.assertTrue(parsed["read_only"])
        self.assertTrue(parsed["untrusted_content"])
        self.assertEqual(parsed["frames"][0]["text"], "hello ✓\n")
        self.assertEqual(parsed["frames"][0]["captured_at"], 42.25)

        with self.assertRaises(CoordPolicyError) as nf_ctx:
            store.read_replay_frames(_OPERATOR, target="missing-sb", terminal_id=_TUI)
        self.assertIn(ERR_STREAM_NOT_FOUND, str(nf_ctx.exception))

    def test_esc_ignored_nul_del_padding_no_control_string_leak(self) -> None:
        # P2-1 regression: NUL/DEL padding inside ESC must not drop ESC and leak OSC/DCS bodies
        before_after = "beforeafter"
        cases = (
            (b"before\x1b\x00]0;HIDDEN\x07after", before_after, 1, 0),
            (b"before\x1b\x7fPSECRET\x1b\\after", before_after, 0, 1),
            (b"before\x1b\x00\x7f_KITTY_PAYLOAD\x1b\\after", before_after, 0, 1),
        )
        for raw, expected, exp_osc, exp_str in cases:
            for mode in (SanitizerMode.PLAIN, SanitizerMode.SAFE_SGR):
                out_full, st_full = sanitize_bytes(raw, mode=mode)
                out_split, st_split = _feed_chunked(raw, 1, mode=mode)
                self.assertEqual(out_full, expected)
                self.assertEqual(out_split, expected)
                self.assertEqual(st_full, st_split)
                self.assertEqual(st_full.dropped_osc_count, exp_osc)
                self.assertEqual(st_full.dropped_string_seq_count, exp_str)

        # Padded ESC \x00 [ 31 m in SAFE_SGR must consume CSI AND poison SAFE_SGR
        csi_out, csi_stats = _feed_chunked(
            b"before\x1b\x00[31mSAFE_TEXT", 1, mode=SanitizerMode.SAFE_SGR
        )
        self.assertEqual(csi_out, "beforeSAFE_TEXT")
        self.assertEqual(csi_stats.allowed_sgr_count, 0)
        self.assertEqual(csi_stats.dropped_csi_count, 1)

        # Overlong NUL padding before OSC must not double-count or leak OSC body
        flood = b"before\x1b" + (b"\x00" * 5000) + b"]0;HIDDEN\x07after"
        f_out, f_stats = sanitize_bytes(flood)
        self.assertEqual(f_out, before_after)
        self.assertEqual(f_stats.overlong_seq_dropped_count, 1)
        self.assertEqual(f_stats.dropped_esc_count + f_stats.dropped_osc_count, 1)

        # Explicit CAN (0x18) and SUB (0x1A) still abort pending ESC cleanly
        for abort_byte in (b"\x18", b"\x1a"):
            ab_out, ab_stats = _feed_chunked(b"\x1b" + abort_byte + b"ok", 1)
            self.assertEqual(ab_out, "ok")
            self.assertEqual(ab_stats.dropped_esc_count, 1)
            self.assertEqual(ab_stats.dropped_c0_c1_count, 1)

    def test_oversized_cursor_and_text_rejected_before_utf8_encode(self) -> None:
        # P2-2 regression: character length checked BEFORE .encode() allocation
        scope = compute_replay_scope_hash(
            target=_TARGET_LOCAL,
            terminal_id=_TUI,
            incarnation_id=_INC_1,
            stream_epoch=1,
        )
        oversize_ascii_cursor = _NoEncodeStr(f"{CURSOR_PREFIX}" + ("A" * (MAX_CURSOR_BYTES + 1)))
        non_ascii_cursor = _NoEncodeStr(f"{CURSOR_PREFIX}" + ("\U0001f525" * 300))
        for bad_cursor in (oversize_ascii_cursor, non_ascii_cursor):
            with self.assertRaises(CoordValidationError) as c_ctx:
                decode_replay_cursor(
                    bad_cursor,
                    expected_scope_hash=scope,
                    expected_incarnation_id=_INC_1,
                    expected_stream_epoch=1,
                )
            self.assertIn(ERR_CURSOR_MALFORMED, str(c_ctx.exception))

        # Malformed/oversized cursor is rejected BEFORE lock acquisition / target lookup
        store = TerminalReplayStore()
        with self.assertRaises(CoordValidationError) as pre_ctx:
            store.read_replay_frames(
                _OPERATOR,
                target="missing-sb",
                terminal_id=_TUI,
                after_cursor=oversize_ascii_cursor,
            )
        self.assertIn(ERR_CURSOR_MALFORMED, str(pre_ctx.exception))

        oversize_text = _NoEncodeStr("a" * (MAX_FEED_CHUNK_BYTES + 1))
        with self.assertRaises(CoordValidationError):
            sanitize_text_str(oversize_text)


if __name__ == "__main__":
    unittest.main()
