# PRD M3.3 Confined Read-Only Terminal Output Sanitizer & Replay Walkthrough (`docs/prds/spikes/m/terminal-observe/`)

Parent: [prd_m3.md](../../../prd_m3.md) · related: [prd_i2.md](../../../prd_i2.md) ·
[PROJECTION_WALKTHROUGH.md](../projection/PROJECTION_WALKTHROUGH.md) · builds read-only on
[oc_address.py](../oc_address.py) and [oc_coord_contract.py](../oc_coord_contract.py)

## 1. Scope, Boundaries, and Non-Goals

This Gate 1 walkthrough specifies the **standalone, offline, operator-only M3.3 read-only terminal
output sanitizer and bounded replay slice**. It provides an adversarial-grade stateful streaming
VT/UTF-8 scrubber, provenance-bound in-memory replay ring buffer, and deterministic offline
qualification fixtures so untrusted sandbox PTY bytes can never smuggle terminal escapes, clipboard
writes, answerback queries, bidi spoofing, or unbounded memory growth into Trusted Host Chrome or
confined terminal viewers.

### Owned File Boundary (Strictly Disjoint)

All documentation, code, and tests for this slice live exclusively under
`docs/prds/spikes/m/terminal-observe/`:

- `WALKTHROUGH.md` — this Gate 1 design walkthrough.
- `oc_terminal_contract.py` — frozen dataclasses, schema version and bounds constants,
  `SanitizerMode` enum, validation helpers, collision-free canonical base64url JSON cursor codec,
  and strict `allow_nan=False` UTF-8 JSON serializer.
- `oc_terminal_sanitizer.py` — stateful streaming VT/UTF-8 byte-stream sanitizer FSM
  (`TerminalOutputSanitizer`), strict RFC 3629 UTF-8 decoder, bounded O(1) escape/string-sequence
  draining, closed `SAFE_SGR` allowlist validator, UTF-8/SGR-safe truncation, and `SanitizerStats`.
- `oc_terminal_replay.py` — `TerminalReplayStore` (operator-only bounded in-memory replay ring
  store and paginated reader with per-sandbox incarnation fencing, monotonic `stream_epoch` and
  `frame_seq` enforcement, pre/post session & live-authority fencing, and hard end-to-end UTF-8
  JSON `max_response_bytes` enforcement).
- `test_terminal_observe.py` — exhaustive offline qualification suite (pure Python stdlib plus
  read-only imports from `docs/prds/spikes/m/`, zero live PTYs, zero Podman, zero network, zero
  writes to host directories).

**Zero edits to shared files:** This slice imports read-only from `oc_address.py` and
`oc_coord_contract.py` (`AddressError`, `TargetAddr`, `parse_canonical_addr`, `_BIDI_CODEPOINTS`,
`PrincipalCtx`, `CoordRole`, `validate_opaque_token`, `CoordValidationError`, `CoordAuthError`,
`CoordPolicyError`, `IncarnationMismatchError`, `RevokedError`). All `AddressError` exceptions
raised by `parse_canonical_addr` or `validate_opaque_token` are caught and converted to
`CoordValidationError` so callers receive one uniform validation exception hierarchy. It makes zero
edits outside `docs/prds/spikes/m/terminal-observe/`.

### Explicit Non-Goals (Deferred to Later Slices / Other Owners)

- **ZERO live PTY attachment:** No `podman exec`, `tmux`, `ssh`, `pty.openpty`, or host FD I/O.
- **ZERO input path:** No keyboard/mouse/paste input handling, no resize ioctls, no `InputLease`
  minting or writes, and no TUI Enter receipt generation.
- **ZERO network / UI transport:** No WebSockets, HTTP routes, SvelteKit/xterm.js iframe assets, or
  Tauri v2 IPC bridge.
- **ZERO non-operator read authority:** Standalone `TerminalReplayStore` is strictly
  `CoordRole.OPERATOR`-only (`sandbox_addr is None, incarnation_id is None`). `JOB`,
  `ORCHESTRATOR`, and `EXTERNAL_PEER` callers are unconditionally denied before any stream lookup.
- **ZERO SQLite / filesystem persistence:** Pure in-memory bounded ring buffer plus deterministic
  offline replay fixtures; no host state files or production paths are touched.
- **ZERO changes to production `oc-sandbox`, `oc-bridge.py`, shared spike modules, or any PRD
  `Human review` checkbox.**

---

## 2. Threat Model & Trust Boundaries

Every byte arriving from a sandbox PTY (`opencode-tui` or `shell`) is **untrusted, potentially
hostile output** (`untrusted_content = True`, `read_only = True`). A compromised sandbox agent can
attempt:

1. **Terminal escape exploitation & answerback injection:** Emitting OSC 52 (clipboard read/write),
   OSC 8 (spoofed hyperlinks), OSC 0/2/9/99/777/10/11 (window title/notification/palette spoofing),
   DCS/APC/PM/SOS (Sixel, Kitty graphics, iTerm2 inline images, tmux passthrough), CSI window
   manipulation (`CSI 8 t`), screen/scrollback clear or alternate-screen flips (`CSI 2 J`,
   `CSI ? 1049 h`), cursor repositioning (`CSI H`, `CSI A/B/C/D`), or terminal query answerbacks
   (`ENQ` `0x05`, `CSI 6 n` DSR, `CSI c` DA1, `CSI > c` DA2, `CSI > q` XTVERSION, `CSI ? ... $ p`
   DECRQM) to spoof Trusted Chrome or synthesize stdin keystrokes.
2. **8-bit C1 & UTF-8 C1 smuggling:** Sending raw 8-bit C1 introducers (`0x90` DCS, `0x98` SOS,
   `0x9B` CSI, `0x9D` OSC, `0x9E` PM, `0x9F` APC) OR their UTF-8 encoded equivalents
   (`0xC2 0x80`..`0xC2 0x9F` -> `U+0080..U+009F`) to bypass naive 7-bit `0x1B`-only filters.
3. **Adversarial chunk-boundary splitting:** Splitting UTF-8 multibyte characters (e.g., 3-byte
   `U+202E` RLO `0xE2 0x80 0xAE` or 2-byte `U+009B` `0xC2 0x9B`), `ESC ]` / `ESC [` / `ESC P` /
   `ESC \`, or `\r\n` pairs across arbitrary read boundaries (down to 1-byte chunks).
4. **Parser-differential & interleaved control smuggling:** Interleaving NUL (`0x00`), C0 controls,
   nested `ESC`, or incomplete UTF-8 lead bytes before `ESC` to desynchronize scrubber vs renderer
   state machines; using `SGR 8` (concealed/invisible text), private-prefix SGR (`CSI ? 1 m`,
   `CSI > 4;2 m`), colon subparameters (`CSI 38:2::... m`), or 24-bit RGB SGR to hide or spoof text.
5. **Visual spoofing in plain text:** Bare carriage return (`\r` not followed by `\n`) overwriting
   earlier text on the same line, Unicode bidi overrides/isolates (`_BIDI_CODEPOINTS`), NUL bytes,
   lone surrogates / UTF-8 surrogate bytes (`0xED 0xA0..0xBF`), and invalid UTF-8 sequences.
6. **Memory / CPU / response-size DoS:** Feeding unterminated multi-MiB OSC/DCS/CSI sequences to
   exhaust parser buffers, flooding replay rings with megabytes of output, or crafting JSON-escape-
   heavy text (`\"`, `\\`, `\n`) to blow past `max_response_bytes`.
7. **Cross-incarnation / stale-epoch / stale-session replay:** Feeding late frames from a retired
   `incarnation_id`, stale `stream_epoch`, or out-of-order `frame_seq`, or returning buffered frames
   after an operator's session generation or live authority was revoked mid-read.

---

## 3. Stateful Streaming Sanitizer FSM (`oc_terminal_sanitizer.py`)

### 3.1 Sanitizer Modes & Hard Parser Bounds

```python
class SanitizerMode(str, Enum):
    PLAIN = "plain"        # Default: strips ALL ANSI/VT escape sequences (including SGR)
    SAFE_SGR = "safe_sgr"  # Permits ONLY the closed basic SGR subset defined in Section 3.3

MAX_ESC_SEQ_BYTES = 4096                # Hard ceiling per escape/CSI/OSC/STRING_SEQ before overlong drop
MAX_SAFE_SGR_PARAM_BYTES = 64           # Hard CSI parameter buffer cap in SAFE_SGR mode
MAX_SAFE_SGR_PARAMS = 16                # Max semicolon-separated numeric SGR parameters
MAX_SAFE_SGR_VALUE = 255                # Max numeric value of any SGR parameter
MAX_FEED_CHUNK_BYTES = 4 * 1024 * 1024  # 4 MiB single feed() call ceiling
```

**Strict O(1) / bounded parser memory invariant:**
- `UTF8_PENDING` holds at most `3` bytes (`utf8_buf`).
- `CSI` holds at most `MAX_SAFE_SGR_PARAM_BYTES` (`64` bytes) in `SAFE_SGR` mode and `0` bytes in
  `PLAIN` mode.
- `ESC`, `ESC_INTERMEDIATE`, `OSC`, and `STRING_SEQ` hold **`0` bytes** of payload buffer (only
  O(1) scalar state: `seq_bytes`, `seq_overlong`, `seq_counted`, `esc_seen`, plus strict RFC 3629
  UTF-8 continuation tracking `str_utf8_rem`, `str_utf8_min`, `str_utf8_max`, `str_utf8_is_c2`).
- An unterminated 1 MiB or 100 MiB OSC/DCS/APC/PM/SOS/CSI sequence therefore consumes **O(1) RAM**
  and leaks **zero** payload bytes to display output.

### 3.2 Seven-State Streaming FSM & Exact Transitions

`TerminalOutputSanitizer` maintains one explicit `state` enum in:
`GROUND`, `UTF8_PENDING`, `ESC`, `ESC_INTERMEDIATE`, `CSI`, `OSC`, `STRING_SEQ`, plus a 1-bit
`pending_cr: bool` latch for chunk-split `\r\n` normalization.

**Strict `MAX_ESC_SEQ_BYTES` accounting rule (applies uniformly across ALL sequence states):**
Every byte consumed as part of an active sequence — including introducer bytes, parameter bytes,
intermediate bytes, C0/DEL bytes drained inside `CSI` or `ESC_INTERMEDIATE`, payload bytes inside
`OSC`/`STRING_SEQ`, and the completing final or terminator byte (`m`, `BEL`, `0x9C`, `0xC2 0x9C`,
`ESC \`) — increments `seq_bytes` and executes the `seq_bytes > MAX_ESC_SEQ_BYTES` check. A byte
that aborts the current sequence to begin a *new* sequence (nested `ESC` followed by non-`\`, or a
standalone raw/UTF-8 C1 introducer) does not charge the aborted sequence; instead it opens the new
sequence with its own `seq_bytes`.

#### State Transition Table

| Current State | Incoming Byte / Condition | Action & Output | Next State | Stats Incremented |
|---|---|---|---|---|
| `GROUND` (`pending_cr=True`) | `0x0A` (`\n`) | Clear `pending_cr`; emit `"\n"` (completes CRLF pair) | `GROUND` | *(none)* |
| `GROUND` (`pending_cr=True`) | Any byte `!= 0x0A` | Clear `pending_cr`; emit `"\n"` (neutralize bare CR), then **re-dispatch current byte** in `GROUND` | *(per re-dispatch)* | `neutralized_bare_cr_count += 1`, `dropped_c0_c1_count += 1` |
| `GROUND` | `0x0D` (`\r`) | Set `pending_cr = True` | `GROUND` | *(none yet; resolved on next byte or `flush()`)* |
| `GROUND` | `0x09` (`\t`) or `0x0A` (`\n`) or `0x20..0x7E` | Emit `chr(b)` | `GROUND` | *(none)* |
| `GROUND` | `0x1B` (`ESC`) | Reset seq counters (`seq_bytes=1`) | `ESC` | *(none yet)* |
| `GROUND` | Other C0 (`0x00..0x1F`) or `0x7F` (`DEL`) | Drop byte | `GROUND` | `dropped_c0_c1_count += 1` |
| `GROUND` | Raw 8-bit C1 `0x9B` (CSI) | Enter `CSI(from_c1=True, csi_valid=False, seq_bytes=1)` | `CSI` | `dropped_c0_c1_count += 1` |
| `GROUND` | Raw 8-bit C1 `0x9D` (OSC) | Enter `OSC(from_c1=True, seq_bytes=1, str_utf8_rem=0)` | `OSC` | `dropped_c0_c1_count += 1` |
| `GROUND` | Raw 8-bit C1 `0x90`/`0x98`/`0x9E`/`0x9F` (DCS/SOS/PM/APC) | Enter `STRING_SEQ(from_c1=True, seq_bytes=1, str_utf8_rem=0)` | `STRING_SEQ` | `dropped_c0_c1_count += 1` |
| `GROUND` | Other raw 8-bit C1 `0x80..0x9F` | Drop byte | `GROUND` | `dropped_c0_c1_count += 1` |
| `GROUND` | Valid UTF-8 lead `0xC2..0xF4` | Initialize `utf8_buf=[b]` + RFC 3629 2nd-byte bounds (`_utf8_min_next`, `_utf8_max_next`) | `UTF8_PENDING` | *(none yet)* |
| `GROUND` | Invalid UTF-8 (`0xA0..0xBF`, `0xC0`, `0xC1`, `0xF5..0xFF`) | Emit `"\ufffd"` | `GROUND` | `invalid_utf8_count += 1` |
| `UTF8_PENDING` | Valid continuation byte in `[_utf8_min_next, _utf8_max_next]` | Append to `utf8_buf`, **immediately reset `_utf8_min_next=0x80, _utf8_max_next=0xBF`** for bytes 3/4; if complete, decode scalar `cp` -> dispatch `cp` (below) | `UTF8_PENDING` or `GROUND` (or C1 state) | *(per decoded `cp`)* |
| `UTF8_PENDING` | Invalid / unexpected byte (incl. `0x1B`, C0, new lead, bad continuation) | Emit `"\ufffd"`, clear `utf8_buf`, reset `_utf8_min_next=0x80, _utf8_max_next=0xBF`, **re-dispatch current byte in `GROUND`** | *(per re-dispatch)* | `invalid_utf8_count += 1` |
| `ESC` | `0x5B` (`[`) | Promote to `CSI` preserving `seq_bytes`/`seq_overlong`/`seq_counted`, charge `+1` + overlong check; `csi_valid = (mode is SAFE_SGR and seq_bytes == 2 and not seq_overlong)` (poisons CSI if C0/DEL padding preceded `[`), `from_c1=False` | `CSI` | If overlong (once): `overlong_seq_dropped_count += 1`, `dropped_csi_count += 1` |
| `ESC` | `0x5D` (`]`) | Promote to `OSC` preserving `seq_bytes`/`seq_overlong`/`seq_counted`, charge `+1` + overlong check; `from_c1=False`, `esc_seen=False`, `str_utf8_rem=0`, `str_utf8_is_c2=False` | `OSC` | If overlong (once): `overlong_seq_dropped_count += 1`, `dropped_osc_count += 1` |
| `ESC` | `0x50` (`P`), `0x58` (`X`), `0x5E` (`^`), `0x5F` (`_`) | Promote to `STRING_SEQ` preserving `seq_bytes`/`seq_overlong`/`seq_counted`, charge `+1` + overlong check; `from_c1=False`, `esc_seen=False`, `str_utf8_rem=0`, `str_utf8_is_c2=False` | `STRING_SEQ` | If overlong (once): `overlong_seq_dropped_count += 1`, `dropped_string_seq_count += 1` |
| `ESC` | `0x20..0x2F` (intermediate) | Promote to `ESC_INTERMEDIATE` preserving `seq_bytes`/`seq_overlong`/`seq_counted`, charge `+1` + overlong check | `ESC_INTERMEDIATE` | If overlong (once): `overlong_seq_dropped_count += 1`, `dropped_esc_count += 1` |
| `ESC` | `0x30..0x7E` (Fe/Fp/Fs final, e.g. `ESC c` RIS) | Charge `+1` + overlong check; drop sequence | `GROUND` | `dropped_esc_count += 1` (if not already counted) |
| `ESC` | `0x1B` (nested `ESC`) | Drop previous `ESC`, restart `ESC(seq_bytes=1)` | `ESC` | `dropped_esc_count += 1` (if not already counted) |
| `ESC` | `0x18` (`CAN`) / `0x1A` (`SUB`) | Abort & drop `ESC` | `GROUND` | `dropped_esc_count += 1` (if not counted), `dropped_c0_c1_count += 1` |
| `ESC` | Other C0 (`0x00..0x1F`) or `0x7F` (`DEL`) (ignored VT padding) | Charge `seq_bytes += 1` + overlong check; **stay in `ESC`** so padded `ESC \x00 ]` / `ESC \x7f P` still enters `OSC`/`STRING_SEQ` instead of leaking control-string payload | `ESC` | `dropped_c0_c1_count += 1` (+ overlong once if `> MAX_ESC_SEQ_BYTES`) |
| `ESC` | `>= 0x80` (C1 or high byte) | Drop `ESC`, **re-dispatch current byte in `GROUND`** | *(per re-dispatch)* | `dropped_esc_count += 1` (if not already counted) |
| `ESC_INTERMEDIATE` | `0x20..0x2F` | Increment `seq_bytes` + overlong check `> MAX_ESC_SEQ_BYTES` | `ESC_INTERMEDIATE` | If overlong (once): `overlong_seq_dropped_count += 1`, `dropped_esc_count += 1` |
| `ESC_INTERMEDIATE` | `0x30..0x7E` (final) | Increment `seq_bytes` + overlong check; drop sequence | `GROUND` | `dropped_esc_count += 1` (if not already counted) |
| `ESC_INTERMEDIATE` | `0x1B` | Drop sequence, restart `ESC(seq_bytes=1)` | `ESC` | `dropped_esc_count += 1` (if not counted) |
| `ESC_INTERMEDIATE` | `0x18` (`CAN`) / `0x1A` (`SUB`) | Abort & drop sequence | `GROUND` | `dropped_esc_count += 1` (if not counted), `dropped_c0_c1_count += 1` |
| `ESC_INTERMEDIATE` | Other C0 (`0x00..0x1F`) or `0x7F` (`DEL`) | Increment `seq_bytes` + overlong check; **stay draining `ESC_INTERMEDIATE`** until final/abort so e.g. `ESC ( \x00 B` never leaks `"B"` | `ESC_INTERMEDIATE` | `dropped_c0_c1_count += 1` (+ overlong once if `> MAX_ESC_SEQ_BYTES`) |
| `ESC_INTERMEDIATE` | `>= 0x80` (C1 or high byte) | Abort & drop sequence, **re-dispatch byte in `GROUND`** | *(per re-dispatch)* | `dropped_esc_count += 1` (if not counted) |
| `CSI` | `0x30..0x3F` (param) | Increment `seq_bytes` + overlong check; buffer ONLY if `csi_valid`, no intermediates, `b in 0-9;`, and `len(csi_buf) < 64`, else `csi_valid = False` | `CSI` | If overlong (once): `overlong_seq_dropped_count += 1`, `dropped_csi_count += 1` |
| `CSI` | `0x20..0x2F` (intermediate) | Increment `seq_bytes` + overlong check; `csi_valid = False`, clear `csi_buf` | `CSI` | If overlong (once): `overlong_seq_dropped_count += 1`, `dropped_csi_count += 1` |
| `CSI` | `0x40..0x7E` (final) | Increment `seq_bytes` + overlong check FIRST; if `csi_valid` and `b == ord('m')` and `not from_c1` and `not seq_overlong` and `_is_allowed_safe_sgr(csi_buf)`: emit `"\x1b[" + params + "m"`; else drop | `GROUND` | `allowed_sgr_count += 1` OR `dropped_csi_count += 1` (if not counted) |
| `CSI` | `0x1B` (nested `ESC`) | Abort & drop CSI, restart `ESC(seq_bytes=1)` | `ESC` | `dropped_csi_count += 1` (if not counted) |
| `CSI` | `0x18` (`CAN`) / `0x1A` (`SUB`) | Abort & drop CSI | `GROUND` | `dropped_csi_count += 1` (if not counted), `dropped_c0_c1_count += 1` |
| `CSI` | Other C0 (`0x00..0x1F`) or `0x7F` (`DEL`) | Increment `seq_bytes` + overlong check; poison CSI (`csi_valid = False`, clear `csi_buf`), stay draining CSI until final/abort | `CSI` | `dropped_c0_c1_count += 1` (+ overlong once if `> MAX_ESC_SEQ_BYTES`) |
| `CSI` | `>= 0x80` (C1 or high byte) | Abort & drop CSI, **re-dispatch byte in `GROUND`** | *(per re-dispatch)* | `dropped_csi_count += 1` (if not counted) |
| `OSC` / `STRING_SEQ` | `esc_seen=True` and `b == 0x5C` (`\`, ST) | `esc_seen=False`; increment `seq_bytes += 2` (for `ESC \`) + overlong check; complete & drop sequence | `GROUND` | `dropped_osc_count` or `dropped_string_seq_count` += 1 (if not counted) |
| `OSC` / `STRING_SEQ` | `esc_seen=True` and `b != 0x5C` | `esc_seen=False`; abort & drop string sequence; enter `ESC(seq_bytes=1)` and **immediately process `b` in `ESC`** | *(per `ESC`)* | `dropped_osc_count` or `dropped_string_seq_count` += 1 (if not counted) |
| `OSC` / `STRING_SEQ` | `str_utf8_rem > 0` and `str_utf8_min <= b <= str_utf8_max` (valid UTF-8 continuation) | Decrement `str_utf8_rem -= 1`; reset `str_utf8_min=0x80, str_utf8_max=0xBF`. If `str_utf8_is_c2`: clear `str_utf8_is_c2=False`; if `b == 0x9C` (UTF-8 ST) -> `seq_bytes += 2` (for `0xC2 0x9C`) + overlong check, drop & return to `GROUND`; if `b in (0x90, 0x98, 0x9B, 0x9D, 0x9E, 0x9F)` (UTF-8 C1 introducer) -> abort & drop current seq, bump `dropped_c0_c1_count`, enter new C1 seq (`from_c1=True, seq_bytes=2`); else `seq_bytes += 2` (for `0xC2 b`) + overlong check, discard. If `not str_utf8_is_c2` (3/4-byte or `0xC3..0xDF` continuation, e.g., `“`, `”`, `‛`, `←`, `🚀`) -> `seq_bytes += 1` + overlong check, discard as payload (**NEVER fires raw 8-bit C1 rules!**). | `OSC` / `STRING_SEQ` (or `GROUND`/new C1 seq for `0xC2` ST/introducer) | Overlong (once) if `> MAX_ESC_SEQ_BYTES`; drop counter on ST/abort |
| `OSC` / `STRING_SEQ` | `str_utf8_rem > 0` and byte out of `[str_utf8_min, str_utf8_max]` (invalid UTF-8 continuation, e.g., `0xE2` followed by `0x1B \`) | If `str_utf8_is_c2`: charge deferred `seq_bytes += 1` + overlong check for the orphaned `0xC2`. Clear `str_utf8_rem=0, str_utf8_min=0x80, str_utf8_max=0xBF, str_utf8_is_c2=False` and **immediately fall through to normal `OSC`/`STRING_SEQ` byte dispatch below** | *(per normal dispatch below)* | *(per normal dispatch)* |
| `OSC` / `STRING_SEQ` | Raw 8-bit C1 introducer (`0x90`, `0x98`, `0x9B`, `0x9D`, `0x9E`, `0x9F`) when `str_utf8_rem == 0` | Abort & drop sequence, **re-dispatch C1 byte in `GROUND`** | *(per C1)* | `dropped_osc_count`/`dropped_string_seq_count` += 1 (if not counted) |
| `OSC` | `0x07` (`BEL`) | Increment `seq_bytes += 1` + overlong check; complete & drop OSC | `GROUND` | `dropped_osc_count += 1` (if not counted) |
| `OSC` / `STRING_SEQ` | `0x9C` (raw 8-bit ST when `str_utf8_rem == 0`) | Increment `seq_bytes += 1` + overlong check; complete & drop sequence | `GROUND` | `dropped_osc_count` or `dropped_string_seq_count` += 1 (if not counted) |
| `OSC` / `STRING_SEQ` | `0x18` (`CAN`) / `0x1A` (`SUB`) | Increment `seq_bytes += 1` + overlong check; abort & drop sequence | `GROUND` | `dropped_osc_count`/`dropped_string_seq_count` += 1 (if not counted), `dropped_c0_c1_count += 1` |
| `OSC` / `STRING_SEQ` | `0x1B` | Set `esc_seen = True` (`seq_bytes` deferred until `\` or `flush()` so a nested `ESC` aborting into a new sequence doesn't miscount) | `OSC` / `STRING_SEQ` | *(resolved on next byte or `flush()`)* |
| `OSC` / `STRING_SEQ` | Valid UTF-8 lead `0xC2..0xF4` | If `b == 0xC2`: defer `seq_bytes` charge until byte 2 or `flush()` (matching `0x1B` above so a byte-4097 UTF-8 C1 introducer doesn't miscount), else increment `seq_bytes += 1` + overlong check; set `(str_utf8_rem, str_utf8_min, str_utf8_max)` from the RFC 3629 lead table and `str_utf8_is_c2 = (b == 0xC2)` | `OSC` / `STRING_SEQ` | If overlong (once): `overlong_seq_dropped_count += 1` + seq drop counter |
| `OSC` / `STRING_SEQ` | Any other byte | Discard in O(1) memory; increment `seq_bytes += 1` + overlong check | `OSC` / `STRING_SEQ` | If overlong (once): `overlong_seq_dropped_count += 1` + seq drop counter |

#### Decoded UTF-8 Scalar Dispatch (on completing `UTF8_PENDING`)

Strict RFC 3629 2nd-byte bounds enforced before decoding (shared with `OSC`/`STRING_SEQ` UTF-8
continuation tracking); immediately after consuming byte 2 of any 3- or 4-byte sequence,
`_utf8_min_next` and `_utf8_max_next` reset to `0x80` and `0xBF` so bytes 3 and 4 allow the full
RFC 3629 continuation range:
- `0xC2..0xDF` (2-byte): 2nd byte `0x80..0xBF`
- `0xE0` (3-byte): 2nd byte `0xA0..0xBF` (blocks overlong 3-byte; 3rd byte `0x80..0xBF`)
- `0xE1..0xEC`, `0xEE..0xEF` (3-byte): 2nd byte `0x80..0xBF`
- `0xED` (3-byte): 2nd byte `0x80..0x9F` (blocks UTF-8 surrogates `U+D800..U+DFFF`; 3rd byte `0x80..0xBF`)
- `0xF0` (4-byte): 2nd byte `0x90..0xBF` (blocks overlong 4-byte; 3rd & 4th bytes `0x80..0xBF`)
- `0xF1..0xF3` (4-byte): 2nd byte `0x80..0xBF`
- `0xF4` (4-byte): 2nd byte `0x80..0x8F` (blocks `> U+10FFFF`; 3rd & 4th bytes `0x80..0xBF`)

When a valid scalar `cp` completes:
1. If `0x80 <= cp <= 0x9F` (UTF-8 encoded C1 control, e.g., `0xC2 0x9B` -> `U+009B`):
   - Increment `dropped_c0_c1_count += 1`.
   - `0x9B` -> enter `CSI(from_c1=True, csi_valid=False, seq_bytes=2)`.
   - `0x9D` -> enter `OSC(from_c1=True, seq_bytes=2, str_utf8_rem=0)`.
   - `0x90`, `0x98`, `0x9E`, `0x9F` -> enter `STRING_SEQ(from_c1=True, seq_bytes=2, str_utf8_rem=0)`.
   - All other `0x80..0x9F` -> dropped in `GROUND`.
2. Else if `cp in _BIDI_CODEPOINTS` (imported from `oc_address.py`: `U+202A..U+202E`, `U+2066..U+2069`, `U+200E`, `U+200F`, `U+061C`):
   - Drop character; increment `dropped_bidi_count += 1`.
3. Else:
   - Emit `chr(cp)`.

#### End-of-Stream `flush()` Semantics

When `flush()` is called (stream close or fixture completion):
- If `pending_cr`: emit `"\n"`, increment `neutralized_bare_cr_count += 1` and `dropped_c0_c1_count += 1`, clear `pending_cr`.
- If `state == UTF8_PENDING`: emit `"\ufffd"`, increment `invalid_utf8_count += 1`, clear `utf8_buf`, reset `_utf8_min_next=0x80, _utf8_max_next=0xBF`, reset to `GROUND`.
- If `state in (ESC, ESC_INTERMEDIATE, CSI, OSC, STRING_SEQ)`:
  - If `state in (OSC, STRING_SEQ)` and `(esc_seen or str_utf8_is_c2)`: increment `seq_bytes += 1` and run the overlong check once (accounting for the deferred trailing `0x1B` or `0xC2` byte before resetting both flags; note `esc_seen` and `str_utf8_is_c2` are mutually exclusive).
  - Increment the matching drop counter (`dropped_esc_count`, `dropped_csi_count`, `dropped_osc_count`, or `dropped_string_seq_count`) if `not seq_counted`, clear all sequence state (including `esc_seen`, `str_utf8_rem`, `str_utf8_min`, `str_utf8_max`, `str_utf8_is_c2`), reset to `GROUND`.
- `flush()` is idempotent on an already-ground sanitizer (calling `flush()` twice produces `""` with zero double-counting).

#### Chunk-Split Invariance Property

Because every transition operates strictly byte-by-byte across persistent FSM state, for **any**
raw byte payload `B` and **any** partition `B = b_1 || b_2 || ... || b_k` (including 1-byte
chunks):
```text
"".join(s1.feed(b_i) for b_i in partition) + s1.flush() == s2.feed(B) + s2.flush()
s1.stats == s2.stats
```

#### Overlong Sequence Zero-Tail-Leakage Property

When an `OSC`, `STRING_SEQ`, `CSI`, or `ESC_INTERMEDIATE` sequence exceeds `MAX_ESC_SEQ_BYTES`
(`4096`):
- `overlong_seq_dropped_count` AND the corresponding sequence drop counter increment **immediately**
  upon crossing byte `4097` (setting `seq_counted = True` so later termination/`flush()` does not
  double-count).
- The parser stays in its O(1)-memory drain state until the sequence terminator (`ST`, `BEL` for
  OSC, `CAN`/`SUB`, nested `ESC`, C1 introducer, or `flush()`), guaranteeing **zero** tail bytes
  from a 10 KiB or 1 MiB OSC 52 / DCS Sixel payload ever leak into visible terminal output.

### 3.3 Closed `SAFE_SGR` Allowlist Grammar

In `SanitizerMode.PLAIN`, ALL CSI sequences are dropped (`allowed_sgr_count` is always `0`).

In `SanitizerMode.SAFE_SGR`, a CSI sequence is emitted **if and only if** ALL of the following hold:
1. Introducer was 7-bit `ESC [` (`from_c1 is False`) — 8-bit `0x9B` and UTF-8 `U+009B` are ALWAYS
   rejected.
2. Total sequence length `<= MAX_ESC_SEQ_BYTES` and no C0/DEL byte occurred inside the sequence.
3. Zero intermediate bytes (`0x20..0x2F`).
4. Final byte is strictly `'m'` (`0x6D`).
5. Parameter string length `<= MAX_SAFE_SGR_PARAM_BYTES` (`64`), containing ONLY ASCII digits
   `'0'..'9'` and `';'` (unconditionally rejects private prefixes `'?'`, `'>'`, `'='`, `'<'` and
   colon subparameters `':'`).
6. Either parameter string is empty (`""`, canonical SGR reset `ESC [ m`), OR splitting on `';'`
   produces `1..MAX_SAFE_SGR_PARAMS` (`1..16`) non-empty tokens, each strictly `1..3` ASCII digits
   (`0 <= int(tok) <= 255`, rejecting empty `;;` tokens and leading-zero padding DoS).
7. Walking the parsed integer list `nums` sequentially with index `i`:
   - `nums[i]` in `_BASIC_SAFE_SGR_CODES`:
     `{0, 1, 2, 3, 4, 7, 9, 22, 23, 24, 27, 29} | set(range(30, 38)) | {39} | set(range(40, 48)) | {49} | set(range(90, 98)) | set(range(100, 108))`
     -> advance `i += 1`.
     *(Explicitly excludes `5`/`6` blink and `8` concealed/invisible text spoofing!)*
   - `nums[i] in (38, 48)` (extended foreground/background):
     - MUST have `i + 2 < len(nums)` AND `nums[i + 1] == 5` (8-bit indexed color ONLY) AND
       `0 <= nums[i + 2] <= 255` -> advance `i += 3`.
     - **Unconditionally rejects** `38;2;R;G;B` / `48;2;R;G;B` (24-bit truecolor), `58;...`
       (underline color), truncated `38` / `38;5`, and any sub-selector `!= 5`!
   - Any other code -> **reject the entire CSI sequence** (`dropped_csi_count += 1`).

### 3.4 `SanitizerStats` & SGR-Safe Truncation

```python
@dataclass(frozen=True, slots=True)
class SanitizerStats:
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
```

- `to_dict()` emits all 12 integer counters explicitly.
- `to_compact_dict()` emits `input_bytes`, `output_bytes`, plus every non-zero diagnostic counter
  (used inside `TerminalReplayPage.to_dict()` for both `stream_stats` and per-frame `frame_stats`
  so 1 KiB response budgets retain ample room for escape-heavy frame text without losing any
  non-zero anomaly telemetry; Python dataclasses retain full typed 12-field `SanitizerStats`).
- **O(1) Cross-Frame Active SGR State & Self-Contained Frame Invariant (`SAFE_SGR` mode):**
  - `TerminalOutputSanitizer` maintains a fixed-size 8-slot O(1) active SGR state (`bold: bool` [SGR
    `1`], `faint: bool` [SGR `2`], `italic: bool` [`3`], `underline: bool` [`4`], `inverse: bool`
    [`7`], `strike: bool` [`9`], `fg` [16-color or `38;5;N`], `bg` [16-color or `48;5;N`]), exposed
    via `active_sgr_seq: str` (canonical `"\x1b[<codes>m"` <= 34 bytes, strictly
    `<= MAX_SAFE_SGR_PARAM_BYTES`; `""` in `PLAIN` mode or when all attributes are default). `bold`
    and `faint` are tracked as **independent booleans** so both `1` and `2` are preserved across a
    frame boundary when both are active; every accepted `SAFE_SGR` sequence updates the 8-slot state
    (`ESC[m` / `ESC[0m` clears all slots to `""`; SGR `22` clears **both** `bold` and `faint`;
    partial resets `23`/`24`/`27`/`29`/`39`/`49` clear only their corresponding slot).
  - **Self-contained replay frame invariant:** Every stored and paged `SAFE_SGR` replay frame
    strictly **starts and ends in default terminal style** while preserving cross-frame styling:
    1. Before feeding `raw_bytes` into `stream.sanitizer.feed(raw_bytes)`, capture
       `prefix_sgr = stream.sanitizer.active_sgr_seq`.
    2. After `clean_chunk = stream.sanitizer.feed(raw_bytes)`, if `clean_chunk != ""`:
       - If `prefix_sgr != ""` and `not clean_chunk.startswith(("\x1b[0m", "\x1b[m"))`, prepend
         `prefix_sgr` so styles opened in an earlier frame carry seamlessly into this frame.
       - If `stream.sanitizer.active_sgr_seq != ""` (style still open at end of chunk), append
         `"\x1b[0m"` so the frame ends in default style.
    3. If `clean_chunk == ""` (e.g., chunk contained only dropped OSC/CSI), emit `""` without
       spurious SGR wrappers while preserving `stream.sanitizer.active_sgr_seq` for the next
       non-empty frame.
    4. Every stored `SAFE_SGR` frame is therefore 100% self-contained whether viewed standalone,
       evicted past earlier frames, truncated at `MAX_FRAME_TEXT_BYTES`, or split across a
       `max_response_bytes` page boundary!
- **SGR-boundary-safe & reset-closed UTF-8 truncation (`truncate_sanitized_text_utf8(text, max_bytes, mode)`):**
  - If `len(text.encode("utf-8")) <= max_bytes`, returns `(text, utf8_len, False)` untouched.
  - Truncates `text` to `<= max_bytes` UTF-8 bytes without splitting any multibyte Unicode character.
  - When `mode is SanitizerMode.SAFE_SGR`:
    1. If the cut point falls inside an emitted `\x1b[...m` sequence (after `\x1b` before its
       terminating `'m'`), backs the cut point up to right before that `\x1b` so a truncated frame
       NEVER emits a dangling partial escape sequence.
    2. Evaluates `_sgr_is_open(prefix)` using the exact 8-slot SGR state machine over `prefix`
       (handling cumulative SGRs, partial resets, full resets `ESC[0m`/`ESC[m`, and prepended
       cross-frame `prefix_sgr`). Whenever `_sgr_is_open(prefix)` is `True`, reserves `4` UTF-8
       bytes for `"\x1b[0m"` within `max_bytes` (re-cutting the prefix at a UTF-8 + SGR boundary
       within `max_bytes - 4` if needed) and appends `"\x1b[0m"` whenever `_sgr_is_open` remains
       `True`. (When shrinking inside `max_response_bytes` JSON serialization, Section 5.4 accounts
       for JSON's 6-byte `\u001b` expansion — `9` UTF-8 JSON bytes for `"\x1b[0m"`!)
- **String helper (`sanitize_text_str`):** For fixtures passing Python `str` values (including lone
  surrogates `"\ud800"`..`"\udfff"`), encodes via `utf-8` (`surrogatepass`) through a fresh
  `TerminalOutputSanitizer` + `flush()`, ensuring lone surrogates are rejected by the RFC 3629
  decoder and never survive into output.

---

## 4. Caller Authority & Pre/Post Session-Generation Fencing (`oc_terminal_replay.py`)

`TerminalReplayStore.read_replay_frames(...)` enforces the exact same fail-closed operator-only
authority and session-generation fencing model as `ReadOnlyProjectionService`:

### 4.1 Strict Operator-Only Admission

Checked **before** any stream lookup (eliminating any target-existence oracle for non-operators):

```python
def authorize_operator_caller(caller: object) -> PrincipalCtx:
    if not isinstance(caller, PrincipalCtx):
        raise CoordValidationError("caller must be PrincipalCtx")
    if caller.role is not CoordRole.OPERATOR:
        raise CoordAuthError("operator_role_required")
    if caller.sandbox_addr is not None or caller.incarnation_id is not None:
        raise CoordAuthError("operator_principal_must_not_bind_sandbox")
    return caller
```

### 4.2 Mandatory Pre-Read and Post-Read Session & Live-Authority Fencing

`TerminalReplayStore` accepts two optional host-side authority callbacks:
- `session_validator: Callable[[PrincipalCtx, str, int], bool] | None = None`
- `live_authority_checker: Callable[[PrincipalCtx], bool] | None = None`

Exact fail-closed rules:
1. Supplying only one of `(read_session_id, session_generation)` raises
   `CoordValidationError("read_session_pair_required")`.
2. When `(read_session_id, session_generation)` are supplied:
   - Validate `read_session_id` via `validate_terminal_token(read_session_id, "read_session_id")`
     (wraps `validate_opaque_token` and converts any `AddressError` to `CoordValidationError`).
   - Validate `type(session_generation) is int and 1 <= session_generation <= MAX_INT64`.
   - If `session_validator is None`, raise `CoordPolicyError("read_session_validator_unconfigured")`.
3. When `session_validator is not None`:
   - Omitting `(read_session_id, session_generation)` raises `CoordAuthError("read_session_required")`.
   - Call `session_validator(caller, read_session_id, session_generation)` **both before** snapshotting
     the ring buffer **and after** building the bounded page **before returning**.
   - Require strict `result is True`; any non-`True` return or raised exception raises
     `RevokedError("read_session_retired")` and returns zero frames.
4. When `live_authority_checker is not None`:
   - Call `live_authority_checker(caller)` **both before** snapshotting **and after** building the
     page **before returning**.
   - Require strict `result is True`; any non-`True` return or raised exception raises
     `RevokedError("read_authority_revoked")` and returns zero frames.
5. Echo validated `(read_session_id, session_generation)` as `ReadSessionEcho` on the returned
   `TerminalReplayPage`.

---

## 5. Bounded Replay Store, Provenance Binding, Cursors, & Hard Byte Caps

### 5.1 Hard Bounds (`oc_terminal_contract.py`)

```python
TERMINAL_OBSERVE_SCHEMA_VERSION = "oc.m3.terminal_observe@1"
VALID_TERMINAL_IDS: frozenset[str] = frozenset({"opencode-tui", "shell"})

MAX_ESC_SEQ_BYTES = 4096
MAX_SAFE_SGR_PARAM_BYTES = 64
MAX_SAFE_SGR_PARAMS = 16
MAX_SAFE_SGR_VALUE = 255
MAX_FEED_CHUNK_BYTES = 4 * 1024 * 1024

MAX_FRAME_TEXT_BYTES = 16 * 1024
DEFAULT_MAX_RING_FRAMES = 512
MAX_RING_FRAMES = 4096
DEFAULT_MAX_RING_BYTES = 1024 * 1024
MAX_RING_BYTES = 8 * 1024 * 1024        # Matches prd_m3.md 8 MiB host ring bound
MAX_TRACKED_SANDBOXES = 64
MAX_RETIRED_INCARNATIONS = 1024

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200
MIN_RESPONSE_BYTES = 1024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_CURSOR_BYTES = 512
MAX_INT64 = (1 << 63) - 1
```

All integer parameters reject `bool`, `float`, and out-of-range values with `CoordValidationError`.
All `captured_at` timestamps require `type(ts) in (int, float)` with `math.isfinite(ts)` and
`ts >= 0.0` (rejecting `bool`, `NaN`, `+Inf`, `-Inf`, and negative numbers with
`CoordValidationError`).

### 5.2 Target Addressing, Provenance Tuple, & Incarnation/Epoch Fencing

- **Target & token validation (`parse_terminal_target`, `validate_terminal_token`):**
  - `parse_terminal_target(target)` calls `parse_canonical_addr(target)` and catches `AddressError`,
    converting it to `CoordValidationError`. Accepts `"local"` (`"NAME"`) and `"remote"`
    (`"REMOTE / NAME"`) sandboxes; rejects `"@PEER"`, invalid syntax, non-`str`, surrogates, and
    control/bidi characters with `CoordValidationError`.
  - `validate_terminal_token(value, label)` wraps `validate_opaque_token(value, label)` and catches
    `AddressError`, converting it to `CoordValidationError`. Used uniformly for `incarnation_id`,
    `read_session_id`, and cursor `inc`.
- **Every `TerminalReplayFrame` binds the full 6-tuple:**
  `(sandbox_addr, incarnation_id, terminal_id, stream_epoch, frame_seq, captured_at)`
  plus `text`, `text_bytes`, `text_truncated`, `original_sanitized_bytes`, `raw_input_bytes`,
  `frame_stats`, and `untrusted_content = True`.
- **Per-sandbox incarnation fencing & fail-closed capacity limits:**
  - Each registered `sandbox_addr` tracks ONE `active_incarnation_id` shared across both
    `"opencode-tui"` and `"shell"`, plus a non-evicting set `retired_incarnations`.
  - **Fail-closed sandbox capacity (`MAX_TRACKED_SANDBOXES = 64`):** Registering a brand-new
    `sandbox_addr` when `len(self._sandboxes) >= MAX_TRACKED_SANDBOXES` fails closed with
    `CoordPolicyError("max_tracked_sandboxes_exceeded")` (zero state mutated).
  - **Fail-closed retired-incarnation capacity (`MAX_RETIRED_INCARNATIONS = 1024`):** Entries are
    **NEVER evicted** from `retired_incarnations` (eviction would allow stale incarnation reuse).
    Rotating a sandbox to a new `incarnation_id` when
    `len(sb.retired_incarnations) >= MAX_RETIRED_INCARNATIONS` fails closed with
    `CoordPolicyError("max_retired_incarnations_exceeded")` before mutating `active_incarnation_id`,
    `retired_incarnations`, or `sb.streams`.
  - **Cross-terminal incarnation rotation & check ordering:** Rotating a sandbox to a new
    `incarnation_id` (`register_stream` with a new incarnation) adds the prior `incarnation_id` to
    `retired_incarnations`, **clears `sb.streams` completely** (retiring both `"opencode-tui"` and
    `"shell"` under the old incarnation so sibling terminals must be explicitly registered under the
    new incarnation), and refuses any future registration referencing a retired `incarnation_id`
    with `IncarnationMismatchError("retired_incarnation_reused")`.
  - Across `append_chunk`, `read_replay_frames`, `close_stream`, and `rotate_stream_epoch`, lookup
    always runs in the exact order:
    1. `sb = self._sandboxes.get(addr)` -> if `None`, raise `CoordPolicyError("terminal_stream_not_registered")` (or `"terminal_stream_not_found"` on read);
    2. `inc != sb.active_incarnation_id` -> raise `IncarnationMismatchError("stale_incarnation_id")` (even if `tid` was cleared during incarnation rotation!);
    3. `stream = sb.streams.get(tid)` -> if `None`, raise `CoordPolicyError("terminal_stream_not_registered")` (or `"terminal_stream_not_found"` on read).
- **Per-stream monotonic `stream_epoch`, `frame_seq`, & fenced `close_stream`:**
  - `register_stream(target, incarnation_id, terminal_id, *, stream_epoch=1, mode=SanitizerMode.PLAIN)`
    initializes a stream at `stream_epoch >= 1` (`last_frame_seq = 0`, `last_evicted_seq = 0`,
    `closed = False`). Re-registering the exact same `(sandbox_addr, incarnation_id, terminal_id)`
    requires strictly greater `stream_epoch` (or use `rotate_stream_epoch`), resetting the sanitizer
    FSM and clearing the prior epoch's ring so partial escapes or frames from an old attach can
    never bleed across epochs.
  - `append_chunk(...)` validates ALL arguments, incarnation match, open stream state, exact
    `stream_epoch == active_stream_epoch`, and strict `frame_seq > last_frame_seq` **before**
    feeding a single byte into the sanitizer FSM (100% atomic on rejection!).
  - `close_stream(target, incarnation_id, terminal_id, *, stream_epoch, flush_frame_seq=None, captured_at=None)`
    enforces full fencing and atomic pre-flush validation:
    1. Requires `stream_epoch` (`1..MAX_INT64`) checked strictly against `stream.stream_epoch`
       (`stale_stream_epoch` / `unregistered_stream_epoch`).
    2. Optional `(flush_frame_seq, captured_at)` MUST be supplied as a pair (supplying only one
       raises `CoordValidationError("close_flush_frame_pair_required")`); when provided, validates
       `1 <= flush_frame_seq <= MAX_INT64`, `flush_frame_seq > stream.last_frame_seq`
       (`CoordPolicyError("non_monotonic_frame_seq")`), and finite `captured_at >= 0.0` **before**
       calling `stream.sanitizer.flush()` or setting `stream.closed = True`.
    3. Calling `close_stream` on an already-closed stream raises
       `RevokedError("terminal_stream_closed")` (fail-closed on double-close, zero mutation).
    4. Once validated, runs `stream.sanitizer.flush()`, sets `stream.closed = True`, and (if
       `(flush_frame_seq, captured_at)` was supplied) appends the flush frame with the exact same
       `MAX_FRAME_TEXT_BYTES` SGR/UTF-8 truncation and bounded ring eviction as `append_chunk`
       (returning the `TerminalReplayFrame`, else `None`).
    5. Subsequent `append_chunk` calls raise `RevokedError("terminal_stream_closed")`, while
       operators may still read retained replay frames (`stream_closed = True`).
  - **Post-close `rotate_stream_epoch` (explicit reconnect rule):** Calling
    `rotate_stream_epoch(target, incarnation_id, terminal_id, new_stream_epoch, *, mode=...)` (or
    `register_stream` on the same active `(addr, inc, tid)`) after `close_stream` is **allowed if
    and only if `new_stream_epoch > stream.stream_epoch`**, replacing the closed epoch with a fresh
    open stream (`closed = False`, reset sanitizer FSM, empty ring, `last_frame_seq = 0`,
    `last_evicted_seq = 0`); `new_stream_epoch <= stream.stream_epoch` fails closed with
    `CoordPolicyError("stale_stream_epoch")`.
- **Bounded ring eviction & exact `last_evicted_seq` gap signaling:**
  - After appending a frame (whose sanitized text is capped to `MAX_FRAME_TEXT_BYTES` at a UTF-8 +
    SGR-reset boundary), evict oldest frames from the left of `deque` while
    `len(ring) > max_ring_frames` OR `ring_bytes > max_ring_bytes`, incrementing
    `evicted_frame_count += 1` and updating `stream.last_evicted_seq = evicted.frame_seq`.
  - Store construction validates `MAX_FRAME_TEXT_BYTES <= max_ring_bytes <= MAX_RING_BYTES` so the
    most recent frame is always retainable.
  - On `read_replay_frames`, compute `frames_evicted_before_page` strictly from `last_evicted_seq`
    (zero false positives on sparse monotonic sequences like `10, 20, 30` and exact on empty rings):
    - When `after_cursor is None`: `frames_evicted_before_page = (stream.last_evicted_seq > 0)`.
    - When `after_cursor` decodes to `after_seq`: `frames_evicted_before_page = (stream.last_evicted_seq > after_seq)`.

### 5.3 Collision-Free Canonical Cursor Codec

Mirrors `oc_projection_contract.py:718-809` verbatim (avoiding `:`-delimited collisions since
`incarnation_id` permits `:`):

```text
cursor = "v1." + base64url_nopad(
    json.dumps(
        {"op": "terminal_replay", "fh": scope_hash, "inc": incarnation_id, "ep": stream_epoch, "seq": frame_seq},
        separators=(",", ":"), sort_keys=True, ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")
)
```

- `scope_hash`: 16-hex-char SHA-256 prefix over canonical JSON of
  `{"op": "terminal_replay", "params": {"target": addr, "terminal_id": terminal_id, "incarnation_id": inc, "stream_epoch": ep}}`.
- Decode strictly validates in exact order:
  1. `isinstance(raw, str)`; `raw.encode("utf-8", errors="surrogatepass")` length `<= MAX_CURSOR_BYTES (512)`; starts with `"v1."`.
  2. `b64_part` non-empty and matches `^[A-Za-z0-9_-]+$` (`re.ASCII`); `pad_len = (-len(b64_part)) % 4` with `pad_len != 3` (rejecting impossible 1-char base64url tails!).
  3. Decode base64url + UTF-8 + `json.loads(..., parse_constant=_reject_json_constant)` catching `(ValueError, RecursionError)` -> `CoordValidationError("cursor_malformed")`.
  4. Require `isinstance(parsed, dict)` and strict canonical re-encoding equality (`encode_cursor(parsed) == raw`, catching `(ValueError, TypeError, CoordValidationError)` -> `CoordValidationError("cursor_malformed")`).
  5. **Structural field validation BEFORE scope-mismatch checks:**
     - Exact key set `{"op", "fh", "inc", "ep", "seq"}` else `CoordValidationError("cursor_malformed")`.
     - `op` is a `str` in `VALID_CURSOR_OPS` (`{"terminal_replay"}`) else `CoordValidationError("cursor_malformed")`.
     - `fh` is a `str` matching `_SCOPE_HASH_RE` (`^[0-9a-f]{16}$`, ASCII) else `CoordValidationError("cursor_malformed")`.
     - `inc` passes `validate_terminal_token(parsed["inc"], "incarnation_id")` (converting `AddressError` -> `CoordValidationError("cursor_malformed")`).
     - `ep` satisfies `type(ep) is int and 1 <= ep <= MAX_INT64` (strictly rejecting `bool`, `<= 0`, `> MAX_INT64`) else `CoordValidationError("cursor_malformed")`.
     - `seq` satisfies `type(seq) is int and 1 <= seq <= MAX_INT64` (strictly rejecting `bool`, `<= 0`, `> MAX_INT64`) else `CoordValidationError("cursor_malformed")`.
  6. **Scope/incarnation/epoch binding:** Require `op == "terminal_replay"`, `fh == expected_scope_hash`, `inc == expected_incarnation_id`, and `ep == expected_stream_epoch` -> mismatch raises `CoordValidationError("cursor_scope_mismatch")`.

### 5.4 Hard End-to-End Serialized UTF-8 JSON Byte Cap (`allow_nan=False`)

All serialization uses:
```python
json.dumps(obj.to_dict(), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
```

For `read_replay_frames(..., max_response_bytes=...)`:
1. `TerminalReplayPage.to_dict()` serializes both `stream_stats` and per-frame `frame_stats` via
   `to_compact_dict()`, and per-frame JSON entries omit fields already invariant on the enclosing
   page (`sandbox_addr`, `incarnation_id`, `terminal_id`, `stream_epoch`), keeping a single-frame
   1 KiB page envelope compact (~350–500 bytes, leaving >500 bytes for escape-heavy text even at
   `max_response_bytes = 1024`).
2. Measure the exact UTF-8 byte length of the empty-frames page:
   - Reserve `next_cursor` bytes **only when `len(candidates) > 1`** (using the exact `next_cursor`
     for `candidates[0].frame_seq`; when `len(candidates) <= 1`, the 1-frame page has
     `has_more = False` and `next_cursor = None` so no phantom cursor budget is reserved!).
   - If the empty envelope alone exceeds `max_response_bytes`, raise
     `CoordValidationError("response_budget_too_small_for_envelope")`.
3. Admit candidate frames in strictly ascending `frame_seq` order up to `limit`, verifying the
   **exact serialized UTF-8 byte length** of the full `TerminalReplayPage` (with actual
   `has_more` and `next_cursor`) stays `<= max_response_bytes`:
   - **First-frame rule (UTF-8, JSON-escape, & SGR-reset exact):** If the first candidate frame
     alone exceeds `max_response_bytes` (e.g., 1 KiB budget with escape-heavy `\"\\\"\n`, multibyte
     UTF-8, or `\x1b[31m...` SGR text):
     - If `len(frame.text) == 0` (or even `text = ""` on the first frame cannot fit), immediately raise
       `CoordValidationError("response_budget_too_small_for_item")` before entering binary search.
     - Otherwise binary-search character prefix length `k` in `[0, len(frame.text) - 1]`. For each probe `k`,
       back up before any incomplete `\x1b[...` SGR sequence (`prefix = _back_up_mid_sgr(frame.text[:k], mode)`),
       and when `mode is SanitizerMode.SAFE_SGR and "\x1b[" in prefix`, test the **monotonically
       non-decreasing** probe `prefix + "\x1b[0m"` (accounting for JSON's 6-byte `\u001b`
       expansion — 9 JSON bytes for `"\x1b[0m"`!) inside the full serialized page!
     - Once the maximum fitting `k` is found, evaluate `_sgr_is_open(prefix)` (using the exact
       8-slot SGR state tracker across `prefix`, including any cross-frame prepended `active_sgr_seq`
       from Section 3.4): emit `prefix + "\x1b[0m"` iff `mode is SAFE_SGR and _sgr_is_open(prefix)`,
       else `prefix` (guaranteed `<=` tested JSON byte length `<= max_response_bytes` and guaranteed
       to start and end in default style!), setting `text_truncated = True` and updating `text_bytes`.
   - **Subsequent frames:** Stop before exceeding `max_response_bytes`, set `has_more = True`, and
     emit `next_cursor` for the last admitted frame's `frame_seq`.

---

## 6. Pseudocode Walkthrough of Core APIs

### 6.1 `TerminalOutputSanitizer.feed` & `flush`

```python
class TerminalOutputSanitizer:
    def __init__(self, *, mode: SanitizerMode = SanitizerMode.PLAIN) -> None:
        validate_sanitizer_mode(mode)
        self._mode = mode
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
        self._sgr_state = _SgrState()  # O(1) 8-slot active SGR tracker (independent bold/faint; SAFE_SGR mode only)
        self._stats = _MutableStats()

    @property
    def active_sgr_seq(self) -> str:
        """Canonical active SGR sequence (<= 34 B) or '' when in default style / PLAIN mode."""
        return "" if self._mode is not SanitizerMode.SAFE_SGR else self._sgr_state.to_sgr_seq()

    def feed(self, chunk: bytes) -> str:
        if not isinstance(chunk, bytes):
            raise CoordValidationError("chunk must be bytes")
        if len(chunk) > MAX_FEED_CHUNK_BYTES:
            raise CoordValidationError("chunk exceeds MAX_FEED_CHUNK_BYTES")
        self._stats.input_bytes += len(chunk)
        out: list[str] = []
        for b in chunk:
            self._step_byte(b, out)
        text = "".join(out)
        self._stats.output_bytes += len(text.encode("utf-8"))
        return text

    def flush(self) -> str:
        out: list[str] = []
        if self._pending_cr:
            self._pending_cr = False
            out.append("\n")
            self._stats.neutralized_bare_cr_count += 1
            self._stats.dropped_c0_c1_count += 1
        if self._state is _State.UTF8_PENDING:
            self._utf8_buf.clear()
            self._utf8_min_next = 0x80
            self._utf8_max_next = 0xBF
            self._state = _State.GROUND
            out.append("\ufffd")
            self._stats.invalid_utf8_count += 1
        elif self._state is not _State.GROUND:
            if self._state in (_State.OSC, _State.STRING_SEQ) and (
                self._esc_seen or self._str_utf8_is_c2
            ):
                self._charge_seq_byte_and_check_overlong()
            self._finalize_dropped_active_seq()
            self._reset_seq_state()
            self._state = _State.GROUND
        text = "".join(out)
        self._stats.output_bytes += len(text.encode("utf-8"))
        return text
```

### 6.2 `TerminalReplayStore` (`register_stream`, `close_stream`, `append_chunk`, `read_replay_frames`)

```python
def register_stream(
    self,
    *,
    target: str,
    incarnation_id: str,
    terminal_id: str,
    stream_epoch: int = 1,
    mode: SanitizerMode = SanitizerMode.PLAIN,
) -> None:
    addr = parse_terminal_target(target).canonical
    inc = validate_terminal_token(incarnation_id, "incarnation_id")
    tid = validate_terminal_id(terminal_id)
    ep = validate_strict_int_range(stream_epoch, "stream_epoch", 1, MAX_INT64)
    validate_sanitizer_mode(mode)

    with self._lock:
        sb = self._sandboxes.get(addr)
        if sb is None:
            if len(self._sandboxes) >= MAX_TRACKED_SANDBOXES:
                raise CoordPolicyError("max_tracked_sandboxes_exceeded")
            sb = _SandboxState(active_incarnation_id=inc)
            sb.streams[tid] = _StreamState(stream_epoch=ep, mode=mode)
            self._sandboxes[addr] = sb
            return
        if inc in sb.retired_incarnations:
            raise IncarnationMismatchError("retired_incarnation_reused")
        if inc != sb.active_incarnation_id:
            if len(sb.retired_incarnations) >= MAX_RETIRED_INCARNATIONS:
                raise CoordPolicyError("max_retired_incarnations_exceeded")
            sb.retired_incarnations.add(sb.active_incarnation_id)
            sb.active_incarnation_id = inc
            sb.streams.clear()  # Retires all sibling terminals under old incarnation
            sb.streams[tid] = _StreamState(stream_epoch=ep, mode=mode)
            return
        existing = sb.streams.get(tid)
        if existing is not None and ep <= existing.stream_epoch:
            raise CoordPolicyError("stale_stream_epoch")
        # Allowed after close_stream when ep > existing.stream_epoch
        sb.streams[tid] = _StreamState(stream_epoch=ep, mode=mode)


def close_stream(
    self,
    *,
    target: str,
    incarnation_id: str,
    terminal_id: str,
    stream_epoch: int,
    flush_frame_seq: int | None = None,
    captured_at: float | None = None,
) -> TerminalReplayFrame | None:
    addr = parse_terminal_target(target).canonical
    inc = validate_terminal_token(incarnation_id, "incarnation_id")
    tid = validate_terminal_id(terminal_id)
    ep = validate_strict_int_range(stream_epoch, "stream_epoch", 1, MAX_INT64)
    if (flush_frame_seq is None) != (captured_at is None):
        raise CoordValidationError("close_flush_frame_pair_required")
    flush_seq = validate_strict_int_range(flush_frame_seq, "flush_frame_seq", 1, MAX_INT64) if flush_frame_seq is not None else None
    flush_ts = validate_finite_timestamp(captured_at, "captured_at") if captured_at is not None else None

    with self._lock:
        sb = self._sandboxes.get(addr)
        if sb is None:
            raise CoordPolicyError("terminal_stream_not_registered")
        if inc != sb.active_incarnation_id:
            raise IncarnationMismatchError("stale_incarnation_id")
        stream = sb.streams.get(tid)
        if stream is None:
            raise CoordPolicyError("terminal_stream_not_registered")
        if stream.closed:
            raise RevokedError("terminal_stream_closed")
        if ep < stream.stream_epoch:
            raise CoordPolicyError("stale_stream_epoch")
        if ep > stream.stream_epoch:
            raise CoordPolicyError("unregistered_stream_epoch")
        if flush_seq is not None and flush_seq <= stream.last_frame_seq:
            raise CoordPolicyError("non_monotonic_frame_seq")

        before = stream.sanitizer.stats
        prefix_sgr = stream.sanitizer.active_sgr_seq
        flushed = stream.sanitizer.flush()
        after = stream.sanitizer.stats
        sgr_open_end = bool(stream.sanitizer.active_sgr_seq)
        stream.closed = True
        if flush_seq is None:
            return None
        wrapped = wrap_self_contained_sgr_frame(flushed, prefix_sgr, sgr_open_end, mode=stream.mode)
        return _store_sanitized_frame(
            stream, addr, inc, tid, ep, flush_seq, flush_ts, wrapped, raw_input_bytes=0, frame_stats=diff_stats(before, after)
        )


def append_chunk(
    self,
    *,
    target: str,
    incarnation_id: str,
    terminal_id: str,
    stream_epoch: int,
    frame_seq: int,
    raw_bytes: bytes,
    captured_at: float,
) -> TerminalReplayFrame:
    addr = parse_terminal_target(target).canonical
    inc = validate_terminal_token(incarnation_id, "incarnation_id")
    tid = validate_terminal_id(terminal_id)
    ep = validate_strict_int_range(stream_epoch, "stream_epoch", 1, MAX_INT64)
    seq = validate_strict_int_range(frame_seq, "frame_seq", 1, MAX_INT64)
    ts = validate_finite_timestamp(captured_at, "captured_at")
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) > MAX_FEED_CHUNK_BYTES:
        raise CoordValidationError("raw_bytes must be bounded bytes")

    with self._lock:
        sb = self._sandboxes.get(addr)
        if sb is None:
            raise CoordPolicyError("terminal_stream_not_registered")
        if inc != sb.active_incarnation_id:
            raise IncarnationMismatchError("stale_incarnation_id")
        stream = sb.streams.get(tid)
        if stream is None:
            raise CoordPolicyError("terminal_stream_not_registered")
        if stream.closed:
            raise RevokedError("terminal_stream_closed")
        if ep < stream.stream_epoch:
            raise CoordPolicyError("stale_stream_epoch")
        if ep > stream.stream_epoch:
            raise CoordPolicyError("unregistered_stream_epoch")
        if seq <= stream.last_frame_seq:
            raise CoordPolicyError("non_monotonic_frame_seq")

        before = stream.sanitizer.stats
        prefix_sgr = stream.sanitizer.active_sgr_seq
        clean_full = stream.sanitizer.feed(raw_bytes)
        after = stream.sanitizer.stats
        sgr_open_end = bool(stream.sanitizer.active_sgr_seq)
        # In SAFE_SGR mode, wrap non-empty frames with prefix_sgr + closing ESC[0m so every
        # stored frame starts and ends in default style across frame and page boundaries.
        wrapped = wrap_self_contained_sgr_frame(clean_full, prefix_sgr, sgr_open_end, mode=stream.mode)
        return _store_sanitized_frame(
            stream, addr, inc, tid, ep, seq, ts, wrapped, raw_input_bytes=len(raw_bytes), frame_stats=diff_stats(before, after)
        )
        # _store_sanitized_frame truncates via truncate_sanitized_text_utf8 (preserving SGR reset),
        # appends to stream.ring, and evicts oldest frames while updating evicted_frame_count
        # and stream.last_evicted_seq = evicted.frame_seq.


def read_replay_frames(
    self,
    caller: PrincipalCtx,
    *,
    target: str,
    terminal_id: str,
    incarnation_id: str | None = None,
    stream_epoch: int | None = None,
    after_cursor: str | None = None,
    limit: int = DEFAULT_PAGE_LIMIT,
    max_response_bytes: int = MAX_RESPONSE_BYTES,
    read_session_id: str | None = None,
    session_generation: int | None = None,
) -> TerminalReplayPage:
    authorize_operator_caller(caller)
    addr = parse_terminal_target(target).canonical
    tid = validate_terminal_id(terminal_id)
    req_inc = validate_terminal_token(incarnation_id, "incarnation_id") if incarnation_id is not None else None
    req_ep = validate_strict_int_range(stream_epoch, "stream_epoch", 1, MAX_INT64) if stream_epoch is not None else None
    page_limit = validate_strict_int_range(limit, "limit", 1, MAX_PAGE_LIMIT)
    budget = validate_strict_int_range(max_response_bytes, "max_response_bytes", MIN_RESPONSE_BYTES, MAX_RESPONSE_BYTES)
    session_echo = validate_and_check_pre_fences(caller, read_session_id, session_generation)

    with self._lock:
        sb = self._sandboxes.get(addr)
        if sb is None:
            raise CoordPolicyError("terminal_stream_not_found")
        if req_inc is not None and req_inc != sb.active_incarnation_id:
            raise IncarnationMismatchError("stale_incarnation_id")
        stream = sb.streams.get(tid)
        if stream is None:
            raise CoordPolicyError("terminal_stream_not_found")
        if req_ep is not None and req_ep != stream.stream_epoch:
            raise CoordPolicyError("stale_stream_epoch")

        applied_inc = sb.active_incarnation_id
        applied_ep = stream.stream_epoch
        captured_closed = stream.closed
        scope_hash = compute_replay_scope_hash(
            target=addr, terminal_id=tid, incarnation_id=applied_inc, stream_epoch=applied_ep
        )
        after_seq = decode_replay_cursor(
            after_cursor,
            expected_scope_hash=scope_hash,
            expected_incarnation_id=applied_inc,
            expected_stream_epoch=applied_ep,
        )
        # Exact eviction gap signal using last_evicted_seq (zero false positives on sparse seqs)
        evicted_before = (stream.last_evicted_seq > 0) if after_seq is None else (stream.last_evicted_seq > after_seq)
        snapshot = snapshot_stream_candidates(stream, after_seq, evicted_before=evicted_before)

    if self._on_after_snapshot_before_release is not None:
        self._on_after_snapshot_before_release()
    page = build_bounded_replay_page(
        snapshot=snapshot,
        scope_hash=scope_hash,
        limit=page_limit,
        max_response_bytes=budget,
        read_session=session_echo,
    )
    # Post-pack fencing: verify operator session/authority FIRST (zero target-state oracle on
    # revoked callers), then re-acquire self._lock to verify stream identity did not rotate or
    # close while packing (returning zero frames on any race!).
    check_post_fences(caller, read_session_id, session_generation)
    with self._lock:
        sb = self._sandboxes.get(addr)
        if sb is None:
            raise CoordPolicyError("terminal_stream_not_found")
        if sb.active_incarnation_id != applied_inc:
            raise IncarnationMismatchError("stale_incarnation_id")
        stream = sb.streams.get(tid)
        if stream is None:
            raise CoordPolicyError("terminal_stream_not_found")
        if stream.stream_epoch != applied_ep:
            raise CoordPolicyError("stale_stream_epoch")
        if not captured_closed and stream.closed:
            raise RevokedError("terminal_stream_closed")
    return page
```

---

## 7. Failure & Recovery Matrix (Pinned Exception Mapping)

| Failure / Edge Condition | Exact Exception / Result |
|---|---|
| `caller` is not `PrincipalCtx` | `CoordValidationError("caller must be PrincipalCtx")` |
| `caller.role != CoordRole.OPERATOR` (`JOB`, `ORCHESTRATOR`, `EXTERNAL_PEER`) | `CoordAuthError("operator_role_required")` (before target lookup) |
| `OPERATOR` with non-`None` `sandbox_addr` or `incarnation_id` | `CoordAuthError("operator_principal_must_not_bind_sandbox")` |
| `session_validator` configured, but `(read_session_id, session_generation)` omitted | `CoordAuthError("read_session_required")` |
| Partial `(read_session_id, session_generation)` or invalid type/value (`bool`, `<= 0`, control/bidi/surrogate/non-`str` `read_session_id`) | `CoordValidationError` (`AddressError` wrapped) |
| Session args supplied with `session_validator is None` | `CoordPolicyError("read_session_validator_unconfigured")` |
| `session_validator` returns non-`True` or raises (pre-read OR post-read) | `RevokedError("read_session_retired")` (zero frames returned) |
| `live_authority_checker` returns non-`True` or raises (pre-read OR post-read) | `RevokedError("read_authority_revoked")` (zero frames returned) |
| Invalid `target` (e.g., `"@peer"`, control/bidi/surrogate/non-`str`, bad syntax), invalid `incarnation_id`, invalid `terminal_id`, invalid `mode` | `CoordValidationError` (`AddressError` wrapped) |
| Partial `(flush_frame_seq, captured_at)` on `close_stream` | `CoordValidationError("close_flush_frame_pair_required")` |
| Non-`bytes` `chunk`/`raw_bytes` or `len > MAX_FEED_CHUNK_BYTES` | `CoordValidationError` |
| `NaN`, `+Inf`, `-Inf`, negative, or `bool` `captured_at` | `CoordValidationError` |
| `bool` or out-of-range `stream_epoch`, `frame_seq`, `flush_frame_seq`, `limit`, `max_response_bytes`, ring limits | `CoordValidationError` |
| Registering a new sandbox when `len(sandboxes) >= MAX_TRACKED_SANDBOXES` (`64`) | `CoordPolicyError("max_tracked_sandboxes_exceeded")` (atomic: zero state mutated) |
| Rotating incarnation when `len(retired_incarnations) >= MAX_RETIRED_INCARNATIONS` (`1024`) | `CoordPolicyError("max_retired_incarnations_exceeded")` (never evicts retired IDs; atomic) |
| Append/close/rotate/read on unregistered sandbox or unregistered terminal of current incarnation | `CoordPolicyError("terminal_stream_not_registered")` / `CoordPolicyError("terminal_stream_not_found")` |
| Registering a previously retired `incarnation_id` for a sandbox | `IncarnationMismatchError("retired_incarnation_reused")` |
| Append, close, rotate, or read with stale/mismatched `incarnation_id` (checked BEFORE `tid in sb.streams`!) OR incarnation rotated mid-read during page packing | `IncarnationMismatchError("stale_incarnation_id")` (atomic; zero frames returned on mid-read race) |
| Append or close with `stream_epoch < active_stream_epoch` / `> active_stream_epoch` | `CoordPolicyError("stale_stream_epoch")` / `CoordPolicyError("unregistered_stream_epoch")` |
| Read with explicit `stream_epoch != active_stream_epoch`, epoch rotated mid-read during page packing, or `rotate_stream_epoch` / re-register with `new_epoch <= active_stream_epoch` | `CoordPolicyError("stale_stream_epoch")` (zero frames returned on mid-read race) |
| Append or `close_stream(flush_frame_seq=...)` with `seq <= last_frame_seq` | `CoordPolicyError("non_monotonic_frame_seq")` (atomic: zero flush/sanitizer/ring mutation) |
| Append to or double-close on an already-closed stream, OR open stream closed mid-read during page packing | `RevokedError("terminal_stream_closed")` (operators may still open new reads on already-closed streams with `stream_closed=True`; `rotate_stream_epoch` with strictly higher epoch opens a new epoch) |
| Malformed, oversized, `pad_len == 3`, non-canonical, `NaN`/deeply-nested, `bool`/out-of-range `ep`/`seq`, bad `inc`/`fh`, or scope/incarnation/epoch-mismatched cursor | `CoordValidationError("cursor_malformed")` / `CoordValidationError("cursor_scope_mismatch")` |
| `max_response_bytes` too small for empty envelope or minimal empty-text first frame | `CoordValidationError("response_budget_too_small_for_envelope")` / `CoordValidationError("response_budget_too_small_for_item")` |
| Unterminated `> MAX_ESC_SEQ_BYTES` OSC/DCS/APC/PM/SOS/CSI/ESC_INTERMEDIATE (including final/terminator and C0-in-CSI/ESC_INTERMEDIATE bytes) | O(1)-memory drain until terminator/`flush()`; immediate `overlong_seq_dropped_count += 1` + seq drop counter; zero tail bytes leaked |
| Invalid UTF-8 bytes or UTF-8/Python lone surrogates | Replaced with `"\ufffd"` + `invalid_utf8_count += 1`; zero surrogates survive |
| Bare `\r` (not followed by `\n`) or trailing `\r` at `flush()` | Neutralized to `"\n"` + `neutralized_bare_cr_count += 1`, `dropped_c0_c1_count += 1`; zero `\r` survives |
| Ring buffer capacity (`MAX_RING_FRAMES` or `MAX_RING_BYTES`) exceeded | Oldest frames evicted from left; `evicted_frame_count` incremented & `last_evicted_seq = evicted.frame_seq`; reads set `frames_evicted_before_page = (last_evicted_seq > 0)` or `(last_evicted_seq > after_seq)` |

---

## 8. Open Choices Resolved in This Walkthrough (For Gate 1 Review)

1. **Overlong escape/string-sequence drain & strict RFC 3629 UTF-8 tracking inside `OSC`/`STRING_SEQ`:**
   Exceeding `MAX_ESC_SEQ_BYTES (4096)` (counting every byte consumed by the sequence including
   C0-in-CSI/ESC_INTERMEDIATE and completing terminators) keeps the parser in O(1)-memory drain mode
   until a valid terminator (`ST`, `BEL` for OSC, `CAN`/`SUB`, nested `ESC`, C1 introducer, or
   `flush()`) while immediately incrementing `overlong_seq_dropped_count` and the sequence drop
   counter. Tracking RFC 3629 UTF-8 continuation bytes inside `OSC`/`STRING_SEQ` in O(1) scalar
   state guarantees multibyte UTF-8 characters whose continuation bytes are `0x90..0x9F` (such as
   `“`, `”`, `‛`, `←`, `🚀`) can never prematurely terminate an OSC or switch sequence states.
2. **Bare `\r` neutralization (`\r\n -> \n`, bare `\r -> \n`):** Normalizing `\r\n` (including
   chunk-split `\r` + `\n`) to `\n` and neutralizing bare `\r` to `\n` (with diagnostic counters)
   defeats single-line overwrite spoofing while preserving both pieces of text on separate lines
   with zero `\r` in sanitized output — consistent with `oc_coord_contract.canonicalize_body_text`.
3. **Closed `SAFE_SGR` allowlist & cross-frame self-contained SGR closure:** Excludes `SGR 8`
   (conceal), blink (`5`/`6`), and 24-bit RGB (`38;2`/`48;2`/`58;2`), while allowing basic
   attributes, 16-color, and 8-bit indexed `38;5;N`/`48;5;N` (`0 <= N <= 255`). An O(1) 8-slot
   `active_sgr_seq` tracker prepends active styles onto continuation frames and closes open styles
   with `"\x1b[0m"` on every non-empty frame (and on truncation at BOTH `MAX_FRAME_TEXT_BYTES` and
   `max_response_bytes`, accounting for JSON's 6-byte `\u001b` expansion), guaranteeing every stored
   and paged `SAFE_SGR` frame starts and ends in default style.
4. **Target scope, closed `terminal_id` set, & fail-closed capacity bounds:** Accepts both `"local"`
   (`"NAME"`) and `"remote"` (`"REMOTE / NAME"`) canonical sandbox addresses (rejecting `"@PEER"`),
   with closed `VALID_TERMINAL_IDS = {"opencode-tui", "shell"}` matching `prd_m3.md`, uniform
   `AddressError -> CoordValidationError` wrapping, and fail-closed capacity bounds
   (`MAX_TRACKED_SANDBOXES = 64`, non-evicting `MAX_RETIRED_INCARNATIONS = 1024`).
5. **Compact stats & exact cursor reservation on paginated responses:** Python dataclasses retain
   full 12-field `SanitizerStats`, while `TerminalReplayPage.to_dict()` serializes both
   `stream_stats` and per-frame `frame_stats` via `to_compact_dict()`, and reserves `next_cursor`
   budget only when `len(candidates) > 1`, ensuring `MIN_RESPONSE_BYTES = 1024` fits escape-heavy
   frames cleanly without losing any non-zero anomaly telemetry.

---

## 9. Offline Qualification & Verification Plan (`test_terminal_observe.py`)

All tests run offline via
`python3 -B -m unittest discover -s docs/prds/spikes/m/terminal-observe -p 'test_*.py'` with zero
external dependencies, zero Podman, zero network, and zero host state writes:

1. **Hostile escape & control red-team suite (1-chunk AND 1-byte chunk-split invariance):**
   - **OSC family:** OSC 52 clipboard (`ESC ] 52;c;... BEL` and `ST`), OSC 8 hyperlinks, OSC 0/2
     title, OSC 9/99/777 notifications, OSC 10/11 palette — both 7-bit `ESC ]`, raw 8-bit `0x9D`,
     and UTF-8 `0xC2 0x9D`, terminated by `BEL`, `ESC \`, raw `0x9C`, UTF-8 `0xC2 0x9C`, `CAN`,
     `SUB`, and aborted by nested `ESC [ 6 n`. Verify zero sequence bytes survive and exact
     `dropped_osc_count`.
   - **UTF-8 multibyte continuation bytes inside `OSC` and `STRING_SEQ` (P1-1 regression fixtures):**
     Feed `b"\x1b]0;title\xe2\x80\x9cSPOOF\x07"` (`“ = 0xE2 0x80 0x9C`, no real `ESC` after `“`),
     `b"\x1b]0;title\xe2\x80\x9b31mSPOOF\x07"` (`‛ = 0xE2 0x80 0x9B`), `” = 0xE2 0x80 0x9D`,
     `← = 0xE2 0x86 0x90`, `🚀 = 0xF0 0x9F 0x9A 0x80` followed by `BEL` inside OSC (and DCS with `ST`),
     `0xC2 0xA0` (NBSP) followed by a later `0x9C` / normal payload, and truncated UTF-8 lead
     `0xE2` immediately followed by `ESC \` ST inside OSC/DCS — both 1-chunk and 1-byte split!
     Verify zero spoofed text leaks into `GROUND`, OSC terminates cleanly on `BEL` after `🚀`, and
     exact `dropped_osc_count` / `dropped_string_seq_count`.
   - **String sequences (`DCS`/`APC`/`PM`/`SOS`):** Sixel (`ESC P q ... ESC \`), Kitty graphics
     (`ESC _ G ... ESC \`), tmux passthrough (`ESC P tmux;... ESC \`), PM (`ESC ^ ...`), SOS
     (`ESC X ...`), plus raw 8-bit `0x90`/`0x98`/`0x9E`/`0x9F` and UTF-8 `0xC2 0x90`..`0xC2 0x9F`.
     Verify zero bytes survive and exact `dropped_string_seq_count`.
   - **CSI & terminal queries:** `CSI 6 n` (DSR), `CSI c` (DA1), `CSI > c` (DA2), `CSI > q`
     (XTVERSION), `CSI ? 1049 h/l` (alt screen), `CSI ? 25 l`, `CSI ? 1004 h`, `CSI ? 2004 h`,
     `CSI ? 1 $ p` (DECRQM), `CSI 8;50;100 t` (window resize), `CSI 2 J`, `CSI H`, `CSI 1 A`,
     raw 8-bit `0x9B 31 m`, UTF-8 `0xC2 0x9B 31 m`. Verify ALL dropped in BOTH `PLAIN` and
     `SAFE_SGR` modes.
   - **ESC Fe/Fp/Fs & intermediate sequences:** `ESC c` (RIS reset), `ESC 7`, `ESC 8`, `ESC ( B`,
     `ESC ( \x00 B` (verifying `"B"` does NOT leak!), `ESC # 8`, `ESC D`, `ESC M`, double `ESC`.
     Verify ALL dropped (`dropped_esc_count`).
   - **C0/C1/DEL/NUL/bare-CR/bidi/UTF-8/surrogates:**
     - NUL (`\x00`), `ENQ` (`\x05`), `BEL` (`\x07`), `BS` (`\x08`), `DEL` (`\x7F`), bare C0
       controls dropped (`dropped_c0_c1_count`), while `\n`, `\t`, and `\r\n` (including `\r` at
       end of chunk 1 + `\n` at start of chunk 2!) emit cleanly.
     - Bare-CR injection (`b"rm -rf /\rOK: clean\n"`, `b"a\r\r\nb"`, trailing `b"abc\r"` at
       `flush()`) neutralizes every bare `\r` to `\n` with zero `\r` surviving in output and exact
       `neutralized_bare_cr_count`.
     - All Unicode bidi codepoints (`_BIDI_CODEPOINTS`, e.g., `U+202E` RLO split across 3 single-byte
       chunks) dropped (`dropped_bidi_count`).
     - Valid RFC 3629 boundary scalars `U+0800` (`0xE0 0xA0 0x80`), `U+D7FF` (`0xED 0x9F 0xBF`),
       `U+10000` (`0xF0 0x90 0x80 0x80`), and `U+10FFFF` (`0xF4 0x8F 0xBF 0xBF`) decode cleanly
       (proving `_utf8_min_next`/`_utf8_max_next` reset after byte 2!).
     - Invalid UTF-8 (overlong `0xC0 0xAF`, `0xE0 0x80 0xAF`, UTF-8 surrogate `0xED 0xA0 0x80`,
       `> U+10FFFF` `0xF4 0x90 0x80 0x80`, truncated lead before `ESC ] 52 ...`, bare `0xA0..0xBF`,
       trailing incomplete sequence at `flush()`) emits `U+FFFD` with exact `invalid_utf8_count`,
       never swallows a following `ESC`, and `sanitize_text_str` rejects Python lone surrogates.
   - **Chunk-split invariance:** Run the entire composite hostile payload through 1-chunk, 1-byte,
     2-byte, 3-byte, and prime-length (`7`-byte) chunkings and assert **identical output string AND
     identical `SanitizerStats`** across every partitioning.
2. **`SAFE_SGR` allowlist & spoofing rejection:**
   - Permits `ESC[m`, `ESC[0m`, `ESC[1;31m`, `ESC[32;40;97;100m`, `ESC[38;5;196;1m`, `ESC[48;5;0m`
     (`allowed_sgr_count` exact).
   - Rejects in `SAFE_SGR`: 24-bit RGB (`ESC[38;2;255;0;0m`, `ESC[48;2;1;2;3m`), colon subparams
     (`ESC[38:2::255:0:0m`, `ESC[4:3m`), underline color (`ESC[58;5;1m`), concealed text (`ESC[8m`),
     blink (`ESC[5m`), private-prefix SGR (`ESC[?1m`, `ESC[>4;2m`, `ESC[=1m`, `ESC[<1m`),
     intermediate-byte SGR (`ESC[0$m`), C0-interleaved SGR (`ESC[3\x001m`), `> 16` parameters,
     parameter `> 255` (`ESC[38;5;256m`), empty subparam (`ESC[1;;31m`), leading-zero padded token
     (`ESC[0001m`), truncated `ESC[38;5m`, 8-bit `0x9B 31 m`, UTF-8 `0xC2 0x9B 31 m`, and all non-`m`
     CSI sequences.
   - In `PLAIN` mode, even `ESC[31m` is stripped (`allowed_sgr_count == 0`).
3. **Unterminated 1 MiB escape DoS, exact `MAX_ESC_SEQ_BYTES` boundary, & bounded parser memory:**
   - Feed 1 MiB unterminated OSC 52 (`b"\x1b]52;c;" + b"A" * 1_048_576`), 1 MiB unterminated DCS,
     and 100 KiB unterminated CSI (including C0-in-CSI flood `b"\x1b[" + b"\x00" * 5000 + b"m"`, in
     both single-chunk and 1 KiB streamed chunks).
   - Verify `output_bytes == 0` (zero tail leakage!), `overlong_seq_dropped_count == 1` immediately
     before `flush()`, parser internal buffer size strictly `<= MAX_SAFE_SGR_PARAM_BYTES` (O(1)
     memory), and subsequent `b"\x07AFTER"` / `b"\x1b\\AFTER"` cleanly resynchronizes and emits
     `"AFTER"` without double-counting.
   - Exact boundary tests at `MAX_ESC_SEQ_BYTES` (4096 bytes including final/terminator `BEL`,
     `ESC \`, `0xC2 0x9C`, or CSI `m` -> not overlong; 4097 bytes triggered by the final/terminator
     byte -> `overlong_seq_dropped_count == 1`), PLUS EOF boundary test for a 4096-byte OSC/DCS
     ending in a lone `0xC2` (or lone `0x1B`) at byte 4097 followed by `flush()` (triggers
     `overlong_seq_dropped_count == 1` and `dropped_osc_count == 1`) and a second idempotent
     `flush()` call verifying counters do NOT double-increment.
4. **Provenance binding, incarnation/epoch/sequence fencing, capacity caps, `close_stream`, & ring eviction:**
   - Reject stale `incarnation_id`, reused retired `incarnation_id`, stale/unregistered
     `stream_epoch`, duplicate/decreasing `frame_seq`, closed-stream append, double-close,
     `close_stream` with wrong `stream_epoch` / partial `(flush_frame_seq, captured_at)` /
     non-monotonic `flush_frame_seq` (verifying pre-flush atomicity: stream stays open and sanitizer
     state stays intact!), `@peer` target, invalid `terminal_id`, and `NaN`/`Inf`/negative/`bool`
     `captured_at` — verifying atomic non-mutation on every rejection.
   - Verify `AddressError -> CoordValidationError` wrapping on control/bidi/surrogate/non-`str`
     inputs for `target`, `incarnation_id`, `read_session_id`, and cursor `inc`.
   - Verify cross-terminal incarnation rotation: registering `("feat-a", "inc_1", "opencode-tui")`
     and `("feat-a", "inc_1", "shell")`, then rotating `("feat-a", "inc_2", "opencode-tui")` clears
     `"shell"` so `append_chunk`/`read_replay_frames`/`close_stream` on `"shell"` with `"inc_1"`
     raises `IncarnationMismatchError("stale_incarnation_id")` (not `"terminal_stream_not_registered"`),
     while `"inc_2"` on unregistered `"shell"` raises `CoordPolicyError`.
   - Verify fail-closed capacity bounds: 65th sandbox raises
     `CoordPolicyError("max_tracked_sandboxes_exceeded")`; 1025th incarnation rotation raises
     `CoordPolicyError("max_retired_incarnations_exceeded")` without evicting any retired ID.
   - Verify `close_stream` flush frame + post-close `rotate_stream_epoch` (higher epoch succeeds and
     reopens clean stream; `<=` epoch raises `CoordPolicyError("stale_stream_epoch")`).
   - Verify ring eviction enforces BOTH `max_ring_frames` and `max_ring_bytes`, updates
     `evicted_frame_count` and `last_evicted_seq`, emits ZERO false-positive
     `frames_evicted_before_page` on sparse monotonic sequences (`10, 20, 30`) with no eviction, and
     accurately sets `frames_evicted_before_page = True` iff `last_evicted_seq > after_seq` (or `> 0`
     when `after_cursor is None`).
5. **Operator-only admission & pre/post session/live-authority fencing:**
   - `JOB`, root `ORCHESTRATOR`, sandbox-bound `ORCHESTRATOR`, `EXTERNAL_PEER`, `OPERATOR` with
     bound `sandbox_addr`/`incarnation_id`, and non-`PrincipalCtx` all fail closed before target
     lookup (zero target-existence oracle).
   - Configured `session_validator` rejects omitted session args (`CoordAuthError`), partial pairs
     (`CoordValidationError`), pre-read retired session (`RevokedError`), and mid-read revoked
     session or `live_authority_checker` (`RevokedError`, zero frames returned); session args
     without a validator raise `CoordPolicyError`; valid reads echo `ReadSessionEcho`.
   - **Mid-read stream-identity race barrier (`on_after_snapshot_before_release`):** Pause a read
     after releasing the snapshot lock while keeping the operator session and live authority valid:
     (a) rotate the sandbox's `incarnation_id` -> held read fails closed with
     `IncarnationMismatchError("stale_incarnation_id")` returning zero frames;
     (b) rotate `stream_epoch` -> held read fails closed with `CoordPolicyError("stale_stream_epoch")`
     returning zero frames;
     (c) close the open stream -> held read fails closed with `RevokedError("terminal_stream_closed")`
     returning zero frames (while a *new* read opened on an already-closed stream succeeds with
     `stream_closed=True`!).
6. **Hard UTF-8 JSON byte caps, cross-frame SGR-reset-closed truncation, cursors, & `allow_nan=False`:**
   - 1 KiB `max_response_bytes` page containing escape-heavy text (`\"\\\"\n`) and multibyte UTF-8
     (both 1-candidate page without phantom cursor reservation and multi-candidate page with
     `next_cursor`) stays strictly `<= 1024` UTF-8 bytes, truncates cleanly at UTF-8 boundary, and
     paginates deterministically across `limit=1` pages with zero skips or duplicates.
   - **Cross-frame `SAFE_SGR` self-containment, bold+faint fidelity, & truncation:** Style opened in
     frame A (`b"\x1b[31mhello"` -> stored frame A ends with `"\x1b[0m"`), continued in frame B
     (`b"world\x1b[0m"` -> stored frame B prepends `"\x1b[31m"` and ends with `"\x1b[0m"`), PLUS
     a dedicated frame-boundary test with **both SGR `1` (bold) and SGR `2` (faint) active**
     (`b"\x1b[1;2mhello"` in frame A -> frame B `b"world\x1b[22mplain"` prepends `"\x1b[1;2m"` and
     clears both on SGR `22` so frame C `b"after"` starts with zero active SGR), PLUS
     truncating frame B's closing `"\x1b[0m"` BOTH at `MAX_FRAME_TEXT_BYTES` (`b"A" * 20000 + b"\x1b[0m"`)
     AND across a `max_response_bytes = 1024` page boundary (accounting for 6-byte JSON `\u001b`
     expansion) — verifying every emitted frame starts and ends in default style (`_sgr_is_open == False`),
     never splits mid-SGR, and stays strictly `<= max_bytes` / `<= max_response_bytes`.
   - Too-small envelope/item budget raises explicit `CoordValidationError`.
   - Cursor tampering (`pad_len == 3`, non-canonical base64 padding, extra whitespace, unknown key,
     embedded `NaN`, deeply nested JSON `RecursionError`, `bool`/`0`/negative/`> MAX_INT64` `ep` or
     `seq`, bad `fh`, control/bidi/surrogate `inc`, oversized `> 512` B, wrong
     target/terminal/incarnation/epoch) raises exact `CoordValidationError("cursor_malformed")` vs
     `CoordValidationError("cursor_scope_mismatch")`.
   - Direct `serialize_terminal_json` / `serialize_terminal_bytes` rejects `NaN`, `+Inf`, and `-Inf`
     with `ValueError` (`allow_nan=False`), and every returned `TerminalReplayPage` round-trips
     cleanly through `json.loads` with `untrusted_content=True` and `read_only=True`.
