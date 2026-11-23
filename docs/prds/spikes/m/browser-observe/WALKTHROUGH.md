# PRD M3.4 Read-Only Browser Frame & Navigation Provenance Pairing Walkthrough (`docs/prds/spikes/m/browser-observe/`)

Parent: [prd_m3.md](../../../prd_m3.md) · related: [prd_d.md](../../../prd_d.md), [prd_e.md](../../../prd_e.md),
[PROJECTION_WALKTHROUGH.md](../projection/PROJECTION_WALKTHROUGH.md) · builds read-only on
[oc_address.py](../oc_address.py) and [oc_coord_contract.py](../oc_coord_contract.py)

---

## 1. Scope, Boundaries, and Non-Goals

This Gate 1 walkthrough specifies the **standalone, offline, read-only M3.4 browser frame and
navigation provenance pairing slice** for embedded sandbox browser observation and the fleet PiP
Browser Wall. It models the trusted host-side boundary that pairs host-observed Chromium navigation
and TLS state with binary screencast frames, enforces strict stale-frame/generation/incarnation
fencing, redacts URL credentials/queries/fragments, scrubs untrusted page titles, and serves
operator-only, byte-bounded, `allow_nan=False` JSON snapshots.

### Owned File Boundary (Strictly Disjoint)

All documentation, implementation, and tests for this slice live exclusively under
`docs/prds/spikes/m/browser-observe/`:

- `WALKTHROUGH.md` — this Gate 1 design walkthrough.
- `oc_browser_contract.py` — frozen dataclasses with `__post_init__` invariant enforcement, schema
  version constants, hard bounds, closed enums, strict `allow_nan=False` JSON serializer, and
  collision-free canonical base64url JSON cursor codec.
- `oc_browser_validate.py` — backtracking-free browser-canonical ASCII URL/origin redactor &
  trust/TLS classifier, PNG/JPEG binary header & dimension inspector (provenance pairing only;
  full bounded bitstream decoding before display remains a downstream display gate), and linear-time
  ANSI/ECMA-48/C0/C1/bidi/NUL/surrogate single-line page-title scrubber.
- `oc_browser_observe.py` — thread-safe in-memory provenance pairing store and operator-only
  `BrowserObserveService` (`register_sandbox`, `set_sandbox_status`, `record_navigation`,
  `ingest_frame`, `get_surface_snapshot`, `list_browser_wall`) with pre/post authority & session
  fencing and hard UTF-8 JSON `max_response_bytes` enforcement.
- `test_browser_observe.py` — deterministic offline qualification suite covering every threat vector
  in Section 9 (pure Python stdlib, programmatic PNG/JPEG fixtures, fake monotonic clock).

**Zero edits to shared files:** This slice imports read-only symbols from `docs/prds/spikes/m/`
(`oc_address.py` and `oc_coord_contract.py`) without modifying any file outside
`docs/prds/spikes/m/browser-observe/`.

### Explicit Non-Goals (Out of Scope for This Slice)

- **Zero live Chromium / Podman / CDP I/O:** No Chromium containers, no DevTools WebSocket or UDS
  connections, no `Page.startScreencast` transport, and no Xvfb/noVNC framebuffers.
- **Zero browser control or input injection:** No CDP `Input.dispatch*`, mouse, keyboard, wheel,
  scroll, viewport resize, or `Page.navigate` commands.
- **Zero `InputLease` writes:** No lease minting, renewal, takeover quiescence, or controller state
  mutation.
- **Zero network access or DNS/TLS handshakes:** All navigation and TLS verification observations
  enter as typed host-side observations from the simulated trusted CDP arbiter boundary.
- **Zero filesystem or SQLite writes:** Pure in-memory store plus deterministic offline fixtures;
  never touches `~/.config/oc-sandbox`, `~/.local/share/oc-sandbox`, or `~/opencode-sandbox`.
- **Zero SvelteKit/Tauri frontend code** and zero changes to `oc-sandbox`, `oc-bridge.py`, shared
  `docs/prds/spikes/m/*.py` modules, or any PRD `Human review` checkbox.

---

## 2. Trust Boundaries, Threat Model, and Core Invariants

### 2.1 Trust Model

```text
Untrusted Sandbox App / Page DOM / Rendered Pixels
  │  (controls page pixels, document.title, redirects, URL query/fragment/userinfo)
  ▼
Chromium Sidecar (isolated-sidecars, --network=none, CA public cert only)
  │  (host-only 0o600 CDP UDS — simulated here via trusted host ingestion calls)
  ▼
BrowserObserveService (Trusted Host Provenance Pairing Boundary — THIS SLICE)
  ├── Validates, scrubs, redacts, and classifies browser-canonical ASCII navigations
  ├── Performs PNG/JPEG header inspection (magic bytes, IHDR/SOF dims, SHA-256; not full decode)
  ├── Enforces exact (sandbox_addr, incarnation_id, surface_id, capture_generation, nav_generation) pairing
  ├── Retires capture_generation on disconnect/disable and drops/quarantines stale/future/replayed frames
  ├── Evaluates frame freshness strictly against an injected monotonic clock + post-pack release fence
  └── Serves operator-only, session-fenced, byte-bounded JSON snapshots (untrusted_content=True)
```

### 2.2 Non-Negotiable Security Invariants

1. **Every browser frame is unconditionally untrusted (`untrusted_content = True`):** Even a frame
   rendered from `https://<NAME>.oc-sandbox.internal` with verified internal-CA TLS comes from an
   agent-controlled app inside the sandbox that can paint fake approval modals, spoofed URL bars,
   or prompt-injection text. `PairedBrowserFrame`, `BrowserSurfaceSnapshot`, and `BrowserWallTile`
   enforce `untrusted_content is True` structurally in `__post_init__`.
2. **Zero cross-navigation or cross-capture-generation frame pairing (anti-spoofing):** A frame
   carrying a mismatched `capture_generation` or `nav_generation != current_nav.nav_generation` can
   NEVER be paired with a newer navigation or resumed capture session. Committing a new
   `nav_generation` atomically clears `paired_frame` and `paired_frame_bytes`; disconnecting or
   disabling a sandbox atomically retires `capture_generation` (incrementing it) and clears
   `current_nav`, `paired_frame`, and `paired_frame_bytes` across all surfaces so delayed pre-stop
   frames can never be admitted after resume.
3. **Structural pairing invariant:** `PairedBrowserFrame.__post_init__` enforces exact equality of
   `SurfaceKey(sandbox_addr, incarnation_id, surface_id, capture_generation)` and `nav_generation`
   between its `nav: BrowserNavState` and `frame: BrowserFrameMeta` components, plus
   `untrusted_content is True`. A mismatched pairing is unrepresentable.
4. **Zero URL secret leakage:** Userinfo (`user:pass@`), query strings (`?token=SECRET`), and
   fragments (`#jwt=XYZ`) are stripped before storage or projection and are **never** interpolated
   into error messages, snapshots, or PiP wall tiles.
5. **Opt-in capability enforcement:** Sandboxes registered with `browser_enabled = False` refuse
   navigation/frame ingestion and `get_surface_snapshot` with
   `CoordPolicyError("browser_service_not_enabled")`, and never appear in `list_browser_wall`.
6. **Terminal `"revoked"` per incarnation:** Once an incarnation enters `status == "revoked"`, it
   can never transition back to `"running"`, `"starting"`, `"stopped"`, or `"degraded"` under the
   same `incarnation_id` (`RevokedError("incarnation_revoked")`); resuming requires rotating to a
   fresh `incarnation_id`.
7. **Strict monotonic clock & finite numerics:** Frame TTL expiry and monotonicity use an injectable
   monotonic clock (`clock: Callable[[], float] = time.monotonic`), sampled **inside `with lock:`**
   for every mutation and read snapshot so concurrent callers cannot observe inverted timestamps.
   Every float input and clock sample is validated finite (`math.isfinite`, rejecting `bool`, `NaN`,
   `+/-Inf`, and negatives), every positive sequence/generation integer is capped at
   `1 <= x <= MAX_SQLITE_INT64` (`(1 << 63) - 1`), and every JSON serialization uses `allow_nan=False`.
8. **Hard memory & DoS caps:**
   - `MAX_TRACKED_SANDBOXES = 256`
   - `MAX_SURFACES_PER_SANDBOX = 16`
   - `MAX_FRAME_BYTES = 512 * 1024` (512 KiB; at most **one** active paired frame buffer retained
     per surface; quarantined/rejected frames retain zero payload bytes)
   - `MAX_QUARANTINE_HISTORY_PER_SURFACE = 32` (bounded ring of lightweight metadata records)
   - `MAX_ROTATIONS_PER_SANDBOX = 256` (fail-closed ceiling on tracked superseded incarnations per
     sandbox so historical `incarnation_id`s are never evicted and can never be re-registered)
   - Thread safety: all store mutations and snapshot reads synchronize under an internal
     `threading.RLock()`; immutable snapshots are built under lock and serialized/fenced outside.

### 2.3 Sandbox Target Addressing & Exception Wrapping

Browser surfaces belong to sandboxes (`"NAME"` local or `"REMOTE / NAME"` remote) and NEVER to
external peers (`"@PEER"`). Because `oc_address.parse_canonical_addr` and
`oc_coord_contract.validate_opaque_token` can raise `AddressError` (which is a `ValueError`, NOT a
`CoordValidationError`) and may include raw text in their messages, `oc_browser_contract.py` imports
`AddressError` and wraps all address/token checks in closed-error helpers:

- `parse_sandbox_target(raw: object) -> TargetAddr`: calls `parse_canonical_addr(raw)` inside
  `try/except AddressError`, converting any failure to
  `CoordValidationError("invalid_sandbox_target")` (never echoing `raw`), and rejects
  `addr.kind == "peer"` with `CoordValidationError("peer_target_not_sandbox")`. Both local
  (`"feat-a"`) and remote (`"macmini / feat-a"`) targets expose the validated instance atom
  `addr.name == "feat-a"`, which anchors `<NAME>.oc-sandbox.internal` matching.
- `validate_token_strict(value: object, label: str) -> str`: wraps `validate_opaque_token`,
  catching `(AddressError, CoordValidationError)` and raising `CoordValidationError(f"invalid_{label}")`
  without echoing raw inputs.

---

## 3. Input Validation, Redaction, & Classification (`oc_browser_validate.py`)

### 3.1 Backtracking-Free URL Parser, Redactor, & Origin/TLS Classifier

All URL parsing uses linear `O(n)` string scans and character-set checks (zero backtracking regexes)
and raises `CoordValidationError("<closed_code>")` **without echoing `raw_url`** so embedded
credentials can never leak into logs or stack traces.

```python
ALLOWED_URL_SCHEMES = frozenset({"http", "https"})
VALID_TLS_EVIDENCE = frozenset({"sandbox_internal_ca", "external_ca", "tls_error", "unknown"})
SANDBOX_INTERNAL_DOMAIN = "oc-sandbox.internal"
SANDBOX_INTERNAL_SUFFIX = ".oc-sandbox.internal"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
MAX_RAW_URL_BYTES = 8_192
MAX_DISPLAY_URL_BYTES = 2_048
MAX_PATH_BYTES = 256
_NUMERIC_OR_HEX_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$", re.ASCII)

function parse_and_classify_url(
    raw_url,
    *,
    sandbox_instance_name: str,
    tls_verified: bool,
    tls_state_evidence: str | None = None,
    reject_userinfo: bool = False,
) -> ParsedBrowserUrl:
    # 1. Fail-closed pre-encode validation (checks surrogates BEFORE .encode("utf-8") so a
    #    hostile surrogate + credentials URL can never raise UnicodeEncodeError echoing raw_url!)
    require isinstance(raw_url, str)
    require 1 <= len(raw_url) <= MAX_RAW_URL_BYTES else CoordValidationError("url_length_invalid")
    reject if has_forbidden_control_or_bidi(raw_url) or any(ch.isspace() for ch in raw_url)
    try:
        raw_bytes = raw_url.encode("utf-8")
    except UnicodeEncodeError:
        raise CoordValidationError("url_invalid_utf8")
    require 1 <= len(raw_bytes) <= MAX_RAW_URL_BYTES else CoordValidationError("url_length_invalid")

    # 2. Linear scheme scan before first ':', '/', '?', '#'
    #    Allow ONLY "http://" and "https://" (case-insensitive ASCII scheme).
    #    Unconditionally rejects javascript:, data:, file:, chrome:, chrome-extension:,
    #    devtools:, about: (incl. about:srcdoc), blob:, view-source:, ftp:, ws:, wss:,
    #    schemeless URLs, and protocol-relative "//host".
    scheme, after_scheme = split_http_https_scheme(raw_url)

    # 3. Split fragment ('#') and query ('?') BEFORE inspecting authority/path
    #    Record fragment_redacted / query_redacted booleans and discard raw query/fragment bytes.
    before_frag, fragment_redacted = strip_after_first(after_scheme, "#")
    before_query, query_redacted = strip_after_first(before_frag, "?")

    # 4. Reject backslash '\' anywhere in authority or path (blocks WHATWG/RFC3986
    #    differential confusion such as "https://evil.com\@feat-a.oc-sandbox.internal").
    reject if "\\" in before_query

    # 5. Split authority and path at first '/'
    authority, raw_path = split_authority_and_path(before_query)
    reject if not authority

    # 6. Userinfo ('@') handling:
    #    - If reject_userinfo=True: raise CoordValidationError("url_userinfo_rejected").
    #    - Default (host-observer redaction): split on LAST '@' (RFC 3986 / WHATWG),
    #      discard userinfo immediately (never stored/logged), set userinfo_redacted=True,
    #      and refuse trust elevation (origin_trust forced to "external_untrusted").
    hostport, userinfo_redacted = strip_userinfo(authority, reject_userinfo=reject_userinfo)

    # 7. Parse host and optional port strictly (preserving browser-observed ASCII origin spelling;
    #    NEVER calling Python's stdlib host.encode("idna") which implements IDNA 2003 and can
    #    diverge from Chromium's UTS #46 canonicalization, e.g. "straße.example"!):
    #    - Strict browser-canonical ASCII host contract:
    #      * Require host.isascii() — reject ANY non-ASCII hostname (including "straße.example",
    #        "bücher.example", fullwidth ASCII, ideographic dots \u3002/\uff0e/\uff61, and
    #        invisible Cf chars) with CoordValidationError("url_host_non_canonical"). Already-
    #        punycoded ASCII labels emitted by Chromium (e.g. "xn--strae-oqa.example",
    #        "xn--bcher-kva.example") are preserved verbatim after ASCII lowercasing!
    #    - Bracketed IPv6 "[...]": validate via ipaddress.IPv6Address (reject zone IDs '%',
    #      reject malformed literals); normalize to compressed form; loopback iff == IPv6Address("::1")
    #      (IPv4-mapped [::ffff:127.0.0.1] is NOT loopback).
    #    - Non-IPv6 ASCII host:
    #      * Reject '%' and leading/trailing/empty dot labels; lowercase ASCII host.
    #    - Canonical IPv4 vs. ambiguous numeric/hex/octal/short IPv4 rejection:
    #      * Accept IPv4 ONLY if ascii_host == str(ipaddress.IPv4Address(ascii_host)).
    #      * Otherwise reject ANY host whose last label matches _NUMERIC_OR_HEX_LABEL_RE
    #        (^(?:0x[0-9a-f]+|[0-9]+)$) OR whose labels all match it (blocks 2130706433,
    #        0x7f000001, 0177.0.0.1, 127.1, 0x7f.0.0.1, 127.0.0.01!).
    #      * Validate RFC-1123 DNS labels (1..63 ASCII alnum/hyphen, total <= 253).
    #    - Port (optional): require 1 <= len(port_str) <= 5, port_str.isascii() and
    #      port_str.isdigit(), port_str[0] != "0", 1 <= int(port_str) <= 65535.
    #      Omit default port (80 for http, 443 for https); preserve non-default port (:8443).
    ascii_host, host_kind, port = parse_strict_host_port(hostport, scheme=scheme)

    # 8. Sanitize & bound path_redacted (defaults to "/", starts with "/", <= MAX_PATH_BYTES UTF-8)
    path_redacted, path_truncated = truncate_utf8_clean(raw_path or "/", MAX_PATH_BYTES)

    # 9. Assemble canonical origin & verify display_url <= MAX_DISPLAY_URL_BYTES
    origin = format_origin(scheme, ascii_host, host_kind, port)
    require len(f"{origin}{path_redacted}".encode("utf-8")) <= MAX_DISPLAY_URL_BYTES

    # 10. Classify tls_state, effective_tls_verified, and origin_trust (exact matrix below)
    tls_state, effective_tls_verified, origin_trust = classify_origin_and_tls(
        scheme=scheme,
        ascii_host=ascii_host,
        sandbox_instance_name=sandbox_instance_name,
        tls_verified=tls_verified,
        tls_state_evidence=tls_state_evidence,
        userinfo_redacted=userinfo_redacted,
    )
    return ParsedBrowserUrl(...)
```

#### Exact `tls_state`, `effective_tls_verified`, and `origin_trust` Classification Matrix

`tls_state` and `effective_tls_verified` are always resolved **first** (strictly requiring explicit
same-document CA evidence and downgrading every mismatched CA/host pairing to `"unknown"` / `False`),
and the `userinfo_redacted` trust cap is applied **second**. Because all admitted hostnames must
arrive in browser-canonical ASCII form (`url_host_non_canonical` rejects any non-ASCII host without
re-encoding), `ascii_host` preserves Chromium's exact UTS #46 / punycode spelling.

Define:
- `is_own_sandbox_internal = (ascii_host == f"{NAME}.oc-sandbox.internal")`
- `is_internal_namespace = (ascii_host == "oc-sandbox.internal") or ascii_host.endswith(".oc-sandbox.internal")`

| Condition | `tls_state` | `effective_tls_verified` | `origin_trust` | `untrusted_content` |
|---|---|---|---|---|
| `scheme == "http"` AND (`tls_verified == True` OR `tls_state_evidence is not None`) | **Rejected** (`CoordValidationError("http_cannot_be_tls_verified")`) | — | — | — |
| `scheme == "https"` AND (`tls_state_evidence` not in `VALID_TLS_EVIDENCE \| {None}`, OR `tls_verified=True` with `"tls_error"`/`"unknown"`, OR `tls_verified=False` with `"sandbox_internal_ca"`/`"external_ca"`) | **Rejected** (`CoordValidationError("invalid_tls_evidence")`) | — | — | — |
| `scheme == "https"` AND `tls_state_evidence is None` (missing CA evidence — NEVER fabricates CA trust!) | `"unknown"` | `False` | `"external_untrusted"` | `True` |
| `scheme == "https"` AND `tls_state_evidence == "unknown"` | `"unknown"` | `False` | `"external_untrusted"` | `True` |
| `scheme == "https"` AND `tls_state_evidence == "tls_error"` | `"tls_error"` | `False` | `"external_untrusted"` | `True` |
| `scheme == "https"` AND `tls_state_evidence == "sandbox_internal_ca"` AND `is_own_sandbox_internal` AND `not userinfo_redacted` | `"sandbox_internal_ca"` | `True` | `"sandbox_internal_https"` | `True` |
| `scheme == "https"` AND `tls_state_evidence == "sandbox_internal_ca"` AND `is_own_sandbox_internal` AND `userinfo_redacted` | `"sandbox_internal_ca"` | `True` | `"external_untrusted"` | `True` |
| `scheme == "https"` AND `tls_state_evidence == "sandbox_internal_ca"` AND `not is_own_sandbox_internal` (sibling sandbox, subdomain, bare `oc-sandbox.internal`, `localhost`, IP, or external host!) | `"unknown"` | `False` | `"external_untrusted"` | `True` |
| `scheme == "https"` AND `tls_state_evidence == "external_ca"` AND `is_internal_namespace` (bare, own, sibling, or subdomain `*.oc-sandbox.internal`!) | `"unknown"` | `False` | `"external_untrusted"` | `True` |
| `scheme == "https"` AND `tls_state_evidence == "external_ca"` AND `not is_internal_namespace` | `"verified_external_tls"` | `True` | `"external_untrusted"` | `True` |
| `scheme == "http"` AND `ascii_host in {"127.0.0.1", "::1", "localhost"}` AND `not userinfo_redacted` | `"http_unencrypted"` | `False` | `"loopback_http"` | `True` |
| `scheme == "http"` AND (`userinfo_redacted` OR non-loopback host, incl. `http://<NAME>.oc-sandbox.internal` or `http://sub.localhost`) | `"http_unencrypted"` | `False` | `"external_untrusted"` | `True` |

*Port & CA alignment with `prd_d.md`, `prd_e.md`, and `prd_m3.md`:*
- Default `:443` on `https` (and `:80` on `http`) is omitted from canonical `origin`. Non-default
  ports (e.g., `https://feat-a.oc-sandbox.internal:8443/app`) are preserved in `origin`
  (`"https://feat-a.oc-sandbox.internal:8443"`) and still qualify for `"sandbox_internal_https"`
  when `tls_verified=True` and `tls_state_evidence="sandbox_internal_ca"` (leaf certs cover the host
  across declared app preview ports).
- Profile E excludes IP SANs and `localhost` from the sandbox CA, so `https://127.0.0.1` and
  `https://localhost` never earn `"sandbox_internal_https"` or `"loopback_http"`.

### 3.2 PNG & JPEG Binary Header Inspection & Dimension Guard (Provenance Pairing Scope)

Strictly matches `prd_m3.md:271-273, 454` (CDP `Page.startScreencast` formats — PNG and JPEG only;
WebP, SVG, GIF, and all other media types are unconditionally rejected).

**Scope clarification:** `_validate_png_header` and `_validate_jpeg_header` perform **binary header
inspection and provenance pairing** (verifying magic bytes, IHDR/SOF dimensions, pixel ceiling, and
computing the authoritative SHA-256 digest over the supplied bytes). They do **not** perform full
image decompression/decoding; **full bounded bitstream decoding before display remains a separate
downstream display gate** (e.g., confined `<canvas>` `createImageBitmap` / display decoder per
`prd_m3.md:271-280`).

```python
ALLOWED_FRAME_MEDIA_TYPES = frozenset({"image/png", "image/jpeg"})
MIN_FRAME_BYTES = 16
MAX_FRAME_BYTES = 512 * 1024        # 512 KiB
MIN_FRAME_WIDTH = 1
MAX_FRAME_WIDTH = 4096
MIN_FRAME_HEIGHT = 1
MAX_FRAME_HEIGHT = 4096
MAX_FRAME_PIXELS = 4096 * 2160      # 8,847,360 pixels (~33.75 MiB RGBA decode ceiling)
MAX_JPEG_SEGMENTS = 256             # linear marker-scan DoS guard
```

Header-inspection rules (exact fail-closed order):

1. **Type & size gate:** Require `type(frame_bytes) is bytes` (rejects mutable `bytearray`,
   `memoryview`, `str`) and `MIN_FRAME_BYTES <= len(frame_bytes) <= MAX_FRAME_BYTES`.
2. **Closed MIME allowlist:** Require `media_type in ALLOWED_FRAME_MEDIA_TYPES` (unconditionally
   rejects `image/webp`, `image/svg+xml`, `image/gif`, `text/html`, arbitrary strings with
   `CoordValidationError("frame_media_type_unsupported")`).
3. **Magic-byte vs. declared MIME parity:** Detect actual format from leading magic bytes:
   - PNG: `b"\x89PNG\r\n\x1a\n"`
   - JPEG: `b"\xff\xd8\xff"`
   If detected format is unknown or differs from declared `media_type`, raise
   `CoordValidationError("frame_media_type_mismatch")`.
4. **Format-specific header & dimension inspection:**
   - **PNG (`_validate_png_header`):**
     - Require `len >= 33`, first chunk length == `13` (`b"\x00\x00\x00\x0d"`), type == `b"IHDR"`.
     - Verify IHDR CRC-32 (`zlib.crc32(raw[12:29]) & 0xFFFFFFFF == struct.unpack(">I", raw[29:33])[0]`).
     - Parse big-endian uint32 `width, height = struct.unpack(">II", raw[16:24])`, plus
       `bit_depth, color_type, compression, filter_method, interlace = raw[24:29]`.
     - Validate legal PNG `(color_type, bit_depth)` pairs:
       `{0: {1,2,4,8,16}, 2: {8,16}, 3: {1,2,4,8}, 4: {8,16}, 6: {8,16}}`, and require
       `compression == 0`, `filter_method == 0`, `interlace in (0, 1)`.
   - **JPEG (`_validate_jpeg_header`):**
     - Walk markers linearly from `pos = 2`, bounded by `MAX_JPEG_SEGMENTS = 256` iterations.
     - At every marker boundary, require `pos < len(raw)` AND **`raw[pos] == 0xFF`** (else
       `CoordValidationError("frame_jpeg_malformed")`).
     - Skip fill `0xFF` bytes (`while pos < len(raw) and raw[pos] == 0xFF: pos += 1`), then
       **explicitly check `if pos >= len(raw): raise CoordValidationError("frame_jpeg_malformed")`**
       before reading `marker = raw[pos]; pos += 1` (so trailing `0xFF` bytes never raise
       `IndexError`).
     - **Explicitly reject** `marker == 0x00` (byte-stuffing outside entropy data), `marker == 0xD8`
       (nested SOI), and `0xD0 <= marker <= 0xD7` (RSTn restart markers before SOF/SOS) with
       `CoordValidationError("frame_jpeg_malformed")`.
     - Handle standalone `marker == 0x01` (TEM); abort with
       `CoordValidationError("frame_jpeg_missing_sof")` if `EOI` (`0xD9`) or `SOS` (`0xDA`) is hit
       before any SOF marker.
     - For all length-bearing segments (including `APP1` EXIF, `COM`, `DQT`, `DHT`, `SOF*`),
       **explicitly check `if pos + 2 > len(raw): raise CoordValidationError("frame_jpeg_malformed")`**
       before unpacking 2-byte big-endian `seg_len` (so truncated markers never raise `struct.error`);
       require `seg_len >= 2` and `pos + seg_len <= len(raw)`.
     - On SOF markers (`0xC0..0xC3`, `0xC5..0xC7`, `0xC9..0xCB`, `0xCD..0xCF`):
       - Require **`seg_len >= 11`**, sample precision `raw[pos + 2] in (8, 12, 16)`,
         `height, width = struct.unpack(">HH", raw[pos + 3 : pos + 7])`,
         component count `nf = raw[pos + 7] >= 1`, and **`seg_len == 8 + 3 * nf`**.
       - Stop scan and validate dimensions.
     - Otherwise advance `pos += seg_len` atomically (so an `APP1` EXIF thumbnail embedding a fake
       `FF C0` SOF sequence inside its segment payload is skipped cleanly without spoofing the main
       image's dimensions!).
5. **Decompression-bomb dimension & pixel bounds:** Require
   `MIN_FRAME_WIDTH <= width <= MAX_FRAME_WIDTH`, `MIN_FRAME_HEIGHT <= height <= MAX_FRAME_HEIGHT`,
   and `width * height <= MAX_FRAME_PIXELS` (`8_847_360`), else raise
   `CoordValidationError("frame_dimensions_out_of_bounds")`.
6. **Authoritative digest:** Compute `frame_sha256 = hashlib.sha256(frame_bytes).hexdigest()` over
   the exact supplied bytes.

### 3.3 Deterministic Single-Line Page Title Scrubber

Untrusted `document.title` values pass through a linear-time `O(n)` state machine (`scrub_page_title`):

1. Require `isinstance(raw_title, str)`. Bound input scan to `MAX_RAW_TITLE_CHARS = 4_096` (if
   longer, inspect the 4,096-char prefix and set `title_truncated = True`, `title_scrubbed = True`
   to prevent CPU amplification on multi-MB hostile titles).
2. **Escape-sequence stripping (`_strip_terminal_escapes`, before single-char filtering):**
   - **7-bit ESC (`0x1B`):**
     - `ESC [` -> CSI state: consume parameter/intermediate bytes (`0x20..0x3F`) until final byte
       (`0x40..0x7E`); **if a nested `0x1B` appears inside CSI**, immediately restart ESC dispatch
       from that `0x1B` (so `\x1b[31\x1b]52;c;AAAA\x07` transitions into OSC and strips the entire
       OSC 52 payload instead of leaking `52;c;AAAA`!).
     - `ESC ]` (OSC) or `ESC P / X / ^ / _` (DCS/SOS/PM/APC) -> string state: consume until BEL
       (`\x07`, for OSC), 7-bit ST (`ESC \`), or **8-bit ST (`\x9c`)**, or end-of-prefix.
     - **ECMA-48 `nF` sequences:** `ESC` + zero or more intermediate bytes `0x20..0x2F` (e.g.,
       `\x1b(0`, `\x1b#8`) + final byte `0x30..0x7E` — consumed completely so `\x1b(0Title` becomes
       `"Title"`.
   - **8-bit C1 sequences (`0x9B` CSI, `0x9D` OSC, `0x90`/`0x98`/`0x9E`/`0x9F` DCS/SOS/PM/APC):**
     Identical CSI (with nested `ESC` restart) and string-terminator (`\x07` for OSC, `ESC \`, or
     `\x9c` 8-bit ST) handling.
   - Unterminated sequences consume to end-of-prefix and set `title_scrubbed = True`.
3. **Character filtering & single-line collapse:**
   - Normalize **every** `ch.isspace()` (including `\r`, `\n`, `\t`, `\v`, `\f`, `U+00A0` NBSP,
     `U+2028` Line Separator, `U+2029` Paragraph Separator, `U+3000`) to ASCII space `" "`
     (setting `title_scrubbed = True` whenever `ch != " "`).
   - Drop NUL (`\x00`), remaining C0 (`< 0x20`), DEL (`0x7F`), C1 (`0x80..0x9F`), lone surrogates
     (`0xD800..0xDFFF`), and Unicode bidi characters (`U+202A..U+202E`, `U+2066..U+2069`,
     `U+200E`, `U+200F`, `U+061C`), setting `title_scrubbed = True`.
   - Collapse consecutive ASCII spaces and `.strip()`.
4. **UTF-8 byte cap:** Truncate cleanly on UTF-8 character boundary to `MAX_TITLE_BYTES = 256`
   bytes (`title_truncated = True` if shortened).

---

## 4. Authoritative Navigation <-> Frame Provenance Pairing Model (`oc_browser_observe.py`)

### 4.1 Surface State, Capture Generation, & Monotonic Counters

`VALID_SANDBOX_STATUSES = frozenset({"starting", "running", "stopped", "revoked", "degraded"})`
(matching `oc_coord_contract.SANDBOX_LIFECYCLE_STATES`; only `"running"` admits navigations/frames).

Every sandbox browser record tracks a strictly monotonic **`capture_generation: int`**
(`1 <= capture_generation <= MAX_SQLITE_INT64`, starting at `1` on initial registration or fresh
incarnation rotation):

- Whenever an active capture session (`status == "running" and browser_enabled is True`) leaves
  `"running"` (disconnect/stop/degraded/starting/revoked) OR toggles `browser_enabled` to `False`,
  the service **atomically retires the current capture generation**:
  1. Increments `sb.capture_generation += 1` (raising `CoordPolicyError("max_capture_generations_exceeded")`
     at `MAX_SQLITE_INT64`), and
  2. Clears **`surf.current_nav = None`, `surf.paired_frame = None`, and
     `surf.paired_frame_bytes = None`** across all surfaces of `sb`!
- Both `record_navigation` and `ingest_frame` require an explicit `capture_generation` matching
  `sb.capture_generation` (else fail closed with `CoordPolicyError("stale_capture_generation")`),
  closing the delayed pre-stop frame race across disconnect/disable/resume cycles.

Every browser surface is uniquely keyed by
`SurfaceKey(sandbox_addr, incarnation_id, surface_id, capture_generation)` under its parent sandbox
record and tracks:

- `current_nav: BrowserNavState | None` — latest host-observed committed navigation for the active
  `capture_generation` (cleared to `None` whenever `capture_generation` is retired).
- `last_nav_generation: int` — strictly monotonic navigation watermark across the surface's
  incarnation lifetime (starts at `0`; every `record_navigation` requires
  `last_nav_generation < nav_generation <= MAX_SQLITE_INT64`, even across `capture_generation`
  bumps).
- `last_frame_seq: int` — strictly monotonic frame sequence watermark across the surface's
  incarnation lifetime (starts at `0`; every accepted frame requires
  `last_frame_seq < frame_seq <= MAX_SQLITE_INT64`).
- `last_nav_committed_at: float | None` and `last_frame_captured_at: float | None` — monotonic
  timestamp watermarks (preventing time rollback even after `current_nav` is cleared on disconnect).
- `paired_frame: PairedBrowserFrame | None` — present **iff** a header-inspected frame has been
  admitted for the **exact** `(capture_generation, current_nav.nav_generation)` while the sandbox
  remained `"running"` and enabled.
- `paired_frame_bytes: bytes | None` — raw supplied bytes of `paired_frame` (`<= 512 KiB`), always
  cleared **together with `paired_frame = None`** on navigation commit, incarnation rotation,
  `browser_enabled = False`, or transition to any non-`"running"` status.
- `dropped_frame_counts: dict[str, int]` and `quarantine_recent: deque[QuarantinedFrameEvent]`
  (bounded to `MAX_QUARANTINE_HISTORY_PER_SURFACE = 32`, zero payload bytes stored).

### 4.2 Lifecycle & Ingestion Pseudocode

```python
function clear_surface_state(sb):
    for surf in sb.surfaces.values():
        surf.current_nav = None
        surf.paired_frame = None
        surf.paired_frame_bytes = None

function retire_capture_generation(sb):
    if sb.capture_generation >= MAX_SQLITE_INT64:
        raise CoordPolicyError("max_capture_generations_exceeded")
    sb.capture_generation += 1
    clear_surface_state(sb)

function register_sandbox(sandbox_addr, *, incarnation_id, browser_enabled=True, status="running"):
    target = parse_sandbox_target(sandbox_addr)                # wraps AddressError; rejects @PEER
    inc = validate_token_strict(incarnation_id, "incarnation_id")
    require type(browser_enabled) is bool
    require status in VALID_SANDBOX_STATUSES
    with lock:
        existing = sandboxes.get(target.canonical)
        if existing is not None:
            if inc == existing.current_incarnation_id:
                if existing.status == "revoked":
                    if status != "revoked" or browser_enabled != existing.browser_enabled:
                        raise RevokedError("incarnation_revoked")
                    return
                was_active = (existing.status == "running" and existing.browser_enabled)
                is_active = (status == "running" and browser_enabled)
                if was_active and not is_active:
                    retire_capture_generation(existing)        # checked before mutating status/enabled!
                elif not is_active:
                    clear_surface_state(existing)
                existing.browser_enabled = browser_enabled
                existing.status = status
                return
            if inc in existing.superseded_incarnations:
                raise IncarnationMismatchError("superseded_incarnation")
            if len(existing.superseded_incarnations) >= MAX_ROTATIONS_PER_SANDBOX:
                raise CoordPolicyError("max_incarnation_rotations_exceeded")
            # Incarnation rotation: retire old incarnation, reset capture_generation=1 & purge all surfaces!
            existing.superseded_incarnations.add(existing.current_incarnation_id)
            existing.current_incarnation_id = inc
            existing.capture_generation = 1
            existing.browser_enabled = browser_enabled
            existing.status = status
            existing.surfaces.clear()
            return
        require len(sandboxes) < MAX_TRACKED_SANDBOXES else CoordPolicyError("max_sandboxes_exceeded")
        sandboxes[target.canonical] = SandboxBrowserRecord(capture_generation=1, ...)

function set_sandbox_status(sandbox_addr, *, incarnation_id, status):
    target = parse_sandbox_target(sandbox_addr)
    inc = validate_token_strict(incarnation_id, "incarnation_id")
    require status in VALID_SANDBOX_STATUSES
    with lock:
        sb = sandboxes.get(target.canonical)
        if sb is None:
            raise CoordPolicyError("sandbox_not_found")
        if inc != sb.current_incarnation_id:
            raise IncarnationMismatchError("superseded_incarnation")
        if sb.status == "revoked":
            if status != "revoked":
                raise RevokedError("incarnation_revoked")      # revoked is terminal per incarnation!
            return
        was_active = (sb.status == "running" and sb.browser_enabled)
        is_active = (status == "running" and sb.browser_enabled)
        if was_active and not is_active:
            retire_capture_generation(sb)                      # checked before mutating status!
        elif not is_active:
            clear_surface_state(sb)
        sb.status = status

function record_navigation(
    sandbox_addr, *, incarnation_id, surface_id, capture_generation, nav_generation,
    raw_url, tls_verified, tls_state_evidence=None, page_title="", committed_at=None,
) -> BrowserNavState:
    target = parse_sandbox_target(sandbox_addr)
    inc = validate_token_strict(incarnation_id, "incarnation_id")
    sid = validate_token_strict(surface_id, "surface_id")
    validate_positive_int(capture_generation, "capture_generation")  # 1 <= x <= MAX_SQLITE_INT64
    validate_positive_int(nav_generation, "nav_generation")          # 1 <= x <= MAX_SQLITE_INT64
    require type(tls_verified) is bool
    explicit_ts = None if committed_at is None else validate_finite_nonneg_float(committed_at, "committed_at")
    # Validate & redact browser-canonical ASCII URL + scrub page title BEFORE mutating state
    parsed = parse_and_classify_url(
        raw_url, sandbox_instance_name=target.name,
        tls_verified=tls_verified, tls_state_evidence=tls_state_evidence,
    )
    title_clean, title_scrubbed, title_truncated = scrub_page_title(page_title)

    with lock:
        now = read_monotonic_clock()                           # sampled INSIDE lock (zero clock race!)
        ts = now if explicit_ts is None else explicit_ts
        if ts > now:
            raise CoordValidationError("committed_at_in_future")
        sb = require_enabled_sandbox(target.canonical)
        if inc != sb.current_incarnation_id:
            raise IncarnationMismatchError("superseded_incarnation")
        if sb.status != "running":
            raise CoordPolicyError("sandbox_not_running")
        if capture_generation != sb.capture_generation:
            raise CoordPolicyError("stale_capture_generation")
        surf = sb.surfaces.get(sid)
        if surf is not None:
            if nav_generation <= surf.last_nav_generation:
                raise CoordValidationError("non_monotonic_nav_generation")
            min_ts = max_non_none(surf.last_nav_committed_at, surf.last_frame_captured_at)
            if min_ts is not None and ts < min_ts:
                raise CoordValidationError("committed_at_non_monotonic")
        else:
            require len(sb.surfaces) < MAX_SURFACES_PER_SANDBOX else CoordPolicyError("max_surfaces_exceeded")
            surf = SurfaceRecord(surface_id=sid)
            sb.surfaces[sid] = surf

        skey = SurfaceKey(target.canonical, inc, sid, capture_generation)
        nav = BrowserNavState(surface_key=skey, nav_generation=nav_generation, ...)
        surf.current_nav = nav
        surf.last_nav_generation = nav_generation
        surf.last_nav_committed_at = ts
        # CRITICAL ANTI-SPOOFING FENCE: immediately clear previous nav_generation's paired frame!
        surf.paired_frame = None
        surf.paired_frame_bytes = None
        return nav

function ingest_frame(
    sandbox_addr, *, incarnation_id, surface_id, capture_generation, nav_generation,
    frame_seq, media_type, frame_bytes, captured_at=None,
) -> FrameAdmissionResult:
    # Step 1: Validate caller argument types & bounds (CoordValidationError on bad types)
    target = parse_sandbox_target(sandbox_addr)
    inc = validate_token_strict(incarnation_id, "incarnation_id")
    sid = validate_token_strict(surface_id, "surface_id")
    validate_positive_int(capture_generation, "capture_generation")  # 1 <= x <= MAX_SQLITE_INT64
    validate_positive_int(nav_generation, "nav_generation")          # 1 <= x <= MAX_SQLITE_INT64
    validate_positive_int(frame_seq, "frame_seq")                    # 1 <= x <= MAX_SQLITE_INT64
    explicit_ts = None if captured_at is None else validate_finite_nonneg_float(captured_at, "captured_at")

    # Step 2: PNG/JPEG binary header inspection (size 16..512 KiB, magic bytes, IHDR/SOF dims,
    #         pixel cap, SHA-256). Always rejects malformed/spoofed headers before lock!
    header = validate_frame_bytes(media_type, frame_bytes)

    with lock:
        now = read_monotonic_clock()                           # sampled INSIDE lock (zero clock race!)
        ts = now if explicit_ts is None else explicit_ts
        if ts > now:
            raise CoordValidationError("frame_captured_at_in_future")
        sb = require_enabled_sandbox(target.canonical)

        # Step 3: Superseded incarnation fence (never touches current incarnation's surfaces!)
        if inc != sb.current_incarnation_id:
            sb.superseded_frame_drops += 1
            return FrameAdmissionResult(accepted=False, stale_reason="superseded_incarnation")

        # Step 4: Sandbox lifecycle fence
        if sb.status != "running":
            return FrameAdmissionResult(accepted=False, stale_reason="sandbox_not_running")

        # Step 5: Capture-generation fence (blocks delayed pre-stop/pre-disable frames after resume!)
        if capture_generation != sb.capture_generation:
            surf_existing = sb.surfaces.get(sid)
            if surf_existing is not None:
                record_quarantine(surf_existing, frame_seq, nav_generation, "stale_capture_generation", now)
            raise CoordPolicyError("stale_capture_generation")

        # Step 6: Surface & nav_generation fence
        surf = sb.surfaces.get(sid)
        if surf is None or surf.current_nav is None:
            return FrameAdmissionResult(accepted=False, stale_reason="unknown_nav_generation")
        cur_gen = surf.current_nav.nav_generation
        if nav_generation < cur_gen:
            record_quarantine(surf, frame_seq, nav_generation, "stale_nav_generation", now)
            return FrameAdmissionResult(accepted=False, stale_reason="stale_nav_generation")
        if nav_generation > cur_gen:
            record_quarantine(surf, frame_seq, nav_generation, "unknown_nav_generation", now)
            return FrameAdmissionResult(accepted=False, stale_reason="unknown_nav_generation")

        # Step 7: Monotonic frame_seq fence (prevents replay / out-of-order frames)
        if frame_seq <= surf.last_frame_seq:
            record_quarantine(surf, frame_seq, nav_generation, "non_monotonic_frame_seq", now)
            return FrameAdmissionResult(accepted=False, stale_reason="non_monotonic_frame_seq")

        # Step 8: Pre-commit & non-monotonic timestamp fence
        if ts < surf.current_nav.committed_at:
            record_quarantine(surf, frame_seq, nav_generation, "stale_nav_generation", now)
            return FrameAdmissionResult(accepted=False, stale_reason="stale_nav_generation")
        if surf.last_frame_captured_at is not None and ts < surf.last_frame_captured_at:
            raise CoordValidationError("frame_captured_at_non_monotonic")

        # Step 9: Atomic pairing!
        skey = SurfaceKey(target.canonical, inc, sid, capture_generation)
        meta = BrowserFrameMeta(
            surface_key=skey, nav_generation=nav_generation, frame_seq=frame_seq,
            media_type=header.media_type, width=header.width, height=header.height,
            size_bytes=header.size_bytes, frame_sha256=header.frame_sha256, captured_at=ts,
        )
        paired = PairedBrowserFrame(nav=surf.current_nav, frame=meta, untrusted_content=True)
        surf.last_frame_seq = frame_seq
        surf.last_frame_captured_at = ts
        surf.paired_frame = paired
        surf.paired_frame_bytes = frame_bytes
        return FrameAdmissionResult(accepted=True, stale_reason=None, frame_meta=meta, paired_frame=paired)
```

### 4.3 Frame Freshness, Stale-Reason Evaluation, & Post-Pack Pixel Release Fence

At read time (`get_surface_snapshot` / `list_browser_wall`), freshness is evaluated under `with lock:`
against `now = read_monotonic_clock()` and configured `max_frame_age_ms`
(`100 <= max_frame_age_ms <= 300_000`, default `10_000` ms):

1. If `sandbox.status != "running"` -> `frame_stale = True`, `stale_reason = "sandbox_disconnected"`.
2. Else if `surf.current_nav is None` (e.g., resumed after capture-generation retirement, awaiting
   fresh navigation for the new `capture_generation`) -> `frame_stale = True`,
   `stale_reason = "awaiting_navigation_for_capture_generation"`.
3. Else if `surf.paired_frame is None or surf.paired_frame_bytes is None` -> `frame_stale = True`,
   `stale_reason = "awaiting_frame_for_navigation"` (makes `b64encode(None)` structurally impossible!).
4. Else if `now < surf.paired_frame.frame.captured_at` (clock regression!) -> `frame_stale = True`,
   `stale_reason = "clock_regression"`, `frame_age_ms = None`.
5. Else compute `age_ms = int((now - surf.paired_frame.frame.captured_at) * 1000)`:
   - If `age_ms > max_frame_age_ms` -> `frame_stale = True`, `stale_reason = "frame_ttl_expired"`,
     `frame_age_ms = age_ms`.
   - Else -> `frame_stale = False`, `stale_reason = None`, `frame_age_ms = age_ms`.

When `frame_stale = True`:
- All read-only diagnostic metadata (`current_nav` if present for the active capture generation,
  `paired_frame` metadata if one existed for the current nav, `frame_age_ms`, `frame_stale = True`,
  `stale_reason`) remains readable so the operator can inspect the last observed state without
  spoofing freshness.
- `frame_b64` is **always suppressed (`None`)** with `frame_b64_omitted_reason = stale_reason` so a
  consumer can never accidentally render expired, pre-disconnect, or superseded pixels as live.

#### Mandatory Post-Pack Pixel Release Fence (Defeats TOCTOU Between Capture and Return)

Because base64 encoding and JSON byte-budget packing run **outside `self._lock`**, a concurrent
navigation commit, capture-generation retirement, incarnation rotation, revocation, or TTL expiry
can occur *while packing*. Therefore `get_surface_snapshot` enforces a strict **post-pack release
fence** immediately before returning:

```python
# After packing snapshot outside self._lock (and invoking optional test seam on_after_pack_before_release):
# First re-verify operator session & live authority so revoked callers fail closed with zero target-state oracle!
check_authority_and_session_post(caller, read_session_id, session_generation)
with lock:
    now_release = read_monotonic_clock()
    sb = sandboxes.get(target.canonical)
    if sb is None:
        raise CoordPolicyError("sandbox_not_found")
    if sb.current_incarnation_id != captured_incarnation_id:
        raise IncarnationMismatchError("superseded_incarnation")
    if sb.status == "revoked":
        raise RevokedError("incarnation_revoked")
    if not sb.browser_enabled:
        raise CoordPolicyError("browser_service_not_enabled")

    if packed_snapshot.frame_b64 is not None:
        surf = sb.surfaces.get(sid)
        release_failure = check_pixel_release_invariant(
            sb, surf, now_release,
            captured_capture_generation=captured_capture_generation,
            captured_nav_generation=captured_nav_generation,
            captured_frame_seq=captured_frame_seq,
            captured_frame_sha256=captured_frame_sha256,
            max_frame_age_ms=self._max_frame_age_ms,
        )
        # Verifies ALL of:
        #   - sb.status == "running" and sb.capture_generation == captured_capture_generation
        #   - surf is not None and surf.current_nav is not None
        #     and surf.current_nav.nav_generation == captured_nav_generation
        #   - surf.paired_frame is not None and surf.paired_frame_bytes is not None
        #   - surf.paired_frame.frame.frame_seq == captured_frame_seq
        #     and surf.paired_frame.frame.frame_sha256 == captured_frame_sha256
        #   - now_release >= surf.paired_frame.frame.captured_at
        #     and int((now_release - surf.paired_frame.frame.captured_at) * 1000) <= max_frame_age_ms
        if release_failure is not None:
            # FAIL CLOSED: suppress pixels & rebuild zero-pixel stale snapshot from current locked state!
            packed_snapshot = rebuild_zero_pixel_stale_snapshot_locked(
                sb, surf, now_release, omission_reason=release_failure, max_response_bytes=max_response_bytes
            )

return packed_snapshot
```

- On incarnation rotation or revocation during packing: raises `IncarnationMismatchError` or
  `RevokedError` (zero data returned).
- On mid-pack navigation commit, capture-generation bump, frame superseding, disconnect, clock
  regression, or TTL expiry: **suppresses pixels unconditionally** (`frame_b64 = None`,
  `frame_b64_omitted_reason = release_failure`) and re-packs a zero-pixel stale metadata snapshot
  from the current locked state (matching `max_response_bytes`), followed by the final post-read
  `session_validator` & `live_authority_checker` gate.
- `list_browser_wall` never carries pixels (`frame_b64` is never emitted on wall tiles) and enforces
  the post-pack `session_validator` and `live_authority_checker` gate before returning.

---

## 5. Operator-Only Read APIs, Authority Fencing, Cursors, & Hard Byte Budgets

### 5.1 Strict Operator-Only Admission & Pre/Post Fencing

Mirrors [PROJECTION_WALKTHROUGH.md Section 3](../projection/PROJECTION_WALKTHROUGH.md) verbatim:

- **Caller admission (first check before any store lookup — zero existence oracle):**
  - Require `isinstance(caller, PrincipalCtx)` -> else `CoordValidationError`.
  - Require `caller.role is CoordRole.OPERATOR` -> else `CoordAuthError("operator_role_required")`
    (unconditionally rejects `JOB`, root `ORCHESTRATOR`, sandbox-bound `ORCHESTRATOR`,
    `EXTERNAL_PEER`).
  - Require `caller.sandbox_addr is None and caller.incarnation_id is None` -> else
    `CoordAuthError("operator_principal_must_not_bind_sandbox")`.
- **Strict boolean parameter validation:** `include_frame_b64` and `include_disconnected` require
  `type(flag) is bool` (rejects `0`/`1`/strings/`None` with `CoordValidationError`).
- **Pre-read AND post-read `session_validator` & `live_authority_checker`:**
  - Passing only one of `(read_session_id, session_generation)` -> `CoordValidationError("read_session_pair_required")`.
  - `read_session_id` validated via `validate_token_strict`; `session_generation` validated via
    `validate_positive_int` (`1 <= session_generation <= MAX_SQLITE_INT64`).
  - Supplying session args when `session_validator is None` ->
    `CoordPolicyError("read_session_validator_unconfigured")`.
  - Omitting session args when `session_validator is not None` ->
    `CoordAuthError("read_session_required")`.
  - Both callbacks run **before** reading store state **and after** assembling the response
    **before returning**. Strict `result is True` required; any non-`True` return or exception
    raises `RevokedError("read_session_retired")` or `RevokedError("read_authority_revoked")` with
    zero data returned.
  - Validated `(read_session_id, session_generation)` is echoed in `ReadSessionEcho`.

### 5.2 Collision-Free Canonical Cursor Codec (`list_browser_wall`)

```text
cursor = "v1." + base64url_nopad(
    json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True, allow_nan=False).encode("utf-8")
)
```

- Payload shape: `{"op": "browser_wall", "fh": "<16-hex>", "addr": "<sandbox_addr>", "sid": "<surface_id>"}`.
- `MAX_CURSOR_BYTES = 512`. Maximum valid cursor length is `3 + ceil(227 * 4 / 3) = 307` bytes
  (max `sandbox_addr` = 59 ASCII chars, max `surface_id` = 96 ASCII chars, 72 bytes fixed JSON
  framing + `"op"` + `"fh"` = 227 JSON bytes -> 304 base64url chars + 3-byte `"v1."` prefix = 307 B,
  always `< 512`).
- Scope hash `"fh"` is the 16-lowercase-hex SHA-256 prefix over canonical JSON of
  `{"op": "browser_wall", "include_disconnected": bool}`.
- Hardened decode (`decode_wall_cursor`):
  1. Require `isinstance(cursor, str)`, ASCII-only, `len(cursor) <= MAX_CURSOR_BYTES`, `"v1."`
     prefix, strict unpadded base64url alphabet.
  2. Decode JSON with `parse_constant=_reject_non_finite_constant` inside
     `try/except (ValueError, TypeError, RecursionError)` -> `CoordValidationError("cursor_malformed")`.
  3. Require `type(obj) is dict` with exact key set `{"op", "fh", "addr", "sid"}` and `str` values.
  4. Re-validate `addr` via `parse_sandbox_target(obj["addr"])` AND verify exact canonical equality
     `parsed_target.canonical == obj["addr"]`, and re-validate `sid` via
     `validate_token_strict(obj["sid"], "surface_id")`.
  5. Verify canonical re-encoding equals the exact input string (rejects malleable base64 padding,
     extra whitespace, or non-canonical JSON) -> else `CoordValidationError("cursor_malformed")`.
  6. Verify `obj["op"] == "browser_wall"` and `obj["fh"] == expected_scope_hash` -> else
     `CoordValidationError("cursor_scope_mismatch")`.

### 5.3 Compact Deduplicated Wire Format & Hard UTF-8 JSON `max_response_bytes` Enforcement

All read responses serialize via
`json.dumps(obj.to_dict(), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")`
and **strictly guarantee `len(serialized_utf8) <= max_response_bytes`**:

- **Deduplicated JSON wire layout (exact byte arithmetic verified):**
  - Inside `BrowserSurfaceSnapshot.to_dict()` and `BrowserWallTile.to_dict()`:
    - `sandbox_addr`, `incarnation_id`, `surface_id`, and `capture_generation` appear **once** at
      the snapshot/tile top level (not repeated inside nested `nav` and `frame` objects).
    - `BrowserSurfaceSnapshot.to_dict()` emits `"nav"` once (or `null` when awaiting a new
      navigation after capture-generation retirement) and `"frame"` (from `paired_frame.frame`)
      without duplicating `"nav"` inside `"frame"`.
    - `NavClassification` serializes its 6 redaction/truncation flags as a compact sorted
      `"redacted_flags": [...]` list of active tokens (closed set: `"userinfo"`, `"query"`,
      `"fragment"`, `"path_truncated"`, `"title_scrubbed"`, `"title_truncated"` — `20` bytes when
      clean instead of `148` bytes of `false` booleans!), while exposing all 6 booleans directly as
      Python properties on `NavClassification` and `BrowserNavState`.
  - **Verified byte sizes (`MIN_RESPONSE_BYTES = 1024`):**
    - Typical `BrowserSurfaceSnapshot` (with paired frame, `capture_generation`, `frame_b64=None`,
      `read_session`, `dropped_frame_counts`) is **~833 UTF-8 bytes** (fits cleanly inside `1024`
      bytes with > 190 B headroom for title/path).
    - Typical 1-tile `BrowserWallPage` (with `capture_generation`, `next_cursor` ~115 B, and
      `read_session` ~70 B) is **~883 UTF-8 bytes** (fits cleanly inside `1024` bytes with > 140 B
      headroom).
    - Pathological max-length inputs (253 B DNS hostname + 96 B `incarnation_id` + 96 B `surface_id`
      + 307 B `next_cursor` + 96 B `read_session_id`) have a worst-case minimal snapshot of ~1,610 B
      and minimal 1-tile wall page of ~1,590 B; under a 1 KiB caller cap those fail closed cleanly
      with `CoordValidationError("response_budget_too_small_for_envelope")` or
      `CoordValidationError("response_budget_too_small_for_item")` rather than ever exceeding
      `max_response_bytes`.

1. **`get_surface_snapshot`:**
   ```python
   def get_surface_snapshot(
       self,
       caller: PrincipalCtx,
       *,
       target: str,
       surface_id: str = "main",
       incarnation_id: str | None = None,
       include_frame_b64: bool = False,
       max_response_bytes: int = MAX_SNAPSHOT_RESPONSE_BYTES,   # 768 KiB cap; min 1024 B
       read_session_id: str | None = None,
       session_generation: int | None = None,
   ) -> BrowserSurfaceSnapshot
   ```
   - `MIN_RESPONSE_BYTES = 1024`, `MAX_SNAPSHOT_RESPONSE_BYTES = 768 * 1024` (sized so a 512 KiB
     frame base64-encodes to ~683 KiB + envelope overhead within 768 KiB).
   - If `incarnation_id` is provided and `!= sandbox.current_incarnation_id`, raises
     `IncarnationMismatchError("superseded_incarnation")`.
   - If `include_frame_b64=True`:
     - When `frame_stale=True`: `frame_b64 = None`, `frame_b64_omitted_reason = stale_reason`.
     - When `frame_stale=False`: encodes `base64.b64encode(raw_bytes).decode("ascii")` and checks
       exact UTF-8 serialized JSON size against `max_response_bytes`. If it exceeds the budget,
       omits `frame_b64 = None` with `frame_b64_omitted_reason = "response_budget_exceeded"`.
   - If the metadata-only snapshot still exceeds `max_response_bytes`, binary-searches
     `page_title_clean` (down to `""`, setting `title_truncated = True`) and then `path_redacted`
     (preserving the leading `"/"` — minimum length `1`, setting `path_truncated = True`),
     **atomically rebuilding `PairedBrowserFrame(nav=shrunk_nav, frame=paired.frame, untrusted_content=True)`**
     so `snapshot.nav == snapshot.paired_frame.nav` stays 100% synchronized! If even the minimal
     envelope exceeds `max_response_bytes`, raises
     `CoordValidationError("response_budget_too_small_for_envelope")`.
   - **Mandatory post-pack release fence (§4.3):** Immediately after packing and **before returning**,
     re-acquires `self._lock` to re-verify incarnation, `capture_generation`, `browser_enabled`,
     `status == "running"`, `nav_generation`, `(frame_seq, frame_sha256)`, and TTL freshness
     against `now_release` (failing closed to a zero-pixel stale snapshot or raising
     `IncarnationMismatchError`/`RevokedError`), followed by the final post-read `session_validator`
     & `live_authority_checker` gate.

2. **`list_browser_wall`:**
   ```python
   def list_browser_wall(
       self,
       caller: PrincipalCtx,
       *,
       include_disconnected: bool = False,
       after_cursor: str | None = None,
       limit: int = DEFAULT_WALL_LIMIT,                         # 25; range 1..100
       max_response_bytes: int = MAX_WALL_RESPONSE_BYTES,       # 256 KiB cap; min 1024 B
       read_session_id: str | None = None,
       session_generation: int | None = None,
   ) -> BrowserWallPage
   ```
   - Never includes raw frame bytes or `frame_b64` (metadata-only PiP tiles; post-pack
     `session_validator` & `live_authority_checker` still run before returning).
   - Iterates browser-enabled sandboxes' active-incarnation surfaces in deterministic total order
     `(sandbox_addr ASC, surface_id ASC)` strictly greater than `(cursor.addr, cursor.sid)`.
   - Excludes non-`"running"` sandboxes unless `include_disconnected=True`.
   - Checks empty envelope first -> raises
     `CoordValidationError("response_budget_too_small_for_envelope")` if too small.
   - Adds tiles one by one checking exact UTF-8 serialized JSON length **including the exact actual
     `next_cursor` computed for the candidate last admitted tile whenever more surfaces remain**
     (`has_more = True`):
     - **First-tile rule:** If tile 0 (with actual `next_cursor` if more surfaces follow) exceeds
       `max_response_bytes`, binary-searches `page_title_clean` (down to `""`) then `path_redacted`
       (preserving leading `"/"`, min length `1`) so the full page fits `<= max_response_bytes`;
       if even the minimal first tile cannot fit, raises
       `CoordValidationError("response_budget_too_small_for_item")`.
     - **Subsequent tiles:** Stop before exceeding `max_response_bytes`, set `has_more = True`, and
       emit the exact verified `next_cursor` for the last admitted tile.

---

## 6. Focused Module Layout & Complexity Discipline

All 4 files live strictly under `docs/prds/spikes/m/browser-observe/` with crisp separation, zero
circular imports, SonarCloud-clean complexity (`CC <= 12`, `<= 12` parameters per function/method/
dataclass constructor including `self`, zero duplicated `>= 10`-char string literals):

1. **`oc_browser_contract.py`:**
   - Constants: `BROWSER_OBSERVE_SCHEMA_VERSION = "oc.m3.browser_observe@1"`, `MAX_SQLITE_INT64`,
     bounds constants, closed enum/string constants (`OriginTrust`, `TlsState`, `StaleReason`,
     `ALLOWED_FRAME_MEDIA_TYPES = frozenset({"image/png", "image/jpeg"})`, `VALID_SANDBOX_STATUSES`,
     `VALID_TLS_EVIDENCE`).
   - Strict wrappers: `parse_sandbox_target`, `validate_token_strict`, `validate_positive_int`,
     `validate_finite_nonneg_float`, `require_bool`.
   - Composed frozen dataclasses (each `<= 11` fields so `__init__` stays `<= 12` params incl.
     `self`, every dataclass validating its invariants in `__post_init__`):
     - `ReadSessionEcho(read_session_id, session_generation)`
     - `SurfaceKey(sandbox_addr, incarnation_id, surface_id, capture_generation)` — 4 fields; validates canonical target, opaque tokens, and `1 <= capture_generation <= MAX_SQLITE_INT64`.
     - `NavClassification(origin_trust, tls_state, userinfo_redacted, query_redacted, fragment_redacted, path_truncated, title_scrubbed, title_truncated)`
     - `BrowserNavState(surface_key, nav_generation, origin, path_redacted, scheme, tls_verified, page_title_clean, committed_at, classification)` — 9 fields (`<= 10` params incl. `self`); validates all fields + `len(display_url.encode("utf-8")) <= MAX_DISPLAY_URL_BYTES` in `__post_init__`; exposes `sandbox_addr`, `incarnation_id`, `surface_id`, `capture_generation`, `display_url`, and classification properties, full `to_dict()`, and deduplicated `to_compact_dict()`.
     - `BrowserFrameMeta(surface_key, nav_generation, frame_seq, media_type, width, height, size_bytes, frame_sha256, captured_at)` — 9 fields (`<= 10` params incl. `self`); validates all fields/ranges/SHA-256 hex in `__post_init__`; exposes `sandbox_addr`, `incarnation_id`, `surface_id`, `capture_generation` properties, full `to_dict()`, and deduplicated `to_compact_dict()`.
     - `PairedBrowserFrame(nav, frame, untrusted_content=True)` — structurally verifies `nav.surface_key == frame.surface_key`, `nav.nav_generation == frame.nav_generation`, and `untrusted_content is True`.
     - `FrameAdmissionResult(accepted, stale_reason=None, frame_meta=None, paired_frame=None)`
     - `SandboxViewMeta(worker_ref, instance_name, sandbox_status, capture_generation)`
     - `FrameFreshness(frame_stale, stale_reason, frame_age_ms)`
     - `BrowserSurfaceAudit(dropped_frame_counts, observed_at, read_session)` — wraps `dropped_frame_counts` in `types.MappingProxyType(dict(...))` in `__post_init__`.
     - `BrowserWallTile(sandbox_meta, surface_key, nav, frame_meta, freshness, untrusted_content=True)` — 6 fields (`<= 7` params incl. `self`); `nav` may be `None` when awaiting navigation after capture-generation retirement; exposes convenience properties and deduplicated `to_dict()`.
     - `BrowserSurfaceSnapshot(schema_version, sandbox_meta, surface_key, nav, paired_frame, freshness, frame_b64, frame_b64_omitted_reason, audit, untrusted_content=True)` — 10 fields (`<= 11` params incl. `self`); `nav` may be `None` after capture-generation retirement; exposes convenience properties and deduplicated `to_dict()`.
     - `BrowserWallPage(schema_version, tiles, has_more, next_cursor, observed_at, read_session)`
   - Strict JSON serializer (`serialize_json_bytes`, `serialize_json_str` with `allow_nan=False`).
   - Hardened canonical base64url JSON cursor codec (`compute_wall_scope_hash`, `encode_wall_cursor`,
     `decode_wall_cursor`).
2. **`oc_browser_validate.py`:**
   - `parse_and_classify_url(...)` with small linear helpers (`_split_http_https_scheme`,
     `_parse_strict_host_port`, `_parse_ipv6_host`, `_parse_dns_or_ipv4_host`, `_parse_port`,
     `_classify_origin_and_tls`) enforcing browser-canonical ASCII hosts (zero `encode("idna")`).
   - `validate_frame_bytes(media_type, frame_bytes)` dispatching strictly to `_validate_png_header`
     and `_validate_jpeg_header` (header inspection & SHA-256 provenance only; full bitstream
     decoding remains a downstream display gate), plus `_check_dimensions`.
   - `scrub_page_title(raw_title)` using `_strip_terminal_escapes` (7-bit CSI/OSC/DCS/ECMA-48 `nF`,
     nested-ESC restart, 8-bit C1 & `\x9c` ST) and `_filter_and_cap_single_line` (`ch.isspace()`
     normalization + control/bidi/NUL/surrogate removal).
3. **`oc_browser_observe.py`:**
   - `BrowserObserveService(clock=time.monotonic, max_frame_age_ms=DEFAULT_MAX_FRAME_AGE_MS, session_validator=None, live_authority_checker=None, on_after_pack_before_release=None)`.
   - Ingestion/lifecycle: `register_sandbox`, `set_sandbox_status`, `record_navigation`, `ingest_frame`.
   - Operator-only reads: `get_surface_snapshot`, `list_browser_wall`.
   - Byte-budget packers, atomic binary-search shrinkers, & post-pack release fence:
     `_pack_surface_snapshot`, `_enforce_pixel_release_fence`, `_pack_browser_wall_page`.
4. **`test_browser_observe.py`:**
   - Offline qualification test suite with deterministic PNG/JPEG binary builders, fake clock, and
     post-pack barrier hooks.

---

## 7. Failure & Recovery Matrix (Pinned Exception & Outcome Mapping)

| Failure / Attack Vector | Exact Exception / Outcome |
|---|---|
| `caller` not `PrincipalCtx` | `CoordValidationError("caller must be PrincipalCtx")` |
| `caller.role != CoordRole.OPERATOR` (`JOB`, `ORCHESTRATOR`, `EXTERNAL_PEER`) | `CoordAuthError("operator_role_required")` (before any store lookup) |
| `OPERATOR` with non-`None` `sandbox_addr` or `incarnation_id` | `CoordAuthError("operator_principal_must_not_bind_sandbox")` |
| Non-`bool` passed for `include_frame_b64`, `include_disconnected`, `browser_enabled`, or `tls_verified` | `CoordValidationError` |
| `session_validator` configured, `(read_session_id, session_generation)` omitted | `CoordAuthError("read_session_required")` |
| Partial session pair or invalid `session_generation` (`bool`/`<= 0`/`> MAX_SQLITE_INT64`/float) | `CoordValidationError` |
| Session args supplied with `session_validator is None` | `CoordPolicyError("read_session_validator_unconfigured")` |
| `session_validator` returns non-`True` or raises (pre-read OR post-read) | `RevokedError("read_session_retired")` (zero data returned) |
| `live_authority_checker` returns non-`True` or raises (pre-read OR post-read) | `RevokedError("read_authority_revoked")` (zero data returned) |
| Target is `@PEER` or malformed address (wrapping `AddressError`) | `CoordValidationError` (raw input never echoed) |
| Unknown sandbox target | `CoordPolicyError("sandbox_not_found")` |
| Sandbox registered with `browser_enabled=False` | `CoordPolicyError("browser_service_not_enabled")` (omitted from wall) |
| Unknown `surface_id` on `get_surface_snapshot` | `CoordPolicyError("surface_not_found")` |
| `MAX_TRACKED_SANDBOXES`, `MAX_SURFACES_PER_SANDBOX`, `MAX_ROTATIONS_PER_SANDBOX`, or `MAX_SQLITE_INT64` `capture_generation` exceeded | `CoordPolicyError("max_sandboxes_exceeded" \| "max_surfaces_exceeded" \| "max_incarnation_rotations_exceeded" \| "max_capture_generations_exceeded")` |
| Transitioning out of `"revoked"` on the same `incarnation_id` (`register_sandbox` or `set_sandbox_status`) | `RevokedError("incarnation_revoked")` (must rotate to fresh `incarnation_id`) |
| `record_navigation`, `set_sandbox_status`, or `get_surface_snapshot` with superseded `incarnation_id` | `IncarnationMismatchError("superseded_incarnation")` |
| `record_navigation` or `ingest_frame` with mismatched/stale `capture_generation` | `CoordPolicyError("stale_capture_generation")` (drop counter incremented; zero pixels admitted) |
| `ingest_frame` with superseded `incarnation_id` | `FrameAdmissionResult(accepted=False, stale_reason="superseded_incarnation")` (zero bytes stored) |
| `ingest_frame` with `nav_generation < current_nav_generation` or `captured_at < committed_at` | `FrameAdmissionResult(accepted=False, stale_reason="stale_nav_generation")` (quarantined; never paired!) |
| `ingest_frame` with `nav_generation > current_nav_generation` or no committed nav | `FrameAdmissionResult(accepted=False, stale_reason="unknown_nav_generation")` (quarantined) |
| `ingest_frame` with `frame_seq <= last_frame_seq` | `FrameAdmissionResult(accepted=False, stale_reason="non_monotonic_frame_seq")` (quarantined) |
| `capture_generation`, `nav_generation`, or `frame_seq` out of `1..MAX_SQLITE_INT64` or `bool` | `CoordValidationError` |
| `committed_at` earlier than prior `committed_at` / `last_frame_captured_at` | `CoordValidationError("committed_at_non_monotonic")` |
| `captured_at` earlier than prior `last_frame_captured_at` | `CoordValidationError("frame_captured_at_non_monotonic")` |
| Future `committed_at > now` or `captured_at > now` | `CoordValidationError("..._in_future")` |
| Frame age exceeds `max_frame_age_ms` on injected monotonic clock | `frame_stale = True`, `stale_reason = "frame_ttl_expired"`, `frame_b64 = None` (diagnostic metadata preserved) |
| New navigation committed before next frame arrives | `paired_frame = None`, `paired_frame_bytes = None`, `frame_stale = True`, `stale_reason = "awaiting_frame_for_navigation"` |
| Disconnect/disable retires `capture_generation`, then resumes before a new `capture_generation` navigation commits | `current_nav = None`, `paired_frame = None`, `paired_frame_bytes = None`, `frame_stale = True`, `stale_reason = "awaiting_navigation_for_capture_generation"`, `frame_b64 = None` |
| Mid-pack navigation commit, capture-generation bump, frame superseding, disconnect, clock regression, or TTL expiry before release | Post-pack release fence suppresses `frame_b64 = None` and returns zero-pixel stale snapshot (or raises `IncarnationMismatchError`/`RevokedError` on incarnation/revocation change) |
| Sandbox `"starting"`, `"stopped"`, `"revoked"`, or `"degraded"` | `frame_stale = True`, `stale_reason = "sandbox_disconnected"`, `capture_generation` retired, `current_nav` & paired frame/bytes purged |
| Monotonic clock returns `NaN`/`Inf`/`bool`/negative | `CoordPolicyError("invalid_monotonic_clock")` |
| Monotonic clock steps backwards below `captured_at` | `frame_stale = True`, `stale_reason = "clock_regression"`, `frame_b64 = None` |
| `NaN`, `+Inf`, `-Inf`, or `bool` in numeric args | `CoordValidationError` (and `serialize_json_bytes` uses `allow_nan=False`) |
| Forbidden URL scheme (`javascript:`, `data:`, `file:`, `chrome:`, `chrome-extension:`, `about:srcdoc`, `blob:`, `devtools:`, `ftp:`, etc.) | `CoordValidationError("url_scheme_rejected")` (raw URL never echoed) |
| Any non-ASCII host (e.g., `straße.example`, `bücher.example`, fullwidth ASCII, ideographic dot, `Cf` invisible char) | `CoordValidationError("url_host_non_canonical")` (raw URL never echoed; browser-canonical ASCII `xn--...` required) |
| Control, C1, DEL, NUL, surrogate, bidi, whitespace, `\`, invalid port (leading `0` / `>5` digits), or ambiguous hex/octal/short IPv4 | `CoordValidationError` (raw URL never echoed) |
| Missing `tls_state_evidence` (`None`) on HTTPS, or mismatched CA/host pairing | `tls_state = "unknown"`, `effective_tls_verified = False`, `origin_trust = "external_untrusted"` |
| Contradictory `tls_verified` vs. `tls_state_evidence` or HTTP with `tls_verified=True`/evidence | `CoordValidationError("invalid_tls_evidence" \| "http_cannot_be_tls_verified")` |
| URL with `user:pass@host/path?token=SECRET#frag` | Userinfo, query, and fragment stripped & discarded; `userinfo_redacted=True`, `query_redacted=True`, `fragment_redacted=True`; `origin_trust` forced to `"external_untrusted"` (or rejected outright if `reject_userinfo=True`) |
| Disallowed MIME (`image/webp`, `image/svg+xml`, `image/gif`), bad magic, or MIME vs. magic mismatch | `CoordValidationError("frame_media_type_unsupported")` / `CoordValidationError("frame_media_type_mismatch")` |
| Frame size `< 16` B or `> 512 KiB`, zero/oversized dimensions, pixel cap exceeded, invalid PNG IHDR CRC/color-depth, or malformed/truncated JPEG marker (`pos >= len` / `pos + 2 > len`) / SOF length (`seg_len != 8 + 3 * nf`) | `CoordValidationError` |
| ANSI CSI/OSC/DCS/ECMA-48 `nF`/8-bit C1/`\x9c` ST, NUL, bidi, surrogates, Unicode line separators (`U+2028`/`U+2029`) in page title | Stripped/normalized cleanly to single-line UTF-8 `<= 256` bytes (`title_scrubbed=True`) |
| Malformed, padded, nested-recursion, `NaN`-containing, oversized, non-canonical, or scope-mismatched wall cursor | `CoordValidationError("cursor_malformed")` / `CoordValidationError("cursor_scope_mismatch")` |
| `max_response_bytes` exceeded by `frame_b64` | `frame_b64 = None`, `frame_b64_omitted_reason = "response_budget_exceeded"`, serialized JSON `<= max_response_bytes` |
| `max_response_bytes` too small even for empty envelope or minimal first tile (incl. actual `next_cursor`) | `CoordValidationError("response_budget_too_small_...")` |

---

## 8. Open Choices Resolved in This Walkthrough (For Gate 1 Review)

1. **Strict PNG/JPEG header inspection (no WebP, full decode downstream):**
   `ALLOWED_FRAME_MEDIA_TYPES = {"image/png", "image/jpeg"}` matches `prd_m3.md:271-273, 454` 1:1
   and removes the WebP `VP8X` surface completely. `_validate_png_header` and `_validate_jpeg_header`
   perform binary header inspection and SHA-256 provenance pairing; full bounded bitstream decoding
   before display remains a separate downstream display gate.
2. **Browser-canonical ASCII host contract (no IDNA 2003 re-encoding):** Dropping Python's stdlib
   `host.encode("idna")` eliminates IDNA-2003-vs-UTS-#46 divergence (such as `straße.example`).
   Non-ASCII hostnames are rejected with `CoordValidationError("url_host_non_canonical")` while
   already-punycoded ASCII labels from Chromium (`xn--...`) are preserved verbatim.
3. **Explicit `tls_state_evidence` required for HTTPS trust elevation:** Missing evidence
   (`tls_state_evidence=None`) on HTTPS never fabricates `"sandbox_internal_ca"` or
   `"verified_external_tls"`; it always classifies as `tls_state="unknown"`,
   `effective_tls_verified=False`, `origin_trust="external_untrusted"`, and every mismatched CA/host
   pairing is downgraded identically before applying the `userinfo_redacted` cap.
4. **Capture-generation retirement + post-pack pixel release fence:** Leaving `"running"` or
   disabling a sandbox retires `capture_generation` (bumping it and clearing `current_nav`,
   `paired_frame`, and `paired_frame_bytes`), and every pixel-bearing `get_surface_snapshot`
   re-checks surface identity, `capture_generation`, `nav_generation`, `(frame_seq, frame_sha256)`,
   and TTL freshness under lock *after* packing before releasing any pixels.
5. **Compact deduplicated JSON wire representation:** Snapshots and wall tiles emit identity keys
   (`sandbox_addr`, `incarnation_id`, `surface_id`, `capture_generation`) once at the top level and
   serialize redaction flags as a compact `"redacted_flags"` list so typical paired snapshots
   (~833 B) and 1-tile wall pages with cursor (~883 B) fit comfortably inside
   `MIN_RESPONSE_BYTES = 1024`, while pathological max-length records fail closed cleanly.

---

## 9. Offline Qualification & Verification Plan (`test_browser_observe.py`)

All tests run completely offline via
`python3 -B -m unittest discover -s docs/prds/spikes/m/browser-observe -p 'test_*.py'`
with zero Podman, zero live Chromium, zero network calls, and zero writes to host directories:

1. **Frame-after-navigation spoofing & generation fencing:**
   - Commit `nav_generation = 1` (`http://external.example/phish`, `tls_verified = False`), admit
     `frame_seq = 1` -> paired.
   - Commit `nav_generation = 2` (`https://feat-a.oc-sandbox.internal/app`, `tls_verified = True`,
     `tls_state_evidence = "sandbox_internal_ca"`): immediately verify `paired_frame is None`,
     `frame_stale = True`, `stale_reason = "awaiting_frame_for_navigation"`, and prior bytes purged!
   - Deliver delayed frame carrying `nav_generation = 1, frame_seq = 2`: verify
     `accepted = False, stale_reason = "stale_nav_generation"`, quarantined without overwriting
     current nav or advancing `last_frame_seq`.
   - Deliver valid frame carrying `nav_generation = 2, frame_seq = 2`: verify `accepted = True`,
     exact `(nav_generation=2, frame_seq=2)` pairing, `origin_trust = "sandbox_internal_https"`,
     `tls_state = "sandbox_internal_ca"`, and `untrusted_content = True`.
   - Deliver another delayed frame (`nav_generation = 1, frame_seq = 3`) -> quarantined while
     `nav_generation = 2` paired frame stays intact.
   - Deliver pre-commit frame (`nav_generation = 2, frame_seq = 3, captured_at < committed_at`) ->
     `accepted = False, stale_reason = "stale_nav_generation"`.
2. **Future `nav_generation`, incarnation rotation, terminal `"revoked"`, & replay fencing:**
   - Frame before any navigation or with `nav_generation = 99 > current_nav_generation` ->
     `accepted = False, stale_reason = "unknown_nav_generation"`.
   - Non-monotonic `frame_seq` (equal/lower -> `"non_monotonic_frame_seq"`; `0`, `-1`, `True`,
     `MAX_SQLITE_INT64 + 1` -> `CoordValidationError`).
   - Non-monotonic `nav_generation` or `nav_generation > MAX_SQLITE_INT64` -> `CoordValidationError`.
   - Rotate sandbox `"feat-a"` from `inc_1` to `inc_2`: `inc_1` surfaces/frames purged,
     `ingest_frame(inc_1)` -> `accepted = False, stale_reason = "superseded_incarnation"`,
     `record_navigation(inc_1)` / `set_sandbox_status(inc_1)` / `get_surface_snapshot(inc_1)` ->
     `IncarnationMismatchError`, re-registering `inc_1` -> `IncarnationMismatchError`.
   - Terminal `"revoked"` fixture: `set_sandbox_status(..., "revoked")` purges paired frames;
     attempting `set_sandbox_status(..., "running")` or `register_sandbox(..., inc_same, status="running")`
     raises `RevokedError("incarnation_revoked")`; rotating to fresh `inc_3` succeeds.
   - **Capture-generation retirement on disconnect/disable & delayed-frame race fixture:**
     - Sandbox running at `capture_generation = 1`: commit nav (`nav_generation = 1`) and ingest
       frame (`frame_seq = 1`).
     - Disconnect (`set_sandbox_status(..., "stopped")`) or disable (`register_sandbox(..., browser_enabled=False)`),
       then resume (`status = "running"`, `browser_enabled = True`) — bumping `capture_generation = 2`
       and clearing `current_nav`, `paired_frame`, and `paired_frame_bytes`.
     - Deliver a held old frame from `capture_generation = 1` (and a stale nav from
       `capture_generation = 1`) -> rejected with `CoordPolicyError("stale_capture_generation")`.
     - Verify `get_surface_snapshot(..., include_frame_b64=True)` returns **zero pixels**
       (`nav = None`, `paired_frame = None`, `frame_b64 = None`,
       `stale_reason = "awaiting_navigation_for_capture_generation"`) until a new navigation and
       frame bound to `capture_generation = 2` arrive!
   - Status `"starting"` and `"degraded"` treated as non-running (`sandbox_disconnected`).
   - Structural invariant check: direct instantiation of `PairedBrowserFrame` with mismatched
     `SurfaceKey` (including mismatched `capture_generation`) or `nav_generation` or
     `untrusted_content=False`, or direct `BrowserNavState`/`BrowserFrameMeta` with invalid fields,
     raises `CoordValidationError`; mutating `snapshot.audit.dropped_frame_counts` raises
     `TypeError` (`MappingProxyType`).
3. **Fake monotonic clock TTL expiry, post-pack release barrier, & clock-anomaly defense:**
   - Admit frame at `t = 100.0` with `max_frame_age_ms = 5000`; at `t = 104.999` -> `frame_stale = False`,
     `include_frame_b64 = True` returns exact base64 bytes matching `frame_sha256`.
   - Advance fake clock to `t = 105.001` -> `frame_stale = True`,
     `stale_reason = "frame_ttl_expired"`, `frame_age_ms = 5001`, diagnostic `BrowserFrameMeta`
     preserved, `frame_b64 = None`, `frame_b64_omitted_reason = "frame_ttl_expired"`.
   - **Post-pack pixel release barrier fixtures (`on_after_pack_before_release`):**
     - *(a) Mid-pack navigation commit:* Begin `get_surface_snapshot(..., include_frame_b64=True)` on
       `nav_generation = 1`; inside `on_after_pack_before_release`, commit `nav_generation = 2` ->
       verify post-pack release fence suppresses pixels (`frame_b64 = None`, zero `nav_generation = 1`
       pixels released!).
     - *(b) Mid-pack TTL expiry:* Begin `get_surface_snapshot(..., include_frame_b64=True)` at
       `t = 104.999`; inside `on_after_pack_before_release`, advance fake clock to `t = 105.001` ->
       verify post-pack release fence suppresses pixels (`frame_b64 = None`,
       `stale_reason = "frame_ttl_expired"`, zero expired pixels released!).
     - *(c) Mid-pack incarnation rotation / revocation:* Inside `on_after_pack_before_release`,
       rotate incarnation or mark `"revoked"` -> raises `IncarnationMismatchError` / `RevokedError`
       with zero data returned!
   - Future `captured_at > now` or `committed_at > now`, or non-monotonic `committed_at` /
     `captured_at` rejected with `CoordValidationError`.
   - Backwards clock step (`t = 99.0 < captured_at`) -> `frame_stale = True`,
     `stale_reason = "clock_regression"`, `frame_b64 = None`.
   - Broken clock returning `NaN`, `+Inf`, `-1.0`, or `True` fails closed with
     `CoordPolicyError("invalid_monotonic_clock")`.
4. **URL redaction, browser-canonical ASCII host contract, IPv4/port hardening, & exact TLS/CA classification:**
   - `https://user:pass@feat-a.oc-sandbox.internal/callback?token=SECRET&a=1#jwt=FRAG` with
     `tls_verified=True, tls_state_evidence="sandbox_internal_ca"` ->
     `origin == "https://feat-a.oc-sandbox.internal"`, `path_redacted == "/callback"`,
     `userinfo_redacted = True`, `query_redacted = True`, `fragment_redacted = True`,
     `tls_state == "sandbox_internal_ca"`, `origin_trust == "external_untrusted"`, and none of
     `"user"`, `"pass"`, `"SECRET"`, `"FRAG"`, `"@"` appear anywhere in serialized JSON.
   - Surrogate + credential URL (`"https://user:SECRET@example.com/\ud800"`) raises
     `CoordValidationError` without `UnicodeEncodeError` and without `"SECRET"` in the exception!
   - `reject_userinfo=True` rejects `https://user:pass@example.com/` without echoing credentials.
   - Forbidden schemes (`javascript:alert(1)`, `data:text/html,<b>x</b>`, `file:///etc/passwd`,
     `chrome://settings`, `chrome-extension://abc/bg.html`, `about:srcdoc`, `about:blank`,
     `blob:https://example.com/1`, `devtools://devtools`, `ftp://example.com`, `//example.com`)
     all raise `CoordValidationError`.
   - **IDNA-2003 vs. UTS-#46 / browser-canonical ASCII origin fixtures:**
     - Non-ASCII hosts (`https://straße.example/`, `https://bücher.example/`, fullwidth
       `\uff4c\uff4f\uff43\uff41\uff4c\uff48\uff4f\uff53\uff54`, fullwidth
       `\uff46\uff45\uff41\uff54-a.oc-sandbox.internal`, ideographic dots `\u3002`/`\uff0e`,
       invisible `Cf` ZWSP `\u200b` / soft hyphen `\u00ad`) are ALL rejected with
       `CoordValidationError("url_host_non_canonical")` (zero `encode("idna")` re-encoding!).
     - Browser-canonical ASCII punycode (`https://xn--strae-oqa.example/p`,
       `https://xn--bcher-kva.example/p`) is accepted verbatim without re-encoding (`origin`
       preserved identically; with `external_ca` -> `tls_state="verified_external_tls"`,
       `origin_trust="external_untrusted"`).
   - Backslash `https://evil.com\@feat-a.oc-sandbox.internal`, hex/octal/short/integer IPv4
     (`http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`, `http://127.1/`,
     `http://0x7f.0.0.1/`), IPv4-mapped IPv6 (`http://[::ffff:127.0.0.1]/`), IPv6 zone IDs
     (`http://[::1%25lo]/`), and leading-zero/oversize ports (`:0443`, `:00000080`, `:99999`) are
     rejected with `CoordValidationError`.
   - Explicit `:443` omitted (`https://feat-a.oc-sandbox.internal:443/` -> `origin == "https://feat-a.oc-sandbox.internal"`),
     non-default `:8443` preserved (`origin == "https://feat-a.oc-sandbox.internal:8443"`, still
     `"sandbox_internal_https"` with `sandbox_internal_ca`).
   - Complete TLS/CA matrix verified:
     - HTTPS with `tls_state_evidence=None` (even `tls_verified=True`!) -> `tls_state="unknown"`,
       `tls_verified=False`, `origin_trust="external_untrusted"`.
     - `sandbox_internal_ca` on exact `<NAME>.oc-sandbox.internal` (local `"feat-a"` and remote
       `"macmini / feat-a"`) -> `"sandbox_internal_ca"` / `"sandbox_internal_https"`.
     - `sandbox_internal_ca` on sibling `feat-b.oc-sandbox.internal`, subdomain `sub.feat-a.oc-sandbox.internal`,
       bare `oc-sandbox.internal`, `localhost`, `127.0.0.1`, or `example.com` -> downgraded to
       `tls_state="unknown"`, `tls_verified=False`, `origin_trust="external_untrusted"`.
     - `external_ca` on own/sibling/sub/bare `.oc-sandbox.internal` -> downgraded to
       `tls_state="unknown"`, `tls_verified=False`, `origin_trust="external_untrusted"`.
     - `external_ca` on `https://example.com` -> `tls_state="verified_external_tls"`,
       `origin_trust="external_untrusted"`.
     - Contradictory `(tls_verified=True, "tls_error")`, `(tls_verified=False, "sandbox_internal_ca")`,
       or `(http, tls_verified=True)` / `(http, tls_state_evidence=...)` -> `CoordValidationError`.
     - `http://127.0.0.1:3000/`, `http://[::1]:8080/`, `http://localhost:5173/` -> `"loopback_http"`.
5. **PNG/JPEG binary header inspection, MIME mismatch, JPEG EXIF-SOF, truncated markers, & decompression-bomb guard:**
   - Valid PNG (all legal `(color_type, bit_depth)` forms) and valid JPEG (SOF0/SOF2 with preceding
     `APP0`/`COM` AND an **`APP1` EXIF segment containing a fake embedded `FF C0` SOF** whose inner
     dimensions differ from the real main SOF!) pass header inspection with exact main-image
     `(width, height)` and authoritative `frame_sha256`.
   - Disallowed MIME (`image/webp` even with valid RIFF/WEBP bytes, `image/svg+xml`, `image/gif`) ->
     `CoordValidationError("frame_media_type_unsupported")`.
   - MIME vs. magic mismatch (PNG declared `image/jpeg`, JPEG declared `image/png`, SVG declared
     `image/png`) -> `CoordValidationError("frame_media_type_mismatch")`.
   - Decompression-bomb dimensions (`width=0`, `height=0`, `65535 x 65535`, `4096 x 4096` exceeding
     `MAX_FRAME_PIXELS`) -> `CoordValidationError("frame_dimensions_out_of_bounds")`.
   - **Truncated JPEG marker fixtures:** (a) JPEG ending with trailing `0xFF` fill bytes after
     `SOI` (`pos >= len(raw)`), (b) JPEG truncated right after marker byte with `< 2` bytes left
     for `seg_len` (`pos + 2 > len(raw)`), and (c) JPEG truncated mid-SOF header — all raise
     `CoordValidationError("frame_jpeg_malformed")` (never `IndexError` or `struct.error`).
   - Corrupt PNG IHDR CRC, illegal PNG `(color_type, bit_depth)` pair (e.g. `color_type=3, bit_depth=16`),
     oversized payload (`512 KiB + 1`), undersized payload (`< 16` B), non-`bytes` payload, JPEG
     missing `0xFF` alignment, `0x00`/`0xD8`/`0xD0` markers before SOF, mismatched SOF
     `seg_len != 8 + 3 * nf`, and `> MAX_JPEG_SEGMENTS` -> `CoordValidationError`.
6. **Page-title scrubbing (ANSI / ECMA-48 `nF` / nested ESC / C1 / Unicode line breaks / bidi / NUL):**
   - Title with 7-bit CSI (`\x1b[31mRed\x1b[0m`), OSC (`\x1b]52;c;AAAA\x07`), 8-bit ST (`\x1b]0;spoof\x9c`),
     ECMA-48 `nF` (`\x1b(0Box`), nested ESC inside CSI (`\x1b[31\x1b]52;c;AAAA\x07Safe`), DCS
     (`\x1bP1$r\x1b\\`), 8-bit C1 CSI/OSC (`\x9b2J`, `\x9d0;spoof\x07`), NUL (`\x00`), bidi
     override (`\u202e`), lone surrogate (`\ud800`), `\r\n`, `\t`, `\v`, `\f`, `U+00A0`, `U+2028`,
     and `U+2029` collapses cleanly to plain single-line UTF-8 with `title_scrubbed = True` and zero
     surviving forbidden codepoints.
   - Multi-KiB multibyte UTF-8 title truncates cleanly at a UTF-8 char boundary `<= 256` bytes with
     `title_truncated = True`.
7. **Operator-only admission, pre/post session & live-authority fencing, & capability gating:**
   - `JOB`, root `ORCHESTRATOR`, sandbox-bound `ORCHESTRATOR`, `EXTERNAL_PEER`, `OPERATOR` with
     bound `sandbox_addr`, non-`PrincipalCtx`, and `@PEER` / invalid targets (`AddressError` wrapped
     to `CoordValidationError`) all fail closed before touching store state.
   - Configured `session_validator` rejects omitted session args (`CoordAuthError`), partial pairs
     (`CoordValidationError`), pre-read failure (`RevokedError`), and **mid-read revocation**
     (returns `True` pre-read and `False` post-read -> `RevokedError`, zero data returned!).
   - Same pre/post verification for `live_authority_checker` (including exception raised -> `RevokedError`).
   - Non-`bool` (`1`, `"true"`) passed to `include_frame_b64` / `include_disconnected` raises
     `CoordValidationError`.
   - Sandbox with `browser_enabled=False` raises `CoordPolicyError("browser_service_not_enabled")`
     and is absent from `list_browser_wall`.
8. **1 KiB JSON budget, atomic `nav`/`paired_frame` shrink, hardened cursor codec, & `allow_nan=False`:**
   - `list_browser_wall` paginates across multiple sandboxes/surfaces (including `REMOTE / NAME`
     and `:` in `incarnation_id`/`surface_id`) with `limit=1` and `max_response_bytes=1024`
     containing escape-heavy (`"\\"\n`) and multibyte UTF-8 titles/paths: every page (including
     actual `next_cursor` and `read_session`) serializes strictly `<= 1024` UTF-8 bytes
     (`allow_nan=False`), preserves leading `"/"` on shrunk paths, has zero skips/duplicates, and
     never emits raw frame bytes.
   - `get_surface_snapshot(..., include_frame_b64=True, max_response_bytes=1024)` omits `frame_b64`
     cleanly with `frame_b64_omitted_reason = "response_budget_exceeded"`, keeps
     `snapshot.nav == snapshot.paired_frame.nav` after title/path shrinking, preserves leading `"/"`,
     and stays `<= 1024` B; under `max_response_bytes = 768 * 1024` returns exact `frame_b64`
     decoding to `frame_sha256`.
   - Hardened cursor rejection: flipped `include_disconnected` (`cursor_scope_mismatch`), tampered
     base64 padding, extra JSON key, wrong `"op"`, `NaN` inside cursor JSON, deeply nested JSON
     triggering `RecursionError`, non-canonical `addr` / invalid `sid`, or `> 512` bytes all raise
     `CoordValidationError`.
   - Passing `float("nan")`, `float("inf")`, `-float("inf")`, or `bool` to any numeric argument
     raises `CoordValidationError`, and `serialize_json_bytes({"x": float("nan")})` fails closed.
