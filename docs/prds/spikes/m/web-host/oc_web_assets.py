"""Admit the trusted M3a static build before the listener starts."""

import base64
from dataclasses import dataclass
from hashlib import sha256
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType

ASSET_LIMIT = 4 * 1024 * 1024
BUILD_LIMIT = 16 * 1024 * 1024
MAX_ASSETS = 256
MAX_DEPTH = 8
MANIFEST = "csp-manifest.json"
FALLBACK = "200.html"
HTML_TYPE = "text/html; charset=utf-8"
FILE_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".webp": "image/webp",
    ".woff2": "font/woff2",
}
PATH_COMPONENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*\Z", re.ASCII)
RESERVED = {"api", "dashboard", "events"}
SCRIPT_HASH = re.compile(r"[A-Za-z0-9+/]{43}=\Z", re.ASCII)
SERVICE_WORKERS = {"service-worker.js", "serviceworker.js", "sw.js"}
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class AssetError(ValueError):
    """A trusted build package is missing or outside the fixture's contract."""


@dataclass(frozen=True)
class Asset:
    content_type: str
    content: bytes


@dataclass(frozen=True)
class Build:
    html: bytes
    csp: str
    assets: MappingProxyType


class _Scripts(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=False)
        self.offsets = [0]
        self.offsets.extend(match.end() for match in re.finditer("\n", text))
        self.start = None
        self.in_title = False
        self.spans = []

    def _offset(self):
        line, column = self.getpos()
        return self.offsets[line - 1] + column

    def _check_markup(self, tag, attrs):
        if self.in_title or tag in {
            "base", "frame", "frameset", "iframe", "math", "noembed", "noframes",
            "noscript", "plaintext", "style", "svg", "template", "textarea", "xmp",
        }:
            raise AssetError("Unsupported fallback HTML element")
        for name, _ in attrs:
            if name.startswith("on") or name == "style" or (tag == "meta" and name == "http-equiv"):
                raise AssetError("Unsupported fallback HTML attribute")

    def handle_starttag(self, tag, attrs):
        self._check_markup(tag, attrs)
        if tag == "title":
            self.in_title = True
        if tag != "script":
            return
        # The trusted fixture has one inline script. External code arrives via
        # imports from that bootstrap. Refuse other script markup.
        if attrs not in ([], [("type", "module")]):
            raise AssetError("Unsupported script markup")
        self.start = self._offset() + len(self.get_starttag_text())

    def handle_startendtag(self, tag, attrs):
        self._check_markup(tag, attrs)
        # HTML browsers ignore the slash on a nonvoid title and interpret
        # subsequent bootstrap markup as title text.
        if tag in {"script", "title"}:
            raise AssetError("Unsupported self-closing shell element")

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "script" and self.start is not None:
            self.spans.append((self.start, self._offset()))
            self.start = None


def _bootstrap_hash(html: bytes) -> str:
    if b"\r" in html or b"\0" in html:
        raise AssetError("HTML must use LF with no NUL")
    text = html.decode("utf-8", errors="strict")
    scripts = _Scripts(text)
    scripts.feed(text)
    scripts.close()
    if scripts.start is not None or len(scripts.spans) != 1:
        raise AssetError("Expected exactly one inline script")
    start, end = scripts.spans[0]
    if "<!--" in text[start:end]:
        raise AssetError("Unsupported script markup")
    byte_start = len(text[:start].encode("utf-8"))
    byte_end = byte_start + len(text[start:end].encode("utf-8"))
    return base64.b64encode(sha256(html[byte_start:byte_end]).digest()).decode("ascii")


def _walk(fd: int, prefix: str, files: dict[str, bytes], budget: list[int], depth: int):
    if depth > MAX_DEPTH:
        raise AssetError("Build directory is too deep")
    with os.scandir(fd) as entries:
        for entry in entries:
            budget[0] += 1
            if budget[0] > MAX_ASSETS:
                raise AssetError("Build has too many entries")
            name = entry.name
            path = prefix + name
            if (not PATH_COMPONENT.fullmatch(name) or name.lower() in SERVICE_WORKERS
                    or (not prefix and name in RESERVED) or (prefix and name == MANIFEST)):
                raise AssetError("Unsupported build path")
            if entry.is_dir(follow_symlinks=False):
                child = os.open(name, DIR_FLAGS, dir_fd=fd)
                try:
                    _walk(child, path + "/", files, budget, depth + 1)
                finally:
                    os.close(child)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise AssetError("Build entry is not a regular file")
            if path not in (MANIFEST, FALLBACK) and Path(name).suffix not in FILE_TYPES:
                raise AssetError("Unsupported build file type")
            file_fd = os.open(
                name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            with os.fdopen(file_fd, "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise AssetError("Build entry must be a regular single-link file")
                data = source.read(ASSET_LIMIT + 1)
            budget[1] += len(data)
            if len(data) > ASSET_LIMIT or budget[1] > BUILD_LIMIT:
                raise AssetError("Build file size limit exceeded")
            files[path] = data


def _unique_object(items):
    result = dict(items)
    if len(result) != len(items):
        raise AssetError("Duplicate JSON key")
    return result


def load_build(path: Path) -> Build:
    """Copy a strict trusted directory tree into an immutable in-memory map."""
    files = {}
    try:
        full_path = path.absolute()
        if ".." in full_path.parts or full_path == Path("/"):
            raise AssetError("Expected a specific build directory")
        fd = os.open("/", DIR_FLAGS)
        try:
            for part in full_path.parts[1:]:
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            _walk(fd, "", files, [0, 0], 0)
        finally:
            os.close(fd)

        html = files.pop(FALLBACK)
        manifest = json.loads(files.pop(MANIFEST), object_pairs_hook=_unique_object)
        if type(manifest) is not dict or set(manifest) != {
            "version", "html_sha256", "inline_script_sha256",
        }:
            raise AssetError("Invalid build manifest")
        declared_script = manifest["inline_script_sha256"]
        if (type(manifest["version"]) is not int or manifest["version"] != 1
                or type(declared_script) is not str or not SCRIPT_HASH.fullmatch(declared_script)):
            raise AssetError("Invalid build manifest")
        digest = _bootstrap_hash(html)
        if manifest["html_sha256"] != sha256(html).hexdigest() or declared_script != digest:
            raise AssetError("Build digest mismatch")
    except (OSError, KeyError, UnicodeError, RecursionError, json.JSONDecodeError):
        raise AssetError("Invalid static build") from None

    csp = (
        f"default-src 'none'; script-src 'self' 'sha256-{digest}'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    assets = {"/" + name: Asset(FILE_TYPES[Path(name).suffix], data)
              for name, data in files.items()}
    return Build(html, csp, MappingProxyType(assets))
