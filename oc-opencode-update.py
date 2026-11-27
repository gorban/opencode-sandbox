#!/usr/bin/env python3
"""Stage verified OpenCode releases with a read-only shared home; promote via an offline writer.

An offline reader sees the shared home read-only and sends only the digest of
the current binary to a networked updater with no mounts. The networked updater
downloads the direct GitHub release archive with strict transfer/decompression
bounds and verifies the expected binary SHA-256 before executing `--version`.
The offline writer alone sees the shared home writable and independently verifies
the expected SHA-256 before promoting atomically.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import posixpath
import re
import select
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zlib

VERSION = re.compile(r'v?\d+(?:\.\d+){2}(?:[-+][0-9A-Za-z.-]+)?', re.ASCII)
CHECKSUM = re.compile(r'[0-9a-f]{64}', re.ASCII)
INSTALL_DIRNAME = '.opencode'
SOURCE_MAGIC = b'OC-OPENCODE-SOURCE-2\n'
MAGIC = b'OC-OPENCODE-UPDATE-1\n'
END = b'\nOC-OPENCODE-UPDATE-END\n'
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_BINARY = 512 * 1024 * 1024
MAX_DECOMPRESSED_TAR = 544 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 64
RELEASE_URL_TEMPLATE = (
    'https://github.com/anomalyco/opencode/releases/download/'
    'v{version}/opencode-linux-{arch}-musl.tar.gz'
)


def run(args, env, timeout):
    proc = subprocess.Popen(
        args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, start_new_session=True,
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate(timeout=5)
        raise
    if proc.returncode != 0:
        raise RuntimeError(f'{args[0]} failed ({proc.returncode})')
    return out.decode('utf-8', 'replace')


def reported_version(output):
    """Accept one complete version line, optionally branded by OpenCode."""
    match = re.fullmatch(rf'(?:opencode )?({VERSION.pattern})\n?', output, flags=VERSION.flags)
    if not match:
        raise ValueError('invalid OpenCode version output')
    return match.group(1)


def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def release_arch(machine=None):
    raw = (machine if machine is not None else platform.machine()).lower()
    if raw in ('x86_64', 'amd64'):
        return 'x64'
    if raw in ('aarch64', 'arm64'):
        return 'arm64'
    raise ValueError(f'unsupported architecture for direct OpenCode release: {raw}')


def release_url(requested, machine=None):
    clean = requested.lstrip('v')
    major = int(clean.partition('.')[0])
    if major < 2:
        raise ValueError('direct OpenCode release updates require version 2.x or newer')
    return RELEASE_URL_TEMPLATE.format(version=clean, arch=release_arch(machine))


def _kill_process_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _stream_download(proc, out, deadline, max_bytes):
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    total = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired('curl', 0)
        ready, _, _ = select.select([fd], [], [], min(remaining, 0.25))
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            continue
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError('release archive exceeds size limit')
        out.write(chunk)
    return total


def download_release(url, dest, env, timeout=60, max_bytes=MAX_ARCHIVE):
    """Stream release archive from curl with hard monotonic deadline and byte limit."""
    cmd = [
        'curl', '-fsSL', '--proto', '=https', '--tlsv1.2',
        '--connect-timeout', '5', '--max-time', str(int(timeout)),
        '--max-filesize', str(int(max_bytes)), url,
    ]
    # Open the exclusive destination BEFORE spawning curl so open failures never leak a child.
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    proc = None
    succeeded = False
    try:
        with os.fdopen(fd, 'wb') as out:
            deadline = time.monotonic() + timeout
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=env, start_new_session=True,
            )
            total = _stream_download(proc, out, deadline, max_bytes)
            out.flush()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired('curl', timeout)
        rc = proc.wait(timeout=remaining)
        if rc != 0:
            raise RuntimeError(f'curl failed ({rc})')
        if total == 0:
            raise ValueError('downloaded release archive is empty')
        succeeded = True
        return total
    finally:
        if proc is not None:
            if proc.stdout is not None:
                proc.stdout.close()
            if proc.poll() is None:
                _kill_process_group(proc)
        if not succeeded:
            try:
                os.unlink(dest)
            except FileNotFoundError:
                pass


class _BoundedReader:
    """Cap total decompressed bytes across the entire tar stream."""

    def __init__(self, stream, limit):
        self._stream = stream
        self._limit = limit
        self.total = 0

    def read(self, size=-1):
        data = self._stream.read(size)
        self.total += len(data)
        if self.total > self._limit:
            raise ValueError('decompressed release archive exceeds size limit')
        return data


def _validate_tar_member(member):
    name = member.name
    if '\x00' in name or name.startswith('/'):
        raise ValueError('unsafe member path in release archive')
    parts = [p for p in name.split('/') if p and p != '.']
    if any(p == '..' for p in parts):
        raise ValueError('path traversal member in release archive')
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        raise ValueError('unsafe special member in release archive')
    if not (member.isdir() or member.isreg()):
        raise ValueError('unsupported member type in release archive')
    return posixpath.normpath(name) if parts else '.'


def _copy_member_bounded(src, dest_path, expected_size, max_binary):
    if expected_size <= 0 or expected_size > max_binary:
        raise ValueError('updated OpenCode binary has invalid size')
    fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    total = 0
    with os.fdopen(fd, 'wb') as out:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_binary:
                raise ValueError('updated OpenCode binary exceeds size limit')
            out.write(chunk)
        out.flush()
    if total != expected_size:
        raise ValueError('truncated OpenCode binary in release archive')


def _drain_stream(stream):
    """Consume remaining bytes through _BoundedReader so trailing bombs or truncation fail closed."""
    drained = 0
    while chunk := stream.read(65536):
        drained += len(chunk)
    return drained


def extract_opencode_binary(
    archive_path, candidate_path, *,
    max_decompressed=MAX_DECOMPRESSED_TAR,
    max_binary=MAX_BINARY,
    max_members=MAX_ARCHIVE_MEMBERS,
):
    """Extract only the single regular-file opencode binary under strict bounds."""
    found = False
    members = 0
    try:
        with gzip.GzipFile(filename=archive_path, mode='rb') as gz:
            bounded = _BoundedReader(gz, max_decompressed)
            with tarfile.open(fileobj=bounded, mode='r|') as tf:
                for member in tf:
                    members += 1
                    if members > max_members:
                        raise ValueError('release archive has too many members')
                    norm = _validate_tar_member(member)
                    if member.isdir():
                        continue
                    src = tf.extractfile(member)
                    if src is None:
                        raise ValueError('unreadable member in release archive')
                    if norm == 'opencode':
                        if found:
                            raise ValueError('release archive contains duplicate opencode binaries')
                        _copy_member_bounded(src, candidate_path, member.size, max_binary)
                        found = True
                    else:
                        _drain_stream(src)
            # Drain remaining compressed/decompressed bytes to catch trailing bombs or truncation.
            _drain_stream(bounded)
    except (tarfile.TarError, EOFError, zlib.error, OSError) as exc:
        raise ValueError(f'invalid or truncated release archive: {exc}') from exc
    if not found:
        raise ValueError('release archive did not contain an opencode binary')


def open_install_dir(home, create):
    """Open each volume directory without following symlinks."""
    opened = [os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in (INSTALL_DIRNAME, 'bin'):
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=opened[-1])
                except FileExistsError:
                    pass
            opened.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=opened[-1]))
        return opened
    except BaseException:
        for fd in reversed(opened):
            os.close(fd)
        raise


def read_old(home):
    try:
        opened = open_install_dir(home, False)
    except FileNotFoundError:
        return None
    try:
        try:
            fd = os.open('opencode', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=opened[-1])
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'rb') as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or not (st.st_mode & 0o111):
                raise ValueError('existing OpenCode binary is not an executable regular file')
            data = f.read(MAX_BINARY + 1)
            if len(data) > MAX_BINARY:
                raise ValueError('existing OpenCode binary is too large')
            return data
    finally:
        for fd in reversed(opened):
            os.close(fd)


def snapshot(home, output):
    old = read_old(home)
    digest = None if old is None else hashlib.sha256(old).hexdigest()
    output.write(SOURCE_MAGIC + json.dumps(digest).encode('ascii') + b'\n' + END)
    output.flush()


def read_snapshot(stream):
    if stream.readline(len(SOURCE_MAGIC) + 1) != SOURCE_MAGIC:
        raise ValueError('invalid source frame')
    raw = stream.readline(67)
    if not raw.endswith(b'\n'):
        raise ValueError('invalid source digest')
    digest = json.loads(raw)
    if digest is not None and (type(digest) is not str or not CHECKSUM.fullmatch(digest)):
        raise ValueError('invalid source digest')
    if stream.read(len(END)) != END or stream.read(1):
        raise ValueError('corrupt or incomplete source frame')
    return digest


def _validate_stage_inputs(requested, expected_sha256, expected_archive_sha256):
    if not requested or not VERSION.fullmatch(requested):
        raise ValueError('OC_OPENCODE_VERSION must be a version such as 2.3.0')
    if not expected_sha256 or not CHECKSUM.fullmatch(expected_sha256):
        raise ValueError('OC_OPENCODE_SHA256 must be a 64-character lowercase hex digest')
    if expected_archive_sha256 and not CHECKSUM.fullmatch(expected_archive_sha256):
        raise ValueError('OC_OPENCODE_ARCHIVE_SHA256 must be a 64-character lowercase hex digest')


def stage(
    stream, requested, expected_sha256, output, *,
    expected_archive_sha256='', runner=run, downloader=download_release,
):
    _validate_stage_inputs(requested, expected_sha256, expected_archive_sha256)
    url = release_url(requested)
    oldhash = read_snapshot(stream)
    if oldhash == expected_sha256:
        print('OpenCode: already up to date', file=sys.stderr)
        return
    with tempfile.TemporaryDirectory(prefix='oc-opencode-update-') as tmp:
        base = Path(tmp)
        archive = base / 'release.tar.gz'
        candidate = base / 'opencode'
        env = dict(os.environ)
        env.update(
            HOME=str(base / 'home'), PATH='/usr/bin:/bin', CI='true',
            XDG_CONFIG_HOME=str(base / 'config'), XDG_DATA_HOME=str(base / 'data'),
            XDG_CACHE_HOME=str(base / 'cache'), XDG_STATE_HOME=str(base / 'state'),
        )
        (base / 'home').mkdir(mode=0o700)
        downloader(url, archive, env, 60, MAX_ARCHIVE)
        if expected_archive_sha256 and digest_file(archive) != expected_archive_sha256:
            raise ValueError('downloaded OpenCode archive digest does not match OC_OPENCODE_ARCHIVE_SHA256')
        extract_opencode_binary(archive, candidate)
        if candidate.is_symlink() or not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise ValueError('upgrade did not produce an executable regular file')
        newhash = digest_file(candidate)
        size = candidate.stat().st_size
        # Verify the expected binary digest BEFORE executing the candidate even for --version.
        if newhash != expected_sha256:
            raise ValueError('downloaded OpenCode binary digest does not match OC_OPENCODE_SHA256')
        version = reported_version(runner([str(candidate), '--version'], env, 10))
        if version.lstrip('v') != requested.lstrip('v'):
            raise ValueError('updated OpenCode version does not match the requested pin')
        if not 0 < size <= MAX_BINARY:
            raise ValueError('updated OpenCode binary has invalid size')
        header = json.dumps(
            {'old': oldhash, 'new': newhash, 'size': size, 'version': version},
            separators=(',', ':'),
        ).encode('ascii') + b'\n'
        payload = candidate.read_bytes()
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError('candidate changed while preparing the update frame')
    output.write(MAGIC + header + payload + END)
    output.flush()


def read_candidate_metadata(stream):
    magic = stream.readline(len(MAGIC) + 1)
    if magic == b'':
        return None  # no update, or upstream failed before sending a candidate
    if magic != MAGIC:
        raise ValueError('invalid update frame')
    raw = stream.readline(1025)
    if len(raw) > 1024 or not raw.endswith(b'\n'):
        raise ValueError('invalid update header')
    header = json.loads(raw)
    if (
        set(header) != {'old', 'new', 'size', 'version'}
        or not (header['old'] is None or CHECKSUM.fullmatch(header['old']))
        or not CHECKSUM.fullmatch(header['new'])
        or type(header['size']) is not int or not 0 < header['size'] <= MAX_BINARY
        or not VERSION.fullmatch(header['version'])
    ):
        raise ValueError('invalid update metadata')
    return header


def check_current_install(home, opened, expected_hash):
    def named_identity():
        try:
            st = os.stat('opencode', dir_fd=opened[-1], follow_symlinks=False)
        except FileNotFoundError:
            return None
        return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns

    before = named_identity()
    current = read_old(home)
    current_hash = None if current is None else hashlib.sha256(current).hexdigest()
    if current_hash != expected_hash or before != named_identity():
        raise ValueError('OpenCode changed during update; keeping current copy')
    for idx, component in enumerate((INSTALL_DIRNAME, 'bin')):
        named = os.stat(component, dir_fd=opened[idx], follow_symlinks=False)
        held = os.fstat(opened[idx + 1])
        if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
            raise ValueError('OpenCode install directory changed during update')
    if named_identity() != before:
        raise ValueError('OpenCode changed during promotion')


def promote(home, stream, expected_sha256):
    if not expected_sha256 or not CHECKSUM.fullmatch(expected_sha256):
        raise ValueError('OC_OPENCODE_SHA256 must be a 64-character lowercase hex digest')
    header = read_candidate_metadata(stream)
    if header is None:
        return
    if header['new'] != expected_sha256:
        raise ValueError('candidate frame digest does not match expected OC_OPENCODE_SHA256')
    opened = open_install_dir(home, True)
    bindir = opened[-1]
    tmpname = '.oc-update-' + os.urandom(16).hex()
    try:
        fd = os.open(tmpname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755, dir_fd=bindir)
        h = hashlib.sha256()
        remaining = header['size']
        with os.fdopen(fd, 'wb') as out:
            while remaining:
                block = stream.read(min(1024 * 1024, remaining))
                if not block:
                    raise ValueError('truncated update frame')
                out.write(block)
                h.update(block)
                remaining -= len(block)
            out.flush()
            os.fsync(out.fileno())
        if h.hexdigest() != expected_sha256 or stream.read(len(END)) != END or stream.read(1):
            raise ValueError('corrupt or incomplete update frame')
        check_current_install(home, opened, header['old'])
        os.replace(tmpname, 'opencode', src_dir_fd=bindir, dst_dir_fd=bindir)
        print('OpenCode: installed ' + header['version'], file=sys.stderr)
    finally:
        try:
            os.unlink(tmpname, dir_fd=bindir)
        except FileNotFoundError:
            pass
        for fd in reversed(opened):
            os.close(fd)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2:
            raise ValueError('expected snapshot, stage or promote')
        if sys.argv[1] == 'snapshot':
            snapshot(Path('/source'), sys.stdout.buffer)
        elif sys.argv[1] == 'stage':
            stage(
                sys.stdin.buffer,
                os.environ.get('OC_OPENCODE_VERSION', ''),
                os.environ.get('OC_OPENCODE_SHA256', ''),
                sys.stdout.buffer,
                expected_archive_sha256=os.environ.get('OC_OPENCODE_ARCHIVE_SHA256', ''),
            )
        elif sys.argv[1] == 'promote':
            promote(Path('/root'), sys.stdin.buffer, os.environ.get('OC_OPENCODE_SHA256', ''))
        else:
            raise ValueError('expected snapshot, stage or promote')
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f'warning: OpenCode update failed; keeping the existing copy: {exc}', file=sys.stderr)
        sys.exit(1)
