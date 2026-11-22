#!/usr/bin/env python3
"""Stage OpenCode with a read-only shared home; promote via a separate offline writer.

An offline reader sees the shared home read-only and sends only the digest of
the current binary to a networked updater with no mounts. The offline writer alone sees the
shared home writable; it promotes a complete verified candidate atomically.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

VERSION = re.compile(r'v?\d+(?:\.\d+){2}(?:[-+][0-9A-Za-z.-]+)?', re.ASCII)
CHECKSUM = re.compile(r'[0-9a-f]{64}')
INSTALL_DIRNAME = '.opencode'
SOURCE_MAGIC = b'OC-OPENCODE-SOURCE-2\n'
MAGIC = b'OC-OPENCODE-UPDATE-1\n'
END = b'\nOC-OPENCODE-UPDATE-END\n'
MAX_BINARY = 512 * 1024 * 1024


def run(args, env, timeout):
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
    except BaseException:
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        proc.communicate(timeout=5)
        raise
    if proc.returncode != 0:
        raise RuntimeError(f'{args[0]} failed ({proc.returncode})')
    return out.decode('utf-8', 'replace')


def reported_version(output):
    """Accept one complete version line, optionally branded by OpenCode."""
    match = re.fullmatch(rf'(?:opencode )?({VERSION.pattern})\n?', output, flags=VERSION.flags)
    if not match: raise ValueError('invalid OpenCode version output')
    return match.group(1)


def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''): h.update(block)
    return h.hexdigest()


def open_install_dir(home, create):
    """Open each volume directory without following symlinks."""
    opened = [os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in (INSTALL_DIRNAME, 'bin'):
            if create:
                try: os.mkdir(part, 0o700, dir_fd=opened[-1])
                except FileExistsError: pass
            opened.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=opened[-1]))
        return opened
    except BaseException:
        for fd in reversed(opened): os.close(fd)
        raise


def read_old(home):
    try: opened = open_install_dir(home, False)
    except FileNotFoundError: return None
    try:
        try: fd = os.open('opencode', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=opened[-1])
        except FileNotFoundError: return None
        with os.fdopen(fd, 'rb') as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or not (st.st_mode & 0o111):
                raise ValueError('existing OpenCode binary is not an executable regular file')
            data = f.read(MAX_BINARY+1)
            if len(data) > MAX_BINARY: raise ValueError('existing OpenCode binary is too large')
            return data
    finally:
        for fd in reversed(opened): os.close(fd)


def snapshot(home, output):
    old = read_old(home)
    digest = None if old is None else hashlib.sha256(old).hexdigest()
    output.write(SOURCE_MAGIC + json.dumps(digest).encode('ascii') + b'\n' + END)
    output.flush()


def read_snapshot(stream):
    if stream.readline(len(SOURCE_MAGIC)+1) != SOURCE_MAGIC: raise ValueError('invalid source frame')
    raw = stream.readline(67)
    if not raw.endswith(b'\n'): raise ValueError('invalid source digest')
    digest = json.loads(raw)
    if digest is not None and (type(digest) is not str or not CHECKSUM.fullmatch(digest)):
        raise ValueError('invalid source digest')
    if stream.read(len(END)) != END or stream.read(1):
        raise ValueError('corrupt or incomplete source frame')
    return digest

def install_release(installer, requested, env, runner):
    v1_pin = requested and int(requested.lstrip('v').partition('.')[0]) < 2
    url = 'https://opencode.ai/install' if v1_pin else 'https://opencode.ai/v2/install'
    runner(['curl', '-fsSL', '--connect-timeout', '5', '--max-time', '30',
            '-o', str(installer), url], env, 35)
    args = ['bash', str(installer), '--no-modify-path']
    if requested:
        args += ['--version', requested]
    runner(args, env, 90)


def stage(stream, requested, output, runner=run):
    if requested and not VERSION.fullmatch(requested):
        raise ValueError('OC_OPENCODE_VERSION must be keep or a version such as 2.3.0')
    oldhash = read_snapshot(stream)
    with tempfile.TemporaryDirectory(prefix='oc-opencode-update-') as tmp:
        base = Path(tmp); stagehome = base/'home'; stagebin = stagehome/INSTALL_DIRNAME/'bin'
        stagebin.mkdir(parents=True); candidate = stagebin/'opencode'
        env = dict(os.environ)
        env.update(HOME=str(stagehome), PATH=f'{stagebin}:/usr/bin:/bin', CI='true',
                   XDG_CONFIG_HOME=str(base/'config'), XDG_DATA_HOME=str(base/'data'),
                   XDG_CACHE_HOME=str(base/'cache'), XDG_STATE_HOME=str(base/'state'))
        install_release(base/'install.sh', requested, env, runner)
        if candidate.is_symlink() or not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise ValueError('upgrade did not produce an executable regular file')
        version = reported_version(runner([str(candidate), '--version'], env, 10))
        if requested and version.lstrip('v') != requested.lstrip('v'):
            raise ValueError('updated OpenCode version does not match the requested pin')
        newhash = digest_file(candidate); size = candidate.stat().st_size
        if newhash == oldhash:
            print('OpenCode: already up to date', file=sys.stderr)
            return
        if not 0 < size <= MAX_BINARY: raise ValueError('updated OpenCode binary has invalid size')
        header = json.dumps({'old': oldhash, 'new': newhash, 'size': size, 'version': version},
                            separators=(',', ':')).encode('ascii') + b'\n'
        # Complete all stage validation and temporary-directory cleanup before sending.
        payload = candidate.read_bytes()
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != newhash:
        raise ValueError('candidate changed while preparing the update frame')
    output.write(MAGIC + header + payload + END); output.flush()


def read_candidate_metadata(stream):
    magic = stream.readline(len(MAGIC)+1)
    if magic == b'': return None  # no update, or upstream failed before sending a candidate
    if magic != MAGIC: raise ValueError('invalid update frame')
    raw = stream.readline(1025)
    if len(raw) > 1024 or not raw.endswith(b'\n'): raise ValueError('invalid update header')
    header = json.loads(raw)
    if (set(header) != {'old', 'new', 'size', 'version'} or
        not (header['old'] is None or CHECKSUM.fullmatch(header['old'])) or
        not CHECKSUM.fullmatch(header['new']) or
        type(header['size']) is not int or not 0 < header['size'] <= MAX_BINARY or
        not VERSION.fullmatch(header['version'])):
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
        held = os.fstat(opened[idx+1])
        if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
            raise ValueError('OpenCode install directory changed during update')
    if named_identity() != before:
        raise ValueError('OpenCode changed during promotion')


def promote(home, stream):
    header = read_candidate_metadata(stream)
    if header is None:
        return
    opened = open_install_dir(home, True)
    bindir = opened[-1]; tmpname = '.oc-update-' + os.urandom(16).hex()
    try:
        fd = os.open(tmpname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755, dir_fd=bindir)
        h = hashlib.sha256(); remaining = header['size']
        with os.fdopen(fd, 'wb') as out:
            while remaining:
                block = stream.read(min(1024*1024, remaining))
                if not block: raise ValueError('truncated update frame')
                out.write(block); h.update(block); remaining -= len(block)
            out.flush(); os.fsync(out.fileno())
        if h.hexdigest() != header['new'] or stream.read(len(END)) != END or stream.read(1):
            raise ValueError('corrupt or incomplete update frame')
        check_current_install(home, opened, header['old'])
        os.replace(tmpname, 'opencode', src_dir_fd=bindir, dst_dir_fd=bindir)
        print('OpenCode: installed ' + header['version'], file=sys.stderr)
    finally:
        try: os.unlink(tmpname, dir_fd=bindir)
        except FileNotFoundError: pass
        for fd in reversed(opened): os.close(fd)


if __name__ == '__main__':
    try:
        if len(sys.argv) != 2: raise ValueError('expected snapshot, stage or promote')
        if sys.argv[1] == 'snapshot': snapshot(Path('/source'), sys.stdout.buffer)
        elif sys.argv[1] == 'stage': stage(sys.stdin.buffer, os.environ.get('OC_OPENCODE_VERSION', ''), sys.stdout.buffer)
        elif sys.argv[1] == 'promote': promote(Path('/root'), sys.stdin.buffer)
        else: raise ValueError('expected snapshot, stage or promote')
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f'warning: OpenCode update failed; keeping the existing copy: {exc}', file=sys.stderr)
        sys.exit(1)
