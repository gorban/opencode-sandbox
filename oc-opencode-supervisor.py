#!/usr/bin/env python3
"""Run isolated updater phases, verifying each owned container is gone before proceeding.

Receipts and binary frames live only in a private host-trusted work directory. A
missing/invalid receipt or unverified cleanup retains that directory and fails closed.
"""
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

MAX_FRAME = 512 * 1024 * 1024 + 4096
OWNER_LABEL = 'io.github.gorban.opencode-sandbox.update'


class UnsafeCleanup(Exception): pass


def command(argv, *, stdin=None, stdout=None, stderr=None, timeout=30, parent=None, max_output=MAX_FRAME):
    proc = subprocess.Popen(argv, stdin=stdin if stdin is not None else subprocess.DEVNULL,
                            stdout=stdout if stdout is not None else subprocess.DEVNULL,
                            stderr=stderr if stderr is not None else subprocess.DEVNULL,
                            start_new_session=True, close_fds=True)
    start = time.monotonic()
    try:
        while proc.poll() is None:
            if parent is not None and os.getppid() != parent: raise InterruptedError('calling shell exited')
            if time.monotonic() - start > timeout: raise TimeoutError('host Podman command timed out')
            if stdout is not None and os.fstat(stdout.fileno()).st_size > max_output:
                raise ValueError('update output exceeds size limit')
            time.sleep(.05)
        if stdout is not None and os.fstat(stdout.fileno()).st_size > max_output:
            raise ValueError('update output exceeds size limit')
        return proc.returncode
    except BaseException:
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        proc.wait(timeout=5)
        raise


def read_cid(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1 or st.st_size > 128:
            raise ValueError('unsafe container ID receipt')
        data = os.read(fd, 129).decode('ascii').strip()
        if not re.fullmatch(r'[0-9a-f]{64}', data): raise ValueError('invalid container ID receipt')
        return data
    finally: os.close(fd)


def podman_text(prefix, args, directory, timeout=10):
    with tempfile.TemporaryFile(dir=directory) as out:
        rc = command([*prefix, 'podman', *args], stdout=out, timeout=timeout, max_output=4096)
        out.seek(0); return rc, out.read(4096).decode('utf-8', 'replace').strip()


def cleanup_container(prefix, cid, token, directory):
    try:
        rc, _ = podman_text(prefix, ['container', 'exists', cid], directory)
        if rc == 1: return
        if rc != 0: raise UnsafeCleanup('cannot determine whether updater container exists')
        fmt = '{{.Id}} {{index .Config.Labels "' + OWNER_LABEL + '"}}'
        rc, actual = podman_text(prefix, ['container', 'inspect', '--format', fmt, cid], directory)
        if rc != 0 or actual != f'{cid} {token}':
            raise UnsafeCleanup('updater container ID or ownership label could not be verified')
        rc, _ = podman_text(prefix, ['rm', '-f', cid], directory)
        if rc != 0: raise UnsafeCleanup('could not remove updater container')
        rc, _ = podman_text(prefix, ['container', 'exists', cid], directory)
        if rc != 1: raise UnsafeCleanup('could not verify updater container removal')
    except (OSError, TimeoutError, ValueError, subprocess.SubprocessError) as exc:
        raise UnsafeCleanup(str(exc)) from exc


def phase(prefix, directory, token, name, options, image, level, memory, inp, out, timeout, parent):
    cidfile = directory / (name + '.cid')
    cid = None
    attempted = False
    try:
        create = [*prefix, 'podman', 'create', '--cidfile', str(cidfile), '--label', f'{OWNER_LABEL}={token}',
                  '-i', '--http-proxy=false', '--entrypoint', 'python3', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                  '--security-opt', f'label=level:{level}', '--pids-limit=128', f'--memory={memory}',
                  *options, image, '-I', '/usr/local/bin/oc-opencode-update', name]
        attempted = True
        rc = command(create, timeout=30, parent=parent)
        try: cid = read_cid(cidfile)
        except (OSError, ValueError, UnicodeError) as exc: raise UnsafeCleanup(f'{name}: missing or invalid ID receipt: {exc}') from exc
        if rc != 0: raise RuntimeError(f'{name}: container creation failed')
        if inp is not None: inp.seek(0)
        rc = command([*prefix, 'podman', 'start', '-ai', cid], stdin=inp, stdout=out,
                     timeout=timeout, parent=parent)
        if rc != 0: raise RuntimeError(f'{name}: updater command failed ({rc})')
    finally:
        if attempted:
            # Finish exact-ID cleanup even if Ctrl-C or SIGTERM arrives during cleanup.
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                if cid is None:
                    try: cid = read_cid(cidfile)
                    except (OSError, ValueError, UnicodeError) as exc:
                        raise UnsafeCleanup(f'{name}: cannot prove which container was created: {exc}') from exc
                cleanup_container(prefix, cid, token, directory)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def main():
    if len(sys.argv) < 7: raise ValueError('invalid updater supervisor arguments')
    state, level, volume, image, memory, version = sys.argv[1:7]
    prefix = sys.argv[7:]
    if prefix not in ([], ['distrobox-host-exec']): raise ValueError('invalid host command prefix')
    if not re.fullmatch(r's0:c[0-9]+,c[0-9]+', level): raise ValueError('invalid SELinux level')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', volume) or not re.fullmatch(r'[A-Za-z0-9_.:-]+', image):
        raise ValueError('invalid volume or image name')
    state_path = Path(state)
    if state_path.is_symlink() or not state_path.is_dir() or state_path.stat().st_uid != os.geteuid():
        raise ValueError('unsafe state directory')
    if any(state_path.glob('opencode-update.*')):
        raise UnsafeCleanup('prior updater receipts require inspection before retry')
    directory = Path(tempfile.mkdtemp(prefix='opencode-update.', dir=state_path))
    token = secrets.token_hex(16); parent = os.getppid(); safe = True
    try:
        with tempfile.TemporaryFile(dir=directory) as snapshot, tempfile.TemporaryFile(dir=directory) as candidate:
            phase(prefix, directory, token, 'snapshot', ['--network=none', '-v', f'{volume}:/source:ro'],
                  image, level, memory, None, snapshot, 30, parent)
            phase(prefix, directory, token, 'stage', ['-e', f'OC_OPENCODE_VERSION={version}'],
                  image, level, memory, snapshot, candidate, 120, parent)
            # Stage and reader containers have both been verified gone before promotion begins.
            phase(prefix, directory, token, 'promote', ['--network=none', '-v', f'{volume}:/root'],
                  image, level, memory, candidate, None, 30, parent)
        print('OpenCode update check complete', file=sys.stderr)
    except UnsafeCleanup:
        safe = False
        raise
    finally:
        if safe:
            shutil.rmtree(directory)
        else:
            print(f'Updater cleanup uncertain; receipts retained at {directory}', file=sys.stderr)


def stop(_signum, _frame): raise InterruptedError('interrupted')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop)
    try: main()
    except UnsafeCleanup as exc:
        print(f'error: {exc}', file=sys.stderr); sys.exit(2)
    except (OSError, ValueError, RuntimeError, TimeoutError, InterruptedError, KeyboardInterrupt) as exc:
        print(f'warning: OpenCode update failed; keeping the existing copy: {exc}', file=sys.stderr); sys.exit(1)
