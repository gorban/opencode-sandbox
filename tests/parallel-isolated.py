#!/usr/bin/env python3
"""Isolated real-host parallel acceptance runner. Without --run, audit sources only.

A private rootless Podman store is mandatory. Never point it at an existing store.
The default real run uses headless Chromium. --run --wayland runs the opt-in
desktop smoke. Failed or uncertain cleanup retains the private directory for inspection.

Because oc-sandbox fails closed into managed mode whenever the calling Linux account has
~/.config/oc-sandbox/{providers.toml,openai}, run --run under a dedicated local test user,
SELinux VM, or host CI runner without managed provider state in its account home.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parent.parent
HOST_EXEC = '/usr/bin/distrobox-host-exec'
PODMAN = '/usr/bin/podman'


def die(message):
    raise RuntimeError(message)


def policy(source):
    found = re.findall(r"^atomic_host_file \"\$POLDIR/oc_chromium.cil\" 0644 <<'POL'\n(.*?)\nPOL\n", source, re.S | re.M)
    if len(found) != 1:
        die('policy source anchor changed; inspect before running')
    return found[0] + '\n'


def run_host(args, *, timeout=15, capture=False):
    cmd = ([HOST_EXEC] if os.environ.get('CONTAINER_ID') else []) + list(args)
    return subprocess.run(cmd, stdin=subprocess.DEVNULL, timeout=timeout, check=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def preflight():
    for name in ('oc-sandbox', 'tests/parallel.sh', 'oc-bridge.py'):
        if not (REPO / name).is_file():
            die('missing required source: ' + name)
    content = (REPO / 'oc-sandbox').read_text()
    pol = policy(content)
    suite = (REPO / 'tests/parallel.sh').read_text()
    for port in ('18181', '18182', '18192', '18183'):
        if port not in suite:
            die('port substitution anchor missing: ' + port)
    if 'OC_PTEST_ISOLATED' not in suite:
        die('suite isolation guard missing')
    if os.environ.get('CONTAINER_ID') and not os.path.isfile(HOST_EXEC):
        die('distrobox-host-exec unavailable')
    print('Source audit passed; no Podman calls or resources created.')
    return pol


def host_preflight(desktop):
    code = ('import ctypes; l=ctypes.CDLL("libselinux.so.1"); '
            'l.security_check_context.argtypes=[ctypes.c_char_p]; '
            'raise SystemExit(not (l.is_selinux_enabled()==1 and '
            'l.security_check_context(b"system_u:system_r:oc_chromium.process:s0")==0))')
    try:
        run_host(['/usr/bin/python3', '-c', code], capture=True)
    except (subprocess.SubprocessError, OSError):
        die('SELinux is disabled or the oc_chromium.process context is unavailable; install/verify policy first')
    runtime = Path(os.environ.get('XDG_RUNTIME_DIR') or f'/run/user/{os.getuid()}')
    if not runtime.is_absolute():
        die('XDG_RUNTIME_DIR must be an absolute path')
    root_receipt(runtime)
    if not desktop:
        return runtime, None
    display = os.environ.get('WAYLAND_DISPLAY', 'wayland-0')
    if '/' in display or not display:
        die('a simple WAYLAND_DISPLAY is required')
    path = runtime / display
    if not path.is_socket():
        die('real Wayland socket unavailable')
    return runtime, path


def shell_file(path, text):
    path.write_text('#!/bin/sh\nset -eu\n' + text + '\n')
    path.chmod(0o700)


def fresh_ports():
    # The caller can be in a different network namespace from Podman.
    code = ('import socket; s=[]; '
            '[(s.append(socket.socket()),s[-1].bind(("127.0.0.1",0))) for _ in range(4)]; '
            'print(" ".join(str(x.getsockname()[1]) for x in s))')
    values = run_host(['/usr/bin/python3', '-c', code], capture=True).stdout.decode().split()
    if len(values) != 4 or len(set(values)) != 4 or any(not x.isdecimal() for x in values):
        die('could not select four distinct host ports')
    return values


def root_receipt(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        die('private root has unsafe identity or permissions')
    return (info.st_dev, info.st_ino, info.st_uid)


def check_receipt(path, receipt):
    if root_receipt(path) != receipt:
        die('private root identity changed')


def prepare(base, runtime_base, pol, wayland):
    for dirname in ('bin', 'home', 'home/opencode-sandbox', 'store', 'source', 'source/tests'):
        (base / dirname).mkdir(mode=0o700)
    for dirname in ('xdg', 'runroot', 'tmp'):
        (runtime_base / dirname).mkdir(mode=0o700)
    # The workspace is mounted into containers with different UIDs; private parents
    # remain 0700 on the host, while the mounted directory permits traversal.
    (base / 'home/opencode-sandbox').chmod(0o755)
    source = base / 'source'
    # Copy only this checkout's runtime files; never copy personal configuration.
    for f in REPO.glob('oc-*'):
        if f.is_file():
            shutil.copy2(f, source / f.name)
            if hashlib.sha256(f.read_bytes()).digest() != hashlib.sha256((source / f.name).read_bytes()).digest():
                die('runtime copy changed during preparation: ' + f.name)
    shutil.copy2(REPO / 'README.md', source / 'README.md')
    print('Runtime script SHA-256:', hashlib.sha256((source / 'oc-sandbox').read_bytes()).hexdigest(), flush=True)
    suite = (REPO / 'tests/parallel.sh').read_text()
    for original, replacement in zip(('18181', '18182', '18192', '18183'), fresh_ports()):
        suite = suite.replace(original, replacement)
    (source / 'tests/parallel.sh').write_text(suite)
    if wayland is not None:
        (runtime_base / 'xdg' / wayland.name).symlink_to(wayland)
    # The default shared-memory lock name is per UID, not per graphroot.  A fresh
    # store with file locks keeps lock state under this run's private directory.
    (base / 'containers.conf').write_text('[engine]\nlock_type="file"\ncgroup_manager="cgroupfs"\n')
    (base / 'storage.conf').write_text('[storage]\ndriver="vfs"\ngraphroot=' +
        json.dumps(str(base / 'store')) + '\nrunroot=' + json.dumps(str(runtime_base / 'runroot')) + '\n')
    (base / 'auth.json').write_text('{"auths":{}}\n')
    receipt = base / 'home/.local/share/oc-sandbox/policy/installed'
    receipt.parent.mkdir(parents=True, mode=0o700)
    receipt.write_text(hashlib.sha256(pol.encode()).hexdigest()[:16] + '\n')
    q = shlex.quote
    home = str(base / 'home')
    runtime = str(runtime_base / 'xdg')
    clean_env = {'HOME': home, 'XDG_RUNTIME_DIR': runtime, 'XDG_DATA_HOME': home + '/.local/share',
        'XDG_CONFIG_HOME': home + '/.config', 'TMPDIR': str(runtime_base / 'tmp'),
        'CONTAINERS_CONF': str(base / 'containers.conf'), 'CONTAINERS_STORAGE_CONF': str(base / 'storage.conf'),
        'REGISTRY_AUTH_FILE': str(base / 'auth.json'), 'PATH': '/usr/local/bin:/usr/bin:/bin',
        'USER': pwd.getpwuid(os.getuid()).pw_name, 'LANG': 'C'}
    flags = ['--root=' + str(base / 'store'), '--runroot=' + str(runtime_base / 'runroot'),
             '--tmpdir=' + str(runtime_base / 'tmp'), '--storage-driver=vfs', '--events-backend=file']
    local_podman = str(base / 'bin/podman-host')
    shell_file(Path(local_podman), 'exec /usr/bin/env -i ' +
        ' '.join(q(k + '=' + v) for k, v in clean_env.items()) + ' ' + q(PODMAN) + ' ' +
        ' '.join(map(q, flags)) + ' "$@"')
    if os.environ.get('CONTAINER_ID'):
        shell_file(base / 'bin/podman', 'exec ' + q(HOST_EXEC) + ' ' + q(local_podman) + ' "$@"')
        shell_file(base / 'bin/distrobox-host-exec',
                   'case "${1-}" in\n'
                   ' podman) shift; exec ' + q(HOST_EXEC) + ' ' + q(local_podman) + ' "$@";;\n'
                   ' systemctl) shift; exec ' + q(str(base / 'bin/systemctl')) + ' "$@";;\n'
                   ' pkexec|sudo|semodule) echo "privileged command refused" >&2; exit 1;;\n'
                   ' *) exec ' + q(HOST_EXEC) + ' /usr/bin/env -i ' +
                   ' '.join(q(k + '=' + v) for k, v in clean_env.items()) + ' "$@";;\nesac')
    else:
        shell_file(base / 'bin/podman', 'exec ' + q(local_podman) + ' "$@"')
    manager_fixture = q(str(REPO / 'tests/bridge-manager-fixture.sh'))
    shell_file(base / 'bin/systemctl', f'exec /usr/bin/bash {manager_fixture} "$@"')
    for cmd in ('sudo', 'pkexec', 'semodule'):
        shell_file(base / ('bin/' + cmd), 'echo "privileged command refused" >&2; exit 1')
    env = {k: os.environ[k] for k in ('CONTAINER_ID', 'LANG', 'TERM') if k in os.environ}
    env.update(HOME=home, XDG_RUNTIME_DIR=runtime, XDG_DATA_HOME=home + '/.local/share',
               XDG_CONFIG_HOME=home + '/.config', TMPDIR=str(runtime_base / 'tmp'),
               PATH=str(base / 'bin') + ':/usr/local/bin:/usr/bin:/bin', OC_PTEST_ISOLATED='1')
    env['OC_CHROMIUM_MODE'] = 'headless' if wayland is None else 'wayland'
    if wayland is not None:
        env['WAYLAND_DISPLAY'] = wayland.name
    return env


def cleanup(base, runtime_base, env, base_receipt, runtime_receipt, store_receipt):
    # Every query and deletion uses the private store and only IDs/names returned by it.
    check_receipt(base, base_receipt)
    check_receipt(runtime_base, runtime_receipt)
    check_receipt(base/'store', store_receipt)
    podman = str(base / 'bin/podman')
    def query(*args):
        p = subprocess.run([podman, *args], env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        if p.returncode:
            die('private-store inventory failed: ' + ' '.join(args[:2]))
        return list(dict.fromkeys(line.strip() for line in p.stdout.splitlines() if line.strip()))
    def remove(args, ids, *, tags=False):
        for ident in ids:
            pattern = r'[a-zA-Z0-9][a-zA-Z0-9._:/@-]*' if tags else r'[a-zA-Z0-9_.:-]+'
            if not re.fullmatch(pattern, ident):
                die('invalid private-store identifier')
            p = subprocess.run([podman, *args, ident], env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
            if p.returncode:
                die('private-store removal failed: ' + ' '.join(args))
    remove(['pod', 'rm', '-f'], query('pod', 'ps', '-q', '--no-trunc'))
    remove(['rm', '-f'], query('ps', '-aq', '--no-trunc'))
    if query('ps', '-aq', '--no-trunc', '--external'):
        die('private storage still contains external containers; retain both roots')
    remove(['secret', 'rm'], query('secret', 'ls', '--format', '{{.ID}}'))
    remove(['volume', 'rm'], query('volume', 'ls', '-q'))
    for entry in query('images', '--no-trunc', '--format', '{{.ID}}|{{.Repository}}:{{.Tag}}'):
        ident, sep, tag = entry.partition('|')
        if not sep or not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', ident):
            die('invalid private image identity')
        if '<none>' in tag:
            continue
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:/@-]*', tag):
            die('invalid private image tag')
        actual = query('image', 'inspect', '--format', '{{.Id}}', tag)
        if len(actual) != 1 or actual[0].removeprefix('sha256:') != ident.removeprefix('sha256:'):
            die('private image tag changed during cleanup')
        remove(['untag', ident], [tag], tags=True)
    def image_exists(ident):
        p = subprocess.run([podman, 'image', 'exists', ident], env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        if p.returncode == 0:
            return True
        if p.returncode == 1:
            return False
        die('private-store image existence check failed')
    for ident in query('images', '-aq', '--no-trunc'):
        if not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', ident):
            die('invalid private image identity')
        if not image_exists(ident):
            continue
        p = subprocess.run([podman, 'rmi', ident], env=env, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
        if p.returncode and image_exists(ident):
            die('private-store image removal failed')
    for args in (('pod', 'ps', '-q'), ('ps', '-aq'), ('secret', 'ls', '-q'), ('volume', 'ls', '-q'), ('images', '-aq')):
        if query(*args):
            die('private-store inventory not empty')
    def check_mounts():
        host_roots = []
        for root in (base, runtime_base):
            canonical = run_host(['/usr/bin/realpath', '--', str(root)], capture=True).stdout.decode().rstrip('\n')
            if not canonical.startswith('/'):
                die('could not resolve private directory on host')
            host_roots.append(canonical)
        mounts = run_host(['/usr/bin/cat', '/proc/self/mountinfo'], capture=True).stdout.decode(errors='replace')
        for line in mounts.splitlines():
            fields = line.split()
            if len(fields) < 5:
                die('could not parse host mount inventory')
            mount = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), fields[4])
            if any(mount == root or mount.startswith(root + '/') for root in host_roots):
                die('mount remains under private directory')
    check_mounts()
    check_receipt(base, base_receipt)
    check_receipt(runtime_base, runtime_receipt)
    check_receipt(base/'store', store_receipt)
    # The private graphroot can contain files owned by mapped container UIDs.  This
    # constant program opens the owned parent and exact graphroot without following
    # symlinks and clears its contents under the private Podman user namespace.
    script = '''import os,re,shutil,stat,sys
parent,dev,ino=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 st=os.stat("store",dir_fd=fd,follow_symlinks=False)
 if not stat.S_ISDIR(st.st_mode) or (st.st_dev,st.st_ino)!=(dev,ino) or not shutil.rmtree.avoids_symlink_attacks:
  raise SystemExit("private graphroot identity changed")
 root=os.path.join(os.path.realpath(parent),"store")
 with open("/proc/self/mountinfo",encoding="utf-8",errors="strict") as mounts:
  for line in mounts:
   fields=line.split()
   if len(fields)<5:
    raise SystemExit("could not parse user namespace mounts")
   mount=re.sub(r"\\\\([0-7]{3})",lambda m:chr(int(m.group(1),8)),fields[4])
   if mount==root or mount.startswith(root+"/"):
    raise SystemExit("mount remains under private graphroot")
 store=os.open("store",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 try:
  opened=os.fstat(store)
  if (opened.st_dev,opened.st_ino)!=(dev,ino):
   raise SystemExit("private graphroot identity changed")
  for name in os.listdir(store):
   entry=os.stat(name,dir_fd=store,follow_symlinks=False)
   if stat.S_ISDIR(entry.st_mode):
    shutil.rmtree(name,dir_fd=store)
   else:
    os.unlink(name,dir_fd=store)
 finally:
  os.close(store)
finally:
 os.close(fd)
'''
    subprocess.run([podman, 'unshare', '/usr/bin/python3', '-I', '-c', script,
                    str(base), str(store_receipt[0]), str(store_receipt[1])],
                   env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=90, check=True)
    check_receipt(base/'store', store_receipt)
    check_mounts()
    check_receipt(base, base_receipt)
    check_receipt(runtime_base, runtime_receipt)
    check_receipt(base/'store', store_receipt)
    shutil.rmtree(base/'store')
    shutil.rmtree(runtime_base)
    shutil.rmtree(base)


def descendants():
    """Return current descendants and start times; no command lines or environments read."""
    parents, starts = {}, {}
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            stat = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            parents[int(path.name)], starts[int(path.name)] = int(stat[1]), int(stat[19])
        except FileNotFoundError:
            continue
    owned = {os.getpid()}
    while True:
        expanded = owned | {pid for pid, parent in parents.items() if parent in owned}
        if expanded == owned:
            return {pid: starts[pid] for pid in owned if pid != os.getpid()}
        owned = expanded


def wait_for_suite(child, pending, timeout):
    cutoff = time.monotonic() + timeout
    while child.poll() is None and not pending:
        if time.monotonic() >= cutoff:
            return True
        time.sleep(.05)
    return False


def suite_exit(status, pending, timed_out):
    if pending:
        return 128 + pending[0]
    return 124 if timed_out else status


def supervised_suite(command, env, *, grace=3, timeout=float('inf')):
    """Adopt, cancel and reap the suite tree; never clean a store with live children."""
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        die('pidfd support is required for safe interruption handling')
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        die('could not enable child subreaper')
    pending = []
    old = {sig: signal.signal(sig, lambda number, frame: pending.append(number))
           for sig in (signal.SIGINT, signal.SIGTERM)}
    child = None
    try:
        child = subprocess.Popen(command, env=env, start_new_session=True)
        timed_out = wait_for_suite(child, pending, timeout)
        status = child.poll()
        interrupted = bool(pending) or timed_out
        cancelled = interrupted
        deadline = time.monotonic() + grace
        kill_deadline = deadline + grace
        while True:
            # Reap adopted descendants without consuming the tracked Popen child.
            if child.poll() is not None:
                while True:
                    try:
                        pid, _ = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if not pid:
                        break
            owned = descendants()
            if not owned:
                break
            now = time.monotonic()
            if now >= kill_deadline:
                return suite_exit(status or 1, pending, timed_out), False, interrupted
            sig = signal.SIGKILL if now >= deadline else signal.SIGTERM
            cancelled = True
            for pid, start in owned.items():
                try:
                    fd = os.pidfd_open(pid)
                    try:
                        # Verify identity after opening before signalling.
                        if descendants().get(pid) == start:
                            signal.pidfd_send_signal(fd, sig)
                            if sig == signal.SIGTERM:
                                signal.pidfd_send_signal(fd, signal.SIGCONT)
                    finally:
                        os.close(fd)
                except ProcessLookupError:
                    pass
            time.sleep(.05)
        status = child.wait()
        return suite_exit(status, pending, timed_out), True, cancelled
    finally:
        for sig, handler in old.items():
            signal.signal(sig, handler)


def require_clean_legacy_account(account_home=None):
    """Fail fast before --run if the calling Linux account has managed provider state."""
    home = Path(account_home) if account_home is not None else Path(pwd.getpwuid(os.geteuid()).pw_dir)
    cfg = home / '.config' / 'oc-sandbox'
    if any((cfg / leaf).exists() or (cfg / leaf).is_symlink() for leaf in ('providers.toml', 'openai')):
        die(
            'account home has managed provider configuration (~/.config/oc-sandbox/{providers.toml,openai}); '
            'oc-sandbox enforces managed mode fail-closed for this account. Run tests/parallel-isolated.py --run '
            'under a clean local test user, SELinux VM, or host CI runner without managed provider state.'
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='run real isolated headless Podman acceptance')
    parser.add_argument('--wayland', action='store_true', help='use --run to run only the visible Wayland smoke')
    args = parser.parse_args()
    if args.wayland and not args.run:
        parser.error('--wayland requires --run')
    pol = preflight()
    if not args.run:
        return 0
    require_clean_legacy_account()
    runtime_parent, wayland = host_preflight(args.wayland)
    # The distrobox /tmp is not necessarily visible to the host bridge.
    base = Path(tempfile.mkdtemp(prefix='.oc-parallel-private-', dir=Path.home()))
    os.chmod(base, 0o700)
    runtime_base = None
    env = None
    result = 1
    clean = False
    safe = False
    try:
        base_receipt = root_receipt(base)
        runtime_base = Path(tempfile.mkdtemp(prefix='oc-parallel-private-', dir=runtime_parent))
        os.chmod(runtime_base, 0o700)
        runtime_receipt = root_receipt(runtime_base)
        env = prepare(base, runtime_base, pol, wayland)
        store_receipt = root_receipt(base/'store')
        for path, receipt in ((base, base_receipt), (runtime_base, runtime_receipt), (base/'store', store_receipt)):
            host_id = run_host(['/usr/bin/stat', '-Lc', '%d:%i:%u', str(path)], capture=True).stdout.decode().strip()
            if host_id != ':'.join(map(str, receipt)):
                die('private root is not the same directory on the host')
        info = subprocess.run([str(base / 'bin/podman'), 'info', '--format',
            '{{.Store.GraphRoot}}|{{.Store.RunRoot}}|{{.Store.GraphDriverName}}'], env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=30, check=True).stdout.strip()
        if info != str(base / 'store') + '|' + str(runtime_base / 'runroot') + '|vfs':
            die('Podman did not confirm the private store and vfs driver')
        print('Private acceptance directories:', base, runtime_base, flush=True)
        command = ['/usr/bin/bash', str(base / 'source/tests/parallel.sh')]
        options = {'timeout': 480} if args.wayland else {}
        result, safe, interrupted = supervised_suite(command, env, **options)
        if args.wayland and result == 124:
            print('Wayland smoke timed out.', file=sys.stderr)
        # A killed forwarding bridge cannot prove a host-side command never started late.
        if interrupted and os.environ.get('CONTAINER_ID'):
            safe = False
    finally:
        if env is not None and safe:
            try:
                cleanup(base, runtime_base, env, base_receipt, runtime_receipt, store_receipt)
                clean = True
                print('Private resources and directory removed.')
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                print('Cleanup incomplete; inspect private directories:', base, runtime_base, str(exc), file=sys.stderr)
        else:
            print('Completion could not be verified; retain private directories:', base, runtime_base, file=sys.stderr)
    return result if result else (0 if clean else 1)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print('ABORT:', exc, file=sys.stderr)
        sys.exit(1)
