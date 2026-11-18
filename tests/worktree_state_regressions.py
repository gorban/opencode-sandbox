#!/usr/bin/env python3
"""Scratch-only regressions for host worktree records, locks and selection."""
import os, pathlib, select, subprocess, sys, tempfile

source = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1] / 'oc-sandbox').resolve()
s = source.read_text()
repo = pathlib.Path(__file__).resolve().parents[1]
helper = repo / 'oc-setup-lock.py'

def func(name):
    start = s.index(name + '() {')
    return s[start:s.index('\n}', start) + 2]

def sh(body, cwd, env):
    return subprocess.run(['bash', '-eu', '-o', 'pipefail', '-c', body], cwd=cwd, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def require(label, condition):
    if not condition: raise AssertionError(label)
    print('PASS ' + label)

with tempfile.TemporaryDirectory(prefix='oc-wt-host-') as temp:
    t = pathlib.Path(temp); state = t / 'state'; state.mkdir(); sb = t / 'sandbox'; sb.mkdir()
    sentinel = sb / 'sentinel'; sentinel.write_text('intact')
    (sb / 'second.lock').symlink_to(sentinel)
    (state / 'worktrees').symlink_to(sb, target_is_directory=True)
    start = s.index('# Serialize worktree selection') if '# Serialize worktree selection' in s else s.index('# Serialize each instance')
    if '# Serialize worktree selection' in s:
        end = s.index('release_worktree_lock', start) + len('release_worktree_lock')
    else: end = s.index('exec {wt_fd}>&-', start) + len('exec {wt_fd}>&-')
    functions = '\n'.join(func(n) for n in ('trusted_path', 'trusted_dir'))
    for name in ('trusted_file', 'worktree_state', 'acquire_guard', 'release_worktree_lock'):
        if name + '() {' in s: functions += '\n' + func(name)
    body = '''SB=$TEST_SB; sb_real=$SB; STATE=$TEST_STATE; SCRIPT_DIR=$TEST_REPO; ILABEL=second; INST=second
CALLER_PWD=/; CALLER_PHYSICAL=/; CWD_ARG=x; WT_ARG=; WT_REPO=; WT_BRANCH=; CWD=x
in_sb() { [[ $1/ == "$sb_real"/* ]]; }; die() { echo "$*" >&2; exit 2; }
valid_relpath() { return 0; }; init_sandbox_tree() { :; }
''' + functions + '\n' + s[start:end]
    env = {**os.environ, 'TEST_SB': str(sb), 'TEST_STATE': str(state), 'TEST_REPO': str(repo)}
    result = sh(body, t, env)
    require('symlinked state is refused without touching sandbox sentinel', result.returncode != 0 and sentinel.read_text() == 'intact')
    (state / 'worktrees').unlink()
    if 'worktree_state() {' not in s: raise SystemExit('missing worktree_state implementation')
    wt = state / 'worktrees'; wt.mkdir(mode=0o700)
    state_function = func('worktree_state')
    run = lambda args: sh('STATE=$TEST_STATE\n' + state_function + '\nworktree_state ' + args, t, env)
    outside = t / 'outside'; outside.write_text('intact'); outside.chmod(0o600)
    for kind in ('symlink', 'hardlink'):
        lock = wt / 'second.lock'
        if kind == 'symlink': lock.symlink_to(outside)
        else: os.link(outside, lock)
        result = subprocess.run([sys.executable, '-I', str(helper), str(wt), 'worktree', 'exclusive', 'second', str(os.getpid())],
                                input='', stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        require(kind + ' lock is refused without truncating target', result.returncode != 0 and outside.read_text() == 'intact')
        lock.unlink()
    for kind in ('symlink', 'hardlink', 'mode'):
        record = wt / 'second'
        if kind == 'symlink': record.symlink_to(outside)
        elif kind == 'hardlink': os.link(outside, record)
        else: record.write_text('x\ny\nz\n'); record.chmod(0o644)
        result = run('read second')
        write_result = run('write second x y z')
        require(kind + ' record refused for read and write', result.returncode not in (0, 3) and write_result.returncode != 0 and outside.read_text() == 'intact')
        record.unlink()
    def guard(name):
        return subprocess.Popen([sys.executable, '-I', str(helper), str(wt), 'worktree', 'exclusive', name, str(os.getpid())],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    a = guard('alpha'); b = guard('beta'); c = None
    try:
        require('distinct instance worktree locks proceed concurrently',
                bool(select.select([a.stdout], [], [], 3)[0]) and a.stdout.readline().strip() == 'LOCKED'
                and bool(select.select([b.stdout], [], [], 3)[0]) and b.stdout.readline().strip() == 'LOCKED')
        c = guard('alpha')
        require('same instance worktree lock serializes', not select.select([c.stdout], [], [], .3)[0])
        a.stdin.close(); require('waiting worktree lock acquires after release', bool(select.select([c.stdout], [], [], 3)[0]) and c.stdout.readline().strip() == 'LOCKED')
    finally:
        for process in (a, b, c):
            if process is None: continue
            if process.stdin and not process.stdin.closed: process.stdin.close()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
            if process.stdout: process.stdout.close()
            if process.stderr: process.stderr.close()
    wt.chmod(0o755)
    require('nonprivate worktree directory refused', run('create').returncode != 0)
    wt.chmod(0o700)
    require('private record writes and reads', run('write second wt/a a branch').returncode == 0 and run('read second').stdout == 'wt/a\na\nbranch\n')
    # Startup must reject every derived host directory that leads into $SB,
    # even for -h (which exits before any Podman or systemd call).
    home = t / 'home'; sandbox = home / 'opencode-sandbox'; sandbox.mkdir(parents=True)
    host_state = home / '.local' / 'share' / 'oc-sandbox'; host_state.mkdir(parents=True)
    host_env = {k: v for k, v in os.environ.items() if k not in ('XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'CONTAINER_ID')}
    host_env['HOME'] = str(home)
    for directory in ('build', 'policy', 'bridge-stage'):
        link = host_state / directory; link.symlink_to(sandbox, target_is_directory=True)
        result = subprocess.run(['bash', str(source), '-h'], env=host_env, cwd=t, capture_output=True, text=True)
        require(directory + ' symlink into sandbox is refused before use', result.returncode != 0)
        link.unlink()
