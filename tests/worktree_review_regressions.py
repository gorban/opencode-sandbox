#!/usr/bin/env python3
"""Deterministic repository replacement and host-Git cwd regressions in private scratch."""
import os, pathlib, subprocess, sys, tempfile

script = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1] / 'oc-sandbox')
source = script.read_text()
start = source.index("SANDBOX_TREE_PY='") + len("SANDBOX_TREE_PY='")
end = source.index("\ninit_sandbox_tree()", start)
program = source[start:end].rstrip()[:-1]

def cmd(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)

failures = []
with tempfile.TemporaryDirectory(prefix='oc-c-review-') as tmp:
    base = pathlib.Path(tmp)
    sb = base / 'worktree-control'
    sb.mkdir()
    repo = sb / 'a'
    cmd('git', 'init', '-q', '-b', 'main', str(repo))
    cmd('git', '-C', str(repo), '-c', 'user.name=test', '-c', 'user.email=test@example.invalid',
        'commit', '--allow-empty', '-qm', 'init')
    cmd('git', '-C', str(repo), 'worktree', 'add', '--relative-paths', '-b', 'feature', str(sb / 'dest'))
    admin = repo / '.git' / 'worktrees' / 'dest'
    worker = [sys.executable, '-c', program.replace('/sandbox', str(sb)), 'init', 'dest', 'a', 'feature']
    for path in (sb / 'dest' / '.git', admin / 'commondir', admin / 'gitdir'):
        original = path.read_bytes()
        path.unlink(); os.mkfifo(path)
        try:
            result = subprocess.run(worker, capture_output=True, text=True, timeout=2)
            if result.returncode == 0 or 'invalid worktree control file' not in result.stderr:
                failures.append('FIFO control was not refused: ' + path.name)
        except subprocess.TimeoutExpired:
            failures.append('worktree control blocked on FIFO: ' + path.name)
        finally:
            path.unlink(); path.write_bytes(original)
    (admin / 'gitdir').write_text('wrong-target\n')
    result = subprocess.run(worker, capture_output=True, text=True, timeout=2)
    if result.returncode == 0:
        failures.append('accepted administrative link to a different worktree')

    if 'tree_run() {' not in source:
        failures.append('worktree worker has no confined and bounded launch path')
    else:
        start_run = source.index('tree_run() {')
        tree_run = source[start_run:source.index('\n}', start_run) + 2]
        fixture = '''
LEVEL=s0:c7,c9; SB=/fixture; AGENT_MEM=512m; AGENT_IMG=fixture; SANDBOX_TREE_PY=stub
timeout() {
  if IFS= read -r line; then printf '%s\\n' 'worktree worker inherited stdin'; fi
  printf '%s\\n' "$@"
}
host_dispatch() { "$@"; }
'''
        first_worker_failure = len(failures)
        for dispatch in ('H=()', 'H=(host_dispatch)'):
            call = tree_run + '\n' + fixture + dispatch + '\ntree_run init dest a feature\n'
            launch = cmd('bash', '-c', call, input='fixture terminal data\n').stdout.splitlines()
            if 'worktree worker inherited stdin' in launch:
                failures.append('worktree worker inherited stdin with ' + dispatch)
                launch.remove('worktree worker inherited stdin')
            if any(arg in launch for arg in ('-i', '--interactive')):
                failures.append('worktree worker requested interactive attachment with ' + dispatch)
            if (launch[:3] != ['-k', '5s', '70s'] or '--timeout=60' not in launch
                    or '--network=none' not in launch or 'label=level:s0:c7,c9' not in launch
                    or 'label=disable' in launch):
                failures.append('unsafe worktree worker launch arguments with ' + dispatch)
        for failure in failures[first_worker_failure:]:
            print('FAIL: ' + failure)
        if len(failures) == first_worker_failure:
            print('PASS: worktree worker launches without terminal input or attachment')

    for swap in ('symlink', 'directory'):
        sb = base / swap; sb.mkdir()
        for name in ('a', 'b'):
            cmd('git', 'init', '-q', '-b', 'main', str(sb / name))
            cmd('git', '-C', str(sb / name), '-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '--allow-empty', '-qm', 'init')
        cmd('git', '-C', str(sb / 'b'), 'worktree', 'add', '--relative-paths', '-b', 'feature', str(sb / 'dest'))
        # Swap after the actual first Git common-dir response; both repos remain private fixtures.
        hook = '''import subprocess, os, sys\noriginal = subprocess.run\ndone = False\ndef injected(*a, **kw):\n global done\n r = original(*a, **kw)\n if not done and "--git-common-dir" in a[0]:\n  done = True\n  os.rename("a", "a-held")\n  if sys.argv[1] == "symlink": os.symlink("b", "a")\n  else:\n   os.rename("b", "a")\n   os.symlink("a", "b")\n return r\nsubprocess.run = injected\nsys.argv = ["tree", "init", "dest", "a", "feature"]\n'''
        worker = hook + program.replace('/sandbox', str(sb))
        result = subprocess.run([sys.executable, '-c', worker, swap], capture_output=True, text=True, cwd=sb)
        if result.returncode == 0:
            failures.append(f'accepted {swap} repository replacement')
            print(f'FAIL: accepted {swap} repository replacement')
        else: print(f'PASS: refused {swap} repository replacement')

    # Preserve inode but change each worktree control file after Git reads the branch.
    for control in ('dotgit', 'commondir'):
        sb = base / ('control-' + control); sb.mkdir()
        for name in ('a', 'b'):
            cmd('git', 'init', '-q', '-b', 'main', str(sb / name))
            cmd('git', '-C', str(sb / name), '-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '--allow-empty', '-qm', 'init')
        cmd('git', '-C', str(sb / 'a'), 'worktree', 'add', '--relative-paths', '-b', 'feature', str(sb / 'dest'))
        cmd('git', '-C', str(sb / 'b'), 'worktree', 'add', '--relative-paths', '-b', 'feature', str(sb / 'otherdest'))
        mutate_hook = """import subprocess, os, sys
original = subprocess.run
def injected(*a, **kw):
 r = original(*a, **kw)
 if 'symbolic-ref' in a[0]:
  if kind == 'dotgit':
   with open('dest/.git', 'w') as f: f.write('gitdir: ../b/.git/worktrees/otherdest\\n')
  else:
   with open('a/.git/worktrees/dest/commondir', 'w') as f: f.write(os.path.abspath('b/.git') + '\\n')
 return r
subprocess.run = injected
kind = sys.argv[1]
sys.argv = ['tree', 'init', 'dest', 'a', 'feature']
"""
        worker = mutate_hook + program.replace('/sandbox', str(sb))
        result = subprocess.run([sys.executable, '-c', worker, control], capture_output=True, text=True, cwd=sb)
        if result.returncode == 0:
            failures.append('accepted in-place ' + control + ' mutation')
            print('FAIL: accepted in-place ' + control + ' mutation')
        else: print('PASS: refused in-place ' + control + ' mutation')

    # Substitute B metadata only while the real worktree-add subprocess is running.
    sb = base / 'aba'; sb.mkdir()
    for name in ('a', 'b'):
        repo = sb / name
        cmd('git', 'init', '-q', '-b', 'main', str(repo))
        (repo / 'origin.txt').write_text(name)
        cmd('git', '-C', str(repo), 'add', 'origin.txt')
        cmd('git', '-C', str(repo), '-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'init')
    aba_hook = """import subprocess, os, sys
original = subprocess.run
def injected(*a, **kw):
 if 'worktree' in a[0] and 'add' in a[0]:
  os.rename('a/.git', 'a/held.git'); os.rename('b/.git', 'a/.git')
  try: return original(*a, **kw)
  finally: os.rename('a/.git', 'b/.git'); os.rename('a/held.git', 'a/.git')
 return original(*a, **kw)
subprocess.run = injected
sys.argv = ['tree', 'init', 'dest', 'a', 'feature']
"""
    worker = aba_hook + program.replace('/sandbox', str(sb))
    result = subprocess.run([sys.executable, '-c', worker], capture_output=True, text=True, cwd=sb)
    wt = sb / 'dest'
    status = subprocess.run(['git', '-C', str(wt), 'status', '--porcelain'], capture_output=True, text=True)
    branch = subprocess.run(['git', '-C', str(wt), 'branch', '--show-current'], capture_output=True, text=True)
    link = (wt / '.git').read_text() if (wt / '.git').is_file() else ''
    actual = (wt / 'origin.txt').read_text() if (wt / 'origin.txt').is_file() else ''
    if result.returncode or actual != 'a' or status.returncode or branch.stdout.strip() != 'feature' or not link.startswith('gitdir: ../a/.git/worktrees/'):
        failures.append('creation ABA did not preserve source identity and portable links')
        print('FAIL: creation ABA source or portable worktree link')
        if result.returncode: print(result.stderr)
    else:
        moved = base / 'moved-aba'
        sb.rename(moved)
        moved_status = subprocess.run(['git', '-C', str(moved / 'dest'), 'status', '--porcelain'], capture_output=True, text=True)
        moved_branch = subprocess.run(['git', '-C', str(moved / 'dest'), 'branch', '--show-current'], capture_output=True, text=True)
        if moved_status.returncode or moved_branch.stdout.strip() != 'feature':
            failures.append('worktree links broke when sandbox moved')
            print('FAIL: relative worktree links after sandbox move')
        else: print('PASS: creation ABA preserves source and portable worktree links')

    # Replace the newly populated destination after actual Git returns.
    sb = base / 'destination-swap'; sb.mkdir(); src = sb / 'a'
    cmd('git', 'init', '-q', '-b', 'main', str(src))
    (src / 'origin.txt').write_text('original')
    cmd('git', '-C', str(src), 'add', 'origin.txt')
    cmd('git', '-C', str(src), '-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'init')
    destination_hook = """import subprocess, os, shutil, sys
original = subprocess.run
def injected(*a, **kw):
 r = original(*a, **kw)
 if 'worktree' in a[0] and 'add' in a[0] and r.returncode == 0:
  os.rename('dest', 'dest-held'); os.mkdir('dest')
  shutil.copyfile('dest-held/.git', 'dest/.git')
  open('dest/evil.txt', 'w').write('replacement')
 return r
subprocess.run = injected
sys.argv = ['tree', 'init', 'dest', 'a', 'feature']
"""
    result = subprocess.run([sys.executable, '-c', destination_hook + program.replace('/sandbox', str(sb))],
                            capture_output=True, text=True, cwd=sb)
    if result.returncode == 0:
        failures.append('accepted replacement destination')
        print('FAIL: accepted replacement destination')
    else: print('PASS: refused replacement destination')

    # Extract the actual host wrapper and attest Git cwd and environment from a stub.
    if 'host_git() {' not in source:
        print('FAIL: host Git wrapper missing')
        failures.append('host Git wrapper missing')
        wrapper = 'host_git() { git "$@"; }'
    else:
        a = source.index('host_git() {'); b = source.index('\n}', a) + 2
        wrapper = source[a:b]
    build = base / 'trusted-build'; build.mkdir()
    poison = base / 'poison'; cmd('git', 'init', '-q', str(poison))
    (poison / '.git' / 'config').write_text('[not-closed\n')
    config = base / 'trusted-config'; config.write_text('[user]\n name = Example\n')
    bad = subprocess.run(['git', 'config', '--file', str(config), '--get', 'user.name'], cwd=poison, capture_output=True)
    if bad.returncode == 0: raise SystemExit('FAIL: poison fixture did not affect unwrapped host Git')
    env = os.environ.copy(); env['BUILD'] = str(build); env['GIT_DIR'] = str(poison / '.git')
    test = wrapper + '\nhost_git config --file "$1" --get user.name\n'
    good = subprocess.run(['bash', '-c', test, 'bash', str(config)], cwd=poison, env=env, capture_output=True, text=True)
    if good.returncode or good.stdout.strip() != 'Example':
        failures.append('host Git inherited hostile cwd or Git environment')
        print('FAIL: host Git inherited hostile cwd or Git environment')
    stub = base / 'bin'; stub.mkdir(); log = base / 'git.log'
    fake = stub / 'git'; fake.write_text('#!/bin/sh\nprintf "%s|%s|%s\\n" "$PWD" "${GIT_DIR-unset}" "$*" >> "$GIT_TEST_LOG"\n'); fake.chmod(0o755)
    # GIT_TEST_LOG is deliberately removed by the wrapper too; pass log via a non-Git variable.
    fake.write_text('#!/bin/sh\nprintf "%s|%s|%s\\n" "$PWD" "${GIT_DIR-unset}" "$*" >> "$OC_TEST_LOG"\n')
    env['PATH'] = str(stub) + os.pathsep + env['PATH']; env['OC_TEST_LOG'] = str(log)
    calls = wrapper + '\nhost_git config --file x --get user.name\nhost_git config --file x core.editor vim\nhost_git clone example destination\n'
    cmd('bash', '-c', calls, cwd=poison, env=env)
    lines = log.read_text().splitlines()
    if len(lines) != 3 or any(not line.startswith(str(build) + '|unset|') for line in lines):
        failures.append('host Git cwd or GIT_DIR was inherited')
        print('FAIL: host Git cwd or GIT_DIR was inherited')
    else: print('PASS: host Git uses trusted cwd and clears Git overrides')
if failures: raise SystemExit(1)
