#!/usr/bin/env python3
"""Interrupt harmless workers; no Podman, networking, or broad process signals."""
import fcntl
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[4]
probe = Path(os.environ.get('OC_SPIKE_PROBE', Path(__file__).with_name('probe.sh'))).resolve()
source = probe.read_text()
base = repo / '.scratch'
if base.is_symlink():
    raise RuntimeError('scratch directory must not be a symlink')
base.mkdir(exist_ok=True)
if '# ---- poll worker control' not in source:
    # Replay the reviewed old cleanup with harmless sleep processes. pidfds are opened
    # while the child is alive, so the fixture's final SIGTERM can never hit a reused PID.
    host = next(line for line in source.splitlines() if line.startswith('host()'))
    cleanup = source[source.index('cleanup() {'):source.index('\ntrap ', source.index('cleanup() {'))]
    leaks = []
    with tempfile.TemporaryDirectory(prefix='old-worker.', dir=base) as temp:
        root = Path(temp).resolve()
        proxy = root / 'proxy'
        proxy.write_text('#!/bin/sh\nexec "$@"\n'); proxy.chmod(0o755)
        for label, route in [('native', 'H=()'), ('forwarder', f'H=("{proxy}")')]:
            d = root / label; d.mkdir()
            code = f'''set -u
{route}
BASE_REAL="{d}"; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
pm() {{ echo UNEXPECTED_PODMAN >&2; return 91; }}
''' + host + '\n' + cleanup + '''
host /bin/bash -c 'echo "$BASHPID" >"$1"; exec sleep 30' _ "$BASE_REAL/pid" &
pp=$!
for i in {1..100}; do [[ -s $BASE_REAL/pid ]] && break; sleep 0.01; done
echo READY
for i in {1..500}; do [[ -e $BASE_REAL/go ]] && break; sleep 0.01; done
cleanup; echo CLEANED
'''
            process = subprocess.Popen(['bash'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            process.stdin.write(code); process.stdin.close()
            assert process.stdout.readline().strip() == 'READY'
            pid = int((d / 'pid').read_text())
            fd = os.pidfd_open(pid)
            try:
                (d / 'go').touch()
                assert process.stdout.readline().strip() == 'CLEANED'
                poller = select.poll(); poller.register(fd, select.POLLIN)
                if not poller.poll(0):
                    leaks.append(label)
                    signal.pidfd_send_signal(fd, signal.SIGTERM)
                    assert poller.poll(5000), label
                process.wait(timeout=5)
            finally:
                os.close(fd)
        assert not leaks, f'worker survived old cleanup: {leaks}'
    raise SystemExit(0)
block = source[source.index('# ---- poll worker control'):source.index('# Fail before scratch')]
cleanup = source[source.index('cleanup() {'):source.index('\ntrap ', source.index('cleanup() {'))]
with tempfile.TemporaryDirectory(prefix='worker-test.', dir=base) as temp:
    root = Path(temp).resolve()
    proxy = root / 'forwarder.sh'
    # Deliberately does not exec: killing the forwarding process alone would not stop the child.
    proxy.write_text('#!/bin/sh\n"$@" & child=$!\nwait "$child"\n')
    proxy.chmod(0o755)
    slow_proxy = root / 'slow-forwarder.sh'
    slow_proxy.write_text('#!/bin/sh\n"$@" & child=$!\nwait "$child"\nwhile [ ! -e "$PROXY_FINISH" ]; do sleep 0.05; done\n')
    slow_proxy.chmod(0o755)
    # A proxy deliberately outlives its payload. Losing the recorded job identity
    # must keep IDs and scratch; release only this owned fixture, then retry cleanup.
    kinds = (os.environ['OC_SPIKE_IDENTITY_KIND'],) if os.environ.get('OC_SPIKE_IDENTITY_KIND') else ('starting', 'mismatch', 'nonchild')
    for kind in kinds:
        d = root / ('identity-' + kind); d.mkdir()
        code = f'''set -u -o pipefail
H=("{slow_proxy}")
BASE_REAL="{d}"; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
export PROXY_FINISH="$BASE_REAL/finish"
pm() {{ echo "$*" >>"$BASE_REAL/podman.log"; return 0; }}
die() {{ echo "$*" >&2; exit 2; }}
''' + block + '\n' + cleanup + f'''
printf '%064d\\n' 0 >"$SCR/pod-owned.id"
start_worker fixture "$SCR/output" 127.0.0.1 || exit 3
actual=$pp; actualjob=${{worker_job:-$actual}}
case {kind} in
  starting) pp=starting ;;
  mismatch) pp=99999999 ;;
  nonchild) pp=99999999; worker_job=99999999 ;;
esac
cleanup; first=$?
safe=0
if [[ $first -ne 0 && -f $SCR/pod-owned.id && ! -e $BASE_REAL/podman.log ]] && jobs -pr | grep -Fxq -- "$actual"; then safe=1; fi
touch "$PROXY_FINISH"
if (( safe )); then
  pp=$actual; worker_job=$actualjob
  cleanup || exit 4
  [[ ! -d $SCR ]] || exit 5
else
  wait "$actual" 2>/dev/null || :
  echo 'identity uncertainty was accepted' >&2
  exit 6
fi
'''
        r = subprocess.run(['bash'], input=code, text=True, capture_output=True, timeout=20)
        assert r.returncode == 0, (kind, r.returncode, r.stdout, r.stderr)
    inherited = subprocess.run(['bash'], input='pp=foreign worker_job=foreign\n' + block +
                               '\n[[ -z $pp && -z $worker_job ]]\n', text=True,
                               capture_output=True, timeout=10)
    assert inherited.returncode == 0, 'inherited worker identity was not reset'
    if os.environ.get('OC_SPIKE_IDENTITY_ONLY'):
        print('PASS: 3 unknown-job states and inherited state; owned worker released cleanly')
        raise SystemExit(0)
    routes = [('native', 'H=()'), ('forwarder', f'H=("{proxy}")')]
    if os.environ.get('OC_SPIKE_TEST_REAL_HOST'):
        routes.append(('real-distrobox', 'H=(distrobox-host-exec)'))
    for label, route in routes:
        d = root / label
        d.mkdir()
        code = f'''set -u -o pipefail
{route}
BASE_REAL="{d}"; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
pm() {{ echo 'UNEXPECTED PODMAN' >&2; return 91; }}
die() {{ echo "$*" >&2; exit 2; }}
''' + block + '\n' + cleanup + f'''
trap 'rc=$?; cleanup; c=$?; printf "cleanup=%s\\n" "$c"; (( c == 0 )) || rc=1; exit "$rc"' EXIT
start_worker fixture "$SCR/output" 127.0.0.1 || exit 3
ln "$worker_lock" "$BASE_REAL/oracle.lock"
if flock -n "$BASE_REAL/oracle.lock" true; then echo 'FAIL worker was not alive'; exit 4; fi
printf 'worker started\\n'
exit 17
'''
        r = subprocess.run(['bash'], input=code, text=True, capture_output=True, timeout=45)
        assert r.returncode == 17 and 'cleanup=0' in r.stdout and 'worker started' in r.stdout, (label, r.returncode, r.stdout, r.stderr)
        assert not list(d.glob('probe.*')), (label, list(d.iterdir()))
        with open(d / 'oracle.lock') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # Exercise both production worker bodies with stubbed network commands. Only the
    # deadline is shortened for this fixture, which never connects to a real service.
    fake_net = root / 'fake-net'; fake_net.mkdir()
    fakecurl = fake_net / 'curl'
    fakecurl.write_text('#!/bin/sh\ncase "$*" in *:3000/*) echo "C:3000 from=127.0.0.1";; esac\nexit 0\n')
    fakecurl.chmod(0o755)
    fakess = fake_net / 'ss'; fakess.write_text('#!/bin/sh\nexit 1\n'); fakess.chmod(0o755)
    fast_natural = block.replace('SECONDS+20', 'SECONDS+1').replace('SECONDS+9', 'SECONDS+1')
    natural_routes = routes[:2]
    if os.environ.get('OC_SPIKE_TEST_REAL_HOST'):
        # Host-spawn uses the host environment. Set PATH explicitly so even the real
        # forwarding route runs the fake curl and ss, never the user's services.
        natural_routes.append(('real-distrobox', f'H=(distrobox-host-exec env "PATH={fake_net}:/usr/bin:/bin")'))
    for label, route in natural_routes:
        d = root / (label + '-natural'); d.mkdir()
        code = f'''set -u -o pipefail
{route}
BASE_REAL="{d}"; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
pm() {{ echo 'UNEXPECTED PODMAN' >&2; return 91; }}
die() {{ echo "$*" >&2; exit 2; }}
''' + fast_natural + '\n' + cleanup + '''
start_worker atomic "$SCR/atomic" 127.0.0.1 || exit 3
worker_wait || exit 4
[[ -s $SCR/atomic ]] && ! grep -vE '^[0-9]+ closed ok$' "$SCR/atomic" | grep -q . || exit 5
start_worker dyn "$SCR/dyn" 127.0.0.1 14110 || exit 6
worker_wait || exit 7
[[ -s $SCR/dyn ]] && ! grep -vE '^[0-9]+[.][0-9]+ OK -$' "$SCR/dyn" | grep -q . || exit 8
cleanup || exit 9
'''
        env = {**os.environ, 'PATH': f'{fake_net}:/usr/bin:/bin'}
        r = subprocess.run(['bash'], input=code, text=True, capture_output=True, env=env, timeout=20)
        assert r.returncode == 0, (label, r.returncode, r.stdout, r.stderr)

    # Interrupt each actual poll body while its owned lock is held. In the real
    # distrobox route, explicit PATH keeps curl/ss stubbed on the host as well.
    for label, route in natural_routes:
        for mode in ('atomic', 'dyn'):
            d = root / (label + '-early-' + mode); d.mkdir()
            code = f'''set -u -o pipefail
{route}
BASE_REAL="{d}"; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
pm() {{ echo UNEXPECTED_PODMAN >&2; return 91; }}
die() {{ echo "$*" >&2; exit 2; }}
''' + block + '\n' + cleanup + f'''
trap 'rc=$?; cleanup || rc=1; exit "$rc"' EXIT
start_worker {mode} "$SCR/output" 127.0.0.1 14110 || exit 3
ln "$worker_lock" "$BASE_REAL/oracle.lock"
if flock -n "$BASE_REAL/oracle.lock" true; then exit 4; fi
exit 17
'''
            env = {**os.environ, 'PATH': f'{fake_net}:/usr/bin:/bin'}
            r = subprocess.run(['bash'], input=code, text=True, capture_output=True, env=env, timeout=45)
            assert r.returncode == 17 and not list(d.glob('probe.*')), (label, mode, r.returncode, r.stderr)
            with open(d / 'oracle.lock') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    # A failed worker lock command prevents a receipt. No podman/resource cleanup may occur;
    # retain the scratch and ID files instead of asserting safe cleanup without evidence.
    fakebin = root / 'fakebin'; fakebin.mkdir()
    badflock = fakebin / 'flock'; badflock.write_text('#!/bin/sh\nexit 1\n'); badflock.chmod(0o755)
    fast_block = block.replace('{1..100}', '{1..4}').replace('sleep 0.05', 'sleep 0.01')
    for label, route in routes[:2]:
        d = root / (label + '-failed-exit'); d.mkdir()
        code = f'''set -u -o pipefail
{route}
BASE_REAL="{d}"; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
pm() {{ echo "$*" >>"$BASE_REAL/podman.log"; if [[ $* == 'pod exists '* ]]; then return 0; fi; return 0; }}
die() {{ echo "$*" >&2; exit 2; }}
''' + block + '\n' + cleanup + '''
trap 'rc=$?; cleanup; c=$?; echo "cleanup=$c worker_status=$worker_status"; (( c == 0 )) || rc=1; exit "$rc"' EXIT
printf '%064d\\n' 0 >"$SCR/pod-owned.id"
start_worker fixture_fail "$SCR/output" 127.0.0.1 || exit 3
exit 17
'''
        r = subprocess.run(['bash'], input=code, text=True, capture_output=True, timeout=45)
        assert r.returncode == 17 and 'cleanup=0 worker_status=143' in r.stdout, (label, r.returncode, r.stdout, r.stderr)
        assert 'pod rm -f -t 0 ' in (d / 'podman.log').read_text(), label

    # Job control exposes the stopped-forwarder case: it must not be mistaken
    # for a completed job or passed to an unbounded wait. The only signals go to
    # this shell's verified, still-stopped child job, never a searched PID.
    d = root / 'stopped-forwarder'; d.mkdir()
    quick_jobs = block.replace('{1..300}', '{1..10}').replace('sleep 0.1', 'sleep 0.01')
    code = f'''set -u -o pipefail
set -m
H=("{proxy}")
BASE_REAL="{d}"; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
pm() {{ echo "$*" >>"$BASE_REAL/podman.log"; return 1; }}
die() {{ echo "$*" >&2; exit 2; }}
''' + quick_jobs + '\n' + cleanup + '''
printf '%064d\\n' 0 >"$SCR/pod-owned.id"
start_worker fixture "$SCR/output" 127.0.0.1 || exit 3
jobs -p | grep -Fxq -- "$pp" || exit 4
kill -STOP "$pp" || exit 5
for i in {1..100}; do jobs -ps | grep -Fxq -- "$pp" && break; sleep 0.01; done
jobs -ps | grep -Fxq -- "$pp" || exit 6
cleanup; c=$?
printf "first=%s scratch=%s log=%s pid=%s jobs=%s\n" "$c" "$([[ -f $SCR/pod-owned.id ]] && echo yes || echo no)" "$([[ -e $BASE_REAL/podman.log ]] && echo yes || echo no)" "$pp" "$(jobs -ps)"
[[ $c -ne 0 && -f $SCR/pod-owned.id && ! -e $BASE_REAL/podman.log ]] || exit 7
jobs -ps | grep -Fxq -- "$pp" || exit 8
kill -CONT "$pp" || exit 9
cleanup || exit 10
[[ ! -d $SCR ]] || exit 11
'''
    r = subprocess.run(['bash'], input=code, text=True, capture_output=True, timeout=15)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)

    for label, route in routes[:2]:
        d = root / (label + '-lock-failure'); d.mkdir()
        code = f'''set -u -o pipefail
{route}
BASE_REAL="{d}"; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
pm() {{ echo "$*" >>"$BASE_REAL/podman.log"; return 1; }}
die() {{ echo "$*" >&2; exit 2; }}
''' + block + '\n' + cleanup + f'''
printf '%064d\\n' 0 >"$SCR/pod-owned.id"
start_worker fixture "$SCR/output" 127.0.0.1 || exit 3
old_path=$PATH; PATH="{fakebin}:$PATH"; export PATH
cleanup; first=$?
[[ $first -ne 0 && -f $SCR/pod-owned.id && ! -e $BASE_REAL/podman.log ]] || exit 4
PATH=$old_path; export PATH
cleanup || exit 5
[[ ! -d $SCR ]] || exit 6
'''
        r = subprocess.run(['bash'], input=code, text=True, capture_output=True, timeout=15)
        assert r.returncode == 0, (label, r.stdout, r.stderr)
    for label, route in routes[:2]:
        d = root / (label + '-receipt-failure'); d.mkdir()
        code = f'''set -u -o pipefail
{route}
BASE_REAL="{d}"; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
pm() {{ echo 'UNEXPECTED PODMAN' >&2; return 91; }}
die() {{ echo "$*" >&2; exit 2; }}
''' + fast_block + '\n' + cleanup + '''
start_worker fixture "$SCR/output" 127.0.0.1 || :
cleanup; c=$?
printf 'cleanup=%s retained=%s\\n' "$c" "$([[ -d $SCR ]] && echo yes || echo no)"
[[ -n ${pp:-} ]] && wait "$pp" 2>/dev/null || :
'''
        env = {**os.environ, 'PATH': f'{fakebin}:/usr/bin:/bin'}
        r = subprocess.run(['bash'], input=code, text=True, capture_output=True, env=env, timeout=15)
        assert r.returncode == 0 and 'cleanup=1 retained=yes' in r.stdout and 'UNEXPECTED PODMAN' not in r.stderr, (label, r.stdout, r.stderr)
print(f'PASS: 3 unknown-job states and inherited state; {len(routes)} fixture and {len(natural_routes) * 2} poll-body interruptions, {len(natural_routes) * 2} natural worker runs, 2 failed-worker cleanup, stopped forwarder, 2 lock-failure and 2 missing-receipt retention paths')
