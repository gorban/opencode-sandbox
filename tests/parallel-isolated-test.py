#!/usr/bin/env python3
"""Harmless regressions for the private parallel-test runner; no Podman calls."""
import importlib.util
import ctypes
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

MODULE = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name('parallel-isolated.py')).resolve()
REPO = Path(__file__).resolve().parent.parent


def load():
    spec = importlib.util.spec_from_file_location('runner', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.REPO = REPO
    return module


def empty_mount_host(args, **kwargs):
    out = (str(Path(args[-1]).resolve())+'\n').encode() if args[0] == '/usr/bin/realpath' else b''
    return subprocess.CompletedProcess(args,0,out,b'')


def environment(distro, desktop=False):
    m = load()
    m.fresh_ports = lambda: ['41001', '41002', '41003', '41004']
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)/'home-root'; base.mkdir(mode=0o700)
        runtime_base = Path(td)/'runtime-root'; runtime_base.mkdir(mode=0o700)
        backend, bridge, result = base/'backend', base/'bridge', base/'result'
        backend.write_text('#!/usr/bin/python3\nimport json,os\nopen('+repr(str(result))+',"w").write(json.dumps(dict(os.environ)))\n')
        backend.chmod(0o700)
        bridge.write_text('#!/bin/sh\nexport CONTAINERS_CONF_OVERRIDE=hostbad CONTAINERS_STORAGE_CONF=hostbad REGISTRY_AUTH_FILE=hostbad ANTHROPIC_API_KEY=hostbad\nexec "$@"\n')
        bridge.chmod(0o700)
        m.PODMAN, m.HOST_EXEC = str(backend), str(bridge)
        if distro:
            os.environ['CONTAINER_ID'] = 'test'
        else:
            os.environ.pop('CONTAINER_ID', None)
        wayland = base/'unused-socket' if desktop else None
        with patch.dict(os.environ, {'DISPLAY': ':99', 'WAYLAND_DISPLAY': 'desktop-fixture',
                                     'DBUS_SESSION_BUS_ADDRESS': 'fixture', 'OC_CHROMIUM_MODE': 'wayland'}):
            env = m.prepare(base, runtime_base, 'policy\n', wayland)
        sandbox = base/'home/opencode-sandbox'
        assert sandbox.is_dir() and not sandbox.is_symlink()
        assert sandbox.stat().st_mode & 0o777 == 0o755
        assert (base/'home').stat().st_mode & 0o777 == 0o700
        assert base.stat().st_mode & 0o777 == 0o700
        cmd = [str(base/'bin/distrobox-host-exec'), 'podman'] if distro else [str(base/'bin/podman')]
        # Inject at the actual backend process for native routing as well.
        env.update(CONTAINERS_CONF_OVERRIDE='hostbad', CONTAINERS_STORAGE_CONF='hostbad',
                   REGISTRY_AUTH_FILE='hostbad', ANTHROPIC_API_KEY='hostbad')
        subprocess.run(cmd + ['info'], env=env, check=True)
        got = json.loads(result.read_text())
        assert 'ANTHROPIC_API_KEY' not in got and 'CONTAINERS_CONF_OVERRIDE' not in got
        assert got['CONTAINERS_STORAGE_CONF'] == str(base/'storage.conf')
        assert got['REGISTRY_AUTH_FILE'] == str(base/'auth.json')
        assert (base/'containers.conf').read_text() == '[engine]\nlock_type="file"\ncgroup_manager="cgroupfs"\n'
        assert got['XDG_RUNTIME_DIR'] == str(runtime_base/'xdg')
        assert got['TMPDIR'] == str(runtime_base/'tmp')
        assert 'runroot="'+str(runtime_base/'runroot')+'"' in (base/'storage.conf').read_text()
        assert 'DISPLAY' not in env and 'DBUS_SESSION_BUS_ADDRESS' not in env
        if desktop:
            assert env['OC_CHROMIUM_MODE'] == 'wayland' and env['WAYLAND_DISPLAY'] == wayland.name
            assert (runtime_base/'xdg'/wayland.name).readlink() == wayland
            verify_desktop_smoke(base, backend, env)
        else:
            assert env['OC_CHROMIUM_MODE'] == 'headless' and 'WAYLAND_DISPLAY' not in env
            assert not list((runtime_base/'xdg').iterdir())
        print(('distrobox' if distro else 'native') + ' backend environment isolated')


def verify_desktop_smoke(base, backend, env):
    source = base/'source'
    (source/'oc-sandbox').write_text('#!/bin/sh\ntest "$*" = "-n -K -i ptest1"\n')
    backend.write_text('''#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in --*=*) shift;; *) break;; esac
done
test "$*" = 'exec oc-ptest1-chromium curl -sf --max-time 2 http://127.0.0.1:9222/json/list' || exit 1
printf '%s\\n' '[{"title": "oc ptest1"}]'
''')
    result = subprocess.run(['/usr/bin/bash', str(source/'tests/parallel.sh')], env=env,
                            text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert 'Wayland Chromium and its named DevTools tab verified.' in result.stdout


def headless_preflight():
    m = load()
    m.run_host = empty_mount_host
    with tempfile.TemporaryDirectory() as td:
        with patch.dict(os.environ, {'XDG_RUNTIME_DIR': td, 'WAYLAND_DISPLAY': '/untrusted/socket'}):
            assert m.host_preflight(False) == (Path(td), None)
            try:
                m.host_preflight(True)
            except RuntimeError as error:
                assert 'WAYLAND_DISPLAY' in str(error)
            else:
                raise AssertionError('unsafe explicit Wayland socket accepted')


def child_mode(marker, result):
    m = load()
    code = '''import os,time,sys
open(sys.argv[1]+'.parent',"w").write(str(os.getpid()))
p=os.fork()
if p==0:
 os.setsid()
 open(sys.argv[1],"w").write(str(os.getpid()))
 while True: time.sleep(1)
while True: time.sleep(1)
'''
    if not hasattr(m, 'supervised_suite'):
        # Exercise the old main() with only host/preparation/cleanup replaced by fixtures.
        private = Path(marker).parent/'private'; private.mkdir()
        m.preflight=lambda: 'policy'
        m.host_preflight=lambda: (Path('/unused'), 'wayland-0')
        m.prepare=lambda *args: os.environ.copy()
        m.tempfile.mkdtemp=lambda **kw: str(private)
        m.run_host=lambda *args, **kw: None
        m.cleanup=lambda *args: Path(result).write_text('old cleanup called')
        real_run=subprocess.run
        def fixture_run(cmd, **kw):
            return real_run([sys.executable, '-c', code, marker], **kw)
        m.subprocess.run=fixture_run
        sys.argv=[str(MODULE), '--run']
        m.main()
        return
    rc, safe, _ = m.supervised_suite([sys.executable, '-c', code, marker], os.environ.copy(), grace=1)
    Path(result).write_text(json.dumps([rc, safe]))


def interrupted(sig, distro):
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    with tempfile.TemporaryDirectory() as td:
        marker, result = Path(td)/'pid', Path(td)/'result'
        env=os.environ.copy()
        if distro: env['CONTAINER_ID']='test'
        else: env.pop('CONTAINER_ID',None)
        proc = subprocess.Popen([sys.executable, '-B', __file__, str(MODULE), '--child', str(marker), str(result)],env=env)
        pid = None; worker_fd = None; parent_fd = None
        try:
            for _ in range(100):
                if marker.exists() and marker.read_text():
                    pid = int(marker.read_text()); break
                if proc.poll() is not None: break
                time.sleep(.05)
            assert pid is not None, 'worker did not start'
            worker_fd = os.pidfd_open(pid)
            parent_fd = os.pidfd_open(int(Path(str(marker)+'.parent').read_text()))
            print(('distrobox' if distro else 'native') + ' ' + signal.Signals(sig).name + ' worker started', flush=True)
            os.kill(proc.pid, sig)
            status = proc.wait(timeout=8)
            poll = select.poll(); poll.register(worker_fd, select.POLLIN)
            print('runner status=%s; worker %s' % (status, 'exited' if poll.poll(0) else 'still alive'), flush=True)
            assert status == 0
            rc, safe = json.loads(result.read_text())
            assert rc == 128 + sig and safe
            assert poll.poll(0), 'owned session child survived'
            print(('distrobox' if distro else 'native') + ' ' + signal.Signals(sig).name + ' reaped detached child before cleanup')
        finally:
            if proc.poll() is None:
                proc.kill(); proc.wait()
            for fd in (parent_fd, worker_fd):
                if fd is not None:
                    try: signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError: pass
                    os.close(fd)
            # Reap any fixture parent/child adopted after testing old code.
            for _ in range(30):
                try: adopted, _ = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError: break
                if not adopted: time.sleep(.05)


def images():
    m = load()
    ident = 'a'*64
    calls = []
    with tempfile.TemporaryDirectory() as td:
        base=Path(td)/'home-root'; base.mkdir(mode=0o700); (base/'store').mkdir(mode=0o700)
        runtime_base=Path(td)/'runtime-root'; runtime_base.mkdir(mode=0o700)
        receipts=[m.root_receipt(base),m.root_receipt(runtime_base),m.root_receipt(base/'store')]
        nested=base/'store/mapped-uid-probe'; nested.mkdir(); (nested/'file').write_text('fixture')
        (nested/'file').chmod(0)
        outside=Path(td)/'outside'; outside.write_text('keep')
        (base/'store/link').symlink_to(outside)
        def fake(cmd, **kwargs):
            args=cmd[1:]; calls.append(args); out=''
            if args[:2] == ['pod', 'ps'] and args not in (['pod','ps','-q','--no-trunc'], ['pod','ps','-q']):
                return subprocess.CompletedProcess(cmd, 125, '', 'invalid pod ps arguments')
            if args[:2] == ['images','--no-trunc']:
                out=ident+'|localhost/first:latest\n'+ident+'|localhost/second:latest\n'
            elif args[:2] == ['image','inspect']:
                out='sha256:'+ident+'\n'
            elif args[:2] == ['images','-aq'] and '--no-trunc' in args:
                out=ident+'\n'+ident+'\n'
            elif args[:1] == ['unshare']:
                assert (base/'store').is_dir() and runtime_base.is_dir()
                # Run the fixed fd-relative remover locally on this harmless fixture.
                original_run(args[1:], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if (base/'store').exists():
                    assert m.root_receipt(base/'store') == receipts[2]
                    assert not list((base/'store').iterdir())
                else:
                    # The previous remover deleted the directory; model Podman
                    # recreating it while the unshare command is shutting down.
                    (base/'store').mkdir(mode=0o700)
                # Simulate Podman shutdown recreating ordinary metadata after the child exits.
                (base/'store/storage.lock').write_text('recreated')
                (base/'store/vfs-layers').mkdir()
                (base/'store/vfs-layers/layers.lock').write_text('recreated')
            else: out=''
            return subprocess.CompletedProcess(cmd, 0, out, '')
        original_run=m.subprocess.run
        m.subprocess.run=fake
        m.run_host=empty_mount_host
        try: m.cleanup(base,runtime_base,{},*receipts)
        finally: m.subprocess.run=original_run
        assert len([a for a in calls if a and a[0]=='untag'])==2
        assert len([a for a in calls if a and a[0]=='rmi'])==1
        assert ['pod','ps','-q','--no-trunc'] in calls and ['pod','ps','-q'] in calls
        assert not base.exists() and not runtime_base.exists()
        assert outside.read_text() == 'keep'
        print('multiple image tags untagged and image ID removed once')


def image_cascade():
    for mode in ('cascade', 'rmi_race', 'exists_error', 'rmi_error'):
        m = load(); child='a'*64; parent='b'*64; live={child, parent}; calls=[]
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)/'home-root'; base.mkdir(mode=0o700); (base/'store').mkdir(mode=0o700)
            runtime_base=Path(td)/'runtime-root'; runtime_base.mkdir(mode=0o700)
            receipts=[m.root_receipt(base),m.root_receipt(runtime_base),m.root_receipt(base/'store')]
            def fake(cmd, **kwargs):
                args=cmd[1:]; calls.append(args); code=0; out=''
                if args[:2] == ['images','-aq'] and '--no-trunc' in args:
                    out=child+'\n'+parent+'\n'
                elif args[:2] == ['image','exists']:
                    code=125 if mode == 'exists_error' else (0 if args[2] in live else 1)
                elif args[0] == 'rmi':
                    ident=args[1]
                    if mode == 'rmi_error': code=125
                    elif ident not in live: code=1
                    else:
                        live.clear()
                        if mode == 'rmi_race': code=1
                elif args[0] == 'unshare':
                    assert not live and (base/'store').is_dir() and runtime_base.is_dir()
                    for entry in (base/'store').iterdir():
                        if entry.is_dir() and not entry.is_symlink(): shutil.rmtree(entry)
                        else: entry.unlink()
                return subprocess.CompletedProcess(cmd,code,out,'')
            original_run=m.subprocess.run; m.subprocess.run=fake
            m.run_host=empty_mount_host
            failure=None
            try:
                try: m.cleanup(base,runtime_base,{},*receipts)
                except RuntimeError as exc: failure=str(exc)
            finally: m.subprocess.run=original_run
            if mode in ('cascade', 'rmi_race'):
                assert failure is None and not base.exists() and not runtime_base.exists(), (mode, failure)
                assert ['rmi',parent] not in calls, 'already removed parent was retried'
            else:
                assert failure is not None and base.exists() and runtime_base.exists(), mode
            print('image cleanup '+mode+' handled safely')


def cleanup_guards():
    for mode in ('runtime_identity', 'store_identity', 'external', 'runtime_mount', 'alias_mount', 'unshare_failure'):
        m=load(); calls=[]
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td)
            if mode == 'alias_mount':
                real=parent/'real'; real.mkdir(); alias=parent/'alias'; alias.symlink_to(real, target_is_directory=True)
                parent=alias
            base=parent/'home-root'; base.mkdir(mode=0o700); (base/'store').mkdir(mode=0o700)
            runtime_base=Path(td)/'runtime root'; runtime_base.mkdir(mode=0o700)
            receipts=[m.root_receipt(base),m.root_receipt(runtime_base),m.root_receipt(base/'store')]
            if mode in ('runtime_identity','store_identity'):
                i=1 if mode == 'runtime_identity' else 2
                dev,ino,uid=receipts[i]; receipts[i]=(dev,ino+1,uid)
            def fake(cmd, **kwargs):
                args=cmd[1:]; calls.append(args)
                if args[:2] == ['ps','-aq'] and '--external' in args and mode == 'external':
                    return subprocess.CompletedProcess(cmd,0,'a'*64+'\n','')
                if args[:1] == ['unshare'] and mode == 'unshare_failure':
                    raise subprocess.CalledProcessError(125,cmd)
                return subprocess.CompletedProcess(cmd,0,'','')
            def host(*args,**kw):
                if args[0][0] == '/usr/bin/realpath':
                    return empty_mount_host(*args,**kw)
                if mode in ('runtime_mount', 'alias_mount'):
                    mounted=runtime_base if mode == 'runtime_mount' else base.resolve()/'store'
                    escaped=str(mounted).replace(' ',r'\040')
                    return subprocess.CompletedProcess([],0,('1 1 0:1 / '+escaped+'/nested rw - tmpfs tmpfs rw\n').encode(),b'')
                return subprocess.CompletedProcess([],0,b'',b'')
            old=m.subprocess.run; m.subprocess.run=fake; m.run_host=host
            try:
                try: m.cleanup(base,runtime_base,{},*receipts)
                except (RuntimeError,subprocess.SubprocessError): pass
                else: raise AssertionError(mode+' did not fail closed')
            finally: m.subprocess.run=old
            assert base.exists() and runtime_base.exists() and (base/'store').exists(), mode
            if mode in ('runtime_identity','store_identity'):
                assert not calls, 'identity failure issued Podman command'
            if mode in ('external','runtime_mount','alias_mount'):
                assert not any(a[0]=='unshare' for a in calls), mode
            print('cleanup '+mode+' retained both private roots')


def namespace_mount_guard():
    for mode in ('exact', 'nested', 'alias', 'none'):
        m=load()
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td)
            if mode == 'alias':
                real=parent/'real'; real.mkdir(); alias=parent/'alias'; alias.symlink_to(real, target_is_directory=True)
                parent=alias
            base=parent/'private home'; base.mkdir(mode=0o700); store=base/'store'; store.mkdir(mode=0o700)
            runtime_base=Path(td)/'runtime'; runtime_base.mkdir(mode=0o700)
            sentinel=store/'sentinel'; sentinel.write_text('untouched')
            receipts=[m.root_receipt(base),m.root_receipt(runtime_base),m.root_receipt(store)]
            mountinfo=Path(td)/'synthetic-mountinfo'
            mountpoint=str(store.resolve()) + ('/nested path' if mode == 'nested' else '')
            if mode == 'none': mountpoint='/unrelated'
            mountpoint=mountpoint.replace(' ',r'\040')
            mountinfo.write_text('1 1 0:1 / '+mountpoint+' rw - tmpfs tmpfs rw\n')
            original_run=m.subprocess.run
            def fake(cmd, **kwargs):
                args=cmd[1:]
                if args[:1] == ['unshare']:
                    script=args[4]
                    assert script.count('"/proc/self/mountinfo"') == 1
                    script=script.replace('"/proc/self/mountinfo"',repr(str(mountinfo)))
                    p=original_run([args[1],args[2],args[3],script,*args[5:]],
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    if p.returncode: raise subprocess.CalledProcessError(p.returncode,cmd,stderr=p.stderr)
                return subprocess.CompletedProcess(cmd,0,'','')
            m.subprocess.run=fake
            m.run_host=empty_mount_host
            try:
                try: m.cleanup(base,runtime_base,{},*receipts)
                except subprocess.CalledProcessError:
                    assert mode != 'none' and sentinel.read_text() == 'untouched'
                    assert base.exists() and runtime_base.exists()
                else:
                    assert mode == 'none' and not base.exists() and not runtime_base.exists()
            finally: m.subprocess.run=original_run
            print('user namespace mount guard '+mode+' verified')


def bootstrap_git():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td); binary = base/'bin'; binary.mkdir(); temp = base/'tmp'; temp.mkdir()
        fake = binary/'git'
        fake.write_text('''#!/bin/sh
test "$1" = -C || exit 128
repo=$2; shift 2
case "$*" in
  "init -q") mkdir "$repo/.git";;
  "worktree add -h") echo '    --[no-]relative-paths   use relative paths for worktrees'; exit 129;;
  "-c user.name=Test -c user.email=test@example.invalid -c core.hooksPath=/dev/null commit --allow-empty -qm init") test -d "$repo/.git";;
  "-c core.hooksPath=/dev/null worktree add -q --relative-paths -b oc-test "*)
    test "${GIT_FIXTURE_MODE:-ok}" != unsupported || exit 129
    mkdir "$9" || exit 1
    if test "${GIT_FIXTURE_MODE:-ok}" = absolute; then echo 'gitdir: /absolute/location' > "$9/.git"
    else echo 'gitdir: ../repo/.git/worktrees/wt' > "$9/.git"; fi;;
  *) exit 1;;
esac
''')
        fake.chmod(0o700)
        line = next(line for line in (REPO/'tests/parallel.sh').read_text().splitlines()
                    if "could not verify bootstrap Git relative-worktree support" in line)
        parts = shlex.split(line); command = parts[parts.index('inbox') + 1]
        env = {'PATH':str(binary)+':/usr/bin:/bin', 'TMPDIR':str(temp), 'HOME':str(base)}
        repo=base/'old-repo'; repo.mkdir(); (repo/'.git').mkdir()
        old = subprocess.run(['/bin/sh','-c',
            'help=$(git -C "$1" worktree add -h 2>&1) || exit 1; printf "%s\\n" "$help" | grep -q -- relative-paths',
            'sh', str(repo)], env=env)
        assert old.returncode != 0, 'old help-status check unexpectedly succeeded'
        for mode, expected in (('ok', 0), ('unsupported', 1), ('absolute', 1)):
            new = subprocess.run(['/bin/sh','-c',command], env={**env, 'GIT_FIXTURE_MODE':mode})
            assert (new.returncode == 0) == (expected == 0), mode
        # Exercise the same command with the host Git in a trusted scratch HOME.
        actual = subprocess.run(['/bin/sh','-c',command], env={**env, 'PATH':'/usr/bin:/bin',
            'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':'/dev/null'}, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert actual.returncode == 0, 'host Git failed the functional relative-worktree check'
        assert not list(temp.iterdir()), 'temporary Git repository remains'
        print('bootstrap Git capability checked in a cleaned temporary repository')


def interruption_cleanup(distro, *, smoke_timeout=False):
    m = load()
    with tempfile.TemporaryDirectory() as td:
        base=Path(td)/'private'; base.mkdir(); calls=[]
        runtime_base=Path(td)/'runtime-private'; runtime_base.mkdir()
        m.preflight=lambda: 'policy'
        m.require_clean_legacy_account=lambda: None
        m.host_preflight=lambda desktop: (Path(td), Path(td)/'unused' if desktop else None)
        def prepare_fixture(*args):
            (base/'store').mkdir(mode=0o700)
            return {}
        m.prepare=prepare_fixture
        old_mkdtemp=m.tempfile.mkdtemp; old_run=m.subprocess.run
        roots=iter((str(base),str(runtime_base)))
        m.tempfile.mkdtemp=lambda **kw: next(roots)
        def host_fixture(args, **kw):
            info=Path(args[-1]).stat()
            return subprocess.CompletedProcess(args,0,('%s:%s:%s' % (info.st_dev,info.st_ino,info.st_uid)).encode(),b'')
        m.run_host=host_fixture
        real_supervise = m.supervised_suite

        def timeout_fixture(_command, _env, *, timeout):
            assert timeout == 480
            child = [sys.executable, '-IB', '-c', 'import time; time.sleep(30)']
            return real_supervise(child, os.environ.copy(), timeout=.05, grace=1)

        m.supervised_suite = timeout_fixture if smoke_timeout else lambda *a, **kw: (143, True, True)
        m.cleanup=lambda *a: calls.append('cleanup')
        m.subprocess.run=lambda *a,**kw: subprocess.CompletedProcess([],0,str(base/'store')+'|'+str(runtime_base/'runroot')+'|vfs','')
        old_argv=sys.argv; old_container=os.environ.get('CONTAINER_ID')
        try:
            sys.argv = ['runner', '--run', '--wayland'] if smoke_timeout else ['runner', '--run']
            if distro: os.environ['CONTAINER_ID']='test'
            else: os.environ.pop('CONTAINER_ID',None)
            rc=m.main()
            assert calls == ([] if distro else ['cleanup'])
            assert rc == (124 if smoke_timeout else 143)
            assert base.is_dir() and runtime_base.is_dir()
            reason = 'Wayland timeout' if smoke_timeout else 'interruption'
            print(('distrobox retains store' if distro else 'native cleans store') + f' after {reason}')
        finally:
            sys.argv=old_argv
            m.tempfile.mkdtemp=old_mkdtemp; m.subprocess.run=old_run
            if old_container is None: os.environ.pop('CONTAINER_ID',None)
            else: os.environ['CONTAINER_ID']=old_container


if '--child' in sys.argv:
    i=sys.argv.index('--child'); child_mode(sys.argv[i+1],sys.argv[i+2]); sys.exit(0)
case = sys.argv[2] if len(sys.argv) > 2 else 'all'
if case in ('all', 'native'): environment(False)
if case in ('all', 'distrobox'): environment(True)
if case in ('all', 'desktop'): environment(False, desktop=True)
if case in ('all', 'headless_preflight'): headless_preflight()
if case in ('all', 'sigint'):
    for route in (False, True): interrupted(signal.SIGINT, route)
if case in ('all', 'sigterm'):
    for route in (False, True): interrupted(signal.SIGTERM, route)
if case in ('sigint_native', 'sigint_distrobox'): interrupted(signal.SIGINT, case.endswith('distrobox'))
if case in ('sigterm_native', 'sigterm_distrobox'): interrupted(signal.SIGTERM, case.endswith('distrobox'))
if case in ('all', 'images'): images()
if case in ('all', 'cascade'): image_cascade()
if case in ('all', 'guards'): cleanup_guards()
if case in ('all', 'namespace_mount'): namespace_mount_guard()
if case in ('all', 'bootstrap'): bootstrap_git()
if case in ('all', 'retention'):
    for route in (False, True): interruption_cleanup(route)
if case in ('all', 'wayland_timeout'):
    for route in (False, True): interruption_cleanup(route, smoke_timeout=True)
