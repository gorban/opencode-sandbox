#!/usr/bin/env python3
"""Offline tests of lock, updater and agent guard; no Podman or real state."""
import hashlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('oc_update', ROOT/'oc-opencode-update.py')
update = importlib.util.module_from_spec(spec); spec.loader.exec_module(update)


class LockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.state = Path(self.tmp.name)/'state'
        self.state.mkdir(mode=0o700); self.procs = []
    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                if p.stdin and not p.stdin.closed: p.stdin.close()
                try: p.wait(timeout=3)
                except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=3)
            if p.stdin and not p.stdin.closed: p.stdin.close()
            if p.stdout: p.stdout.close()
            if p.stderr: p.stderr.close()
        self.tmp.cleanup()
    def guard(self, name='setup', mode='exclusive', instance='alpha'):
        helper = os.environ.get('OC_TEST_LOCK_HELPER', str(ROOT/'oc-setup-lock.py'))
        p = subprocess.Popen([sys.executable, '-I', helper, str(self.state),
                              name, mode, instance, str(os.getpid())], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.procs.append(p); return p
    def acquired(self, p):
        self.assertTrue(select.select([p.stdout], [], [], 3)[0], 'guard did not respond')
        self.assertEqual(p.stdout.readline().strip(), 'LOCKED')
    def blocked(self, p): self.assertFalse(select.select([p.stdout], [], [], .3)[0], 'guard unexpectedly responded')
    def release(self, p): p.stdin.close(); self.assertEqual(p.wait(timeout=3),0)
    def test_setup_serializes_and_reports_holder(self):
        a=self.guard(instance='first'); self.acquired(a)
        b=self.guard(instance='second'); self.blocked(b)
        self.assertTrue(select.select([b.stderr], [], [], 3)[0])
        self.assertIn('instance=first', b.stderr.readline())
        self.release(a); self.acquired(b); self.release(b)
    def test_holder_diagnostic_on_checkout_and_tmpfs(self):
        for directory in (ROOT, Path('/dev/shm')):
            if not directory.is_dir() or not os.access(directory, os.W_OK):
                continue
            with self.subTest(directory=str(directory)), tempfile.TemporaryDirectory(prefix='oc-lock-test-', dir=directory) as temp:
                old_state = self.state; self.state = Path(temp)
                try:
                    a=self.guard(instance='first'); self.acquired(a)
                    b=self.guard(instance='second')
                    self.assertTrue(select.select([b.stderr], [], [], 3)[0])
                    self.assertIn(f'pid={os.getpid()} instance=first', b.stderr.readline())
                    self.release(a); self.acquired(b); self.release(b)
                finally:
                    self.state = old_state
    def test_wrong_or_stale_guard_metadata_reports_unknown(self):
        for pid in (os.getpid(), 99999999):
            with self.subTest(pid=pid):
                a=self.guard(instance='first'); self.acquired(a)
                (self.state/'setup.lock').write_text(f'pid={os.getpid()} instance=first guard={pid}\n')
                b=self.guard(instance='second')
                self.assertTrue(select.select([b.stderr], [], [], 3)[0])
                self.assertIn('holder unknown', b.stderr.readline())
                self.release(a); self.acquired(b); self.release(b)
    def test_holder_diagnostic_denied_proc_access_is_unknown(self):
        spec = importlib.util.spec_from_file_location('oc_guard_diagnostic', ROOT/'oc-setup-lock.py')
        guard = importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)
        with patch.object(guard.os, 'stat', side_effect=PermissionError):
            self.assertFalse(guard.guard_holds_lock(os.getpid(), SimpleNamespace(st_dev=1, st_ino=1)))
    def test_lifecycle_shared_parallel_and_exclusive_teardown_waits(self):
        a=self.guard('lifecycle','shared','one'); b=self.guard('lifecycle','shared','two')
        self.acquired(a); self.acquired(b)
        d=self.guard('lifecycle','exclusive','delete'); self.blocked(d)
        self.release(a); self.blocked(d); self.release(b); self.acquired(d); self.release(d)
    def test_killed_holder_releases_kernel_lock(self):
        a=self.guard(); self.acquired(a); b=self.guard(instance='next'); self.blocked(b)
        a.kill(); a.wait(timeout=3); self.acquired(b); self.release(b)
    def test_parent_death_releases_even_if_pipe_is_inherited(self):
        marker=Path(self.tmp.name)/'grandchild'
        code = r'''import os, pathlib, subprocess, sys
p=subprocess.Popen([sys.executable,'-I',sys.argv[1],sys.argv[2],'lifecycle','shared','parent',str(os.getpid())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
assert p.stdout.readline().strip()=='LOCKED'
c=subprocess.Popen(['/bin/sleep','30'],pass_fds=(p.stdin.fileno(),),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
pathlib.Path(sys.argv[3]).write_text(str(c.pid))
os._exit(0)'''
        owner=subprocess.run([sys.executable,'-I','-c',code,str(ROOT/'oc-setup-lock.py'),str(self.state),str(marker)],
                             stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=5)
        self.assertEqual(owner.returncode,0,owner.stderr); child=int(marker.read_text())
        try:
            waiter=self.guard('lifecycle','exclusive','after-parent'); self.acquired(waiter); self.release(waiter)
        finally:
            try: os.kill(child,signal.SIGTERM)
            except ProcessLookupError: pass
    def test_bash_guard_fds_do_not_reach_stub_grandchild(self):
        source=(ROOT/'oc-sandbox').read_text()
        match=re.search(r'(?ms)^acquire_guard\(\) \{.*?^\}',source)
        self.assertIsNotNone(match)
        marker=Path(self.tmp.name)/'child-check'; childpid=Path(self.tmp.name)/'child-pid'
        childcode = r'''import os,pathlib,sys,time
links=[]
for fd in os.listdir('/proc/self/fd'):
 try: links.append(os.readlink('/proc/self/fd/'+fd))
 except OSError: pass
pathlib.Path(sys.argv[3]).write_text('leaked' if sys.argv[1] in links or sys.argv[2] in links else 'closed')
time.sleep(30)'''
        owner = match.group(0)+r'''
STATE=$1; SCRIPT_DIR=$2; ILABEL=test
 die() { echo "$*" >&2; exit 1; }
 trusted_file() { printf '%s\n' "$1"; }
acquire_guard lifecycle shared
acquire_guard setup exclusive
link1=$(readlink "/proc/$$/fd/$LIFECYCLE_LOCK_FD")
link2=$(readlink "/proc/$$/fd/$SETUP_LOCK_FD")
python3 -I -c "$3" "$link1" "$link2" "$4" </dev/null >/dev/null 2>&1 &
echo "$!" > "$5"
for i in $(seq 1 100); do [ -s "$4" ] && break; sleep .02; done
[ -s "$4" ] || exit 1
'''
        env={**os.environ,'HOME':self.tmp.name}
        result=subprocess.run(['bash','-c',owner,'test',str(self.state),str(ROOT),childcode,str(marker),str(childpid)],
                              env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=8)
        self.assertEqual(result.returncode,0,result.stderr); child=int(childpid.read_text())
        try:
            self.assertEqual(marker.read_text(),'closed')
            waiter=self.guard('lifecycle','exclusive','after-bash'); self.acquired(waiter)
            setup=self.guard('setup','exclusive','after-bash'); self.acquired(setup)
            self.release(setup); self.release(waiter)
        finally:
            try: os.kill(child,signal.SIGTERM)
            except ProcessLookupError: pass
    def test_refuses_wrong_owner_for_directory_or_lock(self):
        spec = importlib.util.spec_from_file_location('oc_guard', ROOT/'oc-setup-lock.py')
        guard = importlib.util.module_from_spec(spec); spec.loader.exec_module(guard)
        real_fstat = os.fstat
        for wrong_directory in (True, False):
            def fake_fstat(fd):
                st=real_fstat(fd)
                if stat.S_ISDIR(st.st_mode) == wrong_directory:
                    return SimpleNamespace(st_uid=st.st_uid+1, st_mode=st.st_mode,
                                           st_nlink=st.st_nlink, st_dev=st.st_dev, st_ino=st.st_ino)
                return st
            argv=['oc-setup-lock.py',str(self.state),'setup','exclusive','test',str(os.getpid())]
            with patch.object(sys, 'argv', argv), patch.object(guard.os, 'fstat', side_effect=fake_fstat):
                with self.assertRaises(ValueError): guard.main()
    def test_replaced_lock_inode_is_refused_after_wait(self):
        a=self.guard(); self.acquired(a); b=self.guard(instance='waiting'); self.blocked(b)
        replacement=self.state/'replacement'; replacement.touch(mode=0o600); replacement.chmod(0o600)
        os.replace(replacement,self.state/'setup.lock')
        self.release(a); self.assertNotEqual(b.wait(timeout=3),0)
    def test_refuses_symlink_without_touching_target(self):
        victim=Path(self.tmp.name)/'victim'; victim.write_text('safe')
        (self.state/'setup.lock').symlink_to(victim)
        p=self.guard(); self.assertNotEqual(p.wait(timeout=3),0); self.assertEqual(victim.read_text(),'safe')
    def test_refuses_hardlink_and_unsafe_mode(self):
        victim=Path(self.tmp.name)/'victim'; victim.write_text('safe'); victim.chmod(0o600)
        os.link(victim,self.state/'setup.lock'); p=self.guard(); self.assertNotEqual(p.wait(timeout=3),0)
        (self.state/'setup.lock').unlink(); victim.unlink()
        (self.state/'setup.lock').touch(mode=0o644); (self.state/'setup.lock').chmod(0o644)
        p=self.guard(); self.assertNotEqual(p.wait(timeout=3),0)


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.home=Path(self.tmp.name)/'home'; self.home.mkdir()
        self.bin=self.home/'.opencode'/'bin'; self.bin.mkdir(parents=True)
        self.live=self.bin/'opencode'; self.live.write_bytes(b'old binary'); self.live.chmod(0o755)
    def tearDown(self): self.tmp.cleanup()
    def snapshot(self):
        out=io.BytesIO(); update.snapshot(self.home,out); return io.BytesIO(out.getvalue())
    def runner(self, new=b'new binary', version='2.3.0'):
        calls=[]
        def fake(args,env,timeout):
            calls.append((args,timeout))
            if 'upgrade' in args:
                (Path(env['HOME'])/'.opencode/bin/opencode').write_bytes(new)
                return ''
            if args[-1]=='--version': return version
            raise AssertionError(args)
        return fake,calls
    def stage(self, runner, pin=''):
        out=io.BytesIO(); update.stage(self.snapshot(),pin,out,runner); return out.getvalue()
    def test_version_output_is_not_trimmed_by_real_runner(self):
        script=Path(self.tmp.name)/'version'; script.write_text('#!/bin/sh\nprintf "opencode v2.3.0\\n\\n"\n'); script.chmod(0o755)
        self.assertEqual(update.run([str(script)],os.environ,10),'opencode v2.3.0\n\n')
    def test_branded_versions_select_upgrade_path_and_frame(self):
        for old in ('opencode v1.19.2\n','opencode v2.2.0\n','1.19.2\n','v2.2.0\n'):
            with self.subTest(old=old):
                calls=[]
                def fake(args,env,timeout):
                    calls.append(args); candidate=Path(env['HOME'])/'.opencode/bin/opencode'
                    if 'upgrade' in args: candidate.write_bytes(b'new binary'); return ''
                    if args[-1]=='--version': return old if candidate.read_bytes()==b'old binary' else 'opencode v2.3.0\n'
                    raise AssertionError(args)
                frame=self.stage(fake)
                upgrade=next(args for args in calls if 'upgrade' in args)
                self.assertEqual('--major' in upgrade, '1.19.2' in old)
                header=json.loads(frame[len(update.MAGIC):].split(b'\n',1)[0])
                self.assertEqual(header['version'],'v2.3.0')
                update.promote(self.home,io.BytesIO(frame))
                self.assertEqual(self.live.read_bytes(),b'new binary')
                self.live.write_bytes(b'old binary')
    def test_rejects_extra_or_control_version_output_in_both_phases(self):
        bad_outputs=('prefix opencode v2.3.0\n','opencode v2.3.0 trailing\n',
                     'warning\nopencode v2.3.0\n','opencode v2.3.0\nextra\n',
                     'opencode v2.3.0\n\n','opencode v2.3.0\r\n',
                     'opencode v2.3.0\x00\n',' opencode v2.3.0\n')
        for invalid in bad_outputs:
            for phase in ('old','new'):
                with self.subTest(output=repr(invalid),phase=phase):
                    def fake(args,env,timeout):
                        candidate=Path(env['HOME'])/'.opencode/bin/opencode'
                        if 'upgrade' in args: candidate.write_bytes(b'new binary'); return ''
                        if args[-1]=='--version':
                            is_old=candidate.read_bytes()==b'old binary'
                            return invalid if is_old == (phase=='old') else 'opencode v2.3.0\n'
                        raise AssertionError(args)
                    out=io.BytesIO()
                    with self.assertRaises(ValueError): update.stage(self.snapshot(),'2.3.0',out,fake)
                    self.assertEqual(out.getvalue(),b''); self.assertEqual(self.live.read_bytes(),b'old binary')
    def test_stages_then_promotes_atomically_and_honours_pin(self):
        fake,calls=self.runner(version='opencode v2.3.0\n'); frame=self.stage(fake,'2.3.0')
        self.assertEqual(self.live.read_bytes(),b'old binary')
        self.assertEqual(next(args for args,_ in calls if 'upgrade' in args)[1:],['upgrade','2.3.0','--method','curl'])
        update.promote(self.home,io.BytesIO(frame)); self.assertEqual(self.live.read_bytes(),b'new binary')
    def test_offline_and_timeout_do_not_modify_live_binary(self):
        for exc in (RuntimeError('offline'),subprocess.TimeoutExpired('updater',1)):
            out=io.BytesIO()
            def fail(*args): raise exc
            with self.assertRaises(type(exc)): update.stage(self.snapshot(),'',out,fail)
            self.assertEqual(out.getvalue(),b''); self.assertEqual(self.live.read_bytes(),b'old binary')
    def test_wrong_pin_and_incomplete_or_corrupt_frame_do_not_promote(self):
        fake,_=self.runner(version='2.3.1'); out=io.BytesIO()
        with self.assertRaises(ValueError): update.stage(self.snapshot(),'2.3.0',out,fake)
        self.assertEqual(out.getvalue(),b''); self.assertEqual(self.live.read_bytes(),b'old binary')
        fake,_=self.runner(); frame=self.stage(fake)
        for bad in (frame[:-1],frame[:-len(update.END)]+b'bad'):
            with self.assertRaises(ValueError): update.promote(self.home,io.BytesIO(bad))
            self.assertEqual(self.live.read_bytes(),b'old binary')
    def test_concurrent_binary_change_is_not_overwritten(self):
        fake,_=self.runner(); frame=self.stage(fake)
        self.live.write_bytes(b'another update')
        with self.assertRaises(ValueError): update.promote(self.home,io.BytesIO(frame))
        self.assertEqual(self.live.read_bytes(),b'another update')
    def test_up_to_date_still_checks_each_time_and_sends_no_update(self):
        fake,calls=self.runner(new=b'old binary')
        self.assertEqual(self.stage(fake),b''); self.assertEqual(self.stage(fake),b'')
        self.assertEqual(sum('upgrade' in args for args,_ in calls),2)
    def test_unpinned_legacy_version_requests_major_upgrade(self):
        calls=[]
        def fake(args,env,timeout):
            calls.append(args)
            candidate=Path(env['HOME'])/'.opencode/bin/opencode'
            if 'upgrade' in args:
                if '--major' in args: candidate.write_bytes(b'version two')
                return ''
            if args[-1]=='--version':
                return '1.19.2' if candidate.read_bytes() == b'old binary' else '2.3.0'
            raise AssertionError(args)
        frame=self.stage(fake)
        self.assertTrue(frame)
        self.assertIn('--major', next(args for args in calls if 'upgrade' in args))
        update.promote(self.home,io.BytesIO(frame))
        self.assertEqual(self.live.read_bytes(),b'version two')
    def test_legacy_to_v2_pin_uses_versioned_v2_installer(self):
        calls=[]
        def fake(args,env,timeout):
            calls.append(args)
            candidate=Path(env['HOME'])/'.opencode/bin/opencode'
            if args[0]=='curl': Path(args[args.index('-o')+1]).write_text('fixture'); return ''
            if args[0]=='bash': candidate.write_bytes(b'version two'); return ''
            if args[-1]=='--version': return 'opencode v1.19.2\n' if candidate.read_bytes()==b'old binary' else 'opencode v2.3.0\n'
            raise AssertionError(args)
        frame=self.stage(fake,'2.3.0')
        self.assertEqual(next(a for a in calls if a[0]=='bash')[-3:],['--no-modify-path','--version','2.3.0'])
        update.promote(self.home,io.BytesIO(frame)); self.assertEqual(self.live.read_bytes(),b'version two')
    def test_symlinked_binary_never_reaches_target(self):
        victim=Path(self.tmp.name)/'victim'; victim.write_bytes(b'untouched'); victim.chmod(0o755)
        self.live.unlink(); self.live.symlink_to(victim)
        with self.assertRaises(OSError): self.snapshot()
        self.assertEqual(victim.read_bytes(),b'untouched')
    def test_snapshot_never_forwards_other_shared_home_files(self):
        secret=self.home/'auth'; secret.write_bytes(b'PRIVATE-TEST-CREDENTIAL')
        source=self.snapshot().getvalue()
        self.assertNotIn(b'PRIVATE-TEST-CREDENTIAL',source)
        self.assertEqual(update.read_snapshot(io.BytesIO(source)),b'old binary')
    def test_first_install_uses_official_pinned_installer_in_staging(self):
        self.live.unlink(); source=self.snapshot(); calls=[]
        def fake(args,env,timeout):
            calls.append(args)
            if args[0]=='curl': Path(args[args.index('-o')+1]).write_text('fixture installer'); return ''
            if args[0]=='bash':
                candidate=Path(env['HOME'])/'.opencode/bin/opencode'
                candidate.write_bytes(b'first install'); candidate.chmod(0o755); return ''
            if args[-1]=='--version': return 'opencode v2.3.0\n'
            raise AssertionError(args)
        frame=io.BytesIO(); update.stage(source,'2.3.0',frame,fake)
        self.assertFalse(self.live.exists())
        self.assertEqual(calls[0][-1],'https://opencode.ai/v2/install')
        self.assertEqual(calls[1][-3:],['--no-modify-path','--version','2.3.0'])
        update.promote(self.home,io.BytesIO(frame.getvalue()))
        self.assertEqual(self.live.read_bytes(),b'first install')


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.base=Path(self.tmp.name)
        self.state=self.base/'state'; self.state.mkdir(mode=0o700)
        self.db=self.base/'db'; self.db.mkdir(); self.bin=self.base/'bin'; self.bin.mkdir()
        self.log=self.base/'podman.log'
        stub=self.bin/'podman'
        stub.write_text('''#!/usr/bin/python3
import hashlib,json,os,pathlib,sys,time
args=sys.argv[1:]; db=pathlib.Path(os.environ['FAKE_DB']); log=pathlib.Path(os.environ['FAKE_LOG'])
with log.open('a') as f: f.write(json.dumps(args)+'\\n')
if args[0]=='create':
 phase=args[-1]; ident=hashlib.sha256(phase.encode()).hexdigest()
 if os.environ.get('FAKE_NO_RECEIPT')==phase: sys.exit(125)
 token=next(a.split('=',2)[-1] for a in args if a.startswith('io.github.gorban.opencode-sandbox.update='))
 (db/ident).write_text(json.dumps({'phase':phase,'token':token}))
 pathlib.Path(args[args.index('--cidfile')+1]).write_text(ident)
 print(ident); sys.exit(0)
if args[0]=='start':
 ident=args[-1]; state=json.loads((db/ident).read_text()); phase=state['phase']
 if os.environ.get('FAKE_HANG')==phase: time.sleep(30)
 if os.environ.get('FAKE_FAIL')==phase: sys.exit(4)
 if phase=='snapshot': sys.stdout.buffer.write(b'snapshot')
 elif phase=='stage': sys.stdin.buffer.read(); sys.stdout.buffer.write(b'candidate')
 else: sys.stdin.buffer.read()
 sys.exit(0)
if args[:2]==['container','exists']:
 if os.environ.get('FAKE_EXISTS_ERROR')=='1': sys.exit(125)
 sys.exit(0 if (db/args[-1]).exists() else 1)
if args[:2]==['container','inspect']:
 ident=args[-1]; state=json.loads((db/ident).read_text()); token=state['token']
 if os.environ.get('FAKE_WRONG_OWNER')=='1': token='foreign'
 print(ident,token); sys.exit(0)
if args[0]=='rm':
 (db/args[-1]).unlink(missing_ok=True); sys.exit(0)
sys.exit(125)
'''); stub.chmod(0o755)
        self.env={**os.environ,'HOME':self.tmp.name,'PATH':str(self.bin)+':/usr/bin:/bin',
                  'FAKE_DB':str(self.db),'FAKE_LOG':str(self.log)}
    def tearDown(self): self.tmp.cleanup()
    def invoke(self, **extra):
        return subprocess.run([sys.executable,'-I',str(ROOT/'oc-opencode-supervisor.py'),str(self.state),
                               's0:c1,c2','oc-home','oc-agent','4g','2.3.0'],
                              env={**self.env,**extra},stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=15)
    def actions(self):
        import json
        return [json.loads(x) for x in self.log.read_text().splitlines()]
    def test_each_guest_removed_before_next_phase_and_no_mount_on_network_stage(self):
        p=self.invoke(); self.assertEqual(p.returncode,0,p.stderr)
        acts=self.actions(); create=[x for x in acts if x[0]=='create']; self.assertEqual([x[-1] for x in create],['snapshot','stage','promote'])
        self.assertIn('--network=none',create[0]); self.assertIn('oc-home:/source:ro',create[0]); self.assertNotIn('-v',create[1]); self.assertIn('--http-proxy=false',create[1]); self.assertIn('--network=none',create[2]); self.assertIn('oc-home:/root',create[2])
        for i,entry in enumerate(acts):
            if entry[0]=='create' and entry[-1] in ('stage','promote'):
                self.assertIn('rm',[a[0] for a in acts[:i]])
                self.assertEqual(sum(a[0]=='rm' for a in acts[:i]),1 if entry[-1]=='stage' else 2)
        self.assertEqual(list(self.db.iterdir()),[]); self.assertEqual(list(self.state.iterdir()),[])
    def test_failed_stage_never_starts_writer_and_cleans_receipts(self):
        p=self.invoke(FAKE_FAIL='stage'); self.assertEqual(p.returncode,1,p.stderr)
        self.assertNotIn('promote',[x[-1] for x in self.actions() if x[0]=='create'])
        self.assertEqual(list(self.db.iterdir()),[]); self.assertEqual(list(self.state.iterdir()),[])
    def test_unverified_owner_keeps_receipt_and_does_not_remove(self):
        p=self.invoke(FAKE_WRONG_OWNER='1'); self.assertEqual(p.returncode,2,p.stderr)
        self.assertTrue(list(self.state.glob('opencode-update.*')))
        self.assertNotIn('rm',[x[0] for x in self.actions()])
    def test_missing_receipt_fails_closed_without_name_cleanup(self):
        p=self.invoke(FAKE_NO_RECEIPT='snapshot'); self.assertEqual(p.returncode,2,p.stderr)
        self.assertTrue(list(self.state.glob('opencode-update.*')))
        self.assertNotIn('rm',[x[0] for x in self.actions()])
    def test_host_timeout_removes_exact_created_guest_before_returning(self):
        spec=importlib.util.spec_from_file_location('oc_supervisor',ROOT/'oc-opencode-supervisor.py')
        mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        work=self.state/'opencode-update.test'; work.mkdir(mode=0o700)
        with patch.dict(os.environ,{**self.env,'FAKE_HANG':'stage'},clear=True):
            with tempfile.TemporaryFile(dir=work) as inp, tempfile.TemporaryFile(dir=work) as out:
                with self.assertRaises(TimeoutError):
                    mod.phase([],work,'fixedtest','stage',[], 'oc-agent','s0:c1,c2','4g',inp,out,.4,os.getppid())
        acts=self.actions(); self.assertEqual(sum(x[0]=='rm' for x in acts),1)
        self.assertEqual(list(self.db.iterdir()),[])


class LaunchHandoffTests(unittest.TestCase):
    def test_name_replacement_after_release_does_not_start_replacement(self):
        source=(ROOT/'oc-sandbox').read_text()
        launch=source[source.index('pm create -it --rm') if 'pm create -it --rm' in source else source.index('agent_id=$(pm create -it --rm'):]
        # Include the assignment prefix when the create command captures an immutable ID.
        if source[source.index('pm create -it --rm')-11:source.index('pm create -it --rm')] == 'agent_id=$(':
            launch='agent_id=$('+launch
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); host=d/'host'; observed=d/'observed'; replaced=d/'replaced'
            host.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$OBSERVED"\ntest -e "$REPLACED"\n'); host.chmod(0o755)
            prefix='''set -e
pm() { printf '%064d\\n' 1; }
release_lifecycle_lock() { : > "$REPLACED"; }
log() { :; }; die() { exit 2; }
AGENT=shared-name POD=p ILABEL=i LEVEL=l AGENT_MEM=1 SB=/sandbox HOMEVOL=v CWD=. AGENT_IMG=img
envargs=(); H=("$HOST")
'''
            env={**os.environ,'HOST':str(host),'OBSERVED':str(observed),'REPLACED':str(replaced)}
            result=subprocess.run(['bash','-c',prefix+launch],env=env,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(observed.read_text().strip(),'podman start -ai '+('0'*63+'1'))


class AgentGuardTests(unittest.TestCase):
    def run_case(self, changed, rc):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); exe=d/'opencode'; counter=d/'count'
            exe.write_text('''#!/usr/bin/python3
import os, pathlib, sys
p=pathlib.Path(__file__); count=pathlib.Path(os.environ['COUNT']); n=int(count.read_text())+1 if count.exists() else 1; count.write_text(str(n))
if os.environ['CHANGE']=='1':
 t=p.with_name('next'); t.write_text(p.read_text()+'\\n#new'+str(n)); t.chmod(0o755); os.replace(t,p)
sys.exit(int(os.environ['RC']))
'''); exe.chmod(0o755)
            env={**os.environ,'HOME':td,'PATH':td+':/usr/bin:/bin','COUNT':str(counter),'CHANGE':str(changed),'RC':str(rc)}
            p=subprocess.run([sys.executable,'-I',str(ROOT/'oc-opencode-run.py')],env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
            return p.returncode,int(counter.read_text())
    def test_normal_exit_does_not_restart_even_if_binary_changed(self): self.assertEqual(self.run_case(1,0),(0,1))
    def test_failure_without_binary_change_does_not_restart(self): self.assertEqual(self.run_case(0,1),(1,1))
    def test_changed_binary_nonzero_exit_is_preserved(self): self.assertEqual(self.run_case(1,1),(1,1))
    def test_signal_is_forwarded_and_no_restart(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); exe=d/'opencode'; marker=d/'child'
            exe.write_text('#!/usr/bin/python3\nimport os,pathlib,time\npathlib.Path(os.environ["MARKER"]).write_text(str(os.getpid()))\ntime.sleep(120)\n'); exe.chmod(0o755)
            env={**os.environ,'HOME':td,'PATH':td+':/usr/bin:/bin','MARKER':str(marker)}
            p=subprocess.Popen([sys.executable,'-I',str(ROOT/'oc-opencode-run.py')],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                deadline=time.monotonic()+5
                while not marker.exists() and time.monotonic()<deadline: time.sleep(.02)
                self.assertTrue(marker.exists()); child=int(marker.read_text())
                p.send_signal(signal.SIGTERM); p.communicate(timeout=5)
                self.assertEqual(p.returncode,143)
                with self.assertRaises(ProcessLookupError): os.kill(child,0)
            finally:
                if p.poll() is None: os.killpg(p.pid,signal.SIGKILL); p.communicate(timeout=5)


if __name__=='__main__': unittest.main(verbosity=2)
