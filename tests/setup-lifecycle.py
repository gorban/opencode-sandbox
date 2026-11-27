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
    def make_archive(self, dest, members):
        import tarfile as tf_mod
        with tf_mod.open(dest, 'w:gz') as tf:
            for item in members:
                if item[0] == 'reg':
                    _, name, data = item
                    info = tf_mod.TarInfo(name=name); info.size = len(data); info.mode = 0o755
                    tf.addfile(info, io.BytesIO(data))
                elif item[0] == 'sym':
                    _, name, target = item
                    info = tf_mod.TarInfo(name=name); info.type = tf_mod.SYMTYPE; info.linkname = target
                    tf.addfile(info)
                elif item[0] == 'dir':
                    _, name = item
                    info = tf_mod.TarInfo(name=name); info.type = tf_mod.DIRTYPE; info.mode = 0o755
                    tf.addfile(info)
    def downloader(self, payload=b'new binary', members=None):
        urls=[]
        def fake_dl(url, dest, env, timeout, max_bytes):
            urls.append((url, timeout, max_bytes))
            items = members if members is not None else [('reg', 'opencode', payload)]
            self.make_archive(dest, items)
            return dest.stat().st_size
        return fake_dl, urls
    def runner(self, version='opencode v2.3.0\n'):
        calls=[]
        def fake(args, env, timeout):
            calls.append((args, timeout))
            if args[-1] == '--version': return version
            raise AssertionError(args)
        return fake, calls
    def stage(self, *, payload=b'new binary', pin='2.3.0', sha256=None, version='opencode v2.3.0\n',
              archive_sha256='', members=None):
        expected = hashlib.sha256(payload).hexdigest() if sha256 is None else sha256
        dl, urls = self.downloader(payload=payload, members=members)
        fake, calls = self.runner(version=version)
        out = io.BytesIO()
        update.stage(self.snapshot(), pin, expected, out,
                     expected_archive_sha256=archive_sha256, runner=fake, downloader=dl)
        return out.getvalue(), urls, calls, expected
    def test_version_output_is_not_trimmed_by_real_runner(self):
        script=Path(self.tmp.name)/'version'; script.write_text('#!/bin/sh\nprintf "opencode v2.3.0\\n\\n"\n'); script.chmod(0o755)
        self.assertEqual(update.run([str(script)],os.environ,10),'opencode v2.3.0\n\n')
    def test_rejects_extra_or_control_version_output(self):
        for suffix in (' trailing', '\r', '\x00', '\nextra'):
            with self.subTest(suffix=suffix):
                with self.assertRaises(ValueError):
                    self.stage(version='opencode v2.3.0' + suffix)
                self.assertEqual(self.live.read_bytes(), b'old binary')
    def test_stages_direct_release_verifies_digest_before_exec_and_promotes_atomically(self):
        frame, urls, calls, expected = self.stage(payload=b'new binary', pin='2.3.0')
        self.assertEqual(self.live.read_bytes(), b'old binary')
        self.assertEqual(len(urls), 1)
        self.assertTrue(urls[0][0].startswith('https://github.com/anomalyco/opencode/releases/download/v2.3.0/opencode-linux-'))
        self.assertTrue(urls[0][0].endswith('-musl.tar.gz'))
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0][-1], '--version')
        update.promote(self.home, io.BytesIO(frame), expected)
        self.assertEqual(self.live.read_bytes(), b'new binary')
    def test_wrong_binary_digest_refused_before_executing_version(self):
        wrong = '0' * 64
        dl, urls = self.downloader(payload=b'untrusted payload')
        fake, calls = self.runner(version='opencode v2.3.0\n')
        snap = self.snapshot()
        out = io.BytesIO()
        with self.assertRaisesRegex(ValueError, 'OC_OPENCODE_SHA256'):
            update.stage(snap, '2.3.0', wrong, out, runner=fake, downloader=dl)
        self.assertEqual(len(urls), 1)
        self.assertEqual(calls, [])
        self.assertEqual(out.getvalue(), b'')
        self.assertEqual(self.live.read_bytes(), b'old binary')
    def test_promote_independently_rejects_consistent_forged_frame_with_wrong_digest(self):
        frame, _, _, real_sha = self.stage(payload=b'new binary', pin='2.3.0')
        other_sha = hashlib.sha256(b'different expected binary').hexdigest()
        self.assertNotEqual(real_sha, other_sha)
        stream = io.BytesIO(frame)
        with self.assertRaisesRegex(ValueError, 'OC_OPENCODE_SHA256'):
            update.promote(self.home, stream, other_sha)
        self.assertEqual(self.live.read_bytes(), b'old binary')
    def test_matching_existing_digest_short_circuits_without_network(self):
        old_sha = hashlib.sha256(b'old binary').hexdigest()
        dl, urls = self.downloader(payload=b'old binary')
        fake, calls = self.runner()
        out = io.BytesIO()
        update.stage(self.snapshot(), '2.3.0', old_sha, out, runner=fake, downloader=dl)
        self.assertEqual(out.getvalue(), b'')
        self.assertEqual(urls, [])
        self.assertEqual(calls, [])
    def test_offline_and_timeout_do_not_modify_live_binary(self):
        expected = hashlib.sha256(b'new binary').hexdigest()
        for exc in (RuntimeError('offline'), subprocess.TimeoutExpired('curl', 1)):
            snap = self.snapshot()
            out = io.BytesIO()
            def fail(*args): raise exc
            with self.assertRaises(type(exc)):
                update.stage(snap, '2.3.0', expected, out, downloader=fail)
            self.assertEqual(out.getvalue(), b''); self.assertEqual(self.live.read_bytes(), b'old binary')
    def test_wrong_pin_and_incomplete_or_corrupt_frame_do_not_promote(self):
        with self.assertRaises(ValueError):
            self.stage(pin='2.3.0', version='2.3.1')
        self.assertEqual(self.live.read_bytes(), b'old binary')
        frame, _, _, expected = self.stage()
        for bad in (frame[:-1], frame[:-len(update.END)] + b'bad'):
            stream = io.BytesIO(bad)
            with self.assertRaises(ValueError):
                update.promote(self.home, stream, expected)
            self.assertEqual(self.live.read_bytes(), b'old binary')
    def test_concurrent_binary_change_is_not_overwritten(self):
        frame, _, _, expected = self.stage()
        self.live.write_bytes(b'another update')
        stream = io.BytesIO(frame)
        with self.assertRaises(ValueError):
            update.promote(self.home, stream, expected)
        self.assertEqual(self.live.read_bytes(), b'another update')
    def test_v1_and_missing_digest_are_rejected(self):
        valid_sha = hashlib.sha256(b'new binary').hexdigest()
        with self.assertRaises(ValueError):
            self.stage(pin='1.19.2', version='1.19.2')
        with self.assertRaises(ValueError):
            self.stage(pin='', sha256=valid_sha)
        with self.assertRaises(ValueError):
            self.stage(pin='2.3.0', sha256='not-a-digest')
    def test_archive_bounds_special_members_truncation_and_temp_cleanup(self):
        with tempfile.TemporaryDirectory() as scratch_tmp:
            scratch = Path(scratch_tmp)
            env_patch = {'TMPDIR': str(scratch)}
            cases = [
                ('symlink', [('sym', 'opencode', '/etc/passwd')]),
                ('traversal', [('reg', '../opencode', b'new binary')]),
                ('duplicate', [('reg', 'opencode', b'a'), ('reg', './opencode', b'b')]),
                ('missing', [('reg', 'README.md', b'hi')]),
                ('too_many', [('reg', f'f{i}', b'x') for i in range(65)]),
            ]
            for label, members in cases:
                with self.subTest(case=label), patch.dict(os.environ, env_patch):
                    with self.assertRaises(ValueError):
                        self.stage(members=members)
                    self.assertEqual(list(scratch.iterdir()), [])
            # Truncated gzip archive and oversized total decompressed stream (including skipped member)
            with patch.dict(os.environ, env_patch):
                def trunc_dl(url, dest, env, timeout, max_bytes):
                    self.make_archive(dest, [('reg', 'opencode', b'x' * 4096)])
                    raw = dest.read_bytes()
                    dest.write_bytes(raw[:len(raw) // 2])
                    return dest.stat().st_size
                fake, calls = self.runner()
                snap = self.snapshot()
                expected_trunc = hashlib.sha256(b'x' * 4096).hexdigest()
                out = io.BytesIO()
                with self.assertRaises(ValueError):
                    update.stage(snap, '2.3.0', expected_trunc, out, runner=fake, downloader=trunc_dl)
                self.assertEqual(calls, [])
                self.assertEqual(list(scratch.iterdir()), [])
                # Oversized total decompressed stream covering skipped members + opencode
                archive = scratch / 'bomb.tar.gz'
                self.make_archive(archive, [('reg', 'pad.bin', b'a' * 8192), ('reg', 'opencode', b'b' * 4096)])
                with self.assertRaisesRegex(ValueError, 'decompressed'):
                    update.extract_opencode_binary(archive, scratch / 'out', max_decompressed=4096)
                archive.unlink()
                self.assertEqual(list(scratch.iterdir()), [])
    def test_download_release_enforces_streaming_size_bound_and_timeout_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td); fakebin = d / 'bin'; fakebin.mkdir()
            # 1) Streaming response without Content-Length exceeding max_bytes
            curl_big = fakebin / 'curl'
            curl_big.write_text('#!/usr/bin/python3\nimport sys\nsys.stdout.buffer.write(b"x" * 20000)\nsys.stdout.buffer.flush()\n')
            curl_big.chmod(0o755)
            env = {**os.environ, 'PATH': f'{fakebin}:/usr/bin:/bin'}
            with self.assertRaisesRegex(ValueError, 'size limit'):
                update.download_release('https://example.invalid/a.tar.gz', d / 'a.tar.gz', env, timeout=5, max_bytes=4096)
            self.assertFalse((d / 'a.tar.gz').exists())
            # 2) Hanging download killed cleanly within deadline
            marker = d / 'child.pid'
            curl_hang = fakebin / 'curl'
            curl_hang.write_text(f'#!/usr/bin/python3\nimport os, pathlib, time\npathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\ntime.sleep(30)\n')
            curl_hang.chmod(0o755)
            with self.assertRaises(subprocess.TimeoutExpired):
                update.download_release('https://example.invalid/b.tar.gz', d / 'b.tar.gz', env, timeout=0.4, max_bytes=4096)
            self.assertFalse((d / 'b.tar.gz').exists())
            if marker.exists():
                pid = int(marker.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
    def test_download_release_does_not_spawn_curl_when_destination_exists(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / 'existing.tar.gz'
            dest.write_bytes(b'already present')
            with patch.object(update.subprocess, 'Popen') as popen:
                with self.assertRaises(FileExistsError):
                    update.download_release('https://example.invalid/c.tar.gz', dest, os.environ, timeout=5, max_bytes=4096)
                popen.assert_not_called()
            self.assertEqual(dest.read_bytes(), b'already present')
            fresh = Path(td) / 'spawn-fail.tar.gz'
            with patch.object(update.subprocess, 'Popen', side_effect=FileNotFoundError('missing curl')):
                with self.assertRaises(FileNotFoundError):
                    update.download_release('https://example.invalid/d.tar.gz', fresh, os.environ, timeout=5, max_bytes=4096)
            self.assertFalse(fresh.exists())
    def test_snapshot_refuses_fifo_without_a_writer(self):
        self.live.unlink()
        os.mkfifo(self.live)
        script = ('import runpy, sys; from pathlib import Path; '
                  'runpy.run_path(sys.argv[1])["read_old"](Path(sys.argv[2]))')
        result = subprocess.run([sys.executable, '-I', '-c', script, str(ROOT/'oc-opencode-update.py'), str(self.home)],
                                capture_output=True, timeout=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'not an executable regular file', result.stderr)
    def test_symlinked_binary_never_reaches_target(self):
        victim=Path(self.tmp.name)/'victim'; victim.write_bytes(b'untouched'); victim.chmod(0o755)
        self.live.unlink(); self.live.symlink_to(victim)
        with self.assertRaises(OSError): self.snapshot()
        self.assertEqual(victim.read_bytes(),b'untouched')
    def test_snapshot_never_forwards_other_shared_home_files(self):
        secret=self.home/'auth'; secret.write_bytes(b'PRIVATE-TEST-CREDENTIAL')
        source=self.snapshot().getvalue()
        self.assertNotIn(b'PRIVATE-TEST-CREDENTIAL',source)
        self.assertNotIn(b'old binary', source)
        self.assertEqual(update.read_snapshot(io.BytesIO(source)), hashlib.sha256(b'old binary').hexdigest())
    def test_first_install_uses_direct_release_and_verifies_optional_archive_digest(self):
        self.live.unlink()
        payload = b'first install'
        expected = hashlib.sha256(payload).hexdigest()
        # Verify archive digest mismatch fails before extraction
        with self.assertRaisesRegex(ValueError, 'OC_OPENCODE_ARCHIVE_SHA256'):
            self.stage(payload=payload, pin='2.3.0', archive_sha256='f' * 64)
        self.assertFalse(self.live.exists())
        frame, _, _, _ = self.stage(payload=payload, pin='2.3.0')
        self.assertFalse(self.live.exists())
        update.promote(self.home, io.BytesIO(frame), expected)
        self.assertEqual(self.live.read_bytes(), payload)


class SupervisorTests(unittest.TestCase):
    TEST_SHA = 'a' * 64
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
    def invoke(self, *, volume='oc-home', image='oc-agent', memory='4g', version='2.3.0', sha256=TEST_SHA, **extra):
        return subprocess.run([sys.executable,'-I',str(ROOT/'oc-opencode-supervisor.py'),str(self.state),
                               's0:c1,c2',volume,image,memory,version,sha256],
                              env={**self.env,**extra},stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=15)
    def actions(self):
        import json
        return [json.loads(x) for x in self.log.read_text().splitlines()]
    def test_each_guest_removed_before_next_phase_and_no_mount_on_network_stage(self):
        p=self.invoke(); self.assertEqual(p.returncode,0,p.stderr)
        acts=self.actions(); create=[x for x in acts if x[0]=='create']; self.assertEqual([x[-1] for x in create],['snapshot','stage','promote'])
        self.assertIn('--network=none',create[0]); self.assertIn('oc-home:/source:ro',create[0]); self.assertNotIn('-v',create[1]); self.assertIn('--http-proxy=false',create[1]); self.assertIn('--network=none',create[2]); self.assertIn('oc-home:/root',create[2])
        self.assertIn(f'OC_OPENCODE_SHA256={self.TEST_SHA}', create[1])
        self.assertIn(f'OC_OPENCODE_SHA256={self.TEST_SHA}', create[2])
        self.assertIn('label=level:s0:c1,c2', create[0])
        self.assertFalse(any(option.startswith('label=level:') for option in create[1]))
        self.assertIn('label=level:s0:c1,c2', create[2])
        for i,entry in enumerate(acts):
            if entry[0]=='create' and entry[-1] in ('stage','promote'):
                self.assertIn('rm',[a[0] for a in acts[:i]])
                self.assertEqual(sum(a[0]=='rm' for a in acts[:i]),1 if entry[-1]=='stage' else 2)
        self.assertEqual(list(self.db.iterdir()),[]); self.assertEqual(list(self.state.iterdir()),[])
    def test_container_image_is_delimited_from_options(self):
        result = self.invoke(memory='4g', version='2.3.0-rc.1')
        self.assertEqual(result.returncode, 0, result.stderr)
        for args in self.actions():
            if args[0] != 'create':
                continue
            phase = args[-1]
            self.assertEqual(args[-5:], ['--', 'oc-agent', '-I', '/usr/local/bin/oc-opencode-update', phase])
            self.assertEqual(args.count('--memory=4g'), 1)
            if phase == 'stage':
                self.assertIn('OC_OPENCODE_VERSION=2.3.0-rc.1', args)
                self.assertIn(f'OC_OPENCODE_SHA256={self.TEST_SHA}', args)
            if phase == 'promote':
                self.assertIn(f'OC_OPENCODE_SHA256={self.TEST_SHA}', args)
    def test_invalid_digest_rejected_before_podman(self):
        result = self.invoke(sha256='not-hex')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(self.log.exists())

    def test_option_like_container_operands_are_rejected_before_podman(self):
        for kind in ('image', 'volume'):
            with self.subTest(kind=kind):
                result = self.invoke(**{kind: '-fixture'})
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('invalid volume or image name', result.stderr)
                self.assertFalse(self.log.exists())

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


class ChromiumModeTests(unittest.TestCase):
    def test_same_mode_reuses_browser_and_switch_only_replaces_browser(self):
        source = (ROOT/'oc-sandbox').read_text()
        browser = source[source.index('# ---- Chromium -'):source.index('log "Waiting for Chromium DevTools')]
        fixture = r'''
set -euo pipefail
CHROME=chrome CHROME_IMG=chrome-image CHROME_MEM=1g CHROMEVOL=retained-profile
POD=retained-pod POLDIR=$PWD SCRIPT_REAL=$1 WL=$PWD/test-wayland INST=test ILABEL=test NOKEY=0
log() { :; }
cstate() { printf 'running\n'; }
detect_keys() { printf '/dev/hidraw-fixture|test-key|test-id\n'; printf 'detect\n' >> trace; }
fido_device_nodes() { cut -d'|' -f1; }
pm() {
  case "$1 $2" in
    'image inspect') printf 'image\n' ;;
    'container inspect')
      test -s receipt || return 1
      if [[ $4 == '{{.Image}}' ]]; then printf 'image\n'; else cat receipt; fi ;;
    'run --rm') : ;;  # profile lock cleanup
    'rm -f') printf 'remove %s\n' "$3" >> trace; : > receipt ;;
    'run -d')
      printf 'launch %s\n' "$*" >> trace
      printf '%s\n' "$8" | sed 's/^oc.cfg=//' > receipt ;;
    *) return 97 ;;
  esac
}
for CHROMIUM_MODE in headless headless wayland wayland headless headless; do
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'oc_chromium.cil').write_text('fixture policy')
            result = subprocess.run(['/usr/bin/bash', '-c', fixture + browser + '\ndone',
                                     'fixture', str(ROOT/'oc-sandbox')], cwd=root,
                                    env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            trace = (root/'trace').read_text().splitlines()
        self.assertEqual(trace.count('detect'), 2)
        lifecycle = [row for row in trace if row != 'detect']
        self.assertEqual([row.split()[0] for row in lifecycle], ['launch', 'remove', 'launch', 'remove', 'launch'])
        self.assertEqual(lifecycle[1::2], ['remove chrome', 'remove chrome'])
        for row in lifecycle[0::2]:
            self.assertIn('--pod retained-pod', row)
            self.assertIn('-v retained-profile:/profile:Z', row)
        self.assertIn('--ozone-platform=wayland', lifecycle[2])
        self.assertIn('--device /dev/hidraw-fixture', lifecycle[2])
        for row in lifecycle[0::4]:
            self.assertIn('--headless', row)
            for forbidden in ('WAYLAND_DISPLAY', '--device', '/run/udev'):
                self.assertNotIn(forbidden, row)


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
    _HARNESS = (
        'import ctypes, importlib.util, sys; '
        'subreaper = sys.argv[1] == "1"; '
        'subreaper and (ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0 or sys.exit(99)); '
        'spec = importlib.util.spec_from_file_location("oc_run", sys.argv[2]); '
        'mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); '
        'mod.BAKED_OPENCODE = sys.argv[3]; '
        'sys.argv = ["oc-opencode-run.py", *sys.argv[4:]]; '
        'sys.exit(mod.main())'
    )

    def _wrapper_cmd(self, exe: Path, *args, subreaper: bool = False):
        return [
            sys.executable, '-I', '-c', self._HARNESS,
            '1' if subreaper else '0', str(ROOT / 'oc-opencode-run.py'), str(exe), *args,
        ]

    def test_signal_during_spawn_is_forwarded_and_all_children_are_reaped(self):
        spec = importlib.util.spec_from_file_location('oc_run_sig', ROOT / 'oc-opencode-run.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        child = SimpleNamespace(pid=42, returncode=None, wait=lambda: 0)
        handlers = {}

        def spawn(_):
            handlers[signal.SIGTERM](signal.SIGTERM, None)
            return child

        with tempfile.TemporaryDirectory() as td:
            baked = Path(td) / 'opencode'
            baked.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
            baked.chmod(0o755)
            mod.BAKED_OPENCODE = str(baked)
            with patch.object(signal, 'signal', side_effect=handlers.__setitem__), \
                    patch.object(subprocess, 'Popen', side_effect=spawn), \
                    patch.object(os, 'pidfd_open', return_value=99), \
                    patch.object(os, 'close'), patch.object(signal, 'pidfd_send_signal') as send, \
                    patch.object(os, 'waitpid', side_effect=[(42, 0), (0, 0)]) as wait:
                self.assertEqual(mod.main(), 0)
        send.assert_called_once_with(99, signal.SIGTERM)
        self.assertEqual([call.args for call in wait.call_args_list],
                         [(-1, 0x40000000), (-1, os.WNOHANG | 0x40000000)])

    def test_reaps_adopted_children_while_opencode_is_still_running(self):
        with tempfile.TemporaryDirectory() as temp:
            exe = Path(temp) / 'opencode'
            exe.write_text('''#!/usr/bin/python3
import os
from pathlib import Path
import time

reader, writer = os.pipe()
intermediate = os.fork()
if intermediate == 0:
    orphan = os.fork()
    if orphan == 0:
        os._exit(0)
    os.write(writer, str(orphan).encode())
    os._exit(0)
os.close(writer)
orphan = int(os.read(reader, 30))
os.waitpid(intermediate, 0)
deadline = time.monotonic() + 2
while time.monotonic() < deadline:
    if not Path(f'/proc/{orphan}').exists():
        os._exit(0)
    time.sleep(0.02)
os._exit(9)
''')
            exe.chmod(0o755)
            # Make the wrapper the adoptive parent without needing a system-wide PID namespace.
            env = {**os.environ, 'PATH': '/usr/bin:/bin'}
            result = subprocess.run(self._wrapper_cmd(exe, subreaper=True),
                                    env=env, capture_output=True, timeout=6)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_forwarding_preserves_argument_boundaries(self):
        with tempfile.TemporaryDirectory() as temp:
            exe = Path(temp) / 'opencode'
            exe.write_text('#!/usr/bin/python3\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n')
            exe.chmod(0o755)
            arguments = ['--title', 'two words', 'literal *', '--', '-fixture']
            env = {**os.environ, 'PATH': '/usr/bin:/bin'}
            result = subprocess.run(
                self._wrapper_cmd(exe, *arguments),
                env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), arguments)

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
            env={**os.environ,'HOME':td,'PATH':'/usr/bin:/bin','COUNT':str(counter),'CHANGE':str(changed),'RC':str(rc)}
            p=subprocess.run(self._wrapper_cmd(exe),env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
            return p.returncode,int(counter.read_text())
    def test_normal_exit_does_not_restart_even_if_binary_changed(self): self.assertEqual(self.run_case(1,0),(0,1))
    def test_failure_without_binary_change_does_not_restart(self): self.assertEqual(self.run_case(0,1),(1,1))
    def test_changed_binary_nonzero_exit_is_preserved(self): self.assertEqual(self.run_case(1,1),(1,1))
    def test_signal_is_forwarded_and_no_restart(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); exe=d/'opencode'; marker=d/'child'
            exe.write_text('#!/usr/bin/python3\nimport os,pathlib,time\npathlib.Path(os.environ["MARKER"]).write_text(str(os.getpid()))\ntime.sleep(120)\n'); exe.chmod(0o755)
            env={**os.environ,'HOME':td,'PATH':'/usr/bin:/bin','MARKER':str(marker)}
            p=subprocess.Popen(self._wrapper_cmd(exe),env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
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
