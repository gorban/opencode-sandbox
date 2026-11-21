#!/usr/bin/env python3
"""Exercise ownership serialization using only temporary files and stub certificates."""
from pathlib import Path
import subprocess
import sys
import tempfile
import time

source = Path(sys.argv[1]).read_text()
begin = source.index('record_valid() {')
end = source.index('CAFP=$(fp_of_pem', begin)
defs = source[begin:end]
harness = r'''SCRATCH=$1; RECORD=$1/record; TNICK=nick; TAB=$'\t'
fp_of_pem() { touch "$SCRATCH/access"; printf '%064d\n' 0; }
nick_fps() { touch "$SCRATCH/access"; cat "$1/cert" 2>/dev/null || :; }
mx() { local op=$2 db=${4#sql:}; case $op in -A) fp_of_pem > "$db/cert" ;; -D) rm -f "$db/cert" ;; *) return 1 ;; esac; }
mv() { touch "$SCRATCH/at-move"; for ((i=0; i<500; i++)); do [ -e "$SCRATCH/release" ] && break; sleep 0.01; done; [ -e "$SCRATCH/release" ] || return 1; command mv "$@"; }
''' + defs + r'''
case $2 in remove) ts_remove_all ;; install) ts_install "$SCRATCH/db2" "$SCRATCH/cert" ;; fail-install) flock() { return 1; }; ts_install "$SCRATCH/db2" "$SCRATCH/cert" ;; fail-remove) flock() { return 1; }; ts_remove_all ;; esac
'''
with tempfile.TemporaryDirectory(prefix='f-race-') as tmp:
    w = Path(tmp); (w/'state').mkdir(); (w/'db2').mkdir(); (w/'record').write_bytes(b'')
    installed_cert = w/'db2/cert'
    def start(op):
        return subprocess.Popen(['bash', '-c', harness, '_', tmp, op], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    remove = start('remove')
    install = None
    try:
        deadline = time.monotonic() + 5
        while not (w/'at-move').exists() and time.monotonic() < deadline:
            if remove.poll() is not None: raise AssertionError('uninstall exited before paused move')
            time.sleep(0.01)
        assert (w/'at-move').exists(), 'uninstall did not reach paused move'
        install = start('install')
        time.sleep(0.25)
        (w/'release').touch()
        ro, re = remove.communicate(timeout=8); io, ie = install.communicate(timeout=8)
        assert remove.returncode == install.returncode == 0, (ro, re, io, ie)
        assert installed_cert.exists() and (str(w/'db2')+'\tnick\t') in (w/'record').read_text(), 'concurrent uninstall lost the installation record'
    finally:
        (w/'release').touch()
        for proc in (remove, install):
            if proc and proc.poll() is None:
                proc.kill(); proc.communicate()
    before = (w/'record').read_bytes()
    for op in ('fail-install', 'fail-remove'):
        (w/'access').unlink(missing_ok=True)
        result = subprocess.run(['bash', '-c', harness, '_', tmp, op], capture_output=True, text=True, timeout=8)
        assert result.returncode != 0 and (w/'record').read_bytes() == before and installed_cert.exists() and not (w/'access').exists(), 'lock failure allowed certificate access or mutation'
with tempfile.TemporaryDirectory(prefix='f-lock-open-') as tmp:
    w = Path(tmp); (w/'state/trust-record.lock').mkdir(parents=True); (w/'db2').mkdir()
    installed_cert = w/'db2/cert'
    (w/'record').write_bytes(b''); installed_cert.write_bytes(b'unchanged')
    for op in ('install', 'remove'):
        result = subprocess.run(['bash', '-c', harness, '_', tmp, op], capture_output=True, text=True, timeout=8)
        assert result.returncode != 0 and (w/'record').read_bytes() == b'' and installed_cert.read_bytes() == b'unchanged' and not (w/'access').exists(), 'lock open failure allowed certificate access or mutation'
print('concurrency and lock-failure regressions passed')
