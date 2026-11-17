#!/usr/bin/env python3
"""Test launcher control-file isolation with real Flatpak shells, no GUI or trust changes.

Usage: python3 -I host-browser-control-regression.py CHROME_MANIFEST E_EXPORT X_EXPORT
All browser data and control files in this test are disposable.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('chrome_manifest', type=Path)
parser.add_argument('e_export', type=Path)
parser.add_argument('x_export', type=Path)
args = parser.parse_args()  # Reject unknown options before reading or loading any source.

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SCRATCH = (ROOT/'.scratch').resolve(strict=True)
sys.dont_write_bytecode = True
files = {'firefox': 'host-browser-fixture.py', 'chrome': 'prepare-host-chrome.py',
         'repair': 'repair-host-chrome-portal.py'}
def load(key):
    source = HERE / files[key]
    spec = importlib.util.spec_from_file_location('e1_control_' + key, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def check(label, directory, profile_name, content, app):
    launcher=directory/('launch-firefox.sh' if app=='org.mozilla.firefox' else 'launch-chrome.sh')
    manifest=directory/'manifest.json'; ca=directory/'ca'/'E.pem'
    before=(launcher.read_bytes(),manifest.read_bytes(),digest(ca))
    argv=shlex.split(content.splitlines()[2][5:]); app_index=argv.index(app)
    shell='''
set -u
for name in home config data cache state "$6"; do
  printf state > "$1/$name/.e1-state-canary" || exit 11
done
if test -w "$4"; then echo ca-writable; fi
if [ "$7" = yes ]; then
  for exported in "$8" "$9"; do
    test -r "$exported" || exit 14
    if test -w "$exported"; then echo portal-writable; fi
  done
fi
printf altered > "$1/$(basename "$5")" 2>/dev/null || :
printf altered > "$1/manifest.json" 2>/dev/null || :
printf marker > "$1/.e1-control-canary" 2>/dev/null || :
if printf replacement > "$1/.e1-replace-launcher" 2>/dev/null; then mv -f -- "$1/.e1-replace-launcher" "$1/$(basename "$5")" 2>/dev/null || :; fi
if printf replacement > "$1/.e1-replace-manifest" 2>/dev/null; then mv -f -- "$1/.e1-replace-manifest" "$1/manifest.json" 2>/dev/null || :; fi
for p in "${10}" "${11}" "${12}"; do test ! -e "$p" || exit 13; done
'''
    cmd=argv[:app_index]+['--command=sh',app,'-c',shell,'canary',str(directory),str(directory/'home'),str(directory/profile_name),str(ca),str(launcher),profile_name, 'yes' if label == 'Chrome repair builder' else 'no',str(exports['E']),str(exports['X'])] + [str(Path.home().resolve()/p) for p in ('.pki/nssdb', '.local/share/pki/nssdb', '.mozilla')]
    result=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=20)
    intact=(launcher.read_bytes(),manifest.read_bytes(),digest(ca))==before and not any((directory/n).exists() for n in ('.e1-control-canary', '.e1-replace-launcher', '.e1-replace-manifest'))
    state=all((directory/n/'.e1-state-canary').read_text()=='state' for n in ('home','config','data','cache','state',profile_name))
    passed=result.returncode==0 and state and intact and 'ca-writable' not in result.stdout and 'portal-writable' not in result.stdout
    print(f'{label}: '+('PASS' if passed else f'FAIL (control intact={intact}, state writable={state}, CA writable={"ca-writable" in result.stdout}, shell status={result.returncode})'))
    return passed

manifest=args.chrome_manifest.resolve(strict=True)
exports={'E':args.e_export,'X':args.x_export}
base=json.loads(manifest.read_text())
cas={v:Path(base['ca_files'][v]) for v in ('E','X')}
copies={v:cas[v].read_bytes() for v in cas}
fixture=load('firefox'); chrome_module=load('chrome'); repair=load('repair')
created=[]
def remember(path):
    created.append((path,path.stat().st_ino))
    return path
try:
    ff, _, ff_launch=fixture.prepare_firefox(SCRATCH,cas,45678,{'ca_sha256':base['ca_sha256']})
    remember(ff)
    results=[check('Firefox builder',ff,'firefox-profile',ff_launch.read_text(),'org.mozilla.firefox')]
    chrome_manifest, chrome_launch=chrome_module.prepare(ff,base,copies)
    chrome=remember(chrome_manifest.parent)
    results.append(check('Chrome builder',chrome,'profile',chrome_launch.read_text(),'com.google.Chrome'))
    # A fresh control directory prevents the old-builder canary from corrupting the repair input.
    repair_manifest, _=chrome_module.prepare(ff,base,copies)
    repair_dir=remember(repair_manifest.parent)
    _, content=repair.build(repair_manifest,exports)
    results.append(check('Chrome repair builder',repair_dir,'profile',content,'com.google.Chrome'))
    if not all(results): raise SystemExit(1)
finally:
    for path,inode in reversed(created):
        if path.parent==SCRATCH and not path.is_symlink() and path.stat().st_ino==inode:
            shutil.rmtree(path)
