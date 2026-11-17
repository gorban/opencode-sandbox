#!/usr/bin/env python3
"""Offline portal repair checks; uses disposable private files, no trust or GUI."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('e1_repair', HERE / 'repair-host-chrome-portal.py')
repair = importlib.util.module_from_spec(spec); spec.loader.exec_module(repair)
source = Path(sys.argv[1]).resolve(strict=True)
data = json.loads(source.read_text())
scratch = (ROOT / '.scratch').resolve(strict=True)
chrome = Path(tempfile.mkdtemp(prefix='e1-chrome-', dir=scratch))
try:
    for n in ('home', 'config', 'data', 'cache', 'state', 'profile', 'ca'):
        (chrome/n).mkdir(mode=0o700)
    (chrome/'profile'/'sentinel').write_text('unchanged')
    data['chrome_home'] = str(chrome/'home'); data['chrome_user_data_dir'] = str(chrome/'profile')
    data['chrome_launcher'] = str(chrome/'launch-chrome.sh')
    for v in ('E', 'X'):
        old = Path(data['ca_files'][v]); new = chrome/'ca'/f'{v}.pem'
        shutil.copyfile(old, new); new.chmod(0o600); data['ca_files'][v] = str(new)
    manifest = chrome/'manifest.json'; manifest.write_text(json.dumps(data)); manifest.chmod(0o600)
    launcher = chrome/'launch-chrome.sh'; launcher.write_text('before\n'); launcher.chmod(0o700)
    with tempfile.TemporaryDirectory() as td:
        doc = Path(td)/'doc'; doc.mkdir()
        exports = {}
        for v in ('E', 'X'):
            d=doc/f'id{v}'; d.mkdir(); p=d/f'{v}.pem'; shutil.copyfile(data['ca_files'][v], p); exports[v]=p
        real_validate = repair.validate_export
        def validate(path, variant, expected, _doc_root): real_validate(path, variant, expected, doc)
        with patch.object(repair, 'validate_export', side_effect=validate):
            target, content = repair.build(manifest, exports)
            assert launcher.read_text() == 'before\n'  # validation must be read-only
            argv = shlex.split(content.splitlines()[2][5:])
            mounts = [x for x in argv if x.startswith('--filesystem=')]
            assert mounts == [f'--filesystem={chrome/n}' for n in ('home', 'config', 'data', 'cache', 'state', 'profile')] + [f'--filesystem={chrome/"ca"}:ro', f'--filesystem={exports["E"]}:ro', f'--filesystem={exports["X"]}:ro']
            assert '--session-bus' in argv and '--sandbox' in argv
            assert not any('ignore-certificate-errors' in x or x == '--no-sandbox' or '--socket=session-bus' in x for x in argv)
            repair.replace_launcher(target, content)
            assert launcher.read_text() == content and (launcher.stat().st_mode & 0o777) == 0o700
            assert (chrome/'profile'/'sentinel').read_text() == 'unchanged'
            print('exact mounts, private profile and atomic launcher replacement: PASS')
            for reason in ('different bytes', 'wrong filename', 'symlink'):
                if reason == 'different bytes':
                    bad = doc/'bad'/'E.pem'; bad.parent.mkdir(); bad.write_bytes(b'not a CA')
                elif reason == 'wrong filename':
                    bad = doc/'idE'/'other.pem'; shutil.copyfile(exports['E'], bad)
                else:
                    bad = doc/'link'/'E.pem'; bad.parent.mkdir(); bad.symlink_to(exports['E'])
                try: repair.build(manifest, {'E': bad, 'X': exports['X']})
                except ValueError: print(reason + ': rejected')
                else: raise AssertionError(reason + ' accepted')
            original = manifest.read_text(); data['proxy'] = '8.8.8.8:443'; manifest.write_text(json.dumps(data))
            try: repair.build(manifest, exports)
            except ValueError: print('non-loopback proxy: rejected')
            else: raise AssertionError('non-loopback proxy accepted')
            manifest.write_text(original)
finally:
    if chrome.parent == scratch and chrome.name.startswith('e1-chrome-') and not chrome.is_symlink(): shutil.rmtree(chrome)
