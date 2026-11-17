#!/usr/bin/env python3
"""Host-only Flatpak shell regression; no browser, trust import or network.

Usage: python3 -I host-chrome-isolation-regression.py FIXTURE_MANIFEST
The manifest supplies public CAs and fixture URLs. Temporary profiles are deleted.
"""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('fixture_manifest', type=pathlib.Path)
args = parser.parse_args()
source = args.fixture_manifest.resolve(strict=True)
helper = HERE / 'prepare-host-chrome.py'
scratch = (ROOT / '.scratch').resolve(strict=True)
firefox = pathlib.Path(tempfile.mkdtemp(prefix='e1-browser-', dir=scratch))
chrome = None
try:
    data = json.loads(source.read_text())
    for name in ('home', 'config', 'data', 'cache', 'state', 'firefox-profile', 'ca'):
        (firefox / name).mkdir(mode=0o700)
    for v in ('E', 'X'):
        out = firefox / 'ca' / f'{v}.pem'
        shutil.copyfile(data['ca_files'][v], out); out.chmod(0o600)
        data['ca_files'][v] = str(out)
    manifest = firefox / 'manifest.json'
    manifest.write_text(json.dumps(data)); manifest.chmod(0o600)
    result = subprocess.run([sys.executable, '-I', str(helper), str(manifest)], stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=15, check=True)
    line = next(x for x in result.stdout.splitlines() if x.startswith('Manifest: '))
    new_manifest = pathlib.Path(line.removeprefix('Manifest: '))
    chrome = new_manifest.parent
    if not ((chrome.parent == firefox and chrome.name.startswith('chrome-')) or
            (chrome.parent == scratch and chrome.name.startswith('e1-chrome-'))):
        raise RuntimeError('helper returned an unexpected scratch path')
    marker = chrome / '.isolation-regression-marker'
    # Reproduce the actual Firefox mount, without executing the browser. The marker
    # is exclusive and removed by the shell if it could be created.
    shell = 'if (set -C; : > "$1") 2>/dev/null; then rm -- "$1"; exit 3; else exit 0; fi'
    ff_mounts = [f'--filesystem={firefox/n}' for n in ('home', 'config', 'data', 'cache', 'state', 'firefox-profile')] + [f'--filesystem={firefox/"ca"}:ro']
    result = subprocess.run(['flatpak', 'run', '--sandbox'] + ff_mounts + ['--command=sh',
                             'org.mozilla.firefox', '-c', shell, 'test', str(marker)],
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
    if result.returncode != 0:
        raise SystemExit(f'Firefox sandbox can write to Chrome scratch (status {result.returncode})')
    if chrome.parent != scratch or not chrome.name.startswith('e1-chrome-'):
        raise SystemExit('Chrome scratch is not an isolated sibling')
    firefox_marker = firefox / '.isolation-regression-marker'
    chrome_mounts = [f'--filesystem={chrome/n}' for n in ('home', 'config', 'data', 'cache', 'state', 'profile')] + [f'--filesystem={chrome/"ca"}:ro']
    reverse = subprocess.run(['flatpak', 'run', '--sandbox', '--session-bus'] + chrome_mounts + ['--command=sh',
                              'com.google.Chrome', '-c', shell, 'test', str(firefox_marker)],
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
    if reverse.returncode != 0:
        raise SystemExit(f'Chrome sandbox can write to Firefox scratch (status {reverse.returncode})')
    print('Firefox and Chrome sandboxes cannot write each other’s sibling scratch; isolation passed')
finally:
    if chrome is not None and chrome.parent == scratch and chrome.name.startswith('e1-chrome-') and not chrome.is_symlink():
        shutil.rmtree(chrome)
    if firefox.parent == scratch and firefox.name.startswith('e1-browser-') and not firefox.is_symlink():
        shutil.rmtree(firefox)
