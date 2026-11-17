#!/usr/bin/env python3
"""Host-only wrapper smoke test using --version; never opens a browser window.

Usage: python3 -I host-chrome-portal-regression.py FIXTURE_MANIFEST
Temporary Chrome scratch is removed after the process exits.
"""
import argparse
import os
import pathlib
import shlex
import shutil
import signal
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('fixture_manifest', type=pathlib.Path)
args = parser.parse_args()
helper = HERE / 'prepare-host-chrome.py'
manifest = args.fixture_manifest.resolve(strict=True)
scratch = (ROOT / '.scratch').resolve(strict=True)
existing = {p.name for p in scratch.glob('e1-chrome-*')}
chrome = None
inode = None
try:
    prepared = subprocess.run([sys.executable, '-I', str(helper), str(manifest)], stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=15, check=True)
    line = next(x for x in prepared.stdout.splitlines() if x.startswith('Chrome launcher: '))
    launcher = pathlib.Path(line.removeprefix('Chrome launcher: '))
    chrome = launcher.parent
    if chrome.parent != scratch or not chrome.name.startswith('e1-chrome-') or chrome.name in existing or chrome.is_symlink():
        raise RuntimeError('helper did not create a new private Chrome scratch')
    inode = chrome.stat().st_ino
    lines = launcher.read_text().splitlines()
    if len(lines) != 3 or lines[:2] != ['#!/bin/sh', 'exec </dev/null'] or not lines[2].startswith('exec '):
        raise RuntimeError('unexpected launcher format')
    argv = shlex.split(lines[2][5:]) + ['--version']
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=20)
    except BaseException:
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        proc.communicate(timeout=5)
        raise
    if proc.returncode != 0 or not out.strip().startswith('Google Chrome '):
        raise SystemExit(f'Chrome wrapper failed before --version (status {proc.returncode}): {err.strip()}')
    print('Chrome wrapper --version passed:', out.strip())
finally:
    if (chrome is not None and inode is not None and chrome.parent == scratch and
            chrome.name.startswith('e1-chrome-') and not chrome.is_symlink() and chrome.stat().st_ino == inode):
        shutil.rmtree(chrome)
