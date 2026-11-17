#!/usr/bin/env python3
"""Repair one private Chrome launcher with two exact read-only portal file mounts.

Run on the host: python3 -I repair-host-chrome-portal.py CHROME_MANIFEST E_EXPORT X_EXPORT
This changes only the private launcher; it does not launch Chrome or import trust.
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import ssl
import stat
import tempfile
from pathlib import Path


def owned_dir(path):
    if path.is_symlink() or path.resolve(strict=True) != path or not path.is_dir():
        raise ValueError(f'unsafe private directory: {path}')
    st = path.stat()
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError(f'private directory must be user-owned and mode 0700: {path}')


def regular(path):
    if path.is_symlink() or path.resolve(strict=True) != path or not path.is_file():
        raise ValueError(f'unsafe file: {path}')


def validate_export(path, variant, expected, doc_root):
    # Permit only one file in one document ID; no doc-root/directory or extra files.
    if not path.is_absolute() or path.name != f'{variant}.pem' or path.parent.parent != doc_root:
        raise ValueError(f'{variant} export must be a single matching PEM below the document portal')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', path.parent.name):
        raise ValueError(f'invalid {variant} portal document ID')
    regular(path)
    if path.read_bytes() != expected:
        raise ValueError(f'{variant} export does not match the private CA bytes')


def build(manifest, exports):
    repo = Path(__file__).resolve().parents[4]
    scratch = repo / '.scratch'
    if scratch.is_symlink() or manifest.is_symlink(): raise ValueError('scratch or manifest is a symlink')
    manifest = manifest.resolve(strict=True)
    chrome = manifest.parent
    if (chrome.parent != scratch.resolve(strict=True) or not chrome.name.startswith('e1-chrome-')
            or manifest.name != 'manifest.json'):
        raise ValueError('manifest must be directly inside a private e1-chrome scratch directory')
    owned_dir(chrome); regular(manifest)
    if manifest.stat().st_uid != os.getuid(): raise ValueError('manifest owner mismatch')
    data = json.loads(manifest.read_text())
    for name in ('home', 'config', 'data', 'cache', 'state', 'profile', 'ca'):
        owned_dir(chrome / name)
    if (data['chrome_home'] != str(chrome / 'home') or
        data['chrome_user_data_dir'] != str(chrome / 'profile') or
        data['chrome_launcher'] != str(chrome / 'launch-chrome.sh')):
        raise ValueError('private paths do not match manifest')
    proxy = data['proxy']
    if not isinstance(proxy, str) or not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', proxy):
        raise ValueError('proxy must be loopback')
    if not 1024 <= int(proxy.split(':')[1]) <= 65535: raise ValueError('invalid proxy port')
    doc_root = Path('/run/user') / str(os.getuid()) / 'doc'
    digests = []
    for variant in ('E', 'X'):
        ca = chrome / 'ca' / f'{variant}.pem'
        regular(ca)
        if data['ca_files'][variant] != str(ca): raise ValueError(f'{variant} CA path mismatch')
        pem = ca.read_bytes()
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode('ascii'))).hexdigest()
        if digest != data['ca_sha256'][variant]: raise ValueError(f'{variant} CA fingerprint mismatch')
        validate_export(exports[variant], variant, pem, doc_root)
        digests.append(digest)
    if digests[0] == digests[1]: raise ValueError('CAs are not distinct')
    launcher = chrome / 'launch-chrome.sh'
    regular(launcher)
    st = launcher.stat()
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError('launcher must be user-owned and mode 0700')
    cmd = ['flatpak', 'run', '--sandbox', '--session-bus', '--share=network', '--share=ipc',
           '--socket=wayland', '--socket=fallback-x11']
    for name in ('home', 'config', 'data', 'cache', 'state', 'profile'):
        cmd.append(f'--filesystem={chrome / name}')
    cmd += [f'--filesystem={chrome / "ca"}:ro',
            f'--filesystem={exports["E"]}:ro', f'--filesystem={exports["X"]}:ro']
    for key, folder in [('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'), ('XDG_DATA_HOME', 'data'),
                        ('XDG_CACHE_HOME', 'cache'), ('XDG_STATE_HOME', 'state')]:
        cmd.append(f'--env={key}={chrome / folder}')
    cmd += ['com.google.Chrome', f'--user-data-dir={chrome / "profile"}',
            f'--proxy-server=http://{proxy}', '--proxy-bypass-list=<-loopback>',
            '--no-first-run', '--no-default-browser-check']
    return launcher, '#!/bin/sh\nexec </dev/null\nexec ' + shlex.join(cmd) + '\n'


def replace_launcher(launcher, content):
    fd, name = tempfile.mkstemp(prefix='.launcher-', dir=launcher.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o700)
            f.write(content); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, launcher)
    finally:
        if temporary.exists() and not temporary.is_symlink(): temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('e_export', type=Path)
    parser.add_argument('x_export', type=Path)
    parser.add_argument('--dry-run', action='store_true', help='validate and print the candidate without writing')
    args = parser.parse_args()
    launcher, content = build(args.manifest, {'E': args.e_export, 'X': args.x_export})
    if args.dry_run:
        print(content, end='')
    else:
        replace_launcher(launcher, content)
        print(f'Repaired private launcher: {launcher}')


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f'Chrome portal repair failed: {exc}')
