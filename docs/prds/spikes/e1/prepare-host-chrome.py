#!/usr/bin/env python3
"""Prepare a private Chrome launcher from an active e1 host fixture manifest.

Run on the host, with stdin closed. This creates a new private scratch directory;
it does not launch Chrome, install a certificate, or modify the Firefox profile.
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import ssl
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

HOSTS = {'feat': 'feat-a.oc-sandbox.internal', 'evil': 'evil.example.com', 'ip127': '127.0.0.1'}


def _validate_urls(data, proxy_port):
    ports = {proxy_port}
    for label, url in data['urls'].items():
        u = urlsplit(url); leaf = label.split('/')[1]
        if (u.scheme != 'https' or u.hostname != HOSTS[leaf] or u.username or u.password
                or u.path != '/' or u.query or u.fragment or not u.port or not 1024 <= u.port <= 65535
                or u.port in ports):
            raise ValueError(f'invalid or duplicate URL: {label}')
        ports.add(u.port)


def checked_manifest(path):
    repo = Path(__file__).resolve().parents[4]
    scratch = repo / '.scratch'
    if scratch.is_symlink() or path.is_symlink():
        raise ValueError('scratch or manifest is a symlink')
    path = path.resolve(strict=True)
    run = path.parent
    if (run.parent != scratch.resolve(strict=True) or not run.name.startswith('e1-browser-')
            or path.name != 'manifest.json' or not path.is_file()):
        raise ValueError('manifest must be inside a private e1-browser directory under this worktree scratch')
    st = run.stat()
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError('fixture directory must be owned by this user and mode 0700')
    data = json.loads(path.read_text())
    proxy = data['proxy']
    if not isinstance(proxy, str) or not re.fullmatch(r'127\.0\.0\.1:\d{1,5}', proxy, re.ASCII):
        raise ValueError('proxy must be an IPv4 loopback address')
    proxy_port = int(proxy.split(':')[1])
    if not 1024 <= proxy_port <= 65535: raise ValueError('invalid proxy port')
    if not re.fullmatch(r'[0-9a-f]{24}', data['marker']): raise ValueError('invalid fixture marker')
    expected = {f'{v}/{leaf}' for v in ('E', 'X') for leaf in HOSTS}
    if set(data['urls']) != expected: raise ValueError('manifest must contain exactly six fixture URLs')
    _validate_urls(data, proxy_port)
    copies = {}
    for variant in ('E', 'X'):
        ca = run / 'ca' / f'{variant}.pem'
        if ca.is_symlink() or ca.parent.is_symlink() or ca.resolve(strict=True) != ca or not ca.is_file():
            raise ValueError(f'unsafe {variant} CA path')
        if data['ca_files'][variant] != str(ca): raise ValueError(f'{variant} CA path does not match manifest')
        pem = ca.read_bytes()
        digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode('ascii'))).hexdigest()
        if digest != data['ca_sha256'][variant]: raise ValueError(f'{variant} CA fingerprint mismatch')
        copies[variant] = pem
    if data['ca_sha256']['E'] == data['ca_sha256']['X']: raise ValueError('CAs are not distinct')
    return run, data, copies


def prepare(run, data, copies):
    scratch = run.parent
    chrome = Path(tempfile.mkdtemp(prefix='e1-chrome-', dir=scratch))
    inode = chrome.stat().st_ino
    try:
        for name in ('home', 'config', 'data', 'cache', 'state', 'profile', 'ca'):
            (chrome / name).mkdir(mode=0o700)
        (chrome / 'cache' / 'tmp').mkdir(mode=0o700)
        (chrome / 'config' / 'google-chrome').mkdir(mode=0o700)
        (chrome / 'home' / '.local' / 'share' / 'pki').mkdir(parents=True, mode=0o700)
        for v, pem in copies.items():
            cert = chrome / 'ca' / f'{v}.pem'
            with cert.open('xb') as f: f.write(pem)
            cert.chmod(0o600)
        cmd = ['flatpak', 'run', '--sandbox', '--session-bus', '--share=network', '--share=ipc',
               '--socket=wayland', '--socket=fallback-x11']
        for name in ('home', 'config', 'data', 'cache', 'state', 'profile'):
            cmd.append(f'--filesystem={chrome / name}')
        cmd.append(f'--filesystem={chrome / "ca"}:ro')
        for key, folder in [('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'), ('XDG_DATA_HOME', 'data'),
                            ('XDG_CACHE_HOME', 'cache'), ('XDG_STATE_HOME', 'state')]:
            cmd.append(f'--env={key}={chrome / folder}')
        cmd += ['com.google.Chrome', f'--user-data-dir={chrome / "profile"}',
                f'--proxy-server=http://{data["proxy"]}', '--proxy-bypass-list=<-loopback>',
                '--no-first-run', '--no-default-browser-check']
        launcher = chrome / 'launch-chrome.sh'
        with launcher.open('x') as f: f.write('#!/bin/sh\nexec </dev/null\nexec ' + shlex.join(cmd) + '\n')
        launcher.chmod(0o700)
        manifest = chrome / 'manifest.json'
        result = {'proxy': data['proxy'], 'urls': data['urls'], 'marker': data['marker'],
                  'ca_sha256': data['ca_sha256'], 'ca_files': {v: str(chrome / 'ca' / f'{v}.pem') for v in copies},
                  'chrome_user_data_dir': str(chrome / 'profile'), 'chrome_home': str(chrome / 'home'),
                  'chrome_launcher': str(launcher)}
        with manifest.open('x') as f: json.dump(result, f, indent=2); f.write('\n')
        manifest.chmod(0o600)
        return manifest, launcher
    except BaseException:
        if not chrome.is_symlink() and chrome.parent == scratch and chrome.stat().st_ino == inode:
            shutil.rmtree(chrome)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    run, data, copies = checked_manifest(args.manifest)
    manifest, launcher = prepare(run, data, copies)
    print(f'Chrome scratch prepared\nManifest: {manifest}\nChrome launcher: {launcher}')


if __name__ == '__main__':
    try: main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f'Chrome preparation failed: {exc}')
