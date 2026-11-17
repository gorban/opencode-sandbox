#!/usr/bin/env python3
"""Loopback-only TLS fixtures for manual host-browser testing; no browser or trust changes.

From the native host:
  python3 -I /absolute/path/to/host-browser-fixture.py /absolute/path/to/.scratch/e1-run.XXXXXX </dev/null
From the devbox distrobox, run that command on the host instead:
  distrobox-host-exec python3 -I /absolute/path/to/host-browser-fixture.py /absolute/path/to/.scratch/e1-run.XXXXXX </dev/null
Prints paths to a private manifest and Firefox launcher. Keep this process in the foreground;
SIGINT, SIGTERM or the bounded lifetime closes its listeners. The private scratch profile
and public CA copies are retained for inspection. Never import either CA globally.
"""
import argparse
import hashlib
import http.server
import json
import secrets
import shlex
import shutil
import select
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import tempfile
from pathlib import Path

HOST = '127.0.0.1'
NAMES = {'feat': 'feat-a.oc-sandbox.internal', 'evil': 'evil.example.com', 'ip127': '127.0.0.1'}


def asset(root, rel):
    p = root / rel
    if p.resolve(strict=True) != p or not p.is_file():
        raise ValueError(f'asset must be a regular file without symlinks: {p}')
    return p


def checked_assets(path, stop):
    repo = Path(__file__).resolve().parents[4]
    scratch = repo / '.scratch'
    if scratch.is_symlink() or path.is_symlink():
        raise ValueError('scratch and run directory must not be symlinks')
    root = path.resolve(strict=True)
    if root.parent != scratch.resolve(strict=True) or not root.name.startswith('e1-run.'):
        raise ValueError('assets must be an e1-run directory directly under this worktree .scratch')
    cas = {v: asset(root, f'ca/{v}/ca.pem') for v in ('E', 'X')}
    leaves = {(v, l): (asset(root, f'leaf/{l}/{v}.pem'), asset(root, f'leaf/{l}/key.pem'))
              for v in cas for l in NAMES}
    contexts = {}
    for (v, leaf), (cert, key) in leaves.items():
        if stop.is_set(): raise InterruptedError("stopped during certificate preflight")
        # Confirm the test setup itself before publishing an endpoint.
        result = subprocess.run(['openssl', 'verify', '-CAfile', str(cas[v]), '-verify_ip' if leaf == 'ip127' else '-verify_hostname',
                                 NAMES[leaf], str(cert)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        if stop.is_set(): raise InterruptedError("stopped during certificate preflight")
        expected_error = {'evil': 'permitted subtree violation', 'ip127': 'excluded subtree violation'}.get(leaf) if v == 'E' else None
        if expected_error:
            if result.returncode == 0 or expected_error not in result.stderr.lower():
                raise ValueError(f'{v}/{leaf} did not fail with {expected_error}')
        elif result.returncode != 0:
            raise ValueError(f'{v}/{leaf} failed certificate verification: {result.stderr.strip()}')
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))  # validates cert/key pair
        contexts[v, leaf] = ctx
    fingerprints = {}
    for v, ca in cas.items():
        der = ssl.PEM_cert_to_DER_cert(ca.read_text())
        fingerprints[v] = hashlib.sha256(der).hexdigest()
    if fingerprints['E'] == fingerprints['X']:
        raise ValueError('control and constrained CA must be distinct')
    return cas, contexts, fingerprints


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = False


class TLSHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('Host', '').lower() != f'{self.server.name}:{self.server.server_address[1]}':
            self.send_error(400); return
        body = f'oc-spike-e1 {self.server.label} {self.server.marker}\n'.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def log_message(self, *args):
        pass


class TLSServer(Server):
    def get_request(self):
        conn, addr = self.socket.accept()
        conn.settimeout(5)
        try:
            return self.context.wrap_socket(conn, server_side=True), addr
        except BaseException:
            conn.close()
            raise


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(5)
        header = b''
        while b'\r\n\r\n' not in header and len(header) < 8192:
            data = client.recv(1)
            if not data: return
            header += data
        try:
            if not header.endswith(b'\r\n\r\n'):
                raise ValueError('incomplete or oversized headers')
            first = header.split(b'\r\n', 1)[0].decode('ascii')
            method, authority, version = first.split(' ')
            if method != 'CONNECT' or version not in ('HTTP/1.0', 'HTTP/1.1') or authority not in self.server.routes:
                raise ValueError('not an allowed CONNECT')
            port = self.server.routes[authority]
        except (UnicodeDecodeError, ValueError):
            client.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            return
        # No DNS lookup or arbitrary destination: the only outbound address is loopback.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
            upstream.settimeout(5); upstream.connect((HOST, port))
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            while True:
                ready, _, _ = select.select([client, upstream], [], [], 15)
                if not ready: return
                for source in ready:
                    data = source.recv(65536)
                    if not data: return
                    (upstream if source is client else client).sendall(data)


def prepare_firefox(scratch, cas, proxy_port, data):
    # mkdtemp reserves a new private directory; it never reuses a real browser profile.
    run = Path(tempfile.mkdtemp(prefix='e1-browser-', dir=scratch))
    identity = run.stat().st_ino
    try:
        for name in ('home', 'config', 'data', 'cache', 'state', 'firefox-profile', 'ca'):
            (run / name).mkdir(mode=0o700)
        (run / 'cache' / 'tmp').mkdir(mode=0o700)
        for variant, source in cas.items():
            target = run / 'ca' / f'{variant}.pem'
            with target.open('xb') as f: f.write(source.read_bytes())
            target.chmod(0o600)
            copied = hashlib.sha256(ssl.PEM_cert_to_DER_cert(target.read_text())).hexdigest()
            if copied != data['ca_sha256'][variant]:
                raise ValueError(f'{variant} CA changed during preparation')
        profile = run / 'firefox-profile'
        prefs = {
            'network.proxy.type': 1,
            'network.proxy.http': HOST,
            'network.proxy.http_port': proxy_port,
            'network.proxy.ssl': HOST,
            'network.proxy.ssl_port': proxy_port,
            'network.proxy.no_proxies_on': '',
            'network.proxy.allow_hijacking_localhost': True,
            'network.proxy.failover_direct': False,
            'network.dns.disablePrefetch': True,
            'network.trr.mode': 5,
            'network.prefetch-next': False,
            'network.captive-portal-service.enabled': False,
            'network.connectivity-service.enabled': False,
            'toolkit.telemetry.enabled': False,
            'datareporting.healthreport.uploadEnabled': False,
            'browser.shell.checkDefaultBrowser': False,
            'browser.startup.page': 0,
            'browser.startup.homepage': 'about:blank',
        }
        with (profile / 'user.js').open('x') as f:
            for name, value in prefs.items():
                f.write(f'user_pref({json.dumps(name)}, {json.dumps(value)});\n')
        (profile / 'user.js').chmod(0o600)
        cmd = ['flatpak', 'run', '--sandbox', '--share=network', '--share=ipc',
               '--socket=wayland', '--socket=fallback-x11']
        for name in ('home', 'config', 'data', 'cache', 'state', 'firefox-profile'):
            cmd.append(f'--filesystem={run / name}')
        cmd.append(f'--filesystem={run / "ca"}:ro')
        for env, dirname in [('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'),
                             ('XDG_DATA_HOME', 'data'), ('XDG_CACHE_HOME', 'cache'),
                             ('XDG_STATE_HOME', 'state')]:
            cmd.append(f'--env={env}={run / dirname}')
        cmd += ['org.mozilla.firefox', '--no-remote', '--profile', str(profile)]
        launcher = run / 'launch-firefox.sh'
        with launcher.open('x') as f: f.write('#!/bin/sh\nexec </dev/null\nexec ' + shlex.join(cmd) + '\n')
        launcher.chmod(0o700)
        data['ca_files'] = {v: str(run / 'ca' / f'{v}.pem') for v in cas}
        data['firefox_profile'] = str(profile)
        data['firefox_launcher'] = str(launcher)
        manifest = run / 'manifest.json'
        with manifest.open('x') as f: json.dump(data, f, indent=2); f.write('\n')
        manifest.chmod(0o600)
        return run, manifest, launcher
    except BaseException:
        # Only remove the exact directory mkdtemp created if preparation did not finish.
        if not run.is_symlink() and run.parent == scratch and run.stat().st_ino == identity:
            shutil.rmtree(run)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('assets', type=Path)
    parser.add_argument('--seconds', type=int, default=1800, help='automatic shutdown in 1–1800 seconds')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 1800: parser.error('--seconds must be between 1 and 1800')
    stop = threading.Event()
    def request_stop(_signum, _frame): stop.set()
    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    cas, contexts, fingerprints = checked_assets(args.assets, stop)
    if stop.is_set(): return
    marker = secrets.token_hex(12)
    servers, threads, endpoints = [], [], {}
    try:
        routes = {}
        for (variant, leaf), ctx in contexts.items():
            server = TLSServer((HOST, 0), TLSHandler)
            servers.append(server)
            port = server.server_address[1]
            if port < 1024: raise RuntimeError('unexpected privileged port')
            server.context, server.name, server.label, server.marker = ctx, NAMES[leaf], f'{variant}/{leaf}', marker
            authority = f'{server.name}:{port}'
            routes[authority] = port
            endpoints[server.label] = f'https://{authority}/'
        proxy = Server((HOST, 0), ProxyHandler)
        servers.append(proxy)
        if proxy.server_address[1] < 1024: raise RuntimeError('unexpected privileged proxy port')
        proxy.routes = routes
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.2}, daemon=True)
            thread.start(); threads.append(thread)
        data = {'proxy': f'{HOST}:{proxy.server_address[1]}', 'urls': endpoints,
                'ca_sha256': fingerprints, 'marker': marker, 'expires_seconds': args.seconds}
        run, manifest, launcher = prepare_firefox(Path(args.assets).resolve().parent, cas,
                                                   proxy.server_address[1], data)
        print(f'Fixture ready (loopback only; expires in {args.seconds}s)\n'
              f'Manifest: {manifest}\nFirefox launcher: {launcher}', flush=True)
        stop.wait(args.seconds)
    finally:
        for server in servers[:len(threads)]: server.shutdown()
        for server in servers: server.server_close()
        for thread in threads: thread.join(timeout=2)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'fixture error: {exc}', file=sys.stderr)
        sys.exit(1)
