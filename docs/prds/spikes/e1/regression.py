#!/usr/bin/env python3
"""Offline regressions. Pass the e1 script directory to test a historical copy."""
import os, pathlib, subprocess, sys, tempfile

src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).parent).resolve()
errors = {
    'openssl-verify-4.0': 'permitted subtree violation',
    'openssl-verify+host-4.0': 'excluded subtree violation',
    'openssl-verify-3.5': 'path length constraint exceeded',
    'openssl-verify+host-3.5': 'permitted subtree violation',
    'openssl-s_client-3.5': 'num=47:permitted subtree violation',
    'curl-8': 'SSL certificate problem: permitted subtree violation',
    'py-3': 'permitted subtree violation',
    'node-24': 'UNSPECIFIED permitted subtree violation',
    'go-1': 'tls: failed to verify certificate: x509: too many intermediates for path length constraint',
    'psql-17': 'connection to server at "localhost" (127.0.0.1), port 5432 failed: SSL error: certificate verify failed',
    'chromium-157': 'net::ERR_CERT_INVALID',
    'nss-3': "certutil: certificate is invalid: Peer's Certificate issuer is not recognized.",
}
# Host OpenSSL must see the same scratch path as the distrobox.
root = pathlib.Path(subprocess.check_output(
    ['git', '-C', str(pathlib.Path(__file__).resolve().parent), 'rev-parse', '--show-toplevel'], text=True).strip())
scratch = pathlib.Path(os.environ.get('E1_TEST_TMPDIR', root / '.scratch'))
if scratch.is_symlink():
    raise SystemExit('scratch directory must not be a symlink')
scratch.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=scratch) as td:
    w = pathlib.Path(td); (w/'results').mkdir()
    (w/'variants.tsv').write_text('A\tconstraint\nX\t-\n')
    (w/'leaves.tsv').write_text('leaf\tname\tsan\tname\tplain\n')
    (w/'combos.tsv').write_text('A\tleaf\nX\tleaf\n')
    def validate(error=None, target=None):
        rows = []
        for c, detail in errors.items():
            rows += [f'{c}\tA\tleaf\tFAIL\t{error if c == target else detail}', f'{c}\tX\tleaf\tOK\t']
        (w/'results'/'fixture.tsv').write_text('\n'.join(rows)+'\n')
        return subprocess.run([sys.executable, str(src/'matrix.py'), str(w)], stdout=subprocess.DEVNULL).returncode
    assert validate() == 0, 'legitimate verification errors rejected'
    for error in ('net::ERR_SSL_PROTOCOL_ERROR', 'SSL error: wrong version number', 'SSL connect error', 'unknown error'):
        for client in errors:
            assert validate(error, client) != 0, f'{client} accepted invalid TLS error: {error}'
    # The PRD's relative template invocation: run from the directory containing templates.
    for name in ('recommended.sh', 'ca.cnf', 'leaf.cnf'):
        (w/name).write_bytes((src/name).read_bytes())
    nc = 'permitted;DNS:.oc-sandbox.internal,permitted;DNS:oc-sandbox.internal'
    for san in ('DNS:feat-a.oc-sandbox.internal', 'DNS:feat-a.oc-sandbox.internal,DNS:localhost,IP:127.0.0.1,IP:::1'):
        p = subprocess.run(['distrobox-host-exec', 'bash', './recommended.sh', 'out', '.', 'feat-a.oc-sandbox.internal', nc, san], cwd=w, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert p.returncode == 0, 'relative template invocation failed'
    print('matrix verification and relative template regressions passed')
