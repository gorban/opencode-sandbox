#!/usr/bin/env python3
"""Exercise failed row setup using only fake commands and private fixtures.
Pass a directory containing clients/psql.sh and clients/nss_certutil.sh to test an old revision.
"""
import os, pathlib, signal, subprocess, sys, tempfile

def run_fixture(args, *, env, timeout=10):
    """Run only fixture commands in a private session; never signal the caller's group."""
    proc = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except BaseException:
        # The session and process group were created exclusively for this child. Kill
        # the group even if its leader has exited but a descendant still holds a pipe.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            # Do not wait forever if a broken fixture leaves a pipe open.
            proc.stdout.close()
            proc.stderr.close()
            proc.wait(timeout=3)
        raise
    return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)


def main():
    src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).parent).resolve()
    with tempfile.TemporaryDirectory() as td:
        t = pathlib.Path(td); w = t/'w'; (w/'leaf'/'atk').mkdir(parents=True); (w/'ca'/'A').mkdir(parents=True)
        (t/'pgdata').mkdir(); (t/'pgssl').mkdir(); (t/'bin').mkdir()
        for p in (w/'leaf'/'atk'/'A.pem', w/'leaf'/'atk'/'A.chain.pem', w/'leaf'/'atk'/'key.pem', w/'ca'/'A'/'ca.pem'):
            p.write_text('fixture\n')
        (w/'variants.tsv').write_text('A\tconstraint\n')
        (w/'leaves.tsv').write_text('atk\tname\tsan\tname\ttwin\n')
        (w/'combos.tsv').write_text('A\tatk\t20000\tname\tdns\n')
        (t/'pgdata'/'pg_hba.conf').touch()
        def stub(name, content):
            p=t/'bin'/name; p.write_text('#!/bin/bash\n'+content+'\n'); p.chmod(0o755)
        stub('pg_ctl', '[[ ${TEST_SCENARIO:-} == stale ]] && exit 0; exit 1')
        stub('psql', 'if [[ ${1:-} == --version ]]; then echo "psql (PostgreSQL) 17"; exit 0; fi; echo "psql: error: SSL error: certificate verify failed"; exit 1')
        stub('rpm', 'echo 3')
        stub('certutil', '''
    case " $* " in
      *" -A "*" -n chain "*) if [[ ${TEST_SCENARIO:-} == import ]]; then echo "forced chain import failure" >&2; exit 1; fi;;
      *" -L "*) if [[ ${TEST_SCENARIO:-} == nss_mismatch && " $* " == *" -n chain "* ]]; then echo different; else echo fixture; fi;;
      *" -V "*) echo "certutil: certificate is invalid: Peer's Certificate issuer is not recognized."; exit 1;;
    esac
    exit 0''')
        stub('openssl', '''
    case "${1:-}" in
      version) echo 'OpenSSL fixture 0.0';;
      s_client) echo served;;
      x509)
        if [[ " $* " == *" -fingerprint "* ]]; then
          if [[ " $* " == *" -in "* ]]; then echo expected; else cat >/dev/null; echo stale; fi
        else
          if [[ " $* " == *" -in "* ]]; then echo fixture; else cat; fi
        fi;;
      *) echo "unsupported openssl fixture command: ${1:-<none>}" >&2; exit 2;;
    esac''')
        env={**os.environ, 'PATH': str(t/'bin')+':/usr/bin:/bin'}
        for name, scenario, expected in (
            ('psql.sh', 'restart', 'postgres restart failed for A/atk'),
            ('psql.sh', 'stale', 'stale postgres certificate for A/atk'),
            ('nss_certutil.sh', 'import', f'import chain failed: {w}/leaf/atk/A.chain.pem'),
            ('nss_certutil.sh', 'nss_mismatch', f'import chain fingerprint mismatch: {w}/leaf/atk/A.chain.pem'),
        ):
            script=(src/'clients'/name).read_text().replace('/tmp/pgdata', str(t/'pgdata')).replace('/tmp/pgssl', str(t/'pgssl')).replace('/tmp/nss-', str(t/'nss-')).replace('/tmp/pg.log', str(t/'pg.log')).replace('/w/', str(w)+'/')
            path=t/name; path.write_text(script)
            result=run_fixture(['bash', str(path)], env={**env, 'TEST_SCENARIO': scenario})
            if result.returncode == 0 or result.stdout.strip():
                raise SystemExit(f'{name} {scenario}: failed setup emitted a cell or returned success: rc={result.returncode}, stdout={result.stdout!r}')
            if expected not in result.stderr.splitlines():
                raise SystemExit(f'{name} {scenario}: failed for unexpected reason: {result.stderr!r}')
            print(f'{name} {scenario}: failed setup aborted without a result cell')
        # A missing attack chain must not turn offline verification into a different test.
        (w/'leaf'/'atk'/'A.chain.pem').unlink()
        script=(src/'clients'/'openssl_verify.sh').read_text()
        path=t/'openssl_verify.sh'; path.write_text(script)
        result=run_fixture(['bash', str(path), str(t/'bin'/'openssl')], env={**env, 'OC_W': str(w)})
        if result.returncode == 0 or result.stdout.strip() or 'missing chain A/atk' not in result.stderr.splitlines():
            raise SystemExit(f'openssl_verify: missing chain not rejected: rc={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}')
        print('openssl_verify missing chain: aborted without a result cell')


if __name__ == "__main__":
    main()
