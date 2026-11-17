#!/usr/bin/env python3
"""Isolated Postgres host-authentication check. Requires a serialized Podman test lease.

Uses only a unique test pod, volume, containers and secrets. No global oc-sandbox
setup/teardown, host trust store, systemd, real credentials, or installed checkout.
"""
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time

repo = Path(__file__).resolve().parents[1]
source = repo / 'oc-sandbox'
image = 'docker.io/library/postgres:17'
helper_image = 'python:3.12-alpine'
prefix = 'oc-pgtest-' + secrets.token_hex(8)
password = 'fixture:password\\value'
user = db = 'pgtest'
host = ['distrobox-host-exec'] if os.environ.get('CONTAINER_ID') else []
checks = 0
containers, pods, secret_ids, volumes = [], [], [], []

def run(args, *, input=None, ok=True, timeout=30):
    r = subprocess.run(host + ['podman'] + args, input=input, text=True, stdin=subprocess.DEVNULL if input is None else None,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if ok and r.returncode:
        raise RuntimeError(f'Podman {args[0]} failed (exit {r.returncode}): ' + r.stderr.replace(password, '<redacted>'))
    return r

def check(label, result):
    global checks
    if not result:
        raise AssertionError(label)
    checks += 1
    print('PASS ' + label, flush=True)

def secret(name, data):
    r = run(['secret', 'create', name, '-'], input=data)
    sid = r.stdout.strip()
    if not sid:
        raise RuntimeError('secret creation returned no ID')
    secret_ids.append(sid)
    return sid

def container(args):
    cidfile = test_scratch / f'container-{len(containers)}.id'
    r = run(['run', '-d', '--cidfile', str(cidfile)] + args)
    cid = r.stdout.strip()
    if not cid:
        raise RuntimeError('container creation returned no ID')
    containers.append(cid)
    return cid

def wait_ready(cid):
    for _ in range(60):
        if run(['exec', cid, 'pg_isready', '-h', '/var/run/postgresql', '-U', user, '-d', db, '-q'], ok=False).returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError('Postgres did not become ready')

def source_function(name):
    text = source.read_text()
    start = text.index(name + '() {')
    return text[start:text.index('\n}', start) + 2]

def main(scratch):
    for img in (image, helper_image):
        if run(['image', 'exists', img], ok=False).returncode:
            raise RuntimeError('required local image unavailable: ' + img)
    # Confirm our entire random prefix is unused before any creation.
    for args in (['pod', 'ls', '--format', '{{.Name}}'], ['ps', '-a', '--format', '{{.Names}}'],
                 ['volume', 'ls', '--format', '{{.Name}}'], ['secret', 'ls', '--format', '{{.Name}}']):
        if prefix in run(args).stdout:
            raise RuntimeError('test prefix already in use')
    # Host loopback only; bind-and-release a kernel-selected port, then Podman checks it again.
    py = 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
    port = int(subprocess.check_output(host + ['python3', '-c', py], stdin=subprocess.DEVNULL, text=True, timeout=10).strip())
    podfile = scratch / 'pod.id'
    pod = run(['pod', 'create', '--name', prefix + '-pod', '--pod-id-file', str(podfile),
               '--network', 'pasta:--host-lo-to-ns-lo', '--label', f'oc.ports={port}:5432',
               '-p', f'127.0.0.1:{port}:5432']).stdout.strip()
    pods.append(pod)
    bindings = run(['pod', 'inspect', '--format', '{{json .InfraConfig.PortBindings}}', pod]).stdout.strip()
    bindcheck = scratch / 'bindcheck.sh'
    bindcheck.write_text('#!/usr/bin/env bash\n' + source_function('validate_existing_ports') + '\nvalidate_existing_ports "$1" "$2" "$3"\n')
    def validate(label, pg):
        return subprocess.run(['bash', str(bindcheck), bindings, label, pg], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode
    check('actual pod mapping accepted with -p and matching label', validate(f'{port}:5432', '1') == 0)
    check('actual pod mapping rejected without -p', validate(f'{port}:5432', '0') != 0)
    check('hidden actual pod mapping rejected', validate('', '1') != 0)
    good = prefix + '-host-good'; bad = prefix + '-host-bad'
    esc = password.replace('\\', '\\\\').replace(':', '\\:')
    secret(good, f'127.0.0.1:{port}:{db}:{user}:{esc}\n')
    secret(bad, f'127.0.0.1:{port}:{db}:{user}:wrong-fixture-password\n')
    client = container(['--name', prefix + '-host-client', '--network', 'host',
                        '--secret', f'{good},target=/run/secrets/good,mode=0600',
                        '--secret', f'{bad},target=/run/secrets/bad,mode=0600',
                        '--entrypoint', 'sleep', image, '600'])
    def psql(passfile):
        return run(['exec', '-e', 'PGPASSFILE=' + passfile, client, 'psql', '-w', '-X', '-h', '127.0.0.1',
                    '-p', str(port), '-U', user, '-d', db, '-Atqc', 'SELECT 1'], ok=False, timeout=10)
    # Use the actual implementation function, with a pm wrapper that records every
    # created container/secret ID. Inputs and all synthetic passwords stay in stdin/files.
    state = scratch / 'state'; state.mkdir()
    registry = scratch / 'ids'; registry.write_text('')
    script = scratch / 'exercise.sh'
    shell_functions = '\n'.join(source_function(n) for n in ('pg_sig', 'urlenc', 'pgpass_field', 'create_pg_auth_secrets', 'ensure_postgres'))
    script.write_text('''#!/usr/bin/env bash
set -euo pipefail
H=(); if [[ -n ${CONTAINER_ID:-} ]]; then H=(distrobox-host-exec); fi
pm() {
  case "$1 ${2:-}" in
    'secret create'|'run -d')
      local id; id=$("${H[@]}" podman "$@") || return $?
      printf '%s %s\\n' "$1" "$id" >> "$REGISTRY"
      printf '%s\\n' "$id" ;;
    *) "${H[@]}" podman "$@" ;;
  esac
}
cstate() { pm container inspect --format '{{.State.Status}}' "$1" 2>/dev/null || echo none; }
log() { :; }
''' + shell_functions + '''
STATE=$TEST_STATE POD=$TEST_POD PGC=$TEST_PGC PGVOL=$TEST_VOL
PGSECRET=$TEST_RAW PGPASSSECRET=$TEST_PASS PGHBASECRET=$TEST_HBA
PG_INIT=$TEST_INIT INST= ILABEL=$TEST_OWNER PG_IMAGE=$TEST_IMAGE
PG_USER=pgtest PG_DB=pgtest PG_PASSWORD='fixture:password\\value' PORTS=("$TEST_PORT:5432")
ensure_postgres
''')
    script.chmod(0o700)
    env = {**os.environ, 'REGISTRY': str(registry), 'TEST_STATE': str(state), 'TEST_POD': pod,
           'TEST_PGC': prefix + '-postgres', 'TEST_VOL': prefix + '-volume', 'TEST_RAW': prefix + '-raw',
           'TEST_PASS': prefix + '-pass', 'TEST_HBA': prefix + '-hba', 'TEST_INIT': str(scratch / 'no-init'),
           'TEST_OWNER': prefix, 'TEST_IMAGE': image, 'TEST_PORT': str(port)}
    volumes.append(prefix + '-volume')
    def exercise():
        return subprocess.run(['bash', str(script)], env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    def collect_ids():
        for line in registry.read_text().splitlines():
            kind, ident = line.split(' ', 1)
            if kind == 'run' and ident not in containers: containers.append(ident)
            if kind == 'secret' and ident not in secret_ids: secret_ids.append(ident)
    def observed_start():
        samples = []
        stop = threading.Event()
        def monitor():
            while not stop.is_set():
                samples.append(psql('/dev/null').returncode)
                stop.wait(.15)
        t = threading.Thread(target=monitor); t.start()
        try:
            for _ in range(100):
                if samples: break
                time.sleep(.05)
            before = len(samples)
            r = exercise()
            during = len(samples) - before
            time.sleep(1)
            after = len(samples) - before - during
        finally:
            stop.set(); t.join(timeout=15)
        if t.is_alive(): raise RuntimeError('authentication monitor did not stop')
        collect_ids()
        check('no passwordless connection observed during startup', before > 0 and during > 0 and after > 0 and all(x != 0 for x in samples))
        print(f'  no-password probes: {before} before, {during} during, {after} after', flush=True)
        return r
    first = observed_start()
    check('new volume starts with authenticated TCP', first.returncode == 0)
    check('no password rejected after readiness', psql('/dev/null').returncode != 0)
    check('wrong password rejected', psql('/run/secrets/bad').returncode != 0)
    check('correct password succeeds', psql('/run/secrets/good').stdout.strip() == '1')
    check('server uses script-owned HBA', run(['exec', prefix + '-postgres', 'psql', '-X', '-h', '/var/run/postgresql', '-U', user, '-d', db, '-Atqc', 'SHOW hba_file']).stdout.strip() == '/run/secrets/oc-pg-hba')
    original_id = run(['container', 'inspect', '--format', '{{.Id}}', prefix + '-postgres']).stdout.strip()
    again = exercise()
    collect_ids()
    same_id = run(['container', 'inspect', '--format', '{{.Id}}', prefix + '-postgres']).stdout.strip()
    check('rerun preserves a running secure Postgres and working passfile', again.returncode == 0 and original_id == same_id and psql('/run/secrets/good').stdout.strip() == '1')
    # Exercise the real plain-relaunch verifier with the fixture server and secret.
    passcheck = scratch / 'passcheck.sh'
    passcheck.write_text("""#!/usr/bin/env bash
set -euo pipefail
H=(); if [[ -n ${CONTAINER_ID:-} ]]; then H=(distrobox-host-exec); fi
pm() { "${H[@]}" podman "$@"; }
cstate() { pm container inspect --format '{{.State.Status}}' "$1" 2>/dev/null || echo none; }
die() { echo "$*" >&2; exit 2; }
""" + source_function('agent_pg_passfile') + """
PG=0; PGC=$TEST_PGC; PGPASSSECRET=$TEST_PASS; ILABEL=$TEST_OWNER; AGENT_IMG=$TEST_HELPER
agent_pg_passfile
""")
    pass_env = {**env, 'TEST_HELPER': helper_image}
    def verify_passfile():
        return subprocess.run(['bash', str(passcheck)], env=pass_env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
    check('plain relaunch verifies current managed passfile', verify_passfile().returncode == 0)
    pass_name = prefix + '-pass'
    original_secret = run(['secret', 'inspect', '--format', '{{.ID}}', pass_name]).stdout.strip()
    run(['secret', 'rm', original_secret])
    check('plain relaunch rejects missing passfile secret', verify_passfile().returncode != 0)
    wrong_id = secret(pass_name, '127.0.0.1:5432:pgtest:pgtest:wrong-fixture-password\n')
    check('plain relaunch rejects replaced passfile secret', verify_passfile().returncode != 0)
    run(['secret', 'rm', wrong_id])
    secret(pass_name, f'127.0.0.1:5432:{db}:{user}:{esc}\n')
    check('plain relaunch accepts restored passfile secret', verify_passfile().returncode == 0)
    run(['exec', prefix + '-postgres', 'psql', '-X', '-h', '/var/run/postgresql', '-U', user, '-d', db, '-c', 'CREATE TABLE oc_pgtest_marker (id integer)'])
    # Verify the actual private passfile mount and TCP login in a separate container in the pod.
    cfile = scratch / 'client.id'
    r = run(['run', '--rm', '--cidfile', str(cfile), '--name', prefix + '-agent-check', '--pod', pod,
             '--secret', f'{prefix}-pass,target=/run/secrets/oc-pgpass,mode=0600', '-e', 'PGPASSFILE=/run/secrets/oc-pgpass',
             '--entrypoint', 'sh', image, '-c', 'test "$(stat -c %a "$PGPASSFILE")" = 600 && psql -w -X -h 127.0.0.1 -U pgtest -d pgtest -Atqc "SELECT 1"'])
    check('agent passfile is 0600 and authenticates without a prompt', r.stdout.strip() == '1')
    run(['stop', '-t', '5', prefix + '-postgres'])
    # Place an explicitly insecure old HBA in the stopped volume. It must be ignored.
    run(['run', '--rm', '--cidfile', str(scratch / 'writer.id'), '--network', 'none', '--name', prefix + '-hba-writer',
         '-v', prefix + '-volume:/data:Z', '--entrypoint', 'sh', helper_image, '-c',
         "printf 'local all all trust\\nhost all all 0.0.0.0/0 trust\\n' > /data/pg_hba.conf"])
    restarted = observed_start()
    check('existing volume with trust HBA starts under enforced HBA', restarted.returncode == 0)
    check('existing trust file does not allow passwordless TCP', psql('/dev/null').returncode != 0)
    check('volume still contains the ignored trust HBA', run(['exec', prefix + '-postgres', 'sh', '-c', 'grep -q "^host all all 0.0.0.0/0 trust$" "$PGDATA/pg_hba.conf"'], ok=False).returncode == 0)
    check('existing data remains available', run(['exec', prefix + '-postgres', 'psql', '-X', '-h', '/var/run/postgresql', '-U', user, '-d', db, '-Atqc', "SELECT to_regclass('oc_pgtest_marker') IS NOT NULL"]).stdout.strip() == 't')
    # Simulate a legacy MD5 verifier on the existing volume without putting the
    # synthetic password in argv or logs. Unix trust is confined to PG's socket.
    sql = "SET password_encryption='md5'; ALTER ROLE pgtest PASSWORD 'fixture:password\\value';\n"
    run(['exec', '-i', prefix + '-postgres', 'psql', '-X', '-h', '/var/run/postgresql', '-U', user, '-d', db, '-v', 'ON_ERROR_STOP=1', '-f', '-'], input=sql)
    check('test volume now has a legacy MD5 verifier', run(['exec', prefix + '-postgres', 'psql', '-X', '-h', '/var/run/postgresql', '-U', user, '-d', db, '-Atqc', "SELECT rolpassword LIKE 'md5%' FROM pg_authid WHERE rolname=current_user"]).stdout.strip() == 't')
    run(['stop', '-t', '5', prefix + '-postgres'])
    failed = observed_start()
    check('legacy MD5 verifier fails closed with a clear error', failed.returncode != 0 and 'SCRAM login failed' in failed.stderr)
    check('failed verifier leaves Postgres stopped', run(['container', 'inspect', '--format', '{{.State.Status}}', prefix + '-postgres']).stdout.strip() != 'running')
    check('existing data volume is retained', run(['volume', 'exists', prefix + '-volume'], ok=False).returncode == 0)
    # Restart only the script-created SCRAM-HBA container to inspect retained data
    # over its private Unix socket; no plaintext-authentication TCP window opens.
    run(['start', prefix + '-postgres']); wait_ready(prefix + '-postgres')
    check('legacy verifier failure preserves existing table', run(['exec', prefix + '-postgres', 'psql', '-X', '-h', '/var/run/postgresql', '-U', user, '-d', db, '-Atqc', "SELECT to_regclass('oc_pgtest_marker') IS NOT NULL"]).stdout.strip() == 't')
    check('legacy verifier never opens passwordless TCP', psql('/dev/null').returncode != 0)
    print(f'{checks} passed, 0 failed', flush=True)

# Never remove a resource by a broad filter. The test pod/containers/secrets are
# removed only by IDs recorded when created; the volume name is checked by label.
base = repo / '.scratch'
if base.is_symlink(): raise RuntimeError('scratch is a symlink')
base.mkdir(exist_ok=True)
start_hash = hashlib.sha256(source.read_bytes()).hexdigest()
print('oc-sandbox sha256:', start_hash, flush=True)
cleanup_failed = False
with tempfile.TemporaryDirectory(prefix='postgres-real.', dir=base) as temp:
    scratch = Path(temp).resolve()
    test_scratch = scratch
    print('owned test prefix:', prefix, flush=True)
    try:
        main(scratch)
        if hashlib.sha256(source.read_bytes()).hexdigest() != start_hash:
            raise RuntimeError('source changed during the test')
    finally:
        registry = scratch / 'ids'
        if registry.exists():
            for line in registry.read_text().splitlines():
                kind, ident = line.split(' ', 1)
                if kind == 'run' and ident not in containers: containers.append(ident)
                if kind == 'secret' and ident not in secret_ids: secret_ids.append(ident)
        for idfile in list(scratch.glob('container-*.id')) + [scratch / 'client.id', scratch / 'writer.id']:
            if idfile.exists():
                ident = idfile.read_text().strip()
                if ident and ident not in containers: containers.append(ident)
        podfile = scratch / 'pod.id'
        if podfile.exists():
            ident = podfile.read_text().strip()
            if ident and ident not in pods: pods.append(ident)
        for ident in reversed(containers):
            state = run(['container', 'exists', ident], ok=False)
            if state.returncode == 0:
                if run(['rm', '-f', '-t', '0', ident], ok=False).returncode: cleanup_failed = True
            elif state.returncode != 1: cleanup_failed = True
        for ident in reversed(pods):
            state = run(['pod', 'exists', ident], ok=False)
            if state.returncode == 0:
                if run(['pod', 'rm', '-f', '-t', '0', ident], ok=False).returncode: cleanup_failed = True
            elif state.returncode != 1: cleanup_failed = True
        secret_list = run(['secret', 'ls', '--format', '{{.ID}}'], ok=False)
        if secret_list.returncode:
            cleanup_failed = True
        else:
            existing = set(secret_list.stdout.split())
            for ident in reversed(secret_ids):
                if ident in existing and run(['secret', 'rm', ident], ok=False).returncode: cleanup_failed = True
        for name in volumes:
            state = run(['volume', 'exists', name], ok=False)
            if state.returncode == 0:
                label = run(['volume', 'inspect', '--format', '{{index .Labels "oc.instance"}}', name], ok=False)
                if label.returncode or label.stdout.strip() != prefix or run(['volume', 'rm', name], ok=False).returncode: cleanup_failed = True
            elif state.returncode != 1: cleanup_failed = True
        print('owned-resource cleanup:', 'FAILED' if cleanup_failed else 'complete', flush=True)
        if cleanup_failed:
            print('test prefix for inspection:', prefix, flush=True)
            raise SystemExit(1)
