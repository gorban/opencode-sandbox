#!/usr/bin/env python3
"""Run isolated regressions against a supplied probe.sh and sibling lockcmp.py."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

probe = Path(sys.argv[1]).resolve()
source = probe.read_text()
lockcmp = probe.with_name('lockcmp.py')

def run(*args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, **kwargs)

with tempfile.TemporaryDirectory(prefix='f-regression-') as tmp:
    w = Path(tmp)
    # Exercise the real source lines in a harmless shell with command stubs and hostile paths.
    marker = w / 'injected'
    bad = str(w / ("quote'$(touch " + str(marker) + ")'"))
    lines = [line for line in source.splitlines() if ('bash -c ' in line and ('regenerated lock equals' in line or 'lockcmp.py detects' in line or 'mise config ls' in line))]
    assert len(lines) == 5
    shell = '''expect_ok() { shift; "$@"; }; expect_fail() { shift 2; "$@"; }; expect_text() { shift 2; "$@"; }; expect_not_text() { shift 2; "$@"; }; run() { "$@"; }; mise() { :; }; shorten() { cat; }; export -f mise
SCRATCH=$1; HERE=$1; P=$1; mkdir -p "$1/regen"; : > "$1/mise.lock"; : > "$1/regen/mise.lock"; : > "$1/lockcmp.py"
''' + '\n'.join(lines) + '\n'
    run('bash', '-c', shell, '_', bad)
    assert not marker.exists(), 'shell executed a path as code'
    assert '"$PROBE_REALCU"' in source and '"$PROBE_SUDOLOG"' in source, 'generated shell embeds paths'

    fixture = '''lockfile_version=3
[[tools.demo]]
version="1"
backend="aqua:demo/demo"
[tools.demo."platforms.linux-x64"]
url="https://example.invalid/v1"
checksum="sha256:1111"
[[tools.demo]]
version="2"
backend="aqua:demo/demo"
[tools.demo."platforms.linux-x64"]
url="https://example.invalid/v2"
checksum="sha256:2222"
'''
    a, b = w / 'a.lock', w / 'b.lock'
    a.write_text(fixture); b.write_text(fixture.replace('sha256:1111', 'sha256:evil'))
    for flags in ([], ['--strict']):
        assert run('python3', '-I', str(lockcmp), *flags, str(a), str(b)).returncode == 1, 'multi-version checksum ignored'
    b.write_text('future_field="changed"\n' + fixture)
    assert run('python3', '-I', str(lockcmp), '--strict', str(a), str(b)).returncode == 1, 'strict top-level field ignored'

    b.write_text(fixture + '\n[tools.empty]\n')
    assert run('python3', '-I', str(lockcmp), '--strict', str(a), str(b)).returncode == 1, 'strict empty structure ignored'

    begin = source.index('record_valid() {') if 'record_valid() {' in source else source.index('ts_install() {')
    end = source.index('CAFP=$(fp_of_pem', begin)
    code = '''SCRATCH=$1; RECORD=$1/record; TNICK=nick; TAB=$'\\t'; mkdir -p "$1/state"; : > "$RECORD"; printf '%064d\n' 0 > "$1/current"
fp_of_pem() { printf '%064d\n' 0; }; nick_fps() { cat "$SCRATCH/current" 2>/dev/null; }; mx() { [ "$2" = -D ] && rm -f "$SCRATCH/current"; }
''' + source[begin:end] + '''
ts_install "$SCRATCH/db" "$SCRATCH/cert" || exit 2
[ ! -s "$RECORD" ] || exit 3
ts_remove_all || exit 4
[ -f "$SCRATCH/current" ] || exit 5
'''
    result = run('bash', '-c', code, '_', str(w))
    assert result.returncode == 0, 'pre-existing certificate was claimed or removed'

    # A refusal must happen before any certificate call; malformed records must survive byte-for-byte.
    defs = source[begin:end]
    harness = r'''SCRATCH=$1; RECORD=$1/record2; TNICK=$2; DB=$3; TAB=$'\t'; mkdir -p "$1/state"
fp_of_pem() { printf '%064d\n' 0; }; nick_fps() { echo called >> "$SCRATCH/calls"; }; mx() { echo called >> "$SCRATCH/calls"; return 0; }
''' + defs + r'''
case $4 in install) ts_install "$DB" "$SCRATCH/cert" ;; remove) ts_remove_all ;; esac
'''
    clean = b''
    for kind, nick, db in [('tab-path', 'nick', str(w / 'db\tbad')), ('newline-path', 'nick', str(w / 'db\nbad')), ('tab-nick', 'nick\tbad', str(w / 'db')), ('newline-nick', 'nick\nbad', str(w / 'db'))]:
        (w / 'record2').write_bytes(clean)
        (w / 'calls').unlink(missing_ok=True)
        result = run('bash', '-c', harness, '_', str(w), nick, db, 'install')
        assert result.returncode != 0 and not (w / 'calls').exists() and (w / 'record2').read_bytes() == clean, kind + ' was not refused before certificate access'
    valid = (str(w / 'db') + '\tnick\t' + '0' * 64 + '\n').encode()
    for malformed in [valid + b'broken\n', valid + b'/truncated\tnick\t', valid + b'/bad\tnick\txyz\n', valid + b'/a\tb\tc\td\n']:
        for op in ('install', 'remove'):
            (w / 'record2').write_bytes(malformed)
            (w / 'calls').unlink(missing_ok=True)
            result = run('bash', '-c', harness, '_', str(w), 'nick', str(w / 'db'), op)
            assert result.returncode != 0 and not (w / 'calls').exists() and (w / 'record2').read_bytes() == malformed, 'malformed record changed or certificate accessed'

print('isolated regressions passed')
