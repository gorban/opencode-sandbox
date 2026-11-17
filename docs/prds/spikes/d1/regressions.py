#!/usr/bin/env python3
"""Stub-only checks; no Podman or host resources are touched."""
from pathlib import Path
import subprocess
import os
import tempfile

source = Path(os.environ.get('OC_SPIKE_PROBE', Path(__file__).with_name('probe.sh'))).read_text()
def section(start, end):
    return source[source.index(start):source.index(end, source.index(start))]

def run(code):
    return subprocess.run(['bash'], input=code, text=True, capture_output=True, check=True).stdout

base = Path(__file__).resolve().parents[4] / '.scratch'
if base.is_symlink():
    raise RuntimeError('scratch directory must not be a symlink')
base.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=base) as scratch:
    check = section('check_poll() {', '\n# ---- pod construction')
    code = '''set -u
res() { echo "$1"; }
''' + check + f'''
poll={scratch}/poll
: >"$poll"
check_poll "$poll" 0 200 400 || :
printf '100 closed ok\\n300 closed ok\\n500 closed ok\\n' >"$poll"
check_poll "$poll" 1 200 400 || :
check_poll "$poll" 0 200 400 || :
printf '100 closed ok\\n300 closed bad\\n500 closed ok\\n' >"$poll"
check_poll "$poll" 0 200 400 || :
printf '100 closed ok\\n500 closed ok\\n' >"$poll"
check_poll "$poll" 0 200 400 || :
printf '100 closed ok\\n300 leak ok\\n500 closed ok\\n' >"$poll"
check_poll "$poll" 0 200 400 || :
'''
    assert run(code).splitlines() == ['FAIL', 'FAIL', 'PASS', 'FAIL', 'FAIL', 'FAIL']
    cleanup = section('cleanup() {', '\ntrap ')
    create = section('pcreate() {', '\n\n# ---- servers')
    fake_id = 'a' * 64
    code = f'''set -u
BASE_REAL={scratch}; SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX")
P=oc-spike-d1-test; log="$BASE_REAL/log"; : >"$log"
stop_worker() {{ return 0; }}
pm() {{
 if [[ $1 == pod && $2 == create ]]; then return 125; fi
 if [[ $1 == pod && $2 == exists ]]; then return 0; fi
 printf '%s\\n' "$*" >>"$log"
}}
''' + create + '\n' + cleanup + f'''
pcreate collision pm --network pasta || :
printf '%s\\n' {fake_id} >"$SCR/pod-owned.id"
cleanup
cat "$log"
'''
    assert run(code).splitlines() == ['pod rm -f -t 0 ' + fake_id]
    restart = section('if has restart; then', '\n# ---- dyn:')
    for fault in ('pasta', 'command', 'app', 'nft', 'apply', 'pasta_second', 'command_second', 'app_second', 'nft_second', 'sensitive', 'host_control', 'leak'):
        code = f"""set -u
B=127.0.1.202; SENS='9222 5432'; BAD={fault}; state={scratch}/state; echo none >\"$state\"
has() {{ return 0; }}
say() {{ :; }}
res() {{ echo \"$1 $2\"; }}
id_of() {{ echo testid; }}
pmx() {{
  if [[ $3 == restart && $4 != -t ]]; then echo first >\"$state\"; [[ $BAD != command ]];
  elif [[ $3 == restart ]]; then echo "unknown shorthand flag: 't'" >&2; return 125;
  elif [[ $3 == stop ]]; then echo third >\"$state\"; [[ $BAD != command_second ]]; else return 0; fi
}}
srv() {{ :; }}
nft_apply() {{ [[ $BAD != apply || $(cat \"$state\") != none ]]; }}
pasta_verify() {{ [[ $BAD != pasta || $(cat \"$state\") != first ]] && [[ $BAD != pasta_second || $(cat \"$state\") != third ]]; }}
inpod() {{
  if [[ $BAD == app && $(cat \"$state\") == first || $BAD == app_second && $(cat \"$state\") == third ]]; then echo ERR; return; fi
  if [[ $BAD == sensitive && $2 == *:5432/* ]]; then echo ERR; return; fi
  port=${{2##*:}}; port=${{port%%/*}}; echo B:$port
}}
nft_list() {{ if [[ $BAD == nft && $(cat \"$state\") == first || $BAD == nft_second && $(cat \"$state\") == third ]]; then return 1; fi; }}
nft_verify() {{ return 1; }}
hc() {{ if [[ $1 == *:4001/* && $BAD != host_control ]]; then echo B:4001; elif [[ $1 == *:5432/* && $BAD == leak ]]; then echo LEAK; else return 1; fi; }}
want() {{ :; }}
nope() {{ :; }}
sleep() {{ :; }}
""" + restart
        output = run(code)
        assert 'FAIL ' in output, (fault, output)
print('PASS: 6 poll cases, 2 ownership cases, 12 restart failure cases (stubbed)')
