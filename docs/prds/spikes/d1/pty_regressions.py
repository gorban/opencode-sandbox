#!/usr/bin/env python3
"""Real distrobox-host-exec PTY regressions, using only /bin/true."""
import fcntl
import os
from pathlib import Path
import pty
import shlex
import shutil
import subprocess
import tempfile
import termios

repo = Path(__file__).resolve().parents[4]
probe = Path(os.environ.get('OC_SPIKE_PROBE', Path(__file__).with_name('probe.sh'))).resolve()
source = probe.read_text()
route = source[source.index('H=()'):source.index('A=127.0.1.201')]
workers = source[source.index('# ---- poll worker control'):source.index('# Fail before scratch')]
new_signature = 'local stage=$1' in route
base = repo / '.scratch'
if base.is_symlink():
    raise RuntimeError('scratch directory must not be a symlink')
base.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='pty-test.', dir=base) as tmp:
    root = Path(tmp)
    failures = []
    modes = ['native']
    if os.environ.get('CONTAINER_ID') or os.environ.get('DISTROBOX_ENTER_PATH'):
        modes.append('distrobox')
    for mode in modes:
        for method in ('host', 'host_timeout', 'worker'):
            name = mode + '-' + method
            helper = root / (name + '.sh')
            if method == 'host':
                call = 'host /bin/true'
            elif method == 'host_timeout':
                call = 'host_timeout fixture /bin/true' if new_signature else 'host_timeout /bin/true'
            else:
                scratch = root / (name + '-scratch')
                scratch.mkdir()
                call = (f'SCR={shlex.quote(str(scratch))}\n' + workers +
                        '\nstart_worker fixture "$SCR/output" 127.0.0.1 && stop_worker')
            helper.write_text('#!/bin/bash\n' +
                              'if [[ ${EXPECT_TTY:-0} == 1 ]]; then [[ -t 0 && -t 1 ]] || exit 88; else [[ ! -t 0 && ! -t 1 ]] || exit 89; fi\n' +
                              route + ('H=()\n' if mode == 'native' else '') +
                              call + '\nrc=$?\nprintf "marker rc=%s\\n" "$rc"\nexit "$rc"\n')
            cmd = f'EXPECT_TTY=1 timeout 4 bash {shlex.quote(str(helper))}'
            if shutil.which('script'):
                # util-linux script allocates a controlling PTY, matching the user's shell.
                result = subprocess.run(['script', '-q', '-e', '-c', cmd, '/dev/null'], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
                status, output, error = result.returncode, result.stdout, result.stderr
            else:
                # Some native hosts lack util-linux script. A PTY pair still checks
                # native routing; the distrobox reproduction requires script itself.
                if mode != 'native':
                    raise RuntimeError('script is required for the distrobox PTY regression')
                master, slave = pty.openpty()
                def make_controlling_terminal():
                    os.setsid()
                    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                process = subprocess.Popen(['timeout', '4', 'bash', str(helper)],
                                           stdin=slave, stdout=slave, stderr=slave,
                                           preexec_fn=make_controlling_terminal,
                                           env={**os.environ, 'EXPECT_TTY': '1'})
                os.close(slave)
                try:
                    status = process.wait(timeout=10)
                    output = os.read(master, 4096).decode(errors='replace')
                    error = ''
                finally:
                    if process.poll() is None:
                        process.kill(); process.wait()
                    os.close(master)
            if status != 0 or 'marker rc=0' not in output:
                failures.append((name, status, output, error))
            # Also check ordinary non-terminal host execution and its exit status.
            result = subprocess.run(['timeout', '4', 'bash', str(helper)], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            if result.returncode != 0 or 'marker rc=0' not in result.stdout:
                failures.append((name + '-non-tty', result.returncode, result.stdout, result.stderr))
    assert not failures, failures
print('PASS: ' + ', '.join(modes) + ' host/host_timeout/worker, controlling PTY with outer timeout and non-TTY')
