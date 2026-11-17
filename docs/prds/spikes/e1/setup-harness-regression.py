#!/usr/bin/env python3
"""Check PTY execution and timeout/interrupt cleanup of private fixture process groups."""
import fcntl, importlib.util, os, pathlib, pty, select, signal, subprocess, sys, tempfile, termios, time

HERE = pathlib.Path(__file__).resolve().parent
HARNESS = HERE / 'setup-regression.py'

def child(mode, receipt):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('setup_fixture', HARNESS)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    # Both the shell and its child are in the private session created by run_fixture.
    cmd = ['bash', '-c', 'sleep 120 & echo "$$ $!" > "$1"; wait', 'fixture', receipt]
    module.run_fixture(cmd, env={**os.environ, 'PATH': '/usr/bin:/bin'}, timeout=0.8 if mode == 'timeout' else 30)
    raise SystemExit('fixture unexpectedly succeeded')

def active(pid):
    try:
        data = pathlib.Path(f'/proc/{pid}/stat').read_text()
    except FileNotFoundError:
        return False
    return data.rsplit(')', 1)[1].split()[0] != 'Z'

def pty_run(script, expected_lines, expect_hang=False):
    master, slave = pty.openpty()
    def setup():
        os.setsid(); fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    proc = subprocess.Popen([sys.executable, '-u', '-I', str(script), str(HERE)], stdin=slave,
                            stdout=slave, stderr=slave, preexec_fn=setup, close_fds=True)
    os.close(slave); data = b''; deadline = time.monotonic() + (4 if expect_hang else 15)
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try: data += os.read(master, 65536)
                except OSError: break
            if proc.poll() is not None: break
        # Drain output already written just before the process exited.
        while select.select([master], [], [], 0)[0]:
            try: data += os.read(master, 65536)
            except OSError: break
        lines = data.count(b'aborted without a result cell')
        if expect_hang:
            assert proc.poll() is None and lines == expected_lines, (proc.poll(), data)
        else:
            assert proc.wait(timeout=2) == 0 and lines == expected_lines, data
        print(f'{"old" if expect_hang else "new"} controlling PTY: {lines} checks, ' + ('blocked as expected' if expect_hang else 'exited successfully'))
    finally:
        if proc.poll() is None:
            # Give the new harness a chance to clean its own nested fixture session.
            if not expect_hang:
                os.kill(proc.pid, signal.SIGINT)
                try: proc.wait(timeout=4)
                except subprocess.TimeoutExpired: pass
            if proc.poll() is None:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
        proc.wait(); os.close(master)

def cleanup_check(mode, tmp):
    receipt = tmp / (mode + '.ids')
    proc = subprocess.Popen([sys.executable, '-I', __file__, '--child', mode, str(receipt)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    ids = []
    try:
        deadline = time.monotonic() + 5
        while not receipt.exists() and time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.02)
        assert receipt.exists(), f'{mode}: fixture did not start'
        ids = [int(x) for x in receipt.read_text().split()]
        assert len(ids) == 2 and os.getpgid(ids[0]) == ids[0], f'{mode}: unexpected fixture group'
        if mode == 'interrupt': os.kill(proc.pid, signal.SIGINT)
        out, err = proc.communicate(timeout=6)
        assert proc.returncode != 0 and ('TimeoutExpired' if mode == 'timeout' else 'KeyboardInterrupt') in err, (out, err)
        deadline = time.monotonic() + 3
        while any(active(pid) for pid in ids) and time.monotonic() < deadline: time.sleep(0.02)
        assert not any(active(pid) for pid in ids), f'{mode}: fixture descendant still running: {ids}'
        print(f'{mode}: failure propagated and fixture shell/child stopped')
    finally:
        if proc.poll() is None:
            if ids:
                try: os.killpg(ids[0], signal.SIGKILL)
                except ProcessLookupError: pass
            proc.kill()
        proc.communicate(timeout=3)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child': child(sys.argv[2], sys.argv[3])
    else:
        if len(sys.argv) == 2: pty_run(pathlib.Path(sys.argv[1]).resolve(), 4, True)
        pty_run(HARNESS, 5)
        plain = subprocess.Popen([sys.executable, '-I', str(HARNESS)], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 start_new_session=True)
        try:
            out, err = plain.communicate(timeout=15)
            assert plain.returncode == 0 and out.count('aborted without a result cell') == 5, (out, err)
        finally:
            if plain.poll() is None:
                os.kill(plain.pid, signal.SIGINT)
                try: plain.communicate(timeout=4)
                except subprocess.TimeoutExpired:
                    os.killpg(plain.pid, signal.SIGKILL)
                    plain.communicate(timeout=3)
        print('non-TTY: five checks and successful exit')
        with tempfile.TemporaryDirectory() as td:
            cleanup_check('timeout', pathlib.Path(td))
            cleanup_check('interrupt', pathlib.Path(td))
