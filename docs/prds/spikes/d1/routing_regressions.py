#!/usr/bin/env python3
"""Exercise host routing and fail-fast preflight with stub commands only."""
import os
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[4]
probe = Path(os.environ.get('OC_SPIKE_PROBE', Path(__file__).with_name('probe.sh'))).resolve()
base = repo / '.scratch'
if base.is_symlink():
    raise RuntimeError('scratch directory must not be a symlink')
base.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='route.', dir=base) as tmp:
    root = Path(tmp)
    bindir = root / 'bin'
    bindir.mkdir()
    driver = bindir / 'driver'
    driver.write_text('''#!/bin/sh
name=${0##*/}
printf '%s %s\\n' "$name" "$*" >> "$FAKE_LOG"
if [ "${FAKE_HELPERS:-}" = 1 ]; then { printf 'args %s' "$name"; printf ' <%s>' "$@"; printf '\\n'; } >> "$FAKE_LOG"; fi
case "$name" in
 sh) [ "${FAIL_WHICH:-}" = host_tools ] && exit 1; exec /bin/sh "$@" ;;
 distrobox-host-exec) [ "${FAKE_HOST_EXEC_FAIL:-}" = 1 ] && exit 42; exec "$@" ;;
 podman)
   if [ "${FAKE_HELPERS:-}" = 1 ]; then [ -n "${CONTAINERS_CONF_OVERRIDE:-}" ] && printf 'conf <%s>\\n' "$CONTAINERS_CONF_OVERRIDE" >> "$FAKE_LOG"; exit 0; fi
   case "$*" in
     --version) [ "${FAIL_WHICH:-}" = podman_version ] && exit 1; echo 'podman version stub';;
     info) [ "${FAIL_WHICH:-}" = podman_info ] && exit "${FAKE_INFO_RC:-1}";;
     'image exists '*) [ "${FAIL_WHICH:-}" = image ] && exit "${FAKE_IMAGE_RC:-1}";;
     'unshare '*) [ "${FAIL_WHICH:-}" = unshare ] && exit 1;;
     'pod ls '*) [ "${FAIL_WHICH:-}" = pods ] && exit 1; [ "${FAKE_STALE:-}" = 1 ] && echo oc-spike-d1-existing;;
     'ps -a '*) [ "${FAIL_WHICH:-}" = ctrs ] && exit 1;;
     'images '*) [ "${FAIL_WHICH:-}" = images ] && exit 1;;
     *) echo 'unexpected podman mutation' >&2; exit 91;;
   esac; exit 0 ;;
 rpm) [ "${FAIL_WHICH:-}" = rpm ] && exit 1; echo passt-stub ;;
 nft) [ "${FAIL_WHICH:-}" = nft_empty ] || echo nft-stub ;;
 uname) [ "${FAIL_WHICH:-}" = kernel_empty ] || echo kernel-stub ;;
 ip) [ "${FAIL_WHICH:-}" = ip_empty ] || echo '2: eth0 inet 192.0.2.1/24 scope global eth0' ;;
 curl|ss|iptables|nsenter) [ "${FAIL_WHICH:-}" = "$name" ] && exit 1; exit 0 ;;
 *) exit 0 ;;
esac
''')
    driver.chmod(0o755)
    for cmd in ('distrobox-host-exec', 'podman', 'rpm', 'nft', 'uname', 'ip', 'curl', 'ss', 'iptables', 'nsenter', 'unshare', 'pasta', 'sh'):
        (bindir / cmd).symlink_to(driver)
    env = {k: v for k, v in os.environ.items() if k not in ('CONTAINER_ID', 'DISTROBOX_ENTER_PATH', 'container')}
    log = root / 'calls'
    env.update(PATH=f'{bindir}:/usr/bin:/bin', FAKE_LOG=str(log))

    def run(extra):
        log.write_text('')
        p = subprocess.run(['bash', str(probe), 'main'], env={**env, **extra}, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        calls = log.read_text().splitlines()
        assert p.returncode != 0, (extra, p.stdout, p.stderr)
        assert not any(line.startswith('podman ') and any(x in line.split() for x in ('create', 'run', 'rm', 'build')) for line in calls), calls
        return p, calls

    def check_unused_info():
        # Simulate a full-system info query returning 124. The stale resource is a
        # harmless stop after all read-only prerequisite checks; no creation occurs.
        p, calls = run({'FAIL_WHICH': 'podman_info', 'FAKE_INFO_RC': '124', 'FAKE_STALE': '1'})
        assert 'resources named oc-spike-d1-' in p.stderr, (p.stdout, p.stderr, calls)
        assert 'podman info' not in calls, calls
        required = ('sh -c for cmd in podman ', 'podman --version', 'podman image exists ', 'podman unshare ',
                    'podman pod ls ', 'podman ps -a ', 'podman images ',
                    'rpm -q passt', 'nft --version', 'uname -r', 'ip -4 ',
                    'curl --version', 'ss -tlnpH', 'iptables --version', 'nsenter --version')
        for prefix in required:
            assert any(line.startswith(prefix) for line in calls), (prefix, calls)

    if os.environ.get('OC_SPIKE_INFO_ONLY'):
        check_unused_info()
        print('PASS: unused Podman info not called; all required preflight queries ran')
        raise SystemExit(0)
    check_unused_info()

    only = os.environ.get('OC_SPIKE_FAILURE_ONLY')
    if only:
        p, calls = run({'FAIL_WHICH': only})
        assert 'ABORT:' in p.stderr and '== versions:' not in p.stdout, (only, p.stdout, p.stderr)
        print(f'PASS: {only} failure stopped before resource creation')
        raise SystemExit(0)

    for mode in ('host', 'distrobox', 'distrobox_marker'):
        settings = {'FAKE_STALE': '1'}
        if mode == 'distrobox':
            settings.update(CONTAINER_ID='fixture', container='podman')
        if mode == 'distrobox_marker':
            settings.update(DISTROBOX_ENTER_PATH='/fixture/distrobox-enter', container='podman')
        p, calls = run(settings)
        assert 'resources named oc-spike-d1-' in p.stderr, (mode, p.stderr)
        routed = any(line.startswith('distrobox-host-exec ') for line in calls)
        assert routed == (mode != 'host'), (mode, calls)
        assert any(line == 'podman --version' for line in calls) and any(line.startswith('ip -4 ') for line in calls), calls
    # Exercise the same wrapper used by Podman, curl, config overrides, namespace
    # entry and background workers, including arguments containing spaces.
    source = probe.read_text()
    route = source[source.index('H=()'):source.index('A=127.0.1.201')]
    wrappers = source[source.index('pm()  {'):source.index('say() {')]
    pmx = source[source.index('pmx()   {'):source.index('# mkpod MODE')]
    nsx = source[source.index('nsx()       {'):source.index('\n# (`| cat`')]
    for mode in ('host', 'distrobox'):
        log.write_text('')
        extra = {'FAKE_HELPERS': '1', 'SCR': str(root / 'with space')}
        if mode == 'distrobox':
            extra.update(CONTAINER_ID='fixture', container='podman')
        code = route + wrappers + pmx + 'infra_pid() { echo 123; }\n' + nsx + """
pm 'arg with space'
hc 'http://example.invalid/a b'
pmx a 'arg with space'
nsx a nft 'arg with space'
host bash -c 'printf "%s" "worker arg with space"' &
wait $!
"""
        result = subprocess.run(['bash'], input=code, env={**env, **extra}, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        assert result.returncode == 0 and result.stdout == 'worker arg with space', (mode, result.stdout, result.stderr)
        calls = log.read_text()
        assert 'args podman <arg with space>' in calls, (mode, calls)
        assert 'args curl <-s> <-m> <3> <http://example.invalid/a b>' in calls, (mode, calls)
        assert 'args podman <unshare> <nsenter> <-t> <123> <-n> <nft> <arg with space>' in calls, (mode, calls)
        assert f'conf <{root}/with space/a.conf>' in calls, (mode, calls)
        assert ('distrobox-host-exec ' in calls) == (mode == 'distrobox')
    for failure in ('host_tools', 'podman_version', 'rpm', 'nft_empty', 'kernel_empty', 'ip_empty',
                    'curl', 'ss', 'iptables', 'nsenter', 'image', 'unshare', 'pods', 'ctrs', 'images'):
        p, calls = run({'FAIL_WHICH': failure})
        assert 'ABORT:' in p.stderr and '== versions:' not in p.stdout, (failure, p.stdout, p.stderr)
    # PATH contains no host-exec, even if one exists elsewhere on this machine.
    empty_path = root / 'no-host-exec'
    empty_path.mkdir()
    missing = subprocess.run(['/bin/bash', str(probe), 'main'],
                             env={**env, 'PATH': str(empty_path), 'CONTAINER_ID': 'fixture'},
                             text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    assert missing.returncode != 0 and 'distrobox-host-exec is required' in missing.stderr
    assert '== versions:' not in missing.stdout
    unsupported, calls = run({'container': 'podman'})
    assert 'unsupported container environment' in unsupported.stderr
    assert not calls
    failed, calls = run({'FAIL_WHICH': 'image'})
    assert 'host preflight Python image failed (exit 1)' in failed.stderr
    timed_out, calls = run({'FAIL_WHICH': 'image', 'FAKE_IMAGE_RC': '124'})
    assert 'host preflight Python image timed out or returned 124 (exit 124)' in timed_out.stderr
    p, calls = run({'CONTAINER_ID': 'fixture', 'FAKE_HOST_EXEC_FAIL': '1'})
    assert 'ABORT:' in p.stderr and '== versions:' not in p.stdout
print('PASS: 3 routing cases, 2 helper/worker modes, 15 prerequisite failures, unused info bypass, stage/status diagnostics, unsupported container, missing host-exec and failed host execution; no Podman mutations')
