#!/usr/bin/env python3
"""Scratch-only host state leaf regressions; Podman/systemd are stubbed."""
import os, pathlib, subprocess, sys, tempfile
source = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1] / 'oc-sandbox')
text = source.read_text()
with tempfile.TemporaryDirectory(prefix='oc-leaf-') as tmp:
    base = pathlib.Path(tmp); home = base / 'home'; sb = home / 'opencode-sandbox'; sb.mkdir(parents=True)
    state = home / '.local/share/oc-sandbox'; build = state / 'build'; policy = state / 'policy'
    build.mkdir(parents=True); policy.mkdir()
    stub = base / 'stub'; stub.mkdir()
    for name in ('podman', 'systemctl', 'pkexec', 'sudo', 'distrobox-host-exec'):
        f = stub / name; f.write_text('#!/bin/sh\nexit 0\n'); f.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in ('XDG_DATA_HOME', 'XDG_CONFIG_HOME', 'CONTAINER_ID')}
    env.update(HOME=str(home), PATH=str(stub) + os.pathsep + os.environ['PATH'])
    sentinel = sb / 'sentinel'; sentinel.write_text('unchanged\n')
    failures = []
    for target in (build / 'Containerfile.agent', policy / 'oc_chromium.cil', state / 'sb-level',
                   state / 'built-images', state / 'built-images.lock', state / 'pg-sig.key', state / 'pg-sig.lock',
                   build / 'gitconfig', policy / 'installed'):
        for kind in ('symlink', 'hardlink'):
            if kind == 'symlink': target.symlink_to(sentinel)
            else: os.link(sentinel, target)
            for option in ('-h', '-l'):
                r = subprocess.run(['bash', str(source), option], cwd=base, env=env, capture_output=True, text=True)
                if r.returncode == 0 or sentinel.read_text() != 'unchanged\n':
                    failures.append(f'{target.name} {kind} {option}')
            target.unlink()
    # Run the exact generated-file section in a private fixture to verify writes do not follow links.
    for dirname, leaf, endtoken in [('BUILD', 'Containerfile.agent', 'EOF'), ('POLDIR', 'oc_chromium.cil', 'POL')]:
        prefix_old = 'cat > "$' + dirname + '/' + leaf + '" <<\'' + endtoken + "'"
        prefix_new = 'atomic_host_file "$' + dirname + '/' + leaf + '" 0644 <<\'' + endtoken + "'"
        prefix = prefix_new if prefix_new in text else prefix_old
        begin = text.index(prefix); end = text.index('\n' + endtoken + '\n', begin) + len(endtoken) + 2
        fragment = text[begin:end]
        if 'atomic_host_file() {' in text:
            a = text.index('atomic_host_file() {'); b = text.index('\n}', a) + 2
            fragment = text[a:b] + '\n' + fragment
        for kind in ('symlink', 'hardlink'):
            target = (build if dirname == 'BUILD' else policy) / leaf
            if kind == 'symlink': target.symlink_to(sentinel)
            else: os.link(sentinel, target)
            runenv = {**env, 'BUILD': str(build), 'POLDIR': str(policy)}
            r = subprocess.run(['bash', '-eu', '-c', fragment], cwd=base, env=runenv, capture_output=True, text=True)
            if r.returncode or sentinel.read_text() != 'unchanged\n':
                failures.append(f'{leaf} {kind} writes through link')
            target.unlink(missing_ok=True)
            sentinel.write_text('unchanged\n')
    for directory in (state, build, policy):
        directory.chmod(0o777)
        r = subprocess.run(['bash', str(source), '-h'], cwd=base, env=env, capture_output=True, text=True)
        if r.returncode == 0: failures.append(f'{directory.name} writable parent')
        directory.chmod(0o755)
    # Personal dotfiles may link to host-managed dotfiles but not via $SB.
    start = text.index('trusted_path() {'); end = text.index('\n}', start) + 2
    trusted = text[start:end]
    dotfile = home / '.gitconfig'; host_config = base / 'host-config'; host_config.write_text('[user]\n')
    probe = 'sb_real=$TEST_SB; in_sb() { [[ $1/ == "$sb_real"/* ]]; };\n' + trusted + '\ntrusted_path "$HOME/.gitconfig"'
    probe_env = {**env, 'TEST_SB': str(sb)}
    dotfile.symlink_to(host_config)
    r = subprocess.run(['bash', '-c', probe], cwd=base, env=probe_env, capture_output=True, text=True)
    if r.returncode or r.stdout.strip() != str(host_config): failures.append('safe personal symlink refused')
    dotfile.unlink(); dotfile.symlink_to(sentinel)
    r = subprocess.run(['bash', '-c', probe], cwd=base, env=probe_env, capture_output=True, text=True)
    if r.returncode == 0: failures.append('sandbox personal symlink accepted')
    dotfile.unlink()
    # Execute the actual shared-setup directory creation under umask 0002.
    # /tmp is a sticky shared ancestor; the test home and nearest parents are
    # user-owned and protected, and existing personal directories are untouched.
    setup_start = text.index('# Host-owned directories only.')
    setup_end = text.index('# One SELinux level', setup_start)
    setup_block = text[setup_start:setup_end]
    if 'mkdir -p "$POLDIR"' in text:
        setup_block += '\nmkdir -p "$POLDIR"\n'
    check_home = base / 'created-umask' / 'home'; check_home.mkdir(parents=True)
    state2 = check_home / '.local/share/oc-sandbox'; state2.mkdir(parents=True, mode=0o700)
    sb2 = check_home / 'opencode-sandbox'; sb2.mkdir()
    build2 = state2 / 'build'; policy2 = state2 / 'policy'; stage2 = state2 / 'bridge-stage'
    bin2 = check_home / '.local/bin'; units2 = check_home / '.config/systemd/user'
    validators = []
    for name in ('validate_host_state', 'shared_host_directory', 'verify_bridge_stage'):
        function = name + '() {'
        if function in text:
            start = text.index(function)
            end = text.index('\n}', start) + 2
            validators.append(text[start:end])
    harness = '\n'.join(validators) + '\ndie() { echo "$*" >&2; exit 2; }\nH=()\numask 0002\n' + setup_block
    creation_env = {**env, 'HOME': str(check_home), 'SB': str(sb2), 'STATE': str(state2),
                    'BUILD': str(build2), 'POLDIR': str(policy2), 'BRIDGE_STAGE': str(stage2),
                    'BIN': str(bin2), 'UNITS': str(units2), 'INSTALL_DIR': str(units2 / '.oc-sandbox')}
    r = subprocess.run(['bash', '-eu', '-o', 'pipefail', '-c', harness], cwd=base,
                       env=creation_env, capture_output=True, text=True)
    created = [build2, policy2, bin2, units2]
    if 'mkdir -p "$BUILD" "$BIN" "$UNITS" "$POLDIR" "$BRIDGE_STAGE"' in setup_block:
        created.append(stage2)
    if r.returncode or any(not path.is_dir() or path.stat().st_mode & 0o022 for path in created):
        failures.append('permissive umask created unsafe managed directories')
    if failures:
        print('FAIL: ' + ', '.join(failures)); sys.exit(1)
    print('PASS: unsafe host leaves refused for help and listing')
    print('PASS: generated config and policy writes do not follow symlinks or hard links')
    print('PASS: permissive umask creates protected managed directories')
