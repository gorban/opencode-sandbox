#!/usr/bin/env python3
"""Check that browser regressions cannot select external executable sources.

The adjacent scripts are staged in a private temporary repository. Any historical
predictable handoff-directory constant is redirected to a private fixture. The only
code placed there writes a private sentinel and exits. No real handoff path, browser,
Flatpak, trust store or network is accessed.
"""
import ast
import json
from pathlib import Path
import subprocess
import sys
import tempfile

here = Path(__file__).resolve().parent
names = ('host-browser-control-regression.py', 'host-chrome-isolation-regression.py',
         'host-chrome-portal-regression.py')
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    scripts = root/'repo'/'docs'/'prds'/'spikes'/'e1'; scripts.mkdir(parents=True)
    (root/'repo'/'.scratch').mkdir()
    handoff = root/'private-handoff'; handoff.mkdir()
    sentinel = root/'sentinel'
    payload = f'from pathlib import Path\nPath({str(sentinel)!r}).write_text("executed")\nraise SystemExit(97)\n'
    (handoff/'e1-old-browser-fixture-rw-control.py').write_text(payload)
    external = handoff/'explicit-helper.py'; external.write_text(payload)
    class Redirect(ast.NodeTransformer):
        def visit_Constant(self, node):
            if node.value == '/tmp/oc-sandbox-codex-handoff':
                return ast.copy_location(ast.Constant(str(handoff)), node)
            return node
    for name in names:
        tree = ast.fix_missing_locations(Redirect().visit(ast.parse((here/name).read_text())))
        (scripts/name).write_text(ast.unparse(tree) + '\n')
    ca = root/'ca.pem'; ca.write_text('private test fixture')
    manifest = root/'manifest.json'; manifest.write_text(json.dumps({'ca_files': {'E': str(ca), 'X': str(ca)}}))
    cases = (
        (names[0], [str(manifest), str(ca), str(ca), '--old']),
        (names[1], [str(manifest), str(external)]),
        (names[2], [str(manifest), str(external)]),
    )
    failed = False
    for name, args in cases:
        sentinel.unlink(missing_ok=True)
        result = subprocess.run([sys.executable, '-I', str(scripts/name), *args],
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        ok = not sentinel.exists() and result.returncode == 2 and 'unrecognized arguments:' in result.stderr
        print(f'{name}: '+('PASS' if ok else f'FAIL (sentinel={sentinel.exists()}, status={result.returncode})'))
        failed |= not ok
    # Normal argument counts must still proceed to the adjacent, trusted sibling.
    # These staged siblings are inert fixtures and exit before any Flatpak command.
    (scripts/'host-browser-fixture.py').write_text('raise SystemExit(94)\n')
    (scripts/'prepare-host-chrome.py').write_text('raise SystemExit(94)\n')
    defaults = ((names[0], [str(manifest), str(ca), str(ca)]),
                (names[1], [str(manifest)]), (names[2], [str(manifest)]))
    for name, args in defaults:
        result = subprocess.run([sys.executable, '-I', str(scripts/name), *args],
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
        ok = result.returncode == 94 if name == names[0] else 'exit status 94' in result.stderr
        print(f'{name} default arguments: '+('PASS' if ok else f'FAIL (status={result.returncode})'))
        failed |= not ok
    # Verify the trust-path shell check receives host-home paths as arguments,
    # including spaces, rather than relying on a particular user's home directory.
    control = ast.parse((here/names[0]).read_text())
    function = next(n for n in control.body if isinstance(n, ast.FunctionDef) and n.name == 'check')
    shell = next(n.value.value for n in function.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == 'shell' for t in n.targets))
    path_line = next(line for line in shell.splitlines() if line.startswith('for p in '))
    dynamic = all('${%d}' % n in path_line for n in (10, 11, 12)) and 'Path.home().resolve()' in ast.unparse(function)
    if dynamic:
        fake_home = root/'other user home'; fake_home.mkdir()
        checked = [str(fake_home/p) for p in ('.pki/nssdb', '.local/share/pki/nssdb', '.mozilla')]
        command = ['/bin/sh', '-c', path_line, 'fixture'] + ['unused']*9 + checked
        absent = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        (fake_home/'.mozilla').mkdir()
        visible = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        dynamic = absent.returncode == 0 and visible.returncode == 13
    print('host trust paths follow host HOME with spaces: '+('PASS' if dynamic else 'FAIL'))
    failed |= not dynamic
    if failed: raise SystemExit(1)
