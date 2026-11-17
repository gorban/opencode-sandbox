#!/usr/bin/env python3
"""Test the actual fake OpenSSL source; pass a historical harness path to compare."""
import ast, importlib.util, os, pathlib, sys, tempfile

here = pathlib.Path(__file__).resolve().parent
source = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else here / 'setup-regression.py'
tree = ast.parse(source.read_text())
matches = [node.args[1].value for node in ast.walk(tree)
           if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'stub'
           and len(node.args) >= 2 and isinstance(node.args[0], ast.Constant) and node.args[0].value == 'openssl'
           and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)]
if len(matches) != 1:
    raise SystemExit('expected exactly one literal OpenSSL stub')
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('setup_fixture', here / 'setup-regression.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
with tempfile.TemporaryDirectory() as td:
    stub = pathlib.Path(td) / 'openssl'
    stub.write_text('#!/bin/bash\n' + matches[0] + '\n'); stub.chmod(0o755)
    env = {**os.environ, 'PATH': '/usr/bin:/bin'}
    version = module.run_fixture([str(stub), 'version'], env=env)
    unknown = module.run_fixture([str(stub), 'unsupported-fixture-command'], env=env)
    version_ok = version.returncode == 0 and version.stdout.strip().startswith('OpenSSL ') and len(version.stdout.strip()) > len('OpenSSL ')
    unknown_ok = unknown.returncode != 0 and not unknown.stdout.strip()
    print('version: ' + ('PASS' if version_ok else 'FAIL') + f' (status {version.returncode}, output {version.stdout.strip()!r})')
    print('unknown command: ' + ('PASS' if unknown_ok else 'FAIL') + f' (status {unknown.returncode}, output {unknown.stdout.strip()!r})')
    if not (version_ok and unknown_ok):
        raise SystemExit(1)
