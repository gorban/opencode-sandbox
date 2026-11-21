#!/usr/bin/env python3
"""Measure statement and branch coverage of the two offline Python cores."""

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[2]
WHEEL = (
    'https://files.pythonhosted.org/packages/5f/04/'
    '642c1d8a448ae5ea1369eac8495740a79eb4e581a9fb0cbdce56bbf56da1/'
    'coverage-7.11.0-py3-none-any.whl'
)
WHEEL_HASH = '4b7589765348d78fb4e5fb6ea35d07564e387da2fc5efff62e0222971f155f68'
CORES = {
    'oc_bridge_merge.py': 'bridge_merge_core.py',
    'oc_controller.py': 'test_controller_core.py',
}


def install_coverage(scratch):
    subprocess.run([sys.executable, '-Im', 'venv', str(scratch / 'venv')],
                   cwd=scratch, check=True, timeout=60)
    python = str(scratch / 'venv/bin/python')
    requirements = scratch / 'requirements.txt'
    requirements.write_text(f'{WHEEL} --hash=sha256:{WHEEL_HASH}\n', encoding='ascii')
    subprocess.run(
        [python, '-Im', 'pip', '--isolated', '--disable-pip-version-check', 'install',
         '--no-index', '--no-cache-dir', '--no-deps', '--require-hashes',
         '--only-binary=:all:', '-r', str(requirements)],
        cwd=scratch, env={**os.environ, 'PIP_CONFIG_FILE': os.devnull}, check=True, timeout=120,
    )
    return python


def report_coverage(json_report, xml_report):
    files = json.loads(json_report.read_text(encoding='utf-8'))['files']
    xml_files = [entry.attrib['filename'] for entry in ElementTree.parse(xml_report).iter('class')]
    if files.keys() != CORES.keys() or sorted(xml_files) != sorted(CORES):
        raise ValueError('coverage reports must contain both core modules with repository-relative paths')
    for name, info in files.items():
        summary = info['summary']
        statements, branches = summary['num_statements'], summary['num_branches']
        if not statements or not branches:
            raise ValueError(f'expected both statements and branches in coverage data for {name}')
        print(f"{name}: {summary['covered_lines']}/{statements} statements, "
              f"{summary['covered_branches']}/{branches} branches")


def main():
    with TemporaryDirectory(prefix='oc-core-coverage-') as directory:
        scratch = Path(directory).resolve()
        python = install_coverage(scratch)
        config = scratch / 'coverage.ini'
        config.write_text('[run]\nbranch = true\nrelative_files = true\ninclude =\n    '
                          + '\n    '.join(CORES) + '\n', encoding='ascii')
        env = {name: value for name, value in os.environ.items() if not name.startswith('COVERAGE_')}
        env.update(COVERAGE_RCFILE=str(config), COVERAGE_FILE=str(scratch / '.coverage'))

        def coverage(*args):
            subprocess.run([python, '-EsB', '-m', 'coverage', *args],
                           cwd=ROOT, env=env, check=True, timeout=60)

        for suite in CORES.values():
            coverage('run', '--append', '-m', 'unittest', 'discover', '-s', 'tests', '-p', suite)
        json_report = scratch / 'coverage.json'
        xml_report = scratch / 'coverage.xml'
        coverage('json', '-o', str(json_report))
        coverage('xml', '-o', str(xml_report))
        report_coverage(json_report, xml_report)


if __name__ == '__main__':
    main()
