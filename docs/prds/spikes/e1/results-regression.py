#!/usr/bin/env python3
"""Check E1 result capture and ingestion without starting containers."""

import contextlib
import io
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(sys.argv.pop(1)).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent
VERIFY_CLIENT = "/c/openssl_verify.sh"
ALPINE_OUTPUTS = (
    (VERIFY_CLIENT, "openssl-alpine-verify.tsv"),
    ("/c/sclient.sh", "openssl-alpine-sclient.tsv"),
    ("/c/curl.sh", "curl.tsv"),
)

CLIENT_STUBS = """
log() { :; }
die() { printf '%s\n' "$*" >&2; exit 1; }
bash() {
  [[ "$*" == '/fixture/clients/openssl_verify.sh openssl' ]] || exit 96
  printf 'host\n'
}
crun() {
  printf '%s\n' "$*" >> "$W/commands"
  if [[ "$1" == fixture-alpine ]]; then
    printf '%s\n' "$3" >&2
    [[ "$3" != "$FAIL_CLIENT" ]] || return 88
  fi
  printf '%s\n' "$3"
}
"""


class AlpineCaptureTests(unittest.TestCase):
    def run_clients(self, fail_client):
        probe = (SOURCE / "probe.sh").read_text()
        function = probe.split("\nrun_clients() {\n", 1)[1].split("\nrun_pg() {\n", 1)[0]
        return subprocess.run(
            ["bash", "-s"],
            input=CLIENT_STUBS + "\nrun_clients() {\n" + function + "\nrun_clients\n",
            env={**os.environ, "W": str(self.work), "HERE": "/fixture", "ALPINE_ID": "fixture-alpine",
                 "PY_IMG": "fixture-python", "NODE_IMG": "fixture-node", "HOSTSSL": "openssl",
                 "SKIP_GO": "1", "SKIP_PG": "1", "SKIP_CHROMIUM": "1", "FAIL_CLIENT": fail_client},
            text=True, capture_output=True, timeout=5,
        )

    def setUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.results = self.work / "results"
        self.results.mkdir()

    def alpine_commands(self):
        return [
            "fixture-alpine bash " + script + (" openssl" if script == VERIFY_CLIENT else "")
            for script, _ in ALPINE_OUTPUTS
        ]

    def test_host_captures_same_files_and_shared_stderr(self):
        run = self.run_clients("")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual((self.work / "commands").read_text().splitlines()[:3], self.alpine_commands())
        for script, name in ALPINE_OUTPUTS:
            self.assertEqual((self.results / name).read_text(), script + "\n")
        self.assertEqual((self.results / "alpine.err").read_text().splitlines(),
                         [script for script, _ in ALPINE_OUTPUTS])
        self.assertEqual((self.results / "openssl-host-verify.tsv").read_text(), "host\n")

    def test_failed_alpine_client_stops_before_later_clients(self):
        for i, (script, _) in enumerate(ALPINE_OUTPUTS):
            with self.subTest(script=script):
                (self.work / "commands").write_text("")
                run = self.run_clients(script)
                self.assertEqual(run.returncode, 1)
                self.assertIn("alpine OpenSSL client setup failed", run.stderr)
                self.assertEqual((self.work / "commands").read_text().splitlines(),
                                 self.alpine_commands()[:i + 1])


class MatrixIngestionTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.results = self.work / "results"
        self.results.mkdir()
        (self.work / "variants.tsv").write_text("X\t-\n")
        (self.work / "leaves.tsv").write_text("leaf\tname\tsan\tname\tplain\n")
        (self.work / "combos.tsv").write_text("X\tleaf\n")
        (self.results / "good.tsv").write_bytes(b"py-3\tX\tleaf\tOK\r\n")

    def matrix(self):
        return subprocess.run(
            [sys.executable, "-I", str(SOURCE / "matrix.py"), str(self.work)],
            env={**os.environ, "OC_E1_EXPECT": "py"}, text=True, capture_output=True, timeout=5,
        )

    def test_normal_results_and_hidden_file_filter(self):
        baseline = self.matrix()
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertIn("CHECKS: all passed", baseline.stdout)
        (self.results / ".ignored.tsv").write_bytes(b"py-3\tX\tleaf\tINVALID\n")
        run = self.matrix()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout, baseline.stdout)

    def assert_rejected(self, diagnostic):
        run = self.matrix()
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(run.stdout, "")
        self.assertIn("Cannot read matrix results: " + diagnostic, run.stderr)

    def test_rejects_nonregular_result(self):
        (self.results / "directory.tsv").mkdir()
        self.assert_rejected("result must be a single-link regular file")

    def test_rejects_oversized_result(self):
        (self.results / "large.tsv").write_bytes(b"\n" * (1024 * 1024 + 1))
        self.assert_rejected("result exceeds the byte limit")

    def test_rejects_excessive_file_count(self):
        for i in range(32):
            (self.results / f"{i}.tsv").touch()
        self.assert_rejected("too many result files")

    def test_rejects_result_changed_during_read(self):
        actual_fstat = os.fstat
        file_checks = 0

        def changed_fstat(fd):
            nonlocal file_checks
            info = actual_fstat(fd)
            if stat.S_ISREG(info.st_mode):
                file_checks += 1
                if file_checks == 2:
                    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
                    return SimpleNamespace(
                        **{key: getattr(info, key) for key in fields}, st_ctime_ns=info.st_ctime_ns + 1
                    )
            return info

        with (
            patch.object(os, "fstat", changed_fstat),
            patch.object(sys, "argv", ["matrix.py", str(self.work)]),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as failure,
        ):
            runpy.run_path(str(SOURCE / "matrix.py"), run_name="__main__")
        self.assertIn("Cannot read matrix results: result changed while reading", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
