"""Exercise launcher dispatch with a scratch home and stubbed host commands."""

from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest


SOURCE = Path(__file__).resolve().parents[1]


class OpenAILauncherTests(unittest.TestCase):
    def setUp(self):
        scratch = self.enterContext(TemporaryDirectory())
        self.root = Path(scratch)
        self.home = self.root / "home"
        self.checkout = self.root / "checkout"
        self.stubs = self.root / "stubs"
        self.marker = self.root / "legacy-host-command"
        for directory in (self.home, self.checkout, self.stubs):
            directory.mkdir()
        self.launcher = self.checkout / "oc-sandbox"
        self.bootstrap = self.checkout / "oc-openai.py"
        self.package = self.checkout / "oc_openai"
        self.package.mkdir()
        for name in (
            "oc-sandbox", "oc-openai.py", "oc_openai/__init__.py", "oc_openai/cli.py",
            "oc_openai/profiles.py", "oc_openai/connection_state.py", "oc_openai/exposure.py",
        ):
            shutil.copy2(SOURCE / name, self.checkout / name)
        for command in ("podman", "systemctl", "distrobox-host-exec", "curl", "readlink", "realpath"):
            stub = self.stubs / command
            stub.write_text(f"#!/bin/sh\ntouch '{self.marker}'\nexit 99\n")
            stub.chmod(0o700)
        self.env = {
            "HOME": str(self.home),
            "PATH": str(self.stubs) + ":/usr/bin:/bin",
            "OPENAI_API_KEY": "synthetic-key-must-not-be-inherited",
            "PYTHONPATH": str(self.home),
        }

    def launch(self, *args, path=None):
        result = subprocess.run(
            [str(path or self.launcher), *args],
            cwd=self.home, env=self.env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
        )
        self.assertFalse(self.marker.exists(), "legacy effects occurred")
        self.assertFalse((self.home / ".local/share/oc-sandbox").exists())
        return result

    def test_exact_command_is_reserved_and_invalid_invocations_are_effect_free(self):
        for args in [
            ("openai",), ("openai", "bogus"), ("openai", "accept", "-d"),
            ("openai", "connect"), ("openai", "select"), ("openai", "select", "work", "-d"),
            ("openai", "accept", "--no-browser"), ("openai", "connect", "--no-browser", "work"),
            ("openai", "connect", "work", "--no-browser", "--no-browser"),
        ]:
            with self.subTest(args=args):
                result = self.launch(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("usage: oc-sandbox openai", result.stderr)

        for label in ("", "--flag", "../outside", "üser", "line\nbreak", "a" * 33):
            with self.subTest(label=label):
                result = self.launch("openai", "select", label)
                self.assertEqual(result.returncode, 2)
                self.assertIn("labels must be 1 to 32 ASCII", result.stderr)

        result = self.launch("openai", "accept")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage: oc-sandbox openai", result.stderr)
        self.assertNotIn("accept", self.launch("-h").stdout)
        result = self.launch("openai", "connect", "work", "--no-browser")
        self.assertEqual(result.returncode, 2)
        self.assertIn("attended workstation terminal", result.stderr)

    def test_legacy_help_and_parser_are_still_available(self):
        result = self.launch("-h")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Ensure everything exists", result.stdout)
        result = self.launch("-n", "openai", "disconnect")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unexpected argument: openai", result.stderr)

    def test_interpreter_ignores_startup_environment_before_openai_and_legacy_parsing(self):
        startup = self.home / "startup.sh"
        startup.write_text('printf "startup\\n" > "$HOME/startup-marker"\n')
        self.env["BASH_ENV"] = str(startup)
        path_bash = self.stubs / "bash"
        path_bash.write_text(
            '#!/bin/sh\nprintf "path-bash\\n" > "$HOME/path-marker"\nexec /usr/bin/bash "$@"\n'
        )
        path_bash.chmod(0o700)
        result = self.launch("openai", "connect", "work")
        self.assertEqual(result.returncode, 2)
        self.assertIn("attended workstation terminal", result.stderr)
        result = self.launch("-h")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Ensure everything exists", result.stdout)
        self.assertFalse((self.home / "path-marker").exists())
        self.assertFalse((self.home / "startup-marker").exists())

    def test_installed_style_link_drops_environment_and_ignores_caller_cwd(self):
        link = self.home / "oc-sandbox"
        link.symlink_to(self.launcher)
        (self.home / "oc_openai.py").write_text("raise RuntimeError('untrusted import')\n")
        (self.package / "live.py").write_text(
            "import os\n"
            "from pathlib import Path\n"
            "from .cli import ConnectionStatus, SavedProfile\n"
            "class Backend:\n"
            "    def status(self):\n"
            "        assert 'OPENAI_API_KEY' not in os.environ and 'PYTHONPATH' not in os.environ\n"
            "        assert Path.cwd() == Path(__file__).parent.parent\n"
            "        return ConnectionStatus((SavedProfile('work', True),), 'work')\n"
            "    def select(self, label):\n"
            "        assert label == 'work'\n"
            "def make_backend():\n"
            "    return Backend()\n"
        )
        result = self.launch("openai", "status", path=link)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("work (connected, active)", result.stdout)
        result = self.launch("openai", "select", "work", path=link)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Selected ChatGPT registration work", result.stdout)

    def test_rejects_helper_or_package_links_into_sandbox(self):
        sandbox = self.home / "opencode-sandbox"
        sandbox.mkdir()
        script = sandbox / "fake.py"
        script.write_text("raise SystemExit(98)\n")
        live = self.package / "live.py"
        live.symlink_to(script)
        result = self.launch("openai", "status")
        self.assertEqual(result.returncode, 1)
        self.assertIn("trusted workstation command unavailable", result.stderr)
        self.bootstrap.unlink()
        self.bootstrap.symlink_to(script)
        result = self.launch("openai", "status")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsafe OpenAI helper path", result.stderr)

    def test_launcher_link_may_not_pass_through_sandbox_even_if_target_is_trusted(self):
        sandbox = self.home / "opencode-sandbox"
        sandbox.mkdir()
        inside = sandbox / "launcher"
        inside.symlink_to(self.launcher)
        outside = self.home / "oc-sandbox"
        outside.symlink_to(inside)
        result = self.launch("openai", "status", path=outside)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsafe OpenAI launcher path", result.stderr)


if __name__ == "__main__":
    unittest.main()
