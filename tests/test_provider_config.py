"""Unit tests for trusted operator providers.toml loading and strict schema validation."""

import os
from pathlib import Path
import tempfile
import unittest

from oc_providers.config import (
    CONFIG_FILENAME,
    MAX_CONFIG_BYTES,
    ProviderConfigError,
    load_provider_config,
)


def _write_toml(config_dir: Path, text: str, *, mode: int = 0o600) -> Path:
    path = config_dir / CONFIG_FILENAME
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)
    return path


class ProviderConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="oc-cfg-test-")))
        self.cfg_dir = self.tmp / "config"
        self.cfg_dir.mkdir(mode=0o700)
        self.sandbox = self.tmp / "opencode-sandbox"
        self.sandbox.mkdir(mode=0o700)

    def _load(self):
        return load_provider_config(config_dir=self.cfg_dir, sandbox_dir=self.sandbox)

    def test_missing_directory_or_file_returns_none(self):
        self.assertIsNone(self._load())
        self.assertIsNone(
            load_provider_config(config_dir=self.tmp / "does-not-exist", sandbox_dir=self.sandbox)
        )

    def test_valid_multi_provider_toml_and_launch_defaults(self):
        _write_toml(
            self.cfg_dir,
            """
            [provider_defaults]
            openai = "personal"
            claude = "work-main"

            [launch]
            default_provider = "openai/personal"
            default_model = "gpt-6.2-sol"
            mini = true

            [providers.openai.personal]
            enabled = true
            auth_mode = "subscription"
            default_model = "gpt-6.2-sol"

            [providers.openai.team-api]
            enabled = false
            auth_mode = "api_key"
            credential_ref = "openai-team-prod"

            [providers.claude.work-main]
            enabled = true
            auth_mode = "subscription"
            cli_path = "/usr/local/bin/claude"

            [providers.google.personal]
            enabled = true
            auth_mode = "subscription"
            cli_path = "/opt/bin/agy"
            """,
        )
        cfg = self._load()
        self.assertIsNotNone(cfg)
        self.assertEqual(len(cfg.instances), 4)
        self.assertEqual(cfg.provider_defaults, {"openai": "personal", "claude": "work-main"})
        self.assertEqual(cfg.launch.default_provider, ("openai", "personal"))
        self.assertEqual(cfg.launch.default_model, "gpt-6.2-sol")
        self.assertIs(cfg.launch.mini, True)
        self.assertEqual(cfg.get("openai", "team-api").credential_ref, "openai-team-prod")
        self.assertEqual(cfg.get("claude", "work-main").cli_path, "/usr/local/bin/claude")

    def test_untrusted_file_permissions_symlinks_hardlinks_fifo_and_sandbox_rejected(self):
        cfg_file = _write_toml(self.cfg_dir, "[providers]\n", mode=0o664)
        with self.assertRaisesRegex(ProviderConfigError, "permissions"):
            self._load()
        os.chmod(cfg_file, 0o600)

        hardlink = self.cfg_dir / "other.toml"
        os.link(cfg_file, hardlink)
        try:
            with self.assertRaisesRegex(ProviderConfigError, "permissions|links"):
                self._load()
        finally:
            hardlink.unlink()

        cfg_file.unlink()
        target = self.tmp / "real.toml"
        target.write_text("[providers]\n", encoding="utf-8")
        os.chmod(target, 0o600)
        cfg_file.symlink_to(target)
        with self.assertRaises(ProviderConfigError):
            self._load()
        cfg_file.unlink()

        os.mkfifo(cfg_file, 0o600)
        try:
            with self.assertRaises(ProviderConfigError):
                self._load()
        finally:
            cfg_file.unlink()

        inside_sb = self.sandbox / "cfg"
        inside_sb.mkdir(mode=0o700)
        _write_toml(inside_sb, "[providers]\n")
        with self.assertRaisesRegex(ProviderConfigError, "sandbox"):
            load_provider_config(config_dir=inside_sb, sandbox_dir=self.sandbox)

        _write_toml(self.cfg_dir, "#" * (MAX_CONFIG_BYTES + 10))
        with self.assertRaisesRegex(ProviderConfigError, "size"):
            self._load()

    def test_schema_rejects_unknown_sections_raw_secrets_bad_labels_and_unsafe_cli_paths(self):
        bad_cases = (
            ("unknown_top_level", "[bogus]\nx = 1\n"),
            ("unknown_instance_field", '[providers.openai.personal]\nenabled = true\nauth_mode = "subscription"\napi_key = "nope"\n'),
            ("missing_enabled", '[providers.openai.personal]\nauth_mode = "subscription"\n'),
            ("non_bool_enabled", '[providers.openai.personal]\nenabled = "true"\nauth_mode = "subscription"\n'),
            ("bad_label_uppercase", '[providers.openai.Work]\nenabled = true\nauth_mode = "subscription"\n'),
            ("bad_label_underscore", '[providers.openai.work_1]\nenabled = true\nauth_mode = "subscription"\n'),
            ("bad_label_double_hyphen", '[providers.openai.work--1]\nenabled = true\nauth_mode = "subscription"\n'),
            ("cred_ref_on_subscription", '[providers.openai.personal]\nenabled = true\nauth_mode = "subscription"\ncredential_ref = "ref"\n'),
            ("missing_cred_ref_on_api_key", '[providers.openai.team]\nenabled = true\nauth_mode = "api_key"\n'),
            ("raw_sk_secret_in_cred_ref", '[providers.openai.team]\nenabled = true\nauth_mode = "api_key"\ncredential_ref = "sk-live12345"\n'),
            ("raw_ghp_secret_in_cred_ref", '[providers.openai.team]\nenabled = true\nauth_mode = "api_key"\ncredential_ref = "ghp_abc123"\n'),
            ("cli_path_on_openai", '[providers.openai.personal]\nenabled = true\nauth_mode = "subscription"\ncli_path = "/usr/bin/openai"\n'),
            ("cli_path_relative", '[providers.claude.personal]\nenabled = true\nauth_mode = "subscription"\ncli_path = "bin/claude"\n'),
            ("cli_path_dotdot", '[providers.claude.personal]\nenabled = true\nauth_mode = "subscription"\ncli_path = "/usr/../bin/claude"\n'),
            ("cli_path_inside_sandbox", f'[providers.claude.personal]\nenabled = true\nauth_mode = "subscription"\ncli_path = "{self.sandbox}/claude"\n'),
            ("undeclared_provider_default", '[provider_defaults]\nopenai = "missing"\n'),
            ("launch_model_without_provider", '[launch]\ndefault_model = "gpt-6.2-sol"\n'),
            ("launch_undeclared_provider", '[launch]\ndefault_provider = "openai/missing"\n'),
            ("launch_non_bool_mini", '[launch]\nmini = "yes"\n'),
        )
        for name, body in bad_cases:
            with self.subTest(case=name):
                _write_toml(self.cfg_dir, body)
                with self.assertRaises(ProviderConfigError):
                    self._load()

    def test_more_than_16_enabled_instances_rejected(self):
        blocks = [
            f'[providers.openai.acc-{idx}]\nenabled = true\nauth_mode = "subscription"\n'
            for idx in range(17)
        ]
        _write_toml(self.cfg_dir, "\n".join(blocks))
        with self.assertRaisesRegex(ProviderConfigError, "at most 16"):
            self._load()


if __name__ == "__main__":
    unittest.main()
