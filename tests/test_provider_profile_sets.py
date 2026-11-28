"""Provider profile sets declare bounded metadata without authorizing a launch."""

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
import sys
import tempfile
import unittest

from oc_providers.config import (
    CONFIG_FILENAME,
    MAX_CONFIG_BYTES,
    MAX_PROFILE_SETS,
    MAX_PROFILE_SET_MODELS_PER_MEMBER,
    ProviderConfigError,
    hash_providers_config_bytes,
    load_provider_config,
    parse_profile_set_config,
)
from oc_providers.contracts import MAX_PROVIDER_SLOTS, ProviderInstanceSpec


_DECLARATIONS = """
[providers.openai.harbor]
enabled = true
auth_mode = "subscription"

[providers.openai.meridian]
enabled = true
auth_mode = "subscription"

[providers.claude.birch]
enabled = true
auth_mode = "subscription"

[providers.google.orchard]
enabled = false
auth_mode = "subscription"

[provider_defaults]
openai = "meridian"
"""

_LAUNCH = """
[launch]
profile_set = "subscriptions"
mini = false
"""

_SET = """
[profile_sets.subscriptions]
default_provider = "openai/harbor"
default_model = "gpt-6.2-sol"

[profile_sets.subscriptions.members]
"openai/harbor" = ["gpt-6.2-sol", "gpt-extra"]
"openai/meridian" = ["gpt-6.2-sol", "gpt-meridian-only"]
"claude/birch" = ["claude-model-id", "gpt-6.2-sol"]
"google/orchard" = ["gemini-model-id"]
"""

_SAMPLE = _LAUNCH + _SET

_EXPECTED_INSTANCES = (
    ProviderInstanceSpec("openai", "harbor", True, "subscription"),
    ProviderInstanceSpec("openai", "meridian", True, "subscription"),
    ProviderInstanceSpec("claude", "birch", True, "subscription"),
    ProviderInstanceSpec("google", "orchard", False, "subscription"),
)


class ProviderProfileSetTests(unittest.TestCase):
    def parse(self, text=_SAMPLE, instances=_EXPECTED_INSTANCES):
        return parse_profile_set_config(text.encode("utf-8"), expected_instances=instances)

    def assert_invalid(self, text, message):
        with self.assertRaisesRegex(ProviderConfigError, message) as caught:
            self.parse(text)
        self.assertEqual(caught.exception.code, "invalid_provider_config")

    def test_distinct_declared_members_keep_duplicate_raw_model_ids(self):
        result = self.parse(_DECLARATIONS + _SAMPLE)
        self.assertEqual(result.sets, (result.selected,))
        selected = result.selected
        self.assertEqual(selected.name, "subscriptions")
        self.assertEqual(selected.default_provider, ("openai", "harbor"))
        self.assertEqual(selected.default_model, "gpt-6.2-sol")
        self.assertEqual(
            [(member.provider, member.models, member.enabled) for member in selected.members],
            [
                (("claude", "birch"), ("claude-model-id", "gpt-6.2-sol"), True),
                (("google", "orchard"), ("gemini-model-id",), False),
                (("openai", "harbor"), ("gpt-6.2-sol", "gpt-extra"), True),
                (("openai", "meridian"), ("gpt-6.2-sol", "gpt-meridian-only"), True),
            ],
        )

    def test_canonical_wire_order_and_distinct_exact_bytes_digest(self):
        first = self.parse()
        reordered = """
        [profile_sets.subscriptions]
        default_model = 'gpt-6.2-sol'
        default_provider = 'openai/harbor'

        [profile_sets.subscriptions.members]
        'google/orchard'=['gemini-model-id']
        'openai/meridian'=['gpt-meridian-only','gpt-6.2-sol']
        'claude/birch'=['gpt-6.2-sol','claude-model-id']
        'openai/harbor'=['gpt-extra','gpt-6.2-sol']
        """ + _LAUNCH
        second = self.parse(reordered, tuple(reversed(_EXPECTED_INSTANCES)))
        wire = (
            b'{"default_model":"gpt-6.2-sol","default_provider":"openai/harbor","members":'
            b'{"claude/birch":["claude-model-id","gpt-6.2-sol"],"google/orchard":["gemini-model-id"],'
            b'"openai/harbor":["gpt-6.2-sol","gpt-extra"],"openai/meridian":["gpt-6.2-sol","gpt-meridian-only"]}}'
        )
        self.assertEqual(first.selected.canonical_bytes(), wire)
        self.assertEqual(second.selected.canonical_bytes(), wire)
        self.assertEqual(first.selected.declaration_digest, sha256(b"oc-sandbox:profile-set:v1\0" + wire).hexdigest())
        self.assertEqual(first.selected.declaration_digest, second.selected.declaration_digest)
        self.assertEqual(first.config_digest, hash_providers_config_bytes(_SAMPLE.encode("utf-8")))
        self.assertEqual(second.config_digest, hash_providers_config_bytes(reordered.encode("utf-8")))
        self.assertNotEqual(first.config_digest, second.config_digest)

    def test_model_allowlist_and_default_changes_change_declaration_digest(self):
        original = self.parse().selected.declaration_digest
        changes = (
            _SAMPLE.replace('"gpt-extra"', '"gpt-different"'),
            _SAMPLE.replace('default_provider = "openai/harbor"', 'default_provider = "openai/meridian"'),
            _SAMPLE.replace('default_model = "gpt-6.2-sol"', 'default_model = "gpt-extra"'),
        )
        for text in changes:
            self.assertNotEqual(self.parse(text).selected.declaration_digest, original)

    def test_disabled_policy_is_separate_from_canonical_declaration(self):
        enabled = replace(_EXPECTED_INSTANCES[-1], enabled=True)
        enabled_result = self.parse(
            _DECLARATIONS.replace("enabled = false", "enabled = true") + _SAMPLE,
            (*_EXPECTED_INSTANCES[:-1], enabled),
        )
        disabled_result = self.parse(_DECLARATIONS + _SAMPLE)
        self.assertTrue(enabled_result.selected.members[1].enabled)
        self.assertFalse(disabled_result.selected.members[1].enabled)
        self.assertEqual(enabled_result.selected.declaration_digest, disabled_result.selected.declaration_digest)
        self.assertNotEqual(enabled_result.config_digest, disabled_result.config_digest)

    def test_alternate_set_and_set_free_projection(self):
        alternate = _SET.replace("profile_sets.subscriptions", "profile_sets.alternate").replace(
            'default_provider = "openai/harbor"', 'default_provider = "openai/meridian"'
        )
        result = self.parse(_LAUNCH.replace('"subscriptions"', '"alternate"') + _SET + alternate)
        self.assertEqual(tuple(item.name for item in result.sets), ("alternate", "subscriptions"))
        self.assertEqual(result.selected.default_provider, ("openai", "meridian"))
        self.assertIsNone(self.parse(_SET + alternate).selected)
        legacy = self.parse(_DECLARATIONS + '[launch]\nmini = true\ndefault_provider = "openai/harbor"\n')
        self.assertIsNone(legacy.selected)
        self.assertEqual(legacy.sets, ())

    def test_invalid_structure_selectors_and_model_ids(self):
        cases = (
            (_SAMPLE + '"openai/harbor" = ["duplicate"]\n', "malformed providers.toml"),
            (_SAMPLE + "'openai/harbor' = ['duplicate']\n", "malformed providers.toml"),
            (_SAMPLE.replace(_LAUNCH, _LAUNCH + 'profile_set = "subscriptions"\n'), "malformed providers.toml"),
            (_SAMPLE.replace('"subscriptions"', '"missing"'), "reference a declared profile set"),
            (_SAMPLE.replace('"subscriptions"', '"Subscriptions"'), "invalid .*profile_set"),
            (_SAMPLE.replace('profile_set = "subscriptions"', "profile_set = 1"), "invalid .*profile_set"),
            (_SET.replace("profile_sets.subscriptions", "profile_sets.Wrong"), "invalid name"),
            (_SAMPLE.replace("mini = false", 'mini = "false"'), "mini must be boolean"),
            (_SAMPLE.replace("mini = false", 'unrecognized = false'), "invalid fields in"),
            (_SAMPLE.replace(_LAUNCH, _LAUNCH + 'default_provider = "openai/harbor"\n'), "conflicts"),
            (_SAMPLE.replace(_LAUNCH, _LAUNCH + 'default_model = "gpt-6.2-sol"\n'), "conflicts"),
            ("unexpected = 0\n" + _SAMPLE, "unexpected top-level"),
            ("profile_sets = true\n", "must be a table"),
            (_SAMPLE.replace("[profile_sets.subscriptions.members]", 'billing = "subscription"\n[profile_sets.subscriptions.members]'), "invalid name or fields"),
            (_SAMPLE.split('"openai/harbor" = [')[0], "requires 1 to .* members"),
            (_SAMPLE.replace('["gpt-6.2-sol", "gpt-extra"]', "[]"), "requires 1 to .* models"),
            (_SAMPLE.replace('["gpt-6.2-sol", "gpt-extra"]', '"gpt-6.2-sol"'), "requires 1 to .* models"),
            (_SAMPLE.replace('"gpt-extra"', '"gpt-6.2-sol"'), "duplicate profile set member model"),
            (_SAMPLE.replace('"gpt-extra"', '"provider/friendly-title"'), "invalid profile set member model"),
            (_SAMPLE.replace('"gpt-extra"', "1"), "invalid profile set member model"),
            (_SAMPLE.replace('"openai/harbor" = [', '"openai/Harbor" = ['), "profile set member must reference"),
            (_SAMPLE.replace('"openai/harbor" = [', '"harbor" = ['), "profile set member must be"),
        )
        for text, message in cases:
            with self.subTest(message=message, text=text):
                self.assert_invalid(text, message)
        with self.assertRaisesRegex(ProviderConfigError, "malformed providers.toml"):
            parse_profile_set_config(b"\xff", expected_instances=_EXPECTED_INSTANCES)
        self.assert_invalid("#" * (MAX_CONFIG_BYTES + 1), "size limit")

    def test_nested_toml_parser_failure_is_typed(self):
        depth = sys.getrecursionlimit() + 10
        raw = "profile_sets = " + "[" * depth + "0" + "]" * depth
        self.assertLess(len(raw), MAX_CONFIG_BYTES)
        self.assert_invalid(raw, "^malformed providers.toml$")

    def test_toml_integer_conversion_failure_is_typed(self):
        limit = 4300
        self.addCleanup(sys.set_int_max_str_digits, sys.get_int_max_str_digits())
        sys.set_int_max_str_digits(limit)
        raw = "profile_sets = " + "9" * (limit + 1)
        self.assertLess(len(raw), MAX_CONFIG_BYTES)
        self.assert_invalid(raw, "^malformed providers.toml$")

    def test_named_defaults_must_match_one_exact_declared_member_and_model(self):
        default_provider = 'default_provider = "openai/harbor"'
        default_model = 'default_model = "gpt-6.2-sol"'
        self.assert_invalid(_SAMPLE.replace(default_provider, ""), "invalid name or fields")
        self.assert_invalid(_SAMPLE.replace(default_model, ""), "invalid name or fields")
        self.assert_invalid(_SAMPLE.replace(default_model, 'default_model = "invalid/model"'), "invalid .* default_model")
        self.assert_invalid(_SAMPLE.replace(default_model, 'default_model = "gpt-missing"'), "its allowed model")
        self.assert_invalid(_SAMPLE.replace(default_model, 'default_model = "gpt-meridian-only"'), "its allowed model")
        self.assert_invalid(
            _SAMPLE.replace('"openai/harbor" = ["gpt-6.2-sol", "gpt-extra"]', ""),
            "its allowed model",
        )

    def test_unknown_members_are_distinct_from_incompatible_auth(self):
        with self.assertRaisesRegex(ProviderConfigError, "undeclared provider instance") as caught:
            self.parse(instances=_EXPECTED_INSTANCES[1:])
        self.assertEqual(caught.exception.code, "unknown_profile_set_member")
        api_key = replace(_EXPECTED_INSTANCES[0], auth_mode="api_key")
        with self.assertRaisesRegex(ProviderConfigError, "must use subscription") as caught:
            self.parse(instances=(api_key, *_EXPECTED_INSTANCES[1:]))
        self.assertEqual(caught.exception.code, "invalid_provider_config")

    def test_set_member_and_model_caps_apply_independently(self):
        capped_sets = self.parse("".join(
            _SET.replace("profile_sets.subscriptions", f"profile_sets.set-{index}")
            for index in range(MAX_PROFILE_SETS)
        ))
        self.assertEqual(len(capped_sets.sets), MAX_PROFILE_SETS)
        self.assert_invalid(
            "".join(_SET.replace("profile_sets.subscriptions", f"profile_sets.set-{index}")
                    for index in range(MAX_PROFILE_SETS + 1)),
            "at most .* sets",
        )

        instances = tuple(
            ProviderInstanceSpec("openai", f"account-{index}", False, "subscription")
            for index in range(MAX_PROVIDER_SLOTS + 1)
        )
        def members(count):
            return """
            [profile_sets.subscriptions]
            default_provider = "openai/account-0"
            default_model = "model"
            [profile_sets.subscriptions.members]
            """ + "\n".join(
                f'"openai/account-{index}" = ["model"]' for index in range(count)
            )

        self.assertEqual(len(self.parse(members(MAX_PROVIDER_SLOTS), instances).sets[0].members), MAX_PROVIDER_SLOTS)
        with self.assertRaisesRegex(ProviderConfigError, "requires 1 to .* members"):
            self.parse(members(MAX_PROVIDER_SLOTS + 1), instances)

        def many_models(count):
            models = ", ".join(f'"extra-{index}"' for index in range(count - 1))
            return _SAMPLE.replace('"gpt-extra"', models)

        self.assertEqual(len(self.parse(many_models(MAX_PROFILE_SET_MODELS_PER_MEMBER)).selected.members[2].models),
                         MAX_PROFILE_SET_MODELS_PER_MEMBER)
        self.assert_invalid(many_models(MAX_PROFILE_SET_MODELS_PER_MEMBER + 1), "requires 1 to .* models")

    def test_current_production_loader_keeps_existing_config_and_refuses_new_fields(self):
        legacy = _DECLARATIONS + '[launch]\nmini = true\ndefault_provider = "openai/meridian"\n'
        with tempfile.TemporaryDirectory(prefix="oc-profile-set-test-") as tmp:
            directory = Path(tmp)
            config_path = directory / CONFIG_FILENAME
            config_path.write_text(legacy, encoding="utf-8")
            config_path.chmod(0o600)
            config = load_provider_config(config_dir=directory, sandbox_dir=directory.parent / "unused-sandbox")
            self.assertTrue(config.launch.mini)
            self.assertEqual(config.launch.default_provider, ("openai", "meridian"))
            self.assertEqual(config.provider_defaults, {"openai": "meridian"})
            self.assertEqual(set(config.instances), set(_EXPECTED_INSTANCES))

            for addition in (_LAUNCH, _SET, _SAMPLE):
                config_path.write_text(_DECLARATIONS + addition, encoding="utf-8")
                with self.assertRaisesRegex(ProviderConfigError, "invalid fields in .*launch|unexpected top-level"):
                    load_provider_config(config_dir=directory, sandbox_dir=directory.parent / "unused-sandbox")


if __name__ == "__main__":
    unittest.main()
