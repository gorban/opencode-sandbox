"""Unit tests for multi-provider catalog resolution, disclosure, narrowing, and --mini mode."""

from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest

from oc_providers.catalog import (
    LaunchRefusedError,
    build_multi_provider_opencode_config,
    expected_provider_display_name,
    plan_interactive_launch,
    project_picker_rows,
    validate_opencode_config,
)
from oc_providers.config import LaunchDefaults, ProviderConfig
from oc_providers.contracts import (
    ExposureHoldSummary,
    InstancePreflight,
    PersistedSelection,
    ProviderId,
    ProviderInstanceSpec,
    ProviderIntegrityError,
    ReadinessState,
    SelectionState,
    sanitize_display_text,
)
from oc_providers.registry import UnqualifiedProviderAdapter, default_session_adapters


class _FakeTerminal:
    def __init__(self, *, confirms=(), choices=(), attended=True):
        self._attended = attended
        self._confirms = list(confirms)
        self._choices = list(choices)
        self.lines: list[str] = []
        self.errors: list[str] = []
        self.confirm_prompts: list[str] = []
        self.choose_prompts: list[tuple[str, list[str]]] = []

    def attended(self) -> bool:
        return self._attended

    def write(self, text: str) -> None:
        self.lines.append(text)

    def error(self, text: str) -> None:
        self.errors.append(text)

    def confirm(self, prompt: str) -> bool:
        self.confirm_prompts.append(prompt)
        return self._confirms.pop(0) if self._confirms else True

    def choose(self, prompt: str, options) -> int | None:
        self.choose_prompts.append((prompt, list(options)))
        return self._choices.pop(0) if self._choices else 0


class _FakeAdapter:
    def __init__(
        self,
        kind: ProviderId,
        *,
        qualified_modes: frozenset[str] = frozenset({"subscription"}),
        active: str | None = None,
        selection: PersistedSelection | None = None,
        discovered: tuple[ProviderInstanceSpec, ...] = (),
        preflights: dict[str, InstancePreflight] | None = None,
        integrity_on: set[str] | None = None,
    ):
        self.kind = kind
        self._qualified_modes = qualified_modes
        self._active = active
        self._selection = selection
        self._discovered = discovered
        self._preflights = preflights or {}
        self._integrity_on = integrity_on or set()

    def is_qualified(self, auth_mode: str, placement: str) -> bool:
        return placement == "sandbox" and auth_mode in self._qualified_modes

    def active_label(self) -> str | None:
        return self._active

    def selection_state(self) -> PersistedSelection:
        if self._selection is not None:
            return self._selection
        if self._active is not None:
            return PersistedSelection(SelectionState.SELECTED, label=self._active)
        return PersistedSelection(SelectionState.UNSET)

    def discover_instances(self) -> tuple[ProviderInstanceSpec, ...]:
        return self._discovered

    def preflight_instance(self, instance: ProviderInstanceSpec) -> InstancePreflight:
        if instance.label in self._integrity_on:
            raise ProviderIntegrityError("corrupt_store", f"corrupt store for {instance.qualified_name}")
        return self._preflights.get(
            instance.label,
            InstancePreflight(spec=instance, readiness=ReadinessState.DISCONNECTED),
        )

    def provider_config_entry(
        self,
        preflight: InstancePreflight,
        *,
        port: int,
        worker_token: str,
        display_label: str | None = None,
    ) -> dict:
        label = display_label or preflight.spec.label
        return {
            "name": expected_provider_display_name(preflight, label),
            "package": "@opencode/ai/providers/openai-compatible/responses",
            "settings": {"baseURL": f"http://127.0.0.1:{port}/v1", "apiKey": worker_token, "store": False},
            "models": {
                slug: {
                    "name": slug,
                    "capabilities": {"tools": True, "input": ["text"], "output": ["text"]},
                    "limit": {"context": 128000, "output": 16384},
                }
                for slug in preflight.models
            },
        }

    def open_slot(self, *_args, **_kwargs):
        return nullcontext(None)


def _spec(kind: ProviderId, label: str, *, enabled=True, auth_mode="subscription", default_model=None):
    return ProviderInstanceSpec(
        kind=kind, label=label, enabled=enabled, auth_mode=auth_mode,
        credential_ref="ref-1" if auth_mode == "api_key" else None,
        default_model=default_model,
    )


class ProviderCatalogTests(unittest.TestCase):
    def test_default_multi_provider_admits_all_qualified_and_builds_merged_config(self):
        oa_personal = _spec("openai", "personal", default_model="gpt-6.2-sol")
        oa_work = _spec("openai", "work")
        oa_disabled = _spec("openai", "disabled-one", enabled=False)
        oa_api = _spec("openai", "team-api", auth_mode="api_key")
        cl_personal = _spec("claude", "personal")
        cl_offline = _spec("claude", "offline")
        gg_unqual = _spec("google", "personal")

        cfg = ProviderConfig(
            instances=(oa_personal, oa_work, oa_disabled, oa_api, cl_personal, cl_offline, gg_unqual),
            provider_defaults={"openai": "personal"},
            launch=LaunchDefaults(default_provider=("openai", "personal"), default_model="gpt-6.2-sol"),
        )
        adapters = {
            "openai": _FakeAdapter(
                "openai",
                active="personal",
                preflights={
                    "personal": InstancePreflight(oa_personal, ReadinessState.READY, ("gpt-6.2-sol", "gpt-6.1-sol"), route_policy="sub"),
                    "work": InstancePreflight(oa_work, ReadinessState.READY, ("gpt-6.1-sol",), route_policy="sub"),
                },
            ),
            "claude": _FakeAdapter(
                "claude",
                active="personal",
                preflights={
                    "personal": InstancePreflight(cl_personal, ReadinessState.READY, ("claude-sonnet",), route_policy="sub"),
                    "offline": InstancePreflight(cl_offline, ReadinessState.DISCONNECTED),
                },
            ),
            "google": _FakeAdapter("google", qualified_modes=frozenset()),
        }
        term = _FakeTerminal(confirms=[True])
        plan = plan_interactive_launch(
            instance_name="default",
            cwd="construct",
            provider_filter="",
            cli_ui_mode="mini",
            config=cfg,
            adapters=adapters,
            terminal=term,
        )
        self.assertEqual([item.spec.scoped_id for item in plan.admitted], [
            "openai--personal", "openai--work", "claude--personal",
        ])
        self.assertEqual({(e.kind, e.label, e.reason) for e in plan.excluded}, {
            ("openai", "disabled-one", "disabled"),
            ("openai", "team-api", "unqualified"),
            ("claude", "offline", "disconnected"),
            ("google", "personal", "unqualified"),
        })
        self.assertEqual((plan.initial_provider_id, plan.initial_model), ("openai--personal", "gpt-6.2-sol"))
        self.assertEqual((plan.ui_mode, plan.ui_source), ("mini", "--mini"))
        self.assertEqual(term.choose_prompts, [])

        oc_cfg = build_multi_provider_opencode_config(
            plan=plan,
            adapters=adapters,
            slot_ports={"openai--personal": 8401, "openai--work": 8402, "claude--personal": 8403},
            slot_tokens={"openai--personal": "tok-a", "openai--work": "tok-b", "claude--personal": "tok-c"},
        )
        self.assertEqual(oc_cfg["model"], "openai--personal/gpt-6.2-sol")
        self.assertEqual(set(oc_cfg["providers"]), {"openai--personal", "openai--work", "claude--personal"})
        self.assertEqual(oc_cfg["providers"]["openai--work"]["settings"]["baseURL"], "http://127.0.0.1:8402/v1")
        self.assertEqual(oc_cfg["providers"]["claude--personal"]["settings"]["apiKey"], "tok-c")
        allowed = [p["resource"] for p in oc_cfg["policies"] if p["action"] == "provider.use" and p["effect"] == "allow"]
        self.assertEqual(allowed, ["openai--personal", "openai--work", "claude--personal"])

    def test_integrity_failure_aborts_entire_default_launch(self):
        oa_good = _spec("openai", "personal")
        oa_bad = _spec("openai", "corrupt")
        cfg = ProviderConfig(instances=(oa_good, oa_bad), provider_defaults={}, launch=LaunchDefaults())
        adapters = {
            "openai": _FakeAdapter(
                "openai",
                preflights={"personal": InstancePreflight(oa_good, ReadinessState.READY, ("gpt-6.2-sol",))},
                integrity_on={"corrupt"},
            ),
        }
        term = _FakeTerminal()
        with self.assertRaisesRegex(ProviderIntegrityError, "corrupt"):
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="",
                cli_ui_mode="default", config=cfg, adapters=adapters, terminal=term,
            )

    def test_shared_exposure_hold_prompts_once_per_scope_and_decline_excludes_scope(self):
        oa_a = _spec("openai", "personal")
        oa_b = _spec("openai", "work")
        cl_a = _spec("claude", "personal")
        hold = ExposureHoldSummary(scope_id="openai", file_count=2, unsettled_count=1, digest="a" * 64)
        cfg = ProviderConfig(instances=(oa_a, oa_b, cl_a), provider_defaults={}, launch=LaunchDefaults())
        adapters = {
            "openai": _FakeAdapter(
                "openai",
                preflights={
                    "personal": InstancePreflight(oa_a, ReadinessState.READY, ("gpt-6.2-sol",), exposure_hold=hold, route_policy="sub"),
                    "work": InstancePreflight(oa_b, ReadinessState.READY, ("gpt-6.2-sol",), exposure_hold=hold, route_policy="sub"),
                },
            ),
            "claude": _FakeAdapter(
                "claude",
                preflights={"personal": InstancePreflight(cl_a, ReadinessState.READY, ("claude-sonnet",), route_policy="sub")},
            ),
        }
        # Decline shared openai hold -> both openai instances excluded, claude admitted and confirmed.
        term = _FakeTerminal(confirms=[False, True])
        plan = plan_interactive_launch(
            instance_name="default", cwd="construct", provider_filter="",
            cli_ui_mode="default", config=cfg, adapters=adapters, terminal=term,
        )
        self.assertEqual([item.spec.scoped_id for item in plan.admitted], ["claude--personal"])
        self.assertEqual(plan.acknowledged_digests, {})
        self.assertEqual(len(term.confirm_prompts), 2)
        self.assertIn("openai/personal, openai/work", term.confirm_prompts[0])

    def test_disconnected_default_provider_prompts_explicitly_never_silent_switch(self):
        oa_down = _spec("openai", "personal")
        oa_paid = _spec("openai", "team-api", auth_mode="api_key")
        cfg = ProviderConfig(
            instances=(oa_down, oa_paid),
            provider_defaults={"openai": "personal"},
            launch=LaunchDefaults(default_provider=("openai", "personal")),
        )
        adapters = {
            "openai": _FakeAdapter(
                "openai",
                qualified_modes=frozenset({"subscription", "api_key"}),
                preflights={
                    "personal": InstancePreflight(oa_down, ReadinessState.DISCONNECTED),
                    "team-api": InstancePreflight(oa_paid, ReadinessState.READY, ("gpt-6.2-sol",), route_policy="paid api_key"),
                },
            ),
        }
        # Operator cancels when prompted because configured default subscription is down.
        term = _FakeTerminal(choices=[None])
        with self.assertRaisesRegex(LaunchRefusedError, "Cancelled"):
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="",
                cli_ui_mode="default", config=cfg, adapters=adapters, terminal=term,
            )
        self.assertEqual(len(term.choose_prompts), 1)

    def test_narrowed_bare_provider_never_falls_through_from_disconnected_selection(self):
        oa_a = _spec("openai", "personal")
        oa_b = _spec("openai", "work")
        cfg = ProviderConfig(
            instances=(oa_a, oa_b),
            provider_defaults={"openai": "work"},
            launch=LaunchDefaults(),
        )
        adapters = {
            "openai": _FakeAdapter(
                "openai",
                active="personal",  # persisted active is personal, which is disconnected!
                preflights={
                    "personal": InstancePreflight(oa_a, ReadinessState.DISCONNECTED),
                    "work": InstancePreflight(oa_b, ReadinessState.READY, ("gpt-6.2-sol",)),
                },
            ),
        }
        term = _FakeTerminal()
        with self.assertRaisesRegex(LaunchRefusedError, "openai/personal.*disconnected"):
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="openai",
                cli_ui_mode="default", config=cfg, adapters=adapters, terminal=term,
            )

    def test_narrowed_disabled_or_undeclared_instance_fails_closed(self):
        oa_a = _spec("openai", "personal", enabled=False)
        oa_b = _spec("openai", "work", enabled=True)
        cfg = ProviderConfig(instances=(oa_a, oa_b), provider_defaults={}, launch=LaunchDefaults())
        adapters = {
            "openai": _FakeAdapter(
                "openai",
                preflights={"work": InstancePreflight(oa_b, ReadinessState.READY, ("gpt-6.2-sol",))},
            ),
        }
        term = _FakeTerminal()
        with self.assertRaisesRegex(LaunchRefusedError, "disabled"):
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="openai/personal",
                cli_ui_mode="default", config=cfg, adapters=adapters, terminal=term,
            )
        with self.assertRaisesRegex(LaunchRefusedError, "not declared"):
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="openai/missing",
                cli_ui_mode="default", config=cfg, adapters=adapters, terminal=term,
            )

    def test_ui_mode_precedence_no_mini_overrides_toml_mini(self):
        oa_a = _spec("openai", "personal")
        cfg = ProviderConfig(instances=(oa_a,), provider_defaults={}, launch=LaunchDefaults(mini=True))
        adapters = {
            "openai": _FakeAdapter(
                "openai",
                preflights={"personal": InstancePreflight(oa_a, ReadinessState.READY, ("gpt-6.2-sol",), route_policy="sub")},
            ),
        }
        plan_toml = plan_interactive_launch(
            instance_name="default", cwd="construct", provider_filter="",
            cli_ui_mode="default", config=cfg, adapters=adapters, terminal=_FakeTerminal(confirms=[True]),
        )
        self.assertEqual((plan_toml.ui_mode, plan_toml.ui_source), ("mini", "providers.toml"))

        plan_override = plan_interactive_launch(
            instance_name="default", cwd="construct", provider_filter="",
            cli_ui_mode="full", config=cfg, adapters=adapters, terminal=_FakeTerminal(confirms=[True]),
        )
        self.assertEqual((plan_override.ui_mode, plan_override.ui_source), ("full", "--no-mini"))

    def test_narrowed_bare_provider_refuses_disconnected_selection_state_without_default_fallback(self):
        oa_a = _spec("openai", "personal")
        oa_b = _spec("openai", "backup")
        cfg = ProviderConfig(
            instances=(oa_a, oa_b),
            provider_defaults={"openai": "backup"},
            launch=LaunchDefaults(),
        )
        # Disconnected persisted selection MUST refuse instead of silently falling back to provider_defaults.
        adapters_disc = {
            "openai": _FakeAdapter(
                "openai",
                selection=PersistedSelection(SelectionState.DISCONNECTED),
                preflights={"backup": InstancePreflight(oa_b, ReadinessState.READY, ("gpt-6.2-sol",), route_policy="sub")},
            ),
        }
        term_disc = _FakeTerminal()
        with self.assertRaises(LaunchRefusedError) as ctx:
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="openai",
                cli_ui_mode="default", config=cfg, adapters=adapters_disc, terminal=term_disc,
            )
        self.assertEqual(ctx.exception.code, "selection_disconnected")

        # Never-selected (UNSET) adapter still resolves [provider_defaults].openai cleanly.
        adapters_unset = {
            "openai": _FakeAdapter(
                "openai",
                selection=PersistedSelection(SelectionState.UNSET),
                preflights={"backup": InstancePreflight(oa_b, ReadinessState.READY, ("gpt-6.2-sol",), route_policy="sub")},
            ),
        }
        plan = plan_interactive_launch(
            instance_name="default", cwd="construct", provider_filter="openai",
            cli_ui_mode="default", config=cfg, adapters=adapters_unset, terminal=_FakeTerminal(confirms=[True]),
        )
        self.assertEqual([item.spec.label for item in plan.admitted], ["backup"])

    def test_sanitize_display_text_and_picker_row_collision_projection(self):
        # Strips ANSI CSI, OSC, 2-byte ESC, 8-bit C1, and control/format/bidi/line-sep chars.
        dirty = "\x1b[31mChatGPT\x1b]0;evil\x07\x1bM \x9b2J\x9d0;title\x9c\u202eWork\u2028\t  Slot\x00"
        self.assertEqual(sanitize_display_text(dirty), "ChatGPT Work Slot")
        self.assertEqual(len(sanitize_display_text("a" * 100, max_len=16)), 16)
        with self.assertRaises(ValueError):
            sanitize_display_text("\x1b[31m\u200b\u202e   ")
        with self.assertRaises(ValueError):
            sanitize_display_text(123)  # type: ignore[arg-type]

        oa_p = InstancePreflight(_spec("openai", "personal"), ReadinessState.READY, ("shared-slug",), route_policy="sub")
        oa_w = InstancePreflight(_spec("openai", "work"), ReadinessState.READY, ("gpt-6.2-sol",), route_policy="sub")
        gg_p = InstancePreflight(_spec("google", "personal"), ReadinessState.READY, ("shared-slug",), route_policy="sub")
        rows = project_picker_rows((oa_p, oa_w, gg_p))
        self.assertEqual([r.display_label for r in rows], ["work", "google/personal", "openai/personal"])
        self.assertEqual([r.scoped_provider_id for r in rows], [
            "openai--work", "google--personal", "openai--personal",
        ])

    def test_exact_bool_qualification_and_unqualified_registry_adapter(self):
        oa_a = _spec("openai", "personal")
        cfg = ProviderConfig(instances=(oa_a,), provider_defaults={}, launch=LaunchDefaults())

        class _TruthyNonBoolAdapter(_FakeAdapter):
            def is_qualified(self, auth_mode: str, placement: str):
                return 1  # truthy non-bool MUST be rejected

        adapters = {
            "openai": _TruthyNonBoolAdapter(
                "openai",
                preflights={"personal": InstancePreflight(oa_a, ReadinessState.READY, ("gpt-6.2-sol",))},
            ),
        }
        with self.assertRaises(LaunchRefusedError) as ctx_def:
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="",
                cli_ui_mode="default", config=cfg, adapters=adapters, terminal=_FakeTerminal(),
            )
        self.assertEqual(ctx_def.exception.code, "no_admitted_providers")
        with self.assertRaises(LaunchRefusedError) as ctx_nar:
            plan_interactive_launch(
                instance_name="default", cwd="construct", provider_filter="openai/personal",
                cli_ui_mode="default", config=cfg, adapters=adapters, terminal=_FakeTerminal(),
            )
        self.assertEqual(ctx_nar.exception.code, "route_unqualified")

        unqual = UnqualifiedProviderAdapter("google")
        self.assertIs(unqual.is_qualified("subscription", "sandbox"), False)
        self.assertEqual(unqual.selection_state().state, SelectionState.UNSET)
        self.assertEqual(unqual.discover_instances(), ())
        gg_spec = _spec("google", "personal")
        self.assertEqual(unqual.preflight_instance(gg_spec).readiness, ReadinessState.UNQUALIFIED)
        with self.assertRaises(ProviderIntegrityError):
            unqual.provider_config_entry(
                InstancePreflight(gg_spec, ReadinessState.UNQUALIFIED), port=8401, worker_token="tok",
            )
        with self.assertRaises(ProviderIntegrityError):
            with unqual.open_slot(
                InstancePreflight(gg_spec, ReadinessState.UNQUALIFIED),
                slot_index=0, slot_root=Path("/tmp"), port=8401, worker_token="tok",
                acknowledged_exposure_digest=None, on_revoke=lambda _i: None,
            ):
                pass
        with self.assertRaises(ProviderIntegrityError):
            with unqual.open_discovery_slot(
                InstancePreflight(gg_spec, ReadinessState.UNQUALIFIED),
                slot_index=0, slot_root=Path("/tmp"), port=8401, worker_token="tok",
                acknowledged_exposure_digest=None, on_revoke=lambda _i: None,
            ):
                pass

        reg = default_session_adapters(backend_factory=lambda: object())
        self.assertEqual(set(reg), {"openai", "google", "claude"})
        self.assertIs(reg["google"].is_qualified("subscription", "sandbox"), False)
        self.assertIs(reg["claude"].is_qualified("subscription", "sandbox"), False)

    def test_validate_opencode_config_rejects_tampering_pre_and_post_hardening(self):
        import copy

        oa_p = _spec("openai", "personal")
        gg_p = _spec("google", "personal")
        cfg = ProviderConfig(instances=(oa_p, gg_p), provider_defaults={}, launch=LaunchDefaults())
        adapters = {
            "openai": _FakeAdapter(
                "openai",
                preflights={"personal": InstancePreflight(oa_p, ReadinessState.READY, ("gpt-6.2-sol",), route_policy="sub")},
            ),
            "google": _FakeAdapter(
                "google",
                preflights={"personal": InstancePreflight(gg_p, ReadinessState.READY, ("gemini-pro",), route_policy="sub")},
            ),
        }
        plan = plan_interactive_launch(
            instance_name="default", cwd="construct", provider_filter="",
            cli_ui_mode="mini", config=cfg, adapters=adapters, terminal=_FakeTerminal(confirms=[True]),
        )
        slot_ports = {"openai--personal": 8401, "google--personal": 8402}
        slot_tokens = {"openai--personal": "tok-oa", "google--personal": "tok-gg"}
        base_cfg = build_multi_provider_opencode_config(
            plan=plan, adapters=adapters, slot_ports=slot_ports, slot_tokens=slot_tokens,
        )
        self.assertEqual(base_cfg["providers"]["openai--personal"]["name"], "ChatGPT Subscription (openai/personal)")
        self.assertEqual(base_cfg["providers"]["google--personal"]["name"], "Google Subscription (google/personal)")

        # Pre-hardening mutations that MUST all fail closed:
        bad_cases: list[tuple[str, object]] = [
            ("wrong_schema", lambda d: d.__setitem__("$schema", "https://evil.example/config.json")),
            ("wrong_update", lambda d: d.__setitem__("update", "auto")),
            ("extra_top_key", lambda d: d.__setitem__("extra", True)),
            ("extra_provider", lambda d: d["providers"].__setitem__("rogue", copy.deepcopy(d["providers"]["openai--personal"]))),
            ("spoofed_display_substring", lambda d: d["providers"]["google--personal"].__setitem__("name", "ChatGPT Subscription (google/personal) Google Subscription")),
            ("unapproved_openai_pkg", lambda d: d["providers"]["openai--personal"].__setitem__("package", "@opencode/ai/providers/openai-compatible/chat")),
            ("non_canonical_url", lambda d: d["providers"]["openai--personal"]["settings"].__setitem__("baseURL", "http://127.0.0.1:8401/v1/")),
            ("wrong_token", lambda d: d["providers"]["openai--personal"]["settings"].__setitem__("apiKey", "wrong-tok")),
            ("caps_bool", lambda d: d["providers"]["openai--personal"]["models"]["gpt-6.2-sol"].__setitem__("capabilities", True)),
            ("extra_nested_key", lambda d: d["providers"]["openai--personal"]["models"]["gpt-6.2-sol"]["limit"].__setitem__("extra", 1)),
            ("bool_limit", lambda d: d["providers"]["openai--personal"]["models"]["gpt-6.2-sol"]["limit"].__setitem__("context", True)),
        ]
        for label, mutator in bad_cases:
            with self.subTest(case=label):
                mutated = copy.deepcopy(base_cfg)
                mutator(mutated)
                with self.assertRaises(ProviderIntegrityError):
                    validate_opencode_config(
                        mutated, plan=plan, slot_ports=slot_ports, slot_tokens=slot_tokens, proof_hardened=False,
                    )

        # Valid proof-hardened config passes, while lingering mcp, tools=True, or port/token drift fails closed.
        hardened = copy.deepcopy(base_cfg)
        hardened.pop("mcp")
        hardened["model"] = "google--personal/gemini-pro"
        hardened["snapshots"] = False
        hardened["permissions"] = [{"action": "*", "resource": "*", "effect": "deny"}]
        hardened["plugins"] = ["-opencode.tool.*"]
        for pdef in hardened["providers"].values():
            for mdef in pdef["models"].values():
                mdef["capabilities"]["tools"] = False
        validate_opencode_config(
            hardened, plan=plan, slot_ports=slot_ports, slot_tokens=slot_tokens,
            proof_hardened=True, expected_model="google--personal/gemini-pro",
        )

        for label, mutator in (
            ("lingering_mcp", lambda d: d.__setitem__("mcp", {})),
            ("tools_true_hardened", lambda d: d["providers"]["google--personal"]["models"]["gemini-pro"]["capabilities"].__setitem__("tools", True)),
            ("port_drift_hardened", lambda d: d["providers"]["google--personal"]["settings"].__setitem__("baseURL", "http://127.0.0.1:8409/v1")),
            ("token_drift_hardened", lambda d: d["providers"]["google--personal"]["settings"].__setitem__("apiKey", "drifted")),
            ("wrong_model_hardened", lambda d: d.__setitem__("model", "openai--personal/gpt-6.2-sol")),
        ):
            with self.subTest(hardened_case=label):
                mutated = copy.deepcopy(hardened)
                mutator(mutated)
                with self.assertRaises(ProviderIntegrityError):
                    validate_opencode_config(
                        mutated, plan=plan, slot_ports=slot_ports, slot_tokens=slot_tokens,
                        proof_hardened=True, expected_model="google--personal/gemini-pro",
                    )


if __name__ == "__main__":
    unittest.main()
