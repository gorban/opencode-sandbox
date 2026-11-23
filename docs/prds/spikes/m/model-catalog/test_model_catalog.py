from dataclasses import FrozenInstanceError, replace
import json
from types import SimpleNamespace
import unittest

from model_catalog import (
    AgentGrant,
    AgentProfile,
    Denied,
    InvalidInput,
    Lease,
    ModelCatalog,
    Reasoning,
    lower,
    project,
)


ROUTE = "fixture-responses"
MODEL = "fixture-model"
JOB = "fixture-job"
PRIMARY = "primary"
SUBAGENT = "subagent"
RAW_OPTION_KEYS = ("reasoning", "thinking", "output_config", "budget_tokens")
CATALOG = ModelCatalog(
    route=ROUTE,
    model=MODEL,
    context_limit=16_384,
    output_limit=2_048,
    variants=(
        ("low", Reasoning("low", "auto")),
        ("high", Reasoning("high", "auto")),
    ),
)
LEASE = Lease(
    active=True,
    job=JOB,
    route=ROUTE,
    model=MODEL,
    grants=(
        AgentGrant(PRIMARY, frozenset({"low"})),
        AgentGrant(SUBAGENT, frozenset({"high"})),
    ),
)
PROFILE = (AgentProfile(PRIMARY, MODEL, "low"), AgentProfile(SUBAGENT, MODEL, "high"))


def request(variant: str) -> dict:
    return {"model": MODEL, "x_oc_effort": variant}


class ModelCatalogTest(unittest.TestCase):
    def test_project_only_leased_model_and_explicit_agent_variants(self):
        config = project(CATALOG, LEASE, JOB, PROFILE).to_worker_config()
        self.assertEqual(config, {
            "env": {"OPENCODE_DISABLE_MODELS_DEV": "1"},
            "opencode": {
                "provider": {ROUTE: {"models": {MODEL: {
                    "limit": {"context": 16_384, "output": 2_048},
                    "variants": {
                        "low": {"x_oc_effort": "low"},
                        "high": {"x_oc_effort": "high"},
                    },
                }}}},
                "agent": {
                    PRIMARY: {"model": f"{ROUTE}/{MODEL}", "variant": "low"},
                    SUBAGENT: {"model": f"{ROUTE}/{MODEL}", "variant": "high"},
                },
            },
        })
        serialized = json.dumps(config)
        for key in RAW_OPTION_KEYS:
            with self.subTest(key=key):
                self.assertNotIn(f'"{key}":', serialized)

    def test_project_only_catalog_variants_granted_to_profiled_agents(self):
        projection = project(CATALOG, LEASE, JOB, PROFILE[:1])
        self.assertEqual(projection.variants, ("low",))

    def test_one_profiled_agent_exposes_all_granted_variants(self):
        grant = AgentGrant(PRIMARY, frozenset({"low", "high"}))
        lease = replace(LEASE, grants=(grant,))
        projection = project(CATALOG, lease, JOB, PROFILE[:1])
        self.assertEqual(projection.variants, ("high", "low"))
        config = projection.to_worker_config()["opencode"]
        self.assertEqual(config["agent"][PRIMARY]["variant"], "low")
        self.assertEqual(
            lower(CATALOG, lease, JOB, PRIMARY, ROUTE, request("high")).reasoning.effort,
            "high",
        )

    def test_lower_uses_the_exact_host_options(self):
        for agent, variant in ((PRIMARY, "low"), (SUBAGENT, "high")):
            with self.subTest(agent=agent):
                result = lower(CATALOG, LEASE, JOB, agent, ROUTE, request(variant))
                self.assertEqual(result.to_wire(), {
                    "model": MODEL,
                    "reasoning": {"effort": variant, "summary": "auto"},
                })

        catalog = replace(
            CATALOG,
            variants=(("low", Reasoning("synthetic-low", "auto")), CATALOG.variants[1]),
        )
        self.assertEqual(
            lower(catalog, LEASE, JOB, PRIMARY, ROUTE, request("low")).reasoning.effort,
            "synthetic-low",
        )

    def test_missing_inactive_and_wrong_job_lease_takes_precedence(self):
        for lease in (
            None,
            replace(LEASE, active=False),
            replace(LEASE, active="false"),
            replace(LEASE, job="other"),
        ):
            with self.subTest(lease=lease):
                with self.assertRaises(Denied):
                    project(CATALOG, lease, JOB, ())
                with self.assertRaises(Denied):
                    lower(CATALOG, lease, JOB, PRIMARY, ROUTE, {})

    def test_wrong_route_cannot_lower(self):
        with self.assertRaises(Denied):
            lower(CATALOG, LEASE, JOB, PRIMARY, "other", {})

    def test_missing_or_inconsistent_catalog_is_invalid(self):
        for catalog in (
            None,
            replace(CATALOG, route="other"),
            replace(CATALOG, model="other"),
        ):
            with self.subTest(catalog=catalog):
                with self.assertRaises(InvalidInput):
                    project(catalog, LEASE, JOB, PROFILE)
                with self.assertRaises(InvalidInput):
                    lower(catalog, LEASE, JOB, PRIMARY, ROUTE, request("low"))

    def test_invalid_limits_are_rejected_at_catalog_construction(self):
        for limits in (
            {"output_limit": True},
            {"context_limit": True, "output_limit": 1},
            {"output_limit": 1.0},
            {"output_limit": 0},
            {"context_limit": -1},
            {"output_limit": CATALOG.context_limit + 1},
        ):
            with self.subTest(limits=limits), self.assertRaises(InvalidInput):
                replace(CATALOG, **limits)

    def test_malformed_options_are_rejected(self):
        for options in ({}, [], {"effort": "low"}, {"effort": "low", "summary": []}):
            with self.subTest(options=options), self.assertRaises(InvalidInput):
                replace(CATALOG, variants=(("low", options),))
        with self.assertRaises(InvalidInput):
            Reasoning("low", "")
        for payload in (
            {},
            "effort",
            {"effort": "low", "summary": []},
            {"effort": "low", "summary": "auto", "budget_tokens": 1},
        ):
            with self.subTest(payload=payload), self.assertRaises(InvalidInput):
                Reasoning.from_options(payload)

    def test_ambiguous_or_mutable_variant_table_is_rejected(self):
        for variants in ((), CATALOG.variants * 2, list(CATALOG.variants)):
            with self.subTest(variants=variants), self.assertRaises(InvalidInput):
                replace(CATALOG, variants=variants)

    def test_unknown_agent_and_unleased_model_precede_missing_catalog(self):
        for agent, body in (
            ("other-agent", request("low")),
            (PRIMARY, {"model": "other-model", "x_oc_effort": "low"}),
        ):
            with self.subTest(agent=agent, body=body), self.assertRaises(Denied):
                lower(None, LEASE, JOB, agent, ROUTE, body)

    def test_project_checks_catalog_before_agent_and_lower_checks_agent_first(self):
        profile = (replace(PROFILE[0], agent="unknown"),)
        with self.assertRaises(InvalidInput):
            project(None, LEASE, JOB, profile)
        with self.assertRaises(Denied):
            lower(None, LEASE, JOB, "unknown", ROUTE, request("low"))

    def test_malformed_record_and_profile_container_are_invalid(self):
        lookalike = SimpleNamespace(agent=PRIMARY, model=MODEL, variant="low")
        for profile in (
            None,
            [PROFILE[0]],
            (None,),
            (replace(PROFILE[0], agent=[]),),
            (lookalike,),
        ):
            with self.subTest(profile=profile), self.assertRaises(InvalidInput):
                project(CATALOG, LEASE, JOB, profile)

        fake_lease = SimpleNamespace(**vars(LEASE))
        fake_catalog = SimpleNamespace(**vars(CATALOG))
        for catalog, lease in ((fake_catalog, LEASE), (CATALOG, fake_lease)):
            with self.subTest(catalog=catalog, lease=lease):
                with self.assertRaises(InvalidInput):
                    project(catalog, lease, JOB, PROFILE)
                with self.assertRaises(InvalidInput):
                    lower(catalog, lease, JOB, PRIMARY, ROUTE, request("low"))

    def test_malformed_grant_records_and_containers_are_invalid(self):
        for grants in (
            None,
            list(LEASE.grants),
            (None,),
            (replace(LEASE.grants[0], agent=[]),),
            (SimpleNamespace(agent=PRIMARY, variants=frozenset({"low"})),),
            (AgentGrant(PRIMARY, ["low"]),),
        ):
            lease = replace(LEASE, grants=grants)
            with self.subTest(grants=grants):
                with self.assertRaises(InvalidInput):
                    project(CATALOG, lease, JOB, PROFILE[:1])
                with self.assertRaises(InvalidInput):
                    lower(CATALOG, lease, JOB, PRIMARY, ROUTE, request("low"))

    def test_grant_members_require_exact_identifier_strings(self):
        class StringSubclass(str):
            pass

        for value in (False, "low ", "low\u202e", StringSubclass("low")):
            grant = AgentGrant(PRIMARY, frozenset({value}))
            lease = replace(LEASE, grants=(grant,))
            with self.subTest(value=value):
                with self.assertRaises(InvalidInput):
                    project(CATALOG, lease, JOB, PROFILE[:1])
                with self.assertRaises(InvalidInput):
                    lower(CATALOG, lease, JOB, PRIMARY, ROUTE, request("low"))

    def test_request_requires_a_plain_dict_with_plain_string_keys(self):
        class DictSubclass(dict):
            pass

        class StringSubclass(str):
            pass

        for body in (DictSubclass(request("low")), {StringSubclass("model"): MODEL, "x_oc_effort": "low"}):
            with self.subTest(body=body), self.assertRaises(InvalidInput):
                lower(CATALOG, LEASE, JOB, PRIMARY, ROUTE, body)

    def test_bad_identifiers_are_rejected(self):
        for value in ("", " padded", "padded ", "newline\n", "control\x7f", "dir/name", "bidi\u202e"):
            with self.subTest(identifier=value):
                with self.assertRaises(InvalidInput):
                    replace(CATALOG, route=value)
                with self.assertRaises(InvalidInput):
                    replace(CATALOG, model=value)
                with self.assertRaises(InvalidInput):
                    replace(CATALOG, variants=((value, CATALOG.variants[0][1]),))
                with self.assertRaises(InvalidInput):
                    project(CATALOG, replace(LEASE, job=value), value, PROFILE)
                with self.assertRaises(InvalidInput):
                    project(CATALOG, LEASE, JOB, (replace(PROFILE[0], agent=value),))
                with self.assertRaises(InvalidInput):
                    lower(CATALOG, LEASE, JOB, value, ROUTE, request("low"))
                with self.assertRaises(InvalidInput):
                    lower(
                        CATALOG, LEASE, JOB, PRIMARY, ROUTE, {"model": value, "x_oc_effort": "low"}
                    )

    def test_all_grants_must_be_nonempty_and_supported(self):
        for agent in (PRIMARY, SUBAGENT):
            for variants in (frozenset(), frozenset({"low", "bogus"})):
                grants = tuple(
                    replace(grant, variants=variants) if grant.agent == agent else grant
                    for grant in LEASE.grants
                )
                lease = replace(LEASE, grants=grants)
                with self.subTest(agent=agent, variants=variants):
                    with self.assertRaises(InvalidInput):
                        project(CATALOG, lease, JOB, PROFILE[:1])
                    with self.assertRaises(InvalidInput):
                        lower(CATALOG, lease, JOB, PRIMARY, ROUTE, request("low"))

    def test_unleased_model_and_unknown_agent_are_denied(self):
        with self.assertRaises(Denied):
            lower(CATALOG, LEASE, JOB, PRIMARY, ROUTE, {"model": "other", "x_oc_effort": "low"})
        with self.assertRaises(Denied):
            project(CATALOG, LEASE, JOB, (replace(PROFILE[0], model="other"),))
        with self.assertRaises(Denied):
            lower(CATALOG, LEASE, JOB, "unknown", ROUTE, request("low"))
        with self.assertRaises(Denied):
            project(CATALOG, LEASE, JOB, (replace(PROFILE[0], agent="unknown"),))

    def test_model_variant_union_confers_no_agent_grant(self):
        self.assertEqual(project(CATALOG, LEASE, JOB, PROFILE).variants, ("high", "low"))
        with self.assertRaises(Denied):
            lower(CATALOG, LEASE, JOB, PRIMARY, ROUTE, request("high"))
        with self.assertRaises(Denied):
            project(CATALOG, LEASE, JOB, (replace(PROFILE[0], variant="high"),))

    def test_request_requires_exact_model_and_effort_strings(self):
        for body in (
            None,
            ["low"],
            {"model": MODEL},
            {"x_oc_effort": "low"},
            {"model": 1, "x_oc_effort": "low"},
            {"model": "", "x_oc_effort": "low"},
            {"model": MODEL, "x_oc_effort": ["low"]},
            request(""),
            request("LOW"),
            request("unknown"),
        ):
            with self.subTest(body=body), self.assertRaises(InvalidInput):
                lower(CATALOG, LEASE, JOB, PRIMARY, ROUTE, body)

    def test_project_rejects_missing_unsupported_and_ambiguous_profile_entries(self):
        for profile in (
            (),
            (PROFILE[0], PROFILE[0]),
            (PROFILE[0], AgentProfile(SUBAGENT, MODEL)),
            (PROFILE[0], replace(PROFILE[1], variant="unknown")),
        ):
            with self.subTest(profile=profile), self.assertRaises(InvalidInput):
                project(CATALOG, LEASE, JOB, profile)

    def test_duplicate_host_grants_are_invalid(self):
        lease = replace(LEASE, grants=LEASE.grants + (AgentGrant(PRIMARY, frozenset({"high"})),))
        with self.assertRaises(InvalidInput):
            project(CATALOG, lease, JOB, PROFILE)
        with self.assertRaises(InvalidInput):
            lower(CATALOG, lease, JOB, PRIMARY, ROUTE, request("high"))

    def test_extra_request_fields_are_rejected_with_or_without_a_symbol(self):
        fields = {
            "reasoning": {"effort": "high"},
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": "high"},
            "budget_tokens": 2_048,
            "agent": SUBAGENT,
            "job": JOB,
            "route": ROUTE,
            "lease": "fixture-lease",
        }
        for key, value in fields.items():
            for body in ({"model": MODEL}, request("low")):
                body[key] = value
                with self.subTest(body=body), self.assertRaises(InvalidInput):
                    lower(CATALOG, LEASE, JOB, PRIMARY, ROUTE, body)

    def test_corrected_host_snapshot_and_authorized_retry_succeed(self):
        mismatched = replace(LEASE, model="other")
        with self.assertRaises(InvalidInput):
            project(CATALOG, mismatched, JOB, PROFILE)
        projection = project(CATALOG, LEASE, JOB, PROFILE)
        inactive = replace(LEASE, active=False)
        effort = projection.agents[0].variant
        with self.assertRaises(Denied):
            lower(CATALOG, inactive, JOB, PRIMARY, ROUTE, request(effort))
        self.assertEqual(
            lower(CATALOG, LEASE, JOB, PRIMARY, ROUTE, request(effort)).reasoning.effort,
            "low",
        )

    def test_catalog_copies_accepted_host_options_into_a_frozen_record(self):
        source = {"effort": "low", "summary": "auto"}
        options = Reasoning.from_options(source)
        catalog = replace(CATALOG, variants=(("low", options), CATALOG.variants[1]))
        source["effort"] = "high"
        with self.assertRaises(FrozenInstanceError):
            catalog.variants = ()
        with self.assertRaises(FrozenInstanceError):
            options.effort = "high"
        result = lower(catalog, LEASE, JOB, PRIMARY, ROUTE, request("low"))
        self.assertEqual(result.to_wire()["reasoning"], {"effort": "low", "summary": "auto"})

    def test_serialization_never_shares_mutable_policy_state(self):
        projection = project(CATALOG, LEASE, JOB, PROFILE)
        lowered = lower(CATALOG, LEASE, JOB, PRIMARY, ROUTE, request("low"))
        with self.assertRaises(FrozenInstanceError):
            projection.agents[0].variant = "high"
        with self.assertRaises(FrozenInstanceError):
            lowered.reasoning.effort = "high"

        config = projection.to_worker_config()
        config["opencode"]["agent"][PRIMARY]["variant"] = "high"
        wire = lowered.to_wire()
        wire["reasoning"]["effort"] = "high"
        self.assertEqual(projection.to_worker_config()["opencode"]["agent"][PRIMARY]["variant"], "low")
        self.assertEqual(lowered.to_wire()["reasoning"]["effort"], "low")
