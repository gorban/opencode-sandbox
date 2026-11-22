"""Comprehensive offline adversarial & unit test suite for PRD L spike PoC.

Uses only isolated TemporaryDirectory --config-dir paths; never touches ~/.config/oc-sandbox/.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_SPIKE_DIR = Path(__file__).resolve().parent
if str(_SPIKE_DIR) not in sys.path:
    sys.path.insert(0, str(_SPIKE_DIR))

from oc_config_mcp import (  # noqa: E402
    OperatorControlServer,
    OrchestratorConfigMcpServer,
    call_mcp_uds,
    call_operator_uds,
    encode_content_length_frame,
)
from oc_plan import (  # noqa: E402
    PlanError,
    PlanOverrides,
    classify_drift,
    compile_plan,
    compute_closed_security_delta,
)
import oc_sandbox_cli  # noqa: E402
from oc_schema import (  # noqa: E402
    PolicyError,
    SchemaError,
    assert_trusted_dir,
    check_not_in_sandbox,
    validate_host_url_template,
    validate_opaque_id,
)
from oc_store import (  # noqa: E402
    POC_STORE_MARKER,
    ConflictError,
    DigestMismatchError,
    ExpiredProposalError,
    HostConfigStore,
    PublishUncertainError,
    StaleProposalError,
)


def _ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def _sample_bundle_toml(bid: str, extra: str = "") -> str:
    return (
        f'schema_version = 1\n'
        f'kind = "bundle@1"\n'
        f'id = "{bid}"\n'
        f'description = "Sample bundle {bid}"\n'
        f'{extra}\n'
    )


def _sample_service_toml(
    sid: str,
    *,
    provides: str = "[]",
    requires: str = "[]",
    port: int = 8081,
    security_profile: str = "standard",
    fallback: str | None = None,
    req_caps: str = '["supports_pods"]',
    cardinality: str = "singleton",
    instance_port: int | None = None,
    requires_auth: bool = False,
    auth_enforcer: str | None = None,
    max_exposure: str = "host-loopback",
    extra: str = "",
) -> str:
    fb_line = f'fallback_service = "{fallback}"\n' if fallback else ""
    ip_line = f"instance_port = {instance_port}\n" if instance_port is not None else ""
    ae_line = f'auth_enforcer = "{auth_enforcer}"\n' if auth_enforcer else ""
    return (
        f'schema_version = 1\n'
        f'kind = "service@1"\n'
        f'id = "{sid}"\n'
        f'image = "ghcr.io/example/svc@sha256:{"a" * 64}"\n'
        f'provides = {provides}\n'
        f'requires = {requires}\n'
        f'cardinality = "{cardinality}"\n'
        f'{ip_line}'
        f'security_profile = "{security_profile}"\n'
        f'{fb_line}'
        f'required_capabilities = {req_caps}\n'
        f'[resources]\n'
        f'memory = "256m"\n'
        f'pids_limit = 64\n'
        f'[[endpoints]]\n'
        f'name = "main"\n'
        f'port = {port}\n'
        f'protocol = "http"\n'
        f'default_exposure = "pod-only"\n'
        f'max_exposure = "{max_exposure}"\n'
        f'requires_auth = {"true" if requires_auth else "false"}\n'
        f'{ae_line}'
        f'{extra}\n'
    )


class TestPlanCompiler(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="oc-prdl-test-")
        self.cfg_dir = Path(self.tmp.name) / "cfg"
        self.store = HostConfigStore(self.cfg_dir)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_zero_mcp_postgres_fullstack_and_slot_expansion(self) -> None:
        res = compile_plan(self.store, "builtin/fullstack-pg")
        svc_ids = [s["id"] for s in res.plan["services"]]
        self.assertIn("builtin/postgres", svc_ids)
        self.assertIn("builtin/chromium-wayland", svc_ids)
        self.assertEqual(res.plan["role_contract"]["opencode_config"]["mcp"], {})
        self.assertIn("Never hardcode secrets", res.plan["role_contract"]["primary_persona"]["mission"])
        self.assertIn("builtin/postgres", res.plan["role_contract"]["services_md"])
        pg_ep = [e for e in res.plan["endpoints"] if e["service"] == "builtin/postgres"][0]
        self.assertEqual(pg_ep["exposure"], "host-loopback")
        self.assertEqual(pg_ep["auth_enforcer"], "pg-scram-ro-hba")
        self.assertEqual(res.plan["toolchain_delivery"], "image-mount")

    def test_cross_arch_arm64_and_non_escalating_fallback(self) -> None:
        res = compile_plan(self.store, "builtin/fullstack-pg", worker_id="builtin/example-macos-arm64")
        self.assertEqual(res.plan["worker"]["arch"], "arm64")
        self.assertTrue(res.plan["base_image"].endswith("c" * 64))
        svc_ids = [s["id"] for s in res.plan["services"]]
        # Wayland unsupported on macOS VM -> auto-falls back to standard chromium-managed
        self.assertIn("builtin/chromium-managed", svc_ids)
        self.assertNotIn("builtin/chromium-wayland", svc_ids)

    def test_cloud_provider_rejects_sidecars(self) -> None:
        with self.assertRaises(PlanError):
            compile_plan(self.store, "builtin/fullstack-pg", worker_id="builtin/example-render-cloud")

    def test_local_conditional_pruning_and_active_root_reachability(self) -> None:
        # Blank API_ENDPOINT -> pulls builtin/api-demo AND transitive builtin/postgres (in topological order!)
        local_res = compile_plan(self.store, "builtin/api-workbench")
        svc_ids = [s["id"] for s in local_res.plan["services"]]
        self.assertEqual(svc_ids, ["builtin/postgres", "builtin/api-demo"])

        # Remote API_ENDPOINT -> prunes BOTH api-demo and transitive postgres; rewrites container URL to host broker
        remote_res = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"}),
        )
        self.assertEqual(remote_res.plan["services"], [])
        self.assertEqual(
            remote_res.plan["role_contract"]["opencode_config"]["mcp"]["api_client"]["url"],
            "http://127.0.0.1:18080/mcp/api_client",
        )
        self.assertEqual(
            remote_res.plan["broker_routes"]["mcp:api_client"]["upstream"],
            "https://staging.example.com/mcp",
        )

        # Active-root reachability: with builtin/postgres-app also active, postgres survives pruning
        mixed_res = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(
                with_mods=("builtin/postgres-app",),
                env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
            ),
        )
        self.assertEqual([s["id"] for s in mixed_res.plan["services"]], ["builtin/postgres"])

    def test_remote_endpoint_ssrf_denied(self) -> None:
        for bad in (
            "http://staging.example.com/mcp",
            "https://127.0.0.1:8080/mcp",
            f"https://{_ip(169, 254, 169, 254)}/latest/meta-data",
            "https://host.containers.internal/mcp",
            "https://user:pass@staging.example.com/mcp",
            f"https://{_ip(10, 0, 0, 5)}/mcp",
        ):
            ov = PlanOverrides(env_bindings={"API_ENDPOINT": bad})
            with self.subTest(url=bad), self.assertRaises(PolicyError):
                compile_plan(self.store, "builtin/api-workbench", overrides=ov)

    def test_persona_conflict_and_role_filtered_mcp(self) -> None:
        # Security-audit uses [composition] replace=["persona"] and restricts api_client to query_ro
        res = compile_plan(self.store, "builtin/security-audit")
        self.assertEqual(res.plan["role_contract"]["default_agent"], "security-reviewer")
        self.assertEqual(
            res.plan["role_contract"]["opencode_config"]["mcp"]["api_client"]["allowed_tools"],
            ["query_ro"],
        )

        # Second persona without replace=["persona"] fails closed
        self.store.operator_direct_upsert(
            "bundle",
            "team/persona-two",
            _sample_bundle_toml(
                "team/persona-two",
                '[persona]\nname = "other"\nauthority = "triage"\nmission = "Triage issues."\n',
            ),
        )
        with self.assertRaises(PlanError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(with_mods=("team/persona-two",)),
            )

    def test_endpoint_policy_blocks_9222_and_unauthenticated_exposure(self) -> None:
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/fullstack-pg",
                overrides=PlanOverrides(
                    cli_ports=({"service": "builtin/chromium-wayland", "endpoint": "devtools", "exposure": "host-loopback"},)
                ),
            )
        # Service requiring auth with no auth_enforcer cannot be exposed
        self.store.operator_direct_upsert(
            "service",
            "team/no-enforcer",
            _sample_service_toml("team/no-enforcer", port=9001, requires_auth=True, auth_enforcer=None),
        )
        self.store.operator_direct_upsert(
            "bundle",
            "team/no-enforcer-b",
            _sample_bundle_toml("team/no-enforcer-b", 'requires_services = ["team/no-enforcer"]'),
        )
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(
                    with_mods=("team/no-enforcer-b",),
                    cli_ports=({"service": "team/no-enforcer", "endpoint": "main", "exposure": "host-loopback"},),
                ),
            )

    def test_bundle_and_service_cycles_rejected(self) -> None:
        self.store.operator_direct_upsert("bundle", "team/cyc-a", _sample_bundle_toml("team/cyc-a", 'includes = ["team/cyc-b"]'))
        self.store.operator_direct_upsert("bundle", "team/cyc-b", _sample_bundle_toml("team/cyc-b", 'includes = ["team/cyc-a"]'))
        with self.assertRaises(PlanError):
            compile_plan(self.store, "builtin/api-workbench", overrides=PlanOverrides(with_mods=("team/cyc-a",)))

        self.store.operator_direct_upsert("service", "team/sc-a", _sample_service_toml("team/sc-a", port=9101, requires='["team/sc-b"]'))
        self.store.operator_direct_upsert("service", "team/sc-b", _sample_service_toml("team/sc-b", port=9102, requires='["team/sc-a"]'))
        self.store.operator_direct_upsert("bundle", "team/sc-bun", _sample_bundle_toml("team/sc-bun", 'requires_services = ["team/sc-a"]'))
        with self.assertRaises(PlanError):
            compile_plan(self.store, "builtin/api-workbench", overrides=PlanOverrides(with_mods=("team/sc-bun",)))

    def test_ambiguous_capability_and_builtin_downgrade_rejected(self) -> None:
        # Downgrading builtin/postgres auth via competing capability provider is blocked
        self.store.operator_direct_upsert(
            "service",
            "team/weak-pg",
            _sample_service_toml(
                "team/weak-pg",
                provides='["cap:db.postgres@17.5"]',
                port=5432,
                requires_auth=False,
                max_exposure="instance-dns",
            ),
        )
        self.store.operator_direct_upsert(
            "bundle",
            "team/use-weak-pg",
            _sample_bundle_toml(
                "team/use-weak-pg",
                'requires_services = [{capability = "cap:db.postgres@^17.0", provider = "team/weak-pg"}]',
            ),
        )
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(
                    with_mods=("team/use-weak-pg",),
                    env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
                ),
            )

        # Ambiguous providers (two providers for cap:db.postgres without explicit pin) fail closed
        with self.assertRaises(PlanError):
            compile_plan(self.store, "builtin/api-workbench")

    def test_fallback_partial_order_rejects_incomparable_and_widened_exposure(self) -> None:
        # elevated-nested cannot fall back to desktop-wayland (incomparable in partial order)
        self.store.operator_direct_upsert(
            "service",
            "team/fb-wayland",
            _sample_service_toml("team/fb-wayland", port=9201, security_profile="desktop-wayland", req_caps='["supports_pods"]'),
        )
        self.store.operator_direct_upsert(
            "service",
            "team/prim-dind",
            _sample_service_toml(
                "team/prim-dind",
                port=9201,
                security_profile="elevated-nested",
                fallback="team/fb-wayland",
                req_caps='["supports_pods", "supports_dind"]',
            ),
        )
        self.store.operator_direct_upsert("bundle", "team/b-fb", _sample_bundle_toml("team/b-fb", 'requires_services = ["team/prim-dind"]'))
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                worker_id="builtin/example-macos-arm64",
                overrides=PlanOverrides(with_mods=("team/b-fb",)),
            )

        # Fallback widening max_exposure on a port is rejected
        self.store.operator_direct_upsert(
            "service",
            "team/fb-wide",
            _sample_service_toml("team/fb-wide", port=9202, max_exposure="instance-dns", req_caps='["supports_pods"]'),
        )
        self.store.operator_direct_upsert(
            "service",
            "team/prim-narrow",
            _sample_service_toml(
                "team/prim-narrow",
                port=9202,
                max_exposure="pod-only",
                fallback="team/fb-wide",
                req_caps='["supports_pods", "supports_dind"]',
            ),
        )
        self.store.operator_direct_upsert("bundle", "team/b-wide", _sample_bundle_toml("team/b-wide", 'requires_services = ["team/prim-narrow"]'))
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                worker_id="builtin/example-macos-arm64",
                overrides=PlanOverrides(with_mods=("team/b-wide",)),
            )

    def test_named_instances_and_port_collision(self) -> None:
        self.store.operator_direct_upsert(
            "service",
            "team/cache-a",
            _sample_service_toml("team/cache-a", port=6379, cardinality="named-instance", instance_port=6380),
        )
        self.store.operator_direct_upsert(
            "service",
            "team/cache-b",
            _sample_service_toml("team/cache-b", port=6379, cardinality="named-instance", instance_port=6381),
        )
        self.store.operator_direct_upsert(
            "bundle",
            "team/two-caches",
            _sample_bundle_toml(
                "team/two-caches",
                'requires_services = [{service = "team/cache-a", instance = "c1"}, {service = "team/cache-b", instance = "c2"}]',
            ),
        )
        res = compile_plan(self.store, "builtin/api-workbench", overrides=PlanOverrides(with_mods=("team/two-caches",)))
        ports = {e["port"] for e in res.plan["endpoints"] if e["service"].startswith("team/cache-")}
        self.assertEqual(ports, {6380, 6381})

        # Collision on 6380 fails closed
        self.store.operator_direct_upsert(
            "service",
            "team/cache-c",
            _sample_service_toml("team/cache-c", port=6380),
        )
        self.store.operator_direct_upsert(
            "bundle",
            "team/collide",
            _sample_bundle_toml("team/collide", 'requires_services = ["team/cache-c"]'),
        )
        with self.assertRaises(PlanError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(with_mods=("team/two-caches", "team/collide")),
            )

    def test_mise_conflict_and_single_pass_slot_and_symlink_rejection(self) -> None:
        # Conflicting mise pins fail closed
        self.store.operator_direct_upsert(
            "bundle",
            "team/py-old",
            _sample_bundle_toml("team/py-old", '[mise_tools]\n"core:python" = "3.12.9"\n'),
        )
        with self.assertRaises(PlanError):
            compile_plan(self.store, "builtin/fullstack-pg", overrides=PlanOverrides(with_mods=("team/py-old",)))

        # Single-pass {{slot}} expansion does NOT recursively expand tokens inside slot content
        asset_dir = self.cfg_dir / "assets" / "team@slot-test"
        asset_dir.mkdir(parents=True, exist_ok=True)
        (asset_dir / "s1.md").write_text("literal {{s2}} here", encoding="utf-8")
        (asset_dir / "s2.md").write_text("SHOULD_NOT_EXPAND", encoding="utf-8")
        self.store.operator_direct_upsert(
            "bundle",
            "team/slot-test",
            _sample_bundle_toml(
                "team/slot-test",
                'instructions = ["Start {{s1}}"]\n[prompt_slots]\ns1 = "s1.md"\ns2 = "s2.md"\n',
            ),
        )
        res = compile_plan(self.store, "builtin/api-workbench", overrides=PlanOverrides(with_mods=("team/slot-test",)))
        texts = [i["content"] for i in res.plan["role_contract"]["instructions"]]
        self.assertIn("Start literal {{s2}} here", texts)

        # Symlink slot file rejected via O_NOFOLLOW inside the bundle's own asset root
        sym_asset_dir = self.cfg_dir / "assets" / "team@slot-symlink"
        sym_asset_dir.mkdir(parents=True, exist_ok=True)
        secret_file = Path(self.tmp.name) / "outside.md"
        secret_file.write_text("SECRET_CONTENT", encoding="utf-8")
        link_path = sym_asset_dir / "evil.md"
        os.symlink(secret_file, link_path)
        self.store.operator_direct_upsert(
            "bundle",
            "team/slot-symlink",
            _sample_bundle_toml(
                "team/slot-symlink",
                'instructions = ["{{evil}}"]\n[prompt_slots]\nevil = "evil.md"\n',
            ),
        )
        with self.assertRaisesRegex(PolicyError, "Symlink"):
            compile_plan(self.store, "builtin/api-workbench", overrides=PlanOverrides(with_mods=("team/slot-symlink",)))

    def test_plan_digest_invariant_across_drift_and_classifications(self) -> None:
        r_fresh = compile_plan(self.store, "builtin/fullstack-pg")
        self.assertEqual(r_fresh.drift["kind"], "fresh")

        r_none = compile_plan(self.store, "builtin/fullstack-pg", applied_plan=r_fresh.plan)
        self.assertEqual(r_none.drift["kind"], "none")
        # Crucial P1-4 invariant: plan_digest MUST NOT change with applied_plan/drift!
        self.assertEqual(r_fresh.plan_digest, r_none.plan_digest)

        # Role-only change -> hot-safe
        modified_role = json.loads(json.dumps(r_fresh.plan))
        modified_role["role_contract"]["skills"] = ["extra/skill"]
        r_hot = compile_plan(self.store, "builtin/fullstack-pg", applied_plan=modified_role)
        self.assertEqual(r_hot.drift["kind"], "hot-safe")
        self.assertEqual(r_hot.plan_digest, r_fresh.plan_digest)

        # Durable Postgres image change -> stateful-migration-required
        modified_pg = json.loads(json.dumps(r_fresh.plan))
        for svc in modified_pg["services"]:
            if svc["id"] == "builtin/postgres":
                svc["image"] = f"docker.io/library/postgres@sha256:{'f' * 64}"
        r_mig = compile_plan(self.store, "builtin/fullstack-pg", applied_plan=modified_pg)
        self.assertEqual(r_mig.drift["kind"], "stateful-migration-required")

    def test_schema_and_policy_rejections(self) -> None:
        # Invalid opaque IDs
        for bad_id in ("../etc", "a//b", "a/b/c", "/leading", "trailing/", "UPPER", "has space"):
            with self.subTest(bad_id=bad_id), self.assertRaises(SchemaError):
                validate_opaque_id(bad_id)

        # Host URL template rejects password placeholder and bad schemes
        with self.assertRaises(SchemaError):
            validate_host_url_template("postgresql://{user}:{password}@{host}:{port}/{db}", "tpl")
        with self.assertRaises(SchemaError):
            validate_host_url_template("file://{path}", "tpl")

        # Forbidden env keys, raw secrets, host bind mounts, unpinned image, latest mise
        bad_services = [
            (
                "team/bad-env",
                _sample_service_toml("team/bad-env", extra='[env]\nLD_PRELOAD = "/evil.so"'),
                PolicyError,
                "Forbidden env key",
            ),
            (
                "team/bad-key",
                _sample_service_toml("team/bad-key", extra='[env]\nOPENAI_API_KEY = "foo"'),
                PolicyError,
                "Forbidden env key",
            ),
            (
                "team/bad-sec",
                _sample_service_toml("team/bad-sec", extra='[env]\nSAFE_VAR = "sk-1234567890"'),
                SchemaError,
                "Raw secret prefix",
            ),
            (
                "team/bad-bind",
                _sample_service_toml("team/bad-bind", extra='[[volumes]]\nname = "v"\nkind = "bind"\ntarget = "/host"'),
                PolicyError,
                "Unsupported or forbidden volume kind",
            ),
            (
                "team/bad-mise",
                _sample_service_toml("team/bad-mise", extra='[mise_tools]\n"core:node" = "latest"'),
                SchemaError,
                "exact three-part pinned version",
            ),
        ]
        for obj_id, raw, exc_cls, msg_re in bad_services:
            with self.subTest(obj_id=obj_id), self.assertRaisesRegex(exc_cls, msg_re):
                self.store.create_proposal(kind="service", obj_id=obj_id, action="upsert", proposed_toml=raw)

    def test_p1_2_builtin_downgrade_alternate_port_and_same_service_named_instances(self) -> None:
        # Alternate-port competing capability providers cannot weaken auth, exposure, or security_profile
        for sid, cap_req, kwargs, label in (
            (
                "team/alt-pg-noauth",
                "cap:db.postgres@^17.0",
                {"provides": '["cap:db.postgres@17.5"]', "port": 5433, "requires_auth": False, "max_exposure": "host-loopback"},
                "no-auth",
            ),
            (
                "team/alt-chr-wide",
                "cap:browser.chromium@^1.0",
                {
                    "provides": '["cap:browser.chromium@1.1"]',
                    "port": 9223,
                    "requires_auth": False,
                    "max_exposure": "host-loopback",
                },
                "widened-exposure",
            ),
            (
                "team/alt-pg-elev",
                "cap:db.postgres@^17.0",
                {
                    "provides": '["cap:db.postgres@17.5"]',
                    "port": 5433,
                    "requires_auth": True,
                    "auth_enforcer": "pg-scram-ro-hba",
                    "max_exposure": "host-loopback",
                    "security_profile": "elevated-nested",
                },
                "elevated-profile",
            ),
        ):
            with self.subTest(case=label):
                self.store.operator_direct_upsert("service", sid, _sample_service_toml(sid, **kwargs))
                bid = f"team/use-{label}"
                self.store.operator_direct_upsert(
                    "bundle",
                    bid,
                    _sample_bundle_toml(
                        bid,
                        f'requires_services = [{{capability = "{cap_req}", provider = "{sid}"}}]',
                    ),
                )
                with self.assertRaises(PolicyError):
                    compile_plan(
                        self.store,
                        "builtin/api-workbench",
                        overrides=PlanOverrides(
                            with_mods=(bid,),
                            env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
                        ),
                    )

        # Two named instances of the SAME service@1 coexist cleanly with distinct per-instance instance_port
        self.store.operator_direct_upsert(
            "service",
            "team/shared-cache",
            _sample_service_toml("team/shared-cache", port=6379, cardinality="named-instance"),
        )
        self.store.operator_direct_upsert(
            "bundle",
            "team/two-same-caches",
            _sample_bundle_toml(
                "team/two-same-caches",
                (
                    "requires_services = [\n"
                    '  {service = "team/shared-cache", instance = "cache_a", instance_port = 6380},\n'
                    '  {service = "team/shared-cache", instance = "cache_b", instance_port = 6381},\n'
                    "]\n"
                ),
            ),
        )
        res = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(
                with_mods=("team/two-same-caches",),
                env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
                cli_ports=({"service": "team/shared-cache@cache_a", "endpoint": "main", "exposure": "host-loopback"},),
            ),
        )
        cache_eps = [e for e in res.plan["endpoints"] if e["service"] == "team/shared-cache"]
        self.assertEqual(
            {e["service_key"] for e in cache_eps},
            {"team/shared-cache@cache_a", "team/shared-cache@cache_b"},
        )
        self.assertEqual({e["port"] for e in cache_eps}, {6380, 6381})
        exp_by_inst = {e["service_key"]: e["exposure"] for e in cache_eps}
        self.assertEqual(
            exp_by_inst,
            {"team/shared-cache@cache_a": "host-loopback", "team/shared-cache@cache_b": "pod-only"},
        )

        # Un-aliased cli_port targeting ambiguous multi-instance service fails closed
        with self.assertRaises(PlanError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(
                    with_mods=("team/two-same-caches",),
                    env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
                    cli_ports=({"service": "team/shared-cache", "endpoint": "main", "exposure": "host-loopback"},),
                ),
            )

    def test_p1_3_sandbox_symlink_hop_mcp_local_ssrf_and_numeric_cgnat_ip(self) -> None:
        # Symlink inside sandbox_root pointing outside must be rejected
        sb_dir = Path(self.tmp.name) / "fake_sb"
        sb_dir.mkdir(mode=0o700)
        outside_dir = Path(self.tmp.name) / "outside_trusted"
        outside_dir.mkdir(mode=0o700)
        hop_inside_sb = sb_dir / "escape_link"
        os.symlink(outside_dir, hop_inside_sb)
        with self.assertRaises(PolicyError):
            assert_trusted_dir(hop_inside_sb, sandbox_root=sb_dir)
        with self.assertRaises(PolicyError):
            HostConfigStore(hop_inside_sb, sandbox_root=sb_dir)

        # Multi-hop symlink outside sandbox_root transiting through sandbox_root back outside must be rejected
        outer_link = Path(self.tmp.name) / "outer_hop"
        os.symlink(hop_inside_sb, outer_link)
        with self.assertRaises(PolicyError):
            assert_trusted_dir(outer_link, sandbox_root=sb_dir)

        # Direct symlink as config_dir itself must be rejected
        direct_link = Path(self.tmp.name) / "cfg_link"
        os.symlink(outside_dir, direct_link)
        with self.assertRaises(PolicyError):
            HostConfigStore(direct_link, sandbox_root=sb_dir)

        # MCP http URL & local.url SSRF / userinfo / port 9222 bypasses rejected
        meta_ip = _ip(169, 254, 169, 254)
        bad_mcp_cases = [
            'url = "http://127.0.0.1:@evil.com/mcp"',
            'url = "http://127.0.0.1:9222/json"',
            f'url = "https://{meta_ip}/latest/meta-data"',
            'url = "http://127.0.0.1:8080/mcp"\n[mcp.bad.local]\nwhen_env_empty = "API_ENDPOINT"\nservice = "builtin/api-demo"\nurl = "file:///etc/passwd"',
            'url = "http://127.0.0.1:8080/mcp"\n[mcp.bad.local]\nwhen_env_empty = "API_ENDPOINT"\nservice = "builtin/api-demo"\nurl = "http://127.0.0.1:9222/mcp"',
        ]
        for idx, snippet in enumerate(bad_mcp_cases):
            bid = f"team/bad-mcp-{idx}"
            raw = _sample_bundle_toml(bid, f'[mcp.bad]\ntransport = "http"\n{snippet}\n')
            with self.subTest(case=idx), self.assertRaises((SchemaError, PolicyError)):
                self.store.create_proposal(kind="bundle", obj_id=bid, action="upsert", proposed_toml=raw)

        # CGNAT (100.64.0.0/10) and non-canonical numeric/octal/hex IPv4 remote endpoints rejected
        for bad_url in (
            f"https://{_ip(100, 64, 0, 1)}/mcp",
            "https://0177.0.0.1/mcp",
            "https://2130706433/mcp",
            "https://0x7f000001/mcp",
            "https://127.1/mcp",
        ):
            ov = PlanOverrides(env_bindings={"API_ENDPOINT": bad_url})
            with self.subTest(url=bad_url), self.assertRaises(PolicyError):
                compile_plan(self.store, "builtin/api-workbench", overrides=ov)

        # persistent_flock rejects tampered mode on store.lock
        os.chmod(self.cfg_dir / "store.lock", 0o640)
        try:
            with self.assertRaises(PolicyError), self.store.persistent_flock():
                self.fail("Expected PolicyError for group-readable store.lock")
        finally:
            os.chmod(self.cfg_dir / "store.lock", 0o600)

    def test_p2_6_readiness_cmd_secret_ref_security_delta_drift_and_dag_cap(self) -> None:
        # Orchestrator proposal with custom readiness_probe.command is rejected
        bad_probe = _sample_service_toml(
            "team/bad-probe",
            extra='[readiness_probe]\nkind = "exec_auth"\nport = 8081\ncommand = ["sh", "-c", "id"]\n',
        )
        with self.assertRaises(PolicyError):
            self.store.create_proposal(
                kind="service", obj_id="team/bad-probe", action="upsert", proposed_toml=bad_probe
            )

        # Plaintext secret_slots[].secret_ref rejected (requires provider:key grammar)
        bad_secret_ref = _sample_service_toml(
            "team/bad-sref",
            extra='[[secret_slots]]\nslot = "db_pw"\ntarget = "/run/secrets/db_pw"\nsecret_ref = "my-plaintext-password"\n',
        )
        with self.assertRaises(SchemaError):
            self.store.create_proposal(
                kind="service", obj_id="team/bad-sref", action="upsert", proposed_toml=bad_secret_ref
            )

        # security_delta detects base_image change, existing MCP mutation, and tier/topology weakening
        base_res = compile_plan(self.store, "builtin/api-workbench")
        mut_plan = json.loads(json.dumps(base_res.plan))
        mut_plan["base_image"] = f"ghcr.io/example/other@sha256:{'e' * 64}"
        mut_plan["role_contract"]["opencode_config"]["mcp"]["api_client"]["url"] = "https://new.example.com/mcp"
        mut_plan["topology"] = "isolated-sidecars"

        class _FakeCompiled:
            def __init__(self, plan: dict) -> None:
                self.plan = plan

        delta_img_mcp = compute_closed_security_delta(
            {"builtin/api-workbench": base_res},
            {"builtin/api-workbench": _FakeCompiled(mut_plan)},  # type: ignore[dict-item]
        )
        self.assertIn("service_image_changed", delta_img_mcp["triggers"])
        self.assertIn("mcp_tool_surface_widened", delta_img_mcp["triggers"])

        # Weakening isolated-sidecars -> pod-shared or managed -> interactive triggers security_profile_elevation
        weak_plan = json.loads(json.dumps(mut_plan))
        weak_plan["topology"] = "pod-shared"
        weak_plan["tier"] = "interactive"
        strong_plan = json.loads(json.dumps(mut_plan))
        strong_plan["topology"] = "isolated-sidecars"
        strong_plan["tier"] = "managed"
        delta_weak = compute_closed_security_delta(
            {"t": _FakeCompiled(strong_plan)},  # type: ignore[dict-item]
            {"t": _FakeCompiled(weak_plan)},  # type: ignore[dict-item]
        )
        self.assertIn("security_profile_elevation", delta_weak["triggers"])

        # classify_drift classifies MCP changes as recreate-stateless, NOT hot-safe
        mcp_changed = json.loads(json.dumps(base_res.plan))
        mcp_changed["role_contract"]["opencode_config"]["mcp"]["api_client"]["url"] = "http://127.0.0.1:9999/mcp"
        drift = classify_drift(base_res.plan, mcp_changed)
        self.assertEqual(drift["kind"], "recreate-stateless")

        # 64-node DAG cap enforced across bundles
        prev_id: str | None = None
        for i in range(66):
            bid = f"team/chain-{i:02d}"
            extra = f'includes = ["{prev_id}"]' if prev_id else ""
            self.store.operator_direct_upsert("bundle", bid, _sample_bundle_toml(bid, extra))
            prev_id = bid
        with self.assertRaisesRegex(PlanError, "64"):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(
                    with_mods=("team/chain-65",),
                    env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
                ),
            )

    def test_human_review_1_remote_mcp_readonly_default_write_grant_and_credential_split(self) -> None:
        # 1. Local mode: read + write tools active, local credential slot mounted
        local_res = compile_plan(self.store, "builtin/api-workbench")
        local_mcp = local_res.plan["role_contract"]["opencode_config"]["mcp"]["api_client"]
        self.assertEqual(local_mcp["access_mode"], "local")
        self.assertEqual(local_mcp["allowed_tools"], ["query_ro", "mutate_write"])
        self.assertEqual(
            local_mcp["headers"]["Authorization"],
            "Bearer {file:/run/secrets/api_local_token}",
        )
        self.assertEqual(local_res.plan["remote_write_grants"], {})

        # 2. Remote default (staging): fails closed to read-only tools + host-brokered token in container,
        #    with remote-RO credential slot kept strictly host-side in broker_routes
        remote_ro = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"}),
        )
        ro_mcp = remote_ro.plan["role_contract"]["opencode_config"]["mcp"]["api_client"]
        self.assertEqual(ro_mcp["access_mode"], "remote-ro")
        self.assertEqual(ro_mcp["credential_delivery"], "host-brokered")
        self.assertEqual(ro_mcp["allowed_tools"], ["query_ro"])
        self.assertEqual(
            ro_mcp["headers"]["Authorization"],
            "Bearer {file:/run/secrets/oc_broker_token}",
        )
        self.assertEqual(
            remote_ro.plan["broker_routes"]["mcp:api_client"]["upstream_headers"]["Authorization"],
            "Bearer {file:/run/secrets/api_remote_ro_token}",
        )
        self.assertEqual(remote_ro.plan["remote_write_grants"], {})

        # 3. Remote with matching explicit write grant (canonical URL normalized):
        #    admits write tools, switches host-side broker_routes to remote-RW slot, changes plan_digest, surfaces security_delta
        remote_rw = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(
                env_bindings={"API_ENDPOINT": "https://STAGING.example.com:443/mcp"},
                remote_write_grants={"api_client": "https://staging.example.com/mcp"},
            ),
        )
        rw_mcp = remote_rw.plan["role_contract"]["opencode_config"]["mcp"]["api_client"]
        self.assertEqual(rw_mcp["access_mode"], "remote-rw")
        self.assertEqual(rw_mcp["credential_delivery"], "host-brokered")
        self.assertEqual(rw_mcp["allowed_tools"], ["query_ro", "mutate_write"])
        self.assertEqual(
            rw_mcp["headers"]["Authorization"],
            "Bearer {file:/run/secrets/oc_broker_token}",
        )
        self.assertEqual(
            remote_rw.plan["broker_routes"]["mcp:api_client"]["upstream_headers"]["Authorization"],
            "Bearer {file:/run/secrets/api_remote_rw_token}",
        )
        self.assertEqual(
            remote_rw.plan["remote_write_grants"],
            {"api_client": "https://staging.example.com/mcp"},
        )
        self.assertNotEqual(remote_ro.plan_digest, remote_rw.plan_digest)
        delta = compute_closed_security_delta(
            {"builtin/api-workbench": remote_ro},
            {"builtin/api-workbench": remote_rw},
        )
        self.assertIn("remote_write_granted", delta["triggers"])
        self.assertIn("mcp_tool_surface_widened", delta["triggers"])
        self.assertIn("secret_slot_added", delta["triggers"])
        self.assertEqual(classify_drift(remote_ro.plan, remote_rw.plan)["kind"], "recreate-stateless")

        # P3-1: ';params' in remote endpoint URL must be rejected, not silently stripped
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp;foo=bar"}),
            )

        # P3-2: duplicate CLI --env-binding / --allow-remote-write keys fail closed
        with self.assertRaises(SchemaError):
            oc_sandbox_cli._parse_kv(["api_client=https://a.example.com/mcp", "api_client=https://b.example.com/mcp"])

        # 4. Remote with mismatched URL grant is refused fail-closed
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(
                    env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
                    remote_write_grants={"api_client": "https://other.example.com/mcp"},
                ),
            )

        # 5. Remote write grant when MCP is running locally (or unknown MCP) is refused
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(
                    remote_write_grants={"api_client": "https://staging.example.com/mcp"},
                ),
            )
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(
                    env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
                    remote_write_grants={"nonexistent_mcp": "https://staging.example.com/mcp"},
                ),
            )

        # 6. Persona restriction (builtin/persona-security-reviewer) STILL blocks mutate_write
        #    AND downgrades mounted credentials back to remote-RO even with matching write grant!
        audit_rw_attempt = compile_plan(
            self.store,
            "builtin/security-audit",
            overrides=PlanOverrides(
                env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
                remote_write_grants={"api_client": "https://staging.example.com/mcp"},
            ),
        )
        audit_mcp = audit_rw_attempt.plan["role_contract"]["opencode_config"]["mcp"]["api_client"]
        self.assertEqual(audit_mcp["allowed_tools"], ["query_ro"])
        self.assertEqual(audit_mcp["access_mode"], "remote-ro")
        self.assertEqual(
            audit_mcp["headers"]["Authorization"],
            "Bearer {file:/run/secrets/oc_broker_token}",
        )
        self.assertEqual(
            audit_rw_attempt.plan["broker_routes"]["mcp:api_client"]["upstream_headers"]["Authorization"],
            "Bearer {file:/run/secrets/api_remote_ro_token}",
        )
        self.assertEqual(audit_rw_attempt.plan["remote_write_grants"], {})

        # 7. Schema rejects shared secret slot between remote RO and RW, or top-level headers and remote RO
        shared_slot_bundle = _sample_bundle_toml(
            "team/shared-slot",
            (
                '[mcp.dup]\ntype = "remote"\nurl = "http://127.0.0.1:8080/mcp"\n'
                'read_only_tools = ["r"]\nwrite_tools = ["w"]\n'
                '[mcp.dup.remote.read_only_headers]\nAuthorization = "Bearer {file:/run/secrets/same_tok}"\n'
                '[mcp.dup.remote.write_headers]\nAuthorization = "Bearer {file:/run/secrets/same_tok}"\n'
            ),
        )
        with self.assertRaises(PolicyError):
            self.store.create_proposal(
                kind="bundle", obj_id="team/shared-slot", action="upsert", proposed_toml=shared_slot_bundle
            )

        # P2-1: remote.read_only_* cannot overlap top-level local-fallback headers/secret_env
        shared_top_ro_bundle = _sample_bundle_toml(
            "team/shared-top-ro",
            (
                '[mcp.dup_top]\ntype = "remote"\nurl = "http://127.0.0.1:8080/mcp"\n'
                'read_only_tools = ["r"]\nwrite_tools = ["w"]\n'
                '[mcp.dup_top.headers]\nAuthorization = "Bearer {file:/run/secrets/shared_top}"\n'
                '[mcp.dup_top.local]\nbinding_key = "DUP_EP"\nservice = "builtin/api-demo"\nurl = "http://127.0.0.1:8080/mcp"\n'
                '[mcp.dup_top.remote.read_only_headers]\nAuthorization = "Bearer {file:/run/secrets/shared_top}"\n'
            ),
        )
        with self.assertRaises(PolicyError):
            self.store.create_proposal(
                kind="bundle", obj_id="team/shared-top-ro", action="upsert", proposed_toml=shared_top_ro_bundle
            )

        # 8. Bundle without explicit read_only_tools fails closed when bound to a remote endpoint
        no_split_bundle = _sample_bundle_toml(
            "team/no-ro-split",
            (
                '[mcp.legacy_api]\ntype = "remote"\nurl = "http://127.0.0.1:8080/mcp"\n'
                'tools = ["read_item", "write_item"]\n'
                '[mcp.legacy_api.local]\nbinding_key = "LEGACY_EP"\n'
                'service = "builtin/api-demo"\nurl = "http://127.0.0.1:8080/mcp"\n'
            ),
        )
        self.store.operator_direct_upsert("bundle", "team/no-ro-split", no_split_bundle)
        with self.assertRaisesRegex(PolicyError, "read_only_tools"):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(
                    with_mods=("team/no-ro-split",),
                    env_bindings={
                        "API_ENDPOINT": "https://staging.example.com/mcp",
                        "LEGACY_EP": "https://legacy.example.com/mcp",
                    },
                ),
            )

        # 9. P3 regression checks: hyphenated prose words containing "sk-" are allowed,
        #    while token-boundary raw secret prefixes are still rejected; raw "$SB/../outside" is rejected.
        prose_bundle = _sample_bundle_toml(
            "team/prose-ok",
            'instructions = ["Use task-runner and disk-cache safely at low risk-level."]\n',
        )
        prop_ok = self.store.create_proposal(
            kind="bundle", obj_id="team/prose-ok", action="upsert", proposed_toml=prose_bundle
        )
        self.assertEqual(prop_ok["status"], "pending")

        bad_bearer = _sample_bundle_toml(
            "team/prose-bad",
            'instructions = ["Do not paste Bearer sk-1234567890 here"]\n',
        )
        with self.assertRaises(SchemaError):
            self.store.create_proposal(
                kind="bundle", obj_id="team/prose-bad", action="upsert", proposed_toml=bad_bearer
            )

        sb_dir = Path(self.tmp.name) / "sb_dotdot"
        sb_dir.mkdir(mode=0o700)
        with self.assertRaises(PolicyError):
            check_not_in_sandbox(sb_dir / ".." / "outside", sandbox_root=sb_dir)


class TestStoreControllerAndMcp(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="oc-prdl-mcp-")
        self.cfg_dir = Path(self.tmp.name) / "cfg"
        self.sock_dir = Path(self.tmp.name) / "sock"
        self.now = 1000
        self.store = HostConfigStore(self.cfg_dir, clock=lambda: self.now)
        self.server = OrchestratorConfigMcpServer(self.store, self.sock_dir, rate_limit_max=50)
        self.sock_path = self.server.start()

    def tearDown(self) -> None:
        self.server.stop()
        self.tmp.cleanup()

    def _rpc(self, method: str, params: dict | None = None, *, token: str | None = None) -> dict:
        return call_mcp_uds(
            self.sock_path,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "auth_token": self.server.session_token if token is None else token,
                "method": method,
                "params": params or {},
            },
        )

    def test_socket_permissions_and_read_redaction(self) -> None:
        self.assertEqual(stat.S_IMODE(os.lstat(self.sock_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.lstat(self.sock_path).st_mode), 0o600)

        w_resp = self._rpc("config_get", {"kind": "worker", "id": "builtin/example-macos-arm64"})
        self.assertNotIn("host", w_resp["result"]["document"])
        self.assertNotIn("port", w_resp["result"]["document"])

        s_resp = self._rpc("config_get", {"kind": "service", "id": "builtin/postgres"})
        for slot in s_resp["result"]["document"]["secret_slots"]:
            self.assertNotIn("secret_ref", slot)
            self.assertTrue(slot["configured"])

    def test_mcp_auth_framing_strict_json_and_rate_limit(self) -> None:
        # Wrong session token rejected
        bad_tok = self._rpc("config_schema", token="0" * 64)
        self.assertEqual(bad_tok["error"]["code"], -32001)

        # Duplicate JSON key rejected
        dup_body = (
            f'{{"jsonrpc":"2.0","id":1,"auth_token":"{self.server.session_token}",'
            f'"method":"config_schema","method":"config_list","params":{{}}}}'
        ).encode("utf-8")
        dup_frame = f"Content-Length: {len(dup_body)}\r\n\r\n".encode("ascii") + dup_body
        dup_resp = call_mcp_uds(self.sock_path, {}, raw_override=dup_frame)
        self.assertEqual(dup_resp["error"]["code"], -32700)

        # NaN rejected
        nan_body = (
            f'{{"jsonrpc":"2.0","id":NaN,"auth_token":"{self.server.session_token}","method":"config_schema"}}'
        ).encode("utf-8")
        nan_frame = f"Content-Length: {len(nan_body)}\r\n\r\n".encode("ascii") + nan_body
        nan_resp = call_mcp_uds(self.sock_path, {}, raw_override=nan_frame)
        self.assertEqual(nan_resp["error"]["code"], -32700)

        # Excessive nesting depth > 32 rejected
        deep: dict = {"a": 1}
        for _ in range(36):
            deep = {"x": deep}
        deep_resp = self._rpc("config_schema", deep)
        self.assertEqual(deep_resp["error"]["code"], -32700)

        # Trailing/pipelined junk bytes rejected
        valid_frame = encode_content_length_frame(
            {"jsonrpc": "2.0", "id": 1, "auth_token": self.server.session_token, "method": "config_schema"}
        )
        junk_resp = call_mcp_uds(self.sock_path, {}, raw_override=valid_frame + b"EXTRA")
        self.assertEqual(junk_resp["error"]["code"], -32700)

        # Oversized Content-Length rejected
        big_resp = call_mcp_uds(self.sock_path, {}, raw_override=b"Content-Length: 999999\r\n\r\n{}")
        self.assertEqual(big_resp["error"]["code"], -32700)

        # Restart rotates per-incarnation token
        old_token = self.server.session_token
        self.server.stop()
        self.server = OrchestratorConfigMcpServer(self.store, self.sock_dir, rate_limit_max=2)
        self.sock_path = self.server.start()
        self.assertNotEqual(old_token, self.server.session_token)
        stale_resp = self._rpc("config_schema", token=old_token)
        self.assertEqual(stale_resp["error"]["code"], -32001)

        # Rate limiter triggers BEFORE reading/parsing 256 KiB JSON
        _ = self._rpc("config_schema")
        rl_resp = call_mcp_uds(self.sock_path, {}, raw_override=b"NOT_EVEN_VALID_FRAMING")
        self.assertEqual(rl_resp["error"]["code"], -32002)

    def test_so_peercred_wrong_uid_closes_immediately(self) -> None:
        bad_dir = Path(self.tmp.name) / "sock_uid"
        srv = OrchestratorConfigMcpServer(self.store, bad_dir, expected_uid=os.geteuid() + 1)
        sp = srv.start()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as cli:
                cli.settimeout(2.0)
                cli.connect(str(sp))
                try:
                    cli.sendall(encode_content_length_frame({"jsonrpc": "2.0", "id": 1, "method": "config_schema"}))
                    data = cli.recv(1024)
                    self.assertEqual(data, b"")
                except (BrokenPipeError, ConnectionResetError):
                    pass
        finally:
            srv.stop()

    def test_closed_allowlists_and_builtin_immutability(self) -> None:
        # Orchestrator cannot propose worker, host-provider, transport, factory, or builtin/*
        for kind, oid in (
            ("worker", "team/my-worker"),
            ("host-provider", "team/my-hp"),
            ("transport", "team/my-tr"),
            ("factory", "team/my-fac"),
            ("service", "builtin/postgres"),
            ("bundle", "builtin/postgres-app"),
        ):
            resp = self._rpc(
                "config_propose_revision",
                {"kind": kind, "id": oid, "action": "upsert", "proposed_toml": "schema_version = 1\n"},
            )
            self.assertEqual(resp["error"]["code"], -32003, f"Expected refusal for {kind}/{oid}")

        # plan_preview rejects draft overlaying builtin/* or worker
        p_resp = self._rpc(
            "plan_preview",
            {
                "sandbox_type": "builtin/api-workbench",
                "draft": [{"kind": "bundle", "id": "builtin/api-dev", "toml": _sample_bundle_toml("builtin/api-dev")}],
            },
        )
        self.assertEqual(p_resp["error"]["code"], -32003)

    def test_proposal_approval_restore_no_replay_and_cli(self) -> None:
        raw_v1 = _sample_bundle_toml("team/extra", 'instructions = ["V1 rule"]\n')
        # Preview draft first
        prev = self._rpc(
            "plan_preview",
            {
                "sandbox_type": "builtin/api-workbench",
                "overrides": {"with_mods": ["team/extra"]},
                "draft": [{"kind": "bundle", "id": "team/extra", "toml": raw_v1}],
            },
        )
        self.assertIn("plan_digest", prev["result"])
        self.assertIn("team/extra", prev["result"]["bundles"])

        # Propose via MCP
        prop = self._rpc(
            "config_propose_revision",
            {"kind": "bundle", "id": "team/extra", "action": "upsert", "proposed_toml": raw_v1},
        )["result"]
        pid, pdig = prop["proposal_id"], prop["proposal_digest"]

        # Wrong digest fails closed
        with self.assertRaises(DigestMismatchError):
            self.store.approve_proposal(pid, "0" * 64)

        # Approve via clean-slate CLI!
        # (Use same store for controller incarnation check)
        rev1 = self.store.approve_proposal(pid, pdig)
        self.assertEqual(rev1, 1)

        # Upsert v2
        raw_v2 = _sample_bundle_toml("team/extra", 'instructions = ["V2 rule"]\n')
        prop2 = self._rpc(
            "config_propose_revision",
            {"kind": "bundle", "id": "team/extra", "action": "upsert", "proposed_toml": raw_v2},
        )["result"]
        rev2 = self.store.approve_proposal(prop2["proposal_id"], prop2["proposal_digest"])
        self.assertEqual(rev2, 2)

        # Diff & history via MCP (diffs redacted canonical JSON)
        diff_resp = self._rpc("config_diff", {"kind": "bundle", "id": "team/extra", "from_rev": 1, "to_rev": 2})
        self.assertIn('-    "V1 rule"', diff_resp["result"]["diff"])
        self.assertIn('+    "V2 rule"', diff_resp["result"]["diff"])

        # Operator restore creates monotonic rev 3 (never re-emits 1), so old proposal cannot replay
        rev3 = self.store.operator_restore_revision("bundle", "team/extra", 1)
        self.assertEqual(rev3, 3)
        with self.assertRaises(ConflictError):
            self.store.approve_proposal(prop2["proposal_id"], prop2["proposal_digest"])

        # CLI plan works offline with explicit --config-dir
        rc = oc_sandbox_cli.main(["--config-dir", str(self.cfg_dir), "config", "list", "bundle"])
        self.assertEqual(rc, 0)

    def test_archive_dependent_check_unarchive_revalidation_and_action_enum(self) -> None:
        self.store.operator_direct_upsert("bundle", "team/child", _sample_bundle_toml("team/child"))
        self.store.operator_direct_upsert(
            "bundle", "team/parent", _sample_bundle_toml("team/parent", 'includes = ["team/child"]')
        )
        # Cannot archive referenced bundle
        resp = self._rpc("config_propose_revision", {"kind": "bundle", "id": "team/child", "action": "archive"})
        self.assertEqual(resp["error"]["code"], -32004)

        # Closed action enum rejects delete & rejects proposed_toml on archive
        bad_act = self._rpc("config_propose_revision", {"kind": "bundle", "id": "team/parent", "action": "delete"})
        self.assertEqual(bad_act["error"]["code"], -32602)
        bad_toml = self._rpc(
            "config_propose_revision",
            {"kind": "bundle", "id": "team/parent", "action": "archive", "proposed_toml": "x=1"},
        )
        self.assertEqual(bad_toml["error"]["code"], -32602)

        # Archive unreferenced parent -> approve -> unarchive succeeds
        p_arch = self.store.create_proposal(kind="bundle", obj_id="team/parent", action="archive", proposed_toml=None)
        self.store.approve_proposal(p_arch["id"], p_arch["digest"])
        self.assertTrue(self.store.is_archived("bundle", "team/parent"))

        # Gate 2 note #3: tamper archived file on disk with forbidden orchestrator field -> unarchive rejects!
        archived_file = self.cfg_dir / "objects" / "bundle__team@parent.toml"
        archived_file.write_text(
            _sample_bundle_toml("team/parent", '[mise_tools]\n"core:python" = "latest"\n'),
            encoding="utf-8",
        )
        with self.assertRaises(SchemaError):
            self.store.create_proposal(kind="bundle", obj_id="team/parent", action="unarchive", proposed_toml=None)

    def test_uncertain_applying_crash_recovery_restart_and_expiry(self) -> None:
        # 1. State.UNCERTAIN (uncommitted) -> blocks new proposals -> reconcile settles to failed
        raw_a = _sample_bundle_toml("team/unc-a")
        p1 = self.store.create_proposal(kind="bundle", obj_id="team/unc-a", action="upsert", proposed_toml=raw_a)
        self.store.adapter.inject_uncertain_once = True
        with self.assertRaises(PublishUncertainError):
            self.store.approve_proposal(p1["id"], p1["digest"])
        self.assertEqual(self.store.load_proposal(p1["id"])["status"], "uncertain")
        # Blocked until reconciled
        raw_unc_b = _sample_bundle_toml("team/unc-b")
        with self.assertRaises(ConflictError):
            self.store.create_proposal(kind="bundle", obj_id="team/unc-b", action="upsert", proposed_toml=raw_unc_b)
        self.assertEqual(self.store.reconcile_proposal(p1["id"]), "failed")
        self.assertEqual(self.store.load_proposal(p1["id"])["status"], "failed")

        # 2. State.UNCERTAIN (crash AFTER journal write) -> cross-restart reconcile settles to applied!
        p2 = self.store.create_proposal(kind="bundle", obj_id="team/unc-a", action="upsert", proposed_toml=raw_a)
        self.store.adapter.inject_crash_after_write_once = True
        with self.assertRaises(PublishUncertainError):
            self.store.approve_proposal(p2["id"], p2["digest"])
        # Simulate helper restart (fresh incarnation!)
        restarted = HostConfigStore(self.cfg_dir, clock=lambda: self.now)
        self.assertEqual(restarted.reconcile_proposal(p2["id"]), "applied")
        self.assertEqual(restarted.get_revision("bundle", "team/unc-a"), 1)

        # 3. Gate 2 note #1: durable "applying" crash window blocks new publishes and reconciles from journal
        p3 = restarted.create_proposal(kind="bundle", obj_id="team/app-c", action="upsert", proposed_toml=_sample_bundle_toml("team/app-c"))
        prop3 = restarted.load_proposal(p3["id"])
        prop3["status"] = "applying"
        restarted._save_proposal_unlocked(prop3)
        raw_app_d = _sample_bundle_toml("team/app-d")
        with self.assertRaises(ConflictError):
            restarted.create_proposal(kind="bundle", obj_id="team/app-d", action="upsert", proposed_toml=raw_app_d)
        self.assertEqual(restarted.reconcile_proposal(p3["id"]), "failed")

        # 4. Prior-incarnation pending proposal fails closed after restart
        p_old = restarted.create_proposal(kind="bundle", obj_id="team/re-inc", action="upsert", proposed_toml=_sample_bundle_toml("team/re-inc"))
        restarted2 = HostConfigStore(self.cfg_dir, clock=lambda: self.now)
        with self.assertRaises(StaleProposalError):
            restarted2.approve_proposal(p_old["id"], p_old["digest"])

        # 5. Gate 2 note #2: controller.decide() State.EXPIRED handled cleanly before invoke()
        # Simulate clock ticking past TTL right between approve_proposal's pre-check and controller.decide()
        clock_ticks = {"mode": "normal", "calls": 0}

        def _racy_clock() -> int:
            if clock_ticks["mode"] == "race":
                clock_ticks["calls"] += 1
                # First call is approve_proposal's own check (still valid); second is controller.decide() (expired!)
                return self.now if clock_ticks["calls"] == 1 else self.now + 1000
            return self.now

        racy_store = HostConfigStore(self.cfg_dir, clock=_racy_clock)
        p_exp = racy_store.create_proposal(
            kind="bundle", obj_id="team/exp", action="upsert", proposed_toml=_sample_bundle_toml("team/exp")
        )
        clock_ticks["mode"] = "race"
        with self.assertRaises(ExpiredProposalError):
            racy_store.approve_proposal(p_exp["id"], p_exp["digest"])
        self.assertEqual(racy_store.load_proposal(p_exp["id"])["status"], "expired")

    def test_p1_1_config_diff_redaction_malformed_toml_and_cli_ports(self) -> None:
        # 1. config_diff redacts worker.host/port and service.secret_slots[].secret_ref
        host_v1 = _ip(10, 99, 0, 10)
        host_v2 = _ip(10, 99, 0, 20)
        w_v1 = (
            'schema_version = 1\nkind = "worker@1"\nid = "team/private-w"\n'
            'host_provider = "builtin/podman-macos-vm"\ntransport = "builtin/ssh-pinned"\n'
            f'arch = "arm64"\nhost = "{host_v1}"\nport = 2222\n'
        )
        w_v2 = (
            'schema_version = 1\nkind = "worker@1"\nid = "team/private-w"\n'
            'host_provider = "builtin/podman-macos-vm"\ntransport = "builtin/ssh-pinned"\n'
            f'arch = "x86_64"\nhost = "{host_v2}"\nport = 2223\n'
        )
        self.store.operator_direct_upsert("worker", "team/private-w", w_v1)
        self.store.operator_direct_upsert("worker", "team/private-w", w_v2)
        w_diff = self._rpc("config_diff", {"kind": "worker", "id": "team/private-w", "from_rev": 1, "to_rev": 2})
        self.assertIn("result", w_diff)
        self.assertNotIn(host_v1, w_diff["result"]["diff"])
        self.assertNotIn(host_v2, w_diff["result"]["diff"])
        self.assertNotIn("2222", w_diff["result"]["diff"])
        self.assertNotIn("2223", w_diff["result"]["diff"])
        self.assertIn("arm64", w_diff["result"]["diff"])
        self.assertIn("x86_64", w_diff["result"]["diff"])

        s_v1 = _sample_service_toml(
            "team/secret-svc",
            port=8111,
            extra='[[secret_slots]]\nslot = "db_pw"\ntarget = "/run/secrets/db_pw"\nsecret_ref = "keeper:vault/secret_v1"\n',
        )
        s_v2 = _sample_service_toml(
            "team/secret-svc",
            port=8112,
            extra='[[secret_slots]]\nslot = "db_pw"\ntarget = "/run/secrets/db_pw"\nsecret_ref = "keeper:vault/secret_v2"\n',
        )
        self.store.operator_direct_upsert("service", "team/secret-svc", s_v1)
        self.store.operator_direct_upsert("service", "team/secret-svc", s_v2)
        s_diff = self._rpc("config_diff", {"kind": "service", "id": "team/secret-svc", "from_rev": 1, "to_rev": 2})
        self.assertIn("result", s_diff)
        self.assertNotIn("secret_v1", s_diff["result"]["diff"])
        self.assertNotIn("secret_v2", s_diff["result"]["diff"])
        self.assertNotIn("secret_ref", s_diff["result"]["diff"])

        # 2. Malformed TOML, duplicate drafts, malformed overrides, and bad cli_ports return clean JSON-RPC errors
        bad_calls = [
            (
                "config_propose_revision",
                {"kind": "bundle", "id": "team/bad-toml", "action": "upsert", "proposed_toml": "not valid [ toml"},
            ),
            (
                "plan_preview",
                {
                    "sandbox_type": "builtin/api-workbench",
                    "draft": [{"kind": "bundle", "id": "team/bad-toml", "toml": "not valid [ toml"}],
                },
            ),
            (
                "plan_preview",
                {
                    "sandbox_type": "builtin/api-workbench",
                    "draft": [
                        {"kind": "bundle", "id": "team/dup", "toml": _sample_bundle_toml("team/dup")},
                        {"kind": "bundle", "id": "team/dup", "toml": _sample_bundle_toml("team/dup")},
                    ],
                },
            ),
            (
                "plan_preview",
                {
                    "sandbox_type": "builtin/api-workbench",
                    "draft": [{"kind": "bundle", "id": "team/x", "toml": _sample_bundle_toml("team/x"), "extra": 1}],
                },
            ),
            (
                "plan_preview",
                {"sandbox_type": "builtin/api-workbench", "overrides": {"with_mods": "not-a-list"}},
            ),
            (
                "plan_preview",
                {"sandbox_type": "builtin/api-workbench", "overrides": {"env_bindings": ["not", "dict"]}},
            ),
            (
                "plan_preview",
                {
                    "sandbox_type": "builtin/api-workbench",
                    "overrides": {
                        "cli_ports": [
                            {"service": "builtin/postgres", "endpoint": "pg", "exposure": "host-loopback", "host_port": 80}
                        ]
                    },
                },
            ),
            (
                "plan_preview",
                {
                    "sandbox_type": "builtin/api-workbench",
                    "overrides": {
                        "cli_ports": [{"service": "builtin/postgres", "endpoint": "pg", "exposure": "public"}]
                    },
                },
            ),
        ]
        for method, params in bad_calls:
            with self.subTest(method=method, params=params):
                resp = self._rpc(method, params)
                self.assertIn("error", resp)
                self.assertEqual(resp["error"]["code"], -32602)

        # Server remains healthy after all malformed calls
        ok_resp = self._rpc("config_schema")
        self.assertIn("result", ok_resp)

    def test_p1_4_injective_id_filenames_strict_proposal_id_and_locked_restore(self) -> None:
        # "team/foo" and "team__foo" must NOT collide on disk or in revision history
        self.store.operator_direct_upsert("bundle", "team/foo", _sample_bundle_toml("team/foo", 'instructions = ["SLASH"]'))
        self.store.operator_direct_upsert("bundle", "team__foo", _sample_bundle_toml("team__foo", 'instructions = ["UNDER"]'))
        self.assertEqual(self.store.get("bundle", "team/foo")["instructions"], ["SLASH"])
        self.assertEqual(self.store.get("bundle", "team__foo")["instructions"], ["UNDER"])
        self.assertIn("SLASH", self.store.get_revision_toml("bundle", "team/foo", 1))
        self.assertIn("UNDER", self.store.get_revision_toml("bundle", "team__foo", 1))

        # Strict proposal_id validation
        for bad_pid in ("", "../state", "prop_short", "prop_GGGGGGGGGGGGGGGG", "not-a-prop"):
            with self.subTest(bad_pid=bad_pid), self.assertRaises(SchemaError):
                self.store.load_proposal(bad_pid)

        # Strict revision/kind validation on get_revision_toml
        with self.assertRaises(SchemaError):
            self.store.get_revision_toml("bundle", "team/foo", 0)
        with self.assertRaises(SchemaError):
            self.store.get_revision_toml("evil-kind", "team/foo", 1)

    def test_p2_5_mcp_framing_unicode_cursor_bool_coercion_and_write_timeout(self) -> None:
        # Non-ASCII header returns clean -32700 error
        bad_hdr = call_mcp_uds(self.sock_path, {}, raw_override=b"Content-Length: 2\r\nX-Bad: \xff\r\n\r\n{}")
        self.assertEqual(bad_hdr["error"]["code"], -32700)

        # Unknown header (Transfer-Encoding) rejected
        te_hdr = call_mcp_uds(
            self.sock_path,
            {},
            raw_override=b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
        )
        self.assertEqual(te_hdr["error"]["code"], -32700)

        # Unknown top-level RPC key rejected
        extra_rpc = call_mcp_uds(
            self.sock_path,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "auth_token": self.server.session_token,
                "method": "config_schema",
                "params": {},
                "smuggled": True,
            },
        )
        self.assertEqual(extra_rpc["error"]["code"], -32600)

        # Unicode superscript digit cursor rejected
        bad_cur = self._rpc("config_list", {"kind": "bundle", "cursor": "off:\u00b2"})
        self.assertEqual(bad_cur["error"]["code"], -32602)

        # String "false" for include_archived rejected (no truthy bool coercion)
        bad_bool_list = self._rpc("config_list", {"kind": "bundle", "include_archived": "false"})
        self.assertEqual(bad_bool_list["error"]["code"], -32602)
        bad_bool_get = self._rpc("config_get", {"kind": "bundle", "id": "builtin/api-dev", "include_archived": "false"})
        self.assertEqual(bad_bool_get["error"]["code"], -32602)

        # Symlink socket_dir and non-socket mcp.sock rejected on start()
        sym_sock_dir = Path(self.tmp.name) / "sym_sock_dir"
        os.symlink(self.sock_dir, sym_sock_dir)
        sym_srv = OrchestratorConfigMcpServer(self.store, sym_sock_dir)
        with self.assertRaises(PolicyError):
            sym_srv.start()

        nonsock_dir = Path(self.tmp.name) / "nonsock_dir"
        nonsock_dir.mkdir(mode=0o700)
        decoy = nonsock_dir / "mcp.sock"
        decoy.write_text("keep me", encoding="utf-8")
        nonsock_srv = OrchestratorConfigMcpServer(self.store, nonsock_dir)
        with self.assertRaises(PolicyError):
            nonsock_srv.start()
        self.assertTrue(decoy.exists())

        # Write timeout prevents slow/non-reading client from blocking _send indefinitely
        fast_srv = OrchestratorConfigMcpServer(
            self.store, Path(self.tmp.name) / "wt_sock", write_timeout=0.05
        )
        s_a, s_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s_a.setblocking(False)
            # Fill kernel send buffer completely so next sendall blocks until timeout
            try:
                while True:
                    s_a.send(b"x" * 16384)
            except BlockingIOError:
                pass
            fast_srv._send(s_a, {"jsonrpc": "2.0", "id": 1, "result": {"pad": "A" * 65536}})
            self.assertEqual(s_a.gettimeout(), 0.05)
        finally:
            s_a.close()
            s_b.close()

    def test_p2_8_cli_symlink_validate_port_bounds_and_proposal_ttl_bounds(self) -> None:
        # CLI config validate rejects symlinks via read_regular_no_follow
        target = Path(self.tmp.name) / "real.toml"
        target.write_text(_sample_bundle_toml("team/cli-val"), encoding="utf-8")
        sym = Path(self.tmp.name) / "link.toml"
        os.symlink(target, sym)
        with self.assertRaises(PolicyError):
            oc_sandbox_cli.main(["--config-dir", str(self.cfg_dir), "config", "validate", "bundle", str(sym)])

        # CLI _parse_port rejects privileged host_port and invalid exposure
        with self.assertRaises(SchemaError):
            oc_sandbox_cli._parse_port(["builtin/postgres:pg:host-loopback:80"])
        with self.assertRaises(SchemaError):
            oc_sandbox_cli._parse_port(["builtin/postgres:pg:world-public:5432"])

        # create_proposal enforces 1 <= ttl_seconds <= DEFAULT_PROPOSAL_TTL_SECONDS
        raw_ttl = _sample_bundle_toml("team/ttl-check")
        for bad_ttl in (0, -10, 2000, True):
            with self.subTest(bad_ttl=bad_ttl), self.assertRaises(SchemaError):
                self.store.create_proposal(
                    kind="bundle",
                    obj_id="team/ttl-check",
                    action="upsert",
                    proposed_toml=raw_ttl,
                    ttl_seconds=bad_ttl,  # type: ignore[arg-type]
                )

    def test_human_review_2_scratch_config_dir_isolation_and_marker(self) -> None:
        fake_home = Path(self.tmp.name) / "fake_home"
        fake_xdg = Path(self.tmp.name) / "fake_xdg"
        fake_home.mkdir(mode=0o700)
        fake_xdg.mkdir(mode=0o700)
        prod_home_cfg = fake_home / ".config" / "oc-sandbox"
        prod_xdg_cfg = fake_xdg / "oc-sandbox"

        with mock.patch.dict(
            os.environ,
            {"HOME": str(fake_home), "XDG_CONFIG_HOME": str(fake_xdg)},
        ):
            # Refuse ~/.config/oc-sandbox, nested paths, $XDG_CONFIG_HOME/oc-sandbox, and CLI entry
            for target in (prod_home_cfg, prod_home_cfg / "sub", prod_xdg_cfg):
                with self.subTest(target=str(target)):
                    with self.assertRaises(PolicyError):
                        HostConfigStore(target)
                    self.assertFalse(target.exists(), f"Refused dir should not be created: {target}")

            with self.assertRaises(PolicyError):
                oc_sandbox_cli.main(["--config-dir", str(prod_home_cfg), "config", "list", "bundle"])
            self.assertFalse(prod_home_cfg.exists())

            # Refuse symlink pointing into ~/.config/oc-sandbox
            sym_to_prod = Path(self.tmp.name) / "sym_prod"
            os.symlink(prod_home_cfg, sym_to_prod)
            with self.assertRaises(PolicyError):
                HostConfigStore(sym_to_prod)

        # Refuse initializing into an existing non-empty non-PoC directory (zero side effects!)
        nonempty = Path(self.tmp.name) / "existing_nonempty"
        nonempty.mkdir(mode=0o755)
        (nonempty / "unrelated.txt").write_text("do not touch", encoding="utf-8")
        with self.assertRaisesRegex(PolicyError, "non-empty non-PoC"):
            HostConfigStore(nonempty)
        self.assertFalse((nonempty / "store.lock").exists())
        self.assertFalse((nonempty / "state.json").exists())
        self.assertFalse((nonempty / POC_STORE_MARKER).exists())
        self.assertEqual(stat.S_IMODE(os.lstat(nonempty).st_mode), 0o755)

        # Existing empty directory IS accepted, gets 0o600 marker, and can be re-opened cleanly
        empty_dir = Path(self.tmp.name) / "empty_scratch"
        empty_dir.mkdir(mode=0o700)
        s1 = HostConfigStore(empty_dir)
        marker = empty_dir / POC_STORE_MARKER
        self.assertTrue(marker.is_file())
        self.assertEqual(stat.S_IMODE(os.lstat(marker).st_mode), 0o600)
        s2 = HostConfigStore(empty_dir)
        self.assertEqual(s2.store_revision, s1.store_revision)

    def test_human_review_3_cross_process_operator_uds_approve_and_restart_fail_closed(self) -> None:
        op_sock_dir = Path(self.tmp.name) / "op_sock"
        op_srv = OperatorControlServer(self.store, op_sock_dir)
        op_sock = op_srv.start()
        try:
            # Verify host-only socket & token permissions
            self.assertEqual(stat.S_IMODE(os.lstat(op_sock_dir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.lstat(op_sock).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.lstat(op_sock_dir / "operator.token").st_mode), 0o600)

            # Orchestrator socket NEVER allows operator_approve; operator socket rejects wrong token
            orch_attempt = self._rpc("operator_approve", {"proposal_id": "prop_" + "0" * 16, "digest": "a" * 64})
            self.assertEqual(orch_attempt["error"]["code"], -32601)
            bad_op_tok = call_mcp_uds(
                op_sock,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "auth_token": "0" * 64,
                    "method": "operator_status",
                    "params": {},
                },
            )
            self.assertEqual(bad_op_tok["error"]["code"], -32001)

            # 1. Propose via orchestrator MCP -> approve from a FRESH CLI subprocess via --operator-socket
            raw_v1 = _sample_bundle_toml("team/cross-proc", 'instructions = ["Cross-process v1"]\n')
            prop1 = self._rpc(
                "config_propose_revision",
                {"kind": "bundle", "id": "team/cross-proc", "action": "upsert", "proposed_toml": raw_v1},
            )["result"]

            # Without --operator-socket, fresh CLI process has different incarnation and fails closed
            no_sock_proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(_SPIKE_DIR / "oc_sandbox_cli.py"),
                    "--config-dir",
                    str(self.cfg_dir),
                    "config",
                    "approve",
                    prop1["proposal_id"],
                    "--digest",
                    prop1["proposal_digest"],
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(no_sock_proc.returncode, 0)
            self.assertIn("prior helper incarnation", no_sock_proc.stderr)

            # With --operator-socket pointing at the live helper, fresh CLI subprocess succeeds!
            ok_proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(_SPIKE_DIR / "oc_sandbox_cli.py"),
                    "--config-dir",
                    str(self.cfg_dir),
                    "config",
                    "approve",
                    prop1["proposal_id"],
                    "--digest",
                    prop1["proposal_digest"],
                    "--operator-socket",
                    str(op_sock),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(ok_proc.returncode, 0, f"stderr={ok_proc.stderr}")
            parsed_out = json.loads(ok_proc.stdout)
            self.assertEqual(parsed_out, {"approved": True, "revision": 1})
            self.assertEqual(self.store.get_revision("bundle", "team/cross-proc"), 1)

            # End-to-end CLI --allow-remote-write smoke check in fresh subprocess
            cli_rw = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(_SPIKE_DIR / "oc_sandbox_cli.py"),
                    "--config-dir",
                    str(self.cfg_dir),
                    "plan",
                    "--type",
                    "builtin/api-workbench",
                    "--env-binding",
                    "API_ENDPOINT=https://staging.example.com/mcp",
                    "--allow-remote-write",
                    "api_client=https://staging.example.com/mcp",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(cli_rw.returncode, 0, f"stderr={cli_rw.stderr}")
            cli_plan = json.loads(cli_rw.stdout)["plan"]
            self.assertEqual(
                cli_plan["role_contract"]["opencode_config"]["mcp"]["api_client"]["access_mode"],
                "remote-rw",
            )

            # 2. Propose v2 under incarnation 1, then RESTART helper (incarnation 2) -> must FAIL CLOSED!
            raw_v2 = _sample_bundle_toml("team/cross-proc", 'instructions = ["Cross-process v2"]\n')
            prop2 = self._rpc(
                "config_propose_revision",
                {"kind": "bundle", "id": "team/cross-proc", "action": "upsert", "proposed_toml": raw_v2},
            )["result"]
        finally:
            op_srv.stop()

        # Start fresh helper incarnation 2 on the SAME config_dir and op_sock_dir
        restarted_store = HostConfigStore(self.cfg_dir, clock=lambda: self.now)
        op_srv2 = OperatorControlServer(restarted_store, op_sock_dir)
        op_sock2 = op_srv2.start()
        try:
            stale_proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(_SPIKE_DIR / "oc_sandbox_cli.py"),
                    "--config-dir",
                    str(self.cfg_dir),
                    "config",
                    "approve",
                    prop2["proposal_id"],
                    "--digest",
                    prop2["proposal_digest"],
                    "--operator-socket",
                    str(op_sock2),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(stale_proc.returncode, 0)
            self.assertIn("prior helper incarnation", stale_proc.stderr)
            self.assertEqual(restarted_store.get_revision("bundle", "team/cross-proc"), 1)
        finally:
            op_srv2.stop()

    def test_delta_p1_1_symlink_dotdot_and_p2_2_operator_uds_boundaries(self) -> None:
        # P1-1 Attack A: base/link -> base/a/b, base/a/evil_prod -> $HOME/.config/oc-sandbox
        # HostConfigStore(base/link/../evil_prod/poc_sub) must fail BEFORE mkdir/chmod!
        fake_home = Path(self.tmp.name) / "p1_home"
        prod_dir = fake_home / ".config" / "oc-sandbox"
        prod_dir.mkdir(parents=True, mode=0o700)
        base = Path(self.tmp.name) / "p1_base"
        (base / "a" / "b").mkdir(parents=True, mode=0o700)
        os.symlink(base / "a" / "b", base / "link")
        os.symlink(prod_dir, base / "a" / "evil_prod")
        with mock.patch.dict(os.environ, {"HOME": str(fake_home)}, clear=False), self.assertRaises(PolicyError):
            HostConfigStore(base / "link" / ".." / "evil_prod" / "poc_sub")
        self.assertFalse((prod_dir / "poc_sub").exists())

        # P1-1 Attack B: base/link -> base/a/b, base/a/via_sb -> $SB/hop, $SB/hop -> outside_target
        sb = Path(self.tmp.name) / "p1_sb"
        sb.mkdir(mode=0o700)
        outside = Path(self.tmp.name) / "p1_outside"
        outside.mkdir(mode=0o700)
        os.symlink(outside, sb / "hop")
        os.symlink(sb / "hop", base / "a" / "via_sb")
        with self.assertRaises(PolicyError):
            HostConfigStore(base / "link" / ".." / "via_sb" / "store_dir", sandbox_root=sb)
        self.assertFalse((outside / "store_dir").exists())

        # P2-2a: Refuse shared socket_dir between OrchestratorConfigMcpServer and OperatorControlServer
        shared_op_srv = OperatorControlServer(self.store, self.sock_dir)
        with self.assertRaises(PolicyError):
            shared_op_srv.start()

        op_dir = Path(self.tmp.name) / "p2_op_dir"
        op_srv = OperatorControlServer(self.store, op_dir)
        op_sock = op_srv.start()
        try:
            shared_mcp_srv = OrchestratorConfigMcpServer(self.store, op_dir)
            with self.assertRaises(PolicyError):
                shared_mcp_srv.start()

            # P2-2b: Mismatched --config-dir with --operator-socket fails closed AND does NOT create the dir
            prop = self._rpc(
                "config_propose_revision",
                {
                    "kind": "bundle",
                    "id": "team/mismatch-cfg",
                    "action": "upsert",
                    "proposed_toml": _sample_bundle_toml("team/mismatch-cfg"),
                },
            )["result"]
            wrong_cfg = Path(self.tmp.name) / "never_create_me"
            mismatch_proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(_SPIKE_DIR / "oc_sandbox_cli.py"),
                    "--config-dir",
                    str(wrong_cfg),
                    "config",
                    "approve",
                    prop["proposal_id"],
                    "--digest",
                    prop["proposal_digest"],
                    "--operator-socket",
                    str(op_sock),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(mismatch_proc.returncode, 0)
            self.assertFalse(wrong_cfg.exists(), "CLI must not create --config-dir on --operator-socket mismatch")
            self.assertEqual(self.store.get_revision("bundle", "team/mismatch-cfg"), 0)

            # P2-2c: Client-side socket permission check (0o640 rejected) & peer UID check before sending token
            os.chmod(op_sock, 0o640)
            try:
                with self.assertRaisesRegex(PolicyError, "permissions too open"):
                    call_operator_uds(op_sock, "operator_status", {})
            finally:
                os.chmod(op_sock, 0o600)

            wrong_uid = os.geteuid() + 1
            with self.assertRaisesRegex(PolicyError, "peer UID mismatch"):
                call_operator_uds(op_sock, "operator_status", {}, expected_peer_uid=wrong_uid)
        finally:
            op_srv.stop()

    def test_orchestrator_base_skills_present_with_frontmatter(self) -> None:
        skills_dir = _SPIKE_DIR / "orchestrator_skills"
        expected = {
            "oc-config-architecture",
            "oc-sandbox-authoring",
            "oc-services-and-ports",
            "oc-workers-and-providers",
        }
        found = set()
        for name in expected:
            sk = skills_dir / name / "SKILL.md"
            self.assertTrue(sk.is_file(), f"Missing skill {sk}")
            txt = sk.read_text("utf-8")
            self.assertTrue(txt.startswith("---\nname: " + name + "\n"))
            found.add(name)
        self.assertEqual(found, expected)


if __name__ == "__main__":
    unittest.main()
