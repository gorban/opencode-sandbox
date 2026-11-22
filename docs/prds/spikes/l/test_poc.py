"""Comprehensive offline adversarial & unit test suite for PRD L spike PoC.

Uses only isolated TemporaryDirectory --config-dir paths; never touches ~/.config/oc-sandbox/.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest

_SPIKE_DIR = Path(__file__).resolve().parent
if str(_SPIKE_DIR) not in sys.path:
    sys.path.insert(0, str(_SPIKE_DIR))

from oc_config_mcp import (  # noqa: E402
    OrchestratorConfigMcpServer,
    call_mcp_uds,
    encode_content_length_frame,
)
from oc_plan import PlanError, PlanOverrides, compile_plan  # noqa: E402
import oc_sandbox_cli  # noqa: E402
from oc_schema import (  # noqa: E402
    PolicyError,
    SchemaError,
    validate_host_url_template,
    validate_opaque_id,
)
from oc_store import (  # noqa: E402
    ConflictError,
    DigestMismatchError,
    ExpiredProposalError,
    HostConfigStore,
    PublishUncertainError,
    StaleProposalError,
)


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

        # Remote API_ENDPOINT -> prunes BOTH api-demo and transitive postgres
        remote_res = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"}),
        )
        self.assertEqual(remote_res.plan["services"], [])
        self.assertEqual(
            remote_res.plan["role_contract"]["opencode_config"]["mcp"]["api_client"]["url"],
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
            "https://169.254.169.254/latest/meta-data",
            "https://host.containers.internal/mcp",
            "https://user:pass@staging.example.com/mcp",
            "https://10.0.0.5/mcp",
        ):
            with self.subTest(url=bad):
                with self.assertRaises(PolicyError):
                    compile_plan(
                        self.store,
                        "builtin/api-workbench",
                        overrides=PlanOverrides(env_bindings={"API_ENDPOINT": bad}),
                    )

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
        asset_dir = self.cfg_dir / "assets" / "team__slot-test"
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

        # Symlink slot file rejected via O_NOFOLLOW
        secret_file = Path(self.tmp.name) / "outside.md"
        secret_file.write_text("SECRET_CONTENT", encoding="utf-8")
        link_path = asset_dir / "evil.md"
        os.symlink(secret_file, link_path)
        self.store.operator_direct_upsert(
            "bundle",
            "team/slot-symlink",
            _sample_bundle_toml(
                "team/slot-symlink",
                'instructions = ["{{evil}}"]\n[prompt_slots]\nevil = "evil.md"\n',
            ),
        )
        with self.assertRaises(PolicyError):
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
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(SchemaError):
                    validate_opaque_id(bad_id)

        # Host URL template rejects password placeholder and bad schemes
        with self.assertRaises(SchemaError):
            validate_host_url_template("postgresql://{user}:{password}@{host}:{port}/{db}", "tpl")
        with self.assertRaises(SchemaError):
            validate_host_url_template("file://{path}", "tpl")

        # Forbidden env keys, raw secrets, host bind mounts, unpinned image, latest mise
        bad_services = [
            _sample_service_toml("team/bad-env", extra='[env]\nLD_PRELOAD = "/evil.so"'),
            _sample_service_toml("team/bad-key", extra='[env]\nOPENAI_API_KEY = "foo"'),
            _sample_service_toml("team/bad-sec", extra='[env]\nSAFE_VAR = "sk-1234567890"'),
            _sample_service_toml("team/bad-bind", extra='[[volumes]]\nname = "v"\nkind = "bind"\ntarget = "/host"'),
            _sample_service_toml("team/bad-mise", extra='[mise_tools]\n"core:node" = "latest"'),
        ]
        for raw in bad_services:
            with self.assertRaises((SchemaError, PolicyError)):
                self.store.create_proposal(kind="service", obj_id="team/bad-env", action="upsert", proposed_toml=raw)


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

        # Diff & history via MCP
        diff_resp = self._rpc("config_diff", {"kind": "bundle", "id": "team/extra", "from_rev": 1, "to_rev": 2})
        self.assertIn("-instructions = [\"V1 rule\"]", diff_resp["result"]["diff"])
        self.assertIn("+instructions = [\"V2 rule\"]", diff_resp["result"]["diff"])

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
        archived_file = self.cfg_dir / "objects" / "bundle__team__parent.toml"
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
        with self.assertRaises(ConflictError):
            self.store.create_proposal(kind="bundle", obj_id="team/unc-b", action="upsert", proposed_toml=_sample_bundle_toml("team/unc-b"))
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
        with self.assertRaises(ConflictError):
            restarted.create_proposal(kind="bundle", obj_id="team/app-d", action="upsert", proposed_toml=_sample_bundle_toml("team/app-d"))
        self.assertEqual(restarted.reconcile_proposal(p3["id"]), "failed")

        # 4. Prior-incarnation pending proposal fails closed after restart
        p_old = restarted.create_proposal(kind="bundle", obj_id="team/re-inc", action="upsert", proposed_toml=_sample_bundle_toml("team/re-inc"))
        restarted2 = HostConfigStore(self.cfg_dir, clock=lambda: self.now)
        with self.assertRaises(StaleProposalError):
            restarted2.approve_proposal(p_old["id"], p_old["digest"])

        # 5. Gate 2 note #2: controller.decide() State.EXPIRED handled cleanly before invoke()
        p_exp = restarted2.create_proposal(
            kind="bundle", obj_id="team/exp", action="upsert", proposed_toml=_sample_bundle_toml("team/exp"), ttl_seconds=2000
        )
        # Advance clock past controller lifetime (900) while still < proposal ttl (2000) -> controller.decide returns EXPIRED
        self.now += 1000
        with self.assertRaises(ExpiredProposalError):
            restarted2.approve_proposal(p_exp["id"], p_exp["digest"])
        self.assertEqual(restarted2.load_proposal(p_exp["id"])["status"], "expired")

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
