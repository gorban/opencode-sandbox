"""Unit and adversarial tests for PRD L1 Lane 1: Plan IR & Schema Split.

Pure offline tests using isolated TemporaryDirectory stores; never touches ~/.config/oc-sandbox/.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

_SPIKE_DIR = Path(__file__).resolve().parent
if str(_SPIKE_DIR) not in sys.path:
    sys.path.insert(0, str(_SPIKE_DIR))

from oc_config_mcp import OrchestratorConfigMcpServer, call_mcp_uds  # noqa: E402
from oc_plan import (  # noqa: E402
    DEFAULT_BROKER_HTTP_PORT,
    DEFAULT_BROKER_PG_PORT,
    PlanError,
    PlanOverrides,
    compile_plan,
    compute_closed_security_delta,
    redact_plan_summary,
)
from oc_schema import (  # noqa: E402
    BODY_POLICIES,
    CREDENTIAL_DELIVERY_MODES,
    HTTP_METHODS,
    INBOUND_AUTH_MODES,
    SECURITY_DELTA_TRIGGERS,
    SENSITIVE_HTTP_HEADERS,
    PolicyError,
    SchemaError,
    get_default_wire_policy_preset,
    parse_toml_strict,
    validate_bundle_doc,
    validate_wire_policy,
)
from oc_store import HostConfigStore  # noqa: E402


def _ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def _cidr(a: int, b: int, c: int, d: int, prefix: int) -> str:
    return f"{_ip(a, b, c, d)}/{prefix}"


def _bundle_toml(bid: str, extra: str = "") -> str:
    return (
        f'schema_version = 1\n'
        f'kind = "bundle@1"\n'
        f'id = "{bid}"\n'
        f'description = "Test bundle {bid}"\n'
        f'{extra}\n'
    )


def _sandbox_type_toml(
    stid: str,
    *,
    tier: str = "interactive",
    topology: str = "pod-shared",
    bundles: str = '["builtin/api-dev", "builtin/persona-implementer"]',
    default_worker: str = "builtin/local-workstation",
) -> str:
    return (
        f'schema_version = 1\n'
        f'kind = "sandbox-type@1"\n'
        f'id = "{stid}"\n'
        f'description = "Test sandbox type {stid}"\n'
        f'tier = "{tier}"\n'
        f'topology = "{topology}"\n'
        f'default_worker = "{default_worker}"\n'
        f'bundles = {bundles}\n'
        f'base_image = "ghcr.io/anomalyco/opencode@sha256:{"b" * 64}"\n'
    )


class _FakeCompiled:
    def __init__(self, plan: dict) -> None:
        self.plan = plan


class TestBrokerSchemaPrimitives(unittest.TestCase):
    def test_closed_constants_and_security_delta_triggers(self) -> None:
        self.assertIn("raw_remote_secret_mounted", SECURITY_DELTA_TRIGGERS)
        self.assertEqual(
            CREDENTIAL_DELIVERY_MODES,
            frozenset({"host-brokered", "local-ephemeral", "raw-container-mount"}),
        )
        self.assertEqual(
            INBOUND_AUTH_MODES,
            frozenset({"bearer", "basic-token", "aws-sigv4-job-key", "header"}),
        )
        self.assertEqual(
            BODY_POLICIES,
            frozenset({"none", "mcp-jsonrpc", "graphql-query-only", "aws-sigv4"}),
        )
        self.assertEqual(
            HTTP_METHODS,
            frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}),
        )
        self.assertTrue(
            {
                "authorization",
                "x-api-key",
                "x-goog-api-key",
                "cookie",
                "proxy-authorization",
                "x-auth-token",
                "x-access-token",
            }.issubset(SENSITIVE_HTTP_HEADERS)
        )

    def test_expanded_sensitive_headers_reject_plaintext_and_accept_secret_ref(self) -> None:
        for hdr in (
            "Authorization",
            "X-API-Key",
            "X-Goog-API-Key",
            "Cookie",
            "Proxy-Authorization",
            "X-Auth-Token",
            "X-Access-Token",
            "x-auth-token",
        ):
            bad_doc = parse_toml_strict(
                _bundle_toml(
                    "team/hdr-bad",
                    f'[mcp.s]\ntype = "remote"\nurl = "http://127.0.0.1:8080/mcp"\n'
                    f'tools = ["r"]\n[mcp.s.headers]\n"{hdr}" = "plaintext-secret-value"\n',
                )
            )
            with self.subTest(header=hdr, mode="bad"), self.assertRaises(PolicyError):
                validate_bundle_doc(bad_doc, expected_id="team/hdr-bad")

            ok_doc = parse_toml_strict(
                _bundle_toml(
                    "team/hdr-ok",
                    f'[mcp.s]\ntype = "remote"\nurl = "http://127.0.0.1:8080/mcp"\n'
                    f'tools = ["r"]\n[mcp.s.headers]\n"{hdr}" = "{{file:/run/secrets/tok_slot}}"\n',
                )
            )
            with self.subTest(header=hdr, mode="ok"):
                validated = validate_bundle_doc(ok_doc, expected_id="team/hdr-ok")
                self.assertEqual(validated["mcp"]["s"]["headers"][hdr], "{file:/run/secrets/tok_slot}")

    def test_wire_policy_validation_and_default_presets(self) -> None:
        for preset_name in ("concourse", "k8s", "sonarqube", "github", "aws", "mcp"):
            wp = get_default_wire_policy_preset(preset_name)
            validated = validate_wire_policy(wp, f"preset:{preset_name}")
            self.assertEqual(validated, wp)

        k8s = get_default_wire_policy_preset("k8s")
        k8s_patterns = k8s["allow_rules"][0]["path_patterns"]
        self.assertIn("/api/v1/namespaces/*/pods/*", k8s_patterns)
        self.assertIn("/api/v1/namespaces/*/pods/*/log", k8s_patterns)
        self.assertIn("/api/v1/namespaces/*/secrets", k8s["denied_paths"])
        self.assertIn("/api/v1/namespaces/*/pods/*/exec", k8s["denied_paths"])

        for bad_pat in (
            "relative/path",
            "/api//v1",
            "/api/../secrets",
            "/api/./pods",
            "/api/**/pods",
            "/api/%2f/pods",
            "/api/pods?foo=1",
            "/api/pods#frag",
            "/api/pods;param=1",
        ):
            raw_wp = {
                "denied_paths": [],
                "allow_rules": [{"methods": ["GET"], "path_patterns": [bad_pat], "body_policy": "none"}],
            }
            with self.subTest(bad_pat=bad_pat), self.assertRaises((SchemaError, PolicyError)):
                validate_wire_policy(raw_wp, "bad_wp")

        bad_method_wp = {
            "denied_paths": [],
            "allow_rules": [{"methods": ["CONNECT"], "path_patterns": ["/"], "body_policy": "none"}],
        }
        with self.assertRaises(SchemaError):
            validate_wire_policy(bad_method_wp, "bad_method")

        bad_body_wp = {
            "denied_paths": [],
            "allow_rules": [{"methods": ["POST"], "path_patterns": ["/"], "body_policy": "raw-passthrough"}],
        }
        with self.assertRaises(SchemaError):
            validate_wire_policy(bad_body_wp, "bad_body")

    def test_inbound_auth_and_allowed_cidrs_validation(self) -> None:
        ok_cidr = _cidr(10, 20, 0, 0, 16)
        cgnat_cidr = _cidr(100, 64, 1, 0, 24)
        ok_toml = _bundle_toml(
            "team/ok-broker",
            f'[broker_services.sonar]\nkind = "http"\n'
            f'upstream_url = "https://sonar.corp.example.com"\n'
            f'inbound_auth = "header"\ninbound_auth_header = "X-Sonar-Job"\n'
            f'allow_streaming = false\n'
            f'allowed_cidrs = ["{ok_cidr}", "{cgnat_cidr}"]\n'
            f'read_only_secret_ref = "keeper:sonar_ro"\n'
            f'preset = "sonarqube"\nclient_env_var = "SONAR_HOST_URL"\n',
        )
        doc = validate_bundle_doc(parse_toml_strict(ok_toml), expected_id="team/ok-broker")
        self.assertEqual(doc["broker_services"]["sonar"]["inbound_auth"], "header")
        self.assertEqual(doc["broker_services"]["sonar"]["inbound_auth_header"], "X-Sonar-Job")
        self.assertEqual(doc["broker_services"]["sonar"]["allowed_cidrs"], [ok_cidr, cgnat_cidr])

        # Missing inbound_auth_header when inbound_auth = "header"
        missing_hdr = parse_toml_strict(
            _bundle_toml(
                "team/miss-hdr",
                '[broker_services.s]\nkind = "http"\nupstream_url = "https://api.example.com"\n'
                'inbound_auth = "header"\npreset = "sonarqube"\n',
            )
        )
        with self.assertRaises(SchemaError):
            validate_bundle_doc(missing_hdr, expected_id="team/miss-hdr")

        # Forbidden hop-by-hop inbound_auth_header
        bad_hdr = parse_toml_strict(
            _bundle_toml(
                "team/bad-hdr",
                '[broker_services.s]\nkind = "http"\nupstream_url = "https://api.example.com"\n'
                'inbound_auth = "header"\ninbound_auth_header = "Upgrade"\npreset = "sonarqube"\n',
            )
        )
        with self.assertRaises(PolicyError):
            validate_bundle_doc(bad_hdr, expected_id="team/bad-hdr")

        # Non-RFC1918/CGNAT CIDRs rejected
        for bad_cidr in (
            _cidr(127, 0, 0, 0, 8),
            _cidr(169, 254, 0, 0, 16),
            _cidr(8, 8, 8, 0, 24),
        ):
            bad_doc = parse_toml_strict(
                _bundle_toml(
                    "team/bad-cidr",
                    f'[broker_services.s]\nkind = "http"\nupstream_url = "https://api.example.com"\n'
                    f'allowed_cidrs = ["{bad_cidr}"]\npreset = "sonarqube"\n',
                )
            )
            with self.subTest(bad_cidr=bad_cidr), self.assertRaises(PolicyError):
                validate_bundle_doc(bad_doc, expected_id="team/bad-cidr")

    def test_broker_services_postgres_and_ssh_validation(self) -> None:
        pg_ok = parse_toml_strict(
            _bundle_toml(
                "team/pg-ok",
                '[broker_services.prod_db]\nkind = "postgres"\nhost = "pg.example.com"\n'
                'port = 5432\ndatabase = "app_prod"\nsslmode = "verify-full"\n'
                'read_only_user = "app_ro"\nread_only_secret_ref = "keeper:pg_ro_pw"\n'
                'write_user = "app_rw"\nwrite_secret_ref = "keeper:pg_rw_pw"\n',
            )
        )
        validated = validate_bundle_doc(pg_ok, expected_id="team/pg-ok")
        self.assertEqual(validated["broker_services"]["prod_db"]["sslmode"], "verify-full")

        # Reject non-verify-full sslmode
        pg_bad_ssl = parse_toml_strict(
            _bundle_toml(
                "team/pg-ssl",
                '[broker_services.prod_db]\nkind = "postgres"\nhost = "pg.example.com"\n'
                'database = "app_prod"\nsslmode = "require"\n'
                'read_only_user = "app_ro"\nread_only_secret_ref = "keeper:pg_ro_pw"\n',
            )
        )
        with self.assertRaises(PolicyError):
            validate_bundle_doc(pg_bad_ssl, expected_id="team/pg-ssl")

        # Reject shared RO/RW Postgres user
        pg_same_user = parse_toml_strict(
            _bundle_toml(
                "team/pg-same",
                '[broker_services.prod_db]\nkind = "postgres"\nhost = "pg.example.com"\n'
                'database = "app_prod"\nread_only_user = "app_same"\n'
                'read_only_secret_ref = "keeper:pg_ro_pw"\n'
                'write_user = "app_same"\nwrite_secret_ref = "keeper:pg_rw_pw"\n',
            )
        )
        with self.assertRaises(PolicyError):
            validate_bundle_doc(pg_same_user, expected_id="team/pg-same")

        # SSH rejects raw-container-mount
        ssh_raw = parse_toml_strict(
            _bundle_toml(
                "team/ssh-raw",
                '[broker_services.bastion]\nkind = "ssh"\nhost = "bastion.example.com"\n'
                'user = "ops"\nknown_hosts_ref = "file:bastion_kh"\n'
                'allowed_presets = ["journalctl", "df"]\n'
                'credential_delivery = "raw-container-mount"\n',
            )
        )
        with self.assertRaises(PolicyError):
            validate_bundle_doc(ssh_raw, expected_id="team/ssh-raw")

    def test_pinned_artifact_local_bypass_closed(self) -> None:
        # pinned-artifact with secret_env and NO explicit credential_delivery fails closed
        bypass_env = parse_toml_strict(
            _bundle_toml(
                "team/pa-env",
                '[mcp.helper]\ntype = "pinned-artifact"\nartifact_id = "builtin/helper"\n'
                'tools = ["run"]\n[mcp.helper.secret_env]\nTOKEN = "{file:/run/secrets/ext_tok}"\n',
            )
        )
        with self.assertRaises(PolicyError):
            validate_bundle_doc(bypass_env, expected_id="team/pa-env")

        # pinned-artifact with sensitive header (Cookie) and NO explicit credential_delivery fails closed
        bypass_hdr = parse_toml_strict(
            _bundle_toml(
                "team/pa-hdr",
                '[mcp.helper]\ntype = "pinned-artifact"\nartifact_id = "builtin/helper"\n'
                'tools = ["run"]\n[mcp.helper.headers]\nCookie = "{file:/run/secrets/ext_cookie}"\n',
            )
        )
        with self.assertRaises(PolicyError):
            validate_bundle_doc(bypass_hdr, expected_id="team/pa-hdr")

        # pinned-artifact with explicit local-ephemeral is allowed
        ok_ephemeral = parse_toml_strict(
            _bundle_toml(
                "team/pa-ok",
                '[mcp.helper]\ntype = "pinned-artifact"\nartifact_id = "builtin/helper"\n'
                'credential_delivery = "local-ephemeral"\ntools = ["run"]\n'
                '[mcp.helper.secret_env]\nTOKEN = "{file:/run/secrets/local_tok}"\n',
            )
        )
        validated = validate_bundle_doc(ok_ephemeral, expected_id="team/pa-ok")
        self.assertEqual(validated["mcp"]["helper"]["credential_delivery"], "local-ephemeral")

        # pinned-artifact with raw-container-mount is rejected for orchestrator proposals
        raw_pa = parse_toml_strict(
            _bundle_toml(
                "team/pa-raw",
                '[mcp.helper]\ntype = "pinned-artifact"\nartifact_id = "builtin/helper"\n'
                'credential_delivery = "raw-container-mount"\ntools = ["run"]\n'
                '[mcp.helper.secret_env]\nTOKEN = "{file:/run/secrets/ext_tok}"\n',
            )
        )
        with self.assertRaises(PolicyError):
            validate_bundle_doc(raw_pa, expected_id="team/pa-raw", for_orchestrator=True)


class TestPlanBrokerSplitAndGates(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="oc-l1-plan-")
        self.cfg_dir = Path(self.tmp.name) / "cfg"
        self.store = HostConfigStore(self.cfg_dir)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_only_one_postgres_route_can_use_the_broker_listener(self) -> None:
        def pg(name: str, delivery: str) -> str:
            return (
                f'[broker_services.{name}]\nkind = "postgres"\nhost = "{name}.example.com"\n'
                f'database = "{name}"\nread_only_user = "reporting"\n'
                f'read_only_secret_ref = "keeper:{name}"\ncredential_delivery = "{delivery}"\n'
            )

        self.store.operator_direct_upsert(
            "sandbox-type", "team/interactive-pg",
            _sandbox_type_toml("team/interactive-pg"),
        )
        for second in ("host-brokered", "raw-container-mount"):
            with self.subTest(second=second):
                self.store.operator_direct_upsert(
                    "bundle", "team/pg-pair",
                    _bundle_toml("team/pg-pair", pg("primary", "host-brokered") + pg("secondary", second)),
                )
                options = PlanOverrides(
                    with_mods=("team/pg-pair",),
                    allow_raw_remote_mounts=frozenset({"pg:secondary"}) if second != "host-brokered" else frozenset(),
                )
                if second == "host-brokered":
                    with self.assertRaisesRegex(PlanError, "only one host-brokered Postgres route"):
                        compile_plan(self.store, "team/interactive-pg", overrides=options)
                else:
                    result = compile_plan(self.store, "team/interactive-pg", overrides=options)
                    self.assertEqual(
                        result.plan["broker_routes"]["pg:secondary"]["credential_delivery"], second
                    )

    def test_host_brokered_split_linux_vs_macos_and_broker_client_env(self) -> None:
        self.store.operator_direct_upsert(
            "bundle",
            "team/ext-stack",
            _bundle_toml(
                "team/ext-stack",
                '[broker_services.k8s]\nkind = "http"\n'
                'upstream_url = "https://k8s.staging.example.com"\n'
                'read_only_secret_ref = "keeper:k8s_ro"\npreset = "k8s"\n'
                'client_env_var = "K8S_PROXY_URL"\n'
                '[broker_services.rds]\nkind = "postgres"\nhost = "rds.staging.example.com"\n'
                'port = 5432\ndatabase = "orders"\nsslmode = "verify-full"\n'
                'read_only_user = "orders_ro"\nread_only_secret_ref = "keeper:rds_ro"\n'
                '[broker_services.ops_ssh]\nkind = "ssh"\nhost = "ops.staging.example.com"\n'
                'user = "readonly"\nknown_hosts_ref = "file:ops_known_hosts"\n'
                'allowed_presets = ["journalctl", "df"]\n',
            ),
        )
        linux_res = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(
                with_mods=("team/ext-stack",),
                env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
            ),
        )
        plan = linux_res.plan
        self.assertEqual(
            set(plan["broker_routes"].keys()),
            {"mcp:api_client", "http:k8s", "pg:rds", "ssh:ops_ssh"},
        )
        # Container-visible MCP config has zero real external secret slots
        mcp_cfg = plan["role_contract"]["opencode_config"]["mcp"]["api_client"]
        self.assertEqual(mcp_cfg["url"], f"http://127.0.0.1:{DEFAULT_BROKER_HTTP_PORT}/mcp/api_client")
        self.assertEqual(mcp_cfg["headers"], {"Authorization": "Bearer {file:/run/secrets/oc_broker_token}"})
        self.assertEqual(mcp_cfg["secret_env"], {})
        self.assertEqual(mcp_cfg["credential_delivery"], "host-brokered")

        # Container-visible broker_client_env references only disposable proxy URLs/tokens
        client_env = plan["broker_client_env"]
        self.assertEqual(
            client_env["K8S_PROXY_URL"],
            f"http://127.0.0.1:{DEFAULT_BROKER_HTTP_PORT}/http/k8s",
        )
        self.assertEqual(
            client_env["OC_BROKER_PG_RDS_URL"],
            f"postgresql://ocjob:{{file:/run/secrets/oc_broker_token}}@127.0.0.1:{DEFAULT_BROKER_PG_PORT}/orders?sslmode=disable",
        )
        serialized_env = json.dumps(client_env)
        self.assertNotIn("keeper:", serialized_env)
        self.assertNotIn("rds.staging.example.com", serialized_env)
        self.assertNotIn("orders_ro", serialized_env)

        # macOS worker (podman-macos-vm + ssh-pinned) rewrites broker host to host.containers.internal
        mac_res = compile_plan(
            self.store,
            "builtin/api-workbench",
            worker_id="builtin/example-macos-arm64",
            overrides=PlanOverrides(
                with_mods=("team/ext-stack",),
                env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
            ),
        )
        mac_scheme = "http"
        self.assertEqual(
            mac_res.plan["role_contract"]["opencode_config"]["mcp"]["api_client"]["url"],
            f"{mac_scheme}://host.containers.internal:{DEFAULT_BROKER_HTTP_PORT}/mcp/api_client",
        )
        self.assertEqual(
            mac_res.plan["broker_client_env"]["K8S_PROXY_URL"],
            f"{mac_scheme}://host.containers.internal:{DEFAULT_BROKER_HTTP_PORT}/http/k8s",
        )
        self.assertIn(
            f"@host.containers.internal:{DEFAULT_BROKER_PG_PORT}/orders",
            mac_res.plan["broker_client_env"]["OC_BROKER_PG_RDS_URL"],
        )

    def test_transport_and_topology_gates_fail_closed(self) -> None:
        # cloud-https lacks open_reverse_channel -> refuses host-brokered remote MCP
        with self.assertRaisesRegex(PolicyError, "open_reverse_channel"):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                worker_id="builtin/example-render-cloud",
                overrides=PlanOverrides(env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"}),
            )

        # managed tier + pod-shared topology -> refuses host-brokered routes
        self.store.operator_direct_upsert(
            "sandbox-type",
            "team/managed-shared",
            _sandbox_type_toml("team/managed-shared", tier="managed", topology="pod-shared"),
        )
        with self.assertRaisesRegex(PolicyError, "isolated-sidecars"):
            compile_plan(
                self.store,
                "team/managed-shared",
                overrides=PlanOverrides(env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"}),
            )

    def test_exact_breakglass_binding_and_managed_tier_prohibition(self) -> None:
        self.store.operator_direct_upsert(
            "bundle",
            "team/raw-mcp",
            _bundle_toml(
                "team/raw-mcp",
                '[mcp.ext_raw]\ntype = "remote"\nurl = "https://raw.example.com/mcp"\n'
                'credential_delivery = "raw-container-mount"\n'
                'read_only_tools = ["get_item"]\n'
                '[mcp.ext_raw.remote.read_only_headers]\n'
                'Authorization = "Bearer {file:/run/secrets/ext_raw_ro}"\n',
            ),
        )
        self.store.operator_direct_upsert(
            "sandbox-type",
            "team/interactive-dev",
            _sandbox_type_toml(
                "team/interactive-dev",
                tier="interactive",
                topology="pod-shared",
                bundles='["team/raw-mcp", "builtin/persona-implementer"]',
            ),
        )
        self.store.operator_direct_upsert(
            "sandbox-type",
            "team/managed-raw",
            _sandbox_type_toml(
                "team/managed-raw",
                tier="managed",
                topology="isolated-sidecars",
                bundles='["team/raw-mcp", "builtin/persona-implementer"]',
            ),
        )

        # Blanket bool is rejected
        ov_bool = PlanOverrides(allow_raw_remote_mounts=True)  # type: ignore[arg-type]
        with self.assertRaises(PolicyError):
            compile_plan(self.store, "team/interactive-dev", overrides=ov_bool)

        # Permanently forbidden in managed tier even with explicit route ID
        ov_managed = PlanOverrides(allow_raw_remote_mounts=frozenset({"mcp:ext_raw"}))
        with self.assertRaisesRegex(PolicyError, "managed"):
            compile_plan(self.store, "team/managed-raw", overrides=ov_managed)

        # Interactive tier without explicit grant fails closed
        with self.assertRaisesRegex(PolicyError, "allow_raw_remote_mounts"):
            compile_plan(self.store, "team/interactive-dev")

        # Unknown / inactive route ID in allow_raw_remote_mounts fails closed
        ov_ghost = PlanOverrides(allow_raw_remote_mounts=frozenset({"mcp:ext_raw", "mcp:ghost"}))
        with self.assertRaisesRegex(PolicyError, "unknown, inactive"):
            compile_plan(self.store, "team/interactive-dev", overrides=ov_ghost)

        # Interactive tier with exact grant succeeds and emits raw_remote_secret_mounted
        res = compile_plan(
            self.store,
            "team/interactive-dev",
            overrides=PlanOverrides(allow_raw_remote_mounts=frozenset({"mcp:ext_raw"})),
        )
        self.assertEqual(res.plan["raw_remote_mounts"], ["mcp:ext_raw"])
        ext_mcp = res.plan["role_contract"]["opencode_config"]["mcp"]["ext_raw"]
        self.assertEqual(ext_mcp["credential_delivery"], "raw-container-mount")
        self.assertEqual(ext_mcp["url"], "https://raw.example.com/mcp")
        self.assertEqual(ext_mcp["headers"]["Authorization"], "Bearer {file:/run/secrets/ext_raw_ro}")

        delta = compute_closed_security_delta({}, {"team/interactive-dev": res})
        self.assertIn("raw_remote_secret_mounted", delta["triggers"])

    def test_security_delta_detects_all_broker_route_widenings(self) -> None:
        base_cidr = _cidr(10, 20, 1, 0, 24)
        wide_cidr = _cidr(10, 20, 0, 0, 16)
        self.store.operator_direct_upsert(
            "bundle",
            "team/b-k8s",
            _bundle_toml(
                "team/b-k8s",
                f'[broker_services.k8s]\nkind = "http"\n'
                f'upstream_url = "https://k8s.example.com"\n'
                f'allowed_cidrs = ["{base_cidr}"]\n'
                f'read_only_secret_ref = "keeper:k8s_ro"\npreset = "k8s"\n',
            ),
        )
        base_res = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(
                with_mods=("team/b-k8s",),
                env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
            ),
        )

        cases = [
            ("allow_streaming_enabled", lambda p: p["broker_routes"]["http:k8s"].__setitem__("allow_streaming", True), "mcp_tool_surface_widened"),
            ("denied_path_removed", lambda p: p["broker_routes"]["http:k8s"]["wire_policy"]["denied_paths"].pop(), "mcp_tool_surface_widened"),
            ("allow_rule_added", lambda p: p["broker_routes"]["http:k8s"]["wire_policy"]["allow_rules"].append({"methods": ["POST"], "path_patterns": ["/api/v1/pods"], "body_policy": "none"}), "mcp_tool_surface_widened"),
            ("allowed_cidrs_widened", lambda p: p["broker_routes"]["http:k8s"].__setitem__("allowed_cidrs", [wide_cidr]), "remote_endpoint_added"),
            ("upstream_changed", lambda p: p["broker_routes"]["http:k8s"].__setitem__("upstream", "https://other.example.com"), "remote_endpoint_added"),
            ("downgraded_to_raw", lambda p: p["broker_routes"]["http:k8s"].__setitem__("credential_delivery", "raw-container-mount"), "raw_remote_secret_mounted"),
        ]
        for label, mutator, expected_trigger in cases:
            mut_plan = json.loads(json.dumps(base_res.plan))
            mutator(mut_plan)
            delta = compute_closed_security_delta(
                {"builtin/api-workbench": base_res},
                {"builtin/api-workbench": _FakeCompiled(mut_plan)},  # type: ignore[dict-item]
            )
            with self.subTest(case=label):
                self.assertIn(expected_trigger, delta["triggers"])

    def test_redaction_strips_broker_secrets_cidrs_and_private_upstreams(self) -> None:
        priv_cidr = _cidr(10, 42, 0, 0, 16)
        self.store.operator_direct_upsert(
            "bundle",
            "team/secret-stack",
            _bundle_toml(
                "team/secret-stack",
                f'[broker_services.rds]\nkind = "postgres"\nhost = "rds-internal.corp.example.com"\n'
                f'port = 5432\ndatabase = "ledger"\nsslmode = "verify-full"\n'
                f'allowed_cidrs = ["{priv_cidr}"]\n'
                f'read_only_user = "ledger_ro_priv"\nread_only_secret_ref = "keeper:vault_rds_secret_99"\n'
                f'[broker_services.bastion]\nkind = "ssh"\nhost = "bastion-priv.corp.example.com"\n'
                f'user = "secops_priv"\nknown_hosts_ref = "file:bastion_kh_secret"\n'
                f'allowed_presets = ["journalctl"]\n',
            ),
        )
        res = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(
                with_mods=("team/secret-stack",),
                env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
            ),
        )
        summary = redact_plan_summary(res)
        self.assertEqual(summary["broker_routes"]["pg:rds"]["credential_delivery"], "host-brokered")
        self.assertEqual(summary["broker_routes"]["pg:rds"]["access_mode"], "ro")
        self.assertEqual(summary["broker_routes"]["ssh:bastion"]["kind"], "ssh")

        summary_json = json.dumps(summary)
        for leaked in (
            "keeper:vault_rds_secret_99",
            "rds-internal.corp.example.com",
            "ledger_ro_priv",
            "bastion-priv.corp.example.com",
            "secops_priv",
            "file:bastion_kh_secret",
            priv_cidr,
            "api_remote_ro_token",
        ):
            self.assertNotIn(leaked, summary_json)

    def test_orchestrator_mcp_blocks_raw_remote_mounts_in_preview_and_redacts_bundle(self) -> None:
        sock_dir = Path(self.tmp.name) / "sock"
        srv = OrchestratorConfigMcpServer(self.store, sock_dir)
        sock_path = srv.start()
        try:
            # plan_preview rejects allow_raw_remote_mounts override key
            resp = call_mcp_uds(
                sock_path,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "auth_token": srv.session_token,
                    "method": "plan_preview",
                    "params": {
                        "sandbox_type": "builtin/api-workbench",
                        "overrides": {"allow_raw_remote_mounts": ["mcp:api_client"]},
                    },
                },
            )
            self.assertIn("error", resp)
            self.assertIn("allow_raw_remote_mounts", resp["error"]["message"])

            # config_schema includes raw_remote_secret_mounted
            schema_resp = call_mcp_uds(
                sock_path,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "auth_token": srv.session_token,
                    "method": "config_schema",
                    "params": {},
                },
            )
            self.assertIn("raw_remote_secret_mounted", schema_resp["result"]["security_delta_triggers"])

            # config_get on bundle redacts broker_services secret_ref & allowed_cidrs
            priv_cidr = _cidr(10, 55, 0, 0, 16)
            self.store.operator_direct_upsert(
                "bundle",
                "team/redacted-b",
                _bundle_toml(
                    "team/redacted-b",
                    f'[broker_services.pg]\nkind = "postgres"\nhost = "pg-priv.example.com"\n'
                    f'database = "db1"\nallowed_cidrs = ["{priv_cidr}"]\n'
                    f'read_only_user = "priv_ro"\nread_only_secret_ref = "keeper:secret_pg_ref"\n',
                ),
            )
            get_resp = call_mcp_uds(
                sock_path,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "auth_token": srv.session_token,
                    "method": "config_get",
                    "params": {"kind": "bundle", "id": "team/redacted-b"},
                },
            )
            body = json.dumps(get_resp["result"])
            self.assertNotIn("keeper:secret_pg_ref", body)
            self.assertNotIn("pg-priv.example.com", body)
            self.assertNotIn(priv_cidr, body)
        finally:
            srv.stop()

    def test_review_regressions_p1_p2_p3(self) -> None:
        # P1-1: pinned-artifact cannot declare [local] or [remote] subtables
        pa_local = parse_toml_strict(
            _bundle_toml(
                "team/pa-local",
                '[mcp.sneaky]\ntype = "pinned-artifact"\nartifact_id = "builtin/helper"\ntools = ["run"]\n'
                '[mcp.sneaky.local]\nbinding_key = "EXT_EP"\nservice = "builtin/api-demo"\n'
                'url = "http://127.0.0.1:8080/mcp"\n'
                '[mcp.sneaky.local.secret_env]\nEXT_TOKEN = "{file:/run/secrets/prod_secret}"\n',
            )
        )
        with self.assertRaises(PolicyError):
            validate_bundle_doc(pa_local, expected_id="team/pa-local", for_orchestrator=True)

        # P1-2: unvalidated header names (trailing space/tab) and CRLF in header values rejected
        for bad_hdr_line, exc_cls in (
            ('"Authorization " = "Bearer plaintext-jwt"', SchemaError),
            ('"Cookie\\t" = "session=secret"', SchemaError),
            ('"X-Custom" = "ok\\r\\nX-Injected: evil"', PolicyError),
        ):
            doc = parse_toml_strict(
                _bundle_toml(
                    "team/bad-hdr-name",
                    f'[mcp.s]\ntype = "remote"\nurl = "http://127.0.0.1:8080/mcp"\ntools = ["r"]\n'
                    f'[mcp.s.headers]\n{bad_hdr_line}\n',
                )
            )
            with self.subTest(line=bad_hdr_line), self.assertRaises(exc_cls):
                validate_bundle_doc(doc, expected_id="team/bad-hdr-name")

        # P2-5 & P2-6: uppercase HTTP://127.0.0.1, host-brokered or raw-container-mount on pod-local URL rejected
        for snippet in (
            'url = "HTTP://127.0.0.1:8080/mcp"\ntools = ["r"]',
            'url = "http://127.0.0.1:8080/mcp"\ncredential_delivery = "host-brokered"\ntools = ["r"]',
            'url = "http://127.0.0.1:8080/mcp"\ncredential_delivery = "raw-container-mount"\ntools = ["r"]',
        ):
            doc = parse_toml_strict(_bundle_toml("team/pod-local-bad", f'[mcp.loc]\ntype = "remote"\n{snippet}\n'))
            with self.subTest(snippet=snippet), self.assertRaises(PolicyError):
                validate_bundle_doc(doc, expected_id="team/pod-local-bad")

        # P2-6 (plan-time): conditional [local] MCP running locally rejects raw-container-mount even with grant
        self.store.operator_direct_upsert(
            "bundle",
            "team/cond-raw",
            _bundle_toml(
                "team/cond-raw",
                '[mcp.cond]\ntype = "remote"\nurl = "http://127.0.0.1:8080/mcp"\n'
                'credential_delivery = "raw-container-mount"\nread_only_tools = ["r"]\n'
                '[mcp.cond.local]\nbinding_key = "COND_EP"\nservice = "builtin/api-demo"\n'
                'url = "http://127.0.0.1:8080/mcp"\n',
            ),
        )
        self.store.operator_direct_upsert(
            "sandbox-type",
            "team/int-cond",
            _sandbox_type_toml(
                "team/int-cond",
                tier="interactive",
                topology="pod-shared",
                bundles='["team/cond-raw", "builtin/persona-implementer"]',
            ),
        )
        ov_cond = PlanOverrides(allow_raw_remote_mounts=frozenset({"mcp:cond"}))
        with self.assertRaisesRegex(PolicyError, "Pod-local MCP"):
            compile_plan(self.store, "team/int-cond", overrides=ov_cond)

        # P2-7: NAT64 IPv6 (64:ff9b::/96) rejected at schema time
        nat64_doc = parse_toml_strict(
            _bundle_toml(
                "team/nat64",
                '[broker_services.s]\nkind = "http"\nupstream_url = "https://[64:ff9b::a9fe:a9fe]/api"\n'
                'preset = "sonarqube"\n',
            )
        )
        with self.assertRaises(PolicyError):
            validate_bundle_doc(nat64_doc, expected_id="team/nat64")

        # P3-9: remote MCP rejects non-bearer inbound_auth
        non_bearer_mcp = parse_toml_strict(
            _bundle_toml(
                "team/mcp-auth",
                '[mcp.m]\ntype = "remote"\nurl = "https://api.example.com/mcp"\n'
                'inbound_auth = "basic-token"\nread_only_tools = ["r"]\n',
            )
        )
        with self.assertRaises(SchemaError):
            validate_bundle_doc(non_bearer_mcp, expected_id="team/mcp-auth")

    def test_review_regressions_delta_redaction_and_env_collision(self) -> None:
        # P1-3: security_delta detects known_hosts_ref, inbound_auth, and upstream_headers mutations
        self.store.operator_direct_upsert(
            "bundle",
            "team/delta-ext",
            _bundle_toml(
                "team/delta-ext",
                '[broker_services.ops]\nkind = "ssh"\nhost = "ops.example.com"\n'
                'user = "ro"\nknown_hosts_ref = "file:kh_v1"\nallowed_presets = ["df"]\n'
                '[broker_services.sonar]\nkind = "http"\nupstream_url = "https://sonar.example.com"\n'
                'inbound_auth = "bearer"\npreset = "sonarqube"\n',
            ),
        )
        base = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(
                with_mods=("team/delta-ext",),
                env_bindings={"API_ENDPOINT": "https://staging.example.com/mcp"},
            ),
        )
        for label, mutator, expected in (
            ("known_hosts_swap", lambda p: p["broker_routes"]["ssh:ops"].__setitem__("known_hosts_ref", "file:kh_evil"), "auth_requirement_changed"),
            ("inbound_auth_change", lambda p: p["broker_routes"]["http:sonar"].__setitem__("inbound_auth", "basic-token"), "auth_requirement_changed"),
            ("upstream_header_mutation", lambda p: p["broker_routes"]["mcp:api_client"]["upstream_headers"].__setitem__("X-Admin-Bypass", "true"), "mcp_tool_surface_widened"),
        ):
            mut_plan = json.loads(json.dumps(base.plan))
            mutator(mut_plan)
            delta = compute_closed_security_delta(
                {"builtin/api-workbench": base},
                {"builtin/api-workbench": _FakeCompiled(mut_plan)},  # type: ignore[dict-item]
            )
            with self.subTest(case=label):
                self.assertIn(expected, delta["triggers"])

        # P3-8: broker_client_env collision raises PlanError
        self.store.operator_direct_upsert(
            "bundle",
            "team/env-collide",
            _bundle_toml(
                "team/env-collide",
                '[broker_services.foo-bar]\nkind = "http"\nupstream_url = "https://a.example.com"\npreset = "sonarqube"\n'
                '[broker_services.foo_bar]\nkind = "http"\nupstream_url = "https://b.example.com"\npreset = "sonarqube"\n',
            ),
        )
        with self.assertRaisesRegex(PlanError, "Conflicting broker_client_env"):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(with_mods=("team/env-collide",)),
            )

        # P2-4: orchestrator config_get & config_diff redact mcp.allowed_cidrs and private https:// URLs
        priv_cidr = _cidr(10, 42, 0, 0, 16)
        priv_ip = _ip(10, 42, 1, 5)
        self.store.operator_direct_upsert(
            "bundle",
            "team/priv-mcp",
            _bundle_toml(
                "team/priv-mcp",
                f'[mcp.priv]\ntype = "remote"\nurl = "https://{priv_ip}:8443/mcp"\n'
                f'allowed_cidrs = ["{priv_cidr}"]\nread_only_tools = ["r"]\n',
            ),
        )
        sock_dir = Path(self.tmp.name) / "sock-p24"
        srv = OrchestratorConfigMcpServer(self.store, sock_dir)
        sock_path = srv.start()
        try:
            get_resp = call_mcp_uds(
                sock_path,
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "auth_token": srv.session_token,
                    "method": "config_get",
                    "params": {"kind": "bundle", "id": "team/priv-mcp"},
                },
            )
            body = json.dumps(get_resp["result"])
            self.assertNotIn(priv_cidr, body)
            self.assertNotIn(priv_ip, body)
        finally:
            srv.stop()

    def test_gate2_r1_local_ephemeral_slots_forbidden_env_delta_and_local_cidrs(self) -> None:
        # P1-3: pinned-artifact local-ephemeral MCP referencing an unbacked secret slot fails closed
        self.store.operator_direct_upsert(
            "bundle",
            "team/unbacked-pinned",
            _bundle_toml(
                "team/unbacked-pinned",
                '[mcp.sneaky]\ntype = "pinned-artifact"\nartifact_id = "builtin/mcp-demo"\n'
                'credential_delivery = "local-ephemeral"\ntools = ["read_only"]\n'
                '[mcp.sneaky.secret_env]\nSTAGING_KEY = "{file:/run/secrets/unbacked_staging_secret}"\n',
            ),
        )
        with self.assertRaisesRegex(PolicyError, "not backed by any active local pod service"):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(with_mods=("team/unbacked-pinned",)),
            )

        # Backed local-ephemeral slot (pg_password from active builtin/postgres) succeeds
        self.store.operator_direct_upsert(
            "bundle",
            "team/backed-pinned",
            _bundle_toml(
                "team/backed-pinned",
                '[mcp.pg_helper]\ntype = "pinned-artifact"\nartifact_id = "builtin/mcp-demo"\n'
                'credential_delivery = "local-ephemeral"\ntools = ["read_only"]\n'
                '[mcp.pg_helper.secret_env]\nLOCAL_PG_PW = "{file:/run/secrets/pg_password}"\n',
            ),
        )
        ok_pinned = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(with_mods=("team/backed-pinned",)),
        )
        self.assertIn("pg_helper", ok_pinned.plan["role_contract"]["opencode_config"]["mcp"])

        # P2-1: Proxy/CA/Kubeconfig/AWS env vars rejected by FORBIDDEN_ENV_EXACT
        for bad_var in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "CURL_CA_BUNDLE",
            "REQUESTS_CA_BUNDLE",
            "KUBECONFIG",
            "AWS_CONFIG_FILE",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_PROFILE",
        ):
            raw = _bundle_toml(
                "team/bad-env",
                f'[broker_services.sonar]\nkind = "http"\nupstream_url = "https://sonar.example.com"\n'
                f'preset = "sonarqube"\nclient_env_var = "{bad_var}"\n',
            )
            with self.subTest(bad_var=bad_var), self.assertRaises(PolicyError):
                validate_bundle_doc(parse_toml_strict(raw))

        # P2-1: security_delta detects broker_client_env changes AND secret_ref removal/change
        class _FakeCompiled:
            def __init__(self, plan: dict[str, object]) -> None:
                self.plan = plan

        self.store.operator_direct_upsert(
            "bundle",
            "team/delta-p21",
            _bundle_toml(
                "team/delta-p21",
                '[broker_services.sonar]\nkind = "http"\nupstream_url = "https://sonar.example.com"\n'
                'preset = "sonarqube"\nread_only_secret_ref = "vault:sonar_ro"\n',
            ),
        )
        base = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(with_mods=("team/delta-p21",)),
        )
        for label, mutator, expected in (
            (
                "secret_ref_removed",
                lambda p: p["broker_routes"]["http:sonar"].pop("secret_ref", None),
                "auth_requirement_changed",
            ),
            (
                "broker_client_env_changed",
                lambda p: p["broker_client_env"].__setitem__("SONAR_HOST_URL", "http://127.0.0.1:18080/http/evil"),
                "remote_endpoint_added",
            ),
        ):
            mut_plan = json.loads(json.dumps(base.plan))
            mutator(mut_plan)
            delta = compute_closed_security_delta(
                {"builtin/api-workbench": base},
                {"builtin/api-workbench": _FakeCompiled(mut_plan)},  # type: ignore[dict-item]
            )
            with self.subTest(case=label):
                self.assertIn(expected, delta["triggers"])

        # P3-4: [local] MCP declaring allowed_cidrs can bind private IP via env_bindings & write grant
        priv_cidr = _cidr(10, 55, 0, 0, 16)
        priv_ip = _ip(10, 55, 1, 9)
        outside_ip = _ip(10, 99, 1, 9)
        self.store.operator_direct_upsert(
            "bundle",
            "team/local-cidr-mcp",
            _bundle_toml(
                "team/local-cidr-mcp",
                f'[mcp.corp_api]\ntype = "remote"\nurl = "http://127.0.0.1:8080/mcp"\n'
                f'allowed_cidrs = ["{priv_cidr}"]\nread_only_tools = ["q"]\nwrite_tools = ["w"]\n'
                f'[mcp.corp_api.local]\nbinding_key = "CORP_ENDPOINT"\nservice = "builtin/api-demo"\n'
                f'url = "http://127.0.0.1:8080/mcp"\n'
                f'[mcp.corp_api.remote.read_only_headers]\nAuthorization = "Bearer {{file:/run/secrets/corp_ro}}"\n'
                f'[mcp.corp_api.remote.write_headers]\nAuthorization = "Bearer {{file:/run/secrets/corp_rw}}"\n',
            ),
        )
        ok_priv = compile_plan(
            self.store,
            "builtin/api-workbench",
            overrides=PlanOverrides(
                with_mods=("team/local-cidr-mcp",),
                env_bindings={"CORP_ENDPOINT": f"https://{priv_ip}:8443/mcp"},
                remote_write_grants={"corp_api": f"https://{priv_ip}:8443/mcp"},
            ),
        )
        self.assertEqual(
            ok_priv.plan["broker_routes"]["mcp:corp_api"]["upstream"],
            f"https://{priv_ip}:8443/mcp",
        )
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "builtin/api-workbench",
                overrides=PlanOverrides(
                    with_mods=("team/local-cidr-mcp",),
                    env_bindings={"CORP_ENDPOINT": f"https://{outside_ip}:8443/mcp"},
                ),
            )


if __name__ == "__main__":
    unittest.main()
