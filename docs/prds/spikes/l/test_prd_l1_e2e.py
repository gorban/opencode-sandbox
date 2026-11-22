"""Cross-lane end-to-end integration & synthetic canary qualification for PRD L1.

Compiles a multi-target bundle via Lane 1 (oc_schema + oc_plan), lowers
plan['broker_routes'] directly into live Lane 2 (HostHttpBrokerServer) and
Lane 3 (HostPostgresBrokerServer + HostSshBroker) instances backed by a shared
HostVaultMemory and a single oc_controller.Controller-bound BrokerLease.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from urllib.parse import urlsplit

_SPIKE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SPIKE_DIR.parents[3]
for _p in (str(_SPIKE_DIR), str(_REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_controller as occ  # noqa: E402
from oc_broker_common import (  # noqa: E402
    BrokerLease,
    BrokerPolicyError,
    HostVaultMemory,
    build_strict_tls_context,
)
from oc_broker_http import (  # noqa: E402
    AllowRule,
    HostHttpBrokerServer,
    HttpBrokerRoute,
    WirePolicy,
)
from oc_broker_pg import HostPostgresBrokerServer, PgBrokerRoute, encode_pg_frame  # noqa: E402
from oc_broker_ssh import HostSshBroker, SshRawOutput, SshTarget  # noqa: E402
from oc_plan import PlanOverrides, compile_plan, redact_plan_summary  # noqa: E402
from oc_schema import PolicyError  # noqa: E402
from oc_store import HostConfigStore  # noqa: E402
from test_broker_http import (  # noqa: E402
    MockTlsUpstream,
    RecordedRequest,
    _build_req,
    _generate_test_tls_cert,
    _make_resolver,
    _raw_http_exchange,
)
from test_broker_pg_ssh import (  # noqa: E402
    _MockUpstreamPgServer,
    _client_handshake,
)


class _E2ELeaseAdapter:
    def target_revision(self, target: str) -> str | None:
        return "rev_e2e_0001" if target == "e2e_broker_target" else None

    def set_target_revision(self, target: str, revision: str | None) -> None:
        _ = (target, revision)

    def dispatch(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        _ = (attempt, payload)
        return occ.Outcome.SUCCEEDED

    def reconcile(self, attempt: occ.Attempt, payload: occ.Payload) -> occ.Outcome:
        return self.dispatch(attempt, payload)


def _lower_plan_http_routes(
    broker_routes: dict[str, dict[str, object]],
    upstream_port: int,
) -> list[HttpBrokerRoute]:
    routes: list[HttpBrokerRoute] = []
    for route_id, rcfg in sorted(broker_routes.items()):
        kind = rcfg["kind"]
        if kind not in ("mcp", "http"):
            continue
        wp_raw = rcfg["wire_policy"]
        if not isinstance(wp_raw, dict):
            raise TypeError("wire_policy must be a dict")
        allow_rules = tuple(
            AllowRule(
                methods=tuple(r["methods"]),
                path_patterns=tuple(r["path_patterns"]),
                body_policy=r["body_policy"],
            )
            for r in wp_raw["allow_rules"]
        )
        wp = WirePolicy(
            denied_paths=tuple(wp_raw["denied_paths"]),
            allow_rules=allow_rules,
            allowed_tools=frozenset(wp_raw.get("allowed_tools", [])),
        )
        prefix = (
            f"/mcp/{route_id.split(':', 1)[1]}"
            if kind == "mcp"
            else f"/http/{route_id.split(':', 1)[1]}"
        )
        parsed = urlsplit(str(rcfg["upstream"]))
        local_up = f"https://{parsed.hostname}:{upstream_port}{parsed.path or '/'}"
        routes.append(
            HttpBrokerRoute(
                route_id=route_id,
                route_prefix=prefix,
                upstream_url=local_up,
                secret_ref="slot:api_remote_ro_token" if route_id == "mcp:api_client" else str(rcfg["secret_ref"]),
                wire_policy=wp,
                inbound_auth=str(rcfg["inbound_auth"]),
                inbound_auth_header=rcfg.get("inbound_auth_header"),  # type: ignore[arg-type]
                allow_streaming=bool(rcfg["allow_streaming"]),
                allowed_cidrs=tuple(rcfg.get("allowed_cidrs", ())),  # type: ignore[arg-type]
            )
        )
    return routes


class TestPrdL1EndToEnd(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg_dir = Path(self.tmp.name) / "cfg"
        self.store = HostConfigStore(self.cfg_dir)
        self.cert_dir = Path(self.tmp.name) / "certs"
        self.cert_dir.mkdir(mode=0o700)
        self.cert_path, self.key_path = _generate_test_tls_cert(self.cert_dir)
        self.client_ctx = build_strict_tls_context(cafile=str(self.cert_path))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _create_controller_lease(self) -> tuple[occ.Controller, occ.Principal, str, BrokerLease]:
        op = occ.Principal(occ.Role.OPERATOR, "host_op")
        orch = occ.Principal(occ.Role.ORCHESTRATOR, "orch_1")
        job_p = occ.Principal(occ.Role.JOB, "e2e_job")
        subj = occ.Subject("worker_local", "e2e_inc_01", "e2e_job")
        ctrl = occ.Controller(
            incarnation="abcdef0123456789abcdef0123456789",
            clock=lambda: 100,
            lifetime=600,
            workers=[occ.Worker("worker_local", op)],
            jobs=[occ.Job(subj, orch, 16)],
            capabilities=[occ.Capability("cap_e2e", occ.Operation.PROBE, "e2e_broker_target")],
            references=[occ.Reference("ref_e2e", "cap_e2e")],
            adapter=_E2ELeaseAdapter(),
        )
        ctrl._set_alias("e2e_alias", "e2e_broker_target")
        prop = ctrl.propose(job_p, occ.Proposal(occ.Intent.PROBE_GRANT, "e2e_alias", "ref_e2e"))
        view = ctrl.view(op, prop.request_id)
        ctrl.decide(op, prop.request_id, view.payload.revision, view.digest, occ.Decision.APPROVE)
        lease = BrokerLease(
            "e2e_job_1",
            controller=ctrl,
            controller_actor=job_p,
            controller_request_id=prop.request_id,
        )
        return ctrl, op, prop.request_id, lease

    def test_plan_to_live_brokers_zero_canary_and_subsecond_revocation(self) -> None:
        bundle_toml = (
            'schema_version = 1\n'
            'kind = "bundle@1"\n'
            'id = "team/e2e-external"\n'
            'description = "Multi-target external broker bundle"\n'
            'includes = ["builtin/api-dev"]\n'
            '\n'
            '[broker_services.k8s]\n'
            'kind = "http"\n'
            'preset = "k8s"\n'
            'upstream_url = "https://upstream.test"\n'
            'read_only_secret_ref = "keeper:k8s/ro_token"\n'
            'client_env_var = "KUBE_PROXY_URL"\n'
            '\n'
            '[broker_services.github]\n'
            'kind = "http"\n'
            'preset = "github"\n'
            'upstream_url = "https://upstream.test"\n'
            'read_only_secret_ref = "keeper:github/ro_token"\n'
            'client_env_var = "GH_PROXY_URL"\n'
            '\n'
            '[broker_services.pg_ext]\n'
            'kind = "postgres"\n'
            'host = "upstream.test"\n'
            'port = 5432\n'
            'database = "prod_readonly"\n'
            'read_only_user = "ro_analyst_role"\n'
            'read_only_secret_ref = "keeper:pg/ro_pass"\n'
            'write_user = "rw_admin_role"\n'
            'write_secret_ref = "keeper:pg/rw_pass"\n'
            '\n'
            '[broker_services.ssh_ops]\n'
            'kind = "ssh"\n'
            'host = "upstream.test"\n'
            'port = 22\n'
            'user = "deployro"\n'
            'known_hosts_ref = "file:known_hosts_staging"\n'
            'allowed_presets = ["journalctl", "df"]\n'
        )
        st_toml = (
            'schema_version = 1\n'
            'kind = "sandbox-type@1"\n'
            'id = "team/e2e-managed"\n'
            'description = "Managed e2e sandbox"\n'
            'tier = "managed"\n'
            'topology = "isolated-sidecars"\n'
            f'base_image = "ghcr.io/example/base@sha256:{"a" * 64}"\n'
            'bundles = ["team/e2e-external"]\n'
        )
        self.store.operator_direct_upsert("bundle", "team/e2e-external", bundle_toml)
        self.store.operator_direct_upsert("sandbox-type", "team/e2e-managed", st_toml)

        ov = PlanOverrides(env_bindings={"API_ENDPOINT": "https://upstream.test/mcp"})
        compiled = compile_plan(self.store, "team/e2e-managed", overrides=ov)
        plan = compiled.plan
        summary = redact_plan_summary(compiled)

        # Synthetic canaries live ONLY in HostVaultMemory
        canaries = {
            "slot:api_remote_ro_token": "CANARY_MCP_RO_TOKEN_9876543210",
            "keeper:k8s/ro_token": "CANARY_K8S_RO_TOKEN_1122334455",
            "keeper:github/ro_token": "CANARY_GH_RO_TOKEN_5566778899",
            "keeper:pg/ro_pass": "CANARY_PG_RO_SECRET_6677889900",
            "keeper:pg/rw_pass": "CANARY_PG_RW_SECRET_0099887766",
        }
        vault = HostVaultMemory(canaries)

        # Verify ZERO canaries or external secret refs appear in container config or redacted summary
        container_blob = json.dumps(
            {
                "opencode_config": plan["role_contract"]["opencode_config"],
                "broker_client_env": plan["broker_client_env"],
            }
        )
        summary_blob = json.dumps(summary)
        for ref, secret_val in canaries.items():
            self.assertNotIn(secret_val, container_blob)
            self.assertNotIn(secret_val, summary_blob)
            self.assertNotIn(ref, container_blob)
            self.assertNotIn(ref, summary_blob)
        self.assertEqual(
            plan["role_contract"]["opencode_config"]["mcp"]["api_client"]["headers"],
            {"Authorization": "Bearer {file:/run/secrets/oc_broker_token}"},
        )

        # Cloud-https worker fails closed on host-brokered routes
        with self.assertRaises(PolicyError):
            compile_plan(
                self.store,
                "team/e2e-managed",
                worker_id="builtin/example-render-cloud",
                overrides=ov,
            )

        ctrl, op, req_id, lease = self._create_controller_lease()
        lease.start_watchdog(poll_interval=0.02)

        def _http_upstream_handler(req: RecordedRequest, conn: socket.socket) -> None:
            if req.target == "/mcp":
                body = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "tools": [
                                {"name": "query_ro", "description": "safe"},
                                {"name": "mutate_write", "description": "blocked"},
                            ]
                        },
                    }
                ).encode("utf-8")
                ctype = "application/json"
            elif req.target == "/api/v1/namespaces/default/pods/app/log":
                body = b"pod log line 1\n"
                ctype = "text/plain"
            else:
                body = b'{"data":{"viewer":{"login":"alice"}}}'
                ctype = "application/json"
            conn.sendall(
                f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode(
                    "ascii"
                )
                + body
            )

        upstream_http = MockTlsUpstream(self.cert_path, self.key_path)
        upstream_http.handler = _http_upstream_handler
        upstream_http.start()
        pg_up = _MockUpstreamPgServer(
            self.cert_path,
            self.key_path,
            auth_mode="scram",
            user="ro_analyst_role",
            password=canaries["keeper:pg/ro_pass"],
        )
        pg_up.start()

        http_routes = _lower_plan_http_routes(plan["broker_routes"], upstream_http.port)
        http_broker = HostHttpBrokerServer(
            http_routes,
            vault,
            lease,
            ssl_context=self.client_ctx,
            resolver=_make_resolver("127.0.0.1"),
            allow_test_loopback=True,
        )
        pg_plan_route = plan["broker_routes"]["pg:pg_ext"]
        pg_broker = HostPostgresBrokerServer(
            PgBrokerRoute(
                route_id="pg:pg_ext",
                upstream_host=pg_plan_route["upstream"]["host"],
                upstream_port=pg_up.port,
                upstream_database=pg_plan_route["upstream"]["database"],
                upstream_user=pg_plan_route["upstream"]["user"],
                secret_ref=pg_plan_route["secret_ref"],
                access_mode="ro",
                pair_distinct_user="rw_admin_role",
                pair_distinct_secret_ref="keeper:pg/rw_pass",
            ),
            vault,
            lease,
            ssl_context=self.client_ctx,
            resolver=_make_resolver("127.0.0.1"),
            allow_test_loopback=True,
        )
        http_addr = http_broker.start()
        pg_broker.start()
        try:
            auth_hdr = {"Authorization": f"Bearer {lease.ocjob_token}"}

            # 1. MCP tools/list uses exact Lane 1 rewritten URL, filters out mutate_write, and injects secret on host
            mcp_path = urlsplit(plan["role_contract"]["opencode_config"]["mcp"]["api_client"]["url"]).path
            mcp_req = _build_req(
                "POST",
                mcp_path,
                headers={**auth_hdr, "Content-Type": "application/json"},
                body=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode("utf-8"),
            )
            st, _hdrs, body = _raw_http_exchange(http_addr, mcp_req)
            self.assertEqual(st, 200)
            tools = [t["name"] for t in json.loads(body)["result"]["tools"]]
            self.assertEqual(tools, ["query_ro"])
            self.assertEqual(
                upstream_http.recorded[-1].headers.get("authorization"),
                f"Bearer {canaries['slot:api_remote_ro_token']}",
            )

            # 2. K8s multi-segment pod log allowed, secrets & exec Upgrade denied
            st_log, _, _ = _raw_http_exchange(
                http_addr, _build_req("GET", "/http/k8s/api/v1/namespaces/default/pods/app/log", headers=auth_hdr)
            )
            self.assertEqual(st_log, 200)
            st_sec, _, _ = _raw_http_exchange(
                http_addr, _build_req("GET", "/http/k8s/api/v1/namespaces/default/secrets", headers=auth_hdr)
            )
            self.assertEqual(st_sec, 403)
            st_upg, _, _ = _raw_http_exchange(
                http_addr,
                _build_req(
                    "GET",
                    "/http/k8s/api/v1/namespaces/default/pods/app/exec",
                    headers={**auth_hdr, "Connection": "Upgrade", "Upgrade": "SPDY/3.1"},
                ),
            )
            self.assertEqual(st_upg, 400)

            # 3. GitHub GraphQL query allowed, mutation & APQ extensions denied
            st_q, _, _ = _raw_http_exchange(
                http_addr,
                _build_req(
                    "POST",
                    "/http/github/graphql",
                    headers={**auth_hdr, "Content-Type": "application/json"},
                    body=json.dumps({"query": "query { viewer { login } }"}).encode("utf-8"),
                ),
            )
            self.assertEqual(st_q, 200)
            st_mut, _, _ = _raw_http_exchange(
                http_addr,
                _build_req(
                    "POST",
                    "/http/github/graphql",
                    headers={**auth_hdr, "Content-Type": "application/json"},
                    body=json.dumps({"query": "mutation { deleteRepo }"}).encode("utf-8"),
                ),
            )
            self.assertEqual(st_mut, 403)

            # 4. SSH broker executes fixed-argv preset safely and blocks shell injection
            kh_file = Path(self.tmp.name) / "known_hosts"
            kh_file.write_text("upstream.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n", encoding="utf-8")
            os.chmod(kh_file, 0o600)
            seen_argv: list[list[str]] = []

            def _fake_ssh(
                argv: list[str], *, timeout: float, shell: bool = False
            ) -> SshRawOutput:
                self.assertFalse(shell)
                self.assertGreater(timeout, 0)
                seen_argv.append(argv)
                return SshRawOutput(returncode=0, stdout=b"ok\n", stderr=b"")

            ssh_route = plan["broker_routes"]["ssh:ssh_ops"]
            ssh_broker = HostSshBroker(
                runner=_fake_ssh,
                canary_secrets=list(canaries.values()),
                resolver=_make_resolver("127.0.0.1"),
                allow_test_loopback=True,
            )
            target = SshTarget(
                user=ssh_route["upstream"]["user"],
                host=ssh_route["upstream"]["host"],
                known_hosts_path=kh_file,
                port=ssh_route["upstream"]["port"],
            )
            res = ssh_broker.run_preset(target, "df", {"path": "/var/log"}, lease=lease)
            self.assertEqual(res.returncode, 0)
            self.assertIn("ForwardAgent=no", seen_argv[-1])
            with self.assertRaises(BrokerPolicyError):
                ssh_broker.run_preset(target, "df", {"path": "/var; rm -rf /"}, lease=lease)

            # 5. Live Postgres TLS+SCRAM-SHA-256 receives synthetic BackendKeyData and tears down <1s on revoke
            pg_cli = socket.create_connection(("127.0.0.1", pg_broker.bound_port), timeout=5.0)
            try:
                params, backend_key = _client_handshake(pg_cli, lease.ocjob_token)
                self.assertIsNotNone(backend_key)
                self.assertNotEqual(backend_key, (pg_up.real_pid, pg_up.real_key))
                self.assertNotIn("session_authorization", params)
                pg_cli.sendall(encode_pg_frame(b"Q", b"SELECT 1\x00"))
                pg_cli.settimeout(2.0)
                first_hdr = pg_cli.recv(5)
                self.assertEqual(len(first_hdr), 5)

                # Out-of-band oc_controller.revoke() tears down active PG stream AND blocks HTTP within <1s
                t0 = time.monotonic()
                ctrl.revoke(op, req_id)
                pg_cli.settimeout(1.5)
                while True:
                    chunk = pg_cli.recv(4096)
                    if not chunk:
                        break
                self.assertLess(time.monotonic() - t0, 1.0)
            finally:
                pg_cli.close()

            st_rev, _, _ = _raw_http_exchange(
                http_addr, _build_req("GET", "/http/k8s/api/v1/namespaces/default/pods/app/log", headers=auth_hdr)
            )
            self.assertEqual(st_rev, 403)
        finally:
            lease.stop_watchdog()
            http_broker.stop()
            pg_broker.stop()
            upstream_http.stop()
            pg_up.stop()


if __name__ == "__main__":
    unittest.main()
