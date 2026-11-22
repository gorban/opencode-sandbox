#!/usr/bin/env python3
"""Clean-slate CLI PoC for PRD L (plan, config, worker subcommands).

Always requires an explicit --config-dir and never reads/writes ~/.config/oc-sandbox/.
Pure Python standard library only.
"""

from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path
import sys
from typing import Any

from oc_config_mcp import call_operator_uds
from oc_plan import PlanOverrides, compile_plan
from oc_schema import (
    MAX_CONFIG_FILE_BYTES,
    READABLE_ORCHESTRATOR_KINDS,
    SchemaError,
    parse_toml_strict,
    read_regular_no_follow,
    validate_doc_by_kind,
    validate_port_request,
)
from oc_store import HostConfigStore


def _parse_kv(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise SchemaError(f"Expected KEY=VALUE, got {item!r}")
        k, v = item.split("=", 1)
        if k in out:
            raise SchemaError(f"Duplicate CLI key: {k!r}")
        out[k] = v
    return out


def _parse_port(items: list[str]) -> tuple[dict[str, Any], ...]:
    out = []
    for item in items:
        # Format: service[@instance]:endpoint[:exposure[:host_port]]
        parts = item.split(":")
        if len(parts) < 2 or len(parts) > 4:
            raise SchemaError(f"Expected service:endpoint[:exposure[:host_port]], got {item!r}")
        host_port: int | None = None
        if len(parts) == 4 and parts[3]:
            if not (parts[3].isascii() and parts[3].isdigit()):
                raise SchemaError(f"Invalid host_port in --port {item!r}")
            host_port = int(parts[3])
        entry: dict[str, Any] = {
            "service": parts[0],
            "endpoint": parts[1],
            "exposure": parts[2] if len(parts) >= 3 and parts[2] else "host-loopback",
            "host_port": host_port,
        }
        out.append(validate_port_request(entry, f"cli --port {item!r}"))
    return tuple(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oc-sandbox-poc", description="PRD L composable sandbox CLI PoC")
    parser.add_argument("--config-dir", required=True, type=Path, help="Explicit isolated config directory")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # plan
    p_plan = sub.add_parser("plan", help="Pure dry-run compilation of a sandbox type")
    p_plan.add_argument("--type", required=True, dest="sandbox_type")
    p_plan.add_argument("--host", dest="worker", default=None)
    p_plan.add_argument("--with", dest="with_mods", action="append", default=[])
    p_plan.add_argument("--without", dest="without_mods", action="append", default=[])
    p_plan.add_argument("--env-binding", action="append", default=[])
    p_plan.add_argument("--port", action="append", default=[])
    p_plan.add_argument(
        "--allow-remote-write",
        dest="remote_write_grants",
        action="append",
        default=[],
        help="Explicit remote write grant bound to exact canonical URL (MCP_NAME=URL)",
    )

    # config
    p_cfg = sub.add_parser("config", help="Host-operator config management")
    cfg_sub = p_cfg.add_subparsers(dest="cfg_cmd", required=True)

    c_list = cfg_sub.add_parser("list")
    c_list.add_argument("kind", choices=sorted(READABLE_ORCHESTRATOR_KINDS))
    c_list.add_argument("--include-archived", action="store_true")

    c_show = cfg_sub.add_parser("show")
    c_show.add_argument("kind", choices=sorted(READABLE_ORCHESTRATOR_KINDS))
    c_show.add_argument("id")

    c_val = cfg_sub.add_parser("validate")
    c_val.add_argument("kind", choices=sorted(READABLE_ORCHESTRATOR_KINDS))
    c_val.add_argument("file", type=Path)

    c_app = cfg_sub.add_parser("approve")
    c_app.add_argument("proposal_id")
    c_app.add_argument("--digest", required=True)
    c_app.add_argument("--operator-socket", type=Path, default=None)

    c_rej = cfg_sub.add_parser("reject")
    c_rej.add_argument("proposal_id")
    c_rej.add_argument("--operator-socket", type=Path, default=None)

    c_rec = cfg_sub.add_parser("reconcile")
    c_rec.add_argument("proposal_id")
    c_rec.add_argument("--operator-socket", type=Path, default=None)

    c_hist = cfg_sub.add_parser("history")
    c_hist.add_argument("kind", choices=sorted(READABLE_ORCHESTRATOR_KINDS))
    c_hist.add_argument("id")

    c_diff = cfg_sub.add_parser("diff")
    c_diff.add_argument("kind", choices=sorted(READABLE_ORCHESTRATOR_KINDS))
    c_diff.add_argument("id")
    c_diff.add_argument("from_rev", type=int)
    c_diff.add_argument("to_rev", type=int)

    c_rest = cfg_sub.add_parser("restore")
    c_rest.add_argument("kind", choices=sorted(READABLE_ORCHESTRATOR_KINDS))
    c_rest.add_argument("id")
    c_rest.add_argument("rev", type=int)

    # worker
    p_wrk = sub.add_parser("worker", help="Inspect registered workers")
    wrk_sub = p_wrk.add_subparsers(dest="wrk_cmd", required=True)
    wrk_sub.add_parser("list")
    w_show = wrk_sub.add_parser("show")
    w_show.add_argument("id")

    args = parser.parse_args(argv)

    # Operator UDS calls talk directly to the live helper incarnation and must NOT initialize
    # args.config_dir as a side effect; the helper verifies config_dir matches its live store.
    if (
        args.cmd == "config"
        and args.cfg_cmd in ("approve", "reject", "reconcile")
        and args.operator_socket is not None
    ):
        if args.cfg_cmd == "approve":
            res_op = call_operator_uds(
                args.operator_socket,
                "operator_approve",
                {"proposal_id": args.proposal_id, "digest": args.digest},
                expected_config_dir=args.config_dir,
            )
            print(json.dumps(res_op, indent=2))
            return 0
        if args.cfg_cmd == "reject":
            res_op = call_operator_uds(
                args.operator_socket,
                "operator_reject",
                {"proposal_id": args.proposal_id},
                expected_config_dir=args.config_dir,
            )
            print(json.dumps(res_op, indent=2))
            return 0
        res_op = call_operator_uds(
            args.operator_socket,
            "operator_reconcile",
            {"proposal_id": args.proposal_id},
            expected_config_dir=args.config_dir,
        )
        print(json.dumps(res_op, indent=2))
        return 0

    store = HostConfigStore(args.config_dir)

    if args.cmd == "plan":
        ov = PlanOverrides(
            with_mods=tuple(args.with_mods),
            without_mods=tuple(args.without_mods),
            env_bindings=_parse_kv(args.env_binding),
            cli_ports=_parse_port(args.port),
            remote_write_grants=_parse_kv(args.remote_write_grants),
        )
        res = compile_plan(store, args.sandbox_type, worker_id=args.worker, overrides=ov)
        print(
            json.dumps(
                {
                    "plan_digest": res.plan_digest,
                    "drift": res.drift,
                    "plan": res.plan,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.cmd == "config":
        if args.cfg_cmd == "list":
            print(json.dumps(store.list_ids(args.kind, include_archived=args.include_archived), indent=2))
            return 0
        if args.cfg_cmd == "show":
            print(json.dumps(store.get(args.kind, args.id), indent=2, sort_keys=True))
            return 0
        if args.cfg_cmd == "validate":
            raw = read_regular_no_follow(args.file, max_bytes=MAX_CONFIG_FILE_BYTES)
            doc = parse_toml_strict(raw.decode("utf-8"), context=str(args.file))
            validated = validate_doc_by_kind(args.kind, doc)
            print(json.dumps({"valid": True, "id": validated["id"]}, indent=2))
            return 0
        if args.cfg_cmd == "approve":
            new_rev = store.approve_proposal(args.proposal_id, args.digest)
            print(json.dumps({"approved": True, "revision": new_rev}, indent=2))
            return 0
        if args.cfg_cmd == "reject":
            prop = store.reject_proposal(args.proposal_id)
            print(json.dumps({"rejected": True, "status": prop["status"]}, indent=2))
            return 0
        if args.cfg_cmd == "reconcile":
            settled = store.reconcile_proposal(args.proposal_id)
            print(json.dumps({"reconciled": True, "status": settled}, indent=2))
            return 0
        if args.cfg_cmd == "history":
            print(json.dumps(store.get_history(args.kind, args.id), indent=2))
            return 0
        if args.cfg_cmd == "diff":
            a = store.get_revision_toml(args.kind, args.id, args.from_rev).splitlines(keepends=True)
            b = store.get_revision_toml(args.kind, args.id, args.to_rev).splitlines(keepends=True)
            sys.stdout.write("".join(difflib.unified_diff(a, b, fromfile=f"r{args.from_rev}", tofile=f"r{args.to_rev}")))
            return 0
        if args.cfg_cmd == "restore":
            new_rev = store.operator_restore_revision(args.kind, args.id, args.rev)
            print(json.dumps({"restored": True, "new_revision": new_rev}, indent=2))
            return 0

    if args.cmd == "worker":
        if args.wrk_cmd == "list":
            print(json.dumps(store.list_ids("worker"), indent=2))
            return 0
        if args.wrk_cmd == "show":
            print(json.dumps(store.get("worker", args.id), indent=2, sort_keys=True))
            return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
