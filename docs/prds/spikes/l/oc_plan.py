"""Pure-Python Plan Compiler for PRD L spike PoC.

Compiles host-trusted declarative TOML specs (sandbox-type, bundle, service,
host-provider, transport, worker) into an immutable Plan IR + plan_digest.
Zero side effects, zero Python factory imports during planning.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import ipaddress
from pathlib import Path
from typing import Any, Protocol

from oc_schema import (
    CAPABILITY_PROVIDES_RE,
    CAPABILITY_REQUIRES_RE,
    EXPOSURE_RANK,
    MAX_DAG_NODES,
    MAX_INSTRUCTIONS_TOTAL_BYTES,
    MAX_MISE_MANIFESTS,
    MAX_MISE_TOOLS,
    MAX_MISSION_BYTES,
    MAX_SLOT_FILE_BYTES,
    ROUTE_ID_RE,
    SIMPLE_NAME_RE,
    SLOT_TOKEN_RE,
    PolicyError,
    SchemaError,
    canonicalize_remote_url,
    capability_satisfies,
    default_mcp_wire_policy,
    extract_secret_slots,
    is_builtin_id,
    parse_mem_bytes,
    read_regular_no_follow,
    render_host_url,
    security_profile_allows_fallback,
    security_profile_elevates,
    sha256_canonical_json,
    validate_opaque_id,
    validate_port_request,
)

DEFAULT_BROKER_HTTP_PORT = 18080
DEFAULT_BROKER_PG_PORT = 15432


class PlanError(ValueError):
    """Compilation failure (cycle, diamond conflict, capability mismatch, policy denial)."""


class PlanStoreView(Protocol):
    def get(self, kind: str, obj_id: str, *, include_archived: bool = False) -> dict[str, Any]: ...
    def list_ids(self, kind: str, *, include_archived: bool = False) -> list[str]: ...
    def get_revision(self, kind: str, obj_id: str) -> int: ...
    def bundle_asset_root(self, bundle_id: str) -> Path | None: ...


@dataclass(frozen=True, slots=True)
class PlanOverrides:
    with_mods: tuple[str, ...] = ()
    without_mods: tuple[str, ...] = ()
    env_bindings: dict[str, str] = field(default_factory=dict)
    cli_ports: tuple[dict[str, Any], ...] = ()
    remote_write_grants: dict[str, str] = field(default_factory=dict)
    allow_http_remote: bool = False
    allowed_remote_hosts: frozenset[str] = frozenset()
    allow_raw_remote_mounts: frozenset[str] = frozenset()
    broker_http_port: int = DEFAULT_BROKER_HTTP_PORT
    broker_pg_port: int = DEFAULT_BROKER_PG_PORT


@dataclass(frozen=True, slots=True)
class CompiledPlanResult:
    plan: dict[str, Any]
    plan_digest: str
    drift: dict[str, Any]
    closure_digest: str


def _resolve_bundle_dag(
    store: PlanStoreView,
    root_bundles: list[str],
    with_mods: tuple[str, ...],
    without_mods: tuple[str, ...],
) -> tuple[list[dict[str, Any]], list[tuple[str, str, int]]]:
    excluded = set(without_mods)
    roots = [b for b in list(root_bundles) + list(with_mods) if b not in excluded]
    state: dict[str, int] = {}  # Visit state: 0 unvisited, 1 visiting, 2 done
    ordered: list[dict[str, Any]] = []
    closure: list[tuple[str, str, int]] = []

    def visit(bid: str, stack: list[str]) -> None:
        if bid in excluded:
            return
        st = state.get(bid, 0)
        if st == 1:
            cycle = " -> ".join(stack[stack.index(bid) :] + [bid])
            raise PlanError(f"Cycle detected in bundle includes: {cycle}")
        if st == 2:
            return
        if len(ordered) + len(stack) >= MAX_DAG_NODES:
            raise PlanError(f"Bundle DAG exceeds maximum {MAX_DAG_NODES} nodes")
        state[bid] = 1
        doc = store.get("bundle", bid)
        for inc in doc["includes"]:
            visit(inc, stack + [bid])
        state[bid] = 2
        ordered.append(doc)
        closure.append(("bundle", bid, store.get_revision("bundle", bid)))

    for b in roots:
        validate_opaque_id(b, label="bundle")
        visit(b, [])
    return ordered, closure


def _check_fallback_non_escalating(primary: dict[str, Any], fallback: dict[str, Any]) -> None:
    if not security_profile_allows_fallback(primary["security_profile"], fallback["security_profile"]):
        raise PolicyError(
            f"Fallback service {fallback['id']!r} ({fallback['security_profile']}) "
            f"cannot substitute for {primary['id']!r} ({primary['security_profile']})"
        )
    primary_eps = {ep["port"]: ep for ep in primary["endpoints"]}
    for fep in fallback["endpoints"]:
        pep = primary_eps.get(fep["port"])
        if pep is None:
            if fep["max_exposure"] != "pod-only":
                raise PolicyError(
                    f"Fallback {fallback['id']!r} adds exposed port {fep['port']} absent from {primary['id']!r}"
                )
            continue
        if EXPOSURE_RANK[fep["max_exposure"]] > EXPOSURE_RANK[pep["max_exposure"]]:
            raise PolicyError(
                f"Fallback {fallback['id']!r} widens max_exposure on port {fep['port']}"
            )
        if pep["requires_auth"] and not fep["requires_auth"]:
            raise PolicyError(
                f"Fallback {fallback['id']!r} relaxes requires_auth on port {fep['port']}"
            )


def _check_service_against_builtin_floor(svc: dict[str, Any], bsvc: dict[str, Any], cap_name: str) -> None:
    if not security_profile_allows_fallback(bsvc["security_profile"], svc["security_profile"]):
        raise PolicyError(
            f"Service {svc['id']!r} cannot provide {cap_name} with elevated security_profile "
            f"{svc['security_profile']!r} over builtin {bsvc['security_profile']!r}"
        )
    if not bsvc["endpoints"]:
        return
    builtin_max_rank = max(EXPOSURE_RANK[ep["max_exposure"]] for ep in bsvc["endpoints"])
    builtin_requires_auth = any(ep["requires_auth"] for ep in bsvc["endpoints"])
    builtin_enforcers = {ep["auth_enforcer"] for ep in bsvc["endpoints"] if ep["auth_enforcer"]}
    for ep in svc["endpoints"]:
        if EXPOSURE_RANK[ep["max_exposure"]] > builtin_max_rank:
            raise PolicyError(
                f"Service {svc['id']!r} cannot provide {cap_name} with widened max_exposure "
                f"{ep['max_exposure']!r} on port {ep['port']}"
            )
        if builtin_requires_auth and not ep["requires_auth"]:
            raise PolicyError(
                f"Service {svc['id']!r} cannot provide {cap_name} with weakened requires_auth on port {ep['port']}"
            )
        if builtin_enforcers and ep["auth_enforcer"] not in builtin_enforcers:
            raise PolicyError(
                f"Service {svc['id']!r} cannot replace builtin auth_enforcer on port {ep['port']}"
            )


def _provided_capability_names(svc: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for cap in svc["provides"]:
        cm = CAPABILITY_PROVIDES_RE.fullmatch(cap)
        if cm:
            names.add(cm.group(1))
    return names


def _check_no_builtin_capability_downgrade(store: PlanStoreView, svc: dict[str, Any]) -> None:
    """Enforce builtin/* capability security floors across ALL endpoints (regardless of port number)."""
    if is_builtin_id(svc["id"]):
        return
    svc_caps = _provided_capability_names(svc)
    if not svc_caps:
        return
    for sid in store.list_ids("service"):
        if not is_builtin_id(sid):
            continue
        bsvc = store.get("service", sid)
        for cap_name in sorted(svc_caps & _provided_capability_names(bsvc)):
            _check_service_against_builtin_floor(svc, bsvc, cap_name)


def _worker_satisfies(worker_caps: dict[str, Any], required_caps: list[str]) -> bool:
    return all(bool(worker_caps.get(rc, False)) for rc in required_caps)


def _resolve_primary_service(
    store: PlanStoreView, target: str, explicit_provider: str | None
) -> dict[str, Any]:
    if not CAPABILITY_REQUIRES_RE.fullmatch(target):
        return store.get("service", target)
    if explicit_provider is not None:
        cand = store.get("service", explicit_provider)
        if not any(capability_satisfies(p, target) for p in cand["provides"]):
            raise PlanError(f"Explicit provider {explicit_provider!r} does not satisfy {target!r}")
        return cand
    matches = [
        sdoc
        for sid in sorted(store.list_ids("service"))
        for sdoc in (store.get("service", sid),)
        if any(capability_satisfies(p, target) for p in sdoc["provides"])
    ]
    if not matches:
        raise PlanError(f"Unsatisfied capability requirement: {target!r}")
    if len(matches) > 1:
        names = ", ".join(m["id"] for m in matches)
        raise PlanError(
            f"Ambiguous providers for capability {target!r} ({names}); specify explicit provider"
        )
    return matches[0]


def _resolve_worker_fallback(
    store: PlanStoreView, primary: dict[str, Any], target: str, worker_caps: dict[str, Any]
) -> dict[str, Any]:
    if _worker_satisfies(worker_caps, primary["required_capabilities"]):
        return primary
    fb_id = primary.get("fallback_service")
    if fb_id is None:
        raise PlanError(
            f"Service {primary['id']!r} requires {primary['required_capabilities']}, "
            f"not supported by worker and no fallback_service declared"
        )
    fb = store.get("service", fb_id)
    _check_no_builtin_capability_downgrade(store, fb)
    _check_fallback_non_escalating(primary, fb)
    if not _worker_satisfies(worker_caps, fb["required_capabilities"]):
        raise PlanError(
            f"Fallback {fb['id']!r} requires {fb['required_capabilities']}, not supported by worker"
        )
    if CAPABILITY_REQUIRES_RE.fullmatch(target) and not any(
        capability_satisfies(p, target) for p in fb["provides"]
    ):
        raise PlanError(f"Fallback {fb['id']!r} does not satisfy required capability {target!r}")
    return fb


def _select_service_for_requirement(
    store: PlanStoreView,
    req: dict[str, Any],
    worker_caps: dict[str, Any],
) -> tuple[dict[str, Any], str | None, int | None]:
    target = req["target"]
    instance_alias = req.get("instance")
    instance_port_override = req.get("instance_port")

    primary = _resolve_primary_service(store, target, req.get("provider"))
    _check_no_builtin_capability_downgrade(store, primary)
    primary = _resolve_worker_fallback(store, primary, target, worker_caps)

    if instance_alias is not None and primary["cardinality"] != "named-instance":
        raise PlanError(
            f"Service {primary['id']!r} has cardinality={primary['cardinality']!r}, cannot bind instance {instance_alias!r}"
        )
    if instance_port_override is not None and primary["cardinality"] != "named-instance":
        raise PlanError(
            f"instance_port override only allowed for named-instance services, not {primary['id']!r}"
        )
    if primary["cardinality"] == "named-instance" and instance_alias is None:
        instance_alias = primary["id"].replace("/", "-")
    return primary, instance_alias, instance_port_override


def _check_singleton_diamond_conflicts(selected: dict[str, dict[str, Any]]) -> None:
    singleton_cap_owner: dict[str, str] = {}
    for key, node in sorted(selected.items()):
        svc = node["doc"]
        if svc["cardinality"] != "singleton":
            continue
        for cap_name in sorted(_provided_capability_names(svc)):
            prev = singleton_cap_owner.get(cap_name)
            if prev is not None and prev != key:
                raise PlanError(
                    f"Diamond conflict: both {prev!r} and {key!r} provide singleton capability {cap_name!r}"
                )
            singleton_cap_owner[cap_name] = key


def _kahn_toposort(selected: dict[str, dict[str, Any]], deps_of: dict[str, set[str]]) -> list[str]:
    dependents: dict[str, list[str]] = {k: [] for k in selected}
    in_degree: dict[str, int] = {}
    for k, ds in deps_of.items():
        in_degree[k] = len(ds)
        for d in ds:
            dependents[d].append(k)
    ready = deque(sorted(k for k, deg in in_degree.items() if deg == 0))
    ordered_keys: list[str] = []
    while ready:
        cur = ready.popleft()
        ordered_keys.append(cur)
        for nxt in sorted(dependents[cur]):
            in_degree[nxt] -= 1
            if in_degree[nxt] == 0:
                ready.append(nxt)
    if len(ordered_keys) != len(selected):
        raise PlanError("Cycle detected in service DAG")
    return ordered_keys


def _materialize_resolved_services(
    store: PlanStoreView,
    ordered_keys: list[str],
    selected: dict[str, dict[str, Any]],
    deps_of: dict[str, set[str]],
) -> tuple[list[dict[str, Any]], list[tuple[str, str, int]]]:
    used_pod_ports: dict[int, str] = {}
    resolved_services: list[dict[str, Any]] = []
    closure: list[tuple[str, str, int]] = []
    seen_svc_ids: set[str] = set()
    for key in ordered_keys:
        node = selected[key]
        svc = node["doc"]
        eff_inst_port = node["instance_port"]
        effective_endpoints = []
        for idx, ep in enumerate(svc["endpoints"]):
            port = (
                eff_inst_port
                if svc["cardinality"] == "named-instance" and eff_inst_port is not None and idx == 0
                else ep["port"]
            )
            if port in used_pod_ports:
                raise PlanError(
                    f"Pod port collision on {port}: both {used_pod_ports[port]!r} and {key!r} bind port {port}"
                )
            used_pod_ports[port] = key
            effective_endpoints.append({**ep, "port": port})
        resolved_services.append(
            {
                "key": key,
                "id": svc["id"],
                "instance": node["instance"],
                "dependencies": sorted(deps_of[key]),
                "doc": svc,
                "endpoints": effective_endpoints,
            }
        )
        if svc["id"] not in seen_svc_ids:
            seen_svc_ids.add(svc["id"])
            closure.append(("service", svc["id"], store.get_revision("service", svc["id"])))
    return resolved_services, closure


def _check_diamond_constraints(
    cap_constraints: dict[str, list[str]], node_key: str, target: str, svc: dict[str, Any]
) -> None:
    if not CAPABILITY_REQUIRES_RE.fullmatch(target):
        return
    cap_constraints.setdefault(node_key, []).append(target)
    for c in cap_constraints[node_key]:
        if not any(capability_satisfies(p, c) for p in svc["provides"]):
            raise PlanError(f"Incompatible diamond constraint {c!r} on {node_key!r}")


def _merge_existing_node_port(node: dict[str, Any], node_key: str, inst_port: int | None) -> None:
    prev_port = node["instance_port"]
    if inst_port is not None and prev_port is not None and inst_port != prev_port:
        raise PlanError(f"Conflicting instance_port for {node_key!r}: {prev_port} vs {inst_port}")
    if inst_port is not None and prev_port is None:
        node["instance_port"] = inst_port


def _resolve_service_dag(
    store: PlanStoreView,
    active_roots: list[dict[str, Any]],
    worker_caps: dict[str, Any],
    *,
    prior_node_count: int = 0,
) -> tuple[list[dict[str, Any]], list[tuple[str, str, int]]]:
    """Resolve recursive service DAG with fallback selection, diamond checks, and Kahn sort."""
    selected: dict[str, dict[str, Any]] = {}
    deps_of: dict[str, set[str]] = {}
    cap_constraints: dict[str, list[str]] = {}
    visiting: list[str] = []

    def resolve_req(req: dict[str, Any]) -> str:
        svc, inst, inst_port = _select_service_for_requirement(store, req, worker_caps)
        node_key = f"{svc['id']}@{inst}" if inst else svc["id"]
        _check_diamond_constraints(cap_constraints, node_key, req["target"], svc)
        if node_key in visiting:
            cycle = " -> ".join(visiting[visiting.index(node_key) :] + [node_key])
            raise PlanError(f"Cycle detected in service dependencies: {cycle}")
        if node_key in selected:
            _merge_existing_node_port(selected[node_key], node_key, inst_port)
            return node_key
        if prior_node_count + len(selected) + len(visiting) >= MAX_DAG_NODES:
            raise PlanError(f"Resolved DAG exceeds maximum {MAX_DAG_NODES} nodes")
        visiting.append(node_key)
        node_deps = {resolve_req(child_req) for child_req in svc["requires"]}
        visiting.pop()
        selected[node_key] = {
            "key": node_key,
            "instance": inst,
            "instance_port": inst_port if inst_port is not None else svc.get("instance_port"),
            "doc": svc,
        }
        deps_of[node_key] = node_deps
        return node_key

    for root in active_roots:
        resolve_req(root)

    _check_singleton_diamond_conflicts(selected)
    ordered_keys = _kahn_toposort(selected, deps_of)
    return _materialize_resolved_services(store, ordered_keys, selected, deps_of)


def _apply_endpoint_override(
    req: dict[str, Any],
    id_counts: dict[str, int],
    by_svc_ep: dict[tuple[str, str], dict[str, Any]],
    used_host_ports: dict[int, str],
) -> None:
    svc_ref, ep_name = req["service"], req["endpoint"]
    desired_exp, host_port = req["exposure"], req["host_port"]
    if "@" not in svc_ref and id_counts.get(svc_ref, 0) > 1:
        raise PlanError(
            f"Ambiguous port target {svc_ref}:{ep_name}; specify named instance as '{svc_ref}@<instance>'"
        )
    entry = by_svc_ep.get((svc_ref, ep_name))
    if entry is None:
        raise PolicyError(
            f"Cannot expose undeclared endpoint {svc_ref}:{ep_name} (service not active in plan)"
        )
    if EXPOSURE_RANK[desired_exp] > EXPOSURE_RANK[entry["max_exposure"]]:
        raise PolicyError(
            f"Exposure {desired_exp!r} for {svc_ref}:{ep_name} exceeds max_exposure {entry['max_exposure']!r}"
        )
    if desired_exp != "pod-only" and entry["requires_auth"] and not entry["auth_enforcer"]:
        raise PolicyError(
            f"Endpoint {svc_ref}:{ep_name} requires authentication before {desired_exp!r} exposure, "
            f"but no auth_enforcer is configured"
        )
    if host_port is not None:
        owner = f"{entry['service_key']}:{ep_name}"
        if host_port in used_host_ports and used_host_ports[host_port] != owner:
            raise PlanError(f"Duplicate host_port {host_port}")
        used_host_ports[host_port] = owner
    entry["exposure"] = desired_exp
    entry["host_port"] = host_port


def _compile_endpoints(
    resolved_services: list[dict[str, Any]],
    type_ports: list[dict[str, Any]],
    cli_ports: tuple[dict[str, Any], ...],
) -> list[dict[str, Any]]:
    id_counts: dict[str, int] = {}
    for rsvc in resolved_services:
        id_counts[rsvc["id"]] = id_counts.get(rsvc["id"], 0) + 1

    by_svc_ep: dict[tuple[str, str], dict[str, Any]] = {}
    out: list[dict[str, Any]] = []
    for rsvc in resolved_services:
        for ep in rsvc["endpoints"]:
            entry = {
                "service": rsvc["id"],
                "service_key": rsvc["key"],
                "endpoint": ep["name"],
                "port": ep["port"],
                "protocol": ep["protocol"],
                "exposure": ep["default_exposure"],
                "max_exposure": ep["max_exposure"],
                "requires_auth": ep["requires_auth"],
                "auth_enforcer": ep["auth_enforcer"],
                "tls_policy": ep["tls_policy"],
                "host_port": None,
                "host_url_template": ep["host_url_template"],
            }
            by_svc_ep[(rsvc["key"], ep["name"])] = entry
            if id_counts[rsvc["id"]] == 1:
                by_svc_ep[(rsvc["id"], ep["name"])] = entry
            out.append(entry)

    used_host_ports: dict[int, str] = {}
    validated_cli = [validate_port_request(p, f"cli_ports[{i}]") for i, p in enumerate(cli_ports)]
    for req in list(type_ports) + validated_cli:
        _apply_endpoint_override(req, id_counts, by_svc_ep, used_host_ports)

    for entry in out:
        if entry["host_url_template"] and entry["exposure"] != "pod-only":
            render_host_url(
                entry["host_url_template"],
                {
                    "host": "127.0.0.1",
                    "port": entry["host_port"] or entry["port"],
                    "user": "app",
                    "db": "app",
                    "path": "/",
                },
            )
    return out


def _expand_slots_single_pass(
    text: str,
    bundle_id: str,
    slot_map: dict[str, str],
    bundle_root: Path | None,
) -> str:
    """Expand {{slot}} in a single non-recursive pass from O_NOFOLLOW bundle-confined files."""
    if "{{" not in text:
        return text
    loaded: dict[str, str] = {}

    def _replace(match: Any) -> str:
        slot_name = match.group(1)
        if slot_name not in slot_map:
            raise SchemaError(f"Undeclared prompt slot {{{{{slot_name}}}}} in bundle {bundle_id!r}")
        if slot_name not in loaded:
            if bundle_root is None:
                raise PolicyError(f"Bundle {bundle_id!r} has no trusted asset root for slot {slot_name!r}")
            slot_path = bundle_root / slot_map[slot_name]
            raw = read_regular_no_follow(
                slot_path,
                max_bytes=MAX_SLOT_FILE_BYTES,
                confined_root=bundle_root,
            )
            loaded[slot_name] = raw.decode("utf-8")
        return loaded[slot_name]

    return SLOT_TOKEN_RE.sub(_replace, text)


def _bind_bundle_mcp_entry(mcfg: dict[str, Any], remote_bindings: dict[str, str]) -> dict[str, Any]:
    effective_cfg = dict(mcfg)
    if mcfg["local"] is not None:
        bkey = mcfg["local"]["binding_key"]
        if bkey in remote_bindings:
            effective_cfg["url"] = remote_bindings[bkey]
            effective_cfg["_is_remote"] = True
        else:
            effective_cfg["url"] = mcfg["local"]["url"]
            effective_cfg["_is_remote"] = False
    elif mcfg["type"] == "remote":
        effective_cfg["_is_remote"] = not (mcfg["url"] or "").lower().startswith("http://127.0.0.1:")
    else:
        effective_cfg["_is_remote"] = False
    return effective_cfg


def _merge_bundle_persona(
    b: dict[str, Any],
    broot: Path | None,
    replace_set: set[str],
    primary_persona: dict[str, Any] | None,
    primary_owner: str | None,
) -> tuple[dict[str, Any] | None, str | None]:
    if b["persona"] is None:
        return primary_persona, primary_owner
    bid = b["id"]
    if primary_persona is not None and "persona" not in replace_set:
        raise PlanError(
            f"Conflicting primary persona between {primary_owner!r} and {bid!r}; "
            f"declare [composition] replace = ['persona'] explicitly"
        )
    expanded_mission = _expand_slots_single_pass(b["persona"]["mission"], bid, b["prompt_slots"], broot)
    if len(expanded_mission.encode("utf-8")) > MAX_MISSION_BYTES:
        raise SchemaError(f"Expanded persona.mission in {bid!r} exceeds {MAX_MISSION_BYTES} bytes")
    return {**b["persona"], "mission": expanded_mission}, bid


def _append_bundle_instructions(
    b: dict[str, Any],
    broot: Path | None,
    instructions: list[dict[str, str]],
    total_instr_bytes: int,
) -> int:
    bid = b["id"]
    for idx, raw_instr in enumerate(b["instructions"]):
        expanded = _expand_slots_single_pass(raw_instr, bid, b["prompt_slots"], broot)
        total_instr_bytes += len(expanded.encode("utf-8"))
        if total_instr_bytes > MAX_INSTRUCTIONS_TOTAL_BYTES:
            raise SchemaError(f"Compiled instructions exceed {MAX_INSTRUCTIONS_TOTAL_BYTES} byte cap")
        instructions.append(
            {
                "path": f"/run/oc-config/instructions/{len(instructions):02d}-{bid.replace('/', '-')}-{idx}.md",
                "source_bundle": bid,
                "content": expanded,
            }
        )
    return total_instr_bytes


def _merge_bundle_mcps(
    b: dict[str, Any],
    replace_set: set[str],
    remote_bindings: dict[str, str],
    mcp_servers: dict[str, dict[str, Any]],
    mcp_owners: dict[str, str],
) -> None:
    bid = b["id"]
    for mname, mcfg in b["mcp"].items():
        effective_cfg = _bind_bundle_mcp_entry(mcfg, remote_bindings)
        if mname in mcp_servers and mcp_servers[mname] != effective_cfg and "mcp" not in replace_set:
            raise PlanError(
                f"Conflicting MCP server {mname!r} between {mcp_owners[mname]!r} and {bid!r}; "
                f"declare [composition] replace = ['mcp']"
            )
        mcp_servers[mname] = effective_cfg
        mcp_owners[mname] = bid


def _collect_bundle_role_parts(
    store: PlanStoreView,
    bundles: list[dict[str, Any]],
    remote_bindings: dict[str, str],
) -> tuple[
    dict[str, Any] | None,
    dict[str, dict[str, Any]],
    list[dict[str, str]],
    dict[str, str],
    dict[str, dict[str, Any]],
]:
    primary_persona: dict[str, Any] | None = None
    primary_owner: str | None = None
    subagents: dict[str, dict[str, Any]] = {}
    instructions: list[dict[str, str]] = []
    skills: dict[str, str] = {}
    mcp_servers: dict[str, dict[str, Any]] = {}
    mcp_owners: dict[str, str] = {}
    total_instr_bytes = 0

    for b in bundles:
        bid = b["id"]
        replace_set = set(b["composition"]["replace"])
        broot = store.bundle_asset_root(bid)
        primary_persona, primary_owner = _merge_bundle_persona(
            b, broot, replace_set, primary_persona, primary_owner
        )
        for sa in b["subagents"]:
            if sa["name"] in subagents and subagents[sa["name"]] != sa:
                raise PlanError(f"Conflicting subagent definition {sa['name']!r} in {bid!r}")
            subagents[sa["name"]] = sa
        total_instr_bytes = _append_bundle_instructions(b, broot, instructions, total_instr_bytes)
        for skill_id in b["skills"]:
            if skill_id in skills and skills[skill_id] != bid:
                raise PlanError(f"Duplicate skill {skill_id!r} contributed by {skills[skill_id]!r} and {bid!r}")
            skills[skill_id] = bid
        _merge_bundle_mcps(b, replace_set, remote_bindings, mcp_servers, mcp_owners)

    return primary_persona, subagents, instructions, skills, mcp_servers


def _filter_tools_by_persona(
    mname: str,
    candidate_tools: list[str],
    allow_set: set[str] | None,
    deny_set: set[str],
) -> list[str]:
    tools = list(candidate_tools)
    if allow_set is not None:
        tools = [t for t in tools if f"{mname}.{t}" in allow_set or t in allow_set]
    if deny_set:
        tools = [t for t in tools if f"{mname}.{t}" not in deny_set and t not in deny_set]
    return tools


def _select_remote_credentials(
    mname: str, mcfg: dict[str, Any], *, write_active: bool
) -> tuple[str, dict[str, str], dict[str, str]]:
    rcfg = mcfg.get("remote")
    mode = "remote-rw" if write_active else "remote-ro"
    if rcfg is not None:
        prefix = "write" if write_active else "read_only"
        return mode, dict(rcfg[f"{prefix}_headers"]), dict(rcfg[f"{prefix}_secret_env"])
    if mcfg["headers"] or mcfg["secret_env"]:
        role_word = "write" if write_active else "read_only"
        raise PolicyError(
            f"Remote MCP {mname!r} must declare separate [mcp.{mname}.remote] {role_word} credentials "
            f"instead of reusing local headers/secret_env"
        )
    return mode, {}, {}


def _require_raw_mount_breakglass(
    route_id: str,
    tier: str,
    allow_raw_remote_mounts: frozenset[str],
    active_raw_remote_mounts: set[str],
) -> None:
    if tier == "managed":
        raise PolicyError(
            f"credential_delivery='raw-container-mount' for {route_id!r} is permanently forbidden in 'managed' tier"
        )
    if route_id not in allow_raw_remote_mounts:
        raise PolicyError(
            f"credential_delivery='raw-container-mount' for {route_id!r} requires explicit "
            f"PlanOverrides.allow_raw_remote_mounts grant"
        )
    active_raw_remote_mounts.add(route_id)


def _build_remote_mcp_broker_route(
    mname: str,
    mcfg: dict[str, Any],
    *,
    resolved_url: str,
    cred_delivery: str,
    access_mode: str,
    eff_headers: dict[str, str],
    eff_secret_env: dict[str, str],
    tools: list[str],
) -> dict[str, Any]:
    allow_streaming = bool(mcfg.get("allow_streaming", False))
    base_wp = (
        mcfg["wire_policy"]
        if mcfg.get("wire_policy") is not None
        else default_mcp_wire_policy(allow_streaming=allow_streaming)
    )
    return {
        "route_id": f"mcp:{mname}",
        "kind": "mcp",
        "credential_delivery": cred_delivery,
        "access_mode": access_mode,
        "inbound_auth": mcfg.get("inbound_auth", "bearer"),
        "inbound_auth_header": mcfg.get("inbound_auth_header"),
        "upstream": resolved_url,
        "upstream_headers": eff_headers,
        "upstream_secret_env": eff_secret_env,
        "secret_slots": sorted(extract_secret_slots(eff_headers, eff_secret_env)),
        "allow_streaming": allow_streaming,
        "allowed_cidrs": list(mcfg.get("allowed_cidrs", [])),
        "wire_policy": {**base_wp, "allowed_tools": list(tools)},
    }


def _compile_remote_mcp_entry(
    mname: str,
    mcfg: dict[str, Any],
    remote_write_grants: dict[str, str],
    allow_set: set[str] | None,
    deny_set: set[str],
    effective_remote_write_grants: dict[str, str],
    *,
    tier: str,
    sandbox_broker_host: str,
    broker_http_port: int,
    allow_raw_remote_mounts: frozenset[str],
    active_raw_remote_mounts: set[str],
    broker_routes: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    resolved_url = mcfg["url"]
    ro_tools = mcfg.get("read_only_tools")
    wr_tools = mcfg.get("write_tools", [])
    if ro_tools is None:
        raise PolicyError(
            f"Remote MCP server {mname!r} must explicitly declare read_only_tools (failing closed)"
        )
    grant_matched = False
    if mname in remote_write_grants:
        granted_url = remote_write_grants[mname]
        if granted_url != resolved_url:
            raise PolicyError(
                f"Remote write grant for MCP {mname!r} targets {granted_url!r}, "
                f"which does not match bound remote endpoint {resolved_url!r}"
            )
        grant_matched = True

    candidate_tools = list(ro_tools) + (list(wr_tools) if grant_matched else [])
    tools = _filter_tools_by_persona(mname, candidate_tools, allow_set, deny_set)
    # Persona narrowing overrides even an explicit remote write grant; never mount RW credentials
    # if zero write tools survive persona filtering!
    write_active = grant_matched and any(t in wr_tools for t in tools)
    access_mode, eff_headers, eff_secret_env = _select_remote_credentials(
        mname, mcfg, write_active=write_active
    )
    if write_active:
        if resolved_url is None:
            raise PlanError(f"Remote MCP {mname!r} missing resolved_url")
        effective_remote_write_grants[mname] = resolved_url
    if allow_set is not None and candidate_tools and not tools:
        return None

    raw_delivery = mcfg.get("credential_delivery")
    cred_delivery = "host-brokered" if raw_delivery is None else raw_delivery
    if cred_delivery == "local-ephemeral":
        raise PolicyError(
            f"Remote MCP {mname!r} cannot use credential_delivery='local-ephemeral' when bound remotely"
        )
    route_id = f"mcp:{mname}"
    if cred_delivery == "raw-container-mount":
        _require_raw_mount_breakglass(route_id, tier, allow_raw_remote_mounts, active_raw_remote_mounts)

    if resolved_url is None:
        raise PlanError(f"Remote MCP {mname!r} missing resolved_url")
    broker_routes[route_id] = _build_remote_mcp_broker_route(
        mname,
        mcfg,
        resolved_url=resolved_url,
        cred_delivery=cred_delivery,
        access_mode=access_mode,
        eff_headers=eff_headers,
        eff_secret_env=eff_secret_env,
        tools=tools,
    )
    if cred_delivery == "host-brokered":
        container_url = f"http://{sandbox_broker_host}:{broker_http_port}/mcp/{mname}"
        container_headers = {"Authorization": "Bearer {file:/run/secrets/oc_broker_token}"}
        container_secret_env: dict[str, str] = {}
    else:
        container_url = resolved_url
        container_headers = eff_headers
        container_secret_env = eff_secret_env

    return {
        "type": mcfg["type"],
        "access_mode": access_mode,
        "credential_delivery": cred_delivery,
        "url": container_url,
        "artifact_id": mcfg["artifact_id"],
        "args": mcfg["args"],
        "headers": container_headers,
        "secret_env": container_secret_env,
        "allowed_tools": tools,
    }


def _compile_local_mcp_entry(
    mname: str,
    mcfg: dict[str, Any],
    remote_write_grants: dict[str, str],
    allow_set: set[str] | None,
    deny_set: set[str],
    *,
    tier: str,
    allow_raw_remote_mounts: frozenset[str],
    active_raw_remote_mounts: set[str],
) -> dict[str, Any] | None:
    if mname in remote_write_grants:
        raise PolicyError(
            f"Remote write grant specified for MCP {mname!r}, which is not bound to a remote endpoint"
        )
    candidate_tools = list(mcfg["tools"])
    tools = _filter_tools_by_persona(mname, candidate_tools, allow_set, deny_set)
    if allow_set is not None and candidate_tools and not tools:
        return None
    raw_delivery = mcfg.get("credential_delivery")
    cred_delivery = "local-ephemeral" if raw_delivery is None else raw_delivery
    if cred_delivery == "host-brokered":
        raise PolicyError(f"Local MCP {mname!r} cannot use credential_delivery='host-brokered'")
    if cred_delivery == "raw-container-mount":
        if mcfg["type"] != "pinned-artifact":
            raise PolicyError(f"Pod-local MCP {mname!r} cannot use credential_delivery='raw-container-mount'")
        _require_raw_mount_breakglass(f"mcp:{mname}", tier, allow_raw_remote_mounts, active_raw_remote_mounts)
    lcfg = mcfg.get("local") if mcfg["type"] != "pinned-artifact" else None
    use_local = lcfg is not None and (lcfg["headers"] or lcfg["secret_env"])
    src = lcfg if use_local else mcfg
    return {
        "type": mcfg["type"],
        "access_mode": "local",
        "credential_delivery": cred_delivery,
        "url": mcfg["url"],
        "artifact_id": mcfg["artifact_id"],
        "args": mcfg["args"],
        "headers": dict(src["headers"]),
        "secret_env": dict(src["secret_env"]),
        "allowed_tools": tools,
    }


def _render_services_md(resolved_services: list[dict[str, Any]]) -> str:
    service_lines = ["# Active Sandbox Services", ""]
    if not resolved_services:
        service_lines.append("- None")
    else:
        for rs in resolved_services:
            ep_str = ", ".join(
                f"{ep['name']}=127.0.0.1:{ep['port']} (auth={'yes' if ep['requires_auth'] else 'no'})"
                for ep in rs["endpoints"]
            )
            service_lines.append(f"- `{rs['key']}`: {ep_str or 'no ports'}")
    return "\n".join(service_lines) + "\n"


def _compile_role_contract(
    store: PlanStoreView,
    bundles: list[dict[str, Any]],
    default_agent_override: str | None,
    resolved_services: list[dict[str, Any]],
    remote_bindings: dict[str, str],
    remote_write_grants: dict[str, str],
    tier: str,
    *,
    sandbox_broker_host: str,
    broker_http_port: int,
    allow_raw_remote_mounts: frozenset[str],
    active_raw_remote_mounts: set[str],
    broker_routes: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, str]]:
    primary_persona, subagents, instructions, skills, mcp_servers = _collect_bundle_role_parts(
        store, bundles, remote_bindings
    )
    unknown_grant_mcps = sorted(set(remote_write_grants) - set(mcp_servers))
    if unknown_grant_mcps:
        raise PolicyError(
            f"Remote write grant references unknown/inactive MCP server(s): {', '.join(unknown_grant_mcps)}"
        )

    allow_set = (
        set(primary_persona["allowed_mcp_tools"])
        if primary_persona and primary_persona["allowed_mcp_tools"] is not None
        else None
    )
    deny_set = set(primary_persona["denied_mcp_tools"]) if primary_persona else set()

    filtered_mcp: dict[str, dict[str, Any]] = {}
    effective_remote_write_grants: dict[str, str] = {}
    for mname, mcfg in sorted(mcp_servers.items()):
        compiled_entry = (
            _compile_remote_mcp_entry(
                mname,
                mcfg,
                remote_write_grants,
                allow_set,
                deny_set,
                effective_remote_write_grants,
                tier=tier,
                sandbox_broker_host=sandbox_broker_host,
                broker_http_port=broker_http_port,
                allow_raw_remote_mounts=allow_raw_remote_mounts,
                active_raw_remote_mounts=active_raw_remote_mounts,
                broker_routes=broker_routes,
            )
            if mcfg.get("_is_remote", False)
            else _compile_local_mcp_entry(
                mname,
                mcfg,
                remote_write_grants,
                allow_set,
                deny_set,
                tier=tier,
                allow_raw_remote_mounts=allow_raw_remote_mounts,
                active_raw_remote_mounts=active_raw_remote_mounts,
            )
        )
        if compiled_entry is not None:
            filtered_mcp[mname] = compiled_entry

    default_agent = default_agent_override or (primary_persona["name"] if primary_persona else "default")
    opencode_config = {
        "$schema": "https://opencode.ai/config.json",
        "default_agent": default_agent,
        "instructions": [ins["path"] for ins in instructions] + ["/run/oc-config/SERVICES.md"],
        "mcp": filtered_mcp,
        "managed_workspace_lockout": tier == "managed",
    }
    return (
        {
            "default_agent": default_agent,
            "primary_persona": primary_persona,
            "subagents": [subagents[k] for k in sorted(subagents)],
            "instructions": instructions,
            "services_md": _render_services_md(resolved_services),
            "skills": sorted(skills.keys()),
            "opencode_config": opencode_config,
        },
        effective_remote_write_grants,
    )


def _merge_bundle_broker_services(bundles: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    owners: dict[str, str] = {}
    for b in bundles:
        bid = b["id"]
        for name, cfg in b.get("broker_services", {}).items():
            if name in merged and merged[name] != cfg:
                raise PlanError(
                    f"Conflicting broker_services.{name!r} between {owners[name]!r} and {bid!r}"
                )
            merged[name] = cfg
            owners[name] = bid
    return merged


def _set_broker_client_env(env_map: dict[str, str], key: str, value: str) -> None:
    if key in env_map and env_map[key] != value:
        raise PlanError(f"Conflicting broker_client_env variable {key!r}")
    env_map[key] = value


def _compile_broker_http_entry(
    name: str,
    cfg: dict[str, Any],
    *,
    sandbox_broker_host: str,
    broker_http_port: int,
    broker_routes: dict[str, dict[str, Any]],
    broker_client_env: dict[str, str],
) -> None:
    route_id = f"http:{name}"
    cred_delivery = cfg["credential_delivery"]
    broker_routes[route_id] = {
        "route_id": route_id,
        "kind": "http",
        "credential_delivery": cred_delivery,
        "access_mode": "remote-ro",
        "inbound_auth": cfg["inbound_auth"],
        "inbound_auth_header": cfg["inbound_auth_header"],
        "upstream": cfg["upstream_url"],
        "secret_ref": cfg["read_only_secret_ref"],
        "allow_streaming": cfg["allow_streaming"],
        "allowed_cidrs": list(cfg["allowed_cidrs"]),
        "wire_policy": cfg["wire_policy"],
    }
    if cred_delivery == "host-brokered":
        proxy_url = f"http://{sandbox_broker_host}:{broker_http_port}/http/{name}"
        _set_broker_client_env(broker_client_env, f"OC_BROKER_HTTP_{name.upper().replace('-', '_')}_URL", proxy_url)
        if cfg.get("client_env_var"):
            _set_broker_client_env(broker_client_env, cfg["client_env_var"], proxy_url)


def _compile_broker_pg_entry(
    name: str,
    cfg: dict[str, Any],
    *,
    sandbox_broker_host: str,
    broker_pg_port: int,
    broker_routes: dict[str, dict[str, Any]],
    broker_client_env: dict[str, str],
) -> None:
    route_id = f"pg:{name}"
    cred_delivery = cfg["credential_delivery"]
    broker_routes[route_id] = {
        "route_id": route_id,
        "kind": "postgres",
        "credential_delivery": cred_delivery,
        "access_mode": "ro",
        "upstream": {
            "host": cfg["host"],
            "port": cfg["port"],
            "database": cfg["database"],
            "user": cfg["read_only_user"],
            "sslmode": cfg["sslmode"],
        },
        "secret_ref": cfg["read_only_secret_ref"],
        "allowed_cidrs": list(cfg["allowed_cidrs"]),
    }
    if cred_delivery == "host-brokered":
        pg_url = (
            f"postgresql://ocjob:{{file:/run/secrets/oc_broker_token}}"
            f"@{sandbox_broker_host}:{broker_pg_port}/{cfg['database']}?sslmode=disable"
        )
        _set_broker_client_env(broker_client_env, f"OC_BROKER_PG_{name.upper().replace('-', '_')}_URL", pg_url)


def _compile_broker_ssh_entry(
    name: str,
    cfg: dict[str, Any],
    *,
    broker_routes: dict[str, dict[str, Any]],
) -> None:
    route_id = f"ssh:{name}"
    broker_routes[route_id] = {
        "route_id": route_id,
        "kind": "ssh",
        "credential_delivery": "host-brokered",
        "access_mode": "ro",
        "upstream": {
            "host": cfg["host"],
            "port": cfg["port"],
            "user": cfg["user"],
        },
        "known_hosts_ref": cfg["known_hosts_ref"],
        "allowed_presets": list(cfg["allowed_presets"]),
        "allowed_cidrs": list(cfg["allowed_cidrs"]),
    }


def _compile_broker_services(
    bundles: list[dict[str, Any]],
    *,
    tier: str,
    sandbox_broker_host: str,
    broker_http_port: int,
    broker_pg_port: int,
    allow_raw_remote_mounts: frozenset[str],
    active_raw_remote_mounts: set[str],
    broker_routes: dict[str, dict[str, Any]],
) -> dict[str, str]:
    broker_services = _merge_bundle_broker_services(bundles)
    broker_client_env: dict[str, str] = {}
    prefix_map = {"http": "http", "postgres": "pg", "ssh": "ssh"}
    for name, cfg in sorted(broker_services.items()):
        kind = cfg["kind"]
        route_id = f"{prefix_map[kind]}:{name}"
        if cfg["credential_delivery"] == "raw-container-mount":
            _require_raw_mount_breakglass(route_id, tier, allow_raw_remote_mounts, active_raw_remote_mounts)
        if kind == "http":
            _compile_broker_http_entry(
                name,
                cfg,
                sandbox_broker_host=sandbox_broker_host,
                broker_http_port=broker_http_port,
                broker_routes=broker_routes,
                broker_client_env=broker_client_env,
            )
        elif kind == "postgres":
            _compile_broker_pg_entry(
                name,
                cfg,
                sandbox_broker_host=sandbox_broker_host,
                broker_pg_port=broker_pg_port,
                broker_routes=broker_routes,
                broker_client_env=broker_client_env,
            )
        elif kind == "ssh":
            _compile_broker_ssh_entry(name, cfg, broker_routes=broker_routes)
    return broker_client_env


def _merge_single_mise_source(
    src_id: str,
    tools: dict[str, str],
    overrides: dict[str, str],
    merged: dict[str, tuple[str, str]],
) -> None:
    for tool, ver in tools.items():
        if tool in overrides:
            continue
        prev = merged.get(tool)
        if prev is not None and prev[0] != ver:
            raise PlanError(
                f"Conflicting mise tool pins for {tool!r}: {prev[1]}={prev[0]!r} vs {src_id}={ver!r}"
            )
        merged[tool] = (ver, src_id)


def _merge_mise_tools(
    bundles: list[dict[str, Any]],
    resolved_services: list[dict[str, Any]],
    overrides: dict[str, str],
) -> dict[str, str]:
    manifest_count = 0
    merged: dict[str, tuple[str, str]] = {}
    sources = [(b["id"], b["mise_tools"]) for b in bundles] + [
        (rs["id"], rs["doc"]["mise_tools"]) for rs in resolved_services
    ]
    for src_id, tools in sources:
        if not tools:
            continue
        manifest_count += 1
        if manifest_count > MAX_MISE_MANIFESTS:
            raise PlanError(f"Too many mise manifests (max {MAX_MISE_MANIFESTS})")
        _merge_single_mise_source(src_id, tools, overrides, merged)
    out = {k: v[0] for k, v in merged.items()}
    out.update(overrides)
    if len(out) > MAX_MISE_TOOLS:
        raise PlanError(f"Too many distinct mise tools (max {MAX_MISE_TOOLS})")
    return dict(sorted(out.items()))


def _bind_image_for_arch(image: str | None, images_by_arch: dict[str, str] | None, arch: str, ctx: str) -> str:
    if images_by_arch is not None:
        if arch not in images_by_arch:
            raise PlanError(f"{ctx} has no digest-pinned image for arch {arch!r}")
        return images_by_arch[arch]
    if image is None:
        raise PlanError(f"{ctx} missing digest-pinned image")
    return image


def _runtime_role_projection(plan: dict[str, Any]) -> dict[str, Any]:
    """Runtime-affecting subset of role_contract (changes here require container/process recreation)."""
    rc = plan.get("role_contract", {})
    oc = rc.get("opencode_config", {})
    return {
        "default_agent": rc.get("default_agent"),
        "mcp": oc.get("mcp"),
        "managed_workspace_lockout": oc.get("managed_workspace_lockout"),
    }


def classify_drift(applied_plan: dict[str, Any] | None, desired_plan: dict[str, Any]) -> dict[str, Any]:
    if applied_plan is None:
        return {"kind": "fresh", "reasons": ["no_applied_plan"]}
    if applied_plan == desired_plan:
        return {"kind": "none", "reasons": []}

    reasons: list[str] = []
    old_svcs = {s["key"]: s for s in applied_plan.get("services", [])}
    new_svcs = {s["key"]: s for s in desired_plan.get("services", [])}
    for key, old_s in old_svcs.items():
        has_durable = any(v.get("durable") for v in old_s.get("volumes", []))
        if not has_durable:
            continue
        new_s = new_svcs.get(key)
        if new_s is None:
            reasons.append(f"durable_service_removed:{key}")
        elif new_s["image"] != old_s["image"] or new_s["volumes"] != old_s["volumes"]:
            reasons.append(f"durable_service_changed:{key}")
    if reasons:
        return {"kind": "stateful-migration-required", "reasons": sorted(reasons)}

    # Only non-runtime prose/skills changes are hot-safe; MCP/default_agent/lockout changes require recreate-stateless
    stripped_old = {k: v for k, v in applied_plan.items() if k != "role_contract"}
    stripped_new = {k: v for k, v in desired_plan.items() if k != "role_contract"}
    if stripped_old == stripped_new and _runtime_role_projection(applied_plan) == _runtime_role_projection(desired_plan):
        return {"kind": "hot-safe", "reasons": ["role_instructions_or_skills_updated"]}
    return {"kind": "recreate-stateless", "reasons": ["runtime_plan_changed"]}


def _bind_or_activate_local(
    bkey: str,
    target_req: dict[str, Any],
    ov: PlanOverrides,
    active_roots: list[dict[str, Any]],
    remote_bindings: dict[str, str],
) -> None:
    ext = ov.env_bindings.get(bkey, "")
    if ext:
        remote_bindings[bkey] = canonicalize_remote_url(
            ext,
            allow_http=ov.allow_http_remote,
            allowed_hosts=ov.allowed_remote_hosts,
        )
    else:
        active_roots.append(target_req)


def _collect_roots_and_bindings(
    bundles: list[dict[str, Any]], ov: PlanOverrides
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    active_roots: list[dict[str, Any]] = []
    remote_bindings: dict[str, str] = {}
    for b in bundles:
        active_roots.extend(b["requires_services"])
        for lsvc in b["local_services"]:
            _bind_or_activate_local(
                lsvc["binding_key"],
                {
                    "target": lsvc["service"],
                    "provider": None,
                    "instance": lsvc["instance"],
                    "instance_port": lsvc.get("instance_port"),
                },
                ov,
                active_roots,
                remote_bindings,
            )
        for mcfg in b["mcp"].values():
            if mcfg["local"] is not None:
                _bind_or_activate_local(
                    mcfg["local"]["binding_key"],
                    {
                        "target": mcfg["local"]["service"],
                        "provider": None,
                        "instance": None,
                        "instance_port": None,
                    },
                    ov,
                    active_roots,
                    remote_bindings,
                )
    return active_roots, remote_bindings


def _canonicalize_write_grants(ov: PlanOverrides) -> dict[str, str]:
    canonical_write_grants: dict[str, str] = {}
    for g_mcp, g_url in ov.remote_write_grants.items():
        if type(g_mcp) is not str or SIMPLE_NAME_RE.fullmatch(g_mcp) is None:
            raise SchemaError(f"Invalid MCP name in remote_write_grants: {g_mcp!r}")
        canonical_write_grants[g_mcp] = canonicalize_remote_url(
            g_url,
            allow_http=ov.allow_http_remote,
            allowed_hosts=ov.allowed_remote_hosts,
        )
    return canonical_write_grants


def _validate_broker_overrides(ov: PlanOverrides, tier: str) -> frozenset[str]:
    raw_mounts = ov.allow_raw_remote_mounts
    if not isinstance(raw_mounts, frozenset):
        raise PolicyError("PlanOverrides.allow_raw_remote_mounts must be a frozenset of explicit route IDs")
    for rid in raw_mounts:
        if type(rid) is not str or ROUTE_ID_RE.fullmatch(rid) is None or rid.startswith("ssh:"):
            raise SchemaError(f"Invalid route ID in allow_raw_remote_mounts: {rid!r}")
    if tier == "managed" and raw_mounts:
        raise PolicyError("PlanOverrides.allow_raw_remote_mounts is permanently forbidden in 'managed' tier")
    for label, port in (("broker_http_port", ov.broker_http_port), ("broker_pg_port", ov.broker_pg_port)):
        if type(port) is not int or not (1024 <= port <= 65535) or port == 9222:
            raise PolicyError(f"Invalid {label}: {port!r}")
    if ov.broker_http_port == ov.broker_pg_port:
        raise PlanError("broker_http_port and broker_pg_port must be distinct")
    return raw_mounts


def _resolve_sandbox_broker_host(host_provider: dict[str, Any], transport: dict[str, Any]) -> str:
    if host_provider["id"] == "builtin/podman-macos-vm" and transport["id"] == "builtin/ssh-pinned":
        return "host.containers.internal"
    return "127.0.0.1"


def _enforce_broker_gates(
    broker_routes: dict[str, dict[str, Any]],
    *,
    tier: str,
    topology: str,
    worker_id: str,
    transport: dict[str, Any],
    allow_raw_remote_mounts: frozenset[str],
    active_raw_remote_mounts: set[str],
) -> None:
    unmatched = sorted(allow_raw_remote_mounts - active_raw_remote_mounts)
    if unmatched:
        raise PolicyError(
            f"allow_raw_remote_mounts references unknown, inactive, or non-raw-container-mount route(s): "
            f"{', '.join(unmatched)}"
        )
    has_host_brokered = any(r["credential_delivery"] == "host-brokered" for r in broker_routes.values())
    if not has_host_brokered:
        return
    if "open_reverse_channel" not in transport["primitives"]:
        raise PolicyError(
            f"Worker {worker_id!r} transport {transport['id']!r} lacks 'open_reverse_channel' "
            f"required for host-brokered routes"
        )
    if tier == "managed" and topology != "isolated-sidecars":
        raise PolicyError("Host-brokered routes in 'managed' tier require topology='isolated-sidecars'")


def compile_plan(
    store: PlanStoreView,
    sandbox_type_id: str,
    worker_id: str | None = None,
    overrides: PlanOverrides | None = None,
    applied_plan: dict[str, Any] | None = None,
) -> CompiledPlanResult:
    ov = overrides or PlanOverrides()
    validate_opaque_id(sandbox_type_id, label="sandbox_type")
    st = store.get("sandbox-type", sandbox_type_id)
    allow_raw_mounts = _validate_broker_overrides(ov, st["tier"])
    eff_worker_id = worker_id or st["default_worker"]
    validate_opaque_id(eff_worker_id, label="worker")
    worker = store.get("worker", eff_worker_id)
    host_provider = store.get("host-provider", worker["host_provider"])
    transport = store.get("transport", worker["transport"])

    worker_caps = {**host_provider["capabilities"], **worker["capabilities_override"]}
    arch = worker["arch"]
    sandbox_broker_host = _resolve_sandbox_broker_host(host_provider, transport)

    bundles, bundle_closure = _resolve_bundle_dag(store, st["bundles"], ov.with_mods, ov.without_mods)
    active_roots, remote_bindings = _collect_roots_and_bindings(bundles, ov)
    canonical_write_grants = _canonicalize_write_grants(ov)

    if active_roots and not bool(worker_caps.get("supports_pods", False)):
        raise PlanError(
            f"Worker {eff_worker_id!r} ({host_provider['id']}) has supports_pods=false; "
            f"cannot run sidecar services"
        )

    resolved_services, svc_closure = _resolve_service_dag(
        store, active_roots, worker_caps, prior_node_count=len(bundles)
    )
    endpoints = _compile_endpoints(resolved_services, st["ports"], ov.cli_ports)

    broker_routes: dict[str, dict[str, Any]] = {}
    active_raw_remote_mounts: set[str] = set()
    role, effective_remote_write_grants = _compile_role_contract(
        store,
        bundles,
        st["default_agent"],
        resolved_services,
        remote_bindings,
        canonical_write_grants,
        st["tier"],
        sandbox_broker_host=sandbox_broker_host,
        broker_http_port=ov.broker_http_port,
        allow_raw_remote_mounts=allow_raw_mounts,
        active_raw_remote_mounts=active_raw_remote_mounts,
        broker_routes=broker_routes,
    )
    broker_client_env = _compile_broker_services(
        bundles,
        tier=st["tier"],
        sandbox_broker_host=sandbox_broker_host,
        broker_http_port=ov.broker_http_port,
        broker_pg_port=ov.broker_pg_port,
        allow_raw_remote_mounts=allow_raw_mounts,
        active_raw_remote_mounts=active_raw_remote_mounts,
        broker_routes=broker_routes,
    )
    _enforce_broker_gates(
        broker_routes,
        tier=st["tier"],
        topology=st["topology"],
        worker_id=eff_worker_id,
        transport=transport,
        allow_raw_remote_mounts=allow_raw_mounts,
        active_raw_remote_mounts=active_raw_remote_mounts,
    )

    mise_tools = _merge_mise_tools(bundles, resolved_services, st["mise_overrides"])
    base_image = _bind_image_for_arch(
        st["base_image"], st["base_images_by_arch"], arch, f"sandbox-type({sandbox_type_id})"
    )

    compiled_services = [
        {
            "key": rs["key"],
            "id": rs["id"],
            "instance": rs["instance"],
            "dependencies": rs["dependencies"],
            "image": _bind_image_for_arch(
                rs["doc"]["image"], rs["doc"]["images_by_arch"], arch, f"service({rs['doc']['id']})"
            ),
            "security_profile": rs["doc"]["security_profile"],
            "factory_id": rs["doc"]["factory_id"],
            "resources": rs["doc"]["resources"],
            "endpoints": rs["endpoints"],
            "volumes": rs["doc"]["volumes"],
            "secret_slots": rs["doc"]["secret_slots"],
            "env": rs["doc"]["env"],
            "readiness_probe": rs["doc"]["readiness_probe"],
        }
        for rs in resolved_services
    ]

    plan = {
        "schema_version": 1,
        "sandbox_type": sandbox_type_id,
        "tier": st["tier"],
        "topology": st["topology"],
        "base_image": base_image,
        "worker": {
            "id": worker["id"],
            "host_provider": host_provider["id"],
            "transport": transport["id"],
            "arch": arch,
            "os": worker["os"],
            "lease_limits": {**host_provider["lease_limits"], **worker["lease_limits"]},
        },
        "bundles": [b["id"] for b in bundles],
        "services": compiled_services,
        "remote_bindings": dict(sorted(remote_bindings.items())),
        "remote_write_grants": dict(sorted(effective_remote_write_grants.items())),
        "raw_remote_mounts": sorted(active_raw_remote_mounts),
        "broker_routes": dict(sorted(broker_routes.items())),
        "broker_client_env": dict(sorted(broker_client_env.items())),
        "endpoints": endpoints,
        "role_contract": role,
        "mise_tools": mise_tools,
        "toolchain_delivery": "image-mount" if worker_caps.get("supports_image_mounts") else "copy-layer",
    }

    # Hash IMMUTABLE Plan IR strictly BEFORE computing mutable drift!
    plan_digest = sha256_canonical_json(plan)
    drift = classify_drift(applied_plan, plan)

    closure_tuples = sorted(
        {
            ("sandbox-type", sandbox_type_id, store.get_revision("sandbox-type", sandbox_type_id)),
            ("worker", worker["id"], store.get_revision("worker", worker["id"])),
            ("host-provider", host_provider["id"], store.get_revision("host-provider", host_provider["id"])),
            ("transport", transport["id"], store.get_revision("transport", transport["id"])),
            *bundle_closure,
            *svc_closure,
        }
    )
    closure_digest = sha256_canonical_json(closure_tuples)

    return CompiledPlanResult(
        plan=plan,
        plan_digest=plan_digest,
        drift=drift,
        closure_digest=closure_digest,
    )


def _delta_sandbox_type(
    st_id: str, old_p: dict[str, Any] | None, new_p: dict[str, Any], triggers: set[str], details: list[dict[str, Any]]
) -> None:
    if old_p is None:
        if new_p["tier"] == "interactive" or new_p["topology"] == "pod-shared":
            triggers.add("security_profile_elevation")
            details.append({"trigger": "security_profile_elevation", "sandbox_type": st_id, "change": "new_elevated_tier_or_topology"})
        return
    if old_p["base_image"] != new_p["base_image"]:
        triggers.add("service_image_changed")
        details.append({"trigger": "service_image_changed", "sandbox_type": st_id, "service": "base_image"})
    if old_p["tier"] == "managed" and new_p["tier"] == "interactive":
        triggers.add("security_profile_elevation")
        details.append({"trigger": "security_profile_elevation", "sandbox_type": st_id, "change": "tier:managed->interactive"})
    if old_p["topology"] == "isolated-sidecars" and new_p["topology"] == "pod-shared":
        triggers.add("security_profile_elevation")
        details.append({"trigger": "security_profile_elevation", "sandbox_type": st_id, "change": "topology:isolated-sidecars->pod-shared"})


def _delta_service_pair(
    st_id: str, key: str, osvc: dict[str, Any], ns: dict[str, Any], triggers: set[str], details: list[dict[str, Any]]
) -> None:
    if security_profile_elevates(osvc["security_profile"], ns["security_profile"]):
        triggers.add("security_profile_elevation")
        details.append({"trigger": "security_profile_elevation", "sandbox_type": st_id, "service": key, "from": osvc["security_profile"], "to": ns["security_profile"]})
    if osvc["image"] != ns["image"]:
        triggers.add("service_image_changed")
        details.append({"trigger": "service_image_changed", "sandbox_type": st_id, "service": key})
    if (
        parse_mem_bytes(ns["resources"]["memory"]) > parse_mem_bytes(osvc["resources"]["memory"])
        or ns["resources"]["pids_limit"] > osvc["resources"]["pids_limit"]
    ):
        triggers.add("resource_limit_increased")
        details.append({"trigger": "resource_limit_increased", "sandbox_type": st_id, "service": key})
    if {s["slot"] for s in ns["secret_slots"]} - {s["slot"] for s in osvc["secret_slots"]}:
        triggers.add("secret_slot_added")


def _delta_services(
    st_id: str, old_p: dict[str, Any] | None, new_p: dict[str, Any], triggers: set[str], details: list[dict[str, Any]]
) -> None:
    old_svcs = {s["key"]: s for s in (old_p["services"] if old_p else [])}
    for ns in new_p["services"]:
        key = ns["key"]
        osvc = old_svcs.get(key)
        if osvc is None:
            triggers.add("new_service_added")
            details.append({"trigger": "new_service_added", "sandbox_type": st_id, "service": key})
            if ns["security_profile"] != "standard":
                triggers.add("security_profile_elevation")
                details.append({"trigger": "security_profile_elevation", "sandbox_type": st_id, "service": key, "to": ns["security_profile"]})
            if ns["secret_slots"]:
                triggers.add("secret_slot_added")
        else:
            _delta_service_pair(st_id, key, osvc, ns, triggers, details)


def _delta_endpoints(
    old_p: dict[str, Any] | None, new_p: dict[str, Any], triggers: set[str]
) -> None:
    old_eps = {(e["service_key"], e["endpoint"]): e for e in (old_p["endpoints"] if old_p else [])}
    for ne in new_p["endpoints"]:
        oe = old_eps.get((ne["service_key"], ne["endpoint"]))
        if oe is None:
            if ne["exposure"] != "pod-only":
                triggers.add("exposure_widened")
            continue
        if (
            EXPOSURE_RANK[ne["exposure"]] > EXPOSURE_RANK[oe["exposure"]]
            or EXPOSURE_RANK[ne["max_exposure"]] > EXPOSURE_RANK[oe["max_exposure"]]
        ):
            triggers.add("exposure_widened")
        if oe["requires_auth"] != ne["requires_auth"] or oe["auth_enforcer"] != ne["auth_enforcer"]:
            triggers.add("auth_requirement_changed")


def _mcp_surface_widened(om: dict[str, Any], mcfg: dict[str, Any]) -> bool:
    return bool(
        set(mcfg["allowed_tools"]) - set(om["allowed_tools"])
        or mcfg.get("url") != om.get("url")
        or mcfg.get("artifact_id") != om.get("artifact_id")
        or mcfg.get("args") != om.get("args")
        or mcfg.get("headers") != om.get("headers")
        or mcfg.get("secret_env") != om.get("secret_env")
    )


def _delta_existing_mcp(
    st_id: str,
    mname: str,
    om: dict[str, Any],
    mcfg: dict[str, Any],
    new_slots: set[str],
    triggers: set[str],
    details: list[dict[str, Any]],
) -> None:
    added_slots = new_slots - extract_secret_slots(om.get("headers", {}), om.get("secret_env", {}))
    if added_slots:
        triggers.add("secret_slot_added")
        details.append({"trigger": "secret_slot_added", "sandbox_type": st_id, "mcp": mname, "slots": sorted(added_slots)})
    if mcfg.get("credential_delivery") == "raw-container-mount" and om.get("credential_delivery") != "raw-container-mount":
        triggers.add("raw_remote_secret_mounted")
        details.append({"trigger": "raw_remote_secret_mounted", "sandbox_type": st_id, "route": f"mcp:{mname}"})
    if _mcp_surface_widened(om, mcfg):
        triggers.add("mcp_tool_surface_widened")
        details.append({"trigger": "mcp_tool_surface_widened", "sandbox_type": st_id, "mcp": mname})


def _delta_mcp(
    st_id: str, old_p: dict[str, Any] | None, new_p: dict[str, Any], triggers: set[str], details: list[dict[str, Any]]
) -> None:
    old_mcp = old_p["role_contract"]["opencode_config"]["mcp"] if old_p else {}
    for mname, mcfg in new_p["role_contract"]["opencode_config"]["mcp"].items():
        new_slots = extract_secret_slots(mcfg.get("headers", {}), mcfg.get("secret_env", {}))
        if mname not in old_mcp:
            triggers.add("new_mcp_server_added")
            if new_slots:
                triggers.add("secret_slot_added")
                details.append({"trigger": "secret_slot_added", "sandbox_type": st_id, "mcp": mname, "slots": sorted(new_slots)})
            if mcfg.get("credential_delivery") == "raw-container-mount":
                triggers.add("raw_remote_secret_mounted")
                details.append({"trigger": "raw_remote_secret_mounted", "sandbox_type": st_id, "route": f"mcp:{mname}"})
            continue
        _delta_existing_mcp(st_id, mname, old_mcp[mname], mcfg, new_slots, triggers, details)


def _cidrs_widened(old_cidrs: list[str], new_cidrs: list[str]) -> bool:
    if not new_cidrs:
        return False
    old_nets = [ipaddress.ip_network(c, strict=True) for c in old_cidrs]
    for c in new_cidrs:
        net = ipaddress.ip_network(c, strict=True)
        if not any(net.subnet_of(on) for on in old_nets):
            return True
    return False


def _wire_policy_widened(old_wp: dict[str, Any] | None, new_wp: dict[str, Any] | None) -> bool:
    if new_wp is None:
        return False
    if old_wp is None:
        return True
    if set(old_wp.get("denied_paths", [])) - set(new_wp.get("denied_paths", [])):
        return True
    if new_wp.get("allow_rules", []) != old_wp.get("allow_rules", []):
        return True
    if set(new_wp.get("allowed_tools", [])) - set(old_wp.get("allowed_tools", [])):
        return True
    return False


def _broker_route_auth_changed(old_r: dict[str, Any], new_r: dict[str, Any]) -> bool:
    return (
        new_r.get("known_hosts_ref") != old_r.get("known_hosts_ref")
        or new_r.get("inbound_auth") != old_r.get("inbound_auth")
        or new_r.get("inbound_auth_header") != old_r.get("inbound_auth_header")
        or new_r.get("upstream_headers") != old_r.get("upstream_headers")
        or new_r.get("upstream_secret_env") != old_r.get("upstream_secret_env")
    )


def _broker_route_surface_widened(old_r: dict[str, Any], new_r: dict[str, Any]) -> bool:
    return (
        (bool(new_r.get("allow_streaming", False)) and not bool(old_r.get("allow_streaming", False)))
        or _wire_policy_widened(old_r.get("wire_policy"), new_r.get("wire_policy"))
        or bool(set(new_r.get("allowed_presets", [])) - set(old_r.get("allowed_presets", [])))
        or new_r.get("upstream_headers") != old_r.get("upstream_headers")
        or new_r.get("upstream_secret_env") != old_r.get("upstream_secret_env")
    )


def _delta_broker_route_pair(
    st_id: str,
    rid: str,
    old_r: dict[str, Any],
    new_r: dict[str, Any],
    triggers: set[str],
    details: list[dict[str, Any]],
) -> None:
    if new_r.get("credential_delivery") == "raw-container-mount" and old_r.get("credential_delivery") != "raw-container-mount":
        triggers.add("raw_remote_secret_mounted")
        details.append({"trigger": "raw_remote_secret_mounted", "sandbox_type": st_id, "route": rid})
    if new_r.get("upstream") != old_r.get("upstream") or _cidrs_widened(
        old_r.get("allowed_cidrs", []), new_r.get("allowed_cidrs", [])
    ):
        triggers.add("remote_endpoint_added")
        details.append({"trigger": "remote_endpoint_added", "sandbox_type": st_id, "route": rid})
    if new_r.get("access_mode") != old_r.get("access_mode") and new_r.get("access_mode") in ("remote-rw", "rw"):
        triggers.add("remote_write_granted")
        details.append({"trigger": "remote_write_granted", "sandbox_type": st_id, "route": rid})
    added_slots = set(new_r.get("secret_slots", [])) - set(old_r.get("secret_slots", []))
    if added_slots or (new_r.get("secret_ref") and new_r.get("secret_ref") != old_r.get("secret_ref")):
        triggers.add("secret_slot_added")
        details.append({"trigger": "secret_slot_added", "sandbox_type": st_id, "route": rid})
    if _broker_route_auth_changed(old_r, new_r):
        triggers.add("auth_requirement_changed")
        details.append({"trigger": "auth_requirement_changed", "sandbox_type": st_id, "route": rid})
    if _broker_route_surface_widened(old_r, new_r):
        triggers.add("mcp_tool_surface_widened")
        details.append({"trigger": "mcp_tool_surface_widened", "sandbox_type": st_id, "route": rid})


def _delta_broker_routes(
    st_id: str, old_p: dict[str, Any] | None, new_p: dict[str, Any], triggers: set[str], details: list[dict[str, Any]]
) -> None:
    old_routes = old_p.get("broker_routes", {}) if old_p else {}
    for rid, new_r in sorted(new_p.get("broker_routes", {}).items()):
        old_r = old_routes.get(rid)
        if old_r is None:
            triggers.add("remote_endpoint_added")
            details.append({"trigger": "remote_endpoint_added", "sandbox_type": st_id, "route": rid})
            if new_r.get("credential_delivery") == "raw-container-mount":
                triggers.add("raw_remote_secret_mounted")
                details.append({"trigger": "raw_remote_secret_mounted", "sandbox_type": st_id, "route": rid})
            if new_r.get("access_mode") in ("remote-rw", "rw"):
                triggers.add("remote_write_granted")
                details.append({"trigger": "remote_write_granted", "sandbox_type": st_id, "route": rid})
            if new_r.get("secret_slots") or new_r.get("secret_ref"):
                triggers.add("secret_slot_added")
                details.append({"trigger": "secret_slot_added", "sandbox_type": st_id, "route": rid})
        else:
            _delta_broker_route_pair(st_id, rid, old_r, new_r, triggers, details)


def _delta_misc(
    st_id: str, old_p: dict[str, Any] | None, new_p: dict[str, Any], triggers: set[str], details: list[dict[str, Any]]
) -> None:
    old_mise = old_p["mise_tools"] if old_p else {}
    if any(k not in old_mise or old_mise[k] != v for k, v in new_p["mise_tools"].items()):
        triggers.add("new_mise_tool_added")
    old_persona = old_p["role_contract"]["primary_persona"] if old_p else None
    if old_persona != new_p["role_contract"]["primary_persona"]:
        triggers.add("persona_changed")
    old_rem = old_p["remote_bindings"] if old_p else {}
    if any(k not in old_rem or old_rem[k] != v for k, v in new_p["remote_bindings"].items()):
        triggers.add("remote_endpoint_added")
    old_rw = old_p.get("remote_write_grants", {}) if old_p else {}
    for mname, url in new_p.get("remote_write_grants", {}).items():
        if old_rw.get(mname) != url:
            triggers.add("remote_write_granted")
            details.append({"trigger": "remote_write_granted", "sandbox_type": st_id, "mcp": mname, "url": url})
    old_raw_mounts = set(old_p.get("raw_remote_mounts", [])) if old_p else set()
    for rid in sorted(set(new_p.get("raw_remote_mounts", [])) - old_raw_mounts):
        triggers.add("raw_remote_secret_mounted")
        details.append({"trigger": "raw_remote_secret_mounted", "sandbox_type": st_id, "route": rid})


def compute_closed_security_delta(
    old_plans: dict[str, CompiledPlanResult],
    new_plans: dict[str, CompiledPlanResult],
) -> dict[str, Any]:
    """Compute the exact closed set of PRD L security_delta triggers."""
    triggers: set[str] = set()
    details: list[dict[str, Any]] = []

    for st_id in sorted(set(old_plans) | set(new_plans)):
        old_p = old_plans[st_id].plan if st_id in old_plans else None
        new_p = new_plans[st_id].plan if st_id in new_plans else None
        if new_p is None:
            continue
        _delta_sandbox_type(st_id, old_p, new_p, triggers, details)
        _delta_services(st_id, old_p, new_p, triggers, details)
        _delta_endpoints(old_p, new_p, triggers)
        _delta_mcp(st_id, old_p, new_p, triggers, details)
        _delta_broker_routes(st_id, old_p, new_p, triggers, details)
        _delta_misc(st_id, old_p, new_p, triggers, details)

    summary = {"triggers": sorted(triggers), "details": details}
    return {**summary, "digest": sha256_canonical_json(summary)}


def redact_plan_summary(result: CompiledPlanResult) -> dict[str, Any]:
    """Return an orchestrator-safe summary omitting host paths, vault IDs, and private worker addresses."""
    p = result.plan
    return {
        "plan_digest": result.plan_digest,
        "drift": result.drift,
        "sandbox_type": p["sandbox_type"],
        "tier": p["tier"],
        "topology": p["topology"],
        "worker": {
            "id": p["worker"]["id"],
            "host_provider": p["worker"]["host_provider"],
            "transport": p["worker"]["transport"],
            "arch": p["worker"]["arch"],
            "os": p["worker"]["os"],
        },
        "bundles": p["bundles"],
        "services": [
            {
                "key": s["key"],
                "id": s["id"],
                "dependencies": s["dependencies"],
                "security_profile": s["security_profile"],
                "resources": s["resources"],
                "secret_slot_names": [sl["slot"] for sl in s["secret_slots"]],
            }
            for s in p["services"]
        ],
        "endpoints": [
            {
                "service": e["service_key"],
                "endpoint": e["endpoint"],
                "port": e["port"],
                "exposure": e["exposure"],
                "requires_auth": e["requires_auth"],
                "tls_policy": e["tls_policy"],
            }
            for e in p["endpoints"]
        ],
        "default_agent": p["role_contract"]["default_agent"],
        "skills": p["role_contract"]["skills"],
        "mcp_servers": {
            k: {
                "type": v["type"],
                "access_mode": v.get("access_mode", "local"),
                "credential_delivery": v.get("credential_delivery", "local-ephemeral"),
                "allowed_tools": v["allowed_tools"],
            }
            for k, v in p["role_contract"]["opencode_config"]["mcp"].items()
        },
        "broker_routes": {
            rid: {
                "kind": r["kind"],
                "credential_delivery": r["credential_delivery"],
                "access_mode": r["access_mode"],
                "allow_streaming": bool(r.get("allow_streaming", False)),
            }
            for rid, r in sorted(p.get("broker_routes", {}).items())
        },
        "broker_client_env_keys": sorted(p.get("broker_client_env", {}).keys()),
        "raw_remote_mounts": list(p.get("raw_remote_mounts", [])),
        "remote_write_granted_mcps": sorted(p.get("remote_write_grants", {}).keys()),
        "mise_tools": p["mise_tools"],
        "toolchain_delivery": p["toolchain_delivery"],
    }
