"""Pure-Python Plan Compiler for PRD L spike PoC.

Compiles host-trusted declarative TOML specs (sandbox-type, bundle, service,
host-provider, transport, worker) into an immutable Plan IR + plan_digest.
Zero side effects, zero Python factory imports during planning.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from oc_schema import (
    CAPABILITY_PROVIDES_RE,
    CAPABILITY_REQUIRES_RE,
    EXPOSURE_RANK,
    MAX_INSTRUCTIONS_TOTAL_BYTES,
    MAX_MISE_MANIFESTS,
    MAX_MISE_TOOLS,
    MAX_SLOT_FILE_BYTES,
    SLOT_TOKEN_RE,
    PolicyError,
    SchemaError,
    capability_satisfies,
    is_builtin_id,
    parse_mem_bytes,
    read_regular_no_follow,
    render_host_url,
    security_profile_allows_fallback,
    security_profile_elevates,
    sha256_canonical_json,
    validate_opaque_id,
    validate_remote_endpoint_url,
)


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
    allow_http_remote: bool = False
    allowed_remote_hosts: frozenset[str] = frozenset()


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
    state: dict[str, int] = {}  # 0=unvisited, 1=visiting, 2=done
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


def _check_no_builtin_capability_downgrade(store: PlanStoreView, svc: dict[str, Any]) -> None:
    """Prevent non-builtin services from claiming a builtin/* capability with weaker security."""
    if is_builtin_id(svc["id"]):
        return
    builtin_services = [
        store.get("service", sid) for sid in store.list_ids("service") if is_builtin_id(sid)
    ]
    for cap in svc["provides"]:
        cm = CAPABILITY_PROVIDES_RE.fullmatch(cap)
        if not cm:
            continue
        cap_name = cm.group(1)
        for bsvc in builtin_services:
            for bcap in bsvc["provides"]:
                bcm = CAPABILITY_PROVIDES_RE.fullmatch(bcap)
                if not bcm or bcm.group(1) != cap_name:
                    continue
                b_eps = {ep["port"]: ep for ep in bsvc["endpoints"]}
                for ep in svc["endpoints"]:
                    bep = b_eps.get(ep["port"])
                    if bep is None:
                        continue
                    if bep["requires_auth"] and not ep["requires_auth"]:
                        raise PolicyError(
                            f"Service {svc['id']!r} cannot provide {cap_name} with weakened requires_auth"
                        )
                    if EXPOSURE_RANK[ep["max_exposure"]] > EXPOSURE_RANK[bep["max_exposure"]]:
                        raise PolicyError(
                            f"Service {svc['id']!r} cannot provide {cap_name} with widened max_exposure"
                        )
                    if bep["auth_enforcer"] and ep["auth_enforcer"] != bep["auth_enforcer"]:
                        raise PolicyError(
                            f"Service {svc['id']!r} cannot replace builtin auth_enforcer {bep['auth_enforcer']!r}"
                        )


def _worker_satisfies(worker_caps: dict[str, Any], required_caps: list[str]) -> bool:
    for rc in required_caps:
        if not bool(worker_caps.get(rc, False)):
            return False
    return True


def _select_service_for_requirement(
    store: PlanStoreView,
    req: dict[str, Any],
    worker_caps: dict[str, Any],
) -> tuple[dict[str, Any], str | None]:
    target = req["target"]
    explicit_provider = req.get("provider")
    instance_alias = req.get("instance")

    if CAPABILITY_REQUIRES_RE.fullmatch(target):
        if explicit_provider is not None:
            cand = store.get("service", explicit_provider)
            if not any(capability_satisfies(p, target) for p in cand["provides"]):
                raise PlanError(
                    f"Explicit provider {explicit_provider!r} does not satisfy {target!r}"
                )
            primary = cand
        else:
            matches = []
            for sid in sorted(store.list_ids("service")):
                sdoc = store.get("service", sid)
                if any(capability_satisfies(p, target) for p in sdoc["provides"]):
                    matches.append(sdoc)
            if not matches:
                raise PlanError(f"Unsatisfied capability requirement: {target!r}")
            if len(matches) > 1:
                names = ", ".join(m["id"] for m in matches)
                raise PlanError(
                    f"Ambiguous providers for capability {target!r} ({names}); specify explicit provider"
                )
            primary = matches[0]
    else:
        primary = store.get("service", target)

    _check_no_builtin_capability_downgrade(store, primary)

    # Capability-aware fallback selection INSIDE DAG resolution
    if not _worker_satisfies(worker_caps, primary["required_capabilities"]):
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
        primary = fb

    if instance_alias is not None and primary["cardinality"] != "named-instance":
        raise PlanError(
            f"Service {primary['id']!r} has cardinality={primary['cardinality']!r}, cannot bind instance {instance_alias!r}"
        )
    if primary["cardinality"] == "named-instance" and instance_alias is None:
        instance_alias = primary["id"].replace("/", "-")
    return primary, instance_alias


def _resolve_service_dag(
    store: PlanStoreView,
    active_roots: list[dict[str, Any]],
    worker_caps: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[tuple[str, str, int]]]:
    """Resolve recursive service DAG with fallback selection, diamond checks, and Kahn sort."""
    selected: dict[str, dict[str, Any]] = {}  # key -> resolved node
    deps_of: dict[str, set[str]] = {}
    cap_constraints: dict[str, list[str]] = {}  # service_key -> all capability constraints targeting it
    visiting: list[str] = []

    def resolve_req(req: dict[str, Any]) -> str:
        svc, inst = _select_service_for_requirement(store, req, worker_caps)
        node_key = f"{svc['id']}@{inst}" if inst else svc["id"]
        if CAPABILITY_REQUIRES_RE.fullmatch(req["target"]):
            cap_constraints.setdefault(node_key, []).append(req["target"])
            # Verify diamond compatibility against all existing constraints on this node
            for c in cap_constraints[node_key]:
                if not any(capability_satisfies(p, c) for p in svc["provides"]):
                    raise PlanError(f"Incompatible diamond constraint {c!r} on {node_key!r}")
        if node_key in visiting:
            cycle = " -> ".join(visiting[visiting.index(node_key) :] + [node_key])
            raise PlanError(f"Cycle detected in service dependencies: {cycle}")
        if node_key in selected:
            return node_key
        visiting.append(node_key)
        node_deps: set[str] = set()
        for child_req in svc["requires"]:
            child_key = resolve_req(child_req)
            node_deps.add(child_key)
        visiting.pop()
        selected[node_key] = {
            "key": node_key,
            "instance": inst,
            "doc": svc,
        }
        deps_of[node_key] = node_deps
        return node_key

    for root in active_roots:
        resolve_req(root)

    # Check diamond conflict: two different services claiming same singleton capability
    singleton_cap_owner: dict[str, str] = {}
    for key, node in sorted(selected.items()):
        svc = node["doc"]
        if svc["cardinality"] == "singleton":
            for cap in svc["provides"]:
                cap_name = CAPABILITY_PROVIDES_RE.fullmatch(cap).group(1)  # type: ignore[union-attr]
                prev = singleton_cap_owner.get(cap_name)
                if prev is not None and prev != key:
                    raise PlanError(
                        f"Diamond conflict: both {prev!r} and {key!r} provide singleton capability {cap_name!r}"
                    )
                singleton_cap_owner[cap_name] = key

    # Kahn topological sort (dependencies before dependents; deterministic lexical tie-breaking)
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

    # Pod port-collision validation across all resolved services (accounting for named-instance ports)
    used_pod_ports: dict[int, str] = {}
    resolved_services: list[dict[str, Any]] = []
    closure: list[tuple[str, str, int]] = []
    seen_svc_ids: set[str] = set()
    for key in ordered_keys:
        node = selected[key]
        svc = node["doc"]
        inst = node["instance"]
        effective_endpoints = []
        for idx, ep in enumerate(svc["endpoints"]):
            port = ep["port"]
            if svc["cardinality"] == "named-instance" and svc.get("instance_port") is not None and idx == 0:
                port = svc["instance_port"]
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
                "instance": inst,
                "dependencies": sorted(deps_of[key]),
                "doc": svc,
                "endpoints": effective_endpoints,
            }
        )
        if svc["id"] not in seen_svc_ids:
            seen_svc_ids.add(svc["id"])
            closure.append(("service", svc["id"], store.get_revision("service", svc["id"])))

    return resolved_services, closure


def _compile_endpoints(
    resolved_services: list[dict[str, Any]],
    type_ports: list[dict[str, Any]],
    cli_ports: tuple[dict[str, Any], ...],
) -> list[dict[str, Any]]:
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
            by_svc_ep[(rsvc["id"], ep["name"])] = entry
            by_svc_ep[(rsvc["key"], ep["name"])] = entry
            out.append(entry)

    used_host_ports: dict[int, str] = {}
    for req in list(type_ports) + list(cli_ports):
        svc_ref = req["service"]
        ep_name = req["endpoint"]
        desired_exp = req.get("exposure", "host-loopback")
        host_port = req.get("host_port")
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
            if host_port in used_host_ports and used_host_ports[host_port] != f"{svc_ref}:{ep_name}":
                raise PlanError(f"Duplicate host_port {host_port}")
            used_host_ports[host_port] = f"{svc_ref}:{ep_name}"
        entry["exposure"] = desired_exp
        entry["host_port"] = host_port

    # Validate any host_url_template rendering cleanly with safe sample placeholders
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


def _compile_role_contract(
    store: PlanStoreView,
    bundles: list[dict[str, Any]],
    default_agent_override: str | None,
    resolved_services: list[dict[str, Any]],
    remote_bindings: dict[str, str],
    tier: str,
) -> dict[str, Any]:
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

        if b["persona"] is not None:
            if primary_persona is not None and "persona" not in replace_set:
                raise PlanError(
                    f"Conflicting primary persona between {primary_owner!r} and {bid!r}; "
                    f"declare [composition] replace = ['persona'] explicitly"
                )
            if primary_persona is not None and primary_owner and is_builtin_id(primary_owner):
                # Replacing persona is allowed (user can specialize a builtin persona),
                # but builtin security invariants in services remain untouched.
                pass
            primary_persona = {
                **b["persona"],
                "mission": _expand_slots_single_pass(
                    b["persona"]["mission"], bid, b["prompt_slots"], broot
                ),
            }
            primary_owner = bid

        for sa in b["subagents"]:
            if sa["name"] in subagents and subagents[sa["name"]] != sa:
                raise PlanError(f"Conflicting subagent definition {sa['name']!r} in {bid!r}")
            subagents[sa["name"]] = sa

        for idx, raw_instr in enumerate(b["instructions"]):
            expanded = _expand_slots_single_pass(raw_instr, bid, b["prompt_slots"], broot)
            total_instr_bytes += len(expanded.encode("utf-8"))
            if total_instr_bytes > MAX_INSTRUCTIONS_TOTAL_BYTES:
                raise SchemaError(
                    f"Compiled instructions exceed {MAX_INSTRUCTIONS_TOTAL_BYTES} byte cap"
                )
            instructions.append(
                {
                    "path": f"/run/oc-config/instructions/{len(instructions):02d}-{bid.replace('/', '-')}-{idx}.md",
                    "source_bundle": bid,
                    "content": expanded,
                }
            )

        for skill_id in b["skills"]:
            if skill_id in skills and skills[skill_id] != bid:
                raise PlanError(f"Duplicate skill {skill_id!r} contributed by {skills[skill_id]!r} and {bid!r}")
            skills[skill_id] = bid

        for mname, mcfg in b["mcp"].items():
            effective_cfg = dict(mcfg)
            if mcfg["local"] is not None:
                bkey = mcfg["local"]["binding_key"]
                if bkey in remote_bindings:
                    effective_cfg["url"] = remote_bindings[bkey]
                else:
                    effective_cfg["url"] = mcfg["local"]["url"]
            if mname in mcp_servers and mcp_servers[mname] != effective_cfg:
                if "mcp" not in replace_set:
                    raise PlanError(
                        f"Conflicting MCP server {mname!r} between {mcp_owners[mname]!r} and {bid!r}; "
                        f"declare [composition] replace = ['mcp']"
                    )
            mcp_servers[mname] = effective_cfg
            mcp_owners[mname] = bid

    # Apply persona role filtering to MCP tool surface
    filtered_mcp: dict[str, dict[str, Any]] = {}
    allow_set = (
        set(primary_persona["allowed_mcp_tools"])
        if primary_persona and primary_persona["allowed_mcp_tools"] is not None
        else None
    )
    deny_set = set(primary_persona["denied_mcp_tools"]) if primary_persona else set()
    for mname, mcfg in sorted(mcp_servers.items()):
        tools = list(mcfg["tools"])
        if allow_set is not None:
            tools = [t for t in tools if f"{mname}.{t}" in allow_set or t in allow_set]
        if deny_set:
            tools = [t for t in tools if f"{mname}.{t}" not in deny_set and t not in deny_set]
        if allow_set is not None and mcfg["tools"] and not tools:
            continue
        filtered_mcp[mname] = {
            "type": mcfg["type"],
            "url": mcfg["url"],
            "artifact_id": mcfg["artifact_id"],
            "args": mcfg["args"],
            "headers": mcfg["headers"],
            "secret_env": mcfg["secret_env"],
            "allowed_tools": tools,
        }

    # Auto-generate SERVICES.md from resolved services (never drifts)
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
    services_md = "\n".join(service_lines) + "\n"

    default_agent = default_agent_override or (primary_persona["name"] if primary_persona else "default")
    opencode_config = {
        "$schema": "https://opencode.ai/config.json",
        "default_agent": default_agent,
        "instructions": [ins["path"] for ins in instructions] + ["/run/oc-config/SERVICES.md"],
        "mcp": filtered_mcp,
        "managed_workspace_lockout": tier == "managed",
    }

    return {
        "default_agent": default_agent,
        "primary_persona": primary_persona,
        "subagents": [subagents[k] for k in sorted(subagents)],
        "instructions": instructions,
        "services_md": services_md,
        "skills": sorted(skills.keys()),
        "opencode_config": opencode_config,
    }


def _merge_mise_tools(
    bundles: list[dict[str, Any]],
    resolved_services: list[dict[str, Any]],
    overrides: dict[str, str],
) -> dict[str, str]:
    manifest_count = 0
    merged: dict[str, tuple[str, str]] = {}  # tool -> (version, source)
    sources = [(b["id"], b["mise_tools"]) for b in bundles] + [
        (rs["id"], rs["doc"]["mise_tools"]) for rs in resolved_services
    ]
    for src_id, tools in sources:
        if not tools:
            continue
        manifest_count += 1
        if manifest_count > MAX_MISE_MANIFESTS:
            raise PlanError(f"Too many mise manifests (max {MAX_MISE_MANIFESTS})")
        for tool, ver in tools.items():
            if tool in overrides:
                continue
            prev = merged.get(tool)
            if prev is not None and prev[0] != ver:
                raise PlanError(
                    f"Conflicting mise tool pins for {tool!r}: {prev[1]}={prev[0]!r} vs {src_id}={ver!r}"
                )
            merged[tool] = (ver, src_id)
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


def classify_drift(applied_plan: dict[str, Any] | None, desired_plan: dict[str, Any]) -> dict[str, Any]:
    if applied_plan is None:
        return {"kind": "fresh", "reasons": ["no_applied_plan"]}
    if applied_plan == desired_plan:
        return {"kind": "none", "reasons": []}

    reasons: list[str] = []
    # Check stateful volume / durable service changes first -> fail-closed migration required
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

    # Check if only role instructions/skills changed (hot-safe) vs container/ports/tools (recreate-stateless)
    stripped_old = {k: v for k, v in applied_plan.items() if k != "role_contract"}
    stripped_new = {k: v for k, v in desired_plan.items() if k != "role_contract"}
    if stripped_old == stripped_new:
        return {"kind": "hot-safe", "reasons": ["role_contract_updated"]}
    return {"kind": "recreate-stateless", "reasons": ["runtime_plan_changed"]}


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
    eff_worker_id = worker_id or st["default_worker"]
    validate_opaque_id(eff_worker_id, label="worker")
    worker = store.get("worker", eff_worker_id)
    host_provider = store.get("host-provider", worker["host_provider"])
    transport = store.get("transport", worker["transport"])

    worker_caps = {**host_provider["capabilities"], **worker["capabilities_override"]}
    arch = worker["arch"]

    bundles, bundle_closure = _resolve_bundle_dag(store, st["bundles"], ov.with_mods, ov.without_mods)

    # Collect active roots with [local] conditional pruning + remote endpoint policy
    active_roots: list[dict[str, Any]] = []
    remote_bindings: dict[str, str] = {}
    for b in bundles:
        for req in b["requires_services"]:
            active_roots.append(req)
        for lsvc in b["local_services"]:
            bkey = lsvc["binding_key"]
            ext = ov.env_bindings.get(bkey, "")
            if ext:
                validated = validate_remote_endpoint_url(
                    ext,
                    allow_http=ov.allow_http_remote,
                    allowed_hosts=ov.allowed_remote_hosts,
                )
                remote_bindings[bkey] = validated
            else:
                active_roots.append(
                    {"target": lsvc["service"], "provider": None, "instance": lsvc["instance"]}
                )
        for mcfg in b["mcp"].values():
            if mcfg["local"] is not None:
                bkey = mcfg["local"]["binding_key"]
                ext = ov.env_bindings.get(bkey, "")
                if ext:
                    validated = validate_remote_endpoint_url(
                        ext,
                        allow_http=ov.allow_http_remote,
                        allowed_hosts=ov.allowed_remote_hosts,
                    )
                    remote_bindings[bkey] = validated
                else:
                    active_roots.append(
                        {"target": mcfg["local"]["service"], "provider": None, "instance": None}
                    )

    if active_roots and not bool(worker_caps.get("supports_pods", False)):
        raise PlanError(
            f"Worker {eff_worker_id!r} ({host_provider['id']}) has supports_pods=false; "
            f"cannot run sidecar services"
        )

    resolved_services, svc_closure = _resolve_service_dag(store, active_roots, worker_caps)
    endpoints = _compile_endpoints(resolved_services, st["ports"], ov.cli_ports)
    role = _compile_role_contract(
        store, bundles, st["default_agent"], resolved_services, remote_bindings, st["tier"]
    )
    mise_tools = _merge_mise_tools(bundles, resolved_services, st["mise_overrides"])

    base_image = _bind_image_for_arch(
        st["base_image"], st["base_images_by_arch"], arch, f"sandbox-type({sandbox_type_id})"
    )

    compiled_services = []
    for rs in resolved_services:
        sdoc = rs["doc"]
        compiled_services.append(
            {
                "key": rs["key"],
                "id": rs["id"],
                "instance": rs["instance"],
                "dependencies": rs["dependencies"],
                "image": _bind_image_for_arch(
                    sdoc["image"], sdoc["images_by_arch"], arch, f"service({sdoc['id']})"
                ),
                "security_profile": sdoc["security_profile"],
                "factory_id": sdoc["factory_id"],
                "resources": sdoc["resources"],
                "endpoints": rs["endpoints"],
                "volumes": sdoc["volumes"],
                "secret_slots": sdoc["secret_slots"],
                "env": sdoc["env"],
                "readiness_probe": sdoc["readiness_probe"],
            }
        )

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
        "endpoints": endpoints,
        "role_contract": role,
        "mise_tools": mise_tools,
        "toolchain_delivery": "image-mount" if worker_caps.get("supports_image_mounts") else "copy-layer",
    }

    # Hash IMMUTABLE Plan IR strictly BEFORE computing mutable drift!
    plan_digest = sha256_canonical_json(plan)
    drift = classify_drift(applied_plan, plan)

    closure_tuples = sorted(
        set(
            [
                ("sandbox-type", sandbox_type_id, store.get_revision("sandbox-type", sandbox_type_id)),
                ("worker", worker["id"], store.get_revision("worker", worker["id"])),
                ("host-provider", host_provider["id"], store.get_revision("host-provider", host_provider["id"])),
                ("transport", transport["id"], store.get_revision("transport", transport["id"])),
                *bundle_closure,
                *svc_closure,
            ]
        )
    )
    closure_digest = sha256_canonical_json(closure_tuples)

    return CompiledPlanResult(
        plan=plan,
        plan_digest=plan_digest,
        drift=drift,
        closure_digest=closure_digest,
    )


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
        old_svcs = {s["key"]: s for s in (old_p["services"] if old_p else [])}
        new_svcs = {s["key"]: s for s in new_p["services"]}

        for key, ns in new_svcs.items():
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
                old_slots = {s["slot"] for s in osvc["secret_slots"]}
                new_slots = {s["slot"] for s in ns["secret_slots"]}
                if new_slots - old_slots:
                    triggers.add("secret_slot_added")

        old_eps = {(e["service_key"], e["endpoint"]): e for e in (old_p["endpoints"] if old_p else [])}
        for ne in new_p["endpoints"]:
            oe = old_eps.get((ne["service_key"], ne["endpoint"]))
            if oe is None:
                if ne["exposure"] != "pod-only":
                    triggers.add("exposure_widened")
            else:
                if EXPOSURE_RANK[ne["exposure"]] > EXPOSURE_RANK[oe["exposure"]] or EXPOSURE_RANK[ne["max_exposure"]] > EXPOSURE_RANK[oe["max_exposure"]]:
                    triggers.add("exposure_widened")
                if oe["requires_auth"] != ne["requires_auth"] or oe["auth_enforcer"] != ne["auth_enforcer"]:
                    triggers.add("auth_requirement_changed")

        old_mcp = (old_p["role_contract"]["opencode_config"]["mcp"] if old_p else {})
        new_mcp = new_p["role_contract"]["opencode_config"]["mcp"]
        for mname, mcfg in new_mcp.items():
            if mname not in old_mcp:
                triggers.add("new_mcp_server_added")
            elif set(mcfg["allowed_tools"]) - set(old_mcp[mname]["allowed_tools"]):
                triggers.add("mcp_tool_surface_widened")

        old_mise = old_p["mise_tools"] if old_p else {}
        if any(k not in old_mise or old_mise[k] != v for k, v in new_p["mise_tools"].items()):
            triggers.add("new_mise_tool_added")

        old_persona = old_p["role_contract"]["primary_persona"] if old_p else None
        if old_persona != new_p["role_contract"]["primary_persona"]:
            triggers.add("persona_changed")

        old_rem = old_p["remote_bindings"] if old_p else {}
        if any(k not in old_rem or old_rem[k] != v for k, v in new_p["remote_bindings"].items()):
            triggers.add("remote_endpoint_added")

    summary = {
        "triggers": sorted(triggers),
        "details": details,
    }
    return {
        **summary,
        "digest": sha256_canonical_json(summary),
    }


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
            k: {"type": v["type"], "allowed_tools": v["allowed_tools"]}
            for k, v in p["role_contract"]["opencode_config"]["mcp"].items()
        },
        "mise_tools": p["mise_tools"],
        "toolchain_delivery": p["toolchain_delivery"],
    }
