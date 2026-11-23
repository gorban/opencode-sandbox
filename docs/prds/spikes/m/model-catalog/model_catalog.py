"""In-process proof of host-owned model and reasoning variant policy."""

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import cast


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class Denied(Exception):
    """The current host lease does not authorize the selection."""


class InvalidInput(Exception):
    """The synthetic request, profile, or catalog is invalid."""


def _require_identifiers(*values: object) -> None:
    if any(type(value) is not str or not _IDENTIFIER.fullmatch(value) for value in values):
        raise InvalidInput


@dataclass(frozen=True)
class Reasoning:
    effort: str
    summary: str

    def __post_init__(self) -> None:
        _require_identifiers(self.effort, self.summary)

    @classmethod
    def from_options(cls, options: object) -> "Reasoning":
        if not isinstance(options, Mapping) or options.keys() != {"effort", "summary"}:
            raise InvalidInput
        return cls(effort=options["effort"], summary=options["summary"])

    def to_wire(self) -> dict:
        return {"effort": self.effort, "summary": self.summary}


@dataclass(frozen=True)
class ModelCatalog:
    """The proof catalog holds one route/model descriptor."""

    route: str
    model: str
    context_limit: int
    output_limit: int
    variants: tuple[tuple[str, Reasoning], ...]

    def __post_init__(self) -> None:
        _require_identifiers(self.route, self.model)
        if type(self.context_limit) is not int or type(self.output_limit) is not int:
            raise InvalidInput
        if not 0 < self.output_limit <= self.context_limit:
            raise InvalidInput
        if type(self.variants) is not tuple or not self.variants:
            raise InvalidInput
        seen: set[str] = set()
        for entry in self.variants:
            if type(entry) is not tuple or len(entry) != 2:
                raise InvalidInput
            variant, options = entry
            _require_identifiers(variant)
            if variant in seen or type(options) is not Reasoning:
                raise InvalidInput
            seen.add(variant)


@dataclass(frozen=True)
class AgentGrant:
    agent: str
    variants: frozenset[str]


@dataclass(frozen=True)
class Lease:
    active: bool
    job: str
    route: str
    model: str
    grants: tuple[AgentGrant, ...]


@dataclass(frozen=True)
class AgentProfile:
    agent: str
    model: str
    variant: str | None = None


@dataclass(frozen=True)
class Projection:
    route: str
    model: str
    context_limit: int
    output_limit: int
    variants: tuple[str, ...]
    agents: tuple[AgentProfile, ...]

    def to_worker_config(self) -> dict:
        model_id = f"{self.route}/{self.model}"
        model = {
            "limit": {"context": self.context_limit, "output": self.output_limit},
            "variants": {variant: {"x_oc_effort": variant} for variant in self.variants},
        }
        return {
            "env": {"OPENCODE_DISABLE_MODELS_DEV": "1"},
            "opencode": {
                "provider": {self.route: {"models": {self.model: model}}},
                "agent": {
                    entry.agent: {"model": model_id, "variant": entry.variant}
                    for entry in self.agents
                },
            },
        }


@dataclass(frozen=True)
class Lowered:
    model: str
    reasoning: Reasoning

    def to_wire(self) -> dict:
        return {"model": self.model, "reasoning": self.reasoning.to_wire()}


def _active_lease(lease: Lease | None, host_job: str) -> Lease:
    if lease is None:
        raise Denied
    if type(lease) is not Lease:
        raise InvalidInput
    if lease.active is not True:
        raise Denied
    if type(lease.job) is not str or type(host_job) is not str:
        raise InvalidInput
    if lease.job != host_job:
        raise Denied
    return lease


def _catalog_for_lease(catalog: ModelCatalog | None, lease: Lease) -> ModelCatalog:
    if type(catalog) is not ModelCatalog or (catalog.route, catalog.model) != (lease.route, lease.model):
        raise InvalidInput
    return catalog


def _lease_grants(lease: Lease) -> dict[str, frozenset[str]]:
    if type(lease.grants) is not tuple:
        raise InvalidInput
    grants: dict[str, frozenset[str]] = {}
    for grant in lease.grants:
        if type(grant) is not AgentGrant:
            raise InvalidInput
        _require_identifiers(grant.agent)
        if grant.agent in grants:
            raise InvalidInput
        grants[grant.agent] = grant.variants
    return grants


def _validate_grants(grants: dict[str, frozenset[str]], variants: dict[str, Reasoning]) -> None:
    for allowed in grants.values():
        if type(allowed) is not frozenset or not allowed:
            raise InvalidInput
        for variant in allowed:
            _require_identifiers(variant)
        if not allowed.issubset(variants):
            raise InvalidInput


def _grant_for_agent(grants: dict[str, frozenset[str]], agent: str) -> frozenset[str]:
    if agent not in grants:
        raise Denied
    return grants[agent]


def _require_variant(
    variants: dict[str, Reasoning],
    grant: frozenset[str],
    variant: str,
) -> Reasoning:
    reasoning = variants.get(variant)
    if reasoning is None:
        raise InvalidInput
    if variant not in grant:
        raise Denied
    return reasoning


def _validate_profile(profile: tuple[AgentProfile, ...]) -> None:
    if type(profile) is not tuple or not profile:
        raise InvalidInput
    agents: set[str] = set()
    for entry in profile:
        if type(entry) is not AgentProfile:
            raise InvalidInput
        _require_identifiers(entry.agent, entry.model, entry.variant)
        if entry.agent in agents:
            raise InvalidInput
        agents.add(entry.agent)


def project(
    catalog: ModelCatalog | None,
    lease: Lease | None,
    host_job: str,
    profile: tuple[AgentProfile, ...],
) -> Projection:
    lease = _active_lease(lease, host_job)
    _require_identifiers(lease.job, lease.route, lease.model)
    catalog = _catalog_for_lease(catalog, lease)
    variants = dict(catalog.variants)
    grants = _lease_grants(lease)
    _validate_grants(grants, variants)
    _validate_profile(profile)
    visible_variants: set[str] = set()
    for entry in profile:
        if entry.model != lease.model:
            raise Denied
        grant = _grant_for_agent(grants, entry.agent)
        _require_variant(variants, grant, entry.variant)
        visible_variants.update(grant)
    return Projection(
        route=lease.route,
        model=lease.model,
        context_limit=catalog.context_limit,
        output_limit=catalog.output_limit,
        variants=tuple(sorted(visible_variants)),
        agents=profile,
    )


def lower(
    catalog: ModelCatalog | None,
    lease: Lease | None,
    host_job: str,
    host_agent: str,
    route: str,
    request: object,
) -> Lowered:
    lease = _active_lease(lease, host_job)
    if type(lease.route) is not str or type(route) is not str:
        raise InvalidInput
    if lease.route != route:
        raise Denied
    if type(request) is not dict:
        raise InvalidInput
    body: dict = cast(dict, request)
    if len(body) != 2 or any(type(key) is not str for key in body):
        raise InvalidInput
    if body.keys() != {"model", "x_oc_effort"}:
        raise InvalidInput
    model = body["model"]
    variant = body["x_oc_effort"]
    _require_identifiers(lease.job, lease.route, lease.model, model, variant, host_agent)
    if model != lease.model:
        raise Denied
    grants = _lease_grants(lease)
    grant = _grant_for_agent(grants, host_agent)
    catalog = _catalog_for_lease(catalog, lease)
    variants = dict(catalog.variants)
    _validate_grants(grants, variants)
    return Lowered(model, _require_variant(variants, grant, variant))
