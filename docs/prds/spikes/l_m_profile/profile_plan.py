"""Translate only the two reviewed PRD L fixture plans into local image selections."""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from oc_plan import CompiledPlanResult, PlanOverrides, compile_plan
from oc_schema import parse_toml_strict, read_regular_no_follow, sha256_canonical_json, validate_doc_by_kind


HERE = Path(__file__).resolve().parent
BUILTIN = HERE.parent / "l" / "builtin"
PROFILE = "poc/local-profile"
BROWSER_BUNDLE = "poc/headless-browser"
PG_SERVICE = "builtin/postgres"
CDP_SERVICE = "builtin/chromium-managed"
WORKER = "builtin/local-workstation"
PROVIDER = "builtin/podman-linux"
TRANSPORT = "builtin/local"
WORKER_REF = "ghcr.io/anomalyco/opencode@sha256:8cb14899e31ea4fd34c1093cfa15278fac46b3c10c9ad4ec2f2d56ff4484ba6b"
RELAY_REF = "docker.io/library/python@sha256:aa679aa4eed6eb56c1dc6ad3f1b98b7d2d788fd961596779d188fdedad97fb38"
PG_REF = "docker.io/library/postgres@sha256:5aee909f99ab78c62f03636b6ca25a17195657605ce6782d9919ce4288595eda"
CDP_REF = "localhost/oc-chromium@sha256:3ee5603eb2af371f316c1d200e834bde026768c28058b7deae28108ee7a03ec1"
RECIPES = {
    PG_SERVICE: (PG_REF, "postgres_scram_service", "pg", 5432, "postgres"),
    CDP_SERVICE: (CDP_REF, None, "devtools", 9222, "http"),
}


class ProfileError(ValueError):
    """Only fixed, credential-free diagnostics leave the profile proof."""


def _document(directory: Path, filename: str, kind: str, obj_id: str, *, image=None) -> dict:
    raw = read_regular_no_follow(directory / filename, max_bytes=65536, confined_root=directory)
    doc = parse_toml_strict(raw.decode("utf-8"), context=filename)
    if image is not None:
        doc["images_by_arch"] = {"x86_64": image}
    return validate_doc_by_kind(kind, doc, expected_id=obj_id, for_orchestrator=False)


class FixtureCatalog:
    """The compiler sees a finite catalog with immutable, checkout-owned inputs."""

    def __init__(self) -> None:
        specs = (
            ("sandbox-type", PROFILE, HERE, "profile.toml", None),
            ("bundle", BROWSER_BUNDLE, HERE, "headless.toml", None),
            ("bundle", "builtin/postgres-app", BUILTIN / "bundles", "postgres-app.toml", None),
            ("worker", WORKER, BUILTIN / "workers", "local-workstation.toml", None),
            ("host-provider", PROVIDER, BUILTIN / "host-providers", "podman-linux.toml", None),
            ("transport", TRANSPORT, BUILTIN / "transports", "local.toml", None),
            ("service", PG_SERVICE, BUILTIN / "services", "postgres.toml", PG_REF),
            ("service", CDP_SERVICE, BUILTIN / "services", "chromium-managed.toml", CDP_REF),
        )
        self.documents = {
            (kind, obj_id): _document(root, filename, kind, obj_id, image=image)
            for kind, obj_id, root, filename, image in specs
        }

    def get(self, kind: str, obj_id: str, *, include_archived: bool = False) -> dict:
        return self.documents[kind, obj_id]

    def list_ids(self, kind: str) -> list[str]:
        return sorted(obj_id for doc_kind, obj_id in self.documents if doc_kind == kind)

    def get_revision(self, kind: str, obj_id: str) -> int:
        self.get(kind, obj_id)
        return 1

    def bundle_asset_root(self, bundle_id: str) -> None:
        return None


@dataclass(frozen=True)
class Selection:
    digest: str
    services: tuple[str, ...]


def _check_worker(plan: dict) -> None:
    worker = plan["worker"]
    if (
        plan["sandbox_type"] != PROFILE
        or (plan["tier"], plan["topology"], plan["base_image"]) != ("interactive", "pod-shared", WORKER_REF)
        or (worker["id"], worker["host_provider"], worker["transport"]) != (WORKER, PROVIDER, TRANSPORT)
        or (worker["arch"], worker["os"]) != ("x86_64", "linux")
        or any(plan[key] for key in (
            "remote_bindings", "remote_write_grants", "broker_routes", "broker_client_env", "raw_remote_mounts",
        ))
    ):
        raise ProfileError("Unsupported local fixture plan")


def _check_recipe(service: dict, endpoint: dict) -> None:
    obj_id = service["id"]
    image, factory, name, port, protocol = RECIPES[obj_id]
    if (
        service["key"] != obj_id
        or service["instance"] is not None
        or service["dependencies"]
        or service["env"]
        or service["security_profile"] != "standard"
        or (service["image"], service["factory_id"]) != (image, factory)
        or (endpoint["service_key"], endpoint["endpoint"], endpoint["port"], endpoint["protocol"])
        != (obj_id, name, port, protocol)
        or endpoint["exposure"] != "pod-only"
        or endpoint["host_port"] is not None
    ):
        raise ProfileError("Unsupported local service recipe")


def lower(result: CompiledPlanResult) -> Selection:
    plan = result.plan
    if sha256_canonical_json(plan) != result.plan_digest:
        raise ProfileError("Compiled plan digest did not match")
    _check_worker(plan)
    services = tuple(service["id"] for service in plan["services"])
    if len(services) != len(set(services)) or set(services) not in ({PG_SERVICE}, set(RECIPES)):
        raise ProfileError("Unsupported local service selection")
    endpoints = {entry["service"]: entry for entry in plan["endpoints"]}
    if len(plan["endpoints"]) != len(services) or endpoints.keys() != set(services):
        raise ProfileError("Unsupported local endpoint selection")
    for service in plan["services"]:
        _check_recipe(service, endpoints[service["id"]])
    return Selection(result.plan_digest, services)


def compile_fixture(*, without_chromium: bool) -> Selection:
    omitted = (BROWSER_BUNDLE,) if without_chromium else ()
    return lower(compile_plan(FixtureCatalog(), PROFILE, overrides=PlanOverrides(without_mods=omitted)))


def verify_image(image_id: str, image_ref: str, inspect: Callable[..., dict]) -> None:
    metadata = inspect("image", "inspect", image_id)
    if (
        (metadata.get("Id") or "").removeprefix("sha256:") != image_id
        or image_ref not in (metadata.get("RepoDigests") or ())
        or metadata.get("Os") != "linux"
        or metadata.get("Architecture") != "amd64"
    ):
        raise ProfileError("Cached image did not match the pinned Linux fixture")
