"""Translate only the two reviewed PRD L fixture plans into local image selections."""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Callable

from oc_plan import CompiledPlanResult, PlanOverrides, PlanStoreView, compile_plan
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
SERVICE_IMAGES = {PG_SERVICE: PG_REF, CDP_SERVICE: CDP_REF}
IMAGE_ID = re.compile(r"[0-9a-f]{64}")
# Pin the complete reviewed IR for each variant, including endpoints, resources,
# role contract and all service recipes.
FIXTURE_PLANS = {
    "2baf150e33e16dbc3aff218fb491142e984e225d5e3386c5197c8089b8e7e5a0": (CDP_SERVICE, PG_SERVICE),
    "66900aba71145553925f04b433deaa7404ce802ea69ab64174bb75fbe21e797a": (PG_SERVICE,),
}


class ProfileError(ValueError):
    """Only fixed, credential-free diagnostics leave the profile proof."""


def _document(directory: Path, filename: str, kind: str, obj_id: str, *, image=None) -> dict:
    raw = read_regular_no_follow(directory / filename, max_bytes=65536, confined_root=directory)
    doc = parse_toml_strict(raw.decode("utf-8"), context=filename)
    if image is not None:
        doc["images_by_arch"] = {"x86_64": image}
    return validate_doc_by_kind(kind, doc, expected_id=obj_id, for_orchestrator=False)


class FixtureCatalog(PlanStoreView):
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

    def list_ids(self, kind: str, *, include_archived: bool = False) -> list[str]:
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


def lower(result: CompiledPlanResult) -> Selection:
    if sha256_canonical_json(result.plan) != result.plan_digest:
        raise ProfileError("Compiled plan digest did not match")
    services = tuple(service["id"] for service in result.plan["services"])
    if services != FIXTURE_PLANS.get(result.plan_digest):
        raise ProfileError("Unsupported local fixture plan")
    return Selection(result.plan_digest, services)


def compile_fixture(*, without_chromium: bool) -> Selection:
    omitted = (BROWSER_BUNDLE,) if without_chromium else ()
    return lower(compile_plan(FixtureCatalog(), PROFILE, overrides=PlanOverrides(without_mods=omitted)))


def verify_image(image_id: str, image_ref: str, inspect: Callable[..., dict]) -> None:
    clean_id = image_id.removeprefix("sha256:")
    if not IMAGE_ID.fullmatch(clean_id):
        raise ProfileError("Image pin must be a full immutable ID")
    metadata = inspect("image", "inspect", clean_id)
    if (
        (metadata.get("Id") or "").removeprefix("sha256:") != clean_id
        or image_ref not in (metadata.get("RepoDigests") or ())
        or metadata.get("Os") != "linux"
        or metadata.get("Architecture") != "amd64"
    ):
        raise ProfileError("Cached image did not match the pinned Linux fixture")
