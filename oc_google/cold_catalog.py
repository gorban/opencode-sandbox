"""Verify the measured cold-reopen model catalog without granting inference."""

from dataclasses import dataclass, field
import json

from .account_binding import AccountBindingError, MetadataOperation
from .enrollment import EnrollmentMetadataError, _bounded_object, _exchange_observed, _valid_identifier
from .metadata_destination import MetadataRoute
from .token_diagnostic import PostTokenStage, observe_post_token


_CATALOG_FIELDS = {"models", "defaultAgentModelId", "agentModelSorts"}
_MODEL_FIELDS = {"displayName", "model", "modelProvider", "apiProvider", "maxTokens", "maxOutputTokens"}
_CATALOG_LIMIT = MetadataRoute.FETCH_AVAILABLE_MODELS.value[-1]


@dataclass(frozen=True, slots=True)
class VerifiedColdCatalog:
    body: bytes = field(repr=False)
    gemini_models: tuple[str, ...]

    def __reduce_ex__(self, _protocol):
        raise TypeError("Google native catalog reply must remain in memory")


def _label(value):
    return type(value) is str and 0 < len(value) <= 256 and value.isprintable()


def _max_tokens(value):
    return type(value) is int and 0 < value < (1 << 31)


def _model(value):
    return (type(value) is dict and value.keys() == _MODEL_FIELDS and _label(value["displayName"])
            and all(_valid_identifier(value[key]) for key in ("model", "modelProvider", "apiProvider"))
            and all(_max_tokens(value[key]) for key in ("maxTokens", "maxOutputTokens")))


def _group(value, models):
    return (type(value) is dict and value.keys() == {"displayName", "modelIds"}
            and _label(value["displayName"]) and type(value["modelIds"]) is list
            and len(value["modelIds"]) <= len(models)
            and all(type(model) is str and model in models for model in value["modelIds"]))


def _section(value, models):
    return (type(value) is dict and value.keys() == {"displayName", "groups"}
            and _label(value["displayName"]) and type(value["groups"]) is list
            and len(value["groups"]) <= 32 and all(_group(group, models) for group in value["groups"]))


def _observe_catalog(body):
    fields = _bounded_object(body, _CATALOG_LIMIT)
    if fields.keys() != _CATALOG_FIELDS:
        raise EnrollmentMetadataError("Unexpected Google cold catalog envelope")
    models, default, sorts = (fields[key] for key in ("models", "defaultAgentModelId", "agentModelSorts"))
    if (type(models) is not dict or not 1 <= len(models) <= 128 or type(default) is not str or default not in models
            or any(not _valid_identifier(name) or not _model(model) for name, model in models.items())
            or type(sorts) is not list or len(sorts) > 32 or any(not _section(section, models) for section in sorts)):
        raise EnrollmentMetadataError("Unexpected Google cold catalog metadata")
    return tuple(sorted(name for name, model in models.items()
                        if model["modelProvider"] == "MODEL_PROVIDER_GOOGLE"
                        and model["apiProvider"] == "API_PROVIDER_GOOGLE_GEMINI"))


def verify_cold_catalog(*, proof, load_reply, authorization, body, deadline, spend, destination, post_diagnostic=None):
    """Verify the catalog on the same bearer and project as the preceding load call."""
    with observe_post_token(post_diagnostic, PostTokenStage.COLD_CATALOG, EnrollmentMetadataError, AccountBindingError):
        if type(authorization) is not bytes or not authorization.startswith(b"Bearer "):
            raise EnrollmentMetadataError("Invalid Google cold catalog authorization")
        proof.require_metadata_bearer(MetadataOperation.FETCH_AVAILABLE_MODELS, authorization[7:])
        project = _bounded_object(load_reply.body, 4096).get("cloudaicompanionProject")
        request = _bounded_object(body, 1024)
        if not _valid_identifier(project) or request != {"project": project}:
            raise EnrollmentMetadataError("Google cold catalog project does not match the verified load reply")
    route = MetadataRoute.FETCH_AVAILABLE_MODELS
    response, observed = _exchange_observed(
        route, authorization=authorization, body=json.dumps(request).encode("ascii"), deadline=deadline,
        spend=spend, destination=destination, post_diagnostic=post_diagnostic,
    )
    with observe_post_token(post_diagnostic if observed else None, PostTokenStage.COLD_CATALOG,
                            EnrollmentMetadataError):
        return VerifiedColdCatalog(response, _observe_catalog(response))
