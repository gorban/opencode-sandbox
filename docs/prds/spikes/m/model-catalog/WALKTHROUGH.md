# Offline ModelCatalog proof

[M1.2](../../../prd_m1.md#concrete-gaps-and-checkboxes) proposes a host-owned model catalog and explicit reasoning variants in compiled OpenCode profiles. This proof checks that one route and model can be projected into a lease-scoped configuration and that a symbolic variant can be lowered only for the agent authorized to use it.

## Inputs and trust boundary

- A synthetic host catalog has one descriptor for route `fixture-responses` and model `fixture-model`. It declares context and output limits and exact symbolic mappings for `low` and `high` into a fake Responses-style body. The quota proof may reuse the two fixture IDs independently.
- A typed lease snapshot from the fake host has an active flag, a job binding, the exact route and model, and an explicit allowed variant set for each agent. The synthetic profile requests `low` for the primary agent and `high` for a subagent, both on the same model. Use distinct sets in the fixture to detect accidental inheritance or widening.
- The host supplies the active job and agent context from fixture code. The request can name the model and symbolic effort. Request fields cannot establish job, agent, route or lease authority. The proof exercises this rule with simulated caller context.
- Use Python's standard library and in-process inputs and outputs. Provider options exist only in the host descriptor and in the synthetic upstream result. The worker-facing output carries model limits, explicit agent variants, and symbolic `x_oc_effort` values. All fixtures are synthetic and the proof requires no processes, network, provider credentials or host state.

## Normal flow and rejection

```text
project(catalog, lease, host_job, profile):
    require active lease for host_job and its exact catalog route/model
    for each agent: require explicit model and variant
        require model matches the lease and variant exists in both
            the descriptor and the agent's allowed set
    emit one worker model with the descriptor's limits
    emit symbolic model variants from the union of the profiled agents' allowed sets
        intersected with the descriptor's variants
    emit explicit model and variant on each agent, including the subagent
    emit OPENCODE_DISABLE_MODELS_DEV=1 in the proposed environment

lower(catalog, lease, host_job, host_agent, route, request):
    require active lease bound to host_job and route
    require a closed request shape containing exact model and x_oc_effort strings
    require model matches the lease and an exact route/model descriptor exists
    require host_agent and effort in the lease's per-agent allowlist
    require the exact symbolic effort in that descriptor
    construct a fresh synthetic body with the model and descriptor's mapped reasoning options
```

The projection uses a model-level union to express the OpenCode configuration and repeats the selected variant on every agent. The lowering check enforces the narrower per-agent allowlist even if another variant is visible in the model entry. Both paths require explicit symbols, including when a model has only one remaining variant. The chooser uses exact identifiers and resolves neither aliases nor defaults. Construct and validate the complete projection before returning it. Return immutable policy results with explicit serialization for the synthetic worker config and upstream body.

Fail with a fixed denial for a missing, inactive, wrong-job or wrong-route lease, an unleased model, an unknown agent or a recognized variant outside that agent's grant. Fail with a fixed invalid-input result for missing or malformed request fields, unsupported catalog entries or variants, and extra request fields such as raw provider options. Also reject a host fixture whose lease, catalog or requested profile entries disagree. Rejected calls yield neither a partial projection nor a synthetic body. Each call evaluates the supplied current lease and descriptor, so a corrected request or restored host snapshot can succeed on retry.

## Planned verification

| Case | Expected result |
| --- | --- |
| One lease and descriptor, two agents with different grants | One projected model with exact limits, an explicit variant on each agent, models.dev disabled and symbolic options only. Lowering produces distinct, exact synthetic reasoning options. |
| Missing, inactive or mismatched lease, plus unknown route/model or agent | The lease binding takes precedence. A matching lease with a missing catalog descriptor is invalid. Each rejected call produces no projection or synthetic body. An earlier successful projection confers no lowering authority after a lease is invalidated. |
| Missing, malformed or unknown effort, the other agent's known variant, and omitted subagent variant | Rejection, including when the model-level union contains the requested effort. |
| Raw provider options alone or alongside a valid symbol | Rejection for extra fields such as `reasoning`, `thinking`, `output_config` and `budget_tokens`. Request-provided agent, job and route fields are also rejected. |
| Inconsistent host snapshot followed by a corrected snapshot or an authorized request after a failed one | The failed call has no output or side effects. A fresh valid call succeeds. |

Run the prospective tests with Python's standard-library test runner. The proof is a standalone spike under this directory. The production schema, compiler, broker integration and provider qualification are separate review work.
