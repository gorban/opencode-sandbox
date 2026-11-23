# Offline ModelCatalog proof

[M1.2](../../../prd_m1.md#concrete-gaps-and-checkboxes) proposes a host-owned model catalog and explicit reasoning variants in compiled OpenCode profiles. This proof checks that one route and model can be projected into a lease-scoped configuration and that a symbolic variant can be lowered only for the agent authorized to use it.

## Inputs and trust boundary

- A synthetic host catalog has one descriptor for route `fixture-responses` and model `fixture-model`. It declares context and output limits and immutable symbolic mappings for `low` and `high` into a fake Responses-style body. The quota proof may reuse the two fixture IDs independently.
- A typed lease snapshot from the fake host has an active flag, a job binding, the exact route and model, and an explicit allowed variant set for each agent. The synthetic profile requests `low` for the primary agent and `high` for a subagent, both on the same model. Use distinct sets in the fixture to detect accidental inheritance or widening.
- The host supplies the active job and agent context from fixture code. The request can name the model and symbolic effort. Request fields cannot establish job, agent, route or lease authority. The proof exercises this rule with simulated caller context.
- Use Python's standard library and in-process inputs and outputs. Provider options exist only in the host descriptor and in the synthetic upstream result. The worker-facing output carries model limits, explicit agent variants, and symbolic `x_oc_effort` values. All fixtures are synthetic and the proof requires no processes, network, provider credentials or host state.

## Normal flow and rejection

Use exact ASCII identifiers matching `[A-Za-z0-9][A-Za-z0-9._-]*` for job, route, model, agents, and variant symbols. This rejects empty, padded, control and bidi values before any identifier is used in serialized output. Require exact integers for limits, with `0 < output_limit <= context_limit`. At descriptor construction, accept a nonempty unique variant table of frozen reasoning options. Normalize host provider payloads only from mappings with exactly the `effort` and `summary` identifier strings, copying those strings into the frozen records. Reject empty, non-mapping, or malformed options.

```text
project(catalog, lease, host_job, profile):
    require active lease for host_job (denial)
    require valid lease identifiers and its exact catalog route/model (invalid input)
    validate every lease grant has a unique agent and a nonempty set
        containing only descriptor variants (invalid input)
    require a nonempty profile with unique agents
    for each agent: require explicit model and variant (invalid input)
        require model matches the lease and agent is known (denial)
        require variant exists in the descriptor (invalid input)
        require variant exists in the agent's grant (denial)
    emit one worker model with the descriptor's limits
    emit symbolic model variants from the exact union of the profiled agents' grants
    emit explicit model and variant on each agent, including the subagent
    emit OPENCODE_DISABLE_MODELS_DEV=1 in the proposed environment

lower(catalog, lease, host_job, host_agent, route, request):
    require active lease bound to host_job and route (denial)
    require a closed request shape containing exact model and x_oc_effort identifiers,
        valid lease identifiers and a valid host_agent identifier (invalid input)
    require model matches the lease (denial)
    index grants by valid unique agent identifiers (invalid input)
    require agent is known (denial)
    require exact route/model descriptor (invalid input)
    validate all lease grants against the descriptor (invalid input)
    require the symbolic variant exists in the descriptor (invalid input)
    require the effort in the host_agent's grant (denial)
    construct a fresh synthetic body with the model and descriptor's mapped reasoning options
```

The projection uses a model-level union to express the OpenCode configuration and repeats the selected variant on every agent. The lowering check enforces the narrower per-agent allowlist even if another variant is visible in the model entry. Both paths require explicit symbols, including when a model has only one remaining variant. The chooser uses exact identifiers and resolves neither aliases nor defaults. Construct and validate the complete projection before returning it. Return immutable policy results with explicit serialization for the synthetic worker config and upstream body.

Fail with a fixed denial for a missing, inactive, wrong-job or wrong-route lease, an unleased model, an unknown agent or a recognized variant outside that agent's grant. Fail with a fixed invalid-input result for missing or malformed request fields, unsupported catalog entries or variants, and extra request fields such as raw provider options. Reject malformed identifiers, duplicate grant agents, and any empty or unsupported grant set, including grants for agents outside the current profile. Rejected calls yield neither a partial projection nor a synthetic body. Each call evaluates the supplied current lease and descriptor, so a corrected request or restored host snapshot can succeed on retry.

## Planned verification

| Case | Expected result |
| --- | --- |
| One lease and descriptor, two agents with different grants | One projected model with exact limits, an explicit variant on each agent and models.dev disabled. Check the entire serialized worker config for zero `reasoning`, `thinking`, `output_config` and `budget_tokens` keys. Lowering produces distinct, exact synthetic reasoning options. |
| Missing, inactive or mismatched lease, plus unknown route/model or agent | The lease binding takes precedence, followed by model and agent authorization. A matching lease and known agent with a missing catalog descriptor yield invalid input. Each rejected call produces no projection or synthetic body. An earlier successful projection confers no lowering authority after a lease is invalidated. |
| Missing, malformed or unknown effort, the other agent's known variant, and omitted subagent variant | Unknown symbols yield invalid input. A known but ungranted symbol is denied even if visible in the projection. |
| Raw provider options alone or alongside a valid symbol | Rejection for extra fields such as `reasoning`, `thinking`, `output_config` and `budget_tokens`. Request-provided agent, job and route fields are also rejected. |
| Empty or inconsistent grant sets, including for an agent outside the profile | Both projection and lowering reject the full lease snapshot. |
| Empty profile, duplicate agents, invalid identifiers, boolean or out-of-range limits, and malformed provider options | Invalid input with no policy result. |
| Provider mapping or serialized output modified after validation | The descriptor and policy results remain immutable. Each serializer returns a fresh structure. |
| Inconsistent host snapshot followed by a corrected snapshot or an authorized request after a failed one | The failed call has no output or side effects. A fresh valid call succeeds. |

Run the prospective tests with Python's standard-library test runner. The proof is a standalone spike under this directory. The production schema, compiler, broker integration and provider qualification are separate review work.
