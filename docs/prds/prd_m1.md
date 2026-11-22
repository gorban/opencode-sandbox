# prd_m1: Model selection, reasoning variants, and dual-window quota telemetry

Parent: [prd_m](prd_m.md) · related: [LLM gateway](prd_i4.md),
[host credential brokering](prd_l1.md), [cross-model orchestration](prd_m2.md)

## Problem statement and ACP investigation findings

When running OpenCode inside isolated sandboxes routed through our host LLM proxy with **Codex**
(OAuth subscription / Responses API / host-confined `codex app-server`) and **Claude** (Claude Code
OAuth subscription, gated on [prd_i4](prd_i4.md) Stage 0 authorization, and Anthropic API keys),
three capabilities are essential for both the human operator and the orchestrator:

1. Accurate **model listing** restricted to host-authorized routes/models.
2. Lossless **reasoning-effort / thinking-level** selection (`low`, `medium`, `high`, `xhigh`, `max`).
3. Live **token metrics, quota remaining, and reset timestamps** across **multiple quota windows**
   (specifically both a **5-hour rolling window** and a **7-day weekly window**, matching Claude
   Pro/Max, Codex Plus/Pro, and Google AI Pro).

### Empirical verdict on ACP (`agentclientprotocol.com`)

- **Does ACP standardize 5-hour rolling + 7-day weekly quotas or `resets_at`? No.**
  - ACP's `session/update` (`sessionUpdate: "usage_update"`) carries **only**
    `{ used, size, cost? }` — active context-window token fill and optional session monetary cost.
  - Neither core ACP nor `@zed-industries/codex-acp`, `@agentclientprotocol/claude-agent-acp`, or
    `opencode acp` exposes account-level `5h` utilization, `7d` utilization, or `resets_at`
    timestamps.
  - Notably, `codex-acp` wraps `codex app-server` — whose internal JSON-RPC *does* emit
    `account/rateLimits/read` and `account/rateLimits/updated` (`primary` 300-min 5h window +
    `secondary` 10,080-min 7d window) — **but `codex-acp` does not forward them** over standard ACP.
- **ACP reasoning/model controls also vary across adapters:** ACP defines `session/set_config_option`
  (`model`, `mode`, `thought_level`), but concrete adapters have diverged between `reasoning_effort`
  keys, model-ID suffixes (`opus[1m]/high`), and trailing notification drops in `opencode acp`.
- **Anthropic adaptive-thinking pitfall:** Newer Claude 4.6/4.7 models require `effort`
  (`low`/`medium`/`high`/`max`) with adaptive thinking; sending legacy manual `budget_tokens`
  triggers HTTP `400`.
- **OpenCode subagent variant pitfall:** Inside OpenCode, a subagent definition that explicitly pins
  `model:` silently drops the parent session's active `variant` unless `variant:` is also written
  explicitly on the subagent entry.
- **Anthropic `/api/oauth/usage` polling hazard:** Polling `GET /api/oauth/usage` aggressively
  triggers HTTP `429` (often with misleading `Retry-After: 0`), breaking status HUDs even when
  inference tokens remain available.

**Architectural conclusion:** Never rely on ACP or external `models.dev` fetches for model schemas
or multi-window quotas. Separate the problem into **three clean host-owned subplanes**:
1. **Inference & Auth Adapters** (unified `/llm/*` routes on `oc_broker_http.py` with strict
   request-body allowlisting),
2. **Host `ModelCatalog` + Lossless Variant Lowering**, and
3. **Passive-First $N$-Window `QuotaLedger` + Durable Pre-Flight Admission & Spend Reservation**.

## Design specification

### 1. Unified per-job LLM + L7 broker mux & request-body egress firewall

- Mount LLM routes (`/llm/codex/v1/*`, `/llm/anthropic/v1/messages`, `/llm/litellm/v1/*`) onto the
  same per-job `HostHttpBrokerServer` (`oc_broker_http.py`, [prd_l1](prd_l1.md)) using the same
  per-job `BrokerLease`, `ocjob_...` `/run/secrets/oc_broker_token`, and `<1s` `oc_controller`
  revocation teardown.
- **Strict per-provider request-body allowlisting (blocks provider-side egress exfiltration and
  cost-multiplier smuggling):**
  - Never pass arbitrary sandbox JSON fields upstream. Reconstruct the upstream body from a closed
    per-provider allowlist of inference fields (`model`, `messages`/`input`, `system`/`instructions`,
    `tools` [local function definitions ONLY], `tool_choice`, `stream`, `temperature`, `top_p`,
    clamped `max_tokens`/`max_output_tokens`, and broker-lowered reasoning fields).
  - **Block provider-executed network/compute tools fail-closed by default (mandatory in
    `tier == "managed"`):** Reject any OpenAI Responses `tools[]` entry whose `type != "function"`
    (blocking `mcp` with `server_url`, `web_search*`, `code_interpreter`, `computer_use*`,
    `file_search`), and reject Anthropic `mcp_servers`, `container`, and server-executed `tools[]`
    types (`web_fetch*`, `web_search*`, `code_execution*`, `computer*`, `bash*`, `text_editor*`) so
    a compromised `--network=none` sandbox cannot exfiltrate data via the model provider's cloud.
  - **Block cost-multiplier & data-retention smuggling:** Strip/reject client-supplied
    `service_tier`, `speed`, `store` (force `store: false` where supported), `background`, and
    arbitrary `metadata`; clamp `max_tokens` / `max_output_tokens` to the lease/model cap.
  - **Host-owned beta/feature headers:** Strip any inbound `anthropic-beta` / `openai-beta` header
    from sandboxes; the host broker injects only its own explicitly allowlisted beta headers needed
    for supported capabilities (e.g., prompt caching / adaptive thinking).
- **Passive header capture & error-body scrubbing invariant:**
  - Tap upstream rate-limit headers (`x-codex-*`, `anthropic-ratelimit-unified-*`, `x-ratelimit-*`,
    `retry-after`) into `QuotaLedger` **inside the host broker before** `SAFE_RESPONSE_HEADERS`
    scrubbing strips them from the sandbox response.
  - Scrub **all** upstream `4xx` and `5xx` response bodies (including `429`) before replying to the
    sandbox, returning only safe broker-synthesized JSON (e.g., `{"error": "upstream_rate_limited",
    "retry_after_sec": <int>}`) so raw upstream account/org IDs or credentials are never reflected.
  - When LiteLLM UDS is used for API-key routes, either bypass LiteLLM for direct Anthropic/OpenAI
    endpoints or configure raw upstream header passthrough so rate-limit headers are not stripped
    before `oc_broker_http.py` observes them.

### 2. Host `ModelCatalog`, OpenCode compile-time sync, and host-side variant lowering

- Set `OPENCODE_DISABLE_MODELS_DEV=1` in managed sandboxes (mandatory under `--network=none` and to
  prevent stale upstream registry drift).
- At plan compilation (`oc_plan.py`), populate `/run/oc-config/opencode.json` **strictly** from the
  host `ModelCatalog` (seeded from OS-confined `codex app-server` `model/list` + host Anthropic
  capability metadata), emitting ONLY models authorized by the sandbox's `lease.allowed_models`:
  - Each model entry carries explicit `context` / `output` limits and symbolic `variants`
    (`none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max`) that serialize a single normalized
    `x_oc_effort` / `variant` parameter rather than raw provider-specific `budget_tokens`.
  - Extend `bundle.persona`, `bundle.subagents[]`, and `sandbox-type@1` in `oc_schema.py` with
    optional `model` (`<provider>/<model_id>`) and `variant`.
  - In `_compile_role_contract()`, **always** emit explicit `"variant"` alongside `"model"` on
    every compiled subagent entry so OpenCode subagents never silently drop reasoning depth.
- **Host-side lossless lowering:** `oc_broker_http.py`'s `/llm/*` handler validates `(model_id,
  effort)` against `ModelCatalog` (failing closed with `400 unsupported_model_or_effort` or
  `403 model_not_allowed` on unleased models) and lowers into the exact upstream wire format:
  - **Codex / OpenAI Responses:** `reasoning: { effort: "low"|"medium"|"high"|"xhigh", summary: "auto" }`.
  - **Claude adaptive models (4.6+):** `thinking: { type: "adaptive" }` + `output_config: { effort: "low"|"medium"|"high"|"max" }` (stripping any client-supplied `budget_tokens`).
  - **Claude legacy extended-thinking models:** `thinking: { type: "enabled", budget_tokens: <mapped> }`.

### 3. Generalized $N$-window `QuotaLedger`, host `codex app-server` confinement, and durable `PaidFallbackGrant`

Store account-scoped telemetry in host-only runtime state under `$STATE`
(`~/.local/share/oc-sandbox/telemetry/quota_state.json`, `0o600`, verified via `check_not_in_sandbox`,
`assert_trusted_dir`, `O_NOFOLLOW`, atomic rename, guarded by `check_not_host_production_dir` in
tests; never stored under static `$CONF_DIR` or mounted into sandboxes):

```json
{
  "quota_bucket_id": "acct:claude-max-work",
  "provider": "anthropic-subscription",
  "auth_mode": "oauth_subscription",
  "observed_at": 1795370100,
  "source": "passive_response_headers",
  "representative_bottleneck": "5h_rolling",
  "windows": [
    {
      "window_id": "5h_rolling",
      "scope": "account",
      "window_seconds": 18000,
      "used_ratio": 0.74,
      "remaining_ratio": 0.26,
      "resets_at": 1795377600,
      "state": "ok",
      "staleness_ttl_sec": 300
    },
    {
      "window_id": "7d_weekly",
      "scope": "account",
      "window_seconds": 604800,
      "used_ratio": 0.92,
      "remaining_ratio": 0.08,
      "resets_at": 1795740000,
      "state": "throttled_soft",
      "staleness_ttl_sec": 900
    }
  ],
  "session_tokens": {
    "input": 148200,
    "cached_input": 112000,
    "output": 19400,
    "reasoning": 8100,
    "estimated_usd": 0.0
  }
}
```

#### Three-tier observation priority (passive-first, anti-self-DoS)

| Tier | Source | Providers & Signals | Guardrails |
|---|---|---|---|
| **Tier 1 (Primary, 0 extra calls)** | Passive HTTP response headers + streaming SSE usage chunks tapped on every `200` and `429` | **Codex:** `x-codex-primary-{used-percent,window-minutes,reset-at}`, `x-codex-secondary-*`, `x-codex-rate-limit-reached-type`, `response.completed.response.usage`. **Claude:** `anthropic-ratelimit-unified-5h-{utilization,reset,status}`, `anthropic-ratelimit-unified-7d-*`, `anthropic-ratelimit-unified-representative-claim`, `message_start`/`message_delta` usage. **API keys:** `x-ratelimit-*` + durable USD spend ledger. | Monotonic merge (`signal.observed_at >= window.observed_at` or authoritative `429`); strip upstream headers and scrub `4xx`/`5xx` bodies before forwarding to sandbox. |
| **Tier 2 (OS-confined host RPC)** | Host-confined `codex app-server` JSON-RPC | `model/list`, `account/rateLimits/read` on cold start + push `account/rateLimits/updated` (`primary` 300m + `secondary` 10080m). | **Mandatory OS confinement matching [prd_i4](prd_i4.md):** dedicated minimal isolated `$HOME`, zero access to operator `$HOME`/workspaces/SSH agent/Podman/D-Bus, local tools/exec disabled, network restricted strictly to documented OpenAI endpoints, used only for metadata/rate-limits/authorized host inference. |
| **Tier 3 (Single-flight jittered fallback)** | Explicit user refresh or cold-start pre-dispatch when `state == "unknown"` | Only when no Tier 1/2 observation exists within `staleness_ttl_sec`. | Per-bucket single-flight lock; minimum `>= 600s + jitter(0..60s)` floor; **429 circuit-breaker** (on `429` from `/api/oauth/usage`, ignore `Retry-After: 0`, back off `15m -> 30m -> 60m` without poisoning inference state). Never background-poll `/api/oauth/usage`. |

#### Time-decay, `unknown` lattice, pre-dispatch admission, and atomic `PaidFallbackGrant` accounting

- **Never fabricate 100%:** An unobserved bucket reports `state = "unknown"` until a real signal
  arrives.
- **Post-reset transition:** When `now >= resets_at` and no newer observation exists, transition
  `exhausted -> reset_elapsed_unverified`, allowing a single canary turn to refresh headers.
- **Pre-dispatch admission (`admit_lane`):** Before creating a pod or worktree, compute
  `headroom = min(remaining_ratio for w in applicable_windows)`:
  - If `headroom == 0` and `now < resets_at`: **hard block** launch and return
    `{ allowed: false, reason: "quota_exhausted", blocking_window, resets_at, eligible_alternatives }`.
  - If `0 < headroom < soft_reserve_threshold` (default `0.10`): surface warning in launch preview
    and orchestrator `quota_status()` tool so non-critical lanes can downgrade effort or switch
    provider family.
- **Explicit route-bound `PaidFallbackGrant` with durable pre-flight spend reservation:**
  - Switching from an exhausted OAuth subscription bucket to a metered `api_key` route NEVER happens
    automatically ([prd_i4](prd_i4.md)).
  - Operator approval in `oc_controller` binds `PaidFallbackGrant(grant_id, source_bucket_id,
    target_api_route_id, allowed_models, max_spend_usd, max_concurrent, expires_at)` — explicitly
    naming the metered `target_api_route_id` and its `api_key` credential.
  - **Atomic worst-case reservation:** Revalidate the selected paid route, model, effort and
    output cap against the lease and grant. Lower the body with the paid route's descriptor and
    get a conservative upper bound using that route's pinned tariff, including all billable
    tokens and fees. Refuse the fallback if a bound cannot be enforced. Before dialing,
    atomically check `active_concurrent < grant.max_concurrent` and
    `spent_usd + reserved_usd + upper_bound_usd <= grant.max_spend_usd`. Persist the reservation
    and its route, model, tariff revision, and request ID in `$STATE/registry.sqlite`.
  - **Durable send boundary:** Persist `may_have_sent` before making the first upstream request
    write. A verified pre-send failure may release a reservation. Once transmission may have
    occurred, retain the full bound across disconnects, missing usage and restarts. Reduce it
    only on authoritative, request-bound settlement. If the provider reports a charge above the
    bound, record the charge and suspend the route pending price or limit requalification.

## Gate 1 pseudocode walkthrough

```text
function handle_llm_broker_request(conn, lease, route, req):
    if not controller.check_lease_active(lease.request_id):
        return http_error(403, "lease_revoked_or_expired")
    raw_body = parse_strict_json_object(req.body, max_bytes=MAX_LLM_BODY)
    model_id = raw_body.get("model")
    effort   = raw_body.get("x_oc_effort") or route.default_effort
    if model_id not in lease.allowed_models:
        return http_error(403, "model_not_allowed")

    desc = model_catalog.get(route.route_id, model_id)
    if desc is None or not desc.supports_effort(effort):
        return http_error(400, "unsupported_model_or_effort")

    effective_route = route
    effective_desc = desc
    grant = None
    admission = quota_ledger.check_bucket(desc.quota_bucket_id, model_id, now=clock())
    if admission.hard_blocked:
        grant = controller.get_active_paid_fallback(lease, source_bucket_id=desc.quota_bucket_id,
                                                    model_id=model_id)
        if grant is None:
            return http_error(503, "quota_exhausted", retry_after=admission.seconds_until_reset,
                              blocking_window=admission.blocking_window)
        effective_route, effective_desc = require_approved_paid_target(grant, lease, model_id, effort)
        # Verify API-key route, exact approved route/model, and target-side effort/limits.

    # Enforce the closed body allowlist and lower using the selected route's descriptor.
    sanitized_body, clamped_max_tokens = sanitize_and_lower_llm_body(
        effective_desc, raw_body, effort, tier=lease.tier, max_tokens_cap=lease.max_output_tokens
    )
    reservation_id = None
    if grant is not None:
        bound = require_hard_billable_bound(effective_desc, sanitized_body, clamped_max_tokens)
        reservation_id = quota_ledger.reserve_spend_durable(grant, effective_desc, bound)
        if reservation_id is None:
            return http_error(429, "paid_fallback_budget_or_concurrency_exceeded")

    up_sock = None
    usage = None
    try:
        ip = resolve_and_validate_ip(effective_route.upstream_host, effective_route.allowed_cidrs)
        up_sock = connect_tls_pinned_ip(ip, effective_route.upstream_port,
                                        server_hostname=effective_route.upstream_host)
        lease.register_stream(up_sock)
        if reservation_id is not None:
            # Denies stale grant or tariff revision; never send without the persisted boundary.
            quota_ledger.mark_may_have_sent_durable(reservation_id, grant, effective_desc)
        up_resp = forward_with_host_auth(up_sock, effective_route, sanitized_body,
                                         allowlisted_beta_headers=effective_route.host_beta_headers,
                                         follow_redirects=False)
        raw_quota = extract_provider_quota_headers(effective_route.provider_family, up_resp.headers, up_resp.status)
        if raw_quota is not None:
            quota_ledger.merge_monotonic(effective_route.quota_bucket_id, raw_quota, observed_at=clock())
        if up_resp.status >= 400:
            retry_after = raw_quota.retry_after_sec if raw_quota is not None else None
            return send_scrubbed_llm_error(conn, up_resp.status, retry_after=retry_after)
        usage = stream_scrubbed_sse_and_tap_verified_usage(up_resp, conn, lease,
                                                           canary_secrets=effective_route.secrets)
    finally:
        close_and_unregister_if_open(up_sock, lease)
        if reservation_id is not None:
            quota_ledger.settle_verified_or_hold_full_bound(reservation_id, usage)
        elif usage is not None:
            quota_ledger.record_session_usage(lease.job_id, model_id, usage)
```

### Failure, recovery, and verification tests

- **Failure / recovery:**
  - Unknown/changed upstream header schema degrades gracefully to `source = "partial"` or
    `state = "unknown"` without failing inference.
  - Telemetry-endpoint `429` trips the Tier 3 circuit breaker only; active inference continues via
    Tier 1 passive header updates.
  - On restart, reconcile reservations by their durable send state. Release pre-send rows only
    after confirming the previous writer is fenced and that no transmission was possible.
    Retain the full bound for `may_have_sent` rows pending authoritative settlement, including
    when a provider returns an error with incomplete usage.
  - `oc_controller.revoke()` terminates in-flight SSE inference streams in `<1s`.
- **Verification tests (offline fixtures + live qualification):**
  1. Provider-tool egress smuggling tests proving OpenAI `tools: [{"type": "mcp", ...}]` /
     `web_search` and Anthropic `mcp_servers` / `web_fetch` / `code_execution` / `service_tier` /
     client `anthropic-beta` are rejected fail-closed in `managed` pods.
  2. Header capture & error scrubbing tests proving passive capture of `x-codex-{primary,secondary}-*`
     and `anthropic-ratelimit-unified-{5h,7d}-*` BEFORE `SAFE_RESPONSE_HEADERS` scrubbing, plus
     proof that `429`/`4xx`/`5xx` bodies never leak account/org IDs or secrets to sandboxes.
  3. Adaptive Claude 4.6 lowering tests verifying `budget_tokens` is stripped and `effort` emitted,
     while unleased models fail closed with `403`.
  4. Synthetic `PaidFallbackGrant` tests cover a fallback with different pricing and model limits,
     concurrent requests at the cap, verified pre-send connection failure, and a disconnect or
     crash after the durable send mark. Missing usage holds the full target-route bound across
     restart and blocks a call that would exceed the cap. Verify idempotent settlement, refusal
     when no hard bound is available, and route suspension on out-of-bound provider charge.
  5. Tier 3 circuit-breaker test proving `/api/oauth/usage` `429` with `Retry-After: 0` backs off
     (`15m -> 30m -> 60m`) without tight polling; `oc_plan.py` test verifying explicit subagent
     `variant:` emission and `OPENCODE_DISABLE_MODELS_DEV=1`.

## Concrete gaps and checkboxes

- [ ] **Gap M1.1 — Unify `/llm/*` routes onto `oc_broker_http.py` with request-body egress
      firewall:** merge `oc_llm_broker.py` routes into `HostHttpBrokerServer`, enforce per-provider
      body allowlisting (blocking server-executed network tools, cost multipliers, and client beta
      headers), scrub all `4xx`/`5xx` bodies, and ensure LiteLLM UDS preserves upstream rate-limit
      headers.
- [ ] **Gap M1.2 — Schema & compiler `model` + `variant` support (`oc_schema.py`, `oc_plan.py`):**
      add `model`/`variant` to `bundle.persona`, `bundle.subagents[]`, and `sandbox-type@1`; emit
      host-authorized `ModelCatalog` + symbolic `variants` into `/run/oc-config/opencode.json` with
      `OPENCODE_DISABLE_MODELS_DEV=1` and explicit subagent `variant:` propagation.
- [ ] **Gap M1.3 — `QuotaLedger`, OS-confined `codex app-server`, and durable `PaidFallbackGrant`
      (`oc_quota.py`):** implement `$STATE`-backed $N$-window telemetry (`5h_rolling`, `7d_weekly`,
      model subcaps, `rpm`/`tpm`, `spend_cap_usd`), passive header parsers, OS-confined `codex
      app-server` (`prd_i4` boundary), Tier 3 429-safe circuit breaker, and atomic pre-flight
      spend reservation/reconciliation across daemon restarts.
- [ ] **Gap M1.4 — Live SIWC 5h/7d header check & Claude Stage 0 gate ([prd_i4](prd_i4.md)):**
      verify empirically during live qualification whether `api.openai.com/v1/responses` (SIWC)
      emits `x-codex-{primary,secondary}-*` headers or requires an OS-confined `codex app-server`
      companion; keep live Claude OAuth subscription traffic disabled fail-closed until
      [prd_i4](prd_i4.md) Stage 0 provider authorization is cleared.
