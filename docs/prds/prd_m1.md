# prd_m1: Model selection, reasoning variants, and dual-window quota telemetry

Parent: [prd_m](prd_m.md) · related: [LLM gateway](prd_i4.md),
[host credential brokering](prd_l1.md), [cross-model orchestration](prd_m2.md)

## Problem statement and ACP investigation findings

When running OpenCode inside isolated sandboxes routed through our host LLM proxy with **Codex**
(OAuth subscription / Responses API / `codex app-server`) and **Claude** (Claude Code OAuth
subscription, gated on [prd_i4](prd_i4.md) Stage 0 authorization, and Anthropic API keys), three
capabilities are essential for both the human operator and the orchestrator:

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
1. **Inference & Auth Adapters** (unified `/llm/*` routes on `oc_broker_http.py`),
2. **Host `ModelCatalog` + Lossless Variant Lowering**, and
3. **Passive-First $N$-Window `QuotaLedger` + Pre-Dispatch Admission**.

## Design specification

### 1. Unified per-job LLM + L7 broker mux

- Mount LLM routes (`/llm/codex/v1/*`, `/llm/anthropic/v1/messages`, `/llm/litellm/v1/*`) onto the
  same per-job `HostHttpBrokerServer` (`oc_broker_http.py`, [prd_l1](prd_l1.md)) using the same
  per-job `BrokerLease`, `ocjob_...` `/run/secrets/oc_broker_token`, and `<1s` `oc_controller`
  revocation teardown.
- **Passive header capture order invariant:** Upstream rate-limit headers (`x-codex-*`,
  `anthropic-ratelimit-unified-*`, `x-ratelimit-*`, `retry-after`) MUST be tapped into `QuotaLedger`
  **inside the host broker before** `SAFE_RESPONSE_HEADERS` scrubbing strips them from the sandbox
  response. When LiteLLM UDS is used for API-key routes, either bypass LiteLLM for direct
  Anthropic/OpenAI endpoints or configure raw upstream header passthrough so rate-limit headers are
  not stripped before `oc_broker_http.py` observes them.

### 2. Host `ModelCatalog`, OpenCode compile-time sync, and host-side variant lowering

- Set `OPENCODE_DISABLE_MODELS_DEV=1` in managed sandboxes (mandatory under `--network=none` and to
  prevent stale upstream registry drift).
- At plan compilation (`oc_plan.py`), populate `/run/oc-config/opencode.json` **strictly** from the
  host `ModelCatalog` (seeded from `codex app-server` `model/list` + host Anthropic capability
  metadata), emitting ONLY models authorized by the sandbox's `lease.allowed_models`:
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

### 3. Generalized $N$-window `QuotaLedger` and pre-dispatch admission

Store account-scoped telemetry in host-only `$CONF_DIR/telemetry/quota_state.json` (`0o600`, atomic
rename, never mounted into sandboxes):

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
| **Tier 1 (Primary, 0 extra calls)** | Passive HTTP response headers + streaming SSE usage chunks tapped on every `200` and `429` | **Codex:** `x-codex-primary-{used-percent,window-minutes,reset-at}`, `x-codex-secondary-*`, `x-codex-rate-limit-reached-type`, `response.completed.response.usage`. **Claude:** `anthropic-ratelimit-unified-5h-{utilization,reset,status}`, `anthropic-ratelimit-unified-7d-*`, `anthropic-ratelimit-unified-representative-claim`, `message_start`/`message_delta` usage. **API keys:** `x-ratelimit-*` + cumulative USD spend. | Monotonic merge (`signal.observed_at >= window.observed_at` or authoritative `429`); strip upstream headers before forwarding to sandbox. |
| **Tier 2 (Local host RPC)** | Host-resident `codex app-server` JSON-RPC | `account/rateLimits/read` on cold start + push `account/rateLimits/updated` (`primary` 300m + `secondary` 10080m). | Host-confined process only; credentials never enter sandboxes. |
| **Tier 3 (Single-flight jittered fallback)** | Explicit user refresh or cold-start pre-dispatch when `state == "unknown"` | Only when no Tier 1/2 observation exists within `staleness_ttl_sec`. | Per-bucket single-flight lock; minimum `>= 600s + jitter(0..60s)` floor; **429 circuit-breaker** (on `429` from `/api/oauth/usage`, ignore `Retry-After: 0`, back off `15m -> 30m -> 60m` without poisoning inference state). Never background-poll `/api/oauth/usage`. |

#### Time-decay, `unknown` lattice, and pre-dispatch admission (`admit_lane`)

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
- **No silent billing escalation ([prd_i4](prd_i4.md)):** Switching from an exhausted OAuth
  subscription bucket to a metered `api_key` route NEVER happens automatically; it requires an
  explicit operator-approved `PaidFallbackGrant(max_spend_usd, expires_at)` bound in `oc_controller`.

## Gate 1 pseudocode walkthrough

```text
function handle_llm_broker_request(conn, lease, route, req):
    if not controller.check_lease_active(lease.request_id):
        return http_error(403, "lease_revoked_or_expired")
    body = parse_strict_json_object(req.body, max_bytes=MAX_LLM_BODY)
    model_id = body.get("model")
    effort   = body.pop("x_oc_effort", None) or route.default_effort
    if model_id not in lease.allowed_models:
        return http_error(403, "model_not_allowed")

    desc = model_catalog.get(route.route_id, model_id)
    if desc is None or not desc.supports_effort(effort):
        return http_error(400, "unsupported_model_or_effort")

    # Pre-flight quota check (never silently escalate subscription -> metered API key)
    admission = quota_ledger.check_bucket(desc.quota_bucket_id, model_id, now=clock())
    if admission.hard_blocked and not controller.has_active_paid_fallback(lease, route):
        return http_error(503, "quota_exhausted",
                          retry_after=admission.seconds_until_reset,
                          blocking_window=admission.blocking_window)

    wire_body = lower_reasoning_payload(desc, body, effort)
        # Adaptive Claude 4.6+: thinking={type:"adaptive"} + output_config={effort}; strips budget_tokens
        # Codex/OpenAI: reasoning={effort, summary:"auto"}
    ip = resolve_and_validate_ip(route.upstream_host, route.allowed_cidrs)
    up_sock = connect_tls_pinned_ip(ip, route.upstream_port, server_hostname=route.upstream_host)
    lease.register_stream(up_sock)
    try:
        up_resp = forward_with_host_auth(up_sock, route, wire_body, follow_redirects=False)
        # Tap rate-limit headers BEFORE SAFE_RESPONSE_HEADERS scrubbing!
        raw_quota = extract_provider_quota_headers(route.provider_family, up_resp.headers, up_resp.status)
        if raw_quota is not None:
            quota_ledger.merge_monotonic(desc.quota_bucket_id, raw_quota, observed_at=clock())
        # Stream scrubbed response to sandbox while tapping final SSE token usage chunk
        usage = stream_scrubbed_sse_and_tap_usage(up_resp, conn, lease, canary_secrets=route.secrets)
        if usage is not None:
            quota_ledger.record_session_usage(lease.job_id, model_id, usage)
    finally:
        lease.unregister_stream(up_sock)
```

### Failure, recovery, and verification tests

- **Failure / recovery:**
  - Unknown/changed upstream header schema degrades gracefully to `source = "partial"` or
    `state = "unknown"` without failing inference.
  - Telemetry-endpoint `429` trips the Tier 3 circuit breaker only; active inference continues via
    Tier 1 passive header updates.
  - `oc_controller.revoke()` terminates in-flight SSE inference streams in `<1s`.
- **Verification tests (offline fixtures + live qualification):**
  1. Unit tests verifying passive capture of `x-codex-{primary,secondary}-*` and
     `anthropic-ratelimit-unified-{5h,7d}-*` headers BEFORE `SAFE_RESPONSE_HEADERS` scrubbing, plus
     proof that scrubbed headers do not leak raw account/org identifiers to sandboxes.
  2. Unit tests verifying adaptive Claude 4.6 lowering strips `budget_tokens` and emits `effort`,
     while unleased models fail closed with `403`.
  3. Unit tests verifying `admit_lane` blocks pod launch on `used_ratio == 1.0` (`5h_rolling` OR
     `7d_weekly`), allows canary turn after `resets_at`, and refuses silent subscription -> API-key
     fallback without an active `oc_controller` grant.
  4. Unit tests verifying `/api/oauth/usage` `429` with `Retry-After: 0` engages exponential backoff
     (`15m -> 30m -> 60m`) and never retries in a tight loop.
  5. Unit tests verifying `oc_plan.py` emits explicit `variant:` alongside `model:` on every
     compiled OpenCode subagent and sets `OPENCODE_DISABLE_MODELS_DEV=1`.

## Concrete gaps and checkboxes

- [ ] **Gap M1.1 — Unify `/llm/*` routes onto `oc_broker_http.py`:** merge `oc_llm_broker.py`
      routes into the shared per-job `HostHttpBrokerServer` and ensure LiteLLM UDS does not swallow
      upstream rate-limit headers.
- [ ] **Gap M1.2 — Schema & compiler `model` + `variant` support (`oc_schema.py`, `oc_plan.py`):**
      add `model`/`variant` to `bundle.persona`, `bundle.subagents[]`, and `sandbox-type@1`; emit
      host-authorized `ModelCatalog` + symbolic `variants` into `/run/oc-config/opencode.json` with
      `OPENCODE_DISABLE_MODELS_DEV=1` and explicit subagent `variant:` propagation.
- [ ] **Gap M1.3 — `QuotaLedger` & pre-dispatch `admit_lane` (`oc_quota.py`):** implement
      $N$-window schema (`5h_rolling`, `7d_weekly`, model subcaps, `rpm`/`tpm`, `spend_cap_usd`),
      passive header parsers, `codex app-server` `account/rateLimits/read` adapter, Tier 3
      429-safe circuit breaker, and `oc_controller`-gated `PaidFallbackGrant`.
- [ ] **Gap M1.4 — Live SIWC 5h/7d header check & Claude Stage 0 gate ([prd_i4](prd_i4.md)):**
      verify empirically during live qualification whether `api.openai.com/v1/responses` (SIWC)
      emits `x-codex-{primary,secondary}-*` headers or requires a host `codex app-server`
      companion; keep live Claude OAuth subscription traffic disabled fail-closed until
      [prd_i4](prd_i4.md) Stage 0 provider authorization is cleared.
