# prd_i4: Host model gateway and subscription routes

Parent: [prd_i](prd_i.md) · children: [outside-in broker, subscriptions, and agy acp](prd_i4a.md),
[security documentation and Meridian qualification](prd_i4b.md) · related: [worker fleet](prd_i2.md),
[credential broker](prd_i3.md)

## Gateway

- [ ] Keep the agent runtime, worktree and tools on the worker when the provider supports that
      split. Route model traffic to the trusted host over authenticated transport. Keep
      upstream API credentials and any host-owned subscription login on the trusted side.
- [ ] Provide API-key routes with broker identities scoped to a worker and job, model allowlists,
      request/token limits and revocation. Verify the managed-job credential boundary in
      [I3](prd_i3.md) before enabling a live route. Attribute model usage by worker and session.
      Make API billing and subscription usage visible and require opt-in for paid fallback.
- [ ] Preserve streaming, tool calls, cancellation and session separation. Record model,
      latency, usage and failure metadata for the dashboard and health monitor. Keep raw
      model inputs, outputs and provider credentials out of routine gateway logs.
- [ ] Validate eligible OpenAI subscription use against the provider's current authorization
      rules and documented inference path. Verify that the exact worker client, host
      authentication flow and entitlement work together. LiteLLM documents both gateway-owned
      ChatGPT credentials and client-owned forwarding. Its gateway-owned route defaults to
      the ChatGPT backend. OpenAI's open-source Sign in with ChatGPT inference guide specifies
      the public Responses API. Treat these as separate routes and record any gap.
      See [OpenAI inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference),
      [LiteLLM ChatGPT provider](https://docs.litellm.ai/docs/providers/chatgpt), and
      [LiteLLM Codex forwarding](https://docs.litellm.ai/docs/tutorials/openai_codex_byok).

## Feasibility spike — host-only Claude subscription routing

- [ ] **Question** — can remote OpenCode keep its own tools and conversation state on a worker
      while a trusted host runs supported Claude authentication and model calls? Keep the
      provider session on the host and follow the authorization scope of the integration.
- [ ] **Stage 0: authorization** — confirm with provider documentation or the provider that the
      exact topology, client, account entitlement, authentication and billing are permitted before
      any live subscription test. Treat the existing OpenCode integration as evidence for its own
      design only. Use mocks or the API-key baseline while authorization is unclear. If the proposed
      subscription route is unsupported, record it as blocked and keep it disabled. See
      [Anthropic authentication guidance](https://code.claude.com/docs/en/legal-and-compliance).
- [ ] **Baseline** — OpenCode's built-in Claude Agent provider invokes the user's installed
      Claude Code through the Agent SDK. Its maintainer reports permission for that
      integration, whose specification requires both components on the same machine and
      describes a Claude process per conversation. LiteLLM's Claude subscription setup
      forwards client OAuth, with login and refresh at Claude Code. Neither establishes
      host-only auth for the proposed split. See the [OpenCode PR](https://github.com/anomalyco/opencode/pull/58782),
      [provider spec](https://github.com/Tarquinen/opencode/blob/claude-agent-provider/specs/v2/claude-agent-provider.md),
      [Anthropic guidance](https://code.claude.com/docs/en/agent-sdk/overview) and
      [LiteLLM Claude setup](https://docs.litellm.ai/docs/tutorials/claude_code_max_subscription).
- [ ] **Compare** — OpenCode and Claude Code on the trusted host with remote tool execution
      (closest to the documented integration, retains controller RAM use), or a thin
      host-side native Claude/SDK bridge with remote OpenCode (closer to the target, needs
      technical proof and provider confirmation for the new integration). Include the
      API-key gateway as a baseline and fallback.
- [ ] **Host execution boundary** — run either host client in an OS sandbox that exposes only
      its own provider session, the required provider connection and the authenticated remote-tool
      adapter. Deny model access to local files and shell, unrelated host credentials, inherited
      sockets and arbitrary network destinations. Disable built-in local tools and untrusted config,
      hooks and plugins. Allow only registered remote tools scoped to the correct job. Verify with
      mocks that local actions and cross-job requests fail before enabling any live route.
- [ ] **Exit criteria** — verify no provider login or token reaches the worker and no model action
      can invoke local host tools. Demonstrate streaming, tool-call round trips, per-session
      isolation, cancellation, refresh and provider-limit behavior on authorized paths. Measure
      host memory per active and idle session and proxy latency. Record supported and blocked
      paths and recommend proceed, revise or defer. Estimate 3–5 engineering days for the spike,
      excluding any wait for provider confirmation.

## Open choice

- [ ] **Gateway software** — chosen: **thin host broker (`oc_llm_broker.py` + `oc_controller.py`)
      fronting host-only LiteLLM Proxy** for Gemini, Claude, and GPT API-key routes, plus direct
      host-brokered **OpenAI Sign in with ChatGPT** (`/v1/models`, `/v1/responses`) reusing
      `api-agent`'s OAuth/Playwright lifecycle, plus a separate standalone host **`agy acp`**
      lifecycle client with `antigravity-oauth` and `claude-subscription` fail-closed at the
      OpenCode proxy dispatch gate (see [prd_i4a](prd_i4a.md)).

[LiteLLM core](https://github.com/BerriAI/litellm/blob/main/LICENSE) uses MIT with separate
enterprise terms. [Caddy](https://github.com/caddyserver/caddy/blob/master/LICENSE) uses
Apache-2.0 and can provide HTTPS transport for a separately authenticated model adapter.
