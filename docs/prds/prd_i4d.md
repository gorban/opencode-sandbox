# I4d: Provider settings and first-use connection

Parent: [I4](prd_i4.md) · related: [configuration](prd_l.md),
[worker credential isolation](prd_i3a.md), [Claude sign-in](prd_i4b.md),
[Antigravity sign-in](prd_i4c.md)

Owner: **Codex**, coordinating the shared contract with **AGY**, which owns the ChatGPT
launch slice. This is the proposed interface. Shared code extraction and live route
qualification have their own review gates.

## One configuration model

Follow the api-agent pattern of versioned field declarations, typed values, conditional fields,
explicit overrides and source provenance (`7b6ded36077d`, `src/api_agent/config/`). A registered,
workstation-trusted component contributes
its own settings and may override a shared default only where the base schema explicitly allows it.
Reject conflicting declarations, type changes and attempts to weaken a field's validation,
sensitivity or authority. Compose inert declarations without importing provider code or selecting
executables from the workspace. Reuse the same resolved configuration for CLI, help, preview,
the eventual settings editor and the launcher. [L](prd_l.md) owns the general configuration
contract. I4d is its first model-provider consumer.

Under the proposed grammar, a typed setting has one canonical path. TOML, environment and CLI
spellings are inputs to that same setting. For example, a declared boolean `some_setting` accepts
`--some-setting` as `SOME_SETTING=True`, `--something-else valueA` maps to `SOMETHING_ELSE=valueA`,
and `--equals-one=1` maps to `EQUALS_ONE=1`. The resolver converts the values to their declared
types. These names illustrate the mapping. Actual environment inputs use the `OC_SANDBOX__`
prefix. CLI parsing records overrides without exporting them to the process environment.
Use dots between nested CLI segments and `__` between environment segments. Instance labels
use lowercase ASCII words and digits, start with a letter, and permit single hyphens between
segments. Reject case variants, underscores in labels, reserved separators and collisions after
normalization. For example, TOML `providers.google.personal.cli_path`, CLI
`--providers.google.personal.cli-path`, and environment
`OC_SANDBOX__PROVIDERS__GOOGLE__PERSONAL__CLI_PATH` address the same setting. Resolve the target
instance before expanding legacy shorthand. A shorthand and its canonical spelling in one source
are duplicate settings even if their values agree. Reject unknown fields and duplicate settings
within one source. Overrides across sources follow the normal precedence.

For eligible workstation settings, the value precedence is declared defaults, trusted operator
TOML, trusted operator environment, then operator CLI. Workstation policy still decides which
source may set each field and which routes and placements are allowed. Only trusted operator
TOML can create an instance or change `enabled`, `auth_mode`, `credential_ref`, its billing
policy or `provider_defaults.<kind>`. A dedicated operator setup action can persist those
changes after approval.
CLI or environment settings may override `cli_path` for an existing instance. A default
`oc-sandbox` launch catalogs all enabled, qualified provider instances for the selected placement;
an optional `--provider` restricts one launch to a single already enabled instance. `--mini`
selects OpenCode Mini as an opt-in UI mode (defaulting to full OpenCode when omitted). Provider
declarations, instance profiles and agent requests cannot use precedence to elevate authority.
Use only trusted startup inputs for a persistent supervisor.

## Named instances and credentials

A provider kind names an integration. A provider instance names one configuration and credential
binding, with its own lifecycle, limits and allowed models. Support multiple instances of the
same kind even when they use different authentication modes. Use explicit opt-in per instance in
operator-owned TOML under `~/.config/oc-sandbox/`.

```toml
[provider_defaults]
openai = "personal"

[providers.openai.personal]
enabled = true
auth_mode = "subscription"

[providers.openai.team-api]
enabled = true
auth_mode = "api_key"
credential_ref = "openai-team"

[providers.google.personal]
enabled = true
auth_mode = "subscription"
cli_path = "/home/operator/.local/bin/agy"
```

`google` denotes the Google integration. Its subscription route uses Antigravity ACP. Use an
initial default only until persisted selection state exists. An explicitly disconnected or
unusable selection cannot fall through to the TOML default. For an explicit launch, select an
instance such as `openai/team-api`. A bare `openai` resolves only through a persisted selection
or explicit default. Unqualified routes can be configured while remaining unavailable.

Accept API keys through a workstation-only masked prompt or the approved host secret manager.
Store a reference in configuration. The broker resolves it after policy admits the route.
Multiple keys for one provider use separately named instances. Bind approval to a stable instance
identity, auth mode, credential generation and billing policy. Recreating a deleted label creates
a different identity. A changed vault reference, secret version or billing binding requires fresh
verification and approval. Rotation invalidates stale grants before further dispatch. Raw key
values are outside the general config resolver. Keep them out of argv,
generic environment, TOML, model transcripts, logs, and worker state. An instance specifies its
authentication mode and billing. Exhaustion or auth failure returns a typed reason and leaves any
other instance for the operator to select explicitly. In-flight and continued work remain bound
to the authorized instance and credential generation.

T3 Code provides distinct instances per driver and a picker for native accounts. Its usage view
aggregates and deduplicates reported subscription limits across environments and optional hubs.
Connecting a usage hub alone does not route requests through it. Use named instances first.
Cross-account dispatch or pooled quota would need separate authorization and design for consent,
provider rules, tenant boundaries, budget attribution and session state. Do not combine limits
unless identity and quota equivalence can be established through supported provider signals.
Separate local budgets can still draw on the same upstream quota.
[T3 provider instance contract](https://github.com/pingdotgg/t3code/blob/main/packages/contracts/src/providerInstance.ts) ·
[T3 usage and limits](https://github.com/pingdotgg/t3code/blob/main/docs/user/usage.md#track-subscription-limits)

## Native executable settings

Resolve native executables in this order for a trusted workstation invocation:

1. A scoped CLI setting such as `--providers.google.personal.cli-path /absolute/path`,
   or `--cli-path` on a command that selects that instance.
2. The scoped workstation environment setting, for example
   `OC_SANDBOX__PROVIDERS__GOOGLE__PERSONAL__CLI_PATH`. Earlier proposed shorthands
   `OC_SANDBOX_CLAUDE_CLI` and `OC_SANDBOX_AGY_CLI` have the same scope restrictions.
3. The instance's `cli_path` in trusted user TOML.
4. An approved executable on the workstation's trusted PATH (`claude` or `agy`). ChatGPT's
   workstation browser flow needs no native CLI.

An override changes executable discovery only. Resolve the configuration root from the trusted
operator context. Exclude empty, relative and untrusted PATH entries. Before executing even
`--version`, verify provenance, the resolved executable and its parent directories, and any
wrapper or interpreter it invokes. Fail on an invalid effective override without trying the next
source. Bind verification and launch to the same executable identity and require re-verification
if it or its placement changes. Never resolve from the workspace, worker environment,
project-local shims or an agent-supplied path. Use argv, no shell, a clean environment and a
trusted working directory. Standalone invocations may use trusted environment overrides.
A persistent supervisor takes them only from its operator-owned startup environment or
configuration, never from a client request.

## Default multi-provider launch and `--mini` UI mode

A normal `oc-sandbox` launch (without `--provider`) loads **all enabled, qualified provider
instances** declared in trusted operator TOML for the selected placement, projecting each admitted
instance under its stable provider label into OpenCode's read-only configuration behind isolated
host brokers and relays. The operator can select and switch between models from multiple configured
providers (for example, both OpenAI and Claude once each adapter and placement is qualified) in the
same OpenCode session without passing `--provider`.

- **Strict per-instance isolation:** Cataloging multiple enabled instances never pools accounts,
  merges quotas, shares tokens across relays, or enables automatic fallback between providers or
  paid API keys. Every dispatch, retry, and continuation stays bound to the explicitly chosen
  provider instance, auth mode, credential generation, billing policy, selection epoch, and
  exposure checks.
- **Placement qualification gate:** Unqualified or disabled instances stay excluded from the
  generated OpenCode catalog (and report a typed readiness reason on explicit selection). A live
  combined OpenAI + Claude launch remains gated until the exact Claude host-isolated launch
  topology clears qualification and review.
- **Optional narrowing:** `--provider KIND[/INSTANCE]` remains an optional explicit restriction for
  a single launch when the operator wants to limit a session to one enabled instance. It takes
  precedence over a profile's provider list for that launch and leaves persisted configuration and
  selections unchanged.
- **Opt-in OpenCode Mini (`--mini`):** `oc-sandbox` accepts `--mini` to launch OpenCode Mini
  instead of full OpenCode, defaulting to full OpenCode when omitted. Both full and `--mini`
  launches enforce the identical host broker, read-only config, SELinux/container isolation,
  exposure hold, and worker credential isolation invariants.

## Connection and first-use flow

The proposed CLI shape is `oc-sandbox <openai|claude|google> <connect|status|verify|select|disconnect>`.
`connect LABEL` starts attended setup for that instance and authentication mode. `status` reads projected local metadata
only. `verify` explicitly checks the active or requested registration from a fresh workstation
process without inference. `select LABEL` picks an existing instance. `disconnect` revokes local
routing for the selected instance first and preserves unrelated native sessions. Advertise supported actions as each
adapter qualifies. Claude can guide the operator through native sign-in and verification while
its separate worker subscription route remains unqualified.

On a default launch, the trusted launcher preflights every enabled, qualified provider instance for
the selected placement without an LLM, excluding disabled or unqualified routes rather than failing
silently into paid fallback. When `--provider KIND[/INSTANCE]` is passed explicitly, refuse
incompatible models or placements with a typed reason. Use one typed workstation operation for CLI
and orchestrator connection. In an interactive session it can show the reason, offer the attended
action and repeat preflight after sign-in.
For a running orchestrator selecting a worker model, the restricted interface returns a typed
readiness result and may request that the workstation offer the connection action. It carries
provider and local label, without native commands, executable paths or credentials. The
workstation UI owns approval, sign-in and selection.

| State on model selection | Workstation guidance |
| --- | --- |
| Disabled by policy | Show how the operator can enable the route. |
| Route unqualified for this placement | Show the outstanding qualification and any separately selectable route. |
| CLI missing or unsuitable | Show the expected CLI, supported version and trusted path override. |
| Disconnected or needs verification | Offer attended `connect` or explicit `verify`, respectively. |
| Ready | Continue using the exact selected provider, placement and registration generation. |

For ChatGPT, the attended action reuses the `openai connect` workstation browser flow, including
its manual open-link option. For Claude and Antigravity, guide the operator through the supported
native login or open a qualified operator-only terminal action. Keep links, codes and native
output in the trusted workstation UI. Headless startup exits with a typed reason and fixed operator
hint when setup is needed. A worker has no authority to initiate enrollment. Sign-in or verification
establishes readiness only. Job creation and inference still need the applicable execution authority
and exposure checks. At dispatch, recheck provider instance, model, placement, credential or
registration generation and selection epoch. Switching away and back invalidates stale approval. An abandoned or failed
connection leaves the model launch pending or exits with a reason. Never switch provider, account
or billing automatically.

AGY can deliver the private ChatGPT route through its existing review gates before shared TOML,
command migration or code extraction. Later integration preserves its browser options,
registration binding and exposure holds.

## Acceptance

- [ ] (decision needed) Confirm scoped CLI and environment naming with the grouped command plan.
  Qualify override precedence,
  typed source equivalence, provider-contributed fields and permitted overrides, normalized-name
  collisions, trusted PATH lookup, invalid paths, changed executable identity and disabled routes.
- [ ] Test same-kind subscriptions and API keys with separate fake identities and budgets. Verify
  explicit selection, single-instance lease scope, vault resolution, key rotation and revocation,
  redaction, and a typed refusal at quota exhaustion without a second account receiving the request.
  Verify that the environment cannot redirect a bare first launch to a different default and
  that an explicit approved `--provider openai/team-api` can select that route for one launch.
  Replace a fake vault key out of band between a turn and continuation. Refuse the continuation
  before dispatch and preserve the original usage attribution. Repeat with a deleted and recreated
  instance with the same label.
- [ ] With fake adapters, test first launch and later model selection, no automatic browser from a
  worker or non-interactive job, attended approval/cancellation, stale bindings, revoked access,
  and zero inference or paid fallback while the provider is unavailable. Start with no ready
  orchestrator model, complete sign-in, assert zero inference, then switch A → B → A before
  dispatch. Even with the original registration and generation restored, the stale selection
  epoch must cause refusal and zero inference.
- [ ] Reuse the CLI workstation action in the orchestrator. Keep browser/terminal interaction and
  provider state out of model transcripts, worker config and the orchestrator's generic tools.
- [ ] Verify default multi-provider launch catalogs all enabled, qualified provider instances for
  the selected placement (with no `--provider` flag), excludes disabled or unqualified instances,
  preserves per-instance billing/credential/revocation isolation with zero cross-provider fallback,
  and still honors optional `--provider KIND[/INSTANCE]` narrowing for a single launch.
- [ ] Verify `--mini` launches OpenCode Mini while default (no `--mini`) launches full OpenCode,
  with identical read-only config, broker isolation, exposure hold, and credential-separation
  invariants in both modes.
- [ ] Link and qualify the per-provider and combined opt-in live e2e pytest milestones in
  [I4f](prd_i4f.md#opt-in-live-e2e-pytest-milestones).
- [ ] Review every live adapter and placement independently under [I3a](prd_i3a.md),
  [I4](prd_i4.md), and the [implementation review gates](README.md#implementation-review-gates).
