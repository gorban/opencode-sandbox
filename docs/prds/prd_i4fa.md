# I4fa · Config-first provider rollout walkthrough

Parent: [I4f](prd_i4f.md) · [provider and picker contract](prd_i4d.md)

Start from reviewed `main` at `3c25934aeb01f2aa22b3643326197a15759d2201`.
The first reviewable outcome is one real, exact `ok` through each qualified provider's normal
OpenCode launch, with zero tool calls. The full and Mini sandbox checks use the same
configuration and policy. One provider can reach this milestone while the others qualify.

## Shared launch and test contract

1. The trusted launcher loads the operator's configuration and preflights enabled instances
   for the actual placement. Reuse the provider-instance, readiness, and selection types from
   `oc_providers`. Keep new provider implementation modules isolated until a caller needs a
   shared API change. Use one config reader and catalog authority. Abort launch on integrity
   failures, including corrupt provider configuration, an untrusted state store, a tampered
   exposure receipt, or an invalid executable override. Under the
   [I4d default launch policy](prd_i4d.md#default-multi-provider-launch-and---mini-ui-mode),
   report each excluded disabled, unqualified, or cleanly disconnected instance, and each
   instance whose valid exposure hold the operator declines. Start no relay for excluded instances.
   Refuse explicit selection of an excluded instance without fallback. In a default launch, offer
   the remaining instances for trusted selection. Abort if the admitted catalog is empty.
2. Project a picker row for each admitted `(scoped_provider_id, upstream_model_id)` pair.
   Present the model name first, then the configured instance label. Show version distinctions,
   use `kind/label` when labels collide, and retain the instance's billing disclosure. Take
   labels, collision disambiguation, and billing disclosures from trusted host configuration
   and policy. Bound and sanitize display names obtained from providers. Display data carries
   no routing authority. If a saved model is unavailable, require a new trusted selection
   before inference.
3. Launch admission authorizes discovery. Follow the first-write rules below to authorize the
   selected route. Before provider dispatch and continuation, the broker rechecks the exact
   instance, upstream model, placement and job incarnation, selection epoch, credential
   generation, lease, auth mode, billing policy, and applicable exposure authority. Hold native
   provider state, keyring, provider executable, and provider protocol on the trusted host.
   Pass only the admitted model reference and scoped broker route to OpenCode. Deny unknown,
   stale, or revoked bindings. Retire owned processes and relays and verify cleanup on cancel,
   failure, or owner loss. Preserve recoverable evidence when cleanup is uncertain.
4. Live pytest requires the provider's direct command-line opt-in and the provider's
   reviewed test allowance. AGY owns the live `conftest.py` helpers
   `explicit_cli_flag(flag, argv=None)`, `explicit_cli_option(option, argv=None)`, and
   `validate_source_sha256_pin(value)`. Check direct argv from
   `request.config.invocation_params.args` before `--` and require pytest to recognize the
   same options and values. Use option parsing that distinguishes an option occurrence
   from a value consumed by a preceding option. Reject duplicates, ambiguous parses,
   and any live option supplied via `PYTEST_ADDOPTS` or ini `addopts`, including matching
   overrides. Require direct values for source pin, model, mode, and route wherever
   the proof accepts those options. Disclose the resolved model and mode before dispatch.
   Before accessing provider state, the credential-owning driver verifies an exact
   reviewed SHA-256 manifest of a read-only execution snapshot. Include every
   first-party script and module actually invoked, including `oc-sandbox`,
   `oc-openai-session.py`, `oc-orchestrate.py`, helpers, `oc_providers/`, provider
   packages, and the selected driver where applicable. Execute the verified snapshot
   and abort on missing or unmeasured code. A parser or source check failure permits
   zero dispatches.
5. Before live use, prove the actual launch and selector with a synthetic provider and sentinel
   credentials. Verify exact route dispatch, zero unintended tool calls, credential inaccessibility,
   and cleanup. The live check uses the public launch command, a fresh conversation, and the
   fixed `Reply with exactly: ok` prompt. Verify exact `ok`, route attribution, zero tool calls,
   and zero requests through other admitted instances. Document which frontends actually passed.

### First inference and model switches

- For a fixed live proof, the operator approves one exact instance, upstream model ID, placement
  and launch incarnation before dispatch. Keep inference closed during startup. The exact
  OpenCode row is a readiness check against the tuple already resolved by the trusted owner.
  The owner activates a broker-enforced one-send latch for that tuple and fixed proof turn.
  The broker atomically claims and closes the latch before the first upstream write, including
  on uncertain delivery. Refuse title, restore, summary, compaction, retry and other automatic
  requests before and after the approved turn.
- In Phase 1, authorize general session selections only on a trusted workstation surface
  before attaching OpenCode to the worker terminal. Show the resolved route and billing
  there. A picker choice sent from a sandbox cannot approve or switch a route. The supported
  Phase 1 switch retires the launch and requires a fresh workstation confirmation. A live
  switch requires a separately reviewed workstation control surface and bounded proposal
  channel. Any such switch must retire the previous selection under the dispatch fence,
  abort its in-flight writes and continuations, and isolate its reasoning and continuation
  state from the new route. Bind approval to the current session and a strictly monotonic
  selection epoch, including when switching back to an earlier model or instance.
- In fake transport tests, require zero sends before authorization, with the other instance's
  own valid token, with a different model on the selected instance, and when a saved selection or
  startup title request appears. The approved row must produce one `ok` with exact attribution.
  Deny a second send after the latch is claimed. For a switch implementation, verify that a
  canceled change leaves the binding intact, an approved switch fences in-flight writes
  on the previous route, and `A → B → A` rejects a replay of the original A epoch.

### Provider qualification before live dispatch

- OpenAI shell acceptance uses the normal public launch and reads the operator's
  `~/.config/oc-sandbox/providers.toml` without editing it. Scratch config overrides
  are confined to offline tests. A live alternate config path would need its own review,
  including the unchanged real credential store and exposure checks.
- Verify Claude login on the workstation with the trusted native `claude` binary pinned
  by provenance and version. Strip API-key and gateway overrides. Check native status
  for `account.tokenSource == "claude.ai"` and `apiProvider == "firstParty"`.
  Verify that provider egress belongs only to the isolated native holder and OpenCode
  has no external egress on this route.
- For Antigravity, carry forward the [I4c enrollment checks](prd_i4c.md), including
  reopen across private D-Bus and keyring daemon restart, denial of ordinary workstation
  credentials to isolated `agy`, and known-present private home, keyring and socket
  denial to worker and relay. Verify that non-subscription fallback is unavailable.

## Parallel lanes

| Owner | First slice | Boundaries |
|---|---|---|
| AGY | OpenAI live full and Mini sandbox acceptance | OpenAI driver and test, shared pytest option registration, OpenAI I4f entry. Use the normal public launch and read-only workstation configuration. |
| Codex | Claude live orchestrator qualification | Start from PR #72's synthetic boundary and reuse its owner-lifeline fence. Check that a known-present login sentinel is available to the isolated native process and denied to OpenCode and the shim. Native-boundary evidence must show zero tool calls. Integrate the live entry after review of the exact launcher and shim topology. |
| Codex | Antigravity ACP qualification | Audit the existing I4c private-profile and enrollment candidates against current main. Qualify isolated, pinned `agy` with fake credentials. Qualify attended enrollment, fresh-process readiness, and reviewed text as separate steps. Require native evidence of zero tool calls and preserve the ordinary workstation profile. |
| Codex | Full and Mini model picker feasibility | Synthetic catalog with repeated models across kinds and accounts. Measure labels, list/search order, exact IDs through selection, and a stale saved selection in both pinned frontends. Review the smallest supported model-first change separately before adopting a frontend change. |

Independent offline lanes can begin after both reviewers clear their walkthroughs.
Shared launcher, broker and pytest changes wait for both reviewers to clear the common
contract. Claude and Antigravity coordinate any edits to `oc-orchestrate.py`, shared
configuration, or broker APIs before integration. Keep the picker probe and OpenAI-only
acceptance independent. The combined live sandbox test follows individual qualifications.

- [ ] Reciprocal security and PR-style reviewers approve the common contract and each walkthrough.
- [ ] Verify the common pytest opt-in and source pin using fake transport before subscription use.
- [ ] Integrate reviewed lane outputs, rerun the affected checks, and obtain reciprocal reviews
      on the exact integration head.

### Isolated holder spike

- [x] Exercise the [controller receipts and inherited channels](spikes/i4/isolated-authority-r3/WALKTHROUGH.md)
  in scratch. Verify that lost acknowledgments and uncertain publication block reuse, a retained
  socket cannot prolong the original peer's authority, and an invalid local lock cannot hang the
  bounded transaction. See `codex/openai-isolated-holder-r3`.
- [ ] Verify independent holder and controller identities in the sealed guest against the exact
  legacy OpenAI paths, with a separate rollback domain and an actual pre-write scope check.
