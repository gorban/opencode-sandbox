# I4c: Verify initial Google Antigravity sign-in

Parent: [I4](prd_i4.md) · related: [provider setup contract](prd_i4d.md),
[worker credential isolation](prd_i3a.md)

Owner: **Codex**, within **Outside-in integrations**. Scope is the native Google account
sign-in for Antigravity ACP and reuse from a fresh dedicated workstation process. The existing
devbox login supported ACP v1 session creation with `agy` 1.5.13. An offline empty profile
negotiated ACP and asked for authentication. Dedicated profile enrollment remains open.

Prefer a rootless workstation supervisor for normal installation and use. Treat the workstation
operator and any same-UID devbox with unrestricted host command access as trusted in this
placement. Keep native provider state, keyring and ACP stdio outside the worker and relay. A
separate service UID is an optional hardened placement for operators who need to deny the
same-UID devbox access to the login. It requires deliberate one-time admin provisioning and a
qualified control interface. Routine provider actions run without sudo in either placement.

The offline workstation proof under dedicated UID 958 reopened a synthetic keyring credential
and returned the signed-out ACP verdict using `agy` 1.5.15. A separate rootless OpenCode and relay
test completed a synthetic text turn while both containers lacked access to a synthetic private
workstation file and socket. Enrollment and the brokered native route still need qualification.

The [synthetic ACP readiness probe](spikes/i4c/acp_readiness.py) exercises only `initialize` and
`session/new` with a bundled fake peer. It requires Linux with
`PIDFD_SIGNAL_PROCESS_GROUP` (upstream 6.9 or later). From the repository root, run
`python3 -B -m unittest discover -s docs/prds/spikes/i4c -v`. The test enrollment writes a private
credential record and a separate verifier record for the exact generation. The verifier binds the
issued synthetic credential and its expiry to that generation. Substituting another enrollment's
credential fails even when the profile still names the expected generation. The launcher and fresh
peer both check that the synthetic enrollment handle has closed. This models enrollment authority
with a file lock.
The peer reads the separate credential record. A missing record returns `DISCONNECTED`, synthetic
expiry returns `NEEDS_VERIFY`, and a mismatched or untrusted record gives an integrity error.
Readiness publishes only after the fresh peer retires and the new journal state is synced.
Unconfirmed retirement retains the private scratch and journal receipt with
`REVOCATION_UNCONFIRMED`, which blocks further probes and enrollment in that scratch. If a
crash restores a receipt whose eviction did not sync, it still blocks reuse. Malformed ACP
responses give protocol errors. The fixture uses a caller-created private scratch directory
beneath a trusted path. Actual native egress restrictions, private keyring restart, isolation of
the ordinary workstation login, and worker and relay denial require separate qualification.
Live text also requires build-specific evidence that native and provider-side tools are disabled
and that attempted calls are observable.

The [offline text proxy spike](spikes/i4c/text-proxy.md) extends the synthetic transcript through one
`session/prompt` from a pinned OpenCode orchestrator worker. It keeps ACP on the workstation and
holds text through terminal completion, evidence from the bundled peer and verified retirement.
The Gate 1 walkthrough cleared both reviews at SHA-256
`83f1d8bc608d496905382a47f4f63c788c0eae080bc27e29da5348a2bae5d839`.
The readiness-only check and production launch commands retain their existing scope.

The installed `agy acp` 1.5.15 and a separately downloaded 1.5.17 retained native tools
and sent two prompt-bearing requests in the synthetic text trial, including with session
filter metadata. The separately published editor ACP server 1.5.2 is a distinct candidate.
An isolated fake personal login discovered the fixture models,
and a selected model with the empty allowlist sent zero tool declarations and one request
for a plain prompt. A separate fake tool response failed to obtain the synthetic file marker
but induced another prompt-bearing request. Before a live turn, qualify a response gate and
an independently enforced request allowance. The standalone archive and its required
companion executable stay host-only and outside the repository. [Official ACP registry entry][standalone-acp]

The stock OpenCode Full shell selected a fixture Gemini model and returned exact `ok`
through the pinned standalone server and a local fake upstream. The broker admitted one
generation, refused replay, withheld invalid tool or trailing response data, and verified
process and container retirement. A separate fake authorization-code exchange produced
an owner-only credential file and reopened it from a fresh isolated process with zero
prompts.

The live pytest in [test_google_text_e2e.py](../../tests/e2e/live/test_google_text_e2e.py)
exercises stock OpenCode 2.3.0 through the workstation's cached `agy acp` 1.5.15 login.
`--run-google-opencode-live` selects the OpenCode check and `--run-google-text-live`
selects the direct ACP check. Pytest asks once, before running the selected cases. Each
case sends one fixed Hydrogen prompt after approval. The automated OpenCode check reads
`[providers.google.elgoog]` from a scratch TOML and verifies the display
`gemini-4-hydrogen - elgoog [subscription]`, exact `ok`, replay refusal and retirement.
The configured label identifies a provider instance. The subscription always uses the
workstation's credential custody and upstream connection, independent of the worker's location.
Normal launcher integration, multiple configured providers in the same session, and
qualification of provider-side tool and retry behavior remain open.

The first public shell, `oc-sandbox google shell LABEL`, loads the named enabled Google
subscription entry from trusted `providers.toml`. It presents the selected model and the
one permitted prompt before the second-terminal arm. The worker displays
`MODEL - LABEL [subscription]` in the stock OpenCode picker. The worker and relay have no
native login or keyring. The workstation launches the pinned `agy acp` process with a
private home and opens the previously authenticated session before permitting the first
turn. ACP frames use the documented editor client protocol while `clientInfo` states the
actual `oc-sandbox` client. Native tools are disabled in the test profile, client tool
callbacks are refused, and no client identity is impersonated.

The local public-path check used trusted `[providers.google.elgoog]` with
`enabled = true`, `auth_mode = "subscription"`, and
`default_model = "gemini-4-hydrogen"`. `oc-sandbox google shell elgoog` opened the stock
OpenCode picker, displayed `gemini-4-hydrogen - elgoog [subscription]`, and returned
exact `ok` after `oc-sandbox google arm RUN_ID` in a second terminal. Both containers and
the private run directory retired. The label is configurable: the implementation
accepts any enabled Google subscription label with the qualified Hydrogen model.
The broker checks the configured label at the measured model-display and provider-ID
positions, then matches the complete normalized `elgoog` system digest before admitting
a turn. A second live run
with a temporary `custom-google` label initially failed at that check, then returned
exact `ok` after the bounded substitution was added. The temporary provider entry was
removed after verified cleanup.
The opt-in [public shell live test](../../tests/e2e/live/test_google_text_e2e.py)
uses `--run-google-public-shell-live` and one collection-time approval. It requires a
cached workstation Antigravity login and an enabled `elgoog` entry for that test fixture.
Ordinary test and CI runs skip it.

This public slice admits only the measured Hydrogen model and exact one-turn
OpenCode transcript. The broker validates the selected route and fixed prompt, spends
one approval under the owner fence, buffers the native text until terminal completion,
and retires the native process before returning `ok`. Replay and changed inputs are
refused. An uncertain turn retains no authority to send another prompt. The broker
checks the native exit status as well as its terminal output before releasing reply bytes.
If native retirement cannot be verified, the owner keeps its private ACP scratch and an
actor-identity receipt; the retained shell placement links to that cleanup directory.
The live test reports only fixed failure categories and a bounded exit code, without
echoing terminal content.
A later adapter
will join the default multi-provider session after the account binding, spend journal,
and original worker incarnation conditions below are qualified. The general route
must bind consent to a verified account and authorization mode, recheck it before the
first prompt write, persist the approval as spent before that write, and bind delivery
to the original worker connection and slot. Google exhaustion must leave an authorized
OpenAI slot usable.

Google's [Antigravity FAQ](https://antigravity.google/docs/faq#why-cant-i-use-third-party-software-such-as-claude-code-openclaw-or-opencode-with-my-antigravity-login)
calls out OpenCode. The operator may choose this experimental local route with the
known account risk. Release documentation should describe that risk and the supported
Gemini API-key path. The product must respect provider authentication and entitlement
responses and avoid changing client identity to alter those responses.

The pinned standalone fixture's cold refresh used the same client ID and the same three
scopes as enrollment. The local metadata controller now joins the initial and cold
request parsers to the durable profile and checks owner authority before a destination
write, subject binding, or native reply. A synthetic cold replay admitted exactly
token refresh, subject lookup, load metadata and model catalog. Missing credentials,
changed subjects, and mismatched catalog projects fail closed.

The pinned standalone supervisor passed a synthetic sign-in through a private callback
without opening a browser. It then started a separate zero-prompt reopen. The broker
observed the same subject and a fixture Gemini model, and settled the observation after
the exact service exited and its disposable profile was removed. The native server
replaced the disposable credential inode during refresh. The registered credential's
inode and bytes remained intact. Startup ACP notifications were discarded after exact
session and schema validation.

The workstation command is `oc-sandbox google connect LABEL`. It requires an enabled
`google/LABEL` subscription entry in the trusted `providers.toml` and the two pinned
standalone 1.5.2 files under `~/.local/share/oc-sandbox/google/standalone-1.5.2`.
The command presents link-only consent on the verified foreground terminal.
A copied-launcher fixture ran the pinned native process, recorded seven ordered fake
metadata operations across sign-in and a fresh reopen, and verified both native
retirements. The resulting local observation grants no invocation authority.
The attended Chrome run completed the authorization callback after a successful
official `agy acp --login`. The standalone metadata response still omitted both
the current tier and companion project. The broker refused enrollment and the
registration remained incomplete. The refusal now distinguishes the shape of a
personal first-use offer using fixed categories. A separate offline test of the
pinned standalone build observed native setup and a subsequent metadata reload.
The live account's first-use eligibility remains unknown.

The attended test in `tests/e2e/live/test_google_text_e2e.py` exercises a separate path using the
workstation's existing official `agy acp` personal login. It opened a private native session
using the pinned CLI 1.5.15 and an empty, read-only workspace. The broker closed the Secret
Service proxy before the prompt. A live `gemini-4-neon` turn returned exact `ok` and a terminal
ACP event with no tool calls reported. This proves one ACP prompt and the text result. Native
provider requests and billing remain opaque. The driver presents foreground consent and accepts
only its fixed prompt. Normal sandbox and orchestrator launch remain the intended OpenCode entry
points for named Google subscriptions.

- [x] Demonstrate one text-only OpenCode turn through the bundled ACP peer
  (`codex/antigravity-acp-text-proxy`). The pinned worker returned exact `ok` in devbox.
  The peer counted one prompt, replay was refused, and cleanup was verified. Offline controls
  observed zero prompts when revocation won before admission and zero answer bytes when
  the peer emitted early text or a callback.
- [x] Demonstrate the experimental public, fixed-text Hydrogen shell on `codex/gemini-public-shell`.
  The live stock OpenCode picker selected a named subscription, two configured labels returned
  exact `ok` through the cached workstation ACP login, and worker, relay and run cleanup passed.
  Preserve the opt-in live regression and the ordinary no-inference test default.
- [ ] Bind a named Google provider to a verified subscription subject before claiming
  multi-account or general-release support. The tested ACP session exposes a model and tier
  but no account subject. The current command displays that it uses the workstation's active
  Antigravity login and cannot verify which account the login represents.
- [ ] Resolve the release eligibility of this Antigravity subscription route against the
  provider's published third-party software restriction. This does not block the
  maintainer's attended local interoperability proof. Keep final Human review open.
- [ ] Qualify the pinned `agy` binary, rootless private provider home and keyring, bounded ACP
  channel, and separately scoped enrollment and execution egress. Verify the provider cannot
  access ordinary workstation credentials. Verify that the worker and relay get only the approved
  broker route and cannot read or invoke private provider resources.
- [ ] Before rootless enrollment, use the actual rootless launcher to reopen a synthetic keyring
  item after both bus and daemon restart, reach signed-out ACP with pinned `agy`, and check worker
  and relay denial with known-present workstation fixtures. Qualify same-UID devbox denial and
  sudo-free routine launches separately before offering the optional stronger placement.
- [ ] Qualify personal Google OAuth enrollment with the pinned standalone editor ACP server.
  Present the verified workstation-only consent link without opening a browser automatically.
  Verify the pinned desktop callback envelope and host server identities. Bind the initial
  OAuth subject and a fresh reopen to the exact private profile, while keeping account
  identifiers, browser state, codes and credentials outside the worker. Keep enrollment
  limited to authentication and metadata. Test cancellation, expiration, subject replacement,
  and denial of non-subscription fallback. Preserve the ordinary Antigravity login.
- [ ] Qualify a separately authorized native first-use setup path for the standalone ACP
  build. Require a verified personal offer, keep the vendor request bound to the same
  account and enrollment, and cap setup to one mutation and bounded status checks. Require
  Google's completed tier and project metadata before cold verification. A missing or
  contradictory offer leaves enrollment unavailable.
- [ ] From a fresh process in the same qualified placement, negotiate ACP and open a session
  in an empty scratch directory with no MCP servers. Verify only `initialize` and `session/new`
  were sent, zero tool grants, bounded redacted output and cleanup. A signed-out profile must
  request authentication. Keep identity, plan tier and billing unknown where unsupported.
- [ ] Record sign-in and reuse evidence. Review the exact route, host tool boundary, provider
  scope and first live prompt separately before enabling Antigravity in a managed worker.
- [ ] Qualify provider-side tool disabling and output bounds for the exact personal
  subscription endpoint and selected model. The standalone build emitted function-calling
  mode `AUTO` and requested 65,535 output tokens in the measured turn. A typed candidate
  projection to `NONE` and 64 output tokens passed offline validation. Establish the public
  endpoint behavior before offering inference.

### Native first-use walkthrough for review

1. Bind the verified Google account and native process to the attended enrollment. If the
   first metadata response already contains the tier and project, continue to the existing
   cold check.
2. If Google returns an unambiguous personal first-use offer, ask for separate foreground
   consent before opening additional routes. Explain the provider-side enrollment effect.
   Absent, contradictory, enterprise, project-selection, or paid-plan-change requirements
   stop the enrollment.
3. The pinned native process must originate the setup request. Recheck the account, process,
   consent, and observed offer immediately before reserving its single write. Poll only the
   returned operation under a deadline. An ambiguous write leaves a held receipt and cannot
   retry automatically.
4. Re-read Google metadata. Require the completed tier and project and continuity of any
   earlier paid-tier evidence. Retire the initial process, then require the existing fresh
   zero-prompt cold check. Failed or denied setup publishes no launchable provider.

[Antigravity ACP authentication](https://antigravity.google/docs/ide/extensions/acp/#authentication)

[standalone-acp]: https://github.com/agentclientprotocol/registry/blob/e29b5bf3bfd8756db5d901690b43dc31e926ccd5/antigravity-acp/agent.json
