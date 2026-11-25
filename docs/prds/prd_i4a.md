# I4a: Local OpenAI subscription acceptance

Parent: [I4 model gateway](prd_i4.md) · related: [I3a worker isolation](prd_i3a.md),
[M1 request and usage policy](prd_m1.md)

- [ ] Qualify the workstation connection, fixed GPT proposal, and local worker
  acceptance below, including reviewer and operator acceptance.
- [ ] Extend the accepted route to the Chromium and Postgres app workflow.
  Qualify its separate service placement and job-local credentials before
  admitting the broader developer tools and workspace.
- [ ] Reclaim abandoned local registration directories. Failed sign-in can
  free its registry slot while leaving the private state directory behind.
  Review cleanup under the existing Connect lifetime and registry locks.
  Remove only verified, unreferenced directories with no active attempt,
  retained provider registration or possible token exchange, unsettled
  revocation, or worker cleanup. Preserve uncertain state for recovery.
  Test failed sign-in, cancellation, restart recovery, and a concurrent
  connect or disconnect with synthetic credentials in a scratch store.
- [ ] Define recovery for a possible upstream send without verified usage.
  Preserve the original request reservation and its unresolved outcome.
  The maintainer chose one attended workstation diagnostic with the full
  outstanding reservation included in its disclosed exposure. The
  original run cannot continue from the diagnostic.
- [ ] Qualify delegated diagnostics from a protected controller. The
  workstation helper owns consent and provider credentials. Expose only the
  trigger for an already-approved request and its redacted result.

## Gate 1 walkthrough

After foreground consent with `[y/N]`, display a single-use browser-start
URL on the existing loopback listener. It redirects only to the host-built
OpenAI authorization request while the exact attempt remains current.
The optional default opener uses a private temporary page. `--no-browser`
uses the loopback URL without creating that page. Both entry paths share
the same callback and token exchange. Keep inference approvals separate
and flush terminal typeahead before each prompt.

The [Tauri dashboard](prd_m3b.md) can later trigger this typed workstation
sign-in flow. Open provider authorization in the external browser and
return connection status to the dashboard. The daemon owns the transaction
and credential store. [OAuth for native apps](https://www.rfc-editor.org/rfc/rfc8252.html#section-8.12)

Use the official open-source Sign in with ChatGPT dynamic registration and
the public Responses API for a free local application operated by one user.
OpenAI's example uses `gpt-6.2-sol`; select only that slug if the same token's
catalog includes it with visibility `list`. Separate the operator's app
connection, grant for one proof, and worker lifetime. The registered
application name is `oc-sandbox`. Never reuse the first-party Codex login or
copy provider credentials, legacy OpenCode home, or credential-bearing files
into any worker. [Sign-in guide](https://developers.openai.com/siwc/token-sharing-open-source/sign-in)
· [Responses guide](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference)
· [Usage terms](https://openai.com/policies/sign-in-with-chatgpt-terms/)

### CLI and control lane

- Reserve the exact leading `oc-sandbox openai` subcommand with `connect`,
  `status`, `disconnect`, and `select`. Connect and select take one
  bounded local registration label. Reject extra flags and paths before
  any effects. Dispatch to trusted installed helper after source and
  sandbox path guards but before legacy setup. Keep all other launcher
  entry points unchanged. The first release qualifies the existing
  devbox/host-spawn placement only. A reviewer can call the worktree's
  actual launcher; do not replace the installed symlink as part of review.
- The [attended pytest case](../../tests/e2e/live/test_openai_proof.py) runs
  one foreground terminal sequence in an isolated workstation process.
  Require explicit live opt-in and verify the checkout and driver before
  spawn. Reap the driver after its cleanup on terminal interruption.
  Present data disclosure and
  usage, require direct operator consent, then send one fixed harmless GPT
  input from the workstation. It asks for one exact text marker proposing a
  disposable worker proof. The host recognizes that marker only after
  verified completion, shows the fixed proposal and asks for separate
  operator approval, which authorizes one disposable worker, the exact
  scratch write and at most two more upstream requests. Pin both approvals
  to the same run, registration, model and connection generation. Recheck
  after each prompt. Before each respective approval there is no inference
  or worker creation, prompt or grant. Unknown model output, an incomplete stream, failure,
  absent TTY, or cancellation stops without spawning a worker. The model
  cannot select a shell command, file, URL, flags, or account. For this
  single-purpose terminal orchestrator, an in-process state machine is
  sufficient; general CoordHub integration is a follow-up. A model
  proposal carries no authority.
- After the second approval, create one disposable worker and submit one
  fixed OpenCode task. Exit success only after verified tool receipt, exact
  scratch bytes, native terminal event, and verified owned-resource cleanup.
  Start fresh on each invocation and never automatically replay a turn.
  A fake backend is injected by tests only; no runtime environment or
  subcommand selects an arbitrary issuer, URL, test implementation, or
  scope. Normal output identifies ChatGPT plan use and never prints token,
  account IDs, provider diagnostics, or arbitrary model text.

### Connection and upstream lane

- `connect`: trusted terminal consent and local privacy notice before
  opening the host browser. Use a fresh finite loopback attempt on
  `127.0.0.1` with unique state, nonce, PKCE S256 and exact callback URI.
  Validate one success or error callback, consume it before token
  exchange, and reject replay and duplicate/malformed query values. Do
  not use a browser controlled by the worker. Start with
  `dynamic_agent_client`, retain the issued client per verified identity
  and a stable opaque host ID, and verify the ID token's signature,
  issuer, audience, nonce, expiry, subject and returning-account match.
  Use a maintained JOSE verifier from a trusted distribution and pin
  supported algorithms and key source. No custom signature crypto.
  Install prerequisites explicitly; never download packages while
  reading credentials. Require direct-use scope from the token response.
  Account connection issues zero worker grants.
- Support separate saved registrations and show the active local label in
  status and both inference approvals. Persist one provider-facing UUID
  URN per workstation installation. Each label maps to an opaque private
  directory with the registration's own issued client, verified subject
  and generation. Reject duplicate issued clients across labels. Keep
  pending sign-in separate until identity and scope are verified. Fence the
  exact attempt and selection epoch before the first exchange write and
  again before publishing. Persist observation of a valid issued client
  before acknowledging the callback. A failed or stale attempt preserves the active
  selection. One nonblocking sign-in lifetime lock covers reservation
  through cleanup. Reclaim an abandoned label at capacity only when
  durable state shows no issuance or possible exchange.
  Keep unresolved upstream revocation visible for the affected label,
  including an unselected or unpublished registration.
- Serialize selection publication against foreground inference and the
  managed worker. Check for a still-unsettled usage record or worker
  lease before switching labels. Later approval checks include the
  selection epoch. Keep the reuse and revocation controls across labels.
- On disconnect, write the local account retirement fence before
  reporting a registry change. Cross-process late callbacks or refresh
  results may not restore a retired connection. Keep unresolved provider
  revocation visible. A returning callback that omits the issued client
  uses the stored client. A different returned client is rejected.
- Use bounded HTTPS to exact documented OpenAI origins, no redirects or
  worker-supplied headers. Hold bearer in workstation process memory and
  attach it only to the chosen fixed origin. Rebuild every body using
  `store: false`, `stream: true`, host-owned input and function definitions.
  No API-key fallback. Status and catalog checks never dispatch inference.
- Exposure decision for this attended acceptance only: at most one
  orchestrator inference and two worker inferences after separate operator
  authorizations. No retry, no background, and no arbitrary transcript.
  Disclose use of ChatGPT plan or account credits and require the operator
  to review the app's usage/credit settings before approval. The
  [GPT-6.2 Sol model documentation](https://developers.openai.com/api/docs/models/gpt-6.2-sol)
  lists up to 922,000 input tokens and 128,000 output tokens per request.
  The SIWC API does not accept a caller-specified output cap. Reserve
  those maxima before each eligible POST. The first consent covers one
  reservation, and the second covers up to two more. The independent
  placement review accepted the published maxima for this fixed, attended
  proof with exact same-token model visibility checks. The operator
  chooses whether to accept provider-managed credit exposure without a
  verified hard money ceiling. API-key fallback is disabled.
- Durably reserve one exact phase and its possible exposure before the
  first upstream byte can be sent. Crash, unknown send and missing valid
  usage retain the reservation across restart and connection retirement,
  so they cannot create another send or fresh headroom. Validate
  one matching `response.created` and `response.completed` identity,
  consistent model, and authenticated terminal usage before accepting success. Record an
  authoritative usage overage and suspend future inference. A failed,
  truncated, over-limit, or unknown send does not earn a replacement request. Closing local I/O is not proof that OpenAI stopped work.

### Managed worker lane

- Project a fresh OpenCode 2.3.0 worker and its relay from pinned cached
  images with no pulls. Qualify rootless Podman, enforcing SELinux and
  shared monotonic clock on the measured devbox path. Verify immutable
  resource IDs, distinct PID/mount boundaries, exact read-only relay
  mounts and process labels. Give the worker a private disposable home
  and workspace, full local file and shell access, and an isolated
  network with only its private route. Mount no legacy home, workstation
  secrets, sockets or data. Scope the public OpenCode compatibility
  strings to the fixture. The relay gets only its own private job proof,
  not the upstream credentials. Agree on exact ownership, terminal
  transition and cleanup evidence. Do not reuse an existing legacy pod.
- Keep inference closed through trusted native readiness. Authorize only
  the predeclared workflow with at most one initial request and one
  matching continuation. The workstation chooses exact user input,
  instructions, model and one local write tool with a fixed path and
  contents. Worker HTTP can only trigger that exact task. It supplies no
  upstream prompt, tool schema, raw tool output, header, or destination.
  Verify this with a separate fake upstream and an alternate in-job
  client that varies each of those inputs. It must see zero requests
  or the same host-constructed request.
  Only the validated expected tool call becomes executable. Buffer the
  bounded proof output through terminal validation. Before admitting a
  continuation require the exact shared relay delivery receipt plus an
  independent bounded no-follow read of the expected scratch bytes.
  Establish that the file is absent initially and bind the read to the
  intended workspace. The bytes prove the observed effect and the
  pinned client's native tool events provide separate execution evidence.
  Construct the continuation using the prior approved request, accepted
  call and a fixed host-produced tool result. If OpenAI supplies reasoning
  items, keep their bounded encrypted continuation data and order on the
  workstation. Before tool delivery, verify that the complete approved
  continuation fits the request limit. Return the data only to the
  same OpenAI route for that continuation. [Stateless reasoning
  replay](https://developers.openai.com/api/docs/guides/reasoning#preserve-reasoning-without-stored-responses) The sandbox can consume its
  own admitted allowance, but cannot request arbitrary inference. If
  this exact connected-app placement changes, review the new route
  before enabling it.
- Fence admission and final worker delivery against the same revoke /
  expiry authority. Record the exact grant directory and stable lock
  and lifetime inodes before activation. On account disconnect, preserve
  the retirement intent before taking the relay's delivery lock and
  publishing the terminal marker. Keep the same-grant marker check under
  every nonblocking worker write. For reboot recovery, require a fresh
  corroborated physical-workstation and boot observation bound to the
  exact persisted lease. Otherwise use the pinned fence or retain the
  unfinished retirement. Close relay sockets on
  revoke, failure or owner loss. Bind continuation to one admitted phase and verify
  exact cleanup of all owned containers. Retain a private ownership
  receipt only if cleanup is inconclusive. User data, local service
  sidecars and remote placement have separate acceptance before use.

### Proof and review

The maintainer reported a successful attended `connect personal --no-browser`
with the one-time loopback link. Workstation inference and the managed
OpenCode worker still require their own live acceptance.

The first attended pytest run reached the workstation approval and recorded
one possible upstream send. It stopped without verified terminal usage,
before the worker approval. The installation ledger retains that reservation.

The attended one-shot diagnostic reached response handling and failed event
stream validation. Both the original reservation and the diagnostic receipt
have unknown usage. The terminal message did not distinguish the specific
parser check. The installation has spent its one-shot diagnostic and ordinary
inference remains on hold.

- [ ] Qualify the SSE framing updates against the live route. Synthetic
  fixtures cover CR, LF and CRLF, one leading UTF-8 BOM, two explicit names
  for a terminal `[DONE]` after completion, complete trailing comments,
  and typed JSON with either generic SSE event name. Completion still needs
  valid HTTP termination and verified usage. Independent offline comparison
  also identified unqualified heartbeat frames and model aliases. The
  retained live evidence does not identify any of these forms.

#### One-shot diagnostic after an unsettled send

The historical request used `store: false` and no provider request ID or
verified usage was captured. Keep the original ledger bytes and unknown
outcome. The recovery test is eligible only for an installation with exactly
one unresolved workstation proposal and the same active connection
generation and selection. This first mode has one recovery opportunity per
installation.

1. Require both explicit pytest switches, the reviewed local checkout and a
   foreground workstation terminal. Check the exact original row and the
   absence of any diagnostic receipt under the installation exposure lock.
   Check the foreground request lock before offering approval.
2. Present the possible exposure as the original full reservation plus one
   additional reservation, for a combined 1,844,000 input and 256,000 output
   tokens. The provider determines actual usage and credits. Obtain new
   operator confirmation for one fixed workstation diagnostic.
3. Recheck the selected connection and exact old and new slots before
   dispatch. Under the exposure lock, durably write the new diagnostic
   receipt before the first possible request byte. A failure after this
   point consumes the one opportunity. Use the same fixed payload,
   authenticated provider, and strict terminal usage checks.
4. Settle only the diagnostic with its own verified usage. Keep any reported
   overage. On restart, the receipt continues to block repeat diagnostics.
   Ordinary inference stays suspended while the original outcome is unknown,
   and the diagnostic has no worker phase. A malformed or orphaned receipt
   keeps admission closed.

#### Final SSE diagnostic

After the offline framing changes, allow one final workstation-only request
through the separate `--recover-stream-live` pytest mode. Check that the
original and first diagnostic are distinct, remain unknown, and match
the current selected registration. Show both unknown outcomes, all three
reservations (2,766,000 input and 384,000 output tokens), and the usage and
credit settings notice. One fresh foreground approval covers one fixed
proposal. Seal the third receipt before the first possible request byte
   and retain both earlier files byte-for-byte. Only this request's verified
terminal usage can settle its receipt. Any third receipt keeps ordinary
inference on hold. A successful workstation diagnostic has no worker phase.
On a stream failure, offer one structural line with a fixed rejection code,
bounded counters and allowlisted event names. The completion and sentinel
flags describe observed wire structure. Verified usage still needs the
full settlement checks. Response content stays out of the diagnostic.

The attended stream diagnostic reached HTTP 200 and failed at the media-type
check before reading response body bytes. The content-type bucket was
`other`. All three linked reservations still have unknown usage. Use
closed header and bounded body-prefix categories to diagnose a future
approved request. An SSE-like prefix by itself cannot establish completion.

#### Delegated diagnostics

Codex can run the offline and real-Podman fixture tests from devbox. To
delegate one live request, a foreground operator starts a short-lived trusted
workstation helper. The consent binds the active registration and selection,
the three existing receipts, one fixed request, the exact reviewed executable,
and expiry. Show the aggregate reservation for all four possible requests,
3,688,000 input and 512,000 output tokens, and the usage and credit settings
notice. The helper rechecks that binding and writes the new receipt durably
before the first possible POST byte. An unused permit expires when the
helper exits. A used permit cannot be triggered again.

The test controller receives only a trigger socket and a redacted result.
A synthetic devbox prototype used Bubblewrap with only that socket mounted.
It triggered once while protected synthetic state and approval files were
inaccessible. The fixture refused minting, replay, expiration, revocation,
and a changed binding. Qualify the real consent and credential owner,
receipt durability and execution from the actual restricted controller
before live use. The existing unrestricted devbox tool runner
shares the workstation account; its access permissions do not provide
independent operator authority.

#### One approval for a full recovery proof

- [ ] Qualify one dedicated recovery run after the three linked unknown
  workstation receipts. Carry one foreground approval through the fixed
  workstation proposal and, only after verified usage and the expected
  marker, one disposable OpenCode worker with an initial turn and one tool
  continuation. Reserve each possible send before it can reach OpenAI.
  Retain the three earlier receipts and the hold on ordinary inference.

The approval is for this foreground process, selected registration,
generation and selection epoch, model, exact payloads, and five-minute
dispatch window. Show the three historical reservations and up to three new
ones (5,532,000 input and 768,000 output tokens in total), the usage and credit
settings notice, and the absence of a verified currency ceiling. Reuse the
approval for the worker phases in that process. Process exit, revocation, or
a source revision change requires a new review of any further live attempt.

```text
preflight the exact linked unknown receipts and absent recovery receipt
show the fixed sequence and combined exposure; ask once
recheck selection and receipt bindings; open the five-minute window
for proposal, worker initial, and worker continuation in that order:
    check phase authorization, deadline, durable predecessor and lease
    write the exact new phase reservation under the exposure lock before POST
    settle that phase only with authenticated complete response and verified usage
    stop on any uncertain send, overage, payload mismatch or lease loss
verify native tool delivery, exact scratch bytes and container cleanup
```

Use a separate versioned receipt for the new phases. The first possible
send consumes the run even if the helper dies. Each later phase must
belong to the same run and follow verified, in-bound usage for the previous
phase. Keep the original receipts byte-for-byte.

The diagnostic evidence for the prior HTTP 200 stops at the media check.
The recovery proof may use a bounded compatibility check for an absent
media type or a single well-formed plain-text or octet-stream type.
Replay inspected bytes into the strict SSE parser only on a positive SSE
prefix. Require authenticated direct TLS, strict HTTP framing, matching
response identity and model, completion, usage, and exact marker or tool
evidence as before. Ambiguous headers and JSON, markup, and other bodies
stay rejected. Publish only fixed categories and counters on failure.

A loopback comparison with the OpenAI Python SDK used the same endpoint
path and request JSON with a synthetic token. Both clients parsed standard
SSE. The SDK accepted the same SSE fixture served as plain text, which the
ordinary connector rejected. The recovery connector parsed it with closed
media evidence. The SDK sent `Accept: application/json` and offered
compression. The connector requests SSE and identity encoding. This
comparison leaves the historical provider body and header unknown.

Verify historical receipt tampering and replay, same-run phase sequence,
terminal usage, deadlines, revocation, media compatibility and rejection,
and one-prompt success and failure. Qualify the complete proof first with
the synthetic provider and pinned Podman containers.

The security and PR-style reviews cleared the walkthrough and the exact
local proof source digest
`4cbcf31fc1e5c740c2fe5e2ea27b4a1f71c542c0b4f63ac09477af8370570118`
for one foreground run after verification. Devbox passed 169 OpenAI tests,
including the pinned Podman worker and synthetic provider, and 246 host
security checks. Portable CI and the pinned quality checks passed.
Real subscription acceptance remains open until the live run succeeds.

The attended run for that digest verified the workstation marker and
settled both the workstation and worker-initial requests. In both phases
the provider sent valid SSE without a Content-Type header. The worker
reported a generic failure before a continuation was reserved. Devbox
showed no owned proof containers or private proof directories afterward.
Preserve the complete accounting record of this attempt.

#### Worker-only follow-up

- [ ] Qualify a fresh worker from the verified workstation evidence and
  the settled initial request of the prior attempt. Admit one initial
  request and, only after the approved file and delivery receipt verify,
  one stateless tool continuation. Preserve all prior receipts.

Use the same selected registration, generation, and selection epoch. Check
the exact prior proof source digest and settled phases, the absence of a
prior continuation, and the absence of a follow-up receipt. One fresh
foreground approval binds the exact new snapshot and those two fixed
requests for five minutes. The two new requests reserve up to 1,844,000
input and 256,000 output tokens. Counting the five previous reservations
in full, the total is 6,454,000 input and 896,000 output tokens. No verified
currency ceiling is available. Retain the installation hold on ordinary
inference. One possible send spends the follow-up opportunity.

The maintainer delegated this diagnostic run to the local workstation
operator for this chat. The one-off reviewed developer launcher pins its
own execution, the package source, the selected binding, and the prior
receipts. Its supervisor can retire the pinned worker if the operator
process exits, and each send checks that supervisor's lifetime. The
launcher digest identifies the code. The maintainer's message supplies
the operator authority. The ordinary CLI and pytest consent path still
require a foreground operator.

Expose only fixed worker failure categories to the workstation operator,
covering validation, projection, relay delivery, native tool evidence,
and continuation admission. Preserve cleanup and retirement failure
precedence. The first run did not retain provider payloads, so the exact
worker validation failure is unknown. Synthetic tests reproduced two
documented response variants the current validator rejects: a completed
tool call without an assistant preamble and a completed response whose
tool call omits the per-item status. The worker proof still requires the
exact approved write, verified file bytes and receipt, and a final model
message. An absent preamble yields no synthesized model text. Restrict
accepted reasoning replay to authenticated, matched, completed, bounded
ciphertext in provider order.

The first delegated worker-only run verified the initial request usage
within its bounds and reported an upstream event validation failure.
There was no continuation reservation, and devbox verified cleanup.
The next reviewed allowance pins that settled worker receipt as well as
the four earlier files. It accepts a closed set of bounded queue and
heartbeat events and separately reports event ordering, identity, label,
type, annotation, output-item and size failures. Exactly two new requests
are possible, with the same five-minute authority window. Across the
three historical unknowns, three settled requests and two possible new
requests, the full reservation ceilings total 7,376,000 input and
1,024,000 output tokens.

The delegated event-compatibility run settled its initial usage and
reported an unknown event. It sent no continuation and removed its
owned resources. The next diagnostic is scoped to the exact initial
request and the event-type evidence needed to distinguish a new
provider event from a worker-validation error. The diagnostic does
not launch a worker or call a tool. It consumes one dedicated
reservation after independently matching all six predecessor files and
the active selection. No request or response content enters the
diagnostic output.

The standalone trace settled its one initial request. The private
fingerprint matched `response.metadata` locally. Its top-level response
ID matched the active response, and the sequence number was valid. The
checks found absent nested response, output item, error and incomplete
details. The [OpenAI Codex stream
reader](https://github.com/openai/codex/blob/main/codex-rs/codex-api/src/sse/responses.rs)
handles that event separately from output items. Its [event
fixture](https://github.com/openai/codex/blob/main/codex-rs/core/tests/common/responses.rs)
gives the expected envelope. Qualification requires a targeted
metadata check that preserves moderation and review stops and keeps
metadata out of the worker and the continuation.

The delegated worker with the reviewed envelope handler settled its
initial request and reached the moderation-content check. The broker
reported unsupported moderation metadata. The continuation remained
unreserved and devbox verified cleanup. The diagnostic establishes
the field that needs qualification while leaving the exact payload
shape and any affirmative policy signal unverified.

The reviewed standalone moderation trace settled one initial request.
The bounded summary found a prompt classification with one unblocked
output, no captured affirmative block or review flag, and extra fields
at the moderation root. The result does not establish an all-clear.
The provider's published client treats the moderation object as a
notification and has a separate action-bound Guardian check. The
available contract gives no tool-release rule for the observed shape.
Keep the worker hold and leave live acceptance open until that rule
can be established. Devbox confirmed zero remaining proof containers
and private run directories. The exact diagnostic package passed
184 OpenAI tests, 246 host security checks, portable CI and pinned
quality checks.

Test CLI dispatch and rejection before legacy effects, exact scoped
operator consent, wrong/replayed callbacks and ID tokens, credential
redaction, refresh/disconnect ordering, provider HTTP framing and
usage failure, readiness and resource identity, stale/sibling/late
revocation, receipt and tool continuation, and exact cleanup. Run all
premerge tests with inert synthetic data. For the real worker qualification
use pinned OpenCode on disposable Podman; include the repository's real
security and parallel host gates. Before the live review, record the
provider, placement and hard usage gate status, and provide one step at a
time for operator sign-in and acceptance. Follow the
[review gates](README.md#implementation-review-gates) for exact changes.
