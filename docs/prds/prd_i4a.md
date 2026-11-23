# I4a: Local OpenAI subscription acceptance

Parent: [I4 model gateway](prd_i4.md) · related: [I3a worker isolation](prd_i3a.md),
[M1 request and usage policy](prd_m1.md)

- [ ] Qualify the workstation connection, fixed GPT proposal, and local worker
  acceptance below, including reviewer and operator acceptance.
- [ ] Extend the accepted route to the Chromium and Postgres app workflow.
  Qualify its separate service placement and job-local credentials before
  admitting the broader developer tools and workspace.

## Gate 1 walkthrough

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
  `status`, `disconnect`, `select`, and `accept`. Connect and select take one
  bounded local registration label. Reject extra flags and paths before
  any effects. Dispatch to trusted installed helper after source and
  sandbox path guards but before legacy setup. Keep all other launcher
  entry points unchanged. The first release qualifies the existing
  devbox/host-spawn placement only. A reviewer can call the worktree's
  actual launcher; do not replace the installed symlink as part of review.
- `accept` is one foreground terminal sequence. Present data disclosure and
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
  again before publishing. A failed or stale attempt preserves the active
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
  one matching `response.created` and `response.completed` identity and
  authenticated terminal usage before accepting success. Record an
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
