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

- [x] Demonstrate one text-only OpenCode turn through the bundled ACP peer
  (`codex/antigravity-acp-text-proxy`). The pinned worker returned exact `ok` in devbox.
  The peer counted one prompt, replay was refused, and cleanup was verified. Offline controls
  observed zero prompts when revocation won before admission and zero answer bytes when
  the peer emitted early text or a callback.
- [ ] Qualify the pinned `agy` binary, rootless private provider home and keyring, bounded ACP
  channel, and separately scoped enrollment and execution egress. Verify the provider cannot
  access ordinary workstation credentials. Verify that the worker and relay get only the approved
  broker route and cannot read or invoke private provider resources.
- [ ] Before rootless enrollment, use the actual rootless launcher to reopen a synthetic keyring
  item after both bus and daemon restart, reach signed-out ACP with pinned `agy`, and check worker
  and relay denial with known-present workstation fixtures. Qualify same-UID devbox denial and
  sudo-free routine launches separately before offering the optional stronger placement.
- [ ] In the qualified placement, guide the operator through documented `agy acp --login`
  for personal Google OAuth. Use the native terminal or browser handoff without sharing browser
  state, codes or credential material with agents. Test unavailable binary, cancellation,
  expiration and denial of non-subscription fallback. Preserve the ordinary Antigravity login.
- [ ] From a fresh process in the same qualified placement, negotiate ACP and open a session
  in an empty scratch directory with no MCP servers. Verify only `initialize` and `session/new`
  were sent, zero tool grants, bounded redacted output and cleanup. A signed-out profile must
  request authentication. Keep identity, plan tier and billing unknown where unsupported.
- [ ] Record sign-in and reuse evidence. Review the exact route, host tool boundary, provider
  scope and first live prompt separately before enabling Antigravity in a managed worker.

[Antigravity ACP authentication](https://antigravity.google/docs/ide/extensions/acp/#authentication)
