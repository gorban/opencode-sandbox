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

### Attended enrollment walkthrough

The offline command will use the pinned client, a disposable outer keyring
and two local TLS peers. Its approval binds one attempt to the registration,
the client build and the ordered destinations `oauth2.googleapis.com:443`
and `www.googleapis.com:443`. Each destination gets one tunnel. The operator
can approve any HTTPS path on those destinations during enrollment. Methods
and paths are encrypted.

The foreground terminal displays a validated native Google link and accepts
a code with echo disabled. Browser launch, recording and agent output are
absent from this path. Loss of the terminal before submission cancels the
attempt. Native sign-in uses an empty workspace and only the isolated profile
and keyring.

Pinned `agy` 1.5.15 emitted the measured Google authorization URL and
Antigravity callback in an offline launcher. The foreground component accepted
that link shape. A synthetic controlling terminal verified hidden input, echo
restoration, fresh confirmation after the scope is shown, and removal of
unsubmitted code when the prompt times out. A detached terminal cancels the
handoff. The link guard checks the pinned public client ID, scopes and prompt.

The supervisor records a pending generation before creating the unlock item
or opening egress. The attempt has independent revocation, and cancellation
can close its sockets while the registration remains pending. The offline
test cancels after token issuance but before userinfo forwarding and verifies
no second-peer bytes, exact service retirement and the same pending generation.
The journal exercises ordered non-reusable reservations, cancellation across
reopen, stale-generation rejection, and distinct retirement and readiness
publication. Wiring the terminal, journal and credential holder together
remains open.

A fresh process must select exactly one existing unlock item for that
registration in the trusted collection. Missing, locked or duplicate items
leave it pending. The unlock pipe closes before the client starts.
Readiness requires only ACP `initialize` and `session/new` with enrollment
egress gone, then a generation check before publication. An expired item
that cannot refresh stays pending. A fresh attended retry requires an
explicit signed-out result.

[Antigravity ACP authentication](https://antigravity.google/docs/ide/extensions/acp/#authentication)
