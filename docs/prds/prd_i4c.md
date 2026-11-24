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

### Credential-free TLS qualification

The workstation diagnostic bounds DNS, validates every result and tries one
numeric address for each pinned destination. It verifies the TLS certificate
and hostname without accessing a registration or sending HTTP. The local
fixture covers resolver timeout and overflow, revocation before ClientHello,
cancellation during the handshake, and a successful TLS exchange with zero
application bytes.

- [x] Qualify the two enrollment destinations with a credential-free
  workstation diagnostic. The reviewed `30a9456` implementation negotiated
  TLS 1.3 with certificate and hostname verification at
  `oauth2.googleapis.com:443` and `www.googleapis.com:443`. It sent zero HTTP
  requests and no application bytes. Attended enrollment, refresh and
  inference remain open.

[Antigravity ACP authentication](https://antigravity.google/docs/ide/extensions/acp/#authentication)
