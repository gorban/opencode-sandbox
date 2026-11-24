# I4c: Verify initial Google Antigravity sign-in

Parent: [I4](prd_i4.md) · related: [provider setup contract](prd_i4d.md),
[worker credential isolation](prd_i3a.md)

Owner: **Codex**, within **Outside-in integrations**. Scope is the native Google account
sign-in for Antigravity ACP and reuse from a fresh dedicated workstation process. The existing
devbox login supported ACP v1 session creation with `agy` 1.5.13. An offline empty profile
negotiated ACP and asked for authentication. Dedicated profile enrollment remains open.

- [ ] Qualify the trusted `agy` binary and a separate workstation OS identity, provider state,
  keyring and ACP channel using synthetic evidence. Verify that the provider cannot access
  ordinary workstation credentials and that the devbox runner, relay and worker cannot read
  or invoke private provider resources. Keep enrollment and later model execution egress
  policies separate.
- [ ] In the qualified placement, guide the operator through documented `agy acp --login`
  for personal Google OAuth. Use the native terminal or browser handoff without sharing browser
  state, codes or credential material with agents. Test unavailable binary, cancellation,
  expiration and denial of non-subscription fallback. Preserve the ordinary Antigravity login.
- [ ] From a fresh process under the same dedicated identity, negotiate ACP and open a session
  in an empty scratch directory with no MCP servers. Verify only `initialize` and `session/new`
  were sent, zero tool grants, bounded redacted output and cleanup. A signed-out profile must
  request authentication. Keep identity, plan tier and billing unknown where unsupported.
- [ ] Record sign-in and reuse evidence. Review the exact route, host tool boundary, provider
  scope and first live prompt separately before enabling Antigravity in a managed worker.

[Antigravity ACP authentication](https://antigravity.google/docs/ide/extensions/acp/#authentication)
