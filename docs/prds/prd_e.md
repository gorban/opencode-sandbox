# prd_e: Local HTTPS / TLS per instance

[Index](README.md) · children: [prd_e1](prd_e1.md) (CA and trust), [prd_e2](prd_e2.md) (per-instance certificates), [prd_e3](prd_e3.md) (Postgres TLS)

## Goal

An app in instance `feat-a` serves `https://feat-a.<suffix>` with a certificate that is trusted both by
the pod's Chromium and by the host's browsers and tools, using the same URL on the same port. Postgres
at `feat-a.<suffix>:5432` uses TLS by default. Depends on [prd_d](prd_d.md) for the name and address.

## Reference: api-agent (`~/construct/api-agent`)

- Tools are pinned in `mise.toml` with `locked = true` and checksums in `mise.lock`:
  `"aqua:FiloSottile/mkcert" = { version = "1.4.4", lazy = true }` and
  `"conda:openssl" = { version = "3.5.9", lazy = true }`.
- `src/api_agent/runtime/https.py`: runs `mkcert -install` interactively (the trust prompt), reads
  `mkcert -CAROOT`, and issues certificates into a staging directory under a directory lock. Keys must
  be regular files, owned by the user, mode 0600 (no symlinks). Existing certificates are reused while
  their SANs match and they aren't close to expiry.

## Security stance

**The CA private key never enters a sandbox.** An agent holding a CA that the host trusts could mint a
certificate for any site (your bank, GitHub) and intercept host traffic. Therefore:

- A dedicated CA for oc-sandbox, separate from the mkcert CA that api-agent uses.
- Constrain the CA's names, including explicit IP constraints. The E1 spike found that a DNS-only
  constraint leaves IP identities unconstrained, while profiles permitting localhost also allow
  impersonation of unrelated loopback services. E, which excludes all IPs, is recommended but has not
  been selected; C and D permit narrower or broader loopback identities. Even E permits misuse of
  allowed names if the key leaks. The spike measured a client matrix and a limited Firefox/Chrome host
  subset; see [prd_e1](prd_e1.md) for results and the open profile choice. mkcert cannot create
  constrained CAs; OpenSSL can. Whether mkcert or direct tools should handle installation and leaf
  issuance remains open ([prd_e1](prd_e1.md), [prd_f](prd_f.md)).
- Only the instance's **leaf** key and certificate go into its pod, valid only for `feat-a.<suffix>`.

## Items

- [ ] CA creation and trust installation on the host and in pods ([prd_e1](prd_e1.md)).
- [ ] Per-instance leaf certificates, renewal, and where apps find them ([prd_e2](prd_e2.md)).
- [ ] Postgres with TLS by default ([prd_e3](prd_e3.md)).
- [ ] Tool pinning via mise ([prd_f](prd_f.md)).

Estimated time: 2–4 days after [prd_d](prd_d.md).

- [ ] **Human review**: checked only when the user says so
