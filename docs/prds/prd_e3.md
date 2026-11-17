# prd_e3: Postgres with TLS by default

Parent: [prd_e](prd_e.md) · related: [prd_a](prd_a.md)

- [ ] Start Postgres with `ssl=on`, using the instance leaf (`ssl_cert_file`, `ssl_key_file`; the key
      copied with the `postgres` owner and mode 0600, as Postgres requires).
- [ ] `pg_hba.conf` (the script-owned template from [prd_a](prd_a.md)): `hostssl … scram-sha-256` for
      TCP and `hostnossl all all all reject`. **Decision (2026-11-15): TLS required**; plain TCP is
      rejected.
- [ ] The agent and the host use `sslmode=verify-full` against the CA, with host `feat-a.<suffix>`.
- [ ] Print the host connection string with `sslmode=verify-full&sslrootcert=…`.
