# prd_a: Postgres reachable from the host

[Index](README.md)

## Problem

Users want to reach an instance's Postgres from host tools (psql, IDE, migrations). The usual
convention is `-P 5432` (same port on both sides) or `-P 5433:5432` when the host already uses 5432.
Port numbers must never be picked automatically: another app may want that port.

## Current behaviour

- `-P` refuses pod port 5432, because pods use `--host-lo-to-ns-lo`, so host connections reach the pod
  as `127.0.0.1`. The official Postgres image **trusts** `127.0.0.1` with no password (initdb default).
  Mapping it would let any host process, as any database user, in without a password.
- `-P` requires `HOST:POD`; a single port number is rejected.

## Proposal

- [ ] Accept `-P PORT` as shorthand for `-P PORT:PORT` (any port, not just Postgres).
- [ ] Make Postgres require a password on every TCP connection, including `127.0.0.1` (scram-sha-256 in
      `pg_hba.conf`). Keep `trust` only for the Unix socket inside the container. The agent gets a
      `PGPASSFILE` (mode 0600, in the pod only) so its `psql` keeps working without a prompt.
      **Decision (2026-11-15): rewrite `pg_hba.conf` from a script-owned template on every Postgres
      start**, so existing and new volumes behave the same. Custom hba edits are not kept; document
      this.
- [ ] With per-instance names ([prd_d](prd_d.md)), Postgres is reachable as
      `feat-a.oc-sandbox.internal:5432` once the password requirement is in place. `-P` stays for a fixed
      host port on `127.0.0.1`.
- [ ] With that in place, allow mapping pod port 5432 **only when `-p` is given** (`-p -P 5432`,
      `-p -P 5433:5432`). Keep refusing 9222 (DevTools) unconditionally.
- [ ] Print the host connection string on start (`postgresql://USER@127.0.0.1:5433/DB`), never the
      password.
- [ ] Tests: the host connects with a password, fails without one, and `-P 5432` without `-p` is
      refused.
- [ ] If [prd_e](prd_e.md) lands: default to TLS (`hostssl`), see [prd_e3](prd_e3.md).

### Options for existing data volumes (pg_hba lives in the data directory)

| Option | Pros | Cons | Time |
|---|---|---|---|
| **Rewrite `pg_hba.conf` at every Postgres start**, from a script-owned template mounted read-only (recommended) | the same on new and old volumes; can't drift; the user doesn't need to do anything | the script owns that file: custom hba edits would be lost | 0.5–1 day |
| Init script only (`/docker-entrypoint-initdb.d`) | simple | only applies to new volumes; old ones stay `trust` until recreated | 0.25 day |
| Refuse `-P 5432` until the volume is recreated | no migration code | the user loses data or has to dump and restore | 0.25 day |

- [ ] **Human review**: checked only when the user says so
