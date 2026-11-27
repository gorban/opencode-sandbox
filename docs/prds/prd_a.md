# prd_a: Postgres reachable from the host

[Index](README.md)

## Problem

Users want to reach an instance's Postgres from host tools (psql, IDE, migrations). The usual
convention is `-P 5432` (same port on both sides) or `-P 5433:5432` when the host already uses 5432.
Port numbers must never be picked automatically: another app may want that port. The current implementation is on `codex/foundations-batch`.

## Previous behaviour (before this branch)

- `-P` previously refused pod port 5432, because pods use `--host-lo-to-ns-lo`, so host connections reach the pod
  as `127.0.0.1`. The official Postgres image **trusts** `127.0.0.1` with no password (initdb default).
  Mapping it would let any host process, as any database user, in without a password.
- `-P` previously required `HOST:POD`; a single port number was rejected.

## Proposal

- [x] Accept `-P PORT` as shorthand for `-P PORT:PORT` (any port, not just Postgres).
- [x] Make Postgres require a password on every TCP connection, including `127.0.0.1` (scram-sha-256 in
      `pg_hba.conf`). Keep `trust` only for the Unix socket inside the container. The agent gets a
      `PGPASSFILE` (mode 0600, in the pod only) so its `psql` keeps working without a prompt.
      **Implementation (`codex/foundations-batch`):** supply the script-owned template as the server's
      read-only `hba_file` from process startup on every new or recreated container. Existing and new
      volumes behave the same, and volume-local `pg_hba.conf` edits are ignored rather than overwritten.
      Incompatible existing verifiers fail closed; the data volume is retained.
- [ ] **Deferred until prd_d implementation:** With per-instance names ([prd_d](prd_d.md)), Postgres is reachable as
      `feat-a.oc-sandbox.internal:5432` once the password requirement is in place. `-P` stays for a fixed
      host port on `127.0.0.1`.
- [x] With that in place, allow mapping pod port 5432 **only when `-p` is given** (`-p -P 5432`,
      `-p -P 5433:5432`). Keep refusing 9222 (DevTools) unconditionally.
- [x] Print the host connection string on start (`postgresql://USER@127.0.0.1:5433/DB`), never the
      password.
- [x] Tests: the host connects with a password, fails without one, and `-P 5432` without `-p` is
      refused.
- [ ] **Deferred until prd_e3 implementation:** If [prd_e](prd_e.md) lands: default to TLS (`hostssl`), see [prd_e3](prd_e3.md).

### Options for existing data volumes (pg_hba lives in the data directory)

| Option | Pros | Cons | Time |
|---|---|---|---|
| **Rewrite `pg_hba.conf` at every Postgres start**, from a script-owned template mounted read-only (recommended) | the same on new and old volumes; can't drift; the user doesn't need to do anything | the script owns that file: custom hba edits would be lost | 0.5–1 day |
| Init script only (`/docker-entrypoint-initdb.d`) | simple | only applies to new volumes; old ones stay `trust` until recreated | 0.25 day |
| Refuse `-P 5432` until the volume is recreated | no migration code | the user loses data or has to dump and restore | 0.25 day |

### Reopened: published-port check imported modules from the caller's directory

Found by the 2026-11-26 security audit after this grouping passed human review.

- [x] The check that compares an existing pod's real port bindings with its label ran host Python
      without isolated mode. The launcher keeps the caller's directory, which can be a sandbox
      repository, so an agent-planted `json.py` or `re.py` there ran as the operator on the next
      launch against an existing pod. Run that check, and the bridge's Python version probe, with
      `-I`. `tests/postgres-host.sh` now runs the check from a directory holding canary modules, and
      `tests/security.sh` audits that every `python3` option list in the launcher starts with `-I`.
      Both fail on the previous launcher. Branch `fix/launcher-isolated-host-python`; external
      review pending.
- [x] Review follow-up: that check and the bridge's version probe still found `python3` through the
      caller's `PATH`. Every host Python call in the launcher now names `/usr/bin/python3`, and
      the probe reaches the host through distrobox's installed dispatcher path.
      `tests/postgres-host.sh` and `tests/security.sh` cover both with stand-in commands on
      `PATH`. Same branch.
- [x] Review follow-up: the source check in `tests/security.sh` is now an audit that separates host
      calls from container entry points, requires the system interpreter and isolated mode where
      each call is made, covers direct-script and array forms, and fails if it cannot read the
      launcher. Fixtures for each form are checked alongside it. Same branch.

- [ ] **Human review**: checked only when the user says so
