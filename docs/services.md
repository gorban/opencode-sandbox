# Services

## Chromium

Chromium opens on your Wayland desktop and OpenCode can drive it through Chrome DevTools MCP.
The agent image sets `OPENCODE_CONFIG=/etc/opencode/oc-sandbox.json` with the DevTools MCP
configuration. OpenCode merges it with your own configuration. DevTools listens on
`127.0.0.1:9222` in the pod.

Only FIDO/U2F interfaces of security keys are passed to Chromium. Run `oc-sandbox -k` to list
the keys it detects or start with `oc-sandbox -K` to withhold them. Displayed device labels use
printable ASCII. See the
[browser security limits](security.md#security-model) before signing in.

## Port mapping (`-P`)

```bash
oc-sandbox -P 8080:80            # host 127.0.0.1:8080 -> pod 127.0.0.1:80
oc-sandbox -P 3000               # shorthand for 3000:3000
oc-sandbox -p -P 5433:5432       # password-authenticated Postgres on host loopback
curl http://127.0.0.1:8080       # on the host
```

- Chromium (and everything else in the pod) uses the app's own port (`http://127.0.0.1/` here); the host
  reaches it **only** through the mapped port, and only on `127.0.0.1` (not your LAN).
- Apps may listen on `127.0.0.1` or `0.0.0.0` inside the pod: pods are created with pasta's
  `--host-lo-to-ns-lo`, so mapped connections arrive on the pod's loopback (from `127.0.0.1`).
- Apps may bind ports below 1024 (80, 443) even though the agent has no capabilities: the pod's network
  namespace sets `net.ipv4.ip_unprivileged_port_start=0` (only there; the host keeps its setting). Host
  ports must be unprivileged (normally >= 1024).
- Repeat `-P` or use commas (`-P 8080:80,8443:443`). Mappings are kept on later runs; `-P none` removes them.
- Ports are fixed when a pod is created, so changing them **recreates the pod** (Chromium restarts;
  Postgres data, docker storage and the profile are kept, and Postgres / docker-in-docker come back).
  That is refused while the instance's OpenCode runs: exit it first.
- **Refused:** pod port 9222 (Chromium DevTools gives full browser control). Publishing pod port 5432
  requires `-p`, which enforces Postgres password authentication. A later plain `-i NAME` launch keeps
  an existing mapping after verifying its managed SCRAM server and password file. Mapped connections
  arrive from `127.0.0.1` and are reachable by every local host user.
- If the app builds absolute URLs, cookies, CORS origins or OAuth callbacks from its port, prefer the
  same number on both sides for the instance you browse from the host (`-P 3000:3000`).

## Postgres configuration (required for `-p`)

There are **no defaults** for the database. `oc-sandbox -p` exits with an error until all four settings
exist. Put them in `~/.config/oc-sandbox/postgres.env` outside the sandbox. For instance-specific
settings, put `postgres.NAME.env` in the same directory. Exported environment values take precedence.
Use a throwaway password and review how the [agent can access Postgres](security.md#security-model).

```ini
# ~/.config/oc-sandbox/postgres.env
OC_PG_IMAGE=docker.io/library/postgres:17   # trusted image with the official docker-entrypoint.sh interface
OC_PG_USER=app_owner                        # superuser created on first start
OC_PG_PASSWORD=change-me                    # throwaway password
OC_PG_DB=app_dev                            # initial database
```

A ready-to-copy version is in [`examples/postgres.env.example`](../examples/postgres.env.example).
Lines are `KEY=VALUE` (an `export ` prefix and spaces around `=` are fine). An unquoted value ends at
whitespace followed by `#`, so inline comments work. Quote a value (`"..."` or `'...'`) to take it
literally, for example a password containing ` #`.

**Optional first-start SQL.** Files in `~/.config/oc-sandbox/postgres-init/` (or the directory in
`OC_PG_INIT_DIR`) run once, when the data volume is first created, as the standard
`/docker-entrypoint-initdb.d` mechanism. A relative override is resolved from the calling
directory. Path checks and content hashing run on the Podman host, including when invoked
from Distrobox. Use a dedicated directory outside the sandbox and keep its parent directories under
trusted control so the path cannot be replaced during setup. The init tree must be owned by you
or root, with no group or world write access. Podman applies a private SELinux label to the init
directory on mount. See
[`examples/postgres-init/01-roles.sql.example`](../examples/postgres-init/01-roles.sql.example).

### Data, upgrades and connections

- Each instance has its own data volume (`oc-pg`, `oc-NAME-pg`); data written in one is invisible to
  the others.
- Postgres only reads user, password, database, and init scripts when its data volume is **first
  created**. The script records those settings on the volume and **refuses** to start if they later
  differ. To apply new settings, back up anything you need before deleting the matching data
  volume. Run only the command for the instance you want to reset, on the host.

  **Default instance**

  ```bash
  oc-sandbox -i default -d && podman volume rm oc-pg
  ```

  **Named instance** (substitute the same instance name for both occurrences of `NAME`)

  ```bash
  oc-sandbox -i NAME -d && podman volume rm oc-NAME-pg
  ```

  Launch the reset instance with `-p` again.
- Changing only `OC_PG_IMAGE` keeps the data and recreates the container (a new major version of
  Postgres will still refuse to open an old data directory).
- Data persists across restarts and `oc-sandbox -d`. Use `-d -a` to remove the volume as part of teardown.
- Postgres listens on `127.0.0.1` inside the pod and requires SCRAM-SHA-256 for **all TCP** clients,
  including localhost and any `-p -P 5432` host mapping. Unix-socket connections inside the Postgres
  container use `trust`; that socket is not mounted into the agent. The script supplies a script-owned
  HBA file at server startup for new and existing volumes. Volume-local `pg_hba.conf` and custom HBA
  edits are ignored; keep authentication changes out of that file. A pre-existing volume must have a
  compatible SCRAM verifier for the configured password: if authentication fails, startup stops and
  retains the data. Migrate older MD5 verifiers through a trusted local administrative procedure before
  enabling host access; do not put the password on a command line.
- Inside a newly launched agent, `PGPASSFILE` points to a per-instance mode-0600 secret, so
  `psql -h 127.0.0.1 -U <user> -d <db>` authenticates without a prompt. Restart an already-running agent
  before enabling `-p`, because its mounts and environment cannot be changed. For host tools use
  `oc-sandbox -p -P 5433:5432`, then `postgresql://<user>@127.0.0.1:5433/<db>`; enter the password
  through your client. Printed URLs never include it.
- **How the password is handled:** it is read into an unexported shell variable (values that came from
  the environment are un-exported too), sent over stdin into the Podman secret `oc[-NAME]-pg-password`,
  and mounted into the container as `POSTGRES_PASSWORD_FILE`. It never appears in a command line, in the
  container's environment or `podman inspect`, or in the output. A separate per-instance Podman secret
  contains the escaped, mode-0600 agent passfile. The settings record on the volume is a
  hash keyed with a random file (`~/.local/share/oc-sandbox/pg-sig.key`, mode 0600), so it cannot be
  used to guess the password offline. Volumes made by older versions carry an unkeyed hash; they keep
  working, with a notice to recreate them.
- The Postgres client (`psql`) is included in the agent image.
- The container runs with only the extra capabilities the standard image's entrypoint needs
  (`CHOWN SETUID SETGID FOWNER DAC_OVERRIDE`).

## Docker-in-docker (`-D`)

```bash
oc-sandbox -D                     # then, inside the sandbox:
docker run -d --network host docker.io/traefik/whoami --port 3001
curl 127.0.0.1:3001               # agent, this instance's Chromium, and -P mappings all see it
```

- A sidecar `oc[-NAME]-dind` (image `quay.io/podman/stable`, override with `OC_DIND_IMAGE`) runs rootless
  Podman with its storage in the volume `oc[-NAME]-dind`. The agent talks to its Docker-compatible API
  through a socket in the volume `oc[-NAME]-dind-run` (`DOCKER_HOST`/`CONTAINER_HOST` are set), with the
  `docker` and `docker compose` CLIs in the agent image. Your host's Podman/Docker socket is never mounted.
- `--network host` makes a nested container share the pod's network (`127.0.0.1`, published ports).
  Containers on the default nested network get outbound access; use `--network host` to serve the pod.
- **Bind mounts of the sandbox are read-only in effect:** the sidecar mounts `~/opencode-sandbox`
  read-only at the same path (`/sandbox`), and nested root is not you on the host. Use named volumes or
  `docker cp` for data that containers write. Files must be world-readable to be seen.
- Data in the sidecar (images, containers, volumes) persists in `oc[-NAME]-dind`; `-d -a` deletes it.
- Testcontainers works via `DOCKER_HOST`; if its Ryuk container fails, set `TESTCONTAINERS_RYUK_DISABLED=true`.
- **Weaker isolation than the agent** ([security model](security.md#security-model)), which is why it is opt-in.

## Host bridge

Inside the sandbox, `code FILE...` opens files in your host VS Code and `bcompare A B` opens Beyond
Compare (files or folders). The host tools work on a **copy**:

- When launched from Distrobox, the launcher and the host service must see the same protected
  staging directory. Use a shared host path for the configured data directory.
- Saving in VS Code / Beyond Compare writes the file back into the sandbox within about a second
  when the sandbox and host staging share a mount. If write-back fails, the bridge retains the
  staged save and logs its recovery path.
- Changes the agent makes while the file is open are not shown in the editor. If the agent changed the
  file in the meantime, your save goes to `FILE.host-edit` next to it instead of overwriting the agent's
  version.
- The packaged VS Code launcher waits for you to close the tab (`--wait`). Its copy is removed
  after a confirmed close and successful write-back. Beyond Compare folders are read-only
  snapshots of ordinary files and directories. The bridge retains files when it cannot verify
  that a custom launcher or Beyond Compare has finished.
- Snapshots are limited to 64 MiB per file, 512 MiB and 5000 visited entries per session, and
  64 levels of nesting. The bridge allows up to eight active or uncertain sessions and up to
  sixteen private session directories total, including closed recovery.
- Recovery files have no automatic expiry. Use the private session path in the bridge message
  to copy out the saved files. After confirming any associated editor and bridge session have
  closed, remove that session directory to release capacity. Close or recover sessions before
  upgrading a legacy bridge or performing global teardown.
- Symlinks inside the sandbox are not followed by the host; `code` resolves them inside the sandbox
  first, so links that stay inside the sandbox still work.
- One bridge serves all instances.
- VS Code defaults to `/home/linuxbrew/.linuxbrew/bin/code` and Beyond Compare defaults to
  `/usr/bin/bcompare`. Set `OC_CODE_BIN` or `OC_BCOMPARE_BIN` to an absolute host path. Missing
  tools produce a warning and the corresponding command has no effect.
