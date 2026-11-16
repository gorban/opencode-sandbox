# opencode-sandbox

One command that runs [OpenCode](https://opencode.ai) in a rootless Podman sandbox, together with a
**visible Chromium on your Wayland desktop** that OpenCode can drive, an optional **Postgres**, an
optional **docker-in-docker** sidecar, and a restricted **bridge** for opening files in your host's
VS Code / Beyond Compare. Several **instances** (for example one per git worktree) can run side by side,
each with its own browser, database and ports.

```
oc-sandbox -p                                  # Chromium + Postgres + OpenCode
oc-sandbox -i feat-a -W myrepo -P 3001:3000 -p # a second instance on a worktree of ~/opencode-sandbox/myrepo
```

> Personal tooling, shared as-is. Developed and tested on **Fedora Atomic (Bazzite), KDE Plasma on
> Wayland, Podman 6.x rootless, SELinux enforcing**. Other setups may need changes. Read the
> [security model](#security-model) before relying on it.

## What you get

```
 host                                   one rootless Podman pod per instance ("oc", "oc-NAME")
 ──────────────────────────            ─────────────────────────────────────────────────────────
 ~/opencode-sandbox/  ──mounted──►     oc[-NAME]-agent     OpenCode + zsh/git/vim/docker CLI
   construct/   (default instance)     oc[-NAME]-chromium  Chromium on your Wayland desktop,
   wt/NAME/     (other instances)                          DevTools on 127.0.0.1:9222 (pod only)
   .bridge/     (request spool)        oc[-NAME]-postgres  optional (-p), 127.0.0.1:5432 (pod only)
 Wayland socket  ──────────────►       oc[-NAME]-dind      optional (-D), rootless Podman for `docker`
 FIDO/U2F key (hidraw) ────────►       (to Chromium only)
 127.0.0.1:HOST ──── -P ───────►       127.0.0.1:POD in the pod (published ports, loopback only)
 oc-bridge service ◄── requests ──     `code FILE` / `bcompare A B` shims in the agents
```

- **OpenCode** in an unprivileged container: all capabilities dropped, `no-new-privileges`, pid and
  memory limits, only `~/opencode-sandbox` mounted. It updates itself (the binary lives in a volume).
- **Chromium** is controlled by OpenCode through the Chrome DevTools MCP, configured in the agent image
  (`OPENCODE_CONFIG=/etc/opencode/oc-sandbox.json`, merged with your own OpenCode configs).
- **Postgres** (`-p`) runs in the same pod, so only that instance's agent and Chromium can reach it.
- **Instances** (`-i NAME`): each has its own pod (network namespace), Chromium profile, Postgres data
  and docker storage, so copies of the same app can use the same default ports at the same time.
- **Port mapping** (`-P HOST:POD`): look at an app in the sandbox from your host, on loopback only.
- **docker-in-docker** (`-D`): `docker run`, `docker compose` inside the sandbox, without your host's
  Podman or Docker.
- **Security keys:** FIDO/U2F keys (YubiKey etc.) are passed through to Chromium, and only the FIDO
  interface of each key. Never keyboards or mice.
- **Host bridge:** inside the sandbox, `code FILE` and `bcompare A B` open the files on your host.
  The host tools get a copy in a host-owned staging directory; saving writes your edit back into the
  sandbox (see [host bridge](#host-bridge) and the security model).
- **Shell:** `oc-sandbox [-i NAME] -x` opens zsh (oh-my-zsh, vi mode, your git identity) in the running
  agent, with a red `[sandbox:NAME]` prompt marker and `OC_SANDBOX=1`, `OC_INSTANCE=NAME` set.

## Requirements

- Linux with **rootless Podman** (with pasta networking, the default since Podman 5), a **systemd user
  session**, **SELinux** (a small policy module is installed), and a **Wayland** session (socket at
  `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`).
- `udica` (its templates in `/usr/share/udica/templates`) and `pkexec` or `sudo`, used once to install
  the SELinux module `oc_chromium`.
- `python3` >= 3.11 on the host, for the bridge handler.
- Optional: VS Code at `/home/linuxbrew/.linuxbrew/bin/code` and Beyond Compare at `/usr/bin/bcompare`
  (override with the environment variables `OC_CODE_BIN` and `OC_BCOMPARE_BIN`; the script only warns
  if they are missing).
- For `-D`: `/dev/fuse` and `/dev/net/tun` on the host (standard on Fedora).
- Works from inside a **Distrobox** too: if `$CONTAINER_ID` is set it runs `podman`/`systemctl` on the
  host through `distrobox-host-exec`.

## Install

```bash
git clone git@github.com:gorban/opencode-sandbox.git ~/code/opencode-sandbox
ln -s ~/code/opencode-sandbox/oc-sandbox ~/.local/bin/oc-sandbox
```

**Do not put the checkout inside `~/opencode-sandbox`.** That directory is mounted into the agent
containers, and `oc-sandbox` runs on your host and asks for admin rights. If an agent could edit the
script it could run code on your host. The script refuses to run from inside that directory.

The first run builds two images (a few minutes) and asks for your admin password once, to install the
SELinux module.

## Usage

| Command | What it does |
|---|---|
| `oc-sandbox` | Set up whatever is missing, then start OpenCode (default instance, in `/sandbox/construct`) |
| `oc-sandbox -i NAME` | Same for instance `NAME` (in `/sandbox/wt/NAME`); see [instances](#parallel-instances) |
| `oc-sandbox -p` | Plus Postgres ([configuration required](#postgres-configuration-required-for--p)) |
| `oc-sandbox -D` | Plus a [docker-in-docker](#docker-in-docker--d) sidecar |
| `oc-sandbox -P 8080:80` | Publish pod port 80 as `127.0.0.1:8080` on the host ([ports](#port-mapping--p)) |
| `oc-sandbox -C DIR` | Working directory `~/opencode-sandbox/DIR` (created if missing) |
| `oc-sandbox -W REPO[:BRANCH]` | Make the working directory a git worktree of `~/opencode-sandbox/REPO` |
| `oc-sandbox -n ...` | Setup only, do not start OpenCode |
| `oc-sandbox [-i NAME] -x` | zsh shell inside that instance's **running** OpenCode container |
| `oc-sandbox -l` | List instances: agent state, ports, working directory, sidecars |
| `oc-sandbox -k` | List the FIDO/U2F keys that would be passed to Chromium, then exit |
| `oc-sandbox -K` | Start without passing any security key |
| `oc-sandbox -r` | Rebuild images from fresh bases and recreate the pod |
| `oc-sandbox -i NAME -d [-a] [-y]` | Remove that instance's pod; `-a` also its volumes (Chromium profile, Postgres data, docker storage) |
| `oc-sandbox -d` | Remove **all** instance pods and the host bridge. **Keeps** images, volumes, and `~/opencode-sandbox` |
| `oc-sandbox -d -a [-y]` | Also delete images, all volumes (OpenCode login, profiles, data), build files, and the SELinux module |
| `oc-sandbox -h` | Help |

Flags combine (`oc-sandbox -i b -W myrepo -P 3001:3000 -p -D`). It is idempotent: rerun it any time
and only missing or changed pieces are touched. If that instance's OpenCode is already running, it just
completes the setup (like `-n`) and tells you to use `-x`. Closing a Chromium window stops that
container, and the next run starts it again. Memory limits can be changed with `OC_AGENT_MEMORY`,
`OC_CHROMIUM_MEMORY` and `OC_DIND_MEMORY` (default `4g` each; Postgres has `2g`); they apply per
instance.

## Parallel instances

```bash
oc-sandbox -i a -W myrepo -P 3001:3000 -p   # terminal 1: worktree ~/opencode-sandbox/wt/a, branch a
oc-sandbox -i b -W myrepo -P 3002:3000 -p   # terminal 2: worktree ~/opencode-sandbox/wt/b, branch b
oc-sandbox -l                               # what is running
```

- **Per instance:** pod `oc-NAME` (its own `127.0.0.1`), containers `oc-NAME-{agent,chromium,postgres,dind}`,
  volumes `oc-NAME-chrome`, `oc-NAME-pg`, `oc-NAME-dind`, `oc-NAME-dind-run`, secret
  `oc-NAME-pg-password`. Both instances above run the app on port 3000 and Postgres on 5432 without
  conflict; each Chromium sees only its own pod. A named instance's Chromium opens a first tab titled
  `oc NAME` so you can tell the windows apart.
- **Shared:** images, the `oc-home` volume (OpenCode login, sessions, the self-updated binary), the
  bridge, and the Postgres settings (`~/.config/oc-sandbox/postgres.NAME.env` overrides
  `postgres.env` for one instance). All agents mount all of `~/opencode-sandbox` (worktrees need the
  main repository's `.git`).
- **Working directory:** `construct/` for the default instance, `wt/NAME/` for others, or `-C DIR`.
  `-W REPO[:BRANCH]` turns it into a git worktree of `REPO` on `BRANCH` (default: the instance name,
  created from `REPO`'s current `HEAD` if it does not exist). Worktrees use relative links
  (`git worktree add --relative-paths`; `worktree.useRelativePaths` is also set in the agents), so they
  work both inside the sandbox (`/sandbox/...`) and on the host (`~/opencode-sandbox/...`).
- **Git never runs on the host** inside `~/opencode-sandbox`: the repository is agent-writable, so its
  hooks and config could run code. `-W` runs `git worktree add` in a throwaway container without network,
  with hooks disabled.
- Instance names: `a-z`, `0-9` and inner `-`, at most 24 characters. `default` means the default instance
  (`-i default -d [-a]` removes only the default instance; only a bare `-d` acts on all of them).
- `oc-sandbox -i NAME -d` leaves the worktree alone; remove it with `git worktree remove` in a sandbox shell.

## Port mapping (`-P`)

```bash
oc-sandbox -P 8080:80            # host 127.0.0.1:8080 -> pod 127.0.0.1:80
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
- **Refused:** pod ports 9222 (Chromium DevTools: full control of the browser) and 5432 (Postgres:
  trusts `127.0.0.1`, any role, no password). A mapped connection appears inside the pod as
  `127.0.0.1`, so either would be open to every process on your host.
- If the app builds absolute URLs, cookies, CORS origins or OAuth callbacks from its port, prefer the
  same number on both sides for the instance you browse from the host (`-P 3000:3000`).

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
- **Weaker isolation than the agent** (see the security model), which is why it is opt-in.

## Postgres configuration (required for `-p`)

There are **no defaults** for the database. `oc-sandbox -p` exits with an error until all four settings
exist. Put them in `~/.config/oc-sandbox/postgres.env` (outside the sandbox, so the agent cannot edit
it; `postgres.NAME.env` for instance `NAME` if you want different settings there) or export them as
environment variables (environment wins over the file):

```ini
# ~/.config/oc-sandbox/postgres.env
OC_PG_IMAGE=docker.io/library/postgres:17   # any image that honors POSTGRES_USER/_DB and POSTGRES_PASSWORD_FILE
OC_PG_USER=app_owner                        # superuser created on first start
OC_PG_PASSWORD=change-me                    # throwaway; see "Postgres authentication" in the security model
OC_PG_DB=app_dev                            # initial database
```

A ready-to-copy version is in [`examples/postgres.env.example`](examples/postgres.env.example).
Lines are `KEY=VALUE` (an `export ` prefix and spaces around `=` are fine). An unquoted value ends at
whitespace followed by `#`, so inline comments work. Quote a value (`"..."` or `'...'`) to take it
literally, for example a password containing ` #`.

**Optional first-start SQL.** Files in `~/.config/oc-sandbox/postgres-init/` (or the directory in
`OC_PG_INIT_DIR`) run once, when the data volume is first created, as the standard
`/docker-entrypoint-initdb.d` mechanism. See
[`examples/postgres-init/01-roles.sql.example`](examples/postgres-init/01-roles.sql.example).

**Behavior to know about**

- Each instance has its own data volume (`oc-pg`, `oc-NAME-pg`); data written in one is invisible to
  the others.
- Postgres only reads user, password, database, and init scripts when its data volume is **first
  created**. The script records those settings on the volume and **refuses** to start if they later
  differ, instead of silently ignoring your change. To apply new settings, discard the data:
  `oc-sandbox [-i NAME] -d && podman volume rm oc-pg` (or `oc-NAME-pg`), then run with `-p` again.
- Changing only `OC_PG_IMAGE` keeps the data and recreates the container (a new major version of
  Postgres will still refuse to open an old data directory).
- Data persists across restarts and `oc-sandbox -d`; only `-d -a` deletes it.
- It listens on `127.0.0.1` inside the pod only. Connect from OpenCode or `oc-sandbox -x`:
  `psql -h 127.0.0.1 -U <user> -d <db>`. **No password is needed.** The settings file is read by the
  host script, not by `psql` (nothing from it is passed into the agent), and the standard Postgres images
  use `trust` authentication for `127.0.0.1`, which is exactly how the agent reaches it. The configured
  password only applies to non-local connections, and there are none. An image that enforces passwords
  on localhost will ask for one (set `PGPASSWORD` yourself). The script prints the connection lines
  when it is ready; they never contain the password.
- **How the password is handled:** it is read into an unexported shell variable (values that came from
  the environment are un-exported too), sent over stdin into the Podman secret `oc[-NAME]-pg-password`,
  and mounted into the container as `POSTGRES_PASSWORD_FILE`. It never appears in a command line, in the
  container's environment or `podman inspect`, or in the output. The settings record on the volume is a
  hash keyed with a random file (`~/.local/share/oc-sandbox/pg-sig.key`, mode 0600), so it cannot be
  used to guess the password offline. Volumes made by older versions carry an unkeyed hash; they keep
  working, with a notice to recreate them.
- The Postgres client (`psql`) is included in the agent image.
- The container runs with only the extra capabilities the standard image's entrypoint needs
  (`CHOWN SETUID SETGID FOWNER DAC_OVERRIDE`).

## Host bridge

Inside the sandbox, `code FILE...` opens files in your host VS Code and `bcompare A B` opens Beyond
Compare (files or folders). The host tools work on a **copy**:

- Saving in VS Code / Beyond Compare writes the file back into the sandbox within about a second.
- Changes the agent makes while the file is open are not shown in the editor. If the agent changed the
  file in the meantime, your save goes to `FILE.host-edit` next to it instead of overwriting the agent's
  version.
- `code` waits for you to close the tab (`--wait`); the copy is deleted then. Folders opened in Beyond
  Compare are read-only snapshots (only regular files; symlinks are skipped). Limits: 64 MiB per file,
  5000 files / 512 MiB per folder snapshot.
- Symlinks inside the sandbox are not followed by the host; `code` resolves them inside the sandbox
  first, so links that stay inside the sandbox still work.
- One bridge serves all instances.

## Security model

What is isolated: the agents can only see `~/opencode-sandbox`, run unprivileged with all capabilities
dropped, are confined by SELinux, and the pods' services (DevTools, Postgres, the docker sidecar) are not
exposed to the host or LAN unless you publish a port. What is **not** a hard boundary, so you know what
you are trusting:

- **A container is not a VM.** It shares your kernel. For stronger isolation consider running the
  containers with a libkrun microVM runtime (`--runtime=krun`); this project does not do that.
- **Instances are not isolated from each other's files.** Every agent mounts all of `~/opencode-sandbox`
  and they share one SELinux level (below) and the `oc-home` volume. What instances do not share is the
  network namespace (apps, DevTools, Postgres, the docker sidecar), browser profiles and data volumes.
- **Chromium runs with `--no-sandbox`** and its own sandbox is off, so the container is its only sandbox.
  Podman only allows the user-namespace setup Chromium's sandbox needs at the pod level, which would
  change how the agent container runs. The "unsupported flag" warning bar is hidden with the enterprise
  policy `CommandLineFlagSecurityWarningsEnabled`; that hides the message, it does not turn the sandbox on.
- **OpenCode drives that browser**, so anything you sign into there (cookies, saved passwords, extensions,
  a password manager) is reachable by the agent, and by prompt injection from the pages it visits. There is
  no OS keyring in the container, so saved credentials are weakly protected on disk. Use throwaway accounts.
- **SELinux module `oc_chromium`:** a type that applies *only* to the Chromium containers. It lets them use
  the Wayland socket (KWin is unconfined), shared-memory buffers, and the security-key device and udev data.
  No other container gets these rules. `oc-sandbox -d -a` removes it.
- **One SELinux level for all agents:** a random MCS level is chosen once
  (`~/.local/share/oc-sandbox/sb-level`) and every agent runs with it, so several agents can use
  `~/opencode-sandbox` at once (Podman's `:Z` would give each agent a new level and lock the others out).
  The sandbox and `oc-home` are relabelled to that level by a throwaway container that sees only them
  (Python `os.walk`, never following symlinks), not by Podman on the host. Containers at any other level
  (Chromium, Postgres, other containers on your system) cannot read these files.
- **Network:** outbound is open, including your LAN. Services on the host's `127.0.0.1` are unreachable
  from the sandbox, but services bound to `0.0.0.0` are reachable via `host.containers.internal`.
- **Published ports (`-P`)** bind host `127.0.0.1` only, and arrive in the pod as connections from
  `127.0.0.1`. Anything on your host (any local user or process, and web pages in your host browser via
  DNS rebinding) can reach a published app as if it were local to the pod. DevTools and Postgres ports
  are refused for that reason; do not publish other services that trust localhost.
- **docker-in-docker (`-D`)** is the weakest part, opt-in. Nested rootless Podman needs the default
  capability set, setuid `newuidmap` (so no `no-new-privileges`), `/dev/fuse`, `/dev/net/tun`, and it runs
  **without SELinux confinement** (`label=disable`, as `spc_t`): confining it with a nested label
  (`label=nested`) does not work on this setup yet. It sees only its own volumes and a read-only view of
  `~/opencode-sandbox`, and it is still an unprivileged user namespace, but kernel attack surface is
  larger than for the agent, and the agent (or prompt injection through it) can run arbitrary containers
  there. Your host's Podman or Docker socket is never exposed.
- **Postgres authentication:** inside the pod, connections to `127.0.0.1` need no password (see above), so
  the agent, and Chromium, and any page that can make it run commands, can connect as any role, including
  the superuser. The password protects nothing against them. Treat everything in this database as readable
  and writable by the agent, and never load real data into it.
- **Self-updating OpenCode** downloads from the internet at runtime into the `oc-home` volume, which the
  agents can write to. A compromised session could replace the binary and it would persist (for all
  instances) until you reset the volume (`oc-sandbox -d -a`).
- **Everything in `~/opencode-sandbox` is hostile input for host code**: an agent can replace any file
  or directory there with a symlink at any moment, including between a check and a use. So:
  - `oc-sandbox` never creates, writes, relabels or runs git on anything inside it from the host. Working
    directories, `.bridge/`, worktrees and SELinux labels are handled by throwaway containers that see
    only that directory (no network, no capabilities), so a symlink resolves inside the container and
    cannot point at the host.
  - The bridge handler (`~/.local/bin/oc-bridge`, Python, outside the sandbox) never resolves a sandbox
    path by name. See below.
- **Host bridge:** requests are text files in `~/opencode-sandbox/.bridge/requests/`. The handler accepts
  only `code` (files) and `bcompare` (files or folders), at most 20 requests per run and 8 paths each. It
  never runs a command taken from a request, and never hands a path inside the sandbox to VS Code or
  Beyond Compare. Instead it:
  - opens every path component with `openat(O_NOFOLLOW)` relative to its parent's descriptor, starting at
    `~/opencode-sandbox`, so a symlink anywhere on the path is refused instead of followed, and a directory
    renamed after it was opened stays inside the sandbox;
  - opens files `O_NONBLOCK` and checks the open descriptor with `fstat`, so FIFOs and devices are refused;
  - copies the content into `~/.local/share/oc-sandbox/bridge-stage/` (host-owned, 0700, not mounted) and
    opens that copy;
  - writes saved edits back by creating a new file `O_EXCL|O_NOFOLLOW` in the pinned parent directory and
    renaming it over the target, which replaces a directory entry and never follows one. If the file was
    changed or replaced in the sandbox since it was opened, the edit is saved as `NAME.host-edit` instead;
  - pins `.bridge/requests` the same way before reading or draining it; a symlink there is removed (only
    the link) and nothing else happens.
- **Bridge copies:** `code`/`bcompare` on a path outside `/sandbox` copies it into `.bridge/files/` first
  (the host can only see the sandbox directory). Copies older than 7 days are removed automatically.
- **Secrets:** only these variables are forwarded into the agent if set: `ANTHROPIC_API_KEY`,
  `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`. Use scoped keys with spend
  limits. The script, Postgres config, and credentials live outside the mounted directory.

## What it creates

| Where | What |
|---|---|
| Podman (default instance) | pod `oc`; containers `oc-agent`, `oc-chromium`, `oc-postgres`, `oc-dind`; volumes `oc-chrome`, `oc-pg`, `oc-dind`, `oc-dind-run`; secret `oc-pg-password` |
| Podman (instance `NAME`) | the same with `oc-NAME` in place of `oc` (pod `oc-NAME`, `oc-NAME-agent`, ...) |
| Podman (shared) | images `oc-agent`, `oc-chromium` (and the pulled `quay.io/podman/stable` for `-D`); volume `oc-home` |
| `~/opencode-sandbox/` | your workspace (`construct/`, `wt/NAME/`), plus `.bridge/` (request spool) |
| `~/.local/share/oc-sandbox/` | generated build files, the SELinux policy, `sb-level`, `pg-sig.key`, and `bridge-stage/` (copies open in VS Code / Beyond Compare) |
| `~/.local/bin/oc-bridge` and `~/.config/systemd/user/oc-bridge.{path,service}` | the host-side bridge |
| SELinux | module `oc_chromium` |
| `~/.config/oc-sandbox/` | **yours**: `postgres.env`, `postgres.NAME.env`, `postgres-init/` (never created or deleted by the script) |

## Uninstall

```bash
oc-sandbox -d -a -y            # all pods, bridge, images, volumes, secrets, build files, SELinux module
rm ~/.local/bin/oc-sandbox     # the symlink
rm -rf ~/code/opencode-sandbox # the checkout
```

Your files in `~/opencode-sandbox` (including worktrees) are never touched.

## Tests

- `tests/security.sh` runs adversarial regression tests for the host-side code in a temporary directory:
  symlinked and concurrently swapped directories against the bridge, the sandbox-tree container, worktree
  creation and relabelling; FIFO requests; planted git hooks; `postgres.env` parsing; password exposure in
  output, argv and child environments; and argument validation (ports, instance names, paths). The
  container tests need Podman and the `oc-agent` image; `OC_TEST_NO_PODMAN=1` skips them.
- `tests/parallel.sh` is an acceptance test against the real host (two Chromium windows open for a few
  minutes): two instances with worktrees, agents launched in parallel, the same echo server on the same
  port in both, host access through `-P`, per-instance Postgres, docker-in-docker, `-l`, port changes and
  instance removal. It cleans up after itself (`OC_PTEST_KEEP=1` keeps everything).

## Troubleshooting

- **Chromium exits with "Permission denied" for the Wayland socket:** the SELinux module is missing. Remove
  `~/.local/share/oc-sandbox/policy/installed` and rerun; you will be asked for your admin password.
- **Security key not detected:** `oc-sandbox -k` shows what is seen. The key set is fixed when the container
  is created; plug the key in and rerun `oc-sandbox` (Chromium restarts, its profile is kept).
- **"profile in use" after a crash:** handled automatically; stale lock files are cleared when the
  Chromium container is recreated.
- **`-P`: "address already in use":** another instance (or a host program) uses that host port; `oc-sandbox -l`
  shows the mappings.
- **An agent gets "Permission denied" on a file in `~/opencode-sandbox`:** the file kept a label from
  elsewhere (for example after `mv` on the host); rerun `oc-sandbox` (any instance, `-n` is enough) to
  relabel.
- **Restarting from scratch:** `oc-sandbox -d -a -y && oc-sandbox -p`.

## License

BSD 2-Clause. See [LICENSE](LICENSE).
