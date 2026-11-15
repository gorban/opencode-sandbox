# opencode-sandbox

One command that runs [OpenCode](https://opencode.ai) in a rootless Podman sandbox, together with a
**visible Chromium on your Wayland desktop** that OpenCode can drive, an optional **Postgres**, and a
restricted **bridge** for opening files in your host's VS Code / Beyond Compare.

```
oc-sandbox -p        # Chromium + Postgres + OpenCode, from scratch or already running
```

> Personal tooling, shared as-is. Developed and tested on **Fedora Atomic (Bazzite), KDE Plasma on
> Wayland, Podman 6.x rootless, SELinux enforcing**. Other setups may need changes. Read the
> [security model](#security-model) before relying on it.

## What you get

```
 host                                    rootless Podman pod "oc"  (shared network namespace)
 ──────────────────────────             ───────────────────────────────────────────────────────
 ~/opencode-sandbox/  ──mounted──►      oc-agent      OpenCode + zsh/git/vim, cwd /sandbox/construct
   construct/  (your work)              oc-chromium   Chromium on your Wayland desktop,
   .bridge/    (request spool)                        DevTools on 127.0.0.1:9222 (pod only)
 Wayland socket  ───────────────►       oc-postgres   optional (-p), 127.0.0.1:5432 (pod only)
 FIDO/U2F key (hidraw) ─────────►       (to Chromium only)
 oc-bridge service ◄── requests ──      `code FILE` / `bcompare A B` shims in the agent
```

- **OpenCode** in an unprivileged container: all capabilities dropped, `no-new-privileges`, pid and
  memory limits, only `~/opencode-sandbox` mounted. It updates itself (the binary lives in a volume).
- **Chromium** is controlled by OpenCode through the Chrome DevTools MCP, which is pre-configured in
  `~/opencode-sandbox/construct/opencode.json` on first run.
- **Postgres** (`-p`) runs in the same pod, so only the agent and Chromium can reach it.
- **Security keys:** FIDO/U2F keys (YubiKey etc.) are passed through to Chromium, and only the FIDO
  interface of each key. Never keyboards or mice.
- **Host bridge:** inside the sandbox, `code FILE` and `bcompare A B` open the files on your host.
  A host-side service validates every request (see the security model).
- **Shell:** `oc-sandbox -x` opens zsh (oh-my-zsh, vi mode, your git identity) in the running agent,
  with a red `[sandbox]` prompt marker and `OC_SANDBOX=1` set.

## Requirements

- Linux with **rootless Podman**, a **systemd user session**, **SELinux** (a small policy module is
  installed), and a **Wayland** session (socket at `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`).
- `udica` (its templates in `/usr/share/udica/templates`) and `pkexec` or `sudo`, used once to install
  the SELinux module `oc_chromium`.
- Optional: VS Code at `/home/linuxbrew/.linuxbrew/bin/code` and Beyond Compare at `/usr/bin/bcompare`
  (override with the environment variables `OC_CODE_BIN` and `OC_BCOMPARE_BIN`; the script only warns
  if they are missing).
- Works from inside a **Distrobox** too: if `$CONTAINER_ID` is set it runs `podman`/`systemctl` on the
  host through `distrobox-host-exec`.

## Install

```bash
git clone git@github.com:gorban/opencode-sandbox.git ~/code/opencode-sandbox
ln -s ~/code/opencode-sandbox/oc-sandbox ~/.local/bin/oc-sandbox
```

**Do not put the checkout inside `~/opencode-sandbox`.** That directory is mounted into the agent
container, and `oc-sandbox` runs on your host and asks for admin rights. If the agent could edit the
script it could run code on your host. The script refuses to run from inside that directory.

The first run builds two images (a few minutes) and asks for your admin password once, to install the
SELinux module.

## Usage

| Command | What it does |
|---|---|
| `oc-sandbox` | Set up whatever is missing, then start OpenCode in `/sandbox/construct` |
| `oc-sandbox -p` | Same, plus Postgres ([configuration required](#postgres-configuration-required-for--p)) |
| `oc-sandbox -n [-p]` | Setup only, do not start OpenCode |
| `oc-sandbox -x` | zsh shell inside the **running** OpenCode container (from another terminal) |
| `oc-sandbox -k` | List the FIDO/U2F keys that would be passed to Chromium, then exit |
| `oc-sandbox -K` | Start without passing any security key |
| `oc-sandbox -r` | Rebuild images from fresh bases and recreate the pod |
| `oc-sandbox -d` | Remove the pod (Chromium, Postgres, agent) and the host bridge. **Keeps** images, volumes, and `~/opencode-sandbox` |
| `oc-sandbox -d -a [-y]` | Also delete images, volumes (OpenCode login, Chromium profile, Postgres data), build files, and the SELinux module |
| `oc-sandbox -h` | Help |

It is idempotent: rerun it any time and only missing or changed pieces are touched. If OpenCode is
already running, it just completes the setup (like `-n`) and tells you to use `-x`. Closing the Chromium
window stops that container, and the next run starts it again.

## Postgres configuration (required for `-p`)

There are **no defaults** for the database. `oc-sandbox -p` exits with an error until all four settings
exist. Put them in `~/.config/oc-sandbox/postgres.env` (outside the sandbox, so the agent cannot edit
it) or export them as environment variables (environment wins over the file):

```ini
# ~/.config/oc-sandbox/postgres.env
OC_PG_IMAGE=docker.io/library/postgres:17   # any Postgres image that honors the standard POSTGRES_* variables
OC_PG_USER=app_owner                        # superuser created on first start
OC_PG_PASSWORD=change-me                    # throwaway; the agent can read everything in this database
OC_PG_DB=app_dev                            # initial database
```

A ready-to-copy version is in [`examples/postgres.env.example`](examples/postgres.env.example).

**Optional first-start SQL.** Files in `~/.config/oc-sandbox/postgres-init/` (or the directory in
`OC_PG_INIT_DIR`) run once, when the data volume is first created, as the standard
`/docker-entrypoint-initdb.d` mechanism. See
[`examples/postgres-init/01-roles.sql.example`](examples/postgres-init/01-roles.sql.example).

**Behavior to know about**

- Postgres only reads user, password, database, and init scripts when its data volume is **first
  created**. The script records those settings on the volume (`oc-pg`) and **refuses** to start if they
  later differ, instead of silently ignoring your change. To apply new settings, discard the data:
  `oc-sandbox -d && podman volume rm oc-pg`, then run with `-p` again.
- Changing only `OC_PG_IMAGE` keeps the data and recreates the container (a new major version of
  Postgres will still refuse to open an old data directory).
- Data persists across restarts and `oc-sandbox -d`; only `oc-sandbox -d -a` deletes it.
- It listens on `127.0.0.1` inside the pod only. Connect from OpenCode or `oc-sandbox -x`:
  `PGPASSWORD=… psql -h 127.0.0.1 -U <user> -d <db>`. The script prints the exact lines when it is ready.
- The Postgres client (`psql`) is included in the agent image.
- The container runs with only the extra capabilities the standard image's entrypoint needs
  (`CHOWN SETUID SETGID FOWNER DAC_OVERRIDE`).

## Security model

What is isolated: the agent can only see `~/opencode-sandbox`, runs unprivileged with all capabilities
dropped, is confined by SELinux, and the pod's services (DevTools, Postgres) are not exposed to the
host or LAN. What is **not** a hard boundary, so you know what you are trusting:

- **A container is not a VM.** It shares your kernel. For stronger isolation consider running the
  containers with a libkrun microVM runtime (`--runtime=krun`); this project does not do that.
- **Chromium runs with `--no-sandbox`** and its own sandbox is off, so the container is its only sandbox.
  Podman only allows the user-namespace setup Chromium's sandbox needs at the pod level, which would
  change how the agent container runs. The "unsupported flag" warning bar is hidden with the enterprise
  policy `CommandLineFlagSecurityWarningsEnabled`; that hides the message, it does not turn the sandbox on.
- **OpenCode drives that browser**, so anything you sign into there (cookies, saved passwords, extensions,
  a password manager) is reachable by the agent, and by prompt injection from the pages it visits. There is
  no OS keyring in the container, so saved credentials are weakly protected on disk. Use throwaway accounts.
- **SELinux module `oc_chromium`:** a type that applies *only* to the Chromium container. It lets it use
  the Wayland socket (KWin is unconfined), shared-memory buffers, and the security-key device and udev data.
  No other container gets these rules. `oc-sandbox -d -a` removes it.
- **Network:** outbound is open, including your LAN. Services on the host's `127.0.0.1` are unreachable
  from the sandbox, but services bound to `0.0.0.0` are reachable via `host.containers.internal`.
- **Self-updating OpenCode** downloads from the internet at runtime into the `oc-home` volume, which the
  agent can write to. A compromised session could replace the binary and it would persist until you reset
  the volume (`oc-sandbox -d -a`).
- **Host bridge:** requests are text files in `~/opencode-sandbox/.bridge/requests/`. The host handler
  (`~/.local/bin/oc-bridge`, outside the sandbox) accepts only the tools `code` and `bcompare`, maps paths
  under `/sandbox` to `~/opencode-sandbox`, resolves symlinks and rejects anything outside, opens only
  **files** (never folders) in VS Code, and caps the work per run. It never runs a shell command taken from
  a request.
- **Secrets:** only these variables are forwarded into the agent if set: `ANTHROPIC_API_KEY`,
  `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`. Use scoped keys with spend
  limits. The script, Postgres config, and credentials live outside the mounted directory.

## What it creates

| Where | What |
|---|---|
| Podman | pod `oc`; containers `oc-chromium`, `oc-postgres`, `oc-agent`; images `oc-agent`, `oc-chromium`; volumes `oc-home`, `oc-chrome`, `oc-pg` |
| `~/opencode-sandbox/` | your workspace (`construct/`), plus `.bridge/` (request spool) |
| `~/.local/share/oc-sandbox/` | generated build files and the SELinux policy |
| `~/.local/bin/oc-bridge` and `~/.config/systemd/user/oc-bridge.{path,service}` | the host-side bridge |
| SELinux | module `oc_chromium` |
| `~/.config/oc-sandbox/` | **yours**: `postgres.env`, `postgres-init/` (never created or deleted by the script) |

## Uninstall

```bash
oc-sandbox -d -a -y            # pod, bridge, images, volumes, build files, SELinux module
rm ~/.local/bin/oc-sandbox     # the symlink
rm -rf ~/code/opencode-sandbox # the checkout
```

Your files in `~/opencode-sandbox/construct` are never touched.

## Troubleshooting

- **Chromium exits with "Permission denied" for the Wayland socket:** the SELinux module is missing. Remove
  `~/.local/share/oc-sandbox/policy/installed` and rerun; you will be asked for your admin password.
- **Security key not detected:** `oc-sandbox -k` shows what is seen. The key set is fixed when the container
  is created; plug the key in and rerun `oc-sandbox` (Chromium restarts, its profile is kept).
- **"profile in use" after a crash:** handled automatically; stale lock files are cleared when the
  Chromium container is recreated.
- **Restarting from scratch:** `oc-sandbox -d -a -y && oc-sandbox -p`.
