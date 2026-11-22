# Operations

[Install and start oc-sandbox](../README.md#install).

## Usage

| Command | What it does |
|---|---|
| `oc-sandbox` | Set up whatever is missing, then start OpenCode (default instance, in `/sandbox/construct`) |
| `oc-sandbox -i NAME` | Same for instance `NAME` (in `/sandbox/wt/NAME`); see [instances](#parallel-instances) |
| `oc-sandbox -p` | Plus Postgres ([configuration required](services.md#postgres-configuration-required-for--p)) |
| `oc-sandbox -D` | Plus a [docker-in-docker](services.md#docker-in-docker--d) sidecar |
| `oc-sandbox -P 8080:80` | Publish pod port 80 as `127.0.0.1:8080` on the host ([ports](services.md#port-mapping--p)) |
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
| `oc-sandbox -d -a [-y]` | Also delete the project's images and volumes, host state, the workspace's bridge spool and the SELinux module. See [Uninstall](#uninstall). |
| `oc-sandbox -h` | Help |

Flags combine (`oc-sandbox -i b -W myrepo -P 3001:3000 -p -D`). It is idempotent: rerun it any time;
shared images are rebuilt only when their inputs change or `-r` is given, and OpenCode is checked for
updates on each setup unless `OC_OPENCODE_VERSION=keep`. If that instance's OpenCode is already running, it just
completes the setup (like `-n`) and tells you to use `-x`. Closing a Chromium window stops that
container, and the next run starts it again. Memory limits can be changed with `OC_AGENT_MEMORY`,
`OC_CHROMIUM_MEMORY` and `OC_DIND_MEMORY` (default `4g` each; Postgres has `2g`); they apply per
instance.

The agent image includes zsh, Git, Vim and the Docker CLI. The agent shell uses oh-my-zsh,
vi mode and your Git identity. A red `[sandbox:NAME]` prompt, `OC_SANDBOX=1` and
`OC_INSTANCE=NAME` identify the session. The agent runs unprivileged with all capabilities
dropped, `no-new-privileges`, and PID and memory limits.

## Startup, updates and rebuilds

The first setup builds the agent and Chromium images and installs the SELinux module.

Concurrent starts serialize shared setup, then create their individual pods and sidecars in parallel.
A waiting start reports the setup holder when it can identify it. Global teardown waits for active
starts to finish creating resources; neither lock is held during an interactive OpenCode session.
The small `setup.lock` and `lifecycle.lock` files under `~/.local/share/oc-sandbox` are retained even
after `-d -a` so that concurrent commands cannot accidentally lock different inodes.

Each setup checks for an OpenCode update, including `-n`. The networked updater has its own SELinux
label and has neither the shared home nor sandbox mounted. It stages a fresh release and receives
only a digest of the current binary for change detection and promotion. Set
`OC_OPENCODE_VERSION=keep` to skip the update or specify a version such as `2.3.0` to stage it with
the official versioned installer. On failure or timeout, setup keeps the working copy or uses the
image's baked-in copy if needed.
Choosing Restart after an in-app update currently ends the session. Launch `oc-sandbox` again.
An update in another instance and quitting OpenCode can produce the same signal as Restart.

## Parallel instances

For these examples, start with a repository at `~/opencode-sandbox/myrepo` and
[configure Postgres](services.md#postgres-configuration-required-for--p).

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
  When a named instance is started from inside a sandbox repository, it defaults to a worktree at
  `wt/<repository path>/NAME` on branch `NAME`; `-W` or `-C` overrides this choice. Relaunching the
  instance reuses its recorded worktree. `-W REPO[:BRANCH]` turns the working directory into a git
  worktree of `REPO` on `BRANCH` (default: the instance name,
  created from `REPO`'s current `HEAD` if it does not exist). Worktrees use relative links
  (`git worktree add --relative-paths`; `worktree.useRelativePaths` is also set in the agents), so they
  work both inside the sandbox (`/sandbox/...`) and on the host (`~/opencode-sandbox/...`).
- **Git never runs on the host** inside `~/opencode-sandbox`: the repository is agent-writable, so its
  hooks and config could run code. `-W` runs `git worktree add` in a throwaway container without network,
  with hooks and fsmonitor disabled. Repository detection also runs in the isolated container;
  symlinked paths and repositories under `wt/` are refused. Existing worktrees must match the
  requested repository and branch. `-l` shows recorded worktree details.
- Instance names use `a-z`, `0-9` and inner `-`, up to 24 characters. The launcher reserves
  `agent`, `chromium`, `chrome`, `postgres`, `pg`, `dind` and `home`.
  `-i default -d [-a]` removes only the default instance. Bare `-d` acts on all of them.
- `oc-sandbox -i NAME -d` leaves the worktree alone; remove it with `git worktree remove` in a sandbox shell.

## What it creates

| Where | What |
|---|---|
| Podman (default instance) | pod `oc`; containers `oc-agent`, `oc-chromium`, `oc-postgres`, `oc-dind`; volumes `oc-chrome`, `oc-pg`, `oc-dind`, `oc-dind-run`; secrets `oc-pg-password`, `oc-pg-passfile`, `oc-pg-hba` |
| Podman (instance `NAME`) | the same with `oc-NAME` in place of `oc` (pod `oc-NAME`, `oc-NAME-agent`, ...) |
| Podman (shared) | images `oc-agent`, `oc-chromium` (and the pulled `quay.io/podman/stable` for `-D`); volume `oc-home`. A rebuild removes the previous build once no container uses it and it has no other tag; only images recorded in `built-images` are ever removed, never another image that happens to have these names |
| `~/opencode-sandbox/` | your workspace (`construct/`, `wt/NAME/`), plus `.bridge/` (request spool) |
| `~/.local/share/oc-sandbox/` | generated build files, the SELinux policy, `sb-level`, `pg-sig.key`, `built-images` (IDs of the images it built), and `bridge-stage/` (copies open in VS Code / Beyond Compare). This, the config directory, `~/.local/bin` and the systemd units must lie outside `~/opencode-sandbox`, and no step of their paths (including symlinks on the way) may pass through it; the script refuses to run otherwise (e.g. with `XDG_DATA_HOME` pointing into it, or at a symlink inside it) |
| `~/.local/bin/oc-bridge` and `~/.config/systemd/user/oc-bridge.{path,service}` | the host-side bridge |
| SELinux | module `oc_chromium` |
| `~/.config/oc-sandbox/` | **yours**: `postgres.env`, `postgres.NAME.env`, `postgres-init/` (never created or deleted by the script) |

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
- **Restarting from scratch:** `oc-sandbox -d -a -y && oc-sandbox -p` deletes all project
  volumes and starts the default instance with [configured Postgres](services.md#postgres-configuration-required-for--p).

## Uninstall

Global `-d -a` deletes OpenCode login and sessions, Chromium profiles, Postgres data and
Docker-in-Docker storage. It removes `~/opencode-sandbox/.bridge/` with its queued requests and
copies. Successful teardown clears host state, including staged editor copies in
`bridge-stage/`, and retains the setup and lifecycle lock files. A SELinux removal failure
keeps host state for retry. Save any needed edits before running teardown. Remove the checkout
or extracted ZIP directory once teardown succeeds. The example uses the
[default install path](../README.md#install).

```bash
oc-sandbox -d -a -y &&
  rm "$HOME/.local/bin/oc-sandbox" &&
  rm -rf -- "$HOME/code/opencode-sandbox"
```

Project files and worktrees in `~/opencode-sandbox` are kept, along with your Postgres configuration.
