# Security

## Security model

The agent mounts the writable `~/opencode-sandbox` workspace and runs unprivileged with all
capabilities dropped under SELinux. DevTools, Postgres and the Docker sidecar are pod-local by
default. The containers share your host kernel. A microVM runtime such as libkrun
(`--runtime=krun`) can provide stronger isolation and would require a separate setup.

- **Shared files:** every agent mounts all of `~/opencode-sandbox` and shares one SELinux
  level and the `oc-home` volume. Each pod has its own network namespace and volumes for
  Chromium, Postgres and the Docker sidecar.
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
  DNS rebinding) can reach a published app as if it were local to the pod. DevTools is refused; Postgres
  publication requires `-p` and SCRAM authentication. Do not publish services that trust localhost.
- **docker-in-docker (`-D`)** is the weakest part, opt-in. Nested rootless Podman needs the default
  capability set, setuid `newuidmap` (so no `no-new-privileges`), `/dev/fuse`, `/dev/net/tun`, and it runs
  **without SELinux confinement** (`label=disable`, as `spc_t`): confining it with a nested label
  (`label=nested`) does not work on this setup yet. It sees only its own volumes and a read-only view of
  `~/opencode-sandbox`, and it is still an unprivileged user namespace, but kernel attack surface is
  larger than for the agent, and the agent (or prompt injection through it) can run arbitrary containers
  there. Your host's Podman or Docker socket is never exposed.
- **Postgres authentication:** all TCP connections require SCRAM, including host mappings and pod
  loopback. The agent receives the configured database credentials through its private passfile, so
  treat the database as readable and writable by the agent and never load real data into it. SCRAM
  authenticates clients but does not encrypt the database connection.
- **OpenCode updates:** setup downloads a fresh release in a networked updater with no sandbox or
  shared home mounts. An offline worker supplies only the current binary's digest and a separate
  offline worker promotes the new release. Agents can still replace the binary in the shared
  `oc-home` volume used by agent sessions. See [OpenCode updates](operations.md#startup-updates-and-rebuilds).
- **Everything in `~/opencode-sandbox` is hostile input for host code**: an agent can replace any file
  or directory there with a symlink at any moment, including between a check and a use.
  - The launcher prepares working directories and the `.bridge/` spool, manages Git worktrees and
    relabels files in throwaway containers. They see only the workspace or agent volume required
    for that operation and run without network, with capabilities dropped except `FOWNER` for
    relabelling. Symlinks resolve inside the container.
  - Git hooks and fsmonitor are disabled for worktree operations. Checkout filters can still
    run in the offline worktree container, which uses the agents' SELinux label and a time limit.
  - Global `-d -a` verifies pod removal and stops the bridge path and service. It stops before
    purging volumes if editor staging directories remain. Successful cleanup removes the `.bridge/`
    spool without following its symlinks. Project files and worktrees are kept. See
    [Uninstall](operations.md#uninstall).
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
  - prepares saved edits in private host staging and applies the sandbox's SELinux label before
    publication. It checks the target before renaming and verifies the published inode. A detected
    conflict gets a new sibling copy, usually `NAME.host-edit`. If the destination exists, its
    identity changes during publication, or publication crosses a mount boundary, the staged save
    remains available for recovery. A concurrent edit can still race the final check and rename;
  - pins `.bridge/requests` the same way before draining it in paced batches. A symlink there is
    unlinked. Invalid nonempty directories are moved out of the queue without traversing their
    contents. The move leaves them under `.bridge/` until sandbox bridge cleanup.
- **Bridge copies:** `code`/`bcompare` on a path outside `/sandbox` copies it into `.bridge/files/` first
  (the host can only see the sandbox directory). Copies older than 7 days are removed automatically.
- **Secrets:** these API key variables are forwarded into the agent if set: `ANTHROPIC_API_KEY`,
  `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`. Use scoped keys with spend
  limits. The script and Postgres config remain outside the mounted directory; `-p` gives the agent its
  per-instance Postgres passfile through a separate Podman secret.
