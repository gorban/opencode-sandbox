# opencode-sandbox

`oc-sandbox` runs [OpenCode](https://opencode.ai) in a rootless Podman pod with a visible Chromium
window on your Wayland desktop. Run a pod per project or worktree, with its own browser profile,
ports and optional Postgres and Docker-in-Docker storage.

Personal tooling, shared as-is. Developed and tested on Fedora Atomic (Bazzite) with KDE Plasma on
Wayland, rootless Podman 6.x and SELinux enforcing. Other setups may need changes.

## What you get

The host runs the launcher, Podman and the editor bridge. Each pod runs the OpenCode agent and its
Chromium. OpenCode can drive Chromium through Chrome DevTools MCP on the pod's loopback.
The default agent starts in `/sandbox/construct`. Named instances use `/sandbox/wt/NAME` by default.
All agents share the writable `~/opencode-sandbox` workspace at `/sandbox` and the `oc-home` volume.

Keep the launcher and host configuration outside that workspace. The containers share the host kernel,
and the agent can access accounts you sign into in Chromium. Read the [security model](#security-model)
before relying on the isolation.

## Requirements

- Linux with rootless Podman and pasta networking (the default since Podman 5), a systemd user
  session and SELinux. Desktop Chromium also needs a Wayland socket at
  `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`. See [headless Chromium](docs/operations.md#parallel-instances).
- Host `udica` with templates under `/usr/share/udica/templates`, and `pkexec` or `sudo` to install
  the Chromium SELinux module on first setup.
- Python 3.11 or later on the host for the bridge. Optional editors and their paths are listed in the
  [bridge guide](docs/services.md#host-bridge). Docker-in-Docker also needs `/dev/fuse` and
  `/dev/net/tun` on the host.
- From a Distrobox session with `CONTAINER_ID` set, the launcher uses `distrobox-host-exec` for
  Podman and systemd. Run `curl` against published ports from the host.

## Install

Use a trusted source directory such as `~/code/opencode-sandbox`. **Keep the whole checkout or ZIP
extraction, its path and the installed symlink outside `~/opencode-sandbox`.** The agents can change
files in that workspace. The launcher runs on the host and can ask for administrator privileges.

Clone into a new directory. An HTTPS clone does not require a GitHub SSH key.

```bash
mkdir -p "$HOME/code"
git clone https://github.com/gorban/opencode-sandbox.git "$HOME/code/opencode-sandbox"
```

For a ZIP installation, use GitHub's **Code → Download ZIP** on the
[repository](https://github.com/gorban/opencode-sandbox). Extract the full archive and move the
extracted directory to `~/code/opencode-sandbox` if that path is free. Git is optional for this
installation. If the extraction dropped the executable bit, run
`chmod +x "$HOME/code/opencode-sandbox/oc-sandbox"`. Keep the adjacent helper files with the launcher.

Set up the command for either installation. The link command fails if the destination already exists.

```bash
mkdir -p "$HOME/.local/bin"
ln -sT "$HOME/code/opencode-sandbox/oc-sandbox" "$HOME/.local/bin/oc-sandbox"
export PATH="$HOME/.local/bin:$PATH"
```

Keep `~/.local/bin` on your shell's `PATH` for future terminals. Run these commands from your
Wayland session.

```bash
oc-sandbox -n       # Optional first run that prepares the pod and opens Chromium
oc-sandbox          # Set up anything missing and start OpenCode
```

You can start with `oc-sandbox` directly. The first run builds the two images and prompts once for
administrator privileges to install SELinux policy. Allow a few minutes and internet access for the
initial build and downloads.

## Usage

| Task | Command |
|---|---|
| List instances and port mappings | `oc-sandbox -l` |
| Open a shell in a running agent | `oc-sandbox -x` or `oc-sandbox -i NAME -x` |
| See available options | `oc-sandbox -h` |

See the [full command reference](docs/operations.md#usage), including working directories, rebuilds,
security-key options and teardown.

## Guides

### Experimental Gemini text shell

[Use a named Google subscription in the restricted OpenCode shell.](docs/subscriptions.md#gemini-text-shell)

### Parallel instances

[Start parallel instances and create Git worktrees.](docs/operations.md#parallel-instances)

### Port mapping (`-P`)

[Reach a pod service from your host.](docs/services.md#port-mapping--p)

### Docker-in-docker (`-D`)

[Run nested containers and Docker Compose.](docs/services.md#docker-in-docker--d)

### Postgres configuration (required for `-p`)

Set all four Postgres values before running `oc-sandbox -p`.
[Configure credentials and first-start SQL, and connect to the database.](docs/services.md#postgres-configuration-required-for--p)

### Host bridge

[Open sandbox files in host VS Code or Beyond Compare.](docs/services.md#host-bridge)

### Security model

[Understand workspace, browser, network and credential access.](docs/security.md#security-model)

### What it creates

[Find pods, volumes, host state and configuration.](docs/operations.md#what-it-creates)

### Uninstall

[Uninstall and see which data is removed.](docs/operations.md#uninstall)

### Tests

[Run contributor checks and host acceptance.](docs/development.md#tests)
See the [repository layout](docs/architecture.md) and [review gates](AGENTS.md).

### Troubleshooting

[Recover from Wayland, security key, port and file permission errors.](docs/operations.md#troubleshooting)

## License

BSD 2-Clause. See [LICENSE](LICENSE).
