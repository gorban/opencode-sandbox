# Repository layout

## Find the implementation

| Path | Responsibility |
|---|---|
| [`oc-sandbox`](../oc-sandbox) | Public Bash launcher. Resolves the physical source path, guards host state, builds images, installs the host bridge and SELinux policy, and manages rootless pods and sidecars. It also generates the Containerfiles, agent shell and bridge shims, and service units. |
| [`oc-bridge.py`](../oc-bridge.py) | Host integration. The launcher installs it as `~/.local/bin/oc-bridge` for the systemd user service. It handles sandbox requests, stages editor copies and writes edits back. |
| [`oc-setup-lock.py`](../oc-setup-lock.py), [`oc-opencode-supervisor.py`](../oc-opencode-supervisor.py) | Host helpers for setup and lifecycle locks and for supervising the isolated OpenCode update phases. |
| [`oc-opencode-update.py`](../oc-opencode-update.py), [`oc-opencode-run.py`](../oc-opencode-run.py) | Container helpers copied into the agent image. They stage and promote updates and run OpenCode with signal forwarding and child reaping. |
| [`oc_bridge_merge.py`](../oc_bridge_merge.py), [`oc_controller.py`](../oc_controller.py) | Offline bridge merge and controller approval policy. Inputs and effects are modeled with synthetic fixtures. |
| [`tools/ci/`](../tools/ci/), [`.github/workflows/`](../.github/workflows/) | Contributor check runner and the hosted pull-request workflow. |
| [`tests/`](../tests/) | Offline policy tests, source-extraction and stubbed launcher tests, and isolated real-host acceptance. See [Development](development.md#tests) for the commands and fixtures. |
| [`examples/`](../examples/) | Operator-supplied Postgres configuration and initialization examples. |
| [`docs/`](.) | Operator and contributor guides. [`docs/prds/`](prds/README.md) records design, decisions and review evidence. [`docs/prds/spikes/`](prds/spikes/) holds retained probes. |

## Compatibility during later moves

The launcher stays at the repository root and is invoked through
`~/.local/bin/oc-sandbox` or directly. It resolves the symlink before looking for adjacent Python
helpers and reading its own source. Tests also copy the launcher and extract shell blocks using its
existing source markers. The [isolated parallel runner](../tests/parallel-isolated.py) copies
the root `oc-*` runtime files, `README.md` and a fixture copy of `tests/parallel.sh`. Its private
checkout has no `docs/` tree. The runner audits the fixed SELinux policy source marker and
parallel test port anchors before it builds the fixture. Keep those paths and anchors compatible
with any move.

The [layout plan](prds/prd_k.md#later-runtime-layout) proposes moving deployed helpers into
`runtime/host/` and `runtime/container/`, and the reusable offline policy into `src/oc_sandbox/`.
Before each move, pin down which callers, install paths, image inputs and test commands rely on
the current paths. Land each move with those compatibility checks and relevant rootless acceptance.
Group tests by fixture type when that makes test commands easier to find.
