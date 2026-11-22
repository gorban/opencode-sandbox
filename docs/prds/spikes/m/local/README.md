# Local OpenCode 2.3.0 proof

Run this disposable probe from a trusted checkout inside the existing `devbox`
distrobox. It needs Python 3.10 or later in `devbox`, rootless Podman with cgroup
v2, SELinux enforcing and FIPS disabled on the host, and locally cached OpenCode
2.3.0 and Python 3.12 Alpine images. Use the existing `/usr/bin/host-spawn` and
session bus in `devbox`, with
`/usr/bin/getfattr` available on the host. The driver and its in-process model
broker run in `devbox`. The driver verifies its private scratch directory under
`/tmp` is shared with the host, then uses bounded host calls without a PTY to
start two containers in an isolated network namespace. The host commands use
an explicit environment. The probe generates synthetic credentials and passes
the worker environment through a private temporary file outside its mounts.
Podman inspection can still show the container's synthetic environment.

On this Fedora policy, launching Python directly in the workstation's
`unconfined_t` context caused SELinux to deny the relay's Unix-socket connection
to the broker with `EACCES`. The direct workstation launch remains unqualified.

## Run

Enter `devbox` and change to the trusted checkout. Use the full image IDs
from the host's local store. The harness sets `--pull=never` for container
creation.

```sh
opencode_image=$(/usr/bin/host-spawn --no-pty /usr/bin/podman --remote=false \
  image inspect --format '{{.Id}}' ghcr.io/anomalyco/opencode:2.3.0)
relay_image=$(/usr/bin/host-spawn --no-pty /usr/bin/podman --remote=false \
  image inspect --format '{{.Id}}' docker.io/library/python:3.12-alpine)
OC_POC_PODMAN_HOST=distrobox PYTHONDONTWRITEBYTECODE=1 python3 docs/prds/spikes/m/local/probe.py \
  --opencode-image "$opencode_image" --relay-image "$relay_image"
```

Add `--attended` from a terminal to pause after the streamed turn and file proof.
Press Enter within 30 seconds to start the held turn and revocation. Each socket
exchange, provider hold, and Podman operation has a time limit. Ctrl+C triggers
cleanup. A failed or interrupted run reports the private receipt directory
under `/tmp/ocm-*`. The receipt records owned container names, immutable IDs,
the run label, and any container role with a pending create acknowledgment.
Cleanup checks the complete label inventory and the exact recorded IDs before
reporting success. A pending create leaves cleanup unconfirmed and retains the
receipt, even if the final inventory is empty.

## Expected evidence

1. The probe checks that `/workspace/proof.txt` is absent inside the worker.
   It creates the session and receives the event stream's connection
   acknowledgment before submitting its host-pinned message.
2. Matching fixture text appears in one native assistant text part before
   the terminal event. The scripted model asks OpenCode to invoke its native
   write tool. The host independently checks that the scratch file contains exactly
   `local OpenCode proof` followed by a newline.
3. The host sees a second response held open and pauses a separate prompt
   before the relay dials the worker. It confirms that the control
   event stream is still open, revokes the grant, and verifies peer EOF on
   that stream and shutdown of the held broker socket. Releasing the paused
   attempt yields `zero_bytes_sent`.
4. A fresh request with the stale synthetic bearer returns HTTP 403 while
   both containers are running. The broker confirms zero new admissions and
   zero active streams.
5. The probe verifies removal of its two containers and removes the run
   directory.

The native request paths, response shapes, and event order are checked against
the pinned image. [OpenCode HTTP API reference](https://opencode.ai/docs/api)

The handoff receipt uses the coordination contract's outcome names. The
standalone host driver waits for the relay receipt outside a coordination hub.
Durable outbox restart and production integration remain in their respective
workstreams. See the [walkthrough](WALKTHROUGH.md).
