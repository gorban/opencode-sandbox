# Local profile proof

This disposable probe compiles the checked-in PRD L profile, then runs the existing
OpenCode 2.3.0 job and synthetic model with the selected Postgres and Chromium
sidecars. The containers share the worker's private, loopback-only network
namespace. Podman creates separate containers and publishes no host ports.
Chromium's raw DevTools endpoint is intentionally available in this interactive
fixture. See the [walkthrough](WALKTHROUGH.md) for its boundaries.

## Preview the selection

From a trusted checkout:

```sh
python3 -B docs/prds/spikes/l_m_profile/probe_profile.py --plan-only
python3 -B docs/prds/spikes/l_m_profile/probe_profile.py --plan-only --without-chromium
```

The second command compiles the same profile with the Chromium bundle omitted.
Both commands print the compiler's plan digest and selected service IDs without
starting Podman.

## Run the two variants

Use the [local OpenCode devbox prerequisites](../m/local/README.md) and the
cached images pinned in [profile_plan.py](profile_plan.py). The probe binds each
full local image ID to its checked-in repository digest and never pulls.
The Chromium pin refers to the cached local `oc-chromium` build used for this proof.

```sh
image_id() {
  /usr/bin/host-spawn --no-pty /usr/bin/podman --remote=false \
    image inspect --format '{{.Id}}' "$1"
}
worker=$(image_id ghcr.io/anomalyco/opencode:2.3.0)
relay=$(image_id docker.io/library/python:3.12-alpine)
postgres=$(image_id docker.io/library/postgres:17)
chromium=$(image_id localhost/oc-chromium:latest)

run_profile() {
  OC_POC_PODMAN_HOST=distrobox python3 -B docs/prds/spikes/l_m_profile/probe_profile.py \
    --opencode-image "$worker" --relay-image "$relay" --postgres-image "$postgres" "$@"
}
run_profile --chromium-image "$chromium"
run_profile --without-chromium
```

Each run checks exact sidecar isolation before start. The OpenCode worker sees a
Postgres SCRAM challenge, plus a DevTools version response or an explicit
connection refusal when Chromium is omitted. The authenticated SQL check runs
inside Postgres using an ephemeral synthetic password. The OpenCode job then
streams a synthetic turn, writes the expected scratch file, and loses access
after revocation. Success ends with verified removal of all owned containers
and their private scratch directory.

A failed or interrupted run reports its retained private directory. Its
`receipt.json` and `sidecars.json` record run labels, names and any confirmed
container IDs for recovery. A missing create acknowledgment remains uncertain.

```sh
python3 -B -m unittest discover -s docs/prds/spikes/l_m_profile -p 'test_*.py'
```
