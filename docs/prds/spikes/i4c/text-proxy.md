# Offline Antigravity ACP text proxy

From the trusted repository checkout on Linux, run the synthetic readiness and text-turn tests:

```bash
python3 -B -m unittest discover -s docs/prds/spikes/i4c -v
```

For the real OpenCode worker and relay check, use the qualified Linux devbox with rootless Podman,
SELinux enforcing and the pinned images already present. The probe never pulls an image.

```bash
python3 -IB docs/prds/spikes/i4c/acp_text_probe.py
```

Expect exact `ok` from OpenCode, one prompt independently counted by the bundled ACP peer,
zero tool events, replay refusal, and verified retirement of the peer, containers and private
scratch. The worker uses a network with no external route. The relay listens on that network's
loopback only after the host accepts the one-shot arm. The spike uses synthetic enrollment and
does not start native `agy`, a browser, or a provider session. If retirement cannot be verified,
the report identifies the retained private scratch and the pending receipt stays in place.
If the peer retired but journal settlement was interrupted, the retained receipt still blocks reuse.
If the host cannot confirm container creation, the placement stays on disk. Its
`placement.json` records the run label and exact owned names for reconciliation.
The private runtime parent is trusted. Recursive cleanup uses the original directory descriptor,
and the owner verifies the parent entry before removing the empty directory.

[PRD I4c](../../prd_i4c.md) tracks native enrollment and live qualification.
