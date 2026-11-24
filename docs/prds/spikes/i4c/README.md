# Offline Antigravity qualification

[PRD I4c](../../prd_i4c.md) covers workstation registration and live acceptance.

Run this offline proof in devbox with rootless Bubblewrap and user systemd on the
workstation. The fixture uses the pinned Antigravity CLI 1.5.15 build and a local
GNOME Keyring bundle containing `gnome-keyring-daemon`, `libgck-1.so.0` and
`libgcr-base-3.so.1`. The runner checks SHA-256 pins and stages only those exact
files. The vendor binaries and libraries stay outside the checkout.

```bash
python3 -IB docs/prds/spikes/i4c/qualify-native.py \
  --agy "$HOME/.local/bin/agy" \
  --keyring-bundle "$HOME/.cache/oc-sandbox-antigravity-qualification/bundle"
```

The probe verifies that the process cannot see a known-present workstation
file, Unix socket or loopback listener. It stores a synthetic item, restarts
both the private D-Bus and Secret Service processes, and reopens the item. It
then calls only ACP `initialize` and `session/new` and expects an explicit
authentication-required reply. A second run interrupts the live private
keyring and verifies that its exact systemd unit retired.

The final phase runs the pinned native terminal-login client on a synthetic
PTY. Its fake code produces a CONNECT request from private loopback through
the dedicated workstation Unix socket. The fixture checks the exact
`oauth2.googleapis.com:443` request and returns a denial without forwarding it.
The policy tests also reject unexpected hosts, malformed framing and non-public
DNS answers. Run them with `python3 -IB -m unittest discover -s docs/prds/spikes/i4c`.

The proof creates no workstation Secret Service item or real provider session.
When host retirement is uncertain, its output identifies the retained
synthetic scratch directory. The next qualification covers native client
egress, isolated personal sign-in, and the credential boundary to OpenCode.
