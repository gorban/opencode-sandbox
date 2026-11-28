# Offline stock worker tools proof

This fixture exercises the bare public `oc-sandbox` launch on main with a synthetic named
OpenAI subscription. Stock OpenCode runs its built-in `patch`, `read`, and `shell` functions
against a writable job directory, then returns each result through the real relay and
Responses broker. The measured stock client uses `patch` with an Add File operation for the
write and labels its shell tool `shell`. It sends four causal chat requests and one separate
tool-free title request.

## Local capture

In an isolated Linux namespace with loopback only, mount the pinned stock binary, the same
OCI musl loader and libc alias at `/lib`, and the two pinned stock libraries. Use an empty
writable `/sandbox/construct` and a private evidence destination that does not yet exist.

```sh
python3 -IB tests/e2e/stock_worker_tools_capture.py /oc-bin/opencode \
  --musl-libraries /musl --evidence /evidence/stock-tools.json
python3 -IB tests/e2e/test_stock_worker_tools_guards.py
```

The capture applies the stock request validator, pins the measured tool declarations and
uses the strict stream parser and projector against a fake upstream. It answers the
exact measured title envelope with a fixed local stream. The independent upstream
counter and private scratch exposure ledger must show exactly four writes and three
distinct continuation claims. Each continuation must repeat the ordered accepted
tool history and add exactly the batch handed off by its predecessor. The fixture
replays five mutations to the earlier prefix of the third continuation and checks that
each reaches neither claim nor send. It verifies native execution with the stock
session export and exact file bytes.

Run again with a fresh namespace, workspace and evidence file for each refusal:

```sh
python3 -IB tests/e2e/stock_worker_tools_capture.py /oc-bin/opencode \
  --musl-libraries /musl --case hosted --evidence /evidence/stock-hosted.json
python3 -IB tests/e2e/stock_worker_tools_capture.py /oc-bin/opencode \
  --musl-libraries /musl --case undeclared --evidence /evidence/stock-undeclared.json
python3 -IB tests/e2e/test_stock_worker_tools_turns.py
```

The capture writes a new mode 0600 evidence file in a private directory owned by the
capture user. If the capture fails, it stops the observer and snapshots the bounded
synthetic journal before removing scratch. An unresolved claim retains null usage
only when the settled prefix and the exact claim match, including when SQLite
commits before reporting an error. Cleanup errors accompany the original failure
as exception notes. A missing or invalid journal produces an unavailable or corrupt
status. Record the evidence SHA-256 and the source revision. The capture is a loopback proof with a
synthetic accounting store. The public launcher, production broker and TLS peer are exercised by
the separate sealed guest procedure below.

## Pinned built-in inventory

The first chat request advertised these 11 tools. Match each qualification to the same
stock binary and exact declared schema.

| Tools | Evidence or next qualification |
| --- | --- |
| `patch`, `read`, `shell` | Positive loopback runs verify the resulting bytes, readback, and shell output. |
| `glob`, `grep` | Verify workspace searches and denial of their access to host files. |
| `question`, `skill` | Verify the stock terminal question flow and reads from approved in-job skills. |
| `subagent` | Verify the child stays in the job and inherits only permitted model routes and budgets. |
| `webfetch`, `websearch` | Verify use of the intended job egress, denial of provider login routes, and no access to host credentials. |
| `execute` | Verify the confined JavaScript runtime cannot escape the job's tool or HTTP permissions. |

## Sealed guest

Use a disposable QEMU/KVM Fedora guest with SELinux enforcing and no host mounts or passed
through services. Use guest account `oc-gemini-proof`, home `/home/oc-gemini-proof`, fresh
rootless Podman storage with subordinate IDs, a qualified Distrobox devbox with `host-spawn`,
tmux and a session bus, the installed `attr` and Python PyJWT prerequisites, and the same
root-owned sticky host `/tmp` visible inside devbox. Use a fresh account without a sandbox
directory, prior OpenCode state or prior provider registration. A run is single-use.

Before disabling egress, load only the reviewed immutable launcher images. Give the private
test account only the reviewed image archives and inventory, with its Podman store otherwise
containing just the running devbox. Warm and export images using a separate disposable account
if needed. Record the launcher build ledger for the exact warmed image inputs. Allow no shared
volumes, remote Podman, imported secrets or staging-account storage state.

On the guest host, apply this complete guest-only nftables table. Keep a controller console
available while sealing the firewall.

```nft
table inet oc_gemini_fixture {
    chain output {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct direction reply tcp sport 22 ct state established accept
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
}
```

Grant only this scoped read to the dedicated account after checking the rule with
`visudo -cf`.

```sudoers
oc-gemini-proof ALL=(root) NOPASSWD: /usr/sbin/nft -j list table inet oc_gemini_fixture
```

Transfer just the reviewed source, including the fixture files, into root-owned guest
storage. Produce the inventory digest from the same source at review time. Install and seal
as guest root.

```sh
cd /root/stock-worker-tools-source
/usr/bin/python3 -IB tests/e2e/stock_worker_tools_projection.py source .
/usr/bin/python3 -IB tests/e2e/stock_worker_tools_projection.py install "$PWD" "$SOURCE_SHA256"
/usr/bin/python3 -IB /home/.oc-stock-tools-proof/source/tests/e2e/stock_worker_tools_host.py \
  "$DEVBOX_ID" --image "$AGENT_IMAGE_ID" --image "$CHROMIUM_IMAGE_ID" --image "$RELAY_IMAGE_ID"
```

Include an additional `--image` for the devbox image if it appears separately in the sealed
Podman store. The host and devbox must see the same root-owned read-only projection at
`/home/.oc-stock-tools-proof`. Use a read-only, ID-mapped bind if needed to preserve ownership
as UID 0 in devbox. The only transformed source in the capsule is the TLS connect function used
to dial the synthetic provider. The launcher, worker supervisor, adapters, request validator,
projector and relay retain the measured source bytes.

As the dedicated account inside devbox, run the measured driver from the fixed location.

```sh
cd /home/.oc-stock-tools-proof/source
/usr/bin/python3 -IB /home/.oc-stock-tools-proof/source/tests/e2e/stock_worker_tools_guest.py
```

The driver waits for the exact route and billing disclosure, exercises decline before
approval, and verifies stock attachment, filesystem and shell results. It checks worker
and relay mounts, synthetic credential isolation, outside-pod reachability, private relay
proof, incorrect bearer, hosted tool rejection, the broker reasoning vault and revoked
stream closure. The network probes check the relay's kernel listener, no published ports,
and the guest host and independent container's access to the measured IPv4 candidates.
The two stock refusal cases allow one exact initial prompt retry and stop it with a
fixture 401. Their failed exports have zero tool parts and the approved job bytes are
verified afterward. It verifies worker, relay, lease, TLS peer and scratch retirement. The
remaining support pod, volumes and images are reported in the sealed guest inventory.
The disposable guest controller owns the final reset. Keep the redacted report and exact
source/projection hashes with the review evidence.

The guest's firewall is a condition of this offline proof. Production placement egress
enforcement remains a separate qualification.
