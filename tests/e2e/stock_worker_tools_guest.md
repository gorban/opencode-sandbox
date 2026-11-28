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
only when the settled prefix and the exact claim values and SQLite types match,
including when SQLite commits before reporting an error. Observer serving and
request handlers share one shutdown deadline. Capture commands require the
existing foreground tmux server. Terminal teardown checks its shutdown command
and observes the exact child exit within a separate deadline. If either teardown,
journal publication, or settlement cannot be confirmed,
the capture retains the journal and an owner-only recovery receipt in a private
child of the persistent evidence directory. The raised diagnostic gives that
location and the requested failure evidence gives only the unavailable status.
On the host, the same run directory is under the evidence bind's source path.
Terminal scratch uses the namespace's short local path while it may still be
in use. It can disappear with the namespace while the journal and receipt
survive. The receipt records the run and local scratch identity. It includes the
tmux socket identity when verified and records it as unavailable otherwise.
The capture holds private directory descriptors and verifies their visible names
before publishing evidence or removing scratch. It syncs the evidence parent
before starting and persists bounded SQLite snapshots through the held run
directory before authorizing synthetic sends. It checks the published ledger
after synchronization and again before final first-write authorization. The
receipt records the known owned ledger inodes when publication is uncertain.
If a name has moved, use the private diagnostic and receipt to locate the
retained evidence after retirement. This fixture assumes exclusive same-UID access to the
evidence bind and terminal scratch during capture. Peers with the same UID can
mutate directory names, and POSIX checks inode identity and removes a name in
separate calls.
Cleanup errors accompany the original failure as exception notes. A missing
or invalid journal produces an unavailable or corrupt status. Record the
evidence SHA-256 and the source revision. The
capture is a loopback proof with a synthetic accounting store. The separate
sealed guest procedure below exercises the public launcher, production broker
and TLS peer.

## Workspace search capture

Use a fresh loopback namespace and empty job for the separate search proof. In addition to
the pinned OpenCode binary and musl inputs above, mount the worker image's ripgrep at
`/usr/bin/rg` and include its `libpcre2-8.so.0` in `/musl`. The fixture verifies both
SHA-256 pins before starting the UI.

```sh
python3 -IB tests/e2e/test_stock_worker_tools_search.py
python3 -IB tests/e2e/stock_worker_tools_capture.py /oc-bin/opencode \
  --musl-libraries /musl --case search --evidence /evidence/stock-search.json
```

The fixture writes two synthetic control files. It pins the exact `glob` and `grep`
schema projections from the independent capture whose SHA-256 is
`59459dd54e589e62a34c90724c0c566b3b8c4fb984349d11df8a65a90412f97e`.
The approved declarations and typed search schemas are checked on the first chat request
and both continuations before any corresponding claim. The fixture compares the unique
glob path and grep path, line number and text with its independent reading of the job
bytes. The stock export must record two distinct completed tool calls and the final
ordinary reply. The private ledger must show three settled claims, matching three
synthetic writes. The one local title costs no claim, and the fixture checks that the job
inventory and bytes are unchanged. Keep the exact source tree, evidence SHA-256 and
namespace exit status with the review record.

The loopback capture covers positive workspace search. Sealed guest qualification is
separate and still requires an independently verified, controller-readable sentinel
outside the worker mount. Each native search must record the issued tool and exact input
with an explicit permission refusal or genuine lookup error for the protected target.
Record the mount inventory and absence of marker delivery. An empty result alone cannot
establish this boundary.

## Stock question and skill capture

Use the measured OpenCode Full v2.3.0 binary above in a fresh loopback namespace
per case. Each run needs its own private evidence directory and an empty job.
The upstream and operator are synthetic.

```sh
python3 -IB tests/e2e/test_stock_worker_tools_interaction.py
for case in question question-cancel skill skill-unavailable skill-undeclared; do
  # Run this invocation in a new loopback namespace for each case.
  python3 -IB tests/e2e/stock_worker_tools_capture.py /oc-bin/opencode \
    --musl-libraries /musl --case "$case" --evidence "/evidence/$case.json"
done
```

The pinned declarations come from independent capture
`18b4f54bb42d256441b2681b894800ceedd8e3bdb8991f732b7cb60ca9da5709`.
Check the two exact schema projections and the full stock request envelope before
authorization. The fake upstream receives only the function approved for the case.
The question driver matches the current screen with the fully handed-off prompt's
chat, scoped route, model and pending call before applying Enter or Escape. The
native result must match the exact continuation. Escape shows an interrupted
terminal and exported aborted tool with no continuation request.

The skill case puts one pinned `SKILL.md` in the job's private OpenCode home.
It disables MCP for these cases and grants skill permission only to the intended
fixture ID. Both the tool result and export must bind the loaded ID and exact
skill text while the source inventory stays fixed. An unavailable synthetic ID
must return the native lookup error. The undeclared tool stream may use only its
initial claim and never produce a native call. Separate guards reject unexpected
source files or IDs, crossed sessions and calls, and mutated or replayed results.
A local title consumes zero inference claims.

Record the source tree, evidence SHA-256, successful process exit and retired
namespace together. The redacted evidence records usage and outcomes without the
native transcript or absolute skill path. A provisional evidence file from a
failed capture is insufficient for qualification.

The separate sealed guest qualification remains open. It requires a known-present
synthetic skill sentinel on the controller, independent verification of the fixed
mounts and worker-visible inventory, a native lookup denial for that sentinel,
and zero marker delivery. The loopback fixture exercises no real account, worker
mounts or launch approvals.

## Pinned built-in inventory

The first chat request advertised these 11 tools. Match each qualification to the same
stock binary and exact declared schema.

| Tools | Evidence or next qualification |
| --- | --- |
| `patch`, `read`, `shell` | Positive loopback runs verify the resulting bytes, readback, and shell output. |
| `glob`, `grep` | Positive loopback checks exact synthetic path, line and text. Sealed denial remains open. |
| `question`, `skill` | Loopback covers terminal answer and dismissal, approved skill bytes and native lookup failure. Sealed sentinel denial remains open. |
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

### Sealed workspace search

The same guest command runs the original launcher cases first, then launches
fresh chats for positive search and for native denial by both built-ins. The
controller seeds only the synthetic search subtree mounted under the worker
job and a separately held, verified control under its private fixture home.
The trusted guest host observes the worker and relay through the live
process roots and mount namespaces in procfs. It pins each approved host
source and container destination, associates both descriptors with their
kernel mount IDs, and compares device, inode, filesystem and translated
mount root. It checks these identities before and after the native run,
refuses ancestor or descendant shadows of the runtime paths, and rejects
any mount rooted in or above the sentinel backing tree on its filesystem.
The controller sentinel paths must be absent under the pinned process
roots. Ordinary unrelated stock system mounts remain in scope only for
the overlap checks. This proves the exact paths and tested backing aliases,
with any separate copies or unrelated mount contents outside the evidence.

A worker-local OpenCode config disables just the title agent for the added
scenarios. A pinned v2.3.0 loopback run confirmed that this setting suppresses
title writes while the normal tool turn completes. The sealed peer refuses a
title POST as an unexpected request. Keep the legacy launch cases under their
original settings.

The fake peer records a fixed request-shape receipt before each validation.
The receipt keeps measured field names and counts without including requests,
unknown names, or values. For the interaction fixture, a separate shape
receipt uses the locked per-case journal stage and reports bounded item
type and role categories, counts, and exact expected-user and causal-match
flags. It excludes content, identifiers and arbitrary digests.
A failed peer that already bound its TLS handoff
records only an approved error category and bounded fixture source locations.
A peer failure still blocks the case and cleanup proof.
The optional shape receipt goes to a separate best-effort
`peer-shapes.jsonl` stream so a failed diagnostic append leaves the
lifecycle journal intact. Provisioning can skip this stream only on a
resource or read-only error with a proven absent leaf under the pinned
private directory. Existing or unsafe paths stop setup. The stream
records only fixed match categories, booleans, approved field names and
counts. Sealed tool validation uses the
full independently measured v2.3.0 Bash declaration and its exact typed
schema. The measurement removed `SHELL` at stock process startup and
confirmed that the production broker sanitizer retained the declaration.
A different shell description or schema fails validation. No observed
request can update the expected pin.

Each case has a fresh controller-only journal. The TLS fixture validates the
broker-sanitized schema, job, scoped case, model, session and exact causal
prefix before persisting its claim and sending the synthetic TLS response.
The peer records a provisional submission after the complete response has
been handed to TLS. It distinguishes reciprocal TLS shutdown from the EOF
that can follow a one-way server alert. A broken pipe, timeout or incomplete
write leaves the claim unresolved. A submission alone earns no delivery or
usage credit. The final proof requires the exact causal continuations,
native export and the production broker's completed usage records.
Once the transcript is visible, the driver waits up to eight seconds for
the exact fresh usage sequence under the broker's journal lock. It sends
the normal exit keys only after acknowledgement and then verifies the
same journal snapshot after retirement. A wrong, extra, incomplete or
changed row fails the proof. The approved missing-skill refusal requires
its existing null-usage outcome alongside the completed generation.
The peer claim precedes the fixture reply. The unchanged production broker has already sent
the corresponding request to the synthetic peer by that point.

The protected glob requests the independently observed control filename.
The protected grep requests a literal substring confirmed in the known
control bytes. The complete sentinel marker stays out of each request and
result. The search-denial case requires the exact native missing-path error
stock export and the peer's causal prefix and verifies that the control marker
never enters either. Keep the exact source manifest and the guest reset
receipt. This stage needs an independent sealed run before recording a
worker-bound qualification.

### Sealed question and skill

After the original and search cases finish, the same sealed driver runs four
fresh chats in the same worker home. The answer, approved skill and
controller-sentinel lookup run before cancellation. The driver restores
the worker-only skill allowlist before the last launch.
OpenCode v2.3.0 can resume a suspended execution after a managed restart.
A separate cross-launch qualification would need to account for that
recovery. The cancellation case covers the same launch through teardown.
[OpenCode v2.3.0 session execution](https://github.com/anomalyco/opencode/blob/v2.3.0/packages/core/src/session/execution.ts#L143-L158)
and [restart recovery](https://github.com/anomalyco/opencode/blob/v2.3.0/packages/core/src/session/execution/restart.ts#L431-L445)
describe the durable claim and restart behavior.

Before the native question input, the fixture requires the exact live
terminal dialog, the pending export's chat and model, and one durable peer
claim and corresponding submission. It sends Enter or Escape in that terminal.
Before offering a second generation, the peer requires the exact answer,
call identity, session and receipt written after the terminal input. A
dismissal requires a native interrupted export and zero additional peer
requests or broker usage entries.

The approved worker-local skill is seeded as exact synthetic bytes within
the existing named worker home volume. The fixture does not add a mount or
change the published launcher. It confirms the skill inventory and bytes
from the worker before and after the turn. The controller sentinel is
independently readable from the dedicated synthetic controller's own skill
directory. The worker and relay must both lack that path. The separate
sentinel-lookup run permits the missing synthetic ID and requires the exact
native missing-skill error, zero marker delivery and no second generation.

The stock client forwards its native failed skill result as a continuation.
The unchanged broker sends that request to the sealed fake peer, which
refuses it without a second generation claim. The report accounts for that
broker request separately. This case does not qualify a zero-wire policy
for failed skill lookups.

Install and launch from the fixed capsule paths above, with the exact source
and manifest digests recorded alongside the archive. If fixture cleanup
raises, preserve the private terminal scratch, per-case journals, usage
journal and run identities until controller-owned retirement is verified.
Retain redacted results and host/guest reset evidence separately.

The guest's firewall is a condition of this offline proof. Production placement egress
enforcement remains a separate qualification.
