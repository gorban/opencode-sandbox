# I4d model-first picker spike

Both stock OpenCode 2.3.0 terminal frontends show distinct model-first labels from
configuration. Their normal browse order still groups rows by provider. Both retain
the exact saved route when it disappears from a resumed session and refuse the
next turn locally. The stock full picker can display two indistinguishable rows
when two registrations supply the same model display name.

## Reproduce

The probe was verified on Fedora 44 x86-64 with rootless Bubblewrap, tmux, and
Python 3 with Linux pidfd support. Both namespaces mount `/usr` and map `/lib64` to `/usr/lib64`. The pinned
ELF requires `/lib64/ld-linux-x86-64.so.2`. The host must provide that loader
and the required shared libraries under the mounted `/usr`. Run from the repository root.

```bash
python3 -B docs/prds/spikes/i4/model-picker/probe.py
```

The probe reads the [existing v2.3.0 fixture](../../../../development.md#local-opencode-text-proof)
from the account's `~/.cache/oc-sandbox/fixtures/opencode-2.3.0`. Use
`--binary /absolute/path/to/opencode` for a copy of the same executable. The probe
requires SHA-256 `2e0e4656521ca56e5ba16a00d48429958b8105b3fa6466710a4350e68759381f`
and verifies the executable version. It never downloads an executable or package.

The outer Bubblewrap namespace verifies that its only interface is loopback.
It runs a recording fake HTTP provider and a private tmux server. Each frontend
starts in a second filesystem and PID namespace sharing only the isolated network.
Its mounts include the stock executable, read-only JSON configuration, read-only
empty workspace, and its own scratch home and XDG directories. The tmux control
socket and the fake's one-shot gate are outside the frontend's mounts. The
launcher uses a separate mode-0700 temporary directory for each frontend.
The controller creates a mode-0700 staging directory at the location required
by nested Bubblewrap. The frontend receives its own `TMPDIR` and no host temporary directory.
The launcher uses these managed startup settings.

- `OPENCODE_CONFIG_PROJECT_DISABLE=true`
- `OPENCODE_DISABLE_MODELS_FETCH=true`
- `OPENCODE_DISABLE_FREE_MODELS=true`
- `OPENCODE_DISABLE_AUTOUPDATE=true`
- `OPENCODE_DISABLE_CLAUDE_CODE=true`

The probe uses OpenCode's bundled OpenAI-compatible Chat Completions package
and a fixed fixture key. The endpoint only produces prerecorded text and
cannot forward requests. Tools, title generation, summarization, and compaction
are disabled. The fake records all syntactically valid HTTP methods that reach
the application handler, with the request target taken from the original request
line. It records arrivals before reading the body, so an invalid or incomplete
body still counts as a request. The allow gate compares the target literally
and requires dispatch to the handler after the current approval. A query string
or extra leading slash changes the target and is refused. The probe fails if the request
log across all cases differs from the one authorized POST, even when every
extra attempt was refused. Before checking the final log, the controller waits
for each frontend pane to exit, then shuts down and joins the HTTP server so
a request already being handled appears in the verdict. Both waits are bounded.
Diagnostics retain the first 16 entries and truncate unusually long methods
and targets. Timeouts or failed checks exit nonzero and release the private
PTY server, the namespaces, and the scratch files.

Run the harness regressions in a loopback-only namespace.

```bash
/usr/bin/bwrap --unshare-all --die-with-parent \
  --ro-bind /usr /usr --symlink usr/lib64 /lib64 \
  --ro-bind "$PWD/docs/prds/spikes/i4/model-picker" /probe \
  -- /usr/bin/python3 -B /probe/test_probe.py
```

## Test flow and observed results

1. Open the full picker with Ctrl-X, then M. In Mini, use Ctrl-P and select
   **Switch model**. Both show five rows from two synthetic Claude accounts
   and one synthetic Google account. Each offers the upstream ID `opal-v2`.
   The two `personal` labels appear as `claude/personal` and `google/personal`.
   The configured model names carry their billing labels and expose v1 and v2
   as separate rows.
2. The probe asserts the five exact browse labels and the four search labels
   for `Opal v2`, including the v1 decoy whose name contains `opal-v2`.
   The recorded browse order places Zircon between Opal v2 rows. Full visits
   Claude personal, Claude work, then Google personal. Mini visits Claude
   personal, Google personal, then Claude work. Search for `google/personal`,
   choose its sole row, and dismiss the full picker's variant dialog if it appears.
3. Arm the fake for one POST with the exact Google path, upstream ID `opal-v2`,
   fixed prompt `Reply with exactly: ok`, and zero tools in the request.
   Submit through the normal composer. Each mode records exactly one accepted
   request and renders exactly `ok`. The fake returns a text-only stream with
   no tool calls. Both logs contain only the intended POST and show no
   startup or background request to the fake.
4. Close and relaunch with `--continue` using the same private profile and a
   policy/catalog with the selected Google scope removed. Both remaining
   registrations still offer `opal-v2`. The saved turn appears in the
   transcript, and the picker omits the removed scope. Full marks the
   selected route unavailable before submit. Mini shows the saved pair in the
   footer. The probe independently requires the local refusal after submit to
   name `google--personal/opal-v2`. In Mini it checks the complete rendered
   refusal line. The closed fixture records zero HTTP requests
   during the resumed run, including zero through other providers offering
   `opal-v2`.
5. In two fresh sessions, give the work account's `opal-v1` and then its
   `opal-v2` the exact Google v2 display name, including the Google account
   and subscription text. The probe checks that both copies appear in browse
   and in the `google/personal` search results. Full search showed identical
   rows in both cases. Mini browse showed separate `google/personal` and
   `work` headings. Its same-ID rows showed the same `opal-v2` footer, while
   search showed the actual provider labels on the right. Neither collision
   case submits a prompt. Both logs record zero requests during these cases.

## Follow-up

Use config-projected labels for the model-first text. A separate managed
picker change in both frontends is required to put models together during
normal browsing. Sort on a trusted model family and version followed by the
instance label. Keep the scoped provider, upstream model ID, and billing
disclosure visible in separately rendered fields so repeated or deceptive names
cannot hide the actual route. Preserve the exact `(providerID, modelID)` pair
as the selection value. Preserve the reviewed trusted approval and broker
checks for opening a route.

The results cover the two stock terminal frontends with a synthetic provider
and one resumed-session path. The shipped Podman launch, browser or desktop
pickers, subscription adapters, and production broker lifecycle remain outside
this probe. HTTP evidence covers syntactically valid requests dispatched to the
fake. The loopback-only namespace prevents external delivery.
