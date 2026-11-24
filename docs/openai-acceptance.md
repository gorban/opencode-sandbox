# Local OpenAI acceptance

After the feature checkout clears review, run its `oc-sandbox` command
from the foreground devbox terminal. Use the installed command once the
feature is merged.

## Workstation prerequisites

- Fedora devbox system Python needs PyJWT with RSA support. In devbox,
  install it with `sudo dnf install python3-jwt+crypto`.
- Use a workstation browser that can reach `127.0.0.1`. Automatic opening
  uses `host-spawn` and the default browser's local-file access.
- The proof needs rootless Podman with SELinux enforcing and the exact
  cached OpenCode and relay images pinned by [the worker](../oc_openai/worker.py).
  The command checks these before proposing the proof and never pulls them.
  The current placement uses devbox and the local host on one Linux kernel.
- Install pytest in a trusted developer environment before the live run.
  The proof driver uses the devbox system Python for PyJWT.

## Inference and exposure

`connect LABEL` enrolls a local registration after the privacy notice and
the `[y/N]` prompt. Keep the terminal open during sign-in. If the default
browser cannot complete it, copy the displayed sign-in link into another
browser on this workstation. Use `connect LABEL --no-browser` to open it
yourself from the start. The one-time loopback link opens OpenAI in the
external browser. It works with a sandboxed browser such as Flatpak Chrome
without granting access to the registration directory. Restart Connect if
you have opened the link and need a new one.
Use `status` to see the active label, saved registrations, and any
unconfirmed OpenAI revocation from a current or interrupted connection.
Use `select LABEL` to switch registrations.
From the reviewed checkout, run the test in the foreground devbox terminal:

```bash
env -i HOME="$HOME" PATH=/usr/bin:/bin PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /path/to/developer/venv/bin/python -IB -m pytest -s -p no:cacheprovider --run-openai-live \
  tests/e2e/live/test_openai_proof.py
```

The test reuses the active workstation registration. It requires fresh
consent for the fixed GPT proposal and again for a disposable OpenCode
worker to write one known file. No project
files are used. The continuation returns the approved outcome and any
encrypted reasoning from OpenAI to that same endpoint. The replay stays
in workstation memory. The proof reports success after verifying both
worker phases and cleanup.

Review the app's ChatGPT usage and credit settings before approving.
The proposal reserves up to 922,000 input and 128,000 output tokens.
The worker reserves up to 1,844,000 additional input and 256,000 output
tokens. ChatGPT plan and credit settings determine actual use. A hard
currency cap is unavailable in this preview, and API-key fallback is
disabled. An uncertain send or an observed overage stops further
inference. Keep its local accounting record for investigation.
An outstanding reservation is reported before the first approval prompt.
The proof reports workstation request failures by category without logging
provider response content. A stream failure leaves the reservation open
unless the test verified terminal usage for that request.

### One-shot workstation diagnostic

For the original unresolved workstation proposal, add
`--recover-openai-live` alongside the explicit `--run-openai-live` switch.
The active registration must still match the original request, and only
the first possible diagnostic send is allowed. Approve one fixed request
after reviewing the combined exposure for both requests. The original
reservation stays unknown. The diagnostic receipt is written before any
request bytes can be sent. Once written, it spends the recovery opportunity,
even if the process stops before the request reaches OpenAI. The diagnostic
stops after the workstation response. The worker test remains on hold.

If both earlier receipts remain unknown, the reviewed SSE compatibility
follow-up uses `--recover-stream-live` in place of `--recover-openai-live`.
Keep the explicit `--run-openai-live` switch. Review the displayed reservation
for all three possible requests. This workstation diagnostic uses one
separate receipt and ends before the worker.

### Single-approval recovery proof

After all three linked workstation requests remain unresolved, the reviewed
recovery proof can proceed with `--recover-proof-live=REVIEWED_SHA256` alongside
`--run-openai-live`. Use the SHA-256 for the exact reviewed driver and
workstation package. Pytest runs a private source-only snapshot with that
digest. Run from a foreground workstation terminal.

One approval covers the marker request and, if it succeeds with verified
usage, the disposable OpenCode worker and its one continuation. The
approval stays with that process and expires for new dispatches after five
minutes. It adds up to three requests. The displayed combined reservation
includes all three earlier unknown outcomes. Keep the earlier receipts and
the new `recovery-proof.json` if the run fails. A possible send consumes the
recovery proof and prevents replay. Ordinary inference remains suspended.

- [Sign in with ChatGPT account management](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions)
- [GPT-6.2 Sol model limits](https://developers.openai.com/api/docs/models/gpt-6.2-sol)

## Interrupted worker cleanup

`disconnect` fences the active registration and tries remote revocation.
If the terminal fence is incomplete, retry the same command. Keep the
private /tmp run directory while retirement or cleanup is uncertain.

On abrupt driver loss, the grant closes the relay sockets. The inactive
worker container and private run receipt can remain until cleaned up.
Inspect the exact `receipt.json` in the reported `/tmp/oc-i4a-…`
directory. If the driver could not print a path, list your candidate
receipts from the workstation without removing anything.

```bash
find /tmp -maxdepth 2 -type f -user "$(id -un)" -path '/tmp/oc-i4a-*/receipt.json' -print
```

Use host Podman to inspect each full container ID in the matching receipt. Confirm
its exact name, ownership label and role against the receipt before
removing it. If an ID was never recorded, the labels or name differ, or
you cannot confirm removal, preserve the receipt for recovery. Avoid
removing resources by prefix or deleting a private run directory before
retirement and container removal are confirmed.

[I4a design and review gates](prds/prd_i4a.md)
