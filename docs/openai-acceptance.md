# Local OpenAI acceptance

After the feature checkout clears review, run its `oc-sandbox` command
from the foreground devbox terminal. Use the installed command once the
feature is merged.

## Workstation prerequisites

- Fedora devbox system Python needs PyJWT with RSA support. In devbox,
  install it with `sudo dnf install python3-jwt+crypto`.
- Browser sign-in uses the installed `host-spawn` and the workstation
  desktop's browser. Complete the consent in the account you want to use.
- The proof needs rootless Podman with SELinux enforcing and the exact
  cached OpenCode and relay images pinned by [the worker](../oc_openai/worker.py).
  The command checks these before proposing the proof and never pulls them.
  The current placement uses devbox and the local host on one Linux kernel.

## Inference and exposure

`connect LABEL` enrolls a local registration after the privacy notice.
Use `status` to see its label and `select LABEL` to switch registrations.
`accept` requires fresh consent for the fixed GPT proposal and again
for a disposable OpenCode worker to write one known file. No project
files are used. The proof reports success only after the two worker
phases and exact cleanup are verified.

Review the app's ChatGPT usage and credit settings before approving.
The proposal reserves up to 922,000 input and 128,000 output tokens.
The worker reserves up to 1,844,000 additional input and 256,000 output
tokens. ChatGPT plan and credit settings determine actual use. A hard
currency cap is unavailable in this preview, and API-key fallback is
disabled. An uncertain send or an observed overage stops further
inference. Keep its local accounting record for investigation.

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
