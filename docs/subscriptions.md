# Subscription text shells

## Gemini text shell

This experimental route uses the cached workstation Antigravity login. The Google client runs on
the workstation. Its credentials and ACP connection are absent from the disposable OpenCode worker.
The current public route allows one fixed, tool-free prompt per shell and only the measured
`gemini-4-hydrogen` model. The [I4c plan](prds/prd_i4c.md) records the boundary and remaining work.

Add a named provider to the trusted `~/.config/oc-sandbox/providers.toml`:

```toml
[providers.google.elgoog]
enabled = true
auth_mode = "subscription"
default_model = "gemini-4-hydrogen"
```

The name `elgoog` is an example. Any valid, enabled Google subscription label works with this model.
Sign in on the workstation with `agy acp --login` if the official client is not already signed in.
The shell currently requires the tested `agy` 1.5.15 executable at `~/.local/bin/agy`.

In the first terminal, from the trusted source checkout, run:

```bash
./oc-sandbox google shell elgoog
```

OpenCode displays `gemini-4-hydrogen - elgoog [subscription]` in its model picker. The first
terminal prints a run ID. In a second terminal, run `./oc-sandbox google arm RUN_ID`, replacing
`RUN_ID` with that value, and type `arm` after checking the model and scope. Return to OpenCode and
send exactly `Reply with exactly: ok`. The response should be `ok`. Exit the OpenCode shell to
retire the worker, relay and private run directory. A second prompt is refused by design.

The opt-in live regression is `tests/e2e/live/test_google_text_e2e.py` with
`--run-google-public-shell-live`. It requires an enabled `elgoog` entry and asks once for the
selected test collection. Ordinary local and CI test runs skip subscription inference.
