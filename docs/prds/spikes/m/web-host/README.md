# Running the M3a host fixture

From the repository root, give the host the trusted SvelteKit build directory
prepared by the [UI fixture](../web-ui/WALKTHROUGH.md). Pass its canonical
path so the strict directory checks also work on hosts where `/home` is a
symlink.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 docs/prds/spikes/m/web-host/oc_web_host.py \
  --build "$(realpath -- /absolute/path/to/build)"
```

For an automated browser launch, start the host with private stdin and
stdout pipes. Its first stdout line is a JSON object with the loopback
`origin` and a single-use `code`. Keep the line in the harness process.
Open `<origin>/dashboard/threads` in a fresh single-tab profile and enter
the code in the bootstrap input within 60 seconds. Send `mint` followed by
a newline on stdin to get another `{"code": ...}` line. Send `stop` or close
stdin to shut down the listener and join its handlers. Discard the profile
when the harness stops.

Use a second disposable loopback origin when checking browser CSP. The
test target can serve an inert fixed response. For the host Origin check,
send `Origin: http://127.0.0.1:1` on a local request to a dashboard path and
assert `403`. Keep the synthetic cookie and bootstrap code out of that
request.

The standard library tests construct their own trusted package and use
disposable TCP listeners.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s docs/prds/spikes/m/web-host -v
```

To check the shared raw-byte fixture from `web-ui/fixtures/`, copy
`bootstrap.html` into a private temporary build directory as `200.html`
and copy `csp-manifest.json` next to it. Launch against that directory and
compare a dashboard response with the original bootstrap file. The fixture
CSP includes `'sha256-ryOtdTEaDoHqpdYPuB0kwICxVEs4+liEH2Shgg9msLE='`.
Use the actual packaged UI for the joint Chromium smoke.

The internal projection reader accepts a typed host context with the pinned
operator and read session coordinates. The retirement guard covers the
fixture read. Supply only trusted, bounded in-memory source data that stays
stable during serialization. The reader does not block or perform I/O.
