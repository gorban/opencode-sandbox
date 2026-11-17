# Host browser name-constraint probe

This manual E/X subset of [prd_e1](../../prd_e1.md) uses six cases per browser, not the full matrix
of 2,268 results (189 CA/leaf combinations across 12 verification paths).
Run Firefox and Chrome one at a time in throwaway Flatpak profiles. The fixture and launchers do not
install a system CA or modify a real browser profile. Do not use certificate-error bypasses, a real
profile or trust database, global DNS/hosts changes, or `--no-sandbox`.

## Start the fixture

From the repository root on the **host**, use a disposable, retained `.scratch/e1-run.*` directory
created by `probe.sh --keep-scratch` with the E/X CA certificates and `feat`, `evil`, and `ip127`
leaves and keys:

```sh
python3 -I docs/prds/spikes/e1/host-browser-fixture.py /absolute/path/to/.scratch/e1-run.EXAMPLE </dev/null
```

From the devbox distrobox, prefix the command with `distrobox-host-exec`. Keep the process in the
foreground: Ctrl-C or the default 1,800-second lifetime stops its loopback listeners. It prints a new
private manifest and Firefox launcher. If it expires, start a fresh fixture and use its new profile,
ports, URLs and marker; never assume stale ports still belong to the fixture.

The manifest contains six URLs, a per-run response marker, E/X public CA paths and fingerprints, and
one loopback proxy. The proxy accepts only the exact host/port CONNECT pairs and forwards only to
loopback. `evil.example.com` in a URL must go through this proxy; if the browser cannot use the fixture
proxy, stop instead of browsing directly. The IPv4 case uses the fixture's loopback listener. The fixture
checks the cert/key pairs and expected OpenSSL E/X outcomes before publishing the manifest.

## Firefox

1. Run the printed `launch-firefox.sh` path on the host. It uses `--no-remote`, an explicit private
   profile and closed stdin. In `about:support`, confirm **Profile Directory** equals the manifest's
   `firefox_profile`; stop if it differs.
2. In Firefox's certificate settings, import the two manifest CA files into this profile as authorities
   trusted for websites. Compare both displayed SHA-256 fingerprints with the manifest: E and X have
   the same subject but different keys and fingerprints.
3. Visit each manifest URL. E/feat and all X cases should show a secure connection and the exact marker
   for that label. E/evil and E/ip127 should be rejected. Record the browser version, profile,
   fingerprints, each result and marker. Do not bypass a certificate error.
4. Close the test browser and check for its remaining test-owned helpers before proceeding.

## Chrome

Prepare a separate Chrome scratch directory from the **live** Firefox fixture manifest:

```sh
python3 -I docs/prds/spikes/e1/prepare-host-chrome.py /absolute/path/to/fixture/manifest.json </dev/null
```

Run the printed Chrome launcher on the host. Before importing, confirm `chrome://version` **Profile
Path** is the Chrome manifest's `chrome_user_data_dir` plus `/Default`; stop if it differs. The
launcher uses a separate sibling scratch directory, individual writable state mounts, a read-only CA
directory and Flatpak's filtered `--session-bus`, not full session-bus access.

On the tested host, choosing either private CA file in Chrome's trusted-certificate import UI first
produced **Error reading file**: the picker exported it through the document portal, but `--sandbox`
had not mounted that path. Select the Chrome manifest's `ca/E.pem` and `ca/X.pem` once each to create
their test exports. Inspect **only those two known files** on the host:

```sh
flatpak document-info /absolute/path/to/e1-chrome-EXAMPLE/ca/E.pem
flatpak document-info /absolute/path/to/e1-chrome-EXAMPLE/ca/X.pem
```

Check each origin is the exact private CA file, its fingerprint matches the manifest, the grant belongs
to `com.google.Chrome`, and the exported path is one `/run/user/<uid>/doc/<id>/E.pem` or `X.pem` file.
`Not exported` is not a usable path even if the command returns success. Record the two test-created IDs;
do not inspect or reuse unrelated app exports.

Close the test Chrome and its attested helpers. Validate the candidate repair, then apply it only to
this private Chrome profile:

```sh
python3 -I docs/prds/spikes/e1/repair-host-chrome-portal.py CHROME_MANIFEST E_EXPORT X_EXPORT --dry-run </dev/null
python3 -I docs/prds/spikes/e1/repair-host-chrome-portal.py CHROME_MANIFEST E_EXPORT X_EXPORT </dev/null
```

Substitute the Chrome manifest and exact exported PEM paths. The helper validates owner, profile,
fingerprints, complete PEM bytes and path scope, then atomically reconstructs the private launcher
with **only those two files** mounted read-only. It does not launch Chrome or import trust. Do not mount
the whole document portal. Relaunch the test profile, confirm its path again, then import E/X in
Chrome's trusted-certificate UI, checking both fingerprints. Visit and record all six cases as for
Firefox. Chrome's observed negative error was generic `net::ERR_CERT_INVALID`: the paired X controls
support the inference, but that message alone does not identify the exact cause.

## Cleanup

- Close the test browser and stop the foreground fixture with Ctrl-C. A closed window may leave
  test-owned Flatpak helpers. Inspect `flatpak ps --columns=instance,application`; identify a current
  instance by the recorded test instance ID or by narrowly checking its `/.flatpak-info` Context for
  the exact private test profile and state mounts. Verify its app ID, and reject any candidate with
  broader host or home mounts. A visible profile directory alone does not prove ownership. Stop only
  positively attested test instances; if uncertain, leave them running. Never `flatpak kill` an app ID
  such as `com.google.Chrome` or `org.mozilla.firefox`.
- After Chrome closes, inspect each exact test export again with `flatpak document-info` on its private
  CA file. Only when origin, ID, fingerprint and app grants still match and no unrelated grants exist,
  remove that exact test ID with `flatpak document-unexport --doc-id ID`; check the known file now says
  `Not exported`. Never remove unrelated grants.
- Remove only recorded, owned, non-symlink `.scratch/e1-browser-*` and `.scratch/e1-chrome-*`
  directories after their processes have stopped. The fixture retains them for inspection. Treat the
  separate `.scratch/e1-run.*` assets according to the spike cleanup plan; never delete an unverified path.
- Compare the relevant real certificate-store and certificate-setting snapshots before and after the
  test. Report exactly what was checked and any unrelated changes; a finite file list cannot establish
  that every host setting was unchanged.

The host-only `host-browser-control-regression.py`, `host-chrome-isolation-regression.py`,
`host-chrome-portal-regression.py`, and `repair-host-chrome-portal-regression.py` check control-file
isolation, sibling mounts, the filtered-bus wrapper requirement and the scoped repair. Read each
script's usage; they use disposable scratch and do not open a GUI or install trust.

`host-browser-source-regression.py` uses private temporary fixtures to check rejection of external
executable-source arguments and host-home paths containing spaces. Run it with `python3 -I`; it needs
no Flatpak or retained crypto assets. The other regressions load only their adjacent repository builders.
