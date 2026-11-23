# M3a dashboard proof

Use Node 24.18.0 and npm 11.16.0 in this directory.

```sh
npm ci
npm run check
npm test
npm run build
npm exec -- playwright install chromium
npm run test:browser
npm audit
```

The browser tests serve the production assets with an enforcing CSP on an ephemeral
loopback port and intercept private API requests with synthetic fixtures. They check
keyboard navigation, deep links, private DOM clearing, inert content and error recovery.
The controller tests use an injected clock and transport to deliver held responses and
queued events after cancellation. The separate host integration checks real cookies,
authority, revocation and exact host CSP using the same static artifact. After reload,
Chromium shows three framework-owned session storage keys for scroll and navigation
state. The test checks that history metadata contains only numbers and both app snapshot
maps are empty. The dashboard registers no framework snapshots.

## Loopback qualification

Give the M3a host an absolute path to this directory's `build/`. The host uses its own
private launch pipe to issue a one-use code. Open `/dashboard/sandboxes` in a fresh
single-tab qualification profile on that server's origin and enter the code in the
password field. Keep that tab open without reloading while sign-in or sign-out is
pending. If the result is uncertain, reset the host and start a fresh browser profile.
The served HTML references immutable static assets and the browser reads
the session and workspace through the authenticated same-origin API.

To measure cold navigation, use the Playwright-pinned Chrome for Testing with a new
profile and a loopback-only DevTools port. Complete the synthetic exchange in that
profile and close other tabs. Run Lighthouse attached to that same profile with
`--disable-storage-reset` to retain the session cookie. Use `--throttling-method=devtools`
and report the browser version, requested throttling, transferred bytes and request
count. In the Lighthouse user timings, read `first-populated-sandbox-list` as the
navigation-to-list measurement. Keep the report and the scratch profile outside the
repository and shut down the host and browser after qualification.

One local run used Lighthouse 13.6.0 and Chrome for Testing 159.0.8154.6 with
an authenticated synthetic loopback fixture, storage reset disabled, and DevTools
mobile throttling (150 ms RTT, 1,638 kbps configured throughput, 4× CPU slowdown).
The first populated sandbox list appeared at 4.27 seconds. Lighthouse recorded 17
requests, 126,402 transferred bytes, a performance score of 0.79, and an accessibility
score of 1.00. This was a single fixture run.
