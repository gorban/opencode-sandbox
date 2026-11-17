# prd_d1: Per-instance loopback address and port forwarding

Parent: [prd_d](prd_d.md)

## Idea

All of `127.0.0.0/8` is local on Linux with no configuration. Give each instance a stable address
`127.0.1.N`, stored as a pod label and allocated under a lock in `$STATE`, and have pasta forward to the
pod from that address only.

## Spike results (branch `spike-d1`, 2026-11-15, revised after review)

Host: Podman 6.1.3, passt/pasta 0^20261002.gcba3570, nftables 1.1.6, kernel 7.3.3,
`ip_unprivileged_port_start=1024`. All curls ran on the host (directly on the host, or via `distrobox-host-exec` from a distrobox).
A full run of an earlier probe revision recorded 61 PASS and 0 FAIL; the native-host atomic section recorded 12 PASS and 0 FAIL; the revised restart section recorded 8 PASS and 0 FAIL;
`probe.sh SECTION…` runs parts. Host conflict and container-capability results are historical **hand tests**, not reproduced by the current script. The script creates only `oc-spike-d1-*`
resources, uses private per-run Podman ID files and deletes only recorded immutable IDs, and
keeps its scratch files in a `mktemp -d` directory that it alone removes. In the text `ADDR` is `127.0.1.N`.

### How Podman starts pasta, and why the first probes failed

Podman runs one pasta per pod (host namespace):

```
pasta --config-net [pasta options] [-t SPEC for each -p, else -t none] --dns-forward 169.254.1.1 \
  -u none -T none -U none --no-map-gw --quiet --map-guest-addr 169.254.1.2 --netns /run/user/…/netns/netns-ID
```

- The pasta options come either from `--network pasta:opt,opt…` or, when the pod is created with plain
  `--network pasta`, from `[network] pasta_options = [...]` in containers.conf.
- **`--network pasta:…` is split on every comma, with no escape.** `-t,ADDR/1024-65535,auto` made `auto` a
  positional argument, which pasta treats as the command to run in a new namespace: the `uid_map` error
  (probe `neg3`). `-t,ADDR/auto` has no comma and works. A literal `-t` replaces Podman's `-t none`;
  `--tcp-ports=SPEC` is not recognised, Podman adds `-t none`, pasta stops (`neg4`). Exclusions need
  commas; a second `-t` for the same address conflicts with `auto` (`neg5`).
- **Correction to the first version of this PRD:** `pasta_options` in `CONTAINERS_CONF_OVERRIDE` is not ignored.
  It is read **every time the pod starts** (not stored in the pod). My first test created the pod with the
  override but started it without, and wrongly concluded it was ignored. A pod started without the override
  gets `-t none`: **nothing is forwarded** (`neg6`, matrix `mnoenv`). That fails closed. Array elements are
  not comma-split, so `-t ADDR/~9222,~5432,auto` works, and it is also how the pod's pasta is told to leave
  the sensitive ports alone.
- The old "no answer" for `-t ADDR/4321` was the app: with `--host-lo-to-ns-lo` pasta connects to the **same
  loopback address inside the pod** (`ADDR`), which an app bound to `127.0.0.1` does not accept; without that
  option it connects to the pod's interface address (the app saw `from=192.168.1.2`), also refused for
  `127.0.0.1` apps (`neg1`, `neg1b`). `toaddr 127.0.0.1` forwards nothing, not even to `0.0.0.0` apps
  (`neg2`; inferred: only same-loopback splicing works, other targets go through the tap path). So **pasta
  alone can't reach a `127.0.0.1` app through `ADDR`**; a netfilter `REDIRECT` inside the pod does it.

### Design that passed, with two independent layers for the sensitive ports

1. **pasta layer (primary for 9222/5432):** pod created with `--network pasta`; every podman command that
   may start the pod runs with `CONTAINERS_CONF_OVERRIDE=<host-trusted file>` containing
   `pasta_options = ["--host-lo-to-ns-lo", "-t", "ADDR/~9222,~5432,auto"]`. Pasta never opens or connects to
   an excluded port, whatever binds it.
2. **netfilter layer (needed for `127.0.0.1` apps, and a second wall for the excluded ports):** one table in
   the pod netns, applied from the host with the host's own `nft`, **no container and no image**:

```
distrobox-host-exec podman unshare nsenter -t INFRA_PID -n sh -c 'printf "%s\n" "$1" | nft -f -' _ "$RULES"
```

```
table ip oc_d1
delete table ip oc_d1                      # same transaction: atomic replace
table ip oc_d1 {
  chain nat_out    { type nat hook output priority dstnat; policy accept;
                     ip daddr 127.0.1.0/24 tcp dport != { 9222, 5432 } redirect }
  chain filter_out { type filter hook output priority filter; policy accept;
                     ip daddr 127.0.1.0/24 tcp dport { 9222, 5432 } reject with tcp reset }
}
```

   The two rules cover complementary port sets, so the result does not depend on rule order and a changed
   list can't leave a port in both states (the first version used `iptables -C`/`-A`; a port added later landed
   after the REDIRECT and was redirected, as the reviewer showed. That design is dropped).

Practical notes from the probe: `distrobox-host-exec` does not forward stdin (pass the rules as an argument);
`nft list` prints nothing when its stdout is the pipe distrobox gives it (list through `| cat` inside the
`sh -c`); `nft -f FILE` failed silently under `podman unshare` (use stdin). `INFRA_PID` is
`podman inspect --format '{{.State.Pid}}' $(podman pod inspect --format '{{.InfraContainerID}}' POD)`.

### Results

| # | Probe | Result |
|---|---|---|
| 1 | `neg1`/`neg1b`: `-t ADDR/4321-4322`, apps on `0.0.0.0:4321`, `127.0.0.1:4322`, with and without `--host-lo-to-ns-lo` | 4321 answers, 4322 never (control = 4321) |
| 2 | `neg2`: `…-t,ADDR/4321-4322:127.0.0.1/4321-4322` | neither port answers (both servers up in the pod) |
| 3 | `neg3`, `neg4`, `neg5`: comma in `--network pasta:`, `--tcp-ports=`, auto plus `~9222` | `uid_map` error; `-t none conflicts`; `Forwarding configuration conflict` |
| 4 | `neg6`: pod with override at create and start; same pod restarted without it | `-t ADDR/~9222,~5432,~9223,auto` ; then plain `pasta --config-net` (`-t none`) |
| 5 | matrix `full` (pasta layer + nft): `9222` on `127.0.0.1`, `5432` on `0.0.0.0`, `9223` on `ADDR` itself; plus `3000` on `127.0.0.1`, `4000` on `0.0.0.0` | all three sensitive ports closed; 3000 and 4000 answer. In-pod clients still reach `127.0.0.1:9222` and `:5432` |
| 6 | matrix `pasta` (pasta layer only) | sensitive closed; 4000 answers; `127.0.0.1` app 3000 closed (no redirect) |
| 7 | matrix `nft` (plain `-t ADDR/auto` + table only) | sensitive closed; 3000 and 4000 answer |
| 8 | matrix `bare` (plain `-t ADDR/auto`, no table) = what happens when the rules are missing | **fail-open**: `5432` (`0.0.0.0`) and `9223` (`ADDR`) answer, the app sees `from=127.0.0.1`; only the `127.0.0.1`-bound `9222` stays closed |
| 9 | pod started without the override (`mnoenv`) | app up in the pod, host gets no answer: fails closed |
| 10 | two pods `127.0.1.201`/`.202`, `127.0.0.1:3000` in both (bodies `A`, `B`) | each address answers its own pod only; a pod's address does not answer the other's ports |
| 11 | exposure | no answer on `192.168.1.2`, `0.0.0.0`, `127.0.0.1`, `[::1]`, unallocated `127.0.1.203` (each with a positive control). Host `ss`: only `127.0.0.1` and `127.0.1.20x` sockets; no UDP sockets |
| 12 | `-p 127.0.0.1:14001:3001 -p 127.0.0.1:14002:4000` on the same pod | pasta gets `-t ADDR/~…,auto -t 127.0.0.1/14001-14001:3001-3001 …`; both mappings and `auto` work |
| 13 | in-pod client (another container) -> `127.0.0.1:3000` | `A`/`B` as before |
| 14 | `[::ffff:ADDR]:3000` and `curl --interface 127.0.0.5` to `ADDR:3000` | both **answer** (they are ordinary IPv4 connections to `ADDR`). The review's "reset" was not reproduced |
| 15 | apps on 32767, 32768, 40000 | 32767 forwarded; 32768 and 40000 not (`auto` skips the ephemeral range) |
| 16 | app on `127.0.0.1:80` | not forwarded (pasta can't bind host port 80) |
| 17 | app on `[::1]:3002` only | no answer on `ADDR:3002`; pasta still opens the host socket |
| 18 | auto latency: 2 full runs x 6 listeners, host polled every ~30 ms, `ss` + curl | latest run: answers 0.35–1.02 s after bind. Last observed socket was −0.01–0.82 s relative to close; polling brackets removal and does not measure the exact instant |
| 19 | port list changed on a running pod: `{9222,5432}` -> `+6379`, app on `0.0.0.0:6379` and `127.0.0.1:6380` | the old append-only iptables rules leak newly excluded 6379; with the new rules, 6379 answers before the change and closes after it; 6380 still redirects |
| 20 | 10 atomic re-applies with a different list each time, polled 974 times (2 before, 353 during, 619 after replacement; all positive controls answered) (pod with only the nft layer, `5432` on `0.0.0.0`) | no 5432 responses observed; finite polling cannot prove a transient never occurred |
| 21 | verify: applied `{9222,5432}` vs expected 3 ports; empty ruleset; wrong pod address in the pasta check | all detected (read-back compared with what `nft` prints for the same script in a throwaway netns) |
| 22 | a list of 20 ports | applies and verifies (nft sets handled 20 here; iptables `multiport` allows 15, **not tested**) |
| 23 | `pod restart` and `pod stop -t 1` + `start` (override present), each beginning with verified nft rules | each returns successfully, the app is back, pasta exclusions match, and the **nft table is gone** (listing succeeded). All three sensitive listeners answer inside the pod and are refused on the host, while a separate host control answers. Re-apply + verify restores forwarding. `pod restart -t 1` was rejected twice with `unknown shorthand flag: 't' in -t`; it did not test a restart. Earlier versions incorrectly logged it as successful |
| 24 | **Hand test:** container applying the same rules: `--cap-drop=ALL --cap-add=NET_ADMIN --security-opt=no-new-privileges`, alpine + `apk add nftables` | works; a container with **default caps** and one with `--cap-drop=ALL` are refused (`Operation not permitted`) |
| 25 | inside a pod, connect to another instance's address (pod a -> `127.0.1.202:3000`) | pod a's own app answers: the redirect applies to every connection to `127.0.1.0/24` |
| 26 | same, redirect restricted with `meta skuid 0` | pasta (uid 0 in the pod's user namespace) and root processes still redirected; a `--user 1000` client is refused instead of reaching itself |
| 27 | **Hand test:** host-network container holds `ADDR:14100` before the pod app starts | host traffic goes to the host process, silently |
| 28 | **Hand test:** host wildcard `0.0.0.0:14101` first | the host service answers; pasta can't bind |
| 29 | **Hand test:** pod forwards `14102`; host-network container binds `0.0.0.0:14102` and `[::]:14102` | both fail (`Address in use`); `127.0.0.1:14103` (not forwarded) binds fine |
| 30 | **Hand test:** explicit range `-t ADDR/1024-65535,~9222,~5432,auto` (to also forward ephemeral ports), host wildcard holds 14101 | `14150` stays closed although its server is up; 14100 and 5000 (lower) work. Plain `~…,auto` is not affected. **Don't use an explicit range.** |

## Conclusion

**Recommended configuration** (changes `oc-sandbox` pod creation around the current line 848):

- Create: `pm pod create … --network pasta --sysctl net.ipv4.ip_unprivileged_port_start=0 "${podargs[@]}"`
  (drop `--network pasta:--host-lo-to-ns-lo`).
- Per-instance override file in a host-trusted directory (`$STATE`, never under the sandbox home), written by
  the script: `[network]` / `pasta_options = ["--host-lo-to-ns-lo", "-t", "127.0.1.N/~9222,~5432,auto"]`.
  **Export `CONTAINERS_CONF_OVERRIDE` for every podman command of the instance** (`pm` wrapper), including
  `pod start`, `start`, `run --pod` and `pod restart`. A start without it forwards nothing (fail closed), but
  the instance is then silently unreachable, so check and report it.
- After every start or attach, apply and **verify** the nft table (above) and verify the pasta command line
  (find the pasta process by `--netns <SandboxKey of the infra container>`; compare the `-t` spec). On any
  mismatch: stop the pod and refuse to continue, with a clear message. Never run the agent against an unverified pod.
- Apply with `nsenter` and the host's `nft`: no image, no capability grant, nothing to pin. If a container is
  preferred anyway: `--cap-drop=ALL --cap-add=NET_ADMIN --security-opt=no-new-privileges` is enough (row 24),
  and the image must be digest-pinned and minimal (alpine + nftables), not `oc-agent` or a `:latest` tag.
- **Invariant, with a test:** sensitive sidecars (Chromium DevTools, Postgres) listen on `127.0.0.1` only.
  Chromium already does (`--remote-debugging-port` without an address). The official Postgres image listens on
  `*`; run it with `-c listen_addresses=127.0.0.1` (coordinate with [prd_a](prd_a.md)). The probe shows a
  `127.0.0.1` listener stays closed even with both layers missing (row 8), so this is the third wall.
- The excluded-port list lives in one place and feeds both layers. A change needs `pod stop` + `start`
  (pasta layer is fixed at start); the nft layer can be replaced live (row 19, 20).
- Do **not** add an explicit range (row 30). Ports 32768+ are not forwarded (document; `-P` stays for them).
- Allocate `N` from 2 to 254 (avoid 127.0.1.0, `.1`, `.255`: Debian maps `127.0.1.1` to the hostname).

**Remaining fail-open behaviour, stated plainly:**

- If **both** layers are absent or wrong (nft table lost on a pod restart *and* a pod started with a pasta
  spec that lacks the exclusions), a sensitive service listening on `0.0.0.0` or on `127.0.1.N` is reachable
  from the host, and it sees the connection as `127.0.0.1` (so `trust 127.0.0.1` rules apply). Row 8 shows it.
  Either layer alone is enough to keep 9222/5432 closed (rows 6, 7). The mitigation is not to prevent this
  state but to check both layers on every start and attach and refuse otherwise, plus the `127.0.0.1`-only invariant.
- The netfilter layer is lost whenever the pod's netns is recreated (`pod restart`, stop/start, reboot). It
  is not applied by Podman itself (an `--init-ctr always` container re-applied it unreliably in **hand tests**,
  2 of 3 runs lost it on `pod restart`). The script must do it, every time.
- A container with `NET_ADMIN` in the pod netns could remove the rules. Default-capability containers can't
  (row 24). Keep `NET_ADMIN` away from sidecars (re-check the docker-in-docker sidecar if it gets extra caps).

**Fallbacks** (reasoned, not probed): requiring apps to bind `0.0.0.0` (no extra layer; breaks "any dev
server", most default to loopback); an in-pod forwarder sidecar (no NET_ADMIN, but a daemon that re-implements
`auto`, 1-2 days); `route_localnet` + PREROUTING DNAT (same capability need, no gain).

**Risks and limits to document:**

- **Host port conflicts.** (a) Any local process that binds `ADDR:P` first receives that pod port's traffic,
  silently (row 27). (b) A host wildcard listener on `P` silently blocks forwarding of `P` (row 28). (c) While a
  pod forwards `P`, the host cannot bind `0.0.0.0:P` or `[::]:P` (row 29): an untrusted agent can deny host
  services that bind wildcard addresses at ports 1024-32767 by listening on those ports first (this host has
  `*:1716`, `*:3389`, `[::]:5355`). Loopback binds are unaffected. Decide whether to accept it or to block a
  list of host-service ports (pasta `~P`).
- **Every forwarded port is reachable by every local user** (no authentication at the forwarder), and the app
  sees `127.0.0.1`. Inferred from the design, not tested with a second user account.
- **Self-redirect (row 25):** inside a pod, a connection to another instance's name/address reaches the pod
  itself. See the item with [prd_d2](prd_d2.md): names of other instances must not resolve to `127.0.1.x`
  inside a pod. `meta skuid 0` (row 26) narrows it but not for root processes, so it is not a fix.
- Pasta also opens host sockets for excluded and `[::1]`-only ports? Excluded ports: no (row 5; pasta layer).
  `[::1]`-only apps: socket yes, forwarding no (row 17). The IPv4-only redirect means `[::1]` apps are not
  reachable; `::1` is a single host address, so there is no per-instance IPv6 loopback without root.
- Ports below 1024 can't be bound by pasta (row 16): the privileged forwarder item below.
- A connection made less than ~1 s after an app starts listening can be refused (row 18).
- Verified by the review, not re-tested here: other pods and bridge-network containers can't reach
  `127.0.1.N` (`--no-map-gw`); UDP is not forwarded (`-u none -U none`, row 11 shows no UDP sockets).
  Inferred, not tested beyond row 24: a root container with default capabilities can't flush the table.
- Podman 6.1.3 does not support `pod restart -t`; use a supported stop/start if a bounded stop is needed, and fail closed on any failed operation.
- Not tested: many pods at once, host reboot, kernels without nf_tables/`nft_redir`.

## Items

- [x] Stop poll workers before removing their resources (branch `spike-d1`): a private receipt and
      lock verify termination across native and distrobox forwarding; unknown or unowned job identities retain IDs, while a verified failed worker still permits resource cleanup.

- [x] Make the spike probe run on the host and in a distrobox (branch `spike-d1`): host routing and
      bounded prerequisite/inventory checks precede resource creation. A native-host `main` run recorded
      31 PASS / 0 FAIL. A devbox terminal run under `timeout` also recorded 31 PASS / 0 FAIL;
      batch host calls close stdin to avoid the distrobox PTY bridge hang. Routing and failure paths were
      checked with stubs and real controlling-PTY fixtures. Preflight checks the required operations
      directly; it no longer requires a full `podman info` query after two reported timeouts whose cause
      remains unknown.

- [x] Spike: investigate repeat global teardown when `oc_chromium` is absent at priority 400
      (branch `spike-d1`). The investigation identified the required behavior: check the module store
      first, report listing or removal failures, and retain state for retry. The production fix remains open.
- [ ] Apply and review the corresponding production teardown fix separately on
      `codex/selinux-teardown`; that branch is being prepared and is not yet merged into `main`.

- [x] Find a pasta option set that forwards **listening ports only** (`auto`) from `127.0.1.N`, for apps
      on `127.0.0.1` too (branch spike-d1): `--network pasta` + containers.conf `pasta_options`
      `-t ADDR/~9222,~5432,auto`, plus an in-pod nft `REDIRECT` of `127.0.1.0/24` to `127.0.0.1`.
- [x] Exclude 9222 (and 5432 unless [prd_a](prd_a.md) allows it) from automatic forwarding (branch
      spike-d1): in pasta (`~`) and again in the nft table; each alone is enough.
- [ ] Implement: allocate `127.0.1.N` (2-254) per instance under a lock in `$STATE`, store it in the pod
      label and `oc.podcfg`, recreate pods created without it.
- [ ] Implement: per-instance `CONTAINERS_CONF_OVERRIDE` file in a host-trusted directory, exported by `pm`
      for every podman call of the instance; report clearly if a pod was started without it.
- [ ] Implement `ensure_netfilter`: apply the nft table with `podman unshare nsenter` (no container), read
      back and compare, verify the pasta command line, on every start and attach; **refuse to run on mismatch**.
- [ ] Make "Chromium and Postgres bind `127.0.0.1` only" an enforced, tested invariant (Postgres
      `listen_addresses`), see [prd_a](prd_a.md).
- [ ] Tests in `tests/parallel.sh`: two pods, same internal port, each answers only on its own address,
      from a `127.0.0.1` app; 9222/5432 refused with a positive control; nothing on the LAN address; rules
      re-applied and verified after `pod stop` + `start`; mismatch is refused; list change on a running pod.
- [ ] Decide on host-port conflicts: accept and document, or exclude a list of host service ports with `~P`.
- [ ] With [prd_d2](prd_d2.md): inside a pod, other instances' names must not resolve to `127.0.1.x`
      (self-redirect), or the redirect must be limited to pasta's connections (only partly possible, row 26).
- [ ] Document: ports >= 32768 are not forwarded; `[::1]`-only apps are not reachable; every forwarded
      port is reachable by all local users and the app sees `127.0.0.1`; ~1 s before a new listener is forwarded.
- [ ] Privileged ports on the host (443/80) for portless `https://feat-a…`. **Decision (2026-11-15):
      a narrow host forwarder** that holds only `CAP_NET_BIND_SERVICE`, binds only instance addresses
      (`127.0.1.x`) on 80/443, never the LAN, and is installed once with an admin prompt. Options
      considered:
  - a one-time host sysctl `net.ipv4.ip_unprivileged_port_start=443`. Pros: simple. Cons: lets every
    local user bind 443–1023 on every address.
  - a host-side forwarder with `CAP_NET_BIND_SERVICE` bound only to `127.0.1.0/24`. Pros: narrow. Cons:
    a privileged component to maintain.
  - keep high ports (`https://feat-a…:8443`). Pros: no root. Cons: the URL needs a port.
