# prd_e1: Name-constrained CA and trust installation

Parent: [prd_e](prd_e.md)

**Decision (2026-11-15):** a dedicated CA created with OpenSSL, name-constrained to
`.oc-sandbox.internal`. mkcert (pinned via mise, [prd_f](prd_f.md)) installs trust and issues leaves
from that CAROOT. Rejected: a separate unconstrained mkcert CA, and reusing api-agent's mkcert CA.
Note for testing: a few older clients ignore name constraints; list the ones found.

**Spike result (2026-11-15, branch `spike-e1`):** all 9 clients tested (12 test paths) enforce the name
constraint, including against two key-holder attacks (a re-issued CA twin and an unconstrained intermediate).
The profile has traps, all measured: the bare name needs its own entry, IP SANs are unconstrained unless
the CA says otherwise, and a CA that permits `localhost` also lets a leaked key impersonate every `*.localhost` and `127.x`
HTTPS service on the host. **Recommended CA: variant E (instance names only, all IPs excluded); fallback
D.** Probe: [`spikes/e1/probe.sh`](spikes/e1/probe.sh). Raw matrix: [`spikes/e1/results.txt`](spikes/e1/results.txt).

## Spike: name-constraint enforcement

### Setup

- Seven CAs made with host OpenSSL 4.0.3: EC P-256, critical `basicConstraints CA:TRUE,pathlen:0`, critical
  `keyUsage keyCertSign,cRLSign`, SKI, 3650 days, and (except X) a critical `nameConstraints`:

| CA | `nameConstraints` |
|---|---|
| A | `permitted;DNS:.oc-sandbox.internal` |
| B | A + `permitted;DNS:oc-sandbox.internal` |
| C | B + `permitted;IP:127.0.0.0/255.0.0.0` + `permitted;IP:0:0:0:0:0:0:0:1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff` (`::1` only) |
| D | C + `permitted;DNS:localhost` |
| E | A's and B's two DNS entries + `excluded;IP:0.0.0.0/0.0.0.0` + `excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0` (instance names only, every IP denied) |
| F | `permitted;DNS:oc-sandbox.internal` only (tests whether the bare entry alone also covers subdomains) |
| X | none (control: checks the same leaves without name constraints) |

  The IPv6 entries use the full-mask form; OpenSSL 3.5 rejects the short `::1/128` form.
- 27 leaves for each CA (EC P-256, 30 days, serverAuth), signed with the CA key (that is what "a leaked CA
  key" means). Templates: [`ca.cnf`](spikes/e1/ca.cnf), [`leaf.cnf`](spikes/e1/leaf.cnf); leaves:
  [`leaves.tsv`](spikes/e1/leaves.tsv). Attack leaves: (a) the CA key re-issues a **twin** of the CA (same key
  and subject, no constraints) that the server sends as an intermediate; (b) the CA key signs an
  **unconstrained intermediate** with another subject, which signs the leaf (once for `evil.example.com`, once
  for an in-constraint name, to show that `pathlen:0` alone stops it).
- One `openssl s_server -www` per CA × leaf (189 servers) in a podman pod with `--network none`: nothing
  leaves the host. `8.8.8.8` and `2001:db8::1` are loopback aliases inside the pod's private network
  namespace, so clients really connect to those addresses (`::ffff:8.8.8.8` reaches the IPv4 alias). All test
  names resolve to loopback through a mounted `/etc/hosts`. Each client connects to the leaf's own name (IP
  leaves: to the IP) with the CA as its only extra trust anchor, so hostname and constraints are both
  checked. `openssl verify` runs offline.
- Trust stores were scratch only: `-CAfile`/`--cacert`, `NODE_EXTRA_CA_CERTS`, a Go `CertPool`,
  `sslrootcert`, and a throwaway NSS db inside the Chromium container (`certutil -A -t "C,,"`).
  Host trust stores and `~/.pki/nssdb` were not touched.
- The probe refuses to report a result unless: every client produced a row for every CA × leaf, every
  rejection has recognized per-client certificate verification evidence, and the control CA X behaves as
  expected (plain leaves and the CA-twin chain accepted, the unconstrained intermediate rejected by
  `pathlen:0`; the only exceptions are CN-only leaves in Go and Chromium and the IPv4-mapped IPv6 SAN in Go,
  see below). The exit status is 1 otherwise. Setup steps (every `openssl` call, the server fleet: 189 of
  189 listening, the NSS imports) are checked explicitly.
- Cleanup scope: scratch is one `mktemp -d` directory under `.scratch/` (removed only if it is that exact,
  non-symlink path); Podman pods and containers use per-run `oc-spike-e1-*` names. Built images are untagged to avoid
  overwriting a shared tag; their ownership labels carry the run identifier. Cleanup uses Podman-created
  immutable ID receipts and verifies the label before removing a resource. Public base images are retained, including images downloaded during a run.

After the cleanup and validator review fixes, a real `--skip-chromium --skip-go --skip-pg` rerun
covered 1,512 cells (728 accepted, 784 rejected) across eight paths, with all checks passing. Offline
regressions cover the other clients’ recorded error forms, unknown TLS errors, relative template paths,
and simulated failed creation, name replacement, untagged image builds and cleanup. This rerun did not retest Go, PostgreSQL, Chromium or NSS.

After the row-setup review fixes, a targeted real PostgreSQL 17.10 and NSS 3.133.0 run tested variants
A and X with four leaves each: permitted, disallowed, CA-twin attack and unconstrained-intermediate
attack. Each path returned 4 accepts and 4 rejects, with X accepting the twin and rejecting the
intermediate. PostgreSQL checked the fingerprint served after every successful restart; NSS checked
the imported CA, leaf and required chain fingerprints. This was a 16-cell subset, not a full rerun.
A separate eight-server run tested host and Alpine OpenSSL verification across the same subset
(32 cells, 16 accepts and 16 rejects); the matrix checks passed. Stubbed regressions also confirm
restart and chain-import failures cannot emit a result cell.

### Clients and versions

9 clients, 12 test paths:

| Short | Client | Version |
|---|---|---|
| Hvfy, Hvfy+h | `openssl verify` (chain only; with `-verify_hostname`/`-verify_ip`), host | OpenSSL 4.0.3 |
| Avfy, Avfy+h | same, in `alpine:3.22` | OpenSSL 3.5.9 |
| s_cli | `openssl s_client -verify_return_error -verify_hostname/-verify_ip` against `s_server` | OpenSSL 3.5.9 |
| curl | `curl --cacert`, Alpine | 8.14.1 (OpenSSL 3.5.9) |
| py | Python `ssl.create_default_context(cafile=…)`, `python:3.12-alpine` | 3.12.13, OpenSSL 3.5.7 |
| node | `tls.connect` with `NODE_EXTRA_CA_CERTS`, `node:24-alpine` | v24.22.3, OpenSSL 3.5.9 |
| go | `crypto/tls` with `RootCAs`, `golang:alpine` | go1.27.4 |
| psql | `sslmode=verify-full sslrootcert=…`, `postgres:17` (server restarted per leaf, key 0600 owned by postgres) | psql 17.10 |
| chrom | headless Chromium `--dump-dom`, scratch NSS db, Fedora 45 image built from the public Fedora base (now untagged with a run ownership label) | 157.0.8103.78 |
| nss | `certutil -V -u V` (classic NSS verifier, chain only; **not** Firefox's mozilla::pkix) | nss-tools 3.133.0 |

### Host browser subset (2026-11-16)

The user tested the installed Flatpak browsers on the host, each in a separate throwaway profile with
private HOME/XDG directories and the E and X public CA certificates trusted in that profile. A local
CONNECT proxy routed the test hostnames to six separate loopback TLS endpoints; the browsers used the
actual hostname or IP in the URL. Both CA fingerprints were checked by the user. For each accepted
case, the user confirmed the browser's secure state and the per-run response marker. These observations
are user-reported; they cover six cells per browser, not the full 2,268-result matrix (189 CA/leaf
combinations across 12 verification paths):

| CA and leaf | Firefox 160.0, build 20261104181552 | Chrome 157.0.8103.78 |
|---|---|---|
| E / `feat-a.oc-sandbox.internal` | secure, exact marker | secure, exact marker |
| E / `evil.example.com` | `SEC_ERROR_CERT_NOT_IN_NAME_SPACE` | `net::ERR_CERT_INVALID` |
| E / `127.0.0.1` | `SEC_ERROR_CERT_NOT_IN_NAME_SPACE` | `net::ERR_CERT_INVALID` |
| X / `feat-a.oc-sandbox.internal` | secure, exact marker | secure, exact marker |
| X / `evil.example.com` | secure, exact marker | secure, exact marker |
| X / `127.0.0.1` | secure, exact marker | secure, exact marker |

The observed Firefox marker was `f511ffabf16ecb85b276961e`; the Chrome marker was
`46bdfc29cd594fc09f332fcd`. The user confirmed the SHA-256 fingerprints for E
(`9c565f7458dc2468981ea2103fa3511501c708b8c567c23971f6cdcb2b90c005`) and X
(`5d26e7e59e5d96dacbdb44c187511a6143cec7619359d22e4b325b4508ae9b01`) in both browsers.

The paired X controls show that both browsers could connect to the corresponding unconstrained leaves,
while E rejected the forbidden DNS name and IP. This is consistent with E's name constraints being
applied; Chrome's generic `ERR_CERT_INVALID` alone does not establish the exact internal cause. Its
[error definitions](https://raw.githubusercontent.com/chromium/chromium/157.0.8103.78/net/base/net_error_list.h)
distinguish this generic error from a name-constraint-specific error. Chrome 157's
[path-builder mapping](https://raw.githubusercontent.com/chromium/chromium/157.0.8103.78/net/cert/cert_verify_proc_builtin.cc)
and [status mapping](https://raw.githubusercontent.com/chromium/chromium/157.0.8103.78/net/cert/cert_status_flags.cc)
provide context; they do not prove which internal path produced this GUI error.

Only the throwaway browser profiles were used for these imports; no host system trust installation was
performed. The checked real certificate-store and certificate-setting files were unchanged. One unrelated
real Chrome preferences file changed during the Chrome observation; the certificate-related subset did
not. These file snapshots do not establish that every possible host store or setting was unchanged.
The test profiles and their two specifically identified Chrome document-portal exports were removed;
the loopback listeners were closed. See the [host-browser walkthrough](spikes/e1/HOST-BROWSERS.md).

- [x] Make the offline Chrome portal repair regression use only disposable synthetic inputs and
  cover exact mounts, atomic launcher replacement, and refusal cases (`codex/offline-portal-regression`).

### Results

Cell: `all` = accepted by all 12 paths, `none` = rejected by all, otherwise the exceptions or the accepting
paths. X is the control (no constraint).

| Leaf | A | B | C | D | E | F | X |
|---|---|---|---|---|---|---|---|
| `feat-a.oc-sandbox.internal` | all | all | all | all | all | all | all |
| `oc-sandbox.internal` (bare) | none | all | all | all | all | all | all |
| `*.oc-sandbox.internal` (checked as `foo.…`) | all | all | all | all | all | all | all |
| `evil.example.com` | none | none | none | none | none | none | all |
| `feat-a…` + `example.com` | none | none | none | none | none | none | all |
| CN-only `CN=example.com`, no SAN | none | none | none | none | none | none | all but chrom,go |
| IP `127.0.0.1`, `CN=127.0.0.1` | only chrom,go,nss | only chrom,go,nss | only chrom,go,nss | only chrom,go,nss | none | only chrom,go,nss | all |
| IP `8.8.8.8`, `CN=8.8.8.8` | only chrom,go,nss | only chrom,go,nss | none | none | none | only chrom,go,nss | all |
| IP `127.0.0.1`, `CN=feat-a…` | all | all | all | all | none | all | all |
| IP `8.8.8.8`, `CN=feat-a…` | all | all | none | none | none | all | all |
| IP `127.0.0.1`, no CN | all | all | all | all | none | all | all |
| IP `8.8.8.8`, no CN | all | all | none | none | none | all | all |
| DNS `feat-a…`, `CN=example.com` | all | all | all | all | all | all | all |
| `a.b.oc-sandbox.internal` | all | all | all | all | all | all | all |
| `evil-oc-sandbox.internal` | none | none | none | none | none | none | all |
| `localhost` | none | none | none | all | none | none | all |
| prd_e2 plan: `feat-a…` + `localhost` + `127.0.0.1` | none | none | none | all | none | none | all |
| same + `::1` | none | none | none | all | none | none | all |
| same, bare `oc-sandbox.internal` | none | none | none | all | none | none | all |
| `app.localhost` | none | none | none | all | none | none | all |
| IP `127.0.0.2`, no CN | all | all | all | all | none | all | all |
| IP `::1`, no CN | all | all | all | all | none | all | all |
| IP `2001:db8::1`, no CN | all | all | none | none | none | all | all |
| IP `::ffff:8.8.8.8`, no CN | all but go | all but go | none | none | none | all but go | all but go |
| attack (a): CA twin as intermediate, `evil.example.com` | none | none | none | none | none | none | all |
| attack (b): unconstrained intermediate, `evil.example.com` | none | none | none | none | none | none | none |
| attack (b): unconstrained intermediate, in-constraint name | none | none | none | none | none | none | none |

Attack results (rows `attack (a)` and `attack (b)`), all 12 paths, all CAs A to F: **rejected**. Under X
(control, `pathlen:0` only), (a) is accepted (a self-issued twin adds no power without a constraint to lift) and
(b) is rejected by every path, so `pathlen:0` alone stops an unconstrained intermediate, even for an
in-constraint name. Confirmed per client: OpenSSL (4.0.3 and 3.5.9 `verify`, `s_client`), curl, Python and
Node name the cause (a: `permitted subtree violation`; b: `path length constraint exceeded`, or the name
violation first for `evil.example.com`); Go says `not authorized to sign for this name … not permitted by any
constraint` for (a) and `too many intermediates for path length constraint` for (b). Chromium
(`ERR_CERT_INVALID`), psql (`certificate verify failed`) and NSS reject without naming the cause. The NSS
result for (a) says `issuer has been marked as not trusted by the user`, which is probably a side effect of
importing the twin (same subject and key as the root) into the scratch db, so it is **not** independent
confirmation for NSS; Chromium's own verifier is the NSS-adjacent evidence.

Do the error messages name the cause? Rejections under A to F, total / message names a name constraint
or path length: OpenSSL family (Hvfy, Hvfy+h, Avfy, Avfy+h, s_cli, curl, py, node): yes (96 / 86 each; the other 10
are `excluded subtree violation` under E, which also names the constraint, and node's `UNSPECIFIED`
prefix). Go: names it in most rows (the others are CN-only, SAN-parse and IP-constraint messages). **Chromium,
psql and NSS do not name the cause**: Chromium reports `net::ERR_CERT_INVALID` (and `ERR_CERT_COMMON_NAME_INVALID`
for the CN-only leaf), psql `SSL error: certificate verify failed`, and NSS `Peer's Certificate issuer is not
recognized` in most rows (`not permitted to issue a certificate with this name` only for CN-only leaves). For those three the
rejection is consistent with constraint enforcement when the unconstrained control CA X accepts the same
leaves in the same run; the message and separate control endpoint do not prove the exact cause of each rejection. Raw lists:
[`results.txt`](spikes/e1/results.txt).

### Conclusion (findings)

1. **All 9 clients (12 paths) enforce `nameConstraints`**, including Chromium 157, Go and the OpenSSL
   family (OpenSSL 3.5/4.0, curl, Python, Node, libpq). A leaf for `evil.example.com` or a mixed-SAN leaf is
   rejected by every path when signed by A, B, C, D, E or F, and accepted by every path under the
   unconstrained control X. No matrix client was found that ignores the constraint. Firefox was not
   part of this full matrix; its six-case E/X host subset is reported above. Safari, Java, Windows,
   curl with a non-OpenSSL backend and busybox `wget` were not tested.
2. **`.oc-sandbox.internal` alone does not cover the bare name `oc-sandbox.internal`** in any path (A).
   A constraint **without** the leading dot covers the name itself **and its subdomains** (RFC 5280): CA F
   (`permitted;DNS:oc-sandbox.internal` only) accepts `oc-sandbox.internal`, `feat-a…`, `a.b…` and the
   wildcard in all 12 paths, and still rejects `evil-oc-sandbox.internal`. So the dotted entry is redundant
   in these clients; keep both entries (B) for compatibility with verifiers that read the dot literally
   (not tested beyond these clients).
3. **With no IP constraint (A, B, F), every IP SAN is accepted**: `8.8.8.8` and `2001:db8::1` by all paths,
   `::ffff:8.8.8.8` by all but Go (Go refuses to parse a certificate with an IPv4-mapped IPv6 SAN,
   `SAN iPAddress contains IPv4-mapped IPv6 address`, with any CA, including X). A leaked key could then
   impersonate any IP-literal site. With a permitted IP list (C, D) `8.8.8.8`, `2001:db8::1` and
   `::ffff:8.8.8.8` are rejected, while `127.0.0.1`, `127.0.0.2` and `::1` are accepted: both address
   families are enforced on their own merit. E (excluded all-IPv4 and all-IPv6 subtrees) rejects every IP
   SAN including `127.0.0.1` and `::1`. DNS constraints alone also leave email, URI and directoryName names
   unconstrained; none is used for TLS server verification (not tested further).
4. **Variant D is much wider than `localhost` itself.** A DNS constraint without a leading dot also matches
   subdomains, and the CA accepts `app.localhost` under D in all 12 paths (measured), plus `127.0.0.2`
   (inside the permitted `127.0.0.0/8`) and `::1`. Browsers and systemd-resolved send `*.localhost` to
   loopback (known behaviour, not re-tested here). Inference: with D trusted on the host (system store, NSS,
   Firefox), a leaked key can impersonate **every HTTPS service on host loopback** (`localhost`, any
   `*.localhost`, any `127.x.y.z`), including the user's other dev projects, and taking over a loopback port needs
   only an unprivileged local process. C has the same reach for IP-literal URLs (`https://127.0.0.1:PORT`)
   but not for `localhost` names. Only E removes loopback.
5. **prd_e2's SAN plan** (`feat-a…` + `localhost` + `127.0.0.1`) is accepted only under D. Under A, B, C, E
   and F every client rejects the whole certificate, not only the `localhost` name (the constraint applies to
   every SAN).
6. **The subject CN matters to the OpenSSL family.** OpenSSL, curl, Python, Node and libpq check a hostname-like
   `CN` against the DNS constraints. A leaf with `IP:127.0.0.1` and `CN=127.0.0.1` is **rejected** by them under
   every constrained CA, but accepted by Go, Chromium and NSS (they ignore CN) wherever the IP is allowed.
   Safe subjects: no CN, or `CN=` the primary DNS name. A foreign CN next to a DNS SAN
   (`CN=example.com` + `DNS:feat-a…`) is accepted everywhere, so the CN is only checked when no DNS SAN exists.
   CN-only leaves (no SAN) are rejected by all paths under A to F (by the constraint for the OpenSSL
   family, by "no SAN / CN not supported" for Go and Chromium even without a constraint).
7. **Key-holder attacks.** The CA-twin chain (a) and the unconstrained intermediate (b) are rejected by every path;
   `pathlen:0` stops (b) by itself and the constraint stops (a) and the names of (b). See above for which
   clients name the cause.
8. **Error messages from Chromium, psql and NSS do not name the cause** (see above); the attribution rests on
   the control CA.
9. Chromium reads the scratch NSS db at `$HOME/.pki/nssdb`; with the CA imported as `C,,` it accepted
   in-constraint leaves and rejected the others at navigation time (`--dump-dom` printed the page or
   `Page load failed: net::ERR_*`).
10. **Why no `excluded` subtree is needed for names:** once a type has a `permitted` list, every name of that
    type outside it is denied, so `excluded;DNS:localhost` would add nothing (and `localhost` is not in the
    narrow DNS list anyway). The only case where `excluded` is useful is a type with **no** permitted list:
    IP addresses under an instance-names-only CA, which is variant E.

## Recommended profiles

### CA (create once; host-only; key 0600)

**Recommended: variant E** (instance names only; every IP SAN denied) with prd_e2 dropping the `localhost`,
`127.0.0.1` and `::1` SANs. In pods the instance name already maps to `127.0.0.1` through `--add-host`, so
tools use `https://feat-a.oc-sandbox.internal:PORT`. **Fallback: D** (keeps prd_e2 as it is) with the
loopback risk in finding 4. C is not recommended: it keeps the `127.0.0.0/8` impersonation reach. Never A, B or F: they leave IP SANs
unconstrained. Changing the constraints later means a new CA and a new trust installation (admin prompt on the host), so decide
before the first `-i`.

`ca.cnf` and `leaf.cnf` (verbatim; `OC_NC` and `OC_SAN` come from the environment):

```ini
# CA profile for the oc-sandbox local CA (spike e1).
# Name constraints come from the environment so one file serves every variant:
#   OC_NC="permitted;DNS:.oc-sandbox.internal,permitted;DNS:oc-sandbox.internal"
# Use section v3_ca_unconstrained only for the control CA.
[ req ]
distinguished_name = dn
prompt             = no
[ dn ]
O  = oc-sandbox
CN = oc-sandbox local CA
[ v3_ca ]
basicConstraints       = critical,CA:TRUE,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
nameConstraints        = critical,$ENV::OC_NC
[ v3_ca_unconstrained ]
basicConstraints       = critical,CA:TRUE,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
# Attack (b): what a key holder would sign to get around pathlen:0 and the constraints.
[ v3_intermediate_unconstrained ]
basicConstraints       = critical,CA:TRUE
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
```

```ini
# Leaf profile for a per-instance server certificate (spike e1).
# OC_SAN is a comma separated list such as
#   "DNS:feat-a.oc-sandbox.internal,DNS:localhost,IP:127.0.0.1"
# Section v3_leaf_nosan exists only to test a CN-only certificate.
[ v3_leaf ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
subjectAltName         = $ENV::OC_SAN
[ v3_leaf_nosan ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
```

`recommended.sh` (verbatim; [`probe.sh`](spikes/e1/probe.sh) runs this exact file for variants D and E and checks
the leaf with `openssl verify -verify_hostname`):

```bash
#!/usr/bin/env bash
# The recommended CA and one leaf, exactly as quoted in prd_e1.md (probe.sh runs this file).
# usage: recommended.sh OUTDIR TEMPLATE_DIR NAME NC SAN
#   NC  = nameConstraints value, e.g. "permitted;DNS:.oc-sandbox.internal,permitted;DNS:oc-sandbox.internal,..."
#   SAN = subjectAltName value, e.g. "DNS:feat-a.oc-sandbox.internal"
set -euo pipefail
out=$1 tmpl=$(cd "$2" && pwd -P) name=$3
export OC_NC=$4 OC_SAN=$5
mkdir -p "$out" && cd "$out"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key && chmod 600 ca.key
openssl req -x509 -new -key ca.key -config "$tmpl/ca.cnf" -extensions v3_ca -days 3650 -sha256 -out ca.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem && chmod 600 key.pem
openssl req -new -key key.pem -subj "/CN=$name" -out req.pem
openssl x509 -req -in req.pem -CA ca.pem -CAkey ca.key -CAserial serial -CAcreateserial \
  -extfile "$tmpl/leaf.cnf" -extensions v3_leaf -days 30 -sha256 -out cert.pem
```

Values (copied from [`variants.tsv`](spikes/e1/variants.tsv)):

```bash
# E (recommended). Leaf SAN: DNS:NAME only
NC='permitted;DNS:.oc-sandbox.internal,permitted;DNS:oc-sandbox.internal,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0'
./recommended.sh out . feat-a.oc-sandbox.internal "$NC" 'DNS:feat-a.oc-sandbox.internal'
# D (fallback). Leaf SAN as in prd_e2
NC='permitted;DNS:.oc-sandbox.internal,permitted;DNS:oc-sandbox.internal,permitted;IP:127.0.0.0/255.0.0.0,permitted;IP:0:0:0:0:0:0:0:1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,permitted;DNS:localhost'
./recommended.sh out . feat-a.oc-sandbox.internal "$NC" 'DNS:feat-a.oc-sandbox.internal,DNS:localhost,IP:127.0.0.1,IP:::1'
```

If the suffix changes (prd_d2), change the first two entries and keep both the dotted and the bare form.

Rules the probes support: EC P-256; `CN` = the primary DNS name (never an IP; `localhost` only under D); every
SAN inside the constraints; `serverAuth` only; `CA:FALSE`; short validity (30 days). Wildcards are accepted
by all clients but not needed. The host script should issue leaves directly with OpenSSL (it knows the profile, and
`mkcert` is then only needed for `-install`, if at all; see the open item on mkcert).

### Risk statement for the PRD

- In the 12-path matrix, a leaf for `evil.example.com` signed with the CA key and both the CA-twin and
  unconstrained-intermediate attacks were rejected by OpenSSL 3.5/4.0, curl, Python, Node, libpq, Go,
  Chromium 157 and NSS `certutil`. No matrix client was found to ignore these constraints. The smaller
  host-browser subset above did not test the two attack chains.
- **Not verified:** the full matrix, variant D, or the key-holder attack chains in the real host browsers;
  Safari/macOS, Windows, Java, and curl or wget built with a non-OpenSSL TLS library also remain untested.
  The Firefox and Chrome host observations above cover only E and X with three leaves each, in private
  profiles. Chrome, psql and NSS give errors that do not name the constraint; their results rely on controls
  and do not prove the exact cause of each rejection.
- **Residual power of a leaked key under D** (measured: these are accepted): any name under
  `.oc-sandbox.internal`, `localhost`, `*.localhost` (`app.localhost`), any `127.0.0.0/8` address and `::1`.
  Inference: that lets the holder impersonate every HTTPS service on host loopback to any browser or tool that
  trusts the CA, including unrelated dev projects, and a local unprivileged process can take over a free
  loopback port. C leaves the IP-literal part. **E leaves only `.oc-sandbox.internal` names.** Under A, B or F
  (DNS only) any IP address would be accepted (measured for `8.8.8.8` and `2001:db8::1`): don't use them.
- Name constraints don't stop misuse of the permitted names: a leaked key still mints valid certificates
  for `*.oc-sandbox.internal`. The key must stay host-only and 0600.
- Clients that look at the CN (the OpenSSL family) reject a leaf whose CN is an IP or an out-of-subtree
  name even when its SANs are fine. Use the leaf profile above.
- The constraint check is done by the client's verifier; a client given `--insecure`/`-k` or a pinned
  leaf (no chain validation) does not check anything.

## Items

- [ ] Create the CA once with OpenSSL in `~/.local/share/oc-sandbox/ca/` (host-only, trusted path,
      key 0600) with the **measured profile** above (`recommended.sh`): EC P-256, critical `basicConstraints
      CA:TRUE,pathlen:0`, critical `keyUsage keyCertSign,cRLSign`, critical `nameConstraints` listing
      `.<suffix>` **and** the bare `<suffix>`, and, for variant E, `excluded` all-IPv4 and all-IPv6 subtrees
      (without an IP constraint any IP SAN is accepted). Variant D only if the decision below picks it.
- [ ] Host trust: determine and implement installation and removal for the system store (`trust anchor`,
      which needs an admin prompt), Firefox profiles, and the applicable Chrome user trust locations.
      [Chromium's Linux documentation](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md)
      says M146 and later use `~/.local/share/pki/nssdb` by default, but use the legacy `~/.pki/nssdb`
      when it already exists. The tested Chrome GUI imports used the private profile's
      `ServerCertificate` database. Verify the applicable paths and behavior before choosing
      `CAROOT=… mkcert -install` or equivalent direct steps; the private-profile subset did not verify
      system-store or installer behavior.
- [ ] Pod trust: mount the CA **certificate** (never the key) read-only into the agent (system bundle
      and `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`) and into the pod's Chromium NSS
      database.
- [ ] `-d -a` removes the CA from every store it was added to.
- [ ] Tests: a leaf for `evil.example.com` signed by the CA is rejected by OpenSSL verification (name
      constraint); the key is never visible inside a pod. Also assert from the spike matrix: a leaf for
      `8.8.8.8` and one for `2001:db8::1` are rejected, `oc-sandbox.internal` and `feat-a.oc-sandbox.internal`
      are accepted, a leaf with `IP:127.0.0.1` and `CN=127.0.0.1` is rejected by `openssl verify` (CN rule),
      the CA twin chain and an unconstrained intermediate are rejected, the CA PEM shows
      `Name Constraints: critical`.
- [x] Spike: name-constraint enforcement across clients (branch `spike-e1`; results and profiles above;
      probe in `docs/prds/spikes/e1/`).
- [ ] **(decision needed)** Which names may the CA vouch for? Options:

  | Option | Names the CA can vouch for | Pros | Cons | Time |
  |---|---|---|---|---|
  | **E (recommended)** | `*.oc-sandbox.internal` and the bare name only; every IP denied | smallest blast radius: a leaked key cannot touch loopback services or any IP-literal site | prd_e2 drops `localhost`/`127.0.0.1`/`::1` SANs; tools and examples must use the instance name (already `127.0.0.1` in pods via `--add-host`) | CA: same as D; prd_e2 and examples: about 2-3 hours |
  | C | instance names + all of `127.0.0.0/8` and `::1` | IP SANs for loopback possible | a leaked key can still impersonate `https://127.x.y.z:PORT` services on the host; saves little over E | about 1 hour |
  | D (fallback) | C + `localhost` and every `*.localhost` | prd_e2 unchanged; `localhost` URLs work in pods | a leaked key can impersonate every loopback HTTPS service, names and IPs (finding 4) | about 1 hour |

  The choice is fixed when the CA is created.
- [ ] **Correction for prd_e2** (cannot be edited from this branch): with E, issue the leaf with SAN
      `DNS:NAME` only, `CN=NAME`; drop `localhost` and `127.0.0.1` (the plan as written is accepted only
      by variant D; under A, B, C, E and F every client rejects the whole certificate). Leaf rules:
      `keyUsage digitalSignature`, `extendedKeyUsage serverAuth`, 30 days, EC P-256, never `CN=<IP>`
      (rejected by OpenSSL/curl/Python/Node/libpq).
- [ ] Issue leaves with OpenSSL from the host script using the leaf profile (rather than `mkcert`): mkcert
      leaf generation is untested here. If mkcert is kept for `-install`, test that it accepts an EC
      PKCS#8 `rootCA-key.pem` and that its leaves have no CN outside the constraints.
- [x] Verify on the real host: Firefox and Chrome in throwaway profiles rejected E's out-of-constraint
      DNS and IPv4 leaves, with E's in-constraint and all three X controls accepted (branch `spike-e1`;
      six-case subset and limits above).
- [ ] Add the probe's key assertions to `tests/` (needs only OpenSSL): the matrix cells for the chosen
      variant that the PRD relies on.
