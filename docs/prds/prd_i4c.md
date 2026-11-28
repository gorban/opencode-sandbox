# I4c: Verify initial Google Antigravity sign-in

Parent: [I4](prd_i4.md) · related: [provider setup contract](prd_i4d.md),
[worker credential isolation](prd_i3a.md)

Owner: **Codex**, within **Outside-in integrations**. Scope is the native Google account
sign-in for Antigravity ACP and reuse from a fresh dedicated workstation process. The existing
devbox login supported ACP v1 session creation with `agy` 1.5.13. An offline empty profile
negotiated ACP and asked for authentication. Dedicated profile enrollment remains open.

Prefer a rootless workstation supervisor for normal installation and use. Treat the workstation
operator and any same-UID devbox with unrestricted host command access as trusted in this
placement. Keep native provider state, keyring and ACP stdio outside the worker and relay. A
separate service UID is an optional hardened placement for operators who need to deny the
same-UID devbox access to the login. It requires deliberate one-time admin provisioning and a
qualified control interface. Routine provider actions run without sudo in either placement.

The offline workstation proof under dedicated UID 958 reopened a synthetic keyring credential
and returned the signed-out ACP verdict using `agy` 1.5.15. A separate rootless OpenCode and relay
test completed a synthetic text turn while both containers lacked access to a synthetic private
workstation file and socket. Enrollment and the brokered native route still need qualification.

The [synthetic ACP readiness probe](spikes/i4c/acp_readiness.py) exercises only `initialize` and
`session/new` with a bundled fake peer. It requires Linux with
`PIDFD_SIGNAL_PROCESS_GROUP` (upstream 6.9 or later). From the repository root, run
`python3 -B -m unittest discover -s docs/prds/spikes/i4c -v`. The test enrollment writes a private
credential record and a separate verifier record for the exact generation. The verifier binds the
issued synthetic credential and its expiry to that generation. Substituting another enrollment's
credential fails even when the profile still names the expected generation. The launcher and fresh
peer both check that the synthetic enrollment handle has closed. This models enrollment authority
with a file lock.
The peer reads the separate credential record. A missing record returns `DISCONNECTED`, synthetic
expiry returns `NEEDS_VERIFY`, and a mismatched or untrusted record gives an integrity error.
Readiness publishes only after the fresh peer retires and the new journal state is synced.
Unconfirmed retirement retains the private scratch and journal receipt with
`REVOCATION_UNCONFIRMED`, which blocks further probes and enrollment in that scratch. If a
crash restores a receipt whose eviction did not sync, it still blocks reuse. Malformed ACP
responses give protocol errors. The fixture uses a caller-created private scratch directory
beneath a trusted path. Actual native egress restrictions, private keyring restart, isolation of
the ordinary workstation login, and worker and relay denial require separate qualification.
Live text also requires build-specific evidence that native and provider-side tools are disabled
and that attempted calls are observable.

The [offline text proxy spike](spikes/i4c/text-proxy.md) extends the synthetic transcript through one
`session/prompt` from a pinned OpenCode orchestrator worker. It keeps ACP on the workstation and
holds text through terminal completion, evidence from the bundled peer and verified retirement.
The Gate 1 walkthrough cleared both reviews at SHA-256
`83f1d8bc608d496905382a47f4f63c788c0eae080bc27e29da5348a2bae5d839`.
The readiness-only check and production launch commands retain their existing scope.

- [x] Demonstrate one text-only OpenCode turn through the bundled ACP peer
  (`codex/antigravity-acp-text-proxy`). The pinned worker returned exact `ok` in devbox.
  The peer counted one prompt, replay was refused, and cleanup was verified. Offline controls
  observed zero prompts when revocation won before admission and zero answer bytes when
  the peer emitted early text or a callback.
- [ ] Qualify the pinned `agy` binary, rootless private provider home and keyring, bounded ACP
  channel, and separately scoped enrollment and execution egress. Verify the provider cannot
  access ordinary workstation credentials. Verify that the worker and relay get only the approved
  broker route and cannot read or invoke private provider resources.
- [ ] Before rootless enrollment, use the actual rootless launcher to reopen a synthetic keyring
  item after both bus and daemon restart, reach signed-out ACP with pinned `agy`, and check worker
  and relay denial with known-present workstation fixtures. Qualify same-UID devbox denial and
  sudo-free routine launches separately before offering the optional stronger placement.
- [ ] In the qualified placement, guide the operator through documented `agy acp --login`
  for personal Google OAuth. Use the native terminal or browser handoff without sharing browser
  state, codes or credential material with agents. Test unavailable binary, cancellation,
  expiration and denial of non-subscription fallback. Preserve the ordinary Antigravity login.
- [ ] From a fresh process in the same qualified placement, negotiate ACP and open a session
  in an empty scratch directory with no MCP servers. Verify only `initialize` and `session/new`
  were sent, zero tool grants, bounded redacted output and cleanup. A signed-out profile must
  request authentication. Keep identity, plan tier and billing unknown where unsupported.
- [ ] Record sign-in and reuse evidence. Review the exact route, host tool boundary, provider
  scope and first live prompt separately before enabling Antigravity in a managed worker.

[Antigravity ACP authentication](https://antigravity.google/docs/ide/extensions/acp/#authentication)

## Sealed offline cold-catalog fixture

The fixture exercises metadata enrollment and cold reopen with synthetic identities and the
exact standalone editor ACP 1.5.2 pair. The ordinary launcher remains unchanged.

- [x] Run the sealed offline catalog fixture from source tree
  `b29cb18440b3481338262133ebaaabde18d23968`. Verify three named catalogs, two Flash candidates,
  zero prompts, six native retirements, and an empty scoped native inventory. A separate root
  observer verified that all 65,966 ordinary-home metadata entries matched. The paired result
  SHA-256 is `e3e6b463d2d5877b05536e7b91a9ca601bceed324e227aa5173a75a9ef72c6e2`.

Prepare a disposable QEMU/KVM Fedora guest with SELinux enforcing, a dedicated
`oc-gemini-proof` account with no provider state, its working user systemd manager,
and the qualified guest Distrobox with `/usr/bin/host-spawn`, shared host PID and
network namespaces, and a shared owner-only `/run/user/UID`. Provide protected `/usr/bin/xdg-open` on the guest from the distro's
`xdg-utils` package. Allow space for at least three copies of the pinned artifact pair
and account for any retained failed fixtures. Pass no workstation filesystems or
services through to the guest. Restrict guest egress with this root-owned nftables table.

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

Grant the disposable account read-only inspection of that exact table. Validate the
sudoers entry using `visudo -cf`.

```sudoers
oc-gemini-proof ALL=(root) NOPASSWD: /usr/sbin/nft -j list table inet oc_gemini_fixture
```

Transfer the exact reviewed `source` archive and controller pair into the protected
guest capsule `/home/.oc-gemini-cold-proof`. Extract only the source inventory under
`source/`, and place the two controller files `google_home_controller.py` and
`controller-manifest.json` alongside it. Set all files to root ownership and 0444.
Use root-owned directories without group or other write access. Place both pinned
vendor artifacts at the reviewed `vendor/` paths as root-owned 0444 files. Require
canonical capsule paths and make the same protected projection visible to the devbox.
The capsule, including its source inventory, must be fresh.

Before running any fixture code as root, verify the protected controller file against the
independently reviewed controller hash. Use the separate reviewed manifest hash when
starting the controller. Both pins come from source review.

```sh
printf '%s  %s\n' REVIEWED_CONTROLLER_SHA256 /home/.oc-gemini-cold-proof/google_home_controller.py \
  | /usr/bin/sha256sum --strict --check - &&
  /usr/bin/python3 -IBS /home/.oc-gemini-cold-proof/google_home_controller.py REVIEWED_MANIFEST_SHA256
```

The controller verifies its protected bytes and every fixed source against that
reviewed manifest before loading driver code. It validates or creates the seal, checks
the named running rootless `oc-proof-devbox` container for the dedicated account,
starts one fixed interactive exec with the measured unprivileged supervisor in that
exact container. The supervisor waits at the first barrier while root records the
whole ordinary-home baseline. When root releases the start barrier, the supervisor
runs exactly one dedicated child with no stdin:
`/usr/bin/python3 -IBS /home/.oc-gemini-cold-proof/source/tests/google-connect-fixture.py --bound-catalog`.
The controller binds the dedicated UID and HOME and bounds the held session to
900 seconds. The supervisor waits for the actual child, caps captured output at
4 KiB, verifies no descendants or scoped native runtime remain, and then holds the
exec at the second barrier with the typed outcome.

The unprivileged fixture verifies the guest policy, boot, UID, source and root baseline
before enrollment. It checks the three ordinary provider paths are absent and uses a
separately sealed synthetic HOME for config, artifacts and enrollment. The controller
independently checks the exact positive output for all three named catalogs, two Flash
bindings, zero prompts, six retired native runtimes and an empty scoped native inventory.
Root repeats the whole-home metadata snapshot at that second barrier, before releasing
the exec. This puts Podman exec creation and release outside the observed interval,
which still includes the full persistent graphroot. The snapshot covers up to
131,072 entries and 64 levels without opening file contents or changing permissions.
Keep other account workloads stopped throughout. Root releases the exec only after
capturing the in-window snapshot, then requires the exact retirement acknowledgement,
end-of-stream and successful local client wait before persisting the paired result.
A local client timeout or exit alone establishes no guest retirement.

Keep the root-owned `home-before.json`, `native-result.json` and `home-result.json`
as one acceptance record. Acceptance requires the matching digests, exact positive
child evidence, exact transport retirement and equal before/after home fingerprints.
An ambiguous or incomplete run records after evidence as unavailable, distinct from a
checked mismatch. Either condition withholds acceptance. Preserve remaining private case paths for inspection and verify
native retirement before reprovisioning. A new run requires a fresh guest capsule
and case roots.

The native gate here covers the three named cases. The earlier native OIDC and LOAD
variant runners remain with their separately measured source trees. The portable
suites still cover OIDC, LOAD projection and their rejection paths.
