# Local compiled-profile walkthrough

[PRD L proof](../../prd_l.md#local-compiled-profile-proof) ·
[PRD M local job](../m/local/README.md)

Compile one checked-in interactive profile and prove that its service selection controls a real
disposable OpenCode job. The two supported variants are Postgres plus Chromium, and the same
profile with its Chromium bundle removed through the compiler. This proof does not install a
launcher, expose a service to the workstation, or accept user-supplied TOML or operations.
Direct CDP is intentional in the interactive shared-network fixture. Managed CDP isolation and
its job-scoped arbiter require separate verification.

## Plan and start

1. Load fixture documents from the trusted checkout using the existing strict TOML and kind
   validators. Use a private in-memory store over the read-only builtin catalog. The profile
   selects the builtin Postgres service and a headless bundle that directly selects managed
   Chromium. It specifies no published ports. The spike catalog replaces placeholder image
   references with the fixture's actual digest-pinned references before compilation. Accept only
   operator-selected full IDs of cached images. Compare each ID and inspected digest to its
   fixture pin and reject missing images, substitutions, or non-Linux/x86-64 targets. Never pull.
2. Compile each variant through `compile_plan`; show the plan digest and service names. Lower
   only the supported shape: local Podman, interactive tier, pod-shared topology, exact fixture base
   and service images, zero remote bindings/broker routes/raw mounts, no user environment
   overrides, one approved factory per selected service, and only expected pod-local endpoints
   on 5432/9222. Verify the immutable digest. Reject unsupported shapes before any Podman create.
   Lower only fixed fixture commands. Do not interpret plan exec commands, secret references,
   persistent volume requests, or user environment as executable configuration. The test
   substitutes tmpfs and synthetic credentials for fixture-declared durable service state.
3. Prepare the existing PRD M `Job` and fake model `Broker` in private devbox scratch and start
   the verified worker and relay. The worker starts in Podman network mode `none`, with its own
   loopback. Start the selected sidecars as network-only members of that namespace
   (`--network=container:<exact worker ID>`). Retain separate PID/IPC/mount namespaces and
   distinct SELinux MCS labels. Retain the original relay's separate role and bind mounts.
   This models shared pod-local networking while retaining individual SELinux categories.
   The proof will use no Podman pod object or host port mapping.
4. Verify each exact container identity, image, name, label and effective namespace before
   accepting readiness. Inspect port bindings, image volume suppression, capabilities, mounts,
   memory/PID limits and SELinux labels. Use read-only roots with bounded tmpfs for data,
   bounded host calls, no default Podman mounts or environment passthrough, no host sockets
   in the sidecars, and no desktop session or browser profile. Run both as unprivileged
   container UIDs with dropped caps and `no-new-privileges`. Postgres uses loopback,
   SCRAM and a fresh private password file available only in its own container. Headless
   Chromium uses Podman confinement with Chromium's same `--no-sandbox` policy as the existing
   container, disposable state, no external network interface, and a loopback-only CDP listener.
   Forwarding, remote CDP access and persistent state require separate designs.

## Observe and clean up

1. Compare the worker, relay and service network namespace IDs with the host ID; verify only
   loopback is present. Test CDP from the existing relay container with a bounded, local
   `/json/version` request and verify the intended Chromium response shape. Test Postgres with
   a TCP `SELECT 1` and a rejected authentication attempt from its own container inside that
   same namespace. Use the verified namespace membership as evidence that the OpenCode worker
   has the same network reachability. In the Postgres-only run, require port 9222 to refuse a
   connection and require the Chromium sidecar to be absent from the run inventory.
2. Reuse the existing OpenCode proof for a synthetic response, exact scratch-file write and
   job grant revocation. Verify no stale grant can admit a new model call.
3. Record names and an unguessable run label before create, then an immutable ID receipt before
   start. Record sidecar resources separately from the existing worker/relay ledger. On failure
   or interruption, close the broker and remove sidecars before their network namespace owner.
   Reconfirm exact ID/name/label before removing by ID, then verify exact ID absence and the
   full label-scoped inventory. Retain a private receipt and report unconfirmed cleanup on lost
   acknowledgment or failed inspection. Never remove by a mutable tag, guessed ID, or prefix.

## Verification

- Run offline tests for image and unsupported-plan denial, exact optional bundle omission,
  fixed command lowering, and cleanup for a partial startup or uncertain create.
- Run both variants in devbox using cached, pinned images, rootless Podman and SELinux
  enforcing. Record the plan digest, selected services, port and namespace evidence,
  application proof and cleanup summary without logging credentials.
- Run the repository's real Podman security and isolated parallel tests. Record any
  environment prerequisite that prevents a required check from running.
