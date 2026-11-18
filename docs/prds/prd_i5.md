# prd_i5: Warm starts for local and remote workers

Parent: [prd_i](prd_i.md) · related: [worker fleet](prd_i2.md), [credential broker](prd_i3.md),
[worktree defaults](prd_c.md), [host mise tools](prd_f.md), [local shared setup](prd_h.md)

## Goal

Get a job to a usable checkout faster by reusing three independent inputs: the development image,
the Git objects and selected build artifacts. Each job gets its own writable checkout and home.
Several jobs on one worker can share an immutable image without repeating expensive installs.

## Images and restricted bootstrap

- [ ] Build a common OpenCode image from a pinned base digest. Add profile layers for declared OS
      packages and approved, locked mise tools. Store tools at a stable path outside the job home
      and checkout mounts. Resolve by platform and digest so local and remote workers can use the
      same recipe. Keep Git history and ordinary source edits separate from the image key.
- [ ] Publish reusable common and profile images to a configured OCI registry. Require a verified
      signature or signed attestation from a configured trusted builder. Bind the immutable image
      digest to the publisher identity, base digest, selected platform manifest, immutable recipe
      and profile revision, and exact input digests. Resolve the approved image from trusted policy
      and verify the match before use, including on a local hit. Reject substitution and rollback
      to an unapproved digest. Tags, registry metadata and image labels carry no authority.
- [ ] Let the worker helper request an optional, restricted bootstrap from a registered recipe.
      Use it to build a derived image on the worker on the first miss, then reuse that image for
      subsequent matching jobs. Use a persistent helper-owned lock per key and Podman store. Record
      the builder identity, attempt and exact IDs of temporary outputs. Verify the build inputs,
      result and smoke check before atomically promoting it. Record the same provenance fields in a
      helper-owned immutable receipt bound to the worker, store and output ID. Waiters and jobs
      after restart must verify the receipt, image and current grants before use. A local receipt
      proves origin only within its store. Require signed provenance before exporting the layer.
- [ ] On timeout, crash or restart, verify the prior builder is stopped before retrying. Clean up
      only its recorded temporary outputs by exact ID. Quarantine partial or ambiguous results.
      Fail closed on integrity, signature, provenance, authorization or revocation failures. For an
      ordinary miss or availability failure, permit only a fallback shown in the launch preview
      that uses the same locked inputs, source policy, scoped proxy or fetch adapter and credential
      boundary. Apply the same offline execution rules in the fallback. If no equivalent fallback
      is approved, leave the launch blocked.
- [ ] Support package ecosystems through explicit recipe adapters, starting with one workload where
      repeated setup is costly. Candidates include a PyPI wheelhouse, a NuGet restore layer, Cargo
      dependencies, or installed tools from mise. Where applicable, fetch verified packages or
      install the dependency set once and let each job use the resulting layer as a read-only seed.
      Keep writable caches and build outputs per job. Key native binaries and installed dependency
      sets on the base digest, platform and ABI, toolchain, locked inputs, recipe and required paths.
      A source-only edit should leave a dependency layer reusable when its inputs still match.
- [ ] Generate the build context from approved manifests and allowlisted inputs. A worker may
      propose new packages through profile review. First, fetch pinned packages into private,
      content-addressed staging using approved registries and redirect targets. Fetch adapters
      verify the content and execute no package or project code. Keep read credentials in the
      helper or scoped proxy. Then install and run hooks or builds in a bounded, isolated builder
      with the verified inputs mounted read-only, no network, no credentials, and no host home,
      live checkout mounts or engine socket. Keep credentials out of build args, diagnostics,
      contexts and every layer, including intermediate layers. If an adapter cannot split fetch
      from execution, keep that bootstrap recipe disabled. Build from declared inputs in a clean
      builder. Never publish a running parent's filesystem or copy arbitrary system directories.

See [mise lockfiles](https://mise.en.dev/dev-tools/mise-lock) and
[Podman build and layer cache](https://docs.podman.io/en/latest/markdown/podman-build.1.html).

## Repo and parent handoff

- [ ] Pin the starting commit in the launch request. Keep a helper-owned Git object cache per repo
      and authorization scope. Fetch missing objects from the approved remote. In a fresh checkout,
      copy only the reachable objects and refs covered by the job's grant. Keep the cache and its
      alternates outside the job, including read-only access. Verify the requested commit before
      launch.
- [ ] For a parent's unpushed commits, allow an authorized Git bundle containing the selected
      history. Quarantine Git objects and bundles. In a resource-bounded offline sandbox with a
      generated Git configuration, verify the sender, bundle prerequisites, object integrity and
      authorized reachable closure before promotion. Keep hooks, filters and fsmonitor disabled
      and prevent Git from loading host, parent or project configuration. Never use host Git on a
      sandbox checkout. For uncommitted work, show the operator the exact patch and selected files
      before transfer, and apply the path and file-type checks in [I2](prd_i2.md) before applying
      them in the sandbox. Exclude ignored files by default and keep auth files out of the handoff.
      Disable automatic submodule and Git LFS actions. Handle those as separately authorized fetches.
- [ ] Accept selected parent artifacts only after an explicit export with a manifest of digests,
      expected paths and compatibility inputs. Reuse them only when the job matches the producing
      platform, toolchain and build inputs. Use the bounded staging and safe export rules in
      [I2](prd_i2.md). Rebuild on mismatch.

See [Git bundles and prerequisites](https://git-scm.com/docs/git-bundle) and
[Git clone reference objects](https://git-scm.com/docs/git-clone).

## Credentials, placement and source selection

- [ ] Use short-lived or narrowly scoped, pull-only registry access in the worker helper and a
      separate publisher identity. Fetch Git with repo-specific read grants and private packages
      with registry-specific read grants under [I3](prd_i3.md). Give jobs only the data or scoped
      proxy access they need. A complete authorized bundle can seed a job without a remote Git
      credential. Keep private package layers, image caches and Git objects scoped to authorized
      jobs even when they contain no tokens. Check current grants before serving a warm hit. Expose
      only job-scoped availability to the orchestrator, without a raw inventory of worker caches.
- [ ] Authorize each transfer for the exact object or manifest digest, authenticated source and
      destination, job, scope and expiry. This covers workstation-to-worker, worker-to-worker and
      handoff between jobs on one worker. Validate both peers and grants at planning and at dispatch.
      Use a single-use capability bound to the authenticated transfer channel, verify the digest
      at the destination, terminate transfers on revocation, and discard incomplete data. A child
      job needs its own grants even when placed on its parent's worker.
- [ ] Keep manual worker selection first. For placement recommendations, filter candidate workers
      by authorization, data placement policy, platform and capacity before comparing estimated time
      to ready. Account for each destination's verified image, Git and artifact hits, queue time,
      missing bytes, checkout/install time and remaining rebuild. Compare origin fetches with the
      cost of a workstation or peer packing, transferring, verifying and restoring the data. Prefer
      the parent's worker when it is eligible and faster. Use origin for ordinary source and
      packages when it wins. Show the proposed worker, sources and authorized fallback in the launch
      preview. Replan and obtain fresh approval if a change alters the approved worker or transfer.

## Retention and revocation

- [ ] Record exact ownership, grants, size, expiry and active leases for images, package layers,
      Git object caches, staged transfers, bundles and artifacts. Enforce quotas per worker and
      scope. Clean up interrupted attempts and evict expired assets only after their last lease is
      released. Never delete another tool's assets. Retain ambiguous resources for inspection.
- [ ] On revocation, deny new reuse, reads and transfers, cancel active transfers and mark scoped
      assets for deletion once unused. Stop managed consumers when policy revokes ongoing access
      and the copy cannot otherwise be withdrawn. Track copies already delivered as disclosures.
      Require a fresh grant check for reuse after disconnect or restart. Clean up retained copies
      on reachable workers and reconcile cleanup on reconnect for offline workers.

## Priority and evidence

1. [ ] **Registry images and Git seeding** (estimated 3–5 days for a spike). Compare cold and warm
   launches locally and on SSH workers. Compare two starts on a warm remote, a child on its eligible
   parent's worker, workstation-to-cold-remote and warm-remote-to-cold-remote transfers, and a case
   where fetching from origin wins. Record time to usable checkout, network bytes and disk use.
   Confirm a source-only change reuses the image. Test refused source/destination grants, revocation
   during transfer and on a warm hit, out-of-scope Git objects and unsafe imports. Test swapped tags,
   unapproved rollback, wrong platform, forged labels and modified provenance.
2. [ ] **Worker bootstrap for shared package layers** (estimated 3–5 days for one adapter). Launch
   two matching jobs concurrently, then repeat after restart. Confirm one build/download per key
   in the worker's store, isolation between jobs and invalidation on lock or platform changes. Test
   owner death, timeout, lock replacement, incomplete-build cleanup, and eviction with active and
   foreign assets. Verify that hooks cannot reach the network or see credential markers and that
   credential markers do not survive in intermediate layers or logs. Compare direct downloads and
   test that only ordinary availability failures allow a policy-equivalent fallback.
3. [ ] **Parent build artifacts or publishing worker-built package layers** (follow-up if measurements
   justify it). Test compatibility failures and measure whether packing and transfer beat a rebuild.
4. [ ] **Standalone npm download cache** (lowest priority, deferred). Fetch from the package registry
   by default. Revisit only if measurements show npm downloads are a bottleneck that reusable
   package layers or direct downloads do not address.

- [ ] (decision needed) **First package adapter**. Prefer a profile with slow, repeated dependency
      setup and an existing lockfile. Keep support for other ecosystems open until the first
      adapter demonstrates a benefit on the target worker.
