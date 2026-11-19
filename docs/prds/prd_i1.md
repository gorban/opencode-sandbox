# prd_i1: Restricted orchestrator and operator dashboard

Parent: [prd_i](prd_i.md) · related: [worker fleet](prd_i2.md), [credential broker](prd_i3.md)

## Orchestrator and profiles

- [ ] Launch `oc-sandbox -o` with a dedicated OpenCode configuration and minimal home, using
      an OS sandbox that uses a distinct, verifiable identity. Deny generic file reads, writes,
      shell, subagent launch and web fetch/search by default. Allow named MCP tools and curated
      knowledge lookups. Run from trusted configuration, plugins and a working directory outside
      agent-writable trees. Prevent loading user or project configuration and plugins. Deny access
      to the operator's home, SSH agent, Podman socket, D-Bus and arbitrary network destinations.
      Allow only the files and connections explicitly needed by this role. Enforce and test this
      boundary independently of OpenCode's tool permissions.
      See [OpenCode permissions](https://opencode.ai/docs/permissions/) and
      [MCP servers](https://opencode.ai/docs/mcp-servers/).
- [ ] Search curated repo docs, runbooks and examples. Consider an opt-in search tool with
      bounded output and an explicit data-sharing policy.
- [ ] Provide named profiles for collections of skills, MCPs, pinned `mise` tools and an
      optional worker prompt. Validate versions and schemas. Pin the profile revision on
      launch and show it in the launch preview. Treat profile-provided commands and MCP servers
      as worker capabilities subject to approval and policy.
- [ ] List and search profile metadata and schemas with paging. Update by creating a revision.
      Support diff, restore, archive and unarchive. Hide archived items from default results.
      Expose schema and presence metadata for secret fields. Omit permanent deletion from tools.
- [ ] Launch a host helper alongside the orchestrator with typed operations over a private local
      Unix socket owned by the helper, with filesystem access limited to authorized peers. Verify
      kernel-reported peer credentials against the sandbox identity and authorize each operation
      for that role and target. Bound message sizes and request rates, reject malformed or unknown
      operations, and reject stale or replayed authority across reconnects and restarts. Resolve
      registered opaque keys to host-owned config entries using safe file resolution. Open files in
      the user's preferred viewer/editor only through a human action, with status returned to the
      orchestrator. Test that the sandbox denies host file and socket access and that the helper
      rejects wrong peers, oversized requests, unauthorized operations and replay after restart.
      Suggested formats are JSON and JSON Schema for profiles, `mise.toml` and its lock for
      tool pins, and `.env.example` for reference names. Secret values use the broker store.

## Dashboard

- [ ] Open the operator dashboard in a dedicated hardened host browser profile or native shell.
      Isolate it from general browsing, third-party extensions, service workers and worker browser
      profiles. Keep secret entry and operator controls on this surface. Provide fleet overview,
      approval inbox, browser wall, terminal links and searchable job timeline.
- [ ] If served over HTTP, bind the control interface to loopback and require authenticated,
      expiring operator sessions. Check Host on every request and Origin whenever supplied.
      Require the exact dashboard Origin for mutations and WebSocket upgrades, and enforce CSRF
      protection on mutations. Deny cross-origin access and embedding, and apply a restrictive
      content security policy. Authenticate every status, preview and input stream before opening
      it, and close it on session expiry or revocation. Test that foreign origins, DNS rebinding
      and stale sessions cannot read streams or exercise operator controls.
- [ ] Let the orchestrator propose or edit versioned layouts through a dedicated tool. Support
      views, menus, grouping, filters and component placement using a Glint-style declarative
      catalog. Evaluate [A2UI](https://a2ui.org/) (Apache-2.0) or a small JSON layout schema.
      The host renderer validates data and permits catalog components and registered data bindings.
- [ ] Give the orchestrator sanitized read-only view snapshots (DOM or accessibility projection,
      optionally rendered snapshots). Exclude secrets and approval/session capabilities. Keep
      the operator dashboard outside the orchestrator's browser control tools.
- [ ] Keep approvals, credential editing, browser takeover and terminal attach in trusted host
      components. Render the exact pending operation from the broker's record, including target,
      command or operation and arguments, ref/revision, scope, expiry and cost where relevant.
      Keep this surface outside editable layout slots. Layouts cannot supply approval fields,
      actions, overlays, arbitrary HTML/CSS or scripts. Test that hostile layout input cannot
      impersonate, obscure, reorder within, or modify the approval component.
- [ ] Offer an on-demand launch preview, reconnect controls, and worker grant revocation.

## Worker direction and health

- [ ] Require the orchestrator's launch tool to supply a short, nonblank task description alongside
      the feature or instance name. Describe the intended outcome and what evidence would count
      as progress or completion. The host helper validates the field before starting the job,
      shows it in the launch preview, and records the exact text as the original brief delivered
      to the worker. Manual CLI launches can still omit a description.
- [ ] Capture milestones and expected evidence against the original brief. Record operator-approved
      changes as separate revisions. Show which revision an assessment used, elapsed time per
      milestone, and time since the last meaningful change.
- [ ] Derive health signals from redacted events: heartbeat and server probes, queue time,
      CPU/RAM pressure, test results, repeated actions/errors, no-progress intervals, and
      time spent waiting for human approval or provider limits. Distinguish worker liveness and
      expected waits from evidence that the job is advancing.
- [ ] Use deterministic rules for fast loop, stall and service-health signals. In the model-assisted
      slice, reassess on short batches of meaningful events or when rules flag ambiguity. Estimate
      two scores independently: how likely the observed direction matches the task description and
      how likely the job is still making meaningful progress. For each, report confidence, evidence
      event IDs, the assessed time window, and `unknown` when evidence is stale or insufficient.
      Treat worker events as evidence, never as instructions. Use only the scoped brief and bounded,
      redacted evidence for the job.
- [ ] When an assessment crosses a configured threshold for long enough, publish a scoped event
      back to the orchestrator and dashboard. Flag possible drift and possible stalls separately.
      Include the job and brief revision, scores, confidence, evidence IDs and a suggested next
      check. Use separate recovery thresholds and deduplicate repeated alerts. Low confidence or
      stale telemetry can trigger an evidence check instead of a drift or stall alert. The
      orchestrator can inspect the timeline, ask the worker for status or surface the alert to the
      operator. Assessment events carry no approval or execution authority.
- [ ] Replay on-track work, genuine drift and stalls, healthy long-running checks, provider limits,
      and stale feeds. Tune thresholds against missed alerts and false alarms, and measure the time
      from qualifying evidence to delivery and cost per active worker-hour. Bound call size and
      frequency. The decision model can flag and recommend. It cannot approve, grant access,
      provision resources, stop a worker or rewrite the original brief.

## Open choices

- [ ] (decision needed) **Layout format** — fixed host dashboard plus a small declarative catalog
      (recommended, simpler trust boundary, fewer layout features, 4–7 days) or A2UI adapter
      (reuses a component protocol, adds version and policy integration, 1–2 weeks).
- [ ] (decision needed) **Profile history** — SQLite with immutable revisions (recommended,
      paging and atomic updates, needs export tooling, 2–4 days) or Git-versioned redacted
      profiles (portable diffs, more coordination for concurrent edits, 3–5 days).
- [ ] (decision needed) **Health assessment rollout** — start with rules (recommended, predictable
      and cheap, limited semantic drift detection, 2–4 days), then add the budgeted decision model
      after replay evaluation and a model route are available (another 3–5 days). Decide the event
      cadence, latency target, score thresholds and alert persistence from replay results.
