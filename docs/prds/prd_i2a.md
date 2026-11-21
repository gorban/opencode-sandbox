# prd_i2a: SSH remote host onboarding and first remote sandbox run

Parent: [prd_i2](prd_i2.md) · related: [prd_i](prd_i.md), [host LLM broker](prd_i4a.md),
[credential broker](prd_i3.md), [warm worker starts](prd_i5.md)

## Goal and target roles

Run a real OpenCode sandbox on a named remote SSH worker while keeping **all provider credentials,
password managers, and SSH signing keys strictly on the workstation**. Concrete machine hostnames,
usernames, and SSH key fingerprints live only in local host-trusted `~/.config/oc-sandbox/workers.toml`
and `~/.config/oc-sandbox/known_hosts/` — never in git-tracked files.

| Role | Host | Responsibilities | Explicitly excluded |
|---|---|---|---|
| **Trusted controller / workstation** | Linux workstation (rootless Podman 6.x, Keeper SSH Agent) | Worker enrollment registry (`~/.config/oc-sandbox/workers.toml`), per-worker pinned `known_hosts`, SSH transport, Minimal Host LLM Broker ([prd_i4a](prd_i4a.md)), `oc_controller.py` grants/revocation. | Does not expose SSH agent (`ForwardAgent=no`) or raw provider credentials to remote host. |
| **First remote SSH worker** | Named macOS Apple Silicon host (`<macos-worker>.local:22`, Homebrew `/opt/homebrew/bin`, Podman Machine) — plus Linux rootless Podman workers | Runs isolated OpenCode sandbox container(s) inside Podman, executes sandbox tools locally, streams bounded output back over SSH. | Holds zero upstream API keys, zero OAuth tokens, zero password-manager state, zero SSH signing keys. |

## Coordination with Warm Worker Seeding (`prd_i5`)

`codex/warm-worker-seeding` owns [prd_i5](prd_i5.md) (registry image verification, Git object
caches, package layer seeding, and cache-aware placement). This slice owns worker enrollment,
pinned SSH transport, first remote sandbox execution, and a reusable public contract in
`oc_ssh_worker.py` so `prd_i5` can layer seeding without duplicating SSH plumbing:

- Typed **`WorkerSpec`** and **`WorkerProbe`** (`platform`, `arch`, `remote_uid`, `podman_version`,
  `socket_ready`, `gateway_ports_safe`).
- Bounded **`run_remote_cmd(worker, argv, stdin_stream=None, max_stdout=..., timeout=...)`**
  supporting binary stdin/stdout streaming (reusable for Git bundle/artifact transfers).
- Digest-pinned **`job_spec.image`** (`@sha256:...`) and optional read-only checkout/seed mount
  hooks.
- Reusable offline stub fixture **`tests/ssh_worker_fixture.py`** for deterministic worker tests.

## Resolved open choices and remote transport design

- **Transport** (resolves [prd_i2](prd_i2.md#open-choices)): **SSH first**, using OpenSSH with:
  - `-F /dev/null`, `-T` (`RequestTTY=no`), `BatchMode=yes`, `ForwardAgent=no`,
    `IdentitiesOnly=yes`, `ClearAllForwardings=yes`, `PermitLocalCommand=no`,
    `StrictHostKeyChecking=yes`, `GlobalKnownHostsFile=/dev/null`,
    `UserKnownHostsFile=<per-worker single-entry known_hosts>`,
    `HostKeyAlgorithms=<pinned key algo, e.g. ssh-ed25519>`, `ExitOnForwardFailure=yes`,
    `ControlPersist=no`, and scrubbed `SSH_AUTH_SOCK` in child `env`.
  - Identity served by **Keeper SSH Agent** (`~/.keeper/*.ssh_agent`, verified via full ancestor
    ownership/mode walk and outside `~/opencode-sandbox`) paired with explicit public key
    (`~/.ssh/oc-worker.pub`).
  - Host key pinned to a verified Ed25519 fingerprint confirmed out-of-band by the maintainer
    against `/etc/ssh/ssh_host_ed25519_key.pub` on the remote host.
- **Remote LLM reverse-tunnel boundary (workstation zero-TCP + macOS Podman Machine vs. Linux)**:
  - On the **workstation**, `oc_llm_broker.py` listens on a dedicated per-job `0o700` Unix domain
    socket under `$XDG_RUNTIME_DIR/oc-sandbox/jobs/<job_id>/broker.sock` (zero host TCP listener).
    OpenSSH natively bridges remote TCP loopback to that local UDS via:
    `ssh -R 127.0.0.1:0:/run/user/<uid>/oc-sandbox/jobs/<job_id>/broker.sock`.
  - **Remote `GatewayPorts` guard (mandatory before container launch)**: Preflight verifies that
    `sshd` does not bind `0.0.0.0` / `*` (e.g. via `GatewayPorts yes`), and after requesting the
    ephemeral forward, the launcher verifies on the remote host that the allocated port listens
    strictly on `127.0.0.1` / `::1` before launching any container.
  - **On macOS remote workers (`macos-podman-machine`)**: Podman runs containers inside a Linux VM
    where VirtioFS does not pass macOS Unix sockets. The container calls
    `http://host.containers.internal:<remote_port>` authenticated by the 256-bit `ocjob_...` token
    delivered via a per-job **Podman secret mount** (`mode=0400`, never `--env-file` or argv).
    Security note: macOS host loopback is reachable by other local processes on that same macOS
    account; the broker mitigates this with single-lease listener binding, constant-time 256-bit
    bearer auth, strict model allowlist, zero credential-read endpoints, and immediate teardown +
    revocation on exit/disconnect. Multi-tenant remote hosts require Linux `pasta` isolation below.
  - **On Linux remote workers (`linux-podman`)**: The container runs with
    `--network pasta:--no-map-gw,-T,<remote_port>` so it reaches **only** `http://127.0.0.1:<remote_port>`
    (no arbitrary remote host loopback access, no `unix://` mismatch for OpenCode, and no custom
    SELinux `.cil` required on the remote host).
- **Browser view & terminal UX** ([prd_i2](prd_i2.md#open-choices)): Deferred to follow-up slices;
  this slice runs headless remote OpenCode sandboxes with explicit SSH status/logs/teardown.

## Scope checklist

- [ ] **Worker registry & enrollment (`oc_ssh_worker.py`)** — host-trusted
      `~/.config/oc-sandbox/workers.toml` (`0o700`/`0o600`, shared atomic TOML helpers from
      [prd_i4a](prd_i4a.md)), strict validation of worker name, hostname, username, port, single-entry
      pinned `known_hosts` (supporting `[host]:port`, rejecting wildcards/`@cert-authority`/extra
      keys), `-o` path character validation (rejecting whitespace, `%`, control chars), and full
      ancestor walk on Keeper SSH agent socket and pubkey path.
- [ ] **SSH preflight & readiness probe** — verifies pinned host key, remote `id -u`, `uname -m`,
      `podman --version`, `podman info --format json` (confirming Podman Machine socket is actually
      ready on macOS, not merely `running`), `GatewayPorts` safety, and real container-to-broker
      `host.containers.internal` / `pasta -T` reachability.
- [ ] **Remote sandbox launch, reverse tunnel, secret mount, and lifecycle** — admits job lease in
      [oc_controller.py](../../oc_controller.py), creates workstation per-job `0o700` UDS, opens SSH
      control master (`sun_path < 100` bytes under `$XDG_RUNTIME_DIR`) + ephemeral `-R` forward,
      verifies loopback-only remote bind, passes variable launch spec via stdin JSON (zero remote
      shell interpolation), creates per-job Podman secret (`mode=0400`) for `ocjob_...` + rendered
      `opencode.json`, launches hardened container (`--cap-drop=ALL`, `--security-opt=no-new-privileges`,
      `--pids-limit`, `--memory`, ownership labels), persists orphan-cleanup receipt under
      `$CONF_DIR/remote-state/`, and revokes lease + removes container & secret + closes SSH master
      (with bounded 5s cleanup timeout and signal reaping) on exit, error, or cancel.
- [ ] **Offline tests (`tests/ssh_worker_fixture.py`) & live macOS acceptance** — deterministic
      security/failure tests with stubbed SSH/Podman plus real end-to-end remote run on the
      enrolled macOS worker.

## Gate 1: Pseudocode walkthrough (before implementation)

### 1. Worker enrollment, path validation, and readiness probe

```text
function validate_ssh_option_path(path):
    assert_host_trusted_file_or_socket(path)        # outside ~/opencode-sandbox; full ancestor walk
    if re.search(r"[\s%\x00-\x1f\x7f]", str(path)):
        raise InvalidWorkerConfig("SSH option path contains forbidden whitespace, %, or control chars")

function verify_single_entry_known_hosts(kh_path, host, port, expected_fp, expected_algo="ssh-ed25519"):
    assert_host_trusted_file(kh_path)
    lines = [ln.strip() for ln in read_lines(kh_path) if ln.strip() and not ln.startswith("#")]
    if len(lines) != 1:
        raise HostKeyMismatch("Per-worker known_hosts must contain exactly one pinned host entry")
    entry = parse_known_hosts_line(lines[0])        # rejects @cert-authority, @revoked, *, ?, |1| mismatch
    expected_host_token = host if port == 22 else f"[{host}]:{port}"
    if entry.host_token != expected_host_token or entry.key_type != expected_algo:
        raise HostKeyMismatch("Host token or key algorithm mismatch")
    if sha256_fingerprint(entry.key_blob) != expected_fp:
        raise HostKeyMismatch("Pinned host key fingerprint mismatch")

function ssh_base_args(worker, agent_sock):
    validate_ssh_option_path(agent_sock)            # checks socket + 0700 parent + ancestor walk
    validate_ssh_option_path(worker.pubkey_path)
    validate_ssh_option_path(worker.known_hosts_path)
    verify_single_entry_known_hosts(worker.known_hosts_path, worker.host, worker.port,
                                    worker.host_key_fp, worker.host_key_algo)
    return [
        "ssh",
        "-F", "/dev/null",
        "-T",
        "-o", "BatchMode=yes",
        "-o", "ForwardAgent=no",
        "-o", "IdentitiesOnly=yes",
        "-o", "ClearAllForwardings=yes",
        "-o", "PermitLocalCommand=no",
        "-o", "ControlPersist=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={worker.known_hosts_path}",
        "-o", f"HostKeyAlgorithms={worker.host_key_algo}",
        "-o", f"IdentityAgent={agent_sock}",
        "-o", f"IdentityFile={worker.pubkey_path}",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-o", "ConnectTimeout=10",
        "-p", str(worker.port),
        "--", f"{worker.user}@{worker.host}",
    ]

function probe_worker(worker, agent_sock):
    # Fixed constant remote probe script passed via stdin to `sh -s` (zero variable interpolation);
    # prepends /opt/homebrew/bin:/usr/local/bin safely and emits JSON:
    # {remote_uid, arch, podman_version, socket_ready, machine_state, gateway_ports_safe}.
    probe = parse_probe_json(run_ssh_fixed(worker, agent_sock, FIXED_PROBE_SCRIPT, timeout=15s))
    if not probe.socket_ready:
        raise WorkerNotReady("Remote Podman socket is not ready (check `podman machine start`)")
    if not probe.gateway_ports_safe:
        raise WorkerUnsafe("Remote sshd enables GatewayPorts; refusing to expose broker on LAN")
    return WorkerProbe(**probe)
```

### 2. Remote sandbox launch, secret delivery, and teardown/reconciliation

```text
function run_remote_sandbox(worker, probe, job_spec, broker, controller):
    validate_job_id(job_spec.job_id)                # ^[a-z0-9][a-z0-9_-]{0,47}$
    validate_digest_pinned_image(job_spec.image)    # requires @sha256:<64hex>, no leading '-'
    assert_arch_compatible(job_spec.arch, probe.arch)

    lease = broker.create_uds_job_lease(worker.name, job_spec, controller)
    ctrl_dir = None
    ctrl_sock = None
    ssh_master = None
    receipt_path = None
    container_name = f"oc-remote-{job_spec.job_id}"
    secret_names = [f"oc-sec-tok-{job_spec.job_id}", f"oc-sec-cfg-{job_spec.job_id}"]
    try:
        ctrl_dir = mkdtemp_0700(XDG_RUNTIME_DIR / "oc-sandbox", prefix="ssh-")
        ctrl_sock = ctrl_dir / "c"                  # guaranteed < 100 bytes
        ssh_master = start_ssh_control_master(worker, agent_sock, ctrl_sock)   # scrubbed SSH_AUTH_SOCK in env
        # Native OpenSSH remote TCP loopback -> workstation local UDS (zero workstation TCP port)
        remote_port = ssh_control_forward_ephemeral(ctrl_sock, "127.0.0.1:0", lease.local_uds_path)
        verify_remote_port_loopback_only(ctrl_sock, remote_port)               # rejects 0.0.0.0 / * bind

        if worker.platform == "macos-podman-machine":
            broker_url = f"http://host.containers.internal:{remote_port}"
            net_args = []
        else:
            broker_url = f"http://127.0.0.1:{remote_port}"
            net_args = ["--network", f"pasta:--no-map-gw,-T,{remote_port}"]

        # Record orphan receipt right before creating remote container/secrets
        receipt_path = write_orphan_receipt_0600(CONF_DIR / "remote-state",
                                                 worker.name, container_name, secret_names, controller.incarnation)
        # Deliver job token + rendered opencode.json strictly via Podman secrets over stdin (mode=0400);
        # never placed on remote argv (`ps`) or `--env-file` (`podman inspect`).
        payload = json_dumps({
            "container_name": container_name,
            "secret_names": secret_names,
            "image": job_spec.image,
            "broker_url": broker_url,
            "net_args": net_args,
            "memory": worker.memory_limit,
            "pids_limit": worker.pids_limit,
            "labels": {
                "oc.sandbox.remote": "1",
                "oc.job_id": job_spec.job_id,
                "oc.controller_incarnation": controller.incarnation,
            },
            "job_token": lease.token,
            "opencode_config": render_managed_opencode_json(broker_url, lease.allowed_routes),
        })
        # Fixed remote Python/sh launcher reads JSON from stdin, creates Podman secrets via stdin,
        # starts container with --cap-drop=ALL --security-opt=no-new-privileges --pids-limit --memory,
        # mounts secrets mode=0400, isolated home, zero upstream creds.
        return run_remote_launcher_and_stream(ctrl_sock, FIXED_REMOTE_LAUNCH_SCRIPT, stdin=payload, lease=lease)
    finally:
        # 1. Revoke first so even an unreachable remote container loses LLM access immediately (< 1s)
        controller.revoke(lease.operator, lease.request_id)
        broker.close_job_listener(lease.id)
        # 2. Bounded remote cleanup (5s timeout): stop/rm ONLY label-verified container & all secrets
        if receipt_path is not None and ctrl_sock is not None:
            cleaned = best_effort_remote_cleanup(ctrl_sock, container_name, secret_names,
                                                 controller.incarnation, timeout=5s)
            if cleaned:
                remove_file_if_exists(receipt_path) # otherwise keep receipt for reconnect reconciliation
        # 3. Always terminate and reap SSH master + remove private control dir
        if ssh_master is not None and ctrl_sock is not None:
            close_and_reap_ssh_master(ssh_master, ctrl_sock)
        if ctrl_dir is not None:
            remove_tree_verified(ctrl_dir)
```

**Failure & recovery paths:**
- Host key changed, missing, or extra unpinned key in `known_hosts` -> fails closed before SSH connects.
- Keeper SSH agent socket missing, stale, or weak ancestor perms -> fails closed with Keeper unlock instruction.
- `GatewayPorts yes` or remote port listening on `0.0.0.0` -> aborts immediately before launching container.
- Reverse forward fails (`ExitOnForwardFailure=yes`) -> container never starts; lease revoked immediately.
- SSH drops mid-job -> control master closes, reverse tunnel collapses, `finally` revokes lease immediately (`< 1s`), bounded 5s cleanup attempt runs, and if unreachable, orphan receipt remains under `$CONF_DIR/remote-state/` so `reconcile_worker_orphans()` removes ONLY label-verified owned containers/secrets on next reconnect.

## Verification plan

1. **Offline unit & adversarial security tests (`tests/ssh_worker_fixture.py`, scratch `HOME`):**
   - Enrollment & path guards: reject hostile hostnames (`-oProxyCommand=...`), invalid `job_id`/`image` (unpinned tag, leading `-`, shell metacharacters), symlinked `workers.toml`, multi-key/wildcard/`@cert-authority`/wrong-port `known_hosts`, whitespace/`%` in `-o` paths, and weak Keeper SSH agent ancestor perms.
   - SSH argv & env checks: assert `-F /dev/null`, `-T`, `GlobalKnownHostsFile=/dev/null`, `ClearAllForwardings=yes`, `PermitLocalCommand=no`, `ForwardAgent=no`, `IdentitiesOnly=yes`, `StrictHostKeyChecking=yes`, `HostKeyAlgorithms=...`, `ExitOnForwardFailure=yes`, `ControlPersist=no`, scrubbed `SSH_AUTH_SOCK`, and confirm `ocjob_...` NEVER appears in SSH argv, `podman inspect`, or logs.
   - Failure, revocation & reconciliation: `GatewayPorts yes` / `0.0.0.0` bind aborts launch; reverse-forward failure revokes lease; arch mismatch rejected; `oc_controller.revoke_worker()` aborts an active remote stream `< 1s`; mid-run SSH drop keeps orphan receipt and reconnect reconciliation removes ONLY label-verified owned resources (leaving foreign containers untouched).
2. **Live readiness & acceptance on the enrolled macOS worker (after maintainer setup batch):**
   - Quick readiness check: pinned host key + Keeper SSH agent + `podman --version` + `podman info` + `GatewayPorts` check.
   - Full remote acceptance (after implementation): launch an isolated OpenCode container on the macOS worker, verify `host.containers.internal:<port>` reaches workstation broker with `ocjob_...`, complete a real model round trip through workstation subscription/API-key broker, prove zero upstream credentials exist inside the remote container or on the macOS host, trigger `oc_controller.revoke_worker()` mid-stream and confirm `< 1s` abort + `403` denial, and verify clean container/secret/tunnel teardown.

## Review record

- Gate 1 design review round 1 (internal adversarial security + PR-style architecture reviewers):
  all P1/P2/P3 findings addressed.
- Gate 1 design re-review: **CLEARED** by both internal reviewers (with localized fixes folded in:
  `try:` immediately after `lease` creation, receipt written right before remote container/secrets
  creation, and both token/config secret names tracked in orphan receipts and cleanup). External
  Daybreak Blue review pending PR push.
- Implementation PR review (Gate 2): pending.
