#!/usr/bin/env bash
# Postgres host-publication regression checks; all Podman operations are stubs.
set -uo pipefail
REPO=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
SCRIPT=${OC_TEST_SCRIPT:-$REPO/oc-sandbox}
T=$(mktemp -d "${TMPDIR:-/tmp}/oc-pg-unit.XXXXXX")
trap 'rm -rf "$T"' EXIT
pass=0 fail=0
check() { local label=$1; shift; if "$@"; then echo "  ok    $label"; ((pass+=1)); else echo "  FAIL  $label"; ((fail+=1)); fi; }
fn() { local requested_function=$1; sed -n "/^$requested_function() {/,/^}/p" "$SCRIPT"; }
cat >"$T/parse.sh" <<EOF2
set -u -o pipefail
H=(); PG=\$1; shift; PORT_ARGS=("\$@"); PORTS=(); PORTS_SET=0
$(grep '^SENSITIVE_PORTS=' "$SCRIPT")
die() { echo "\$*" >&2; exit 2; }
$(fn parse_ports)
parse_ports
printf '%s\\n' "\${PORTS[@]}"
EOF2
parse() { bash "$T/parse.sh" "$@"; }
check 'single-port shorthand maps the same port' bash -c '[[ $(bash "$1" 0 3000) == 3000:3000 ]]' _ "$T/parse.sh"
check '5432 is allowed only with -p' bash -c '[[ $(bash "$1" 1 5432) == 5432:5432 ]] && ! bash "$1" 0 5432 >/dev/null 2>&1' _ "$T/parse.sh"
check '9222 remains forbidden even with -p' bash -c '! bash "$1" 1 9222 >/dev/null 2>&1' _ "$T/parse.sh"
check 'shorthand participates in duplicate checks' bash -c '! bash "$1" 1 5432,5432:80 >/dev/null 2>&1' _ "$T/parse.sh"
# Execute the actual stored-label restoration block, with all Podman calls stubbed.
sed -n '/^if pod_exists && (( !PORTS_SET )); then/,/^want_podcfg=/p' "$SCRIPT" | sed '$d' >"$T/restore.block"
cat >"$T/restore.sh" <<EOF2
set -u -o pipefail
H=(); PG=0; PORT_ARGS=(); PORTS=(); PORTS_SET=0; INHERITED_PG_VERIFIED=0; POD=oc; have_ports='15432:5432'
$(grep '^SENSITIVE_PORTS=' "$SCRIPT")
die() { echo "\$*" >&2; exit 2; }
$(fn parse_ports)
pod_exists() { return 0; }
pm() { echo '15432:5432'; }
$(cat "$T/restore.block")
printf 'accepted:%s\\n' "\${PORTS[*]}"
EOF2
check 'stored 5432 mapping refused without -p' bash -c '! bash "$1" >/dev/null 2>&1' _ "$T/restore.sh"
# Compare the actual Podman binding map to its label; no Podman command is run here.
cat >"$T/bindings.sh" <<EOF2
set -u -o pipefail
$(fn validate_existing_ports)
declare -F validate_existing_ports >/dev/null || exit 99
validate_existing_ports "\$1" "\$2" "\$3"
EOF2
binding='{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"15432"}]}'
check 'matching actual binding accepted with -p' bash "$T/bindings.sh" "$binding" '15432:5432' 1
check 'actual 5432 rejected without -p' bash -c 'bash "$1" "$2" "15432:5432" 0 >/dev/null 2>&1; [[ $? -eq 1 ]]' _ "$T/bindings.sh" "$binding"
check 'hidden 5432 mapping rejected even with -p' bash -c 'bash "$1" "$2" "" 1 >/dev/null 2>&1; [[ $? -eq 1 ]]' _ "$T/bindings.sh" "$binding"
check 'malformed binding metadata rejected' bash -c 'bash "$1" not-json "" 1 >/dev/null 2>&1; [[ $? -eq 1 ]]' _ "$T/bindings.sh"
public_binding='{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"15432"}]}'
check 'unexpected public binding rejected' bash -c 'bash "$1" "$2" "15432:5432" 1 >/dev/null 2>&1; [[ $? -eq 1 ]]' _ "$T/bindings.sh" "$public_binding"
# The launcher keeps the caller's directory, which may be an agent-writable sandbox repository.
# Host Python must not import the modules planted there. Each canary only records that it loaded.
mkdir "$T/hostile-cwd"
for module in json re; do
  printf 'import os\nopen(os.environ["OC_TEST_CANARY"], "a").write("%s\\n")\n' "$module" >"$T/hostile-cwd/$module.py"
done
(cd "$T/hostile-cwd" && OC_TEST_CANARY="$T/canary" bash "$T/bindings.sh" "$binding" '15432:5432' 1 >/dev/null 2>&1); rc=$?
check 'port validation ignores modules in the current directory' bash -c '[[ $1 -eq 0 && ! -e $2 ]]' _ "$rc" "$T/canary"
# PATH is inherited from the caller as well. The interpreter must be the system one, not whichever
# python3 is found first. The canary records that it ran and then behaves like the real interpreter.
mkdir "$T/hostile-path"
printf '#!/usr/bin/bash\nprintf "ran\\n" >>"$OC_TEST_CANARY"\nexec /usr/bin/python3 "$@"\n' >"$T/hostile-path/python3"
chmod +x "$T/hostile-path/python3"
(PATH="$T/hostile-path:$PATH" OC_TEST_CANARY="$T/path-canary" bash "$T/bindings.sh" "$binding" '15432:5432' 1 >/dev/null 2>&1); rc=$?
check 'port validation ignores python3 found through PATH' bash -c '[[ $1 -eq 0 && ! -e $2 ]]' _ "$rc" "$T/path-canary"
# Exercise the actual inherited-port validation and restoration with a stubbed verifier.
sed -n '/^INHERITED_PG_VERIFIED=0$/,/^want_podcfg=/p' "$SCRIPT" | sed '$d' >"$T/inherit.block"
cat >"$T/inherit.sh" <<EOF2
set -u -o pipefail
PG=0; PORTS_SET=0; PORTS=(); PORT_ARGS=(); POD=oc
$(grep '^SENSITIVE_PORTS=' "$SCRIPT")
$(fn parse_ports)
$(fn validate_existing_ports)
die() { echo "\$*" >&2; exit 2; }
pod_exists() { return 0; }
agent_pg_passfile() { [[ \${VERIFIED:-0} == 1 ]]; }
pm() { if [[ \$* == *PortBindings* ]]; then printf '%s\\n' '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"15432"}]}'; else echo 15432:5432; fi; }
$(cat "$T/inherit.block")
printf 'accepted:%s pg=%s verified=%s\\n' "\${PORTS[*]}" "\$PG" "\${INHERITED_PG_VERIFIED:-0}"
EOF2
VERIFIED=1 bash "$T/inherit.sh" >"$T/inherit.out" 2>&1; rc=$?
check 'verified SCRAM server preserves inherited 5432 without -p' bash -c '[[ $1 -eq 0 ]] && grep -q "accepted:15432:5432 pg=0 verified=1" "$2"' _ "$rc" "$T/inherit.out"
VERIFIED=0 bash "$T/inherit.sh" >"$T/inherit-fail.out" 2>&1; rc=$?
check 'unverified server cannot inherit published 5432' bash -c '[[ $1 -ne 0 ]] && ! grep -q accepted "$2"' _ "$rc" "$T/inherit-fail.out"
# Test the real ensure_postgres function in a disposable shell. The only pm function
# below logs arguments and accepts secret bytes via stdin; it never calls Podman.
cat >"$T/pg.sh" <<EOF2
set -u -o pipefail
STATE=$T/state POD=oc PGC=oc-postgres PGVOL=oc-pg PGSECRET=oc-pg-password
PGPASSSECRET=oc-pg-passfile PGHBASECRET=oc-pg-hba PG_INIT=$T/no-init INST= ILABEL=default
PG_IMAGE=img PG_USER=app PG_DB=db PG_PASSWORD='p:a\\b' PORTS=(15432:5432)
SB=$T/sandbox H=()
$(fn in_sb); $(fn trusted_path); $(fn host_input); $(fn inspect_pg_init)
$(fn secret_name_inventory)
$(fn secret_ownership)
$(fn pg_secret_replace_flag)
$(fn preflight_pg_secrets)
$(fn create_pg_secret)
$(fn postgres_container_metadata)
$(fn pg_sig); $(fn urlenc); $(fn pgpass_field); $(fn create_pg_auth_secrets); $(fn ensure_postgres)
cstate() { printf '%s\\n' "\${FAKE_STATE:-none}"; }
log() { :; }; sleep() { :; }
pm() {
  printf '%s\\0' "\$@" >>"$T/argv"; printf '\\n' >>"$T/argv"
  case "\$1 \${2:-}" in
    'volume exists') return 1 ;;
    'container exists'|'container inspect') return 1 ;;
    'secret create') while [[ \$# -gt 2 ]]; do shift; done; cat >"$T/secret.\$1" ;;
    'exec oc-postgres') [[ \${FAIL_AUTH:-0} == 1 && \$* == *' psql '* ]] && return 1 ;;
  esac
  return 0
}
ensure_postgres
EOF2
: >"$T/argv"
bash "$T/pg.sh" >"$T/out" 2>&1; rc=$?
check 'Postgres setup succeeds with stubbed authentication' test "$rc" -eq 0
check 'password not present in arguments or output' bash -c '! grep -qaF "p:a\\b" "$1" "$2"' _ "$T/argv" "$T/out"
check 'HBA enforces SCRAM for IPv4 and IPv6 TCP' bash -c 'grep -qx "host all all 0.0.0.0/0 scram-sha-256" "$1" && grep -qx "host all all ::/0 scram-sha-256" "$1" && ! grep -q "^host .*trust" "$1"' _ "$T/secret.oc-pg-hba"
check 'launch forces HBA at server start' grep -qaF 'hba_file=/run/secrets/oc-pg-hba' "$T/argv"
check 'launch forces SCRAM password encryption' grep -qaF 'password_encryption=scram-sha-256' "$T/argv"
check 'private passfile is mounted mode 0600' grep -qaF 'oc-pgpass,mode=0600' "$T/argv"
check 'pgpass escapes colons and backslashes' grep -qxF '127.0.0.1:5432:db:app:p\:a\\b' "$T/secret.oc-pg-passfile"
check 'host connection URL has no password' grep -qxF '  Host: postgresql://app@127.0.0.1:15432/db' "$T/out"
: >"$T/argv"
FAIL_AUTH=1 bash "$T/pg.sh" >"$T/fail-out" 2>&1; rc=$?
check 'failed authenticated login stops Postgres and fails' bash -c '[[ $1 -ne 0 ]] && grep -qa "stop" "$2" && grep -q "SCRAM login failed" "$3"' _ "$rc" "$T/argv" "$T/fail-out"
# Simultaneous instances must observe one atomically initialized private key.
cat >"$T/key-race.sh" <<EOF2
set -euo pipefail
STATE=$T/key-race; PG_USER=fixture; PG_PASSWORD=fixture; PG_DB=fixture
$(fn pg_sig)
pg_sig fixture
EOF2
pids=()
for n in {1..20}; do bash "$T/key-race.sh" >"$T/key-result.$n" 2>"$T/key-error.$n" & pids+=("$!"); done
key_ok=1
for pid in "${pids[@]}"; do wait "$pid" || key_ok=0; done
check 'concurrent initializations agree on one signature' bash -c '[[ $1 == 1 ]] && [[ $(cat "$2"/key-result.* | sort -u | wc -l) == 1 ]] && [[ $(wc -c < "$2/key-race/pg-sig.key") == 64 ]]' _ "$key_ok" "$T"
check 'signature key and persistent lock remain private single-link files' bash -c '[[ $(stat -c "%a %h" "$1/pg-sig.key") == "600 1" ]] && [[ $(stat -c "%a %h" "$1/pg-sig.lock") == "600 1" ]]' _ "$T/key-race"
# Legacy server must be stopped before the pod section can create published ports.
sed -n '/^# Stop a legacy Postgres before/,/^# ---- pod /p' "$SCRIPT" | sed '$d' >"$T/guard.block"
cat >"$T/guard.sh" <<EOF2
set -u -o pipefail
PG=1 PGC=oc-postgres
$(fn postgres_container_metadata)
cstate() { echo running; }
pm() {
  printf '%s\\n' "\$*" >>"$T/guard.log"
  case "\$1 \${2:-}" in
    'container inspect')
      [[ \${GUARD_INSPECT_FAIL:-0} == 0 ]] || return 125
      if [[ \$4 == *State.Status* ]]; then echo running:v2:legacy; else echo v2:legacy; fi ;;
    'stop -t') return "\${STOP_FAIL:-0}" ;;
  esac
}
log() { :; }; die() { echo "\$*" >&2; exit 2; }
$(cat "$T/guard.block")
printf 'after guard\\n'
EOF2
: >"$T/guard.log"; bash "$T/guard.sh" >"$T/guard.out" 2>&1
check 'legacy running Postgres is stopped before pod handling' grep -q '^stop -t 5 oc-postgres' "$T/guard.log"
STOP_FAIL=1 bash "$T/guard.sh" >"$T/guard-fail.out" 2>&1; rc=$?
check 'failed legacy stop prevents pod handling' bash -c '[[ $1 -ne 0 ]] && ! grep -q "after guard" "$2"' _ "$rc" "$T/guard-fail.out"
: >"$T/guard.log"
GUARD_INSPECT_FAIL=1 bash "$T/guard.sh" >"$T/guard-fail.out" 2>&1; rc=$?
check 'a failed Postgres inspection stops pod handling without stopping the server' \
  bash -c '[[ $1 -ne 0 ]] && ! grep -q "after guard" "$2" && ! grep -q "^stop " "$3"' _ \
  "$rc" "$T/guard-fail.out" "$T/guard.log"
# Exercise the pod recreation branch without any real Podman commands.
sed -n '/^if \[\[ -n \$recreate \]\]; then$/,/^if ! pod_exists; then$/p' "$SCRIPT" | sed '$d' >"$T/recreate.block"
cat >"$T/recreate.sh" <<EOF2
set -euo pipefail
PG=\$1 POD=oc AGENT=oc-agent PGC=oc-postgres DINDC=oc-dind ILABEL=default
PGHBASECRET=oc-pg-hba PGPASSSECRET=oc-pg-passfile PGSECRET=oc-pg-password
recreate='port mapping changed'
$(fn secret_name_inventory)
$(fn secret_ownership)
$(fn pg_secret_replace_flag)
$(fn preflight_pg_secrets)
cstate() { if [[ \$1 == oc-postgres ]]; then printf '%s\\n' "\${FAKE_PG_STATE:-none}"; else echo none; fi; }
any_relay_running() { return 1; }
load_pg_config() { :; }
log() { :; }; die() { echo "\$*" >&2; exit 2; }
pm() {
  printf '%s\\n' "\$*" >>"$T/recreate.log"
  case "\$1 \${2:-}" in
    'container exists')
      [[ \${FAKE_PG_EXISTS_FAIL:-0} == 0 ]] || return 125
      [[ \${FAKE_PG_STATE:-none} != none ]] ;;
    'secret ls') printf '%s\\n' 'aaaaaaaaaaaaaaaaaaaaaaaaa "oc-pg-password"' ;;
    'secret inspect') printf '%s\\n' 'aaaaaaaaaaaaaaaaaaaaaaaaa "oc-pg-password" 0 ""' ;;
  esac
}
$(cat "$T/recreate.block")
EOF2
for requested_postgres in 1 0; do
  : >"$T/recreate.log"
  FAKE_PG_STATE=running bash "$T/recreate.sh" "$requested_postgres" >"$T/recreate.out" 2>&1; rc=$?
  check "pod recreation with Postgres preserves the pod on preflight failure (explicit -p: $requested_postgres)" \
    bash -c '[[ $1 -ne 0 ]] && grep -q "without verified Postgres secrets" "$2" && ! grep -q "^pod rm " "$3"' \
    _ "$rc" "$T/recreate.out" "$T/recreate.log"
done
: >"$T/recreate.log"
FAKE_PG_EXISTS_FAIL=1 bash "$T/recreate.sh" 0 >"$T/recreate.out" 2>&1; rc=$?
check 'an uncertain inherited Postgres container keeps the pod intact' \
  bash -c '[[ $1 -ne 0 ]] && grep -q "could not determine whether Postgres container" "$2" && ! grep -q "^pod rm " "$3"' \
  _ "$rc" "$T/recreate.out" "$T/recreate.log"
: >"$T/recreate.log"
bash "$T/recreate.sh" 0 >"$T/recreate.out" 2>&1; rc=$?
check 'pod recreation without Postgres does not query Postgres secrets' \
  bash -c '[[ $1 -eq 0 ]] && grep -qx "pod rm -f oc" "$2" && ! grep -q "^secret " "$2"' _ "$rc" "$T/recreate.log"
# Run the actual agent passfile decision and launch-argument block with stubbed Podman.
sed -n '/^agent_pg=0$/,/^if \[\[ \$(cstate "\$DINDC")/p' "$SCRIPT" | sed '$d' >"$T/agent.block"
cat >"$T/agent.sh" <<EOF2
set -u -o pipefail
PG=\$1; PGC=oc-postgres; AGENT=oc-agent; ILABEL=default; PGPASSSECRET=oc-pg-passfile; AGENT_IMG=oc-agent
FWD_ENV=()
$(fn agent_pg_passfile)
die() { echo "\$*" >&2; exit 2; }
cstate() { echo "\${FAKE_PG_STATE:-running}"; }
pm() {
  printf '%s\\n' "\$*" >>"$T/agent-pm.log"
  case "\$1 \${2:-}" in
    'container inspect') printf '%s\\n' "\${FAKE_PG_CFG:-v3:scram:k1:abc:img}" ;;
    'exec oc-postgres') [[ \${FAIL_MOUNTED:-0} != 1 ]] || return 1; printf '%s  /run/secrets/oc-pgpass\\n' "\${MOUNT_HASH:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" ;;
    'run --rm') [[ \${FAIL_SECRET:-0} != 1 ]] || return 1; printf '%s  /run/secrets/oc-pgpass\\n' "\${SECRET_HASH:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}" ;;
  esac
}
$(cat "$T/agent.block")
printf '%s\\n' "\${envargs[@]}"
EOF2
check 'agent passfile decision is wired into launch' bash -c 'grep -q "^agent_pg=0" "$1" && grep -q "agent_pg_passfile" "$1" && grep -q "if (( agent_pg ))" "$1"' _ "$T/agent.block"
: >"$T/agent-pm.log"
bash "$T/agent.sh" 0 >"$T/agent.out" 2>&1; rc=$?
check 'plain relaunch mounts verified managed passfile' bash -c '[[ $1 -eq 0 ]] && grep -q "oc-pgpass,mode=0600" "$2" && grep -q "PGPASSFILE=/run/secrets/oc-pgpass" "$2"' _ "$rc" "$T/agent.out"
check 'plain relaunch checks current secret in isolated container' grep -q -- '--network=none --cap-drop=ALL --security-opt=no-new-privileges' "$T/agent-pm.log"
FAKE_PG_STATE=none bash "$T/agent.sh" 0 >"$T/agent-none.out" 2>&1; rc=$?
check 'no existing Postgres launches without passfile' bash -c '[[ $1 -eq 0 ]] && ! grep -q PGPASSFILE "$2"' _ "$rc" "$T/agent-none.out"
FAKE_PG_CFG=v2:legacy bash "$T/agent.sh" 0 >"$T/agent-legacy.out" 2>&1; rc=$?
check 'plain relaunch refuses legacy Postgres' bash -c '[[ $1 -ne 0 ]] && grep -q "not a managed SCRAM" "$2"' _ "$rc" "$T/agent-legacy.out"
FAKE_PG_STATE=exited bash "$T/agent.sh" 0 >"$T/agent-stopped.out" 2>&1; rc=$?
check 'plain relaunch refuses stopped Postgres with guidance' bash -c '[[ $1 -ne 0 ]] && grep -q "rerun with -p" "$2"' _ "$rc" "$T/agent-stopped.out"
FAIL_SECRET=1 bash "$T/agent.sh" 0 >"$T/agent-missing.out" 2>&1; rc=$?
check 'plain relaunch refuses missing passfile secret' bash -c '[[ $1 -ne 0 ]] && grep -q "secret is missing" "$2"' _ "$rc" "$T/agent-missing.out"
SECRET_HASH=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb bash "$T/agent.sh" 0 >"$T/agent-stale.out" 2>&1; rc=$?
check 'plain relaunch refuses stale passfile secret' bash -c '[[ $1 -ne 0 ]] && grep -q "secret is stale" "$2"' _ "$rc" "$T/agent-stale.out"
FAIL_MOUNTED=1 bash "$T/agent.sh" 0 >"$T/agent-no-mounted.out" 2>&1; rc=$?
check 'plain relaunch refuses missing server passfile' bash -c '[[ $1 -ne 0 ]] && grep -q "passfile is missing" "$2"' _ "$rc" "$T/agent-no-mounted.out"
echo "$pass passed, $fail failed"
(( fail == 0 ))
