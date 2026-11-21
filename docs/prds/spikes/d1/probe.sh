#!/usr/bin/env bash
# Spike d1 probe (v2): per-instance loopback address 127.0.1.N with pasta `auto` forwarding.
#
# Design under test (two independent layers, both exclude the sensitive ports):
#   1. pasta: the pod is created with `--network pasta` and started with CONTAINERS_CONF_OVERRIDE pointing
#      at a file with  pasta_options = ["--host-lo-to-ns-lo","-t","ADDR/~9222,~5432,~9223,auto"].
#      (Podman splits `--network pasta:...` on commas, so a spec with commas can only come from containers.conf.
#      The file is read at every pod START, not stored in the pod.)
#   2. netfilter in the pod's network namespace, applied from the host with
#      `podman unshare nsenter -t INFRA_PID -n nft -f -` (no container, no image): one table `oc_d1`, replaced
#      atomically: REDIRECT of 127.0.1.0/24 to 127.0.0.1 for every port NOT in the list, REJECT for ports in it.
#
# Resources: pods/containers oc-spike-d1-*, no images,
# host addresses 127.0.1.201-205, host ports 14001-14002 and 14100-14102. Everything is removed on exit.
# Scratch files go to <worktree>/.scratch/probe.XXXXXX.
# Run on the host or in a distrobox; needs host Podman, pasta, curl, ss, nft, iptables, nsenter, rpm, ip,
# flock, and the locally available python:3.12-alpine image; flock is also needed in the calling environment.
# Usage: probe.sh [section...]   sections: neg matrix main atomic restart dyn   (default: all)
set -u -o pipefail
P=oc-spike-d1-$$-$RANDOM
H=()
if [[ -n ${CONTAINER_ID:-} || -n ${DISTROBOX_ENTER_PATH:-} ]]; then
  command -v distrobox-host-exec >/dev/null 2>&1 || { echo 'ABORT: distrobox-host-exec is required inside a distrobox' >&2; exit 2; }
  H=(distrobox-host-exec)
elif [[ -n ${container:-} ]]; then
  echo 'ABORT: unsupported container environment; run on the host or in a distrobox' >&2; exit 2
fi
# Every host call is batch-only. Closing stdin forces distrobox-host-exec's non-PTY
# path even when this script itself is run from a terminal under an outer timeout.
host() { "${H[@]}" "$@" </dev/null; }
host_timeout() {
  local stage=$1 rc; shift
  timeout 15 "${H[@]}" "$@" </dev/null; rc=$?
  if (( rc != 0 )); then
    if (( rc == 124 )); then echo "host preflight $stage timed out or returned 124 (exit $rc)" >&2
    else echo "host preflight $stage failed (exit $rc)" >&2; fi
  fi
  return "$rc"
}
A=127.0.1.201 B=127.0.1.202 N=127.0.1.205 M=127.0.1.203
SENS="9222 5432 9223"
PASS=0 FAIL=0

pm()  { host podman "$@"; }
hc()  { host curl -s -m 3 "$@"; }
say() { printf '%s\n' "$*"; }
die() { printf 'ABORT: %s\n' "$*" >&2; exit 2; }
res() { # res PASS|FAIL|INFO name detail
  case $1 in PASS) PASS=$((PASS+1));; FAIL) FAIL=$((FAIL+1));; esac
  printf '%-5s %-52s %s\n' "$1" "$2" "$3"
}

# ---- poll worker control ----------------------------------------------------------------------------------
# The worker holds an advisory lock until its shell and inherited child descriptors exit. A private
# receipt confirms it acquired that lock. Cancellation is cooperative: never signal a mutable PID or
# assume a distrobox forwarding process propagates signals to the host worker.
# Ignore any inherited shell variables: only this process can register its child.
pp= worker_job= worker_status=0
start_worker() { # start_worker atomic|dyn OUTPUT ADDR [PORT]
  local mode=$1 output=$2 addr=$3 port=${4:-}
  [[ -z $pp && -z $worker_job ]] || { echo "worker already active" >&2; return 1; }
  worker_lock="$SCR/worker.lock"; worker_receipt="$SCR/worker.ready"; worker_cancel="$SCR/worker.cancel"
  worker_token="$$-$RANDOM-$RANDOM"
  rm -f -- "$worker_receipt" "$worker_cancel" || return 1
  : >"$worker_lock" || die "cannot create worker lock"
  # If interrupted between launch and recording $!, cleanup must assume a worker may exist.
  pp=starting
  "${H[@]}" bash -c '
    lock=$1 receipt=$2 cancel=$3 token=$4 mode=$5 addr=$6 port=$7
    exec 9>"$lock" || exit 1
    flock -x 9 || exit 1
    printf "%s\n" "$token" >"$receipt" || exit 1
    [[ ! -e $cancel ]] || exit 0
    if [[ $mode == atomic ]]; then
      end=$((SECONDS+20))
      while ((SECONDS<end)) && [[ ! -e $cancel ]]; do
        t=$(date +%s%N); a=$(curl --noproxy "*" -s -m 1 "http://$addr:5432/")
        b=$(curl --noproxy "*" -s -m 1 "http://$addr:3000/")
        [[ -n $a ]] && a=leak || a=closed; [[ $b == C:3000* ]] && b=ok || b=bad
        echo "$t $a $b"
      done
    elif [[ $mode == dyn ]]; then
      end=$((SECONDS+9))
      while ((SECONDS<end)) && [[ ! -e $cancel ]]; do
        t=$EPOCHREALTIME
        if curl -s -m 1 -o /dev/null "http://$addr:$port/"; then c=OK; else c=FAIL; fi
        if ss -tlnH src "$addr:$port" | grep -q .; then l=L; else l=-; fi
        echo "$t $c $l"; sleep 0.03
      done
    elif [[ $mode == fixture || $mode == fixture_fail ]]; then
      # Harmless workers for interruption regressions; no network or Podman.
      while [[ ! -e $cancel ]]; do sleep 0.1; done
      if [[ $mode == fixture_fail ]]; then exit 143; fi
    else exit 2; fi
  ' _ "$worker_lock" "$worker_receipt" "$worker_cancel" "$worker_token" "$mode" "$addr" "$port" </dev/null >"$output" &
  worker_job=$!
  pp=$worker_job
  local i
  for i in {1..100}; do
    [[ -f $worker_receipt && $(<"$worker_receipt") == "$worker_token" ]] && return 0
    sleep 0.05
  done
  return 1
}
worker_wait() { # wait for the owned lock and forwarding job; preserve receipts on uncertainty
  [[ -n $pp || -n $worker_job ]] || return 0
  local i active known
  if [[ ! $pp =~ ^[1-9][0-9]*$ || $pp != "$worker_job" ]]; then
    echo "worker forwarding job identity is unknown; retaining $SCR for inspection" >&2; return 1
  fi
  # Bash keeps an unwaited child in its job table even after completion. A numeric
  # string alone is not proof that wait will reap a child owned by this shell.
  known=$(jobs -p)
  if [[ $'\n'$known$'\n' != *$'\n'"$pp"$'\n'* ]]; then
    echo "worker forwarding job is not owned by this shell; retaining $SCR for inspection" >&2; return 1
  fi
  worker_status=0
  for i in {1..100}; do
    [[ -f $worker_receipt && $(<"$worker_receipt") == "$worker_token" ]] && break
    sleep 0.05
  done
  if [[ ! -f $worker_receipt || $(<"$worker_receipt") != "$worker_token" ]]; then
    echo "worker receipt missing or invalid; retaining $SCR for inspection" >&2; return 1
  fi
  if ! flock -w 30 "$worker_lock" true; then
    echo "worker did not release its lock; retaining $SCR for inspection" >&2; return 1
  fi
  for i in {1..300}; do
    active=$(jobs -pr; jobs -ps)
    [[ $'\n'$active$'\n' == *$'\n'"$pp"$'\n'* ]] || break
    sleep 0.1
  done
  active=$(jobs -pr; jobs -ps)
  if [[ $'\n'$active$'\n' == *$'\n'"$pp"$'\n'* ]]; then
    echo "worker forwarding job did not finish; retaining $SCR for inspection" >&2; return 1
  fi
  wait "$pp" || worker_status=$?
  pp= worker_job=
  rm -f -- "$worker_lock" "$worker_receipt" "$worker_cancel"
  return 0
}
stop_worker() { # request cancellation, then verify lock release and forwarding completion
  [[ -n $pp || -n $worker_job ]] || return 0
  : >"$worker_cancel" || { echo "cannot request worker cancellation; retaining $SCR" >&2; return 1; }
  worker_wait
}

# Fail before scratch or resource creation if host routing, required tools, metadata, or
# the local image is unavailable. In particular, never print a partial versions line.
for tool in git timeout awk grep sed mktemp flock; do
  command -v "$tool" >/dev/null 2>&1 || die "local prerequisite not found: $tool"
done
host_timeout "tool availability" sh -c 'for cmd in podman pasta curl ss nft iptables nsenter rpm ip bash ps unshare uname flock; do command -v "$cmd" >/dev/null 2>&1 || { echo "missing host prerequisite: $cmd" >&2; exit 1; }; done' || die "host tools unavailable or host execution failed"
podman_ver=$(host_timeout "Podman version" podman --version) && [[ -n $podman_ver ]] || die "cannot read host Podman version"
pasta_ver=$(host_timeout "passt version" rpm -q passt) && [[ -n $pasta_ver ]] || die "cannot read host passt version"
nft_ver=$(host_timeout "nft version" nft --version) && [[ -n $nft_ver ]] || die "cannot read host nft version"
kernel_ver=$(host_timeout "kernel version" uname -r) && [[ -n $kernel_ver ]] || die "cannot read host kernel version"
lan_raw=$(host_timeout "IPv4 addresses" ip -4 -o addr show scope global) || die "cannot list host IPv4 addresses"
LAN=$(awk '{split($4,a,"/"); print a[1]; exit}' <<<"$lan_raw")
[[ $LAN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "no host LAN IPv4 address available for exposure controls"
host_timeout "curl" curl --version >/dev/null || die "host curl is not executable"
host_timeout "TCP listeners" ss -tlnpH >/dev/null || die "cannot inspect host TCP listeners"
host_timeout "iptables" iptables --version >/dev/null || die "host iptables is not executable"
host_timeout "nsenter" nsenter --version >/dev/null || die "host nsenter is not executable"
host_timeout "Python image" podman image exists python:3.12-alpine || die "required image python:3.12-alpine is not available locally"
host_timeout "rootless network namespace" podman unshare unshare -n true >/dev/null || die "rootless network namespace prerequisites unavailable"
pods=$(host_timeout "pod inventory" podman pod ls --format '{{.Name}}') || die "cannot list host pods"
ctrs=$(host_timeout "container inventory" podman ps -a --format '{{.Names}}') || die "cannot list host containers"
images=$(host_timeout "image inventory" podman images --format '{{.Repository}}') || die "cannot list host images"
stale=$(printf '%s\n%s\n%s\n' "$pods" "$ctrs" "$images" | grep -E "^(localhost/)?oc-spike-d1-" || true)
[[ -z $stale ]] || die "resources named oc-spike-d1-* already exist; inspect them before proceeding: $stale"
say "== versions: $podman_ver; $pasta_ver; $nft_ver; kernel $kernel_ver"
say "== host LAN address used for the exposure check: $LAN"

# ---- scratch directory and resource registry --------------------------------------------------------------
# Podman writes immutable IDs into private scratch files as resources are created. Cleanup
# removes only those IDs; a failed create never authorizes removal by name.
ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel) || die "not in a git worktree"
BASE=$ROOT/.scratch
[[ -L $BASE || -L $ROOT ]] && die "$BASE or $ROOT is a symlink"
mkdir -p "$BASE" && [[ -d $BASE ]] || die "cannot create $BASE"
BASE_REAL=$(cd "$BASE" && pwd -P)
SCR=$(mktemp -d "$BASE_REAL/probe.XXXXXX") || die "mktemp failed"
SCR_REAL=$(cd "$SCR" && pwd -P)
[[ $SCR_REAL == "$BASE_REAL"/probe.?????? && ! -L $SCR_REAL ]] || die "unexpected scratch path $SCR_REAL"
SCR=$SCR_REAL
id_of() {
  local probe_pod=$1 v
  local receipt_path=$SCR/pod-$probe_pod.id
  [[ -f $receipt_path ]] || return 1
  read -r v <"$receipt_path"
  [[ $v =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$v"
}
rmpod() { local id; id=$(id_of "$1") || return 1; pm pod rm -f -t 0 "$id" >/dev/null; }
cleanup() {
  trap - EXIT
  if ! stop_worker; then echo "Cleanup stopped before resource removal; inspect $SCR" >&2; return 1; fi
  local f id rc failed=0
  shopt -s nullglob
  for f in "$SCR"/pod-*.id; do
    id=$(cat "$f") || { failed=1; continue; }
    [[ $id =~ ^[0-9a-f]{64}$ ]] || { failed=1; continue; }
    pm pod exists "$id" >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then pm pod rm -f -t 0 "$id" >/dev/null 2>&1 || failed=1
    elif (( rc != 1 )); then failed=1; fi
  done
  for f in "$SCR"/ctr-*.id; do
    id=$(cat "$f") || { failed=1; continue; }
    [[ $id =~ ^[0-9a-f]{64}$ ]] || { failed=1; continue; }
    pm container exists "$id" >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then pm rm -f -t 0 "$id" >/dev/null 2>&1 || failed=1
    elif (( rc != 1 )); then failed=1; fi
  done
  shopt -u nullglob
  if (( failed )); then printf 'Cleanup failed; inspect ID files in %s\n' "$SCR" >&2; return 1; fi
  [[ -d $SCR && ! -L $SCR && $SCR == "$BASE_REAL"/probe.?????? ]] || return 1
  rm -rf -- "$SCR"
}
trap 'rc=$?; cleanup || rc=1; exit "$rc"' EXIT
trap 'exit 130' INT TERM
pcreate() { # pcreate NAME mode(pm|pmx) podman-pod-create-args
  local name=$1 mode=$2; shift 2
  if [[ $mode == pmx ]]; then pmx "$name" pod create --pod-id-file "$SCR/pod-$name.id" --name "$P-$name" "$@" >/dev/null
  else pm pod create --pod-id-file "$SCR/pod-$name.id" --name "$P-$name" "$@" >/dev/null; fi
}

# ---- servers -------------------------------------------------------------------------------------------
# body "LABEL:PORT from=CLIENTADDR"; argv: label bind port [lifetime-seconds]; prints "bind T" when listening
SRV='import sys,time,socket,http.server
lab,bind,port=sys.argv[1],sys.argv[2],int(sys.argv[3]); life=float(sys.argv[4]) if len(sys.argv)>4 else 0
class Hd(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        b=("%s:%d from=%s\n"%(lab,port,s.client_address[0])).encode()
        s.send_response(200); s.send_header("Content-Length",str(len(b))); s.end_headers(); s.wfile.write(b)
    def log_message(*a): pass
class S(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET
s=S((bind,port),Hd); s.timeout=0.05
print("bind %.3f"%time.time(),flush=True)
if life:
    end=time.time()+life
    while time.time()<end: s.handle_request()
    s.server_close(); print("closed %.3f"%time.time(),flush=True)
else: s.serve_forever()'
# srv POD LABEL BIND PORT [life]: starts a server in the pod and waits (10 s) until it prints "bind"; aborts if not
srv() {
  local probe_pod=$1 bind_address=$3 listen_port=$4 lifetime=${5:-} i
  local name="$P-$probe_pod-s$listen_port-${bind_address//[:.]/_}"
  pm run -d --pod "$(id_of "$probe_pod")" --name "$name" --cidfile "$SCR/ctr-$name.id" python:3.12-alpine python -c "$SRV" "${@:2}" >/dev/null || die "cannot start server $name"
  [[ -n $lifetime ]] && return 0
  for i in $(seq 1 40); do
    out=$(pm logs "$name" 2>&1); [[ $out == *bind* ]] && return 0; sleep 0.25
  done
  die "server $name never started listening: $out"
}
# inpod POD URL: fetch from a client container inside the pod (positive control that the server is up)
inpod() {
  local probe_pod=$1 probe_url=$2
  pm run --rm --pod "$(id_of "$probe_pod")" --name "$P-$probe_pod-cl$RANDOM" --cidfile "$SCR/ctr-client-$BASHPID-$RANDOM.id" python:3.12-alpine python -c '
import sys
import urllib.request as u
try: print(u.urlopen(sys.argv[1],timeout=3).read().decode().strip())
except Exception as e: print("ERR",e)' "$probe_url" 2>&1 | tail -1
}

# ---- host-side checks ----------------------------------------------------------------------------------
want() { # want NAME URL SUBSTR: answers (retry up to 6 s)
  local check_name=$1 probe_url=$2 expected_text=$3 out i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    out=$(hc "$probe_url") && [[ $out == *"$expected_text"* ]] && { res PASS "$check_name" "$probe_url -> $out"; return 0; }
    sleep 0.5
  done
  res FAIL "$check_name" "$probe_url -> '${out:-no answer}' (wanted '$expected_text')"
}
nope() { # nope NAME URL CTRL_URL [CTRL_SUBSTR]: URL gives no answer while CTRL_URL (a server that is up) does
  local check_name=$1 probe_url=$2 control_url=$3 out ctl
  ctl=$(hc "$control_url")
  [[ -n $ctl ]] || { res FAIL "$check_name" "positive control $control_url gave no answer; result not meaningful"; return 1; }
  out=$(hc "$probe_url")
  [[ -n $out ]] && { res FAIL "$check_name" "$probe_url -> $out (wanted no answer; control $control_url ok)"; return 1; }
  res PASS "$check_name" "$probe_url -> no answer (control $control_url -> ${ctl%% *})"
}
info() {
  local check_name=$1 probe_url=$2 out
  out=$(hc "$probe_url")
  res INFO "$check_name" "$probe_url -> ${out:-no answer}"
}
# up POD SUFFIX NAME: the server printed "bind" (it is listening inside the pod)
up() {
  local probe_pod=$1 server_suffix=$2 check_name=$3 out
  out=$(pm logs "$P-$probe_pod-s$server_suffix" 2>&1)
  [[ $out == *bind* ]] && res PASS "$check_name" "server s$server_suffix is listening in pod $probe_pod" || res FAIL "$check_name" "server s$server_suffix did not start"
}

# Require valid samples before, during, and after replacement; every positive control must
# return the expected server body. Finite sampling observes behavior, not absence of all leaks.
check_poll() {
  local file=$1 worker_rc=$2 start=$3 end=$4 stats
  if (( worker_rc != 0 )) || ! stats=$(awk -v start="$start" -v end="$end" '
    NF != 3 || $1 !~ /^[0-9]+$/ || ($2 != "closed" && $2 != "leak") || ($3 != "ok" && $3 != "bad") { invalid=1; next }
    { n++; if ($1 < start) before++; else if ($1 <= end) during++; else after++; if ($2 == "leak") leaks++; if ($3 != "ok") bad++ }
    END { if (invalid || n == 0 || before == 0 || during == 0 || after == 0 || leaks || bad) exit 1; print n, before, during, after }' "$file"); then
    res FAIL "atomic polling evidence" "worker=$worker_rc; missing, malformed, leaking, failed control, or no overlap"; return 1
  fi
  res PASS "no sensitive responses observed during replacements" "$stats samples (total, before, during, after); all controls answered"
}

# ---- pod construction ----------------------------------------------------------------------------------
spec()  { echo "$1/$(for p in $SENS; do printf '~%s,' "$p"; done)auto"; }
# spec_range ADDR: the variant with an explicit 1024-65535 range (forwards ephemeral ports too, but see hostconf)
spec_range() { echo "$1/1024-65535,$(for p in $SENS; do printf '~%s,' "$p"; done)auto"; }
conf()  { # conf POD ADDR: containers.conf override with the pasta options; prints the path
  local probe_pod=$1 bind_address=$2
  printf '[network]\npasta_options = ["--host-lo-to-ns-lo", "-t", "%s"]\n' "$(spec "$bind_address")" >"$SCR/$probe_pod.conf"
  echo "$SCR/$probe_pod.conf"
}
pmx()   { # pmx POD podman-args: podman with the pod's override file (as oc-sandbox must do for EVERY start)
  local pod=$1; shift; host env CONTAINERS_CONF_OVERRIDE="$SCR/$pod.conf" podman "$@"; }
# mkpod MODE NAME ADDR [pod-create args]
#   full  pasta exclusion (containers.conf) + nft table      pasta  pasta exclusion only
#   nft   plain `-t ADDR/auto` + nft table                    bare   plain `-t ADDR/auto`, nothing else
mkpod() {
  local mode=$1 name=$2 addr=$3; shift 3
  case $mode in
    full|pasta)
      conf "$name" "$addr" >/dev/null
      pcreate "$name" pmx --network pasta --sysctl net.ipv4.ip_unprivileged_port_start=0 "$@" >/dev/null || return 1
      pmx "$name" pod start "$(id_of "$name")" >/dev/null || return 1 ;;
    nft|bare)
      pcreate "$name" pm --network "pasta:--host-lo-to-ns-lo,-t,$addr/auto" \
        --sysctl net.ipv4.ip_unprivileged_port_start=0 "$@" >/dev/null || return 1
      pm pod start "$(id_of "$name")" >/dev/null || return 1 ;;
  esac
  case $mode in full|pasta) pasta_verify "$name" "$addr" || { echo "pasta args wrong for $name: $(pasta_args "$name")" >&2; return 1; } ;; esac
  case $mode in full|nft) nft_apply "$name" "$SENS" || { echo "nft ruleset wrong for $name" >&2; return 1; } ;; esac
}
infra_id() {
  local probe_pod=$1
  pm pod inspect --format '{{.InfraContainerID}}' "$(id_of "$probe_pod")"
}
infra_pid() {
  local probe_pod=$1
  pm inspect --format '{{.State.Pid}}' "$(infra_id "$probe_pod")"
}
# pasta_args POD: the pasta command line serving this pod (found through the pod's netns path), up to --dns-forward
pasta_args() {
  local key; key=$(pm inspect --format '{{.NetworkSettings.SandboxKey}}' "$(infra_id "$1")")
  host ps -eo args | grep -F -- "--netns $key" | grep -v grep | sed 's/ --dns-forward.*//;s/ -u none.*//'
}

# ---- netfilter in the pod netns (nsenter with the host's own nft; nothing runs in a container) ----------
rules() { # rules "PORT PORT ..." -> nft script; one table, replaced in a single transaction
  local list; list=$(echo $1 | sed 's/ /, /g')
  cat <<EOT
table ip oc_d1
delete table ip oc_d1
table ip oc_d1 {
  chain nat_out {
    type nat hook output priority dstnat; policy accept;
    ip daddr 127.0.1.0/24 tcp dport != { $list } ${3:-} redirect
  }
  chain filter_out {
    type filter hook output priority filter; policy accept;
    ip daddr 127.0.1.0/24 tcp dport { $list } reject with tcp reset
  }
}
EOT
}
nsx()       {
  local probe_pod=$1
  host podman unshare nsenter -t "$(infra_pid "$probe_pod")" -n "${@:2}"
}
# (`| cat`: nft prints nothing when its stdout is the pipe distrobox-host-exec hands it, so list through a second pipe)
nft_list()  {
  local probe_pod=$1
  nsx "$probe_pod" bash -o pipefail -c 'nft -s list ruleset 2>&1 | cat'
}
nft_expect(){ # nft_expect "PORTS" [EXTRA-MATCH]: what nft prints for the same rules in a throwaway netns
  local excluded_ports=$1 extra_match=${2:-}
  host podman unshare unshare -n sh -c 'printf "%s\n" "$1" | nft -f - && nft -s list ruleset 2>&1 | cat' _ "$(rules "$excluded_ports" x "$extra_match")"
}
nft_verify(){ # nft_verify POD "PORTS" [EXTRA]: exact match of the applied ruleset, else non-zero
  local probe_pod=$1 excluded_ports=$2 extra_match=${3:-} want got
  want=$(nft_expect "$excluded_ports" "$extra_match") || return 1
  got=$(nft_list "$probe_pod") || return 1
  [[ -n $want && $got == "$want" ]]
}
# nft_apply POD "PORTS" [EXTRA]: apply in one transaction, then READ BACK and compare; non-zero if it is not what was asked for
nft_apply() {
  local probe_pod=$1 excluded_ports=$2 extra_match=${3:-}
  nsx "$probe_pod" sh -c 'printf "%s\n" "$1" | nft -f -' _ "$(rules "$excluded_ports" x "$extra_match")" || return 1
  nft_verify "$probe_pod" "$excluded_ports" "$extra_match"
}
pasta_verify() { # pasta_verify POD ADDR: pasta was started with exactly the expected -t spec
  local probe_pod=$1 bind_address=$2
  [[ $(pasta_args "$probe_pod") == *"--host-lo-to-ns-lo -t $(spec "$bind_address")"* ]]
}

sections=${*:-neg matrix main atomic restart dyn}
has() { local section=$1; [[ " $sections " == *" $section "* ]]; }

# ---- neg: the earlier failures, and what does not work ---------------------------------------------------
if has neg; then
  say; say "## neg: why the first probes failed, and options that do not work"
  pcreate neg1 pm --network "pasta:--host-lo-to-ns-lo,-t,$N/4321-4322" >/dev/null
  srv neg1 any 0.0.0.0 4321; srv neg1 lo 127.0.0.1 4322; sleep 2
  res INFO "pasta args (fixed ports)" "$(pasta_args neg1)"
  want "neg1 app on 0.0.0.0 works" "http://$N:4321/" "any:4321"
  nope "neg1 app on 127.0.0.1 fails" "http://$N:4322/" "http://$N:4321/"
  rmpod neg1 || die "cannot remove pod neg1"
  pcreate neg1b pm --network "pasta:-t,$N/4321-4322" >/dev/null
  srv neg1b any 0.0.0.0 4321; srv neg1b lo 127.0.0.1 4322; sleep 2
  want "neg1b no --host-lo-to-ns-lo: app on 0.0.0.0" "http://$N:4321/" "any:4321"
  nope "neg1b no --host-lo-to-ns-lo: app on 127.0.0.1" "http://$N:4322/" "http://$N:4321/"
  rmpod neg1b || die "cannot remove pod neg1b"
  pcreate neg2 pm --network "pasta:--host-lo-to-ns-lo,-t,$N/4321-4322:127.0.0.1/4321-4322" >/dev/null
  srv neg2 any 0.0.0.0 4321; srv neg2 lo 127.0.0.1 4322; sleep 2
  res INFO "neg2 in-pod: 4321 / 4322 (both servers are up)" "$(inpod neg2 http://127.0.0.1:4321/) | $(inpod neg2 http://127.0.0.1:4322/)"
  [[ -z $(hc http://$N:4321/)$(hc http://$N:4322/) ]] && res PASS "neg2 toaddr=127.0.0.1 forwards nothing (0.0.0.0 and 127.0.0.1 apps)" "4321 and 4322 -> no answer" || res FAIL "neg2" "something answered"
  rmpod neg2 || die "cannot remove pod neg2"
  pcreate neg3 pm --network "pasta:--host-lo-to-ns-lo,-t,$N/1024-65535,auto" >/dev/null
  res INFO "neg3 comma in --network pasta: spec (start)" "$(pm pod start $(id_of neg3) 2>&1 | grep -E 'uid_map|user mappings|GID' | cut -c1-80 | tr '\n' ' ')"
  rmpod neg3 || die "cannot remove pod neg3"
  pcreate neg4 pm --network "pasta:--host-lo-to-ns-lo,--tcp-ports=$N/auto" >/dev/null
  res INFO "neg4 --tcp-ports=SPEC (start)" "$(pm pod start $(id_of neg4) 2>&1 | grep -E 'conflicts' | cut -c1-90)"
  rmpod neg4 || die "cannot remove pod neg4"
  pcreate neg5 pm --network "pasta:--host-lo-to-ns-lo,-t,$N/auto,-t,$N/~9222" >/dev/null
  res INFO "neg5 auto + second -t ~9222 (start)" "$(pm pod start $(id_of neg5) 2>&1 | grep -E 'conflict' | cut -c1-170)"
  rmpod neg5 || die "cannot remove pod neg5"
  # containers.conf: read at START, so the override must be present on every start
  conf neg6 "$N" >/dev/null
  pcreate neg6 pmx --network pasta >/dev/null; pmx neg6 pod start $(id_of neg6) >/dev/null
  res INFO "neg6 override at create+start" "$(pasta_args neg6)"
  pm pod stop -t 0 $(id_of neg6) >/dev/null; pm pod start $(id_of neg6) >/dev/null 2>&1
  res INFO "neg6 same pod restarted WITHOUT the override" "$(pasta_args neg6)"
  rmpod neg6 || die "cannot remove pod neg6"
fi

# ---- matrix: what is reachable in each combination of the two layers ------------------------------------------
if has matrix; then
  say; say "## matrix: sensitive ports (9222 on 127.0.0.1, 5432 on 0.0.0.0, 9223 on 127.0.1.N itself) per layer combination"
  for mode in full pasta nft bare; do
    mkpod $mode m$mode $M || exit 2
    srv m$mode S 127.0.0.1 9222; srv m$mode S 0.0.0.0 5432; srv m$mode S $M 9223
    srv m$mode OK 0.0.0.0 4000; srv m$mode OK 127.0.0.1 3000; sleep 2.5
    r=""; for x in 9222 5432 9223 4000 3000; do o=$(hc http://$M:$x/); r+=" $x=${o:-closed}"; done
    case $mode in
      full)  exp="all three sensitive ports closed, 4000 and 3000 open" ;;
      pasta) exp="sensitive closed, 4000 open, 3000 closed (no redirect)" ;;
      nft)   exp="sensitive closed, 4000 and 3000 open" ;;
      bare)  exp="FAIL-OPEN: 5432 and 9223 open, 9222 (127.0.0.1 only) closed" ;;
    esac
    res INFO "matrix $mode: $exp" "$r"
    # assertions; every "closed" claim needs the control (4000 on 0.0.0.0, forwarded in every mode) to answer
    [[ $(hc http://$M:4000/) == OK:4000* ]] || res FAIL "matrix $mode: positive control 4000" "control did not answer, closed-checks below are void"
    s9222=$(hc http://$M:9222/); s5432=$(hc http://$M:5432/); s9223=$(hc http://$M:9223/)
    if [[ $mode == bare ]]; then
      [[ -z $s9222 && $s5432 == S:5432* && $s9223 == S:9223* ]] && res PASS "matrix bare reproduces the fail-open" "0.0.0.0 and 127.0.1.N listeners reachable, app saw: ${s5432#*from=}" || res FAIL "matrix bare" "unexpected: $r"
    else
      [[ -z $s9222$s5432$s9223 ]] && res PASS "matrix $mode: sensitive ports closed" "9222/5432/9223 -> no answer" || res FAIL "matrix $mode" "sensitive port answered:$r"
    fi
    if [[ $mode == full || $mode == pasta ]]; then
      [[ $(pasta_args m$mode) == *"-t $(spec $M)"* ]] && res PASS "matrix $mode: pasta args carry the exclusions" "$(pasta_args m$mode | sed 's/.*--host-lo/--host-lo/')" || res FAIL "matrix $mode pasta args" "$(pasta_args m$mode)"
    fi
    [[ $mode == pasta ]] && { [[ $(hc http://$M:4000/) == OK:4000* && -z $(hc http://$M:3000/) ]] && res PASS "matrix pasta: no rules -> 0.0.0.0 app ok, 127.0.0.1 app closed" "" || res FAIL "matrix pasta" "$r"; }
    [[ $mode == full || $mode == nft ]] && { [[ $(hc http://$M:3000/) == OK:3000* ]] && res PASS "matrix $mode: 127.0.0.1 app reachable" "" || res FAIL "matrix $mode: 127.0.0.1 app" "$r"; }
    if [[ $mode == full ]]; then
      # inside the pod the sensitive services still work for their own pod
      res INFO "in-pod 127.0.0.1:9222 / :5432" "$(inpod m$mode http://127.0.0.1:9222/) | $(inpod m$mode http://127.0.0.1:5432/)"
      [[ $(inpod m$mode http://127.0.0.1:9222/) == S:9222* && $(inpod m$mode http://127.0.0.1:5432/) == S:5432* ]] && res PASS "sensitive services reachable from inside the pod" "" || res FAIL "in-pod sensitive" ""
    fi
    rmpod "m$mode" || die "cannot remove matrix pod"
  done
  # started without the override: pasta gets -t none, nothing is forwarded (fails closed)
  mkpod full mnoenv $M || exit 2
  srv mnoenv OK 0.0.0.0 4000; sleep 2; want "mnoenv before restart: forwarded" "http://$M:4000/" "OK:4000"
  pm pod stop -t 0 $(id_of mnoenv) >/dev/null; pm pod start $(id_of mnoenv) >/dev/null 2>&1; sleep 3
  res INFO "mnoenv restarted without override: pasta args" "$(pasta_args mnoenv)"
  appup=$(inpod mnoenv http://127.0.0.1:4000/)
  [[ $appup == OK:4000* && -z $(hc http://$M:4000/) ]] && res PASS "started without override: nothing forwarded (fails closed)" "app up in pod ($appup), host -> no answer" || res FAIL "start without override" "in-pod=$appup host=$(hc http://$M:4000/)"
  rmpod mnoenv || die "cannot remove pod mnoenv"
fi

# ---- main: two pods, same port, exposure, -p alongside, in-pod clients ----------------------------------------
if has main || has atomic || has restart || has dyn; then
  say; say "## setup: pods $A (a) and $B (b), mode full"
  mkpod full a $A -p 127.0.0.1:14001:3001 -p 127.0.0.1:14002:4000 || exit 2
  mkpod full b $B || exit 2
  srv a A 127.0.0.1 3000; srv a A 127.0.0.1 3001; srv a A 0.0.0.0 4000
  srv a A 127.0.0.1 9222; srv a A 0.0.0.0 5432; srv a A $A 9223
  srv a A 127.0.0.1 32767; srv a A 127.0.0.1 32768; srv a A 127.0.0.1 40000; srv a A ::1 3002
  srv b B 127.0.0.1 3000; srv b B 127.0.0.1 3003; srv b B 127.0.0.1 80; srv b B 0.0.0.0 4001
  res INFO "pasta args pod a" "$(pasta_args a)"
  res INFO "pasta args pod b" "$(pasta_args b)"
  nft_verify a "$SENS" && res PASS "nft ruleset pod a matches expected" "" || res FAIL "nft ruleset pod a" "$(nft_list a | tr '\n' ' ')"
  pasta_verify a $A && res PASS "pasta args pod a match expected" "" || res FAIL "pasta args pod a" "$(pasta_args a)"
  sleep 2
fi
if has main; then
  say; say "## main"
  want "a: 3000 on 127.0.0.1 -> pod a"      "http://$A:3000/" "A:3000"
  want "b: 3000 on 127.0.0.1 -> pod b"      "http://$B:3000/" "B:3000"
  want "a: 3001 on 127.0.0.1"               "http://$A:3001/" "A:3001"
  want "a: 4000 on 0.0.0.0"                 "http://$A:4000/" "A:4000"
  want "b: 3003 on 127.0.0.1"               "http://$B:3003/" "B:3003"
  want "a: 32767 (last port below the ephemeral range)" "http://$A:32767/" "A:32767"
  nope "a: 32768 NOT forwarded (ephemeral range)" "http://$A:32768/" "http://$A:3000/"
  nope "a: 40000 NOT forwarded (ephemeral range)" "http://$A:40000/" "http://$A:3000/"
  nope "a does not answer for b's port 3003" "http://$A:3003/" "http://$A:3000/"
  nope "b does not answer for a's port 3001" "http://$B:3001/" "http://$B:3000/"
  for x in 9222 5432 9223; do nope "a: $x excluded" "http://$A:$x/" "http://$A:3000/"; done
  [[ $(inpod a http://127.0.0.1:9222/) == A:9222* && $(inpod a http://127.0.0.1:5432/) == A:5432* ]] && res PASS "9222 and 5432 do answer from inside pod a" "(so the host-side silence is the exclusion, not a dead server)" || res FAIL "in-pod 9222/5432" ""
  up a "9223-${A//./_}" "9223 listener on $A itself"
  nope "unallocated 127.0.1.203:3000"       "http://127.0.1.203:3000/" "http://$A:3000/"
  nope "127.0.0.1:3000 not forwarded"        "http://127.0.0.1:3000/" "http://$A:3000/"
  nope "LAN $LAN:3000"                       "http://$LAN:3000/" "http://$A:3000/"
  nope "LAN $LAN:4000"                       "http://$LAN:4000/" "http://$A:3000/"
  nope "0.0.0.0:3000"                        "http://0.0.0.0:3000/" "http://$A:3000/"
  nope "[::1]:3000"                          "http://[::1]:3000/" "http://$A:3000/"
  info "[::ffff:$A]:3000 (v4-mapped)"        "http://[::ffff:$A]:3000/"
  out=$(hc --interface 127.0.0.5 "http://$A:3000/"); res INFO "other source address 127.0.0.5 -> $A:3000" "${out:-no answer/reset}"
  info "b: port 80 (host ip_unprivileged_port_start=$(host cat /proc/sys/net/ipv4/ip_unprivileged_port_start))" "http://$B:80/"
  info "a: 3002 bound to [::1] only"         "http://$A:3002/"
  want "-p 127.0.0.1:14001 -> pod port 3001" "http://127.0.0.1:14001/" "A:3001"
  want "-p 127.0.0.1:14002 -> pod port 4000" "http://127.0.0.1:14002/" "A:4000"
  res INFO "source address the app sees" "$(hc http://$A:3000/)"
  socks=$(host ss -tlnpH 2>/dev/null | grep pasta | awk '{print $4}' | sort -u | tr '\n' ' ')
  if [[ $socks =~ (^|[[:space:]])(0\.0\.0\.0|\*|\[::\]|192\.168\.|10\.)[^[:space:]]* ]]; then
    res FAIL "pasta host listeners" "wildcard or LAN socket: $socks"
  else res PASS "pasta host listeners" "loopback only: $socks"; fi
  res INFO "UDP sockets held by pasta" "$(host ss -ulnpH 2>/dev/null | grep -c pasta)"
  for x in a b; do
    out=$(inpod $x http://127.0.0.1:3000/)
    [[ $out == *"${x^^}:3000"* ]] && res PASS "in-pod client pod $x -> 127.0.0.1:3000" "$out" || res FAIL "in-pod client pod $x" "$out"
  done
  # inside a pod, 127.0.1.0/24 is redirected to the pod itself
  res INFO "in-pod client of pod a -> $B:3000 (b's address)" "$(inpod a http://$B:3000/)  <- pod a itself answers"
  [[ $(inpod a http://$B:3000/) == A:3000* ]] && res PASS "self-redirect confirmed" "connecting to another instance's address from inside a pod reaches the pod itself" || res FAIL "self-redirect" "unexpected result"
  # can the redirect be limited to pasta's own connections? pasta's sockets are uid 0 in the pod's userns.
  nft_apply b "$SENS" "meta skuid 0" || die "nft_apply b failed"
  CL='import urllib.request as u
try: print(u.urlopen("http://'$A':3000/",timeout=2).read().decode().strip())
except Exception as e: print("ERR",e)'
  r0=$(pm run --rm --pod $(id_of b) --name "$P-b-u0" --cidfile "$SCR/ctr-u0.id" --user 0 python:3.12-alpine python -c "$CL" 2>&1 | tail -1)
  r1=$(pm run --rm --pod $(id_of b) --name "$P-b-u1" --cidfile "$SCR/ctr-u1.id" --user 1000 python:3.12-alpine python -c "$CL" 2>&1 | tail -1)
  res INFO "with 'meta skuid 0' on the redirect: host -> b" "$(hc http://$B:3000/)"
  res INFO "  in-pod uid 0 client -> $A:3000 (redirected to itself)" "$r0"
  res INFO "  in-pod uid 1000 client -> $A:3000" "$r1"
  [[ $(hc http://$B:3000/) == B:3000* && $r0 == B:3000* && $r1 == ERR* ]] && res PASS "skuid limits the self-redirect to uid 0 processes" "non-root clients are refused instead; root clients (host user's uid) still reach themselves" || res FAIL "skuid self-redirect" "unexpected result"
  nft_apply b "$SENS" || die "nft_apply b failed"
  nft_verify b "$SENS" && res PASS "nft ruleset pod b restored" "" || res FAIL "nft restore pod b" ""
fi

# ---- atomic: verification, changing the port list on a running pod, no gap during replacement --------------------
if has atomic; then
  say; say "## atomic: verify, change the list while running, replace atomically"
  # verification detects a changed list and a missing table
  nft_apply b "9222 5432" || die "nft_apply b {9222,5432} failed"; nft_verify b "$SENS" && res FAIL "verify detects a different port list" "" || res PASS "verify detects a different port list" "applied {9222,5432}, expected {$SENS}"
  nsx b nft flush ruleset; nft_verify b "$SENS" && res FAIL "verify detects missing rules" "" || res PASS "verify detects missing rules" "ruleset empty"
  pasta_verify b $A && res FAIL "pasta_verify detects wrong address/spec" "" || res PASS "pasta_verify detects wrong address/spec" "pod b is on $B, checked against $A"
  # 20 ports (iptables multiport allows 15, nft sets do not)
  big=$(seq 9300 9319 | tr '\n' ' '); nft_apply b "$big" && res PASS "nft set with 20 ports applies and verifies" "" || res FAIL "20-port set" ""
  # list change on a RUNNING pod: new port 6379 is excluded by the new table, order independent
  srv b X 0.0.0.0 6379; srv b X 127.0.0.1 6380; sleep 2
  # Reproduce the previous append-only iptables design in this disposable pod. The newly
  # added RETURN follows REDIRECT, so 6379 still reaches the app despite the later REJECT.
  nsx b nft flush ruleset || die "cannot clear test netns"
  nsx b sh -c 'iptables -t nat -A OUTPUT -d 127.0.1.0/24 -p tcp -m multiport --dports 9222,5432 -j RETURN && iptables -t nat -A OUTPUT -d 127.0.1.0/24 -p tcp -j REDIRECT && iptables -A OUTPUT -d 127.0.1.0/24 -p tcp -m multiport --dports 9222,5432 -j REJECT --reject-with tcp-reset && iptables -t nat -A OUTPUT -d 127.0.1.0/24 -p tcp -m multiport --dports 9222,5432,6379 -j RETURN && iptables -A OUTPUT -d 127.0.1.0/24 -p tcp -m multiport --dports 9222,5432,6379 -j REJECT --reject-with tcp-reset' || die "cannot apply old test rules"
  want "old append-only rules leak added port 6379" "http://$B:6379/" "X:6379"
  nsx b nft flush ruleset || die "cannot clear old test rules"
  nft_apply b "9222 5432" || die "nft_apply b failed"; sleep 0.5
  want "6379 forwarded while not in the list" "http://$B:6379/" "X:6379"
  nft_apply b "9222 5432 6379" && res PASS "list change verified" "" || res FAIL "list change verify" ""
  nope "6379 (0.0.0.0 listener) closed after adding it to the list" "http://$B:6379/" "http://$B:3000/"
  want "6380 (not in the list) is still redirected to the 127.0.0.1 app" "http://$B:6380/" "X:6380"
  nft_apply b "$SENS" || die "nft_apply b failed"
  # no gap during replacement: pod c has ONLY the nft layer, 5432 listens on 0.0.0.0
  mkpod nft c $M || exit 2
  srv c C 0.0.0.0 5432; srv c C 127.0.0.1 3000; sleep 2.5
  poll=$(mktemp -p "$SCR")
  start_worker atomic "$poll" "$M" || die "poll worker failed to start; cleanup will retain unverified resources"
  for i in {1..100}; do [[ -s $poll ]] && break; kill -0 "$pp" 2>/dev/null || break; sleep 0.1; done
  [[ -s $poll ]] || die "poller produced no samples before updates"
  start=$(date +%s%N)
  for i in 1 2 3 4 5 6 7 8 9 10; do nft_apply c "9222 5432 9223 $((6000+i))" || die "nft_apply c failed in round $i"; done
  end=$(date +%s%N)
  worker_wait || die "poll worker termination could not be verified"
  worker_rc=$worker_status
  check_poll "$poll" "$worker_rc" "$start" "$end"
  rm -f "$poll"; rmpod c || die "cannot remove pod c"

fi

# ---- restart: rules live in the pod netns --------------------------------------------------------------------
if has restart; then
  say; say "## restart: pod stop/start/restart (pasta layer is re-created from the override; netfilter is not)"
  # The sensitive listeners exist before each restart; they bind to three distinct addresses.
  srv b B 127.0.0.1 9222; srv b B 0.0.0.0 5432; srv b B "$B" 9223
  for how in "restart" "stop-start"; do
    # Each restart starts with verified rules; otherwise their absence proves nothing.
    if ! nft_apply b "$SENS"; then
      res FAIL "before pod $how" "cannot apply and verify nft rules"; continue
    fi
    restart_ok=0
    case $how in
      stop-start) restart_out=$(pmx b pod stop -t 1 "$(id_of b)" 2>&1) && restart_out=$(pmx b pod start "$(id_of b)" 2>&1) && restart_ok=1 ;;
      *) restart_out=$(pmx b pod $how "$(id_of b)" 2>&1) && restart_ok=1 ;;
    esac
    if (( ! restart_ok )); then res FAIL "pod $how" "restart command failed: $restart_out"; continue; fi
    for i in 1 2 3 4 5 6 7 8; do [[ $(inpod b http://127.0.0.1:3000/) == B:3000* ]] && break; sleep 1; done
    appup=$(inpod b http://127.0.0.1:3000/)
    if [[ $appup != B:3000* ]]; then res FAIL "pod $how" "app did not return: $appup"; continue; fi
    if ! pasta_verify b "$B"; then res FAIL "pod $how" "pasta exclusions do not match"; continue; fi
    if ! ruleset=$(nft_list b); then res FAIL "pod $how" "could not inspect nft rules"; continue; fi
    if [[ $ruleset == *oc_d1* ]]; then res FAIL "pod $how" "nft table remained after restart"; continue; fi
    # 4001 is a separate wildcard-bound app: it must be forwarded while the nft
    # table is absent, so silence on excluded ports cannot pass from a dead path.
    control=
    for i in {1..12}; do control=$(hc "http://$B:4001/"); [[ $control == B:4001* ]] && break; sleep 0.5; done
    if [[ $control != B:4001* ]]; then res FAIL "pod $how" "host positive control 4001 failed: $control"; continue; fi
    sensitive_ok=1
    for port in 9222 5432 9223; do
      bind=127.0.0.1; [[ $port == 9223 ]] && bind=$B
      inside=$(inpod b "http://$bind:$port/")
      if [[ $inside != B:$port* ]]; then res FAIL "pod $how port $port" "in-pod positive control failed: $inside"; sensitive_ok=0; continue; fi
      if [[ -n $(hc "http://$B:$port/") ]]; then res FAIL "pod $how port $port" "excluded port answered on host"; sensitive_ok=0; fi
    done
    (( sensitive_ok )) || continue
    res PASS "pod $how" "app up, pasta exclusions verified, nft absent; 3 live sensitive ports refused with host control"
  done
  # Podman 6.1.3 rejects this flag. Treat rejection as an observed negative test,
  # never as evidence that a restart happened.
  restart_out=$(pmx b pod restart -t 1 "$(id_of b)" 2>&1); restart_rc=$?
  if (( restart_rc != 0 )) && [[ $restart_out == *"unknown shorthand flag: 't'"* ]]; then
    res PASS "pod restart -t 1 rejected" "unsupported flag; no restart verified"
  else res FAIL "pod restart -t 1 rejection" "rc=$restart_rc output=$restart_out"; fi
  nft_apply b "$SENS" && pasta_verify b $B && res PASS "re-apply + verify (nft and pasta) succeeds" "" || res FAIL "re-apply + verify" ""
  want "forwarding works again" "http://$B:3000/" "B:3000"
  if [[ $(inpod b http://127.0.0.1:9222/) == B:9222* ]]; then
    nope "9222 excluded again" "http://$B:9222/" "http://$B:3000/"
  else res FAIL "9222 excluded again" "positive in-pod sensitive-port control failed"; fi
fi

# ---- dyn: latency of auto ------------------------------------------------------------------------------------------
if has dyn; then
  say; say "## dyn: pick-up and drop latency of auto (pod b, 6 rounds, listener lives 4 s, host polled every ~60 ms)"
  picks=() drops=()
  for port in 14110 14111 14112 14113 14114 14115; do
    poll=$(mktemp -p "$SCR")
    start_worker dyn "$poll" "$B" "$port" || die "latency worker failed to start; cleanup will retain unverified resources"
    sleep $(awk -v r=$RANDOM 'BEGIN{printf "%.2f", 0.8+(r%100)/100}')   # vary the phase against pasta's 1 s rescan
    pm run -d --pod $(id_of b) --name "$P-b-dyn$port" --cidfile "$SCR/ctr-dyn$port.id" python:3.12-alpine python -c "$SRV" B 127.0.0.1 $port 4 >/dev/null
    worker_wait || die "latency worker termination could not be verified"
    if (( worker_status != 0 )); then res FAIL "dyn $port" "worker exited $worker_status"; continue; fi
    logs=$(pm logs $P-b-dyn$port 2>&1)
    bind=$(awk '$1=="bind"{print $2}' <<<"$logs"); closed=$(awk '$1=="closed"{print $2}' <<<"$logs")
    first_ok=$(awk '$2=="OK"{print $1; exit}' "$poll"); last_l=$(awk '$3=="L"{l=$1} END{print l}' "$poll")
    if [[ -n $bind && -n $first_ok && -n $closed && -n $last_l ]]; then
      pk=$(awk -v b="$bind" -v ok="$first_ok" 'BEGIN{printf "%.2f",ok-b}'); dr=$(awk -v c="$closed" -v l="$last_l" 'BEGIN{printf "%.2f",l-c}')
      picks+=("$pk"); drops+=("$dr"); res INFO "dyn $port" "answers $pk s after bind; last observed host socket $dr s relative to close"
    else res FAIL "dyn $port" "bind='$bind' first_ok='$first_ok' closed='$closed' last_l='$last_l'"; fi
    rm -f "$poll"
  done
  rng() { printf '%s\n' "$@" | sort -n | sed -n '1p;$p' | tr '\n' ' '; }
  res INFO "pick-up latency range (min max, s) over ${#picks[@]} runs" "$(rng "${picks[@]}")"
  res INFO "last observation relative to close (min max, s)" "$(rng "${drops[@]}")"
fi

say; say "== PASS=$PASS FAIL=$FAIL"
cleanup || exit 1
left=$({ pm pod ls --format '{{.Name}}' | grep -c "^$P-"; pm ps -a --format '{{.Names}}' | grep -c "^$P-"; pm images --format '{{.Repository}}' | grep -c 'oc-spike-d1'; } | tr '\n' ' ')
say "== left after cleanup (pods, containers, images; expect 0 0 0): $left"
[[ $FAIL -eq 0 && $left == "0 0 0 " ]]
