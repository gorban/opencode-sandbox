#!/usr/bin/env bash
# Spike e1: which clients enforce X.509 name constraints on an oc-sandbox CA?
# Re-runnable. Run from the devbox distrobox (podman and openssl run on the host through
# distrobox-host-exec). Everything lives in one mktemp -d directory under <repo>/.scratch/ and in
# named pod/container resources use oc-spike-e1-*; images are untagged and carry a run label.
# Podman ID receipts constrain the EXIT trap to resources this run created.
#   probe.sh [--skip-chromium] [--skip-go] [--skip-pg] [--keep-images] [--keep-scratch]
# Output: matrix on stdout (also $W/matrix.txt). Exit status 1 = the run is invalid (setup failed, a
# result row is missing, a rejection lacks recognized verification evidence, or the unconstrained control CA X did
# not behave as expected), so a "reject" can never come from a broken setup.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(git -C "$HERE" rev-parse --show-toplevel)
H=(); command -v distrobox-host-exec >/dev/null 2>&1 && H=(distrobox-host-exec)
pm() { "${H[@]}" podman "$@"; }
HOSTSSL=("${H[@]}" openssl)
PY_IMG=docker.io/library/python:3.12-alpine
NODE_IMG=${NODE_IMG:-docker.io/library/node:24-alpine}
GO_IMG=${GO_IMG:-docker.io/library/golang:alpine}
PG_IMG=docker.io/library/postgres:17
SKIP_CHROMIUM=0; SKIP_GO=0; SKIP_PG=0; KEEP_IMAGES=0; KEEP_SCRATCH=0
for a in "$@"; do case $a in
  --skip-chromium) SKIP_CHROMIUM=1;; --skip-go) SKIP_GO=1;; --skip-pg) SKIP_PG=1;;
  --keep-images) KEEP_IMAGES=1;; --keep-scratch) KEEP_SCRATCH=1;;
  *) echo "unknown arg $a" >&2; exit 2;; esac; done

log() { printf '== %s\n' "$*" >&2; }
die() { printf 'PROBE INVALID: %s\n' "$*" >&2; exit 1; }
must() { "$@" || die "setup step failed: $*"; }

# ---------------------------------------------------------------- scratch dir (this run only)
SCR=$ROOT/.scratch
[[ -L "$SCR" ]] && die "$SCR is a symlink"
mkdir -p "$SCR" || die "cannot create $SCR"
W=$(mktemp -d "$SCR/e1-run.XXXXXX") || die "mktemp failed"
case $(realpath -e -- "$W") in "$(realpath -e -- "$ROOT")/.scratch/e1-run."*) ;; *) die "scratch dir outside $ROOT/.scratch: $W";; esac
W_OWNED=1
# The unpredictable mktemp suffix separates simultaneous and interrupted runs.
P=oc-spike-e1-$(printf %s "${W##*.}" | tr A-Z a-z)
POD=$P-pod
OWNER=oc-spike-e1-${W##*.}

# ---------------------------------------------------------------- resources this run creates
CTR_N=0
mkdir -p "$W/ids" || die "cannot create ID directory"
CTRS=($P-srv $P-pg)
# Only remove resources carrying this run's unpredictable ownership label.
owned() {
  local kind=$1 name=$2 fmt
  case $kind in
    image) fmt='{{ index .Config.Labels "oc.spike.e1.owner" }}';;
    container) fmt='{{ index .Config.Labels "oc.spike.e1.owner" }}';;
    pod) fmt='{{ index .Labels "oc.spike.e1.owner" }}';;
    *) return 1;;
  esac
  [[ "$(pm "$kind" inspect --format "$fmt" "$name" 2>/dev/null)" = "$OWNER" ]]
}

# Files are created by Podman only after resource creation, not from candidate names.
# Require a full immutable ID: never let an empty, abbreviated or forged value resolve as a name.
read_id() {
  local receipt=$1 id
  [[ -f "$receipt" ]] && [[ ! -L "$receipt" ]] || return 1
  id=$(<"$receipt")
  id=${id#sha256:}
  [[ $id =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "$id"
}
remove_id() {
  local kind=$1 file=$2 id rc
  local -a remove_argv
  case $kind in
    container) remove_argv=(rm -f);;
    pod) remove_argv=(pod rm);;
    image) remove_argv=(rmi);;
    *) log "unsupported resource kind: $kind"; return 1;;
  esac
  [[ -e "$file" ]] || [[ -L "$file" ]] || return 0
  id=$(read_id "$file") || { log "invalid $kind ID receipt: $file"; return 1; }
  pm "$kind" exists "$id" >/dev/null 2>&1; rc=$?
  [[ "$rc" = 1 ]] && return 0  # auto-removed one-shot container
  [[ "$rc" = 0 ]] || { log "cannot check $kind ID $id"; return 1; }
  owned "$kind" "$id" || { log "$kind ID $id does not have this run's owner label"; return 1; }
  pm "${remove_argv[@]}" "$id" >/dev/null || { log "could not remove $kind ID $id"; return 1; }
}
cleanup() {
  local status=$? failed=0 f
  trap - EXIT
  log "cleanup"
  for f in "$W"/ids/ctr-*; do remove_id container "$f" || failed=1; done
  remove_id pod "$W/ids/pod" || failed=1
  if [[ "$KEEP_IMAGES" = 0 ]]; then
    for f in "$W"/ids/img-*; do remove_id image "$f" || failed=1; done
  fi
  # Keep receipts if cleanup fails, so the exact IDs can be inspected and removed safely.
  if [[ "$failed" = 1 ]]; then
    log "cleanup incomplete; receipts retained in $W/ids"
    [[ "$status" = 0 ]] && status=1
  elif [[ "$KEEP_SCRATCH" = 0 ]] && [[ "${W_OWNED:-0}" = 1 ]] && [[ -d "$W" ]] && [[ ! -L "$W" ]] &&
     [[ $(realpath -e -- "$W") == "$(realpath -e -- "$ROOT")/.scratch/e1-run."* ]]; then
    rm -rf -- "$W"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
pm pod exists "$POD" && die "pod $POD already exists"
for c in "${CTRS[@]}"; do pm container exists "$c" && die "container $c already exists"; done

# ---------------------------------------------------------------- 1. PKI
gen() {
  log "generating CAs and leaves in $W with $("${HOSTSSL[@]}" version)"
  mkdir -p "$W/ca" "$W/leaf" "$W/results" "$W/img" || die "mkdir"
  cp "$HERE/leaves.tsv" "$HERE/variants.tsv" "$W/" || die "cp"
  : > "$W/combos.tsv"
  local vi=0 li
  while IFS=$'\t' read -r V NC; do
    mkdir -p "$W/ca/$V"
    must "${HOSTSSL[@]}" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/ca/$V/ca.key"
    # distrobox-host-exec does not pass the environment on, so the $ENV:: placeholders in the
    # templates are substituted into a per-CA config file here (recommended.sh uses the env form).
    local sect=v3_ca ncv=$NC tmpl; tmpl=$(<"$HERE/ca.cnf")
    [[ "$NC" = - ]] && { sect=v3_ca_unconstrained; ncv=x; }
    printf '%s\n' "${tmpl//'$ENV::OC_NC'/$ncv}" > "$W/ca/$V/ca.cnf"
    must "${HOSTSSL[@]}" req -x509 -new -key "$W/ca/$V/ca.key" -config "$W/ca/$V/ca.cnf" -extensions $sect \
      -days 3650 -sha256 -out "$W/ca/$V/ca.pem"
    if [[ "$NC" != - ]]; then   # the constraint really is in the certificate, and critical
      "${HOSTSSL[@]}" x509 -in "$W/ca/$V/ca.pem" -noout -text | grep -q 'Name Constraints: critical' \
        || die "CA $V has no critical nameConstraints"
    fi
    # attack material (leaves.tsv column 5): a twin of the CA (same key and subject, no constraints,
    # served as an intermediate) and an unconstrained intermediate with another subject
    must "${HOSTSSL[@]}" req -x509 -new -key "$W/ca/$V/ca.key" -config "$W/ca/$V/ca.cnf" -extensions v3_ca_unconstrained \
      -days 3650 -sha256 -out "$W/ca/$V/twin.pem"
    must "${HOSTSSL[@]}" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/ca/$V/int.key"
    must "${HOSTSSL[@]}" req -new -key "$W/ca/$V/int.key" -subj "/O=oc-sandbox/CN=evil intermediate" -out "$W/ca/$V/int.req"
    must "${HOSTSSL[@]}" x509 -req -in "$W/ca/$V/int.req" -CA "$W/ca/$V/ca.pem" -CAkey "$W/ca/$V/ca.key" \
      -CAcreateserial -CAserial "$W/ca/$V/serial-int" -extfile "$W/ca/$V/ca.cnf" -extensions v3_intermediate_unconstrained \
      -days 3650 -sha256 -out "$W/ca/$V/int.pem"
    li=0
    while IFS=$'\t' read -r L CN SAN CHECK MODE; do
      mkdir -p "$W/leaf/$L"
      local subj="/CN=$CN"; [[ "$CN" = - ]] && subj="/O=oc-sandbox"   # "-" = subject without any CN
      if [[ ! -f "$W/leaf/$L/key.pem" ]]; then
        must "${HOSTSSL[@]}" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$W/leaf/$L/key.pem"
        must "${HOSTSSL[@]}" req -new -key "$W/leaf/$L/key.pem" -subj "$subj" -out "$W/leaf/$L/req.pem"
      fi
      local lsect=v3_leaf sanv=$SAN ltmpl; ltmpl=$(<"$HERE/leaf.cnf")
      [[ "$SAN" = - ]] && { lsect=v3_leaf_nosan; sanv=x; }
      printf '%s\n' "${ltmpl//'$ENV::OC_SAN'/$sanv}" > "$W/leaf/$L/leaf.cnf"
      local sca=$W/ca/$V/ca.pem skey=$W/ca/$V/ca.key
      rm -f -- "$W/leaf/$L/$V.chain.pem"
      case $MODE in
        plain) ;;
        twin) sca=$W/ca/$V/twin.pem; must cp "$sca" "$W/leaf/$L/$V.chain.pem";;
        unc)  sca=$W/ca/$V/int.pem; skey=$W/ca/$V/int.key; must cp "$sca" "$W/leaf/$L/$V.chain.pem";;
        *) die "unknown mode $MODE in leaves.tsv";;
      esac
      must "${HOSTSSL[@]}" x509 -req -in "$W/leaf/$L/req.pem" -CA "$sca" -CAkey "$skey" \
        -CAcreateserial -CAserial "$W/ca/$V/serial-$MODE" -extfile "$W/leaf/$L/leaf.cnf" -extensions $lsect \
        -days 30 -sha256 -out "$W/leaf/$L/$V.pem"
      [[ -s "$W/leaf/$L/$V.pem" ]] || die "leaf $L/$V was not written"
      local kind=dns; [[ $CHECK =~ ^[0-9.]+$ || $CHECK == *:* ]] && kind=ip
      printf '%s\t%s\t%s\t%s\t%s\n' "$V" "$L" "$((20000 + vi*100 + li))" "$CHECK" "$kind" >> "$W/combos.tsv"
      li=$((li+1))
    done < "$HERE/leaves.tsv"
    vi=$((vi+1))
  done < "$HERE/variants.tsv"
  chmod -R a+rX "$W"
  # hosts file for all containers: every test name resolves to loopback inside the pod
  printf '127.0.0.1 localhost\n::1 localhost\n127.0.0.1 feat-a.oc-sandbox.internal oc-sandbox.internal app.localhost foo.oc-sandbox.internal a.b.oc-sandbox.internal evil-oc-sandbox.internal evil.example.com example.com\n' > "$W/hosts"
}

# The exact commands quoted in prd_e1.md, run for the two recommended CA variants (D and E).
recommended() {
  log "recommended.sh (the PRD snippet) for variants D and E"
  local variant constraints san
  for variant in D E; do
    constraints=$(awk -F'\t' -v v=$variant '$1==v{print $2}' "$HERE/variants.tsv")
    san='DNS:feat-a.oc-sandbox.internal'; [[ $variant = D ]] && san='DNS:feat-a.oc-sandbox.internal,DNS:localhost,IP:127.0.0.1,IP:::1'
    must "${H[@]}" bash "$HERE/recommended.sh" "$W/rec-$variant" "$HERE" feat-a.oc-sandbox.internal "$constraints" "$san"
    "${HOSTSSL[@]}" verify -CAfile "$W/rec-$variant/ca.pem" -verify_hostname feat-a.oc-sandbox.internal "$W/rec-$variant/cert.pem" >/dev/null \
      || die "recommended leaf for $variant does not verify"
    "${HOSTSSL[@]}" x509 -in "$W/rec-$variant/ca.pem" -noout -text | grep -q 'Name Constraints: critical' || die "recommended CA $variant lacks nameConstraints"
    [[ "$(stat -c %a "$W/rec-$variant/ca.key")" = 600 ]] || die "ca.key is not 0600"
    echo "recommended $variant: leaf verifies, nameConstraints critical, ca.key 0600" >> "$W/results/recommended.txt"
  done
}

# ---------------------------------------------------------------- 2. images, pod, servers
crun() {  # one-shot named container in the pod; extra podman args first, then image and command
  CTR_N=$((CTR_N+1)); local n=$P-c$CTR_N
  pm container exists "$n" && die "container $n already exists"
  pm run --rm --cidfile "$W/ids/ctr-$CTR_N" --label "oc.spike.e1.owner=$OWNER" --name "$n" --pod "$POD_ID" --no-hosts --security-opt label=disable \
    -v "$W":/w:ro -v "$HERE/clients":/c:ro -v "$W/hosts":/etc/hosts:ro "$@"
}

build_images() {
  log "building untagged images with per-run ownership labels"
  printf 'FROM docker.io/library/alpine:3.22\nRUN apk add --no-cache openssl curl iproute2 bash\n' > "$W/img/Containerfile.alpine"
  must pm build -q --iidfile "$W/ids/img-alpine" --label "oc.spike.e1.owner=$OWNER" -f "$W/img/Containerfile.alpine" "$W/img" >/dev/null
  ALPINE_ID=$(read_id "$W/ids/img-alpine") || die "missing alpine image ID"
  if [[ $SKIP_CHROMIUM = 0 ]]; then
    printf 'FROM registry.fedoraproject.org/fedora:latest\nRUN dnf install -y chromium curl nss-tools openssl && dnf clean all\n' > "$W/img/Containerfile.chromium"
    must pm build -q --iidfile "$W/ids/img-chromium" --label "oc.spike.e1.owner=$OWNER" -f "$W/img/Containerfile.chromium" "$W/img" >/dev/null
    CHROMIUM_ID=$(read_id "$W/ids/img-chromium") || die "missing chromium image ID"
  fi
}

start_pod() {
  log "starting pod (network none: nothing leaves the host) and the s_server fleet"
  must pm pod create --pod-id-file "$W/ids/pod" --label "oc.spike.e1.owner=$OWNER" --name "$POD" --network none >/dev/null
  POD_ID=$(read_id "$W/ids/pod") || die "missing pod ID"
  # 8.8.8.8 and 2001:db8::1 are loopback aliases inside the pod's private netns (servers.sh)
  must pm run -d --cidfile "$W/ids/ctr-srv" --label "oc.spike.e1.owner=$OWNER" --name $P-srv --pod "$POD_ID" --no-hosts --security-opt label=disable --cap-add NET_ADMIN \
    -v "$W":/w:ro -v "$HERE/clients":/c:ro -v "$W/hosts":/etc/hosts:ro "$ALPINE_ID" bash /c/servers.sh >/dev/null
  SRV_ID=$(read_id "$W/ids/ctr-srv") || die "missing server container ID"
  local want got=
  want=$(wc -l < "$W/combos.tsv")
  for _ in $(seq 1 60); do
    got=$(pm logs "$SRV_ID" 2>&1 | sed -n 's/^ready \([0-9]*\)$/\1/p' | head -1)
    [[ -n "$got" ]] && break; sleep 0.5
  done
  [[ "$got" = "$want" ]] || { pm logs "$SRV_ID" 2>&1 | tail -5 >&2; die "s_server fleet: $got of $want servers listening"; }
  log "$got servers listening"
}

# ---------------------------------------------------------------- 3. clients
run_clients() {
  local results=$W/results
  log "openssl verify, host"
  OC_W=$W bash "$HERE/clients/openssl_verify.sh" "${HOSTSSL[@]}" > "$results/openssl-host-verify.tsv" 2> "$results/openssl-host-verify.err" || die "host OpenSSL client setup failed"
  log "openssl verify + s_client, curl (alpine)"
  # Keep the shared workspace read-only. The host owns the result filenames.
  crun "$ALPINE_ID" bash /c/openssl_verify.sh openssl > "$results/openssl-alpine-verify.tsv" 2>> "$results/alpine.err" || die "alpine OpenSSL client setup failed"
  crun "$ALPINE_ID" bash /c/sclient.sh > "$results/openssl-alpine-sclient.tsv" 2>> "$results/alpine.err" || die "alpine OpenSSL client setup failed"
  crun "$ALPINE_ID" bash /c/curl.sh > "$results/curl.tsv" 2>> "$results/alpine.err" || die "alpine OpenSSL client setup failed"
  log "python"
  crun $PY_IMG python -I /c/py_tls.py > "$results/python.tsv" 2>"$results/python.err" || die "python client failed"
  log "node (NODE_EXTRA_CA_CERTS)"
  crun $NODE_IMG sh -c 'set -e; for V in $(cut -f1 /w/variants.tsv); do NODE_EXTRA_CA_CERTS=/w/ca/$V/ca.pem node /c/node_tls.mjs $V; done' > "$results/node.tsv" 2>"$results/node.err" || die "node client failed"
  if [[ $SKIP_GO = 0 ]]; then
    log "go"
    crun -e GOCACHE=/tmp/gocache -e HOME=/tmp -e GOFLAGS=-mod=mod -e GOTOOLCHAIN=local $GO_IMG sh -c 'cd /tmp && mkdir -p g && cp /c/go_tls.go g/main.go && cd g && go mod init x >/dev/null 2>&1; go run .' > "$results/go.tsv" 2>"$results/go.err" || die "go client failed"
  fi
  if [[ $SKIP_PG = 0 ]]; then
    log "psql sslmode=verify-full against postgres:17"
    run_pg > "$results/psql.tsv" 2>"$results/psql.err" || die "postgres client setup failed"
  fi
  if [[ $SKIP_CHROMIUM = 0 ]]; then
    log "chromium headless (scratch NSS db per CA)"
    crun "$CHROMIUM_ID" bash /c/chromium.sh > "$results/chromium.tsv" 2>"$results/chromium.err" || die "chromium client failed"
    log "nss certutil -V (chain only)"
    crun "$CHROMIUM_ID" bash /c/nss_certutil.sh > "$results/nss-certutil.tsv" 2>"$results/nss-certutil.err" || die "NSS client setup failed"
  fi
}

run_pg() {
  # postgres is started by hand (not as PID 1) so it can be restarted with each certificate
  pm run -d --cidfile "$W/ids/ctr-pg" --label "oc.spike.e1.owner=$OWNER" --name $P-pg --pod "$POD_ID" --no-hosts --security-opt label=disable --entrypoint sleep \
    -v "$W":/w:ro -v "$HERE/clients":/c:ro -v "$W/hosts":/etc/hosts:ro $PG_IMG infinity >/dev/null || return 1
  local pg_id; pg_id=$(read_id "$W/ids/ctr-pg") || return 1
  pm exec -u postgres "$pg_id" bash -c 'initdb -D /tmp/pgdata --auth=trust >/dev/null && mkdir -p /tmp/pgssl && psql --version' >&2 || return 1
  pm exec -u postgres "$pg_id" bash /c/psql.sh
}

main() {
  gen
  recommended
  build_images
  start_pod
  run_clients
  local exp="Hvfy,Hvfy+h,Avfy,Avfy+h,s_cli,curl,py,node"
  [[ $SKIP_GO = 0 ]] && exp+=",go"; [[ $SKIP_PG = 0 ]] && exp+=",psql"; [[ $SKIP_CHROMIUM = 0 ]] && exp+=",chrom,nss"
  (cd -P -- "$W" && OC_E1_EXPECT=$exp exec python3 -I "$HERE/matrix.py") > "$W/matrix.txt"
  local rc=$?
  cat "$W/matrix.txt" "$W/results/recommended.txt"
  [[ $rc = 0 ]] || { log "PROBE INVALID: see the CHECKS section above"; exit 1; }
}
[[ -n "${OC_E1_NOMAIN:-}" ]] || main
