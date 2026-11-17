#!/usr/bin/env bash
# Spike f probe: host tools (mkcert, NSS certutil, OpenSSL) pinned and checksummed through mise.
#
# Re-runnable. Optional: PROBE_NEWER_MISE=2026.11.8 also downloads that mise (180 MB, sha256 pinned) into scratch and checks it regenerates the same lock content. Needs network access to public registries (github.com, conda.anaconda.org) on first run.
# Ends with "ALL CHECKS PASSED" only if: no check failed, no setup step failed unexpectedly, and the number
# of checks that ran equals EXPECTED_CHECKS (so a skipped or crashed section cannot go unnoticed).
#
# Scratch safety (the script deletes things, so it is strict about where):
#   - PROBE_SCRATCH (default <worktree>/.scratch) must be an absolute path with no "..", ".", "//" or
#     symlink component, inside <worktree>/.scratch. Anything else is refused before anything is written.
#   - Every run works in its own mktemp -d directory below it, and the EXIT trap deletes only that
#     directory, and only if it is still the same directory (device:inode), not a symlink, and still a
#     direct child of the base. Section 0 tests this with hostile values.
# Isolation:
#   - All inherited MISE_* variables are unset first (they can inject configs), then ours are set to scratch.
#   - mkcert, certutil and openssl run with HOME and XDG_{DATA,CONFIG,CACHE,STATE}_HOME in scratch, so the
#     real ~/.pki/nssdb, ~/.local/share/pki/nssdb, ~/.local/share/mkcert, Firefox profiles and Flatpak
#     (~/.var/app) dbs are not reachable. NEVER run certutil against a copy of /etc/pki/nssdb or
#     "sql:/etc/pki/nssdb" with a real HOME: that db loads libnsssysinit, which redirects to the user's db
#     (see the PRD; this bit the spike once). The real Flatpak dbs are never opened: only stat/find.
#   - A stub `sudo` that always fails shadows the real one for mkcert probes; no root, no system trust store.
# Before and after, the real mise dirs, ~/.pki, ~/.local/share/{pki,mkcert}, /etc/pki/nssdb and every NSS
# file under ~/.var/app and the Firefox profile dirs are fingerprinted; any change fails the run.
set -u -o pipefail
exec </dev/null   # nothing may ever wait for input (certutil would prompt for a password)

EXPECTED_CHECKS=123

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SELF=$HERE/$(basename "${BASH_SOURCE[0]}")
REPO=$(git -C "$HERE" rev-parse --show-toplevel) || exit 2
REPO=$(realpath -e -- "$REPO") || exit 2
GITCOMMON=$(realpath -e -- "$(git -C "$REPO" rev-parse --git-common-dir)") || exit 2

# --- scratch path validation (no side effects) ---
scratch_base_ok() { # $1 candidate; returns 0 only for a clean absolute path under <worktree>/.scratch
  local cand=$1 rel comp cur
  [ -n "$cand" ] || return 1
  case $cand in /*) ;; *) return 1 ;; esac
  case $cand in *$'\n'*) return 1 ;; esac
  case "$cand/" in */../*|*/./*|*//*) return 1 ;; esac
  case $cand in "$REPO/.scratch"|"$REPO/.scratch/"*) ;; *) return 1 ;; esac
  rel=${cand#"$REPO"/}
  cur=$REPO
  local -a parts; IFS=/ read -ra parts <<<"$rel"
  for comp in "${parts[@]}"; do
    cur=$cur/$comp
    [ -L "$cur" ] && return 1
    if [ -e "$cur" ] && [ ! -d "$cur" ]; then return 1; fi
  done
  [ "$(realpath -m -- "$cand")" = "$cand" ] || return 1
  return 0
}
remove_run_dir() { # $1 dir $2 expected dev:inode $3 expected parent; deletes only if it is still our directory
  local d=$1 id=$2 parent=$3
  [ -n "$d" ] && [ -n "$id" ] && [ -n "$parent" ] || { echo "remove_run_dir: missing argument" >&2; return 1; }
  if [ -d "$d" ] && [ ! -L "$d" ] && [ "$(stat -c %d:%i -- "$d")" = "$id" ] &&
     [ "$(realpath -e -- "$d")" = "$d" ] && [ "$(dirname -- "$d")" = "$parent" ]; then
    rm -rf --one-file-system -- "$d"
  else
    echo "refusing to delete $d: it is not the directory this run created" >&2
    return 1
  fi
}

BASE_IN=${PROBE_SCRATCH-$REPO/.scratch}
if ! scratch_base_ok "$BASE_IN"; then
  echo "refused: PROBE_SCRATCH='$BASE_IN' is not a clean absolute path inside $REPO/.scratch" >&2
  exit 2
fi
BASE=$BASE_IN
if [ -e "$BASE" ]; then
  [ -d "$BASE" ] && [ ! -L "$BASE" ] && [ -O "$BASE" ] || { echo "refused: $BASE is not a real directory owned by you" >&2; exit 2; }
else
  mkdir -p -- "$BASE" || exit 2
  scratch_base_ok "$BASE" && [ -d "$BASE" ] && [ ! -L "$BASE" ] || { echo "refused: $BASE changed while creating it" >&2; exit 2; }
fi
SCRATCH=$(mktemp -d "$BASE/probe-f.XXXXXX") || exit 2
RUN_ID=$(stat -c %d:%i -- "$SCRATCH")
[ "$(realpath -e -- "$SCRATCH")" = "$SCRATCH" ] && [ "$(dirname -- "$SCRATCH")" = "$BASE" ] || { echo "unexpected run dir $SCRATCH" >&2; exit 2; }
cleanup() { [ "${KEEP:-0}" = 1 ] || remove_run_dir "$SCRATCH" "$RUN_ID" "$BASE"; }
trap cleanup EXIT
grep -qx '.scratch/' "$GITCOMMON/info/exclude" 2>/dev/null || echo '.scratch/' >> "$GITCOMMON/info/exclude"

REPO_TOP_BEFORE=$(ls -A "$REPO" | sort | sha256sum | cut -d' ' -f1)
TAB=$'\t'

# --- check framework ---
CHECKS=0; FAILS=0; UNEXPECTED=0
pass() { CHECKS=$((CHECKS + 1)); echo "PASS  $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); echo "FAIL  $*"; }
unexpected() { UNEXPECTED=$((UNEXPECTED + 1)); echo "UNEXPECTED  $*"; }
section() { printf '\n### %s\n' "$*"; }
shorten() { python3 -c 'import sys; sys.stdout.write(sys.stdin.read().replace(sys.argv[1] + "/", ""))' "$SCRATCH"; }
tail2() { printf '%s' "$1" | tail -2 | tr '\n' ' ' | cut -c1-240; }
run() { OUT=$("$@" 2>&1); RC=$?; }                       # sets OUT and RC
must() { run "$@"; if [ "$RC" -ne 0 ]; then unexpected "setup step rc=$RC: $* :: $(tail2 "$OUT")"; return 1; fi; }
expect_ok() { local d=$1; shift; run "$@"; [ "$RC" -eq 0 ] && pass "$d" || fail "$d (rc=$RC: $(tail2 "$OUT"))"; }
expect_out() { local d=$1 re=$2; shift 2; run "$@"; if [ "$RC" -eq 0 ] && grep -Eq -- "$re" <<<"$OUT"; then pass "$d"; else fail "$d (rc=$RC, wanted /$re/: $(tail2 "$OUT"))"; fi; }
expect_text() { local d=$1 re=$2; shift 2; run "$@"; if grep -Eq -- "$re" <<<"$OUT"; then pass "$d"; else fail "$d (rc=$RC, wanted /$re/: $(tail2 "$OUT"))"; fi; }   # ignores rc
expect_not_text() { local d=$1 re=$2; shift 2; run "$@"; if [ "$RC" -eq 0 ] && ! grep -Eq -- "$re" <<<"$OUT"; then pass "$d"; else fail "$d (rc=$RC, unwanted /$re/: $(tail2 "$OUT"))"; fi; }
expect_fail() { local d=$1 re=$2; shift 2; run "$@"; if [ "$RC" -ne 0 ] && grep -Eq -- "$re" <<<"$OUT"; then pass "$d (rc=$RC, matched /$re/)"; else fail "$d (rc=$RC, wanted nonzero and /$re/: $(tail2 "$OUT"))"; fi; }
expect_true() { local d=$1; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }

# --- real-state fingerprint (read-only) ---
fingerprint() {
  {
    for d in "$HOME/.local/share/mise" "$HOME/.config/mise" "$HOME/.cache/mise" "$HOME/.local/state/mise" \
             "$HOME/.pki" "$HOME/.local/share/pki" "$HOME/.local/share/mkcert" /etc/pki/nssdb; do
      echo "## $d"
      find "$d" -printf '%p %T@ %s\n' 2>/dev/null | sort
    done
    for d in "$HOME/.mozilla" "$HOME/.config/mozilla" "$HOME/snap/firefox" "$HOME/.var/app"; do
      echo "## $d (NSS files)"
      find "$d" -maxdepth 8 \( -name cert9.db -o -name cert8.db -o -name key4.db -o -name pkcs11.txt \) -printf '%p %T@ %s\n' 2>/dev/null | sort
    done
    find "$HOME/.pki" "$HOME/.local/share/pki" "$HOME/.local/share/mkcert" /etc/pki/nssdb "$HOME/.mozilla" "$HOME/.config/mozilla" "$HOME/.var/app" \
         -maxdepth 8 \( -name cert9.db -o -name key4.db -o -name 'rootCA*.pem' \) -exec sha256sum {} + 2>/dev/null | sort
  } | sha256sum | cut -d' ' -f1
}
BEFORE=$(fingerprint)

# -------------------------------------------------------------------------------------------------
section "0. scratch safety self-tests (hostile PROBE_SCRATCH values are refused before anything is written)"
ST=$SCRATCH/selftest; mkdir "$ST" "$ST/real"; ln -s "$ST/real" "$ST/link"
ESC=zz-probe-f-escape-$$
SNAP_BEFORE=$({ ls -A "$REPO"; find "$REPO/.scratch" -maxdepth 1 | sort; } | sha256sum)
hostile=(
  "$REPO/.scratch/../.git"
  "$REPO/.scratch/x/../../../$ESC"
  "$REPO/.git"
  "$REPO"
  "$GITCOMMON"
  "/"
  "$HOME"
  "relative/dir"
  ""
  "$ST/link"
  "$ST/link/sub"
  "$REPO/.scratch/./x"
  "$REPO/.scratch//x"
  "$REPO/.scratch-evil"
)
for h in "${hostile[@]}"; do
  run env PROBE_SCRATCH="$h" bash "$SELF"
  if [ "$RC" -eq 2 ] && grep -q '^refused' <<<"$OUT"; then pass "hostile PROBE_SCRATCH refused (rc 2): '${h/#$REPO/<repo>}'"
  else fail "hostile PROBE_SCRATCH not refused: '$h' (rc=$RC: $(tail2 "$OUT"))"; fi
done
SNAP_AFTER=$({ ls -A "$REPO"; find "$REPO/.scratch" -maxdepth 1 | sort; } | sha256sum)
[ "$SNAP_BEFORE" = "$SNAP_AFTER" ] && [ ! -e "$REPO/$ESC" ] && [ ! -e "$REPO/.scratch/x" ] && pass "refused runs wrote nothing (repo root and .scratch listing unchanged, no escape dir)" || fail "a refused run changed the repo root or .scratch"
# the trap's deletion guard
mkdir "$ST/victim"; VID=$(stat -c %d:%i "$ST/victim")
rmdir "$ST/victim"; ln -s "$ST/real" "$ST/victim"; touch "$ST/real/keep"
run remove_run_dir "$ST/victim" "$VID" "$ST"
[ "$RC" -ne 0 ] && [ -e "$ST/real/keep" ] && pass "delete guard: a directory replaced by a symlink is not followed or deleted" || fail "delete guard followed a symlink"
rm -f "$ST/victim"; mkdir "$ST/victim2"; run remove_run_dir "$ST/victim2" "1:1" "$ST"
[ "$RC" -ne 0 ] && [ -d "$ST/victim2" ] && pass "delete guard: a directory with a different device:inode is not deleted" || fail "delete guard deleted a different directory"
mkdir "$ST/victim3"; V3=$(stat -c %d:%i "$ST/victim3"); run remove_run_dir "$ST/victim3" "$V3" "$ST/elsewhere"
[ "$RC" -ne 0 ] && [ -d "$ST/victim3" ] && pass "delete guard: a directory outside the expected parent is not deleted" || fail "delete guard ignored the parent check"
run remove_run_dir "$ST/victim3" "$V3" "$ST"
[ "$RC" -eq 0 ] && [ ! -e "$ST/victim3" ] && pass "delete guard: the directory this run created is deleted" || fail "delete guard refused a legitimate delete"

command -v mise >/dev/null || { echo "mise is required (https://mise.jdx.dev). Not installing it." >&2; exit 2; }
mkdir -p "$SCRATCH"/{mise/data,mise/cache,mise/config,mise/state,home,proj,stub,ca,out,state}
H=$SCRATCH/home P=$SCRATCH/proj
INHERITED_MISE=$(compgen -e | grep '^MISE_' | tr '\n' ' ')
for v in $INHERITED_MISE; do unset "$v"; done
mkdir -p "$H/.pki/nssdb" "$H/.local/share" "$H/.config" "$H/.cache" "$H/.local/state"
export XDG_DATA_HOME=$H/.local/share XDG_CONFIG_HOME=$H/.config XDG_CACHE_HOME=$H/.cache XDG_STATE_HOME=$H/.local/state
export MISE_DATA_DIR=$SCRATCH/mise/data MISE_CACHE_DIR=$SCRATCH/mise/cache
export MISE_CONFIG_DIR=$SCRATCH/mise/config MISE_STATE_DIR=$SCRATCH/mise/state
export MISE_CEILING_PATHS=$SCRATCH MISE_NO_ENV=1 MISE_NO_HOOKS=1
cp "$HERE/mise.toml" "$HERE/mise.lock" "$P/"   # work on a copy so mise never rewrites the committed lock
mxr() { mise --cd "$P" exec -- "$@"; }                 # real HOME: only for mise-level checks
mx()  { HOME=$H mise --cd "$P" exec -- "$@"; }          # scratch HOME: everything that touches NSS
tenv() { env MISE_DATA_DIR=$T/data MISE_CACHE_DIR=$T/cache MISE_CONFIG_DIR=$T/config MISE_STATE_DIR=$T/state "$@"; }
scrub() { # delete a path, but only inside this run's scratch dir
  local p
  for p in "$@"; do
    case $p in "$SCRATCH"/?*) ;; *) unexpected "scrub refused $p"; return 1 ;; esac
    case "$p/" in */../*) unexpected "scrub refused $p"; return 1 ;; esac
    rm -rf --one-file-system -- "$p"
  done
}

# -------------------------------------------------------------------------------------------------
section "1. versions and install (real HOME, MISE_*_DIR in scratch)"
mise --version 2>/dev/null | head -1
must mise trust "$P/mise.toml"
expect_ok "mise install (locked mode) succeeds" mise --cd "$P" install; echo "$OUT" | tail -4 | shorten
run mise --cd "$P" ls; echo "$OUT" | shorten
for tl in 'aqua:FiloSottile/mkcert +1\.4\.4' 'conda:nss +3\.118' 'conda:openssl +3\.5\.9'; do
  grep -Eq -- "$tl" <<<"$OUT" && pass "pinned: $tl" || fail "pin missing in mise ls: $tl"
done
expect_out "mkcert -version is v1.4.4" '^v1\.4\.4$' mxr mkcert -version
expect_out "openssl is 3.5.9" '^OpenSSL 3\.5\.9 ' mxr openssl version
expect_text "certutil runs (-H prints usage; rc is 1 by design)" 'Add a certificate to the database' mxr certutil -H
CU=$(mise --cd "$P" which certutil); echo "mise which certutil -> ${CU#"$SCRATCH"/}"
CUREAL=$(dirname "$(dirname "$CU")")/bin/certutil
expect_true "certutil real binary exists" test -x "$CUREAL"
run ldd "$CUREAL"; echo "$OUT" | shorten
[ "$RC" -eq 0 ] && ! grep -q 'not found' <<<"$OUT" && pass "certutil: ldd succeeds, no missing shared libs" || fail "certutil has missing shared libs or ldd failed"
echo "--- cost of one 'mise exec -- true':"; ( time mxr true ) 2>&1 | grep real

section "1b. lock file: reproduces, covers both platforms, artifacts match, tamper detected"
run grep -cE '^\[tools\."[^"]+"\."platforms\.linux-(x64|arm64)"\]' "$HERE/mise.lock"
[ "$OUT" = 6 ] && pass "lock has linux-x64 and linux-arm64 entries for all 3 tools" || fail "lock platform entries: $OUT (want 6)"
mkdir -p "$SCRATCH/regen"; cp "$HERE/mise.toml" "$SCRATCH/regen/"
must mise trust "$SCRATCH/regen/mise.toml"
must mise --cd "$SCRATCH/regen" lock   # platforms come from lockfile_platforms in mise.toml
LOCKGEN=$(sed -n 's/^# mise\.lock generated with mise \([0-9.]*\).*/\1/p' "$HERE/mise.toml")
RUNMISE=$(mise --version 2>/dev/null | awk '{print $1}')
[ -n "$LOCKGEN" ] && pass "mise.toml records the mise version that generated the lock ($LOCKGEN)" || fail "mise.toml does not record the generator version"
[ "$LOCKGEN" = "$RUNMISE" ] || echo "WARN: running mise $RUNMISE differs from the lock generator $LOCKGEN; byte-level format may differ, content is compared below"
expect_ok "regenerated lock equals the committed lock except the lockfile_version line" bash -c 'diff <(grep -v "^lockfile_version" "$1") <(grep -v "^lockfile_version" "$2")' _ "$SCRATCH/regen/mise.lock" "$HERE/mise.lock"
expect_text "regenerated lock equals the committed lock by content (lockcmp.py: tools, URLs, checksums, conda packages)" ', 0 differ' python3 -I "$HERE/lockcmp.py" "$SCRATCH/regen/mise.lock" "$HERE/mise.lock"
echo "committed lock format: $(grep '^lockfile_version' "$HERE/mise.lock"); regenerated by $RUNMISE: $(grep '^lockfile_version' "$SCRATCH/regen/mise.lock")"
expect_fail "lockcmp.py detects a changed checksum" '^DIFF' bash -c 'sed "s/sha256:44dd98ff/sha256:00000000/" "$1" > "$2"; python3 -I "$3" "$2" "$1"' _ "$HERE/mise.lock" "$SCRATCH/regen/tampered.lock" "$HERE/lockcmp.py"
lockfile_sum() { awk -v t="[tools.\"$1\".\"platforms.linux-x64\"]" '$0==t{f=1;next} f&&/^checksum/{gsub(/.*sha256:|"/,"");print;exit}' "$HERE/mise.lock"; }
sha_of() { sha256sum -- "$1" | cut -d' ' -f1; }
for spec in "aqua:FiloSottile/mkcert|$SCRATCH/mise/data/installs/aqua-filo-sottile-mkcert/1.4.4/mkcert" \
            "conda:nss|$SCRATCH/mise/data/conda-packages/nss-3.118-h445c969_0.conda" \
            "conda:openssl|$SCRATCH/mise/data/conda-packages/openssl-3.5.9-h781a0a9_0.conda"; do
  tool=${spec%%|*}; f=${spec#*|}; want=$(lockfile_sum "$tool")
  [ -n "$want" ] && [ -f "$f" ] && [ "$(sha_of "$f")" = "$want" ] && pass "linux-x64 artifact sha256 matches mise.lock: $tool ${want:0:16}..." || fail "artifact sha256 differs from lock or file missing: $tool ($f)"
done
T=$SCRATCH/tamper; mkdir -p "$T"/{data,cache,config,state,proj}; cp "$HERE/mise.toml" "$HERE/mise.lock" "$T/proj/"
sed -i 's/sha256:44dd98ff/sha256:00000000/' "$T/proj/mise.lock"
grep -q 'sha256:00000000' "$T/proj/mise.lock" || unexpected "tamper edit did not apply"
expect_fail "tampered checksum: install fails" 'checksum mismatch' tenv mise --cd "$T/proj" install
cp "$HERE/mise.lock" "$T/proj/mise.lock"; sed -i 's/"3.118"/"3.117"/' "$T/proj/mise.toml"
grep -q '"3.117"' "$T/proj/mise.toml" || unexpected "version edit did not apply"
expect_fail "version not in the lock: install fails in locked mode" 'not in the lockfile|lockfile' tenv mise --cd "$T/proj" install
cp "$HERE/mise.lock" "$T/proj/mise.lock"; cp "$HERE/mise.toml" "$T/proj/mise.toml"; scrub "$T/data" "$T/state"
expect_out "untrusted plain [tools] config still runs (no mise trust needed)" 'v1\.4\.4' tenv mise --cd "$T/proj" exec -- mkcert -version

echo "--- a NEWER mise (downloaded into scratch only, sha256 pinned here; ~/.local/bin/mise is not touched) from the same pins"
NEWV=${PROBE_NEWER_MISE:-}; NEWSHA=32b6abe844efa43d37d7ac4ed21d2ec41e9479d66feb19b0db8d2c548cd6e36d
if [ -n "$NEWV" ]; then
  EXPECTED_CHECKS=$((EXPECTED_CHECKS + 5))
  NM=$SCRATCH/newmise; mkdir -p "$NM/proj" "$NM/proj2" "$NM/data" "$NM/cache" "$NM/config" "$NM/state"
  if run curl -fsSL --max-time 120 -o "$NM/mise" "https://github.com/jdx/mise/releases/download/v$NEWV/mise-v$NEWV-linux-x64" && [ "$(sha_of "$NM/mise")" = "$NEWSHA" ]; then
    pass "newer mise $NEWV downloaded into scratch, sha256 matches the value pinned in this script"; chmod +x "$NM/mise"
    nenv() { env MISE_DATA_DIR=$NM/data MISE_CACHE_DIR=$NM/cache MISE_CONFIG_DIR=$NM/config MISE_STATE_DIR=$NM/state "$NM/mise" "$@"; }
    cp "$HERE/mise.toml" "$HERE/mise.lock" "$NM/proj/"; cp "$HERE/mise.toml" "$NM/proj2/"
    expect_ok "newer mise installs from the committed (older-format) lock in locked mode" nenv --cd "$NM/proj" install
    expect_ok "newer mise leaves the committed lock file byte-identical" diff -q "$NM/proj/mise.lock" "$HERE/mise.lock"
    must nenv trust "$NM/proj2/mise.toml"; must nenv --cd "$NM/proj2" lock
    echo "newer mise lock format: $(grep '^lockfile_version' "$NM/proj2/mise.lock")"
    expect_text "newer mise regenerates the same artifacts and checksums (lockcmp.py --strict)" ', 0 differ' python3 -I "$HERE/lockcmp.py" --strict "$NM/proj2/mise.lock" "$HERE/mise.lock"
    run diff "$HERE/mise.lock" "$NM/proj2/mise.lock"; echo "full diff old vs new: $(tr '\n' ' ' <<<"$OUT")"
    [ "$(diff "$HERE/mise.lock" "$NM/proj2/mise.lock" | grep -c '^[<>]')" = 2 ] && pass "the only textual difference is the lockfile_version line" || fail "lock texts differ beyond lockfile_version"
  else
    fail "newer mise download or sha256 check failed ($(tail2 "$OUT"))"
  fi
else
  echo "(skipped: set PROBE_NEWER_MISE=2026.11.8 to test a newer mise; 180 MB download into scratch)"
fi

section "1c. missing mise: what the script should print (simulated with an empty PATH)"
expect_text "missing-mise message" 'mise is required for local HTTPS tools' env PATH=/nonexistent "$BASH" -c 'command -v mise >/dev/null || echo "oc-sandbox: mise is required for local HTTPS tools (https://mise.jdx.dev); not installed automatically"'

section "1d. mise environment hygiene"
run bash -c 'cd "$1" && mise config ls' _ "$P"; echo "$OUT" | shorten
grep -Eq 'docker|lima' <<<"$OUT" && fail "real global mise config leaked in" || pass "global mise config (docker/lima) does not leak with the four MISE_*_DIR vars"
echo "--- inherited MISE_* variables unset by this script: ${INHERITED_MISE:-<none>}"
printf '[tools]\n"aqua:jqlang/jq" = "1.7.1"\n' > "$SCRATCH/injected.toml"
expect_text "an inherited MISE_GLOBAL_CONFIG_FILE injects a config (hence: unset MISE_* first)" 'injected\.toml' bash -c 'cd "$1" && MISE_GLOBAL_CONFIG_FILE=$2 mise config ls' _ "$P" "$SCRATCH/injected.toml"
expect_not_text "after unsetting MISE_GLOBAL_CONFIG_FILE it is not listed" 'injected\.toml' bash -c 'cd "$1" && env -u MISE_GLOBAL_CONFIG_FILE mise config ls' _ "$P"
PT=$SCRATCH/paranoid; mkdir -p "$PT/proj" "$PT/state"; cp "$HERE/mise.toml" "$HERE/mise.lock" "$PT/proj/"
penv() { env MISE_STATE_DIR=$PT/state MISE_PARANOID=1 "$@"; }
expect_fail "MISE_PARANOID=1 refuses an untrusted tools/mise.toml" 'not trusted|trust' penv mise --cd "$PT/proj" exec -- mkcert -version
must penv mise trust "$PT/proj/mise.toml"
expect_out "MISE_PARANOID=1 + explicit trust works" 'v1\.4\.4' penv mise --cd "$PT/proj" exec -- mkcert -version

# -------------------------------------------------------------------------------------------------
section "2. CA variants (OpenSSL, EC P-256, PKCS#8): IP identities are ALWAYS constrained"
CA=$SCRATCH/ca
mkca() { # name nameConstraints-value ; key shared in $CA/pkcs8.key
  printf '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nO=oc-sandbox spike (throwaway)\nCN=oc-sandbox spike CA %s\n[v3]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n%s\n' \
    "$1" "${2:+nameConstraints=critical,$2}" > "$CA/$1.cnf"
  mx openssl req -x509 -new -key "$CA/pkcs8.key" -sha256 -days 30 -config "$CA/$1.cnf" -out "$CA/$1.pem"
}
NC_DNS='permitted;DNS:.oc-sandbox.internal'
NC_LOOP="$NC_DNS,permitted;IP:127.0.0.0/255.0.0.0,permitted;IP:::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
NC_NOIP="$NC_DNS,excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:::/::"
must mx openssl ecparam -name prime256v1 -genkey -noout -out "$CA/sec1.key"
must mx openssl pkcs8 -topk8 -nocrypt -in "$CA/sec1.key" -out "$CA/pkcs8.key"
head -1 "$CA/sec1.key" "$CA/pkcs8.key" | grep -v '^$' | shorten
must mkca loop "$NC_LOOP";   expect_text "variant L (loopback IPs only) CA builds" 'IP:127\.0\.0\.0/255\.0\.0\.0' mx openssl x509 -in "$CA/loop.pem" -noout -ext nameConstraints
must mkca noip "$NC_NOIP";   expect_text "variant E (no IPs at all) CA builds" 'Excluded:' mx openssl x509 -in "$CA/noip.pem" -noout -ext nameConstraints
must mkca dnsonly "$NC_DNS"  # NEGATIVE EXAMPLE only: never use
run mx openssl x509 -in "$CA/loop.pem" -noout -ext basicConstraints,nameConstraints; echo "$OUT"
# the documented ::1/128 form is rejected by OpenSSL 3.5
printf '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=x\n[v3]\nnameConstraints=critical,permitted;IP:::1/128\n' > "$CA/bad.cnf"
expect_fail "IP:::1/128 is rejected by OpenSSL 3.5 (use the full mask form)" 'bad ip address' mx openssl req -x509 -new -key "$CA/pkcs8.key" -days 1 -config "$CA/bad.cnf" -out "$CA/bad.pem"
cp "$CA/loop.pem" "$CA/ca.pem"        # main CA for the rest of the probe = variant L
cp "$CA/loop.cnf" "$CA/ca.cnf"

section "3. certutil against a scratch NSS SQL db (each step and its resulting state checked)"
D=$SCRATCH/nssdb; scrub "$D"; mkdir -p "$D"
must mx certutil -N -d "sql:$D" --empty-password
expect_true "certutil -N created cert9.db and key4.db" test -f "$D/cert9.db" -a -f "$D/key4.db"
expect_fail "before -A the nickname is absent" '[Cc]ould not find cert' mx certutil -L -d "sql:$D" -n oc-sandbox-spike
must mx certutil -A -d "sql:$D" -t "C,," -n oc-sandbox-spike -i "$CA/ca.pem"
expect_out "after -A the CA is listed with trust C,," '^oc-sandbox-spike +C,,' mx certutil -L -d "sql:$D"
expect_text "-L -n shows the critical name constraint" 'Permitted Subtree:' mx certutil -L -d "sql:$D" -n oc-sandbox-spike
must mx certutil -D -d "sql:$D" -n oc-sandbox-spike
expect_not_text "after -D the CA is no longer listed" 'oc-sandbox-spike' mx certutil -L -d "sql:$D"
expect_fail "after -D, -L -n fails" '[Cc]ould not find cert' mx certutil -L -d "sql:$D" -n oc-sandbox-spike

section "4. mkcert with an externally created CA"
for fmt in pkcs8 sec1; do
  R=$SCRATCH/caroot-$fmt; mkdir -p "$R"; cp "$CA/ca.pem" "$R/rootCA.pem"; cp "$CA/$fmt.key" "$R/rootCA-key.pem"; chmod 600 "$R/rootCA-key.pem"
done
R=$SCRATCH/caroot-pkcs8
CAROOT=$SCRATCH/caroot-pkcs8 TRUST_STORES=nss run mx mkcert -cert-file "$SCRATCH/out/pkcs8.pem" -key-file "$SCRATCH/out/pkcs8-key.pem" feat-a.oc-sandbox.internal
[ "$RC" -eq 0 ] && [ -s "$SCRATCH/out/pkcs8.pem" ] && pass "mkcert accepts a PKCS#8 CA key and issues a leaf" || fail "mkcert rejected PKCS#8 ($(tail2 "$OUT"))"
CAROOT=$SCRATCH/caroot-sec1 TRUST_STORES=nss run mx mkcert -cert-file "$SCRATCH/out/sec1.pem" -key-file "$SCRATCH/out/sec1-key.pem" feat-a.oc-sandbox.internal
[ "$RC" -ne 0 ] && [ ! -s "$SCRATCH/out/sec1.pem" ] && grep -q 'failed to read the CA key: unexpected content' <<<"$OUT" && pass "mkcert rejects a SEC1 (BEGIN EC PRIVATE KEY) CA key: failed to read the CA key" || fail "SEC1 key handling unexpected (rc=$RC: $(tail2 "$OUT"))"
cp "$SCRATCH/out/pkcs8.pem" "$SCRATCH/out/good.pem"
mx openssl x509 -in "$SCRATCH/out/good.pem" -noout -issuer -subject -dates -ext subjectAltName,extendedKeyUsage,authorityKeyIdentifier | sed '/^subject=/ s/OU=.*/OU=<user>@<host> (<full name>)/'
expect_text "mkcert default key type is RSA 2048" 'rsaEncryption' mx openssl x509 -in "$SCRATCH/out/good.pem" -noout -text
LS=$(date -d "$(mx openssl x509 -in "$SCRATCH/out/good.pem" -noout -startdate | cut -d= -f2)" +%s); LE=$(date -d "$(mx openssl x509 -in "$SCRATCH/out/good.pem" -noout -enddate | cut -d= -f2)" +%s)
[ $(( (LE - LS) / 86400 )) -ge 820 ] && [ $(( (LE - LS) / 86400 )) -le 830 ] && pass "mkcert leaf lifetime is fixed at 2 years 3 months ($(( (LE - LS) / 86400 )) days)" || fail "mkcert leaf lifetime is $(( (LE - LS) / 86400 )) days"
expect_out "leaf for feat-a.oc-sandbox.internal verifies (OpenSSL, hostname)" ': OK$' mx openssl verify -CAfile "$CA/ca.pem" -verify_hostname feat-a.oc-sandbox.internal "$SCRATCH/out/good.pem"
vname() { # names...: mkcert issues; then OpenSSL verifies. Sets ISSUED and VERIFY
  rm -f "$SCRATCH/out/t.pem" "$SCRATCH/out/t-key.pem"
  CAROOT=$R TRUST_STORES=nss run mx mkcert -cert-file "$SCRATCH/out/t.pem" -key-file "$SCRATCH/out/t-key.pem" "$@"
  ISSUED=no; [ -s "$SCRATCH/out/t.pem" ] && ISSUED=yes
  VERIFY=$(mx openssl verify -CAfile "$CA/ca.pem" "$SCRATCH/out/t.pem" 2>&1 | grep -E ': OK|error [0-9]+' | head -1 | shorten)
  printf 'mkcert %-55s issued=%s verify: %s\n' "$*" "$ISSUED" "$VERIFY"
}
for n in example.com oc-sandbox.internal feat-a.oc-sandbox.internal.evil.com "feat-a.oc-sandbox.internal localhost 127.0.0.1" "feat-a.oc-sandbox.internal 192.0.2.7"; do
  IFS=' ' read -ra NA <<<"$n"; vname "${NA[@]}"
  [ "$ISSUED" = yes ] && grep -q 'error 47' <<<"$VERIFY" && pass "mkcert issues '$n' but verifiers reject it (error 47)" || fail "'$n': issued=$ISSUED verify='$VERIFY'"
done
for n in "feat-a.oc-sandbox.internal 127.0.0.1 ::1" "*.oc-sandbox.internal" "FEAT-A.OC-SANDBOX.INTERNAL"; do
  IFS=' ' read -ra NA <<<"$n"; vname "${NA[@]}"
  [ "$ISSUED" = yes ] && grep -q ': OK' <<<"$VERIFY" && pass "mkcert leaf '$n' verifies under the L CA" || fail "'$n': issued=$ISSUED verify='$VERIFY'"
done

echo "--- NSS enforces the name constraint too, and an unconstrained CA is the control"
scrub "$D"; mkdir -p "$D"; must mx certutil -N -d "sql:$D" --empty-password
CAROOT=$R TRUST_STORES=nss run mx mkcert -cert-file "$SCRATCH/out/bad.pem" -key-file "$SCRATCH/out/bad-key.pem" example.com
[ -s "$SCRATCH/out/bad.pem" ] || unexpected "bad.pem not issued"
must mx certutil -A -d "sql:$D" -t "C,," -n oc-ca -i "$CA/ca.pem"
must mx certutil -A -d "sql:$D" -t ",," -n leaf-good -i "$SCRATCH/out/good.pem"
must mx certutil -A -d "sql:$D" -t ",," -n leaf-bad -i "$SCRATCH/out/bad.pem"
expect_text "NSS: in-constraint leaf is valid" 'certificate is valid' mx certutil -V -d "sql:$D" -n leaf-good -u V
expect_fail "NSS: example.com leaf rejected ('issuer is not recognized' is how NSS reports the violation)" "Peer's Certificate issuer is not recognized" mx certutil -V -d "sql:$D" -n leaf-bad -u V
RU=$SCRATCH/caroot-unc; mkdir -p "$RU"
must mx openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$RU/rootCA-key.pem"
printf '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nO=oc-sandbox spike (throwaway)\nCN=unconstrained control CA\n[v3]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' > "$CA/unc.cnf"
must mx openssl req -x509 -new -key "$RU/rootCA-key.pem" -sha256 -days 30 -config "$CA/unc.cnf" -out "$RU/rootCA.pem"
CAROOT=$RU TRUST_STORES=nss run mx mkcert -cert-file "$SCRATCH/out/unc.pem" -key-file "$SCRATCH/out/unc-key.pem" example.com
[ -s "$SCRATCH/out/unc.pem" ] || unexpected "unc.pem not issued"
DU=$SCRATCH/nssdb-unc; scrub "$DU"; mkdir -p "$DU"; must mx certutil -N -d "sql:$DU" --empty-password
must mx certutil -A -d "sql:$DU" -t "C,," -n unc-ca -i "$RU/rootCA.pem"
must mx certutil -A -d "sql:$DU" -t ",," -n unc-leaf -i "$SCRATCH/out/unc.pem"
expect_text "NSS control: unconstrained CA, example.com leaf is valid" 'certificate is valid' mx certutil -V -d "sql:$DU" -n unc-leaf -u V

echo "--- IP constraints (the DNS-only CA is a NEGATIVE EXAMPLE)"
ipcase() { # caname leaf-names... -> prints and sets VERIFY
  local ca=$1; shift
  local rr=$SCRATCH/caroot-$ca; mkdir -p "$rr"; cp "$CA/$ca.pem" "$rr/rootCA.pem"; cp "$CA/pkcs8.key" "$rr/rootCA-key.pem"; chmod 600 "$rr/rootCA-key.pem"
  rm -f "$SCRATCH/out/ip.pem" "$SCRATCH/out/ip-key.pem"
  CAROOT=$rr TRUST_STORES=nss run mx mkcert -ecdsa -cert-file "$SCRATCH/out/ip.pem" -key-file "$SCRATCH/out/ip-key.pem" "$@"
  [ -s "$SCRATCH/out/ip.pem" ] || unexpected "ip leaf for $* not issued"
  VERIFY=$(mx openssl verify -CAfile "$CA/$ca.pem" "$SCRATCH/out/ip.pem" 2>&1 | grep -E ': OK|error [0-9]+' | head -1 | shorten)
  printf 'CA=%-8s leaf: %-48s -> %s\n' "$ca" "$*" "$VERIFY"
}
ipcase dnsonly feat-a.oc-sandbox.internal 192.0.2.7;   grep -q ': OK' <<<"$VERIFY" && pass "NEGATIVE EXAMPLE: a DNS-only CA lets a leaf for 192.0.2.7 through (so IP subtrees are mandatory)" || fail "dns-only CA did not accept 192.0.2.7 ($VERIFY)"
ipcase loop feat-a.oc-sandbox.internal 127.0.0.1 ::1;  grep -q ': OK' <<<"$VERIFY" && pass "variant L: loopback IPv4+IPv6 SANs verify" || fail "variant L loopback ($VERIFY)"
ipcase loop feat-a.oc-sandbox.internal 192.0.2.7;      grep -q 'error 47' <<<"$VERIFY" && pass "variant L: 192.0.2.7 rejected" || fail "variant L 192.0.2.7 ($VERIFY)"
ipcase loop feat-a.oc-sandbox.internal 2001:db8::1;    grep -q 'error 47' <<<"$VERIFY" && pass "variant L: 2001:db8::1 rejected" || fail "variant L 2001:db8::1 ($VERIFY)"
ipcase noip feat-a.oc-sandbox.internal;                grep -q ': OK' <<<"$VERIFY" && pass "variant E: DNS-only leaf verifies" || fail "variant E dns leaf ($VERIFY)"
ipcase noip feat-a.oc-sandbox.internal 127.0.0.1;      grep -q 'error 48' <<<"$VERIFY" && pass "variant E: 127.0.0.1 rejected" || fail "variant E 127.0.0.1 ($VERIFY)"
ipcase noip feat-a.oc-sandbox.internal ::1;            grep -q 'error 48' <<<"$VERIFY" && pass "variant E: ::1 rejected" || fail "variant E ::1 ($VERIFY)"
ipcase noip feat-a.oc-sandbox.internal 192.0.2.7;      grep -q 'error 48' <<<"$VERIFY" && pass "variant E: 192.0.2.7 rejected" || fail "variant E 192.0.2.7 ($VERIFY)"
expect_text "mkcert -ecdsa gives an EC P-256 leaf" 'prime256v1' mx openssl x509 -in "$SCRATCH/out/ip.pem" -noout -text
# NSS and IP constraints (variant E: no IPs at all)
scrub "$D"; mkdir -p "$D"; must mx certutil -N -d "sql:$D" --empty-password
must mx certutil -A -d "sql:$D" -t "C,," -n e-ca -i "$CA/noip.pem"
ipcase noip feat-a.oc-sandbox.internal
must mx certutil -A -d "sql:$D" -t ",," -n e-leaf-dns -i "$SCRATCH/out/ip.pem"
ipcase noip feat-a.oc-sandbox.internal 192.0.2.7
must mx certutil -A -d "sql:$D" -t ",," -n e-leaf-ip -i "$SCRATCH/out/ip.pem"
expect_text "NSS, variant E: DNS-only leaf is valid" 'certificate is valid' mx certutil -V -d "sql:$D" -n e-leaf-dns -u V
expect_fail "NSS, variant E: leaf with an IP SAN is rejected (same misleading 'issuer not recognized' text)" "issuer is not recognized" mx certutil -V -d "sql:$D" -n e-leaf-ip -u V

section "4b. leaf issuance with the pinned OpenSSL: script-controlled extensions, 30 days"
LF=$SCRATCH/leaf-ossl; mkdir -p "$LF"
must mx openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$LF/evil-key.pem" -subj "/CN=feat-a.oc-sandbox.internal" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "subjectAltName=DNS:feat-a.oc-sandbox.internal,DNS:example.com" -out "$LF/evil.csr"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:feat-a.oc-sandbox.internal\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > "$LF/leaf.ext"
( umask 077; mx openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$LF/key.pem" ) || unexpected "genpkey failed"
[ "$(stat -c %a "$LF/key.pem")" = 600 ] && pass "leaf key generated under umask 077 has mode 600" || fail "leaf key mode is $(stat -c %a "$LF/key.pem")"
must mx openssl req -new -key "$LF/key.pem" -subj "/CN=feat-a.oc-sandbox.internal" -addext "subjectAltName=DNS:feat-a.oc-sandbox.internal" -out "$LF/ok.csr"
for n in ok evil; do
  must mx openssl x509 -req -in "$LF/$n.csr" -CA "$CA/ca.pem" -CAkey "$CA/pkcs8.key" -CAcreateserial -CAserial "$LF/serial" -days 30 -sha256 -extfile "$LF/leaf.ext" -out "$LF/$n.pem"
  printf '%s CSR -> ' "$n"; mx openssl x509 -in "$LF/$n.pem" -noout -subject -ext basicConstraints,subjectAltName | tr -s ' \n' ' '; echo
done
S1=$(date -d "$(mx openssl x509 -in "$LF/ok.pem" -noout -startdate | cut -d= -f2)" +%s); S2=$(date -d "$(mx openssl x509 -in "$LF/ok.pem" -noout -enddate | cut -d= -f2)" +%s)
[ $(( (S2 - S1) / 86400 )) -eq 30 ] && pass "OpenSSL leaf lifetime is exactly 30 days" || fail "OpenSSL leaf lifetime is $(( (S2 - S1) / 86400 )) days"
expect_out "OpenSSL leaf verifies (strict, hostname)" ': OK$' mx openssl verify -CAfile "$CA/ca.pem" -x509_strict -verify_hostname feat-a.oc-sandbox.internal "$LF/ok.pem"
expect_text "hostile CSR: result has CA:FALSE" 'CA:FALSE' mx openssl x509 -in "$LF/evil.pem" -noout -ext basicConstraints
expect_not_text "hostile CSR: its extra SAN example.com was not copied" 'example\.com' mx openssl x509 -in "$LF/evil.pem" -noout -text
expect_ok "serial file written (fresh serial per CA/leaf)" test -s "$LF/serial"
echo "--- mkcert -csr (key made by OpenSSL, mkcert only signs): clean subject, same fixed validity"
CAROOT=$R TRUST_STORES=nss run mx mkcert -csr "$LF/ok.csr" -cert-file "$SCRATCH/out/csr.pem"
[ -s "$SCRATCH/out/csr.pem" ] || unexpected "mkcert -csr failed: $(tail2 "$OUT")"
run mx openssl x509 -in "$SCRATCH/out/csr.pem" -noout -subject -dates -ext subjectAltName; echo "$OUT"
grep -q '^subject=CN=feat-a.oc-sandbox.internal' <<<"$OUT" && ! grep -q 'OU=' <<<"$OUT" && pass "mkcert -csr: clean subject, no OU leak" || fail "mkcert -csr subject: $(tail2 "$OUT")"

# -------------------------------------------------------------------------------------------------
section "5. mkcert -install / -uninstall restricted to NSS, scratch HOME, sudo stubbed, certutil logged"
scrub "$H"; mkdir -p "$H/.pki/nssdb" "$H/.mozilla/firefox/abc.default" "$H/.config/mozilla/firefox/xyz.default" "$H/.local/share" "$H/.cache" "$H/.local/state"
for d in "$H/.pki/nssdb" "$H/.mozilla/firefox/abc.default" "$H/.config/mozilla/firefox/xyz.default"; do must mx certutil -N -d "sql:$d" --empty-password; done
LOG=$SCRATCH/certutil.log; SUDOLOG=$SCRATCH/sudo.log; : > "$LOG"; : > "$SUDOLOG"
printf '%s\n' '#!/bin/sh' 'echo "sudo $*" >> "$PROBE_SUDOLOG"' 'exit 1' > "$SCRATCH/stub/sudo"
REALCU=$(mx sh -c 'command -v certutil')
printf '%s\n' '#!/bin/sh' 'out=$("$PROBE_REALCU" "$@" 2>&1); rc=$?' 'echo "rc=$rc certutil $*" >> "$PROBE_LOG"' 'printf "%s\n" "$out"; exit $rc' > "$SCRATCH/stub/certutil"
export PROBE_REALCU=$REALCU PROBE_LOG=$LOG PROBE_SUDOLOG=$SUDOLOG
chmod +x "$SCRATCH/stub/sudo" "$SCRATCH/stub/certutil"
MP=$(mx printenv PATH)
inst() { CAROOT=$R TRUST_STORES=nss mx env "PATH=$SCRATCH/stub:$MP" mkcert "$@"; }
ca_count() { mx certutil -L -d "sql:$1" | grep -c 'mkcert development CA' || true; }
run inst -install; echo "$OUT" | grep -v '^$'
[ "$RC" -eq 0 ] && grep -q 'now installed in the Firefox and/or Chrome/Chromium trust store' <<<"$OUT" && pass "mkcert -install (TRUST_STORES=nss) reports the CA installed" || fail "mkcert -install: rc=$RC $(tail2 "$OUT")"
echo "--- certutil calls mkcert made (scratch paths shortened):"; shorten < "$LOG" | sed 's/-n mkcert development CA [0-9]*/-n <mkcert CA>/'
grep -q 'certutil -A -d sql:.*home/.pki/nssdb' "$LOG" && pass "mkcert used the mise-provided certutil (stub logged -A on the scratch ~/.pki/nssdb)" || fail "mkcert did not call the PATH certutil for ~/.pki/nssdb"
grep -q 'certutil -A -d sql:/etc/pki/nssdb' "$LOG" && pass "mkcert also targets sql:/etc/pki/nssdb (hard-coded)" || fail "no -A on sql:/etc/pki/nssdb seen"
[ "$(ca_count "$H/.pki/nssdb")" = 1 ] && pass "CA is in the scratch ~/.pki/nssdb" || fail "CA missing from scratch ~/.pki/nssdb"
[ "$(ca_count "$H/.mozilla/firefox/abc.default")" = 1 ] && pass "CA is in the scratch ~/.mozilla Firefox profile" || fail "CA missing from the .mozilla profile"
[ "$(ca_count "$H/.config/mozilla/firefox/xyz.default")" = 0 ] && pass "mkcert does NOT see a profile under ~/.config/mozilla/firefox (nor any Flatpak path)" || fail "mkcert unexpectedly used the .config/mozilla profile"
run inst -uninstall; echo "$OUT" | grep -v '^$'
[ "$RC" -eq 0 ] && [ "$(ca_count "$H/.pki/nssdb")" = 0 ] && [ "$(ca_count "$H/.mozilla/firefox/abc.default")" = 0 ] && pass "mkcert -uninstall removed the CA from the scratch dbs" || fail "mkcert -uninstall left the CA behind"
[ "$(wc -l < "$SUDOLOG")" = 0 ] && pass "sudo stub was never invoked (install and uninstall)" || fail "sudo was invoked"

echo "--- sysinit precedence with BOTH ~/.pki/nssdb and \$XDG_DATA_HOME/pki/nssdb present (distinct marker CA in each)"
scrub "$H"; mkdir -p "$H/.pki/nssdb" "$H/.local/share/pki/nssdb" "$H/.config" "$H/.cache" "$H/.local/state"
for d in "$H/.pki/nssdb" "$H/.local/share/pki/nssdb"; do must mx certutil -N -d "sql:$d" --empty-password; done
must mx certutil -A -d "sql:$H/.pki/nssdb" -t "C,," -n marker-in-dot-pki -i "$CA/ca.pem"
must mx certutil -A -d "sql:$H/.local/share/pki/nssdb" -t "C,," -n marker-in-xdg -i "$RU/rootCA.pem"
run mx certutil -L -d sql:/etc/pki/nssdb; echo "listing of sql:/etc/pki/nssdb (scratch HOME/XDG, read-only): $(grep -o 'marker-[a-z-]*' <<<"$OUT" | tr '\n' ' ')"
[ "$RC" -eq 0 ] && grep -q marker-in-dot-pki <<<"$OUT" && ! grep -q marker-in-xdg <<<"$OUT" && pass "sql:/etc/pki/nssdb resolves to ~/.pki/nssdb when both exist" || fail "sysinit precedence differs from ~/.pki first"
echo "--- sysinit redirect when the home has ONLY \$XDG_DATA_HOME/pki/nssdb (no ~/.pki)"
scrub "$H"; mkdir -p "$H/.local/share/pki/nssdb" "$H/.config" "$H/.cache" "$H/.local/state"
must mx certutil -N -d "sql:$H/.local/share/pki/nssdb" --empty-password
: > "$LOG"; run inst -install; echo "$OUT" | grep -v '^$'
shorten < "$LOG" | sed 's/-n mkcert development CA [0-9]*/-n <mkcert CA>/' | grep ' -A '
[ "$(ca_count "$H/.local/share/pki/nssdb")" = 1 ] && pass "sql:/etc/pki/nssdb write landed in \$XDG_DATA_HOME/pki/nssdb (fallback)" || fail "no CA in the XDG db"
run inst -uninstall; [ "$RC" -eq 0 ] && [ "$(ca_count "$H/.local/share/pki/nssdb")" = 0 ] && pass "uninstall removed it from the XDG db" || fail "uninstall left the CA in the XDG db"
scrub "$H"; mkdir -p "$H/.local/share" "$H/.config" "$H/.cache" "$H/.local/state" "$H/.pki/nssdb"
must mx certutil -N -d "sql:$H/.pki/nssdb" --empty-password

echo "--- CAROOT with certificate only (no rootCA-key.pem): install works, issuing does not"
RN=$SCRATCH/caroot-nokey; mkdir -p "$RN"; cp "$CA/ca.pem" "$RN/rootCA.pem"
CAROOT=$RN TRUST_STORES=nss run mx env "PATH=$SCRATCH/stub:$MP" mkcert -install
[ "$RC" -eq 0 ] && [ "$(ca_count "$H/.pki/nssdb")" = 1 ] && pass "certificate-only CAROOT: -install works" || fail "cert-only install: rc=$RC $(tail2 "$OUT")"
CAROOT=$RN TRUST_STORES=nss run mx env "PATH=$SCRATCH/stub:$MP" mkcert -uninstall
[ "$RC" -eq 0 ] && [ "$(ca_count "$H/.pki/nssdb")" = 0 ] && pass "certificate-only CAROOT: -uninstall works" || fail "cert-only uninstall: rc=$RC $(tail2 "$OUT")"
CAROOT=$RN TRUST_STORES=nss run mx mkcert -cert-file "$SCRATCH/out/nk.pem" -key-file "$SCRATCH/out/nk-key.pem" feat-a.oc-sandbox.internal
[ "$RC" -ne 0 ] && grep -q "CA key (rootCA-key.pem) is missing" <<<"$OUT" && pass "issuing without rootCA-key.pem fails: CA key is missing" || fail "key-less issuing: rc=$RC $(tail2 "$OUT")"
echo "--- mkcert -install with no certutil on PATH (PATH = a stub dir with a failing sudo only)"
mkdir -p "$SCRATCH/stub-nocu"; cp "$SCRATCH/stub/sudo" "$SCRATCH/stub-nocu/sudo"; : > "$SUDOLOG"
MK=$(mx sh -c 'command -v mkcert')
CAROOT=$R TRUST_STORES=nss HOME=$H run env "PATH=$SCRATCH/stub-nocu" "$MK" -install; echo "$OUT" | grep -v '^$' | head -3
[ "$RC" -eq 0 ] && [ "$(ca_count "$H/.pki/nssdb")" = 0 ] && grep -Eq 'support is not available|"certutil" is not available' <<<"$OUT" && [ "$(wc -l < "$SUDOLOG")" = 0 ] && pass "no certutil on PATH: mkcert installs nothing, says so (rc 0), real sudo unreachable" || fail "no-certutil case: rc=$RC $(tail2 "$OUT")"

# -------------------------------------------------------------------------------------------------
section "5b. trust install/remove with proof of ownership (reference implementation for the real script)"
RECORD=$SCRATCH/state/trust-record.tsv; : > "$RECORD"
TNICK=oc-sandbox-CA
fp_of_pem() { mx openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
nick_fps() { # db nick -> one SHA-256 DER fingerprint per cert that has this nickname (none if absent)
  local blocks f n=0
  blocks=$(mx certutil -L -d "sql:$1" -n "$2" -a 2>/dev/null) || return 0
  rm -f "$SCRATCH"/blk.*.pem
  awk -v d="$SCRATCH/blk" '/BEGIN CERTIFICATE/{n++; f=d"."n".pem"} f{print > f} /END CERTIFICATE/{f=""}' <<<"$blocks"
  for f in "$SCRATCH"/blk.*.pem; do [ -e "$f" ] || continue; fp_of_pem "$f"; rm -f "$f"; done
}
record_valid() { # Validate the complete file before acting; malformed bytes are preserved for recovery.
  python3 -I - "$RECORD" <<'PYCODE'
import re, sys
try:
    data = open(sys.argv[1], 'rb').read()
    if data and not data.endswith(b'\n'):
        raise ValueError('unterminated record')
    for line in data.splitlines(keepends=True):
        fields = line[:-1].split(b'\t')
        if (len(fields) != 3 or not fields[0].startswith(b'/') or not fields[1]
                or not re.fullmatch(b'[0-9a-f]{64}', fields[2])
                or any(any(c < 32 or c == 127 for c in f) for f in fields)):
            raise ValueError('invalid fields')
except (OSError, ValueError) as exc:
    print('invalid ownership record; refusing changes:', exc, file=sys.stderr)
    sys.exit(1)
PYCODE
}
record_field_ok() { # POSIX paths with control bytes are deliberately refused, not serialized.
  local LC_ALL=C
  [ -n "$1" ] || return 1
  case $1 in *[[:cntrl:]]*) return 1 ;; esac
}
# Both operations acquire the same stable lock file before validation or NSS access.
# It must remain in trusted state and never be unlinked while any process can use it.
ts_with_lock() (
  exec {lock_fd}>>"$SCRATCH/state/trust-record.lock" || { echo "cannot open trust lock" >&2; return 7; }
  flock -x "$lock_fd" || { echo "cannot acquire trust lock" >&2; return 7; }
  "$@"
)
ts_install() { ts_with_lock ts_install_locked "$@"; }
ts_remove_all() { ts_with_lock ts_remove_all_locked "$@"; }
ts_install_locked() { # called only under ts_with_lock
  local db=$1 pem=$2 want have
  case $db in /*) ;; *) echo "refused non-absolute database path" >&2; return 7 ;; esac
  if ! record_field_ok "$db" || ! record_field_ok "$TNICK" || ! record_valid; then
    echo "refused unsafe database path, nickname, or ownership record" >&2; return 7
  fi
  want=$(fp_of_pem "$pem")
  if [[ ! $want =~ ^[0-9a-f]{64}$ ]]; then echo "invalid CA fingerprint" >&2; return 7; fi
  have=$(nick_fps "$db" "$TNICK")
  if [ -n "$have" ]; then
    if [ "$have" = "$want" ]; then echo "identical certificate already present: $db"; return 0; fi
    echo "COLLISION: $db already has a certificate named $TNICK that is not ours (sha256 ${have:0:16}...); refusing to touch it"; return 3
  fi
  mx certutil -A -d "sql:$db" -t "C,," -n "$TNICK" -i "$pem" >/dev/null 2>&1 || return 4
  [ "$(nick_fps "$db" "$TNICK")" = "$want" ] || return 5
  printf '%s\t%s\t%s\n' "$db" "$TNICK" "$want" >> "$RECORD" || return 7; echo "installed: $db"
}
ts_remove_all_locked() { # called only under ts_with_lock
  local db nick fp cur rc=0 keep=$SCRATCH/state/trust-record.new
  record_valid || return 7
  : > "$keep" || return 7
  while IFS=$'\t' read -r db nick fp; do
    [ -n "$db" ] || continue
    cur=$(nick_fps "$db" "$nick")
    if [ "$cur" = "$fp" ]; then
      if mx certutil -D -d "sql:$db" -n "$nick" >/dev/null 2>&1 && [ -z "$(nick_fps "$db" "$nick")" ]; then echo "removed: $db"; else echo "FAILED to remove: $db"; printf '%s\t%s\t%s\n' "$db" "$nick" "$fp" >> "$keep"; rc=6; fi
    elif [ -z "$cur" ]; then echo "already gone: $db"
    else echo "LEFT UNTOUCHED (certificate named $nick is no longer ours): $db"; fi
  done < "$RECORD"
  mv "$keep" "$RECORD" || return 7; return $rc
}
CAFP=$(fp_of_pem "$CA/ca.pem"); FORFP=$(fp_of_pem "$RU/rootCA.pem")
[ -n "$CAFP" ] && [ -n "$FORFP" ] && [ "$CAFP" != "$FORFP" ] && pass "two distinct CA fingerprints available (ours ${CAFP:0:16}..., foreign ${FORFP:0:16}...)" || fail "fingerprint setup"
NS=$SCRATCH/ts; mkdir -p "$NS"; DB1=$NS/db1; DB2=$NS/db2; DB3=$NS/db3; DB4=$NS/db4; DB5=$NS/db5
for d in "$DB1" "$DB2" "$DB3" "$DB4" "$DB5"; do mkdir -p "$d"; must mx certutil -N -d "sql:$d" --empty-password; done
# db2: a foreign cert already uses our nickname; db3: ours first, later swapped for a foreign one; db4: naive-delete demo
must mx certutil -A -d "sql:$DB2" -t "C,," -n "$TNICK" -i "$RU/rootCA.pem"
must mx certutil -A -d "sql:$DB4" -t "C,," -n "$TNICK" -i "$RU/rootCA.pem"
must mx certutil -A -d "sql:$DB5" -t "C,," -n "$TNICK" -i "$CA/ca.pem"
run ts_install "$DB5" "$CA/ca.pem"
[ "$RC" -eq 0 ] && ! grep -Fq "$DB5$TAB" "$RECORD" && pass "pre-existing identical CA is not claimed" || fail "pre-existing identical CA was claimed"
run ts_install "$DB1" "$CA/ca.pem"; echo "$OUT"
[ "$RC" -eq 0 ] && [ "$(nick_fps "$DB1" "$TNICK")" = "$CAFP" ] && pass "fresh db: installed, fingerprint of the stored cert equals our CA" || fail "fresh install failed (rc=$RC)"
expect_out "fresh db: listed with trust C,," "^$TNICK +C,," mx certutil -L -d "sql:$DB1"
run ts_install "$DB1" "$CA/ca.pem"; [ "$RC" -eq 0 ] && [ "$(grep -Fc "$DB1$TAB" "$RECORD")" = 1 ] && pass "re-install is idempotent (one record line, nothing changed)" || fail "re-install not idempotent"
run ts_install "$DB2" "$CA/ca.pem"; echo "$OUT"
[ "$RC" -eq 3 ] && grep -q COLLISION <<<"$OUT" && pass "foreign cert with our nickname: install refuses (collision)" || fail "collision not detected (rc=$RC)"
[ "$(nick_fps "$DB2" "$TNICK")" = "$FORFP" ] && pass "foreign cert in db2 was neither replaced nor removed by the refused install" || fail "db2 foreign cert changed"
! grep -Fq "$DB2$TAB" "$RECORD" && pass "no ownership record is written for a refused install" || fail "refused install was recorded"
run ts_install "$DB3" "$CA/ca.pem"; [ "$RC" -eq 0 ] || unexpected "db3 install rc=$RC"
echo "--- naive 'certutil -A' over a foreign nickname (what a nickname-only script would do), on a throwaway copy:"
run mx certutil -A -d "sql:$DB4" -t "C,," -n "$TNICK" -i "$CA/ca.pem"; echo "naive -A rc=$RC: $(tail2 "$OUT"); fingerprints now under that nickname: $(nick_fps "$DB4" "$TNICK" | tr '\n' ' ' | cut -c1-80)"
scrub "$DB4"; mkdir -p "$DB4"; must mx certutil -N -d "sql:$DB4" --empty-password
must mx certutil -A -d "sql:$DB4" -t "C,," -n "$TNICK" -i "$RU/rootCA.pem"
must mx certutil -D -d "sql:$DB4" -n "$TNICK"
[ -z "$(nick_fps "$DB4" "$TNICK")" ] && pass "HAZARD demonstrated: nickname-only 'certutil -D' deletes a foreign certificate" || fail "naive delete demo"
# swap in db3 after our install
must mx certutil -D -d "sql:$DB3" -n "$TNICK"
must mx certutil -A -d "sql:$DB3" -t "C,," -n "$TNICK" -i "$RU/rootCA.pem"
[ "$(nick_fps "$DB3" "$TNICK")" = "$FORFP" ] && pass "db3: our cert was swapped for a foreign one under the same nickname (setup)" || fail "db3 swap setup"
run ts_remove_all; echo "$OUT"
grep -q "^removed: $DB1" <<<"$OUT" && [ -z "$(nick_fps "$DB1" "$TNICK")" ] && pass "uninstall: our CA (fingerprint matched) was removed from db1" || fail "db1 not removed"
grep -q "^LEFT UNTOUCHED.*$DB3" <<<"$OUT" && [ "$(nick_fps "$DB3" "$TNICK")" = "$FORFP" ] && pass "uninstall: the swapped-in foreign cert in db3 was left alone" || fail "db3 foreign cert not preserved"
[ "$(nick_fps "$DB2" "$TNICK")" = "$FORFP" ] && pass "uninstall: the pre-existing foreign cert in db2 (never recorded) was left alone" || fail "db2 foreign cert not preserved"
[ "$(nick_fps "$DB5" "$TNICK")" = "$CAFP" ] && pass "uninstall preserves pre-existing identical CA" || fail "pre-existing identical CA removed"
[ ! -s "$RECORD" ] && pass "ownership record is empty after uninstall" || fail "record not cleared: $(cat "$RECORD")"

# -------------------------------------------------------------------------------------------------
section "6. lazy install: first use installs only what is needed"
T=$SCRATCH/lazy; mkdir -p "$T"/{data,cache,config,state,proj}; cp "$HERE/mise.lock" "$T/proj/"
printf '[tool_config]\nlocked = true\n\n[tools]\n"aqua:FiloSottile/mkcert" = { version = "1.4.4", lazy = true, lazy_bins = ["mkcert"] }\n"conda:nss" = { version = "3.118", lazy = true, lazy_bins = ["certutil", "pk12util"] }\n"conda:openssl" = { version = "3.5.9", lazy = true, lazy_bins = ["openssl"] }\n' > "$T/proj/mise.toml"
must tenv mise --cd "$T/proj" install
[ -z "$(ls "$T/data/installs" 2>/dev/null)" ] && pass "lazy: 'mise install' installs nothing" || fail "lazy install installed: $(ls "$T/data/installs")"
run tenv mise --cd "$T/proj" exec -- sh -c 'mkcert -version; command -v certutil || echo "certutil is NOT on mkcerts PATH"'; echo "$OUT" | grep -v '^mise'
[ "$(ls "$T/data/installs" | tr '\n' ' ')" = "aqua-filo-sottile-mkcert " ] && pass "lazy: exec mkcert installed only mkcert" || fail "lazy exec installed: $(ls "$T/data/installs")"
expect_text "lazy: the certutil shim that mkcert would find fails until nss is installed" 'not a valid shim' tenv "$T/data/shims/certutil" -H

# -------------------------------------------------------------------------------------------------
section "7. nothing outside scratch changed"
AFTER=$(fingerprint)
[ "$BEFORE" = "$AFTER" ] && pass "real mise dirs, ~/.pki, ~/.local/share/{pki,mkcert}, Flatpak and Firefox NSS files, /etc/pki/nssdb are unchanged" || fail "real state changed (fingerprint $BEFORE -> $AFTER)"
REPO_TOP_AFTER=$(ls -A "$REPO" | sort | sha256sum | cut -d' ' -f1)
[ "$REPO_TOP_BEFORE" = "$REPO_TOP_AFTER" ] && pass "worktree top level unchanged" || fail "worktree top level changed"
echo
echo "checks run: $CHECKS (expected $EXPECTED_CHECKS), failed: $FAILS, unexpected setup failures: $UNEXPECTED"
if [ "$FAILS" = 0 ] && [ "$UNEXPECTED" = 0 ] && [ "$CHECKS" = "$EXPECTED_CHECKS" ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "NOT ALL CHECKS PASSED"; exit 1
