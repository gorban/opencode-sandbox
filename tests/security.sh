#!/usr/bin/env bash
# Adversarial regression tests for the host-side parts of oc-sandbox.
#   tests/security.sh            all tests (the container test needs podman and the oc-agent image)
#   OC_TEST_NO_PODMAN=1 tests/security.sh   skip the container test
# Runs entirely in a temporary directory; never touches ~/opencode-sandbox or the real bridge.
set -uo pipefail
REPO=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
SCRIPT=$REPO/oc-sandbox BRIDGE=$REPO/oc-bridge.py
T=$(mktemp -d "${TMPDIR:-/tmp}/oc-sec.XXXXXX")
trap 'jobs -p | xargs -r kill 2>/dev/null; rm -rf "$T"' EXIT
pass=0 fail=0
ok()   { pass=$((pass + 1)); printf '  ok    %s\n' "$*"; }
bad()  { fail=$((fail + 1)); printf '  FAIL  %s\n' "$*"; }
check() {  # description, command... ; a leading '!' negates
  local d=$1 neg=0; shift
  [[ $1 == '!' ]] && { neg=1; shift; }
  if "$@"; then r=0; else r=1; fi
  if (( r == neg )); then ok "$d"; else bad "$d"; fi
}
fn()   { sed -n "/^$1() {/,/^}/p" "$SCRIPT"; }          # extract one function from the script
SECRET=TOP-SECRET-HOST-DATA

# ================================================================================================
echo "postgres.env parsing"
cat > "$T/pg.env" <<EOF
# comment line
OC_PG_IMAGE=docker.io/library/postgres:17   # inline comment
export OC_PG_USER = app_owner
OC_PG_PASSWORD='p@ss \$(touch $T/pwned1) \`touch $T/pwned2\` ; | & " #x'   # comment after quotes
OC_PG_DB=app#dev
NOT_OC=ignored
EOF
printf 'OC_PG_INIT_DIR="/x y"' >> "$T/pg.env"                  # final line without newline
cat > "$T/parse.sh" <<EOF
$(fn load_pg_config)
SCRIPT_DIR=. OC_PG_CONF=$T/pg.env
load_pg_config
printf '%s\n' "\$PG_IMAGE" "\$PG_USER" "\$PG_PASSWORD" "\$PG_DB" "\$PG_INIT"
env > $T/child.env
bash -c 'printf "%s" "\${OC_PG_PASSWORD:-}"' > $T/child.pw
EOF
env -i HOME="$HOME" PATH="$PATH" bash "$T/parse.sh" > "$T/parsed" 2>&1
mapfile -t got < "$T/parsed"
check "inline comment stripped"            [ "${got[0]:-}" = docker.io/library/postgres:17 ]
check "export prefix and spaces around ="  [ "${got[1]:-}" = app_owner ]
check "quoted value kept literally"        [ "${got[2]:-}" = "p@ss \$(touch $T/pwned1) \`touch $T/pwned2\` ; | & \" #x" ]
check "unquoted # without space kept"      [ "${got[3]:-}" = 'app#dev' ]
check "final line without newline"         [ "${got[4]:-}" = "/x y" ]
check "no shell expansion of values"       [ ! -e "$T/pwned1" ] && [ ! -e "$T/pwned2" ]
check "password not in child environment"  ! grep -q 'p@ss' "$T/child.env"
check "password not visible to child bash" [ ! -s "$T/child.pw" ]
# environment wins, and is un-exported as well
cat > "$T/parse2.sh" <<EOF
$(fn load_pg_config)
SCRIPT_DIR=. OC_PG_CONF=$T/pg.env
load_pg_config; echo "\$PG_PASSWORD"; env > $T/child2.env
EOF
out=$(env -i HOME="$HOME" PATH="$PATH" OC_PG_PASSWORD=from-env-pw bash "$T/parse2.sh")
check "environment wins over the file"     [ "$out" = from-env-pw ]
check "env password un-exported"           ! grep -q from-env-pw "$T/child2.env"

# ================================================================================================
echo "Postgres password exposure (podman stubbed)"
PW='S3cr3t-pw:@/#'
cat > "$T/pg.sh" <<EOF
set -euo pipefail
$(fn pg_sig); $(fn urlenc); $(fn ensure_postgres)
$(grep "^cstate()" "$SCRIPT")
log() { echo "==> \$*"; }
sleep() { :; }
pm() {
  printf '%s\0' "\$@" >> $T/argv.log; printf '\n' >> $T/argv.log
  case "\$1 \${2:-}" in
    "secret create") cat >> $T/secret.log ;;
    "volume exists"|"container inspect") return 1 ;;
  esac
  return 0
}
STATE=$T/state POD=oc PGC=oc-postgres PGVOL=oc-pg PGSECRET=oc-pg-password PG_INIT=$T/none INST= ILABEL=default
PG_IMAGE=img PG_USER=app PG_DB=db PG_PASSWORD='$PW'
ensure_postgres
EOF
bash "$T/pg.sh" > "$T/pg.out" 2>&1; rc=$?
check "ensure_postgres ran (stubbed)"      [ $rc -eq 0 ]
check "password absent from output"        ! grep -qF "$PW" "$T/pg.out"
check "password absent from every argv"    ! grep -qaF "$PW" "$T/argv.log"
check "password sent only via stdin secret" [ "$(cat "$T/secret.log" 2>/dev/null)" = "$PW" ]
check "postgres gets POSTGRES_PASSWORD_FILE" grep -qa POSTGRES_PASSWORD_FILE "$T/argv.log"
unkeyed=$(printf '%s|%s|%s|%s' app "$PW" db "" | sha256sum | cut -c1-16)
check "volume label is not the unkeyed hash" ! grep -qa "$unkeyed" "$T/argv.log"
check "signature key is private (0600)"    [ "$(stat -c %a "$T/state/pg-sig.key" 2>/dev/null)" = 600 ]

pgmsg() {  # volume-label -> stderr of ensure_postgres for '-i default' with an existing volume
  cat > "$T/pgm.sh" <<EOF
set -euo pipefail
$(fn pg_sig); $(fn urlenc); $(fn ensure_postgres)
$(grep "^cstate()" "$SCRIPT")
log() { :; }; sleep() { :; }
pm() {
  case "\$1 \${2:-}" in
    "volume exists") return 0 ;;
    "volume inspect") echo '$1' ;;
    "container inspect") return 1 ;;
  esac
  return 0
}
STATE=$T/state POD=oc PGC=oc-postgres PGVOL=oc-pg PGSECRET=oc-pg-password PG_INIT=$T/none INST= ILABEL=default
PG_IMAGE=img PG_USER=app PG_DB=db PG_PASSWORD=pw
ensure_postgres
EOF
  bash "$T/pgm.sh" 2>&1 >/dev/null
}
legacy=$(printf '%s|%s|%s|%s' app pw db "" | sha256sum | cut -c1-16)
out=$(pgmsg "$legacy")
check "legacy-volume hint keeps -i default"   grep -q -- '-i default -d && podman volume rm oc-pg' <<<"$out"
out=$(pgmsg mismatch)
check "settings-mismatch hint keeps -i default" grep -q -- '-i default -d && podman volume rm oc-pg' <<<"$out"
check "no hint suggests a bare -d"            ! grep -qE '\.sh -d && podman' <<<"$out$(pgmsg "$legacy")"

# ================================================================================================
echo "host bridge (oc-bridge.py)"
SB=$T/sb V=$T/victim B=$T/bin
mkdir -p "$SB/construct/dir" "$SB/.bridge/requests" "$V/requests" "$B"
echo hello > "$SB/construct/a.txt"; echo inner > "$SB/construct/dir/x"
echo "$SECRET" > "$V/secret"; echo "$SECRET" > "$V/requests/precious"; echo "$SECRET" > "$V/f"
ln -s ../../victim "$SB/construct/link"                        # resolves to $V on the host
ln -s ../../../victim/secret "$SB/construct/dir/evil"          # symlink inside a snapshotted dir
cat > "$B/launch" <<'EOF'
#!/bin/sh
while [ $# -gt 0 ] && [ "$1" != -- ]; do shift; done; shift; exec "$@"
EOF
cat > "$B/tool" <<EOF
#!/bin/sh
# fake VS Code / Beyond Compare: record what it was given, optionally act like the agent or an edit
for a in "\$@"; do case \$a in --*) ;; *)
  printf '%s\n' "\$a" >> $T/tool.args
  if [ -f "\$a" ]; then cat "\$a" >> $T/tool.seen; elif [ -d "\$a" ]; then find "\$a" >> $T/tool.seen; cat \$(find "\$a" -type f) >> $T/tool.seen 2>/dev/null; fi
  [ -n "\${FAKE_AGENT:-}" ] && sh -c "\$FAKE_AGENT"
  [ -n "\${FAKE_EDIT:-}" ] && [ -f "\$a" ] && printf '%s\n' "\$FAKE_EDIT" > "\$a"
esac; done; exit 0
EOF
chmod +x "$B/launch" "$B/tool"
export OC_SB=$SB OC_BRIDGE_STAGE=$T/stage OC_CODE_BIN=$B/tool OC_BCOMPARE_BIN=$B/tool OC_BRIDGE_LAUNCH=$B/launch
req() { local id=$1; shift; printf '%s\n' "$@" > "$SB/.bridge/requests/$id.req"; }
bridge() { timeout 20 python3 -I "$BRIDGE" 2>>"$T/bridge.log"; }
victim_ok() { [ "$(cat "$V/secret" "$V/requests/precious" "$V/f")" = "$SECRET"$'\n'"$SECRET"$'\n'"$SECRET" ]; }
reset_tool() { rm -f "$T/tool.args" "$T/tool.seen"; }

reset_tool; req 1 code /sandbox/construct/a.txt; FAKE_EDIT=edited bridge
check "file opened as a host-owned staged copy" grep -q "^$T/stage/" "$T/tool.args"
check "staged copy had the sandbox content" grep -qx hello "$T/tool.seen"
check "saved edit written back into the sandbox" [ "$(cat "$SB/construct/a.txt")" = edited ]
check "staging cleaned after the session"   [ -z "$(ls -A "$T/stage")" ]
check "queue drained"                       [ -z "$(ls -A "$SB/.bridge/requests")" ]

reset_tool; req 2 code /sandbox/construct/dir /etc/passwd /sandbox/../victim/secret \
  /sandbox/construct/link/secret /sandbox/construct/./a.txt; bridge
check "folders, escapes, symlink components refused" [ ! -e "$T/tool.args" ]

reset_tool; req 3 bcompare /sandbox/construct/dir /sandbox/construct/a.txt; bridge
check "bcompare folder snapshot copied regular files" grep -qx inner "$T/tool.seen"
check "symlink inside a folder snapshot skipped" ! grep -q evil "$T/tool.seen"

reset_tool; mkfifo "$SB/.bridge/requests/fifo.req"; ln -s ../../../victim/secret "$SB/.bridge/requests/link.req"
mkdir "$SB/.bridge/requests/dir.req"; ln -s ../../../victim "$SB/.bridge/requests/linkdir"
bridge; rc=$?
check "FIFO / symlinked requests do not hang" [ $rc -ne 124 ]
check "FIFO / symlinked requests not followed" [ ! -e "$T/tool.args" ] && victim_ok
check "drain removed links, not their targets" [ -z "$(ls -A "$SB/.bridge/requests")" ] && victim_ok

mv "$SB/.bridge" "$T/bridge.real"; ln -s ../victim "$SB/.bridge"     # $SB/.bridge -> $V (has requests/)
bridge
check ".bridge symlink: target directory untouched" victim_ok
check ".bridge symlink: link removed"       [ ! -L "$SB/.bridge" ] && [ ! -e "$SB/.bridge" ]
mv "$T/bridge.real" "$SB/.bridge"; rmdir "$SB/.bridge/requests"; ln -s ../../victim/requests "$SB/.bridge/requests"
bridge
check "requests symlink: target untouched"  victim_ok
check "requests symlink: link removed"      [ ! -e "$SB/.bridge/requests" ]
mkdir "$SB/.bridge/requests"

# agent swaps the opened file for a symlink to a host file while the editor is open
reset_tool; echo orig > "$SB/construct/b.txt"; req 4 code /sandbox/construct/b.txt
FAKE_AGENT="rm $SB/construct/b.txt; ln -s ../../victim/secret $SB/construct/b.txt" FAKE_EDIT=mine bridge
check "write-back never follows a swapped-in symlink" victim_ok && [ -L "$SB/construct/b.txt" ]
check "conflicting edit saved as .host-edit"  [ "$(cat "$SB/construct/b.txt.host-edit" 2>/dev/null)" = mine ]

# race: a directory on the path flips between a real directory and a symlink to the host, as fast as
# possible, while requests (with edits) are processed
mkdir -p "$SB/construct/d"; echo ok > "$SB/construct/d/f"; ln -s ../../victim "$SB/construct/d.link"
swap() {  # dir name: flip DIR/NAME between the real directory and the symlink NAME.link, forever
  exec python3 -I -c 'import os, sys
os.chdir(sys.argv[1]); n = sys.argv[2]
steps = [(n, n + ".tmp"), (n + ".link", n), (n, n + ".link"), (n + ".tmp", n)]
while True:                      # keep flipping even when the code under test recreated or removed n
    for a, b in steps:
        try: os.rename(a, b)
        except OSError: pass' "$@"
}
swap "$SB/construct" d & swapper=$!
reset_tool
for i in $(seq 1 150); do req "r$i" code /sandbox/construct/d/f; FAKE_EDIT="race-$i" bridge; done
kill $swapper; wait $swapper 2>/dev/null || true
check "race: host file never shown to the tool ($(grep -c . "$T/tool.args" 2>/dev/null || echo 0) opened)" \
  ! grep -q "$SECRET" "$T/tool.seen" 2>/dev/null
check "race: host file never written"       victim_ok
check "race: edits reached the sandbox file" [ -n "$(find "$SB/construct" -name f -type f -exec grep -l '^race-' {} +)" ]

# ================================================================================================
# Every run of the real script below goes through stubs: Podman, systemctl, pkexec, sudo and
# distrobox-host-exec only log their arguments, and HOME is a scratch directory. A regression (an
# argument that should be refused but is not) then deletes nothing real.
mkdir -p "$T/stub" "$T/dhome"
cat > "$T/stub/podman" <<EOF
#!/bin/sh
echo "\${0##*/} \$*" >> "$T/stub.log"
case "\$1 \$2" in
  "pod ls") printf 'oc\noc-other\n' ;;
  "secret ls") [ -n "\${STUB_SECRET_LS_FAIL:-}" ] && exit 125; printf '%b' "\${STUB_SECRETS:-}" ;;
  "image inspect")  # STUB_IDS="name=id ...": the image each tag points to; images have no tags left
    case "\$*" in *RepoTags*) echo 0; exit 0 ;; esac
    for m in \${STUB_IDS:-}; do [ "\${m%%=*}" = "\$5" ] && { echo "\${m#*=}"; exit 0; }; done; exit 125 ;;
esac
exit 0
EOF
chmod +x "$T/stub/podman"
for c in systemctl pkexec sudo distrobox-host-exec; do ln -s podman "$T/stub/$c"; done
stubbed() { env -u CONTAINER_ID -u XDG_DATA_HOME -u XDG_CONFIG_HOME HOME="$T/dhome" PATH="$T/stub:$PATH" "$SCRIPT" "$@"; }
del() {  # args... -> log of stubbed commands
  : > "$T/stub.log"
  stubbed "$@" >/dev/null 2>&1 </dev/null
  cat "$T/stub.log"
}

echo "argument validation (stubbed podman/systemctl; nothing real is touched)"
argfail() {  # expected-message-fragment args...: must exit 2 with that message
  local want=$1 out rc; shift
  out=$(stubbed "$@" 2>&1 </dev/null); rc=$?
  [[ $rc -eq 2 && $out == *"$want"* ]]
}
check "refuses publishing DevTools 9222"   argfail "refusing to publish pod port 9222" -P 18080:9222
check "refuses publishing Postgres 5432"   argfail "refusing to publish pod port 5432" -P 18080:5432
# The script refuses host ports below the host's ip_unprivileged_port_start; where that is 0 or 1
# every port is bindable and there is nothing to refuse. (The stubbed run reads this kernel's value.)
low=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)
if (( low > 1 )); then
  check "refuses privileged host port ($((low - 1)) < $low)" argfail "below" -P "$((low - 1)):80"
else echo "  skip  privileged host port (ip_unprivileged_port_start=$low: every port is bindable)"; fi
check "refuses duplicate host port"        argfail "given twice" -P 18080:80,18080:81
check "refuses malformed mapping"          argfail "is not HOSTPORT:PODPORT" -P 18080
check "refuses out-of-range port"          argfail "ports are 1-65535" -P 18080:70000
check "refuses bad instance name"          argfail "invalid instance name" -i Bad
check "refuses reserved instance name"     argfail "invalid instance name" -i agent
check "refuses -C with .."                 argfail "plain relative path" -C ../x
check "refuses absolute -C"                argfail "plain relative path" -C /etc
check "refuses -W with .."                 argfail "plain relative path" -W a/../b
check "refuses setup flags with -d"        argfail "only apply when setting up" -d -P 18080:80
check "refuses stray arguments"            argfail "unexpected argument" -i ok extra
check "refuses empty -i (no global -d)"    argfail "-i needs an instance name" -i "" -d -a -y

echo "delete scope (stubbed)"
out=$(del -i default -d -a -y)
check "-i default -d -a removes pod oc"                 grep -qx 'podman pod rm -f oc' <<<"$out"
check "-i default -d -a leaves other instances"         ! grep -q 'oc-other' <<<"$out"
check "-i default -d -a leaves bridge, images, login"   ! grep -qE '^systemctl|rmi|oc-home|semodule' <<<"$out"
check "-i default -d -a removes only default volumes"   grep -qx 'podman volume rm -f oc-pg' <<<"$out"
out=$(del -d)
check "bare -d still removes every instance pod"        grep -qx 'podman pod rm -f oc-other' <<<"$out"
DSTATE=$T/dhome/.local/share/oc-sandbox
for case in "no Postgres secrets:STUB_SECRETS=" "secret ls fails:STUB_SECRET_LS_FAIL=1" \
            "secrets present:STUB_SECRETS=oc-pg-password\\nother\\noc-x-pg-password\\n"; do
  name=${case%%:*} envset=${case#*:}
  : > "$T/stub.log"; mkdir -p "$DSTATE/build"; rc=0
  env -u CONTAINER_ID -u XDG_DATA_HOME -u XDG_CONFIG_HOME "$envset" HOME="$T/dhome" PATH="$T/stub:$PATH" \
    "$SCRIPT" -d -a -y >/dev/null 2>&1 </dev/null || rc=$?
  check "-d -a ($name) completes"              [ $rc -eq 0 ]
  check "-d -a ($name) removes the state dir"  [ ! -e "$DSTATE" ]
  check "-d -a ($name) removes SELinux module" grep -q 'semodule -r oc_chromium' "$T/stub.log"
done
check "-d -a removes only oc Postgres secrets" sh -c "grep -qx 'podman secret rm oc-pg-password' '$T/stub.log' \
  && grep -qx 'podman secret rm oc-x-pg-password' '$T/stub.log' && ! grep -q 'secret rm other' '$T/stub.log'"
# -d -a with a recorded build on oc-agent and a foreign image on oc-chromium
A=$(printf 'a%.0s' {1..64}) B=$(printf 'b%.0s' {1..64})
mkdir -p "$DSTATE"; printf '%s\n' "$A" > "$DSTATE/built-images"; : > "$T/stub.log"
env -u CONTAINER_ID -u XDG_DATA_HOME -u XDG_CONFIG_HOME STUB_IDS="oc-agent=$A oc-chromium=$B" HOME="$T/dhome" \
  PATH="$T/stub:$PATH" "$SCRIPT" -d -a -y >/dev/null 2>&1 </dev/null
check "-d -a: our build untagged and removed"   sh -c "grep -qx 'podman untag $A localhost/oc-agent:latest' '$T/stub.log' \
  && grep -qx 'podman rmi $A' '$T/stub.log'"
check "-d -a: foreign image on our tag kept"    ! grep -q "$B" <(grep -E 'untag|rmi' "$T/stub.log")
check "-d -a: never removes images by force or by tag" ! grep -qE 'rmi -f|rmi .*oc-(agent|chromium)|image prune' "$T/stub.log"

echo "sandbox tree, worktrees and relabelling (in containers)"
if [[ -n ${OC_TEST_NO_PODMAN:-} ]]; then echo "  skip  (OC_TEST_NO_PODMAN)"; else
  if [[ -n ${CONTAINER_ID:-} ]] && command -v distrobox-host-exec >/dev/null; then H=(distrobox-host-exec); else H=(); fi
  if ! "${H[@]}" podman image exists oc-agent 2>/dev/null; then echo "  skip  (no oc-agent image; run oc-sandbox -n first)"; else
    VOL=oc-sectest-$$
    cat > "$T/lib.sh" <<EOF
H=(${H[*]}); pm() { "\${H[@]}" podman "\$@"; }
AGENT_IMG=oc-agent HOMEVOL=$VOL LEVEL=s0:c7,c9 SB=\$1; shift
$(sed -n '/^safe_run() {/,/; }$/p' "$SCRIPT")
$(fn init_sandbox_tree)
$(sed -n "/^RELABEL_PY=/,/file=sys.stderr)'\$/p" "$SCRIPT")
$(fn relabel_shared)
"\$@"
EOF
    lib() { bash "$T/lib.sh" "$@"; }
    inbox() { "${H[@]}" podman run --rm --network=none --security-opt=label=disable -v "$T/isb":/sandbox -w /sandbox \
      --entrypoint sh oc-agent -c "$1"; }
    mk() { rm -rf "$T/isb" "$T/iv"; mkdir -p "$T/isb" "$T/iv"; echo "$SECRET" > "$T/iv/keep"; }
    mk; lib "$T/isb" init_sandbox_tree construct >/dev/null 2>&1
    check "working directory and bridge spool created" [ -d "$T/isb/construct" ] && [ -d "$T/isb/.bridge/requests" ]
    for target in "$T/iv" ../iv; do
      mk; ln -s "$target" "$T/isb/construct"; lib "$T/isb" init_sandbox_tree construct/sub >/dev/null 2>&1
      check "cwd construct -> $target: nothing written on the host" [ "$(ls -A "$T/iv")" = keep ]
    done
    mk; mkdir "$T/isb/construct"; ln -s ../iv "$T/isb/construct.link"
    swap "$T/isb" construct & sw=$!
    for _ in 1 2 3 4 5; do lib "$T/isb" init_sandbox_tree construct/sub >/dev/null 2>&1; done
    kill $sw; wait $sw 2>/dev/null || true
    check "construct swapped during init: host untouched" [ "$(ls -A "$T/iv")" = keep ]

    mk; inbox 'set -e; mkdir repo; cd repo; git init -q -b main; git -c user.email=t@t -c user.name=t commit -q --allow-empty -m i
      printf "#!/bin/sh\ntouch /sandbox/HOOK-RAN\n" > .git/hooks/post-checkout; chmod +x .git/hooks/post-checkout' >/dev/null 2>&1
    lib "$T/isb" init_sandbox_tree wt/x repo feature >/dev/null 2>&1
    check "worktree created on a new branch"  inbox '[ "$(git -C wt/x branch --show-current)" = feature ]'
    check "worktree link is relative"         grep -q '^gitdir: \.\./\.\./repo/' "$T/isb/wt/x/.git"
    check "agent-planted git hook not run"    [ ! -e "$T/isb/HOOK-RAN" ]
    mk; ln -s "$T/iv" "$T/isb/repo"; lib "$T/isb" init_sandbox_tree wt/y repo b >/dev/null 2>&1
    check "-W repo symlinked to the host: refused, host untouched" [ "$(ls -A "$T/iv")" = keep ] && [ ! -e "$T/isb/wt/y/.git" ]

    mk; echo data > "$T/isb/f"; ln -s "$T/iv/keep" "$T/isb/link-to-host"; ln -s ../iv "$T/isb/rel-link"
    before=$(stat -c %C "$T/iv/keep")
    "${H[@]}" podman volume create "$VOL" >/dev/null
    lib "$T/isb" relabel_shared >/dev/null 2>&1
    "${H[@]}" podman volume rm -f "$VOL" >/dev/null
    check "relabel: sandbox file gets the agents' level" [ "$(stat -c %C "$T/isb/f")" = system_u:object_r:container_file_t:s0:c7,c9 ]
    check "relabel: symlink targets on the host untouched" [ "$(stat -c %C "$T/iv/keep")" = "$before" ]
  fi
fi

echo "image ownership (real Podman, throwaway images FROM scratch)"
if [[ -n ${OC_TEST_NO_PODMAN:-} ]]; then echo "  skip  (OC_TEST_NO_PODMAN)"; else
  if [[ -n ${CONTAINER_ID:-} ]] && command -v distrobox-host-exec >/dev/null; then H=(distrobox-host-exec); else H=(); fi
  IT=localhost/oc-imgtest-$$ L=io.github.gorban.opencode-sandbox.image
  mkdir -p "$T/ib"; printf 'FROM scratch\n' > "$T/ib/Containerfile.t"
  cat > "$T/img.sh" <<EOF
set -euo pipefail
H=(${H[*]}); pm() { "\${H[@]}" podman "\$@"; }
IMAGE_LOG=$T/built-images OWNER_LABEL=$L
$(fn owned_image); $(fn prune_images); $(fn ensure_image)
log() { :; }
REBUILD=1 PULL=() BUILD=$T/ib
"\$@"
EOF
  img() { bash "$T/img.sh" "$@" 2>&1 >/dev/null; }
  iid() { "${H[@]}" podman image inspect --format '{{.Id}}' "$1" 2>/dev/null; }
  has() { "${H[@]}" podman image exists "$1"; }
  pbuild() { "${H[@]}" podman build -q "$@" -f "$T/ib/Containerfile.t" "$T/ib"; }
  # an unrelated image on our tag, even one carrying our labels
  foreign=$(pbuild --label oc.hash=x --label "$L=agent" -t "$IT")
  out=$(img ensure_image "$IT" Containerfile.t h1 agent); ours1=$(iid "$IT")
  check "real: foreign image on our tag (with our labels) kept" has "$foreign"
  check "real: user told about the foreign image"   grep -q 'not built by this oc-sandbox' <<<"$out"
  img ensure_image "$IT" Containerfile.t h2 agent >/dev/null; ours2=$(iid "$IT")
  check "real: our superseded build removed"        sh -c "[ '$ours1' != '$ours2' ] && ! ${H[*]} podman image exists '$ours1'"
  # an untagged image derived from ours (inherits every label) and an unrelated dangling oc.hash image
  printf 'FROM %s\n' "$IT" > "$T/ib/Containerfile.d"
  derived=$("${H[@]}" podman build -q --label mine=1 -f "$T/ib/Containerfile.d" "$T/ib")
  dangling=$(pbuild --label oc.hash=y)
  img prune_images >/dev/null
  check "real: untagged image derived from ours kept" has "$derived"
  check "real: unrelated dangling oc.hash image kept" has "$dangling"
  # a build of ours you tagged yourself, and one a container uses
  "${H[@]}" podman tag "$ours2" "$IT-backup"
  img ensure_image "$IT" Containerfile.t h3 agent >/dev/null; ours3=$(iid "$IT")
  check "real: our build with your own tag kept"    has "$ours2"
  ctr=$("${H[@]}" podman create "$ours3" /none 2>/dev/null)
  img ensure_image "$IT" Containerfile.t h4 agent >/dev/null
  check "real: our build used by a container kept"  has "$ours3"
  "${H[@]}" podman rm -f "$ctr" >/dev/null 2>&1; img prune_images >/dev/null
  check "real: ...and removed once it is unused"    ! has "$ours3"
  "${H[@]}" podman rmi "$IT" "$IT-backup" "$foreign" "$derived" "$dangling" >/dev/null 2>&1 || true
fi

echo; echo "$pass passed, $fail failed"
(( fail == 0 ))
