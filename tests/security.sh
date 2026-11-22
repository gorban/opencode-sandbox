#!/usr/bin/env bash
# Adversarial regression tests for the host-side parts of oc-sandbox.
#   tests/security.sh            all tests (the container test needs podman and the oc-agent image)
#   OC_TEST_NO_PODMAN=1 tests/security.sh   skip the container test
# Runs entirely in a temporary directory; never touches ~/opencode-sandbox or the real bridge.
set -uo pipefail
REPO=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
SCRIPT=$REPO/oc-sandbox BRIDGE=$REPO/oc-bridge.py
# A test-owned Python/Git image can supply the sandbox-tree fixture without
# installing or replacing the user's production oc-agent tag.
TEST_AGENT_IMG=${OC_TEST_AGENT_IMAGE:-oc-agent}
[[ $TEST_AGENT_IMG == oc-agent || $TEST_AGENT_IMG =~ ^(sha256:)?[0-9a-f]{64}$ ]] \
  || { echo "OC_TEST_AGENT_IMAGE must be a complete image ID" >&2; exit 2; }
T=$(mktemp -d "${TMPDIR:-/tmp}/oc-sec.XXXXXX")
trap 'jobs -p | xargs -r kill 2>/dev/null; rm -rf "$T"' EXIT
pass=0 fail=0
ok()   { pass=$((pass + 1)); printf '  ok    %s\n' "$*"; }
bad()  { fail=$((fail + 1)); printf '  FAIL  %s\n' "$*"; }
check() {  # description, command... ; a leading '!' negates
  local d=$1 neg=0; shift
  local first_test_arg=$1
  [[ $first_test_arg == '!' ]] && { neg=1; shift; }
  if "$@"; then r=0; else r=1; fi
  if (( r == neg )); then ok "$d"; else bad "$d"; fi
}
fn()   { local requested_function=$1; sed -n "/^$requested_function() {/,/^}/p" "$SCRIPT"; }  # extract one function
host_input_functions() {
  fn in_sb
  fn trusted_path
  fn host_input
  fn inspect_pg_init
  printf 'SB=%q\nH=()\n' "$T/pg-sandbox"
}
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
$(fn trusted_path)
in_sb() { [[ \$1/ == "\$sb_real"/* ]]; }
die() { echo "\$*" >&2; exit 2; }
$(fn host_input); $(fn inspect_pg_init)
SB=$T/pg-sandbox H=()
sb_real=$T/pg-sandbox CALLER_PHYSICAL=$T CALLER_PWD=$T
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
check "dollar command substitution in values is not evaluated" [ ! -e "$T/pwned1" ]
check "backtick command substitution in values is not evaluated" [ ! -e "$T/pwned2" ]
check "password not in child environment"  ! grep -q 'p@ss' "$T/child.env"
check "password not visible to child bash" [ ! -s "$T/child.pw" ]
# environment wins, and is un-exported as well
cat > "$T/parse2.sh" <<EOF
$(fn trusted_path)
in_sb() { [[ \$1/ == "\$sb_real"/* ]]; }
die() { echo "\$*" >&2; exit 2; }
$(fn host_input); $(fn inspect_pg_init)
SB=$T/pg-sandbox H=()
sb_real=$T/pg-sandbox CALLER_PHYSICAL=$T CALLER_PWD=$T
$(fn load_pg_config)
SCRIPT_DIR=. OC_PG_CONF=$T/pg.env
load_pg_config; echo "\$PG_PASSWORD"; env > $T/child2.env
EOF
out=$(env -i HOME="$HOME" PATH="$PATH" PG_PASSWORD=inherited OC_PG_PASSWORD=from-env-pw bash "$T/parse2.sh")
check "environment wins over the file"     [ "$out" = from-env-pw ]
check "env password un-exported"           ! grep -q from-env-pw "$T/child2.env"

# Config overrides may use host dotfile symlinks but must not traverse the sandbox.
mkdir -p "$T/pg-sandbox"
ln -s "$T/pg.env" "$T/pg-host-link"
ln -s "$T/pg.env" "$T/pg-sandbox/link"
ln -s "$T/pg-sandbox/link" "$T/pg-bad-link"
cat > "$T/parse-path.sh" <<EOF
$(fn trusted_path)
in_sb() { [[ \$1/ == "\$sb_real"/* ]]; }
die() { echo "\$*" >&2; exit 2; }
$(fn host_input); $(fn inspect_pg_init)
SB=$T/pg-sandbox H=()
sb_real=$T/pg-sandbox CALLER_PHYSICAL=$T CALLER_PWD=$T SCRIPT_DIR=.
$(fn load_pg_config)
load_pg_config
EOF
check 'host Postgres config symlink outside sandbox is accepted' env -i HOME="$HOME" PATH="$PATH" OC_PG_CONF="$T/pg-host-link" bash "$T/parse-path.sh"
check 'Postgres config path through sandbox is refused' bash -c '! env -i HOME="$1" PATH="$2" OC_PG_CONF="$3" bash "$4" >/dev/null 2>&1' _ "$HOME" "$PATH" "$T/pg-bad-link" "$T/parse-path.sh"
mkdir -p "$T/pg-init"
ln -s "$T/pg-sandbox" "$T/init-link"
sed '$a\printf "%s\\n" "$PG_INIT"' "$T/parse-path.sh" > "$T/parse-init.sh"
parse_init() { env -i HOME="$HOME" PATH="$PATH" OC_PG_CONF="$T/pg.env" OC_PG_INIT_DIR="$1" bash "$T/parse-init.sh"; }
check 'relative Postgres init directory becomes a host bind path' test "$(parse_init pg-init)" = "$T/pg-init"
check 'Postgres init directory entering sandbox is refused' ! parse_init "$T/init-link"
check 'Postgres init directory containing sandbox is refused' ! parse_init "$T"
check 'Postgres init rejects the filesystem root before inspecting it' ! parse_init /
ln -s "$T/pg.env" "$T/pg-init/01.sql"
cat > "$T/check-init-tree.sh" <<EOF
set -euo pipefail
$(host_input_functions)
$(fn ensure_postgres)
PG_INIT=$T/pg-init
die() { echo "\$*"; exit 2; }
pg_sig() { :; }
pm() { echo unexpected-podman-call; exit 4; }
ensure_postgres
EOF
out=$(bash "$T/check-init-tree.sh" 2>&1 || true)
check 'linked Postgres init file refused before Podman' grep -qx 'Postgres init requires ordinary owner-controlled directories and files without links' <<<"$out"
check 'linked Postgres init file never reaches Podman' ! grep -q 'unexpected-podman-call' <<<"$out"
unlink "$T/pg-init/01.sql"
install -m 0666 /dev/null "$T/pg-init/01.sql"
out=$(bash "$T/check-init-tree.sh" 2>&1 || true)
check 'world-writable Postgres init file refused before Podman' grep -q 'owner-controlled' <<<"$out"

# ================================================================================================
echo "Postgres password exposure (podman stubbed)"
PW='S3cr3t-pw:@/#'
cat > "$T/pg.sh" <<EOF
set -euo pipefail
$(host_input_functions)
$(fn pg_sig); $(fn urlenc); $(fn pgpass_field); $(fn create_pg_auth_secrets); $(fn ensure_postgres)
$(grep "^cstate()" "$SCRIPT")
log() { echo "==> \$*"; }
sleep() { :; }
pm() {
  printf '%s\0' "\$@" >> $T/argv.log; printf '\n' >> $T/argv.log
  case "\$1 \${2:-}" in
    "secret create") cat > "$T/secret.\$4" ;;
    "volume exists"|"container inspect") return 1 ;;
  esac
  return 0
}
STATE=$T/state POD=oc PGC=oc-postgres PGVOL=oc-pg PGSECRET=oc-pg-password PG_INIT=$T/none INST= ILABEL=default
PGHBASECRET=oc-pg-hba PGPASSSECRET=oc-pg-passfile PORTS=()
PG_IMAGE=img PG_USER=app PG_DB=db PG_PASSWORD='$PW'
ensure_postgres
EOF
bash "$T/pg.sh" > "$T/pg.out" 2>&1; rc=$?
check "ensure_postgres ran (stubbed)"      [ $rc -eq 0 ]
check "password absent from output"        ! grep -qF "$PW" "$T/pg.out"
check "password absent from every argv"    ! grep -qaF "$PW" "$T/argv.log"
check "password sent via stdin secret" [ "$(cat "$T/secret.oc-pg-password" 2>/dev/null)" = "$PW" ]
check "pgpass escapes password colon" grep -qxF '127.0.0.1:5432:db:app:S3cr3t-pw\:@/#' "$T/secret.oc-pg-passfile"
check "HBA requires SCRAM for TCP" sh -c "grep -qx 'host all all 0.0.0.0/0 scram-sha-256' '$T/secret.oc-pg-hba' && grep -qx 'host all all ::/0 scram-sha-256' '$T/secret.oc-pg-hba' && ! grep -q '^host .*trust' '$T/secret.oc-pg-hba'"
check "postgres always uses script-owned HBA" grep -qa 'hba_file=/run/secrets/oc-pg-hba' "$T/argv.log"
check "Postgres password file is private" grep -qa 'oc-pgpass,mode=0600' "$T/argv.log"
check "postgres gets POSTGRES_PASSWORD_FILE" grep -qa POSTGRES_PASSWORD_FILE "$T/argv.log"
unkeyed=$(printf '%s|%s|%s|%s' app "$PW" db "" | sha256sum | cut -c1-16)
check "volume label is not the unkeyed hash" ! grep -qa "$unkeyed" "$T/argv.log"
check "signature key is private (0600)"    [ "$(stat -c %a "$T/state/pg-sig.key" 2>/dev/null)" = 600 ]

pgmsg() {  # volume-label [init-directory] -> stderr of ensure_postgres with an existing volume
  cat > "$T/pgm.sh" <<EOF
set -euo pipefail
$(host_input_functions)
$(fn pg_sig); $(fn urlenc); $(fn pgpass_field); $(fn create_pg_auth_secrets); $(fn ensure_postgres)
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
STATE=$T/state POD=oc PGC=oc-postgres PGVOL=oc-pg PGSECRET=oc-pg-password PG_INIT=$(printf '%q' "${2:-$T/none}") INST= ILABEL=default
PGHBASECRET=oc-pg-hba PGPASSSECRET=oc-pg-passfile PORTS=()
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
mkdir -p "$T/directory-init/empty-subdirectory"
directory_sig=$({ cat "$T/state/pg-sig.key"; printf '|app|pw|db|abcfa6a9d4df344d'; } | sha256sum | cut -c1-16)
check "existing volume keeps its directory-only Postgres init signature" \
  pgmsg "k1:$directory_sig" "$T/directory-init"

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
  if [ -n "\${FAKE_ATOMIC_EDIT:-}" ] && [ -f "\$a" ]; then
    printf '%s\n' "\$FAKE_ATOMIC_EDIT" > "\$a.tmp" && mv -- "\$a.tmp" "\$a"
  fi
  [ -n "\${FAKE_SAVE_LINK:-}" ] && ln -sf -- "\$FAKE_SAVE_LINK" "\$a"
esac; done; exit 0
EOF
chmod +x "$B/launch" "$B/tool"
export OC_SB=$SB OC_BRIDGE_STAGE=$T/stage OC_CODE_BIN=$B/tool OC_BCOMPARE_BIN=$B/tool OC_BRIDGE_LAUNCH=$B/launch
req() { local id=$1; shift; printf '%s\n' "$@" > "$SB/.bridge/requests/$id.req"; }
bridge() { timeout 20 python3 -I "$BRIDGE" 2>>"$T/bridge.log"; }
victim_ok() { [[ "$(cat "$V/secret" "$V/requests/precious" "$V/f")" == "$SECRET"$'\n'"$SECRET"$'\n'"$SECRET" ]]; }
reset_tool() { rm -f "$T/tool.args" "$T/tool.seen"; }

reset_tool; req 1 code /sandbox/construct/a.txt; FAKE_EDIT=edited bridge
check "file opened as a host-owned staged copy" grep -q "^$T/stage/" "$T/tool.args"
check "staged copy had the sandbox content" grep -qx hello "$T/tool.seen"
check "saved edit written back into the sandbox" [ "$(cat "$SB/construct/a.txt")" = edited ]
check "staging cleaned after the session"   [ -z "$(ls -A "$T/stage")" ]
check "queue drained"                       [ -z "$(ls -A "$SB/.bridge/requests")" ]

reset_tool
echo '{}' > "$SB/construct/test.code-workspace"
req workspace code /sandbox/construct/test.code-workspace
{ printf 'code\n/sandbox/construct/a.txt\n'; head -c 8192 /dev/zero | tr '\0' a; } > "$SB/.bridge/requests/over.req"
bridge
check 'workspace definitions and oversized requests never reach the host editor' [ ! -e "$T/tool.args" ]
check 'bridge drains rejected requests' [ -z "$(ls -A "$SB/.bridge/requests")" ]
req failed-launch code /sandbox/construct/a.txt
OC_BRIDGE_LAUNCH=/usr/bin/false bridge
check 'known editor launch failure reclaims its staging directory' [ -z "$(ls -A "$T/stage")" ]

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
check "FIFO / symlinked requests not passed to the tool" [ ! -e "$T/tool.args" ]
check "FIFO / symlinked requests leave host targets intact" victim_ok
check "drain removed all request entries" [ -z "$(ls -A "$SB/.bridge/requests")" ]
check "drain leaves request targets intact" victim_ok

mkdir -p "$SB/.bridge/requests/stuck/nested"
ln -s "$V" "$SB/.bridge/tmp"
bridge
check 'nonempty junk leaves the watched queue even with a substituted tmp' test ! -e "$SB/.bridge/requests/stuck"
check 'quarantining junk keeps the substituted target intact' victim_ok
unlink "$SB/.bridge/tmp"
for (( entry=0; entry<1300; entry++ )); do : > "$SB/.bridge/requests/junk-$entry"; done
for (( batch=0; batch<6; batch++ )); do bridge; done
check 'queue backlog drains in bounded batches' [ -z "$(ls -A "$SB/.bridge/requests")" ]
reset_tool; req after-backlog code /sandbox/construct/a.txt; bridge
check 'bridge still handles requests after backlog' test -s "$T/tool.args"
check 'bridge units pace bounded batches without tripping the start limits' bash -c \
  'grep -qF "ExecStartPre=/usr/bin/sleep 1" "$1" && grep -qF "StartLimitIntervalSec=0" "$1" && grep -qF "TriggerLimitIntervalSec=0" "$1"' _ "$SCRIPT"

mv "$SB/.bridge" "$T/bridge.real"; ln -s ../victim "$SB/.bridge"     # $SB/.bridge -> $V (has requests/)
bridge
check ".bridge symlink: target directory untouched" victim_ok
check ".bridge symlink: link removed"       [ ! -L "$SB/.bridge" ]
check ".bridge symlink: path is absent"      [ ! -e "$SB/.bridge" ]
mv "$T/bridge.real" "$SB/.bridge"; rmdir "$SB/.bridge/requests"; ln -s ../../victim/requests "$SB/.bridge/requests"
bridge
check "requests symlink: target untouched"  victim_ok
check "requests symlink: link removed"      [ ! -e "$SB/.bridge/requests" ]
mkdir "$SB/.bridge/requests"

# agent swaps the opened file for a symlink to a host file while the editor is open
reset_tool; echo orig > "$SB/construct/b.txt"; req 4 code /sandbox/construct/b.txt
FAKE_AGENT="rm $SB/construct/b.txt; ln -s ../../victim/secret $SB/construct/b.txt" FAKE_EDIT=mine bridge
check "swapped-in symlink leaves the host target intact" victim_ok
check "write-back preserves the sandbox symlink entry" [ -L "$SB/construct/b.txt" ]
check "conflicting edit saved as .host-edit"  [ "$(cat "$SB/construct/b.txt.host-edit" 2>/dev/null)" = mine ]

echo original > "$SB/construct/saved.txt"; req 5 code /sandbox/construct/saved.txt
FAKE_ATOMIC_EDIT=replaced bridge
check "atomic editor save written back as a regular file" grep -qx replaced "$SB/construct/saved.txt"

echo unrelated > "$T/staged-save-control"; req 6 code /sandbox/construct/saved.txt
FAKE_SAVE_LINK="$T/staged-save-control" bridge
check "staged save symlink refused before write-back" grep -qx replaced "$SB/construct/saved.txt"

# Session fixtures use the same metadata as the queue and a fake editor in scratch.
make_session() {
  local session=$T/stage/$1 fixture_tool=$2 manifest_padding=$3
  mkdir -m 700 "$session"
  mkdir -m 700 -p "$session/files/construct"
  printf 'fixture\n' > "$session/files/construct/session.txt"
  python3 -I - "$session" "$fixture_tool" "$manifest_padding" <<'PY'
import json
from pathlib import Path
import sys

session = Path(sys.argv[1])
staged = session / "files/construct/session.txt"
st = staged.stat()
entry = {"kind": "file", "parts": ["construct", "session.txt"], "staged": str(staged),
         "mode": 0o600, "target": [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns],
         "seen": [st.st_ino, st.st_size, st.st_mtime_ns]}
manifest = json.dumps({"tool": sys.argv[2], "entries": [entry]})
(session / "manifest.json").write_text(manifest + " " * int(sys.argv[3]), encoding="utf-8")
PY
}
run_fixture_session() {
  local fixture_name=$1
  timeout 20 python3 -I "$BRIDGE" session "$T/stage/$fixture_name" 2>>"$T/bridge.log"
}
session_refused() {
  local fixture_name=$1
  run_fixture_session "$fixture_name"
  [[ $? -eq 2 && ! -e "$T/tool.args" ]]
}

reset_tool; make_session unknown-tool unknown 0
check "unknown session tool rejected before editor launch" session_refused unknown-tool

reset_tool; make_session oversized code 262144
check "oversized session manifest rejected before editor launch" session_refused oversized

reset_tool; make_session non-regular code 0
ln -sf -- "$T/staged-save-control" "$T/stage/non-regular/files/construct/session.txt"
check "non-regular staged input rejected before editor launch" session_refused non-regular

mkdir "$SB/construct/save-recovery"
echo original > "$SB/construct/save-recovery/a.txt"; req 7 code /sandbox/construct/save-recovery/a.txt
FAKE_AGENT="mv '$SB/construct/save-recovery' '$SB/construct/recovery-original'" FAKE_EDIT=recover-me bridge
retained_edit() {
  local path
  for path in "$T/stage"/*/files/construct/save-recovery/a.txt; do
    if [[ -f $path ]] && grep -qx recover-me "$path"; then return 0; fi
  done
  return 1
}
check "failed write-back retains the staged edit" retained_edit
check "failed write-back preserves the sandbox file" grep -qx original "$SB/construct/recovery-original/a.txt"

bridge_copy_regressions() {
  timeout 20 python3 -I - "$BRIDGE" "$T" <<'PY'
import errno
from io import StringIO
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

bridge_path, scratch = sys.argv[1:]
base, edit = b"before", b"host edit with more bytes"
real_write = os.write


class CopyTests(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory(dir=scratch)))
        sandbox, stage = root / "sandbox", root / "stage"
        sandbox.mkdir()
        self.target = sandbox / "edit.txt"
        self.target.write_bytes(base)
        self.enterContext(patch.dict(os.environ, OC_SB=str(sandbox), OC_BRIDGE_STAGE=str(stage)))
        self.bridge = runpy.run_path(bridge_path)["run_session"].__globals__

    def stage(self):
        session = Path(self.bridge["stage_request"]("code", ["/sandbox/edit.txt"]))
        staged = session / "files/edit.txt"
        self.assertEqual(staged.read_bytes(), base)
        return session, staged

    def test_short_staging_writes(self):
        with patch.object(os, "write", side_effect=lambda fd, data: real_write(fd, data[:2])):
            self.stage()

    def test_bounded_directory_and_session_staging(self):
        tree = self.target.parent / "tree"
        (tree / "a" / "b").mkdir(parents=True)
        for limits in ({"MAX_TREE_DEPTH": 2}, {"MAX_TREE_FILES": 1}):
            with self.subTest(limits=limits), patch.dict(self.bridge, limits):
                with self.assertRaises(self.bridge["Refused"]):
                    self.bridge["stage_request"]("bcompare", ["/sandbox/tree"])
                self.assertEqual(list(Path(self.bridge["STAGE"]).iterdir()), [])
        other = self.target.with_name("more.txt")
        other.write_bytes(base)
        with patch.dict(self.bridge, MAX_SESSION_BYTES=len(base)):
            with self.assertRaises(self.bridge["Refused"]):
                self.bridge["stage_request"]("code", ["/sandbox/edit.txt", "/sandbox/more.txt"])
        with patch.dict(self.bridge, MAX_STAGE_SESSIONS=1):
            self.stage()
            with self.assertRaises(self.bridge["Refused"]):
                self.stage()

    def test_save_does_not_replace_existing_conflict_copy_or_concurrent_edit(self):
        session, staged = self.stage()
        staged.write_bytes(edit)
        conflict = self.target.with_name("edit.txt.host-edit")
        conflict.write_bytes(b"older host save")
        fsync = os.fsync

        def edited_during_copy(fd):
            fsync(fd)
            self.target.write_bytes(b"agent updated during copy")

        with patch.object(os, "fsync", side_effect=edited_during_copy):
            self.assertFalse(self.sync(session))
        self.assertEqual(self.target.read_bytes(), b"agent updated during copy")
        self.assertEqual(conflict.read_bytes(), b"older host save")
        self.assertEqual(staged.read_bytes(), edit)

    def test_label_failure_preserves_target_and_staged_edit(self):
        session, staged = self.stage()
        staged.write_bytes(edit)
        with patch.dict(self.bridge, SELINUX_LEVEL='s0:c7,c9'), \
                patch.object(os, 'setxattr', side_effect=PermissionError('fixture')):
            self.assertFalse(self.sync(session))
        self.assert_preserved(staged)

    def test_short_save_writes(self):
        session, staged = self.stage()
        staged.write_bytes(edit)
        with patch.object(os, "write", side_effect=lambda fd, data: real_write(fd, data[:2])):
            self.assertTrue(self.sync(session))
        self.assertEqual(self.target.read_bytes(), edit)

    def test_pending_save_name_is_private(self):
        session, staged = self.stage()
        staged.write_bytes(edit)
        fsync = os.fsync

        def during_copy(fd):
            fsync(fd)
            self.assertEqual(list(self.target.parent.glob(".oc-bridge-*")), [])

        with patch.object(os, "fsync", side_effect=during_copy):
            self.assertTrue(self.sync(session))
        self.assertEqual(self.target.read_bytes(), edit)

    def test_replaced_publication_keeps_private_save(self):
        for changed in (False, True):
            with self.subTest(conflict=changed):
                self.target.write_bytes(base)
                session, staged = self.stage()
                staged.write_bytes(edit)
                dest = self.target
                operation = "rename"
                if changed:
                    self.target.write_bytes(b"concurrent edit")
                    dest = self.target.with_name("edit.txt.host-edit")
                    operation = "link"
                publish = getattr(os, operation)

                def replace_published_inode(*args, **kwargs):
                    publish(*args, **kwargs)
                    replacement = dest.with_name("other-inode")
                    replacement.write_bytes(b"replacement")
                    os.replace(replacement, dest)

                with patch.object(os, operation, side_effect=replace_published_inode):
                    self.assertFalse(self.sync(session))
                self.assertEqual(dest.read_bytes(), b"replacement")
                self.assertEqual(staged.read_bytes(), edit)

    def test_cross_mount_preserves_private_save(self):
        session, staged = self.stage()
        observations = iter((None, None, None, 0))
        saves = iter((edit, b"next host edit", b"latest host edit"))
        errors = StringIO()
        with patch("subprocess.Popen", return_value=SimpleNamespace(poll=lambda: next(observations))), \
                patch("time.sleep", side_effect=lambda _: staged.write_bytes(next(saves))), \
                patch.object(os, "rename", side_effect=OSError(errno.EXDEV, "fixture")) as publish, \
                patch.object(sys, "stderr", errors):
            self.bridge["run_session"](str(session))
        self.assertEqual(publish.call_count, 1)
        self.assert_preserved(staged, expected=b"latest host edit")
        self.assertEqual(errors.getvalue().count("must share a mount"), 1)
        self.assertEqual(errors.getvalue().count(str(session)), 1)

    def test_abandoned_prepared_save_expires_with_session(self):
        session, staged = self.stage()

        def editor(*args, **kwargs):
            staged.write_bytes(edit)
            return SimpleNamespace(poll=lambda: 0)

        with patch("subprocess.Popen", side_effect=editor), \
                patch.object(os, "rename", side_effect=OSError(errno.EXDEV, "fixture")), \
                patch.object(os, "unlink", side_effect=PermissionError("interrupted cleanup fixture")):
            self.bridge["run_session"](str(session))
        self.assertEqual(len(list(session.glob(".oc-bridge-*"))), 1)
        os.utime(session, (1, 1))
        self.bridge["expire_stage"]()
        self.assertEqual(list(session.parent.iterdir()), [])

    def sync(self, session):
        with (session / "manifest.json").open() as manifest:
            entry = json.load(manifest)["entries"][0]
        session_fd = os.open(session, os.O_RDONLY | os.O_DIRECTORY)
        try:
            files_fd = os.open("files", os.O_RDONLY | os.O_DIRECTORY, dir_fd=session_fd)
            try:
                return self.bridge["sync"](session_fd, files_fd, [entry], set())
            finally:
                os.close(files_fd)
        finally:
            os.close(session_fd)

    def assert_preserved(self, staged, expected=edit):
        self.assertEqual(self.target.read_bytes(), base)
        self.assertEqual(staged.read_bytes(), expected)
        self.assertEqual(list(self.target.parent.iterdir()), [self.target])

    def test_incomplete_writes_keep_recovery(self):
        for error in (None, OSError(errno.ENOSPC, "test disk full"), InterruptedError()):
            with self.subTest(error=error):
                self.target.write_bytes(base)
                session, staged = self.stage()

                def editor(*args, **kwargs):
                    staged.write_bytes(edit)
                    return SimpleNamespace(poll=lambda: 0)

                def write(fd, data):
                    if len(data) == len(edit):
                        return real_write(fd, data[:2])
                    if error is None:
                        return 0
                    raise error

                with patch("subprocess.Popen", side_effect=editor), patch.object(os, "write", side_effect=write):
                    self.bridge["run_session"](str(session))
                self.assert_preserved(staged)

    def test_periodic_failure_retries_same_save(self):
        session, staged = self.stage()
        observations = iter((None, 0))

        def editor(*args, **kwargs):
            staged.write_bytes(edit)
            return SimpleNamespace(poll=lambda: next(observations))

        def write(fd, data):
            if not attempted:
                attempted.append(True)
                raise OSError(errno.ENOSPC, "test disk full")
            return real_write(fd, data)

        attempted = []
        with patch("subprocess.Popen", side_effect=editor), patch("time.sleep"), patch.object(os, "write", side_effect=write):
            self.bridge["run_session"](str(session))
        self.assertEqual(self.target.read_bytes(), edit)
        self.assertFalse(session.exists())

    def test_oversized_save_keeps_recovery(self):
        session, staged = self.stage()
        staged.write_bytes(edit)
        with patch.dict(self.bridge, MAX_FILE=len(base)):
            self.assertFalse(self.sync(session))
        self.assert_preserved(staged)

    def test_source_change_during_copy_keeps_recovery(self):
        for changed in (edit.upper(), edit + b"more"):
            with self.subTest(changed=changed):
                self.target.write_bytes(base)
                session, staged = self.stage()
                staged.write_bytes(edit)

                def write(fd, data):
                    staged.write_bytes(changed)
                    return real_write(fd, data)

                with patch.dict(self.bridge, MAX_FILE=len(edit)), patch.object(os, "write", side_effect=write):
                    self.assertFalse(self.sync(session))
                self.assert_preserved(staged, changed)

    def test_replaced_stage_refused_before_editor(self):
        session, staged = self.stage()
        replacement = staged.with_suffix(".replacement")
        replacement.write_bytes(base)
        replacement.replace(staged)
        self.assert_launch_refused(session)

    def test_duplicate_path_refused_before_editor(self):
        session, _ = self.stage()
        manifest = session / "manifest.json"
        data = json.loads(manifest.read_bytes())
        data["entries"] *= 2
        manifest.write_text(json.dumps(data), encoding="utf-8")
        self.assert_launch_refused(session)

    def assert_launch_refused(self, session):
        with patch("subprocess.Popen") as launch:
            launch.return_value.poll.return_value = 0
            with self.assertRaises(self.bridge["Refused"]):
                self.bridge["run_session"](str(session))
        launch.assert_not_called()
        self.assertTrue(session.exists())


unittest.main(argv=[sys.argv[0]])
PY
}
check "bounded bridge copies preserve and retry incomplete saves" bridge_copy_regressions

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
check "race: at least one save was published or retained privately" \
  [ -n "$(find "$SB/construct" "$T/stage" \( -name f -o -name f.host-edit \) -type f -exec grep -l '^race-' {} +)" ]

# ================================================================================================
# Every run of the real script below goes through stubs: Podman, systemctl, pkexec, sudo and
# distrobox-host-exec only log their arguments, and HOME is a scratch directory. A regression (an
# argument that should be refused but is not) then deletes nothing real.
mkdir -p "$T/stub" "$T/dhome"
cat > "$T/stub/podman" <<EOF
#!/bin/sh
echo "\${0##*/} \$*" >> "$T/stub.log"
# Optional lifecycle integration stub: every image/volume/pod operation stays in scratch.
if [ -n "\${STUB_SETUP:-}" ]; then
  case "\$1 \${2:-}" in
    "image inspect")
      case "\$4" in *RepoTags*) echo 1; exit 0;; esac
      name=\$5; record="$T/lifecycle/images/\$name"
      [ -f "\$record" ] || exit 125
      hash=\$(cat "\$record")
      case "\$name" in oc-agent) id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;
        *) id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;; esac
      case "\$4" in *oc.hash*) printf '%s %s\n' "\$id" "\$hash";; *) echo "\$id";; esac
      exit 0;;
    "pod exists"|"container inspect") exit 1;;
    "pod create")
      if [ -n "\${STUB_HOLD_POD:-}" ]; then
        : > "$T/lifecycle/entered"
        while [ ! -e "$T/lifecycle/release" ]; do sleep .05; done
      fi
      exit 0;;
    "pod rm") [ -n "\${STUB_DELETE_SIGNAL:-}" ] && : > "$T/lifecycle/deleted"; exit 0;;
  esac
  if [ "\$1" = build ]; then
    shift; tag= hash=
    while [ \$# -gt 0 ]; do
      case "\$1" in
        -t) tag=\$2; shift 2;;
        --label) case "\$2" in oc.hash=*) hash=\${2#oc.hash=};; esac; shift 2;;
        *) shift;;
      esac
    done
    echo "\$tag" >> "$T/lifecycle/builds"
    sleep .3
    printf '%s\n' "\$hash" > "$T/lifecycle/images/\$tag"
    exit 0
  fi
fi
case "\${0##*/}" in
  semodule)
    [ -n "\${STUB_SEMODULE_LIST_FAIL:-}" ] && exit 1
    printf '%b' "\${STUB_MODULES-400 oc_chromium cil\\n}"; exit 0 ;;
  pkexec|sudo)
    if [ "\$1" = semodule ] && [ "\$2" = -lfull ]; then
      [ -n "\${STUB_ELEV_LIST_FAIL:-}" ] && exit 1
      printf '%b' "\${STUB_MODULES-400 oc_chromium cil\\n}"; exit 0
    fi
    if [ "\$1" = semodule ]; then [ -n "\${STUB_REMOVE_FAIL:-}" ] && exit 1; exit 0; fi ;;
esac
case "\$1 \$2" in
  "pod ls")
    [ -n "\${STUB_LIST_PODS_FAIL:-}" ] && exit 125
    for name in oc oc-other; do
      if [ -n "\${STUB_POD_REMAINS:-}" ] || ! grep -Fqx "podman pod rm --ignore -f -- \$name" "$T/stub.log"; then
        printf '%s\\n' "\$name"
      fi
    done ;;
  "pod exists")
    [ -n "\${STUB_POD_EXISTS_FAIL:-}" ] && exit 125
    if [ -z "\${STUB_POD_REMAINS:-}" ] && grep -Fqx "podman pod rm --ignore -f -- \$3" "$T/stub.log"; then exit 1; fi ;;
  "pod rm") [ -n "\${STUB_POD_REMOVE_FAIL:-}" ] && exit 125 ;;
  "volume exists"|"secret exists")
    if grep -Fqx "podman \$1 rm \$3" "$T/stub.log" || \
       grep -Fqx "podman \$1 rm -f \$3" "$T/stub.log"; then exit 1; fi ;;
  "volume rm") [ "\${STUB_VOLUME_REMOVE_FAIL:-}" = "\${4:-}" ] && exit 125 ;;
  "secret rm") [ "\${STUB_SECRET_REMOVE_FAIL:-}" = "\${3:-}" ] && exit 125 ;;
  "secret ls") [ -n "\${STUB_SECRET_LS_FAIL:-}" ] && exit 125; printf '%b' "\${STUB_SECRETS:-}" ;;
  "image inspect")  # STUB_IDS="name=id ...": the image each tag points to; images have no tags left
    case "\$*" in *RepoTags*) echo 0; exit 0 ;; esac
    for m in \${STUB_IDS:-}; do [ "\${m%%=*}" = "\$5" ] && { echo "\${m#*=}"; exit 0; }; done; exit 125 ;;
esac
if [ "\${0##*/}" = systemctl ] && [ -n "\${STUB_BRIDGE_STAYS_ACTIVE:-}" ]; then
  case "\$2" in stop) exit 1 ;; show) echo active; exit 0 ;; esac
fi
exit 0
EOF
chmod +x "$T/stub/podman"
for c in systemctl pkexec sudo semodule; do ln -s podman "$T/stub/$c"; done
cat > "$T/stub/distrobox-host-exec" <<'EOF'
#!/usr/bin/env bash
set -eu
if [[ $1 == /usr/bin/bash ]]; then
  args=("$@")
  # Model a shared-looking path that points into the sandbox on the host only.
  if [[ ${args[-1]} == "$HOME/guest-only-path" ]]; then
    args[-1]="$HOME/opencode-sandbox/host-path"
  fi
  if [[ ${args[-2]} == bridge-stage && -n ${STUB_HOST_STAGE_PATH:-} ]]; then
    args[-1]=$STUB_HOST_STAGE_PATH
  fi
  exec "${args[@]}"
fi
case $1 in
  cat|podman|systemctl|/usr/bin/python3) exec "$@" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$T/stub/distrobox-host-exec"
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
check "refuses malformed mapping"          argfail "is not PORT or HOSTPORT:PODPORT" -P bad:80
check "refuses out-of-range port"          argfail "ports are 1-65535" -P 18080:70000
check "refuses bad instance name"          argfail "invalid instance name" -i Bad
check "refuses reserved instance name"     argfail "invalid instance name" -i agent
check "refuses -C with .."                 argfail "plain relative path" -C ../x
check "refuses absolute -C"                argfail "plain relative path" -C /etc
check "refuses -W with .."                 argfail "plain relative path" -W a/../b
check "refuses setup flags with -d"        argfail "only apply when setting up" -d -P 18080:80
check "refuses stray arguments"            argfail "unexpected argument" -i ok extra
check "refuses empty -i (no global -d)"    argfail "-i needs an instance name" -i "" -d -a -y

echo "host state outside the sandbox (stubbed)"
# The agent controls everything under $SB; host state (the image ledger above all) must not be there.
pathrun() {  # VAR=value... -- script-args...: stderr+rc of a stubbed run with these variables
  local envs=() rc=0 out next_setting=$1
  while [[ $next_setting != -- ]]; do
    envs+=("$next_setting")
    shift
    next_setting=$1
  done
  shift
  : > "$T/stub.log"
  out=$(env -u CONTAINER_ID -u XDG_DATA_HOME -u XDG_CONFIG_HOME HOME="$T/dhome" PATH="$T/stub:$PATH" "${envs[@]}" \
        "$SCRIPT" "$@" 2>&1 </dev/null) || rc=$?
  printf '%s\nrc=%s\n' "$out" "$rc"
}
DSB=$T/dhome/opencode-sandbox; mkdir -p "$DSB/st/oc-sandbox" "$T/outer/oc-sandbox/h"
mkdir -p "$T/helper-repo"
cp "$SCRIPT" "$T/helper-repo/oc-sandbox"
printf 'open("%s", "w").write("executed")\n' "$T/helper-executed" > "$DSB/lock-helper.py"
ln -s "$DSB/lock-helper.py" "$T/helper-repo/oc-setup-lock.py"
helper_out=$(env -u CONTAINER_ID -u XDG_DATA_HOME -u XDG_CONFIG_HOME HOME="$T/dhome" PATH="$T/stub:$PATH" \
  bash "$T/helper-repo/oc-sandbox" -d -a -y 2>&1 </dev/null || true)
check "sandbox-linked lock helper refused" grep -q 'missing or unsafe oc-setup-lock.py' <<<"$helper_out"
check "sandbox-linked lock helper never executed" test ! -e "$T/helper-executed"
ln -s "$DSB/lock-helper.py" "$T/helper-repo/oc-bridge.py"
helper_out=$(env -u CONTAINER_ID -u XDG_DATA_HOME -u XDG_CONFIG_HOME HOME="$T/dhome" PATH="$T/stub:$PATH" \
  bash "$T/helper-repo/oc-sandbox" -n 2>&1 </dev/null || true)
check 'sandbox-linked bridge helper refused before setup' grep -q 'missing or unsafe oc-bridge.py' <<<"$helper_out"
out=$(pathrun OC_CODE_BIN="$DSB/editor" -- -n)
check 'sandbox-side editor executable refused' grep -q 'OC_CODE_BIN must be an absolute path outside the sandbox' <<<"$out"
out=$(pathrun OC_BCOMPARE_BIN=$'/host/editor\nextra' -- -n)
check 'newline in editor executable refused' grep -q 'OC_BCOMPARE_BIN must be an absolute path outside the sandbox' <<<"$out"
out=$(pathrun CONTAINER_ID=fixture OC_CODE_BIN="$T/dhome/guest-only-path" -- -n)
check 'editor path is refused when it enters the sandbox on the host only' \
  grep -q 'OC_CODE_BIN must be an absolute path outside the sandbox' <<<"$out"
out=$(pathrun CONTAINER_ID=fixture OC_PG_IMAGE=fixture OC_PG_USER=fixture \
  OC_PG_PASSWORD=fixture OC_PG_DB=fixture OC_PG_INIT_DIR="$T/dhome/guest-only-path" -- -p -n)
check 'Postgres init path is refused when it enters the sandbox on the host only' \
  grep -q 'refusing unsafe host Postgres init directory' <<<"$out"
out=$(pathrun CONTAINER_ID=fixture STUB_HOST_STAGE_PATH="$DSB/host-stage" -- -n)
check 'setup refuses staging that enters the sandbox on the host only' \
  grep -q 'unsafe host bridge staging directory' <<<"$out"
check 'unsafe stage is refused before systemd' ! grep -q '^systemctl' "$T/stub.log"
out=$(pathrun CONTAINER_ID=fixture STUB_HOST_STAGE_PATH="$DSB/host-stage" -- -d -a -y)
check 'global teardown refuses staging that enters the sandbox on the host only' \
  grep -q 'unsafe host bridge staging directory' <<<"$out"
check 'unsafe stage is refused before teardown removes pods' ! grep -q '^podman pod rm' "$T/stub.log"
mkdir -m 700 "$T/other-host-stage"
out=$(pathrun CONTAINER_ID=fixture STUB_HOST_STAGE_PATH="$T/other-host-stage" -- -n)
check 'setup refuses different launcher and host staging directory identities' \
  grep -q 'launcher and host see different bridge staging directories' <<<"$out"
mkdir -m 0777 "$T/unprotected-host-stage"
out=$(pathrun CONTAINER_ID=fixture STUB_HOST_STAGE_PATH="$T/unprotected-host-stage" -- -n)
check 'setup refuses an unprotected host staging directory' \
  grep -q 'unsafe host bridge staging directory' <<<"$out"
ln -s "$T/outer"$'\n' "$T/path-linebreak"
out=$(pathrun XDG_DATA_HOME="$T/path-linebreak" -- -l)
check 'line break in symlink target refused before path splitting' grep -q 'refusing to use' <<<"$out"
mkdir -p "$T/hid/hidraw0" "$T/usb/a/b"
ln -s "$T/usb/a/b" "$T/hid/hidraw0/device"
printf '\006\320\361' > "$T/usb/a/b/report_descriptor"
printf 'Vendor|\033\302\233\nother-device\n' > "$T/usb/manufacturer"
printf 'Product\r' > "$T/usb/product"
printf '0102' > "$T/usb/idVendor"
printf '0304' > "$T/usb/idProduct"
cat > "$T/check-hid.sh" <<EOF
set -euo pipefail
H=()
$(fn detect_keys | sed "s|/sys/class/hidraw|$T/hid|g")
detect_keys
EOF
check 'FIDO display metadata stays on the detected device record' \
  test "$(bash "$T/check-hid.sh")" = '/dev/hidraw0|Vendorother-device Product|0102:0304'
printf 'Vendor\302|\233\302\001\233\302\302\233\233' > "$T/usb/manufacturer"
check 'FIDO filtering cannot join bytes into terminal controls' \
  test "$(bash "$T/check-hid.sh")" = '/dev/hidraw0|Vendor Product|0102:0304'
if [[ -n $(fn fido_device_nodes) ]]; then
  check 'device argument selection accepts only hidraw paths' test \
    "$(eval "$(fn fido_device_nodes)"; fido_device_nodes <<< $'/dev/hidraw0|legitimate\nnot-a-device|text\n/dev/hidraw1 extra|text')" \
    = '/dev/hidraw0'
fi
A=$(printf 'a%.0s' {1..64})
printf '%s\n' "$A" > "$DSB/st/oc-sandbox/built-images"                 # forged by the agent
echo "$SECRET" > "$T/victim-file"; ln -s "$T/victim-file" "$DSB/st/oc-sandbox/built-images.new"
ln -sfn "$DSB" "$T/dlink"
out=$(pathrun XDG_DATA_HOME="$DSB/st" STUB_IDS="oc-agent=$A" -- -d -a -y)
check "state dir inside the sandbox: refused"         grep -qx 'rc=2' <<<"$out"
check "...before any podman call (forged ledger unused)" [ ! -s "$T/stub.log" ]
check "...planted ledger symlink target untouched"   grep -qx "$SECRET" "$T/victim-file"
sandbox_path_refusal='leads into the sandbox directory'
check "state dir reaching the sandbox via a symlink: refused" grep -q "$sandbox_path_refusal" \
  <<<"$(pathrun XDG_DATA_HOME="$T/dlink/st" -- -l)"
check "config dir inside the sandbox: refused"        grep -q "$sandbox_path_refusal" \
  <<<"$(pathrun XDG_CONFIG_HOME="$DSB/cfg" -- -l)"
# Reverse: an agent-owned symlink that points OUT of the sandbox when checked (and can be swapped
# later); a host symlink into the sandbox that hops back out; a '..' walk through the sandbox.
mkdir -p "$T/outside" "$T/outside2"; ln -sfn "$T/outside" "$DSB/xdg"; ln -sfn "$T/outside2" "$DSB/hop"
ln -sfn "$DSB/hop" "$T/hostlink"
check "agent symlink pointing outside: refused"       grep -q "$sandbox_path_refusal" \
  <<<"$(pathrun XDG_DATA_HOME="$DSB/xdg" -- -l)"
check "config via agent symlink pointing outside: refused" grep -q "$sandbox_path_refusal" \
  <<<"$(pathrun XDG_CONFIG_HOME="$DSB/xdg" -- -l)"
check "host link -> sandbox link -> outside: refused" grep -q "$sandbox_path_refusal" \
  <<<"$(pathrun XDG_DATA_HOME="$T/hostlink" -- -l)"
check "'..' through the sandbox: refused"             grep -q "$sandbox_path_refusal" \
  <<<"$(pathrun XDG_DATA_HOME="$DSB/../.local/share" -- -l)"
check "relative XDG_DATA_HOME: refused"               grep -qx 'rc=2' <<<"$(pathrun XDG_DATA_HOME=rel/share -- -l)"
ln -sfn "$T/outside" "$T/hostonly"
check "host-only symlink outside the sandbox: accepted" ! grep -qE 'refusing to use|rc=2' \
  <<<"$(pathrun XDG_DATA_HOME="$T/hostonly" -- -l)"
check "state dir containing the sandbox: refused"     grep -q 'sandbox directory .* is inside it' \
  <<<"$(pathrun HOME="$T/outer/oc-sandbox/h" XDG_DATA_HOME="$T/outer" -- -l)"
check "state dir outside the sandbox: accepted"       ! grep -qE 'refusing to use|rc=2' \
  <<<"$(pathrun XDG_DATA_HOME="$T/dhome/.local/share" -- -l)"

echo "delete scope (stubbed)"
out=$(del -i default -d -a -y)
check "-i default -d -a removes pod oc"                 grep -qx 'podman pod rm --ignore -f -- oc' <<<"$out"
check "-i default -d -a leaves other instances"         ! grep -q 'oc-other' <<<"$out"
check "-i default -d -a leaves bridge, images, login"   ! grep -qE '^systemctl|rmi|oc-home|semodule' <<<"$out"
check "-i default -d -a removes only default volumes"   grep -qx 'podman volume rm -f oc-pg' <<<"$out"
out=$(del -d)
check "bare -d still removes every instance pod"        grep -qx 'podman pod rm --ignore -f -- oc-other' <<<"$out"
check 'bare -d stops the active bridge service' grep -qx 'systemctl --user stop oc-bridge.service' <<<"$out"
DSTATE=$T/dhome/.local/share/oc-sandbox
for fault in STUB_LIST_PODS_FAIL STUB_POD_REMOVE_FAIL STUB_POD_REMAINS STUB_BRIDGE_STAYS_ACTIVE; do
  mkdir -p "$DSB/.bridge" "$DSTATE/build"
  : > "$DSB/.bridge/keep"
  out=$(pathrun "$fault=1" -- -d -a -y)
  check "teardown preserves bridge data on $fault" test -f "$DSB/.bridge/keep"
  check "teardown reports failure on $fault" ! grep -qx 'rc=0' <<<"$out"
  check "teardown preserves build state on $fault" test -d "$DSTATE/build"
done
mkdir -m 700 -p "$DSTATE/worktrees"
(umask 077; printf 'wt/repo/other\nrepo\nother\n' > "$DSTATE/worktrees/other")
for fault in STUB_VOLUME_REMOVE_FAIL=oc-other-pg STUB_SECRET_REMOVE_FAIL=oc-other-pg-password; do
  out=$(pathrun "$fault" -- -i other -d -a -y)
  check "partial instance purge ($fault) reports failure" grep -q 'instance storage cleanup incomplete' <<<"$out"
  check "partial instance purge ($fault) retains selection" test -f "$DSTATE/worktrees/other"
done
out=$(pathrun -- -i other -d -a -y)
check 'instance -d -a clears only the stale selection record' test ! -e "$DSTATE/worktrees/other"
check 'clearing the selection record succeeds' grep -qx 'rc=0' <<<"$out"
out=$(pathrun STUB_POD_EXISTS_FAIL=1 -- -l)
check 'instance listing reports incomplete inventory' grep -q 'could not list instance pods' <<<"$out"
check 'instance listing prints no successful table on inventory failure' ! grep -q '^INSTANCE' <<<"$out"
for case in "no Postgres secrets:STUB_SECRETS=" "secret ls fails:STUB_SECRET_LS_FAIL=1" \
            "secrets present:STUB_SECRETS=oc-pg-password\\nother\\noc-x-pg-password\\n"; do
  name=${case%%:*} envset=${case#*:}
  : > "$T/stub.log"; mkdir -p "$DSTATE/build"; rc=0
  env -u CONTAINER_ID -u XDG_DATA_HOME -u XDG_CONFIG_HOME "$envset" HOME="$T/dhome" PATH="$T/stub:$PATH" \
    "$SCRIPT" -d -a -y >/dev/null 2>&1 </dev/null || rc=$?
  check "-d -a ($name) completes"              [ $rc -eq 0 ]
  check "-d -a ($name) retains the persistent setup lock" [ -f "$DSTATE/setup.lock" ]
  check "-d -a ($name) retains the lifecycle barrier" [ -f "$DSTATE/lifecycle.lock" ]
  check "-d -a ($name) removes other state"    [ ! -e "$DSTATE/build" ]
  check "-d -a ($name) removes SELinux module" grep -q 'semodule -X 400 -r oc_chromium' "$T/stub.log"
done
check "-d -a removes only oc Postgres secrets" sh -c "grep -qx 'podman secret rm oc-pg-password' '$T/stub.log' \
  && grep -qx 'podman secret rm oc-x-pg-password' '$T/stub.log' && ! grep -q 'secret rm other' '$T/stub.log'"

echo "shared setup and teardown barrier (Podman stubbed; scratch HOME)"
LHOME=$T/lifecycle/home LSTATE=$T/lifecycle/home/.local/share/oc-sandbox
mkdir -p "$T/lifecycle/images" "$T/lifecycle/runtime" "$LHOME/.oh-my-zsh/custom/plugins/zsh-vi-mode" "$LSTATE/policy"
# Seed only the scratch policy marker, so these tests never invoke host SELinux tools.
sed -n '/^; SELinux type/,/^POL$/p' "$SCRIPT" | sed '$d' | sha256sum | cut -c1-16 > "$LSTATE/policy/installed"
python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); time.sleep(60)' "$T/lifecycle/runtime/wayland-0" &
LSOCK=$!
for _ in $(seq 1 100); do [[ -S $T/lifecycle/runtime/wayland-0 ]] && break; sleep .02; done
life_run() {
  env -u CONTAINER_ID -u XDG_DATA_HOME -u XDG_CONFIG_HOME HOME="$LHOME" PATH="$T/stub:$PATH" \
    XDG_RUNTIME_DIR="$T/lifecycle/runtime" WAYLAND_DISPLAY=wayland-0 OC_OPENCODE_VERSION=keep \
    STUB_SETUP=1 "$@"
}
: > "$T/lifecycle/builds"; : > "$T/stub.log"
life_run timeout 30 "$SCRIPT" -n -i first -K > "$T/lifecycle/first.out" 2>&1 </dev/null & P1=$!
life_run timeout 30 "$SCRIPT" -n -i second -K > "$T/lifecycle/second.out" 2>&1 </dev/null & P2=$!
r1=0; wait "$P1" || r1=$?; r2=0; wait "$P2" || r2=$?
check "two scratch setups complete" test "$r1:$r2" = 0:0
check "agent image built once across concurrent setups" test "$(grep -c '^oc-agent$' "$T/lifecycle/builds")" = 1
check "chromium image built once across concurrent setups" test "$(grep -c '^oc-chromium$' "$T/lifecycle/builds")" = 1
check "keep skips update containers" ! grep -q 'oc-opencode-update' "$T/stub.log"
check "waiting setup names the holder" grep -qE 'Waiting for setup \(pid=[0-9]+ instance=(first|second)\)' "$T/lifecycle/first.out" "$T/lifecycle/second.out"
setup_inode=$(stat -c '%d:%i' "$LSTATE/setup.lock" 2>/dev/null || true)
life_inode=$(stat -c '%d:%i' "$LSTATE/lifecycle.lock" 2>/dev/null || true)
life_run env STUB_HOLD_POD=1 timeout 30 "$SCRIPT" -n -i third -K > "$T/lifecycle/third.out" 2>&1 </dev/null & P3=$!
for _ in $(seq 1 200); do [[ -e $T/lifecycle/entered ]] && break; sleep .02; done
check "setup reached per-instance pod creation" test -e "$T/lifecycle/entered"
life_run env STUB_DELETE_SIGNAL=1 timeout 30 "$SCRIPT" -d -a -y > "$T/lifecycle/delete.out" 2>&1 </dev/null & P4=$!
sleep .4
check "global teardown waits while instance creation is active" test ! -e "$T/lifecycle/deleted"
touch "$T/lifecycle/release"
r3=0; wait "$P3" || r3=$?; r4=0; wait "$P4" || r4=$?
check "setup and subsequent teardown complete" test "$r3:$r4" = 0:0
check "teardown proceeds after instance creation" test -e "$T/lifecycle/deleted"
check "setup lock inode survives global teardown" test "$setup_inode" = "$(stat -c '%d:%i' "$LSTATE/setup.lock" 2>/dev/null || true)"
check "lifecycle lock inode survives global teardown" test "$life_inode" = "$(stat -c '%d:%i' "$LSTATE/lifecycle.lock" 2>/dev/null || true)"
kill "$LSOCK" 2>/dev/null || true; wait "$LSOCK" 2>/dev/null || true

echo "SELinux module teardown (all calls stubbed; scratch HOME)"
# No privileged mutation or real -d/-a occurs in these cases.
for vars in 'STUB_MODULES=' 'STUB_MODULES=200 oc_chromium cil'; do
  out=$(pathrun "$vars" -- -d -a -y)
  check "absent priority-400 module succeeds ($vars)" grep -qx 'rc=0' <<<"$out"
  check "absent module: no escalation ($vars)" ! grep -qE '^(pkexec|sudo) ' "$T/stub.log"
  check "absent module: no removal claim ($vars)" ! grep -q 'Removing SELinux module' <<<"$out"
done
out=$(pathrun 'STUB_MODULES=400 oc_chromium cil' -- -d -a -y)
check "present module removal succeeds" grep -qx 'rc=0' <<<"$out"
check "present module: remove only priority 400" grep -qx 'pkexec semodule -X 400 -r oc_chromium' "$T/stub.log"
out=$(pathrun STUB_SEMODULE_LIST_FAIL=1 STUB_MODULES= -- -d -a -y)
check "private store: elevated listing finds absence" grep -qx 'rc=0' <<<"$out"
check "private store: no removal for absent module" ! grep -q ' -r oc_chromium' "$T/stub.log"
mkdir -p "$DSTATE"
out=$(pathrun STUB_SEMODULE_LIST_FAIL=1 STUB_ELEV_LIST_FAIL=1 -- -d -a -y)
check "listing failure returns failure" grep -qx 'rc=1' <<<"$out"
check "listing failure identifies incomplete cleanup" grep -q 'could not list SELinux modules' <<<"$out"
check "listing failure does not try sudo" ! grep -q '^sudo ' "$T/stub.log"
check "listing failure retains state for retry" [ -d "$DSTATE" ]
mkdir -p "$DSB/.bridge"
: > "$DSB/.bridge/keep"
out=$(pathrun STUB_REMOVE_FAIL=1 -- -d -a -y)
check 'SELinux cleanup failure keeps the bridge spool for retry' test -f "$DSB/.bridge/keep"
check "removal failure returns failure" grep -qx 'rc=1' <<<"$out"
check "removal failure reports incomplete cleanup" grep -q 'could not remove SELinux module' <<<"$out"
check "removal failure does not retry with sudo" ! grep -q '^sudo ' "$T/stub.log"
check "removal failure retains state for retry" [ -d "$DSTATE" ]
binding_home=$T/binding-home
binding_stage="$binding_home/.local/share/oc-sandbox/bridge-stage"
binding_units="$binding_home/.config/systemd/user"
mkdir -p "$binding_stage/edit" "$binding_units" "$T/alternate-data"
printf 'unsaved fixture' > "$binding_stage/edit/save"
printf '[Service]\nEnvironment="OC_BRIDGE_STAGE=%s"\n' "$binding_stage" > "$binding_units/oc-bridge.service"
out=$(pathrun HOME="$binding_home" XDG_DATA_HOME="$T/alternate-data" -- -d -a -y)
check 'purge refuses a caller root different from the installed legacy stage' \
  grep -q 'installed bridge stage differs' <<<"$out"
check 'legacy stage mismatch is refused before resource removal' \
  ! grep -qE '^podman (pod|volume) rm|^systemctl' "$T/stub.log"
check 'legacy stage mismatch preserves the installed service' test -f "$binding_units/oc-bridge.service"
out=$(pathrun HOME="$binding_home" -- -d -a -y)
check 'matching legacy stage protects its outstanding save' grep -q 'staged editor sessions remain' <<<"$out"
check 'refused purge retains the installation binding' test -f "$binding_units/.oc-sandbox/binding"
out=$(pathrun HOME="$binding_home" XDG_DATA_HOME="$T/alternate-data" -- -d -a -y)
check 'retry with a different root is refused after dispatcher removal' \
  grep -q 'installed state or bridge stage differs' <<<"$out"
check 'different-root retry is refused before resource removal' \
  ! grep -qE '^podman (pod|volume) rm|^systemctl' "$T/stub.log"
check 'different-root retry leaves the outstanding save intact' grep -qx 'unsaved fixture' "$binding_stage/edit/save"
unlink "$binding_stage/edit/save"
rmdir "$binding_stage/edit"
out=$(pathrun HOME="$binding_home" -- -d -a -y)
check 'successful matching purge releases the installation binding' test ! -e "$binding_units/.oc-sandbox/binding"
mkdir -p "$DSTATE/bridge-stage/edit"
printf 'unsaved fixture' > "$DSTATE/bridge-stage/edit/save"
out=$(pathrun -- -d -a -y)
check 'global purge refuses while staged edits remain' grep -q 'staged editor sessions remain' <<<"$out"
check 'global purge preserves staged edit' grep -qx 'unsaved fixture' "$DSTATE/bridge-stage/edit/save"
check 'global purge does not remove volumes with staged edits' ! grep -q '^podman volume rm' "$T/stub.log"
unlink "$DSTATE/bridge-stage/edit/save"
rmdir "$DSTATE/bridge-stage/edit"
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
  if ! "${H[@]}" podman image exists "$TEST_AGENT_IMG" 2>/dev/null; then echo "  skip  (no test agent image; run oc-sandbox -n first or supply OC_TEST_AGENT_IMAGE)"; else
    delimited_update_image() {
      local id output
      id=$("${H[@]}" podman create --rm --network=none --cap-drop=ALL --security-opt=no-new-privileges \
        --entrypoint python3 -- "$TEST_AGENT_IMG" -I -c 'print("update image operand accepted")') || return
      [[ $id =~ ^[0-9a-f]{64}$ ]] || return 1
      if ! output=$("${H[@]}" podman start -a "$id"); then
        "${H[@]}" podman rm -f "$id" >/dev/null 2>&1 || true
        return 1
      fi
      [[ $output == 'update image operand accepted' ]]
    }
    check "real Podman accepts the delimited updater image operand" delimited_update_image
    real_bridge_mcs() {
      local fixture=$T/bridge-mcs
      mkdir -p "$fixture/sandbox" "$fixture/stage"
      printf 'old' > "$fixture/sandbox/file"
      "${H[@]}" python3 -I - "$BRIDGE" "$fixture" <<'PYCODE'
import os
from pathlib import Path
import runpy
import sys

script, directory = sys.argv[1:]
root = Path(directory)
os.environ.update(OC_SB=str(root / "sandbox"), OC_BRIDGE_STAGE=str(root / "stage"),
                  OC_BRIDGE_SELINUX_LEVEL="s0:c7,c9")
bridge = runpy.run_path(script)
target = root / "sandbox" / "file"
for conflict in (False, True):
    identity = bridge["ident"](target.stat())
    if conflict:
        target.write_bytes(b"changed source")
    with (root / "stage" / "edit").open("w+b") as edit:
        edit.write(b"saved bytes")
        edit.seek(0)
        stage_fd = os.open(root / "stage", os.O_RDONLY | os.O_DIRECTORY)
        try:
            bridge["write_back"]({"parts": ["file"], "target": identity},
                                 (edit.fileno(), os.fstat(edit.fileno())), stage_fd)
        finally:
            os.close(stage_fd)
    destination = target.with_name("file.host-edit") if conflict else target
    assert destination.read_bytes() == b"saved bytes"
    assert os.getxattr(destination, "security.selinux").rstrip(b"\0") == b"system_u:object_r:container_file_t:s0:c7,c9"
PYCODE
    }
    check "real SELinux bridge saves keep the sandbox MCS label" real_bridge_mcs
    VOL=oc-sectest-$$
    cat > "$T/lib.sh" <<EOF
H=(${H[*]}); pm() { "\${H[@]}" podman "\$@"; }
AGENT_IMG=$TEST_AGENT_IMG AGENT_MEM=512m HOMEVOL=$VOL LEVEL=s0:c7,c9 SB=\$1; shift
$(sed -n '/^safe_run() {/,/; }$/p' "$SCRIPT")
$(fn tree_run)
$(sed -n "/^SANDBOX_TREE_PY=/,/os.makedirs(dest, exist_ok=True)'$/p" "$SCRIPT")
$(fn init_sandbox_tree)
$(fn init_bridge_spool)
$(sed -n "/^RELABEL_PY=/,/file=sys.stderr)'\$/p" "$SCRIPT")
$(fn relabel_shared)
if [[ \$1 == init_sandbox_tree ]] && declare -F tree_run >/dev/null; then
  safe_run --cap-add=FOWNER --entrypoint python3 "\$AGENT_IMG" \
    -I -c "\$RELABEL_PY" "system_u:object_r:container_file_t:\$LEVEL" /sandbox || exit 1
fi
"\$@"
EOF
    lib() { bash "$T/lib.sh" "$@"; }
    inbox() {
      local shell_code=$1
      "${H[@]}" podman run --rm --network=none --security-opt=label=disable -v "$T/isb":/sandbox -w /sandbox \
        --entrypoint sh "$TEST_AGENT_IMG" -c "$shell_code"
    }
    mk() { rm -rf "$T/isb" "$T/iv"; mkdir -p "$T/isb" "$T/iv"; echo "$SECRET" > "$T/iv/keep"; }
    mk; lib "$T/isb" init_bridge_spool >/dev/null 2>&1
    lib "$T/isb" init_sandbox_tree construct >/dev/null 2>&1
    check "working directory created" [ -d "$T/isb/construct" ]
    check "bridge request spool created" [ -d "$T/isb/.bridge/requests" ]
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
    check "-W repo symlinked to the host leaves the host target intact" [ "$(ls -A "$T/iv")" = keep ]
    check "-W repo symlinked to the host creates no worktree git link" [ ! -e "$T/isb/wt/y/.git" ]

    mk; echo data > "$T/isb/f"; ln -s "$T/iv/keep" "$T/isb/link-to-host"; ln -s ../iv "$T/isb/rel-link"
    before=$(stat -c %C "$T/iv/keep")
    "${H[@]}" podman volume create "$VOL" >/dev/null
    lib "$T/isb" relabel_shared >/dev/null 2>&1
    "${H[@]}" podman volume rm -f "$VOL" >/dev/null
    check "relabel: sandbox file gets the agents' level" [ "$(stat -c %C "$T/isb/f")" = system_u:object_r:container_file_t:s0:c7,c9 ]
    check "relabel: symlink targets on the host untouched" [ "$(stat -c %C "$T/iv/keep")" = "$before" ]
  fi
fi

echo "image ledger under parallel use (podman stubbed)"
cat > "$T/ledger.sh" <<EOF
set -euo pipefail
IMAGE_LOG=$T/ledger/built-images
$(fn owned_image); $(fn ledger_locked); $(fn _ledger_add); $(fn record_image); $(fn _prune); $(fn prune_images)
pm() { sleep 0.01; echo 1; }   # every recorded image still tagged: a rewrite must keep them all
for i in 1 2 3 4 5; do record_image "\$(printf '%064x' \$((\$1 * 100 + i)))"; prune_images; done
EOF
rm -rf "$T/ledger"; mkdir -p "$T/ledger"; : > "$T/ledger/built-images"
pids=(); for w in 1 2 3 4 5 6 7 8; do bash "$T/ledger.sh" $w > "$T/ledger/out.$w" 2>&1 & pids+=($!); done
lrc=0; for pid in "${pids[@]}"; do wait "$pid" || lrc=1; done
check "parallel ledger updates: all succeed"          [ $lrc -eq 0 ]
check "parallel ledger updates: no ID lost (40)"      [ "$(sort -u "$T/ledger/built-images" | grep -c .)" -eq 40 ]
check "parallel ledger updates: no temp files left"   [ -z "$(find "$T/ledger" -name 'built-images.?*' ! -name '*.lock')" ]
check "parallel ledger updates: no warnings"          ! grep -q . "$T"/ledger/out.*

echo "image ownership (real Podman, throwaway images FROM scratch)"
if [[ -n ${OC_TEST_NO_PODMAN:-} ]]; then echo "  skip  (OC_TEST_NO_PODMAN)"; else
  if [[ -n ${CONTAINER_ID:-} ]] && command -v distrobox-host-exec >/dev/null; then H=(distrobox-host-exec); else H=(); fi
  IT=localhost/oc-imgtest-$$ L=io.github.gorban.opencode-sandbox.image
  mkdir -p "$T/ib"; printf 'FROM scratch\n' > "$T/ib/Containerfile.t"
  cat > "$T/img.sh" <<EOF
set -euo pipefail
H=(${H[*]}); pm() { "\${H[@]}" podman "\$@"; }
IMAGE_LOG=$T/built-images OWNER_LABEL=$L
$(fn owned_image); $(fn ledger_locked); $(fn _ledger_add); $(fn record_image); $(fn _prune); $(fn prune_images)
$(fn ensure_image)
log() { :; }
REBUILD=1 PULL=() BUILD=$T/ib
"\$@"
EOF
  img() { bash "$T/img.sh" "$@" 2>&1 >/dev/null; }
  iid() { local image_reference=$1; "${H[@]}" podman image inspect --format '{{.Id}}' "$image_reference" 2>/dev/null; }
  has() { local image_reference=$1; "${H[@]}" podman image exists "$image_reference"; }
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
