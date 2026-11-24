#!/usr/bin/env bash
# Acceptance test for parallel instances, port mapping, per-instance Postgres, docker-in-docker and
# worktrees, against the real host (Podman, SELinux and headless Chromium).
# Creates instances ptest1/ptest2 and $SB/.oc-ptest-repo, and removes them again (also on failure).
# Run through tests/parallel-isolated.py; direct execution is refused.
set -uo pipefail
[[ ${OC_PTEST_ISOLATED:-} == 1 ]] || { echo "Use tests/parallel-isolated.py; direct execution is unsafe" >&2; exit 2; }
REPO=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
OCS=$REPO/oc-sandbox SB=$HOME/opencode-sandbox
if [[ -n ${CONTAINER_ID:-} ]] && command -v distrobox-host-exec >/dev/null; then H=(distrobox-host-exec); else H=(); fi
host_podman() { "${H[@]}" podman "$@"; }
LEVEL=$(cat "${XDG_DATA_HOME:-$HOME/.local/share}/oc-sandbox/sb-level" 2>/dev/null || true)
T=$(mktemp -d "${TMPDIR:-/tmp}/oc-ptest.XXXXXX")
pass=0 fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$*"; }
check() {
  local description=$1 expected=0 result
  shift
  local first_argument=$1
  if [[ $first_argument == '!' ]]; then expected=1; shift; fi
  if "$@" >/dev/null 2>&1; then result=0; else result=1; fi
  if (( result == expected )); then ok "$description"; else bad "$description"; fi
}
inbox() {  # run a fixed command in a throwaway container that sees only $SB (never touch $SB from the host)
  host_podman run --rm -i --network=none --cap-drop=ALL --security-opt=no-new-privileges --security-opt=label=disable \
    -v "$SB":/sandbox -w /sandbox --entrypoint sh "${OC_PTEST_INBOX_IMAGE:-oc-agent}" -c "$@"; }
# the test's Postgres settings (environment wins over postgres.env; no init scripts)
export OC_PG_IMAGE=${OC_PTEST_PG_IMAGE:-docker.io/library/postgres:17} OC_PG_USER=ptest OC_PG_PASSWORD=ptest-pw \
       OC_PG_DB=ptest OC_PG_INIT_DIR=/nonexistent
cleanup() {
  echo "stopping acceptance-test jobs; private store cleanup follows"
  local pid
  for pid in $(jobs -p); do kill "$pid" 2>/dev/null || true; done
  for pid in $(jobs -p); do wait "$pid" 2>/dev/null || true; done
  rm -rf "$T"
}
trap cleanup EXIT

if [[ ${OC_CHROMIUM_MODE:-} == wayland ]]; then
  echo "Wayland smoke: one visible Chromium window"
  "$OCS" -n -K -i ptest1 > "$T/wayland.log" 2>&1 || {
    tail -n 80 "$T/wayland.log"; exit 1;
  }
  for _ in $(seq 1 15); do
    if host_podman exec oc-ptest1-chromium curl -sf --max-time 2 http://127.0.0.1:9222/json/list \
        | grep -F '"title": "oc ptest1"' >/dev/null; then
      echo "Wayland Chromium and its named DevTools tab verified."
      exit 0
    fi
    sleep 1
  done
  echo "Wayland Chromium's expected DevTools tab did not appear" >&2
  exit 1
fi
[[ ${OC_CHROMIUM_MODE:-} == headless ]] || { echo "Missing isolated Chromium mode" >&2; exit 2; }

echo "prepare: test repository inside the sandbox (with a hook that must NOT run)"
OC_PTEST_INBOX_IMAGE=docker.io/alpine/git:latest inbox 'test -d /sandbox' || { echo "bootstrap container or sandbox mount failed" >&2; exit 1; }
OC_PTEST_INBOX_IMAGE=docker.io/alpine/git:latest inbox 'd=$(mktemp -d "${TMPDIR:-/tmp}/oc-git-check.XXXXXX") || exit 1; trap '\''rm -rf "$d"'\'' EXIT; mkdir "$d/repo" || exit 1; git -C "$d/repo" init -q || exit 1; git -C "$d/repo" -c user.name=Test -c user.email=test@example.invalid -c core.hooksPath=/dev/null commit --allow-empty -qm init || exit 1; git -C "$d/repo" -c core.hooksPath=/dev/null worktree add -q --relative-paths -b oc-test "$d/wt" || exit 1; IFS= read -r link < "$d/wt/.git" || exit 1; case "$link" in "gitdir: ../repo/.git/worktrees/"*) ;; *) exit 1;; esac' || { echo "could not verify bootstrap Git relative-worktree support" >&2; exit 1; }
OC_PTEST_INBOX_IMAGE=docker.io/alpine/git:latest inbox 'set -e; rm -rf .oc-ptest-repo wt/ptest1 wt/ptest2; mkdir .oc-ptest-repo; cd .oc-ptest-repo
  git init -q -b main; git config user.email t@t; git config user.name t
  cat > echo.py <<EOF
import http.server, os
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("<title>instance " + os.environ["OC_INSTANCE"] + "</title>" + os.environ["OC_INSTANCE"] + "\n").encode()
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 3000), H).serve_forever()
EOF
  git add echo.py; git commit -qm init
  printf "#!/bin/sh\ntouch /sandbox/.oc-ptest-repo/HOOK-RAN\n" > .git/hooks/post-checkout; chmod +x .git/hooks/post-checkout' || { echo "repository preparation failed" >&2; exit 1; }

echo "setup: two instances (each: own pod, Chromium, Postgres; ptest1 also docker-in-docker)"
"$OCS" -n -K -i ptest1 -P 18181:3000 -p -D -W .oc-ptest-repo > "$T/ptest1.log" 2>&1 & setup1=$!
"$OCS" -n -K -i ptest2 -P 18182:3000,18192:80 -p -W .oc-ptest-repo:other > "$T/ptest2.log" 2>&1 & setup2=$!
wait "$setup1"; r1=$?; wait "$setup2"; r2=$?
check "shared agent image built once" [ "$(grep -hcF '==> Building oc-agent' "$T/ptest1.log" "$T/ptest2.log" | awk '{n+=$1} END{print n+0}')" -eq 1 ]
check "shared Chromium image built once" [ "$(grep -hcF '==> Building oc-chromium' "$T/ptest1.log" "$T/ptest2.log" | awk '{n+=$1} END{print n+0}')" -eq 1 ]
check "setup ptest1" [ $r1 -eq 0 ]; check "setup ptest2" [ $r2 -eq 0 ]
(( r1 == 0 && r2 == 0 )) || { tail -n 80 -- "$T/ptest1.log" "$T/ptest2.log"; exit 1; }
# The named-removal test needs a default pod. Keep the bootstrap store empty
# until setup has recorded its installation binding.
host_podman pod create --name oc >/dev/null || { echo "could not create private default-pod sentinel" >&2; exit 1; }
LEVEL=$(cat "${XDG_DATA_HOME:-$HOME/.local/share}/oc-sandbox/sb-level")

echo "worktrees"
check "ptest1 worktree on branch ptest1" inbox '[ "$(git -C wt/ptest1 branch --show-current)" = ptest1 ]'
check "ptest2 worktree on branch other"  inbox '[ "$(git -C wt/ptest2 branch --show-current)" = other ]'
check "worktree link is relative"        inbox 'grep -q "^gitdir: \.\./\.\./\.oc-ptest-repo/" wt/ptest1/.git'
check "repository hooks did not run"     inbox '[ ! -e .oc-ptest-repo/HOOK-RAN ]'

echo "real agents, launched in parallel (pseudo-terminals)"
for i in ptest1 ptest2; do
  ( exec script -qec "$OCS -K -i $i" /dev/null >$T/$i.agent.log 2>&1 ) & sleep 1
done
for _ in $(seq 1 60); do
  [[ $(host_podman container inspect -f '{{.State.Status}}' oc-ptest1-agent 2>/dev/null) == running &&
     $(host_podman container inspect -f '{{.State.Status}}' oc-ptest2-agent 2>/dev/null) == running ]] && break; sleep 1
done
check "both agents running at once" [ "$(host_podman ps --filter name='^oc-ptest[12]-agent$' -q | wc -l)" -eq 2 ]
agent_shell() {
  local instance=$1 script=$2
  host_podman exec "oc-${instance}-agent" sh -c "$script"
}
check "ptest1 agent cwd is its worktree" [ "$(host_podman container inspect -f '{{.Config.WorkingDir}}' oc-ptest1-agent)" = /sandbox/wt/ptest1 ]
check "agents share one SELinux level"   [ "$(agent_shell ptest1 'cat /proc/self/attr/current' | tr -d '\0')" = "system_u:system_r:container_t:$LEVEL" ]
check "both agents write the sandbox"    agent_shell ptest1 'echo one > /sandbox/wt/ptest1/w1 && cat /sandbox/wt/ptest2/echo.py >/dev/null'
check "...concurrently"                  agent_shell ptest2 'echo two > /sandbox/wt/ptest2/w2 && cat /sandbox/wt/ptest1/w1 | grep -q one'
check "agent still allowed after the other started" agent_shell ptest1 'cat /sandbox/wt/ptest2/w2 | grep -q two'
check "Chromium MCP config present"      agent_shell ptest1 'grep -q chrome-devtools "$OPENCODE_CONFIG"'
check "instance name in agent env"       [ "$(agent_shell ptest2 'echo $OC_INSTANCE')" = ptest2 ]

echo "same app, same port, both instances"
for i in ptest1 ptest2; do agent_shell $i "cd /sandbox/wt/$i && nohup python3 echo.py >/dev/null 2>&1 &"; done; sleep 2
check "ptest1 agent sees its own app"    [ "$(agent_shell ptest1 'curl -s 127.0.0.1:3000' | sed 's|.*>||')" = ptest1 ]
check "ptest2 agent sees its own app"    [ "$(agent_shell ptest2 'curl -s 127.0.0.1:3000' | sed 's|.*>||')" = ptest2 ]
check "host :18181 -> ptest1"            [ "$("${H[@]}" curl -s -m 3 127.0.0.1:18181 | sed 's|.*>||')" = ptest1 ]
check "host :18182 -> ptest2"            [ "$("${H[@]}" curl -s -m 3 127.0.0.1:18182 | sed 's|.*>||')" = ptest2 ]
check "host cannot reach pod port 3000 directly" ! "${H[@]}" curl -s -m 2 127.0.0.1:3000
lan=$("${H[@]}" sh -c "ip -4 -o route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p'")
check "mapped port not on the LAN ($lan)" ! "${H[@]}" curl -s -m 2 "$lan:18181"
headless_configuration() {
  host_podman container inspect "$1" | python3 -c '
import json, sys
browser, = json.load(sys.stdin)
env = {item.split("=", 1)[0] for item in browser["Config"]["Env"]}
mounts = {item["Destination"] for item in browser["Mounts"]}
valid = ("--headless" in browser["Config"]["Cmd"] and mounts == {"/profile"}
         and not browser["HostConfig"].get("Devices")
         and not env & {"DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"})
raise SystemExit(0 if valid else 1)
'
}
for i in ptest1 ptest2; do
  check "$i Chromium has no display or hardware device exposure" headless_configuration "oc-$i-chromium"
  host_podman exec "oc-$i-chromium" curl -s -X PUT "http://127.0.0.1:9222/json/new?http://127.0.0.1:3000/" >/dev/null
done; sleep 3
check "ptest1 Chromium loads its own app" sh -c "${H[*]} podman exec oc-ptest1-chromium curl -s 127.0.0.1:9222/json/list | grep -q '\"title\": \"instance ptest1\"'"
check "ptest2 Chromium loads its own app" sh -c "${H[*]} podman exec oc-ptest2-chromium curl -s 127.0.0.1:9222/json/list | grep -q '\"title\": \"instance ptest2\"'"
check "port 80 in pod (ptest2, no extra capability)" agent_shell ptest2 'python3 -c "import socket; s=socket.socket(); s.bind((\"127.0.0.1\", 80))"'

echo "Postgres data is per instance"
postgres_query() {
  local instance=$1 sql=$2
  host_podman exec "oc-${instance}-postgres" psql -qtA -U ptest -d ptest -c "$sql"
}
postgres_query ptest1 'create table only_in_ptest1(x int)' >/dev/null
check "table exists in ptest1"           [ "$(postgres_query ptest1 "select to_regclass('only_in_ptest1') is not null")" = t ]
check "table absent in ptest2"           [ "$(postgres_query ptest2 "select to_regclass('only_in_ptest1') is not null")" = f ]
check "agent reaches its Postgres"       agent_shell ptest1 'psql -h 127.0.0.1 -U ptest -d ptest -qtAc "select 1" | grep -qx 1'

echo "docker-in-docker (ptest1 only)"
check "docker CLI talks to the sidecar"  agent_shell ptest1 'docker version --format "{{.Server.Version}}"'
check "docker compose available"         agent_shell ptest1 'docker compose version'
agent_shell ptest1 'docker run -d -q --name whoami --network host docker.io/traefik/whoami --port 3001' >/dev/null 2>&1; sleep 3
check "nested echo server reachable from the agent" agent_shell ptest1 'curl -s -m 3 127.0.0.1:3001 | grep -q "^Hostname"'
check "...and from ptest1's Chromium"    host_podman exec oc-ptest1-chromium curl -s -m 3 127.0.0.1:3001
check "...but not from ptest2"           ! agent_shell ptest2 'curl -s -m 2 127.0.0.1:3001'
check "nested default network works"     agent_shell ptest1 'docker run --rm -q docker.io/library/alpine:3.22 wget -qO- -T 5 http://example.com | grep -qi example'
check "nested containers can read the sandbox" agent_shell ptest1 'docker run --rm -q -v /sandbox/wt/ptest1:/w docker.io/library/alpine:3.22 cat /w/echo.py'
check "ptest2 has no docker"             ! agent_shell ptest2 'docker version'

echo "management"
"$OCS" -l > $T/ptest.list 2>&1
check "-l lists both with ports"         sh -c "grep -q '^ptest1 .*18181->3000' $T/ptest.list && grep -q '^ptest2 .*18182->3000,18192->80' $T/ptest.list"
"$OCS" -n -K -i ptest1 -P 18183:3000 > $T/ptest.refuse 2>&1; rc=$?
check "port change refused while agent runs" sh -c "[ $rc -ne 0 ] && grep -q 'OpenCode is running' $T/ptest.refuse"
chrome_before=$(host_podman container inspect --format '{{.Id}}' oc-ptest2-chromium)
"$OCS" -n -K -i ptest2 > $T/ptest.rerun 2>&1; rc=$?
check "rerun without -P keeps the mapping" sh -c "[ $rc -eq 0 ] && ${H[*]} curl -s -m 3 127.0.0.1:18182 | grep -q ptest2"
check "rerun keeps the headless Chromium container" bash -c '[[ -n $1 && $1 == "$2" ]]' fixture \
  "$chrome_before" "$(host_podman container inspect --format '{{.Id}}' oc-ptest2-chromium)"
host_podman stop -t 2 oc-ptest1-agent >/dev/null 2>&1
"$OCS" -n -K -i ptest1 -P 18183:3000 > $T/ptest.change 2>&1; rc=$?
check "port change after agent exits"    [ $rc -eq 0 ]
check "...keeps Postgres data"           [ "$(postgres_query ptest1 "select to_regclass('only_in_ptest1') is not null")" = t ]
check "...keeps docker-in-docker"        [ "$(host_podman container inspect -f '{{.State.Status}}' oc-ptest1-dind 2>/dev/null)" = running ]
check "...old host port gone"            ! "${H[@]}" curl -s -m 2 127.0.0.1:18181
"$OCS" -d -i ptest1 > /dev/null 2>&1
check "-d -i removes only that instance" sh -c "! ${H[*]} podman pod exists oc-ptest1 && ${H[*]} podman pod exists oc-ptest2 && ${H[*]} podman pod exists oc"
check "...and keeps its volumes"         host_podman volume exists oc-ptest1-pg

echo; echo "$pass passed, $fail failed"
(( fail == 0 ))
