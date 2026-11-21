#!/usr/bin/env bash
# Exercise the container's fixed Python program against disposable repositories outside $SB.
set -euo pipefail
SCRIPT=${SCRIPT:-$(cd "$(dirname "$0")/.." && pwd)/oc-sandbox}
t=$(mktemp -d); trap 'rm -rf -- "$t"' EXIT
mkdir -p "$t/sandbox/construct/project/nested" "$t/home"
export HOME="$t/home" GIT_CONFIG_NOSYSTEM=1
python3 - "$SCRIPT" "$t" <<'PY'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
start = s.index("SANDBOX_TREE_PY='") + len("SANDBOX_TREE_PY='")
end = s.index("\ninit_sandbox_tree()", start)
p = s[start:end].rstrip()
assert p.endswith("'")
p = p[:-1].replace('/sandbox', sys.argv[2] + '/sandbox')
pathlib.Path(sys.argv[2], 'tree.py').write_text(p)
PY
repo="$t/sandbox/construct/project"
git init -q -b main "$repo"
git -C "$repo" -c user.name=test -c user.email=test@example.invalid commit --allow-empty -qm init
run() { python3 "$t/tree.py" "$@"; }
pass=0
check() { if "$@"; then pass=$((pass+1)); else echo "FAIL: $*" >&2; exit 1; fi; }
check test "$(run detect construct/project/nested)" = construct/project
check run init wt/construct/project/feature construct/project feature
check test "$(git -C "$t/sandbox/wt/construct/project/feature" branch --show-current)" = feature
check run init wt/construct/project/feature construct/project feature
check test "$(run info wt/construct/project/feature)" = construct/project:feature
git -C "$repo" branch existing
check run init wt/existing construct/project existing
if run init wt/construct/project/feature construct/project wrong 2>/dev/null; then echo 'FAIL: mismatch accepted' >&2; exit 1; else pass=$((pass+1)); fi
ln -s project "$t/sandbox/construct/link"
if run detect construct/link/nested 2>/dev/null; then echo 'FAIL: symlink accepted' >&2; exit 1; else pass=$((pass+1)); fi
if run detect wt/construct/project/feature 2>/dev/null; then echo 'FAIL: nested worktree accepted' >&2; exit 1; else pass=$((pass+1)); fi
if run init wt/bad construct/project -option 2>/dev/null; then echo 'FAIL: option branch accepted' >&2; exit 1; else pass=$((pass+1)); fi
# Exercise the actual destination-selection block with a fake safe_run and scratch HOME.
python3 - "$SCRIPT" "$t/selection.sh" <<'PYCODE'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
a = s.index("# Serialize worktree selection")
b = s.index("release_worktree_lock", a) + len("release_worktree_lock")
pathlib.Path(sys.argv[2]).write_text(s[a:b])
PYCODE
mkdir -p "$t/state"
(
  cd "$repo/nested"
  SB="$t/sandbox"; sb_real=$SB; AGENT_IMG=oc-agent; SANDBOX_TREE_PY=stub; STATE="$t/state"; ILABEL=second; INST=second
  CALLER_PWD=$PWD; CALLER_PHYSICAL=$(pwd -P)
  CWD_ARG= WT_ARG= WT_REPO= WT_BRANCH= CWD=wt/second
  valid_relpath() { local candidate_path=$1; [[ $candidate_path =~ ^[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$ ]]; }
  die() { echo "$*" >&2; exit 1; }
  SCRIPT_DIR=${SCRIPT%/*}
  in_sb() { local candidate_path=$1; [[ $candidate_path/ == "$sb_real"/* ]]; }
  for fn_name in trusted_path trusted_file trusted_dir worktree_state; do
    eval "$(sed -n "/^$fn_name() {/,/^}/p" "$SCRIPT")"
  done
  acquire_guard() { :; }; release_worktree_lock() { :; }
  safe_run() { run detect "${@: -1}"; }
  init_sandbox_tree() { run init "$@"; }
  source "$t/selection.sh"
  [[ $CWD = wt/construct/project/second ]]
  cd "$t"
  CALLER_PWD=$PWD; CALLER_PHYSICAL=$(pwd -P)
  CWD=wt/second WT_REPO= WT_BRANCH=
  source "$t/selection.sh"
  [[ $CWD = wt/construct/project/second && $WT_REPO = construct/project && $WT_BRANCH = second ]]
) || { echo 'FAIL: detection or relaunch selection' >&2; exit 1; }
pass=$((pass+2))
echo "$pass worktree checks passed"
