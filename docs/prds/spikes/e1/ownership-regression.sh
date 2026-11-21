#!/usr/bin/env bash
# Simulate Podman: no real resource is accessed. Pass a probe.sh path to test an old revision.
set -euo pipefail
probe=$(realpath "${1:-$(dirname "$0")/probe.sh}")
t=$(mktemp -d)
trap 'rm -rf -- "$t"' EXIT
mkdir "$t/bin"
printf '#!/bin/sh\nexit 1\n' > "$t/bin/distrobox-host-exec"
chmod +x "$t/bin/distrobox-host-exec"
export PATH="$t/bin:$PATH" T="$t" PROBE="$probe"
if [[ ${E1_OWNERSHIP_CASE:-all} != replacement && ${E1_OWNERSHIP_CASE:-all} != build ]]; then
# Even an owner-label match cannot authorize deletion of a candidate whose creation failed.
OC_E1_NOMAIN=1 bash -c '
 source "$PROBE"
 pm() {
   [[ $2 == exists ]] && return 0
   [[ $2 == inspect ]] && { printf "%s\n" "$OWNER"; return 0; }
   printf "%s\n" "$*" >> "$T/actions"
 }
 IMGS_BUILT=("$P-alpine")
 cleanup
' 2>/dev/null || true
if [[ -s "$t/actions" ]]; then echo 'deleted resources without creation receipts' >&2; cat "$t/actions" >&2; exit 1; fi
fi
if [[ ${E1_OWNERSHIP_CASE:-all} != failed && ${E1_OWNERSHIP_CASE:-all} != build ]]; then
# Simulate names being replaced between inspection and deletion: only the IDs of
# resources actually created may be deleted. No name or foreign ID is authorized.
: > "$t/actions"
OC_E1_NOMAIN=1 bash -c '
 source "$PROBE"
 mkdir -p "$W/ids"
 printf "%064d" 1 > "$W/ids/pod"
 printf "%064d" 2 > "$W/ids/ctr-srv"
 printf "sha256:%064d" 3 > "$W/ids/img-alpine"
 pm() {
   [[ $2 == exists ]] && return 0
   if [[ $2 == inspect ]]; then printf "%s\n" "$OWNER"; return 0; fi
   printf "%s\n" "$*" >> "$T/actions"
 }
 IMGS_BUILT=("$P-alpine")
 cleanup
' 2>/dev/null || true
python3 - "$t/actions" <<'PY'
import sys
actual = open(sys.argv[1]).read().splitlines()
expected = ['rm -f ' + f'{2:064d}', 'pod rm ' + f'{1:064d}', 'rmi ' + f'{3:064d}']
if actual != expected:
    raise SystemExit('wrong deletion targets: ' + repr(actual))
PY
fi
# Builds must never write a mutable image tag, even if another process creates it concurrently.
: > "$t/actions"
OC_E1_NOMAIN=1 bash -c '
 source "$PROBE"
 pm() {
   [[ $1 == image && $2 == exists ]] && return 1
   if [[ $1 == build ]]; then
     printf "%s\n" "$*" >> "$T/actions"
     while [[ $# -gt 0 ]]; do
       if [[ $1 == --iidfile ]]; then printf "sha256:%064d" 3 > "$2"; break; fi
       shift
     done
     return 0
   fi
   return 1
 }
 SKIP_CHROMIUM=1
 mkdir -p "$W/img"
 build_images
' 2>/dev/null || true
if ! grep -q '^build ' "$t/actions" || grep -Eq '(^| )(-t|--tag)( |$)' "$t/actions"; then
 echo 'image build did not run untagged' >&2; cat "$t/actions" >&2; exit 1
fi
echo 'failed creation, name replacement and untagged build regressions passed'

if [[ ${E1_OWNERSHIP_CASE:-all} == all ]]; then
OC_E1_NOMAIN=1 bash -c '
 source "$PROBE"
 set -e
 trace=$T/helper-actions
 receipt=$T/helper-receipt
 fixture_id=$(printf "%064d" 4)
 exists_status=0
 observed_owner=$OWNER
 pm() {
   printf "%s\n" "$*" >> "$trace"
   if [[ $2 == exists ]]; then return "$exists_status"; fi
   if [[ $2 == inspect ]]; then printf "%s\n" "$observed_owner"; fi
 }
 : > "$trace"
 remove_id container "$receipt" || exit 86
 printf "%s" malformed > "$receipt"
 if remove_id container "$receipt"; then exit 81; fi
 [[ ! -s "$trace" ]]
 printf "%s" "$fixture_id" > "$receipt"
 exists_status=1
 remove_id container "$receipt" || exit 87
 [[ $(<"$trace") == "container exists $fixture_id" ]]
 : > "$trace"
 exists_status=2
 if remove_id container "$receipt"; then exit 82; fi
 [[ $(<"$trace") == "container exists $fixture_id" ]]
 : > "$trace"
 exists_status=0
 observed_owner=another-owner
 if remove_id container "$receipt"; then exit 83; fi
 mapfile -t calls < "$trace"
 [[ ${#calls[@]} == 2 && ${calls[0]} == "container exists $fixture_id" &&
    ${calls[1]} == "container inspect --format "*"$fixture_id" ]]
 : > "$trace"
 read_id() { echo "read_id" >> "$trace"; printf "%s" "$fixture_id"; }
 if remove_id unsupported "$receipt"; then exit 84; fi
 if [[ -s "$trace" ]]; then echo "unsupported removal reached a receipt or Podman" >&2; exit 88; fi
 if owned unsupported "$fixture_id"; then exit 85; fi
 [[ ! -s "$trace" ]]
' 2>"$t/helper-errors" || { cat "$t/helper-errors" >&2; exit 1; }
echo 'receipt and ownership failures stop cleanup before removal'
fi
