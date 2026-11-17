#!/usr/bin/env bash
# Offline: openssl verify, chain only and chain + host/IP. Args: the openssl command (prefix).
# Prints: client V L OK|FAIL detail
W=${OC_W:-/w}
first_err() { grep -m1 -E 'error [0-9]+ at|error:' | sed 's/^.*error [0-9]* at [0-9]* depth lookup: //' | tr -d '\r'; }
ver=$("$@" version | awk '{print $2}')
while IFS=$'\t' read -r V L port check kind; do
  ca=$W/ca/$V/ca.pem; leaf=$W/leaf/$L/$V.pem
  chain=$W/leaf/$L/$V.chain.pem
  mode=$(awk -F '\t' -v l="$L" '$1 == l {print $5}' "$W/leaves.tsv")
  untr=()
  case "$mode" in
    plain) [ ! -e "$chain" ] || { echo "unexpected chain $V/$L" >&2; exit 1; };;
    twin|unc) [ -s "$chain" ] || { echo "missing chain $V/$L" >&2; exit 1; }; untr=(-untrusted "$chain");;
    *) echo "unknown leaf mode $V/$L" >&2; exit 1;;
  esac
  out=$("$@" verify -CAfile "$ca" -purpose sslserver "${untr[@]}" "$leaf" 2>&1); rc=$?
  [ $rc = 0 ] && r=OK d= || { r=FAIL; d=$(echo "$out" | first_err); }
  printf 'openssl-verify-%s\t%s\t%s\t%s\t%s\n' "$ver" "$V" "$L" "$r" "$d"
  if [ $kind = ip ]; then hopt=(-verify_ip "$check"); else hopt=(-verify_hostname "$check"); fi
  out=$("$@" verify -CAfile "$ca" -purpose sslserver "${untr[@]}" "${hopt[@]}" "$leaf" 2>&1); rc=$?
  [ $rc = 0 ] && r=OK d= || { r=FAIL; d=$(echo "$out" | first_err); }
  printf 'openssl-verify+host-%s\t%s\t%s\t%s\t%s\n' "$ver" "$V" "$L" "$r" "$d"
done < "$W/combos.tsv"
