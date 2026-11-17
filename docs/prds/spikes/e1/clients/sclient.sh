#!/usr/bin/env bash
# openssl s_client -verify_return_error -verify_hostname/-verify_ip against the s_server fleet.
ver=$(openssl version | awk '{print $2}')
while IFS=$'\t' read -r V L port check kind; do
  hp=$check; [[ $check == *:* ]] && hp="[$check]"
  if [ $kind = ip ]; then extra=(-verify_ip "$check"); else extra=(-verify_hostname "$check" -servername "$check"); fi
  out=$(timeout 10 openssl s_client -connect "$hp:$port" -CAfile "/w/ca/$V/ca.pem" -verify_return_error "${extra[@]}" </dev/null 2>&1); rc=$?
  if [ $rc = 0 ] && echo "$out" | grep -q 'Verification: OK'; then r=OK d=
  else r=FAIL; d=$(echo "$out" | grep -m1 -E 'error [0-9]+ at|Verify return code|verify error|error:' | sed 's/^.*verify error://' | tr -d '\r'); fi
  printf 'openssl-s_client-%s\t%s\t%s\t%s\t%s\n' "$ver" "$V" "$L" "$r" "$d"
done < /w/combos.tsv
