#!/usr/bin/env bash
ver=$(curl --version | head -1 | awk '{print $2}')
while IFS=$'\t' read -r V L port check kind; do
  hp=$check; [[ $check == *:* ]] && hp="[$check]"
  out=$(curl -sS --max-time 10 --cacert "/w/ca/$V/ca.pem" -o /dev/null -w '%{http_code}' "https://$hp:$port/" 2>&1); rc=$?
  if [ $rc = 0 ]; then r=OK d=; else r=FAIL; d=$(echo "$out" | grep -m1 -E 'curl:' | sed 's/^curl: ([0-9]*) //'); fi
  printf 'curl-%s\t%s\t%s\t%s\t%s\n' "$ver" "$V" "$L" "$r" "$d"
done < /w/combos.tsv
