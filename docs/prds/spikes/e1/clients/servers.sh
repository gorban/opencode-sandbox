#!/usr/bin/env bash
# One openssl s_server per (CA variant, leaf) combination, all in the pod's private netns.
ip addr add 8.8.8.8/32 dev lo || { echo "ip addr failed"; exit 1; }
ip -6 addr add 2001:db8::1/128 dev lo || { echo "ip -6 addr failed"; exit 1; }
while IFS=$'\t' read -r V L port check kind; do
  file="/w/leaf/$L/$V.chain.pem"
  mode=$(awk -F '\t' -v l="$L" '$1 == l {print $5}' /w/leaves.tsv)
  chain=()
  case "$mode" in
    plain) [ ! -e "$file" ] || { echo "unexpected chain $V/$L" >&2; exit 1; };;
    twin|unc) [ -s "$file" ] || { echo "missing chain $V/$L" >&2; exit 1; }; chain=(-cert_chain "$file");;
    *) echo "unknown leaf mode $V/$L" >&2; exit 1;;
  esac
  openssl s_server -accept "$port" -cert "/w/leaf/$L/$V.pem" -key "/w/leaf/$L/key.pem" "${chain[@]}" -www -quiet >/dev/null 2>&1 &
done < /w/combos.tsv
trap 'kill $(jobs -p) 2>/dev/null; exit 0' TERM INT
sleep 3
n=$(ss -ltnH | awk '{n=split($4,a,":"); print a[n]}' | grep -E '^2[0-9]{4}$' | sort -u | wc -l)
echo "ready $n"
wait
