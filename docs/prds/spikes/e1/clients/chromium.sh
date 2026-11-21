#!/usr/bin/env bash
# Headless Chromium, one scratch NSS db per CA variant ($HOME/.pki/nssdb is where Chromium on Linux
# looks). Success: the DOM contains the s_server page; failure: "Page load failed: net::ERR_*".
ver=$(chromium-browser --version | awk '{print "chromium-"$2}')
for V in $(cut -f1 /w/variants.tsv); do
  export HOME=/tmp/h-$V
  mkdir -p "$HOME/.pki/nssdb"
  certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password || { echo "certutil -N failed" >&2; exit 1; }
  certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n oc-spike-ca -i "/w/ca/$V/ca.pem" || { echo "certutil -A failed" >&2; exit 1; }
  while IFS=$'\t' read -r v L port check kind; do
    [[ "$v" = "$V" ]] || continue
    hp=$check; [[ $check == *:* ]] && hp="[$check]"
    out=$(timeout 90 chromium-browser --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
          --user-data-dir="/tmp/ud-$V" --enable-logging=stderr --dump-dom "https://$hp:$port/" 2>&1)
    if echo "$out" | grep -q 's_server -accept'; then r=OK d=
    else r=FAIL; d=$(echo "$out" | grep -o -m1 'net::ERR_[A-Z_]*'); [[ -n "$d" ]] || d="no s_server page, see log"; fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$ver" "$V" "$L" "$r" "$d"
  done < /w/combos.tsv
done
