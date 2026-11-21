#!/usr/bin/env bash
# NSS classic path validation, not Firefox's mozilla::pkix.
set -euo pipefail
ver=nss-tools-$(rpm -q --qf '%{VERSION}' nss-tools)
# Compare DER hashes rather than textual formatting or an unchecked nickname.
fingerprint_file() {
  local certificate=$1
  openssl x509 -in "$certificate" -outform DER | sha256sum | cut -d ' ' -f1
}
fingerprint_nss() {
  local database=$1 nickname=$2
  certutil -d "sql:$database" -L -n "$nickname" -a | openssl x509 -outform DER | sha256sum | cut -d ' ' -f1
}
import_cert() {
  local db=$1 nick=$2 trust=$3 file=$4 expected actual
  certutil -d "sql:$db" -A -t "$trust" -n "$nick" -i "$file" || { echo "import $nick failed: $file" >&2; exit 1; }
  expected=$(fingerprint_file "$file") || exit 1
  actual=$(fingerprint_nss "$db" "$nick") || exit 1
  [[ "$expected" = "$actual" ]] || { echo "import $nick fingerprint mismatch: $file" >&2; exit 1; }
}
for V in $(cut -f1 /w/variants.tsv); do
  D=/tmp/nss-$V; mkdir -p "$D"
  certutil -d "sql:$D" -N --empty-password || { echo "certutil -N failed" >&2; exit 1; }
  import_cert "$D" ca 'C,,' "/w/ca/$V/ca.pem"
  while IFS=$'\t' read -r v L port check kind; do
    [[ "$v" = "$V" ]] || continue
    leaf="/w/leaf/$L/$V.pem"; chain="/w/leaf/$L/$V.chain.pem"
    mode=$(awk -F '\t' -v l="$L" '$1 == l {print $5}' /w/leaves.tsv)
    import_cert "$D" leaf ',,' "$leaf"
    case "$mode" in
      plain) [[ ! -e "$chain" ]] || { echo "unexpected chain $V/$L" >&2; exit 1; };;
      twin|unc) [[ -s "$chain" ]] || { echo "missing chain $V/$L" >&2; exit 1; }; import_cert "$D" chain ',,' "$chain";;
      *) echo "unknown leaf mode $V/$L" >&2; exit 1;;
    esac
    rc=0; out=$(certutil -d "sql:$D" -V -n leaf -u V 2>&1) || rc=$?
    if [[ "$rc" = 0 ]]; then r=OK d=; else r=FAIL; d=$(echo "$out" | head -1 | tr -d '\r'); fi
    certutil -d "sql:$D" -D -n leaf
    if [[ "$mode" != plain ]]; then certutil -d "sql:$D" -D -n chain; fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$ver" "$V" "$L" "$r" "$d"
  done < /w/combos.tsv
done
