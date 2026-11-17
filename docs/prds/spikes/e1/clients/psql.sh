#!/usr/bin/env bash
# Runs as postgres inside postgres:17; reject a row unless its exact certificate is served.
set -euo pipefail
PGD=/tmp/pgdata; S=/tmp/pgssl
echo "hostssl all all all trust" >> "$PGD/pg_hba.conf"
ver=$(psql --version | awk '{print $3}')
while IFS=$'\t' read -r V L port check kind; do
  leaf="/w/leaf/$L/$V.pem"; chain="/w/leaf/$L/$V.chain.pem"
  mode=$(awk -F '\t' -v l="$L" '$1 == l {print $5}' /w/leaves.tsv)
  case "$mode" in
    plain) [ ! -e "$chain" ] || { echo "unexpected chain $V/$L" >&2; exit 1; }; cp "$leaf" "$S/server.crt";;
    twin|unc) [ -s "$chain" ] || { echo "missing chain $V/$L" >&2; exit 1; }; cat "$leaf" "$chain" > "$S/server.crt";;
    *) echo "unknown leaf mode $V/$L" >&2; exit 1;;
  esac
  cp "/w/leaf/$L/key.pem" "$S/server.key"; chmod 600 "$S/server.key"
  pg_ctl -D "$PGD" -m fast -w -s -l /tmp/pg.log \
    -o "-c listen_addresses=* -c port=5432 -c unix_socket_directories=/tmp -c ssl=on -c ssl_cert_file=$S/server.crt -c ssl_key_file=$S/server.key" restart >/dev/null 2>&1 || {
      echo "postgres restart failed for $V/$L" >&2; exit 1;
    }
  expected=$(openssl x509 -in "$leaf" -noout -fingerprint -sha256) || exit 1
  served=$(timeout 10 openssl s_client -starttls postgres -connect 127.0.0.1:5432 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256) || {
    echo "cannot read served certificate for $V/$L" >&2; exit 1;
  }
  [ "$served" = "$expected" ] || { echo "stale postgres certificate for $V/$L" >&2; exit 1; }
  rc=0
  out=$(PGCONNECT_TIMEOUT=10 psql "host=$check port=5432 user=postgres dbname=postgres sslmode=verify-full sslrootcert=/w/ca/$V/ca.pem" -Atc 'select ssl from pg_stat_ssl where pid=pg_backend_pid()' 2>&1) || rc=$?
  if [ "$rc" = 0 ] && [ "$out" = t ]; then r=OK d=; else r=FAIL; d=$(echo "$out" | head -1 | sed 's/^psql: error: //'); fi
  printf 'psql-%s\t%s\t%s\t%s\t%s\n' "$ver" "$V" "$L" "$r" "$d"
done < /w/combos.tsv
pg_ctl -D "$PGD" -m fast -w -s stop >/dev/null 2>&1
