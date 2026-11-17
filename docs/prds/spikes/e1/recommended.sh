#!/usr/bin/env bash
# The recommended CA and one leaf, exactly as quoted in prd_e1.md (probe.sh runs this file).
# usage: recommended.sh OUTDIR TEMPLATE_DIR NAME NC SAN
#   NC  = nameConstraints value, e.g. "permitted;DNS:.oc-sandbox.internal,permitted;DNS:oc-sandbox.internal,..."
#   SAN = subjectAltName value, e.g. "DNS:feat-a.oc-sandbox.internal"
set -euo pipefail
out=$1 tmpl=$(cd "$2" && pwd -P) name=$3
export OC_NC=$4 OC_SAN=$5
mkdir -p "$out" && cd "$out"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key && chmod 600 ca.key
openssl req -x509 -new -key ca.key -config "$tmpl/ca.cnf" -extensions v3_ca -days 3650 -sha256 -out ca.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem && chmod 600 key.pem
openssl req -new -key key.pem -subj "/CN=$name" -out req.pem
openssl x509 -req -in req.pem -CA ca.pem -CAkey ca.key -CAserial serial -CAcreateserial \
  -extfile "$tmpl/leaf.cnf" -extensions v3_leaf -days 30 -sha256 -out cert.pem
