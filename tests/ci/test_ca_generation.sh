#!/usr/bin/env bash
set -euo pipefail

# Test: generate root and subordinate CA (in temp dir), verify chain and fields
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${script_dir}/../.." && pwd)"

TMPDIR=$(mktemp -d)
echo "Using TMPDIR=${TMPDIR}"
pushd "${TMPDIR}" >/dev/null

mkdir -p outputs

echo "1) Generate root CA (non-interactive with passphrase)"
ROOT_PASS=testing-root-pass
mkdir -p root
${REPO_ROOT}/certs/scripts/generate-root-ca.sh --out-dir root --passphrase "${ROOT_PASS}"

echo "2) Generate subordinate key and CSR locally"
mkdir -p sub
cd sub
openssl genrsa -out sub.key 4096
openssl req -new -key sub.key -out sub.csr -subj "/CN=test-sub/O=TestOrg"

echo "3) Sign CSR with root (simulate offline signing by calling openssl with passin)"
cp ../root/root-ca.crt .
cp ../root/root-ca-key.pem .
EXTFILE=$(mktemp)
cat > "$EXTFILE" <<EOF
[ v3_ca ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth,clientAuth
EOF
openssl x509 -req -in sub.csr -CA root-ca.crt -CAkey root-ca-key.pem -CAcreateserial -out sub.crt -days 3650 -sha256 -passin pass:"${ROOT_PASS}" -extfile "$EXTFILE" -extensions v3_ca
rm -f "$EXTFILE"

echo "4) Run verify-chain.sh"
${REPO_ROOT}/certs/scripts/verify-chain.sh --root ../root/root-ca.crt --sub sub.crt --sub-key sub.key

echo "Test CA generation: PASS"
popd >/dev/null
rm -rf "${TMPDIR}"
exit 0
