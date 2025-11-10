#!/usr/bin/env bash
set -euo pipefail

# Test subordinate key encryption via generate-subordinate-ca.sh flags
# This test is now self-contained: it generates an ephemeral root CA, then
# invokes the subordinate generator with --encrypt-sub-key and verifies the
# subordinate key is encrypted and has correct permissions. Finally verifies chain.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${script_dir}/../.." && pwd)"

TMPDIR=$(mktemp -d)
echo "Using TMPDIR=${TMPDIR}"
pushd "${TMPDIR}" >/dev/null

mkdir -p outputs input root
# Prepare a minimal input YAML for subordinate parser
cat > input/minimal.yaml <<EOF
spec:
  commonName: test-sub
  organization: TestOrg
  keySize: 2048
  validityDays: 365
EOF

# Create a passfile for subordinate key encryption
echo "sub-pass-123" > sub-passfile
chmod 600 sub-passfile

echo "1) Generate ephemeral root CA"
ROOT_PASS=ephemeral-root-pass
${REPO_ROOT}/certs/scripts/generate-root-ca.sh --out-dir root --passphrase "${ROOT_PASS}"


INPUT_PATH="$(pwd)/input/minimal.yaml"
ROOT_KEY_PATH="$(pwd)/root/root-ca-key.pem"
ROOT_CERT_PATH="$(pwd)/root/root-ca.crt"
SUB_PASSFILE_PATH="$(pwd)/sub-passfile"
echo "2) Run generate-subordinate-ca.sh with --encrypt-sub-key and --sub-passfile"
${REPO_ROOT}/certs/scripts/generate-subordinate-ca.sh --input "${INPUT_PATH}" --out-dir outputs --encrypt-sub-key --sub-passfile "${SUB_PASSFILE_PATH}" --root-key "${ROOT_KEY_PATH}" --root-cert "${ROOT_CERT_PATH}" --root-passphrase "${ROOT_PASS}"

SUB_KEY=outputs/subordinate-ca-key.pem
SUB_CERT=outputs/subordinate-ca.crt

if [[ ! -f "${SUB_KEY}" ]]; then echo "ERROR: subordinate key missing"; exit 1; fi

echo "Checking subordinate key encryption"
if openssl rsa -in "${SUB_KEY}" -check -noout >/dev/null 2>&1; then
  echo "ERROR: subordinate key appears unencrypted"; exit 1
else
  echo "Subordinate key appears encrypted (expected)"
fi

perms=$(stat -c %a "${SUB_KEY}")
if [[ "$perms" != "600" ]]; then echo "ERROR: wrong perms $perms"; exit 1; fi

echo "Running verify-chain.sh to verify the subordinate certificate"
${REPO_ROOT}/certs/scripts/verify-chain.sh --root root/root-ca.crt --sub "${SUB_CERT}" --sub-key "${SUB_KEY}" --sub-passfile "${SUB_PASSFILE_PATH}" || { echo "verify-chain failed"; exit 1; }

echo "Subordinate encryption test: PASS (key present, encrypted, perms 600, chain OK)"
popd >/dev/null
rm -rf "${TMPDIR}"
exit 0
