#!/usr/bin/env bash
set -euo pipefail

# verify-chain.sh
# Verify a subordinate CA certificate against a root CA and perform additional checks:
# - openssl verify chain
# - Basic Constraints include CA:TRUE and optional pathlen
# - Extended Key Usage includes serverAuth or TLS Web Server Authentication
# - If a private key is provided, check modulus matches the certificate

usage() {
  echo "Usage: $0 --root <root.crt> --sub <sub.crt> [--sub-key <sub.key>]"; exit 2
}

ROOT=""
SUB=""
SUB_KEY=""
SUB_PASSPHRASE=""
SUB_PASSFILE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --root) ROOT="$2"; shift 2;;
    --sub) SUB="$2"; shift 2;;
    --sub-key) SUB_KEY="$2"; shift 2;;
      --sub-passphrase) SUB_PASSPHRASE="$2"; shift 2;;
      --sub-passfile) SUB_PASSFILE="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

if [[ -z "${ROOT}" || -z "${SUB}" ]]; then
  usage
fi

command -v openssl >/dev/null 2>&1 || { echo "openssl missing"; exit 2; }

echo "Verifying chain: sub=${SUB} root=${ROOT}"
if ! openssl verify -CAfile "${ROOT}" "${SUB}" >/dev/null 2>&1; then
  echo "ERROR: openssl verify failed"; openssl verify -CAfile "${ROOT}" "${SUB}" || true; exit 1
fi

echo "Checking certificate fields..."
CERT_TEXT=$(openssl x509 -in "${SUB}" -noout -text)

# Basic Constraints: CA:TRUE
echo "Checking Basic Constraints for CA:TRUE"
echo "$CERT_TEXT" | grep -A2 "Basic Constraints" | grep -q "CA:TRUE" || { echo "ERROR: Certificate is not a CA (Basic Constraints missing CA:TRUE)"; exit 1; }

# Pathlen (optional) - report if present
PATHLEN_LINE=$(echo "$CERT_TEXT" | grep -A2 "Basic Constraints" | grep -Eo 'pathlen:[0-9]+' || true)
if [[ -n "$PATHLEN_LINE" ]]; then
  echo "Found $PATHLEN_LINE"
fi

# Extended Key Usage should include serverAuth (TLS Web Server Authentication)
echo "Checking Extended Key Usage for serverAuth / TLS Web Server Authentication"
echo "$CERT_TEXT" | grep -A2 "Extended Key Usage" | grep -Eqi 'Server Authentication|serverAuth|TLS Web Server Authentication' || { echo "ERROR: Extended Key Usage does not include serverAuth"; exit 1; }

if [[ -n "${SUB_KEY}" ]]; then
  echo "Checking modulus between cert and key"
  CERT_MOD=$(openssl x509 -noout -modulus -in "${SUB}" | openssl md5)
  if [[ -n "${SUB_PASSPHRASE}" ]]; then
    KEY_MOD=$(openssl rsa -noout -modulus -in "${SUB_KEY}" -passin pass:"${SUB_PASSPHRASE}" | openssl md5)
  elif [[ -n "${SUB_PASSFILE}" ]]; then
    if [[ ! -f "${SUB_PASSFILE}" ]]; then echo "Sub passfile not found: ${SUB_PASSFILE}"; exit 1; fi
    SUB_PW="$(<"${SUB_PASSFILE}")"
    KEY_MOD=$(openssl rsa -noout -modulus -in "${SUB_KEY}" -passin pass:"${SUB_PW}" | openssl md5)
    unset SUB_PW
  else
    KEY_MOD=$(openssl rsa -noout -modulus -in "${SUB_KEY}" | openssl md5) || { echo "ERROR: unable to read private key modulus (is the key encrypted?)."; exit 1; }
  fi
  if [[ "${CERT_MOD}" != "${KEY_MOD}" ]]; then
    echo "ERROR: Certificate modulus does not match private key"; exit 1
  fi
fi

echo "verify-chain: OK"
exit 0
