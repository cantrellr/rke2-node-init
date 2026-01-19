#!/usr/bin/env bash
set -euo pipefail

# generate-root-ca.sh
# Creates an offline Root CA private key (encrypted) and self-signed certificate.
# Usage: generate-root-ca.sh [--out-dir path] [--cn "Common Name"] [--days N]

OUT_DIR="${OUT_DIR:-./outputs/root-ca}"
CN="${CN:-Offline Root CA}"
DAYS="${DAYS:-36500}" # default 100 years for root (shorter is OK)
KEY_SIZE="${KEY_SIZE:-4096}"

PASSFLAG=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --out-dir) OUT_DIR="$2"; shift 2;;
    --cn) CN="$2"; shift 2;;
    --days) DAYS="$2"; shift 2;;
    --key-size) KEY_SIZE="$2"; shift 2;;
    --passphrase) PASSFLAG="$2"; shift 2;;
    -h|--help) echo "Usage: $0 [--out-dir path] [--cn 'Common Name'] [--days N] [--passphrase secret]"; exit 0;;
    *) echo "Unknown arg: $1"; exit 1;;
  esac
done

# If passphrase provided via flag, set environment variable for non-interactive use
if [[ -n "${PASSFLAG:-}" ]]; then
  ROOT_PASSPHRASE="${PASSFLAG}"
fi

mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

echo "Generating Offline Root CA in: ${OUT_DIR}"

# Prompt for passphrase if not provided via env or flag
if [[ -z "${ROOT_PASSPHRASE:-}" ]]; then
  read -r -p "Enter a secure passphrase to encrypt the root private key (will not echo): " -s ROOT_PASSPHRASE
  echo
  read -r -p "Confirm passphrase: " -s ROOT_PASSPHRASE2
  echo
  if [[ "${ROOT_PASSPHRASE}" != "${ROOT_PASSPHRASE2}" ]]; then
    echo "Passphrases do not match. Aborting."; exit 1
  fi
fi

ROOT_KEY="root-ca-key.pem"
ROOT_CERT="root-ca.crt"

if [[ -f "${ROOT_KEY}" ]] || [[ -f "${ROOT_CERT}" ]]; then
  read -r -p "Existing root CA files found. Overwrite? (yes/NO): " -r
  if [[ ! "${REPLY}" =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Aborted."; exit 0
  fi
fi

echo "Generating RSA ${KEY_SIZE} private key (encrypted)..."
openssl genrsa -aes256 -passout pass:"${ROOT_PASSPHRASE}" -out "${ROOT_KEY}" "${KEY_SIZE}"
chmod 600 "${ROOT_KEY}"

echo "Generating self-signed root certificate (CN=${CN}, days=${DAYS})..."
openssl req -x509 -new -nodes -key "${ROOT_KEY}" -sha256 -days "${DAYS}" \
  -out "${ROOT_CERT}" -subj "/CN=${CN}" -passin pass:"${ROOT_PASSPHRASE}"
chmod 644 "${ROOT_CERT}"

echo "Root CA generation complete. Files:"; ls -lh "${ROOT_KEY}" "${ROOT_CERT}" || true

echo "IMPORTANT: Move ${ROOT_KEY} to an offline, encrypted storage (USB/HSM) and DO NOT keep it on build systems."

exit 0
