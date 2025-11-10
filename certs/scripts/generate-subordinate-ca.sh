#!/usr/bin/env bash
set -euo pipefail

# generate-subordinate-ca.sh
# Creates a subordinate CA key and CSR, signs the CSR with a Root CA to produce a subordinate certificate.
# Supports interactive prompts or YAML input via --input <file>

OUT_DIR="${OUT_DIR:-./outputs/sub-ca}"
INPUT_FILE=""
CN=""
ORG=""
KEY_SIZE="4096"
DAYS="3650"
PATHLEN="0"
ROOT_KEY=""
ROOT_CERT=""
ENCRYPT_SUB_KEY="false"
SUB_PASSPHRASE=""
SUB_PASSFILE=""

usage() { echo "Usage: $0 [--out-dir path] [--input file.yaml] [--cn 'Common Name'] [--org 'Org'] [--root-key path] [--root-cert path] [--encrypt-sub-key] [--sub-passphrase 'pass'] [--sub-passfile path]"; }

PASSFLAG=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --out-dir) OUT_DIR="$2"; shift 2;;
    --input) INPUT_FILE="$2"; shift 2;;
    --cn) CN="$2"; shift 2;;
    --org) ORG="$2"; shift 2;;
    --key-size) KEY_SIZE="$2"; shift 2;;
  --days) DAYS="$2"; shift 2;;
  --pathlen) PATHLEN="$2"; shift 2;;
  --root-key) ROOT_KEY="$2"; shift 2;;
  --root-cert) ROOT_CERT="$2"; shift 2;;
  --root-passphrase) PASSFLAG="$2"; shift 2;;
  --encrypt-sub-key) ENCRYPT_SUB_KEY="true"; shift 1;;
  --sub-passphrase) SUB_PASSPHRASE="$2"; shift 2;;
  --sub-passfile) SUB_PASSFILE="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 1;;
  esac
done

mkdir -p "${OUT_DIR}"
cd "${OUT_DIR}"

# If input YAML provided, parse simple keys using yq if available, otherwise grep
if [[ -n "${INPUT_FILE}" ]]; then
  if [[ ! -f "${INPUT_FILE}" ]]; then echo "Input file not found: ${INPUT_FILE}"; exit 1; fi
  if command -v yq >/dev/null 2>&1; then
    CN_VAL=$(yq e '.spec.subject.commonName // .spec.commonName // .spec.cn' "${INPUT_FILE}" 2>/dev/null || echo "")
    ORG_VAL=$(yq e '.spec.subject.organization // .spec.organization // .spec.org' "${INPUT_FILE}" 2>/dev/null || echo "")
    KEY_SIZE_VAL=$(yq e '.spec.keySize // .spec.keySize' "${INPUT_FILE}" 2>/dev/null || echo "")
    DAYS_VAL=$(yq e '.spec.validityDays // .spec.validityDays' "${INPUT_FILE}" 2>/dev/null || echo "")
    CN="${CN:-${CN_VAL}}"
    ORG="${ORG:-${ORG_VAL}}"
    KEY_SIZE="${KEY_SIZE:-${KEY_SIZE_VAL:-${KEY_SIZE}}}"
    DAYS="${DAYS:-${DAYS_VAL:-${DAYS}}}"
  else
    # fallback simple grep for common patterns
    CN_VAL=$(grep -E "commonName:|CN:" -m1 "${INPUT_FILE}" || true)
    ORG_VAL=$(grep -E "organization:|O:" -m1 "${INPUT_FILE}" || true)
    CN="${CN:-$(echo "${CN_VAL}" | sed -E 's/.*:[[:space:]]*//g') }"
    ORG="${ORG:-$(echo "${ORG_VAL}" | sed -E 's/.*:[[:space:]]*//g') }"
  fi
fi

# Interactive prompts for missing values
if [[ -z "${CN}" ]]; then read -r -p "Subordinate CA Common Name (e.g. 'RKE2 Cluster CA'): " CN; fi
if [[ -z "${ORG}" ]]; then read -r -p "Organization: " ORG; fi
if [[ -z "${ROOT_KEY}" ]]; then read -r -p "Path to Root CA private key (e.g. /path/to/root-ca-key.pem): " ROOT_KEY; fi
if [[ -z "${ROOT_CERT}" ]]; then read -r -p "Path to Root CA certificate (e.g. /path/to/root-ca.crt): " ROOT_CERT; fi

# Ensure files exist
if [[ ! -f "${ROOT_KEY}" ]]; then echo "Root key not found: ${ROOT_KEY}"; exit 1; fi
if [[ ! -f "${ROOT_CERT}" ]]; then echo "Root cert not found: ${ROOT_CERT}"; exit 1; fi

SUB_KEY="subordinate-ca-key.pem"
SUB_CSR="subordinate-ca.csr"
SUB_CERT="subordinate-ca.crt"

echo "Generating subordinate private key (${KEY_SIZE} bits)..."
openssl genrsa -out "${SUB_KEY}" "${KEY_SIZE}"
chmod 600 "${SUB_KEY}"
echo "Generating CSR for subordinate CA (CN=${CN}, O=${ORG})..."
openssl req -new -key "${SUB_KEY}" -out "${SUB_CSR}" -subj "/CN=${CN}/O=${ORG}"

# Generate CSR while key is unencrypted, then optionally encrypt the key for storage
echo "Generating CSR for subordinate CA (CN=${CN}, O=${ORG})..."
openssl req -new -key "${SUB_KEY}" -out "${SUB_CSR}" -subj "/CN=${CN}/O=${ORG}"

# Optionally encrypt the subordinate private key using AES-256 if requested
if [[ "${ENCRYPT_SUB_KEY}" == "true" ]]; then
  echo "Encrypting subordinate private key..."
  # Determine passphrase source: explicit, file, or prompt
  if [[ -n "${SUB_PASSPHRASE}" ]]; then
    ENC_PASS="${SUB_PASSPHRASE}"
  elif [[ -n "${SUB_PASSFILE}" ]]; then
    if [[ ! -f "${SUB_PASSFILE}" ]]; then echo "Sub passfile not found: ${SUB_PASSFILE}"; exit 1; fi
    ENC_PASS="$(<"${SUB_PASSFILE}")"
  else
    read -r -s -p "Enter passphrase to encrypt subordinate private key: " ENC_PASS
    echo
  fi

  # Write a temporary encrypted key and replace the unencrypted key
  openssl rsa -in "${SUB_KEY}" -aes256 -passout pass:"${ENC_PASS}" -out "${SUB_KEY}.enc"
  mv "${SUB_KEY}.enc" "${SUB_KEY}"
  shred -u -z "${SUB_KEY}.enc" 2>/dev/null || true
  chmod 600 "${SUB_KEY}"
  # Clear ENC_PASS from memory
  unset ENC_PASS
fi

# Create a config for CA extensions
cat > ca-sub-ext.cnf <<EOF
[ v3_ca ]
basicConstraints = critical,CA:TRUE,pathlen:${PATHLEN}
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth,clientAuth
EOF

echo "Signing subordinate CSR with Root CA..."
# If root key is encrypted, prompt for passphrase
if [[ -n "${PASSFLAG:-}" ]]; then
  ROOT_PASSPHRASE="${PASSFLAG}"
fi

if [[ -z "${ROOT_PASSPHRASE:-}" ]]; then
  # If the key is unencrypted, this will succeed; otherwise prompt interactively
  if openssl rsa -in "${ROOT_KEY}" -check -noout >/dev/null 2>&1; then
    openssl x509 -req -in "${SUB_CSR}" -CA "${ROOT_CERT}" -CAkey "${ROOT_KEY}" -CAcreateserial -out "${SUB_CERT}" -days "${DAYS}" -sha256 -extfile ca-sub-ext.cnf -extensions v3_ca
  else
    read -r -s -p "Enter passphrase for Root CA private key: " ROOT_PASSPHRASE
    echo
    openssl x509 -req -in "${SUB_CSR}" -CA "${ROOT_CERT}" -CAkey "${ROOT_KEY}" -CAcreateserial -out "${SUB_CERT}" -days "${DAYS}" -sha256 -extfile ca-sub-ext.cnf -extensions v3_ca -passin pass:"${ROOT_PASSPHRASE}"
  fi
else
  openssl x509 -req -in "${SUB_CSR}" -CA "${ROOT_CERT}" -CAkey "${ROOT_KEY}" -CAcreateserial -out "${SUB_CERT}" -days "${DAYS}" -sha256 -extfile ca-sub-ext.cnf -extensions v3_ca -passin pass:"${ROOT_PASSPHRASE}"
fi

chmod 644 "${SUB_CERT}"

echo "Subordinate CA generated:"; ls -lh "${SUB_KEY}" "${SUB_CSR}" "${SUB_CERT}" || true

echo "You may copy ${SUB_CERT} to RKE2 config as the cluster CA certificate. Keep ${SUB_KEY} secure."

exit 0
