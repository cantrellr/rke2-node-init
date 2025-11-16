#!/usr/bin/env bash
set -euo pipefail

# scripts/certs-auto.sh
# Automate root CA and subordinate CA creation, install into OS trust,
# stage certs under STAGE_DIR, and generate a bootstrap token that embeds
# the subordinate CA sha256 fingerprint. Designed to be invoked from Make
# as a normal user; script will use sudo for privileged operations.

OUTDIR="${OUTDIR:-outputs/certs}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
ROOT_OUT="${OUTDIR}/root-${TIMESTAMP}"
SUB_OUT="${OUTDIR}/subca-${TIMESTAMP}"
STAGE_DIR="${STAGE_DIR:-/opt/rke2/stage/certs}"
TOKEN_DIR="${TOKEN_OUTPUT_DIR:-outputs/tokens}"
GENERATE_TOKEN="${GENERATE_TOKEN:-true}"

ROOT_CN="${ROOT_CN:-Offline Root CA}"
ROOT_PASS="${ROOT_PASS:-}"
SUB_CN="${SUB_CN:-RKE2 Subordinate CA}"
SUB_ORG="${SUB_ORG:-RKE2}"
SUB_ENCRYPT="${SUB_ENCRYPT:-false}"
SUB_PASSFILE="${SUB_PASSFILE:-}"
SUB_PATHLEN="${SUB_PATHLEN:-1}"

echo "certs-auto: OUTDIR=${OUTDIR} STAGE_DIR=${STAGE_DIR}"

# Helper: ensure directory exists and is owned by current user; if not, use sudo
ensure_dir() {
  local dir="$1"
  if mkdir -p "${dir}" 2>/dev/null; then
    return 0
  fi
  echo "Directory ${dir} requires sudo to create; creating with sudo and chowning to user"
  sudo mkdir -p "${dir}"
  sudo chown -R "$(id -u):$(id -g)" "${dir}"
}

ensure_dir "${ROOT_OUT}"
ensure_dir "${SUB_OUT}"

# Ensure token dir only when token generation is enabled
if [[ "${GENERATE_TOKEN}" == "true" || "${GENERATE_TOKEN}" == "1" ]]; then
  ensure_dir "${TOKEN_DIR}"
fi

# Generate or use provided root passphrase
if [[ -z "${ROOT_PASS}" ]]; then
  ROOT_PASS="$(openssl rand -base64 24)"
  echo "Generated ROOT_PASS (kept only in memory)"
fi

echo "Generating Root CA in ${ROOT_OUT}..."
./certs/scripts/generate-root-ca.sh --out-dir "${ROOT_OUT}" --cn "${ROOT_CN}" --passphrase "${ROOT_PASS}"
ROOT_KEY_PATH="${ROOT_OUT}/root-ca-key.pem"
ROOT_CERT_PATH="${ROOT_OUT}/root-ca.crt"

# Normalize to absolute paths so child scripts that change cwd can find them
if command -v readlink >/dev/null 2>&1; then
  ROOT_KEY_PATH="$(readlink -f "${ROOT_KEY_PATH}")"
  ROOT_CERT_PATH="$(readlink -f "${ROOT_CERT_PATH}")"
else
  ROOT_KEY_PATH="$(cd "$(dirname "${ROOT_KEY_PATH}")" && pwd)/$(basename "${ROOT_KEY_PATH}")"
  ROOT_CERT_PATH="$(cd "$(dirname "${ROOT_CERT_PATH}")" && pwd)/$(basename "${ROOT_CERT_PATH}")"
fi

if [[ ! -f "${ROOT_KEY_PATH}" ]]; then
  echo "ERROR: expected root key at ${ROOT_KEY_PATH} but it was not found" >&2
  exit 1
fi
if [[ ! -f "${ROOT_CERT_PATH}" ]]; then
  echo "ERROR: expected root cert at ${ROOT_CERT_PATH} but it was not found" >&2
  exit 1
fi

echo "Generating subordinate CA in ${SUB_OUT}..."
# Ensure SUB_OUT is an absolute path too
if command -v readlink >/dev/null 2>&1; then
  SUB_OUT="$(readlink -m "${SUB_OUT}")"
else
  SUB_OUT="$(cd "$(dirname "${SUB_OUT}")" && pwd)/$(basename "${SUB_OUT}")"
fi

SUB_FLAGS=(--out-dir "${SUB_OUT}" --cn "${SUB_CN}" --org "${SUB_ORG}" --root-key "${ROOT_KEY_PATH}" --root-cert "${ROOT_CERT_PATH}" --root-passphrase "${ROOT_PASS}" --pathlen "${SUB_PATHLEN}")
if [[ "${SUB_ENCRYPT}" == "true" ]]; then
  SUB_FLAGS+=(--encrypt-sub-key)
fi
if [[ -n "${SUB_PASSFILE}" ]]; then
  SUB_FLAGS+=(--sub-passfile "${SUB_PASSFILE}")
fi
# shellcheck disable=SC2068
./certs/scripts/generate-subordinate-ca.sh "${SUB_FLAGS[@]}"

SUB_KEY_PATH="${SUB_OUT}/subordinate-ca-key.pem"
SUB_CERT_PATH="${SUB_OUT}/subordinate-ca.crt"

# Install into OS trust
if command -v update-ca-certificates >/dev/null 2>&1; then
  echo "Installing CA certs to /usr/local/share/ca-certificates and running update-ca-certificates"
  sudo install -m 644 "${ROOT_CERT_PATH}" /usr/local/share/ca-certificates/root-ca.crt
  sudo install -m 644 "${SUB_CERT_PATH}" /usr/local/share/ca-certificates/subordinate-ca.crt
  sudo update-ca-certificates
elif command -v update-ca-trust >/dev/null 2>&1 || [[ -d /etc/pki/ca-trust/source/anchors ]]; then
  echo "Installing CA certs to /etc/pki/ca-trust/source/anchors and running update-ca-trust"
  sudo install -m 644 "${ROOT_CERT_PATH}" /etc/pki/ca-trust/source/anchors/root-ca.crt || true
  sudo install -m 644 "${SUB_CERT_PATH}" /etc/pki/ca-trust/source/anchors/subordinate-ca.crt || true
  sudo update-ca-trust extract || true
else
  echo "WARNING: no known CA update command found; skipping OS trust installation"
fi

# Stage certs
echo "Staging certs into ${STAGE_DIR}"
sudo mkdir -p "${STAGE_DIR}"
sudo install -m 644 "${ROOT_CERT_PATH}" "${STAGE_DIR}/root-ca.crt"
sudo install -m 644 "${SUB_CERT_PATH}" "${STAGE_DIR}/subordinate-ca.crt"
sudo install -m 600 "${SUB_KEY_PATH}" "${STAGE_DIR}/subordinate-ca-key.pem" || true

## Generate bootstrap token in the canonical RKE2 format used by rke2nodeinit:
##   - passphrase: 20 bytes, hex
##   - ca_hash: sha256 of CA in DER form
##   - token format: K10<ca_hash>::server:<passphrase>
PASSHEX="$(openssl rand -hex 20 2>/dev/null || true)"
PASSHEX="${PASSHEX//$'\n'/}"
if [[ -z "${PASSHEX}" ]]; then
  PASSHEX="$(dd if=/dev/urandom bs=1 count=40 2>/dev/null | od -An -v -t x1 | tr -d ' \n' | cut -c1-40 || true)"
  PASSHEX="${PASSHEX//$'\n'/}"
fi

# Compute ca_hash from subordinate cert (DER -> sha256)
if [[ "${GENERATE_TOKEN}" == "true" || "${GENERATE_TOKEN}" == "1" ]]; then
  CA_HASH="$(openssl x509 -outform der -in "${SUB_CERT_PATH}" 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}' || true)"
  if [[ -z "${CA_HASH}" ]]; then
    echo "WARNING: failed to compute CA_HASH from ${SUB_CERT_PATH}; falling back to simple token" >&2
    FULL_TOKEN="${PASSHEX}"
  else
    FULL_TOKEN="K10${CA_HASH}::server:${PASSHEX}"
  fi

  TOKEN_FILE="${TOKEN_DIR}/bootstrap-${TIMESTAMP}.token"
  echo "${FULL_TOKEN}" > "${TOKEN_FILE}"
  chmod 600 "${TOKEN_FILE}"
  echo "Staging token to ${STAGE_DIR}/bootstrap.token"
  sudo install -m 600 "${TOKEN_FILE}" "${STAGE_DIR}/bootstrap.token" || true
  echo "certs-auto completed. Root CA: ${ROOT_CERT_PATH}, Sub CA: ${SUB_CERT_PATH}, Token: ${TOKEN_FILE}"
else
  TOKEN_FILE=""
  echo "GENERATE_TOKEN is disabled; skipping token creation and token staging"
  echo "certs-auto completed. Root CA: ${ROOT_CERT_PATH}, Sub CA: ${SUB_CERT_PATH}, Token: <skipped>"
fi

exit 0
