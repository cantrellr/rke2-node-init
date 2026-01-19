#!/usr/bin/env bash
#
# Generate RKE2 CA certificates
#
# Usage:
#   ./generate-ca.sh [--cn "Common Name"] [--org "Organization"] [--days 3650]
#
# This script generates:
#   - rke2ca-cert-key.pem (CA private key)
#   - rke2ca-cert.crt (CA certificate)
#   - rke2registry-ca.crt (copy of CA cert for registry use)

set -euo pipefail

# Default values
CN="${CN:-Example Organization RKE2 CA}"
ORG="${ORG:-Example Organization}"
DAYS="${DAYS:-3650}"
KEY_SIZE="${KEY_SIZE:-4096}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --cn)
      CN="$2"
      shift 2
      ;;
    --org)
      ORG="$2"
      shift 2
      ;;
    --days)
      DAYS="$2"
      shift 2
      ;;
    --key-size)
      KEY_SIZE="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--cn 'Common Name'] [--org 'Organization'] [--days 3650] [--key-size 4096]"
      echo ""
      echo "Environment variables:"
      echo "  CN        - Certificate Common Name (default: Example Organization RKE2 CA)"
      echo "  ORG       - Organization name (default: Example Organization)"
      echo "  DAYS      - Certificate validity in days (default: 3650)"
      echo "  KEY_SIZE  - RSA key size (default: 4096)"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Output directory
CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${CERT_DIR}"

echo "============================================"
echo "RKE2 CA Certificate Generator"
echo "============================================"
echo "Common Name:     ${CN}"
echo "Organization:    ${ORG}"
echo "Validity (days): ${DAYS}"
echo "Key Size:        ${KEY_SIZE}"
echo "Output Dir:      ${CERT_DIR}"
echo "============================================"
echo ""

# Check if files already exist
if [[ -f "rke2ca-cert-key.pem" ]] || [[ -f "rke2ca-cert.crt" ]]; then
  echo "⚠️  WARNING: Certificate files already exist!"
  echo ""
  ls -lh rke2ca-cert-key.pem rke2ca-cert.crt 2>/dev/null || true
  echo ""
  read -p "Overwrite existing certificates? (yes/NO): " -r
  if [[ ! "${REPLY}" =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Aborted. Existing certificates preserved."
    exit 0
  fi
  echo ""
fi

# Generate CA private key
echo "📝 Generating CA private key (${KEY_SIZE}-bit RSA)..."
openssl genrsa -out rke2ca-cert-key.pem "${KEY_SIZE}"

# Set secure permissions on private key
chmod 600 rke2ca-cert-key.pem
echo "✅ Private key generated: rke2ca-cert-key.pem (permissions: 600)"
echo ""

# Generate CA certificate
echo "📝 Generating CA certificate..."
openssl req -new -x509 -days "${DAYS}" \
  -key rke2ca-cert-key.pem \
  -out rke2ca-cert.crt \
  -subj "/CN=${CN}/O=${ORG}" \
  -extensions v3_ca

chmod 644 rke2ca-cert.crt
echo "✅ CA certificate generated: rke2ca-cert.crt"
echo ""

# Copy CA cert to registry CA cert
echo "📝 Creating registry CA certificate..."
cp rke2ca-cert.crt rke2registry-ca.crt
chmod 644 rke2registry-ca.crt
echo "✅ Registry CA certificate created: rke2registry-ca.crt"
echo ""

# Display certificate details
echo "============================================"
echo "Certificate Details"
echo "============================================"
openssl x509 -in rke2ca-cert.crt -noout -text | grep -A2 "Subject:"
openssl x509 -in rke2ca-cert.crt -noout -text | grep -A2 "Validity"
echo ""

# Calculate SHA-256 fingerprint
echo "SHA-256 Fingerprint:"
openssl x509 -in rke2ca-cert.crt -noout -fingerprint -sha256
echo ""

# Show file permissions
echo "============================================"
echo "Generated Files"
echo "============================================"
ls -lh rke2ca-cert-key.pem rke2ca-cert.crt rke2registry-ca.crt
echo ""

echo "✅ Certificate generation complete!"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "   1. NEVER commit rke2ca-cert-key.pem to version control"
echo "   2. Store the private key securely (encrypted backup recommended)"
echo "   3. The .gitignore should already exclude *.pem and *.key files"
echo ""
echo "Next steps:"
echo "   1. Review certificate details above"
echo "   2. Install CA cert on all RKE2 nodes"
echo "   3. Update RKE2 configuration to use this CA"
echo "   4. Backup private key to secure location"
echo ""
