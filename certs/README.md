# Certificate Management Guide

## ⚠️ SECURITY NOTICE

**NEVER commit real certificates or private keys to version control!**

This directory should contain:
- ✅ Example/template YAML files
- ✅ Certificate generation scripts
- ✅ Documentation
- ❌ **NO** real `.pem`, `.key`, or `.crt` files (except examples)

---

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Generating CA Certificates](#generating-ca-certificates)
- [Generating Registry Certificates](#generating-registry-certificates)
- [RKE2 Certificate Configuration](#rke2-certificate-configuration)
- [Certificate Verification](#certificate-verification)
- [Troubleshooting](#troubleshooting)
- [File Structure](#file-structure)

---

## 🚀 Quick Start
### Recommended: Automated generation (Make + scripts)

We provide non-interactive scripts and top-level Makefile targets to generate a secure root CA and a subordinate CA. This is the recommended workflow because the scripts:

- create encrypted root private keys (AES-256) and set safe file permissions
- generate subordinate CSRs and sign them with explicit OpenSSL extensions (CA:TRUE, pathlen, EKU)
- support both interactive and non-interactive usage (passphrases, input YAML)

Examples (run from the repository root):

```bash
# Generate an encrypted Root CA and store outputs under outputs/certs/root-<timestamp>/
make certs-root-ca

# Generate a Subordinate CA from an input YAML (see examples in certs/examples/).
# INPUT may be a manifest that contains spec.subject.* fields; OUTDIR is optional.
make certs-sub-ca INPUT=certs/examples/rke2clusterCA-example.yaml

# Verify OpenSSL is available and a short reminder to protect keys
make certs-verify
```

If you prefer to call the scripts directly you can (from repo root):

```bash
# Root CA (interactive prompt for passphrase unless --passphrase is supplied)
./certs/scripts/generate-root-ca.sh --out-dir outputs/certs/root-<ts> [--passphrase "mysecret"]

# Subordinate CA: supports --input <yaml>, --cn, --org, --pathlen, and --root-passphrase
./certs/scripts/generate-subordinate-ca.sh --input certs/examples/rke2clusterCA-example.yaml \
  --out-dir outputs/certs/subca-<ts> --pathlen 1 --root-passphrase "mysecret"
```

The scripts validate inputs, create an OpenSSL extensions file for the subordinate CA, and sign using:

- extensions: v3_ca (ensures CA:TRUE and pathlen)
- extendedKeyUsage: serverAuth, clientAuth (so the sub-CA may issue TLS server certs)

Use the `--root-passphrase` and `--passphrase` flags for non-interactive automation in CI or provisioning. Always move the root private key offline after generation.

### Manual OpenSSL (optional)

If you need to generate certificates manually the steps below remain valid. The scripted flow is preferred for repeatability and safe defaults.

#### Generate Custom CA for RKE2

```bash
# 1. Generate CA private key (4096-bit RSA)
openssl genrsa -out rke2ca-cert-key.pem 4096

# 2. Create CA certificate (valid for 10 years)
openssl req -new -x509 -days 3650 \
  -key rke2ca-cert-key.pem \
  -out rke2ca-cert.crt \
  -subj "/CN=Your Organization RKE2 CA"

# 3. Generate registry CA certificate (same or different CA)
cp rke2ca-cert.crt rke2registry-ca.crt

# 4. Set proper permissions
chmod 600 rke2ca-cert-key.pem
chmod 644 rke2ca-cert.crt rke2registry-ca.crt
```

### Verify Certificates

```bash
# Check CA certificate details
openssl x509 -in rke2ca-cert.crt -text -noout

# Verify certificate validity
openssl x509 -in rke2ca-cert.crt -noout -checkend 86400

# Check certificate fingerprint (SHA-256)
openssl x509 -in rke2ca-cert.crt -noout -fingerprint -sha256
```

---

## 🔐 Generating CA Certificates

### Method 1: OpenSSL (Recommended)

#### Create CA Configuration File

```bash
cat > ca-config.cnf <<EOF
[ req ]
default_bits       = 4096
default_md         = sha256
default_keyfile    = rke2ca-cert-key.pem
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca
prompt             = no

[ req_distinguished_name ]
C  = US
ST = State
L  = City
O  = Your Organization Name
OU = IT Department
CN = Your Organization RKE2 CA

[ v3_ca ]
basicConstraints       = critical,CA:TRUE
keyUsage              = critical,keyCertSign,cRLSign
subjectKeyIdentifier  = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
```

#### Generate CA Certificate

```bash
# Generate private key
openssl genrsa -out rke2ca-cert-key.pem 4096

# Generate self-signed CA certificate
openssl req -new -x509 -days 3650 \
  -config ca-config.cnf \
  -key rke2ca-cert-key.pem \
  -out rke2ca-cert.crt

# Set secure permissions
chmod 600 rke2ca-cert-key.pem
chmod 644 rke2ca-cert.crt
```

### Method 2: Using cfssl

```bash
# Install cfssl
go install github.com/cloudflare/cfssl/cmd/cfssl@latest
go install github.com/cloudflare/cfssl/cmd/cfssljson@latest

# Create CA config
cat > ca-csr.json <<EOF
{
  "CN": "Your Organization RKE2 CA",
  "key": {
    "algo": "rsa",
    "size": 4096
  },
  "names": [
    {
      "C": "US",
      "ST": "State",
      "L": "City",
      "O": "Your Organization",
      "OU": "IT"
    }
  ],
  "ca": {
    "expiry": "87600h"
  }
}
EOF

# Generate CA
cfssl gencert -initca ca-csr.json | cfssljson -bare rke2ca

# Rename to match expected filenames
mv rke2ca-key.pem rke2ca-cert-key.pem
mv rke2ca.pem rke2ca-cert.crt
```

---

## 📦 Generating Registry Certificates

### Option 1: Use Same CA Certificate

If your registry trusts the same CA:

```bash
cp rke2ca-cert.crt rke2registry-ca.crt
```

### Option 2: Generate Separate Registry CA

```bash
# Generate registry CA private key
openssl genrsa -out registry-ca-key.pem 4096

# Generate registry CA certificate
openssl req -new -x509 -days 3650 \
  -key registry-ca-key.pem \
  -out rke2registry-ca.crt \
  -subj "/CN=Your Organization Registry CA"

# Set permissions
chmod 600 registry-ca-key.pem
chmod 644 rke2registry-ca.crt
```

### Option 3: Extract from Existing Registry

```bash
# Download CA cert from registry server
openssl s_client -showcerts -connect registry.example.com:443 </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > rke2registry-ca.crt

# Verify
openssl x509 -in rke2registry-ca.crt -text -noout
```

---

## 🎯 RKE2 Certificate Configuration

### Create RKE2 CA YAML Configuration

Create a YAML file (e.g., `rke2clusterCA.yaml`) to reference your CA:

```yaml
apiVersion: rkeprep/v1
kind: CustomCA
metadata:
  name: production-cluster-ca

spec:
  # Path to CA certificate file
  caCert: /path/to/certs/rke2ca-cert.crt
  
  # Path to CA private key
  caKey: /path/to/certs/rke2ca-cert-key.pem
  
  # Optional: Custom subject for server certificates
  subject:
    commonName: "rke2-server"
    organization: "Your Organization"
    organizationalUnit: "Kubernetes"
    locality: "City"
    province: "State"
    country: "US"
```

### Install CA Certificate on Nodes

```bash
# Copy CA cert to trusted location
sudo cp rke2ca-cert.crt /usr/local/share/ca-certificates/rke2ca.crt

# Update CA trust store (Ubuntu/Debian)
sudo update-ca-certificates

# Update CA trust store (RHEL/CentOS)
sudo cp rke2ca-cert.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust

# Verify installation
ls -l /etc/ssl/certs/ | grep rke2ca
```

---

## ✅ Certificate Verification

### Verify Certificate Properties

```bash
# Show certificate details
openssl x509 -in rke2ca-cert.crt -text -noout

# Check expiration date
openssl x509 -in rke2ca-cert.crt -noout -enddate

# Verify it's a CA certificate
openssl x509 -in rke2ca-cert.crt -noout -text | grep "CA:TRUE"

# Calculate SHA-256 fingerprint (for server tokens)
openssl x509 -in rke2ca-cert.crt -noout -fingerprint -sha256 | \
  cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]'
```

### Verify Certificate Chain

```bash
# Verify certificate against CA
openssl verify -CAfile rke2ca-cert.crt rke2ca-cert.crt

# Check certificate and key match
openssl x509 -in rke2ca-cert.crt -noout -modulus | openssl md5
openssl rsa -in rke2ca-cert-key.pem -noout -modulus | openssl md5
# (Both MD5 hashes should match)
```

---

## 🔧 Troubleshooting

### Common Issues

#### "unable to load certificate"
```bash
# Check file format
file rke2ca-cert.crt
# Should show: "PEM certificate"

# Verify PEM format
openssl x509 -in rke2ca-cert.crt -text -noout
```

#### "certificate verify failed"
```bash
# Check if CA is installed in system trust store
openssl s_client -connect your-server:6443 -CAfile rke2ca-cert.crt

# Verify certificate dates
openssl x509 -in rke2ca-cert.crt -noout -dates
```

#### "permission denied"
```bash
# Fix file permissions
chmod 600 rke2ca-cert-key.pem  # Private key (read-only for owner)
chmod 644 rke2ca-cert.crt       # Public cert (readable by all)

# Verify permissions
ls -l rke2ca-cert*
# Should show: -rw------- for .pem, -rw-r--r-- for .crt
```

### Certificate Rotation

When certificates are near expiration:

```bash
# Check days until expiration
openssl x509 -in rke2ca-cert.crt -noout -checkend $((30*86400))

# Generate new CA (follow generation steps above)
# Update RKE2 configuration with new CA
# Restart RKE2 services on all nodes
```

---

## 📂 File Structure

After certificate generation, your `certs/` directory should look like:

```
certs/
├── README.md                          # This file
├── .gitkeep                           # Keep directory in git
│
├── examples/                          # Example YAML configurations
│   ├── example-ca.yaml               # Example CA config
│   ├── rke2clusterCA-example.yaml    # Example cluster CA config
│   └── registry-ca-example.yaml      # Example registry CA config
│
├── scripts/                           # Certificate generation scripts
│   ├── generate-ca.sh                # Automated CA generation
│   └── rotate-certs.sh               # Certificate rotation helper
│
├── rke2ca-cert-key.pem               # Your CA private key (NEVER commit!)
├── rke2ca-cert.crt                   # Your CA certificate
├── rke2registry-ca.crt               # Registry CA certificate
│
└── *.yaml                             # Custom CA YAML configs (domain-specific)
```

### Files in .gitignore

The following patterns prevent accidental commits of sensitive files:

```gitignore
# Certificate private keys and certificates (except examples)
certs/*.pem
certs/*.key
certs/*.crt
!certs/examples/*.crt
!certs/examples/*.pem
```

---

## 🔒 Security Best Practices

1. **Never commit private keys** (`.pem`, `.key` files) to version control
2. **Use strong key sizes** - 4096-bit RSA minimum, or EC P-384/P-521
3. **Set appropriate validity periods** - 1-10 years for CA certificates
4. **Secure key storage** - Use encrypted volumes, HSM, or vault systems
5. **Restrict key permissions** - `chmod 600` for private keys
6. **Regular rotation** - Rotate certificates before expiration
7. **Audit access** - Log and monitor certificate usage
8. **Backup securely** - Encrypt backups of CA private keys
9. **Use strong passphrases** - If encrypting private keys
10. **Separate environments** - Different CAs for dev/staging/production

---

## 📚 Additional Resources

- [RKE2 Certificate Management](https://docs.rke2.io/security/certificate_management)
- [OpenSSL Certificate Authority](https://jamielinux.com/docs/openssl-certificate-authority/)
- [Kubernetes PKI Certificates](https://kubernetes.io/docs/setup/best-practices/certificates/)
- [CFSSL Documentation](https://github.com/cloudflare/cfssl)

---

## 📧 Support

For certificate-related issues:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review RKE2 logs: `journalctl -u rke2-server -f`
3. Open an issue with certificate details (NOT the private key!)

**Last Updated:** November 8, 2025

---

## Makefile targets and automated scripts

### CI / Automation checklist

When automating CA generation in CI or provisioning pipelines prefer non-interactive flags and ephemeral output directories.

- Use `--passphrase` / `--root-passphrase` to provide passphrases securely from a secrets manager (avoid embedding in code).
- Supply `OUTDIR` or capture the Make outputs under `outputs/certs/...` and move private keys to secure storage (Vault, HSM) immediately.
- Example non-interactive flow (CI runner with a secrets store):

```bash
OUTDIR=outputs/certs/root-$(date +%Y%m%d-%H%M%S)
make certs-root-ca OUTDIR=${OUTDIR} # or call the script with --passphrase
# Move the generated root key into secure storage and delete from build host
```

- Verify artifacts in CI (always):

```bash
openssl x509 -in outputs/certs/root-*/root-ca.crt -noout -text
openssl verify -CAfile outputs/certs/root-*/root-ca.crt outputs/certs/subca-*/subordinate-ca.crt
```

- Security reminders:
  - Never persist root private keys in build artifacts or Docker images.
  - Prefer using a short-lived subordinate CA for automated signing and keep the root offline.
  - Rotate subordinate keys regularly and audit signing operations.

We provide Makefile targets and helper scripts to produce an offline Root CA and a signed subordinate CA suitable for RKE2 cluster issuer configuration.

Usage examples (run these from the repository root):

```bash
# Create an offline Root CA interactively (files under outputs/certs/root-<timestamp>)
make certs-root-ca

# Create a subordinate CA from an input YAML (see examples/rke2clusterCA-example.yaml)
make certs-sub-ca INPUT=certs/examples/rke2clusterCA-example.yaml
```

Scripts:
- `certs/scripts/generate-root-ca.sh` - interactive creation of an encrypted root private key and self-signed certificate. Move the private key offline after creation.
- `certs/scripts/generate-subordinate-ca.sh` - create subordinate key/CSR and sign with the provided root CA (supports `--input` YAML or interactive prompts). Uses a strict v3 CA extension and sets pathlen to 0 by default.

Security notes:
- The root private key is created encrypted with AES-256 and a passphrase prompted interactively. Keep it offline and store in encrypted backup / HSM.
- The subordinate CA private key is generated unencrypted by default to support automated RKE2 installations; if you need it encrypted, wrap it using a secure vault or use openssl to encrypt.
- The Makefile only orchestrates scripts; review the scripts and run them on an isolated machine when creating production keys.

