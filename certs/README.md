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

### Generate Custom CA for RKE2

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
# OR generate a separate registry CA following the same steps

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
