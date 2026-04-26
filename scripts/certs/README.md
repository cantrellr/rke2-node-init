# scripts/certs

This folder contains helper scripts for generating and validating CA materials used with RKE2. All scripts assume `openssl` is installed. Example commands below are shown from this directory.

**Last Updated:** April 24, 2026

## generate-ca.sh

Generates a simple self-signed CA and a registry CA copy in the parent `scripts/` directory.

Outputs (in `scripts/`, because the script writes to its parent directory):
- `rke2ca-cert-key.pem` (CA private key)
- `rke2ca-cert.crt` (CA certificate)
- `rke2registry-ca.crt` (copy of CA cert for registry use)

Options and env vars:
- `--cn`, `CN` (default: Example Organization RKE2 CA)
- `--org`, `ORG` (default: Example Organization)
- `--days`, `DAYS` (default: 3650)
- `--key-size`, `KEY_SIZE` (default: 4096)

Examples:
```bash
./generate-ca.sh
./generate-ca.sh --cn "My RKE2 CA" --org "My Org" --days 3650 --key-size 4096
CN="My RKE2 CA" ORG="My Org" DAYS=3650 KEY_SIZE=4096 ./generate-ca.sh
```

## generate-root-ca.sh

Creates an offline Root CA private key (AES-256 encrypted) and a self-signed Root CA certificate. Outputs are written to the selected output directory (default `./outputs/root-ca`).

Outputs (in `OUT_DIR`):
- `root-ca-key.pem` (encrypted Root CA private key)
- `root-ca.crt` (Root CA certificate)

Options and env vars:
- `--out-dir`, `OUT_DIR` (default: `./outputs/root-ca`)
- `--cn`, `CN` (default: Offline Root CA)
- `--days`, `DAYS` (default: 36500)
- `--key-size`, `KEY_SIZE` (default: 4096)
- `--passphrase` (non-interactive passphrase)

Examples:
```bash
./generate-root-ca.sh
./generate-root-ca.sh --out-dir ./outputs/root-ca --cn "Offline Root CA" --days 36500
./generate-root-ca.sh --passphrase "S3curePassphrase" --out-dir ./outputs/root-ca
OUT_DIR=./outputs/root-ca CN="Offline Root CA" DAYS=36500 ./generate-root-ca.sh
```

## generate-subordinate-ca.sh

Creates a subordinate CA key and CSR, then signs it with a Root CA to produce a subordinate CA certificate. Supports interactive prompts or input from a YAML file.

Outputs (in `OUT_DIR`):
- `subordinate-ca-key.pem` (subordinate CA private key)
- `subordinate-ca.csr` (CSR)
- `subordinate-ca.crt` (subordinate CA certificate)
- `ca-sub-ext.cnf` (temporary extensions config)

Options and env vars:
- `--out-dir`, `OUT_DIR` (default: `./outputs/sub-ca`)
- `--input` (YAML input with CN/Org/key size/validity)
- `--cn`, `--org`
- `--key-size`, `--days`, `--pathlen`
- `--root-key` (path to Root CA private key)
- `--root-cert` (path to Root CA certificate)
- `--root-passphrase` (non-interactive passphrase for Root CA key)
- `--encrypt-sub-key` (encrypt subordinate private key)
- `--sub-passphrase` (non-interactive passphrase for subordinate key)
- `--sub-passfile` (file containing subordinate key passphrase)

Examples:
```bash
./generate-subordinate-ca.sh \
  --out-dir ./outputs/sub-ca \
  --cn "RKE2 Cluster CA" \
  --org "My Org" \
  --root-key ./outputs/root-ca/root-ca-key.pem \
  --root-cert ./outputs/root-ca/root-ca.crt

./generate-subordinate-ca.sh \
  --input ../../examples/certs/rke2clusterCA-example.yaml \
  --root-key ./outputs/root-ca/root-ca-key.pem \
  --root-cert ./outputs/root-ca/root-ca.crt

./generate-subordinate-ca.sh \
  --root-key ./outputs/root-ca/root-ca-key.pem \
  --root-cert ./outputs/root-ca/root-ca.crt \
  --encrypt-sub-key --sub-passphrase "S3curePassphrase"
```

## verify-chain.sh

Verifies a subordinate CA certificate against a root CA and checks basic constraints, extended key usage, and (optionally) that the private key matches the certificate.

Options:
- `--root` (path to Root CA certificate)
- `--sub` (path to subordinate CA certificate)
- `--sub-key` (optional path to subordinate CA private key)
- `--sub-passphrase` (passphrase for encrypted subordinate key)
- `--sub-passfile` (file containing passphrase)

Examples:
```bash
./verify-chain.sh --root ./outputs/root-ca/root-ca.crt --sub ./outputs/sub-ca/subordinate-ca.crt

./verify-chain.sh \
  --root ./outputs/root-ca/root-ca.crt \
  --sub ./outputs/sub-ca/subordinate-ca.crt \
  --sub-key ./outputs/sub-ca/subordinate-ca-key.pem

./verify-chain.sh \
  --root ./outputs/root-ca/root-ca.crt \
  --sub ./outputs/sub-ca/subordinate-ca.crt \
  --sub-key ./outputs/sub-ca/subordinate-ca-key.pem \
  --sub-passphrase "S3curePassphrase"
```
