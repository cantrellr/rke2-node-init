# Certificate Management Guide

This directory contains certificate manifests, examples, and generation utilities used by RKE2 bootstrap workflows.

**Last Updated:** February 13, 2026

---

## Security Requirements

- Never commit real private keys or production certificates.
- Treat `*.pem` / `*.key` as sensitive material.
- Generate CA assets on trusted hosts and move root keys to offline secure storage.
- Use encrypted private keys whenever operationally feasible.

---

## Directory Layout

```
certs/
├── README.md
├── *.yaml                         # Cluster/site CA manifests
├── scripts/
│   ├── generate-ca.sh
│   ├── generate-root-ca.sh
│   ├── generate-subordinate-ca.sh
│   └── verify-chain.sh
└── scripts/outputs/               # Script-generated outputs (local use)
```

Example test fixtures live in [../examples/certs](../examples/certs).

---

## Supported Generation Workflows

### 1) Legacy single-CA helper

```bash
./certs/scripts/generate-ca.sh --cn "Example RKE2 CA" --org "Example Org"
```

Creates `rke2ca-cert-key.pem`, `rke2ca-cert.crt`, and `rke2registry-ca.crt` under `certs/`.

### 2) Root + Subordinate CA chain (recommended)

```bash
# Create encrypted root CA
./certs/scripts/generate-root-ca.sh --out-dir certs/scripts/outputs/root-ca

# Create subordinate CA signed by root
./certs/scripts/generate-subordinate-ca.sh \
  --input examples/certs/rke2clusterCA-example.yaml \
  --out-dir certs/scripts/outputs/sub-ca \
  --root-key certs/scripts/outputs/root-ca/root-ca-key.pem \
  --root-cert certs/scripts/outputs/root-ca/root-ca.crt
```

### 3) Chain verification

```bash
./certs/scripts/verify-chain.sh \
  --root certs/scripts/outputs/root-ca/root-ca.crt \
  --sub certs/scripts/outputs/sub-ca/subordinate-ca.crt \
  --sub-key certs/scripts/outputs/sub-ca/subordinate-ca-key.pem
```

---

## Integrating With `rkeprep/v2` Manifests

Use `kind: CustomCA` manifests to reference CA assets consumed by `bin/rke2nodeinit.sh`:

```yaml
apiVersion: rkeprep/v2
kind: CustomCA
metadata:
  name: cluster-ca
spec:
  customCA:
    rootCrt: certs/root-ca.crt
    rootKey: certs/root-ca-key.pem
    intermediateCrt: certs/subordinate-ca.crt
    intermediateKey: certs/subordinate-ca-key.pem
    installToOSTrust: true
```

For sample values, see [../examples/certs/rke2clusterCA-example.yaml](../examples/certs/rke2clusterCA-example.yaml).

---

## Operational Verification

Useful checks before deployment:

```bash
openssl x509 -in certs/scripts/outputs/root-ca/root-ca.crt -noout -text
openssl x509 -in certs/scripts/outputs/sub-ca/subordinate-ca.crt -noout -enddate
openssl verify \
  -CAfile certs/scripts/outputs/root-ca/root-ca.crt \
  certs/scripts/outputs/sub-ca/subordinate-ca.crt
```

---

## CI Coverage

Certificate tooling is covered by:

- [../tests/ci/test_ca_generation.sh](../tests/ci/test_ca_generation.sh)
- [../tests/ci/test_subordinate_encryption.sh](../tests/ci/test_subordinate_encryption.sh)
- [../.github/workflows/certs-ci.yml](../.github/workflows/certs-ci.yml)

---

## Related Documentation

- [scripts/README.md](scripts/README.md)
- [../SECURITY.md](../SECURITY.md)
- [../README.md](../README.md)
