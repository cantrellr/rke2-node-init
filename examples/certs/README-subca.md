# Subordinate CA input template

This folder contains a sample YAML used by the subordinate CA generator.

This folder contains sample YAML used by `scripts/certs/generate-subordinate-ca.sh`.

## Usage

Interactive (script prompts for missing values):

```bash
./scripts/certs/generate-subordinate-ca.sh --input examples/certs/subca-input.yaml \
  --root-key /path/to/root-key.pem \
  --root-cert /path/to/root-cert.pem
```

Fully non-interactive (including encrypted root key passphrase):

```bash
./scripts/certs/generate-subordinate-ca.sh --input examples/certs/subca-input.yaml \
  --root-key /path/to/root-key.pem \
  --root-cert /path/to/root-cert.pem \
  --root-passphrase 'rootpassphrase'
```

Specify output directory and encrypted subordinate key:

```bash
./scripts/certs/generate-subordinate-ca.sh --input examples/certs/subca-input.yaml \
  --out-dir scripts/certs/outputs/sub-ca \
  --root-key /path/to/root-key.pem \
  --root-cert /path/to/root-cert.pem \
  --encrypt-sub-key --sub-passphrase 'subordinate-passphrase'
```

## Notes
- If you have `yq` installed the generator will parse YAML robustly. Otherwise it falls back to a simple grep-based extraction.
- Keep generated private keys secure. Prefer `--encrypt-sub-key` with `--sub-passfile` (or `--sub-passphrase`) for encrypted subordinate key storage.
