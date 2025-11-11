Subordinate CA input template

This folder contains a sample YAML used by the subordinate CA generator.

Usage

Interactive (Make will prompt for missing values):

    make certs-sub-ca INPUT=certs/examples/subca-input.yaml

Fully non-interactive (provide root key/cert/pass when calling Make):

    make certs-sub-ca INPUT=certs/examples/subca-input.yaml ROOT_KEY=/path/to/root-key.pem \
      ROOT_CERT=/path/to/root-cert.pem ROOT_PASS='rootpassphrase'

Or run the generator directly:

    ./certs/scripts/generate-subordinate-ca.sh --input certs/examples/subca-input.yaml \
      --root-key /path/to/root-key.pem --root-cert /path/to/root-cert.pem

Notes
- If you have `yq` installed the generator will parse YAML robustly. Otherwise it falls back to a simple grep-based extraction.
- `ROOT_PASS` is forwarded as `--root-passphrase` to the generator so it can run non-interactively if the root key is encrypted.
- Keep generated private keys secure. Consider using `SUB_ENCRYPT=true` and `SUB_PASSFILE` to encrypt subordinate private key storage.
