# CLI Reference

Last Updated: April 24, 2026

This document is the canonical command-line reference for the repository.

## Primary Entrypoint

Script: `bin/rke2nodeinit.sh`

### Usage Pattern

```bash
sudo ./bin/rke2nodeinit.sh [flags] <action>
sudo ./bin/rke2nodeinit.sh -f <manifest.yaml> [flags] <action>
```

### Actions

| Action | Purpose | Typical Host |
| --- | --- | --- |
| `image` | Download/stage artifacts for offline use | Connected template host |
| `push` | Push staged images to private registry | Registry-connected host |
| `server` | Configure and install `rke2-server` | Control-plane node |
| `add-server` | Join additional control-plane node | Control-plane node |
| `agent` | Configure and install `rke2-agent` | Worker node |
| `verify` | Validate prerequisites only | Any node |
| `airgap` | `image` flow, then power off for templating | Template host |
| `label-node` | Apply Kubernetes labels | Cluster node with kubectl context |
| `taint-node` | Apply Kubernetes taints | Cluster node with kubectl context |
| `custom-ca` | Generate/install token material from CA config | Prep host |

### Common Flags

| Flag | Meaning |
| --- | --- |
| `-f <file>` | Input YAML manifest (`apiVersion: rkeprep/v2`) |
| `-v <version>` | Explicit RKE2 version |
| `-r <registry>` | Registry endpoint |
| `-u <user>` / `-p <pass>` | Registry credentials |
| `-y` | Non-interactive confirmations |
| `-P` | Print sanitized manifest |
| `--dry-push` | Simulate push action |
| `--enable-fips` | Enable FIPS mode (Ubuntu Pro) |
| `--fix-cni-permissions` | Enable CNI permission remediation on image action |
| `--enable-boot-service` | Enable first-boot ISO execution flow |
| `--boot-yaml-path <dir>` | Directory used to generate boot ISOs |
| `--boot-mode <oneshot|persistent>` | Boot service execution policy |

### Example Commands

```bash
# Build template image artifacts
sudo ./bin/rke2nodeinit.sh -f configs/preprod/preprod-vmware-v1.35.3+rke2r3-image.yaml image

# Push staged images
sudo ./bin/rke2nodeinit.sh --dry-push push -r reg.example.local/rke2 -u svc -p 'secret'

# Configure first server
sudo ./bin/rke2nodeinit.sh -f configs/preprod/nodes/dc1manager-ctrl01.yaml server

# Configure worker
sudo ./bin/rke2nodeinit.sh -f configs/preprod/nodes/dc1manager-work01.yaml agent

# Verify prerequisites only
sudo ./bin/rke2nodeinit.sh -f configs/preprod/nodes/dc1manager-ctrl01.yaml verify
```

## Related CLIs

### Makefile Targets

| Target | Purpose |
| --- | --- |
| `make token TOKEN_IMAGE_NAME=<image-name>` | Generate reusable bootstrap token under image output folder |
| `make sh` | Mark root-level shell scripts executable |
| `make kubeconfig` | Install `kubectl` and copy local kubeconfig |
| `make boot-isos` | Build node boot ISOs from YAMLs |
| `make boot-isos-clean` | Remove generated ISO artifacts |

Notes:
- `make token` requires `TOKEN_IMAGE_NAME` and writes to `outputs/<image-name>/<image-name>-bootstrap-token.txt`.

### Certificate Tooling

Path: `scripts/certs/`

| Script | Purpose |
| --- | --- |
| `generate-root-ca.sh` | Create encrypted root CA key + cert |
| `generate-subordinate-ca.sh` | Create subordinate CA chain |
| `verify-chain.sh` | Verify root/subordinate CA chain |
| `generate-ca.sh` | Legacy single-CA helper |

See `docs/SCRIPTS-REFERENCE.md` for full utility coverage.
