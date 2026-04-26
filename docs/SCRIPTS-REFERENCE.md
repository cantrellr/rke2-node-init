# Scripts and Utilities Reference

Last Updated: April 24, 2026

This document inventories all operational scripts and utilities currently present in the repository.

## Primary Entrypoint

| Path | Type | Purpose |
| --- | --- | --- |
| `bin/rke2nodeinit.sh` | Bash | Main orchestration for image, push, server, add-server, agent, verify, airgap, label-node, taint-node, custom-ca |

## Operations Scripts (`scripts/`)

| Path | Type | Purpose |
| --- | --- | --- |
| `scripts/apply-stigs.sh` | Bash | STIG report and remediation helper |
| `scripts/build-boot-isos.sh` | Bash | Build per-node ISO images from YAML manifests |
| `scripts/boot_script.sh` | Bash | Boot helper utilities for template workflows |
| `scripts/cleanup-rke2.sh` | Bash | Cleanup/remove RKE2 and related artifacts |
| `scripts/fix-cni-perms.sh` | Bash | CNI permissions remediation |
| `scripts/list-effective-rke2-images.sh` | Bash | Enumerate effective staged RKE2 image references |
| `scripts/run_vuln_scan.sh` | Bash | Vulnerability scan helper scaffold |
| `scripts/certs-auto.sh` | Bash | CA generation and staging automation |

## Certificate Tooling (`scripts/certs/`)

| Path | Type | Purpose |
| --- | --- | --- |
| `scripts/certs/generate-ca.sh` | Bash | Legacy single-CA generation |
| `scripts/certs/generate-root-ca.sh` | Bash | Encrypted root CA generation |
| `scripts/certs/generate-subordinate-ca.sh` | Bash | Subordinate CA generation/signing |
| `scripts/certs/verify-chain.sh` | Bash | Cert chain and key/cert consistency validation |

## Development Environment

| Path | Type | Purpose |
| --- | --- | --- |
| `scripts/ubuntu24/ubuntu24-dev-setup.sh` | Bash | Ubuntu 24 developer environment setup |
| `scripts/wsl-env/wsl-dev-setup.sh` | Bash | WSL developer environment setup |
| `scripts/wsl-env/WSL-DEV-SETUP.md` | Markdown | WSL setup and usage guide |

## Python Utilities

| Path | Purpose |
| --- | --- |
| `scripts/render_rke2_config.py` | Render RKE2 config fragments from rkeprep manifests |
| `scripts/select_hardened_cni_tag.py` | Select hardened CNI tag from release metadata |
| `scripts/vm-config/config_validator.py` | VM config schema/semantic validation |
| `scripts/vm-config/apply_vm_config.py` | VM config apply orchestrator |
| `scripts/vm-config/hyperv_client.py` | Hyper-V integration client helpers |

## Example and Test Scripts

| Path | Purpose |
| --- | --- |
| `examples/phase1-demo.sh` | Demo workflow phase 1 |
| `examples/phase2-demo.sh` | Demo workflow phase 2 |
| `examples/phase3-cli-demo.sh` | Demo workflow phase 3 |
| `examples/phase4-demo.sh` | Demo workflow phase 4 |
| `examples/phase5-demo.sh` | Demo workflow phase 5 |
| `scripts/test/test-interface-detection.sh` | Validate interface list extraction behavior |
| `tests/*.sh` | Functional and contract tests |
| `tests/ci/*.sh` | CI-focused certificate tests |

## VM PowerShell Tooling (`vm/scripts/`)

| Path | Type | Purpose |
| --- | --- | --- |
| `vm/scripts/New-VmsFromCsv.ps1` | PowerShell | Provision new VMs from CSV definitions |
| `vm/scripts/Clone-VmsFromCsv.ps1` | PowerShell | Clone VMs from template/source VM definitions |
| `vm/scripts/rke2-vsphere-resource-pools.ps1` | PowerShell | Build resource pools/folder hierarchy and DRS rules |

## Notes

1. Historical/deprecated scripts are retained in `scripts/archived/` and are not operationally authoritative.
2. For CLI behavior and action syntax, use `docs/CLI-REFERENCE.md`.
3. For execution sequence, use `docs/OPERATIONAL-RUNBOOK.md`.
4. For failures and remediation, use `docs/TROUBLESHOOTING.md`.
