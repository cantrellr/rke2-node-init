# Testing Guide

Last Updated: April 24, 2026

This guide maps local tests to repository risk areas and CI workflows.

## Prerequisites

- Bash
- Python 3.11+
- `shellcheck`
- `yamllint`

## Static Validation

```bash
shellcheck bin/rke2nodeinit.sh scripts/*.sh tests/*.sh
yamllint configs examples
```

## Functional Bash Tests

Run from repository root:

```bash
bash tests/test_generate_bootstrap_token_contract.sh
bash tests/test_hardened_cni_fetch.sh
bash tests/test_token_strict_policy.sh
bash tests/test_token_yaml_key_normalization.sh
bash tests/test_tokenfile_paths.sh
bash tests/test_truncated_image_staging.sh
bash tests/test_verify_stage_images.sh
bash tests/verify_no_duplicate_tokenfile.sh
```

## Certificate CI Tests (Local Execution)

```bash
bash tests/ci/test_ca_generation.sh
bash tests/ci/test_subordinate_encryption.sh
```

## Utility Sanity Tests

```bash
bash scripts/test/test-interface-detection.sh
python3 scripts/render_rke2_config.py configs/preprod/nodes/dc1manager-ctrl01.yaml >/tmp/rendered.yaml
```

## CI Workflow Mapping

| Workflow | Purpose |
| --- | --- |
| `.github/workflows/validate-rke-configs.yml` | Validate `rkeprep/v2` YAML syntax and required fields |
| `.github/workflows/verify-tokenfile.yml` | Detect duplicate token-file output from render helper |
| `.github/workflows/certs-ci.yml` | Validate CA generation and chain verification |
| `.github/workflows/validate-vm-configs.yml` | VM config validation automation |
| `.github/workflows/apply-vm-configs.yml` | Self-hosted apply pipeline for VM config operations |

## Recommended Pre-PR Test Set

1. static validation
2. all tests under `tests/`
3. certificate tests under `tests/ci/`
4. one representative `verify` action against a preprod node manifest

## Test Evidence in PR

Include:
- commands run
- pass/fail status
- any skipped tests and rationale
