# PR Validation Checklist

Last Updated: April 24, 2026

Use this checklist before opening or merging a PR.

## 1) Static Quality Gates

```bash
shellcheck bin/rke2nodeinit.sh scripts/*.sh tests/*.sh
yamllint configs examples
```

## 2) Documentation Quality Gates

```bash
markdownlint README.md CONTRIBUTING.md docs/**/*.md
```

Recommended additional check:
- markdown link checker in CI for root docs and `docs/`

## 3) Functional and Contract Tests

```bash
bash tests/test_generate_bootstrap_token_contract.sh
bash tests/test_hardened_cni_fetch.sh
bash tests/test_tokenfile_paths.sh
bash tests/test_truncated_image_staging.sh
bash tests/test_verify_stage_images.sh
bash tests/verify_no_duplicate_tokenfile.sh
bash tests/ci/test_ca_generation.sh
bash tests/ci/test_subordinate_encryption.sh
```

## 4) Path Integrity Checks

```bash
rg -n "clusters/" README.md CONTRIBUTING.md docs scripts
rg -n "\./certs/scripts/" README.md docs scripts examples tests
rg -n "/rke2-node-init/certs/(cocloud|scripts/outputs)" configs
```

## 5) Release Hygiene

- Update `CHANGELOG.md` with behavior and path changes.
- Ensure migration guidance exists for breaking changes.
- Ensure docs are updated in the same PR as behavioral changes.

## 6) PR Description Requirements

Include:
1. problem statement
2. implementation summary
3. validation evidence
4. risk and rollback notes
5. documentation files updated
