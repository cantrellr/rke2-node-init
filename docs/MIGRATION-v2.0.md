# Migration Guide: v2.0 Path and Documentation Changes

Last Updated: April 24, 2026

This guide summarizes breaking path changes introduced for v2.0 readiness.

## Breaking Changes

### 1) Runtime certificate paths are now environment-scoped

Old patterns:
- `/rke2-node-init/certs/cocloud/...`
- `/rke2-node-init/certs/scripts/outputs/root-ca/...`

New patterns:
- `/rke2-node-init/configs/cotpa/certs/...`
- `/rke2-node-init/configs/preprod/certs/...`

### 2) Certificate generation script location

Old pattern:
- `./certs/scripts/<tool>.sh`

New pattern:
- `./scripts/certs/<tool>.sh`

### 3) Manifest examples

Old pattern:
- `clusters/...`

New pattern:
- `configs/...`

## Migration Checklist

1. Update all customCA paths in manifests to environment-scoped runtime paths.
2. Update local automation scripts to call `scripts/certs/*.sh`.
3. Update internal runbooks and command snippets from `clusters/` to `configs/`.
4. Ensure expected cert files exist under `configs/<env>/certs/`.
5. Run validation and test commands from `docs/TESTING-GUIDE.md`.

## Compatibility Notes

1. Historical documentation under `docs/redesign/` and `docs/report/` may contain legacy path examples.
2. Active operational references are now:
   - `README.md`
   - `docs/CLI-REFERENCE.md`
   - `docs/OPERATIONAL-RUNBOOK.md`
   - `docs/TROUBLESHOOTING.md`

## Quick Verification

```bash
# No legacy cert path patterns in active manifests
rg -n "/rke2-node-init/certs/(cocloud|scripts/outputs)" configs

# No legacy cert script location in active docs/scripts
rg -n "\./certs/scripts/" README.md docs scripts tests examples
```
