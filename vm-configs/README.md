# VM Configuration Management

Declarative VM provisioning and update workflow for RKE2 nodes using `vmconfig/v1` manifests, schema validation, and GitHub Actions orchestration.

**Last Updated:** February 13, 2026

---

## Architecture Overview

- **Source of truth**: `vm-configs/**/*.yaml`
- **Schema enforcement**: `vm-configs/schema.json`
- **Validation engine**: `scripts/vm-config/config_validator.py`
- **Apply engine**: `scripts/vm-config/apply_vm_config.py`
- **Hypervisor backend**: Hyper-V (current); VMware/Proxmox are roadmap items

---

## Directory Layout

```text
vm-configs/
├── schema.json
├── README.md
└── clusters/
    └── <cluster>/
        ├── cluster-defaults.yaml
        ├── <vm-name>.yaml
        └── rke2-configs/
            └── <vm-name>.yaml
```

---

## Manifest Kinds

### `VirtualMachineConfig`

Defines VM-specific hypervisor settings, KVP guest variables, and optional lifecycle hooks.

### `ClusterConfig`

Defines reusable defaults for VMs in a cluster scope.

---

## Local Validation

```bash
# Validate one file
python3 scripts/vm-config/config_validator.py vm-configs/clusters/cotpa/cotpa-ctrl01.yaml

# Validate all files in a tree
python3 scripts/vm-config/config_validator.py vm-configs/ --all

# Treat warnings as errors
python3 scripts/vm-config/config_validator.py vm-configs/ --all --strict

# Machine-readable output
python3 scripts/vm-config/config_validator.py vm-configs/ --all --json
```

Validation includes schema checks plus semantic checks such as naming conventions, VM resource guidance, and guest-variable consistency.

---

## Dry-Run and Apply

```bash
# Validate and simulate a single VM apply
python3 scripts/vm-config/apply_vm_config.py vm-configs/clusters/cotpa/cotpa-ctrl01.yaml --dry-run

# Simulate applying all VM configs under a cluster
python3 scripts/vm-config/apply_vm_config.py vm-configs/clusters/cotpa/ --all --dry-run
```

Apply mode uses credentials from environment variables defined by `credentialsSecret`:

- `<SECRET>_USER`
- `<SECRET>_PASS`

For example, `credentialsSecret: HYPERV_CREDENTIALS` requires `HYPERV_CREDENTIALS_USER` and `HYPERV_CREDENTIALS_PASS`.

---

## GitHub Workflows

- `.github/workflows/validate-vm-configs.yml`
  - Runs schema + semantic validation
  - Checks for duplicate VM names
  - Comments validation report on PRs
- `.github/workflows/apply-vm-configs.yml`
  - Runs on `main` pushes and manual dispatch
  - Requires self-hosted runner with hypervisor access
  - Applies changed VM configs

Note: CI dry-run application is currently disabled in the validation workflow pending orchestrator changes for fully credentialless dry-run execution.

---

## New Cluster Bootstrap

```bash
mkdir -p vm-configs/clusters/my-cluster/rke2-configs
cp vm-configs/clusters/cotpa/cluster-defaults.yaml vm-configs/clusters/my-cluster/cluster-defaults.yaml
cp vm-configs/clusters/cotpa/cotpa-ctrl01.yaml vm-configs/clusters/my-cluster/my-cluster-ctrl01.yaml
cp examples/config/server-example.yaml vm-configs/clusters/my-cluster/rke2-configs/my-cluster-ctrl01.yaml
python3 scripts/vm-config/config_validator.py vm-configs/clusters/my-cluster --all
```

---

## Operational Notes

- Keep VM names DNS-safe (`lowercase`, `numbers`, `hyphens`).
- Keep filenames aligned to `metadata.name`.
- Avoid sensitive material in guest variables.
- Use small, reviewable PRs for VM changes.

---

## Related Documentation

- [../docs/HYPERV-VM-NAME-SETUP.md](../docs/HYPERV-VM-NAME-SETUP.md)
- [../examples/config/README.md](../examples/config/README.md)
- [../README.md](../README.md)
