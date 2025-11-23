# VM Configuration Management

GitOps-based VM configuration and deployment system for RKE2 clusters. This directory contains declarative VM configurations that are automatically applied to hypervisors via GitHub Actions workflows.

## Overview

This system provides infrastructure-as-code for VM lifecycle management:

- **Declarative Configuration**: Define VMs in YAML with validation against JSON schema
- **GitOps Workflow**: Commit config → GitHub Actions applies → VMs created/updated
- **Automated Deployment**: VMs automatically clone from templates and configure themselves
- **Version Control**: Full audit trail, rollback capability, change tracking
- **Multi-Hypervisor**: Supports Hyper-V, VMware (planned), Proxmox (planned)

## Directory Structure

```
vm-configs/
├── schema.json                      # JSON Schema for validation
├── clusters/                        # Cluster-specific configurations
│   └── cotpa/                       # Example cluster
│       ├── cluster-defaults.yaml    # Cluster-wide defaults
│       ├── cotpa-ctrl01.yaml        # Control plane node 1
│       ├── cotpa-worker01.yaml      # Worker node 1
│       └── rke2-configs/            # RKE2 node configurations
│           ├── cotpa-ctrl01.yaml    # (rkeprep format)
│           └── cotpa-worker01.yaml
└── README.md                        # This file
```

## Configuration Format

### VirtualMachineConfig

Defines a single VM's configuration:

```yaml
---
apiVersion: vmconfig/v1
kind: VirtualMachineConfig
metadata:
  name: cotpa-ctrl01              # VM hostname (DNS-compatible)
  cluster: cotpa                  # Cluster association
  environment: production         # Environment classification
  labels:
    role: control-plane
    tier: infrastructure

spec:
  hypervisor:
    type: hyperv                  # Hypervisor type
    connection:
      host: hyperv-host.example.com
      credentialsSecret: HYPERV_CREDENTIALS  # GitHub secret name
    
    vmSettings:
      templateName: ubuntu22-rke2-template  # Source template
      network: "Internal Network"
      cpus: 4
      memoryMB: 8192
    
    guestVariables:               # Exposed to guest via KVP/guestinfo
      VirtualMachineName: cotpa-ctrl01
      ClusterName: cotpa
      NodeRole: server
      RKE2ConfigPath: /rke2-node-init/configs/cotpa-ctrl01.yaml

  rke2Config:
    role: server                  # server or agent
    configPath: clusters/cotpa/rke2-configs/cotpa-ctrl01.yaml
    autoStart: true               # Boot service auto-executes

  operations:                     # Lifecycle hooks
    onCreate:
      - "echo 'VM created'"
    onUpdate:
      - "echo 'VM updated'"
```

### ClusterConfig

Defines cluster-wide defaults:

```yaml
---
apiVersion: vmconfig/v1
kind: ClusterConfig
metadata:
  name: cotpa

spec:
  defaults:
    hypervisor:
      type: hyperv
      connection:
        host: hyperv-host.example.com
        credentialsSecret: HYPERV_CREDENTIALS
      vmSettings:
        templateName: ubuntu22-rke2-template
        network: "Internal Network"
        cpus: 4
        memoryMB: 8192
    
    rke2Config:
      autoStart: true
```

## Workflows

### Validation (Pull Requests)

Automatically triggered on PRs that modify VM configs:

1. **Schema Validation**: Ensures YAML matches schema
2. **Semantic Checks**: Validates naming, resource requirements, consistency
3. **Conflict Detection**: Checks for duplicate VM names
4. **Dry-Run**: Tests configuration application without changes
5. **PR Comment**: Posts validation report

### Application (Main Branch)

Automatically triggered on push to main branch:

1. **Change Detection**: Identifies modified VM configs
2. **Validation**: Re-validates before application
3. **Hypervisor Connection**: Connects via WinRM/API
4. **VM Operations**: Creates/updates VMs, sets KVP data
5. **Verification**: Confirms successful application
6. **Reporting**: Uploads application report as artifact

### Manual Dispatch

Trigger workflow manually:

```
Actions → Apply VM Configurations → Run workflow
  config_path: vm-configs/clusters/cotpa/cotpa-ctrl01.yaml (optional)
  dry_run: true (optional)
```

## Getting Started

### Prerequisites

1. **Self-Hosted Runner** with hypervisor network access
   ```bash
   # On runner host, install dependencies:
   pip3 install jsonschema pyyaml pywinrm
   ```

2. **GitHub Secrets** for hypervisor credentials:
   - `HYPERV_CREDENTIALS_USER` - Hyper-V administrator username
   - `HYPERV_CREDENTIALS_PASS` - Hyper-V administrator password

3. **Template VM** prepared with rke2nodeinit.sh image action:
   ```bash
   ./bin/rke2nodeinit.sh image -f config.yaml --enable-boot-service
   ```

### Creating a New Cluster

1. **Create cluster directory**:
   ```bash
   mkdir -p vm-configs/clusters/my-cluster/rke2-configs
   ```

2. **Define cluster defaults** (`cluster-defaults.yaml`):
   ```yaml
   apiVersion: vmconfig/v1
   kind: ClusterConfig
   metadata:
     name: my-cluster
   spec:
     defaults:
       hypervisor:
         type: hyperv
         connection:
           host: hyperv.example.com
   ```

3. **Create VM configs** for each node:
   ```bash
   # Copy examples and customize
   cp vm-configs/clusters/cotpa/cotpa-ctrl01.yaml \
      vm-configs/clusters/my-cluster/my-cluster-ctrl01.yaml
   ```

4. **Create RKE2 node configs** (rkeprep format):
   ```bash
   cp configs/examples/server-example.yaml \
      vm-configs/clusters/my-cluster/rke2-configs/my-cluster-ctrl01.yaml
   ```

5. **Validate locally**:
   ```bash
   python3 scripts/vm-config/config_validator.py \
     vm-configs/clusters/my-cluster/ --all
   ```

6. **Commit and push**:
   ```bash
   git checkout -b add-my-cluster
   git add vm-configs/clusters/my-cluster/
   git commit -m "Add my-cluster VM configurations"
   git push origin add-my-cluster
   ```

7. **Create PR** - validation workflow runs automatically

8. **Merge PR** - VMs are created/updated automatically

## VM Lifecycle

### Creation

When a new VM config is committed:

1. GitHub Actions detects new config file
2. Validates configuration
3. Connects to hypervisor via API
4. Clones VM from template
5. Sets VM resources (CPU, memory, network)
6. Injects KVP data (VM name, cluster, role, config path)
7. Starts VM (if `autoStart: true`)
8. VM boots and rke2-boot.service triggers
9. Boot script reads VM name from KVP
10. Searches for matching config file
11. Copies config to `/root/server-config/`
12. Executes `rke2nodeinit.sh` with config
13. RKE2 cluster node is configured automatically

### Updates

When an existing VM config is modified:

1. GitHub Actions detects changed config
2. Validates new configuration
3. Applies changes to existing VM
4. Updates KVP data if changed
5. VM can be rebooted to apply changes

### Deletion

To remove a VM:

1. Delete config file from repository
2. Commit and push
3. Manual cleanup required (safety measure)
4. Or implement `onDelete` operations for automation

## Validation

### Local Validation

Validate before committing:

```bash
# Single file
python3 scripts/vm-config/config_validator.py vm-configs/clusters/cotpa/cotpa-ctrl01.yaml

# All configs in directory
python3 scripts/vm-config/config_validator.py vm-configs/ --all

# Strict mode (warnings as errors)
python3 scripts/vm-config/config_validator.py vm-configs/ --all --strict

# JSON output for tooling
python3 scripts/vm-config/config_validator.py vm-configs/ --all --json
```

### Validation Checks

- **Schema Compliance**: apiVersion, kind, required fields
- **Naming Conventions**: DNS-compatible hostnames
- **Resource Requirements**: Minimum CPU/memory for role
- **Consistency**: VM name matches filename and KVP data
- **Conflicts**: No duplicate VM names across cluster

## Dry-Run Testing

Test configuration application without making changes:

```bash
# Single config
python3 scripts/vm-config/apply_vm_config.py \
  vm-configs/clusters/cotpa/cotpa-ctrl01.yaml --dry-run

# All configs in directory
python3 scripts/vm-config/apply_vm_config.py \
  vm-configs/clusters/cotpa/ --all --dry-run
```

## Troubleshooting

### Validation Failures

**Error**: `Schema validation failed: 'name' is a required property`

**Solution**: Add `metadata.name` field to configuration

**Error**: `VM name contains invalid characters`

**Solution**: Use only lowercase letters, numbers, and hyphens (DNS-compatible)

### Application Failures

**Error**: `Failed to connect to Hyper-V host`

**Solution**: 
- Verify self-hosted runner has network access
- Check GitHub secrets are configured correctly
- Ensure WinRM is enabled on Hyper-V host

**Error**: `Template VM not found`

**Solution**:
- Verify template VM exists on hypervisor
- Check `vmSettings.templateName` matches actual VM name
- Ensure template VM is powered off

### Boot Service Issues

**Error**: Boot script can't find config file

**Solution**:
- Verify KVP data was set correctly: `pwsh -c "Get-VMKeyValuePairItem -VMName <vm>"`
- Check config file exists in search paths
- Ensure filename matches VM hostname pattern

## Best Practices

### Naming Conventions

- **Control Plane**: `<cluster>-ctrl<NN>` (e.g., `cotpa-ctrl01`)
- **Workers**: `<cluster>-worker<NN>` (e.g., `cotpa-worker01`)
- **Filenames**: Must match `metadata.name` (e.g., `cotpa-ctrl01.yaml`)

### Resource Sizing

Minimum requirements:

- **Server nodes**: 2 CPUs, 4GB RAM
- **Agent nodes**: 2 CPUs, 2GB RAM
- **Production**: Use cluster defaults, override per node as needed

### Security

- **Credentials**: Never commit passwords - use GitHub secrets
- **KVP Data**: Avoid sensitive data in guestVariables
- **Templates**: Keep templates up-to-date with security patches

### Change Management

- **Small PRs**: One cluster or small set of VMs per PR
- **Descriptive Commits**: Explain why changes are needed
- **Dry-Run First**: Test with dry-run before production apply
- **Gradual Rollout**: Update one node at a time for production clusters

## Architecture

```
┌─────────────────┐
│  Git Repository │
│   (vm-configs)  │
└────────┬────────┘
         │ commit/push
         ▼
┌─────────────────┐
│ GitHub Actions  │
│   Workflows     │
├─────────────────┤
│ • Validation    │
│ • Application   │
└────────┬────────┘
         │ WinRM/API
         ▼
┌─────────────────┐      ┌──────────────┐
│   Hypervisor    │─────▶│  Template VM │
│  (Hyper-V/...)  │      │  (prepared)  │
└────────┬────────┘      └──────────────┘
         │ clone + KVP
         ▼
┌─────────────────┐
│    Guest VM     │
│ ┌─────────────┐ │
│ │ rke2-boot   │ │ 1. Read KVP
│ │   service   │ │ 2. Find config
│ └──────┬──────┘ │ 3. Copy config
│        │        │ 4. Execute rke2nodeinit.sh
│        ▼        │
│ ┌─────────────┐ │
│ │ rke2nodeinit│ │ 5. Configure node
│ │    .sh      │ │ 6. Join cluster
│ └─────────────┘ │
└─────────────────┘
```

## Future Enhancements

- [ ] VMware vSphere support via pyvmomi
- [ ] Proxmox support via API
- [ ] VM deletion automation (with safety checks)
- [ ] Multi-stage rollouts (canary, blue-green)
- [ ] Integration with external IPAM systems
- [ ] Terraform provider for vm-configs
- [ ] Web UI for configuration management
- [ ] Cost estimation and optimization

## Support

For issues or questions:

1. Check validation workflow logs in GitHub Actions
2. Review application workflow artifacts
3. Check rke2-boot.service logs: `journalctl -u rke2-boot`
4. Review boot script logs: `/var/log/rke2-boot.log`
5. Open GitHub issue with logs and config

## Related Documentation

- [Boot Service Setup](../docs/HYPERV-VM-NAME-SETUP.md)
- [RKE2 Configuration Examples](../configs/examples/)
- [Main README](../README.md)
- [Contributing Guide](../CONTRIBUTING.md)
