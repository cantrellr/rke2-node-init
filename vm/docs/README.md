# RKE2 VM Provisioning Toolkit

This directory contains PowerShell automation scripts for provisioning and managing VMware vSphere VMs for RKE2 Kubernetes clusters. The toolkit provides end-to-end VM lifecycle management from initial creation to DRS rule configuration.

---

## Table of Contents

- [Overview](#overview)
- [Scripts](#scripts)
  - [New-VmsFromCsv.ps1](#new-vmsfromcsvps1)
  - [Clone-VmsFromCsv.ps1](#clone-vmsfromcsvps1)
  - [rke2-vsphere-resource-pools.ps1](#rke2-vsphere-resource-poolsps1)
- [CSV Templates](#csv-templates)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Usage Examples](#usage-examples)
- [DRS Anti-Affinity Rules](#drs-anti-affinity-rules)
- [Troubleshooting](#troubleshooting)

---

## Overview

The VM provisioning toolkit automates the creation and configuration of vSphere VMs for RKE2 clusters with a focus on:

- **Infrastructure as Code**: CSV-driven VM definitions for repeatability
- **High Availability**: Automatic DRS anti-affinity rules for controller/worker separation
- **Intelligent Placement**: CPU-based host selection for load distribution
- **Flexibility**: Support for both template-based and scratch VM creation
- **Idempotency**: Skip existing VMs to support incremental deployments

The toolkit follows a three-phase workflow:
1. **Hierarchy Creation**: Establish folder and resource pool structure
2. **VM Provisioning**: Create or clone VMs from CSV definitions
3. **HA Configuration**: Apply DRS rules for fault tolerance

---

## Scripts

### New-VmsFromCsv.ps1

**Purpose**: Create new VMs from scratch or from templates based on CSV definitions.

**Key Features**:
- Create VMs from templates or build from scratch
- Configure CPU, memory, and disk resources
- Assign to specific clusters, resource pools, and folders
- Apply OS customization specifications
- Set CPU and memory reservations for resource guarantees
- Idempotent operation with `-SkipExisting`

**Usage**:
```powershell
$cred = Get-Credential
.\New-VmsFromCsv.ps1 -CsvPath .\new-vms-from-csv-template.csv `
                     -VCenter vcsa.lab.local `
                     -Credential $cred
```

**CSV Columns**:
- **Required**: `VMName`
- **Optional**: `Cluster`, `Datastore`, `Network`, `CpuCount`, `MemoryGB`, `DiskGB`, `Template`, `Folder`, `ResourcePool`, `GuestId`, `OSCustomizationSpec`, `CpuReservationMHz`, `MemoryReservationGB`

---

### Clone-VmsFromCsv.ps1

**Purpose**: Clone VMs from existing templates or powered-off source VMs with advanced placement and configuration options.

**Key Features**:
- Clone from templates or powered-off VMs
- Intelligent ESXi host selection based on CPU utilization
- Post-clone CPU, memory, and disk resizing
- Network adapter reconfiguration
- Per-VM or global PowerOn control
- Automatic DRS anti-affinity rule creation for controller/worker separation
- Support for OS customization specifications

**Usage**:
```powershell
$cred = Get-Credential
.\Clone-VmsFromCsv.ps1 -CsvPath .\clone-vms-from-csv-template.csv `
                       -VCenter vcsa.lab.local `
                       -Credential $cred `
                       -PowerOn
```

**CSV Columns**:
- **Required**: `VMName`, `SourceVM`
- **Optional**: `Cluster`, `VMHost`, `ResourcePool`, `Datastore`, `Folder`, `Network`, `CpuCount`, `MemoryGB`, `DiskGB`, `OSCustomizationSpec`, `PowerOn`

**DRS Anti-Affinity Rules**: Automatically creates rules for these folders:
- `dc1manager`
- `dc1domain`
- `dc2domain`
- `dc3domain`

---

### rke2-vsphere-resource-pools.ps1

**Purpose**: Create vSphere folder and resource pool hierarchy for RKE2 clusters with DRS anti-affinity rules.

**Key Features**:
- Creates hierarchical folder structure under `Kube.Sites`
- Establishes resource pools with CPU and memory reservations
- Configures DRS anti-affinity rules for high availability
- Supports multiple site and cluster configurations

**Folder Structure Created**:
```
Kube.Sites/
├── j64/
│   ├── dc1manager/ (7 VMs: 3 ctrl + 4 work)
│   └── dc1domain/  (6 VMs: 3 ctrl + 3 work)
├── j52/
│   └── dc2domain/  (6 VMs: 3 ctrl + 3 work)
└── r01/
    └── dc3domain/  (6 VMs: 3 ctrl + 3 work)
```

**Resource Allocations** (30% overhead included):
- **dc1manager**: 28,600 MHz CPU, 114 GB RAM
- **Other domains**: 23,400 MHz CPU, 94 GB RAM

**Usage**:
```powershell
.\rke2-vsphere-resource-pools.ps1
# Script will prompt for vCenter FQDN and credentials
```

---

## CSV Templates

The `vm/` directory includes several CSV templates:

| Template | Purpose |
|----------|---------|
| `new-vms-from-csv-template.csv` | Template for creating new VMs from scratch |
| `clone-vms-from-csv-template.csv` | Template for cloning VMs from templates |
| `clone-rkeimage-matrix.csv` | Example matrix for bulk RKE2 node cloning |
| `new-vm-template.csv` | Alternative template format for VM creation |

**CSV Best Practices**:
- Use descriptive VM names that include node type (ctrl/work)
- Keep cluster/site naming consistent for DRS rule matching
- Specify resource pools to ensure proper capacity allocation
- Include network names to avoid default network assignment

---

## Prerequisites

### Software Requirements
- **VMware PowerCLI**: Module must be installed
  ```powershell
  Install-Module -Name VMware.PowerCLI -Scope CurrentUser
  ```
- **vCenter Server**: 8.0.3 or later (tested)
- **PowerShell**: 5.1 or later (Windows PowerShell or PowerShell Core)

### vSphere Infrastructure
- vSphere cluster with DRS enabled (for anti-affinity rules)
- Existing top-level folder: `Kube.Sites`
- Existing top-level resource pool: `Kube.Sites`
- Source templates or VMs for cloning
- Available datastores with sufficient capacity

### Permissions Required
- Create and modify VMs
- Create and modify folders
- Create and modify resource pools
- Configure DRS rules
- Assign VMs to networks and resource pools

---

## Quick Start

### 1. Create Infrastructure Hierarchy
```powershell
# Run the resource pool script first to establish folder/pool structure
.\rke2-vsphere-resource-pools.ps1
```

### 2. Provision VMs
```powershell
# Clone VMs from a template
$cred = Get-Credential
.\Clone-VmsFromCsv.ps1 -CsvPath .\clone-rkeimage-matrix.csv `
                       -VCenter vcsa.lab.local `
                       -Credential $cred `
                       -PowerOn
```

### 3. Verify DRS Rules
```powershell
# Check that anti-affinity rules were created
Get-DrsRule -Cluster "R01_Kubernetes" | Where-Object { $_.Name -match "j64|j52|r01" }
```

---

## Architecture

### VM Naming Convention
Scripts use pattern matching to identify VM roles:
- **Controllers**: VM name contains `ctrl` (e.g., `dc1manager-ctrl01`)
- **Workers**: VM name contains `work` (e.g., `dc1manager-work01`)

### Resource Pool Strategy
Resource pools are calculated with 30% overhead for Kubernetes infrastructure:

**Calculation Example (dc1manager)**:
- Base: 7 VMs (3 ctrl @ 4vCPU/8GB + 4 work @ 4vCPU/16GB)
- vCPU total: 28 vCPU × 2,600 MHz = 72,800 MHz
- Memory total: (3 × 8) + (4 × 16) = 88 GB
- With 30% overhead: ~95 GHz CPU, ~114 GB RAM
- Reserved: 28,600 MHz CPU, 114 GB RAM

### Intelligent Host Placement
`Clone-VmsFromCsv.ps1` automatically selects the least-utilized ESXi host by sorting hosts by CPU usage (ascending) and selecting the first available host.

---

## Usage Examples

### Example 1: Clone RKE2 cluster nodes
```powershell
# Create CSV with cluster definitions
$csv = @"
VMName,SourceVM,Cluster,Folder,Network,CpuCount,MemoryGB,DiskGB
dc1manager-ctrl01,rke2-ubuntu-template,R01_Kubernetes,dc1manager,VM Network,4,8,60
dc1manager-ctrl02,rke2-ubuntu-template,R01_Kubernetes,dc1manager,VM Network,4,8,60
dc1manager-work01,rke2-ubuntu-template,R01_Kubernetes,dc1manager,VM Network,4,16,100
"@ | Out-File -FilePath cluster.csv -Encoding UTF8

# Clone and power on
$cred = Get-Credential
.\Clone-VmsFromCsv.ps1 -CsvPath cluster.csv `
                       -VCenter vcsa.lab.local `
                       -Credential $cred `
                       -PowerOn
```

### Example 2: Create VMs from scratch with reservations
```powershell
$csv = @"
VMName,Cluster,Datastore,Network,CpuCount,MemoryGB,DiskGB,CpuReservationMHz,MemoryReservationGB
test-ctrl01,R01_Kubernetes,datastore1,VM Network,4,8,60,10400,8
test-work01,R01_Kubernetes,datastore1,VM Network,4,16,100,10400,16
"@ | Out-File -FilePath newvms.csv -Encoding UTF8

$cred = Get-Credential
.\New-VmsFromCsv.ps1 -CsvPath newvms.csv `
                     -VCenter vcsa.lab.local `
                     -Credential $cred
```

### Example 3: Skip existing VMs (idempotent deployment)
```powershell
.\Clone-VmsFromCsv.ps1 -CsvPath cluster.csv `
                       -VCenter vcsa.lab.local `
                       -Credential $cred `
                       -SkipExisting `
                       -PowerOn
```

### Example 4: Test with WhatIf (dry run)
```powershell
.\Clone-VmsFromCsv.ps1 -CsvPath cluster.csv `
                       -VCenter vcsa.lab.local `
                       -Credential $cred `
                       -WhatIf
```

---

## DRS Anti-Affinity Rules

### Overview
DRS (Distributed Resource Scheduler) anti-affinity rules ensure high availability by preventing VMs from running on the same ESXi host.

### Rule Naming Convention
- **Controllers**: `<cluster>_Controllers` (e.g., `dc1manager_Controllers`)
- **Workers**: `<cluster>_Workers` (e.g., `dc1manager_Workers`)

### How It Works
1. Scripts scan designated folders for VMs
2. Pattern match on VM names (`ctrl` or `work`)
3. Create two anti-affinity rules per cluster:
   - One for all controller VMs
   - One for all worker VMs
4. Rules use `KeepTogether=$false` to enforce separation

### Supported Clusters
- `dc1manager`
- `dc1domain`
- `dc2domain`
- `dc3domain`

### Manual Rule Verification
```powershell
# List all DRS rules
Get-DrsRule -Cluster "R01_Kubernetes"

# Check specific rule details
Get-DrsRule -Name "dc1manager_Controllers" -Cluster "R01_Kubernetes" | Format-List

# Verify VMs in a rule
(Get-DrsRule -Name "dc1manager_Controllers" -Cluster "R01_Kubernetes").VM
```

---

## Troubleshooting

### Common Issues

#### Issue: "CSV file not found"
**Solution**: Verify the CSV path is correct and use absolute paths if needed.

#### Issue: "VM already exists" error
**Solution**: Use `-SkipExisting` switch to skip existing VMs.

#### Issue: PowerCLI certificate warnings
**Workaround**: Scripts automatically set `InvalidCertificateAction Ignore` for lab environments. For production, configure proper certificates.

#### Issue: DRS rules not created
**Causes**:
- VMs not in expected folders
- VM names don't match pattern (`ctrl` or `work`)
- Cluster doesn't have DRS enabled
- Insufficient permissions

**Solution**: 
```powershell
# Verify VM folder location
Get-VM -Name "dc1manager-ctrl01" | Select-Object Name, Folder

# Check DRS is enabled
Get-Cluster -Name "R01_Kubernetes" | Select-Object Name, DrsEnabled

# Verify permissions
Get-VIPermission -Entity (Get-Cluster "R01_Kubernetes")
```

#### Issue: "Folder not found" during DRS rule creation
**Solution**: Run `rke2-vsphere-resource-pools.ps1` first to create folder structure.

#### Issue: Insufficient resources for VM creation
**Solution**: Check resource pool reservations and cluster capacity:
```powershell
Get-ResourcePool | Select-Object Name, CpuReservationMHz, MemReservationMB
Get-Cluster | Select-Object Name, @{N="CPU(MHz)";E={$_.ExtensionData.Summary.EffectiveCpu}}, @{N="Memory(GB)";E={[math]::Round($_.ExtensionData.Summary.EffectiveMemory/1024,2)}}
```

### Logging
All scripts output detailed progress to the console with color-coded messages:
- **Cyan**: Informational messages
- **Green**: Success messages
- **Yellow**: Warnings
- **Red**: Errors

### Getting Help
```powershell
Get-Help .\Clone-VmsFromCsv.ps1 -Detailed
Get-Help .\New-VmsFromCsv.ps1 -Examples
```

---

## Additional Resources

- [VMware PowerCLI Documentation](https://developer.vmware.com/powercli)
- [RKE2 Documentation](https://docs.rke2.io/)
- [vSphere DRS Documentation](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-resource-management/GUID-8ACF3502-5314-469F-8CC9-4A9BD5925BC2.html)

---

**Last Updated**: November 8, 2025  
**Maintainer**: Cloud Operations Team
