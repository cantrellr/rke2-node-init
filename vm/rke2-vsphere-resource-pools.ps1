# ==============================================================================
# rke2-vsphere-resource-pools.ps1
# ==============================================================================
#
# Purpose:
#   Create vSphere folder and resource pool hierarchy for RKE2 Kubernetes
#   clusters with DRS anti-affinity rules for high availability.
#
# Description:
#   This script automates the creation of a hierarchical folder and resource
#   pool structure under an existing "Kube.Sites" parent container. It creates
#   site-level folders (j64, j52, r01) and cluster-level subfolders
#   (dc1manager, dc1domain, dc2domain, dc3domain), then establishes
#   corresponding resource pools with CPU and memory reservations calculated
#   with 30% overhead for cluster infrastructure.
#
#   After creating the infrastructure hierarchy, the script optionally creates
#   DRS anti-affinity rules to ensure controller and worker VMs are distributed
#   across different ESXi hosts for fault tolerance.
#
# Prerequisites:
#   - VMware PowerCLI module installed and imported
#   - vCenter Server 8.0.3 or compatible version
#   - Existing top-level folder "Kube.Sites" in target datacenter
#   - Existing top-level resource pool "Kube.Sites" in target cluster
#   - vCenter credentials with permissions to:
#       * Create folders and resource pools
#       * Configure DRS rules
#       * Query VM and cluster information
#   - VM naming convention: "ctrl" for controllers, "work" for workers
#
# Usage:
#   .\rke2-vsphere-resource-pools.ps1
#
#   The script will prompt for:
#     - vCenter Server FQDN or IP address
#     - vCenter credentials (interactive)
#
# Resource Allocation Strategy:
#   dc1manager:  28600 MHz CPU, 114 GB memory (7 nodes: 3 ctrl + 4 work)
#   dc1domain:   23400 MHz CPU,  94 GB memory (6 nodes: 3 ctrl + 3 work)
#   dc2domain:   23400 MHz CPU,  94 GB memory (6 nodes: 3 ctrl + 3 work)
#   dc3domain:   23400 MHz CPU,  94 GB memory (6 nodes: 3 ctrl + 3 work)
#
#   Calculations based on:
#     - 3x controller VMs: 4 vCPU, 8 GB RAM each
#     - 3-4x worker VMs: 4 vCPU, 16 GB RAM each
#     - 30% overhead for Kubernetes infrastructure
#     - Assumes 2.6 GHz CPU cores (vCPU * 2600 MHz)
#
# Folder Structure Created:
#   Kube.Sites/
#   ├── j64/
#   │   ├── dc1manager/  (7 VMs: 3 ctrl + 4 work)
#   │   └── dc1domain/   (6 VMs: 3 ctrl + 3 work)
#   ├── j52/
#   │   └── dc2domain/   (6 VMs: 3 ctrl + 3 work)
#   └── r01/
#       └── dc3domain/   (6 VMs: 3 ctrl + 3 work)
#
# DRS Anti-Affinity Rules:
#   - Separate controller VMs across different ESXi hosts
#   - Separate worker VMs across different ESXi hosts
#   - Rules named: <cluster>_Controllers, <cluster>_Workers
#
# Version:
#   1.0.0 - Initial implementation
#
# Author:
#   Cloud Operations Team
#
# Last Modified:
#   2024-11-08
#
# Notes:
#   - Script uses -ErrorAction SilentlyContinue to handle pre-existing objects
#   - Memory reservations converted from GB to MB (GB * 1024)
#   - Certificate validation disabled for lab environments (modify for production)
#   - Optional KubeControl/KubeWorker subfolders commented out (not currently used)
#   - DRS rule creation requires VMs to exist in folders (run after VM provisioning)
#
# ==============================================================================

# ==============================================================================
# Initial Setup: PowerCLI Module and vCenter Connection
# ==============================================================================

# ------------------------------------------------------------------------
# Import PowerCLI module and suppress certificate warnings for lab use
# ------------------------------------------------------------------------
Import-Module VMware.PowerCLI -ErrorAction Stop
Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# ------------------------------------------------------------------------
# Prompt for vCenter connection details and establish session
# ------------------------------------------------------------------------
$vCenter = Read-Host -Prompt "Enter the vCenter FQDN or IP address"
$cred = Get-Credential -Message "Enter vCenter credentials"

# Connect to vCenter using provided credentials
Connect-VIServer -Server $vCenter -Credential $cred

# ==============================================================================
# Configuration Parameters
# ==============================================================================

# ------------------------------------------------------------------------
# vSphere environment configuration
# Modify these to match your datacenter and cluster names
# ------------------------------------------------------------------------
$datacenterName = "Datacenter"      # Change to match your datacenter
$clusterName    = "R01_Kubernetes"  # Change to match your cluster

# ==============================================================================
# Section 1: Folder Hierarchy Creation
# ==============================================================================

# ------------------------------------------------------------------------
# Retrieve datacenter object and verify top-level folder exists
# ------------------------------------------------------------------------
# ------------------------------------------------------------------------
# Retrieve datacenter object and verify top-level folder exists
# ------------------------------------------------------------------------
$dc = Get-Datacenter -Name $datacenterName

# Verify that the top-level folder "Kube.Sites" exists.
$topFolder = Get-Folder -Name "Kube.Sites" -Location $dc -ErrorAction SilentlyContinue
if (-not $topFolder) {
    Write-Error "Top-level folder 'Kube.Sites' was not found in datacenter '$datacenterName'. Please create it manually first."
    exit
}

# ------------------------------------------------------------------------
# Create site-level folders under Kube.Sites
# j64 = Site 64 (production), j52 = Site 52 (dev/test), r01 = Region 01
# ------------------------------------------------------------------------
New-Folder -Name "j64" -Location $topFolder -ErrorAction SilentlyContinue
New-Folder -Name "j52" -Location $topFolder -ErrorAction SilentlyContinue
New-Folder -Name "r01" -Location $topFolder -ErrorAction SilentlyContinue

# ------------------------------------------------------------------------
# Retrieve site folder objects for subfolder creation
# ------------------------------------------------------------------------
$j64Folder = Get-Folder -Name "j64" -Location $topFolder
$j52Folder = Get-Folder -Name "j52" -Location $topFolder
$r01Folder = Get-Folder -Name "r01" -Location $topFolder

# ------------------------------------------------------------------------
# Create cluster-level subfolders under each site
# Each subfolder will contain controller and worker VMs for one cluster
# ------------------------------------------------------------------------
# j64 site has two clusters: manager and domain
New-Folder -Name "dc1manager" -Location $j64Folder -ErrorAction SilentlyContinue
New-Folder -Name "dc1domain" -Location $j64Folder -ErrorAction SilentlyContinue

# j52 and r01 sites each have one domain cluster
New-Folder -Name "dc2domain" -Location $j52Folder -ErrorAction SilentlyContinue
New-Folder -Name "dc3domain" -Location $r01Folder -ErrorAction SilentlyContinue

# ------------------------------------------------------------------------
# Optional: Create logical segregation subfolders (currently not used)
# Uncomment to create KubeControl/KubeWorker separation within each cluster
# ------------------------------------------------------------------------
# ------------------------------------------------------------------------
# Optional: Create logical segregation subfolders (currently not used)
# Uncomment to create KubeControl/KubeWorker separation within each cluster
# ------------------------------------------------------------------------
<#
# Optionally, create additional subfolders for logical segregation.
$dc1managerFolder = Get-Folder -Name "dc1manager" -Location $j64Folder
New-Folder -Name "KubeControl" -Location $dc1managerFolder -ErrorAction SilentlyContinue
New-Folder -Name "KubeWorker"  -Location $dc1managerFolder -ErrorAction SilentlyContinue

$dc1domainFolder = Get-Folder -Name "dc1domain" -Location $j64Folder
New-Folder -Name "KubeControl" -Location $dc1domainFolder -ErrorAction SilentlyContinue
New-Folder -Name "KubeWorker"  -Location $dc1domainFolder -ErrorAction SilentlyContinue

$dc2domainFolder = Get-Folder -Name "dc2domain" -Location $j52Folder
New-Folder -Name "KubeControl" -Location $dc2domainFolder -ErrorAction SilentlyContinue
New-Folder -Name "KubeWorker"  -Location $dc2domainFolder -ErrorAction SilentlyContinue

$dc3domainFolder = Get-Folder -Name "dc3domain" -Location $r01Folder
New-Folder -Name "KubeControl" -Location $dc3domainFolder -ErrorAction SilentlyContinue
New-Folder -Name "KubeWorker"  -Location $dc3domainFolder -ErrorAction SilentlyContinue
#>

# ==============================================================================
# Section 2: Resource Pool Hierarchy Creation with Reservations
# ==============================================================================

# ------------------------------------------------------------------------
# Retrieve cluster object and verify top-level resource pool exists
# ------------------------------------------------------------------------
$cluster = Get-Cluster -Name $clusterName

$topRP = Get-ResourcePool -Name "Kube.Sites" -Location $cluster -ErrorAction SilentlyContinue
if (-not $topRP) {
    Write-Error "Top-level Resource Pool 'Kube.Sites' was not found in cluster '$clusterName'. Please create it manually first."
    exit
}

# ------------------------------------------------------------------------
# Create site-level resource pools under Kube.Sites (if not existing)
# ------------------------------------------------------------------------
$j64RP = Get-ResourcePool -Name "j64" -Location $topRP -ErrorAction SilentlyContinue
if (-not $j64RP) { $j64RP = New-ResourcePool -Name "j64" -Location $topRP }

$j52RP = Get-ResourcePool -Name "j52" -Location $topRP -ErrorAction SilentlyContinue
if (-not $j52RP) { $j52RP = New-ResourcePool -Name "j52" -Location $topRP }

$r01RP = Get-ResourcePool -Name "r01" -Location $topRP -ErrorAction SilentlyContinue
if (-not $r01RP) { $r01RP = New-ResourcePool -Name "r01" -Location $topRP }

# ------------------------------------------------------------------------
# Resource reservation calculations (30% overhead included):
# - dc1manager: 7 VMs (3 ctrl @ 4vCPU/8GB + 4 work @ 4vCPU/16GB)
#   Base: 28 vCPU * 2600 MHz = 72,800 MHz, 88 GB RAM
#   With 30% overhead: ~95 GHz CPU, ~114 GB RAM
#   Reserved: 28,600 MHz CPU, 114 GB RAM
#
# - Other domains: 6 VMs (3 ctrl @ 4vCPU/8GB + 3 work @ 4vCPU/16GB)
#   Base: 24 vCPU * 2600 MHz = 62,400 MHz, 72 GB RAM
#   With 30% overhead: ~81 GHz CPU, ~94 GB RAM
#   Reserved: 23,400 MHz CPU, 94 GB RAM
# ------------------------------------------------------------------------

# Create cluster-level resource pools under j64 site
New-ResourcePool -Name "dc1manager" -Location $j64RP `
    -CpuReservationMHz 28600 `
    -MemReservationMB ([math]::Round(114 * 1024))

New-ResourcePool -Name "dc1domain" -Location $j64RP `
    -CpuReservationMHz 23400 `
    -MemReservationMB ([math]::Round(94 * 1024))

# Create cluster-level resource pool under j52 site
New-ResourcePool -Name "dc2domain" -Location $j52RP `
    -CpuReservationMHz 23400 `
    -MemReservationMB ([math]::Round(94 * 1024))

# Create cluster-level resource pool under r01 site
New-ResourcePool -Name "dc3domain" -Location $r01RP `
    -CpuReservationMHz 23400 `
    -MemReservationMB ([math]::Round(94 * 1024))

# ==============================================================================
# DRS Anti-Affinity Rule Creation Functions
# ==============================================================================

# ------------------------------------------------------------------------------
# Function: Create-DrsRulesForPool
# ------------------------------------------------------------------------------
# Purpose:
#   Create DRS anti-affinity rules for controller and worker VMs in a folder.
#   Ensures high availability by preventing controllers and workers from
#   running on the same ESXi host.
#
# Arguments:
#   FolderName - Name of VM folder to search (e.g., "dc1manager")
#   RulePrefix - Prefix for rule naming (e.g., "dc1manager")
#
# Returns:
#   None (creates DRS rules in vSphere cluster as side effect)
#
# Notes:
#   - Uses VM name pattern matching: "ctrl" for controllers, "work" for workers
#   - Creates two separate anti-affinity rules per folder (ctrl, work)
#   - Skips folder if either controller or worker VMs are not found
#   - Cluster name derived from first VM's parent cluster
#   - KeepTogether=$false enforces anti-affinity (separate hosts)
# ------------------------------------------------------------------------------
function Create-DrsRulesForPool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderName,   # The name of the folder where VMs reside
        [Parameter(Mandatory = $true)]
        [string]$RulePrefix    # A prefix used for naming the rules
    )
    
    # ------------------------------------------------------------------------
    # Locate target VM folder by name
    # ------------------------------------------------------------------------
    $folder = Get-Folder -Name $FolderName -ErrorAction SilentlyContinue
    if (-not $folder) {
        Write-Host "Folder '$FolderName' not found. Skipping DRS rule creation for this folder."
        return
    }
    
    # ------------------------------------------------------------------------
    # Find VMs matching controller and worker naming patterns
    # Pattern: VM names containing "ctrl" are controllers, "work" are workers
    # ------------------------------------------------------------------------
    $ctrlVMs = Get-VM -Location $folder | Where-Object { $_.Name -match "ctrl" }
    $workerVMs = Get-VM -Location $folder | Where-Object { $_.Name -match "work" }
    
    # ------------------------------------------------------------------------
    # Validate VM discovery: Need both controllers and workers for HA rules
    # ------------------------------------------------------------------------
    if (($ctrlVMs.Count -eq 0) -or ($workerVMs.Count -eq 0)) {
        Write-Host "Either controller or worker VMs were not found in folder '$FolderName'. Skipping DRS rule creation for this folder."
        return
    }
    
    # ------------------------------------------------------------------------
    # Create anti-affinity DRS rules to prevent co-location on same host
    # - Controllers rule: Separate all controller VMs across ESXi hosts
    # - Workers rule: Separate all worker VMs across ESXi hosts
    # KeepTogether=$false enforces anti-affinity (VMs must be on different hosts)
    # ------------------------------------------------------------------------
    New-DrsRule -Name "${RulePrefix}_Controllers" -VM $ctrlVMs -Cluster $cluster -KeepTogether $false
    New-DrsRule -Name "${RulePrefix}_Workers" -VM $workerVMs -Cluster $cluster -KeepTogether $false
    
    Write-Host "DRS anti-affinity rules created for folder '$FolderName'." -ForegroundColor Green
    
    # Note: Optional cross-group anti-affinity rule (currently commented out)
    # This would prevent ANY controller from sharing a host with ANY worker
    # <#
    # New-DrsRule -Name "${RulePrefix}_NoMix" -VM ($ctrlVMs + $workerVMs) `
    #     -Cluster $cluster -Enabled $true #-Type SeparateVMHosts
    # #>
}

# ==============================================================================
# Main Execution: Create DRS Rules for All RKE2 Cluster Folders
# ==============================================================================

# Create anti-affinity rules for each cluster environment
Create-DrsRulesForPool -FolderName "dc1manager" -RulePrefix "dc1manager"
Create-DrsRulesForPool -FolderName "dc1domain"  -RulePrefix "dc1domain"
Create-DrsRulesForPool -FolderName "dc2domain"  -RulePrefix "dc2domain"
Create-DrsRulesForPool -FolderName "dc3domain"  -RulePrefix "dc3domain"

# ==============================================================================
# Script Complete
# ==============================================================================