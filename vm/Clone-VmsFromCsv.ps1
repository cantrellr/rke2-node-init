<#
# ==============================================================================
# Clone-VmsFromCsv.ps1
# ==============================================================================
#
#       Version: 1.0
#       Written by: Ron Cantrell
#           Github: cantrellr
#            Email: charlescantrelljr@outlook.com
#
# ==============================================================================
# Purpose:
#   Clone VMware vSphere VMs from existing templates or powered-off source VMs
#   using CSV-driven definitions. Automates mass VM provisioning for RKE2
#   Kubernetes clusters with intelligent host placement, resource configuration,
#   and DRS anti-affinity rule creation for high availability.
#
# Features:
#   - Clone from templates or powered-off VMs
#   - Intelligent ESXi host selection based on CPU utilization
#   - Post-clone CPU, memory, and disk resizing
#   - Network adapter reconfiguration
#   - Per-VM or global PowerOn control
#   - Automatic DRS anti-affinity rule creation for controller/worker separation
#   - Support for OS customization specifications
#   - Idempotent operation with -SkipExisting
#
# Requirements:
#   - VMware PowerCLI module
#   - vCenter Server 8.0.3 or later (tested)
#   - vSphere cluster with DRS enabled (for anti-affinity rules)
#   - Source template or powered-off VM
#   - Appropriate vCenter permissions (VM creation, DRS rule management)
#
# CSV Schema:
#   Required columns:
#     VMName    - Unique name for the cloned VM
#     SourceVM  - Name of template or powered-off VM to clone from
#
#   Optional columns:
#     Cluster             - Target cluster (used for host selection if VMHost not provided)
#     VMHost              - Specific ESXi host for VM placement
#     ResourcePool        - Resource pool assignment
#     Datastore           - Datastore for clone storage
#     Folder              - vCenter folder for organization
#     Network             - Port group for primary NIC
#     CpuCount            - Override vCPU count (must be valid for guest OS)
#     MemoryGB            - Override memory size in GB
#     DiskGB              - Resize primary disk (must be >= source disk size)
#     OSCustomizationSpec - Customization spec for guest OS
#     PowerOn             - TRUE/FALSE to override global -PowerOn switch
#
# DRS Anti-Affinity Rules:
#   The script automatically creates DRS anti-affinity rules to separate
#   controller and worker VMs based on naming conventions:
#     - Controllers: VM name contains "ctrl"
#     - Workers: VM name contains "work"
#
#   Rules are created for these folders:
#     - j64manager
#     - j64domain
#     - j52domain
#     - r01domain
#
# Examples:
#   # Clone VMs and power them on
#   $cred = Get-Credential
#   .\Clone-VmsFromCsv.ps1 -CsvPath .\clone-matrix.csv `
#                          -VCenter vcsa.lab.local `
#                          -Credential $cred `
#                          -PowerOn
#
#   # Clone VMs, skip existing, and test with WhatIf
#   .\Clone-VmsFromCsv.ps1 -CsvPath .\clone-matrix.csv `
#                          -VCenter vcsa.lab.local `
#                          -Credential $cred `
#                          -SkipExisting `
#                          -WhatIf
#
# Exit Codes:
#   0 - Success
#   1 - CSV file not found
#   2 - CSV file empty or unreadable
#   3 - vCenter connection failure
#   4 - VM cloning failure (non-fatal, continues with remaining VMs)
#
# ==============================================================================
.SYNOPSIS
  Clone VMware vSphere VMs from a CSV definition using an existing source VM or template.

.DESCRIPTION
  Requires VMware PowerCLI (tested against vSphere 8.0.3). The CSV should contain one VM per row
  with the following recommended columns (case-insensitive):
    VMName              - Name for the cloned VM (required).
    SourceVM            - Name of the template or powered-off VM to clone from (required).
    Cluster             - Target cluster name (optional, used when VMHost not provided).
    VMHost              - Specific ESXi host to place the VM on (optional).
    ResourcePool        - Resource pool name (optional).
    Datastore           - Datastore name for the clone (optional if storage policies handle placement).
    Folder              - vCenter folder name (optional).
    Network             - Port group name to connect the primary NIC to (optional).
    CpuCount            - Target vCPU count (optional; defaults to source VM setting).
    MemoryGB            - Target memory size in GB (optional; defaults to source VM setting).
    DiskGB              - Desired size of the primary disk in GB (optional; must be >= source disk).
    OSCustomizationSpec - Customization spec name (optional).
    PowerOn             - True/False to power on the VM post-clone (optional; overrides -PowerOn switch).

  The script accepts global -PowerOn and -SkipExisting switches. Per-row PowerOn values override
  the global -PowerOn choice.

.PARAMETER CsvPath
  Path to the CSV file containing clone definitions. Required.

.PARAMETER VCenter
  vCenter Server FQDN or IP address. Required.

.PARAMETER Credential
  PSCredential object for vCenter authentication. Required.

.PARAMETER SkipExisting
  If specified, skip VMs that already exist instead of failing.

.PARAMETER PowerOn
  If specified, power on VMs after cloning (unless overridden per-row).

.EXAMPLE
  $cred = Get-Credential
  .\Clone-VmsFromCsv.ps1 -CsvPath .\vm-template.csv -VCenter vcsa.lab.local -Credential $cred -PowerOn
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)]
  [string]$CsvPath,

  [Parameter(Mandatory)]
  [string]$VCenter,

  [Parameter(Mandatory)]
  [pscredential]$Credential,

  [switch]$SkipExisting,

  [switch]$PowerOn
)

# ==============================================================================
# Module Initialization
# ==============================================================================
Import-Module VMware.PowerCLI -ErrorAction Stop
Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# ==============================================================================
# Input Validation
# ==============================================================================
if (-not (Test-Path -Path $CsvPath -PathType Leaf)) {
  throw "CSV file not found at $CsvPath"
}

# ==============================================================================
# vCenter Connection
# ==============================================================================
$viserver = Get-VIServer -Server $VCenter -ErrorAction SilentlyContinue
if (-not $viserver) {
  $viserver = Connect-VIServer -Server $VCenter -Credential $Credential -ErrorAction Stop
}

# ==============================================================================
# CSV Import and Validation
# ==============================================================================
$vmDefinitions = Import-Csv -Path $CsvPath
if (-not $vmDefinitions -or $vmDefinitions.Count -eq 0) {
  throw "CSV $CsvPath is empty or unreadable."
}

# ==============================================================================
# Helper Functions
# ==============================================================================

# ------------------------------------------------------------------------------
# Function: Get-StringOrNull
# Purpose : Safely extract a string value from CSV, returning null if blank or
#           whitespace-only. Trims leading/trailing whitespace.
# Arguments:
#   $Value - Raw string value from CSV column
# Returns :
#   Trimmed string or $null if blank/whitespace
# ------------------------------------------------------------------------------
function Get-StringOrNull {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value.Trim()
}

# ------------------------------------------------------------------------------
# Function: Get-IntOrNull
# Purpose : Safely parse an integer value from CSV, throwing an error if the
#           value is present but not a valid integer.
# Arguments:
#   $Value - Raw string value from CSV column
# Returns :
#   Parsed integer or $null if blank/whitespace
# Throws  :
#   Exception if value is non-empty but not a valid integer
# ------------------------------------------------------------------------------
function Get-IntOrNull {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $parsed = 0
  if ([int]::TryParse($Value, [ref]$parsed)) { return $parsed }
  throw "Value '$Value' is not a valid integer."
}

# ------------------------------------------------------------------------------
# Function: Get-BoolOrNull
# Purpose : Safely parse a boolean value from CSV, throwing an error if the
#           value is present but not a valid boolean.
# Arguments:
#   $Value - Raw string value from CSV column (e.g., "true", "false", "TRUE")
# Returns :
#   Parsed boolean or $null if blank/whitespace
# Throws  :
#   Exception if value is non-empty but not a valid boolean
# ------------------------------------------------------------------------------
function Get-BoolOrNull {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $parsed = $false
  if ([bool]::TryParse($Value, [ref]$parsed)) { return $parsed }
  throw "Value '$Value' is not a valid boolean."
}

# ------------------------------------------------------------------------------
# Function: Resolve-ResourcePool
# Purpose : Resolve a resource pool by name, or fallback to cluster's root
#           resource pool if only cluster is provided. This supports flexible
#           CSV definitions where either pool or cluster can be specified.
# Arguments:
#   $PoolName - Optional resource pool name from CSV
#   $Cluster  - Optional cluster object to resolve root pool from
# Returns :
#   Resource pool object or $null if neither can be resolved
# ------------------------------------------------------------------------------
function Resolve-ResourcePool {
  param(
    [string]$PoolName,
    [VMware.VimAutomation.ViCore.Impl.V1.Inventory.ClusterImpl]$Cluster
  )

  # Explicit resource pool name takes precedence
  if ($PoolName) {
    return Get-ResourcePool -Name $PoolName -ErrorAction Stop
  }

  # Fallback to cluster's root resource pool
  if ($Cluster -and $Cluster.ExtensionData -and $Cluster.ExtensionData.ResourcePool) {
    return Get-ResourcePool -Id $Cluster.ExtensionData.ResourcePool -ErrorAction SilentlyContinue
  }

  return $null
}

# ==============================================================================
# Main VM Cloning Loop
# ==============================================================================
foreach ($vmRow in $vmDefinitions) {
  # --------------------------------------------------------------------------
  # Extract and validate VM name (required field)
  # --------------------------------------------------------------------------
  $vmName = Get-StringOrNull $vmRow.VMName
  if (-not $vmName) {
    Write-Warning "Skipping row with blank VMName."
    continue
  }

  # --------------------------------------------------------------------------
  # Check if VM already exists (skip if -SkipExisting specified)
  # --------------------------------------------------------------------------
  if ($SkipExisting -and (Get-VM -Name $vmName -ErrorAction SilentlyContinue)) {
    Write-Host "VM '$vmName' already exists; skipping." -ForegroundColor Yellow
    continue
  }

  try {
    # ------------------------------------------------------------------------
    # Validate source VM/template (required)
    # ------------------------------------------------------------------------
    $sourceName   = Get-StringOrNull $vmRow.SourceVM
    if (-not $sourceName) { throw "SourceVM column is required for '$vmName'." }

    # ------------------------------------------------------------------------
    # Parse CSV columns for optional placement and configuration
    # ------------------------------------------------------------------------
    $clusterName  = Get-StringOrNull $vmRow.Cluster
    $hostName     = Get-StringOrNull $vmRow.VMHost
    $poolName     = Get-StringOrNull $vmRow.ResourcePool
    $datastoreName= Get-StringOrNull $vmRow.Datastore
    $folderName   = Get-StringOrNull $vmRow.Folder
    $networkName  = Get-StringOrNull $vmRow.Network
    $oscSpecName  = Get-StringOrNull $vmRow.OSCustomizationSpec

    # ------------------------------------------------------------------------
    # Parse optional resource overrides (CPU, memory, disk, PowerOn)
    # Only process these columns if they exist in the CSV
    # ------------------------------------------------------------------------
    $cpuCount     = $null
    $memoryGb     = $null
    $diskGb       = $null
    $powerOnRow   = $null

    if ($vmRow.PSObject.Properties.Name -contains 'CpuCount') { $cpuCount   = Get-IntOrNull $vmRow.CpuCount }
    if ($vmRow.PSObject.Properties.Name -contains 'MemoryGB') { $memoryGb   = Get-IntOrNull $vmRow.MemoryGB }
    if ($vmRow.PSObject.Properties.Name -contains 'DiskGB')   { $diskGb     = Get-IntOrNull $vmRow.DiskGB }
    if ($vmRow.PSObject.Properties.Name -contains 'PowerOn')  { $powerOnRow = Get-BoolOrNull $vmRow.PowerOn }

    # ------------------------------------------------------------------------
    # Resolve vCenter objects from names
    # ------------------------------------------------------------------------
    $sourceVm  = Get-VM -Name $sourceName -ErrorAction Stop
    $cluster   = if ($clusterName) { Get-Cluster -Name $clusterName -ErrorAction Stop } else { $null }
    $vmHost    = if ($hostName)    { Get-VMHost -Name $hostName -ErrorAction Stop } else { $null }
    $datastore = if ($datastoreName) { Get-Datastore -Name $datastoreName -ErrorAction Stop } else { $null }
    $folder    = if ($folderName)    { Get-Folder -Name $folderName -ErrorAction Stop } else { $null }
    $oscSpec   = if ($oscSpecName)   { Get-OSCustomizationSpec -Name $oscSpecName -ErrorAction Stop } else { $null }
    $pool      = Resolve-ResourcePool -PoolName $poolName -Cluster $cluster

    # ------------------------------------------------------------------------
    # Intelligent ESXi host selection: Pick least-utilized host from cluster
    # Sort by overall CPU usage (ascending) to distribute load evenly
    # ------------------------------------------------------------------------
    if (-not $vmHost -and $cluster) {
      $vmHost = Get-VMHost -Location $cluster | Sort-Object -Property @{Expression = 'ExtensionData.Summary.QuickStats.OverallCpuUsage'; Descending = $false} | Select-Object -First 1
    }

    # ------------------------------------------------------------------------
    # Build New-VM clone parameter hash
    # ------------------------------------------------------------------------
    $cloneParams = @{
      Name        = $vmName
      VM          = $sourceVm
      ErrorAction = 'Stop'
    }

    # Add optional parameters if resolved
    if ($vmHost)    { $cloneParams['VMHost']       = $vmHost }
    if ($pool)      { $cloneParams['ResourcePool'] = $pool }
    if ($datastore) { $cloneParams['Datastore']    = $datastore }
    if ($folder)    { $cloneParams['Location']     = $folder }
    if ($oscSpec)   { $cloneParams['OSCustomizationSpec'] = $oscSpec }

    # ------------------------------------------------------------------------
    # Clone the VM (respects -WhatIf from SupportsShouldProcess)
    # ------------------------------------------------------------------------
    if ($PSCmdlet.ShouldProcess($vmName, 'Clone VM')) {
      Write-Host "Cloning VM '$vmName' from '$sourceName'..." -ForegroundColor Cyan
      $newVm = New-VM @cloneParams

      # ----------------------------------------------------------------------
      # Post-clone customization: CPU count override
      # ----------------------------------------------------------------------
      if ($cpuCount -and $cpuCount -ne $newVm.NumCPU) {
        Set-VM -VM $newVm -NumCpu $cpuCount -Confirm:$false | Out-Null
      }

      # ----------------------------------------------------------------------
      # Post-clone customization: Memory size override
      # ----------------------------------------------------------------------
      if ($memoryGb -and $memoryGb -ne [math]::Ceiling($newVm.MemoryMB / 1024)) {
        Set-VM -VM $newVm -MemoryGB $memoryGb -Confirm:$false | Out-Null
      }

      # ----------------------------------------------------------------------
      # Post-clone customization: Disk expansion (cannot shrink)
      # ----------------------------------------------------------------------
      if ($diskGb -and $diskGb -gt 0) {
        $primaryDisk = Get-HardDisk -VM $newVm | Select-Object -First 1
        if ($primaryDisk -and [int][math]::Round($primaryDisk.CapacityGB) -lt $diskGb) {
          Set-HardDisk -HardDisk $primaryDisk -CapacityGB $diskGb -Expand -Confirm:$false | Out-Null
        }
      }

      # ----------------------------------------------------------------------
      # Post-clone customization: Network adapter reconfiguration
      # ----------------------------------------------------------------------
      if ($networkName) {
        $targetPortGroup = Get-VirtualPortGroup -Name $networkName -ErrorAction Stop
        $adapter = Get-NetworkAdapter -VM $newVm | Select-Object -First 1
        if ($adapter -and $adapter.NetworkName -ne $networkName) {
          Set-NetworkAdapter -NetworkAdapter $adapter -PortGroup $targetPortGroup -Confirm:$false | Out-Null
        }
      }

      # ----------------------------------------------------------------------
      # Power on VM (per-row PowerOn overrides global -PowerOn switch)
      # ----------------------------------------------------------------------
      $finalPowerOn = if ($null -ne $powerOnRow) { $powerOnRow } else { [bool]$PowerOn }
      if ($finalPowerOn) {
        Start-VM -VM $newVm -Confirm:$false | Out-Null
      }

      Write-Host "VM '$vmName' cloned successfully." -ForegroundColor Green
    }
  }
  catch {
    # ------------------------------------------------------------------------
    # Error handling: Report clone failure and continue to next row
    # ------------------------------------------------------------------------
    Write-Error "Failed to clone VM '$vmName': $_"
  }
}

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
#   FolderName - Name of VM folder to search (e.g., "j64manager")
#   RulePrefix - Prefix for rule naming (e.g., "j64manager")
#
# Returns:
#   None (creates DRS rules in vSphere cluster as side effect)
#
# Notes:
#   - Uses VM name pattern matching: "ctrl" for controllers, "work" for workers
#   - Creates two separate anti-affinity rules per folder (ctrl, work)
#   - Skips folder if either controller or worker VMs are not found
#   - Cluster name derived from first VM's parent cluster
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
    # Derive cluster name from first controller VM's parent cluster
    # All VMs in folder should belong to same cluster for DRS rules
    # ------------------------------------------------------------------------
    $cluster = $ctrlVMs[0].VMHost.Parent
    
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
Create-DrsRulesForPool -FolderName "j64manager" -RulePrefix "j64manager"
Create-DrsRulesForPool -FolderName "j64domain"  -RulePrefix "j64domain"
Create-DrsRulesForPool -FolderName "j52domain"  -RulePrefix "j52domain"
Create-DrsRulesForPool -FolderName "r01domain"  -RulePrefix "r01domain"

# ==============================================================================
# Cleanup: Disconnect from vCenter Server
# ==============================================================================

Disconnect-VIServer -Server $viserver -Confirm:$false | Out-Null

