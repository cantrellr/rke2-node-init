<#
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

Import-Module VMware.PowerCLI -ErrorAction Stop
Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

if (-not (Test-Path -Path $CsvPath -PathType Leaf)) {
  throw "CSV file not found at $CsvPath"
}

$viserver = Get-VIServer -Server $VCenter -ErrorAction SilentlyContinue
if (-not $viserver) {
  $viserver = Connect-VIServer -Server $VCenter -Credential $Credential -ErrorAction Stop
}

$vmDefinitions = Import-Csv -Path $CsvPath
if (-not $vmDefinitions -or $vmDefinitions.Count -eq 0) {
  throw "CSV $CsvPath is empty or unreadable."
}

function Get-StringOrNull {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  return $Value.Trim()
}

function Get-IntOrNull {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $parsed = 0
  if ([int]::TryParse($Value, [ref]$parsed)) { return $parsed }
  throw "Value '$Value' is not a valid integer."
}

function Get-BoolOrNull {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
  $parsed = $false
  if ([bool]::TryParse($Value, [ref]$parsed)) { return $parsed }
  throw "Value '$Value' is not a valid boolean."
}

function Resolve-ResourcePool {
  param(
    [string]$PoolName,
    [VMware.VimAutomation.ViCore.Impl.V1.Inventory.ClusterImpl]$Cluster
  )

  if ($PoolName) {
    return Get-ResourcePool -Name $PoolName -ErrorAction Stop
  }

  if ($Cluster -and $Cluster.ExtensionData -and $Cluster.ExtensionData.ResourcePool) {
    return Get-ResourcePool -Id $Cluster.ExtensionData.ResourcePool -ErrorAction SilentlyContinue
  }

  return $null
}

foreach ($vmRow in $vmDefinitions) {
  $vmName = Get-StringOrNull $vmRow.VMName
  if (-not $vmName) {
    Write-Warning "Skipping row with blank VMName."
    continue
  }

  if ($SkipExisting -and (Get-VM -Name $vmName -ErrorAction SilentlyContinue)) {
    Write-Host "VM '$vmName' already exists; skipping." -ForegroundColor Yellow
    continue
  }

  try {
    $sourceName   = Get-StringOrNull $vmRow.SourceVM
    if (-not $sourceName) { throw "SourceVM column is required for '$vmName'." }

    $clusterName  = Get-StringOrNull $vmRow.Cluster
    $hostName     = Get-StringOrNull $vmRow.VMHost
    $poolName     = Get-StringOrNull $vmRow.ResourcePool
    $datastoreName= Get-StringOrNull $vmRow.Datastore
    $folderName   = Get-StringOrNull $vmRow.Folder
    $networkName  = Get-StringOrNull $vmRow.Network
    $oscSpecName  = Get-StringOrNull $vmRow.OSCustomizationSpec

    $cpuCount     = $null
    $memoryGb     = $null
    $diskGb       = $null
    $powerOnRow   = $null

    if ($vmRow.PSObject.Properties.Name -contains 'CpuCount') { $cpuCount   = Get-IntOrNull $vmRow.CpuCount }
    if ($vmRow.PSObject.Properties.Name -contains 'MemoryGB') { $memoryGb   = Get-IntOrNull $vmRow.MemoryGB }
    if ($vmRow.PSObject.Properties.Name -contains 'DiskGB')   { $diskGb     = Get-IntOrNull $vmRow.DiskGB }
    if ($vmRow.PSObject.Properties.Name -contains 'PowerOn')  { $powerOnRow = Get-BoolOrNull $vmRow.PowerOn }

    $sourceVm  = Get-VM -Name $sourceName -ErrorAction Stop
    $cluster   = if ($clusterName) { Get-Cluster -Name $clusterName -ErrorAction Stop } else { $null }
    $vmHost    = if ($hostName)    { Get-VMHost -Name $hostName -ErrorAction Stop } else { $null }
    $datastore = if ($datastoreName) { Get-Datastore -Name $datastoreName -ErrorAction Stop } else { $null }
    $folder    = if ($folderName)    { Get-Folder -Name $folderName -ErrorAction Stop } else { $null }
    $oscSpec   = if ($oscSpecName)   { Get-OSCustomizationSpec -Name $oscSpecName -ErrorAction Stop } else { $null }
    $pool      = Resolve-ResourcePool -PoolName $poolName -Cluster $cluster

    if (-not $vmHost -and $cluster) {
      $vmHost = Get-VMHost -Location $cluster | Sort-Object -Property @{Expression = 'ExtensionData.Summary.QuickStats.OverallCpuUsage'; Descending = $false} | Select-Object -First 1
    }

    $cloneParams = @{
      Name        = $vmName
      VM          = $sourceVm
      ErrorAction = 'Stop'
    }

    if ($vmHost)    { $cloneParams['VMHost']       = $vmHost }
    if ($pool)      { $cloneParams['ResourcePool'] = $pool }
    if ($datastore) { $cloneParams['Datastore']    = $datastore }
    if ($folder)    { $cloneParams['Location']     = $folder }
    if ($oscSpec)   { $cloneParams['OSCustomizationSpec'] = $oscSpec }

    if ($PSCmdlet.ShouldProcess($vmName, 'Clone VM')) {
      Write-Host "Cloning VM '$vmName' from '$sourceName'..." -ForegroundColor Cyan
      $newVm = New-VM @cloneParams

      if ($cpuCount -and $cpuCount -ne $newVm.NumCPU) {
        Set-VM -VM $newVm -NumCpu $cpuCount -Confirm:$false | Out-Null
      }

      if ($memoryGb -and $memoryGb -ne [math]::Ceiling($newVm.MemoryMB / 1024)) {
        Set-VM -VM $newVm -MemoryGB $memoryGb -Confirm:$false | Out-Null
      }

      if ($diskGb -and $diskGb -gt 0) {
        $primaryDisk = Get-HardDisk -VM $newVm | Select-Object -First 1
        if ($primaryDisk -and [int][math]::Round($primaryDisk.CapacityGB) -lt $diskGb) {
          Set-HardDisk -HardDisk $primaryDisk -CapacityGB $diskGb -Expand -Confirm:$false | Out-Null
        }
      }

      if ($networkName) {
        $targetPortGroup = Get-VirtualPortGroup -Name $networkName -ErrorAction Stop
        $adapter = Get-NetworkAdapter -VM $newVm | Select-Object -First 1
        if ($adapter -and $adapter.NetworkName -ne $networkName) {
          Set-NetworkAdapter -NetworkAdapter $adapter -PortGroup $targetPortGroup -Confirm:$false | Out-Null
        }
      }

      $finalPowerOn = if ($powerOnRow -ne $null) { $powerOnRow } else { [bool]$PowerOn }
      if ($finalPowerOn) {
        Start-VM -VM $newVm -Confirm:$false | Out-Null
      }

      Write-Host "VM '$vmName' cloned successfully." -ForegroundColor Green
    }
  }
  catch {
    Write-Error "Failed to clone VM '$vmName': $_"
  }
}

Disconnect-VIServer -Server $viserver -Confirm:$false | Out-Null
