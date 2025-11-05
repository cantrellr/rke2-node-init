<#!
.SYNOPSIS
  Provision VMware vSphere VMs from a CSV definition.

.DESCRIPTION
  Requires VMware PowerCLI. The CSV should contain one VM per row with columns such as:
    VMName, Cluster, Datastore, Network, CpuCount, MemoryGB, DiskGB, Template,
    Folder, ResourcePool, GuestId, OSCustomizationSpec, CpuReservationMHz, MemoryReservationGB.

.EXAMPLE
  $cred = Get-Credential
  .\New-VmsFromCsv.ps1 -CsvPath .\vm-template.csv -VCenter vcsa.lab.local -Credential $cred
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$CsvPath,

  [Parameter(Mandatory)]
  [string]$VCenter,

  [Parameter(Mandatory)]
  [pscredential]$Credential,

  [switch]$SkipExisting
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

function Get-IntOrDefault {
  param(
    [string]$Value,
    [int]$Default
  )
  if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
  $parsed = 0
  if ([int]::TryParse($Value, [ref]$parsed)) { return $parsed }
  return $Default
}

function Get-ClusterRootResourcePool {
  param($Cluster)
  if (-not $Cluster) { return $null }
  if (-not $Cluster.ExtensionData -or -not $Cluster.ExtensionData.ResourcePool) { return $null }
  return Get-ResourcePool -Id $Cluster.ExtensionData.ResourcePool -ErrorAction SilentlyContinue
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
    $clusterName   = Get-StringOrNull $vmRow.Cluster
    $datastoreName = Get-StringOrNull $vmRow.Datastore
    $networkName   = Get-StringOrNull $vmRow.Network
    $templateName  = Get-StringOrNull $vmRow.Template
    $folderName    = Get-StringOrNull $vmRow.Folder
    $poolName      = Get-StringOrNull $vmRow.ResourcePool
    $guestId       = Get-StringOrNull $vmRow.GuestId
    $oscSpecName   = Get-StringOrNull $vmRow.OSCustomizationSpec

    $cpuCount      = Get-IntOrDefault $vmRow.CpuCount 2
    $memoryGb      = Get-IntOrDefault $vmRow.MemoryGB 4
    $diskGb        = Get-IntOrDefault $vmRow.DiskGB 40
    $cpuResMhz     = Get-IntOrDefault $vmRow.CpuReservationMHz 0
    $memResGb      = Get-IntOrDefault $vmRow.MemoryReservationGB 0

    $cluster      = if ($clusterName)   { Get-Cluster -Name $clusterName -ErrorAction Stop }        else { $null }
    $datastore    = if ($datastoreName) { Get-Datastore -Name $datastoreName -ErrorAction Stop }    else { $null }
    $folder       = if ($folderName)    { Get-Folder -Name $folderName -ErrorAction Stop }          else { $null }
    $resourcePool = if ($poolName)      { Get-ResourcePool -Name $poolName -ErrorAction Stop }      else { $null }
    $template     = if ($templateName)  { Get-Template -Name $templateName -ErrorAction Stop }      else { $null }
    $oscSpec      = if ($oscSpecName)   { Get-OSCustomizationSpec -Name $oscSpecName -ErrorAction Stop } else { $null }

    if (-not $resourcePool -and $cluster) {
      $resourcePool = Get-ClusterRootResourcePool $cluster
    }

    if (-not $template -and -not $resourcePool) {
      throw "ResourcePool (or Cluster resolving to a resource pool) is required when not cloning from a template."
    }

    $params = @{
      Name     = $vmName
      NumCPU   = $cpuCount
      MemoryMB = $memoryGb * 1024
    }

    if ($template) {
      $params['Template'] = $template
      if ($datastore) { $params['Datastore'] = $datastore }
    } else {
      if (-not $datastore) {
        throw "Datastore is required when creating a VM without a template."
      }
      $params['Datastore'] = $datastore
      $params['DiskGB'] = $diskGb
    }

    if ($folder)       { $params['Location'] = $folder }
    if ($resourcePool) { $params['ResourcePool'] = $resourcePool }
    if ($guestId)      { $params['GuestId'] = $guestId }
    if ($oscSpec)      { $params['OSCustomizationSpec'] = $oscSpec }
    if ($networkName)  { $params['NetworkName'] = $networkName }

    Write-Host "Creating VM '$vmName'..." -ForegroundColor Cyan
    $newVm = New-VM @params -ErrorAction Stop

    if (-not $template) {
      $primaryDisk = Get-HardDisk -VM $newVm | Select-Object -First 1
      if ($primaryDisk -and [int]$primaryDisk.CapacityGB -ne $diskGb) {
        Set-HardDisk -HardDisk $primaryDisk -CapacityGB $diskGb -Expand -Confirm:$false | Out-Null
      }
    }

    if ($cpuResMhz -gt 0 -or $memResGb -gt 0) {
      $resourceParams = @{}
      if ($cpuResMhz -gt 0) { $resourceParams['CpuReservationMhz'] = $cpuResMhz }
      if ($memResGb -gt 0)  { $resourceParams['MemReservationGB']  = $memResGb }
      Set-VMResourceConfiguration -VM $newVm @resourceParams -Confirm:$false | Out-Null
    }

    Write-Host "VM '$vmName' created successfully." -ForegroundColor Green
  }
  catch {
    Write-Error "Failed to create VM '$vmName': $_"
  }
}

Disconnect-VIServer -Server $viserver -Confirm:$false | Out-Null
