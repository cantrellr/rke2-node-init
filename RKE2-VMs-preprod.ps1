<#
.SYNOPSIS
  Provision VMs in vCenter from a CSV definition.

.DESCRIPTION
  Requires VMware PowerCLI. The CSV should contain one row per VM with columns like:
    VMName, Cluster, Datastore, Network, CpuCount, MemoryGB, DiskGB, Template, Folder,
    ResourcePool, GuestId, OSCustomizationSpec

.PARAMETER CsvPath
  Path to the CSV with VM definitions.

.PARAMETER VCenter
  FQDN or IP of the vCenter Server.

.PARAMETER Credential
  PSCredential to authenticate against vCenter. Pass in via Get-Credential.

.EXAMPLE
  $cred = Get-Credential
  .\New-VmsFromCsv.ps1 -CsvPath .\vm-list.csv -VCenter vcsa.lab.local -Credential $cred
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

$session = Get-VIServer -Server $VCenter -ErrorAction SilentlyContinue
if (-not $session) {
  Write-Verbose "Connecting to $VCenter"
  $session = Connect-VIServer -Server $VCenter -Credential $Credential -ErrorAction Stop
}

$vmDefs = Import-Csv -Path $CsvPath
if (-not $vmDefs) {
  throw "CSV $CsvPath is empty or unreadable."
}

foreach ($vm in $vmDefs) {
  try {
    $vmName = $vm.VMName
    if ([string]::IsNullOrWhiteSpace($vmName)) {
      Write-Warning "Skipping row with blank VMName."
      continue
    }

    if ($SkipExisting -and (Get-VM -Name $vmName -ErrorAction SilentlyContinue)) {
      Write-Host "VM '$vmName' already exists; skipping (per SkipExisting)." -ForegroundColor Yellow
      continue
    }

    $cluster      = if ($vm.Cluster)      { Get-Cluster -Name $vm.Cluster -ErrorAction Stop }      else { $null }
    $resourcePool = if ($vm.ResourcePool) { Get-ResourcePool -Name $vm.ResourcePool -ErrorAction Stop } else { $null }
    $folder       = if ($vm.Folder)       { Get-Folder -Name $vm.Folder -ErrorAction Stop }        else { $null }
    $datastore    = if ($vm.Datastore)    { Get-Datastore -Name $vm.Datastore -ErrorAction Stop }  else { $null }
    $network      = if ($vm.Network)      { Get-VMNetworkAdapter -ErrorAction SilentlyContinue; Get-VirtualPortGroup -Name $vm.Network -ErrorAction Stop } else { $null }
    $template     = if ($vm.Template)     { Get-Template -Name $vm.Template -ErrorAction Stop }    else { $null }
    $spec         = if ($vm.OSCustomizationSpec) { Get-OSCustomizationSpec -Name $vm.OSCustomizationSpec -ErrorAction Stop } else { $null }

    $cpu    = [int]($vm.CpuCount   ?? 2)
    $memory = ([int]($vm.MemoryGB  ?? 4)) * 1GB
    $diskGb = [int]($vm.DiskGB     ?? 40)

    $newVmParams = @{
      Name         = $vmName
      NumCPU       = $cpu
      MemoryMB     = [int]($memory / 1MB)
      DiskGB       = $diskGb
      Datastore    = $datastore
      ResourcePool = $resourcePool
      VMHost       = $null
      Location     = $folder
      GuestId      = $vm.GuestId
      OSCustomizationSpec = $spec
    }

    if ($template) {
      $newVmParams['Template'] = $template
    } elseif (-not $cluster) {
      throw "Cluster is required when not cloning from a template."
    } else {
      $newVmParams['Cluster'] = $cluster
    }

    if ($network) {
      $newVmParams['NetworkName'] = $network.Name
    }

    Write-Host "Creating VM '$vmName'..." -ForegroundColor Cyan
    $newVm = New-VM @newVmParams -ErrorAction Stop

    if (-not $template -and $diskGb -gt 0) {
      # Adjust first hard disk only when we created from scratch
      $hd = Get-HardDisk -VM $newVm | Select-Object -First 1
      if ($hd -and $hd.CapacityGB -ne $diskGb) {
        Set-HardDisk -HardDisk $hd -CapacityGB $diskGb -Expand -Confirm:$false | Out-Null
      }
    }

    if ($vm.CpuReservationMHz) {
      Set-VMResourceConfiguration -VM $newVm -CpuReservationMhz [int]$vm.CpuReservationMHz -Confirm:$false | Out-Null
    }
    if ($vm.MemoryReservationGB) {
      Set-VMResourceConfiguration -VM $newVm -MemReservationGB [int]$vm.MemoryReservationGB -Confirm:$false | Out-Null
    }

    Write-Host "VM '$vmName' created successfully." -ForegroundColor Green
  }
  catch {
    Write-Error "Failed to create VM '$($vm.VMName)': $_"
  }
}

Disconnect-VIServer -Server $session -Confirm:$false | Out-Null