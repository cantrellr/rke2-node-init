#*************************************************************************
# Full PowerShell Script for Creating Folders, Resource Pools, and DRS Rules
#
# Overview:
# This script logs into a vCenter server and creates a site-level folder and 
# resource pool hierarchy under an existing top-level "Kube.Sites" object.
#
# Pre-requisites:
#   - Top-level Folder and Resource Pool "Kube.Sites" must already exist.
#   - VMs follow naming conventions: "ctrl" for controllers and "work" for workers.
#   - PowerCLI is installed and imported.
#
# The script:
# 1. Prompts for vCenter FQDN/IP and credentials then logs in.
# 2. Checks that the top-level folder "Kube.Sites" exists in the specified datacenter.
# 3. Creates subordinate site folders: j64, j52, and r01, under "Kube.Sites".
# 4. Under each site folder, creates further subfolders for clusters:
#      - j64 => j64manager and j64domain
#      - j52 => j52domain
#      - r01 => r01domain
#    Additionally, optional subfolders "KubeControl" and "KubeWorker" are created.
# 5. Verifies that the top-level resource pool "Kube.Sites" exists in the specified cluster.
# 6. Creates site resource pools under "Kube.Sites": j64, j52, and r01.
# 7. Under each site resource pool, creates subordinate resource pools with
#    CPU/Memory reservations based on the following:
#         j64manager: ~28600 MHz CPU and ~114GB memory.
#         j64domain, j52domain, r01domain: ~23400 MHz CPU and ~94GB memory.
# 8. Calls a helper function that searches each folder for VMs (by name) that include 
#    "ctrl" or "work" and creates DRS anti-affinity rules to keep them on separate hosts.
#*************************************************************************

#------------------------------
# Step 0: Prompt for vCenter Login Details
#------------------------------
Import-Module VMware.PowerCLI -ErrorAction Stop
Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

#$vCenter = Read-Host -Prompt "Enter the vCenter FQDN or IP address"
$vCenter = "vcsa001.dev.local"
$cred = Get-Credential
#$vcUser  = Read-Host -Prompt "Enter your vCenter username"
#$vcPass  = Read-Host -Prompt "Enter your vCenter password" -AsSecureString

# Connect to vCenter using provided credentials.
Connect-VIServer -Server $vCenter -Credential $cred

#------------------------------
# Step 1: Set Base Parameters and Verify Top-Level Folder
#------------------------------
$datacenterName = "Datacenter"   # Change this to match your datacenter name.
$clusterName    = "R01_Kubernetes"    # Change this to your cluster name.

# Retrieve the datacenter object.
$dc = Get-Datacenter -Name $datacenterName

# Verify that the top-level folder "Kube.Sites" exists.
$topFolder = Get-Folder -Name "Kube.Sites" -Location $dc -ErrorAction SilentlyContinue
if (-not $topFolder) {
    Write-Error "Top-level folder 'Kube.Sites' was not found in datacenter '$datacenterName'. Please create it manually first."
    exit
}

# Create site folders under the top-level "Kube.Sites" folder.
New-Folder -Name "j64" -Location $topFolder -ErrorAction SilentlyContinue
New-Folder -Name "j52" -Location $topFolder -ErrorAction SilentlyContinue
New-Folder -Name "r01" -Location $topFolder -ErrorAction SilentlyContinue

# Retrieve the site folders.
$j64Folder = Get-Folder -Name "j64" -Location $topFolder
$j52Folder = Get-Folder -Name "j52" -Location $topFolder
$r01Folder = Get-Folder -Name "r01" -Location $topFolder

# Under j64 folder, create subfolders for clusters.
New-Folder -Name "j64manager" -Location $j64Folder -ErrorAction SilentlyContinue
New-Folder -Name "j64domain" -Location $j64Folder -ErrorAction SilentlyContinue

# Under j52 and r01 folders, create subfolders for the domain.
New-Folder -Name "j52domain" -Location $j52Folder -ErrorAction SilentlyContinue
New-Folder -Name "r01domain" -Location $r01Folder -ErrorAction SilentlyContinue

<#
# Optionally, create additional subfolders for logical segregation.
$j64managerFolder = Get-Folder -Name "j64manager" -Location $j64Folder
New-Folder -Name "KubeControl" -Location $j64managerFolder -ErrorAction SilentlyContinue
New-Folder -Name "KubeWorker"  -Location $j64managerFolder -ErrorAction SilentlyContinue

$j64domainFolder = Get-Folder -Name "j64domain" -Location $j64Folder
New-Folder -Name "KubeControl" -Location $j64domainFolder -ErrorAction SilentlyContinue
New-Folder -Name "KubeWorker"  -Location $j64domainFolder -ErrorAction SilentlyContinue

$j52domainFolder = Get-Folder -Name "j52domain" -Location $j52Folder
New-Folder -Name "KubeControl" -Location $j52domainFolder -ErrorAction SilentlyContinue
New-Folder -Name "KubeWorker"  -Location $j52domainFolder -ErrorAction SilentlyContinue

$r01domainFolder = Get-Folder -Name "r01domain" -Location $r01Folder
New-Folder -Name "KubeControl" -Location $r01domainFolder -ErrorAction SilentlyContinue
New-Folder -Name "KubeWorker"  -Location $r01domainFolder -ErrorAction SilentlyContinue
#>
#------------------------------
# Step 2: Verify Top-Level Resource Pool and Create Resource Pool Hierarchy
#------------------------------
$cluster = Get-Cluster -Name $clusterName

# Verify that the top-level Resource Pool "Kube.Sites" exists.
$topRP = Get-ResourcePool -Name "Kube.Sites" -Location $cluster -ErrorAction SilentlyContinue
if (-not $topRP) {
    Write-Error "Top-level Resource Pool 'Kube.Sites' was not found in cluster '$clusterName'. Please create it manually first."
    exit
}

# Under "Kube.Sites", create site-level resource pools if they do not exist.
$j64RP = Get-ResourcePool -Name "j64" -Location $topRP -ErrorAction SilentlyContinue
if (-not $j64RP) { $j64RP = New-ResourcePool -Name "j64" -Location $topRP }
$j52RP = Get-ResourcePool -Name "j52" -Location $topRP -ErrorAction SilentlyContinue
if (-not $j52RP) { $j52RP = New-ResourcePool -Name "j52" -Location $topRP }
$r01RP = Get-ResourcePool -Name "r01" -Location $topRP -ErrorAction SilentlyContinue
if (-not $r01RP) { $r01RP = New-ResourcePool -Name "r01" -Location $topRP }

# Reservation values based on 30% overhead:
# j64manager: ~28600 MHz CPU & ~114GB memory.
# j64domain, j52domain, r01domain: ~23400 MHz CPU & ~94GB memory.
# Memory values are given in MB (GB * 1024).

# Under j64 resource pool, create subordinate pools.
New-ResourcePool -Name "j64manager" -Location $j64RP `
    -CpuReservationMHz 28600 `
    -MemReservationMB ([math]::Round(114 * 1024))
New-ResourcePool -Name "j64domain" -Location $j64RP `
    -CpuReservationMHz 23400 `
    -MemReservationMB ([math]::Round(94 * 1024))

# Under j52 resource pool, create the j52domain pool.
New-ResourcePool -Name "j52domain" -Location $j52RP `
    -CpuReservationMHz 23400 `
    -MemReservationMB ([math]::Round(94 * 1024))

# Under r01 resource pool, create the r01domain pool.
New-ResourcePool -Name "r01domain" -Location $r01RP `
    -CpuReservationMHz 23400 `
    -MemReservationMB ([math]::Round(94 * 1024))

#------------------------------
# Step 3: Create DRS Anti-Affinity Rules for Controllers and Workers
#------------------------------
#
# The function below searches each subfolder for VMs whose names contain 
# "ctrl" or "work" and creates DRS anti-affinity rules so that controllers 
# and workers are not co-located on the same ESXi host.
#
function Create-DrsRulesForPool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderName,   # The name of the folder where VMs reside (e.g. "j64manager")
        [Parameter(Mandatory = $true)]
        [string]$RulePrefix    # A prefix used for naming the rules (e.g. "j64manager")
    )
    
    # Locate the folder by name.
    $folder = Get-Folder -Name $FolderName -ErrorAction SilentlyContinue
    if (-not $folder) {
        Write-Host "Folder '$FolderName' not found. Skipping DRS rule creation for this folder."
        return
    }
    
    # Retrieve VMs from the folder using naming patterns.
    $ctrlVMs = Get-VM -Location $folder | Where-Object { $_.Name -match "ctrl" }
    $workerVMs = Get-VM -Location $folder | Where-Object { $_.Name -match "work" }
    
    if (($ctrlVMs.Count -eq 0) -or ($workerVMs.Count -eq 0)) {
        Write-Host "Either controller or worker VMs were not found in folder '$FolderName'. Skipping DRS rule creation for this folder."
        return
    }
    
    # Create optional VM groups for controllers and workers.
    New-DrsRule -Name "${RulePrefix}_Controllers" -VM $ctrlVMs -Cluster $cluster -KeepTogether $false
    New-DrsRule -Name "${RulePrefix}_Workers" -VM $workerVMs -Cluster $cluster -KeepTogether $false
    
    <#
    # Create an anti-affinity rule to ensure controllers and workers do not share the same host.
    New-DrsRule -Name "${RulePrefix}_NoMix" -VM ($ctrlVMs + $workerVMs) `
        -Cluster $cluster -Enabled $true #-Type SeparateVMHosts
    Write-Host "DRS anti-affinity rules created for folder '$FolderName'."
    #>
}

# Call the function for each of the subfolders.
Create-DrsRulesForPool -FolderName "j64manager" -RulePrefix "j64manager"
Create-DrsRulesForPool -FolderName "j64domain"  -RulePrefix "j64domain"
Create-DrsRulesForPool -FolderName "j52domain"  -RulePrefix "j52domain"
Create-DrsRulesForPool -FolderName "r01domain"  -RulePrefix "r01domain"

#*************************************************************************
# End of Script
#*************************************************************************