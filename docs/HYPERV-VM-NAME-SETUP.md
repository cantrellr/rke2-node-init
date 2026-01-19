# Hyper-V VM Name Configuration for Boot Service

## Overview

The RKE2 boot service needs to know the VM name to discover the correct configuration file. For Hyper-V VMs, the name must be set from the Hyper-V host using PowerShell.

## Prerequisites

- Hyper-V host with PowerShell (Windows Server 2016+ or Windows 10/11 Pro)
- Administrator access to the Hyper-V host
- VMs must be running to accept KVP items

## Setting VM Name for Single VM

Run this PowerShell command on the **Hyper-V host** (not in the guest):

```powershell
# Set the VM name for a single VM
$vmName = "cotpa-ctrl01"
Set-VMKeyValuePairItem -VMName $vmName -Key "VirtualMachineName" -Value $vmName
```

### Verify the Setting

```powershell
# View all KVP items for a VM
Get-VMKeyValuePairItem -VMName "cotpa-ctrl01"
```

## Setting VM Names for Multiple VMs

For bulk configuration, use this script:

```powershell
# Set VM names for all VMs matching a pattern
$vmNames = @(
    "cotpa-ctrl01",
    "cotpa-ctrl02",
    "cotpa-ctrl03",
    "cotpa-work01",
    "cotpa-work02"
)

foreach ($vmName in $vmNames) {
    try {
        Set-VMKeyValuePairItem -VMName $vmName -Key "VirtualMachineName" -Value $vmName
        Write-Host "✓ Set VirtualMachineName for $vmName" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to set VirtualMachineName for $vmName : $_"
    }
}
```

## Setting VM Names for All VMs in a Cluster

```powershell
# Set VM name for all running VMs on the host
Get-VM | Where-Object {$_.State -eq 'Running'} | ForEach-Object {
    $vmName = $_.Name
    try {
        Set-VMKeyValuePairItem -VMName $vmName -Key "VirtualMachineName" -Value $vmName
        Write-Host "✓ Configured $vmName" -ForegroundColor Green
    } catch {
        Write-Warning "Failed for $vmName : $_"
    }
}
```

## Verification from Guest

After setting the VM name from the host, verify it's readable from within the guest VM:

### Using PowerShell (if installed in guest)

```bash
pwsh -NoProfile -Command '
  $kvp0 = [System.IO.File]::ReadAllBytes("/var/lib/hyperv/.kvp_pool_0")
  $text = [System.Text.Encoding]::ASCII.GetString($kvp0)
  $lines = $text -split "\x00" | Where-Object {$_.Trim()}
  for($i=0; $i -lt $lines.Count; $i++) {
    if($lines[$i] -eq "VirtualMachineName" -and $i+1 -lt $lines.Count) {
      Write-Output "VM Name: $($lines[$i+1].Trim())"
      exit 0
    }
  }
  Write-Output "VirtualMachineName not found"
'
```

### Using Bash

```bash
cat /var/lib/hyperv/.kvp_pool_0 2>/dev/null | tr '\0' '\n' | grep -A1 "^VirtualMachineName$" | tail -1
```

## Boot Service Behavior

The boot service hostname detection follows this priority:

1. **PowerShell method** (if `pwsh` is available): Reads `VirtualMachineName` from KVP pool_0
2. **Bash method**: Reads `VirtualMachineName` from KVP pool_0 using grep
3. **Fallback**: Uses guest OS hostname via `hostname` command

## Troubleshooting

### VM Name Not Found in Guest

**Symptom**: Guest cannot read the VirtualMachineName

**Solutions**:
1. Ensure VM is running when you set the KVP item
2. Restart the `hv_kvp_daemon` service in the guest:
   ```bash
   sudo systemctl restart hv-kvp-daemon
   ```
3. Verify KVP daemon is running:
   ```bash
   sudo systemctl status hv-kvp-daemon
   ```

### Permission Denied Reading KVP Files

**Symptom**: Cannot read `/var/lib/hyperv/.kvp_pool_0`

**Solution**:
```bash
# The boot service runs as root, but for manual testing:
sudo cat /var/lib/hyperv/.kvp_pool_0
```

### Boot Service Uses Hostname Instead of VM Name

**Symptom**: Boot service logs show hostname instead of expected VM name

**Causes**:
1. VM name not set from Hyper-V host
2. KVP daemon not running in guest
3. Guest hasn't refreshed KVP data

**Solution**: Set VM name from host and verify in guest as shown above

## Alternative: Use Hostname Matching

If you prefer not to configure KVP items from the host, you can:

1. **Set guest hostname to match config file name** during VM provisioning
2. **Use cloud-init** to set hostname from metadata
3. **Configure hostname** via netplan or systemd-hostnamed

Example cloud-init configuration:
```yaml
#cloud-config
hostname: cotpa-ctrl01
fqdn: cotpa-ctrl01.k8.cantrellcloud.net
```

## Best Practices

1. **Set VM names immediately after cloning** from template
2. **Use consistent naming convention** (e.g., `cluster-role-number`)
3. **Match VM name to config file name exactly** (e.g., VM "cotpa-ctrl01" → config "cotpa-ctrl01.yaml")
4. **Document your naming scheme** for the operations team
5. **Automate VM name setting** in your provisioning scripts

## Example: Complete Workflow

### 1. On Hyper-V Host (PowerShell)

```powershell
# Clone template VM
$templateVM = "cotpa-template"
$newVMName = "cotpa-ctrl01"

# Clone the VM
Export-VM -Name $templateVM -Path "C:\Temp\Export"
Import-VM -Path "C:\Temp\Export\$templateVM\*\*.vmcx" -Copy -GenerateNewId
Rename-VM -Name $templateVM -NewName $newVMName

# Set VM name in KVP
Set-VMKeyValuePairItem -VMName $newVMName -Key "VirtualMachineName" -Value $newVMName

# Start the VM
Start-VM -Name $newVMName
```

### 2. Verify in Guest (after boot)

```bash
# Check what name the boot service will use
sudo journalctl -u rke2-boot -n 50 | grep "Result:"
```

### 3. Expected Output

```
[INFO]   Result: cotpa-ctrl01
[INFO] Step 2: Search for matching configuration file
[INFO]   Searching: /rke2-node-init/configs
[INFO]   ✓ Found: /rke2-node-init/configs/cotpa-ctrl01.yaml
```

## References

- [Hyper-V KVP Exchange Documentation](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/reference/integration-services#key-value-pair-exchange)
- [Set-VMKeyValuePairItem Cmdlet](https://docs.microsoft.com/en-us/powershell/module/hyper-v/set-vmkeyvaluepairitem)
