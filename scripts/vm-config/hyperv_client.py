#!/usr/bin/env python3
"""
Hyper-V Client for VM Configuration Management

Manages Hyper-V VMs via PowerShell remoting (WinRM). Handles VM cloning,
configuration, and KVP data injection for guest consumption.

Dependencies:
    pip3 install pywinrm

Usage:
    from hyperv_client import HyperVClient
    
    client = HyperVClient(host='hyperv.example.com', username='admin', password='pass')
    client.create_vm_from_template(vm_name='test-vm', template='template-vm')
"""

import sys
import json
import logging
from typing import Dict, List, Optional, Any

try:
    import winrm
except ImportError:
    print("ERROR: pywinrm package not installed", file=sys.stderr)
    print("Install: pip3 install pywinrm", file=sys.stderr)
    sys.exit(2)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('hyperv_client')


class HyperVClientError(Exception):
    """Base exception for Hyper-V client errors"""
    pass


class HyperVClient:
    """Client for managing Hyper-V VMs via PowerShell remoting"""
    
    def __init__(self, host: str, username: str, password: str, port: int = 5985, use_ssl: bool = False):
        """
        Initialize Hyper-V client
        
        Args:
            host: Hyper-V host address
            username: WinRM username
            password: WinRM password
            port: WinRM port (5985 for HTTP, 5986 for HTTPS)
            use_ssl: Use HTTPS for WinRM connection
        """
        self.host = host
        self.username = username
        self.port = port
        self.use_ssl = use_ssl
        
        # Build WinRM endpoint
        protocol = 'https' if use_ssl else 'http'
        endpoint = f'{protocol}://{host}:{port}/wsman'
        
        try:
            self.session = winrm.Session(
                endpoint,
                auth=(username, password),
                transport='ntlm',
                server_cert_validation='ignore' if use_ssl else None
            )
            logger.info(f"Connected to Hyper-V host: {host}")
        except Exception as e:
            raise HyperVClientError(f"Failed to connect to {host}: {e}")
    
    def _run_powershell(self, script: str, check: bool = True) -> Dict[str, Any]:
        """
        Execute PowerShell script on remote host
        
        Args:
            script: PowerShell script to execute
            check: Raise exception on non-zero exit code
            
        Returns:
            Dict with stdout, stderr, status_code
        """
        try:
            result = self.session.run_ps(script)
            
            response = {
                'stdout': result.std_out.decode('utf-8').strip(),
                'stderr': result.std_err.decode('utf-8').strip(),
                'status_code': result.status_code
            }
            
            if check and result.status_code != 0:
                logger.error(f"PowerShell execution failed: {response['stderr']}")
                raise HyperVClientError(
                    f"PowerShell script failed with exit code {result.status_code}: "
                    f"{response['stderr']}"
                )
            
            return response
            
        except Exception as e:
            if isinstance(e, HyperVClientError):
                raise
            raise HyperVClientError(f"Failed to execute PowerShell: {e}")
    
    def vm_exists(self, vm_name: str) -> bool:
        """Check if VM exists"""
        script = f"""
        $vm = Get-VM -Name "{vm_name}" -ErrorAction SilentlyContinue
        if ($vm) {{ Write-Output "EXISTS" }} else {{ Write-Output "NOT_FOUND" }}
        """
        result = self._run_powershell(script, check=False)
        return result['stdout'].strip() == 'EXISTS'
    
    def get_vm_info(self, vm_name: str) -> Dict[str, Any]:
        """Get VM information as JSON"""
        script = f"""
        $vm = Get-VM -Name "{vm_name}" -ErrorAction Stop
        $info = @{{
            Name = $vm.Name
            State = $vm.State.ToString()
            CPUCount = $vm.ProcessorCount
            MemoryMB = $vm.MemoryStartup / 1MB
            Generation = $vm.Generation
            Path = $vm.Path
        }}
        $info | ConvertTo-Json
        """
        result = self._run_powershell(script)
        return json.loads(result['stdout'])
    
    def create_vm_from_template(
        self,
        vm_name: str,
        template_name: str,
        cpus: Optional[int] = None,
        memory_mb: Optional[int] = None,
        network: Optional[str] = None,
        path: Optional[str] = None
    ) -> bool:
        """
        Clone VM from template (export/import method)
        
        Args:
            vm_name: New VM name
            template_name: Source template VM name
            cpus: CPU count (optional, overrides template)
            memory_mb: Memory in MB (optional, overrides template)
            network: Network switch name (optional)
            path: VM storage path (optional)
            
        Returns:
            True if successful
        """
        logger.info(f"Creating VM '{vm_name}' from template '{template_name}'")
        
        # Check if VM already exists
        if self.vm_exists(vm_name):
            logger.warning(f"VM '{vm_name}' already exists - skipping creation")
            return False
        
        # Check if template exists
        if not self.vm_exists(template_name):
            raise HyperVClientError(f"Template VM '{template_name}' not found")
        
        # Build export path
        export_path = path or f"C:\\VMs\\{vm_name}"
        
        script = f"""
        $templateName = "{template_name}"
        $newVMName = "{vm_name}"
        $exportPath = "{export_path}"
        
        # Ensure template is stopped
        $template = Get-VM -Name $templateName -ErrorAction Stop
        if ($template.State -ne 'Off') {{
            Write-Error "Template VM must be powered off"
            exit 1
        }}
        
        # Export template to temporary location
        $tempExportPath = "$env:TEMP\\hyperv-export-$templateName-$(Get-Date -Format 'yyyyMMddHHmmss')"
        Export-VM -Name $templateName -Path $tempExportPath -ErrorAction Stop
        
        # Find exported VM config
        $exportedVMConfig = Get-ChildItem -Path $tempExportPath -Recurse -Filter "*.vmcx" | Select-Object -First 1
        if (-not $exportedVMConfig) {{
            Write-Error "Failed to find exported VM configuration"
            exit 1
        }}
        
        # Import as copy with new name
        Import-VM -Path $exportedVMConfig.FullName -Copy -GenerateNewId -VirtualMachinePath $exportPath -ErrorAction Stop | Out-Null
        
        # Get imported VM and rename
        $importedVM = Get-VM | Where-Object {{ $_.Path -like "$exportPath*" }} | Select-Object -First 1
        if ($importedVM) {{
            Rename-VM -VM $importedVM -NewName $newVMName -ErrorAction Stop
        }} else {{
            Write-Error "Failed to find imported VM"
            exit 1
        }}
        
        # Cleanup temporary export
        Remove-Item -Path $tempExportPath -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-Output "VM '$newVMName' created successfully"
        """
        
        result = self._run_powershell(script)
        logger.info(f"VM creation result: {result['stdout']}")
        
        # Apply configuration overrides
        if cpus:
            self.set_vm_cpu(vm_name, cpus)
        
        if memory_mb:
            self.set_vm_memory(vm_name, memory_mb)
        
        if network:
            self.set_vm_network(vm_name, network)
        
        return True
    
    def set_vm_cpu(self, vm_name: str, cpu_count: int) -> bool:
        """Set VM CPU count"""
        logger.info(f"Setting VM '{vm_name}' CPUs to {cpu_count}")
        script = f"""
        Set-VMProcessor -VMName "{vm_name}" -Count {cpu_count} -ErrorAction Stop
        Write-Output "CPU count set to {cpu_count}"
        """
        self._run_powershell(script)
        return True
    
    def set_vm_memory(self, vm_name: str, memory_mb: int) -> bool:
        """Set VM memory (startup memory)"""
        logger.info(f"Setting VM '{vm_name}' memory to {memory_mb}MB")
        memory_bytes = memory_mb * 1024 * 1024
        script = f"""
        Set-VMMemory -VMName "{vm_name}" -StartupBytes {memory_bytes} -ErrorAction Stop
        Write-Output "Memory set to {memory_mb}MB"
        """
        self._run_powershell(script)
        return True
    
    def set_vm_network(self, vm_name: str, switch_name: str) -> bool:
        """Set VM network adapter to specified switch"""
        logger.info(f"Setting VM '{vm_name}' network to switch '{switch_name}'")
        script = f"""
        $adapter = Get-VMNetworkAdapter -VMName "{vm_name}" -ErrorAction Stop | Select-Object -First 1
        Connect-VMNetworkAdapter -VMNetworkAdapter $adapter -SwitchName "{switch_name}" -ErrorAction Stop
        Write-Output "Network adapter connected to switch '{switch_name}'"
        """
        self._run_powershell(script)
        return True
    
    def set_kvp_data(self, vm_name: str, key: str, value: str) -> bool:
        """
        Set KVP data item (pool 0 - guest-accessible)
        
        Args:
            vm_name: VM name
            key: KVP key name
            value: KVP value
            
        Returns:
            True if successful
        """
        logger.info(f"Setting KVP data for VM '{vm_name}': {key}={value}")
        
        # Escape special characters for PowerShell
        value_escaped = value.replace('"', '`"').replace('$', '`$')
        
        script = f"""
        $vm = Get-VM -Name "{vm_name}" -ErrorAction Stop
        $kvp = Get-VMKeyValuePairItem -VMName "{vm_name}" -Key "{key}" -ErrorAction SilentlyContinue
        
        if ($kvp) {{
            Set-VMKeyValuePairItem -VMName "{vm_name}" -Key "{key}" -Value "{value_escaped}" -ErrorAction Stop
            Write-Output "Updated KVP: {key}={value_escaped}"
        }} else {{
            Set-VMKeyValuePairItem -VMName "{vm_name}" -Key "{key}" -Value "{value_escaped}" -ErrorAction Stop
            Write-Output "Created KVP: {key}={value_escaped}"
        }}
        """
        
        self._run_powershell(script)
        return True
    
    def set_kvp_data_bulk(self, vm_name: str, kvp_data: Dict[str, str]) -> bool:
        """Set multiple KVP data items at once"""
        logger.info(f"Setting {len(kvp_data)} KVP items for VM '{vm_name}'")
        
        for key, value in kvp_data.items():
            self.set_kvp_data(vm_name, key, value)
        
        return True
    
    def start_vm(self, vm_name: str) -> bool:
        """Start VM"""
        logger.info(f"Starting VM '{vm_name}'")
        script = f"""
        Start-VM -Name "{vm_name}" -ErrorAction Stop
        Write-Output "VM started"
        """
        self._run_powershell(script)
        return True
    
    def stop_vm(self, vm_name: str, force: bool = False) -> bool:
        """Stop VM (graceful shutdown or force)"""
        action = "Force stopping" if force else "Stopping"
        logger.info(f"{action} VM '{vm_name}'")
        
        if force:
            script = f'Stop-VM -Name "{vm_name}" -Force -ErrorAction Stop'
        else:
            script = f'Stop-VM -Name "{vm_name}" -ErrorAction Stop'
        
        self._run_powershell(script)
        return True
    
    def delete_vm(self, vm_name: str, delete_files: bool = False) -> bool:
        """Delete VM (optionally delete files)"""
        logger.info(f"Deleting VM '{vm_name}' (delete_files={delete_files})")
        
        # Ensure VM is stopped
        if self.vm_exists(vm_name):
            try:
                self.stop_vm(vm_name, force=True)
            except Exception:
                pass  # Already stopped
        
        script = f"""
        $vm = Get-VM -Name "{vm_name}" -ErrorAction SilentlyContinue
        if ($vm) {{
            $vmPath = $vm.Path
            Remove-VM -Name "{vm_name}" -Force -ErrorAction Stop
            Write-Output "VM removed"
            
            if ({str(delete_files).lower()}) {{
                if (Test-Path $vmPath) {{
                    Remove-Item -Path $vmPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Output "VM files deleted: $vmPath"
                }}
            }}
        }} else {{
            Write-Output "VM not found"
        }}
        """
        
        self._run_powershell(script)
        return True
    
    def get_vm_state(self, vm_name: str) -> str:
        """Get VM power state (Running, Off, etc.)"""
        script = f"""
        $vm = Get-VM -Name "{vm_name}" -ErrorAction Stop
        Write-Output $vm.State.ToString()
        """
        result = self._run_powershell(script)
        return result['stdout'].strip()


def main():
    """Test/demo Hyper-V client functionality"""
    import os
    
    # Example usage
    host = os.getenv('HYPERV_HOST', 'hyperv.example.com')
    username = os.getenv('HYPERV_USER', 'Administrator')
    password = os.getenv('HYPERV_PASS', '')
    
    if not password:
        print("ERROR: Set HYPERV_PASS environment variable", file=sys.stderr)
        return 1
    
    try:
        client = HyperVClient(host=host, username=username, password=password)
        
        # Test connection
        logger.info("Testing connection...")
        result = client._run_powershell("Get-VM | Select-Object -First 1 | ConvertTo-Json")
        logger.info(f"Connection successful: {result['stdout'][:100]}...")
        
        return 0
        
    except HyperVClientError as e:
        logger.error(f"Hyper-V client error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
