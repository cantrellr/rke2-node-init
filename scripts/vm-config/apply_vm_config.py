#!/usr/bin/env python3
"""
VM Configuration Orchestrator

Main orchestration script for applying VM configurations to hypervisors.
Reads VM config YAML, validates it, and applies to target hypervisor via
appropriate client (Hyper-V, VMware, etc.).

Usage:
    python3 apply_vm_config.py <config-file.yaml>
    python3 apply_vm_config.py <config-file.yaml> --dry-run
    python3 apply_vm_config.py --all <config-directory>/
"""

import sys
import os
import json
import yaml
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add script directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from config_validator import VMConfigValidator
    from hyperv_client import HyperVClient, HyperVClientError
except ImportError as e:
    print(f"ERROR: Failed to import required modules: {e}", file=sys.stderr)
    sys.exit(2)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('apply_vm_config')


class VMConfigOrchestratorError(Exception):
    """Base exception for orchestrator errors"""
    pass


class VMConfigOrchestrator:
    """Orchestrates VM configuration application to hypervisors"""
    
    def __init__(self, dry_run: bool = False):
        """
        Initialize orchestrator
        
        Args:
            dry_run: If True, validate but don't apply changes
        """
        self.dry_run = dry_run
        self.validator = None
        self.hyperv_clients = {}  # Cache clients by host
        
        if dry_run:
            logger.info("DRY-RUN MODE: No changes will be applied")
    
    def load_config(self, config_path: Path) -> Dict[str, Any]:
        """Load and validate VM configuration file"""
        logger.info(f"Loading configuration: {config_path}")
        
        # Load YAML
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            raise VMConfigOrchestratorError(f"Failed to load config: {e}")
        
        # Validate against schema
        if not self.validator:
            schema_path = Path(__file__).parent.parent.parent / 'vm-configs' / 'schema.json'
            self.validator = VMConfigValidator(schema_path)
        
        is_valid, errors, warnings = self.validator.validate_file(config_path)
        
        if not is_valid:
            logger.error(f"Configuration validation failed:")
            for error in errors:
                logger.error(f"  - {error}")
            raise VMConfigOrchestratorError("Configuration validation failed")
        
        if warnings:
            logger.warning(f"Configuration has {len(warnings)} warning(s):")
            for warning in warnings:
                logger.warning(f"  - {warning}")
        
        logger.info("✓ Configuration validated successfully")
        return config
    
    def get_hyperv_client(self, host: str, credentials_secret: str) -> HyperVClient:
        """
        Get or create Hyper-V client for host (with caching)
        
        Args:
            host: Hyper-V host address
            credentials_secret: GitHub secret name for credentials
            
        Returns:
            HyperVClient instance
        """
        if host in self.hyperv_clients:
            return self.hyperv_clients[host]
        
        # Load credentials from environment (GitHub Actions secrets)
        username = os.getenv(f"{credentials_secret}_USER")
        password = os.getenv(f"{credentials_secret}_PASS")
        
        if not username or not password:
            raise VMConfigOrchestratorError(
                f"Credentials not found in environment: "
                f"{credentials_secret}_USER and {credentials_secret}_PASS"
            )
        
        logger.info(f"Connecting to Hyper-V host: {host}")
        
        if self.dry_run:
            logger.info("DRY-RUN: Skipping actual connection")
            # Return a mock client for dry-run
            return None
        
        try:
            client = HyperVClient(host=host, username=username, password=password)
            self.hyperv_clients[host] = client
            return client
        except HyperVClientError as e:
            raise VMConfigOrchestratorError(f"Failed to connect to Hyper-V host: {e}")
    
    def apply_vm_config(self, config_path: Path) -> bool:
        """
        Apply VM configuration to hypervisor
        
        Args:
            config_path: Path to VM config YAML
            
        Returns:
            True if successful
        """
        logger.info(f"{'='*70}")
        logger.info(f"Applying configuration: {config_path.name}")
        logger.info(f"{'='*70}")
        
        # Load and validate config
        config = self.load_config(config_path)
        
        kind = config.get('kind')
        
        if kind == 'ClusterConfig':
            logger.info("ClusterConfig detected - skipping (defaults only)")
            return True
        
        if kind != 'VirtualMachineConfig':
            logger.warning(f"Unknown config kind: {kind} - skipping")
            return True
        
        # Extract configuration
        metadata = config.get('metadata', {})
        spec = config.get('spec', {})
        
        vm_name = metadata.get('name')
        cluster = metadata.get('cluster')
        environment = metadata.get('environment', 'production')
        
        logger.info(f"VM Name: {vm_name}")
        logger.info(f"Cluster: {cluster}")
        logger.info(f"Environment: {environment}")
        
        # Get hypervisor config
        hypervisor = spec.get('hypervisor', {})
        hypervisor_type = hypervisor.get('type')
        connection = hypervisor.get('connection', {})
        vm_settings = hypervisor.get('vmSettings', {})
        guest_variables = hypervisor.get('guestVariables', {})
        
        if hypervisor_type != 'hyperv':
            raise VMConfigOrchestratorError(
                f"Hypervisor type '{hypervisor_type}' not yet implemented "
                "(only 'hyperv' currently supported)"
            )
        
        # Connect to hypervisor
        host = connection.get('host')
        credentials_secret = connection.get('credentialsSecret', 'HYPERV_CREDENTIALS')
        
        client = self.get_hyperv_client(host, credentials_secret)
        
        # Check if VM exists
        if self.dry_run:
            logger.info(f"DRY-RUN: Would check if VM '{vm_name}' exists")
            vm_exists = False
        else:
            vm_exists = client.vm_exists(vm_name)
        
        if vm_exists:
            logger.info(f"VM '{vm_name}' already exists - updating configuration")
            return self._update_vm(client, vm_name, vm_settings, guest_variables)
        else:
            logger.info(f"VM '{vm_name}' does not exist - creating from template")
            return self._create_vm(client, vm_name, vm_settings, guest_variables, spec)
    
    def _create_vm(
        self,
        client: Optional[HyperVClient],
        vm_name: str,
        vm_settings: Dict[str, Any],
        guest_variables: Dict[str, str],
        spec: Dict[str, Any]
    ) -> bool:
        """Create new VM from template"""
        
        template_name = vm_settings.get('templateName')
        if not template_name:
            raise VMConfigOrchestratorError("templateName not specified in vmSettings")
        
        cpus = vm_settings.get('cpus')
        memory_mb = vm_settings.get('memoryMB')
        network = vm_settings.get('network')
        
        logger.info(f"Creating VM from template: {template_name}")
        logger.info(f"  CPUs: {cpus or 'inherit from template'}")
        logger.info(f"  Memory: {memory_mb or 'inherit from template'}MB")
        logger.info(f"  Network: {network or 'inherit from template'}")
        
        if self.dry_run:
            logger.info("DRY-RUN: Would create VM with above settings")
        else:
            # Create VM
            client.create_vm_from_template(
                vm_name=vm_name,
                template_name=template_name,
                cpus=cpus,
                memory_mb=memory_mb,
                network=network
            )
            logger.info(f"✓ VM '{vm_name}' created successfully")
        
        # Set KVP data for guest
        if guest_variables:
            logger.info(f"Setting {len(guest_variables)} KVP variables for guest access:")
            for key, value in guest_variables.items():
                logger.info(f"  {key}={value}")
            
            if self.dry_run:
                logger.info("DRY-RUN: Would set KVP variables")
            else:
                client.set_kvp_data_bulk(vm_name, guest_variables)
                logger.info("✓ KVP variables set successfully")
        
        # Check if auto-start is enabled
        rke2_config = spec.get('rke2Config', {})
        auto_start = rke2_config.get('autoStart', True)
        
        if auto_start:
            logger.info("Auto-start enabled - starting VM")
            if self.dry_run:
                logger.info("DRY-RUN: Would start VM")
            else:
                client.start_vm(vm_name)
                logger.info(f"✓ VM '{vm_name}' started successfully")
        else:
            logger.info("Auto-start disabled - VM left powered off")
        
        # Run onCreate operations
        operations = spec.get('operations', {})
        on_create = operations.get('onCreate', [])
        if on_create:
            logger.info(f"Running {len(on_create)} onCreate operation(s)")
            for cmd in on_create:
                logger.info(f"  Command: {cmd}")
                if not self.dry_run:
                    # Note: These commands run on the GitHub Actions runner, not in the VM
                    # For in-VM operations, use cloud-init or similar
                    os.system(cmd)
        
        return True
    
    def _update_vm(
        self,
        client: Optional[HyperVClient],
        vm_name: str,
        vm_settings: Dict[str, Any],
        guest_variables: Dict[str, str]
    ) -> bool:
        """Update existing VM configuration"""
        
        logger.info(f"Updating VM '{vm_name}' configuration")
        
        # Update CPU if specified
        cpus = vm_settings.get('cpus')
        if cpus:
            logger.info(f"Updating CPUs to: {cpus}")
            if not self.dry_run:
                client.set_vm_cpu(vm_name, cpus)
        
        # Update memory if specified
        memory_mb = vm_settings.get('memoryMB')
        if memory_mb:
            logger.info(f"Updating memory to: {memory_mb}MB")
            if not self.dry_run:
                client.set_vm_memory(vm_name, memory_mb)
        
        # Update network if specified
        network = vm_settings.get('network')
        if network:
            logger.info(f"Updating network to: {network}")
            if not self.dry_run:
                client.set_vm_network(vm_name, network)
        
        # Update KVP data
        if guest_variables:
            logger.info(f"Updating {len(guest_variables)} KVP variables")
            if not self.dry_run:
                client.set_kvp_data_bulk(vm_name, guest_variables)
        
        logger.info(f"✓ VM '{vm_name}' updated successfully")
        return True


def find_vm_configs(base_path: Path) -> List[Path]:
    """Find all VirtualMachineConfig YAML files in directory"""
    configs = []
    for pattern in ['**/*.yaml', '**/*.yml']:
        for path in base_path.glob(pattern):
            # Quick check if it's a VirtualMachineConfig
            try:
                with open(path, 'r') as f:
                    content = yaml.safe_load(f)
                    if content and content.get('kind') == 'VirtualMachineConfig':
                        configs.append(path)
            except Exception:
                continue
    return sorted(configs)


def main():
    parser = argparse.ArgumentParser(
        description='Apply VM configurations to hypervisors'
    )
    parser.add_argument(
        'path',
        type=Path,
        help='Path to VM config file or directory'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Apply all VM configs in directory'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Validate configs but do not apply changes'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Resolve path
    config_path = args.path.resolve()
    
    if not config_path.exists():
        logger.error(f"Path not found: {config_path}")
        return 1
    
    # Collect configs to apply
    if config_path.is_dir():
        if args.all:
            configs = find_vm_configs(config_path)
            if not configs:
                logger.error(f"No VirtualMachineConfig files found in {config_path}")
                return 1
            logger.info(f"Found {len(configs)} VM configuration(s) to apply")
        else:
            logger.error(f"{config_path} is a directory - use --all flag")
            return 1
    elif config_path.is_file():
        configs = [config_path]
    else:
        logger.error(f"Invalid path: {config_path}")
        return 1
    
    # Apply configurations
    orchestrator = VMConfigOrchestrator(dry_run=args.dry_run)
    
    success_count = 0
    failure_count = 0
    
    for config_file in configs:
        try:
            if orchestrator.apply_vm_config(config_file):
                success_count += 1
                logger.info(f"✓ SUCCESS: {config_file.name}")
            else:
                failure_count += 1
                logger.error(f"✗ FAILED: {config_file.name}")
        except Exception as e:
            failure_count += 1
            logger.error(f"✗ ERROR applying {config_file.name}: {e}")
    
    # Summary
    logger.info(f"\n{'='*70}")
    logger.info(f"Application Summary:")
    logger.info(f"  Total configs: {len(configs)}")
    logger.info(f"  Successful: {success_count}")
    logger.info(f"  Failed: {failure_count}")
    logger.info(f"{'='*70}")
    
    return 0 if failure_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
