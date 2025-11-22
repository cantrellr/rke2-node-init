#!/usr/bin/env python3
"""
VM Configuration Validator

Validates VM configuration YAML files against the JSON schema and performs
additional semantic checks for consistency and best practices.

Usage:
    python3 config_validator.py <config-file.yaml>
    python3 config_validator.py --all vm-configs/
"""

import sys
import json
import yaml
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Any

try:
    import jsonschema
    from jsonschema import validate, ValidationError, Draft7Validator
except ImportError:
    print("ERROR: jsonschema package not installed", file=sys.stderr)
    print("Install: pip3 install jsonschema", file=sys.stderr)
    sys.exit(2)


class VMConfigValidator:
    """Validates VM configuration files against schema and business rules"""
    
    def __init__(self, schema_path: Path):
        """Initialize validator with JSON schema"""
        with open(schema_path, 'r') as f:
            self.schema = json.load(f)
        self.validator = Draft7Validator(self.schema)
        self.errors = []
        self.warnings = []
    
    def validate_file(self, config_path: Path) -> Tuple[bool, List[str], List[str]]:
        """
        Validate a single VM configuration file
        
        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.errors.append(f"YAML parsing error: {e}")
            return False, self.errors, self.warnings
        except Exception as e:
            self.errors.append(f"Failed to read file: {e}")
            return False, self.errors, self.warnings
        
        # Schema validation
        try:
            self.validator.validate(config)
        except ValidationError as e:
            self.errors.append(f"Schema validation failed: {e.message}")
            return False, self.errors, self.warnings
        
        # Semantic validation
        self._validate_semantics(config, config_path)
        
        is_valid = len(self.errors) == 0
        return is_valid, self.errors, self.warnings
    
    def _validate_semantics(self, config: Dict[str, Any], config_path: Path):
        """Perform semantic validation beyond schema checks"""
        
        kind = config.get('kind')
        metadata = config.get('metadata', {})
        spec = config.get('spec', {})
        
        if kind == 'VirtualMachineConfig':
            self._validate_vm_config(config, metadata, spec, config_path)
        elif kind == 'ClusterConfig':
            self._validate_cluster_config(config, metadata, spec, config_path)
    
    def _validate_vm_config(self, config: Dict, metadata: Dict, spec: Dict, config_path: Path):
        """Validate VirtualMachineConfig-specific rules"""
        
        vm_name = metadata.get('name', '')
        
        # Check filename matches VM name
        expected_filename = f"{vm_name}.yaml"
        if config_path.name != expected_filename:
            self.warnings.append(
                f"Filename '{config_path.name}' doesn't match VM name '{vm_name}' "
                f"(expected: {expected_filename})"
            )
        
        # Validate hostname format (DNS-compatible)
        if not vm_name.replace('-', '').replace('.', '').isalnum():
            self.errors.append(
                f"VM name '{vm_name}' contains invalid characters for hostname"
            )
        
        # Check RKE2 role consistency
        rke2_config = spec.get('rke2Config', {})
        role = rke2_config.get('role')
        
        if role == 'server' and 'ctrl' not in vm_name and 'master' not in vm_name:
            self.warnings.append(
                f"VM name '{vm_name}' doesn't indicate server role (consider using ctrl/master prefix)"
            )
        
        if role == 'agent' and ('ctrl' in vm_name or 'master' in vm_name):
            self.warnings.append(
                f"VM name '{vm_name}' suggests control plane but role is 'agent'"
            )
        
        # Validate resource requirements
        hypervisor = spec.get('hypervisor', {})
        vm_settings = hypervisor.get('vmSettings', {})
        
        cpus = vm_settings.get('cpus')
        memory_mb = vm_settings.get('memoryMB')
        
        if role == 'server':
            if cpus and cpus < 2:
                self.warnings.append(
                    f"Server node has only {cpus} CPU(s) - minimum 2 CPUs recommended"
                )
            if memory_mb and memory_mb < 4096:
                self.warnings.append(
                    f"Server node has only {memory_mb}MB RAM - minimum 4GB recommended"
                )
        
        if role == 'agent':
            if cpus and cpus < 2:
                self.warnings.append(
                    f"Agent node has only {cpus} CPU(s) - minimum 2 CPUs recommended"
                )
            if memory_mb and memory_mb < 2048:
                self.warnings.append(
                    f"Agent node has only {memory_mb}MB RAM - minimum 2GB recommended"
                )
        
        # Validate guestVariables consistency
        guest_vars = hypervisor.get('guestVariables', {})
        if 'VirtualMachineName' in guest_vars:
            if guest_vars['VirtualMachineName'] != vm_name:
                self.errors.append(
                    f"guestVariables.VirtualMachineName '{guest_vars['VirtualMachineName']}' "
                    f"doesn't match metadata.name '{vm_name}'"
                )
        else:
            self.warnings.append(
                "VirtualMachineName not set in guestVariables - guest may not auto-detect hostname"
            )
    
    def _validate_cluster_config(self, config: Dict, metadata: Dict, spec: Dict, config_path: Path):
        """Validate ClusterConfig-specific rules"""
        
        cluster_name = metadata.get('name', '')
        
        # Check filename
        expected_filename = "cluster-defaults.yaml"
        if config_path.name != expected_filename:
            self.warnings.append(
                f"ClusterConfig filename should be '{expected_filename}' (got: {config_path.name})"
            )
        
        # Validate defaults structure
        defaults = spec.get('defaults', {})
        if not defaults:
            self.warnings.append("ClusterConfig has no defaults defined")


def find_all_configs(base_path: Path) -> List[Path]:
    """Find all YAML config files in directory tree"""
    configs = []
    for pattern in ['**/*.yaml', '**/*.yml']:
        configs.extend(base_path.glob(pattern))
    
    # Exclude schema files and other non-config files
    configs = [c for c in configs if c.name not in ['schema.yaml', 'schema.yml']]
    
    # Exclude rke2-configs subdirectory (different schema format)
    configs = [c for c in configs if 'rke2-configs' not in c.parts]
    
    return sorted(configs)


def main():
    parser = argparse.ArgumentParser(
        description='Validate VM configuration files against schema'
    )
    parser.add_argument(
        'path',
        type=Path,
        help='Path to config file or directory'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Validate all configs in directory (if path is directory)'
    )
    parser.add_argument(
        '--schema',
        type=Path,
        default=Path(__file__).parent.parent.parent / 'vm-configs' / 'schema.json',
        help='Path to JSON schema file'
    )
    parser.add_argument(
        '--strict',
        action='store_true',
        help='Treat warnings as errors'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )
    
    args = parser.parse_args()
    
    # Resolve paths
    config_path = args.path.resolve()
    schema_path = args.schema.resolve()
    
    if not schema_path.exists():
        print(f"ERROR: Schema file not found: {schema_path}", file=sys.stderr)
        return 2
    
    # Load validator
    try:
        validator = VMConfigValidator(schema_path)
    except Exception as e:
        print(f"ERROR: Failed to load schema: {e}", file=sys.stderr)
        return 2
    
    # Collect files to validate
    if config_path.is_dir():
        if args.all:
            config_files = find_all_configs(config_path)
            if not config_files:
                print(f"No YAML files found in {config_path}", file=sys.stderr)
                return 1
        else:
            print(f"ERROR: {config_path} is a directory - use --all flag", file=sys.stderr)
            return 1
    elif config_path.is_file():
        config_files = [config_path]
    else:
        print(f"ERROR: Path not found: {config_path}", file=sys.stderr)
        return 1
    
    # Validate all files
    results = {}
    total_errors = 0
    total_warnings = 0
    
    for config_file in config_files:
        is_valid, errors, warnings = validator.validate_file(config_file)
        
        results[str(config_file)] = {
            'valid': is_valid,
            'errors': errors,
            'warnings': warnings
        }
        
        total_errors += len(errors)
        total_warnings += len(warnings)
        
        if not args.json:
            status = "✓ VALID" if is_valid else "✗ INVALID"
            print(f"\n{status}: {config_file}")
            
            for error in errors:
                print(f"  ERROR: {error}")
            
            for warning in warnings:
                print(f"  WARNING: {warning}")
    
    # Summary
    if args.json:
        print(json.dumps({
            'total_files': len(config_files),
            'total_errors': total_errors,
            'total_warnings': total_warnings,
            'results': results
        }, indent=2))
    else:
        print(f"\n{'='*70}")
        print(f"Validation Summary:")
        print(f"  Files validated: {len(config_files)}")
        print(f"  Total errors: {total_errors}")
        print(f"  Total warnings: {total_warnings}")
        print(f"{'='*70}")
    
    # Determine exit code
    if total_errors > 0:
        return 1
    if args.strict and total_warnings > 0:
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
