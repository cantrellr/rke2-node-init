# RKE2 Node Init Configuration Examples

This directory contains example YAML configuration files for all `rke2nodeinit.sh` actions. These examples demonstrate the complete API specification and common use cases.

## Quick Start

1. Copy an example file:
   ```bash
   cp configs/examples/server-example.yaml my-config.yaml
   ```

2. Edit the configuration with your values:
   ```bash
   vim my-config.yaml
   ```

3. Run with the configuration:
   ```bash
   sudo ./bin/rke2nodeinit.sh -f my-config.yaml
   ```

## Available Examples

### Image Preparation

- **[image-example.yaml](image-example.yaml)** - Prepare air-gapped base image
  - Download RKE2 artifacts for offline installation
  - Configure network defaults for template
  - Install custom CA certificates
  - Reboots after completion

- **[airgap-example.yaml](airgap-example.yaml)** - Prepare VM template (powers off)
  - Same as Image but powers off instead of reboot
  - Ideal for creating VM templates in vSphere/Proxmox

### Registry Operations

- **[push-example.yaml](push-example.yaml)** - Push images to private registry
  - Harbor, JFrog Artifactory, and generic registry examples
  - Authentication configuration
  - Custom CA support
  - Dry-run mode for testing

### Cluster Deployment

- **[server-example.yaml](server-example.yaml)** - First control-plane server
  - Single and multi-interface configurations
  - HA setup with load balancer
  - TLS SAN configuration
  - Network CIDR settings

- **[add-server-example.yaml](add-server-example.yaml)** - Additional control-plane servers
  - Join existing cluster as control-plane
  - HA quorum setup
  - Multi-NIC configurations
  - Token-based authentication

- **[agent-example.yaml](agent-example.yaml)** - Worker nodes
  - General purpose workers
  - GPU-enabled nodes with taints
  - Storage-optimized nodes
  - Edge location workers
  - Node labels and taints

### Operations

- **[verify-example.yaml](verify-example.yaml)** - Verify prerequisites and installation
  - Pre-deployment checks
  - Post-installation validation
  - Registry connectivity verification
  - Certificate validation

- **[custom-ca-example.yaml](custom-ca-example.yaml)** - Install custom CA certificates
  - Enterprise CA chains
  - Registry-specific CAs
  - Air-gapped environment CAs
  - System trust configuration

## Configuration API Reference

### Common Fields

All configurations share these common fields:

```yaml
apiVersion: rkeprep/v1      # Required: API version
kind: <ActionKind>           # Required: One of the supported kinds
metadata:
  name: <unique-name>        # Required: Unique identifier
  description: <text>        # Optional: Human-readable description

spec:                        # Required: Action-specific configuration
  # ... fields vary by kind
```

### Supported Kinds

| Kind | Purpose | Example File |
|------|---------|--------------|
| `Image` | Prepare air-gapped base image | [image-example.yaml](image-example.yaml) |
| `Airgap` | Prepare VM template (powers off) | [airgap-example.yaml](airgap-example.yaml) |
| `Push` | Push images to registry | [push-example.yaml](push-example.yaml) |
| `Server` | First control-plane server | [server-example.yaml](server-example.yaml) |
| `AddServer` | Additional control-plane | [add-server-example.yaml](add-server-example.yaml) |
| `Agent` | Worker node | [agent-example.yaml](agent-example.yaml) |
| `Verify` | Verify prerequisites | [verify-example.yaml](verify-example.yaml) |
| `CustomCA` | Install custom CA | [custom-ca-example.yaml](custom-ca-example.yaml) |

### Network Interface Configuration

Multi-interface syntax (supported in Server, AddServer, Agent, Image, Airgap):

```yaml
spec:
  interfaces:
    - name: eth0                    # Interface name
      ip: 10.0.100.10               # Static IP address
      prefix: 24                    # CIDR prefix
      gateway: 10.0.100.1           # Default gateway
      dns:                          # DNS servers
        - 10.0.0.10
        - 10.0.0.11
      searchDomains:                # DNS search domains
        - cluster.local
        - example.com
      mtu: 1500                     # Optional: MTU size
      metric: 100                   # Optional: Route metric
    
    - name: eth1                    # Additional interface
      dhcp4: true                   # Use DHCP instead of static
```

### Registry Configuration

```yaml
spec:
  registry:
    endpoint: registry.example.com:5000/namespace  # Registry URL
    username: myuser                                # Username
    password: CHANGE-ME                             # Password (use env vars!)
    insecure: false                                 # Allow insecure (dev only)
```

### RKE2 Configuration

```yaml
spec:
  rke2:
    version: v1.34.1+rke2r1         # RKE2 version
    
    # Network settings
    nodeIp: 192.168.1.10            # Node IP for cluster communication
    bindAddress: 192.168.1.10       # API server bind address
    advertiseAddress: 192.168.1.10  # API server advertise address
    
    # Cluster networking
    clusterCidr: 10.42.0.0/16       # Pod network CIDR
    serviceCidr: 10.43.0.0/16       # Service network CIDR
    clusterDns: 10.43.0.10          # Cluster DNS IP
    clusterDomain: cluster.local    # Cluster domain
    
    # TLS configuration
    tlsSans:                        # Additional TLS SANs
      - api.example.com
      - 10.0.100.100
```

### Cluster Join Configuration

```yaml
spec:
  cluster:
    serverUrl: https://10.0.100.10:9345             # Server URL
    token: K10abc...::server:abc123                 # Join token
    tlsCertFingerprint: sha256:abc123...            # Optional: CA fingerprint
```

## Security Best Practices

### 1. Never Commit Credentials

**DO NOT commit real credentials to version control!**

Bad (DO NOT DO THIS):
```yaml
spec:
  registry:
    username: admin
    password: my-real-password-123  # ❌ NEVER!
```

Good alternatives:

**Option A: Use environment variables**
```bash
export RKE2_REGISTRY_USER="admin"
export RKE2_REGISTRY_PASS="my-real-password"
./bin/rke2nodeinit.sh -f config.yaml
```

**Option B: Use placeholder and manual entry**
```yaml
spec:
  registry:
    username: admin
    password: CHANGE-ME  # Will be prompted or set via env var
```

**Option C: Store in production configs (git-ignored)**
```bash
cp configs/examples/server-example.yaml configs/production/my-server.yaml
vim configs/production/my-server.yaml  # Edit with real values
# configs/production/ is in .gitignore
```

### 2. Protect Configuration Files

```bash
# Set restrictive permissions
chmod 600 configs/production/*.yaml

# Never share production configs
# Only use sanitized examples for documentation
```

### 3. Use the Print Option

Print sanitized configuration (masks secrets):
```bash
sudo ./bin/rke2nodeinit.sh -f config.yaml -P
```

## Common Workflows

### Workflow 1: Air-Gapped Cluster Setup

1. **Prepare base image** (online system):
   ```bash
   sudo ./bin/rke2nodeinit.sh -f configs/examples/image-example.yaml
   ```

2. **Push to registry** (system with registry access):
   ```bash
   sudo ./bin/rke2nodeinit.sh -f configs/examples/push-example.yaml
   ```

3. **Deploy first server** (offline):
   ```bash
   sudo ./bin/rke2nodeinit.sh -f configs/examples/server-example.yaml
   ```

4. **Add more servers** (offline):
   ```bash
   sudo ./bin/rke2nodeinit.sh -f configs/examples/add-server-example.yaml
   ```

5. **Add worker nodes** (offline):
   ```bash
   sudo ./bin/rke2nodeinit.sh -f configs/examples/agent-example.yaml
   ```

### Workflow 2: VM Template Creation

1. **Create template** (online system):
   ```bash
   sudo ./bin/rke2nodeinit.sh -f configs/examples/airgap-example.yaml
   # VM powers off automatically when done
   ```

2. **Clone VMs from template**
   - Use vSphere, Proxmox, or your VM platform
   - See `vm/` directory for automation scripts

3. **Deploy nodes** (offline):
   - Boot cloned VMs
   - Run server/agent configs as needed

### Workflow 3: Custom CA Installation

1. **Install CA before deployment**:
   ```bash
   sudo ./bin/rke2nodeinit.sh -f configs/examples/custom-ca-example.yaml
   ```

2. **Then deploy cluster** with registry trust already configured

### Recommended: Repeatable CA generation

For repeatable CA generation and offline workflows prefer the repository scripts and Make targets. Examples (run from repo root):

```bash
# Generate an encrypted root CA (outputs go to outputs/certs/root-<timestamp>/)
make certs-root-ca

# Generate a subordinate CA from an example YAML
make certs-sub-ca INPUT=certs/examples/rke2clusterCA-example.yaml
```

## Validation

### Validate YAML Syntax

```bash
# Check YAML syntax
yamllint configs/examples/server-example.yaml

# Validate with Python
python3 -c "import yaml; yaml.safe_load(open('configs/examples/server-example.yaml'))"
```

### Print Sanitized Configuration

```bash
# See what the script will use (secrets masked)
sudo ./bin/rke2nodeinit.sh -f configs/examples/server-example.yaml -P
```

### Verify Prerequisites

```bash
# Check system is ready before deployment
sudo ./bin/rke2nodeinit.sh -f configs/examples/verify-example.yaml
```

## CLI Override

You can override YAML values with CLI flags:

```bash
# Override registry credentials
sudo ./bin/rke2nodeinit.sh \
  -f configs/examples/push-example.yaml \
  -r registry.example.com:5000/rke2 \
  -u myuser \
  -p mypassword

# Override RKE2 version
sudo ./bin/rke2nodeinit.sh \
  -f configs/examples/server-example.yaml \
  -v v1.34.2+rke2r1
```

## Troubleshooting

### Common Issues

1. **YAML parsing errors**
   - Validate YAML syntax with `yamllint`
   - Check indentation (use spaces, not tabs)
   - Ensure proper quoting of special characters

2. **Missing required fields**
   - Each kind has required fields
   - Check example files for complete structure
   - Run with `-P` to see parsed configuration

3. **Permission errors**
   - Always run with `sudo`
   - Check file permissions on certificates/keys
   - Ensure paths are accessible

4. **Network configuration issues**
   - Verify interface names match system (`ip addr`)
   - Check CIDR notation is correct
   - Ensure gateway is reachable

## Getting Help

- **Documentation**: See main [README.md](../../README.md)
- **Troubleshooting**: See [docs/troubleshooting.md](../../docs/troubleshooting.md) (when available)
- **Issues**: Open an issue on GitHub
- **Examples**: This directory has comprehensive examples

## Contributing

Found an issue with examples or have a new use case?

1. Check [CONTRIBUTING.md](../../CONTRIBUTING.md)
2. Submit a pull request with improvements
3. Include clear description of the use case

---

**Remember**: These are EXAMPLES only. Always customize with your own values before use!
