# Phase 4 Quick Reference

**Quick access guide for Phase 4 deployment actions**

---

## Commands

### Deployment Actions

```bash
# Initialize first control plane node
sudo ./rke2nodeinit.sh server

# Deploy worker node
sudo ./rke2nodeinit.sh agent

# Add control plane node to cluster
sudo ./rke2nodeinit.sh add-server

# Create airgap VM template
sudo ./rke2nodeinit.sh airgap
```

### Global Flags

```bash
--dry-run     # Validate without making changes
--verbose     # Enable detailed logging
--quiet       # Minimal output
--version     # Show script version
--help        # Show help message
```

### Combined Examples

```bash
# Validate server configuration
sudo ./rke2nodeinit.sh --dry-run server

# Deploy agent with verbose logging
sudo ./rke2nodeinit.sh --verbose agent

# Validate add-server in quiet mode
sudo ./rke2nodeinit.sh --dry-run --quiet add-server
```

---

## Metrics Cheat Sheet

### action_server Metrics (13)

| Metric | Description |
|--------|-------------|
| `site_defaults_loaded` | Site defaults configuration loaded |
| `config_loaded` | Server configuration loaded |
| `config_validated` | Configuration validation passed |
| `tls_sans_configured` | TLS SANs configured |
| `artifacts_staged` | Artifacts staged to system |
| `hostname_set` | System hostname configured |
| `custom_ca_configured` | Custom CA certificates installed |
| `interfaces_configured` | Network interfaces configured |
| `token_generated` | Bootstrap token generated |
| `config_written` | RKE2 config.yaml written |
| `netplan_written` | Netplan configuration written |
| `rke2_installed` | RKE2 service installed |
| `flannel_fix_installed` | Flannel systemd fix applied |

### action_agent Metrics (10)

| Metric | Description |
|--------|-------------|
| `site_defaults_loaded` | Site defaults configuration loaded |
| `config_loaded` | Agent configuration loaded |
| `config_validated` | Configuration validation passed |
| `artifacts_staged` | Artifacts staged to system |
| `hostname_set` | System hostname configured |
| `interfaces_configured` | Network interfaces configured |
| `token_configured` | Cluster join token configured |
| `config_written` | RKE2 config.yaml written |
| `netplan_written` | Netplan configuration written |
| `rke2_installed` | RKE2 service installed |
| `flannel_fix_installed` | Flannel systemd fix applied |

### action_add_server Metrics (13)

| Metric | Description |
|--------|-------------|
| `site_defaults_loaded` | Site defaults configuration loaded |
| `config_loaded` | Server configuration loaded |
| `config_validated` | Configuration validation passed |
| `tls_sans_configured` | TLS SANs configured |
| `artifacts_staged` | Artifacts staged to system |
| `hostname_set` | System hostname configured |
| `custom_ca_configured` | Custom CA certificates installed |
| `interfaces_configured` | Network interfaces configured |
| `token_configured` | Cluster join token configured |
| `config_written` | RKE2 config.yaml written |
| `netplan_written` | Netplan configuration written |
| `rke2_installed` | RKE2 service installed |
| `flannel_fix_installed` | Flannel systemd fix applied |

### action_airgap Metrics (3+)

| Metric | Description |
|--------|-------------|
| `image_prepared` | RKE2 images staged (from action_image) |
| `filesystems_synced` | Filesystems synced before poweroff |
| *(plus all action_image metrics)* | Inherited from action_image |

---

## Progress Phases

### 8-Phase Standard (server, agent, add-server)

| Phase | Description |
|-------|-------------|
| 1/8 | Load Configuration |
| 2/8 | Validate Configuration |
| 3/8 | Configure Network / Stage Artifacts |
| 4/8 | Stage Artifacts / Configure System |
| 5/8 | Configure System |
| 6/8 | Configure Interfaces / Cluster Join |
| 7/8 | Write RKE2 Configuration |
| 8/8 | Install RKE2 Service |

### Phase-Specific Details

**action_server:**
1. Load site defaults + server config
2. Validate all required settings
3. Configure network (static/DHCP)
4. Stage binaries and images
5. Set hostname, install CA certs
6. Configure interfaces, generate token
7. Write RKE2 config + netplan
8. Install RKE2 server service

**action_agent:**
1. Load site defaults + agent config
2. Validate token and server URL
3. Stage binaries and images
4. Set hostname
5. Configure interfaces
6. Configure cluster join token
7. Write RKE2 config + netplan
8. Install RKE2 agent service

**action_add_server:**
1. Load site defaults + server config
2. Validate cluster join settings
3. Configure network
4. Stage binaries and images
5. Set hostname, install CA certs
6. Configure interfaces, set join token
7. Write RKE2 config + netplan
8. Install RKE2 server service

---

## Configuration Requirements

### action_server

**Required Variables:**
```yaml
CLUSTER_NAME: "my-cluster"
NODE_NAME: "server01"
PRIMARY_IP: "192.168.1.10"
```

**Optional Variables:**
```yaml
TLS_SAN:
  - "192.168.1.10"
  - "manager.example.com"
CUSTOM_CA_ENABLED: "true"
NETWORK_MODE: "static"  # or "dhcp"
```

### action_agent

**Required Variables:**
```yaml
NODE_NAME: "agent01"
PRIMARY_IP: "192.168.1.20"
CLUSTER_TOKEN: "<token-from-server>"
SERVER_URL: "https://192.168.1.10:9345"
```

**Optional Variables:**
```yaml
NODE_LABELS:
  - "node.kubernetes.io/role=worker"
NETWORK_MODE: "static"
```

### action_add_server

**Required Variables:**
```yaml
CLUSTER_NAME: "my-cluster"
NODE_NAME: "server02"
PRIMARY_IP: "192.168.1.11"
CLUSTER_TOKEN: "<token-from-first-server>"
SERVER_URL: "https://192.168.1.10:9345"
```

**Optional Variables:**
```yaml
TLS_SAN:
  - "192.168.1.11"
CUSTOM_CA_ENABLED: "true"
```

### action_airgap

**Required Variables:**
```yaml
AIRGAP_IMAGES_FILE: "/downloads/rke2-images.linux-amd64.tar.zst"
```

**Note:** Inherits all configuration from action_image

---

## Error Codes

### Common Exit Codes

| Code | Description | Remediation |
|------|-------------|-------------|
| 0 | Success | N/A |
| 1 | Configuration error | Check YAML syntax and required fields |
| 2 | Validation error | Review validation output, fix missing requirements |
| 3 | File not found | Verify file paths in configuration |
| 4 | Network error | Check network connectivity, server URL |
| 5 | Installation error | Review installation logs, check disk space |

### Common Error Patterns

**Missing Configuration:**
```
[ERROR] NODE_NAME is not set
[ERROR] Remediation: Add 'NODE_NAME: hostname' to /configs/server.yaml
```

**File Not Found:**
```
[ERROR] File not found: /downloads/install.sh
[ERROR] Remediation: Download RKE2 installation script:
[ERROR]   curl -sfL https://get.rke2.io -o /downloads/install.sh
```

**Invalid Token:**
```
[ERROR] CLUSTER_TOKEN is not set
[ERROR] Remediation: Get token from first server:
[ERROR]   cat /var/lib/rancher/rke2/server/node-token
```

---

## File Locations

### Configuration Files

```
/configs/
  site-defaults.yaml       # Site-wide defaults
  server.yaml              # Server node configuration
  agent.yaml               # Agent node configuration
  add-server.yaml          # Additional server configuration
```

### Download Files

```
/downloads/
  install.sh               # RKE2 installation script
  rke2-images.linux-amd64.tar.zst  # RKE2 container images
  sha256sum-amd64.txt      # Checksums for verification
```

### Generated Files

```
/etc/rancher/rke2/
  config.yaml              # RKE2 configuration
/etc/netplan/
  50-cloud-init.yaml       # Network configuration
/var/lib/rancher/rke2/
  server/node-token        # Cluster join token (servers only)
  agent/images/            # Staged container images
```

### Log Files

```
/var/log/rke2-install.log     # Installation log
/var/log/rke2-config.log      # Configuration log
```

---

## Quick Troubleshooting

### Deployment Validation

```bash
# Check syntax
bash -n /rke2/rke2-node-init/bin/rke2nodeinit.sh

# Validate configuration
sudo ./rke2nodeinit.sh --dry-run <action>

# Check file permissions
ls -la /configs/
ls -la /downloads/
```

### Post-Deployment Checks

```bash
# Check RKE2 service status
systemctl status rke2-server  # for server/add-server
systemctl status rke2-agent   # for agent

# View RKE2 logs
journalctl -u rke2-server -f
journalctl -u rke2-agent -f

# Check node status
kubectl get nodes  # from server node
```

### Common Issues

**Issue: Token not found**
```bash
# Get token from first server
sudo cat /var/lib/rancher/rke2/server/node-token
```

**Issue: Network not configured**
```bash
# Check netplan configuration
sudo netplan get
sudo netplan apply
```

**Issue: Artifacts not staged**
```bash
# Verify artifact files exist
ls -lh /downloads/
ls -lh /var/lib/rancher/rke2/agent/images/
```

---

## Workflow Examples

### Basic Cluster Deployment

```bash
# Step 1: Deploy first server
sudo ./rke2nodeinit.sh server --config /configs/server01.yaml

# Step 2: Get token
TOKEN=$(sudo cat /var/lib/rancher/rke2/server/node-token)

# Step 3: Deploy agents (on agent nodes)
sudo ./rke2nodeinit.sh agent --config /configs/agent01.yaml
```

### HA Control Plane

```bash
# Step 1: Deploy first server
sudo ./rke2nodeinit.sh server --config /configs/server01.yaml

# Step 2: Add servers (on other nodes)
sudo ./rke2nodeinit.sh add-server --config /configs/server02.yaml
sudo ./rke2nodeinit.sh add-server --config /configs/server03.yaml
```

### Airgap Deployment

```bash
# Step 1: Create template VM
sudo ./rke2nodeinit.sh airgap

# Step 2: Convert to template (manual/automation)
# VM will be powered off and ready

# Step 3: Clone from template
# Deploy clones with specific configs

# Step 4: Deploy RKE2 on clones
sudo ./rke2nodeinit.sh server  # on first server
sudo ./rke2nodeinit.sh add-server  # on additional servers
sudo ./rke2nodeinit.sh agent  # on workers
```

---

## Metrics Summary Format

All actions display metrics in this format:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
<ACTION> DEPLOYMENT SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Metric                      Value
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
metric_name                 1
...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Interpreting Values:**
- `1` = Operation completed successfully
- `0` = Operation not performed (usually in dry-run)
- `>1` = Multiple operations (rare, indicates loops/retries)

---

## Best Practices

### Pre-Deployment

1. **Validate configuration**
   ```bash
   sudo ./rke2nodeinit.sh --dry-run <action>
   ```

2. **Check prerequisites**
   - Network connectivity
   - DNS resolution
   - Disk space (20GB+ recommended)
   - Required files in /downloads/

3. **Review configuration files**
   - Syntax validation (YAML)
   - Required fields present
   - Values correct for environment

### During Deployment

1. **Monitor progress**
   - Watch progress phases (1/8 through 8/8)
   - Check for errors immediately
   - Review metrics summary

2. **Use verbose mode for troubleshooting**
   ```bash
   sudo ./rke2nodeinit.sh --verbose <action>
   ```

3. **Save logs**
   ```bash
   sudo ./rke2nodeinit.sh <action> 2>&1 | tee deployment.log
   ```

### Post-Deployment

1. **Verify services**
   ```bash
   systemctl status rke2-server  # or rke2-agent
   ```

2. **Check cluster status**
   ```bash
   kubectl get nodes
   kubectl get pods -A
   ```

3. **Review metrics summary**
   - Ensure all metrics show `1`
   - Investigate any `0` values (in production mode)

---

## Phase 1 Utilities Used

Phase 4 actions leverage these Phase 1 utilities:

**Validation:**
- `validate_file_exists()`
- `validate_directory_exists()`

**Logging:**
- `log_info()`
- `log_debug()`
- `log_success()`
- `log_error()`

**Metrics:**
- `metrics_init()`
- `metrics_increment()`
- `metrics_summary()`

**Progress:**
- `report_progress()`

**Safety:**
- `safe_file_write()`
- `safe_copy()`
- `safe_move()`

**Dry-Run:**
- `skip_in_dry_run()`

---

## Additional Resources

**Full Documentation:**
- [PHASE4-IMPLEMENTATION.md](PHASE4-IMPLEMENTATION.md) - Comprehensive guide
- [PHASE4-SUMMARY.md](PHASE4-SUMMARY.md) - Executive summary

**Example Configurations:**
- `examples/config/server-example.yaml`
- `examples/config/agent-example.yaml`
- `examples/config/add-server-example.yaml`
- `examples/config/airgap-example.yaml`

**Related Documentation:**
- [README.md](../README.md) - Project overview
- [ROADMAP.md](../ROADMAP.md) - Future plans

---

**Last Updated:** 2024  
**Phase Status:** ✅ COMPLETE
