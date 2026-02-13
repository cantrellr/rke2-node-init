# Technical Report: RKE2 Deployment Actions Analysis

**Document Version:** 1.0  
**Report Date:** November 18, 2025  
**Script Version:** rke2nodeinit.sh v0.8b  
**Actions Covered:** `server`, `agent`, `add-server`  
**Lines:** 7064-7423 (server), 7424-7765 (agent), 7766-8142 (add-server)

---

## Executive Summary

This report provides a comprehensive technical analysis of the three primary RKE2 deployment actions in the `rke2nodeinit.sh` script. These actions configure and install RKE2 nodes in an air-gapped environment using cached artifacts from the `image` action.

**Actions:**
1. **server** - Initialize first control plane node (cluster bootstrap)
2. **agent** - Join worker node to existing cluster
3. **add-server** - Join additional control plane node to existing cluster

**Key Operations:**
- Configure multi-interface networking with static IP or DHCP
- Set hostname and DNS resolution
- Install custom CA certificates for cluster PKI
- Generate or validate cluster join tokens
- Configure TLS SANs for control plane API
- Write RKE2 configuration (`/etc/rancher/rke2/config.yaml`)
- Apply netplan network configuration
- Install RKE2 from cached artifacts
- Deploy flannel TX checksum offload fix

**Dependencies:**
- Cached artifacts from `image` action
- netplan (network configuration)
- systemd (service management)
- RKE2 install script

---

## Action Comparison Matrix

| Feature | server | agent | add-server |
|---------|--------|-------|------------|
| **Purpose** | Bootstrap first control plane | Join worker node | Join additional control plane |
| **Cluster Init** | Yes (`clusterInit: true`) | No | No |
| **Requires Server URL** | No | Yes | Yes |
| **Requires Token** | Optional (generates) | Yes | Yes |
| **TLS SANs** | Yes (required) | No | Yes (required) |
| **Phases** | 8 | 8 | 8 |
| **Service Installed** | `rke2-server` | `rke2-agent` | `rke2-server` |
| **Port Requirements** | 6443, 9345, 10250 | 10250 | 6443, 9345, 10250 |
| **High Availability** | First node (no HA) | N/A | HA enabled |

---

## Configuration Analysis

### Server Configuration Example

```yaml
apiVersion: rkeprep/v2
kind: Server
metadata:
  name: dc1manager-ctrl01
spec:
  hostname: dc1manager-ctrl01.k8.cantrellcloud.net
  ip: 172.16.69.81
  prefix: 24
  gateway: 172.16.69.1
  dns:
    - 172.16.69.71
    - 172.16.69.72
  searchDomains:
    - k8.cantrellcloud.net
    - cantrellcloud.net
  tlsSans:
    - dc1manager-ctrl01.k8.cantrellcloud.net
    - 172.16.69.81
    - dc1manager.k8.cantrellcloud.net
    - 172.16.69.80
  token: K10abc123def456... # Optional (generated if omitted)
  clusterInit: true
  customCA:
    rootCrt: certs/rke2ca-cert.crt
    rootKey: certs/rke2ca-cert-key.pem
```

### Agent Configuration Example

```yaml
apiVersion: rkeprep/v2
kind: Agent
metadata:
  name: dc1manager-work01
spec:
  hostname: dc1manager-work01.k8.cantrellcloud.net
  ip: 172.16.69.85
  prefix: 24
  gateway: 172.16.69.1
  dns:
    - 172.16.69.71
    - 172.16.69.72
  searchDomains:
    - k8.cantrellcloud.net
  serverURL: https://172.16.69.80:9345
  token: K10abc123def456...::server:abc123...
```

### AddServer Configuration Example

```yaml
apiVersion: rkeprep/v2
kind: AddServer
metadata:
  name: dc1manager-ctrl02
spec:
  hostname: dc1manager-ctrl02.k8.cantrellcloud.net
  ip: 172.16.69.82
  prefix: 24
  gateway: 172.16.69.1
  dns:
    - 172.16.69.71
    - 172.16.69.72
  searchDomains:
    - k8.cantrellcloud.net
  serverURL: https://172.16.69.81:9345
  token: K10abc123def456...::server:abc123...
  tlsSans:
    - dc1manager-ctrl02.k8.cantrellcloud.net
    - 172.16.69.82
    - dc1manager.k8.cantrellcloud.net
    - 172.16.69.80
```

---

## Common Phase-by-Phase Analysis

All three actions follow an 8-phase execution pattern with progress tracking.

### Phase 1: Configuration Loading (Lines: server=7066-7117, agent=7426-7465, add-server=7768-7821)
**Progress:** [1/8 - 12%]

**Operations:**
1. Load site defaults from `/etc/rke2image.defaults` (if exists)
2. Read configuration from YAML file (if provided)
3. Parse CLI arguments and override YAML values
4. Validate configuration file exists and is readable

**Site Defaults Loading:**
```bash
load_site_defaults() {
  if [[ -f /etc/rke2image.defaults ]]; then
    # Source default values set during 'image' action
    source /etc/rke2image.defaults
    log_info "Loaded site defaults from /etc/rke2image.defaults"
  fi
}
```

**YAML Configuration Parsing:**
```bash
IP="$(yaml_spec_get "$CONFIG_FILE" ip || true)"
PREFIX="$(yaml_spec_get "$CONFIG_FILE" prefix || true)"
HOSTNAME="$(yaml_spec_get "$CONFIG_FILE" hostname || true)"
GW="$(yaml_spec_get "$CONFIG_FILE" gateway || true)"
DNS="$(yaml_spec_get "$CONFIG_FILE" dns || true)"
SEARCH="$(yaml_spec_get "$CONFIG_FILE" searchDomains || true)"
```

**CLI Override Example:**
```bash
# CLI arguments take precedence over YAML
if [[ -z "$IP" && -n "${server_cli[ip]:-}" ]]; then
  IP="${server_cli[ip]}"
fi
```

**Metrics Tracked:**
```bash
METRICS[site_defaults_loaded]=1
METRICS[config_loaded]=1
```

**Failure Modes:**
- Configuration file not found → Exit code 1 with error message
- YAML parsing failure → Falls back to grep-based parsing
- Invalid YAML structure → Exit code 5

---

### Phase 2: Configuration Validation (Lines: server=7118-7190, agent=7466-7530, add-server=7822-7890)
**Progress:** [2/8 - 25%]

**Operations:**
1. Merge YAML, CLI, and default values
2. Prompt for missing required fields (interactive)
3. Validate IP addresses, prefixes, DNS, search domains
4. Collect multi-interface specifications

**Interactive Prompts (if values missing):**
```bash
if [[ -z "$HOSTNAME" ]]; then
  read -rp "Enter hostname for this server node: " HOSTNAME
fi
if [[ -z "$IP" ]]; then
  read -rp "Enter static IPv4 for this server node: " IP
fi
if [[ -z "$PREFIX" ]]; then
  read -rp "Enter subnet prefix length (0-32) [default 24]: " PREFIX
fi
```

**Validation Functions:**
```bash
# IP address validation (RFC 5735 compliant)
while ! valid_ipv4 "$IP"; do
  read -rp "Invalid IPv4. Re-enter server IP: " IP
done

# Prefix validation (0-32)
while ! valid_prefix "${PREFIX:-}"; do
  read -rp "Invalid prefix (0-32). Re-enter [default 24]: " PREFIX
done

# Gateway validation (allow blank)
while ! valid_ipv4_or_blank "${GW:-}"; do
  read -rp "Invalid gateway IPv4 (or blank). Re-enter: " GW
done

# DNS validation (CSV format)
while ! valid_csv_dns "${DNS:-}"; do
  read -rp "Invalid DNS list. Re-enter CSV IPv4s: " DNS
done

# Search domains validation (DNS labels)
while ! valid_search_domains_csv "${SEARCH:-}"; do
  read -rp "Invalid search domains CSV. Re-enter: " SEARCH
done
```

**Multi-Interface Collection:**
```bash
collect_interface_specs NET_INTERFACES "$CONFIG_FILE" "${server_cli[interfaces]:-}"
merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH
```

**Metrics Tracked:**
```bash
METRICS[config_validated]=1
```

---

### Phase 3: Network Configuration (server only, Lines 7191-7203)
**Progress:** [3/8 - 37%]

**Operations (server and add-server only):**
1. Determine TLS SANs for API server certificate
2. Auto-derive SANs from hostname, IP, and search domains
3. Allow manual override via YAML or CLI

**TLS SAN Auto-Derivation:**
```bash
capture_sans() {
  local hostname="$1"
  local ip="$2"
  local search="$3"
  
  local -a sans=()
  sans+=("$hostname")
  sans+=("$ip")
  
  # Add FQDN variants with each search domain
  if [[ -n "$search" ]]; then
    local domain
    IFS=',' read -ra domains <<< "$search"
    for domain in "${domains[@]}"; do
      sans+=("${hostname}.${domain}")
    done
  fi
  
  # Deduplicate and join
  printf '%s\n' "${sans[@]}" | sort -u | paste -sd,
}
```

**Example TLS SANs:**
```
Input:
  hostname: dc1manager-ctrl01
  ip: 172.16.69.81
  search: k8.cantrellcloud.net,cantrellcloud.net

Output TLS SANs:
  172.16.69.81,
  dc1manager-ctrl01,
  dc1manager-ctrl01.cantrellcloud.net,
  dc1manager-ctrl01.k8.cantrellcloud.net
```

**Metrics Tracked:**
```bash
METRICS[tls_sans_configured]=1
```

---

### Phase 4: Artifact Staging (Lines: server=7204-7213, agent=7531-7540, add-server=7891-7900)
**Progress:** [4/8 - 50%]

**Operations:**
1. Verify cached artifacts exist in staging directory
2. Validate RKE2 binaries, install script, and images archive
3. Ensure all files readable and have expected structure

**Artifact Validation:**
```bash
ensure_staged_artifacts() {
  local STAGE_DIR="${STAGE_DIR:-/opt/rke2/stage}"
  
  # Check for RKE2 tarball
  if [[ ! -f "$STAGE_DIR/rke2.linux-amd64.tar.gz" ]]; then
    log_error "RKE2 binary archive not found: $STAGE_DIR/rke2.linux-amd64.tar.gz"
    return 1
  fi
  
  # Check for install script
  if [[ ! -f "$STAGE_DIR/install.sh" || ! -x "$STAGE_DIR/install.sh" ]]; then
    log_error "RKE2 install script not found or not executable: $STAGE_DIR/install.sh"
    return 1
  fi
  
  # Check for images archive
  local IMAGES_DIR="/var/lib/rancher/rke2/agent/images"
  if [[ ! -f "$IMAGES_DIR/rke2-images.linux-amd64.tar.zst" ]]; then
    log_warn "Images archive not found (optional): $IMAGES_DIR/rke2-images.linux-amd64.tar.zst"
  fi
  
  log_info "All required artifacts validated"
  return 0
}
```

**Expected Artifact Locations:**
```
/opt/rke2/stage/
  ├── rke2.linux-amd64.tar.gz (~50-100 MB)
  └── install.sh (~20 KB, executable)

/var/lib/rancher/rke2/agent/images/
  └── rke2-images.linux-amd64.tar.zst (~3-5 GB, optional)
```

**Metrics Tracked:**
```bash
METRICS[artifacts_staged]=1
```

**Failure Modes:**
- Missing artifacts → Exit code 3 with remediation steps
- Non-executable install script → Exit code 3
- Insufficient disk space → Exit code 3

---

### Phase 5: System Configuration (Lines: server=7214-7231, agent=7541-7555, add-server=7901-7918)
**Progress:** [5/8 - 62%]

**Operations:**
1. Set system hostname using `hostnamectl`
2. Update `/etc/hosts` with node IP and hostname
3. Install custom CA certificates (server and add-server only)
4. Prompt for additional network interfaces (if not defined in YAML)

**Hostname Configuration:**
```bash
hostnamectl set-hostname "$HOSTNAME"

# Add to /etc/hosts if not already present
if ! grep -qE "[[:space:]]$HOSTNAME(\$|[[:space:]])" /etc/hosts; then
  echo "$IP $HOSTNAME" >> /etc/hosts
fi
```

**Custom CA Setup (server/add-server only):**
```bash
setup_custom_cluster_ca() {
  if [[ -z "${CUSTOM_CA_ROOT_CRT:-}" ]]; then
    log_info "No custom CA configured, skipping"
    return 0
  fi
  
  log_info "Installing custom cluster CA certificates"
  
  # Create RKE2 PKI directory
  mkdir -p /var/lib/rancher/rke2/server/tls
  
  # Copy root CA certificate and key
  if [[ -n "${CUSTOM_CA_ROOT_CRT:-}" && -f "$CUSTOM_CA_ROOT_CRT" ]]; then
    cp "$CUSTOM_CA_ROOT_CRT" /var/lib/rancher/rke2/server/tls/server-ca.crt
    chmod 644 /var/lib/rancher/rke2/server/tls/server-ca.crt
  fi
  
  if [[ -n "${CUSTOM_CA_ROOT_KEY:-}" && -f "$CUSTOM_CA_ROOT_KEY" ]]; then
    cp "$CUSTOM_CA_ROOT_KEY" /var/lib/rancher/rke2/server/tls/server-ca.key
    chmod 600 /var/lib/rancher/rke2/server/tls/server-ca.key
  fi
  
  log_success "Custom CA installed to /var/lib/rancher/rke2/server/tls/"
}
```

**File System Changes:**
```
/etc/hostname - Updated with new hostname
/etc/hosts - Appended with IP and hostname mapping

# For server/add-server with custom CA:
/var/lib/rancher/rke2/server/tls/
  ├── server-ca.crt (644 permissions)
  └── server-ca.key (600 permissions)
```

**Metrics Tracked:**
```bash
METRICS[hostname_set]=1
METRICS[custom_ca_configured]=1
```

---

### Phase 6: Interface Configuration (Lines: server=7232-7290, agent=7556-7610, add-server=7919-7977)
**Progress:** [6/8 - 75%]

**Operations:**
1. Prompt for additional network interfaces (if not in YAML)
2. Collect interface specifications (name, IP, prefix, gateway, DNS)
3. Merge primary interface fields with collected data
4. Generate interface summary for logging

**Additional Interface Prompt:**
```bash
prompt_additional_interfaces() {
  local -n _ifaces_ref="$1"
  local default_dns="$2"
  local action="$3"
  
  echo ""
  log_info "Multi-interface networking support"
  log_info "Primary interface already configured from spec"
  log_info "You may add additional interfaces (e.g., storage, management networks)"
  
  while true; do
    read -rp "Configure an additional network interface? (y/n): " add_more
    [[ "$add_more" =~ ^[Nn] ]] && break
    
    local iface_name iface_ip iface_prefix iface_gw
    read -rp "  Interface name (e.g., eth1, ens192): " iface_name
    read -rp "  IP address: " iface_ip
    read -rp "  Prefix (default 24): " iface_prefix
    iface_prefix="${iface_prefix:-24}"
    read -rp "  Gateway (optional): " iface_gw
    
    # Validate inputs
    valid_ipv4 "$iface_ip" || continue
    valid_prefix "$iface_prefix" || continue
    
    # Encode interface specification
    local encoded
    interface_encode_entry encoded \
      "name=$iface_name" \
      "ip=$iface_ip" \
      "prefix=$iface_prefix" \
      "gateway=$iface_gw"
    
    _ifaces_ref+=("$encoded")
    log_success "Added interface: $iface_name ($iface_ip/$iface_prefix)"
  done
}
```

**Interface Summary Generation:**
```bash
# Example output:
# Network interfaces prepared: eth0:172.16.69.81/24; eth1:10.20.30.40/24; eth2:dhcp4
```

**Metrics Tracked:**
```bash
METRICS[interfaces_configured]=1
```

---

### Phase 7: RKE2 Configuration (Lines: server=7291-7350, agent=7611-7670, add-server=7978-8040)
**Progress:** [7/8 - 87%]

**Operations:**
1. Generate or validate cluster join token
2. Write RKE2 configuration to `/etc/rancher/rke2/config.yaml`
3. Apply netplan network configuration
4. Set file permissions (600) on config file

**Token Generation (server only):**
```bash
if [[ -z "$TOKEN" ]]; then
  TOKEN="$(generate_bootstrap_token)"
  log_info "Generated secure first-server bootstrap token"
fi
```

**Token Validation (agent/add-server):**
```bash
if [[ -n "$TOKEN" ]]; then
  local full_token
  full_token="$(ensure_full_cluster_token "$TOKEN")"
  if [[ -n "$full_token" && "$full_token" != "$TOKEN" ]]; then
    log_info "Expanded provided token to full format (custom CA hash included)"
    TOKEN="$full_token"
  fi
fi
```

**RKE2 Config Generation (server):**
```yaml
# /etc/rancher/rke2/config.yaml
debug: true
token: K10abc123def456...
tls-san:
  - 172.16.69.81
  - dc1manager-ctrl01.k8.cantrellcloud.net
  - dc1manager.k8.cantrellcloud.net
cluster-init: true  # Only for first server
kubelet-arg:
  - resolv-conf=/run/systemd/resolve/resolv.conf
  - container-log-max-size=10Mi
  - container-log-max-files=5
```

**RKE2 Config Generation (add-server):**
```yaml
# /etc/rancher/rke2/config.yaml
debug: true
server: https://172.16.69.81:9345
token: K10abc123def456...::server:abc123...
tls-san:
  - 172.16.69.82
  - dc1manager-ctrl02.k8.cantrellcloud.net
kubelet-arg:
  - resolv-conf=/run/systemd/resolve/resolv.conf
  - container-log-max-size=10Mi
  - container-log-max-files=5
```

**RKE2 Config Generation (agent):**
```yaml
# /etc/rancher/rke2/config.yaml
debug: true
server: https://172.16.69.81:9345
token: K10abc123def456...::server:abc123...
kubelet-arg:
  - resolv-conf=/run/systemd/resolve/resolv.conf
  - container-log-max-size=10Mi
  - container-log-max-files=5
```

**Netplan Configuration:**
```bash
write_netplan() {
  if (( ${#NET_INTERFACES[@]} )); then
    # Multi-interface mode
    write_netplan --interfaces "${NET_INTERFACES[@]}"
  else
    # Single interface mode (legacy)
    write_netplan "$IP" "$PREFIX" "${GW:-}" "${DNS:-}" "${SEARCH:-}"
  fi
}
```

**Netplan Output** (`/etc/netplan/50-rke2.yaml`):
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - 172.16.69.81/24
      routes:
        - to: default
          via: 172.16.69.1
      nameservers:
        addresses:
          - 172.16.69.71
          - 172.16.69.72
        search:
          - k8.cantrellcloud.net
          - cantrellcloud.net
```

**File Permissions:**
```bash
chmod 600 /etc/rancher/rke2/config.yaml
```

**Metrics Tracked:**
```bash
METRICS[token_generated]=1  # or METRICS[token_configured]=1
METRICS[config_written]=1
METRICS[netplan_written]=1
```

---

### Phase 8: RKE2 Installation (Lines: server=7351-7385, agent=7671-7705, add-server=8041-8075)
**Progress:** [8/8 - 100%]

**Operations:**
1. Clean up legacy containerd installations
2. Run RKE2 installer from staged artifacts
3. Enable systemd service (`rke2-server` or `rke2-agent`)
4. Deploy flannel TX checksum offload fix
5. Display summary and prompt for reboot

**Containerd Cleanup:**
```bash
cleanup_containerd_before_rke2() {
  local role="$1"  # "rke2-server" or "rke2-agent"
  
  # Stop and disable standalone containerd if present
  if systemctl is-active --quiet containerd 2>/dev/null; then
    log_warn "Stopping standalone containerd (RKE2 manages its own)"
    systemctl stop containerd || true
    systemctl disable containerd || true
  fi
  
  # Remove containerd binaries that conflict with RKE2
  if [[ -f /usr/local/bin/containerd ]]; then
    log_warn "Removing standalone containerd binary"
    rm -f /usr/local/bin/containerd
  fi
}
```

**RKE2 Installation:**
```bash
run_rke2_installer() {
  local stage_dir="$1"
  local install_type="$2"  # "server" or "agent"
  
  export INSTALL_RKE2_TYPE="$install_type"
  export INSTALL_RKE2_ARTIFACT_PATH="$stage_dir"
  
  log_info "Running RKE2 installer (type: $install_type)"
  
  if ! "$stage_dir/install.sh"; then
    log_error "RKE2 installation failed"
    return 1
  fi
  
  log_success "RKE2 $install_type installed successfully"
  return 0
}
```

**Service Enablement:**
```bash
# For server/add-server
systemctl enable rke2-server

# For agent
systemctl enable rke2-agent
```

**Flannel Fix Deployment:**
```bash
install_flannel_txcsum_fix() {
  local fix_script="/usr/local/bin/flannel-txcsum-fix.sh"
  local fix_service="/etc/systemd/system/flannel-txcsum-fix.service"
  
  # Create fix script
  cat > "$fix_script" << 'EOF'
#!/bin/bash
# Disable TX checksum offload on flannel interfaces
# Prevents checksum errors in CNI overlay network

for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -E '^flannel|^cni'); do
  ethtool -K "$iface" tx off 2>/dev/null || true
done
EOF
  
  chmod +x "$fix_script"
  
  # Create systemd service
  cat > "$fix_service" << 'EOF'
[Unit]
Description=Flannel TX Checksum Offload Fix
After=rke2-server.service rke2-agent.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/flannel-txcsum-fix.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  
  systemctl daemon-reload
  systemctl enable flannel-txcsum-fix.service
  
  log_success "Flannel TX checksum fix installed"
}
```

**Metrics Tracked:**
```bash
METRICS[rke2_installed]=1
METRICS[flannel_fix_installed]=1
```

---

## File System Changes Summary

### Server Deployment

```
/etc/hostname - Updated
/etc/hosts - Appended with hostname mapping

/etc/rancher/rke2/
  ├── config.yaml (600 permissions)
  └── server/
      └── tls/
          ├── server-ca.crt (644, if custom CA)
          └── server-ca.key (600, if custom CA)

/etc/netplan/
  └── 50-rke2.yaml (644 permissions)

/usr/local/bin/
  ├── rke2 (installed by install.sh)
  ├── kubectl (symlink to rke2)
  ├── crictl (symlink to rke2)
  └── flannel-txcsum-fix.sh (created by script)

/etc/systemd/system/
  ├── rke2-server.service (created by install.sh)
  └── flannel-txcsum-fix.service (created by script)

/var/lib/rancher/rke2/
  ├── bin/ (RKE2 binaries)
  ├── agent/
  │   └── images/ (container images)
  └── server/
      ├── manifests/ (addon manifests)
      ├── tls/ (cluster PKI)
      └── node-token (generated after first start)
```

### Agent Deployment

```
/etc/hostname - Updated
/etc/hosts - Appended

/etc/rancher/rke2/
  └── config.yaml (600 permissions)

/etc/netplan/
  └── 50-rke2.yaml

/usr/local/bin/
  ├── rke2 (symlinks)
  └── flannel-txcsum-fix.sh

/etc/systemd/system/
  ├── rke2-agent.service
  └── flannel-txcsum-fix.service

/var/lib/rancher/rke2/
  ├── bin/
  └── agent/
      └── images/
```

---

## Network Requirements

### Server (Control Plane)

**Inbound Ports:**
- 6443/TCP - Kubernetes API server (kubectl, other nodes)
- 9345/TCP - RKE2 supervisor API (join protocol for nodes)
- 10250/TCP - Kubelet metrics (Kubernetes control plane)
- 2379-2380/TCP - etcd peer communication (multi-server only)

**Outbound Ports:**
- None (air-gapped deployment)
- Optional: DNS (53/UDP) for name resolution

### Agent (Worker Node)

**Inbound Ports:**
- 10250/TCP - Kubelet metrics
- 30000-32767/TCP - NodePort services (if used)

**Outbound Ports:**
- 9345/TCP - Connect to supervisor API on server
- 6443/TCP - Connect to Kubernetes API
- None else (air-gapped)

### Add-Server (Additional Control Plane)

**Same as Server** plus:
- Must reach existing server on 9345/TCP for join

---

## Cluster Token Analysis

### Token Formats

**Short Token (32-character hex):**
```
K10abc123def456789012345678901234
```
- Used for first server (cluster init)
- Generated by `generate_bootstrap_token()`
- Stored in `/var/lib/rancher/rke2/server/node-token` after first start

**Full Token (with CA hash):**
```
K10abc123def456789012345678901234::server:abc123def456...
```
- Used for agent and add-server joins
- Includes server CA certificate hash for trust verification
- Generated by `ensure_full_cluster_token()` from short token + custom CA

**Token File Path:**
```
/var/lib/rancher/rke2/server/node-token
```
- Created by rke2-server on first successful start
- Contains full token with CA hash
- Used by agents/additional servers to join cluster

### Token Security

**Permissions:**
```bash
chmod 600 /var/lib/rancher/rke2/server/node-token
chown root:root /var/lib/rancher/rke2/server/node-token
```

**Token Rotation:**
- Tokens do not expire by default
- Rotate by generating new token and updating all nodes
- Consider using Kubernetes TokenRequest API for short-lived tokens

---

## Metrics Summary

### Server Deployment Metrics

```bash
METRICS[site_defaults_loaded]=1
METRICS[config_loaded]=1
METRICS[config_validated]=1
METRICS[tls_sans_configured]=1
METRICS[artifacts_staged]=1
METRICS[hostname_set]=1
METRICS[custom_ca_configured]=1
METRICS[interfaces_configured]=1
METRICS[token_generated]=1
METRICS[config_written]=1
METRICS[netplan_written]=1
METRICS[rke2_installed]=1
METRICS[flannel_fix_installed]=1
METRICS[server_deployment_start]=<timestamp>
METRICS[server_deployment_end]=<timestamp>
```

### Typical Console Output (Server)

```
[INFO] ========================================
[INFO] RKE2 First Server Initialization
[INFO] ========================================
[1/8 - 12%] Loading configuration
[INFO] Loading site defaults...
[INFO] Reading configuration from YAML (if provided)...
[2/8 - 25%] Validating configuration
[INFO] Prompting for any missing configuration values...
[INFO] Validating configuration...
[3/8 - 37%] Configuring network
[INFO] Determining TLS SANs...
[INFO] Auto-derived TLS SANs: 172.16.69.81,dc1manager-ctrl01,...
[4/8 - 50%] Staging RKE2 artifacts
[INFO] Ensuring staged artifacts for offline RKE2 server install...
[5/8 - 62%] Configuring system
[INFO] Setting new hostname: dc1manager-ctrl01.k8.cantrellcloud.net...
[INFO] Seeding custom cluster CA...
[6/8 - 75%] Configuring interfaces
[INFO] Network interfaces prepared: eth0:172.16.69.81/24
[7/8 - 87%] Writing RKE2 configuration
[INFO] Writing file: /etc/rancher/rke2/config.yaml...
[INFO] Writing netplan configuration and applying network settings...
[8/8 - 100%] Installing RKE2 server
[INFO] Installing rke2-server from cache at /opt/rke2/stage
[INFO] Deploying flannel TX checksum offload fix...
[SUCCESS] =========================================
[SUCCESS] Server initialization completed
[SUCCESS] =========================================

================================================================================
Server Deployment Summary
================================================================================
Total items:     13
Successful:      13
Failed:          0
Elapsed time:    3m 45s
================================================================================

[INFO] Configuration:
[INFO]   Hostname: dc1manager-ctrl01.k8.cantrellcloud.net
[INFO]   IP Address: 172.16.69.81/24
[INFO]   Gateway: 172.16.69.1
[INFO]   DNS: 172.16.69.71,172.16.69.72
[INFO]   Search Domains: k8.cantrellcloud.net,cantrellcloud.net

[INFO] Next steps:
[INFO]   1. Reboot the system to apply changes
[INFO]   2. After reboot, check cluster status: kubectl get nodes
[INFO]   3. Retrieve node token: cat /var/lib/rancher/rke2/server/node-token
[INFO]   4. Use token to join additional servers or agents

[READY] rke2-server installed. Reboot to initialize the control plane.
        First server token: /var/lib/rancher/rke2/server/node-token
```

---

## Post-Deployment Verification

### 1. Reboot System (Required)

**Why:**
- Apply netplan network changes
- Load kernel modules (br_netfilter, overlay, ip_tables)
- Initialize RKE2 services in clean state

**Command:**
```bash
sudo reboot
```

### 2. Verify RKE2 Service Status

**Server:**
```bash
sudo systemctl status rke2-server

# Expected output:
# ● rke2-server.service - Rancher Kubernetes Engine v2 (server)
#    Loaded: loaded (/etc/systemd/system/rke2-server.service; enabled)
#    Active: active (running) since ...
```

**Agent:**
```bash
sudo systemctl status rke2-agent

# Expected output:
# ● rke2-agent.service - Rancher Kubernetes Engine v2 (agent)
#    Loaded: loaded (/etc/systemd/system/rke2-agent.service; enabled)
#    Active: active (running) since ...
```

### 3. Verify Network Configuration

```bash
# Check IP addresses
ip addr show

# Check routes
ip route show

# Check DNS resolution
nslookup kubernetes.default.svc.cluster.local
```

### 4. Verify Cluster Access (Server)

```bash
# Wait for cluster to initialize (may take 1-2 minutes)
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml

# Check nodes
kubectl get nodes

# Expected output:
# NAME                                      STATUS   ROLES                       AGE   VERSION
# dc1manager-ctrl01.k8.cantrellcloud.net   Ready    control-plane,etcd,master   5m    v1.34.1+rke2r1

# Check pods
kubectl get pods -A

# Expected output: All system pods running (coredns, flannel, metrics-server, etc.)
```

### 5. Retrieve Join Token (Server)

```bash
sudo cat /var/lib/rancher/rke2/server/node-token

# Output example:
# K10abc123def456789012345678901234::server:abc123def456...
```

**Use this token for agent and add-server joins.**

---

## Failure Modes & Recovery

### Failure Mode 1: Network Configuration Error

**Scenario:** Invalid IP or conflicting network settings

**Symptoms:**
- System unreachable after reboot
- SSH connection lost
- Network interface down

**Recovery (requires console access):**
```bash
# Boot into recovery mode or connect via console
# Revert netplan changes
sudo rm /etc/netplan/50-rke2.yaml
sudo netplan apply

# Or manually fix configuration
sudo nano /etc/netplan/50-rke2.yaml
sudo netplan apply
```

**Prevention:**
- Validate network settings before reboot
- Test netplan configuration: `sudo netplan try`
- Keep backup of original netplan config
- Use `--dry-run` flag to validate without applying

---

### Failure Mode 2: RKE2 Service Fails to Start

**Scenario:** rke2-server or rke2-agent fails to start after reboot

**Error Message:**
```bash
sudo systemctl status rke2-server

# Output:
# ● rke2-server.service - Rancher Kubernetes Engine v2 (server)
#    Active: failed (Result: exit-code)
```

**Diagnosis:**
```bash
# Check logs
sudo journalctl -u rke2-server -n 100 --no-pager

# Common errors:
# - "token is required" → Missing or invalid token
# - "connection refused" → Server URL unreachable (agent/add-server)
# - "certificate verification failed" → CA trust issue
```

**Recovery:**
```bash
# Fix configuration
sudo nano /etc/rancher/rke2/config.yaml

# Restart service
sudo systemctl restart rke2-server

# Check status again
sudo systemctl status rke2-server
```

**Prevention:**
- Validate token before installation
- Test server URL connectivity (agent/add-server)
- Verify custom CA certificates are correct

---

### Failure Mode 3: Token Validation Error

**Scenario:** Agent or add-server cannot join cluster due to token mismatch

**Error Message:**
```
[ERROR] Failed to validate cluster join token
[ERROR] Token may be expired, incorrect, or CA hash mismatch
```

**Recovery:**
```bash
# On server node, retrieve fresh token
sudo cat /var/lib/rancher/rke2/server/node-token

# On agent/add-server node, update config
sudo nano /etc/rancher/rke2/config.yaml
# Update token field with fresh token

# Restart service
sudo systemctl restart rke2-agent  # or rke2-server
```

**Prevention:**
- Copy token directly from server's `/var/lib/rancher/rke2/server/node-token`
- Avoid manual token entry (use secure copy method)
- Verify token format includes `::server:` for agent joins

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-18 | GitHub Copilot | Initial comprehensive deployment actions report |

---

**End of Report**
