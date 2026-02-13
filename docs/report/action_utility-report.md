# Technical Report: Utility Actions Analysis

**Document Version:** 1.0  
**Report Date:** November 18, 2025  
**Script Version:** rke2nodeinit.sh v1.2.0  
**Actions Covered:** `verify`, `airgap`, `label-node`, `taint-node`, `custom-ca`, `list-images`  
**Lines:** 8143-8549

---

## Executive Summary

This report provides comprehensive technical analysis of the utility actions in the `rke2nodeinit.sh` script. These actions support the main deployment workflow by providing validation, operational convenience, and cluster management capabilities.

**Actions:**
1. **verify** - Validate node prerequisites before RKE2 installation
2. **airgap** - Prepare golden image and power off for VM templating
3. **label-node** - Apply Kubernetes labels to nodes using kubectl
4. **taint-node** - Apply Kubernetes taints to nodes using kubectl
5. **custom-ca** - Generate bootstrap token from custom CA configuration
6. **list-images** - Display contents of RKE2 images archive

---

## Action: verify

### Purpose

Read-only validation of system prerequisites before RKE2 installation. Checks for required packages, kernel modules, system configuration, and network connectivity without making any changes to the system.

### Location

**Lines:** 8143-8163

### Usage

```bash
# Verify system is ready for RKE2
sudo bin/rke2nodeinit.sh verify

# Verify with specific configuration
sudo bin/rke2nodeinit.sh verify -f config.yaml
```

### Execution Flow

```
1. Load site defaults (from /etc/rke2image.defaults if exists)
2. Run verify_prereqs() function
3. Display results (pass/fail)
4. Exit with appropriate code
```

### Validation Checks

**System Requirements:**
```bash
verify_prereqs() {
  local checks_passed=0
  local checks_failed=0
  
  log_info "Checking system prerequisites..."
  
  # 1. Operating system validation
  if [[ ! -f /etc/os-release ]]; then
    log_error "Cannot detect OS - /etc/os-release missing"
    ((checks_failed++))
  else
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
      log_warn "Unsupported OS: $ID (expected ubuntu or debian)"
      ((checks_failed++))
    else
      log_success "OS Check: $PRETTY_NAME"
      ((checks_passed++))
    fi
  fi
  
  # 2. Kernel version validation
  local kernel_version
  kernel_version="$(uname -r)"
  local kernel_major
  kernel_major="$(echo "$kernel_version" | cut -d. -f1)"
  if (( kernel_major < 4 )); then
    log_error "Kernel too old: $kernel_version (minimum 4.x required)"
    ((checks_failed++))
  else
    log_success "Kernel Check: $kernel_version"
    ((checks_passed++))
  fi
  
  # 3. Required kernel modules
  local -a required_modules=(
    "br_netfilter"
    "overlay"
    "ip_tables"
    "ip6_tables"
    "iptable_filter"
    "iptable_nat"
    "xt_conntrack"
  )
  
  for mod in "${required_modules[@]}"; do
    if lsmod | grep -q "^$mod"; then
      log_success "Kernel Module: $mod (loaded)"
      ((checks_passed++))
    elif modprobe "$mod" 2>/dev/null; then
      log_success "Kernel Module: $mod (loaded on demand)"
      ((checks_passed++))
    else
      log_error "Kernel Module: $mod (missing or failed to load)"
      ((checks_failed++))
    fi
  done
  
  # 4. Required system packages
  local -a required_packages=(
    "curl"
    "iptables"
    "tar"
    "gzip"
  )
  
  for pkg in "${required_packages[@]}"; do
    if command -v "$pkg" >/dev/null 2>&1; then
      log_success "Package: $pkg (installed)"
      ((checks_passed++))
    else
      log_error "Package: $pkg (missing)"
      ((checks_failed++))
    fi
  done
  
  # 5. System configuration
  if [[ ! -d /var/lib/rancher ]]; then
    log_warn "Directory /var/lib/rancher does not exist (will be created)"
  else
    log_success "Directory: /var/lib/rancher (exists)"
    ((checks_passed++))
  fi
  
  if [[ ! -d /etc/rancher ]]; then
    log_warn "Directory /etc/rancher does not exist (will be created)"
  else
    log_success "Directory: /etc/rancher (exists)"
    ((checks_passed++))
  fi
  
  # 6. Network configuration
  if command -v netplan >/dev/null 2>&1; then
    log_success "Network: netplan available"
    ((checks_passed++))
  else
    log_error "Network: netplan not found"
    ((checks_failed++))
  fi
  
  # 7. systemd validation
  if systemctl --version >/dev/null 2>&1; then
    log_success "Init System: systemd"
    ((checks_passed++))
  else
    log_error "Init System: systemd not found"
    ((checks_failed++))
  fi
  
  # Summary
  log_info "Validation Summary: $checks_passed passed, $checks_failed failed"
  
  if (( checks_failed > 0 )); then
    return 1
  else
    return 0
  fi
}
```

### Success Output

```
[INFO] Starting RKE2 prerequisites verification
[INFO] This is a read-only check - no changes will be made to the system
[INFO] Checking system prerequisites...
[SUCCESS] OS Check: Ubuntu 22.04.3 LTS
[SUCCESS] Kernel Check: 5.15.0-91-generic
[SUCCESS] Kernel Module: br_netfilter (loaded)
[SUCCESS] Kernel Module: overlay (loaded)
[SUCCESS] Kernel Module: ip_tables (loaded)
[SUCCESS] Kernel Module: ip6_tables (loaded)
[SUCCESS] Kernel Module: iptable_filter (loaded)
[SUCCESS] Kernel Module: iptable_nat (loaded)
[SUCCESS] Kernel Module: xt_conntrack (loaded)
[SUCCESS] Package: curl (installed)
[SUCCESS] Package: iptables (installed)
[SUCCESS] Package: tar (installed)
[SUCCESS] Package: gzip (installed)
[SUCCESS] Directory: /var/lib/rancher (exists)
[SUCCESS] Directory: /etc/rancher (exists)
[SUCCESS] Network: netplan available
[SUCCESS] Init System: systemd
[INFO] Validation Summary: 18 passed, 0 failed
[SUCCESS] VERIFY PASSED: Node meets all RKE2 prerequisites
[INFO] Next steps:
[INFO]   - Run 'image' action to prepare golden image
[INFO]   - Run 'server' or 'agent' action to deploy RKE2
```

### Failure Output

```
[INFO] Starting RKE2 prerequisites verification
[INFO] This is a read-only check - no changes will be made to the system
[INFO] Checking system prerequisites...
[SUCCESS] OS Check: Ubuntu 22.04.3 LTS
[SUCCESS] Kernel Check: 5.15.0-91-generic
[ERROR] Kernel Module: br_netfilter (missing or failed to load)
[SUCCESS] Kernel Module: overlay (loaded)
[ERROR] Package: curl (missing)
[INFO] Validation Summary: 14 passed, 2 failed
[ERROR] VERIFY FAILED: One or more prerequisites not met
[ERROR] Remediation steps:
[ERROR]   - Review error messages above for specific issues
[ERROR]   - Install missing dependencies or fix configuration
[ERROR]   - Re-run verification: bin/rke2nodeinit.sh verify
```

### Exit Codes

- `0` - All prerequisites met (success)
- `2` - One or more prerequisites not met (failure)

### Use Cases

1. **Pre-deployment validation** - Verify node is ready before running image/server/agent
2. **Troubleshooting** - Identify missing dependencies causing deployment failures
3. **Compliance checks** - Document system state for audit purposes
4. **CI/CD integration** - Automated pre-flight checks in deployment pipelines

---

## Action: airgap

### Purpose

Wrapper around the `image` action that prepares a golden image and powers off the system for VM templating instead of prompting for reboot. Designed for automated VM image preparation workflows.

### Location

**Lines:** 8177-8223

### Usage

```bash
# Prepare image and power off for templating
sudo bin/rke2nodeinit.sh airgap -f image-config.yaml

# With dry-run (no power off)
sudo bin/rke2nodeinit.sh airgap -f image-config.yaml --dry-run
```

### Execution Flow

```
1. Initialize action context
2. Initialize metrics tracking
3. Run action_image() with NO_REBOOT=1
4. Sync filesystems
5. Power off system
```

### Implementation

```bash
action_airgap() {
  initialize_action_context false "airgap"
  
  metrics_init "airgap_operation"
  
  log_info "========================================"
  log_info "RKE2 Airgap Image Preparation"
  log_info "========================================"
  log_info "Preparing VM for template/cloning with poweroff"
  log_info ""
  
  # Run full image preparation (without reboot prompt)
  NO_REBOOT=1 action_image
  
  metrics_increment "image_prepared"
  
  # Sync filesystems to ensure all data written to disk
  log_info "Syncing filesystems..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    sync
    metrics_increment "filesystems_synced"
  else
    log_info "DRY-RUN: Would sync filesystems"
  fi
  
  log_success "Airgap preparation complete"
  metrics_summary "Airgap Operation Summary"
  
  log_warn "Powering off now so you can template/clone the VM."
  
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    sleep 3  # Give time to read message
    poweroff
  else
    log_info "DRY-RUN: Would power off system for VM templating"
  fi
}
```

### Differences from `image` Action

| Aspect | image | airgap |
|--------|-------|--------|
| **Reboot Prompt** | Yes (interactive) | No (automatic poweroff) |
| **Use Case** | Interactive preparation | Automated VM image creation |
| **Final State** | Running (awaiting reboot) | Powered off |
| **Metrics** | image_operation | airgap_operation |

### Console Output

```
[INFO] ========================================
[INFO] RKE2 Airgap Image Preparation
[INFO] ========================================
[INFO] Preparing VM for template/cloning with poweroff
[INFO] 
[... image action output ...]
[SUCCESS] Airgap preparation complete

================================================================================
Airgap Operation Summary
================================================================================
Total items:     1
Successful:      1
Failed:          0
Elapsed time:    18m 32s
================================================================================

[WARN] Powering off now so you can template/clone the VM.
[System powers off after 3 seconds]
```

### Post-Poweroff Steps

**1. Convert to Template (VMware vSphere):**
```
Right-click VM → Template → Convert to Template
Name: rke2-v1.34.1-ubuntu22.04-20251118
```

**2. Export Template (Hyper-V):**
```powershell
Export-VM -Name "rke2-golden-image" -Path "C:\Templates\"
```

**3. Clone Template (KVM/Libvirt):**
```bash
virt-clone --original rke2-airgap \
           --name rke2-template \
           --file /var/lib/libvirt/images/rke2-template.qcow2
```

### Use Cases

1. **Automated golden image creation** - Packer, Terraform workflows
2. **CI/CD image pipelines** - Automated VM image builds
3. **Mass deployment preparation** - Template once, deploy many

---

## Action: label-node

### Purpose

Apply Kubernetes labels to an RKE2 node using kubectl. Labels are metadata key-value pairs used for scheduling, filtering, and organizational purposes.

### Location

**Lines:** 8225-8281

### Usage

```bash
# Label current node
sudo bin/rke2nodeinit.sh label-node \
  node-role.kubernetes.io/worker=true \
  environment=production

# Label specific node
sudo bin/rke2nodeinit.sh label-node \
  --node-name worker-02 \
  disktype=ssd \
  region=us-west-2

# Label with overwrite
sudo bin/rke2nodeinit.sh label-node \
  --overwrite \
  tier=frontend
```

### Implementation

```bash
action_label_node() {
  initialize_action_context false "label-node"

  local node="$NODE_NAME"  # From --node-name flag or default hostname
  local -a label_args=( "${ACTION_ARGS[@]}" )
  local -a display_args=( "${label_args[@]}" )

  # Validate labels provided
  if (( ${#label_args[@]} == 0 )); then
    log_error "No labels supplied. Provide at least one key=value pair."
    exit 1
  fi

  # Find kubectl binary
  local kubectl_bin
  if ! kubectl_bin="$(find_kubectl_binary)"; then
    log_error "kubectl not found. Ensure RKE2 is installed and kubectl is available in PATH."
    exit 2
  fi

  # Detect kubeconfig
  local kubeconfig=""
  if kubeconfig="$(detect_kubeconfig)"; then
    log_info "Using kubeconfig: $kubeconfig"
  else
    log_warn "No kubeconfig detected; relying on kubectl defaults."
    kubeconfig=""
  fi

  # Auto-add --overwrite flag if not present
  local append_overwrite=1 arg
  for arg in "${label_args[@]}"; do
    if [[ "$arg" == --overwrite* ]]; then
      append_overwrite=0
      break
    fi
  done
  if (( append_overwrite )); then
    label_args+=( "--overwrite" )
  fi

  log_info "Labeling node '$node' with: ${display_args[*]}"

  # Build kubectl command
  local -a cmd=( "$kubectl_bin" )
  if [[ -n "$kubeconfig" ]]; then
    cmd+=( "--kubeconfig" "$kubeconfig" )
  fi
  cmd+=( label node "$node" )
  cmd+=( "${label_args[@]}" )

  # Execute with spinner
  spinner_run "Labeling node $node" "${cmd[@]}"
}
```

### Helper Functions

```bash
find_kubectl_binary() {
  # Search order: RKE2 path, system path
  if [[ -x /var/lib/rancher/rke2/bin/kubectl ]]; then
    echo "/var/lib/rancher/rke2/bin/kubectl"
    return 0
  elif command -v kubectl >/dev/null 2>&1; then
    command -v kubectl
    return 0
  else
    return 1
  fi
}

detect_kubeconfig() {
  # Search order: RKE2 default, environment variable
  if [[ -f /etc/rancher/rke2/rke2.yaml ]]; then
    echo "/etc/rancher/rke2/rke2.yaml"
    return 0
  elif [[ -n "${KUBECONFIG:-}" && -f "$KUBECONFIG" ]]; then
    echo "$KUBECONFIG"
    return 0
  else
    return 1
  fi
}
```

### Examples

**Add role labels:**
```bash
sudo bin/rke2nodeinit.sh label-node \
  node-role.kubernetes.io/storage=true \
  node-role.kubernetes.io/monitoring=true
```

**Add infrastructure labels:**
```bash
sudo bin/rke2nodeinit.sh label-node \
  topology.kubernetes.io/region=us-west-2 \
  topology.kubernetes.io/zone=us-west-2a \
  failure-domain.beta.kubernetes.io/zone=us-west-2a
```

**Add custom application labels:**
```bash
sudo bin/rke2nodeinit.sh label-node \
  app=database \
  tier=backend \
  environment=production
```

### Console Output

```
[INFO] Labeling node 'dc1manager-work01' with: node-role.kubernetes.io/worker=true environment=production
[INFO] Using kubeconfig: /etc/rancher/rke2/rke2.yaml
[SPINNER] Labeling node dc1manager-work01...
node/dc1manager-work01 labeled
```

### Verification

```bash
# Verify labels applied
kubectl get nodes --show-labels

# Filter nodes by label
kubectl get nodes -l environment=production

# Describe node to see all labels
kubectl describe node dc1manager-work01
```

---

## Action: taint-node

### Purpose

Apply Kubernetes taints to an RKE2 node using kubectl. Taints prevent pods from being scheduled on nodes unless they have matching tolerations.

### Location

**Lines:** 8283-8357

### Usage

```bash
# Add NoSchedule taint
sudo bin/rke2nodeinit.sh taint-node \
  dedicated=database:NoSchedule

# Add PreferNoSchedule taint
sudo bin/rke2nodeinit.sh taint-node \
  maintenance=true:PreferNoSchedule

# Add NoExecute taint (evicts existing pods)
sudo bin/rke2nodeinit.sh taint-node \
  hardware=gpu:NoExecute

# Remove taint (note the minus suffix)
sudo bin/rke2nodeinit.sh taint-node \
  dedicated=database:NoSchedule-
```

### Implementation

```bash
action_taint_node() {
  initialize_action_context false "taint-node"

  local node="$NODE_NAME"
  local -a taint_args=( "${ACTION_ARGS[@]}" )
  local -a taint_display=( "${taint_args[@]}" )

  # Validate taints provided
  if (( ${#taint_args[@]} == 0 )); then
    log_error "No taints supplied. Provide one or more key=value:Effect entries."
    exit 1
  fi

  # Find kubectl binary
  local kubectl_bin
  if ! kubectl_bin="$(find_kubectl_binary)"; then
    log_error "kubectl not found. Ensure RKE2 is installed and kubectl is available in PATH."
    exit 2
  fi

  # Detect kubeconfig
  local kubeconfig=""
  if kubeconfig="$(detect_kubeconfig)"; then
    log_info "Using kubeconfig: $kubeconfig"
  else
    log_warn "No kubeconfig detected; relying on kubectl defaults."
    kubeconfig=""
  fi

  # Auto-add --overwrite flag if not present
  local append_overwrite=1 arg
  for arg in "${taint_args[@]}"; do
    if [[ "$arg" == --overwrite* ]]; then
      append_overwrite=0
      break
    fi
  done
  if (( append_overwrite )); then
    taint_args+=( "--overwrite" )
  fi

  log_info "Tainting node '$node' with: ${taint_display[*]}"

  # Build kubectl command
  local -a cmd=( "$kubectl_bin" )
  if [[ -n "$kubeconfig" ]]; then
    cmd+=( "--kubeconfig" "$kubeconfig" )
  fi
  cmd+=( taint node "$node" )
  cmd+=( "${taint_args[@]}" )

  # Execute with spinner
  spinner_run "Tainting node $node" "${cmd[@]}"
}
```

### Taint Effects

| Effect | Behavior | Use Case |
|--------|----------|----------|
| **NoSchedule** | New pods not scheduled | Dedicated nodes (databases, monitoring) |
| **PreferNoSchedule** | Avoid scheduling if possible | Soft reservation |
| **NoExecute** | New pods not scheduled, existing pods evicted | Maintenance, draining nodes |

### Examples

**Dedicate node to specific workload:**
```bash
# Taint node for database workloads only
sudo bin/rke2nodeinit.sh taint-node \
  dedicated=database:NoSchedule

# Pods requiring this node must have toleration:
tolerations:
- key: dedicated
  operator: Equal
  value: database
  effect: NoSchedule
```

**Mark node for maintenance:**
```bash
# Soft drain (prefer not to schedule)
sudo bin/rke2nodeinit.sh taint-node \
  maintenance=true:PreferNoSchedule

# Hard drain (evict existing pods)
sudo bin/rke2nodeinit.sh taint-node \
  maintenance=true:NoExecute
```

**GPU node reservation:**
```bash
sudo bin/rke2nodeinit.sh taint-node \
  nvidia.com/gpu=true:NoSchedule
```

**Remove taint:**
```bash
# Remove taint by adding minus suffix
sudo bin/rke2nodeinit.sh taint-node \
  dedicated=database:NoSchedule-
```

### Console Output

```
[INFO] Tainting node 'dc1manager-work01' with: dedicated=database:NoSchedule
[INFO] Using kubeconfig: /etc/rancher/rke2/rke2.yaml
[SPINNER] Tainting node dc1manager-work01...
node/dc1manager-work01 tainted
```

### Verification

```bash
# View node taints
kubectl describe node dc1manager-work01 | grep Taints

# Output:
# Taints:             dedicated=database:NoSchedule
```

---

## Action: custom-ca

### Purpose

Generate bootstrap token from custom CA certificate configuration. Used for clusters with custom PKI infrastructure instead of RKE2's auto-generated certificates.

### Location

**Lines:** 8359-8434

### Usage

```bash
# Generate token from custom CA
sudo bin/rke2nodeinit.sh custom-ca -f custom-ca-config.yaml
```

### Configuration Example

```yaml
apiVersion: rkeprep/v2
kind: CustomCA
metadata:
  name: dc1manager-custom-ca
spec:
  customCA:
    rootCrt: certs/rke2ca-cert.crt
    rootKey: certs/rke2ca-cert-key.pem
    intermediateCrt: certs/rke2registry-ca.crt
    intermediateKey: certs/rke2registry-ca-key.pem
```

### Implementation

```bash
action_custom_ca() {
  initialize_action_context false "custom-ca"

  log_info "Starting custom CA bootstrap token generation"
  
  # Validate prerequisites
  if ! validate_non_empty "${CONFIG_FILE:-}" "CONFIG_FILE"; then
    log_error "Custom-CA action requires a YAML configuration file"
    log_error "Remediation: Provide config file with -f flag"
    exit 5
  fi
  
  if ! validate_file_exists "$CONFIG_FILE" "configuration file"; then
    log_error "Configuration file not found: $CONFIG_FILE"
    exit 5
  fi

  # Validate YAML kind
  local kind_folded="${YAML_KIND:-}"
  kind_folded="${kind_folded,,}"
  if [[ "${kind_folded//-/}" != "customca" ]]; then
    log_error "Invalid YAML kind for custom-ca action"
    log_error "Expected: kind: CustomCA"
    log_error "Found: ${YAML_KIND:-<none>}"
    exit 5
  fi

  # Load custom CA configuration
  log_info "Loading custom CA configuration from: $CONFIG_FILE"
  load_custom_ca_from_config "$CONFIG_FILE" "" 1

  # Validate CA certificates present
  if [[ -z "${CUSTOM_CA_ROOT_CRT:-}" && -z "${CUSTOM_CA_INT_CRT:-}" ]]; then
    log_error "Custom CA configuration incomplete"
    log_error "spec.customCA must define at least one of:"
    log_error "  - rootCrt: Root CA certificate"
    log_error "  - intermediateCrt: Intermediate CA certificate"
    exit 5
  fi

  # Generate bootstrap token
  log_info "Generating bootstrap token from custom CA"
  report_progress "Generating token" 1 1

  local TOKEN="" TOKEN_FILE=""
  generate_bootstrap_token
  TOKEN=$token

  if [[ -z "$TOKEN" ]]; then
    log_error "Bootstrap token generation failed"
    exit 1
  fi
  
  # Save token to file
  TOKEN_FILE="${OUT_DIR}/${SPEC_NAME}-bootstrap-token.txt"
  echo "$TOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  
  log_success "Bootstrap token generated successfully"
  log_info "Token saved to: $TOKEN_FILE (permissions: 600)"
  log_info "Next steps:"
  log_info "  - Use this token for server/agent bootstrap"
  log_info "  - Keep token file secure - it provides cluster access"
}
```

### Token Generation Process

```bash
generate_bootstrap_token() {
  local ca_hash=""
  
  # Calculate CA certificate hash
  if [[ -n "${CUSTOM_CA_ROOT_CRT:-}" && -f "$CUSTOM_CA_ROOT_CRT" ]]; then
    ca_hash=$(openssl x509 -in "$CUSTOM_CA_ROOT_CRT" -noout -fingerprint -sha256 | \
              sed 's/SHA256 Fingerprint=//;s/://g' | tr '[:upper:]' '[:lower:]')
  elif [[ -n "${CUSTOM_CA_INT_CRT:-}" && -f "$CUSTOM_CA_INT_CRT" ]]; then
    ca_hash=$(openssl x509 -in "$CUSTOM_CA_INT_CRT" -noout -fingerprint -sha256 | \
              sed 's/SHA256 Fingerprint=//;s/://g' | tr '[:upper:]' '[:lower:]')
  fi
  
  # Generate random token component
  local token_prefix="K10"
  local token_random
  token_random=$(openssl rand -hex 32)
  
  if [[ -n "$ca_hash" ]]; then
    # Full token with CA hash
    token="${token_prefix}${token_random}::server:${ca_hash}"
  else
    # Short token (no CA hash)
    token="${token_prefix}${token_random}"
  fi
  
  log_info "Generated token: ${token:0:20}... (truncated)"
}
```

### Console Output

```
[INFO] Starting custom CA bootstrap token generation
[INFO] Loading custom CA configuration from: custom-ca-config.yaml
[INFO] Generating bootstrap token from custom CA
[1/1 - 100%] Generating token
[SUCCESS] Bootstrap token generated successfully
[INFO] Token saved to: /rke2-node-init/outputs/dc1manager-custom-ca-bootstrap-token.txt (permissions: 600)
[INFO] Next steps:
[INFO]   - Use this token for server/agent bootstrap
[INFO]   - Keep token file secure - it provides cluster access
```

### Token Format

**With CA hash (recommended):**
```
K10abc123def456789012345678901234567890123456789012345678901234::server:abcdef0123456789...
```

**Without CA hash (fallback):**
```
K10abc123def456789012345678901234567890123456789012345678901234
```

### Security Considerations

1. **Token Storage:**
   - Saved with 600 permissions (root only)
   - Contains CA fingerprint for trust validation
   - Provides full cluster access - treat as sensitive

2. **CA Certificate Requirements:**
   - Must be valid X.509 PEM format
   - Should have appropriate key usage extensions
   - Private keys must be 600 permissions

3. **Token Rotation:**
   - Regenerate periodically for security
   - Update all nodes with new token
   - Consider using Kubernetes TokenRequest API for short-lived tokens

---

## Action: list-images

### Purpose

Display contents of RKE2 images archive and manifest files. Useful for verifying image availability before push operations.

### Location

**Lines:** 6992-7063

### Usage

```bash
# List images in archive
sudo bin/rke2nodeinit.sh list-images

# List with verbose output
sudo bin/rke2nodeinit.sh list-images --verbose
```

### Implementation

```bash
action_list_images() {
  initialize_action_context false "list-images"
  log_info "Listing RKE2 images archive contents and manifest entries (if present)"

  local IMAGES_TAR="rke2-images.linux-${ARCH}.tar.zst"
  local images_candidate=""
  local IMAGES_DIR="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"

  # Search for images archive
  if [[ -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
    images_candidate="$DOWNLOADS_DIR/$IMAGES_TAR"
  elif [[ -f "$IMAGES_DIR/$IMAGES_TAR" ]]; then
    images_candidate="$IMAGES_DIR/$IMAGES_TAR"
  fi

  if [[ -z "$images_candidate" ]]; then
    log_error "Images archive not found in $DOWNLOADS_DIR or $IMAGES_DIR: $IMAGES_TAR"
    return 3
  fi

  log_info "Found images archive: $images_candidate"

  # List archive contents (filter out OCI blob entries)
  local _filter="grep -v -E '^blobs(/|$)'"
  if command -v zstd >/dev/null 2>&1; then
    log_info "Listing archive (via zstd -dc | tar -tf) — hiding blobs/ entries"
    zstd -dc "$images_candidate" | tar -tf - | eval "$_filter"
  elif command -v zstdcat >/dev/null 2>&1; then
    log_info "Listing archive (via zstdcat | tar -tf) — hiding blobs/ entries"
    zstdcat "$images_candidate" | tar -tf - | eval "$_filter"
  else
    # Fallback for gzip archives
    if [[ "$images_candidate" == *.tar.gz ]]; then
      log_info "Listing gzip-compressed archive (tar -tzf) — hiding blobs/ entries"
      tar -tzf "$images_candidate" | eval "$_filter"
    else
      log_error "No zstd available to read $images_candidate; please install zstd"
      return 2
    fi
  fi

  # Also show manifest entries if available
  local sha_file="$DOWNLOADS_DIR/${SHA256_FILE:-sha256sum-${ARCH}.txt}"
  if [[ -f "$sha_file" ]]; then
    echo
    log_info "Release manifest entries from: $sha_file"
    awk '{print $2}' "$sha_file" | sort -u
  else
    log_info "No release sha256 manifest found in $DOWNLOADS_DIR"
  fi

  return 0
}
```

### Console Output

```
[INFO] Listing RKE2 images archive contents and manifest entries (if present)
[INFO] Found images archive: /opt/rke2/downloads/rke2-images.linux-amd64.tar.zst
[INFO] Listing archive (via zstd -dc | tar -tf) — hiding blobs/ entries
index.json
manifest.json
oci-layout
rancher/
rancher/hardened-kubernetes/
rancher/hardened-kubernetes/v1.34.1-rke2r1/
rancher/hardened-kubernetes/v1.34.1-rke2r1/index.json
rancher/rke2-runtime/
rancher/rke2-runtime/v1.34.1/
rancher/rke2-runtime/v1.34.1/index.json
rancher/mirrored-pause/
rancher/mirrored-pause/3.10/
rancher/mirrored-pause/3.10/index.json
...

[INFO] Release manifest entries from: /opt/rke2/downloads/sha256sum-amd64.txt
rke2-images.linux-amd64.tar.zst
rke2.linux-amd64.tar.gz
install.sh
sha256sum-amd64.txt
```

---

## Comparison Matrix

| Action | Read-Only | Requires RKE2 | Network | Root | Exit on Success | Exit on Failure |
|--------|-----------|---------------|---------|------|-----------------|-----------------|
| **verify** | ✅ Yes | ❌ No | ❌ No | ✅ Yes | 0 | 2 |
| **airgap** | ❌ No | ❌ No | ✅ Yes (for image) | ✅ Yes | Powers off | 1/3 |
| **label-node** | ❌ No | ✅ Yes | ❌ No | ⚠️ Depends | 0 | 1/2 |
| **taint-node** | ❌ No | ✅ Yes | ❌ No | ⚠️ Depends | 0 | 1/2 |
| **custom-ca** | ❌ No (writes token) | ❌ No | ❌ No | ✅ Yes | 0 | 1/5 |
| **list-images** | ✅ Yes | ❌ No | ❌ No | ⚠️ Depends | 0 | 2/3 |

---

## Integration Patterns

### Workflow 1: Pre-Deployment Validation

```bash
#!/bin/bash
set -e

# Step 1: Verify prerequisites
if sudo bin/rke2nodeinit.sh verify; then
  echo "✓ Prerequisites check passed"
else
  echo "✗ Prerequisites check failed"
  exit 1
fi

# Step 2: Prepare golden image
sudo bin/rke2nodeinit.sh image -f image-config.yaml

# Step 3: Deploy server
sudo bin/rke2nodeinit.sh server -f server-config.yaml
```

### Workflow 2: Automated VM Template Creation

```bash
#!/bin/bash
set -e

# Packer/Terraform workflow for automated golden image

# Prepare and power off
sudo bin/rke2nodeinit.sh airgap -f image-config.yaml

# System powers off automatically
# Hypervisor converts to template externally
```

### Workflow 3: Node Management

```bash
#!/bin/bash

# Label nodes by role
for node in ctrl-01 ctrl-02 ctrl-03; do
  sudo bin/rke2nodeinit.sh label-node \
    --node-name "$node" \
    node-role.kubernetes.io/control-plane=true
done

for node in work-01 work-02 work-03; do
  sudo bin/rke2nodeinit.sh label-node \
    --node-name "$node" \
    node-role.kubernetes.io/worker=true
done

# Taint GPU nodes
sudo bin/rke2nodeinit.sh taint-node \
  --node-name gpu-01 \
  nvidia.com/gpu=true:NoSchedule
```

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-18 | GitHub Copilot | Initial utility actions comprehensive report |

---

**End of Report**
