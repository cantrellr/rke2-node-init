# Technical Report: Push Action Analysis

**Document Version:** 1.0  
**Report Date:** November 18, 2025  
**Script Version:** rke2nodeinit.sh v0.8b  
**Action Function:** action_push()  
**Lines:** 6325-6516

---

## Executive Summary

This report provides a comprehensive technical analysis of the `action_push()` function in the `rke2nodeinit.sh` script. This action loads cached container images from a compressed archive and pushes them to a private container registry using nerdctl. It's designed for air-gapped environments where images must be transferred to a local registry before RKE2 deployment.

**Key Operations:**
- Loads images from zstd-compressed archive (~3-5GB)
- Authenticates to private container registry
- Tags images with target registry namespace
- Pushes images to private registry with progress tracking
- Generates manifest files (JSON and text) for audit trail
- Tracks comprehensive metrics for success/failure analysis

**Dependencies:**
- nerdctl (containerd CLI)
- zstd/zstdcat (decompression utilities)
- Private container registry (accessible via network)

---

## Configuration Analysis

### YAML Configuration Example

```yaml
apiVersion: rkeprep/v1
kind: Push
metadata:
  name: registry-push-operation
spec:
  registry: kuberegistry.k8.cantrellcloud.net:8443/rke2
  registryUsername: admin
  registryPassword: <secure-password>
  rke2Version: v1.34.1+rke2r1
```

**Configuration Fields:**
- `registry` - Target registry URL with optional namespace
- `registryUsername` - Registry authentication username
- `registryPassword` - Registry authentication password (sensitive)
- `rke2Version` - RKE2 version (optional, for documentation)

**CLI Override:**
```bash
sudo bin/rke2nodeinit.sh push \
  -f push-config.yaml \
  -r kuberegistry.k8.cantrellcloud.net:8443 \
  -u admin \
  -p <password>
```

---

## Phase-by-Phase Execution Analysis

### Phase 1: Configuration Loading & Validation (Lines 6327-6361)
**Progress:** [1/4 - 25%]

**Operations:**
1. Initializes action context with `initialize_action_context false "push"`
2. Loads configuration from YAML if `CONFIG_FILE` is provided
3. Validates required parameters (registry URL)
4. Checks for default credentials and warns if detected

**Configuration Loading:**
```bash
if [[ -n "$CONFIG_FILE" ]]; then
  REGISTRY="$(yaml_spec_get "$CONFIG_FILE" registry || echo "$REGISTRY")"
  REG_USER="$(yaml_spec_get "$CONFIG_FILE" registryUsername || echo "$REG_USER")"
  REG_PASS="$(yaml_spec_get "$CONFIG_FILE" registryPassword || echo "$REG_PASS")"
  log_warn "Using YAML configuration values (CLI flags may be overridden)"
fi
```

**Validation Checks:**
- Registry URL must be non-empty
- Username and password validated (warns about defaults)
- Dependencies checked: `zstd` (with auto-install prompt)
- Images archive validated: `$DOWNLOADS_DIR/rke2-images.linux-amd64.tar.zst`

**File System Checks:**
```bash
if ! validate_file_exists "$work/$IMAGES_TAR" "images archive"; then
  log_error "Images archive not found: $work/$IMAGES_TAR"
  exit 3
fi
```

**Expected State:**
- `/opt/rke2/downloads/rke2-images.linux-amd64.tar.zst` exists
- `zstd` or `zstdcat` utility available
- Registry URL properly formatted (host[:port][/namespace])

**Failure Modes:**
- Missing images archive → Exit code 3 with remediation steps
- Invalid registry URL → Exit code 1 with usage examples
- Missing zstd dependency → Interactive install prompt or exit

---

### Phase 2: Image Loading & Manifest Generation (Lines 6362-6415)
**Progress:** [2/4 - 50%]

**Operations:**
1. Decompresses and loads images into nerdctl namespace `k8s.io`
2. Retrieves list of loaded images (excluding `<none>` tags)
3. Parses registry host and namespace from `REGISTRY` variable
4. Generates push manifest in JSON and text formats

**Image Loading Command:**
```bash
zstdcat "$work/$IMAGES_TAR" | nerdctl -n k8s.io load
```

**Alternative (if zstdcat not available):**
```bash
zstd -dc "$work/$IMAGES_TAR" | nerdctl -n k8s.io load
```

**Image Enumeration:**
```bash
nerdctl -n k8s.io images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | sort -u
```

**Registry Parsing Logic:**
```bash
local REG_HOST="$REGISTRY" REG_NS=""
[[ "$REGISTRY" == *"/"* ]] && {
  REG_HOST="${REGISTRY%%/*}"
  REG_NS="${REGISTRY#*/}"
}
```

**Examples:**
- Input: `kuberegistry.k8.cantrellcloud.net:8443` → Host: `kuberegistry.k8.cantrellcloud.net:8443`, Namespace: `` (empty)
- Input: `kuberegistry.k8.cantrellcloud.net:8443/rke2` → Host: `kuberegistry.k8.cantrellcloud.net:8443`, Namespace: `rke2`

**Manifest Generation:**

**JSON Manifest** (`/rke2-node-init/outputs/images-manifest.json`):
```json
[
  {"source":"rancher/rke2-runtime:v1.34.1","target":"kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1"},
  {"source":"rancher/hardened-kubernetes:v1.34.1","target":"kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/hardened-kubernetes:v1.34.1"},
  {"source":"rancher/mirrored-pause:3.10","target":"kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/mirrored-pause:3.10"}
]
```

**Text Manifest** (`/rke2-node-init/outputs/images-manifest.txt`):
```
rancher/rke2-runtime:v1.34.1  ->  kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1
rancher/hardened-kubernetes:v1.34.1  ->  kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/hardened-kubernetes:v1.34.1
rancher/mirrored-pause:3.10  ->  kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/mirrored-pause:3.10
```

**Metrics Tracked:**
```bash
METRICS[images_loaded]=1
METRICS[total]=<image_count>
```

**Failure Modes:**
- Archive decompression failure → Exit code 1 (check zstd installation)
- nerdctl load failure → Exit code 1 (check containerd status)
- No images found → Warning, continues (empty archive)

---

### Phase 3: Registry Authentication (Lines 6416-6443)
**Progress:** [3/4 - 75%]

**Operations:**
1. Checks for dry-run mode (`--dry-push` flag)
2. Authenticates to registry using nerdctl login
3. Validates credentials and network connectivity

**Dry-Run Mode:**
```bash
if [[ "${DRY_PUSH:-0}" -eq 1 ]]; then
  log_warn "Dry-run mode enabled (--dry-push flag)"
  log_warn "Skipping actual registry authentication and image pushes"
  metrics_summary "Push Operation (Dry-Run)"
  return 0
fi
```

**Authentication Command:**
```bash
nerdctl login "$REG_HOST" -u "$REG_USER" -p "$REG_PASS"
```

**Spinner Wrapper:**
```bash
if ! spinner_run "Logging into $REG_HOST" nerdctl login "$REG_HOST" -u "$REG_USER" -p "$REG_PASS"; then
  # Authentication failed
fi
```

**Metrics Tracked:**
```bash
METRICS[authenticated]=1
METRICS[failed]=1  # (on authentication failure)
```

**Failure Modes:**
- Invalid credentials → Exit code 1 with remediation steps
- Registry unreachable → Exit code 1 (network connectivity)
- TLS certificate verification failure → Exit code 1 (CA trust issue)
- Registry requires different auth method → Exit code 1

**Remediation Steps (on failure):**
```
Remediation steps:
  - Verify registry URL is correct: kuberegistry.k8.cantrellcloud.net:8443
  - Check username and password credentials
  - Ensure registry is accessible from this network
  - Test manually: nerdctl login kuberegistry.k8.cantrellcloud.net:8443 -u <user>
```

---

### Phase 4: Image Tagging & Push Operations (Lines 6444-6507)
**Progress:** [4/4 - 100%]

**Operations:**
1. Iterates through all loaded images
2. Tags each image with target registry path
3. Pushes tagged image to registry
4. Tracks success/failure metrics per image
5. Logs out from registry (cleanup)

**Image Processing Loop:**
```bash
local push_num=0
for IMG in "${imgs[@]}"; do
  [[ -z "$IMG" ]] && continue
  push_num=$((push_num + 1))
  
  # Construct target path
  local TARGET
  if [[ -n "$REG_NS" ]]; then
    TARGET="$REG_HOST/$REG_NS/$IMG"
  else
    TARGET="$REG_HOST/$IMG"
  fi
  
  # Tag image
  nerdctl -n k8s.io tag "$IMG" "$TARGET"
  
  # Push image
  nerdctl -n k8s.io push "$TARGET"
done
```

**Tagging Operation:**
```bash
if ! nerdctl -n k8s.io tag "$IMG" "$TARGET" >>"$LOG_FILE" 2>&1; then
  log_error "Failed to tag image: $IMG"
  metrics_increment "failed"
  report_item_failure "$IMG" "Tag operation failed"
  continue
fi
```

**Push Operation (with spinner):**
```bash
if spinner_run "Pushing $TARGET" nerdctl -n k8s.io push "$TARGET"; then
  metrics_increment "success"
  report_item_success "$IMG" "Pushed to $TARGET"
else
  log_error "Failed to push image: $TARGET"
  metrics_increment "failed"
  report_item_failure "$IMG" "Push operation failed"
fi
```

**Progress Reporting:**
```
[INFO] [1/45] Processing: rancher/rke2-runtime:v1.34.1 -> kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1
[SUCCESS] rancher/rke2-runtime:v1.34.1 - Pushed to kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1
[INFO] [2/45] Processing: rancher/hardened-kubernetes:v1.34.1 -> kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/hardened-kubernetes:v1.34.1
...
```

**Cleanup:**
```bash
nerdctl logout "$REG_HOST" >>"$LOG_FILE" 2>&1 || true
```

**Metrics Summary:**
```bash
metrics_summary "Image Push Summary"

# Output example:
================================================================================
Image Push Summary
================================================================================
Total items:     45
Successful:      45
Failed:          0
Skipped:         0
Elapsed time:    8m 32s
================================================================================
```

**Exit Status Determination:**
```bash
if metrics_should_fail; then
  log_error "Push operation completed with failures"
  return 1
else
  log_success "Image push operation completed successfully"
  log_info "All $img_count images pushed to $REG_HOST"
  return 0
fi
```

---

## Network Activity Summary

**Total Bandwidth Usage:** Varies (typically 3-5 GB for RKE2 v1.34.1)

**Outbound Connections:**

1. **Registry Authentication:**
   - Destination: `$REG_HOST` (e.g., kuberegistry.k8.cantrellcloud.net:8443)
   - Protocol: HTTPS
   - Operation: Token/basic auth exchange

2. **Image Push Operations:**
   - Destination: `$REG_HOST`
   - Protocol: HTTPS (Docker Registry API v2)
   - Data: Container image layers (3-5 GB total)
   - Compression: Layers transferred compressed

**Registry API Calls:**
- `POST /v2/auth/token` - Authentication
- `HEAD /v2/<name>/manifests/<tag>` - Check if image exists
- `POST /v2/<name>/blobs/uploads/` - Initiate layer upload
- `PUT /v2/<name>/blobs/uploads/<uuid>` - Upload layer blob
- `PUT /v2/<name>/manifests/<tag>` - Upload manifest

**Firewall Requirements:**
- Outbound HTTPS (443 or custom port) to private registry
- No inbound connections required

---

## File System Changes

### Input Files (Required Before Execution)
```
/opt/rke2/downloads/
  └── rke2-images.linux-amd64.tar.zst (3-5 GB, created by 'image' action)
```

### Output Files (Created During Execution)
```
/rke2-node-init/outputs/
  ├── images-manifest.json (JSON format manifest)
  └── images-manifest.txt (human-readable manifest)

/rke2-node-init/logs/
  └── rke2nodeinit_<timestamp>.log (detailed operation log)
```

### Temporary State Changes
```
# nerdctl namespace k8s.io
# Images loaded into containerd (persist after push completes)

nerdctl -n k8s.io images
# Shows all loaded images plus newly tagged images
```

---

## Security Implications

### Positive Security Measures

1. **Credential Validation:**
   - Warns when default credentials detected
   - Encourages override via environment or config file
   - Credentials never logged to stdout (only sanitized in YAML output)

2. **Manifest Generation:**
   - Complete audit trail of what was pushed where
   - JSON format enables automated verification
   - Tracks source → target mapping for compliance

3. **Registry Logout:**
   - Always logs out after push operations
   - Prevents credential reuse in shared environments

4. **Dry-Run Mode:**
   - `--dry-push` flag allows validation without actual push
   - Generates manifests for review before execution

### Potential Security Concerns

1. **Credentials in YAML:**
   - Risk: YAML config file contains plaintext password
   - Mitigation: File permissions (600), sanitize_yaml() masks in output
   - Residual Risk: Root compromise exposes credentials

2. **Credentials on CLI:**
   - Risk: `-p` flag visible in process listing
   - Mitigation: Prefer YAML config or environment variables
   - Residual Risk: `ps` output exposure during execution

3. **Registry TLS Validation:**
   - Concern: nerdctl may fail on self-signed certificates
   - Mitigation: Install CA certificates to system trust store
   - Alternative: Use `--insecure-registry` (not recommended for production)

4. **Image Integrity:**
   - Concern: No signature verification during push
   - Mitigation: Images loaded from verified archive (checksummed in 'image' action)
   - Residual Risk: Registry compromise could inject malicious images

### Recommendations

1. **Secure Credential Storage:**
   - Use Kubernetes Secrets for registry credentials
   - Consider external secret management (HashiCorp Vault, AWS Secrets Manager)
   - Rotate credentials regularly

2. **Registry Security:**
   - Enable TLS with valid certificates
   - Use role-based access control (RBAC)
   - Enable image scanning and admission control
   - Implement content trust (Notary, Cosign)

3. **Audit Trail:**
   - Archive manifest files for compliance
   - Correlate push operations with image scanning results
   - Monitor registry for unexpected image additions

4. **Network Security:**
   - Restrict registry access to specific subnets
   - Use private network or VPN for registry communication
   - Enable registry audit logging

---

## Metrics & Observability

### Tracked Metrics (Stored in METRICS associative array)

```bash
METRICS[images_loaded]=1              # Archive successfully loaded
METRICS[total]=45                     # Total images to push
METRICS[success]=45                   # Successfully pushed images
METRICS[failed]=0                     # Failed push operations
METRICS[skipped]=0                    # Skipped images (usually 0)
METRICS[authenticated]=1              # Registry auth successful
METRICS[push_operation_start]=<timestamp>
METRICS[push_operation_end]=<timestamp>
```

### Console Output Example

```
[INFO] Starting image push operation
[WARN] Using YAML configuration values (CLI flags may be overridden)
[INFO] Loading images from archive: /opt/rke2/downloads/rke2-images.linux-amd64.tar.zst
[1/4 - 25%] Loading images into nerdctl
[INFO] Found 45 images to process
[INFO] Target registry: kuberegistry.k8.cantrellcloud.net:8443
[INFO] Target namespace: rke2
[2/4 - 50%] Generating push manifest
[INFO] Pre-push manifest written:
[INFO]   - Text: /rke2-node-init/outputs/images-manifest.txt
[INFO]   - JSON: /rke2-node-init/outputs/images-manifest.json
[3/4 - 75%] Authenticating to registry
[INFO] Logging into registry: kuberegistry.k8.cantrellcloud.net:8443
[SUCCESS] Logged into kuberegistry.k8.cantrellcloud.net:8443
[4/4 - 100%] Pushing images to registry
[INFO] Starting image push operations (45 images)
[INFO] [1/45] Processing: rancher/rke2-runtime:v1.34.1 -> kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1
[SUCCESS] rancher/rke2-runtime:v1.34.1 - Pushed to kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1
...
[INFO] [45/45] Processing: rancher/mirrored-coredns-coredns:1.11.1 -> kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/mirrored-coredns-coredns:1.11.1
[SUCCESS] rancher/mirrored-coredns-coredns:1.11.1 - Pushed to kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/mirrored-coredns-coredns:1.11.1

================================================================================
Image Push Summary
================================================================================
Total items:     45
Successful:      45
Failed:          0
Skipped:         0
Elapsed time:    8m 32s
================================================================================

[SUCCESS] Image push operation completed successfully
[INFO] All 45 images pushed to kuberegistry.k8.cantrellcloud.net:8443
```

---

## Failure Modes & Recovery

### Failure Mode 1: Missing Images Archive

**Scenario:** Archive not found in downloads directory

**Error Message:**
```
[ERROR] Images archive not found: /opt/rke2/downloads/rke2-images.linux-amd64.tar.zst
[ERROR] Remediation steps:
[ERROR]   1. Run image action first: bin/rke2nodeinit.sh image -f config.yaml
[ERROR]   2. Verify downloads directory: /opt/rke2/downloads
[ERROR]   3. Check for disk space issues
```

**Recovery:**
1. Run `image` action to download and cache artifacts
2. Verify `/opt/rke2/downloads/` has sufficient space (5GB+ free)
3. Check file permissions on downloads directory

**Prevention:**
- Always run `image` action before `push` action
- Validate artifact presence with `ls -lh /opt/rke2/downloads/`

---

### Failure Mode 2: Registry Authentication Failure

**Scenario:** Invalid credentials or registry unreachable

**Error Message:**
```
[ERROR] Registry login failed
[ERROR] Remediation steps:
[ERROR]   - Verify registry URL is correct: kuberegistry.k8.cantrellcloud.net:8443
[ERROR]   - Check username and password credentials
[ERROR]   - Ensure registry is accessible from this network
[ERROR]   - Test manually: nerdctl login kuberegistry.k8.cantrellcloud.net:8443 -u <user>
```

**Recovery:**
1. Test registry connectivity: `curl -k https://kuberegistry.k8.cantrellcloud.net:8443/v2/`
2. Verify credentials: `nerdctl login <registry> -u <user>`
3. Check firewall rules for outbound HTTPS
4. Verify CA certificates if using self-signed certs

**Prevention:**
- Test registry access before running push
- Use valid, non-default credentials
- Ensure CA certificates installed to system trust store

---

### Failure Mode 3: Individual Image Push Failure

**Scenario:** One or more images fail to push (network timeout, disk quota)

**Error Message:**
```
[ERROR] Failed to push image: kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1
[FAILURE] rancher/rke2-runtime:v1.34.1 - Push operation failed

================================================================================
Image Push Summary
================================================================================
Total items:     45
Successful:      42
Failed:          3
Skipped:         0
Elapsed time:    8m 32s
================================================================================

[ERROR] Push operation completed with failures
[ERROR] Review error messages above and retry failed images
```

**Recovery:**
1. Check detailed logs: `grep ERROR /rke2-node-init/logs/rke2nodeinit_*.log`
2. Verify registry disk space (quota exceeded)
3. Retry push action (idempotent, skips already-pushed images)
4. For specific image: `nerdctl -n k8s.io push <target>`

**Manual Retry:**
```bash
# Re-tag and push specific failed image
nerdctl -n k8s.io tag rancher/rke2-runtime:v1.34.1 \
  kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1

nerdctl -n k8s.io push \
  kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1
```

**Prevention:**
- Ensure stable network connection
- Verify registry has sufficient storage
- Consider rate limiting or bandwidth throttling

---

## Post-Push Verification

### 1. Verify Registry Contents

**Using nerdctl:**
```bash
# List images in registry (if registry supports listing)
nerdctl -n k8s.io pull kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/rke2-runtime:v1.34.1
nerdctl -n k8s.io images | grep kuberegistry
```

**Using curl (Registry API v2):**
```bash
# List repositories
curl -k -u admin:<password> \
  https://kuberegistry.k8.cantrellcloud.net:8443/v2/_catalog

# List tags for specific repository
curl -k -u admin:<password> \
  https://kuberegistry.k8.cantrellcloud.net:8443/v2/rke2/rancher/rke2-runtime/tags/list
```

### 2. Validate Manifest Files

**Compare pushed images to manifest:**
```bash
# Count lines in manifest (should match image count)
wc -l /rke2-node-init/outputs/images-manifest.txt

# Verify JSON syntax
jq . /rke2-node-init/outputs/images-manifest.json

# Extract all target images
jq -r '.[].target' /rke2-node-init/outputs/images-manifest.json
```

### 3. Test Image Pull from Registry

**Pull test image:**
```bash
# Pull from private registry to verify accessibility
nerdctl -n k8s.io pull \
  kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/mirrored-pause:3.10

# Verify image metadata
nerdctl -n k8s.io inspect \
  kuberegistry.k8.cantrellcloud.net:8443/rke2/rancher/mirrored-pause:3.10
```

### 4. Configure RKE2 to Use Private Registry

**Update `/etc/rancher/rke2/registries.yaml`:**
```yaml
mirrors:
  docker.io:
    endpoint:
      - "https://kuberegistry.k8.cantrellcloud.net:8443"
configs:
  "kuberegistry.k8.cantrellcloud.net:8443":
    auth:
      username: admin
      password: <secure-password>
    tls:
      ca_file: /etc/rancher/rke2/ca/registry-ca.crt
```

---

## Integration with Other Actions

### Prerequisite: `image` Action

```bash
# Step 1: Prepare golden image with cached artifacts
sudo bin/rke2nodeinit.sh image -f image-config.yaml

# Step 2: Push images to private registry
sudo bin/rke2nodeinit.sh push -f push-config.yaml
```

**Data Flow:**
```
image action → /opt/rke2/downloads/rke2-images.linux-amd64.tar.zst → push action → private registry
```

### Subsequent: `server` or `agent` Actions

**After push completes, deploy RKE2 nodes:**
```bash
# Configure server to use private registry
sudo bin/rke2nodeinit.sh server -f server-config.yaml

# Configure agent to use private registry
sudo bin/rke2nodeinit.sh agent -f agent-config.yaml
```

**RKE2 will pull images from private registry instead of public sources.**

---

## Appendix A: Typical Image List (RKE2 v1.34.1)

**Core RKE2 Components** (~45 images total):

```
rancher/rke2-runtime:v1.34.1
rancher/hardened-kubernetes:v1.34.1-rke2r1
rancher/rke2-cloud-provider:v1.30.2-build20240725
rancher/mirrored-pause:3.10
rancher/mirrored-coredns-coredns:1.11.1
rancher/mirrored-calico-cni:v3.28.0
rancher/mirrored-calico-kube-controllers:v3.28.0
rancher/mirrored-calico-node:v3.28.0
rancher/mirrored-calico-pod2daemon-flexvol:v3.28.0
rancher/mirrored-calico-typha:v3.28.0
rancher/hardened-calico:v3.28.0-build20240625
rancher/mirrored-metrics-server:v0.7.1
rancher/mirrored-ingress-nginx-controller:v1.10.1
rancher/rke2-multus:v4.0.2-build20240612
rancher/hardened-addon-resizer:1.8.20-build20240410
rancher/mirrored-sig-storage-snapshot-controller:v8.0.1
rancher/mirrored-sig-storage-snapshot-validation-webhook:v8.0.1
... (28 more images)
```

**Total Size:** ~3-5 GB compressed, ~10-15 GB uncompressed

---

## Appendix B: Estimated Timings

**Based on typical hardware (4 vCPU, 8GB RAM, 1Gbps network to registry):**

| Phase | Operation | Typical Duration | Network I/O | Disk I/O |
|-------|-----------|------------------|-------------|----------|
| 1 | Configuration & Validation | 2-5 seconds | None | Read config |
| 2 | Image Loading | 2-4 minutes | None | 10-15 GB read |
| 3 | Registry Authentication | 2-5 seconds | <1 KB | None |
| 4 | Image Push (45 images) | 5-15 minutes | 3-5 GB | Read images |
| **Total** | **End-to-End** | **8-20 minutes** | **3-5 GB** | **~15 GB** |

**Variables Affecting Duration:**
- Network bandwidth to registry (bottleneck for Phase 4)
- Registry backend storage speed
- Number of images (RKE2 version dependent)
- Image layer deduplication (registry-side)

---

## Appendix C: Dry-Run Mode Usage

### Purpose

Validate push configuration without actually pushing images.

### Activation

```bash
sudo bin/rke2nodeinit.sh push -f push-config.yaml --dry-push
```

### Behavior

1. ✅ Loads images from archive
2. ✅ Generates manifest files
3. ✅ Validates registry URL format
4. ❌ **Skips** registry authentication
5. ❌ **Skips** image tagging
6. ❌ **Skips** image push operations

### Output

```
[WARN] Dry-run mode enabled (--dry-push flag)
[WARN] Skipping actual registry authentication and image pushes
[INFO] Review manifest files above to verify push targets

================================================================================
Push Operation (Dry-Run)
================================================================================
Total items:     45
Successful:      0
Failed:          0
Skipped:         45
Elapsed time:    2m 15s
================================================================================
```

### Use Cases

- Validate YAML configuration syntax
- Preview target image paths
- Generate manifest for approval workflow
- Test script logic without registry access

---

## Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-18 | GitHub Copilot | Initial technical analysis report |

---

**End of Report**
