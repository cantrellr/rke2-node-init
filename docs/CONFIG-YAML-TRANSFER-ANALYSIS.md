# RKE2 Config.yaml Transfer Analysis

## Executive Summary

This document analyzes how the `rke2nodeinit.sh` script transfers configuration options from the input YAML file to the RKE2 `config.yaml` file, validates against official RKE2 documentation, and identifies gaps or issues.

**Analysis Date:** November 11, 2025  
**Script Version:** 0.8b  
**RKE2 Documentation:** https://docs.rke2.io/reference/server_config and https://docs.rke2.io/reference/linux_agent_config

---

## Configuration Transfer Mechanism

### Primary Function: `append_spec_config_extras()`

**Location:** Lines 743-785 in `bin/rke2nodeinit.sh`

This function is responsible for transferring YAML spec options to the RKE2 config.yaml file. It is called by:
- `action_server()` - Line 4446
- `action_agent()` - Line 4686
- `action_add_server()` - Line 4946

### How It Works

1. **Duplicate Prevention:** Checks if a key already exists in config.yaml before adding it
2. **Scalar Values:** Processes single-value options
3. **List Values:** Processes array-type options (like node-labels, taints, etc.)
4. **Name Normalization:** Supports both hyphenated and camelCase variants

**Note (Nov 2025):** The implementation was updated to prefer kebab-case keys in examples while still accepting lowerCamelCase aliases (e.g., `node-ip` or `nodeIp`). A previous duplication issue where `token-file` could be emitted twice has been resolved — the script now emits `token` or `token-file` once and the preview helper was aligned.

---

## Supported Scalar Options

### Currently Supported (20 options)

The script supports the following scalar configuration options:

```bash
"cluster-cidr"                    # ✅ Valid - Server only
"service-cidr"                    # ✅ Valid - Server only  
"cluster-dns"                     # ✅ Valid - Server only
"cluster-domain"                  # ✅ Valid - Server only
"cni"                             # ✅ Valid - Server only
"system-default-registry"         # ✅ Valid - Server & Agent
"private-registry"                # ✅ Valid - Server & Agent
"write-kubeconfig-mode"           # ✅ Valid - Server only
"selinux"                         # ✅ Valid - Server & Agent
"protect-kernel-defaults"         # ✅ Valid - Server & Agent
"kube-apiserver-image"            # ✅ Valid - Server & Agent
"kube-controller-manager-image"   # ✅ Valid - Server & Agent
"kube-scheduler-image"            # ✅ Valid - Server & Agent
"etcd-image"                      # ✅ Valid - Server & Agent
"disable-cloud-controller"        # ✅ Valid - Server only
"disable-kube-proxy"              # ✅ Valid - Server only
"enable-servicelb"                # ✅ Valid - Server only
"node-ip"                         # ✅ Valid - Server & Agent
"bind-address"                    # ✅ Valid - Server only
"advertise-address"               # ✅ Valid - Server only
```

**Status:** ✅ All 20 scalar options are valid according to RKE2 documentation

---

## Supported List Options

### Currently Supported (7 options)

```bash
"kube-apiserver-arg"              # ✅ Valid - Server & Agent
"kube-controller-manager-arg"     # ✅ Valid - Server & Agent
"kube-scheduler-arg"              # ✅ Valid - Server & Agent
"kube-proxy-arg"                  # ✅ Valid - Server & Agent
"node-taint"                      # ✅ Valid - Server & Agent
"node-label"                      # ✅ Valid - Server & Agent
"tls-san"                         # ✅ Valid - Server only
```

**Status:** ✅ All 7 list options are valid according to RKE2 documentation

---

## Missing RKE2 Options (Not Currently Supported)

### High Priority Server Options (Recommended to Add)

These are commonly used options that should be supported:

#### Networking
```yaml
service-node-port-range           # ❌ Missing - Default: "30000-32767"
egress-selector-mode              # ❌ Missing - Default: "agent"
servicelb-namespace               # ❌ Missing - Default: "kube-system"
```

#### Database/Etcd
```yaml
etcd-disable-snapshots            # ❌ Missing
etcd-snapshot-schedule-cron       # ❌ Missing - Default: "0 */12 * * *"
etcd-snapshot-retention           # ❌ Missing - Default: 5
etcd-snapshot-dir                 # ❌ Missing
etcd-snapshot-compress            # ❌ Missing
etcd-expose-metrics               # ❌ Missing - Default: false
```

#### S3 Backup
```yaml
etcd-s3                           # ❌ Missing
etcd-s3-endpoint                  # ❌ Missing
etcd-s3-bucket                    # ❌ Missing
etcd-s3-region                    # ❌ Missing
etcd-s3-access-key                # ❌ Missing (sensitive)
etcd-s3-secret-key                # ❌ Missing (sensitive)
```

#### Components
```yaml
disable                           # ❌ Missing - Array of components to disable
disable-scheduler                 # ❌ Missing
ingress-controller                # ❌ Missing - "none", "ingress-nginx", "traefik"
```

#### Images
```yaml
kube-proxy-image                  # ❌ Missing (despite being listed, it's not in scalars)
pause-image                       # ❌ Missing
runtime-image                     # ❌ Missing
cloud-controller-manager-image    # ❌ Missing
```

#### Security
```yaml
profile                           # ❌ Missing - CIS profile
audit-policy-file                 # ❌ Missing
pod-security-admission-config-file # ❌ Missing
```

#### Cloud Provider
```yaml
cloud-provider-name               # ❌ Missing
cloud-provider-config             # ❌ Missing
```

#### TLS
```yaml
tls-san-security                  # ❌ Missing - Default: true
```

### High Priority Agent Options

```yaml
node-external-ip                  # ❌ Missing
resolv-conf                       # ❌ Missing
lb-server-port                    # ❌ Missing - Default: 6444
```

### Medium Priority Options

#### Server Runtime
```yaml
container-runtime-endpoint        # ❌ Missing
default-runtime                   # ❌ Missing
snapshotter                       # ❌ Missing - Default: "overlayfs"
disable-default-registry-endpoint # ❌ Missing
```

#### Server Advanced
```yaml
data-dir                          # ❌ Missing - Default: "/var/lib/rancher/rke2"
write-kubeconfig                  # ❌ Missing
helm-job-image                    # ❌ Missing
embedded-registry                 # ❌ Missing
enable-pprof                      # ❌ Missing
kubelet-path                      # ❌ Missing
```

#### Node Management
```yaml
node-name                         # ❌ Missing (though handled separately in script)
with-node-id                      # ❌ Missing
```

### Low Priority (Experimental/Advanced)

```yaml
control-plane-resource-requests   # ❌ Missing
control-plane-resource-limits     # ❌ Missing
control-plane-probe-configuration # ❌ Missing
kube-apiserver-extra-mount        # ❌ Missing
kube-scheduler-extra-mount        # ❌ Missing
kube-controller-manager-extra-mount # ❌ Missing
kube-proxy-extra-mount            # ❌ Missing
etcd-extra-mount                  # ❌ Missing
cloud-controller-manager-extra-mount # ❌ Missing
kube-apiserver-extra-env          # ❌ Missing
kube-scheduler-extra-env          # ❌ Missing
kube-controller-manager-extra-env # ❌ Missing
kube-proxy-extra-env              # ❌ Missing
etcd-extra-env                    # ❌ Missing
cloud-controller-manager-extra-env # ❌ Missing
image-credential-provider-bin-dir # ❌ Missing
image-credential-provider-config  # ❌ Missing
```

---

## Issues and Recommendations

### Issue 1: Incomplete Coverage

**Problem:** Only 27 out of 100+ valid RKE2 config options are supported.

**Impact:** Users cannot configure many important RKE2 features via the YAML input file.

**Recommendation:** Add support for high-priority options listed above, especially:
- Etcd snapshot configuration
- Security profiles (CIS)
- Additional component images
- Cloud provider settings
- Service load balancer options

### Issue 2: Missing List-Type Options

**Problem:** Several important list-type options are not supported:

```yaml
etcd-arg                          # ❌ Missing but should be supported
disable                           # ❌ Missing (array of components)
kube-cloud-controller-manager-arg # ❌ Missing
```

**Recommendation:** Add these to the `lists` array in `append_spec_config_extras()`.

### Issue 3: No Validation Against Node Type

**Problem:** The function doesn't validate whether an option is valid for the node type (server vs agent).

**Impact:** Users could configure server-only options on agent nodes, which would be ignored or cause errors.

**Recommendation:** Add validation to warn/error when incompatible options are used:
- Server-only: `cluster-cidr`, `service-cidr`, `cni`, `disable-cloud-controller`, etc.
- Agent-only: (most options are server or both)

### Issue 4: Hardcoded kubelet-arg Values

**Problem:** In all three action functions (server, agent, add-server), kubelet-arg is hardcoded:

```bash
echo "kubelet-arg:"
if [[ -f /run/systemd/resolve/resolv.conf ]]; then
  echo "  - resolv-conf=/run/systemd/resolve/resolv.conf"
fi
echo "  - container-log-max-size=10Mi"
echo "  - container-log-max-files=5"
```

**Impact:** 
- If YAML includes `kubelet-arg`, these hardcoded values will be duplicated
- `_cfg_has_key` check in `append_spec_config_extras` skips YAML kubelet-arg values
- User cannot override or extend the kubelet args

**Recommendation:** 
1. Check if YAML contains `kubelet-arg` first
2. If not, write the defaults
3. If yes, merge defaults with YAML values (avoiding duplicates)

### Issue 5: Boolean Normalization

**Problem:** `normalize_bool_value()` is called on ALL scalar values, not just booleans.

**Code Location:** Line 769
```bash
normalized="$(normalize_bool_value "$v")"
echo "$k: $normalized" >> "$cfg"
```

**Impact:** 
- Non-boolean values like "10.43.0.0/16" pass through unchanged (correct)
- But this is inefficient and semantically incorrect
- Could cause issues if normalize_bool_value changes

**Recommendation:** Only normalize known boolean fields:
```bash
case "$k" in
  selinux|protect-kernel-defaults|disable-cloud-controller|\
  disable-kube-proxy|enable-servicelb|etcd-disable-snapshots|\
  etcd-snapshot-compress|etcd-s3|tls-san-security)
    normalized="$(normalize_bool_value "$v")"
    ;;
  *)
    normalized="$v"
    ;;
esac
```

### Issue 6: CamelCase Support Incomplete

**Code Location:** Line 766
```bash
v="$(yaml_spec_get_any "$file" "$k" "$(echo "$k" | sed -E 's/-([a-z])/\U\\1/g; s/^([a-z])/\U\\1/; s/-//g')")" || true
```

**Problem:** The sed command tries to support camelCase variants but:
- Only checks one camelCase variant (capitalizing first letter)
- RKE2 official docs use hyphenated names exclusively
- This adds complexity without clear benefit

**Recommendation:** 
- Remove camelCase support OR
- Document which camelCase variants are supported
- Consider using the official hyphenated names only

---

## Test Coverage Gaps

### Missing Test Scenarios

1. **No test for scalar option transfer**
   - Should verify each supported scalar option is written correctly
   
2. **No test for list option transfer**
   - Should verify YAML arrays become proper config.yaml arrays

3. **No test for duplicate prevention**
   - Should verify _cfg_has_key prevents duplicates

4. **No test for invalid options**
   - Should verify unknown options are ignored (or warned)

5. **No test for kubelet-arg conflicts**
   - Should verify hardcoded kubelet-arg doesn't conflict with YAML

---

## Recommended Enhancements

### Short Term (High Priority)

1. **Add Missing High-Priority Options**
   ```bash
   # Add to scalars array:
   "service-node-port-range" "egress-selector-mode" "servicelb-namespace"
   "etcd-snapshot-retention" "etcd-snapshot-schedule-cron"
   "pause-image" "runtime-image" "cloud-controller-manager-image"
   "profile" "cloud-provider-name" "cloud-provider-config"
   "node-external-ip" "resolv-conf" "lb-server-port"
   ```

2. **Add Missing List Options**
   ```bash
   # Add to lists array:
   "etcd-arg" "kube-cloud-controller-manager-arg" "disable"
   ```

3. **Fix kubelet-arg Conflict**
   - Merge hardcoded values with YAML values instead of skipping

### Medium Term

4. **Add Validation**
   - Warn when server-only options used in agent config
   - Validate option values (e.g., CIDR format, port ranges)

5. **Add Tests**
   - Create test cases for config.yaml generation
   - Verify each supported option transfers correctly

### Long Term

6. **Auto-generate Support**
   - Consider parsing RKE2 schema/docs to auto-generate supported options
   - Reduce manual maintenance burden

7. **Configuration Profiles**
   - Add pre-configured profiles (minimal, standard, hardened, etc.)
   - Make it easier for users to get started

---

## Example YAML Coverage

### What Works Today ✅

```yaml
apiVersion: rkeprep/v1
kind: Server
metadata:
  name: my-server
spec:
  # Networking
  cluster-cidr: "10.42.0.0/16"
  service-cidr: "10.43.0.0/16"
  cluster-dns: "10.43.0.10"
  cluster-domain: "cluster.local"
  cni: "cilium"
  
  # Registry
  system-default-registry: "registry.example.com"
  
  # Security
  selinux: true
  protect-kernel-defaults: true
  
  # Images
  kube-apiserver-image: "custom-registry/kube-apiserver:v1.34.1"
  
  # Components
  disable-cloud-controller: false
  enable-servicelb: true
  
  # Node Configuration
  node-ip: "10.0.0.5"
  bind-address: "0.0.0.0"
  advertise-address: "10.0.0.5"
  
  # Lists
  tls-san:
    - my-server.example.com
    - 10.0.0.5
  node-label:
    - "node-role.kubernetes.io/control-plane=true"
    - "environment=production"
  kube-apiserver-arg:
    - "enable-admission-plugins=NodeRestriction"
```

### What Doesn't Work ❌

```yaml
spec:
  # These are valid RKE2 options but NOT supported by script
  service-node-port-range: "30000-32767"  # ❌ Ignored
  etcd-snapshot-retention: 10              # ❌ Ignored
  profile: "cis"                           # ❌ Ignored
  pause-image: "registry/pause:3.9"        # ❌ Ignored
  node-external-ip: "203.0.113.5"          # ❌ Ignored
  
  # This conflicts with hardcoded values
  kubelet-arg:                             # ❌ Skipped (hardcoded wins)
    - "max-pods=200"
```

---

## Conclusion

The current implementation provides **basic coverage** of RKE2 configuration options, supporting 27 out of 100+ valid options. While the core mechanism works correctly, there are significant gaps:

### Strengths ✅
- Duplicate prevention works
- Scalar and list handling is correct
- Common options are supported
- Boolean normalization functions

### Weaknesses ❌
- Only ~25% of valid options supported
- kubelet-arg hardcoded values override YAML
- No validation for node-type compatibility
- No test coverage for config transfer
- Missing important options (etcd snapshots, security profiles, etc.)

### Priority Actions
1. Add support for high-priority missing options (etcd, security, images)
2. Fix kubelet-arg conflict by merging instead of skipping
3. Add validation to prevent invalid configurations
4. Create test cases for config.yaml generation

---

## Related Files

- Script: `bin/rke2nodeinit.sh`
- Function: `append_spec_config_extras()` (lines 743-785)
- Called by: `action_server()`, `action_agent()`, `action_add_server()`
- Official Docs: 
  - https://docs.rke2.io/reference/server_config
  - https://docs.rke2.io/reference/linux_agent_config

---

**Document Version:** 1.0  
**Author:** GitHub Copilot Analysis  
**Date:** 2025-11-11
