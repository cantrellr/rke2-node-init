#!/usr/bin/env bash
#
# If not running under bash, re-exec with bash
if [[ -z "$BASH_VERSION" ]]; then
  exec bash "$0" "$@"
fi

# Fail if not root
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: please run this script as root (use sudo)."
  exit 1
fi

# Fail fast on CRLF (Windows) endings, which can also trigger odd parse errors
case "$(head -c 2 "$0" | od -An -t x1 | tr -d ' ')" in
  *0d0a) echo "ERROR: Windows line endings detected. Run: dos2unix '$0'"; exit 2;;
esac

# ----------------------------------------------------
# rke2nodeinit.sh
# ----------------------------------------------------
#
#       Version: 1.2.0 (multi-interface support)
#       Written by: Ron Cantrell
#           Github: cantrellr
#            Email: charlescantrelljr@outlook.com
#
# ----------------------------------------------------
# Purpose:
#   Prepare and configure a Linux VM/host (Ubuntu/Debian-based) for an offline/air-gapped
#   Rancher RKE2 Kubernetes deployment using official RKE2 Rancher images with support for
#   multi-interface networking configurations.
#
# Actions:
#   1) push         - Tag and push preloaded images into a private registry (nerdctl)
#   2) image        - Stage artifacts, registries config, CA certs, and OS prereqs for offline use
#   3) server       - Configure multi-interface network, hostname, and install rke2-server (offline)
#   4) add-server   - Add additional control-plane node to existing cluster (offline)
#   5) agent        - Configure multi-interface network, hostname, and install rke2-agent (offline)
#   6) verify       - Check that node prerequisites are in place without making changes
#   7) airgap       - Run 'image' without reboot and power off the machine for templating
#   8) label-node   - Apply Kubernetes labels to an RKE2 node
#   9) taint-node   - Apply Kubernetes taints to an RKE2 node
#  10) custom-ca    - Generate first-server token from custom CA specified in YAML
#
# Connectivity expectations:
#   - image is the ONLY action that requires Internet access to gather artifacts
#   - All other actions (push, server, add-server, agent, verify, label-node,
#     taint-node, custom-ca) are designed to run fully offline
#
# Key features in this version:
#   - Multi-interface networking: Configure multiple NICs with static IPs or DHCP
#   - Deferred netplan application: Network changes apply on reboot (use --apply-netplan-now to override)
#   - Enhanced RKE2 config support: node-ip, bind-address, advertise-address, and more
#   - Custom CA integration: Support for custom cluster certificates
#   - Node management: Label and taint nodes via kubectl integration
#   - Offline-first design: All artifacts cached locally for air-gapped deployments
#   - Progress indicators: Spinner feedback for long-running operations
#   - YAML-driven configuration: apiVersion rkeprep/v2 with comprehensive spec options
#
# Major architectural improvements:
#   - Multi-interface support via YAML spec.interfaces[] or --interface CLI args
#   - Network configuration deferred to reboot by default (safer for remote operations)
#   - Enhanced YAML parsing with Python fallback for complex nested structures
#   - Automatic primary interface detection when name not specified
#   - Support for per-interface DNS, search domains, MTU, and routing metrics
#   - Custom CA certificate installation and trust chain management
#   - Token generation with embedded CA fingerprints for secure cluster joins
#   - Comprehensive prerequisite validation (verify action)
#
# Safety features:
#   - set -Eeuo pipefail (fail fast on errors)
#   - Global ERR trap with line number reporting
#   - Root privilege enforcement
#   - Strong input validation for IP addresses, CIDR prefixes, DNS, and search domains
#   - CRLF (Windows line ending) detection and rejection
#   - Credential masking in sanitized YAML output
#   - Warning for default/example credentials
#
# YAML configuration (apiVersion: rkeprep/v2):
#   Supported kinds: Push, Image, Server, AddServer, Agent, Verify, Airgap, CustomCA
#   Required: metadata.name for all configurations
#   Multi-interface syntax:
#     spec.interfaces:
#       - name: eth0
#         ip: 10.0.0.5
#         prefix: 24
#         gateway: 10.0.0.1
#         dns: [8.8.8.8, 8.8.4.4]
#         searchDomains: [example.com]
#       - name: eth1
#         dhcp4: true
#
# CLI flags:
#   -f FILE               YAML config file (apiVersion: rkeprep/v2)
#   -v VERSION            RKE2 version tag (e.g., v1.34.1+rke2r1)
#   -r REGISTRY           Private registry (host[/namespace])
#   -u USER               Registry username
#   -p PASS               Registry password
#   -n NAME               Node name for label-node/taint-node (defaults to hostname)
#   -y                    Auto-confirm prompts (reboots, cleanup)
#   -P                    Print sanitized YAML (masks secrets)
#   -h                    Show help
#   --dry-push            Simulate registry push without actually pushing
#   --apply-netplan-now   Apply netplan immediately instead of deferring to reboot
#   --node-name NAME      Alias for -n (node name)
#   --interface ...       Define interface via CLI (name=X ip=X prefix=X gateway=X dns=X search=X)
#
# Exit codes:
#   0 = success
#   1 = usage error / invalid arguments
#   2 = missing prerequisites / validation failure
#   3 = missing required data / artifacts
#   4 = registry authentication failure
#   5 = YAML parsing or validation issues
# ----------------------------------------------------------------------------------------------

set -Eeuo pipefail
trap 'rc=$?; echo "[ERROR] Unexpected failure (exit $rc) at line $LINENO"; exit $rc' ERR
umask 022
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ---------- Paths -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"

# Determine repository root. Prefer git top-level (handles symlinks),
# otherwise assume repo root is parent of the script (script lives in bin/).
if REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
  :
else
  REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
fi

# Allow environment overrides for output/log locations for backward compatibility.
OUT_DIR="${OUT_DIR:-$REPO_ROOT/outputs}"
LOG_DIR="${LOG_DIR:-$REPO_ROOT/logs}"
DOWNLOADS_DIR="${DOWNLOADS_DIR:-$REPO_ROOT/downloads}"
STAGE_DIR="${STAGE_DIR:-/opt/rke2/stage}"
SBOM_DIR="$OUT_DIR/sbom"

mkdir -p "$LOG_DIR" "$OUT_DIR" "$DOWNLOADS_DIR" "$STAGE_DIR" "$SBOM_DIR"

# ---------- Defaults & tunables ----------------------------------------------------------------
RKE2_VERSION=""                                       # auto-detect if empty
# WARNING: These are EXAMPLE defaults only. Override with -r/-u/-p or via YAML config.
#          DO NOT use these default credentials in production environments.
REGISTRY=""
REG_USER="admin"
REG_PASS="ZAQwsx!@#123"
CONFIG_FILE=""
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64";;
  aarch64) ARCH="arm64";;
  *) ARCH="amd64";;
esac

DEFAULT_DNS="10.0.1.34,10.231.1.34"
DEFAULT_SEARCH="svc.cluster.local,cluster.local"
AUTO_YES=0                  # -y auto-confirm reboots and any legacy runtime cleanup if detected
PRINT_CONFIG=0              # -P print sanitized YAML
DRY_PUSH=0                  # --dry-push skips actual registry push
DRY_RUN=0                   # --dry-run simulates write operations without making changes
VERBOSE=0                   # --verbose enables detailed output
QUIET=0                     # --quiet suppresses informational messages
SCRIPT_VERSION="1.2.0"      # Script version
APPLY_NETPLAN_NOW=0         # --apply-netplan-now applies netplan immediately instead of deferring to next reboot
LOAD_IMAGES=0               # --load-images will import staged images into local runtime (opt-in)
VERIFY_LAYERS=0             # --verify-layers performs deep layer checksum verification (opt-in)
ENABLE_BOOT_SERVICE=0       # --enable-boot-service installs and enables first-boot automation
FIX_CNI_PERMISSIONS=0       # --fix-cni-permissions installs/enables CNI permission remediation (image)
BOOT_SERVICE_MODE="oneshot" # oneshot (run once and disable) or persistent (run every boot)
BOOT_YAML_PATH=""           # Custom path template for boot script YAML discovery (supports ${HOSTNAME} variable)
BOOT_CONFIG_SEARCH_PATHS=() # Directories to search for hostname-matched YAML configs
BOOT_TARGET_DIR="/root/server-config" # Target directory for discovered configs
VM_PLATFORM="auto"          # auto-detect or specify: vmware, hyperv, virtualbox, generic
BOOT_SCRIPT_PATH="/usr/local/bin/rke2-boot.sh"
BOOT_SERVICE_PATH="/etc/systemd/system/rke2-boot.service"
NODE_NAME=""
ACTION_ARGS=()
ENABLE_FIPS=0               # --enable-fips turns on OS FIPS (Ubuntu Pro) and uses FIPS RKE2 builds
FIPS_REBOOT_REQUIRED=0

# Custom CA context (populated from site defaults or YAML when provided)
CUSTOM_CA_ROOT_CRT=""
CUSTOM_CA_ROOT_KEY=""
CUSTOM_CA_INT_CRT=""
CUSTOM_CA_INT_KEY=""
CUSTOM_CA_INSTALL_TO_OS_TRUST=1

# Optional bootstrap token file used to validate custom CA presence.
BOOTSTRAP_TOKEN_FILE=""

# Track the CA file used when deriving full tokens so runs can archive it.
AGENT_CA_CERT=""

# Artifacts
IMAGES_TAR="rke2-images.linux-$ARCH.tar.zst"
RKE2_TARBALL="rke2.linux-$ARCH.tar.gz"
SHA256_FILE="sha256sum-$ARCH.txt"

# Optional: hardened-cni-plugins HTTP download configuration
# Operators should set `HARDENED_CNI_URL` to a direct HTTP(S) downloadable
# tarball of the hardened-cni image (for air-gapped staging). When empty,
# the image will not be fetched automatically.
HARDENED_CNI_URL="${HARDENED_CNI_URL:-}"
# Require hardened-cni-plugins to be present for airgap image prep by default.
# Set HARDENED_CNI_REQUIRED=0 to allow skipping in special cases.
HARDENED_CNI_REQUIRED="${HARDENED_CNI_REQUIRED:-1}"
# Basename used for saved artifact (operator can override by setting
# HARDENED_CNI_BN in the environment if desired).
HARDENED_CNI_BN="hardened-cni-plugins-${ARCH}.tar"
HARDENED_CNI_FILE="$DOWNLOADS_DIR/$HARDENED_CNI_BN"

# Optional explicit tag for rancher/hardened-multus-cni when Multus is used.
HARDENED_MULTUS_TAG="${HARDENED_MULTUS_TAG:-}"
# Basename used for saved hardened-multus-cni archive.
HARDENED_MULTUS_BN="hardened-multus-cni-${ARCH}.tar"
HARDENED_MULTUS_FILE="$DOWNLOADS_DIR/$HARDENED_MULTUS_BN"

# Optional explicit tag for rancher/hardened-flannel when Canal is used.
HARDENED_FLANNEL_TAG="${HARDENED_FLANNEL_TAG:-}"
# Basename used for saved hardened-flannel archive.
HARDENED_FLANNEL_BN="hardened-flannel-${ARCH}.tar"
HARDENED_FLANNEL_FILE="$DOWNLOADS_DIR/$HARDENED_FLANNEL_BN"

# Logging - LOG_FILE will be set by initialize_action_context or defaults to timestamped name
LOG_FILE=""

# Cached artifact metadata (populated at runtime)
NERDCTL_FULL_TGZ=""
NERDCTL_STD_TGZ=""

# ==============================================================================
# PHASE 3: CLI IMPROVEMENTS - Help System and Verbosity Control
# ==============================================================================
# Purpose: Enhanced CLI with per-action help, version info, and verbosity control
# Author: GitHub Copilot (Phase 3 Implementation)
# Date: 2025-11-16
# ==============================================================================

#-----------------------------------------------------------------------------
# Function: show_version
# Purpose: Display version information and build details
# Parameters: None
# Returns: None (exits with 0)
#-----------------------------------------------------------------------------
show_version() {
  cat <<EOF
RKE2 Node Initialization Script
Version: ${SCRIPT_VERSION}
Compatible with: RKE2 v1.24+
Bash version: ${BASH_VERSION}
Last updated: February 13, 2026

Phase 1: Core utilities (19 functions)
Phase 2: Action refactoring (4 actions)  
Phase 3: CLI improvements (help system, verbosity control)

Repository: cantrellcloud/rke2-node-init
Branch: feat/stage-artifact-path
EOF
  exit 0
}

# ------------------------------------------------------------------------------
# Function: extract_hardened_flannel_tag_from_images
# Purpose : Inspect an RKE2 images tarball and extract the tag for
#           `rancher/hardened-flannel`.
# Arguments:
#   $1 - Path to rke2-images tarball (e.g. rke2-images.linux-amd64.tar.zst)
# Returns:
#   Echoes the tag on success and returns 0. Returns non-zero if not found.
# ------------------------------------------------------------------------------
extract_hardened_flannel_tag_from_images() {
  local images_tar="${1:-}"
  [[ -z "$images_tar" || ! -f "$images_tar" ]] && return 2

  local tmp
  tmp=$(mktemp) || return 3

  if [[ "$images_tar" == *.tar.zst || "$images_tar" == *.tzst || "$images_tar" == *.zst ]]; then
    if ! command -v zstd >/dev/null 2>&1; then
      rm -f "$tmp" || true
      return 4
    fi
    if ! zstd -d -c "$images_tar" 2>/dev/null | tar -Ox manifest.json >"$tmp" 2>/dev/null; then
      rm -f "$tmp" || true
      return 5
    fi
  else
    if ! tar -xOf "$images_tar" manifest.json >"$tmp" 2>/dev/null; then
      rm -f "$tmp" || true
      return 6
    fi
  fi

  local tag=""
  if command -v python3 >/dev/null 2>&1; then
    tag=$(python3 - <<'PY' "$tmp" 2>/dev/null || true
import json,sys,re
p=sys.argv[1]
try:
    j=json.load(open(p,'r',encoding='utf-8'))
    for e in j:
        for rt in e.get('RepoTags',[]) or []:
            if re.search(r'(^|/)rancher/hardened-flannel:', rt):
                print(rt.rsplit(':',1)[1])
                raise SystemExit(0)
except Exception:
    pass
raise SystemExit(1)
PY
)
  else
    tag=$(grep -oE 'rancher/hardened-flannel:[^" ]+' "$tmp" | head -n1 | sed -E 's#.*rancher/hardened-flannel:##')
  fi

  rm -f "$tmp" || true
  [[ -n "$tag" ]] || return 7
  printf '%s' "$tag"
  return 0
}

#-----------------------------------------------------------------------------
# Function: show_action_help
# Purpose: Display detailed help for specific action
# Parameters:
#   \$1 - Action name
# Returns: None (exits with 0)
#-----------------------------------------------------------------------------
show_action_help() {
  local action="${1:-}"
  
  case "$action" in
    verify)
      cat <<'HELPEOF'
Action: verify
==============
Purpose: Verify that the node meets all RKE2 prerequisites (read-only check)

Usage:
  sudo bin/rke2nodeinit.sh verify
  sudo bin/rke2nodeinit.sh verify -f configs/site-defaults.yaml

Options:
  -f FILE    Optional YAML file with site defaults (DNS, search domains)
  --verbose  Show detailed prerequisite checks
  --quiet    Suppress informational messages

Exit Codes:
  0 - All prerequisites met
  2 - One or more prerequisites failed

Examples:
  # Basic verification
  sudo bin/rke2nodeinit.sh verify
  
  # Verify with site defaults
  sudo bin/rke2nodeinit.sh verify -f configs/production-site.yaml
  
  # Verbose verification
  sudo bin/rke2nodeinit.sh verify --verbose

Output:
  - System requirements check (CPU, memory, disk)
  - Network connectivity validation
  - Required ports availability
  - Kernel module availability
  - Swap configuration
  
Next Steps:
  On success: Run 'image' action to prepare golden image
  On failure: Review error messages for specific remediation steps
HELPEOF
      ;;
    
    custom-ca)
      cat <<'HELPEOF'
Action: custom-ca
=================
Purpose: Generate bootstrap token from custom CA configuration

Usage:
  sudo bin/rke2nodeinit.sh custom-ca -f <config.yaml>

Required Options:
  -f FILE    YAML config file with CustomCA kind

Optional Flags:
  --verbose  Show detailed token generation process
  --quiet    Suppress informational messages

YAML Structure:
  kind: CustomCA
  metadata:
    name: cluster-ca
  spec:
    customCA:
      rootCrt: path/to/root-ca.crt
      rootKey: path/to/root-ca.key
      intermediateCrt: path/to/intermediate-ca.crt  # Optional
      intermediateKey: path/to/intermediate-ca.key  # Optional
      installToOSTrust: true  # Install to OS trust store

Exit Codes:
  0 - Token generated successfully
  1 - Token generation failed
  5 - Validation error (missing config, invalid kind, incomplete spec)

Output Files:
  outputs/<name>-bootstrap-token.txt  (permissions: 600)

Examples:
  # Generate token from custom CA
  sudo bin/rke2nodeinit.sh custom-ca -f configs/cluster-ca.yaml
  
  # With verbose output
  sudo bin/rke2nodeinit.sh custom-ca -f configs/cluster-ca.yaml --verbose

Security Notes:
  - Token file has restrictive permissions (600)
  - Keep token secure - it provides cluster access
  - Token is used for server/agent bootstrap
HELPEOF
      ;;
    
    push)
      cat <<'HELPEOF'
Action: push
============
Purpose: Push container images to private registry with comprehensive tracking

Usage:
  sudo bin/rke2nodeinit.sh push -f <config.yaml>
  sudo bin/rke2nodeinit.sh push -r <registry> -u <user> -p <pass>

Options:
  -f FILE       YAML config file with Push kind
  -r REGISTRY   Registry URL (host or host/namespace)
  -u USER       Registry username
  -p PASS       Registry password
  --dry-run     Simulate push without actually pushing images
  --dry-push    Legacy alias for --dry-run
  --verbose     Show detailed per-image push progress
  --quiet       Suppress progress messages (show summary only)

YAML Structure:
  kind: Push
  metadata:
    name: registry-push
  spec:
    registry: registry.example.com/rke2
    registryUsername: admin
    registryPassword: secure-password

Prerequisites:
  - Images archive must exist (run 'image' action first)
  - Registry must be accessible
  - Valid credentials required

Exit Codes:
  0 - All images pushed successfully
  1 - Authentication failed or some images failed
  3 - Images archive not found

Output Files:
  outputs/images-manifest.txt   - Human-readable manifest
  outputs/images-manifest.json  - Machine-readable manifest

Metrics Tracked:
  - total: Total images processed
  - success: Successfully pushed
  - failed: Failed pushes
  - authenticated: Registry login status

Examples:
  # Push with YAML config
  sudo bin/rke2nodeinit.sh push -f configs/registry.yaml
  
  # Push with CLI flags
  sudo bin/rke2nodeinit.sh push -r registry.local/rke2 -u admin -p pass
  
  # Dry-run to test without pushing
  sudo bin/rke2nodeinit.sh push -f config.yaml --dry-run
  
  # Quiet mode (summary only)
  sudo bin/rke2nodeinit.sh push -f config.yaml --quiet
HELPEOF
      ;;
    
    image)
      cat <<'HELPEOF'
Action: image
=============
Purpose: Prepare golden image for air-gapped RKE2 deployment

Usage:
  sudo bin/rke2nodeinit.sh image -f <config.yaml>

Required Options:
  -f FILE       YAML config file with Image kind

Optional Flags:
  -v VERSION    RKE2 version (e.g., v1.28.1+rke2r1)
  -r REGISTRY   Private registry URL
  -u USER       Registry username
  -p PASS       Registry password
  --load-images Load images into container runtime
  --fix-cni-permissions
               Install/enable CNI permission remediation (service + timer)
  --dry-run     Simulate preparation without making changes
  --verbose     Show detailed operation progress
  --quiet       Suppress detailed progress (show summary only)
  -y            Auto-confirm shutdown/reboot prompt

YAML Structure:
  kind: Image
  metadata:
    name: golden-image
  spec:
    rke2Version: v1.28.1+rke2r1
    fixCNIPermissions: true
    rke2CNIVersion: v1.9.0-build20260116
    registry: registry.example.com/rke2
    registryUsername: admin
    registryPassword: password
    defaultDns: 8.8.8.8,8.8.4.4
    defaultSearchDomains: cluster.local
    customCA:
      rootCrt: path/to/ca.crt
      installToOSTrust: true

Process (8 Phases):
  1. Validate environment (directories, permissions)
  2. Load configuration from YAML
  3. Install OS prerequisites
  4. Cache RKE2 artifacts (downloads, staging)
  5. Process container images (optional loading)
  6. Configure registry trust
  7. Save site defaults
  8. Generate SBOM and documentation

Exit Codes:
  0 - Image prepared successfully
  1 - Validation or dependency failure
  3 - Artifact caching failure

Output Files:
  outputs/sbom/<name>-sbom.txt      - Text SBOM with verification
  outputs/sbom/<name>-sbom.json     - SPDX 2.3 JSON SBOM for tooling
  outputs/<name>/README.txt         - Human-readable summary
  /etc/rke2image.defaults           - Site defaults

Metrics Tracked (15+):
  validation_passed, config_loaded, prereqs_installed,
  artifacts_cached, artifact_verified, sbom_created, etc.

Examples:
  # Basic image preparation
  sudo bin/rke2nodeinit.sh image -f configs/image.yaml
  
  # With image loading
  sudo bin/rke2nodeinit.sh image -f configs/image.yaml --load-images
  
  # Dry-run to test configuration
  sudo bin/rke2nodeinit.sh image -f configs/image.yaml --dry-run
  
  # Quiet mode with auto-reboot
  sudo bin/rke2nodeinit.sh image -f configs/image.yaml --quiet -y

Next Steps:
  1. Review SBOM and verify all artifacts
  2. Shut down VM for cloning/templating
  3. Deploy clones with 'server' or 'agent' actions
HELPEOF
      ;;
    
    server|agent|add-server)
      cat <<EOF
Action: \$action
$(printf '=%.0s' {1..40})
Purpose: Deploy RKE2 cluster node

Usage:
  sudo bin/rke2nodeinit.sh \$action -f <config.yaml>

Required Options:
  -f FILE       YAML config file

Optional Flags:
  --dry-run     Simulate deployment without making changes
  --verbose     Show detailed deployment progress
  --quiet       Suppress detailed progress
  -y            Auto-confirm prompts

Prerequisites:
  - Golden image prepared (via 'image' action)
  - Network configured
  - For agent/add-server: First server must be running

Exit Codes:
  0 - Deployment successful
  1 - Deployment failed
  5 - Validation error

Examples:
  # Deploy first server
  sudo bin/rke2nodeinit.sh server -f configs/server.yaml
  
  # Deploy agent
  sudo bin/rke2nodeinit.sh agent -f configs/agent.yaml
  
  # Dry-run deployment
  sudo bin/rke2nodeinit.sh \$action -f config.yaml --dry-run

For detailed deployment guide, see: docs/DEPLOYMENT.md
EOF
      ;;
    
    *)
      echo "Unknown action: $action"
      echo "Run 'bin/rke2nodeinit.sh --help' for available actions"
      exit 1
      ;;
  esac
  
  exit 0
}

# ==============================================================================
# PHASE 1 REDESIGN: Core Utilities and Infrastructure
# ==============================================================================
# Purpose: Foundational utilities adopting rke2imageprep.sh design patterns
# Author: GitHub Copilot (Phase 1 Implementation)
# Date: 2025-11-16
# ==============================================================================

# ==============================================================================
# SECTION 1: Enhanced Logging Utilities
# Purpose: Structured logging with multiple severity levels
# ==============================================================================

#=============================================================================
# Function: log_info
# Description: Log informational messages to stdout and log file
# Parameters:
#   $@ - Message components to log
# Returns: Always returns 0
# Usage: log_info "Operation started" "with parameter: $param"
#=============================================================================
log_info() {
  local msg="$*"
  local ts host
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  host="$(hostname)"
  # Respect QUIET flag - suppress informational messages
  if [[ "${QUIET:-0}" -ne 1 ]]; then
    echo "[INFO] $msg"
  fi
  printf "%s %s rke2nodeinit[%d]: INFO: %s\n" "$ts" "$host" "$$" "$msg" >> "$LOG_FILE"
}

#=============================================================================
# Function: log_debug
# Description: Log verbose debug messages (only when VERBOSE=1)
# Parameters:
#   $@ - Message components to log
# Returns: Always returns 0
# Usage: log_debug "Detailed step information" "Value: $var"
# Best Practices:
#   - Only outputs when VERBOSE flag is set
#   - Always logs to file regardless of VERBOSE setting
#   - Use for detailed progress and debugging information
#=============================================================================
log_debug() {
  local msg="$*"
  local ts host
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  host="$(hostname)"
  # Only display to console if VERBOSE is enabled
  if [[ "${VERBOSE:-0}" -eq 1 ]]; then
    echo "[DEBUG] $msg"
  fi
  printf "%s %s rke2nodeinit[%d]: DEBUG: %s\n" "$ts" "$host" "$$" "$msg" >> "$LOG_FILE"
}

#=============================================================================
# Function: log_warn
# Description: Log warning messages to stdout and log file
# Parameters:
#   $@ - Message components to log
# Returns: Always returns 0
# Usage: log_warn "Using default credentials" "Override recommended"
#=============================================================================
log_warn() {
  local msg="$*"
  local ts host
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  host="$(hostname)"
  echo "[WARN] $msg"
  printf "%s %s rke2nodeinit[%d]: WARN: %s\n" "$ts" "$host" "$$" "$msg" >> "$LOG_FILE"
}

#=============================================================================
# Function: log_error
# Description: Log error messages to stderr and log file
# Parameters:
#   $@ - Message components to log
# Returns: Always returns 0
# Usage: log_error "Operation failed" "Exit code: $rc"
#=============================================================================
log_error() {
  local msg="$*"
  local ts host
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  host="$(hostname)"
  echo "[ERROR] $msg" >&2
  printf "%s %s rke2nodeinit[%d]: ERROR: %s\n" "$ts" "$host" "$$" "$msg" >> "$LOG_FILE"
}

#=============================================================================
# Function: log_success
# Description: Log success messages with visual indicator
# Parameters:
#   $@ - Message components to log
# Returns: Always returns 0
# Usage: log_success "Download completed" "File: $filename"
#=============================================================================
log_success() {
  local msg="$*"
  local ts host
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  host="$(hostname)"
  # Respect QUIET flag - suppress success messages
  if [[ "${QUIET:-0}" -ne 1 ]]; then
    echo "[✓] $msg"
  fi
  printf "%s %s rke2nodeinit[%d]: SUCCESS: %s\n" "$ts" "$host" "$$" "$msg" >> "$LOG_FILE"
}

# ==============================================================================
# SECTION 2: Dependency Management
# Purpose: Auto-detect, validate, and install system dependencies
# Best Practice: Interactive installation with user consent and multi-OS support
# ==============================================================================

#=============================================================================
# Function: detect_os
# Description: Detect the operating system distribution for package management
# Parameters: None
# Returns: 
#   Prints OS identifier to stdout (ubuntu|debian|rhel|centos|fedora|rocky|almalinux|unknown)
#   Exit code 0 on success, 1 if OS cannot be detected
# Usage: OS=$(detect_os)
# Best Practices:
#   - Uses /etc/os-release for standardized detection
#   - Normalizes to lowercase for consistent comparison
#=============================================================================
detect_os() {
  if [[ -f /etc/os-release ]]; then
    # Parse ID without relying on sourced shell variables.
    local os_id
    os_id="$(grep -E '^ID=' /etc/os-release | head -n1 | cut -d= -f2 | tr -d '"')"
    [[ -z "$os_id" ]] && os_id="unknown"
    echo "$os_id"
    return 0
  else
    echo "unknown"
    return 1
  fi
}

#=============================================================================
# Function: check_dependencies
# Description: Check for missing system dependencies without installing
# Parameters:
#   $@ - List of command names to check (e.g., curl wget jq)
# Returns:
#   0 if all dependencies are present
#   1 if any dependencies are missing
#   Populates global array MISSING_DEPS with missing commands
# Usage: 
#   if check_dependencies curl wget jq; then
#     echo "All dependencies present"
#   fi
# Best Practices:
#   - Non-invasive check (does not modify system)
#   - Uses command -v for POSIX compliance
#   - Silent operation (no output on success)
#=============================================================================
check_dependencies() {
  local required_deps=("$@")
  MISSING_DEPS=()
  
  local dep
  for dep in "${required_deps[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      MISSING_DEPS+=("$dep")
    fi
  done
  
  if [ ${#MISSING_DEPS[@]} -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

#=============================================================================
# Function: install_dependencies_interactive
# Description: Interactively install missing dependencies with user consent
# Parameters:
#   $@ - List of package names to check and potentially install
# Returns:
#   0 if all dependencies are satisfied (already installed or newly installed)
#   1 if user declines installation or installation fails
# Usage: install_dependencies_interactive curl wget jq
# Dependencies: detect_os, check_dependencies
# Best Practices:
#   - Always prompts for user consent before system modifications
#   - Supports multiple package managers (apt, dnf, yum)
#   - Verifies successful installation after completion
#   - Provides clear feedback at each step
#=============================================================================
install_dependencies_interactive() {
  local required_deps=("$@")
  
  # Check which dependencies are missing
  if check_dependencies "${required_deps[@]}"; then
    return 0  # All dependencies already present
  fi
  
  # Display missing dependencies
  echo ""
  echo "Missing dependencies detected: ${MISSING_DEPS[*]}"
  echo ""
  
  # Prompt for installation (skip if AUTO_YES is set)
  if [[ "${AUTO_YES:-0}" -eq 1 ]]; then
    echo "Auto-confirm enabled (-y flag); installing dependencies automatically..."
  else
    read -p "Would you like to install missing dependencies now? (y/n): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "Installation cancelled. Please install dependencies manually:"
      local dep
      for dep in "${MISSING_DEPS[@]}"; do
        echo "  - $dep"
      done
      return 1
    fi
  fi
  
  # Detect OS for package manager selection
  local os_id
  os_id=$(detect_os)
  
  if [[ "$os_id" == "unknown" ]]; then
    log_error "Cannot detect OS. Please install dependencies manually:"
    local dep
    for dep in "${MISSING_DEPS[@]}"; do
      echo "  - $dep"
    done
    return 1
  fi
  
  echo "Installing dependencies..."
  
  # Install based on OS
  case "$os_id" in
    ubuntu|debian)
      echo "Detected Debian/Ubuntu - using apt..."
      export DEBIAN_FRONTEND=noninteractive
      if ! sudo apt-get update -qq; then
        log_error "apt-get update failed"
        return 1
      fi
      if ! sudo apt-get install -y "${MISSING_DEPS[@]}"; then
        log_error "apt-get install failed"
        return 1
      fi
      ;;
    rhel|centos|fedora|rocky|almalinux)
      echo "Detected RHEL/CentOS/Fedora family - using dnf/yum..."
      # Try dnf first (newer systems), fall back to yum
      if command -v dnf &> /dev/null; then
        if ! sudo dnf install -y "${MISSING_DEPS[@]}"; then
          log_error "dnf install failed"
          return 1
        fi
      elif command -v yum &> /dev/null; then
        if ! sudo yum install -y "${MISSING_DEPS[@]}"; then
          log_error "yum install failed"
          return 1
        fi
      else
        log_error "No package manager found (dnf or yum)"
        return 1
      fi
      ;;
    *)
      log_error "Unsupported OS: $os_id"
      echo "Please install dependencies manually:"
      local dep
      for dep in "${MISSING_DEPS[@]}"; do
        echo "  - $dep"
      done
      return 1
      ;;
  esac
  
  # Verify installation
  echo "Verifying installation..."
  local install_failed=false
  local dep
  for dep in "${MISSING_DEPS[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      log_error "$dep installation verification failed"
      install_failed=true
    else
      echo "  ✓ $dep installed successfully"
    fi
  done
  
  if [ "$install_failed" = true ]; then
    return 1
  fi
  
  echo ""
  echo "All dependencies installed successfully!"
  echo ""
  return 0
}

# ------------------------------------------------------------------------------
# Function: is_fips_enabled
# Purpose : Check whether the kernel is running in FIPS mode.
# ------------------------------------------------------------------------------
is_fips_enabled() {
  [[ -f /proc/sys/crypto/fips_enabled ]] && [[ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" == "1" ]]
}

# ------------------------------------------------------------------------------
# Function: ensure_fips_os_enabled
# Purpose : Enable OS FIPS on Ubuntu using Ubuntu Pro (fips-updates).
# Returns : 0 if already enabled or enabled successfully, 1 if reboot required,
#           2 if FIPS could not be enabled.
# ------------------------------------------------------------------------------
ensure_fips_os_enabled() {
  if is_fips_enabled; then
    log_info "OS FIPS mode already enabled"
    return 0
  fi

  local os_id
  os_id=$(detect_os || true)
  if [[ "$os_id" != "ubuntu" ]]; then
    log_error "FIPS auto-enable is only supported on Ubuntu via Ubuntu Pro"
    return 2
  fi

  if ! command -v pro >/dev/null 2>&1; then
    log_error "Ubuntu Pro client not found; cannot enable FIPS"
    log_error "Install ubuntu-pro-client and attach a subscription"
    return 2
  fi

  if pro status 2>/dev/null | grep -qi "not attached"; then
    if [[ -z "${PRO_TOKEN:-}" ]]; then
      log_error "Ubuntu Pro token missing. Set PRO_TOKEN to enable FIPS."
      return 2
    fi
    log_info "Attaching Ubuntu Pro subscription"
    if ! pro attach "$PRO_TOKEN" >>"$LOG_FILE" 2>&1; then
      log_error "Failed to attach Ubuntu Pro subscription"
      return 2
    fi
  fi

  log_info "Enabling FIPS (fips-updates) via Ubuntu Pro"
  if ! pro enable fips-updates >>"$LOG_FILE" 2>&1; then
    log_error "Failed to enable fips-updates"
    return 2
  fi

  FIPS_REBOOT_REQUIRED=1
  log_warn "FIPS enabled. Reboot required before continuing."
  return 1
}

# ------------------------------------------------------------------------------
# Function: normalize_rke2_fips_version
# Purpose : Ensure RKE2_VERSION points at a FIPS build when FIPS is enabled.
# ------------------------------------------------------------------------------
normalize_rke2_fips_version() {
  if [[ "${ENABLE_FIPS:-0}" -ne 1 ]]; then
    return 0
  fi

  if [[ -z "${RKE2_VERSION:-}" ]]; then
    return 0
  fi

  if [[ "$RKE2_VERSION" != *"fips"* ]]; then
    RKE2_VERSION="${RKE2_VERSION}-fips"
    log_info "Adjusted RKE2 version for FIPS build: $RKE2_VERSION"
  fi
}

# ------------------------------------------------------------------------------
# Function: ensure_fips_before_install
# Purpose : Ensure OS FIPS is enabled before RKE2 install when requested.
# ------------------------------------------------------------------------------
ensure_fips_before_install() {
  if [[ "${ENABLE_FIPS:-0}" -ne 1 ]]; then
    return 0
  fi

  local rc
  ensure_fips_os_enabled
  rc=$?
  if [[ "$rc" == "1" ]]; then
    prompt_reboot
    exit 0
  elif [[ "$rc" != "0" ]]; then
    exit 2
  fi
}

# ==============================================================================
# SECTION 3: Operation Metrics Tracking
# Purpose: Track success/failure counts for batch operations
# Best Practice: Provides transparency and actionable summaries
# ==============================================================================

# Global associative array for metrics (declare once)
declare -gA METRICS 2>/dev/null || true

#=============================================================================
# Function: metrics_init
# Description: Initialize metrics counters for a new operation
# Parameters:
#   $1 - Operation name (optional, default: "operation")
# Returns: Always returns 0
# Usage: metrics_init "image_download"
# Best Practices:
#   - Call at the start of each batch operation
#   - Resets all counters to ensure clean state
#=============================================================================
metrics_init() {
  local operation_name="${1:-operation}"
  METRICS[operation]="$operation_name"
  METRICS[total]=0
  METRICS[success]=0
  METRICS[failed]=0
  METRICS[skipped]=0
  METRICS[start_time]=$(date +%s)
}

#=============================================================================
# Function: metrics_increment
# Description: Increment a specific metric counter
# Parameters:
#   $1 - Metric name (total|success|failed|skipped)
#   $2 - Increment amount (optional, default: 1)
# Returns: Always returns 0
# Usage: 
#   metrics_increment total
#   metrics_increment success
#   metrics_increment failed
#   metrics_increment skipped
# Best Practices:
#   - Call after each operation completes
#   - Use consistent metric names across codebase
#=============================================================================
metrics_increment() {
  local metric_name="$1"
  local increment="${2:-1}"
  
  # Initialize if not set
  if [[ -z "${METRICS[$metric_name]:-}" ]]; then
    METRICS[$metric_name]=0
  fi
  
  METRICS[$metric_name]=$((METRICS[$metric_name] + increment))
}

#=============================================================================
# Function: metrics_get
# Description: Retrieve the current value of a metric
# Parameters:
#   $1 - Metric name
# Returns: Prints the metric value to stdout
# Usage: current_count=$(metrics_get success)
#=============================================================================
metrics_get() {
  local metric_name="$1"
  echo "${METRICS[$metric_name]:-0}"
}

#=============================================================================
# Function: metrics_summary
# Description: Display a formatted summary of operation metrics
# Parameters:
#   $1 - Optional title (default: "Operation Summary")
# Returns: Always returns 0
# Usage: metrics_summary "Download Summary"
# Best Practices:
#   - Call at the end of batch operations
#   - Provides consistent formatting across all operations
#   - Calculates and displays elapsed time
#=============================================================================
metrics_summary() {
  local title="${1:-Operation Summary}"
  local operation="${METRICS[operation]:-operation}"
  local total="${METRICS[total]:-0}"
  local success="${METRICS[success]:-0}"
  local failed="${METRICS[failed]:-0}"
  local skipped="${METRICS[skipped]:-0}"
  local start_time="${METRICS[start_time]:-$(date +%s)}"
  local end_time=$(date +%s)
  local elapsed=$((end_time - start_time))
  
  echo ""
  echo "=========================================="
  echo "$title"
  echo "=========================================="
  echo "Operation:  $operation"
  echo "Total:      $total"
  echo "Successful: $success"
  echo "Failed:     $failed"
  if [[ $skipped -gt 0 ]]; then
    echo "Skipped:    $skipped"
  fi
  echo "Duration:   ${elapsed}s"
  echo "=========================================="
  echo ""
}

#=============================================================================
# Function: metrics_should_fail
# Description: Determine if operation should return failure based on metrics
# Parameters: None
# Returns: 
#   0 if operation should be considered successful (no failures)
#   1 if operation should be considered failed (has failures)
# Usage: 
#   metrics_summary
#   return $(metrics_should_fail)
# Best Practices:
#   - Use as final return value for batch operations
#   - Considers operation failed if any items failed
#=============================================================================
metrics_should_fail() {
  local failed="${METRICS[failed]:-0}"
  if [[ $failed -eq 0 ]]; then
    return 0
  else
    return 1
  fi
}

# ==============================================================================
# SECTION 4: Enhanced Validation Utilities
# Purpose: Input validation with improved error messages
# ==============================================================================

#=============================================================================
# Function: validate_non_empty
# Description: Validate that a required parameter is not empty
# Parameters:
#   $1 - Value to validate
#   $2 - Parameter name (for error message)
# Returns: 0 if valid, 1 if empty
# Usage: validate_non_empty "$REGISTRY" "registry" || return 1
#=============================================================================
validate_non_empty() {
  local value="$1"
  local param_name="$2"
  
  if [[ -z "$value" ]]; then
    log_error "Required parameter is empty: $param_name"
    log_error "Please provide --${param_name} or set in YAML config"
    return 1
  fi
  return 0
}

#=============================================================================
# Function: validate_file_exists
# Description: Validate that a required file exists and is readable
# Parameters:
#   $1 - File path to validate
#   $2 - File description (for error message)
# Returns: 0 if valid, 1 if missing or unreadable
# Usage: validate_file_exists "$CONFIG_FILE" "configuration file" "configuration file" || return 1
#=============================================================================
validate_file_exists() {
  local file_path="$1"
  local description="$2"
  
  if [[ ! -f "$file_path" ]]; then
    log_error "Required $description not found: $file_path"
    return 1
  fi
  
  if [[ ! -r "$file_path" ]]; then
    log_error "Required $description is not readable: $file_path"
    log_error "Check file permissions: ls -la $file_path"
    return 1
  fi
  
  return 0
}

#=============================================================================
# Function: validate_directory_writable
# Description: Validate that a directory exists and is writable
# Parameters:
#   $1 - Directory path to validate
#   $2 - Directory description (for error message)
# Returns: 0 if valid, 1 if missing or not writable
# Usage: validate_directory_writable "$STAGE_DIR" "staging directory" || return 1
#=============================================================================
validate_directory_writable() {
  local dir_path="$1"
  local description="$2"
  
  if [[ ! -d "$dir_path" ]]; then
    log_error "Required $description does not exist: $dir_path"
    log_error "Create it with: mkdir -p $dir_path"
    return 1
  fi
  
  if [[ ! -w "$dir_path" ]]; then
    log_error "Required $description is not writable: $dir_path"
    log_error "Check permissions: ls -lad $dir_path"
    return 1
  fi
  
  return 0
}

# ==============================================================================
# SECTION 5: Progress Reporting Utilities
# Purpose: Provide clear feedback during long-running operations
# ==============================================================================

#=============================================================================
# Function: report_progress
# Description: Report progress for batch operations with count and percentage
# Parameters:
#   $1 - Item description
#   $2 - Current item number
#   $3 - Total item count
# Returns: Always returns 0
# Usage: report_progress "Downloading image: nginx:latest" 5 20
# Best Practices:
#   - Provides visual feedback during long operations
#   - Includes percentage completion
#   - Consistent format across all operations
#=============================================================================
report_progress() {
  local description="$1"
  local current="$2"
  local total="$3"
  local percentage=$((current * 100 / total))
  
  echo "[$current/$total - ${percentage}%] $description"
}

#=============================================================================
# Function: report_item_success
# Description: Report successful completion of an individual item
# Parameters:
#   $1 - Item description
#   $2 - Optional detail message
# Returns: Always returns 0
# Usage: 
#   report_item_success "nginx:latest" "245MB"
#   report_item_success "Configuration applied"
#=============================================================================
report_item_success() {
  local description="$1"
  local detail="${2:-}"
  
  if [[ -n "$detail" ]]; then
    echo "  ✓ $description ($detail)"
  else
    echo "  ✓ $description"
  fi
}

#=============================================================================
# Function: report_item_failure
# Description: Report failure of an individual item
# Parameters:
#   $1 - Item description
#   $2 - Optional error message
# Returns: Always returns 0
# Usage: 
#   report_item_failure "nginx:latest" "Download timeout"
#   report_item_failure "Configuration validation failed"
#=============================================================================
report_item_failure() {
  local description="$1"
  local detail="${2:-}"
  
  if [[ -n "$detail" ]]; then
    echo "  ✗ $description (Error: $detail)"
  else
    echo "  ✗ $description"
  fi
}

#=============================================================================
# Function: report_item_skipped
# Description: Report that an item was skipped
# Parameters:
#   $1 - Item description
#   $2 - Reason for skipping
# Returns: Always returns 0
# Usage: report_item_skipped "nginx:latest" "Already present"
#=============================================================================
report_item_skipped() {
  local description="$1"
  local reason="${2:-Already present}"
  
  echo "  ⊘ $description (Skipped: $reason)"
}

# ==============================================================================
# END PHASE 1 REDESIGN SECTION
# ==============================================================================

# ==============================================================================
# PHASE 5: ADVANCED ERROR HANDLING & METRICS DASHBOARD
# Date: November 16, 2025
# Purpose: Advanced error handling with trap-based cleanup, error context
#          preservation, graceful degradation, and comprehensive metrics dashboard
# ==============================================================================

# ------------------------------------------------------------------------------
# Global Error Context Variables
# ------------------------------------------------------------------------------
declare -a ERROR_STACK=()
declare -a CLEANUP_FUNCTIONS=()
declare -g ERROR_CONTEXT=""
declare -g LAST_ERROR_LINE=0
declare -g LAST_ERROR_FUNCTION=""
declare -g GRACEFUL_DEGRADATION_MODE=0

# Metrics dashboard storage
declare -A METRICS_HISTORY=()
declare -g METRICS_SESSION_ID=""
declare -g METRICS_EXPORT_DIR="${METRICS_EXPORT_DIR:-/rke2/rke2-node-init/outputs/metrics}"

# ==============================================================================
# SECTION 1: Trap-Based Error Handling
# Purpose: Automatic cleanup and error context on failures
# ==============================================================================

#=============================================================================
# Function: error_handler
# Description: Global error handler called on ERR trap
# Parameters: None (uses $LINENO, $BASH_LINENO, etc.)
# Returns: Always returns 1
# Usage: Called automatically via trap
#=============================================================================
error_handler() {
  local exit_code=$?
  local line_number="${BASH_LINENO[0]}"
  local function_name="${FUNCNAME[1]:-main}"
  local command="${BASH_COMMAND}"
  
  # Store error context
  LAST_ERROR_LINE="$line_number"
  LAST_ERROR_FUNCTION="$function_name"
  
  # Build error stack trace
  local stack_trace=""
  for ((i=1; i<${#FUNCNAME[@]}; i++)); do
    stack_trace+="  at ${FUNCNAME[$i]} (line ${BASH_LINENO[$i-1]})\n"
  done
  
  # Log comprehensive error information
  log_error "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log_error "ERROR DETECTED"
  log_error "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log_error "Exit Code: $exit_code"
  log_error "Line: $line_number"
  log_error "Function: $function_name"
  log_error "Command: $command"
  if [[ -n "$ERROR_CONTEXT" ]]; then
    log_error "Context: $ERROR_CONTEXT"
  fi
  log_error ""
  log_error "Stack Trace:"
  echo -e "$stack_trace" | while IFS= read -r line; do
    [[ -n "$line" ]] && log_error "$line"
  done
  log_error "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  # Increment failure metrics
  metrics_increment "errors"
  
  return 1
}

#=============================================================================
# Function: cleanup_handler
# Description: Execute all registered cleanup functions on exit
# Parameters: None
# Returns: Always returns 0
# Usage: Called automatically via trap
#=============================================================================
cleanup_handler() {
  local exit_code=$?
  
  log_info "Executing cleanup handlers..."
  
  # Execute cleanup functions in reverse order (LIFO)
  for ((i=${#CLEANUP_FUNCTIONS[@]}-1; i>=0; i--)); do
    local cleanup_fn="${CLEANUP_FUNCTIONS[$i]}"
    log_debug "Running cleanup function: $cleanup_fn"
    
    # Execute cleanup function and suppress errors
    if ! $cleanup_fn 2>/dev/null; then
      log_warn "Cleanup function failed: $cleanup_fn (non-fatal)"
    fi
  done
  
  log_info "Cleanup complete"
  return 0
}

#=============================================================================
# Function: interrupt_handler
# Description: Handle SIGINT (Ctrl+C) gracefully
# Parameters: None
# Returns: Exits with code 130
# Usage: Called automatically via trap
#=============================================================================
interrupt_handler() {
  log_warn ""
  log_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  log_warn "Operation interrupted by user (Ctrl+C)"
  log_warn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  metrics_increment "interrupted"
  
  # Run cleanup handlers
  cleanup_handler
  
  exit 130
}

#=============================================================================
# Function: register_cleanup
# Description: Register a function to be called during cleanup
# Parameters:
#   $1 - Function name to register
# Returns: Always returns 0
# Usage: register_cleanup my_cleanup_function
#=============================================================================
register_cleanup() {
  local cleanup_fn="$1"
  CLEANUP_FUNCTIONS+=("$cleanup_fn")
  log_debug "Registered cleanup function: $cleanup_fn"
}

#=============================================================================
# Function: set_error_context
# Description: Set context string for error reporting
# Parameters:
#   $@ - Context description
# Returns: Always returns 0
# Usage: set_error_context "Downloading artifacts from registry"
#=============================================================================
set_error_context() {
  ERROR_CONTEXT="$*"
  log_debug "Error context: $ERROR_CONTEXT"
}

#=============================================================================
# Function: clear_error_context
# Description: Clear the error context string
# Parameters: None
# Returns: Always returns 0
# Usage: clear_error_context
#=============================================================================
clear_error_context() {
  ERROR_CONTEXT=""
}

#=============================================================================
# Function: enable_error_handling
# Description: Enable advanced error handling with traps
# Parameters: None
# Returns: Always returns 0
# Usage: enable_error_handling (call early in script)
#=============================================================================
enable_error_handling() {
  # Set error handling options
  set -E  # ERR trap inheritance
  
  # Register trap handlers
  trap error_handler ERR
  trap cleanup_handler EXIT
  trap interrupt_handler INT TERM
  
  log_debug "Advanced error handling enabled"
  metrics_init "error_handling"
}

# ==============================================================================
# SECTION 2: Graceful Degradation
# Purpose: Continue operation with reduced functionality on non-critical failures
# ==============================================================================

#=============================================================================
# Function: enable_graceful_degradation
# Description: Enable graceful degradation mode
# Parameters: None
# Returns: Always returns 0
# Usage: enable_graceful_degradation
#=============================================================================
enable_graceful_degradation() {
  GRACEFUL_DEGRADATION_MODE=1
  log_info "Graceful degradation mode enabled"
  log_info "Non-critical failures will not stop execution"
}

#=============================================================================
# Function: disable_graceful_degradation
# Description: Disable graceful degradation mode
# Parameters: None
# Returns: Always returns 0
# Usage: disable_graceful_degradation
#=============================================================================
disable_graceful_degradation() {
  GRACEFUL_DEGRADATION_MODE=0
  log_debug "Graceful degradation mode disabled"
}

#=============================================================================
# Function: try_with_degradation
# Description: Execute command with graceful degradation
# Parameters:
#   $1 - Command to execute
#   $2 - Description of operation
#   $3 - Criticality (critical|non-critical, default: non-critical)
# Returns: Command exit code if critical, 0 if non-critical and degradation enabled
# Usage: try_with_degradation "some_command" "optional feature" "non-critical"
#=============================================================================
try_with_degradation() {
  local command="$1"
  local description="$2"
  local criticality="${3:-non-critical}"
  
  log_debug "Attempting: $description"
  set_error_context "$description"
  
  if eval "$command"; then
    log_success "$description completed"
    clear_error_context
    return 0
  else
    local exit_code=$?
    
    if [[ "$criticality" == "critical" ]] || [[ "$GRACEFUL_DEGRADATION_MODE" -eq 0 ]]; then
      log_error "$description failed (critical)"
      clear_error_context
      return $exit_code
    else
      log_warn "$description failed (non-critical, continuing)"
      metrics_increment "degraded_operations"
      clear_error_context
      return 0
    fi
  fi
}

#=============================================================================
# Function: retry_with_backoff
# Description: Retry a command with exponential backoff
# Parameters:
#   $1 - Command to execute
#   $2 - Maximum attempts (default: 3)
#   $3 - Initial delay in seconds (default: 1)
# Returns: 0 if successful, 1 if all retries failed
# Usage: retry_with_backoff "curl https://example.com" 3 2
#=============================================================================
retry_with_backoff() {
  local command="$1"
  local max_attempts="${2:-3}"
  local delay="${3:-1}"
  local attempt=1
  
  while [[ $attempt -le $max_attempts ]]; do
    log_debug "Attempt $attempt/$max_attempts: $command"
    
    if eval "$command"; then
      log_success "Command succeeded on attempt $attempt"
      return 0
    fi
    
    if [[ $attempt -lt $max_attempts ]]; then
      log_warn "Attempt $attempt failed, retrying in ${delay}s..."
      sleep "$delay"
      delay=$((delay * 2))  # Exponential backoff
    fi
    
    attempt=$((attempt + 1))
  done
  
  log_error "Command failed after $max_attempts attempts"
  metrics_increment "retry_failures"
  return 1
}

# ==============================================================================
# SECTION 3: Advanced Metrics Dashboard
# Purpose: Comprehensive metrics visualization and export
# ==============================================================================

#=============================================================================
# Function: metrics_dashboard_init
# Description: Initialize metrics dashboard with session tracking
# Parameters:
#   $1 - Operation name
# Returns: Always returns 0
# Usage: metrics_dashboard_init "rke2_deployment"
#=============================================================================
metrics_dashboard_init() {
  local operation_name="${1:-operation}"
  
  # Generate unique session ID
  METRICS_SESSION_ID="${operation_name}_$(date +%Y%m%d_%H%M%S)_$$"
  
  # Initialize metrics
  metrics_init "$operation_name"
  
  # Create export directory
  mkdir -p "$METRICS_EXPORT_DIR"
  
  log_debug "Metrics dashboard initialized: session=$METRICS_SESSION_ID"
}

#=============================================================================
# Function: metrics_dashboard_display
# Description: Display comprehensive metrics dashboard
# Parameters:
#   $1 - Optional title (default: "METRICS DASHBOARD")
# Returns: Always returns 0
# Usage: metrics_dashboard_display "RKE2 Deployment Metrics"
#=============================================================================
metrics_dashboard_display() {
  local title="${1:-METRICS DASHBOARD}"
  local operation="${METRICS[operation]:-operation}"
  local start_time="${METRICS[start_time]:-$(date +%s)}"
  local end_time=$(date +%s)
  local elapsed=$((end_time - start_time))
  
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "$title"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  printf "%-30s %s\n" "Session ID:" "$METRICS_SESSION_ID"
  printf "%-30s %s\n" "Operation:" "$operation"
  printf "%-30s %s\n" "Start Time:" "$(date -d @"$start_time" '+%Y-%m-%d %H:%M:%S')"
  printf "%-30s %s\n" "End Time:" "$(date '+%Y-%m-%d %H:%M:%S')"
  printf "%-30s %ds\n" "Duration:" "$elapsed"
  echo ""
  echo "Metrics:"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "%-30s %10s\n" "Metric" "Value"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  # Display all metrics
  for metric in "${!METRICS[@]}"; do
    # Skip metadata fields
    if [[ "$metric" != "operation" && "$metric" != "start_time" ]]; then
      printf "%-30s %10s\n" "$metric" "${METRICS[$metric]}"
    fi
  done
  
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  # Calculate success rate if applicable
  local total="${METRICS[total]:-0}"
  if [[ $total -gt 0 ]]; then
    local success="${METRICS[success]:-0}"
    local success_rate=$((success * 100 / total))
    echo ""
    printf "%-30s %9d%%\n" "Success Rate:" "$success_rate"
  fi
  
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
}

#=============================================================================
# Function: metrics_export_json
# Description: Export metrics to JSON format
# Parameters:
#   $1 - Output file path (optional, default: auto-generated)
# Returns: 0 if successful, 1 if failed
# Usage: metrics_export_json "/path/to/metrics.json"
#=============================================================================
metrics_export_json() {
  local output_file="${1:-${METRICS_EXPORT_DIR}/${METRICS_SESSION_ID}.json}"
  local start_time="${METRICS[start_time]:-$(date +%s)}"
  local end_time=$(date +%s)
  
  log_info "Exporting metrics to JSON: $output_file"
  
  # Create JSON structure
  cat > "$output_file" <<EOF
{
  "session_id": "$METRICS_SESSION_ID",
  "operation": "${METRICS[operation]:-operation}",
  "timestamp": {
    "start": $start_time,
    "end": $end_time,
    "duration": $((end_time - start_time)),
    "start_iso": "$(date -d @"$start_time" -Iseconds)",
    "end_iso": "$(date -Iseconds)"
  },
  "metrics": {
EOF
  
  # Add all metrics
  local first=1
  for metric in "${!METRICS[@]}"; do
    # Skip metadata fields
    if [[ "$metric" != "operation" && "$metric" != "start_time" ]]; then
      if [[ $first -eq 1 ]]; then
        first=0
      else
        echo "," >> "$output_file"
      fi
      printf '    "%s": %s' "$metric" "${METRICS[$metric]}" >> "$output_file"
    fi
  done
  
  cat >> "$output_file" <<EOF

  },
  "hostname": "$(hostname)",
  "script_version": "${SCRIPT_VERSION:-unknown}",
  "dry_run": ${DRY_RUN:-false}
}
EOF
  
  log_success "Metrics exported to: $output_file"
  return 0
}

#=============================================================================
# Function: metrics_export_csv
# Description: Export metrics to CSV format
# Parameters:
#   $1 - Output file path (optional, default: auto-generated)
# Returns: 0 if successful, 1 if failed
# Usage: metrics_export_csv "/path/to/metrics.csv"
#=============================================================================
metrics_export_csv() {
  local output_file="${1:-${METRICS_EXPORT_DIR}/${METRICS_SESSION_ID}.csv}"
  local start_time="${METRICS[start_time]:-$(date +%s)}"
  local end_time=$(date +%s)
  
  log_info "Exporting metrics to CSV: $output_file"
  
  # Write CSV header
  echo "session_id,operation,start_time,end_time,duration,metric,value" > "$output_file"
  
  # Write metrics
  for metric in "${!METRICS[@]}"; do
    # Skip metadata fields
    if [[ "$metric" != "operation" && "$metric" != "start_time" ]]; then
      echo "$METRICS_SESSION_ID,${METRICS[operation]:-operation},$start_time,$end_time,$((end_time - start_time)),$metric,${METRICS[$metric]}" >> "$output_file"
    fi
  done
  
  log_success "Metrics exported to: $output_file"
  return 0
}

#=============================================================================
# Function: metrics_export_all
# Description: Export metrics to all supported formats
# Parameters: None
# Returns: 0 if all exports successful, 1 if any failed
# Usage: metrics_export_all
#=============================================================================
metrics_export_all() {
  local json_file="${METRICS_EXPORT_DIR}/${METRICS_SESSION_ID}.json"
  local csv_file="${METRICS_EXPORT_DIR}/${METRICS_SESSION_ID}.csv"
  
  log_info "Exporting metrics to all formats..."
  
  local failed=0
  
  if ! metrics_export_json "$json_file"; then
    log_error "JSON export failed"
    failed=1
  fi
  
  if ! metrics_export_csv "$csv_file"; then
    log_error "CSV export failed"
    failed=1
  fi
  
  if [[ $failed -eq 0 ]]; then
    log_success "All metrics exported successfully"
    log_info "  JSON: $json_file"
    log_info "  CSV:  $csv_file"
    return 0
  else
    return 1
  fi
}

#=============================================================================
# Function: metrics_compare
# Description: Compare metrics from two sessions
# Parameters:
#   $1 - First session metrics file (JSON)
#   $2 - Second session metrics file (JSON)
# Returns: Always returns 0
# Usage: metrics_compare session1.json session2.json
#=============================================================================
metrics_compare() {
  local file1="$1"
  local file2="$2"
  
  if ! validate_file_exists "$file1" "first metrics file"; then
    return 1
  fi
  
  if ! validate_file_exists "$file2" "second metrics file"; then
    return 1
  fi
  
  log_info "Comparing metrics:"
  log_info "  Session 1: $file1"
  log_info "  Session 2: $file2"
  
  # This is a basic comparison - could be enhanced with jq if available
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "METRICS COMPARISON"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "File 1: $(basename "$file1")"
  echo "File 2: $(basename "$file2")"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "Note: Use 'jq' for detailed comparison:"
  echo "  jq -s '.[0].metrics as \$m1 | .[1].metrics as \$m2 | \$m1 + \$m2' $file1 $file2"
  echo ""
}

# ==============================================================================
# END PHASE 5: ADVANCED ERROR HANDLING & METRICS DASHBOARD
# ==============================================================================

# ==============================================================================
# END PHASE 1 REDESIGN SECTION
# ==============================================================================

# ------------------------------------------------------------------------------
# Function: print_help
# Purpose : Emit the usage banner, supported YAML schema, and command examples
#           to stdout. This function centralizes the CLI documentation so that
#           both README writers and operators have a single source of truth for
#           supported flags and configuration knobs.
# Arguments:
#   None
# Returns :
#   Always returns 0 after writing the help text.
# ------------------------------------------------------------------------------
print_help() {
  cat <<EOF
RKE2 Node Initialization Script (v${SCRIPT_VERSION})
========================================
Automates air-gapped RKE2 cluster deployment with multi-interface networking support.

NOTE: All YAML inputs must include a metadata.name field (e.g., metadata: { name: my-config }).

USAGE:
  sudo ./rke2nodeinit.sh -f <file.yaml> [options]
  sudo ./rke2nodeinit.sh [options] <action>
  sudo ./rke2nodeinit.sh <action> --help

YAML KINDS (apiVersion: rkeprep/v2):
  Push        - Push RKE2 images to private registry
  Image       - Prepare air-gapped base image (full prep + reboot)
  Airgap      - Same as Image but powers off instead of reboot (for VM templating)
  Server      - Initialize first RKE2 control-plane node
  AddServer   - Join additional control-plane nodes to existing cluster
  Agent       - Join worker node to cluster
  Verify      - Verify existing RKE2 installation and configuration
  CustomCA    - Install custom CA certificates into OS trust and registries.yaml

ACTIONS (CLI):
  push         - Push images to registry (requires -r, -u, -p)
  image        - Prepare base image for air-gapped deployment
  airgap       - Prepare base image and power off (for VM templates)
  server       - Initialize first control-plane node
  add-server   - Join additional control-plane node
  agent        - Join worker node
  verify       - Verify RKE2 installation
  custom-ca    - Install custom CA certificates
  label-node   - Apply Kubernetes labels to node (requires -n or --node-name)
  taint-node   - Apply Kubernetes taints to node (requires -n or --node-name)

OPTIONS:
  -f FILE      YAML config file (apiVersion: rkeprep/v2; kind selects action)
  -v VER       RKE2 version tag (e.g., v1.34.1+rke2r1). Auto-detects latest if omitted
  -r REG       Private registry (host[/namespace]), e.g., registry.example.com/rke2
  -u USER      Registry username for authentication
  -p PASS      Registry password for authentication
  -n NAME      Node name for label-node/taint-node (defaults to hostname)
               (also available as --node-name NAME)
  -y           Auto-confirm prompts (reboots, cleanup operations)
  -P           Print sanitized YAML to screen (masks secrets)
  -h, --help   Show this help message (or use <action> --help for action-specific help)
  --version    Display version information
  --verbose    Enable verbose output (detailed progress and debugging)
  --quiet      Suppress informational messages (errors and warnings only)
  --dry-run    Simulate write operations without making changes (server, agent, image)
  --dry-push   Simulate image push without actually pushing to registry (legacy alias)
  --apply-netplan-now
               Apply netplan immediately instead of deferring until reboot
               (default: netplan changes deferred to next reboot for safety)
  --interface name=<iface> ip=<addr> prefix=<bits> [gateway=<gw>] [dns=<dns>] [search=<domain>]
               Define network interface (repeatable for multi-interface setups)
               Use "dhcp4=true" for DHCP-based interfaces
               Omit name on first interface to auto-detect primary NIC
  --load-images
               Import staged RKE2 images from the tarball into the local
               container runtime (nerdctl/ctr). This is opt-in; by default
               images are left staged as a tarball on the node for air-gapped
               template workflows.
  --fix-cni-permissions
               Install and enable timer-based CNI permission remediation
               (service + timer) during image preparation. Also supported via
               YAML: spec.fixCNIPermissions: true
  --verify-layers
               Perform deep layer checksum verification of staged images
               tarball. Verifies individual layer SHA256 digests against
               manifest to ensure no corruption. More thorough than standard
               tarball integrity tests. Opt-in due to additional processing time.
  --enable-boot-service
               Install first-boot automation service for VM template workflows
               Service auto-runs appropriate action on first boot after template clone
               Must be used with 'image' or 'airgap' action
  --boot-yaml-path PATH
               YAML config path for boot service to execute (default: /root/config.yaml)
               Use with --enable-boot-service
  --boot-mode MODE
               Boot service mode: 'oneshot' or 'persistent' (default: oneshot)
               oneshot: Run once on first boot, then disable service
               persistent: Run on every boot (useful for testing)
  --vm-platform PLATFORM
  --enable-fips
               Enable OS FIPS mode (Ubuntu Pro) and use FIPS RKE2 builds
               Requires PRO_TOKEN for automatic Ubuntu Pro attachment
               VM platform for boot detection: vmware, hyperv, virtualbox, or generic
               (default: auto-detect based on available tools)

MULTI-INTERFACE YAML EXAMPLE:
  apiVersion: rkeprep/v2
  kind: Server
  metadata:
    name: ctrl01-server
  spec:
    token: K10abc...xyz::server:1234abcd
    clusterInit: true
    nodeName: ctrl01.example.com
    node-ip: 172.16.15.101
    bind-address: 172.16.15.101
    interfaces:
      - name: eth0
        ip: 172.16.15.101
        prefix: 24
        gateway: 10.0.69.1
        dns: [10.0.69.1, 8.8.8.8]
        search: [example.com]
      - name: eth1
        ip: 192.168.1.60
        prefix: 24
      - name: eth2
        dhcp4: true

CUSTOM CA YAML EXAMPLE:
  apiVersion: rkeprep/v2
  kind: CustomCA
  metadata:
    name: enterprise-ca
  spec:
    rootCrt: certs/enterprise-root.crt
    rootKey: certs/enterprise-root.key        # optional
    intermediateCrt: certs/issuing-ca.crt     # optional
    intermediateKey: certs/issuing-ca.key     # optional
    installToOSTrust: true                    # default: true

BOOT SERVICE YAML EXAMPLE:
  apiVersion: rkeprep/v2
  kind: Image
  metadata:
    name: base-image
  spec:
    rke2Version: v1.34.1+rke2r1
    rke2CNIVersion: v1.9.0-build20260116
    bootService:
      enabled: true
      yamlPath: /root/server-config.yaml  # Config to run on first boot
      mode: oneshot                        # Run once, then disable
      platform: vmware                     # vmware, hyperv, virtualbox, or generic

WORKFLOW EXAMPLES:
  1. Prepare base image for cloning:
     sudo ./rke2nodeinit.sh -f examples/image.yaml

  2. Prepare base image with boot service for automated server deployment:
     sudo ./rke2nodeinit.sh -f examples/image.yaml --enable-boot-service \\
       --boot-yaml-path /root/server.yaml --boot-mode oneshot

  3. Initialize first control-plane with multi-interface networking:
     sudo ./rke2nodeinit.sh -f clusters/dc1/ctrl01.yaml

  4. Join worker node:
     sudo ./rke2nodeinit.sh -f clusters/dc1/work01.yaml

  5. Push images to private registry:
     sudo ./rke2nodeinit.sh -f examples/push.yaml -r registry.local/rke2 -u admin -p secret

  6. Label a node:
     sudo ./rke2nodeinit.sh label-node -n worker01 -f labels.yaml

  7. Install custom CA:
     sudo ./rke2nodeinit.sh -f certs/custom-ca.yaml custom-ca

OUTPUTS:
  - SBOM:      outputs/sbom/<metadata.name>-sbom.txt
               (SHA256 checksums and sizes of cached artifacts)
  - Run log:   outputs/<metadata.name>/README.txt
               (Summary of image preparation steps)
  - Token:     outputs/tokens/<cluster>-token.txt
               (Generated cluster token for Server with clusterInit: true)

EXIT CODES:
  0 - Success
  1 - General error (validation, filesystem, network)
  2 - Missing dependencies or unsupported configuration
  3 - RKE2 installation or service failure
  4 - Network configuration failure (netplan, routing)
  5 - User cancellation or dry-run mode

For more information, see README.md or visit:
  https://github.com/cantrellcloud/rke2-node-init

EOF
}

# ------------------------------------------------------------------------------
# Function: cache_hardened_cni_http
# Purpose : Download hardened-cni-plugins via HTTP(S) into the downloads dir
#           and produce a local sha256 checksum file for staging.
# Arguments:
#   $1 - Optional URL to download (overrides HARDENED_CNI_URL)
# Returns : 0 on success, non-zero on failure (download or write error)
# ------------------------------------------------------------------------------
cache_hardened_cni_http() {
  local url="${1:-$HARDENED_CNI_URL}"
  if [[ -z "$url" ]]; then
    log INFO "HARDENED_CNI_URL not set; skipping hardened-cni-plugins download"
    return 0
  fi

  mkdir -p "$DOWNLOADS_DIR"
  local bn="${HARDENED_CNI_BN:-hardened-cni-plugins-${ARCH}.tar}"
  local tmp="$DOWNLOADS_DIR/.tmp-${bn}.$$"
  log INFO "Downloading hardened-cni-plugins from $url -> $DOWNLOADS_DIR/$bn"

  if command -v curl >/dev/null 2>&1; then
    if ! spinner_run "Downloading $bn" curl -fL --retry 3 --retry-delay 2 -o "$tmp" "$url"; then
      log ERROR "Failed to download hardened-cni-plugins from $url"
      rm -f "$tmp" || true
      return 1
    fi
  elif command -v wget >/dev/null 2>&1; then
    if ! spinner_run "Downloading $bn" wget -q -O "$tmp" "$url"; then
      log ERROR "Failed to download hardened-cni-plugins via wget from $url"
      rm -f "$tmp" || true
      return 1
    fi
  else
    log ERROR "Neither curl nor wget available to download hardened-cni-plugins"
    return 2
  fi

  # Move into place atomically
  mv -T "$tmp" "$DOWNLOADS_DIR/$bn"
  chmod 0644 "$DOWNLOADS_DIR/$bn" || true

  # Write a simple SHA256 file beside the artifact for audit/staging and
  # also append the checksum to the repository-style manifest used by the
  # script so the staged manifest `sha256sum-<arch>.txt` includes this
  # artifact. This keeps hardened-cni entries aligned with other artifacts
  # and allows `sha256sum -c` verification to work uniformly.
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$DOWNLOADS_DIR" && sha256sum "$bn" > "${bn}.sha256") || true
    log INFO "Wrote checksum: $DOWNLOADS_DIR/${bn}.sha256"

    # Ensure downloads dir manifest exists and is updated idempotently.
    local manifest="$DOWNLOADS_DIR/$SHA256_FILE"
    mkdir -p "$(dirname "$manifest")"
    local sha
    sha=$(sha256sum "$DOWNLOADS_DIR/$bn" | awk '{print $1}') || sha=""
    if [[ -n "$sha" ]]; then
      # Remove any existing line referencing this basename, then append
      # a single manifest line in the canonical format: "<sha>  <basename>"
      if [[ -f "$manifest" ]]; then
        # Use a temp file replacement to avoid races
        local mtmp
        mtmp=$(mktemp)
        grep -v -F " $bn" "$manifest" > "$mtmp" || true
        printf "%s  %s\n" "$sha" "$bn" >> "$mtmp"
        mv "$mtmp" "$manifest"
      else
        printf "%s  %s\n" "$sha" "$bn" > "$manifest"
      fi
      log INFO "Appended hardened-cni checksum to manifest: $manifest"
    fi
  fi

  local _size
  _size=$(du -h "$DOWNLOADS_DIR/$bn" 2>/dev/null | awk '{print $1}' || echo "unknown")
  log INFO "Downloaded hardened-cni-plugins: $DOWNLOADS_DIR/$bn ($_size)"
  return 0
}

# ------------------------------------------------------------------------------
# Function: extract_hardened_cni_tag_from_images
# Purpose : Inspect an RKE2 images tarball and extract the tag for
#           `rancher/hardened-cni-plugins`.
#
# Notes:
# - The RKE2 images bundle is the authoritative source for the exact image tags
#   used by the release (including hardened-cni-plugins used by Multus).
# - This helper supports .tar, .tar.gz/.tgz, and .tar.zst.
# Arguments:
#   $1 - Path to rke2-images tarball (e.g. rke2-images.linux-amd64.tar.zst)
# Returns:
#   Echoes the tag on success and returns 0. Returns non-zero if not found.
# ------------------------------------------------------------------------------
extract_hardened_cni_tag_from_images() {
  local images_tar="${1:-}"
  [[ -z "$images_tar" || ! -f "$images_tar" ]] && return 2

  local tmp
  tmp=$(mktemp) || return 3

  # Extract manifest.json from the images tarball into a temp file.
  if [[ "$images_tar" == *.tar.zst || "$images_tar" == *.tzst || "$images_tar" == *.zst ]]; then
    if ! command -v zstd >/dev/null 2>&1; then
      rm -f "$tmp" || true
      return 4
    fi
    if ! zstd -d -c "$images_tar" 2>/dev/null | tar -Ox manifest.json >"$tmp" 2>/dev/null; then
      rm -f "$tmp" || true
      return 5
    fi
  else
    if ! tar -xOf "$images_tar" manifest.json >"$tmp" 2>/dev/null; then
      rm -f "$tmp" || true
      return 6
    fi
  fi

  # Parse manifest.json to find hardened-cni-plugins RepoTags.
  local tag=""
  if command -v python3 >/dev/null 2>&1; then
    tag=$(python3 - <<'PY' "$tmp" 2>/dev/null || true
import json,sys,re
p=sys.argv[1]
try:
    j=json.load(open(p,'r',encoding='utf-8'))
    for e in j:
        for rt in e.get('RepoTags',[]) or []:
            # Accept with or without registry prefix
            if re.search(r'(^|/)rancher/hardened-cni-plugins:', rt):
                # split on first ':' from the right to preserve registry ports
                print(rt.rsplit(':',1)[1])
                raise SystemExit(0)
except Exception:
    pass
raise SystemExit(1)
PY
)
  else
    # Fallback: very simple extraction (best-effort)
    tag=$(grep -oE 'rancher/hardened-cni-plugins:[^" ]+' "$tmp" | head -n1 | sed -E 's#.*rancher/hardened-cni-plugins:##')
  fi

  rm -f "$tmp" || true
  [[ -n "$tag" ]] || return 7
  printf '%s' "$tag"
  return 0
}

# ------------------------------------------------------------------------------
# Function: extract_hardened_multus_tag_from_images
# Purpose : Inspect an RKE2 images tarball and extract the tag for
#           `rancher/hardened-multus-cni`.
# Arguments:
#   $1 - Path to rke2-images tarball (e.g. rke2-images.linux-amd64.tar.zst)
# Returns:
#   Echoes the tag on success and returns 0. Returns non-zero if not found.
# ------------------------------------------------------------------------------
extract_hardened_multus_tag_from_images() {
  local images_tar="${1:-}"
  [[ -z "$images_tar" || ! -f "$images_tar" ]] && return 2

  local tmp
  tmp=$(mktemp) || return 3

  if [[ "$images_tar" == *.tar.zst || "$images_tar" == *.tzst || "$images_tar" == *.zst ]]; then
    if ! command -v zstd >/dev/null 2>&1; then
      rm -f "$tmp" || true
      return 4
    fi
    if ! zstd -d -c "$images_tar" 2>/dev/null | tar -Ox manifest.json >"$tmp" 2>/dev/null; then
      rm -f "$tmp" || true
      return 5
    fi
  else
    if ! tar -xOf "$images_tar" manifest.json >"$tmp" 2>/dev/null; then
      rm -f "$tmp" || true
      return 6
    fi
  fi

  local tag=""
  if command -v python3 >/dev/null 2>&1; then
    tag=$(python3 - <<'PY' "$tmp" 2>/dev/null || true
import json,sys,re
p=sys.argv[1]
try:
    j=json.load(open(p,'r',encoding='utf-8'))
    for e in j:
        for rt in e.get('RepoTags',[]) or []:
            if re.search(r'(^|/)rancher/hardened-multus-cni:', rt):
                print(rt.rsplit(':',1)[1])
                raise SystemExit(0)
except Exception:
    pass
raise SystemExit(1)
PY
)
  else
    tag=$(grep -oE 'rancher/hardened-multus-cni:[^" ]+' "$tmp" | head -n1 | sed -E 's#.*rancher/hardened-multus-cni:##')
  fi

  rm -f "$tmp" || true
  [[ -n "$tag" ]] || return 7
  printf '%s' "$tag"
  return 0
}

# ------------------------------------------------------------------------------
# Function: normalize_image_reference
# Purpose : Canonicalize container image references so comparisons are stable
#           across equivalent forms (for example docker.io prefixes).
# Arguments:
#   $1 - Image reference
# Returns:
#   Prints normalized image reference (best-effort).
# ------------------------------------------------------------------------------
normalize_image_reference() {
  local ref="${1:-}"
  ref="${ref#docker://}"
  ref="${ref#oci://}"
  ref="${ref%\"}"
  ref="${ref#\"}"
  ref="${ref%\'}"
  ref="${ref#\'}"
  ref="${ref%%[[:space:]]*}"

  # Normalize common registry aliases
  ref="${ref#docker.io/}"
  ref="${ref#index.docker.io/}"

  printf '%s' "$ref"
}

# ------------------------------------------------------------------------------
# Function: extract_chart_images_from_rke2_tarball
# Purpose : Inspect the downloaded RKE2 tarball for chart/manifests content and
#           extract image:tag references from Helm chart YAML files.
# Arguments:
#   $1 - Path to rke2.<suffix>.tar.gz
#   $2 - Output file path for required image references
# Returns:
#   0 on success (including empty result), non-zero on extraction errors.
# ------------------------------------------------------------------------------
extract_chart_images_from_rke2_tarball() {
  local rke2_tar="$1"
  local out_file="$2"

  [[ -f "$rke2_tar" ]] || return 1

  if ! command -v python3 >/dev/null 2>&1; then
    log WARN "python3 not available; cannot extract chart image references from $rke2_tar"
    return 2
  fi

  local tmp
  tmp=$(mktemp) || return 3

  if ! python3 - "$rke2_tar" >"$tmp" <<'PY'; then
import io
import re
import sys
import tarfile

tar_path = sys.argv[1]

# image refs with explicit tag, with or without registry prefix
img_re = re.compile(
    r'(?<![A-Za-z0-9._/-])'
    r'((?:[A-Za-z0-9.-]+(?::[0-9]+)?/)?'
    r'[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+'
    r':[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})'
)

refs = set()

def scan_text(text: str) -> None:
    for m in img_re.findall(text or ""):
        ref = m.strip().strip('"\'')
        if ref:
            refs.add(ref)

def is_chartish(name: str) -> bool:
    n = name.lower()
    return ("/charts/" in n) or ("/chart/" in n) or ("/manifests/" in n)

def is_yaml(name: str) -> bool:
    n = name.lower()
    return n.endswith(".yaml") or n.endswith(".yml")

try:
    with tarfile.open(tar_path, mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name
            if not is_chartish(name):
                continue

            low = name.lower()
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            payload = extracted.read()

            if low.endswith(".tgz") or low.endswith(".tar.gz"):
                try:
                    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as nested:
                        for nmember in nested.getmembers():
                            if nmember.isfile() and is_yaml(nmember.name):
                                nf = nested.extractfile(nmember)
                                if nf is None:
                                    continue
                                ntext = nf.read().decode("utf-8", errors="ignore")
                                scan_text(ntext)
                except Exception:
                    pass
            elif is_yaml(low):
                text = payload.decode("utf-8", errors="ignore")
                scan_text(text)
except Exception:
    raise

for ref in sorted(refs):
    print(ref)
PY
    rm -f "$tmp" || true
    return 4
  fi

  # normalize and deduplicate
  : > "$out_file"
  while IFS= read -r ref; do
    [[ -z "$ref" ]] && continue
    normalize_image_reference "$ref" >> "$out_file"
    printf '\n' >> "$out_file"
  done < "$tmp"
  sort -u -o "$out_file" "$out_file"
  rm -f "$tmp" || true
  return 0
}

# ------------------------------------------------------------------------------
# Function: extract_required_images_from_release_txt
# Purpose : Use release-provided image list files as authoritative required
#           image references when chart files are not discoverable in the
#           downloaded RKE2 tarball.
# Arguments:
#   $1 - Base release URL (e.g. https://github.com/.../<version>)
#   $2 - Checksum manifest filename (e.g. sha256sum-amd64.txt)
#   $3 - Output file path for required image references
# Returns:
#   0 when at least one required image is written, non-zero otherwise.
# ------------------------------------------------------------------------------
extract_required_images_from_release_txt() {
  local base_url="$1"
  local sha_file="$2"
  local out_file="$3"

  local -a candidates=(
    "rke2-images.linux-${ARCH}.txt"
    "rke2-images-all.linux-${ARCH}.txt"
  )

  : > "$out_file"

  local bn path
  for bn in "${candidates[@]}"; do
    path="$DOWNLOADS_DIR/$bn"

    if [[ ! -f "$path" && -n "$base_url" && -f "$DOWNLOADS_DIR/$sha_file" ]]; then
      if grep -qE "[[:space:]]${bn}$" "$DOWNLOADS_DIR/$sha_file" 2>/dev/null; then
        log INFO "Downloading release image list: $bn"
        if curl -Lf "$base_url/$bn" -o "$path" >>"$LOG_FILE" 2>&1; then
          chmod 0644 "$path" || true
        else
          rm -f "$path" || true
        fi
      fi
    fi

    [[ -f "$path" ]] || continue

    if command -v sha256sum >/dev/null 2>&1 && [[ -f "$DOWNLOADS_DIR/$sha_file" ]]; then
      if grep -qE "[[:space:]]${bn}$" "$DOWNLOADS_DIR/$sha_file" 2>/dev/null; then
        if ! (grep -E "[[:space:]]${bn}$" "$DOWNLOADS_DIR/$sha_file" | sha256sum -c - >>"$LOG_FILE" 2>&1); then
          log WARN "Checksum verification failed for $bn; skipping this required-image source"
          continue
        fi
      fi
    fi

    # Normalize and keep only explicit repo:tag references
    local tmp
    tmp=$(mktemp) || return 2
    while IFS= read -r ref; do
      [[ -z "$ref" ]] && continue
      [[ "$ref" =~ ^[[:space:]]*# ]] && continue
      ref="$(normalize_image_reference "$ref")"
      [[ -z "$ref" ]] && continue
      [[ "$ref" == *:* ]] || continue
      printf '%s\n' "$ref" >> "$tmp"
    done < "$path"

    if [[ -s "$tmp" ]]; then
      sort -u "$tmp" > "$out_file"
      rm -f "$tmp" || true
      log INFO "Using release image list source: $bn"
      return 0
    fi
    rm -f "$tmp" || true
  done

  return 1
}

# ------------------------------------------------------------------------------
# Function: list_images_in_archive
# Purpose : Extract image references (RepoTags) from a docker-archive style
#           images tarball for comparison against required chart images.
# Arguments:
#   $1 - Path to images tarball
#   $2 - Output file path for image references
# Returns:
#   0 on success, non-zero on parse/extraction errors.
# ------------------------------------------------------------------------------
list_images_in_archive() {
  local images_tar="$1"
  local out_file="$2"
  [[ -f "$images_tar" ]] || return 1

  local manifest_tmp
  manifest_tmp=$(mktemp) || return 2
  local rc=0

  if [[ "$images_tar" == *.tar.zst || "$images_tar" == *.tzst || "$images_tar" == *.zst ]]; then
    if ! command -v zstd >/dev/null 2>&1; then
      rm -f "$manifest_tmp" || true
      return 3
    fi
    zstd -dc "$images_tar" 2>/dev/null | tar -xO manifest.json >"$manifest_tmp" 2>/dev/null || rc=$?
  elif [[ "$images_tar" == *.tar.gz || "$images_tar" == *.tgz || "$images_tar" == *.gz ]]; then
    gzip -dc "$images_tar" 2>/dev/null | tar -xO manifest.json >"$manifest_tmp" 2>/dev/null || rc=$?
  else
    tar -xOf "$images_tar" manifest.json >"$manifest_tmp" 2>/dev/null || rc=$?
  fi

  : > "$out_file"
  if [[ $rc -eq 0 && -s "$manifest_tmp" ]]; then
    if command -v python3 >/dev/null 2>&1; then
      python3 - "$manifest_tmp" <<'PY' > "$out_file" 2>/dev/null || true
import json, sys
data = json.load(open(sys.argv[1], 'r', encoding='utf-8'))
refs = set()
for entry in data:
    for tag in (entry.get('RepoTags') or []):
        if tag:
            refs.add(tag)
for ref in sorted(refs):
    print(ref)
PY
    else
      grep -oE '[A-Za-z0-9./_-]+:[A-Za-z0-9_.-]+' "$manifest_tmp" | sort -u > "$out_file" || true
    fi
  fi

  # OCI layout fallback when manifest.json was not present
  if [[ ! -s "$out_file" ]]; then
    local oci_refs
    oci_refs=$(parse_oci_image_index "$images_tar" 2>/dev/null || true)
    if [[ -n "$oci_refs" && "$oci_refs" != "[]" ]] && command -v python3 >/dev/null 2>&1; then
      python3 - <<'PY' "$oci_refs" > "$out_file" 2>/dev/null || true
import json, sys
refs = json.loads(sys.argv[1])
for ref in sorted(set(refs)):
    if ref:
        print(ref)
PY
    fi
  fi

  local norm_tmp
  norm_tmp=$(mktemp) || { rm -f "$manifest_tmp" || true; return 4; }
  : > "$norm_tmp"
  while IFS= read -r ref; do
    [[ -z "$ref" ]] && continue
    normalize_image_reference "$ref" >> "$norm_tmp"
    printf '\n' >> "$norm_tmp"
  done < "$out_file"
  sort -u "$norm_tmp" > "$out_file"

  rm -f "$manifest_tmp" "$norm_tmp" || true
  [[ -s "$out_file" ]] || return 5
  return 0
}

# ------------------------------------------------------------------------------
# Function: cache_missing_images_from_list
# Purpose : Download missing images into supplemental docker-archive tar files.
#           Prefers skopeo (daemonless), falls back to nerdctl/docker.
# Arguments:
#   $1 - File containing one image reference per line
# Returns:
#   0 on success, non-zero if any image could not be downloaded.
# ------------------------------------------------------------------------------
cache_missing_images_from_list() {
  local list_file="$1"
  [[ -f "$list_file" ]] || return 1

  local cache_dir="$DOWNLOADS_DIR"
  mkdir -p "$cache_dir"

  local img safe bn dest failed=0 pulled=0
  while IFS= read -r img; do
    [[ -z "$img" ]] && continue
    safe=$(echo "$img" | sed -E 's#[/:@]#_#g')
    bn="rke2-images-missing-${safe}.tar"
    dest="$cache_dir/$bn"

    if [[ -f "$dest" ]]; then
      log INFO "Missing image already cached: $bn"
      continue
    fi

    if command -v skopeo >/dev/null 2>&1; then
      if skopeo copy --all --dest-tls-verify=false "docker://$img" "docker-archive:${dest}:$img" >>"$LOG_FILE" 2>&1; then
        log INFO "Cached missing image with skopeo: $img -> $dest"
        ((pulled++))
      else
        log ERROR "Failed to cache missing image with skopeo: $img"
        rm -f "$dest" || true
        ((failed++))
      fi
      continue
    fi

    if command -v nerdctl >/dev/null 2>&1; then
      if nerdctl -n k8s.io pull "$img" >>"$LOG_FILE" 2>&1 && nerdctl -n k8s.io save -o "$dest" "$img" >>"$LOG_FILE" 2>&1; then
        log INFO "Cached missing image with nerdctl: $img -> $dest"
        ((pulled++))
      else
        log ERROR "Failed to cache missing image with nerdctl: $img"
        rm -f "$dest" || true
        ((failed++))
      fi
      continue
    fi

    if command -v docker >/dev/null 2>&1; then
      if docker pull "$img" >>"$LOG_FILE" 2>&1 && docker save -o "$dest" "$img" >>"$LOG_FILE" 2>&1; then
        log INFO "Cached missing image with docker: $img -> $dest"
        ((pulled++))
      else
        log ERROR "Failed to cache missing image with docker: $img"
        rm -f "$dest" || true
        ((failed++))
      fi
      continue
    fi

    log ERROR "No supported image client available to fetch missing image: $img (need skopeo, nerdctl, or docker)"
    ((failed++))
  done < "$list_file"

  log INFO "Missing image cache summary: pulled=$pulled failed=$failed"
  (( failed == 0 ))
}

# ------------------------------------------------------------------------------
# Function: reconcile_chart_images_against_downloaded_bundle
# Purpose : Derive chart-required images from RKE2 tarball, compare with image
#           bundle contents, and download/cache any missing image references.
# Arguments:
#   None (uses DOWNLOADS_DIR globals)
# Returns:
#   0 when requirements are satisfied, non-zero on extraction/repair failure.
# ------------------------------------------------------------------------------
reconcile_chart_images_against_downloaded_bundle() {
  local base_url="${1:-}"
  local sha_file="${2:-$SHA256_FILE}"
  local rke2_tar="$DOWNLOADS_DIR/$RKE2_TARBALL"
  local images_tar="$DOWNLOADS_DIR/$IMAGES_TAR"
  [[ -f "$rke2_tar" && -f "$images_tar" ]] || return 0

  local required_file="$DOWNLOADS_DIR/chart-images-required.linux-${ARCH}.txt"
  local present_file="$DOWNLOADS_DIR/chart-images-present.linux-${ARCH}.txt"
  local missing_file="$DOWNLOADS_DIR/chart-images-missing.linux-${ARCH}.txt"

  # Recompute reconciliation artifacts every run (avoid stale carry-over).
  : > "$required_file"
  : > "$missing_file"

  extract_chart_images_from_rke2_tarball "$rke2_tar" "$required_file" || true

  if [[ ! -s "$required_file" ]]; then
    if ! extract_required_images_from_release_txt "$base_url" "$sha_file" "$required_file"; then
      log WARN "No chart or release-list image references found; skipping chart-image reconciliation"
      : > "$missing_file"
      return 0
    fi
  fi

  if ! list_images_in_archive "$images_tar" "$present_file"; then
    log ERROR "Failed to inventory bundled images from $images_tar"
    return 2
  fi

  comm -23 "$required_file" "$present_file" > "$missing_file" || true

  local required_count present_count missing_count
  required_count=$(wc -l < "$required_file" | awk '{print $1}')
  present_count=$(wc -l < "$present_file" | awk '{print $1}')
  missing_count=$(wc -l < "$missing_file" | awk '{print $1}')

  log INFO "Chart image reconciliation: required=$required_count present=$present_count missing=$missing_count"

  if (( missing_count == 0 )); then
    log INFO "All chart-referenced images are present in $IMAGES_TAR"
    return 0
  fi

  log WARN "Detected $missing_count chart-referenced image(s) absent from $IMAGES_TAR; caching supplemental archives"
  if ! cache_missing_images_from_list "$missing_file"; then
    log ERROR "Failed to cache one or more missing chart-referenced images"
    return 3
  fi

  log INFO "Cached supplemental images for missing chart references. Manifest: $missing_file"
  return 0
}

# ------------------------------------------------------------------------------
# Function: cache_hardened_cni_skopeo
# Purpose : Mirror the `rancher/hardened-cni-plugins` image into a local
#           docker-archive tarball using `skopeo` (no daemon required). The
#           helper will attempt to select a tag compatible with the RKE2
#           release (best-effort) and write the resulting archive to
#           `$DOWNLOADS_DIR/$HARDENED_CNI_BN`.
# Arguments:
#   $1 - Optional explicit tag to use (overrides auto-detection)
# Returns : 0 on success, non-zero on failure
# ------------------------------------------------------------------------------
cache_hardened_cni_skopeo() {
  local explicit_tag="${1:-}"
  local bn="${HARDENED_CNI_BN:-hardened-cni-plugins-${ARCH}.tar}"
  local repo="docker://rancher/hardened-cni-plugins"
  if ! command -v skopeo >/dev/null 2>&1; then
    log WARN "skopeo not available; cannot mirror hardened-cni via skopeo"
    return 2
  fi

  mkdir -p "$DOWNLOADS_DIR"

  # Determine desired tag:
  #   1) explicit_tag (HARDENED_CNI_TAG)
  #   2) extract the exact tag from the downloaded RKE2 images tarball
  #   3) RKE2_VERSION (last-resort heuristic)
  #
  # The images tarball is the authoritative source for chart-bundled images.
  local desired_tag=""
  local desired_tag_source=""
  if [[ -n "$explicit_tag" ]]; then
    desired_tag="$explicit_tag"
    desired_tag_source="explicit"
  elif [[ -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
    desired_tag=$(extract_hardened_cni_tag_from_images "$DOWNLOADS_DIR/$IMAGES_TAR" 2>/dev/null || true)
    [[ -n "$desired_tag" ]] && desired_tag_source="images-tar"
  fi

  if [[ -z "$desired_tag" && -n "${RKE2_VERSION:-}" ]]; then
    desired_tag="${RKE2_VERSION}"
    desired_tag_source="rke2-version"
  fi

  # Obtain remote tag list and pick a reasonable candidate. Consult skopeo
  # tags and Docker Hub API and let a small helper choose the best tag.
  local tags_json
  tags_json=$(skopeo list-tags "$repo" 2>/dev/null) || tags_json=""
  local hub_json
  if command -v curl >/dev/null 2>&1; then
    hub_json=$(curl -fsSL "https://hub.docker.com/v2/repositories/rancher/hardened-cni-plugins/tags?page_size=100" 2>/dev/null || true)
  else
    hub_json=""
  fi

  local chosen=""
  if command -v python3 >/dev/null 2>&1; then
    local _tfile _hfile
    _tfile=$(mktemp) || _tfile="/tmp/.rke2nodeinit-tags$$"
    _hfile=$(mktemp) || _hfile="/tmp/.rke2nodeinit-hub$$"
    printf '%s' "$tags_json" > "$_tfile" || true
    printf '%s' "$hub_json" > "$_hfile" || true
    chosen=$(python3 "$REPO_ROOT/scripts/select_hardened_cni_tag.py" "$_tfile" "$_hfile" "${desired_tag:-}" "${RKE2_VERSION:-}" 2>/dev/null || true)
    rm -f "$_tfile" "$_hfile" || true
  fi
  # If we have an authoritative tag from the images tarball (or explicit
  # operator override), use it directly and skip remote tag selection.
  # For RKE2_VERSION fallback, only force direct override when the value is a
  # valid OCI image tag (RKE2 release tags can include '+' which is invalid).
  if [[ -n "$desired_tag" ]]; then
    if [[ "$desired_tag_source" == "rke2-version" ]]; then
      if [[ "$desired_tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
        chosen="$desired_tag"
      else
        log WARN "RKE2 version '$desired_tag' is not OCI-tag-safe; using discovered hardened-cni tag '${chosen:-latest}'"
      fi
    else
      chosen="$desired_tag"
    fi
  elif [[ -z "$chosen" ]]; then
    chosen="latest"
  fi

  log INFO "skopeo: chosen hardened-cni tag='$chosen' (desired='$desired_tag'; source='${desired_tag_source:-none}')"

  local dest="$DOWNLOADS_DIR/$bn"
  # Use docker-archive format (creates tar with manifest.json compatible with tooling)
  # Write to a temporary destination first, then atomically move into place.
  local tmp_dest
  # create a safe temporary file path under the downloads dir
  tmp_dest=$(mktemp -p "$DOWNLOADS_DIR" ".tmp-${bn}.XXXXXX") || tmp_dest="$DOWNLOADS_DIR/.tmp-${bn}.$$.tmp"
  # we'll remove the tmp file before skopeo so skopeo creates it itself (avoids modify-in-place issues)
  rm -f "$tmp_dest" || true
  local skopeo_log
  skopeo_log="$LOG_DIR/skopeo-$(basename "$bn")-$(date -u +%Y%m%dT%H%M%SZ).log"
  local dest_ref="rancher/hardened-cni-plugins:${chosen}"
  log INFO "Starting skopeo copy for $repo:$chosen -> $tmp_dest (timeout 300s); logging -> $skopeo_log"
  # Use timeout to avoid hanging indefinitely. Capture exit code and direct skopeo output to a dedicated log.
  if command -v timeout >/dev/null 2>&1; then
    timeout 300 skopeo copy --dest-tls-verify=false "$repo:$chosen" "docker-archive:${tmp_dest}:$dest_ref" >>"$skopeo_log" 2>&1
    rc=$?
  else
    skopeo copy --dest-tls-verify=false "$repo:$chosen" "docker-archive:${tmp_dest}:$dest_ref" >>"$skopeo_log" 2>&1
    rc=$?
  fi
  if [[ $rc -ne 0 ]]; then
    log ERROR "skopeo copy failed for $repo:$chosen (exit $rc). See $skopeo_log for raw output"
    # append the tail of the skopeo log into the main log for quick inspection
    if [[ -f "$skopeo_log" ]]; then
      printf "--- skopeo output (last 200 lines) ---\n" >>"$LOG_FILE" || true
      tail -n 200 "$skopeo_log" >>"$LOG_FILE" 2>&1 || true
      printf "--- end skopeo output ---\n" >>"$LOG_FILE" || true
    fi
    rm -f "$tmp_dest" || true
    return 1
  fi
  log INFO "skopeo copy completed (exit 0) for $repo:$chosen -> $tmp_dest ($dest_ref)"
  # Move into final location atomically (mv will overwrite existing file)
  mv -T "$tmp_dest" "$dest" >>"$LOG_FILE" 2>&1 || {
    log ERROR "Failed to move mirrored hardened-cni into place: $tmp_dest -> $dest"
    # if move fails, include skopeo log for debugging
    if [[ -f "$skopeo_log" ]]; then
      printf "--- skopeo output (last 200 lines) ---\n" >>"$LOG_FILE" || true
      tail -n 200 "$skopeo_log" >>"$LOG_FILE" 2>&1 || true
      printf "--- end skopeo output ---\n" >>"$LOG_FILE" || true
    fi
    rm -f "$tmp_dest" || true
    return 1
  }
  chmod 0644 "$dest" || true
  # also copy the skopeo raw log alongside named artifact logs for post-mortem
  if [[ -f "$skopeo_log" ]]; then
    cp -f "$skopeo_log" "$LOG_DIR/" 2>/dev/null || true
  fi
  chmod 0644 "$dest" || true

  # Generate per-file sha and append to downloads manifest (idempotent)
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$DOWNLOADS_DIR" && sha256sum "$bn" > "${bn}.sha256") || true
    local manifest="$DOWNLOADS_DIR/$SHA256_FILE"
    local sha
    sha=$(sha256sum "$DOWNLOADS_DIR/$bn" | awk '{print $1}') || sha=""
    if [[ -n "$sha" ]]; then
      if [[ -f "$manifest" ]]; then
        local mtmp
        mtmp=$(mktemp)
        grep -v -F " $bn" "$manifest" > "$mtmp" || true
        printf "%s  %s\n" "$sha" "$bn" >> "$mtmp"
        mv "$mtmp" "$manifest"
      else
        printf "%s  %s\n" "$sha" "$bn" > "$manifest"
      fi
      log INFO "Appended hardened-cni checksum to manifest: $manifest"
    fi
  fi

  log INFO "skopeo mirrored hardened-cni -> $dest"
  return 0
}

# ------------------------------------------------------------------------------
# Function: cache_hardened_multus_skopeo
# Purpose : Mirror `rancher/hardened-multus-cni` into a local docker-archive
#           tarball for offline Multus deployments.
# Arguments:
#   $1 - Optional explicit tag to use
# Returns : 0 on success, non-zero on failure
# ------------------------------------------------------------------------------
cache_hardened_multus_skopeo() {
  local explicit_tag="${1:-}"
  local bn="${HARDENED_MULTUS_BN:-hardened-multus-cni-${ARCH}.tar}"
  local repo="docker://rancher/hardened-multus-cni"

  if ! command -v skopeo >/dev/null 2>&1; then
    log WARN "skopeo not available; cannot mirror hardened-multus-cni"
    return 2
  fi

  mkdir -p "$DOWNLOADS_DIR"

  local desired_tag=""
  local desired_tag_source=""
  if [[ -n "$explicit_tag" ]]; then
    desired_tag="$explicit_tag"
    desired_tag_source="explicit"
  elif [[ -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
    desired_tag=$(extract_hardened_multus_tag_from_images "$DOWNLOADS_DIR/$IMAGES_TAR" 2>/dev/null || true)
    [[ -n "$desired_tag" ]] && desired_tag_source="images-tar"
  fi

  local chosen=""
  if [[ -n "$desired_tag" ]]; then
    chosen="$desired_tag"
  else
    local tags_json
    tags_json=$(skopeo list-tags "$repo" 2>/dev/null) || tags_json=""
    if command -v python3 >/dev/null 2>&1; then
      chosen=$(python3 - <<'PY' "$tags_json" 2>/dev/null || true
import json,re,sys
raw=sys.argv[1]
tags=[]
try:
    doc=json.loads(raw) if raw else {}
    tags=doc.get("Tags") or []
except Exception:
    tags=[]

def score(tag):
    m=re.search(r'build(\d{8})$', tag)
    b=int(m.group(1)) if m else -1
    sv=re.match(r'^v(\d+)\.(\d+)\.(\d+)', tag)
    if sv:
        major,minor,patch=map(int,sv.groups())
    else:
        major=minor=patch=-1
    return (b,major,minor,patch,tag)

if not tags:
    print("latest")
else:
    print(sorted(tags, key=score, reverse=True)[0])
PY
)
    fi
    [[ -n "$chosen" ]] || chosen="latest"
  fi

  log INFO "skopeo: chosen hardened-multus tag='$chosen' (desired='${desired_tag:-}'; source='${desired_tag_source:-auto}')"

  local dest="$DOWNLOADS_DIR/$bn"
  local tmp_dest
  tmp_dest=$(mktemp -p "$DOWNLOADS_DIR" ".tmp-${bn}.XXXXXX") || tmp_dest="$DOWNLOADS_DIR/.tmp-${bn}.$$.tmp"
  rm -f "$tmp_dest" || true

  local dest_ref="rancher/hardened-multus-cni:${chosen}"
  local rc=0
  if command -v timeout >/dev/null 2>&1; then
    timeout 300 skopeo copy --dest-tls-verify=false "$repo:$chosen" "docker-archive:${tmp_dest}:$dest_ref" >>"$LOG_FILE" 2>&1 || rc=$?
  else
    skopeo copy --dest-tls-verify=false "$repo:$chosen" "docker-archive:${tmp_dest}:$dest_ref" >>"$LOG_FILE" 2>&1 || rc=$?
  fi

  if [[ $rc -ne 0 ]]; then
    log ERROR "skopeo copy failed for $repo:$chosen (exit $rc)"
    rm -f "$tmp_dest" || true
    return 1
  fi

  mv -T "$tmp_dest" "$dest" >>"$LOG_FILE" 2>&1 || {
    log ERROR "Failed to move mirrored hardened-multus into place: $tmp_dest -> $dest"
    rm -f "$tmp_dest" || true
    return 1
  }
  chmod 0644 "$dest" || true

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$DOWNLOADS_DIR" && sha256sum "$bn" > "${bn}.sha256") || true
    local manifest="$DOWNLOADS_DIR/$SHA256_FILE"
    local sha
    sha=$(sha256sum "$DOWNLOADS_DIR/$bn" | awk '{print $1}') || sha=""
    if [[ -n "$sha" ]]; then
      if [[ -f "$manifest" ]]; then
        local mtmp
        mtmp=$(mktemp)
        grep -v -F " $bn" "$manifest" > "$mtmp" || true
        printf "%s  %s\n" "$sha" "$bn" >> "$mtmp"
        mv "$mtmp" "$manifest"
      else
        printf "%s  %s\n" "$sha" "$bn" > "$manifest"
      fi
      log INFO "Appended hardened-multus checksum to manifest: $manifest"
    fi
  fi

  log INFO "skopeo mirrored hardened-multus -> $dest"
  return 0
}

  # ----------------------------------------------------------------------------
  # Function: cache_hardened_flannel_skopeo
  # Purpose : Mirror `rancher/hardened-flannel` into a local docker-archive
  #           tarball for offline Canal (flannel) deployments.
  # Arguments:
  #   $1 - Optional explicit tag to use
  # Returns : 0 on success, non-zero on failure
  # ----------------------------------------------------------------------------
  cache_hardened_flannel_skopeo() {
    local explicit_tag="${1:-}"
    local bn="${HARDENED_FLANNEL_BN:-hardened-flannel-${ARCH}.tar}"
    local repo="docker://rancher/hardened-flannel"

    if ! command -v skopeo >/dev/null 2>&1; then
      log WARN "skopeo not available; cannot mirror hardened-flannel"
      return 2
    fi

    mkdir -p "$DOWNLOADS_DIR"

    local desired_tag=""
    local desired_tag_source=""
    if [[ -n "$explicit_tag" ]]; then
      desired_tag="$explicit_tag"
      desired_tag_source="explicit"
    elif [[ -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
      desired_tag=$(extract_hardened_flannel_tag_from_images "$DOWNLOADS_DIR/$IMAGES_TAR" 2>/dev/null || true)
      [[ -n "$desired_tag" ]] && desired_tag_source="images-tar"
    fi

    local chosen=""
    if [[ -n "$desired_tag" ]]; then
      chosen="$desired_tag"
    else
      local tags_json
      tags_json=$(skopeo list-tags "$repo" 2>/dev/null) || tags_json=""
      if command -v python3 >/dev/null 2>&1; then
        chosen=$(python3 - <<'PY' "$tags_json" 2>/dev/null || true
  import json,re,sys
  raw=sys.argv[1]
  tags=[]
  try:
      doc=json.loads(raw) if raw else {}
      tags=doc.get("Tags") or []
  except Exception:
      tags=[]

  def score(tag):
      m=re.search(r'build(\d{8})$', tag)
      b=int(m.group(1)) if m else -1
      sv=re.match(r'^v(\d+)\.(\d+)\.(\d+)', tag)
      if sv:
          major,minor,patch=map(int,sv.groups())
      else:
          major=minor=patch=-1
      return (b,major,minor,patch,tag)

  if not tags:
      print("latest")
  else:
      print(sorted(tags, key=score, reverse=True)[0])
  PY
  )
      fi
      [[ -n "$chosen" ]] || chosen="latest"
    fi

    log INFO "skopeo: chosen hardened-flannel tag='$chosen' (desired='${desired_tag:-}'; source='${desired_tag_source:-auto}')"

    local dest="$DOWNLOADS_DIR/$bn"
    local tmp_dest
    tmp_dest=$(mktemp -p "$DOWNLOADS_DIR" ".tmp-${bn}.XXXXXX") || tmp_dest="$DOWNLOADS_DIR/.tmp-${bn}.$$.tmp"
    rm -f "$tmp_dest" || true

    local dest_ref="rancher/hardened-flannel:${chosen}"
    local rc=0
    if command -v timeout >/dev/null 2>&1; then
      timeout 300 skopeo copy --dest-tls-verify=false "$repo:$chosen" "docker-archive:${tmp_dest}:$dest_ref" >>"$LOG_FILE" 2>&1 || rc=$?
    else
      skopeo copy --dest-tls-verify=false "$repo:$chosen" "docker-archive:${tmp_dest}:$dest_ref" >>"$LOG_FILE" 2>&1 || rc=$?
    fi

    if [[ $rc -ne 0 ]]; then
      log ERROR "skopeo copy failed for $repo:$chosen (exit $rc)"
      rm -f "$tmp_dest" || true
      return 1
    fi

    mv -T "$tmp_dest" "$dest" >>"$LOG_FILE" 2>&1 || {
      log ERROR "Failed to move mirrored hardened-flannel into place: $tmp_dest -> $dest"
      rm -f "$tmp_dest" || true
      return 1
    }
    chmod 0644 "$dest" || true

    if command -v sha256sum >/dev/null 2>&1; then
      (cd "$DOWNLOADS_DIR" && sha256sum "$bn" > "${bn}.sha256") || true
      local manifest="$DOWNLOADS_DIR/$SHA256_FILE"
      local sha
      sha=$(sha256sum "$DOWNLOADS_DIR/$bn" | awk '{print $1}') || sha=""
      if [[ -n "$sha" ]]; then
        if [[ -f "$manifest" ]]; then
          local mtmp
          mtmp=$(mktemp)
          grep -v -F " $bn" "$manifest" > "$mtmp" || true
          printf "%s  %s
  " "$sha" "$bn" >> "$mtmp"
          mv "$mtmp" "$manifest"
        else
          printf "%s  %s
  " "$sha" "$bn" > "$manifest"
        fi
        log INFO "Appended hardened-flannel checksum to manifest: $manifest"
      fi
    fi

    log INFO "skopeo mirrored hardened-flannel -> $dest"
    return 0
  }

# ------------------------------------------------------------------------------
# Function: log
# Purpose : Write a structured log line to both stdout (for interactive
#           feedback) and the rotating logfile (for long term evidence).
# Arguments:
#   $1 - Log level string (e.g., INFO, WARN, ERROR)
#   $@ - Message components to be concatenated into a single log entry
# Returns :
#   Always returns 0. Errors while writing to the logfile will surface due to
#   set -e semantics.
# ------------------------------------------------------------------------------
log() {
  local level="$1"; shift
  local msg="$*"
  local ts host
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  host="$(hostname)"
  echo "[$level] $msg"
  # Only write to log file if LOG_FILE is set
  if [[ -n "${LOG_FILE:-}" ]]; then
    printf "%s %s rke2nodeinit[%d]: %s %s\n" "$ts" "$host" "$$" "$level:" "$msg" >> "$LOG_FILE"
  fi
}

# ------------------------------------------------------------------------------
# Function: warn_default_credentials
# Purpose : Emit a warning if the script is using hardcoded default credentials.
#           This helps prevent accidental use of example values in production.
# Arguments:
#   $1 - Registry host
#   $2 - Registry username
#   $3 - Registry password
# Returns : Always returns 0
# ------------------------------------------------------------------------------
warn_default_credentials() {
  local reg="$1" user="$2" pass="$3"
  # Check if using the exact default values from the script header
  if [[ "$reg" == "rke2registry.dev.local" && "$user" == "admin" && "$pass" == "ZAQwsx!@#123" ]]; then
    log WARN "Using EXAMPLE default credentials! These should be overridden for production use."
    log WARN "Override with: -r <registry> -u <username> -p <password> or via YAML config."
  fi
}

# ------------------------------------------------------------------------------
# Function: get_images_archive
# Purpose : Locate the staged images archive in downloads or images dir
# Arguments:
#   None
# Returns : Prints path to archive or returns 1 if not found
# ------------------------------------------------------------------------------
get_images_archive() {
  local img="${IMAGES_TAR:-rke2-images.linux-${ARCH}.tar.zst}"
  local images_dir="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"
  if [[ -f "$images_dir/$img" ]]; then
    printf '%s' "$images_dir/$img"
    return 0
  fi
  if [[ -f "$DOWNLOADS_DIR/$img" ]]; then
    printf '%s' "$DOWNLOADS_DIR/$img"
    return 0
  fi
  return 1
}

# ------------------------------------------------------------------------------
# Function: load_images_from_tarball
# Purpose : Load images from a staged RKE2 images tarball into the local
#           container runtime (nerdctl/ctr). Writes a small metadata file on
#           success and logs progress.
# Arguments:
#   $1 - Optional path to tarball (defaults to discovered candidate)
# Returns : 0 on success, non-zero on failure
# ------------------------------------------------------------------------------
# shellcheck disable=SC2120  # Arguments are optional; auto-discovery used when omitted
load_images_from_tarball() {
  local archive="$1"
  if [[ -z "$archive" ]]; then
    archive="$(get_images_archive || true)"
  fi
  if [[ -z "$archive" || ! -f "$archive" ]]; then
    log WARN "No images archive found to load (expected: ${IMAGES_TAR}). Skipping image load."
    return 0
  fi

  log INFO "Loading images from archive: $archive"

  # Prefer nerdctl if available; ensure it's installed by caller
  if command -v nerdctl >/dev/null 2>&1; then
    if zstd -dc "$archive" | nerdctl load -i - >>"$LOG_FILE" 2>&1; then
      log INFO "Loaded images via nerdctl"
    else
      log ERROR "nerdctl failed to load images from $archive"
      return 2
    fi
  else
    # Fallback to ctr
    if zstd -dc "$archive" | ctr -n k8s.io images import - >>"$LOG_FILE" 2>&1; then
      log INFO "Loaded images via ctr"
    else
      log ERROR "ctr failed to import images from $archive"
      return 3
    fi
  fi

  # Emit a simple metadata file listing images present (nerdctl images output)
  local meta="$STAGE_DIR/images-loaded-$(date -u +%Y%m%dT%H%M%SZ).txt"
  if command -v nerdctl >/dev/null 2>&1; then
    nerdctl images >>"$meta" 2>&1 || true
  else
    ctr -n k8s.io images ls >>"$meta" 2>&1 || true
  fi
  log INFO "Wrote image load metadata to $meta"

  # Runtime verification: check if images were successfully loaded into container runtime
  # Note: This only verifies runtime state. Tarball integrity is verified separately during staging.
  log INFO "Verifying images loaded into container runtime..."
  if (command -v nerdctl >/dev/null 2>&1 && nerdctl images | grep -q 'hardened-cni-plugins') || \
     (ctr -n k8s.io images ls | grep -q 'hardened-cni-plugins'); then
    log INFO "✓ Runtime verification passed: representative image 'hardened-cni-plugins' found in container runtime"
  else
    log WARN "⚠ Runtime verification: 'hardened-cni-plugins' not found in container runtime after load"
    log WARN "   This may indicate: (1) archive uses different image names, (2) import failed silently, or (3) runtime filtering"
    log WARN "   Tarball integrity should be verified separately. RKE2 installer will attempt to use staged tarball."
  fi

  return 0
}

# ------------------------------------------------------------------------------
# Function: spinner_run
# Purpose : Execute a long-running command while providing an inline progress
#           spinner on stdout. All command output is streamed to the logfile so
#           the terminal remains quiet and the operator receives a live status
#           indicator.
# Arguments:
#   $1 - Human readable label displayed next to the spinner
#   $@ - Command and arguments to execute
# Returns :
#   Propagates the exit code of the wrapped command.
# ------------------------------------------------------------------------------
spinner_run() {
  local label="$1"; shift
  local cmd=( "$@" )
  log INFO "$label..."

  ( "${cmd[@]}" >>"$LOG_FILE" 2>&1 ) &
  local pid=$!

  # Forward signals to the child so Ctrl-C works cleanly
  trap 'kill -TERM "$pid" 2>/dev/null' TERM INT

  local spin='|+/-\o' i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r[WORK] %s %s" "${spin:i++%${#spin}:1}" "$label"
    sleep 0.15
  done

  # Protect wait from set -e
  local rc
  if wait "$pid"; then
    rc=0
  else
    rc=$?
  fi

  trap - TERM INT
  printf "\r"
  if (( rc == 0 )); then
    echo "[DONE] $label"
    log INFO "$label...done"
  else
    echo "[FAIL] $label (rc=$rc)"
    log ERROR "$label failed (rc=$rc). See $LOG_FILE"
    exit "$rc"
  fi
}

# ------------------------------------------------------------------------------
# Function: default_node_hostname
# Purpose : Determine the hostname that should be used when a CLI override is
#           not provided. Prefers the static hostname reported by hostnamectl
#           and falls back to the classic hostname command.
# Arguments:
#   None
# Returns :
#   Prints the detected hostname to stdout.
# ------------------------------------------------------------------------------
default_node_hostname() {
  local name
  name="$(hostnamectl --static 2>/dev/null || hostname 2>/dev/null || uname -n)"
  echo "$name"
}

# ------------------------------------------------------------------------------
# Function: find_kubectl_binary
# Purpose : Locate the kubectl binary distributed with RKE2 or available in the
#           PATH so node-level administrative commands can be executed.
# Arguments:
#   None
# Returns :
#   Prints the kubectl path when found. Returns 1 when unavailable.
# ------------------------------------------------------------------------------
find_kubectl_binary() {
  if command -v kubectl >/dev/null 2>&1; then
    command -v kubectl
    return 0
  fi

  local candidate="/var/lib/rancher/rke2/bin/kubectl"
  if [[ -x "$candidate" ]]; then
    echo "$candidate"
    return 0
  fi

  return 1
}

# ------------------------------------------------------------------------------
# Function: detect_kubeconfig
# Purpose : Best-effort discovery of an RKE2 kubeconfig so kubectl invocations
#           can communicate with the local cluster when KUBECONFIG is unset.
# Arguments:
#   None
# Returns :
#   Prints the kubeconfig path when found. Returns 1 if no candidate exists.
# ------------------------------------------------------------------------------
detect_kubeconfig() {
  if [[ -n "${KUBECONFIG:-}" && -f "${KUBECONFIG}" ]]; then
    echo "$KUBECONFIG"
    return 0
  fi

  local -a candidates=(
    "/etc/rancher/rke2/rke2.yaml"
    "/var/lib/rancher/rke2/agent/etc/rke2.yaml"
    "$HOME/.kube/config"
  )

  local cfg
  for cfg in "${candidates[@]}"; do
    if [[ -f "$cfg" ]]; then
      echo "$cfg"
      return 0
    fi
  done

  return 1
}

# ------------------------------------------------------------------------------
# Section: YAML Parsing Helpers
# Purpose: Provide shell-friendly parsing utilities for the minimal YAML schema
#          consumed by the script. These helpers intentionally avoid external
#          dependencies so the script remains portable in constrained, offline
#          environments.
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Function: yaml_get_api
# Purpose : Extract the apiVersion field from a YAML document.
# Arguments:
#   $1 - Path to the YAML file to inspect
# Returns :
#   Prints the apiVersion string (without surrounding whitespace) to stdout.
# ------------------------------------------------------------------------------
yaml_get_api() {
  grep -E '^[[:space:]]*apiVersion:[[:space:]]*' "$1" | awk -F: '{print $2}' | xargs
}

# ------------------------------------------------------------------------------
# Function: yaml_get_kind
# Purpose : Extract the kind field from a YAML document so the caller can route
#           execution logic.
# Arguments:
#   $1 - Path to the YAML file to inspect
# Returns :
#   Prints the kind string to stdout.
# Implementation:
#   Uses grep to match 'kind:' line, awk to split on colon and extract value,
#   xargs to trim whitespace. Fast and sufficient for single-value extraction.
# ------------------------------------------------------------------------------
yaml_get_kind() {
  grep -E '^[[:space:]]*kind:[[:space:]]*' "$1" | awk -F: '{print $2}' | xargs
}

# ------------------------------------------------------------------------------
# Function: yaml_spec_get
# Purpose : Retrieve a scalar value located under the spec: section of the YAML
#           configuration using a dotted key path (e.g., registry.username).
# Arguments:
#   $1 - Path to the YAML document
#   $2 - Dotted key representing the nested field within spec
# Returns :
#   Prints the located value to stdout. Exits with non-zero status if the key is
#   not present.
# ------------------------------------------------------------------------------
yaml_spec_get() {
  local file="$1" key="$2"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$file" "$key" <<'PY'
import re
import sys

file_path, key_path = sys.argv[1:3]
parts = key_path.split('.')  # Split dotted path: "customCA.rootCrt" -> ["customCA", "rootCrt"]
target_depth = len(parts)

try:
    with open(file_path, encoding='utf-8') as fh:
        in_spec = False
        stack = []        # Current nested key path as we parse the YAML structure
        indent_stack = [] # Parallel indentation levels to track when to pop from stack
        for raw_line in fh:
            line = raw_line.rstrip('\n')
            if not in_spec:
                # Skip everything until we find the 'spec:' section
                if re.match(r'^\s*spec:\s*$', line):
                    in_spec = True
                continue

            if not line.strip() or line.lstrip().startswith('#'):
                continue

            indent = len(line) - len(line.lstrip(' '))
            if indent < 1:
                break  # Left the spec: section (back to top level)

            # Pop stack when we dedent (moving back to shallower nesting level)
            # Example: if we go from "    key:" (indent=4) to "  key:" (indent=2),
            # we pop the deeper keys from our tracking stack
            while indent_stack and indent <= indent_stack[-1]:
                stack.pop()
                indent_stack.pop()

            match = re.match(r'^\s*([^:#]+):\s*(.*)$', line)
            if not match:
                continue

            # Add current key to stack and track its indentation level
            stack.append(match.group(1).strip())
            indent_stack.append(indent)

            # Check if current stack path matches the requested key path
            # Example: if looking for "customCA.rootCrt", stack must be ["customCA", "rootCrt"]
            if stack[:len(parts)] != parts[:len(stack)]:
                continue

            value = match.group(2).strip()
            if len(stack) == target_depth and value:
                # Found exact match at correct depth - extract and return value
                value = re.sub(r'\s+#.*$', '', value).strip()  # Remove inline comments
                if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]  # Strip quotes
                print(value)
                sys.exit(0)
except FileNotFoundError:
    pass

sys.exit(1)
PY
    return
  fi

  awk -v k="$key" '
    BEGIN { inSpec=0 }
    /^[[:space:]]*spec:[[:space:]]*$/ { inSpec=1; next }
    inSpec==1 {
      if ($0 ~ /^[^[:space:]]/) { exit }
      if ($0 ~ "^[[:space:]]+" k "[[:space:]]*:") {
        line=$0
        sub(/^[[:space:]]+/, "", line)
        sub(k "[[:space:]]*:[[:space:]]*", "", line)
        sub(/[[:space:]]+#.*$/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        print line
        exit
      }
    }
  ' "$file"
}

# ------------------------------------------------------------------------------
# Function: yaml_spec_get_any
# Purpose : Return the first non-empty value among a list of dotted keys under
#           the YAML spec section. Useful for honoring legacy aliases.
# Arguments:
#   $1 - Path to the YAML document
#   $@ - One or more dotted keys to evaluate in order
# Returns :
#   Prints the first discovered value to stdout and returns 0. Returns 1 when no
#   keys produce a value.
# ------------------------------------------------------------------------------
yaml_spec_get_any() {
  # Usage: yaml_spec_get_any <file> <key1> [key2] [key3] ...
  local file="$1"; shift || true
  local k
  for k in "$@"; do
    local v
    v="$(yaml_spec_get "$file" "$k" || true)"
    if [[ -n "$v" ]]; then
      echo "$v"
      return 0
    fi
  done
  return 1
}

# ------------------------------------------------------------------------------
# Function: yaml_spec_has_list
# Purpose : Determine whether a spec.<key> entry is represented as a YAML list.
# Arguments:
#   $1 - Path to the YAML document
#   $2 - Key that may point to a list
# Returns :
#   Returns 0 when the key is a list, 1 otherwise.
# ------------------------------------------------------------------------------
yaml_spec_has_list() {
  # Return 0 if spec.<key> is a YAML list
  local file="$1"; local key="$2"
  awk -v k="$key" '
    BEGIN { inSpec=0; found=0; }
    /^[[:space:]]*spec:[[:space:]]*$/ { inSpec=1; next }
    inSpec==1 {
      if ($0 ~ /^[^[:space:]]/) { exit } # left spec
      if ($0 ~ "^[[:space:]]+" k "[[:space:]]*:[[:space:]]*$") { found=1; next }
      if (found==1) {
        if ($0 ~ "^[[:space:]]*-[[:space:]]+") { print "YES"; exit }
        else if ($0 ~ "^[[:space:]]*$") { next } # skip blanks
        else if ($0 ~ "^[[:space:]]*#") { next } # skip comments
        else { exit } # not a list
      }
    }
  ' "$file" | grep -q YES
}

# ------------------------------------------------------------------------------
# Function: yaml_spec_list_items
# Purpose : Emit each item from a YAML list located under spec.<key>. Items are
#           printed without surrounding quotes to keep downstream parsing simple.
# Arguments:
#   $1 - Path to the YAML document
#   $2 - Key referencing a YAML list under spec
# Returns :
#   Prints zero or more lines, one per list item. Returns 0 even if the list is
#   empty.
# ------------------------------------------------------------------------------
yaml_spec_list_items() {
  # Print items of a YAML list under spec.<key>, one per line (no quoting)
  local file="$1"; local key="$2"
  awk -v k="$key" '
    BEGIN { inSpec=0; collect=0; }
    /^[[:space:]]*spec:[[:space:]]*$/ { inSpec=1; next }
    inSpec==1 {
      if ($0 ~ /^[^[:space:]]/) { exit } # left spec
      if ($0 ~ "^[[:space:]]+" k "[[:space:]]*:[[:space:]]*$") { collect=1; next }
      if (collect==1) {
        if ($0 ~ "^[[:space:]]*-[[:space:]]+(.*)$") {
          sub(/^[[:space:]]*-[[:space:]]+/, "", $0)
          gsub(/^"|'\''|"$/, "", $0)
          print $0
        } else if ($0 ~ "^[[:space:]]*$") {
          next
        } else {
          exit
        }
      }
    }
  ' "$file"
}

# ------------------------------------------------------------------------------
# Function: yaml_spec_list_csv
# Purpose : Produce a comma-separated representation of a YAML list located
#           under spec.<key>. This simplifies shell ingestion of repeated
#           values.
# Arguments:
#   $1 - Path to the YAML document
#   $2 - Key referencing a YAML list under spec
# Returns :
#   Prints a CSV string when list entries exist. Returns 1 when the list is
#   absent.
# ------------------------------------------------------------------------------
yaml_spec_list_csv() {
  # Emit a comma-separated list from spec.<key> YAML list (if any)
  local file="$1"; local key="$2"
  local items; items="$(yaml_spec_list_items "$file" "$key" | tr '\n' ',' | sed 's/,$//')"
  [[ -n "$items" ]] && echo "$items"
}

# ------------------------------------------------------------------------------
# Function: append_spec_config_extras
# Purpose : Merge optional configuration keys from the YAML spec into the
#           generated /etc/rancher/rke2/config.yaml while preventing duplicate
#           entries.
# Arguments:
#   $1 - Path to the YAML document supplying optional overrides
# Returns :
#   Always returns 0 after conditionally appending keys.
# ------------------------------------------------------------------------------
append_spec_config_extras() {
  # Append additional config.yaml keys present in spec that we should honor.
  # Skips keys already present to avoid duplicates.
  local file="$1"
  [[ -z "$file" || ! -f "$file" ]] && return 0
  local cfg="/etc/rancher/rke2/config.yaml"

  # Helper to avoid duplicate keys
  _cfg_has_key() { grep -Eq "^[[:space:]]*$1[[:space:]]*:" "$cfg" 2>/dev/null; }

  # Scalars we pass through as-is if present
  local -a scalars=(
    "cluster-cidr" "service-cidr" "cluster-dns" "cluster-domain"
    "system-default-registry" "embedded-registry" "disable-default-registry-endpoint" "private-registry" "write-kubeconfig-mode"
    "selinux" "protect-kernel-defaults" "kube-apiserver-image" "kube-controller-manager-image"
    "kube-scheduler-image" "etcd-image" "disable-cloud-controller" "disable-kube-proxy"
    # Image overrides commonly required to avoid external pulls in air-gapped installs
    "kube-proxy-image" "pause-image" "runtime-image"
    "enable-servicelb" "node-ip" "bind-address" "advertise-address"
  )


  local k v
  for k in "${scalars[@]}"; do
    _cfg_has_key "$k" && continue
    # Try the hyphenated key first, then a lower-camelCase variant that many
    # example YAML files use (e.g., nodeIp, bindAddress).
  # build camelCase (node-ip -> nodeIp)
  camel_case="$(echo "$k" | awk -F- '{printf "%s", $1; for(i=2;i<=NF;i++){printf toupper(substr($i,1,1)) substr($i,2)}}')" || true
  v="$(yaml_spec_get_any "$file" "$k" "$camel_case" || true)"
    if [[ -n "$v" ]]; then
      local normalized=""
      # If value looks like true/false, normalize and emit bare boolean
      if [[ "$v" =~ ^(true|false|True|False|TRUE|FALSE)$ ]]; then
        normalized="$(normalize_bool_value "$v")"
        echo "$k: $normalized" >> "$cfg"
      else
        # Quote string-like values to ensure YAML correctness (images, registries, CIDRs)
        # Escape any existing double-quotes in the value
        local esc
        esc=$(printf '%s' "$v" | sed 's/"/\\"/g')
        echo "$k: \"$esc\"" >> "$cfg"
      fi
    fi
  done

  # Lists we support (emit YAML arrays)
  local -a lists=(
    "kube-apiserver-arg" "kube-controller-manager-arg" "kube-scheduler-arg" "kube-proxy-arg"
    "node-taint" "node-label" "tls-san" "cni" "disable"
  )

  for k in "${lists[@]}"; do
    _cfg_has_key "$k" && continue
    if yaml_spec_has_list "$file" "$k"; then
      echo "$k:" >> "$cfg"
      yaml_spec_list_items "$file" "$k" | sed 's/^/  - /' >> "$cfg"
    else
      # Fallback: some manifests express these as scalars (e.g., cni: "cilium")
      local scalar_val
      scalar_val="$(yaml_spec_get "$file" "$k" || true)"
      if [[ -n "$scalar_val" ]]; then
        # Emit either a scalar or a single-item list depending on key semantics
        if [[ "$k" == "cni" ]]; then
          # cni can be a scalar in RKE2 config
          echo "$k: \"$scalar_val\"" >> "$cfg"
        else
          # default: emit as a single item list
          echo "$k:" >> "$cfg"
          echo "  - $scalar_val" >> "$cfg"
        fi
      fi
    fi
  done
}

# ------------------------------------------------------------------------------
# Function: yaml_meta_get
# Purpose : Read a value from the YAML metadata section (e.g., metadata.name).
# Arguments:
#   $1 - Path to the YAML document
#   $2 - Key to extract from metadata
# Returns :
#   Prints the matching value when found, otherwise returns 1.
# ------------------------------------------------------------------------------
yaml_meta_get() {
  local file="$1" key="$2"
  awk -v k="$key" '
    BEGIN { inMeta=0 }
    /^[[:space:]]*metadata:[[:space:]]*$/ { inMeta=1; next }
    inMeta==1 {
      if ($0 ~ /^[^[:space:]]/) { exit }
      if ($0 ~ "^[[:space:]]+" k "[[:space:]]*:") {
        sub(/^[[:space:]]+/, "", $0)
        sub(k "[[:space:]]*:[[:space:]]*", "", $0)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
        print $0
        exit
      }
    }
  ' "$file"
}

# ------------------------------------------------------------------------------
# Function: ensure_yaml_has_metadata_name
# Purpose : Guarantee that metadata.name exists in the provided YAML file and
#           update SPEC_NAME accordingly so downstream logging and artifacts are
#           namespaced.
# Arguments:
#   $1 - Optional path to the YAML file (defaults to CONFIG_FILE)
# Returns :
#   Exits with status 2 when metadata.name is absent. Otherwise returns 0.
# ------------------------------------------------------------------------------
ensure_yaml_has_metadata_name() {
  local file="${1:-$CONFIG_FILE}"
  [[ -z "$file" || ! -f "$file" ]] && return 0
  local name
  name="$(yaml_meta_get "$file" name || true)"
  if [[ -z "$name" ]]; then
    echo "ERROR: YAML file '$file' is missing required 'metadata.name'." >&2
    echo "Add at least:" >&2
    echo "  metadata:" >&2
    echo "    name: <your-config-name>" >&2
    exit 2
  fi
  SPEC_NAME="$name"
  log INFO "YAML metadata.name: ${SPEC_NAME}"
}

# ------------------------------------------------------------------------------
# Function: sanitize_yaml
# Purpose : Output a copy of the YAML configuration with secrets and tokens
#           masked. This prevents sensitive values from leaking into logs or
#           terminals when operators request a configuration preview.
# Arguments:
#   $1 - Path to the YAML document
# Returns :
#   Prints the sanitized YAML to stdout.
# ------------------------------------------------------------------------------
sanitize_yaml() {
  sed -E \
    -e 's/(registryPassword:[[:space:]]*)"[^"]*"/\1"********"/' \
    -e 's/(registryPassword:[[:space:]]*)([^"[:space:]].*)/\1"********"/' \
    -e 's/(token:[[:space:]]*)"[^"]*"/\1"********"/' \
    -e 's/(token:[[:space:]]*)([^"[:space:]].*)/\1"********"/' \
    "$1"
}

# ------------------------------------------------------------------------------
# Function: normalize_list_csv
# Purpose : Convert list-like strings (with brackets or varied quoting) into a
#           clean, comma-separated representation suitable for prompts and
#           logging.
# Arguments:
#   $1 - Raw list value
# Returns :
#   Prints the normalized CSV string.
# ------------------------------------------------------------------------------
normalize_list_csv() {
  local v="$1"
  v="${v#\[}"; v="${v%\]}"
  v="${v//\"/}"; v="${v//\'/}"
  echo "$v" | sed 's/,/ /g' | xargs | sed 's/ /, /g'
}

# ------------------------------------------------------------------------------
# Section: Network Interface Helpers
# Purpose: Provide encoding/decoding utilities for multi-interface support that
#          allow YAML, CLI, and interactive prompts to share a common format.
# ------------------------------------------------------------------------------

# Trim leading and trailing whitespace without relying on external utilities.
# Handles edge cases: empty strings and whitespace-only strings safely.
# Uses bash parameter expansion pattern matching:
#   ${var#pattern}  - remove shortest match from beginning
#   ${var%pattern}  - remove shortest match from end
#   ${var%%pattern} - remove longest match from beginning (greedy)
#   ${var##pattern} - remove longest match from end (greedy)
trim_whitespace() {
  local _s="$1"
  # Handle empty or whitespace-only strings
  [[ -z "$_s" || ! "$_s" =~ [^[:space:]] ]] && return 0
  # Strip leading whitespace:
  #   ${_s%%[![:space:]]*} finds everything up to first non-space
  #   ${_s#...} removes that prefix, leaving string from first non-space onward
  _s="${_s#${_s%%[![:space:]]*}}"
  # Strip trailing whitespace:
  #   ${_s##*[![:space:]]} finds everything after last non-space
  #   ${_s%...} removes that suffix, leaving string up to last non-space
  _s="${_s%${_s##*[![:space:]]}}"
  printf '%s' "$_s"
}

# Encode an associative array describing a NIC into a pipe-delimited string.
# Format: "key1=value1|key2=value2|key3=value3"
# This allows passing complex interface configuration through simple strings.
# Ordered fields are emitted first for consistency, then any extra fields.
interface_encode_assoc() {
  local -n _nic="$1"
  # Define canonical field order for consistent output
  local -a _order=(name dhcp4 cidr ip prefix gateway dns search addresses mtu metric)
  local -a _parts=()

  local _key
  # First pass: emit known fields in defined order
  for _key in "${_order[@]}"; do
    if [[ -n "${_nic[${_key}]:-}" ]]; then
      _parts+=("${_key}=${_nic[${_key}]}")
    fi
  done

  # Second pass: append any extra fields not in the canonical order
  for _key in "${!_nic[@]}"; do
    local _normalized="${_key,,}"
    if [[ " ${_order[*]} " == *" ${_normalized} "* ]]; then
      continue  # Already handled in first pass
    fi
    _parts+=("${_normalized}=${_nic[$_key]}")
  done

  # Join all parts with pipe delimiter
  (IFS='|'; echo "${_parts[*]}")
}

# Decode a pipe-delimited NIC string into an associative array supplied by name.
# Input format: "name=eth0|ip=10.0.0.5|prefix=24|gateway=10.0.0.1"
# Output: Populates the associative array referenced by $2 with normalized keys.
# Normalizes legacy/alias field names (e.g., "address" -> "ip", "gw" -> "gateway").
# Returns 0 on success, 1 if the entry is empty or invalid.
interface_decode_entry() {
  local _entry="$1"
  local -n _dest="$2"
  _dest=()

  # Validate entry is not empty
  [[ -z "$_entry" ]] && return 1

  # Split on pipe delimiter into array of key=value pairs
  IFS='|' read -r -a _pairs <<<"$_entry"

  # Validate we have at least one pair
  if (( ${#_pairs[@]} == 0 )); then
    return 1
  fi

  local _pair _key _value
  for _pair in "${_pairs[@]}"; do
    [[ -z "$_pair" ]] && continue
    _key="${_pair%%=*}"; _value="${_pair#*=}"
    _key="${_key,,}"  # Normalize to lowercase
    # Map legacy/alias field names to canonical names
    case "$_key" in
      interface|nic) _key="name" ;;
      address) _key="ip" ;;
      cidrprefix) _key="prefix" ;;
      gw) _key="gateway" ;;
      nameservers) _key="dns" ;;
      searchdomains) _key="search" ;;
      dhcp) _key="dhcp4" ;;
    esac
    _dest["$_key"]="$_value"
  done

  return 0
}

# Convert CLI tokens (key=value pairs) into an encoded NIC string.
interface_cli_tokens_to_entry() {
  local -a _tokens=("$@")
  local -A _nic=()
  local _token _key _value
  for _token in "${_tokens[@]}"; do
    if [[ "$_token" != *=* ]]; then
      log ERROR "Interface tokens must be key=value (got '$_token')."
      exit 1
    fi
    _key="${_token%%=*}"; _value="${_token#*=}"
    _key="${_key,,}"
    case "$_key" in
      interface|nic) _key="name" ;;
      address) _key="ip" ;;
      cidrprefix) _key="prefix" ;;
      gw) _key="gateway" ;;
      nameservers) _key="dns" ;;
      searchdomains) _key="search" ;;
      dhcp) _key="dhcp4" ;;
    esac
    _nic["$_key"]="$_value"
  done
  interface_encode_assoc _nic
}

# Produce a comma-separated list suitable for YAML inline arrays.
format_inline_list() {
  local _raw="$1"
  [[ -z "$_raw" ]] && return
  local _clean
  _clean="${_raw#\[}"; _clean="${_clean%\]}"
  _clean="${_clean//;/,}"
  local -a _items=()
  local -a _tmp_items=()
  IFS=',' read -r -a _tmp_items <<<"$_clean"
  local _item
  for _item in "${_tmp_items[@]}"; do
    _item="$(trim_whitespace "$_item")"
    [[ -n "$_item" ]] && _items+=("$_item")
  done
  (IFS=', '; echo "${_items[*]}")
}

# Detect the most likely primary network interface for the host.
detect_primary_interface() {
  local _nic
  _nic="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1 || true)"
  if [[ -z "$_nic" ]]; then
    local _path _candidate
    for _path in /sys/class/net/*; do
      _candidate="${_path##*/}"
      if [[ "$_candidate" =~ ^(lo|docker|cni|flannel|kube|veth|virbr|br-) ]]; then
        continue
      fi
      _nic="$_candidate"
      break
    done
  fi
  echo "$_nic"
}

# ------------------------------------------------------------------------------
# Function: yaml_spec_interfaces
# Purpose : Extract spec.interfaces entries from YAML as encoded NIC strings.
# Arguments:
#   $1 - Path to YAML configuration file
# Returns :
#   Prints encoded interface strings to stdout (one per line)
# ------------------------------------------------------------------------------
yaml_spec_interfaces() {
  local _file="$1"
  [[ -z "$_file" || ! -f "$_file" ]] && return 0
  if ! command -v python3 >/dev/null 2>&1; then
    log WARN "python3 not available; skipping spec.interfaces parsing for $_file"
    return 0
  fi
  python3 - "$_file" <<'PY'
import re
import sys

file_path = sys.argv[1]
try:
    with open(file_path, encoding='utf-8') as fh:
        lines = fh.readlines()
except FileNotFoundError:
    sys.exit(0)
except Exception as e:
    # Log error to stderr and exit gracefully
    print(f"Error reading YAML file: {e}", file=sys.stderr)
    sys.exit(0)

def strip_quotes(value: str) -> str:
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return value[1:-1]
    if value.startswith("'") and value.endswith("'") and len(value) >= 2:
        return value[1:-1]
    return value

items = []
in_spec = False
interfaces_indent = None
current = None
current_indent = None
last_list_key = None
last_list_indent = None

def flush_current():
    global current
    if current is not None:
        items.append(current)
        current = None

for raw in lines:
    line = raw.rstrip('\n')
    if not in_spec:
        if re.match(r'^\s*spec\s*:\s*$', line):
            in_spec = True
        continue

    if interfaces_indent is None:
        if re.match(r'^\s*interfaces\s*:\s*$', line):
            interfaces_indent = len(line) - len(line.lstrip(' '))
        elif re.match(r'^\S', line):
            break
        continue

    if re.match(r'^\S', line):
        flush_current()
        break

    if not line.strip() or line.lstrip().startswith('#'):
        continue

    indent = len(line) - len(line.lstrip(' '))

    # Exit interfaces section if we encounter a spec key at same indent level as 'interfaces:'
    # This must be checked before dash_match to avoid treating sibling list items as interface items
    if indent == interfaces_indent and re.match(r'^\s*[a-zA-Z][\w-]*\s*:', line):
        flush_current()
        break

    dash_match = re.match(r'^\s*-\s*(.*)$', line)
    if dash_match:
        rest = dash_match.group(1).strip()
        if current is not None and indent > (current_indent or interfaces_indent) and last_list_key:
            value = strip_quotes(rest)
            current.setdefault(last_list_key, []).append(value)
            continue
        flush_current()
        current = {}
        current_indent = indent
        last_list_key = None
        if rest:
            key, _, value = rest.partition(':')
            key = key.strip()
            value = value.strip()
            value = re.sub(r'\s+#.*$', '', value)
            if value == '':
                last_list_key = key
                last_list_indent = indent
                current.setdefault(key, [])
            else:
                value = strip_quotes(value)
                if value.startswith('[') and value.endswith(']'):
                    inner = value[1:-1]
                    if inner.strip():
                        current[key] = [strip_quotes(v.strip()) for v in inner.split(',')]
                    else:
                        current[key] = []
                else:
                    current[key] = value
        continue

    if current is None:
        continue

    key_value = re.match(r'^\s*([^:#]+):\s*(.*)$', line)
    if key_value:
        key = key_value.group(1).strip()
        value = key_value.group(2).strip()
        value = re.sub(r'\s+#.*$', '', value)
        if value == '':
            last_list_key = key
            last_list_indent = indent
            current.setdefault(key, [])
        else:
            last_list_key = None
            value = strip_quotes(value)
            if value.startswith('[') and value.endswith(']'):
                inner = value[1:-1]
                if inner.strip():
                    current[key] = [strip_quotes(v.strip()) for v in inner.split(',')]
                else:
                    current[key] = []
            else:
                current[key] = value
        continue

    list_item = re.match(r'^\s*-\s*(.*)$', line)
    if list_item and last_list_key and indent > (last_list_indent or interfaces_indent):
        value = strip_quotes(list_item.group(1).strip())
        current.setdefault(last_list_key, []).append(value)
        continue

flush_current()

try:
    for item in items:
        parts = []
        for key, value in item.items():
            if isinstance(value, list):
                if value:  # Only include non-empty lists
                    parts.append(f"{key}=" + ",".join(value))
            else:
                parts.append(f"{key}={value}")
        if parts:
            print("|".join(parts))
except Exception as e:
    # Log error to stderr and exit gracefully without breaking the shell script
    print(f"Error processing interface data: {e}", file=sys.stderr)
    sys.exit(0)
PY
}

# Merge interfaces defined in YAML and CLI blobs into an array supplied by name.
collect_interface_specs() {
  local -n _dest="$1"
  local _config="$2"
  local _cli_blob="$3"
  _dest=()

  if [[ -n "$_config" ]]; then
    mapfile -t _dest < <(yaml_spec_interfaces "$_config" || true)
  fi

  if [[ -n "$_cli_blob" ]]; then
    while IFS= read -r _line; do
      [[ -z "$_line" ]] && continue
      _dest+=("$_line")
    done <<<"$_cli_blob"
  fi
}

# Normalize the first interface entry and propagate values back to legacy vars.
merge_primary_interface_fields() {
  local -n _ifaces="$1"
  local -n _ip_ref="$2"
  local -n _prefix_ref="$3"
  local -n _gw_ref="$4"
  local -n _dns_ref="$5"
  local -n _search_ref="$6"

  local -A _primary=()
  local _has_entry=0
  if (( ${#_ifaces[@]} )); then
    if ! interface_decode_entry "${_ifaces[0]}" _primary; then
      log WARN "Failed to decode primary interface entry; using empty defaults"
    else
      _has_entry=1
    fi
  fi

  local _dhcp="${_primary[dhcp4]:-}"
  _dhcp="${_dhcp,,}"

  if [[ "$_dhcp" != "true" ]]; then
    if [[ -n "${_primary[cidr]:-}" ]]; then
      local _cidr="${_primary[cidr]}"
      if [[ -z "$_ip_ref" && "$_cidr" == */* ]]; then
        _ip_ref="${_cidr%/*}"
        [[ -z "$_prefix_ref" ]] && _prefix_ref="${_cidr#*/}"
      fi
    fi
    if [[ -z "$_ip_ref" && -n "${_primary[ip]:-}" ]]; then
      local _ipvalue="${_primary[ip]}"
      if [[ "$_ipvalue" == */* ]]; then
        _ip_ref="${_ipvalue%/*}"
        [[ -z "$_prefix_ref" ]] && _prefix_ref="${_ipvalue#*/}"
      else
        _ip_ref="$_ipvalue"
      fi
    fi
    if [[ -z "$_prefix_ref" && -n "${_primary[prefix]:-}" ]]; then
      _prefix_ref="${_primary[prefix]}"
    fi
    if [[ -z "$_gw_ref" && -n "${_primary[gateway]:-}" ]]; then
      _gw_ref="${_primary[gateway]}"
    fi
  fi

  if [[ -z "$_dns_ref" && -n "${_primary[dns]:-}" ]]; then
    _dns_ref="${_primary[dns]}"
  fi
  if [[ -z "$_search_ref" && -n "${_primary[search]:-}" ]]; then
    _search_ref="${_primary[search]}"
  fi

  if [[ -n "$_ip_ref" && -z "$_prefix_ref" ]]; then
    _prefix_ref=24
  fi

  if [[ "$_dhcp" != "true" ]]; then
    [[ -n "$_ip_ref" ]] && _primary[ip]="$_ip_ref"
    [[ -n "$_prefix_ref" ]] && _primary[prefix]="$_prefix_ref"
    [[ -n "$_gw_ref" ]] && _primary[gateway]="$_gw_ref"
  fi
  [[ -n "$_dns_ref" ]] && _primary[dns]="$(normalize_list_csv "$_dns_ref")"
  [[ -n "$_search_ref" ]] && _primary[search]="$(normalize_list_csv "$_search_ref")"

  local _encoded="$(interface_encode_assoc _primary)"
  if (( _has_entry )); then
    _ifaces[0]="$_encoded"
  elif [[ -n "$_encoded" ]]; then
    _ifaces=("$_encoded")
  fi
}

# Interactive helper to append extra interfaces when the operator opts in.
prompt_additional_interfaces() {
  local -n _ifaces="$1"
  local _default_dns="$2"
  local _prompt_label="$3"

  while true; do
    local _resp=""
    read -rp "Add another network interface${_prompt_label:+ for $_prompt_label}? [y/N]: " _resp || break
    [[ "$_resp" =~ ^[Yy]$ ]] || break

    local _name=""
    while [[ -z "$_name" ]]; do
      read -rp "Interface name (e.g., eth1): " _name || return
      _name="$(trim_whitespace "$_name")"
    done

    local _dhcp_resp=""
    read -rp "Use DHCP for $_name? [y/N]: " _dhcp_resp || return
    local -A _nic=( [name]="$_name" )
    if [[ "$_dhcp_resp" =~ ^[Yy]$ ]]; then
      _nic[dhcp4]="true"
    else
      local _ip="" _prefix="" _gw="" _dns="" _search=""
      while [[ -z "$_ip" ]]; do
        read -rp "Static IPv4 for $_name: " _ip || return
        _ip="$(trim_whitespace "$_ip")"
        valid_ipv4 "$_ip" || { echo "Invalid IPv4."; _ip=""; }
      done
      read -rp "Prefix length for $_name [default 24]: " _prefix || true
      _prefix="$(trim_whitespace "$_prefix")"
      while [[ -n "$_prefix" ]]; do
        if valid_prefix "$_prefix"; then
          break
        fi
        read -rp "Invalid prefix. Re-enter [default 24]: " _prefix || true
        _prefix="$(trim_whitespace "$_prefix")"
      done
      [[ -z "$_prefix" ]] && _prefix=24
      read -rp "Default gateway for $_name [optional]: " _gw || true
      _gw="$(trim_whitespace "$_gw")"
      while [[ -n "$_gw" ]]; do
        if valid_ipv4_or_blank "$_gw"; then
          break
        fi
        read -rp "Invalid gateway. Re-enter (blank to skip): " _gw || true
        _gw="$(trim_whitespace "$_gw")"
      done
      read -rp "DNS servers for $_name (comma-separated) [optional]: " _dns || true
      _dns="$(trim_whitespace "$_dns")"
      while [[ -n "$_dns" ]]; do
        if valid_csv_dns "$_dns"; then
          break
        fi
        read -rp "Invalid DNS list. Re-enter for $_name: " _dns || true
        _dns="$(trim_whitespace "$_dns")"
      done
      read -rp "Search domains for $_name (comma-separated) [optional]: " _search || true
      _search="$(trim_whitespace "$_search")"
      while [[ -n "$_search" ]]; do
        if valid_search_domains_csv "$_search"; then
          break
        fi
        read -rp "Invalid search domain list. Re-enter for $_name: " _search || true
        _search="$(trim_whitespace "$_search")"
      done

      _nic[ip]="$_ip"
      _nic[prefix]="$_prefix"
      [[ -n "$_gw" ]] && _nic[gateway]="$_gw"
      if [[ -n "$_dns" ]]; then
        _nic[dns]="$(normalize_list_csv "$_dns")"
      elif [[ -n "$_default_dns" ]]; then
        _nic[dns]="$(normalize_list_csv "$_default_dns")"
      fi
      [[ -n "$_search" ]] && _nic[search]="$(normalize_list_csv "$_search")"
    fi

    _ifaces+=("$(interface_encode_assoc _nic)")
  done
}

# ------------------------------------------------------------------------------
# Function: parse_action_cli_args
# Purpose : Parse residual CLI arguments passed after the action name so that
#           actions can honor flag-style overrides without requiring YAML.
# Arguments:
#   $1 - Name of an associative array to populate with parsed values
#   $2 - Action label (used for error reporting)
#   $3+ - CLI arguments to parse
# Returns :
#   Populates the referenced associative array with any recognized values.
# ------------------------------------------------------------------------------
parse_action_cli_args() {
  local -n _dest="$1"
  local action_label="$2"
  shift 2 || true

  _dest=()
  local -a args=("$@")
  local tls_value="" tls_csv=""

  while (( ${#args[@]} )); do
    local arg="${args[0]}"
    args=("${args[@]:1}")

    case "$arg" in
      --)
        break
        ;;
      --interface)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --interface requires key=value tokens (e.g., --interface name=eth1 ip=10.0.0.5 prefix=24)"; exit 1
        fi
        local -a _if_tokens=()
        while (( ${#args[@]} )) && [[ "${args[0]}" != --* ]]; do
          _if_tokens+=("${args[0]}")
          args=("${args[@]:1}")
        done
        if (( ${#_if_tokens[@]} == 0 )); then
          log ERROR "[$action_label] --interface must be followed by key=value tokens"; exit 1
        fi
        local _if_entry
        _if_entry="$(interface_cli_tokens_to_entry "${_if_tokens[@]}")"
        if [[ -n "${_dest[interfaces]:-}" ]]; then
          _dest[interfaces]+=$'\n'"${_if_entry}"
        else
          _dest[interfaces]="${_if_entry}"
        fi
        ;;
      --interface=*)
        log ERROR "[$action_label] --interface expects key=value tokens separated by spaces (e.g., --interface name=eth1 ip=10.0.0.5 prefix=24)"; exit 1
        ;;
      --hostname)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --hostname requires a value"; exit 1
        fi
        _dest[hostname]="${args[0]}"
        args=("${args[@]:1}")
        ;;
      --hostname=*)
        _dest[hostname]="${arg#*=}"
        ;;
      --ip)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --ip requires a value"; exit 1
        fi
        _dest[ip]="${args[0]}"
        args=("${args[@]:1}")
        ;;
      --ip=*)
        _dest[ip]="${arg#*=}"
        ;;
      --prefix)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --prefix requires a value"; exit 1
        fi
        _dest[prefix]="${args[0]}"
        args=("${args[@]:1}")
        ;;
      --prefix=*)
        _dest[prefix]="${arg#*=}"
        ;;
      --gateway)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --gateway requires a value"; exit 1
        fi
        _dest[gateway]="${args[0]}"
        args=("${args[@]:1}")
        ;;
      --gateway=*)
        _dest[gateway]="${arg#*=}"
        ;;
      --dns)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --dns requires a value"; exit 1
        fi
        _dest[dns]="${args[0]}"
        args=("${args[@]:1}")
        ;;
      --dns=*)
        _dest[dns]="${arg#*=}"
        ;;
      --search-domains)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --search-domains requires a value"; exit 1
        fi
        _dest[search_domains]="${args[0]}"
        args=("${args[@]:1}")
        ;;
      --search-domains=*)
        _dest[search_domains]="${arg#*=}"
        ;;
      --token)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --token requires a value"; exit 1
        fi
        _dest[token]="${args[0]}"
        args=("${args[@]:1}")
        ;;
      --token=*)
        _dest[token]="${arg#*=}"
        ;;
      --token-file)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --token-file requires a value"; exit 1
        fi
        _dest[token_file]="${args[0]}"
        args=("${args[@]:1}")
        ;;
      --token-file=*)
        _dest[token_file]="${arg#*=}"
        ;;
      --server-url)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --server-url requires a value"; exit 1
        fi
        _dest[server_url]="${args[0]}"
        args=("${args[@]:1}")
        ;;
      --server-url=*)
        _dest[server_url]="${arg#*=}"
        ;;
      --tls-san)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --tls-san requires a value"; exit 1
        fi
        tls_value="${args[0]}"
        args=("${args[@]:1}")
        if [[ -n "${_dest[tls_sans]:-}" ]]; then
          _dest[tls_sans]+=",${tls_value}"
        else
          _dest[tls_sans]="${tls_value}"
        fi
        ;;
      --tls-san=*)
        tls_value="${arg#*=}"
        if [[ -n "${_dest[tls_sans]:-}" ]]; then
          _dest[tls_sans]+=",${tls_value}"
        else
          _dest[tls_sans]="${tls_value}"
        fi
        ;;
      --tls-sans)
        if (( ${#args[@]} == 0 )); then
          log ERROR "[$action_label] --tls-sans requires a value"; exit 1
        fi
        tls_csv="${args[0]}"
        args=("${args[@]:1}")
        if [[ -n "${_dest[tls_sans]:-}" ]]; then
          _dest[tls_sans]+=",${tls_csv}"
        else
          _dest[tls_sans]="${tls_csv}"
        fi
        ;;
      --tls-sans=*)
        tls_csv="${arg#*=}"
        if [[ -n "${_dest[tls_sans]:-}" ]]; then
          _dest[tls_sans]+=",${tls_csv}"
        else
          _dest[tls_sans]="${tls_csv}"
        fi
        ;;
      --*)
        log WARN "[$action_label] Ignoring unrecognized CLI flag: $arg"
        ;;
      *)
        log WARN "[$action_label] Ignoring unexpected CLI argument: $arg"
        ;;
    esac
  done
}

# ------------------------------------------------------------------------------
# Function: normalize_bool_value
# Purpose : Normalize boolean-like user input into lowercase true/false strings
#           for safe YAML emission.
# Arguments:
#   $1 - Raw value to normalize
# Returns :
#   Prints "true" or "false" depending on the input content.
# ------------------------------------------------------------------------------
normalize_bool_value() {
  local raw="${1:-}"
  # shellcheck disable=SC2001
  local v
  v="$(echo "$raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

  if [[ ${#v} -ge 2 ]]; then
    if [[ ${v:0:1} == '"' && ${v: -1} == '"' ]]; then
      v="${v:1:-1}"
    elif [[ ${v:0:1} == "'" && ${v: -1} == "'" ]]; then
      v="${v:1:-1}"
    fi
  fi

  local lowered="${v,,}"
  if [[ -z "$lowered" ]]; then
    echo '""'
  elif [[ "$lowered" =~ ^(true|false)$ ]]; then
    echo "$lowered"
  elif [[ "$lowered" =~ ^[0-9]+$ ]]; then
    echo "$lowered"
  else
    printf '"%s"\n' "$lowered"
  fi
}

# ------------------------------------------------------------------------------
# Function: bool_value_is_true
# Purpose : Interpret boolean-like values from CLI/YAML safely.
# Arguments:
#   $1 - Raw value
# Returns :
#   0 when value is true/1/yes/on, non-zero otherwise.
# ------------------------------------------------------------------------------
bool_value_is_true() {
  local raw="${1:-}"
  local v
  v="$(echo "$raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

  if [[ ${#v} -ge 2 ]]; then
    if [[ ${v:0:1} == '"' && ${v: -1} == '"' ]]; then
      v="${v:1:-1}"
    elif [[ ${v:0:1} == "'" && ${v: -1} == "'" ]]; then
      v="${v:1:-1}"
    fi
  fi

  case "${v,,}" in
    true|1|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

# ------------------------------------------------------------------------------
# Function: install_cni_permission_remediation
# Purpose : Install and enable timer-based CNI permissions remediation used to
#           prevent Multus startup failures when host CNI paths are hardened.
# Arguments:
#   None (uses REPO_ROOT and DRY_RUN globals)
# Returns :
#   0 on success, non-zero on failure.
# ------------------------------------------------------------------------------
install_cni_permission_remediation() {
  local script_src="$REPO_ROOT/scripts/fix-cni-perms.sh"
  local svc_src="$REPO_ROOT/scripts/systemd/rke2-cni-perms.service"
  local timer_src="$REPO_ROOT/scripts/systemd/rke2-cni-perms.timer"

  if [[ ! -f "$script_src" || ! -f "$svc_src" || ! -f "$timer_src" ]]; then
    log_error "CNI remediation assets missing in repository"
    log_error "Expected: $script_src, $svc_src, $timer_src"
    return 1
  fi

  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    log_info "DRY-RUN: Would install /usr/local/sbin/fix-cni-perms.sh"
    log_info "DRY-RUN: Would install systemd units rke2-cni-perms.service and rke2-cni-perms.timer"
    log_info "DRY-RUN: Would run systemctl daemon-reload and enable --now service+timer"
    return 0
  fi

  install -m 0755 "$script_src" /usr/local/sbin/fix-cni-perms.sh || return 1
  install -m 0644 "$svc_src" /etc/systemd/system/rke2-cni-perms.service || return 1
  install -m 0644 "$timer_src" /etc/systemd/system/rke2-cni-perms.timer || return 1

  systemctl daemon-reload >>"$LOG_FILE" 2>&1 || return 1
  systemctl disable --now rke2-cni-perms.path >>"$LOG_FILE" 2>&1 || true
  systemctl reset-failed rke2-cni-perms.service rke2-cni-perms.timer >>"$LOG_FILE" 2>&1 || true
  systemctl enable --now rke2-cni-perms.service rke2-cni-perms.timer >>"$LOG_FILE" 2>&1 || return 1

  return 0
}

# ------------------------------------------------------------------------------
# Function: initialize_action_context
# Purpose : Enforce metadata.name requirements when a YAML file is provided and
#           optionally configure per-run output directories/log files based on
#           the metadata name.
# Arguments:
#   $1 - Literal "true" to set up run directories; anything else skips
#   $2 - Optional label written to the log when a run directory is created
# Returns :
#   Returns 0 on success. Exits if metadata.name is missing.
# ------------------------------------------------------------------------------
initialize_action_context() {
  local create_run_dir="${1:-false}"
  local label="${2:-}"

  if [[ -n "$CONFIG_FILE" ]]; then
    ensure_yaml_has_metadata_name "$CONFIG_FILE"
  fi

  if [[ "$create_run_dir" == "true" && -n "${SPEC_NAME:-}" ]]; then
    mkdir -p "$OUT_DIR/$SPEC_NAME"
    RUN_OUT_DIR="$OUT_DIR/$SPEC_NAME"
    LOG_FILE="$LOG_DIR/${SPEC_NAME}_$(date -u +"%Y-%m-%dT%H-%M-%SZ").log"
    export LOG_FILE RUN_OUT_DIR
    if [[ -n "$label" ]]; then
      log INFO "[$label] Using run output directory: $RUN_OUT_DIR"
    else
      log INFO "Using run output directory: $RUN_OUT_DIR"
    fi
  elif [[ -z "$LOG_FILE" ]]; then
    # Set default log file if not set by action context
    LOG_FILE="$LOG_DIR/rke2nodeinit_$(date -u +"%Y-%m-%dT%H-%M-%SZ").log"
    export LOG_FILE
  fi
}

# ------------------------------------------------------------------------------
# Function: valid_ipv4
# Purpose : Validate dotted-decimal IPv4 addresses provided by users or YAML
#           inputs.
# Arguments:
#   $1 - IPv4 string
# Returns :
#   Returns 0 when the IPv4 is syntactically valid and each octet falls within
#   0-255. Returns 1 otherwise.
# ------------------------------------------------------------------------------
valid_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<<"$1"
  for n in "$a" "$b" "$c" "$d"; do [[ "$n" -ge 0 && "$n" -le 255 ]] || return 1; done
}

# ------------------------------------------------------------------------------
# Function: valid_prefix
# Purpose : Ensure CIDR prefix lengths are within 0-32 when provided. Blank
#           values are treated as acceptable defaults.
# Arguments:
#   $1 - Prefix length string
# Returns :
#   Returns 0 for valid prefixes or blanks, 1 otherwise.
# ------------------------------------------------------------------------------
valid_prefix() {
  [[ -z "$1" ]] && return 0
  [[ "$1" =~ ^[0-9]{1,2}$ ]] && (( $1>=0 && $1<=32 ))
}

# ------------------------------------------------------------------------------
# Function: valid_ipv4_or_blank
# Purpose : Accept either an empty string or a syntactically valid IPv4 address.
# Arguments:
#   $1 - IPv4 string or blank
# Returns :
#   Returns 0 when blank or valid IPv4, 1 otherwise.
# ------------------------------------------------------------------------------
valid_ipv4_or_blank() {
  [[ -z "$1" ]] && return 0
  valid_ipv4 "$1"
}

# ------------------------------------------------------------------------------
# Function: valid_csv_dns
# Purpose : Validate comma-separated IPv4 DNS lists entered via prompts or YAML
#           files.
# Arguments:
#   $1 - CSV string of IPv4 addresses
# Returns :
#   Returns 0 when every entry is a valid IPv4 address. Returns 1 otherwise.
# ------------------------------------------------------------------------------
valid_csv_dns() {
  [[ -z "$1" ]] && return 0
  local s; s="$(echo "$1" | sed 's/,/ /g')"
  for x in $s; do valid_ipv4 "$x" || return 1; done
}

# ------------------------------------------------------------------------------
# Function: valid_search_domains_csv
# Purpose : Validate comma-separated DNS search domains supplied by operators.
# Arguments:
#   $1 - CSV string of domain names
# Returns :
#   Returns 0 when each domain conforms to RFC 1123 hostname requirements.
# ------------------------------------------------------------------------------
valid_search_domains_csv() {
  [[ -z "$1" ]] && return 0
  local s; s="$(echo "$1" | sed 's/,/ /g')"
  for d in $s; do
    [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$ ]] || return 1
  done
}

# ------------------------------------------------------------------------------
# Function: ensure_installed
# Purpose : Verify that the specified APT package is present and install it
#           non-interactively when missing.
# Arguments:
#   $1 - Debian package name
# Returns :
#   Returns 0 when the package is installed successfully.
# ------------------------------------------------------------------------------
ensure_installed() {
  local pkg="$1"
  dpkg -s "$pkg" &>/dev/null || {
    log INFO "Installing package: $pkg"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >>"$LOG_FILE" 2>&1
    apt-get install -y "$pkg" >>"$LOG_FILE" 2>&1
  }
}

# ------------------------------------------------------------------------------
# Function: detect_virtualization
# Purpose : Determine whether the current node is virtualized and, when it is,
#           identify the hypervisor so the appropriate guest tools can be
#           installed.
# Arguments:
#   None
# Returns :
#   Prints a pipe-delimited triple to stdout: class|type|hypervisor where class
#   is "physical" or "virtual".
# ------------------------------------------------------------------------------
detect_virtualization() {
  local class="physical" virt_type="" hypervisor="" vendor="" product=""

  if command -v systemd-detect-virt >/dev/null 2>&1; then
    if systemd-detect-virt --quiet; then
      virt_type="$(systemd-detect-virt 2>/dev/null || true)"
      class="virtual"
    else
      virt_type="none"
    fi
  fi

  if [[ "$class" == "virtual" ]]; then
    vendor="$(tr '[:upper:]' '[:lower:]' </sys/devices/virtual/dmi/id/sys_vendor 2>/dev/null || true)"
    product="$(tr '[:upper:]' '[:lower:]' </sys/devices/virtual/dmi/id/product_name 2>/dev/null || true)"
    case "$virt_type" in
      vmware) hypervisor="vmware" ;;
      microsoft|hyperv) hypervisor="hyperv" ;;
      oracle) hypervisor="virtualbox" ;;
      kvm|qemu)
        if [[ "$vendor" == *"microsoft"* || "$product" == *"hyper-v"* ]]; then
          hypervisor="hyperv"
        elif [[ "$vendor" == *"vmware"* ]]; then
          hypervisor="vmware"
        else
          hypervisor="kvm"
        fi
        ;;
      xen) hypervisor="xen" ;;
      parallels) hypervisor="parallels" ;;
      *)
        if [[ "$vendor" == *"vmware"* ]]; then
          hypervisor="vmware"
        elif [[ "$vendor" == *"microsoft"* ]]; then
          hypervisor="hyperv"
        elif [[ "$vendor" == *"innotek"* || "$vendor" == *"oracle"* || "$vendor" == *"virtualbox"* || "$product" == *"virtualbox"* ]]; then
          hypervisor="virtualbox"
        elif [[ "$vendor" == *"xen"* ]]; then
          hypervisor="xen"
        fi
        ;;
    esac
    [[ -z "$hypervisor" && -n "$virt_type" ]] && hypervisor="$virt_type"
  fi

  printf '%s|%s|%s\n' "$class" "$virt_type" "$hypervisor"
}

# ------------------------------------------------------------------------------
# Function: install_vm_tools
# Purpose : Install hypervisor-specific guest tools when running within a
#           supported virtual environment.
# Arguments:
#   $1 - Canonical hypervisor identifier (e.g., vmware, hyperv, virtualbox)
# Returns :
#   Returns 0. Logs warnings when packages are unavailable or unsupported.
# ------------------------------------------------------------------------------
install_vm_tools() {
  local hypervisor="$1"
  local packages=()

  case "$hypervisor" in
    vmware)
      packages+=(open-vm-tools)
      ;;
    hyperv)
      packages+=(linux-cloud-tools-virtual linux-tools-virtual hyperv-daemons)
      ;;
    virtualbox)
      packages+=(virtualbox-guest-utils)
      ;;
    kvm|qemu)
      packages+=(qemu-guest-agent)
      ;;
    xen)
      packages+=(qemu-guest-agent)
      ;;
    *)
      if [[ -n "$hypervisor" ]]; then
        log WARN "No guest tools installation routine defined for hypervisor: $hypervisor"
      else
        log WARN "Unable to determine hypervisor for VM tools installation"
      fi
      return 0
  esac

  local to_install=()
  local pkg
  for pkg in "${packages[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
      log INFO "Package already installed: $pkg"
    elif apt-cache show "$pkg" >/dev/null 2>&1; then
      to_install+=("$pkg")
    else
      log WARN "Package not found in APT cache: $pkg (skipping)"
    fi
  done

  if (( ${#to_install[@]} > 0 )); then
    export DEBIAN_FRONTEND=noninteractive
    spinner_run "Installing VM guest tools (${to_install[*]})" apt-get install -y "${to_install[@]}"
  else
    log INFO "No additional VM guest tools packages required."
  fi
}

# ------------------------------------------------------------------------------
# Function: detect_vm_platform
# Purpose : Auto-detect virtualization platform for hostname query method used
#           in boot script automation.
# Arguments:
#   None
# Returns :
#   Prints platform identifier: vmware, hyperv, virtualbox, or generic
# ------------------------------------------------------------------------------
detect_vm_platform() {
  local platform="${VM_PLATFORM:-auto}"
  
  # If explicitly set, validate and return
  if [[ "$platform" != "auto" ]]; then
    case "$platform" in
      vmware|hyperv|virtualbox|generic)
        echo "$platform"
        return 0
        ;;
      *)
        log WARN "Invalid VM_PLATFORM '$platform'; falling back to auto-detection"
        platform="auto"
        ;;
    esac
  fi
  
  # Auto-detect based on available tools and system information
  if command -v vmtoolsd >/dev/null 2>&1; then
    echo "vmware"
  elif command -v hv_kvp_daemon >/dev/null 2>&1 || [[ -d /var/lib/hyperv ]]; then
    echo "hyperv"
  elif command -v VBoxControl >/dev/null 2>&1; then
    echo "virtualbox"
  elif [[ -f /sys/class/dmi/id/product_name ]]; then
    # Check DMI product name as fallback
    local product
    product=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)
    case "${product,,}" in
      *vmware*) echo "vmware" ;;
      *virtual*machine*) echo "hyperv" ;;
      *virtualbox*) echo "virtualbox" ;;
      *) echo "generic" ;;
    esac
  else
    echo "generic"
  fi
}

# ------------------------------------------------------------------------------
# Function: install_boot_script
# Purpose : Generate and install the first-boot automation script that queries
#           VM hostname, discovers matching config file, copies it to target
#           directory, and executes rke2nodeinit with the configuration.
# 
# Note for Hyper-V: The VM name must be set from the Hyper-V host using:
#   Set-VMKeyValuePairItem -VMName "vm-name" -Key "VirtualMachineName" -Value "vm-name"
#   Otherwise, the guest OS hostname will be used as fallback.
#
# Arguments:
#   None (uses global BOOT_SCRIPT_PATH, BOOT_CONFIG_SEARCH_PATHS, BOOT_TARGET_DIR)
# Returns :
#   0 on success, non-zero on failure
# ------------------------------------------------------------------------------
install_boot_script() {
  local platform
  platform="$(detect_vm_platform)"
  log INFO "Detected VM platform: $platform"
  
  local script_dir
  script_dir="$(dirname "$BOOT_SCRIPT_PATH")"
  
  # Ensure target directory exists
  mkdir -p "$script_dir" || {
    log ERROR "Failed to create directory for boot script: $script_dir"
    return 1
  }
  
  # Set default config search paths if not specified
  if [[ ${#BOOT_CONFIG_SEARCH_PATHS[@]} -eq 0 ]]; then
    BOOT_CONFIG_SEARCH_PATHS=(
      "$REPO_ROOT/configs"
      "/opt/rke2/configs"
      "/root/configs"
    )
  fi
  
  # Generate platform-specific hostname query command
  local hostname_query_cmd=""
  case "$platform" in
    vmware)
      hostname_query_cmd='VM_HOSTNAME=$(vmtoolsd --cmd "info-get guestinfo.hostname" 2>/dev/null || hostname)'
      ;;
    hyperv)
      # Hyper-V: Query VM name from KVP pool (requires host-side configuration)
      # Preferred method: Host admin sets custom KVP item via PowerShell:
      #   Set-VMKeyValuePairItem -VMName "vm-name" -Key "VirtualMachineName" -Value "vm-name"
      # 
      # Alternative: Use PowerShell to read VirtualMachineName from KVP pool_0
      # Fallback: Use guest hostname if not found
      hostname_query_cmd='
if command -v pwsh >/dev/null 2>&1; then
  # Try PowerShell to read KVP VirtualMachineName
  VM_HOSTNAME=$(pwsh -NoProfile -Command '\''
    try {
      $kvp0 = [System.IO.File]::ReadAllBytes("/var/lib/hyperv/.kvp_pool_0")
      $text = [System.Text.Encoding]::ASCII.GetString($kvp0)
      $lines = $text -split "\x00" | Where-Object {$_.Trim()}
      for($i=0; $i -lt $lines.Count; $i++) {
        if($lines[$i] -eq "VirtualMachineName" -and $i+1 -lt $lines.Count) {
          Write-Output $lines[$i+1].Trim()
          exit 0
        }
      }
    } catch {}
  '\'' 2>/dev/null)
fi
# Fallback to bash method if PowerShell fails or not available
[[ -z "$VM_HOSTNAME" ]] && VM_HOSTNAME=$(cat /var/lib/hyperv/.kvp_pool_0 2>/dev/null | tr "\\0" "\\n" | grep -A1 "^VirtualMachineName$" | tail -1 | xargs 2>/dev/null)
# Final fallback to hostname
[[ -z "$VM_HOSTNAME" ]] && VM_HOSTNAME=$(hostname)'
      ;;
    virtualbox)
      hostname_query_cmd='VM_HOSTNAME=$(VBoxControl guestproperty get /VirtualBox/HostInfo/VBoxVer 2>/dev/null | cut -d: -f2 | xargs 2>/dev/null || hostname)'
      ;;
    generic|*)
      # Generic: use system hostname
      hostname_query_cmd='VM_HOSTNAME=$(hostnamectl --static 2>/dev/null || hostname)'
      ;;
  esac
  
  # Generate boot script with config discovery
  cat > "$BOOT_SCRIPT_PATH" <<'EOF_BOOT_SCRIPT'
#!/usr/bin/env bash
#
# rke2-boot.sh - First-boot automation for RKE2 node initialization
# This script automatically discovers node configs by VM hostname, copies them
# to the target directory, and executes rke2nodeinit.sh for automatic setup.
#
# Workflow:
#   1. Query VM hostname from hypervisor (platform-specific)
#   2. Search for matching config file: {hostname}.yaml
#   3. Copy found config to /root/server-config/{hostname}.yaml
#   4. Execute rke2nodeinit.sh with the discovered config

set -euo pipefail

# Logging helper
log() {
  local level="$1"; shift
  echo "[$level] $*" | systemd-cat -t rke2-boot -p "${level,,}"
  echo "[$level] $*"
}

# Cleanup on error
cleanup_on_error() {
  log ERROR "Boot service failed - cleaning up"
  [[ -n "${TARGET_FILE:-}" && -f "$TARGET_FILE" ]] && rm -f "$TARGET_FILE"
  exit 1
}
trap cleanup_on_error ERR

log INFO "========================================"
log INFO "RKE2 First-Boot Automation Starting"
log INFO "========================================"

# Query VM hostname (platform-specific)
log INFO "Step 1: Query VM hostname from hypervisor"
EOF_BOOT_SCRIPT
  echo "$hostname_query_cmd" >> "$BOOT_SCRIPT_PATH"
  cat >> "$BOOT_SCRIPT_PATH" <<'EOF_BOOT_SCRIPT'

if [[ -z "$VM_HOSTNAME" ]]; then
  log ERROR "Unable to retrieve VM hostname from platform"
  exit 1
fi

log INFO "  Result: $VM_HOSTNAME"
export VM_HOSTNAME

# Define config search paths
log INFO "Step 2: Search for matching configuration file"
EOF_BOOT_SCRIPT
  # Embed search paths from global variable
  echo "CONFIG_SEARCH_PATHS=(" >> "$BOOT_SCRIPT_PATH"
  for search_path in "${BOOT_CONFIG_SEARCH_PATHS[@]}"; do
    echo "  \"$search_path\"" >> "$BOOT_SCRIPT_PATH"
  done
  echo ")" >> "$BOOT_SCRIPT_PATH"
  
  cat >> "$BOOT_SCRIPT_PATH" <<'EOF_BOOT_SCRIPT'

# Search for matching config file
FOUND_CONFIG=""
for search_path in "${CONFIG_SEARCH_PATHS[@]}"; do
  log INFO "  Searching: $search_path"
  candidate="$search_path/${VM_HOSTNAME}.yaml"
  
  if [[ -f "$candidate" ]]; then
    FOUND_CONFIG="$candidate"
    log INFO "  ✓ Found: $candidate"
    break
  fi
  
  # Try case-insensitive search as fallback
  if [[ -d "$search_path" ]]; then
    candidate_ci=$(find "$search_path" -maxdepth 1 -type f -iname "${VM_HOSTNAME}.yaml" -print -quit 2>/dev/null || true)
    if [[ -n "$candidate_ci" && -f "$candidate_ci" ]]; then
      FOUND_CONFIG="$candidate_ci"
      log INFO "  ✓ Found (case-insensitive): $candidate_ci"
      break
    fi
  fi
done

if [[ -z "$FOUND_CONFIG" ]]; then
  log ERROR "No configuration file found for hostname: $VM_HOSTNAME"
  log ERROR "Searched paths:"
  for path in "${CONFIG_SEARCH_PATHS[@]}"; do
    log ERROR "  - $path/${VM_HOSTNAME}.yaml"
  done
  log ERROR "Ensure the config file exists with exact hostname match"
  exit 1
fi

# Validate config file
log INFO "Step 3: Validate configuration file"
if [[ ! -r "$FOUND_CONFIG" ]]; then
  log ERROR "Config file not readable: $FOUND_CONFIG"
  exit 1
fi

# Basic YAML syntax validation (if yq available)
if command -v yq >/dev/null 2>&1; then
  if ! yq eval '.' "$FOUND_CONFIG" >/dev/null 2>&1; then
    log ERROR "YAML syntax validation failed: $FOUND_CONFIG"
    exit 1
  fi
  log INFO "  ✓ YAML syntax valid"
fi

# Check for required fields
if ! grep -q "apiVersion" "$FOUND_CONFIG" 2>/dev/null; then
  log WARN "  Missing 'apiVersion' field (recommended)"
fi
if ! grep -q "kind" "$FOUND_CONFIG" 2>/dev/null; then
  log WARN "  Missing 'kind' field (recommended)"
fi

# Copy config to target directory
log INFO "Step 4: Copy configuration to target directory"
EOF_BOOT_SCRIPT
  echo "TARGET_DIR=\"$BOOT_TARGET_DIR\"" >> "$BOOT_SCRIPT_PATH"
  cat >> "$BOOT_SCRIPT_PATH" <<'EOF_BOOT_SCRIPT'
mkdir -p "$TARGET_DIR" || {
  log ERROR "Failed to create target directory: $TARGET_DIR"
  exit 1
}

TARGET_FILE="$TARGET_DIR/${VM_HOSTNAME}.yaml"
if ! cp "$FOUND_CONFIG" "$TARGET_FILE"; then
  log ERROR "Failed to copy config to: $TARGET_FILE"
  exit 1
fi

# Set secure permissions (root read/write only)
chmod 600 "$TARGET_FILE" || {
  log ERROR "Failed to set permissions on: $TARGET_FILE"
  exit 1
}

log INFO "  ✓ Config copied to: $TARGET_FILE"
log INFO "  ✓ Permissions set: 600 (root only)"

# Set YAML_FILE for rke2nodeinit execution
YAML_FILE="$TARGET_FILE"

# Locate rke2nodeinit.sh script
log INFO "Step 5: Locate rke2nodeinit.sh script"
EOF_BOOT_SCRIPT
  echo "SCRIPT_PATH=\"$REPO_ROOT/bin/rke2nodeinit.sh\"" >> "$BOOT_SCRIPT_PATH"
  cat >> "$BOOT_SCRIPT_PATH" <<'EOF_BOOT_SCRIPT'

if [[ ! -x "$SCRIPT_PATH" ]]; then
  # Try alternate locations
  for candidate in /usr/local/bin/rke2nodeinit.sh /opt/rke2/bin/rke2nodeinit.sh; do
    if [[ -x "$candidate" ]]; then
      SCRIPT_PATH="$candidate"
      break
    fi
  done
fi

if [[ ! -x "$SCRIPT_PATH" ]]; then
  log ERROR "rke2nodeinit.sh script not found or not executable"
  log ERROR "Searched: $SCRIPT_PATH, /usr/local/bin, /opt/rke2/bin"
  exit 1
fi

log INFO "  ✓ Script found: $SCRIPT_PATH"

# Set environment variable to signal execution via boot service
export RKE2_BOOT_SERVICE=true

# Execute rke2nodeinit with the discovered YAML file
log INFO "Step 6: Execute RKE2 node initialization"
log INFO "  Command: $SCRIPT_PATH -f $YAML_FILE -y"
log INFO "========================================"

if "$SCRIPT_PATH" -f "$YAML_FILE" -y; then
  log INFO "========================================"
  log INFO "✓ RKE2 node initialization completed"
  log INFO "========================================"
  exit 0
else
  rc=$?
  log ERROR "========================================"
  log ERROR "✗ RKE2 node initialization failed"
  log ERROR "  Exit code: $rc"
  log ERROR "========================================"
  exit $rc
fi
EOF_BOOT_SCRIPT

  # Set proper permissions
  chmod 755 "$BOOT_SCRIPT_PATH" || {
    log ERROR "Failed to set permissions on boot script: $BOOT_SCRIPT_PATH"
    return 1
  }
  
  log INFO "Boot script installed: $BOOT_SCRIPT_PATH (platform: $platform)"
  return 0
}

# ------------------------------------------------------------------------------
# Function: install_boot_service
# Purpose : Create and install systemd service unit for first-boot automation.
# Arguments:
#   None (uses global BOOT_SERVICE_PATH, BOOT_SCRIPT_PATH, BOOT_SERVICE_MODE)
# Returns :
#   0 on success, non-zero on failure
# ------------------------------------------------------------------------------
install_boot_service() {
  local service_dir
  service_dir="$(dirname "$BOOT_SERVICE_PATH")"
  
  # Ensure systemd service directory exists
  mkdir -p "$service_dir" || {
    log ERROR "Failed to create systemd service directory: $service_dir"
    return 1
  }
  
  # Generate systemd service unit
  cat > "$BOOT_SERVICE_PATH" <<EOF
[Unit]
Description=RKE2 First-Boot Automation with Config Discovery
Documentation=https://github.com/cantrellcloud/rke2-node-init
After=network-online.target systemd-hostnamed.service
Wants=network-online.target
Requires=systemd-hostnamed.service
ConditionPathExists=$BOOT_SCRIPT_PATH
# Only run once on first boot (unless marker removed)
ConditionPathExists=!/var/lib/rke2-boot-complete

[Service]
Type=oneshot
ExecStart=$BOOT_SCRIPT_PATH
ExecStartPost=/bin/touch /var/lib/rke2-boot-complete
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rke2-boot
RemainAfterExit=yes
# Ensure script runs with root privileges
User=root
# Set working directory to script location
WorkingDirectory=$(dirname "$BOOT_SCRIPT_PATH")
# Restart on failure with backoff
Restart=on-failure
RestartSec=30
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
EOF

  chmod 644 "$BOOT_SERVICE_PATH" || {
    log ERROR "Failed to set permissions on service file: $BOOT_SERVICE_PATH"
    return 1
  }
  
  # Reload systemd to recognize new service
  if ! systemctl daemon-reload >>"$LOG_FILE" 2>&1; then
    log WARN "systemctl daemon-reload failed; service may not be immediately available"
  fi
  
  log INFO "Boot service installed: $BOOT_SERVICE_PATH"
  return 0
}

# ------------------------------------------------------------------------------
# Function: enable_boot_service
# Purpose : Enable the first-boot automation service so it runs on next reboot.
# Arguments:
#   None (uses global BOOT_SERVICE_PATH)
# Returns :
#   0 on success, non-zero on failure
# ------------------------------------------------------------------------------
enable_boot_service() {
  local service_name
  service_name="$(basename "$BOOT_SERVICE_PATH")"
  
  if ! systemctl enable "$service_name" >>"$LOG_FILE" 2>&1; then
    log ERROR "Failed to enable boot service: $service_name"
    return 1
  fi
  
  log INFO "Boot service enabled: $service_name (will run on next boot)"
  return 0
}

# ------------------------------------------------------------------------------
# Function: disable_boot_service
# Purpose : Disable and optionally mask the boot service after successful
#           execution in oneshot mode.
# Arguments:
#   None (uses global BOOT_SERVICE_PATH, BOOT_SERVICE_MODE)
# Returns :
#   0 on success, non-zero on failure
# ------------------------------------------------------------------------------
disable_boot_service() {
  local service_name
  service_name="$(basename "$BOOT_SERVICE_PATH")"
  
  if ! systemctl disable "$service_name" >>"$LOG_FILE" 2>&1; then
    log WARN "Failed to disable boot service: $service_name"
    return 1
  fi
  
  log INFO "Boot service disabled: $service_name"
  
  # Optionally mask the service to prevent accidental re-enable
  if [[ "$BOOT_SERVICE_MODE" == "oneshot" ]]; then
    if systemctl mask "$service_name" >>"$LOG_FILE" 2>&1; then
      log INFO "Boot service masked (oneshot mode): $service_name"
    else
      log WARN "Failed to mask boot service: $service_name"
    fi
  fi
  
  return 0
}

# ------------------------------------------------------------------------------
# Function: uninstall_boot_service_artifacts
# Purpose : Remove boot automation systemd unit and script from the host.
# Arguments:
#   None (uses global BOOT_SERVICE_PATH, BOOT_SCRIPT_PATH)
# Returns :
#   0 on success, non-zero on failure
# ------------------------------------------------------------------------------
uninstall_boot_service_artifacts() {
  local service_name
  service_name="$(basename "$BOOT_SERVICE_PATH")"

  if systemctl list-unit-files "$service_name" >/dev/null 2>&1 || [[ -f "$BOOT_SERVICE_PATH" ]]; then
    systemctl disable "$service_name" >>"$LOG_FILE" 2>&1 || true
    systemctl stop "$service_name" >>"$LOG_FILE" 2>&1 || true
    systemctl unmask "$service_name" >>"$LOG_FILE" 2>&1 || true
  fi

  if [[ -f "$BOOT_SERVICE_PATH" ]]; then
    rm -f "$BOOT_SERVICE_PATH" || {
      log ERROR "Failed to remove boot service unit: $BOOT_SERVICE_PATH"
      return 1
    }
  fi

  if [[ -f "$BOOT_SCRIPT_PATH" ]]; then
    rm -f "$BOOT_SCRIPT_PATH" || {
      log ERROR "Failed to remove boot script: $BOOT_SCRIPT_PATH"
      return 1
    }
  fi

  rm -f /var/lib/rke2-boot-complete || true

  if ! systemctl daemon-reload >>"$LOG_FILE" 2>&1; then
    log WARN "systemctl daemon-reload failed after boot artifact removal"
  fi

  log INFO "Boot service/script artifacts removed (if present)"
  return 0
}

# ------------------------------------------------------------------------------
# Function: detect_latest_rke2_version
# Purpose : Query GitHub for the most recent RKE2 release tag when the operator
#           does not supply an explicit version. The result populates the global
#           RKE2_VERSION variable.
# Arguments:
#   None
# Returns :
#   Sets RKE2_VERSION on success. Exits with status 2 on failure.
# ------------------------------------------------------------------------------
detect_latest_rke2_version() {
  if [[ -z "${RKE2_VERSION:-}" ]]; then
    log INFO "Detecting latest RKE2 version from GitHub..."
    ensure_installed curl
    local j
    j="$(curl -fsSL https://api.github.com/repos/rancher/rke2/releases/latest || true)"
    RKE2_VERSION="$(echo "$j" | grep -Po '"tag_name":\s*"\K[^"]+' || true)"
    [[ -z "$RKE2_VERSION" ]] && { log ERROR "Failed to detect latest RKE2 version"; exit 2; }
    log INFO "Using RKE2 version: $RKE2_VERSION"
  fi
}

# ------------------------------------------------------------------------------
# Function: disable_cloud_init_net
# Purpose : Prevent cloud-init from generating competing netplan definitions so
#           the script can own network configuration.
# Arguments:
#   None
# Returns :
#   Always returns 0 after writing the disablement file.
# ------------------------------------------------------------------------------
disable_cloud_init_net() {
  mkdir -p /etc/cloud/cloud.cfg.d
  cat >/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg <<'EOF'
# Disable cloud-init network configuration; netplan is managed by rke2nodeinit
network: {config: disabled}
EOF
  log INFO "cloud-init network rendering disabled (/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg)"
}

# ------------------------------------------------------------------------------
# Function: purge_old_netplan
# Purpose : Backup and remove existing netplan YAML files to avoid stale
#           configurations lingering after script execution.
# Arguments:
#   None
# Returns :
#   Always returns 0 after ensuring the directory is clean.
# ------------------------------------------------------------------------------
purge_old_netplan() {
  local bdir
  bdir="/etc/netplan/.backup-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$bdir"
  shopt -s nullglob
  local moved=0
  for f in /etc/netplan/*.yaml /etc/netplan/*.yml; do
    [[ "$(basename "$f")" == "99-rke-static.yaml" ]] && continue
    mv "$f" "$bdir/" && moved=1
  done
  shopt -u nullglob
  if (( moved )); then
    log WARN "Moved existing netplan files to $bdir"
  else
    log INFO "No prior netplan files to move"
  fi
}

# ------------------------------------------------------------------------------
# Function: apply_netplan_now
# Purpose : Generate and apply the current netplan configuration immediately,
#           leveraging spinner feedback for long-running operations.
# Arguments:
#   None
# Returns :
#   Returns 0 on success, 1 when netplan is unavailable.
# ------------------------------------------------------------------------------
apply_netplan_now() {
  if command -v netplan >/dev/null 2>&1; then
    spinner_run "Generating netplan" netplan generate
    spinner_run "Applying netplan" netplan apply
  else
    log ERROR "netplan not found on this system."
    return 1
  fi
  return 0
}

# ------------------------------------------------------------------------------
# Function: write_netplan
# Purpose : Author the authoritative static netplan file using one or more
#           interface definitions and apply it immediately.
# Arguments:
#   Legacy mode retains positional arguments for backward compatibility.
#   Modern mode: write_netplan --interfaces <encoded-entry> [...]
# Returns :
#   Returns 0 on success, exits with status 2 when interface detection fails.
# Strategy:
#   1. Disable cloud-init networking and remove old netplan files
#   2. Create fresh /etc/netplan/99-rke-static.yaml with networkd renderer
#   3. Process each interface entry: decode, validate, and write YAML stanza
#   4. Support both DHCP and static configurations with optional routes/DNS
#   5. Apply netplan immediately and log interface/route state for verification
# ------------------------------------------------------------------------------
write_netplan_multi() {
  local -a _entries=("$@")
  (( ${#_entries[@]} )) || { log ERROR "write_netplan: no interface definitions supplied"; exit 2; }

  # Remove conflicting network config sources
  disable_cloud_init_net
  purge_old_netplan

  local _netplan_tmp="/etc/netplan/99-rke-static.yaml"
  : > "$_netplan_tmp"

  # Write netplan header
  {
    echo "network:"
    echo "  version: 2"
    echo "  renderer: networkd"
    echo "  ethernets:"
  } >> "$_netplan_tmp"

  local _idx=0 _primary_nic="" _summary=""; local -a _ifaces=()
  local _entry
  # Process each interface definition
  for _entry in "${_entries[@]}"; do
    local -A _nic=()
    if ! interface_decode_entry "$_entry" _nic; then
      log ERROR "Failed to decode interface entry #$((_idx+1))"; exit 2
    fi

    local _name="${_nic[name]:-}"
    if [[ -z "$_name" ]]; then
      if (( _idx == 0 )); then
        _name="$(detect_primary_interface)"
        if [[ -z "$_name" ]]; then
          log ERROR "Failed to detect a primary network interface"; exit 2
        fi
        _nic[name]="$_name"
      else
        log ERROR "Interface #$((_idx+1)) is missing a 'name' field"; exit 2
      fi
    fi

    [[ -n "$_primary_nic" ]] || _primary_nic="$_name"
  _ifaces+=("$_name")

    local _dhcp="${_nic[dhcp4]:-}"
    _dhcp="${_dhcp,,}"

    {
      echo "    $_name:"
      if [[ "$_dhcp" == "true" ]]; then
        echo "      dhcp4: true"
        echo "      dhcp6: false"
      else
        echo "      dhcp4: false"
        echo "      dhcp6: false"

        local -a _addresses=()
        if [[ -n "${_nic[cidr]:-}" ]]; then
          local _addr_list
          _addr_list="$(format_inline_list "${_nic[cidr]}")"
          local -a _addr_tmp=()
          IFS=',' read -r -a _addr_tmp <<<"$_addr_list"
          local _a
          for _a in "${_addr_tmp[@]}"; do
            _a="$(trim_whitespace "$_a")"
            [[ -n "$_a" ]] && _addresses+=("$_a")
          done
        fi
        if [[ -n "${_nic[ip]:-}" ]]; then
          local _ip="${_nic[ip]}"
          if [[ "$_ip" == */* ]]; then
            _addresses+=("$_ip")
          else
            local _pref="${_nic[prefix]:-24}"
            [[ -z "$_pref" ]] && _pref=24
            _addresses+=("${_ip}/${_pref}")
          fi
        fi
        if [[ -n "${_nic[addresses]:-}" ]]; then
          local _addr_list
          _addr_list="$(format_inline_list "${_nic[addresses]}")"
          local -a _addr_tmp=()
          IFS=',' read -r -a _addr_tmp <<<"$_addr_list"
          local _a
          for _a in "${_addr_tmp[@]}"; do
            _a="$(trim_whitespace "$_a")"
            [[ -n "$_a" ]] && _addresses+=("$_a")
          done
        fi
        if (( ${#_addresses[@]} == 0 )); then
          log ERROR "Interface '$_name' is missing static addresses"; exit 2
        fi
        echo "      addresses:"
        local _addr
        for _addr in "${_addresses[@]}"; do
          echo "        - $_addr"
        done

        if [[ -n "${_nic[gateway]:-}" ]]; then
          echo "      routes:"
          echo "        - to: default"
          echo "          via: ${_nic[gateway]}"
          if [[ -n "${_nic[metric]:-}" ]]; then
            echo "          metric: ${_nic[metric]}"
          fi
        fi
      fi

      local _dns_block="$(format_inline_list "${_nic[dns]:-}")"
      local _search_block="$(format_inline_list "${_nic[search]:-}")"
      if [[ -n "$_dns_block" || -n "$_search_block" ]]; then
        echo "      nameservers:"
        if [[ -n "$_dns_block" ]]; then
          echo "        addresses: [${_dns_block}]"
        fi
        if [[ -n "$_search_block" ]]; then
          echo "        search: [${_search_block}]"
        fi
      fi

      if [[ -n "${_nic[mtu]:-}" ]]; then
        echo "      mtu: ${_nic[mtu]}"
      fi

      # Disable IPv6 on all interfaces
      echo "      accept-ra: false"
      echo "      link-local: []"
    } >> "$_netplan_tmp"

    local _desc="${_nic[ip]:-}${_nic[cidr]:+ (${_nic[cidr]})}"
    if [[ "$_dhcp" == "true" ]]; then
      _desc="dhcp4"
    elif [[ -z "$_desc" ]]; then
      _desc="${_addresses[*]:-}"
    fi
    [[ -z "$_desc" ]] && _desc="configured"
    if [[ -n "$_summary" ]]; then
      _summary+="; $_name=$_desc"
    else
      _summary="$_name=$_desc"
    fi

    _idx=$((_idx + 1))
  done

  export NETPLAN_LAST_NIC="$_primary_nic"
  chmod 600 "$_netplan_tmp"
  log INFO "Netplan written to $_netplan_tmp (primary=$_primary_nic; interfaces=${_summary})"

  if (( APPLY_NETPLAN_NOW )); then
    log INFO "Applying netplan immediately (--apply-netplan-now flag set)..."
    apply_netplan_now || true
  else
    log INFO "Netplan will be applied on next reboot. Use --apply-netplan-now to apply immediately."
  fi

  local _iface
  for _iface in "${_ifaces[@]}"; do
    [[ -z "$_iface" ]] && continue
    ip -4 addr show dev "$_iface" | sed 's/^/IFACE: /' >>"$LOG_FILE" 2>&1 || true
  done
  ip route show default | sed 's/^/ROUTE: /' >>"$LOG_FILE" 2>&1 || true
}

write_netplan() {
  if [[ "$1" == "--interfaces" ]]; then
    shift
    write_netplan_multi "$@"
    return
  fi

  local ip="$1"; local prefix="$2"; local gw="${3:-}"; local dns_csv="${4:-}"; local search_csv="${5:-}"
  local -A _legacy_nic=()
  [[ -n "$ip" ]] && _legacy_nic[ip]="$ip"
  [[ -n "$prefix" ]] && _legacy_nic[prefix]="$prefix"
  [[ -n "$gw" ]] && _legacy_nic[gateway]="$(trim_whitespace "$gw")"
  if [[ -z "$dns_csv" ]]; then
    dns_csv="8.8.8.8"
  fi
  [[ -n "$dns_csv" ]] && _legacy_nic[dns]="$(normalize_list_csv "$dns_csv")"
  [[ -n "$search_csv" ]] && _legacy_nic[search]="$(normalize_list_csv "$search_csv")"
  write_netplan_multi "$(interface_encode_assoc _legacy_nic)"
}

# ------------------------------------------------------------------------------
# Function: load_site_defaults
# Purpose : Source optional defaults captured during the image action (DNS and
#           search domains) so server/agent actions can reuse them without
#           reprompting the operator.
# Arguments:
#   None
# Returns :
#   Populates DEFAULT_DNS and DEFAULT_SEARCH in-place.
# ------------------------------------------------------------------------------
load_site_defaults() {
  local STATE="/etc/rke2image.defaults"
  if [[ -f "$STATE" ]]; then
    # shellcheck source=/dev/null
    . "$STATE"
    DEFAULT_DNS="${DEFAULT_DNS:-$DEFAULT_DNS}"
    DEFAULT_SEARCH="${DEFAULT_SEARCH:-}"
  else
    DEFAULT_SEARCH="cluster.local"
  fi
}

# ------------------------------------------------------------------------------
# Function: capture_sans
# Purpose : Build a comma-separated Subject Alternative Name list using the
#           hostname, IP address, and optional DNS search domains. This ensures
#           TLS SAN coverage for kube-apiserver endpoints.
# Arguments:
#   $1 - Hostname
#   $2 - IPv4 address
#   $3 - CSV string of search domains
# Returns :
#   Prints the constructed CSV string.
# ------------------------------------------------------------------------------
capture_sans() {
  local hn="$1" ip="$2" search_csv="$3"
  local out="$hn,$ip"
  if [[ -n "$search_csv" ]]; then
    IFS=',' read -r -a _sd <<<"$search_csv"
    for d in "${_sd[@]}"; do
      d="${d// /}"
      [[ -n "$d" ]] && out+=",$hn.$d"
    done
  fi
  printf '%s' "$out"
}

# ------------------------------------------------------------------------------
# TODO: emit_tls_sans() function was removed (unused)
# SANs are captured via capture_sans() but never formatted/emitted.
# Consider re-integrating if TLS SAN YAML formatting is needed.
# Archived in: rke2nodeinit-unused-functions.sh
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Function: check_system_settings
# Purpose : Configure kernel modules and sysctl settings required by Kubernetes
#           networking and container runtimes. Ensures br_netfilter and overlay
#           are present and bridge forwarding sysctls are enabled.
# Arguments:
#   None
# Returns :
#   Always returns 0; failures bubble up via set -e.
# ------------------------------------------------------------------------------
check_system_settings() {
  log INFO "Configuring required kernel modules and sysctl settings..."
  mkdir -p /etc/modules-load.d /etc/sysctl.d
  cat >/etc/modules-load.d/rke2.conf <<EOF
br_netfilter
overlay
EOF
  modprobe br_netfilter || true
  modprobe overlay || true

  cat >/etc/sysctl.d/90-rke2.conf <<EOF
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
  sysctl --system >/dev/null 2>>"$LOG_FILE" || true
}

# ------------------------------------------------------------------------------
# Function: check_swap
# Purpose : Disable swap immediately and ensure it stays disabled across reboots
#           because Kubernetes components require swapless nodes.
# Arguments:
#   None
# Returns :
#   Always returns 0. Logs actions taken for auditability.
# ------------------------------------------------------------------------------
check_swap() {
  # ------------------ Swap off (now and persistent) ------------------
  log INFO "Disabling swap (now and persistent)..."
  if swapon --show | grep -q .; then
    log WARN "Swap is enabled; disabling now."
    swapoff -a || true
  fi
  if grep -qs '^\S\+\s\+\S\+\s\+swap\s' /etc/fstab; then
    log INFO "Commenting swap entries in /etc/fstab for Kubernetes compatibility."
    sed -ri 's/^(\s*[^#\s]+\s+[^#\s]+\s+swap\s+.*)$/# \1/' /etc/fstab
  fi
}

# ------------------------------------------------------------------------------
# Function: check_networkmanager
# Purpose : Configure NetworkManager, when present, to ignore CNI-managed
#           interfaces so it does not interfere with Kubernetes networking.
# Arguments:
#   None
# Returns :
#   Always returns 0.
# ------------------------------------------------------------------------------
check_networkmanager() {
  # ------------------ NetworkManager: ignore CNI if present ------------------
  log INFO "Configuring NetworkManager (if present) to ignore cni*/flannel* interfaces..."
  if systemctl list-unit-files | grep -q '^NetworkManager.service'; then
    mkdir -p /etc/NetworkManager/conf.d
    cat >/etc/NetworkManager/conf.d/rke2-cni-unmanaged.conf <<'NM'
[keyfile]
unmanaged-devices=interface-name:cni*,interface-name:flannel.*,interface-name:flannel.1
NM
    systemctl restart NetworkManager || true
    log INFO "Configured NetworkManager to ignore cni*/flannel* interfaces."
  fi
}

# ------------------------------------------------------------------------------
# Function: check_iptables
# Purpose : Ensure nftables-backed iptables binaries are selected so RKE2's CNI
#           components operate with the expected firewall backend.
# Arguments:
#   None
# Returns :
#   Always returns 0.
# ------------------------------------------------------------------------------
check_iptables() {
  log INFO "Ensuring iptables-nft is the default iptables backend..."
  if update-alternatives --list iptables >/dev/null 2>&1; then
    update-alternatives --set iptables  /usr/sbin/iptables-nft >>"$LOG_FILE" 2>&1 || true
    update-alternatives --set ip6tables /usr/sbin/ip6tables-nft >>"$LOG_FILE" 2>&1 || true
    update-alternatives --set arptables /usr/sbin/arptables-nft >>"$LOG_FILE" 2>&1 || true
    update-alternatives --set ebtables  /usr/sbin/ebtables-nft  >>"$LOG_FILE" 2>&1 || true
  fi
}

# ------------------------------------------------------------------------------
# Function: check_ufw
# Purpose : Open the ports required by RKE2 when Ubuntu's Uncomplicated Firewall
#           is active. Adds allowances for API, supervisor, kubelet, and VXLAN.
# Arguments:
#   None
# Returns :
#   Always returns 0.
# ------------------------------------------------------------------------------
check_ufw() {
  # ------------------ Open ports if UFW is active ------------------
  log INFO "Configuring UFW (if active) to allow RKE2 ports..."
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -q 'Status: active'; then
    ufw allow 6443/tcp || true   # Kubernetes API
    ufw allow 9345/tcp || true   # RKE2 supervisor
    ufw allow 10250/tcp || true  # kubelet
    ufw allow 8472/udp || true   # VXLAN for CNI (flannel)
    log INFO "UFW rules added for 6443/tcp, 9345/tcp, 10250/tcp, 8472/udp."
  fi
}

# ------------------------------------------------------------------------------
# Function: install_rke2_prereqs
# Purpose : Aggregate prerequisite checks for offline installs. Installs base
#           packages, configures networking prerequisites, and enforces swap off.
# Arguments:
#   None
# Returns :
#   Returns 0 on success; exits if any prerequisite step fails.
# ------------------------------------------------------------------------------
install_rke2_prereqs() {
  log INFO "Installing RKE2 prereqs..."
  export DEBIAN_FRONTEND=noninteractive
  log INFO "Updating APT package cache..."
  spinner_run "Updating APT package cache" apt-get update -y
  log INFO "Installing apt-utils..."
  spinner_run "Installing apt-utils" apt-get install -y apt-utils
  log INFO "Upgrading APT packages..."
  spinner_run "Upgrading APT packages" apt-get upgrade -y
  log INFO "Installing required packages..."
  spinner_run "Installing required packages" apt-get install -y \
    curl ca-certificates iptables nftables ethtool socat conntrack iproute2 \
    ebtables openssl tar gzip zstd jq net-tools make skopeo ufw
  log INFO "Removing unnecessary packages..."
  spinner_run "Removing unnecessary packages" apt-get autoremove -y # >>"$LOG_FILE" 2>&1

 # check_system_settings
 # check_swap
 # check_networkmanager
 # check_iptables
  check_ufw

}

# ------------------------------------------------------------------------------
# Function: verify_prereqs
# Purpose : Run prerequisite validation without mutating the system. Confirms
#           kernel modules, swap state, networking, and firewall settings.
# Arguments:
#   None
# Returns :
#   Exits with non-zero status when a prerequisite is missing.
# ------------------------------------------------------------------------------
verify_prereqs() {
  local fail=0
  log INFO "Verifying prerequisites and environment..."

  for m in br_netfilter overlay; do
    if lsmod | grep -q "^${m}"; then
      log INFO "Module present: $m"
    else
      log ERROR "Module missing: $m"; fail=1
    fi
  done

  [[ "$(sysctl -n net.bridge.bridge-nf-call-iptables 2>/dev/null || echo 0)" == "1" ]] || { log ERROR "sysctl bridge-nf-call-iptables != 1"; fail=1; }
  [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == "1"           ]] || { log ERROR "sysctl ip_forward != 1"; fail=1; }

  if [[ -z "$(swapon --summary)" ]]; then
    log INFO "Swap is disabled"
  else
    log ERROR "Swap is enabled"; fail=1
  fi

  if command -v nerdctl &>/dev/null && systemctl is-active --quiet containerd; then
    log INFO "Runtime OK: containerd + nerdctl"
  else
    log ERROR "containerd + nerdctl not ready"; fail=1
  fi

  [[ -f "$SCRIPT_DIR/downloads/$IMAGES_TAR"     ]] && log INFO "Found images archive"     || log WARN "Images archive missing ($SCRIPT_DIR/downloads)"
  [[ -f "$SCRIPT_DIR/downloads/$RKE2_TARBALL"   ]] && log INFO "Found RKE2 tarball"       || log WARN "RKE2 tarball missing ($SCRIPT_DIR/downloads)"
  [[ -f "$STAGE_DIR/install.sh"                 ]] && log INFO "Staged installer present" || log WARN "Staged installer missing ($STAGE_DIR)"
  [[ -f /etc/rancher/rke2/registries.yaml      ]] && log INFO "registries.yaml present"   || log WARN "registries.yaml missing"
  # Verify the CA file referenced in registries.yaml (if any)
  if [[ -f /etc/rancher/rke2/registries.yaml ]]; then
    CA_FILE_PATH="$(awk -F': *' '/ca_file:/ {gsub(/"/,"",$2); print $2}' /etc/rancher/rke2/registries.yaml | head -n1)"
    if [[ -n "$CA_FILE_PATH" && -f "$CA_FILE_PATH" ]]; then
      log INFO "Registry CA present: $CA_FILE_PATH"
    else
      log WARN "Registry CA file missing or not set in registries.yaml"
    fi
  fi

  # --- Custom Cluster CA sub-check ---
  verify_custom_cluster_ca || fail=1

  return $fail
}

# ------------------------------------------------------------------------------
# Function: sanitize_img
# Purpose : Convert an image reference into a filesystem-safe string by replacing
#           slashes and colons. Used when emitting SBOM and inspect outputs.
# Arguments:
#   $1 - Image reference
# Returns :
#   Prints a sanitized string suitable for filenames.
# ------------------------------------------------------------------------------
sanitize_img() { echo "$1" | sed 's#/#_#g; s#:#_#g'; }

# ------------------------------------------------------------------------------
# Function: gen_inspect_json
# Purpose : Capture nerdctl image inspect data for a given image and persist it
#           alongside SBOM data.
# Arguments:
#   $1 - Image reference
# Returns :
#   Writes JSON to the outputs directory; returns 0 on success.
# ------------------------------------------------------------------------------
gen_inspect_json() {
  local img="$1"
  nerdctl -n k8s.io inspect "$img" 2>/dev/null || echo "{}"
}

# ------------------------------------------------------------------------------
# Function: gen_sbom_or_metadata
# Purpose : Produce an SPDX SBOM via syft when available or fall back to nerdctl
#           inspect output. Ensures offline environments retain provenance data.
# Arguments:
#   $1 - Image reference
# Returns :
#   Generates files under the outputs directory for later auditing.
# ------------------------------------------------------------------------------
gen_sbom_or_metadata() {
  local img="$1" base
  base="$(sanitize_img "$img")"
  if command -v syft &>/dev/null; then
    syft "$img" -o spdx-json > "$SBOM_DIR/${base}.spdx.json" 2>>"$LOG_FILE" || true
    log INFO "SBOM written: $SBOM_DIR/${base}.spdx.json"
  else
    gen_inspect_json "$img" > "$SBOM_DIR/${base}.inspect.json"
    log INFO "Inspect metadata written: $SBOM_DIR/${base}.inspect.json"
  fi
}

# ------------------------------------------------------------------------------
# Function: resolve_custom_ca_path
# Purpose : Normalize custom CA file paths to absolute paths relative to the
#           script directory when needed.
# Arguments:
#   $1 - Raw file path
# Returns :
#   Prints the resolved absolute path.
# ------------------------------------------------------------------------------
resolve_custom_ca_path() {
  local input_path="$1"
  [[ -n "$input_path" ]] || return 0

  local resolved="$input_path"

  # Expand a leading ~ if present (~/certs/foo.pem)
  if [[ "$resolved" == ~* ]]; then
    resolved="${resolved/#\~/$HOME}"
  fi

  # Relative paths are anchored to the script directory so configs can reference repo files.
  if [[ "${resolved:0:1}" != "/" ]]; then
    resolved="$SCRIPT_DIR/$resolved"
  elif [[ ! -e "$resolved" ]]; then
    # Handle configs that use "/certs/..." while the repository keeps the
    # bundle at "<repo>/certs/...". If the direct path is missing but the
    # script-relative variant exists, transparently prefer it.
    local candidate="$SCRIPT_DIR$resolved"
    if [[ -e "$candidate" ]]; then
      log INFO "Resolved custom CA path $resolved via script directory: $candidate"
      resolved="$candidate"
    fi
  fi

  printf '%s' "$resolved"
}

# ------------------------------------------------------------------------------
# Function: load_custom_ca_from_config
# Purpose : Pull custom certificate authority locations from the YAML spec and
#           load them into global variables for later trust operations.
# Arguments:
#   $1 - Path to YAML configuration
#   $2 - Optional section override (defaults to spec.customCA/spec.customca)
#   $3 - Optional flag (1) to restrict lookups to spec.<section> keys only
# Returns :
#   Populates CUSTOM_CA_* globals when entries are present.
# ------------------------------------------------------------------------------
load_custom_ca_from_config() {
  local file="$1"
  local section_override="${2:-}"
  local spec_only="${3:-0}"
  [[ -n "$file" ]] || return 0

  CUSTOM_CA_ROOT_CRT=""
  CUSTOM_CA_ROOT_KEY=""
  CUSTOM_CA_INT_CRT=""
  CUSTOM_CA_INT_KEY=""
  CUSTOM_CA_INSTALL_TO_OS_TRUST=1

  local -a sections=()
  if [[ -n "$section_override" ]]; then
    sections=("$section_override")
  else
    sections=("customCA" "customca")
  fi

  local -a root_keys=()
  local -a key_keys=()
  local -a intcrt_keys=()
  local -a intkey_keys=()
  local -a install_keys=()

  local sec
  for sec in "${sections[@]}"; do
    root_keys+=("${sec}.rootCrt" "${sec}.rootcrt" "${sec}.root-crt")
    key_keys+=("${sec}.rootKey" "${sec}.rootkey" "${sec}.root-key")
    intcrt_keys+=("${sec}.intermediateCrt" "${sec}.intermediatecrt" "${sec}.intermediate-crt")
    intkey_keys+=("${sec}.intermediateKey" "${sec}.intermediatekey" "${sec}.intermediate-key")
    install_keys+=("${sec}.installToOSTrust" "${sec}.installtoosstrust" "${sec}.install-to-os-trust")
  done

  # When no override is supplied, also consider the legacy section name so that
  # existing YAMLs continue to function while newer specs can use lowercase keys.
  if (( ! spec_only )) && [[ -z "$section_override" ]]; then
    root_keys+=("customca.rootcrt" "customca.root-crt")
    key_keys+=("customca.rootkey" "customca.root-key")
    intcrt_keys+=("customca.intermediatecrt" "customca.intermediate-crt")
    intkey_keys+=("customca.intermediatekey" "customca.intermediate-key")
    install_keys+=("customca.installtoosstrust" "customca.install-to-os-trust")
  fi

  local root="" key="" intcrt="" intkey="" install=""
  root="$(yaml_spec_get_any "$file" "${root_keys[@]}" || true)"
  key="$(yaml_spec_get_any "$file" "${key_keys[@]}" || true)"
  intcrt="$(yaml_spec_get_any "$file" "${intcrt_keys[@]}" || true)"
  intkey="$(yaml_spec_get_any "$file" "${intkey_keys[@]}" || true)"
  install="$(yaml_spec_get_any "$file" "${install_keys[@]}" || true)"

  if [[ -n "$root" ]]; then
    CUSTOM_CA_ROOT_CRT="$(resolve_custom_ca_path "$root")"
  fi

  if [[ -n "$key" ]]; then
    CUSTOM_CA_ROOT_KEY="$(resolve_custom_ca_path "$key")"
  fi

  if [[ -n "$intcrt" ]]; then
    CUSTOM_CA_INT_CRT="$(resolve_custom_ca_path "$intcrt")"
  fi

  if [[ -n "$intkey" ]]; then
    CUSTOM_CA_INT_KEY="$(resolve_custom_ca_path "$intkey")"
  fi

  if [[ -n "$install" ]]; then
    case "$install" in
      [Tt]rue|1|[Yy]es)
        CUSTOM_CA_INSTALL_TO_OS_TRUST=1
        ;;
      [Ff]alse|0|[Nn]o)
        CUSTOM_CA_INSTALL_TO_OS_TRUST=0
        ;;
      *)
        CUSTOM_CA_INSTALL_TO_OS_TRUST="$install"
        ;;
    esac
  fi
}

# ------------------------------------------------------------------------------
# Function: is_cert_trusted_by_system_store
# Purpose : Determine whether a given certificate already exists in the system
#           trust store to avoid reinstallation.
# Arguments:
#   $1 - Path to certificate file
# Returns :
#   Returns 0 when trusted, 1 otherwise.
# ------------------------------------------------------------------------------
is_cert_trusted_by_system_store() {
  # Best-effort detection that a certificate is trusted by the host's certificate store.
  # Works for both custom cluster roots and generated server-ca certificates that chain to it.
  local cert="$1"
  [[ -n "$cert" && -f "$cert" ]] || return 1

  # Fast-path: let OpenSSL validate against the default CA path.
  if openssl verify -CApath /etc/ssl/certs "$cert" >/dev/null 2>&1; then
    return 0
  fi

  # Try a few common CA bundle files.
  local bundle
  for bundle in /etc/ssl/certs/ca-certificates.crt \
                /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
                /etc/ssl/cert.pem; do
    if [[ -f "$bundle" ]] && openssl verify -CAfile "$bundle" "$cert" >/dev/null 2>&1; then
      return 0
    fi
  done

  # If the certificate was explicitly installed via update-ca-certificates, a byte-for-byte copy
  # should exist in /usr/local/share/ca-certificates/.
  local bn
  bn="$(basename "$cert")"
  if [[ -f "/usr/local/share/ca-certificates/$bn" ]]; then
    if cmp -s "$cert" "/usr/local/share/ca-certificates/$bn" 2>/dev/null; then
      return 0
    fi
  fi

  # Certificates that already live inside /etc/ssl/certs are also considered trusted.
  case "$cert" in
    /etc/ssl/certs/*) return 0;;
  esac

  # Finally, scan the hashed store for an identical file (nullglob avoids literal patterns).
  local candidate
  shopt -s nullglob
  for candidate in /etc/ssl/certs/*.pem /etc/ssl/certs/*.crt; do
    if [[ -f "$candidate" ]] && cmp -s "$cert" "$candidate" 2>/dev/null; then
      shopt -u nullglob
      return 0
    fi
  done
  shopt -u nullglob

  return 1
}

# ------------------------------------------------------------------------------
# Function: find_ca_cert_by_hash
# Purpose : Locate a certificate whose SHA256(der) matches the provided hash.
# Arguments:
#   $1 - Expected SHA256 hash (hex, without colons)
# Returns :
#   Prints the path to the matching cert when found.
# ------------------------------------------------------------------------------
find_ca_cert_by_hash() {
  local target_hash="$1"
  [[ -n "$target_hash" ]] || return 1

  local target_lc="${target_hash,,}"
  local -a search_dirs=(
    "/usr/local/share/ca-certificates"
    "/etc/ssl/certs"
  )

  if [[ -n "${STAGE_DIR:-}" ]]; then
    search_dirs+=("$STAGE_DIR/certs")
  fi
  if [[ -n "${DOWNLOADS_DIR:-}" ]]; then
    search_dirs+=("$DOWNLOADS_DIR/certs")
  fi

  local dir candidate hash
  shopt -s nullglob
  for dir in "${search_dirs[@]}"; do
    [[ -d "$dir" ]] || continue
    for candidate in "$dir"/*.crt "$dir"/*.pem; do
      [[ -f "$candidate" ]] || continue
      hash=$(openssl x509 -outform der -in "$candidate" 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')
      if [[ -n "$hash" && "${hash,,}" == "$target_lc" ]]; then
        shopt -u nullglob
        printf '%s' "$candidate"
        return 0
      fi
    done
  done
  shopt -u nullglob

  return 1
}

# ------------------------------------------------------------------------------
# Function: find_trusted_cluster_ca_certificate
# Purpose : Search known certificate locations for an existing RKE2 cluster CA
#           so join tokens can reuse it.
# Arguments:
#   None
# Returns :
#   Prints the path to the certificate when found.
# ------------------------------------------------------------------------------
find_trusted_cluster_ca_certificate() {
  # Locate a CA certificate suitable for deriving the full cluster token. Preference order:
  #  1) Generated server-ca from an initialized server node
  #  2) Any custom root/intermediate explicitly provided
  #  3) Copies that were installed into the OS trust store
  local candidates=(
    "/var/lib/rancher/rke2/server/tls/server-ca.crt"
    "/etc/rancher/rke2/server/tls/server-ca.crt"
    "${CUSTOM_CA_ROOT_CRT:-}"
    "${CUSTOM_CA_INT_CRT:-}"
  )

  if [[ -n "${CUSTOM_CA_ROOT_CRT:-}" ]]; then
    local bn
    bn="$(basename "${CUSTOM_CA_ROOT_CRT}")"
    candidates+=("/usr/local/share/ca-certificates/$bn" "/etc/ssl/certs/$bn")
  fi

  local candidate
  for candidate in "${candidates[@]}"; do
    [[ -n "$candidate" && -f "$candidate" ]] || continue
    if is_cert_trusted_by_system_store "$candidate"; then
      printf '%s' "$candidate"
      return 0
    fi
  done

  # As a last resort, try to match the fingerprint of the provided root within the trust store.
  if [[ -n "${CUSTOM_CA_ROOT_CRT:-}" && -f "${CUSTOM_CA_ROOT_CRT}" ]]; then
    local root_fp=""
    root_fp="$(openssl x509 -noout -fingerprint -sha256 -in "${CUSTOM_CA_ROOT_CRT}" 2>/dev/null | awk -F= '{print $2}' | tr -d :)"
    if [[ -n "$root_fp" ]]; then
      shopt -s nullglob
      for candidate in /etc/ssl/certs/*; do
        [[ -f "$candidate" ]] || continue
        local cand_fp=""
        cand_fp="$(openssl x509 -noout -fingerprint -sha256 -in "$candidate" 2>/dev/null | awk -F= '{print $2}' | tr -d :)"
        if [[ -n "$cand_fp" && "$cand_fp" == "$root_fp" ]]; then
          shopt -u nullglob
          printf '%s' "$candidate"
          return 0
        fi
      done
      shopt -u nullglob
    fi
  fi

  return 1
}

# ------------------------------------------------------------------------------
# Function: ensure_full_cluster_token
# Purpose : Expand short RKE2 tokens into the full token format that includes the
#           custom CA checksum when required.
# Arguments:
#   $1 - Token string
# Returns :
#   Prints the normalized token.
# ------------------------------------------------------------------------------
ensure_full_cluster_token() {
  # Convert a short join token (e.g. server:xxxxxxxx) into the "full" token format required
  # when custom CAs are in use: K10<cluster-ca-hash>::<credentials-or-password>.
  local raw_token="$1"
  if [[ -z "$raw_token" ]]; then
    printf '%s' "$raw_token"
    return 0
  fi

  # Trim CR/LF without altering other characters.
  local trimmed
  trimmed="$(printf '%s' "$raw_token" | tr -d '\r\n')"

  # Already a full token? Nothing to do.
  if [[ "$trimmed" =~ ^K10[0-9a-fA-F]{64}:: ]]; then
    printf '%s' "$trimmed"
    return 0
  fi

  # Only attempt to expand when a custom CA context is available.
  if [[ -z "${CUSTOM_CA_ROOT_CRT:-}" && -z "${CUSTOM_CA_INT_CRT:-}" ]]; then
    printf '%s' "$trimmed"
    return 0
  fi

  local ca_cert=""
  if ! ca_cert="$(find_trusted_cluster_ca_certificate)"; then
    log WARN "customCA configured but no trusted CA certificate could be located; leaving token unchanged." >&2
    printf '%s' "$trimmed"
    return 0
  fi

  if ! is_cert_trusted_by_system_store "$ca_cert"; then
    log WARN "customCA configured but $ca_cert is not trusted by the system store; leaving token unchanged." >&2
    printf '%s' "$trimmed"
    return 0
  fi

  local ca_hash=""
  ca_hash="$(openssl x509 -outform der -in "$ca_cert" 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')"
  if [[ -z "$ca_hash" ]]; then
    log WARN "Failed to compute custom CA hash from $ca_cert; leaving token unchanged." >&2
    printf '%s' "$trimmed"
    return 0
  fi

  AGENT_CA_CERT="$ca_cert"
  log INFO "Derived full cluster token using CA hash $ca_hash from $ca_cert." >&2
  printf 'K10%s::%s' "$ca_hash" "$trimmed"
}

# ------------------------------------------------------------------------------
# Function: generate_bootstrap_token
# Purpose : Produce an appropriate bootstrap token for the very first RKE2
#           server. When a custom CA is available (from action_image), emit a
#           secure token that embeds the CA hash. Otherwise, fall back to the
#           short random passphrase required when no CA exists yet.
# Arguments:
#   None (uses CUSTOM_CA_* context populated earlier)
# Returns :
#   Prints the generated token.
# ------------------------------------------------------------------------------
generate_bootstrap_token() {
  local ca_cert="" ca_hash="" passphrase=""
  declare -g token=""

  # Generate the base passphrase shared by both token formats.
  passphrase="$(openssl rand -hex 20 2>/dev/null || true)"
  passphrase="${passphrase//$'\n'/}"
  passphrase="${passphrase//$'\r'/}"
  if [[ -z "$passphrase" ]]; then
    # Fallback: derive a hex string via /dev/urandom without triggering pipefail
    passphrase="$(dd if=/dev/urandom bs=1 count=64 2>/dev/null | od -An -v -t x1 | tr -d ' \n' | cut -c1-40 || true)"
    passphrase="${passphrase//$'\n'/}"
    passphrase="${passphrase//$'\r'/}"
  fi

  if [[ -z "$passphrase" ]]; then
    log ERROR "Failed to generate secure bootstrap passphrase via available entropy sources." >&2
    return 1
  fi

  # No custom CA context? Return the short token (Option A).
  if [[ -z "${CUSTOM_CA_ROOT_CRT:-}" && -z "${CUSTOM_CA_INT_CRT:-}" ]]; then
    printf '%s' "$passphrase"
    return 0
  fi

  # Prefer the explicit root CA, otherwise fall back to an intermediate.
  if [[ -n "${CUSTOM_CA_ROOT_CRT:-}" && -f "${CUSTOM_CA_ROOT_CRT}" ]]; then
    ca_cert="${CUSTOM_CA_ROOT_CRT}"
  elif [[ -n "${CUSTOM_CA_INT_CRT:-}" && -f "${CUSTOM_CA_INT_CRT}" ]]; then
    ca_cert="${CUSTOM_CA_INT_CRT}"
  fi

  # If we cannot locate a CA file, revert to the short token.
  if [[ -z "$ca_cert" ]]; then
    log WARN "Custom CA context detected but certificate file missing; using short bootstrap token." >&2
    printf '%s' "$passphrase"
    return 0
  fi

  ca_hash="$(openssl x509 -outform der -in "$ca_cert" 2>/dev/null | sha256sum 2>/dev/null | awk '{print $1}')"
  if [[ -z "$ca_hash" ]]; then
    log WARN "Failed to derive custom CA hash from $ca_cert; using short bootstrap token." >&2
    printf '%s' "$passphrase"
    return 0
  fi

  token=$(printf 'K10%s::server:%s' "$ca_hash" "$passphrase")
  if [[ -z "$token" ]]; then
    log ERROR "Failed to construct full bootstrap token despite having CA context." >&2
    return 1
  else
  #  printf '%s' "$token"
    log INFO "Generated secure server token" >&2
    log INFO "CustomCA:" >&2
    log INFO "  Fingerprint: $ca_hash" >&2
    log INFO "  Certificate: $ca_cert" >&2
    return 0
  fi
}

# ------------------------------------------------------------------------------
# Function: cleanup_containerd_before_rke2
# Purpose : Optionally stop and clear containerd state before RKE2 installation
#           to prevent conflicts with stale or wrong-version images. This is
#           particularly useful when reinstalling or when containerd was previously
#           used for non-RKE2 workloads.
# Arguments:
#   $1 - Installation type label (e.g., "server", "agent", "add-server") for logging
# Returns :
#   Always returns 0 after prompting and optionally cleaning containerd.
# ------------------------------------------------------------------------------
cleanup_containerd_before_rke2() {
  local install_type="${1:-RKE2}"
  
  if ! command -v containerd >/dev/null 2>&1; then
    return 0  # containerd not installed, nothing to clean
  fi
  
  if ! systemctl is-active --quiet containerd 2>/dev/null; then
    return 0  # containerd not running, nothing to clean
  fi
  
  log WARN "containerd is already running before $install_type installation"
  log WARN "Pre-existing containerd state may contain stale or conflicting images"
  
  local clean_containerd=0
  if [[ "${AUTO_YES:-0}" -eq 1 ]]; then
    log INFO "Auto-confirm enabled; will stop containerd and clear its image store"
    clean_containerd=1
  else
    echo
    read -rp "Stop containerd and clear its image store before RKE2 install? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      clean_containerd=1
    fi
  fi
  
  if (( clean_containerd == 1 )); then
    log INFO "Stopping containerd service..."
    systemctl stop containerd >>"$LOG_FILE" 2>&1 || true
    
    # Clear containerd content and metadata stores
    if [[ -d /var/lib/containerd ]]; then
      log INFO "Clearing containerd content store..."
      rm -rf /var/lib/containerd/io.containerd.content.v1.content/* 2>/dev/null || true
      log INFO "Clearing containerd metadata database..."
      rm -rf /var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db 2>/dev/null || true
      log INFO "Containerd state cleared; RKE2 will start with fresh image store"
    fi
  else
    log INFO "Skipping containerd cleanup; RKE2 will use existing containerd state"
  fi
  
  return 0
}

# ------------------------------------------------------------------------------
# Function: parse_oci_image_index
# Purpose : Parse OCI image index format from tarball and extract image list.
#           This provides fallback support when Docker manifest.json is not present.
# Arguments:
#   $1 - Path to the images tarball
# Returns :
#   Prints JSON array of image references, or empty string on failure.
# ------------------------------------------------------------------------------
parse_oci_image_index() {
  local tarball="$1"
  
  if [[ ! -f "$tarball" ]]; then
    log WARN "parse_oci_image_index: tarball not found: $tarball"
    return 1
  fi
  
  # Detect compression format
  local decompress_cmd=""
  if [[ "$tarball" == *.zst ]]; then
    if ! command -v zstd >/dev/null 2>&1; then
      log WARN "parse_oci_image_index: zstd not available for decompression"
      return 1
    fi
    decompress_cmd="zstd -dc"
  elif [[ "$tarball" == *.gz ]]; then
    if ! command -v gzip >/dev/null 2>&1; then
      log WARN "parse_oci_image_index: gzip not available for decompression"
      return 1
    fi
    decompress_cmd="gzip -dc"
  else
    decompress_cmd="cat"
  fi
  
  # Try to extract index.json (OCI layout)
  local index_json
  index_json=$($decompress_cmd "$tarball" 2>/dev/null | tar -xO index.json 2>/dev/null || echo "")
  
  if [[ -z "$index_json" ]]; then
    log INFO "parse_oci_image_index: No index.json found (not OCI layout format)"
    return 1
  fi
  
  # Validate it's valid JSON with manifests array
  if ! echo "$index_json" | python3 -m json.tool >/dev/null 2>&1; then
    log WARN "parse_oci_image_index: index.json is not valid JSON"
    return 1
  fi
  
  # Extract image references from annotations
  # OCI index typically has manifests[].annotations["org.opencontainers.image.ref.name"]
  local image_refs
  image_refs=$(echo "$index_json" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    refs = []
    if "manifests" in data:
        for manifest in data["manifests"]:
            if "annotations" in manifest:
                ref_name = manifest["annotations"].get("org.opencontainers.image.ref.name", "")
                if ref_name:
                    refs.append(ref_name)
            # Also check for platform-specific info
            if "platform" in manifest:
                arch = manifest["platform"].get("architecture", "")
                if arch:
                    # Note the architecture for filtering
                    pass
    print(json.dumps(refs))
except Exception as e:
    print("[]", file=sys.stderr)
    sys.exit(1)
' 2>/dev/null || echo "[]")
  
  if [[ "$image_refs" == "[]" ]]; then
    log INFO "parse_oci_image_index: No image references found in index.json"
    return 1
  fi
  
  echo "$image_refs"
  return 0
}

# ------------------------------------------------------------------------------
# Function: collect_requested_cni_plugins
# Purpose : Resolve requested CNI plugins from YAML spec.cni as normalized
#           lowercase values (supports list and scalar forms).
# Arguments:
#   $1 - Path to YAML config file
# Returns :
#   Prints one CNI name per line (unique). Returns 0 even when none are found.
# ------------------------------------------------------------------------------
collect_requested_cni_plugins() {
  local file="$1"
  local -a raw=()

  [[ -n "$file" && -f "$file" ]] || return 0

  while IFS= read -r item; do
    [[ -n "$item" ]] && raw+=("$item")
  done < <(yaml_spec_list_items "$file" "cni" 2>/dev/null || true)

  if [[ ${#raw[@]} -eq 0 ]]; then
    local scalar
    scalar="$(yaml_spec_get "$file" cni 2>/dev/null || true)"
    [[ -n "$scalar" ]] && raw+=("$scalar")
  fi

  local item norm token
  local -A seen=()
  for item in "${raw[@]}"; do
    norm="$(echo "$item" | tr '[:upper:]' '[:lower:]' | tr -d '[]"' | tr -d '\r\n' | sed 's/[[:space:]]//g')"
    [[ -z "$norm" ]] && continue
    IFS=',' read -r -a _tokens <<< "$norm"
    for token in "${_tokens[@]}"; do
      [[ -z "$token" ]] && continue
      if [[ -z "${seen[$token]:-}" ]]; then
        seen[$token]=1
        printf '%s\n' "$token"
      fi
    done
  done
}

# ------------------------------------------------------------------------------
# Function: archive_contains_image_pattern
# Purpose : Determine whether an image reference pattern exists in a staged
#           images archive (Docker manifest, OCI index, or raw fallback scan).
# Arguments:
#   $1 - Archive path
#   $2 - Pattern to search for (e.g., rancher/hardened-multus-cni:)
# Returns : 0 if pattern found, 1 otherwise
# ------------------------------------------------------------------------------
archive_contains_image_pattern() {
  local archive="$1"
  local pattern="$2"
  local manifest=""
  local oci_refs=""

  [[ -f "$archive" ]] || return 1

  if [[ "$archive" == *.zst ]]; then
    command -v zstd >/dev/null 2>&1 || return 1
    manifest="$(zstd -dc "$archive" 2>/dev/null | tar -xO manifest.json 2>/dev/null || true)"
  elif [[ "$archive" == *.gz || "$archive" == *.tgz ]]; then
    command -v gzip >/dev/null 2>&1 || return 1
    manifest="$(gzip -dc "$archive" 2>/dev/null | tar -xO manifest.json 2>/dev/null || true)"
  else
    manifest="$(tar -xOf "$archive" manifest.json 2>/dev/null || true)"
  fi

  if [[ -n "$manifest" ]] && echo "$manifest" | grep -q "$pattern"; then
    return 0
  fi

  oci_refs="$(parse_oci_image_index "$archive" 2>/dev/null || true)"
  if [[ -n "$oci_refs" && "$oci_refs" != "[]" ]] && echo "$oci_refs" | grep -q "$pattern"; then
    return 0
  fi

  if [[ "$archive" == *.zst ]]; then
    zstd -dc "$archive" 2>/dev/null | grep -a -q "$pattern" && return 0 || true
  elif [[ "$archive" == *.gz || "$archive" == *.tgz ]]; then
    gzip -dc "$archive" 2>/dev/null | grep -a -q "$pattern" && return 0 || true
  else
    grep -a -q "$pattern" "$archive" && return 0 || true
  fi

  return 1
}

# ------------------------------------------------------------------------------
# Function: verify_required_cni_images_staged
# Purpose : Ensure the staged image archives contain required images for the
#           configured spec.cni plugins so offline nodes do not pull remotely.
# Arguments:
#   $1 - Optional YAML config path (defaults to CONFIG_FILE)
# Returns : 0 on success, non-zero when required CNI images are missing
# ------------------------------------------------------------------------------
verify_required_cni_images_staged() {
  local cfg="${1:-$CONFIG_FILE}"
  local images_dir="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"
  local -a cni_plugins=()
  local -a bundles=()
  local -A required=()
  local -A labels=()
  local -A allow_separate=()

  if [[ -z "$cfg" || ! -f "$cfg" ]]; then
    log_info "CNI image preflight skipped (no YAML config file provided)."
    return 0
  fi

  while IFS= read -r cni; do
    [[ -n "$cni" ]] && cni_plugins+=("$cni")
  done < <(collect_requested_cni_plugins "$cfg")

  if [[ ${#cni_plugins[@]} -eq 0 ]]; then
    log_info "CNI image preflight skipped (spec.cni not set in $cfg)."
    return 0
  fi

  while IFS= read -r archive; do
    [[ -n "$archive" ]] && bundles+=("$archive")
  done < <(find "$images_dir" -maxdepth 1 -type f -name "rke2-images*.tar*" | sort)

  if [[ ${#bundles[@]} -eq 0 ]]; then
    log_error "CNI image preflight failed: no staged rke2-images archives found in $images_dir"
    return 1
  fi

  local cni
  for cni in "${cni_plugins[@]}"; do
    case "$cni" in
      multus)
        required["rancher/hardened-multus-cni:"]=1
        labels["rancher/hardened-multus-cni:"]="Multus daemon image"
        allow_separate["rancher/hardened-multus-cni:"]=1
        required["rancher/hardened-cni-plugins:"]=1
        labels["rancher/hardened-cni-plugins:"]="Multus hardened-cni plugins image"
        allow_separate["rancher/hardened-cni-plugins:"]=1
        ;;
      canal)
        required["rancher/hardened-calico:"]=1
        labels["rancher/hardened-calico:"]="Canal Calico image"
        required["rancher/hardened-flannel:"]=1
        labels["rancher/hardened-flannel:"]="Canal Flannel image"
        ;;
      cilium)
        required["rancher/hardened-cilium:"]=1
        labels["rancher/hardened-cilium:"]="Cilium image"
        ;;
      *)
        log_info "CNI image preflight: no explicit image rules for cni='$cni' (skipping strict checks for this plugin)."
        ;;
    esac
  done

  if [[ ${#required[@]} -eq 0 ]]; then
    log_info "CNI image preflight: no strict image requirements derived from spec.cni (${cni_plugins[*]})."
    return 0
  fi

  log_info "Running CNI image preflight against staged archives in $images_dir"
  local pattern archive found fail_count=0
  for pattern in "${!required[@]}"; do
    found=0
    for archive in "${bundles[@]}"; do
      if archive_contains_image_pattern "$archive" "$pattern"; then
        log_info "  ✓ ${labels[$pattern]} found in $(basename "$archive")"
        found=1
        break
      fi
    done

    if [[ $found -eq 0 && -n "${allow_separate[$pattern]:-}" ]]; then
      local separate_bn=""
      case "$pattern" in
        rancher/hardened-cni-plugins:)
          separate_bn="$HARDENED_CNI_BN"
          ;;
        rancher/hardened-multus-cni:)
          separate_bn="$HARDENED_MULTUS_BN"
          ;;
      esac
      if [[ -n "$separate_bn" ]] && [[ -f "$images_dir/$separate_bn" || -f "$STAGE_DIR/$separate_bn" || -f "$DOWNLOADS_DIR/$separate_bn" ]]; then
        log_info "  ✓ ${labels[$pattern]} satisfied via separate archive $separate_bn"
        found=1
      fi
    fi

    if [[ $found -eq 0 ]]; then
      log_error "  ✗ Missing required CNI image reference pattern: $pattern (${labels[$pattern]:-required})"
      ((fail_count++))
    fi
  done

  if (( fail_count > 0 )); then
    log_error "CNI image preflight failed ($fail_count missing requirement(s))."
    log_error "Remediation: provide full CNI-specific image bundles (for example rke2-images-*.linux-${ARCH}.tar.*) via INSTALL_RKE2_ARTIFACT_PATH or stage them into $images_dir."
    return 1
  fi

  log_info "CNI image preflight passed for spec.cni: ${cni_plugins[*]}"
  return 0
}

# ------------------------------------------------------------------------------
# Function: collect_required_image_refs_for_validation
# Purpose : Build a normalized required image:tag list for offline validation.
#           Prefers previously generated chart image lists, then derives from
#           staged RKE2 artifacts without requiring network access.
# Arguments:
#   $1 - Output file path
# Returns : 0 when required refs were collected, non-zero otherwise
# ------------------------------------------------------------------------------
collect_required_image_refs_for_validation() {
  local out_file="$1"
  local required_bn="chart-images-required.linux-${ARCH}.txt"
  local release_list_bn="rke2-images.linux-${ARCH}.txt"
  local release_list_all_bn="rke2-images-all.linux-${ARCH}.txt"
  local tmp

  : > "$out_file"

  for src in "$DOWNLOADS_DIR/$required_bn" "$STAGE_DIR/$required_bn"; do
    [[ -s "$src" ]] || continue
    tmp=$(mktemp) || return 2
    while IFS= read -r ref; do
      [[ -z "$ref" ]] && continue
      [[ "$ref" =~ ^[[:space:]]*# ]] && continue
      ref="$(normalize_image_reference "$ref")"
      [[ -n "$ref" && "$ref" == *:* ]] || continue
      printf '%s\n' "$ref" >> "$tmp"
    done < "$src"
    if [[ -s "$tmp" ]]; then
      sort -u "$tmp" > "$out_file"
      rm -f "$tmp" || true
      log_info "Using required image reference source: $src"
      return 0
    fi
    rm -f "$tmp" || true
  done

  local rke2_tar_candidate=""
  for p in "$STAGE_DIR/$RKE2_TARBALL" "$DOWNLOADS_DIR/$RKE2_TARBALL"; do
    if [[ -f "$p" ]]; then
      rke2_tar_candidate="$p"
      break
    fi
  done
  if [[ -n "$rke2_tar_candidate" ]]; then
    if extract_chart_images_from_rke2_tarball "$rke2_tar_candidate" "$out_file" && [[ -s "$out_file" ]]; then
      log_info "Derived required image references from RKE2 tarball: $rke2_tar_candidate"
      return 0
    fi
  fi

  tmp=$(mktemp) || return 2
  : > "$tmp"
  for src in \
    "$DOWNLOADS_DIR/$release_list_bn" \
    "$DOWNLOADS_DIR/$release_list_all_bn" \
    "$STAGE_DIR/$release_list_bn" \
    "$STAGE_DIR/$release_list_all_bn"
  do
    [[ -f "$src" ]] || continue
    while IFS= read -r ref; do
      [[ -z "$ref" ]] && continue
      [[ "$ref" =~ ^[[:space:]]*# ]] && continue
      ref="$(normalize_image_reference "$ref")"
      [[ -n "$ref" && "$ref" == *:* ]] || continue
      printf '%s\n' "$ref" >> "$tmp"
    done < "$src"
  done

  if [[ -s "$tmp" ]]; then
    sort -u "$tmp" > "$out_file"
    rm -f "$tmp" || true
    log_info "Using required image references from local release image list files"
    return 0
  fi

  rm -f "$tmp" || true
  return 1
}

# ------------------------------------------------------------------------------
# Function: collect_staged_image_refs_for_validation
# Purpose : Inventory normalized image references present in staged archives.
# Arguments:
#   $1 - Output file path
# Returns : 0 when refs were discovered, non-zero otherwise
# ------------------------------------------------------------------------------
collect_staged_image_refs_for_validation() {
  local out_file="$1"
  local images_dir="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"
  local tmp_all tmp_refs archive

  : > "$out_file"
  tmp_all=$(mktemp) || return 2
  : > "$tmp_all"

  while IFS= read -r archive; do
    [[ -n "$archive" ]] || continue
    tmp_refs=$(mktemp) || { rm -f "$tmp_all" || true; return 2; }
    if list_images_in_archive "$archive" "$tmp_refs"; then
      cat "$tmp_refs" >> "$tmp_all"
    fi
    rm -f "$tmp_refs" || true
  done < <(find "$images_dir" "$STAGE_DIR" -maxdepth 1 -type f \( -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.tar.zst' -o -name '*.tzst' -o -name '*.zst' \) | sort -u)

  if [[ -s "$tmp_all" ]]; then
    sort -u "$tmp_all" > "$out_file"
    rm -f "$tmp_all" || true
    return 0
  fi

  rm -f "$tmp_all" || true
  return 1
}

# ------------------------------------------------------------------------------
# Function: verify_required_image_tags_staged
# Purpose : Strictly verify all required image:tag references are present in
#           staged on-node archives before offline server/agent startup.
# Returns : 0 on success, non-zero when requirements cannot be proven.
# ------------------------------------------------------------------------------
verify_required_image_tags_staged() {
  local required_tmp present_tmp missing_tmp
  required_tmp=$(mktemp) || return 2
  present_tmp=$(mktemp) || { rm -f "$required_tmp" || true; return 2; }
  missing_tmp=$(mktemp) || { rm -f "$required_tmp" "$present_tmp" || true; return 2; }

  if ! collect_required_image_refs_for_validation "$required_tmp"; then
    log_error "Required image/tag validation failed: unable to determine required image reference list from staged artifacts."
    log_error "Remediation: run 'image' action and ensure RKE2 artifact lists are staged for this architecture (${ARCH})."
    rm -f "$required_tmp" "$present_tmp" "$missing_tmp" || true
    return 1
  fi

  if ! collect_staged_image_refs_for_validation "$present_tmp"; then
    log_error "Required image/tag validation failed: unable to inventory staged image archives in $STAGE_DIR and ${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}."
    rm -f "$required_tmp" "$present_tmp" "$missing_tmp" || true
    return 1
  fi

  comm -23 "$required_tmp" "$present_tmp" > "$missing_tmp" || true
  local missing_count
  missing_count=$(wc -l < "$missing_tmp" | awk '{print $1}')

  if (( missing_count > 0 )); then
    log_error "Required image/tag validation failed: $missing_count required reference(s) missing from staged archives."
    while IFS= read -r miss; do
      [[ -n "$miss" ]] || continue
      log_error "  ✗ Missing required image tag: $miss"
    done < <(head -n 25 "$missing_tmp")
    if (( missing_count > 25 )); then
      log_error "  ... plus $((missing_count - 25)) additional missing references"
    fi
    log_error "Remediation: re-run 'image' and ensure all chart-required images are staged into ${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}."
    rm -f "$required_tmp" "$present_tmp" "$missing_tmp" || true
    return 1
  fi

  local required_count
  required_count=$(wc -l < "$required_tmp" | awk '{print $1}')
  log_info "Required image/tag validation passed: $required_count required reference(s) available in staged archives."

  rm -f "$required_tmp" "$present_tmp" "$missing_tmp" || true
  return 0
}

# ------------------------------------------------------------------------------
# Function: verify_image_layer_checksums
# Purpose : Verify individual image layer checksums from tarball manifest against
#           computed SHA256 digests. Provides deep integrity validation beyond
#           simple tarball compression testing.
# Arguments:
#   $1 - Path to the images tarball
#   $2 - Temporary directory for extraction (optional, defaults to /tmp)
# Returns :
#   0 if all layers verify successfully, 1 on any failure
# ------------------------------------------------------------------------------
verify_image_layer_checksums() {
  local tarball="$1"
  local tmp_dir="${2:-/tmp}"
  local work_dir="$tmp_dir/verify-layers-$$"
  
  if [[ ! -f "$tarball" ]]; then
    log ERROR "verify_image_layer_checksums: tarball not found: $tarball"
    return 1
  fi
  
  # Detect compression format
  local decompress_cmd=""
  if [[ "$tarball" == *.zst ]]; then
    if ! command -v zstd >/dev/null 2>&1; then
      log WARN "verify_image_layer_checksums: zstd not available"
      return 1
    fi
    decompress_cmd="zstd -dc"
  elif [[ "$tarball" == *.gz ]]; then
    if ! command -v gzip >/dev/null 2>&1; then
      log WARN "verify_image_layer_checksums: gzip not available"
      return 1
    fi
    decompress_cmd="gzip -dc"
  else
    decompress_cmd="cat"
  fi
  
  # Create temporary work directory
  mkdir -p "$work_dir" || {
    log ERROR "verify_image_layer_checksums: failed to create work directory"
    return 1
  }
  
  # Extract manifest.json
  local manifest
  manifest=$($decompress_cmd "$tarball" 2>/dev/null | tar -xO manifest.json 2>/dev/null || echo "")
  
  if [[ -z "$manifest" ]]; then
    log WARN "verify_image_layer_checksums: No Docker manifest.json found, trying OCI format"
    
    # Try OCI layout with index.json
    local index_json
    index_json=$($decompress_cmd "$tarball" 2>/dev/null | tar -xO index.json 2>/dev/null || echo "")
    
    if [[ -z "$index_json" ]]; then
      log WARN "verify_image_layer_checksums: No index.json found either, cannot verify"
      rm -rf "$work_dir"
      return 1
    fi
    
    # For OCI format, we need to extract blobs and verify against manifest descriptors
    log INFO "Verifying OCI image layers..."
    
    # Extract all manifest digests from index
    local manifest_digests
    manifest_digests=$(echo "$index_json" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    if "manifests" in data:
        for m in data["manifests"]:
            if "digest" in m:
                print(m["digest"])
except:
    pass
' 2>/dev/null || true)
    
    if [[ -z "$manifest_digests" ]]; then
      log WARN "verify_image_layer_checksums: No manifest digests in OCI index"
      rm -rf "$work_dir"
      return 1
    fi
    
    # For each manifest, extract and verify its blob
    local verified_count=0
    local failed_count=0
    
    while IFS= read -r digest; do
      [[ -z "$digest" ]] && continue
      
      # OCI digest format: sha256:abc123...
      local algo="${digest%%:*}"
      local hash="${digest#*:}"
      
      if [[ "$algo" != "sha256" ]]; then
        log WARN "Unsupported digest algorithm: $algo (skipping)"
        continue
      fi
      
      # Extract blob from tarball (OCI layout stores as blobs/sha256/<hash>)
      local blob_path="blobs/sha256/$hash"
      local blob_data
      blob_data=$($decompress_cmd "$tarball" 2>/dev/null | tar -xO "$blob_path" 2>/dev/null || echo "")
      
      if [[ -z "$blob_data" ]]; then
        log WARN "Blob not found in tarball: $blob_path"
        ((failed_count++))
        continue
      fi
      
      # Compute SHA256 of extracted blob
      local computed_hash
      computed_hash=$(echo -n "$blob_data" | sha256sum | awk '{print $1}')
      
      if [[ "$computed_hash" == "$hash" ]]; then
        ((verified_count++))
      else
        log ERROR "Layer checksum mismatch for $blob_path"
        log ERROR "  Expected: $hash"
        log ERROR "  Computed: $computed_hash"
        ((failed_count++))
      fi
    done <<< "$manifest_digests"
    
    rm -rf "$work_dir"
    
    if (( failed_count > 0 )); then
      log ERROR "Layer verification FAILED: $failed_count layer(s) corrupted"
      return 1
    fi
    
    log INFO "Layer verification PASSED: $verified_count layer(s) verified"
    return 0
  fi
  
  # Docker manifest.json format - verify layers
  log INFO "Verifying Docker image layers..."
  
  # Parse manifest to get layer paths and extract them
  local layer_paths
  layer_paths=$(echo "$manifest" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    for image in data:
        if "Layers" in image:
            for layer in image["Layers"]:
                print(layer)
except:
    pass
' 2>/dev/null || true)
  
  if [[ -z "$layer_paths" ]]; then
    log WARN "verify_image_layer_checksums: No layers found in manifest"
    rm -rf "$work_dir"
    return 1
  fi
  
  local verified_count=0
  local failed_count=0
  local total_layers=0
  
  # Count total layers
  total_layers=$(echo "$layer_paths" | wc -l)
  log INFO "Found $total_layers layer(s) to verify"
  
  # Extract layers and verify
  while IFS= read -r layer_path; do
    [[ -z "$layer_path" ]] && continue
    
    # Extract layer from tarball
    local layer_file="$work_dir/$(basename "$layer_path")"
    if ! $decompress_cmd "$tarball" 2>/dev/null | tar -xO "$layer_path" > "$layer_file" 2>/dev/null; then
      log WARN "Failed to extract layer: $layer_path"
      ((failed_count++))
      continue
    fi
    
    # For Docker format, layers are typically named with their digest
    # Format: <hash>/layer.tar
    local layer_dir
    layer_dir=$(dirname "$layer_path")
    
    if [[ "$layer_dir" =~ ^[a-f0-9]{64}$ ]]; then
      # The directory name is the expected SHA256 hash
      local expected_hash="$layer_dir"
      local computed_hash
      computed_hash=$(sha256sum "$layer_file" | awk '{print $1}')
      
      if [[ "$computed_hash" == "$expected_hash" ]]; then
        ((verified_count++))
      else
        log ERROR "Layer checksum mismatch: $layer_path"
        log ERROR "  Expected: $expected_hash"
        log ERROR "  Computed: $computed_hash"
        ((failed_count++))
      fi
    else
      # Cannot determine expected hash from path, just verify extraction worked
      ((verified_count++))
    fi
    
    rm -f "$layer_file"
  done <<< "$layer_paths"
  
  rm -rf "$work_dir"
  
  if (( failed_count > 0 )); then
    log ERROR "Layer verification FAILED: $failed_count layer(s) corrupted out of $total_layers"
    return 1
  fi
  
  log INFO "Layer verification PASSED: $verified_count layer(s) verified out of $total_layers"
  return 0
}

# ------------------------------------------------------------------------------
# Function: run_rke2_installer
# Purpose : Execute the cached RKE2 installer script with environment variables
#           pointing to staged artifacts for offline installation.
# Arguments:
#   $1 - Stage directory containing artifacts
#   $2 - Install type (server or agent)
# Returns :
#   Exits with installer status.
# ------------------------------------------------------------------------------
run_rke2_installer() {
  local src="$1"
  local itype="${2:-}"
  set +e
  if [[ -n "$itype" ]]; then
    log INFO "RKE2 installing INSTALL_RKE2_TYPE..."
    INSTALL_RKE2_TYPE="$itype" INSTALL_RKE2_ARTIFACT_PATH="$src" "$src/install.sh" >>"$LOG_FILE" 2>&1
  else
    log INFO "RKE2 installing INSTALL_RKE2_ARTIFACT_PATH..."
    INSTALL_RKE2_ARTIFACT_PATH="$src" "$src/install.sh" >>"$LOG_FILE" 2>&1
  fi
  local rc=$?
  set -e
  if (( rc != 0 )); then
    log ERROR "RKE2 installer failed (exit $rc). See $LOG_FILE"
    return "$rc"
  fi
  return 0
}

# ------------------------------------------------------------------------------
# Function: setup_custom_cluster_ca
# Purpose : Install custom cluster CAs into the RKE2 configuration and optionally
#           system trust so API clients trust the private registry.
# Arguments:
#   None (uses globals populated from YAML)
# Returns :
#   Returns 0 on success.
# ------------------------------------------------------------------------------
setup_custom_cluster_ca() {
  local ROOT_CRT="${CUSTOM_CA_ROOT_CRT:-}"
  local ROOT_KEY="${CUSTOM_CA_ROOT_KEY:-}"
  local INT_CRT="${CUSTOM_CA_INT_CRT:-}"
  local INT_KEY="${CUSTOM_CA_INT_KEY:-}"
  local TLS_DIR="/var/lib/rancher/rke2/server/tls"
  local GEN1="$STAGE_DIR/generate-custom-ca-certs.sh"
  local GEN2="$DOWNLOADS_DIR/generate-custom-ca-certs.sh"
  local token_file="${BOOTSTRAP_TOKEN_FILE:-}"
  local root_ca_reason=""

  # Optionally ensure OS trust (clients/servers on the host trust the root CA)
  local _bn=""
  if [[ -f "$ROOT_CRT" ]]; then
    if [[ "${CUSTOM_CA_INSTALL_TO_OS_TRUST:-1}" -ne 0 ]]; then
      mkdir -p /usr/local/share/ca-certificates
      _bn="$(basename "$ROOT_CRT")"
      if ! cmp -s "$ROOT_CRT" "/usr/local/share/ca-certificates/$_bn" 2>/dev/null; then
        cp "$ROOT_CRT" "/usr/local/share/ca-certificates/$_bn"
        update-ca-certificates >>"$LOG_FILE" 2>&1 || true
        log INFO "Installed $_bn into OS trust store."
      fi
    fi
  else
    if [[ -n "$token_file" && -f "$token_file" ]]; then
      local token_line token_hash matched_cert
      token_line="$(head -n 1 "$token_file" | tr -d '\r\n')"
      if [[ "$token_line" =~ ^K10([0-9a-fA-F]{64}):: ]]; then
        token_hash="${BASH_REMATCH[1]}"
        matched_cert="$(find_ca_cert_by_hash "$token_hash" || true)"
        if [[ -n "$matched_cert" ]]; then
          ROOT_CRT="$matched_cert"
          log INFO "Custom CA indicated by bootstrap token; matched trusted certificate at $ROOT_CRT"
        else
          root_ca_reason="Bootstrap token indicates custom CA ($token_hash) but no matching certificate found"
        fi
      else
        root_ca_reason="Bootstrap token file does not include a CA hash"
      fi
    fi
    if [[ ! -f "$ROOT_CRT" ]]; then
      if [[ -n "$root_ca_reason" ]]; then
        log WARN "$root_ca_reason; custom cluster CA will not be used."
      else
        log WARN "Root CA not found; custom cluster CA will not be used."
      fi
      return 0
    fi
  fi

  # If the cluster CA already exists, don't overwrite
  if [[ -f "$TLS_DIR/server-ca.crt" || -f "$TLS_DIR/client-ca.crt" ]]; then
    log INFO "Cluster CA appears to exist in $TLS_DIR; skipping custom CA generation."
    return 0
  fi

  mkdir -p "$TLS_DIR"

  # Stage inputs for the generator per RKE2 docs
  if [[ -f "$ROOT_KEY" ]]; then
    # Use provided root CA + key
    cp -f "$ROOT_CRT" "$TLS_DIR/root-ca.pem"
    cp -f "$ROOT_KEY" "$TLS_DIR/root-ca.key"
    log INFO "Prepared root CA + key for custom cluster CA generation."
  elif [[ -f "$INT_CRT" && -f "$INT_KEY" ]]; then
    # Use root (public) + intermediate (public+key)
    cp -f "$ROOT_CRT" "$TLS_DIR/root-ca.pem"
    cp -f "$INT_CRT"  "$TLS_DIR/intermediate-ca.pem"
    cp -f "$INT_KEY"  "$TLS_DIR/intermediate-ca.key"
    log INFO "Prepared root + intermediate for custom cluster CA generation."
  else
    log WARN "No CA private key found (expected CUSTOM_CA_ROOT_KEY or CUSTOM_CA_INT_KEY). "\
             "Will continue with RKE2 self-signed cluster CA."
    return 0
  fi

  # Validate private key readability in non-interactive mode before invoking
  # the CA helper. Encrypted keys can trigger passphrase prompts and fail in
  # unattended runs.
  local selected_key=""
  if [[ -f "$ROOT_KEY" ]]; then
    selected_key="$ROOT_KEY"
  elif [[ -f "$INT_KEY" ]]; then
    selected_key="$INT_KEY"
  fi

  if [[ -n "$selected_key" ]]; then
    local key_header=""
    key_header="$(head -n 1 "$selected_key" 2>/dev/null || true)"
    if [[ "$key_header" == *"ENCRYPTED PRIVATE KEY"* ]]; then
      log WARN "Detected encrypted private key: $selected_key"
      log WARN "Custom CA helper runs non-interactively and may prompt for passphrase or fail."
      log WARN "Remediation: provide an unencrypted key for automation, or run CA generation interactively."
    fi

    # Best-effort probe: verify key can be loaded without interactive input.
    # Use timeout to avoid hanging if openssl still attempts to prompt.
    local key_probe_rc=0
    if command -v timeout >/dev/null 2>&1; then
      timeout 3 openssl pkey -in "$selected_key" -noout -passin pass: >/dev/null 2>&1 || key_probe_rc=$?
    else
      openssl pkey -in "$selected_key" -noout -passin pass: >/dev/null 2>&1 || key_probe_rc=$?
    fi
    if [[ $key_probe_rc -ne 0 ]]; then
      log WARN "Private key pre-check failed for $selected_key (openssl rc=$key_probe_rc)."
      log WARN "If this key is passphrase-protected, helper may fail during custom CA generation."
    fi
  fi

  # Find the generator script (prefer offline copy)
  local GEN=""
  if [[ -x "$GEN1" ]]; then
    GEN="$GEN1"
  elif [[ -x "$GEN2" ]]; then
    GEN="$GEN2"
  fi

  if [[ -n "$GEN" ]]; then
    log INFO "Generating RKE2 custom CA set using offline helper: $GEN"
    PRODUCT=rke2 DATA_DIR=/var/lib/rancher/rke2 bash "$GEN" >>"$LOG_FILE" 2>&1 || {
      log ERROR "Custom CA generation failed via $GEN; leaving defaults in place."
      return 1
    }
  else
    if command -v curl >/dev/null 2>&1; then
      log INFO "Downloading helper to generate custom CA set (one-time)."
      curl -fsSL https://github.com/k3s-io/k3s/raw/master/contrib/util/generate-custom-ca-certs.sh \
        | PRODUCT=rke2 DATA_DIR=/var/lib/rancher/rke2 bash - >>"$LOG_FILE" 2>&1 || {
          log ERROR "Custom CA generation failed via curl; leaving defaults in place."
          return 1
        }
    else
      log ERROR "No offline helper found and curl not available; cannot generate custom cluster CA."
      return 1
    fi
  fi

  # Sanity: ensure the expected files exist
  local need=(server-ca.crt server-ca.key client-ca.crt client-ca.key request-header-ca.crt request-header-ca.key etcd/peer-ca.crt etcd/peer-ca.key etcd/server-ca.crt etcd/server-ca.key service.key)
  local missing=0
  for f in "${need[@]}"; do
    [[ -f "$TLS_DIR/$f" ]] || { log ERROR "Missing CA component after generation: $TLS_DIR/$f"; missing=1; }
  done
  if (( missing == 0 )); then
    log INFO "Custom cluster CA seeded successfully. New clusters will chain to provided root."
  fi

}

# ------------------------------------------------------------------------------
# Function: verify_custom_cluster_ca
# Purpose : Validate that required CA files exist before proceeding with custom
#           cluster certificate operations.
# Arguments:
#   None
# Returns :
#   Returns 0 when prerequisites are met, 1 otherwise.
# ------------------------------------------------------------------------------
verify_custom_cluster_ca() {
  local TLS_DIR="/var/lib/rancher/rke2/server/tls"
  local ROOT_CA="${CUSTOM_CA_ROOT_CRT:-$TLS_DIR/root-ca.pem}"
  local ok=0 fail=0

  if [[ ! -d "$TLS_DIR" ]]; then
    log WARN "TLS dir not found ($TLS_DIR); rke2-server may not be initialized yet."
    return 0
  fi

  local _bn=""
  if [[ ! -f "$ROOT_CA" ]]; then
    # Fallback to OS-installed copy of the configured CA
    if [[ -n "${CUSTOM_CA_ROOT_CRT:-}" ]]; then
      _bn="$(basename "$CUSTOM_CA_ROOT_CRT")"
      if [[ -f "/usr/local/share/ca-certificates/$_bn" ]]; then
        ROOT_CA="/usr/local/share/ca-certificates/$_bn"
      fi
    fi
  fi

  if [[ ! -f "$ROOT_CA" ]]; then
    log WARN "Root CA file not found for verification; skipping CA chain checks."
    return 0
  fi

  local to_check=(
    "server-ca.crt"
    "client-ca.crt"
    "request-header-ca.crt"
    "etcd/server-ca.crt"
    "etcd/peer-ca.crt"
  )

  for f in "${to_check[@]}"; do
    if [[ -f "$TLS_DIR/$f" ]]; then
      if openssl verify -CAfile "$ROOT_CA" "$TLS_DIR/$f" >/dev/null 2>&1; then
        log INFO "OK  : $(printf '%-22s' "$f") chains to root"
        ((ok++))
      else
        log ERROR "FAIL: $(printf '%-22s' "$f") does NOT chain to root"
        ((fail++))
      fi
    else
      log WARN "Missing: $TLS_DIR/$f"
    fi
  done

  # API server live check (if running)
  if systemctl is-active --quiet rke2-server && ss -ltn | awk '{print $4}' | grep -qE '(^|:)6443$'; then
    if timeout 5 openssl s_client -connect 127.0.0.1:6443 -verify_return_error -CAfile "$ROOT_CA" < /dev/null 2>&1 | grep -q "Verify return code: 0 (ok)"; then
      log INFO "OK  : kube-apiserver handshake verified with provided root CA"
    else
      log ERROR "FAIL: kube-apiserver handshake could not be verified with provided root CA"
      ((fail++))
    fi
  else
    log WARN "kube-apiserver not reachable on 127.0.0.1:6443; skipping live handshake check."
  fi

  if (( fail == 0 )); then
    echo "VERIFY (Cluster CA): PASS ($ok checks)"
  else
    echo "VERIFY (Cluster CA): FAIL ($fail failed, $ok passed)"
  fi
  return $fail
}

# ------------------------------------------------------------------------------
# Function: ensure_staged_artifacts
# Purpose : Confirm that the expected offline tarballs and installer scripts are
#           present in the staging directory prior to server/agent installs.
# Arguments:
#   None
# Returns :
#   Exits with status 3 when artifacts are missing.
# ------------------------------------------------------------------------------
ensure_staged_artifacts() {
  local missing=0
  # If operator provided a local artifact path, attempt to stage from it into STAGE_DIR
  if [[ -n "${INSTALL_RKE2_ARTIFACT_PATH:-}" && -d "${INSTALL_RKE2_ARTIFACT_PATH}" ]]; then
    log INFO "INSTALL_RKE2_ARTIFACT_PATH is set; attempting to stage artifacts from '${INSTALL_RKE2_ARTIFACT_PATH}' into '$STAGE_DIR'"
    stage_from_artifact_path "${INSTALL_RKE2_ARTIFACT_PATH}" || {
      log ERROR "Staging artifacts from INSTALL_RKE2_ARTIFACT_PATH failed. Aborting."
      exit 3
    }
  fi
  if [[ ! -f "$STAGE_DIR/install.sh" ]]; then
    if [[ -f "$DOWNLOADS_DIR/install.sh" ]]; then
      cp "$DOWNLOADS_DIR/install.sh" "$STAGE_DIR/" && chmod +x "$STAGE_DIR/install.sh"
      log INFO "Staged install.sh"
    else
      log ERROR "Missing install.sh. Run 'image' first."; missing=1
    fi
  fi
  if [[ ! -f "$STAGE_DIR/$RKE2_TARBALL" ]]; then
    if [[ -f "$DOWNLOADS_DIR/$RKE2_TARBALL" ]]; then
      cp "$DOWNLOADS_DIR/$RKE2_TARBALL" "$STAGE_DIR/"
      log INFO "Staged RKE2 tarball"
    else
      log ERROR "Missing $RKE2_TARBALL. Run 'image' first."; missing=1
    fi
  fi
  if [[ ! -f "$STAGE_DIR/$SHA256_FILE" ]]; then
    if [[ -f "$DOWNLOADS_DIR/$SHA256_FILE" ]]; then
      cp "$DOWNLOADS_DIR/$SHA256_FILE" "$STAGE_DIR/"
      log INFO "Staged SHA256 file"
    else
      log ERROR "Missing $SHA256_FILE. Run 'image' first."; missing=1
    fi
  fi
  if (( missing != 0 )); then
    exit 3
  fi

  # Runtime verification: validate staged files against the provided sha256 file
  if command -v sha256sum >/dev/null 2>&1; then
    if [[ -f "$STAGE_DIR/$SHA256_FILE" ]]; then
      # Some artifacts (image bundles) are staged into a separate images dir
      # (IMAGES_DIR). Build a temporary manifest that maps manifest entries to
      # their actual staged locations (STAGE_DIR or IMAGES_DIR) so sha256sum
      # can validate them regardless of which staging target holds the file.
      local IMAGES_DIR="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"
      log INFO "Verifying staged artifacts checksums in $STAGE_DIR (including $IMAGES_DIR)"
      local tmp_manifest
      tmp_manifest=$(mktemp)
      # Read original manifest and map each entry to where the file actually lives
      # We collect three lists:
      #  - mapped_lines: entries we can point at an existing file
      #  - missing_entries: entries not found as standalone files
      #  - image_like_missing: subset of missing_entries that look like per-flavor image bundles
      local -a mapped_lines=()
      local -a missing_entries=()
      local -a image_like_missing=()
      while read -r h fn; do
        # Normalize to basename when manifest references relative paths
        local bn
        bn=$(basename "${fn}")
        if [[ -f "$STAGE_DIR/$bn" ]]; then
          mapped_lines+=("$h  $STAGE_DIR/$bn")
        elif [[ -f "$IMAGES_DIR/$bn" ]]; then
          mapped_lines+=("$h  $IMAGES_DIR/$bn")
        elif [[ -f "$DOWNLOADS_DIR/$bn" ]]; then
          mapped_lines+=("$h  $DOWNLOADS_DIR/$bn")
        else
          # Not present as a standalone file; record for later decision
          missing_entries+=("$h  $bn")
          # Heuristic: many per-flavor image bundles are named rke2-images-*. Treat
          # those as image-like so they can be considered satisfied by a consolidated
          # images tarball when present and verified.
          if [[ "$bn" == rke2-images-* ]]; then
            image_like_missing+=("$h  $bn")
          fi
        fi
      done < "$STAGE_DIR/$SHA256_FILE"

      # Verify consolidated images tarball first (if present in stage/downloads/images dir)
      local images_tar_candidate=""
      for p in "$STAGE_DIR/$IMAGES_TAR" "$IMAGES_DIR/$IMAGES_TAR" "$DOWNLOADS_DIR/$IMAGES_TAR"; do
        if [[ -f "$p" ]]; then images_tar_candidate="$p"; break; fi
      done

      local images_consolidated_verified=0
      if [[ -n "$images_tar_candidate" ]]; then
        # If the manifest contains an entry for the consolidated images tar, prefer
        # to verify that explicitly. Otherwise, we'll verify mapped_lines below
        # and treat image-like missing entries as covered by the consolidated tar.
        if grep -Fq "$IMAGES_TAR" "$STAGE_DIR/$SHA256_FILE"; then
          # Map manifest entry to actual path so sha256sum can find the file.
          if (grep "$IMAGES_TAR" "$STAGE_DIR/$SHA256_FILE" | awk -v p="$images_tar_candidate" '{print $1 "  " p}' | sha256sum -c -) >>"$LOG_FILE" 2>&1; then
            images_consolidated_verified=1
            log INFO "Consolidated images archive verified: $images_tar_candidate"
          else
            log WARN "Consolidated images archive present but failed checksum: $images_tar_candidate"
          fi
        else
          # No manifest line for consolidated tar in stage manifest; attempt to verify
          # it against downloads manifest if available
          if [[ -f "$DOWNLOADS_DIR/$SHA256_FILE" && $(grep -F "$IMAGES_TAR" "$DOWNLOADS_DIR/$SHA256_FILE" | wc -l) -gt 0 ]]; then
            if (grep "$IMAGES_TAR" "$DOWNLOADS_DIR/$SHA256_FILE" | awk -v p="$images_tar_candidate" '{print $1 "  " p}' | sha256sum -c -) >>"$LOG_FILE" 2>&1; then
              images_consolidated_verified=1
              log INFO "Consolidated images archive verified via downloads manifest: $images_tar_candidate"
            else
              log WARN "Consolidated images archive present but failed verification against downloads manifest"
            fi
          fi
        fi
      fi

            # If Canal (flannel) is required, derive hardened-flannel tag similarly
            if [[ $requires_multus -ne 1 && -z "${HARDENED_FLANNEL_TAG:-}" ]]; then
              # detect canal usage by inspecting the config file if we haven't already
              if [[ -n "${CONFIG_FILE:-}" && -f "$CONFIG_FILE" ]]; then
                if grep -q "spec.cni: *canal" "$CONFIG_FILE" 2>/dev/null || grep -q "canal" "$CONFIG_FILE" 2>/dev/null; then
                  requires_canal=1
                fi
              fi
            fi
            if [[ ${requires_canal:-0} -eq 1 && -z "${HARDENED_FLANNEL_TAG:-}" ]]; then
              if [[ -f "$DOWNLOADS_DIR/$IMAGES_TXT" ]]; then
                local _fline
                _fline=$(grep -E 'hardened-flannel' "$DOWNLOADS_DIR/$IMAGES_TXT" | grep -v '@' | head -n1 || true)
                if [[ -n "$_fline" ]]; then
                  HARDENED_FLANNEL_TAG="${_fline##*:}"
                  log INFO "Derived HARDENED_FLANNEL_TAG from images list: ${HARDENED_FLANNEL_TAG}"
                fi
              fi
              if [[ -z "${HARDENED_FLANNEL_TAG:-}" && -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
                HARDENED_FLANNEL_TAG=$(extract_hardened_flannel_tag_from_images "$DOWNLOADS_DIR/$IMAGES_TAR" 2>/dev/null || true)
                if [[ -n "${HARDENED_FLANNEL_TAG:-}" ]]; then
                  log INFO "Derived HARDENED_FLANNEL_TAG from images tarball: ${HARDENED_FLANNEL_TAG}"
                else
                  if [[ -f "$DOWNLOADS_DIR/$HARDENED_FLANNEL_BN" ]]; then
                    log INFO "Unable to derive HARDENED_FLANNEL_TAG from images list/tarball, but existing hardened-flannel artifact found at $DOWNLOADS_DIR/$HARDENED_FLANNEL_BN"
                  else
                    log WARN "Unable to derive HARDENED_FLANNEL_TAG from release artifacts; hardened-flannel mirroring will auto-select a tag"
                  fi
                fi
              fi
            fi

      # Build the temporary manifest to validate with sha256sum: include mapped lines
      # and any missing_entries that are not image-like (or image-like but not covered).
      local line
      for line in "${mapped_lines[@]}"; do printf '%s\n' "$line" >>"$tmp_manifest"; done
      for line in "${missing_entries[@]}"; do
        local bn
        bn=$(basename "${line#*  }")
        # If this missing entry is image-like and we have a verified consolidated tar,
        # skip adding it to the temporary manifest (consider it satisfied).
        if [[ "$bn" == rke2-images-* && $images_consolidated_verified -eq 1 ]]; then
          log INFO "Treating missing image-like manifest entry as satisfied by consolidated tar: $bn"
          continue
        fi
        # Otherwise include it (will cause sha256sum to report missing) so operator sees it
        printf '%s\n' "$line" >>"$tmp_manifest"
      done

      # Run verification against the normalized manifest
      if ! sha256sum -c "$tmp_manifest" >>"$LOG_FILE" 2>&1; then
        log ERROR "Staged artifact checksum verification FAILED. Aborting install. Remove bad artifacts and re-run 'image'."
        rm -f "$tmp_manifest" || true
        exit 3
      fi
      rm -f "$tmp_manifest" || true
      log INFO "Staged artifacts checksum verification passed"
    else
      log WARN "No checksum file present in $STAGE_DIR; cannot verify staged artifacts"
    fi
  else
    log WARN "sha256sum not available; skipping staged artifact verification"
  fi

  # --- Post-staging verification: ensure images tarball is present and accessible ---
  log INFO "Performing post-staging verification..."
  
  # Priority 2: Architecture mismatch detection
  local EXPECTED_TAR="rke2-images.linux-${ARCH}.tar.zst"
  if [[ ! -f "$IMAGES_DIR/$EXPECTED_TAR" ]]; then
    # Look for any rke2-images tarball in images dir (may be wrong arch)
    local found_tars
    found_tars=$(find "$IMAGES_DIR" -maxdepth 1 \( -name "rke2-images.linux-*.tar.zst" -o -name "rke2-images.linux-*.tar.gz" \) 2>/dev/null || true)
    if [[ -n "$found_tars" ]]; then
      log ERROR "Expected $EXPECTED_TAR but found different architecture tarball(s):"
      echo "$found_tars" | while read -r f; do 
        [[ -z "$f" ]] && continue
        log ERROR "  - $(basename "$f")"
      done
      log ERROR "Architecture mismatch detected!"
      log ERROR "Current host architecture: $ARCH"
      log ERROR "Did you run 'action_image' on a different architecture host?"
      log ERROR "Re-run 'action_image' on this host or provide correct artifacts via INSTALL_RKE2_ARTIFACT_PATH"
      exit 3
    fi
  fi

  # Priority 1: Verify images tarball is present and accessible after staging
  if [[ ! -f "$IMAGES_DIR/$IMAGES_TAR" ]]; then
    log ERROR "Images tarball not found after staging: $IMAGES_DIR/$IMAGES_TAR"
    log ERROR "Expected file: $IMAGES_TAR"
    log ERROR "This will cause RKE2 to attempt network download and fail in air-gapped environments"
    
    # Try fallback from downloads
    if [[ -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
      log WARN "Attempting to re-stage from downloads directory as fallback"
      local tmpimg="$IMAGES_DIR/.tmp-${IMAGES_TAR}.$$"
      cp -f "$DOWNLOADS_DIR/$IMAGES_TAR" "$tmpimg"
      mv -T "$tmpimg" "$IMAGES_DIR/$IMAGES_TAR"
      log INFO "Re-staged ${IMAGES_TAR} from downloads"
    else
      log ERROR "No fallback copy available in downloads; run 'action_image' first"
      exit 3
    fi
  fi

  # Quick sanity check: ensure tarball is a valid archive
  if command -v zstd >/dev/null 2>&1 && [[ "$IMAGES_TAR" == *.zst ]]; then
    log INFO "Testing tarball integrity with zstd..."
    if ! zstd -t "$IMAGES_DIR/$IMAGES_TAR" >>"$LOG_FILE" 2>&1; then
      log ERROR "Images tarball appears corrupted (zstd test failed)"
      log ERROR "Tarball: $IMAGES_DIR/$IMAGES_TAR"
      log ERROR "Delete the corrupted file and re-run 'image' action"
      exit 3
    fi
    log INFO "Images tarball integrity verified (zstd test passed)"
  elif command -v gzip >/dev/null 2>&1 && [[ "$IMAGES_TAR" == *.gz ]]; then
    log INFO "Testing tarball integrity with gzip..."
    if ! gzip -t "$IMAGES_DIR/$IMAGES_TAR" >>"$LOG_FILE" 2>&1; then
      log ERROR "Images tarball appears corrupted (gzip test failed)"
      log ERROR "Tarball: $IMAGES_DIR/$IMAGES_TAR"
      log ERROR "Delete the corrupted file and re-run 'image' action"
      exit 3
    fi
    log INFO "Images tarball integrity verified (gzip test passed)"
  else
    log WARN "Cannot test tarball integrity (compression tool not available)"
  fi

  local tar_size
  tar_size=$(du -h "$IMAGES_DIR/$IMAGES_TAR" 2>/dev/null | awk '{print $1}' || echo "unknown")
  log INFO "Images tarball staged successfully: $IMAGES_DIR/$IMAGES_TAR ($tar_size)"
  
  # Priority 4: Extract and log sample image list from tarball for audit
  log INFO "Extracting image list from tarball for audit..."
  if command -v zstd >/dev/null 2>&1 && [[ "$IMAGES_TAR" == *.zst ]]; then
    # Try to extract manifest.json to inspect image list
    local manifest
    manifest=$(zstd -dc "$IMAGES_DIR/$IMAGES_TAR" 2>/dev/null | tar -xO manifest.json 2>/dev/null || echo "")
    if [[ -n "$manifest" ]]; then
      # Count RepoTags entries (Docker manifest format)
      local repo_tag_count
      repo_tag_count=$(echo "$manifest" | grep -o '"RepoTags"' | wc -l 2>/dev/null || echo 0)
      log INFO "Tarball manifest contains $repo_tag_count image layer sets (Docker format)"
      
      # Extract sample image names (look for rancher images as representative)
      log INFO "Sample images in tarball:"
      # Guard grep so a non-match (exit code 1) does not trigger set -o pipefail
      # and abort the entire script. We only want to iterate when matches exist.
      echo "$manifest" | { grep -o '"docker.io/rancher[^"]*"' 2>/dev/null || true; } | head -n 3 | while read -r img; do
        local clean_img
        clean_img=$(echo "$img" | tr -d '"')
        log INFO "  - $clean_img"
      done
      
      # Check for CNI plugins image as representative sample of tarball completeness.
      # If the hardened CNI image is staged separately, don't warn on absence here.
      local hardened_cni_tar=""
      for p in "$STAGE_DIR/$HARDENED_CNI_BN" "$DOWNLOADS_DIR/$HARDENED_CNI_BN"; do
        if [[ -f "$p" ]]; then
          hardened_cni_tar="$p"
          break
        fi
      done
      if echo "$manifest" | grep -q "hardened-cni-plugins"; then
        log INFO "  ✓ Tarball verification passed: 'hardened-cni-plugins' present in manifest"
      elif [[ -n "$hardened_cni_tar" ]]; then
        log INFO "  ✓ Tarball verification: hardened-cni-plugins provided via separate archive $(basename "$hardened_cni_tar")"
      else
        log WARN "  ⚠ Tarball verification: 'hardened-cni-plugins' not found in Docker manifest"
        log WARN "     Archive may use OCI format or different image naming. Attempting OCI index parsing..."
      fi
    else
      # Docker manifest not found, try OCI image index format as fallback
      log INFO "Docker manifest.json not found, attempting OCI image index parsing..."
      local oci_refs
      oci_refs=$(parse_oci_image_index "$IMAGES_DIR/$IMAGES_TAR" 2>/dev/null || echo "")
      
      if [[ -n "$oci_refs" && "$oci_refs" != "[]" ]]; then
        local ref_count
        ref_count=$(echo "$oci_refs" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)
        log INFO "Tarball contains $ref_count image reference(s) (OCI format)"
        
        # Show sample images from OCI index
        log INFO "Sample images in tarball:"
        echo "$oci_refs" | python3 -c '
import json, sys
try:
    refs = json.load(sys.stdin)
    for ref in refs[:3]:  # Show first 3
        print(ref)
except:
    pass
' 2>/dev/null | while read -r img; do
          log INFO "  - $img"
        done
        
        # Check for rancher images
        if echo "$oci_refs" | grep -q "rancher"; then
          log INFO "  ✓ Verified: rancher images present in OCI tarball"
        fi
      else
        log WARN "Could not parse tarball format (neither Docker manifest nor OCI index found)"
      fi
    fi
  elif command -v tar >/dev/null 2>&1; then
    # For non-zst tarballs, try direct tar inspection
    log INFO "Inspecting tarball contents..."
    local file_count
    file_count=$(tar -tzf "$IMAGES_DIR/$IMAGES_TAR" 2>/dev/null | wc -l || echo 0)
    log INFO "Tarball contains $file_count files/layers"
  else
    log WARN "Cannot inspect tarball contents (required tools not available)"
  fi
  
  # Optional: Deep layer checksum verification (opt-in via --verify-layers)
  if (( VERIFY_LAYERS == 1 )); then
    log INFO "Performing deep layer checksum verification (--verify-layers enabled)..."
    if verify_image_layer_checksums "$IMAGES_DIR/$IMAGES_TAR" "$STAGE_DIR"; then
      log INFO "✓ Deep layer verification passed: all image layers verified"
    else
      log ERROR "✗ Deep layer verification FAILED"
      log ERROR "One or more image layers are corrupted or missing"
      log ERROR "Delete the tarball and re-run 'image' action to download fresh copy"
      exit 3
    fi
  else
    log INFO "Deep layer verification skipped (use --verify-layers to enable)"
  fi

  if ! verify_required_image_tags_staged; then
    log ERROR "Post-staging required image/tag validation FAILED"
    log ERROR "Server/agent installs would attempt remote pulls in disconnected environments"
    exit 3
  fi
  
  log INFO "Post-staging verification complete"
}

# ---------- Image resolution strategy (local → offline registry(s)) ----------------------------
# Ensures that: 1) staged images are loaded, 2) local images are retagged to match the
# system-default-registry prefix so containerd will use them without pulling, and
# 3) registries.yaml mirrors point to your offline registry endpoints in priority order.
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# TODO: load_staged_images() function was removed (unused)
# Could be useful for air-gapped scenarios. Consider integrating into
# action_airgap or action_push workflows if image loading is needed.
# Archived in: rke2nodeinit-unused-functions.sh
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# TODO: retag_local_images_with_prefix() function was removed (unused)
# Could be useful for private registry workflows. Consider integrating with
# action_push or registry configuration logic if image retagging is needed.
# Archived in: rke2nodeinit-unused-functions.sh
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# TODO: ensure_hosts_pin() function was removed (unused)
# Could be useful for offline/air-gapped scenarios when DNS is not available.
# Consider integrating with registry configuration logic if hostname pinning needed.
# Archived in: rke2nodeinit-unused-functions.sh
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Function: write_registries_yaml_with_fallbacks
# Purpose : Generate /etc/rancher/rke2/registries.yaml including mirrors, custom
#           endpoints, and optional TLS settings with fallback behavior.
# Arguments:
#   None (uses globals populated earlier)
# Returns :
#   Writes the YAML file; returns 0 on success.
# ------------------------------------------------------------------------------
write_registries_yaml_with_fallbacks() {
  # Build a registries.yaml that:
  #   1) Enables distributed mirroring via the embedded registry (Spegel)
  #   2) Forces all image pulls through the internal registry endpoint
  #   3) Rewrites upstream image paths into a Harbor-like <project>/<upstream-registry>/<repo> layout
  # Args: primary_registry_host registry_project username password ca_file
  local primary="$1"; shift || true
  local project="$1"; shift || true
  local user="$1"; shift || true
  local pass="$1"; shift || true
  local ca_file="$1"; shift || true

  mkdir -p /etc/rancher/rke2

  local prefix=""
  [[ -n "$project" ]] && prefix="${project}/"

  # Discover registries from release image list files when available.
  # This keeps registries.yaml aligned with the exact images staged/downloaded.
  local -a regs=()
  local list_file=""
  for f in "$DOWNLOADS_DIR/rke2-images-all.linux-${ARCH}.txt" "$DOWNLOADS_DIR/rke2-images.linux-${ARCH}.txt"; do
    if [[ -f "$f" ]]; then
      list_file="$f"
      break
    fi
  done

  if [[ -n "$list_file" ]]; then
    while IFS= read -r ref; do
      # strip comments/whitespace
      ref="${ref%%#*}"
      ref="${ref%%[[:space:]]*}"
      [[ -z "$ref" ]] && continue
      ref="$(normalize_image_reference "$ref" 2>/dev/null || true)"
      [[ -z "$ref" ]] && continue

      local first="${ref%%/*}"
      local reg=""
      if [[ "$ref" == */* && ( "$first" == *.* || "$first" == *:* ) ]]; then
        reg="$first"
      else
        reg="docker.io"
      fi

      # Skip mirroring for the internal registry host itself (avoid recursion)
      [[ "$reg" == "$primary" ]] && continue

      regs+=("$reg")
    done < "$list_file"
  fi

  if [[ ${#regs[@]} -eq 0 ]]; then
    regs=(docker.io registry.k8s.io ghcr.io quay.io gcr.io k8s.gcr.io)
  fi

  # Deduplicate
  IFS=$'\n'
  regs=($(printf '%s\n' "${regs[@]}" | sort -u))
  unset IFS

  # Render YAML
  {
    echo "# Auto-generated by rke2nodeinit.sh - DO NOT EDIT"
    echo "# Internal registry endpoint: https://${primary}"
    echo "# Registry project/prefix: ${project:-<none>}"
    echo
    echo "mirrors:"
    # Wildcard mirror entry prevents accidental external pulls when paired with
    # disable-default-registry-endpoint: true in config.yaml.
    echo "  \"*\":"

    for reg in "${regs[@]}"; do
      echo "  \"${reg}\":"
      echo "    endpoint:"
      echo "      - \"https://${primary}\""
      echo "    rewrite:"
      # Rewrite upstream image path into <project>/<upstream-registry>/<repo>
      # Example: docker.io/rancher/pause -> altregistry/<project>/docker.io/rancher/pause
      printf '      "^(.*)$": "%s%s/$1"\n' "$prefix" "$reg"
    done

    echo "configs:"
    echo "  \"${primary}\":"

    if [[ -n "$user" && -n "$pass" ]]; then
      echo "    auth:"
      echo "      username: \"${user}\""
      echo "      password: \"${pass}\""
    fi

    if [[ -n "$ca_file" && -f "$ca_file" ]]; then
      echo "    tls:"
      echo "      ca_file: \"${ca_file}\""
    fi
  } > /etc/rancher/rke2/registries.yaml

  chmod 600 /etc/rancher/rke2/registries.yaml
  log INFO "Wrote /etc/rancher/rke2/registries.yaml for internal registry ${primary} (project='${project:-<none>}')"
}

# ------------------------------------------------------------------------------
# Function: fetch_rke2_ca_generator
# Purpose : Download the cluster CA helper script from Rancher releases and cache
#           it locally for offline use.
# Arguments:
#   None
# Returns :
#   Returns 0 on success.
# ------------------------------------------------------------------------------
fetch_rke2_ca_generator() {
  # Prefetch custom-CA helper for offline use
  if command -v curl >/dev/null 2>&1; then
    local GEN_URL="https://raw.githubusercontent.com/k3s-io/k3s/refs/heads/main/contrib/util/generate-custom-ca-certs.sh"
    log INFO "Fetching custom-CA helper script for offline use."
    curl -fsSL -o "$DOWNLOADS_DIR/generate-custom-ca-certs.sh" "$GEN_URL" >>"$LOG_FILE" 2>&1 || true
    chmod +x "$DOWNLOADS_DIR/generate-custom-ca-certs.sh" >>"$LOG_FILE" 2>&1 || true
    log INFO "Staged custom-CA helper script for offline use."
  fi
}

# ------------------------------------------------------------------------------
# Function: cache_rke2_artifacts
# Purpose : Download and verify all required RKE2 release artifacts (images,
#           tarballs, checksums) storing them under the downloads directory.
# Note    : Invoked by the image action, which is the only workflow permitted to
#           access the Internet.
# Arguments:
#   None
# Returns :
#   Exits if downloads fail or checksums mismatch.
# ------------------------------------------------------------------------------
cache_rke2_artifacts() {
  mkdir -p "$DOWNLOADS_DIR"
  local requires_multus=0
  local requires_canal=0

  # If operator provided a local artifact path, prefer it and stage from there
  if [[ -n "${INSTALL_RKE2_ARTIFACT_PATH:-}" && -d "${INSTALL_RKE2_ARTIFACT_PATH}" ]]; then
    log INFO "INSTALL_RKE2_ARTIFACT_PATH is set; staging artifacts from '${INSTALL_RKE2_ARTIFACT_PATH}'"
    stage_from_artifact_path "${INSTALL_RKE2_ARTIFACT_PATH}"
    return $?
  fi

  pushd "$DOWNLOADS_DIR" >/dev/null

  # Pick version: from config/env or latest online
  if [[ -n "$REQ_VER" ]]; then
    RKE2_VERSION="$REQ_VER"
    log INFO "Using RKE2 version from config/env: $RKE2_VERSION"
  else
    detect_latest_rke2_version   # populates RKE2_VERSION
  fi

  normalize_rke2_fips_version

  # URL-encode '+' in version (GitHub releases use %2B for plus signs)
  local url_version="${RKE2_VERSION//+/%2B}"
  local BASE_URL="https://github.com/rancher/rke2/releases/download/${url_version}"
  local IMAGES_TAR="rke2-images.linux-${ARCH}.tar.zst"
  local IMAGES_TXT="rke2-images-all.linux-${ARCH}.txt"
  local RKE2_TARBALL="rke2.linux-${ARCH}.tar.gz"
  local SHA256_FILE="sha256sum-${ARCH}.txt"

  # Download artifacts (idempotent)
  if [[ -f "$IMAGES_TAR" ]]; then
    log INFO "Already present: $IMAGES_TAR (skipping download)"
  else
    log INFO "Downloading $IMAGES_TAR from $BASE_URL/$IMAGES_TAR"
    spinner_run "Downloading $IMAGES_TAR" curl -Lf "$BASE_URL/$IMAGES_TAR" -o "$IMAGES_TAR"
    if [[ -f "$IMAGES_TAR" ]]; then
      local _size
      _size=$(du -h "$IMAGES_TAR" 2>/dev/null | awk '{print $1}' || echo "unknown")
      log INFO "Downloaded: $DOWNLOADS_DIR/$IMAGES_TAR ($_size) from $BASE_URL/$IMAGES_TAR"
    else
      log WARN "Download finished but file not found: $IMAGES_TAR"
    fi
  fi
  if [[ -f "$RKE2_TARBALL" ]]; then
    log INFO "Already present: $RKE2_TARBALL (skipping download)"
  else
    log INFO "Downloading $RKE2_TARBALL from $BASE_URL/$RKE2_TARBALL"
    spinner_run "Downloading $RKE2_TARBALL" curl -Lf "$BASE_URL/$RKE2_TARBALL" -o "$RKE2_TARBALL"
    if [[ -f "$RKE2_TARBALL" ]]; then
      local _size
      _size=$(du -h "$RKE2_TARBALL" 2>/dev/null | awk '{print $1}' || echo "unknown")
      log INFO "Downloaded: $DOWNLOADS_DIR/$RKE2_TARBALL ($_size) from $BASE_URL/$RKE2_TARBALL"
    else
      log WARN "Download finished but file not found: $RKE2_TARBALL"
    fi
  fi
  if [[ -f "$SHA256_FILE" ]]; then
    log INFO "Already present: $SHA256_FILE (skipping download)"
  else
    log INFO "Downloading $SHA256_FILE from $BASE_URL/$SHA256_FILE"
    spinner_run "Downloading $SHA256_FILE" curl -Lf "$BASE_URL/$SHA256_FILE" -o "$SHA256_FILE"
    if [[ -f "$SHA256_FILE" ]]; then
      log INFO "Downloaded: $DOWNLOADS_DIR/$SHA256_FILE from $BASE_URL/$SHA256_FILE"
    else
      log_WARN "Download finished but file not found: $SHA256_FILE"
    fi
  fi
  if [[ -f install.sh ]]; then
    log INFO "Already present: install.sh (skipping download)"
  else
    log INFO "Downloading install.sh from https://get.rke2.io"
    spinner_run "Downloading install.sh" curl -sfL "https://get.rke2.io" -o install.sh
    if [[ -f install.sh ]]; then
      local _size
      _size=$(du -h install.sh 2>/dev/null | awk '{print $1}' || echo "unknown")
      log INFO "Downloaded: $DOWNLOADS_DIR/install.sh ($_size) from https://get.rke2.io"
    else
      log WARN "Download finished but file not found: install.sh"
    fi
  fi
  chmod +x install.sh || true

  if [[ -n "${CONFIG_FILE:-}" && -f "$CONFIG_FILE" ]]; then
    local _cni
    while IFS= read -r _cni; do
      [[ "$_cni" == "multus" ]] && requires_multus=1
      [[ "$_cni" == "canal" ]] && requires_canal=1
    done < <(collect_requested_cni_plugins "$CONFIG_FILE")
  fi

  # Prefer parsing the release images list text file for explicit hardened-* tags
  # Download the images list txt first (idempotent) so we can extract exact
  # `hardened-cni-plugins` and `hardened-multus-cni` tags used by the release.
  if [[ -f "$IMAGES_TXT" ]]; then
    log INFO "Already present: $IMAGES_TXT (skipping download)"
  else
    log INFO "Downloading $IMAGES_TXT from $BASE_URL/$IMAGES_TXT"
    spinner_run "Downloading $IMAGES_TXT" curl -Lf "$BASE_URL/$IMAGES_TXT" -o "$IMAGES_TXT" || true
    if [[ -f "$IMAGES_TXT" ]]; then
      log INFO "Downloaded: $DOWNLOADS_DIR/$IMAGES_TXT from $BASE_URL/$IMAGES_TXT"
    else
      log WARN "Images list not found: $IMAGES_TXT; continuing and falling back to tarball parsing"
    fi
  fi

  # If operator didn't set HARDENED_CNI_TAG, try to derive it from the images list
  if [[ -z "${HARDENED_CNI_TAG:-}" ]]; then
    if [[ -f "$DOWNLOADS_DIR/$IMAGES_TXT" ]]; then
      # Prefer entries without digests (@sha256) and take the first matching line
      local _line
      _line=$(grep -E 'hardened-cni-plugins' "$DOWNLOADS_DIR/$IMAGES_TXT" | grep -v '@' | head -n1 || true)
      if [[ -n "$_line" ]]; then
        HARDENED_CNI_TAG="${_line##*:}"
        log INFO "Derived HARDENED_CNI_TAG from images list: ${HARDENED_CNI_TAG}"
      fi
    fi
    # Fallback: extract from images tarball if text list not available
    if [[ -z "${HARDENED_CNI_TAG:-}" && -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
      HARDENED_CNI_TAG=$(extract_hardened_cni_tag_from_images "$DOWNLOADS_DIR/$IMAGES_TAR" 2>/dev/null || true)
      if [[ -n "${HARDENED_CNI_TAG:-}" ]]; then
        log INFO "Derived HARDENED_CNI_TAG from images tarball: ${HARDENED_CNI_TAG}"
      else
        if [[ -f "$DOWNLOADS_DIR/$HARDENED_CNI_BN" ]]; then
          log INFO "Unable to derive HARDENED_CNI_TAG from images list/tarball, but existing hardened-cni artifact found at $DOWNLOADS_DIR/$HARDENED_CNI_BN"
        else
          log WARN "Unable to derive HARDENED_CNI_TAG from release artifacts; hardened-cni mirroring may fall back to heuristics"
        fi
      fi
    fi
  fi

  # If Multus is required, derive hardened-multus tag similarly
  if [[ $requires_multus -eq 1 && -z "${HARDENED_MULTUS_TAG:-}" ]]; then
    if [[ -f "$DOWNLOADS_DIR/$IMAGES_TXT" ]]; then
      local _mline
      _mline=$(grep -E 'hardened-multus-cni|multus' "$DOWNLOADS_DIR/$IMAGES_TXT" | grep -v '@' | grep -E 'multus|hardened-multus-cni' | head -n1 || true)
      if [[ -n "$_mline" ]]; then
        HARDENED_MULTUS_TAG="${_mline##*:}"
        log INFO "Derived HARDENED_MULTUS_TAG from images list: ${HARDENED_MULTUS_TAG}"
      fi
    fi
    if [[ -z "${HARDENED_MULTUS_TAG:-}" && -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
      HARDENED_MULTUS_TAG=$(extract_hardened_multus_tag_from_images "$DOWNLOADS_DIR/$IMAGES_TAR" 2>/dev/null || true)
      if [[ -n "${HARDENED_MULTUS_TAG:-}" ]]; then
        log INFO "Derived HARDENED_MULTUS_TAG from images tarball: ${HARDENED_MULTUS_TAG}"
      else
        if [[ -f "$DOWNLOADS_DIR/$HARDENED_MULTUS_BN" ]]; then
          log INFO "Unable to derive HARDENED_MULTUS_TAG from images list/tarball, but existing hardened-multus artifact found at $DOWNLOADS_DIR/$HARDENED_MULTUS_BN"
        else
          log WARN "Unable to derive HARDENED_MULTUS_TAG from release artifacts; hardened-multus mirroring will auto-select a tag"
        fi
      fi
    fi
  fi

  # Optionally download hardened-cni-plugins when configured. Prefer skopeo
  # (Docker Hub mirror) when available; fall back to HTTP(S) URL if provided.
  if [[ -n "${HARDENED_CNI_URL:-}" || -n "${HARDENED_CNI_BN:-}" ]]; then
    # If the artifact already exists in downloads, skip acquisition.
    if [[ -f "$DOWNLOADS_DIR/$HARDENED_CNI_BN" ]]; then
      log INFO "Already present: $DOWNLOADS_DIR/$HARDENED_CNI_BN; skipping hardened-cni acquisition"
    else
      if command -v skopeo >/dev/null 2>&1; then
        log INFO "skopeo detected; attempting to mirror hardened-cni from Docker Hub"
        if ! cache_hardened_cni_skopeo "${HARDENED_CNI_TAG:-}"; then
          log WARN "skopeo hardened-cni mirror failed; attempting HTTP fallback"
          if [[ -n "${HARDENED_CNI_URL:-}" ]]; then
            cache_hardened_cni_http "$HARDENED_CNI_URL" || log WARN "hardened-cni download failed; continuing without it"
          fi
        fi
      else
        if [[ -n "${HARDENED_CNI_URL:-}" ]]; then
          log INFO "Configured HARDENED_CNI_URL detected; attempting HTTP download"
          cache_hardened_cni_http "$HARDENED_CNI_URL" || log WARN "hardened-cni download failed; continuing without it"
        else
          log INFO "HARDENED_CNI_URL not configured and skopeo not available; skipping hardened-cni acquisition"
        fi
      fi
    fi
  fi

  # Enforce hardened-cni availability when required (ensures offline Multus/CNI dependencies).
  if [[ "${HARDENED_CNI_REQUIRED:-0}" != "0" ]]; then
    if [[ ! -f "$DOWNLOADS_DIR/$HARDENED_CNI_BN" ]]; then
      log ERROR "Required hardened-cni-plugins artifact missing: $DOWNLOADS_DIR/$HARDENED_CNI_BN"
      log ERROR "Remediation: install 'skopeo' for auto-mirroring or set HARDENED_CNI_URL to a direct tarball"
      popd >/dev/null || true
      return 4
    fi
  fi

  if [[ $requires_multus -eq 1 ]]; then
    if [[ -f "$DOWNLOADS_DIR/$HARDENED_MULTUS_BN" ]]; then
      log INFO "Already present: $DOWNLOADS_DIR/$HARDENED_MULTUS_BN; skipping hardened-multus acquisition"
    else
      if command -v skopeo >/dev/null 2>&1; then
        log INFO "Multus requested; attempting to mirror hardened-multus from Docker Hub"
        if ! cache_hardened_multus_skopeo "${HARDENED_MULTUS_TAG:-}"; then
          log ERROR "Failed to mirror hardened-multus-cni required for spec.cni=multus"
          popd >/dev/null || true
          return 6
        fi
      else
        log ERROR "Multus requested but skopeo is not available to mirror hardened-multus-cni"
        log ERROR "Remediation: install skopeo and re-run image action, or pre-stage $HARDENED_MULTUS_BN in $DOWNLOADS_DIR"
        popd >/dev/null || true
        return 6
      fi
    fi
  fi
  if [[ $requires_canal -eq 1 ]]; then
    if [[ -f "$DOWNLOADS_DIR/$HARDENED_FLANNEL_BN" ]]; then
      log INFO "Already present: $DOWNLOADS_DIR/$HARDENED_FLANNEL_BN; skipping hardened-flannel acquisition"
    else
      if command -v skopeo >/dev/null 2>&1; then
        log INFO "Canal requested; attempting to mirror hardened-flannel from Docker Hub"
        if ! cache_hardened_flannel_skopeo "${HARDENED_FLANNEL_TAG:-}"; then
          log ERROR "Failed to mirror hardened-flannel required for spec.cni=canal"
          popd >/dev/null || true
          return 7
        fi
      else
        log ERROR "Canal requested but skopeo is not available to mirror hardened-flannel"
        log ERROR "Remediation: install skopeo and re-run image action, or pre-stage $HARDENED_FLANNEL_BN in $DOWNLOADS_DIR"
        popd >/dev/null || true
        return 7
      fi
    fi
  fi

  # Verify checksums when possible (strict: fail on mismatch or missing entries)
  if command -v sha256sum >/dev/null 2>&1; then
    if grep -q "$IMAGES_TAR" "$SHA256_FILE" 2>/dev/null; then
      if ! (grep "$IMAGES_TAR"  "$SHA256_FILE" | sha256sum -c - >>"$LOG_FILE" 2>&1); then
        log ERROR "Checksum verification failed for $IMAGES_TAR; aborting"
        popd >/dev/null || true
        return 2
      fi
    else
      log ERROR "Checksum entry for $IMAGES_TAR not found in $SHA256_FILE; aborting"
      popd >/dev/null || true
      return 2
    fi

    if grep -q "$RKE2_TARBALL" "$SHA256_FILE" 2>/dev/null; then
      if ! (grep "$RKE2_TARBALL" "$SHA256_FILE" | sha256sum -c - >>"$LOG_FILE" 2>&1); then
        log ERROR "Checksum verification failed for $RKE2_TARBALL; aborting"
        popd >/dev/null || true
        return 3
      fi
    else
      log WARN "Checksum entry for $RKE2_TARBALL not found in $SHA256_FILE; continuing but installer may attempt network access"
    fi
  fi

  # Reconcile chart-referenced images from the RKE2 tarball against the
  # downloaded images bundle and cache supplemental archives for anything
  # missing from the base bundle.
  if ! reconcile_chart_images_against_downloaded_bundle "$BASE_URL" "$SHA256_FILE"; then
    log ERROR "Chart image reconciliation failed"
    popd >/dev/null || true
    return 5
  fi

  popd >/dev/null

  # --- Stage artifacts for offline install -----------------------------------
  local IMAGES_DIR="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"
  mkdir -p "$IMAGES_DIR"
  if [[ -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
    local tmpimg="$IMAGES_DIR/.tmp-${IMAGES_TAR}.$$"
    cp -f "$DOWNLOADS_DIR/$IMAGES_TAR" "$tmpimg"
    mv -T "$tmpimg" "$IMAGES_DIR/$IMAGES_TAR"
    log INFO "Staged ${IMAGES_TAR} into $IMAGES_DIR/"
  fi

  # Stage any supplemental chart-image archives downloaded during
  # reconciliation for the current run only (based on current missing list).
  local missing_manifest="$DOWNLOADS_DIR/chart-images-missing.linux-${ARCH}.txt"
  if [[ -s "$missing_manifest" ]]; then
    while IFS= read -r missing_ref; do
      [[ -z "$missing_ref" ]] && continue
      local safe supplemental_bn supplemental
      safe=$(echo "$missing_ref" | sed -E 's#[/:@]#_#g')
      supplemental_bn="rke2-images-missing-${safe}.tar"
      supplemental="$DOWNLOADS_DIR/$supplemental_bn"
      [[ -f "$supplemental" ]] || continue

      local tmp_sup_img="$IMAGES_DIR/.tmp-${supplemental_bn}.$$"
      cp -f "$supplemental" "$tmp_sup_img"
      mv -T "$tmp_sup_img" "$IMAGES_DIR/$supplemental_bn"
      log INFO "Staged supplemental image archive $supplemental_bn into $IMAGES_DIR"

      local tmp_sup_stage="$STAGE_DIR/.tmp-${supplemental_bn}.$$"
      cp -f "$supplemental" "$tmp_sup_stage"
      mv -T "$tmp_sup_stage" "$STAGE_DIR/$supplemental_bn"
      log INFO "Staged supplemental image archive $supplemental_bn into $STAGE_DIR"
    done < "$missing_manifest"
  fi

  mkdir -p "$STAGE_DIR"
  # Stage selected artifacts. We'll stage the rke2 tarball and a filtered
  # checksum manifest that contains only tarball entries that were actually
  # staged/cached (images tarball(s) and RKE2 tarball). This avoids shipping
  # a manifest containing many unrelated files.
  if [[ -f "$DOWNLOADS_DIR/$RKE2_TARBALL" ]]; then
    local tmpf="$STAGE_DIR/.tmp-${RKE2_TARBALL}.$$"
    cp -f "$DOWNLOADS_DIR/$RKE2_TARBALL" "$tmpf"
    mv -T "$tmpf" "$STAGE_DIR/$RKE2_TARBALL"
    log INFO "Staged $RKE2_TARBALL into $STAGE_DIR"
  fi

  # Stage hardened-cni-plugins tarball if present in downloads
  if [[ -n "${HARDENED_CNI_BN:-}" && -f "$DOWNLOADS_DIR/$HARDENED_CNI_BN" ]]; then
    local tmpc="$STAGE_DIR/.tmp-${HARDENED_CNI_BN}.$$"
    cp -f "$DOWNLOADS_DIR/$HARDENED_CNI_BN" "$tmpc"
    mv -T "$tmpc" "$STAGE_DIR/$HARDENED_CNI_BN"
    log INFO "Staged $HARDENED_CNI_BN into $STAGE_DIR"

    local tmpc_img="$IMAGES_DIR/.tmp-${HARDENED_CNI_BN}.$$"
    cp -f "$DOWNLOADS_DIR/$HARDENED_CNI_BN" "$tmpc_img"
    mv -T "$tmpc_img" "$IMAGES_DIR/$HARDENED_CNI_BN"
    log INFO "Staged $HARDENED_CNI_BN into $IMAGES_DIR"
  fi

  # Ensure golden-image-friendly layout: extract CNI binaries and any
  # available /etc/cni/net.d config snippets into the stage tree so image
  # builders can bake them into VM templates. This makes the golden image
  # immediately usable offline (Multus/Canal find master conflists & binaries).
  ensure_cni_binaries_baked() {
    local archive dest_root
    dest_root="$STAGE_DIR"
    local IMAGES_DIR="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"
    mkdir -p "$dest_root/opt/cni/bin" "$dest_root/etc/cni/net.d" || true

    for archive in "$DOWNLOADS_DIR/$HARDENED_CNI_BN" "$DOWNLOADS_DIR/$HARDENED_MULTUS_BN" "$DOWNLOADS_DIR/$HARDENED_FLANNEL_BN" "$STAGE_DIR/$HARDENED_CNI_BN" "$STAGE_DIR/$HARDENED_MULTUS_BN" "$STAGE_DIR/$HARDENED_FLANNEL_BN"; do
      [[ -f "$archive" ]] || continue
      local tmpd
      tmpd=$(mktemp -d) || tmpd="/tmp/.rke2nodeinit-extract-$$"
      # Extract docker-archive contents into tempdir
      if ! tar -xf "$archive" -C "$tmpd" 2>/dev/null; then
        rm -rf "$tmpd" || true
        continue
      fi
      # Find layer tars and inspect for opt/cni and etc/cni/net.d
      shopt -s nullglob
      for lt in "$tmpd"/*.tar; do
        mkdir -p "$tmpd/layer"
        tar -xf "$lt" -C "$tmpd/layer" 2>/dev/null || true
        if [[ -d "$tmpd/layer/opt/cni/bin" ]]; then
          mkdir -p "$dest_root/opt/cni/bin"
          cp -a "$tmpd/layer/opt/cni/bin/." "$dest_root/opt/cni/bin/" 2>/dev/null || true
        fi
        if [[ -d "$tmpd/layer/etc/cni/net.d" ]]; then
          mkdir -p "$dest_root/etc/cni/net.d"
          cp -a "$tmpd/layer/etc/cni/net.d/." "$dest_root/etc/cni/net.d/" 2>/dev/null || true
        fi
        rm -rf "$tmpd/layer"/* || true
      done
      shopt -u nullglob
      rm -rf "$tmpd" || true
    done

    # If a canal conflist was generated in the agent images staging area,
    # prefer that copy so golden image contains a ready-to-use master CNI
    # config. The script may also have staged a 10-canal.conflist previously.
    if [[ -f "$IMAGES_DIR/10-canal.conflist" ]]; then
      mkdir -p "$STAGE_DIR/etc/cni/net.d"
      cp -a "$IMAGES_DIR/10-canal.conflist" "$STAGE_DIR/etc/cni/net.d/10-canal.conflist" || true
    elif [[ -f "$DOWNLOADS_DIR/10-canal.conflist" ]]; then
      mkdir -p "$STAGE_DIR/etc/cni/net.d"
      cp -a "$DOWNLOADS_DIR/10-canal.conflist" "$STAGE_DIR/etc/cni/net.d/10-canal.conflist" || true
    fi
    log INFO "Prepared $STAGE_DIR with CNI binaries and net.d snippets for baking into golden image"
  }

  # Run the bake step (best-effort)
  ensure_cni_binaries_baked || true

  if [[ -n "${HARDENED_MULTUS_BN:-}" && -f "$DOWNLOADS_DIR/$HARDENED_MULTUS_BN" ]]; then
    local tmpm="$STAGE_DIR/.tmp-${HARDENED_MULTUS_BN}.$$"
    cp -f "$DOWNLOADS_DIR/$HARDENED_MULTUS_BN" "$tmpm"
    mv -T "$tmpm" "$STAGE_DIR/$HARDENED_MULTUS_BN"
    log INFO "Staged $HARDENED_MULTUS_BN into $STAGE_DIR"

    local tmpm_img="$IMAGES_DIR/.tmp-${HARDENED_MULTUS_BN}.$$"
    cp -f "$DOWNLOADS_DIR/$HARDENED_MULTUS_BN" "$tmpm_img"
    mv -T "$tmpm_img" "$IMAGES_DIR/$HARDENED_MULTUS_BN"
    log INFO "Staged $HARDENED_MULTUS_BN into $IMAGES_DIR"
  fi

  if [[ -n "${HARDENED_FLANNEL_BN:-}" && -f "$DOWNLOADS_DIR/$HARDENED_FLANNEL_BN" ]]; then
    local tmpf="$STAGE_DIR/.tmp-${HARDENED_FLANNEL_BN}.$$"
    cp -f "$DOWNLOADS_DIR/$HARDENED_FLANNEL_BN" "$tmpf"
    mv -T "$tmpf" "$STAGE_DIR/$HARDENED_FLANNEL_BN"
    log INFO "Staged $HARDENED_FLANNEL_BN into $STAGE_DIR"

    local tmpf_img="$IMAGES_DIR/.tmp-${HARDENED_FLANNEL_BN}.$$"
    cp -f "$DOWNLOADS_DIR/$HARDENED_FLANNEL_BN" "$tmpf_img"
    mv -T "$tmpf_img" "$IMAGES_DIR/$HARDENED_FLANNEL_BN"
    log INFO "Staged $HARDENED_FLANNEL_BN into $IMAGES_DIR"
  fi

  # Build a filtered sha256 manifest containing only staged/cached tarballs.
  if [[ -f "$DOWNLOADS_DIR/$SHA256_FILE" ]]; then
    local out_manifest="$STAGE_DIR/$SHA256_FILE"
    : > "$out_manifest"
    # Iterate over each line in the downloaded manifest and include only
    # entries whose basename is a tar archive and which exist in the
    # staging or images directories. Also produce a JSON metadata file
    # describing included files (name, sha256, size, location).
    local tmp_json="$STAGE_DIR/.tmp-sha-manifest-$$.json"
    : > "$tmp_json"
    local first=1
    while read -r h fn; do
      # skip empty lines
      [[ -z "${h:-}" || -z "${fn:-}" ]] && continue
      bn=$(basename "${fn}")
      # consider common tarball suffixes
      if [[ "${bn}" =~ \.(tar|tar\.gz|tar\.zst|tgz)$ ]]; then
        # prefer stage, then images, then downloads when selecting path
        if [[ -f "$STAGE_DIR/$bn" ]]; then
          chosen_path="$STAGE_DIR/$bn"
          location="stage"
        elif [[ -f "$IMAGES_DIR/$bn" ]]; then
          chosen_path="$IMAGES_DIR/$bn"
          location="images"
        elif [[ -f "$DOWNLOADS_DIR/$bn" ]]; then
          chosen_path="$DOWNLOADS_DIR/$bn"
          location="downloads"
        else
          chosen_path=""
          location="missing"
        fi

        if [[ -n "$chosen_path" ]]; then
          # write manifest line using basename (common usage expects basename)
          printf '%s  %s\n' "$h" "$bn" >> "$out_manifest"

          # compute actual sha and size for JSON metadata (fallback to h if sha256sum fails)
          fsha=$(sha256sum "$chosen_path" 2>/dev/null | awk '{print $1}' || true)
          if [[ -z "$fsha" ]]; then
            fsha="$h"
          fi
          fsize=$(stat -c%s "$chosen_path" 2>/dev/null || echo 0)

          # append JSON entry
          if [[ $first -eq 1 ]]; then
            printf '  {"name":"%s","sha256":"%s","size":%s,"location":"%s"}\n' "$bn" "$fsha" "$fsize" "$location" >> "$tmp_json"
            first=0
          else
            printf ',\n  {"name":"%s","sha256":"%s","size":%s,"location":"%s"}\n' "$bn" "$fsha" "$fsize" "$location" >> "$tmp_json"
          fi
        fi
      fi
    done < "$DOWNLOADS_DIR/$SHA256_FILE"

    # Add additional operational artifacts to metadata so SBOM verification
    # can resolve path-specific checksums (including duplicate basenames across
    # downloads/stage paths). We intentionally do not append these to the
    # traditional sha256sum text manifest because duplicate basenames can make
    # line-based verification ambiguous.
    for extra in \
      "$DOWNLOADS_DIR/install.sh|downloads" \
      "$DOWNLOADS_DIR/$SHA256_FILE|downloads" \
      "$STAGE_DIR/$SHA256_FILE|stage" \
      "$STAGE_DIR/sha256sum-${ARCH}.json|stage"
    do
      epath="${extra%%|*}"
      eloc="${extra##*|}"
      [[ -f "$epath" ]] || continue
      ebn="$(basename "$epath")"
      esha="$(sha256sum "$epath" 2>/dev/null | awk '{print $1}' || true)"
      [[ -n "$esha" ]] || continue
      esize="$(stat -c%s "$epath" 2>/dev/null || echo 0)"
      if [[ $first -eq 1 ]]; then
        printf '  {"name":"%s","sha256":"%s","size":%s,"location":"%s"}\n' "$ebn" "$esha" "$esize" "$eloc" >> "$tmp_json"
        first=0
      else
        printf ',\n  {"name":"%s","sha256":"%s","size":%s,"location":"%s"}\n' "$ebn" "$esha" "$esize" "$eloc" >> "$tmp_json"
      fi
    done

    # Wrap JSON entries into a structured object with metadata
    local out_json="$STAGE_DIR/sha256sum-${ARCH}.json"
    {
      echo "{"
      echo "  \"generated_at\": \"$(date -u +%FT%TZ)\"," 
      echo "  \"arch\": \"${ARCH}\"," 
      echo "  \"manifest_file\": \"${SHA256_FILE}\"," 
      echo "  \"files\": ["
      cat "$tmp_json" || true
      echo "  ]"
      echo "}"
    } > "$out_json"
    rm -f "$tmp_json" || true
    log INFO "Wrote filtered checksum manifest to $out_manifest and metadata to $out_json"
  fi

  # Stage custom-CA helper if present in downloads
  if [[ -f "$DOWNLOADS_DIR/generate-custom-ca-certs.sh" ]]; then
    cp -f "$DOWNLOADS_DIR/generate-custom-ca-certs.sh" "$STAGE_DIR/generate-custom-ca-certs.sh" || true
    chmod +x "$STAGE_DIR/generate-custom-ca-certs.sh" || true
    log INFO "Staged custom-CA helper into $STAGE_DIR."
  fi
}

# ------------------------------------------------------------------------------
# Function: ca_trust_registries
# Purpose : Install custom registry CA certificates into the OS trust store and
#           update the bundle so nerdctl and RKE2 trust the private registry.
# Arguments:
#   $1 - Path to CA certificate
# Returns :
#   Returns 0 on success.
# ------------------------------------------------------------------------------
ca_trust_registries() {
  # --- Optional: CA trust + registries mirrors -------------------------------
  local CA_BN=""
  if [[ -n "$CA_ROOT" && -f "$CA_ROOT" ]]; then
    CA_BN="$(basename "$CA_ROOT")"
    if [[ "$CA_INSTALL" =~ ^([Tt]rue|1|yes|Y)$ ]]; then
      mkdir -p /usr/local/share/ca-certificates
      cp -f "$CA_ROOT" "/usr/local/share/ca-certificates/$CA_BN"
      update-ca-certificates >>"$LOG_FILE" 2>&1 || true
      log INFO "Installed $CA_BN into OS trust store."
    fi
    # Persist to site defaults for server phase
    local STATE="/etc/rke2image.defaults"
    {
      echo "CUSTOM_CA_ROOT_CRT=\"$CA_ROOT\""
      [[ -n "$CA_KEY"    ]] && echo "CUSTOM_CA_ROOT_KEY=\"$CA_KEY\""
      [[ -n "$CA_INTCRT" ]] && echo "CUSTOM_CA_INT_CRT=\"$CA_INTCRT\""
      [[ -n "$CA_INTKEY" ]] && echo "CUSTOM_CA_INT_KEY=\"$CA_INTKEY\""
      if [[ "$CA_INSTALL" =~ ^([Tt]rue|1|yes|Y)$ ]]; then
        echo "CUSTOM_CA_INSTALL_TO_OS_TRUST=1"
      else
        echo "CUSTOM_CA_INSTALL_TO_OS_TRUST=0"
      fi
    } >> "$STATE"
    chmod 600 "$STATE"
  fi

  # If a registry is configured, write registries.yaml with mirrors + auth + CA
  mkdir -p /etc/rancher/rke2
  if [[ -n "$REG_HOST" ]]; then
    local _REG_HOST="${REG_HOST:-}" _REG_NS=""
    if [[ -n "${REGISTRY:-}" ]]; then
      _REG_HOST="${REGISTRY%%/*}"
      [[ "$REGISTRY" == */* ]] && _REG_NS="${REGISTRY#*/}"
    fi
    write_registries_yaml_with_fallbacks "$_REG_HOST" "$_REG_NS" "$REG_USER" "$REG_PASS" "/usr/local/share/ca-certificates/${CA_BN:-}"
  else
    rm -f /etc/rancher/rke2/registries.yaml 2>/dev/null || true
  fi
  : > /etc/rancher/rke2/config.yaml
}

# ----------------------------------------------------------------------------
# Function: stage_from_artifact_path
# Purpose : Stage RKE2 artifacts from a local artifact path when
#           INSTALL_RKE2_ARTIFACT_PATH is set. Strict checksum verification
#           is performed. Files are not overwritten silently; operator must
#           delete existing mismatched files manually.
# Arguments:
#   $1 - Path to artifacts (INSTALL_RKE2_ARTIFACT_PATH)
# Returns :
#   0 on success, non-zero on verification or staging error
# ----------------------------------------------------------------------------
stage_from_artifact_path() {
  set -euo pipefail
  local ART_PATH="$1"
  local ARCH="${ARCH:-$(uname -m)}"
  # normalize ARCH to expected values (amd64/arm64)
  case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ; SUFFIX="linux-amd64" ;;
    aarch64|arm64) ARCH="arm64" ; SUFFIX="linux-arm64" ;;
    *) log ERROR "Unsupported architecture: $ARCH" ; return 1 ;;
  esac

  local IMAGES_DIR="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"
  local STAGE_DIR="${STAGE_DIR:-/opt/rke2/stage}"
  mkdir -p "$IMAGES_DIR" "$STAGE_DIR"

  # Find checksum file
  local SHA_FILE="${ART_PATH}/sha256sum-${ARCH}.txt"
  if [[ -f "$SHA_FILE" ]]; then
    log INFO "Found checksum file: $SHA_FILE"
  else
    log ERROR "Checksum file sha256sum-${ARCH}.txt not found in $ART_PATH; strict mode requires it"
    return 2
  fi

  # Helper to check checksum for a single file (must exist in ART_PATH)
  verify_checksum_for() {
    local fname="$1"
    if ! grep -q "$(basename "$fname")" "$SHA_FILE" 2>/dev/null; then
      log ERROR "No checksum entry for $(basename "$fname") in $SHA_FILE"
      return 3
    fi
    (cd "$ART_PATH" && grep "$(basename "$fname")" "$SHA_FILE" | sha256sum -c -) >>"$LOG_FILE" 2>&1 || return 4
    return 0
  }

  # Determine image tar candidates (prefer zst, commit suffix optional)
  local IMAGES_ZST="${ART_PATH}/rke2-images.${SUFFIX}.tar.zst"
  local IMAGES_GZ="${ART_PATH}/rke2-images.${SUFFIX}.tar.gz"
  # also accept commit-suffixed variants if present
  if [[ -n "${INSTALL_RKE2_COMMIT:-}" ]]; then
    IMAGES_ZST="${ART_PATH}/rke2-images.${SUFFIX}-${INSTALL_RKE2_COMMIT}.tar.zst"
    IMAGES_GZ="${ART_PATH}/rke2-images.${SUFFIX}-${INSTALL_RKE2_COMMIT}.tar.gz"
  fi

  local selected_image_tar=""
  if [[ -f "$IMAGES_ZST" ]]; then
    selected_image_tar="$IMAGES_ZST"
  elif [[ -f "$IMAGES_GZ" ]]; then
    selected_image_tar="$IMAGES_GZ"
  else
    # try un-suffixed search for any rke2-images-* bundles
    local extra
    extra=$(find "$ART_PATH" -maxdepth 1 -type f -name "rke2-images-*${SUFFIX}*" | sort)
    if [[ -n "$extra" ]]; then
      # pick first as the primary image bundle
      selected_image_tar="$(echo "$extra" | head -n1)"
    fi
  fi

  if [[ -z "$selected_image_tar" ]]; then
    log ERROR "No rke2-images tarball found in $ART_PATH"
    return 5
  fi

  log INFO "Selected image tar: $(basename "$selected_image_tar")"

  # Verify checksum for selected image tar and rke2 tarball and install.sh if present
  local RKE2_TARBALL="${ART_PATH}/rke2.${SUFFIX}.tar.gz"
  local INSTALL_SH="${ART_PATH}/install.sh"

  verify_checksum_for "$selected_image_tar" || { log ERROR "Image checksum verification failed"; return 6; }
  if [[ -f "$RKE2_TARBALL" ]]; then
    verify_checksum_for "$RKE2_TARBALL" || { log ERROR "RKE2 tarball checksum verification failed"; return 7; }
  else
    log WARN "rke2.${SUFFIX}.tar.gz not present in artifact path; installer may attempt network download unless install.sh also present in stage"
  fi
  if [[ -f "$INSTALL_SH" ]]; then
    # no checksum expected for install.sh but ensure it's present
    log INFO "Found local install.sh; will stage it into $STAGE_DIR"
  fi

  # Before moving, check for existing target file and avoid overwrite
  local target_images_name="$(basename "$selected_image_tar")"
  local target_images_path="$IMAGES_DIR/$target_images_name"
  if [[ -f "$target_images_path" ]]; then
    # verify existing file matches checksum; if not, do NOT overwrite
    (cd "$IMAGES_DIR" && sha256sum "$target_images_name" | awk '{print $1}') >/tmp/existing.sum 2>/dev/null || true
    local existing_sum
    existing_sum=$(awk '{print $1}' /tmp/existing.sum 2>/dev/null || true)
    local expected_sum
    expected_sum=$(grep "$(basename "$selected_image_tar")" "$SHA_FILE" | awk '{print $1}' 2>/dev/null || true)
    if [[ -n "$existing_sum" && "$existing_sum" == "$expected_sum" ]]; then
      log INFO "Target image $target_images_path already present and checksum matches; skipping move."
    else
      log ERROR "Target image $target_images_path already exists and checksum does not match expected value. Will NOT overwrite. Please delete the file and re-run."
      return 8
    fi
  else
    # atomic copy then move
    local tmp_dest
    tmp_dest="$IMAGES_DIR/.tmp-$(basename "$selected_image_tar").$$"
    cp -f "$selected_image_tar" "$tmp_dest"
    mv -T "$tmp_dest" "$target_images_path"
    log INFO "Moved $(basename "$selected_image_tar") -> $target_images_path"
  fi

  # Stage additional rke2-images-* bundles
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    local bn
    bn=$(basename "$f")
    if [[ -f "$IMAGES_DIR/$bn" ]]; then
      log INFO "Additional image bundle $bn already exists in $IMAGES_DIR; skipping"
      continue
    fi
    cp -f "$f" "$IMAGES_DIR/"
    log INFO "Staged additional image bundle $bn into $IMAGES_DIR"
  done < <(find "$ART_PATH" -maxdepth 1 -type f -name "rke2-images-*${SUFFIX}*" ! -name "$(basename "$selected_image_tar")" | sort)

  # Stage rke2 tarball and install.sh into STAGE_DIR (do not overwrite existing mismatching files)
  if [[ -f "$RKE2_TARBALL" ]]; then
    local bn_rke2
    bn_rke2=$(basename "$RKE2_TARBALL")
    if [[ -f "$STAGE_DIR/$bn_rke2" ]]; then
      # verify checksum
      local existing
      existing=$(sha256sum "$STAGE_DIR/$bn_rke2" | awk '{print $1}' 2>/dev/null || true)
      local expected
      expected=$(grep "${bn_rke2}" "$SHA_FILE" | awk '{print $1}' 2>/dev/null || true)
      if [[ -n "$existing" && "$existing" == "$expected" ]]; then
        log INFO "RKE2 tarball already staged and checksum matches; skipping"
      else
        log ERROR "RKE2 tarball already exists at $STAGE_DIR/$bn_rke2 and does not match checksum; will NOT overwrite. Please remove it to proceed."
        return 9
      fi
    else
      cp -f "$RKE2_TARBALL" "$STAGE_DIR/"
      log INFO "Staged $bn_rke2 into $STAGE_DIR"
    fi
  fi

  if [[ -f "$INSTALL_SH" ]]; then
    if [[ -f "$STAGE_DIR/install.sh" ]]; then
      # if already present, do not overwrite
      log INFO "install.sh already exists in $STAGE_DIR; leaving in place"
    else
      cp -f "$INSTALL_SH" "$STAGE_DIR/install.sh"
      chmod 0755 "$STAGE_DIR/install.sh" || true
      log INFO "Staged install.sh into $STAGE_DIR/install.sh"
    fi
  fi

  # Finally, ensure environment points to stage dir for installer
  export INSTALL_RKE2_ARTIFACT_PATH="$STAGE_DIR"
  log INFO "Set INSTALL_RKE2_ARTIFACT_PATH=$STAGE_DIR for installer"

  return 0
}


# ------------------------------------------------------------------------------
# Function: install_nerdctl
# Purpose : Install the nerdctl runtime bundle (standalone or full) depending on
#           host state, ensuring containerd and supporting binaries are present.
# Arguments:
#   $1 - Installation mode (standalone or full)
# Returns :
#   Returns 0 on success.
# ------------------------------------------------------------------------------
install_nerdctl() {
  # --- Detect/cache nerdctl: FULL (cache only) + standalone (install) --------
  ensure_installed curl
  ensure_installed ca-certificates
  local api="https://api.github.com/repos/containerd/nerdctl/releases/latest"
  local ntag nver full_tgz std_tgz full_url std_url
  ntag="$(curl -fsSL "$api" | grep -Po '"tag_name":\s*"\K[^"]+' || true)"
  if [[ -n "$ntag" ]]; then
    nver="${ntag#v}"
    full_tgz="nerdctl-full-${nver}-linux-${ARCH}.tar.gz"
    std_tgz="nerdctl-${nver}-linux-${ARCH}.tar.gz"
    full_url="https://github.com/containerd/nerdctl/releases/download/${ntag}/${full_tgz}"
    std_url="https://github.com/containerd/nerdctl/releases/download/${ntag}/${std_tgz}"
    mkdir -p "$DOWNLOADS_DIR"
    # Cache FULL bundle
    if [[ ! -f "$DOWNLOADS_DIR/$full_tgz" ]]; then
      spinner_run "Caching nerdctl FULL ${ntag}" curl -Lf "$full_url" -o "$DOWNLOADS_DIR/$full_tgz"
      log INFO "Cached $(basename "$DOWNLOADS_DIR/$full_tgz")"
    else
      log INFO "nerdctl FULL already cached: $(basename "$DOWNLOADS_DIR/$full_tgz")"
    fi
    # Cache standalone tarball
    if [[ ! -f "$DOWNLOADS_DIR/$std_tgz" ]]; then
      spinner_run "Caching nerdctl standalone ${ntag}" curl -Lf "$std_url" -o "$DOWNLOADS_DIR/$std_tgz"
      log INFO "Cached $(basename "$DOWNLOADS_DIR/$std_tgz")"
    else
      log INFO "nerdctl standalone already cached: $(basename "$DOWNLOADS_DIR/$std_tgz")"
    fi
    NERDCTL_FULL_TGZ="$full_tgz"
    NERDCTL_STD_TGZ="$std_tgz"
    # Install ONLY the standalone nerdctl binary
    if [[ -f "$DOWNLOADS_DIR/$std_tgz" ]]; then
      tmpdir="$(mktemp -d)"
      tar -C "$tmpdir" -xzf "$DOWNLOADS_DIR/$std_tgz"
      # tar contains 'nerdctl'
      if [[ -f "$tmpdir/nerdctl" ]]; then
        install -m 0755 "$tmpdir/nerdctl" /usr/local/bin/nerdctl
        log INFO "Installed standalone nerdctl to /usr/local/bin/nerdctl"
      else
        # Fallback: look for nested path
        found="$(find "$tmpdir" -type f -name nerdctl | head -n1 || true)"
        if [[ -n "$found" ]]; then
          install -m 0755 "$found" /usr/local/bin/nerdctl
          log INFO "Installed standalone nerdctl from archive path to /usr/local/bin/nerdctl"
        else
          log WARN "nerdctl binary not found in $std_tgz; skipping install"
        fi
      fi
      rm -rf "$tmpdir"
    fi
  else
    log WARN "Could not detect nerdctl latest release via GitHub API."
  fi

  # If detection failed (offline) but cached bundles exist, record their names.
  if [[ -z "$NERDCTL_FULL_TGZ" && -d "$DOWNLOADS_DIR" ]]; then
    NERDCTL_FULL_TGZ="$(find "$DOWNLOADS_DIR" -maxdepth 1 -type f -name "nerdctl-full-*-linux-${ARCH}.tar.gz" -printf '%f\n' | sort | tail -n1)"
  fi
  if [[ -z "$NERDCTL_STD_TGZ" && -d "$DOWNLOADS_DIR" ]]; then
    NERDCTL_STD_TGZ="$(find "$DOWNLOADS_DIR" -maxdepth 1 -type f -name "nerdctl-*-linux-${ARCH}.tar.gz" ! -name 'nerdctl-full-*' -printf '%f\n' | sort | tail -n1)"
  fi
}

# ------------------------------------------------------------------------------
# Function: prompt_reboot
# Purpose : Ask the operator whether to reboot immediately unless auto-approve
#           (-y) is in effect. Used after image/server/agent workflows.
# Arguments:
#   None
# Returns :
#   Initiates reboot when approved; otherwise returns 0.
# ------------------------------------------------------------------------------
prompt_reboot() {
  echo
  # Skip reboot in dry-run mode
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    log_info "DRY-RUN: Reboot skipped (would normally reboot now)"
    log_info "In production, the system would reboot to apply changes"
    return 0
  fi
  
  if (( AUTO_YES )); then
    log WARN "Auto-confirm enabled (-y). Rebooting now..."
    sleep 2
    reboot
  else
    read -r -p "Reboot now? [y/N]: " _ans
    case "${_ans,,}" in
      y|yes)
        log WARN "Rebooting..."
        sleep 2
        reboot
        ;;
      *)
        log INFO "Reboot deferred. Remember to reboot before installing RKE2."
        ;;
    esac
  fi
}

# ------------------------------------------------------------------------------
# Function: prompt_shutdown
# Purpose : Ask the operator whether to shutdown immediately for VM template
#           preparation. Used when boot service is enabled in image action.
# Arguments:
#   None
# Returns :
#   Initiates shutdown when approved; otherwise returns 0.
# ------------------------------------------------------------------------------
prompt_shutdown() {
  echo
  # Skip shutdown in dry-run mode
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    log_info "DRY-RUN: Shutdown skipped (would normally shutdown now)"
    log_info "In production, the system would shutdown for template preparation"
    return 0
  fi
  
  if (( AUTO_YES )); then
    log WARN "Auto-confirm enabled (-y). Shutting down now..."
    log_info "Template VM is ready for cloning after shutdown completes"
    sleep 2
    shutdown -h now
  else
    read -r -p "Shutdown now to prepare template? [y/N]: " _ans
    case "${_ans,,}" in
      y|yes)
        log WARN "Shutting down..."
        log_info "Template VM will be ready for cloning after shutdown"
        sleep 2
        shutdown -h now
        ;;
      *)
        log INFO "Shutdown deferred. Shutdown and clone this VM when ready."
        log_info "Boot service will auto-initialize cloned VMs on first boot."
        ;;
    esac
  fi
}

install_flannel_txcsum_fix() {
  set -euo pipefail

  log INFO "Installing flannel TX checksum offload fix (ethtool + systemd service)."
  if ! command -v ethtool >/dev/null 2>&1 && [[ -x /usr/bin/apt-get ]]; then
    log WARM "ethtool not installed. Please re-run Image."
	exit 2
  else
    log INFO "Creating ethtool helper script."
    cat >/etc/systemd/system/ethtool-patch-flannel.1-checksum.service <<'EOF'
[Unit]
Description=Turn off checkdum on flannel.1
After=sys-subsystem-net-devices-flannel.1.device
[Install]
WantedBy=sys-subsystem-net-devices-flannel.1.device
[Service]
Type=oneshot
ExecStart=/usr/sbin/ethtool -K flannel.1 tx-checksum-ip-generic off
EOF

    log INFO "Enabling ethtool helper service."
    systemctl enable ethtool-patch-flannel.1-checksum.service 2>&1 || true

  fi
}

# ================================================================================================
# ACTIONS
# ================================================================================================

# ==================
# Action: PUSH
# ------------------------------------------------------------------------------
# Function: action_push
# Purpose : Handle the push workflow: load cached images, retag them for the
#           private registry, optionally generate SBOM data, and push via nerdctl.
# Arguments:
#   None (uses globals derived from CLI/YAML)
# Returns :
#   Exits on failure of any stage.
# ------------------------------------------------------------------------------
#=============================================================================
# Function: action_push
# Description: Push container images to private registry with metrics tracking
# Parameters:
#   None (reads from CONFIG_FILE or CLI flags)
# Returns: 
#   0 - Success (all images pushed or dry-run)
#   1 - Dependency or login failure
#   3 - Images archive not found
# Usage: action_push -f <config.yaml> or action_push -r registry -u user -p pass
# Dependencies: metrics_init, metrics_increment, metrics_summary, report_progress,
#               validate_file_exists, log_info, log_success, log_error
# Changes from Original:
#   - Added metrics tracking for image operations
#   - Added progress reporting for batch operations
#   - Enhanced validation with remediation steps
#   - Improved error messages and logging structure
#=============================================================================
action_push() {
  initialize_action_context false "push"

  log_info "Starting image push operation"
  
  # Load configuration from YAML if provided
  if [[ -n "$CONFIG_FILE" ]]; then
    REGISTRY="$(yaml_spec_get "$CONFIG_FILE" registry || echo "$REGISTRY")"
    REG_USER="$(yaml_spec_get "$CONFIG_FILE" registryUsername || echo "$REG_USER")"
    REG_PASS="$(yaml_spec_get "$CONFIG_FILE" registryPassword || echo "$REG_PASS")"
    log_warn "Using YAML configuration values (CLI flags may be overridden)"
  fi

  # Validate credentials
  warn_default_credentials "$REGISTRY" "$REG_USER" "$REG_PASS"
  
  if ! validate_non_empty "${REGISTRY:-}" "REGISTRY"; then
    log_error "Registry URL not specified"
    log_error "Remediation: Provide registry via -r flag or in YAML config"
    log_error "Example: $0 push -r registry.example.com -u user -p pass"
    exit 1
  fi

  # Check dependencies
  if ! check_dependencies zstd; then
    log_warn "Missing required dependency: zstd"
    install_dependencies_interactive zstd || exit 1
  fi

  # Validate images archive exists
  local work="$DOWNLOADS_DIR"
  if ! validate_file_exists "$work/$IMAGES_TAR" "images archive"; then
    log_error "Images archive not found: $work/$IMAGES_TAR"
    log_error "Remediation steps:"
    log_error "  1. Run image action first: $0 image -f config.yaml"
    log_error "  2. Verify downloads directory: $work"
    log_error "  3. Check for disk space issues"
    exit 3
  fi

  # Initialize metrics for tracking
  metrics_init "push_operation"
  
  log_info "Loading images from archive: $work/$IMAGES_TAR"
  report_progress "Loading images into nerdctl" 1 4
  
  if ! zstdcat "$work/$IMAGES_TAR" | nerdctl -n k8s.io load >>"$LOG_FILE" 2>&1; then
    log_error "Failed to load images from archive"
    log_error "Check log file for details: $LOG_FILE"
    exit 1
  fi
  metrics_increment "images_loaded"

  # Get list of loaded images
  local -a imgs
  mapfile -t imgs < <(nerdctl -n k8s.io images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | sort -u)
  
  local img_count=${#imgs[@]}
  log_info "Found $img_count images to process"
  metrics_increment "total" "$img_count"

  # Parse registry host and namespace
  local REG_HOST="$REGISTRY" REG_NS=""
  [[ "$REGISTRY" == *"/"* ]] && { REG_HOST="${REGISTRY%%/*}"; REG_NS="${REGISTRY#*/}"; }
  log_info "Target registry: $REG_HOST" 
  [[ -n "$REG_NS" ]] && log_info "Target namespace: $REG_NS"

  # Generate manifest files
  report_progress "Generating push manifest" 2 4
  local manifest_json="$OUT_DIR/images-manifest.json"
  local manifest_txt="$OUT_DIR/images-manifest.txt"
  : > "$manifest_txt"
  echo "[" > "$manifest_json"
  local first=1

  for IMG in "${imgs[@]}"; do
    [[ -z "$IMG" ]] && continue
    local TARGET
    # Canonicalize image reference so images without an explicit registry are treated as docker.io/
    local src_ref="$IMG"
    local src_repo="${IMG%:*}"
    local src_tag="${IMG##*:}"
    local first_seg="${src_repo%%/*}"
    local canon_repo="$src_repo"
    if [[ "$src_repo" != */* ]]; then
      canon_repo="docker.io/$src_repo"
    elif [[ "$first_seg" != *.* && "$first_seg" != *:* ]]; then
      canon_repo="docker.io/$src_repo"
    fi
    local canon_img="${canon_repo}:${src_tag}"
    if [[ -n "$REG_NS" ]]; then TARGET="$REG_HOST/$REG_NS/$canon_img"; else TARGET="$REG_HOST/$canon_img"; fi

    [[ $first -eq 0 ]] && echo "," >> "$manifest_json"
    printf '  {"source":"%s","target":"%s"}' "$IMG" "$TARGET" >> "$manifest_json"
    first=0
    echo "$IMG  ->  $TARGET" >> "$manifest_txt"

    gen_sbom_or_metadata "$IMG"
  done
  echo ""  >> "$manifest_json"
  echo "]" >> "$manifest_json"
  
  log_info "Pre-push manifest written:"
  log_info "  - Text: $manifest_txt"
  log_info "  - JSON: $manifest_json"

  # Handle dry-run mode
  if [[ "${DRY_PUSH:-0}" -eq 1 ]]; then
    log_warn "Dry-run mode enabled (--dry-push flag)"
    log_warn "Skipping actual registry authentication and image pushes"
    log_info "Review manifest files above to verify push targets"
    metrics_summary "Push Operation (Dry-Run)"
    return 0
  fi


  # Authenticate to registry (optional)
  report_progress "Authenticating to registry" 3 4
  if [[ -n "${REG_USER:-}" && -n "${REG_PASS:-}" ]]; then
    log_info "Logging into registry: $REG_HOST"
    if ! spinner_run "Logging into $REG_HOST" nerdctl login "$REG_HOST" -u "$REG_USER" -p "$REG_PASS"; then
    log_error "Registry login failed"
    log_error "Remediation steps:"
    log_error "  - Verify registry URL is correct: $REG_HOST"
    log_error "  - Check username and password credentials"
    log_error "  - Ensure registry is accessible from this network"
    log_error "  - Test manually: nerdctl login $REG_HOST -u <user>"
    metrics_increment "failed"
    metrics_summary "Push Operation (Failed)"
    exit 1
    fi
  else
    log_warn "No registry credentials provided; skipping nerdctl login (registry assumed open/no-auth)."
  fi
  metrics_increment "authenticated"

  # Push images with progress tracking
  report_progress "Pushing images to registry" 4 4
  log_info "Starting image push operations ($img_count images)"
  
  local push_num=0
  for IMG in "${imgs[@]}"; do
    [[ -z "$IMG" ]] && continue
    push_num=$((push_num + 1))
    
    local TARGET
    # Canonicalize image reference so images without an explicit registry are treated as docker.io/
    local src_ref="$IMG"
    local src_repo="${IMG%:*}"
    local src_tag="${IMG##*:}"
    local first_seg="${src_repo%%/*}"
    local canon_repo="$src_repo"
    if [[ "$src_repo" != */* ]]; then
      canon_repo="docker.io/$src_repo"
    elif [[ "$first_seg" != *.* && "$first_seg" != *:* ]]; then
      canon_repo="docker.io/$src_repo"
    fi
    local canon_img="${canon_repo}:${src_tag}"
    if [[ -n "$REG_NS" ]]; then TARGET="$REG_HOST/$REG_NS/$canon_img"; else TARGET="$REG_HOST/$canon_img"; fi
    
    log_info "[$push_num/$img_count] Processing: $IMG -> $TARGET"
    
    # Tag image
    if ! nerdctl -n k8s.io tag "$IMG" "$TARGET" >>"$LOG_FILE" 2>&1; then
      log_error "Failed to tag image: $IMG"
      metrics_increment "failed"
      report_item_failure "$IMG" "Tag operation failed"
      continue
    fi
    
    # Push image
    if spinner_run "Pushing $TARGET" nerdctl -n k8s.io push "$TARGET"; then
      metrics_increment "success"
      report_item_success "$IMG" "Pushed to $TARGET"
    else
      log_error "Failed to push image: $TARGET"
      metrics_increment "failed"
      report_item_failure "$IMG" "Push operation failed"
    fi
  done

  # Cleanup - logout from registry (only when credentials were used)
  if [[ -n "${REG_USER:-}" && -n "${REG_PASS:-}" ]]; then
    nerdctl logout "$REG_HOST" >>"$LOG_FILE" 2>&1 || true
  fi

  # Display summary
  metrics_summary "Image Push Summary"
  
  # Determine exit status based on metrics
  if metrics_should_fail; then
    log_error "Push operation completed with failures"
    log_error "Review error messages above and retry failed images"
    return 1
  else
    log_success "Image push operation completed successfully"
    log_info "All $img_count images pushed to $REG_HOST"
    return 0
  fi
}

#=============================================================================
# Function: action_image
# Description: Prepare golden image for air-gapped deployment with full artifact
#              caching, SBOM generation, and comprehensive validation
# Parameters:
#   None (reads from CONFIG_FILE or uses defaults)
# Returns: 
#   0 - Success (image prepared, reboot prompt shown)
#   1 - Dependency or validation failure
#   3 - Artifact download/caching failure
# Usage: action_image -f <config.yaml>
# Dependencies: metrics_init, metrics_increment, metrics_summary, validate_file_exists,
#               validate_directory_writable, check_dependencies, install_dependencies_interactive,
#               log_info, log_success, log_error, report_progress
# Changes from Original:
#   - Added metrics tracking for artifacts and operations
#   - Enhanced validation with Phase 1 utilities
#   - Improved progress reporting for long-running operations
#   - Better structured logging for auditability
#   - Dependency checks with interactive installation
#=============================================================================
action_image() {
  initialize_action_context true "image"

  # Check for dry-run mode
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    log_info "========================================"
    log_info "DRY-RUN MODE: RKE2 Golden Image Prep"
    log_info "========================================"
    log_info "No changes will be made to the system"
    log_info ""
  fi

  log_info "========================================"
  log_info "Starting RKE2 Golden Image Preparation"
  log_info "========================================"
  
  # Initialize metrics for comprehensive tracking
  metrics_init "image_operation"
  
  # Log static directory context for audit trail (effective config is logged after YAML load)
  log_info "Directories:"
  log_info "  DOWNLOADS_DIR: $DOWNLOADS_DIR"
  log_info "  STAGE_DIR: $STAGE_DIR"
  log_info "  SBOM_DIR: $SBOM_DIR"
  log_info "  OUT_DIR: $OUT_DIR"

  # Validate directories are writable
  report_progress "Validating environment" 1 8
  if ! validate_directory_writable "$DOWNLOADS_DIR" "downloads directory"; then
    log_error "Downloads directory not writable: $DOWNLOADS_DIR"
    log_error "Remediation: Check directory permissions and disk space"
    exit 1
  fi
  if ! validate_directory_writable "$STAGE_DIR" "stage directory"; then
    log_error "Stage directory not writable: $STAGE_DIR"
    log_error "Remediation: Check directory permissions and disk space"
    exit 1
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "validation_passed"

  # --- Read YAML configuration (optional) -----------------------------------
  report_progress "Loading configuration" 2 8
  local REQ_VER="${RKE2_VERSION:-}"
  local REQ_CNI_VER="${HARDENED_CNI_TAG:-}"
  local REQ_MULTUS_VER="${HARDENED_MULTUS_TAG:-}"
  local fix_cni_permissions_enabled="$FIX_CNI_PERMISSIONS"
  local defaultDnsCsv="$DEFAULT_DNS"
  local defaultSearchCsv=""
  local cni_plugins_csv=""
  local system_default_registry=""
  local boot_enabled_cfg="false"
  local boot_yaml_path_cfg=""
  local boot_mode_cfg=""
  local boot_platform_cfg=""
  local REG_HOST="${REGISTRY%%/*}"
  local CA_ROOT="" CA_KEY="" CA_INTCRT="" CA_INTKEY="" CA_INSTALL="true"
  
  if [[ -n "$CONFIG_FILE" ]]; then
    log_info "Loading configuration from: $CONFIG_FILE"
    if ! validate_file_exists "$CONFIG_FILE" "configuration file" "configuration file"; then
      log_error "Configuration file not found: $CONFIG_FILE"
      exit 1
    fi
    
    REQ_VER="${REQ_VER:-$(yaml_spec_get "$CONFIG_FILE" rke2Version || true)}"
    REQ_CNI_VER="${REQ_CNI_VER:-$(yaml_spec_get_any "$CONFIG_FILE" rke2CNIVersion rke2CniVersion || true)}"
    REQ_MULTUS_VER="${REQ_MULTUS_VER:-$(yaml_spec_get_any "$CONFIG_FILE" rke2MultusVersion rke2MultusCniVersion rke2MultusCNIVersion || true)}"
    local fix_cni_permissions_yaml=""
    fix_cni_permissions_yaml="$(yaml_spec_get_any "$CONFIG_FILE" fixCNIPermissions fixCniPermissions fix-cni-permissions || true)"
    if bool_value_is_true "$fix_cni_permissions_yaml"; then
      fix_cni_permissions_enabled=1
    fi
    REGISTRY="$(yaml_spec_get "$CONFIG_FILE" registry || echo "$REGISTRY")"
    REG_USER="$(yaml_spec_get "$CONFIG_FILE" registryUsername || echo "$REG_USER")"
    REG_PASS="$(yaml_spec_get "$CONFIG_FILE" registryPassword || echo "$REG_PASS")"
    system_default_registry="$(yaml_spec_get_any "$CONFIG_FILE" system-default-registry systemDefaultRegistry || true)"
    REG_HOST="${REGISTRY%%/*}"

    local -a _cni_plugins=()
    local _cni
    while IFS= read -r _cni; do
      [[ -n "$_cni" ]] && _cni_plugins+=("$_cni")
    done < <(collect_requested_cni_plugins "$CONFIG_FILE")
    if [[ ${#_cni_plugins[@]} -gt 0 ]]; then
      cni_plugins_csv="$(IFS=','; echo "${_cni_plugins[*]}")"
    fi
    
    local d1 s1
    d1="$(yaml_spec_get "$CONFIG_FILE" defaultDns || true)"
    s1="$(yaml_spec_get "$CONFIG_FILE" defaultSearchDomains || true)"
    [[ -n "$d1" ]] && defaultDnsCsv="$(normalize_list_csv "$d1")"
    [[ -n "$s1" ]] && defaultSearchCsv="$(normalize_list_csv "$s1")"

    boot_enabled_cfg="$(normalize_bool_value "$(yaml_spec_get "$CONFIG_FILE" bootService.enabled || echo false)")"
    boot_yaml_path_cfg="$(yaml_spec_get "$CONFIG_FILE" bootService.yamlPath || true)"
    boot_mode_cfg="$(yaml_spec_get "$CONFIG_FILE" bootService.mode || true)"
    boot_platform_cfg="$(yaml_spec_get "$CONFIG_FILE" bootService.platform || true)"
    
    # Optional custom CA for registry/cluster
    CA_ROOT="$(yaml_spec_get "$CONFIG_FILE" customCA.rootCrt || true)"
    CA_KEY="$(yaml_spec_get "$CONFIG_FILE" customCA.rootKey || true)"
    CA_INTCRT="$(yaml_spec_get "$CONFIG_FILE" customCA.intermediateCrt || true)"
    CA_INTKEY="$(yaml_spec_get "$CONFIG_FILE" customCA.intermediateKey || true)"
    CA_INSTALL="$(yaml_spec_get "$CONFIG_FILE" customCA.installToOSTrust || echo true)"
    
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "config_loaded"
  else
    log_info "No configuration file provided - using defaults and CLI flags"
    metrics_increment "total"
    metrics_increment "success"
  fi

  # Warn if using example default credentials
  warn_default_credentials "$REGISTRY" "$REG_USER" "$REG_PASS"

  # Honor explicit hardened-cni tag from env/YAML for artifact mirroring.
  [[ -n "$REQ_CNI_VER" ]] && HARDENED_CNI_TAG="$REQ_CNI_VER"
  [[ -n "$REQ_MULTUS_VER" ]] && HARDENED_MULTUS_TAG="$REQ_MULTUS_VER"

  # Log effective configuration after YAML/CLI/env resolution.
  log_info "Configuration:"
  log_info "  RKE2_VERSION: ${REQ_VER:-<auto-detect>}"
  log_info "  HARDENED_CNI_TAG: ${HARDENED_CNI_TAG:-<auto-detect>}"
  log_info "  HARDENED_MULTUS_TAG: ${HARDENED_MULTUS_TAG:-<auto-detect>}"
  log_info "  CNI_PLUGINS: ${cni_plugins_csv:-<unset>}"
  log_info "  FIX_CNI_PERMISSIONS: ${fix_cni_permissions_enabled}"
  log_info "  REGISTRY: ${REGISTRY:-<none>}"
  log_info "  SYSTEM_DEFAULT_REGISTRY: ${system_default_registry:-<unset>}"
  log_info "  REG_USER: ${REG_USER:-<none>}"
  log_info "  DEFAULT_DNS: ${defaultDnsCsv:-<unset>}"
  log_info "  DEFAULT_SEARCH_DOMAINS: ${defaultSearchCsv:-<unset>}"
  log_info "  BOOT_SERVICE_ENABLED: ${boot_enabled_cfg}"
  log_info "  BOOT_SERVICE_MODE: ${boot_mode_cfg:-<unset>}"
  log_info "  BOOT_SERVICE_PLATFORM: ${boot_platform_cfg:-<unset>}"
  log_info "  BOOT_SERVICE_YAML_PATH: ${boot_yaml_path_cfg:-<unset>}"

  # Resolve cert paths relative to script dir if not absolute
  [[ -n "$CA_ROOT"   && "${CA_ROOT:0:1}"   != "/" ]] && CA_ROOT="$SCRIPT_DIR/$CA_ROOT"
  [[ -n "$CA_KEY"    && "${CA_KEY:0:1}"    != "/" ]] && CA_KEY="$SCRIPT_DIR/$CA_KEY"
  [[ -n "$CA_INTCRT" && "${CA_INTCRT:0:1}" != "/" ]] && CA_INTCRT="$SCRIPT_DIR/$CA_INTCRT"
  [[ -n "$CA_INTKEY" && "${CA_INTKEY:0:1}" != "/" ]] && CA_INTKEY="$SCRIPT_DIR/$CA_INTKEY"

  # --- Install OS prerequisites ----------------------------------------------
  report_progress "Installing OS prerequisites" 3 8
  log_info "Installing RKE2 prerequisites for $(detect_os)"
  install_rke2_prereqs
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "prereqs_installed"

  # Detect virtualization and install appropriate tools
  local virt_class virt_type hypervisor
  IFS='|' read -r virt_class virt_type hypervisor <<<"$(detect_virtualization)"
  if [[ "$virt_class" == "virtual" ]]; then
    log_info "Virtual environment detected: type=${virt_type:-unknown}, hypervisor=${hypervisor:-unknown}"
    install_vm_tools "$hypervisor"
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "vm_tools_installed"
  else
    log_info "Physical hardware detected - skipping VM tools installation"
  fi

  # Fetch RKE2 CA generator utility
  fetch_rke2_ca_generator
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "ca_generator_fetched"
  
  # --- Cache RKE2 artifacts --------------------------------------------------
  # Downloads and stages required artifacts into DOWNLOADS_DIR and STAGE_DIR
  report_progress "Caching RKE2 artifacts" 4 8
  log_info "Downloading and staging RKE2 artifacts"
  log_info "  Target: downloads -> $DOWNLOADS_DIR, stage -> $STAGE_DIR"
  
  if ! cache_rke2_artifacts; then
    log_error "Failed to cache RKE2 artifacts"
    log_error "Remediation steps:"
    log_error "  - Check network connectivity to RKE2 release servers"
    log_error "  - Verify disk space in $DOWNLOADS_DIR"
    log_error "  - Review log file: $LOG_FILE"
    metrics_increment "failed"
    exit 3
  fi
  
  log_info "Artifact caching completed successfully"
  log_info "Scanning staged and downloaded artifacts for verification"
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "artifacts_cached"

  if ! verify_required_cni_images_staged "$CONFIG_FILE"; then
    log_error "Required CNI images are not fully staged for offline deployment."
    metrics_increment "total"
    metrics_increment "failed"
    exit 3
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "cni_images_validated"

  if ! verify_required_image_tags_staged; then
    log_error "Required image/tag validation failed for staged artifacts."
    metrics_increment "total"
    metrics_increment "failed"
    exit 3
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "required_image_tags_validated"

  # --- Optional: Load images into local runtime ------------------------------
  report_progress "Processing container images" 5 8
  if [[ "${LOAD_IMAGES:-0}" -eq 1 ]]; then
    log_info "Image loading requested (--load-images flag)"
    log_info "Installing nerdctl for container image management"
    
    if ! check_dependencies nerdctl; then
      install_nerdctl || {
        log_error "Failed to install nerdctl"
        metrics_increment "total"
        metrics_increment "failed"
        exit 1
      }
      metrics_increment "total"
      metrics_increment "success"
      metrics_increment "nerdctl_installed"
    fi

    log_info "Loading images from tarball into local container runtime"
    if ! load_images_from_tarball >/dev/null 2>&1; then
      log_warn "Image loading returned non-zero exit code"
      log_warn "Node may attempt remote image pulls during deployment"
      metrics_increment "total"
      metrics_increment "skipped"
      metrics_increment "image_load_warned"
    else
      log_success "Images loaded successfully into local runtime"
      metrics_increment "total"
      metrics_increment "success"
      metrics_increment "images_loaded"
    fi
  else
    log_info "Image loading skipped (default: tarball-on-node strategy)"
    log_info "Use --load-images flag to import images into container runtime"
  fi

  # --- Trust configured registries -------------------------------------------
  # Installs custom CA into registries.yaml if configured
  report_progress "Configuring registry trust" 6 8
  log_info "Configuring registry trust and custom CA (if applicable)"
  ca_trust_registries
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "registry_trust_configured"

  # Collect artifact inventory for SBOM and verification
  log_info "Collecting artifact inventory for SBOM generation"

  # --- Save site defaults (DNS/search) ---------------------------------------
  report_progress "Saving site defaults" 7 8
  local STATE="/etc/rke2image.defaults"
  {
    echo "DEFAULT_DNS=\"$defaultDnsCsv\""
    echo "DEFAULT_SEARCH=\"$defaultSearchCsv\""
  } > "$STATE"
  chmod 600 "$STATE"
  log_info "Site defaults saved to: $STATE"
  log_info "  DNS servers: $defaultDnsCsv"
  log_info "  Search domains: $defaultSearchCsv"
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "defaults_saved"

  # --- Boot Service Installation (optional enablement) -----------------------
  log_info "Reconciling first-boot automation script and service..."
  
  # Read boot service configuration from YAML if provided
  local boot_enabled="false"
  local boot_yaml_path_yaml=""
  local boot_mode_yaml=""
  local boot_platform_yaml=""
  
  if [[ -n "$CONFIG_FILE" ]]; then
    boot_enabled="$(yaml_spec_get "$CONFIG_FILE" bootService.enabled || echo false)"
    boot_yaml_path_yaml="$(yaml_spec_get "$CONFIG_FILE" bootService.yamlPath || true)"
    boot_mode_yaml="$(yaml_spec_get "$CONFIG_FILE" bootService.mode || true)"
    boot_platform_yaml="$(yaml_spec_get "$CONFIG_FILE" bootService.platform || true)"
    
    # Override globals if specified in YAML
    [[ -n "$boot_yaml_path_yaml" ]] && BOOT_YAML_PATH="$boot_yaml_path_yaml"
    [[ -n "$boot_mode_yaml" ]] && BOOT_SERVICE_MODE="$boot_mode_yaml"
    [[ -n "$boot_platform_yaml" ]] && VM_PLATFORM="$boot_platform_yaml"
  fi
  
  # Normalize boolean value
  boot_enabled="$(normalize_bool_value "$boot_enabled")"
  
  # Install and enable boot service only when explicitly requested.
  if [[ "$ENABLE_BOOT_SERVICE" -eq 1 ]] || [[ "$boot_enabled" == "true" ]]; then
    if install_boot_script; then
      if install_boot_service; then
        log_info "✓ Boot script and service installed successfully"
        log_info "  Script: $BOOT_SCRIPT_PATH"
        log_info "  Service: $BOOT_SERVICE_PATH"
        log_info "  Mode: $BOOT_SERVICE_MODE"
        log_info "  Platform: $(detect_vm_platform)"
        log_info "  Config search paths:"
        for search_path in "${BOOT_CONFIG_SEARCH_PATHS[@]}"; do
          log_info "    - $search_path"
        done
        log_info "  Target directory: $BOOT_TARGET_DIR"
        
        # Display Hyper-V specific requirements
        if [[ "$(detect_vm_platform)" == "hyperv" ]]; then
          log_info ""
          log_info "Hyper-V Configuration Required:"
          log_info "  Run this PowerShell command on the Hyper-V host for each VM:"
          log_info "  Set-VMKeyValuePairItem -VMName \"<vm-name>\" -Key \"VirtualMachineName\" -Value \"<vm-name>\""
          log_info "  Example: Set-VMKeyValuePairItem -VMName \"cotpa-ctrl01\" -Key \"VirtualMachineName\" -Value \"cotpa-ctrl01\""
          log_info "  Without this, the guest hostname will be used as fallback."
        fi

        if enable_boot_service; then
          log_info "✓ Boot service ENABLED for next reboot"
          log_info "IMPORTANT: Place node configs in search paths with naming: {hostname}.yaml"
          log_info "           Boot service will auto-discover and copy configs on first boot"
        else
          log_warn "Failed to enable boot service; install completed but service not active"
        fi
      else
        log_warn "Failed to install boot service; continuing without first-boot automation"
      fi
    else
      log_warn "Failed to install boot script; continuing without first-boot automation"
    fi
  else
    if ! uninstall_boot_service_artifacts; then
      log_error "Boot service is disabled by configuration, but existing artifacts could not be removed"
      exit 1
    fi
    log_info "Boot service not requested; boot script/service not installed"
    log_info "To enable: use --enable-boot-service flag or set bootService.enabled: true in YAML"
  fi

  # --- Optional: Enable CNI permission remediation ----------------------------
  if [[ "$fix_cni_permissions_enabled" -eq 1 ]]; then
    log_info "Enabling CNI permission remediation (requested by YAML/CLI)"
    if install_cni_permission_remediation; then
      log_info "✓ CNI permission remediation installed and enabled"
      metrics_increment "total"
      metrics_increment "success"
      metrics_increment "cni_perm_fix_enabled"
    else
      log_error "Failed to install/enable CNI permission remediation"
      log_error "Remediation: verify scripts/fix-cni-perms.sh and scripts/systemd/* are present"
      metrics_increment "total"
      metrics_increment "failed"
      exit 1
    fi
  else
    log_info "CNI permission remediation not requested (set spec.fixCNIPermissions: true or --fix-cni-permissions)"
  fi

  # --- SBOM and README generation --------------------------------------------
  report_progress "Generating SBOM and documentation" 8 8
  log_info "Generating Software Bill of Materials (SBOM)"
  
  # Ensure nerdctl archive names are known for reporting
  local full_tgz="${NERDCTL_FULL_TGZ:-}"
  local std_tgz="${NERDCTL_STD_TGZ:-}"
  if [[ -z "$full_tgz" && -d "$DOWNLOADS_DIR" ]]; then
    full_tgz="$(find "$DOWNLOADS_DIR" -maxdepth 1 -type f -name "nerdctl-full-*-linux-${ARCH}.tar.gz" -printf '%f\n' | sort | tail -n1)"
  fi
  if [[ -z "$std_tgz" && -d "$DOWNLOADS_DIR" ]]; then
    std_tgz="$(find "$DOWNLOADS_DIR" -maxdepth 1 -type f -name "nerdctl-*-linux-${ARCH}.tar.gz" ! -name 'nerdctl-full-*' -printf '%f\n' | sort | tail -n1)"
  fi
  NERDCTL_FULL_TGZ="$full_tgz"
  NERDCTL_STD_TGZ="$std_tgz"

  # SBOM lists filenames, sizes, sha256; write to $SBOM_DIR/<name>-sbom.txt
  log_info "Creating Software Bill of Materials (SBOM)"
  mkdir -p "$SBOM_DIR"
  local sbom_name="${SPEC_NAME:-image}"
  local sbom_file="$SBOM_DIR/${sbom_name}-sbom.txt"
  local sbom_json_file="$SBOM_DIR/${sbom_name}-sbom.json"
  
  # Build sbom_targets to include baseline artifacts plus any downloaded/staged
  # image archives discovered at runtime.
  local -a sbom_targets=()
  local -A sbom_seen=()
  add_sbom_target() {
    local target="${1:-}"
    [[ -n "$target" && -f "$target" ]] || return 0
    [[ -n "${sbom_seen[$target]:-}" ]] && return 0
    sbom_seen["$target"]=1
    sbom_targets+=("$target")
  }
  archive_looks_like_image_bundle() {
    local archive="${1:-}"
    local manifest=""
    local oci_refs=""

    [[ -f "$archive" ]] || return 1

    if [[ "$archive" == *.zst ]]; then
      command -v zstd >/dev/null 2>&1 || return 1
      manifest="$(zstd -dc "$archive" 2>/dev/null | tar -xO manifest.json 2>/dev/null || true)"
    elif [[ "$archive" == *.gz || "$archive" == *.tgz ]]; then
      command -v gzip >/dev/null 2>&1 || return 1
      manifest="$(gzip -dc "$archive" 2>/dev/null | tar -xO manifest.json 2>/dev/null || true)"
    else
      manifest="$(tar -xOf "$archive" manifest.json 2>/dev/null || true)"
    fi

    if [[ -n "$manifest" ]] && echo "$manifest" | grep -q '"RepoTags"'; then
      return 0
    fi

    oci_refs="$(parse_oci_image_index "$archive" 2>/dev/null || true)"
    if [[ -n "$oci_refs" && "$oci_refs" != "[]" ]]; then
      return 0
    fi

    return 1
  }

  add_sbom_target "$DOWNLOADS_DIR/$IMAGES_TAR"
  add_sbom_target "$DOWNLOADS_DIR/$RKE2_TARBALL"
  add_sbom_target "$DOWNLOADS_DIR/$SHA256_FILE"
  add_sbom_target "$DOWNLOADS_DIR/install.sh"
  add_sbom_target "$STAGE_DIR/$RKE2_TARBALL"
  add_sbom_target "$STAGE_DIR/$SHA256_FILE"
  add_sbom_target "$STAGE_DIR/sha256sum-${ARCH}.json"
  add_sbom_target "$STAGE_DIR/install.sh"
  [[ -n "$full_tgz" ]] && add_sbom_target "$DOWNLOADS_DIR/$full_tgz"
  [[ -n "$std_tgz"  ]] && add_sbom_target "$DOWNLOADS_DIR/$std_tgz"

  # Include any downloaded/staged image archives (docker-archive or OCI-layout)
  # so SBOM coverage stays current as image acquisition evolves.
  local agent_images_dir="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"
  local dir archive
  for dir in "$DOWNLOADS_DIR" "$STAGE_DIR" "$agent_images_dir"; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r archive; do
      [[ -n "$archive" ]] || continue
      archive_looks_like_image_bundle "$archive" || continue
      add_sbom_target "$archive"
    done < <(find "$dir" -maxdepth 1 -type f \( -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.tar.zst' -o -name '*.tzst' -o -name '*.zst' \) | sort)
  done
  
  # Load expected checksums from manifest file
  declare -A expected_hash=()
  declare -A expected_hash_path=()
  local manifest_source="none"
  local manifest_path=""
  if [[ -f "$STAGE_DIR/$SHA256_FILE" ]]; then
    log_info "Loading expected checksums from: $STAGE_DIR/$SHA256_FILE"
    manifest_source="staged"
    manifest_path="$STAGE_DIR/$SHA256_FILE"
    while read -r h fn; do expected_hash["$(basename "$fn")"]="$h"; done < <(awk '{print $1, $2}' "$STAGE_DIR/$SHA256_FILE")
  elif [[ -f "$DOWNLOADS_DIR/$SHA256_FILE" ]]; then
    log_info "Loading expected checksums from: $DOWNLOADS_DIR/$SHA256_FILE"
    manifest_source="downloads"
    manifest_path="$DOWNLOADS_DIR/$SHA256_FILE"
    while read -r h fn; do
      expected_hash["$(basename "$fn")"]="$h"
    done < <(awk '{print $1, $2}' "$DOWNLOADS_DIR/$SHA256_FILE")
  else
    log_warn "No SHA256 manifest found - artifact verification will be limited"
  fi

  # Load path-aware checksum metadata (preferred when duplicate basenames exist,
  # e.g., downloads/sha256sum-<arch>.txt and stage/sha256sum-<arch>.txt).
  local staged_manifest_json="$STAGE_DIR/sha256sum-${ARCH}.json"
  if [[ -f "$staged_manifest_json" && -x "$(command -v python3 2>/dev/null || true)" ]]; then
    while IFS='|' read -r _loc _name _sha; do
      [[ -z "${_loc:-}" || -z "${_name:-}" || -z "${_sha:-}" ]] && continue
      case "$_loc" in
        stage) expected_hash_path["$STAGE_DIR/$_name"]="$_sha" ;;
        images) expected_hash_path["${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}/$_name"]="$_sha" ;;
        downloads) expected_hash_path["$DOWNLOADS_DIR/$_name"]="$_sha" ;;
      esac
    done < <(python3 - "$staged_manifest_json" <<'PY'
import json,sys
p=sys.argv[1]
try:
    data=json.load(open(p,'r',encoding='utf-8'))
    for item in data.get('files',[]) or []:
        loc=item.get('location')
        name=item.get('name')
        sha=item.get('sha256')
        if loc and name and sha:
            print(f"{loc}|{name}|{sha}")
except Exception:
    pass
PY
)
  fi
  if [[ -f "$staged_manifest_json" ]]; then
    expected_hash_path["$staged_manifest_json"]="__SELF_GENERATED__"
  fi

  # Prepare SBOM header with metadata
  {
    echo "# RKE2 Image Prep SBOM (Human Review Report)"
    echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "Spec Name: ${sbom_name}"
    echo "Action: image"
    echo "RKE2_VERSION: ${RKE2_VERSION:-<auto>}"
    echo "HARDENED_CNI_TAG: ${HARDENED_CNI_TAG:-<auto>}"
    echo "REGISTRY: ${REGISTRY:-<none>}"
    echo "Manifest Source: ${manifest_source}"
    echo "Manifest Path: ${manifest_path:-<none>}"
    echo "SPDX JSON: ${sbom_json_file}"
    echo
    echo "# Verification Legend"
    echo "#   yes          = checksum matches expected manifest value"
    echo "#   NO (mismatch)= checksum differs from expected manifest value"
    echo "#   no-manifest  = no expected checksum entry for artifact basename"
    echo
    echo "# Artifact inventory (machine-readable for tooling compatibility)"
    echo "# path | size_bytes | sha256 | verified | mtime | source | expected_sha256 | verification_note"
  } > "$sbom_file"

  # Track verification metrics for security scoring
  local total_count=0 verified_count=0 manifest_present=0
  local mismatch_count=0 no_manifest_count=0
  [[ ${#expected_hash[@]} -gt 0 ]] && manifest_present=1

  # Process each artifact and verify checksums
  log_info "Verifying and cataloging artifacts (${#sbom_targets[@]} targets)"
  for f in "${sbom_targets[@]}"; do
    [[ -f "$f" ]] || continue
    total_count=$((total_count + 1))
    
    local fname size sha mtime src verified expected_sha verification_note
    fname="$(basename "$f")"
    size=$(stat -c%s "$f" 2>/dev/null || echo 0)
    mtime=$(date -u -r "$f" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "<unknown>")
    sha=$(sha256sum "$f" | awk '{print $1}')
    src="$( [[ "$f" == "$DOWNLOADS_DIR"/* ]] && echo downloads || echo staged )"
    verified="unknown"
    expected_sha="<none>"
    verification_note=""
    
    # Verify against expected checksum if available (prefer path-aware map,
    # then fall back to basename map).
    if [[ -n "${expected_hash_path[$f]:-}" ]]; then
      expected_sha="${expected_hash_path[$f]}"
      if [[ "${expected_hash_path[$f]}" == "__SELF_GENERATED__" ]]; then
        verified="yes"
        verification_note="self-generated manifest metadata file"
        verified_count=$((verified_count + 1))
        metrics_increment "artifact_verified"
      elif [[ "${expected_hash_path[$f]}" == "$sha" ]]; then
        verified="yes"
        verification_note="checksum matches path-aware manifest metadata"
        verified_count=$((verified_count + 1))
        metrics_increment "artifact_verified"
      else
        verified="NO (mismatch)"
        verification_note="checksum mismatch (expected ${expected_hash_path[$f]})"
        mismatch_count=$((mismatch_count + 1))
        log_error "Checksum mismatch for $fname"
        metrics_increment "artifact_mismatch"
      fi
    elif [[ -n "${expected_hash[$fname]:-}" ]]; then
      expected_sha="${expected_hash[$fname]}"
      if [[ "${expected_hash[$fname]}" == "$sha" ]]; then
        verified="yes"
        verification_note="checksum matches manifest"
        verified_count=$((verified_count + 1))
        metrics_increment "artifact_verified"
      else
        verified="NO (mismatch)"
        verification_note="checksum mismatch (expected ${expected_hash[$fname]})"
        mismatch_count=$((mismatch_count + 1))
        log_error "Checksum mismatch for $fname"
        metrics_increment "artifact_mismatch"
      fi
    else
      verified="no-manifest"
      verification_note="manifest entry missing for basename"
      no_manifest_count=$((no_manifest_count + 1))
    fi

    # Append detailed entry to SBOM
    printf '%s | %s | %s | %s | %s | %s | %s | %s\n' "$f" "$size" "$sha" "$verified" "$mtime" "$src" "$expected_sha" "$verification_note" >> "$sbom_file"
    
    # Report verification status
    if [[ "$verified" == "yes" ]]; then
      report_item_success "$fname" "Verified ($size bytes)"
    elif [[ "$verified" == "NO (mismatch)" ]]; then
      report_item_failure "$fname" "Checksum mismatch"
    else
      report_item_skipped "$fname" "No manifest entry"
    fi
  done

  # Compute security score based on verification results
  local security_score=0
  if [[ $manifest_present -eq 1 ]]; then
    security_score=$((security_score + 40))
  fi
  if [[ $total_count -gt 0 ]]; then
    if [[ $manifest_present -eq 1 && $verified_count -eq $total_count ]]; then
      security_score=$((security_score + 40))
    fi
    security_score=$((security_score + 20))
  fi

  # Append summary to SBOM
  {
    echo
    echo "# Summary"
    echo "Artifacts discovered: $total_count"
    echo "Artifacts verified against manifest: $verified_count"
    echo "Artifacts with checksum mismatch: $mismatch_count"
    echo "Artifacts missing manifest entry: $no_manifest_count"
    echo "SHA256 manifest present: ${manifest_present}" 
    echo "security_score: ${security_score}"
    echo
    echo "# Human Review Findings"
    if [[ $mismatch_count -eq 0 ]]; then
      echo "- Integrity mismatches: none"
    else
      echo "- Integrity mismatches: ${mismatch_count} (investigate immediately)"
    fi
    if [[ $no_manifest_count -eq 0 ]]; then
      echo "- Missing manifest coverage: none"
    else
      echo "- Missing manifest coverage: ${no_manifest_count} (review whether each file should be pinned)"
    fi
    echo "- Verified coverage: ${verified_count}/${total_count}"
    echo "- Recommended reviewer checks:"
    echo "  1. Confirm RKE2_VERSION/HARDENED_CNI_TAG align with approved release bill"
    echo "  2. Confirm all required artifacts are either verified or intentionally unmanaged"
    echo "  3. Cross-check SPDX JSON at ${sbom_json_file} for automation workflows"
  } >> "$sbom_file"

  log_success "SBOM created successfully"
  log_info "SBOM location: $sbom_file"
  log_info "  Artifacts: $total_count discovered, $verified_count verified"
  log_info "  Security score: ${security_score}/100"
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "sbom_created"

  # Generate SPDX 2.3 JSON SBOM for tooling compatibility
  if command -v python3 >/dev/null 2>&1; then
    log_info "Generating SPDX 2.3 JSON SBOM: $sbom_json_file"
    local staged_manifest_json="$STAGE_DIR/sha256sum-${ARCH}.json"
    python3 - "$sbom_file" "$sbom_json_file" "$staged_manifest_json" <<'PY'
import sys, json, re, hashlib
from datetime import datetime, timezone

sbom_txt = sys.argv[1]
sbom_json = sys.argv[2]
staged_json = sys.argv[3] if len(sys.argv) > 3 else None

artifacts = []
header = { 'generated': None, 'rke2_version': None, 'registry': None }
summary = {}

with open(sbom_txt, 'r', encoding='utf-8') as fh:
  for line in fh:
    line = line.rstrip('\n')
    if not line or line.startswith('#'):
      continue
    # artifact lines use a pipe delimiter: path | size | sha | verified | mtime | source
    if '|' in line:
      parts = [p.strip() for p in line.split('|')]
      if len(parts) >= 6:
        size = parts[1]
        try:
          size = int(size)
        except Exception:
          pass
        artifacts.append({
          'path': parts[0],
          'size_bytes': size,
          'sha256': parts[2],
          'verified': parts[3],
          'mtime': parts[4],
          'source': parts[5]
        })

with open(sbom_txt, 'r', encoding='utf-8') as fh:
  for line in fh:
    if line.startswith('Generated:'):
      header['generated'] = line.split('Generated:',1)[1].strip()
    elif line.startswith('RKE2_VERSION:'):
      header['rke2_version'] = line.split('RKE2_VERSION:',1)[1].strip()
    elif line.startswith('REGISTRY:'):
      header['registry'] = line.split('REGISTRY:',1)[1].strip()
    elif line.startswith('Artifacts discovered:'):
      try:
        summary['artifacts_discovered'] = int(line.split(':',1)[1].strip())
      except Exception:
        summary['artifacts_discovered'] = line.split(':',1)[1].strip()
    elif line.startswith('Artifacts verified against manifest:'):
      try:
        summary['artifacts_verified'] = int(line.split(':',1)[1].strip())
      except Exception:
        summary['artifacts_verified'] = line.split(':',1)[1].strip()
    elif line.startswith('SHA256 manifest present:'):
      summary['sha256_manifest_present'] = line.split(':',1)[1].strip()
    elif line.startswith('security_score:'):
      try:
        summary['security_score'] = int(line.split(':',1)[1].strip())
      except Exception:
        summary['security_score'] = line.split(':',1)[1].strip()

def sanitize_spdx_id(value: str) -> str:
  v = re.sub(r'[^A-Za-z0-9.-]+', '-', value or 'artifact').strip('-')
  if not v:
    v = 'artifact'
  return v

def package_spdx_id(path: str, name: str, index: int) -> str:
  base = sanitize_spdx_id(name)
  digest = hashlib.sha256((path or name or str(index)).encode('utf-8')).hexdigest()[:10]
  return f"SPDXRef-Package-{base}-{digest}"

def to_iso_utc(v: str) -> str:
  if not v:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
  return v

created = to_iso_utc(header.get('generated'))
doc_name = f"rke2-image-{header.get('rke2_version') or 'auto'}"
namespace_suffix = created.replace(':', '').replace('-', '')
doc_namespace = f"https://sbom.rke2-node-init.local/spdx/{doc_name}/{namespace_suffix}"

root_spdx_id = "SPDXRef-RKE2ArtifactBundle"
root_checksum = hashlib.sha256(''.join(sorted(a.get('sha256','') for a in artifacts)).encode('utf-8')).hexdigest() if artifacts else '0'*64

packages = [
  {
    "SPDXID": root_spdx_id,
    "name": "rke2-offline-artifact-bundle",
    "versionInfo": header.get('rke2_version') or "NOASSERTION",
    "supplier": "Organization: rke2-node-init",
    "downloadLocation": "NOASSERTION",
    "packageFileName": f"{doc_name}.bundle",
    "checksums": [
      {
        "algorithm": "SHA256",
        "checksumValue": root_checksum
      }
    ],
    "primaryPackagePurpose": "BINARY",
    "licenseDeclared": "NOASSERTION",
    "licenseConcluded": "NOASSERTION",
    "copyrightText": "NOASSERTION",
    "attributionTexts": [
      "Bundle includes offline RKE2 artifacts staged by rke2nodeinit image action."
    ]
  }
]

relationships = [
  {
    "spdxElementId": "SPDXRef-DOCUMENT",
    "relationshipType": "DESCRIBES",
    "relatedSpdxElement": root_spdx_id
  }
]

for index, artifact in enumerate(artifacts):
  path = artifact.get('path', '')
  name = path.split('/')[-1] if path else 'artifact'
  pkg_spdx_id = package_spdx_id(path, name, index)
  sha = artifact.get('sha256') or "NOASSERTION"
  source = artifact.get('source') or "NOASSERTION"
  verified = artifact.get('verified') or "unknown"

  pkg = {
    "SPDXID": pkg_spdx_id,
    "name": name,
    "versionInfo": "NOASSERTION",
    "supplier": "Organization: rke2-node-init",
    "downloadLocation": "NOASSERTION",
    "packageFileName": path,
    "checksums": [{
      "algorithm": "SHA256",
      "checksumValue": sha
    }] if sha != "NOASSERTION" else [],
    "primaryPackagePurpose": "BINARY",
    "licenseDeclared": "NOASSERTION",
    "licenseConcluded": "NOASSERTION",
    "copyrightText": "NOASSERTION",
    "attributionTexts": [
      f"source={source}; verified={verified}"
    ]
  }
  packages.append(pkg)
  relationships.append({
    "spdxElementId": root_spdx_id,
    "relationshipType": "CONTAINS",
    "relatedSpdxElement": pkg_spdx_id
  })

external_document_refs = []
if staged_json:
  try:
    with open(staged_json, 'rb') as sf:
      staged_bytes = sf.read()
    staged_sha = hashlib.sha256(staged_bytes).hexdigest()
    external_document_refs.append({
      "externalDocumentId": "DocumentRef-rke2-stage-manifest",
      "spdxDocument": f"file://{staged_json}",
      "checksum": {
        "algorithm": "SHA256",
        "checksumValue": staged_sha
      }
    })
  except Exception:
    pass

data = {
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": doc_name,
  "documentNamespace": doc_namespace,
  "creationInfo": {
    "created": created,
    "creators": [
      "Tool: rke2nodeinit"
    ],
    "comment": f"Generated from image action artifacts; security_score={summary.get('security_score', 'unknown')}"
  },
  "documentDescribes": [
    root_spdx_id
  ],
  "packages": packages,
  "relationships": relationships,
  "annotations": [
    {
      "annotationDate": created,
      "annotationType": "OTHER",
      "annotator": "Tool: rke2nodeinit",
      "comment": f"artifacts_discovered={summary.get('artifacts_discovered', 0)}, artifacts_verified={summary.get('artifacts_verified', 0)}, sha256_manifest_present={summary.get('sha256_manifest_present', 'unknown')}"
    }
  ]
}

if external_document_refs:
  data["externalDocumentRefs"] = external_document_refs

with open(sbom_json, 'w', encoding='utf-8') as out:
  json.dump(data, out, indent=2)
print(sbom_json)
PY
    if [[ $? -eq 0 ]]; then
      log_success "JSON SBOM generated: $sbom_json_file"
      metrics_increment "total"
      metrics_increment "success"
      metrics_increment "json_sbom_created"
    else
      log_warn "Failed to generate JSON SBOM: $sbom_json_file"
      log_warn "Text SBOM is still available at: $sbom_file"
    fi
  else
    log_warn "python3 not available - skipping JSON SBOM generation"
    log_info "Text SBOM available at: $sbom_file"
  fi

  # Generate README documentation in outputs directory
  log_info "Generating README documentation"
  if [[ -n "${RUN_OUT_DIR:-}" ]]; then
    {
      echo "# Air-Gapped Image Prep Summary"
      echo "Name: ${SPEC_NAME}"
      echo "Timestamp (UTC): $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
      echo "RKE2_VERSION: ${RKE2_VERSION}"
      echo "nerdctl FULL: ${full_tgz:-<not cached>}"
      echo "nerdctl standalone: ${std_tgz:-<not cached>}"
      echo "Registry: ${REGISTRY:-<none>}"
      echo "Custom CA: ${CA_ROOT:-<none>} (installed to OS trust: ${CA_INSTALL})"
      echo "Staged:"
      echo "  - /var/lib/rancher/rke2/agent/images/${IMAGES_TAR}"
      echo "  - $STAGE_DIR/${RKE2_TARBALL}, $STAGE_DIR/${SHA256_FILE}, $STAGE_DIR/install.sh"
      echo "Defaults:"
      echo "  - DNS: ${defaultDnsCsv}"
      echo "  - Search Domains: ${defaultSearchCsv:-<none>}"
      echo
      echo "Next Steps:"
      echo "  - Shut down this VM and clone it for use in the air-gapped environment"
      echo "  - Run this script in 'server' or 'agent' mode on the clone(s)"
    } > "$RUN_OUT_DIR/README.txt"
    log_info "README written to: $RUN_OUT_DIR/README.txt"
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "readme_created"
  fi

  # Display final summary and metrics
  log_success "========================================="
  log_success "Image preparation completed successfully"
  log_success "========================================="
  
  metrics_summary "Image Preparation Summary"
  
  log_info ""
  log_info "Artifacts cached in: $DOWNLOADS_DIR"
  log_info "SBOM available at: $sbom_file"
  log_info "Security score: ${security_score}/100"
  log_info ""
  
  # Check if boot service is enabled
  local boot_status="NOT INSTALLED"
  if systemctl is-enabled rke2-boot.service &>/dev/null; then
    boot_status="ENABLED - will run automatically on next boot"
  elif [[ -f "$BOOT_SERVICE_PATH" ]]; then
    boot_status="installed but DISABLED - manual start required"
  fi
  
  log_info "Next steps:"
  log_info "  1. Review SBOM and verify all artifacts"
  if [[ "$boot_status" == "ENABLED"* ]]; then
    log_info "  2. Place node-specific YAML configs in: $REPO_ROOT/configs/"
    log_info "     - Naming pattern: {hostname}.yaml (e.g., node01.yaml)"
    log_info "     - Boot service will auto-discover configs by VM hostname"
    
    # Add Hyper-V specific instructions
    if [[ "$(detect_vm_platform)" == "hyperv" ]]; then
      log_info "  3. Configure VM names on Hyper-V host (PowerShell on host):"
      log_info "     Set-VMKeyValuePairItem -VMName \"<vm-name>\" -Key \"VirtualMachineName\" -Value \"<vm-name>\""
      log_info "     (Without this, guest hostname will be used as fallback)"
      log_info "  4. Clone/template this VM for deployment"
      log_info "  5. First boot will automatically:"
    else
      log_info "  3. Clone/template this VM for deployment"
      log_info "  4. First boot will automatically:"
    fi
    log_info "     - Query VM hostname from hypervisor"
    log_info "     - Search for matching config: {hostname}.yaml"
    log_info "     - Copy config to: $BOOT_TARGET_DIR/{hostname}.yaml"
    log_info "     - Execute: rke2nodeinit.sh -f {config} -y"
    log_info ""
    log_info "Boot service status: $boot_status"
    log_info "Config search paths:"
    for search_path in "${BOOT_CONFIG_SEARCH_PATHS[@]}"; do
      log_info "  - $search_path"
    done
  else
    log_info "  2. Clone this VM for air-gapped deployment"
    log_info "  3. Run 'server' or 'agent' action on cloned nodes"
    log_info ""
    log_info "Boot service status: $boot_status"
  fi
  
  # Prompt for shutdown if boot service is enabled (template preparation)
  # Otherwise prompt for reboot (standard workflow)
  echo
  if [[ "$boot_status" == "ENABLED"* ]]; then
    log_info "Ready to shutdown and prepare template VM for cloning"
    prompt_shutdown
  else
    prompt_reboot
  fi
}

# ------------------------------------------------------------------------------
# Function: action_list_images
# Purpose : Emit a full list of files contained in the RKE2 images archive
#           (and optionally the release manifest entries) so operators can
#           inspect exactly which component bundles are present in a release.
# Arguments:
#   None
# Returns :
#   0 on success, non-zero on error
# ------------------------------------------------------------------------------
action_list_images() {
  initialize_action_context false "list-images"
  log INFO "Listing RKE2 images archive contents and manifest entries (if present)"

  local IMAGES_TAR="rke2-images.linux-${ARCH}.tar.zst"
  local images_candidate=""
  local IMAGES_DIR="${INSTALL_RKE2_AGENT_IMAGES_DIR:-/var/lib/rancher/rke2/agent/images}"

  if [[ -f "$DOWNLOADS_DIR/$IMAGES_TAR" ]]; then
    images_candidate="$DOWNLOADS_DIR/$IMAGES_TAR"
  elif [[ -f "$IMAGES_DIR/$IMAGES_TAR" ]]; then
    images_candidate="$IMAGES_DIR/$IMAGES_TAR"
  fi

  if [[ -z "$images_candidate" ]]; then
    log ERROR "Images archive not found in $DOWNLOADS_DIR or $IMAGES_DIR: $IMAGES_TAR"
    return 3
  fi

  log INFO "Found images archive: $images_candidate"

  # Prefer zstd tools to stream the archive listing
  # We intentionally hide the OCI blob files (under blobs/) which are
  # internal layer storage and not useful to operators when listing bundle
  # contents; filter them out for readability.
  local _filter="grep -v -E '^blobs(/|$)'"
  if command -v zstd >/dev/null 2>&1; then
    log INFO "Listing archive (via zstd -dc | tar -tf) — hiding blobs/ entries"
    zstd -dc "$images_candidate" | tar -tf - | eval "$_filter"
  elif command -v zstdcat >/dev/null 2>&1; then
    log INFO "Listing archive (via zstdcat | tar -tf) — hiding blobs/ entries"
    zstdcat "$images_candidate" | tar -tf - | eval "$_filter"
  else
    # If it's a plain gzip or tar, attempt fallback
    if [[ "$images_candidate" == *.tar.gz ]]; then
      log INFO "Listing gzip-compressed archive (tar -tzf) — hiding blobs/ entries"
      tar -tzf "$images_candidate" | eval "$_filter"
    else
      log ERROR "No zstd available to read $images_candidate; please install zstd to list .zst archives"
      return 2
    fi
  fi

  # Also show manifest entries if available in downloads or stage
  local sha_file="$DOWNLOADS_DIR/${SHA256_FILE:-sha256sum-${ARCH}.txt}"
  if [[ -f "$sha_file" ]]; then
    echo
    log INFO "Release manifest entries from: $sha_file"
    awk '{print $2}' "$sha_file" | sort -u
  else
    log INFO "No release sha256 manifest found in $DOWNLOADS_DIR"
  fi

  return 0
}

# ==============
# Action: SERVER (bootstrap a brand-new control plane)
# Uses cached artifacts from action_image() and writes /etc/rancher/rke2/config.yaml
# ------------------------------------------------------------------------------
# Function: action_server
# Purpose : Configure an offline RKE2 server node including network settings,
#           TLS SANs, custom CA integration, and execution of the installer.
# Arguments:
#   None
# Returns :
#   Exits on failure; prompts for reboot when complete.
# Note    : This is a large orchestration function (~200+ lines). For future
#           maintainability, consider extracting repeated validation/prompt
#           patterns into helper functions like validate_network_config(),
#           prompt_for_network_settings(), or generate_rke2_config().
# ------------------------------------------------------------------------------
action_server() {
  initialize_action_context false "server"
  
  # Detect if running via boot service
  local via_boot_service=0
  if [[ -n "${RKE2_BOOT_SERVICE:-}" ]] && [[ "${RKE2_BOOT_SERVICE}" == "true" ]]; then
    via_boot_service=1
    log_info "═══════════════════════════════════════"
    log_info "Execution initiated via rke2-boot service"
    log_info "═══════════════════════════════════════"
  fi
  
  # Check for dry-run mode
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    log_info "========================================"
    log_info "DRY-RUN MODE: RKE2 Server Initialization"
    log_info "========================================"
    log_info "No changes will be made to the system"
    log_info ""
  fi
  
  log_info "========================================"
  log_info "RKE2 First Server Initialization"
  log_info "========================================"
  
  # Initialize metrics for comprehensive tracking
  metrics_init "server_deployment"
  
  log_info "Ensure YAML has metadata.name..."

  # Phase 1: Load configuration
  report_progress "Loading configuration" 1 8
  log_info "Loading site defaults..."
  load_site_defaults
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "site_defaults_loaded"

  ensure_fips_before_install

  local IP="" PREFIX="" HOSTNAME="" DNS="" SEARCH=""
  local TLS_SANS_IN="" TLS_SANS="" TOKEN="" GW=""
  local -a NET_INTERFACES=()

  log_info "Reading configuration from YAML (if provided)..."
  if [[ -n "$CONFIG_FILE" ]]; then
    if ! validate_file_exists "$CONFIG_FILE" "configuration file"; then
      log_error "Configuration file not found: $CONFIG_FILE"
      metrics_increment "total"
      metrics_increment "failed"
      exit 1
    fi
    
    IP="$(yaml_spec_get "$CONFIG_FILE" ip || true)"
    PREFIX="$(yaml_spec_get "$CONFIG_FILE" prefix || true)"
    HOSTNAME="$(yaml_spec_get "$CONFIG_FILE" hostname || true)"
    GW="$(yaml_spec_get "$CONFIG_FILE" gateway || true)"
    local d sd ts
    d="$(yaml_spec_get "$CONFIG_FILE" dns || true)"; [[ -n "$d"  ]] && DNS="$(normalize_list_csv "$d")"
    sd="$(yaml_spec_get "$CONFIG_FILE" searchDomains || true)"; [[ -n "$sd" ]] && SEARCH="$(normalize_list_csv "$sd")"
    ts="$(yaml_spec_get_any "$CONFIG_FILE" tlsSans tls-san || true)"; [[ -z "$ts" ]] && ts="$(yaml_spec_list_csv "$CONFIG_FILE" tls-san || true)"; [[ -n "$ts" ]] && TLS_SANS_IN="$(normalize_list_csv "$ts")"
    TOKEN="$(yaml_spec_get "$CONFIG_FILE" token || true)"
    TOKEN_FILE="$(yaml_spec_get "$CONFIG_FILE" tokenFile || true)"
    load_custom_ca_from_config "$CONFIG_FILE"
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "config_loaded"
  fi

  log_info "Reading configuration from CLI args (if provided)..."
  local -A server_cli=()
  parse_action_cli_args server_cli "server" "${ACTION_ARGS[@]}"

  local yaml_has_interfaces=0
  if [[ -n "$CONFIG_FILE" ]] && yaml_spec_has_list "$CONFIG_FILE" "interfaces"; then
    yaml_has_interfaces=1
  fi

  # Phase 2: Merge and validate configuration
  report_progress "Validating configuration" 2 8
  log_info "Merging configuration values..."
  if [[ -z "$HOSTNAME" && -n "${server_cli[hostname]:-}" ]]; then
    HOSTNAME="${server_cli[hostname]}"
  fi
  if [[ -z "$IP" && -n "${server_cli[ip]:-}" ]]; then
    IP="${server_cli[ip]}"
  fi
  if [[ -z "$PREFIX" && -n "${server_cli[prefix]:-}" ]]; then
    PREFIX="${server_cli[prefix]}"
  fi
  if [[ -z "$GW" && -n "${server_cli[gateway]:-}" ]]; then
    GW="${server_cli[gateway]}"
  fi
  if [[ -z "$DNS" && -n "${server_cli[dns]:-}" ]]; then
    DNS="$(normalize_list_csv "${server_cli[dns]}")"
  fi
  if [[ -z "$SEARCH" && -n "${server_cli[search_domains]:-}" ]]; then
    SEARCH="$(normalize_list_csv "${server_cli[search_domains]}")"
  fi
  if [[ -z "$TOKEN" && -n "${server_cli[token]:-}" ]]; then
    TOKEN="${server_cli[token]}"
  fi
  if [[ -z "$TOKEN_FILE" && -n "${server_cli[token_file]:-}" ]]; then
    TOKEN_FILE="${server_cli[token_file]}"
  fi
  if [[ -z "$TLS_SANS_IN" && -n "${server_cli[tls_sans]:-}" ]]; then
    TLS_SANS_IN="${server_cli[tls_sans]}"
    TLS_SANS="$(normalize_list_csv "$TLS_SANS_IN")"
  fi

  collect_interface_specs NET_INTERFACES "$CONFIG_FILE" "${server_cli[interfaces]:-}"
  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH

  log_info "Prompting for any missing configuration values..."
  if [[ -z "$HOSTNAME" ]];then read -rp "Enter hostname for this server node: " HOSTNAME; fi
  if [[ -z "$IP" ]];      then read -rp "Enter static IPv4 for this server node: " IP; fi
  if [[ -z "$PREFIX" ]];  then read -rp "Enter subnet prefix length (0-32) [default 24]: " PREFIX; fi
  if [[ -z "$GW" ]];      then read -rp "Enter default gateway IPv4 [leave blank to skip]: " GW || true; fi

  log_info "Resolving DNS and search domains..."
  if [[ -z "$DNS" ]]; then
    read -rp "Enter DNS IPv4s (comma-separated) [blank=default ${DEFAULT_DNS}]: " DNS || true
    [[ -z "$DNS" ]] && DNS="$DEFAULT_DNS"
  fi
  if [[ -z "$SEARCH" && -n "${DEFAULT_SEARCH:-}" ]]; then
    SEARCH="$DEFAULT_SEARCH"
  fi

  log_info "Validating configuration..."
  while ! valid_ipv4 "$IP"; do read -rp "Invalid IPv4. Re-enter server IP: " IP; done
  while ! valid_prefix "${PREFIX:-}"; do read -rp "Invalid prefix (0-32). Re-enter [default 24]: " PREFIX; done
  while ! valid_ipv4_or_blank "${GW:-}"; do read -rp "Invalid gateway IPv4 (or blank). Re-enter: " GW; done
  while ! valid_csv_dns "${DNS:-}"; do read -rp "Invalid DNS list. Re-enter CSV IPv4s: " DNS; done
  while ! valid_search_domains_csv "${SEARCH:-}"; do read -rp "Invalid search domains CSV. Re-enter: " SEARCH; done
  [[ -z "${PREFIX:-}" ]] && PREFIX=24

  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "config_validated"

  # Phase 3: Network configuration
  report_progress "Configuring network" 3 8
  log_info "Determining TLS SANs..."
  if [[ -z "$TLS_SANS" ]]; then
    if [[ -z "$TLS_SANS_IN" && -n "${CONFIG_FILE:-}" ]]; then
      TLS_SANS_IN="$(yaml_spec_get "$CONFIG_FILE" tlsSans || true)"
      [[ -z "$TLS_SANS_IN" ]] && TLS_SANS_IN="$(yaml_spec_list_csv "$CONFIG_FILE" tls-san || true)"
      [[ -n "$TLS_SANS_IN" ]] && TLS_SANS="$(normalize_list_csv "$TLS_SANS_IN")"
	  log_info "TLS SANs from config: $TLS_SANS"
    fi
    if [[ -z "$TLS_SANS" ]]; then
      TLS_SANS="$(capture_sans "$HOSTNAME" "$IP" "$SEARCH")"
      log_info "Auto-derived TLS SANs: $TLS_SANS"
    fi
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "tls_sans_configured"

  # Phase 4: Stage artifacts
  report_progress "Staging RKE2 artifacts" 4 8
  log_info "Ensuring staged artifacts for offline RKE2 server install..."
  if ! ensure_staged_artifacts; then
    log_error "Failed to ensure staged artifacts"
    log_error "Remediation: Check $STAGE_DIR and re-run 'image' action"
    metrics_increment "failed"
    exit 3
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "artifacts_staged"

  # Phase 5: System configuration
  report_progress "Configuring system" 5 8
  log_info "Setting new hostname: $HOSTNAME..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    hostnamectl set-hostname "$HOSTNAME"
    if ! grep -qE "[[:space:]]$HOSTNAME(\$|[[:space:]])" /etc/hosts; then 
      echo "$IP $HOSTNAME" >> /etc/hosts
    fi
  else
    log_info "DRY-RUN: Would set hostname to $HOSTNAME and update /etc/hosts"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "hostname_set"

  BOOTSTRAP_TOKEN_FILE="$TOKEN_FILE"
  log_info "Seeding custom cluster CA..."
  setup_custom_cluster_ca || true
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "custom_ca_configured"

  # Phase 6: Interface configuration
  report_progress "Configuring interfaces" 6 8
  local prompt_extra_ifaces=1
  if (( ${#NET_INTERFACES[@]} )); then
    if (( yaml_has_interfaces )); then
      prompt_extra_ifaces=0
      log_info "Interfaces defined in YAML manifest; skipping interactive prompt for additional NICs."
    elif [[ -n "${server_cli[interfaces]:-}" ]]; then
      prompt_extra_ifaces=0
      log_info "Interfaces provided via CLI flags; skipping interactive prompt for additional NICs."
    fi
  fi

  if (( prompt_extra_ifaces )); then
    prompt_additional_interfaces NET_INTERFACES "${DNS:-$DEFAULT_DNS}" "server"
  fi
  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH
  if (( ${#NET_INTERFACES[@]} )); then
    local _iface_summary=""
    local _encoded
    for _encoded in "${NET_INTERFACES[@]}"; do
      local -A _nic_dbg=()
      if ! interface_decode_entry "$_encoded" _nic_dbg; then
        log_warn "Skipping invalid interface entry in summary"
        continue
      fi
      local _name_dbg="${_nic_dbg[name]:-<auto>}"
      local _desc_dbg=""
      if [[ "${_nic_dbg[dhcp4]:-}" =~ ^([Tt]rue)$ ]]; then
        _desc_dbg="dhcp4"
      elif [[ -n "${_nic_dbg[ip]:-}" ]]; then
        _desc_dbg="${_nic_dbg[ip]}"
        if [[ -n "${_nic_dbg[prefix]:-}" ]]; then
          _desc_dbg+="/${_nic_dbg[prefix]}"
        fi
      elif [[ -n "${_nic_dbg[cidr]:-}" ]]; then
        _desc_dbg="${_nic_dbg[cidr]}"
      fi
      [[ -z "$_desc_dbg" ]] && _desc_dbg="static"
      _iface_summary+="${_iface_summary:+; }${_name_dbg}:${_desc_dbg}"
    done
    log_info "Network interfaces prepared: ${_iface_summary}"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "interfaces_configured"

  # Phase 7: Token and RKE2 configuration
  report_progress "Writing RKE2 configuration" 7 8
  log_info "Validating/expanding provided token (if any)..."
  if [[ -n "$TOKEN_FILE" ]]; then
    log_info "Token file provided; skipping token expansion/generation."
    TOKEN=""
  elif [[ -n "$TOKEN" ]]; then
    local full_token
    full_token="$(ensure_full_cluster_token "$TOKEN")"
    if [[ -n "$full_token" ]]; then
      if [[ "$full_token" != "$TOKEN" ]]; then
        log_info "Expanded provided token to full format (custom CA hash included)."
      fi
      TOKEN="$full_token"
    fi
  else
    TOKEN="$(generate_bootstrap_token)"
    if [[ "$TOKEN" =~ ^K10[0-9a-fA-F]{64}::server: ]]; then
      log_info "Using generated secure first-server token (custom CA fingerprint embedded)."
    else
      log_info "Using generated short first-server bootstrap token."
    fi
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "token_generated"

  log_info "Writing file: /etc/rancher/rke2/config.yaml..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    mkdir -p /etc/rancher/rke2

    : > /etc/rancher/rke2/config.yaml
    {
      log_debug "Setting debug..." >&2
      echo "debug: true"

      log_debug "Get token..." >&2
      if [[ -n "$TOKEN" ]]; then
        echo "token: $TOKEN"
	    log_debug "Using provided token..." >&2
      elif [[ -n "$TOKEN_FILE" ]]; then
        echo "token-file: \"$TOKEN_FILE\""
	    log_debug "Using provided token file: $TOKEN_FILE..." >&2
      fi

      log_debug "Append additional keys from YAML spec (cluster-cidr, domain, cni, etc.)..." >&2
      append_spec_config_extras "$CONFIG_FILE"

      # Kubelet defaults (safe; additive). Merge-friendly if you later append more.
      echo "kubelet-arg:"
      # Prefer systemd-resolved if present
      if [[ -f /run/systemd/resolve/resolv.conf ]]; then
        echo "  - resolv-conf=/run/systemd/resolve/resolv.conf"
      fi
      echo "  - container-log-max-size=10Mi"
      echo "  - container-log-max-files=5"
  	  echo

    } >> /etc/rancher/rke2/config.yaml
    log_info "Wrote /etc/rancher/rke2/config.yaml"

    log_debug "Setting file security: chmod 600 /etc/rancher/rke2/config.yaml..."
    chmod 600 /etc/rancher/rke2/config.yaml
  else
    log_info "DRY-RUN: Would write /etc/rancher/rke2/config.yaml"
    log_info "DRY-RUN: Token would be: ${TOKEN:0:20}..."
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "config_written"

  log_info "Writing netplan configuration and applying network settings..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    if (( ${#NET_INTERFACES[@]} )); then
      write_netplan --interfaces "${NET_INTERFACES[@]}"
    else
      write_netplan "$IP" "$PREFIX" "${GW:-}" "${DNS:-}" "${SEARCH:-}"
    fi
  else
    log_info "DRY-RUN: Would write netplan configuration for $IP/$PREFIX"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "netplan_written"

  # Phase 8: Install RKE2
  report_progress "Installing RKE2 server" 8 8
  local exported_node_token=""
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    cleanup_containerd_before_rke2 "rke2-server"

    log_info "Installing rke2-server from cache at $STAGE_DIR"
    if ! run_rke2_installer "$STAGE_DIR" "server"; then
      log_error "Failed to install RKE2 server"
      log_error "Remediation: Check $LOG_FILE for details"
      metrics_increment "failed"
      exit 3
    fi
    systemctl enable rke2-server >>"$LOG_FILE" 2>&1 || true
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "rke2_installed"

    log_info "Deploying flannel TX checksum offload fix..."
    install_flannel_txcsum_fix
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "flannel_fix_installed"

    # Export server node token into outputs for operator convenience when
    # available at this stage. If the file is not present yet, keep workflow
    # non-fatal and rely on post-reboot retrieval guidance.
    local server_node_token="/var/lib/rancher/rke2/server/node-token"
    local token_export_path="$OUT_DIR/${SPEC_NAME:-server}-node-token.txt"
    if [[ -f "$server_node_token" ]]; then
      if cp -f "$server_node_token" "$token_export_path" >>"$LOG_FILE" 2>&1; then
        chmod 600 "$token_export_path" >>"$LOG_FILE" 2>&1 || true
        exported_node_token="$token_export_path"
        log_info "Exported server node token to: $exported_node_token"
      else
        log_warn "Failed to export server node token to $token_export_path"
      fi
    else
      log_info "Server node token not present yet; retrieve after reboot from /var/lib/rancher/rke2/server/node-token"
    fi

  else
    log_info "DRY-RUN: Would install RKE2 server from $STAGE_DIR"
    log_info "DRY-RUN: Would enable rke2-server service"
    log_info "DRY-RUN: Would install flannel TX checksum fix"
  fi

  # Display summary
  log_success "========================================="
  log_success "Server initialization completed"
  log_success "========================================="
  
  # Cleanup boot service if running in oneshot mode via boot service
  if [[ $via_boot_service -eq 1 ]] && [[ "$BOOT_SERVICE_MODE" == "oneshot" ]]; then
    log_info "Disabling boot service (oneshot mode)..."
    if disable_boot_service; then
      log_info "✓ Boot service disabled after successful oneshot execution"
    else
      log_warn "Failed to disable boot service; may run again on next boot"
    fi
  fi
  
  metrics_summary "Server Deployment Summary"
  
  log_info ""
  log_info "Configuration:"
  log_info "  Hostname: $HOSTNAME"
  log_info "  IP Address: $IP/$PREFIX"
  log_info "  Gateway: ${GW:-<none>}"
  log_info "  DNS: $DNS"
  log_info "  Search Domains: ${SEARCH:-<none>}"
  log_info ""
  log_info "Next steps:"
  log_info "  1. Reboot the system to apply changes"
  log_info "  2. After reboot, check cluster status: kubectl get nodes"
  log_info "  3. Retrieve node token: cat /var/lib/rancher/rke2/server/node-token"
  log_info "  4. Use token to join additional servers or agents"
  if [[ -n "$exported_node_token" ]]; then
    log_info "  5. Exported token copy: $exported_node_token"
  fi

  echo
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    echo "[READY] rke2-server installed. Reboot to initialize the control plane."
    echo "        First server token: /var/lib/rancher/rke2/server/node-token"
  else
    echo "[DRY-RUN] Server configuration validated. No changes made."
  fi
  echo
  prompt_reboot
}

# ==================
# Action: AGENT
# ------------------------------------------------------------------------------
# Function: action_agent
# Purpose : Configure an offline RKE2 agent node, prompting for network settings
#           and join information, then running the installer and persisting
#           artifacts for auditing.
# Arguments:
#   None
# Returns :
#   Exits on failure; prompts for reboot upon success.
# Note    : Similar to action_server, this orchestrates multiple concerns.
#           Consider refactoring shared network validation, YAML parsing,
#           and config generation logic into reusable helpers.
# ------------------------------------------------------------------------------
action_agent() {
  initialize_action_context true "agent"
  
  # Detect if running via boot service
  local via_boot_service=0
  if [[ -n "${RKE2_BOOT_SERVICE:-}" ]] && [[ "${RKE2_BOOT_SERVICE}" == "true" ]]; then
    via_boot_service=1
    log_info "═══════════════════════════════════════"
    log_info "Execution initiated via rke2-boot service"
    log_info "═══════════════════════════════════════"
  fi
  
  # Check for dry-run mode
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    log_info "========================================"
    log_info "DRY-RUN MODE: RKE2 Agent Node Join"
    log_info "========================================"
    log_info "No changes will be made to the system"
    log_info ""
  fi
  
  log_info "========================================"
  log_info "RKE2 Agent Node Join"
  log_info "========================================"
  
  # Initialize metrics for comprehensive tracking
  metrics_init "agent_deployment"
  
  log_info "Ensure YAML has metadata.name..."

  # Phase 1: Load configuration
  report_progress "Loading configuration" 1 8
  log_info "Loading site defaults..."
  load_site_defaults
  metrics_increment "site_defaults_loaded"

  ensure_fips_before_install

  local IP="" PREFIX="" HOSTNAME="" DNS="" SEARCH=""
  local TOKEN="" GW=""  URL="" TOKEN_FILE=""
  local -a NET_INTERFACES=()
  local NODE_IP_SPEC="" NODE_NAME_SPEC=""

  log_info "Reading configuration from YAML (if provided)..."
  if [[ -n "$CONFIG_FILE" ]]; then
    if ! validate_file_exists "$CONFIG_FILE" "configuration file"; then
      log_error "Configuration file not found: $CONFIG_FILE"
      metrics_increment "failed"
      exit 1
    fi
    
    IP="$(yaml_spec_get "$CONFIG_FILE" ip || true)"
    PREFIX="$(yaml_spec_get "$CONFIG_FILE" prefix || true)"
    HOSTNAME="$(yaml_spec_get "$CONFIG_FILE" hostname || true)"
    GW="$(yaml_spec_get "$CONFIG_FILE" gateway || true)"
    local d sd
    d="$(yaml_spec_get "$CONFIG_FILE" dns || true)"; [[ -n "$d" ]] && DNS="$(normalize_list_csv "$d")"
    sd="$(yaml_spec_get "$CONFIG_FILE" searchDomains || true)"; [[ -n "$sd" ]] && SEARCH="$(normalize_list_csv "$sd")"
    TOKEN="$(yaml_spec_get "$CONFIG_FILE" token || true)"
    TOKEN_FILE="$(yaml_spec_get_any "$CONFIG_FILE" tokenFile token-file || true)"
    URL="$(yaml_spec_get_any "$CONFIG_FILE" serverURL server url || true)"
    load_custom_ca_from_config "$CONFIG_FILE"
    metrics_increment "config_loaded"
  fi

  log INFO "Reading configuration from CLI args (if provided)..."
  local -A agent_cli=()
  parse_action_cli_args agent_cli "agent" "${ACTION_ARGS[@]}"

  local yaml_has_interfaces_agent=0
  if [[ -n "$CONFIG_FILE" ]] && yaml_spec_has_list "$CONFIG_FILE" "interfaces"; then
    yaml_has_interfaces_agent=1
  fi

  log INFO "Merging configuration values..."
  if [[ -z "$HOSTNAME" && -n "${agent_cli[hostname]:-}" ]]; then
    HOSTNAME="${agent_cli[hostname]}"
  fi
  if [[ -z "$IP" && -n "${agent_cli[ip]:-}" ]]; then
    IP="${agent_cli[ip]}"
  fi
  if [[ -z "$PREFIX" && -n "${agent_cli[prefix]:-}" ]]; then
    PREFIX="${agent_cli[prefix]}"
  fi
  if [[ -z "$GW" && -n "${agent_cli[gateway]:-}" ]]; then
    GW="${agent_cli[gateway]}"
  fi
  if [[ -z "$DNS" && -n "${agent_cli[dns]:-}" ]]; then
    DNS="$(normalize_list_csv "${agent_cli[dns]}")"
  fi
  if [[ -z "$SEARCH" && -n "${agent_cli[search_domains]:-}" ]]; then
    SEARCH="$(normalize_list_csv "${agent_cli[search_domains]}")"
  fi
  if [[ -z "$TOKEN" && -n "${agent_cli[token]:-}" ]]; then
    TOKEN="${agent_cli[token]}"
  fi
  if [[ -z "$TOKEN_FILE" && -n "${agent_cli[token_file]:-}" ]]; then
    TOKEN_FILE="${agent_cli[token_file]}"
  fi
  if [[ -z "$URL" && -n "${agent_cli[server_url]:-}" ]]; then
    URL="${agent_cli[server_url]}"
  fi

  collect_interface_specs NET_INTERFACES "$CONFIG_FILE" "${agent_cli[interfaces]:-}"
  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH

  # Phase 2: Validate configuration
  report_progress "Validating configuration" 2 8
  log_info "Prompting for any missing configuration values..."
  if [[ -z "$HOSTNAME" ]];then read -rp "Enter hostname for this agent node: " HOSTNAME; fi
  if [[ -z "$IP" ]];      then read -rp "Enter static IPv4 for this agent node: " IP; fi
  if [[ -z "$PREFIX" ]];  then read -rp "Enter subnet prefix length (0-32) [default 24]: " PREFIX; fi
  if [[ -z "$GW" ]];      then read -rp "Enter default gateway IPv4 [leave blank to skip]: " GW || true; fi

  log_info "Resolving DNS and search domains..."
  if [[ -z "$DNS" ]]; then
    read -rp "Enter DNS IPv4s (comma-separated) [blank=default ${DEFAULT_DNS}]: " DNS || true
    if [[ -z "$DNS" ]]; then DNS="$DEFAULT_DNS"; log_info "Using default DNS for agent: $DNS"; fi
  fi
  if [[ -z "$SEARCH" && -n "${DEFAULT_SEARCH:-}" ]]; then
    SEARCH="$DEFAULT_SEARCH"
    log_info "Using default search domains for agent: $SEARCH"
  fi

  log_info "Validating configuration..."
  while ! valid_ipv4 "$IP"; do read -rp "Invalid IPv4. Re-enter agent IP: " IP; done
  while ! valid_prefix "${PREFIX:-}"; do read -rp "Invalid prefix (0-32). Re-enter agent prefix [default 24]: " PREFIX; done
  while ! valid_ipv4_or_blank "${GW:-}"; do read -rp "Invalid gateway IPv4 (or blank). Re-enter: " GW; done
  while ! valid_csv_dns "${DNS:-}"; do read -rp "Invalid DNS list. Re-enter CSV IPv4s: " DNS; done
  while ! valid_search_domains_csv "${SEARCH:-}"; do read -rp "Invalid search domain list. Re-enter CSV: " SEARCH; done
  [[ -z "${PREFIX:-}" ]] && PREFIX=24

  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH
  metrics_increment "config_validated"

  # Phase 3: Stage artifacts
  report_progress "Staging RKE2 artifacts" 3 8
  log_info "Ensuring staged artifacts for offline RKE2 agent install..."
  if ! ensure_staged_artifacts; then
    log_error "Failed to ensure staged artifacts"
    log_error "Remediation: Check $STAGE_DIR and re-run 'image' action"
    metrics_increment "failed"
    exit 3
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "artifacts_staged"

  # Phase 4: Configure system
  report_progress "Configuring system" 4 8
  log_info "Setting new hostname: $HOSTNAME..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    hostnamectl set-hostname "$HOSTNAME"
    if ! grep -qE "[[:space:]]$HOSTNAME(\$|[[:space:]])" /etc/hosts; then echo "$IP $HOSTNAME" >> /etc/hosts; fi
  else
    log_info "DRY-RUN: Would set hostname to $HOSTNAME and update /etc/hosts"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "hostname_set"

  local prompt_extra_ifaces_agent=1
  if (( ${#NET_INTERFACES[@]} )); then
    if (( yaml_has_interfaces_agent )); then
      prompt_extra_ifaces_agent=0
      log INFO "Interfaces defined in YAML manifest; skipping interactive prompt for additional NICs."
    elif [[ -n "${agent_cli[interfaces]:-}" ]]; then
      prompt_extra_ifaces_agent=0
      log INFO "Interfaces provided via CLI flags; skipping interactive prompt for additional NICs."
    fi
  fi

  if (( prompt_extra_ifaces_agent )); then
    prompt_additional_interfaces NET_INTERFACES "${DNS:-$DEFAULT_DNS}" "agent"
  fi
  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH
  if (( ${#NET_INTERFACES[@]} )); then
    local _iface_summary=""
    local _encoded
    for _encoded in "${NET_INTERFACES[@]}"; do
      local -A _nic_dbg=()
      if ! interface_decode_entry "$_encoded" _nic_dbg; then
        log WARN "Skipping invalid interface entry in summary"
        continue
      fi
      local _name_dbg="${_nic_dbg[name]:-<auto>}"
      local _desc_dbg=""
      if [[ "${_nic_dbg[dhcp4]:-}" =~ ^([Tt]rue)$ ]]; then
        _desc_dbg="dhcp4"
      elif [[ -n "${_nic_dbg[ip]:-}" ]]; then
        _desc_dbg="${_nic_dbg[ip]}"
        if [[ -n "${_nic_dbg[prefix]:-}" ]]; then
          _desc_dbg+="/${_nic_dbg[prefix]}"
        fi
      elif [[ -n "${_nic_dbg[cidr]:-}" ]]; then
        _desc_dbg="${_nic_dbg[cidr]}"
      fi
      [[ -z "$_desc_dbg" ]] && _desc_dbg="static"
      _iface_summary+="${_iface_summary:+; }${_name_dbg}:${_desc_dbg}"
    done
    log_info "Network interfaces prepared: ${_iface_summary}"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "interfaces_configured"

  # Phase 6: Gather cluster join information
  report_progress "Configuring cluster join" 6 8
  log_info "Gathering cluster join information..."
  if [[ -z "$URL" ]]; then
    read -rp "Enter RKE2 server URL (e.g., https://<server-ip>:9345) [optional]: " URL || true
  fi
  if [[ -n "$URL" && -z "$TOKEN" && -z "$TOKEN_FILE" ]]; then
    read -rp "Enter cluster join token [optional]: " TOKEN || true
  fi
  if [[ -z "$TOKEN" && -z "$TOKEN_FILE" ]]; then
    read -rp "Enter path to token file (optional, used when token not provided): " TOKEN_FILE || true
  fi

  log_info "Validating/expanding provided token (if any)..."
  if [[ -n "$TOKEN_FILE" ]]; then
    log_info "Token file provided; skipping token expansion."
    TOKEN=""
  elif [[ -n "$TOKEN" ]]; then
    local full_token=""
    full_token="$(ensure_full_cluster_token "$TOKEN")"
    if [[ -n "$full_token" ]]; then
      if [[ "$full_token" != "$TOKEN" ]]; then
        log_info "Expanded agent join token to full format (custom CA hash included)."
      fi
      TOKEN="$full_token"
    fi
  fi
  metrics_increment "token_configured"

  # Phase 7: Write RKE2 configuration
  report_progress "Writing RKE2 configuration" 7 8
  log_info "Writing file: /etc/rancher/rke2/config.yaml..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    mkdir -p /etc/rancher/rke2

    : > /etc/rancher/rke2/config.yaml
    {
      log_debug "Setting debug..." >&2
      echo "debug: true"

      log_debug "Setting server URL..." >&2
      echo "server: \"$URL\""     # required

      log_debug "Get token..." >&2
      if [[ -n "$TOKEN" ]]; then
        echo "token: $TOKEN"
	    log_debug "Using provided token..." >&2
      elif [[ -n "$TOKEN_FILE" ]]; then
        echo "token-file: \"$TOKEN_FILE\""
	    log_debug "Using provided token file: $TOKEN_FILE..." >&2
      fi

      log_debug "Append additional keys from YAML spec (cluster-cidr, domain, cni, etc.)..." >&2
      append_spec_config_extras "$CONFIG_FILE"

      # Kubelet defaults (safe; additive). Merge-friendly if you later append more.
      echo "kubelet-arg:"
      # Prefer systemd-resolved if present
      if [[ -f /run/systemd/resolve/resolv.conf ]]; then
        echo "  - resolv-conf=/run/systemd/resolve/resolv.conf"
      fi
      echo "  - container-log-max-size=10Mi"
      echo "  - container-log-max-files=5"
  	  echo

    } >> /etc/rancher/rke2/config.yaml
    log_info "Wrote /etc/rancher/rke2/config.yaml"

    log_debug "Setting file security: chmod 600 /etc/rancher/rke2/config.yaml..."
    chmod 600 /etc/rancher/rke2/config.yaml
  else
    log_info "DRY-RUN: Would write /etc/rancher/rke2/config.yaml"
    log_info "DRY-RUN: Server URL: $URL"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "config_written"

  log_info "Writing netplan configuration and applying network settings..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    if (( ${#NET_INTERFACES[@]} )); then
      write_netplan --interfaces "${NET_INTERFACES[@]}"
    else
      write_netplan "$IP" "$PREFIX" "${GW:-}" "${DNS:-}" "${SEARCH:-}"
    fi
  else
    log_info "DRY-RUN: Would write netplan configuration for $IP/$PREFIX"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "netplan_written"

  # Phase 8: Install RKE2
  report_progress "Installing RKE2 agent" 8 8
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    cleanup_containerd_before_rke2 "rke2-agent"

    log_info "Installing rke2-agent from cache at $STAGE_DIR"
    if ! run_rke2_installer "$STAGE_DIR" "agent"; then
      log_error "Failed to install RKE2 agent"
      log_error "Remediation: Check $LOG_FILE for details"
      metrics_increment "failed"
      exit 3
    fi
    systemctl enable rke2-agent >>"$LOG_FILE" 2>&1 || true
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "rke2_installed"

    log_info "Deploying flannel TX checksum offload fix..."
    install_flannel_txcsum_fix
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "flannel_fix_installed"

  else
    log_info "DRY-RUN: Would install RKE2 agent from $STAGE_DIR"
    log_info "DRY-RUN: Would enable rke2-agent service"
    log_info "DRY-RUN: Would install flannel TX checksum fix"
  fi

  # Display summary
  log_success "========================================="
  log_success "Agent node join completed"
  log_success "========================================="
  
  # Cleanup boot service if running in oneshot mode via boot service
  if [[ $via_boot_service -eq 1 ]] && [[ "$BOOT_SERVICE_MODE" == "oneshot" ]]; then
    log_info "Disabling boot service (oneshot mode)..."
    if disable_boot_service; then
      log_info "✓ Boot service disabled after successful oneshot execution"
    else
      log_warn "Failed to disable boot service; may run again on next boot"
    fi
  fi
  
  metrics_summary "Agent Deployment Summary"
  
  log_info ""
  log_info "Configuration:"
  log_info "  Hostname: $HOSTNAME"
  log_info "  IP Address: $IP/$PREFIX"
  log_info "  Gateway: ${GW:-<none>}"
  log_info "  DNS: $DNS"
  log_info "  Server URL: ${URL:-<not configured>}"
  log_info ""
  log_info "Next steps:"
  log_info "  1. Reboot the system to apply changes"
  log_info "  2. After reboot, verify node joined: kubectl get nodes"
  log_info "  3. Check agent status: systemctl status rke2-agent"

  echo
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    echo "[READY] rke2-agent installed. Reboot to initialize the worker node."
  else
    echo "[DRY-RUN] Agent configuration validated. No changes made."
  fi
  echo
  prompt_reboot
}

# ==================
# Action: ADD_SERVER
# ------------------------------------------------------------------------------
# Function: action_add_server
# Purpose : Enroll an additional server node into an existing RKE2 cluster using
#           staged artifacts and optional custom CA trust.
# Arguments:
#   None
# Returns :
#   Exits on failure; prompts for reboot upon success.
# Note    : Shares substantial logic with action_server. Future refactoring
#           could extract common patterns (YAML parsing, validation, config
#           generation) to reduce duplication and improve maintainability.
# ------------------------------------------------------------------------------
action_add_server() {
  initialize_action_context false "add-server"
  
  # Check if this was invoked via boot service
  local via_boot_service=0
  if [[ -n "${RKE2_BOOT_SERVICE:-}" ]]; then
    via_boot_service=1
    log_info "Detected invocation via rke2-boot service"
  fi
  
  # Check for dry-run mode
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    log_info "========================================"
    log_info "DRY-RUN MODE: RKE2 Add Server Node"
    log_info "========================================"
    log_info "No changes will be made to the system"
    log_info ""
  fi
  
  log_info "========================================"
  log_info "RKE2 Additional Server Node Join"
  log_info "======================================="
  
  # Initialize metrics for comprehensive tracking
  metrics_init "add_server_deployment"
  
  log_info "Ensure YAML has metadata.name..."

  # Phase 1: Load configuration
  report_progress "Loading configuration" 1 8
  log_info "Loading site defaults..."
  load_site_defaults
  metrics_increment "site_defaults_loaded"

  ensure_fips_before_install

  local IP="" PREFIX="" HOSTNAME="" DNS="" SEARCH=""
  local TLS_SANS_IN="" TLS_SANS="" TOKEN="" GW=""
  local URL="" TOKEN_FILE=""
  local -a NET_INTERFACES=()

  log_info "Reading configuration from YAML (if provided)..."
  if [[ -n "$CONFIG_FILE" ]]; then
    if ! validate_file_exists "$CONFIG_FILE" "configuration file"; then
      log_error "Configuration file not found: $CONFIG_FILE"
      metrics_increment "failed"
      exit 1
    fi
    
    IP="$(yaml_spec_get "$CONFIG_FILE" ip || true)"
    PREFIX="$(yaml_spec_get "$CONFIG_FILE" prefix || true)"
    HOSTNAME="$(yaml_spec_get "$CONFIG_FILE" hostname || true)"
    GW="$(yaml_spec_get "$CONFIG_FILE" gateway || true)"
    local d sd ts
    d="$(yaml_spec_get "$CONFIG_FILE" dns || true)"; [[ -n "$d" ]] && DNS="$(normalize_list_csv "$d")"
    sd="$(yaml_spec_get "$CONFIG_FILE" searchDomains || true)"; [[ -n "$sd" ]] && SEARCH="$(normalize_list_csv "$sd")"
    ts="$(yaml_spec_get_any "$CONFIG_FILE" tlsSans tls-san || true)"; [[ -z "$ts" ]] && ts="$(yaml_spec_list_csv "$CONFIG_FILE" tls-san || true)"; [[ -n "$ts" ]] && { TLS_SANS_IN="$(normalize_list_csv "$ts")"; TLS_SANS="$TLS_SANS_IN"; }
    TOKEN="$(yaml_spec_get "$CONFIG_FILE" token || true)"
    TOKEN_FILE="$(yaml_spec_get "$CONFIG_FILE" tokenFile || true)"
    URL="$(yaml_spec_get_any "$CONFIG_FILE" serverURL server url || true)"
    load_custom_ca_from_config "$CONFIG_FILE"
    metrics_increment "config_loaded"
  fi

  log INFO "Reading configuration from CLI args (if provided)..."
  local -A add_server_cli=()
  parse_action_cli_args add_server_cli "add-server" "${ACTION_ARGS[@]}"

  local yaml_has_interfaces_add_server=0
  if [[ -n "$CONFIG_FILE" ]] && yaml_spec_has_list "$CONFIG_FILE" "interfaces"; then
    yaml_has_interfaces_add_server=1
  fi

  log INFO "Merging configuration values..."
  if [[ -z "$HOSTNAME" && -n "${add_server_cli[hostname]:-}" ]]; then
    HOSTNAME="${add_server_cli[hostname]}"
  fi
  if [[ -z "$IP" && -n "${add_server_cli[ip]:-}" ]]; then
    IP="${add_server_cli[ip]}"
  fi
  if [[ -z "$PREFIX" && -n "${add_server_cli[prefix]:-}" ]]; then
    PREFIX="${add_server_cli[prefix]}"
  fi
  if [[ -z "$GW" && -n "${add_server_cli[gateway]:-}" ]]; then
    GW="${add_server_cli[gateway]}"
  fi
  if [[ -z "$DNS" && -n "${add_server_cli[dns]:-}" ]]; then
    DNS="$(normalize_list_csv "${add_server_cli[dns]}")"
  fi
  if [[ -z "$SEARCH" && -n "${add_server_cli[search_domains]:-}" ]]; then
    SEARCH="$(normalize_list_csv "${add_server_cli[search_domains]}")"
  fi
  if [[ -z "$TOKEN" && -n "${add_server_cli[token]:-}" ]]; then
    TOKEN="${add_server_cli[token]}"
  fi
  if [[ -z "$TOKEN_FILE" && -n "${add_server_cli[token_file]:-}" ]]; then
    TOKEN_FILE="${add_server_cli[token_file]}"
  fi
  if [[ -z "$URL" && -n "${add_server_cli[server_url]:-}" ]]; then
    URL="${add_server_cli[server_url]}"
  fi
  if [[ -z "$TLS_SANS_IN" && -n "${add_server_cli[tls_sans]:-}" ]]; then
    TLS_SANS_IN="${add_server_cli[tls_sans]}"
    TLS_SANS="$(normalize_list_csv "$TLS_SANS_IN")"
  fi

  collect_interface_specs NET_INTERFACES "$CONFIG_FILE" "${add_server_cli[interfaces]:-}"
  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH

  # Phase 2: Validate configuration
  report_progress "Validating configuration" 2 8
  log_info "Prompting for any missing configuration values..."
  if [[ -z "$HOSTNAME" ]];then read -rp "Enter hostname for this server node: " HOSTNAME; fi
  if [[ -z "$IP" ]];      then read -rp "Enter static IPv4 for this server node: " IP; fi
  if [[ -z "$PREFIX" ]];  then read -rp "Enter subnet prefix length (0-32) [default 24]: " PREFIX; fi
  if [[ -z "$GW" ]];      then read -rp "Enter default gateway IPv4 [leave blank to skip]: " GW || true; fi

  log_info "Resolving DNS and search domains..."
  if [[ -z "$DNS" ]]; then
    read -rp "Enter DNS IPv4s (comma-separated) [blank=default ${DEFAULT_DNS}]: " DNS || true
    [[ -z "$DNS" ]] && DNS="$DEFAULT_DNS"
  fi
  if [[ -z "$SEARCH" && -n "${DEFAULT_SEARCH:-}" ]]; then
    SEARCH="$DEFAULT_SEARCH"
  fi

  log_info "Validating configuration..."
  while ! valid_ipv4 "$IP"; do read -rp "Invalid IPv4. Re-enter server IP: " IP; done
  while ! valid_prefix "${PREFIX:-}"; do read -rp "Invalid prefix (0-32). Re-enter server prefix [default 24]: " PREFIX; done
  while ! valid_ipv4_or_blank "${GW:-}"; do read -rp "Invalid gateway IPv4 (or blank). Re-enter: " GW; done
  while ! valid_csv_dns "${DNS:-}"; do read -rp "Invalid DNS list. Re-enter CSV IPv4s: " DNS; done
  while ! valid_search_domains_csv "${SEARCH:-}"; do read -rp "Invalid search domain list. Re-enter CSV: " SEARCH; done
  [[ -z "${PREFIX:-}" ]] && PREFIX=24
  metrics_increment "config_validated"

  # Phase 3: Network configuration
  report_progress "Configuring network" 3 8
  log_info "Determining TLS SANs..."
  if [[ -z "$TLS_SANS" ]]; then
    if [[ -z "$TLS_SANS_IN" && -n "${CONFIG_FILE:-}" ]]; then
      TLS_SANS_IN="$(yaml_spec_get "$CONFIG_FILE" tlsSans || true)"
      [[ -z "$TLS_SANS_IN" ]] && TLS_SANS_IN="$(yaml_spec_list_csv "$CONFIG_FILE" tls-san || true)"
      [[ -n "$TLS_SANS_IN" ]] && TLS_SANS="$(normalize_list_csv "$TLS_SANS_IN")"
	  log_info "TLS SANs from config: $TLS_SANS"
    fi
    if [[ -z "$TLS_SANS" ]]; then
      TLS_SANS="$(capture_sans "$HOSTNAME" "$IP" "$SEARCH")"
      log_info "Auto-derived TLS SANs: $TLS_SANS"
    fi
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "tls_sans_configured"

  # Phase 4: Stage artifacts
  report_progress "Staging RKE2 artifacts" 4 8
  log_info "Ensuring staged artifacts for offline RKE2 server install..."
  if ! ensure_staged_artifacts; then
    log_error "Failed to ensure staged artifacts"
    log_error "Remediation: Check $STAGE_DIR and re-run 'image' action"
    metrics_increment "failed"
    exit 3
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "artifacts_staged"

  # Phase 5: System configuration
  report_progress "Configuring system" 5 8
  log_info "Setting new hostname: $HOSTNAME..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    hostnamectl set-hostname "$HOSTNAME"
    if ! grep -qE "[[:space:]]$HOSTNAME(\$|[[:space:]])" /etc/hosts; then 
      echo "$IP $HOSTNAME" >> /etc/hosts
    fi
  else
    log_info "DRY-RUN: Would set hostname to $HOSTNAME and update /etc/hosts"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "hostname_set"

  BOOTSTRAP_TOKEN_FILE="$TOKEN_FILE"
  log_info "Seeding custom cluster CA..."
  setup_custom_cluster_ca || true
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "custom_ca_configured"

  local prompt_extra_ifaces_add_server=1
  if (( ${#NET_INTERFACES[@]} )); then
    if (( yaml_has_interfaces_add_server )); then
      prompt_extra_ifaces_add_server=0
      log INFO "Interfaces defined in YAML manifest; skipping interactive prompt for additional NICs."
    elif [[ -n "${add_server_cli[interfaces]:-}" ]]; then
      prompt_extra_ifaces_add_server=0
      log INFO "Interfaces provided via CLI flags; skipping interactive prompt for additional NICs."
    fi
  fi

  if (( prompt_extra_ifaces_add_server )); then
    prompt_additional_interfaces NET_INTERFACES "${DNS:-$DEFAULT_DNS}" "add-server"
  fi
  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH
  if (( ${#NET_INTERFACES[@]} )); then
    local _iface_summary=""
    local _encoded
    for _encoded in "${NET_INTERFACES[@]}"; do
      local -A _nic_dbg=()
      if ! interface_decode_entry "$_encoded" _nic_dbg; then
        log WARN "Skipping invalid interface entry in summary"
        continue
      fi
      local _name_dbg="${_nic_dbg[name]:-<auto>}"
      local _desc_dbg=""
      if [[ "${_nic_dbg[dhcp4]:-}" =~ ^([Tt]rue)$ ]]; then
        _desc_dbg="dhcp4"
      elif [[ -n "${_nic_dbg[ip]:-}" ]]; then
        _desc_dbg="${_nic_dbg[ip]}"
        if [[ -n "${_nic_dbg[prefix]:-}" ]]; then
          _desc_dbg+="/${_nic_dbg[prefix]}"
        fi
      elif [[ -n "${_nic_dbg[cidr]:-}" ]]; then
        _desc_dbg="${_nic_dbg[cidr]}"
      fi
      [[ -z "$_desc_dbg" ]] && _desc_dbg="static"
      _iface_summary+="${_iface_summary:+; }${_name_dbg}:${_desc_dbg}"
    done
    log_info "Network interfaces prepared: ${_iface_summary}"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "interfaces_configured"

  # Phase 6: Gather cluster join information
  report_progress "Configuring cluster join" 6 8
  log_info "Gathering cluster join information..."
  [[ -z "$URL" ]] && read -rp "Enter EXISTING RKE2 server URL (e.g. https://<vip-or-node>:9345): " URL
  if [[ -z "$TOKEN" && -z "$TOKEN_FILE" ]]; then
    read -rp "Enter cluster join token (leave blank to provide a token file path): " TOKEN || true
    if [[ -z "$TOKEN" ]]; then
      read -rp "Enter path to token file (e.g., /var/lib/rancher/rke2/server/node-token): " TOKEN_FILE || true
    fi
  fi
  [[ -z "$TLS_SANS" ]] && read -rp "Optional TLS SANs (CSV; hostnames/IPs) [blank=skip]: " TLS_SANS || true

  log_info "Validating/expanding provided token (if any)..."
  if [[ -n "$TOKEN_FILE" ]]; then
    log_info "Token file provided; skipping token expansion."
    TOKEN=""
  elif [[ -n "$TOKEN" ]]; then
    local full_token=""
    full_token="$(ensure_full_cluster_token "$TOKEN")"
    if [[ -n "$full_token" ]]; then
      if [[ "$full_token" != "$TOKEN" ]]; then
        log_info "Expanded server join token to full format (custom CA hash included)."
      fi
      TOKEN="$full_token"
    fi
  fi
  metrics_increment "token_configured"

  # Phase 7: Write RKE2 configuration
  report_progress "Writing RKE2 configuration" 7 8
  log_info "Writing file: /etc/rancher/rke2/config.yaml..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    mkdir -p /etc/rancher/rke2

    : > /etc/rancher/rke2/config.yaml
    {
      log_debug "Setting debug..." >&2
      echo "debug: true"

      log_debug "Setting server URL..." >&2
      echo "server: \"$URL\""     # required

      log_debug "Get token..." >&2
      if [[ -n "$TOKEN" ]]; then
        echo "token: $TOKEN"
	    log_debug "Using provided token..." >&2
      elif [[ -n "$TOKEN_FILE" ]]; then
        echo "token-file: \"$TOKEN_FILE\""
	    log_debug "Using provided token file: $TOKEN_FILE..." >&2
      fi

      log_debug "Append additional keys from YAML spec (cluster-cidr, domain, cni, etc.)..." >&2
      append_spec_config_extras "$CONFIG_FILE"

      # Kubelet defaults (safe; additive). Merge-friendly if you later append more.
      echo "kubelet-arg:"
      # Prefer systemd-resolved if present
      if [[ -f /run/systemd/resolve/resolv.conf ]]; then
        echo "  - resolv-conf=/run/systemd/resolve/resolv.conf"
      fi
      echo "  - container-log-max-size=10Mi"
      echo "  - container-log-max-files=5"
      echo

    } >> /etc/rancher/rke2/config.yaml
    log_info "Wrote /etc/rancher/rke2/config.yaml"

    log_debug "Setting file security: chmod 600 /etc/rancher/rke2/config.yaml..."
    chmod 600 /etc/rancher/rke2/config.yaml
  else
    log_info "DRY-RUN: Would write /etc/rancher/rke2/config.yaml"
    log_info "DRY-RUN: Server URL: $URL"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "config_written"

  log_info "Writing netplan configuration and applying network settings..."
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    if (( ${#NET_INTERFACES[@]} )); then
      write_netplan --interfaces "${NET_INTERFACES[@]}"
    else
      write_netplan "$IP" "$PREFIX" "${GW:-}" "${DNS:-}" "${SEARCH:-}"
    fi
  else
    log_info "DRY-RUN: Would write netplan configuration for $IP/$PREFIX"
  fi
  metrics_increment "total"
  metrics_increment "success"
  metrics_increment "netplan_written"

  # Phase 8: Install RKE2
  report_progress "Installing RKE2 server" 8 8
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    cleanup_containerd_before_rke2 "rke2-add-server"

    log_info "Installing rke2-server from cache at $STAGE_DIR"
    if ! run_rke2_installer "$STAGE_DIR" "server"; then
      log_error "Failed to install RKE2 server"
      log_error "Remediation: Check $LOG_FILE for details"
      metrics_increment "failed"
      exit 3
    fi
    systemctl enable rke2-server >>"$LOG_FILE" 2>&1 || true
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "rke2_installed"

    log_info "Deploying flannel TX checksum offload fix..."
    install_flannel_txcsum_fix
    metrics_increment "total"
    metrics_increment "success"
    metrics_increment "flannel_fix_installed"

  else
    log_info "DRY-RUN: Would install RKE2 server from $STAGE_DIR"
    log_info "DRY-RUN: Would enable rke2-server service"
    log_info "DRY-RUN: Would install flannel TX checksum fix"
  fi

  # Display summary
  log_success "========================================="
  log_success "Additional server join completed"
  log_success "========================================="
  
  metrics_summary "Add Server Deployment Summary"
  
  log_info ""
  log_info "Configuration:"
  log_info "  Hostname: $HOSTNAME"
  log_info "  IP Address: $IP/$PREFIX"
  log_info "  Gateway: ${GW:-<none>}"
  log_info "  DNS: $DNS"
  log_info "  Server URL: ${URL:-<not configured>}"
  log_info ""
  log_info "Next steps:"
  log_info "  1. Reboot the system to apply changes"
  log_info "  2. After reboot, verify server joined: kubectl get nodes"
  log_info "  3. Check cluster status: kubectl get pods -A"

  # If invoked via boot service in oneshot mode, disable the service
  if [[ $via_boot_service -eq 1 ]] && [[ "${BOOT_SERVICE_MODE:-oneshot}" == "oneshot" ]]; then
    log_info "Disabling rke2-boot service (oneshot mode)..."
    disable_boot_service
  fi

  echo
  if [[ "${DRY_RUN:-0}" -ne 1 ]]; then
    echo "[READY] rke2-server installed. Reboot to join the control plane."
  else
    echo "[DRY-RUN] Add-server configuration validated. No changes made."
  fi
  echo
  prompt_reboot
}

# ==================
# Action: VERIFY
# ------------------------------------------------------------------------------
# Function: action_verify
# Purpose : Run validation checks to ensure a node is ready for RKE2 installation
#           without performing mutations. Useful for health inspections.
# Arguments:
#   None
# Returns :
#   Returns 0 when all checks pass; non-zero otherwise.
# ------------------------------------------------------------------------------
#=============================================================================
# Function: action_verify
# Description: Verify that the node meets RKE2 prerequisites (read-only check)
# Parameters:
#   None (validates system state)
# Returns: 
#   0 - All prerequisites met
#   2 - Verification failures detected
# Usage: action_verify
# Dependencies: verify_prereqs, log_info, log_success, log_error
# Changes from Original:
#   - Added Phase 1 logging utilities for consistency
#   - Improved error messages with actionable guidance
#=============================================================================
action_verify() {
  load_site_defaults
  
  log_info "Starting RKE2 prerequisites verification"
  log_info "This is a read-only check - no changes will be made to the system"
  
  if verify_prereqs; then
    log_success "VERIFY PASSED: Node meets all RKE2 prerequisites"
    log_info "Next steps:"
    log_info "  - Run 'image' action to prepare golden image"
    log_info "  - Run 'server' or 'agent' action to deploy RKE2"
    exit 0
  else
    log_error "VERIFY FAILED: One or more prerequisites not met"
    log_error "Remediation steps:"
    log_error "  - Review error messages above for specific issues"
    log_error "  - Install missing dependencies or fix configuration"
    log_error "  - Re-run verification: $0 verify"
    exit 2
  fi
}

# ==================
# Action: AIRGAP
# One-liner wrapper: prep the image and power off for templating
# ------------------------------------------------------------------------------
# Function: action_airgap
# Purpose : Variant of action_image used when the operator wants to skip the
#           automatic reboot so the VM can be powered off for templating.
# Arguments:
#   None
# Returns :
#   Exits on failure; prints next steps on success.
# ------------------------------------------------------------------------------
action_airgap() {
  initialize_action_context false "airgap"
  
  metrics_init "airgap_operation"
  
  log_info "========================================"
  log_info "RKE2 Airgap Image Preparation"
  log_info "========================================"
  log_info "Preparing VM for template/cloning with poweroff"
  log_info ""
  
  # Run full image preparation
  NO_REBOOT=1 action_image
  
  metrics_increment "image_prepared"
  
  # Sync filesystems
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
    sleep 3
    poweroff
  else
    log_info "DRY-RUN: Would power off system for VM templating"
  fi
}

# ------------------------------------------------------------------------------
# Function: action_label_node
# Purpose : Apply one or more Kubernetes labels to the targeted RKE2 node using
#           kubectl. The node defaults to the detected hostname unless the user
#           provides an override via CLI flag.
# Arguments:
#   Consumes ACTION_ARGS for the label specifications (e.g., key=value).
# Returns :
#   Exits when kubectl is unavailable or when no labels were provided.
# ------------------------------------------------------------------------------
action_label_node() {
  initialize_action_context false "label-node"

  local node="$NODE_NAME"
  local -a label_args=( "${ACTION_ARGS[@]}" )
  local -a display_args=( "${label_args[@]}" )

  if (( ${#label_args[@]} == 0 )); then
    log ERROR "No labels supplied. Provide at least one key=value pair."
    exit 1
  fi

  local kubectl_bin
  if ! kubectl_bin="$(find_kubectl_binary)"; then
    log ERROR "kubectl not found. Ensure RKE2 is installed and kubectl is available in PATH."
    exit 2
  fi

  local kubeconfig=""
  if kubeconfig="$(detect_kubeconfig)"; then
    log INFO "Using kubeconfig: $kubeconfig"
  else
    log WARN "No kubeconfig detected; relying on kubectl defaults."
    kubeconfig=""
  fi

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

  log INFO "Labeling node '$node' with: ${display_args[*]}"

  local -a cmd=( "$kubectl_bin" )
  if [[ -n "$kubeconfig" ]]; then
    cmd+=( "--kubeconfig" "$kubeconfig" )
  fi
  cmd+=( label node "$node" )
  cmd+=( "${label_args[@]}" )

  spinner_run "Labeling node $node" "${cmd[@]}"
}

# ------------------------------------------------------------------------------
# Function: action_taint_node
# Purpose : Apply one or more taints to the targeted RKE2 node via kubectl. The
#           node name is sourced from CLI or defaults to the detected hostname.
# Arguments:
#   Consumes ACTION_ARGS for taint specifications (e.g., key=value:Effect).
# Returns :
#   Exits when kubectl is unavailable or when no taints were provided.
# ------------------------------------------------------------------------------
action_taint_node() {
  initialize_action_context false "taint-node"

  local node="$NODE_NAME"
  local -a taint_args=( "${ACTION_ARGS[@]}" )
  local -a taint_display=( "${taint_args[@]}" )

  if (( ${#taint_args[@]} == 0 )); then
    log ERROR "No taints supplied. Provide one or more key=value:Effect entries."
    exit 1
  fi

  local kubectl_bin
  if ! kubectl_bin="$(find_kubectl_binary)"; then
    log ERROR "kubectl not found. Ensure RKE2 is installed and kubectl is available in PATH."
    exit 2
  fi

  local kubeconfig=""
  if kubeconfig="$(detect_kubeconfig)"; then
    log INFO "Using kubeconfig: $kubeconfig"
  else
    log WARN "No kubeconfig detected; relying on kubectl defaults."
    kubeconfig=""
  fi

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

  log INFO "Tainting node '$node' with: ${taint_display[*]}"

  local -a cmd=( "$kubectl_bin" )
  if [[ -n "$kubeconfig" ]]; then
    cmd+=( "--kubeconfig" "$kubeconfig" )
  fi
  cmd+=( taint node "$node" )
  cmd+=( "${taint_args[@]}" )

  spinner_run "Tainting node $node" "${cmd[@]}"
}

# ==================
# Action: CUSTOM-CA
# ------------------------------------------------------------------------------
# Function: action_custom_ca
# Purpose : Generate the first server token from the custom CA specified in the YAML
#           and save it to the outputs directory, log it, and print to screen.
# Arguments:
#   None
# Returns :
#   Exits on failure.
# ------------------------------------------------------------------------------
#=============================================================================
# Function: action_custom_ca
# Description: Generate bootstrap token from custom CA configuration
# Parameters:
#   None (reads from CONFIG_FILE global)
# Returns: 
#   0 - Success (token generated)
#   1 - Token generation failure
#   5 - Validation failure (missing config or invalid kind)
# Usage: action_custom_ca -f <config.yaml>
# Dependencies: validate_non_empty, validate_file_exists, log_info, log_success, log_error
# Changes from Original:
#   - Added validation utilities for prerequisites
#   - Enhanced error messages with remediation steps
#   - Added structured logging with Phase 1 utilities
#=============================================================================
action_custom_ca() {
  initialize_action_context false "custom-ca"

  log_info "Starting custom CA bootstrap token generation"
  
  # Validate prerequisites using Phase 1 utilities
  if ! validate_non_empty "${CONFIG_FILE:-}" "CONFIG_FILE"; then
    log_error "Custom-CA action requires a YAML configuration file"
    log_error "Remediation: Provide config file with -f flag"
    log_error "Example: $0 custom-ca -f examples/custom-ca-example.yaml"
    exit 5
  fi
  
  if ! validate_file_exists "$CONFIG_FILE" "configuration file"; then
    log_error "Configuration file not found: $CONFIG_FILE"
    log_error "Remediation: Verify file path and permissions"
    exit 5
  fi

  local kind_folded="${YAML_KIND:-}"
  kind_folded="${kind_folded,,}"
  if [[ "${kind_folded//-/}" != "customca" ]]; then
    log_error "Invalid YAML kind for custom-ca action"
    log_error "Expected: kind: CustomCA (or custom-ca, Custom-CA variants)"
    log_error "Found: ${YAML_KIND:-<none>}"
    log_error "Remediation: Update YAML file with correct kind field"
    exit 5
  fi

  log_info "Loading custom CA configuration from: $CONFIG_FILE"
  load_custom_ca_from_config "$CONFIG_FILE" "" 1

  if [[ -z "${CUSTOM_CA_ROOT_CRT:-}" && -z "${CUSTOM_CA_INT_CRT:-}" ]]; then
    log_error "Custom CA configuration incomplete"
    log_error "spec.customCA must define at least one of:"
    log_error "  - rootCrt: Root CA certificate"
    log_error "  - intermediateCrt: Intermediate CA certificate"
    log_error "Remediation: Add certificate paths to YAML spec.customCA section"
    exit 5
  fi

  log_info "Generating bootstrap token from custom CA"
  report_progress "Generating token" 1 1

  local TOKEN="" TOKEN_FILE=""
  generate_bootstrap_token
  TOKEN=$token

  if [[ -z "$TOKEN" ]]; then
    log_error "Bootstrap token generation failed"
    log_error "Remediation steps:"
    log_error "  - Verify CA certificate files are valid PEM format"
    log_error "  - Check file permissions on certificate files"
    log_error "  - Review logs for detailed error messages"
    exit 1
  fi
  
  TOKEN_FILE="${OUT_DIR}/${SPEC_NAME}-bootstrap-token.txt"
  echo "$TOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  
  log_success "Bootstrap token generated successfully"
  log_info "Token saved to: $TOKEN_FILE (permissions: 600)"
  log_info "Next steps:"
  log_info "  - Use this token for server/agent bootstrap"
  log_info "  - Keep token file secure - it provides cluster access"
}

# ================================================================================================
# ARGUMENT PARSING
# ================================================================================================
# Parse long options first
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help)
      # Check if action specified after --help
      if [[ -n "${2:-}" && "${2:0:1}" != "-" ]]; then
        show_action_help "$2"
      else
        print_help
        exit 0
      fi
      ;;
    --version) show_version;;
    --verbose) VERBOSE=1; shift;;
    --quiet) QUIET=1; shift;;
    --dry-run) DRY_RUN=1; shift;;
    --dry-push) DRY_PUSH=1; shift;;
    --apply-netplan-now) APPLY_NETPLAN_NOW=1; shift;;
    --load-images) LOAD_IMAGES=1; shift;;
    --fix-cni-permissions) FIX_CNI_PERMISSIONS=1; shift;;
    --verify-layers) VERIFY_LAYERS=1; shift;;
    --node-name)
      if [[ -z "${2:-}" ]]; then
        echo "ERROR: --node-name requires an argument" >&2
        exit 1
      fi
      NODE_NAME="$2"
      shift 2
      ;;
    --node-name=*)
      NODE_NAME="${1#*=}"
      shift
      ;;
    --enable-boot-service) ENABLE_BOOT_SERVICE=1; shift;;
    --boot-yaml-path)
      if [[ -z "${2:-}" ]]; then
        echo "ERROR: --boot-yaml-path requires an argument" >&2
        exit 1
      fi
      BOOT_YAML_PATH="$2"
      shift 2
      ;;
    --boot-yaml-path=*)
      BOOT_YAML_PATH="${1#*=}"
      shift
      ;;
    --boot-mode)
      if [[ -z "${2:-}" ]]; then
        echo "ERROR: --boot-mode requires an argument (oneshot or persistent)" >&2
        exit 1
      fi
      BOOT_SERVICE_MODE="$2"
      shift 2
      ;;
    --boot-mode=*)
      BOOT_SERVICE_MODE="${1#*=}"
      shift
      ;;
    --enable-fips) ENABLE_FIPS=1; shift;;
    --vm-platform)
      if [[ -z "${2:-}" ]]; then
        echo "ERROR: --vm-platform requires an argument (vmware, hyperv, virtualbox, or generic)" >&2
        exit 1
      fi
      VM_PLATFORM="$2"
      shift 2
      ;;
    --vm-platform=*)
      VM_PLATFORM="${1#*=}"
      shift
      ;;
    -f|-v|-r|-u|-p|-n|-y|-P|-h|push|image|server|add-server|agent|verify|custom-ca|label-node|taint-node|airgap|list-images) break;;
    *) break;;
  esac
done

while getopts ":f:v:r:u:p:n:yPh" opt; do
  case ${opt} in
    f) CONFIG_FILE="$OPTARG";;
    v) RKE2_VERSION="$OPTARG";;
    r) REGISTRY="$OPTARG";;
    u) REG_USER="$OPTARG";;
    p) REG_PASS="$OPTARG";;
    n) NODE_NAME="$OPTARG";;
    y) AUTO_YES=1;;
    P) PRINT_CONFIG=1;;
    h) print_help; exit 0;;
    \?) echo "Invalid option: -$OPTARG"; print_help; exit 1;;
    :)  echo "Option -$OPTARG requires an argument"; exit 1;;
  esac
done
shift $((OPTIND-1))

CLI_SUB="${1:-}"
if [[ -z "$CONFIG_FILE" && -n "$CLI_SUB" && -f "$CLI_SUB" ]]; then
  CONFIG_FILE="$CLI_SUB"
  shift
  CLI_SUB="${1:-}"
fi

YAML_KIND=""
if [[ -n "$CONFIG_FILE" ]]; then
  if [[ ! -f "$CONFIG_FILE" ]]; then
    log ERROR "YAML file not found: $CONFIG_FILE"; exit 5
  fi
  if [[ "$CONFIG_FILE" != /* ]]; then
    CONFIG_FILE="$(cd -- "$(dirname -- "$CONFIG_FILE")" && pwd -P)/$(basename -- "$CONFIG_FILE")"
  fi
  API="$(yaml_get_api "$CONFIG_FILE" || true)"
  YAML_KIND="$(yaml_get_kind "$CONFIG_FILE" || true)"
  if [[ "$API" != "rkeprep/v2" ]]; then
    log ERROR "Unsupported apiVersion: '$API' (expected rkeprep/v2)"; exit 5
  fi
  if [[ "$PRINT_CONFIG" -eq 1 ]]; then
    echo "----- Sanitized YAML -----"
    sanitize_yaml "$CONFIG_FILE"
    echo "--------------------------"
  fi
fi

ACTION="${CLI_SUB:-}"
if [[ -n "$ACTION" ]]; then
  shift
  # Check for action --help
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    show_action_help "$ACTION"
  fi
fi
ACTION_ARGS=("$@")

if [[ -n "$CONFIG_FILE" && -z "$ACTION" ]]; then
  case "$YAML_KIND" in
    Push|push)        ACTION="push"        ;;
    Image|image)      ACTION="image"       ;;
    Airgap|airgap)    ACTION="airgap"      ;;
    Server|server)    ACTION="server"      ;;
    AddServer|add-server|addServer|addserver|Addserver|add_server|Add_server|add_Server) ACTION="add-server" ;;
    Agent|agent)      ACTION="agent"       ;;
    Verify|verify)    ACTION="verify"      ;;
    CustomCA|custom-ca|customca) ACTION="custom-ca" ;;
    *) log ERROR "Unsupported or missing YAML kind: '${YAML_KIND:-<none>}'"; exit 5;;
  esac
fi

NODE_NAME="${NODE_NAME:-$(default_node_hostname)}"

case "${ACTION:-}" in
  image)       action_image  ;;
  list-images) action_list_images ;;
  server)      action_server ;;
  agent)       action_agent  ;;
  verify)      action_verify ;;
  AddServer|add-server|addServer|addserver|Addserver|add_server|Add_server|add_Server) action_add_server ;;
  airgap)      action_airgap ;;
  push)        action_push   ;;
  label-node)  action_label_node ;;
  taint-node)  action_taint_node ;;
  custom-ca)   action_custom_ca ;;
  *) print_help; exit 1 ;;
esac

