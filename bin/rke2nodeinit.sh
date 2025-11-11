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
#       Version: 0.8a (multi-interface support)
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
#   - YAML-driven configuration: apiVersion rkeprep/v1 with comprehensive spec options
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
# YAML configuration (apiVersion: rkeprep/v1):
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
#   -f FILE               YAML config file (apiVersion: rkeprep/v1)
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
APPLY_NETPLAN_NOW=0         # --apply-netplan-now applies netplan immediately instead of deferring to next reboot
NODE_NAME=""
ACTION_ARGS=()

# Custom CA context (populated from site defaults or YAML when provided)
CUSTOM_CA_ROOT_CRT=""
CUSTOM_CA_ROOT_KEY=""
CUSTOM_CA_INT_CRT=""
CUSTOM_CA_INT_KEY=""
CUSTOM_CA_INSTALL_TO_OS_TRUST=1

# Track the CA file used when deriving full tokens so runs can archive it.
AGENT_CA_CERT=""

# Artifacts
IMAGES_TAR="rke2-images.linux-$ARCH.tar.zst"
RKE2_TARBALL="rke2.linux-$ARCH.tar.gz"
SHA256_FILE="sha256sum-$ARCH.txt"

# Logging
LOG_FILE="$LOG_DIR/rke2nodeinit_$(date -u +"%Y-%m-%dT%H-%M-%SZ").log"

# Cached artifact metadata (populated at runtime)
NERDCTL_FULL_TGZ=""
NERDCTL_STD_TGZ=""

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
  cat <<'EOF'
RKE2 Node Initialization Script (v0.8a)
========================================
Automates air-gapped RKE2 cluster deployment with multi-interface networking support.

NOTE: All YAML inputs must include a metadata.name field (e.g., metadata: { name: my-config }).

USAGE:
  sudo ./rke2nodeinit.sh -f <file.yaml> [options]
  sudo ./rke2nodeinit.sh [options] <action>

YAML KINDS (apiVersion: rkeprep/v1):
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
  -f FILE      YAML config file (apiVersion: rkeprep/v1; kind selects action)
  -v VER       RKE2 version tag (e.g., v1.34.1+rke2r1). Auto-detects latest if omitted
  -r REG       Private registry (host[/namespace]), e.g., registry.example.com/rke2
  -u USER      Registry username for authentication
  -p PASS      Registry password for authentication
  -n NAME      Node name for label-node/taint-node (defaults to hostname)
               (also available as --node-name NAME)
  -y           Auto-confirm prompts (reboots, cleanup operations)
  -P           Print sanitized YAML to screen (masks secrets)
  -h           Show this help message
  --dry-push   Simulate image push without actually pushing to registry
  --apply-netplan-now
               Apply netplan immediately instead of deferring until reboot
               (default: netplan changes deferred to next reboot for safety)
  --interface name=<iface> ip=<addr> prefix=<bits> [gateway=<gw>] [dns=<dns>] [search=<domain>]
               Define network interface (repeatable for multi-interface setups)
               Use "dhcp4=true" for DHCP-based interfaces
               Omit name on first interface to auto-detect primary NIC

MULTI-INTERFACE YAML EXAMPLE:
  apiVersion: rkeprep/v1
  kind: Server
  metadata:
    name: ctrl01-server
  spec:
    token: K10abc...xyz::server:1234abcd
    clusterInit: true
    nodeName: ctrl01.example.com
    node-ip: 10.0.69.60
    bind-address: 10.0.69.60
    interfaces:
      - name: eth0
        ip: 10.0.69.60
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
  apiVersion: rkeprep/v1
  kind: CustomCA
  metadata:
    name: enterprise-ca
  spec:
    rootCrt: certs/enterprise-root.crt
    rootKey: certs/enterprise-root.key        # optional
    intermediateCrt: certs/issuing-ca.crt     # optional
    intermediateKey: certs/issuing-ca.key     # optional
    installToOSTrust: true                    # default: true

WORKFLOW EXAMPLES:
  1. Prepare base image for cloning:
     sudo ./rke2nodeinit.sh -f examples/image.yaml

  2. Initialize first control-plane with multi-interface networking:
     sudo ./rke2nodeinit.sh -f clusters/dc1/ctrl01.yaml

  3. Join worker node:
     sudo ./rke2nodeinit.sh -f clusters/dc1/work01.yaml

  4. Push images to private registry:
     sudo ./rke2nodeinit.sh -f examples/push.yaml -r registry.local/rke2 -u admin -p secret

  5. Label a node:
     sudo ./rke2nodeinit.sh label-node -n worker01 -f labels.yaml

  6. Install custom CA:
     sudo ./rke2nodeinit.sh -f certs/custom-ca.yaml custom-ca

OUTPUTS:
  - SBOM:      outputs/sbom/<metadata.name>-sbom.txt
               (SHA256 checksums and sizes of cached artifacts)
  - Run log:   outputs/<metadata.name>/README.txt
               (Summary of image preparation steps)
  - Token:     outputs/generated-token/<cluster>-token.txt
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
  printf "%s %s rke2nodeinit[%d]: %s %s\n" "$ts" "$host" "$$" "$level:" "$msg" >> "$LOG_FILE"
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

  local spin='|+/-\' i=0
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
    "cni" "system-default-registry" "private-registry" "write-kubeconfig-mode"
    "selinux" "protect-kernel-defaults" "kube-apiserver-image" "kube-controller-manager-image"
    "kube-scheduler-image" "etcd-image" "disable-cloud-controller" "disable-kube-proxy"
    "enable-servicelb" "node-ip" "bind-address" "advertise-address"
  )

  local k v
  for k in "${scalars[@]}"; do
    _cfg_has_key "$k" && continue
    v="$(yaml_spec_get_any "$file" "$k" "$(echo "$k" | sed -E 's/-([a-z])/\U\\1/g; s/^([a-z])/\U\\1/; s/-//g')")" || true
    if [[ -n "$v" ]]; then
      local normalized=""
      normalized="$(normalize_bool_value "$v")"
      echo "$k: $normalized" >> "$cfg"
    fi
  done

  # Lists we support (emit YAML arrays)
  local -a lists=(
    "kube-apiserver-arg" "kube-controller-manager-arg" "kube-scheduler-arg" "kube-proxy-arg"
    "node-taint" "node-label" "tls-san"
  )

  for k in "${lists[@]}"; do
    _cfg_has_key "$k" && continue
    if yaml_spec_has_list "$file" "$k"; then
      echo "$k:" >> "$cfg"
      yaml_spec_list_items "$file" "$k" | sed 's/^/  - /' >> "$cfg"
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
  v="${v#[}"; v="${v%]}"
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
  _clean="${_raw#[}"; _clean="${_clean%]}"
  _clean="${_clean//;/,}"
  local -a _items=()
  IFS=',' read -r -a _tmp <<<"$_clean"
  local _item
  for _item in "${_tmp[@]}"; do
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

  local _tmp="/etc/netplan/99-rke-static.yaml"
  : > "$_tmp"

  # Write netplan header
  {
    echo "network:"
    echo "  version: 2"
    echo "  renderer: networkd"
    echo "  ethernets:"
  } >> "$_tmp"

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
    } >> "$_tmp"

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
  chmod 600 "$_tmp"
  log INFO "Netplan written to $_tmp (primary=$_primary_nic; interfaces=${_summary})"

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
  log INFO "Installing RKE2 prereqs (apt-packages, iptables-nft, modules, sysctl, swapoff, network-manager, ufw)..."
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
    ebtables openssl tar gzip zstd jq net-tools make
  log INFO "Removing unnecessary packages..."
  spinner_run "Removing unnecessary packages" apt-get autoremove -y # >>"$LOG_FILE" 2>&1

 # check_system_settings
 # check_swap
 # check_networkmanager
 # check_iptables
 # check_ufw

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
    log WARN "Root CA not found; custom cluster CA will not be used."
    return 0
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
      while read -r h fn; do
        # Normalize to basename when manifest references relative paths
        local bn
        bn=$(basename "${fn}")
        if [[ -f "$STAGE_DIR/$bn" ]]; then
          printf '%s  %s\n' "$h" "$STAGE_DIR/$bn" >>"$tmp_manifest"
        elif [[ -f "$IMAGES_DIR/$bn" ]]; then
          printf '%s  %s\n' "$h" "$IMAGES_DIR/$bn" >>"$tmp_manifest"
        else
          # Leave as basename so sha256sum reports missing files in a helpful way
          printf '%s  %s\n' "$h" "$bn" >>"$tmp_manifest"
        fi
      done < "$STAGE_DIR/$SHA256_FILE"

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
  # Build a registries.yaml that points common upstreams to your offline endpoints in priority order.
  # Args: primary_host [fallback_host] [default_offline_host] [username] [password] [ca_file]
  local primary="$1"; shift || true
  local fallback="$1"; shift || true
  local default_offline="$1"; shift || true
  local user="$1"; shift || true
  local pass="$1"; shift || true
  local ca_file="$1"; shift || true

  mkdir -p /etc/rancher/rke2

  # Build endpoint YAML list
  endpoints_primary="      - \"https://${primary}\""
  endpoints_fallback=""
  endpoints_default=""
  [[ -n "$fallback" ]]        && endpoints_fallback=$'\n'"      - \"https://${fallback}\""
  [[ -n "$default_offline" ]] && endpoints_default=$'\n'"      - \"https://${default_offline}\""

  # CA line (optional)
  tls_block_primary=""
  tls_block_fallback=""
  tls_block_default=""
  if [[ -n "$ca_file" && -f "$ca_file" ]]; then
    tls_block_primary=$'\n'"    tls:"$'\n'"      ca_file: \"${ca_file}\""
    tls_block_fallback=$'\n'"    tls:"$'\n'"      ca_file: \"${ca_file}\""
    tls_block_default=$'\n'"    tls:"$'\n'"      ca_file: \"${ca_file}\""
  fi

  # Auth (optional)
  auth_block_primary=""
  auth_block_fallback=""
  auth_block_default=""
  if [[ -n "$user" && -n "$pass" ]]; then
    auth_block_primary=$'\n'"    auth:"$'\n'"      username: \"${user}\""$'\n'"      password: \"${pass}\""
    auth_block_fallback=$'\n'"    auth:"$'\n'"      username: \"${user}\""$'\n'"      password: \"${pass}\""
    auth_block_default=$'\n'"    auth:"$'\n'"      username: \"${user}\""$'\n'"      password: \"${pass}\""
  fi

  # Known upstreams we want to mirror via offline registry
  # Known upstreams we want to mirror via offline registry
  REG_YAML="$(cat <<EOF
mirrors:
  "docker.io":
    endpoint:
${endpoints_primary}${endpoints_fallback}${endpoints_default}
  "registry.k8s.io":
    endpoint:
${endpoints_primary}${endpoints_fallback}${endpoints_default}
  "k8s.gcr.io":
    endpoint:
${endpoints_primary}${endpoints_fallback}${endpoints_default}
  "quay.io":
    endpoint:
${endpoints_primary}${endpoints_fallback}${endpoints_default}
  "ghcr.io":
    endpoint:
${endpoints_primary}${endpoints_fallback}${endpoints_default}
  "rancher":
    endpoint:
${endpoints_primary}${endpoints_fallback}${endpoints_default}
configs:
  "${primary}":${auth_block_primary}${tls_block_primary}
EOF
)"

  # Optionally add configs for fallback/default
  if [[ -n "$fallback" ]]; then
    REG_YAML+=$'\n'"  \"${fallback}\":${auth_block_fallback}${tls_block_fallback}"
  fi
  if [[ -n "$default_offline" ]]; then
    REG_YAML+=$'\n'"  \"${default_offline}\":${auth_block_default}${tls_block_default}"
  fi

  printf "%s\n" "${REG_YAML}" > /etc/rancher/rke2/registries.yaml
  chmod 600 /etc/rancher/rke2/registries.yaml
  log INFO "Wrote /etc/rancher/rke2/registries.yaml with endpoints (priority): ${primary}${fallback:+, ${fallback}}${default_offline:+, ${default_offline}}"
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

  local BASE_URL="https://github.com/rancher/rke2/releases/download/${RKE2_VERSION}"
  local IMAGES_TAR="rke2-images.linux-${ARCH}.tar.zst"
  local RKE2_TARBALL="rke2.linux-${ARCH}.tar.gz"
  local SHA256_FILE="sha256sum-${ARCH}.txt"

  # Download artifacts (idempotent)
  [[ -f "$IMAGES_TAR"  ]] || spinner_run "Downloading $IMAGES_TAR"  curl -Lf "$BASE_URL/$IMAGES_TAR"  -o "$IMAGES_TAR"
  [[ -f "$RKE2_TARBALL" ]] || spinner_run "Downloading $RKE2_TARBALL" curl -Lf "$BASE_URL/$RKE2_TARBALL" -o "$RKE2_TARBALL"
  [[ -f "$SHA256_FILE" ]] || spinner_run "Downloading $SHA256_FILE"  curl -Lf "$BASE_URL/$SHA256_FILE"  -o "$SHA256_FILE"
  [[ -f install.sh ]]    || spinner_run "Downloading install.sh"    curl -sfL "https://get.rke2.io" -o install.sh
  chmod +x install.sh || true

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

  mkdir -p "$STAGE_DIR"
  for f in "$RKE2_TARBALL" "$SHA256_FILE" "install.sh"; do
    if [[ -f "$DOWNLOADS_DIR/$f" ]]; then
      local tmpf="$STAGE_DIR/.tmp-${f}.$$"
      cp -f "$DOWNLOADS_DIR/$f" "$tmpf"
      mv -T "$tmpf" "$STAGE_DIR/$f"
      [[ "$f" == "install.sh" ]] && chmod +x "$STAGE_DIR/install.sh"
      log INFO "Staged $f into $STAGE_DIR"
    fi
  done

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
    write_registries_yaml_with_fallbacks "$REG_HOST" "" "" "$REG_USER" "$REG_PASS" "/usr/local/share/ca-certificates/${CA_BN:-}"
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
action_push() {
  initialize_action_context false "push"

  if [[ -n "$CONFIG_FILE" ]]; then
    REGISTRY="$(yaml_spec_get "$CONFIG_FILE" registry || echo "$REGISTRY")"
    REG_USER="$(yaml_spec_get "$CONFIG_FILE" registryUsername || echo "$REG_USER")"
    REG_PASS="$(yaml_spec_get "$CONFIG_FILE" registryPassword || echo "$REG_PASS")"
    log WARN "Using YAML values; CLI flags may be overridden (push)."
  fi

  # Warn if using example default credentials
  warn_default_credentials "$REGISTRY" "$REG_USER" "$REG_PASS"

  ensure_installed zstd

  local work="$DOWNLOADS_DIR"
  if [[ ! -f "$work/$IMAGES_TAR" ]]; then
    log ERROR "Images archive not found in $work. Run 'image' first."
    exit 3
  fi

  zstdcat "$work/$IMAGES_TAR" | nerdctl -n k8s.io load >>"$LOG_FILE" 2>&1

  local -a imgs
  mapfile -t imgs < <(nerdctl -n k8s.io images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | sort -u)

  local REG_HOST="$REGISTRY" REG_NS=""
  [[ "$REGISTRY" == *"/"* ]] && { REG_HOST="${REGISTRY%%/*}"; REG_NS="${REGISTRY#*/}"; }

  local manifest_json="$OUT_DIR/images-manifest.json"
  local manifest_txt="$OUT_DIR/images-manifest.txt"
  : > "$manifest_txt"
  echo "[" > "$manifest_json"
  local first=1

  for IMG in "${imgs[@]}"; do
    [[ -z "$IMG" ]] && continue
    local TARGET
    if [[ -n "$REG_NS" ]]; then TARGET="$REG_HOST/$REG_NS/$IMG"; else TARGET="$REG_HOST/$IMG"; fi

    [[ $first -eq 0 ]] && echo "," >> "$manifest_json"
    printf '  {"source":"%s","target":"%s"}' "$IMG" "$TARGET" >> "$manifest_json"
    first=0
    echo "$IMG  ->  $TARGET" >> "$manifest_txt"

    gen_sbom_or_metadata "$IMG"
  done
  echo ""  >> "$manifest_json"
  echo "]" >> "$manifest_json"
  log INFO "Pre-push manifest written:"
  log INFO "  - $manifest_txt"
  log INFO "  - $manifest_json"

  if [[ "$DRY_PUSH" -eq 1 ]]; then
    log WARN "--dry-push set; skipping actual registry pushes."
    return 0
  fi

  spinner_run "Logging into $REG_HOST" nerdctl login "$REG_HOST" -u "$REG_USER" -p "$REG_PASS"
  for IMG in "${imgs[@]}"; do
    [[ -z "$IMG" ]] && continue
    local TARGET
    if [[ -n "$REG_NS" ]]; then TARGET="$REG_HOST/$REG_NS/$IMG"; else TARGET="$REG_HOST/$IMG"; fi
    log INFO "Tag & push: $IMG -> $TARGET"
    nerdctl -n k8s.io tag  "$IMG" "$TARGET"  >>"$LOG_FILE" 2>&1
    spinner_run "Pushing $TARGET" nerdctl -n k8s.io push "$TARGET"
  done
  nerdctl logout "$REG_HOST" >>"$LOG_FILE" 2>&1 || true

  log INFO "push: completed successfully."
}

# ==============
# Action: IMAGE
# ------------------------------------------------------------------------------
# Function: action_image
# Purpose : Prepare a golden image for offline deployment by installing
#           prerequisites, downloading artifacts, caching registries configuration,
#           and writing documentation of the run.
# Arguments:
#   None
# Returns :
#   Exits on failure; triggers reboot prompt on completion.
# ------------------------------------------------------------------------------
action_image() {
  initialize_action_context true "image"

  # Detailed run-level logging: capture key inputs and paths so operators
  # and auditors can see what decisions were made by the image action.
  log INFO "Starting action_image: RKE2_VERSION='${RKE2_VERSION:-<auto>}' REGISTRY='${REGISTRY:-<none>}' REG_USER='${REG_USER:-<none>}'"
  log INFO "Paths: DOWNLOADS_DIR='$DOWNLOADS_DIR' STAGE_DIR='$STAGE_DIR' SBOM_DIR='$SBOM_DIR' OUT_DIR='$OUT_DIR'"

  # --- Read YAML (optional) -------------------------------------------------
  local REQ_VER="${RKE2_VERSION:-}"
  local defaultDnsCsv="$DEFAULT_DNS"
  local defaultSearchCsv=""
  local REG_HOST="${REGISTRY%%/*}"
  local CA_ROOT="" CA_KEY="" CA_INTCRT="" CA_INTKEY="" CA_INSTALL="true"
  if [[ -n "$CONFIG_FILE" ]]; then
    REQ_VER="${REQ_VER:-$(yaml_spec_get "$CONFIG_FILE" rke2Version || true)}"
    REGISTRY="$(yaml_spec_get "$CONFIG_FILE" registry || echo "$REGISTRY")"
    REG_USER="$(yaml_spec_get "$CONFIG_FILE" registryUsername || echo "$REG_USER")"
    REG_PASS="$(yaml_spec_get "$CONFIG_FILE" registryPassword || echo "$REG_PASS")"
    REG_HOST="${REGISTRY%%/*}"
    local d1 s1
    d1="$(yaml_spec_get "$CONFIG_FILE" defaultDns || true)"
    s1="$(yaml_spec_get "$CONFIG_FILE" defaultSearchDomains || true)"
    [[ -n "$d1" ]] && defaultDnsCsv="$(normalize_list_csv "$d1")"
    [[ -n "$s1" ]] && defaultSearchCsv="$(normalize_list_csv "$s1")"
    # Optional custom CA for registry/cluster
    CA_ROOT="$(yaml_spec_get "$CONFIG_FILE" customCA.rootCrt || true)"
    CA_KEY="$(yaml_spec_get "$CONFIG_FILE" customCA.rootKey || true)"
    CA_INTCRT="$(yaml_spec_get "$CONFIG_FILE" customCA.intermediateCrt || true)"
    CA_INTKEY="$(yaml_spec_get "$CONFIG_FILE" customCA.intermediateKey || true)"
    CA_INSTALL="$(yaml_spec_get "$CONFIG_FILE" customCA.installToOSTrust || echo true)"
  fi

  # Warn if using example default credentials
  warn_default_credentials "$REGISTRY" "$REG_USER" "$REG_PASS"

  # Resolve cert paths relative to script dir if not absolute
  [[ -n "$CA_ROOT"   && "${CA_ROOT:0:1}"   != "/" ]] && CA_ROOT="$SCRIPT_DIR/$CA_ROOT"
  [[ -n "$CA_KEY"    && "${CA_KEY:0:1}"    != "/" ]] && CA_KEY="$SCRIPT_DIR/$CA_KEY"
  [[ -n "$CA_INTCRT" && "${CA_INTCRT:0:1}" != "/" ]] && CA_INTCRT="$SCRIPT_DIR/$CA_INTCRT"
  [[ -n "$CA_INTKEY" && "${CA_INTKEY:0:1}" != "/" ]] && CA_INTKEY="$SCRIPT_DIR/$CA_INTKEY"

  # --- OS prereqs ------------------------------------------------------------
  install_rke2_prereqs

  local virt_class virt_type hypervisor
  IFS='|' read -r virt_class virt_type hypervisor <<<"$(detect_virtualization)"
  if [[ "$virt_class" == "virtual" ]]; then
    log INFO "Virtual environment detected (type=${virt_type:-unknown}, hypervisor=${hypervisor:-unknown})."
    install_vm_tools "$hypervisor"
  else
    log INFO "Physical hardware detected; skipping VM tools installation."
  fi

  # install_nerdctl
  fetch_rke2_ca_generator
    # cache_rke2_artifacts downloads / stages required artifacts into
    # $DOWNLOADS_DIR and $STAGE_DIR. It emits its own logging, but record
    # the start/end here for clearer run traces.
    log INFO "Caching RKE2 artifacts (downloads -> $DOWNLOADS_DIR, stage -> $STAGE_DIR)"
    cache_rke2_artifacts
    log INFO "Completed artifact caching; scanning staged/downloaded artifacts for verification"

    # Trust any configured registries (may install custom CA into registries.yaml)
    ca_trust_registries

    # Immediately collect a list of relevant artifacts for reporting and checksum verification.
    # We will inspect both downloads and staged paths so the SBOM and logs accurately reflect
    # what the image action produced.
    log INFO "Collecting artifact inventory for verification"

  # --- Save site defaults (DNS/search) ---------------------------------------
  local STATE="/etc/rke2image.defaults"
  {
    echo "DEFAULT_DNS=\"$defaultDnsCsv\""
    echo "DEFAULT_SEARCH=\"$defaultSearchCsv\""
  } > "$STATE"
  chmod 600 "$STATE"
  log INFO "Saved site defaults: DNS=[$defaultDnsCsv], SEARCH=[$defaultSearchCsv]"

  # --- SBOM and README -------------------------------------------------------
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
  log INFO "Creating SBOM..."
  mkdir -p "$SBOM_DIR"
  local sbom_name="${SPEC_NAME:-image}"
  local sbom_file="$SBOM_DIR/${sbom_name}-sbom.txt"
  # Build sbom_targets to include both downloads and files staged into STAGE_DIR.
  local sbom_targets=(
    "$DOWNLOADS_DIR/$IMAGES_TAR"
    "$DOWNLOADS_DIR/$RKE2_TARBALL"
    "$DOWNLOADS_DIR/$SHA256_FILE"
    "$DOWNLOADS_DIR/install.sh"
    "$STAGE_DIR/$RKE2_TARBALL"
    "$STAGE_DIR/$SHA256_FILE"
    "$STAGE_DIR/install.sh"
  )
  [[ -n "$full_tgz" ]] && sbom_targets+=("$DOWNLOADS_DIR/$full_tgz")
  [[ -n "$std_tgz"  ]] && sbom_targets+=("$DOWNLOADS_DIR/$std_tgz")
  # If there's a sha256 file available, load it to verify artifacts when possible.
  declare -A expected_hash=()
  if [[ -f "$DOWNLOADS_DIR/$SHA256_FILE" ]]; then
    log INFO "Found checksum manifest: $DOWNLOADS_DIR/$SHA256_FILE; loading expected checksums"
    while read -r h fn; do
      # Normalize filename to basename when checksums reference relative paths
      expected_hash["$(basename "$fn")"]="$h"
    done < <(awk '{print $1, $2}' "$DOWNLOADS_DIR/$SHA256_FILE")
  elif [[ -f "$STAGE_DIR/$SHA256_FILE" ]]; then
    log INFO "Found checksum manifest in stage: $STAGE_DIR/$SHA256_FILE; loading expected checksums"
    while read -r h fn; do expected_hash["$(basename "$fn")"]="$h"; done < <(awk '{print $1, $2}' "$STAGE_DIR/$SHA256_FILE")
  else
    log WARN "No SHA256 manifest located in $DOWNLOADS_DIR or $STAGE_DIR; per-artifact verification will be limited"
  fi

  # Prepare sbom header
  {
    echo "# RKE2 Image Prep SBOM"
    echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "RKE2_VERSION: ${RKE2_VERSION:-<auto>}"
    echo "REGISTRY: ${REGISTRY:-<none>}"
    echo
    echo "# Artifact inventory: path | size_bytes | sha256 | verified | mtime | source"
  } > "$sbom_file"

  # Track verification metrics for a simple security score
  local total_count=0 verified_count=0 manifest_present=0
  [[ ${#expected_hash[@]} -gt 0 ]] && manifest_present=1

  for f in "${sbom_targets[@]}"; do
    [[ -f "$f" ]] || continue
    # Use POSIX arithmetic expansion to increment counters to avoid failures
    # in environments where ((..)) might not be supported (defensive).
    total_count=$((total_count + 1))
    local fname size sha mtime src verified
    fname="$(basename "$f")"
    size=$(stat -c%s "$f" 2>/dev/null || echo 0)
    mtime=$(date -u -r "$f" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "<unknown>")
    sha=$(sha256sum "$f" | awk '{print $1}')
    src="$( [[ "$f" == "$DOWNLOADS_DIR"/* ]] && echo downloads || echo staged )"
    verified="unknown"
    if [[ -n "${expected_hash[$fname]:-}" ]]; then
      if [[ "${expected_hash[$fname]}" == "$sha" ]]; then
        verified="yes"
        verified_count=$((verified_count + 1))
      else
        verified="NO (mismatch)"
      fi
    else
      # No expected checksum: still report computed sha
      verified="no-manifest"
    fi

    # Append detailed entry to SBOM
    printf '%s | %s | %s | %s | %s | %s\n' "$f" "$size" "$sha" "$verified" "$mtime" "$src" >> "$sbom_file"
    # Also log the verification outcome for runtime visibility
    log INFO "Artifact: $f size=$size sha256=$sha verified=$verified"
  done

  # Compute a simple security score (0-100) so operators can quickly see if
  # the image collected expected metadata. This is intentionally simple and
  # conservative; projects wanting a richer score should integrate scanners.
  # Scoring heuristic (example):
  #   +40 if checksum manifest present
  #   +40 if all discovered artifacts were verified against manifest
  #   +20 if SBOM contains at least one artifact entry
  local security_score=0
  # Add 40 points if a manifest was present
  if [[ $manifest_present -eq 1 ]]; then
    security_score=$((security_score + 40))
  fi
  if [[ $total_count -gt 0 ]]; then
    # Add 40 points if all artifacts were verified
    if [[ $manifest_present -eq 1 && $verified_count -eq $total_count ]]; then
      security_score=$((security_score + 40))
    fi
    # Add 20 points if there is at least one artifact
    security_score=$((security_score + 20))
  fi

  {
    echo
    echo "# Summary"
    echo "Artifacts discovered: $total_count"
    echo "Artifacts verified against manifest: $verified_count"
    echo "SHA256 manifest present: ${manifest_present}" 
    echo "security_score: ${security_score}"
  } >> "$sbom_file"

  log INFO "SBOM written to $sbom_file (artifacts=$total_count verified=$verified_count security_score=$security_score)"

  # Also emit a machine-friendly JSON SBOM for tooling compatibility. We use
  # a small Python helper here to avoid fragile shell JSON escaping.
  local sbom_json_file="$SBOM_DIR/${sbom_name}-sbom.json"
  if command -v python3 >/dev/null 2>&1; then
  log INFO "Generating JSON SBOM: $sbom_json_file"
  python3 - "$sbom_file" "$sbom_json_file" <<'PY'
import sys, json
sbom_txt = sys.argv[1]
sbom_json = sys.argv[2]

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

data = {
  'metadata': header,
  'artifacts': artifacts,
  'summary': summary,
}

with open(sbom_json, 'w', encoding='utf-8') as out:
  json.dump(data, out, indent=2, sort_keys=True)
print(sbom_json)
PY
  if [[ $? -eq 0 ]]; then
    log INFO "JSON SBOM written to $sbom_json_file"
  else
    log WARN "Failed to generate JSON SBOM ($sbom_json_file)"
  fi
  else
  log WARN "python3 not available; skipping JSON SBOM generation"
  fi

  # README in outputs/<SPEC_NAME>
  log INFO "Write README in Outputs directory..."
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
      echo "Next:"
      echo "  - Shut down this VM and clone it for use in the air-gapped environment."
      echo "  - Then run this script in 'server' or 'agent' mode on the clone(s)."
    } > "$RUN_OUT_DIR/README.txt"
    log INFO "Wrote $RUN_OUT_DIR/README.txt"
  fi

 # Image prep complete
  log INFO "Image prep complete..."
  echo "[READY] Minimal image prep complete. Cached artifacts in: $DOWNLOADS_DIR"
  echo "        - You can now install RKE2 offline using the cached tarballs."
  echo
  prompt_reboot
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
  log INFO "Ensure YAML has metadata.name..."

  log INFO "Loading site defaults..."
  load_site_defaults

  local IP="" PREFIX="" HOSTNAME="" DNS="" SEARCH=""
  local TLS_SANS_IN="" TLS_SANS="" TOKEN="" GW=""
  local -a NET_INTERFACES=()

  log INFO "Reading configuration from YAML (if provided)..."
  if [[ -n "$CONFIG_FILE" ]]; then
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
  fi

  log INFO "Reading configuration from CLI args (if provided)..."
  local -A server_cli=()
  parse_action_cli_args server_cli "server" "${ACTION_ARGS[@]}"

  local yaml_has_interfaces=0
  if [[ -n "$CONFIG_FILE" ]] && yaml_spec_has_list "$CONFIG_FILE" "interfaces"; then
    yaml_has_interfaces=1
  fi

  log INFO "Merging configuration values..."
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

  log INFO "Prompting for any missing configuration values..."
  if [[ -z "$HOSTNAME" ]];then read -rp "Enter hostname for this agent node: " HOSTNAME; fi
  if [[ -z "$IP" ]];      then read -rp "Enter static IPv4 for this agent node: " IP; fi
  if [[ -z "$PREFIX" ]];  then read -rp "Enter subnet prefix length (0-32) [default 24]: " PREFIX; fi
  if [[ -z "$GW" ]];      then read -rp "Enter default gateway IPv4 [leave blank to skip]: " GW || true; fi

  log INFO "Resolving DNS and search domains..."
  if [[ -z "$DNS" ]]; then
    read -rp "Enter DNS IPv4s (comma-separated) [blank=default ${DEFAULT_DNS}]: " DNS || true
    [[ -z "$DNS" ]] && DNS="$DEFAULT_DNS"
  fi
  if [[ -z "$SEARCH" && -n "${DEFAULT_SEARCH:-}" ]]; then
    SEARCH="$DEFAULT_SEARCH"
  fi

  log INFO "Validating configuration..."
  while ! valid_ipv4 "$IP"; do read -rp "Invalid IPv4. Re-enter server IP: " IP; done
  while ! valid_prefix "${PREFIX:-}"; do read -rp "Invalid prefix (0-32). Re-enter [default 24]: " PREFIX; done
  while ! valid_ipv4_or_blank "${GW:-}"; do read -rp "Invalid gateway IPv4 (or blank). Re-enter: " GW; done
  while ! valid_csv_dns "${DNS:-}"; do read -rp "Invalid DNS list. Re-enter CSV IPv4s: " DNS; done
  while ! valid_search_domains_csv "${SEARCH:-}"; do read -rp "Invalid search domains CSV. Re-enter: " SEARCH; done
  [[ -z "${PREFIX:-}" ]] && PREFIX=24

  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH

  log INFO "Determining TLS SANs..."
  if [[ -z "$TLS_SANS" ]]; then
    if [[ -z "$TLS_SANS_IN" && -n "${CONFIG_FILE:-}" ]]; then
      TLS_SANS_IN="$(yaml_spec_get "$CONFIG_FILE" tlsSans || true)"
      [[ -z "$TLS_SANS_IN" ]] && TLS_SANS_IN="$(yaml_spec_list_csv "$CONFIG_FILE" tls-san || true)"
      [[ -n "$TLS_SANS_IN" ]] && TLS_SANS="$(normalize_list_csv "$TLS_SANS_IN")"
	  log INFO "TLS SANs from config: $TLS_SANS"
    fi
    if [[ -z "$TLS_SANS" ]]; then
      TLS_SANS="$(capture_sans "$HOSTNAME" "$IP" "$SEARCH")"
      log INFO "Auto-derived TLS SANs: $TLS_SANS"
    fi
  fi

  log INFO "Ensuring staged artifacts for offline RKE2 server install..."
  ensure_staged_artifacts

  log INFO "Setting new hostname: $HOSTNAME..."
  hostnamectl set-hostname "$HOSTNAME"
  if ! grep -qE "[[:space:]]$HOSTNAME(\$|[[:space:]])" /etc/hosts; then echo "$IP $HOSTNAME" >> /etc/hosts; fi

  log INFO "Seeding custom cluster CA..."
  setup_custom_cluster_ca || true

  local prompt_extra_ifaces=1
  if (( ${#NET_INTERFACES[@]} )); then
    if (( yaml_has_interfaces )); then
      prompt_extra_ifaces=0
      log INFO "Interfaces defined in YAML manifest; skipping interactive prompt for additional NICs."
    elif [[ -n "${server_cli[interfaces]:-}" ]]; then
      prompt_extra_ifaces=0
      log INFO "Interfaces provided via CLI flags; skipping interactive prompt for additional NICs."
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
    log INFO "Network interfaces prepared: ${_iface_summary}"
  fi

  log INFO "Validating/expanding provided token (if any)..."
  if [[ -n "$TOKEN" ]]; then
    local full_token
    full_token="$(ensure_full_cluster_token "$TOKEN")"
    if [[ -n "$full_token" ]]; then
      if [[ "$full_token" != "$TOKEN" ]]; then
        log INFO "Expanded provided token to full format (custom CA hash included)."
      fi
      TOKEN="$full_token"
    fi
  else
    TOKEN="$(generate_bootstrap_token)"
    if [[ "$TOKEN" =~ ^K10[0-9a-fA-F]{64}::server: ]]; then
      log INFO "Using generated secure first-server token (custom CA fingerprint embedded)."
    else
      log INFO "Using generated short first-server bootstrap token."
    fi
  fi

  log INFO "Writing file: /etc/rancher/rke2/config.yaml..."
  mkdir -p /etc/rancher/rke2

  : > /etc/rancher/rke2/config.yaml
  {
    log INFO "Setting debug..." >&2
    echo "debug: true"

    log INFO "Get token..." >&2
    if [[ -n "$TOKEN" ]]; then
      echo "token: $TOKEN"
	  log INFO "Using provided token..." >&2
    elif [[ -n "$TOKEN_FILE" ]]; then
      echo "token-file: \"$TOKEN_FILE\""
	  log INFO "Using provided token file: $TOKEN_FILE..." >&2
    fi

    log INFO "Append additional keys from YAML spec (cluster-cidr, domain, cni, etc.)..." >&2
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
  log INFO "Wrote /etc/rancher/rke2/config.yaml"

  log INFO "Setting file security: chmod 600 /etc/rancher/rke2/config.yaml..."
  chmod 600 /etc/rancher/rke2/config.yaml

  log INFO "Writing netplan configuration and applying network settings..."
  if (( ${#NET_INTERFACES[@]} )); then
    write_netplan --interfaces "${NET_INTERFACES[@]}"
  else
    write_netplan "$IP" "$PREFIX" "${GW:-}" "${DNS:-}" "${SEARCH:-}"
  fi

  log INFO "Installing rke2-server from cache at $STAGE_DIR"
  run_rke2_installer "$STAGE_DIR" "server"
  systemctl enable rke2-server >>"$LOG_FILE" 2>&1 || true

  log INFO "Deploying flannel TX checksum offload fix..."
  install_flannel_txcsum_fix

  echo
  echo "[READY] rke2-server installed. Reboot to initialize the control plane."
  echo "        First server token: /var/lib/rancher/rke2/server/node-token"
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
  log INFO "Ensure YAML has metadata.name..."

  log INFO "Loading site defaults..."
  load_site_defaults

  local IP="" PREFIX="" HOSTNAME="" DNS="" SEARCH=""
  local TOKEN="" GW=""  URL="" TOKEN_FILE=""
  local -a NET_INTERFACES=()
  local NODE_IP_SPEC="" NODE_NAME_SPEC=""

  log INFO "Reading configuration from YAML (if provided)..."
  if [[ -n "$CONFIG_FILE" ]]; then
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

  log INFO "Prompting for any missing configuration values..."
  if [[ -z "$HOSTNAME" ]];then read -rp "Enter hostname for this agent node: " HOSTNAME; fi
  if [[ -z "$IP" ]];      then read -rp "Enter static IPv4 for this agent node: " IP; fi
  if [[ -z "$PREFIX" ]];  then read -rp "Enter subnet prefix length (0-32) [default 24]: " PREFIX; fi
  if [[ -z "$GW" ]];      then read -rp "Enter default gateway IPv4 [leave blank to skip]: " GW || true; fi

  log INFO "Resolving DNS and search domains..."
  if [[ -z "$DNS" ]]; then
    read -rp "Enter DNS IPv4s (comma-separated) [blank=default ${DEFAULT_DNS}]: " DNS || true
    if [[ -z "$DNS" ]]; then DNS="$DEFAULT_DNS"; log INFO "Using default DNS for agent: $DNS"; fi
  fi
  if [[ -z "$SEARCH" && -n "${DEFAULT_SEARCH:-}" ]]; then
    SEARCH="$DEFAULT_SEARCH"
    log INFO "Using default search domains for agent: $SEARCH"
  fi

  log INFO "Validating configuration..."
  while ! valid_ipv4 "$IP"; do read -rp "Invalid IPv4. Re-enter agent IP: " IP; done
  while ! valid_prefix "${PREFIX:-}"; do read -rp "Invalid prefix (0-32). Re-enter agent prefix [default 24]: " PREFIX; done
  while ! valid_ipv4_or_blank "${GW:-}"; do read -rp "Invalid gateway IPv4 (or blank). Re-enter: " GW; done
  while ! valid_csv_dns "${DNS:-}"; do read -rp "Invalid DNS list. Re-enter CSV IPv4s: " DNS; done
  while ! valid_search_domains_csv "${SEARCH:-}"; do read -rp "Invalid search domain list. Re-enter CSV: " SEARCH; done
  [[ -z "${PREFIX:-}" ]] && PREFIX=24

  merge_primary_interface_fields NET_INTERFACES IP PREFIX GW DNS SEARCH

  log INFO "Ensuring staged artifacts for offline RKE2 agent install..."
  ensure_staged_artifacts

  log INFO "Setting new hostname: $HOSTNAME..."
  hostnamectl set-hostname "$HOSTNAME"
  if ! grep -qE "[[:space:]]$HOSTNAME(\$|[[:space:]])" /etc/hosts; then echo "$IP $HOSTNAME" >> /etc/hosts; fi

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
    log INFO "Network interfaces prepared: ${_iface_summary}"
  fi

  log INFO "Gathering cluster join information..."
  if [[ -z "$URL" ]]; then
    read -rp "Enter RKE2 server URL (e.g., https://<server-ip>:9345) [optional]: " URL || true
  fi
  if [[ -n "$URL" && -z "$TOKEN" && -z "$TOKEN_FILE" ]]; then
    read -rp "Enter cluster join token [optional]: " TOKEN || true
  fi
  if [[ -z "$TOKEN" && -z "$TOKEN_FILE" ]]; then
    read -rp "Enter path to token file (optional, used when token not provided): " TOKEN_FILE || true
  fi

  log INFO "Validating/expanding provided token (if any)..."
  if [[ -n "$TOKEN" ]]; then
    local full_token=""
    full_token="$(ensure_full_cluster_token "$TOKEN")"
    if [[ -n "$full_token" ]]; then
      if [[ "$full_token" != "$TOKEN" ]]; then
        log INFO "Expanded agent join token to full format (custom CA hash included)."
      fi
      TOKEN="$full_token"
    fi
  fi

  log INFO "Writing file: /etc/rancher/rke2/config.yaml..."
  mkdir -p /etc/rancher/rke2

  : > /etc/rancher/rke2/config.yaml
  {
    log INFO "Setting debug..." >&2
    echo "debug: true"

    log INFO "Setting server URL..." >&2
    echo "server: \"$URL\""     # required

    log INFO "Get token..." >&2
    if [[ -n "$TOKEN" ]]; then
      echo "token: $TOKEN"
	  log INFO "Using provided token..." >&2
    elif [[ -n "$TOKEN_FILE" ]]; then
      echo "token-file: \"$TOKEN_FILE\""
	  log INFO "Using provided token file: $TOKEN_FILE..." >&2
    fi

    log INFO "Append additional keys from YAML spec (cluster-cidr, domain, cni, etc.)..." >&2
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
  log INFO "Wrote /etc/rancher/rke2/config.yaml"

  log INFO "Setting file security: chmod 600 /etc/rancher/rke2/config.yaml..."
  chmod 600 /etc/rancher/rke2/config.yaml

  log INFO "Writing netplan configuration and applying network settings..."
  if (( ${#NET_INTERFACES[@]} )); then
    write_netplan --interfaces "${NET_INTERFACES[@]}"
  else
    write_netplan "$IP" "$PREFIX" "${GW:-}" "${DNS:-}" "${SEARCH:-}"
  fi

  log INFO "Installing rke2-server from cache at $STAGE_DIR"
  run_rke2_installer "$STAGE_DIR" "agent"
  systemctl enable rke2-agent >>"$LOG_FILE" 2>&1 || true

  log INFO "Deploying flannel TX checksum offload fix..."
  install_flannel_txcsum_fix

  echo
  echo "[READY] rke2-agent installed. Reboot to initialize the worker node."
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
  log INFO "Ensure YAML has metadata.name..."

  log INFO "Loading site defaults..."
  load_site_defaults

  local IP="" PREFIX="" HOSTNAME="" DNS="" SEARCH=""
  local TLS_SANS_IN="" TLS_SANS="" TOKEN="" GW=""
  local URL="" TOKEN_FILE=""
  local -a NET_INTERFACES=()

  log INFO "Reading configuration from YAML (if provided)..."
  if [[ -n "$CONFIG_FILE" ]]; then
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

  log INFO "Prompting for any missing configuration values..."
  if [[ -z "$HOSTNAME" ]];then read -rp "Enter hostname for this agent node: " HOSTNAME; fi
  if [[ -z "$IP" ]];      then read -rp "Enter static IPv4 for this agent node: " IP; fi
  if [[ -z "$PREFIX" ]];  then read -rp "Enter subnet prefix length (0-32) [default 24]: " PREFIX; fi
  if [[ -z "$GW" ]];      then read -rp "Enter default gateway IPv4 [leave blank to skip]: " GW || true; fi

  log INFO "Resolving DNS and search domains..."
  if [[ -z "$DNS" ]]; then
    read -rp "Enter DNS IPv4s (comma-separated) [blank=default ${DEFAULT_DNS}]: " DNS || true
    [[ -z "$DNS" ]] && DNS="$DEFAULT_DNS"
  fi
  if [[ -z "$SEARCH" && -n "${DEFAULT_SEARCH:-}" ]]; then
    SEARCH="$DEFAULT_SEARCH"
  fi

  log INFO "Validating configuration..."
  while ! valid_ipv4 "$IP"; do read -rp "Invalid IPv4. Re-enter server IP: " IP; done
  while ! valid_prefix "${PREFIX:-}"; do read -rp "Invalid prefix (0-32). Re-enter server prefix [default 24]: " PREFIX; done
  while ! valid_ipv4_or_blank "${GW:-}"; do read -rp "Invalid gateway IPv4 (or blank). Re-enter: " GW; done
  while ! valid_csv_dns "${DNS:-}"; do read -rp "Invalid DNS list. Re-enter CSV IPv4s: " DNS; done
  while ! valid_search_domains_csv "${SEARCH:-}"; do read -rp "Invalid search domain list. Re-enter CSV: " SEARCH; done
  [[ -z "${PREFIX:-}" ]] && PREFIX=24

  # Auto-derive tls-sans if none provided in YAML
  log INFO "Determining TLS SANs..."
  if [[ -z "$TLS_SANS" ]]; then
    if [[ -z "$TLS_SANS_IN" && -n "${CONFIG_FILE:-}" ]]; then
      TLS_SANS_IN="$(yaml_spec_get "$CONFIG_FILE" tlsSans || true)"
      [[ -z "$TLS_SANS_IN" ]] && TLS_SANS_IN="$(yaml_spec_list_csv "$CONFIG_FILE" tls-san || true)"
      [[ -n "$TLS_SANS_IN" ]] && TLS_SANS="$(normalize_list_csv "$TLS_SANS_IN")"
	  log INFO "TLS SANs from config: $TLS_SANS"
    fi
    if [[ -z "$TLS_SANS" ]]; then
      TLS_SANS="$(capture_sans "$HOSTNAME" "$IP" "$SEARCH")"
      log INFO "Auto-derived TLS SANs: $TLS_SANS"
    fi
  fi

  log INFO "Ensuring staged artifacts for offline RKE2 server install..."
  ensure_staged_artifacts

  log INFO "Setting new hostname: $HOSTNAME..."
  hostnamectl set-hostname "$HOSTNAME"
  if ! grep -qE "[[:space:]]$HOSTNAME(\$|[[:space:]])" /etc/hosts; then echo "$IP $HOSTNAME" >> /etc/hosts; fi

  log INFO "Seeding custom cluster CA..."
  setup_custom_cluster_ca || true

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
    log INFO "Network interfaces prepared: ${_iface_summary}"
  fi

  log INFO "Gathering cluster join information..."
  [[ -z "$URL" ]] && read -rp "Enter EXISTING RKE2 server URL (e.g. https://<vip-or-node>:9345): " URL
  if [[ -z "$TOKEN" && -z "$TOKEN_FILE" ]]; then
    read -rp "Enter cluster join token (leave blank to provide a token file path): " TOKEN || true
    if [[ -z "$TOKEN" ]]; then
      read -rp "Enter path to token file (e.g., /var/lib/rancher/rke2/server/node-token): " TOKEN_FILE || true
    fi
  fi
  [[ -z "$TLS_SANS" ]] && read -rp "Optional TLS SANs (CSV; hostnames/IPs) [blank=skip]: " TLS_SANS || true

  log INFO "Validating/expanding provided token (if any)..."
  if [[ -n "$TOKEN" ]]; then
    local full_token=""
    full_token="$(ensure_full_cluster_token "$TOKEN")"
    if [[ -n "$full_token" ]]; then
      if [[ "$full_token" != "$TOKEN" ]]; then
        log INFO "Expanded server join token to full format (custom CA hash included)."
      fi
      TOKEN="$full_token"
    fi
  fi

  log INFO "Writing file: /etc/rancher/rke2/config.yaml..."
  mkdir -p /etc/rancher/rke2

  : > /etc/rancher/rke2/config.yaml
  {
    log INFO "Setting debug..." >&2
    echo "debug: true"

    log INFO "Setting server URL..." >&2
    echo "server: \"$URL\""     # required

    log INFO "Get token..." >&2
    if [[ -n "$TOKEN" ]]; then
      echo "token: $TOKEN"
	  log INFO "Using provided token..." >&2
    elif [[ -n "$TOKEN_FILE" ]]; then
      echo "token-file: \"$TOKEN_FILE\""
	  log INFO "Using provided token file: $TOKEN_FILE..." >&2
    fi

    log INFO "Append additional keys from YAML spec (cluster-cidr, domain, cni, etc.)..." >&2
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
  log INFO "Wrote /etc/rancher/rke2/config.yaml"

  log INFO "Setting file security: chmod 600 /etc/rancher/rke2/config.yaml..."
  chmod 600 /etc/rancher/rke2/config.yaml

  log INFO "Writing netplan configuration and applying network settings..."
  if (( ${#NET_INTERFACES[@]} )); then
    write_netplan --interfaces "${NET_INTERFACES[@]}"
  else
    write_netplan "$IP" "$PREFIX" "${GW:-}" "${DNS:-}" "${SEARCH:-}"
  fi

  log INFO "Installing rke2-server from cache at $STAGE_DIR"
  run_rke2_installer "$STAGE_DIR" "server"
  systemctl enable rke2-server >>"$LOG_FILE" 2>&1 || true

  log INFO "Deploying flannel TX checksum offload fix..."
  install_flannel_txcsum_fix

  echo
  echo "[READY] rke2-server installed. Reboot to initialize the control plane."
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
action_verify() {
  load_site_defaults
if verify_prereqs; then
    log INFO "VERIFY PASSED: Node meets RKE2 prerequisites."
    exit 0
  else
    log ERROR "VERIFY FAILED: See messages above and fix issues."
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
  NO_REBOOT=1 action_image
  sync
  log WARN "Powering off now so you can template/clone the VM."
  sleep 3
  poweroff
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
action_custom_ca() {
  initialize_action_context false "custom-ca"

  if [[ -z "${CONFIG_FILE:-}" ]]; then
    log ERROR "Custom-CA action requires a YAML file (-f <file>)"
    exit 5
  fi

  local kind_folded="${YAML_KIND:-}"
  kind_folded="${kind_folded,,}"
  if [[ "${kind_folded//-/}" != "customca" ]]; then
    log ERROR "Custom-CA action expects kind: CustomCA|Custom-CA|customca|custom-CA|custom-ca (found: ${YAML_KIND:-<none>})"
    exit 5
  fi

  log INFO "Loading custom CA from YAML..."
  load_custom_ca_from_config "$CONFIG_FILE" "" 1

  if [[ -z "${CUSTOM_CA_ROOT_CRT:-}" && -z "${CUSTOM_CA_INT_CRT:-}" ]]; then
    log ERROR "spec.customCA must define at least rootCrt or intermediateCrt"
    exit 5
  fi

  log INFO "Generating bootstrap token from custom CA..."

  local TOKEN="" TOKEN_FILE=""
  generate_bootstrap_token
  TOKEN=$token

  if [[ -z "$TOKEN" ]]; then
    log ERROR "Failed to generate bootstrap token."
    exit 1
  else
    TOKEN_FILE="${OUT_DIR}/${SPEC_NAME}-bootstrap-token.txt"
    echo "$TOKEN" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    log INFO "Token saved to $TOKEN_FILE"
  fi

  log INFO "Generated bootstrap token successfully."
}

# ================================================================================================
# ARGUMENT PARSING
# ================================================================================================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-push) DRY_PUSH=1; shift;;
    --apply-netplan-now) APPLY_NETPLAN_NOW=1; shift;;
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
    -f|-v|-r|-u|-p|-n|-y|-P|-h|push|image|server|add-server|agent|verify) break;;
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
  API="$(yaml_get_api "$CONFIG_FILE" || true)"
  YAML_KIND="$(yaml_get_kind "$CONFIG_FILE" || true)"
  if [[ "$API" != "rkeprep/v1" ]]; then
    log ERROR "Unsupported apiVersion: '$API' (expected rkeprep/v1)"; exit 5
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

