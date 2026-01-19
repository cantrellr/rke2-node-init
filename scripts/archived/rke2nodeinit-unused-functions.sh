#!/usr/bin/env bash
# ==============================================================================
# File: rke2nodeinit-unused-functions.sh
# Purpose: Archive of unused functions from rke2nodeinit.sh
# Date: November 7, 2025
# 
# This file contains functions that were identified as unused during code
# analysis. They are preserved here for potential future use or reference.
# ==============================================================================

# ------------------------------------------------------------------------------
# Function: yaml_spec_interfaces
# Purpose : Extract spec.interfaces entries from YAML as encoded NIC strings.
# Status  : UNUSED - Redundant with yaml_spec_get approach used in collect_interface_specs
# Arguments:
#   $1 - Path to YAML configuration file
# Returns :
#   Prints encoded interface strings to stdout (one per line)
# Notes   : This was part of the multi-interface networking feature but the
#           actual implementation uses yaml_spec_get instead.
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

# ------------------------------------------------------------------------------
# Function: emit_tls_sans
# Purpose : Write the tls-san YAML list derived from capture_sans() into the
#           config file while trimming empty entries.
# Status  : UNUSED - SANs are captured via capture_sans() but never formatted with this
# Arguments:
#   $1 - CSV string of SAN entries
# Returns :
#   Prints a YAML fragment to stdout.
# Notes   : Consider integrating this into config generation if TLS SAN
#           formatting is needed.
# ------------------------------------------------------------------------------
emit_tls_sans() {
  local csv="$1"
  [[ -z "$csv" ]] && return 0
  echo "tls-san:"
  IFS=',' read -r -a _sans <<<"$csv"
  for s in "${_sans[@]}"; do
    s="${s//\"/}"; s="${s// /}"
    [[ -n "$s" ]] && echo "  - \"$s\""
  done
}

# ------------------------------------------------------------------------------
# Function: load_staged_images
# Purpose : Load the pre-downloaded RKE2 image archive into containerd using
#           nerdctl so offline hosts have required images available.
# Status  : UNUSED - Potentially useful for air-gapped scenarios
# Arguments:
#   None
# Returns :
#   Returns 0 on success, exits when archive missing.
# Notes   : This could be valuable for offline/air-gapped installations.
#           Consider integrating into action_airgap or action_push workflows.
# ------------------------------------------------------------------------------
load_staged_images() {
  # Load any pre-staged images into containerd so we can retag them.
  shopt -s nullglob
  local loaded=0
  for f in /var/lib/rancher/rke2/agent/images/*.tar*; do
    case "$f" in
      *.zst)  zstdcat "$f" | nerdctl --namespace k8s.io load >/dev/null 2>&1 || true ;;
      *.gz)   gzip -dc "$f" | nerdctl --namespace k8s.io load >/dev/null 2>&1 || true ;;
      *.tar)  nerdctl --namespace k8s.io load -i "$f" >/dev/null 2>&1 || true ;;
    esac
    loaded=1
  done
  shopt -u nullglob
  if (( loaded == 1 )); then
    log INFO "Loaded staged images into containerd namespace k8s.io."
  else
    log INFO "No staged images to load (skip)."
  fi
}

# ------------------------------------------------------------------------------
# Function: retag_local_images_with_prefix
# Purpose : Apply a registry prefix to all cached images to mimic the structure
#           of the private registry prior to pushing.
# Status  : UNUSED - Registry image retagging functionality not currently invoked
# Arguments:
#   $1 - Registry hostname or namespace prefix
# Returns :
#   Returns 0 on success.
# Notes   : Could be useful for private registry workflows. Consider integrating
#           with action_push or registry configuration logic.
# ------------------------------------------------------------------------------
retag_local_images_with_prefix() {
  # Give every locally available image an additional name that includes the private registry host.
  # This guarantees kubelet/containerd can find the content locally when it asks for
  # e.g. <regHost>/rancher/mirrored-pause:3.6.
  local reg_host="$1"
  [[ -z "$reg_host" ]] && return 0

  # Make a best effort and stay quiet on errors
  mapfile -t imgs < <(nerdctl --namespace k8s.io images --format '{{.Repository}}:{{.Tag}}' \
                      | awk '$0 !~ /<none>/' | sort -u)
  local ref
  for ref in "${imgs[@]}"; do
    local new_ref="${reg_host}/${ref}"
    nerdctl --namespace k8s.io tag "$ref" "$new_ref" >/dev/null 2>&1 || true
  done
  log INFO "Retagged $(( ${#imgs[@]} )) images with prefix ${reg_host}."
}

# ------------------------------------------------------------------------------
# Function: ensure_hosts_pin
# Purpose : Ensure /etc/hosts contains an entry mapping the registry hostname to
#           the provided IP when strict pinning is requested.
# Status  : UNUSED - Registry hostname pinning not currently invoked
# Arguments:
#   $1 - Registry hostname
#   $2 - IPv4 address
# Returns :
#   Returns 0 on success.
# Notes   : Could be useful for offline/air-gapped scenarios when DNS is not
#           available. Consider integrating with registry configuration logic.
# ------------------------------------------------------------------------------
ensure_hosts_pin() {
  # Optionally force-resolve a registry name when DNS is not yet populated.
  local host="$1" ip="$2"
  [[ -z "$host" || -z "$ip" ]] && return 0
  if ! grep -qE "^[[:space:]]*${ip}[[:space:]]+${host}(\s|$)" /etc/hosts; then
    echo "$ip $host" >> /etc/hosts
    log INFO "Pinned $host → $ip in /etc/hosts"
  fi
}
