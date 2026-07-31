#!/usr/bin/env bash
#
# Public RKE2 node initialization entrypoint.
#
# This dispatcher keeps the historical operator command stable while allowing
# rkeprep/v2 manifests to drive the action through their YAML kind. The original
# implementation is preserved in bin/rke2nodeinit-core.sh and remains the owner
# of the legacy provisioning functions.

set -Eeuo pipefail
trap 'rc=$?; echo "[ERROR] ${BASH_SOURCE[0]} failed at line ${LINENO} with exit ${rc}" >&2; exit ${rc}' ERR
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
CORE_SCRIPT="${SCRIPT_DIR}/rke2nodeinit-core.sh"
SINGLE_NODE_SCRIPT="${SCRIPT_DIR}/rke2nodeinit-single-node.sh"
SYSTEM_HELPER="${SCRIPT_DIR}/rke2nodeinit-system.sh"
REGISTRY_HELPER="${SCRIPT_DIR}/rke2nodeinit-registry.sh"
SECURE_REGISTRY_CONFIG=""

[[ -f "$SYSTEM_HELPER" ]] || { echo "ERROR: Missing system helper: $SYSTEM_HELPER" >&2; exit 1; }
[[ -f "$REGISTRY_HELPER" ]] || { echo "ERROR: Missing registry helper: $REGISTRY_HELPER" >&2; exit 1; }
# shellcheck source=bin/rke2nodeinit-system.sh
source "$SYSTEM_HELPER"
# shellcheck source=bin/rke2nodeinit-registry.sh
source "$REGISTRY_HELPER"

cleanup_secure_registry_config() {
  if [[ -n "${SECURE_REGISTRY_CONFIG:-}" ]]; then
    rke2nodeinit_registry_remove_staged_manifest "$SECURE_REGISTRY_CONFIG"
    SECURE_REGISTRY_CONFIG=""
  fi
}
trap cleanup_secure_registry_config EXIT

usage() {
  cat <<'USAGE'
Usage:
  sudo bin/rke2nodeinit.sh [action] [options]
  sudo bin/rke2nodeinit.sh -f <rkeprep-yaml> [options]

When -f/--file is provided and no action is supplied, the action is resolved
from apiVersion: rkeprep/v2 and kind: in the manifest.

Supported kind dispatch:
  Push             -> push
  Image            -> image
  singleNodeImage  -> single-node image flow
  Server           -> server
  singleNodeServer -> single-node server flow
  AddServer        -> add-server
  Agent            -> agent
  Verify           -> verify
  Airgap           -> airgap
  CustomCA         -> custom-ca

For Image and singleNodeImage manifests, spec.secureRegistry: true requires
registry credentials. Prefer registryUsernameFile and registryPasswordFile, or
set RKE2_REGISTRY_USERNAME_FILE and RKE2_REGISTRY_PASSWORD_FILE. The dispatcher
stages a root-only runtime manifest and removes it when provisioning completes.

For Server, AddServer, Agent, and singleNodeServer manifests that enable the CIS
profile, the dispatcher applies and persists the RKE2-required kernel parameters
before handing control to the provisioning engine.

Legacy action-first and option-first forms are both accepted:
  sudo bin/rke2nodeinit.sh image -f config.yaml -y
  sudo bin/rke2nodeinit.sh -f config.yaml image -y
  sudo bin/rke2nodeinit.sh -f config.yaml -y
USAGE
}

is_action() {
  case "${1:-}" in
    push|image|server|add-server|agent|verify|airgap|label-node|taint-node|custom-ca) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_kind() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]_-'
}

kind_to_action() {
  case "$(normalize_kind "${1:-}")" in
    push) echo push ;;
    image) echo image ;;
    singlenodeimage) echo image ;;
    server) echo server ;;
    singlenodeserver) echo server ;;
    addserver) echo add-server ;;
    agent) echo agent ;;
    verify) echo verify ;;
    airgap) echo airgap ;;
    customca) echo custom-ca ;;
    *) return 1 ;;
  esac
}

kind_is_single_node() {
  case "$(normalize_kind "${1:-}")" in
    singlenodeimage|singlenodeserver) return 0 ;;
    *) return 1 ;;
  esac
}

read_yaml_kind() {
  local file="${1:-}"
  [[ -n "$file" && -f "$file" ]] || return 1

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$file" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
api = None
kind = None
for raw in path.read_text(encoding='utf-8').splitlines():
    line = raw.split('#', 1)[0].strip()
    if not line:
        continue
    if api is None:
        m = re.match(r'^apiVersion\s*:\s*["\']?([^"\']+)["\']?\s*$', line)
        if m:
            api = m.group(1).strip()
            continue
    if kind is None:
        m = re.match(r'^kind\s*:\s*["\']?([^"\']+)["\']?\s*$', line)
        if m:
            kind = m.group(1).strip()
            continue
    if api and kind:
        break
if api and api != 'rkeprep/v2':
    raise SystemExit(2)
if kind:
    print(kind)
PY
    return $?
  fi

  awk -F: '
    /^[[:space:]]*kind[[:space:]]*:/ {
      gsub(/["'"'"'[:space:]]/, "", $2);
      print $2;
      exit 0;
    }
  ' "$file"
}

parent_is_single_node_helper() {
  local parent=""
  parent="$(ps -o args= -p "${PPID:-0}" 2>/dev/null || true)"
  case "$parent" in
    *rke2-single-node-profile.sh*|*rke2nodeinit-single-node.sh*) return 0 ;;
    *) return 1 ;;
  esac
}

normalize_args() {
  ACTION=""
  CONFIG_FILE=""
  NORMALIZED_ARGS=()

  local pending=""
  local arg
  while [[ $# -gt 0 ]]; do
    arg="$1"
    shift

    if [[ -n "$pending" ]]; then
      NORMALIZED_ARGS+=("$arg")
      pending=""
      continue
    fi

    case "$arg" in
      --)
        NORMALIZED_ARGS+=("$arg" "$@")
        break
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      -f|--file)
        [[ $# -gt 0 ]] || { echo "ERROR: $arg requires a value" >&2; exit 1; }
        CONFIG_FILE="$1"
        NORMALIZED_ARGS+=("$arg" "$1")
        shift
        ;;
      --file=*)
        CONFIG_FILE="${arg#*=}"
        NORMALIZED_ARGS+=("$arg")
        ;;
      -v|-r|-u|-p|-n|--node-name|--interface|--boot-yaml-path|--boot-mode|--vm-platform|--mode|--output-dir|--manifest-dir)
        NORMALIZED_ARGS+=("$arg")
        pending=1
        ;;
      --*=*)
        NORMALIZED_ARGS+=("$arg")
        ;;
      -* )
        NORMALIZED_ARGS+=("$arg")
        ;;
      *)
        if [[ -z "$ACTION" ]] && is_action "$arg"; then
          ACTION="$arg"
        else
          NORMALIZED_ARGS+=("$arg")
        fi
        ;;
    esac
  done
}

normalized_args_contain() {
  local needle="${1:-}"
  local arg=""
  [[ -n "$needle" ]] || return 1

  for arg in "${NORMALIZED_ARGS[@]:-}"; do
    [[ "$arg" == "$needle" ]] && return 0
  done

  return 1
}

replace_normalized_config_file() {
  local replacement="${1:-}"
  local index=0

  [[ -n "$replacement" ]] || return 1

  for ((index = 0; index < ${#NORMALIZED_ARGS[@]}; index++)); do
    case "${NORMALIZED_ARGS[$index]}" in
      -f|--file)
        if (( index + 1 >= ${#NORMALIZED_ARGS[@]} )); then
          echo "ERROR: malformed config-file argument." >&2
          return 1
        fi
        NORMALIZED_ARGS[$((index + 1))]="$replacement"
        CONFIG_FILE="$replacement"
        return 0
        ;;
      --file=*)
        NORMALIZED_ARGS[$index]="--file=$replacement"
        CONFIG_FILE="$replacement"
        return 0
        ;;
    esac
  done

  echo "ERROR: unable to replace config-file argument for secure registry staging." >&2
  return 1
}

prepare_secure_registry_config() {
  local action="${1:-}"
  local manifest="${2:-}"
  local runtime_dir="${RKE2NODEINIT_RUNTIME_DIR:-/run/rke2-node-init}"
  local staged=""
  local detection_rc=0

  [[ "$action" == "image" ]] || return 0
  [[ -n "$manifest" && -f "$manifest" ]] || return 0

  if rke2nodeinit_registry_manifest_is_secure "$manifest"; then
    :
  else
    detection_rc=$?
    if [[ "$detection_rc" -eq 1 ]]; then
      return 0
    fi
    return "$detection_rc"
  fi

  install -d -m 0700 "$runtime_dir"
  staged="$(mktemp "${runtime_dir}/secure-registry.XXXXXX.yaml")"
  chmod 0600 "$staged"

  if ! rke2nodeinit_registry_materialize_secure_manifest "$manifest" "$staged"; then
    rke2nodeinit_registry_remove_staged_manifest "$staged"
    return 1
  fi

  SECURE_REGISTRY_CONFIG="$staged"
  replace_normalized_config_file "$staged"
  echo "[INFO] secureRegistry enabled; registry credentials resolved into a temporary root-only runtime manifest." >&2
}

exec_core() {
  [[ -x "$CORE_SCRIPT" ]] || { echo "ERROR: Missing executable core script: $CORE_SCRIPT" >&2; exit 1; }

  if [[ -n "${SECURE_REGISTRY_CONFIG:-}" ]]; then
    bash "$CORE_SCRIPT" "$@"
    exit $?
  fi

  exec bash "$CORE_SCRIPT" "$@"
}

exec_single_node() {
  local action="${1:-}"
  shift || true
  [[ -f "$SINGLE_NODE_SCRIPT" ]] || { echo "ERROR: Missing single-node helper: $SINGLE_NODE_SCRIPT" >&2; exit 1; }

  if [[ -n "${SECURE_REGISTRY_CONFIG:-}" ]]; then
    if [[ -n "$action" ]]; then
      RKE2NODEINIT_CORE_DELEGATE=1 bash "$SINGLE_NODE_SCRIPT" "$action" "$@"
    else
      RKE2NODEINIT_CORE_DELEGATE=1 bash "$SINGLE_NODE_SCRIPT" "$@"
    fi
    exit $?
  fi

  if [[ -n "$action" ]]; then
    RKE2NODEINIT_CORE_DELEGATE=1 exec bash "$SINGLE_NODE_SCRIPT" "$action" "$@"
  fi
  RKE2NODEINIT_CORE_DELEGATE=1 exec bash "$SINGLE_NODE_SCRIPT" "$@"
}

main() {
  if [[ "${RKE2NODEINIT_CORE_DELEGATE:-0}" == "1" ]] || parent_is_single_node_helper; then
    normalize_args "$@"
    if [[ -n "${ACTION:-}" ]]; then
      exec_core "${NORMALIZED_ARGS[@]}" "$ACTION"
    fi
    exec_core "${NORMALIZED_ARGS[@]}"
  fi

  normalize_args "$@"

  local yaml_kind=""
  local resolved_action=""
  local dry_run=0

  if [[ -n "${CONFIG_FILE:-}" && -f "$CONFIG_FILE" ]]; then
    yaml_kind="$(read_yaml_kind "$CONFIG_FILE" || true)"
    if [[ -n "$yaml_kind" ]]; then
      resolved_action="$(kind_to_action "$yaml_kind" || true)"
    fi
  fi

  if [[ -z "${ACTION:-}" && -n "$resolved_action" ]]; then
    ACTION="$resolved_action"
  fi

  if normalized_args_contain "--dry-run"; then
    dry_run=1
  fi

  prepare_secure_registry_config "${ACTION:-}" "${CONFIG_FILE:-}"
  rke2nodeinit_system_prepare_cis_for_action "${ACTION:-}" "${CONFIG_FILE:-}" "$dry_run"

  if [[ -n "$yaml_kind" ]] && kind_is_single_node "$yaml_kind"; then
    exec_single_node "$ACTION" "${NORMALIZED_ARGS[@]}"
  fi

  if [[ -n "${ACTION:-}" ]]; then
    exec_core "${NORMALIZED_ARGS[@]}" "$ACTION"
  fi

  exec_core "${NORMALIZED_ARGS[@]}"
}

main "$@"
