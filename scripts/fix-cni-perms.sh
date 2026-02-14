#!/usr/bin/env bash
set -euo pipefail

CNI_DIR="${CNI_DIR:-/etc/cni/net.d}"
VERBOSE="${VERBOSE:-1}"

log() {
  if [[ "$VERBOSE" == "1" ]]; then
    echo "[fix-cni-perms] $*"
  fi
}

require_root() {
  if [[ "${EUID:-0}" -ne 0 ]]; then
    echo "This script must run as root." >&2
    exit 1
  fi
}

fix_mode_if_needed() {
  local target="$1"
  local mode="$2"
  if [[ ! -e "$target" ]]; then
    return 0
  fi
  local current
  current="$(stat -c '%a' "$target" 2>/dev/null || true)"
  if [[ "$current" != "$mode" ]]; then
    chmod "$mode" "$target"
    log "set mode ${mode} on ${target}"
  fi
}

main() {
  require_root

  if [[ ! -d "$CNI_DIR" ]]; then
    log "${CNI_DIR} not present; nothing to do"
    exit 0
  fi

  fix_mode_if_needed "$CNI_DIR" 755

  fix_mode_if_needed "${CNI_DIR}/10-canal.conflist" 644
  fix_mode_if_needed "${CNI_DIR}/00-multus.conf" 644

  if [[ -d "${CNI_DIR}/multus.d" ]]; then
    fix_mode_if_needed "${CNI_DIR}/multus.d" 755
    fix_mode_if_needed "${CNI_DIR}/multus.d/multus.kubeconfig" 640
  fi

  log "completed"
}

main "$@"
