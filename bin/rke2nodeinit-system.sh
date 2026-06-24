#!/usr/bin/env bash
# System helper library for rke2nodeinit.

set -Eeuo pipefail

rke2nodeinit_system_require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "ERROR: please run this command as root (use sudo)." >&2
    return 1
  fi
}

rke2nodeinit_system_daemon_reload() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  fi
}

rke2nodeinit_system_stop_rke2_server_if_present() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files rke2-server.service >/dev/null 2>&1; then
    systemctl stop rke2-server || true
    systemctl reset-failed rke2-server || true
  fi
}

rke2nodeinit_system_sysctl_set() {
  local key="${1:-}"
  local value="${2:-}"
  [[ -n "$key" && -n "$value" ]] || return 2
  sysctl -w "${key}=${value}"
}
