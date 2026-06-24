#!/usr/bin/env bash
#
# CNI helper library for rke2nodeinit.
#
# The CNI permission remediation service is safe to run before RKE2 creates
# /etc/cni/net.d. It must not wait on rke2-server/rke2-agent because it can be
# installed before those services are ready.

set -Eeuo pipefail

rke2_cni_repo_root() {
  local script_dir
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  cd -- "$script_dir/.." && pwd -P
}

rke2_cni_install_permission_remediation() {
  local root service timer
  root="$(rke2_cni_repo_root)"
  service="${root}/scripts/systemd/rke2-cni-perms.service"
  timer="${root}/scripts/systemd/rke2-cni-perms.timer"

  [[ -f "$service" ]] || { echo "ERROR: missing $service" >&2; return 2; }
  [[ -f "$timer" ]] || { echo "ERROR: missing $timer" >&2; return 2; }

  install -m 0644 "$service" /etc/systemd/system/rke2-cni-perms.service
  install -m 0644 "$timer" /etc/systemd/system/rke2-cni-perms.timer
  systemctl daemon-reload
  systemctl enable --now rke2-cni-perms.timer
}

rke2_cni_assert_service_not_ordered_after_rke2() {
  local service="${1:-/etc/systemd/system/rke2-cni-perms.service}"
  [[ -f "$service" ]] || return 0

  if grep -Eq '^After=.*rke2-(server|agent)\.service' "$service"; then
    echo "ERROR: $service must not be ordered After rke2-server/rke2-agent" >&2
    return 1
  fi
}

rke2_cni_run_permission_fix_once() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl start rke2-cni-perms.service || true
  elif [[ -x /usr/local/sbin/fix-cni-perms.sh ]]; then
    /usr/local/sbin/fix-cni-perms.sh || true
  fi
}
