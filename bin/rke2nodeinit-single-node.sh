#!/usr/bin/env bash
#
# Internal single-node action helper for rke2nodeinit.sh.
#
# This helper intentionally reuses the existing single-node profile implementation
# while ensuring that any delegated legacy image/server call lands in
# rke2nodeinit-core.sh through the public dispatcher. That avoids recursive
# single-node dispatch while keeping the current single-node implementation
# isolated from the main entrypoint.

set -Eeuo pipefail
trap 'rc=$?; echo "[ERROR] ${BASH_SOURCE[0]} failed at line ${LINENO} with exit ${rc}" >&2; exit ${rc}' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROFILE_SCRIPT="${SCRIPT_DIR}/rke2-single-node-profile.sh"

install_swap_preflight_guard() {
  # Kubelet fails fast when swap is enabled. Ubuntu VM templates often carry
  # /swap.img, and RKE2 can start before a one-time provisioning step notices.
  # Install this as an additional early ExecStartPre guard so single-node RKE2
  # starts with swap disabled even after reboot or template cloning.
  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "[INFO] DRY-RUN would install single-node swap preflight guard" >&2
    return 0
  fi

  if [[ "${EUID}" -ne 0 ]]; then
    return 0
  fi

  install -d -m 0755 /usr/local/sbin /etc/systemd/system/rke2-server.service.d
  cat > /usr/local/sbin/rke2-single-node-swap-preflight.sh <<'SCRIPT'
#!/bin/sh
set -eu

# RKE2/kubelet expects swap to be off unless explicitly configured otherwise.
# Disable active swap at every rke2-server start. Leave /etc/fstab untouched so
# operators can make a conscious persistent OS-template decision separately.
if command -v swapon >/dev/null 2>&1 && swapon --show=NAME --noheadings 2>/dev/null | grep -q .; then
  swapoff -a || true
fi
SCRIPT
  chmod 0755 /usr/local/sbin/rke2-single-node-swap-preflight.sh

  cat > /etc/systemd/system/rke2-server.service.d/05-single-node-swap-preflight.conf <<'EOF'
# Managed by bin/rke2nodeinit-single-node.sh.
[Service]
ExecStartPre=/usr/local/sbin/rke2-single-node-swap-preflight.sh
EOF
  systemctl daemon-reload || true
  /usr/local/sbin/rke2-single-node-swap-preflight.sh || true
  echo "[INFO] Installed rke2-server single-node swap preflight guard" >&2
}

if [[ ! -f "$PROFILE_SCRIPT" ]]; then
  echo "ERROR: Missing single-node profile implementation: $PROFILE_SCRIPT" >&2
  exit 1
fi

install_swap_preflight_guard

export RKE2NODEINIT_CORE_DELEGATE=1
exec bash "$PROFILE_SCRIPT" "$@"
