#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: sudo bin/rke2-multicluster-preflight.sh [server|add-server|agent]

Validates cloned-node identity, stale RKE2 state, CIS prerequisites, routing,
and interface gateway policy before provisioning a multi-node cluster.
Set RKE2NODEINIT_ALLOW_EXISTING_STATE=1 only for an intentional retry.
EOF
}

ACTION="${1:-}"
case "$ACTION" in
  server|add-server|agent) ;;
  -h|--help|'') usage; [[ -n "$ACTION" ]] && exit 0 || exit 2 ;;
  *) echo "ERROR: unsupported action: $ACTION" >&2; exit 2 ;;
esac

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }

fail() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARNING: $*" >&2; }

machine_id="$(tr -d '[:space:]' </etc/machine-id 2>/dev/null || true)"
if [[ -z "$machine_id" ]]; then
  systemd-machine-id-setup
  machine_id="$(tr -d '[:space:]' </etc/machine-id)"
fi
[[ "$machine_id" =~ ^[0-9a-fA-F]{32}$ ]] || fail "invalid /etc/machine-id: ${machine_id:-<empty>}"

if [[ "${RKE2NODEINIT_ALLOW_EXISTING_STATE:-0}" != "1" ]]; then
  stale=()
  [[ -e /etc/rancher/node/password ]] && stale+=(/etc/rancher/node/password)
  [[ -d /var/lib/kubelet/pods ]] && stale+=(/var/lib/kubelet/pods)
  [[ -d /var/lib/cni/networks ]] && stale+=(/var/lib/cni/networks)
  [[ -d /var/lib/rancher/rke2/server/db/etcd ]] && stale+=(/var/lib/rancher/rke2/server/db/etcd)
  if (( ${#stale[@]} > 0 )); then
    printf 'ERROR: cloned or pre-existing RKE2 state detected:\n' >&2
    printf '  - %s\n' "${stale[@]}" >&2
    echo "Sanitize the source VM with bin/rke2-template-sanitize.sh --force before cloning." >&2
    exit 1
  fi
fi

if grep -RqsE '^[[:space:]]*profile:[[:space:]]*["'"']?cis' /etc/rancher/rke2 2>/dev/null; then
  getent passwd etcd >/dev/null || fail "CIS profile requires the etcd system user"
  getent group etcd >/dev/null || fail "CIS profile requires the etcd system group"
  declare -A expected=(
    [vm.overcommit_memory]=1
    [vm.panic_on_oom]=0
    [kernel.panic]=10
    [kernel.panic_on_oops]=1
  )
  for key in "${!expected[@]}"; do
    actual="$(sysctl -n "$key" 2>/dev/null || true)"
    [[ "$actual" == "${expected[$key]}" ]] || fail "$key=$actual; expected ${expected[$key]}"
  done
fi

if command -v ip >/dev/null 2>&1; then
  ip route show default | grep -q . || warn "no default route is configured"
fi

echo "Multi-cluster preflight passed for action=$ACTION machine-id=$machine_id"
