#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: sudo bin/rke2-template-sanitize.sh [--force] [--no-poweroff]

Removes node- and cluster-specific RKE2 state before sealing a VM template.
Preserves staged air-gap artifacts, repository content, custom CA trust, and the
canonical bootstrap token under /etc/rancher/rke2/token.d.
EOF
}

FORCE=0
POWEROFF=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force) FORCE=1 ;;
    --no-poweroff) POWEROFF=0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }

if [[ "$FORCE" -ne 1 ]]; then
  cat <<'EOF'
This operation permanently removes local RKE2 cluster identity and runtime state.
Re-run with --force after confirming this VM is the source image/template.
EOF
  exit 3
fi

for unit in rke2-server rke2-agent; do
  systemctl disable --now "$unit" 2>/dev/null || true
done

rm -rf \
  /var/lib/rancher/rke2 \
  /var/lib/kubelet \
  /var/lib/cni \
  /etc/cni/net.d \
  /etc/rancher/node \
  /run/k3s \
  /run/flannel

# Preserve token.d and registry trust while removing generated node config.
rm -f /etc/rancher/rke2/config.yaml
rm -f /etc/rancher/rke2/config.yaml.d/*.yaml /etc/rancher/rke2/config.yaml.d/*.yml 2>/dev/null || true

truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id

if command -v cloud-init >/dev/null 2>&1; then
  cloud-init clean --logs --seed || true
fi
rm -f /etc/ssh/ssh_host_*

install -d -m 0755 /var/lib/rke2-node-init
cat > /var/lib/rke2-node-init/template-sanitized <<EOF
sanitized_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
hostname=$(hostname)
EOF
chmod 0644 /var/lib/rke2-node-init/template-sanitized

sync
echo "RKE2 template state sanitized successfully."
if [[ "$POWEROFF" -eq 1 ]]; then
  systemctl poweroff
fi
