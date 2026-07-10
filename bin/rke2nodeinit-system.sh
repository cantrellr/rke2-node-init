#!/usr/bin/env bash
# System helper library for rke2nodeinit.

set -Eeuo pipefail

RKE2NODEINIT_CIS_SYSCTL_FILE="${RKE2NODEINIT_CIS_SYSCTL_FILE:-/etc/sysctl.d/99-rke2-cis.conf}"

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

rke2nodeinit_system_ensure_cis_etcd_account() {
  local etcd_db_dir="/var/lib/rancher/rke2/server/db/etcd"

  rke2nodeinit_system_require_root || return 1

  if ! getent group etcd >/dev/null 2>&1; then
    if ! groupadd --system etcd >/dev/null 2>&1; then
      echo "ERROR: failed to create required system group: etcd" >&2
      return 1
    fi
    echo "[INFO] Created system group: etcd" >&2
  fi

  if ! getent passwd etcd >/dev/null 2>&1; then
    if ! useradd --system --no-create-home --home-dir "$etcd_db_dir" --shell /usr/sbin/nologin --gid etcd etcd >/dev/null 2>&1; then
      echo "ERROR: failed to create required system user: etcd" >&2
      return 1
    fi
    echo "[INFO] Created system user: etcd" >&2
  fi

  if [[ -d "$etcd_db_dir" ]]; then
    if ! chown -R etcd:etcd "$etcd_db_dir" >/dev/null 2>&1; then
      echo "ERROR: failed to set ownership on ${etcd_db_dir}" >&2
      return 1
    fi
    echo "[INFO] Ensured etcd ownership on ${etcd_db_dir}" >&2
  fi

  return 0
}

rke2nodeinit_system_manifest_requires_cis() {
  local file="${1:-}"
  [[ -n "$file" && -f "$file" ]] || return 1

  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$file" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
values = {}
stack = []
scalar = re.compile(r'^(?P<indent>\s*)(?P<key>[A-Za-z0-9_.-]+)\s*:\s*(?P<value>.*?)\s*$')

try:
    lines = path.read_text(encoding='utf-8').splitlines()
except OSError:
    raise SystemExit(1)

for raw in lines:
    line = raw.split('#', 1)[0].rstrip()
    if not line.strip() or line.lstrip().startswith('- '):
        continue

    match = scalar.match(line)
    if not match:
        continue

    indent = len(match.group('indent'))
    key = match.group('key')
    value = match.group('value').strip()

    while stack and stack[-1][0] >= indent:
        stack.pop()

    current = [part for _, part in stack] + [key]
    dotted = '.'.join(current)

    if value:
        values[dotted] = value.strip('"\'')
    else:
        stack.append((indent, key))

def truthy(value: str) -> bool:
    return value.strip().lower() in {'1', 'true', 'yes', 'y', 'on', 'enabled'}

profile = values.get('spec.profile', '').strip().lower()
single_node_cis = values.get('spec.singleNode.enableCIS', '')
generic_cis = values.get('spec.enableCIS', '')

raise SystemExit(0 if profile == 'cis' or truthy(single_node_cis) or truthy(generic_cis) else 1)
PY
    then
      return 0
    fi
    return 1
  fi

  if grep -Eiq '^[[:space:]]*profile[[:space:]]*:[[:space:]]*["'"'"']?cis["'"'"']?[[:space:]]*($|#)' "$file"; then
    return 0
  fi

  if grep -Eiq '^[[:space:]]*enableCIS[[:space:]]*:[[:space:]]*(1|true|yes|y|on|enabled)([[:space:]]*($|#))' "$file"; then
    return 0
  fi

  return 1
}

rke2nodeinit_system_config_requires_cis() {
  local file
  local -a candidates=("/etc/rancher/rke2/config.yaml")

  for file in /etc/rancher/rke2/config.yaml.d/*.yaml /etc/rancher/rke2/config.yaml.d/*.yml; do
    [[ -f "$file" ]] && candidates+=("$file")
  done

  for file in "${candidates[@]}"; do
    [[ -f "$file" ]] || continue
    if grep -Eiq '^[[:space:]]*profile[[:space:]]*:[[:space:]]*["'"'"']?cis["'"'"']?[[:space:]]*($|#)' "$file"; then
      return 0
    fi
  done

  return 1
}

rke2nodeinit_system_apply_cis_kernel_prereqs() {
  local sysctl_file="${RKE2NODEINIT_CIS_SYSCTL_FILE:-/etc/sysctl.d/99-rke2-cis.conf}"
  local tmp=""
  local key=""
  local expected=""
  local actual=""
  local rc=0

  rke2nodeinit_system_require_root || return 1

  install -d -m 0755 "$(dirname -- "$sysctl_file")"
  tmp="$(mktemp "${sysctl_file}.tmp.XXXXXX")"

  cat > "$tmp" <<'EOF'
# Managed by rke2-node-init.
# Required by RKE2 when profile: cis enables protect-kernel-defaults.
vm.overcommit_memory = 1
vm.panic_on_oom = 0
kernel.panic = 10
kernel.panic_on_oops = 1
EOF

  install -m 0644 "$tmp" "$sysctl_file"
  rm -f "$tmp"

  while read -r key expected; do
    [[ -n "$key" && -n "$expected" ]] || continue

    if ! rke2nodeinit_system_sysctl_set "$key" "$expected" >/dev/null 2>&1; then
      echo "ERROR: failed to apply RKE2 CIS kernel parameter ${key}=${expected}" >&2
      rc=1
      continue
    fi

    actual="$(sysctl -n "$key" 2>/dev/null || true)"
    if [[ "$actual" != "$expected" ]]; then
      echo "ERROR: invalid kernel parameter value ${key}=${actual:-<unreadable>} - expected ${expected}" >&2
      rc=1
    fi
  done <<'EOF'
vm.overcommit_memory 1
vm.panic_on_oom 0
kernel.panic 10
kernel.panic_on_oops 1
EOF

  if [[ "$rc" -ne 0 ]]; then
    echo "ERROR: RKE2 CIS kernel prerequisite enforcement failed; refusing to continue to RKE2 service startup." >&2
    return "$rc"
  fi

  echo "[INFO] RKE2 CIS kernel prerequisites applied and persisted in ${sysctl_file}" >&2
  return 0
}

rke2nodeinit_system_prepare_cis_for_action() {
  local action="${1:-}"
  local manifest="${2:-}"
  local dry_run="${3:-0}"

  case "$action" in
    server|add-server|agent) ;;
    *) return 0 ;;
  esac

  if ! rke2nodeinit_system_manifest_requires_cis "$manifest" && ! rke2nodeinit_system_config_requires_cis; then
    return 0
  fi

  if [[ "$dry_run" == "1" ]]; then
    echo "[INFO] DRY-RUN would ensure CIS etcd account prerequisites: group=etcd user=etcd shell=/usr/sbin/nologin" >&2
    echo "[INFO] DRY-RUN would apply RKE2 CIS kernel prerequisites: vm.overcommit_memory=1, vm.panic_on_oom=0, kernel.panic=10, kernel.panic_on_oops=1" >&2
    return 0
  fi

  echo "[INFO] CIS profile detected for ${action}; applying account and kernel prerequisites before service startup." >&2
  rke2nodeinit_system_ensure_cis_etcd_account
  rke2nodeinit_system_apply_cis_kernel_prereqs
}
