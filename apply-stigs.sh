#!/usr/bin/env bash
set -euo pipefail

# Apply firewall zone layout and interface bindings.
dry_run=false
if [[ "${1:-}" == "-n" || "${1:-}" == "--dry-run" ]]; then
  dry_run=true
  shift
fi

run_cmd() {
  if [[ "$dry_run" == "true" ]]; then
    echo "DRY-RUN: $*"
  else
    "$@"
  fi
}

SUDO=""
if [[ "${EUID:-0}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "This script must run as root or have sudo available." >&2
    exit 1
  fi
fi

install_firewalld() {
  if command -v dnf >/dev/null 2>&1; then
    run_cmd $SUDO dnf install -y firewalld
  elif command -v yum >/dev/null 2>&1; then
    run_cmd $SUDO yum install -y firewalld
  elif command -v apt-get >/dev/null 2>&1; then
    run_cmd $SUDO apt-get update
    run_cmd $SUDO apt-get install -y firewalld
  elif command -v zypper >/dev/null 2>&1; then
    run_cmd $SUDO zypper --non-interactive install firewalld
  else
    echo "No supported package manager found to install firewalld." >&2
    exit 1
  fi
}

if ! command -v firewall-cmd >/dev/null 2>&1; then
  echo "firewall-cmd not found. Installing firewalld..." >&2
  install_firewalld
fi

if ! command -v ip >/dev/null 2>&1; then
  echo "ip not found. Install iproute2 first." >&2
  exit 1
fi

if ! systemctl is-enabled --quiet firewalld; then
  run_cmd $SUDO systemctl enable --now firewalld
fi

if ! systemctl is-active --quiet firewalld; then
  run_cmd $SUDO systemctl start firewalld
fi

if ! systemctl is-active --quiet firewalld; then
  if [[ "$dry_run" == "true" ]]; then
    echo "warning: firewalld is not running; dry-run will not apply changes" >&2
  else
    echo "firewalld is not running after attempting to start it." >&2
    exit 1
  fi
fi

missing_iface=false
check_interface() {
  local iface="$1"
  if ! ip link show "$iface" >/dev/null 2>&1; then
    echo "warning: interface $iface not found" >&2
    missing_iface=true
  fi
}

create_zone() {
  local zone_name="$1"
  if ! firewall-cmd --get-zones | tr ' ' '\n' | grep -Fxq "$zone_name"; then
    run_cmd firewall-cmd --permanent --new-zone="$zone_name"
  fi
}

check_interface "ens33"
check_interface "ens35"
check_interface "ens36"
if [[ "$missing_iface" == "true" ]]; then
  echo "One or more interfaces are missing. Fix and re-run." >&2
  exit 1
fi

create_zone "DOMAIN"
create_zone "NFS"
create_zone "SEGMENT1"

# Bind interfaces to their zones.
run_cmd firewall-cmd --permanent --zone=DOMAIN --add-interface=ens33
run_cmd firewall-cmd --permanent --zone=NFS --add-interface=ens35
run_cmd firewall-cmd --permanent --zone=SEGMENT1 --add-interface=ens36

# Deny any inter-zone traffic by default.
run_cmd firewall-cmd --permanent --zone=DOMAIN --set-target=DROP
run_cmd firewall-cmd --permanent --zone=NFS --set-target=DROP
run_cmd firewall-cmd --permanent --zone=SEGMENT1 --set-target=DROP

# Only DOMAIN can reach the Internet.
run_cmd firewall-cmd --permanent --zone=DOMAIN --add-masquerade
run_cmd firewall-cmd --permanent --zone=NFS --remove-masquerade
run_cmd firewall-cmd --permanent --zone=SEGMENT1 --remove-masquerade

run_cmd firewall-cmd --reload

if [[ "$dry_run" == "true" ]]; then
  echo "Dry-run complete. No changes applied."
else
  echo "Firewall zones configured: DOMAIN=ens33, NFS=ens35, SEGMENT1=ens36"
fi

# Quick firewall report.
if systemctl is-active --quiet firewalld; then
  echo ""
  echo "Firewall status:"
  firewall-cmd --state
  echo ""
  echo "Active zones:"
  firewall-cmd --get-active-zones
  echo ""
  echo "Zones detail:"
  firewall-cmd --list-all-zones
else
  echo ""
  echo "warning: firewalld is not running; skipping report" >&2
fi
